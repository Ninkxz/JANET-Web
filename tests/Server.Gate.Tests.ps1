# =============================================================================
#  Server.Gate.Tests.ps1 - Pester 3.4 tests for the server-side destructive-
#  action gate (audit#1 / audit#30). Starts a REAL server instance on a test
#  port and probes the HTTP surface. No admin session is ever started and no
#  credential is ever set, so no destructive engine code can run - the gate
#  rejects at the door, which is exactly what these tests prove.
#
#  Run:  Invoke-Pester -Path .\tests\Server.Gate.Tests.ps1
# =============================================================================
$script:Root  = Split-Path $PSScriptRoot -Parent
$script:Port  = 18089
$script:Token = 'PESTER-GATE-TEST-TOKEN-0123456789abcdef'

function Invoke-JanetTestPost {
    param([string]$Path, [string]$Tok = $script:Token, [string]$Body = '{}')
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($script:Port)$Path")
    $req.Method = 'POST'; $req.Timeout = 15000
    if ($Tok) { $req.Headers.Add('X-Janet-Token', $Tok) }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $req.ContentType = 'application/json'; $req.ContentLength = $bytes.Length
    $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    $status = 0; $text = ''
    try {
        $resp = $req.GetResponse()
        $status = [int]$resp.StatusCode
        $text = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
        $resp.Close()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            $text = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
        } else { throw }
    }
    @{ Status = $status; Body = $text }
}

Describe 'Server destructive-action gate (no ack, no credential)' {

    $serverCmd = ". '$script:Root\server\JanetTwo.Server.ps1'; Start-JanetTwoServer -Root '$script:Root' -Port $script:Port -Token '$script:Token'"
    $script:Proc = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$serverCmd) -PassThru -WindowStyle Hidden

    $script:Up = $false
    foreach ($i in 1..60) {
        try {
            $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($script:Port)/api/tools")
            $req.Timeout = 2000; $req.Headers.Add('X-Janet-Token', $script:Token)
            $resp = $req.GetResponse(); $resp.Close(); $script:Up = $true; break
        } catch { Start-Sleep -Milliseconds 500 }
    }

    It 'test server starts and answers /api/tools' {
        $script:Up | Should Be $true
    }

    It 'rejects a request with no session token' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/list-profiles' -Tok ''
        $r.Status | Should Be 403
        $r.Body | Should Match 'token'
    }

    # --- audit#1: ACAS by-id destructive actions must hit the admin-session gate ---
    It 'gates acas patch-selected (by-id, not in manifest)' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/patch-selected'
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    It 'gates acas reboot-selected (by-id, not in manifest)' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/reboot-selected'
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    It 'gates acas schedule-reboot (by-id, not in manifest)' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/schedule-reboot'
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    # --- regression: manifest-registered destructive actions stay gated ---
    It 'still gates a manifest destructive action (restart dispatch-restart)' {
        $r = Invoke-JanetTestPost '/api/tool/restart/action/dispatch-restart'
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    # --- read-only paths must NOT be blocked by the admin-session gate ---
    It 'does not gate a read-only acas by-id action (list-profiles)' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/list-profiles'
        $r.Body | Should Not Match 'Admin session required'
    }

    It 'still 404s an unknown action id' {
        $r = Invoke-JanetTestPost '/api/tool/acas/action/not-a-real-action'
        $r.Status | Should Be 404
    }

    # teardown
    It 'test server shuts down' {
        if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force }
        Start-Sleep -Milliseconds 300
        $true | Should Be $true
    }
}
