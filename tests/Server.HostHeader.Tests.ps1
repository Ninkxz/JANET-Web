# =============================================================================
#  Server.HostHeader.Tests.ps1 - Pester 3.4 tests for the loop-4 Host-header
#  guard (roadmap item 3, DNS-rebinding defense-in-depth).
#
#  http.sys routes an IP-literal HttpListener prefix (http://127.0.0.1:PORT/)
#  by destination ip:port and ignores the Host string - a loop-4 raw-socket
#  probe confirmed 'Host: evil.example.com' reached the request loop and got a
#  200. A DNS-rebound attacker page (its hostname re-resolved to 127.0.0.1) is
#  same-origin to its OWN name, so it could read the no-token surfaces (static
#  UI, report-preview). The guard fails closed: only 'Host: 127.0.0.1:PORT' and
#  'Host: localhost:PORT' are served; everything else (incl. a missing Host)
#  gets 421 Misdirected with no content, BEFORE the static/asset and /api paths.
#
#  These tests boot a REAL server (same harness as Server.Gate) and drive it
#  with raw TCP sockets, because HttpWebRequest forces Host to match the URL
#  authority and cannot forge a foreign Host header.
#
#  Run:  Invoke-Pester -Path .\tests\Server.HostHeader.Tests.ps1
# =============================================================================
$script:Root  = Split-Path $PSScriptRoot -Parent
$script:Port  = 18091
$script:Token = 'PESTER-HOST-TEST-TOKEN-0123456789abcdef'

# Send a raw HTTP/1.1 GET with an arbitrary Host header; return the status line
# + whether the token-gated /api/tools body came back (proof of reaching the app).
function Invoke-RawGet {
    param([string]$Path, [string]$HostHeader, [string]$Tok = '')
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $script:Port)
    $c.ReceiveTimeout = 6000
    $s = $c.GetStream()
    $hdr = "GET $Path HTTP/1.1`r`nHost: $HostHeader`r`n"
    if ($Tok) { $hdr += "X-Janet-Token: $Tok`r`n" }
    $hdr += "Connection: close`r`n`r`n"
    $b = [System.Text.Encoding]::ASCII.GetBytes($hdr)
    $s.Write($b, 0, $b.Length)
    $sr = New-Object System.IO.StreamReader($s)
    $all = ''
    try { $all = $sr.ReadToEnd() } catch {}
    $sr.Close(); $c.Close()
    $statusLine = ($all -split "`r`n")[0]
    @{ Status = $statusLine; Raw = $all }
}

Describe 'Server Host-header guard (DNS-rebinding defense)' {

    $serverCmd = ". '$script:Root\server\JanetWeb.Server.ps1'; Start-JanetWebServer -Root '$script:Root' -Port $script:Port -Token '$script:Token'"
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

    It 'serves a loopback-IP Host (the launcher default)' {
        $r = Invoke-RawGet '/api/tools' "127.0.0.1:$script:Port" $script:Token
        $r.Status | Should Match '200'
    }

    It 'serves a localhost Host' {
        $r = Invoke-RawGet '/api/tools' "localhost:$script:Port" $script:Token
        $r.Status | Should Match '200'
    }

    It 'REJECTS a foreign Host header with 421 (DNS-rebinding attempt)' {
        $r = Invoke-RawGet '/api/tools' "evil.example.com:$script:Port" $script:Token
        $r.Status | Should Match '421'
    }

    It 'REJECTS a foreign Host even on the no-token static surface (the actual rebind target)' {
        $r = Invoke-RawGet '/index.html' "attacker.test:$script:Port"
        $r.Status | Should Match '421'
    }

    It 'REJECTS a foreign Host on the no-token report-preview surface' {
        $r = Invoke-RawGet '/api/report-preview?id=whatever' 'attacker.test'
        $r.Status | Should Match '421'
    }

    It 'REJECTS a bare-IP Host with the wrong port (not this listener''s authority)' {
        $r = Invoke-RawGet '/api/tools' "127.0.0.1:1" $script:Token
        $r.Status | Should Match '421'
    }

    It 'the 421 fires BEFORE the token gate (foreign Host + valid token still rejected)' {
        # proves the guard is not merely the token check in disguise
        $r = Invoke-RawGet '/api/tools' "evil.example.com:$script:Port" $script:Token
        $r.Status | Should Match '421'
        $r.Raw | Should Match 'misdirected'
    }

    It 'test server shuts down' {
        if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force }
        Start-Sleep -Milliseconds 300
        $true | Should Be $true
    }
}
