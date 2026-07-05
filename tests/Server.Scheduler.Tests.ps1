# =============================================================================
#  Server.Scheduler.Tests.ps1 - Pester 3.4 tests for the off-hours scheduler
#  (arm-and-walk-away). Starts a REAL server, arms a READ-ONLY wave a few seconds
#  out, and confirms the background poller fires it through the gated route. Also
#  confirms a DESTRUCTIVE wave cannot be armed without an admin session (403).
#  No destructive action is ever run against any host (read-only fire only).
#
#  Run:  Invoke-Pester -Path .\tests\Server.Scheduler.Tests.ps1
# =============================================================================
$script:Root  = Split-Path $PSScriptRoot -Parent
$script:Port  = 18121
$script:Token = 'PESTER-SCHED-TOKEN-0123456789abcdef'

function Invoke-SchedReq {
    param([string]$Method, [string]$Path, [string]$Body = '')
    $r = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($script:Port)$Path")
    $r.Method = $Method; $r.Timeout = 15000; $r.Headers.Add('X-Janet-Token', $script:Token)
    if ($Method -eq 'POST') {
        $b = [System.Text.Encoding]::UTF8.GetBytes($Body); $r.ContentType = 'application/json'; $r.ContentLength = $b.Length
        $s = $r.GetRequestStream(); $s.Write($b, 0, $b.Length); $s.Close()
    }
    try { $resp = $r.GetResponse(); $t = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd(); $resp.Close(); return @{ Status = [int]$resp.StatusCode; Body = $t } }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) { return @{ Status = [int]$_.Exception.Response.StatusCode; Body = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } }
        return @{ Status = -1; Body = $_.Exception.Message }
    }
}

Describe 'Off-hours scheduler (arm-and-walk-away)' {

    $serverCmd = ". '$script:Root\server\JanetWeb.Server.ps1'; Start-JanetWebServer -Root '$script:Root' -Port $script:Port -Token '$script:Token'"
    $script:Proc = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$serverCmd) -PassThru -WindowStyle Hidden
    $script:Up = $false
    foreach ($i in 1..60) {
        try { if ((Invoke-SchedReq 'GET' '/api/tools').Status -eq 200) { $script:Up = $true; break } } catch {}
        Start-Sleep -Milliseconds 500
    }
    $script:Sid = $null

    It 'server starts' { $script:Up | Should Be $true }

    It 'arms a read-only wave (reports/campaign-list) to fire in 3s' {
        $fireAt = (Get-Date).ToUniversalTime().AddSeconds(3).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $body = @{ toolId='reports'; actionId='campaign-list'; fireAt=$fireAt; label='PESTER read-only'; recurrence='none' } | ConvertTo-Json -Compress
        $r = Invoke-SchedReq 'POST' '/api/schedule' $body
        $r.Status | Should Be 200
        $o = $r.Body | ConvertFrom-Json
        $o.ok | Should Be $true
        $o.destructive | Should Be $false
        $script:Sid = $o.id
    }

    It 'refuses to arm a DESTRUCTIVE wave without an admin session (403)' {
        $fireAt = (Get-Date).ToUniversalTime().AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $body = @{ toolId='restart'; actionId='dispatch-restart'; fireAt=$fireAt } | ConvertTo-Json -Compress
        $r = Invoke-SchedReq 'POST' '/api/schedule' $body
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    It 'the background poller fires the due read-only wave (status -> fired)' {
        Start-Sleep -Seconds 20   # poller ticks every 15s
        $list = (Invoke-SchedReq 'GET' '/api/schedule').Body | ConvertFrom-Json
        $mine = $list.schedules | Where-Object { $_.id -eq $script:Sid }
        $mine | Should Not BeNullOrEmpty
        $mine.status | Should Be 'fired'
        $mine.note   | Should Match 'fired ok'
    }

    It 'cancels a schedule (DELETE marks it cancelled)' {
        $fireAt = (Get-Date).ToUniversalTime().AddHours(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $body = @{ toolId='reports'; actionId='campaign-list'; fireAt=$fireAt; label='PESTER cancel' } | ConvertTo-Json -Compress
        $cid = ((Invoke-SchedReq 'POST' '/api/schedule' $body).Body | ConvertFrom-Json).id
        $del = Invoke-SchedReq 'DELETE' "/api/schedule/$cid"
        $del.Status | Should Be 200
        ($del.Body | ConvertFrom-Json).status | Should Be 'cancelled'
    }

    It 'teardown: stop server + remove test schedule files' {
        if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force }
        Start-Sleep -Milliseconds 400
        $sd = Join-Path $script:Root 'JanetLocal\schedule'
        if (Test-Path $sd) {
            foreach ($f in (Get-ChildItem $sd -Filter '*.json' -File)) {
                try { $j = Get-Content $f.FullName -Raw | ConvertFrom-Json; if ($j.label -like 'PESTER*') { [System.IO.File]::Delete($f.FullName) } } catch {}
            }
        }
        $true | Should Be $true
    }
}
