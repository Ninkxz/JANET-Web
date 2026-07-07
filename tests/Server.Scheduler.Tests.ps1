# =============================================================================
#  Server.Scheduler.Tests.ps1 - Pester 3.4 tests for the off-hours scheduler
#  (arm-and-walk-away). Starts a REAL server and confirms:
#    - ARMING any wave (destructive OR read-only) now requires an admin session,
#      so a bare token-holder can't leave standing automation armed (403). Since
#      setting a credential pops a live smartcard dialog we can't drive in a unit
#      test, the "poller fires" + "DELETE cancels" cases seed an armed schedule
#      file DIRECTLY on disk (the poller/route read the file regardless of how it
#      was armed) and exercise the background poller through the gated route.
#  No destructive action is ever run against any host (read-only fire only).
#
#  Run:  Invoke-Pester -Path .\tests\Server.Scheduler.Tests.ps1
# =============================================================================
$script:Root  = Split-Path $PSScriptRoot -Parent
$script:Port  = 18121
$script:Token = 'PESTER-SCHED-TOKEN-0123456789abcdef'
$script:SchedDir = Join-Path (Join-Path $script:Root 'JanetLocal') 'schedule'

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

# Seed an armed schedule file straight to the poller's watch dir (bypasses the arm
# gate, which now needs a live admin session we can't establish in a unit test).
function New-SchedFile {
    param([string]$ToolId, [string]$ActionId, [string]$FireAtUtc, [string]$Label, [string]$Recurrence = 'none')
    if (-not (Test-Path -LiteralPath $script:SchedDir)) { New-Item -ItemType Directory -Path $script:SchedDir -Force | Out-Null }
    $sid = ([guid]::NewGuid().ToString('N'))
    $obj = [ordered]@{
        id = $sid; createdUtc = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')); createdBy = 'PESTER'
        toolId = $ToolId; actionId = $ActionId; label = $Label; destructive = $false
        fireAtUtc = $FireAtUtc; recurrence = $Recurrence; status = 'armed'; params = @{}; firedUtc = ''; note = ''
    }
    $file = Join-Path $script:SchedDir ("$sid.json")
    [System.IO.File]::WriteAllText($file, ($obj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return $sid
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

    It 'refuses to arm a READ-ONLY wave without an admin session (403)' {
        # FIX (P2): arming ANY schedule now requires the live admin session, not just
        # destructive waves - a bare token-holder must not be able to arm standing work.
        $fireAt = (Get-Date).ToUniversalTime().AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $body = @{ toolId='reports'; actionId='campaign-list'; fireAt=$fireAt; label='PESTER read-only'; recurrence='none' } | ConvertTo-Json -Compress
        $r = Invoke-SchedReq 'POST' '/api/schedule' $body
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    It 'refuses to arm a DESTRUCTIVE wave without an admin session (403)' {
        $fireAt = (Get-Date).ToUniversalTime().AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $body = @{ toolId='restart'; actionId='dispatch-restart'; fireAt=$fireAt } | ConvertTo-Json -Compress
        $r = Invoke-SchedReq 'POST' '/api/schedule' $body
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    It 'the background poller fires a due read-only wave (status -> fired)' {
        # Seed an already-due armed read-only wave straight to the watch dir; the poller
        # fires it through the gated route (read-only needs no admin session at fire time).
        $fireAt = (Get-Date).ToUniversalTime().AddSeconds(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $script:Sid = New-SchedFile -ToolId 'reports' -ActionId 'campaign-list' -FireAtUtc $fireAt -Label 'PESTER poller-fire'
        Start-Sleep -Seconds 20   # poller ticks every 15s
        $list = (Invoke-SchedReq 'GET' '/api/schedule').Body | ConvertFrom-Json
        $mine = $list.schedules | Where-Object { $_.id -eq $script:Sid }
        $mine | Should Not BeNullOrEmpty
        $mine.status | Should Be 'fired'
        $mine.note   | Should Match 'fired ok'
    }

    It 'cancels a schedule (DELETE marks it cancelled)' {
        $fireAt = (Get-Date).ToUniversalTime().AddHours(5).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $cid = New-SchedFile -ToolId 'reports' -ActionId 'campaign-list' -FireAtUtc $fireAt -Label 'PESTER cancel'
        $del = Invoke-SchedReq 'DELETE' "/api/schedule/$cid"
        $del.Status | Should Be 200
        ($del.Body | ConvertFrom-Json).status | Should Be 'cancelled'
    }

    It 'teardown: stop server + remove test schedule files' {
        if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force }
        Start-Sleep -Milliseconds 400
        if (Test-Path $script:SchedDir) {
            foreach ($f in (Get-ChildItem $script:SchedDir -Filter '*.json' -File)) {
                try { $j = Get-Content $f.FullName -Raw | ConvertFrom-Json; if ($j.label -like 'PESTER*') { [System.IO.File]::Delete($f.FullName) } } catch {}
            }
        }
        $true | Should Be $true
    }
}
