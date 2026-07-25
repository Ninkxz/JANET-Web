# =============================================================================
#  Server.ArmedRestart.Tests.ps1 - Pester 3.4 tests for the SERVER-SIDE armed
#  restart (audit 2026-07-25 convergence C1: the delayed start moved out of the
#  browser, where an F5 silently lost a 2 AM reboot wave).
#
#  What these prove, and how:
#    1. The arm REFUSES TO FIRE after the operator session ends, after the log
#       session changes, and after the fire time goes stale. Driven through the
#       real decision function, not a mirror of it.
#    2. The typed RESTART word is demanded AT ARM TIME, live-only, with the
#       dry-run flag read FAIL-CLOSED.
#    3. NOTHING about an arm reaches disk - measured by snapshotting the
#       filesystem around a real arm-record construction, not by reading source.
#    4. GET /api/jobs and POST /api/armed-restart/disarm sit behind the SAME
#       per-launch token gate as every other /api route, and the arm route is
#       gated by the admin session and exists for 'restart' ONLY.
#
#  Run:  Invoke-Pester -Path .\tests\Server.ArmedRestart.Tests.ps1
# =============================================================================
$script:Root  = Split-Path $PSScriptRoot -Parent
$script:Port  = 18091
$script:Token = 'PESTER-ARM-TEST-TOKEN-0123456789abcd'

# Dot-source the server script: this DEFINES the helper functions (and starts
# nothing - Start-JanetWebServer is only a function definition until called).
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

function Invoke-JanetArmTestRequest {
    param([string]$Method, [string]$Path, [string]$Tok = $script:Token, [string]$Body = '{}')
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($script:Port)$Path")
    $req.Method = $Method; $req.Timeout = 15000
    if ($Tok) { $req.Headers.Add('X-Janet-Token', $Tok) }
    if ($Method -eq 'POST') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentType = 'application/json'; $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    }
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

# ---------------------------------------------------------------------------
Describe 'Arm time parsing (ConvertTo-JanetWebArmFireAt)' {

    $now = Get-Date '2026-07-25 22:00:00'

    It 'reads HH:mm as the NEXT occurrence (later today)' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '23:30' -Now $now
        $d.ToString('yyyy-MM-dd HH:mm') | Should Be '2026-07-25 23:30'
    }
    It 'rolls HH:mm to tomorrow when the time already passed today' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '02:00' -Now $now
        $d.ToString('yyyy-MM-dd HH:mm') | Should Be '2026-07-26 02:00'
    }
    It 'reads an ISO 8601 local date-time' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '2026-07-26T02:15:00' -Now $now
        $d.ToString('yyyy-MM-dd HH:mm') | Should Be '2026-07-26 02:15'
    }
    It 'returns nothing for junk, a blank, and an impossible clock time' {
        (ConvertTo-JanetWebArmFireAt -Raw 'tomorrow-ish' -Now $now) | Should BeNullOrEmpty
        (ConvertTo-JanetWebArmFireAt -Raw '' -Now $now)             | Should BeNullOrEmpty
        (ConvertTo-JanetWebArmFireAt -Raw '99:99' -Now $now)        | Should BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
Describe 'Arm request gate (Test-JanetWebArmRequest) - the typed word moves EARLIER' {

    $now = Get-Date '2026-07-25 22:00:00'
    function New-ArmParams {
        param([string]$Confirm = 'RESTART', $Dry = $false, [string]$Targets = "WS-A`nWS-B")
        @{ targets = $Targets; restartTime = '02:00'; confirm = $Confirm; dryRun = $Dry }
    }

    It 'accepts a live arm that carries the typed RESTART word' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams) -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $true
        $r.fireAt.ToString('yyyy-MM-dd HH:mm') | Should Be '2026-07-26 02:00'
    }
    It 'REFUSES a live arm with no confirm word' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams -Confirm '') -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $false
        $r.error | Should Match 'type RESTART'
    }
    It 'REFUSES a live arm whose confirm word is the wrong case (the engine compares -cne)' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams -Confirm 'restart') -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $false
        $r.error | Should Match 'type RESTART'
    }
    It 'exempts a dry run from the confirm word (matches the engine rule exactly)' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams -Confirm '' -Dry $true) -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $true
        $r.dryRun | Should Be $true
    }
    It 'reads the dry-run flag FAIL-CLOSED: a non-boolean value is treated as LIVE' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams -Confirm '' -Dry 'yes-please') -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $false
        $r.dryRun | Should Be $false
        $r.error | Should Match 'type RESTART'
    }
    It 'refuses an arm with no targets' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams -Targets '  ') -FireAtRaw '02:00' -Now $now
        $r.ok | Should Be $false
        $r.error | Should Match 'no targets'
    }
    It 'refuses a fire time in the past' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams) -FireAtRaw '2026-07-25T21:00:00' -Now $now
        $r.ok | Should Be $false
        $r.error | Should Match 'in the past'
    }
    It 'refuses a fire time beyond the max lead (an arm dies with the server, so it may not be days out)' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams) -FireAtRaw '2026-07-30T02:00:00' -Now $now -MaxHours 24
        $r.ok | Should Be $false
        $r.error | Should Match 'not be more than'
    }
    It 'refuses an unreadable fire time' {
        $r = Test-JanetWebArmRequest -Params (New-ArmParams) -FireAtRaw 'when I say so' -Now $now
        $r.ok | Should Be $false
        $r.error | Should Match 'could not read'
    }
}

# ---------------------------------------------------------------------------
Describe 'Armed restart HARD-EXPIRES and refuses to fire (Test-JanetWebArmShouldFire)' {

    $now  = Get-Date '2026-07-26 02:00:05'
    $sess = 'SESSION-ABC'
    function New-Arm {
        param([datetime]$FireAt = (Get-Date '2026-07-26 02:00:00'), [string]$Status = 'armed', [string]$SessionId = 'SESSION-ABC')
        New-JanetWebArmedRestart -Params @{ targets = 'WS-A'; confirm = 'RESTART' } -FireAt $FireAt -SessionId $SessionId -Operator 'tester'
    }

    It 'fires once the fire time is reached and the admin session is still armed' {
        $d = Test-JanetWebArmShouldFire -Arm (New-Arm) -Now $now -SessionArmed $true -SessionId $sess
        $d.fire   | Should Be $true
        $d.expire | Should Be $false
    }

    # THE headline safety property: the operator pressed End Session (or Clear
    # Credentials) after arming. The server drops AckGiven+Cred, so SessionArmed
    # goes false - and the wave must be discarded, never fired.
    It 'REFUSES TO FIRE after the operator session ends, and expires the arm' {
        $d = Test-JanetWebArmShouldFire -Arm (New-Arm) -Now $now -SessionArmed $false -SessionId $sess
        $d.fire   | Should Be $false
        $d.expire | Should Be $true
        $d.reason | Should Match 'admin session ended'
        $d.reason | Should Match 'REFUSING to fire'
    }
    It 'REFUSES TO FIRE when the logging session id changed under it' {
        $d = Test-JanetWebArmShouldFire -Arm (New-Arm -SessionId 'SESSION-OLD') -Now $now -SessionArmed $true -SessionId 'SESSION-NEW'
        $d.fire   | Should Be $false
        $d.expire | Should Be $true
        $d.reason | Should Match 'REFUSING to fire'
    }
    It 'REFUSES TO FIRE a stale wave (fire time long past - server stalled or the clock moved)' {
        $arm = New-Arm -FireAt (Get-Date '2026-07-26 02:00:00')
        $d = Test-JanetWebArmShouldFire -Arm $arm -Now (Get-Date '2026-07-26 03:30:00') -SessionArmed $true -SessionId $sess -GraceMinutes 10
        $d.fire   | Should Be $false
        $d.expire | Should Be $true
        $d.reason | Should Match 'stale wave'
    }
    It 'does neither before the fire time (it just keeps waiting)' {
        $d = Test-JanetWebArmShouldFire -Arm (New-Arm) -Now (Get-Date '2026-07-26 01:00:00') -SessionArmed $true -SessionId $sess
        $d.fire   | Should Be $false
        $d.expire | Should Be $false
    }
    It 'expires any arm that is not in the armed state (a fired/disarmed record can never re-fire)' {
        $arm = New-Arm
        $arm.Status = 'fired'
        $d = Test-JanetWebArmShouldFire -Arm $arm -Now $now -SessionArmed $true -SessionId $sess
        $d.fire   | Should Be $false
        $d.expire | Should Be $true
    }
    It 'does nothing at all when nothing is armed' {
        $d = Test-JanetWebArmShouldFire -Arm $null -Now $now -SessionArmed $true -SessionId $sess
        $d.fire   | Should Be $false
        $d.expire | Should Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'An armed restart NEVER touches disk' {

    # A unique host token so a stray write anywhere is unmistakable.
    $script:ArmSentinel = 'ARMSENTINEL' + ([guid]::NewGuid().ToString('N').Substring(0, 10)).ToUpperInvariant()
    $script:WatchDirs = @(
        (Join-Path $script:Root 'JanetLocal'),
        (Join-Path $env:TEMP 'JanetWeb'),
        (Join-Path $script:Root 'server'),
        (Join-Path $script:Root 'modules')
    )
    function Get-JanetArmDiskSnapshot {
        $snap = @{}
        foreach ($d in $script:WatchDirs) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                $snap[$f.FullName] = ('{0}|{1}' -f $f.Length, $f.LastWriteTimeUtc.Ticks)
            }
        }
        return $snap
    }

    $script:Before = Get-JanetArmDiskSnapshot

    # Build a REAL arm record - the same call the arm route makes - carrying the
    # sentinel host list and the typed confirm word.
    $script:Arm = New-JanetWebArmedRestart `
        -Params @{ targets = $script:ArmSentinel; confirm = 'RESTART'; message = "reboot $script:ArmSentinel" } `
        -FireAt ((Get-Date).AddMinutes(30)) -SessionId 'SESSION-DISK' -Operator 'tester'
    $script:After = Get-JanetArmDiskSnapshot

    It 'builds a real arm record carrying the sentinel host list' {
        $script:Arm.Status | Should Be 'armed'
        ([string]$script:Arm.Params['targets']) | Should Be $script:ArmSentinel
    }
    It 'creates no new file anywhere the server writes' {
        $added = @($script:After.Keys | Where-Object { -not $script:Before.ContainsKey($_) })
        ($added -join '; ') | Should Be ''
    }
    It 'modifies no existing file anywhere the server writes' {
        $changed = @($script:Before.Keys | Where-Object { $script:After.ContainsKey($_) -and $script:After[$_] -ne $script:Before[$_] })
        ($changed -join '; ') | Should Be ''
    }
    It 'leaves the armed host list nowhere on disk (grep for the sentinel)' {
        $hits = @()
        foreach ($d in $script:WatchDirs) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            $hits += @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue |
                        Select-String -SimpleMatch -Pattern $script:ArmSentinel -List -ErrorAction SilentlyContinue |
                        ForEach-Object { $_.Path })
        }
        ($hits -join '; ') | Should Be ''
    }
    It 'carries NO credential field - the fire reads the live in-memory session credential instead' {
        $keys = @($script:Arm.Keys | Where-Object { $_ -match '(?i)cred|password|secret|token' -and $_ -ne 'ArmId' })
        ($keys -join ',') | Should Be ''
    }
    It 'holds the arm in a plain in-memory hashtable (no file/task/registry handle behind it)' {
        $script:Arm -is [hashtable] | Should Be $true
    }
}

# ---------------------------------------------------------------------------
Describe 'Armed-restart HTTP surface (real listener)' {

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

    It 'test server starts' { $script:Up | Should Be $true }

    # --- the required auth-parity checks -----------------------------------
    It 'GET /api/jobs requires the per-launch session token' {
        $r = Invoke-JanetArmTestRequest 'GET' '/api/jobs' -Tok ''
        $r.Status | Should Be 403
        $r.Body | Should Match 'token'
    }
    It 'GET /api/jobs rejects a WRONG token (not just a missing one)' {
        $r = Invoke-JanetArmTestRequest 'GET' '/api/jobs' -Tok 'PESTER-ARM-TEST-TOKEN-000000000000'
        $r.Status | Should Be 403
    }
    It 'GET /api/jobs answers with the job list + armed slot for a valid token' {
        $r = Invoke-JanetArmTestRequest 'GET' '/api/jobs'
        $r.Status | Should Be 200
        $o = ConvertFrom-Json $r.Body
        @($o.jobs).Count | Should Be 0
        $o.armed | Should BeNullOrEmpty
    }
    It 'POST /api/armed-restart/disarm requires the session token' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/armed-restart/disarm' -Tok ''
        $r.Status | Should Be 403
    }
    It 'POST /api/armed-restart/disarm is a safe no-op when nothing is armed' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/armed-restart/disarm'
        $r.Status | Should Be 200
        $r.Body | Should Match '"disarmed":false'
    }

    # --- the arm route is admin-session gated, exactly like a live dispatch ---
    It 'POST arm-dispatch requires the session token' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/restart/action/arm-dispatch' -Tok ''
        $r.Status | Should Be 403
        $r.Body | Should Match 'token'
    }
    It 'POST arm-dispatch is REFUSED without an admin session (no ack, no credential)' {
        $body = '{"fireAt":"23:59","params":{"targets":"WS-A","confirm":"RESTART"}}'
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/restart/action/arm-dispatch' -Body $body
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }
    It 'gates arming at least as hard as running: dispatch-restart is refused the same way' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/restart/action/dispatch-restart'
        $r.Status | Should Be 403
        $r.Body | Should Match 'Admin session required'
    }

    # --- restart ONLY: there is no generic "arm any action" facility ---------
    It 'does NOT expose arm-dispatch for any other tool (wpt)' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/wpt/action/arm-dispatch'
        $r.Status | Should Be 404
        $r.Body | Should Match 'unknown action'
    }
    It 'does NOT expose arm-dispatch for any other tool (acas)' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/acas/action/arm-dispatch'
        $r.Status | Should Be 404
        $r.Body | Should Match 'unknown action'
    }
    It 'does not expose an arm route on GET' {
        $r = Invoke-JanetArmTestRequest 'GET' '/api/tool/restart/action/arm-dispatch'
        $r.Status | Should Be 404
    }

    # --- the refactored shared job launcher still starts real jobs ----------
    It 'still starts a normal read-only action and reports it through GET /api/jobs' {
        $r = Invoke-JanetArmTestRequest 'POST' '/api/tool/restart/action/ping' -Body '{"targets":"127.0.0.1"}'
        $r.Status | Should Be 200
        $jobId = (ConvertFrom-Json $r.Body).jobId
        $jobId | Should Not BeNullOrEmpty
        $seen = $false
        foreach ($i in 1..40) {
            $j = Invoke-JanetArmTestRequest 'GET' '/api/jobs'
            $o = ConvertFrom-Json $j.Body
            $row = @($o.jobs | Where-Object { $_.jobId -eq $jobId })
            if ($row.Count -eq 1 -and $row[0].tool -eq 'restart' -and $row[0].action -eq 'ping' -and $row[0].startedAt) { $seen = $true; break }
            Start-Sleep -Milliseconds 250
        }
        $seen | Should Be $true
    }

    It 'leaves no armed-restart artefact on disk after the whole HTTP pass' {
        $sus = @()
        foreach ($d in @((Join-Path $script:Root 'JanetLocal'), (Join-Path $env:TEMP 'JanetWeb'))) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            $sus += @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '(?i)arm' } | ForEach-Object { $_.FullName })
        }
        ($sus -join '; ') | Should Be ''
    }

    # teardown
    It 'test server shuts down' {
        if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force }
        Start-Sleep -Milliseconds 300
        $true | Should Be $true
    }
}
