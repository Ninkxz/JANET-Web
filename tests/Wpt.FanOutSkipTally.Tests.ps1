# =============================================================================
#  Wpt.FanOutSkipTally.Tests.ps1 - Pester 3.4, audit 2026-07-25 (fable re-audit
#  follow-up). BEHAVIOURAL: Invoke-WptFanOut is actually EXECUTED (real
#  RunspacePool, fake in-process workers - no host contact) and the emitted
#  event stream is asserted.
#
#  The bug: the "EVERY host failed" banner added in 6.10.1 keyed off
#  "$okCount -eq 0", i.e. ANY not-ok host counted toward "failed". A kb-install of
#  a KB that is not deployed in MECM with no MSU, against 10 HEALTHY hosts, is
#  honestly "No change" on every row and audits 'Skipped' every time - and still
#  raised "EVERY host failed (0 of 10 succeeded) - treat this as a failed run".
#  The audit trail stayed honest; the BANNER lied. The same shape hit an
#  all-Pending app-update-apply and an all-cancelled run (where the banner also
#  stacked on top of the cancel warn). The skipped hosts also inflated the
#  "Done. X ok, Y failed" status line so it contradicted the audits beside it.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.FanOutSkipTally.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

# Drive the real harvester over N fake hosts and hand back every emitted event
# plus the summary. $Work runs in a bare pool runspace and only shapes a result.
function Invoke-FanOutProbe {
    param(
        [scriptblock]$Work,
        [scriptblock]$OkOf,
        [scriptblock]$AuditResultOf,
        [string]$ActionId = 'kb-install',
        [int]$HostCount   = 10
    )
    $events  = New-Object System.Collections.ArrayList
    $send    = { param($e) [void]$events.Add($e) }.GetNewClosure()
    $targets = @(1..$HostCount | ForEach-Object { "FAKE-WS-$_" })
    $res = & $script:Mod {
        param($t, $w, $okf, $arf, $s, $aid)
        Invoke-WptFanOut -Targets $t -Threads 4 -ActionId $aid -Send $s `
            -Work $w -AuditAction 'VulnPatched' `
            -ArgFactory { param($h) ,@($h) } `
            -OkOf $okf -AuditResultOf $arf `
            -AuditDetail { param($r) "d:$($r.Host)" } `
            -RowOf { param($r) @{ Host = $r.Host } }
    } $targets $Work $OkOf $AuditResultOf $send $ActionId
    return @{ Events = @($events.ToArray()); Summary = $res.summary; Rows = @($res.rows) }
}

function Get-BannerCount { param($p) @($p.Events | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'EVERY host failed' }).Count }
function Get-DoneText    { param($p) [string](@($p.Events | Where-Object { $_.type -eq 'status' -and "$($_.text)" -match '^Done\.' }) | Select-Object -Last 1).text }
function Get-AuditResults{ param($p) @($p.Events | Where-Object { $_.type -eq 'audit' } | ForEach-Object { [string]$_.result }) }

# kb-install's real OkOf / AuditResultOf (module lines ~6347 / ~6352).
$script:KbOk    = { param($r) (@($r.Errors).Count -eq 0) -and ((([int]$r.MECMInstalled) + ([int]$r.MSUInstalled)) -gt 0) }
$script:KbAudit = { param($r, $ok) if ($ok) { 'Success' } elseif (@($r.Errors).Count -eq 0) { 'Skipped' } else { 'Failure' } }

Describe 'fan-out: an all-SKIPPED run is not an all-FAILED run (audit 2026-07-25)' {
    # kb-install of a KB not in MECM, no MSU, against 10 healthy hosts: every host
    # reports zero errors and installs nothing -> honest 'No change' / 'Skipped'.
    $script:AllSkip = Invoke-FanOutProbe `
        -Work { param($h) @{ Host = $h; Errors = @(); MECMFound = 0; MECMInstalled = 0; MSUInstalled = 0; Skipped = 1 } } `
        -OkOf $script:KbOk -AuditResultOf $script:KbAudit

    It 'every host audits Skipped (the audit trail is honest)' {
        $r = Get-AuditResults $script:AllSkip
        $r.Count | Should Be 10
        (@($r | Where-Object { $_ -eq 'Skipped' }).Count) | Should Be 10
    }
    It 'the "EVERY host failed" banner is NOT emitted' {
        (Get-BannerCount $script:AllSkip) | Should Be 0
    }
    It 'summary.allFailed is false' {
        [bool]$script:AllSkip.Summary.allFailed | Should Be $false
    }
    It 'the status line agrees with the audit trail (0 failed, 10 skipped)' {
        $script:AllSkip.Summary.ok      | Should Be 0
        $script:AllSkip.Summary.failed  | Should Be 0
        $script:AllSkip.Summary.skipped | Should Be 10
        (Get-DoneText $script:AllSkip)  | Should Be 'Done. 0 ok, 0 failed, 10 skipped of 10.'
    }
}

Describe 'fan-out: an all-PENDING app-update-apply is not an all-FAILED run (audit 2026-07-25)' {
    # app-update-apply's real OkOf / AuditResultOf (module lines ~6773 / ~6774).
    $script:AllPending = Invoke-FanOutProbe -ActionId 'app-update-apply' -HostCount 6 `
        -Work { param($h) @{ Host = $h; Status = 'Pending'; Detail = 'reboot pending' } } `
        -OkOf { param($r) ($r.Status -eq 'OK') } `
        -AuditResultOf { param($r, $ok) if ($ok) { 'Success' } elseif ("$($r.Status)" -eq 'Pending' -or "$($r.Status)" -eq 'Skipped') { 'Skipped' } else { 'Failure' } }

    It 'no banner, allFailed false, and the pending hosts are tallied as skipped' {
        (Get-BannerCount $script:AllPending)     | Should Be 0
        [bool]$script:AllPending.Summary.allFailed | Should Be $false
        $script:AllPending.Summary.failed        | Should Be 0
        $script:AllPending.Summary.skipped       | Should Be 6
    }
}

Describe 'fan-out: a GENUINE all-failure still raises the alarm (no weakening)' {
    $script:AllFail = Invoke-FanOutProbe -HostCount 5 `
        -Work { param($h) @{ Host = $h; Errors = @('WinRM connect failed'); MECMFound = 0; MECMInstalled = 0; MSUInstalled = 0; Skipped = 0 } } `
        -OkOf $script:KbOk -AuditResultOf $script:KbAudit

    It 'every host audits Failure' {
        (@((Get-AuditResults $script:AllFail) | Where-Object { $_ -eq 'Failure' }).Count) | Should Be 5
    }
    It 'the banner IS emitted and summary.allFailed is true' {
        (Get-BannerCount $script:AllFail)        | Should Be 1
        [bool]$script:AllFail.Summary.allFailed  | Should Be $true
        $script:AllFail.Summary.failed           | Should Be 5
        $script:AllFail.Summary.skipped          | Should Be 0
    }
    It 'the done line keeps its historic shape when nothing was skipped' {
        (Get-DoneText $script:AllFail) | Should Be 'Done. 0 ok, 5 failed of 5.'
    }
}

Describe 'fan-out: a mixed skipped/failed run is not "EVERY host failed" either' {
    # 3 honest no-change hosts + 3 broken ones, zero successes: real failures exist,
    # but "EVERY host failed" is still untrue - do not raise it.
    $script:Mixed = Invoke-FanOutProbe -HostCount 6 `
        -Work { param($h) if (([int]($h -replace '\D','')) -le 3) { @{ Host=$h; Errors=@(); MECMInstalled=0; MSUInstalled=0; Skipped=1 } } else { @{ Host=$h; Errors=@('boom'); MECMInstalled=0; MSUInstalled=0; Skipped=0 } } } `
        -OkOf $script:KbOk -AuditResultOf $script:KbAudit

    It 'banner suppressed, tallies split 3 failed / 3 skipped' {
        (Get-BannerCount $script:Mixed)       | Should Be 0
        [bool]$script:Mixed.Summary.allFailed | Should Be $false
        $script:Mixed.Summary.failed          | Should Be 3
        $script:Mixed.Summary.skipped         | Should Be 3
        (Get-DoneText $script:Mixed)          | Should Be 'Done. 0 ok, 3 failed, 3 skipped of 6.'
    }
}

Describe 'fan-out: a CANCELLED run does not stack the all-failed banner on the cancel warn' {
    It 'the harvester only raises allFailed for a completed run' {
        $events = New-Object System.Collections.ArrayList
        $send   = { param($e) [void]$events.Add($e) }.GetNewClosure()
        $res = & $script:Mod {
            param($s)
            Invoke-WptFanOut -Targets @('FAKE-WS-1','FAKE-WS-2','FAKE-WS-3') -Threads 3 -ActionId 'kb-install' -Send $s `
                -Work { param($h) Start-Sleep -Seconds 30; @{ Host = $h } } `
                -AuditAction 'VulnPatched' -PollMilliseconds 60 `
                -CancelCheck { $true } `
                -ArgFactory { param($h) ,@($h) } `
                -OkOf { param($r) $false } `
                -AuditDetail { param($r) 'd' } `
                -RowOf { param($r) @{ Host = $r.Host } }
        } $send
        [bool]$res.summary.cancelled | Should Be $true
        [bool]$res.summary.allFailed | Should Be $false
        (@($events | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'EVERY host failed' }).Count) | Should Be 0
    }
}
