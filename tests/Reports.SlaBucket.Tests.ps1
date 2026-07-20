# =============================================================================
#  Reports.SlaBucket.Tests.ps1 - Pester 3.4 for the remediation-SLA boundary
#  math. Two operator-facing views compute the SLA overdue/due-soon/on-track
#  buckets: the SLA / Finding Aging dashboard (sla-aging) and the Executive
#  Command Brief SLA section. They MUST agree - a divergence means the two
#  compliance numbers for the same fleet disagree. loop21 consolidates the
#  boundary rule into ONE pure helper (Get-ReportsSlaBucket) that both call, so
#  the rule can't drift, and pins it here.
#
#  The rule: OVERDUE when past the deadline (dueIn < 0); DUE-SOON within the
#  tightest of 25% of the window or 3 days left (dueIn <= max(3, ceil(0.25*window)));
#  ON-TRACK otherwise. The deadline day itself (dueIn == 0) is DUE-SOON, not overdue.
#  Also pins Get-ReportsSlaDeadline (KEV overrides severity; Info -> Low; unknown -> Medium).
#
#  Pure functions, no I/O. Run:  Invoke-Pester -Path .\tests\Reports.SlaBucket.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

function Get-Bucket([int]$Deadline, [int]$Age) {
    (& $script:Mod { param($d, $a) Get-ReportsSlaBucket -Deadline $d -Age $a } $Deadline $Age)
}
function Get-Deadline([string]$Severity, [bool]$InKev) {
    (& $script:Mod {
        param($sev, $kev)
        $cfg = Get-ReportsSlaDefaults
        Get-ReportsSlaDeadline -Config $cfg -Severity $sev -InKev $kev
    } $Severity $InKev)
}

Describe 'Get-ReportsSlaBucket - the boundary rule (deadline=30 day window)' {
    It 'brand-new finding is ON-TRACK' {
        $b = Get-Bucket 30 0
        $b.DueIn  | Should Be 30
        $b.Bucket | Should Be 'ON-TRACK'
    }
    It 'soon threshold for a 30-day window is max(3, ceil(7.5)) = 8' {
        (Get-Bucket 30 0).SoonThreshold | Should Be 8
    }
    It 'exactly at the soon threshold (dueIn = 8) is DUE-SOON' {
        (Get-Bucket 30 22).Bucket | Should Be 'DUE-SOON'   # 30-22 = 8
    }
    It 'just inside the threshold (dueIn = 9) is still ON-TRACK' {
        (Get-Bucket 30 21).Bucket | Should Be 'ON-TRACK'   # 30-21 = 9
    }
    It 'the deadline day itself (dueIn = 0) is DUE-SOON, not OVERDUE' {
        $b = Get-Bucket 30 30
        $b.DueIn  | Should Be 0
        $b.Bucket | Should Be 'DUE-SOON'
    }
    It 'one day past the deadline (dueIn = -1) is OVERDUE' {
        $b = Get-Bucket 30 31
        $b.DueIn  | Should Be -1
        $b.Bucket | Should Be 'OVERDUE'
    }
}

Describe 'Get-ReportsSlaBucket - the 3-day floor beats 25% on a short (KEV) window' {
    It 'a 7-day window uses the 3-day floor (max(3, ceil(1.75)) = 3)' {
        (Get-Bucket 7 0).SoonThreshold | Should Be 3
    }
    It 'a 4-day window still floors the soon threshold at 3 (not ceil(1) = 1)' {
        (Get-Bucket 4 0).SoonThreshold | Should Be 3
    }
    It 'dueIn = 3 on a 4-day window is DUE-SOON (floor applies)' {
        (Get-Bucket 4 1).Bucket | Should Be 'DUE-SOON'    # 4-1 = 3 <= 3
    }
    It 'dueIn = 4 on a 4-day window is ON-TRACK' {
        (Get-Bucket 4 0).Bucket | Should Be 'ON-TRACK'    # 4-0 = 4 > 3
    }
}

Describe 'Get-ReportsSlaBucket - a zero/absent deadline never divides by zero' {
    It 'deadline 0 uses a window floor of 1 and soon = 3' {
        $b = Get-Bucket 0 0
        $b.Window        | Should Be 1
        $b.SoonThreshold | Should Be 3
        $b.Bucket        | Should Be 'DUE-SOON'   # dueIn 0 -> DUE-SOON
    }
}

Describe 'Get-ReportsSlaDeadline - severity map + KEV override (embedded defaults)' {
    It 'KEV overrides the severity window with the tightest (7)' {
        Get-Deadline 'Low' $true | Should Be 7
    }
    It 'Critical -> 21' { Get-Deadline 'Critical' $false | Should Be 21 }
    It 'High -> 30'     { Get-Deadline 'High'     $false | Should Be 30 }
    It 'Medium -> 90'   { Get-Deadline 'Medium'   $false | Should Be 90 }
    It 'Low -> 180'     { Get-Deadline 'Low'      $false | Should Be 180 }
    It 'Info falls back to the Low window (180)' { Get-Deadline 'Info' $false | Should Be 180 }
    It 'an unknown severity falls back to the Medium window (90)' { Get-Deadline 'Bogus' $false | Should Be 90 }
}
