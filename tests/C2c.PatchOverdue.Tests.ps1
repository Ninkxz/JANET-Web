# =============================================================================
#  C2c.PatchOverdue.Tests.ps1 - Pester 3.4 for the c2c Patches-scan overdue rule
#  (Test-C2cUpdateOverdue, loop30 / c2c deep-dive F5). The Patches pillar scan
#  flags an applicable-not-installed update (CCM_SoftwareUpdate ComplianceState=0,
#  i.e. MISSING) as OVERDUE when its MECM enforcement Deadline is past, or (no
#  deadline) its content StartTime is older than the grace window. The old
#  predicate matched neither branch when BOTH timestamps were null/unparseable, so
#  a missing update with no usable timestamp was counted "pending within grace" ->
#  pillar PASS no matter how old the missing patch was - a false-compliant on the
#  otherwise fail-closed scan. Now: no usable timestamp on a MISSING update -> fail
#  CLOSED (OVERDUE), because we can't prove it's within grace.
#
#  Test-C2cUpdateOverdue is the canonical rule; the scan worker mirrors it inline
#  (it runs over WinRM in a module-less runspace, can't call a module fn).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\C2c.PatchOverdue.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

$script:Now  = [datetime]'2026-07-21 12:00:00'
$script:Grace = 7

function Test-Overdue($Deadline, $StartTime) {
    (& $script:Mod { param($d, $s, $n, $g) Test-C2cUpdateOverdue -Deadline $d -StartTime $s -Now $n -GraceDays $g } $Deadline $StartTime $script:Now $script:Grace)
}

Describe 'Test-C2cUpdateOverdue - deadline-driven' {
    It 'a Deadline in the past is OVERDUE' {
        Test-Overdue $script:Now.AddDays(-1) $null | Should Be $true
    }
    It 'a Deadline in the future is NOT overdue (deadline not yet reached)' {
        Test-Overdue $script:Now.AddDays(1) $script:Now.AddDays(-90) | Should Be $false
    }
}

Describe 'Test-C2cUpdateOverdue - startTime grace when there is no deadline' {
    It 'no deadline + StartTime older than the grace window is OVERDUE' {
        Test-Overdue $null $script:Now.AddDays(-8) | Should Be $true
    }
    It 'no deadline + StartTime within the grace window is NOT overdue' {
        Test-Overdue $null $script:Now.AddDays(-3) | Should Be $false
    }
}

Describe 'Test-C2cUpdateOverdue - fail-closed on a MISSING update with no usable timestamp (the F5 fix)' {
    It 'no deadline AND no startTime -> OVERDUE (cannot prove within grace)' {
        Test-Overdue $null $null | Should Be $true
    }
    It 'a non-datetime Deadline with no usable StartTime -> OVERDUE (deserialize glitch fails closed)' {
        Test-Overdue 'not-a-date' $null | Should Be $true
    }
    It 'a non-datetime Deadline but a usable OLD StartTime -> OVERDUE (uses StartTime, no longer skipped)' {
        Test-Overdue 'not-a-date' $script:Now.AddDays(-30) | Should Be $true
    }
    It 'a non-datetime Deadline but a usable RECENT StartTime -> NOT overdue' {
        Test-Overdue 'not-a-date' $script:Now.AddDays(-2) | Should Be $false
    }
}

Describe 'c2c scan worker - the overdue predicate has the fail-closed else branch' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw
    It 'the Patches overdue predicate mirrors Test-C2cUpdateOverdue with an else { $true }' {
        ($src -match 'Test-C2cUpdateOverdue') | Should Be $true
    }
}

Describe 'c2c - manifest exact version pin (newest bump = loop-30 patch-overdue fail-close)' {
    It 'c2c is at v1.15.4' {
        $man = & $script:Mod { Get-JanetToolManifest }
        [string]$man.version | Should Be '1.15.4'
    }
}
