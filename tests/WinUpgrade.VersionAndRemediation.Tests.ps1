# =============================================================================
#  WinUpgrade.VersionAndRemediation.Tests.ps1 - Pester 3.4 tests for the v0.4.0
#  PURE decision helpers on JanetWeb.winupgrade.psm1 (repair-health / auto-fix /
#  error-report), plus version-aware coverage of the fleet-status classifier:
#    - Get-WinUpgradeRepairVerdict : DISM exit code + sfc /scannow text -> row verdict
#    - Get-WinUpgradeAutoFixPlan   : per-device signals -> ordered fix-key plan
#    - Get-WinUpgradeErrorRowSet   : per-device signals -> error-report row set
#    - Get-WinUpgradeFleetStatus   : -MinBuild/-Version make the verdict target-aware
#  Every helper here is PURE (no WinRM, no registry, no process spawn) and is
#  MIRRORED inline by its worker branch (RepairHealth/AutoFix/ErrorReport run in a
#  bare pool runspace and cannot call back into this module) - these tests are the
#  single source of truth the mirrored code must match.
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.VersionAndRemediation.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

# -----------------------------------------------------------------------------
# Get-WinUpgradeRepairVerdict
# -----------------------------------------------------------------------------
Describe 'Get-WinUpgradeRepairVerdict - DISM exit code + sfc text -> row verdict' {

    It 'dism 0 + "did not find any integrity violations" -> CLEAN, no reboot' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'Windows Resource Protection did not find any integrity violations.' }
        $v.Dism         | Should Be 'OK'
        $v.Sfc          | Should Be 'no violations'
        $v.Status       | Should Be 'CLEAN'
        $v.RebootNeeded | Should Be $false
    }

    It 'dism 3010 -> reboot needed, Dism "OK (reboot)"' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 3010 -SfcText 'did not find any integrity violations' }
        $v.Dism         | Should Be 'OK (reboot)'
        $v.RebootNeeded | Should Be $true
    }

    It 'sfc "successfully repaired" -> REPAIRED + reboot' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'Windows Resource Protection found corrupt files and successfully repaired them.' }
        $v.Sfc          | Should Be 'repaired'
        $v.Status       | Should Be 'REPAIRED'
        $v.RebootNeeded | Should Be $true
    }

    It 'sfc "unable to fix" -> PARTIAL' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'Windows Resource Protection found corrupt files but was unable to fix some of them.' }
        $v.Sfc    | Should Be 'could not fix'
        $v.Status | Should Be 'PARTIAL'
    }

    It 'sfc "could not fix" -> PARTIAL' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'Windows Resource Protection found corrupt files but could not fix all of them.' }
        $v.Sfc    | Should Be 'could not fix'
        $v.Status | Should Be 'PARTIAL'
    }

    It 'sfc "could not perform the requested operation" -> blocked (pending repair), PARTIAL' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'Windows Resource Protection could not perform the requested operation.' }
        $v.Sfc    | Should Be 'blocked (pending repair)'
        $v.Status | Should Be 'PARTIAL'
    }

    It 'dism nonzero exit -> verdict reflects failure (FAILED), regardless of sfc' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 1 -SfcText 'did not find any integrity violations' }
        $v.Dism   | Should Be 'exit 1'
        $v.Status | Should Be 'FAILED'
    }

    It 'DismError flag -> dism "error", Status FAILED' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'did not find any integrity violations' -DismError $true }
        $v.Dism   | Should Be 'error'
        $v.Status | Should Be 'FAILED'
    }

    It 'a null DismExit (no exit code captured) -> dism "error"' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit $null -SfcText 'did not find any integrity violations' }
        $v.Dism | Should Be 'error'
    }

    It 'SfcError flag -> sfc "error", Status FAILED even when dism is clean' {
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'anything' -SfcError $true }
        $v.Sfc    | Should Be 'error'
        $v.Status | Should Be 'FAILED'
    }

    It 'null-byte-laden sfc text (UTF-16 read-as-ASCII artifact) still matches after null-stripping' {
        # Simulates a UTF-16 buffer decoded as single-byte text: every character is
        # interleaved with a literal NUL. The function strips `0 before matching.
        $garbled = "Windows Resource Protection found corrupt files but was unable to f`0i`0x`0 some of them."
        $v = & $m { param($t) Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText $t } $garbled
        $v.Sfc    | Should Be 'could not fix'
        $v.Status | Should Be 'PARTIAL'
    }

    It 'unrecognized / empty sfc text reads UNKNOWN -> PARTIAL, never a false CLEAN (loop37 #31 fail-close)' {
        # Was the module's old fallback (no keyword matched -> "no violations" -> CLEAN), flagged in
        # the report as a false-negative risk. loop37 closed it: an unparseable/localized/truncated sfc
        # now reads 'unknown' and the verdict is PARTIAL (not confirmed clean), never CLEAN.
        $v = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText 'some unrecognized sfc output' }
        $v.Sfc    | Should Be 'unknown'
        $v.Status | Should Be 'PARTIAL'
        $v2 = & $m { Get-WinUpgradeRepairVerdict -DismExit 0 -SfcText '' }
        $v2.Sfc    | Should Be 'unknown'
        $v2.Status | Should Not Be 'CLEAN'
    }
}

# -----------------------------------------------------------------------------
# Get-WinUpgradeAutoFixPlan
# -----------------------------------------------------------------------------
Describe 'Get-WinUpgradeAutoFixPlan - per-device signals -> ordered fix-key plan' {

    It 'already on/above minBuild -> empty plan' {
        (& $m { Get-WinUpgradeAutoFixPlan -Build 26100 -MinBuild 26100 -PolicyComplete $false -CpuSupported $false -TpmSupported $false -FailedDrivers $true -PauseExpired $true -Corruption $true -StagingClass 'Stale' }).Count | Should Be 0
        (& $m { Get-WinUpgradeAutoFixPlan -Build 27000 -MinBuild 26100 }).Count | Should Be 0
    }

    It 'everything-broken host -> full plan, in apply order' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $false -CpuSupported $false -TpmSupported $false -BypassActive $false -FailedDrivers $true -PauseExpired $true -Corruption $true -StagingClass 'Stale' })
        $plan.Count | Should Be 6
        $plan[0] | Should Be 'policy'
        $plan[1] | Should Be 'bypass'
        $plan[2] | Should Be 'drivers'
        $plan[3] | Should Be 'pause'
        $plan[4] | Should Be 'repair'
        $plan[5] | Should Be 'staging'
    }

    It 'policy half-written (TRV=1, Product/Info blank) drives PolicyComplete=false -> policy included' {
        # Wire the two pure helpers together the way the worker does: a half-written
        # pin means "not complete", which is what feeds Get-WinUpgradeAutoFixPlan.
        $halfWritten = & $m { Test-WinUpgradeTrvHalfWritten -TargetReleaseVersion 1 -ProductVersion '' -TargetReleaseVersionInfo '24H2' }
        $halfWritten | Should Be $true
        $plan = (& $m { param($complete) Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete (-not $complete) } $halfWritten)
        ($plan -contains 'policy') | Should Be $true
    }

    It 'hardware supported -> bypass excluded even when a bypass would otherwise be requested' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -BypassActive $false })
        ($plan -contains 'bypass') | Should Be $false
    }

    It 'bypass already set -> excluded even though hardware is unsupported' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $false -TpmSupported $false -BypassActive $true })
        ($plan -contains 'bypass') | Should Be $false
    }

    It 'hardware unsupported and no bypass yet -> bypass included' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $false -TpmSupported $true -BypassActive $false })
        ($plan -contains 'bypass') | Should Be $true
    }

    It 'active (non-expired) pause -> pause fix excluded' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -PauseExpired $false })
        ($plan -contains 'pause') | Should Be $false
    }

    It 'expired pause -> pause fix included' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -PauseExpired $true })
        ($plan -contains 'pause') | Should Be $true
    }

    It 'no corruption signatures -> repair excluded' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -Corruption $false })
        ($plan -contains 'repair') | Should Be $false
    }

    It 'corruption signature present -> repair included' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -Corruption $true })
        ($plan -contains 'repair') | Should Be $true
    }

    It 'staging not stale (Recent/Active/None) -> staging clear excluded' {
        foreach ($class in 'Recent','Active','None') {
            $plan = (& $m { param($c) Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -StagingClass $c } $class)
            ($plan -contains 'staging') | Should Be $false
        }
    }

    It 'staging Stale -> staging clear included' {
        $plan = (& $m { Get-WinUpgradeAutoFixPlan -Build 22631 -MinBuild 26100 -PolicyComplete $true -CpuSupported $true -TpmSupported $true -StagingClass 'Stale' })
        ($plan -contains 'staging') | Should Be $true
    }

    It '25H2 minBuild 26200 gates correctly: a 26100 host (24H2, below 25H2) still gets a plan' {
        (& $m { Get-WinUpgradeAutoFixPlan -Build 26100 -MinBuild 26200 }).Count | Should Not Be 0
        (& $m { Get-WinUpgradeAutoFixPlan -Build 26200 -MinBuild 26200 }).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
# Get-WinUpgradeErrorRowSet
# -----------------------------------------------------------------------------
Describe 'Get-WinUpgradeErrorRowSet - per-device signals -> error-report row set' {

    # NOTE: Get-WinUpgradeErrorRowSet always returns via a unary-comma-protected
    # array (`,@(...)` / `,($rows.ToArray())`) so the value crossing the & $m {}
    # module-scope-invoke boundary is ALREADY a genuine array - do NOT re-wrap
    # the call site in another @(...): that adds a spurious extra array level
    # (the real array becomes a single element INSIDE a 1-item outer array),
    # which silently corrupts .Count and property access for anything but the
    # single-row case. Assign the call's result directly.

    It 'a clean host (no signals, already-scanned) -> exactly one NONE / INFO row' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -MinDisk 64 }
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'NONE'
        $rows[0].Severity | Should Be 'INFO'
        $rows[0].Evidence | Should Be 'No upgrade errors detected'
    }

    It 'a host already on/above the target build -> one NONE row mentioning the build' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 26100 -MinBuild 26100 -Version '24H2' }
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'NONE'
        $rows[0].Severity | Should Be 'INFO'
        $rows[0].Evidence | Should Match '26100'
        $rows[0].Evidence | Should Match '24H2'
    }

    It 'single-issue host returns an ARRAY of one row (regression: single-element unroll was a real bug)' {
        # Deliberately NOT wrapped in @() at the call site - @() would mask the very
        # regression this pins (a bare 1-item array unrolling to a scalar hashtable
        # across the return / module-scope-invoke boundary).
        $result = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 -MinDisk 64 }
        ($result -is [array]) | Should Be $true
        $result.Count | Should Be 1
        $result[0].Category | Should Be 'DISK'
    }

    It 'DISK: free space below the minimum -> DISK / BLOCK' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 -MinDisk 64 }
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'DISK'
        $rows[0].Severity | Should Be 'BLOCK'
    }

    It 'DRIVER: a failed-injection INF -> DRIVER / WARN' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -FailedDrivers @('oem12.inf') }
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'DRIVER'
        $rows[0].Severity | Should Be 'WARN'
    }

    It 'REGISTRY: a REGISTRY_CORRUPT signature -> REGISTRY / BLOCK' {
        $sigs = @(@{ Code='REGISTRY_CORRUPT'; Message='registry hive corrupt'; Rec='RestoreHealth' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'REGISTRY'
        $rows[0].Severity | Should Be 'BLOCK'
    }

    It 'COMPONENT_STORE: a COMPONENT_STORE signature -> COMPONENT_STORE / BLOCK' {
        $sigs = @(@{ Code='COMPONENT_STORE'; Message='component store broken'; Rec='DISM /RestoreHealth' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows[0].Category | Should Be 'COMPONENT_STORE'
        $rows[0].Severity | Should Be 'BLOCK'
    }

    It 'MEMORY: an OOM signature -> MEMORY / BLOCK' {
        $sigs = @(@{ Code='OOM'; Message='out of memory'; Rec='Set Page File' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows[0].Category | Should Be 'MEMORY'
        $rows[0].Severity | Should Be 'BLOCK'
    }

    It 'ADLDS: an ADLDS_MIGRATE signature -> ADLDS / WARN' {
        $sigs = @(@{ Code='ADLDS_MIGRATE'; Message='adammigrate.dll failed'; Rec='n/a' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows[0].Category | Should Be 'ADLDS'
        $rows[0].Severity | Should Be 'WARN'
    }

    It 'PAUSED (SETUP_CANCELLED signature) -> PAUSED / WARN' {
        $sigs = @(@{ Code='SETUP_CANCELLED'; Message='setup cancelled'; Rec='clear pause' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows[0].Category | Should Be 'PAUSED'
        $rows[0].Severity | Should Be 'WARN'
    }

    It 'PAUSED (active) -> PAUSED / BLOCK' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -PauseActive $true }
        $rows[0].Category | Should Be 'PAUSED'
        $rows[0].Severity | Should Be 'BLOCK'
    }

    It 'PAUSED (expired) -> PAUSED / WARN, and active wins over expired when both set' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -PauseExpired $true }
        $rows[0].Category | Should Be 'PAUSED'
        $rows[0].Severity | Should Be 'WARN'

        $rowsBoth = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -PauseActive $true -PauseExpired $true }
        @($rowsBoth | Where-Object { $_.Category -eq 'PAUSED' }).Count | Should Be 1
        ($rowsBoth | Where-Object { $_.Category -eq 'PAUSED' }).Severity | Should Be 'BLOCK'
    }

    It 'POLICY (half-written) -> POLICY / WARN, half-written wins over missing when both set' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -PolicyHalfWritten $true }
        $rows[0].Category | Should Be 'POLICY'
        $rows[0].Severity | Should Be 'WARN'
        $rows[0].Evidence | Should Match 'HALF-WRITTEN'
    }

    It 'POLICY (missing) -> POLICY / WARN' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -PolicyMissing $true }
        $rows[0].Category | Should Be 'POLICY'
        $rows[0].Severity | Should Be 'WARN'
    }

    It 'STAGING (stale) -> STAGING / INFO' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -StagingClass 'Stale' -StagingGB 12.5 }
        $rows[0].Category | Should Be 'STAGING'
        $rows[0].Severity | Should Be 'INFO'
        $rows[0].Evidence | Should Match '12.5'
    }

    It 'SETUPDIAG: a matched profile -> SETUPDIAG / WARN' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -SetupDiagProfile 'RollbackFromSafeOS' }
        $rows[0].Category | Should Be 'SETUPDIAG'
        $rows[0].Severity | Should Be 'WARN'
        $rows[0].Evidence | Should Match 'RollbackFromSafeOS'
    }

    It 'a multi-issue host -> one row per issue, with the correct Category set' {
        $sigs = @(
            @{ Code='REGISTRY_CORRUPT'; Message='registry hive corrupt'; Rec='RestoreHealth' },
            @{ Code='OOM'; Message='out of memory'; Rec='Set Page File' }
        )
        $rows = & $m {
            param($s)
            Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 -MinDisk 64 `
                -FailedDrivers @('oem7.inf') -Signatures $s -PauseExpired $true `
                -PolicyMissing $true -StagingClass 'Stale' -StagingGB 5 -SetupDiagProfile 'FooProfile'
        } $sigs

        # DISK + DRIVER + REGISTRY + MEMORY(OOM) + PAUSED(expired) + POLICY(missing) + STAGING + SETUPDIAG
        $rows.Count | Should Be 8
        $cats = @($rows | ForEach-Object { $_.Category }) | Sort-Object -Unique
        $expected = @('DISK','DRIVER','MEMORY','PAUSED','POLICY','REGISTRY','SETUPDIAG','STAGING') | Sort-Object
        (Compare-Object $cats $expected) | Should Be $null
    }

    It 'Evidence is trimmed to <= 200 chars even for an oversized message' {
        $longMsg = 'X' * 500
        $sigs = @(@{ Code='REGISTRY_CORRUPT'; Message=$longMsg; Rec='RestoreHealth' })
        $rows = & $m { param($s) Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -Signatures $s } $sigs
        $rows[0].Evidence.Length | Should Be 200
    }

    It 'Severity values are only ever BLOCK|WARN|INFO across every row shape' {
        $sigs = @(
            @{ Code='REGISTRY_CORRUPT'; Message='a'; Rec='b' },
            @{ Code='COMPONENT_STORE'; Message='a'; Rec='b' },
            @{ Code='OOM'; Message='a'; Rec='b' },
            @{ Code='ADLDS_MIGRATE'; Message='a'; Rec='b' },
            @{ Code='SETUP_CANCELLED'; Message='a'; Rec='b' }
        )
        $rows = & $m {
            param($s)
            Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 -MinDisk 64 `
                -FailedDrivers @('oem1.inf') -Signatures $s -PauseActive $true `
                -PolicyHalfWritten $true -StagingClass 'Stale' -SetupDiagProfile 'X'
        } $sigs
        foreach ($r in $rows) {
            (@('BLOCK','WARN','INFO') -contains $r.Severity) | Should Be $true
        }
    }
}

# -----------------------------------------------------------------------------
# Get-WinUpgradeFleetStatus - version-aware target (MinBuild / Version params)
# -----------------------------------------------------------------------------
Describe 'Get-WinUpgradeFleetStatus - version-aware target (25H2 gate)' {

    It '-MinBuild 26200 -Version "25H2": a build >= 26200 host -> Already 25H2+' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26200 -Online $true -Eligible $true -MinBuild 26200 -Version '25H2' }) | Should Be 'Already 25H2+'
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 27000 -Online $true -Eligible $true -MinBuild 26200 -Version '25H2' }) | Should Be 'Already 25H2+'
    }

    It '-MinBuild 26200 -Version "25H2": a 24H2 host (26100, below the 25H2 gate) -> Ready, not Already' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26100 -Online $true -Eligible $true -MinBuild 26200 -Version '25H2' }) | Should Be 'Ready'
    }

    It 'defaults (no -MinBuild/-Version passed) still behave as 24H2 / build 26100' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26100 -Online $true -Eligible $true }) | Should Be 'Already 24H2+'
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26099 -Online $true -Eligible $true }) | Should Be 'Ready'
    }
}
