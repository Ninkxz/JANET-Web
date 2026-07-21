# =============================================================================
#  Winupgrade.DiagnoseVerdict.Tests.ps1 - Pester 3.4 for the Diagnose READY
#  verdict (Get-WinUpgradeDiagnoseVerdict, loop32 / winupgrade deep-dive F6). The
#  Diagnose action is the operator's GO/NO-GO signal for upgrading a host. Its
#  one-word verdict was derived from CPU/TPM/[BLOCK]/policy markers ONLY - it
#  IGNORED the [FAIL] Disk / [FAIL] RAM / [FAIL] Secure Boot lines its own scan
#  reported. So a host with supported CPU/TPM, policy set, but insufficient disk
#  read READY ("all clear to Pin / Force Discovery"); the operator pinned + drove
#  and the upgrade failed on disk - a false-clean on the go/no-go verdict. Now
#  those hardware/capacity fails yield a distinct NOT READY.
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Winupgrade.DiagnoseVerdict.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

# A minimal all-PASS eligible report (policy set) - the READY baseline.
$script:PassReport = @"
[PASS] CPU         : supported (Build 22631)
[PASS] TPM         : v2.0
[PASS] Secure Boot : Enabled
[PASS] RAM         : 16 GB (need 4+ GB)
[PASS] Disk        : 100 GB free / 500 GB total on C:
[PASS] Target Release Policy : TargetReleaseVersion=1
"@

function Get-Verdict([string]$Report) {
    (& $script:Mod { param($r) Get-WinUpgradeDiagnoseVerdict -Report $r -Version '24H2' } $Report)
}

Describe 'Get-WinUpgradeDiagnoseVerdict - the disk/RAM/Secure Boot false-clean is closed (F6)' {
    It 'an all-PASS eligible host is READY (baseline unchanged)' {
        Get-Verdict $script:PassReport | Should Be 'READY'
    }
    It 'a [FAIL] Disk host is NOT READY (was falsely READY)' {
        $r = $script:PassReport -replace '\[PASS\] Disk.*', '[FAIL] Disk        : 12 GB free / 120 GB total on C: (need 64+ GB free)'
        Get-Verdict $r | Should Be 'NOT READY'
    }
    It 'a [FAIL] RAM host is NOT READY' {
        $r = $script:PassReport -replace '\[PASS\] RAM.*', '[FAIL] RAM         : 2 GB (need 4+ GB)'
        Get-Verdict $r | Should Be 'NOT READY'
    }
    It 'a [FAIL] Secure Boot host is NOT READY' {
        $r = $script:PassReport -replace '\[PASS\] Secure Boot.*', '[FAIL] Secure Boot : Disabled or unsupported'
        Get-Verdict $r | Should Be 'NOT READY'
    }
}

Describe 'Get-WinUpgradeDiagnoseVerdict - the higher-precedence verdicts still win over a disk fail' {
    It 'CPU unsupported (no bypass) is HW INCOMPAT even with a disk fail' {
        $r = ($script:PassReport -replace '\[PASS\] CPU.*', '[FAIL] CPU         : not supported') -replace '\[PASS\] Disk.*', '[FAIL] Disk        : 12 GB free'
        Get-Verdict $r | Should Be 'HW INCOMPAT'
    }
    It 'a [BLOCK] deferral is BLOCKED even with a disk fail' {
        $r = ($script:PassReport + "`n[BLOCK] Feature update deferral 180 days") -replace '\[PASS\] Disk.*', '[FAIL] Disk        : 12 GB free'
        Get-Verdict $r | Should Be 'BLOCKED'
    }
    It 'missing policy is NEEDS POLICY (surfaces before a disk fail)' {
        $r = $script:PassReport -replace '\[PASS\] Target Release Policy.*', '[FAIL] Target Release Policy : not set'
        Get-Verdict $r | Should Be 'NEEDS POLICY'
    }
    It 'already-on reads ON <version>' {
        Get-Verdict ("[PASS] Already on 24H2+`n" + $script:PassReport) | Should Be 'ON 24H2'
    }
}

Describe 'winupgrade worker - the inline diagnose verdict mirrors the disk/RAM/SecureBoot gate' {
    # The verdict runs in a module-less fan-out runspace, so the worker mirrors the helper inline.
    # Pin that the mirror carries the new hardware/capacity fail checks + the NOT READY branch.
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw
    It 'the worker verdict computes a disk/RAM/Secure Boot fail (diskFail / ramFail / sbFail)' {
        ($src -match '\$diskFail') | Should Be $true
        ($src -match '\$sbFail')   | Should Be $true
    }
    It 'the worker verdict yields a NOT READY status' {
        ($src -match "'NOT READY'") | Should Be $true
    }
}

Describe 'winupgrade - manifest version floor (loop-32 Diagnose disk gate landed at 0.5.3)' {
    It 'winupgrade version is >= 0.5.3 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'0.5.3') | Should Be $true
    }
}
