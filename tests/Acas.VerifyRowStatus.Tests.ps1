# =============================================================================
#  Acas.VerifyRowStatus.Tests.ps1 - Pester 3.4 for the honest acas VERIFY-only
#  row status (loop26, roadmap item 18). "Verify Selected" / "Verify" is a
#  read-only dry-run ("check current state, change nothing"), but its result rows
#  feed the SAME run binder as patching, and that binder lights the PATCHED stat
#  card for any row whose Result is OK (acas.view.js:742). The verify branch
#  returned "v=.. last=.. [fresh|stale|n/a].." with NO status prefix, so every
#  reachable host - INCLUDING [stale] ones (Verified=$false = still on the old,
#  vulnerable version) - classified OK and counted as PATCHED. A still-vulnerable
#  host counting as patched is a false-clean.
#
#  Now: only a confirmed-current host (Verified=$true, [fresh]) stays OK; a stale
#  or indeterminate probe -> UNCONFIRMED (AcasUpdateRowOf renders Result
#  UNCONFIRMED = amber, out of the patched tally). Get-AcasVerifyRowStatus is the
#  canonical rule; the verify branch mirrors it inline (runs in a module-less
#  runspace, can't call a module fn).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.VerifyRowStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-VerifyStatus($Verified) {
    (& $script:Mod { param($v) Get-AcasVerifyRowStatus -Verified $v } $Verified)
}

Describe 'Get-AcasVerifyRowStatus - only a confirmed-current host is OK' {
    It 'Verified $true (fresh / current) -> OK (legitimately verified good)' {
        Get-VerifyStatus $true | Should Be 'OK'
    }
    It 'Verified $false (stale / still on the old version) -> UNCONFIRMED (the false-clean fix)' {
        Get-VerifyStatus $false | Should Be 'UNCONFIRMED'
    }
    It 'Verified $null (indeterminate probe) -> UNCONFIRMED (never over-claims)' {
        Get-VerifyStatus $null | Should Be 'UNCONFIRMED'
    }
}

Describe 'acas verify branch - a non-fresh verify row is prefixed UNCONFIRMED' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
    It 'the verify-only branch prefixes UNCONFIRMED when not fresh' {
        # the prefix is the mirror of Get-AcasVerifyRowStatus; a still-vulnerable [stale] host
        # must not classify OK -> must carry a leading UNCONFIRMED for AcasUpdateRowOf.
        ($moduleSrc -match [regex]::Escape("'UNCONFIRMED '")) | Should Be $true
    }
}

Describe 'acas - manifest version floor (loop-26 honest verify row landed at 1.11.7)' {
    It 'acas version is >= 1.11.7 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.7') | Should Be $true
    }
}
