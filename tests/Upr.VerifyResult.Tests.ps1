# =============================================================================
#  Upr.VerifyResult.Tests.ps1 - Pester 3.4 for the upr post-uninstall verify
#  decision (Get-UprVerifyResult, loop35). A loop-35 deep-dive found upr's
#  removed/remediated decision fail-closed and honest end-to-end (exit-code gated,
#  a MANDATORY registry re-verify after every OK), verdict GREEN. The one
#  hardening: the verify demoted an OK to FAIL when the re-read THREW (catch), but
#  a non-throwing EMPTY ($null) remote result read `[bool]$null.Present` = $false
#  = "not present" = gone, so an empty verify result could let an OK stand. The
#  verify is the trust-critical step (it catches a lying uninstall), so a $null /
#  unreadable verify must fail CLOSED to "could NOT be verified", never "removed".
#
#  Get-UprVerifyResult is the canonical decision; the uninstall worker mirrors it
#  inline (runspace). Pure - tested.  Run:  Invoke-Pester -Path .\tests\Upr.VerifyResult.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

function Get-Verify($VerifyOut, [bool]$Reboot = $false, [string]$AppResult = 'OK (removed)') {
    (& $script:Mod { param($v, $rb, $ar) Get-UprVerifyResult -VerifyOut $v -RebootNeeded $rb -AppResult $ar } $VerifyOut $Reboot $AppResult)
}

Describe 'Get-UprVerifyResult - the verify fails CLOSED, never reads empty-as-removed' {
    It 'a $null verify result (empty, non-throwing) -> could NOT be verified (the fix)' {
        Get-Verify $null | Should Match 'could NOT be verified'
    }
    It 'a $null verify result never reads as removed/OK' {
        (Get-Verify $null) -notmatch '^OK' | Should Be $true
    }
    It 'product still present -> FAIL (still present)' {
        Get-Verify ([pscustomobject]@{ Present = $true }) | Should Match 'still present'
    }
    It 'product confirmed gone -> the app result stands (OK)' {
        Get-Verify ([pscustomobject]@{ Present = $false }) -AppResult 'OK (removed)' | Should Be 'OK (removed)'
    }
    It 'product gone + reboot needed -> OK (removed, reboot required)' {
        Get-Verify ([pscustomobject]@{ Present = $false }) -Reboot $true | Should Match 'reboot required'
    }
}

Describe 'upr - manifest exact version pin (newest bump = loop-35 verify fail-close)' {
    It 'upr is at v1.2.3' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '1.2.3'
    }
}
