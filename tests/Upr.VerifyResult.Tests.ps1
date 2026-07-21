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

Describe 'upr - manifest exact version pin (newest bump = loop-64 generic-handler hardening)' {
    It 'upr is at v1.2.4' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '1.2.4'
    }
}

# loop64: harden the generic uninstall handlers. (1) The MSI handler interpolated a registry-derived
# GUID into a single msiexec ArgumentList string - a crafted UninstallString GUID could inject extra
# switches under the operator credential; it now routes through the injection-safe Invoke-SafeUninstall /
# Get-SafeUninstallPlan (proven in Upr.UninstallStringParse.Tests). (2) The dead Store branch returned an
# unconditional "OK (Store app removed)" that a no-match pipeline never earned and the registry re-verify
# could not catch - a false-clean landmine; removed, so a future 'Store' type fail-closes via the EXE path.
# Static analysis - both handlers live inside the remote WinRM uninstall scriptblock.
Describe 'upr 1.2.4 - generic uninstall handlers: MSI injection-safe + no Store false-clean' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'the MSI handler routes through the injection-safe Invoke-SafeUninstall' {
        $idxMsi  = $src.IndexOf("if (`$type -eq 'MSI')")
        $idxSafe = if ($idxMsi -ge 0) { $src.IndexOf('Invoke-SafeUninstall -UnStr $unStr', $idxMsi) } else { -1 }
        $idxElse = if ($idxMsi -ge 0) { $src.IndexOf('} else {', $idxMsi) } else { -1 }
        ($idxMsi -ge 0)  | Should Be $true
        # the MSI branch reaches an Invoke-SafeUninstall BEFORE its closing '} else {' (the EXE branch)
        ($idxSafe -gt $idxMsi -and $idxSafe -lt $idxElse) | Should Be $true
    }
    It 'the old raw msiexec ArgumentList GUID interpolation is gone' {
        ($src -match 'Start-Process msiexec -ArgumentList "/x') | Should Be $false
    }
    It 'the dead Store unconditional-OK branch is gone (no false-clean landmine)' {
        ($src -match 'OK \(Store app removed\)') | Should Be $false
        ($src -match "\`$type -eq 'Store'")      | Should Be $false
    }
    It 'the manifest no longer advertises a Store handler' {
        ($mani.summary -match 'Store') | Should Be $false
        $ru = @($mani.actions | Where-Object { $_.id -eq 'report-uninstall' })[0]
        ($ru.description -match 'Store') | Should Be $false
    }
}
