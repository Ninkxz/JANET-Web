# =============================================================================
#  Acas.KbInstallStatus.Tests.ps1 - Pester 3.4 for the honest acas kb-install
#  status (loop25). A Fable deep-dive of the acas remediation engine found the
#  kb-install worker reported an unverified MECM InstallUpdates trigger (and a
#  UsoClient fire-and-forget) as OK - which books a VulnPatched Success audit and
#  lights the PATCHED stat card - and let any confirmed install mask a real error
#  (partial-fail-as-OK). These are the acas siblings of the wpt kb-install issues
#  fixed in loops 22-23. Now: any error -> FAIL; a trigger/fire with no confirmed
#  install -> UNCONFIRMED (AcasOkOf renders it amber, out of the OK/patched tally);
#  a confirmed MSU exit-0 install -> OK; only skips -> SKIP.
#
#  Get-AcasKbInstallStatus is the canonical rule; the AcasKbInstallBlock worker
#  mirrors it inline (it runs in a module-less runspace, can't call a module fn).
#  The real worker's status is exercised end-to-end by FixVerify2 (Invoke-AcasKb).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.KbInstallStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-Status {
    param([int]$Err, [int]$Mecm, [int]$Msu, [int]$Skip, [bool]$Uso)
    (& $script:Mod { param($e, $m, $s, $k, $u) Get-AcasKbInstallStatus -ErrorCount $e -MecmTriggered $m -MsuInstalled $s -Skipped $k -UsoTriggered $u } $Err $Mecm $Msu $Skip $Uso)
}

Describe 'Get-AcasKbInstallStatus - a trigger is never "patched"' {
    It 'a MECM trigger with no confirmed install -> UNCONFIRMED (not OK)' {
        Get-Status -Err 0 -Mecm 2 -Msu 0 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
    It 'a UsoClient fire-and-forget -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $true | Should Be 'UNCONFIRMED'
    }
    It 'a confirmed MSU install (no trigger) -> OK' {
        Get-Status -Err 0 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'OK'
    }
    It 'a MECM trigger alongside an MSU install still errs toward verify -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 1 -Msu 1 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
}

Describe 'Get-AcasKbInstallStatus - an error never hides behind a partial install' {
    It 'any error -> FAIL, even with a confirmed MSU install (partial-fail no longer masks)' {
        Get-Status -Err 1 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
    It 'any error -> FAIL, even with a MECM trigger' {
        Get-Status -Err 1 -Mecm 1 -Msu 0 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
}

Describe 'Get-AcasKbInstallStatus - skips and no-ops' {
    It 'nothing installed, only skips -> SKIP' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 2 -Uso $false | Should Be 'SKIP'
    }
    It 'nothing happened at all -> SKIP (never a bare OK)' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $false | Should Be 'SKIP'
    }
}

Describe 'acas - manifest exact version pin (newest bump = loop-25 honest kb-install status)' {
    It 'acas is at v1.11.6' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '1.11.6'
    }
}
