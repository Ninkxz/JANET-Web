# =============================================================================
#  Wpt.KbInstallResult.Tests.ps1 - Pester 3.4 for the honest kb-install outcome
#  label (loop23, roadmap item 14). kb-install applies KBs two ways: an MECM
#  InstallUpdates trigger (the CCM client only ACCEPTS the request - the async
#  download/install can still fail minutes later) and an MSU/wusa install (exit
#  0/3010 is a real local confirmation). The old Result reported BOTH as
#  "Installed" and the view counted every no-error host as installed - a
#  false-clean: an operator sees Installed and moves on while an MECM-triggered
#  box may never finish. Now: any MECM trigger reads "Triggered (verify)" (errs
#  toward verify, never over-claims), only a confirmed MSU install reads
#  "Installed", and the view surfaces r.Result + counts only confirmed installs.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.KbInstallResult.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

function Get-Result([int]$Err, [int]$Mecm, [int]$Msu) {
    (& $script:Mod { param($e, $m, $s) Get-WptKbInstallResult -ErrorCount $e -MecmTriggered $m -MsuInstalled $s } $Err $Mecm $Msu)
}

Describe 'Get-WptKbInstallResult - honest triggered-vs-installed label' {
    It 'any error wins -> Errors' {
        Get-Result 1 5 5 | Should Be 'Errors'
    }
    It 'an MECM trigger (no MSU) is Triggered (verify), NOT Installed' {
        Get-Result 0 2 0 | Should Be 'Triggered (verify)'
    }
    It 'a confirmed MSU install (no MECM) is Installed' {
        Get-Result 0 0 1 | Should Be 'Installed'
    }
    It 'a mix of MECM trigger + MSU install errs toward verify (part is unconfirmed)' {
        Get-Result 0 1 1 | Should Be 'Triggered (verify)'
    }
    It 'nothing found/done is No change' {
        Get-Result 0 0 0 | Should Be 'No change'
    }
}

Describe 'wpt view - kb-install surfaces the server Result and counts only confirmed installs' {
    $viewSrc = Get-Content (Join-Path $script:Root 'web\js\views\wpt.view.js') -Raw
    It 'the kb-install case reads r.Result (not a hardcoded Success->Installed)' {
        ($viewSrc -match [regex]::Escape('String(r.Result')) | Should Be $true
    }
    It 'the installed counter is gated on a confirmed Installed result' {
        ($viewSrc -match [regex]::Escape('/^installed$/i.test(kr)')) | Should Be $true
    }
}

Describe 'wpt - manifest version floor (loop-23 honest kb-install label landed at 6.8.7)' {
    It 'wpt version is >= 6.8.7 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.7') | Should Be $true
    }
}
