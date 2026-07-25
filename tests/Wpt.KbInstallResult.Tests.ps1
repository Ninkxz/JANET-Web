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

Describe 'kb-install - a SKIPPED/unverified host must not audit as a patched vulnerability (audit 2026-07-24)' {

    # Behavioural: drive the REAL dispatcher with the worker scriptblock shadowed, so the
    # OkOf / AuditResultOf wiring is what is under test (not the label helper above). A KB
    # that is not in MECM with no MSU path is counted Skipped and NOTHING is installed
    # (WptKbInstallBlock ~:3104) - that used to book Success + VulnPatched itemCount 1,
    # i.e. a vulnerability recorded as remediated on a box that was never touched.
    function Invoke-KbInstallWithWorker {
        param([string]$WorkerBody)
        & $script:Mod {
            param($body)
            $orig = $script:WptKbInstallBlock
            $script:WptKbInstallBlock = [scriptblock]::Create($body)
            try {
                $ev = New-Object System.Collections.ArrayList
                $emit = { param($e) [void]$ev.Add($e) }
                $res = Invoke-JanetToolAction -ActionId 'kb-install' -Params @{ targets='UNIT-KB-HOST'; kbs='KB5000001'; threads=1 } -Credential $null -Emit $emit
                return @{ Summary = $res.summary; Rows = @($res.rows); Events = @($ev) }
            } finally { $script:WptKbInstallBlock = $orig }
        } $WorkerBody
    }
    function Get-UnitAudit($out) { @($out.Events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'UNIT-KB-HOST' })[0] }

    $hdr = 'param($Computer,$Cred,$Auth,$KBs,$MsuPath,$NoReboot) '
    $skipped   = Invoke-KbInstallWithWorker ($hdr + '@{ Host=$Computer; MECMFound=0; MECMInstalled=0; MSUInstalled=0; Skipped=1; Errors=@(); Details=@("KB5000001 not in MECM, no MSU path -- skipped") }')
    $installed = Invoke-KbInstallWithWorker ($hdr + '@{ Host=$Computer; MECMFound=1; MECMInstalled=0; MSUInstalled=1; Skipped=0; Errors=@(); Details=@("MSU KB5000001: installed (exit 0)") }')
    $errored   = Invoke-KbInstallWithWorker ($hdr + '@{ Host=$Computer; MECMFound=0; MECMInstalled=0; MSUInstalled=0; Skipped=0; Errors=@("Session failed: unit"); Details=@() }')

    It 'a skipped host is NOT counted ok - and is tallied skipped, not failed' {
        # audit 2026-07-25 (fable re-audit follow-up): the skipped host used to land in
        # summary.failed, so the "Done. X ok, Y failed" line contradicted the 'Skipped'
        # audit emitted beside it (and made an all-skipped run look like an all-failed one).
        [int]$skipped.Summary.ok      | Should Be 0
        [int]$skipped.Summary.failed  | Should Be 0
        [int]$skipped.Summary.skipped | Should Be 1
        [bool]$skipped.Summary.allFailed | Should Be $false
    }
    It 'a skipped host audits Skipped with itemCount 0 - never VulnPatched Success' {
        $a = Get-UnitAudit $skipped
        [string]$a.action    | Should Be 'VulnPatched'
        [string]$a.result    | Should Be 'Skipped'
        [int]$a.itemCount    | Should Be 0
    }
    It 'the skipped row still reports the honest No change label' {
        [string]@($skipped.Rows)[0].Result | Should Be 'No change'
    }
    It 'a confirmed MSU install still audits Success with itemCount 1' {
        $a = Get-UnitAudit $installed
        [string]$a.result | Should Be 'Success'
        [int]$a.itemCount | Should Be 1
        [int]$installed.Summary.ok | Should Be 1
    }
    It 'a real error still audits Failure (Skipped never masks a failure)' {
        [string](Get-UnitAudit $errored).result | Should Be 'Failure'
    }
}

Describe 'wpt - manifest version floor (loop-23 honest kb-install label landed at 6.8.7)' {
    It 'wpt version is >= 6.8.7 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.7') | Should Be $true
    }
}
