# =============================================================================
#  C2c.PkiBoxes.Tests.ps1 - Pester 3.4 for the opt-in PkiRoots companions.
#
#  The fix-pki action installs the DoD trust bundle ADDITIVELY (always), then runs
#  two PKI-Fix-ScanFix v1.9 companions that are now OPT-IN via their own boxes:
#    prunePki -> $DoPrune  (prune expired retired DoD intermediates, CA store)
#    fixRdp   -> $DoRdp    (repair a broken RDP-tcp listener certificate)
#  Both default OFF (opt-in, destructive extras) and are gated INDEPENDENTLY. This
#  mirrors the certdeploy tool's shared param contract. PURE checks only: the
#  manifest inputs, the independent source gates, the param threading and the
#  bool-reader default - nothing dials a host or touches machine state.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.PkiBoxes.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

Describe 'C2C - fix-pki exposes the two opt-in companion boxes (shared certdeploy contract)' {

    $fixPki = @((& $cm { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'fix-pki' })[0]

    It 'the fix-pki action exists and is destructive' {
        $fixPki | Should Not BeNullOrEmpty
        [bool]$fixPki.destructive | Should Be $true
    }
    It 'exposes prunePki as an opt-in bool input (required=$false, default=$false)' {
        $p = @($fixPki.inputs | Where-Object { $_.name -eq 'prunePki' })[0]
        $p | Should Not BeNullOrEmpty
        [string]$p.type | Should Be 'bool'
        [bool]$p.required | Should Be $false
        [bool]$p.default | Should Be $false
    }
    It 'exposes fixRdp as an opt-in bool input (required=$false, default=$false)' {
        $p = @($fixPki.inputs | Where-Object { $_.name -eq 'fixRdp' })[0]
        $p | Should Not BeNullOrEmpty
        [string]$p.type | Should Be 'bool'
        [bool]$p.required | Should Be $false
        [bool]$p.default | Should Be $false
    }
    It 'still requires the cert bundle folder + the FIX confirm word (core install unchanged)' {
        @($fixPki.inputs | Where-Object { $_.name -eq 'certBundleFolder' -and $_.required }).Count | Should Be 1
        @($fixPki.inputs | Where-Object { $_.name -eq 'confirm' -and $_.required }).Count | Should Be 1
    }
    It 'the description says the two companions are now opt-in' {
        [string]$fixPki.description | Should Match 'OPT-IN'
        [string]$fixPki.description | Should Match 'prunePki'
        [string]$fixPki.description | Should Match 'fixRdp'
    }
}

Describe 'C2C - the two companions are gated INDEPENDENTLY in the fix block' {

    $src = & $cm { $script:C2cFixBlock.ToString() }

    It 'the old single PkiCompanions gate is gone' {
        $src | Should Not Match ([regex]::Escape('$PkiCompanions'))
    }
    It 'the prune companion is gated by $DoPrune (its own if-block)' {
        $src | Should Match ([regex]::Escape('if ($DoPrune) {'))
    }
    It 'the RDP companion is gated by $DoRdp (its own if-block)' {
        $src | Should Match ([regex]::Escape('if ($DoRdp) {'))
    }
    It 'the $DoPrune gate precedes the PkiExpired prune emit' {
        $iPrune = $src.IndexOf('if ($DoPrune) {')
        $iExpired = $src.IndexOf("'PkiExpired'")
        $iPrune | Should BeGreaterThan -1
        $iExpired | Should BeGreaterThan $iPrune
    }
    It 'the $DoRdp gate precedes the PkiRdp rebind emit' {
        $iRdp = $src.IndexOf('if ($DoRdp) {')
        $iRebind = $src.IndexOf("'PkiRdp'")
        $iRdp | Should BeGreaterThan -1
        $iRebind | Should BeGreaterThan $iRdp
    }
    It 'both companion params are threaded through the worker + inner fix scriptblock' {
        ([regex]::Matches($src, [regex]::Escape('[bool]$DoPrune'))).Count | Should BeGreaterThan 0
        ([regex]::Matches($src, [regex]::Escape('[bool]$DoRdp'))).Count | Should BeGreaterThan 0
    }
}

Describe 'C2C - the bool-reader defaults the boxes OFF (opt-in)' {

    It 'an absent value defaults to $false (companion stays OFF)' {
        & $cm { Get-C2cBool $null $false } | Should Be $false
    }
    It 'an explicit truthy value arms the companion' {
        & $cm { Get-C2cBool 'true' $false } | Should Be $true
        & $cm { Get-C2cBool $true $false }  | Should Be $true
    }
    It 'a falsey value keeps it OFF' {
        & $cm { Get-C2cBool 'false' $false } | Should Be $false
        & $cm { Get-C2cBool $false $false }  | Should Be $false
    }
}
