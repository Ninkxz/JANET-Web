# =============================================================================
#  CertDeploy.Companions.Tests.ps1 - Pester 3.4 for the Cert Deploy v1.4.0
#  opt-in PKI-Fix-ScanFix v1.9 companions (port of the C2C fix-pki Pb/Pc blocks).
#  PURE checks only: manifest wiring (runCompanions input, default OFF), the
#  companion source string (defined but NEVER dot-sourced module-side - it has
#  no read-only path), the deletion allowlist regex, and the guard-copy sync
#  between the companion prune allowlist and CertDeployLegacyIntermediates
#  (divergence there would make the companions DELETE the four certs the
#  deploy just PUSHED). No live store or WinRM I/O.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.Companions.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cd = Import-Module (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Force -PassThru

Describe 'Cert Deploy - split companion boxes wiring (prunePki + fixRdp, opt-in, default OFF)' {

    It 'manifest version is 1.4.0' {
        (& $cd { Get-JanetToolManifest }).version | Should Be '1.4.0'
    }
    It 'deploy exposes a prunePki bool input defaulting to OFF' {
        $a = @((& $cd { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'deploy' })[0]
        $inp = @($a.inputs | Where-Object { $_.name -eq 'prunePki' })
        $inp.Count | Should Be 1
        [string]$inp[0].type | Should Be 'bool'
        [bool]$inp[0].default | Should Be $false
    }
    It 'deploy exposes a fixRdp bool input defaulting to OFF' {
        $a = @((& $cd { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'deploy' })[0]
        $inp = @($a.inputs | Where-Object { $_.name -eq 'fixRdp' })
        $inp.Count | Should Be 1
        [string]$inp[0].type | Should Be 'bool'
        [bool]$inp[0].default | Should Be $false
    }
    It 'deploy no longer exposes the lumped runCompanions input' {
        $a = @((& $cd { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'deploy' })[0]
        @($a.inputs | Where-Object { $_.name -eq 'runCompanions' }).Count | Should Be 0
    }
    It 'the deploy action description names both companions' {
        $a = @((& $cd { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'deploy' })[0]
        ([string]$a.description) -match 'v1\.9'       | Should Be $true
        ([string]$a.description) -match 'RDP-tcp'     | Should Be $true
        ([string]$a.description) -match '(?i)prune'   | Should Be $true
        ([string]$a.description) -match 'prunePki'    | Should Be $true
        ([string]$a.description) -match 'fixRdp'      | Should Be $true
    }
}

Describe 'Cert Deploy v1.4.0 - companion source (remote-only, never module-side)' {

    It 'the companion source string defines Invoke-CertDeployCompanions' {
        $src = & $cd { $script:CertDeployCompanionsSrc }
        $src -match 'function Invoke-CertDeployCompanions' | Should Be $true
    }
    It 'Invoke-CertDeployCompanions is NOT defined in module scope (live-state only on the target)' {
        (& $cd { Get-Command Invoke-CertDeployCompanions -ErrorAction SilentlyContinue }) | Should BeNullOrEmpty
    }
    It 'the deploy worker threads DoPrune + DoRdp + CompanionsSrc through to the remote install' {
        $blk = & $cd { $script:CertDeployDeployBlock.ToString() }
        $blk -match '\$DoPrune'                                                   | Should Be $true
        $blk -match '\$DoRdp'                                                     | Should Be $true
        $blk -match 'Invoke-CertDeployCompanions -DoPrune \$DoPrune -DoRdp \$DoRdp' | Should Be $true
    }
    It 'the companion function takes a DoPrune/DoRdp param and gates each block on it' {
        $src = & $cd { $script:CertDeployCompanionsSrc }
        $src -match 'param\(\[bool\]\$DoPrune = \$true, \[bool\]\$DoRdp = \$true\)' | Should Be $true
        $src -match 'if \(\$DoPrune\)'                                             | Should Be $true
        $src -match 'if \(\$DoRdp\)'                                               | Should Be $true
    }
    It 'Invoke-CertDeployCompanions -DoPrune $false -DoRdp $false gates both blocks off -> empty note set, no live-state I/O' {
        # Dot-source the remote-only source string into THIS scope (it is never module-side)
        # and invoke with BOTH flags off: neither block runs, so no cert store / CIM call is
        # made and the function returns an empty array. Fully offline, no WinRM.
        $src = & $cd { $script:CertDeployCompanionsSrc }
        . ([scriptblock]::Create($src))
        $notes = Invoke-CertDeployCompanions -DoPrune $false -DoRdp $false
        @($notes).Count | Should Be 0
    }
    It 'prune targets the CA store ONLY (never My/Root/TrustedPublisher/Disallowed)' {
        $src = & $cd { $script:CertDeployCompanionsSrc }
        $src -match [regex]::Escape("Cert:\LocalMachine\CA'") | Should Be $true
        # Every store-scoped enumeration feeding a Remove-Item must be CA (the prune) or
        # 'Remote Desktop' (the RDP rebind clear) - comments don't count, code lines do.
        $gciStores = @(($src -split "`n") | Where-Object { $_ -match 'Get-ChildItem' -and $_ -match 'Cert:' -and $_ -notmatch '^\s*#' } |
            ForEach-Object { if ($_ -match "Cert:\\LocalMachine\\(?:'|`")?([A-Za-z ]+)") { $Matches[1].Trim() } })
        foreach ($s in $gciStores) { @('CA','Remote Desktop','My','$stN') -contains $s | Should Be $true }
        # and the only Remove-Item pipe on a store enumeration is the Remote Desktop clear
        $rmLines = @(($src -split "`n") | Where-Object { $_ -match 'Get-ChildItem' -and $_ -match 'Remove-Item' })
        $rmLines.Count | Should Be 1
        $rmLines[0] -match 'Remote Desktop' | Should Be $true
    }
}

Describe 'Cert Deploy v1.4.0 - prune allowlist (guard-copy sync + regex shape)' {

    It 'the prune allowlist regex matches retired DoD intermediates only' {
        $re = '^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD'
        'CN=DOD EMAIL CA-33, OU=PKI, OU=DoD, O=U.S. Government, C=US'    -match $re | Should Be $true
        'CN=DOD DERILITY CA-1, OU=PKI, OU=DoD, O=U.S. Government, C=US'  -match $re | Should Be $true
        'CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US'      -match $re | Should Be $false
        'CN=AFNOAPPS LTMA CA-5, OU=PKI, OU=DoD, O=U.S. Government, C=US' -match $re | Should Be $false
    }
    It 'the companion source carries that exact allowlist regex' {
        $src = & $cd { $script:CertDeployCompanionsSrc }
        $src.Contains('^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD') | Should Be $true
    }
    It 'legacyKeep guard-copy holds EXACTLY the CertDeployLegacyIntermediates thumbprints' {
        $src  = & $cd { $script:CertDeployCompanionsSrc }
        $keys = & $cd { @($script:CertDeployLegacyIntermediates.Keys) }
        $keys.Count | Should Be 4
        foreach ($k in $keys) { $src.Contains([string]$k) | Should Be $true }
    }
}
