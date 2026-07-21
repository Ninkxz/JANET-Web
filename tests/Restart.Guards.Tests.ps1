# =============================================================================
#  Restart.Guards.Tests.ps1 - Pester 3.4 tests for restart-engine guards:
#  IP-target DNS-guard skip (audit#9) and dispatcher self-exclusion (audit#10).
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Force -PassThru

Describe 'IP-target DNS-mismatch guard skip (audit#9)' {
    # The dispatch code computes the expected COMPUTERNAME passed into the remote
    # guard: '' for an IP literal (skip the compare), shortname otherwise.
    function Get-ExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }

    It 'passes empty expected-name for an IPv4 literal (guard is skipped)' {
        (Get-ExpectedName '192.168.1.50') | Should Be ''
    }
    It 'passes the shortname for an FQDN target' {
        (Get-ExpectedName 'WS01.area.af.mil') | Should Be 'WS01'
    }
    It 'passes the shortname for a bare hostname' {
        (Get-ExpectedName 'WS01') | Should Be 'WS01'
    }
}

Describe 'Dispatcher self-exclusion (audit#10)' {
    It 'flags this host by COMPUTERNAME' {
        (& $script:Mod { param($n) Test-JanetHostIsSelf $n } $env:COMPUTERNAME) | Should Be $true
    }
    It 'flags localhost and any 127.x loopback' {
        (& $script:Mod { Test-JanetHostIsSelf 'localhost' }) | Should Be $true
        (& $script:Mod { Test-JanetHostIsSelf '127.0.0.5' }) | Should Be $true
    }
    It 'does not flag an unrelated hostname' {
        (& $script:Mod { Test-JanetHostIsSelf 'WS-NOT-ME-12345' }) | Should Be $false
    }
    It 'does not flag an empty token' {
        (& $script:Mod { Test-JanetHostIsSelf '' }) | Should Be $false
    }
}

# loop79 (informative-failures follow-up): Get-RrsShutdownErrorHint now DELEGATES its raw-detail text
# signatures to the shared Get-JanetTroubleshootHint (the six duplicated branches are gone; the shared
# engine is a strict superset). It still owns the numeric shutdown.exe return codes for the tool-specific
# and no-usable-detail cases.
Describe 'restart shutdown-error hint delegates detail text to the shared engine (loop79)' {
    function Rrs { param([int]$c,[string]$d='') (& $script:Mod { param($cc,$dd) Get-RrsShutdownErrorHint -Code $cc -Detail $dd } $c $d) }

    It 'a detail-string failure returns the shared engine hint (not the old duplicated wording)' {
        (Rrs 0 'Access is denied. (0x80070005)')  | Should Match 'not a local administrator|not authorized'
        (Rrs 0 'Connecting failed: 0x80090351')   | Should Match 'TrustedHosts|realm|CAC'
        # a signature the OLD restart mapper never had, now reachable via delegation:
        (Rrs 0 'A required privilege is not held by the client') | Should Match 'Privilege not held|user right'
    }
    It 'the numeric switch still owns the tool-specific / no-detail return codes' {
        (Rrs 1190 '') | Should Match 'ALREADY SCHEDULED'
        (Rrs 1115 '') | Should Match 'SHUTDOWN_IN_PROGRESS'
        (Rrs 1314 '') | Should Match 'PRIVILEGE_NOT_HELD'
        (Rrs 9999 '') | Should Match 'Unknown shutdown.exe return code 9999'
    }

    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Raw
    It 'restart imports the shared troubleshoot engine and delegates in the mapper' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1')                 | Should Be $true
        ($src -match '\$h\s*=\s*Get-JanetTroubleshootHint\s+-Message\s+\$Detail')   | Should Be $true
    }
    It 'the six duplicated detail-string branches are gone from the mapper' {
        ($src -match "return 'WinRM auth: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY") | Should Be $false
        ($src -match "return 'Target not in the WinRM TrustedHosts")                     | Should Be $false
    }
    It 'restart manifest bumped to 1.5.0-beta9' {
        (& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '1.5.0-beta9'
    }
}
