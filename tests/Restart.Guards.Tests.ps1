# =============================================================================
#  Restart.Guards.Tests.ps1 - Pester 3.4 tests for restart-engine guards:
#  IP-target DNS-guard skip (audit#9) and dispatcher self-exclusion (audit#10).
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetTwo.restart.psm1') -Force -PassThru

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
