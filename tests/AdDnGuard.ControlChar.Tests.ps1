# =============================================================================
#  AdDnGuard.ControlChar.Tests.ps1 - Pester 3.4 for the bind-redirect DN guard
#  hardening (loop-9 P3). The guard Test-Ad{Search,To}DnInLocalDomain pins a
#  credentialed LDAP bind to the local domain. .NET regex '$' also matches just
#  BEFORE a trailing newline, so a value like "OU=x,DC=AREA52,DC=MIL`n" would slip
#  past the component-boundary anchor. We assert:
#   (a) a control char anywhere (CR / LF / TAB / NUL) -> REJECTED (both predicates);
#   (b) the clean local-domain DN still ACCEPTS (no over-reject / regression);
#   (c) the known cross-domain redirect (DC=evil,...) still REJECTS.
#
#  Predicates are exported and take an explicit -ExpectDomainSuffix, so this is a
#  pure offline unit test - no AD, no env dependency.
#
#  Run:  Invoke-Pester -Path .\tests\AdDnGuard.ControlChar.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Force | Out-Null
Import-Module (Join-Path $script:Root 'modules\JanetWeb.adto.psm1')     -Force | Out-Null

$Suffix = 'DC=AREA52,DC=MIL'
$Good   = 'OU=Workstations,DC=AREA52,DC=MIL'

$cases = @(
    @{ Tool = 'adsearch'; Fn = 'Test-AdSearchDnInLocalDomain' }
    @{ Tool = 'adto';     Fn = 'Test-AdToDnInLocalDomain' }
)

foreach ($c in $cases) {
    $fn = $c.Fn
    Describe "DN guard control-char hardening - $($c.Tool)" {

        It 'ACCEPTS a clean local-domain DN (no over-reject)' {
            (& $fn -Value $Good -ExpectDomainSuffix $Suffix) | Should Be $true
        }

        It 'REJECTS a DN with a trailing newline (the .NET $-anchor bypass)' {
            (& $fn -Value ($Good + "`n") -ExpectDomainSuffix $Suffix) | Should Be $false
        }

        It 'REJECTS a trailing carriage return' {
            (& $fn -Value ($Good + "`r") -ExpectDomainSuffix $Suffix) | Should Be $false
        }

        It 'REJECTS an embedded tab' {
            (& $fn -Value "OU=x`t,DC=AREA52,DC=MIL" -ExpectDomainSuffix $Suffix) | Should Be $false
        }

        It 'REJECTS an embedded NUL' {
            (& $fn -Value ("OU=x" + [char]0 + ",DC=AREA52,DC=MIL") -ExpectDomainSuffix $Suffix) | Should Be $false
        }

        It 'still REJECTS a cross-domain redirect (regression)' {
            (& $fn -Value 'DC=evil,DC=AREA52,DC=MIL' -ExpectDomainSuffix $Suffix) | Should Be $false
        }
    }
}
