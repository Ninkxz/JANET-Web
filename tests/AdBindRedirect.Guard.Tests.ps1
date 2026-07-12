# =============================================================================
#  AdBindRedirect.Guard.Tests.ps1 - Pester 3.4 tests for the hardened LDAP
#  bind-redirect DN guard shared by AD Search + AD Nemesis.
#
#  Exercises the PURE predicate offline - NO live domain, NO ADSI, NO bind. The
#  guard closes P2 (a bare foreign DN like DC=evil,DC=com serverless-binds the
#  attacker's DC) and P3 (a legit RFC-4514 escaped comma-CN was wrongly rejected
#  by the old [/\\] char check). Both modules ship a byte-identical predicate;
#  the AD Search engine runs in a bare child runspace so it INLINES a copy of its
#  module-level helper - this test also asserts the two adsearch copies match.
#
#  Run:  Invoke-Pester -Path .\tests\AdBindRedirect.Guard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:AdSearchPsm1 = Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'
$script:AdToPsm1     = Join-Path $script:Root 'modules\JanetWeb.adto.psm1'
$null = Import-Module $script:AdSearchPsm1 -Force
$null = Import-Module $script:AdToPsm1     -Force

$Suffix = 'DC=AREA52,DC=MIL'

# The accept / reject corpus (shared by both modules' identical predicate).
$Accept = @(
    'OU=Squadron,DC=area52,DC=mil'                       # lower-case, ends at local domain
    'CN=Doe\, Jane,OU=Users,DC=AREA52,DC=MIL'            # RFC-4514 escaped comma-CN (P3): '\' is legit
    'DC=area52,DC=mil'                                    # the bare domain root itself
)
$Reject = @(
    'DC=evil,DC=com'                                      # P2: foreign domain -> serverless attacker bind
    'evilhost/DC=area52,DC=mil'                           # explicit-server form (has '/')
    'LDAP://evil'                                         # full LDAP URL redirect
    'CN=x,DC=notarea52,DC=mil'                            # look-alike suffix that is NOT the local domain
    'DC=evil,DC=area52,DC=mil'                            # P3: child-subdomain prepend -> distinct domain evil.area52.mil (extra DC=)
    'CN=ABDC=AREA52,DC=MIL'                               # P3: suffix as a mid-string substring, not a component boundary
)

Describe 'AD bind-redirect guard - AD Search pure predicate' {
    foreach ($v in $Accept) {
        It "ACCEPTS a local-domain DN: $v" {
            Test-AdSearchDnInLocalDomain -Value $v -ExpectDomainSuffix $Suffix | Should Be $true
        }
    }
    foreach ($v in $Reject) {
        It "REJECTS a redirect/foreign value: $v" {
            Test-AdSearchDnInLocalDomain -Value $v -ExpectDomainSuffix $Suffix | Should Be $false
        }
    }
    It 'REJECTS any non-blank value when the domain suffix cannot be derived (fails closed)' {
        Test-AdSearchDnInLocalDomain -Value 'OU=Squadron,DC=area52,DC=mil' -ExpectDomainSuffix '' | Should Be $false
        Test-AdSearchDnInLocalDomain -Value 'DC=area52,DC=mil'             -ExpectDomainSuffix '' | Should Be $false
    }
}

Describe 'AD bind-redirect guard - AD Nemesis pure predicate' {
    foreach ($v in $Accept) {
        It "ACCEPTS a local-domain DN: $v" {
            Test-AdToDnInLocalDomain -Value $v -ExpectDomainSuffix $Suffix | Should Be $true
        }
    }
    foreach ($v in $Reject) {
        It "REJECTS a redirect/foreign value: $v" {
            Test-AdToDnInLocalDomain -Value $v -ExpectDomainSuffix $Suffix | Should Be $false
        }
    }
    It 'REJECTS any non-blank value when the domain suffix cannot be derived (fails closed)' {
        Test-AdToDnInLocalDomain -Value 'OU=Squadron,DC=area52,DC=mil' -ExpectDomainSuffix '' | Should Be $false
    }
}

Describe 'AD bind-redirect guard - both AD Search copies use identical logic' {
    # The engine runs in a bare child runspace (no module scope), so it defines an
    # INLINE copy of Test-AdSearchDnInLocalDomain. Extract every definition from the
    # source and assert their normalized bodies are byte-identical (defence against
    # one copy drifting from the other).
    function Get-FnBodies {
        param([string]$Src, [string]$Name)
        $lines = $Src -split "`r?`n"
        $bodies = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match ('function\s+' + [regex]::Escape($Name) + '\s*\{')) {
                $body = New-Object System.Collections.ArrayList
                for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                    $t = $lines[$j].Trim()
                    if ($t -eq '}') { break }          # first standalone brace closes the fn
                    if ($t -ne '') { [void]$body.Add($t) }
                }
                [void]$bodies.Add(($body -join "`n"))
            }
        }
        return $bodies
    }

    $src    = Get-Content $script:AdSearchPsm1 -Raw
    $bodies = @(Get-FnBodies -Src $src -Name 'Test-AdSearchDnInLocalDomain')

    It 'defines the predicate twice (module-level helper + inline engine copy)' {
        $bodies.Count | Should Be 2
    }
    It 'the two copies are byte-identical after whitespace normalization' {
        $bodies[0] | Should Be $bodies[1]
    }
}
