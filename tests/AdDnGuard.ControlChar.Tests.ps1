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

# -----------------------------------------------------------------------------
#  Drift guard (loop-10): the DN guard exists as THREE hand-copied bodies -
#  adsearch module-level + an inline copy in the bare-runspace $script:AdSearchEngine
#  (the module comment calls this pair "BYTE-IDENTICAL"), plus adto's module-level
#  copy. The loop-9 control-char reject had to be applied to all three by hand; if a
#  future edit lands in only one, the guard silently weakens in the others. These
#  tests fail the moment the copies diverge. (Text/source assertions - no runspace.)
# -----------------------------------------------------------------------------
Describe 'DN guard - source-copy drift guard' {
    $adsearchSrc = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
    $adtoSrc     = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adto.psm1'))
    # Normalize each source line to its trimmed content so the 4-space module copy and
    # the 8-space inline copy compare equal on body, not indentation.
    $bodies = [regex]::Matches($adsearchSrc, '(?s)function\s+Test-AdSearchDnInLocalDomain\s*\{(.*?)\r?\n[ \t]*\}')
    $norm = { param($s) (($s -split "\r?\n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) -join "`n" }

    It 'has exactly two Test-AdSearchDnInLocalDomain copies in adsearch (module + inline engine)' {
        $bodies.Count | Should Be 2
    }
    It 'the two adsearch copies are byte-identical (indentation-normalized)' {
        (& $norm $bodies[0].Groups[1].Value) | Should Be (& $norm $bodies[1].Groups[1].Value)
    }
    It 'the control-char reject is present in BOTH adsearch copies' {
        ([regex]::Matches($adsearchSrc, [regex]::Escape("-match '[\x00-\x1f]'"))).Count | Should Be 2
    }
    It 'the control-char reject is present in the adto copy' {
        ([regex]::Matches($adtoSrc, [regex]::Escape("-match '[\x00-\x1f]'"))).Count | Should Be 1
    }
}
