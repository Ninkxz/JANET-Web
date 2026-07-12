# =============================================================================
#  AdReferralChasing.Tests.ps1 - Pester 3.4 tests for the LDAP referral-chasing
#  hardening (loop-7 AD-bind capstone) shared by AD Search + AD Nemesis.
#
#  Every DirectorySearcher in adsearch/adto must set
#     $s.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
#  so even a local-domain-rooted search cannot auto-follow a directory-returned
#  EXTERNAL referral to a host the DN guard never vetted.
#
#  A live DC isn't available, so we assert the VERIFIABLE invariant offline:
#   (a) property-level - a freshly constructed searcher with the property set the
#       same way reports .ReferralChasing -eq 'None' (proves the enum/property
#       work on this PS build), and
#   (b) STATIC - the count of ReferralChasing=...None assignments in each module
#       source is >= the count of DirectorySearcher/[adsisearcher] constructions,
#       so every searcher is covered and a future un-hardened searcher fails here.
#
#  Run:  Invoke-Pester -Path .\tests\AdReferralChasing.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:AdSearchPsm1 = Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'
$script:AdToPsm1     = Join-Path $script:Root 'modules\JanetWeb.adto.psm1'

# Count searcher CONSTRUCTIONS: New-Object [System.]DirectoryServices.DirectorySearcher
# OR an [adsisearcher] cast. Whitespace-robust, case-insensitive (DN/type case varies).
function Get-SearcherConstructionCount {
    param([string]$Src)
    $ctor = [regex]::Matches($Src, '(?i)New-Object\s+(System\.)?DirectoryServices\.DirectorySearcher').Count
    $cast = [regex]::Matches($Src, '(?i)\[adsisearcher\]').Count
    return ($ctor + $cast)
}

# Count the hardening ASSIGNMENTS: <var>.ReferralChasing = [ ... ]::None
function Get-ReferralNoneCount {
    param([string]$Src)
    return [regex]::Matches($Src, '(?i)\.ReferralChasing\s*=\s*\[[^\]]*\]::None').Count
}

Describe 'LDAP referral-chasing hardening - property-level invariant (offline)' {
    It 'a fresh DirectorySearcher with ReferralChasing=None reports None' {
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        "$($s.ReferralChasing)" | Should Be 'None'
    }
    It 'the enum member ::None exists and is distinct from the .NET default (External)' {
        [string]([System.DirectoryServices.ReferralChasingOption]::None)     | Should Be 'None'
        [string]([System.DirectoryServices.ReferralChasingOption]::External) | Should Not Be 'None'
    }
}

Describe 'LDAP referral-chasing hardening - every AD Search searcher is covered' {
    $src   = Get-Content $script:AdSearchPsm1 -Raw
    $ctors = Get-SearcherConstructionCount -Src $src
    $none  = Get-ReferralNoneCount -Src $src

    It 'adsearch.psm1 constructs at least one searcher (sanity)' {
        $ctors | Should BeGreaterThan 0
    }
    It 'adsearch.psm1 hardens every searcher (ReferralChasing=None count >= construction count)' {
        $none | Should BeGreaterThan ($ctors - 1)   # i.e. $none -ge $ctors, robust on Pester 3.4
    }
}

Describe 'LDAP referral-chasing hardening - every AD Nemesis searcher is covered' {
    $src   = Get-Content $script:AdToPsm1 -Raw
    $ctors = Get-SearcherConstructionCount -Src $src
    $none  = Get-ReferralNoneCount -Src $src

    It 'adto.psm1 constructs at least one searcher (sanity)' {
        $ctors | Should BeGreaterThan 0
    }
    It 'adto.psm1 hardens every searcher (ReferralChasing=None count >= construction count)' {
        $none | Should BeGreaterThan ($ctors - 1)   # i.e. $none -ge $ctors, robust on Pester 3.4
    }
}
