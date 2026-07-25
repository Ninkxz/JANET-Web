# =============================================================================
#  Adsearch.UserFilter.Tests.ps1 - Pester 3.4 for the Search Users LDAP filter
#  (audit 2026-07-24 P1). The old builder was a single interpolated line that
#  ALWAYS appended (givenName=<v>*) and (sn=<v>*). With those fields blank the
#  clauses collapse to (givenName=*) / (sn=*), which in LDAP are PRESENCE tests -
#  so every account that simply has no givenName/sn (.adm / .adw admin accounts,
#  service accounts, org boxes) was filtered out even on an exact EDIPI search and
#  the operator concluded the account did not exist.
#
#  These assert (a) an EDIPI-only search carries NO givenName/sn clause at all,
#  (b) the RFC-4515 escaping of operator input is untouched, and (c) the module
#  copy and the bare-runspace inline copy of the builder have not drifted.
#
#  Run:  Invoke-Pester -Path .\tests\Adsearch.UserFilter.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Force | Out-Null

$Head = '(&(objectCategory=person)(objectClass=user)'

Describe 'Search Users LDAP filter - clause selection (audit 2026-07-24 P1)' {

    It 'an EDIPI-only search emits ONLY the samaccountname clause (the bug: it also emitted (givenName=*)(sn=*))' {
        (New-AdUserLdapFilter -FirstName '' -LastName '' -Edipi '1234567890') |
            Should Be ($Head + '(samaccountname=1234567890*))')
    }

    It 'an EDIPI-only search contains no unconditional givenName presence clause' {
        $f = New-AdUserLdapFilter -FirstName '' -LastName '' -Edipi '1234567890'
        $f.Contains('(givenName=*)') | Should Be $false
        $f.Contains('givenName')     | Should Be $false
    }

    It 'an EDIPI-only search contains no unconditional sn presence clause' {
        $f = New-AdUserLdapFilter -FirstName '' -LastName '' -Edipi '1234567890'
        $f.Contains('(sn=*)') | Should Be $false
        $f.Contains('(sn=')   | Should Be $false
    }

    It 'a last-name-only search carries no samaccountname or givenName clause' {
        (New-AdUserLdapFilter -FirstName '' -LastName 'Doe' -Edipi '') |
            Should Be ($Head + '(sn=Doe*))')
    }

    It 'still ANDs every field the operator DID fill in' {
        (New-AdUserLdapFilter -FirstName 'John' -LastName 'Doe' -Edipi '123') |
            Should Be ($Head + '(givenName=John*)(sn=Doe*)(samaccountname=123*))')
    }

    It 'treats a whitespace-only field as unfilled' {
        (New-AdUserLdapFilter -FirstName "  `t " -LastName '' -Edipi '1234567890') |
            Should Be ($Head + '(samaccountname=1234567890*))')
    }

    It 'a $null field is unfilled, not a presence clause' {
        (New-AdUserLdapFilter -FirstName $null -LastName $null -Edipi '1234567890') |
            Should Be ($Head + '(samaccountname=1234567890*))')
    }
}

Describe 'Search Users LDAP filter - escaping is preserved (regression)' {

    It 'escapes the RFC-4515 metacharacters in a last name' {
        (New-AdUserLdapFilter -FirstName '' -LastName 'a*b(c)\d' -Edipi '') |
            Should Be ($Head + '(sn=a\2ab\28c\29\5cd*))')
    }

    It 'escapes an injected filter fragment in the EDIPI instead of honouring it' {
        $f = New-AdUserLdapFilter -FirstName '' -LastName '' -Edipi '1)(objectClass=*'
        $f | Should Be ($Head + '(samaccountname=1\29\28objectClass=\2a*))')
    }

    It 'escapes a NUL byte' {
        (New-AdUserLdapFilter -FirstName ('x' + [char]0 + 'y') -LastName '' -Edipi '') |
            Should Be ($Head + '(givenName=x\00y*))')
    }
}

# -----------------------------------------------------------------------------
#  Drift guard, same pattern the DN guard uses (AdDnGuard.ControlChar.Tests.ps1):
#  the engine runs in a BARE child runspace, so New-AdUserLdapFilter exists twice -
#  the module-level copy tested above and a hand-copied inline copy inside
#  $script:AdSearchEngine. If a future edit lands in only one, the tested copy stops
#  describing what actually runs. (Text/source assertions - no runspace.)
# -----------------------------------------------------------------------------
Describe 'Search Users filter builder - source-copy drift guard' {
    $src    = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
    $bodies = [regex]::Matches($src, '(?s)function\s+New-AdUserLdapFilter\s*\{(.*?)\r?\n[ \t]*\}')
    $norm   = { param($s) (($s -split "\r?\n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) -join "`n" }

    It 'has exactly two New-AdUserLdapFilter copies (module + inline engine)' {
        $bodies.Count | Should Be 2
    }

    It 'the two copies are byte-identical (indentation-normalized)' {
        (& $norm $bodies[0].Groups[1].Value) | Should Be (& $norm $bodies[1].Groups[1].Value)
    }

    It 'the old unconditional givenName/sn filter line is gone from the engine' {
        ([regex]::Matches($src, [regex]::Escape('(givenName=$(Escape-LdapFilterValue $firstName)*)(sn='))).Count |
            Should Be 0
    }

    It 'both the User arm and the LastPC user lookup route through the builder' {
        ([regex]::Matches($src, [regex]::Escape('$searcher.filter = New-AdUserLdapFilter'))).Count | Should Be 2
    }
}
