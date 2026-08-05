# =============================================================================
#  Adsearch.RowProjection.Tests.ps1 - Pester 3.4 for two row-projection defects
#  found in the 2026-07-24 audit.
#
#  P2 (groups over 1500 members): AD caps a multi-valued attribute at MaxValRange
#      (1500 by default) and past that returns the values under a RANGED key -
#      'member;range=0-1499' - INSTEAD of 'member'. The projector read only
#      'member', so every large group rendered MemberCount 0 with an empty Members
#      cell, i.e. it looked like an empty group.
#  P3 (Base Users last logon): the Base Users row rendered the NON-replicated
#      lastLogon, which is maintained per-DC, so accounts that log on daily showed
#      "never". Every other action already used the replicated lastLogonTimestamp.
#
#  Pure projector tests - no AD, no runspace.
#
#  Run:  Invoke-Pester -Path .\tests\Adsearch.RowProjection.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Force | Out-Null

# 1500 DNs is exactly the page AD hands back as 'member;range=0-1499'.
$BigMembers = @(1..1500 | ForEach-Object { "CN=User$_,OU=Users,DC=AREA52,DC=MIL" })

Describe 'Group member RANGE retrieval (audit 2026-07-24 P2)' {

    It 'counts members carried under the ranged key (the bug: MemberCount was 0)' {
        $P = @{ name = 'BIG-GROUP'; distinguishedname = 'CN=BIG-GROUP,DC=AREA52,DC=MIL'
                'member;range=0-1499' = $BigMembers }
        $row = ConvertTo-AdGridRow -ActionId 'search-group' -P $P -Index 0
        $row['MemberCount'] | Should Be 1500
    }

    It 'lists members from the ranged key (the bug: the Members cell was empty)' {
        $P = @{ name = 'BIG-GROUP'; distinguishedname = 'CN=BIG-GROUP,DC=AREA52,DC=MIL'
                'member;range=0-1499' = $BigMembers }
        $row = ConvertTo-AdGridRow -ActionId 'search-group' -P $P -Index 0
        ([string]$row['Members']).StartsWith('User1;') | Should Be $true
    }

    It 'honours the final-page terminator key (member;range=1500-*)' {
        $P = @{ name = 'BIG-GROUP'; distinguishedname = 'CN=BIG-GROUP,DC=AREA52,DC=MIL'
                'member;range=1500-*' = @('CN=Tail,DC=AREA52,DC=MIL') }
        (Get-AdMemberValues $P).Count | Should Be 1
    }

    It 'still reads a plain member attribute (no regression for small groups)' {
        $P = @{ name = 'SMALL'; distinguishedname = 'CN=SMALL,DC=AREA52,DC=MIL'
                member = @('CN=A,DC=AREA52,DC=MIL','CN=B,DC=AREA52,DC=MIL') }
        $row = ConvertTo-AdGridRow -ActionId 'search-group' -P $P -Index 0
        $row['MemberCount'] | Should Be 2
        $row['Members']     | Should Be 'A; B'
    }

    It 'reports 0 for a genuinely empty group' {
        $P = @{ name = 'EMPTY'; distinguishedname = 'CN=EMPTY,DC=AREA52,DC=MIL' }
        $row = ConvertTo-AdGridRow -ActionId 'search-group' -P $P -Index 0
        $row['MemberCount'] | Should Be 0
        $row['Members']     | Should Be ''
    }

    It 'prefers the plain key when both are somehow present' {
        $P = @{ member = @('CN=Plain,DC=AREA52,DC=MIL'); 'member;range=0-1499' = $BigMembers }
        (Get-AdMemberValues $P).Count | Should Be 1
    }

    It 'the engine pages the ranges itself (source guard - the real fix)' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
        ([regex]::Matches($src, [regex]::Escape('function Get-AdRangedMemberValues'))).Count | Should Be 1
        $src.Contains('member;range=$lo-*') | Should Be $true
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - the P2 range-paging fix above had a
#  hole on its ERROR path. The Group arm did `$props.Remove($ranged)` and then set
#  member from Get-AdRangedMemberValues, whose `catch { $more = $false }` returns
#  NOTHING when the very first re-read page throws. So the 1500 values AD had ALREADY
#  handed back under 'member;range=0-1499' were thrown away and the group rendered
#  MemberCount 0 again - the exact pre-fix symptom. A PARTIAL page set was also shown
#  with no truncation warning. Merge-AdRangedMemberValues is now the single rule: keep
#  the longer set, and say when the enumeration is known-incomplete.
#
#  These FAIL on the pre-fix engine (no merge, no completeness signal).
# =============================================================================
Describe 'Ranged member re-read failure keeps the fetched page (audit 2026-07-25)' {

    # exactly the page AD returns as 'member;range=0-1499'
    $FirstPage = @(1..1500 | ForEach-Object { "CN=User$_,OU=Users,DC=AREA52,DC=MIL" })

    It 'a re-read that throws on its FIRST page keeps the 1500 fetched members (the bug: back to 0)' {
        # a first-page throw is exactly what the pager returns as an empty, incomplete set
        $m = Merge-AdRangedMemberValues -SeedPage $FirstPage -Paged @() -Complete $false
        @($m.Members).Count | Should Be 1500
    }

    It 'and it SAYS so - the kept set is flagged truncated, not passed off as the whole group' {
        (Merge-AdRangedMemberValues -SeedPage $FirstPage -Paged @() -Complete $false).Truncated | Should Be $true
    }

    It 'a PARTIAL page set (page 2 threw after page 1 landed) is kept AND flagged truncated' {
        $partial = @($FirstPage) + @('CN=Tail,DC=AREA52,DC=MIL')
        $m = Merge-AdRangedMemberValues -SeedPage $FirstPage -Paged $partial -Complete $false
        @($m.Members).Count | Should Be 1501
        $m.Truncated        | Should Be $true
    }

    It 'a COMPLETE re-read wins and carries NO warning (the happy path is unchanged)' {
        $full = @($FirstPage) + @(1..200 | ForEach-Object { "CN=Extra$_,DC=AREA52,DC=MIL" })
        $m = Merge-AdRangedMemberValues -SeedPage $FirstPage -Paged $full -Complete $true
        @($m.Members).Count | Should Be 1700
        $m.Truncated        | Should Be $false
    }

    It 'the surviving members still project to a real MemberCount (end-to-end)' {
        $kept = Merge-AdRangedMemberValues -SeedPage $FirstPage -Paged @() -Complete $false
        $P = @{ name = 'BIG-GROUP'; distinguishedname = 'CN=BIG-GROUP,DC=AREA52,DC=MIL'; member = @($kept.Members) }
        (ConvertTo-AdGridRow -ActionId 'search-group' -P $P -Index 0)['MemberCount'] | Should Be 1500
    }

    It 'the engine MERGES instead of blind-overwriting (source guard - the real fix)' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
        $src.Contains('$seedPage = @($props[$ranged])')                     | Should Be $true
        $src.Contains('$props[''member''] = @($merged.Members)')            | Should Be $true
        # the discard-then-overwrite line is gone
        $src.Contains('$props[''member''] = @(Get-AdRangedMemberValues')    | Should Be $false
        # the pager reports completeness instead of swallowing the throw
        $src.Contains('$more = $false; $failed = $true')                    | Should Be $true
        $src.Contains('return @{ Members = $all.ToArray(); Complete = $complete }') | Should Be $true
    }

    It 'a known-incomplete group enumeration reaches the operator as a WARNING' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
        $src.Contains('$props[''_memberTruncated''] = $true')  | Should Be $true
        $src.Contains('Member list INCOMPLETE for')            | Should Be $true
        ($src -match "\`$summary\['memberTruncated'\]\s*=\s*\`$true") | Should Be $true
    }

    It 'the engine copy and the exported copy of the merge rule are identical CODE' {
        # the two copies exist because the engine runs in a bare child runspace with no
        # module scope (same reason Escape-LdapFilterValue is inlined). Comments differ;
        # the CODE must not - a divergent copy is how the runspace silently gets an old rule.
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
        $bodies = @([regex]::Matches($src, '(?s)function Merge-AdRangedMemberValues \{(.*?)\n\s*\}') |
                    ForEach-Object {
                        (($_.Groups[1].Value -split "`n" |
                          Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }) -join '') -replace '\s+', ''
                    })
        $bodies.Count | Should Be 2
        $bodies[0]    | Should Be $bodies[1]
    }
}

Describe 'adsearch - manifest floor (3.4.1 = audit 2026-07-25 fable re-audit follow-up)' {
    # Demoted from an exact pin to a FLOOR on 2026-08-05: 3.4.2 is the read-failure
    # honesty fix, so the exact pin moved to that change's own test file
    # (Adsearch.ReadFailureHonesty.Tests.ps1), per the convention that the newest bump
    # carries the exact pin and older files assert a floor. This file guards the row
    # projection, not adsearch's version number.
    It 'adsearch is at or past 3.4.1' {
        ([version][string](Get-JanetToolManifest).version -ge [version]'3.4.1') | Should Be $true
    }
}

Describe 'Base Users last logon uses the REPLICATED attribute (audit 2026-07-24 P3)' {

    # 2026-07-01 00:00:00 UTC as a FILETIME, formatted by Format-AdFileTime in local time.
    $ft       = ([datetime]'2026-07-01T00:00:00Z').ToFileTime()
    $expected = [datetime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm')

    It 'renders lastLogonTimestamp when the per-DC lastLogon says never (the bug)' {
        $P = @{ samaccountname = 'jdoe'; lastlogon = 0; lastlogontimestamp = $ft }
        $row = ConvertTo-AdGridRow -ActionId 'search-base-users' -P $P -Index 0
        $row['LastLogon'] | Should Be $expected
    }

    It 'prefers lastLogonTimestamp over a stale per-DC lastLogon' {
        $P = @{ lastlogon = ([datetime]'2020-01-01T00:00:00Z').ToFileTime(); lastlogontimestamp = $ft }
        (Get-AdLastLogonString $P) | Should Be $expected
    }

    It 'falls back to lastLogon when the replicated value is absent' {
        $P = @{ lastlogon = $ft }
        (Get-AdLastLogonString $P) | Should Be $expected
    }

    It 'still reports never when neither attribute carries a logon' {
        (Get-AdLastLogonString @{ lastlogon = 0; lastlogontimestamp = 0 }) | Should Be 'never'
    }

    It 'loads lastLogonTimestamp for Base Users (source guard)' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))
        ([regex]::Matches($src, [regex]::Escape("'lockouttime','lastlogontimestamp','lastlogon'"))).Count | Should Be 1
    }
}
