# =============================================================================
#  Adsearch.ReadFailureHonesty.Tests.ps1 - a failed AD read is never reported as
#  a proven absence.
#
#  THE FAMILY (loop 2026-08-05): three sites in this module turned an ERRORED
#  directory read into a confident NEGATIVE claim - which is worse than an empty
#  result, because an operator acts on it:
#
#    BulkComputer (:866-930) - the batch query's catch falls back to a per-name
#      query whose own catch {} swallowed. If BOTH threw, $foundMachines was empty
#      and EVERY name was emitted Status='Not Found' - telling the operator that 50
#      real machines are not in AD, on a read that never succeeded. Those rows were
#      also excluded from auditCount as though the absence were proven.
#
#    BaseUsers base-OU (:945) - a swallowed FindAll produced "No OU matching
#      '<base>' was found in the domain. Try: LAKENHEATH, RAMSTEIN...", so an LDAP
#      timeout read as "that base does not exist".
#
#    BaseUsers child-OU (:993) - the OU was added to $searchedOUs BEFORE its user
#      query ran, and that query's catch {} swallowed. The summary then claimed
#      "... across N searched OU(s)" counting OUs whose read had failed. Worst case:
#      the Administrative OU denies the query, every privileged account is silently
#      missing from the export, and that OU is reported as covered.
#
#  The rule these now follow, and the one this file exists to hold: "we could not
#  read it" must never render as "it is not there".
#
#  Run: Invoke-Pester -Path .\tests\Adsearch.ReadFailureHonesty.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Raw
$script:View = Get-Content (Join-Path $script:Root 'web\js\views\adsearch.view.js') -Raw

Describe 'BulkComputer - an errored lookup is not an absent machine' {

    It 'the per-name fallback records WHY it failed instead of swallowing' {
        ($script:Src -match '\} catch \{ \$lookupErrors\[\$name\] = \$_\.Exception\.Message \}') | Should Be $true
    }
    It 'a name whose lookup errored is reported Lookup Failed, not Not Found' {
        ($script:Src -match "_status         = \`$\(if \(\`$failMsg\) \{ ""Lookup Failed"" \} else \{ ""Not Found"" \}\)") | Should Be $true
    }
    It 'and the reason travels with the row so it is actionable' {
        ($script:Src -match "_fullOU         = \`$\(if \(\`$failMsg\) \{ \`$failMsg \} else \{ ""N/A"" \}\)") | Should Be $true
    }
    It 'a genuine miss is still reported Not Found (the fix did not blanket everything)' {
        ($script:Src -match '"NOT FOUND"') | Should Be $true
    }
}

Describe 'BaseUsers - a failed search is not an empty domain' {

    It 'the base-OU search records its failure' {
        ($script:Src -match '\} catch \{ \$baseOULookupError = \$_\.Exception\.Message \}') | Should Be $true
    }
    It 'and says the search FAILED rather than that the base does not exist' {
        ($script:Src -match "The OU search for '\`$baseName' FAILED - this is NOT a statement that the base does not exist") | Should Be $true
    }
    It 'an OU counts as searched only AFTER its user read succeeds' {
        # The marker must sit after the FindAll, not before it.
        $iFind = $script:Src.IndexOf('$userResults = $userSearcher.FindAll()')
        $iMark = $script:Src.IndexOf('[void]$searchedOUs.Add($childOUDN)')
        ($iFind -gt 0) | Should Be $true
        ($iMark -gt 0) | Should Be $true
        ($iMark -gt $iFind) | Should Be $true
    }
    It 'a failed child-OU read is recorded separately from the searched list' {
        ($script:Src -match '\} catch \{ \[void\]\$ouReadFailures\.Add\("\$baseOUDN : \$\(\$_\.Exception\.Message\)"\) \}') | Should Be $true
        ($script:Src -match '\$ouReadFailures = \[System\.Collections\.ArrayList\]::new\(\)')                              | Should Be $true
    }
    It 'and surfaced as a row saying the export is INCOMPLETE' {
        ($script:Src -match 'OU search\(es\) errored - results are INCOMPLETE')                    | Should Be $true
        ($script:Src -match 'Accounts under these OUs are NOT accounted for')                      | Should Be $true
    }
}

Describe 'adsearch - manifest EXACT pin (newest bump = 3.4.2, read-failure honesty)' {
    # Migrated here from Adsearch.RowProjection.Tests.ps1, which now floors at 3.4.1.
    It 'adsearch is exactly 3.4.2' {
        $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Force -PassThru
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '3.4.2'
    }
}

Describe 'the view counts and colours the new statuses' {

    # The trap this nearly fell into: bulkStatusCls returns '' for an unrecognised
    # status, so a brand-new status would render unstyled AND fall through every
    # branch of the summary tally - vanishing from "of N" exactly like the dhcp and
    # certdeploy defects fixed earlier this week. Adding the status without adding
    # the bucket would have introduced the family while fixing it.
    It 'a lookup failure is matched BEFORE not-found, so it never colours as a clean miss' {
        $iFail = $script:View.IndexOf("s.indexOf('lookup failed')")
        $iMiss = $script:View.IndexOf("s.indexOf('not found')")
        ($iFail -gt 0)      | Should Be $true
        ($iFail -lt $iMiss) | Should Be $true
    }
    It 'it is counted in its own bucket, not lumped into Not Found' {
        ($script:View -match 'if \(isLookupFailure\(r\.Status\)\) \{ lf\+\+; return; \}') | Should Be $true
        ($script:View -match "LOOKUP FAILED: ' \+ lf")                                    | Should Be $true
    }
    It 'and the operator is told what it means' {
        ($script:View -match 'NOT confirmed absent') | Should Be $true
    }
}
