# =============================================================================
#  Adsearch.LastPcCoverage.Tests.ps1 - Pester 3.4 for the two Last PC coverage
#  defects found in the 2026-07-24 audit.
#
#  P2 (bogus coverage): Get-WinEvent -ErrorAction Stop THROWS when the Security log
#      simply holds no matching event, so a DC that answered perfectly well with
#      "nothing here" was filed as a DC ERROR and never counted in $dcsScanned. A
#      complete, successful domain-wide scan therefore reported "0 of 12 DC(s)" and
#      topped the message off with a false "you do not have permission" hint.
#  P2 (all-denied looked like no-results): the zero-hit exit returned _Error with no
#      _Failure, so a scan in which EVERY DC refused access audited as Skipped with
#      failed=0 and rendered "Done. No results." - which reads as "this person has
#      not logged on anywhere" when in truth nothing was ever searched.
#
#  Test-AdLastPcAllDenied is the single, exported copy of that verdict (the engine
#  hands the handler the coverage numbers rather than duplicating the rule), so this
#  is a pure offline unit test - no AD, no DCs.
#
#  Run:  Invoke-Pester -Path .\tests\Adsearch.LastPcCoverage.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1') -Force | Out-Null

Describe 'LastPC all-DCs-denied verdict (audit 2026-07-24 P2)' {

    It 'a zero-hit scan in which NOT ONE DC was read is a FAILURE (the bug: it was "no results")' {
        (Test-AdLastPcAllDenied -DcsScanned 0 -DcsTotal 12) | Should Be $true
    }

    It 'a zero-hit scan that DID read a DC stays a genuine empty result' {
        (Test-AdLastPcAllDenied -DcsScanned 1 -DcsTotal 12) | Should Be $false
    }

    It 'full coverage with no hits is not a failure' {
        (Test-AdLastPcAllDenied -DcsScanned 12 -DcsTotal 12) | Should Be $false
    }

    It 'no DCs discovered at all is left to its own _Failure path, not double-reported' {
        (Test-AdLastPcAllDenied -DcsScanned 0 -DcsTotal 0) | Should Be $false
    }
}

# -----------------------------------------------------------------------------
#  Wiring guards: the verdict above only helps if the engine actually publishes the
#  coverage numbers on the zero-hit exit and the handler actually applies it, and if
#  a clean-but-empty DC is counted as scanned rather than filed as an error. These
#  are source assertions (the engine runs in a bare child runspace against live DCs).
# -----------------------------------------------------------------------------
Describe 'LastPC coverage wiring (audit 2026-07-24 P2)' {
    $src = [System.IO.File]::ReadAllText((Join-Path $script:Root 'modules\JanetWeb.adsearch.psm1'))

    It 'the zero-hit exit publishes the coverage numbers for the handler' {
        $src.Contains('_Error = $msg; _dcsScanned = $dcsScanned; _dcsTotal = $dcs.Count') | Should Be $true
    }

    It 'the handler applies Test-AdLastPcAllDenied to that exit' {
        ([regex]::Matches($src, [regex]::Escape('Test-AdLastPcAllDenied -DcsScanned'))).Count | Should Be 1
    }

    It 'coverage is decided by query success, not by whether rows came back' {
        # the fixed test; the old one was `elseif ($null -ne $events)`
        $src.Contains('} elseif ($null -eq $res.Error) {') | Should Be $true
        $src.Contains('} elseif ($null -ne $events) {')    | Should Be $false
    }

    It 'the DC worker reports a clean "no matching events" as success, not an error' {
        ([regex]::Matches($src, [regex]::Escape("Error = `$null; NoMatch = `$true"))).Count | Should Be 2
    }
}
