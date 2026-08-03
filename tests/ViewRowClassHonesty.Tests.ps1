# =============================================================================
#  ViewRowClassHonesty.Tests.ps1 - a non-success row is never painted as success.
#
#  WHY THIS IS CLASS-SCOPED: the row background is the only thing an operator
#  reads when scanning a 200-host wave. Painting a host GREEN when its outcome is
#  unknown is the same false-clean family this suite keeps relapsing into (the
#  always-OK updater triggers, the inert registry verifies, the MSU
#  "already installed") - just rendered instead of returned. A test naming the one
#  view you fixed passes while the next paste re-introduces it, so this asserts
#  the SHAPE across every view file and lets each real exception be declared
#  explicitly below.
#
#  Found by exactly this sweep on 2026-08-03: pkginstall painted 'Skipped' green
#  though the module emits it for a never-dispatched host AND for an MSI cancelled
#  in flight whose outcome its own comment calls "genuinely UNKNOWN"; remoteadmin
#  had no 'skipped' case at all, so the wrong-box DNS-mismatch abort - the row that
#  most needs to stand out - was the blandest in the grid.
#
#  Run: Invoke-Pester -Path .\tests\ViewRowClassHonesty.Tests.ps1
# =============================================================================
$script:Root     = Split-Path $PSScriptRoot -Parent
$script:ViewsDir = Join-Path $script:Root 'web\js\views'

function Get-ViewSource { param([string]$Name) Get-Content -LiteralPath (Join-Path $script:ViewsDir $Name) -Raw }

Describe 'pkginstall - a cancelled or undispatched host is not green' {
    $src = Get-ViewSource 'pkginstall.view.js'

    It "'Skipped' no longer maps to row-ok" {
        ($src -match "case 'Skipped': return 'row-ok'")  | Should Be $false
        ($src -match "case 'Skipped': return 'row-warn'") | Should Be $true
    }
    It 'Success still maps to row-ok (the fix did not overreach)' {
        ($src -match "case 'Success': return 'row-ok'") | Should Be $true
    }
}

Describe 'remoteadmin - the wrong-box abort is visible' {
    $src = Get-ViewSource 'remoteadmin.view.js'

    # psm1:324 sets Status='Skipped' when the answering box is not the dialled one and
    # the operator's arbitrary scriptblock was NOT run.
    It "statusCell treats 'skipped' as a warning" {
        ($src -match "low === 'session error' \|\| low === 'skipped'") | Should Be $true
    }
    It "the results rowClass treats 'skipped' as a warning" {
        ($src -match "s === 'session error' \|\| s === 'skipped'\) return 'row-warn'") | Should Be $true
    }
}

Describe 'no view paints an unknown-outcome status as success' {

    # The sweep. Any view that maps a status whose NAME says the work did not
    # certainly happen onto the success class is a finding. secureboot is the one
    # declared exception - see below.
    # Only the clause that actually YIELDS row-ok counts. Scanning the whole line
    # flagged patchlib ('ON HAND' -> row-ok, 'UNKNOWN' -> row-warn on one ternary
    # line): both strings present, but UNKNOWN maps to amber and sits AFTER the
    # row-ok. So: cut the line at the first 'row-ok', then keep only the tail after
    # the last preceding row-bad/row-warn/statement break - that is the condition
    # that produced the green. (This test's own first run produced that false
    # positive; the narrowing is the fix.)
    It "no view maps a cancelled/unknown/undispatched status to row-ok" {
        $offenders = New-Object System.Collections.ArrayList
        foreach ($f in (Get-ChildItem -LiteralPath $script:ViewsDir -Filter '*.view.js')) {
            if ($f.Name -eq 'secureboot.view.js') { continue }   # declared exception, asserted below
            foreach ($line in ((Get-Content -LiteralPath $f.FullName) -split "`n")) {
                $i = $line.IndexOf("row-ok")
                if ($i -lt 0) { continue }
                $clause = $line.Substring(0, $i)
                $cut = [regex]::Matches($clause, "row-warn|row-bad|;")
                if ($cut.Count -gt 0) {
                    $last = $cut[$cut.Count - 1]
                    $clause = $clause.Substring($last.Index + $last.Length)
                }
                if ($clause -match "(?i)'(Cancell?ed|Unknown|Abandoned|Undispatched|Skipped)'") {
                    [void]$offenders.Add("$($f.Name): $($line.Trim())")
                }
            }
        }
        ($offenders -join "`n") | Should BeNullOrEmpty
    }

    # Proves the narrowing above did not neuter the check: secureboot's line is the
    # exact shape the sweep must still catch, and it IS caught when not excluded.
    It 'the sweep still detects the shape it is looking for (self-check)' {
        $line   = "          if (s === 'Success' || s === 'Skipped') return 'row-ok';"
        $i      = $line.IndexOf("row-ok")
        $clause = $line.Substring(0, $i)
        $cut    = [regex]::Matches($clause, "row-warn|row-bad|;")
        if ($cut.Count -gt 0) { $last = $cut[$cut.Count - 1]; $clause = $clause.Substring($last.Index + $last.Length) }
        ($clause -match "(?i)'(Cancell?ed|Unknown|Abandoned|Undispatched|Skipped)'") | Should Be $true
    }

    # DECLARED EXCEPTION - a deliberate non-change, pinned so nobody "finishes" the
    # sweep by breaking it. secureboot's 'Skipped' does NOT mean unknown: it means the
    # host is ALREADY ENABLED or has a set ALREADY PENDING a reboot (psm1:658, :1129) -
    # the desired end state, reached with no BIOS write attempted. Its genuinely
    # non-success sibling 'Refused' was already split out to amber by the 2026-07-24
    # audit. Green is correct here; the name just collides with pkginstall's.
    It 'secureboot keeps Skipped green ON PURPOSE (already-enabled / already-pending)' {
        $src = Get-ViewSource 'secureboot.view.js'
        ($src -match "if \(s === 'Success' \|\| s === 'Skipped'\) return 'row-ok'") | Should Be $true
        # ...and Refused must STAY amber, which is what makes the above safe
        ($src -match "s === 'Timeout' \|\| s === 'Refused'\) return 'row-warn'")    | Should Be $true
    }
}
