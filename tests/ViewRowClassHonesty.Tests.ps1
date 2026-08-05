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

Describe 'dhcp - a REFUSED scope is not tallied as a change' {
    $src = Get-ViewSource 'dhcp.view.js'

    # loop 2026-08-03: the bulk row handler's catch-all was OPEN - anything unrecognised
    # was counted as a change and logged green. The engine's own 'ReadError' refusal (it
    # declined to write because it could not read the current value) matched no branch, so
    # a scope JANET explicitly REFUSED to touch rendered "0 -> 0 value(s)" at level ok and
    # the tally said "0 error(s)". loop65 had already fixed exactly this ON THE MODULE SIDE
    # (dhcp.psm1:1062-1068) and the view was never swept - the two sides contradicted each
    # other, module auditing a Failure while the operator saw green.
    It 'the catch-all fails CLOSED - only the engine success statuses count as a change' {
        ($src -match "else if \(st !== 'Changed' && st !== 'WouldChange'\)") | Should Be $true
        ($src -match "REFUSED/UNKNOWN")                                      | Should Be $true
    }
    # loop 2026-08-03: currentOptionId() ended in '|| 6', so a BLANK or typo'd custom
    # option ID became 6 (006 DNS Servers) CLIENT-SIDE. loop69 had added a server-side
    # guard refusing exactly that on a destructive write - "defaulting would live-replace
    # the scope's DNS servers" (dhcp.psm1:1271) - but the view handed the server a
    # perfectly valid 6, so that guard could never fire. Fifth instance of a guard added
    # on one side while the thing that defeats it was left on the other.
    It 'the view never invents an option ID (no silent default to 6)' {
        ($src -match "parseInt\(optIdInput\.value, 10\) \|\| 6") | Should Be $false
        ($src -match 'function optionIdOk\(\)')                  | Should Be $true
        # all three senders (load, apply, bulk) refuse rather than guess
        (@([regex]::Matches($src, 'if \(!optionIdOk\(\)\) \{ refuseBadOptionId\(\); return; \}')).Count) | Should Be 3
    }
    It 'the server-side guard it was defeating is still there' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw
        ($mod -match 'refusing a destructive write rather than defaulting to option 6') | Should Be $true
    }
    It 'the module side it mirrors is still fail-closed (both halves must agree)' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw
        ($mod -match "elseif \(\`$status -eq 'NoChange'\) \{ \`$nochange\+\+ \}") | Should Be $true
        ($mod -match "else \{ \`$errs\+\+ \}")                                    | Should Be $true
    }
}

Describe 'tallies fail closed - an unknown status is never counted as compliant' {

    # loop 2026-08-04, the same family one level up from row colour: a COUNTER whose final
    # branch is open silently books unrecognised or errored outcomes as good news, and the
    # summary line is what gets reported up a chain of command. Four sites, all found by
    # sweeping for the dhcp defect's shape rather than waiting for them to be reported.
    It 'c2c per-pillar tally has an explicit other bucket (it counted unknown as nochange)' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw
        ($mod -match "elseif \(@\('NOCHANGE','NO CHANGE'\) -contains \`$pr\)") | Should Be $true
        ($mod -match "else                                                           \{ \`$perPillar\[\`$pn\]\.other\+\+ \}") | Should Be $true
    }
    It 'c2c per-pillar tally no longer drops a whole host inside a bare catch' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw
        ($mod -match "\} catch \{ \`$perPillarErrors\+\+ \}")                | Should Be $true
        ($mod -match 'per-pillar counts are INCOMPLETE')                     | Should Be $true
    }
    It 'c2c fix done-line downgrades from ok when anything went wrong' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw
        ($mod -match "\`$doneLvl = if \(\`$doneBad -gt 0\) \{ 'warn' \} else \{ 'ok' \}") | Should Be $true
        ($mod -match "level=\`$doneLvl")                                                  | Should Be $true
    }
    It 'c2c version-check tally counts unknown statuses and lets them fail the run' {
        $src = Get-ViewSource 'c2c.view.js'
        ($src -match 'else t\.other\+\+;')                              | Should Be $true
        ($src -match 'var bad = c\.outdated \+ c\.offline \+ c\.other;') | Should Be $true
    }
    It 'certdeploy scan summary accounts for CHECK ERROR / Cancelled instead of losing them' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Raw
        ($mod -match "\`$errored     = @\(\`$rows \| Where-Object \{ \[string\]\`$_\.Status -eq 'CHECK ERROR' \}\)\.Count") | Should Be $true
        ($mod -match "\`$unaccounted = \[Math\]::Max\(0,")                                                                  | Should Be $true
        ($mod -match "\`$lvl = if \(\(\`$errored \+ \`$cancelled \+ \`$unaccounted\) -gt 0\) \{ 'warn' \} else \{ 'ok' \}")  | Should Be $true
    }
}

Describe 'telemetry classifies on a field the action actually emits' {

    # loop 2026-08-04: wpt's app-update-apply telemetry read r.Success, which that action
    # never emits - its RowOf returns Host/Status/Detail only. asBool(undefined) is false,
    # so every apply row booked "Failed" in Reports/Usage and the Updates stat never moved,
    # while the grid showed Status=OK. A contract mismatch, not a colour bug: the view and
    # the audit were describing the same row differently.
    It 'app-update-apply classifies on Status, not on a non-existent Success field' {
        $src = Get-ViewSource 'wpt.view.js'
        ($src -match "case 'app-update-apply': if \(asBool\(r\.Success\)\)") | Should Be $false
        ($src -match 'var aus = String\(r\.Status \|\| ..\);')               | Should Be $true
    }
    It 'and it uses the module OWN vocabulary (OK success; Pending/Skipped neither)' {
        $src = Get-ViewSource 'wpt.view.js'
        ($src -match "if \(/\^OK\$/i\.test\(aus\)\) \{ add\.updates = 1")     | Should Be $true
        ($src -match "else if \(/\^\(pending\|skipped\)\$/i\.test\(aus\)\)")  | Should Be $true
        # the module side those mirror - if either changes, they must change together
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
        ($mod -match "-OkOf \{ param\(\`$r\) \(\`$r\.Status -eq 'OK'\) \}")   | Should Be $true
        ($mod -match "\`"\`$\(\`$r\.Status\)\`" -eq 'Pending' -or \`"\`$\(\`$r\.Status\)\`" -eq 'Skipped'") | Should Be $true
    }
    # loop 2026-08-05, same family one action over: bulk-patch booked a
    # VulnPatched/Success audit (itemCount=1) and a 'Patched' row for a host with 0
    # updates and 0 apps triggered - a host it did nothing to. On a wave where most
    # machines are already current that is a fleet-wide phantom patch in the ledger
    # that gets reported upward. The module already printed "0 updates, 0 apps -
    # nothing to trigger" in the activity log for that same host.
    It 'bulk-patch requires evidence of work before booking a patch' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
        ($mod -match '\(\(\(\[int\]\$r\.UpdatesTriggered\) \+ \(\[int\]\$r\.AppsTriggered\)\) -gt 0\)') | Should Be $true
    }
    It 'and a clean no-op audits Skipped, never Failure (a healthy host is not a failure)' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
        ($mod -match "elseif \(\[bool\]\`$r\.Reachable -and \[string\]::IsNullOrEmpty\(\[string\]\`$r\.Error\)\) \{ 'Skipped' \}") | Should Be $true
    }
    It 'the view agrees with the audit rather than calling every reachable host Patched' {
        $src = Get-ViewSource 'wpt.view.js'
        ($src -match "result = \(u \+ a\) > 0 \? 'Patched' : 'No change';") | Should Be $true
        ($src -match "result = asBool\(r\.Reachable\) \? 'Patched' : 'Unreachable'") | Should Be $false
    }
    It 'the RowOf really does emit Status and not Success' {
        $mod = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
        ($mod -match "-RowOf \{ param\(\`$r\) @\{ Host=\`$r\.Host; Status=\[string\]\`$r\.Status; Detail=\[string\]\`$r\.Detail \} \}") | Should Be $true
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
