# Design - Loop 35 - WPT App Updater "Custom Command" self-guard + wrong-box abort (Desktop)

Highest-value backlog item (loop-29 sweep, highest-severity finding). The Desktop WorkstationPatchingTool
App Updater has a **Custom Command** profile: the operator types free-form PowerShell into `txtAU2Custom`,
it is `[ScriptBlock]::Create()`d (`btnAU2Apply.Add_Click`, 11178) and dispatched via `Invoke-Command`
against every selected host inside `$wrapperSb` (11242). This arbitrary-RCE path has NEITHER a dispatcher
self-guard NOR the wrong-box DNS-mismatch abort that the tool's own Software-Uninstall (7213) and
Auto-Maintenance (6224) paths already implement. The only safeguard is a Yes/No confirm (11221). So an
operator can run arbitrary PowerShell against the JANET console itself, or against a stale-DNS/reused-IP
wrong box, with no technical guard.

This corrects ledger row 38's stale assumption ("no Desktop run-script twin") - the Custom Command IS the
Desktop arbitrary-run-script twin of the Web `remoteadmin` tool (which is already self-guarded + DNS-guarded).

## Web parity
The Web WPT (`JanetWeb.wpt.psm1`) has NO free-form/arbitrary-script action - every action is a fixed
remediation. The Web arbitrary-run-script surface is the separate `remoteadmin` tool, already carrying a
self-guard + DNS-mismatch hard-abort (ledger rows 22/38). So this is a **Desktop-only** fix; Web is
already clean. Row closes CLOSED-BOTH (Web already-clean, Desktop fixed).

## Fix (mirror the tool's OWN existing patterns - no new machinery)
Desktop `WorkstationPatchingTool_6.5.26.ps1` -> `6.5.27`:
1. **Dispatcher self-guard** in `btnAU2Apply.Add_Click` (after `$selected` is validated ~11159, BEFORE the
   confirm dialog so the count is honest): drop `Test-WptHostIsSelf` hosts - mirror the Reboot-Selected
   pattern verbatim (7600-7602): `$selfHits = @($selected | ? { Test-WptHostIsSelf $_ })`; if any, WARN via
   AU2Log + a MessageBox naming the dropped host(s) and `$selected = @($selected | ? { -not (Test-WptHostIsSelf $_) })`;
   if `$selected.Count -eq 0` after the drop, abort (nothing but self was selected). This is the critical
   guard - arbitrary PowerShell must NEVER run on the operator's own box.
2. **Wrong-box DNS-mismatch abort** inside `$wrapperSb`, AFTER `New-PSSession` (11273) and BEFORE running
   `$effectiveInner`: probe `$actualName = Invoke-Command -Session $sess { $env:COMPUTERNAME }`; if it
   returns non-empty and its short name != the dialed `$Computer` short name, set
   `$r.Detail='ABORTED: DNS mismatch -- dialed <x> but remote reports <y>. No action taken.'` and return the
   row (fail-closed, no Inner run). Mirror 6224/7213 exactly (name compare, no PTR on AFNET; if the probe
   itself throws/blank, proceed - same as the siblings). This runs BEFORE the Log4j stage push too.

## Approach
Opus implements against the exact anchors above (both mirror in-file patterns). I gate: confirm the self-drop
is before fan-out and empties -> abort, the DNS abort is before `$effectiveInner`, and neither weakens the
Log4j staging or the existing confirm. Version-bump + archive + config repoint + PS 5.1 parse-clean + BOM.
No Pester on Desktop - verify by parse + BOM + a read-only smoke test of Test-WptHostIsSelf on the selected
set. Web unchanged (already clean). Ledger row -> CLOSED-BOTH.
