# JANET Web — design loop 89 (2026-07-22)

## Decision 1 — fix the deferred P1 the loop-88 wpt deep-dive found (the sccm emit crash)
`sccm-available` (`:5065`) and `sccm-install-available` (`:5106`) build a row carrying an app `Type` key
(App/Update) and emit it with `& $send (@{ type='row' } + $row)`. On PS 5.1 a `@{}` literal is a case-INSENSITIVE
Hashtable, so `type` (the event key) collides with `Type` (the app key) → a duplicate-key `ArgumentException` on
the FIRST result row. Every Available/Install-Available query crashes; on the install path the crash lands AFTER
the destructive CCM trigger already ran, so the per-item `VulnPatched` audits are lost. Same class as the upr P0
(loop 85). This was the loop-88 top-priority backlog item.

## Decision 2 — reuse the proven upr pattern: a case-sensitive emit merge (NO JS change)
The row must reach the case-sensitive JS view carrying BOTH the event `type='row'` and the app `Type='App'`. A
case-insensitive Hashtable can't; a case-SENSITIVE `System.Collections.Hashtable` can, and `ConvertTo-Json` (the
server's emit serializer) renders both as distinct JSON keys. Added `New-WptRowEvent` (module scope — the sccm
dispatchers are in `Invoke-JanetToolAction`, a module function), a byte-for-byte mirror of upr's `New-UprRowEvent`
(loop 85), and swapped the two sccm emit sites to it. **No JS-view change** — the view already keys off `r.Type`
(`wpt.view.js:2447/2468`), which now arrives intact. This is the alternative to renaming the key + touching the
view; it's smaller, lower-risk, and reuses a pattern already proven in production.

## Decision 3 — scope: fix the two CONFIRMED-broken sites, document the class
wpt has 37 `@{ type='row' } + $row` emit sites, but only the two sccm rows carry a `Type` key (verified: the other
35 rows have no colliding key; software-scan already renamed its key to `'Install Type'` in an earlier loop). So
the fix is the two sccm sites; the helper's header comment states that ANY future Type-bearing wpt row must emit
via `New-WptRowEvent`. A blanket 37-site sweep would be large and risky for no current benefit.

## Decision 4 — the test EXECUTES the emit (the class-catching test)
The last several loops' bugs hid behind static/canonical-only tests. `Wpt.SccmRowEvent.Tests.ps1` (NEW) executes
the emit: it asserts the OLD `@{ type='row' } + $row` really throws on a Type-bearing row (guards the root cause),
that `New-WptRowEvent` does NOT throw and keeps both `type` + `Type`, and that the JSON serialization carries both
distinctly; plus static assertions that the two sccm sites use the helper and the helper uses a case-sensitive
Hashtable. (The full dispatchers need a live MECM host, so the row-emit unit is the testable seam.)

## Decision 5 — verify no collateral; the rest of the wpt backlog stays tracked
wpt 6.8.17 → 6.8.18; loop-88's 6.8.17 pin floored. Ran the wpt suite + the full suite. The other loop-88 wpt
findings — `cleanup-disk`/`clean-user-apps` missing wrong-box guard (P2), the freshness-only Oracle-Java verify
(likely also inert), the bool-coercion sweep, and the systemic dead `Get-Item.LastWriteTime` read — remain ranked
backlog for their own loops.
