# JANET Web — review loop 89 (2026-07-22)

**Theme: the recurring `type`/`Type` emit crash, this time in wpt.** Fable-inline + a Fable self-review of loop 88.
Baseline: loop-88 authoritative **1604**.

## Self-review of loop-88 (Chrome/Edge real-timestamp verify) — **SHIP-WORTHY, proven at runtime**
The self-review EXECUTED both generated probes against a sandbox HKCU key AND live-fired against this box's REAL
`EdgeUpdate\Clients\{GUID}` — both returned `Verified=True, Version=150.0.4078.83, LastUpdated=2026-07-22 07:57`, a
real verdict with a real date where four loops of prior code always produced `n/a`. The field-authentic
`ClientState\{GUID}` carries `LastCheckSuccess`/`LastInstallerResult` with exactly the names/types the code reads.
Verdicts confirmed: timezone/age math is correct on a UTC+1 box (`((Get-Date)-$mod).TotalHours = 1.000` for
now−1h; boundary at 13d→True, 20d→False), `[double]` epoch round-trips exactly, the empty-string guard blocks `''`
(loop-87 #2 fixed), the UInt32 DWORD range case reads `False` (loop-87 #3 fixed), and **acas ≡ wpt on all 15
executed cases**. Zero false-cleans found. **Two NON-blocking findings → backlog:** (1) the new executing test
(`Acas.ClientVerify.Tests.ps1`) leaks its `HKCU` sandbox key only if the LAST It's asserts fail — self-healing
(`Set-Sandbox` deletes at the top of every It), path unique, HKCU on the runner; a cleanup-in-`finally`/at-Describe
-top would harden it. (2) a hex-string `'0x10'` `LastInstallerResult` reads `False` from the inline probes vs
`$null` from the canonical (`[int64]` PS-hex vs `TryParse`) — both fail-safe, no real Omaha value is a hex string,
cosmetic lockstep only. (Out of scope, noted: the Office C2R verifies at `acas:163`/`wpt:911` carry the SAME dead
`$key.LastWriteTime` pattern — a future loop, already in the backlog sweep.)

## Workstream: the sccm row-emit crash (the loop-88 top-priority P1) — wpt 6.8.17 → 6.8.18
`sccm-available` (`:5065`) and `sccm-install-available` (`:5106`) build a row carrying an app `Type` key
(App/Update) and emitted it with `& $send (@{ type='row' } + $row)`. On PS 5.1 a `@{}` literal is a
case-INSENSITIVE Hashtable, so the event key `type` collides with the app `Type` → a duplicate-key
`ArgumentException` on the FIRST result row. Every Available/Install-Available query crashed; on the install path
the crash landed AFTER the destructive CCM trigger already ran, losing the per-item `VulnPatched` audits. Same
class as the upr P0 (loop 85).

### Fix — a case-sensitive emit merge (NO JS change), mirroring upr's `New-UprRowEvent`
Added `New-WptRowEvent` (module scope), a byte-for-byte mirror of upr's `New-UprRowEvent`: a case-SENSITIVE
`System.Collections.Hashtable` holds both `type='row'` and `Type='App'`, and `ConvertTo-Json` (the server emit
serializer) renders them as the distinct JSON keys the case-sensitive JS view already keys off (`r.Type`,
`wpt.view.js:2447/2468`) — so no view change. Swapped the two sccm emit sites to it. Verified end-to-end: the OLD
merge throws on a Type-bearing row; `New-WptRowEvent` emits both keys, JSON `{"type":"row","Type":"App"}`.

### Scope
wpt has 37 `@{ type='row' } + $row` emits, but only the two sccm rows carry a `Type` key (the other 35 are safe;
software-scan already renamed its key to `'Install Type'`). Fixed the two confirmed sites; the helper's header
mandates any future Type-bearing wpt row use it. A blanket 37-site sweep is unwarranted.

### Tests
`Wpt.SccmRowEvent.Tests.ps1` (NEW, +8): EXECUTES the emit — the old merge throws (root cause), `New-WptRowEvent`
keeps both keys + JSON distinct, null-row handled, case-sensitive Hashtable; static that both sccm sites use the
helper + exact 6.8.18 pin. loop-88's 6.8.17 pin floored. **loop-37 lesson:** ran wpt + the full suite.

## SECRET parity
- **SECRET parity:** mirror `New-WptRowEvent` + the two sccm emit-site swaps to the wpt SIPR fork (its sccm
  dispatchers share the same Type-bearing row shape and the same crash).

## Remaining wpt backlog (ranked, from loop 88)
- **P2** — `cleanup-disk` / live `clean-user-apps` (profile-DELETING) missing the wrong-box DNS-mismatch guard
  (`:3017`/`:3593`).
- **P2/P3** — Oracle-Java Software-Center verify freshness-only (`:1374`) — likely ALSO inert (dead
  `Get-Item.LastWriteTime`), needs the loop-88 real-timestamp treatment + a success signal.
- **The systemic dead `Get-Item registry .LastWriteTime` sweep** — the C2R verifies (`acas:163`/`wpt:911`),
  reboot-pending age (`wpt:2343`), and other registry-mtime spots.
- **P3** — bool-coercion sweep (hardlock/rebootafter/noreboot raw `[bool]`); `Get-WptThreadCount` garbage→1 thread.
- loop-88 self-review: the `Acas.ClientVerify` test-cleanup `finally` hardening; the hex-string canonical/inline
  lockstep.
