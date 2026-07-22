# JANET Web — review loop 90 (2026-07-22)

**Theme: destructive-path hardening.** Fable-inline + a Fable self-review of loop 89. Baseline: loop-89
authoritative **1612**.

## Self-review of loop-89 (sccm row-emit crash fix) — **SHIP-WORTHY, proven at runtime**
The self-review EXECUTED the real dispatchers (30/30 checks) and even reproduced the pre-fix crash on the parent
commit. Confirmations: `New-WptRowEvent` keeps every key + adds `type='row'`; `ConvertTo-Json -Depth 24` emits BOTH
`"type":"row"` and `"Type":"App"` distinct. **Downstream INTACT** — `sccm-install-available` with 3 items produced
`row,audit,row,audit,row,audit` (the 3 per-item `VulnPatched` audits fire AFTER each row now-succeeds), reading
`$row.Type`/`$row.Name` correctly; summary `total=3 ok=1 failed=1`; `sccm-available`'s stored rows are the ORIGINAL
case-insensitive hashtables (the emit message is a throwaway). **Bonus:** on the parent commit the dispatcher
crashed with the destructive trigger already fired and **0** audits captured — the claimed severity, confirmed.
Exhaustive key-set check of all 36 other emitted wpt rows: **only the 2 sccm rows carry `Type`** (all others safe);
the JS view reads `r.Type` intact. VERDICT: ship-worthy. (One pre-existing note → backlog: a `Skipped` install item
audits as `Failure` while the summary counts it neither — a mild audit/summary asymmetry, present before loop 89.)

## Workstream: the wrong-box guard on the two profile-deleting blocks (wpt 6.8.18 → 6.8.19)
The loop-88 wpt deep-dive found two DESTRUCTIVE workers MISSING the wrong-box (DNS-mismatch) guard every sibling
carries:
- `WptCleanBlock` (cleanup-disk) — deletes temp files, caches, and stale user PROFILES (WMI `.Delete()` / CIM /
  takeown / rd / robocopy `/MIR` / the ProfileList SID key).
- `WptCleanUserAppsBlock` — deletes per-profile app binaries (takeown + remove).
A stale DNS / a reused IP → the operator dials WS01, the session lands on WS02, profiles/binaries are deleted on the
WRONG machine, irreversibly. The highest-consequence unguarded destructive path in wpt.

### Fix — the guard, verbatim from `WptPatchBlock`, first inside the try
Added the DNS-mismatch guard as the FIRST statement inside each block's existing `try { … } finally {
Remove-PSSession }` — before any deletion (in WptCleanBlock, before even the read-only free-space snapshot):
`Invoke-Command { $env:COMPUTERNAME }` vs the dialed shortname, HARD ABORT (`$r.Detail = "DNS mismatch … ABORTED,
nothing cleaned/removed"; return`) on mismatch. Invariants identical to the siblings — IPv4-literal target skips,
empty probe proceeds; the abort `return` runs the finally (session cleanup); the row renders a clean Failed with
nothing deleted.

### Tests
`Wpt.SelfGuardAndClean.Tests.ps1` +6: the guard DECISION via a verbatim replica (`Test-WptCleanWrongBoxAbort` —
mismatch aborts / matching-shortname-case-insensitive no-abort / IPv4-skip / empty-probe-proceeds) AND a STATIC
assertion that BOTH blocks contain the guard (the `$env:COMPUTERNAME` session probe + the `ABORTED, nothing
cleaned`/`nothing removed` returns). The blocks have a TCP pre-check + `New-PSSession` before the guard (unlike
`WptRebootBlock`, which is behaviorally executable), so the replica+static convention (loop 86 kb-install /
`PkginstallSecureboot.WrongBoxGuard`) is the right seam. loop-89's 6.8.18 pin floored. **loop-37 lesson:** ran the
wpt guard suite + the full suite.

## SECRET parity
- **SECRET parity:** mirror the `WptCleanBlock` + `WptCleanUserAppsBlock` wrong-box guards to the wpt SIPR fork (its
  clean blocks share the same destructive profile/binary-deletion shape and the same gap).

## Remaining wpt backlog (ranked)
- The **freshness-only Oracle-Java Software-Center verify** (`:1374`) — same false-clean class as Chrome/Edge, and
  likely ALSO inert (the loop-88 dead `Get-Item.LastWriteTime`); needs the real-timestamp + success-signal treatment.
- The **systemic dead-`Get-Item registry .LastWriteTime` sweep** — the C2R verifies (`acas:163`/`wpt:911`),
  reboot-pending age (`wpt:2343`).
- The **bool-coercion sweep** — `hardlock`/`rebootafter`/`noreboot` use raw `[bool]` (an API `"false"` applies the
  destructive toggle); `Get-WptThreadCount` degrades garbage → 1 thread.
- Minor (loop-89 self-review): the `Skipped`-item-audits-as-`Failure` asymmetry; the `New-UprRowEvent`/
  `New-WptRowEvent` PSCustomObject-row edge; the `Acas.ClientVerify` test-cleanup `finally`.
