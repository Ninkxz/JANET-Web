# JANET Web — review loop 45 (2026-07-21)

Fable-inline. Self-review of loop-44 → **GREEN**. Baseline: loop-44 authoritative **1367** green (confirmed).

## Self-review of loop-44 (c2c AntiMalware unavailable fail-close) — GREEN
The unavailable-branch now books NOT VERIFIED (not FIXED); the SKIP case (no service change) is unchanged; the
host rollup (`:2360`) + audit switch (`:3090`) map NOT VERIFIED to a not-FIXED host status + a non-Success
audit. 109 c2c + 1367 confirm no regression. Nothing to reopen.

## Workstream: close c2c item52 (F5) — Monitoring FIXED requires the Tanium software installed, not just the service
The same partial-signal class as loop-44's F1, and the natural follow-on from the c2c dive.

### Finding (CONFIRMED — re-verified in-code)
The Monitoring fixer's service-exists branch (`:1447-1451`) booked `FIXED` (`:1448`) or `NOCHANGE` (`:1450`) off
`$runNow` (the client service Running) plus a change, **without checking `$ti.Installed`** (the Tanium software
in the uninstall registry). But the scan's Monitoring PASS (`:751`) requires installed **AND** running. So a
Running-but-not-installed box — an orphaned service, or a host whose uninstall registry couldn't be read
(`Get-C2cInstalledProduct` reads are `SilentlyContinue`) — read MONITORED, host rollup FIXED, and a VulnPatched
Success audit, with the Detail literally saying "Tanium not installed", while the scan would still quarantine
it. `FIXED` that doesn't make the box pass the scan is a false-clean.

### Fix (c2c 1.15.5 → 1.15.6)
New pure `Get-C2cMonitoringVerdict(Installed, RunNow, ChangedCount)`: not-running → FAIL; running-but-not-
installed → **NOT VERIFIED**; installed+running+change → FIXED; installed+running → NOCHANGE. The module-less
fix worker mirrors it inline (the new `-not $ti.Installed → NOT VERIFIED` branch), comment-linked. NOT VERIFIED
rolls up to a not-FIXED host status and a non-Success audit — the fix now aligns with the scan's PASS criteria,
so a MONITORED verdict genuinely means the box will pass. Reuses the existing NOT VERIFIED machinery (loop-44).

### Version + tests
- `C2c.MonitoringVerdict.Tests.ps1` (NEW, 6): the pure verdict at every branch (the false-clean fix is
  running-but-not-installed → NOT VERIFIED, both with and without a heal) + a static assert the worker inline
  carries the installed gate; exact pin 1.15.6 (loop-44 AntiMalware exact pin → floor).
- c2c Monitoring/AntiMalware/import/run-all set **85** green — the ImportAndFix + RunAll fixtures that drive the
  Monitoring fixer pass unchanged; grepped all tests for the touched symbols, only the two files I edited.
- Chose the pure-helper + inline-mirror pattern (clean unit tests, no `Get-Command`/registry shimming) after
  loop-44's behavioral harness leaked — the verdict is a clean 4-branch predicate, ideal for it.

## Remaining c2c backlog
item53 (F3, scan sig-age `[int]$null→0` coercion → READY), item54/55 (F4/F7 low), item56 (F8 version ordinal,
read-only), item57 (F9 Firewall empty, speculative); F2/F6 refine the known items 22/24 tally/rollup cluster.

## SECRET parity
- **SECRET parity:** the JanetSec c2c fork shares the Monitoring fixer — mirror `Get-C2cMonitoringVerdict` and
  the inline `-not $ti.Installed → NOT VERIFIED` gate.
