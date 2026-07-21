# JANET Web — review loop 71 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-70 → **GREEN**. Baseline: loop-70 ~**1496**.

## Self-review of loop-70 (troubleshoot engine + remoteadmin wire) — GREEN
`Get-JanetTroubleshootHint` is pure, most-specific-first, `''` on unknown (9 tests); the remoteadmin `$emitResult`
wire computes the hint only for a non-success host and adds it alongside the raw error (row Hint + audit TROUBLESHOOT
+ log FIX). Nothing to reopen.

## Workstream: wire the hint into acas (highest-traffic; one wire covers all its actions)
`Invoke-AcasFanOut` (`:2482`) is the **generic fan-out behind every acas remote action** — install-KB, reboot,
Chrome/Edge/Java/Office fixes, spec-exec, etc. all route through it. Wiring the hint there covers them all at once.
Its harvest (`:2537-2568`) already had the raw worker result (`$resStr`, which carries the `"FAIL: <exception>"` or
`"FAIL: worker error: <msg>"`) and a three-way classify (`$isSkip`/`$ok`/fail), and it emitted a row + audit but
**no per-host log**.

### Fix (acas 1.11.12 → 1.11.13) — purely additive
On a genuine failure (`-not $ok -and -not $isSkip`), the harvest now runs `$resStr` through
`Get-JanetTroubleshootHint -Server $pj.Host` and: (1) attaches it to the row as a `Hint` field (guarded
`$row -is [hashtable]`); (2) emits an err log `"$host : $resStr | FIX: $hint"` — new, since the fan-out logged nothing
per host, so a recognized failure now shows a visible activity-drawer line. The raw result is preserved everywhere; the
160-char audit `detail` is left as-is (the hint exceeds that cap, so it goes to the untruncated row+log instead).
Success/skip rows are untouched. acas imports `JanetWeb.troubleshoot` (like it imports javafix/specfix).

### Tests
+3 (`Acas.FanOutHint.Tests.ps1`, behavioral — drives the REAL `Invoke-AcasFanOut` with a synthetic failing/succeeding
`$Work` scriptblock in a runspace): a `0x80090351` failure → row `Hint` (realm/TrustedHosts/CAC) + an err `FIX:` log +
raw `0x80090351` preserved + audit still `Failure`; a success → no hint, no extra err log; exact `1.11.13` pin.
`Acas.C2rVerify` pin floored. **loop-37 lesson:** the fan-out is shared by every acas action, so I ran **all 186 acas
tests** = green (the change is additive, no action regressed).

## Rollout status (informative-failures theme)
Wired: remoteadmin (loop 70), acas (loop 71 — all fan-out actions). Next: **wpt** (the other most-used; its fan-out
harvest is more bespoke — one wire per action-family), then pkginstall, upr, dhcp, secureboot, c2c, certdeploy.

## SECRET parity
- **SECRET parity:** the JanetSec acas fork shares `Invoke-AcasFanOut` — mirror the hint wire (import
  `JanetWeb.troubleshoot`, attach the `Hint` row field + `FIX:` err log on a failure).
