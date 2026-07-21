# JANET Web — review loop 36 (2026-07-21)

**Baseline:** 1299/1299 at loop-35 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-35 (`5d8bee4` upr verify fail-close, `482cd3b` docs) — verdict GREEN (inline)
Additive: a `$null`/empty verify result now fails closed to "could NOT be verified"; the 4-branch
decision and every non-empty result are byte-identical (36 upr tests green). No guard weakened.
Authoritative 1299/0-fail. GREEN.

## Workstream (winupgrade deep-dive F2, item 27) → FIXED: reboot-when-staged no longer reboots a STALE-staged host
Closing a deferred HIGH-harm backlog item (two GREEN deep-dives signalled fresh reviews were hitting
diminishing returns). upgrade-drive's `rebootWhenStaged` reboots a host the drive re-read as "staged" (a
feature update pending, awaiting the reboot to complete). The `PHASE:STAGED` re-read set `Staged=true`
off a BARE `Test-Path 'C:\$WINDOWS.~BT\Sources'` (`JanetWeb.winupgrade.psm1:2278`, pre-fix) with NO
staleness classification — but a ROLLED-BACK 24H2 attempt leaves that tree behind while nothing is in
progress (the field batch `Get-WinUpgradeStagingClass` was built for), so an un-staged host read staged
and, with `rebootWhenStaged`, got REBOOTED and came back on 23H2 — weakening the manifest's "an un-staged
host is NEVER rebooted" invariant.

**Fix** (winupgrade **0.5.4 → 0.5.5**): the `PHASE:STAGED` re-read now CLASSIFIES the ~BT tree inline
(mirror of the pure `Get-WinUpgradeStagingClass` + the AutoFix `clearStaging` classifier: rollback
marker → Stale, running setup process → Active, >24h no-process → Stale, else Recent) and sets
`Staged=true` ONLY when the class is not `Stale`. A rolled-back/leftover ~BT no longer triggers a reboot.

Coverage rides three proven pieces: the classifier DECISION is a pure tested helper (Diagnose24h2); the
reboot GATE (`Staged=false` → no reboot) is proven by `WinUpgrade.Drive` INVARIANT #4; and the re-read
runs in a remote scriptblock (shimmed in the Drive harness), so `WinUpgrade.StagingReboot.Tests.ps1` (8)
pins the classifier's REBOOT contract (rollback→Stale, setup-proc→Active, old→Stale, recent→Recent,
Active/Recent≠Stale) + a static assertion the `PHASE:STAGED` re-read carries the classification (rollback
marker + `Stale`) rather than a bare Test-Path + the exact 0.5.5 pin (FixVerify2 0.5.4 exact → floor).
Full winupgrade + FixVerify2/3 set green — the reboot gate is intact.

## Scope note (a sibling left ranked)
This closes the CONFIRMED harm (a stale ~BT triggers a reboot). The generic pending-reboot markers
(CBS RebootPending / WU RebootRequired / PFRO) checked BEFORE the ~BT still set `Staged=true` for a
non-feature-update pending reboot (a CU-pending host could read staged) — the F2 "sibling" the deep-dive
noted. Deciding whether a pending reboot is feature-update-specific vs a generic CU is nuanced; left as a
follow-on to item 27.

## winupgrade false-clean status
Fixed: F1 (pin-fail abort, loop 31), F6 (Diagnose disk gate, loop 32), F3+F4 (bypass read-back, loop 33),
F2-core (stale-staging reboot, this loop). Remaining: 27b (generic-pending-reboot staged, above), 29 (F5,
AutoFix premature FIXED — HIGH, multi-site remote), 31 (F7, sfc unparseable→clean — LOW, a one-line fix
in the pure `Get-WinUpgradeRepairVerdict`).

## SECRET parity
- SECRET parity: the reboot-when-staged staleness classification — the JanetSec winupgrade fork shares
  the PHASE:STAGED re-read; mirror the inline classifier.
- Carried (unexecuted): the winupgrade/upr/c2c/acas/wpt series; CSPRNG credential mint; SLA bucket;
  host-key fold; wrong-template hint; CSV-ingestion + routing.
