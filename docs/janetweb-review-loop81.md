# JANET Web — review loop 81 (2026-07-21)

**Theme: informative failures** (loop 70) — follow-up phase. Fable-inline + a Fable adversarial subagent on
loop-80. Baseline: loop-80 authoritative **1549**.

## Self-review of loop-80 (engine fixes + secureboot scan wire) — **clean, 1 plausible over-correction fixed**
A Fable subagent executed the loop-80 functions on PS 5.1 and ran the three touched suites (61 green). Verdict:
**no confirmed new defects** from the four loop-80 fixes — the `\b` boundaries hold on every real form
(`(1314)`, `1314.`, `:1314`, `[1727]`, `1722,`), the `-Code -ne -1` guard is sound (all three −1 sites overwrite
the detail with the synthetic timeout string, so a −1 carrying a real remote error is structurally impossible;
−3/−4 still delegate), and the secureboot scan wire is in-scope, correctly CHECK-ERROR-scoped, and additive
(the view renders a fixed column list, so the extra `Hint` key breaks nothing).

**One plausible over-correction — FIXED:** the loop-80 narrowing `computer\b.{0,40}could\s+not\s+be\s+found`
window was too tight — a quoted long AFNET FQDN falls off the cliff:
`The computer 'AREA52-1234ABC5.area52.afnoapps.usaf.mil' could not be found` (44-char gap) returned '' (no hint).
`.area52.afnoapps.usaf.mil` alone is 26 chars, so realistic names hit it. **Fix:** widened to `.{0,80}?`
(non-greedy, keeps the match tight). Verified: the long FQDN and the short `'WS01'` both route to
name-resolution; `module could not be found` / `user name could not be found` stay correctly excluded (no
"computer"). `Troubleshoot.Hint.Tests.ps1` +1. (Cosmetic notes logged, NOT acted on: the row `Hint` field is
surfaced only via the `FIX:` activity-log line, not a grid column — but that is the established convention across
all wired tools since loop 70; and `0x80070522` has no right boundary, but a 12-digit hex with that exact prefix
is contrived.)

## Workstream: wire the hint into certdeploy's TWO read-only paths (check + scan-cert-management)
Both read-only fan-outs surface a host-level **CHECK ERROR** row carrying the raw probe/session/DNS error in
`$row.Detail`. Same tool, same pattern → one cohesive workstream (as loop 75 did all 5 dhcp call sites).

### Fix (certdeploy 1.4.3 → 1.4.4) — purely additive
- **check** harvest (`Invoke-CertDeployCheckAction` `$emitResult`, `:1028`): on `$status -eq 'CHECK ERROR'`, run
  `$row.Detail` through `Get-JanetTroubleshootHint -Server $row.Host` → `$row['Hint']` + a `FIX:` err log.
- **scan** harvest (`Invoke-CertDeployScanAction` `$emitResult`, `:1592`): the reconciler cell is `$row.Reconciler`;
  on `$rec -eq 'CHECK ERROR'`, same wire.
Row comes from the pure builders (`Get-CertDeployCheckRow` / `Get-CertDeployScanRow`), so the `Hint` key is
mutated conditionally (acas loop-71 pattern), not set in a literal. ALL PRESENT / MISSING / OFFLINE (check),
reconciler verdicts / OFFLINE (scan) compute no hint. certdeploy already imports the engine (loop 78).

### Tests
`CertDeploy.Tests.ps1` +4 (static analysis — both harvests run inside a fan-out over a real RunspacePool): exact
`1.4.4` pin; the check predicate (`$status -eq 'CHECK ERROR'`) and scan predicate (`$rec -eq 'CHECK ERROR'`) each
compute the hint; the `$row['Hint']` mutation appears exactly twice (unique to the read-only paths — deploy uses a
row literal) and the row-based `FIX:` err log appears exactly twice. loop-78's 1.4.3 pin floored.
**loop-78 glob lesson caught:** the per-tool glob `CertDeploy.*.Tests.ps1` silently EXCLUDES `CertDeploy.Tests.ps1`
itself (the `.*.` needs a middle segment) — the correct glob is `CertDeploy*.Tests.ps1` (5 files, 97). Ran the
correct set (97) + engine-consumers (234) green.

## Rollout status (informative-failures theme)
Primary 9-tool wire COMPLETE (70-78); restart folded/delegated (79); first read-only scan (secureboot, 80);
**certdeploy's two read-only paths (81)**. Remaining follow-ups: c2c scan/version harvests, per-candidate upr
failures, grow the signature set.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the loop-81 name-resolution window widening (`.{0,80}?`) in the
  troubleshoot engine, (b) the certdeploy-fork check + scan-cert-management CHECK ERROR hint wires. (Whole-engine
  mirror still pending, tracked since loop 70.)
