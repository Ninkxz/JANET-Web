# JANET Web — review loop 82 (2026-07-21)

**Theme: informative failures** (loop 70) — follow-up phase. Fable-inline + a Fable adversarial subagent on
loop-81. Baseline: loop-81 authoritative **1554**.

## Self-review of loop-81 (engine window widen + certdeploy read-only wires) — **1 confirmed minor mislabel, fixed**
A Fable subagent executed the loop-81 functions on PS 5.1. Verdict: the certdeploy wire is **SAFE** on every real
CHECK ERROR shape (traced both worker blocks — every failure exit sets CHECK ERROR with an informative Detail;
`Get-CertDeploy{Check,Scan}Row` return literal hashtables so `$row['Hint']` mutation is safe; the view uses
explicit column defs so the extra key is inert), the widened regex is **not** a ReDoS risk (bounded lazy
quantifier — 165 ms on 500 KB, no pathological input found), and greedy-vs-lazy is a **no-op for correctness**
(2,000-iteration fuzz, 0 match/no-match differences).

**One confirmed minor issue — FIXED:** the loop-81 widen (`computer\b.{0,80}?could not be found`) newly routes
long-gap **AD-object errors** to the DNS hint — e.g. `The computer account for 'WS01$' in domain 'AREA' could
not be found in Active Directory.` and the Failover-Cluster `The computer object … could not be found in Active
Directory.` A deleted/missing AD computer account is **not** a name-resolution failure (the host may be perfectly
reachable), so "check DNS / is it powered on" misleads. It's rare in these tools' real WinRM-exception inputs,
but a wrong hint in a shared 10-tool engine. **Fix:** two negative lookaheads on the `computer…could not be
found` alternative — `computer\b(?!\s+(?:account|object)\b).{0,80}?could\s+not\s+be\s+found(?!\s+in\s+Active\s+Directory)`
— excluding "computer account/object …" and the "… in Active Directory" suffix. Verified: all four AD-object
forms now return '' while the genuine short-name and long-FQDN host-not-found still route to name-resolution;
"module/user name could not be found" and "server name could not be resolved" unchanged. `Troubleshoot.Hint` +1.
(Cosmetic notes NOT acted on: the row `Hint` field is surfaced only via the `FIX:` log line — the established
convention since loop 70; the `0x80070522` right-boundary nit — a 12-digit hex prefix is contrived.)

## Workstream: wire the hint into c2c's TWO remaining read-only harvests (scan + version-check)
c2c's Mass-Fix was wired loop 77; this completes c2c with its two read-only fan-outs.

### Fix (c2c 1.15.9 → 1.15.10) — purely additive
- **scan** (`Invoke-C2cScanAction` `$emitResult`, `:3519`): the harvest normalizes a raw `ERROR` / `DNS MISMATCH`
  host to `CHECK ERRORS` (raw reason kept in Detail); on `$row.Status -eq 'CHECK ERRORS'` the Detail runs through
  the engine → `$row['Hint']` + a `FIX:` err log after the multi-line report.
- **version-check** (`Invoke-C2cVersionCheckAction` `$emitResult`, `:3385`): scoped to **error-level `$lvl`**
  (hoisted above the row emit). This is the one harvest where feeding the raw Detail unconditionally would be
  unsafe — a healthy row's Detail can carry a version string, and `1722.0` / `1727.x` / `1314.y` would false-match
  the RPC/privilege numeric signatures. Gating on `$lvl -eq 'error'` (OFFLINE + unknown) means only rows whose
  Detail is a WinRM error are ever fed to the engine; within that subset the engine self-gates.
Both mutate `$row['Hint']` conditionally (acas loop-71 pattern; the rows are literals finalized after the status
normalization). c2c already imports the engine (loop 77).

### Tests
`C2c.AuditResult.Tests.ps1` +4 (static analysis — both harvests run inside a fan-out over a real RunspacePool):
exact `1.15.10` pin; the scan predicate (`$row.Status -eq 'CHECK ERRORS'`) and version predicate (`$lvl -eq
'error'`); the `$row['Hint']` mutation appears exactly twice (unique to the read-only paths — Mass-Fix uses a row
literal) and the row-based `FIX:` err log appears exactly twice. loop-77's 1.15.9 pin floored. **loop-37 lesson:**
c2c is slow — ran the full c2c suite (288) + engine-consumers (239) green.

## Rollout status (informative-failures theme)
Primary 9-tool wire COMPLETE (70-78); restart folded/delegated (79); secureboot scan (80); certdeploy read-only
(81); **c2c scan + version-check (82) — c2c now fully wired across all three fan-outs.** Remaining follow-ups:
per-candidate upr failures (the deferred loop-74 item), grow the signature set.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the loop-82 AD-object exclusion lookaheads in the troubleshoot
  engine, (b) the c2c-fork scan + version-check CHECK ERROR hint wires. (Whole-engine mirror still pending, tracked
  since loop 70.)
