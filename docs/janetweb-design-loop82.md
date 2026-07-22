# JANET Web — design loop 82 (2026-07-21)

## Decision 1 — complete c2c's coverage (its two remaining read-only fan-outs)
c2c has three fan-outs: Mass-Fix (wired loop 77), the read-only readiness **scan**, and the read-only
**version-check**. Loop 81 completed certdeploy's read-only paths; this loop completes c2c's, wiring both
read-only harvests in one cohesive workstream (same tool, same CHECK ERROR concept).

## Decision 2 — scan: key on the normalized CHECK ERRORS status
The scan `$emitResult` (`:3519`) already normalizes a raw `ERROR` / `DNS MISMATCH` host to `CHECK ERRORS`
(matching the SECRET engine), keeping the raw reason in `$row.Detail`. So the predicate is
`$row.Status -eq 'CHECK ERRORS'` — computed AFTER the normalization line, before the row emit. A DNS-mismatch
detail ("dialed X but remote is Y") self-explains and the engine returns '' for it; only the WinRM/session
`"worker error: <exc>"` / `"Session: <exc>"` details get a hint. READY / QUARANTINE RISK / OFFLINE get none.

## Decision 3 — version-check: scope to error-level `$lvl`, NOT the raw Detail, to dodge a version-number false match
version-check is the ONE harvest where running the Detail through the engine unconditionally would be unsafe:
a healthy row's Detail can contain a version string, and a version like `1722.0` / `1727.x` / `1314.y` would
false-match the RPC/privilege numeric signatures. So the hint is scoped to error-level statuses only. The
harvest already collapses a raw `ERROR` to `OFFLINE` and computes `$lvl` (`ok`/`info`/`warn` for the healthy
statuses, `error` for OFFLINE + anything unknown). I hoisted `$lvl` above the row emit (a pure move) and gate
the hint on `$lvl -eq 'error'` — so only OFFLINE/unknown rows (whose Detail is a WinRM error, never a version)
are ever fed to the engine. Within that subset the engine self-gates (a genuine "No TCP" offline detail
returns '').

## Decision 4 — additive; conditional row mutation (the acas/loop-81 pattern)
Both rows are hashtable literals built before the status is finalized, so I mutate `$row['Hint'] =
[string]$hint` only when a hint exists (not a row literal like the Mass-Fix wire). The raw Detail, the multi-
line scan report, the version tally, and the per-host log are all unchanged; a single row-based `FIX:` err log
rides after each. Every non-failure row is byte-identical. c2c already imports the engine (loop 77).

## Decision 5 — static analysis, matching c2c's convention; run the whole (slow) suite
Both harvests run inside a fan-out over a real RunspacePool with no swappable-worker seam, and c2c's tests are
static, so the wire is pinned by static analysis (behavior proven in `Troubleshoot.Hint.Tests.ps1`): the scan
predicate keys on `$row.Status -eq 'CHECK ERRORS'`, the version predicate on `$lvl -eq 'error'`, the
`$row['Hint']` mutation appears exactly twice (unique to the read-only paths — Mass-Fix uses a row literal),
and the row-based `FIX:` err log appears exactly twice. c2c 1.15.9 → 1.15.10; the new Describe holds the exact
pin, loop-77's 1.15.9 pin floored. **loop-37 lesson:** ran the full (slow) c2c suite in the background. Next:
per-candidate upr failures, grow the signature set.
