# JANET Web — design loop 70 (2026-07-21)

## Decision 1 — one shared engine, not per-tool copies
The two existing mappers (restart, dhcp) prove the value but also the anti-pattern: each tool reinventing its own
error→hint logic means inconsistent, partial coverage. The codebase already has the sibling-helper-module idiom
(`JanetWeb.javafix.psm1`, imported by wpt/acas/c2c), so the engine goes in `JanetWeb.troubleshoot.psm1` and every tool
imports it. One place to maintain the signature set; one consistent hint for the same error across all tools.

## Decision 2 — generalize the gold-standard, keep it pure
restart's `Get-RrsShutdownErrorHint` is the richest existing mapper; its *text* signatures (WinRM/auth/DNS/RPC) are
universal, its *numeric* shutdown codes are restart-specific. I lifted the universal text signatures into a pure
`Get-JanetTroubleshootHint` and rounded them out (SMB/C$, timeout, disk, file-lock, no-credential). Pure means unit-
testable with no host contact, and callable from any tool's local failure-emission path.

## Decision 3 — most-specific-first, and never guess
The matcher is an ordered if-cascade: narrow, high-signal signatures (specific HRESULTs, "…cannot be resolved") come
before broad ones, so a DNS failure wrapped in a generic WinRM error is diagnosed as DNS, not as a generic WinRM
config problem (this exact ordering bug surfaced in test and was fixed by moving name-resolution above the generic
WinRM-client signature). An unrecognized error returns `''` — the caller then shows only the raw error. A confidently-
wrong hint would send an operator down the wrong path, worse than no hint.

## Decision 4 — augment, never replace, and put it where the operator looks
The hint is appended to three surfaces, with the raw error always kept: the row (`Hint` field, for the view to render
later), the persisted audit detail (`| TROUBLESHOOT:`, so a post-hoc CSV review has it), and the err log (`| FIX:`,
the activity drawer the operator watches live). The hint is computed only for a non-success host with an error, so
success and clean-skip rows are untouched.

## Decision 5 — wire where the error is already local; test behaviorally
The tools' remote work runs in module-less runspace scriptblocks that can't call an imported function — but the raw
error flows *back* to the tool's module-scope harvest (`$emitResult` etc.), which is exactly where restart/dhcp
already apply their hints and where the imported helper IS callable. remoteadmin was first because its `$emitResult`
is a clean central point and I already had the loop-56 worker-swap harness to drive a synthetic failed host through
it behaviorally. remoteadmin 1.0.2 → 1.0.3. The rollout to the other tools is per-loop, highest-traffic first.
