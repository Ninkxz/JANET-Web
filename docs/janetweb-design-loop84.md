# JANET Web — design loop 84 (2026-07-22)

## Decision 1 — the loop this loop: remediate loop-83's regressions (the self-review is the workstream)
Loop 83 was a large shared-engine change; the self-review found a CRITICAL crash + three degradations that the
274-green run missed (the upr coverage was static-only). Fixing shipped regressions outranks a new feature, so this
loop is loop-83 remediation. The parallel acas deep-dive's F2 (a real but delicate bump-verdict bug) is DEFERRED to
its own loop rather than crowding this one; its F1 was refuted (verified `[int]''` → 0 on PS 5.1, not a throw).

## Decision 2 — P1: compute the per-candidate hint where the engine is resolvable (module scope), not the closure
`New-UprEmitRows` returns a `.GetNewClosure()`'d block; that block resolves commands against GLOBAL scope, where
the nested-imported `Get-JanetTroubleshootHint` does not exist — so my loop-83 call there threw and aborted the run.
The host-level hint (loop 74) never hit this because it's computed in `Invoke-UprFanOut` (a plain module function).
So the fix moves the per-candidate hint to that same harvest: after the emit block returns rows, on a REACHED host
(no host-level `$hint`), each row with a Failure `Result` is hinted there. The closure just builds the row (with
`Result`); the harvest does the engine call. Minimal, and it reuses the exact scope the host-level hint proved safe.

## Decision 3 — P1's test must EXECUTE the closure (static analysis is what missed it)
The loop-83 upr test regexed the source and passed while the feature was 100% broken. The regression guard is a
BEHAVIORAL test: build the `New-UprEmitRows` closure and invoke it with a Failure candidate, asserting no throw —
this fails on the loop-83 code and passes on the fix. Plus a static check the closure body has no engine call, and
that the harvest carries the wire. (Lesson: a source-regex test cannot catch a runtime scope failure.)

## Decision 4 — P2 boundary: `(?![\d.])` was too greedy on the RIGHT; `(?!\.?\d)` is the fix
The dotted-version guard must reject `16.0.1603` (version) but ACCEPT `1603.` (sentence period). `(?![\d.])`
rejected both. `(?!\.?\d)` rejects only a dot-followed-by-a-digit (or a glued digit) — a version — while a trailing
period followed by space/end passes. On the LEFT, `(?<![\dxX.])` additionally rejects an `x`-prefixed hex
(`0x1727`, decimal 5927 — a DIFFERENT error) that loop-83's `(?<![\d.])` wrongly admitted (the old `\b1727\b`
didn't). Applied to all six codes.

## Decision 5 — P2 c2c + P3 AD: match the WORKER's real behavior, not the assumed one
- **c2c version-check** hint scope: the worker maps session/auth failures to OFFLINE and only query failures to
  ERROR, so `$wasError` (pre-collapse ERROR) dropped the session/auth hints. The correct predicate is "error-level
  AND not the self-explanatory `No TCP on...` detail" — which hints session/worker/query errors and excludes only
  genuine offline (the loop-83 intent), matching how the worker actually labels failures.
- **AD signature**: real AD errors say "could not be **resolved**" as often as "found"; adding that verb to both AD
  alternatives closes the leak loop-83 claimed (but didn't) to have closed, while a generic "server name could not
  be resolved" (no "in Active Directory") still routes to DNS.

c2c 1.15.11 → 1.15.12, upr 1.2.6 → 1.2.7 (troubleshoot is a shared helper, unversioned). **loop-37 lesson:** ran
engine + all consumers + upr + the full suite. **F2 (acas Java-remove false-Failure) is tracked as a ranked backlog
item for a dedicated loop.**
