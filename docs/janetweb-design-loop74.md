# JANET Web — design loop 74 (2026-07-21)

## Decision 1 — the other destructive remote tool, its multi-row harvest
upr is the second destructive remote tool (after pkginstall) and the natural next wire. Its harvest differs from the
others: the per-host `$EmitRows` callback returns *several* rows for one host (one per candidate EOL product), plus an
honest `ok`/`auditResult`. The hint is per-host (a connection failure applies to the whole host), so it attaches to
every row that host produced.

## Decision 2 — hint the host-level error, not (yet) per-candidate
upr distinguishes two failure kinds: a host-level failure (unreachable, worker error) carried in `$res.Error`, and a
per-candidate uninstall failure carried inside the candidate's own result. This loop hints the host-level error —
that's where the cryptic WinRM/auth/DNS strings live, exactly what the mapper is for. A per-candidate uninstall FAIL
(e.g. an msiexec exit code) is a different, tool-specific class and is left for a later enrichment; scoping to
`$res.Error` keeps the wire clean and the change additive.

## Decision 3 — hoist $ok so the hint rides with the rows
The harvest computed `$ok` *after* emitting the rows. To carry the hint on the rows, `$ok` must be known before the
row loop, so I hoisted its assignment up two lines (a pure move — same value, no behavior change) and compute the hint
from it. Each row in the host's `$emit.rows` gets the `Hint` field, guarded by a hashtable check.

## Decision 4 — upgrade the worker-error surfacing from warn to a proper err+fix
upr already logged a *warn* for a raw worker error but nothing for other host failures, and never a fix. The new err
log (`$host : $err | FIX: $hint`) is gated on a recognized hint, so it fires exactly when there's actionable guidance —
turning a bare warn into an error line that says what to do. The raw error stays in the row/log; the audit is
untouched.

## Decision 5 — static analysis, matching upr's convention; run the whole suite
upr's harvest runs inside a fan-out over a real RunspacePool with no swappable-worker seam, and upr's other harvest
tests are static, so the wire is pinned by static analysis (the hint's behavior is proven behaviorally elsewhere).
Because the harvest is shared by upr's scan and uninstall actions, I ran the full upr suite (44) — the change is
additive and touches neither the verify decision nor the classify, so nothing regressed. upr 1.2.4 → 1.2.5; the new
Describe holds the exact pin, the loop-64 Describe floors. Next tool: dhcp.
