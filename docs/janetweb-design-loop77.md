# JANET Web — design loop 77 (2026-07-21)

## Decision 1 — the Mass-Fix harvest, where the raw error already lives
c2c is large with several fan-outs (scan, version-check, Mass-Fix). The Mass-Fix / run-all harvest is the destructive
one and the one whose per-host `$res.Detail` carries the raw WinRM/session/probe error (`"Session: <exception>"`,
`"Probe: <exception>"`, the wrong-box probe failure). So that's where the hint belongs first; the read-only scan/
version fan-outs have their own emission shapes and are noted as follow-ups.

## Decision 2 — reuse the existing audit classifier for the failure predicate
c2c already has `Get-C2cHostAuditResult`, which maps a host's run status to `Success`/`Skipped`/`Failure` (a PARTIAL
host with any failing pillar is `Failure`, per loop 47). So the hint's failure predicate is simply
`$auditResult -eq 'Failure'` — no new notion of "did this host fail", and it's exactly the set of hosts the audit
already books as failures. A `FIXED`/`NOCHANGE` host, whose `.Detail` is a report rather than an error, gets no hint.

## Decision 3 — hoist the classifier so the hint rides with the row
The harvest computed `$auditResult` just before emitting the audit, but after the row. To carry the hint on the row I
hoisted that computation to the top of `$emitResult` (a pure move — same value) and reuse it for both the hint and the
audit. This also avoids computing it twice.

## Decision 4 — additive; the report log is separate
The per-pillar tally, the audit (result/itemCount/detail), and the multi-line report log are all unchanged; the hint
is computed from the classifier and only read, the row gains a `Hint` field, and a single err `FIX:` line is emitted
for a recognized failure. A success/skip host is byte-identical.

## Decision 5 — static analysis, matching c2c's convention; run the whole suite
The Mass-Fix harvest runs inside the fan-out over a real RunspacePool with no swappable-worker seam, and c2c's tests
are static/pure, so the wire is pinned by static analysis (the hint's behavior is proven behaviorally elsewhere):
imports the engine, the `Failure` predicate computes the hint, the row carries `Hint`, the err log appends `FIX:`.
Because the harvest is shared by the Mass-Fix and run-all actions, I ran the full c2c suite (it's slow) to confirm the
change regressed nothing, plus the AuditResult file directly (14) which exercises the same classifier. c2c 1.15.8 →
1.15.9; the new Describe holds the exact pin, the loop-47 Describe floors. Next tool: certdeploy.
