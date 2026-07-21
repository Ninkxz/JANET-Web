# JANET Web — design loop 78 (2026-07-21)

## Decision 1 — the deploy harvest, where the raw error already lives
certdeploy has three actions: read-only `check`, read-only `import-pki-hosts` (local parse, no WinRM), and the
destructive `deploy`. Only `deploy` is a per-host remote-acting fan-out whose failures carry a raw WinRM/session/
probe error, and it's the one the operator most needs a "why + how to fix" on. So the hint goes into the deploy
`$emitResult` harvest first; the `check`/`scan` read-only fan-outs emit CHECK ERROR rows with a different shape
and are noted as follow-ups.

## Decision 2 — reuse the existing audit classifier for the failure predicate
The deploy harvest already computes `$auditResult` via a status switch (`ROOTS INSTALLED`→Success,
`ROOTS ALREADY PRESENT`/`SKIPPED`/`OFFLINE`→Skipped, **default**→Failure). The default bucket is exactly the set
of real failures — FAILED, NOT VERIFIED, REJECTED (non-CA). So the hint's failure predicate is simply
`$auditResult -eq 'Failure'` — no new notion of "did this host fail", and it matches what the audit already books
as a Failure. A clean/skip/offline host, whose `.Detail` is a report rather than an error, gets no hint.

## Decision 3 — hoist the classifier so the hint rides with the row
The harvest computed `$auditResult` just AFTER building/emitting the row (it was only needed for the audit event).
To carry the hint on the row I hoisted that computation to the top of `$emitResult`, switching on
`[string]$res.Status` instead of the not-yet-built `$row.Status` (a pure move — same value), and reuse it for both
the hint and the audit. Nothing computes it twice.

## Decision 4 — additive; the existing per-host log is separate
The per-host info/ok/warn/error log line (`[HH:mm:ss] host : status - detail`), the audit event
(result/itemCount/detail), and the end-of-run tally are all unchanged; the hint is computed from the classifier
and only read, the row gains a `Hint` field, and a single err `FIX:` line is emitted for a recognized failure. A
clean host is byte-identical to before.

## Decision 5 — static analysis, matching certdeploy's convention; run the whole tool suite
The deploy harvest runs inside the fan-out over a real RunspacePool with no swappable-worker seam, and
certdeploy's tests are static/pure (they poke the pure token classifier `Get-CertDeployResultToken` and regex the
module `$src`), so the wire is pinned by static analysis (the hint's behavior is proven behaviorally in
`Troubleshoot.Hint.Tests.ps1`): imports the engine, the `Failure` predicate computes the hint, the row carries
`Hint`, the err log appends `FIX:`. certdeploy 1.4.2 → 1.4.3; the new Describe holds the exact pin, loop-49's
`1.4.2` pin floors. **This closes the informative-failures primary rollout (9 tools).** Next: the follow-up
backlog, starting with folding restart's numeric-code hints into the shared engine (the last ad-hoc mapper).
