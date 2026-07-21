# JANET Web — design loop 72 (2026-07-21)

## Decision 1 — the two most-used tools share the same fan-out shape
wpt and acas both funnel their remote actions through one generic fan-out with per-action callbacks; the acas wire
(loop 71) was in `Invoke-AcasFanOut`, and `Invoke-WptFanOut` is its near-twin (same `$OkOf`/`$RowOf`/`$AuditDetail`
contract, `$res` a hashtable). So loop 72 is the same one-line-of-logic wire in the twin function — one edit covers
wpt's fan-out actions, exactly as loop 71 did for acas.

## Decision 2 — compute the hint before the row, from the best error source
wpt emits the row before the audit, so to carry the hint on the row it must be computed first. The most error-bearing
text is `$res.Error` (the worker/exception field); when that's empty, the audit-detail string the action's
`$AuditDetail` callback produces is the next-best source. I compute that detail string once, up front, and reuse it for
both the hint fallback and the audit emission — which also removes a latent double-evaluation of the `$AuditDetail`
callback (it was being invoked inline in the audit send).

## Decision 3 — additive, guarded, ok-path byte-identical
Same discipline as acas: the classify, row, audit result/count, and counters are untouched; the hint is computed after
`$ok` and only read; the `Hint` field is added by mutating the row hashtable guarded by a type check. An ok host
computes no hint and emits no extra log, so the common (success) path is byte-identical. The new err log is gated on a
non-empty hint, so an unrecognized failure is unchanged (still shown in the row).

## Decision 4 — static analysis, matching wpt's own fan-out tests
Unlike acas (where I built a behavioral harness driving the real fan-out), wpt's existing fan-out tests
(`Wpt.ChromeProfiles`) are static source assertions, and wpt has no behavioral fan-out harness. The hint's *behavior*
is already behaviorally proven three ways (the 9 `Get-JanetTroubleshootHint` unit tests, the remoteadmin behavioral
test, the acas behavioral test), so pinning the wpt *wire* by static analysis — imports the engine, computes the hint
only on failure, attaches `$row['Hint']`, gates the `FIX:` log on `$hint`, reuses the audit-detail string — is
proportionate and matches the file's convention.

## Decision 5 — run the whole tool's suite; a test-bug caught
Because the fan-out is shared by every wpt fan-out action, I ran all 182 wpt tests, not just the new file — the wire is
additive and none regressed. One failure surfaced, but it was my own static assert: a `[^}]*` in the regex couldn't
cross the `}` inside the log text's `$(if $res.Error …)` interpolation, so it never reached `FIX:`. Split it into two
asserts (the gated err-log emission, and the `FIX: $hint` text) — the wire itself was correct. wpt 6.8.14 → 6.8.15;
the new Describe holds the exact pin, AdobeUninstall floors. Next tool: pkginstall.
