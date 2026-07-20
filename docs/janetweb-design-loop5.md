# JANET Web — design loop 5 (2026-07-20)

## Decision 1 — workstream = a destructive-tool deep-dive, and its outcome is coverage
The cadence rotates the "one workstream". Loops 1–4 fixed defects; this loop I
deep-dived `upr` (a permanent-removal tool never loop-reviewed) expecting to find a
hardening gap. Instead the tool proved solid on every established pattern. The honest
outcome of a clean deep-dive is not to invent a fix — it is to LOCK IN the fail-closed
behavior that had no regression test. So the deliverable is test-coverage growth on the
single most dangerous path (live remove-all), plus one comment-accuracy fix.

## Decision 2 — which gate to cover: live-uninstall-requires-selection
`upr` has several guards; the one with the worst blast radius AND no behavioral test was
the "refuse a live wave with no operator selection" gate. The worker treats a `$null`
RemoveSet as remove-every-proven-candidate; the ONLY thing standing between a stale/non-UI
client and a fleet-wide remove-all is the dispatcher refusing live+no-selection. Self-guard
and DNS-mismatch already had tests (SelfGuard suite, UninstallStringParse suite); this did
not. Highest marginal safety per test.

## Decision 3 — drive the real dispatcher, no host contact
The refusal returns BEFORE `Build-Upr*HostJobs` and fan-out, so the tests call the actual
`Invoke-JanetToolAction` with no credential and assert the refusal — real dispatcher, zero
WinRM. The report path needs findings>0 to reach its gate, so it is fed a one-row CSV whose
Plugin Name matches the unsupported regex (`Parse-CsvFinding` yields ≥1 finding). Asserting
the summary carries `Refused` proves BOTH that the CSV parsed (findings>0) and that the
live gate fired — an empty parse would instead return total 0 with no error, failing the
assert. So the test cannot silently pass on a broken parse.

## Decision 4 — dry-run negative test proves the gate is scoped to LIVE
A gate that refuses everything is useless. The dry-run test (self-only host) proves the
refusal is bypassed in preview mode, while the self-guard still short-circuits to total 0
without host contact — so the negative case is host-free too.

## Decision 5 — no version bump for a comment + tests
The only module edit is a comment-accuracy fix (the shared worker's uninstall-pass was
mislabeled "report-uninstall only"); no tool behavior changed and no test pins upr's
version. Bumping 1.2.2 for a comment would be changelog noise. The manifest-version-bump
convention is for behavioral tool changes; this isn't one.

## Process — Opus F1/F6 notes deferred, not scope-crept
Opus's loop-4 review surfaced two cheap Host-guard test gaps (absent Host, cancel route)
and a non-default-port comment nit. Real but tiny, and adding them would be a SECOND
workstream. Ranked as item 8 + an F1 note; picked up in a later loop rather than diluting
this one.
