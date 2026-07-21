# JANET Web — design loop 45 (2026-07-21)

## Decision 1 — the natural follow-on: F5 is F1's twin
Loop-44 closed F1 (AntiMalware books FIXED off a partial signal it can't confirm). F5 is the identical shape in
the Monitoring pillar: FIXED off the service being Running while ignoring the installed half. Closing it right
after F1 keeps the fix pattern fresh and knocks out the second of the dive's two HIGH partial-signal false-cleans
before moving to the low/speculative tail.

## Decision 2 — align the fix verdict with the SCAN verdict
The decisive framing: the scan is the source of truth for "compliant" (it's the quarantine predictor). If the
fixer books FIXED but the scan would still FAIL the same box (because the software isn't detected), then FIXED is
a lie — the host will still be quarantined. So the Monitoring fix verdict must require exactly what the scan's
PASS requires: installed AND running. A running service with the software undetectable can't honestly claim the
pillar fixed → NOT VERIFIED. This "fix-verdict must match scan-verdict" principle is the general lesson for the
remaining c2c pillar findings.

## Decision 3 — NOT VERIFIED, reusing loop-44's machinery
Same reasoning as F1: a service was changed (not a clean FAIL) but the pillar can't be confirmed compliant (not
FIXED). NOT VERIFIED is exactly that, and the host rollup + audit already map it to a not-FIXED / non-Success
outcome. Zero new verdict plumbing.

## Decision 4 — pure helper this time (the verdict is a clean predicate)
Loop-44's F1 verdict was entangled with the whole AntiMalware heal, so a behavioral harness needed a
`Get-Command` shim that leaked, forcing a static test. F5's verdict is a clean 4-branch function of exactly three
booleans/ints — so I extracted `Get-C2cMonitoringVerdict` and unit-tested it directly at every branch (real
behavioral coverage), with the module-less worker carrying the inline mirror and a static assert pinning the
installed gate. When the logic factors into a pure predicate, prefer the helper; when it's tangled in I/O,
static analysis is the honest fallback. Loop 45 got the clean case.

## Decision 5 — version + scope
A Monitoring host that read FIXED on a running-but-not-installed box now reads NOT VERIFIED — behavioral — so c2c
1.15.5 → 1.15.6, the loop-44 exact pin → floor, the new test holds the exact pin. The c2c set (85 across the
Monitoring/AntiMalware/import/run-all files) is green; the authoritative run gates the close. The dive's tail
(items 53–57, F2/F6) stays ranked — mostly low/read-only/speculative, each needing its own re-verification.
