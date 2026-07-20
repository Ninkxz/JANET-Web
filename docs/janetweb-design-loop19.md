# JANET Web — design loop 19 (2026-07-21)

## Decision 1 — the OTHER CSV front door
Loop 18 pinned acas's importer. reports has its own, separate parser (`Parse-AcasFile`) feeding a
different tool. Same offline/CSV-fed exposure, different code — so it's the natural next read-path
target, and reviewing it lets me compare the two importers' robustness contracts head to head.

## Decision 2 — fix the silent zero-import, not just cover it
Unlike loop 17/18 (which were coverage-only on already-correct code), this loop found a real
behavioral gap: a wrong-template CSV imported zero findings with no warning. That's harm-relevant
(silent undercount = false comfort on an offline tool), and acas already had the guard, so the
right move is to close the parity gap in the code — a loud `warn` — not merely test the silence.

## Decision 3 — additive, $Emit-gated, name the missing column
The fix adds only a diagnostic on the failure path; it changes nothing about what a valid CSV
imports. It's gated on `$Emit` (the optional log callback) so a non-emitting caller is unaffected,
and it names WHICH column is missing (host and/or plugin) so the operator knows what to fix — more
useful than a generic "no findings." Mirrors the acas `ConvertFrom-AcasCsv` hint for consistency.

## Decision 4 — version bump because behavior changed
A new operator-visible warn on a previously-silent path is a behavioral change, so reports bumps
2.14.22 → 2.14.23 (unlike the loop 17/18 test-only adds that did NOT bump). The prior exact-version
test pin moves to a `-ge` floor; the new loop-19 test carries the exact 2.14.23 pin — the repo's
established "one exact pin on the newest bump, floors elsewhere" convention.

## Decision 5 — test the real parser via temp files + captured -Emit
`Parse-AcasFile` takes a file path and an `-Emit` callback, so the test writes real temp CSVs
(UTF-8 BOM, like an export) and captures the emitted log. KEV/IAVM "empty catalog" warns are
filtered out (match only the `could not find` wrong-template line), so the test is independent of
whether JanetLocal ships those reference files. Temp files are removed in a `finally`.

## Decision 6 — Fable-inline, no agents
Reading a second CSV parser, spotting the missing-hint parity gap, and writing an additive warn +
its test is inline Fable work. No adversarial/mechanical agent warranted for a one-line additive
diagnostic on a non-destructive read path.

## Offline posture
Reinforces the offline/CSV-fed constraint from the other side: both importers now tell the operator
"your CSV headers don't match the expected template" instead of silently reporting a clean fleet.
No network, no new dependency — the fix is a local diagnostic string.
