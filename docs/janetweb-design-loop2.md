# JANET Web — design loop 2 (2026-07-20)

## Decision 1 — Edge trigger order is exe-first (inverse of Chrome)
Chrome's honest profile is task-first because Google migrated machines to the modern
GoogleUpdater (no GoogleUpdate.exe). Edge has no such migration: the updater exe
ships with every machine-level Edge and remains the canonical trigger, so the exe is
tried first and the `MicrosoftEdgeUpdateTaskMachineUA*` task is only a fallback for
a missing exe. Mirroring Chrome's task-first order would have added a scheduled-task
dependency for zero coverage gain.

## Decision 2 — per-module result dialect, one boundary rule
Same rule as loop 1, now applied twice and locked by four tests: wpt Scripts speak
`PENDING*` (wpt's classifier maps it to amber Pending); acas Scripts speak
`UNCONFIRMED*` (acas's `AcasOkOf` books any non-FAIL/UNCONFIRMED/SKIP string green).
The port boundary translates; neither module's classifier changes. Tests assert the
acas Script contains no `PENDING` and the wpt Script does.

## Decision 3 — FAIL routing text differs by module capability
acas has an `'Microsoft Edge - Software Center'` alternate → blockers route to it by
exact profile name. wpt has no Edge SC profile → blockers route to "Software Center
/ MECM" generically. Adding a wpt Edge SC profile was considered and skipped: the
wpt App Updater's Edge coverage need is met by MECM deployment ring text, and a new
profile is feature surface, not defect repair (YAGNI; revisit if operators ask).

## Decision 4 — floor asserts replace exact pins in old test files
Applied the operator-approved 2026-07-16 wpt precedent to the acas suites: old test
files assert `[version] -ge <the version they shipped with>`; only the newest bump's
own test file carries the exact pin. Kills the every-bump churn across N files that
the loop-1 close paid (2 pin edits) and Opus flagged (P3-2).

## Versioning
wpt `6.8.0 → 6.8.1`, acas `1.11.4 → 1.11.5` (manifest `version` field, normal git
edit — JANET Web convention). Patch bumps: behavior-honesty repair on an existing
profile, no new action surface.
