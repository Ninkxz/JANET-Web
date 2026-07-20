# JANET Web — design loop 21 (2026-07-21)

## Decision 1 — verify the compliance math, then remove the drift risk
The SLA aging math feeds real prioritization + the POA&M export, so it earned a deep-dive. It turned
out correct, so the value isn't a fix — it's that the boundary rule was duplicated across two views
that MUST agree, with no test. Consolidating to one tested helper is the durable move: it can't be a
bug today, but it's a latent one the moment someone edits one copy.

## Decision 2 — a shared helper is DRY, not gold-plating
Ponytail says no unrequested abstractions — but this isn't speculative. There are two REAL call
sites with identical non-trivial arithmetic producing operator-facing compliance numbers that have
to match. Extracting the boundary decision into `Get-ReportsSlaBucket` is deletion of duplication
and a single source of truth for a compliance path, exactly where DRY earns its keep.

## Decision 3 — extract the whole boundary block, not just the branch
The helper takes (Deadline, Age) and returns DueIn + Bucket + SoonThreshold + Window, so BOTH the
dueIn arithmetic AND the window/soon/boundary rule live in one place. The call sites keep their own
age/ledger/display code and just delegate the decision. That maximizes the shared surface (the part
most likely to be edited) while leaving each view's presentation untouched.

## Decision 4 — no version bump, because behavior is identical
The manifest version in this repo signals a BEHAVIORAL change (that's why loops 17/18 test-only adds
didn't bump and loops 19/20 count changes did). This is an internal consolidation with byte-identical
output — bumping would falsely tell an operator something changed for them. So reports stays 2.14.24,
git records the refactor, and the loop-20 exact version pin remains valid (no floor churn). The
regression test proves the helper's outputs rather than a version.

## Decision 5 — test the pure helper at the boundaries
`Get-ReportsSlaBucket` is pure (no I/O), so the test hits it directly at every transition: the
threshold edge (dueIn 8 vs 9 on a 30-day window), the deadline day (dueIn 0 = DUE-SOON), the first
overdue day (dueIn -1), the 3-day floor beating 25% on 7- and 4-day windows, and the zero-deadline
window-floor guard. Plus Get-ReportsSlaDeadline's severity map + KEV override. Integration is covered
transitively by the existing PostureDigest test (posture-digest reuses the sla-aging action).

## Decision 6 — Fable-inline, no agents
Reading two SLA blocks, confirming they match, and extracting + rewiring one pure helper with a
boundary test is inline Fable work. No agent warranted on a non-destructive, behavior-preserving
read-path consolidation.
