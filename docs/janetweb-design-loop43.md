# JANET Web — design loop 43 (2026-07-21)

## Decision 1 — the worker's top finding, and the concrete slice of item40
item40 is a class spanning M365, Trellix, and the SC-trigger profiles, each with a different ignored-signal
mechanism. The M365 slice is the cleanest and highest-value: it's the worker's top-ranked finding, the profiles
are the most-used Office remediation, and the fix is an unambiguous exit-code gate. Trellix (`$LASTEXITCODE` on a
native call) and the SC-trigger profiles (discarded `Invoke-CimMethod` rv) are the same class with different
plumbing — each gets its own follow-on rather than a sprawling multi-mechanism change in one loop.

## Decision 2 — gate nonzero → FAIL, keep exit-0 → OK (don't over-reach into item51)
OfficeC2RClient's exit code is not a completion signal — with `-forceappshutdown` the Click-to-Run service does
the actual update, and exit 0 often means "accepted/started", not "done". So the honest, bounded fix is: a
NONZERO exit is a definite failure (close that false-clean), and exit 0 stays OK-triggered. Making exit-0 mean
"patched" would require a post-trigger verify — that's the trigger≠patched semantic (item51), a larger change I
deliberately did not fold in. Crucially, exit-0's completion is not unguarded: the paired M365C2RVerify gates
Verified on scenario success (loop24), so the verify action already tells the truth even when the apply says
OK-triggered.

## Decision 3 — fix both M365 profiles, not just Force Update
Force Update and User Visible are the same bug with different OfficeC2RClient args. Fixing one and leaving the
other would ship the same false-clean under a different profile name — the loop-42 lesson (a false-clean is a
class). The module-wide static assert ("the unconditional OK-with-exit form appears nowhere") pins that both
are fixed and no third instance lurks.

## Decision 4 — static analysis is the right test shape here
The profile Scripts run remotely in module-less runspaces, so there's no pure function to unit-test; the exit-
code gate is a two-line branch. Static analysis of the isolated profile blocks (the established pattern for wpt/
acas remote profile Scripts) pins the fix precisely: both blocks test `$proc.ExitCode -ne 0 → FAIL`, and the old
form is gone module-wide. Version: a nonzero-exit host that read OK now reads FAIL — behavioral — so wpt 6.8.10
→ 6.8.11, BulkPatchRv exact pin → floor.

## Decision 5 — honest about what's left
This is the sixth consecutive acas/wpt verify-honesty loop; the remaining wpt HIGH items (the item40 Trellix/SC
residual, item43, item51) are each nuanced (unreliable native signals, a needed version target, an operator-
facing audit-semantic change). The clean-port vein is genuinely thinning. Next loop should weigh a fresh dive on
an un-reviewed destructive tool (c2c pillar fixes, remoteadmin, adto) against these narrower closes.
