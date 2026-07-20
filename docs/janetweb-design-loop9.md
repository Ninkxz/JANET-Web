# JANET Web — design loop 9 (2026-07-20)

## Decision 1 — deep-dive the #1 tool's UNreviewed destructive paths
Loops 1–3 reviewed wpt's Chrome/Edge profiles; loop 5 upr, loop 8 c2c. wpt is the most-used
tool and its other destructive paths (Install-KB, Custom Command, software uninstall,
app-action, fan-out) had never had a dedicated adversarial pass. Highest expected value of the
remaining unreviewed surface, and it paid off: a P2 self-guard gap on the arbitrary-RCE action.

## Decision 2 — fix all three self-guard gaps in one coherent pass, not just the P2
Opus rated F1 (app-update-apply) P2 and F2 (app-action, unsupported-uninstall) P3, recommending
F2 be folded in. Taken, because the three are ONE defect class (destructive dispatchers missing
the established self-guard), and leaving two known-inconsistent siblings — especially
`unsupported-uninstall` removing the same Java that self-guarded `fix-java` removes — is exactly
the latent-inconsistency that causes a future incident. The fix is the identical 4-line block
already proven at 8 call sites; low risk, one version bump, one coherent commit.

## Decision 3 — placement respects each handler's target shape
- app-update-apply / app-action: `$targets` array → mirror bulk-patch verbatim (guard →
  reassign → return total 0 if empty).
- unsupported-uninstall: hosts come from `pairs` (a `$byHost` hashtable), NOT `$targets` — so
  the guard is on the pairs-derived `$hostList`, and `$totalUnits` recomputed from the filtered
  list. The dispatcher's own `targets` gate (line ~5212) is non-empty validation, not a
  self-guard, so it does not cover this; the pairs list is the real dial set.

## Decision 4 — self-guard is the right control, wrong-box is not enough
The wrong-box guard compares remote COMPUTERNAME to the dialed name — it catches dialing the
WRONG host, but the dispatcher dialed by its OWN correct name passes it cleanly. Only a
before-fan-out self-drop stops the dispatcher acting on itself. This is why every other
destructive action has BOTH; app-update-apply had only the wrong-box half.

## Decision 5 — confirm string on the arbitrary-RCE action
F3 is UX/authorization hardening: the generic destructive confirm-word gate already applies,
but the one action that runs arbitrary PowerShell had no per-action `confirm=` warning while
strictly-lower-risk actions (kb-install, fix-java, ccm-repair) all had one. Added it naming both
the arbitrary-PowerShell risk and the self-guard behavior, so the operator sees the loudest
dialog on the highest-capability action.

## Versioning
wpt `6.8.2 → 6.8.3` (behavioral: adds a guard + a confirm to existing destructive actions).
`Wpt.SelfGuardApply` carries the exact pin; `Wpt.EdgeProfile`'s exact pin → floor assert
(wpt-suite precedent — newest bump's file keeps the exact pin, older files floor).

## Test-authoring note
The unsupported-uninstall test first failed because the dispatcher gate needs a non-empty
`targets` param before the handler runs (the view sends both `targets` and `pairs`). Probed the
real dispatcher to find the "No valid targets" early-return, then added `targets` to the test so
it reaches the pairs self-guard. Probe-first beat guessing again.
