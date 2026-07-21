# JANET Web — design loop 35 (2026-07-21)

## Decision 1 — a fresh un-reviewed tool over grinding the hard backlog
The deferred HIGH items (c2c fix-rollup cluster, winupgrade #27/#29) are entangled/remote and each
wants a dedicated careful loop; rather than half-do one, I deep-dived a clean un-reviewed destructive
tool, upr. It has the exact false-clean surface worth checking — an SEoL remediator that reports a
product removed while it's still installed lets the operator close a vuln that's still open.

## Decision 2 — GREEN is the result; the fix is defense-in-depth, not invention
upr's removed decision is fail-closed end-to-end: exit-code gated AND registry-re-verified after every
OK, with skips/rejects/unreachables bucketed separately. Confirming that with file:line evidence is the
deliverable. The one thing worth touching is a speculative twin of an already-present guard, not a new
gap — so I hardened it rather than inventing a problem.

## Decision 3 — the empty-result twin of the throw fail-close
The verify already fails closed when the re-read THROWS (the catch sets $stillPresent=$null → "could NOT
be verified"). But a non-throwing EMPTY result slipped through: [bool]$null.Present is $false, which
reads as "not present" = removed. It's the same failure mode (can't confirm gone) with a different
trigger, and the fix is to treat it the same way. Symmetry: both "couldn't read" cases → fail closed.

## Decision 4 — canonical helper + inline mirror (runspace boundary)
The verify decision runs in the upr uninstall worker, a module-less CreateDefault runspace, so it can't
call the helper. Same pattern as every runspace-boundary fix this series: `Get-UprVerifyResult` is the
pure tested spec (all four branches incl. the null-VerifyOut case), the worker mirrors the one changed
line inline. The helper test proves the decision; the worker keeps the existing 4-branch tail already
matching it.

## Decision 5 — minimal worker change, existing decision unchanged
The worker's 4-branch decision (:1137-1145) was already fail-closed on a $null $stillPresent — the ONLY
gap was how $stillPresent was computed from $vout. So the worker fix is one line (add the $null-$vout
check); the rest is untouched, keeping the diff tiny and the behavior for every non-empty result
byte-identical.

## Decision 6 — version bump, full upr regression pass
A changed verify verdict is behavioral (an empty-result case that read OK now reads FAIL): upr 1.2.2 ->
1.2.3, the loop-35 test holds the exact pin. upr is destructive, so I ran the full 36-test upr set (the
loop-22 wide-gate lesson) — Adobe uninstall, SelfGuard, UninstallStringParse, LiveSelectionRefuse all
green, confirming non-empty results are unchanged. Fable-inline; the deep-dive was a parallel Fable
worker, the hardening a one-line change verified in-code.
