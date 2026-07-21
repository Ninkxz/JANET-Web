# JANET Web — design loop 23 (2026-07-21)

## Decision 1 — repair the loop-22 regression FIRST, as its own commit
The loop-22 authoritative suite came back red (1/1203). Honesty + a clean ledger demand fixing that
before any new work, and as a distinct `loop22-repair` commit so history shows exactly what broke and
why. The fix is a wording restore (the null-fail-close behavior was correct and kept); the regression
was purely a gratuitous string change riding along in the KB-match commit.

## Decision 2 — test the behavior loop 22 shipped untested
The loop-22 null-ReturnValue fail-close had no test (the commit added a behavior without one — the
thing this loop's cadence exists to prevent). So the repair also adds the null case via a `-Rv -1`
sentinel that makes the shim return a method result with no ReturnValue member. Now every InstallUpdates
outcome (0 → installed, non-zero → rejected, null → rejected/fail-closed) is pinned.

## Decision 3 — item 14 is the right next workstream
It's the highest-harm confirmed false-clean from the loop-22 wpt deep-dive and I flagged it pick-next.
A trigger reported "Installed" is exactly the false-comfort the recent loops target, and it's the most
operator-facing of the four wpt verify findings.

## Decision 4 — "Triggered (verify)" errs toward verify, even with a partial MSU install
The honest label prioritizes surfacing the UNCONFIRMED part: any MECM trigger present → "Triggered
(verify)", even if some KBs also installed via MSU. Claiming "Installed" while any piece is an
unconfirmed async trigger is the false-clean; erring toward verify never over-claims, and the Detail
column still carries the MECM/MSU breakdown for the operator who wants specifics.

## Decision 5 — the fix must span server AND view or it's invisible
The server Result was already computed but the view ignored it (hardcoded Installed/Failed off Success)
and counted every success as installed. Fixing only the server would leave the operator still seeing
"Installed" and an inflated installed count. So the view now surfaces `r.Result` and gates its counter
on a confirmed `Installed`. Server helper is pure/tested; the view is pinned by static assertion (the
repo's established view-test pattern — Get-Content -Raw + -match).

## Decision 6 — stop at the label, leave the audit-action for a follow-on
The `VulnPatched` audit still books Success for a MECM trigger. Re-plumbing the fan-out's per-row audit
 action is a bigger change than the operator-facing label, and the label + the MECM/MSU Detail already
close the visible false-clean. Ranked as a follow-on to item 14 rather than expanding this loop.

## Decision 7 — one authoritative suite covers repair + item 14
Both touch kb-install and neither runs a suite until all edits land, so one authoritative run confirms
the loop-22 repair (the FixVerify2 subset green again) AND loop-23 item 14 together. The pre-commit
gate this time was the FULL wpt set PLUS FixVerify2 (138 green) — the exact miss from loop 22, corrected.
