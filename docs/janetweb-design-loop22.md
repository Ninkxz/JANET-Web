# JANET Web — design loop 22 (2026-07-21)

## Decision 1 — diversify to wpt, via a bounded parallel Fable worker
Five of the last loops lived in reports/acas; wpt is the single most-used tool with no loop-era
deep-dive. But wpt is 480KB — too big to fully review inline in one loop. So while the loop-21 suite
ran (dead wait time), I spawned ONE Fable worker scoped to a single harm-relevant question — can wpt
report "patched" when it isn't — rather than an open-ended review. That's the "parallel worker while
I wait" pattern, used to buy a focused answer, not to outsource judgment.

## Decision 2 — verify the worker, then fix ONE
The worker returned YELLOW with 4 confirmed false-cleans. I re-read each in the code before trusting
it (a subagent finding is a lead, not a verdict). Loop discipline is one workstream + one fix + one
test, and these four differ wildly in blast radius, so I fixed the crispest and ranked the rest as
roadmap items 14-17 with the highest-harm one (#14, async-trigger "Installed") flagged as pick-next.

## Decision 3 — fix the ripple-free one, not the highest-harm one, this loop
The highest real-world harm is #14 (a trigger reported "Installed" + a VulnPatched audit), but its
honest fix changes an operator-facing Result label, likely the view, and the audit-action semantics —
too broad to do safely in one loop. The KB-match bug is a self-contained matching-logic error: fixing
it only TIGHTENS matching (strictly safer), touches no label/view/audit/guard, and is fully testable
as a pure predicate. Best harm-reduction-per-ripple for a single loop; #14 gets its own.

## Decision 4 — one canonical rule, mirrored across the WinRM boundary
The match runs remotely (over the update set queried on the host), so it can't call a module function.
Rather than leave it inline-only, I extracted the canonical rule into `Test-WptKbNameMatch` (tested)
and made the remote scriptblock mirror it as `$kbMatch`, comment-linked. Same lockstep discipline as
loop 21's SLA helper, adapted to a boundary code can't cross — the tested helper IS the spec.

## Decision 5 — anchored match: exact article OR bounded Name token
ArticleID is the reliable field → exact `-eq` on the normalized number. The Name is the fallback (some
MECM entries have a blank ArticleID) → match the KB token bounded by a negative-digit lookahead
`KB<num>(?!\d)`, so a shorter KB can't prefix-match a longer article. Left side is anchored by the
literal `KB`. This is the minimum change that closes the substring hole without dropping the
legitimate Name fallback.

## Decision 6 — fail-closed on a null ReturnValue, in the same edit
`$null -eq $rv -or [int]$rv -eq 0` counted a null return as success — a method that returned nothing
did not confirm acceptance. Flipped to `$null -ne $rv -and [int]$rv -eq 0`. It lives in the same remote
block I was already editing and is a one-line fail-closed hardening consistent with the destructive
contract, so it rides along rather than becoming a separate loop.

## Decision 7 — version bump + pin migration, no guard touched
KB matching changes which update installs → behavioral → wpt 6.8.5 → 6.8.6, SelfGuardApply exact pin
→ floor, loop-22 test holds the exact pin. I re-ran all 117 wpt tests to confirm the DNS wrong-box
guard and dispatcher self-guard (untouched by the edit) still hold — a destructive-path change earns
the guard re-verify even when the diff is only matching logic.
