# JANET Web — design loop 24 (2026-07-21)

## Decision 1 — finish the wpt verify false-clean cluster in ranked order
The loop-22 deep-dive mapped four false-cleans; #13 and #14 are done. #15 (M365 mtime verify) is the
next-highest CONFIRMED one and has a clean, contained fix, so it's the pick over diversifying —
closing the cluster methodically is worth a third wpt loop, and #15 doesn't need the version-baseline
feature #16 does.

## Decision 2 — gate on the scenario RESULT, the signal already half-read
The scriptblock already read `$p.LastScenario` for its Detail but ignored `$p.LastScenarioResult` for
its verdict. C2R writes both on every attempt including failures, so freshness proves "an update ran",
not "an update succeeded". The minimal honest fix is to also require the result to say success — no
new data source, just stop throwing away a signal that's sitting right there.

## Decision 3 — never over-claim: unknown result -> $null, not $true
Three outcomes, not two. Fresh + Success is the only green; fresh + Failure is red (the false-clean);
fresh + unknown/blank result is `$null` (indeterminate) rather than green. A verify that can't confirm
success must not report Verified — the whole point of the fix is to stop the tool asserting patched
when it can't prove it.

## Decision 4 — one canonical verdict, mirrored across the WinRM boundary
Same pattern as loops 22-23: the verify scriptblock runs remotely and can't call a module function, so
the decision lives in a pure tested helper `Get-WptC2rVerified` and the scriptblock mirrors it inline,
comment-linked. The helper is the spec; the test pins it; the mirror is a faithful copy.

## Decision 5 — read-only path, but still a full guard/regression pass
This is a verify (registry-read) scriptblock, no destructive fan-out, so no self-guard/confirm applies.
Still ran the full 134-test wpt set (not just the new file) — the loop-22 lesson was that a narrow
gate hides regressions, and a verify verdict feeds operator decisions, so it earns the wide check.

## Decision 6 — version bump + pin migration
Changed verify verdict is behavioral (a host that read Verified may now read not-verified), so wpt
6.8.7 -> 6.8.8, the loop-23 exact pin -> floor, the loop-24 test holds the exact pin. Fable-inline;
reading one scriptblock and extracting a three-branch verdict helper needs no agent.
