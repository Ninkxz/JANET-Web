# JANET Web — design loop 7 (2026-07-20)

## Decision 1 — the last cheap tracked guard, then the backlog turns speculative
Item 7 (report-resource-free guard) was the final small, concretely-scoped tracked item.
After it, the ranked backlog is either decision-gated (SECRET parity, operator sign-off)
or speculative (token-on-cmdline is loopback-local low-sev, SKIP-tally is a reporting
preference). So loop 7 banks item 7; loop 8+ will need to reach for fresh tool deep-dives
(the acas/reports/c2c engines have depth left) rather than the tracked list.

## Decision 2 — static source guard over a per-report render
The faithful test would render all five `Render-*Html` functions and assert on the emitted
HTML. That needs five distinct valid input fixtures and would couple the test to each
render function's data contract. The static source grep catches the realistic regression
(someone pastes an `<img>`/`<link>`, adds a print button) at a fraction of the cost and
with zero fixture drift. The ceiling (string-concatenated external ref) is named in a
ponytail comment with the render-based upgrade path. Smallest thing that makes the sandbox
constraint discoverable — which is exactly what F8 asked for.

## Decision 3 — couple the guard to the thing it guards
The test asserts BOTH that the report module is resource-free AND that the server CSP still
leads with `sandbox allow-scripts`. Either alone rots: a resource-free report with the
sandbox removed loses the backstop silently; a sandbox with an external-ref report breaks
the preview. Asserting both in one file means the pair can't drift apart unnoticed.

## Decision 4 — HTML-context-anchored patterns, not bare tokens
The first draft asserted a bare `src=` and went RED on `$src = ConvertTo-HtmlEscaped(...)`
(PS `-match` is case-insensitive; the var ends in "src"). Fixed by anchoring every
attribute pattern to a leading whitespace (`\ssrc\s*=`) — an HTML attribute always has
whitespace before its name, a PowerShell variable does not. Tag patterns use `<tag\b`. This
is the difference between a guard that fires on real regressions and one that cries wolf on
ordinary PS code.

## Decision 5 — accept Opus F3 rather than relax loop-6's asserts
Opus flagged the loop-6 empty/absent-Host asserts as pinning an exact 421 that a future
http.sys build could turn to 400 (false-RED only). Relaxing them to `Not Match '200'` would
buy build-independence but lose the "OUR guard handled it" distinction that makes the test
informative. On a manually-run, no-CID suite targeting known Windows builds, the exact-421
is worth more than the portability; recorded as accepted rather than churned.
