# JANET Web — design loop 17 (2026-07-20)

## Decision 1 — pivot from security to remediation-ROUTING correctness
The destructive-security surface is exhausted (loops 1-16). The next-highest operator risk in an
offline/CSV-fed remediation tool is a MIS-ROUTE: the auto-patch engine applies the wrong fix to a
real finding. That's the acas match engine (plugin name → profile). It sits between "here is a
real vuln" and "here is the fix we'll run" — a wrong answer there is silently harmful. So loop
17's workstream is a correctness review of the routing.

## Decision 2 — the exclusions are the point
An additive routing bug (a finding that fails to match any rule) is visible: it shows as
NotUpdatable, no Run button, the operator notices. The DANGEROUS bug is a wrong MATCH — a
look-alike routed to the wrong updater (Edge WebView2 → Edge browser, Symantec → Defender). The
exclusions are the only thing preventing that, and they were untested. So the test weight went on
the EXCLUSIONS (5 non-route cases) plus structural assertions that the Exclude lists exist — a
match-table edit that drops an Exclude now fails.

## Decision 3 — test the real router, not a reimplementation
The test drives the actual `Get-AcasVulnGroups` (module-scope) with synthetic findings and reads
back `ProfileNames`, rather than re-deriving the match logic in the test. That means it pins the
ACTUAL routing behavior (order, exclusion, case) — a reimplementation could drift from the code
and pass while the code mis-routes. The finding shape is minimal (`PluginName` is the only field
the routing reads).

## Decision 4 — test-only, no version bump
The routing code is correct; I added coverage, changed no behavior. acas stays v1.11.5. Bumping a
tool version for a coverage add would falsely imply a behavior change (the convention bumps on
behavioral changes).

## Decision 5 — Fable-inline, no agents
Per the directive: the deep-dive and the test were done inline by Fable. Reading a match loop and
writing a routing table test don't need a second model.

## Offline posture
The routing operates entirely on the plugin-name text from the imported CSV — no lookup, no
network. It's pure classification of local data, consistent with the offline/CSV-fed posture.
