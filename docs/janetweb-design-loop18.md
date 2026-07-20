# JANET Web — design loop 18 (2026-07-20)

## Decision 1 — walk UP the pipeline, from routing to ingestion
Loop 17 pinned the routing (plugin name → fix). The layer above it is the CSV import that produces
the plugin name in the first place. In an offline/CSV-fed tool the import is the single point where
one bad row poisons every downstream number, and it's the layer the operator's raw ACAS export hits
first. So loop 18's workstream is the ingestion parser `ConvertFrom-AcasCsv`.

## Decision 2 — the parser is already robust; the value is locking it in
The deep-dive found no defect: `Import-Csv -Encoding UTF8` (BOM + quoted fields), empty-on-missing
column (no throw), host-token whitelist before target, server-skip, and a loud wrong-template hint.
That's a well-built front door. The risk isn't today's code — it's a future edit silently
regressing one of those properties (drop `-Encoding UTF8`, weaken the token gate, delete the hint)
with no test to catch it. So the deliverable is coverage of the ACTUAL parser, not a change.

## Decision 3 — test the real parser via its return contract, not a reimplementation
`ConvertFrom-AcasCsv` returns `@{ Findings; RowCount; ServersSkipped; NoHostSkipped }` and takes a
`-Send` callback for log lines. The test drives it in module scope with synthetic CSV via `-Text`
(no temp files) and asserts against that returned hashtable + a captured `-Send` log — so it pins
the real behavior (host-pick order, mapping, skips, the hint), which a reimplementation couldn't.

## Decision 4 — one real BOM file for the encoding claim
The BOM-decode property can't be exercised through `-Text` (a here-string BOM would fold into the
first header, which is the opposite of what a file import does). So one case writes a genuine UTF-8
BOM file to a temp path and drives the `-Paths` import — the only faithful way to pin `-Encoding
UTF8`. It cleans up in a `finally`. This is the one test that touches the filesystem, deliberately.

## Decision 5 — test-only, no version bump
No behavior changed; acas stays v1.11.5. Same rule as loop 17 — a version bump for a coverage add
would falsely imply a behavior change.

## Decision 6 — Fable-inline, no agents
Reading a CSV parser and writing an ingestion test is squarely inline Fable work per the directive.
No adversarial/mechanical agent warranted (test-only, no destructive code touched).

## Offline posture
The whole change reinforces the offline/CSV-fed constraint: it pins that the import decodes local
UTF-8 CSVs (BOM and all) correctly and surfaces a wrong-template file loudly, with zero network
dependency. Consistent with "everything is fed in via CSVs, offline only."
