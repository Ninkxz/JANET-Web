# JANET Web — design loop 14 (2026-07-20)

## Decision 1 — finish what loop 13 started rather than open a new front
Loop 13 fixed the HEADLINE reports host counts and explicitly ranked the tail (items 11-12)
rather than touch every corner of a 7,410-line file in one risky pass. Loop 14's workstream is
that ranked tail. Completing a coherent correctness fix — so the invariant "every host count
agrees with CORA" actually holds tool-wide, not just for the headline reports — is higher value
than starting a fresh deep-dive and leaving the reports work half-done. Close the thread.

## Decision 2 — the remediation-refresh app-aggregate genuinely needed its own fix
Loop 13 fixed `Build-RemediationPlan`'s internal OtherGroups host count. But the
`remediation-refresh` ACTION re-aggregates per-app from `$plan.Rows` in a SEPARATE loop
(`:4770`) that keyed on the raw row hostname — so the headline fix upstream didn't cover it.
This is exactly the "verify the ACTION paths feed the fixed aggregations" caution from the
loop-13 doc: an upstream dedup does not automatically fix a downstream re-aggregation. Verified
by running the action and seeing TargetCount reflect the fix.

## Decision 3 — normalize the counter KEY, keep the display RAW (export-poam)
export-poam is a POA&M export: each row IS a finding, and its Host column must name the actual
host (raw). Only the per-host "Finding N" *sequence counter* should treat two name forms as one
host. So the fix normalizes the counter key (and its later read, which I had to align or the
number would read 0) while leaving the row's Host column raw. Key on normalized, display raw —
the same rule as the loop-13 headline sites.

## Decision 4 — IAVM guard mirrors the existing helper, doesn't reinvent
`ConvertTo-ReportsCsvCell` already encodes the repo's formula-injection guard (prefix `'` on a
leading `=+-@`/tab/CR). `Write-ReportsIavmMap` had its own `$q` that only quote-wrapped. Rather
than route IAVM through ConvertTo-ReportsCsvCell (different quoting nuances, risk of changing
existing output), I added the identical prefix check into `$q`. Smallest diff, matches the
established guard, no behavior change for clean cells (tested).

## Decision 5 — inline, Fable-only, no agents
Per the operator's mid-loop directive (prefer Fable), the loop-13 self-review and the loop-14
sweep were done inline by Fable. A mechanical normalization sweep + a one-line CSV guard, over a
file I'd just deep-reviewed, does not benefit from an Opus second opinion or a Sonnet mechanical
pass — Fable is good enough here, which is the point of the directive. The baseline suite still
ran in the background while I worked.

## Versioning
reports `2.14.21 → 2.14.22` (behavioral: host-count keys + CSV guard). `Reports.HostCountAgreement`
holds the exact pin.
