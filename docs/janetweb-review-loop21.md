# JANET Web — review loop 21 (2026-07-21)

**Baseline:** 1174/1174 at loop-20 close (authoritative). Fable-inline. Local-only commits.

## Self-review of loop-20 (`68c3103` Remediation Plan host-key fold, `32c17f7` docs) — verdict GREEN (inline)
The fix normalized three coupled sites (bucket key `:1802`, summary count `:1878`, status setter
`:5998`). The risk was the status-key coupling — a mark landing on a key the reader can't find. A
grep for any OTHER raw `"$Hostname|$app"` key consumer returned EMPTY: those three are the only
producers/consumers of that key, and all now use `Get-ReportsAuditHostKey`, so the key space is
uniform and no status is orphaned. Read-path change, no destructive path. GREEN.

## Correctness deep-dive: remediation-SLA aging math (Get-ReportsSlaDeadline + the bucket rule)

The SLA / Finding Aging dashboard and the RMF POA&M export drive real remediation prioritization and
compliance reporting, so the deadline + overdue math is worth verifying. It is CORRECT:
- **Baseline loader** (`Get-ReportsSlaBaseline`, `:954`): safe embedded defaults (KEV=7, Crit=21,
  High=30, Med=90, Low=180), overlays ONLY positive-integer overrides (`:969` `$n -gt 0`) so a
  zero/negative/typo window can never make everything instantly overdue; missing/empty/corrupt file
  falls back to defaults with a source note. Defensive by design.
- **Deadline** (`Get-ReportsSlaDeadline`, `:979`): KEV overrides severity with the tightest window;
  severity map with Info→Low and unknown→Medium. Clean.
- **Bucketing** (sla-aging `:6188`): `$today` is date-only (no time-of-day drift), age is
  `Floor(days)` clamped `>= 0`, `soon = Max(3, Ceil(0.25*window))`, OVERDUE at `dueIn < 0`, DUE-SOON
  at `dueIn <= soon`, ON-TRACK above. The deadline day itself (`dueIn == 0`) is DUE-SOON, not overdue
  — a defensible convention. Non-parseable firstSeen → NEW-UNTRACKED (safe). The ledger backfill
  keys on the normalized audit key, agreeing with the rest of the tool.

**The finding (durability, not a live bug) → FIXED**: the boundary rule was HAND-DUPLICATED across
the two operator-facing SLA views — the sla-aging dashboard (`:6188-6196`) and the Executive Command
Brief SLA section (`:7078-7085`). Both computed `dueIn`/`window`/`soon`/bucket with identical
arithmetic, so they agreed TODAY, but a future edit to one boundary (e.g. "make DUE-SOON 20%") would
silently diverge the two overdue counts for the same fleet — and none of it was unit-tested.
Consolidated into one pure helper `Get-ReportsSlaBucket -Deadline -Age` (`:992`, returns
`@{DueIn;Bucket;SoonThreshold;Window}`); both sites now call it. Behavior-identical (same formulas,
verified by the same-count suite), so **no version bump** — reports stays 2.14.24 (the manifest
version semantic here is a *behavioral* change; this is an internal single-source-of-truth
consolidation, and git records the code move).

`Reports.SlaBucket.Tests.ps1` (18) pins the helper at every edge: ON-TRACK/DUE-SOON/ON-TRACK
transitions around the threshold, the deadline-day boundary (`dueIn 0` = DUE-SOON, `-1` = OVERDUE),
the 3-day floor beating 25% on short KEV windows (7-day and 4-day windows both floor `soon` at 3),
the zero-deadline no-divide guard (window floors to 1), plus `Get-ReportsSlaDeadline`'s severity map
+ KEV override. The two dashboards can no longer drift.

## Correctness/security coverage — where it stands
Destructive surfaces reviewed + test-pinned (loops 1-16). Read-path correctness covers both CSV
front doors (loops 18-19), remediation routing (loop 17), host-count consistency incl. the completed
host-key sweep (loops 13-14, 20), and now the SLA aging boundary (this loop, single source of truth +
pinned). Remaining candidates: the `.nessus` XML parse branch of Parse-AcasFile, the KEV catalog
read/flag path, a fresh wpt deep-dive, or SECRET-parity execution.

## SECRET parity
- SECRET parity: the Get-ReportsSlaBucket consolidation — the JanetSec reports fork has the same two
  duplicated SLA bucketing blocks; extract the same helper + mirror the test so its two SLA views
  can't drift either.
- Carried (unexecuted): all prior SECRET-parity items (Build-RemediationPlan host-key fold, reports
  wrong-template hint, acas CSV-ingestion + match-table routing tests, and everything earlier).
