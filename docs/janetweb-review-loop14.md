# JANET Web — review loop 14 (2026-07-20)

**Baseline:** 1127/1127 at loop-13 close (`b9d73y5jv` authoritative run; tree test-unchanged).
Local-only commits. **First loop under the Fable-preferred / 15-min cadence** — the
self-review and this workstream were done inline by Fable (no Opus/Sonnet agents spawned).

## Self-review of loop-13 (`0331e66` adto RODC, `e0a5d51` reports host-key) — verdict GREEN (inline, Fable)

- **adto RODC (`0331e66`):** `PARTIAL_SECRETS_ACCOUNT` = 0x04000000 is the correct RODC bit;
  an RODC's UAC (WORKSTATION_TRUST 0x1000 + 0x04000000) trips the extended `$isDc` test. The
  adminCount fail-closed flip (`catch { $adminCount = 1 }`) only fires on an unparseable value
  (absent → "0" → 0, no throw → not refused), so no normal object is newly over-blocked.
- **reports host-key (`e0a5d51`):** the 5 headline count sites key on the normalized value; the
  one display side-effect — kb-needed's CSV per-host×KB export now shows normalized host keys
  (`WEB01`) instead of the raw FQDN — is **consistent with how CORA already presents hosts**,
  not a regression. Counts correct, no report structure changed.
No defects; nothing to fix from the self-review. (Loop 13 touched a destructive AD-write path;
its RODC change is a 2-line constant/condition addition, fully covered by the RODC PROTECTED
test + the unchanged existing adto suite — a heavy mechanical re-verify was not warranted.)

## Workstream: complete the reports host-key normalization sweep + IAVM CSV guard (`1c3cdb9`, reports 2.14.21→2.14.22)

Closes ranked items 11 + 12 — finishing the loop-13 correctness work so EVERY host tally in
the reports tool agrees with CORA's dedup.

**Item 11 — the tail count sites:**
- `remediation-refresh` app-aggregate (`:4776`) — `TargetCount`/`KevCount`/the affected-host
  list keyed on raw `$r.Hostname`; now normalized (a two-name host = 1). This was the
  "verify the planner ACTION path" note from loop 13 — confirmed it re-aggregates from
  `$plan.Rows` independently of the loop-13 Build-RemediationPlan fix, so it needed its own.
- `export-poam` per-host "Finding N" counter (`:6254`) — keyed normalized so two name forms
  share the sequence; the POA&M row's Host column keeps the RAW name (identifies the finding).
  The counter READ at `:6295` was aligned to the same key (else the number would read 0).

**Item 12 — IAVM-map CSV formula guard:** `Write-ReportsIavmMap` (`:872`) `$q` quote-wrapped but
omitted the `=+-@`/tab/CR prefix guard every other exporter carries. Added it (mirrors
`ConvertTo-ReportsCsvCell`).

Tests (`Reports.HostCountAgreement`): remediation-refresh per-app TargetCount == 1 for a
two-name host; an IAVM Title beginning `=` gets the `'` prefix; a clean Title is unchanged
(no over-escaping). Pester 1127→(post-change, see ledger) green.

## Reports correctness — now COMPLETE
With loops 13+14, all host counts across the reports tool (CORA, sla-aging, kb-needed,
posture-digest, command-brief, remediation-plan/refresh, export-poam) key on the same
`Get-ReportsAuditHostKey`, and every CSV exporter (incl. IAVM-map) carries the formula guard.
The loop-13 review's other findings were already CORRECT (KEV exact-match, div-by-zero,
Dirty-30, empty-KEV surfaced).

## SECRET parity
- SECRET parity: the reports host-key sweep tail (remediation-refresh/export-poam) + the IAVM
  CSV formula guard — the JanetSec reports fork shares `Get-ReportsAuditHostKey` and
  `Write-ReportsIavmMap`.
- Carried (unexecuted): all prior SECRET-parity items.
