# JANET Web — review loop 30 (2026-07-21)

**Baseline:** 1259/1259 at loop-29 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-29 (`a6aaa87` c2c import compliant-count, `a065857` docs) — verdict GREEN (inline)
Read-only import-count change (Compliant now an explicit `^Compliant` match, unknowns → `other`), the
full 243-test c2c set green, `C2c.ImportAndFix` compliant=1/nonCompliant=3 unchanged (all-explicit →
other=0). Authoritative 1259/0-fail. GREEN.

## Workstream (c2c deep-dive F5, item 25) → FIXED: Patches scan no longer PASSes an un-ageable missing update
The loop-29 c2c deep-dive found the scan verdict otherwise fail-closed except one hole: the Patches
pillar overdue predicate (`JanetWeb.c2c.psm1:873-876`, pre-fix):
```powershell
($_.Deadline -and ($_.Deadline -is [datetime]) -and ($_.Deadline -lt $now)) -or
((-not $_.Deadline) -and $_.StartTime -and ($_.StartTime -is [datetime]) -and ($_.StartTime -lt $now.AddDays(-$graceDays)))
```
An applicable-not-installed update (`ComplianceState=0` = MISSING) with null Deadline AND null StartTime
matches neither branch → counted "pending within grace" → pillar **PASS** however old the missing patch
is. A non-datetime Deadline (deserialize glitch) is worse: `$_.Deadline` is truthy so the first branch's
`-is [datetime]` fails AND the second branch's `(-not $_.Deadline)` is false — both skipped → not overdue.

Chose F5 over the HIGH-harm F1/F2/F3: those three are entangled (they share the fix-rollup host-status +
pillar-tally buckets; fixing one in isolation risks a half-fix — e.g. F2's KICKED needs F3's pending
bucket to not vanish), so they deserve a dedicated loop. F5 is independent and closes the last scan-side
false-compliant, keeping the readiness scan fully fail-closed.

**Fix** (c2c **1.15.3 → 1.15.4**): a pure canonical `Test-C2cUpdateOverdue` (`:622`) — a datetime
Deadline past now → overdue; else a datetime StartTime older than the grace window → overdue; else (no
usable timestamp on a MISSING update) → **overdue** (fail-closed: can't prove within grace, so don't
silently PASS). This also fixes the non-datetime-Deadline case (now falls through to StartTime instead of
skipping both). The scan worker mirrors it inline (runs over WinRM in a module-less runspace — comment-
linked). Read-only scan path — no destructive fan-out touched. Full c2c set green.

`C2c.PatchOverdue.Tests.ps1` (10) pins the rule: deadline past/future, no-deadline StartTime in/out of
grace, and the **fail-closed cases** (no-timestamp → overdue, non-datetime-Deadline → overdue, non-
datetime-Deadline + usable-old-StartTime → overdue) + a static mirror assert + the exact 1.15.4 pin
(ImportCompliance 1.15.3 exact → floor).

## c2c false-compliant status
Scan verdict now FULLY fail-closed (the F5 hole was the last one — the rest was already verified honest
in loop 29). Remaining are the fix-side + import roll-up items: 22 (F1, SKIP-masked FIXED host), 23 (F2,
Patches trigger-as-fixed), 24 (F3, NOT-VERIFIED→nochange tally), 26 (F6, AntiMalware fix unknown-age).
Items 22/23/24 are the entangled fix-rollup cluster — a good candidate for a dedicated loop that fixes
the tally buckets holistically.

## SECRET parity
- SECRET parity: the c2c Patches overdue fail-close — the JanetSec c2c fork shares the Patches scan;
  mirror `Test-C2cUpdateOverdue` + the inline fail-closed predicate.
- Carried (unexecuted): c2c import compliant-count honesty; the acas + wpt remediation-honesty series;
  SLA bucket; host-key fold; wrong-template hint; CSV-ingestion + routing.
