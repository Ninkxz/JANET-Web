# JANET Web — review loop 24 (2026-07-21)

**Baseline:** 1212/1212 at loop-23 close (authoritative, 0 fail — also re-validated the loop-22
repair). Fable-inline. Local-only commits.

## Self-review of loop-23 (`c9b22d1` repair, `d5687e2` honest kb-install label, `c022457` docs) — GREEN
The item-14 fix was label/summary honesty (server `Get-WptKbInstallResult` + the view surfacing
`r.Result`), no guard touched. Prompted by the loop-22 glob-miss lesson, I grepped the WHOLE test
tree for anything asserting the old kb-install view behavior before trusting the wpt-only run; the
guard/behavior tests (Wpt.Guards, SelfGuardAndClean, SpecExec, FixVerify2) all pass, and the loop-23
authoritative suite landed 1212/0-fail. The null-fail-close now has its regression test. GREEN.

## Workstream (roadmap item 15, next wpt verify false-clean) → FIXED
The M365 Click-to-Run verify (`$script:M365C2RVerify`, both Force-Update and User-Visible profiles)
decided "Verified" from ONE signal: the `ClickToRun\Configuration` registry key's LastWriteTime
freshness (`< 7 days`). Evidence (`JanetWeb.wpt.psm1:854`, pre-fix):
`$verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }`. But C2R rewrites that
key on EVERY update attempt INCLUDING failures — the scriptblock even reads `$p.LastScenario` in its
Detail — so a failed Force Update (proxy/offline) bumps the mtime and reads **Verified=$true with the
old, still-vulnerable version**. A textbook false-clean on a verify path.

**Fix** (wpt **6.8.7 → 6.8.8**): a pure canonical helper `Get-WptC2rVerified -HasTimestamp -AgeDays
-ScenarioResult` (`:846`): `$null` when there's no timestamp; `$false` when stale (`>= 7 days`);
otherwise `$true` ONLY when the fresh key's `LastScenarioResult` matches `success`, else `$null`
(fresh-but-unknown never over-claims). The M365 verify scriptblock mirrors it inline (it runs remotely
via Invoke-Command, can't call a module fn — comment-linked to stay in lockstep) and now reads
`$p.LastScenarioResult`, surfacing it in Detail (`Scenario=..; Result=..`). So: fresh + Success →
Verified; fresh + Failure → NOT verified (the fix); stale → not verified; unknown → `$null`.

Read-only verify path — no destructive guard involved. All 134 wpt tests green post-change.

`Wpt.C2rVerify.Tests.ps1` (9) pins the verdict at every case (no-timestamp → `$null`, stale-despite-
Success → `$false`, fresh+Success → `$true`, **fresh+Failure → `$false`** the false-clean fix,
fresh+blank → `$null`, `SuccessRebootRequired` counts, case-insensitive) + a static assert the
scriptblock reads `LastScenarioResult` + the exact 6.8.8 pin (loop-23 KbInstallResult 6.8.7 exact →
`-ge` floor).

## wpt verify false-clean cluster — status
From the loop-22 deep-dive: spine fail-closed; #13 (KB-match) fixed loop 22; #14 (async trigger =
Installed) fixed loop 23; **#15 (M365 mtime verify) fixed this loop**. Remaining: #16 (Chrome/Edge
"Verified" = registry touched in 14 days, no version compare — the honest fix needs an expected-min-
version input or a "Recently updated" relabel) and #17 (verify-patch KB filter article-leg unanchored,
LOW) and the #14b audit-taxonomy follow-on. Two loops from a fully-honest wpt verify surface.

## SECRET parity
- SECRET parity: the honest M365 C2R verify — the JanetSec wpt fork shares `M365C2RVerify`; mirror
  `Get-WptC2rVerified` + the inline scenario-result gate + the test.
- Carried (unexecuted): honest kb-install label (loop 23), kb-install KB-match (loop 22),
  Get-ReportsSlaBucket, host-key fold, wrong-template hint, CSV-ingestion + routing tests, earlier.
