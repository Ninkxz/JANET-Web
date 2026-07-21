# JANET Web — review loop 22 (2026-07-21)

**Baseline:** 1192/1192 at loop-21 close (authoritative). Fable-inline + one parallel Fable worker.
Local-only commits.

## Self-review of loop-21 (`2a7ddfa` SLA-bucket consolidation, `68055a9` docs) — verdict GREEN (inline)
Byte-identical consolidation: both SLA views now delegate to `Get-ReportsSlaBucket`. Proven by the 18
boundary unit tests + the transitive PostureDigest integration test, suite held at the count. No
version bump (behavior-preserving), non-destructive read path. GREEN.

## Fresh deep-dive: wpt patch-VERIFICATION false-clean audit (parallel Fable worker)
wpt (the most-used tool, 480KB) had no loop-era deep-dive. While the loop-21 suite ran I spawned a
bounded Fable worker on ONE harm-relevant slice: can wpt report a host PATCHED/KB-INSTALLED when it
isn't (false-clean)? The worker mapped three "installed" paths (kb-scan Get-HotFix exact `-eq`;
verify-patch SCCM EvaluationState poll; kb-install MECM trigger + MSU fallback) and returned YELLOW
with evidence. I independently verified each finding in the code before acting.

**Fail-closed & correct (confirmed):** kb-scan's targeted verdict uses exact normalized `-eq`
(`KB5001` can't match `KB50011`); a failed Get-HotFix yields "Missing" (safe direction); verify-patch
maps a spent poll budget to Timeout not Installed; unreachable hosts counted separately; worker/session
errors land in Error→Failure. The WinRM/Get-HotFix spine is genuinely fail-closed.

**Confirmed false-cleans (4).** I fixed the crispest, most-contained, ripple-free one this loop and
ranked the rest (roadmap items 14-17) — the others touch operator-facing labels/audit semantics/view
and each deserves its own loop.

### FIXED this loop — kb-install loose KB-match (wrong-update bind) + null-ReturnValue fail-open
Evidence (`JanetWeb.wpt.psm1:2740`, pre-fix): `$_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace
'^KB','')`. The `-like "*$kb*"` leg is a substring on the update Name, so a requested `KB5034`
matches an update named `...(KB5034123)`: the WRONG update is added to `$found`, the real KB is marked
`handled` (`:2749`), and the MSU fallback is SKIPPED (`:2750`) — the requested vuln fix is never
applied AND an unintended update triggers, while the row can still read Installed. Also (`:2743`) a
`$null` `InstallUpdates` ReturnValue was counted as a successful trigger (fail-open).

Fix (wpt **6.8.5 → 6.8.6**): a canonical pure helper `Test-WptKbNameMatch` (`:2703`) — match
ArticleID EXACTLY (normalized), or the Name's KB token bounded by a non-digit lookahead
(`KB<num>(?!\d)`) so `KB5034` can't match `KB5034123`. The kb-install remote scriptblock mirrors it
inline as `$kbMatch` (it runs over WinRM and can't call a module fn; comment-linked to stay in
lockstep). And the trigger acceptance is now fail-closed: `$null -ne $rv -and [int]$rv -eq 0`
(a method that returned nothing is NOT a confirmed acceptance). No guard weakened — the DNS wrong-box
hard-abort (`:2726-2733`) and the reboot-enabled dispatcher self-guard (`:5983`) are untouched;
the change only TIGHTENS matching. All 117 wpt tests green post-change.

`Wpt.KbMatch.Tests.ps1` (11) pins the rule: the bug case (`KB5034` !~ `KB5034123` by Name AND by
article), exact-article match, Name-token match on a blank article, no cross-match to a different KB,
the non-digit boundary, short exact article, bare-numeric request, lowercase-kb normalization, empty
request → no match; + the exact 6.8.6 pin (SelfGuardApply 6.8.5 exact pin → `-ge` floor).

## Correctness/security coverage — where it stands
Destructive surfaces reviewed + test-pinned (loops 1-16, +wpt kb-match hardening this loop). Read-path
correctness covers both CSV front doors (18-19), routing (17), host counts + sweep (13-14, 20), SLA
boundary (21). wpt patch-verification now has a mapped false-clean audit: spine fail-closed, one
false-clean fixed, four ranked (items 14-17, #14 highest). Next candidates: item 14 (async-trigger
"Installed"/VulnPatched), item 15 (M365 mtime verify), or a wpt kb-scan/trend deep-dive.

## SECRET parity
- SECRET parity: the kb-install KB-match anchoring + null-rv fail-close — the JanetSec wpt fork shares
  `WptKbInstallBlock`; mirror `Test-WptKbNameMatch` + the inline `$kbMatch` + the fail-closed trigger.
- Carried (unexecuted): Get-ReportsSlaBucket consolidation, Build-RemediationPlan host-key fold,
  reports wrong-template hint, acas CSV-ingestion + match-table routing tests, and everything earlier.
