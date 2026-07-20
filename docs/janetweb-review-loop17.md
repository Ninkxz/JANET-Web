# JANET Web — review loop 17 (2026-07-20)

**Baseline:** 1137/1137 at loop-16 close. Fable-inline. Local-only commits.

## Self-review of loop-16 (`fac190f` certdeploy prune-sync test) — verdict GREEN (inline)
Test-only, like-for-like `It`-block replacement strengthening the prune-allowlist sync
assertion (bidirectional set-equality). Verified 59/59 certdeploy suite; count unchanged. No
re-verify agent — test-only, no destructive code touched.

## Correctness deep-dive: acas remediation-ROUTING (Get-AcasVulnGroups) — verdict GREEN → coverage locked in

The acas match engine turns an ACAS finding's plugin name into the auto-patch profile(s). A
MIS-ROUTE is worse than a miscount — it applies the WRONG fix (or a no-op) to a real vuln.
Verified CORRECT with file:line evidence (`JanetWeb.acas.psm1:1642-1657`):
- **First-match-wins** — rules iterate in order, `break` on match; specific rules (Edge STIG,
  Unquoted Service Path, MSXML) sit ABOVE the generic ones so a specific finding matches them
  first.
- **Exclusion-before-keyword** — each rule's `Exclude` tokens are checked first
  (`IndexOf OrdinalIgnoreCase`); any hit `continue`s past the rule, so a look-alike never
  reaches the keyword match.
- The exclusions correctly stop the dangerous mis-routes: `Microsoft Edge WebView2` (Exclude
  'WebView') never → Edge browser updater; `Symantec Endpoint Protection` (Exclude 'Symantec')
  never → Windows Defender; `Chrome Remote Desktop` (Exclude 'Remote Desktop') never → Chrome;
  `Access Database Engine` / `LibreOffice` (Exclude those) never → M365.

**The gap (coverage, not correctness) → FIXED** (`bb9e9c2`, test-only, acas stays v1.11.5): the
routing itself was untested — only the individual profiles (Chrome/Edge/Java/SpecExec) were. A
future match-table edit (reorder, drop an Exclude) could silently reintroduce a mis-route with
nothing to catch it. `Acas.MatchTableRouting.Tests.ps1` (13) drives the real `Get-AcasVulnGroups`
router with synthetic findings: 4 POSITIVE routes (incl. specific-beats-generic) + 5 EXCLUSION
non-routes (the safety-critical half) + 4 structural "the Exclude list is present" assertions.

## Correctness/security coverage — where it stands
Both destructive surfaces are fully reviewed + test-pinned (loops 1-16). Correctness of the
operator-facing pipeline is now covered at two key points: host-count consistency (reports,
loops 13-14) and remediation-routing exclusions (acas, this loop). Remaining candidates:
CSV-ingestion robustness (quoted/embedded-comma fields, encoding, malformed-row handling — the
front of the offline/CSV-fed pipeline), the KEV/SLA-deadline math beyond host counts, or
SECRET-parity execution (operator sign-off).

## SECRET parity
- SECRET parity: the acas match-table routing test — the JanetSec acas fork shares
  `Get-AcasProfileMatchTable`/`Get-AcasVulnGroups`; mirror the routing + exclusion assertions.
- Carried (unexecuted): all prior SECRET-parity items.
