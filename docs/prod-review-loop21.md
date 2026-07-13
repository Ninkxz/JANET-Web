# Production Review - Loop 21 (Phase 2, cycle 19) - 2026-07-13

Value pick (design-loop21.md): the deep CORRECTNESS lens - now 4-for-4 - applied to `reports` (7236
lines, v2.14.16), the last large complex tool (POA&M / IAVM / closure / campaign / Dirty30 / posture).
reports is READ-ONLY (lower blast radius) and already the most-tested tool (11 files), so the reviewer was
told to hunt the gaps those tests MISS, not re-report surface. One Opus reviewer. Every P1/P2
spot-verified by me. Both backlogs operator-deferred; reports is committed (non-colliding).

**Rating: YELLOW -> GREEN after fix.** Routing, IAVM/KEV mapping, burndown math, severity parsing, and
the manual-attestation guard all VERIFIED CORRECT. One P1 closure false-positive fixed. Suite 878/878.

## P1 FIXED - campaign-verify false-closed an UNSCANNED host (commit 7e65664)
The single worst outcome for a read-only compliance tool: a still-open vulnerability silently disappears.
`campaign-verify` (`:5321-5367`) built `$openNow`/`$attestedNow` only from findings PRESENT in the fresh
scan, then treated a campaign key in NEITHER set as "physically absent = scan-confirmed REMEDIATED"
(`:5345`). But absent also means the host was NOT SCANNED this pass (offline during the scan window, or a
scoped/subset export). So a still-open vuln on an unscanned host was counted remediated, and if it was
the last outstanding key the campaign flipped to `verified-closed` and was PERSISTED to the campaign JSON
- dropping the vuln off compliance with a "🎉". The only guard was zero-findings-loaded (`:5309`), which
does not catch a SUBSET scan. *Spot-verified against the code: the `else` branch counts remediated
regardless of host presence; `:5366` -> verified-closed; `:5371-73` persists. Also verified
`scan-closure-proof` shares the baseline-only=remediated model but is self-mitigating (audit-touched
split), while campaign-verify is the one that persists a closed verdict with no such check.*
**Fix:** build `$hostsPresent` (host keys actually in the fresh scan); a campaign key whose host is
absent -> a new **NOT-SCANNED** state - a visible row, counted separately, NEVER scored remediated, and
`verified-closed` now additionally requires `notScanned==0`. Surfaced in the summary/audit/banner. reports
2.14.16 -> 2.14.17. Tests: Reports.Campaign V1/V2 corrected (their fresh scans now include the campaign
hosts - the old scans encoded the false-closure assumption) + new V3 (absent host -> NOT-SCANNED /
in-progress, never verified-closed).

## P2 documented (not fixed - needs its own cycle) - host-key different-domain collision
`Get-ReportsAuditHostKey` (`:1571`) folds any non-IP name to its pre-dot short name upper-cased
(`web01.us.af.mil` and `web01.eu.af.mil` -> `WEB01`). This is a DELIBERATE FQDN/short fold (so `HOST1`
and `host1.dom` match), but two physically distinct boxes sharing a short NetBIOS name across
domains/bases collide - which can compound the closure logic. A correct fix (prefer IP discriminator, or
fold the first two labels) changes the key model used across closure/compare/campaign and needs its own
cycle + full test sweep. Documented; ledger row.

## P3 documented - Build-CoraSummary counts unique hosts by RAW name
`Build-CoraSummary` (`:2228,:2257`) keys unique hosts on the raw `$f.Hostname`, so a mixed FQDN/short
export double-counts a host (inflated UniqueHosts, deflated VPH). Everywhere else uses
`Get-ReportsAuditHostKey` or an OrdinalIgnoreCase set. Shifts denominators only, not closure decisions;
cheap fix (normalize the key) deferred as low-value.

## Verified CORRECT (deep) - no action
- **KEV flagging / IAVM mapping**: CVE regex + dedupe correct; an unmapped CVE still counts (IAVA blank,
  never dropped); no CVE->wrong-IAVA.
- **Burndown math**: ISO-8601 sort with file-order tiebreaker (earliest/latest correct); pctClosed over
  the first-snapshot denominator; deltas first-vs-last. No off-by-one / wrong denominator.
- **Scan-compare set logic**: REMEDIATED/STILL-OPEN/NEW are correct set differences (given the key model).
- **Manual-attestation guard**: a hand-flagged Patched finding is attested (not scan-confirmed) and blocks
  verified-closed - the conservative direction.
- **Routing**: correct destinations (Chrome/Edge/Office/Defender/Apache/Unquoted -> acas; KB -> wpt; NOT
  OUR PATCH -> upr; Exception -> non-actionable POA&M); export/row totals reconcile.
- **Severity parsing**: numeric 0-4 + text prefixes; Dirty30 `10C+10H+4M+1L` invariant with correct
  confidence tiers.

## Verdict
reports' compliance math is sound; the one real defect - a false closure that could hide an open vuln -
is fixed and regression-locked. The deep-correctness lens is now 4-for-4 across the big tools (c2c, acas,
wpt, reports). Ledger rows 35-37 (Desktop ReportsTool deferred). Suite 878/878.
