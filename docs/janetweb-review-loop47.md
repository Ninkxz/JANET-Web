# JANET Web — review loop 47 (2026-07-21)

Fable-inline. Self-review of loop-46 → **GREEN**. Baseline: loop-46 authoritative **1380** green (confirmed).

## Self-review of loop-46 (c2c sig-age null-coercion fail-close) — GREEN
Both scan (`:830`) + fix (`:1914`) now `elseif ($null -ne …AntivirusSignatureAge)`; a genuine 0-day age still
fires the elseif → 0 (correctly fresh), only a null age → stays `$null` (stale). `Get-C2cSigAgeHours` matches.
71 c2c + 1380 confirm no regression. Nothing to reopen.

## Workstream decision — item24 (F2) is view-coupled; take the definite item55 (F7) instead
Loops 44–46 *added* NOT VERIFIED verdicts (F1/F5), and F2/item24 (the per-pillar SUMMARY tally folds
NOT VERIFIED/SKIP into `nochange`) would have completed that honesty. But re-verifying it: the `perPillar` dict
(`:3128`, 3 buckets `{fixed, nochange, fail}`) is **returned in the run summary** (`:3215`) for the view, not
just the text line — adding a bucket needs view coordination (the item-24 nuance). So I closed the **definite,
contained** c2c audit-honesty bug instead.

## item55 (F7) — a PARTIAL host audits Failure, not a false VulnPatched Success
### Finding (CONFIRMED — re-verified in-code)
The audit emit (`:3135-3136`) mapped the run host Status → a VulnPatched result: `PARTIAL {'Success'}` with
itemCount 1. But the host rollup only reaches PARTIAL when `failed >= 1` (`:2362`) — a PARTIAL host **always has
≥1 pillar FAIL**. So a host still failing a pillar was booked VulnPatched **Success** in the audit ledger — a
false-compliance record an inspector would read as patched. Same audit-honesty class as loop-38 (reboot-selected
VulnPatched→TouchHost) and loop-44 (NOT VERIFIED→Failure).

### Fix (c2c 1.15.7 → 1.15.8)
New pure `Get-C2cHostAuditResult(Status)`: FIXED → Success; NO CHANGE/SKIPPED/OFFLINE → Skipped; everything else
(PARTIAL, FAILED, NOT VERIFIED) → **Failure** (fail-closed default). The audit emit calls it (controller-side,
module loaded — no mirror needed), and only a fully-FIXED host counts as a patched item (`itemCount = if FIXED
{1} else {0}`, PARTIAL dropped). The row Detail + per-pillar tally keep the granular "N fixed" info; only the
host-level compliance record changed to honest.

### Version + tests
- `C2c.AuditResult.Tests.ps1` (NEW, 10): the pure result at every status (PARTIAL/FAILED/NOT VERIFIED → Failure,
  the fix; FIXED → Success; NO CHANGE/SKIPPED/OFFLINE → Skipped) + static asserts the old `PARTIAL {'Success'}`
  and the `FIXED -or PARTIAL` itemCount forms are gone; exact pin 1.15.8 (SigAge exact pin → floor).
- c2c audit/sig-age/run-all/import set **58** green — the RunAll + ImportAndFix fixtures that drive the audit
  emit pass unchanged (none asserted the old PARTIAL→Success); grep clean.

## Remaining c2c backlog (all low/read-only/speculative + the view-coupled cluster)
item54 (F4, fixer NOCHANGE on unknown age — LOW), item56 (F8, version ordinal fallback — read-only), item57
(F9, Firewall empty — speculative), and items 22/24 (F2/F6 — the view-coupled tally/rollup, needs a coordinated
view change). The c2c high-harm findings are now all closed (F1/F5/F3/F7) — **loop 48 should do a fresh dive on
an un-reviewed acting tool** (certdeploy/adto/remoteadmin) rather than grind this tail.

## SECRET parity
- **SECRET parity:** the JanetSec c2c fork shares the audit emit — mirror `Get-C2cHostAuditResult` (PARTIAL →
  Failure) and the FIXED-only itemCount.
