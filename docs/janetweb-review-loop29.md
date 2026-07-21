# JANET Web — review loop 29 (2026-07-21)

**Baseline:** 1252/1252 at loop-28 close (authoritative, 0 fail). Fable-inline + one parallel Fable
worker. Local-only commits.

## Self-review of loop-28 (`b672a2e` schedule-reboot TouchHost audit, `f4dfede` docs) — verdict GREEN
One-line audit-action demotion; the 194-test acas + FixGuards + Server.Gate run confirmed the
self-guard, DNS wrong-box abort, and admin gate intact. Authoritative 1252/0-fail. GREEN.

## Fresh deep-dive: c2c (C2C Nemesis) compliance false-cleans (parallel Fable worker)
Diversified off wpt/acas (7 loops) to c2c, a COMPLIANCE-readiness tool never loop-era deep-dived — for
a compliance tool a false "compliant" is the highest-stakes false-clean (it feeds an up-chain posture).
A bounded Fable worker read all 3,344 lines; I verified findings in-code. **Scan verdict is fail-closed**
(ERROR/unknown pillar → CHECK ERRORS never READY; OFFLINE/error never in the READY count; both firewall
parsers fail closed; the durability trio — expiry guard + fresh-handle persistence re-verify +
NOT-VERIFIED — is correctly implemented). But the **fix roll-ups and the import summary produce real
false-compliants**: 6 CONFIRMED.

### FIXED this loop — F4: import counts unknown compliance states as Compliant
Evidence (`JanetWeb.c2c.psm1:2499-2500`, pre-fix): `$nonCompliant = count(^Non-?Compliant);
$compliant = $total - $nonCompliant`. So a Tanium row whose Compliance cell is "Not Assessed" / "Error"
/ "Unknown" (kept verbatim on import) is counted **Compliant** in "Imported N host(s): X Compliant, Y
Non-Compliant" — the number most likely quoted up-chain. A compliance tool must fail closed: unknown ≠
compliant.

**Fix** (c2c **1.15.2 → 1.15.3**): count Compliant ONLY on an explicit `^Compliant` match; unknown
states land in a new `other` bucket (`$other = total - compliant - nonCompliant`), surfaced in the
import log (`, N unknown/other`) and the summary hash. Read-only import path — no destructive fan-out
touched. The pre-existing `C2c.ImportAndFix` compliant=1/nonCompliant=3 assertions are unchanged (its
rows are all explicit → other=0). `C2c.ImportCompliance.Tests.ps1` (7) drives the real import: an
unknown "Not Assessed" row lands in `other` not Compliant, the compliant count excludes it,
compliant+nonCompliant+other==total, an all-explicit CSV keeps other=0, + the exact 1.15.3 pin
(C2c.Enable 1.15.2 exact → floor).

### Ranked, not fixed (new items 22-26; F1/F2 are the high-harm next picks)
- **22 (F1, HIGH)** — fix host rollup masks a known-non-compliant SKIP pillar as FIXED/NO CHANGE
  (`:2333-2343`): SKIP only surfaces at host level when EVERY result is SKIP, so Firewall FIXED +
  Encryption SKIP ("route desk-side", definitely non-compliant) → host **FIXED** + `fixed++` + a
  VulnPatched Success audit. Fix: any SKIP alongside successes → a mixed/skip-aware status + tally.
- **23 (F2, HIGH)** — Patches fix reports a MECM trigger (KICKED) as fixed (`:2063-2068`, rolls up
  `:2333`/`:3060` as fixed + VulnPatched Success): the wpt/acas trigger!=done sibling, no post-fix
  re-verify. Fix: distinct TRIGGERED status excluded from the fixed count (or a delayed CCM re-check).
- **24 (F3)** — per-pillar fleet tally folds NOT VERIFIED / SKIP / IN PROGRESS into "nochange"
  (`:3059-3061`) and host-level NOT VERIFIED rows fit no summary bucket (`:3135-3145`), degrading the
  durability trio's loud signal to "nothing needed doing". Fix: dedicated skip/inprogress/notVerified
  buckets in both tallies.
- **25 (F5)** — Patches SCAN missing-data default reads compliant (`:873-876`): an applicable update
  with null Deadline AND null StartTime can never be overdue → PASS however old. Fix: no usable
  timestamp → count overdue (fail-closed) or downgrade to ERROR/advisory.
- **26 (F6)** — AntiMalware FIX: unknown signature age → "ALREADY PROTECTED" (`:1885`/`:1960`) while
  the SCAN treats the same unknown age as FAIL (`:802`). Fix: null age on the fix path → FAIL/UNVERIFIED,
  mirroring the scan. (Plus SPECULATIVE: scan PASSes a Disabled Defender for up to a week — deliberate
  TASKORD alignment per in-code comment, noted not ranked.)

## SECRET parity
- SECRET parity: the c2c import compliant-count honesty — the JanetSec c2c fork shares the import
  summary; mirror the explicit-^Compliant count + `other` bucket. (And items 22-26 when worked.)
- Carried (unexecuted): the whole acas + wpt remediation-honesty series, SLA bucket, host-key fold,
  wrong-template hint, CSV-ingestion + routing.
