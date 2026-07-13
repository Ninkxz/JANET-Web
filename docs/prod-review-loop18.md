# Production Review - Loop 18 (Phase 2, cycle 16) - 2026-07-13

Value pick (design-loop18.md): a deep CORRECTNESS/LOGIC audit of `c2c` (3460 lines) - the largest, most
destructive tool - a lens not yet applied (prior passes cleared the injection/XSS/gating SURFACE). One
Opus reviewer, correctness-focused, with the TASKORD 26-0822 model as the oracle. Every finding
spot-verified by me against the code. Both real backlogs remain operator-deferred; c2c is committed
(non-colliding).

**Rating: YELLOW -> GREEN after fix.** ZERO P1 - the dangerous axes (verdict false-clear, wrong host
fixed, false success) are all VERIFIED CORRECT. One genuine P2 result-honesty bug fixed; one P3 audit-
count nit documented. Suite 869/869.

## P2 FIXED - Patches fix success ('KICKED') mis-rolled to "NO CHANGE" (commit 54f3432)
The Patches fixer emits `KICKED` on success (`:2035`, MECM SUM(113)+eval(108) triggered), but the
per-host status rollup (`:2292`) counted only `FIXED`/`STARTED`, so a lone successful `fix-patches` fell
through to host Status `NO CHANGE` -> JANET audit `Skipped`, itemCount=0 - while the sibling per-pillar
tally (`:3012`) already counted `KICKED` as fixed. The row + audit trail under-reported a real
security-state change on a QUARANTINE pillar's primary success path. Safe direction (never a false
success). *Spot-verified: :2035 emits KICKED; :2292 omits it; :2302 else->NO CHANGE; :3017 NO CHANGE->
Skipped/0; :3012 already counts KICKED.* Fix: add `KICKED` to the :2292 fixed-class filter, aligning it
with :3012. c2c 1.15.0->1.15.1; two version-pin assertions updated. No dedicated unit test - the rollup
lives in a bare-runspace fix-worker scriptblock (not safely extractable/callable offline); the change is
a one-token alignment with the already-shipping sibling tally.

## P3 documented (not fixed) - PARTIAL with no real fix audits as Success/1
A host with only `FAIL` + `NOCHANGE` (no fixed-class result) rolls up to `PARTIAL` (`:2300`), which the
audit map (`:3017-18`) counts as `Success`, itemCount=1 - a minor over-count of "VulnPatched successes".
The operator-facing row stays honest (shows PARTIAL + the FAIL). After the P2 fix the common PARTIAL case
(a real KICKED/FIXED + a FAIL) is correctly Success/1; only the all-non-fix PARTIAL over-counts. Low
impact; a tighter map would gate PARTIAL->Success on a fixed-class result being present. Left as-is.

## Verified CORRECT (deep, empirically) - no action
- **Verdict computation:** the reviewer ran `Get-C2cVerdict` against 14 scenarios. Tier map (`:597-609`)
  matches TASKORD 26-0822 EXACTLY (Firewall/AntiMalware/Patches/Encryption/Vuln=Quarantine;
  PkiRoots/OSVersion=Audit; Monitoring=Attest; AppWhitelist/Agents/COAMS=Info). No quarantine pillar
  mislabeled Audit/Info (**no dangerous false-clear**); precedence correct (quarantine FAIL + Tanium down
  -> QUARANTINE RISK, not NOT ATTESTING); unknown pillar defaults Quarantine (fail-safe); null/empty ->
  READY without throwing.
- **Pool-runspace source injection:** every worker enumerated - the scan pool injects+dot-sources
  VerdictSrc (the only Get-C2cVerdict call site is inside it); the fix pool injects Java/Tanium/WinrmHeal/
  AddCerts and correctly needs no VerdictSrc. No missing injection (the known gotcha is clean).
- **Per-pillar / run-all targeting:** OrdinalIgnoreCase HashSet allow-list re-derived from the CSV,
  intersected with submitted hosts; empty pillar set drops ALL (never "all"); run-all keys each host's
  pillars by its own short name - no cross-wiring. PillarFixTargets derived from RunAllPlan so they can't
  diverge.
- **Partial-failure honesty:** BitLocker emits per-volume results (FIXED+FAIL -> PARTIAL, never false
  FIXED); a FIXED host status requires failed==0; AMRunningMode guard is NOT inverted (RTP forced only
  when Active; Passive/EDR box left protected -> NOCHANGE, never force-RTP'd).
- **Import/dedupe:** dedupe keyed by upper short host (no cross-host merge); Non-Compliant checked before
  Compliant; unknown rules surface verbatim as Failed (never dropped).

## Verdict
c2c's core correctness is sound: the quarantine predictor cannot false-clear a host, the destructive
fixes target and report correctly, and the source-injection gotcha is clean. The one real defect (Patches
success under-reported) is fixed. Open work all operator-deferred. Ledger row 31 added (Desktop C2C twin
deferred).
