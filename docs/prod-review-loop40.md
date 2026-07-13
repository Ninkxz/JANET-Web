# Production Review - Loop 40 (Phase 2 consolidated audit) - 2026-07-14

Capstone adversarial audit of the cumulative new remediation code shipped across loops 30-39 (spec-exec,
BitLocker GPO, winupgrade install-updates, the 7-tool self-guard fix, WPT Custom Command guard, the CSV
neutralizer, and the loop-39 reports host-key collision guard). 3 reviewers: (A) reports host-key guard,
(B) CSV neutralizer + WPT Custom Command guard, (C) session-wide guard re-verification + suite.

**Rating: YELLOW.** No RED. The audit CAUGHT a P1-residual and a P2 in this session's OWN new code (exactly
its purpose) - both being fixed this cycle. Everything else HOLDS: every self-guard / confirm-word /
arg-order / fold intact (reviewer C, all 15 tools + modules), suite 987/987, no version/config drift, ledger
fixes match code. The WPT Custom Command RCE guard is SOUND (no bypass).

## P1-residual (reviewer A) - reports host-key collision guard is a NO-OP for short-name-only exports
`Get-ReportsHostKeyCollisions` (reports.psm1) `continue`s on any hostname WITHOUT a dot and only flags a
short key backed by >=2 DISTINCT dot-bearing FQDNs. So two distinct `WEB01`s exported as BARE short names
(the AFNET norm per MEMORY.md) produce an EMPTY collision set -> the loop-39 AMBIGUOUS guard never fires ->
`acas-apply-remediated` still flips `Status='Patched'` on the merged key. The original false-close is LIVE
for short-name exports. Even a mixed `WEB01` + `web01.eu.af.mil` pair is not flagged (only 1 FQDN in the
bucket). **The loop-39 fix protects the FQDN-bearing case only; row 36 was OVER-CLOSED.** The fix IS airtight
where it applies (additive, no false-reopen, no third unguarded auto-close, ordering correct, AMBIGUOUS never
leaks into a closed count - all confirmed). The real close is the IP-qualified collision signal (the scan IP
is in the raw data but discarded before reaching the finding). FIX THIS CYCLE.

## P2 (reviewer B) - WPT Software CSV export leaks Version + InstallDate raw
`WorkstationPatchingTool_6.5.29` Software export wraps Name+Publisher with Protect-CsvFormula but leaves
`Version` + `InstallDate` RAW - both from the remote registry Uninstall keys (attacker-controlled
DisplayVersion/InstallDate), a real formula-injection into an analyst's spreadsheet. A miss in the exact
export the loop-37 fix touched. FIX THIS CYCLE.

## P3 (fix the cheap ones, note the rest)
- (B) ReportsTool Dirty30 export writes `Hostname` RAW (5850) - the one outlier (every other ACAS export in
  the tool protects it). Attacker-influenceable scan hostname. FIX (1-line).
- (B) Shared `Write-AuditLog` / `Get-WptCsvEscape` (TouchedHosts CSV) + the usage-snapshot $esc neutralize
  NOTHING - pre-existing, predates loop-37, real (Excel-opened). Fold Protect-CsvFormula into the shared
  escape. FIX (WPT; ReportsTool/ADSearch inherit the same block).
- (A) F2: distinct-FQDN collision signal over-fires on a single host with 2 FQDN forms -> stuck-open (SAFE
  direction, never false-close). The IP-qualified key (P1 fix) also corrects this (use distinct IP).
- (A) F4: CORA closurePct + scan-closure-proof exclude AMBIGUOUS from the count -> can read 100% while one
  finding is unconfirmed. Surface an AMBIGUOUS count. Bundle with the P1 fix.
- (B) F2.4: ReportsTool ACAS exports write `PatchedBy` (operator-set) raw - low risk, wrap for consistency.
- (C) cosmetic: ledger row 26 narrative still says rows 11/17 "still CHECK/BLOCKED" - stale prose (they're
  CLOSED-WEB-ONLY). One-line doc fix.

## Fix plan
1. **P1 (Web, reports):** thread the scan IP through Parse-AcasFile/New-AcasFinding; extend
   Get-ReportsHostKeyCollisions (+ the compare/apply collision sets) to ALSO flag a short key backed by >=2
   distinct IPs; keep the FOLD untouched (still additive, still no false-reopen); surface AMBIGUOUS in
   CORA/proof (F4). Opus + comprehensive tests (short-name-only collision -> AMBIGUOUS; single host 2 FQDNs
   same IP -> NOT ambiguous [fixes F2]; anti-over-guard still closes non-collided). REOPEN row 36 first.
2. **P2 + P3 (Desktop CSV):** wrap Version/InstallDate (WPT Software) + Dirty30 Hostname (ReportsTool) +
   fold Protect-CsvFormula into Get-WptCsvEscape/usage-$esc + PatchedBy. Version-bump WPT + ReportsTool.
3. Ledger: reopen row 36 accurately, fix the row-26 cosmetic prose.
Web reports + Desktop CSV touch different trees - implement in parallel; I gate each, suite green.
