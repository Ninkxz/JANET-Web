# JANET Web — review loop 84 (2026-07-22)

**Theme: informative failures** — remediating loop-83 regressions. Fable-inline + TWO Fable subagents (a loop-83
self-review + an acas deep-dive). Baseline: loop-83 authoritative **1564**.

## Self-review of loop-83 (the large shared-engine change) — **1 CRITICAL + 3 confirmed regressions, all fixed**
Loop 83 made a big change (AD signature, 6 numeric-boundary rewrites, 5 MSI signatures, c2c `$wasError`, upr
per-candidate wire). A Fable subagent executed the shipped code on PS 5.1 and found the 274-green run had masked
real regressions (the upr tests were static-only and never executed the closure):

- **P1 — CRITICAL: the upr per-candidate hint crashed the whole uninstall run.** `New-UprEmitRows` returns its
  emit block via `.GetNewClosure()` (`upr.psm1:1496`); that rebinds command resolution to global scope, where the
  nested-imported `Get-JanetTroubleshootHint` does NOT exist. My loop-83 per-candidate call inside that block threw
  `CommandNotFoundException` — terminating, no catch — aborting `Invoke-UprFanOut` at the FIRST failing candidate
  (all remaining hosts' rows + audits lost). Reproduced exactly. **Fix:** removed the hint call from the closure;
  moved it into `Invoke-UprFanOut`'s harvest loop (module scope, where the host-level hint already lives) — on a
  reached host, each Failure candidate's `Result` is hinted there. Verified: the closure no longer throws; the
  harvest resolves the engine. **A new BEHAVIORAL test invokes the closure with a Failure candidate and asserts no
  throw** — the test class that would have caught P1. upr 1.2.6 → 1.2.7.

- **P2 — trailing-dot regression.** loop-83's `(?![\d.])` on all six numeric codes rejected a **sentence-final
  period**: `The uninstaller failed with exit code 1603.` returned NO hint (the classic MSI phrasing). **Fix:**
  trailing `(?!\.?\d)` (block only a dot-then-digit version or a glued digit; allow a sentence period). Also
  leading `(?<![\dxX.])` to kill the **`0x1727` hex false-positive** loop-83's `\b`→lookbehind change introduced
  (`\b1727\b` didn't match `0x1727`; `(?<![\d.])` did). Verified: `exit 1603.` / `1722.` / `1605.` hint again;
  `16.0.1603` and `0x1727` / `0x1603` stay excluded.

- **P2 — c2c version-check session hints lost.** loop-83's `$wasError` scoping (pre-collapse ERROR only) was too
  narrow: the version-check worker maps **session/auth failures to OFFLINE** (`c2c.psm1:3293`), not ERROR, so
  `Session: Access is denied` / `The user name or password is incorrect` lost their hints — exactly the actionable
  cases the engine exists for. **Fix:** hint every error-level row EXCEPT the self-explanatory no-TCP offline
  (`$lvl -eq 'error' -and $row.Detail -notlike 'No TCP on*'`). Restores the session/worker-error hints while still
  excluding the "No TCP on 5985/5986/445" detail (the loop-83 intent). c2c 1.15.11 → 1.15.12.

- **P3 — AD signature still missed "could not be resolved".** loop-83's commit claimed the AD signature caught the
  "SID could not be resolved in Active Directory" phrasing; it did NOT (the phrase list had found/exist/was-not-
  found, not "resolved"), so it leaked to the DNS hint. **Fix:** added `could not be resolved` to both AD
  alternatives. Verified: the SID phrasing now routes to the AD hint; generic "server name could not be resolved"
  (no "in Active Directory") still routes to DNS.

## acas deep-dive (workstream discovery) — F1 REFUTED, F2 deferred
The acas subagent's headline **F1** (kb-install `[int](Get-AcasMarker …)` crashes on marker-less rows because
`[int]''` throws) is **REFUTED**: I verified on PS 5.1 that `[int]''` returns **0**, not a throw (only whitespace/
non-numeric throw, which the integer markers never are). A marker-less FAIL row correctly yields MECM=0/MSU=0/
Skipped=0. Good that I verified before acting — the agent was wrong here.
**F2 (real, deferred):** a successful Oracle-Java removal (`fix-java`) is misbooked — post-version reads
`'not installed'`, which `Get-AcasBumpVerdict`'s degraded-sentinel list rewrites to UNCONFIRMED → audited
VulnPatched **Failure** for a genuine removal (`acas.psm1:2118-2124`). The clean fix is a profile-intent flag
(`PostRemovedOk`) gating the degrade — but it touches the delicate bump-verdict core the Chrome false-clean guard
depends on, so it deserves its OWN careful loop rather than riding this crowded remediation loop. **Tracked as a
ranked backlog item.** (The acas Chrome always-OK chip is confirmed CLOSED; a residual mtime-only verify cousin in
`New-AcasClientVerify` + a kb-install wrong-box-guard parity gap were also noted — backlog.)

## Tests
Troubleshoot.Hint (+trailing-dot, +hex-exclusion, +AD "resolved"), Upr.VerifyResult (behavioral closure no-throw +
harvest-wire static, pin 1.2.7), C2c.AuditResult (predicate + pin 1.15.12). **loop-37 lesson:** engine change is
shared — ran engine + all consumers + upr.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the upr-fork P1 fix (move the per-candidate hint out of the
  GetNewClosure'd block into the harvest), (b) the troubleshoot `(?<![\dxX.])…(?!\.?\d)` boundaries + the AD
  "could not be resolved" phrasing, (c) the c2c-fork version-check no-TCP-exclusion predicate. **These correct the
  loop-70..83 parity items already tracked — do NOT mirror the loop-83 forms; mirror the loop-84-corrected ones.**
