# JANET Web — review loop 80 (2026-07-21)

**Theme: informative failures** (loop 70) — follow-up phase. Fable-inline + a Fable adversarial subagent on
loop-79. Baseline: loop-79 authoritative **1538**.

## Self-review of loop-79 (shared-engine enrichment + restart delegation) — **4 CONFIRMED regressions, all fixed**
A Fable subagent reviewed commit `ae6d11cf8` by executing the committed functions on PS 5.1. It found — and I
reproduced — four real defects that a bare 210-green run had missed (they are wrong-hint routing, not crashes):

1. **Bare-numeric false positives** (`troubleshoot.psm1`). `1314\b` has only a RIGHT boundary and `1727` had
   none, so a coincidental substring false-matched:
   - `'Download failed for KB5031314: connection closed'` → privilege-not-held hint (WRONG).
   - `'copy failed after 172799 ms elapsed'` → RPC hint (WRONG).
   **Fix:** `\b1314\b`, `\b1727\b`, and the pre-existing `\b1722\b` (same class). Added the real 1314 HRESULT
   `0x80070522` (the fully-bounded token the bare numeral was trying to be).
2. **`could\s+not\s+be\s+found` over-broad** (`troubleshoot.psm1:48`) — a 10-consumer shared signature swallowing
   unrelated errors:
   - `'The specified module could not be found.'` (Win32 126) → DNS hint (WRONG).
   - `'The user name could not be found.'` → DNS hint (WRONG).
   **Fix:** narrowed to host-qualified `computer\b.{0,40}could\s+not\s+be\s+found`. The genuine
   `"The computer 'WS01' could not be found."` still routes to name-resolution.
3. **Delegation NOT behavior-preserving for restart rc = −1** (`restart.psm1`). rc −1 is restart's SYNTHETIC
   tool-side-timeout sentinel (`Detail='shutdown.exe timed out after 30s'`); the shared `timeout` signature
   shadowed its precise numeric hint and even suggested "raise the per-host timeout" — an option restart's
   hardcoded 30s `WaitForExit` doesn't expose. Fired on EVERY −1, contradicting loop-79's "behavior-preserving"
   claim. **Fix:** guard the delegation with `-and $Code -ne -1` (a real remote error on −3/−4 STILL delegates,
   verified).
4. **Factual mislabel: 1727 is RPC_S_CALL_FAILED_DNE, not "RPC_S_NO_MORE_ENDPOINTS"** (that phrase is error 1753,
   EPT_S_NOT_REGISTERED). loop-79 carried the wrong label from restart's original switch AND put a fabricated
   `RPC_S_NO_MORE_ENDPOINTS` token in the engine. **Fix:** corrected the label in both the engine hint text and
   restart's numeric switch; dropped the fake token; kept `\b1727\b` + the real 1753 "no more endpoints" text +
   `RPC_S_CALL_FAILED_DNE`. (The loop-79 test that asserted the fabricated token was corrected to the real ones.)

All four verified cleared empirically (the 4 collisions now return '', every real case still routes). restart
1.5.0-beta9 → **beta10**. `Troubleshoot.Hint.Tests.ps1` +6 (false-positive guards), `Restart.Guards.Tests.ps1`
+2 (rc −1 keeps its precise hint / −3 still delegates) + beta10 pin. **loop-37 lesson:** engine change is
shared — ran engine + restart + secureboot + all engine-consumer files (233) green.

## Workstream: wire the hint into a READ-ONLY scan path (secureboot scan CHECK ERROR)
The primary rollout wired DESTRUCTIVE harvests; an operator also hits "cannot be done" on a read-only scan.
secureboot's `Invoke-SbeScanAction` emits host-level **CHECK ERROR** rows carrying the raw probe/session/DNS
error in `$detail` (`"Session: <exc>"`, `"Probe: <exc>"`, `"worker error: <exc>"`, `"per-host timeout …"`).

### Fix (secureboot 1.6.5 → 1.6.6) — purely additive
In the scan `$emitResult`, on a host-level CHECK ERROR (`$verdict -eq 'CHECK ERROR' -and $hostStatus -ne 'OK'
-and $detail`), the raw `$detail` runs through `Get-JanetTroubleshootHint -Server $res.Computer` → a `Hint` row
field + a `FIX:` err log. Scoped to CHECK ERROR: OFFLINE and DNS MISMATCH already carry a complete actionable
detail, and the ambiguous-probe CHECK ERROR (`$hostStatus -eq 'OK'`) is a classifier note, not a remote error.
Every OK / OFFLINE / DNS MISMATCH / Cancelled row is byte-identical (Hint=''). secureboot already imports the
engine (loop 76).

### Tests
`Secureboot.Scan.Tests.ps1` +3 (static analysis — the scan harvest runs inside the fan-out over a real
RunspacePool): exact `1.6.6` pin; the CHECK-ERROR-only predicate computes the hint + the row carries `Hint`;
the err log is gated on `$hint` and carries `FIX:`. loop-76's 1.6.5 pin floored. Full secureboot suite (39) green.

## Rollout status (informative-failures theme)
Primary 9-tool wire COMPLETE (loops 70-78); restart mapper folded/delegated (79). Loop 80: **first read-only
scan path wired (secureboot)** + **loop-79 engine regressions fixed**. Remaining follow-ups: c2c scan/version
harvests, certdeploy check/scan CHECK ERROR rows, per-candidate upr failures, grow the signature set.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the loop-79 engine enrichment WITH the loop-80 corrections
  applied (bounded numerics, narrowed could-not-be-found, corrected 1727 label), (b) the restart-fork rc −1
  delegation guard + 1727-label fix, (c) the secureboot-fork scan CHECK ERROR hint wire. (Whole-engine mirror
  still pending, tracked since loop 70.)
