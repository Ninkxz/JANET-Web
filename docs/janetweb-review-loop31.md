# JANET Web — review loop 31 (2026-07-21)

**Baseline:** 1269/1269 at loop-30 close (authoritative, 0 fail). Fable-inline + one parallel Fable
worker. Local-only commits.

## Self-review of loop-30 (`acd78ad` c2c Patches overdue, `6c35352`/`39ed02a` docs) — verdict GREEN
Read-only scan-predicate fail-closed restructure; 253-test c2c set green, no destructive path. The
loop-30 authoritative landed at **1269** (not the 1266 I estimated — `C2c.PatchOverdue.Tests.ps1` is
10 tests; corrected in `39ed02a`). GREEN.

## Why diversify off c2c: the rest of the c2c deep-dive is entangled
The remaining c2c items (22 SKIP-masked FIXED, 23 trigger-as-fixed, 24 NOT-VERIFIED→nochange, 26
AntiMalware unknown-age) ALL route through the fix-rollup host-status + pillar-tally buckets — e.g. a
correct F6 fix returns an UNVERIFIED status that F3's tally then folds into "nochange". They're one
holistic bucket-taxonomy change deserving a dedicated loop, not a rushed pick (F4/F5 were the only
independent ones, both done). So loop 31 diversifies to a fresh tool.

## Fresh deep-dive: winupgrade false-cleans (parallel Fable worker)
winupgrade (feature-update pin/push/diagnose, v0.5.1) had no loop-era review. A bounded Fable worker
hunted "reports pinned/upgraded/on-target when it isn't"; I verified findings in-code. **Fail-closed &
honest (verified):** Pin/Unpin TRV core does a genuine read-back verify (unreadable → FAILED "PIN NOT
VERIFIED"); install-updates is nonce+hostname-gated, Ok only on driver-confirmed states, unreachable →
Unreachable/Timeout; every build compare is `[int]`/`[version]` (no ordinal), missing build → 0 → not-
on-target; unreachable/timeout/worker-error never fold into success; installcab 3010 → distinct NEEDS
REBOOT. But **7 CONFIRMED false-cleans** on upgrade-drive / AutoFix / Diagnose / the bypass companion.

### FIXED this loop — F1: upgrade-drive reported green "Pinned + triggered" on a FAILED pin
Evidence (`JanetWeb.winupgrade.psm1:2183-2187`, pre-fix): `catch { $pinOut = "pin error: ..."; 
$r.WasPinned = $false }` — and `$pinOut` was never referenced again; the flow proceeded to TRIGGER and
`:2282-2290` set `Status='STAGED'/'DRIVEN'`, `Ok=$true`, `Detail="Pinned + triggered..."`
unconditionally. Scenario: policy-write access-denied → row shows green DRIVEN "Pinned + triggered",
the pin error discarded, and — worse — WU was triggered UNPINNED, so the host can upgrade to the LATEST
feature update instead of the pinned target (the exact thing the pin prevents).

**Fix** (winupgrade **0.5.1 → 0.5.2**): after the pin, if `-not $r.WasPinned` → **abort the drive**
before the trigger: `Status='PIN FAILED'`, `Ok=$false`, `Detail` surfaces the pin error and states the
upgrade was NOT triggered. Fail-closed: no pin → no drive. No guard weakened (self-guard, DNS wrong-box,
confirm intact); 168 winupgrade + FixVerify3 tests green. `WinUpgrade.Drive.Tests.ps1` extended: the
proven `Invoke-DriveWorker` shim gains a `-PinThrows` flag (pin phase throws), and a new test asserts a
thrown pin → `PIN FAILED`, `WasPinned=$false`, `Ok=$false`, and NO TRIGGER/REBOOT call + the exact
0.5.2 pin.

### Ranked, not fixed (new items 27-31; F2/F5 are the high-harm next picks)
- **27 (F2, HIGH)** — upgrade-drive "STAGED" is contaminated by STALE staging + generic pending-reboot:
  the staged re-read (`:2215-2226`) sets staged on bare `Test-Path 'C:\$WINDOWS.~BT\Sources'` with NO
  staleness check, despite `Get-WinUpgradeStagingClass` existing. A rolled-back 24H2 attempt leaves ~BT
  → reports STAGED → with rebootWhenStaged REBOOTS the host (comes back on 23H2), weakening the "never
  reboot un-staged" invariant. Fix: apply the staging classifier + require a feature-update-specific
  signal before STAGED/reboot.
- **28 (F3+F4)** — the CPU/TPM bypass (MoSetup) value is ASSERTED but never read-back-verified: Pin
  bakes "CPU/TPM BYPASS SET" into the message (`:972-987`) but the read-back (`:1131`) checks only the
  TRV trio; Unpin appends "bypass key removed" (`:1218-1227`) unconditionally after a SilentlyContinue
  removal, read-back never covers MoSetup. Fix: extend `$pinReadSb` to the MoSetup value on both paths.
  (F8 SPECULATIVE rides here: ForceDiscovery/AutoFix policy re-writes the TRV pin with no read-back.)
- **29 (F5, HIGH)** — AutoFix marks fixes applied before confirming + mislabels all-failed as "NO
  CHANGES": `'repair'` added to `$fixes` BEFORE DISM/SFC run (`:2804`); a DISM exception still → FIXED
  "Applied: repair"; a needed driver-removal that fails → "NO CHANGES / no fixes necessary". Fix: add
  fix keys only on confirmed success, track failed-attempts into FAILED/PARTIAL, Ok=$false on any fail.
- **30 (F6)** — Diagnose verdict READY ignores disk/RAM/Secure Boot fails its own scan reported
  (`:2339-2343` tests only cpu/tpm/block/policy). Supported CPU/TPM + 10GB free → READY, upgrade fails
  on disk. Fix: fold `[FAIL] Disk` (at least) into the READY gate.
- **31 (F7, LOW)** — unparseable sfc output defaults to 'no violations' → CLEAN (`:668`/`:2606`);
  localized/truncated output reads clean, ExitCode never consulted. Fix: no-match → 'unknown', exclude
  from CLEAN.

## SECRET parity
- SECRET parity: the winupgrade upgrade-drive pin-fail abort — mirror to the JanetSec winupgrade fork
  if present.
- Carried (unexecuted): the c2c/acas/wpt remediation-honesty series; SLA bucket; host-key fold;
  wrong-template hint; CSV-ingestion + routing.
