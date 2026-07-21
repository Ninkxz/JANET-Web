# JANET Web — review loop 33 (2026-07-21)

**Baseline:** 1282/1282 at loop-32 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-32 (`0eead54` Diagnose disk gate, `d8eb35b` docs) — verdict GREEN (inline)
Read-only verdict change (adds NOT READY for disk/RAM/Secure Boot fails, precedence otherwise
unchanged); 179 winupgrade + FixVerify3 green, higher-precedence verdicts intact. Authoritative
1282/0-fail. GREEN.

## Workstream (winupgrade deep-dive item 28, F3+F4) → FIXED: the CPU/TPM bypass value is now read-back-verified
Closing a confirmed backlog item rather than deep-diving a 5th tool. The Pin/Unpin TRV core already does
a genuine read-back verify (`$pinReadSb` + `$pinOk` "PIN NOT VERIFIED"), but the CPU/TPM **bypass**
(MoSetup `AllowUpgradesWithUnsupportedTPMOrCPU`) value was ASSERTED and never verified:
- Pin baked "CPU/TPM BYPASS SET" into the message at write time (`JanetWeb.winupgrade.psm1:984`) but
  `$pinOk` (`:1157`) checked only the TRV trio.
- Unpin appended "bypass key removed" (`:1250`) unconditionally after a `Remove-ItemProperty
  -EA SilentlyContinue`, and the read-back verify (`:1275-1290`) checked only the TRV trio — never the
  MoSetup value.
Scenario (Unpin, security-relevant): a restrictive MoSetup ACL / GPO re-write silently defeats the
removal → the row reports DONE "bypass key removed" while the Microsoft-unsupported bypass stays ARMED,
so the admin believes an unsupported-hardware host was returned to a supported stance when it wasn't.

**Fix** (winupgrade **0.5.3 → 0.5.4**), extending the module's OWN proven read-back gate:
- `$pinReadSb` (`:1076`) now also reads the MoSetup value → `BypassPresent`.
- Pin (`:1157`): when `$Bypass`, `$pinOk` additionally requires `BypassPresent` → else FAILED "BYPASS
  NOT VERIFIED".
- Unpin (`:1291`): when `$RemoveBypass`, the still-present set includes `MoSetup CPU/TPM bypass` if it
  read back present → else FAILED "NOT REMOVED ... bypass".
Fail-closed, additive: when bypass isn't requested nothing changes (the pre-existing Pin/Unpin tests are
untouched). No guard weakened. Full winupgrade + FixVerify2/3 set green.

`FixVerify2.Tests.ps1` FIX-2 extended (the existing Pin/Unpin read-back harness): `Invoke-PinWorker`
gains a `-Bypass` flag (positional arg 17) and `Invoke-UnpinWorker` a `-RemoveBypass` (arg 19), with
four new cases — Pin bypass-confirmed → DONE, Pin bypass-not-set → FAILED "BYPASS NOT VERIFIED", Unpin
bypass-gone → DONE, Unpin bypass-still-armed → FAILED — plus the exact 0.5.4 pin (DiagnoseVerdict 0.5.3
exact → floor).

## winupgrade false-clean status
Fixed: F1 (upgrade-drive pin-fail abort, loop 31), F6 (Diagnose disk gate, loop 32), F3+F4 (bypass
read-back, this loop). Remaining: 27 (F2, stale-staging reboots un-staged host — HIGH; the
classification runs in the remote PHASE:STAGED scriptblock, needs the staging classifier wired + a
feature-update-specific signal), 29 (F5, AutoFix premature FIXED — HIGH, multi-site remote), 31 (F7,
sfc unparseable→clean — LOW, a one-line fix in the pure `Get-WinUpgradeRepairVerdict`).

## SECRET parity
- SECRET parity: the winupgrade bypass read-back verify — mirror the `$pinReadSb` BypassPresent read +
  the Pin/Unpin verify to the JanetSec winupgrade fork if present.
- Carried (unexecuted): winupgrade upgrade-drive pin-fail abort + Diagnose disk gate; the c2c/acas/wpt
  remediation-honesty series; SLA bucket; host-key fold; wrong-template hint; CSV-ingestion + routing.
