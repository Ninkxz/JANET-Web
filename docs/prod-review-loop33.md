# Production Review - Loop 33 (Phase 2 audit) - 2026-07-13

Adversarial audit of THIS session's new code: spec-exec/BHI (WPT+ACAS Web+Desktop), the BitLocker
FVE-on-all-paths move, and the winupgrade `install-updates` SYSTEM-task / WMI-DCOM RCE surface
(Web+Desktop). 3 reviewers: (A) install-updates deep-dive, (B) spec-exec+BitLocker, (C) regression sweep.

**Rating: YELLOW.** No P1, no security hole - injection, fail-open, credential-leak, and self-guard
PLACEMENT all confirmed CLEAN; registry-write safety (no flat overwrite, escrow-first, fail-closed) solid;
regression sweep found ZERO weakened guards. But four real P2s in the cycle's own new code (one a
feature-breaker, three install-path robustness), all cheaply fixed this cycle.

## P2 findings (fixing this cycle)
1. **ACAS carve-out never applied to WEB (feature-breaker).** `acas.psm1:1449` still listed
   'Speculative Execution'/'Intel BHI'/'Spectre' in `$unpatchPatterns`, and `$classifyPlugin` returns
   Unpatchable BEFORE the match table - so the shipped `Spectre/BHI Mitigation - Enable` profile was
   UNREACHABLE on the ACAS auto-patch/preview path (only Desktop 1.10.15 got the carve-out; the Web
   implementation predated the Desktop recon that found the blocker). **FIXED** (carved out -> parity
   with Desktop; Meltdown/ZombieLoad/Oracle Database stay Unpatchable). The WPT manual action + manual
   ACAS profile-by-name were always reachable (separate dispatch).
2. **install-updates WMI/DCOM stale result.json race (Web+Desktop).** `Win32_Process.Create` is async;
   the worker polls `\\host\C$\...\result.json` immediately, and result.json is never cleaned up, so a
   PRIOR run's `Status=Installed` can be read as this run's success (false VulnPatched). WinRM path is
   immune (synchronous in-session delete). FIX: per-run nonce + COMPUTERNAME stamped into result.json;
   worker rejects any JSON whose nonce != this run's.
3. **install-updates no wrong-box / DNS-mismatch guard (Web+Desktop).** The sibling UpgradeDrive has an
   ExpectedName/LocalName guard; install-updates omits it, so a stale-DNS/reused-IP box could be
   patched + reported under the intended hostname. Mostly PILOT-PENDING to demo live. FIX: driver writes
   COMPUTERNAME; worker compares to the dialed short name (skip IP-literal targets), flags on mismatch.
4. **Desktop `Test-HostIsSelf` IP hole (Desktop-only self-install bypass).** `WindowsUpgradeTool_0.5.0`
   Test-HostIsSelf (3580) matches only loopback literals + shortname==COMPUTERNAME; it does NOT enumerate
   the host's own bound NIC IPs/FQDN like Web's `Get-WinUpgradeLocalIdentity` (383). Pasting the tool
   host's own IP as an install-updates target bypasses the self-guard -> installs on the operator's box.
   FIX: port the Web bound-IP/DNS identity set into the Desktop helper (keep fail-closed-on-throw).

## P3 findings
- WPT status string `FeatureSettingsOverride=0 / Mask=3` was leftover flat-write wording (`wpt:5700`).
  **FIXED** -> "OR the BHI bit 0x800000 ... Mask=3".
- JANET_WUA SYSTEM task + driver.ps1 + result.json left on every target (no cleanup) - latent SYSTEM
  exec primitive + the residue that makes P2#2 reachable. FIX: Unregister-ScheduledTask + remove files
  after harvest (Web+Desktop).
- `[int]$fso` cast unguarded on an exotic REG_SZ/QWORD type (`specfix.psm1:47`, `acas.psm1:391`) -
  fail-closed today (worker try/catch), robustness only. FIX: guard the cast.
- HTTPS SkipCACheck/CNCheck unconditional on the SSL dial (no operator toggle). Hardening; scoped to SSL
  only, Kerberos-bounded. Deferred/optional toggle.

## Clean (confirmed by A+B+C)
No command/script injection into the SYSTEM task or the base64 WMI bootstrap (only `#__INCLUDEMU__#` ->
$true/$false and pure-base64 `$driver64` are interpolated; hostname only ever a -ComputerName param / UNC
path, never a shell). No fail-open (Ok only for Installed/InstalledWithErrors/NoUpdates). No credential
leak (PSCredential only to -Credential; $authNote uses UserName only). Self-guard is before ALL transports.
Spec-exec: no flat write, no fail-open, self-guarded, sound DWORD verdicts. BitLocker move: escrow-first +
fail-closed intact, GPO-only writes can't weaken/brick an encrypted box. Regression sweep: all guards HOLD.
