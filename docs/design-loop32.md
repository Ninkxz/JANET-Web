# Design - Loop 32 - Windows Upgrade tool: OS Version audit rule + HTTPS fleet-update installer

Operator request: (1) the Windows Upgrade scan must obey an **Audit Rule - OS Version** (pass/fail, never
partial), and (2) add the **HTTPS installer** (`X:\References\HTTPS_Installer.ps1`) as a **clickable action**.
Both land in Web `JanetWeb.winupgrade.psm1` (+ view) and Desktop `WindowsUpgradeTool` (versioned).

## Feature 1 - OS Version Audit Rule (read-only, PASS/FAIL)
Audit rules cannot be "partial" - a host is compliant only if ALL THREE checks pass:
1. **Generation = Windows 11** - CurrentBuild >= 22000.
2. **Release ID >= 24H2** - CurrentBuild >= 26100 (24H2=26100, 25H2=26200; build is the reliable signal,
   DisplayVersion/ReleaseId as a display backstop). Newer (25H2+) passes.
3. **Edition = Enterprise** - `EditionID -eq 'Enterprise'` EXACT. Pro / Education / Home / Enterprise
   multi-session / IoT Enterprise all FAIL (operator: exclude multi-session unless told otherwise).

New action `os-audit` (read-only, self-inclusive - it's a scan). Per host over the tool's existing SSL-first
Invoke-Command: read CurrentBuild/UBR + DisplayVersion + EditionID/ProductName. Emit per-host row:
`Host, Online, Generation, ReleaseId, Edition, Gen11(PASS/FAIL), Rel24H2(PASS/FAIL), EntEdition(PASS/FAIL),
Verdict(PASS/FAIL), Failed(which checks), Error`. Verdict = PASS iff all three; else FAIL with the failing
check list. Mirrors the C2C audit-tier pass/fail idiom (no partial state).

## Feature 2 - HTTPS Fleet-Update Installer (destructive, self-guarded, confirm-gated)
Port the engine of `HTTPS_Installer.ps1` as a new action `install-updates`. The reference's key insight:
WUA (Microsoft.Update.Session) blocks Download()/Install() under a remote/network logon token, so every
reliable path registers a **SYSTEM scheduled task** (`JANET_WUA`) that runs a WUA-COM **driver** locally,
writing `C:\ProgramData\JANET\WUA\result.json`; the tool polls that.

Transport cascade per host (stop on first success):
1. **WinRM HTTPS (5986)** - reuse the tool's existing `$useSsl` SSL-first PSSession (SkipCACheck/CNCheck).
2. **WinRM HTTP (5985)** fallback.
3. **WMI/DCOM (135)** fallback - `Win32_Process.Create` a bootstrap that writes the driver + registers the
   SYSTEM task, then poll `result.json` via the `\\host\C$` admin share.

Driver (ported verbatim from HTTPS_Installer.ps1 lines 47-128): search WSUS (ssDefault) and - when the
**Include Microsoft Update** option is on - also Windows Update + the MU catalog (catches Defender /
security-platform KBs WSUS/SCCM miss); AcceptEula; Download; Install; report Status / KBs / ResultCode /
RebootRequired. `#__INCLUDEMU__#` is replaced with $true/$false before send.

Inputs: `targets` (hostlist), `includeMU` (bool, default true), `allowHttp` (bool, default true),
`allowWmi` (bool, default true), `timeoutMin` (int, default 45), `threads`. Columns:
`Host, Online, Transport, Method, Status, KBs, Reboot, Error`.

**Safety (non-negotiable):** `destructive=$true` + a confirm string (installs updates; some force reboots).
**Self-guard**: drop `Test-WinUpgradeHostIsSelf` hosts BEFORE the fan-out (this INSTALLS + can REBOOT - it
must never hit the JANET console). Wrong-box DNS-mismatch abort where the tool already does it. This needs a
live domain/WSUS to truly validate - **document as pilot-pending**, never fake a success.

## Approach
- Web: one Opus agent adds both actions to `JanetWeb.winupgrade.psm1` + the `winupgrade.view.js` buttons,
  reusing the existing SSL-first Invoke-Command + `Test-WinUpgradeHostIsSelf`. Pester: os-audit verdict matrix
  (Win11+24H2+Ent=PASS; Pro / 23H2 / build<22000 each FAIL) + install-updates manifest/self-guard/confirm +
  a shimmed driver round-trip (NoUpdates / Installed / reboot). Version-bump winupgrade, full suite green.
- I gate every diff, spot-verify the self-guard + confirm + the audit verdict logic + the driver's
  ResultCode->Status mapping myself. Then mirror both into Desktop `WindowsUpgradeTool` (new versioned file).
- The HTTPS installer's WUA driver / SYSTEM-task registration is copied faithfully; no security logic invented.
