# =============================================================================
#  JanetWeb.winupgrade.psm1  -  Windows Upgrade tool engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from dev\WindowsUpgradeTool_0.1.0.ps1 (engine reused, WinForms layer
#  dropped). Drives Windows feature-update work across many hosts over WinRM,
#  fanned out in parallel with a per-host .NET ping pre-check and live streaming:
#
#    diagnose   - read-only 24H2 readiness + WU health scan (ported verbatim from
#                 the desktop $sbDiagnostic); one verdict row per host + the full
#                 colour-tagged report streamed to the activity log.
#    pin        - write the Windows Update for Business "Target Release Version"
#                 policy so a PC holds at a feature build (e.g. Windows 11 24H2)
#                 and is NOT offered a newer feature release until unpinned.
#                 v0.3.0 adds optional SCCM/MECM client refresh + CPU/TPM bypass.
#    unpin      - remove that policy so the PC tracks its normal update ring.
#                 v0.3.0 optionally also removes the CPU/TPM bypass key (default on).
#    forcediscovery - safe or aggressive WU reset + re-scan (ported verbatim from
#                 the desktop $sbForceDiscovery) for when 24H2 will not surface.
#    installcab - copy a feature-update .cab/.msu to C:\Temp on each target and
#                 install it with DISM /Online /Add-Package, optional reboot.
#    ping       - reachability sweep (latency or Unreachable).
#
#  v0.3.0: diagnose + forcediscovery ported verbatim from References\24h2script.ps1
#  (the desktop "24H2 Remote Helper"); pin/unpin gained the bypass + SCCM options.
#
#  v0.4.0: target-version parameterization (24H2 / 25H2 via $script:WinUpgradeTargets) -
#  fleet-status / diagnose / upgrade-drive take a 'version' input that threads MinBuild
#  into the worker (default 24H2 / 26100 keeps every existing behaviour identical), plus
#  three new actions ported from the desktop helper: repair-health (DISM /RestoreHealth +
#  sfc /scannow), auto-fix (per-device analyse-then-fix, ported from $sbAutoFix) and
#  error-report (read-only per-error row scan reusing the diagnose signature logic).
#
#  v0.5.1: install-updates audit hardening (Loop-33). The WUA driver now stamps a
#  per-run Nonce + Host=$env:COMPUTERNAME into EVERY result.json object; the worker
#  generates a fresh nonce, bakes it into the driver (#__NONCE__# placeholder), and
#  REJECTS any polled result.json whose nonce != this run's (kills the WMI/DCOM
#  stale-read race - keeps polling) or whose Host short-name != the dialed target
#  (-> explicit 'WrongBox' row, Ok=$false). result.json is deleted up front on BOTH
#  transports, and the JANET_WUA SYSTEM task + driver.ps1/result.json are removed
#  after harvest (best-effort; a cleanup failure never flips a real result).
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
#
#  Notes for the web (stateless) model vs the desktop tool:
#    - Per-host intermediate phases ("Copying...", "Installing...") are not
#      streamed; one final row per host is emitted on completion (suite parity
#      with the other modules' harvest loops). The progress bar tracks done/total.
#    - The CAB/MSU is taken as a path on THIS admin box (where the server runs),
#      mirroring the desktop Browse result; the worker copies it to each target.
#    - DISM can run for minutes, so installcab uses a long per-host watchdog.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'winupgrade'
        name     = 'Windows Upgrade'
        version  = '0.5.3'
        category = 'Remediation'
        summary  = 'Pin/unpin the Windows feature-update target version and push feature-update CAB/MSU packages (DISM) across many workstations in parallel. Two common jobs: the 24H2 UPGRADE (Pin to Windows 11 24H2, then let Windows Update / MECM install it) and the 25H2 UPDATE (Install the 25H2 enablement-package CAB; Unpin first if the fleet is pinned). Also diagnoses a failed in-place upgrade: Check Upgrade Errors reads setuperr.log and flags the out-of-memory build failure (0x8007000E), and Set Page File applies the fix (fixed 16 GB page file).'
        actions  = @(
            @{
                id          = 'diagnose'
                label       = 'Run Diagnostic Scan'
                description  = 'Read-only 24H2 readiness + Windows Update health + failed-upgrade forensics scan (changes NOTHING). Per host it checks CPU / TPM / Secure Boot / RAM / disk against the Windows 11 24H2 minimums, the Target Release Version policy (incl. a HALF-WRITTEN pin) + CPU/TPM bypass state, feature-update deferrals / pauses - distinguishing an EXPIRED (lingering) pause window from an active block - the WU service health, and SCCM client 24H2 deployment visibility. It also analyses a FAILED in-place upgrade: it reports C:\$WINDOWS.~BT staging size + age and flags STALE staging left by a rolled-back attempt (never mis-reads it as "in progress"), matches the current setuperr.log against a failure-signature table (registry-hive corrupt 0x000003F1, broken component store CBS_E_INVALID_PACKAGE / FOD-inventory, out-of-memory 0x8007000E, AD LDS adammigrate.dll, cancelled 0x800704C7), surfaces driver-injection failures with an ADVISORY (not blanket) read of DISM BootCritical (a non-boot-class or absent device is called a likely false positive), and reads SetupDiag results - only ever parsing the authoritative ~BT logs (older C:\Windows\Panther logs are labelled stale). Returns a one-word verdict: ON 24H2 (already build 26100+); HW INCOMPAT (unsupported CPU/TPM and no bypass set); BLOCKED (a deferral / pause is holding the feature update); NEEDS POLICY (Target Release Version not set or half-written); READY (all clear to Pin / Force Discovery). The full colour-coded report streams to the activity log; a diagnose that times out points at a wedged WU/WMI stack (winmgmt /verifyrepository).'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='version'; label='Target version'; type='select'; required=$false; default='24H2'; options=@('24H2','25H2'); help='Feature-update target the readiness gate checks against - 24H2 (build 26100+) or 25H2 (build 26200+). Default 24H2.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'fleet-status'
                label       = 'Fleet Status (24H2 board)'
                description  = 'Read-only fleet posture board for the 23H2 -> 24H2 journey (changes NOTHING). Runs the SAME per-host readiness scan as Run Diagnostic Scan across the targets and rolls each host up to a single Win24H2Status: Already 24H2+ (build 26100+); Pending reboot (a feature update is staged / the box is pending-reboot, i.e. mid-upgrade); Ready (on 23H2 / build 22631 or older AND CPU/TPM/disk all pass); Blocked: <reason> (on <=23H2 but a hardware check fails - CPU unsupported / no TPM 2.0 / disk <64GB, joined). Pinned is shown as a secondary flag with the pinned version. Returns per-host rows plus a rollup summary (already24h2 / ready / blocked / pendingReboot counts + block-reason breakdown). Read-only registry / CIM reads only - no policy writes, no reboots.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Online','DisplayVersion','OsBuild','FreeGB','Win24H2Status','Eligible','BlockReason','Pinned','PinnedVersion','PendingReboot','Error')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='version'; label='Target version'; type='select'; required=$false; default='24H2'; options=@('24H2','25H2'); help='Feature-update target the board rolls up against - 24H2 (build 26100+) or 25H2 (build 26200+). Default 24H2. The Win24H2Status column reads "Already <version>+" for the chosen target.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'os-audit'
                label       = 'OS Version Audit'
                description  = 'Read-only OS Version audit rule (changes NOTHING; self-inclusive - it is a scan). Per host it reads CurrentBuild / UBR / DisplayVersion (ReleaseId backstop) / EditionID / ProductName from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion over the tool''s SSL-first WinRM, then computes THREE pass/fail checks with NO partial state: Gen11 = Windows 11 (CurrentBuild >= 22000); Rel24H2 = release 24H2 or newer (CurrentBuild >= 26100; 25H2=26200 and newer PASS); EntEdition = EditionID EXACTLY ''Enterprise'' (Pro / Education / Home / Enterprise multi-session / IoT all FAIL). Verdict = PASS only if ALL THREE pass, else FAIL with the failing-check list. Mirrors the C2C audit-tier pass/fail idiom.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Online','Generation','ReleaseId','Edition','Gen11','Rel24H2','EntEdition','Verdict','Failed','Error')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'install-updates'
                label       = 'Install Windows Updates (SYSTEM task)'
                description  = 'PILOT-PENDING (needs a live domain / WSUS ring to truly validate - never fakes a success row). Install ALL available Windows Updates on each target by registering a JANET_WUA scheduled task that runs a Windows Update Agent (Microsoft.Update.Session) driver as NT AUTHORITY\SYSTEM - the only context in which WUA reliably Download()/Install()s (a remote/network logon token blocks it). The driver searches WSUS (ssDefault) and - when Include Microsoft Update is on - also Windows Update + the Microsoft Update catalog (catches Defender / security-platform KBs WSUS/SCCM miss), AcceptEula, Download, Install, then writes C:\ProgramData\JANET\WUA\result.json which the tool polls. Transport cascade per host, stopping on first success: (1) WinRM HTTPS 5986, (2) WinRM HTTP 5985 (if allowed), (3) WMI/DCOM 135 (if allowed, via Win32_Process.Create + result.json over \\host\C$). SELF-GUARDED: the JANET dispatcher host is dropped BEFORE fan-out (this INSTALLS and some updates force a REBOOT - it must never hit the JANET console).'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Install ALL available Windows Updates on the target(s) via a SYSTEM scheduled task (WSUS + optionally Microsoft Update)? This INSTALLS updates and some will force a REBOOT. The dispatcher host is skipped. Proceed?'
                columns      = @('Host','Online','Transport','Method','Status','KBs','Reboot','Error')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='includeMU'; label='Also search Windows Update + Microsoft Update (Defender / security-platform KBs)'; type='bool'; required=$false; default=$true; help='On: the driver also queries Windows Update and the Microsoft Update catalog (GUID 7971f918-a847-4430-9279-4a52d1efe18d), catching Defender / security-platform updates WSUS/SCCM does not carry. Off: WSUS/SCCM source only.' },
                    @{ name='allowHttp'; label='Allow WinRM HTTP (5985) fallback'; type='bool'; required=$false; default=$true; help='If WinRM HTTPS (5986) does not connect, fall back to plain WinRM HTTP on 5985.' },
                    @{ name='allowWmi'; label='Allow WMI/DCOM (135) fallback'; type='bool'; required=$false; default=$true; help='If neither WinRM transport connects, bootstrap the SYSTEM task over WMI/DCOM (Win32_Process.Create) and poll result.json via the \\host\C$ admin share.' },
                    @{ name='timeoutMin'; label='Per-host timeout (minutes)'; type='int'; required=$false; default=45; help='How long to poll result.json for the SYSTEM task to finish before giving up on a host. Default 45.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes - reports what WOULD happen)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'pin'
                label       = 'Pin Feature Version'
                description  = '24H2 UPGRADE job: hold targets at a feature version (Windows Update for Business Target Release Version policy) - e.g. Product "Windows 11", Version "24H2". WU keeps offering monthly quality fixes but will NOT move the PC to a newer feature build until you Unpin. Pin sets a CEILING; it does not push the install - each PC moves on its next Windows Update / MECM check (a reboot + Check for updates applies it promptly).'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Write the Windows Update for Business Target Release Version policy to HOLD the selected host(s) at the Product / Version entered above (e.g. Windows 11 24H2) - they will NOT move to a newer feature build until you Unpin. If "Apply CPU/TPM bypass for unsupported hardware (MoSetup)" is ticked, this ALSO writes HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU = 1, a Microsoft-unsupported configuration. A Dry-run writes nothing. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='product'; label='Product';  type='text'; required=$true; default='Windows 11'; help='Windows Update for Business ProductVersion value, e.g. "Windows 11". This is the gpedit "Select the Target Feature Update" Product field.' },
                    @{ name='version'; label='Version';  type='text'; required=$true; default='24H2'; help='TargetReleaseVersionInfo value, e.g. "24H2" - the build to hold at. This is the gpedit "Select the Target Feature Update" Target Version field.' },
                    @{ name='runWu'; label='Also trigger a Windows Update scan after pinning'; type='bool'; required=$false; default=$false; help='After writing the policy, kick the Windows Update agent (the built-in Scheduled Start task) so the pinned build is detected and offered sooner - the "then run Windows Update" step of the manual gpedit procedure.' },
                    @{ name='sccmRefresh'; label='Also refresh the SCCM / MECM client (pull policy so Software Center updates)'; type='bool'; required=$false; default=$false; help='After the policy write (and after the optional WU scan) trigger the SCCM client schedule cycles (Machine Policy / Software Updates Deployment Evaluation, etc.) so an assigned Software Center 24H2 deployment surfaces without waiting for the next machine-policy cycle.' },
                    @{ name='bypass'; label='Apply CPU/TPM bypass for unsupported hardware (MoSetup)'; type='bool'; required=$false; default=$false; help='WARNING: sets HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU = 1 so a PC with an unsupported CPU / TPM can take the 24H2 feature update. This is a Microsoft-unsupported configuration; such devices may not receive all future updates.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'unpin'
                label       = 'Unpin (remove hold)'
                description  = 'Remove the Target Release Version policy so the PC follows its normal Windows Update path again and can move to newer feature builds. Use this to reverse a Pin - e.g. run Unpin FIRST before pushing the 25H2 update to a fleet that was pinned to 24H2 (keeps the WU policy consistent; DISM installs regardless of the pin).'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Remove the Target Release Version pin from the selected host(s) so they follow normal Windows Update again and can move to newer feature builds. If "Also remove the CPU/TPM bypass key (MoSetup)" is ticked, this also deletes HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU, returning the device to a supported-hardware-only stance. A Dry-run writes nothing. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='removeBypass'; label='Also remove the CPU/TPM bypass key (MoSetup)'; type='bool'; required=$false; default=$true; help='Also delete HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU (the CPU/TPM upgrade bypass) when unpinning, returning the device to a supported-hardware-only stance. On by default so an Unpin fully reverses a bypassed Pin.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'forcediscovery'
                label       = 'Force Update Discovery'
                description  = 'Force targets to re-check for the pinned feature update when 24H2 still does not appear after Pin. Safe mode (default) re-applies the Target Release Version policy, reports (does NOT remove) any deferrals / pauses, triggers the SCCM client cycles, runs gpupdate /force /target:computer, and kicks a Windows Update scan (DetectNow + UsoClient StartScan). Aggressive mode ALSO removes the deferral / pause policy values, STOPS the WU services, renames SoftwareDistribution + catroot2, re-registers the Windows Update DLLs, restarts the services, re-applies the policy and re-scans - a full WU cache reset. Use aggressive only if safe mode does not resolve. Emits one verdict row per host and streams the full step-by-step log to the activity log.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Force update discovery on these targets. Safe mode re-applies the target-release policy and triggers SCCM / GPO / Windows Update scans. If "Aggressive mode" is ticked and this is NOT a Dry-run, each target will STOP the Windows Update services, RENAME SoftwareDistribution + catroot2, and RE-REGISTER the Windows Update DLLs (a full WU cache reset). Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='product'; label='Product'; type='text'; required=$true; default='Windows 11'; help='Windows Update for Business ProductVersion re-applied before the scan, e.g. "Windows 11".' },
                    @{ name='version'; label='Version'; type='text'; required=$true; default='24H2'; help='TargetReleaseVersionInfo re-applied before the scan, e.g. "24H2".' },
                    @{ name='aggressive'; label='Aggressive mode (clear WU caches, remove deferrals, re-register DLLs)'; type='bool'; required=$false; default=$false; help='WARNING: stops the WU services, renames SoftwareDistribution + catroot2, re-registers the Windows Update DLLs and removes deferral / pause policy values - a full WU reset. Use only if safe mode does not surface the update.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'upgrade-drive'
                label       = 'Drive 24H2 (WUfB)'
                description  = 'Actively DRIVE the 23H2 -> 24H2 feature update over Windows Update for Business, per host. Reads readiness FIRST, then: SKIPS hosts already on 24H2+ (build 26100+) and SKIPS hardware-blocked hosts (CPU/TPM/disk fail) unless "bypass" is ticked (never drives an ineligible host silently); PINS the target (Product "Windows 11", Version "24H2") using the same Target Release Version policy write as Pin; TRIGGERS the Windows Update agent to detect/download/install the OFFERED feature update (UsoClient StartScan/StartDownload/StartInstall + the WUA COM). HONEST LIMITATION: Windows does NOT guarantee a headless feature-update INSTALL from a trigger - this PINS + ACCELERATES the WU path; the reliable completion is pin -> WU stages the update -> reboot. It does NOT claim the update installed - it reports TriggerResult (what it kicked) and RE-READS whether the host is now STAGED (feature update pending / pending-reboot). ONLY if "Reboot when staged" is ticked AND a host is CONFIRMED staged does it reboot that host on a per-host countdown to complete the swap; an un-staged host is NEVER rebooted. Reboots carry the same DNS-mismatch guard as the Restart tool, and the JANET dispatcher box is dropped from the wave. Dry-run reports what WOULD happen and changes NOTHING.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Drive 24H2 on these targets: each eligible host is PINNED to the target feature version and the Windows Update agent is TRIGGERED to stage the update. IF "Reboot when staged" is ticked and this is NOT a Dry-run, any host confirmed STAGED (feature update pending) will REBOOT after the per-host countdown to complete the upgrade - an un-staged host is never rebooted. Hosts already on 24H2+ or hardware-blocked (without bypass) are skipped. Proceed?'
                columns      = @('Host','Online','OsBuild','DisplayVersion','WasPinned','TriggerResult','Staged','Rebooted','CountdownSec','Skipped','Error')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='product'; label='Product'; type='text'; required=$true; default='Windows 11'; help='Windows Update for Business ProductVersion to pin, e.g. "Windows 11".' },
                    @{ name='version'; label='Version'; type='text'; required=$true; default='24H2'; help='TargetReleaseVersionInfo to pin/drive to, e.g. "24H2".' },
                    @{ name='bypass'; label='Apply CPU/TPM bypass for unsupported hardware (MoSetup)'; type='bool'; required=$false; default=$false; help='WARNING: sets HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU = 1 so a PC with an unsupported CPU / TPM can take 24H2 - AND lets this tool drive an otherwise hardware-blocked host. Microsoft-unsupported config; such devices may not receive all future updates. Without this, a hardware-blocked host is SKIPPED (never driven silently).' },
                    @{ name='rebootWhenStaged'; label='Reboot when staged (per-host countdown) to complete the upgrade'; type='bool'; required=$false; default=$false; help='CUSTOMER-AFFECTING: after triggering WU, if a host is CONFIRMED staged (feature update pending / pending-reboot) it will REBOOT after the countdown to finish 24H2. An un-staged host is NEVER rebooted. Off by default. The JANET dispatcher host is dropped from the wave, and every reboot is guarded by a DNS-name-match check.' },
                    @{ name='countdownSeconds'; label='Reboot countdown (seconds)'; type='int'; required=$false; default=300; help='Per-host shutdown /r /t countdown before a staged host reboots. Default 300 (5 min). Clamped 30-86400.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes - reports what WOULD happen)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'installcab'
                label       = 'Install Feature CAB'
                description  = '25H2 UPDATE job: copy a feature-update .cab/.msu (e.g. the 25H2 enablement package KB5054156) to C:\Temp on each target and install it with DISM /Online /Add-Package, optionally rebooting ~10s after a successful install. A CAB install changes the build directly and IGNORES a Pin - if the fleet is pinned to 24H2, run Unpin FIRST to keep the WU policy consistent.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Install the selected CAB/MSU on these targets with DISM /Add-Package. If "Reboot target ~10s after a successful install" is ticked and this is NOT a Dry-run, each target will REBOOT about 10 seconds after a successful install. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='cabPath'; label='CAB/MSU path (on this admin box / a share)'; type='text'; required=$false; help='Full local or UNC path to the .cab/.msu readable by the machine running JANET Web. OR use Browse below to pick/upload one. Copied to C:\Temp on each target, then installed with DISM. A UNC \\server\share path must be readable by the target machine accounts (the in-session pull is a second hop); otherwise it falls back to copying via the admin uplink.' },
                    @{ name='cabUpload'; label='...or Browse / drag a .cab/.msu to upload'; type='file'; required=$false; filter='Update packages (*.cab;*.msu)|*.cab;*.msu|All files (*.*)|*.*'; help='Pick a package in your browser; it uploads to a server temp path that the engine then copies to each target. For very large packages, prefer the path field above pointed at a share (1 GB upload cap).' },
                    @{ name='reboot'; label='Reboot target ~10s after a successful install'; type='bool'; required=$false; default=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'checkupgrade'
                label       = 'Check Upgrade Errors'
                description  = 'Read-only diagnosis of a failed in-place feature upgrade: reads C:\$WINDOWS.~BT\Sources\Panther\setuperr.log on each target and flags the out-of-memory build failure (E_OUTOFMEMORY 0x8007000E) that the page-file fix resolves. Statuses: MEMORY = out-of-memory, run Set Page File; ERRORS = setup errors logged (other cause); CLEAN = log present, no errors; NO LOG = no recent in-place upgrade attempt. Changes nothing.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'setpagefile'
                label       = 'Set Page File (fix memory exhaustion)'
                description  = 'Upgrade memory-exhaustion fix: disable Windows automatic page-file management and set the C: page file to a FIXED size (default 16384 MB / 16 GB), then reboot to apply (a reboot is required for the new size to take effect). Use this on the hosts that Check Upgrade Errors flagged MEMORY (0x8007000E), then re-run the feature update.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Disable automatic page-file management and set the C: page file to a fixed size on these targets. If "Reboot target ~10s after setting" is ticked and this is NOT a Dry-run, each target will REBOOT about 10 seconds after the change - a reboot is REQUIRED for the new page-file size to take effect. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='sizeMb'; label='Page file size (MB)'; type='int'; required=$false; default=16384; help='Fixed initial = maximum page-file size in MB on C:. 16384 = 16 GB. Clamped to 1024-131072.' },
                    @{ name='reboot'; label='Reboot target ~10s after setting (required to apply)'; type='bool'; required=$false; default=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'repair-health'
                label       = 'Repair Health (DISM + SFC)'
                description  = 'Rebuild the component store on each target with DISM /Online /Cleanup-Image /RestoreHealth, then run sfc /scannow to repair protected system files. Use this on hosts that Run Diagnostic Scan flagged with a component-store / registry-hive corruption signature (CBS_E_INVALID_PACKAGE, FOD inventory, 0x000003F1) blocking the feature upgrade. DISM may pull repair payload from Windows Update, so it can run 15-45 min per device. Per host it reports the DISM verdict (OK / OK (reboot) / exit N / error), the SFC verdict (no violations / repaired / could not fix / blocked (pending repair) / error), a rolled-up Status (CLEAN / REPAIRED / PARTIAL / FAILED) and whether a reboot is required. If "reboot" is ticked AND a reboot is required AND no user is logged on, it reboots on a 60s countdown; a logged-on user defers the reboot.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow on the selected host(s). This can take 15-45 MINUTES per device and DISM may pull repair payload from Windows Update. If "Reboot when repairs require it and no user is logged on" is ticked and this is NOT a Dry-run, a host that needs a reboot AND has no interactive user will REBOOT on a 60s countdown to complete the repair (a logged-on user defers it). Proceed?'
                columns      = @('Host','Ping','Status','Dism','Sfc','RebootNeeded','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='reboot'; label='Reboot when repairs require it and no user is logged on'; type='bool'; required=$false; default=$false; help='After a repair that reports a reboot is required, reboot the host on a 60s countdown - but ONLY if no interactive user is logged on. A logged-on user defers the reboot (reported, never forced).' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=4 }
                )
            },
            @{
                id          = 'auto-fix'
                label       = 'Auto-Fix (per device)'
                description  = 'Analyse each device and apply ONLY the fixes it actually needs to unblock the feature upgrade (ported from the desktop Auto-Fix). Per host it reads readiness first and SKIPS a host already on the target build. Then, gated by the ticked categories: writes the Target Release Version policy where it is missing / inactive / half-written; sets the CPU/TPM MoSetup bypass ONLY where the hardware is genuinely unsupported; removes drivers that failed injection per THIS device''s own setup logs (with a corrected boot-critical guard - a non-boot-class or absent device tagged boot-critical is treated as a false positive and removed); clears EXPIRED Windows Update pause values (active pauses are respected); repairs the component store (DISM/SFC) ONLY where the setup logs show corruption; deletes a stale rolled-back $WINDOWS.~BT to reclaim disk; and refreshes the SCCM client. Returns a per-device Status (FIXED / NO CHANGES / ALREADY ON TARGET / DRY-RUN / FAILED) and a semicolon-joined summary of the fixes applied. Optional reboot when a fix requires it and no user is logged on. Dry-run analyses everything read-only and reports what WOULD be fixed.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Auto-Fix the selected host(s): each device is analysed and gets ONLY the fixes it needs from the categories ticked below (policy / bypass / driver removal / pause clear / component-store repair / staging clear / SCCM refresh). This writes registry policy, may remove drivers and (if enabled) run DISM/SFC. If "reboot" is ticked and this is NOT a Dry-run, a host that needs a reboot AND has no logged-on user will REBOOT on a 60s countdown. A Dry-run changes nothing and reports what WOULD be fixed. Proceed?'
                columns      = @('Host','Ping','Status','Fixes','RebootNeeded','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='version'; label='Target version'; type='select'; required=$false; default='24H2'; options=@('24H2','25H2'); help='Feature-update target each device is driven toward - 24H2 (build 26100+) or 25H2 (build 26200+). A device already on/above this build is skipped ("ALREADY ON TARGET").' },
                    @{ name='fixPolicy'; label='Set the Target Release Version policy where missing/half-written'; type='bool'; required=$false; default=$true },
                    @{ name='fixBypass'; label='Apply CPU/TPM bypass ONLY where hardware is unsupported'; type='bool'; required=$false; default=$true; help='Sets HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU=1 only on a device whose CPU or TPM fails the check and where it is not already set.' },
                    @{ name='fixDrivers'; label='Remove drivers that failed injection per this device''s own setup logs'; type='bool'; required=$false; default=$true },
                    @{ name='driverSafe'; label='Skip driver removal when the device is currently connected'; type='bool'; required=$false; default=$true; help='When a failed-injection driver''s device is still present/connected, skip removal (safer). A disconnected/absent device is removed.' },
                    @{ name='fixPause'; label='Clear EXPIRED Windows Update pause values (active pauses are respected)'; type='bool'; required=$false; default=$true },
                    @{ name='fixRepair'; label='DISM/SFC repair only where setup logs show corruption - SLOW'; type='bool'; required=$false; default=$false; help='Runs DISM /RestoreHealth + sfc /scannow ONLY when the setup logs match a registry/component-store corruption signature. 15-45 min per matching device.' },
                    @{ name='clearStaging'; label='Delete a stale rolled-back $WINDOWS.~BT to reclaim disk'; type='bool'; required=$false; default=$false; help='Only when the staging is classified STALE (rolled-back attempt). Best-effort; tolerates partial deletion.' },
                    @{ name='sccmRefresh'; label='Refresh the SCCM / MECM client (policy + eval cycles)'; type='bool'; required=$false; default=$true },
                    @{ name='reboot'; label='Reboot when a fix requires it and no user is logged on'; type='bool'; required=$false; default=$false; help='After a fix that reports a reboot is required, reboot the host on a 60s countdown - but ONLY if no interactive user is logged on. A logged-on user defers the reboot.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (analyse only - reports what WOULD be fixed)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'error-report'
                label       = 'Error Report'
                description  = 'Read-only per-error scan (changes NOTHING): reuses the diagnostic signature logic and returns ONE row per detected upgrade error per host, so a fleet''s blockers roll up as a flat, exportable list. Each row carries a Category (DISK / DRIVER / REGISTRY / COMPONENT_STORE / PAUSED / POLICY / STAGING / MEMORY / ADLDS / SETUPDIAG / NONE), a Severity (BLOCK / WARN / INFO), the concrete Evidence (the value or log line), and a one-sentence Fix. A clean host returns a single NONE / INFO "No upgrade errors detected" row; a host already on/above the target build returns a single NONE row noting the build.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Category','Severity','Evidence','Fix')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='version'; label='Target version'; type='select'; required=$false; default='24H2'; options=@('24H2','25H2'); help='Feature-update target the scan checks readiness/blockers against - 24H2 (build 26100+) or 25H2 (build 26200+).' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'ping'
                label       = 'Ping Sweep'
                description  = 'Quick reachability check across the target list (changes nothing).'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            }
        )
    }
}

function ConvertTo-JanetHostList {
    # Split a pasted blob into clean, unique, upper-cased host tokens. '#' starts a
    # comment to end-of-line (full '# header' line OR trailing 'host # note'), so a
    # pasted commented list does not leak its words in as bogus hosts. Validity is
    # checked separately by Test-JanetTargetToken in the caller.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($line in ($Raw -split '\r?\n')) {
        $l = $line
        $hash = $l.IndexOf('#')
        if ($hash -ge 0) { $l = $l.Substring(0, $hash) }
        foreach ($tok in ($l -split '[\s,;]+')) {
            $h = $tok.Trim()
            if ($h -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
        }
    }
    return $out.ToArray()
}

function Test-JanetTargetToken {
    # A target must be either a strict DNS-ish hostname OR a literal IP address -
    # stops a pasted UNC fragment, account-qualified name, URL, etc. from flowing
    # into New-PSSession / Invoke-Command and mis-targeting. (Shared with pkginstall.)
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Token, [ref]$ip)) { return $true }
    return ($Token -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')
}

function ConvertTo-JanetBool {
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return ("$Value" -match '^(?i:true|1|yes|on)$')
}

function Get-WinUpgradeFleetStatus {
    # Pure classifier: map a host's read-only scan signals to a single 24H2-journey
    # verdict. Precedence (per the Fleet Status spec):
    #   Error            - the scan errored (a message is present)
    #   Offline          - the reachability probe failed
    #   Already 24H2+    - OS build >= 26100
    #   Pending reboot   - a feature update is staged / the box is pending-reboot (mid-upgrade)
    #   Error            - online but the build could not be read (0)
    #   Ready            - on 23H2 (22631) or older AND eligible (CPU/TPM/disk all pass)
    #   Blocked: <reason>- on <=23H2 but a hardware check fails (reasons joined)
    # Pinned is a SECONDARY flag surfaced in its own column, never folded in here.
    # MinBuild + Version make the verdict target-aware (default 26100 / '24H2' keeps every
    # existing string identical); the summary rollup matches the 'Already ' PREFIX so a
    # '25H2' target rolls up the same way.
    param(
        [int]$OsBuild = 0,
        [bool]$Online = $false,
        [bool]$Eligible = $false,
        [string]$BlockReason = '',
        [bool]$PendingReboot = $false,
        [string]$ErrorText = '',
        [int]$MinBuild = 26100,
        [string]$Version = '24H2'
    )
    if ($ErrorText)            { return 'Error' }
    if (-not $Online)          { return 'Offline' }
    if ($OsBuild -ge $MinBuild){ return "Already $Version+" }
    if ($PendingReboot)        { return 'Pending reboot' }
    if ($OsBuild -le 0)      { return 'Error' }
    if ($Eligible)           { return 'Ready' }
    $reason = if ($BlockReason) { $BlockReason } else { 'ineligible' }
    return "Blocked: $reason"
}

function Get-WinUpgradeLocalIdentity {
    # The set of names/addresses that ARE this dispatcher box, so an 'upgrade-drive'
    # wave that reboots staged hosts never reboots the machine running JANET Web.
    # Copied from the Restart tool's Get-JanetLocalIdentity (audit#10 self-guard).
    if ($script:WinUpgradeLocalIdentity) { return $script:WinUpgradeLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    # Also add every locally-BOUND unicast IPv4 (mgmt/OOB NICs, lagging DNS): a bound IP
    # not registered under this box's own name would otherwise be missed by the DNS lookup
    # above, letting a pasted IP-literal target slip past the self-guard (audit P3-1).
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:WinUpgradeLocalIdentity = $set
    return $set
}

function Test-WinUpgradeHostIsSelf {
    # Is $Target this dispatcher box? (name / shortname / IP / loopback). Mirror of the
    # Restart tool's Test-JanetHostIsSelf.
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-WinUpgradeLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

function Get-WinUpgradeDrivePlan {
    # PURE decision authority for the 'upgrade-drive' action - the single source of
    # truth for the SAFETY invariants, unit-tested directly and MIRRORED inline by the
    # worker's UpgradeDrive path (which, like every worker here, runs in a bare pool
    # runspace and therefore cannot call a module function). Keep the two in sync.
    #
    #   Skip precedence (report, NEVER act):
    #     OsBuild >= 26100              -> Skipped='already 24H2+'   (no pin/trigger/reboot)
    #     not Eligible AND not Bypass   -> Skipped='blocked (<reason>)'  (never drive an
    #                                      ineligible host silently; operator must opt into bypass)
    #   Otherwise: WouldPin + WouldTrigger.
    #   Reboot happens ONLY when: RebootWhenStaged AND Staged AND the DNS name-guard passes.
    #     - RebootWhenStaged AND Staged but ExpectedName is present and != LocalName
    #       -> RebootAborted (guard), ShouldReboot=$false.
    #     - Staged=$false                                     -> ShouldReboot=$false (NEVER
    #       reboot an un-staged host - the core invariant).
    param(
        [int]$OsBuild = 0,
        [bool]$Eligible = $false,
        [string]$BlockReason = '',
        [bool]$Bypass = $false,
        [bool]$RebootWhenStaged = $false,
        [bool]$Staged = $false,
        [int]$CountdownSeconds = 300,
        [string]$ExpectedName = '',   # dialed short hostname ('' for an IP target -> guard skipped)
        [string]$LocalName = ''       # the host's own $env:COMPUTERNAME (as read on the box)
    )
    $plan = [ordered]@{
        Skipped = ''; WouldPin = $false; WouldTrigger = $false
        ShouldReboot = $false; RebootAborted = $false; RebootAbortReason = ''; CountdownSec = $CountdownSeconds
    }
    if ($OsBuild -ge 26100) { $plan.Skipped = 'already 24H2+'; return $plan }
    if ((-not $Eligible) -and (-not $Bypass)) {
        $reason = if ($BlockReason) { $BlockReason } else { 'ineligible' }
        $plan.Skipped = "blocked ($reason)"; return $plan
    }
    $plan.WouldPin = $true
    $plan.WouldTrigger = $true
    if ($RebootWhenStaged -and $Staged) {
        if ($ExpectedName -and ($ExpectedName.Trim().ToUpper() -ne ([string]$LocalName).Trim().ToUpper())) {
            $plan.RebootAborted = $true
            $plan.RebootAbortReason = "DNS mismatch: dialed '$ExpectedName' but this machine is '$LocalName' - reboot ABORTED"
        } else {
            $plan.ShouldReboot = $true
        }
    }
    return $plan
}

# --- SCCM CLIENT CYCLES (copied EXACTLY from References\24h2script.ps1 lines 27-33) ---
# Machine Policy Retrieval & Eval, Software Updates Deployment Eval / Scan, etc.
$script:WinUpgradeCycles = @(
    "{00000000-0000-0000-0000-000000000021}",
    "{00000000-0000-0000-0000-000000000022}",
    "{00000000-0000-0000-0000-000000000113}",
    "{00000000-0000-0000-0000-000000000108}",
    "{00000000-0000-0000-0000-000000000121}"
)

# --- WINDOWS 11 24H2 MINIMUM REQUIREMENTS (reference lines 36-52) ---
$script:WinUpgradeMinRAMGB      = 4
$script:WinUpgradeMinDiskGB     = 64
$script:WinUpgradeMinTPMVersion = "2.0"
$script:WinUpgradeCpuPatterns = @(
    'i[3579]-[89]\d{3}',
    'i[3579]-10\d{3}',
    'i[3579]-1[1-4]\d{3}',
    'Core\s*Ultra',
    'Xeon\s*W-1[2-3]\d{2}',
    'Ryzen\s*[3579]\s*[3-9]\d{3}',
    'Ryzen\s*[3579]\s*PRO\s*[3-9]\d{3}',
    'EPYC\s*7[2-9]\d{2}',
    'SQ[123]',
    'Snapdragon\s*[78]cx',
    'Snapdragon\s*X\s*(Elite|Plus)'
)

# --- TARGET FEATURE-UPDATE VERSIONS (v0.4.0 parameterization) ---
# The 'version' input on fleet-status / diagnose / upgrade-drive / auto-fix / error-report
# selects one of these; its MinBuild replaces the previously-hardcoded 26100 build gate and
# its Version string version-derives the verdict text ('Already <version>+' / 'ON <version>').
# 24H2 = build 26100, 25H2 = build 26200. Default is 24H2 so every existing behaviour is
# byte-for-byte identical. Add a row here to teach the engine a new target build.
$script:WinUpgradeTargets = [ordered]@{
    '24H2' = @{ Product = 'Windows 11'; Version = '24H2'; MinBuild = 26100 }
    '25H2' = @{ Product = 'Windows 11'; Version = '25H2'; MinBuild = 26200 }
}

# =============================================================================
#  DIAGNOSE DECISION HELPERS (fleet-batch lessons: 23H2 -> 24H2, 8 boxes / 7 causes)
#
#  These are PURE, script-scope, unit-tested helpers. The Diagnose remote scan runs
#  ON the target in a bare pool runspace and therefore CANNOT call a module function,
#  so it MIRRORS this logic INLINE (the same pattern Get-WinUpgradeDrivePlan uses).
#  The helpers are the tested source of truth; keep the inline mirror in sync.
# =============================================================================

# Plainly non-boot device classes. DISM tags a failed-injection driver "boot-critical"
# defensively; for these classes (or an absent device) that flag is almost always a
# FALSE POSITIVE and removing the driver is frequently the actual 24H2 fix (field batch:
# a disconnected HID presenter dongle tagged boot-critical blocked its own removal).
$script:WinUpgradeNonBootDriverClasses = @(
    'HIDClass','Mouse','Keyboard','Media','Image','Printer','Camera','SoftwareDevice','Bluetooth'
)

# Setup-failure signature table (extensible pattern -> cause -> fix), evaluated over the
# CURRENT ~BT\Sources\Panther\setuperr.log. A rule fires if ANY of its 'Patterns' match
# (OR), or - when 'All' is set - only if EVERY pattern matches (AND). One [FAIL]+[REC]
# per hit. This is the tested source of truth; the remote scan mirrors it inline.
$script:WinUpgradeSetupErrRules = @(
    @{ Code='REGISTRY_CORRUPT'; Patterns=@('0x000003F1','(?i)configuration registry database is corrupt');
       Message='registry hive corrupt';
       Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow; if it persists, deeper hive repair.' }
    @{ Code='COMPONENT_STORE'; Patterns=@('CBS_E_INVALID_PACKAGE','(?i)Failed to enumerate store capabilities');
       Message='component store broken';
       Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' }
    @{ Code='COMPONENT_STORE'; All=@('(?i)FOD inventory','E_INVALIDARG');
       Message='component store broken (FOD inventory E_INVALIDARG)';
       Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' }
    @{ Code='OOM'; Patterns=@('0x8007000E');
       Message='out of memory (E_OUTOFMEMORY)';
       Rec='Run Set Page File (fixed 16 GB) on this host, then re-run the feature update.' }
    @{ Code='ADLDS_MIGRATE'; All=@('adammigrate\.dll','0x80070002');
       Message='AD LDS migration plugin (adammigrate.dll) failing';
       Rec='Investigate the AD LDS migration plugin AFTER clearing the other blockers, then re-diagnose.' }
    @{ Code='SETUP_CANCELLED'; Patterns=@('0x800704C7');
       Message='setup cancelled (0x800704C7)';
       Rec='Cross-check DEFERRALS & BLOCKS - an expired/lingering pause can present as a cancel; clear stale pause values + re-trigger.' }
)

function Get-WinUpgradeSetupErrSignatures {
    # PURE: match the failure-signature table against a setuperr.log body, returning one
    # descriptor per HIT (Code/Message/Rec), table order. Mirrored inline by the remote scan.
    param([string]$LogText)
    if ([string]::IsNullOrWhiteSpace($LogText)) { return @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($rule in $script:WinUpgradeSetupErrRules) {
        $hit = $false
        if ($rule.ContainsKey('All')) {
            $hit = $true
            foreach ($p in $rule['All']) { if ($LogText -notmatch $p) { $hit = $false; break } }
        } else {
            foreach ($p in $rule['Patterns']) { if ($LogText -match $p) { $hit = $true; break } }
        }
        if ($hit) { [void]$out.Add([pscustomobject]@{ Code=$rule['Code']; Message=$rule['Message']; Rec=$rule['Rec'] }) }
    }
    return $out.ToArray()
}

function Get-WinUpgradePauseClass {
    # PURE: classify one WU pause value. Only an End/Expiry value name carries a window end
    # we can place in time: end in the PAST -> 'Expired' (lingering values, clear + re-trigger);
    # end in the FUTURE -> 'Active' (a real pause block). A Start-time value or an unparseable
    # date is just 'Block'. Mirrored inline by the remote scan.
    param([string]$ValueName, $Value, [datetime]$Now = (Get-Date))
    $isEnd = ($ValueName -match '(?i)(End|Expiry)Time$')
    $dt = [datetime]::MinValue
    $parsed = [datetime]::TryParse([string]$Value, [ref]$dt)
    if ($isEnd -and $parsed) {
        if ($dt -lt $Now) { return 'Expired' } else { return 'Active' }
    }
    return 'Block'
}

function Get-WinUpgradeStagingClass {
    # PURE: classify a C:\$WINDOWS.~BT staging folder. A rolled-back attempt leaves the tree
    # behind but NOTHING is in progress (field batch: 7 boxes with rolled-back staging were
    # all misread as 'updates in progress - let them complete'). Precedence:
    #   RollbackMarker present            -> 'Stale' (rolled-back attempt, clear it)
    #   a setup process (SetupHost/Prep)  -> 'Active' (genuinely mid-upgrade)
    #   folder older than 24h, no process -> 'Stale'
    #   otherwise (recent, no process)    -> 'Recent' (may await reboot; NOT 'in progress')
    param([double]$AgeHours, [bool]$RollbackMarker, [bool]$SetupProcessRunning)
    if ($RollbackMarker)      { return 'Stale' }
    if ($SetupProcessRunning) { return 'Active' }
    if ($AgeHours -gt 24)     { return 'Stale' }
    return 'Recent'
}

function Test-WinUpgradeTrvHalfWritten {
    # PURE: a half-written Target Release Version pin - TargetReleaseVersion=1 but the
    # ProductVersion OR TargetReleaseVersionInfo string is empty. WU treats it as
    # incomplete/inert; re-apply. Mirrored inline by the remote scan.
    param($TargetReleaseVersion, [string]$ProductVersion, [string]$TargetReleaseVersionInfo)
    $trv = 0; [void][int]::TryParse([string]$TargetReleaseVersion, [ref]$trv)
    if ($trv -ne 1) { return $false }
    return ([string]::IsNullOrWhiteSpace($ProductVersion) -or [string]::IsNullOrWhiteSpace($TargetReleaseVersionInfo))
}

function Test-WinUpgradeNonBootDriverClass {
    # PURE: is this a plainly non-boot device class? (used to downgrade a DISM BootCritical
    # flag to 'likely false positive' for a failed-injection driver). Mirrored inline.
    param([string]$DriverClass)
    if ([string]::IsNullOrWhiteSpace($DriverClass)) { return $false }
    foreach ($c in $script:WinUpgradeNonBootDriverClasses) { if ($DriverClass -ieq $c) { return $true } }
    return $false
}

# =============================================================================
#  v0.4.0 DECISION HELPERS (repair-health / auto-fix / error-report)
#
#  Same dual-tested pattern as the diagnose helpers: these are PURE, script-scope,
#  unit-tested authorities. The worker ops that use them run in bare pool runspaces
#  and CANNOT call a module function, so they MIRROR this logic INLINE. Keep the two
#  in sync (a sync-warning comment sits at each inline mirror).
# =============================================================================

function Get-WinUpgradeRepairVerdict {
    # PURE: turn a DISM RestoreHealth exit code + the sfc /scannow text into the
    # repair-health row verdicts. Mirrored inline by the RepairHealth worker branch.
    #   Dism : 'OK' | 'OK (reboot)' | 'exit N' | 'error'
    #   Sfc  : 'no violations' | 'repaired' | 'could not fix' | 'blocked (pending repair)' | 'error'
    #   Status: CLEAN (nothing needed fixing) / REPAIRED / PARTIAL (sfc could not fix) / FAILED
    #   RebootNeeded: dism 3010 OR sfc 'repaired' (the worker ORs the CBS/WU reboot keys on top)
    param(
        $DismExit,
        [string]$SfcText,
        [bool]$DismError = $false,
        [bool]$SfcError  = $false
    )
    if ($DismError -or ($null -eq $DismExit)) { $dism = 'error' }
    else {
        $dx = 0; [void][int]::TryParse([string]$DismExit, [ref]$dx)
        if     ($dx -eq 0)    { $dism = 'OK' }
        elseif ($dx -eq 3010) { $dism = 'OK (reboot)' }
        else                  { $dism = "exit $dx" }
    }
    $t = if ($null -ne $SfcText) { ([string]$SfcText -replace "`0","") } else { '' }
    if     ($SfcError)                                              { $sfc = 'error' }
    elseif ($t -match '(?i)did not find any integrity violations')  { $sfc = 'no violations' }
    elseif ($t -match '(?i)successfully repaired')                  { $sfc = 'repaired' }
    elseif ($t -match '(?i)unable to fix' -or $t -match '(?i)could not fix') { $sfc = 'could not fix' }
    elseif ($t -match '(?i)could not perform the requested operation') { $sfc = 'blocked (pending repair)' }
    else                                                            { $sfc = 'no violations' }
    $dismFailed = ($dism -eq 'error' -or $dism -match '^exit ')
    $sfcFailed  = ($sfc -eq 'error')
    if     ($dismFailed -or $sfcFailed)                                   { $status = 'FAILED' }
    elseif ($sfc -eq 'could not fix' -or $sfc -eq 'blocked (pending repair)') { $status = 'PARTIAL' }
    elseif ($sfc -eq 'repaired' -or $dism -eq 'OK (reboot)')             { $status = 'REPAIRED' }
    else                                                                 { $status = 'CLEAN' }
    $rebootNeeded = ($dism -eq 'OK (reboot)' -or $sfc -eq 'repaired')
    return [ordered]@{ Dism = $dism; Sfc = $sfc; Status = $status; RebootNeeded = $rebootNeeded }
}

function Get-WinUpgradeAutoFixPlan {
    # PURE: given a device's read-only signals, return the array of fix KEYS that device
    # NEEDS (order = apply order). The worker intersects this with the operator's enabled
    # toggles before acting. A device already on/above the target build needs nothing.
    # Keys: 'policy','bypass','drivers','pause','repair','staging'. Mirrored inline by AutoFix.
    param(
        [int]$Build = 0,
        [int]$MinBuild = 26100,
        [bool]$PolicyComplete = $false,   # TRV=1 AND ProductVersion AND TargetReleaseVersionInfo all set
        [bool]$CpuSupported = $false,
        [bool]$TpmSupported = $false,
        [bool]$BypassActive = $false,
        [bool]$FailedDrivers = $false,    # >=1 failed-injection INF parsed from setuperr.log
        [bool]$PauseExpired = $false,     # an EXPIRED pause value is lingering
        [bool]$Corruption = $false,       # a registry/component-store corruption signature matched
        [string]$StagingClass = 'None'    # Get-WinUpgradeStagingClass output
    )
    $fixes = New-Object System.Collections.ArrayList
    # Unary-comma returns: without them PowerShell unrolls a 1-element array to a bare
    # string, breaking .Count/-contains at call sites (same guard as Get-WinUpgradeErrorRowSet).
    if ($Build -ge $MinBuild) { return ,@() }
    if (-not $PolicyComplete)                                              { [void]$fixes.Add('policy') }
    if ((-not $CpuSupported -or -not $TpmSupported) -and -not $BypassActive) { [void]$fixes.Add('bypass') }
    if ($FailedDrivers)                                                     { [void]$fixes.Add('drivers') }
    if ($PauseExpired)                                                      { [void]$fixes.Add('pause') }
    if ($Corruption)                                                        { [void]$fixes.Add('repair') }
    if ($StagingClass -eq 'Stale')                                         { [void]$fixes.Add('staging') }
    return ,($fixes.ToArray())
}

function Get-WinUpgradeErrorRowSet {
    # PURE: turn a host's read-only upgrade-error signals into the error-report row set
    # (Category / Severity / Evidence / Fix). Categories:
    #   DISK|DRIVER|REGISTRY|COMPONENT_STORE|PAUSED|POLICY|STAGING|MEMORY|ADLDS|SETUPDIAG|NONE
    # A host already on/above the target build -> one NONE row noting the build; a host with
    # no detected errors -> one NONE 'No upgrade errors detected' row. Mirrored inline by the
    # ErrorReport worker's remote scan (which gathers the signals ON the target).
    param(
        [int]$Build = 0,
        [int]$MinBuild = 26100,
        [string]$Version = '24H2',
        [double]$FreeGB = 999,
        [int]$MinDisk = 64,
        [string[]]$FailedDrivers = @(),
        $Signatures = @(),           # Get-WinUpgradeSetupErrSignatures output (Code/Message/Rec)
        [bool]$PauseActive = $false,
        [bool]$PauseExpired = $false,
        [string]$StagingClass = 'None',
        [double]$StagingGB = 0,
        [bool]$PolicyMissing = $false,
        [bool]$PolicyHalfWritten = $false,
        [string]$SetupDiagProfile = ''
    )
    $trim = { param($s) $x = [string]$s; if ($x.Length -gt 200) { $x = $x.Substring(0,200) }; $x }
    if ($Build -ge $MinBuild) {
        return ,@([ordered]@{ Category='NONE'; Severity='INFO'; Evidence="Already on $Version+ (build $Build)"; Fix='' })
    }
    $rows = New-Object System.Collections.ArrayList
    if ($FreeGB -lt $MinDisk) {
        [void]$rows.Add([ordered]@{ Category='DISK'; Severity='BLOCK'; Evidence=(& $trim "$FreeGB GB free on the system drive (need $MinDisk+ GB)"); Fix="Free disk to 25+ GB (clearing `$WINDOWS.~BT reclaims staging), then re-trigger." })
    }
    foreach ($inf in @($FailedDrivers)) {
        if ([string]::IsNullOrWhiteSpace($inf)) { continue }
        [void]$rows.Add([ordered]@{ Category='DRIVER'; Severity='WARN'; Evidence=(& $trim "Failed to inject driver package: $inf"); Fix="Remove the failed driver (pnputil /delete-driver <oemNN.inf> /force), clear `$WINDOWS.~BT, re-trigger." })
    }
    foreach ($sig in @($Signatures)) {
        if (-not $sig) { continue }
        $code = [string]$sig.Code
        $cat = switch ($code) {
            'REGISTRY_CORRUPT' { 'REGISTRY' }
            'COMPONENT_STORE'  { 'COMPONENT_STORE' }
            'OOM'              { 'MEMORY' }
            'ADLDS_MIGRATE'    { 'ADLDS' }
            'SETUP_CANCELLED'  { 'PAUSED' }
            default            { 'REGISTRY' }
        }
        $sev = if ($code -eq 'ADLDS_MIGRATE' -or $code -eq 'SETUP_CANCELLED') { 'WARN' } else { 'BLOCK' }
        [void]$rows.Add([ordered]@{ Category=$cat; Severity=$sev; Evidence=(& $trim ([string]$sig.Message)); Fix=(& $trim ([string]$sig.Rec)) })
    }
    if ($PauseActive) {
        [void]$rows.Add([ordered]@{ Category='PAUSED'; Severity='BLOCK'; Evidence='An ACTIVE Windows Update pause window is holding the feature update'; Fix='Wait for the pause to expire or clear it (Force Discovery aggressive), then re-trigger.' })
    } elseif ($PauseExpired) {
        [void]$rows.Add([ordered]@{ Category='PAUSED'; Severity='WARN'; Evidence='An EXPIRED pause value is lingering under WindowsUpdate\UX\Settings'; Fix='Clear the expired Pause* values (Auto-Fix / Force Discovery aggressive), then re-trigger.' })
    }
    if ($PolicyHalfWritten) {
        [void]$rows.Add([ordered]@{ Category='POLICY'; Severity='WARN'; Evidence='Target Release Version pin is HALF-WRITTEN (TargetReleaseVersion=1 but Product/Version blank)'; Fix='Re-apply the pin (Pin action / Auto-Fix / Force Discovery re-writes it).' })
    } elseif ($PolicyMissing) {
        [void]$rows.Add([ordered]@{ Category='POLICY'; Severity='WARN'; Evidence='Target Release Version policy is not set'; Fix='Apply the Target Release Version policy (Pin action / Auto-Fix).' })
    }
    if ($StagingClass -eq 'Stale') {
        [void]$rows.Add([ordered]@{ Category='STAGING'; Severity='INFO'; Evidence=(& $trim "Stale rolled-back `$WINDOWS.~BT staging (~$StagingGB GB) - nothing is in progress"); Fix="Clear C:\`$WINDOWS.~BT to reclaim disk AFTER fixing the root cause, then re-trigger." })
    }
    if ($SetupDiagProfile) {
        [void]$rows.Add([ordered]@{ Category='SETUPDIAG'; Severity='WARN'; Evidence=(& $trim "SetupDiag matched profile: $SetupDiagProfile"); Fix='Action the SetupDiag remediation for this profile, then re-trigger.' })
    }
    if ($rows.Count -eq 0) {
        return ,@([ordered]@{ Category='NONE'; Severity='INFO'; Evidence='No upgrade errors detected'; Fix='' })
    }
    return ,($rows.ToArray())
}

# =============================================================================
#  v0.5.0 DECISION HELPERS (os-audit / install-updates)
#
#  Same dual-tested pattern as the diagnose helpers: PURE, script-scope, unit-tested
#  authorities. The worker ops that use them run in bare pool runspaces and CANNOT call
#  a module function, so they MIRROR this logic INLINE. Keep the two in sync.
# =============================================================================

function Get-WinUpgradeOsAuditVerdict {
    # PURE: the OS Version audit rule - THREE pass/fail checks with NO partial state.
    #   Gen11      = (CurrentBuild -ge 22000)   # Windows 11 generation
    #   Rel24H2    = (CurrentBuild -ge 26100)   # release 24H2 (26100) or newer (25H2=26200, ...)
    #   EntEdition = ($EditionID -eq 'Enterprise')  # EXACT; Pro/Education/Home/Enterprise
    #               multi-session (ServerRdsh/EnterpriseS)/IoT (IoTEnterprise) all FAIL
    # Verdict = 'PASS' iff all three true, else 'FAIL'. Failed = comma list of failing
    # check names. Mirrored INLINE by the OsAudit worker branch (keep in sync).
    param([int]$CurrentBuild = 0, [string]$EditionID = '')
    $gen11   = ($CurrentBuild -ge 22000)
    $rel24h2 = ($CurrentBuild -ge 26100)
    $entEd   = ($EditionID -eq 'Enterprise')
    $failed = New-Object System.Collections.ArrayList
    if (-not $gen11)   { [void]$failed.Add('Gen11') }
    if (-not $rel24h2) { [void]$failed.Add('Rel24H2') }
    if (-not $entEd)   { [void]$failed.Add('EntEdition') }
    return [ordered]@{
        Gen11      = $(if ($gen11)   { 'PASS' } else { 'FAIL' })
        Rel24H2    = $(if ($rel24h2) { 'PASS' } else { 'FAIL' })
        EntEdition = $(if ($entEd)   { 'PASS' } else { 'FAIL' })
        Verdict    = $(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })
        Failed     = ($failed.ToArray() -join ', ')
    }
}

function Get-WinUpgradeWuaResultRow {
    # PURE: turn a parsed WUA result.json object (as the SYSTEM driver writes it, then
    # ConvertFrom-Json'd from the poll) into the install-updates row fields. This is the
    # WORKER-side interpretation of the driver's contract and the tested source of truth
    # for the ResultCode->Status mapping; the InstallUpdates worker MIRRORS it inline.
    #   ResultCode 2 -> Installed, 3 -> InstalledWithErrors, else InstallFailed.
    #   When no numeric ResultCode is present the driver's Status string is used verbatim
    #   (NoUpdates / Error / Timeout). A $null result (no result.json before the poll
    #   deadline) -> Status='Timeout'. Got=$false only for a $null/blank result (the
    #   transport produced nothing) OR a NONCE MISMATCH (a stale/prior-run result.json)
    #   so the cascade/poll keeps trying instead of trusting the wrong file. A confirmed
    #   HOST mismatch (result.json Host short-name != the dialed target) -> an explicit
    #   'WrongBox' row (Ok=$false, Got=$true) - never a success. ExpectNonce/TargetShort/
    #   TargetIsIp are optional; when ExpectNonce is blank the nonce gate is skipped
    #   (back-compat), and the host gate is skipped for IP-literal targets.
    param($Result, [string]$ExpectNonce = '', [string]$TargetShort = '', [bool]$TargetIsIp = $false)
    $out = [ordered]@{ Status='Timeout'; KBs=''; Reboot=$false; Error=''; Ok=$false; Got=$false }
    if ($null -eq $Result) { $out.Error = 'no result.json before the poll deadline'; return $out }
    # NONCE gate: a result.json whose Nonce != this run's is a stale/prior file -> reject
    # (Got=$false so the caller keeps polling; NEVER surfaces as this run's success).
    if ($ExpectNonce) {
        $rNonce = ''
        try { if ($Result.PSObject.Properties['Nonce']) { $rNonce = [string]$Result.Nonce } } catch {}
        if ($rNonce -ne $ExpectNonce) { $out.Error = 'result.json nonce mismatch (stale/prior run) - ignored'; return $out }
    }
    # HOST gate: the driver stamps Host=$env:COMPUTERNAME; if it does not match the dialed
    # short name we patched/queried the WRONG box (stale DNS / reused IP). Skip for IP targets.
    if (-not $TargetIsIp -and $TargetShort) {
        $rHost = ''
        try { if ($Result.PSObject.Properties['Host']) { $rHost = [string]$Result.Host } } catch {}
        if ($rHost) {
            $rHostShort = ($rHost -split '\.')[0]
            if ($rHostShort -ine $TargetShort) {
                $out.Got = $true; $out.Status = 'WrongBox'; $out.Ok = $false
                $out.Error = "result.json Host '$rHost' != dialed target '$TargetShort' (WRONG BOX - stale DNS / reused IP)"
                return $out
            }
        }
    }
    $out.Got = $true
    $rc = $null
    try { if ($Result.PSObject.Properties['ResultCode']) { $rc = $Result.ResultCode } } catch {}
    if ($null -ne $rc -and "$rc" -ne '') {
        $rcInt = 0; [void][int]::TryParse("$rc", [ref]$rcInt)
        $out.Status = $(if ($rcInt -eq 2) { 'Installed' } elseif ($rcInt -eq 3) { 'InstalledWithErrors' } else { 'InstallFailed' })
        if ($out.Status -eq 'InstallFailed') { $out.Error = "install ResultCode=$rcInt" }
    } else {
        $out.Status = [string]$Result.Status
    }
    try { $out.Reboot = [bool]$Result.Reboot } catch { $out.Reboot = $false }
    $kbs = @()
    try { if ($null -ne $Result.KBs) { $kbs = @($Result.KBs) } } catch {}
    $out.KBs = ($kbs | Where-Object { $_ } | Select-Object -Unique) -join ','
    if ($out.Status -eq 'Error')   { try { if ($Result.Message) { $out.Error = [string]$Result.Message } } catch {} }
    if ($out.Status -eq 'Timeout' -and -not $out.Error) { $out.Error = 'SYSTEM task did not report a result in time' }
    $out.Ok = (@('Installed','InstalledWithErrors','NoUpdates') -contains $out.Status)
    return $out
}

# The WUA driver that runs ON the target as NT AUTHORITY\SYSTEM. PORTED VERBATIM from
# References\HTTPS_Installer.ps1 $Global:WuaDriver (lines 47-128): a SYSTEM-context
# Microsoft.Update.Session that searches ssDefault (WSUS) and - when IncludeMU - also
# ssWindowsUpdate + the Microsoft Update catalog (GUID 7971f918-...), AcceptEula,
# Download, Install, and writes C:\ProgramData\JANET\WUA\result.json with Status
# (ResultCode 2=Installed, 3=InstalledWithErrors, else InstallFailed) / Installed /
# Reboot / KBs. '#__INCLUDEMU__#' is string-replaced with $true/$false before send.
# '#__NONCE__#' is string-replaced with a fresh per-run token so the worker can prove
# a polled result.json belongs to THIS run (not a stale prior run's file); every
# result object also stamps Host=$env:COMPUTERNAME so the worker can catch a wrong box.
# Single-quoted here-string so $-tokens are preserved literally for the target.
$script:WinUpgradeWuaDriver = @'
$ErrorActionPreference = "Stop"
$base = Join-Path $env:ProgramData "JANET\WUA"
$log  = Join-Path $base "result.json"
# #__INCLUDEMU__# is replaced with $true/$false before this is sent.
$IncludeMU = #__INCLUDEMU__#
# #__NONCE__# is replaced with this run's fresh nonce token before send.
$Nonce = "#__NONCE__#"
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $muGuid = "7971f918-a847-4430-9279-4a52d1efe18d"
    $selections = @( ,@(0, $null) )
    if ($IncludeMU) {
        try {
            $sm = New-Object -ComObject Microsoft.Update.ServiceManager
            $sm.AddService2($muGuid, 7, "") | Out-Null
        } catch {}
        $selections += ,@(2, $null)
        $selections += ,@(3, $muGuid)
    }
    $criteria = "IsInstalled=0 and IsHidden=0 and Type='Software'"
    $agg      = New-Object -ComObject Microsoft.Update.UpdateColl
    $seen     = @{}
    $svcUsed  = @()
    $svcErr   = @()
    foreach ($sel in $selections) {
        try {
            $searcher = $session.CreateUpdateSearcher()
            $searcher.ServerSelection = $sel[0]
            if ($sel[1]) { $searcher.ServiceID = $sel[1] }
            $r = $searcher.Search($criteria)
            foreach ($u in $r.Updates) {
                $id = $u.Identity.UpdateID
                if (-not $seen.ContainsKey($id)) {
                    $seen[$id] = $true
                    $agg.Add($u) | Out-Null
                }
            }
            if ($r.Updates.Count -gt 0) { $svcUsed += "sel$($sel[0])=$($r.Updates.Count)" }
        } catch {
            $svcErr += "sel$($sel[0]): $($_.Exception.Message)"
        }
    }
    if ($agg.Count -eq 0) {
        [pscustomobject]@{ Status="NoUpdates"; Installed=0; Reboot=$false; KBs=@(); Services=$svcUsed; SvcErrors=$svcErr; Nonce=$Nonce; Host=$env:COMPUTERNAME; Time=(Get-Date).ToString("o") } |
            ConvertTo-Json | Set-Content -Path $log -Encoding UTF8
        return
    }
    $kbs = @()
    foreach ($u in $agg) {
        try { if (-not $u.EulaAccepted) { $u.AcceptEula() } } catch {}
        foreach ($k in $u.KBArticleIDs) { $kbs += "KB$k" }
    }
    $dl = $session.CreateUpdateDownloader(); $dl.Updates = $agg; $dl.Download() | Out-Null
    $inst = $session.CreateUpdateInstaller(); $inst.Updates = $agg
    $res = $inst.Install()
    # ResultCode: 2=Succeeded 3=SucceededWithErrors 4=Failed 5=Aborted
    [pscustomobject]@{
        Status     = if ($res.ResultCode -eq 2) { "Installed" } elseif ($res.ResultCode -eq 3) { "InstalledWithErrors" } else { "InstallFailed" }
        Installed  = $agg.Count
        ResultCode = $res.ResultCode
        Reboot     = [bool]$res.RebootRequired
        KBs        = ($kbs | Select-Object -Unique)
        Services   = $svcUsed
        SvcErrors  = $svcErr
        Nonce      = $Nonce
        Host       = $env:COMPUTERNAME
        Time       = (Get-Date).ToString("o")
    } | ConvertTo-Json | Set-Content -Path $log -Encoding UTF8
} catch {
    [pscustomobject]@{ Status="Error"; Message=$_.Exception.Message; Nonce=$Nonce; Host=$env:COMPUTERNAME; Time=(Get-Date).ToString("o") } |
        ConvertTo-Json | Set-Content -Path $log -Encoding UTF8
}
'@

# Per-host worker. Runs in an isolated runspace -- NO outer-scope vars are
# visible; everything comes via .AddArgument(). Returns one [ordered] result
# (Host/Ping/Status/Detail/Ok); the harvest loop turns it into a streamed row.
# Native exit codes (DISM, shutdown) are captured via ProcessStartInfo, NOT the
# call operator, because PS 5.1 wraps a native command's stderr in ErrorRecord
# objects which Invoke-Command then reports as remote errors and corrupts the
# exit code. ProcessStartInfo bypasses that.

# Shared pin policy-write remote block (the Windows Update for Business Target Release
# Version write, + optional MoSetup CPU/TPM bypass). Defined ONCE at module scope and
# passed into the worker as $PinBlock, so BOTH the 'pin' action and the 'upgrade-drive'
# action reuse the exact same proven write (never re-implemented). It is only ever used
# as a REMOTE Invoke-Command -ScriptBlock (serialized to the target), so it is safe to
# hand to a bare pool runspace. Body copied verbatim from the reference $sbApply.
$script:WinUpgradePinBlock = {
    param($tv, $prod, $doBypass)
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -PropertyType DWord  -Value 1    -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'ProductVersion'           -PropertyType String -Value $prod -Force | Out-Null
    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -PropertyType String -Value $tv   -Force | Out-Null
    $msg = "ProductVersion=$prod; TargetReleaseVersionInfo=$tv"
    if ($doBypass) {
        $moKey = 'HKLM:\SYSTEM\Setup\MoSetup'
        if (-not (Test-Path $moKey)) { New-Item -Path $moKey -Force | Out-Null }
        New-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWord -Force | Out-Null
        $msg += '; CPU/TPM BYPASS SET (MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU=1)'
    }
    $msg
}

# loop32 (F6): CANONICAL Diagnose one-word verdict from the report markers. The verdict is the
# operator's GO/NO-GO signal, and it used to check ONLY CPU/TPM/[BLOCK]/policy - it IGNORED the
# [FAIL] Disk / [FAIL] RAM / [FAIL] Secure Boot lines its own scan reported, so a disk-short host
# read READY and the upgrade later failed on disk. Now those hardware/capacity fails yield a
# distinct NOT READY (inserted after NEEDS POLICY, before READY - only reclassifies falsely-READY
# hosts). The runspace worker mirrors this inline (module-less runspace, can't call this fn); keep
# in lockstep. Pure - tested by Winupgrade.DiagnoseVerdict.Tests.ps1.
function Get-WinUpgradeDiagnoseVerdict {
    param([string]$Report, [string]$Version = '24H2')
    $on24     = ($Report -match '(?m)^\[PASS\] Already on ')
    $cpuFail  = ($Report -match '(?m)^\[FAIL\] CPU')
    $tpmFail  = ($Report -match '(?m)^\[FAIL\] TPM')
    $bypassOn = ($Report -match '(?m)^\[INFO\] CPU/TPM Bypass : ACTIVE')
    $hasBlock = ($Report -match '(?m)^\[BLOCK\]')
    $policyOk = ($Report -match '(?m)^\[PASS\] Target Release Policy')
    $diskFail = ($Report -match '(?m)^\[FAIL\] Disk')
    $ramFail  = ($Report -match '(?m)^\[FAIL\] RAM')
    $sbFail   = ($Report -match '(?m)^\[FAIL\] Secure Boot')
    if     ($on24)                                       { return "ON $Version" }
    elseif (($cpuFail -or $tpmFail) -and -not $bypassOn) { return 'HW INCOMPAT' }
    elseif ($hasBlock)                                   { return 'BLOCKED' }
    elseif (-not $policyOk)                              { return 'NEEDS POLICY' }
    elseif ($diskFail -or $ramFail -or $sbFail)          { return 'NOT READY' }
    else                                                 { return 'READY' }
}

$script:WinUpgradeWorker = {
    param(
        [string]$Computer,
        [string]$Op,            # Pin | Unpin | InstallCab | CheckUpgrade | SetPageFile | Ping | Diagnose | ForceDiscovery
        $Cred,                  # PSCredential or $null
        [string]$Product,
        [string]$Version,
        [string]$CabPath,
        [string]$CabName,
        [bool]$CabFromShare,    # $true when CabPath is an operator-typed UNC share (target pulls it)
        [bool]$Reboot,
        [bool]$AttemptOffline,
        [bool]$DryRun,
        [bool]$RunWu,           # Pin: also kick a Windows Update scan after writing the policy
        [int]$SizeMb,           # SetPageFile: fixed C: page-file size in MB
        $CancelJob,             # synchronized hashtable with a 'Cancel' flag, or $null
        $StepQueue,             # ConcurrentQueue for live phase steps (Copying/DISM/Rebooting), or $null
        # --- v0.3.0 appended params (kept at the END so existing positional args are unshifted) ---
        [bool]$Aggressive,      # ForceDiscovery: aggressive WU reset (stop svcs, rename caches, re-reg DLLs)
        [bool]$Bypass,          # Pin: also set the MoSetup CPU/TPM upgrade bypass value = 1
        [bool]$SccmRefresh,     # Pin: also trigger the SCCM client schedule cycles
        [bool]$RemoveBypass,    # Unpin: also remove the MoSetup CPU/TPM bypass value
        $CpuPatterns,           # Diagnose: supported-CPU regex array (reference lines 40-52)
        [int]$MinRAM,           # Diagnose: minimum RAM GB (4)
        [int]$MinDisk,          # Diagnose: minimum free disk GB (64)
        [string]$MinTPM,        # Diagnose: minimum TPM version ("2.0")
        $Cycles,                # ForceDiscovery/Pin SCCM refresh: SCCM client schedule GUID array
        # --- upgrade-drive appended params (kept at the END so existing positional args are unshifted) ---
        [bool]$RebootWhenStaged,# UpgradeDrive: reboot a CONFIRMED-staged host on a countdown
        [int]$CountdownSeconds, # UpgradeDrive: per-host reboot countdown seconds
        $PinBlock,              # shared pin policy-write scriptblock (reused by Pin + UpgradeDrive)
        # --- v0.4.0 appended params (kept at the END so existing positional args are unshifted;
        #     DEFAULTS matter: the Drive test drives the worker with only the pre-v0.4.0 args, so
        #     $MinBuild MUST default to 26100 to preserve the 24H2 build gate) ---
        [int]$MinBuild = 26100, # Diagnose/FleetStatus/UpgradeDrive/AutoFix/ErrorReport: target build gate
        [bool]$FixPolicy = $false,   # AutoFix: write the target-release policy where missing/half-written
        [bool]$FixBypass = $false,   # AutoFix: set the CPU/TPM bypass only where hardware is unsupported
        [bool]$FixDrivers = $false,  # AutoFix: remove drivers that failed injection per this device's logs
        [bool]$DriverSafe = $false,  # AutoFix: skip driver removal when the device is currently connected
        [bool]$FixPause = $false,    # AutoFix: clear EXPIRED pause values (active pauses respected)
        [bool]$FixRepair = $false,   # AutoFix: DISM/SFC repair only where setup logs show corruption
        [bool]$ClearStaging = $false,# AutoFix: delete a stale rolled-back $WINDOWS.~BT to reclaim disk
        # --- v0.5.0 appended params (kept at the END so existing positional args are unshifted;
        #     the pre-v0.5.0 Drive test drives the worker with only 28 args, so these all DEFAULT) ---
        [bool]$IncludeMU = $true,    # InstallUpdates: driver also searches Windows/Microsoft Update
        [bool]$AllowHttp = $true,    # InstallUpdates: allow WinRM HTTP 5985 fallback
        [bool]$AllowWmi = $true,     # InstallUpdates: allow WMI/DCOM 135 fallback
        [int]$TimeoutMin = 45,       # InstallUpdates: per-host result.json poll timeout (minutes)
        $WuaDriver = ''              # InstallUpdates: the SYSTEM WUA driver text (#__INCLUDEMU__# unreplaced)
    )

    $r = [ordered]@{ Host = $Computer; Ping = ''; Status = ''; Detail = ''; Ok = $false; Report = '' }
    $isCancelled = { if ($CancelJob) { try { [bool]$CancelJob['Cancel'] } catch { $false } } else { $false } }
    # enqueue a live phase step the harvest loop streams as a row (parity with pkginstall).
    $pushStep = { param($step, $detail) if ($StepQueue) { try { [void]$StepQueue.Enqueue([pscustomobject]@{ Hostname=$Computer; Step=$step; Detail=$detail }) } catch {} } }

    # Read-back of the three WUfB pin policy values (marker: PINREAD). Pin uses it to
    # CONFIRM the write stuck (a GPO refresh can re-overwrite it, or the write can be
    # silently rejected); Unpin uses it to CONFIRM the values are actually gone (a
    # silently-failed Remove-ItemProperty must not report "removed"). Read-only and
    # self-contained so it serializes into a bare pool runspace (no module scope).
    $pinReadSb = {
        $rp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'   # marker:PINREAD
        $p  = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        $names = if ($p) { @($p.PSObject.Properties.Name) } else { @() }
        [pscustomobject]@{
            KeyPresent               = [bool]$p
            TargetReleaseVersion     = $(if ($names -contains 'TargetReleaseVersion') { $p.TargetReleaseVersion } else { $null })
            ProductVersion           = $(if ($names -contains 'ProductVersion') { [string]$p.ProductVersion } else { '' })
            TargetReleaseVersionInfo = $(if ($names -contains 'TargetReleaseVersionInfo') { [string]$p.TargetReleaseVersionInfo } else { '' })
            HasTRV                   = ($names -contains 'TargetReleaseVersion')
            HasProduct               = ($names -contains 'ProductVersion')
            HasInfo                  = ($names -contains 'TargetReleaseVersionInfo')
        }
    }

    if (& $isCancelled) { $r.Status = 'Cancelled'; $r.Detail = 'cancelled before start'; return $r }

    # ---- reachability pre-check: pure-TCP probe (AFNET-safe; never ICMP). Loop
    # WinRM 5985, then WinRM HTTPS 5986, then SMB 445, TcpClient.BeginConnect with a
    # 1500ms connect timeout, break on first connect. (mirrors the wpt ping-sweep
    # TcpClient.BeginConnect probe.) $useSsl tracks whether ONLY 5986 answered, so
    # every session/command dial below auto-switches to -UseSSL (HTTP 5985 stays
    # preferred when both are open; SMB 445 is a liveness signal only).
    $online = $false; $useSsl = $false
    foreach ($port in 5985, 5986, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $online = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($online) { break }
    }
    if (-not $online) { $r.Ping = 'Unreachable' }

    if ($Op -eq 'Ping') {
        if ($online) { $r.Status = 'Online';  $r.Detail = "Reachable ($($r.Ping))"; $r.Ok = $true }
        else         { $r.Status = 'Offline'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts)' }
        return $r
    }

    if (-not $online -and -not $AttemptOffline) {
        $r.Status = 'Skipped'; $r.Detail = 'Offline (TCP 5985/5986/445 unreachable). Enable "Attempt even if offline" to force.'
        return $r
    }

    $credSet  = ($null -ne $Cred)
    $authNote = if ($credSet) { "as $($Cred.UserName)" } else { 'current session' }

    try {
        switch ($Op) {

            'Pin' {
                if ($DryRun) {
                    $wouldParts = @("pin to $Product $Version")
                    if ($Bypass)      { $wouldParts += 'apply the CPU/TPM bypass (MoSetup)' }
                    if ($RunWu)       { $wouldParts += 'trigger a Windows Update scan' }
                    if ($SccmRefresh) { $wouldParts += 'refresh the SCCM client' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would $([string]::Join(', ', $wouldParts)) ($authNote)."; $r.Ok = $true; break
                }
                $pinNote = if ($Bypass) { "Writing TargetReleaseVersion policy ($Product $Version) + CPU/TPM bypass..." } else { "Writing TargetReleaseVersion policy ($Product $Version)..." }
                & $pushStep 'Pinning' $pinNote
                # REUSE the shared module-scope pin policy-write ($PinBlock) - the same
                # write the 'upgrade-drive' action pins with. $doBypass is the last remote
                # param() arg (matches the call-site ArgumentList order).
                $sb = $PinBlock
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($Version,$Product,$Bypass); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $out = Invoke-Command @ic
                $detailParts = @("Pinned: $out")
                # VERIFY the pin actually stuck: re-read the three policy values on the target
                # and confirm they match what we intended. A GPO refresh could re-overwrite
                # them, or the client could silently reject the write - either way that must
                # NOT report DONE (audit: "reports success without verifying").
                $icv = @{ ComputerName=$Computer; ScriptBlock=$pinReadSb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $icv.Credential = $Cred }
                if ($useSsl) { $icv['UseSSL'] = $true }
                $rb = $null
                try { $rb = Invoke-Command @icv } catch { $rb = $null }
                $pinOk = ($null -ne $rb -and [int]$rb.TargetReleaseVersion -eq 1 -and "$($rb.ProductVersion)" -eq "$Product" -and "$($rb.TargetReleaseVersionInfo)" -eq "$Version")
                if (-not $pinOk) {
                    $rbNote = if ($rb) { "read-back TRV=$($rb.TargetReleaseVersion) ProductVersion='$($rb.ProductVersion)' TargetReleaseVersionInfo='$($rb.TargetReleaseVersionInfo)'" } else { 'policy key not readable after write' }
                    $r.Status = 'FAILED'; $r.Ok = $false
                    $r.Detail = "Pinned: $out | PIN NOT VERIFIED - policy did not read back as $Product $Version ($rbNote); a GPO refresh may have re-overwritten it or the write was rejected."
                    break
                }
                # "Then run Windows Update": optionally kick the WU agent so the pinned build
                # is detected/offered without waiting for the next scheduled scan. Best-effort -
                # a trigger failure never fails the pin (the policy is already written).
                if ($RunWu) {
                    & $pushStep 'Scanning' 'Pinned; triggering a Windows Update scan...'
                    $wuSb = {
                        try { Start-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\' -TaskName 'Scheduled Start' -ErrorAction Stop; 'WU scan triggered (Scheduled Start task)' }
                        catch {
                            $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
                            if (Test-Path -LiteralPath $uso) { Start-Process -FilePath $uso -ArgumentList 'StartScan' -WindowStyle Hidden; 'WU scan triggered (UsoClient StartScan)' }
                            else { 'WU scan NOT triggered (no Scheduled Start task / UsoClient on this build)' }
                        }
                    }
                    $icw = @{ ComputerName=$Computer; ScriptBlock=$wuSb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                    if ($credSet) { $icw.Credential = $Cred }
                    if ($useSsl) { $icw['UseSSL'] = $true }
                    $wuOut = ''
                    try { $wuOut = [string](Invoke-Command @icw) } catch { $wuOut = "WU trigger error: $($_.Exception.Message)" }
                    $detailParts += $wuOut
                }
                # Optional SCCM/MECM client refresh: trigger the client schedule cycles (ported
                # from $sbApply) so an assigned Software Center deployment surfaces. Best-effort -
                # a trigger failure never fails the pin. $cycles passed as ONE positional arg
                # via @(,$Cycles) so the GUID array is not splatted into many params.
                if ($SccmRefresh) {
                    & $pushStep 'SCCM' 'Pinned; triggering SCCM client schedule cycles...'
                    $sccmSb = {
                        param($cycles)
                        try {
                            $svc = Get-Service -Name CcmExec -ErrorAction Stop
                            if ($svc.Status -eq 'Running') {
                                foreach ($id in $cycles) {
                                    try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID=$id } -ErrorAction Stop | Out-Null } catch { }
                                }
                                'SCCM client cycles triggered'
                            } else { 'SCCM client present but not running' }
                        } catch { 'SCCM client (CcmExec) not found' }
                    }
                    $ics = @{ ComputerName=$Computer; ScriptBlock=$sccmSb; ArgumentList=@(,$Cycles); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                    if ($credSet) { $ics.Credential = $Cred }
                    if ($useSsl) { $ics['UseSSL'] = $true }
                    $sccmOut = ''
                    try { $sccmOut = [string](Invoke-Command @ics) } catch { $sccmOut = "SCCM refresh error: $($_.Exception.Message)" }
                    $detailParts += $sccmOut
                }
                $detailParts += 'Reboot target, then run Check for updates.'
                $r.Status = 'DONE'; $r.Detail = ($detailParts -join ' | '); $r.Ok = $true
            }

            'Unpin' {
                if ($DryRun) {
                    $wouldU = if ($RemoveBypass) { 'Would remove the Target Release Version policy AND the CPU/TPM bypass key' } else { 'Would remove the Target Release Version policy' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "$wouldU ($authNote)."; $r.Ok = $true; break
                }
                $unpinNote = if ($RemoveBypass) { 'Removing TargetReleaseVersion policy + CPU/TPM bypass...' } else { 'Removing TargetReleaseVersion policy...' }
                & $pushStep 'Unpinning' $unpinNote
                # $removeBypass appended at the END of the remote param() (matches the call-site
                # ArgumentList order). Bypass removal copied EXACTLY from the reference $sbClear
                # (lines 851-858): key HKLM:\SYSTEM\Setup\MoSetup, value AllowUpgradesWithUnsupportedTPMOrCPU.
                $sb = {
                    param($removeBypass)
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                    if (Test-Path $regPath) {
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'ProductVersion'           -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -ErrorAction SilentlyContinue
                        # If the key holds no real (non-PS*) values after removal, drop it. The
                        # AUTHORITATIVE removed/not-removed decision is the caller's read-back
                        # against the three specific pin value names - NOT this heuristic.
                        $remaining = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).PSObject.Properties |
                            Where-Object { $_.Name -notlike 'PS*' }
                        if (-not $remaining) {
                            Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                            $msg = 'removal attempted; WindowsUpdate policy key was empty and was deleted'
                        } else {
                            $msg = 'removal attempted; other policy values kept'
                        }
                    } else {
                        $msg = 'policy key not present (nothing to remove)'
                    }
                    if ($removeBypass) {
                        $moKey = 'HKLM:\SYSTEM\Setup\MoSetup'
                        if (Test-Path $moKey) {
                            $moVal = Get-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -ErrorAction SilentlyContinue
                            if ($moVal -and $moVal.AllowUpgradesWithUnsupportedTPMOrCPU -eq 1) {
                                Remove-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -ErrorAction SilentlyContinue
                                $msg += '; bypass key removed'
                            } else { $msg += '; bypass was not set' }
                        } else { $msg += '; bypass was not set' }
                    }
                    $msg
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($RemoveBypass); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $out = Invoke-Command @ic
                # VERIFY removal: re-read the three SPECIFIC pin value names on the target and
                # confirm they are actually gone. Remove-ItemProperty -EA SilentlyContinue can
                # fail silently (ACL / GPO re-write), so "removed" must be gated on the read-back
                # (audit: "reports success without verifying").
                $icv = @{ ComputerName=$Computer; ScriptBlock=$pinReadSb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $icv.Credential = $Cred }
                if ($useSsl) { $icv['UseSSL'] = $true }
                $rb = $null
                try { $rb = Invoke-Command @icv } catch { $rb = $null }
                if ($null -eq $rb) {
                    $r.Status = 'FAILED'; $r.Ok = $false
                    $r.Detail = "$out | REMOVAL NOT VERIFIED - could not re-read the policy key to confirm the pin is gone."
                    break
                }
                $stillSet = @()
                if ($rb.HasTRV)     { $stillSet += 'TargetReleaseVersion' }
                if ($rb.HasProduct) { $stillSet += 'ProductVersion' }
                if ($rb.HasInfo)    { $stillSet += 'TargetReleaseVersionInfo' }
                if ($stillSet.Count -eq 0) {
                    $r.Status = 'DONE'; $r.Detail = "$out"; $r.Ok = $true
                } else {
                    $r.Status = 'FAILED'; $r.Ok = $false
                    $r.Detail = "$out | PIN NOT REMOVED - still present after removal: $([string]::Join(', ', $stillSet)) (the pin may still be active)."
                }
            }

            'InstallCab' {
                if ($DryRun) {
                    $rb = if ($Reboot) { 'then reboot (10s)' } else { 'no reboot' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would copy $CabName to C:\Temp and run DISM /Add-Package; $rb ($authNote)."; $r.Ok = $true; break
                }
                # OperationTimeout 0 = no per-operation cap (DISM can run for minutes).
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $sp = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $sp.Credential = $Cred }
                if ($useSsl) { $sp['UseSSL'] = $true }
                $session = New-PSSession @sp
                try {
                    & $pushStep 'Copying' "Copying $CabName to C:\Temp on the target..."
                    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                        if (-not (Test-Path -Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -ErrorAction Stop | Out-Null }
                    }
                    # When the operator typed a UNC share path, have the TARGET pull the package
                    # from the share inside the session (operator credential) instead of base64-
                    # streaming it from the admin box over WS-Man - the latter saturates the admin
                    # uplink under parallel installs. The share->target hop is a second hop, so on
                    # ANY error (e.g. Negotiate double-hop) fall back to the proven -ToSession push
                    # so behavior is never worse than before.
                    $pulledFromShare = $false
                    if ($CabFromShare) {
                        try {
                            Invoke-Command -Session $session -ArgumentList $CabPath, $CabName -ErrorAction Stop -ScriptBlock {
                                param($src, $nm)
                                Copy-Item -LiteralPath $src -Destination (Join-Path 'C:\Temp' $nm) -Force -ErrorAction Stop
                            }
                            $pulledFromShare = $true
                        } catch { $pulledFromShare = $false }
                    }
                    if (-not $pulledFromShare) {
                        Copy-Item -Path $CabPath -Destination 'C:\Temp\' -ToSession $session -Force -ErrorAction Stop
                    }

                    & $pushStep 'DISM' 'DISM /Online /Add-Package (this can run for minutes)...'
                    $res = Invoke-Command -Session $session -ArgumentList $CabName -ScriptBlock {
                        param($name)
                        $cab = Join-Path 'C:\Temp' $name
                        $o = @{ ExitCode = $null; Output = ''; Error = '' }
                        try {
                            $psi = New-Object System.Diagnostics.ProcessStartInfo
                            $psi.FileName               = 'dism.exe'
                            $psi.Arguments              = "/Online /Add-Package /PackagePath:`"$cab`" /Quiet /NoRestart"
                            $psi.UseShellExecute        = $false
                            $psi.RedirectStandardOutput = $true
                            $psi.RedirectStandardError  = $true
                            $psi.CreateNoWindow         = $true
                            $proc = [System.Diagnostics.Process]::Start($psi)
                            $stdout = $proc.StandardOutput.ReadToEnd()
                            $stderr = $proc.StandardError.ReadToEnd()
                            $proc.WaitForExit()
                            $o.ExitCode = $proc.ExitCode
                            $o.Output   = ($stdout + $stderr).Trim()
                        } catch { $o.Error = $_.Exception.Message }
                        return $o
                    }

                    if ($res.Error) {
                        $r.Status = 'FAILED'; $r.Detail = "DISM launch error: $($res.Error)"
                    }
                    elseif ($res.ExitCode -eq 0 -or $res.ExitCode -eq 3010) {
                        # exit 3010 = package staged but a reboot is REQUIRED to activate it; exit 0
                        # = fully applied, no reboot needed. A staged-but-not-rebooted box, or a box
                        # whose reboot failed to issue, is NOT really DONE - it gets the distinct
                        # 'NEEDS REBOOT' status (Ok stays $true: the package is installed) so the
                        # operator does not mistake an amber "still needs a manual reboot" box for a
                        # finished green one when scanning a large fleet.
                        $needsReboot = ($res.ExitCode -eq 3010)
                        $note = if ($needsReboot) { 'installed (reboot required)' } else { 'installed (exit 0)' }
                        if ($Reboot -and -not (& $isCancelled)) {
                            & $pushStep 'Rebooting' 'Install OK; issuing reboot (10s)...'
                            # DNS-mismatch guard: mirror the upgrade-drive reboot (~1298-1307).
                            # An IPv4-literal target has no shortname to compare -> pass '' to skip.
                            $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
                            # Delayed reboot via shutdown.exe (ProcessStartInfo so we capture its
                            # real exit code); /t 10 lets the WinRM call return before the box drops.
                            try {
                                $rbres = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $expectedName -ScriptBlock {
                                    param($expected)
                                    $o = @{ ExitCode = $null; Error = '' }
                                    # DNS-mismatch guard (HARD ABORT): the box that answered runs this,
                                    # so $env:COMPUTERNAME IS the real machine; if it isn't the one we
                                    # dialed (stale DNS / reused IP), abort before shutdown.
                                    if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                                        $o.Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no reboot sent"
                                        return $o
                                    }
                                    try {
                                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                                        $psi.FileName               = 'shutdown.exe'
                                        $psi.Arguments              = '/r /t 10 /f /c "JANET Web Windows Upgrade: feature update installed"'
                                        $psi.UseShellExecute        = $false
                                        $psi.RedirectStandardOutput = $true
                                        $psi.RedirectStandardError  = $true
                                        $psi.CreateNoWindow         = $true
                                        $proc = [System.Diagnostics.Process]::Start($psi)
                                        $sout = $proc.StandardOutput.ReadToEnd()
                                        $serr = $proc.StandardError.ReadToEnd()
                                        $proc.WaitForExit()
                                        $o.ExitCode = $proc.ExitCode
                                        if ($proc.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                                    } catch { $o.Error = $_.Exception.Message }
                                    return $o
                                }
                                if ($rbres.ExitCode -eq 0) { $r.Status = 'DONE'; $r.Detail = "$CabName $note; reboot issued (10s)"; $r.Ok = $true }
                                else { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note; REBOOT FAILED (shutdown exit $($rbres.ExitCode)): $($rbres.Error)"; $r.Ok = $true }
                            } catch {
                                $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note; REBOOT FAILED to issue: $($_.Exception.Message)"; $r.Ok = $true
                            }
                        }
                        elseif ($Reboot -and (& $isCancelled)) {
                            if ($needsReboot) { $r.Status = 'NEEDS REBOOT' } else { $r.Status = 'DONE' }
                            $r.Detail = "$CabName $note; REBOOT SKIPPED (cancelled)"; $r.Ok = $true
                        }
                        else {
                            if ($needsReboot) { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note"; $r.Ok = $true }
                            else { $r.Status = 'DONE'; $r.Detail = "$CabName $note"; $r.Ok = $true }
                        }
                    }
                    else {
                        $msg = [string]$res.Output
                        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) }
                        $r.Status = 'FAILED'; $r.Detail = "DISM exit $($res.ExitCode): $msg"
                    }
                }
                finally {
                    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
                }
            }

            'CheckUpgrade' {
                # Read-only: pull setuperr.log from the failed in-place upgrade and classify it.
                # DryRun is meaningless here (nothing is changed), so it always just reads.
                & $pushStep 'Reading' 'Reading setuperr.log...'
                $sb = {
                    $log = 'C:\$WINDOWS.~BT\Sources\Panther\setuperr.log'
                    if (-not (Test-Path -LiteralPath $log)) { return [pscustomobject]@{ Code = 'NOLOG'; Line = '' } }
                    # setuperr.log can be held open during an in-flight upgrade; open shared.
                    $text = ''
                    $sr = $null
                    try {
                        $fs = [System.IO.File]::Open($log, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        try { $sr = New-Object System.IO.StreamReader($fs); $text = $sr.ReadToEnd() } finally { if ($sr) { $sr.Dispose() }; $fs.Dispose() }
                    } catch {
                        try { $text = Get-Content -LiteralPath $log -Raw -ErrorAction Stop } catch { return [pscustomobject]@{ Code = 'READERR'; Line = $_.Exception.Message } }
                    }
                    if ([string]::IsNullOrWhiteSpace($text)) { return [pscustomobject]@{ Code = 'CLEAN'; Line = '' } }
                    $lines = @($text -split '\r?\n' | Where-Object { $_ -match '\S' })
                    # Out-of-memory build failure the page-file fix resolves: E_OUTOFMEMORY 0x8007000E,
                    # or an explicit out/insufficient-memory phrase in a setup error line.
                    $oom = $lines | Where-Object { $_ -match '0x8007000E' -or $_ -match '(?i)out of memory' -or $_ -match '(?i)insufficient memory' } | Select-Object -Last 1
                    if ($oom) { return [pscustomobject]@{ Code = 'OOM'; Line = ([string]$oom).Trim() } }
                    return [pscustomobject]@{ Code = 'ERRORS'; Line = ([string]($lines | Select-Object -Last 1)).Trim() }
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $res = Invoke-Command @ic
                $line = [string]$res.Line
                if ($line.Length -gt 300) { $line = $line.Substring(0, 300) }
                switch ([string]$res.Code) {
                    'OOM'     { $r.Status = 'MEMORY'; $r.Detail = "Out-of-memory build failure (0x8007000E) - run Set Page File, then re-run the upgrade. $line"; $r.Ok = $true }
                    'ERRORS'  { $r.Status = 'ERRORS'; $r.Detail = "setuperr.log last error: $line"; $r.Ok = $true }
                    'CLEAN'   { $r.Status = 'CLEAN';  $r.Detail = 'setuperr.log present, no error lines.'; $r.Ok = $true }
                    'NOLOG'   { $r.Status = 'NO LOG'; $r.Detail = 'No C:\$WINDOWS.~BT\Sources\Panther\setuperr.log (no recent in-place upgrade attempt).'; $r.Ok = $true }
                    'READERR' { $r.Status = 'FAILED'; $r.Detail = "Could not read setuperr.log: $line"; $r.Ok = $false }
                    default   { $r.Status = 'FAILED'; $r.Detail = 'Unknown check result.'; $r.Ok = $false }
                }
            }

            'SetPageFile' {
                $mb = $SizeMb
                if ($mb -lt 1024)   { $mb = 1024 }
                if ($mb -gt 131072) { $mb = 131072 }
                if ($DryRun) {
                    $rb = if ($Reboot) { 'then reboot (10s)' } else { 'no reboot (apply on next restart)' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would disable automatic page-file management and set C: page file to $mb MB (fixed); $rb ($authNote)."; $r.Ok = $true; break
                }
                & $pushStep 'PageFile' "Disabling auto-manage and setting C: page file to $mb MB..."
                $sb = {
                    param($mb)
                    $notes = New-Object System.Collections.ArrayList
                    $cs = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges -ErrorAction Stop
                    if ($cs.AutomaticManagedPagefile) {
                        $cs.AutomaticManagedPagefile = $false
                        [void]$cs.Put()
                        [void]$notes.Add('automatic management disabled')
                    } else {
                        [void]$notes.Add('automatic management already off')
                    }
                    # -EnableAllPrivileges on BOTH WMI calls: page-file create/resize needs
                    # SeCreatePagefilePrivilege, which WMI leaves present-but-disabled in the
                    # token unless explicitly enabled - without it the Put()/create fails
                    # access-denied AFTER auto-manage was already turned off (worst case: no
                    # usable page file at next boot).
                    $pf = Get-WmiObject -Class Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'" -EnableAllPrivileges -ErrorAction SilentlyContinue
                    if (-not $pf) {
                        [void](Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{ Name = 'C:\pagefile.sys'; InitialSize = $mb; MaximumSize = $mb } -EnableAllPrivileges -ErrorAction Stop)
                        [void]$notes.Add("created C: page file at $mb MB")
                    } else {
                        $pf.InitialSize = $mb
                        $pf.MaximumSize = $mb
                        [void]$pf.Put()
                        [void]$notes.Add("C: page file set to $mb MB (fixed)")
                    }
                    ($notes -join '; ')
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 120000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($mb); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $out = [string](Invoke-Command @ic)
                if ($Reboot -and -not (& $isCancelled)) {
                    & $pushStep 'Rebooting' 'Page file set; issuing reboot (10s)...'
                    try {
                        $icr = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                        if ($credSet) { $icr.Credential = $Cred }
                        if ($useSsl) { $icr['UseSSL'] = $true }
                        # DNS-mismatch guard: mirror the upgrade-drive reboot (~1298-1307).
                        # An IPv4-literal target has no shortname to compare -> pass '' to skip.
                        $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
                        $rbres = Invoke-Command @icr -ArgumentList $expectedName -ScriptBlock {
                            param($expected)
                            $o = @{ ExitCode = $null; Error = '' }
                            # DNS-mismatch guard (HARD ABORT): the box that answered runs this, so
                            # $env:COMPUTERNAME IS the real machine; if it isn't the one we dialed
                            # (stale DNS / reused IP), abort before shutdown.
                            if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                                $o.Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no reboot sent"
                                return $o
                            }
                            try {
                                $psi = New-Object System.Diagnostics.ProcessStartInfo
                                $psi.FileName               = 'shutdown.exe'
                                $psi.Arguments              = '/r /t 10 /f /c "JANET Web Windows Upgrade: page file resized"'
                                $psi.UseShellExecute        = $false
                                $psi.RedirectStandardOutput = $true
                                $psi.RedirectStandardError  = $true
                                $psi.CreateNoWindow         = $true
                                $proc = [System.Diagnostics.Process]::Start($psi)
                                $sout = $proc.StandardOutput.ReadToEnd()
                                $serr = $proc.StandardError.ReadToEnd()
                                $proc.WaitForExit()
                                $o.ExitCode = $proc.ExitCode
                                if ($proc.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                            } catch { $o.Error = $_.Exception.Message }
                            return $o
                        }
                        if ($rbres.ExitCode -eq 0) { $r.Status = 'DONE'; $r.Detail = "$out; reboot issued (10s)"; $r.Ok = $true }
                        else { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT FAILED (shutdown exit $($rbres.ExitCode)): $($rbres.Error). Reboot manually to apply."; $r.Ok = $true }
                    } catch {
                        $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT FAILED to issue: $($_.Exception.Message). Reboot manually to apply."; $r.Ok = $true
                    }
                }
                elseif ($Reboot -and (& $isCancelled)) {
                    $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT SKIPPED (cancelled). Reboot manually to apply."; $r.Ok = $true
                }
                else {
                    $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; reboot required to apply the new size."; $r.Ok = $true
                }
            }

            { ($_ -eq 'Diagnose') -or ($_ -eq 'FleetStatus') -or ($_ -eq 'UpgradeDrive') } {
                # Read-only comprehensive 24H2 compatibility + WU health scan. ONE remote
                # scan, SHARED by both the Diagnose verdict action and the Fleet Status board
                # (no second scanner) - $Op decides only how the returned data is shaped.
                # The remote scriptblock body is ported VERBATIM from the desktop $sbDiagnostic
                # (References\24h2script.ps1 lines 352-638); it returns a multi-line report
                # string. DryRun is meaningless (nothing changes) so it always just reads.
                # Constants fed via the appended worker params ($CpuPatterns/$MinRAM/$MinDisk/$MinTPM).
                & $pushStep 'Scanning' 'Running read-only diagnostic scan...'
                $sb = {
                    param($cpuPatterns, $minRAM, $minDisk, $minTPM, $minBuild, $target)
                    $lines = @()

                    # ===== SECTION: SYSTEM INFO =====
                    $lines += "=== SYSTEM INFO ==="
                    $os = Get-CimInstance Win32_OperatingSystem
                    $cs = Get-CimInstance Win32_ComputerSystem
                    $lines += "[INFO] Hostname    : $($env:COMPUTERNAME)"
                    $lines += "[INFO] OS          : $($os.Caption) (Build $($os.BuildNumber))"
                    $lines += "[INFO] Model       : $($cs.Manufacturer) $($cs.Model)"

                    # Already on the target build?  (v0.4.0: $minBuild/$target replace the
                    # hardcoded 26100 / '24H2' - default 24H2/26100 keeps the strings identical.)
                    if ([int]$os.BuildNumber -ge $minBuild) {
                        $lines += "[PASS] Already on $target or newer (Build $($os.BuildNumber)) - no action needed"
                    } else {
                        $lines += "[INFO] Not yet on $target (current build $($os.BuildNumber), need $minBuild+)"
                    }

                    # ===== SECTION: HARDWARE COMPATIBILITY =====
                    $lines += ""
                    $lines += "=== HARDWARE COMPATIBILITY ==="

                    # CPU
                    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
                    $cpuSupported = $false
                    foreach ($pattern in $cpuPatterns) {
                        if ($cpu -match $pattern) { $cpuSupported = $true; break }
                    }
                    if ($cpuSupported) { $lines += "[PASS] CPU         : $cpu" }
                    else { $lines += "[FAIL] CPU         : $cpu (not in supported list - bypass may be needed)" }

                    # TPM
                    $tpmPass = $false; $tpmVer = "Not found"
                    try {
                        $tpm = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
                        if ($tpm) {
                            $tpmVer = ($tpm.SpecVersion -split ",")[0].Trim()
                            if ([version]$tpmVer -ge [version]$minTPM) { $tpmPass = $true }
                        }
                    } catch { }
                    if ($tpmPass) { $lines += "[PASS] TPM         : v$tpmVer" }
                    else { $lines += "[FAIL] TPM         : v$tpmVer (need $minTPM+ - bypass may be needed)" }

                    # Secure Boot
                    $sbPass = $false
                    try { $sbState = Confirm-SecureBootUEFI -ErrorAction Stop; $sbPass = $sbState -eq $true } catch { }
                    if ($sbPass) { $lines += "[PASS] Secure Boot : Enabled" }
                    else { $lines += "[FAIL] Secure Boot : Disabled or unsupported" }

                    # RAM
                    $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                    if ($ramGB -ge $minRAM) { $lines += "[PASS] RAM         : ${ramGB} GB (need ${minRAM}+ GB)" }
                    else { $lines += "[FAIL] RAM         : ${ramGB} GB (need ${minRAM}+ GB)" }

                    # Disk
                    $sysDrive = $env:SystemDrive
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
                    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
                    $totalGB = [math]::Round($disk.Size / 1GB, 1)
                    if ($freeGB -ge $minDisk) { $lines += "[PASS] Disk        : ${freeGB} GB free / ${totalGB} GB total on $sysDrive" }
                    else { $lines += "[FAIL] Disk        : ${freeGB} GB free / ${totalGB} GB total on $sysDrive (need ${minDisk}+ GB free)" }

                    # ===== SECTION: REGISTRY STATE =====
                    $lines += ""
                    $lines += "=== REGISTRY STATE ==="

                    # Target release version policy. A HALF-WRITTEN pin (TargetReleaseVersion=1
                    # but ProductVersion or TargetReleaseVersionInfo empty) is inert - WU treats
                    # it as incomplete; flag [FAIL] and re-apply (mirrors Test-WinUpgradeTrvHalfWritten).
                    $wuPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    $trvHalfWritten = $false
                    if (Test-Path $wuPol) {
                        $p = Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue
                        if ($p.TargetReleaseVersion -eq 1) {
                            if ([string]::IsNullOrWhiteSpace([string]$p.ProductVersion) -or [string]::IsNullOrWhiteSpace([string]$p.TargetReleaseVersionInfo)) {
                                $trvHalfWritten = $true
                                $lines += "[FAIL] Target Release Policy : HALF-WRITTEN (TargetReleaseVersion=1 but Product='$($p.ProductVersion)' Version='$($p.TargetReleaseVersionInfo)') - re-apply the pin"
                            } else {
                                $lines += "[PASS] Target Release Policy : Product=$($p.ProductVersion) Version=$($p.TargetReleaseVersionInfo) (enabled)"
                            }
                        } else {
                            $lines += "[WARN] Target Release Policy : exists but TargetReleaseVersion != 1 (not active)"
                        }
                    } else {
                        $lines += "[WARN] Target Release Policy : NOT SET (Apply will set this)"
                    }

                    # CPU/TPM bypass
                    $moKey = "HKLM:\SYSTEM\Setup\MoSetup"
                    $bypassActive = $false
                    if (Test-Path $moKey) {
                        $moVal = Get-ItemProperty -Path $moKey -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -ErrorAction SilentlyContinue
                        if ($moVal -and $moVal.AllowUpgradesWithUnsupportedTPMOrCPU -eq 1) { $bypassActive = $true }
                    }
                    if ($bypassActive) { $lines += "[INFO] CPU/TPM Bypass : ACTIVE (AllowUpgradesWithUnsupportedTPMOrCPU=1)" }
                    elseif (-not $cpuSupported -or -not $tpmPass) { $lines += "[WARN] CPU/TPM Bypass : NOT SET (hardware failed checks - bypass may be needed)" }
                    else { $lines += "[INFO] CPU/TPM Bypass : Not set (not needed - hardware is compatible)" }

                    # ===== SECTION: DEFERRALS & BLOCKS =====
                    $lines += ""
                    $lines += "=== DEFERRALS & BLOCKS ==="
                    $blockersFound = $false

                    if (Test-Path $wuPol) {
                        # Feature update deferral days
                        $d = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                        if ($d -and $d.DeferFeatureUpdatesPeriodInDays -gt 0) {
                            $lines += "[BLOCK] DeferFeatureUpdatesPeriodInDays = $($d.DeferFeatureUpdatesPeriodInDays) (may delay 24H2)"
                            $blockersFound = $true
                        }

                        # DeferFeatureUpdates flag
                        $dfu = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
                        if ($dfu -and $dfu.DeferFeatureUpdates -eq 1) {
                            $lines += "[BLOCK] DeferFeatureUpdates = 1 (feature updates deferred)"
                            $blockersFound = $true
                        }

                        # DisableDualScan
                        $dds = Get-ItemProperty -Path $wuPol -Name "DisableDualScan" -ErrorAction SilentlyContinue
                        if ($dds -and $dds.DisableDualScan -eq 1) {
                            $lines += "[BLOCK] DisableDualScan = 1 (device cannot check Microsoft Update alongside WSUS)"
                            $blockersFound = $true
                        }

                        # DoNotConnectToWindowsUpdateInternetLocations
                        $noinet = Get-ItemProperty -Path $wuPol -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
                        if ($noinet -and $noinet.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
                            $lines += "[BLOCK] DoNotConnectToWindowsUpdateInternetLocations = 1 (WSUS-only mode)"
                            $blockersFound = $true
                        }

                        # WUServer set (WSUS managed)
                        $wuServer = Get-ItemProperty -Path $wuPol -Name "WUServer" -ErrorAction SilentlyContinue
                        if ($wuServer -and $wuServer.WUServer) {
                            $lines += "[INFO] WSUS Server : $($wuServer.WUServer) (device is WSUS-managed)"
                        }

                        # Paused via policy
                        foreach ($valName in @("PausedFeatureDate","PausedFeatureStatus")) {
                            $pv = Get-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                            if ($pv.$valName) {
                                $lines += "[BLOCK] Policy $valName = $($pv.$valName)"
                                $blockersFound = $true
                            }
                        }
                    }

                    # UX Settings pause. An End/Expiry value whose time is in the PAST is a
                    # LINGERING (expired) pause, not an active block - flag [WARN] EXPIRED, distinct
                    # from an active [BLOCK] with its window shown (mirrors Get-WinUpgradePauseClass).
                    # Each Start is paired with its End/Expiry so a leftover Start value on an
                    # expired window is not mis-reported as a phantom active block. Force Discovery
                    # aggressive mode clears these values.
                    $wuUx = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
                    $expiredPauseFound = $false
                    if (Test-Path $wuUx) {
                        $nowLocal = Get-Date
                        $pausePairs = @(
                            @{ Start='PauseFeatureUpdatesStartTime'; End='PauseFeatureUpdatesEndTime' },
                            @{ Start='PauseUpdatesStartTime';        End='PauseUpdatesExpiryTime' }
                        )
                        foreach ($pair in $pausePairs) {
                            $sv = Get-ItemProperty -Path $wuUx -Name $pair.Start -ErrorAction SilentlyContinue
                            $ev = Get-ItemProperty -Path $wuUx -Name $pair.End   -ErrorAction SilentlyContinue
                            $startVal = if ($sv) { [string]$sv.($pair.Start) } else { '' }
                            $endVal   = if ($ev) { [string]$ev.($pair.End) }   else { '' }
                            if (-not $startVal -and -not $endVal) { continue }
                            $edt = [datetime]::MinValue
                            $endParsed = ($endVal -and [datetime]::TryParse($endVal, [ref]$edt))
                            if ($endParsed -and $edt -lt $nowLocal) {
                                $lines += "[WARN] UX pause $($pair.Start)/$($pair.End) : window EXPIRED (ended $edt) - lingering values, clear + re-trigger (Force Discovery aggressive removes them)"
                                $expiredPauseFound = $true
                            } elseif ($endParsed) {
                                $lines += "[BLOCK] UX pause active until $edt (Start=$startVal End=$endVal)"
                                $blockersFound = $true
                            } else {
                                if ($startVal) { $lines += "[BLOCK] UX\$($pair.Start) = $startVal"; $blockersFound = $true }
                                if ($endVal)   { $lines += "[BLOCK] UX\$($pair.End) = $endVal";     $blockersFound = $true }
                            }
                        }
                        # FlightSettingsMaxPauseDays - not a block itself but relevant
                        $activeHours = Get-ItemProperty -Path $wuUx -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
                        if ($activeHours) {
                            $ahEnd = Get-ItemProperty -Path $wuUx -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
                            $lines += "[INFO] Active Hours : $($activeHours.ActiveHoursStart):00 - $($ahEnd.ActiveHoursEnd):00"
                        }
                    }

                    if (-not $blockersFound) { $lines += "[PASS] No deferrals or policy blocks detected" }

                    # ===== SECTION: WINDOWS UPDATE HEALTH =====
                    $lines += ""
                    $lines += "=== WINDOWS UPDATE HEALTH ==="

                    # WU services
                    foreach ($svcName in @("wuauserv","bits","cryptSvc","UsoSvc")) {
                        try {
                            $svc = Get-Service -Name $svcName -ErrorAction Stop
                            $startType = (Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
                            if ($svc.Status -eq 'Running') {
                                $lines += "[PASS] Service $svcName : Running ($startType)"
                            } elseif ($svc.Status -eq 'Stopped' -and $startType -eq 'Manual') {
                                $lines += "[INFO] Service $svcName : Stopped (Manual start - normal)"
                            } else {
                                $lines += "[WARN] Service $svcName : $($svc.Status) ($startType)"
                            }
                        } catch {
                            $lines += "[WARN] Service $svcName : not found"
                        }
                    }

                    # SoftwareDistribution size
                    $sdPath = "$env:SystemRoot\SoftwareDistribution"
                    if (Test-Path $sdPath) {
                        try {
                            $sdSize = [math]::Round((Get-ChildItem -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
                            if ($sdSize -gt 2000) {
                                $lines += "[WARN] SoftwareDistribution : ${sdSize} MB (large - may need cache clear)"
                            } else {
                                $lines += "[INFO] SoftwareDistribution : ${sdSize} MB"
                            }
                        } catch { $lines += "[INFO] SoftwareDistribution : present (size check failed)" }
                    }

                    # Existing .bak folders from previous resets
                    $baks = Get-ChildItem -Path $env:SystemRoot -Directory -Filter "SoftwareDistribution.bak*" -ErrorAction SilentlyContinue
                    if ($baks.Count -gt 0) {
                        $lines += "[INFO] Previous WU resets : $($baks.Count) SoftwareDistribution.bak folder(s) found"
                    }

                    # Last WU scan time
                    try {
                        $autoUpdate = Get-CimInstance -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" -ClassName CCM_UpdateStatus -ErrorAction Stop | Select-Object -First 1
                        if ($autoUpdate) { $lines += "[INFO] Last SCCM update scan data present" }
                    } catch { }

                    # ===== SECTION: SCCM CLIENT =====
                    $lines += ""
                    $lines += "=== SCCM CLIENT ==="

                    try {
                        $svc = Get-Service -Name CcmExec -ErrorAction Stop
                        if ($svc.Status -eq 'Running') {
                            $lines += "[PASS] SCCM Client : Running"

                            # Client version
                            try {
                                $ccmVer = (Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop).ClientVersion
                                $lines += "[INFO] Client Version : $ccmVer"
                            } catch { }

                            # target-version deployment visibility. v0.4.0: build the SCCM match
                            # pattern list from the target string + its build number instead of the
                            # '24H2' literal (default 24H2/26100 keeps the previous match).
                            try {
                                $sccmPatterns = @([regex]::Escape($target), "Feature update to Windows 11", [string]$minBuild)
                                $updates = Get-CimInstance -Namespace "root\ccm\ClientSDK" -ClassName CCM_SoftwareUpdate -ErrorAction SilentlyContinue |
                                    Where-Object { $u = $_; ($sccmPatterns | Where-Object { $u.Name -match $_ } | Select-Object -First 1) }
                                if ($updates) {
                                    $lines += "[PASS] $target Deployment : VISIBLE in Software Center ($($updates.Count) matching update(s))"
                                    foreach ($u in $updates) {
                                        $evalState = switch ($u.EvaluationState) {
                                            0 {"None"} 1 {"Available"} 2 {"Submitted"} 3 {"Detecting"}
                                            4 {"PreDownload"} 5 {"Downloading"} 6 {"WaitInstall"}
                                            7 {"Installing"} 8 {"PendingSoftReboot"} 9 {"PendingHardReboot"}
                                            10 {"WaitReboot"} 11 {"Verifying"} 12 {"InstallComplete"}
                                            13 {"Error"} 14 {"WaitServiceWindow"} 15 {"WaitUserLogon"}
                                            16 {"WaitUserLogoff"} 17 {"WaitJobUserLogon"} 18 {"WaitUserReconnect"}
                                            19 {"PendingUserLogoff"} 20 {"PendingUpdate"} 21 {"WaitingRetry"}
                                            22 {"WaitPresModeOff"} 23 {"WaitForOrchestration"}
                                            default {"Unknown($($u.EvaluationState))"}
                                        }
                                        $lines += "[INFO]   -> $($u.Name) | State: $evalState | PercentComplete: $($u.PercentComplete)%"
                                    }
                                } else {
                                    $lines += "[WARN] $target Deployment : NOT visible in Software Center"
                                    $lines += "[WARN]   -> Device may not be in the SCCM target collection (server-side fix)"
                                    $lines += "[WARN]   -> Or SCCM policy has not refreshed yet (Apply will trigger refresh)"
                                }
                            } catch {
                                $lines += "[WARN] 24H2 Deployment : Could not query CCM_SoftwareUpdate"
                            }
                        } else {
                            $lines += "[WARN] SCCM Client : present but $($svc.Status)"
                        }
                    } catch {
                        $lines += "[INFO] SCCM Client : not installed (device may not be SCCM-managed)"
                    }

                    # ===== SECTION: STAGING ($WINDOWS.~BT) =====
                    # A leftover C:\$WINDOWS.~BT is NOT proof an upgrade is in progress: a
                    # rolled-back attempt leaves the whole staging tree behind (field batch: 7
                    # boxes with rolled-back staging were all misread as 'in progress - let them
                    # complete'). Report size + age, classify staleness, and NEVER call it 'in
                    # progress' unless a setup process (SetupHost/SetupPrep) is actually running.
                    # Mirrors Get-WinUpgradeStagingClass.
                    $lines += ""
                    $lines += "=== STAGING (`$WINDOWS.~BT) ==="
                    $btPath = 'C:\$WINDOWS.~BT'
                    $btSizeGB = 0; $stagingClass = 'None'
                    if (Test-Path -LiteralPath $btPath) {
                        try { $btSizeGB = [math]::Round((Get-ChildItem -LiteralPath $btPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1GB, 1) } catch { $btSizeGB = 0 }
                        $btItem = Get-Item -LiteralPath $btPath -Force -ErrorAction SilentlyContinue
                        $btAge  = if ($btItem) { $btItem.LastWriteTime } else { $null }
                        $ageHours = if ($btAge) { [math]::Round(((Get-Date) - $btAge).TotalHours, 1) } else { 9999 }
                        # a running setup process = genuinely mid-upgrade
                        $setupProcs = @(Get-Process -Name 'SetupHost','SetupPrep','Windows10UpgraderApp','SetupPlatformTool' -ErrorAction SilentlyContinue)
                        $setupRunning = ($setupProcs.Count -gt 0)
                        # rollback markers in the CURRENT ~BT Panther logs (the only logs describing
                        # this attempt); grep 'rollback|roll back|abort'
                        $rollbackMarker = $false
                        $btPanther = 'C:\$WINDOWS.~BT\Sources\Panther'
                        if (Test-Path -LiteralPath $btPanther) {
                            foreach ($lg in @('setupact.log','setuperr.log')) {
                                $lp = Join-Path $btPanther $lg
                                if (Test-Path -LiteralPath $lp) {
                                    try { if (Select-String -Path $lp -Pattern 'rollback|roll back|abort' -ErrorAction SilentlyContinue | Select-Object -First 1) { $rollbackMarker = $true; break } } catch {}
                                }
                            }
                        }
                        # classify (mirror Get-WinUpgradeStagingClass)
                        if     ($rollbackMarker)  { $stagingClass = 'Stale' }
                        elseif ($setupRunning)    { $stagingClass = 'Active' }
                        elseif ($ageHours -gt 24) { $stagingClass = 'Stale' }
                        else                      { $stagingClass = 'Recent' }
                        $ageTxt = if ($btAge) { "$btAge (${ageHours}h ago)" } else { 'unknown age' }
                        $lines += "[INFO] Staging folder : ${btSizeGB} GB, last modified $ageTxt"
                        if ($setupRunning) { $lines += "[INFO] Setup process : $(($setupProcs | ForEach-Object { $_.Name }) -join ', ') running" }
                        switch ($stagingClass) {
                            'Active' { $lines += "[INFO] Staging state : ACTIVE - a setup process is running (genuinely mid-upgrade)" }
                            'Stale'  {
                                $why = if ($rollbackMarker) { 'rollback markers in the ~BT Panther logs' } else { "older than 24h (${ageHours}h) with no running setup process" }
                                $lines += "[WARN] Stale staging from a rolled-back attempt - nothing is in progress ($why)"
                                $lines += "[REC] Clear C:\`$WINDOWS.~BT to reclaim ~${btSizeGB} GB AFTER fixing the root cause below, then re-trigger"
                            }
                            'Recent' { $lines += "[INFO] Staging state : recent (<24h) with no setup process - may await a reboot; do NOT assume in-progress" }
                        }
                    } else {
                        $lines += "[INFO] No `$WINDOWS.~BT staging folder (no recent in-place upgrade attempt)"
                    }

                    # ===== SECTION: SETUP FAILURE ANALYSIS =====
                    # Parse the CURRENT attempt's setuperr.log against the failure-signature table,
                    # surface driver-injection failures, and read SetupDiag. Only the ~BT\Sources\
                    # Panther logs describe THIS attempt; a C:\Windows\Panther log older than 90 days
                    # (or older than the ~BT log) is from a prior servicing pass - labelled stale and
                    # never parsed for a failure cause. Gated on not-yet-24H2 (no ~BT on a done box).
                    $setupSignatureHit = $false
                    if ([int]$os.BuildNumber -lt $minBuild) {
                        $lines += ""
                        $lines += "=== SETUP FAILURE ANALYSIS ==="
                        $btErr = 'C:\$WINDOWS.~BT\Sources\Panther\setuperr.log'
                        $curErrText = ''; $curErrTime = $null
                        if (Test-Path -LiteralPath $btErr) {
                            $ei = Get-Item -LiteralPath $btErr -Force -ErrorAction SilentlyContinue
                            $curErrTime = if ($ei) { $ei.LastWriteTime } else { $null }
                            $sr = $null
                            try {
                                $fs = [System.IO.File]::Open($btErr, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                                try { $sr = New-Object System.IO.StreamReader($fs); $curErrText = $sr.ReadToEnd() } finally { if ($sr) { $sr.Dispose() }; $fs.Dispose() }
                            } catch { try { $curErrText = Get-Content -LiteralPath $btErr -Raw -ErrorAction Stop } catch { $curErrText = '' } }
                            $lines += "[INFO] Current setuperr.log : ~BT\Sources\Panther (modified $curErrTime)"
                        } else {
                            $lines += "[INFO] No ~BT\Sources\Panther\setuperr.log (no current in-place attempt to analyse)"
                        }
                        # stale-log discrimination for C:\Windows\Panther (never parsed for a cause)
                        $winPantherErr = "$env:SystemRoot\Panther\setuperr.log"
                        if (Test-Path -LiteralPath $winPantherErr) {
                            $wi = Get-Item -LiteralPath $winPantherErr -Force -ErrorAction SilentlyContinue
                            $wTime = if ($wi) { $wi.LastWriteTime } else { $null }
                            $ageDays = if ($wTime) { [math]::Round(((Get-Date) - $wTime).TotalDays, 0) } else { 9999 }
                            $olderThanBt = ($curErrTime -and $wTime -and $wTime -lt $curErrTime)
                            if ($ageDays -gt 90 -or $olderThanBt) {
                                $lines += "[INFO] C:\Windows\Panther\setuperr.log is STALE (modified $wTime, ${ageDays}d old) - prior servicing pass; ignored for failure analysis"
                            } else {
                                $lines += "[INFO] C:\Windows\Panther\setuperr.log present (modified $wTime) - recent, but ~BT is authoritative for the current attempt"
                            }
                        }
                        # --- FAILURE-SIGNATURE TABLE over the CURRENT log (one [FAIL]+[REC] per hit) ---
                        # Mirrors $script:WinUpgradeSetupErrRules / Get-WinUpgradeSetupErrSignatures.
                        if ($curErrText) {
                            $sigRules = @(
                                @{ Patterns=@('0x000003F1','(?i)configuration registry database is corrupt'); Message='registry hive corrupt'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow; if it persists, deeper hive repair.' },
                                @{ Patterns=@('CBS_E_INVALID_PACKAGE','(?i)Failed to enumerate store capabilities'); Message='component store broken'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' },
                                @{ All=@('(?i)FOD inventory','E_INVALIDARG'); Message='component store broken (FOD inventory E_INVALIDARG)'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' },
                                @{ Patterns=@('0x8007000E'); Message='out of memory (E_OUTOFMEMORY)'; Rec='Run Set Page File (fixed 16 GB) on this host, then re-run the feature update.' },
                                @{ All=@('adammigrate\.dll','0x80070002'); Message='AD LDS migration plugin (adammigrate.dll) failing'; Rec='Investigate the AD LDS migration plugin AFTER clearing the other blockers, then re-diagnose.' },
                                @{ Patterns=@('0x800704C7'); Message='setup cancelled (0x800704C7)'; Rec='Cross-check DEFERRALS & BLOCKS - an expired/lingering pause can present as a cancel; clear stale pause values + re-trigger.' }
                            )
                            foreach ($rule in $sigRules) {
                                $hit = $false
                                if ($rule.ContainsKey('All')) {
                                    $hit = $true
                                    foreach ($pp in $rule['All']) { if ($curErrText -notmatch $pp) { $hit = $false; break } }
                                } else {
                                    foreach ($pp in $rule['Patterns']) { if ($curErrText -match $pp) { $hit = $true; break } }
                                }
                                if ($hit) {
                                    $setupSignatureHit = $true
                                    $lines += "[FAIL] Setup failure: $($rule['Message'])"
                                    $lines += "[REC] $($rule['Rec'])"
                                }
                            }
                            if (-not $setupSignatureHit) {
                                $lastErr = @($curErrText -split '\r?\n' | Where-Object { $_ -match '\S' } | Select-Object -Last 1)
                                $le = if ($lastErr.Count -gt 0) { ([string]$lastErr[0]).Trim() } else { '' }
                                if ($le.Length -gt 300) { $le = $le.Substring(0,300) }
                                if ($le) { $lines += "[WARN] setuperr.log has errors but no known signature matched. Last line: $le" }
                                else     { $lines += "[PASS] setuperr.log present, no error content" }
                            }
                            # --- DRIVER INJECTION FAILURES ---
                            $failedInfs = @()
                            try {
                                foreach ($mm in [regex]::Matches($curErrText, 'Failed to inject driver package.*\\([^\\]+\.inf)')) {
                                    if ($mm.Groups.Count -gt 1) { $failedInfs += $mm.Groups[1].Value }
                                }
                            } catch {}
                            $failedInfs = @($failedInfs | Sort-Object -Unique)
                            if ($failedInfs.Count -gt 0) {
                                $lines += "[FAIL] Driver injection failed during 'Apply Drivers' (Safe OS) - a common 24H2 rollback cause"
                                $allDrv = $null
                                try { $allDrv = Get-WindowsDriver -Online -ErrorAction Stop } catch { $lines += "[INFO] Get-WindowsDriver unavailable - falling back to pnputil /enum-drivers" }
                                # non-boot classes (mirror $script:WinUpgradeNonBootDriverClasses)
                                $nonBootClasses = @('HIDClass','Mouse','Keyboard','Media','Image','Printer','Camera','SoftwareDevice','Bluetooth')
                                foreach ($inf in $failedInfs) {
                                    # resolve the published oemNN.inf
                                    $pub = @()
                                    if ($allDrv) { $pub = @($allDrv | Where-Object { $_.OriginalFileName -and ([System.IO.Path]::GetFileName($_.OriginalFileName) -ieq $inf) } | ForEach-Object { $_.Driver }) }
                                    if ($pub.Count -eq 0) {
                                        try { $pn = & pnputil /enum-drivers 2>$null; $cur=$null; foreach ($ln in $pn) { if ($ln -match 'Published Name\s*:\s*(\S+)') { $cur=$matches[1] } elseif ($ln -match 'Original Name\s*:\s*(\S+)') { if ($matches[1] -ieq $inf -and $cur) { $pub += $cur } } } } catch {}
                                    }
                                    $pub = @($pub | Sort-Object -Unique)
                                    if ($pub.Count -eq 0) { $lines += "[WARN] $inf : failed injection but no matching driver-store entry (may already be removed)"; continue }
                                    foreach ($pp in $pub) {
                                        $present=$false; $devName=''; $drvClass=''
                                        try {
                                            $sd = Get-CimInstance Win32_PnPSignedDriver -Filter "InfName='$pp'" -ErrorAction SilentlyContinue
                                            foreach ($row in @($sd)) {
                                                if ($row.DeviceClass -and -not $drvClass) { $drvClass = [string]$row.DeviceClass }
                                                if ($row.DeviceID) {
                                                    $pd = Get-PnpDevice -InstanceId $row.DeviceID -ErrorAction SilentlyContinue
                                                    if ($pd) { if ($pd.Present) { $present=$true }; if (-not $devName -and $pd.FriendlyName) { $devName = $pd.FriendlyName }; if (-not $drvClass -and $pd.Class) { $drvClass = [string]$pd.Class } }
                                                }
                                            }
                                        } catch {}
                                        $drvObj = if ($allDrv) { @($allDrv | Where-Object { $_.Driver -ieq $pp })[0] } else { $null }
                                        if (-not $drvClass -and $drvObj -and $drvObj.ClassName) { $drvClass = [string]$drvObj.ClassName }
                                        $bootCritical = ($drvObj -and [bool]$drvObj.BootCritical)
                                        $isNonBoot = $false
                                        foreach ($nc in $nonBootClasses) { if ($drvClass -ieq $nc) { $isNonBoot = $true; break } }
                                        $usetxt = if ($present) { 'device present/connected' } else { 'device absent/disconnected' }
                                        $extra  = if ($devName) { "  [$devName]" } else { '' }
                                        $cls    = if ($drvClass) { " class=$drvClass" } else { '' }
                                        # BootCritical is ADVISORY: a plainly non-boot class or an absent
                                        # device makes it a LIKELY FALSE POSITIVE (field batch: a
                                        # disconnected HID dongle tagged boot-critical blocked its own
                                        # removal, which was the actual fix). Otherwise verify first.
                                        if ($bootCritical) {
                                            if ($isNonBoot -or -not $present) {
                                                $lines += "[WARN] $inf -> $pp ($usetxt$cls)$extra | DISM BootCritical set but likely FALSE POSITIVE (non-boot class / device absent) - safe to remove"
                                            } else {
                                                $lines += "[WARN] $inf -> $pp ($usetxt$cls)$extra | DISM BootCritical - present boot-class device; verify before removing"
                                            }
                                        } else {
                                            $lines += "[INFO] $inf -> $pp ($usetxt$cls)$extra | not boot-critical"
                                        }
                                    }
                                    $lines += "[REC] Remove the driver: pnputil /delete-driver <oemNN.inf> /force, then clear C:\`$WINDOWS.~BT and re-trigger the upgrade"
                                }
                            }
                        }
                        # --- SETUPDIAG ---
                        $sdr = "$env:SystemRoot\Logs\SetupDiag\SetupDiagResults.xml"
                        if (Test-Path -LiteralPath $sdr) {
                            $parsedDiag = $false
                            try {
                                [xml]$sdx = Get-Content -LiteralPath $sdr -Raw -ErrorAction Stop
                                $node = $sdx.SelectSingleNode('//*[local-name()="SetupDiag"]')
                                if (-not $node) { $node = $sdx.DocumentElement }
                                $rule = ''; foreach ($rn in @('ProfileName','Rule','MatchingProfile')) { try { if ($node.$rn) { $rule = [string]$node.$rn; break } } catch {} }
                                $det  = ''; foreach ($dn in @('FailureDetails','FailureData','Output','Detail')) { try { if ($node.$dn) { $det = [string]$node.$dn; break } } catch {} }
                                $rem  = ''; foreach ($en in @('Remediation','Remediations')) { try { if ($node.$en) { $rem = [string]$node.$en; break } } catch {} }
                                if ($rule -or $det -or $rem) {
                                    $parsedDiag = $true
                                    if ($rule.Length -gt 300) { $rule = $rule.Substring(0,300) }
                                    if ($det.Length  -gt 300) { $det  = $det.Substring(0,300) }
                                    if ($rem.Length  -gt 300) { $rem  = $rem.Substring(0,300) }
                                    $lines += "[FAIL] SetupDiag: $rule - $det"
                                    if ($rem) { $lines += "[REC] SetupDiag remediation: $rem" }
                                    $setupSignatureHit = $true
                                }
                            } catch { $parsedDiag = $false }
                            if (-not $parsedDiag) { $lines += "[INFO] SetupDiag results present at $sdr (could not parse - inspect manually)" }
                        }
                    }

                    # ===== SECTION: RECOMMENDATIONS =====
                    $lines += ""
                    $lines += "=== RECOMMENDATIONS ==="

                    if ([int]$os.BuildNumber -ge $minBuild) {
                        $lines += "[REC] Already on $target - no action needed"
                    } else {
                        $recs = @()
                        if (-not (Test-Path $wuPol) -or (Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue).TargetReleaseVersion -ne 1) {
                            $recs += "Apply target release version policy (Step 2: Apply)"
                        }
                        if (-not $cpuSupported -or -not $tpmPass) {
                            if (-not $bypassActive) {
                                $recs += "Enable CPU/TPM bypass checkbox before Apply (hardware not compatible)"
                            }
                        }
                        if ($blockersFound) {
                            $recs += "Deferrals/blocks detected - try Force Discovery with Aggressive mode, or contact GPO admin"
                        }
                        if ($trvHalfWritten) {
                            $recs += "Target Release Version pin is HALF-WRITTEN - re-apply the pin (Pin action / Force Discovery re-writes it)"
                        }
                        if ($expiredPauseFound) {
                            $recs += "An EXPIRED pause window is lingering - clear it (Force Discovery aggressive removes the pause values), then re-trigger"
                        }
                        if ($stagingClass -eq 'Stale') {
                            $recs += "Stale ~BT staging from a rolled-back attempt - clear C:\`$WINDOWS.~BT to reclaim ~${btSizeGB} GB AFTER fixing the root cause, then re-trigger (do NOT wait for it to 'complete')"
                        }
                        if ($setupSignatureHit) {
                            $recs += "A known setup-failure signature was found above - action its [REC] before re-running the upgrade"
                        }
                        # disk + staging: low free space AND a >1 GB ~BT -> reclaim it to clear the runway
                        if ($freeGB -lt $minDisk -and $btSizeGB -gt 1) {
                            $recs += "Free disk is ${freeGB} GB (< ${minDisk} GB) and ~BT holds ~${btSizeGB} GB - clear ~BT to reclaim it; target 25+ GB free before re-trigger"
                        }
                        if ($recs.Count -eq 0) {
                            $recs += "Run Apply (Step 2) to set policy and trigger scans"
                            $recs += "If 24H2 does not appear after Apply, run Force Discovery (Step 3)"
                        }
                        foreach ($r in $recs) { $lines += "[REC] $r" }
                    }

                    # ---- structured fields for the Fleet Status board (all READ-ONLY reads) ----
                    # OS build (int) + the friendly DisplayVersion (e.g. 23H2 / 24H2).
                    $osBuild = 0; try { $osBuild = [int]$os.BuildNumber } catch { $osBuild = 0 }
                    $displayVersion = ''
                    try { $displayVersion = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'DisplayVersion' -ErrorAction Stop).DisplayVersion } catch { $displayVersion = '' }
                    # WUfB Target Release Version pin state (read the policy key already located above).
                    $pinned = $false; $pinnedVersion = ''
                    if (Test-Path $wuPol) {
                        $pp = Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue
                        if ($pp -and $pp.TargetReleaseVersion -eq 1) { $pinned = $true; $pinnedVersion = [string]$pp.TargetReleaseVersionInfo }
                    }
                    # Pending-reboot from the three standard signals (CBS / WU RebootRequired / PFRO).
                    $pendingReboot = $false
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReboot = $true }
                    if (-not $pendingReboot -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) { $pendingReboot = $true }
                    if (-not $pendingReboot) {
                        $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                        if ($pfro -and $pfro.PendingFileRenameOperations) { $pendingReboot = $true }
                    }

                    return [pscustomobject]@{
                        Report         = ($lines -join "`n")
                        OsBuild        = $osBuild
                        DisplayVersion = $displayVersion
                        Pinned         = $pinned
                        PinnedVersion  = $pinnedVersion
                        PendingReboot  = $pendingReboot
                        FreeGB         = $freeGB     # system-drive GB free (Fleet Status disk column)
                        TotalGB        = $totalGB
                    }
                }
                # SoftwareDistribution recursive size scan can be slow; give the op a wider cap.
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($CpuPatterns,$MinRAM,$MinDisk,$MinTPM,$MinBuild,$Version); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $diag = Invoke-Command @ic
                $report = [string]$diag.Report
                $r.Report = $report
                if ($Op -eq 'UpgradeDrive') {
                    # DRIVE 23H2 -> 24H2 over WUfB. REUSES the readiness read above and the
                    # pin policy-write ($PinBlock); the decision logic MIRRORS the pure
                    # Get-WinUpgradeDrivePlan (kept in sync) and the reboot carries the same
                    # DNS-mismatch guard as the Restart tool. Nothing here re-implements the
                    # read or the policy write.
                    $r.Report = ''   # per-host readiness report is noise for a multi-host drive
                    $osBuild = 0; try { $osBuild = [int]$diag.OsBuild } catch { $osBuild = 0 }
                    $cpuFail  = ($report -match '(?m)^\[FAIL\] CPU')
                    $tpmFail  = ($report -match '(?m)^\[FAIL\] TPM')
                    $diskFail = ($report -match '(?m)^\[FAIL\] Disk')
                    $eligible = -not ($cpuFail -or $tpmFail -or $diskFail)
                    $reasons = New-Object System.Collections.ArrayList
                    if ($cpuFail)  { [void]$reasons.Add('CPU unsupported') }
                    if ($tpmFail)  { [void]$reasons.Add('no TPM 2.0') }
                    if ($diskFail) { [void]$reasons.Add('disk <64GB') }
                    $blockReason = ($reasons -join '; ')
                    $stagedNow = [bool]$diag.PendingReboot

                    $r.Online         = $true
                    $r.OsBuild        = $osBuild
                    $r.DisplayVersion = [string]$diag.DisplayVersion
                    $r.WasPinned      = $false
                    $r.TriggerResult  = ''
                    $r.Staged         = $stagedNow
                    $r.Rebooted       = $false
                    $r.CountdownSec   = 0
                    $r.Skipped        = ''
                    $r.Error          = ''

                    # -- skip decisions (report, NEVER act) - mirror Get-WinUpgradeDrivePlan --
                    # ($MinBuild/$Version replace the hardcoded 26100/'24H2'; default 24H2 identical.)
                    if ($osBuild -ge $MinBuild) {
                        $r.Skipped = "already $Version+"; $r.Status = 'Skipped'
                        $r.Detail  = "Already on $Version+ (build $osBuild) - nothing to drive."
                        $r.Ok = $true; return $r
                    }
                    if ((-not $eligible) -and (-not $Bypass)) {
                        $rz = if ($blockReason) { $blockReason } else { 'ineligible' }
                        $r.Skipped = "blocked ($rz)"; $r.Status = 'Skipped'
                        $r.Detail  = "Hardware-blocked ($rz); bypass not requested - NOT driven (tick bypass to force). No pin, no reboot."
                        $r.Ok = $true; return $r
                    }

                    # -- dry-run: report WOULD-actions, change NOTHING --
                    if ($DryRun) {
                        $would = New-Object System.Collections.ArrayList
                        [void]$would.Add("would pin $Product $Version")
                        if ($Bypass) { [void]$would.Add('would apply CPU/TPM bypass (MoSetup)') }
                        [void]$would.Add('would trigger Windows Update (UsoClient/WUA)')
                        if ($RebootWhenStaged) {
                            if ($stagedNow) { [void]$would.Add("host is staged now -> WOULD reboot in ${CountdownSeconds}s") }
                            else { [void]$would.Add('host not staged -> would NOT reboot') }
                        }
                        $r.TriggerResult = '(dry-run: not triggered)'
                        $r.CountdownSec  = $CountdownSeconds
                        $r.Status = 'DRY-RUN'
                        $r.Detail = "DRY-RUN ($authNote): $($would -join '; ')."
                        $r.Ok = $true; return $r
                    }

                    $so2 = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 120000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                    $baseIc = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$so2; ErrorAction='Stop' }
                    if ($credSet) { $baseIc.Credential = $Cred }
                    if ($useSsl) { $baseIc['UseSSL'] = $true }

                    # -- 3) PIN to the target (REUSE the shared pin policy-write $PinBlock) --
                    & $pushStep 'Pinning' "Pinning $Product $Version..."
                    $pinOut = ''
                    try {
                        $icP = $baseIc.Clone(); $icP.ScriptBlock = $PinBlock; $icP.ArgumentList = @($Version, $Product, $Bypass)
                        $pinOut = [string](Invoke-Command @icP); $r.WasPinned = $true
                    } catch { $pinOut = "pin error: $($_.Exception.Message)"; $r.WasPinned = $false }

                    # loop31 (F1): a FAILED pin must ABORT the drive. Triggering Windows Update
                    # without a successful pin lets WU upgrade the host to the LATEST feature update
                    # instead of the pinned target (the exact thing the pin prevents), and reporting
                    # green "Pinned + triggered" while the pin threw is a false-clean (the pin error
                    # was being discarded). Fail-closed: no pin -> no trigger, surface the error.
                    if (-not $r.WasPinned) {
                        $r.Status = 'PIN FAILED'; $r.Ok = $false
                        $r.Detail = "Pin did NOT apply - upgrade NOT triggered (an unpinned trigger could upgrade to the wrong build). $pinOut"
                        return $r
                    }

                    # -- 4) TRIGGER Windows Update (best-effort accelerator; NOT a guaranteed install) --
                    & $pushStep 'Triggering' 'Triggering Windows Update detect/download/install...'
                    $trigSb = {
                        # PHASE:TRIGGER - HONEST: Windows does NOT guarantee a headless feature-
                        # update INSTALL from a trigger. This kicks the WU agent to detect/download/
                        # install the OFFERED feature update; the reliable completion is
                        # pin -> WU stages the update -> reboot. We report what we KICKED, never
                        # "installed". UsoClient StartScan/StartDownload/StartInstall exist on 22631;
                        # the WUA COM DetectNow is a belt-and-braces detect trigger.
                        $fired = New-Object System.Collections.ArrayList
                        $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
                        if (Test-Path -LiteralPath $uso) {
                            foreach ($verb in 'StartScan','StartDownload','StartInstall') {
                                try { Start-Process -FilePath $uso -ArgumentList $verb -WindowStyle Hidden -ErrorAction Stop; [void]$fired.Add("UsoClient $verb") } catch {}
                            }
                        }
                        try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow(); [void]$fired.Add('WUA DetectNow') } catch {}
                        if ($fired.Count -eq 0) { 'no WU trigger fired (UsoClient/WUA unavailable on this build)' } else { 'triggered: ' + ($fired -join ', ') + ' (accelerator - completion not guaranteed by a trigger)' }
                    }
                    try { $icT = $baseIc.Clone(); $icT.ScriptBlock = $trigSb; $r.TriggerResult = [string](Invoke-Command @icT) }
                    catch { $r.TriggerResult = "trigger error: $($_.Exception.Message)" }

                    # -- 5) RE-READ staged state (is a feature update now pending?) --
                    & $pushStep 'Checking' 'Re-reading staged / pending-reboot state...'
                    $stagedAfter = $stagedNow
                    try {
                        $stSb = {
                            # PHASE:STAGED - re-read whether a feature update is now staged / the box
                            # is pending-reboot (same signals as the readiness read + $WINDOWS.~BT).
                            $p = $false
                            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $p = $true }
                            if (-not $p -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) { $p = $true }
                            if (-not $p) {
                                $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                                if ($pfro -and $pfro.PendingFileRenameOperations) { $p = $true }
                            }
                            if (-not $p -and (Test-Path -LiteralPath 'C:\$WINDOWS.~BT\Sources')) { $p = $true }
                            [pscustomobject]@{ Staged = $p }
                        }
                        $icS = $baseIc.Clone(); $icS.ScriptBlock = $stSb
                        $sres = Invoke-Command @icS
                        $stagedAfter = [bool]$sres.Staged
                    } catch {}
                    $r.Staged = $stagedAfter

                    # -- 6) REBOOT-WHEN-STAGED (ONLY if opted in AND CONFIRMED staged; guarded) --
                    #    NEVER reboot an un-staged host. The DNS-mismatch guard runs INSIDE the
                    #    remote block (authoritative); IP targets skip the name compare (an IP has
                    #    no DNS indirection) by passing '' - exactly like the Restart tool.
                    if ($RebootWhenStaged -and $stagedAfter) {
                        $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
                        & $pushStep 'Rebooting' "Staged; issuing reboot (${CountdownSeconds}s countdown)..."
                        $rbSb = {
                            param($sec, $msg, $expected)
                            $o = @{ ExitCode = $null; Error = '' }
                            # PHASE:REBOOT - DNS-mismatch guard (HARD ABORT), mirrors the Restart tool:
                            # the box that answered runs this, so $env:COMPUTERNAME IS the real machine;
                            # if it isn't the one we dialed (stale DNS / reused IP), abort before shutdown.
                            if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                                $o.Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no reboot sent"
                                return $o
                            }
                            try {
                                $psi = New-Object System.Diagnostics.ProcessStartInfo
                                $psi.FileName               = 'shutdown.exe'
                                $psi.Arguments              = "/r /t $sec /f /c `"$msg`""
                                $psi.UseShellExecute        = $false
                                $psi.RedirectStandardOutput = $true
                                $psi.RedirectStandardError  = $true
                                $psi.CreateNoWindow         = $true
                                $proc = [System.Diagnostics.Process]::Start($psi)
                                $sout = $proc.StandardOutput.ReadToEnd()
                                $serr = $proc.StandardError.ReadToEnd()
                                $proc.WaitForExit()
                                $o.ExitCode = $proc.ExitCode
                                if ($proc.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                            } catch { $o.Error = $_.Exception.Message }
                            return $o
                        }
                        try {
                            $icB = $baseIc.Clone(); $icB.ScriptBlock = $rbSb; $icB.ArgumentList = @($CountdownSeconds, 'JANET Web: driving Windows 11 24H2 feature update', $expectedName)
                            $rb = Invoke-Command @icB
                            if ($rb.Error) { $r.Rebooted = $false; $r.Status = 'NEEDS REBOOT'; $r.Detail = "Pinned + triggered; STAGED; reboot NOT issued: $($rb.Error)" }
                            elseif ($rb.ExitCode -eq 0) { $r.Rebooted = $true; $r.CountdownSec = $CountdownSeconds; $r.Status = 'REBOOTING'; $r.Detail = "Pinned + triggered; STAGED; reboot issued (${CountdownSeconds}s). $($r.TriggerResult)" }
                            else { $r.Rebooted = $false; $r.Status = 'NEEDS REBOOT'; $r.Detail = "Pinned + triggered; STAGED; reboot FAILED (shutdown exit $($rb.ExitCode)): $($rb.Error)" }
                        } catch {
                            $r.Rebooted = $false; $r.Status = 'NEEDS REBOOT'; $r.Detail = "Pinned + triggered; STAGED; reboot FAILED to issue: $($_.Exception.Message)"
                        }
                        $r.Ok = $true; return $r
                    }

                    # not rebooting: report staged-not-rebooted vs driven-not-yet-staged.
                    $r.Rebooted = $false
                    if ($stagedAfter) {
                        $r.Status = 'STAGED'
                        $offNote = if ($RebootWhenStaged) { '' } else { ' (rebootWhenStaged off)' }
                        $r.Detail = "Pinned + triggered; STAGED (feature update pending), not rebooted$offNote. Reboot to complete. $($r.TriggerResult)"
                    } else {
                        $r.Status = 'DRIVEN'
                        $r.Detail = "Pinned + triggered; not yet staged - WU will stage the update, then a reboot completes 24H2. $($r.TriggerResult)"
                    }
                    $r.Ok = $true; return $r
                }
                if ($Op -eq 'FleetStatus') {
                    # Fleet Status board: reuse the SAME scan; derive the eligibility gates
                    # (CPU / TPM / disk) from the report markers, surface the pin + pending +
                    # build fields. The single Win24H2Status verdict is classified centrally
                    # by Get-WinUpgradeFleetStatus back in Invoke-JanetToolAction.
                    $cpuFail  = ($report -match '(?m)^\[FAIL\] CPU')
                    $tpmFail  = ($report -match '(?m)^\[FAIL\] TPM')
                    $diskFail = ($report -match '(?m)^\[FAIL\] Disk')
                    $reasons = New-Object System.Collections.ArrayList
                    if ($cpuFail)  { [void]$reasons.Add('CPU unsupported') }
                    if ($tpmFail)  { [void]$reasons.Add('no TPM 2.0') }
                    if ($diskFail) { [void]$reasons.Add('disk <64GB') }
                    $r.Online         = $true
                    $r.OsBuild        = [int]$diag.OsBuild
                    $r.DisplayVersion = [string]$diag.DisplayVersion
                    $r.Eligible       = -not ($cpuFail -or $tpmFail -or $diskFail)
                    $r.BlockReason    = ($reasons -join '; ')
                    $r.Pinned         = [bool]$diag.Pinned
                    $r.PinnedVersion  = [string]$diag.PinnedVersion
                    $r.PendingReboot  = [bool]$diag.PendingReboot
                    # -1 = unknown. Explicit null guard: [double]$null casts to 0, which would
                    # read as "0 GB free" (a full disk) instead of "not read".
                    $r.FreeGB         = -1
                    try { if ($null -ne $diag.FreeGB) { $r.FreeGB = [double]$diag.FreeGB } } catch {}
                    $r.Error          = ''
                    $r.Status         = 'SCANNED'
                    $r.Detail         = "Build $([int]$diag.OsBuild) $([string]$diag.DisplayVersion)"
                    $r.Ok             = $true
                    return $r
                }
                # Derive the one-word STATUS verdict + a short one-line summary from the report
                # markers (the ported scriptblock returns only the string). Precedence per spec:
                #   1. build >= 26100                               -> ON 24H2
                #   2. (CPU unsupported OR TPM<2.0) AND no bypass    -> HW INCOMPAT
                #   3. any [BLOCK] deferral/pause                    -> BLOCKED
                #   4. policy missing / TargetReleaseVersion != 1    -> NEEDS POLICY
                #   5. otherwise                                     -> READY
                # v0.4.0: the 'Already on ...' marker is version-derived, so match its PREFIX
                # (not the '24H2' literal) and version-derive the verdict ('ON <version>').
                $on24     = ($report -match '(?m)^\[PASS\] Already on ')
                $cpuFail  = ($report -match '(?m)^\[FAIL\] CPU')
                $tpmFail  = ($report -match '(?m)^\[FAIL\] TPM')
                $bypassOn = ($report -match '(?m)^\[INFO\] CPU/TPM Bypass : ACTIVE')
                $hasBlock = ($report -match '(?m)^\[BLOCK\]')
                $policyOk = ($report -match '(?m)^\[PASS\] Target Release Policy')
                # loop32 (F6): MIRROR of Get-WinUpgradeDiagnoseVerdict - the verdict IGNORED the
                # disk/RAM/Secure Boot fails its own scan reported, so a disk-short host read READY and
                # the upgrade failed on disk. Fold them into a distinct NOT READY (after NEEDS POLICY,
                # before READY - only reclassifies falsely-READY hosts). Keep in lockstep with the helper.
                $diskFail = ($report -match '(?m)^\[FAIL\] Disk')
                $ramFail  = ($report -match '(?m)^\[FAIL\] RAM')
                $sbFail   = ($report -match '(?m)^\[FAIL\] Secure Boot')
                $buildM   = [regex]::Match($report, '\(Build (\d+)\)')
                $buildNum = if ($buildM.Success) { $buildM.Groups[1].Value } else { '?' }
                if     ($on24)                                       { $verdict = "ON $Version" }
                elseif (($cpuFail -or $tpmFail) -and -not $bypassOn) { $verdict = 'HW INCOMPAT' }
                elseif ($hasBlock)                                   { $verdict = 'BLOCKED' }
                elseif (-not $policyOk)                              { $verdict = 'NEEDS POLICY' }
                elseif ($diskFail -or $ramFail -or $sbFail)          { $verdict = 'NOT READY' }
                else                                                 { $verdict = 'READY' }
                $sum = New-Object System.Collections.ArrayList
                [void]$sum.Add("Build $buildNum")
                [void]$sum.Add($(if ($cpuFail) { 'CPU unsupported' } else { 'CPU ok' }))
                [void]$sum.Add($(if ($tpmFail) { 'TPM<2.0' } else { 'TPM ok' }))
                if ($diskFail) { [void]$sum.Add('disk LOW') }
                if ($ramFail)  { [void]$sum.Add('RAM LOW') }
                if ($sbFail)   { [void]$sum.Add('Secure Boot off') }
                if ($bypassOn) { [void]$sum.Add('bypass ACTIVE') }
                [void]$sum.Add($(if ($policyOk) { 'policy set' } else { 'policy not set' }))
                if ($hasBlock) { [void]$sum.Add('deferral/block present') }
                # Read-only summary enrichment (does NOT change the verdict precedence above):
                # surface a logged setup-failure signature and stale (rolled-back) staging so the
                # one-line detail flags them without the operator opening the full report.
                $setupFail    = ($report -match '(?m)^\[FAIL\] Setup failure:' -or $report -match '(?m)^\[FAIL\] SetupDiag:')
                $staleStaging = ($report -match '(?mi)^\[WARN\] Stale staging')
                if ($setupFail)    { [void]$sum.Add('setup failure logged') }
                if ($staleStaging) { [void]$sum.Add('stale staging (rolled back)') }
                $r.Status = $verdict; $r.Detail = ($sum -join ' | '); $r.Ok = $true
            }

            'ForceDiscovery' {
                # Force targets to re-check for the pinned feature update. Safe mode re-applies
                # policy + triggers SCCM/GPO/WU scans; aggressive mode ALSO resets the WU cache.
                # The remote scriptblock body is ported VERBATIM from the desktop
                # $sbForceDiscovery (References\24h2script.ps1 lines 678-820) and returns a
                # multi-line log string. DryRun changes NOTHING - it reports intended steps only.
                if ($DryRun) {
                    $steps = New-Object System.Collections.ArrayList
                    [void]$steps.Add("[DRY-RUN] Would re-apply the target release policy ($Product $Version)")
                    [void]$steps.Add("[DRY-RUN] Would report deferrals/pauses (safe mode does NOT remove them)")
                    [void]$steps.Add("[DRY-RUN] Would trigger the SCCM client schedule cycles")
                    [void]$steps.Add("[DRY-RUN] Would run gpupdate /force /target:computer")
                    [void]$steps.Add("[DRY-RUN] Would trigger a WU scan (DetectNow + UsoClient StartScan)")
                    if ($Aggressive) {
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: would remove deferral/pause policy + UX values")
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: would STOP WU services, rename SoftwareDistribution + catroot2,")
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: re-register the WU DLLs, restart services, re-apply policy, re-scan")
                    }
                    $r.Report = ($steps -join "`n")
                    $r.Status = 'DRY-RUN'
                    $r.Detail = if ($Aggressive) { "Would force discovery (AGGRESSIVE reset) for $Product $Version ($authNote)." } else { "Would force discovery (safe) for $Product $Version ($authNote)." }
                    $r.Ok = $true
                    break
                }
                $fdMsg = if ($Aggressive) { 'Force discovery (AGGRESSIVE WU reset)...' } else { 'Force discovery (safe re-scan)...' }
                & $pushStep 'Forcing' $fdMsg
                $sb = {
                    param($product, $version, $cycles, $aggressive)
                    $log = @()

                    # ===== ALWAYS SAFE: Re-apply target release version policy =====
                    $wuPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    if (-not (Test-Path $wuPol)) { New-Item -Path $wuPol -Force | Out-Null }
                    New-ItemProperty -Path $wuPol -Name "TargetReleaseVersion"     -Value 1        -PropertyType DWord  -Force | Out-Null
                    New-ItemProperty -Path $wuPol -Name "ProductVersion"           -Value $product  -PropertyType String -Force | Out-Null
                    New-ItemProperty -Path $wuPol -Name "TargetReleaseVersionInfo" -Value $version  -PropertyType String -Force | Out-Null
                    $log += "Target release policy applied ($product $version)"

                    # ===== ALWAYS SAFE: Report deferrals =====
                    $deferFound = @()
                    if (Test-Path $wuPol) {
                        $d = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                        if ($d -and $d.DeferFeatureUpdatesPeriodInDays -gt 0) { $deferFound += "DeferDays=$($d.DeferFeatureUpdatesPeriodInDays)" }
                        $dds = Get-ItemProperty -Path $wuPol -Name "DisableDualScan" -ErrorAction SilentlyContinue
                        if ($dds -and $dds.DisableDualScan -eq 1) { $deferFound += "DisableDualScan=1" }
                        $dfu = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
                        if ($dfu -and $dfu.DeferFeatureUpdates -eq 1) { $deferFound += "DeferFeatureUpdates=1" }
                    }
                    $wuUx = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
                    if (Test-Path $wuUx) {
                        foreach ($valName in @("PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime",
                                               "PauseUpdatesStartTime","PauseUpdatesExpiryTime")) {
                            $pv = Get-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                            if ($pv.$valName) { $deferFound += "$valName=$($pv.$valName)" }
                        }
                    }
                    if ($deferFound.Count -gt 0 -and -not $aggressive) {
                        $log += "WARN: Deferrals detected (NOT removed in safe mode): $($deferFound -join ', ')"
                        $log += "WARN: Contact GPO/Intune admin or re-run with Aggressive mode"
                    } elseif ($deferFound.Count -gt 0 -and $aggressive) {
                        $log += "Deferrals detected - will remove in aggressive mode"
                    } else { $log += "No deferrals detected" }

                    # ===== ALWAYS SAFE: SCCM client cycles =====
                    try {
                        $svc = Get-Service -Name CcmExec -ErrorAction Stop
                        if ($svc.Status -eq 'Running') {
                            foreach ($id in $cycles) {
                                try { Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID=$id } -ErrorAction Stop | Out-Null } catch { }
                            }
                            $log += "SCCM client cycles triggered"
                        } else { $log += "SCCM client present but not running" }
                    } catch { $log += "SCCM client not found" }

                    # ===== ALWAYS SAFE: GPO refresh =====
                    try { & gpupdate /force /target:computer 2>&1 | Out-Null; $log += "GPO refreshed" }
                    catch { $log += "WARN: GPO refresh failed" }

                    # ===== ALWAYS SAFE: WU scan triggers =====
                    try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow(); $log += "WU scan triggered" }
                    catch { $log += "WARN: WU scan trigger failed: $($_.Exception.Message)" }
                    try { & UsoClient.exe StartScan 2>&1 | Out-Null; $log += "UsoClient StartScan triggered" }
                    catch { $log += "WARN: UsoClient failed" }

                    # ===== AGGRESSIVE MODE ONLY =====
                    if ($aggressive) {
                        $log += "--- AGGRESSIVE MODE ---"

                        # Remove deferrals from policy key
                        if (Test-Path $wuPol) {
                            foreach ($valName in @("DeferFeatureUpdatesPeriodInDays","DeferFeatureUpdates",
                                                   "PausedFeatureDate","PausedFeatureStatus","DisableDualScan")) {
                                $existing = Get-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                                if ($existing.$valName -ne $null) {
                                    Remove-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                                    $log += "Removed policy value: $valName"
                                }
                            }
                        }
                        # Remove UX pause settings
                        if (Test-Path $wuUx) {
                            foreach ($valName in @("PausedFeatureDate","PausedFeatureStatus",
                                                   "PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime",
                                                   "PauseUpdatesStartTime","PauseUpdatesExpiryTime",
                                                   "PauseQualityUpdatesStartTime","PauseQualityUpdatesEndTime")) {
                                $pv = Get-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                                if ($pv.$valName) {
                                    Remove-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                                    $log += "Removed UX setting: $valName"
                                }
                            }
                        }

                        # Stop WU services
                        $servicesToStop = @("wuauserv","bits","cryptSvc","msiserver")
                        foreach ($svcName in $servicesToStop) {
                            try { Stop-Service -Name $svcName -Force -ErrorAction Stop } catch { }
                        }
                        $log += "WU services stopped"

                        # Rename SoftwareDistribution and catroot2
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $sdPath = "$env:SystemRoot\SoftwareDistribution"
                        if (Test-Path $sdPath) {
                            try {
                                Rename-Item -Path $sdPath -NewName "SoftwareDistribution.bak_$timestamp" -Force -ErrorAction Stop
                                $log += "SoftwareDistribution renamed to .bak_$timestamp"
                            } catch { $log += "WARN: Could not rename SoftwareDistribution: $($_.Exception.Message)" }
                        }
                        $crPath = "$env:SystemRoot\System32\catroot2"
                        if (Test-Path $crPath) {
                            try {
                                Rename-Item -Path $crPath -NewName "catroot2.bak_$timestamp" -Force -ErrorAction Stop
                                $log += "catroot2 renamed to .bak_$timestamp"
                            } catch { $log += "WARN: Could not rename catroot2: $($_.Exception.Message)" }
                        }

                        # Re-register WU-specific DLLs only
                        $wuDlls = @(
                            "wuapi.dll","wuaueng.dll","wuaueng1.dll","wucltui.dll",
                            "wups.dll","wups2.dll","wuweb.dll","wucltux.dll",
                            "muweb.dll","wuwebv.dll","qmgr.dll","qmgrprxy.dll",
                            "wintrust.dll","initpki.dll","softpub.dll","dssenh.dll",
                            "rsaenh.dll","cryptdlg.dll","msxml3.dll","msxml6.dll"
                        )
                        $regCount = 0
                        foreach ($dll in $wuDlls) { & regsvr32.exe /s $dll 2>&1 | Out-Null; $regCount++ }
                        $log += "$regCount WU-specific DLLs re-registered"

                        # Restart WU services
                        foreach ($svcName in $servicesToStop) {
                            try { Start-Service -Name $svcName -ErrorAction Stop } catch { }
                        }
                        $log += "WU services restarted"

                        # Re-apply policy after cache clear
                        New-ItemProperty -Path $wuPol -Name "TargetReleaseVersion"     -Value 1        -PropertyType DWord  -Force | Out-Null
                        New-ItemProperty -Path $wuPol -Name "ProductVersion"           -Value $product  -PropertyType String -Force | Out-Null
                        New-ItemProperty -Path $wuPol -Name "TargetReleaseVersionInfo" -Value $version  -PropertyType String -Force | Out-Null
                        $log += "Target release policy re-applied after reset"

                        # Post-reset scans
                        try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() } catch { }
                        try { & UsoClient.exe StartScan 2>&1 | Out-Null } catch { }
                        $log += "Post-reset WU scans triggered"
                    }

                    return ($log -join "`n")
                }
                # Aggressive mode stops services + re-registers DLLs; no per-op cap (can run minutes).
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($Product,$Version,$Cycles,$Aggressive); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $report = [string](Invoke-Command @ic)
                $r.Report = $report
                $r.Status = if ($Aggressive) { 'RESET' } else { 'DONE' }
                $r.Detail = if ($Aggressive) { "Force discovery complete (AGGRESSIVE WU reset) for $Product $Version. Reboot target, then Check for updates." } else { "Force discovery complete (safe re-scan) for $Product $Version. Reboot target, then Check for updates." }
                $r.Ok = $true
            }

            'RepairHealth' {
                # Component-store repair: DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow,
                # each via the module's native-exit ProcessStartInfo pattern (PS 5.1 wraps a native
                # command's stderr in ErrorRecords that Invoke-Command reports as remote errors, so
                # the call operator would corrupt the exit code). Two separate remote calls so the
                # worker can push a live phase step between the long DISM and the long sfc.
                $rbNote = if ($Reboot) { '; reboot when required and no user is logged on' } else { '' }
                if ($DryRun) {
                    $r.Dism = '(dry-run)'; $r.Sfc = '(dry-run)'; $r.RebootNeeded = $false
                    $r.Status = 'DRY-RUN'
                    $r.Detail = "Would run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow$rbNote ($authNote)."
                    $r.Ok = $true; break
                }
                $rlines = New-Object System.Collections.ArrayList
                # DISM + sfc can each run 15-45 min -> no per-operation cap (OperationTimeout 0).
                $soLong = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $baseIc = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$soLong; ErrorAction='Stop' }
                if ($credSet) { $baseIc.Credential = $Cred }
                if ($useSsl) { $baseIc['UseSSL'] = $true }

                & $pushStep 'DISM' 'DISM /Online /Cleanup-Image /RestoreHealth (15-45 min)...'
                $dismSb = {
                    $o = @{ ExitCode=$null; Output=''; Error='' }
                    try {
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName='dism.exe'; $psi.Arguments='/Online /Cleanup-Image /RestoreHealth'
                        $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true
                        $p=[System.Diagnostics.Process]::Start($psi)
                        $so=$p.StandardOutput.ReadToEnd(); $se=$p.StandardError.ReadToEnd(); $p.WaitForExit()
                        $o.ExitCode=$p.ExitCode; $o.Output=(($so+$se).Trim())
                    } catch { $o.Error=$_.Exception.Message }
                    return $o
                }
                $dismRes=$null; $dismErr=$false
                try { $icD=$baseIc.Clone(); $icD.ScriptBlock=$dismSb; $dismRes=Invoke-Command @icD } catch { $dismErr=$true; $dismRes=@{ ExitCode=$null; Output=''; Error=$_.Exception.Message } }
                if ($dismRes.Error) { $dismErr=$true }

                & $pushStep 'sfc' 'sfc /scannow...'
                $sfcSb = {
                    $o = @{ ExitCode=$null; Text=''; Error='' }
                    try {
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName='sfc.exe'; $psi.Arguments='/scannow'
                        $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true
                        $p=[System.Diagnostics.Process]::Start($psi)
                        $so=$p.StandardOutput.ReadToEnd(); $se=$p.StandardError.ReadToEnd(); $p.WaitForExit()
                        $o.ExitCode=$p.ExitCode; $o.Text=(($so+$se) -replace "`0","")
                    } catch { $o.Error=$_.Exception.Message }
                    return $o
                }
                $sfcRes=$null; $sfcErr=$false
                try { $icS=$baseIc.Clone(); $icS.ScriptBlock=$sfcSb; $sfcRes=Invoke-Command @icS } catch { $sfcErr=$true; $sfcRes=@{ ExitCode=$null; Text=''; Error=$_.Exception.Message } }
                if ($sfcRes.Error) { $sfcErr=$true }

                # verdict: MIRROR of Get-WinUpgradeRepairVerdict (keep in sync).
                $dx = $dismRes.ExitCode
                if ($dismErr -or ($null -eq $dx)) { $dismV='error' }
                else { $dxi=0; [void][int]::TryParse([string]$dx,[ref]$dxi); if ($dxi -eq 0){$dismV='OK'} elseif($dxi -eq 3010){$dismV='OK (reboot)'} else {$dismV="exit $dxi"} }
                $stx = [string]$sfcRes.Text
                if     ($sfcErr) { $sfcV='error' }
                elseif ($stx -match '(?i)did not find any integrity violations') { $sfcV='no violations' }
                elseif ($stx -match '(?i)successfully repaired') { $sfcV='repaired' }
                elseif ($stx -match '(?i)unable to fix' -or $stx -match '(?i)could not fix') { $sfcV='could not fix' }
                elseif ($stx -match '(?i)could not perform the requested operation') { $sfcV='blocked (pending repair)' }
                else { $sfcV='no violations' }
                $dismFailed=($dismV -eq 'error' -or $dismV -match '^exit ')
                $sfcFailed=($sfcV -eq 'error')
                if     ($dismFailed -or $sfcFailed) { $statusV='FAILED' }
                elseif ($sfcV -eq 'could not fix' -or $sfcV -eq 'blocked (pending repair)') { $statusV='PARTIAL' }
                elseif ($sfcV -eq 'repaired' -or $dismV -eq 'OK (reboot)') { $statusV='REPAIRED' }
                else { $statusV='CLEAN' }
                $rebootNeeded=($dismV -eq 'OK (reboot)' -or $sfcV -eq 'repaired')

                if     ($dismV -eq 'error') { [void]$rlines.Add("[FAIL] DISM RestoreHealth error: $([string]$dismRes.Error)") }
                elseif ($dismV -eq 'OK (reboot)') { [void]$rlines.Add('[PASS] DISM RestoreHealth completed - REBOOT REQUIRED (exit 3010)') }
                elseif ($dismV -eq 'OK') { [void]$rlines.Add('[PASS] DISM RestoreHealth completed (exit 0)') }
                else { $dtail=[string]$dismRes.Output; if ($dtail.Length -gt 200){$dtail=$dtail.Substring(0,200)}; [void]$rlines.Add("[WARN] DISM RestoreHealth $dismV : $dtail") }
                switch ($sfcV) {
                    'no violations' { [void]$rlines.Add('[PASS] sfc /scannow: no integrity violations found') }
                    'repaired'      { [void]$rlines.Add('[PASS] sfc /scannow: found and repaired corrupt files') }
                    'could not fix' { [void]$rlines.Add('[WARN] sfc /scannow: found corruption it could NOT fully repair - review CBS.log / consider reimage') }
                    'blocked (pending repair)' { [void]$rlines.Add('[WARN] sfc /scannow: could not run (a pending repair/reboot is needed first)') }
                    'error'         { [void]$rlines.Add("[FAIL] sfc /scannow error: $([string]$sfcRes.Error)") }
                }

                & $pushStep 'Checking' 'Reading reboot-pending state / active user...'
                $stateSb = {
                    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                    $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                    $au  = ''; try { $au=[string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch { $au='' }
                    [pscustomobject]@{ Cbs=$cbs; Wu=$wu; ActiveUser=$au }
                }
                $activeUser=''
                try { $icX=@{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=(New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl); ErrorAction='Stop'; ScriptBlock=$stateSb }; if ($credSet) { $icX.Credential=$Cred }; if ($useSsl) { $icX['UseSSL']=$true }; $stRes=Invoke-Command @icX; if ($stRes.Cbs -or $stRes.Wu) { $rebootNeeded=$true }; $activeUser=[string]$stRes.ActiveUser } catch {}

                $rebootTxt=''
                if ($Reboot -and $rebootNeeded) {
                    if ($activeUser) { [void]$rlines.Add("[REBOOT] deferred - active user $activeUser"); $rebootTxt=" Reboot required but DEFERRED (active user $activeUser)." }
                    else {
                        $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
                        $rbSb = {
                            param($expected)
                            $o=@{ ExitCode=$null; Error='' }
                            # DNS-mismatch guard (HARD ABORT): the box that answered runs this.
                            if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) { $o.Error="DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no reboot sent"; return $o }
                            try {
                                $psi=New-Object System.Diagnostics.ProcessStartInfo
                                $psi.FileName='shutdown.exe'; $psi.Arguments='/r /t 60 /f /c "JANET Web Windows Upgrade: component-store repair complete - reboot to finish"'
                                $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true
                                $p=[System.Diagnostics.Process]::Start($psi); $so=$p.StandardOutput.ReadToEnd(); $se=$p.StandardError.ReadToEnd(); $p.WaitForExit(); $o.ExitCode=$p.ExitCode; if ($p.ExitCode -ne 0){$o.Error=($so+$se).Trim()}
                            } catch { $o.Error=$_.Exception.Message }
                            return $o
                        }
                        try { $icR=@{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=(New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl); ErrorAction='Stop'; ScriptBlock=$rbSb; ArgumentList=@($expectedName) }; if ($credSet) { $icR.Credential=$Cred }; if ($useSsl) { $icR['UseSSL']=$true }; $rb=Invoke-Command @icR
                              if ($rb.Error) { [void]$rlines.Add("[WARN] reboot NOT issued: $($rb.Error)"); $rebootTxt=" Reboot required; NOT issued: $($rb.Error)." }
                              else { [void]$rlines.Add('[REBOOT] issued (60s)'); $rebootTxt=' Reboot issued (60s).' }
                        } catch { [void]$rlines.Add("[WARN] reboot FAILED to issue: $($_.Exception.Message)"); $rebootTxt=" Reboot required; FAILED to issue: $($_.Exception.Message)." }
                    }
                } elseif ($rebootNeeded) {
                    [void]$rlines.Add('[REC] A reboot is required to complete the repair - reboot this host, then re-run the upgrade.')
                    $rebootTxt=' Reboot required (not requested).'
                }
                if ($statusV -eq 'REPAIRED' -or $statusV -eq 'PARTIAL') { [void]$rlines.Add('[REC] After repairs, clear $WINDOWS.~BT and re-trigger the upgrade.') }

                $r.Dism=$dismV; $r.Sfc=$sfcV; $r.RebootNeeded=$rebootNeeded
                $r.Status=$statusV
                $r.Detail="DISM=$dismV; SFC=$sfcV.$rebootTxt"
                $r.Report=($rlines -join "`n")
                $r.Ok=($statusV -ne 'FAILED')
            }

            'AutoFix' {
                # Per-device analyse-then-fix, ported from the desktop $sbAutoFix + adapted. The whole
                # analyse+fix pass runs in ONE remote scriptblock ON the target (so it can read/write
                # locally). Its decision logic MIRRORS the pure Get-WinUpgradeAutoFixPlan +
                # Get-WinUpgradeStagingClass / Get-WinUpgradePauseClass / the setup-err rules /
                # $script:WinUpgradeNonBootDriverClasses (all kept in sync). The reboot carries the
                # same DNS-mismatch guard as every other reboot here.
                $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
                & $pushStep 'AutoFix' 'Analysing device and applying only the fixes it needs...'
                $afSb = {
                    param($minBuild,$product,$version,$cpuPatterns,$minTPM,$cycles,
                          $fixPolicy,$fixBypass,$fixDrivers,$driverSafe,$fixPause,$fixRepair,$clearStaging,$sccmRefresh,
                          $doReboot,$expected,$dryRun)
                    $report=New-Object System.Collections.ArrayList
                    $fixes =New-Object System.Collections.ArrayList
                    $rebootNeeded=$false
                    $os=Get-CimInstance Win32_OperatingSystem; $build=[int]$os.BuildNumber
                    [void]$report.Add("[INFO] Build $build")
                    if ($build -ge $minBuild) {
                        return [pscustomobject]@{ Build=$build; Status='ALREADY ON TARGET'; Fixes=@(); RebootNeeded=$false; ActiveUser=''; Rebooted=$false; RebootDeferred=$false; Report=@($report) }
                    }
                    # hardware eval (drives the bypass decision)
                    $cpu=(Get-CimInstance Win32_Processor | Select-Object -First 1).Name
                    $cpuSupported=$false; foreach ($pat in $cpuPatterns) { if ($cpu -match $pat) { $cpuSupported=$true; break } }
                    $tpmPass=$false; try { $tpm=Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop; if ($tpm) { $tv=($tpm.SpecVersion -split ',')[0].Trim(); if ([version]$tv -ge [version]$minTPM) { $tpmPass=$true } } } catch {}
                    $moKey='HKLM:\SYSTEM\Setup\MoSetup'; $bypassActive=$false
                    if (Test-Path $moKey) { $mv=Get-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -ErrorAction SilentlyContinue; if ($mv -and $mv.AllowUpgradesWithUnsupportedTPMOrCPU -eq 1) { $bypassActive=$true } }

                    # FIX policy: TRV=1 + Product + Info, only if missing / inactive / half-written.
                    if ($fixPolicy) {
                        $key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; $needsReg=$true
                        if (Test-Path $key) { $pp=Get-ItemProperty -Path $key -ErrorAction SilentlyContinue; if ($pp.TargetReleaseVersion -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$pp.ProductVersion) -and -not [string]::IsNullOrWhiteSpace([string]$pp.TargetReleaseVersionInfo)) { $needsReg=$false } }
                        if ($needsReg) {
                            [void]$fixes.Add('policy')
                            if (-not $dryRun) {
                                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                                New-ItemProperty -Path $key -Name 'TargetReleaseVersion' -Value 1 -PropertyType DWord -Force | Out-Null
                                New-ItemProperty -Path $key -Name 'ProductVersion' -Value $product -PropertyType String -Force | Out-Null
                                New-ItemProperty -Path $key -Name 'TargetReleaseVersionInfo' -Value $version -PropertyType String -Force | Out-Null
                                [void]$report.Add("[FIX] Set Target Release Version policy ($product $version)")
                            } else { [void]$report.Add("[FIX] would set Target Release Version policy ($product $version)") }
                        } else { [void]$report.Add('[SKIP] Target Release Version policy already complete') }
                    }

                    # FIX bypass: only where hardware is genuinely unsupported and not already set.
                    if ($fixBypass) {
                        if (-not $cpuSupported -or -not $tpmPass) {
                            if (-not $bypassActive) {
                                $reason = if (-not $cpuSupported -and -not $tpmPass) { 'CPU+TPM' } elseif (-not $cpuSupported) { 'CPU' } else { 'TPM' }
                                [void]$fixes.Add("bypass($reason)")
                                if (-not $dryRun) { if (-not (Test-Path $moKey)) { New-Item -Path $moKey -Force | Out-Null }; New-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWord -Force | Out-Null; [void]$report.Add("[FIX] Set CPU/TPM bypass ($reason unsupported)") }
                                else { [void]$report.Add("[FIX] would set CPU/TPM bypass ($reason unsupported)") }
                            } else { [void]$report.Add('[SKIP] CPU/TPM bypass already active (needed)') }
                        } else { [void]$report.Add('[SKIP] CPU/TPM supported - bypass not needed') }
                    }

                    # FIX drivers: remove drivers that failed injection per THIS device's setup logs,
                    # with the corrected boot-critical guard (mirror $script:WinUpgradeNonBootDriverClasses).
                    if ($fixDrivers) {
                        $failedInfs=@()
                        foreach ($lp in @("$env:SystemDrive\`$WINDOWS.~BT\Sources\Panther","$env:SystemRoot\Panther")) {
                            $se=Join-Path $lp 'setuperr.log'
                            if (Test-Path $se) { try { $hits=Select-String -Path $se -Pattern 'Failed to inject driver package.*\\([^\\]+\.inf)' -ErrorAction SilentlyContinue; foreach ($h in $hits) { foreach ($mm in $h.Matches) { if ($mm.Groups.Count -gt 1) { $failedInfs += $mm.Groups[1].Value } } } } catch {} }
                        }
                        $failedInfs=@($failedInfs | Sort-Object -Unique)
                        if ($failedInfs.Count -eq 0) { [void]$report.Add('[SKIP] No driver-injection failures in setup logs') }
                        else {
                            # non-boot classes (mirror $script:WinUpgradeNonBootDriverClasses - keep in sync)
                            $nonBootClasses=@('HIDClass','Mouse','Keyboard','Media','Image','Printer','Camera','SoftwareDevice','Bluetooth')
                            $allDrv=$null; try { $allDrv=Get-WindowsDriver -Online -ErrorAction Stop } catch {}
                            foreach ($inf in $failedInfs) {
                                $pub=@(); if ($allDrv) { $pub=@($allDrv | Where-Object { $_.OriginalFileName -and ([System.IO.Path]::GetFileName($_.OriginalFileName) -ieq $inf) } | ForEach-Object { $_.Driver }) }
                                if ($pub.Count -eq 0) { try { $pn=& pnputil /enum-drivers 2>$null; $cur=$null; foreach ($ln in $pn) { if ($ln -match 'Published Name\s*:\s*(\S+)') { $cur=$matches[1] } elseif ($ln -match 'Original Name\s*:\s*(\S+)') { if ($matches[1] -ieq $inf -and $cur) { $pub+=$cur } } } } catch {} }
                                $pub=@($pub | Sort-Object -Unique)
                                if ($pub.Count -eq 0) { [void]$report.Add("[SKIP] $inf failed injection but not in the driver store (already gone?)"); continue }
                                foreach ($p in $pub) {
                                    $present=$false; $drvClass=''
                                    try { $sd=Get-CimInstance Win32_PnPSignedDriver -Filter "InfName='$p'" -ErrorAction SilentlyContinue; foreach ($row in @($sd)) { if ($row.DeviceClass -and -not $drvClass) { $drvClass=[string]$row.DeviceClass }; if ($row.DeviceID) { $pd=Get-PnpDevice -InstanceId $row.DeviceID -ErrorAction SilentlyContinue; if ($pd) { if ($pd.Present) { $present=$true }; if (-not $drvClass -and $pd.Class) { $drvClass=[string]$pd.Class } } } } } catch {}
                                    $drvObj=if ($allDrv) { @($allDrv | Where-Object { $_.Driver -ieq $p })[0] } else { $null }
                                    if (-not $drvClass -and $drvObj -and $drvObj.ClassName) { $drvClass=[string]$drvObj.ClassName }
                                    $bootCritical=($drvObj -and [bool]$drvObj.BootCritical)
                                    $isNonBoot=$false; foreach ($nc in $nonBootClasses) { if ($drvClass -ieq $nc) { $isNonBoot=$true; break } }
                                    # BootCritical + present + boot-class -> skip; BootCritical + (non-boot class OR absent) -> false positive, proceed.
                                    if ($bootCritical -and $present -and -not $isNonBoot) { [void]$report.Add("[WARN] $inf ($p) boot-critical, present boot-class device - NOT removing"); continue }
                                    if ($driverSafe -and $present) { [void]$report.Add("[SKIP] $inf ($p) device connected - not removing (driverSafe)"); continue }
                                    if ($dryRun) { [void]$fixes.Add("driver($p)"); [void]$report.Add("[FIX] would remove failed driver $inf ($p)"); continue }
                                    $removed=$false
                                    try { $null=& pnputil /delete-driver $p /uninstall /force 2>&1; if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) { $removed=$true } } catch {}
                                    if (-not $removed) { try { $null=& pnputil /delete-driver $p /force 2>&1; if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) { $removed=$true } } catch {} }
                                    if (-not $removed) { try { $null=& dism /online /remove-driver /driver:$p 2>&1; if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) { $removed=$true } } catch {} }
                                    if ($removed) { [void]$fixes.Add("driver($p)"); [void]$report.Add("[FIX] Removed failed driver $inf ($p)") } else { [void]$report.Add("[FAIL] Could not remove $inf ($p)") }
                                }
                            }
                        }
                    }

                    # FIX pause: clear ONLY EXPIRED UX pause values (mirror Get-WinUpgradePauseClass).
                    if ($fixPause) {
                        $wuUx='HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
                        $clearedAny=$false; $activeAny=$false
                        if (Test-Path $wuUx) {
                            $nowLocal=Get-Date
                            $pairs=@(
                                @{ Start='PauseFeatureUpdatesStartTime'; End='PauseFeatureUpdatesEndTime' },
                                @{ Start='PauseUpdatesStartTime';        End='PauseUpdatesExpiryTime' },
                                @{ Start='PauseQualityUpdatesStartTime'; End='PauseQualityUpdatesEndTime' }
                            )
                            foreach ($pair in $pairs) {
                                $ev=Get-ItemProperty -Path $wuUx -Name $pair.End -ErrorAction SilentlyContinue
                                $endVal=if ($ev) { [string]$ev.($pair.End) } else { '' }
                                if (-not $endVal) { continue }
                                $dt=[datetime]::MinValue
                                if ([datetime]::TryParse($endVal,[ref]$dt)) {
                                    if ($dt -lt $nowLocal) {
                                        $clearedAny=$true
                                        if (-not $dryRun) { Remove-ItemProperty -Path $wuUx -Name $pair.End -ErrorAction SilentlyContinue; Remove-ItemProperty -Path $wuUx -Name $pair.Start -ErrorAction SilentlyContinue; [void]$report.Add("[FIX] Cleared EXPIRED pause $($pair.Start)/$($pair.End) (ended $dt)") }
                                        else { [void]$report.Add("[FIX] would clear EXPIRED pause $($pair.Start)/$($pair.End) (ended $dt)") }
                                    } else { [void]$report.Add("[SKIP] pause $($pair.End) ACTIVE until $dt - respected"); $activeAny=$true }
                                }
                            }
                        }
                        if ($clearedAny) { [void]$fixes.Add('pause-cleared') }
                        elseif (-not $activeAny) { [void]$report.Add('[SKIP] No expired pause values to clear') }
                    }

                    # FIX repair: DISM+SFC ONLY where the setup log matches a corruption signature.
                    if ($fixRepair) {
                        $btErr="$env:SystemDrive\`$WINDOWS.~BT\Sources\Panther\setuperr.log"; $et=''
                        if (Test-Path $btErr) { try { $et=Get-Content $btErr -Raw -ErrorAction Stop } catch {} }
                        $needsRepair=($et -match '0x000003F1' -or $et -match '(?i)configuration registry database is corrupt' -or $et -match 'MigPlatformStartupOffline' -or $et -match '(?i)Offline gather failed' -or $et -match '(?i)FOD inventory' -or $et -match '(?i)Failed to enumerate store capabilities' -or $et -match 'CBS_E_INVALID_PACKAGE' -or $et -match '0x800f0805')
                        if ($needsRepair) {
                            [void]$fixes.Add('repair')
                            if (-not $dryRun) {
                                [void]$report.Add('[FIX] Corruption signature found - running DISM RestoreHealth + sfc (slow)...')
                                try { $psi=New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName='dism.exe'; $psi.Arguments='/Online /Cleanup-Image /RestoreHealth'; $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true; $pr=[System.Diagnostics.Process]::Start($psi); [void]$pr.StandardOutput.ReadToEnd(); [void]$pr.StandardError.ReadToEnd(); $pr.WaitForExit(); $dc=$pr.ExitCode; if ($dc -eq 0 -or $dc -eq 3010) { [void]$report.Add("[FIX] DISM RestoreHealth done (exit $dc)"); if ($dc -eq 3010) { $rebootNeeded=$true } } else { [void]$report.Add("[WARN] DISM exit $dc") } } catch { [void]$report.Add("[FAIL] DISM error: $($_.Exception.Message)") }
                                try { $psi2=New-Object System.Diagnostics.ProcessStartInfo; $psi2.FileName='sfc.exe'; $psi2.Arguments='/scannow'; $psi2.UseShellExecute=$false; $psi2.RedirectStandardOutput=$true; $psi2.RedirectStandardError=$true; $psi2.CreateNoWindow=$true; $pr2=[System.Diagnostics.Process]::Start($psi2); $so2=$pr2.StandardOutput.ReadToEnd(); $se2=$pr2.StandardError.ReadToEnd(); $pr2.WaitForExit(); $stx=(($so2+$se2) -replace "`0",''); if ($stx -match '(?i)unable to fix' -or $stx -match '(?i)could not fix') { [void]$report.Add('[WARN] sfc: corruption not fully repaired (review CBS.log)') } else { [void]$report.Add('[FIX] sfc /scannow done'); if ($stx -match '(?i)successfully repaired') { $rebootNeeded=$true } } } catch { [void]$report.Add("[FAIL] sfc error: $($_.Exception.Message)") }
                            } else { [void]$report.Add('[FIX] would run DISM RestoreHealth + sfc (corruption signature found)') }
                        } else { [void]$report.Add('[SKIP] No registry/CBS corruption signature - repair not needed') }
                    }

                    # clearStaging: delete a STALE (rolled-back) staging tree (mirror Get-WinUpgradeStagingClass).
                    if ($clearStaging) {
                        $btPath='C:\$WINDOWS.~BT'
                        if (Test-Path -LiteralPath $btPath) {
                            $btItem=Get-Item -LiteralPath $btPath -Force -ErrorAction SilentlyContinue
                            $ageHours=if ($btItem) { [math]::Round(((Get-Date)-$btItem.LastWriteTime).TotalHours,1) } else { 9999 }
                            $setupProcs=@(Get-Process -Name 'SetupHost','SetupPrep','Windows10UpgraderApp','SetupPlatformTool' -ErrorAction SilentlyContinue)
                            $rollbackMarker=$false; $btPanther='C:\$WINDOWS.~BT\Sources\Panther'
                            if (Test-Path -LiteralPath $btPanther) { foreach ($lg in @('setupact.log','setuperr.log')) { $lp=Join-Path $btPanther $lg; if (Test-Path -LiteralPath $lp) { try { if (Select-String -Path $lp -Pattern 'rollback|roll back|abort' -ErrorAction SilentlyContinue | Select-Object -First 1) { $rollbackMarker=$true; break } } catch {} } } }
                            if ($rollbackMarker) { $sc='Stale' } elseif ($setupProcs.Count -gt 0) { $sc='Active' } elseif ($ageHours -gt 24) { $sc='Stale' } else { $sc='Recent' }
                            $gb=0; try { $gb=[math]::Round((Get-ChildItem -LiteralPath $btPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum/1GB,1) } catch {}
                            if ($sc -eq 'Stale') {
                                [void]$fixes.Add('staging-cleared')
                                if (-not $dryRun) { try { Remove-Item -LiteralPath $btPath -Recurse -Force -ErrorAction Stop; [void]$report.Add("[FIX] Cleared stale `$WINDOWS.~BT (~$gb GB reclaimed)") } catch { [void]$report.Add("[WARN] `$WINDOWS.~BT partial removal: $($_.Exception.Message)") } }
                                else { [void]$report.Add("[FIX] would clear stale `$WINDOWS.~BT (~$gb GB)") }
                            } else { [void]$report.Add("[SKIP] `$WINDOWS.~BT is $sc (not stale) - not clearing") }
                        } else { [void]$report.Add('[SKIP] No `$WINDOWS.~BT staging to clear') }
                    }

                    # sccmRefresh: trigger the client schedule cycles so the above re-evaluates.
                    if ($sccmRefresh) {
                        try { $svc=Get-Service -Name CcmExec -ErrorAction Stop; if ($svc.Status -eq 'Running') { if (-not $dryRun) { foreach ($id in $cycles) { try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID=$id } -ErrorAction Stop | Out-Null } catch {} }; [void]$fixes.Add('sccm'); [void]$report.Add('[FIX] Triggered SCCM policy/eval cycles') } else { [void]$fixes.Add('sccm'); [void]$report.Add('[FIX] would trigger SCCM policy/eval cycles') } } else { [void]$report.Add('[SKIP] SCCM client not running') } } catch { [void]$report.Add('[SKIP] SCCM client not installed') }
                    }

                    # reboot state + optional reboot (identical policy to repair-health).
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootNeeded=$true }
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootNeeded=$true }
                    $activeUser=''; try { $activeUser=[string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
                    $rebooted=$false; $rebootDeferred=$false
                    if ($fixes.Count -gt 0 -and -not $dryRun) { [void]$report.Add('[REC] Fixes applied - clear $WINDOWS.~BT and re-trigger the upgrade') }
                    if ($doReboot -and $rebootNeeded -and -not $dryRun) {
                        if ($activeUser) { $rebootDeferred=$true; [void]$report.Add("[REBOOT] deferred - active user $activeUser") }
                        elseif ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) { [void]$report.Add("[WARN] reboot ABORTED - DNS mismatch (dialed '$expected', am '$($env:COMPUTERNAME)')") }
                        else { try { $psi=New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName='shutdown.exe'; $psi.Arguments='/r /t 60 /f /c "JANET Web Windows Upgrade: auto-fix applied - reboot to continue"'; $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.CreateNoWindow=$true; $pr=[System.Diagnostics.Process]::Start($psi); [void]$pr.StandardOutput.ReadToEnd(); [void]$pr.StandardError.ReadToEnd(); $pr.WaitForExit(); if ($pr.ExitCode -eq 0) { $rebooted=$true; [void]$report.Add('[REBOOT] issued (60s)') } else { [void]$report.Add("[WARN] reboot NOT issued (shutdown exit $($pr.ExitCode))") } } catch { [void]$report.Add("[WARN] reboot FAILED to issue: $($_.Exception.Message)") } }
                    }
                    $status = if ($dryRun) { 'DRY-RUN' } elseif ($fixes.Count -gt 0) { 'FIXED' } else { 'NO CHANGES' }
                    if ($fixes.Count -eq 0 -and -not $dryRun) { [void]$report.Add('[INFO] No changes were necessary on this device') }
                    return [pscustomobject]@{ Build=$build; Status=$status; Fixes=@($fixes); RebootNeeded=$rebootNeeded; ActiveUser=$activeUser; Rebooted=$rebooted; RebootDeferred=$rebootDeferred; Report=@($report) }
                }
                $soLong = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$afSb; Authentication='Negotiate'; SessionOption=$soLong; ErrorAction='Stop'
                         ArgumentList=@($MinBuild,$Product,$Version,$CpuPatterns,$MinTPM,$Cycles,$FixPolicy,$FixBypass,$FixDrivers,$DriverSafe,$FixPause,$FixRepair,$ClearStaging,$SccmRefresh,$Reboot,$expectedName,$DryRun) }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $af = Invoke-Command @ic
                $fixList = @($af.Fixes)
                $r.Fixes = if ($fixList.Count -gt 0) { if ($DryRun) { 'would: ' + ($fixList -join '; ') } else { ($fixList -join '; ') } } else { '' }
                $r.RebootNeeded = [bool]$af.RebootNeeded
                $r.Status = [string]$af.Status
                $r.Detail = switch ([string]$af.Status) {
                    'ALREADY ON TARGET' { "Already on $Version+ (build $([int]$af.Build)) - no changes." }
                    'NO CHANGES'        { 'Analysed - no fixes were necessary on this device.' }
                    'DRY-RUN'           { if ($fixList.Count -gt 0) { "DRY-RUN: would apply $($fixList.Count) fix(es): $($fixList -join '; ')." } else { 'DRY-RUN: no fixes needed.' } }
                    'FIXED'             { "Applied: $($fixList -join '; ')." + $(if ([bool]$af.Rebooted) { ' Reboot issued (60s).' } elseif ([bool]$af.RebootDeferred) { " Reboot required but DEFERRED (active user $([string]$af.ActiveUser))." } elseif ([bool]$af.RebootNeeded) { ' Reboot required (not requested).' } else { '' }) }
                    default             { 'Auto-fix complete.' }
                }
                $r.Report = (@($af.Report) -join "`n")
                $r.Ok = $true
            }

            'ErrorReport' {
                # Read-only per-error scan (changes NOTHING). Gathers the same signals the diagnose
                # scan uses and builds ONE row per detected error INLINE (mirror of the pure
                # Get-WinUpgradeErrorRowSet + the setup-err rule table / staging / pause classifiers).
                # The worker returns a Rows array the dispatcher fans out as individual row events.
                & $pushStep 'Scanning' 'Read-only upgrade-error scan...'
                $erSb = {
                    param($cpuPatterns,$minRAM,$minDisk,$minTPM,$minBuild,$target)
                    $trim={ param($s) $x=[string]$s; if ($x.Length -gt 200){$x=$x.Substring(0,200)}; $x }
                    $os=Get-CimInstance Win32_OperatingSystem; $build=[int]$os.BuildNumber
                    $rows=New-Object System.Collections.ArrayList
                    if ($build -ge $minBuild) {
                        [void]$rows.Add([pscustomobject]@{ Category='NONE'; Severity='INFO'; Evidence="Already on $target+ (build $build)"; Fix='' })
                        return ,@($rows)
                    }
                    # DISK
                    $sysDrive=$env:SystemDrive
                    $disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
                    $freeGB=[math]::Round($disk.FreeSpace/1GB,1)
                    if ($freeGB -lt $minDisk) { [void]$rows.Add([pscustomobject]@{ Category='DISK'; Severity='BLOCK'; Evidence=(& $trim "$freeGB GB free on $sysDrive (need $minDisk+ GB)"); Fix="Free disk to 25+ GB (clearing `$WINDOWS.~BT reclaims staging), then re-trigger." }) }
                    # read current setuperr.log (shared open; may be held during an in-flight upgrade)
                    $btErr='C:\$WINDOWS.~BT\Sources\Panther\setuperr.log'; $et=''
                    if (Test-Path -LiteralPath $btErr) {
                        $sr=$null
                        try { $fs=[System.IO.File]::Open($btErr,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite); try { $sr=New-Object System.IO.StreamReader($fs); $et=$sr.ReadToEnd() } finally { if ($sr){$sr.Dispose()}; $fs.Dispose() } }
                        catch { try { $et=Get-Content -LiteralPath $btErr -Raw -ErrorAction Stop } catch { $et='' } }
                    }
                    # DRIVER injection failures
                    $failedInfs=@()
                    if ($et) { try { foreach ($mm in [regex]::Matches($et,'Failed to inject driver package.*\\([^\\]+\.inf)')) { if ($mm.Groups.Count -gt 1) { $failedInfs+=$mm.Groups[1].Value } } } catch {} }
                    $failedInfs=@($failedInfs | Sort-Object -Unique)
                    foreach ($inf in $failedInfs) { [void]$rows.Add([pscustomobject]@{ Category='DRIVER'; Severity='WARN'; Evidence=(& $trim "Failed to inject driver package: $inf"); Fix="Remove the failed driver (pnputil /delete-driver <oemNN.inf> /force), clear `$WINDOWS.~BT, re-trigger." }) }
                    # SIGNATURE TABLE (mirror $script:WinUpgradeSetupErrRules / Get-WinUpgradeSetupErrSignatures)
                    if ($et) {
                        $sigRules=@(
                            @{ Cat='REGISTRY'; Sev='BLOCK'; Patterns=@('0x000003F1','(?i)configuration registry database is corrupt'); Message='registry hive corrupt'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow; if it persists, deeper hive repair.' },
                            @{ Cat='COMPONENT_STORE'; Sev='BLOCK'; Patterns=@('CBS_E_INVALID_PACKAGE','(?i)Failed to enumerate store capabilities'); Message='component store broken'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' },
                            @{ Cat='COMPONENT_STORE'; Sev='BLOCK'; All=@('(?i)FOD inventory','E_INVALIDARG'); Message='component store broken (FOD inventory E_INVALIDARG)'; Rec='Run DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow to rebuild the component store.' },
                            @{ Cat='MEMORY'; Sev='BLOCK'; Patterns=@('0x8007000E'); Message='out of memory (E_OUTOFMEMORY)'; Rec='Run Set Page File (fixed 16 GB) on this host, then re-run the feature update.' },
                            @{ Cat='ADLDS'; Sev='WARN'; All=@('adammigrate\.dll','0x80070002'); Message='AD LDS migration plugin (adammigrate.dll) failing'; Rec='Investigate the AD LDS migration plugin AFTER clearing the other blockers, then re-diagnose.' },
                            @{ Cat='PAUSED'; Sev='WARN'; Patterns=@('0x800704C7'); Message='setup cancelled (0x800704C7)'; Rec='Cross-check pauses - an expired/lingering pause can present as a cancel; clear stale pause values + re-trigger.' }
                        )
                        foreach ($rule in $sigRules) {
                            $hit=$false
                            if ($rule.ContainsKey('All')) { $hit=$true; foreach ($pp in $rule['All']) { if ($et -notmatch $pp) { $hit=$false; break } } }
                            else { foreach ($pp in $rule['Patterns']) { if ($et -match $pp) { $hit=$true; break } } }
                            if ($hit) { [void]$rows.Add([pscustomobject]@{ Category=$rule['Cat']; Severity=$rule['Sev']; Evidence=(& $trim $rule['Message']); Fix=(& $trim $rule['Rec']) }) }
                        }
                    }
                    # PAUSED state (mirror Get-WinUpgradePauseClass)
                    $wuUx='HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'; $pauseActive=$false; $pauseExpired=$false
                    if (Test-Path $wuUx) {
                        $nowLocal=Get-Date
                        foreach ($en in @('PauseFeatureUpdatesEndTime','PauseUpdatesExpiryTime')) {
                            $ev=Get-ItemProperty -Path $wuUx -Name $en -ErrorAction SilentlyContinue
                            if ($ev -and $ev.$en) { $dt=[datetime]::MinValue; if ([datetime]::TryParse([string]$ev.$en,[ref]$dt)) { if ($dt -lt $nowLocal) { $pauseExpired=$true } else { $pauseActive=$true } } }
                        }
                    }
                    if ($pauseActive) { [void]$rows.Add([pscustomobject]@{ Category='PAUSED'; Severity='BLOCK'; Evidence='An ACTIVE Windows Update pause window is holding the feature update'; Fix='Wait for the pause to expire or clear it (Force Discovery aggressive), then re-trigger.' }) }
                    elseif ($pauseExpired) { [void]$rows.Add([pscustomobject]@{ Category='PAUSED'; Severity='WARN'; Evidence='An EXPIRED pause value is lingering under WindowsUpdate\UX\Settings'; Fix='Clear the expired Pause* values (Auto-Fix / Force Discovery aggressive), then re-trigger.' }) }
                    # POLICY state
                    $wuPol='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; $polMissing=$true; $polHalf=$false
                    if (Test-Path $wuPol) { $pp=Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue; if ($pp.TargetReleaseVersion -eq 1) { if ([string]::IsNullOrWhiteSpace([string]$pp.ProductVersion) -or [string]::IsNullOrWhiteSpace([string]$pp.TargetReleaseVersionInfo)) { $polHalf=$true; $polMissing=$false } else { $polMissing=$false } } }
                    if ($polHalf) { [void]$rows.Add([pscustomobject]@{ Category='POLICY'; Severity='WARN'; Evidence='Target Release Version pin is HALF-WRITTEN (TargetReleaseVersion=1 but Product/Version blank)'; Fix='Re-apply the pin (Pin action / Auto-Fix / Force Discovery re-writes it).' }) }
                    elseif ($polMissing) { [void]$rows.Add([pscustomobject]@{ Category='POLICY'; Severity='WARN'; Evidence='Target Release Version policy is not set'; Fix='Apply the Target Release Version policy (Pin action / Auto-Fix).' }) }
                    # STAGING class (mirror Get-WinUpgradeStagingClass)
                    $btPath='C:\$WINDOWS.~BT'; $stagingClass='None'; $stagingGB=0
                    if (Test-Path -LiteralPath $btPath) {
                        $btItem=Get-Item -LiteralPath $btPath -Force -ErrorAction SilentlyContinue
                        $ageHours=if ($btItem) { [math]::Round(((Get-Date)-$btItem.LastWriteTime).TotalHours,1) } else { 9999 }
                        $setupProcs=@(Get-Process -Name 'SetupHost','SetupPrep','Windows10UpgraderApp','SetupPlatformTool' -ErrorAction SilentlyContinue)
                        $rollbackMarker=$false; $btP='C:\$WINDOWS.~BT\Sources\Panther'
                        if (Test-Path -LiteralPath $btP) { foreach ($lg in @('setupact.log','setuperr.log')) { $lp=Join-Path $btP $lg; if (Test-Path -LiteralPath $lp) { try { if (Select-String -Path $lp -Pattern 'rollback|roll back|abort' -ErrorAction SilentlyContinue | Select-Object -First 1) { $rollbackMarker=$true; break } } catch {} } } }
                        if ($rollbackMarker) { $stagingClass='Stale' } elseif ($setupProcs.Count -gt 0) { $stagingClass='Active' } elseif ($ageHours -gt 24) { $stagingClass='Stale' } else { $stagingClass='Recent' }
                        try { $stagingGB=[math]::Round((Get-ChildItem -LiteralPath $btPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum/1GB,1) } catch {}
                    }
                    if ($stagingClass -eq 'Stale') { [void]$rows.Add([pscustomobject]@{ Category='STAGING'; Severity='INFO'; Evidence=(& $trim "Stale rolled-back `$WINDOWS.~BT staging (~$stagingGB GB) - nothing is in progress"); Fix="Clear C:\`$WINDOWS.~BT to reclaim disk AFTER fixing the root cause, then re-trigger." }) }
                    # SETUPDIAG
                    $sdr="$env:SystemRoot\Logs\SetupDiag\SetupDiagResults.xml"
                    if (Test-Path -LiteralPath $sdr) { try { [xml]$sdx=Get-Content -LiteralPath $sdr -Raw -ErrorAction Stop; $node=$sdx.SelectSingleNode('//*[local-name()="SetupDiag"]'); if (-not $node) { $node=$sdx.DocumentElement }; $rule=''; foreach ($rn in @('ProfileName','Rule','MatchingProfile')) { try { if ($node.$rn) { $rule=[string]$node.$rn; break } } catch {} }; if ($rule) { [void]$rows.Add([pscustomobject]@{ Category='SETUPDIAG'; Severity='WARN'; Evidence=(& $trim "SetupDiag matched profile: $rule"); Fix='Action the SetupDiag remediation for this profile, then re-trigger.' }) } } catch {} }
                    if ($rows.Count -eq 0) { [void]$rows.Add([pscustomobject]@{ Category='NONE'; Severity='INFO'; Evidence='No upgrade errors detected'; Fix='' }) }
                    return ,@($rows)
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$erSb; ArgumentList=@($CpuPatterns,$MinRAM,$MinDisk,$MinTPM,$MinBuild,$Version); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $erRows = Invoke-Command @ic
                $mapped = New-Object System.Collections.ArrayList
                foreach ($er in @($erRows)) { if ($null -eq $er) { continue }; [void]$mapped.Add([ordered]@{ Host=$Computer; Category=[string]$er.Category; Severity=[string]$er.Severity; Evidence=[string]$er.Evidence; Fix=[string]$er.Fix }) }
                if ($mapped.Count -eq 0) { [void]$mapped.Add([ordered]@{ Host=$Computer; Category='NONE'; Severity='INFO'; Evidence='No upgrade errors detected'; Fix='' }) }
                $r.Rows = @($mapped)
                $r.Status = 'SCANNED'
                $blockN = @($mapped | Where-Object { $_.Severity -eq 'BLOCK' }).Count
                $warnN  = @($mapped | Where-Object { $_.Severity -eq 'WARN' }).Count
                $noneOnly = ($mapped.Count -eq 1 -and [string]$mapped[0].Category -eq 'NONE')
                $r.Detail = if ($noneOnly) { [string]$mapped[0].Evidence } else { "$($mapped.Count) error row(s): $blockN block, $warnN warn" }
                $r.Ok = $true
            }

            'OsAudit' {
                # Read-only OS Version audit rule (self-inclusive scan). Reads the CurrentVersion
                # registry values ON the target over the tool's SSL-first Invoke-Command, then
                # computes the three pass/fail checks. The verdict logic MIRRORS the PURE, tested
                # Get-WinUpgradeOsAuditVerdict (keep in sync); a bare pool runspace cannot call it.
                & $pushStep 'Reading' 'Reading OS version + edition (read-only)...'
                $sb = {
                    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                    $p  = Get-ItemProperty -Path $cv -ErrorAction Stop
                    $cbInt = 0; [void][int]::TryParse([string]$p.CurrentBuild, [ref]$cbInt)
                    $ubrInt = 0; try { [void][int]::TryParse([string]$p.UBR, [ref]$ubrInt) } catch {}
                    [pscustomobject]@{
                        CurrentBuild   = $cbInt
                        UBR            = $ubrInt
                        DisplayVersion = [string]$p.DisplayVersion
                        ReleaseId      = [string]$p.ReleaseId
                        EditionID      = [string]$p.EditionID
                        ProductName    = [string]$p.ProductName
                    }
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000 -SkipCACheck:$useSsl -SkipCNCheck:$useSsl
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                if ($useSsl) { $ic['UseSSL'] = $true }
                $info = Invoke-Command @ic
                $build = 0; try { $build = [int]$info.CurrentBuild } catch { $build = 0 }
                $edition = [string]$info.EditionID
                # ---- inline mirror of Get-WinUpgradeOsAuditVerdict (tested source of truth) ----
                $gen11   = ($build -ge 22000)
                $rel24h2 = ($build -ge 26100)
                $entEd   = ($edition -eq 'Enterprise')
                $failed = New-Object System.Collections.ArrayList
                if (-not $gen11)   { [void]$failed.Add('Gen11') }
                if (-not $rel24h2) { [void]$failed.Add('Rel24H2') }
                if (-not $entEd)   { [void]$failed.Add('EntEdition') }
                $verdict = $(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })
                # ---- end mirror ----
                $rel = if ($info.DisplayVersion) { [string]$info.DisplayVersion } elseif ($info.ReleaseId) { [string]$info.ReleaseId } else { '' }
                $r.Online     = $true
                $r.Generation = $(if ($gen11) { 'Windows 11' } else { 'Windows 10' })
                $r.ReleaseId  = $rel
                $r.Edition    = $edition
                $r.Gen11      = $(if ($gen11)   { 'PASS' } else { 'FAIL' })
                $r.Rel24H2    = $(if ($rel24h2) { 'PASS' } else { 'FAIL' })
                $r.EntEdition = $(if ($entEd)   { 'PASS' } else { 'FAIL' })
                $r.Verdict    = $verdict
                $r.Failed     = ($failed.ToArray() -join ', ')
                $r.Error      = ''
                # Status/Detail so the generic Operations grid renders it (parity with diagnose).
                $r.Status = $verdict
                $r.Detail = "Build $build $rel / $($r.Generation) / Edition $edition | Gen11=$($r.Gen11) Rel24H2=$($r.Rel24H2) EntEdition=$($r.EntEdition)" + $(if ($verdict -eq 'FAIL') { " | Failed: $($r.Failed)" } else { '' })
                $r.Ok = $true
            }

            'InstallUpdates' {
                # PILOT-PENDING: installs ALL available Windows Updates by registering a JANET_WUA
                # SYSTEM scheduled task running the ported WUA driver, polling result.json. Transport
                # cascade, first success wins: WinRM HTTPS 5986 -> WinRM HTTP 5985 (if AllowHttp) ->
                # WMI/DCOM 135 (if AllowWmi). Self-guard already dropped self BEFORE fan-out. Never
                # fakes a success row - a row is Ok only when the driver reported NoUpdates/Installed/
                # InstalledWithErrors. NEEDS A LIVE DOMAIN/WSUS to truly validate; shimmed in tests.
                $r.Online = $online; $r.Transport = ''; $r.Method = 'SchedTask(SYSTEM)'
                $r.KBs = ''; $r.Reboot = $false; $r.Error = ''
                if ($DryRun) {
                    $muNote = if ($IncludeMU) { 'WSUS + Windows/Microsoft Update' } else { 'WSUS/SCCM source only' }
                    $r.Status = 'DRY-RUN'; $r.Ok = $true
                    $r.Detail = "Would register the JANET_WUA SYSTEM task to install all available updates ($muNote), polling result.json up to ${TimeoutMin} min ($authNote). Changes nothing."
                    break
                }
                $timeoutSec = [int]$TimeoutMin * 60
                if ($timeoutSec -lt 300) { $timeoutSec = 300 }
                # Fresh per-run nonce so a polled result.json can be PROVEN to belong to THIS run
                # (kills the WMI/DCOM stale-read race - a prior run's result.json carries a different
                # nonce and is rejected). GUID randomness is fine here (runtime tool, not a workflow).
                $runNonce = [guid]::NewGuid().ToString('N')
                # Target identity for the wrong-box guard: the dialed short name, and whether the
                # target is a bare IP literal (skip the host-name match for IP-literal targets).
                $targetIpParsed = $null
                $targetIsIp     = [System.Net.IPAddress]::TryParse([string]$Computer, [ref]$targetIpParsed)
                $targetShort    = ([string]$Computer -split '\.')[0]
                # Bake the Include-Microsoft-Update toggle + the nonce into the driver text
                # (#__INCLUDEMU__# -> $true/$false, #__NONCE__# -> this run's nonce).
                $driver = ([string]$WuaDriver).Replace('#__INCLUDEMU__#', $(if ($IncludeMU) { '$true' } else { '$false' })).Replace('#__NONCE__#', $runNonce)

                # In-session runner: register+start the SYSTEM task, poll result.json, return json.
                # Ported VERBATIM from HTTPS_Installer.ps1 lines 235-253.
                $remoteTaskRunner = {
                    param($DriverText, $TimeoutSec, $RunNonce)
                    $base = Join-Path $env:ProgramData "JANET\WUA"
                    New-Item -ItemType Directory -Force -Path $base | Out-Null
                    $log = Join-Path $base "result.json"
                    Remove-Item $log -ErrorAction SilentlyContinue
                    Set-Content -Path (Join-Path $base "driver.ps1") -Value $DriverText -Encoding UTF8
                    $act  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$base\driver.ps1`""
                    $prin = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $set  = New-ScheduledTaskSettingsSet -StartWhenAvailable
                    Register-ScheduledTask -TaskName "JANET_WUA" -Action $act -Principal $prin -Settings $set -Force | Out-Null
                    Start-ScheduledTask -TaskName "JANET_WUA"
                    # Poll for a result.json that carries THIS run's nonce (a stale/prior file with a
                    # different nonce is ignored -> keep polling until it is overwritten or we time out).
                    $deadline = (Get-Date).AddSeconds($TimeoutSec)
                    $out = $null
                    while ((Get-Date) -lt $deadline) {
                        if (Test-Path $log) {
                            Start-Sleep 2
                            $txt = $null; try { $txt = Get-Content $log -Raw } catch {}
                            if ($txt) {
                                $ok = $false; try { if (($txt | ConvertFrom-Json).Nonce -eq $RunNonce) { $ok = $true } } catch {}
                                if ($ok) { $out = $txt; break }
                            }
                        }
                        Start-Sleep 6
                    }
                    if (-not $out) { $out = '{"Status":"Timeout","Nonce":"' + $RunNonce + '"}' }
                    # Best-effort cleanup: never leave a persistent SYSTEM task or the driver/result
                    # residue on the target. A cleanup failure must NOT change the harvested result.
                    try { Unregister-ScheduledTask -TaskName "JANET_WUA" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                    try { Remove-Item (Join-Path $base "driver.ps1") -Force -ErrorAction SilentlyContinue } catch {}
                    try { Remove-Item $log -Force -ErrorAction SilentlyContinue } catch {}
                    $out
                }

                # Inline mirror of Get-WinUpgradeWuaResultRow (tested authority) - a bare pool
                # runspace cannot call the module fn. ResultCode 2=Installed,3=InstalledWithErrors,
                # else InstallFailed; Got=$false means the transport produced nothing (keep casc.).
                $shapeRow = {
                    param($json, $ExpectNonce, $TargetShort, $TargetIsIp)
                    $res = $null; try { $res = $json | ConvertFrom-Json } catch {}
                    $o = [ordered]@{ Status='Timeout'; KBs=''; Reboot=$false; Error=''; Ok=$false; Got=$false }
                    if ($null -eq $res) { return $o }
                    # NONCE gate: reject a stale/prior result.json (different nonce) -> Got=$false so
                    # the poll/cascade keeps going; a wrong file can NEVER become this run's success.
                    if ($ExpectNonce) {
                        $rNonce = ''; try { if ($res.PSObject.Properties['Nonce']) { $rNonce = [string]$res.Nonce } } catch {}
                        if ($rNonce -ne $ExpectNonce) { $o.Error = 'nonce mismatch (stale/prior run)'; return $o }
                    }
                    # HOST gate: driver stamps Host=$env:COMPUTERNAME; a mismatch = wrong box.
                    if (-not $TargetIsIp -and $TargetShort) {
                        $rHost = ''; try { if ($res.PSObject.Properties['Host']) { $rHost = [string]$res.Host } } catch {}
                        if ($rHost -and (($rHost -split '\.')[0] -ine $TargetShort)) {
                            $o.Got = $true; $o.Status = 'WrongBox'; $o.Ok = $false
                            $o.Error = "result.json Host '$rHost' != dialed target '$TargetShort' (WRONG BOX - stale DNS / reused IP)"
                            return $o
                        }
                    }
                    $o.Got = $true
                    $rc = $null; try { if ($res.PSObject.Properties['ResultCode']) { $rc = $res.ResultCode } } catch {}
                    if ($null -ne $rc -and "$rc" -ne '') {
                        $rcInt = 0; [void][int]::TryParse("$rc", [ref]$rcInt)
                        $o.Status = $(if ($rcInt -eq 2) { 'Installed' } elseif ($rcInt -eq 3) { 'InstalledWithErrors' } else { 'InstallFailed' })
                        if ($o.Status -eq 'InstallFailed') { $o.Error = "install ResultCode=$rcInt" }
                    } else { $o.Status = [string]$res.Status }
                    try { $o.Reboot = [bool]$res.Reboot } catch { $o.Reboot = $false }
                    $kk = @(); try { if ($null -ne $res.KBs) { $kk = @($res.KBs) } } catch {}
                    $o.KBs = ($kk | Where-Object { $_ } | Select-Object -Unique) -join ','
                    if ($o.Status -eq 'Error') { try { if ($res.Message) { $o.Error = [string]$res.Message } } catch {} }
                    $o.Ok = (@('Installed','InstalledWithErrors','NoUpdates') -contains $o.Status)
                    return $o
                }

                $trail = New-Object System.Collections.ArrayList
                $succeeded = $false
                # --- WinRM transport attempts (HTTPS 5986 first, then HTTP 5985 if allowed) ---
                $attempts = New-Object System.Collections.ArrayList
                [void]$attempts.Add(@{ Label='WinRM HTTPS 5986'; Transport='HTTPS'; UseSSL=$true;  Port=5986 })
                if ($AllowHttp) { [void]$attempts.Add(@{ Label='WinRM HTTP 5985'; Transport='HTTP'; UseSSL=$false; Port=5985 }) }
                foreach ($att in $attempts) {
                    if (& $isCancelled) { $r.Status='Cancelled'; $r.Detail='cancelled by operator'; $r.Ok=$false; break }
                    & $pushStep 'Working' "Registering JANET_WUA SYSTEM task via $($att.Label)..."
                    try {
                        $idleMs = [int][Math]::Min(2147483, ($timeoutSec + 900)) * 1000
                        $so = New-PSSessionOption -OpenTimeout 25000 -OperationTimeout 0 -IdleTimeout $idleMs -CancelTimeout 5000 -SkipCACheck:$att.UseSSL -SkipCNCheck:$att.UseSSL
                        $ic = @{ ComputerName=$Computer; ScriptBlock=$remoteTaskRunner; ArgumentList=@($driver,$timeoutSec,$runNonce); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop'; Port=$att.Port }
                        if ($credSet) { $ic.Credential = $Cred }
                        if ($att.UseSSL) { $ic['UseSSL'] = $true }
                        $json = Invoke-Command @ic
                        $shaped = & $shapeRow $json $runNonce $targetShort $targetIsIp
                        if ($shaped.Got) {
                            $r.Transport = $att.Transport; $r.Status = $shaped.Status; $r.KBs = $shaped.KBs
                            $r.Reboot = $shaped.Reboot; $r.Error = $shaped.Error; $r.Ok = $shaped.Ok
                            $r.Detail = "$($att.Label): $($shaped.Status)" + $(if ($shaped.KBs) { " [$($shaped.KBs)]" } else { '' }) + $(if ($shaped.Reboot) { ' (reboot pending)' } else { '' }) + $(if ($shaped.Error) { " - $($shaped.Error)" } else { '' })
                            $succeeded = $true; break
                        } else {
                            [void]$trail.Add("$($att.Label): no result.json (task may still be running)")
                        }
                    } catch {
                        [void]$trail.Add("$($att.Label): $($_.Exception.Message)")
                    }
                }

                # --- WMI/DCOM fallback: Win32_Process.Create a bootstrap that writes the driver +
                #     registers the SYSTEM task, then poll result.json via \\host\C$ (ported from
                #     HTTPS_Installer.ps1 lines 368-413). Only when WinRM did not succeed. ---
                if (-not $succeeded -and $AllowWmi -and -not (& $isCancelled)) {
                    & $pushStep 'Working' 'WinRM failed; bootstrapping SYSTEM task over WMI/DCOM...'
                    try {
                        $driver64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($driver))
                        $bootstrap = @"
`$base = Join-Path `$env:ProgramData 'JANET\WUA'
New-Item -ItemType Directory -Force -Path `$base | Out-Null
Remove-Item (Join-Path `$base 'result.json') -ErrorAction SilentlyContinue
Set-Content -Path (Join-Path `$base 'driver.ps1') -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$driver64'))) -Encoding UTF8
`$act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + `$base + '\driver.ps1"')
`$prin = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'JANET_WUA' -Action `$act -Principal `$prin -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable) -Force | Out-Null
Start-ScheduledTask -TaskName 'JANET_WUA'
"@
                        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
                        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"
                        $cso = New-CimSessionOption -Protocol Dcom
                        if ($credSet) { $cim = New-CimSession -ComputerName $Computer -Credential $Cred -SessionOption $cso -ErrorAction Stop }
                        else          { $cim = New-CimSession -ComputerName $Computer -SessionOption $cso -ErrorAction Stop }
                        $inv = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
                        if ($inv.ReturnValue -ne 0) {
                            Remove-CimSession $cim -ErrorAction SilentlyContinue
                            [void]$trail.Add("WMI/DCOM: Win32_Process.Create rc=$($inv.ReturnValue)")
                        } else {
                            $unc    = "\\$Computer\C`$\ProgramData\JANET\WUA\result.json"
                            $uncDrv = "\\$Computer\C`$\ProgramData\JANET\WUA\driver.ps1"
                            $useDrive = $credSet
                            if ($useDrive) { New-PSDrive -Name JWUA -PSProvider FileSystem -Root "\\$Computer\C`$" -Credential $Cred -ErrorAction SilentlyContinue | Out-Null }
                            # Poll for a result.json that carries THIS run's nonce. A stale/prior-run
                            # file (wrong nonce) is IGNORED so we keep polling; the async Win32_Process
                            # start can no longer be mis-read as this run's success. WrongBox stops early.
                            $deadline = (Get-Date).AddSeconds($timeoutSec); $shaped = $null
                            while ((Get-Date) -lt $deadline) {
                                if (& $isCancelled) { break }
                                if (Test-Path $unc) {
                                    $polled = $null; try { $polled = Get-Content $unc -Raw } catch {}
                                    if ($polled) {
                                        $cand = & $shapeRow $polled $runNonce $targetShort $targetIsIp
                                        if ($cand.Got) { $shaped = $cand; break }   # matching nonce (real status or WrongBox)
                                    }
                                }
                                Start-Sleep 8
                            }
                            if ($null -eq $shaped) { $shaped = & $shapeRow $null $runNonce $targetShort $targetIsIp }
                            if ($shaped.Got) {
                                $r.Transport = 'WMI/DCOM'; $r.Status = $shaped.Status; $r.KBs = $shaped.KBs
                                $r.Reboot = $shaped.Reboot; $r.Error = $shaped.Error; $r.Ok = $shaped.Ok
                                $r.Detail = "WMI/DCOM: $($shaped.Status)" + $(if ($shaped.KBs) { " [$($shaped.KBs)]" } else { '' }) + $(if ($shaped.Reboot) { ' (reboot pending)' } else { '' }) + $(if ($shaped.Error) { " - $($shaped.Error)" } else { '' })
                                $succeeded = $true
                            } else {
                                [void]$trail.Add('WMI/DCOM: task launched but no matching result.json before timeout')
                            }
                            # Best-effort cleanup (never leave a persistent SYSTEM task / driver residue):
                            # fire a follow-up bootstrap to Unregister the task + delete the files, and
                            # also remove them over the admin share. A cleanup failure must NOT flip a
                            # real Installed result to a failure.
                            try {
                                $cleanup = @"
try { Unregister-ScheduledTask -TaskName 'JANET_WUA' -Confirm:`$false -ErrorAction SilentlyContinue } catch {}
`$b = Join-Path `$env:ProgramData 'JANET\WUA'
Remove-Item (Join-Path `$b 'driver.ps1')   -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path `$b 'result.json')  -Force -ErrorAction SilentlyContinue
"@
                                $encC = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
                                Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encC" } -ErrorAction SilentlyContinue | Out-Null
                            } catch {}
                            try { if (Test-Path $unc)    { Remove-Item $unc    -Force -ErrorAction SilentlyContinue } } catch {}
                            try { if (Test-Path $uncDrv) { Remove-Item $uncDrv -Force -ErrorAction SilentlyContinue } } catch {}
                            if ($useDrive) { Remove-PSDrive -Name JWUA -ErrorAction SilentlyContinue }
                            Remove-CimSession $cim -ErrorAction SilentlyContinue
                        }
                    } catch {
                        [void]$trail.Add("WMI/DCOM: $($_.Exception.Message)")
                    }
                }

                if (-not $succeeded -and [string]$r.Status -ne 'Cancelled') {
                    $r.Transport = 'none'; $r.Status = 'Unreachable'; $r.Ok = $false
                    $r.Error = ($trail.ToArray() -join ' ; ')
                    $r.Detail = "All transports failed: $($r.Error)"
                }
            }
        }
    }
    catch {
        $r.Status = 'FAILED'; $r.Detail = $_.Exception.Message
    }
    return $r
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel contract: the server injects a synchronized hashtable as
    # $Params['__job']; its 'Cancel' flag lets a running fan-out break cooperatively.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Map the UI action id to the worker op.
    $op = switch ($ActionId) {
        'diagnose'       { 'Diagnose' }
        'fleet-status'   { 'FleetStatus' }
        'os-audit'       { 'OsAudit' }
        'install-updates'{ 'InstallUpdates' }
        'pin'            { 'Pin' }
        'unpin'          { 'Unpin' }
        'forcediscovery' { 'ForceDiscovery' }
        'upgrade-drive'  { 'UpgradeDrive' }
        'installcab'     { 'InstallCab' }
        'checkupgrade'   { 'CheckUpgrade' }
        'setpagefile'    { 'SetPageFile' }
        'repair-health'  { 'RepairHealth' }
        'auto-fix'       { 'AutoFix' }
        'error-report'   { 'ErrorReport' }
        'ping'           { 'Ping' }
        default          { $null }
    }
    if (-not $op) { & $send @{ type='error'; text="Unknown action '$ActionId'." }; return @{ rows=@(); summary=@{} } }

    # Audit-action vocabulary the server logger accepts is EXACTLY 'TouchHost' or
    # 'VulnPatched' (any other value is rejected). Map each state-changing op to one;
    # the read-only Ping sweep maps to $null so it emits NO audit row (the desktop
    # twin likewise never records a ping as a logged action - it only grids it).
    #   Pin/Unpin = write/remove the WindowsUpdate TargetReleaseVersion policy -> a
    #               config-writing host touch -> 'TouchHost'.
    #   InstallCab = DISM /Add-Package feature-update install -> remediation -> 'VulnPatched'.
    #   SetPageFile = write the WMI page-file policy -> a config-writing host touch -> 'TouchHost'.
    #   ForceDiscovery = re-write policy + trigger SCCM/GPO/WU (and optionally reset WU) -> 'TouchHost'.
    #   CheckUpgrade / Diagnose = read-only harvest -> $null -> no audit (like Ping).
    $auditAction = switch ($op) {
        'Pin'            { 'TouchHost' }
        'Unpin'          { 'TouchHost' }
        'ForceDiscovery' { 'TouchHost' }
        'UpgradeDrive'   { 'VulnPatched' }
        'InstallCab'     { 'VulnPatched' }
        'SetPageFile'    { 'TouchHost' }
        # RepairHealth (DISM/SFC component-store repair) + AutoFix (per-device remediation)
        # are remediations -> 'VulnPatched'. ErrorReport is a read-only scan -> $null (no audit).
        'RepairHealth'   { 'VulnPatched' }
        'AutoFix'        { 'VulnPatched' }
        'ErrorReport'    { $null }
        # InstallUpdates = installs Windows Updates via the SYSTEM task -> remediation -> 'VulnPatched'.
        # OsAudit = read-only OS version audit scan -> $null (no audit row, like Diagnose/Ping).
        'InstallUpdates' { 'VulnPatched' }
        'OsAudit'        { $null }
        default          { $null }
    }

    # Targets: split (with '#' comment stripping), then keep only valid host/IP tokens.
    $raw = ConvertTo-JanetHostList ([string]$Params['targets'])
    $targets = New-Object System.Collections.ArrayList
    $skipped = 0
    foreach ($t in $raw) { if (Test-JanetTargetToken $t) { [void]$targets.Add($t) } else { $skipped++ } }
    if ($skipped) { & $send @{ type='log'; level='warn'; text="Skipped $skipped invalid target name(s)." } }
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    # Common options.
    $attemptOffline = ConvertTo-JanetBool $Params['attemptOffline'] $false
    $dryRun         = ConvertTo-JanetBool $Params['dryRun'] $false
    # InstallCab/SetPageFile reboot defaults ON (their manifest default); the new RepairHealth/
    # AutoFix reboot defaults OFF (their manifest default) so an absent 'reboot' never arms a
    # reboot wave / the self-guard for those ops.
    $rebootDefault  = if ($op -eq 'RepairHealth' -or $op -eq 'AutoFix') { $false } else { $true }
    $reboot         = ConvertTo-JanetBool $Params['reboot'] $rebootDefault
    $runWu          = ConvertTo-JanetBool $Params['runWu'] $false
    # v0.3.0 options: ForceDiscovery aggressive; Pin bypass + sccmRefresh; Unpin removeBypass
    # (removeBypass DEFAULTS to $true so an Unpin fully reverses a bypassed Pin).
    $aggressive     = ConvertTo-JanetBool $Params['aggressive'] $false
    $bypass         = ConvertTo-JanetBool $Params['bypass'] $false
    # sccmRefresh defaults ON for AutoFix (its manifest default), OFF elsewhere (Pin's default).
    $sccmDefault    = if ($op -eq 'AutoFix') { $true } else { $false }
    $sccmRefresh    = ConvertTo-JanetBool $Params['sccmRefresh'] $sccmDefault
    $removeBypass   = ConvertTo-JanetBool $Params['removeBypass'] $true
    # auto-fix per-category toggles (defaults mirror the manifest).
    $fixPolicy      = ConvertTo-JanetBool $Params['fixPolicy']   $true
    $fixBypass      = ConvertTo-JanetBool $Params['fixBypass']   $true
    $fixDrivers     = ConvertTo-JanetBool $Params['fixDrivers']  $true
    $driverSafe     = ConvertTo-JanetBool $Params['driverSafe']  $true
    $fixPause       = ConvertTo-JanetBool $Params['fixPause']    $true
    $fixRepair      = ConvertTo-JanetBool $Params['fixRepair']   $false
    $clearStaging   = ConvertTo-JanetBool $Params['clearStaging'] $false
    # upgrade-drive options: reboot a CONFIRMED-staged host on a countdown (OFF by default).
    $rebootWhenStaged = ConvertTo-JanetBool $Params['rebootWhenStaged'] $false
    $countdownSeconds = 300
    if ($Params['countdownSeconds']) { $cs2 = 0; if ([int]::TryParse([string]$Params['countdownSeconds'], [ref]$cs2)) { $countdownSeconds = $cs2 } }
    if ($countdownSeconds -lt 30)    { $countdownSeconds = 30 }
    if ($countdownSeconds -gt 86400) { $countdownSeconds = 86400 }
    # install-updates options: includeMU / allowHttp / allowWmi default ON (manifest defaults);
    # timeoutMin default 45, clamped 5-720. The WUA driver text is threaded to the worker.
    $includeMU      = ConvertTo-JanetBool $Params['includeMU'] $true
    $allowHttp      = ConvertTo-JanetBool $Params['allowHttp'] $true
    $allowWmi       = ConvertTo-JanetBool $Params['allowWmi'] $true
    $timeoutMin     = 45
    if ($Params['timeoutMin']) { $tm = 0; if ([int]::TryParse([string]$Params['timeoutMin'], [ref]$tm)) { $timeoutMin = $tm } }
    if ($timeoutMin -lt 5)   { $timeoutMin = 5 }
    if ($timeoutMin -gt 720) { $timeoutMin = 720 }
    $wuaDriver      = $script:WinUpgradeWuaDriver
    # Shared pin policy-write block threaded to the worker (reused by Pin + UpgradeDrive).
    $pinBlock       = $script:WinUpgradePinBlock
    # Diagnose constants + SCCM cycle GUIDs (defined once at module scope, copied EXACTLY
    # from the reference) threaded to the worker via the ArgFactory tail.
    $cpuPatterns    = $script:WinUpgradeCpuPatterns
    $minRAM         = $script:WinUpgradeMinRAMGB
    $minDisk        = $script:WinUpgradeMinDiskGB
    $minTPM         = $script:WinUpgradeMinTPMVersion
    $cycles         = $script:WinUpgradeCycles
    $product        = if ($Params['product']) { ([string]$Params['product']).Trim() } else { 'Windows 11' }
    $version        = if ($Params['version']) { ([string]$Params['version']).Trim() } else { '24H2' }
    # v0.4.0 target-version -> MinBuild gate. fleet-status / diagnose / upgrade-drive / auto-fix /
    # error-report pass a 'version' key resolved against $script:WinUpgradeTargets; default 24H2 /
    # 26100 keeps every existing behaviour identical. An unknown key on a version-select op falls
    # back to 24H2 (with a warning); pin / unpin / forcediscovery keep their free-text version.
    $minBuild       = 26100
    $versionKey     = $version.ToUpperInvariant()
    if ($script:WinUpgradeTargets.Contains($versionKey)) {
        $minBuild = [int]$script:WinUpgradeTargets[$versionKey].MinBuild
        $version  = [string]$script:WinUpgradeTargets[$versionKey].Version
    } elseif (@('FleetStatus','Diagnose','UpgradeDrive','AutoFix','ErrorReport') -contains $op) {
        & $send @{ type='log'; level='warn'; text="Unknown target version '$version' - defaulting to 24H2 (build 26100). Valid: $([string]::Join(', ', @($script:WinUpgradeTargets.Keys)))." }
        $version = '24H2'; $minBuild = 26100
    }
    # SetPageFile size: default 16 GB, clamped 1-128 GB (worker re-clamps as a backstop).
    $sizeMb         = 16384
    if ($Params['sizeMb']) { $sm = 0; if ([int]::TryParse([string]$Params['sizeMb'], [ref]$sm)) { $sizeMb = $sm } }
    if ($sizeMb -lt 1024)   { $sizeMb = 1024 }
    if ($sizeMb -gt 131072) { $sizeMb = 131072 }
    # CAB source: a Browse/drag upload (server temp path) wins over a typed path.
    $cabUpload      = if ($Params['cabUpload']) { ([string]$Params['cabUpload']).Trim() } else { '' }
    $cabTyped       = if ($Params['cabPath'])   { ([string]$Params['cabPath']).Trim() }   else { '' }
    $cabPath        = if ($cabUpload) { $cabUpload } else { $cabTyped }
    $cabName        = ''
    # A Browse/drag upload always lands in a LOCAL server-temp dir, so only an
    # operator-typed UNC path (\\server\share\...) is eligible for the target-pull
    # fast path; everything else keeps the -ToSession push.
    $cabFromShare   = ((-not $cabUpload) -and ($cabTyped -like '\\*'))

    # Per-action validation + tuning.
    $defThreads    = 16
    $maxJobSeconds = 120
    if ($op -eq 'Ping')           { $defThreads = 32 }
    if ($op -eq 'CheckUpgrade')   { $defThreads = 16 }
    if ($op -eq 'Diagnose')       { $defThreads = 16; $maxJobSeconds = 180 }
    if ($op -eq 'FleetStatus')    { $defThreads = 16; $maxJobSeconds = 180 }
    if ($op -eq 'SetPageFile')    { $defThreads = 8; $maxJobSeconds = 180 }
    if ($op -eq 'ForceDiscovery') { $defThreads = 8; $maxJobSeconds = 600 }
    # UpgradeDrive: heavy per host (readiness read + pin + WU trigger + re-read + optional
    # reboot); low fan-out + a wide watchdog.
    if ($op -eq 'UpgradeDrive')   { $defThreads = 8; $maxJobSeconds = 600 }
    # RepairHealth (DISM+SFC) + AutoFix-with-repair can run 15-45 min -> a wide watchdog.
    if ($op -eq 'RepairHealth')   { $defThreads = 4;  $maxJobSeconds = 3600 }
    if ($op -eq 'AutoFix')        { $defThreads = 8;  $maxJobSeconds = if ($fixRepair) { 3600 } else { 900 } }
    if ($op -eq 'ErrorReport')    { $defThreads = 16; $maxJobSeconds = 300 }
    # OsAudit: light read-only registry read -> wide fan-out. InstallUpdates: the SYSTEM task
    # can run for many minutes, so the watchdog must exceed the per-host poll timeout.
    if ($op -eq 'OsAudit')        { $defThreads = 16; $maxJobSeconds = 120 }
    if ($op -eq 'InstallUpdates') { $defThreads = 8;  $maxJobSeconds = ($timeoutMin * 60) + 300 }
    if ($op -eq 'Pin' -or $op -eq 'UpgradeDrive') {
        if ([string]::IsNullOrWhiteSpace($product) -or [string]::IsNullOrWhiteSpace($version)) {
            & $send @{ type='log'; level='warn'; text='Product and Version are both required to drive/pin a target release.' }
            return @{ rows=@(); summary=@{ total=$targets.Count } }
        }
    }
    # Self-guard: never MUTATE the JANET dispatcher box itself mid-fan-out. Drop any target that
    # IS this machine BEFORE dispatch. This began as a reboot-only guard (a self-reboot kills the
    # HttpListener mid-dispatch), but EVERY state-changing op can harm self, not just the rebooters:
    #   Pin / Unpin    -> write/remove the WindowsUpdate TargetReleaseVersion policy
    #   ForceDiscovery -> re-writes policy + triggers WU; in aggressive mode stops WU services and
    #                     renames SoftwareDistribution (would disrupt the dispatcher's own WU stack)
    #   UpgradeDrive   -> pins + triggers WU + may reboot a confirmed-staged host ($rebootWhenStaged)
    #   InstallCab     -> DISM feature-update install (+ reboot when $reboot)
    #   SetPageFile    -> writes the WMI page-file policy (+ reboot when $reboot)
    #   RepairHealth   -> DISM/SFC component-store repair (+ reboot when $reboot)
    #   AutoFix        -> per-device remediation (+ reboot when $reboot)
    # So the guard now runs for ALL mutating ops when not in dry-run. The read-only ops on this
    # path - Ping / CheckUpgrade / Diagnose / FleetStatus / ErrorReport (all map to $null audit) -
    # legitimately query self and are deliberately NOT dropped; a $dryRun preview changes no state
    # and likewise keeps self.
    # (Restart tool audit#10; the in-worker DNS guard does NOT catch self - our own name
    # resolves to us so it passes.)
    # InstallUpdates INSTALLS updates + some force a REBOOT -> it MUST self-guard (never hit the
    # JANET console). OsAudit is a read-only scan -> deliberately NOT dropped (self is auditable).
    $mutatesTarget = ( @('Pin','Unpin','ForceDiscovery','UpgradeDrive','InstallCab','SetPageFile','RepairHealth','AutoFix','InstallUpdates') -contains $op )
    if ($mutatesTarget -and -not $dryRun) {
        $keptT = New-Object System.Collections.ArrayList
        $selfT = New-Object System.Collections.ArrayList
        foreach ($t in $targets) { if (Test-WinUpgradeHostIsSelf $t) { [void]$selfT.Add($t) } else { [void]$keptT.Add($t) } }
        if ($selfT.Count -gt 0) {
            $targets = $keptT
            & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host from this reboot wave ($($selfT -join ', ')) - a self-reboot would abort the dispatch." }
            # Surface a dropped row per self-target so it is visible in the grid, not just the log.
            foreach ($s in $selfT) { & $send (@{ type='row' } + @{ Host=$s; Ping=''; Status='Skipped'; Detail='self-guard: dispatcher host - reboot suppressed' }) }
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='Only target was this dispatcher host - nothing to do.' }
                return @{ rows=@(); summary=@{ total=0; selfSkipped=$selfT.Count } }
            }
        }
    }
    if ($op -eq 'InstallCab') {
        $defThreads = 8
        $maxJobSeconds = 3600    # DISM feature-update install can run for minutes
        if (-not $dryRun) {
            if ([string]::IsNullOrWhiteSpace($cabPath) -or -not (Test-Path -LiteralPath $cabPath)) {
                & $send @{ type='log'; level='warn'; text="No CAB/MSU found. Enter a readable path or use Browse to upload one. ('$cabPath')" }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
        }
        if ($cabPath) { $cabName = Split-Path -Leaf $cabPath }
    }

    $threads = $defThreads
    if ($Params['threads']) {
        $tp = 0
        if ([int]::TryParse([string]$Params['threads'], [ref]$tp)) { $threads = $tp }
    }
    $threads = [Math]::Max(1, [Math]::Min(64, $threads))

    # ArgFactory: leading ',' wraps the arg list so the ONE pipeline unroll in the
    # BeginInvoke loop preserves each element (incl. the $cpuPatterns / $cycles arrays)
    # as a single positional argument. New v0.3.0 args appended at the END in the SAME
    # order as the appended worker param() tail (a mismatch silently corrupts every arg).
    # v0.4.0 args ($minBuild + the auto-fix toggles) appended at the END in the SAME order as the
    # worker param() tail (a mismatch silently corrupts every argument).
    # v0.5.0 args ($includeMU, $allowHttp, $allowWmi, $timeoutMin, $wuaDriver) appended at the END
    # in the SAME order as the worker param() tail (a mismatch silently corrupts every argument).
    $argFactory  = { param($h) ,@($h, $op, $Credential, $product, $version, $cabPath, $cabName, $cabFromShare, $reboot, $attemptOffline, $dryRun, $runWu, $sizeMb, $cancelJob, $stepQueue, $aggressive, $bypass, $sccmRefresh, $removeBypass, $cpuPatterns, $minRAM, $minDisk, $minTPM, $cycles, $rebootWhenStaged, $countdownSeconds, $pinBlock, $minBuild, $fixPolicy, $fixBypass, $fixDrivers, $driverSafe, $fixPause, $fixRepair, $clearStaging, $includeMU, $allowHttp, $allowWmi, $timeoutMin, $wuaDriver) }
    $rowOf       = {
        param($res)
        if ($op -eq 'FleetStatus') {
            # Build the rich Fleet Status row and classify Win24H2Status centrally. Timeout /
            # cancel / worker-error paths pass a bare {Host;Ping;Status;Detail} result with no
            # fleet fields -> those surface as Online=false + Error=<detail> (Offline for the
            # reachability skip, Error for a genuine failure) via the classifier below.
            $online  = [bool]$res.Online
            $status  = [string]$res.Status
            $errText = [string]$res.Error
            if (-not $errText -and $status -and (@('SCANNED','Skipped') -notcontains $status)) { $errText = [string]$res.Detail }
            $ob = 0; [void][int]::TryParse([string]$res.OsBuild, [ref]$ob)
            $eligible    = [bool]$res.Eligible
            $pending     = [bool]$res.PendingReboot
            $blockReason = [string]$res.BlockReason
            $win = Get-WinUpgradeFleetStatus -OsBuild $ob -Online $online -Eligible $eligible -BlockReason $blockReason -PendingReboot $pending -ErrorText $errText -MinBuild $minBuild -Version $version
            $fgb = -1.0
            try { if ($res.Contains('FreeGB') -and $null -ne $res['FreeGB']) { $fgb = [double]$res['FreeGB'] } } catch {}
            return @{
                Host          = $res.Host
                Online        = $online
                DisplayVersion= [string]$res.DisplayVersion
                OsBuild       = $ob
                FreeGB        = $fgb
                Win24H2Status = $win
                TargetVersion = $version
                Eligible      = $eligible
                BlockReason   = $blockReason
                Pinned        = [bool]$res.Pinned
                PinnedVersion = [string]$res.PinnedVersion
                PendingReboot = $pending
                Error         = $errText
            }
        }
        if ($op -eq 'UpgradeDrive') {
            # Rich drive row. Timeout / cancel / worker-error results arrive as a bare
            # {Host;Ping;Status;Detail} ordered hashtable with no drive fields -> surface
            # those as Error=<detail> via the null-safe getter + the FAILED/Cancelled test.
            $get = {
                param($k, $d)
                try { if ($res.Contains($k)) { $v = $res[$k]; if ($null -ne $v) { return $v } } } catch {}
                return $d
            }
            $status = [string]$res.Status
            $isErr  = ($status -eq 'FAILED' -or $status -eq 'Cancelled')
            return @{
                Host           = $res.Host
                Online         = [bool](& $get 'Online' $false)
                OsBuild        = [int](& $get 'OsBuild' 0)
                DisplayVersion = [string](& $get 'DisplayVersion' '')
                WasPinned      = [bool](& $get 'WasPinned' $false)
                TriggerResult  = [string](& $get 'TriggerResult' '')
                Staged         = [bool](& $get 'Staged' $false)
                Rebooted       = [bool](& $get 'Rebooted' $false)
                CountdownSec   = [int](& $get 'CountdownSec' 0)
                Skipped        = [string](& $get 'Skipped' '')
                Error          = if ($isErr) { [string]$res.Detail } else { [string](& $get 'Error' '') }
                Status         = $status
                TargetVersion  = $version
                Detail         = [string]$res.Detail
            }
        }
        if ($op -eq 'OsAudit') {
            # OS Version audit row (the manifest's 11 columns) + Status/Detail for the generic
            # grid. Timeout / cancel / worker-error results arrive as a bare {Host;Ping;Status;
            # Detail} -> surface Online=false + Error=<detail> and blank check columns.
            $get = { param($k, $d) try { if ($res.Contains($k)) { $v = $res[$k]; if ($null -ne $v) { return $v } } } catch {}; return $d }
            $status = [string]$res.Status
            $isErr  = ($status -eq 'FAILED' -or $status -eq 'Cancelled' -or $status -eq 'Skipped')
            return @{
                Host       = $res.Host
                Online     = [bool](& $get 'Online' $false)
                Generation = [string](& $get 'Generation' '')
                ReleaseId  = [string](& $get 'ReleaseId' '')
                Edition    = [string](& $get 'Edition' '')
                Gen11      = [string](& $get 'Gen11' '')
                Rel24H2    = [string](& $get 'Rel24H2' '')
                EntEdition = [string](& $get 'EntEdition' '')
                Verdict    = [string](& $get 'Verdict' '')
                Failed     = [string](& $get 'Failed' '')
                Error      = if ($isErr) { [string]$res.Detail } else { [string](& $get 'Error' '') }
                Status     = $status
                Detail     = [string]$res.Detail
            }
        }
        if ($op -eq 'InstallUpdates') {
            # install-updates row (Host/Online/Transport/Method/Status/KBs/Reboot/Error) +
            # Detail for the generic grid. Timeout/cancel/worker-error -> Error=<detail>.
            $get = { param($k, $d) try { if ($res.Contains($k)) { $v = $res[$k]; if ($null -ne $v) { return $v } } } catch {}; return $d }
            $status = [string]$res.Status
            $isErr  = ($status -eq 'FAILED' -or $status -eq 'Cancelled')
            return @{
                Host      = $res.Host
                Online    = [bool](& $get 'Online' $false)
                Transport = [string](& $get 'Transport' '')
                Method    = [string](& $get 'Method' '')
                Status    = $status
                KBs       = [string](& $get 'KBs' '')
                Reboot    = [bool](& $get 'Reboot' $false)
                Error     = if ($isErr) { [string]$res.Detail } else { [string](& $get 'Error' '') }
                Detail    = [string]$res.Detail
            }
        }
        if ($op -eq 'RepairHealth') {
            # Rich repair row. Timeout / cancel / worker-error results arrive as a bare
            # {Host;Ping;Status;Detail} -> the Dism/Sfc/RebootNeeded getters fall back to defaults.
            $get = { param($k, $d) try { if ($res.Contains($k)) { $v = $res[$k]; if ($null -ne $v) { return $v } } } catch {}; return $d }
            return @{
                Host         = $res.Host
                Ping         = [string]$res.Ping
                Status       = [string]$res.Status
                Dism         = [string](& $get 'Dism' '')
                Sfc          = [string](& $get 'Sfc' '')
                RebootNeeded = [bool](& $get 'RebootNeeded' $false)
                Detail       = [string]$res.Detail
            }
        }
        if ($op -eq 'AutoFix') {
            $get = { param($k, $d) try { if ($res.Contains($k)) { $v = $res[$k]; if ($null -ne $v) { return $v } } } catch {}; return $d }
            return @{
                Host         = $res.Host
                Ping         = [string]$res.Ping
                Status       = [string]$res.Status
                Fixes        = [string](& $get 'Fixes' '')
                RebootNeeded = [bool](& $get 'RebootNeeded' $false)
                Detail       = [string]$res.Detail
            }
        }
        if ($op -eq 'ErrorReport') {
            # Only reached when the worker returned NO 'Rows' array - i.e. the host was
            # never scanned (offline skip, timeout, cancel, worker error). Surface that as
            # one error-schema row so the ERRORS grid shows WHY instead of a blank line
            # (field lesson: a wedged WU/WMI stack that times out is itself a finding).
            $status = [string]$res.Status
            $isOffline = ($status -eq 'OFFLINE' -or $status -eq 'Skipped')
            return @{
                Host     = $res.Host
                Category = if ($isOffline) { 'UNREACHABLE' } else { 'SCAN_FAILED' }
                Severity = 'WARN'
                Evidence = [string]$res.Detail
                Fix      = if ($isOffline) { 'Verify the host is on and reachable (TCP 5985/5986/445), or retry with "Attempt even if offline".' }
                           else { 'Scan did not complete - the WU/WMI stack may be wedged; run winmgmt /verifyrepository on the host and retry.' }
            }
        }
        @{ Host=$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail }
    }

    $modeNote  = if ($dryRun) { ' [DRY-RUN]' } else { '' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }
    # Thread-safe step queue: the per-host worker enqueues live phase messages
    # (Copying / DISM / Rebooting); the harvest loop dequeues each pass and streams a
    # phase row so each host narrates its progress (parity with pkginstall + the desktop
    # "Copying.../Installing..." recolour). The final row, keyed by Host, replaces it.
    $stepQueue = [System.Collections.Concurrent.ConcurrentQueue[psobject]]::new()
    & $send @{ type='status'; text="Starting '$ActionId'$modeNote on $($targets.Count) host(s) with $threads thread(s)..." }
    # Persistent, timestamped START entry in the activity log (desktop-tool parity:
    # type='status' only updates the single transient status line and is overwritten;
    # type='log' lines accumulate as scrollback).
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START '$ActionId'$modeNote on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    # seed Queued rows so the operator sees the whole target list immediately (ping is
    # instant, so it skips straight to Online/Offline rather than flashing Queued).
    if ($op -eq 'FleetStatus') {
        foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Online=$false; DisplayVersion=''; OsBuild=0; FreeGB=-1; Win24H2Status='Queued'; Eligible=$false; BlockReason=''; Pinned=$false; PinnedVersion=''; PendingReboot=$false; Error='' }) }
    }
    elseif ($op -eq 'UpgradeDrive') {
        foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Online=$false; OsBuild=0; DisplayVersion=''; WasPinned=$false; TriggerResult=''; Staged=$false; Rebooted=$false; CountdownSec=0; Skipped=''; Error=''; Status='Queued'; Detail='waiting for a runspace...' }) }
    }
    elseif ($op -eq 'ErrorReport') {
        # No Queued seed for ErrorReport: its grid is keyed Host|Category|Evidence (one row
        # per detected error), so a placeholder row can never be replaced by a real row and
        # would linger as a stale "queued" line. The progress strip covers the feedback.
    }
    elseif ($op -ne 'ping') { foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Detail='waiting for a runspace...' }) } }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:WinUpgradeWorker)
        foreach ($a in (& $argFactory $h)) { [void]$ps.AddArgument($a) }
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartTime=(Get-Date) })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0
    $stopHandles = New-Object System.Collections.ArrayList
    $cancelling  = $false
    $coopDeadline = [datetime]::MaxValue
    try {
        while ($done -lt $jobs.Count) {
            # paint the live phase steps (Copying / DISM / Rebooting) workers enqueued
            $msg = $null
            while ($stepQueue.TryDequeue([ref]$msg)) {
                & $send (@{ type='row' } + @{ Host=$msg.Hostname; Ping=''; Status=$msg.Step; Detail=$msg.Detail })
            }
            foreach ($j in $jobs) {
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = [ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="worker error: $($_.Exception.Message)"; Ok=$false } }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null
                    if ($null -eq $res) { $res = [ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail='worker returned no result'; Ok=$false } }
                    $ok = [bool]$res.Ok
                    if ($ok) { $okCount++ } else { $failCount++ }
                    # Generic multi-row support: when a worker returns a non-empty 'Rows' array
                    # (error-report emits one row per detected error), stream each entry as its own
                    # type='row' event instead of the single $rowOf row. Any future op can use this.
                    $resRows = $null
                    try { if ($res.Contains('Rows')) { $resRows = $res['Rows'] } } catch { try { $resRows = $res.Rows } catch { $resRows = $null } }
                    if ($resRows -and @($resRows).Count -gt 0) {
                        foreach ($rr in @($resRows)) {
                            [void]$rows.Add($rr)
                            & $send (@{ type='row' } + $rr)
                        }
                    } else {
                        $row = & $rowOf $res
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                    }
                    # Diagnose / ForceDiscovery return a full multi-line report on $res.Report;
                    # stream it to the activity log line-by-line, colour tags kept as text prefixes
                    # ([PASS]/[FAIL]/[WARN]/[BLOCK]/[REC]/[INFO], mirror of reference lines 884-895)
                    # that the VIEW colours. level is a best-effort hint only.
                    $rpt = ''
                    try { $rpt = [string]$res.Report } catch { $rpt = '' }
                    if ($rpt) {
                        & $send @{ type='log'; level='info'; text="----- $($res.Host) : $([string]$res.Status) -----" }
                        foreach ($ln in ($rpt -split "`r?`n")) {
                            if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                            $lvl = 'info'
                            if     ($ln -match '^\s*\[FAIL\]' -or $ln -match '^\s*\[BLOCK\]') { $lvl = 'error' }
                            elseif ($ln -match '^\s*\[WARN\]' -or $ln -match '^\s*WARN:')     { $lvl = 'warn' }
                            & $send @{ type='log'; level=$lvl; text=$ln }
                        }
                    }
                    # One audit row per host per state-changing op, matching the depth
                    # at which the desktop twin records each result. $auditAction is $null
                    # only for the read-only Ping sweep -> no emit. Key the RESULT on $ok
                    # (not an exact status string) with a DRY-RUN/Skipped/Cancelled skip-set:
                    # those set Ok=$true but perform NO work, so they audit as 'Skipped' with
                    # itemCount=0 -- never a phantom Success. A real install success ('DONE'
                    # OR 'NEEDS REBOOT' - package staged, reboot pending) audits Success/1;
                    # everything else is a Failure/0.
                    if ($auditAction) {
                        $auditResult = if ('DRY-RUN','Skipped','Cancelled' -contains [string]$res.Status) { 'Skipped' } elseif ($ok) { 'Success' } else { 'Failure' }
                        $auditItems  = if ($auditResult -eq 'Success') { 1 } else { 0 }
                        & $send @{ type='audit'; action=$auditAction; target=$res.Host; result=$auditResult; itemCount=$auditItems; detail=([string]$res.Detail) }
                    }
                    $done++
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Watchdog: a wedged host must not stall the run. BeginStop only (never
            # Dispose here - it blocks); the handle settles via EndStop in finally.
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.Async.IsCompleted -and ((Get-Date) - $j.StartTime).TotalSeconds -gt $maxJobSeconds) {
                    try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                    $j.PS = $null
                    $failCount++; $done++
                    # A read-only Diagnose that times out usually means the target's WU/WMI stack
                    # is wedged (field batch: one box was unreadable for exactly this reason) - point
                    # the operator at the repository check instead of a bare timeout message.
                    $timeoutDetail = "Job timeout over ${maxJobSeconds}s"
                    if ($op -eq 'Diagnose') { $timeoutDetail = "Job timeout over ${maxJobSeconds}s - target's WU/WMI stack may be wedged. Check 'winmgmt /verifyrepository' and consider a WMI repair (winmgmt /salvagerepository) before re-scanning." }
                    $trow = & $rowOf ([ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail=$timeoutDetail; Ok=$false })
                    [void]$rows.Add($trow)
                    & $send (@{ type='row' } + $trow)
                    # Abandon/timeout path for this host is still a failure of the
                    # state-changing op -> audit it (skip for the read-only Ping sweep).
                    if ($auditAction) { & $send @{ type='audit'; action=$auditAction; target=$j.Host; result='Failure'; itemCount=0; detail="Job timeout over ${maxJobSeconds}s" } }
                    & $send @{ type='log'; level='warn'; text="[$($j.Host)] TIMEOUT after ${maxJobSeconds}s - aborting" }
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                if (-not $cancelling -and (& $cancelCheck)) {
                    $cancelling = $true
                    if ($cancelJob) { try { $cancelJob['Cancel'] = $true } catch {} }
                    $coopDeadline = (Get-Date).AddMilliseconds(8000)
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; signalling in-flight host(s) to stop cooperatively...' }
                }
                if ($cancelling -and (Get-Date) -ge $coopDeadline) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                            $j.PS = $null
                            $failCount++; $done++
                            $crow = & $rowOf ([ordered]@{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Ok=$false })
                            [void]$rows.Add($crow)
                            & $send (@{ type='row' } + $crow)
                            # Operator-cancel/force-stop path for this host -> audit the
                            # abandoned state-changing op (skip for the read-only Ping sweep).
                            if ($auditAction) { & $send @{ type='audit'; action=$auditAction; target=$j.Host; result='Failure'; itemCount=0; detail='cancelled by operator' } }
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Cancel grace elapsed; remaining host(s) force-stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
    } finally {
        foreach ($sh in $stopHandles) {
            try { $sh.PS.EndStop($sh.Handle) } catch {}
            try { $sh.PS.Dispose() } catch {}
        }
        try { $pool.Close(); $pool.Dispose() }
        catch { & $send @{ type='log'; level='warn'; text="Runspace pool close error: $($_.Exception.Message)" } }
    }

    $skipNote = if ($skipped) { "  (Skipped $skipped invalid target name(s))" } else { '' }
    & $send @{ type='status'; text="Done$modeNote. $okCount ok, $failCount failed of $($jobs.Count)." }
    # Persistent FINISHED tally in the activity log (desktop-tool parity).
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] FINISHED$modeNote. OK=$okCount  Failed=$failCount  of $($jobs.Count).$skipNote" }

    if ($op -eq 'FleetStatus') {
        # Roll the per-host rows up into the fleet posture summary. Counts are keyed off the
        # single Win24H2Status verdict (card-aligned); Pinned is tallied independently as a
        # secondary flag. blockBreakdown counts each failing-check reason across Blocked hosts.
        $fleet = [ordered]@{
            total=$jobs.Count; already24h2=0; ready=0; blocked=0; pendingReboot=0;
            pinned=0; on23h2OrOlder=0; online=0; offline=0; errors=0
        }
        $blockBreak = @{}
        foreach ($row in $rows) {
            if ([bool]$row.Online) { $fleet.online++ } else { $fleet.offline++ }
            if ([bool]$row.Pinned) { $fleet.pinned++ }
            $ob = 0; [void][int]::TryParse([string]$row.OsBuild, [ref]$ob)
            if ($ob -gt 0 -and $ob -lt 26100) { $fleet.on23h2OrOlder++ }
            $ws = [string]$row.Win24H2Status
            if     ($ws -like 'Already *')    { $fleet.already24h2++ }   # 'Already 24H2+' / 'Already 25H2+'
            elseif ($ws -eq 'Ready')          { $fleet.ready++ }
            elseif ($ws -eq 'Pending reboot') { $fleet.pendingReboot++ }
            elseif ($ws -like 'Blocked:*') {
                $fleet.blocked++
                foreach ($rz in (([string]$row.BlockReason) -split ';')) {
                    $rt = $rz.Trim()
                    if ($rt) { if ($blockBreak.ContainsKey($rt)) { $blockBreak[$rt]++ } else { $blockBreak[$rt] = 1 } }
                }
            }
            elseif ($ws -eq 'Offline') { }   # already tallied via the offline counter
            else { $fleet.errors++ }
        }
        $fleet.blockBreakdown = $blockBreak
        return @{ rows = @($rows); summary = $fleet }
    }

    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; failed=$failCount; skipped=$skipped } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
