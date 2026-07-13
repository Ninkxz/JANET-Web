# =============================================================================
#  JanetWeb.c2c.psm1  ->  C2C Readiness (Comply-to-Connect quarantine predictor)
#
#  Net-new JANET Web tool (no desktop twin). Fans out ONE consolidated read-only
#  WinRM probe across the targets and PREDICTS whether each host would be
#  QUARANTINED under AFI/MPTO Comply-to-Connect rule 3.B.2.B. It CHANGES NOTHING
#  and never needs an admin session (read-only, like the WPT ping / bulk-scan and
#  the Windows Upgrade Diagnose action).
#
#  The probe runs 11 C2C checks. Each yields a status PASS / FAIL / EXT / ERROR and a
#  short Detail, and runs inside ONE Invoke-Command round-trip ON the target, wrapped in
#  its own try/catch so one failed check becomes ERROR and never aborts the probe.
#
#  v1.10.0 aligns the verdict to the authoritative C2C TASKORD 26-0822 Tanium dashboard,
#  which quarantines on ONLY 5 rules and treats the rest as audit/informational. Each
#  pillar carries a TIER ($script:C2cPillarTier); the verdict scores ONLY the quarantine
#  tier, so stricter-than-TASKORD JANET checks stay visible + fixer-remediable but never
#  falsely predict quarantine:
#    Quarantine : Firewall, AntiMalware (Defender installed + sig<7d + MDE OrgId),
#                 Patches (security, 7-day grace), Encryption (C: Protection ON), Vuln (EXT)
#    Audit      : PkiRoots, OSVersion            (shown, never quarantines - matches
#                 the dashboard's "you cannot be non-compliant for audit rules")
#    Info       : AppWhitelist, Agents, COAMS    (advisory; not a TASKORD rule)
#    Attest     : Monitoring (Tanium)            (a dead client cannot attest -> NOT ATTESTING)
#
#  v1.11.0 reworks the view fix surface to one CARD per fixable pillar (view-only; targeting semantics unchanged).
#  v1.12.0 DUAL-MODE fixes: with a CSV imported, fixes stay import-scoped (allow-list). With NO import,
#          fixes run in MANUAL mode - dialing EXACTLY the typed Target Computers for the chosen pillar(s),
#          so you can load machines and run a manual C2C patch without an import (fix-lockscreen already did
#          this). Every guard is unchanged (FIX confirm, self-guard, wrong-box abort, verify-first). Reachability
#          also probes WinRM HTTPS 5986 (after HTTP 5985), auto-switching that host's session to -UseSSL.
#
#  Verdict (computed admin-side, quarantine-tier only):
#    QUARANTINE RISK  = >= 1 quarantine-tier FAIL   (Detail lists the failing pillars)
#    CHECK ERRORS     = 0 quarantine FAIL but >= 1 quarantine-tier ERROR
#    NOT ATTESTING    = only Monitoring (Tanium) failing - box invisible to the dashboard
#    READY            = 0 of the above (audit/info fails are advisory, shown in Detail)
#    OFFLINE          = host unreachable (TCP 5985/5986/445)
#  Vuln + COAMS are EXT (server-side ARAD/ACAS/ePO) - reported, never scored.
#
#  Baseline config (UPR/biosfirmware pattern): an editable JanetLocal\c2c-baseline.json
#  read FRESH each scan, overlaid on the embedded defaults below. The tool never
#  WRITES the file (no SMB atomic-write hazard) and works even if it is missing.
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'c2c'
        name     = 'C2C Nemesis'
        version  = '1.15.1'
        category = 'Remediation'
        summary  = 'C2C Nemesis - Comply-to-Connect (AFI/MPTO rule 3.B.2.B) remediation: (1) IMPORT the Tanium "C2C Compliance Status" CSV export, de-duplicate per host, bucket each failing rule into a canonical pillar with a routing hint, and emit a run-all plan (each host + its own fixable failed pillars); the import drives one CARD PER FIXABLE PILLAR in the view (click its host count to review the flagged hosts); (2) PER-PILLAR FIX (destructive) - six individually runnable endpoint-fixable pillars, each dialing ONLY the hosts the imported CSV flagged for THAT pillar (server-re-derived from the CSV every call and intersected against the submitted host list as an allow-list - never the whole target list; a submitted host not flagged for the pillar is dropped), each with pillar-named result labels: Monitoring (verify Tanium SOFTWARE installed via uninstall registry AND heal the Tanium client service), Firewall (enable disabled profiles), AntiMalware (heal Defender/MDE, honouring AMRunningMode so Passive / EDR Block Mode boxes primary-managed by MDE Sense are left protected, not force-RTP''d), Patches (kick the MECM cycle), Encryption (resume/ENABLE BitLocker across ALL FIXED VOLUMES - OS volume via FVE policy assert + TPM protector + Entra-first/AD-fallback recovery-key escrow + XtsAes256, and fixed DATA volumes via escrow-first RecoveryPassword protector + XtsAes256 + auto-unlock, removable/USB never touched), AntiMalware (heal Defender/MDE, honouring AMRunningMode so Passive / EDR Block Mode boxes primary-managed by MDE Sense are left protected, not force-RTP''d), and PkiRoots (install the DoD trust bundle .cer files ADDITIVELY into LocalMachine Root/CA/Disallowed via WinRM); (3) RUN ALL - re-derive the authoritative plan from the imported CSV server-side and fix every non-compliant host''s OWN failed pillars only in one pass, intersecting the submitted plan - the view sends the CHECKED pillar cards'' host sets (a client host/pillar pair the import did not flag is dropped); (4) READ-ONLY quarantine-predictor scan - fan out one consolidated WinRM probe per host, run 11 tiered C2C checks aligned to the TASKORD 26-0822 dashboard (5 QUARANTINE pillars scored, 2 AUDIT + 3 INFO advisory, Monitoring=ATTEST), flag each host READY / QUARANTINE RISK / NOT ATTESTING; (5) READ-ONLY VERSION CHECK - per host read the 64/32-bit uninstall registry for a product DisplayName substring and compare its DisplayVersion to an optional target (UP TO DATE / OUTDATED / NEWER / NOT INSTALLED). An opt-in RPC-based WinRM-heal pre-step (default off, often blocked) can recover a stopped remote WinRM service before the fix / version fan-out. Vuln -> ACAS/Reports/KEV, OS Version -> Windows Upgrade, STIG -> Reports. (6) FIX LOCK SCREEN / WALLPAPER CACHE (opt-in, destructive) - remediate the Windows 11 cached quarantine lock screen / desktop wallpaper by forcing the HKLM Personalization policy (LockScreenImage + DesktopImage*) to a default Windows image, only where no value is already set; a standalone utility fix, not a scored pillar and never in run-all. (7) FIX JAVA (opt-in, destructive) - remove Oracle/Sun Java older than 8u491 (installed products via msiexec, JavaSoft registry residue, Program Files folders; OpenJDK/Temurin/Corretto and UNKNOWN versions never touched); a standalone utility fix that clears vulnerability-scanner Java findings, not a scored pillar and never in run-all.'
        actions  = @(
            @{
                id          = 'scan'
                label       = 'C2C Readiness Scan'
                description = 'Read-only prediction of Comply-to-Connect quarantine, aligned to the C2C TASKORD 26-0822 dashboard. Per host, one consolidated WinRM probe runs 11 checks, each tiered: QUARANTINE pillars (the only ones that predict quarantine) = Firewall, AntiMalware (Defender installed + signatures <7 days + MDE Org ID), Patches (security updates past a 7-day grace), Encryption (C: Protection ON), Vuln (EXT, AQC server-side); AUDIT pillars (shown, never quarantine) = PKI Trust Roots, OS Version (Win11/24H2+/Enterprise); INFO pillars (advisory) = AppWhitelist, Agents, COAMS; ATTEST = Monitoring (Tanium). Verdict: QUARANTINE RISK (>=1 quarantine FAIL), NOT ATTESTING (only Tanium down - box invisible to the dashboard), CHECK ERRORS, READY (audit/info findings shown as advisory), or OFFLINE. The full colour-tagged report streams to the activity log. Changes NOTHING and needs no admin session.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'import'
                label       = 'Import C2C Compliance CSV'
                description = 'Parse the Tanium "C2C Compliance Status" CSV export (the multiline Compliance cell per host), de-duplicate by host (worst row wins - Non-Compliant over Compliant), map each rule to a canonical pillar (Encryption / AntiMalware / PkiRoots / Patches / Vuln / OSVersion / STIG, unknown rules surfaced verbatim), and summarize per pillar with a routing hint (fixable HERE via Mass Fix, or route to ACAS / Windows Upgrade / Reports). Read-only - local parse, no WinRM, no credential.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Compliance','Failed','Audit','Fqdn')
                inputs      = @(
                    @{ name='csvPath'; label='C2C Compliance CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='csvText'; label='...or paste CSV text'; type='textarea'; required=$false }
                )
            }
            @{
                id          = 'fix-monitoring'
                label       = 'Fix Monitoring (Tanium)'
                description = 'DESTRUCTIVE (service state). Heal the endpoint-monitoring pillar on each target in one WinRM round-trip. First it verifies the Tanium SOFTWARE is installed by scanning the uninstall registry (HKLM 64- and 32-bit Uninstall keys for a DisplayName matching "Tanium"), then the Tanium client service (name from c2c-baseline.json, default "Tanium Client"): if the service is Running it is left alone (ALREADY MONITORED); if it exists but is Stopped/not-Automatic it is set to StartType Automatic and started, then re-read to verify (MONITORED); if the service is ABSENT but the software is installed it FAILs "repair via Software Center/MECM" (no service is created); if NEITHER the software nor the service is present it FAILs "deploy from Software Center/MECM". Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the Monitoring (Tanium) pillar on the import-flagged host(s) you checked? This changes service state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Checked host(s) - a subset of the Monitoring hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';        label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-firewall'
                label       = 'Fix Firewall'
                description = 'DESTRUCTIVE (firewall state). Enable any disabled Windows Firewall profile (Domain/Private/Public) on each target: Set-NetFirewallProfile -Enabled True (netsh advfirewall set <profile>profile state on fallback), then re-read all three profiles to verify. Result FIREWALL ENABLED (turned on) / ALREADY ENABLED (all three were on) / FAIL (a profile would not enable). Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the Firewall pillar on the import-flagged host(s) you checked? This enables disabled firewall profiles. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Checked host(s) - a subset of the Firewall hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';        label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-antimalware'
                label       = 'Fix AntiMalware (Defender)'
                description = 'DESTRUCTIVE (Defender state). Heal Microsoft Defender on each target using Get-MpComputerStatus.AMRunningMode: always set WinDefend/Sense to Automatic + Started; force Real-Time Protection on (Set-MpPreference) ONLY when AMRunningMode is Active - NEVER in Passive / EDR Block Mode (there MDE/Sense is primary and RTP off is correct, so forcing it would fight the MDE config); Update-MpSignature when the signature age exceeds sigMaxAgeHours (default 24h) via a SOURCE CHAIN (Defender-ScanFix v2.1): wuauserv+BITS pre-started, then default channel (WSUS/ConfigMgr) -> Microsoft Update -> MMPC HTTP, verified by re-reading the signature age after each rung (an all-sources failure reports the real 0x error from Defender event 2001; if a Microsoft-signed mpam-fe.exe full offline package is staged in Packages\DefenderDefinitions - shipped empty - it is Authenticode-validated admin-side and pushed over the same session as the LAST rung to exactly those all-sources-failed hosts, executed locally, verified by age re-read, then deleted from the target). A Passive/EDR box with Sense onboarded + fresh signatures reports NOCHANGE (already protected via MDE). The detail reports RunningMode / product+engine versions / last-update / age-hours. A missing MDE Sense service is a note, not a failure, when Defender itself is healthy. When the MDE Org ID is missing/mismatched (the TASKORD-scored value) a POLICY-DRIVEN onboarding heal ladder also runs: DiagTrack/Sense start types fixed (Sense depends on DiagTrack), onboarding blob present -> Sense restarted, blob missing -> gpupdate /force, STILL missing -> the embedded tenant OnboardingInfo blob is written as a bridge (the GPO asserts the same value) - with gateway-443 reachability diagnosed so a CONNECTIVITY-BLOCKED host is called out as a firewall/proxy problem, not retried locally. Result PROTECTED (something healed) / MDE ONBOARDED / ALREADY PROTECTED / IN PROGRESS (onboarding pending) / FAIL. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the AntiMalware (Defender) pillar on the import-flagged host(s) you checked? This changes Defender state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Checked host(s) - a subset of the AntiMalware hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';        label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-patches'
                label       = 'Fix Patches (MECM cycle)'
                description = 'DESTRUCTIVE (kicks a scan). Trigger the MECM Software Updates cycle on each target: Invoke-CimMethod root\ccm SMS_Client TriggerSchedule for {..113} (SUM scan) then {..108} (SUM eval). Installs run asynchronously and Tanium clears the finding after its next scan. Result PATCH CYCLE KICKED / FAIL (root\ccm unreachable - not a MECM client). Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the Patches pillar on the import-flagged host(s) you checked? This kicks the MECM patch cycle. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Checked host(s) - a subset of the Patches hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';        label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-encryption'
                label       = 'Fix Encryption (BitLocker)'
                description = 'DESTRUCTIVE (BitLocker). Iterates EVERY FIXED VOLUME (C:, D:, E:, ...) - removable/USB (BitLocker To Go), network and optical volumes are NEVER touched. Per fixed volume: On -> ALREADY ENCRYPTED; suspended (Off + FullyEncrypted) -> RESUME -> PROTECTION RESUMED (an encrypted OS volume MISSING its TPM protector gets one added first when the TPM is present+ready - BitLocker-TPM-ScanFix v7.11 port); EncryptionInProgress -> IN PROGRESS(percent); FullyDecrypted with "ENABLE BitLocker" NOT ticked -> SKIP (route desk-side). With "ENABLE BitLocker" ticked, a FullyDecrypted fixed volume is encrypted from here - ESCROW-FIRST and FAIL-CLOSED. OS volume (VolumeType OperatingSystem): mirror the enterprise USAF enable script - assert the FVE BitLocker policy once per host (recovery-key escrow + XtsAes256), reuse-or-add a RecoveryPassword protector, escrow Entra-first (BackupToAAD-BitLockerKeyProtector) with on-prem AD fallback (Backup-BitLockerKeyProtector) BEFORE any Enable-BitLocker, TPM-gated (TpmPresent+TpmReady) and domain-joined only, stale TPM protectors from prior failed attempts removed (safe: the volume is FullyDecrypted; prevents FVE_E_PROTECTOR_EXISTS), then Enable-BitLocker with a TPM protector + XtsAes256 full-volume. Fixed DATA volume (VolumeType Data): the OS volume must be BitLocker-on first (else SKIP - auto-unlock needs it), then escrow-first exactly like the OS path (Add RecoveryPassword protector -> escrow Entra-first / AD-fallback BEFORE Enable) with NO TPM protector, Enable-BitLocker XtsAes256 full-volume, dedup to exactly one escrowed recovery protector, and best-effort Enable-BitLockerAutoUnlock. If BOTH escrow paths fail for a volume, a protector we added is removed and that volume is NEVER encrypted; the recovery password is never emitted. Host rollup: any volume FAIL -> PARTIAL (all-fail -> FAILED), any FIXED/STARTED with no FAIL -> FIXED, all NOCHANGE -> NO CHANGE. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the Encryption (BitLocker) pillar on the import-flagged host(s) you checked? This changes BitLocker state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';          label='Checked host(s) - a subset of the Encryption hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';          label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='enableEncryption'; label='ENABLE BitLocker on decrypted FIXED volumes (OS: TPM; DATA: auto-unlock; RecoveryPassword->escrow, XtsAes256; removable never touched)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';          label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';          label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline';   label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-pki'
                label       = 'Fix PKI Trust Roots'
                description = 'DESTRUCTIVE (certificate store). Install the DoD trust bundle into the LocalMachine certificate stores on each target, ADDITIVELY. The engine reads the bundle folder ADMIN-SIDE once, before dialing any host: <folder>\root\*.cer -> Root store, <folder>\Intermediate\*.cer -> CA (intermediate) store, <folder>\Untrusted\*.cer -> Disallowed store, and any loose *.cer directly under <folder> -> Root (case-insensitive). If the folder is missing or yields ZERO certs the action ABORTS and dials nothing. Per host, over one WinRM round-trip, each store is opened ReadWrite and only certs whose thumbprint is NOT already present are added - the bundle install itself never removes anything. Two PKI-Fix-ScanFix v1.9 companions are OPT-IN via their own boxes (both default OFF; the core additive bundle install above always runs): (a) prunePki - EXPIRED retired DoD intermediates are pruned from the CA store ONLY when their subject matches the retired DOD EMAIL/ID/SW/DERILITY CA-n allowlist AND they are not one of the four legacy-keep intermediates this tool intentionally pushes (everything else expired - roots, machine identity, timestamping - is never touched); (b) fixRdp - a BROKEN RDP-tcp listener certificate (self-signed / expired / missing) is rebound to the newest valid CA-issued My-store cert with the Client Authentication EKU matching the host - the replacement is located BEFORE anything is cleared (no candidate = left untouched, SKIP) and a healthy CA-issued listener is never touched. Each companion runs only when its box is ticked. Result ROOTS INSTALLED (added N of M) / ROOTS ALREADY PRESENT (all M present) / EXPIRED PRUNED / RDP CERT REBOUND / FAIL. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the PKI Trust Roots pillar on the import-flagged host(s) you checked? This adds DoD trust bundle certificates to the LocalMachine stores. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';          label='Checked host(s) - a subset of the PKI Trust Roots hosts the import flagged'; type='hostlist'; required=$true },
                    @{ name='csvPath';          label='C2C Compliance CSV (per-pillar targets are re-derived from this import)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='certBundleFolder'; label='DoD trust bundle folder (server-readable path, e.g. a UNC path with root\*.cer, Intermediate\*.cer, Untrusted\*.cer)'; type='text'; required=$true },
                    @{ name='prunePki';         label='Prune expired retired DoD intermediates (CA store; the 4 legacy-keeps never touched)'; type='bool'; required=$false; default=$false },
                    @{ name='fixRdp';           label='Repair broken RDP listener (self-signed/expired/missing -> rebind CA-issued; healthy untouched)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';          label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='winrmHeal';        label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';          label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline';   label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-lockscreen'
                label       = 'Fix Lock Screen / Wallpaper Cache'
                description = 'DESTRUCTIVE (HKLM Personalization policy). Remediates the Windows 11 bug where a device keeps showing the CACHED C2C quarantine lock screen / desktop wallpaper after being unquarantined. Per host, over one WinRM round-trip, sets HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization: LockScreenImage (lock screen) and DesktopImagePath / DesktopImageUrl / DesktopImageStatus (desktop wallpaper) to a DEFAULT image resolved ON the target (the unquarantine package''s C:\ProgramData\Microsoft\User Account Pictures\LockScreen.jpg if present, else the built-in C:\Windows\Web defaults) - so Windows stops using the cached quarantine image. Writes a value ONLY where none is already set (never overwrites an operator/GPO value). Result FIXED (set lock and/or desktop) / NO CHANGE (already set) / SKIP (no default image on target) / FAIL. This is an OPT-IN utility fix, NOT a scored C2C pillar and NOT part of run-all. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Set the default lock screen / wallpaper policy on the target host(s)? Only values that are NOT already set are written (an existing policy is never overwritten). Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='winrmHeal';      label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-java'
                label       = 'Fix Java (remove outdated)'
                description = 'DESTRUCTIVE (uninstall + registry + filesystem). Java-Cleanup-ScanFix v1.1 port: C2C/vulnerability scanners flag hosts on stale Java registry keys even after the product is gone, and on genuinely old installs. Per host, over one WinRM round-trip, three evidence sources are scanned and anything OLDER than Java 8 Update 491 is removed: (1) INSTALLED PRODUCTS - the 64- and 32-bit Uninstall registry hives, Oracle/Sun PUBLISHER ONLY (OpenJDK / Temurin / Corretto are NEVER touched), uninstalled via msiexec /x {GUID} /qn /norestart (exit 0 and 3010=reboot-pending are success; a non-MSI entry is flagged for manual review); (2) REGISTRY RESIDUE - old version subkeys under HKLM JavaSoft (native + WOW6432Node) removed, a CurrentVersion value pointing at a removed version repointed to the newest remaining one, a product key emptied BY THIS CLEANUP dropped; (3) FILESYSTEM RESIDUE - old folders under Program Files\Java (both hives; in-use folders report FAILED). Verdicts: OLD (below 1.8.0_491) removed; OK (1.8.0_491+, any modern JDK 9/11/17/21) kept; UNKNOWN (unparseable version) NEVER auto-removed - listed for manual review. No reboots are forced. Result JAVA CLEANED / NO OLD JAVA / FAIL. An OPT-IN utility fix, NOT a scored C2C pillar and NOT part of run-all (it clears Vulnerability/AQC findings on the next scanner pass). Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Remove all Oracle/Sun Java OLDER than 8u491 (installed products, JavaSoft registry residue, Program Files folders) from the target host(s)? OpenJDK/Temurin/Corretto and unknown versions are never touched. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='winrmHeal';      label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'run-all'
                label       = 'RUN ALL - Fix Imported Non-Compliant Hosts'
                description = 'DESTRUCTIVE. Fix each imported non-compliant host''s OWN failed endpoint-fixable pillars only, in one pass. The plan is re-derived from the imported CSV (csvPath) ADMIN-SIDE and the client "plan" input (the JSON array the view built from the operator''s per-pillar host checkboxes, [{host,pillars:[...]}, ...]) is INTERSECTED against it: a client host/pillar pair the import did not flag is dropped with a warn, and a host absent from the import is dropped entirely. With no csvPath (or a CSV that parses to zero findings) the run is refused - nothing is dialed. Per host only its intersected pillars run. Unknown / non-endpoint-fixable pillar names are dropped per host (Vuln / OSVersion / STIG route elsewhere); a host left with zero fixable pillars is reported and never dialed. If a host plans PkiRoots and a valid cert bundle folder was supplied it is installed; if PkiRoots is planned but no bundle was given it is SKIPPED for that host (info note) without aborting the run. Same safety as the per-pillar fixes: self-guard drops the dispatcher host, wrong-box DNS mismatch aborts a host, per-host watchdog + operator cancel, and the operator must type FIX to confirm. Encryption only STARTS on a decrypted volume if "ENABLE BitLocker" is ticked.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Run ALL fixes across the imported non-compliant hosts (each host, its own failed pillars, re-derived from the CSV and intersected with your per-pillar selections)? This changes machines. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='plan';             label='Run-all plan (JSON: [{host,pillars:[...]}] - the operator''s per-pillar host selections)'; type='textarea'; required=$true },
                    @{ name='csvPath';          label='C2C Compliance CSV (the plan is re-derived from this import and the client plan intersected against it)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='enableEncryption'; label='ENABLE BitLocker on decrypted FIXED volumes (OS + data; only if a host plans Encryption)'; type='bool'; required=$false; default=$false },
                    @{ name='certBundleFolder'; label='DoD trust bundle folder (optional; needed only if a host plans PkiRoots. The two PkiRoots companions - prunePki / fixRdp - are opt-in via the PkiRoots card boxes and default OFF)'; type='text'; required=$false },
                    @{ name='confirm';          label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='winrmHeal';        label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';          label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline';   label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'version-check'
                label       = 'Version Check (read-only)'
                description = 'READ-ONLY. Per host, TCP-probe reachability (5985 then 445) then read BOTH the 64-bit and 32-bit (WOW6432Node) uninstall registry hives for an installed product whose DisplayName CONTAINS the given substring, and report its DisplayVersion. If a target version is supplied the installed version is compared with System.Version when both parse (else an ordinal string compare): UP TO DATE / OUTDATED / NEWER; with no target it reports INSTALLED / NOT INSTALLED only; unreachable hosts are OFFLINE. Changes nothing on the target (unless the opt-in RPC WinRM-heal is ticked, which may start a stopped remote WinRM service). No admin session, no confirm word.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Installed','Version','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='productMatch';   label='Product DisplayName contains (e.g. Google Chrome)'; type='text'; required=$true },
                    @{ name='targetVersion';  label='Target version (optional, e.g. 130.0.6723.117)'; type='text'; required=$false },
                    @{ name='winrmHeal';      label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';        label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
        )
    }
}

# --- Baseline config --------------------------------------------------------
# Embedded defaults (contract). Operators override/extend by editing
# JanetLocal\c2c-baseline.json; the tool never writes the file.
function Get-C2cBaselineDefaults {
    @{
        sigMaxAgeDays         = 7
        sigMaxAgeHours        = 24
        graceDays             = 7          # Patching: MECM-deadline/StartTime grace before a pending update counts (TASKORD rule 5)
        taniumService         = 'Tanium Client'
        securityAgentServices = @('masvc','mfemms','macmnsvc','WinDefend','Sense')
        dodRootThumbprints    = @()
    }
}

function Get-C2cBaselinePath { Join-Path $PSScriptRoot '..\JanetLocal\c2c-baseline.json' }

# Resolver for the SHIPPED DoD trust bundle (mirrors Get-C2cBaselinePath's $PSScriptRoot\..
# form). The repo ships the base bundle at Packages\DoD-Certs (Root\ Intermediate\
# Untrusted\ *.cer), so fix-pki / run-all can run with NO path typed - a blank
# certBundleFolder auto-falls-back here when the folder exists and holds >=1 .cer
# (see Resolve-C2cCertBundleFolder). Read-only: this module never writes the folder.
function Get-C2cDefaultCertBundlePath { Join-Path $PSScriptRoot '..\Packages\DoD-Certs' }

# Read the editable JanetLocal baseline fresh; returns @{ Config=@{...}; Source='...' }.
# Any problem (missing/corrupt/empty) falls back to the embedded defaults - a bad
# JSON never breaks a scan. Read-only: the file is never written by this module.
function Get-C2cBaseline {
    $cfg = Get-C2cBaselineDefaults
    try {
        $p = Get-C2cBaselinePath
        if (-not (Test-Path -LiteralPath $p)) { return @{ Config = $cfg; Source = 'embedded defaults (no JanetLocal\c2c-baseline.json)' } }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($null -eq $raw) { $raw = '' }
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Config = $cfg; Source = 'embedded defaults (baseline file empty)' } }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj) { return @{ Config = $cfg; Source = 'embedded defaults (baseline parsed empty)' } }
        $has = { param($n) $null -ne $obj.PSObject.Properties[$n] }
        if ((& $has 'sigMaxAgeDays') -and $null -ne $obj.sigMaxAgeDays) {
            $n = 0; if ([int]::TryParse([string]$obj.sigMaxAgeDays, [ref]$n)) { $cfg.sigMaxAgeDays = $n }
        }
        # sigMaxAgeHours (v1.7.0): the fleet-standard signature-freshness budget in HOURS
        # (default 24). If the operator omits it, fall back to sigMaxAgeDays * 24 so an
        # older baseline that only set days keeps its effective threshold.
        if ((& $has 'sigMaxAgeHours') -and $null -ne $obj.sigMaxAgeHours) {
            $nh = 0; if ([int]::TryParse([string]$obj.sigMaxAgeHours, [ref]$nh)) { $cfg.sigMaxAgeHours = $nh }
        } else {
            $cfg.sigMaxAgeHours = [int]$cfg.sigMaxAgeDays * 24
        }
        # graceDays (v1.8.0): Patching grace window in DAYS (default 7, TASKORD rule 5).
        if ((& $has 'graceDays') -and $null -ne $obj.graceDays) {
            $ng = 0; if ([int]::TryParse([string]$obj.graceDays, [ref]$ng)) { $cfg.graceDays = $ng }
        }
        if ((& $has 'taniumService') -and -not [string]::IsNullOrWhiteSpace([string]$obj.taniumService)) {
            $cfg.taniumService = [string]$obj.taniumService
        }
        if ((& $has 'securityAgentServices') -and $obj.securityAgentServices) {
            $cfg.securityAgentServices = @($obj.securityAgentServices | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }
        if ((& $has 'dodRootThumbprints') -and $obj.dodRootThumbprints) {
            $cfg.dodRootThumbprints = @($obj.dodRootThumbprints | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        }
        return @{ Config = $cfg; Source = 'JanetLocal\c2c-baseline.json (overlaid on defaults)' }
    } catch { return @{ Config = $cfg; Source = "embedded defaults (baseline read error: $($_.Exception.Message))" } }
}

# The 8 SCORED pillars are Monitoring/Firewall/AntiMalware/Patches/Encryption/
# AppWhitelist/Agents/PkiRoots. The verdict simply tallies FAIL/ERROR
# across the returned checks; the 2 EXT pillars (Vuln, COAMS) carry neither, so
# "count all FAIL" already equals "count the 8 scored FAIL" (no explicit set needed).

# --- Single-source endpoint probe: is the Tanium SOFTWARE installed? -----------
# Both the read-only scan (check #1 Monitoring) and the destructive fix-monitoring
# worker must answer "is Tanium installed?" identically. They run in SEPARATE remote
# sessions, so the answer lives here as ONE source string that crosses the WinRM
# boundary verbatim (strings serialize cleanly) and is dot-sourced remotely by each
# call site to define Get-C2cTaniumInstalled. It scans the 64- and 32-bit uninstall
# registry for a DisplayName matching 'Tanium' (the endpoint-readable install signal
# a Software Center / MECM deployment leaves behind) and returns
# @{ Installed=$bool; DisplayName=''; Version='' }.
#
#  v1.6.0 generalizes this to Get-C2cInstalledProduct -Match <substr> (case-
#  insensitive DisplayName substring) so the read-only Version Check, the Tanium
#  Monitoring check and the Monitoring fixer all share ONE registry-probe
#  implementation. Get-C2cTaniumInstalled is retained as a thin wrapper that calls
#  Get-C2cInstalledProduct -Match 'Tanium' (so every existing call site + test that
#  dot-sources this string and calls Get-C2cTaniumInstalled keeps working).
$script:C2cTaniumInstalledSrc = @'
function Get-C2cInstalledProduct {
    param([string]$Match)
    $needle = [string]$Match
    if (-not $needle) { return [pscustomobject]@{ Installed=$false; DisplayName=''; Version='' } }
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($p in $paths) {
        try {
            foreach ($k in @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue)) {
                $dn = [string]$k.DisplayName
                if ($dn -and ($dn -match [regex]::Escape($needle))) {
                    $ver = ''
                    try { $ver = [string]$k.DisplayVersion } catch { $ver = '' }
                    return [pscustomobject]@{ Installed=$true; DisplayName=$dn; Version=$ver }
                }
            }
        } catch {}
    }
    return [pscustomobject]@{ Installed=$false; DisplayName=''; Version='' }
}
function Get-C2cTaniumInstalled {
    return (Get-C2cInstalledProduct -Match 'Tanium')
}
'@
# Better-named alias for the new Version Check call site (same one source string).
$script:C2cInstalledProductSrc = $script:C2cTaniumInstalledSrc

# --- Shared WinRM-heal source (opt-in, RPC-based, best-effort) -----------------
# For a host whose TCP 5985 probe FAILS, attempt remote SCM recovery of the WinRM
# service over RPC (Get-Service -ComputerName; Start-Service; Set-Service Automatic),
# then re-probe 5985. Buckets: reachable | winrm-recovered | offline | winrm-failed.
# Fully wrapped + non-fatal (a throw becomes 'offline'). The dispatcher self-guard is
# applied by the CALLER (fix fan-out drops self via Test-JanetC2cHostIsSelf; version
# check disables heal per host the same way), so this helper never acts on self.
# $Probe is an injectable 5985 test (default = real TCP) so bucketing is unit-testable
# without opening a real socket. Dot-sourced remotely by the workers AND at module
# load (below) so it is directly callable in module scope for tests.
$script:C2cWinrmHealSrc = @'
function Invoke-JanetC2cWinrmHeal {
    param([string]$Computer, [scriptblock]$Probe)
    if (-not $Probe) {
        $Probe = {
            param($c)
            $ok = $false; $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($c, 5985, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $ok = $true }
            } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
            return $ok
        }
    }
    if (& $Probe $Computer) { return @{ Bucket='reachable'; Detail='WinRM 5985 already reachable' } }
    $svc = $null
    try { $svc = Get-Service -ComputerName $Computer -Name 'WinRM' -ErrorAction Stop }
    catch { return @{ Bucket='offline'; Detail=("WinRM not reachable via RPC: " + $_.Exception.Message) } }
    if (-not $svc) { return @{ Bucket='offline'; Detail='WinRM service not found via RPC' } }
    if ([string]$svc.Status -eq 'Running') { return @{ Bucket='winrm-failed'; Detail='WinRM service Running but 5985 not answering (firewall?)' } }
    $acted = New-Object System.Collections.ArrayList
    try { Start-Service -InputObject $svc -ErrorAction Stop; [void]$acted.Add('started') }
    catch {
        try { $s2 = Get-Service -ComputerName $Computer -Name 'WinRM' -ErrorAction Stop; Start-Service -InputObject $s2 -ErrorAction Stop; [void]$acted.Add('started') } catch {}
    }
    try { Set-Service -ComputerName $Computer -Name 'WinRM' -StartupType Automatic -ErrorAction Stop; [void]$acted.Add('Automatic') } catch {}
    Start-Sleep -Milliseconds 500
    if (& $Probe $Computer) { return @{ Bucket='winrm-recovered'; Detail=("WinRM recovered via RPC (" + ($acted -join ', ') + "); 5985 now reachable") } }
    return @{ Bucket='winrm-failed'; Detail=("WinRM RPC heal attempted (" + ($acted -join ', ') + ") but 5985 still not answering") }
}
'@
# --- Additive cert-store installer (fix-pki worker + unit test) ----------------
# ADDITIVE by construction: for each store group, open the LocalMachine store
# ReadWrite, add ONLY certs whose thumbprint is not already present, and NEVER
# remove anything. $StoreOpener is injectable (default = a real X509Store) so the
# additive-only guard is unit-testable against a fake store. After the adds, each
# store is RE-OPENED ReadOnly (fresh handle, $VerifyOpener, same Invoke-Command) to
# confirm every ADDED thumbprint actually persisted - defeating a reconciler/policy
# that strips certs in-session. Returns
# @{ Added; Already; Total; PerStore=@('Root +N/M', ...); FailDetail; Verified; NotVerified }.
# Verified = count of added thumbprints confirmed present on re-read; NotVerified =
# added thumbprints ABSENT on re-read (added but stripped). Backward-compatible: a
# custom $StoreOpener with NO $VerifyOpener trusts the add (legacy fake-store callers).
$script:C2cAddCertsSrc = @'
function Add-C2cBundleToStores {
    param($Bundle, [scriptblock]$StoreOpener, [scriptblock]$VerifyOpener)
    $customOpener = [bool]$StoreOpener
    if (-not $StoreOpener) {
        $StoreOpener = {
            param($storeName)
            $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            return $st
        }
    }
    # Persistence re-verify opener: fresh ReadOnly handle so we read the store's real
    # backing (not the in-session object we added to). When a custom $StoreOpener was
    # injected but NO $VerifyOpener, DON'T open the real store (unit-test compat) - trust
    # the add. Injecting a $VerifyOpener always turns re-verify on.
    $doVerify = $true
    if (-not $VerifyOpener) {
        if ($customOpener) { $doVerify = $false }
        else {
            $VerifyOpener = {
                param($storeName)
                $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
                $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                return $st
            }
        }
    }
    $added = 0; $already = 0; $total = 0; $failDetail = ''
    $verified = 0
    $perStore = New-Object System.Collections.ArrayList
    $notVerified = New-Object System.Collections.ArrayList
    foreach ($sm in @(@{ Prop='Root'; Store='Root' }, @{ Prop='CA'; Store='CA' }, @{ Prop='Disallowed'; Store='Disallowed' })) {
        $items = @()
        try { $items = @($Bundle.($sm.Prop)) | Where-Object { $_ } } catch { $items = @() }
        if ($items.Count -eq 0) { continue }
        $addedThumbs = New-Object System.Collections.ArrayList
        $st = $null
        try {
            $st = & $StoreOpener $sm.Store
            $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ec in $st.Certificates) { [void]$present.Add((([string]$ec.Thumbprint) -replace '[^0-9A-Fa-f]','')) }
            $sAdd = 0
            foreach ($it in $items) {
                $total++
                $tp = (([string]$it.t) -replace '[^0-9A-Fa-f]','')
                if ($tp -and $present.Contains($tp)) { $already++; continue }
                try {
                    $raw  = [Convert]::FromBase64String([string]$it.b)
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw)
                    $st.Add($cert)
                    if ($tp) { [void]$present.Add($tp); [void]$addedThumbs.Add($tp) }
                    $sAdd++; $added++
                } catch { $failDetail += "add failed in $($sm.Store): $($_.Exception.Message); " }
            }
            [void]$perStore.Add("$($sm.Store) +$sAdd/$($items.Count)")
        } catch {
            $failDetail += "store $($sm.Store) open failed: $($_.Exception.Message); "
        } finally { if ($st) { try { $st.Close() } catch {} } }
        # RE-VERIFY: fresh ReadOnly re-open, confirm each ADDED thumbprint persisted.
        if ($addedThumbs.Count -gt 0) {
            if (-not $doVerify) {
                $verified += $addedThumbs.Count
            } else {
                $vst = $null
                try {
                    $vst = & $VerifyOpener $sm.Store
                    $reread = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($rc in $vst.Certificates) { [void]$reread.Add((([string]$rc.Thumbprint) -replace '[^0-9A-Fa-f]','')) }
                    foreach ($atp in $addedThumbs) {
                        if ($reread.Contains($atp)) { $verified++ } else { [void]$notVerified.Add($atp) }
                    }
                } catch {
                    # Could not re-read -> the adds are UNCONFIRMED (not a hard add failure;
                    # FailDetail is left intact for real .Add errors only).
                    foreach ($atp in $addedThumbs) { [void]$notVerified.Add($atp) }
                } finally { if ($vst) { try { $vst.Close() } catch {} } }
            }
        }
    }
    return @{ Added=$added; Already=$already; Total=$total; PerStore=@($perStore); FailDetail=$failDetail; Verified=$verified; NotVerified=@($notVerified) }
}
# Classify an Add-C2cBundleToStores result into the raw PkiRoots token the fix worker
# emits (and the label map keys on): any .Add error -> FAIL; else added-but-absent on
# re-read -> NOT VERIFIED; else 1+ added -> FIXED; else nothing to add -> NOCHANGE.
# This is the SINGLE classifier both the remote fix worker (fixSb) and the unit tests
# call, so a mis-classification fails a test.
function Get-C2cPkiRootsResultToken {
    param($AddResult)
    if (-not $AddResult) { return 'FAIL' }
    if ([string]$AddResult.FailDetail) { return 'FAIL' }
    if (@($AddResult.NotVerified).Count -gt 0) { return 'NOT VERIFIED' }
    if ([int]$AddResult.Added -gt 0)   { return 'FIXED' }
    return 'NOCHANGE'
}
# Per-pillar DISPLAY label map: pillar-flavoured names for the raw FIXED/NOCHANGE/
# STARTED/KICKED tokens (SKIP/FAIL/IN PROGRESS pass through via the default arm). This
# is the SINGLE label map the fix worker's admin-side rollup delegates to AND the unit
# tests assert against, so a mis-wired label (e.g. a mistyped 'ROOTS INSTALLED') fails
# a test. Defined in this shared source so worker + tests key off ONE definition.
function Get-C2cPillarLabel {
    param($Name, $Result)
    switch ("$Name|$Result") {
        'Monitoring|FIXED'     { 'MONITORED' }
        'Monitoring|NOCHANGE'  { 'ALREADY MONITORED' }
        'Firewall|FIXED'       { 'FIREWALL ENABLED' }
        'Firewall|NOCHANGE'    { 'ALREADY ENABLED' }
        'AntiMalware|FIXED'    { 'PROTECTED' }
        'AntiMalware|NOCHANGE' { 'ALREADY PROTECTED' }
        'Patches|KICKED'       { 'PATCH CYCLE KICKED' }
        'Encryption|STARTED'   { 'ENCRYPTION STARTED' }
        'Encryption|FIXED'     { 'PROTECTION RESUMED' }
        'Encryption|NOCHANGE'  { 'ALREADY ENCRYPTED' }
        'PkiRoots|FIXED'       { 'ROOTS INSTALLED' }
        'PkiRoots|NOCHANGE'    { 'ROOTS ALREADY PRESENT' }
        'PkiExpired|FIXED'     { 'EXPIRED PRUNED' }
        'PkiRdp|FIXED'         { 'RDP CERT REBOUND' }
        'MdeOnboard|FIXED'     { 'MDE ONBOARDED' }
        'Java|FIXED'           { 'JAVA CLEANED' }
        'Java|NOCHANGE'        { 'NO OLD JAVA' }
        'Lockscreen|FIXED'     { 'CACHE FIX APPLIED' }
        'Lockscreen|NOCHANGE'  { 'ALREADY SET' }
        default                { [string]$Result }
    }
}
'@

# Define the heal + installed-product + cert-store helpers in MODULE scope too (for
# admin-side use + direct unit testing). Worker runspaces dot-source them again.
try { . ([scriptblock]::Create($script:C2cInstalledProductSrc)) } catch {}
try { . ([scriptblock]::Create($script:C2cWinrmHealSrc)) } catch {}
try { . ([scriptblock]::Create($script:C2cAddCertsSrc)) } catch {}

# --- TASKORD 26-0822 alignment: MDE Org ID + pillar tiers + display tag ----------
# The required MDE (Microsoft Defender for Endpoint) tenant/Org ID from the C2C
# TASKORD 26-0822 Anti-Malware rule. HARDCODED on purpose: it is the program-wide C2C
# tenant (identical for every base under this TASKORD), NOT a base-specific value like
# the removed hostname patterns - so it can never false-flag another base.
$script:C2cMdeOrgId = '99557BCC-8DC2-443B-AF2E-08C9162C01BB'

# MDE OnboardingInfo blob (Defender-ScanFix v2.1 port). This is the TENANT-WIDE value the
# ATP GPO deploys - identical on every machine in the org (captured from a correctly
# onboarded host 10 Jul 2026; the embedded signing cert EXPIRED 2026-01-07 - the payload
# needs re-capture from a healthy host (pilot-pending) before onboarding heal can take). The
# AntiMalware fixer uses it as the LAST
# rung of the onboarding heal ladder (deps -> gpupdate -> blob): written ONLY when the ATP
# policy key is still empty after gpupdate, as a bridge until the GPO asserts the SAME value.
$script:C2cMdeOnboardingBlob = @'
{"body":"{\"previousOrgIds\":[],\"orgId\":\"99557bcc-8dc2-443b-af2e-08c9162c01bb\",\"geoLocationUrl\":\"https://winatp-gw-usgv.microsoft.com/\",\"datacenter\":\"UsGovVirginia\",\"vortexGeoLocation\":\"FFL4\",\"partnerGeoLocation\":\"FFL5\",\"version\":\"2.03\",\"packageGuid\":\"5ddb3710-4895-44a3-a42e-adb14bd8ce3a\"}","sig":"MiMFsO374dVHT6vhzUCAzwY21Rr4dJZZS90C4EsjHCWpCXCjKlpa7pSfI8b07rp1Xe2D5IJNh5wERf13SDSTa8C45qTOuDsgmS+H/IiKOy0GVZk1wHiq40H0jgaC+SfacldUPaCYtfu5e3kukB/ZtPDpgXt95Jqblyg7QzTPX37nWCKFfdx6RqH9cU2fKw51MRjGCX0680ce3YgiWTAszBUlRsENGJxztjSZmbZQ0thw4I20NPufdL+RBhA8S582d6qvxxNM8ssoNUpeNuhtmaMli10pbaNKVIhViGdY07C0E82BZmMjBuLWt6w/Zv7enM684cAvmchwY/muV7gWfA==","sha256sig":"MiMFsO374dVHT6vhzUCAzwY21Rr4dJZZS90C4EsjHCWpCXCjKlpa7pSfI8b07rp1Xe2D5IJNh5wERf13SDSTa8C45qTOuDsgmS+H/IiKOy0GVZk1wHiq40H0jgaC+SfacldUPaCYtfu5e3kukB/ZtPDpgXt95Jqblyg7QzTPX37nWCKFfdx6RqH9cU2fKw51MRjGCX0680ce3YgiWTAszBUlRsENGJxztjSZmbZQ0thw4I20NPufdL+RBhA8S582d6qvxxNM8ssoNUpeNuhtmaMli10pbaNKVIhViGdY07C0E82BZmMjBuLWt6w/Zv7enM684cAvmchwY/muV7gWfA==","cert":"MIIFuTCCA6GgAwIBAgITMwAAA1KuP8phV63bpgAAAAADUjANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMB4XDTI1MDEwNzE4MjYzM1oXDTI2MDEwNzE4MjYzM1owOTE3MDUGA1UEAxMuQ2xvdWRDbGllbnRBdXRoZW50aWNhdGlvbi1GRi51c2dvdmNsb3VkYXBwLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIDBWZFbZbGsF/cDf0K4w4mqXXj9LB11sgg7kYkqABowL3N/lwUjfp2PY/jr/1mAzSgSGX5p4cp23mFOHNt7jisRqifVN1Vc1M9ZlA6BnVs9TndKTkEfpEshsr/eM92/hYFdyMUoxkgs6+GybvHId1tm7pgR45ZBOgtE/+IWC2AqIT6xUyKjOJkK3y4MPEnm3x7kKyTbElwPnqElyG3WJOfQtqZbT0D6B/bZUc+ucUIHObHp0XKK3PMMUkUACdu0hoqYTW7xsQ/u8F6xs1lY2QmHl5mM7yilKVcVt+Pl7Na72UA9fX+NAtd6Y8YQGn/NrNBUM0f9cH9EqNcAKhy39kCAwEAAaOCAXMwggFvMA4GA1UdDwEB/wQEAwIFIDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADA5BgNVHREEMjAwgi5DbG91ZENsaWVudEF1dGhlbnRpY2F0aW9uLUZGLnVzZ292Y2xvdWRhcHAubmV0MB0GA1UdDgQWBBRzIMpwRp9unotSJTdGI1PhGOkWzDAfBgNVHSMEGDAWgBQ2VollSctbmy88rEIWUE2RuTPXkTBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNTZWNTZXJDQTIwMTFfMjAxMS0xMC0xOC5jcmwwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzAChkRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY1NlY1NlckNBMjAxMV8yMDExLTEwLTE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAMFkb2XuiBz+1dgYqNzr7H2WLKmv+44Jcw6xEzLT3qxDb5YyVGOFtE9x5tYwShJflGLok/H7OiHfphVXjTIufJPsr4yRGtdnfkK/ehuingNCLNh9UEHWdpylgpH/snZ203ljlmMkGefHjLJ7iZ+tZ+rip0jeUtdd/qepSuuCU9juRxfSHhVdZLqcoZRIxyTOocE0sv87vswfq1ps+9CGlWZHMYcJAyu4oN0ftu2g29JzWMfYbj06p811lmtP/1IclIt8zlb9NF+S/KV6/6xxTaLHhyC7257QmHqMM+G7PxPffWrEWB2TLwcFNSPfnkvSnd6Q6YJSciDtLMtg530a7kHWx25TVHlBkEEIcOnaDYeDx4qEfVB/071a+9tgLZ4L+yHhAL3v0JQVs68jRnhWawfbA4il1ckospnC3XoVbm4xWwmsYReWzSHxie0QPlIIP728WEJqTGx7yS+FSTMt4tpmaLJg78iurOlKu5PjgYVCOaiKB1D0F2oMEQTCW90BZ0I7Tjtnx0rnELxE13O49o5xf8QvtCc6LjyRYk3gTNHSFkUUNTgirWrvFfKz0vHGiR1sAhOVxay5fdW+DqH1sqfpBUVhsZEQ63IG8zkhMYYl/xUFfLGFnXrjzaOn58+GdPqDUuTR2NwFuGiI4zYPabM97sklmbBAYZIH/JcPOUAA=","chain":["MIIG2DCCBMCgAwIBAgIKYT+3GAAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTExMDE4MjI1NTE5WhcNMjYxMDE4MjMwNTE5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0AvApKgZgeI25eKq5fOyFVh1vrTlSfHghPm7DWTvhcGBVbjz5/FtQFU9zotq0YST9XV8W6TUdBDKMvMj067uz54EWMLZR8vRfABBSHEbAWcXGK/G/nMDfuTvQ5zvAXEqH4EmQ3eYVFdznVUr8J6OfQYOrBtU8yb3+CMIIoueBh03OP1y0srlY8GaWn2ybbNSqW7prrX8izb5nvr2HFgbl1alEeW3Utu76fBUv7T/LGy4XSbOoArX35Ptf92s8SxzGtkZN1W63SJ4jqHUmwn4ByIxcbCUruCw5yZEV5CBlxXOYexl4kvxhVIWMvi1eKp+zU3sgyGkqJu+mmoE4KMczVYYbP1rL0I+4jfycqvQeHNye97sAFjlITCjCDqZ75/D93oWlmW1w4Gv9DlwSa/2qfZqADj5tAgZ4Bo1pVZ2Il9q8mmuPq1YRk24VPaJQUQecrG8EidT0sH/ss1QmB619Lu2woI52awb8jsnhGqwxiYL1zoQ57PbfNNWrFNMC/o7MTd02Fkr+QB5GQZ7/RwdQtRBDS8FDtVrSSP/z834eoLP2jwt3+jYEgQYuh6Id7iYHxAHu8gFfgsJv2vd405bsPnHhKY7ykyfW2Ip98eiqJWIcCzlwT88UiNPQJrDMYWDL78p8R1QjyGWB87v8oDCRH2bYu8vw3eJq0VNUz4CedMCAwEAAaOCAUswggFHMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQ2VollSctbmy88rEIWUE2RuTPXkTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBByGHB9VuePpEx8bDGvwkBtJ22kHTXCdumLg2fyOd2NEavB2CJTIGzPNX0EjV1wnOl9U2EjMukXa+/kvYXCFdClXJlBXZ5re7RurguVKNRB6xo6yEM4yWBws0q8sP/z8K9SRiax/CExfkUvGuV5Zbvs0LSU9VKoBLErhJ2UwlWDp3306ZJiFDyiiyXIKK+TnjvBWW3S6EWiN4xxwhCJHyke56dvGAAXmKX45P8p/5beyXf5FN/S77mPvDbAXlCHG6FbH22RDD7pTeSk7Kl7iCtP1PVyfQoa1fB+B1qt1YqtieBHKYtn+f00DGDl6gqtqy+G0H15IlfVvvaWtNefVWUEH5TV/RKPUAqyL1nn4ThEO792msVgkn8Rh3/RQZ0nEIU7cU507PNC4MnkENRkvJEgq5umhUXshn6x0VsmAF7vzepsIikkrw4OOAd5HyXmBouX+84Zbc1L71/TyH6xIzSbwb5STXq3yAPJarqYKssH0uJ/Lf6XFSQSz6iKE9s5FJlwf2QHIWCiG7pplXdISh5RbAU5QrM5l/Eu9thNGmfrCY498EpQQgVLkyg9/kMPt5fqwgJLYOsrDSDYvTJSUKJJbVuskfFszmgsSAbLLGOBG+lMEkc0EbpQFv0rW6624JKhxJKgAlN2992uQVbG+C7IHBfACXH0w76Fq17Ip5xCA==","MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwMzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFLh93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3sMJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTeacY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfPSRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUci06AjGQQ7kUBU7h6qfHMdEjiTQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIBAH9yzw+3xRXbm8BJyiZb/p4T5tPw0tuXX/JLP02zrhmu7deXoKzvqTqjwkGw5biRnhOBJAPmCf0/V0A5ISRW0RAvS0CpNoZLtFNXmvvxfomPEf4YbFGq6O0JlbXlccmh6Yd1phV/yX43VF50k8XDZ8wNT2uoFwxtCJJ+i92Bqi1wIcM9BhS7vyRep4TXPw8hIr1LAAbblxzYXtTFC1yHblCk6MM4pPvLLMWSZpuFXst6bJN8gClYW1e1QGm6CHmmZGIVnYeWRbVmIyADixxzoNOieTPgUFmG2y/lAiXqcyqfABTINseSO+lOAOzYVgm5M0kS0lQLAausR7aRKX1MtHWAUgHoyoL2n8ysnI8X6i8msKtyrAv+nlEex0NVZ09Rs1fWtuzuUrc66U7h14GIvE+OdbtLqPA1qibUZ2dJsnBMO5PcHd94kIZysjik0dySTclY6ysSXNQ7roxrsIPlAT/4CTL2kzU0Iq/dNw13CYArzUgA8YyZGUcFAenRv9FO0OYoQzeZpApKCNmacXPSqs0xE2N2oTdvkjgefRI8ZjLny23h/FKJ3crWZgWalmG+oijHHKOnNlA8OqTfSm7mhzvO6/DggTedEzxSjr25HTTGHdUKaj2YKXCMiSrRq4IQSB/c9O+lxbtVGjhjhE63bK2VVOxlIhBJF7jAHscPrFRH"]}
'@

# Java remediation engine (Java-Cleanup-ScanFix v1.1) lives in the SHARED module
# JanetWeb.javafix.psm1 so c2c AND wpt run ONE copy of the vendor-gated (Oracle/Sun-
# only) removal + strict-GUID msiexec guard - no fork. The pool worker has no module
# scope, so $script:C2cJavaSrc carries the SOURCE STRING (Get-JanetJavaVerdict +
# Invoke-JanetJavaRemediation), injected + dot-sourced in the worker. It is also
# dot-sourced here so the classifier resolves in module scope; Get-C2cJavaVerdict is
# kept as a thin delegator so the c2c name (existing tests + any caller) still works.
Import-Module (Join-Path $PSScriptRoot 'JanetWeb.javafix.psm1') -Force -ErrorAction SilentlyContinue
$script:C2cJavaSrc = if (Get-Command Get-JanetJavaFixSrc -ErrorAction SilentlyContinue) { Get-JanetJavaFixSrc } else { '' }
try { . ([scriptblock]::Create($script:C2cJavaSrc)) } catch {}
function Get-C2cJavaVerdict { param([string]$Version, [int]$MinUpdate = 491) Get-JanetJavaVerdict $Version $MinUpdate }

# Per-pillar TIER + tiered verdict + display tag. Defined as a SOURCE STRING so it can be
# dot-sourced BOTH in module scope (admin-side use + unit tests) AND inside each pool worker
# runspace - which is built from InitialSessionState::CreateDefault() and has NO module
# functions. Same idiom as $C2cTaniumInstalledSrc / $C2cWinrmHealSrc: the worker calls
# Get-C2cVerdict, so it must be injected there (a plain module function would be absent ->
# blank verdict on every scanned host). The tier map is the single source both the verdict
# and the report-tag renderer key off; Vuln is Quarantine by meaning but emits EXT (never
# scored); Audit/Info fails are advisory; Monitoring is Attest (dead Tanium client -> NOT ATTESTING).
$script:C2cVerdictSrc = @'
$script:C2cPillarTier = @{
    Monitoring   = 'Attest'
    Firewall     = 'Quarantine'
    AntiMalware  = 'Quarantine'
    Patches      = 'Quarantine'
    Encryption   = 'Quarantine'
    Vuln         = 'Quarantine'
    AppWhitelist = 'Info'
    Agents       = 'Info'
    PkiRoots     = 'Audit'
    OSVersion    = 'Audit'
    COAMS        = 'Info'
}
function Get-C2cPillarTier { param([string]$Name) $t = $script:C2cPillarTier[$Name]; if ($t) { $t } else { 'Quarantine' } }
function Get-C2cDisplayTag {
    param([string]$Name, [string]$Status)
    $tier = Get-C2cPillarTier $Name
    if (($Status -eq 'FAIL' -or $Status -eq 'ERROR')) {
        if ($tier -eq 'Audit') { return 'AUDIT' }
        if ($tier -eq 'Info')  { return 'INFO' }
    }
    return $Status
}
function Get-C2cVerdict {
    param([object[]]$Checks)
    $checks = @($Checks)
    $qFail   = @($checks | Where-Object { $_.Status -eq 'FAIL'  -and (Get-C2cPillarTier $_.Name) -eq 'Quarantine' } | ForEach-Object { [string]$_.Name })
    $qErr    = @($checks | Where-Object { $_.Status -eq 'ERROR' -and (Get-C2cPillarTier $_.Name) -eq 'Quarantine' } | ForEach-Object { [string]$_.Name })
    $monBad  = @($checks | Where-Object { $_.Name -eq 'Monitoring' -and ($_.Status -eq 'FAIL' -or $_.Status -eq 'ERROR') }).Count -gt 0
    $auditBad = @($checks | Where-Object { ($_.Status -eq 'FAIL' -or $_.Status -eq 'ERROR') -and (Get-C2cPillarTier $_.Name) -eq 'Audit' } | ForEach-Object { [string]$_.Name })
    $infoBad  = @($checks | Where-Object { ($_.Status -eq 'FAIL' -or $_.Status -eq 'ERROR') -and (Get-C2cPillarTier $_.Name) -eq 'Info'  } | ForEach-Object { [string]$_.Name })
    $extNames = @($checks | Where-Object { $_.Status -eq 'EXT' } | ForEach-Object { [string]$_.Name })

    if     ($qFail.Count -ge 1) { $status = 'QUARANTINE RISK'; $ok = $false }
    elseif ($qErr.Count  -ge 1) { $status = 'CHECK ERRORS';    $ok = $false }
    elseif ($monBad)            { $status = 'NOT ATTESTING';   $ok = $false }
    else                        { $status = 'READY';           $ok = $true  }

    $parts = New-Object System.Collections.ArrayList
    if ($qFail.Count -ge 1) { [void]$parts.Add("$($qFail.Count) FAIL: $($qFail -join ', ')") }
    if ($qErr.Count  -ge 1) { [void]$parts.Add("$($qErr.Count) ERROR: $($qErr -join ', ')") }
    if ($status -eq 'NOT ATTESTING') { [void]$parts.Add('Tanium not reporting - compliance cannot be attested to the C2C dashboard') }
    if ($status -eq 'READY')         { [void]$parts.Add('all quarantine pillars pass') }
    if ($auditBad.Count -gt 0) { [void]$parts.Add("AUDIT: $($auditBad -join ', ')") }
    if ($infoBad.Count  -gt 0) { [void]$parts.Add("INFO: $($infoBad -join ', ')") }
    if ($extNames.Count -gt 0) { [void]$parts.Add("EXT: $($extNames -join ', ')") }
    if ($status -eq 'READY') { [void]$parts.Add('AQC/Vuln not endpoint-verifiable - import the Tanium C2C CSV to score the #1 quarantine driver') }
    $detail = ($parts -join ' | ')

    $rptLines = foreach ($c in $checks) { '[{0}] {1}: {2}' -f (Get-C2cDisplayTag $c.Name $c.Status), ('{0,-12}' -f [string]$c.Name), ([string]$c.Detail) }
    return @{ Status = $status; Ok = $ok; Detail = $detail; Report = ($rptLines -join "`r`n") }
}
'@
# Dot-source in MODULE scope (admin-side use + unit tests). Each pool worker dot-sources it again.
try { . ([scriptblock]::Create($script:C2cVerdictSrc)) } catch {}

# --- Per-host probe worker (runs in a pool runspace; no module scope here) ---
# Returns @{ Host; Ping; Status; Detail; Ok; Report; Checks }. All 10 checks run
# inside ONE Invoke-Command round-trip; the verdict is computed here (admin-side).
$script:C2cProbeBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, $Config, [string]$TaniumInstalledSrc, [string]$VerdictSrc)

    # This block runs in a pool runspace with NO module scope. Dot-source the tiered-verdict
    # helpers (Get-C2cVerdict / Get-C2cPillarTier / Get-C2cDisplayTag) so the verdict below
    # can call them - a plain module function would be absent here (-> blank verdict).
    if ($VerdictSrc) { try { . ([scriptblock]::Create($VerdictSrc)) } catch {} }

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Ok=$false; Report=''; Checks=@() }

    # Reachability pre-check: pure-TCP probe (AFNET-safe; never ICMP). WinRM HTTP 5985,
    # then WinRM HTTPS 5986, then SMB 445 (liveness only), 1500ms connect timeout, break
    # on first connect (wpt/biosfirmware idiom). $useSsl tracks whether ONLY 5986 answered
    # so the session below auto-switches to -UseSSL (HTTP 5985 is preferred when both open).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) {
            $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'
            return $r
        }
    }

    # Resolve baseline fields admin-side (worker has no module functions), then pass
    # plain typed values into the remote scriptblock's ArgumentList.
    $taniumService = [string]$Config['taniumService']; if (-not $taniumService) { $taniumService = 'Tanium Client' }
    $sigMaxAge     = 7; if ($Config.ContainsKey('sigMaxAgeDays')) { $tmp = 0; if ([int]::TryParse([string]$Config['sigMaxAgeDays'], [ref]$tmp)) { $sigMaxAge = $tmp } }
    # sigMaxAgeHours (v1.7.0): prefer the explicit hours budget; else derive from days.
    $sigMaxHours = 0
    if ($Config.ContainsKey('sigMaxAgeHours')) { $tmph = 0; if ([int]::TryParse([string]$Config['sigMaxAgeHours'], [ref]$tmph)) { $sigMaxHours = $tmph } }
    if ($sigMaxHours -le 0) { $sigMaxHours = $sigMaxAge * 24 }
    $graceDays     = 7; if ($Config.ContainsKey('graceDays')) { $tmpg = 0; if ([int]::TryParse([string]$Config['graceDays'], [ref]$tmpg) -and $tmpg -ge 0) { $graceDays = $tmpg } }
    $mdeOrgId      = [string]$Config['mdeOrgId']
    $secAgents     = @($Config['securityAgentServices'])
    $dodRoots      = @($Config['dodRootThumbprints'])

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is common on
    # AFNET, so skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    $soP = @{ OperationTimeout=180000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # ---- The consolidated read-only probe: all 10 C2C checks in one round-trip. ----
    $probeSb = {
        param($taniumService, $sigMaxAge, $sigMaxHours, $graceDays, $mdeOrgId, $secAgents, $dodRoots, $taniumInstalledSrc)
        # Dot-source the single-source Tanium-installed probe (Get-C2cTaniumInstalled).
        if ($taniumInstalledSrc) { try { . ([scriptblock]::Create($taniumInstalledSrc)) } catch {} }
        # Normalize the array args: an empty collection can cross the WinRM ArgumentList
        # boundary as $null, and @($null) is a 1-element array holding $null (a stray
        # $null host-pattern would be an empty regex that matches EVERYTHING -> a false
        # PASS). Drop null/blank elements so every list is a clean [string] array.
        $secAgents    = @(@($secAgents)    | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $dodRoots     = @(@($dodRoots)     | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $checks = New-Object System.Collections.ArrayList
        $mk = { param($n,$s,$d) [void]$checks.Add([pscustomobject]@{ Name=$n; Status=$s; Detail=[string]$d }) }

        # 1. Monitoring - Tanium SOFTWARE installed (uninstall registry) AND the Tanium
        #    client service Running. PASS needs BOTH; Detail states both facts.
        try {
            $ti = if (Get-Command Get-C2cTaniumInstalled -ErrorAction SilentlyContinue) { Get-C2cTaniumInstalled } else { [pscustomobject]@{ Installed=$false; DisplayName=''; Version='' } }
            $instTxt = if ($ti.Installed) { 'Tanium installed' + $(if ($ti.Version) { " (v$($ti.Version))" } else { '' }) } else { 'Tanium not installed' }
            $svc = Get-Service -Name $taniumService -ErrorAction SilentlyContinue
            $svcTxt = if (-not $svc) { 'service not installed' } else { "service $($svc.Status)" }
            if ($ti.Installed -and $svc -and $svc.Status -eq 'Running') {
                & $mk 'Monitoring' 'PASS' "$instTxt; service Running"
            } else {
                & $mk 'Monitoring' 'FAIL' "$instTxt; $svcTxt"
            }
        } catch { & $mk 'Monitoring' 'ERROR' $_.Exception.Message }

        # 2. Firewall - all three profiles enabled (endpoint firewall active).
        try {
            if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                $profs = Get-NetFirewallProfile -ErrorAction Stop
                $off = @($profs | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
                if ($off.Count -eq 0) { & $mk 'Firewall' 'PASS' 'Domain/Private/Public all enabled' }
                else                  { & $mk 'Firewall' 'FAIL' "disabled profile(s): $($off -join ', ')" }
            } else {
                # Fallback: parse netsh advfirewall show allprofiles state. Fail CLOSED:
                # if the output does not parse (locale, format), do NOT emit a false PASS -
                # require all 3 profile headers AND 3 State lines, else ERROR.
                $txt = (& netsh advfirewall show allprofiles state 2>&1 | Out-String)
                $curProf = ''; $disabled = New-Object System.Collections.ArrayList
                $profHdrs = 0; $stateLns = 0
                foreach ($ln in ($txt -split "`r?`n")) {
                    if     ($ln -match '^(Domain|Private|Public)\s+Profile') { $curProf = $Matches[1]; $profHdrs++ }
                    elseif ($ln -match '^State\s+(\S+)') { $stateLns++; if ($Matches[1] -notmatch '^(?i:on)$' -and $curProf) { [void]$disabled.Add($curProf) } }
                }
                if ($profHdrs -lt 3 -or $stateLns -lt 3) {
                    & $mk 'Firewall' 'ERROR' "netsh output not parseable ($profHdrs profile header(s), $stateLns state line(s)) - cannot confirm firewall state"
                } elseif ($disabled.Count -eq 0) {
                    & $mk 'Firewall' 'PASS' 'all profiles enabled (netsh)'
                } else {
                    & $mk 'Firewall' 'FAIL' "disabled profile(s): $(($disabled | Select-Object -Unique) -join ', ') (netsh)"
                }
            }
        } catch { & $mk 'Firewall' 'ERROR' $_.Exception.Message }

        # 3. AntiMalware - TASKORD 26-0822 rule 1 (quarantine): Defender INSTALLED
        #    AND signature age < 7 DAYS (strict, 168h) AND MDE Org ID == the required
        #    tenant. Those three are the ONLY quarantine conditions. RunningMode / RTP /
        #    Sense-onboarded are shown as advisory detail but NEVER fail the pillar (a
        #    Passive/EDR box or an Active-RTP-off box is TASKORD-compliant if it is
        #    installed, fresh, and correctly tenanted). Fallback: root\SecurityCenter2
        #    (Defender-only - TASKORD requires Microsoft Defender specifically).
        try {
            # Endpoint-read the MDE Org ID (Status\OrgId, else the ATP root OrgId).
            $foundOrg = ''
            try { $st1 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OrgId' -ErrorAction SilentlyContinue; if ($st1) { $foundOrg = [string]$st1.OrgId } } catch {}
            if (-not $foundOrg) { try { $st2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name 'OrgId' -ErrorAction SilentlyContinue; if ($st2) { $foundOrg = [string]$st2.OrgId } } catch {} }
            $reqOrg = ([string]$mdeOrgId).Trim()
            $orgNorm = { param($g) (([string]$g) -replace '[{}\s]','').ToUpperInvariant() }
            $orgOk = ($reqOrg) -and ((& $orgNorm $foundOrg) -eq (& $orgNorm $reqOrg))
            $orgTxt = if ($foundOrg) { "OrgId $foundOrg" } else { 'OrgId missing (not MDE-onboarded)' }

            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $mp     = Get-MpComputerStatus -ErrorAction Stop
                $mode   = [string]$mp.AMRunningMode
                $rtp    = [bool]$mp.RealTimeProtectionEnabled
                $amProd = [string]$mp.AMProductVersion
                $amEng  = [string]$mp.AMEngineVersion
                # Signature age in HOURS from AntivirusSignatureLastUpdated (fall back to
                # AntivirusSignatureAge days * 24 when the timestamp is missing).
                $lastUpd = $null; try { $lastUpd = $mp.AntivirusSignatureLastUpdated } catch { $lastUpd = $null }
                $ageHours = $null
                if ($lastUpd -is [datetime]) { $ageHours = [math]::Round(((Get-Date) - $lastUpd).TotalHours, 1) }
                elseif ($lastUpd -and ($lastUpd -as [datetime])) { $ageHours = [math]::Round(((Get-Date) - ([datetime]$lastUpd)).TotalHours, 1) }
                else { try { $ageHours = [int]$mp.AntivirusSignatureAge * 24 } catch { $ageHours = $null } }
                # TASKORD bar: STRICT < 7 days (168h). $sigMaxHours (default 24) is now an
                # advisory fleet budget only - a breach is noted, never failed.
                $sigFresh = ($null -ne $ageHours) -and ($ageHours -lt 168)
                # MDE Sense onboarded (advisory): Sense service Running OR OnboardingState reg = 1.
                $senseOnboarded = $false
                try { $ss = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue; if ($ss -and $ss.Status -eq 'Running') { $senseOnboarded = $true } } catch {}
                if (-not $senseOnboarded) {
                    try {
                        $ob = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState' -ErrorAction SilentlyContinue
                        if ($ob -and [int]$ob.OnboardingState -eq 1) { $senseOnboarded = $true }
                    } catch {}
                }
                $lastTxt = if ($lastUpd) { [string]$lastUpd } else { 'unknown' }
                $ageTxt  = if ($null -ne $ageHours) { "${ageHours}h" } else { 'unknown' }
                $modeTxt = if ($mode) { $mode } else { 'null (Disabled/Not Running)' }
                # Advisory notes (never fail): mode/RTP posture + fleet-budget breach.
                $adv = New-Object System.Collections.ArrayList
                if (-not $mode)      { [void]$adv.Add('RunningMode empty (Defender Disabled/Not Running)') }
                elseif ($mode -match '(?i)passive|edr') { if (-not $senseOnboarded) { [void]$adv.Add('Passive/EDR but MDE Sense not onboarded') } }
                elseif (-not $rtp)   { [void]$adv.Add('Active but RTP off') }
                if ($sigFresh -and ($null -ne $ageHours) -and ($ageHours -ge $sigMaxHours)) { [void]$adv.Add("sig age $ageTxt exceeds fleet budget ${sigMaxHours}h but within TASKORD 7-day") }
                $advTxt = if ($adv.Count -gt 0) { " | advisory: $($adv -join '; ')" } else { '' }
                $baseDet = "installed (RunningMode $modeTxt; RTP $rtp; prod $amProd; engine $amEng); sig age $ageTxt (last $lastTxt); $orgTxt"
                if ($sigFresh -and $orgOk) {
                    & $mk 'AntiMalware' 'PASS' "Defender installed, signatures <7d, MDE OrgId matches; $baseDet$advTxt"
                } else {
                    $why = New-Object System.Collections.ArrayList
                    if (-not $sigFresh) { [void]$why.Add("sig age $ageTxt >= 7 days") }
                    if (-not $orgOk)    { [void]$why.Add(("MDE " + $(if ($foundOrg) { "OrgId $foundOrg != required $reqOrg (wrong tenant - needs MDE re-onboarding)" } else { 'not onboarded (OrgId missing)' }))) }
                    & $mk 'AntiMalware' 'FAIL' "$($why -join '; '); $baseDet$advTxt"
                }
            } else {
                # Fallback: root\SecurityCenter2. TASKORD requires Microsoft Defender - a
                # healthy third-party-only AV FAILs (named), and the Org ID must still match.
                $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
                if ($av.Count -eq 0) { & $mk 'AntiMalware' 'FAIL' "no AntiVirusProduct registered; $orgTxt" }
                else {
                    $names = (@($av | ForEach-Object { [string]$_.displayName }) -join ', ')
                    $defender = @($av | Where-Object { [string]$_.displayName -match '(?i)defender' })
                    $enabled = $false; $current = $true
                    foreach ($p in $defender) {
                        try {
                            $hex  = '{0:X6}' -f [int]$p.productState
                            $prov = [Convert]::ToInt32($hex.Substring(2,2),16)
                            $sig  = [Convert]::ToInt32($hex.Substring(4,2),16)
                            if (($prov -band 0x10) -ne 0) { $enabled = $true }
                            if (($sig  -band 0x10) -ne 0) { $current = $false }
                        } catch {}
                    }
                    if ($defender.Count -eq 0) {
                        & $mk 'AntiMalware' 'FAIL' "Microsoft Defender not present (SecurityCenter2: $names); TASKORD requires Defender; $orgTxt"
                    } elseif ($enabled -and $current -and $orgOk) {
                        & $mk 'AntiMalware' 'PASS' "SecurityCenter2 Defender enabled + up to date, MDE OrgId matches ($names); $orgTxt"
                    } else {
                        $why = New-Object System.Collections.ArrayList
                        if (-not ($enabled -and $current)) { [void]$why.Add("Defender enabled=$enabled up-to-date=$current") }
                        if (-not $orgOk) { [void]$why.Add(("MDE " + $(if ($foundOrg) { "OrgId $foundOrg != required $reqOrg" } else { 'not onboarded (OrgId missing)' }))) }
                        & $mk 'AntiMalware' 'FAIL' "SecurityCenter2 Defender ($names): $($why -join '; ')"
                    }
                }
            }
        } catch { & $mk 'AntiMalware' 'ERROR' $_.Exception.Message }

        # 4. Patches - TASKORD 26-0822 rule 5 (quarantine): security patches with a 7-day
        #    grace. Quarantine-relevant = an applicable-not-installed update that is OVERDUE:
        #    past its MECM enforcement Deadline, or (no deadline) content older than graceDays.
        #    Pending-but-in-grace updates are advisory, not a fail.
        #    NOTE: the old filter tested InstallState/ApplicabilityState - those are
        #    CCM_Application props, $null on CCM_SoftwareUpdate, so it passed EVERY row (a
        #    no-op bug). ComplianceState=0 (ciNotPresent) is the correct applicable-not-installed test.
        try {
            $now = Get-Date
            $pending = @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState=0" -Namespace root/CCM/ClientSDK -ErrorAction Stop)
            $overdue = @($pending | Where-Object {
                ($_.Deadline -and ($_.Deadline -is [datetime]) -and ($_.Deadline -lt $now)) -or
                ((-not $_.Deadline) -and $_.StartTime -and ($_.StartTime -is [datetime]) -and ($_.StartTime -lt $now.AddDays(-$graceDays)))
            })
            $inGrace = $pending.Count - $overdue.Count
            $caveat = ' (MECM-deployed updates only; Tanium scans the full patch list independently)'
            if ($overdue.Count -eq 0) {
                & $mk 'Patches' 'PASS' "0 overdue update(s); $($pending.Count) pending within ${graceDays}-day grace$caveat"
            } else {
                & $mk 'Patches' 'FAIL' "$($overdue.Count) overdue update(s) past MECM deadline/${graceDays}-day grace ($inGrace more pending within grace)$caveat"
            }
        } catch { & $mk 'Patches' 'ERROR' 'MECM/CCM not queryable' }

        # 5. Vuln threshold - TASKORD rule 3: AQC Score (filtered) must be < 25. This is the
        #    #1 fleet quarantine driver but the AQC score is server-side (ARAD/ACAS) and NOT
        #    endpoint-readable -> EXT (import the Tanium C2C CSV to score it per host).
        & $mk 'Vuln' 'EXT' 'AQC Score (filtered) must be < 25 - the #1 fleet quarantine driver; NOT verifiable by this scan (import the Tanium C2C CSV, or remediate via ACAS / Reports / KEV / UPR)'

        # 6. Encryption - TASKORD 26-0822 rule 2 (quarantine): the C: / OS volume has
        #    Protection Status ON. That single condition is what quarantines. Other fixed
        #    volumes not protected, or the OS volume still converting (Protection On but not
        #    yet FullyEncrypted), are shown as ADVISORY detail but never fail the pillar
        #    (the Fix Encryption card still targets all fixed volumes as DoD hardening).
        #    Fallback: manage-bde on the system drive when Get-BitLockerVolume is unavailable.
        try {
            $sysDrive = $env:SystemDrive
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                # Fixed drive-letter set: Get-Volume DriveType Fixed, else Win32_Volume DriveType=3.
                $fixedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                $haveFixedSrc = $false
                try {
                    if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
                        foreach ($v in @(Get-Volume -ErrorAction Stop)) {
                            if (([string]$v.DriveType -eq 'Fixed') -and [string]$v.DriveLetter) { [void]$fixedSet.Add((([string]$v.DriveLetter).Substring(0,1) + ':')) }
                        }
                        $haveFixedSrc = $true
                    }
                } catch {}
                if (-not $haveFixedSrc) {
                    try {
                        foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop)) {
                            if (([int]$v.DriveType -eq 3) -and [string]$v.DriveLetter) { [void]$fixedSet.Add((([string]$v.DriveLetter).Substring(0,1) + ':')) }
                        }
                        $haveFixedSrc = $true
                    } catch {}
                }
                $allBl = @()
                try { $allBl = @(Get-BitLockerVolume -ErrorAction Stop) } catch { $allBl = @() }
                $fixedVols = New-Object System.Collections.ArrayList
                foreach ($b in $allBl) {
                    $mpB = ([string]$b.MountPoint).TrimEnd('\')
                    $isLetter = ($mpB -match '^[A-Za-z]:$')
                    if ([string]$b.VolumeType -eq 'OperatingSystem') { [void]$fixedVols.Add($b); continue }
                    if (-not $isLetter) { continue }                       # letterless (EFI/recovery) - skip, never fail
                    if ($haveFixedSrc -and $fixedSet.Contains($mpB)) { [void]$fixedVols.Add($b) }
                }
                if ($fixedVols.Count -eq 0) {
                    $blSys = $null
                    try { $blSys = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop } catch {}
                    if ($blSys) { [void]$fixedVols.Add($blSys) }
                }
                if ($fixedVols.Count -eq 0) {
                    & $mk 'Encryption' 'ERROR' 'no fixed BitLocker volumes could be enumerated'
                } else {
                    $srcNote = if (-not $haveFixedSrc) { ' [no fixed-drive source available; OS volume only]' } else { '' }
                    # Identify the OS/C: volume (the ONLY thing TASKORD rule 2 scores).
                    $osVol = @($fixedVols | Where-Object { [string]$_.VolumeType -eq 'OperatingSystem' })[0]
                    if (-not $osVol) { $osVol = @($fixedVols | Where-Object { ([string]$_.MountPoint).TrimEnd('\') -ieq $sysDrive })[0] }
                    if (-not $osVol) { $osVol = $fixedVols[0] }
                    $allTxt = New-Object System.Collections.ArrayList
                    $adv    = New-Object System.Collections.ArrayList
                    foreach ($b in $fixedVols) {
                        $mpB = ([string]$b.MountPoint).TrimEnd('\'); if (-not $mpB) { $mpB = '(no letter)' }
                        $psB = [string]$b.ProtectionStatus; $vsB = [string]$b.VolumeStatus
                        $pctB = ''; try { $pctB = [string]$b.EncryptionPercentage } catch {}
                        $vsTxt = if (($vsB -match '(?i)EncryptionInProgress') -and $pctB) { "$vsB($pctB%)" } else { $vsB }
                        [void]$allTxt.Add("$mpB $psB/$vsTxt")
                        # Advisory (NOT scored): any fixed volume not On, or the OS volume not yet FullyEncrypted.
                        if (-not ($psB -eq 'On')) { [void]$adv.Add("$mpB $psB/$vsTxt") }
                        elseif (($b -eq $osVol) -and -not ($vsB -match '(?i)FullyEncrypted')) { [void]$adv.Add("$mpB On but $vsTxt") }
                    }
                    $osMp = ([string]$osVol.MountPoint).TrimEnd('\'); if (-not $osMp) { $osMp = $sysDrive }
                    $osPs = [string]$osVol.ProtectionStatus
                    $advTxt = if ($adv.Count -gt 0) { " | advisory (not scored): $($adv -join '; ')" } else { '' }
                    if ($osPs -eq 'On') { & $mk 'Encryption' 'PASS' "$osMp (OS) Protection On [all: $($allTxt -join '; ')]$srcNote$advTxt" }
                    else                { & $mk 'Encryption' 'FAIL' "$osMp (OS) Protection $osPs - TASKORD rule 2 requires C: Protection On [all: $($allTxt -join '; ')]$srcNote$advTxt" }
                }
            } else {
                # Fallback: manage-bde -status on the system drive (Get-BitLockerVolume
                # unavailable). TASKORD rule 2 = Protection Status ON on C: (NOT Fully
                # Encrypted) - so PASS on Protection On alone; conversion status is advisory.
                $out = (& manage-bde -status $sysDrive 2>&1 | Out-String)
                $protOn  = ($out -match '(?i)Protection\s+Status:\s*Protection\s+On')
                $fbNote  = '(manage-bde; system-drive only - Get-BitLockerVolume unavailable)'
                $cs = ''
                if ($out -match '(?i)Conversion\s+Status:\s*([^\r\n]+)') { $cs = ([string]$Matches[1]).Trim() }
                $csTxt = if ($cs) { " (Conversion Status $cs)" } else { '' }
                if ($protOn) {
                    & $mk 'Encryption' 'PASS' "$sysDrive Protection On$csTxt $fbNote"
                } else {
                    & $mk 'Encryption' 'FAIL' "$sysDrive Protection Off/unknown$csTxt - TASKORD rule 2 requires C: Protection On $fbNote"
                }
            }
        } catch { & $mk 'Encryption' 'ERROR' $_.Exception.Message }

        # 7. AppWhitelist - AppLocker enforcing, else WDAC code-integrity enforced.
        try {
            $enforced = $false; $note = ''
            if (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
                try {
                    $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
                    foreach ($rc in $pol.RuleCollections) {
                        if ([string]$rc.EnforcementMode -eq 'Enabled') { $enforced = $true; break }
                    }
                    if (-not $enforced) {
                        $audit = @($pol.RuleCollections | Where-Object { [string]$_.EnforcementMode -eq 'AuditOnly' }).Count
                        if ($audit -gt 0) { $note = "AppLocker AuditOnly ($audit collection(s)) - not enforcing" }
                    }
                } catch {}
            }
            if ($enforced) { & $mk 'AppWhitelist' 'PASS' 'AppLocker enforcing (>=1 rule collection Enabled)' }
            else {
                $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
                $ci = if ($dg) { [int]$dg.CodeIntegrityPolicyEnforcementStatus } else { -1 }
                if     ($ci -ge 2) { & $mk 'AppWhitelist' 'PASS' "WDAC code-integrity enforced (status $ci)" }
                elseif ($note)     { & $mk 'AppWhitelist' 'FAIL' $note }
                elseif ($ci -ge 0) { & $mk 'AppWhitelist' 'FAIL' "no AppLocker enforcing; WDAC status $ci (not enforced)" }
                else               { & $mk 'AppWhitelist' 'FAIL' 'no AppLocker or WDAC enforcement active' }
            }
        } catch { & $mk 'AppWhitelist' 'ERROR' $_.Exception.Message }

        # 8. Agents - patching agent (CcmExec) AND >=1 configured security agent running.
        try {
            $ccm = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
            $ccmRun = ($ccm -and $ccm.Status -eq 'Running')
            $secRun = New-Object System.Collections.ArrayList
            foreach ($s in @($secAgents)) {
                $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') { [void]$secRun.Add($s) }
            }
            $ccmTxt = if ($ccmRun) { 'CcmExec Running' } elseif ($ccm) { "CcmExec $($ccm.Status)" } else { 'CcmExec absent' }
            $secTxt = if ($secRun.Count -gt 0) { "security: $($secRun -join ',') Running" } else { 'no configured security agent Running' }
            if ($ccmRun -and $secRun.Count -gt 0) { & $mk 'Agents' 'PASS' "$ccmTxt; $secTxt" }
            else                                  { & $mk 'Agents' 'FAIL' "$ccmTxt; $secTxt" }
        } catch { & $mk 'Agents' 'ERROR' $_.Exception.Message }

        # 9. PkiRoots - required DoD root thumbprints present in LocalMachine\Root.
        #    Empty baseline -> EXT (do NOT fail - operator must configure it).
        try {
            $req = @($dodRoots)
            if ($req.Count -eq 0) {
                & $mk 'PkiRoots' 'EXT' 'configure DoD root thumbprints in c2c-baseline.json'
            } else {
                $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($c in (Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)) {
                    [void]$present.Add((([string]$c.Thumbprint) -replace '[^0-9A-Fa-f]',''))
                }
                $missing = New-Object System.Collections.ArrayList
                foreach ($t in $req) {
                    $tt = (([string]$t) -replace '[^0-9A-Fa-f]','')
                    if ($tt -and -not $present.Contains($tt)) { [void]$missing.Add($tt) }
                }
                if ($missing.Count -eq 0) {
                    & $mk 'PkiRoots' 'PASS' "all $($req.Count) required DoD root(s) present"
                } else {
                    $shorts = @($missing | ForEach-Object { $_.Substring(0, [Math]::Min(8, $_.Length)) })
                    & $mk 'PkiRoots' 'FAIL' "$($missing.Count)/$($req.Count) required root(s) missing: $($shorts -join ', ')"
                }
            }
        } catch { & $mk 'PkiRoots' 'ERROR' $_.Exception.Message }

        # 10. COAMS - 7 asset tags, server-side (ARAD/ePO), not endpoint-readable -> EXT.
        & $mk 'COAMS' 'EXT' 'ARAD/ePO server-side tags (7) - not endpoint-readable'

        # 11. OSVersion - TASKORD 26-0822 AUDIT rule 6 (informational, never quarantines):
        #     Windows 11 AND Release ID 24H2+ AND Edition Enterprise. One registry read
        #     (Get-ItemProperty, not the slow Get-ComputerInfo). ProductName is NOT used -
        #     it still reports "Windows 10" on Win11; CurrentBuildNumber is authoritative.
        try {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $build = 0; [void][int]::TryParse([string]$cv.CurrentBuildNumber, [ref]$build)
            $disp  = [string]$cv.DisplayVersion
            $edir  = [string]$cv.EditionID
            $win11      = ($build -ge 22000)
            $is24h2plus = ($build -ge 26100)
            $enterprise = ($edir -eq 'Enterprise')   # exact - Pro/EnterpriseS(LTSC)/Education fail
            $why = New-Object System.Collections.ArrayList
            if (-not $win11)      { [void]$why.Add("not Windows 11 (build $build)") }
            if (-not $is24h2plus) { [void]$why.Add("release $disp < 24H2 (build $build)") }
            if (-not $enterprise) { [void]$why.Add("edition $edir != Enterprise") }
            $verTxt = "Win11=$win11 (build $build); release $disp; edition $edir"
            if ($why.Count -eq 0) { & $mk 'OSVersion' 'PASS' "Windows 11 $disp Enterprise; $verTxt" }
            else                  { & $mk 'OSVersion' 'FAIL' "$($why -join '; ') - remediate via the Windows Upgrade tool; $verTxt" }
        } catch { & $mk 'OSVersion' 'ERROR' $_.Exception.Message }

        # (The old local Hostname naming-convention check was removed: its patterns were
        # base-specific (^MSEKL/^MSEKW), so it FALSE-flagged every host at other bases as
        # QUARANTINE RISK. The authoritative hostname verdict is ARAD-side anyway.)

        return @{ RemoteName = $env:COMPUTERNAME; Checks = @($checks) }
    }

    try {
        $probe = Invoke-Command -Session $sess -ScriptBlock $probeSb -ArgumentList @($taniumService, $sigMaxAge, $sigMaxHours, $graceDays, $mdeOrgId, $secAgents, $dodRoots, $TaniumInstalledSrc) -ErrorAction Stop
    } catch {
        $r.Status = 'ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    # DNS-mismatch guard (read-only soft-warn, wpt/biosfirmware idiom): a wrong box
    # would report the wrong readiness. Session name compare, never a PTR lookup.
    # An IP-literal target has no name to compare (its short name would be the first octet),
    # so skip the compare for IPs - mirrors the fix worker's wrong-box IP carve-out. Manual
    # mode invites typing the IP of a DNS-broken box; without this every IP scan false-skips.
    $actualName  = ([string]$probe.RemoteName).Trim()
    $targetShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
    if ($targetShort -and $actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
        $r.Status = 'DNS MISMATCH'; $r.Detail = "dialed '$targetShort' but remote is '$actualName' - skipped (would report the wrong machine)"
        return $r
    }

    $checks = @($probe.Checks)
    $r.Checks = $checks
    if ($checks.Count -eq 0) { $r.Status = 'ERROR'; $r.Detail = 'probe returned no checks'; return $r }

    # TASKORD-tiered verdict + tagged report (single source; unit-tested).
    $v = Get-C2cVerdict -Checks $checks
    $r.Status = $v.Status; $r.Ok = $v.Ok; $r.Detail = $v.Detail; $r.Report = $v.Report
    return $r
}

# =============================================================================
#  C2C ACTION SIDE - Import (Tanium C2C Compliance CSV) + Mass Fix (destructive)
#  Added in v1.1.0. The read-only 'scan' path above is untouched.
# =============================================================================

# --- Canonical pillar mapping ------------------------------------------------
# Routing hint per canonical pillar. Endpoint-fixable pillars point at the Mass
# Fix; the rest route to the owning tool. Unknown rule names fall through to
# 'review manually' (never silently dropped).
$script:C2cPillarRouting = @{
    Monitoring  = 'fixable HERE (Fix Monitoring: verify Tanium installed + heal client service)'
    Firewall    = 'fixable HERE (Fix Firewall: enable disabled profiles)'
    Encryption  = 'fixable HERE (Fix Encryption: resume / ENABLE BitLocker)'
    AntiMalware = 'fixable HERE (Fix AntiMalware: heal Defender / MDE)'
    Patches     = 'endpoint-kickable HERE (Fix Patches: trigger MECM scan / eval)'
    PkiRoots    = 'fixable HERE (Fix PKI Trust Roots: install the DoD trust bundle .cer into Root/CA/Disallowed)'
    Vuln        = 'ACAS / Reports / KEV tools'
    OSVersion   = 'Windows Upgrade tool'
    STIG        = 'Reports / STIG'
}
# Endpoint-fixable pillars (each has a per-pillar fix action + is eligible for run-all).
# v1.6.0 brings PkiRoots BACK as fixable - the folder/.cer-bundle DoD-roots installer
# (fix-pki) replaces the removed .sst mechanism. A run-all host that plans PkiRoots is
# only actioned when a valid cert bundle folder is supplied (else it is skipped for
# that host with an info note, never aborting the run).
$script:C2cFixablePillars = @('Monitoring','Firewall','Encryption','AntiMalware','Patches','PkiRoots')
# Stable display order for the summary; unknown pillars append alphabetically.
$script:C2cPillarOrder = @('Monitoring','Firewall','Encryption','AntiMalware','PkiRoots','Patches','Vuln','OSVersion','STIG')

# Map a rule name (already stripped of its "Failed/Audit Rule[ N] - " prefix) to a
# canonical pillar. Unknown names return verbatim (their own stripped name).
function Get-C2cCanonicalPillar {
    param([string]$Stripped)
    $s = ([string]$Stripped).Trim()
    switch -Regex ($s) {
        '^(?i)(Continuous |Endpoint )?Monitoring$' { return 'Monitoring' }
        '^(?i)Tanium( Client)?$'                  { return 'Monitoring' }
        '^(?i)(Host |Endpoint )?Firewall$'        { return 'Firewall' }
        '^(?i)Endpoint Data At Rest Encryption$' { return 'Encryption' }
        '^(?i)Bitlocker$'                        { return 'Encryption' }
        '^(?i)Anti-?malware$'                    { return 'AntiMalware' }
        '^(?i)MDE Health$'                       { return 'AntiMalware' }
        '^(?i)PKI Trust Roots$'                  { return 'PkiRoots' }
        '^(?i)Patching( Compliance)?$'           { return 'Patches' }
        '^(?i)Vulnerabilit(y Compliance|ies)$'   { return 'Vuln' }
        '^(?i)OS Version$'                       { return 'OSVersion' }
        '^(?i)STIG Check$'                        { return 'STIG' }
        default                                  { return $s }
    }
}

function Get-C2cPillarRouting {
    param([string]$Pillar)
    if ($script:C2cPillarRouting.ContainsKey($Pillar)) { return $script:C2cPillarRouting[$Pillar] }
    return 'review manually'
}

# --- Parse the Tanium "C2C Compliance Status" CSV export ---------------------
# The Compliance field is MULTILINE inside one quoted cell: first line
# Compliant/Non-Compliant, following lines are rule names. Import-Csv handles the
# quoting. Returns @{ Records=@(@{Short;Fqdn;Compliance;Failed=@();Audit=@()}); RowCount=int }.
# Dedup by short host name: the worst row wins (Non-Compliant over Compliant; on a
# tie, more failed pillars).
function ConvertFrom-C2cComplianceCsv {
    param([string[]]$Paths, [string]$Text, [scriptblock]$Send)

    $allRows = New-Object System.Collections.ArrayList
    foreach ($path in @($Paths | Where-Object { $_ })) {
        $pp = ([string]$path).Trim().Trim('"')
        if (-not $pp) { continue }
        if (-not (Test-Path -LiteralPath $pp)) {
            if ($Send) { & $Send @{ type='log'; level='warn'; text="File not found: $pp" } }
            continue
        }
        try {
            foreach ($r in (Import-Csv -LiteralPath $pp -Encoding UTF8 -ErrorAction Stop)) { [void]$allRows.Add($r) }
        } catch {
            if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse '$pp': $($_.Exception.Message)" } }
        }
    }
    if ($Text -and -not [string]::IsNullOrWhiteSpace($Text)) {
        try { foreach ($r in (ConvertFrom-Csv $Text)) { [void]$allRows.Add($r) } }
        catch { if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse pasted CSV: $($_.Exception.Message)" } } }
    }

    # Locate the Compliance + Computer Name columns (tolerate header variants).
    $complCol = $null; $hostCol = $null
    if ($allRows.Count -gt 0) {
        foreach ($p in $allRows[0].PSObject.Properties.Name) {
            if (-not $complCol -and $p -match '(?i)Compliance$')     { $complCol = $p }
            if (-not $hostCol  -and $p -match '(?i)Computer Name$')  { $hostCol  = $p }
        }
    }
    if (-not $complCol) { $complCol = 'C2C Compliance Status:Compliance' }
    if (-not $hostCol)  { $hostCol  = 'Computer Name' }

    $recs = New-Object System.Collections.ArrayList
    foreach ($r in $allRows) {
        $cp = $r.PSObject.Properties[$complCol]
        $hp = $r.PSObject.Properties[$hostCol]
        $complVal = if ($cp) { [string]$cp.Value } else { '' }
        $fqdn     = if ($hp) { ([string]$hp.Value).Trim() } else { '' }
        if (-not $fqdn) { continue }
        $short = ($fqdn -split '\.')[0]
        # Whitelist the short token before it can become a remote target.
        if ($short -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') { continue }

        $lines = @([regex]::Split($complVal, '\r\n|\n|\r') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($lines.Count -eq 0) { continue }
        $compliance = if     ($lines[0] -match '(?i)^Non-?Compliant') { 'Non-Compliant' }
                      elseif ($lines[0] -match '(?i)^Compliant')      { 'Compliant' }
                      else                                            { [string]$lines[0] }

        $failed = New-Object System.Collections.ArrayList
        $audit  = New-Object System.Collections.ArrayList
        foreach ($ln in (@($lines) | Select-Object -Skip 1)) {
            $kind = 'Failed'; $stripped = $ln
            if ($ln -match '(?i)^Failed\s+Rule(\s+\d+)?\s*-\s*(.+)$')     { $kind = 'Failed'; $stripped = $Matches[2].Trim() }
            elseif ($ln -match '(?i)^Audit\s+Rule(\s+\d+)?\s*-\s*(.+)$')  { $kind = 'Audit';  $stripped = $Matches[2].Trim() }
            else { $kind = 'Failed'; $stripped = $ln.Trim() }   # no recognizable prefix -> surface as failing, verbatim
            if (-not $stripped) { continue }
            $canon = Get-C2cCanonicalPillar $stripped
            if ($kind -eq 'Audit') { if (-not $audit.Contains($canon))  { [void]$audit.Add($canon) } }
            else                    { if (-not $failed.Contains($canon)) { [void]$failed.Add($canon) } }
        }
        [void]$recs.Add([pscustomobject]@{
            Short=$short; Fqdn=$fqdn; Compliance=$compliance; Failed=@($failed); Audit=@($audit)
        })
    }

    # Dedup by short host - worst row wins.
    $byHost = @{}
    foreach ($rec in $recs) {
        $key = $rec.Short.ToUpperInvariant()
        if (-not $byHost.ContainsKey($key)) { $byHost[$key] = $rec; continue }
        $ex     = $byHost[$key]
        $recBad = ($rec.Compliance -match '(?i)Non-?Compliant')
        $exBad  = ($ex.Compliance  -match '(?i)Non-?Compliant')
        if ($recBad -and -not $exBad) { $byHost[$key] = $rec }
        elseif (($recBad -eq $exBad) -and (@($rec.Failed).Count -gt @($ex.Failed).Count)) { $byHost[$key] = $rec }
    }
    return @{ Records=@($byHost.Values); RowCount=$allRows.Count }
}

# --- Bool coercion (view sends real bools; CLI/tests may send strings) --------
function Get-C2cBool {
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return (@('true','1','yes','on') -contains ([string]$Value).Trim().ToLowerInvariant())
}

# --- Self-guard (mirrors JanetWeb.secureboot / restart) ----------------------
# Set of identities that resolve to THIS dispatcher host. A Mass Fix that resumed
# BitLocker / restarted Defender on the box running JANET could disrupt the server
# mid-run, so the dispatcher is dropped from every fix run.
function Get-JanetC2cLocalIdentity {
    if ($script:C2cLocalIdentity) { return $script:C2cLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:C2cLocalIdentity = $set
    return $set
}

function Test-JanetC2cHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetC2cLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    if ($Target -match '^::1$')  { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

# Dispatch/de-dupe short name that PRESERVES an IP literal. An operator can type the IP of a
# DNS-broken box as a fix target (the fix worker's wrong-box guard has an explicit IP carve-out),
# so 'HOSTP.area52.mil' -> 'HOSTP' but '10.20.30.40' -> '10.20.30.40' (never mangled to '10').
# Mirrors the IP-literal handling in Test-JanetC2cHostIsSelf, so a typed dispatcher IP is still
# caught by the self-guard (Get-JanetC2cLocalIdentity holds this box's IPs).
function Get-C2cShortHost {
    param([string]$Name)
    $n = [string]$Name
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($n, [ref]$ip)) { return $n }
    return ($n -split '\.')[0]
}

# --- Per-host Mass Fix worker (runs in a pool runspace) ----------------------
# Returns @{ Host; Ping; Status; Detail; Report; Pillars }. All enabled pillar
# fixes run inside ONE Invoke-Command round-trip (fix-then-verify); the host-level
# status is computed here (admin-side).
$script:C2cFixBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string[]]$Pillars, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [bool]$WinrmHeal, [string]$WinrmHealSrc, [string]$AddCertsSrc, [int]$SigMaxAgeHours, [string]$MdeOrgId, [string]$MdeBlob, [string]$JavaSrc, [bool]$DoPrune, [bool]$DoRdp, [string]$OfflineDefPath, [string]$OfflineDefSha256)

    # Per-host pillar set (may differ per host in run-all). Normalize to a clean
    # [string] array even if a single-element array crossed a boundary as a scalar.
    $Pillars = @(@($Pillars) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
    if ([string]::IsNullOrWhiteSpace($TaniumService)) { $TaniumService = 'Tanium Client' }
    if ($SigMaxAgeHours -le 0) { $SigMaxAgeHours = 24 }   # signature-freshness budget (hours) for the AntiMalware fixer

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Report=''; Pillars=@() }

    # TCP reachability (WinRM HTTP 5985, then WinRM HTTPS 5986, then SMB 445 liveness, 1.5s).
    # Never ICMP. $useSsl set when ONLY 5986 answered -> session below auto-switches to -UseSSL.
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    # Opt-in RPC WinRM-heal: only when the TCP probe failed AND the caller armed it
    # (the caller already excluded the dispatcher host via Test-JanetC2cHostIsSelf).
    $healNote = ''
    if (-not $reachable -and $WinrmHeal) {
        if ($WinrmHealSrc) { try { . ([scriptblock]::Create($WinrmHealSrc)) } catch {} }
        if (Get-Command Invoke-JanetC2cWinrmHeal -ErrorAction SilentlyContinue) {
            $hb = $null
            try { $hb = Invoke-JanetC2cWinrmHeal -Computer $Computer } catch {}
            if ($hb) {
                $healNote = "winrm-heal: $($hb.Bucket)"
                if ($hb.Bucket -eq 'reachable' -or $hb.Bucket -eq 'winrm-recovered') { $reachable = $true; $r.Ping = "TCP 5985 ($($hb.Bucket))" }
            }
        }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = (@('No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.', $healNote) | Where-Object { $_ }) -join ' | '; return $r }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS common on AFNET).
    $soP = @{ OperationTimeout=280000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=120000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'FAILED'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box guard (HARD ABORT, before any change): compare the answering box's
    # name to the dialed short name. IP-literal targets have no DNS indirection.
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                $r.Status = 'SKIPPED'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - ABORTED, nothing changed"
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = 'FAILED'; $r.Detail = "wrong-box guard probe failed: $($_.Exception.Message)"; return $r
    }

    $fixSb = {
        # Pillars cross as a '|'-delimited string (never an array) so no ArgumentList
        # flattening/serialization ambiguity over the WinRM boundary.
        param([string]$PillarCsv, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [string]$AddCertsSrc, [int]$SigMaxAgeHours, [string]$MdeOrgId, [string]$MdeBlob, [string]$JavaSrc, [bool]$DoPrune, [bool]$DoRdp)
        if ($SigMaxAgeHours -le 0) { $SigMaxAgeHours = 24 }
        $Pillars = @(($PillarCsv -split '\|') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
        if ([string]::IsNullOrWhiteSpace($TaniumService)) { $TaniumService = 'Tanium Client' }
        # Dot-source the single-source Tanium-installed probe (Get-C2cTaniumInstalled).
        if ($TaniumInstalledSrc) { try { . ([scriptblock]::Create($TaniumInstalledSrc)) } catch {} }
        $results = New-Object System.Collections.ArrayList
        $add = { param($n,$a,$res,$d) [void]$results.Add([pscustomobject]@{ Name=$n; Action=[string]$a; Result=[string]$res; Detail=[string]$d }) }

        # M. Monitoring - verify the Tanium SOFTWARE is installed (uninstall registry)
        #    AND heal the Tanium client service (StartType Automatic + Running). A missing
        #    service is NOT created here: installed-but-no-service -> repair via MECM;
        #    neither installed nor service -> deploy via MECM.
        if ($Pillars -contains 'Monitoring') {
            try {
                $ti = if (Get-Command Get-C2cTaniumInstalled -ErrorAction SilentlyContinue) { Get-C2cTaniumInstalled } else { [pscustomobject]@{ Installed=$false; DisplayName=''; Version='' } }
                $instTxt = if ($ti.Installed) { 'Tanium installed' + $(if ($ti.Version) { " (v$($ti.Version))" } else { '' }) } else { 'Tanium not installed' }
                $svc = Get-Service -Name $TaniumService -ErrorAction SilentlyContinue
                if (-not $svc) {
                    if ($ti.Installed) {
                        & $add 'Monitoring' 'none' 'FAIL' "$instTxt but the '$TaniumService' client service is missing - repair via Software Center/MECM"
                    } else {
                        & $add 'Monitoring' 'none' 'FAIL' "Tanium not installed - deploy from Software Center/MECM ('$TaniumService' service absent)"
                    }
                } else {
                    $changed = New-Object System.Collections.ArrayList
                    if ([string]$svc.StartType -ne 'Automatic') {
                        try { Set-Service -Name $TaniumService -StartupType Automatic -ErrorAction Stop; [void]$changed.Add('StartType->Automatic') } catch {}
                    }
                    if ($svc.Status -ne 'Running') {
                        try { Start-Service -Name $TaniumService -ErrorAction Stop; [void]$changed.Add('started') } catch {}
                    }
                    Start-Sleep -Milliseconds 300
                    $svc2 = Get-Service -Name $TaniumService -ErrorAction SilentlyContinue
                    $runNow   = ($svc2 -and $svc2.Status -eq 'Running')
                    $startNow = if ($svc2) { [string]$svc2.StartType } else { [string]$svc.StartType }
                    if (-not $runNow) {
                        $st = if ($svc2) { [string]$svc2.Status } else { [string]$svc.Status }
                        & $add 'Monitoring' 'heal' 'FAIL' "$instTxt; '$TaniumService' still $st after heal attempt"
                    } elseif ($changed.Count -gt 0) {
                        & $add 'Monitoring' 'heal' 'FIXED' "$instTxt; '$TaniumService' healed: $($changed -join '; '); now Running (StartType $startNow)"
                    } else {
                        & $add 'Monitoring' 'none' 'NOCHANGE' "$instTxt; '$TaniumService' already Running (StartType $startNow)"
                    }
                }
            } catch { & $add 'Monitoring' 'error' 'FAIL' $_.Exception.Message }
        }

        # F. Firewall - enable any disabled Domain/Private/Public profile, then verify.
        if ($Pillars -contains 'Firewall') {
            try {
                if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                    $profs = Get-NetFirewallProfile -ErrorAction Stop
                    $off = @($profs | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
                    if ($off.Count -eq 0) {
                        & $add 'Firewall' 'none' 'NOCHANGE' 'Domain/Private/Public all already enabled'
                    } else {
                        foreach ($pn in $off) { try { Set-NetFirewallProfile -Profile $pn -Enabled True -ErrorAction Stop } catch {} }
                        Start-Sleep -Milliseconds 200
                        $profs2 = Get-NetFirewallProfile -ErrorAction Stop
                        $still = @($profs2 | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
                        if ($still.Count -eq 0) { & $add 'Firewall' 'enable' 'FIXED' "enabled profile(s): $($off -join ', ')" }
                        else                    { & $add 'Firewall' 'enable' 'FAIL' "still disabled after enable: $($still -join ', ')" }
                    }
                } else {
                    # netsh fallback (no NetSecurity module). Fail CLOSED: if the output does
                    # not parse (locale/format), THROW rather than report a false NOCHANGE/FIXED
                    # (the outer catch maps it to a Firewall FAIL).
                    $parse = {
                        param($txt)
                        $curProf=''; $dis = New-Object System.Collections.ArrayList
                        $profHdrs=0; $stateLns=0
                        foreach ($ln in ($txt -split "`r?`n")) {
                            if     ($ln -match '^(Domain|Private|Public)\s+Profile') { $curProf = $Matches[1]; $profHdrs++ }
                            elseif ($ln -match '^State\s+(\S+)') { $stateLns++; if ($Matches[1] -notmatch '^(?i:on)$' -and $curProf) { [void]$dis.Add($curProf) } }
                        }
                        if ($profHdrs -lt 3 -or $stateLns -lt 3) { throw "netsh output not parseable ($profHdrs header(s), $stateLns state line(s))" }
                        ,@($dis | Select-Object -Unique)
                    }
                    $off = & $parse (& netsh advfirewall show allprofiles state 2>&1 | Out-String)
                    if (@($off).Count -eq 0) {
                        & $add 'Firewall' 'none' 'NOCHANGE' 'all profiles already enabled (netsh)'
                    } else {
                        foreach ($pn in @($off)) { & netsh advfirewall set ("{0}profile" -f ([string]$pn).ToLower()) state on 2>&1 | Out-Null }
                        $still = & $parse (& netsh advfirewall show allprofiles state 2>&1 | Out-String)
                        if (@($still).Count -eq 0) { & $add 'Firewall' 'enable' 'FIXED' "enabled profile(s): $(@($off) -join ', ') (netsh)" }
                        else                       { & $add 'Firewall' 'enable' 'FAIL' "still disabled after enable: $(@($still) -join ', ') (netsh)" }
                    }
                }
            } catch { & $add 'Firewall' 'error' 'FAIL' $_.Exception.Message }
        }

        # 1. Encryption - iterate EVERY FIXED VOLUME. By default RESUME suspended
        #    protectors; when the operator opts in (DoEnable) a FullyDecrypted fixed
        #    volume is ENABLED escrow-first / fail-closed. The OS volume mirrors the
        #    enterprise USAF script (FVE policy assert ONCE per host -> reuse/add a
        #    RecoveryPassword protector -> Entra-first / AD-fallback escrow BEFORE
        #    Enable-BitLocker; TPM-gated + domain-joined; XtsAes256 + TPM protector).
        #    Fixed DATA volumes enable escrow-first too but with NO TPM protector, require
        #    the OS volume BitLocker-on first (for auto-unlock), dedup to exactly one
        #    escrowed recovery protector, then best-effort Enable-BitLockerAutoUnlock.
        #    Removable/USB (BitLocker To Go), network and optical volumes are NEVER
        #    touched; the recovery password is never emitted. One 'Encryption' result is
        #    emitted PER volume so the host rollup naturally yields FIXED / PARTIAL /
        #    FAILED / NO CHANGE.
        if ($Pillars -contains 'Encryption') {
            try {
                $sys = $env:SystemDrive
                if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                    # ---- Enumerate FIXED volumes (Get-Volume DriveType Fixed, else Win32_Volume DriveType=3). ----
                    $fixedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    $haveFixedSrc = $false
                    try {
                        if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
                            foreach ($v in @(Get-Volume -ErrorAction Stop)) {
                                if (([string]$v.DriveType -eq 'Fixed') -and [string]$v.DriveLetter) { [void]$fixedSet.Add((([string]$v.DriveLetter).Substring(0,1) + ':')) }
                            }
                            $haveFixedSrc = $true
                        }
                    } catch {}
                    if (-not $haveFixedSrc) {
                        try {
                            foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop)) {
                                if (([int]$v.DriveType -eq 3) -and [string]$v.DriveLetter) { [void]$fixedSet.Add((([string]$v.DriveLetter).Substring(0,1) + ':')) }
                            }
                            $haveFixedSrc = $true
                        } catch {}
                    }
                    $allBl = @()
                    try { $allBl = @(Get-BitLockerVolume -ErrorAction Stop) } catch { $allBl = @() }
                    $fixedVols = New-Object System.Collections.ArrayList
                    foreach ($b in $allBl) {
                        $mpB = ([string]$b.MountPoint).TrimEnd('\')
                        $isLetter = ($mpB -match '^[A-Za-z]:$')
                        if ([string]$b.VolumeType -eq 'OperatingSystem') { [void]$fixedVols.Add($b); continue }
                        if (-not $isLetter) { continue }                       # letterless (EFI/recovery) - never touch
                        if ($haveFixedSrc -and $fixedSet.Contains($mpB)) { [void]$fixedVols.Add($b) }
                    }
                    if ($fixedVols.Count -eq 0) {
                        $blSys = $null
                        try { $blSys = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop } catch {}
                        if ($blSys) { [void]$fixedVols.Add($blSys) }
                    }
                    if ($fixedVols.Count -eq 0) {
                        & $add 'Encryption' 'none' 'FAIL' 'no fixed BitLocker volumes could be enumerated'
                    } else {
                        # OS volume first so a data volume can see it encrypted/started for auto-unlock.
                        $ordered = @($fixedVols | Sort-Object @{ Expression = { if ([string]$_.VolumeType -eq 'OperatingSystem') { 0 } else { 1 } } })
                        $osEncOrPlanned = $false

                        # FVE policy asserted at most ONCE per host (memoized in $fve). Policy is what
                        # enforces recovery-key escrow + XtsAes256 - never encrypt without it. A write
                        # failure marks $fve.Ok=$false and the ENABLE path FAILs (enable NOT attempted);
                        # heal/resume/already-on paths proceed regardless (they run no Enable-BitLocker).
                        $fve = @{ Done = $false; Ok = $false; Err = ''; Txt = '' }
                        $assertFve = {
                            if ($fve.Done) { return }
                            $fve.Done = $true
                            $fveKey = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
                            $recMsg = 'Your device is locked and will require a Bitlocker Recovery Key. For key retrieval, you can use another government funded device or if teleworking, the Desktop Anywhere application for key recovery. There are two ways to access your key.   Option 1: Navigate to https://myaccount.azure.us and select your device under the managed device option. Instructions can be found under "How can I get my Bitlocker Recovery Key?" at https://usaf.dps.mil/teams/EnterpriseBitLockerActivation.   Option 2: If the bitlockered device is not listed, you''ll need to contact your local CST or submit a vESD ticket.'
                            $polDwords = @(
                                [pscustomobject]@{ Name='EnableBDEWithNoTPM';              Value=0 }
                                [pscustomobject]@{ Name='EncryptionMethodWithXtsFdv';      Value=7 }
                                [pscustomobject]@{ Name='EncryptionMethodWithXtsOs';       Value=7 }
                                [pscustomobject]@{ Name='EncryptionMethodWithXtsRdv';      Value=7 }
                                [pscustomobject]@{ Name='FDVActiveDirectoryBackup';        Value=1 }
                                [pscustomobject]@{ Name='FDVActiveDirectoryInfoToStore';   Value=2 }
                                [pscustomobject]@{ Name='FDVHideRecoveryPage';             Value=1 }
                                [pscustomobject]@{ Name='FDVManageDRA';                    Value=1 }
                                [pscustomobject]@{ Name='FDVRecovery';                     Value=1 }
                                [pscustomobject]@{ Name='FDVRecoveryKey';                  Value=2 }
                                [pscustomobject]@{ Name='FDVRecoveryPassword';             Value=1 }
                                [pscustomobject]@{ Name='FDVRequireActiveDirectoryBackup'; Value=1 }
                                [pscustomobject]@{ Name='OSActiveDirectoryBackup';         Value=1 }
                                [pscustomobject]@{ Name='OSActiveDirectoryInfoToStore';    Value=2 }
                                [pscustomobject]@{ Name='OSHideRecoveryPage';              Value=1 }
                                [pscustomobject]@{ Name='OSManageDRA';                     Value=1 }
                                [pscustomobject]@{ Name='OSRecovery';                      Value=1 }
                                [pscustomobject]@{ Name='OSRecoveryKey';                   Value=0 }
                                [pscustomobject]@{ Name='OSRecoveryPassword';              Value=2 }
                                [pscustomobject]@{ Name='OSRequireActiveDirectoryBackup';  Value=2 }
                                [pscustomobject]@{ Name='RecoveryKeyMessageSource';        Value=2 }
                                [pscustomobject]@{ Name='UseAdvancedStartup';              Value=1 }
                                [pscustomobject]@{ Name='UseTPM';                          Value=1 }
                            )
                            $polSet = 0; $polOk = 0; $polErr = ''
                            try {
                                $keyItem = $null
                                try { $keyItem = Get-Item -LiteralPath $fveKey -ErrorAction Stop } catch { $keyItem = $null }
                                if (-not $keyItem) {
                                    New-Item -Path $fveKey -Force -ErrorAction Stop | Out-Null
                                    try { $keyItem = Get-Item -LiteralPath $fveKey -ErrorAction Stop } catch { $keyItem = $null }
                                }
                                foreach ($pv in $polDwords) {
                                    $cur = $null
                                    if ($keyItem) { try { $cur = $keyItem.GetValue($pv.Name, $null) } catch { $cur = $null } }
                                    if (($null -ne $cur) -and ([int]$cur -eq [int]$pv.Value)) { $polOk++ }
                                    else { New-ItemProperty -Path $fveKey -Name $pv.Name -PropertyType DWord -Value ([int]$pv.Value) -Force -ErrorAction Stop | Out-Null; $polSet++ }
                                }
                                $curMsg = $null
                                if ($keyItem) { try { $curMsg = $keyItem.GetValue('RecoveryKeyMessage', $null) } catch { $curMsg = $null } }
                                if (($null -ne $curMsg) -and ([string]$curMsg -eq $recMsg)) { $polOk++ }
                                else { New-ItemProperty -Path $fveKey -Name 'RecoveryKeyMessage' -PropertyType String -Value $recMsg -Force -ErrorAction Stop | Out-Null; $polSet++ }
                            } catch { $polErr = $_.Exception.Message }
                            $fve.Err = $polErr
                            $fve.Ok  = (-not $polErr)
                            $fve.Txt = "FVE policy: $polSet set/corrected, $polOk already-correct"
                        }

                        # Shared escrow-first / fail-closed protector+escrow step for a given mount
                        # point ($vol) and its BitLocker object ($blObj). Returns
                        # @{ Ok; KpId; Target; Detail }: Ok=$false means escrow failed (a protector WE
                        # added has been removed) and Enable must NOT run. Never reads .RecoveryPassword.
                        $escrowFirst = {
                            param($vol, $blObj)
                            $weAdded = $false; $newKpId = ''
                            try {
                                $existingRp = @()
                                try { $existingRp = @($blObj.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)RecoveryPassword' }) } catch { $existingRp = @() }
                                if ($existingRp.Count -gt 0) {
                                    $newKpId = [string]$existingRp[0].KeyProtectorId
                                } else {
                                    $beforeIds = @()
                                    try { foreach ($k in @($blObj.KeyProtector)) { $beforeIds += [string]$k.KeyProtectorId } } catch {}
                                    $addRet = Add-BitLockerKeyProtector -MountPoint $vol -RecoveryPasswordProtector -ErrorAction Stop
                                    $weAdded = $true
                                    try {
                                        foreach ($k in @($addRet.KeyProtector)) {
                                            if (([string]$k.KeyProtectorType -match '(?i)RecoveryPassword') -and ($beforeIds -notcontains [string]$k.KeyProtectorId)) { $newKpId = [string]$k.KeyProtectorId; break }
                                        }
                                        if (-not $newKpId) {
                                            $rp = @($addRet.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)RecoveryPassword' })
                                            if ($rp.Count -gt 0) { $newKpId = [string]$rp[$rp.Count - 1].KeyProtectorId }
                                        }
                                    } catch {}
                                }
                            } catch {
                                return @{ Ok = $false; KpId = ''; Target = ''; Detail = "recovery-password protector add failed - encryption NOT started: $($_.Exception.Message)" }
                            }
                            $escrowOk = $false; $escrowTarget = ''
                            try {
                                if (Get-Command BackupToAAD-BitLockerKeyProtector -ErrorAction SilentlyContinue) {
                                    try {
                                        BackupToAAD-BitLockerKeyProtector -MountPoint $vol -KeyProtectorId $newKpId -ErrorAction Stop | Out-Null
                                        $escrowOk = $true; $escrowTarget = 'Entra'
                                    } catch { $escrowOk = $false }
                                }
                                if (-not $escrowOk) {
                                    Backup-BitLockerKeyProtector -MountPoint $vol -KeyProtectorId $newKpId -ErrorAction Stop | Out-Null
                                    $escrowOk = $true; $escrowTarget = 'AD'
                                }
                            } catch { $escrowOk = $false }
                            if (-not $escrowOk) {
                                if ($weAdded) { try { if ($newKpId) { Remove-BitLockerKeyProtector -MountPoint $vol -KeyProtectorId $newKpId -ErrorAction SilentlyContinue | Out-Null } } catch {} }
                                return @{ Ok = $false; KpId = $newKpId; Target = ''; Detail = 'escrow failed (Entra + AD) - encryption NOT started' }
                            }
                            return @{ Ok = $true; KpId = $newKpId; Target = $escrowTarget; Detail = '' }
                        }

                        # v7.11 GPO full parity: assert the FVE policy ONCE up front, before ANY
                        # BitLocker cmdlet on ANY path - so an already-encrypted / suspended box still
                        # gets its GPO values healed (matches the reference Set-FvePolicy-at-top). The
                        # enable branch still re-checks $fve.Ok to fail closed; heal/resume never gate on it.
                        & $assertFve
                        $fveNote = if ($fve.Ok) { $fve.Txt } else { "FVE policy assert FAILED: $($fve.Err)" }

                        foreach ($bv in $ordered) {
                            $mp  = ([string]$bv.MountPoint).TrimEnd('\'); if (-not $mp) { $mp = $sys }
                            $psv = [string]$bv.ProtectionStatus; $vsv = [string]$bv.VolumeStatus
                            $isOsVol = ([string]$bv.VolumeType -eq 'OperatingSystem')
                            $pctv = ''; try { $pctv = [string]$bv.EncryptionPercentage } catch {}

                            if ($psv -eq 'On') {
                                & $add 'Encryption' 'none' 'NOCHANGE' "$mp protection already On; $vsv; $fveNote"
                                if ($isOsVol) { $osEncOrPlanned = $true }
                                continue
                            }
                            if ($vsv -match '(?i)EncryptionInProgress') {
                                & $add 'Encryption' 'none' 'IN PROGRESS' "$mp encryption already in progress ($pctv% done); protection activates on completion - no action taken"
                                if ($isOsVol) { $osEncOrPlanned = $true }
                                continue
                            }
                            if ($vsv -match '(?i)FullyDecrypted') {
                                if (-not $DoEnable) {
                                    & $add 'Encryption' 'none' 'SKIP' "$mp not encrypted ($vsv) - BitLocker enable needs TPM+recovery-key escrow policy; route to MECM/desk-side"
                                    continue
                                }
                                if ($isOsVol) {
                                    # ---- OS volume ENABLE (USAF-aligned; TPM protector; each precondition => SKIP) ----
                                    $tpmOk = $false; $tpmWhy = 'TPM not ready - initialize via desk-side/MECM'
                                    try {
                                        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
                                            $tp = Get-Tpm -ErrorAction Stop
                                            if ([bool]$tp.TpmPresent -and [bool]$tp.TpmReady) { $tpmOk = $true }
                                            elseif (-not [bool]$tp.TpmPresent) { $tpmWhy = 'TPM not present - cannot enable BitLocker (route to desk-side)' }
                                        } else {
                                            $tpmWhy = 'Get-Tpm unavailable - cannot confirm TPM readiness (route to desk-side/MECM)'
                                        }
                                    } catch { $tpmWhy = "TPM not ready - initialize via desk-side/MECM ($($_.Exception.Message))" }
                                    if (-not $tpmOk) { & $add 'Encryption' 'none' 'SKIP' "$mp $tpmWhy"; continue }
                                    $domainJoined = $false
                                    try { $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $domainJoined = $false }
                                    if (-not $domainJoined) { & $add 'Encryption' 'none' 'SKIP' "$mp machine not domain-joined - AD recovery-password escrow unavailable; route to desk-side/MECM"; continue }
                                    & $assertFve
                                    if (-not $fve.Ok) { & $add 'Encryption' 'enable' 'FAIL' "$mp FVE policy assert failed: $($fve.Err)"; continue }
                                    $polTxt = $fve.Txt
                                    $ef = & $escrowFirst $mp $bv
                                    if (-not $ef.Ok) { & $add 'Encryption' 'enable' 'FAIL' "$mp $($ef.Detail)"; continue }
                                    $escrowTarget = [string]$ef.Target
                                    # v7.11 port: drop stale TPM protectors left by prior failed attempts -
                                    # Enable-BitLocker -TpmProtector throws FVE_E_PROTECTOR_EXISTS (0x8031001D)
                                    # if one already exists. Safe HERE only: the volume is FullyDecrypted, so
                                    # no protector is guarding anything.
                                    try {
                                        $staleTpm = @((Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop).KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)Tpm' })
                                        foreach ($spk in $staleTpm) { Remove-BitLockerKeyProtector -MountPoint $mp -KeyProtectorId ([string]$spk.KeyProtectorId) -ErrorAction Stop | Out-Null }
                                    } catch {}
                                    try {
                                        Enable-BitLocker -MountPoint $mp -TpmProtector -EncryptionMethod XtsAes256 -SkipHardwareTest -ErrorAction Stop | Out-Null
                                        Start-Sleep -Milliseconds 500
                                        $blE = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                                        $vsE = [string]$blE.VolumeStatus
                                        $pctE = ''; try { $pctE = [string]$blE.EncryptionPercentage } catch {}
                                        if ($vsE -match '(?i)FullyDecrypted') {
                                            & $add 'Encryption' 'enable' 'FAIL' "$mp Enable-BitLocker returned but volume still FullyDecrypted - encryption did not start"
                                        } else {
                                            $osEncOrPlanned = $true
                                            & $add 'Encryption' 'enable' 'STARTED' "$mp encryption started (XtsAes256, TPM+RecoveryPassword escrowed to $escrowTarget) - $pctE% done; $polTxt; protection activates on completion; Tanium clears after next scan"
                                        }
                                    } catch {
                                        & $add 'Encryption' 'enable' 'FAIL' "$mp escrow succeeded but Enable-BitLocker failed: $($_.Exception.Message)"
                                    }
                                    continue
                                } else {
                                    # ---- Fixed DATA volume ENABLE (no TPM; needs OS BitLocker-on; auto-unlock) ----
                                    if (-not $osEncOrPlanned) {
                                        & $add 'Encryption' 'none' 'SKIP' "$mp OS volume must be encrypted first - data-volume auto-unlock requires the OS volume BitLocker-on; route to MECM/desk-side"
                                        continue
                                    }
                                    & $assertFve
                                    if (-not $fve.Ok) { & $add 'Encryption' 'enable' 'FAIL' "$mp FVE policy assert failed: $($fve.Err)"; continue }
                                    $polTxt = $fve.Txt
                                    $ef = & $escrowFirst $mp $bv
                                    if (-not $ef.Ok) { & $add 'Encryption' 'enable' 'FAIL' "$mp $($ef.Detail)"; continue }
                                    $newKpId = [string]$ef.KpId; $escrowTarget = [string]$ef.Target
                                    try {
                                        Enable-BitLocker -MountPoint $mp -RecoveryPasswordProtector -EncryptionMethod XtsAes256 -SkipHardwareTest -ErrorAction Stop | Out-Null
                                        Start-Sleep -Milliseconds 500
                                        # Dedup: keep ONLY the escrowed recovery protector; drop any extra the cmdlet added.
                                        try {
                                            $blDd = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                                            foreach ($k in @($blDd.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)RecoveryPassword' })) {
                                                $kid = [string]$k.KeyProtectorId
                                                if ($kid -and $newKpId -and ($kid -ne $newKpId)) { try { Remove-BitLockerKeyProtector -MountPoint $mp -KeyProtectorId $kid -ErrorAction SilentlyContinue | Out-Null } catch {} }
                                            }
                                        } catch {}
                                        # Best-effort auto-unlock (requires the OS volume encrypted; note when deferred).
                                        $auNote = 'auto-unlock enabled'
                                        try { Enable-BitLockerAutoUnlock -MountPoint $mp -ErrorAction Stop | Out-Null }
                                        catch { $auNote = "auto-unlock deferred ($($_.Exception.Message))" }
                                        $blE = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                                        $vsE = [string]$blE.VolumeStatus
                                        $pctE = ''; try { $pctE = [string]$blE.EncryptionPercentage } catch {}
                                        if ($vsE -match '(?i)FullyDecrypted') {
                                            & $add 'Encryption' 'enable' 'FAIL' "$mp Enable-BitLocker returned but volume still FullyDecrypted - encryption did not start"
                                        } else {
                                            & $add 'Encryption' 'enable' 'STARTED' "$mp data-volume encryption started (XtsAes256, RecoveryPassword escrowed to $escrowTarget; $auNote) - $pctE% done; $polTxt; protection activates on completion; Tanium clears after next scan"
                                        }
                                    } catch {
                                        & $add 'Encryption' 'enable' 'FAIL' "$mp escrow succeeded but Enable-BitLocker failed: $($_.Exception.Message)"
                                    }
                                    continue
                                }
                            }
                            if ($vsv -match '(?i)Decrypt') {
                                & $add 'Encryption' 'none' 'SKIP' "$mp not encrypted ($vsv) - route to MECM/desk-side"
                                continue
                            }
                            # Off + FullyEncrypted (classic post-firmware suspended-protectors) -> resume.
                            # v7.11 port: an encrypted OS volume with NO TPM protector can never turn
                            # protection On by resuming alone - add the TPM protector first (TPM must be
                            # present + ready; best-effort, the resume below still runs either way).
                            $tpmProtTxt = ''
                            if ($isOsVol) {
                                # Escrow-first: NEVER resume a TPM-only OS volume. If no RecoveryPassword
                                # protector exists, add + escrow one via the SAME fail-closed path the enable
                                # branch uses; if escrow fails, SKIP the resume to avoid a TPM-only lockout.
                                $hasRpProt = $false
                                try { $hasRpProt = @($bv.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)RecoveryPassword' }).Count -gt 0 } catch { $hasRpProt = $false }
                                if (-not $hasRpProt) {
                                    $efR = & $escrowFirst $mp $bv
                                    if (-not $efR.Ok) {
                                        & $add 'Encryption' 'none' 'SKIP' "$mp no escrowed recovery protector - resume skipped to avoid TPM-only lockout ($($efR.Detail))"
                                        continue
                                    }
                                    $tpmProtTxt = "; recovery protector added + escrowed to $([string]$efR.Target)"
                                }
                                $hasTpmProt = $false
                                try { $hasTpmProt = @($bv.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)Tpm' }).Count -gt 0 } catch { $hasTpmProt = $false }
                                if (-not $hasTpmProt) {
                                    try {
                                        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
                                            $tpR = Get-Tpm -ErrorAction Stop
                                            if ([bool]$tpR.TpmPresent -and [bool]$tpR.TpmReady) {
                                                Add-BitLockerKeyProtector -MountPoint $mp -TpmProtector -ErrorAction Stop | Out-Null
                                                $tpmProtTxt += '; missing TPM protector added'
                                            } else { $tpmProtTxt += '; NOTE: no TPM protector and TPM not present/ready - resume may not stick' }
                                        }
                                    } catch { $tpmProtTxt += "; TPM protector add failed ($($_.Exception.Message))" }
                                }
                            }
                            $act = 'Resume-BitLocker'
                            try { Resume-BitLocker -MountPoint $mp -ErrorAction Stop | Out-Null }
                            catch { $act = 'manage-bde -protectors -enable'; & manage-bde -protectors -enable $mp 2>&1 | Out-Null }
                            Start-Sleep -Milliseconds 500
                            $bl2 = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                            if ([string]$bl2.ProtectionStatus -eq 'On') { & $add 'Encryption' $act 'FIXED' "$mp protection resumed -> On; $($bl2.VolumeStatus)$tpmProtTxt; $fveNote"; if ($isOsVol) { $osEncOrPlanned = $true } }
                            elseif ($vsv -match '(?i)FullyEncrypted')     { & $add 'Encryption' $act 'FAIL' "$mp resume attempted but protection still $($bl2.ProtectionStatus)" }
                            else { & $add 'Encryption' $act 'SKIP' "$mp protection $($bl2.ProtectionStatus); volume $($bl2.VolumeStatus) - not a resumable state; route to MECM/desk-side" }
                        }
                    }
                } else {
                    $out = (& manage-bde -status $sys 2>&1 | Out-String)
                    if ($out -match '(?i)Protection\s+Status:\s*Protection\s+On') { & $add 'Encryption' 'none' 'NOCHANGE' "$sys protection already On (manage-bde; system-drive only - Get-BitLockerVolume unavailable, other fixed volumes not checked)" }
                    elseif ($out -match '(?i)Fully\s+Encrypted') {
                        & manage-bde -protectors -enable $sys 2>&1 | Out-Null
                        Start-Sleep -Milliseconds 500
                        $out2 = (& manage-bde -status $sys 2>&1 | Out-String)
                        if ($out2 -match '(?i)Protection\s+Status:\s*Protection\s+On') { & $add 'Encryption' 'manage-bde -protectors -enable' 'FIXED' "$sys protectors enabled -> On (manage-bde; system-drive only)" }
                        else { & $add 'Encryption' 'manage-bde -protectors -enable' 'FAIL' "$sys enable attempted but still Off (manage-bde)" }
                    } else { & $add 'Encryption' 'none' 'SKIP' "$sys not FullyEncrypted - route to MECM/desk-side (manage-bde; system-drive only - Get-BitLockerVolume unavailable)" }
                }
            } catch { & $add 'Encryption' 'error' 'FAIL' $_.Exception.Message }
        }

        # 2. AntiMalware - heal Defender honouring Get-MpComputerStatus.AMRunningMode.
        #    Always heal WinDefend/Sense services. Force RTP on (Set-MpPreference) ONLY when
        #    AMRunningMode is Active - NEVER in Passive / EDR Block Mode, where MDE Sense is
        #    primary and RTP off is correct (forcing it would fight the MDE config).
        #    Update-MpSignature when the signature age exceeds SigMaxAgeHours. A Passive/EDR
        #    box with Sense onboarded + fresh signatures reports NOCHANGE (protected via MDE).
        if ($Pillars -contains 'AntiMalware') {
            try {
                $changed = New-Object System.Collections.ArrayList
                $notes   = New-Object System.Collections.ArrayList
                foreach ($svcName in @('WinDefend','Sense')) {
                    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if (-not $svc) {
                        if ($svcName -eq 'Sense') { [void]$notes.Add('Sense (MDE) not installed') } else { [void]$notes.Add('WinDefend not installed') }
                        continue
                    }
                    if ([string]$svc.StartType -ne 'Automatic') { try { Set-Service -Name $svcName -StartupType Automatic -ErrorAction Stop; [void]$changed.Add("$svcName->Automatic") } catch {} }
                    if ($svc.Status -ne 'Running') { try { Start-Service -Name $svcName -ErrorAction Stop; [void]$changed.Add("$svcName started") } catch { [void]$notes.Add("$svcName start failed") } }
                }
                $failDet = ''
                if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                    $mp     = Get-MpComputerStatus -ErrorAction Stop
                    $mode   = [string]$mp.AMRunningMode
                    $amProd = [string]$mp.AMProductVersion; $amEng = [string]$mp.AMEngineVersion
                    $lastUpd = $null; try { $lastUpd = $mp.AntivirusSignatureLastUpdated } catch { $lastUpd = $null }
                    $ageHours = $null
                    if ($lastUpd -is [datetime]) { $ageHours = [math]::Round(((Get-Date) - $lastUpd).TotalHours, 1) }
                    elseif ($lastUpd -and ($lastUpd -as [datetime])) { $ageHours = [math]::Round(((Get-Date) - ([datetime]$lastUpd)).TotalHours, 1) }
                    else { try { $ageHours = [int]$mp.AntivirusSignatureAge * 24 } catch { $ageHours = $null } }
                    $isPassive = ($mode -match '(?i)passive|edr')
                    $isActive  = ($mode) -and (-not $isPassive)
                    # Force RTP ONLY when Active (never fight the MDE passive/EDR config).
                    if ($isActive -and (-not $mp.RealTimeProtectionEnabled)) {
                        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; [void]$changed.Add('RTP enabled') }
                        catch { $failDet += "RTP enable failed: $($_.Exception.Message); " }
                    }
                    # Update stale signatures (age budget in HOURS) regardless of running mode.
                    # Defender-ScanFix v2.1 port: the default channel needs wuauserv + BITS (a
                    # stopped update service is a common silent cause of "completed with errors"),
                    # then a SOURCE CHAIN - default (WSUS/ConfigMgr on this network) -> Microsoft
                    # Update direct -> the MMPC HTTP source. Success = age drops under budget.
                    if (($null -ne $ageHours) -and ($ageHours -gt $SigMaxAgeHours)) {
                        foreach ($usvc in @('wuauserv', 'BITS')) {
                            $u = Get-Service -Name $usvc -ErrorAction SilentlyContinue
                            if ($u -and $u.Status -ne 'Running') { try { Start-Service -Name $usvc -ErrorAction Stop } catch {} }
                        }
                        $sigFixed = $false; $sigTried = New-Object System.Collections.ArrayList
                        foreach ($src in @('(default)', 'MicrosoftUpdateServer', 'MMPCUpdateServer')) {
                            try {
                                if ($src -eq '(default)') { Update-MpSignature -ErrorAction Stop }
                                else { Update-MpSignature -UpdateSource $src -ErrorAction Stop }
                            } catch {}
                            Start-Sleep -Seconds 3
                            $mpS = Get-MpComputerStatus -ErrorAction SilentlyContinue
                            $luS = $null; if ($mpS) { try { $luS = $mpS.AntivirusSignatureLastUpdated } catch { $luS = $null } }
                            if ($luS -and ($luS -as [datetime])) {
                                $ageHours = [math]::Round(((Get-Date) - ([datetime]$luS)).TotalHours, 1)
                                if ($ageHours -le $SigMaxAgeHours) { $sigFixed = $true; [void]$changed.Add("signatures updated via $src"); break }
                            }
                            [void]$sigTried.Add($src)
                        }
                        if (-not $sigFixed) {
                            # The cmdlet's error is a useless generic - pull the real failure code
                            # from Defender event 2001 (definition update failure) for the report.
                            $sigDiag = ''
                            try {
                                $evS = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 2001 } -MaxEvents 1 -ErrorAction Stop
                                if ($evS -and ("$($evS.Message)" -match '(0x[0-9A-Fa-f]{8})')) { $sigDiag = " (last update error $($Matches[1]))" }
                            } catch {}
                            $failDet += "sig update failed via all sources [$($sigTried -join ', ')]$sigDiag; "
                        }
                    }
                    Start-Sleep -Milliseconds 300
                    $mp2 = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    $modeNow = if ($mp2) { [string]$mp2.AMRunningMode } else { $mode }
                    $rtpNow  = if ($mp2) { [bool]$mp2.RealTimeProtectionEnabled } else { [bool]$mp.RealTimeProtectionEnabled }
                    # Re-evaluate the running mode from the RE-READ, not the pre-heal snapshot:
                    # a box that started Disabled (empty AMRunningMode) can transition to Active
                    # once WinDefend is started, and Get-MpComputerStatus taken right after the
                    # start can lag behind that transition. If it now reads Active with RTP still
                    # off, force RTP HERE and re-verify. Never force RTP in Passive / EDR Block
                    # Mode (MDE Sense is primary there - RTP off is correct).
                    $isPassiveNow = ($modeNow -match '(?i)passive|edr')
                    $isActiveNow  = ($modeNow) -and (-not $isPassiveNow)
                    if ($isActiveNow -and (-not $rtpNow)) {
                        try {
                            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                            [void]$changed.Add('RTP enabled (post-heal Active)')
                            Start-Sleep -Milliseconds 300
                            $mp3 = Get-MpComputerStatus -ErrorAction SilentlyContinue
                            if ($mp3) { $mp2 = $mp3; $modeNow = [string]$mp3.AMRunningMode; $rtpNow = [bool]$mp3.RealTimeProtectionEnabled }
                            $isPassiveNow = ($modeNow -match '(?i)passive|edr')
                            $isActiveNow  = ($modeNow) -and (-not $isPassiveNow)
                        } catch { $failDet += "RTP enable failed: $($_.Exception.Message); " }
                    }
                    $lastNow = $lastUpd; if ($mp2) { try { $lastNow = $mp2.AntivirusSignatureLastUpdated } catch {} }
                    $ageNow  = $ageHours
                    if ($mp2) {
                        if ($lastNow -is [datetime]) { $ageNow = [math]::Round(((Get-Date) - $lastNow).TotalHours, 1) }
                        elseif ($lastNow -and ($lastNow -as [datetime])) { $ageNow = [math]::Round(((Get-Date) - ([datetime]$lastNow)).TotalHours, 1) }
                    }
                    $ageTxt  = if ($null -ne $ageNow) { "${ageNow}h" } else { 'unknown' }
                    $lastTxt = if ($lastNow) { [string]$lastNow } else { 'unknown' }
                    $modeTxt = if ($modeNow) { $modeNow } else { 'null (Disabled/Not Running)' }
                    $stateTxt = "RunningMode $modeTxt; RTP $rtpNow; prod $amProd; engine $amEng; sig last $lastTxt (age $ageTxt, budget ${SigMaxAgeHours}h)"
                    $noteTxt  = if ($notes.Count -gt 0) { '; ' + ($notes -join '; ') } else { '' }
                    # A box that ENDS Active-but-RTP-off is NOT protected - never report FIXED;
                    # reflect the true state (FAIL). RTP-on Active or a compliant Passive/EDR box
                    # can still report FIXED / NOCHANGE below.
                    $rtpStillOff = ($isActiveNow -and (-not $rtpNow))
                    if ($failDet -or $rtpStillOff) {
                        $why = $failDet.TrimEnd('; ')
                        if ($rtpStillOff) { if ($why) { $why += '; ' }; $why += 'Active but RTP still off after heal' }
                        & $add 'AntiMalware' 'heal' 'FAIL' ($why + '; ' + $stateTxt + $noteTxt)
                    }
                    elseif ($changed.Count -gt 0) { & $add 'AntiMalware' 'heal' 'FIXED' (($changed -join '; ') + '; ' + $stateTxt + $noteTxt) }
                    else                          { & $add 'AntiMalware' 'none' 'NOCHANGE' ($(if ($isPassiveNow) { 'already protected via MDE (Passive/EDR - RTP not forced); ' } else { 'already protected; ' }) + $stateTxt + $noteTxt) }
                } else {
                    if ($changed.Count -gt 0) { & $add 'AntiMalware' 'heal' 'FIXED' (($changed -join '; ') + '; Get-MpComputerStatus unavailable') }
                    else { & $add 'AntiMalware' 'none' 'SKIP' ('Get-MpComputerStatus unavailable (non-Defender AV?)' + $(if ($notes.Count) { '; ' + ($notes -join '; ') } else { '' })) }
                }
            } catch { & $add 'AntiMalware' 'error' 'FAIL' $_.Exception.Message }
        }

        # 2b. MdeOnboard (Defender-ScanFix v2.1 port) - runs with the AntiMalware pillar.
        #     TASKORD scores the MDE Org ID; a healthy Defender with the WRONG/missing OrgId
        #     still fails Anti-Malware. POLICY-DRIVEN escalation ladder (this fleet is GPO
        #     managed): (0) diagnose gateway 443 reachability, (1) fix deps - DiagTrack
        #     Disabled->Automatic+start (Sense depends on it), Sense Disabled->Automatic,
        #     (2) onboarding blob present -> restart Sense, (3) blob missing -> gpupdate
        #     /target:computer /force + re-check, (4) STILL missing -> write the embedded
        #     tenant blob (bridge; the GPO asserts the SAME value) + restart Sense. Emits a
        #     row ONLY when the OrgId is missing/mismatched; a matching OrgId is silent.
        if (($Pillars -contains 'AntiMalware') -and $MdeOrgId) {
            try {
                $statusKey = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
                $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
                $orgId = ''
                try { $pAtp = Get-ItemProperty $statusKey -ErrorAction Stop; if ($pAtp.OrgId) { $orgId = [string]$pAtp.OrgId } } catch {}
                if ($orgId.Trim().ToUpper() -ne $MdeOrgId.Trim().ToUpper()) {
                    # Blob sanity: refuse to ever write a blob whose embedded orgId is not the target.
                    $blobUsable = $false
                    try {
                        $bo = "$MdeBlob" | ConvertFrom-Json; $bb = $bo.body | ConvertFrom-Json
                        $blobUsable = ("$($bb.orgId)".Trim().ToUpper() -eq $MdeOrgId.Trim().ToUpper())
                    } catch { $blobUsable = $false }
                    # Advisory (non-blocking): the embedded blob is signed; if that leaf cert has
                    # expired, Sense will reject the local blob and onboarding heal will not take.
                    # Surface it and continue - re-capture needs a live domain, not done here.
                    try {
                        $bCert = "$MdeBlob" | ConvertFrom-Json
                        if ($bCert.cert) {
                            $leafC = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String([string]$bCert.cert))
                            if ($leafC.NotAfter -lt (Get-Date)) {
                                & $add 'MdeOnboard' 'advisory' 'IN PROGRESS' "MDE onboarding blob signing cert EXPIRED $($leafC.NotAfter.ToString('yyyy-MM-dd')) - re-capture from a healthy host; onboarding heal will not take until then"
                            }
                        }
                    } catch {}
                    # Gateway reachability (blob geoLocationUrl, else the USGov default) - the WHY
                    # for a fail: nothing local can complete onboarding if 443 is blocked.
                    $gwHost = 'winatp-gw-usgv.microsoft.com'
                    try { if ($bb -and $bb.geoLocationUrl) { $gwHost = ([uri]$bb.geoLocationUrl).Host } } catch {}
                    $gwOpen = $false
                    $tcpG = New-Object System.Net.Sockets.TcpClient
                    try {
                        $iarG = $tcpG.BeginConnect($gwHost, 443, $null, $null)
                        if ($iarG.AsyncWaitHandle.WaitOne(5000, $false) -and $tcpG.Connected) { $tcpG.EndConnect($iarG); $gwOpen = $true }
                    } catch {} finally { try { $tcpG.Close() } catch {} }

                    $blobPresent = $false
                    try { $ppAtp = Get-ItemProperty $policyKey -ErrorAction Stop; $blobPresent = -not [string]::IsNullOrWhiteSpace([string]$ppAtp.OnboardingInfo) } catch {}

                    # 1. Dependencies: DiagTrack (Sense depends on it) + Sense start types.
                    $depNotes = New-Object System.Collections.ArrayList
                    foreach ($dep in @('DiagTrack', 'Sense')) {
                        $dsvc = Get-Service -Name $dep -ErrorAction SilentlyContinue
                        if (-not $dsvc) { [void]$depNotes.Add("$dep MISSING"); continue }
                        if ([string]$dsvc.StartType -eq 'Disabled') { try { Set-Service -Name $dep -StartupType Automatic -ErrorAction Stop; [void]$depNotes.Add("$dep enabled (was Disabled)") } catch {} }
                        if ($dep -eq 'DiagTrack' -and $dsvc.Status -ne 'Running') { try { Start-Service -Name $dep -ErrorAction Stop; [void]$depNotes.Add('DiagTrack started') } catch {} }
                    }
                    # 2/3/4. Blob present -> bounce Sense; else gpupdate -> re-check -> write blob.
                    $usedLocalBlob = $false; $gpNote = 'gpupdate skipped (blob already present)'
                    if ($blobPresent) {
                        Restart-Service -Name Sense -Force -ErrorAction SilentlyContinue
                    } else {
                        try {
                            $gpProc = Start-Process -FilePath "$env:windir\System32\gpupdate.exe" -ArgumentList '/target:computer /force' -Wait -PassThru -ErrorAction Stop
                            $gpNote = "gpupdate exit $($gpProc.ExitCode)"
                        } catch { $gpNote = "gpupdate failed: $($_.Exception.Message)" }
                        try { $pp2 = Get-ItemProperty $policyKey -ErrorAction Stop; $blobPresent = -not [string]::IsNullOrWhiteSpace([string]$pp2.OnboardingInfo) } catch { $blobPresent = $false }
                        if (-not $blobPresent -and $blobUsable) {
                            if (-not (Test-Path $policyKey)) { New-Item -Path $policyKey -Force -ErrorAction Stop | Out-Null }
                            Set-ItemProperty -Path $policyKey -Name 'OnboardingInfo' -Value ([string]$MdeBlob) -Type String -Force -ErrorAction Stop
                            $usedLocalBlob = $true; $blobPresent = $true
                        }
                        if ($blobPresent) { Restart-Service -Name Sense -Force -ErrorAction SilentlyContinue }
                    }
                    Start-Sleep -Seconds 15
                    $orgNow = ''
                    try { $p2Atp = Get-ItemProperty $statusKey -ErrorAction Stop; if ($p2Atp.OrgId) { $orgNow = [string]$p2Atp.OrgId } } catch {}
                    $depTxt = if ($depNotes.Count -gt 0) { ' [deps: ' + ($depNotes -join ', ') + ']' } else { '' }
                    $wasTxt = if ($orgId) { "OrgId was '$orgId' (mismatch)" } else { 'OrgId was missing' }
                    if ($orgNow.Trim().ToUpper() -eq $MdeOrgId.Trim().ToUpper()) {
                        & $add 'MdeOnboard' 'onboard' 'FIXED' ("$wasTxt - MDE onboarded, OrgId now matches" + $(if ($usedLocalBlob) { ' (via local blob; the GPO asserts the same value)' } else { " ($gpNote)" }) + $depTxt)
                    } elseif (-not $gwOpen) {
                        & $add 'MdeOnboard' 'onboard' 'FAIL' ("$wasTxt and gateway $gwHost 443 is UNREACHABLE - firewall/proxy fix required; no local action can complete onboarding$depTxt")
                    } elseif ($blobPresent) {
                        & $add 'MdeOnboard' 'onboard' 'IN PROGRESS' ("$wasTxt - onboarding pending: blob in place ($gpNote$(if ($usedLocalBlob) { '; embedded tenant blob written' } else { '' })), Sense restarted, OrgId not yet populated; re-scan in a few minutes$depTxt")
                    } else {
                        & $add 'MdeOnboard' 'onboard' 'FAIL' ("$wasTxt - POLICY GAP: no ATP onboarding policy after $gpNote - check GPO scoping$depTxt")
                    }
                }
            } catch { & $add 'MdeOnboard' 'onboard' 'FAIL' ("MDE onboarding heal error: " + $_.Exception.Message) }
        }

        # 3. Patches - kick the MECM Software Updates scan (113) then eval (108).
        if ($Pillars -contains 'Patches') {
            try {
                $ok = $true; $err = ''
                foreach ($sched in @('{00000000-0000-0000-0000-000000000113}','{00000000-0000-0000-0000-000000000108}')) {
                    try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'SMS_Client' -MethodName 'TriggerSchedule' -Arguments @{ sScheduleID = $sched } -ErrorAction Stop | Out-Null }
                    catch { $ok = $false; $err = $_.Exception.Message; break }
                }
                if ($ok) { & $add 'Patches' 'trigger' 'KICKED' 'triggered SUM scan (113) + eval (108); installs run async, Tanium updates after its next scan' }
                else     { & $add 'Patches' 'trigger' 'FAIL' "CCM trigger failed (MECM client namespace root\ccm unreachable?): $err" }
            } catch { & $add 'Patches' 'error' 'FAIL' $_.Exception.Message }
        }

        # P. PkiRoots - install the DoD trust bundle ADDITIVELY. The admin side already
        #    read the folder and handed us base64 certs grouped by store as JSON. For each
        #    store open X509Store(store, LocalMachine) ReadWrite and add ONLY certs whose
        #    thumbprint is not already present (NEVER remove anything), then close.
        if ($Pillars -contains 'PkiRoots') {
            try {
                $bundle = $null
                if ($BundleJson) { try { $bundle = $BundleJson | ConvertFrom-Json } catch { $bundle = $null } }
                if ($AddCertsSrc) { try { . ([scriptblock]::Create($AddCertsSrc)) } catch {} }
                if (-not $bundle) {
                    & $add 'PkiRoots' 'none' 'FAIL' 'no cert bundle delivered to the worker - nothing to install'
                } elseif (-not (Get-Command Add-C2cBundleToStores -ErrorAction SilentlyContinue)) {
                    & $add 'PkiRoots' 'none' 'FAIL' 'cert-store installer helper unavailable on target'
                } else {
                    $ar = Add-C2cBundleToStores -Bundle $bundle
                    $storeTxt = (@($ar.PerStore) -join ', ')
                    # Classify via the shared helper (dot-sourced from $AddCertsSrc above) -
                    # the exact token the label map keys on. Inline fallback if unavailable.
                    $tok = if (Get-Command Get-C2cPkiRootsResultToken -ErrorAction SilentlyContinue) { Get-C2cPkiRootsResultToken $ar }
                           elseif ([string]$ar.FailDetail) { 'FAIL' } elseif (@($ar.NotVerified).Count -gt 0) { 'NOT VERIFIED' } elseif ([int]$ar.Added -gt 0) { 'FIXED' } else { 'NOCHANGE' }
                    if ($tok -eq 'FAIL') {
                        & $add 'PkiRoots' 'addstore' 'FAIL' ("added $($ar.Added) of $($ar.Total); errors: " + ([string]$ar.FailDetail).TrimEnd('; ') + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    } elseif ($tok -eq 'NOT VERIFIED') {
                        $nv = @($ar.NotVerified)
                        & $add 'PkiRoots' 'addstore' 'NOT VERIFIED' ("added $($ar.Added) of $($ar.Total) but $($nv.Count) absent on re-read - a reconciler/policy may be stripping in-session (thumbs: $($nv -join ', '))" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    } elseif ($tok -eq 'FIXED') {
                        & $add 'PkiRoots' 'addstore' 'FIXED' ("added $($ar.Added) of $($ar.Total) across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    } else {
                        & $add 'PkiRoots' 'none' 'NOCHANGE' ("all $($ar.Total) already present across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    }
                }
            } catch { & $add 'PkiRoots' 'error' 'FAIL' $_.Exception.Message }

            # Pb. PkiExpired (PKI-Fix-ScanFix v1.9 port) - prune EXPIRED retired DoD
            #     intermediates. SAFETY MODEL: expired does NOT mean deletable (roots,
            #     timestamping and machine-identity certs are often expired-but-required),
            #     so deletion is gated on an ALLOWLIST: subject must match the retired DoD
            #     intermediate pattern AND the store is CA ONLY (never My/Root/
            #     TrustedPublisher/Disallowed). The four LegacyIntermediates thumbprints
            #     are EXCLUDED - fix-pki intentionally pushes those despite expiry (guard
            #     copy of $script:C2cLegacyIntermediates; keep the two lists in sync).
            #     Emits a row only when something matched; a clean CA store is silent.
            #     $DoPrune gates this companion INDEPENDENTLY (opt-in box on the PkiRoots card;
            #     default OFF). Direct fix-block callers (unit tests) pass $false and so never
            #     touch live machine state. The core additive bundle install above ALWAYS runs.
            if ($DoPrune) {
            try {
                $allowSubject = '^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD'
                $legacyKeep = @(
                    '53FDE0F40638BD1A68A68D1E91089009B33BAE5E'  # DOD EMAIL CA-59
                    '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7'  # DOD ID CA-59
                    '5DFFDAB658915FA6B0DB4E0BCF70D5BB1B8425FC'  # DOD SW CA-60
                    '5F555AB8A87DD146314171621245CF720BF53B8A'  # DOD SW CA-61
                )
                $nowPk = Get-Date
                $prunable = @(Get-ChildItem 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue | Where-Object {
                    $_.NotAfter -lt $nowPk -and $_.Subject -match $allowSubject -and
                    ($legacyKeep -notcontains ((([string]$_.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpper()))
                })
                if ($prunable.Count -gt 0) {
                    $delOk = 0; $delFail = ''
                    foreach ($pc in $prunable) {
                        try { Remove-Item -Path $pc.PSPath -Force -ErrorAction Stop; $delOk++ }
                        catch { $delFail += "$($pc.Thumbprint): $($_.Exception.Message); " }
                    }
                    if ($delFail) { & $add 'PkiExpired' 'prune' 'FAIL' ("removed $delOk of $($prunable.Count) expired retired DoD intermediate(s) from the CA store; errors: " + $delFail.TrimEnd('; ')) }
                    else { & $add 'PkiExpired' 'prune' 'FIXED' ("removed $delOk expired retired DoD intermediate(s) from the CA store (allowlisted DOD EMAIL/ID/SW/DERILITY subjects only; the four legacy-keep intermediates untouched)") }
                }
            } catch { & $add 'PkiExpired' 'prune' 'FAIL' ("expired-intermediate prune error: " + $_.Exception.Message) }
            }

            # Pc. PkiRdp (PKI-Fix-ScanFix v1.9 port) - repair a BROKEN RDP-tcp listener
            #     certificate (self-signed / expired / missing). A healthy CA-issued
            #     listener is NEVER touched (silent). Reordered SAFE for auto-run: the
            #     replacement cert (newest valid My-store cert matching this computer with
            #     the Server Authentication EKU 1.3.6.1.5.5.7.3.1) is located FIRST - with
            #     no candidate the listener is left alone (SKIP), nothing is cleared.
            #     $DoRdp gates this companion INDEPENDENTLY (opt-in box on the PkiRoots card;
            #     default OFF). A healthy CA-issued listener is never touched even when armed.
            if ($DoRdp) {
            try {
                $tsgs = Get-CimInstance -Namespace 'root/cimv2/terminalservices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
                $rdpHash = (([string]$tsgs.SSLCertificateSHA1Hash) -replace '[^0-9A-Fa-f]', '').ToUpper()
                $nowRd = Get-Date
                $lcert = $null
                if ($rdpHash -and $rdpHash -ne ('0' * 40)) {
                    foreach ($stN in @('My', 'Remote Desktop')) {
                        $lcert = Get-ChildItem "Cert:\LocalMachine\$stN" -ErrorAction SilentlyContinue |
                                 Where-Object { ((([string]$_.Thumbprint) -replace '[^0-9A-Fa-f]', '').ToUpper()) -eq $rdpHash } |
                                 Select-Object -First 1
                        if ($lcert) { break }
                    }
                }
                $rdpState = if (-not $lcert) { 'missing' } elseif ($lcert.NotAfter -lt $nowRd) { 'expired' } elseif ($lcert.Subject -eq $lcert.Issuer) { 'self-signed' } else { 'healthy' }
                if ($rdpState -ne 'healthy') {
                    $cand = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
                        (@($_.DnsNameList | ForEach-Object { [string]$_.Unicode } | Where-Object { $_ -eq $env:COMPUTERNAME -or (($_ -split '\.')[0] -eq $env:COMPUTERNAME) }).Count -gt 0) -and $_.NotAfter -gt $nowRd -and $_.HasPrivateKey -and
                        @($_.EnhancedKeyUsageList | Where-Object { [string]$_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0
                    } | Sort-Object NotAfter -Descending | Select-Object -First 1
                    if (-not $cand) {
                        & $add 'PkiRdp' 'none' 'SKIP' "RDP listener cert is $rdpState but no valid CA-issued My-store cert (Server Auth EKU) matches this host - left untouched"
                    } else {
                        # Bind FIRST; only on a successful bind do the destructive clears run. On a bind
                        # failure the old cert/listener are left intact (FAIL) - no dead-listener window.
                        try {
                            Set-CimInstance -InputObject $tsgs -Property @{ SSLCertificateSHA1Hash = [string]$cand.Thumbprint } -ErrorAction Stop | Out-Null
                            Get-ChildItem 'Cert:\LocalMachine\Remote Desktop' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -Name 'SelfSignedCertStore' -Value '' -Force -ErrorAction SilentlyContinue
                            & $add 'PkiRdp' 'rebind' 'FIXED' "RDP listener was $rdpState - bound CA-issued cert $($cand.Thumbprint) (expires $($cand.NotAfter.ToShortDateString()))"
                        } catch {
                            & $add 'PkiRdp' 'rebind' 'FAIL' "RDP listener was $rdpState - bind to CA-issued cert $($cand.Thumbprint) FAILED, old cert/listener left intact: $($_.Exception.Message)"
                        }
                    }
                }
            } catch { & $add 'PkiRdp' 'rebind' 'FAIL' ("RDP listener check/repair error: " + $_.Exception.Message) }
            }
        }

        # J. Java (Java-Cleanup-ScanFix v1.1 port; opt-in fix-java action - never in run-all).
        #    C2C/vuln scanners flag hosts on stale Java registry keys even after the product
        #    is gone, and on genuinely old installs. Three evidence sources, then remove
        #    anything OLDER than 1.8.0_491: (1) installed products - Uninstall registry
        #    (native + WOW6432Node), Oracle/Sun PUBLISHER ONLY (OpenJDK/Temurin/Corretto are
        #    NEVER touched) -> msiexec /x {GUID} /qn /norestart; (2) JavaSoft registry residue
        #    (+ CurrentVersion repair, empty product keys dropped); (3) Program Files\Java
        #    folders. UNKNOWN versions are never auto-removed. No reboots forced (3010 =
        #    reboot pending). One 'Java' row per host with the rollup.
        if ($Pillars -contains 'Java') {
            try {
                # Dot-source the SHARED, vendor-gated engine ($JavaSrc = Get-JanetJavaFixSrc)
                # into this bare worker runspace, then delegate. Behavior is unchanged from the
                # former inline block: the vendor gate ('(?i)oracle|sun microsystems') and the
                # strict-GUID msiexec guard ('^\{[0-9A-Fa-f-]+\}$') live in Invoke-JanetJavaRemediation.
                if ($JavaSrc) { try { . ([scriptblock]::Create($JavaSrc)) } catch {} }
                if (-not (Get-Command Invoke-JanetJavaRemediation -ErrorAction SilentlyContinue)) {
                    & $add 'Java' 'none' 'FAIL' 'Java remediation engine unavailable on target - nothing removed (fail-closed)'
                } else {
                    foreach ($row in @(Invoke-JanetJavaRemediation -MinUpdate 491)) { & $add $row.Name $row.Action $row.Result $row.Detail }
                }
            } catch { & $add 'Java' 'error' 'FAIL' $_.Exception.Message }
        }

        # L. Lockscreen - remediate the Windows 11 CACHED quarantine lock screen / desktop
        #    wallpaper: force the HKLM Personalization policy to a DEFAULT image so Windows
        #    stops using the cached quarantine one. Writes a value ONLY where none is already
        #    set (never overwrites an operator/GPO value). Uses built-in cmdlets only (pool-safe).
        if ($Pillars -contains 'Lockscreen') {
            try {
                $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
                if (-not (Test-Path -LiteralPath $polKey)) { New-Item -Path $polKey -Force | Out-Null }
                $cur = $null; try { $cur = Get-ItemProperty -LiteralPath $polKey -ErrorAction SilentlyContinue } catch {}
                $hasVal = { param($n) $cur -and $cur.PSObject.Properties[$n] -and -not [string]::IsNullOrWhiteSpace([string]$cur.$n) }
                # Resolve default images ON THIS target (the paths must exist here). Prefer the
                # unquarantine package's LockScreen.jpg, else the built-in Windows defaults.
                $lockImg = $null
                foreach ($c in @("$env:ProgramData\Microsoft\User Account Pictures\LockScreen.jpg", "$env:SystemRoot\Web\Screen\img100.jpg")) { if (Test-Path -LiteralPath $c) { $lockImg = $c; break } }
                if (-not $lockImg) { $g = @(Get-ChildItem -LiteralPath "$env:SystemRoot\Web\Screen" -Filter 'img*.jpg' -ErrorAction SilentlyContinue | Sort-Object Name); if ($g.Count -gt 0) { $lockImg = $g[0].FullName } }
                $deskImg = $null
                foreach ($c in @("$env:SystemRoot\Web\Wallpaper\Windows\img0.jpg")) { if (Test-Path -LiteralPath $c) { $deskImg = $c; break } }
                if (-not $deskImg) { $g = @(Get-ChildItem -LiteralPath "$env:SystemRoot\Web\Wallpaper\Windows" -Filter 'img*.jpg' -ErrorAction SilentlyContinue | Sort-Object Name); if ($g.Count -gt 0) { $deskImg = $g[0].FullName } }

                $set = New-Object System.Collections.ArrayList
                $skip = New-Object System.Collections.ArrayList
                # Lock screen (the value the operator named).
                if (& $hasVal 'LockScreenImage')  { [void]$skip.Add("lock already set ($([string]$cur.LockScreenImage))") }
                elseif (-not $lockImg)            { [void]$skip.Add('no default lock image on target') }
                else { New-ItemProperty -LiteralPath $polKey -Name 'LockScreenImage' -Value $lockImg -PropertyType String -Force | Out-Null; [void]$set.Add("lock -> $lockImg") }
                # Desktop wallpaper (Personalization CSP-style DesktopImage* values).
                if (& $hasVal 'DesktopImagePath') { [void]$skip.Add("desktop already set ($([string]$cur.DesktopImagePath))") }
                elseif (-not $deskImg)            { [void]$skip.Add('no default desktop image on target') }
                else {
                    New-ItemProperty -LiteralPath $polKey -Name 'DesktopImagePath'   -Value $deskImg -PropertyType String -Force | Out-Null
                    New-ItemProperty -LiteralPath $polKey -Name 'DesktopImageUrl'    -Value $deskImg -PropertyType String -Force | Out-Null
                    New-ItemProperty -LiteralPath $polKey -Name 'DesktopImageStatus' -Value 1        -PropertyType DWord  -Force | Out-Null
                    [void]$set.Add("desktop -> $deskImg")
                }
                $skipTxt = if ($skip.Count -gt 0) { " | skipped: $($skip -join '; ')" } else { '' }
                if ($set.Count -gt 0) {
                    & $add 'Lockscreen' 'setpolicy' 'FIXED' ("set $($set -join '; ')$skipTxt")
                } elseif (@($skip | Where-Object { $_ -match 'already set' }).Count -gt 0) {
                    & $add 'Lockscreen' 'none' 'NOCHANGE' ("already set - $($skip -join '; ')")
                } else {
                    & $add 'Lockscreen' 'none' 'SKIP' ($skip -join '; ')
                }
            } catch { & $add 'Lockscreen' 'error' 'FAIL' $_.Exception.Message }
        }

        return @{ RemoteName = $env:COMPUTERNAME; Pillars = @($results) }
    }

    $offlineRow = $null
    try {
        # Pass the pillar set as a '|'-delimited string (all-scalar ArgumentList) so it
        # crosses the WinRM boundary intact; the remote block splits it back to an array.
        $fix = Invoke-Command -Session $sess -ScriptBlock $fixSb -ArgumentList ($Pillars -join '|'), $DoEnable, $TaniumService, $TaniumInstalledSrc, $BundleJson, $AddCertsSrc, $SigMaxAgeHours, $MdeOrgId, $MdeBlob, $JavaSrc, $DoPrune, $DoRdp -ErrorAction Stop

        # ---- Offline definition rung (Defender-ScanFix v2.1 LAST rung) --------------
        # Only when a validated Microsoft-signed mpam-fe.exe is staged admin-side AND the
        # AntiMalware fixer just failed EVERY online source on this host. Uses THIS still-
        # open session: copy the installer to the target, run it locally (no network pull
        # from the target), re-read the signature age, delete the copy. Result appended as
        # its own row; its own try/catch so a push error can never FAIL the whole host.
        if ($OfflineDefPath -and (@($fix.Pillars | Where-Object { $_.Name -eq 'AntiMalware' -and $_.Result -eq 'FAIL' -and "$($_.Detail)" -match 'sig update failed via all sources' }).Count -gt 0)) {
            try {
                $remotePkg = 'C:\Windows\Temp\mpam-fe.exe'
                Copy-Item -Path $OfflineDefPath -Destination $remotePkg -ToSession $sess -Force -ErrorAction Stop
                $offR = Invoke-Command -Session $sess -ArgumentList $remotePkg, $SigMaxAgeHours, $OfflineDefSha256 -ErrorAction Stop -ScriptBlock {
                    param($Pkg, $MaxAgeHours, $ExpectHash)
                    $r = @{ Ok = $false; AgeH = $null; Note = '' }
                    try {
                        # TOCTOU gate: the package was Authenticode/size/identity-validated admin-side and
                        # its SHA256 pinned THEN. Re-hash the copy that actually landed on THIS target and
                        # refuse to execute if it drifted from the pinned value (validate->push tamper).
                        $actual = (Get-FileHash -LiteralPath $Pkg -Algorithm SHA256).Hash
                        if ((-not $ExpectHash) -or ($actual -ne $ExpectHash)) {
                            $r.Note = "package SHA256 unverified (no pin) or mismatch (validate->push tamper) - NOT executed"
                            Remove-Item -LiteralPath $Pkg -Force -ErrorAction SilentlyContinue
                            return [pscustomobject]$r
                        }
                        $p = Start-Process -FilePath $Pkg -Wait -PassThru -ErrorAction Stop
                        $r.Note = "installer exit $($p.ExitCode)"
                        Start-Sleep -Seconds 15
                        $mpO = Get-MpComputerStatus -ErrorAction SilentlyContinue
                        $luO = $null; if ($mpO) { try { $luO = $mpO.AntivirusSignatureLastUpdated } catch { $luO = $null } }
                        if ($luO -and ($luO -as [datetime])) {
                            $r.AgeH = [math]::Round(((Get-Date) - ([datetime]$luO)).TotalHours, 1)
                            $r.Ok = ($r.AgeH -le $MaxAgeHours)
                        }
                    } catch { $r.Note = "installer threw: $($_.Exception.Message)" }
                    finally { Remove-Item -LiteralPath $Pkg -Force -ErrorAction SilentlyContinue }
                    [pscustomobject]$r
                }
                if ($offR.Ok) { $offlineRow = [pscustomobject]@{ Name = 'AntiMalware'; Action = 'offline-package'; Result = 'FIXED'; Detail = "OFFLINE definition package installed - signature age now $($offR.AgeH)h ($($offR.Note)); supersedes the online-source failure above" } }
                else { $offlineRow = [pscustomobject]@{ Name = 'AntiMalware'; Action = 'offline-package'; Result = 'FAIL'; Detail = "OFFLINE package pushed but signatures still stale ($($offR.Note))" } }
            } catch {
                $offlineRow = [pscustomobject]@{ Name = 'AntiMalware'; Action = 'offline-package'; Result = 'FAIL'; Detail = "OFFLINE package push error: $($_.Exception.Message)" }
            }
        }
    } catch {
        $r.Status = 'FAILED'; $r.Detail = "Fix: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    # NB: name this LOCAL 'pillarResults', NOT 'pillars' - the worker param is
    # [string[]]$Pillars and PowerShell variable names are case-insensitive, so a
    # local $pillars would alias the typed param and COERCE the result objects to
    # strings (dropping Name/Result/Detail). Keep them distinct.
    $pillarResults = @($fix.Pillars)
    if ($offlineRow) { $pillarResults = @($pillarResults) + @($offlineRow) }
    $r.Pillars = $pillarResults
    if ($pillarResults.Count -eq 0) { $r.Status = 'NO CHANGE'; $r.Detail = 'no enabled pillars returned a result'; return $r }

    # STARTED (BitLocker encryption kicked off) and KICKED (Patches: MECM SUM/eval cycle
    # triggered) both roll up like FIXED for the host verdict - each is a success token, not
    # a no-op. (loop18 P2: KICKED was omitted here, so a lone successful fix-patches reported
    # host Status 'NO CHANGE' / audited Skipped-0 while the per-pillar tally at ~:3012 already
    # counted it FIXED - the two now agree.) NOT VERIFIED (PkiRoots: added but absent on
    # re-read) is its own bucket - louder than a plain FIXED/NO CHANGE, but not a hard FAIL
    # (the add DID succeed, a reconciler stripped it). A real FAIL still wins; FAIL+NOT
    # VERIFIED -> PARTIAL.
    $fixed  = @($pillarResults | Where-Object { $_.Result -eq 'FIXED' -or $_.Result -eq 'STARTED' -or $_.Result -eq 'KICKED' }).Count
    $failed = @($pillarResults | Where-Object { $_.Result -eq 'FAIL'   }).Count
    $notVer = @($pillarResults | Where-Object { $_.Result -eq 'NOT VERIFIED' }).Count
    $skip   = @($pillarResults | Where-Object { $_.Result -eq 'SKIP'   }).Count
    $tot    = $pillarResults.Count
    if     ($failed -ge 1 -and $failed -eq $tot)  { $r.Status = 'FAILED' }
    elseif ($notVer -ge 1 -and $failed -eq 0)     { $r.Status = 'NOT VERIFIED' }
    elseif ($fixed -ge 1 -and $failed -eq 0)      { $r.Status = 'FIXED' }
    elseif ($failed -ge 1)                        { $r.Status = 'PARTIAL' }
    elseif ($skip -ge 1 -and $skip -eq $tot)      { $r.Status = 'SKIPPED' }   # e.g. Lockscreen with no default image on the target
    else                                          { $r.Status = 'NO CHANGE' }

    # Per-pillar DISPLAY label map: pillar-flavoured names for the raw FIXED/NOCHANGE/
    # STARTED/KICKED tokens. The rollup above uses the RAW tokens (stable); the label is
    # only what streams to the row Detail + the per-check report. SKIP/FAIL/IN PROGRESS
    # pass through unchanged (default arm).
    #
    # The label map itself lives in the shared cert/label source ($AddCertsSrc) as
    # Get-C2cPillarLabel so the worker AND the unit tests key labels off ONE definition.
    # Dot-source it here (admin-side, pool runspace) and delegate; when no AddCertsSrc was
    # supplied (older 8-arg test callers) fall back to the identical inline switch so
    # labels are never lost.
    if ($AddCertsSrc) { try { . ([scriptblock]::Create($AddCertsSrc)) } catch {} }
    $labelOf = {
        param($n, $res)
        if (Get-Command Get-C2cPillarLabel -ErrorAction SilentlyContinue) { return (Get-C2cPillarLabel $n $res) }
        switch ("$n|$res") {
            'Monitoring|FIXED'     { 'MONITORED' }
            'Monitoring|NOCHANGE'  { 'ALREADY MONITORED' }
            'Firewall|FIXED'       { 'FIREWALL ENABLED' }
            'Firewall|NOCHANGE'    { 'ALREADY ENABLED' }
            'AntiMalware|FIXED'    { 'PROTECTED' }
            'AntiMalware|NOCHANGE' { 'ALREADY PROTECTED' }
            'Patches|KICKED'       { 'PATCH CYCLE KICKED' }
            'Encryption|STARTED'   { 'ENCRYPTION STARTED' }
            'Encryption|FIXED'     { 'PROTECTION RESUMED' }
            'Encryption|NOCHANGE'  { 'ALREADY ENCRYPTED' }
            'PkiRoots|FIXED'       { 'ROOTS INSTALLED' }
            'PkiRoots|NOCHANGE'    { 'ROOTS ALREADY PRESENT' }
            'PkiExpired|FIXED'     { 'EXPIRED PRUNED' }
            'PkiRdp|FIXED'         { 'RDP CERT REBOUND' }
            'MdeOnboard|FIXED'     { 'MDE ONBOARDED' }
            'Java|FIXED'           { 'JAVA CLEANED' }
            'Java|NOCHANGE'        { 'NO OLD JAVA' }
            default                { [string]$res }
        }
    }

    $r.Detail = (@($pillarResults | ForEach-Object { "$($_.Name): $(& $labelOf $_.Name $_.Result)" }) -join '; ')
    $rptLines = foreach ($p in $pillarResults) { '[{0}] {1}: {2}' -f (& $labelOf $p.Name $p.Result), ('{0,-12}' -f [string]$p.Name), ([string]$p.Detail) }
    $r.Report = ($rptLines -join "`r`n")
    return $r
}

# --- Shared CSV -> pillar/plan derivation (import action + fix actions) ------
# ONE code path so the per-pillar fixes, the run-all plan, and the import summary
# can never DIVERGE in how the CSV maps to pillar host-sets. Pure derivation +
# read-only local parse (ConvertFrom-C2cComplianceCsv); NOTHING persists server-side.
# The presentation logging (per-pillar counts) stays in Invoke-C2cImportAction so a
# fix action re-parsing the CSV does not spam the operator with a second summary.
# Returns @{ Records; RowCount; PillarHosts; PillarOrdered; AuditPillarHosts;
#            AuditOrdered; RunAllPlan; PillarFixTargets; NonCompliantHosts }.
#   PillarHosts       : failed-pillar name  -> @(short hosts)          (display/summary)
#   AuditPillarHosts  : audit-pillar name   -> @(short hosts)
#   RunAllPlan        : @(@{ host; pillars=@(fixable failed U audit); auditPillars })
#   PillarFixTargets  : fixable-pillar name -> @(short hosts)   (failed U fixable-audit;
#                       the AUTHORITATIVE per-pillar dial set, derived FROM RunAllPlan so
#                       it is identical to what run-all would fix for that pillar).
function Get-C2cImportPlan {
    param([string[]]$Paths, [string]$Text, [scriptblock]$Send)

    $parsed = ConvertFrom-C2cComplianceCsv -Paths $Paths -Text $Text -Send $Send
    $recs   = @($parsed.Records)

    $nonCompliantHosts = @($recs | Where-Object { $_.Compliance -match '(?i)^Non-?Compliant' } | ForEach-Object { $_.Short } | Sort-Object -Unique)

    # Aggregate FAILED pillars -> host lists.
    $pillarHosts = @{}
    foreach ($rec in $recs) {
        foreach ($p in @($rec.Failed)) {
            if (-not $pillarHosts.ContainsKey($p)) { $pillarHosts[$p] = New-Object System.Collections.ArrayList }
            if (-not $pillarHosts[$p].Contains($rec.Short)) { [void]$pillarHosts[$p].Add($rec.Short) }
        }
    }
    $ordered = @()
    foreach ($n in $script:C2cPillarOrder) { if ($pillarHosts.ContainsKey($n)) { $ordered += $n } }
    foreach ($n in ($pillarHosts.Keys | Sort-Object)) { if ($ordered -notcontains $n) { $ordered += $n } }

    # Aggregate AUDIT-rule pillars (PKI Trust Roots, OS Version) -> host lists. The dashboard
    # reports these as audit rules that DON'T quarantine, but they are still real, targetable
    # findings (PkiRoots is endpoint-fixable). Kept separate from Failed so the Failed/Audit
    # scoring separation stays honest.
    $auditPillarHosts = @{}
    foreach ($rec in $recs) {
        foreach ($p in @($rec.Audit)) {
            if (-not $auditPillarHosts.ContainsKey($p)) { $auditPillarHosts[$p] = New-Object System.Collections.ArrayList }
            if (-not $auditPillarHosts[$p].Contains($rec.Short)) { [void]$auditPillarHosts[$p].Add($rec.Short) }
        }
    }
    $auditOrdered = @()
    foreach ($n in $script:C2cPillarOrder) { if ($auditPillarHosts.ContainsKey($n)) { $auditOrdered += $n } }
    foreach ($n in ($auditPillarHosts.Keys | Sort-Object)) { if ($auditOrdered -notcontains $n) { $auditOrdered += $n } }

    # Run-all plan: each host + its endpoint-fixable pillars. Includes fixable AUDIT pillars
    # (e.g. PkiRoots) tagged audit=true so run-all can PROACTIVELY remediate the audit
    # population without ever calling audit findings a quarantine cause. Hosts whose only
    # failures route elsewhere (Vuln/OSVersion/STIG) are omitted.
    $runAllPlan = New-Object System.Collections.ArrayList
    foreach ($rec in ($recs | Sort-Object { $_.Short })) {
        $fxFailed = @(@($rec.Failed) | Where-Object { $script:C2cFixablePillars -contains $_ })
        $fxAudit  = @(@($rec.Audit)  | Where-Object { $script:C2cFixablePillars -contains $_ })
        $allFx    = @(@($fxFailed + $fxAudit) | Select-Object -Unique)
        if ($allFx.Count -gt 0) {
            [void]$runAllPlan.Add(@{ host=$rec.Short; pillars=@($allFx); auditPillars=@($fxAudit) })
        }
    }

    # Per-pillar dial set derived FROM the run-all plan, so the per-pillar fix and run-all
    # can NEVER disagree about which hosts a pillar targets.
    $pillarFixTargets = @{}
    foreach ($entry in $runAllPlan) {
        foreach ($p in @($entry.pillars)) {
            if (-not $pillarFixTargets.ContainsKey($p)) { $pillarFixTargets[$p] = New-Object System.Collections.ArrayList }
            if (-not $pillarFixTargets[$p].Contains([string]$entry.host)) { [void]$pillarFixTargets[$p].Add([string]$entry.host) }
        }
    }

    return @{
        Records=@($recs); RowCount=$parsed.RowCount
        PillarHosts=$pillarHosts; PillarOrdered=@($ordered)
        AuditPillarHosts=$auditPillarHosts; AuditOrdered=@($auditOrdered)
        RunAllPlan=@($runAllPlan); PillarFixTargets=$pillarFixTargets
        NonCompliantHosts=@($nonCompliantHosts)
    }
}

# --- Action: import ----------------------------------------------------------
function Invoke-C2cImportAction {
    param([hashtable]$Params, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $csvPath = [string]$Params['csvPath']
    $csvText = [string]$Params['csvText']
    $paths = @()
    if ($csvPath) { $paths = @($csvPath -split '[\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($paths.Count -eq 0 -and [string]::IsNullOrWhiteSpace($csvText)) {
        & $send @{ type='log'; level='warn'; text='No CSV file selected and no CSV text pasted.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    & $send @{ type='status'; text='Parsing C2C Compliance CSV...' }
    $plan = Get-C2cImportPlan -Paths $paths -Text $csvText -Send $send
    $recs = @($plan.Records)
    if ($recs.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text="Parsed $($plan.RowCount) row(s) but resolved no hosts - check the CSV headers (a 'Compliance' column and a 'Computer Name' column)." }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $rows = New-Object System.Collections.ArrayList
    foreach ($rec in ($recs | Sort-Object { $_.Short })) {
        $row = @{ Host=$rec.Short; Compliance=$rec.Compliance; Failed=(@($rec.Failed) -join ', '); Audit=(@($rec.Audit) -join ', '); Fqdn=$rec.Fqdn }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
    }

    $total             = $recs.Count
    $nonCompliant      = @($recs | Where-Object { $_.Compliance -match '(?i)^Non-?Compliant' }).Count
    $compliant         = $total - $nonCompliant
    $nonCompliantHosts = @($plan.NonCompliantHosts)

    & $send @{ type='log'; level='ok'; text="Imported $total host(s): $compliant Compliant, $nonCompliant Non-Compliant." }
    $pillars = New-Object System.Collections.ArrayList
    foreach ($p in @($plan.PillarOrdered)) {
        $hosts = @($plan.PillarHosts[$p])
        $route = Get-C2cPillarRouting $p
        [void]$pillars.Add(@{ name=$p; failedCount=$hosts.Count; hosts=$hosts; routing=$route })
        & $send @{ type='log'; level='info'; text=("{0}: {1} host(s) -> {2}" -f $p, $hosts.Count, $route) }
    }
    $auditPillars = New-Object System.Collections.ArrayList
    foreach ($p in @($plan.AuditOrdered)) {
        $hosts = @($plan.AuditPillarHosts[$p])
        $route = Get-C2cPillarRouting $p
        [void]$auditPillars.Add(@{ name=$p; failedCount=$hosts.Count; hosts=$hosts; routing=$route; audit=$true })
        & $send @{ type='log'; level='info'; text=("AUDIT {0}: {1} host(s) (advisory, non-quarantine) -> {2}" -f $p, $hosts.Count, $route) }
    }

    $runAllPlan = @($plan.RunAllPlan)
    $auditFixHostCount = @($runAllPlan | Where-Object { @($_.auditPillars).Count -gt 0 -and @($_.pillars).Count -eq @($_.auditPillars).Count }).Count
    & $send @{ type='log'; level='info'; text=("Run-all plan: {0} host(s) with >=1 endpoint-fixable pillar ({1} from audit-only findings, proactive)." -f $runAllPlan.Count, $auditFixHostCount) }

    & $send @{ type='status'; text="Done. $total host(s) imported ($nonCompliant non-compliant)." }
    return @{ rows=@($rows); summary=@{ total=$total; compliant=$compliant; nonCompliant=$nonCompliant; nonCompliantHosts=@($nonCompliantHosts); pillars=@($pillars); auditPillars=@($auditPillars); runAllPlan=@($runAllPlan) } }
}

$script:C2cPillarByAction = @{
    'fix-monitoring'  = 'Monitoring'
    'fix-firewall'    = 'Firewall'
    'fix-antimalware' = 'AntiMalware'
    'fix-patches'     = 'Patches'
    'fix-encryption'  = 'Encryption'
    'fix-pki'         = 'PkiRoots'
    'fix-lockscreen'  = 'Lockscreen'   # dedicated opt-in cache fix; NOT in C2cFixablePillars (never in run-all)
    'fix-java'        = 'Java'         # dedicated opt-in Java cleanup; NOT in C2cFixablePillars (never in run-all)
}

# --- Admin-side cert-bundle reader (fix-pki) ---------------------------------
# Reads a DoD trust bundle folder ONCE, before any host is dialed. Enumerates
# (case-insensitive on Windows) <folder>\root\*.cer -> Root, <folder>\Intermediate\*.cer
# -> CA, <folder>\Untrusted\*.cer -> Disallowed, and loose <folder>\*.cer -> Root.
# Each .cer is loaded into an X509Certificate2 and captured as thumbprint + base64
# (base64 crosses the WinRM boundary cleanly). EXPIRED certs (NotAfter < now, admin
# clock) are EXCLUDED from Root/CA/Disallowed (never serialized, never pushed to a
# host - a dead trust anchor is worthless) and reported instead via ExpiredCount +
# Expired[]. Returns
# @{ Ok; Error; Root=@(@{Thumbprint;B64;File}); CA=@(...); Disallowed=@(...); CertCount;
#    FileCount; Folder; ExpiredCount; Expired=@(@{Thumbprint;Subject;NotAfter;Store}) }.
# CertCount counts the PUSHABLE certs = non-expired PLUS allowlisted legacy intermediates
# (LegacyAllowedCount), since those are pushed despite expiry; non-allowlisted expired certs
# (ExpiredCount) are excluded. Ok=$false with a populated Error if the folder is missing,
# yields ZERO .cer, or yields ONLY non-allowlisted expired certs (nothing usable).
# --- LegacyIntermediates: NARROW, audited exception to the expiry guard (mirrors
# JanetWeb.certdeploy). Four EXPIRED DoD intermediate CAs intentionally kept installed for
# legacy chain / signature validation - fix-pki pushes these despite expiry; every other
# expired cert stays a refused dead anchor. Keyed by exact uppercase SHA-1 thumbprint. Do
# NOT add a thumbprint here without confirming the cert is required for legacy validation.
$script:C2cLegacyIntermediates = [ordered]@{
    '53FDE0F40638BD1A68A68D1E91089009B33BAE5E' = 'DOD EMAIL CA-59'  # issuer DoD Root CA 3, expired 2025-04-02
    '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7' = 'DOD ID CA-59'     # issuer DoD Root CA 3, expired 2025-04-02
    '5DFFDAB658915FA6B0DB4E0BCF70D5BB1B8425FC' = 'DOD SW CA-60'     # issuer DoD Root CA 3, expired 2025-04-02
    '5F555AB8A87DD146314171621245CF720BF53B8A' = 'DOD SW CA-61'     # issuer DoD Root CA 5, expired 2025-03-31
}

function Get-C2cCertBundle {
    param([string]$Folder)
    $res = @{ Ok=$false; Error=''; Root=@(); CA=@(); Disallowed=@(); CertCount=0; FileCount=0; Folder=''; ExpiredCount=0; Expired=@(); LegacyAllowed=@(); LegacyAllowedCount=0 }
    $f = ([string]$Folder).Trim().Trim('"')
    $res.Folder = $f
    if (-not $f) { $res.Error = 'no cert bundle folder provided'; return $res }
    if (-not (Test-Path -LiteralPath $f)) { $res.Error = "cert bundle folder not found: $f"; return $res }
    $groups = @{
        Root       = New-Object System.Collections.ArrayList
        CA         = New-Object System.Collections.ArrayList
        Disallowed = New-Object System.Collections.ArrayList
    }
    $expired = New-Object System.Collections.ArrayList
    $legacy  = New-Object System.Collections.ArrayList   # expired BUT allowlisted -> pushed, tracked separately
    # Local set so $loadCer never depends on module-function resolution (mirrors certdeploy).
    $legacySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $script:C2cLegacyIntermediates.Keys) { [void]$legacySet.Add([string]$k) }
    $loadCer = {
        param($file, $store)
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($file)
            # Expired = NotAfter < now (admin-side clock). A dead trust anchor is never
            # serialized/pushed - record it in Expired[] and skip the usable group - UNLESS
            # it is an allowlisted legacy intermediate (kept for legacy chain validation),
            # in which case it is tracked in LegacyAllowed[] and pushed like a valid cert.
            if ($cert.NotAfter -lt (Get-Date)) {
                $rec = [pscustomobject]@{ Thumbprint=[string]$cert.Thumbprint; Subject=[string]$cert.Subject; NotAfter=$cert.NotAfter.ToString('o'); Store=$store }
                $tp  = (([string]$cert.Thumbprint) -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
                if (-not $legacySet.Contains($tp)) {
                    [void]$expired.Add($rec)
                    return $true
                }
                [void]$legacy.Add($rec)   # allowlisted -> fall through and push it
            }
            $b64  = [Convert]::ToBase64String($cert.RawData)
            [void]$groups[$store].Add([pscustomobject]@{ Thumbprint=[string]$cert.Thumbprint; B64=$b64; File=(Split-Path $file -Leaf) })
            return $true
        } catch { return $false }
    }
    $fileCount = 0
    foreach ($m in @(@{ Sub='root'; Store='Root' }, @{ Sub='Intermediate'; Store='CA' }, @{ Sub='Untrusted'; Store='Disallowed' })) {
        $sub = Join-Path $f $m.Sub
        if (Test-Path -LiteralPath $sub) {
            foreach ($cf in @(Get-ChildItem -LiteralPath $sub -Filter '*.cer' -File -ErrorAction SilentlyContinue)) {
                if (& $loadCer $cf.FullName $m.Store) { $fileCount++ }
            }
        }
    }
    # Loose *.cer directly under the folder -> Root (non-recursive).
    foreach ($cf in @(Get-ChildItem -LiteralPath $f -Filter '*.cer' -File -ErrorAction SilentlyContinue)) {
        if (& $loadCer $cf.FullName 'Root') { $fileCount++ }
    }
    $res.ExpiredCount = $expired.Count
    $res.Expired      = @($expired)
    $res.LegacyAllowed = @($legacy)
    $res.LegacyAllowedCount = $legacy.Count
    $total = $groups.Root.Count + $groups.CA.Count + $groups.Disallowed.Count
    if ($total -eq 0) {
        if ($expired.Count -gt 0) {
            $res.Error = "all $($expired.Count) cert(s) under $f are EXPIRED (dead trust anchors) - nothing usable to install"
        } else {
            $res.Error = "no .cer certificates found under $f (expected root\*.cer, Intermediate\*.cer, Untrusted\*.cer, or loose *.cer)"
        }
        return $res
    }
    $res.Root = @($groups.Root); $res.CA = @($groups.CA); $res.Disallowed = @($groups.Disallowed)
    $res.CertCount = $total; $res.FileCount = $fileCount; $res.Ok = $true
    return $res
}

# Resolve the effective cert bundle folder for fix-pki / run-all. An operator-supplied
# path (non-blank) ALWAYS wins; a blank/whitespace path AUTO-falls-back to the SHIPPED
# default (Get-C2cDefaultCertBundlePath = Packages\DoD-Certs) ONLY when that folder
# exists and holds >=1 .cer, so a one-click fix-pki works with nothing typed. Returns
# @{ Folder; Source } where Source is 'operator-supplied' / 'shipped default' / '' and
# Folder='' means NEITHER a path was given NOR a usable default was found.
function Resolve-C2cCertBundleFolder {
    param([string]$Supplied)
    $s = ([string]$Supplied).Trim().Trim('"')
    if (-not [string]::IsNullOrWhiteSpace($s)) { return @{ Folder = $s; Source = 'operator-supplied' } }
    $def = Get-C2cDefaultCertBundlePath
    if ($def -and (Test-Path -LiteralPath $def)) {
        $cerCount = @(Get-ChildItem -LiteralPath $def -Filter '*.cer' -File -Recurse -ErrorAction SilentlyContinue).Count
        if ($cerCount -gt 0) { return @{ Folder = $def; Source = 'shipped default' } }
    }
    return @{ Folder = ''; Source = '' }
}

# --- Offline Defender definition package (Defender-ScanFix v2.1 LAST rung) -------
# The operator stages Microsoft's full offline installer (mpam-fe.exe) in
# Packages\DefenderDefinitions (shipped EMPTY apart from a README - the folder is the
# air-gap staging point). Resolved + validated ADMIN-SIDE before any host is dialed:
# a definition installer going onto fleet hosts must be a Microsoft-signed FULL
# package - anything else is refused. Pushed ONLY to hosts where every online
# signature source failed (see the offline rung in $script:C2cFixBlock).
function Get-C2cDefenderPackageDir { Join-Path $PSScriptRoot '..\Packages\DefenderDefinitions' }

function Test-C2cDefenderPackage {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return 'not found' }
    $len = (Get-Item -LiteralPath $Path).Length
    if ($len -lt 50MB) { return "too small ($([math]::Round($len / 1MB, 0)) MB) - not a full definition package" }
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') { return "signature $($sig.Status)" }
    if ("$($sig.SignerCertificate.Subject)" -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { return "signer is not Microsoft: $($sig.SignerCertificate.Subject)" }
    # Product identity: a Microsoft-signed EXE is not enough - require the Defender definition
    # package specifically (mpam OriginalFilename, or the Antimalware/Defender ProductName).
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    if (("$($vi.OriginalFilename)" -notmatch '(?i)mpam') -and ("$($vi.ProductName)" -notmatch '(?i)antimalware|defender')) {
        return "not a Defender definition package (OriginalFilename='$($vi.OriginalFilename)', ProductName='$($vi.ProductName)')"
    }
    return 'OK'
}

# Returns @{ Path; Note }: Path non-empty ONLY for a validated package; Note carries the
# rejection reason when a candidate exists but fails validation; both empty = folder empty
# (the normal shipped state - the offline rung silently stays off).
function Resolve-C2cDefenderPackage {
    $dir = Get-C2cDefenderPackageDir
    foreach ($name in @('mpam-fe.exe', 'mpam-feX64.exe')) {
        $cand = Join-Path $dir $name
        if (Test-Path -LiteralPath $cand) {
            $v = Test-C2cDefenderPackage $cand
            if ($v -eq 'OK') { return @{ Path = $cand; Note = ''; Sha256 = (Get-FileHash -LiteralPath $cand -Algorithm SHA256).Hash } }
            return @{ Path = ''; Note = "offline definition package rejected ($v): $cand"; Sha256 = '' }
        }
    }
    return @{ Path = ''; Note = ''; Sha256 = '' }
}

# Serialize a bundle to the compact JSON the PkiRoots worker consumes (thumbprint + b64
# per store). @()-wrapped so ConvertFrom-Json single-element arrays round-trip safely.
function Convert-C2cBundleToJson {
    param($Bundle)
    $payload = @{
        Root       = @(@($Bundle.Root)       | ForEach-Object { @{ t=[string]$_.Thumbprint; b=[string]$_.B64 } })
        CA         = @(@($Bundle.CA)         | ForEach-Object { @{ t=[string]$_.Thumbprint; b=[string]$_.B64 } })
        Disallowed = @(@($Bundle.Disallowed) | ForEach-Object { @{ t=[string]$_.Thumbprint; b=[string]$_.B64 } })
    }
    return ($payload | ConvertTo-Json -Depth 5 -Compress)
}

# --- Action: per-pillar fixes + run-all (DESTRUCTIVE) ------------------------
# One worker ($script:C2cFixBlock), one fan-out. The per-pillar actions supply a
# ONE-pillar set applied to every target; run-all supplies each host's OWN pillar
# set from the imported plan JSON. The worker takes the pillar list PER host job.
function Invoke-C2cFixAction {
    param([string]$ActionId, [hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    $isRunAll     = ($ActionId -eq 'run-all')
    $isHostlist   = ($ActionId -eq 'fix-lockscreen' -or $ActionId -eq 'fix-java')   # opt-in plain-hostlist utilities - NOT import-scoped
    $verb         = if ($isRunAll) { 'C2C Run-All' } else { "C2C $ActionId" }

    # Confirm word - exact 'FIX' (case-sensitive), matching the suite idiom. FIRST gate.
    $confirm = ([string]$Params['confirm']).Trim()
    if ($confirm -cne 'FIX') {
        & $send @{ type='log'; level='err'; text="Confirm word mismatch: type FIX (exactly) to run $verb. Nothing was changed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    $attemptOffline = Get-C2cBool $Params['attemptOffline'] $false
    $doEnable       = Get-C2cBool $Params['enableEncryption'] $false
    $winrmHeal      = Get-C2cBool $Params['winrmHeal'] $false
    # PkiRoots companions (opt-in, destructive extras; both default OFF). Gate the two
    # PKI-Fix-ScanFix v1.9 companions INDEPENDENTLY: prunePki -> expired retired-intermediate
    # prune (block a), fixRdp -> broken RDP-listener rebind (block b). The core additive DoD
    # trust-bundle install ALWAYS runs; only these destructive extras are box-gated. Shared
    # param contract with the certdeploy tool so the two stay consistent.
    $doPrune        = Get-C2cBool $Params['prunePki'] $false
    $doRdp          = Get-C2cBool $Params['fixRdp'] $false

    # Baseline (fresh) for the Tanium service name used by the Monitoring fixer.
    $baseline = Get-C2cBaseline
    $taniumService = [string]$baseline.Config['taniumService']
    if (-not $taniumService) { $taniumService = 'Tanium Client' }
    # Signature-freshness budget (hours) for the AntiMalware fixer: explicit hours, else days*24.
    $sigMaxHours = 24
    if ($baseline.Config.ContainsKey('sigMaxAgeHours')) { $tmph = 0; if ([int]::TryParse([string]$baseline.Config['sigMaxAgeHours'], [ref]$tmph) -and $tmph -gt 0) { $sigMaxHours = $tmph } }
    elseif ($baseline.Config.ContainsKey('sigMaxAgeDays')) { $tmpd = 0; if ([int]::TryParse([string]$baseline.Config['sigMaxAgeDays'], [ref]$tmpd) -and $tmpd -gt 0) { $sigMaxHours = $tmpd * 24 } }

    # Offline Defender definition package (Defender-ScanFix v2.1 LAST rung). The operator
    # stages Microsoft's mpam-fe.exe in Packages\DefenderDefinitions (shipped empty); it is
    # resolved + Authenticode-validated HERE, once, before any host is dialed, and pushed
    # ONLY to hosts where every online signature source fails. Empty folder = rung off.
    $offlineDefPath = ''
    $offlineDefSha256 = ''
    $offPkg = Resolve-C2cDefenderPackage
    $offlineDefSha256 = [string]$offPkg.Sha256
    if ($offPkg.Note) { & $send @{ type='log'; level='warn'; text="[AntiMalware] $($offPkg.Note) - offline rung disabled this run." } }
    elseif ($offPkg.Path) {
        $offlineDefPath = [string]$offPkg.Path
        $offMb = [math]::Round((Get-Item -LiteralPath $offlineDefPath).Length / 1MB, 0)
        & $send @{ type='log'; level='info'; text="[AntiMalware] offline definition package staged: $offlineDefPath ($offMb MB, Microsoft-signed) - pushed ONLY to hosts where every online signature source fails." }
    }

    # --- Cert bundle for the PkiRoots fixer -------------------------------------
    # fix-pki: the bundle is REQUIRED - read it ADMIN-SIDE now; abort (dial nothing) if
    # missing/empty. run-all: OPTIONAL - if absent/invalid, PkiRoots is dropped per host
    # (info note) but the run continues for other pillars.
    # Operator path wins; a BLANK path auto-falls-back to the SHIPPED default
    # (Packages\DoD-Certs) when it exists + holds certs, so one-click fix-pki works with
    # nothing typed. fix-pki with NEITHER a path NOR a usable default ABORTS (dials
    # nothing); run-all with neither just SKIPS PkiRoots per host (other pillars run).
    $bundleJson = ''
    $bundleOk   = $false
    if ($ActionId -eq 'fix-pki' -or $isRunAll) {
        $resolved     = Resolve-C2cCertBundleFolder ([string]$Params['certBundleFolder'])
        $bundleFolder = [string]$resolved.Folder
        $bundleSource = [string]$resolved.Source
        if ([string]::IsNullOrWhiteSpace($bundleFolder)) {
            if ($ActionId -eq 'fix-pki') {
                & $send @{ type='log'; level='err'; text="Fix PKI Trust Roots aborted: no cert bundle folder supplied and the shipped default ($(Get-C2cDefaultCertBundlePath)) is missing or has no .cer files. Nothing was dialed." }
                return @{ rows=@(); summary=@{ total=0; rejected=$true } }
            }
            & $send @{ type='log'; level='info'; text='Run-all: no cert bundle folder supplied and no usable shipped default - PkiRoots will be SKIPPED per host; other pillars still run.' }
        } else {
            $bundle = Get-C2cCertBundle -Folder $bundleFolder
            if ($bundle.Ok) {
                # Expiry guard (run-level, before dialing): expired certs were already
                # excluded from the pushed set by Get-C2cCertBundle; report the exclusion.
                if ([int]$bundle.ExpiredCount -gt 0) {
                    $expSubjects = (@($bundle.Expired | ForEach-Object { [string]$_.Subject }) -join ', ')
                    & $send @{ type='log'; level='warn'; text="[SKIP] $($bundle.ExpiredCount) expired cert(s) excluded (dead trust anchors, not allowlisted): $expSubjects" }
                }
                if ([int]$bundle.LegacyAllowedCount -gt 0) {
                    $legSubjects = (@($bundle.LegacyAllowed | ForEach-Object { [string]$_.Subject }) -join ', ')
                    & $send @{ type='log'; level='warn'; text="[LEGACY] $($bundle.LegacyAllowedCount) expired-but-allowlisted intermediate(s) WILL be pushed (LegacyIntermediates - legacy chain/signature validation): $legSubjects" }
                }
                $bundleJson = Convert-C2cBundleToJson $bundle
                $bundleOk   = $true
                & $send @{ type='log'; level='info'; text="Cert bundle: $($bundle.CertCount) cert(s) [Root $(@($bundle.Root).Count)/CA $(@($bundle.CA).Count)/Disallowed $(@($bundle.Disallowed).Count)] from $($bundle.Folder) [$bundleSource]." }
            } elseif ($ActionId -eq 'fix-pki') {
                & $send @{ type='log'; level='err'; text="Fix PKI Trust Roots aborted: $($bundle.Error). Nothing was dialed." }
                return @{ rows=@(); summary=@{ total=0; rejected=$true } }
            } else {
                & $send @{ type='log'; level='warn'; text="Cert bundle invalid ($($bundle.Error)) - PkiRoots will be SKIPPED per host; other pillars still run." }
            }
        }
    }

    # --- Dual-mode targeting (per-pillar + run-all) ----------------------------
    # IMPORT MODE (a CSV was supplied): per-pillar fixes and run-all dial ONLY the hosts
    # the import flagged for each pillar - NEVER the whole list. Re-parse the CSV every
    # call (like ACAS: nothing persists server-side) and derive the authoritative
    # pillar/plan sets; the operator's checked/typed hosts are an ALLOW-LIST intersected
    # against it.
    # MANUAL MODE (NO csvPath/csvText): there is no import to scope against, so the fix
    # dials EXACTLY the operator's typed host list for the chosen pillar(s) - the operator
    # owns the list. Every other guard is unchanged (FIX confirm above, self-guard,
    # wrong-box DNS abort, verify-first fixers). This is what makes "load machines + run a
    # manual C2C patch" work without an import.
    # A CSV that was SUPPLIED but parses to ZERO findings still REFUSES (the operator meant
    # to scope by import but the CSV was bad - do not silently fall through to dialing all
    # typed hosts). Note "supplied but bad" = a real empty/garbage CSV *file*: it has a path,
    # so it lands in the else-branch below and Get-C2cImportPlan's zero-records check refuses
    # it. Only content-less input (no path AND no/whitespace text) is MANUAL - there is
    # genuinely no CSV to scope against. fix-lockscreen BYPASSES this block (plain-hostlist).
    $importPlan = $null
    $manualMode = $false
    if (-not $isHostlist) {
        $fixCsvPath  = [string]$Params['csvPath']
        $fixCsvText  = [string]$Params['csvText']
        $fixCsvPaths = @()
        if ($fixCsvPath) { $fixCsvPaths = @($fixCsvPath -split '[\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        if ($fixCsvPaths.Count -eq 0 -and [string]::IsNullOrWhiteSpace($fixCsvText)) {
            $manualMode = $true
            & $send @{ type='log'; level='info'; text='MANUAL MODE: no C2C import loaded - dialing EXACTLY the host(s) you provided for the selected pillar(s). No import allow-list; FIX confirm, self-guard, wrong-box guard and verify-first fixers still apply.' }
        } else {
            $importPlan = Get-C2cImportPlan -Paths $fixCsvPaths -Text $fixCsvText -Send $send
            if (@($importPlan.Records).Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='A C2C CSV was supplied but parsed to ZERO findings - refusing (nothing dialed). Remove the CSV to run in MANUAL mode against your typed host list, or re-export a valid C2C compliance CSV.' }
                return @{ rows=@(); summary=@{ total=0; rejected=$true } }
            }
        }
    }

    $rows = New-Object System.Collections.ArrayList     # pre-rows (self-guard, zero-fixable info) + result rows
    $plan = New-Object System.Collections.ArrayList     # [ @{ Host; Pillars=@(...) } ] to dial (pre self-guard)

    if ($isRunAll) {
        # Re-derive the AUTHORITATIVE per-host fixable set from the CSV: short(upper) ->
        # HashSet of fixable pillars flagged for that host. The client plan is an ALLOW-LIST
        # intersected against this (never trusted as the dispatch list). MANUAL mode has no
        # import, so $derived stays empty and the intersection below is skipped ($manualMode)
        # - guarded here too so a null $importPlan is never dereferenced (strict-mode safe).
        $derived = @{}
        if (-not $manualMode) {
            foreach ($e in @($importPlan.RunAllPlan)) {
                $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($p in @($e.pillars)) { [void]$hs.Add([string]$p) }
                $derived[([string]$e.host).ToUpperInvariant()] = $hs
            }
        }
        # --- Parse + validate the run-all plan JSON --------------------------
        $planRaw = [string]$Params['plan']
        if ([string]::IsNullOrWhiteSpace($planRaw)) {
            $emptyPlanMsg = if ($manualMode) { 'Run-all plan is empty. Add hosts to Target Computers and check at least one pillar card, then Run All. Nothing was changed.' }
                            else { 'Run-all plan is empty. Import a C2C CSV first, then Run All. Nothing was changed.' }
            & $send @{ type='log'; level='err'; text=$emptyPlanMsg }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        $parsed = $null
        try { $parsed = $planRaw | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
        if ($null -eq $parsed) {
            & $send @{ type='log'; level='err'; text='Run-all plan is not valid JSON. Nothing was changed.' }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @($parsed)) {
            $eh = ''
            try { $eh = ([string]$entry.host).Trim() } catch { $eh = '' }
            if (-not $eh -or ($eh -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')) {
                & $send @{ type='log'; level='warn'; text="Run-all: dropped a plan entry with an invalid host token ('$eh')." }
                continue
            }
            $short = Get-C2cShortHost $eh
            if ($seen.Contains($short)) { continue }   # de-dupe by host (first wins)
            $rawPillars = @()
            try { $rawPillars = @($entry.pillars | ForEach-Object { [string]$_ } | Where-Object { $_ }) } catch { $rawPillars = @() }
            $known   = @($rawPillars | Where-Object { $script:C2cFixablePillars -contains $_ })
            $unknown = @($rawPillars | Where-Object { $script:C2cFixablePillars -notcontains $_ })
            if ($unknown.Count -gt 0) {
                & $send @{ type='log'; level='warn'; text="Run-all: $short - dropped non-endpoint-fixable pillar(s): $($unknown -join ', ') (route to ACAS / Windows Upgrade / Reports)." }
            }
            # Import-scoped intersection: narrow the client's fixable pillars to the set the
            # CSV re-derived for THIS host. A (host,pillar) pair the import did not flag is
            # dropped (warn); a host absent from the import is dropped entirely (never dialed).
            # MANUAL MODE skips this entirely: with no import there is nothing to intersect
            # against - the client plan's fixable pillars are dialed as-is for the typed hosts.
            $importDropped = $false
            if (-not $manualMode -and $known.Count -gt 0) {
                $du = $short.ToUpperInvariant()
                if ($derived.ContainsKey($du)) {
                    $dset   = $derived[$du]
                    $inPlan = @($known | Where-Object { $dset.Contains([string]$_) })
                    $drop   = @($known | Where-Object { -not $dset.Contains([string]$_) })
                    foreach ($dp in $drop) { & $send @{ type='log'; level='warn'; text="Run-all: $short - dropped $dp (not flagged for this host by the import)." } }
                    $known = $inPlan
                } else {
                    & $send @{ type='log'; level='warn'; text="Run-all: $short - not in the imported C2C findings; skipped (nothing dialed)." }
                    $known = @(); $importDropped = $true
                }
            }
            # PkiRoots needs a cert bundle; without one, skip it for this host (info note).
            if (-not $bundleOk -and ($known -contains 'PkiRoots')) {
                $known = @($known | Where-Object { $_ -ne 'PkiRoots' })
                & $send @{ type='log'; level='info'; text="Run-all: $short - PkiRoots skipped (no valid cert bundle folder supplied); other pillars still run." }
            }
            if ($known.Count -eq 0) {
                $skipDetail = if ($importDropped) { 'not in the imported C2C findings - skipped' } else { 'nothing endpoint-fixable (Vuln/OSVersion/STIG route elsewhere)' }
                $row = @{ Host=$short; Ping=''; Status='SKIPPED'; Detail=$skipDetail }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                [void]$seen.Add($short)
                continue
            }
            [void]$seen.Add($short)
            [void]$plan.Add(@{ Host=$short; Pillars=@($known) })
        }
        if ($plan.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='Run-all: no host has an endpoint-fixable pillar - nothing to run.' }
            return @{ rows=@($rows); summary=@{ total=0; infoSkipped=@($rows).Count } }
        }
    } elseif ($isHostlist) {
        # --- fix-lockscreen / fix-java: opt-in plain-hostlist utilities (v1.9.0 semantics) --
        # NOT scored pillars and NOT CSV-mapped, so they SKIP the import intersection
        # entirely: dial exactly the hosts the operator typed (token-regex parsed,
        # deduped case-insensitively, short-named), one utility pillar each, then
        # join the SAME self-guard + fan-out path below as every other action.
        $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No valid host(s) to fix - enter one or more computer names in Target Computers. Nothing was dialed.' }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        $utilPillar = [string]$script:C2cPillarByAction[$ActionId]
        foreach ($t in $targets) { [void]$plan.Add(@{ Host=(Get-C2cShortHost $t); Pillars=@($utilPillar) }) }
    } else {
        # --- Per-pillar fix: ONE pillar. IMPORT MODE dials ONLY the hosts the import flagged
        #     for that pillar (server-re-derived from the CSV), narrowed to the operator's
        #     checked subset (ACAS pattern - the checked hosts are an ALLOW-LIST). MANUAL MODE
        #     (no import) dials EXACTLY the operator's typed hosts for the pillar. -----------
        $pillar = $script:C2cPillarByAction[$ActionId]
        if (-not $pillar) {
            & $send @{ type='error'; text="Unknown fix action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
        # The operator's host list (token-regex at ingress). Empty -> refuse.
        $submitted = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
        if ($submitted.Count -eq 0) {
            $emptyMsg = if ($manualMode) { "No host(s) to fix - enter computer name(s) in Target Computers for the $pillar fix. Nothing was dialed." }
                        else { "No host(s) checked - check the $pillar host(s) to fix in the pillar tab (per-pillar fixes never dial the whole import). Nothing was dialed." }
            & $send @{ type='log'; level='warn'; text=$emptyMsg }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        # Case-INSENSITIVE de-dupe throughout: ArrayList.Contains is ordinal, so 'hostp' +
        # 'HOSTP.dom.mil' would both dial the same box (destructive double-fix race). HashSet.Add
        # returns $false when the short name (any case) is already queued - guard the ArrayList add.
        $dispatch     = New-Object System.Collections.ArrayList
        $dispatchSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if ($manualMode) {
            # MANUAL: no import to intersect against - dial exactly the typed hosts (short-named).
            foreach ($t in $submitted) { $short = Get-C2cShortHost $t; if ($dispatchSeen.Add($short)) { [void]$dispatch.Add($short) } }
        } else {
            # IMPORT: dispatch = S (server-re-derived for THIS pillar) INTERSECT submitted (allow-
            # list). A submitted host NOT flagged for this pillar by the import is DROPPED (warn).
            $serverSet   = @(); if ($importPlan.PillarFixTargets.ContainsKey($pillar)) { $serverSet = @($importPlan.PillarFixTargets[$pillar]) }
            $serverAllow = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($h in $serverSet) { if ($h) { [void]$serverAllow.Add((Get-C2cShortHost $h)) } }
            $droppedNotFlagged = New-Object System.Collections.ArrayList
            foreach ($t in $submitted) {
                $short = Get-C2cShortHost $t
                if ($serverAllow.Contains($short)) { if ($dispatchSeen.Add($short)) { [void]$dispatch.Add($short) } }
                else { [void]$droppedNotFlagged.Add($t) }
            }
            if ($droppedNotFlagged.Count -gt 0) {
                & $send @{ type='log'; level='warn'; text="Dropped $($droppedNotFlagged.Count) submitted host(s) NOT flagged for $pillar by the import: $($droppedNotFlagged -join ', ')." }
            }
        }
        # Re-apply the host-token regex to the FINAL resolved list (never trust the derived list).
        $dispatch = @(@($dispatch) | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' })
        if ($dispatch.Count -eq 0) {
            $noneMsg = if ($manualMode) { "No valid host(s) to fix for $pillar. Nothing was dialed." }
                       else { "None of the submitted host(s) are flagged for $pillar by the import - nothing to fix." }
            & $send @{ type='log'; level='warn'; text=$noneMsg }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        foreach ($t in $dispatch) { [void]$plan.Add(@{ Host=$t; Pillars=@($pillar) }) }
    }

    # --- Self-guard: drop the dispatcher host from the plan, SKIPPED row each -
    $dialPlan    = New-Object System.Collections.ArrayList
    $selfSkipped = New-Object System.Collections.ArrayList
    foreach ($job in $plan) {
        if (Test-JanetC2cHostIsSelf ([string]$job.Host)) {
            [void]$selfSkipped.Add([string]$job.Host)
            $row = @{ Host=[string]$job.Host; Ping=''; Status='SKIPPED'; Detail='self-guard: dispatcher/local host - refused (a self-fix could disrupt the JANET server mid-run)' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        } else { [void]$dialPlan.Add($job) }
    }
    if ($selfSkipped.Count -gt 0) {
        & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host ($($selfSkipped -join ', '))." }
    }
    if ($dialPlan.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='Nothing left to run after the self-guard - only the dispatcher host was targeted.' }
        return @{ rows=@($rows); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
    }

    $threads = 8
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(16, $threads))
    $perHostTimeout = 300
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="$verb on $($dialPlan.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START $verb on $($dialPlan.Count) host(s) ($authLabel)$(if ($doEnable) { ' [ENABLE BitLocker armed]' } else { '' })." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($job in $dialPlan) { & $send (@{ type='row' } + @{ Host=[string]$job.Host; Ping=''; Status='Queued'; Detail=("waiting for a runspace... [{0}]" -f (@($job.Pillars) -join ', ')) }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($job in $dialPlan) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:C2cFixBlock)
        # Per-host heal flag reuses Test-JanetC2cHostIsSelf so the RPC heal never targets
        # the dispatcher (the self-guard already dropped self from $dialPlan; belt + braces).
        $healThis = $winrmHeal -and -not (Test-JanetC2cHostIsSelf ([string]$job.Host))
        [void]$ps.AddArgument([string]$job.Host); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline)
        [void]$ps.AddArgument(@($job.Pillars)); [void]$ps.AddArgument($doEnable); [void]$ps.AddArgument($taniumService); [void]$ps.AddArgument($script:C2cTaniumInstalledSrc)
        [void]$ps.AddArgument($bundleJson); [void]$ps.AddArgument($healThis); [void]$ps.AddArgument($script:C2cWinrmHealSrc); [void]$ps.AddArgument($script:C2cAddCertsSrc)
        [void]$ps.AddArgument([int]$sigMaxHours)
        [void]$ps.AddArgument([string]$script:C2cMdeOrgId); [void]$ps.AddArgument([string]$script:C2cMdeOnboardingBlob); [void]$ps.AddArgument([string]$script:C2cJavaSrc); [void]$ps.AddArgument($doPrune); [void]$ps.AddArgument($doRdp); [void]$ps.AddArgument([string]$offlineDefPath); [void]$ps.AddArgument([string]$offlineDefSha256)
        [void]$jobs.Add([pscustomobject]@{ Host=[string]$job.Host; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    # Per-pillar tallies keyed by pillar name; per-status host counts from the rows.
    $perPillar = @{}
    $emitResult = {
        param($res)
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        # per-pillar fixed/nochange/fail tally (raw tokens from the worker).
        try {
            foreach ($p in @($res.Pillars)) {
                $pn = [string]$p.Name; if (-not $pn) { continue }
                $pr = [string]$p.Result
                if (-not $perPillar.ContainsKey($pn)) { $perPillar[$pn] = @{ fixed=0; nochange=0; fail=0 } }
                if     ($pr -eq 'FAIL')                              { $perPillar[$pn].fail++ }
                elseif (@('FIXED','STARTED','KICKED') -contains $pr) { $perPillar[$pn].fixed++ }
                else                                                 { $perPillar[$pn].nochange++ }
            }
        } catch {}
        # JANET audit: a fix is a security-state change.
        $auditResult = switch ($row.Status) { 'FIXED' {'Success'} 'PARTIAL' {'Success'} 'NO CHANGE' {'Skipped'} 'SKIPPED' {'Skipped'} 'OFFLINE' {'Skipped'} default {'Failure'} }
        $itemCount   = if ($row.Status -eq 'FIXED' -or $row.Status -eq 'PARTIAL') { 1 } else { 0 }
        & $send @{ type='audit'; action='VulnPatched'; target=$row.Host; result=$auditResult; itemCount=$itemCount; detail=$row.Detail }
        $rpt = ''
        try { $rpt = [string]$res.Report } catch { $rpt = '' }
        if ($rpt) {
            & $send @{ type='log'; level='info'; text="----- $([string]$res.Host) : $([string]$res.Status) -----" }
            foreach ($ln in ($rpt -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                # Colour by the pillar-flavoured label family: FAIL -> error, SKIP -> warn,
                # ALREADY*/IN PROGRESS -> info, everything else (MONITORED / FIREWALL ENABLED
                # / PROTECTED / PROTECTION RESUMED / ENCRYPTION STARTED /
                # PATCH CYCLE KICKED) -> ok.
                $lvl = 'ok'
                if     ($ln -match '^\s*\[FAIL\]')          { $lvl = 'error' }
                elseif ($ln -match '^\s*\[SKIP\]')          { $lvl = 'warn' }
                elseif ($ln -match '^\s*\[IN PROGRESS\]')   { $lvl = 'info' }
                elseif ($ln -match '^\s*\[[^\]]*ALREADY')   { $lvl = 'info' }
                & $send @{ type='log'; level=$lvl; text=$ln }
            }
        }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="worker error: $($_.Exception.Message)"; Report='' } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail='worker returned no result'; Report='' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="per-host timeout (${perHostTimeout}s) - possible remote hang"; Report='' }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='SKIPPED'; Detail='cancelled by operator'; Report='' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight fixes stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $cFixed   = @($rows | Where-Object { $_.Status -eq 'FIXED' }).Count
    $cNoChange= @($rows | Where-Object { $_.Status -eq 'NO CHANGE' }).Count
    $cPartial = @($rows | Where-Object { $_.Status -eq 'PARTIAL' }).Count
    $cFailed  = @($rows | Where-Object { $_.Status -eq 'FAILED' }).Count
    $cOffline = @($rows | Where-Object { $_.Status -eq 'OFFLINE' }).Count
    $cSkipped = @($rows | Where-Object { $_.Status -eq 'SKIPPED' }).Count

    $ppTxt = (@($perPillar.Keys | Sort-Object | ForEach-Object { "{0} fixed {1}/nochange {2}/fail {3}" -f $_, $perPillar[$_].fixed, $perPillar[$_].nochange, $perPillar[$_].fail }) -join ' | ')
    & $send @{ type='log'; level='ok'; text="$verb done - FIXED: $cFixed, NO CHANGE: $cNoChange, PARTIAL: $cPartial, FAILED: $cFailed, OFFLINE: $cOffline, SKIPPED: $cSkipped.$(if ($ppTxt) { "  Per-pillar: $ppTxt" } else { '' })" }
    & $send @{ type='status'; text="Done. $cFixed fixed, $cPartial partial, $cNoChange no-change, $cFailed failed of $($rows.Count) row(s)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; fixed=$cFixed; noChange=$cNoChange; partial=$cPartial; failed=$cFailed; offline=$cOffline; skipped=$cSkipped; selfSkipped=$selfSkipped.Count; perPillar=$perPillar } }
}

# =============================================================================
#  Version Check (READ-ONLY) - generalizes the field VersionCheckerFromListPS7.ps1
#  (its PS7 ForEach-Object -parallel becomes the module runspace pool). Per host:
#  TCP reachability (+ optional RPC WinRM-heal), then read BOTH uninstall hives via
#  the shared Get-C2cInstalledProduct, compare DisplayVersion to an optional target.
# =============================================================================
$script:C2cVersionBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string]$ProductMatch, [string]$TargetVersion, [bool]$WinrmHeal, [string]$WinrmHealSrc, [string]$InstalledProductSrc)

    $r = @{ Host=$Computer; Ping=''; Installed=''; Version=''; Status=''; Detail='' }

    # WinRM HTTP 5985, then WinRM HTTPS 5986, then SMB 445 (liveness). $useSsl set when ONLY 5986 answered.
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    $healNote = ''
    if (-not $reachable -and $WinrmHeal) {
        if ($WinrmHealSrc) { try { . ([scriptblock]::Create($WinrmHealSrc)) } catch {} }
        if (Get-Command Invoke-JanetC2cWinrmHeal -ErrorAction SilentlyContinue) {
            $hb = $null
            try { $hb = Invoke-JanetC2cWinrmHeal -Computer $Computer } catch {}
            if ($hb) {
                $healNote = "winrm-heal: $($hb.Bucket)"
                if ($hb.Bucket -eq 'reachable' -or $hb.Bucket -eq 'winrm-recovered') { $reachable = $true; $r.Ping = "TCP 5985 ($($hb.Bucket))" }
            }
        }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = (@('No TCP on 5985/5986/445 (1.5s timeouts).', $healNote) | Where-Object { $_ }) -join ' | '; return $r }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS common on AFNET).
    $soP = @{ OperationTimeout=120000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'OFFLINE'; $r.Detail = (@("Session: $($_.Exception.Message)", $healNote) | Where-Object { $_ }) -join ' | '; return $r }

    $readSb = {
        param($match, $src)
        if ($src) { try { . ([scriptblock]::Create($src)) } catch {} }
        if (Get-Command Get-C2cInstalledProduct -ErrorAction SilentlyContinue) { return (Get-C2cInstalledProduct -Match $match) }
        return [pscustomobject]@{ Installed=$false; DisplayName=''; Version='' }
    }
    $prod = $null
    try { $prod = Invoke-Command -Session $sess -ScriptBlock $readSb -ArgumentList $ProductMatch, $InstalledProductSrc -ErrorAction Stop }
    catch { $r.Status = 'ERROR'; $r.Detail = "Query: $($_.Exception.Message)"; Remove-PSSession $sess -ErrorAction SilentlyContinue; return $r }
    finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    $installed = [bool]$prod.Installed
    $ver       = [string]$prod.Version
    $dn        = [string]$prod.DisplayName
    $tv        = ([string]$TargetVersion).Trim()
    $r.Installed = if ($installed) { 'yes' } else { 'no' }
    $r.Version   = $ver

    if (-not $installed) {
        $r.Status = 'NOT INSTALLED'; $r.Detail = "no DisplayName containing '$ProductMatch' in the uninstall registry"
    } elseif (-not $tv) {
        $r.Status = 'INSTALLED'; $r.Detail = (@($dn, $ver) | Where-Object { $_ }) -join ' '
    } else {
        $cmp = $null
        $iv = $null; $tvv = $null
        if ([System.Version]::TryParse($ver, [ref]$iv) -and [System.Version]::TryParse($tv, [ref]$tvv)) {
            $cmp = $iv.CompareTo($tvv)
        } else {
            $cmp = [string]::CompareOrdinal($ver, $tv)
        }
        if     ($cmp -eq 0) { $r.Status = 'UP TO DATE' }
        elseif ($cmp -lt 0) { $r.Status = 'OUTDATED' }
        else                { $r.Status = 'NEWER' }
        $r.Detail = "$dn installed $ver vs target $tv"
    }
    return $r
}

# --- Action: version-check (READ-ONLY) --------------------------------------
function Invoke-C2cVersionCheckAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    $productMatch = ([string]$Params['productMatch']).Trim()
    if ([string]::IsNullOrWhiteSpace($productMatch)) {
        & $send @{ type='log'; level='warn'; text='No product match string. Enter a DisplayName substring (e.g. Google Chrome).' }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    $targetVersion = ([string]$Params['targetVersion']).Trim()

    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $attemptOffline = Get-C2cBool $Params['attemptOffline'] $false
    $winrmHeal      = Get-C2cBool $Params['winrmHeal'] $false
    $threads = 16
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 200
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    $verTxt = if ($targetVersion) { "target $targetVersion" } else { 'no target (installed/not-installed only)' }
    & $send @{ type='status'; text="Version check '$productMatch' on $($targets.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START version-check '$productMatch' ($verTxt) on $($targets.Count) host(s) ($authLabel)$(if ($winrmHeal) { ' [WinRM-heal armed]' } else { '' })." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Installed=''; Version=''; Status='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        # Heal never targets self (reuse Test-JanetC2cHostIsSelf) - a read-only scan may
        # still query the dispatcher, but the RPC heal (an action) must not.
        $healThis = $winrmHeal -and -not (Test-JanetC2cHostIsSelf $h)
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:C2cVersionBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline)
        [void]$ps.AddArgument($productMatch); [void]$ps.AddArgument($targetVersion); [void]$ps.AddArgument($healThis); [void]$ps.AddArgument($script:C2cWinrmHealSrc); [void]$ps.AddArgument($script:C2cInstalledProductSrc)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList
    $emitResult = {
        param($res)
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Installed=[string]$res.Installed; Version=[string]$res.Version; Status=[string]$res.Status; Detail=[string]$res.Detail }
        if ($row.Status -eq 'ERROR') { $row.Status = 'OFFLINE' }   # session/query failure -> collapse to OFFLINE for the tally
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $lvl = switch ($row.Status) { 'UP TO DATE' {'ok'} 'INSTALLED' {'ok'} 'NEWER' {'info'} 'OUTDATED' {'warn'} 'NOT INSTALLED' {'warn'} default {'error'} }
        & $send @{ type='log'; level=$lvl; text=("[{0}] {1} - {2}" -f $row.Status, $row.Host, $row.Detail) }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Installed=''; Version=''; Status='OFFLINE'; Detail="worker error: $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Installed=''; Version=''; Status='OFFLINE'; Detail='worker returned no result' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Installed=''; Version=''; Status='OFFLINE'; Detail="per-host timeout (${perHostTimeout}s)" }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Installed=''; Version=''; Status='Cancelled'; Detail='cancelled by operator' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight version reads stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $counts = @{}
    foreach ($st in @('UP TO DATE','OUTDATED','NEWER','INSTALLED','NOT INSTALLED','OFFLINE','Cancelled')) { $counts[$st] = @($rows | Where-Object { $_.Status -eq $st }).Count }
    $ppTxt = (@('UP TO DATE','OUTDATED','NEWER','INSTALLED','NOT INSTALLED','OFFLINE') | Where-Object { $counts[$_] -gt 0 } | ForEach-Object { "$_ $($counts[$_])" }) -join ', '
    & $send @{ type='log'; level='ok'; text="Version check done - $ppTxt (of $($targets.Count) host(s))." }
    & $send @{ type='status'; text="Done. $($rows.Count) host(s): $ppTxt." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; upToDate=$counts['UP TO DATE']; outdated=$counts['OUTDATED']; newer=$counts['NEWER']; installed=$counts['INSTALLED']; notInstalled=$counts['NOT INSTALLED']; offline=$counts['OFFLINE'] } }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge (server injects $Params['__job']).
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    if ($ActionId -eq 'import') { return (Invoke-C2cImportAction -Params $Params -Emit $Emit) }
    if ($ActionId -eq 'version-check') { return (Invoke-C2cVersionCheckAction -Params $Params -Credential $Credential -Emit $Emit) }
    if ($ActionId -eq 'run-all' -or $script:C2cPillarByAction.ContainsKey($ActionId)) {
        return (Invoke-C2cFixAction -ActionId $ActionId -Params $Params -Credential $Credential -Emit $Emit)
    }

    if ($ActionId -ne 'scan') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # Load the baseline fresh (works even if the file is missing).
    $baseline = Get-C2cBaseline
    $config   = $baseline.Config
    # Inject the hardcoded TASKORD MDE Org ID (module scope here; the probe runspace has none).
    $config['mdeOrgId'] = $script:C2cMdeOrgId

    # Targets: accept only bare host/IPv4 tokens; drop UNC/URL/junk before any WinRM call.
    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $attemptOffline = $false
    if ($null -ne $Params['attemptOffline']) {
        $av = $Params['attemptOffline']
        $attemptOffline = if ($av -is [bool]) { [bool]$av } else { ("$av" -match '^(?i:true|1|yes|on)$') }
    }
    $threads = 16
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 200  # a read-only 11-check probe that runs this long = a wedged remote read
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="C2C readiness scan on $($targets.Count) host(s) with $threads thread(s)... (baseline: $($baseline.Source))" }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START C2C scan on $($targets.Count) host(s) ($authLabel), $threads thread(s). Baseline: $($baseline.Source)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    # Seed Queued rows so the operator sees the whole target list immediately.
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:C2cProbeBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($config); [void]$ps.AddArgument($script:C2cTaniumInstalledSrc); [void]$ps.AddArgument($script:C2cVerdictSrc)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList

    # Build a row from a worker result, emit it, and stream its per-check report.
    $emitResult = {
        param($res)
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail }
        # Normalize host-level evaluation failures to a status the shared view colours + counts
        # (match the SECRET engine): raw ERROR / DNS MISMATCH -> CHECK ERRORS. The Detail keeps
        # the reason. READY / QUARANTINE RISK / CHECK ERRORS / OFFLINE / Cancelled pass through.
        if ($row.Status -eq 'ERROR' -or $row.Status -eq 'DNS MISMATCH') { $row.Status = 'CHECK ERRORS' }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $rpt = ''
        try { $rpt = [string]$res.Report } catch { $rpt = '' }
        if ($rpt) {
            & $send @{ type='log'; level='info'; text="----- $([string]$res.Host) : $([string]$res.Status) -----" }
            foreach ($ln in ($rpt -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                $lvl = 'info'
                if     ($ln -match '^\s*\[PASS\]')  { $lvl = 'ok' }
                elseif ($ln -match '^\s*\[FAIL\]')  { $lvl = 'error' }
                elseif ($ln -match '^\s*\[ERROR\]') { $lvl = 'warn' }
                elseif ($ln -match '^\s*\[EXT\]')   { $lvl = 'info' }
                & $send @{ type='log'; level=$lvl; text=$ln }
            }
        }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail="worker error: $($_.Exception.Message)"; Ok=$false; Report='' } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail='worker returned no result'; Ok=$false; Report='' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own clock (wedged remote read).
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail="per-host timeout (${perHostTimeout}s) - possible remote read hang"; Ok=$false; Report='' }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Ok=$false; Report='' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight probes stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    # Tally from the emitted rows (each row carries its Status) - no module-scope counters.
    $ready    = @($rows | Where-Object { $_.Status -eq 'READY' }).Count
    $risk     = @($rows | Where-Object { $_.Status -eq 'QUARANTINE RISK' }).Count
    $notAttest= @($rows | Where-Object { $_.Status -eq 'NOT ATTESTING' }).Count
    $chkErr   = @($rows | Where-Object { $_.Status -eq 'CHECK ERRORS' }).Count
    $offline  = @($rows | Where-Object { $_.Status -eq 'OFFLINE' }).Count
    $other    = $targets.Count - $ready - $risk - $notAttest - $chkErr - $offline
    $pct      = if ($targets.Count -gt 0) { [math]::Round(($ready / $targets.Count) * 100, 1) } else { 0 }

    & $send @{ type='log'; level='ok'; text="C2C readiness - $pct% READY ($ready/$($targets.Count)). QUARANTINE RISK: $risk, NOT ATTESTING: $notAttest, CHECK ERRORS: $chkErr, OFFLINE: $offline, Other: $other. (EXT pillars Vuln/COAMS scored server-side.)" }
    & $send @{ type='status'; text="Done. $ready ready, $risk quarantine-risk, $notAttest not-attesting, $chkErr check-errors, $offline offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; ready=$ready; risk=$risk; notAttesting=$notAttest; checkErrors=$chkErr; offline=$offline; other=$other; readyPct=$pct; source=$baseline.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
