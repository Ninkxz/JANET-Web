# =============================================================================
#  JanetWeb.c2c.psm1  ->  C2C Readiness (Comply-to-Connect quarantine predictor)
#
#  Net-new JANET Web tool (no desktop twin). Fans out ONE consolidated read-only
#  WinRM probe across the targets and PREDICTS whether each host would be
#  QUARANTINED under AFI/MPTO Comply-to-Connect rule 3.B.2.B. It CHANGES NOTHING
#  and never needs an admin session (read-only, like the WPT ping / bulk-scan and
#  the Windows Upgrade Diagnose action).
#
#  The probe runs 11 C2C checks. 9 are scored locally (admin-side, from the check
#  results); 2 are marked EXT (external - reported, never scored) because they are
#  server-side (ARAD/ACAS/ePO) and not endpoint-determinable. Every check yields a
#  status PASS / FAIL / EXT / ERROR and a short Detail; each runs inside ONE
#  Invoke-Command round-trip ON the target, wrapped in its own try/catch so one
#  failed check becomes ERROR and never aborts the probe.
#
#  Verdict (computed admin-side): count FAIL among the 9 scored checks ->
#    READY            = 0 FAIL and 0 ERROR
#    QUARANTINE RISK  = >= 1 FAIL   (Detail lists the failing pillars)
#    CHECK ERRORS     = 0 FAIL but >= 1 ERROR
#    OFFLINE          = host unreachable (TCP 5985/445)
#  EXT checks (Vuln, COAMS) are shown but never count toward the verdict.
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
        version  = '1.6.0'
        category = 'Reporting'
        summary  = 'C2C Nemesis - Comply-to-Connect (AFI/MPTO rule 3.B.2.B) remediation: (1) IMPORT the Tanium "C2C Compliance Status" CSV export, de-duplicate per host, bucket each failing rule into a canonical pillar with a routing hint, and emit a run-all plan (each host + its own fixable failed pillars); the import drives one CARD PER FIXABLE PILLAR in the view; (2) PER-PILLAR FIX (destructive) - six individually runnable endpoint-fixable pillars, each with pillar-named result labels: Monitoring (verify Tanium SOFTWARE installed via uninstall registry AND heal the Tanium client service), Firewall (enable disabled profiles), AntiMalware (heal Defender/MDE), Patches (kick the MECM cycle), Encryption (resume/ENABLE BitLocker - FVE policy assert + Entra-first/AD-fallback recovery-key escrow, XtsAes256), and PkiRoots (install the DoD trust bundle .cer files ADDITIVELY into LocalMachine Root/CA/Disallowed via WinRM); (3) RUN ALL - fix every imported non-compliant host''s OWN failed pillars only in one pass; (4) READ-ONLY quarantine-predictor scan - fan out one consolidated WinRM probe per host, run 11 C2C checks (9 scored, 2 external/server-side), flag each host READY or QUARANTINE RISK; (5) READ-ONLY VERSION CHECK - per host read the 64/32-bit uninstall registry for a product DisplayName substring and compare its DisplayVersion to an optional target (UP TO DATE / OUTDATED / NEWER / NOT INSTALLED). An opt-in RPC-based WinRM-heal pre-step (default off, often blocked) can recover a stopped remote WinRM service before the fix / version fan-out. Vuln -> ACAS/Reports/KEV, OS Version -> Windows Upgrade, STIG -> Reports.'
        actions  = @(
            @{
                id          = 'scan'
                label       = 'C2C Readiness Scan'
                description = 'Read-only prediction of Comply-to-Connect quarantine (rule 3.B.2.B). Per host, one consolidated WinRM probe runs 11 checks - Monitoring (Tanium), Firewall, AntiMalware (Defender), Patches (MECM), Vuln threshold (EXT), Encryption (BitLocker), AppWhitelist (AppLocker/WDAC), Agents (patch+security), PKI roots, COAMS tags (EXT), and hostname - and returns a one-word verdict: READY (all scored pillars pass), QUARANTINE RISK (one or more FAIL), CHECK ERRORS (a check could not be evaluated), or OFFLINE. The two EXT pillars (Vuln, COAMS) are server-side (ARAD/ACAS/ePO) so they are reported but never scored. The full colour-tagged 11-line report streams to the activity log. Changes NOTHING and needs no admin session.'
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
                confirm     = 'Fix the Monitoring (Tanium) pillar on the target host(s)? This changes service state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
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
                confirm     = 'Fix the Firewall pillar on the target host(s)? This enables disabled firewall profiles. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-antimalware'
                label       = 'Fix AntiMalware (Defender)'
                description = 'DESTRUCTIVE (Defender state). Heal Microsoft Defender on each target: set WinDefend/Sense to Automatic + Started, enable Real-Time Protection if it is off, and Update-MpSignature if signatures are older than 7 days, then re-read. Result PROTECTED (something healed) / ALREADY PROTECTED (RTP on + signatures fresh) / FAIL. A missing MDE Sense service is a note, not a failure, when Defender itself is healthy. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the AntiMalware (Defender) pillar on the target host(s)? This changes Defender state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
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
                confirm     = 'Fix the Patches pillar on the target host(s)? This kicks the MECM patch cycle. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-encryption'
                label       = 'Fix Encryption (BitLocker)'
                description = 'DESTRUCTIVE (BitLocker). By default RESUME suspended BitLocker protectors on the OS volume only (re-read: PROTECTION RESUMED if now On; ALREADY ENCRYPTED if it was already On). If "ENABLE BitLocker" is ticked, a FullyDecrypted OS volume is encrypted from here - ESCROW-FIRST and FAIL-CLOSED, mirroring the enterprise USAF enable script: assert the FVE BitLocker policy (recovery-key escrow + XtsAes256 method), reuse-or-add a RecoveryPassword protector, escrow it Entra-first (BackupToAAD-BitLockerKeyProtector) with on-prem AD fallback (Backup-BitLockerKeyProtector) BEFORE any Enable-BitLocker, TPM-gated (TpmPresent+TpmReady) and domain-joined only, then Enable-BitLocker with a TPM protector and XtsAes256 full-volume encryption (Result ENCRYPTION STARTED). If BOTH escrow paths fail, a RecoveryPassword protector we added is removed and encryption is NEVER started; the recovery password is never emitted. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the Encryption (BitLocker) pillar on the target host(s)? This changes BitLocker state. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';          label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='enableEncryption'; label='ENABLE BitLocker on decrypted OS volumes (TPM+RecoveryPassword->escrow, XtsAes256)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';          label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';          label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline';   label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'fix-pki'
                label       = 'Fix PKI Trust Roots'
                description = 'DESTRUCTIVE (certificate store). Install the DoD trust bundle into the LocalMachine certificate stores on each target, ADDITIVELY. The engine reads the bundle folder ADMIN-SIDE once, before dialing any host: <folder>\root\*.cer -> Root store, <folder>\Intermediate\*.cer -> CA (intermediate) store, <folder>\Untrusted\*.cer -> Disallowed store, and any loose *.cer directly under <folder> -> Root (case-insensitive). If the folder is missing or yields ZERO certs the action ABORTS and dials nothing. Per host, over one WinRM round-trip, each store is opened ReadWrite and only certs whose thumbprint is NOT already present are added - nothing is ever removed. Result ROOTS INSTALLED (added N of M) / ROOTS ALREADY PRESENT (all M present) / FAIL. Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Fix the PKI Trust Roots pillar on the target host(s)? This adds DoD trust bundle certificates to the LocalMachine stores. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';          label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='certBundleFolder'; label='DoD trust bundle folder (server-readable path, e.g. a UNC path with root\*.cer, Intermediate\*.cer, Untrusted\*.cer)'; type='text'; required=$true },
                    @{ name='confirm';          label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='winrmHeal';        label='Recover WinRM via RPC if 5985 down (best-effort, often blocked)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';          label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
                    @{ name='attemptOffline';   label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false }
                )
            }
            @{
                id          = 'run-all'
                label       = 'RUN ALL - Fix Imported Non-Compliant Hosts'
                description = 'DESTRUCTIVE. Fix each imported non-compliant host''s OWN failed endpoint-fixable pillars only, in one pass. The "plan" input is the JSON array the Import action produced ([{host,pillars:[...]}, ...]); per host only its planned pillars run. Unknown / non-endpoint-fixable pillar names are dropped per host (Vuln / OSVersion / STIG route elsewhere); a host left with zero fixable pillars is reported and never dialed. If a host plans PkiRoots and a valid cert bundle folder was supplied it is installed; if PkiRoots is planned but no bundle was given it is SKIPPED for that host (info note) without aborting the run. Same safety as the per-pillar fixes: self-guard drops the dispatcher host, wrong-box DNS mismatch aborts a host, per-host watchdog + operator cancel, and the operator must type FIX to confirm. Encryption only STARTS on a decrypted volume if "ENABLE BitLocker" is ticked.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Run ALL fixes across the imported non-compliant hosts (each host, its own failed pillars)? This changes machines. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='plan';             label='Run-all plan (JSON: [{host,pillars:[...]}])'; type='textarea'; required=$true },
                    @{ name='enableEncryption'; label='ENABLE BitLocker on decrypted OS volumes (only if a host plans Encryption)'; type='bool'; required=$false; default=$false },
                    @{ name='certBundleFolder'; label='DoD trust bundle folder (optional; needed only if a host plans PkiRoots)'; type='text'; required=$false },
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
        taniumService         = 'Tanium Client'
        securityAgentServices = @('masvc','mfemms','macmnsvc','WinDefend','Sense')
        hostnamePatterns      = @('^MSEKL','^MSEKW')
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
        if ((& $has 'taniumService') -and -not [string]::IsNullOrWhiteSpace([string]$obj.taniumService)) {
            $cfg.taniumService = [string]$obj.taniumService
        }
        if ((& $has 'securityAgentServices') -and $obj.securityAgentServices) {
            $cfg.securityAgentServices = @($obj.securityAgentServices | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }
        if ((& $has 'hostnamePatterns') -and $obj.hostnamePatterns) {
            $cfg.hostnamePatterns = @($obj.hostnamePatterns | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }
        if ((& $has 'dodRootThumbprints') -and $obj.dodRootThumbprints) {
            $cfg.dodRootThumbprints = @($obj.dodRootThumbprints | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        }
        return @{ Config = $cfg; Source = 'JanetLocal\c2c-baseline.json (overlaid on defaults)' }
    } catch { return @{ Config = $cfg; Source = "embedded defaults (baseline read error: $($_.Exception.Message))" } }
}

# The 9 SCORED pillars are Monitoring/Firewall/AntiMalware/Patches/Encryption/
# AppWhitelist/Agents/PkiRoots/Hostname. The verdict simply tallies FAIL/ERROR
# across the returned checks; the 2 EXT pillars (Vuln, COAMS) carry neither, so
# "count all FAIL" already equals "count the 9 scored FAIL" (no explicit set needed).

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
# additive-only guard is unit-testable against a fake store. Returns
# @{ Added; Already; Total; PerStore=@('Root +N/M', ...); FailDetail }.
$script:C2cAddCertsSrc = @'
function Add-C2cBundleToStores {
    param($Bundle, [scriptblock]$StoreOpener)
    if (-not $StoreOpener) {
        $StoreOpener = {
            param($storeName)
            $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            return $st
        }
    }
    $added = 0; $already = 0; $total = 0; $failDetail = ''
    $perStore = New-Object System.Collections.ArrayList
    foreach ($sm in @(@{ Prop='Root'; Store='Root' }, @{ Prop='CA'; Store='CA' }, @{ Prop='Disallowed'; Store='Disallowed' })) {
        $items = @()
        try { $items = @($Bundle.($sm.Prop)) | Where-Object { $_ } } catch { $items = @() }
        if ($items.Count -eq 0) { continue }
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
                    if ($tp) { [void]$present.Add($tp) }
                    $sAdd++; $added++
                } catch { $failDetail += "add failed in $($sm.Store): $($_.Exception.Message); " }
            }
            [void]$perStore.Add("$($sm.Store) +$sAdd/$($items.Count)")
        } catch {
            $failDetail += "store $($sm.Store) open failed: $($_.Exception.Message); "
        } finally { if ($st) { try { $st.Close() } catch {} } }
    }
    return @{ Added=$added; Already=$already; Total=$total; PerStore=@($perStore); FailDetail=$failDetail }
}
# Classify an Add-C2cBundleToStores result into the raw PkiRoots token the fix worker
# emits (and the label map keys on): any .Add error -> FAIL; else 1+ added -> FIXED;
# else nothing to add -> NOCHANGE. This is the SINGLE classifier both the remote fix
# worker (fixSb) and the unit tests call, so a mis-classification fails a test.
function Get-C2cPkiRootsResultToken {
    param($AddResult)
    if (-not $AddResult) { return 'FAIL' }
    if ([string]$AddResult.FailDetail) { return 'FAIL' }
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
        default                { [string]$Result }
    }
}
'@

# Define the heal + installed-product + cert-store helpers in MODULE scope too (for
# admin-side use + direct unit testing). Worker runspaces dot-source them again.
try { . ([scriptblock]::Create($script:C2cInstalledProductSrc)) } catch {}
try { . ([scriptblock]::Create($script:C2cWinrmHealSrc)) } catch {}
try { . ([scriptblock]::Create($script:C2cAddCertsSrc)) } catch {}

# --- Per-host probe worker (runs in a pool runspace; no module scope here) ---
# Returns @{ Host; Ping; Status; Detail; Ok; Report; Checks }. All 11 checks run
# inside ONE Invoke-Command round-trip; the verdict is computed here (admin-side).
$script:C2cProbeBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, $Config, [string]$TaniumInstalledSrc)

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Ok=$false; Report=''; Checks=@() }

    # Reachability pre-check: pure-TCP probe (AFNET-safe; never ICMP). WinRM 5985
    # then SMB 445, 1500ms connect timeout, break on first connect (wpt/biosfirmware idiom).
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port" }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) {
            $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'
            return $r
        }
    }

    # Resolve baseline fields admin-side (worker has no module functions), then pass
    # plain typed values into the remote scriptblock's ArgumentList.
    $taniumService = [string]$Config['taniumService']; if (-not $taniumService) { $taniumService = 'Tanium Client' }
    $sigMaxAge     = 7; if ($Config.ContainsKey('sigMaxAgeDays')) { $tmp = 0; if ([int]::TryParse([string]$Config['sigMaxAgeDays'], [ref]$tmp)) { $sigMaxAge = $tmp } }
    $secAgents     = @($Config['securityAgentServices'])
    $hostPatterns  = @($Config['hostnamePatterns'])
    $dodRoots      = @($Config['dodRootThumbprints'])

    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # ---- The consolidated read-only probe: all 11 C2C checks in one round-trip. ----
    $probeSb = {
        param($taniumService, $sigMaxAge, $secAgents, $hostPatterns, $dodRoots, $taniumInstalledSrc)
        # Dot-source the single-source Tanium-installed probe (Get-C2cTaniumInstalled).
        if ($taniumInstalledSrc) { try { . ([scriptblock]::Create($taniumInstalledSrc)) } catch {} }
        # Normalize the array args: an empty collection can cross the WinRM ArgumentList
        # boundary as $null, and @($null) is a 1-element array holding $null (a stray
        # $null host-pattern would be an empty regex that matches EVERYTHING -> a false
        # PASS). Drop null/blank elements so every list is a clean [string] array.
        $secAgents    = @(@($secAgents)    | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $hostPatterns = @(@($hostPatterns) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
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
                # Fallback: parse netsh advfirewall show allprofiles state.
                $txt = (& netsh advfirewall show allprofiles state 2>&1 | Out-String)
                $curProf = ''; $disabled = New-Object System.Collections.ArrayList
                foreach ($ln in ($txt -split "`r?`n")) {
                    if     ($ln -match '^(Domain|Private|Public)\s+Profile') { $curProf = $Matches[1] }
                    elseif ($ln -match '^State\s+(\S+)') { if ($Matches[1] -notmatch '^(?i:on)$' -and $curProf) { [void]$disabled.Add($curProf) } }
                }
                if ($disabled.Count -eq 0) { & $mk 'Firewall' 'PASS' 'all profiles enabled (netsh)' }
                else                       { & $mk 'Firewall' 'FAIL' "disabled profile(s): $(($disabled | Select-Object -Unique) -join ', ') (netsh)" }
            }
        } catch { & $mk 'Firewall' 'ERROR' $_.Exception.Message }

        # 3. AntiMalware - Defender RTP on AND signatures fresh (fallback SecurityCenter2).
        try {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $mp  = Get-MpComputerStatus -ErrorAction Stop
                $rtp = [bool]$mp.RealTimeProtectionEnabled
                $age = [int]$mp.AntivirusSignatureAge
                $ver = [string]$mp.AntivirusSignatureVersion
                if ($rtp -and $age -le $sigMaxAge) {
                    & $mk 'AntiMalware' 'PASS' "RTP on; sig age ${age}d (<= ${sigMaxAge}d); ver $ver"
                } else {
                    $why = New-Object System.Collections.ArrayList
                    if (-not $rtp)          { [void]$why.Add('RTP off') }
                    if ($age -gt $sigMaxAge){ [void]$why.Add("sig age ${age}d > ${sigMaxAge}d") }
                    & $mk 'AntiMalware' 'FAIL' "$($why -join '; ') (ver $ver)"
                }
            } else {
                # Fallback: root\SecurityCenter2 AntiVirusProduct (productState bitmask).
                $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
                if ($av.Count -eq 0) { & $mk 'AntiMalware' 'FAIL' 'no AntiVirusProduct registered' }
                else {
                    $names = (@($av | ForEach-Object { [string]$_.displayName }) -join ', ')
                    $enabled = $false; $current = $true
                    foreach ($p in $av) {
                        try {
                            $hex  = '{0:X6}' -f [int]$p.productState
                            $prov = [Convert]::ToInt32($hex.Substring(2,2),16)
                            $sig  = [Convert]::ToInt32($hex.Substring(4,2),16)
                            if (($prov -band 0x10) -ne 0) { $enabled = $true }
                            if (($sig  -band 0x10) -ne 0) { $current = $false }
                        } catch {}
                    }
                    if ($enabled -and $current) { & $mk 'AntiMalware' 'PASS' "SecurityCenter2: $names (enabled, up to date)" }
                    else                        { & $mk 'AntiMalware' 'FAIL' "SecurityCenter2: $names (enabled=$enabled, up-to-date=$current)" }
                }
            }
        } catch { & $mk 'AntiMalware' 'ERROR' $_.Exception.Message }

        # 4. Patches - 0 applicable-not-installed MECM updates (exact wpt CCM query).
        try {
            $upd = @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace root/CCM/ClientSDK -ErrorAction Stop |
                     Where-Object { $_.InstallState -ne 'Installed' -and $_.ApplicabilityState -ne 'NotApplicable' })
            if ($upd.Count -eq 0) { & $mk 'Patches' 'PASS' '0 pending MECM update(s)' }
            else                  { & $mk 'Patches' 'FAIL' "$($upd.Count) pending MECM update(s)" }
        } catch { & $mk 'Patches' 'ERROR' 'MECM/CCM not queryable' }

        # 5. Vuln threshold - server-side (ARAD/ACAS), not endpoint-determinable -> EXT.
        & $mk 'Vuln' 'EXT' 'Scored server-side (ARAD/ACAS) - remediate via ACAS / Reports / KEV / UPR'

        # 6. Encryption - BitLocker protection On for the system drive (fallback manage-bde).
        try {
            $sysDrive = $env:SystemDrive
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $bl = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
                $ps = [string]$bl.ProtectionStatus; $vs = [string]$bl.VolumeStatus
                if ($ps -eq 'On') { & $mk 'Encryption' 'PASS' "$sysDrive protection $ps; $vs" }
                else              { & $mk 'Encryption' 'FAIL' "$sysDrive protection $ps; $vs" }
            } else {
                $out = (& manage-bde -status $sysDrive 2>&1 | Out-String)
                if ($out -match '(?i)Protection\s+Status:\s*Protection\s+On') { & $mk 'Encryption' 'PASS' "$sysDrive Protection On (manage-bde)" }
                else                                                          { & $mk 'Encryption' 'FAIL' "$sysDrive Protection Off/unknown (manage-bde)" }
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

        # 11. Hostname - AFNET/AFNS naming convention (authoritative verdict is ARAD-side).
        try {
            $name = $env:COMPUTERNAME
            $matched = $false
            foreach ($pat in @($hostPatterns)) { if ($name -match $pat) { $matched = $true; break } }
            if ($matched) { & $mk 'Hostname' 'PASS' "$name matches naming convention (authoritative verdict is ARAD-side)" }
            else          { & $mk 'Hostname' 'FAIL' "$name does not match naming convention (authoritative verdict is ARAD-side)" }
        } catch { & $mk 'Hostname' 'ERROR' $_.Exception.Message }

        return @{ RemoteName = $env:COMPUTERNAME; Checks = @($checks) }
    }

    try {
        $probe = Invoke-Command -Session $sess -ScriptBlock $probeSb -ArgumentList @($taniumService, $sigMaxAge, $secAgents, $hostPatterns, $dodRoots, $TaniumInstalledSrc) -ErrorAction Stop
    } catch {
        $r.Status = 'ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    # DNS-mismatch guard (read-only soft-warn, wpt/biosfirmware idiom): a wrong box
    # would report the wrong readiness. Session name compare, never a PTR lookup.
    $actualName  = ([string]$probe.RemoteName).Trim()
    $targetShort = ($Computer -split '\.')[0]
    if ($actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
        $r.Status = 'DNS MISMATCH'; $r.Detail = "dialed '$targetShort' but remote is '$actualName' - skipped (would report the wrong machine)"
        return $r
    }

    $checks = @($probe.Checks)
    $r.Checks = $checks
    if ($checks.Count -eq 0) { $r.Status = 'ERROR'; $r.Detail = 'probe returned no checks'; return $r }

    # Verdict: count FAIL / ERROR across the returned checks. The 2 always-EXT pillars
    # (Vuln, COAMS) and an EXT PkiRoots contribute 0 FAIL / 0 ERROR by construction, so
    # a plain FAIL/ERROR tally already honours "EXT is shown but never scored".
    $failNames = @($checks | Where-Object { $_.Status -eq 'FAIL'  } | ForEach-Object { [string]$_.Name })
    $errNames  = @($checks | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { [string]$_.Name })
    $extNames  = @($checks | Where-Object { $_.Status -eq 'EXT'   } | ForEach-Object { [string]$_.Name })
    $fail = $failNames.Count; $err = $errNames.Count

    if     ($fail -ge 1) { $r.Status = 'QUARANTINE RISK'; $r.Ok = $false }
    elseif ($err  -ge 1) { $r.Status = 'CHECK ERRORS';    $r.Ok = $false }
    else                 { $r.Status = 'READY';           $r.Ok = $true  }

    $parts = New-Object System.Collections.ArrayList
    if ($fail -ge 1) { [void]$parts.Add("$fail FAIL: $($failNames -join ', ')") }
    if ($err  -ge 1) { [void]$parts.Add("$err ERROR: $($errNames -join ', ')") }
    if ($fail -eq 0 -and $err -eq 0) { [void]$parts.Add('all 9 scored pillars pass') }
    if ($extNames.Count -gt 0) { [void]$parts.Add("EXT: $($extNames -join ', ')") }
    $r.Detail = ($parts -join ' | ')

    # Full 11-line colour-tagged report ([PASS]/[FAIL]/[EXT]/[ERROR]) the view colours.
    $rptLines = foreach ($c in $checks) { '[{0}] {1}: {2}' -f ([string]$c.Status), ('{0,-12}' -f [string]$c.Name), ([string]$c.Detail) }
    $r.Report = ($rptLines -join "`r`n")
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

# --- Per-host Mass Fix worker (runs in a pool runspace) ----------------------
# Returns @{ Host; Ping; Status; Detail; Report; Pillars }. All enabled pillar
# fixes run inside ONE Invoke-Command round-trip (fix-then-verify); the host-level
# status is computed here (admin-side).
$script:C2cFixBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string[]]$Pillars, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [bool]$WinrmHeal, [string]$WinrmHealSrc, [string]$AddCertsSrc)

    # Per-host pillar set (may differ per host in run-all). Normalize to a clean
    # [string] array even if a single-element array crossed a boundary as a scalar.
    $Pillars = @(@($Pillars) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
    if ([string]::IsNullOrWhiteSpace($TaniumService)) { $TaniumService = 'Tanium Client' }

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Report=''; Pillars=@() }

    # TCP reachability (WinRM 5985 then SMB 445, 1.5s). Never ICMP.
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port" }
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
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = (@('No TCP on 5985/445 (1.5s timeouts). Enable "Attempt even if offline" to force.', $healNote) | Where-Object { $_ }) -join ' | '; return $r }
    }

    $wsOpt = New-PSSessionOption -OperationTimeout 280000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
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
        param([string]$PillarCsv, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [string]$AddCertsSrc)
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
                    # netsh fallback (no NetSecurity module).
                    $parse = {
                        param($txt)
                        $curProf=''; $dis = New-Object System.Collections.ArrayList
                        foreach ($ln in ($txt -split "`r?`n")) {
                            if     ($ln -match '^(Domain|Private|Public)\s+Profile') { $curProf = $Matches[1] }
                            elseif ($ln -match '^State\s+(\S+)') { if ($Matches[1] -notmatch '^(?i:on)$' -and $curProf) { [void]$dis.Add($curProf) } }
                        }
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

        # 1. Encryption - by default RESUME suspended protectors only. When the
        #    operator opts in (DoEnable) and the OS volume is FullyDecrypted, ENABLE
        #    BitLocker mirroring the enterprise USAF script, escrow-first / fail-closed
        #    (FVE policy assert -> reuse/add RecoveryPassword protector -> Entra-first /
        #    AD-fallback escrow BEFORE Enable-BitLocker; TPM-gated + domain-joined;
        #    XtsAes256; recovery password NEVER emitted).
        if ($Pillars -contains 'Encryption') {
            try {
                $sys = $env:SystemDrive
                if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                    $bl = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop
                    $ps = [string]$bl.ProtectionStatus; $vs = [string]$bl.VolumeStatus
                    if ($ps -eq 'On') {
                        & $add 'Encryption' 'none' 'NOCHANGE' "$sys protection already On; $vs"
                    } elseif ($vs -match '(?i)EncryptionInProgress') {
                        $pctIP = ''
                        try { $pctIP = [string]$bl.EncryptionPercentage } catch {}
                        & $add 'Encryption' 'none' 'IN PROGRESS' "encryption already in progress ($pctIP% done); protection activates on completion - no action taken"
                    } elseif ($vs -match '(?i)FullyDecrypted') {
                        if (-not $DoEnable) {
                            & $add 'Encryption' 'none' 'SKIP' "not encrypted ($vs) - BitLocker enable needs TPM+recovery-key escrow policy; route to MECM/desk-side"
                        } else {
                            # ENABLE path - each precondition failing => SKIP, nothing changed.
                            $volType = ''
                            try { $volType = [string]$bl.VolumeType } catch {}
                            if ($volType -and ($volType -ne 'OperatingSystem')) {
                                & $add 'Encryption' 'none' 'SKIP' "$sys is not the OS volume (VolumeType=$volType) - enable only targets the OS volume"
                            } else {
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
                                if (-not $tpmOk) {
                                    & $add 'Encryption' 'none' 'SKIP' $tpmWhy
                                } else {
                                    $domainJoined = $false
                                    try { $domainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $domainJoined = $false }
                                    if (-not $domainJoined) {
                                        & $add 'Encryption' 'none' 'SKIP' 'machine not domain-joined - AD recovery-password escrow unavailable; route to desk-side/MECM'
                                    } else {
                                        # Mirror the enterprise USAF enable script (fail-closed by our design):
                                        #   1. assert FVE policy  2. reuse-or-add a RecoveryPassword protector
                                        #   3. escrow Entra-first, AD fallback  4. Enable-BitLocker.
                                        # Never emit/return the recovery password - do not touch .RecoveryPassword.

                                        # ---- Step 1: assert FVE policy (idempotent). Policy is what enforces the
                                        #      recovery-key escrow + XtsAes256 method - never encrypt without it. A write
                                        #      failure FAILs the pillar and enable is NOT attempted.
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

                                        if ($polErr) {
                                            & $add 'Encryption' 'enable' 'FAIL' "FVE policy assert failed: $polErr"
                                        } else {
                                            $polTxt = "FVE policy: $polSet set/corrected, $polOk already-correct"
                                            # ---- Step 2: REUSE an existing RecoveryPassword protector if one exists;
                                            #      only Add one when none is present (track whether WE added it).
                                            $weAdded = $false; $newKpId = ''; $encFail = ''
                                            try {
                                                $existingRp = @()
                                                try { $existingRp = @($bl.KeyProtector | Where-Object { [string]$_.KeyProtectorType -match '(?i)RecoveryPassword' }) } catch { $existingRp = @() }
                                                if ($existingRp.Count -gt 0) {
                                                    $newKpId = [string]$existingRp[0].KeyProtectorId
                                                } else {
                                                    $beforeIds = @()
                                                    try { foreach ($k in @($bl.KeyProtector)) { $beforeIds += [string]$k.KeyProtectorId } } catch {}
                                                    $addRet = Add-BitLockerKeyProtector -MountPoint $sys -RecoveryPasswordProtector -ErrorAction Stop
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
                                                $encFail = "recovery-password protector add failed - encryption NOT started: $($_.Exception.Message)"
                                            }

                                            if ($encFail) {
                                                & $add 'Encryption' 'enable' 'FAIL' $encFail
                                            } else {
                                                # ---- Step 3: escrow FAIL-CLOSED, Entra first then on-prem AD. Record which
                                                #      target took the key. If BOTH fail: remove the protector only if WE added
                                                #      it this run (a pre-existing protector is never removed), then FAIL.
                                                $escrowOk = $false; $escrowTarget = ''
                                                try {
                                                    if (Get-Command BackupToAAD-BitLockerKeyProtector -ErrorAction SilentlyContinue) {
                                                        try {
                                                            BackupToAAD-BitLockerKeyProtector -MountPoint $sys -KeyProtectorId $newKpId -ErrorAction Stop | Out-Null
                                                            $escrowOk = $true; $escrowTarget = 'Entra'
                                                        } catch { $escrowOk = $false }
                                                    }
                                                    if (-not $escrowOk) {
                                                        Backup-BitLockerKeyProtector -MountPoint $sys -KeyProtectorId $newKpId -ErrorAction Stop | Out-Null
                                                        $escrowOk = $true; $escrowTarget = 'AD'
                                                    }
                                                } catch { $escrowOk = $false }

                                                if (-not $escrowOk) {
                                                    if ($weAdded) { try { if ($newKpId) { Remove-BitLockerKeyProtector -MountPoint $sys -KeyProtectorId $newKpId -ErrorAction SilentlyContinue | Out-Null } } catch {} }
                                                    & $add 'Encryption' 'enable' 'FAIL' 'escrow failed (Entra + AD) - encryption NOT started'
                                                } else {
                                                    # ---- Step 4: escrow confirmed -> start FULL-volume encryption (TPM protector, XtsAes256).
                                                    try {
                                                        Enable-BitLocker -MountPoint $sys -TpmProtector -EncryptionMethod XtsAes256 -SkipHardwareTest -ErrorAction Stop | Out-Null
                                                        Start-Sleep -Milliseconds 500
                                                        $blE = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop
                                                        $vsE = [string]$blE.VolumeStatus
                                                        $pctE = ''
                                                        try { $pctE = [string]$blE.EncryptionPercentage } catch {}
                                                        if ($vsE -match '(?i)FullyDecrypted') {
                                                            & $add 'Encryption' 'enable' 'FAIL' 'Enable-BitLocker returned but volume still FullyDecrypted - encryption did not start'
                                                        } else {
                                                            & $add 'Encryption' 'enable' 'STARTED' "encryption started (XtsAes256, TPM+RecoveryPassword escrowed to $escrowTarget) - $pctE% done; $polTxt; protection activates on completion; Tanium clears after next scan"
                                                        }
                                                    } catch {
                                                        & $add 'Encryption' 'enable' 'FAIL' "escrow succeeded but Enable-BitLocker failed: $($_.Exception.Message)"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } elseif ($vs -match '(?i)Decrypt') {
                        & $add 'Encryption' 'none' 'SKIP' "not encrypted ($vs) - route to MECM/desk-side"
                    } else {
                        # Off + FullyEncrypted (classic post-firmware suspended-protectors) -> resume.
                        $act = 'Resume-BitLocker'
                        try { Resume-BitLocker -MountPoint $sys -ErrorAction Stop | Out-Null }
                        catch { $act = 'manage-bde -protectors -enable'; & manage-bde -protectors -enable $sys 2>&1 | Out-Null }
                        Start-Sleep -Milliseconds 500
                        $bl2 = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop
                        if ([string]$bl2.ProtectionStatus -eq 'On') { & $add 'Encryption' $act 'FIXED' "protection resumed -> On; $($bl2.VolumeStatus)" }
                        elseif ($vs -match '(?i)FullyEncrypted')     { & $add 'Encryption' $act 'FAIL' "resume attempted but protection still $($bl2.ProtectionStatus)" }
                        else { & $add 'Encryption' $act 'SKIP' "protection $($bl2.ProtectionStatus); volume $($bl2.VolumeStatus) - not a resumable state; route to MECM/desk-side" }
                    }
                } else {
                    $out = (& manage-bde -status $sys 2>&1 | Out-String)
                    if ($out -match '(?i)Protection\s+Status:\s*Protection\s+On') { & $add 'Encryption' 'none' 'NOCHANGE' 'protection already On (manage-bde)' }
                    elseif ($out -match '(?i)Fully\s+Encrypted') {
                        & manage-bde -protectors -enable $sys 2>&1 | Out-Null
                        Start-Sleep -Milliseconds 500
                        $out2 = (& manage-bde -status $sys 2>&1 | Out-String)
                        if ($out2 -match '(?i)Protection\s+Status:\s*Protection\s+On') { & $add 'Encryption' 'manage-bde -protectors -enable' 'FIXED' 'protectors enabled -> On (manage-bde)' }
                        else { & $add 'Encryption' 'manage-bde -protectors -enable' 'FAIL' 'enable attempted but still Off (manage-bde)' }
                    } else { & $add 'Encryption' 'none' 'SKIP' 'not FullyEncrypted - route to MECM/desk-side (manage-bde)' }
                }
            } catch { & $add 'Encryption' 'error' 'FAIL' $_.Exception.Message }
        }

        # 2. AntiMalware - heal Defender services / RTP / signatures. Missing MDE
        #    Sense is a note, not a failure, when Defender itself is healthy.
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
                    $mp = Get-MpComputerStatus -ErrorAction Stop
                    if (-not $mp.RealTimeProtectionEnabled) {
                        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; [void]$changed.Add('RTP enabled') }
                        catch { $failDet += "RTP enable failed: $($_.Exception.Message); " }
                    }
                    if ([int]$mp.AntivirusSignatureAge -gt 7) {
                        try { Update-MpSignature -ErrorAction Stop; [void]$changed.Add('signatures updated') }
                        catch { $failDet += "sig update failed: $($_.Exception.Message); " }
                    }
                    Start-Sleep -Milliseconds 300
                    $mp2 = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    $rtpNow = if ($mp2) { [bool]$mp2.RealTimeProtectionEnabled } else { [bool]$mp.RealTimeProtectionEnabled }
                    $ageNow = if ($mp2) { [int]$mp2.AntivirusSignatureAge } else { [int]$mp.AntivirusSignatureAge }
                    $noteTxt = if ($notes.Count -gt 0) { '; ' + ($notes -join '; ') } else { '' }
                    if ($failDet)               { & $add 'AntiMalware' 'heal' 'FAIL' ($failDet.TrimEnd('; ') + $noteTxt) }
                    elseif ($changed.Count -gt 0) { & $add 'AntiMalware' 'heal' 'FIXED' (($changed -join '; ') + "; RTP=$rtpNow sigAge=${ageNow}d" + $noteTxt) }
                    else                        { & $add 'AntiMalware' 'none' 'NOCHANGE' ("RTP on; sig age ${ageNow}d" + $noteTxt) }
                } else {
                    if ($changed.Count -gt 0) { & $add 'AntiMalware' 'heal' 'FIXED' (($changed -join '; ') + '; Get-MpComputerStatus unavailable') }
                    else { & $add 'AntiMalware' 'none' 'SKIP' ('Get-MpComputerStatus unavailable (non-Defender AV?)' + $(if ($notes.Count) { '; ' + ($notes -join '; ') } else { '' })) }
                }
            } catch { & $add 'AntiMalware' 'error' 'FAIL' $_.Exception.Message }
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
                           elseif ([string]$ar.FailDetail) { 'FAIL' } elseif ([int]$ar.Added -gt 0) { 'FIXED' } else { 'NOCHANGE' }
                    if ($tok -eq 'FAIL') {
                        & $add 'PkiRoots' 'addstore' 'FAIL' ("added $($ar.Added) of $($ar.Total); errors: " + ([string]$ar.FailDetail).TrimEnd('; ') + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    } elseif ($tok -eq 'FIXED') {
                        & $add 'PkiRoots' 'addstore' 'FIXED' ("added $($ar.Added) of $($ar.Total) across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    } else {
                        & $add 'PkiRoots' 'none' 'NOCHANGE' ("all $($ar.Total) already present across Root/CA/Disallowed" + $(if ($storeTxt) { " [$storeTxt]" } else { '' }))
                    }
                }
            } catch { & $add 'PkiRoots' 'error' 'FAIL' $_.Exception.Message }
        }

        return @{ RemoteName = $env:COMPUTERNAME; Pillars = @($results) }
    }

    try {
        # Pass the pillar set as a '|'-delimited string (all-scalar ArgumentList) so it
        # crosses the WinRM boundary intact; the remote block splits it back to an array.
        $fix = Invoke-Command -Session $sess -ScriptBlock $fixSb -ArgumentList ($Pillars -join '|'), $DoEnable, $TaniumService, $TaniumInstalledSrc, $BundleJson, $AddCertsSrc -ErrorAction Stop
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
    $r.Pillars = $pillarResults
    if ($pillarResults.Count -eq 0) { $r.Status = 'NO CHANGE'; $r.Detail = 'no enabled pillars returned a result'; return $r }

    # STARTED (BitLocker encryption kicked off) rolls up like FIXED for the host verdict.
    $fixed  = @($pillarResults | Where-Object { $_.Result -eq 'FIXED' -or $_.Result -eq 'STARTED' }).Count
    $failed = @($pillarResults | Where-Object { $_.Result -eq 'FAIL'   }).Count
    $tot    = $pillarResults.Count
    if     ($fixed -ge 1 -and $failed -eq 0)   { $r.Status = 'FIXED' }
    elseif ($failed -ge 1 -and $failed -eq $tot) { $r.Status = 'FAILED' }
    elseif ($failed -ge 1)                     { $r.Status = 'PARTIAL' }
    else                                       { $r.Status = 'NO CHANGE' }

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
            default                { [string]$res }
        }
    }

    $r.Detail = (@($pillarResults | ForEach-Object { "$($_.Name): $(& $labelOf $_.Name $_.Result)" }) -join '; ')
    $rptLines = foreach ($p in $pillarResults) { '[{0}] {1}: {2}' -f (& $labelOf $p.Name $p.Result), ('{0,-12}' -f [string]$p.Name), ([string]$p.Detail) }
    $r.Report = ($rptLines -join "`r`n")
    return $r
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
    $parsed = ConvertFrom-C2cComplianceCsv -Paths $paths -Text $csvText -Send $send
    $recs = @($parsed.Records)
    if ($recs.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text="Parsed $($parsed.RowCount) row(s) but resolved no hosts - check the CSV headers (a 'Compliance' column and a 'Computer Name' column)." }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $rows = New-Object System.Collections.ArrayList
    foreach ($rec in ($recs | Sort-Object { $_.Short })) {
        $row = @{ Host=$rec.Short; Compliance=$rec.Compliance; Failed=(@($rec.Failed) -join ', '); Audit=(@($rec.Audit) -join ', '); Fqdn=$rec.Fqdn }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
    }

    $total            = $recs.Count
    $nonCompliantRecs = @($recs | Where-Object { $_.Compliance -match '(?i)^Non-?Compliant' })
    $nonCompliant     = $nonCompliantRecs.Count
    $compliant        = $total - $nonCompliant
    $nonCompliantHosts = @($nonCompliantRecs | ForEach-Object { $_.Short } | Sort-Object -Unique)

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

    & $send @{ type='log'; level='ok'; text="Imported $total host(s): $compliant Compliant, $nonCompliant Non-Compliant." }
    $pillars = New-Object System.Collections.ArrayList
    foreach ($p in $ordered) {
        $hosts = @($pillarHosts[$p])
        $route = Get-C2cPillarRouting $p
        [void]$pillars.Add(@{ name=$p; failedCount=$hosts.Count; hosts=$hosts; routing=$route })
        & $send @{ type='log'; level='info'; text=("{0}: {1} host(s) -> {2}" -f $p, $hosts.Count, $route) }
    }

    # Run-all plan: each non-compliant host + ONLY its endpoint-fixable failed pillars,
    # exactly the JSON the view hands to the 'run-all' action verbatim. Hosts whose only
    # failures route elsewhere (Vuln/OSVersion/STIG) carry no fixable pillars -> omitted.
    $runAllPlan = New-Object System.Collections.ArrayList
    foreach ($rec in ($recs | Sort-Object { $_.Short })) {
        $fx = @(@($rec.Failed) | Where-Object { $script:C2cFixablePillars -contains $_ })
        if ($fx.Count -gt 0) { [void]$runAllPlan.Add(@{ host=$rec.Short; pillars=@($fx) }) }
    }
    & $send @{ type='log'; level='info'; text=("Run-all plan: {0} host(s) with >=1 endpoint-fixable pillar." -f $runAllPlan.Count) }

    & $send @{ type='status'; text="Done. $total host(s) imported ($nonCompliant non-compliant)." }
    return @{ rows=@($rows); summary=@{ total=$total; compliant=$compliant; nonCompliant=$nonCompliant; nonCompliantHosts=@($nonCompliantHosts); pillars=@($pillars); runAllPlan=@($runAllPlan) } }
}

$script:C2cPillarByAction = @{
    'fix-monitoring'  = 'Monitoring'
    'fix-firewall'    = 'Firewall'
    'fix-antimalware' = 'AntiMalware'
    'fix-patches'     = 'Patches'
    'fix-encryption'  = 'Encryption'
    'fix-pki'         = 'PkiRoots'
}

# --- Admin-side cert-bundle reader (fix-pki) ---------------------------------
# Reads a DoD trust bundle folder ONCE, before any host is dialed. Enumerates
# (case-insensitive on Windows) <folder>\root\*.cer -> Root, <folder>\Intermediate\*.cer
# -> CA, <folder>\Untrusted\*.cer -> Disallowed, and loose <folder>\*.cer -> Root.
# Each .cer is loaded into an X509Certificate2 and captured as thumbprint + base64
# (base64 crosses the WinRM boundary cleanly). Returns
# @{ Ok; Error; Root=@(@{Thumbprint;B64;File}); CA=@(...); Disallowed=@(...); CertCount; FileCount; Folder }.
# Ok=$false with a populated Error if the folder is missing or yields ZERO certs.
function Get-C2cCertBundle {
    param([string]$Folder)
    $res = @{ Ok=$false; Error=''; Root=@(); CA=@(); Disallowed=@(); CertCount=0; FileCount=0; Folder='' }
    $f = ([string]$Folder).Trim().Trim('"')
    $res.Folder = $f
    if (-not $f) { $res.Error = 'no cert bundle folder provided'; return $res }
    if (-not (Test-Path -LiteralPath $f)) { $res.Error = "cert bundle folder not found: $f"; return $res }
    $groups = @{
        Root       = New-Object System.Collections.ArrayList
        CA         = New-Object System.Collections.ArrayList
        Disallowed = New-Object System.Collections.ArrayList
    }
    $loadCer = {
        param($file, $store)
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($file)
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
    $total = $groups.Root.Count + $groups.CA.Count + $groups.Disallowed.Count
    if ($total -eq 0) {
        $res.Error = "no .cer certificates found under $f (expected root\*.cer, Intermediate\*.cer, Untrusted\*.cer, or loose *.cer)"
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

    $isRunAll = ($ActionId -eq 'run-all')
    $verb     = if ($isRunAll) { 'C2C Run-All' } else { "C2C $ActionId" }

    # Confirm word - exact 'FIX' (case-sensitive), matching the suite idiom. FIRST gate.
    $confirm = ([string]$Params['confirm']).Trim()
    if ($confirm -cne 'FIX') {
        & $send @{ type='log'; level='err'; text="Confirm word mismatch: type FIX (exactly) to run $verb. Nothing was changed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    $attemptOffline = Get-C2cBool $Params['attemptOffline'] $false
    $doEnable       = Get-C2cBool $Params['enableEncryption'] $false
    $winrmHeal      = Get-C2cBool $Params['winrmHeal'] $false

    # Baseline (fresh) for the Tanium service name used by the Monitoring fixer.
    $baseline = Get-C2cBaseline
    $taniumService = [string]$baseline.Config['taniumService']
    if (-not $taniumService) { $taniumService = 'Tanium Client' }

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

    $rows = New-Object System.Collections.ArrayList     # pre-rows (self-guard, zero-fixable info) + result rows
    $plan = New-Object System.Collections.ArrayList     # [ @{ Host; Pillars=@(...) } ] to dial (pre self-guard)

    if ($isRunAll) {
        # --- Parse + validate the run-all plan JSON --------------------------
        $planRaw = [string]$Params['plan']
        if ([string]::IsNullOrWhiteSpace($planRaw)) {
            & $send @{ type='log'; level='err'; text='Run-all plan is empty. Import a C2C CSV first, then Run All. Nothing was changed.' }
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
            $short = ($eh -split '\.')[0]
            if ($seen.Contains($short)) { continue }   # de-dupe by host (first wins)
            $rawPillars = @()
            try { $rawPillars = @($entry.pillars | ForEach-Object { [string]$_ } | Where-Object { $_ }) } catch { $rawPillars = @() }
            $known   = @($rawPillars | Where-Object { $script:C2cFixablePillars -contains $_ })
            $unknown = @($rawPillars | Where-Object { $script:C2cFixablePillars -notcontains $_ })
            if ($unknown.Count -gt 0) {
                & $send @{ type='log'; level='warn'; text="Run-all: $short - dropped non-endpoint-fixable pillar(s): $($unknown -join ', ') (route to ACAS / Windows Upgrade / Reports)." }
            }
            # PkiRoots needs a cert bundle; without one, skip it for this host (info note).
            if (-not $bundleOk -and ($known -contains 'PkiRoots')) {
                $known = @($known | Where-Object { $_ -ne 'PkiRoots' })
                & $send @{ type='log'; level='info'; text="Run-all: $short - PkiRoots skipped (no valid cert bundle folder supplied); other pillars still run." }
            }
            if ($known.Count -eq 0) {
                $row = @{ Host=$short; Ping=''; Status='SKIPPED'; Detail='nothing endpoint-fixable (Vuln/OSVersion/STIG route elsewhere)' }
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
    } else {
        # --- Per-pillar fix: one pillar, applied to every target -------------
        $pillar = $script:C2cPillarByAction[$ActionId]
        if (-not $pillar) {
            & $send @{ type='error'; text="Unknown fix action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
        $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No valid targets.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        foreach ($t in $targets) { [void]$plan.Add(@{ Host=$t; Pillars=@($pillar) }) }
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
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
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

    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port" }
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
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = (@('No TCP on 5985/445 (1.5s timeouts).', $healNote) | Where-Object { $_ }) -join ' | '; return $r }
    }

    $wsOpt = New-PSSessionOption -OperationTimeout 120000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
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
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
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
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($config); [void]$ps.AddArgument($script:C2cTaniumInstalledSrc)
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
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
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
    $chkErr   = @($rows | Where-Object { $_.Status -eq 'CHECK ERRORS' }).Count
    $offline  = @($rows | Where-Object { $_.Status -eq 'OFFLINE' }).Count
    $other    = $targets.Count - $ready - $risk - $chkErr - $offline
    $pct      = if ($targets.Count -gt 0) { [math]::Round(($ready / $targets.Count) * 100, 1) } else { 0 }

    & $send @{ type='log'; level='ok'; text="C2C readiness - $pct% READY ($ready/$($targets.Count)). QUARANTINE RISK: $risk, CHECK ERRORS: $chkErr, OFFLINE: $offline, Other: $other. (EXT pillars Vuln/COAMS scored server-side.)" }
    & $send @{ type='status'; text="Done. $ready ready, $risk quarantine-risk, $chkErr check-errors, $offline offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; ready=$ready; risk=$risk; checkErrors=$chkErr; offline=$offline; other=$other; readyPct=$pct; source=$baseline.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
