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
        version  = '1.3.0'
        category = 'Reporting'
        summary  = 'C2C Nemesis - Comply-to-Connect (AFI/MPTO rule 3.B.2.B) remediation: (1) IMPORT the Tanium "C2C Compliance Status" CSV export, de-duplicate per host, and bucket each failing rule into a canonical pillar with a routing hint; (2) MASS FIX (destructive) the endpoint-fixable pillars - resume/ENABLE BitLocker (FVE policy assert + Entra-first/AD-fallback recovery-key escrow, XtsAes256), heal Defender/MDE, add DoD PKI roots from an operator .sst, and kick the MECM patch cycle; (3) READ-ONLY quarantine-predictor scan - fan out one consolidated WinRM probe per host, run 11 C2C checks (9 scored, 2 external/server-side), flag each host READY or QUARANTINE RISK. Vuln -> ACAS/Reports/KEV, OS Version -> Windows Upgrade, STIG -> Reports.'
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
                id          = 'fix'
                label       = 'C2C Mass Fix'
                description = 'DESTRUCTIVE. Remediate the endpoint-fixable failing pillars across the targets in one WinRM round-trip per host, fix-then-verify: Encryption (by default resume suspended BitLocker protectors only; if "ENABLE BitLocker" is also ticked, a FullyDecrypted OS volume is encrypted from here - ESCROW-FIRST and FAIL-CLOSED, mirroring the enterprise USAF enable script: assert the FVE BitLocker policy on the host (recovery-key escrow + XtsAes256 method), reuse-or-add a RecoveryPassword protector, then escrow it Entra-first (BackupToAAD-BitLockerKeyProtector) with on-prem AD fallback (Backup-BitLockerKeyProtector) BEFORE any Enable-BitLocker, TPM-gated (TpmPresent+TpmReady) and domain-joined only, then Enable-BitLocker with a TPM protector and XtsAes256 full-volume encryption; if BOTH escrow paths fail the RecoveryPassword protector we added is removed and encryption is NEVER started; the recovery password is never emitted), AntiMalware (heal Defender services/RTP/signatures; note missing MDE Sense), PkiRoots (add DoD roots from an operator .sst - additive only, never removes), and Patches (kick the MECM Software Updates scan + eval cycles). Self-guards the dispatcher host, aborts on a DNS wrong-box mismatch, and requires the operator to type FIX to confirm.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Run the C2C Mass Fix on the target host(s)? This changes machines. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='fixEncryption';  label='Encryption: resume suspended BitLocker'; type='bool'; required=$false; default=$true },
                    @{ name='enableEncryption'; label='Encryption: ENABLE BitLocker on decrypted volumes (TPM+RecoveryPassword->AD escrow, XtsAes256)'; type='bool'; required=$false; default=$false },
                    @{ name='fixDefender';    label='AntiMalware: heal Defender / MDE'; type='bool'; required=$false; default=$true },
                    @{ name='fixPki';         label='PKI roots: add DoD roots from .sst'; type='bool'; required=$false; default=$false },
                    @{ name='sstPath';        label='DoD root bundle (.sst) - required if PKI roots is ticked'; type='file'; filter='SST files (*.sst)|*.sst|Cert bundles (*.sst;*.p7b)|*.sst;*.p7b|All files (*.*)|*.*'; required=$false },
                    @{ name='kickPatchCycle'; label='Patches: kick the MECM patch cycle (scan + eval)'; type='bool'; required=$false; default=$true },
                    @{ name='confirm';        label='Type FIX to confirm'; type='text'; required=$true },
                    @{ name='threads';        label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 },
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

# --- Per-host probe worker (runs in a pool runspace; no module scope here) ---
# Returns @{ Host; Ping; Status; Detail; Ok; Report; Checks }. All 11 checks run
# inside ONE Invoke-Command round-trip; the verdict is computed here (admin-side).
$script:C2cProbeBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, $Config)

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
        param($taniumService, $sigMaxAge, $secAgents, $hostPatterns, $dodRoots)
        # Normalize the array args: an empty collection can cross the WinRM ArgumentList
        # boundary as $null, and @($null) is a 1-element array holding $null (a stray
        # $null host-pattern would be an empty regex that matches EVERYTHING -> a false
        # PASS). Drop null/blank elements so every list is a clean [string] array.
        $secAgents    = @(@($secAgents)    | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $hostPatterns = @(@($hostPatterns) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $dodRoots     = @(@($dodRoots)     | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        $checks = New-Object System.Collections.ArrayList
        $mk = { param($n,$s,$d) [void]$checks.Add([pscustomobject]@{ Name=$n; Status=$s; Detail=[string]$d }) }

        # 1. Monitoring - Tanium client service running (endpoint monitoring installed).
        try {
            $svc = Get-Service -Name $taniumService -ErrorAction SilentlyContinue
            if (-not $svc)                      { & $mk 'Monitoring' 'FAIL' "service '$taniumService' not installed" }
            elseif ($svc.Status -eq 'Running')  { & $mk 'Monitoring' 'PASS' "'$taniumService' Running" }
            else                                { & $mk 'Monitoring' 'FAIL' "'$taniumService' $($svc.Status)" }
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
        $probe = Invoke-Command -Session $sess -ScriptBlock $probeSb -ArgumentList @($taniumService, $sigMaxAge, $secAgents, $hostPatterns, $dodRoots) -ErrorAction Stop
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
    Encryption  = 'fixable HERE (Mass Fix: resume BitLocker)'
    AntiMalware = 'fixable HERE (Mass Fix: heal Defender / MDE)'
    PkiRoots    = 'fixable HERE (Mass Fix: add DoD roots from operator .sst)'
    Patches     = 'endpoint-kickable HERE (Mass Fix: trigger MECM scan / eval)'
    Vuln        = 'ACAS / Reports / KEV tools'
    OSVersion   = 'Windows Upgrade tool'
    STIG        = 'Reports / STIG'
}
$script:C2cFixablePillars = @('Encryption','AntiMalware','PkiRoots','Patches')
# Stable display order for the summary; unknown pillars append alphabetically.
$script:C2cPillarOrder = @('Encryption','AntiMalware','PkiRoots','Patches','Vuln','OSVersion','STIG')

# Map a rule name (already stripped of its "Failed/Audit Rule[ N] - " prefix) to a
# canonical pillar. Unknown names return verbatim (their own stripped name).
function Get-C2cCanonicalPillar {
    param([string]$Stripped)
    $s = ([string]$Stripped).Trim()
    switch -Regex ($s) {
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
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [bool]$DoEnc, [bool]$DoDef, [bool]$DoPki, [bool]$DoPatch, [bool]$DoEnable, [string]$SstB64)

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
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'; return $r }
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
        param([bool]$DoEnc, [bool]$DoDef, [bool]$DoPki, [bool]$DoPatch, [bool]$DoEnable, [string]$SstB64)
        $results = New-Object System.Collections.ArrayList
        $add = { param($n,$a,$res,$d) [void]$results.Add([pscustomobject]@{ Name=$n; Action=[string]$a; Result=[string]$res; Detail=[string]$d }) }

        # 1. Encryption - by default RESUME suspended protectors only. When the
        #    operator opts in (DoEnable) and the OS volume is FullyDecrypted, ENABLE
        #    BitLocker mirroring the enterprise USAF script, escrow-first / fail-closed
        #    (FVE policy assert -> reuse/add RecoveryPassword protector -> Entra-first /
        #    AD-fallback escrow BEFORE Enable-BitLocker; TPM-gated + domain-joined;
        #    XtsAes256; recovery password NEVER emitted).
        if ($DoEnc) {
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
        if ($DoDef) {
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

        # 3. PkiRoots - add DoD roots from the operator .sst. Additive only.
        if ($DoPki -and $SstB64) {
            $store = $null
            try {
                $bytes = [Convert]::FromBase64String($SstB64)
                $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $col.Import($bytes)
                $total = $col.Count
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root','LocalMachine'
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $present = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($c in $store.Certificates) { [void]$present.Add([string]$c.Thumbprint) }
                $added = 0
                foreach ($c in $col) { if (-not $present.Contains([string]$c.Thumbprint)) { $store.Add($c); $added++ } }
                $store.Close(); $store = $null
                if ($added -gt 0) { & $add 'PkiRoots' 'add-roots' 'FIXED' "added $added of $total root(s) to LocalMachine\Root" }
                else              { & $add 'PkiRoots' 'none' 'NOCHANGE' "all $total root(s) already present" }
            } catch { if ($store) { try { $store.Close() } catch {} }; & $add 'PkiRoots' 'error' 'FAIL' $_.Exception.Message }
        }

        # 4. Patches - kick the MECM Software Updates scan (113) then eval (108).
        if ($DoPatch) {
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

        return @{ RemoteName = $env:COMPUTERNAME; Pillars = @($results) }
    }

    try {
        $fix = Invoke-Command -Session $sess -ScriptBlock $fixSb -ArgumentList @($DoEnc, $DoDef, $DoPki, $DoPatch, $DoEnable, $SstB64) -ErrorAction Stop
    } catch {
        $r.Status = 'FAILED'; $r.Detail = "Fix: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    $pillars = @($fix.Pillars)
    $r.Pillars = $pillars
    if ($pillars.Count -eq 0) { $r.Status = 'NO CHANGE'; $r.Detail = 'no enabled pillars returned a result'; return $r }

    # STARTED (BitLocker encryption kicked off) rolls up like FIXED for the host verdict.
    $fixed  = @($pillars | Where-Object { $_.Result -eq 'FIXED' -or $_.Result -eq 'STARTED' }).Count
    $failed = @($pillars | Where-Object { $_.Result -eq 'FAIL'   }).Count
    $tot    = $pillars.Count
    if     ($fixed -ge 1 -and $failed -eq 0)   { $r.Status = 'FIXED' }
    elseif ($failed -ge 1 -and $failed -eq $tot) { $r.Status = 'FAILED' }
    elseif ($failed -ge 1)                     { $r.Status = 'PARTIAL' }
    else                                       { $r.Status = 'NO CHANGE' }

    $r.Detail = (@($pillars | ForEach-Object { "$($_.Name): $($_.Result)" }) -join '; ')
    $rptLines = foreach ($p in $pillars) { '[{0}] {1}: {2}' -f ([string]$p.Result), ('{0,-12}' -f [string]$p.Name), ([string]$p.Detail) }
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

    & $send @{ type='status'; text="Done. $total host(s) imported ($nonCompliant non-compliant)." }
    return @{ rows=@($rows); summary=@{ total=$total; compliant=$compliant; nonCompliant=$nonCompliant; nonCompliantHosts=@($nonCompliantHosts); pillars=@($pillars) } }
}

# --- Action: fix (DESTRUCTIVE) ----------------------------------------------
function Invoke-C2cFixAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Confirm word - exact 'FIX' (case-sensitive), matching the suite idiom.
    $confirm = ([string]$Params['confirm']).Trim()
    if ($confirm -cne 'FIX') {
        & $send @{ type='log'; level='err'; text="Confirm word mismatch: type FIX (exactly) to run the mass fix. Nothing was changed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    # Targets: bare host/IPv4 tokens only (same regex as scan).
    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $fixEnc    = Get-C2cBool $Params['fixEncryption'] $true
    $doEnable  = Get-C2cBool $Params['enableEncryption'] $false
    $fixDef    = Get-C2cBool $Params['fixDefender']   $true
    $fixPki    = Get-C2cBool $Params['fixPki']        $false
    $kickPatch = Get-C2cBool $Params['kickPatchCycle'] $true
    $attemptOffline = Get-C2cBool $Params['attemptOffline'] $false
    if (-not ($fixEnc -or $fixDef -or $fixPki -or $kickPatch)) {
        & $send @{ type='log'; level='err'; text='No fix pillars enabled - tick at least one (Encryption / AntiMalware / PKI roots / Patches). Nothing was changed.' }
        return @{ rows=@(); summary=@{ total=$targets.Count; rejected=$true } }
    }

    # PKI: read + validate the .sst ADMIN-SIDE, ONCE, before any host is dialed.
    $sstB64 = ''
    if ($fixPki) {
        $sstPath = ([string]$Params['sstPath']).Trim().Trim('"')
        if (-not $sstPath) {
            & $send @{ type='log'; level='err'; text='PKI roots selected but no .sst file provided. Untick PKI or attach a DoD root bundle (.sst). Nothing was changed.' }
            return @{ rows=@(); summary=@{ total=$targets.Count; rejected=$true } }
        }
        if (-not (Test-Path -LiteralPath $sstPath)) {
            & $send @{ type='log'; level='err'; text="PKI .sst not found: $sstPath. Nothing was changed." }
            return @{ rows=@(); summary=@{ total=$targets.Count; rejected=$true } }
        }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($sstPath)
            $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $col.Import($bytes)
            if ($col.Count -eq 0) { throw 'no certificates found in the file' }
            $sstB64 = [Convert]::ToBase64String($bytes)
            & $send @{ type='log'; level='info'; text="PKI: loaded $($col.Count) certificate(s) from $(Split-Path -Leaf $sstPath)." }
        } catch {
            & $send @{ type='log'; level='err'; text="PKI .sst failed to load ($($_.Exception.Message)) - ABORTED before any host was touched." }
            return @{ rows=@(); summary=@{ total=$targets.Count; rejected=$true } }
        }
    }

    # Self-guard: drop the dispatcher host, log a SKIPPED row for each.
    $rows = New-Object System.Collections.ArrayList
    $selfSkipped = New-Object System.Collections.ArrayList
    $nonSelf     = New-Object System.Collections.ArrayList
    foreach ($t in $targets) { if (Test-JanetC2cHostIsSelf $t) { [void]$selfSkipped.Add($t) } else { [void]$nonSelf.Add($t) } }
    foreach ($s in $selfSkipped) {
        $row = @{ Host=$s; Ping=''; Status='SKIPPED'; Detail='self-guard: dispatcher/local host - refused (a self-fix could disrupt the JANET server mid-run)' }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
    }
    if ($selfSkipped.Count -gt 0) {
        & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host ($($selfSkipped -join ', '))." }
    }
    $targets = @($nonSelf.ToArray())
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='Only target was this dispatcher host - nothing to run.' }
        return @{ rows=@($rows); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
    }

    $threads = 8
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(16, $threads))
    $perHostTimeout = 300
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }
    $enabledList = @()
    if ($fixEnc)    { $enabledList += $(if ($doEnable) { 'Encryption(resume+ENABLE)' } else { 'Encryption(resume)' }) }
    if ($fixDef)    { $enabledList += 'AntiMalware' }
    if ($fixPki)    { $enabledList += 'PkiRoots' }
    if ($kickPatch) { $enabledList += 'Patches' }

    & $send @{ type='status'; text="C2C Mass Fix on $($targets.Count) host(s) with $threads thread(s): $($enabledList -join ', ')..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START C2C Mass Fix on $($targets.Count) host(s) ($authLabel), pillars: $($enabledList -join ', ')." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:C2cFixBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline)
        [void]$ps.AddArgument($fixEnc); [void]$ps.AddArgument($fixDef); [void]$ps.AddArgument($fixPki); [void]$ps.AddArgument($kickPatch); [void]$ps.AddArgument($doEnable); [void]$ps.AddArgument($sstB64)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $emitResult = {
        param($res)
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        # JANET audit: a Mass Fix is a security-state change.
        $auditResult = switch ($row.Status) { 'FIXED' {'Success'} 'PARTIAL' {'Success'} 'NO CHANGE' {'Skipped'} 'SKIPPED' {'Skipped'} 'OFFLINE' {'Skipped'} default {'Failure'} }
        $itemCount   = if ($row.Status -eq 'FIXED' -or $row.Status -eq 'PARTIAL') { 1 } else { 0 }
        & $send @{ type='audit'; action='VulnPatched'; target=$row.Host; result=$auditResult; itemCount=$itemCount; detail=$row.Detail }
        $rpt = ''
        try { $rpt = [string]$res.Report } catch { $rpt = '' }
        if ($rpt) {
            & $send @{ type='log'; level='info'; text="----- $([string]$res.Host) : $([string]$res.Status) -----" }
            foreach ($ln in ($rpt -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                $lvl = 'info'
                if     ($ln -match '^\s*\[FIXED\]')       { $lvl = 'ok' }
                elseif ($ln -match '^\s*\[STARTED\]')     { $lvl = 'ok' }
                elseif ($ln -match '^\s*\[NOCHANGE\]')    { $lvl = 'info' }
                elseif ($ln -match '^\s*\[IN PROGRESS\]') { $lvl = 'info' }
                elseif ($ln -match '^\s*\[KICKED\]')      { $lvl = 'info' }
                elseif ($ln -match '^\s*\[SKIP\]')        { $lvl = 'warn' }
                elseif ($ln -match '^\s*\[FAIL\]')        { $lvl = 'error' }
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

    & $send @{ type='log'; level='ok'; text="C2C Mass Fix done - FIXED: $cFixed, NO CHANGE: $cNoChange, PARTIAL: $cPartial, FAILED: $cFailed, OFFLINE: $cOffline, SKIPPED: $cSkipped." }
    & $send @{ type='status'; text="Done. $cFixed fixed, $cPartial partial, $cNoChange no-change, $cFailed failed of $($rows.Count) row(s)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; fixed=$cFixed; noChange=$cNoChange; partial=$cPartial; failed=$cFailed; offline=$cOffline; skipped=$cSkipped } }
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
    if ($ActionId -eq 'fix')    { return (Invoke-C2cFixAction -Params $Params -Credential $Credential -Emit $Emit) }

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
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($config)
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
