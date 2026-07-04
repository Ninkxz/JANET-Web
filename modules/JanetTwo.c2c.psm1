# =============================================================================
#  JanetTwo.c2c.psm1  ->  C2C Readiness (Comply-to-Connect quarantine predictor)
#
#  Net-new JANET TWO tool (no desktop twin). Fans out ONE consolidated read-only
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
        name     = 'C2C Readiness'
        version  = '1.0.0'
        category = 'Reporting'
        summary  = 'Read-only Comply-to-Connect (AFI/MPTO rule 3.B.2.B) quarantine predictor: fan out one consolidated WinRM probe per host, run 11 C2C checks (9 scored, 2 external/server-side), and flag each host READY or QUARANTINE RISK. Streams the full per-check report to the activity log. Changes nothing.'
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
