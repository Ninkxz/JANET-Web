# =============================================================================
#  JanetWeb.biosfirmware.psm1  ->  BIOS Firmware (compliance scan)
#
#  Net-new JANET Web tool (no desktop twin). Fans out a read-only WinRM scan of
#  Win32_BIOS + Win32_ComputerSystem across targets, looks each model up in a
#  per-model target-firmware baseline, and scores Current / Outdated / Unknown.
#  Idea lifted from the DoW Baseline Configuration Manager's BIOS report.
#
#  Baseline source (UPR pattern): an editable JanetLocal\BiosFirmwareCatalog.json
#  read FRESH each scan, falling back to the embedded default seed below. The tool
#  never WRITES the catalog (no SMB atomic-write hazard) - operators edit the JSON
#  and re-run / use List Baselines, exactly like UPR's catalog.
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only.
#
#  Changelog
#    1.1.1  audit 2026-07-25 (fable re-audit follow-up) - (P4) the unscorable-version
#           roll-up split again: a mis-typed / mixed-format TARGET in the catalog used
#           to be reported as "the baseline is fine, investigate the host", which is the
#           opposite action to the one it needs, so Get-BiosComplianceStatus now names
#           the side that failed to parse ('host version format' vs 'baseline version
#           format') and the summary carries a badTargetModels bucket keyed by MODEL;
#           (P4) the Dell letter-series compare is Ordinal, not the culture-sensitive
#           overload; (P4) behavioural coverage added for the operator-cancel progress
#           event (the 1.1.0 fix shipped untested).
#    1.1.0  audit 2026-07-24 - (P2) DNS-mismatch guard gained the IPv4-literal
#           carve-out every sibling guard already had (an IP target false-skipped
#           100% of the time); (P3) the Unknown roll-up split into two buckets -
#           "no baseline for this model" vs "this host returned no usable BIOS
#           version" - because they are different operator actions; (P4) operator
#           cancel now emits a progress event per abandoned host so the strip
#           finishes instead of freezing; version compare taught the Dell-style
#           letter-prefixed format ('A9' < 'A12') and mixed formats now refuse to
#           score rather than guess. Tests: tests\BiosFirmware.Tests.ps1.
#    1.0.1  initial fan-out + catalog fallback.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'biosfirmware'
        name     = 'BIOS Firmware'
        version  = '1.1.2'   # audit 2026-07-25 (fable re-audit follow-up): catalog-side vs host-side unscorable version split out, Ordinal series compare, cancel-progress now tested; tests\BiosFirmware.Tests.ps1 pins it EXACTLY - bump both together
        category = 'Hardening'
        summary  = 'Read-only fleet BIOS firmware compliance: scan Win32_BIOS over WinRM, compare each model to a per-model target-version baseline (editable JanetLocal catalog), and flag Current / Outdated / Unknown.'
        actions  = @(
            @{
                id          = 'scan-bios'
                label       = 'Scan BIOS Firmware'
                description = 'Parallel WinRM scan of each target''s BIOS version + model, scored against the per-model baseline. Read-only - no firmware is written.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Manufacturer','Model','InstalledBIOS','TargetBIOS','Status','BiosDate','Error')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts (1-32)';       type='int';      required=$false; default=16 }
                )
            }
            @{
                id          = 'list-baselines'
                label       = 'List Baselines'
                description = 'Show the per-model target-firmware baseline currently in effect and where it loaded from (JanetLocal catalog or the embedded default).'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Model','TargetBIOS')
                inputs      = @()
            }
        )
    }
}

# --- Baseline catalog -------------------------------------------------------
# Embedded default seed (the DoW Baseline Manager's known-good Dell fleet table).
# Operators override/extend by editing JanetLocal\BiosFirmwareCatalog.json.
function Get-BiosFirmwareDefaultCatalog {
    @{
        'Latitude 5400' = '1.43.1'; 'Latitude 5410' = '1.40.1'; 'Latitude 5420' = '1.50.0'; 'Latitude 5480' = '1.39.0'
        'Latitude 5490' = '1.41.0'; 'Latitude 5500' = '1.43.1'; 'Latitude 5520' = '1.48.0'; 'Latitude 5540' = '1.27.1'
        'Latitude E5470' = '1.34.3'; 'Latitude 5550' = '1.19.1'; 'OptiPlex 7000' = '1.33.2'; 'OptiPlex 7050' = '1.27.0'
        'OptiPlex 7060' = '1.32.0'; 'OptiPlex 7070' = '1.35.0'; 'OptiPlex 7080' = '1.37.0'; 'OptiPlex 7090' = '1.40.0'
        'Precision 3520' = '1.39.0'; 'Precision 3560' = '1.48.0'; 'Precision 7550' = '1.43.0'; 'Precision 7560' = '1.44.1'
        'Precision 7920 Tower' = '2.50.0'; 'Precision 7670' = '1.35.0'; 'Precision 7680' = '1.26.0'; 'Precision 3660' = '2.31.0'
        'OptiPlex SFF Plus 7020' = '1.22.1'; 'Precision 3590' = '1.19.1'; 'OptiPlex SFF Plus 7010' = '1.30.0'; 'Precision 3650' = '1.45.0'
        'Dell Pro Max 14 MC14250' = '1.11.0'; 'Dell Pro Max 16 MC16250' = '1.11.0'; 'Dell Pro Max Slim FCS1250' = '1.11.3'
        'Dell Pro Max Tower T2 FCT2250' = '1.11.3'; 'Dell Pro Max 16 Plus MB16250' = '2.2.2'; 'Dell Pro 13 Plus PB13250' = '2.9.0'
    }
}

function Get-BiosFirmwareCatalogPath { Join-Path $PSScriptRoot '..\JanetLocal\BiosFirmwareCatalog.json' }

# Read the editable JanetLocal catalog fresh; returns a @{ Baselines=@{...}; Source='...' }.
# Any problem (missing/corrupt/empty) falls back to the embedded default - a bad
# JSON never breaks a scan. Read-only: the file is never written by this module.
function Get-BiosFirmwareCatalog {
    $default = Get-BiosFirmwareDefaultCatalog
    try {
        $p = Get-BiosFirmwareCatalogPath
        if (-not (Test-Path -LiteralPath $p)) { return @{ Baselines = $default; Source = 'embedded default (no JanetLocal\BiosFirmwareCatalog.json)' } }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Baselines = $default; Source = 'embedded default (catalog file empty)' } }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj -or -not $obj.Baselines) { return @{ Baselines = $default; Source = 'embedded default (catalog has no Baselines)' } }
        $merged = @{}
        foreach ($k in $default.Keys) { $merged[$k] = $default[$k] }   # default seed first
        foreach ($prop in $obj.Baselines.PSObject.Properties) { $merged[$prop.Name] = [string]$prop.Value }  # operator overrides win
        return @{ Baselines = $merged; Source = 'JanetLocal\BiosFirmwareCatalog.json (merged over default)' }
    } catch { return @{ Baselines = $default; Source = "embedded default (catalog read error: $($_.Exception.Message))" } }
}

# Parse one vendor BIOS version string into a comparable key, or $null when the
# string carries no version this tool knows how to score. Two recognised shapes:
#   Kind='dotted' -> Value is a [version]  ('1.28', 'N40 Ver. 01.28')
#   Kind='alpha'  -> Series (letter run) + Rev (revision as an INT)  ('A12', 'BIOS A05')
# audit 2026-07-24: the alpha shape is new. Dell ships 'A9'/'A12' and any text
# ordering of those is backwards, so the revision is compared as a number.
function ConvertTo-BiosVersionKey {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = ([string]$Text).Trim()
    # Dotted-numeric wins when present. Take the TRAILING dotted token so a leading
    # model number ('N40 Ver. 01.28' -> '01.28') cannot pollute the major field.
    $m = [regex]::Matches($t, '\d+(\.\d+)+')
    if ($m.Count -gt 0) {
        try { return @{ Kind='dotted'; Value=[version]$m[$m.Count - 1].Value } } catch { return $null }
    }
    # Letter-prefixed vendor revision, optionally after a label ('BIOS A05').
    $a = [regex]::Match($t, '^(?:.*\s)?([A-Za-z]{1,3})(\d{1,4})$')
    if ($a.Success) { return @{ Kind='alpha'; Series=$a.Groups[1].Value.ToUpperInvariant(); Rev=[int]$a.Groups[2].Value } }
    return $null
}

# Tolerant version compare (same idiom as wpt/upr) - NEVER a raw string compare:
# as text '1.9.0' sorts ABOVE '1.10.0' and 'A9' above 'A12', both of which would
# report an out-of-date box as Current. Both sides are parsed to a typed key and
# only like-for-like shapes are scored; a dotted version against a letter revision
# is not a comparison anyone can make, so it refuses rather than guesses.
function Get-BiosComplianceStatus {
    param([string]$Installed, [string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return 'Unknown (no baseline)' }
    # audit 2026-07-24: an unreadable BIOS version is a HOST problem, not a missing
    # catalog row - it gets its own state so the roll-up below (and the operator)
    # can tell "investigate this host" from "add a baseline". Never 'Current'.
    if ([string]::IsNullOrWhiteSpace($Installed) -or $Installed -eq 'N/A') { return 'Unknown (no BIOS version)' }
    try {
        $ki = ConvertTo-BiosVersionKey $Installed
        $kt = ConvertTo-BiosVersionKey $Target
        # Unrecognised on either side, or two different vendor formats: not scorable.
        # audit 2026-07-25 (fable re-audit follow-up): WHICH side is unparseable decides the
        # operator's action, and both used to land in one 'Unknown (version format)' bucket
        # whose roll-up said "the baseline is fine, investigate the host" - dead wrong for a
        # typo'd TARGET in the catalog, where the hosts are fine and the JSON needs editing.
        # A mixed pair (both parse, different shapes) stays generic: the catalog is the side
        # we can edit, so the roll-up files it with the catalog, but neither value is provably
        # wrong on its own.
        if ($null -eq $ki -and $null -eq $kt) { return 'Unknown (version format)' }
        if ($null -eq $ki)                    { return 'Unknown (host version format)' }
        if ($null -eq $kt)                    { return 'Unknown (baseline version format)' }
        if ($ki.Kind -ne $kt.Kind)            { return 'Unknown (version format)' }
        if ($ki.Kind -eq 'dotted') {
            if ($ki.Value -ge $kt.Value) { return 'Current' } else { return 'Outdated' }
        }
        # Alpha: the letter series bumps first (Dell A## -> B##), then the revision.
        # audit 2026-07-25 (fable re-audit follow-up): ORDINAL, not the culture-sensitive
        # 3-arg overload. Both series are already ToUpperInvariant'd by the parser, so there
        # is nothing for a culture to case-fold - and a vendor revision letter is a byte code,
        # not text to be collated under whatever culture the service happens to run as.
        if ($ki.Series -ne $kt.Series) {
            if ([string]::Compare($ki.Series, $kt.Series, [System.StringComparison]::Ordinal) -ge 0) { return 'Current' } else { return 'Outdated' }
        }
        if ($ki.Rev -ge $kt.Rev) { return 'Current' } else { return 'Outdated' }
    } catch { return 'Parse Error' }
}

# --- Per-host scan worker (runs in a pool runspace; no module scope here) ----
$script:BiosFirmwareScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; Manufacturer=''; Model=''; ProductName=''; InstalledBIOS=''; BiosDate=''; Error='' }
    # Inline TCP reachability probe (workers can't see module functions) - fail fast.
    # WinRM HTTP 5985, then WinRM HTTPS 5986, then SMB 445 (liveness only), break on first
    # connect (HTTP preferred when both open). $useSsl tracks whether ONLY 5986 answered so
    # the session below auto-switches to -UseSSL (self-signed WinRM HTTPS is common on AFNET).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Error = 'Offline (no TCP 5985/5986/445)'; return $r }
    $r.Online = $true
    $soP = @{ OperationTimeout=60000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        # Single round-trip: pull the remote computer name (for the DNS-mismatch guard)
        # together with the BIOS/model bundle, then compare locally - one Invoke-Command
        # per host instead of two (halves remote chatter; keeps worst-case under watchdog).
        $info = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $bios = Get-CimInstance Win32_BIOS -EA Stop
            $cs   = Get-CimInstance Win32_ComputerSystem -EA Stop
            # Win32_ComputerSystemProduct.Name is what the DoW baseline table was keyed
            # on; pull it too so catalog lookups match the seed (CS.Model can differ).
            $csp  = Get-CimInstance Win32_ComputerSystemProduct -EA SilentlyContinue
            @{
                Name         = $env:COMPUTERNAME
                Manufacturer = [string]$cs.Manufacturer
                Model        = [string]$cs.Model
                ProductName  = if ($csp) { [string]$csp.Name } else { '' }
                BiosVersion  = [string]$bios.SMBIOSBIOSVersion
                BiosDate     = if ($bios.ReleaseDate) { try { $bios.ReleaseDate.ToString('yyyy-MM-dd') } catch { '' } } else { '' }
            }
        }
        # DNS-mismatch guard (read-only soft-warn, consistent with WPT scan): a wrong
        # box would report the wrong firmware. Session name compare, never PTR.
        # audit 2026-07-24: IPv4-literal carve-out (parity with restart/wpt, which is
        # Test-WptRemoteNameMatch's first test). An IP target has no DNS indirection -
        # the box answering at that IP IS the box - and its first dot-token ('192')
        # can never equal a COMPUTERNAME, so without this EVERY IP-addressed host was
        # falsely reported as skipped. Workers can't see module functions, so the test
        # is inlined here exactly as the sibling guards inline it.
        $actualName  = ([string]$info.Name).Trim()
        $targetShort = ($Computer -split '\.')[0]
        $isIPv4      = ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$')
        if (-not $isIPv4 -and $actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
            $r.Error = "DNS mismatch: dialed '$targetShort' but remote is '$actualName' - skipped"
            return $r
        }
        $r.Manufacturer  = ([string]$info.Manufacturer).Trim()
        $r.Model         = ([string]$info.Model).Trim()
        $r.ProductName   = ([string]$info.ProductName).Trim()
        $r.InstalledBIOS = ([string]$info.BiosVersion).Trim()
        $r.BiosDate      = [string]$info.BiosDate
    } catch { $r.Error = $_.Exception.Message }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
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

    $catalog = Get-BiosFirmwareCatalog
    $baselines = $catalog.Baselines

    if ($ActionId -eq 'list-baselines') {
        & $send @{ type='status'; text="Baseline source: $($catalog.Source)" }
        $rows = New-Object System.Collections.ArrayList
        foreach ($model in ($baselines.Keys | Sort-Object)) {
            $row = @{ Model=$model; TargetBIOS=[string]$baselines[$model] }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        & $send @{ type='log'; level='ok'; text="$($rows.Count) model baseline(s) loaded from $($catalog.Source)." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; source=$catalog.Source } }
    }

    if ($ActionId -ne 'scan-bios') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # --- scan-bios ---
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    # Accept only bare host/IPv4 tokens; drop UNC/URL/junk before any WinRM call.
    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    $threads = 16
    if ($Params['threads']) { $tpv = 0; if ([int]::TryParse([string]$Params['threads'], [ref]$tpv)) { $threads = $tpv } }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 180  # a read-only BIOS scan that runs this long = a wedged WMI/CIM call

    & $send @{ type='status'; text="Scanning BIOS firmware on $($targets.Count) host(s) with $threads thread(s)... (baseline: $($catalog.Source))" }
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:BiosFirmwareScanBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0

    # Build a row + emit it (shared by the normal harvest and the timeout/cancel paths).
    $emitRow = {
        param($res)
        # Match the catalog by CS.Model first, then ComputerSystemProduct.Name (the key
        # the DoW seed table used) - first hit wins, so CS/CSP divergence doesn't false-Unknown.
        $lookupKey = if ($baselines.ContainsKey([string]$res.Model)) { [string]$res.Model }
                     elseif ($res.ProductName -and $baselines.ContainsKey([string]$res.ProductName)) { [string]$res.ProductName }
                     else { [string]$res.Model }
        # Resolve the baseline once (ContainsKey + index were each evaluated twice).
        $hasBaseline = $baselines.ContainsKey($lookupKey)
        $baseVal     = if ($hasBaseline) { [string]$baselines[$lookupKey] } else { '' }
        $status = ''
        if ($res.Online -and -not $res.Error) {
            # audit 2026-07-24: the empty-baseline branch moved INSIDE the scorer, which
            # now returns the specific Unknown flavour ('no baseline' vs 'no BIOS version'
            # vs 'version format') the roll-up below buckets on. One source of truth.
            $status = Get-BiosComplianceStatus -Installed $res.InstalledBIOS -Target $baseVal
        } elseif ($res.Error) { $status = 'Error' } else { $status = 'Offline' }
        $target = if ($hasBaseline) { $baseVal } else { 'N/A' }
        $row = @{ Host=[string]$res.Host; Manufacturer=[string]$res.Manufacturer; Model=[string]$res.Model
                  InstalledBIOS=[string]$res.InstalledBIOS; TargetBIOS=$target; Status=$status
                  BiosDate=[string]$res.BiosDate; Error=[string]$res.Error }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        # audit 2026-07-23: no audit emit for this read-only scan. The per-host
        # TouchHost rows inflated the TouchedHosts freshness trail on every scan;
        # the read-only cohort (history/sysadmin/patchlib/kev) deliberately emits none.
    }

    try {
        while ($done -lt $jobs.Count) {
            # Stamp the per-host clock only up to the pool's real concurrency, in queue order: a PS
            # queued in a saturated RunspacePool reports State='Running' at once, so the old check
            # stamped StartedAt at ENQUEUE and the watchdog false-timed-out the backlog (~threads*timeout in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Online=$false; Error="worker error: $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Online=$false; Error='no result' } }
                    & $emitRow $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own clock (wedged CIM).
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitRow @{ Host=$j.Host; Online=$true; Error="per-host timeout (${perHostTimeout}s) - possible WMI/CIM hang" }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitRow @{ Host=$j.Host; Online=$false; Error='cancelled by operator' }
                            # audit 2026-07-24: emit progress here too. The harvest and
                            # watchdog paths both do; cancel only bumped $done, so the
                            # strip froze at its last pre-cancel count while rows kept
                            # landing - the run looked wedged instead of cancelled.
                            $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight scans stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    # Tally from the emitted rows (each row carries its Status) - no module-scope counters.
    $current  = @($rows | Where-Object { $_.Status -eq 'Current' }).Count
    $outdated = @($rows | Where-Object { $_.Status -eq 'Outdated' }).Count
    $unknown  = @($rows | Where-Object { $_.Status -like 'Unknown*' -or $_.Status -like 'Parse*' }).Count
    $failed   = @($rows | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Offline' }).Count
    $withData = $current + $outdated
    $pctData  = if ($withData -gt 0) { [math]::Round(($current / $withData) * 100, 1) } else { 0 }
    $pctFleet = if ($targets.Count -gt 0) { [math]::Round(($current / $targets.Count) * 100, 1) } else { 0 }
    # Unknown roll-up, THREE buckets. audit 2026-07-24: one bucket named catalogued
    # models as "unbaselined" and sent the operator to edit a JSON that already had
    # the row. They are different actions, so they are different messages:
    #   A. no catalog entry for this model     -> ADD a baseline (keyed by model)
    #   B. baselined model, no usable version  -> INVESTIGATE the host (keyed by host)
    # audit 2026-07-25 (fable re-audit follow-up): bucket C. A mis-typed or mixed-format
    # TARGET value in the catalog is unscorable too, and it used to fall into B - which
    # tells the operator to go poke every host over a defect in a JSON file they own.
    # The catalog is the thing to FIX there, and it is keyed by model, not by host.
    $unbaselinedModels = @{}
    $badTargetModels   = @{}
    $noVersionHosts    = New-Object System.Collections.ArrayList
    foreach ($rw in $rows) {
        $st = [string]$rw.Status
        if (-not ($st -like 'Unknown*' -or $st -like 'Parse*')) { continue }
        $mdl = [string]$rw.Model
        # A blank model can't be added to the catalog by name, so it belongs in B
        # (the host read didn't come back usable) rather than being dropped silently.
        if ($st -eq 'Unknown (no baseline)' -and -not [string]::IsNullOrWhiteSpace($mdl)) {
            if (-not $unbaselinedModels.ContainsKey($mdl)) { $unbaselinedModels[$mdl] = @{ Count=0; Bios=[string]$rw.InstalledBIOS } }
            $unbaselinedModels[$mdl].Count++
        } elseif (($st -eq 'Unknown (baseline version format)' -or $st -eq 'Unknown (version format)') -and -not [string]::IsNullOrWhiteSpace($mdl)) {
            if (-not $badTargetModels.ContainsKey($mdl)) { $badTargetModels[$mdl] = @{ Count=0; Target=[string]$rw.TargetBIOS; Bios=[string]$rw.InstalledBIOS } }
            $badTargetModels[$mdl].Count++
        } else {
            $shown = if ([string]::IsNullOrWhiteSpace($mdl)) { 'model unreported' } else { $mdl }
            [void]$noVersionHosts.Add("$([string]$rw.Host) ($shown - $st)")
        }
    }
    if ($unbaselinedModels.Count -gt 0) {
        $parts = foreach ($k in ($unbaselinedModels.Keys | Sort-Object)) { "$k (e.g. BIOS $($unbaselinedModels[$k].Bios)) x$($unbaselinedModels[$k].Count)" }
        & $send @{ type='log'; level='warn'; text="Unbaselined model(s) - add to JanetLocal\BiosFirmwareCatalog.json: $($parts -join '; ')" }
    }
    if ($badTargetModels.Count -gt 0) {
        # The HOSTS are fine here - the catalog's target value is what cannot be scored,
        # so name the model + the offending target string and point at the JSON.
        $bparts = foreach ($k in ($badTargetModels.Keys | Sort-Object)) { "$k (target '$($badTargetModels[$k].Target)' vs installed '$($badTargetModels[$k].Bios)') x$($badTargetModels[$k].Count)" }
        & $send @{ type='log'; level='warn'; text="Unscorable TARGET version in JanetLocal\BiosFirmwareCatalog.json - fix the catalog entry, the host(s) are fine: $($bparts -join '; ')" }
    }
    if ($noVersionHosts.Count -gt 0) {
        # Cap the list so a fleet-wide WMI outage can't emit a 500-host log line.
        $shownHosts = @($noVersionHosts | Select-Object -First 20) -join '; '
        if ($noVersionHosts.Count -gt 20) { $shownHosts += "; ... (+$($noVersionHosts.Count - 20) more)" }
        & $send @{ type='log'; level='warn'; text="No usable BIOS version from $($noVersionHosts.Count) host(s) - the baseline is fine, investigate the host (SMBIOS/WMI read): $shownHosts" }
    }
    & $send @{ type='log'; level='ok'; text="BIOS compliance - Fleet: $pctFleet% ($current/$($targets.Count)) | Measured: $pctData% ($current/$withData with a baseline+data). Outdated: $outdated, Unknown: $unknown, Failed/Offline: $failed." }
    & $send @{ type='status'; text="Done. $current current, $outdated outdated, $unknown unknown, $failed failed/offline of $($targets.Count)." }
    # audit 2026-07-24: the two Unknown buckets are surfaced in the summary too, so a
    # caller never has to re-derive "add a baseline" vs "investigate the host" counts.
    return @{ rows=@($rows); summary=@{ total=$targets.Count; current=$current; outdated=$outdated; unknown=$unknown; failed=$failed
                                        unbaselinedModels=$unbaselinedModels.Count; noVersionHosts=$noVersionHosts.Count
                                        badTargetModels=$badTargetModels.Count
                                        fleetPct=$pctFleet; measuredPct=$pctData; source=$catalog.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
