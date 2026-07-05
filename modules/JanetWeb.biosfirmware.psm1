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
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'biosfirmware'
        name     = 'BIOS Firmware'
        version  = '1.0.1'
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

# Tolerant version compare (same idiom as wpt/upr): strip non-numeric, [version] >= target.
function Get-BiosComplianceStatus {
    param([string]$Installed, [string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target))    { return 'Unknown' }
    if ([string]::IsNullOrWhiteSpace($Installed) -or $Installed -eq 'N/A') { return 'Unknown' }
    # Extract the TRAILING dotted-numeric token (e.g. 'N40 Ver. 01.28' -> '01.28')
    # so a leading model number like the N40 cannot pollute the major field. A bare
    # token with no dotted version (e.g. 'A12') is not comparable - stays Unknown.
    $mi = [regex]::Matches($Installed, '\d+(\.\d+)+')
    $mt = [regex]::Matches($Target,    '\d+(\.\d+)+')
    if ($mi.Count -eq 0 -or $mt.Count -eq 0) { return 'Unknown' }
    try {
        $ci = [version]$mi[$mi.Count - 1].Value
        $ct = [version]$mt[$mt.Count - 1].Value
        if ($ci -ge $ct) { return 'Current' } else { return 'Outdated' }
    } catch { return 'Parse Error' }
}

# --- Per-host scan worker (runs in a pool runspace; no module scope here) ----
$script:BiosFirmwareScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; Manufacturer=''; Model=''; ProductName=''; InstalledBIOS=''; BiosDate=''; Error='' }
    # Inline TCP reachability probe (workers can't see module functions) - fail fast.
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Error = 'Offline (no TCP 5985/445)'; return $r }
    $r.Online = $true
    $wsOpt = New-PSSessionOption -OperationTimeout 60000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
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
        $actualName  = ([string]$info.Name).Trim()
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
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
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
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
            $status = if ($baseVal) { Get-BiosComplianceStatus -Installed $res.InstalledBIOS -Target $baseVal } else { 'Unknown (no baseline)' }
        } elseif ($res.Error) { $status = 'Error' } else { $status = 'Offline' }
        $target = if ($hasBaseline) { $baseVal } else { 'N/A' }
        $row = @{ Host=[string]$res.Host; Manufacturer=[string]$res.Manufacturer; Model=[string]$res.Model
                  InstalledBIOS=[string]$res.InstalledBIOS; TargetBIOS=$target; Status=$status
                  BiosDate=[string]$res.BiosDate; Error=[string]$res.Error }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        $ok = ($status -eq 'Current')
        $auditResult = if ($status -eq 'Error' -or $status -eq 'Offline') { 'Failure' } elseif ($ok) { 'Success' } else { 'Skipped' }
        & $send @{ type='audit'; action='TouchHost'; target=[string]$res.Host; result=$auditResult; itemCount=$(if($ok){1}else{0}); detail="BIOS $($res.InstalledBIOS) vs target $target -> $status" }
    }

    try {
        while ($done -lt $jobs.Count) {
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
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
                            $done++
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
    # Unbaselined-model roll-up: which distinct models scanned Unknown, with an example
    # observed BIOS, so the operator knows exactly what to add to the catalog (read-only).
    $unkModels = @{}
    foreach ($rw in $rows) {
        if (([string]$rw.Status) -like 'Unknown*' -and -not [string]::IsNullOrWhiteSpace([string]$rw.Model)) {
            $k = [string]$rw.Model
            if (-not $unkModels.ContainsKey($k)) { $unkModels[$k] = @{ Count=0; Bios=[string]$rw.InstalledBIOS } }
            $unkModels[$k].Count++
        }
    }
    if ($unkModels.Count -gt 0) {
        $parts = foreach ($k in ($unkModels.Keys | Sort-Object)) { "$k (e.g. BIOS $($unkModels[$k].Bios)) x$($unkModels[$k].Count)" }
        & $send @{ type='log'; level='warn'; text="Unbaselined model(s) - add to JanetLocal\BiosFirmwareCatalog.json: $($parts -join '; ')" }
    }
    & $send @{ type='log'; level='ok'; text="BIOS compliance - Fleet: $pctFleet% ($current/$($targets.Count)) | Measured: $pctData% ($current/$withData with a baseline+data). Outdated: $outdated, Unknown: $unknown, Failed/Offline: $failed." }
    & $send @{ type='status'; text="Done. $current current, $outdated outdated, $unknown unknown, $failed failed/offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; current=$current; outdated=$outdated; unknown=$unknown; failed=$failed; fleetPct=$pctFleet; measuredPct=$pctData; source=$catalog.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
