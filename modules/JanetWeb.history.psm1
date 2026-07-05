# =============================================================================
#  JanetWeb.history.psm1  ->  Patch History / Audit Explorer + staleness board
#
#  Net-new JANET Web tool (no desktop twin). READ-ONLY: it makes the audit trail
#  the suite ALREADY writes queryable in-app. It touches NO hosts, opens NO WinRM
#  session, and writes NOTHING - it only READS the flat-file audit CSVs the shared
#  logging bridge (server\JanetWeb.Logging.ps1) produces. Because no host is
#  touched it emits NO audit rows (the TouchHost/VulnPatched ValidateSet does not
#  apply); the server still keeps its automatic per-session log.
#
#  Data sources (paths + schemas MUST match server\JanetWeb.Logging.ps1):
#    (a) per-tool monthly detail   Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv
#        header: Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail
#    (b) local spool copies        <JANET root>\JanetLocal\<Tool>\<userFolder>\... (share-down capture)
#    (c) per-host attribution      Logs\<Tool>\<userFolder>\TouchedHosts_<YYYY-MM>.csv
#        header: Timestamp,Operator,Edipi,SessionId,SourceHost,Action,TargetHost,Result,Detail
#    (d) fleet usage rollup        Logs\<YYYY-MM>_usage.csv (share root) / JanetLocal\_Rollup\<userFolder>\*_usage.csv
#        header: Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes
#
#  The central share root is 445-ping-gated (AFNET-safe: TCP only, NEVER ICMP) so
#  an unreachable share never hangs on a 30s Test-Path. When the share is down the
#  tool falls back to the local JanetLocal spool ONLY and says so in the summary.
#
#  Actions (all destructive=$false):
#    host-timeline    - every audit row mentioning one host, newest first
#    recent-activity  - all audit rows across tools within N days
#    operator-summary - per-operator actions/successes/failures/sessions/last-active
#    stale-hosts      - per pasted host: last-touched date, days ago, FRESH/STALE/NEVER
#
#  Perf: streams Import-Csv per monthly file (never slurps the whole tree), only
#  reads months inside the requested window, and caps returned rows (5000; noted in
#  the summary when hit).
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

# The production share the desktop + JANET Web tools log to (same constant the
# logging bridge uses). Kept as a literal here because this module loads into its
# own worker runspace and does not share the logging script's private scope.
$script:HistShareRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

# Hard read ceiling (safety net independent of the display cap) so a runaway
# window can never enumerate the whole share into memory.
$script:HistReadCeiling = 50000
# Rows returned to / streamed at the view. Noted in the summary when hit.
$script:HistDisplayCap = 5000

function Get-JanetToolManifest {
    @{
        id       = 'history'
        name     = 'Patch History'
        version  = '1.0.1'
        category = 'Reporting'
        summary  = 'Read-only Patch History / Audit Explorer. Makes the audit trail JANET already writes (per-tool monthly detail CSVs, TouchedHosts attribution, and the fleet usage rollup on the central log share - with local-spool fallback when the share is down) queryable in-app: per-host timeline, recent activity across tools, per-operator summary, and a staleness board that flags hosts not touched within a threshold. Touches no hosts and writes nothing.'
        actions  = @(
            @{
                id          = 'host-timeline'
                label       = 'Host Timeline'
                description = 'Every audit row that mentions one host (detail + TouchedHosts), newest first, across the last N months. Read-only - no hosts touched.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Timestamp','Tool','Action','Result','Operator','Detail','Source')
                inputs      = @(
                    @{ name='host';   label='Host name'; type='text'; required=$true },
                    @{ name='months'; label='Months back (1-24)'; type='int'; required=$false; default=6 }
                )
            }
            @{
                id          = 'recent-activity'
                label       = 'Recent Activity'
                description = 'All audit rows across every tool within the last N days, newest first. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Timestamp','Tool','Action','Target','Result','Operator','Detail')
                inputs      = @(
                    @{ name='days'; label='Days back (1-180)'; type='int'; required=$false; default=7 }
                )
            }
            @{
                id          = 'operator-summary'
                label       = 'Operator Summary'
                description = 'One row per operator over the last N months: actions, successes, failures, sessions (from the usage rollup), hosts touched, and last-active timestamp. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Operator','Sessions','Actions','Successes','Failures','HostsTouched','LastActive')
                inputs      = @(
                    @{ name='months'; label='Months back (1-24)'; type='int'; required=$false; default=3 }
                )
            }
            @{
                id          = 'stale-hosts'
                label       = 'Staleness Board'
                description = 'For each pasted host: the last-touched date (from TouchedHosts + detail rows), days ago, and a verdict FRESH / STALE / NEVER TOUCHED against a threshold. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','LastTouched','DaysAgo','LastTool','LastOperator','Verdict')
                inputs      = @(
                    @{ name='targets';        label='Hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='thresholdDays';  label='Stale threshold (days)'; type='int'; required=$false; default=30 },
                    @{ name='lookbackMonths'; label='Lookback (months)'; type='int'; required=$false; default=12 }
                )
            }
        )
    }
}

# --- Reachability (AFNET-safe: TCP only, NEVER ICMP) ------------------------
function Test-HistTcpPort {
    param([string]$ComputerName, [int]$Port = 445, [int]$TimeoutMs = 1500)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    $tc = $null
    try {
        $tc = New-Object System.Net.Sockets.TcpClient
        $iar = $tc.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) { return $true }
    } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
    return $false
}

function Test-HistShare {
    # 445-gate the share server BEFORE Test-Path so an unreachable share does not
    # hang on a 30s SMB timeout (mirrors the logging bridge Test-JanetWebShare).
    param([string]$Root)
    try {
        if ($Root -notmatch '^\\\\([^\\]+)') { return (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue) }
        $server = $Matches[1]
        if (-not (Test-HistTcpPort -ComputerName $server -Port 445)) { return $false }
        return (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)
    } catch { return $false }
}

# The local spool root the logging bridge writes to when the share is down:
# New-JanetWebLogContext uses JanetRoot = Split-Path -Parent <JANET Web folder>,
# then <JanetRoot>\JanetLocal. $PSScriptRoot here is <JANET Web>\modules.
function Get-HistSpoolRoot {
    $twoRoot   = Split-Path -Parent $PSScriptRoot          # ...\JANET Web
    $janetRoot = Split-Path -Parent $twoRoot               # ...\  (peer to Logs\ / Tools\)
    return (Join-Path $janetRoot 'JanetLocal')
}

# Resolve which root to read: the central share if reachable, else the local
# spool. Returns @{ Root; OnShare; Reason; Exists }.
function Resolve-HistRoot {
    $share = $script:HistShareRoot
    if (Test-HistShare -Root $share) {
        return @{ Root = $share; OnShare = $true; Reason = "central log share ($share)"; Exists = $true }
    }
    $spool  = Get-HistSpoolRoot
    $exists = [bool](Test-Path -LiteralPath $spool -ErrorAction SilentlyContinue)
    return @{ Root = $spool; OnShare = $false; Reason = "log share unreachable - reading local spool only ($spool)"; Exists = $exists }
}

# Count un-replayed local spool CSVs. The logging bridge replays spooled rows to
# the share only at server-launch (New-JanetWebLogContext); if the share blipped
# earlier THIS session, freshly captured rows still sit in the local spool while
# we read the (recovered) share. The spool is always local, so this recursive
# walk cannot hang on SMB. Excludes already-replayed and rotated-legacy files.
function Get-HistPendingSpoolCount {
    $spool = Get-HistSpoolRoot
    if (-not (Test-Path -LiteralPath $spool -ErrorAction SilentlyContinue)) { return 0 }
    $n = 0
    try {
        $n = @(Get-ChildItem -LiteralPath $spool -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike '*.replayed_*' -and $_.Name -notlike '*.legacy_*' }).Count
    } catch { $n = 0 }
    return [int]$n
}

# --- Time helpers -----------------------------------------------------------
function Get-HistMonthTokens {
    # yyyy-MM tokens from now going back $Back months (inclusive, newest first).
    param([int]$Back)
    if ($Back -lt 1)  { $Back = 1 }
    if ($Back -gt 24) { $Back = 24 }
    $now = Get-Date
    $list = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Back; $i++) { [void]$list.Add(($now.AddMonths(-$i)).ToString('yyyy-MM')) }
    return @($list)
}

function ConvertTo-HistDate {
    param([string]$Value)
    $dt = [datetime]::MinValue
    if (-not [string]::IsNullOrWhiteSpace($Value) -and [datetime]::TryParse($Value, [ref]$dt)) { return $dt }
    return [datetime]::MinValue
}

# Short (pre-dot) upper-case name for host matching (FQDN-tolerant).
function Get-HistShortName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ((([string]$Value).Trim() -split '\.')[0]).ToUpper()
}

# --- Core reader ------------------------------------------------------------
# Walks Logs\<Tool>\<userFolder>\ under $Root for the requested months, streaming
# each monthly detail + TouchedHosts CSV through Import-Csv (one file at a time -
# never a whole-tree slurp). Optional $HostMatch (scriptblock: target-string ->
# bool) filters to one host. Stops at $Cap rows (sets .Capped). Returns
# @{ Rows=[ArrayList of PSCustomObject]; Capped; Files }.
function Read-HistoryRows {
    param(
        [string]$Root,
        [string[]]$Months,
        [bool]$IncludeDetail = $true,
        [bool]$IncludeTouched = $true,
        [scriptblock]$HostMatch = $null,
        [datetime]$MinDate = [datetime]::MinValue,
        [int]$Cap = 5000
    )
    $out = New-Object System.Collections.ArrayList
    $capped = $false
    $files = 0
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        return @{ Rows = $out; Capped = $false; Files = 0 }
    }

    $toolDirs = @()
    try { $toolDirs = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Rollup' }) } catch {}

    foreach ($td in $toolDirs) {
        if ($capped) { break }
        $toolName = $td.Name
        $opDirs = @()
        try { $opDirs = @(Get-ChildItem -LiteralPath $td.FullName -Directory -ErrorAction SilentlyContinue) } catch {}
        foreach ($od in $opDirs) {
            if ($capped) { break }
            foreach ($m in $Months) {
                if ($capped) { break }

                if ($IncludeDetail) {
                    $detailFiles = @()
                    # Exclude rotated stale-schema archives (<base>.legacy_<stamp>.csv);
                    # they carry old column names, so replaying them yields blank
                    # Target/Timestamp rows (the replay path skips them the same way).
                    try { $detailFiles = @(Get-ChildItem -LiteralPath $od.FullName -Filter ($m + '_detail*.csv') -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch {}
                    foreach ($f in $detailFiles) {
                        if ($capped) { break }
                        $files++
                        $rows = @()
                        try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { $rows = @() }
                        foreach ($row in $rows) {
                            $target = [string]$row.Target
                            if ($HostMatch -and -not (& $HostMatch $target)) { continue }
                            $ts = [string]$row.Timestamp
                            $tsD = (ConvertTo-HistDate $ts)
                            # Filter out-of-window rows BEFORE the cap so the ceiling
                            # counts only in-window rows (MinValue default = no filter).
                            if ($tsD -lt $MinDate) { continue }
                            if ($out.Count -ge $Cap) { $capped = $true; break }
                            [void]$out.Add([pscustomobject]@{
                                TS        = $tsD
                                Timestamp = $ts
                                Tool      = ([string]$row.Tool)
                                Action    = ([string]$row.Action)
                                Target    = $target
                                Result    = ([string]$row.Result)
                                Operator  = ([string]$row.Operator)
                                Detail    = ([string]$row.Detail)
                                Source    = 'Detail'
                            })
                        }
                    }
                }

                if ($IncludeTouched -and -not $capped) {
                    $touchFiles = @()
                    try { $touchFiles = @(Get-ChildItem -LiteralPath $od.FullName -Filter ('TouchedHosts_' + $m + '*.csv') -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch {}
                    foreach ($f in $touchFiles) {
                        if ($capped) { break }
                        $files++
                        $rows = @()
                        try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { $rows = @() }
                        foreach ($row in $rows) {
                            $target = [string]$row.TargetHost
                            if ($HostMatch -and -not (& $HostMatch $target)) { continue }
                            $ts = [string]$row.Timestamp
                            $tsD = (ConvertTo-HistDate $ts)
                            if ($tsD -lt $MinDate) { continue }
                            if ($out.Count -ge $Cap) { $capped = $true; break }
                            [void]$out.Add([pscustomobject]@{
                                TS        = $tsD
                                Timestamp = $ts
                                Tool      = $toolName
                                Action    = ([string]$row.Action)
                                Target    = $target
                                Result    = ([string]$row.Result)
                                Operator  = ([string]$row.Operator)
                                Detail    = ([string]$row.Detail)
                                Source    = 'TouchedHosts'
                            })
                        }
                    }
                }
            }
        }
    }
    return @{ Rows = $out; Capped = $capped; Files = $files }
}

# Read the fleet usage rollup rows for the requested months from either the share
# root (Logs\<YYYY-MM>_usage.csv) or the spool (_Rollup\<userFolder>\*_usage.csv).
# Returns an ArrayList of PSCustomObject mapped from the usage schema.
function Read-HistUsageRows {
    param([string]$Root, [string[]]$Months)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) { return $out }
    $usageFiles = New-Object System.Collections.ArrayList
    # Match the live <YYYY-MM>_usage.csv AND its header-ensure sisters
    # (<base>.r<unix>.csv redirect files), excluding rotated stale-schema
    # (*.legacy_*) archives - an exact-name Test-Path missed the redirect files.
    foreach ($m in $Months) {
        $mf = @()
        try { $mf = @(Get-ChildItem -LiteralPath $Root -Filter ($m + '_usage*.csv') -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch {}
        foreach ($x in $mf) { [void]$usageFiles.Add($x.FullName) }
    }
    $rollup = Join-Path $Root '_Rollup'
    if (Test-Path -LiteralPath $rollup -ErrorAction SilentlyContinue) {
        $opDirs = @()
        try { $opDirs = @(Get-ChildItem -LiteralPath $rollup -Directory -ErrorAction SilentlyContinue) } catch {}
        foreach ($od in $opDirs) {
            foreach ($m in $Months) {
                $rf = @()
                try { $rf = @(Get-ChildItem -LiteralPath $od.FullName -Filter ($m + '_usage*.csv') -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch {}
                foreach ($x in $rf) { [void]$usageFiles.Add($x.FullName) }
            }
        }
    }
    foreach ($uf in $usageFiles) {
        $rows = @()
        try { $rows = @(Import-Csv -LiteralPath $uf -ErrorAction Stop) } catch { $rows = @() }
        foreach ($row in $rows) {
            [void]$out.Add([pscustomobject]@{
                TS           = (ConvertTo-HistDate ([string]$row.Timestamp))
                Timestamp    = ([string]$row.Timestamp)
                SessionId    = ([string]$row.SessionId)
                Operator     = ([string]$row.Operator)
                Tool         = ([string]$row.Tool)
                RowType      = ([string]$row.RowType)
                HostsTouched = ([string]$row.HostsTouched)
                VulnsPatched = ([string]$row.VulnsPatched)
                Failures     = ([string]$row.Failures)
            })
        }
    }
    return $out
}

function ConvertTo-HistInt {
    param([string]$Value)
    $n = 0
    if ([int]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return 0
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $loc = Resolve-HistRoot
    $root = $loc.Root
    & $send @{ type='log'; level=($(if ($loc.OnShare) { 'info' } else { 'warn' })); text="[$(Get-Date -Format 'HH:mm:ss')] Source: $($loc.Reason)." }
    if ($loc.OnShare) {
        # Reading the share, but un-replayed rows may linger in the local spool
        # from a mid-session share outage - warn so results are not taken as
        # complete (they merge to the share at the next server launch).
        $pendingSpool = Get-HistPendingSpoolCount
        if ($pendingSpool -gt 0) {
            & $send @{ type='log'; level='warn'; text="[$(Get-Date -Format 'HH:mm:ss')] $pendingSpool un-replayed local spool file(s) present (captured during a share outage this session); their rows are not on the share yet, so the freshest activity may be missing until the next server launch." }
        }
    }

    # ------------------------------------------------------------ host-timeline
    if ($ActionId -eq 'host-timeline') {
        $hostName = ([string]$Params['host']).Trim()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='No host entered.' }
            return @{ rows=@(); summary=@{ total=0; source=$loc.Reason; onShare=$loc.OnShare } }
        }
        $months = ConvertTo-HistInt ([string]$Params['months']); if ($months -le 0) { $months = 6 }
        $tokens = Get-HistMonthTokens -Back $months
        $short = Get-HistShortName $hostName
        # Inline the short-name normalization: a GetNewClosure() scriptblock does NOT
        # inherit the module's helper functions, so it must be self-contained.
        $match = { param($t) ((([string]$t).Trim() -split '\.')[0]).ToUpper() -eq $short }.GetNewClosure()

        & $send @{ type='status'; text="Building timeline for $hostName over $($tokens.Count) month(s)..." }
        # Read up to the ceiling, sort newest-first, THEN cap - so a capped view is
        # genuinely the newest rows (capping at the display cap in read order first
        # could drop the host's latest events because tool dirs read alphabetically).
        $res = Read-HistoryRows -Root $root -Months $tokens -IncludeDetail $true -IncludeTouched $true -HostMatch $match -Cap $script:HistReadCeiling
        $sorted = @($res.Rows | Sort-Object -Property TS -Descending)
        $capped = $false
        if ($sorted.Count -gt $script:HistDisplayCap) { $sorted = @($sorted | Select-Object -First $script:HistDisplayCap); $capped = $true }

        $tools = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $fails = 0; $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($r in $sorted) {
            # Count over logical events only (audit#24): a TouchedHosts row is a mirror
            # of its Detail row, so counting both roughly doubled fails/tools. The row
            # is still STREAMED below (the grid's Source column shows the provenance);
            # only the summary rollup excludes the mirror.
            $isMirror = ([string]$r.Source -eq 'TouchedHosts')
            if (-not $isMirror -and [string]$r.Result -eq 'Failure') { $fails++ }
            if (-not $isMirror -and $r.Tool) { [void]$tools.Add([string]$r.Tool) }
            $idx++
            $row = @{ _rk=("t{0}" -f $idx); Timestamp=[string]$r.Timestamp; Tool=[string]$r.Tool; Action=[string]$r.Action; Result=[string]$r.Result; Operator=[string]$r.Operator; Detail=[string]$r.Detail; Source=[string]$r.Source }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        if ($rows.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="No audit rows found for $hostName in the last $months month(s)." }
        } else {
            & $send @{ type='log'; level='ok'; text="$($rows.Count) audit row(s) for $hostName ($($tools.Count) tool(s), $fails failure(s))." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - the timeline may be missing older rows; narrow the month window." } }
        elseif ($capped) { & $send @{ type='log'; level='warn'; text="Display cap ($($script:HistDisplayCap)) reached - showing the newest rows; narrow the month window for the full history." } }
        & $send @{ type='status'; text="Done. $($rows.Count) row(s) for $hostName." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; tools=$tools.Count; failures=$fails; host=$hostName; months=$months; capped=($capped -or [bool]$res.Capped); source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # ---------------------------------------------------------- recent-activity
    if ($ActionId -eq 'recent-activity') {
        $days = ConvertTo-HistInt ([string]$Params['days']); if ($days -le 0) { $days = 7 }
        if ($days -gt 180) { $days = 180 }
        $cutoff = (Get-Date).AddDays(-$days)
        # Enough months to cover the window (plus one for the boundary).
        $back = [int][math]::Ceiling($days / 28.0) + 1
        $tokens = Get-HistMonthTokens -Back $back

        & $send @{ type='status'; text="Reading activity across all tools for the last $days day(s)..." }
        # Pass the cutoff into the reader so the 50k ceiling counts only in-window
        # rows (whole out-of-window months were previously read in full, letting the
        # ceiling trip on ancient rows and drop alphabetically-late tools' newest).
        # Detail rows only (audit#14): a TouchedHosts row is a MIRROR of its detail
        # row, and recent-activity has no Source column - reading both double-counted
        # every host-touching action and inflated the failure %. (Same rationale as
        # operator-summary's -IncludeTouched $false.)
        $res = Read-HistoryRows -Root $root -Months $tokens -IncludeDetail $true -IncludeTouched $false -HostMatch $null -MinDate $cutoff -Cap $script:HistReadCeiling
        $sorted = @($res.Rows | Sort-Object -Property TS -Descending)

        $capped = $false
        if ($sorted.Count -gt $script:HistDisplayCap) { $sorted = @($sorted | Select-Object -First $script:HistDisplayCap); $capped = $true }

        $fails = 0; $ops = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($r in $sorted) {
            if ([string]$r.Result -eq 'Failure') { $fails++ }
            if ($r.Operator) { [void]$ops.Add([string]$r.Operator) }
            $idx++
            $row = @{ _rk=("a{0}" -f $idx); Timestamp=[string]$r.Timestamp; Tool=[string]$r.Tool; Action=[string]$r.Action; Target=[string]$r.Target; Result=[string]$r.Result; Operator=[string]$r.Operator; Detail=[string]$r.Detail }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        $failPct = if ($rows.Count -gt 0) { [math]::Round(($fails / $rows.Count) * 100, 1) } else { 0 }
        if ($rows.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="No audit rows in the last $days day(s)." }
        } else {
            & $send @{ type='log'; level='ok'; text="$($rows.Count) audit row(s) in the last $days day(s): $fails failure(s) ($failPct%), $($ops.Count) operator(s)." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - results are incomplete across tools; shorten the window." } }
        elseif ($capped) { & $send @{ type='log'; level='warn'; text="Display cap ($($script:HistDisplayCap)) reached - showing the newest rows; shorten the window for the full set." } }
        & $send @{ type='status'; text="Done. $($rows.Count) row(s) in $days day(s)." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; failures=$fails; failPct=$failPct; operators=$ops.Count; days=$days; capped=($capped -or $res.Capped); source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # --------------------------------------------------------- operator-summary
    if ($ActionId -eq 'operator-summary') {
        $months = ConvertTo-HistInt ([string]$Params['months']); if ($months -le 0) { $months = 3 }
        $tokens = Get-HistMonthTokens -Back $months

        & $send @{ type='status'; text="Summarizing operator activity over $($tokens.Count) month(s)..." }
        # Detail rows carry the authoritative Action/Result vocabulary; usage rows
        # add session + hosts-touched totals. Only detail rows count actions so a
        # TouchedHosts mirror row does not double-count.
        $res = Read-HistoryRows -Root $root -Months $tokens -IncludeDetail $true -IncludeTouched $false -HostMatch $null -Cap $script:HistReadCeiling
        $usage = Read-HistUsageRows -Root $root -Months $tokens

        $agg = @{}   # operator -> hashtable
        $ensure = {
            param($op)
            $k = if ([string]::IsNullOrWhiteSpace($op)) { '(unknown)' } else { $op }
            if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Operator=$k; Sessions=0; Actions=0; Successes=0; Failures=0; HostsTouched=0; Last=[datetime]::MinValue } }
            return $agg[$k]
        }
        foreach ($r in $res.Rows) {
            $a = & $ensure ([string]$r.Operator)
            $a.Actions++
            if ([string]$r.Result -eq 'Success') { $a.Successes++ }
            elseif ([string]$r.Result -eq 'Failure') { $a.Failures++ }
            if ($r.TS -gt $a.Last) { $a.Last = $r.TS }
        }
        # Usage: dedupe SessionEnd rows by SessionId so each session counts ONCE.
        # JANET Web writes one row per tool PLUS an aggregate 'JANET-TWO' row (all
        # sharing one SessionId); the same shared *_usage.csv also holds the desktop
        # suite's SessionEnd rows (Tool = 'WPT'/'ACAS_Nemesis'/...). The old filter
        # (Tool -eq 'JANET-TWO') dropped every desktop session, so an operator who
        # works only in the desktop tools showed Sessions=0/HostsTouched=0. Group by
        # SessionId, count each once, and prefer the aggregate row's HostsTouched.
        $sessions = @{}   # sessionKey -> hashtable
        foreach ($u in $usage) {
            if ([string]$u.RowType -ne 'SessionEnd') { continue }
            $op    = [string]$u.Operator
            $sid   = ([string]$u.SessionId).Trim()
            $isAgg = ([string]$u.Tool -eq 'JANET-TWO')
            $hosts = (ConvertTo-HistInt ([string]$u.HostsTouched))
            # Blank SessionId (legacy rows): synthesize a per-row key so unrelated
            # sessions are not collapsed together.
            $key = if ($sid) { $sid } else { ('__nosid_' + $op + '_' + ([string]$u.Timestamp) + '_' + [string]$u.Tool) }
            if (-not $sessions.ContainsKey($key)) {
                $sessions[$key] = @{ Operator=$op; HostsTouched=$hosts; HasAgg=$isAgg; TS=$u.TS }
            } else {
                $s = $sessions[$key]
                # Aggregate row wins for HostsTouched; otherwise keep the max so a
                # per-tool row does not clobber a larger aggregate value.
                if ($isAgg) { $s.HostsTouched = $hosts; $s.HasAgg = $true }
                elseif ((-not $s.HasAgg) -and ($hosts -gt [int]$s.HostsTouched)) { $s.HostsTouched = $hosts }
                if ($u.TS -gt $s.TS) { $s.TS = $u.TS }
                if ([string]::IsNullOrWhiteSpace([string]$s.Operator) -and $op) { $s.Operator = $op }
            }
        }
        foreach ($sk in @($sessions.Keys)) {
            $s = $sessions[$sk]
            $a = & $ensure ([string]$s.Operator)
            $a.Sessions++
            $a.HostsTouched += [int]$s.HostsTouched
            if ($s.TS -gt $a.Last) { $a.Last = $s.TS }
        }

        $ordered = @($agg.Values | Sort-Object -Property @{ Expression = { [int]$_.Actions } }, @{ Expression = { $_.Last } } -Descending)
        $totalActions = 0; $totalFails = 0; $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($a in $ordered) {
            $totalActions += [int]$a.Actions; $totalFails += [int]$a.Failures
            $idx++
            $last = if ($a.Last -gt [datetime]::MinValue) { $a.Last.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            $row = @{ _rk=("o{0}" -f $idx); Operator=[string]$a.Operator; Sessions=[int]$a.Sessions; Actions=[int]$a.Actions; Successes=[int]$a.Successes; Failures=[int]$a.Failures; HostsTouched=[int]$a.HostsTouched; LastActive=$last }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        if ($rows.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="No operator activity found in the last $months month(s)." }
        } else {
            & $send @{ type='log'; level='ok'; text="$($rows.Count) operator(s): $totalActions action(s), $totalFails failure(s) over $months month(s)." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - operator totals are partial (some tool directories were not scanned); narrow the window." } }
        & $send @{ type='status'; text="Done. $($rows.Count) operator(s)." }
        return @{ rows=@($rows); summary=@{ operators=$rows.Count; actions=$totalActions; failures=$totalFails; months=$months; capped=[bool]$res.Capped; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # -------------------------------------------------------------- stale-hosts
    if ($ActionId -eq 'stale-hosts') {
        $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No valid hosts entered.' }
            return @{ rows=@(); summary=@{ total=0; source=$loc.Reason; onShare=$loc.OnShare } }
        }
        $threshold = ConvertTo-HistInt ([string]$Params['thresholdDays']); if ($threshold -le 0) { $threshold = 30 }
        $lookback = ConvertTo-HistInt ([string]$Params['lookbackMonths']); if ($lookback -le 0) { $lookback = 12 }
        $tokens = Get-HistMonthTokens -Back $lookback
        $cutoff = (Get-Date).AddDays(-$threshold)

        # Fast membership set of short names; the reader keeps only matching rows.
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($t in $targets) { [void]$set.Add((Get-HistShortName $t)) }
        # Inline (see host-timeline): the closure cannot call the module helper.
        $match = { param($t) $set.Contains(((([string]$t).Trim() -split '\.')[0]).ToUpper()) }.GetNewClosure()

        & $send @{ type='status'; text="Scanning $($targets.Count) host(s) over $lookback month(s) for last-touched..." }
        $res = Read-HistoryRows -Root $root -Months $tokens -IncludeDetail $true -IncludeTouched $true -HostMatch $match -Cap $script:HistReadCeiling

        # Reduce to the newest touch per short-name.
        $latest = @{}
        foreach ($r in $res.Rows) {
            $sn = Get-HistShortName $r.Target
            if (-not $sn) { continue }
            if (-not $latest.ContainsKey($sn) -or $r.TS -gt $latest[$sn].TS) {
                $latest[$sn] = [pscustomobject]@{ TS=$r.TS; Tool=[string]$r.Tool; Operator=[string]$r.Operator; Timestamp=[string]$r.Timestamp }
            }
        }

        # When the read ceiling tripped, whole tool directories were skipped (the
        # reader breaks out of remaining dirs, walked alphabetically), so a host with
        # no matching row might simply live in an unread directory. Reporting that as
        # NEVER TOUCHED is a false verdict a lead acts on, so mark it UNKNOWN instead.
        $capped = [bool]$res.Capped
        $now = Get-Date
        $fresh = 0; $stale = 0; $never = 0; $unknown = 0; $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($t in $targets) {
            $sn = Get-HistShortName $t
            $idx++
            $verdict = ''; $lastStr = ''; $daysAgo = ''; $tool = ''; $op = ''
            if ($latest.ContainsKey($sn) -and $latest[$sn].TS -gt [datetime]::MinValue) {
                $info = $latest[$sn]
                $lastStr = $info.Timestamp
                $tool = [string]$info.Tool; $op = [string]$info.Operator
                $daysAgo = [int][math]::Floor(($now - $info.TS).TotalDays)
                if ($info.TS -ge $cutoff) { $verdict = 'FRESH'; $fresh++ } else { $verdict = 'STALE'; $stale++ }
            } elseif ($capped) {
                $verdict = 'UNKNOWN (capped)'; $unknown++
            } else {
                $verdict = 'NEVER TOUCHED'; $never++
            }
            $row = @{ _rk=("s{0}" -f $idx); Host=$t; LastTouched=$lastStr; DaysAgo=("$daysAgo"); LastTool=$tool; LastOperator=$op; Verdict=$verdict }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        & $send @{ type='log'; level=($(if ($stale -or $never -or $unknown) { 'warn' } else { 'ok' })); text="Staleness (threshold ${threshold}d, lookback ${lookback}mo): FRESH=$fresh, STALE=$stale, NEVER TOUCHED=$never, UNKNOWN=$unknown of $($targets.Count)." }
        if ($capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - some tool directories were not scanned; hosts with no match are shown as UNKNOWN (capped), not NEVER TOUCHED. Narrow the host list or lookback for reliable verdicts." } }
        if ($never -gt 0) { & $send @{ type='log'; level='info'; text="NEVER TOUCHED means no audit row within the ${lookback}-month lookback - not necessarily never in all history." } }
        & $send @{ type='status'; text="Done. FRESH=$fresh, STALE=$stale, NEVER=$never, UNKNOWN=$unknown of $($targets.Count)." }
        return @{ rows=@($rows); summary=@{ total=$targets.Count; fresh=$fresh; stale=$stale; never=$never; unknown=$unknown; capped=$capped; thresholdDays=$threshold; lookbackMonths=$lookback; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    & $send @{ type='error'; text="Unknown action '$ActionId'." }
    return @{ rows=@(); summary=@{} }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
