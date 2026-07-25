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
#    (e) per-run outcome cards     Logs\<Tool>\ACAS-Nemesis-Runs_<YYYY-MM-DD>.csv
#        header: Timestamp,User,Edipi,SessionId,Host,RowType,Action,Scope,Profile,Mode,
#                HostsTotal,Success,Failed,DurationSec,Notes,GroupKey,GroupSize
#        (17-col desktop-compatible schema; byte-merged with desktop-written rows)
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
#    run-outcomes     - Run Outcomes Board: the daily per-run cards (source (e)) grouped
#                       by Action/Profile/Mode with success rate + avg duration
#    coverage-reconcile - fleet coverage: the AD computer population joined in memory
#                       against the SAME audit trail stale-hosts reads
#
#  Perf: streams Import-Csv per monthly file (never slurps the whole tree), only
#  reads months inside the requested window, and caps returned rows (5000; noted in
#  the summary when hit). EVERY read is bounded by $script:HistReadCeiling.
#
#  Changelog:
#    1.0.0 - initial Patch History / Audit Explorer.
#    1.0.1 - read ceiling counts in-window rows only; UNKNOWN (capped) verdict.
#    1.0.2 - usage dedupe by SessionId; host-token validation on host-timeline.
#    1.1.0 - audit 2026-07-24: read failures are COUNTED and surfaced instead of
#            swallowed (a permissions error / dropped share no longer reads as a
#            clean empty audit trail); the staleness board refuses to say
#            NEVER TOUCHED when the underlying read failed (new verdict
#            'UNKNOWN (read error)'); Resolve-HistRoot's .Exists flag is wired
#            into every caller; Read-HistUsageRows is capped like every other read.
#    1.2.0 - capability audit 2026-07-25 additions (#7 + #8):
#            * run-outcomes - the Run Outcomes Board. Write-JanetWebRun has always
#              written a rich 17-column per-run card to Logs\<Tool>\ACAS-Nemesis-Runs_
#              <YYYY-MM-DD>.csv and NOTHING in either repo ever read it. THE TRAP:
#              a rolled-up group card is written as ONE ROW PER MEMBER, every row
#              carrying the SAME counters (Logging.ps1 :804-817). Naive summing
#              multiplies Success/Failed/HostsTotal by GroupSize, so the board
#              de-dupes group cards on (Timestamp, SessionId, GroupKey, Action)
#              BEFORE aggregating - a 3-member card counts ONCE.
#            * coverage-reconcile - fleet coverage reconciliation. The Staleness
#              Board only verdicts hosts the operator PASTES; wpt/ad-computers
#              already enumerates the whole domain but only to feed an OU picker.
#              This joins them: ONE paged LDAP searcher (PageSize 1000,
#              (objectCategory=computer), ReferralChasing None, bounded timeouts,
#              disposed in finally - hygiene copied from adsearch, NOT imported)
#              against the same audit-trail read stale-hosts uses. Verdicts
#              COVERED / STALE (live) / NEVER TOUCHED (live) / GHOST / DEAD OBJECT,
#              and FAIL CLOSED: a capped or errored read on EITHER side renders
#              UNKNOWN, never COVERED. SearchBase rides the same local-domain DN
#              guard the AD TO scan and adsearch ship, and the whole-domain
#              enumeration is capped with an advisory and honours the __job cancel.
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
# Hard ceiling on the whole-domain LDAP computer enumeration (coverage-reconcile).
# A fleet read is the single biggest read this module can issue; past this we stop
# accumulating and say so, exactly like adsearch's manual harvest cap - a truncated
# enumeration must never be presented as a complete fleet picture.
$script:HistAdCeiling = 20000
# Advisory (not a cap) threshold, mirroring adsearch's large-export advisory.
$script:HistAdAdvisory = 2000

function Get-JanetToolManifest {
    @{
        id       = 'history'
        name     = 'Patch History'
        version  = '1.2.0'
        category = 'Reporting'
        summary  = 'Read-only Patch History / Audit Explorer. Makes the audit trail JANET already writes (per-tool monthly detail CSVs, TouchedHosts attribution, the daily per-run outcome cards, and the fleet usage rollup on the central log share - with local-spool fallback when the share is down) queryable in-app: per-host timeline, recent activity across tools, per-operator summary, a staleness board that flags hosts not touched within a threshold, a run-outcomes board over the per-run cards, and a fleet coverage reconciliation that joins the AD computer population against the audit trail. Touches no hosts and writes nothing.'
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
                description = 'For each pasted host: the last-touched date (from TouchedHosts + detail rows), days ago, and a verdict FRESH / STALE / NEVER TOUCHED against a threshold - or UNKNOWN when the read was capped or the audit source could not be read, so a failed read is never mistaken for a never-touched host. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','LastTouched','DaysAgo','LastTool','LastOperator','Verdict')
                inputs      = @(
                    @{ name='targets';        label='Hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='thresholdDays';  label='Stale threshold (days)'; type='int'; required=$false; default=30 },
                    @{ name='lookbackMonths'; label='Lookback (months)'; type='int'; required=$false; default=12 }
                )
            }
            @{
                id          = 'run-outcomes'
                label       = 'Run Outcomes Board'
                description = 'Groups the daily per-run outcome cards (Logs\<Tool>\ACAS-Nemesis-Runs_<date>.csv) by Action / Profile / Mode over a day window: runs, hosts, successes, failures, success rate, average duration, last run and distinct operators. Rolled-up group cards are written one row PER MEMBER with shared counters, so they are de-duped before aggregating - a 3-member card counts once. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Action','Profile','Mode','Runs','HostsTotal','Success','Failed','SuccessPct','AvgDurationSec','LastRun','Operators')
                inputs      = @(
                    @{ name='days'; label='Days back (1-365)'; type='int'; required=$false; default=30 }
                )
            }
            @{
                id          = 'coverage-reconcile'
                label       = 'Fleet Coverage Reconciliation'
                description = 'Enumerates the domain computer population with ONE paged LDAP search and joins it in memory against the audit trail: per host an AD status (Enabled / Disabled / Stale-<N>d / NOT IN AD), its last AD logon, its last JANET touch, and a verdict COVERED / STALE (live) / NEVER TOUCHED (live) / GHOST (JANET touched a host AD says is dead) / DEAD OBJECT. A capped or errored read on either side renders UNKNOWN, never COVERED. Read-only - no hosts touched, nothing written.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','AdStatus','LastAdLogon','LastTouched','DaysAgo','LastTool','Verdict')
                inputs      = @(
                    @{ name='searchBase';     label='Search base DN (blank = whole domain)'; type='text'; required=$false },
                    @{ name='thresholdDays';  label='Coverage threshold (days)'; type='int'; required=$false; default=30 },
                    @{ name='adStaleDays';    label='AD stale threshold (days)'; type='int'; required=$false; default=90 },
                    @{ name='lookbackMonths'; label='Audit lookback (months)'; type='int'; required=$false; default=12 },
                    @{ name='targets';        label='Also reconcile these hosts (one per line, optional)'; type='hostlist'; required=$false }
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

# --- Read-failure accounting (audit 2026-07-24) -----------------------------
# Every read in this module used to sit behind a swallowing catch, so a denied ACL,
# a share that dropped mid-walk, or a CSV locked by the writer produced ZERO rows and
# NO signal - byte-identical to a genuinely clean audit trail. On the staleness board
# that turned an I/O fault into "NEVER TOUCHED", the single most actionable verdict
# here and the one a lead acts on. Reads still never THROW (one bad file must not
# abort a whole-tree walk), but each failure is now counted and its path recorded so
# the caller can report UNKNOWN instead of an empty-but-successful answer.
function New-HistErrorBag {
    return @{ Count = 0; Messages = (New-Object System.Collections.ArrayList) }
}
function Add-HistReadError {
    param([hashtable]$Bag, [string]$Path, $ErrorRecord)
    if ($null -eq $Bag) { return }
    $Bag.Count = [int]$Bag.Count + 1
    # Keep only the first few paths: one dead share can fault thousands of files, and
    # an unbounded message list would be exactly the memory blow-up the read ceiling
    # exists to prevent. The COUNT stays exact; only the detail is trimmed.
    if ($Bag.Messages.Count -ge 10) { return }
    $msg = 'read failed'
    if ($ErrorRecord -and $ErrorRecord.Exception) { $msg = ((([string]$ErrorRecord.Exception.Message) -replace '\s+', ' ').Trim()) }
    [void]$Bag.Messages.Add(("{0} ({1})" -f $Path, $msg))
}

# --- Core reader ------------------------------------------------------------
# Walks Logs\<Tool>\<userFolder>\ under $Root for the requested months, streaming
# each monthly detail + TouchedHosts CSV through Import-Csv (one file at a time -
# never a whole-tree slurp). Optional $HostMatch (scriptblock: target-string ->
# bool) filters to one host. Stops at $Cap rows (sets .Capped). Returns
# @{ Rows=[ArrayList of PSCustomObject]; Capped; Files; Errors; ErrorMessages;
#    RootMissing } - Errors/RootMissing let the caller tell "nothing there" apart
# from "could not look" (audit 2026-07-24).
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
    $errBag = New-HistErrorBag
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        # audit 2026-07-24: an absent / unopenable root is NOT an empty audit trail.
        # Flag it so the caller reports UNKNOWN rather than a clean zero-row result.
        return @{ Rows = $out; Capped = $false; Files = 0; Errors = 1; ErrorMessages = @("$Root (root not found or not readable)"); RootMissing = $true }
    }

    # audit 2026-07-24: -ErrorAction Stop + a RECORDING catch, not SilentlyContinue +
    # a bare catch. A denied/vanished directory used to leave $toolDirs empty and say
    # nothing, so the whole tool reported "no activity" over a tree it never walked.
    $toolDirs = @()
    try { $toolDirs = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop | Where-Object { $_.Name -ne '_Rollup' }) } catch { Add-HistReadError -Bag $errBag -Path $Root -ErrorRecord $_ }

    foreach ($td in $toolDirs) {
        if ($capped) { break }
        $toolName = $td.Name
        $opDirs = @()
        try { $opDirs = @(Get-ChildItem -LiteralPath $td.FullName -Directory -ErrorAction Stop) } catch { Add-HistReadError -Bag $errBag -Path $td.FullName -ErrorRecord $_ }
        foreach ($od in $opDirs) {
            if ($capped) { break }
            foreach ($m in $Months) {
                if ($capped) { break }

                if ($IncludeDetail) {
                    $detailFiles = @()
                    # Exclude rotated stale-schema archives (<base>.legacy_<stamp>.csv);
                    # they carry old column names, so replaying them yields blank
                    # Target/Timestamp rows (the replay path skips them the same way).
                    try { $detailFiles = @(Get-ChildItem -LiteralPath $od.FullName -Filter ($m + '_detail*.csv') -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch { Add-HistReadError -Bag $errBag -Path $od.FullName -ErrorRecord $_ }
                    foreach ($f in $detailFiles) {
                        if ($capped) { break }
                        $files++
                        $rows = @()
                        # audit 2026-07-24: still swallow the THROW (one locked/corrupt month
                        # must not kill the walk) but RECORD it - this row set is now known
                        # to be incomplete, and the caller says so.
                        try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { $rows = @(); Add-HistReadError -Bag $errBag -Path $f.FullName -ErrorRecord $_ }
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
                    try { $touchFiles = @(Get-ChildItem -LiteralPath $od.FullName -Filter ('TouchedHosts_' + $m + '*.csv') -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch { Add-HistReadError -Bag $errBag -Path $od.FullName -ErrorRecord $_ }
                    foreach ($f in $touchFiles) {
                        if ($capped) { break }
                        $files++
                        $rows = @()
                        try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { $rows = @(); Add-HistReadError -Bag $errBag -Path $f.FullName -ErrorRecord $_ }
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
    return @{ Rows = $out; Capped = $capped; Files = $files; Errors = [int]$errBag.Count; ErrorMessages = @($errBag.Messages); RootMissing = $false }
}

# Read the fleet usage rollup rows for the requested months from either the share
# root (Logs\<YYYY-MM>_usage.csv) or the spool (_Rollup\<userFolder>\*_usage.csv).
# Returns @{ Rows=[ArrayList of PSCustomObject]; Capped; Errors; ErrorMessages;
# RootMissing } - same shape contract as Read-HistoryRows (audit 2026-07-24; it
# used to return the bare ArrayList, which had nowhere to report a failed read).
function Read-HistUsageRows {
    param([string]$Root, [string[]]$Months, [int]$Cap = 0)
    # audit 2026-07-24: this was the ONLY unbounded read in the module - every other
    # path rides $script:HistReadCeiling. It was sized for one SessionEnd row per
    # session; the Snapshot writer now emits a live cumulative row PER TOOL every few
    # minutes, so *_usage.csv grows an order of magnitude faster and an operator-summary
    # over a long window could slurp the whole rollup into the worker runspace. Cap it.
    if ($Cap -le 0) { $Cap = $script:HistReadCeiling }
    $out = New-Object System.Collections.ArrayList
    $errBag = New-HistErrorBag
    $capped = $false
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        return @{ Rows = $out; Capped = $false; Errors = 1; ErrorMessages = @("$Root (root not found or not readable)"); RootMissing = $true }
    }
    $usageFiles = New-Object System.Collections.ArrayList
    # Match the live <YYYY-MM>_usage.csv AND its header-ensure sisters
    # (<base>.r<unix>.csv redirect files), excluding rotated stale-schema
    # (*.legacy_*) archives - an exact-name Test-Path missed the redirect files.
    foreach ($m in $Months) {
        $mf = @()
        try { $mf = @(Get-ChildItem -LiteralPath $Root -Filter ($m + '_usage*.csv') -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch { Add-HistReadError -Bag $errBag -Path $Root -ErrorRecord $_ }
        foreach ($x in $mf) { [void]$usageFiles.Add($x.FullName) }
    }
    $rollup = Join-Path $Root '_Rollup'
    if (Test-Path -LiteralPath $rollup -ErrorAction SilentlyContinue) {
        $opDirs = @()
        try { $opDirs = @(Get-ChildItem -LiteralPath $rollup -Directory -ErrorAction Stop) } catch { Add-HistReadError -Bag $errBag -Path $rollup -ErrorRecord $_ }
        foreach ($od in $opDirs) {
            foreach ($m in $Months) {
                $rf = @()
                try { $rf = @(Get-ChildItem -LiteralPath $od.FullName -Filter ($m + '_usage*.csv') -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch { Add-HistReadError -Bag $errBag -Path $od.FullName -ErrorRecord $_ }
                foreach ($x in $rf) { [void]$usageFiles.Add($x.FullName) }
            }
        }
    }
    foreach ($uf in $usageFiles) {
        if ($capped) { break }
        $rows = @()
        try { $rows = @(Import-Csv -LiteralPath $uf -ErrorAction Stop) } catch { $rows = @(); Add-HistReadError -Bag $errBag -Path $uf -ErrorRecord $_ }
        foreach ($row in $rows) {
            if ($out.Count -ge $Cap) { $capped = $true; break }
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
    return @{ Rows = $out; Capped = $capped; Errors = [int]$errBag.Count; ErrorMessages = @($errBag.Messages); RootMissing = $false }
}

function ConvertTo-HistInt {
    param([string]$Value)
    $n = 0
    if ([int]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return 0
}

# =============================================================================
#  Run Outcomes Board (capability audit 2026-07-25 #7)
# =============================================================================
# Write-JanetWebRun (server\JanetWeb.Logging.ps1) has written a 17-column per-run
# card to Logs\<Tool>\ACAS-Nemesis-Runs_<YYYY-MM-DD>.csv since day one - byte-merged
# with the desktop's own rows - and NOTHING in either repo ever read it. Everything
# below is the read side; it walks the SAME roots, uses the SAME 445-gate
# (Resolve-HistRoot), the SAME error bag and the SAME read ceiling as every other
# reader in this module.

# Walk <Root>\<Tool>\ACAS-Nemesis-Runs_*.csv for the requested window. The day is in
# the FILE NAME, so a whole out-of-window day-file is skipped without being opened
# (the same "read only what the window needs" rule the monthly readers follow).
# Returns the module's standard reader contract:
#   @{ Rows; Capped; Files; Errors; ErrorMessages; RootMissing }
function Read-HistRunRows {
    param(
        [string]$Root,
        [datetime]$MinDate = [datetime]::MinValue,
        [int]$Cap = 0
    )
    if ($Cap -le 0) { $Cap = $script:HistReadCeiling }
    $out = New-Object System.Collections.ArrayList
    $errBag = New-HistErrorBag
    $capped = $false
    $files = 0
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        # Same rule as every other reader: an absent / unopenable root is NOT an
        # empty run history, it is a failed look. Say so.
        return @{ Rows = $out; Capped = $false; Files = 0; Errors = 1; ErrorMessages = @("$Root (root not found or not readable)"); RootMissing = $true }
    }
    $toolDirs = @()
    try { $toolDirs = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop | Where-Object { $_.Name -ne '_Rollup' }) } catch { Add-HistReadError -Bag $errBag -Path $Root -ErrorRecord $_ }

    foreach ($td in $toolDirs) {
        if ($capped) { break }
        $toolName = $td.Name
        $runFiles = @()
        # '*.legacy_*' = rotated stale-schema archives (old column names); the replay
        # path skips them and so must this reader.
        try { $runFiles = @(Get-ChildItem -LiteralPath $td.FullName -Filter 'ACAS-Nemesis-Runs_*.csv' -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch { Add-HistReadError -Bag $errBag -Path $td.FullName -ErrorRecord $_ }
        foreach ($f in $runFiles) {
            if ($capped) { break }
            # Day-file pre-filter. Matches both the live name and its header-ensure
            # sister (<base>.r<unix>.csv). A name we cannot parse is READ, never skipped -
            # skipping on an unparsed name would silently drop rows.
            if ($MinDate -gt [datetime]::MinValue -and $f.Name -match 'ACAS-Nemesis-Runs_(\d{4}-\d{2}-\d{2})') {
                $fd = [datetime]::MinValue
                if ([datetime]::TryParse($Matches[1], [ref]$fd) -and $fd.Date -lt $MinDate.Date) { continue }
            }
            $files++
            $rows = @()
            try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { $rows = @(); Add-HistReadError -Bag $errBag -Path $f.FullName -ErrorRecord $_ }
            foreach ($row in $rows) {
                $ts  = [string]$row.Timestamp
                $tsD = (ConvertTo-HistDate $ts)
                if ($tsD -lt $MinDate) { continue }          # window filter BEFORE the cap
                if ($out.Count -ge $Cap) { $capped = $true; break }
                [void]$out.Add([pscustomobject]@{
                    TS          = $tsD
                    Timestamp   = $ts
                    Tool        = $toolName
                    SessionId   = ([string]$row.SessionId)
                    Operator    = ([string]$row.User)
                    RowType     = ([string]$row.RowType)
                    Action      = ([string]$row.Action)
                    Scope       = ([string]$row.Scope)
                    Profile     = ([string]$row.Profile)
                    Mode        = ([string]$row.Mode)
                    HostsTotal  = (ConvertTo-HistInt ([string]$row.HostsTotal))
                    Success     = (ConvertTo-HistInt ([string]$row.Success))
                    Failed      = (ConvertTo-HistInt ([string]$row.Failed))
                    DurationSec = (ConvertTo-HistInt ([string]$row.DurationSec))
                    GroupKey    = ([string]$row.GroupKey)
                    GroupSize   = (ConvertTo-HistInt ([string]$row.GroupSize))
                })
            }
        }
    }
    return @{ Rows = $out; Capped = $capped; Files = $files; Errors = [int]$errBag.Count; ErrorMessages = @($errBag.Messages); RootMissing = $false }
}

# THE TRAP, in one function. Write-JanetWebRun fans a rolled-up group card out to
# ONE ROW PER MEMBER (Logging.ps1 :804-817) and every one of those rows carries the
# SAME Timestamp, SessionId, GroupKey and - critically - the SAME HostsTotal /
# Success / Failed / DurationSec counters. Summing the rows therefore multiplies the
# card's counters by GroupSize: a 3-member card that patched 12 hosts reports 36.
#
# A card is identified by (Timestamp, SessionId, GroupKey) - all three written once
# per card - with Action folded in as a cheap extra discriminator. Action is a
# superset of the stated key: every member row of one card shares it, so it never
# splits a card, and it only ever keeps two DIFFERENT cards apart.
#
# Returns $null for a NON-group row (GroupSize <= 1 and no GroupKey). A null key
# means "never de-dupe this" - two independent single runs inside the same session
# and the same second are two runs, and collapsing them would UNDER-count, which is
# the same class of wrong answer in the other direction.
function Get-HistRunCardKey {
    param($Row)
    if ($null -eq $Row) { return $null }
    $gk = ([string]$Row.GroupKey).Trim()
    $gs = [int]$Row.GroupSize
    if ($gs -gt 1 -or $gk) {
        return ('G|{0}|{1}|{2}|{3}' -f ([string]$Row.Timestamp), ([string]$Row.SessionId), $gk, ([string]$Row.Action))
    }
    return $null
}

# De-dupe group cards, then aggregate by (Action, Profile, Mode).
# Returns @{ Groups=<array of hashtables>; Cards=<deduped card count>; Deduped=<rows dropped> }.
function Group-HistRunOutcomes {
    param($Rows)
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $agg   = @{}
    $order = New-Object System.Collections.ArrayList
    $dupes = 0
    $cards = 0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        # 'SessionNotes' rows are the server's session-close roll-up (Server.ps1:712);
        # their counters are the WHOLE SESSION's, so counting them alongside the
        # per-run cards they summarise would double every number on the board.
        if ([string]$r.RowType -eq 'SessionNotes') { continue }
        $ck = Get-HistRunCardKey $r
        if ($ck) { if (-not $seen.Add($ck)) { $dupes++; continue } }
        $cards++
        $k = ('{0}|{1}|{2}' -f ([string]$r.Action), ([string]$r.Profile), ([string]$r.Mode))
        if (-not $agg.ContainsKey($k)) {
            $agg[$k] = @{
                Action = ([string]$r.Action); Profile = ([string]$r.Profile); Mode = ([string]$r.Mode)
                Runs = 0; HostsTotal = 0; Success = 0; Failed = 0; DurSum = 0
                Last = [datetime]::MinValue; LastStr = ''
                Ops = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
            }
            [void]$order.Add($k)
        }
        $a = $agg[$k]
        $a.Runs++
        $a.HostsTotal  += [int]$r.HostsTotal
        $a.Success     += [int]$r.Success
        $a.Failed      += [int]$r.Failed
        $a.DurSum      += [int]$r.DurationSec
        if ($r.TS -gt $a.Last) { $a.Last = $r.TS; $a.LastStr = [string]$r.Timestamp }
        $op = ([string]$r.Operator).Trim()
        if ($op) { [void]$a.Ops.Add($op) }
    }
    $groups = @()
    foreach ($k in @($order)) { $groups += ,$agg[$k] }
    return @{ Groups = $groups; Cards = $cards; Deduped = $dupes }
}

# =============================================================================
#  Fleet coverage reconciliation (capability audit 2026-07-25 #8)
# =============================================================================

# Local-domain DN guard. BYTE-FAITHFUL copy of Test-AdSearchDnInLocalDomain
# (JanetWeb.adsearch.psm1) / the AD TO scan's twin - COPIED, not imported: this
# module loads into its own worker runspace and importing a sibling tool module to
# borrow one guard would drag its whole engine (and its share probes) in with it.
# Keep it in lockstep with the adsearch copy; History.CoverageReconcile.Tests.ps1
# pins the behaviour that matters.
#
# LDAP://<searchBase> is a BIND path, not a filter: a value like 'evildc/DC=x' or a
# full 'LDAP://evil' URL would redirect the search-root bind to an attacker-chosen
# host, and a bare foreign DN like 'DC=evil,DC=com' would bind SERVERLESSLY to the
# attacker's domain. Require a plain DN that ENDS at THIS host's own domain suffix.
function Test-HistDnInLocalDomain {
    param([string]$Value, [string]$ExpectDomainSuffix)
    if ($Value -notmatch '^[A-Za-z]{1,8}=') { return $false }
    if ($Value -match '/') { return $false }
    # Reject any control char (NUL..US, incl. CR/LF/TAB): a real DN never carries one, and .NET's
    # regex '$' ALSO matches just before a trailing newline - so a value like "...DC=MIL`n" would
    # otherwise slip past the component-boundary anchor below.
    if ($Value -match '[\x00-\x1f]') { return $false }
    if (-not $ExpectDomainSuffix) { return $false }
    # RFC-4514: an RDN value escapes special chars with a backslash (CN=Smith\, John).
    # Strip every \<char> escape pair BEFORE the boundary/count checks so an escaped comma
    # inside a value can't manufacture a fake component boundary or inflate the DC count.
    $bare = $Value -replace '\\.', ''
    # the domain suffix must sit at a COMPONENT boundary (string start or right after a
    # comma), not merely as a trailing substring (blocks e.g. CN=ABDC=AREA52,DC=MIL)
    if ($bare -notmatch ('(^|,)' + [regex]::Escape($ExpectDomainSuffix) + '$')) { return $false }
    # and NO EXTRA DC= component beyond the expected suffix - so a child-subdomain prepend
    # (DC=evil,DC=area52,DC=mil -> the distinct domain evil.area52.mil) is rejected
    $dcInValue  = ([regex]::Matches($bare, '(?i)(^|,)DC=')).Count
    $dcInSuffix = ([regex]::Matches($ExpectDomainSuffix, '(?i)(^|,)DC=')).Count
    if ($dcInValue -ne $dcInSuffix) { return $false }
    return $true
}

# DC=... form of THIS host's own domain. Process-level $env:USERDNSDOMAIN so it
# resolves inside the bare worker runspace.
function Get-HistExpectedDomainSuffix {
    $d = [string]$env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($d)) { return '' }
    return (($d -split '\.' | Where-Object { $_ } | ForEach-Object { "DC=$_" }) -join ',')
}

# ONE paged LDAP searcher over (objectCategory=computer). Never a per-host query -
# at fleet scale that is thousands of round trips. Searcher hygiene (ReferralChasing
# None, bounded server/client timeouts, Dispose in a finally) is copied from
# JanetWeb.adsearch.psm1 :485-486/:547 - copied, not imported, same reason as the DN
# guard above.
#
# userAccountControl is loaded because it is the ONLY authoritative account-status
# flag; the capability audit's C2 finding is that adsearch's bulk computer lookup
# cannot see it at all. lastLogonTimestamp (replicated) is loaded, never lastLogon
# (per-DC, NOT replicated - it renders "never" for accounts that log on daily).
#
# Returns @{ Rows; Capped; Cancelled; Errors; ErrorMessages }. A THROW leaves the
# enumeration KNOWN-INCOMPLETE (Errors>0), which the caller must render as UNKNOWN.
function Read-HistAdComputers {
    param(
        [string]$SearchBase = '',
        [System.Management.Automation.PSCredential]$Credential = $null,
        [int]$Cap = 0,
        [scriptblock]$IsCancelled = $null,
        [scriptblock]$OnProgress = $null
    )
    if ($Cap -le 0) { $Cap = $script:HistAdCeiling }
    $out = New-Object System.Collections.ArrayList
    $errBag = New-HistErrorBag
    $capped = $false; $cancelled = $false
    $rootDse = $null; $de = $null; $searcher = $null; $col = $null
    try {
        $u = $null; $p = $null
        if ($Credential) { $u = $Credential.UserName; $p = $Credential.GetNetworkCredential().Password }
        $path = ''
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $path = "LDAP://$SearchBase"
        } else {
            $rootDse = if ($Credential) { New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE', $u, $p) } else { New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE') }
            $nc = [string]$rootDse.Properties['defaultNamingContext'][0]
            if ([string]::IsNullOrWhiteSpace($nc)) { throw 'cannot read defaultNamingContext (not domain-joined or no DC reachable)' }
            $path = "LDAP://$nc"
        }
        $de = if ($Credential) { New-Object System.DirectoryServices.DirectoryEntry($path, $u, $p) } else { New-Object System.DirectoryServices.DirectoryEntry($path) }
        # ADSI binds LAZILY: neither the constructor nor the SearchRoot assignment
        # contacts the directory, so a typo'd (but syntactically valid) OU would slip
        # past this catch and throw later at an uncaught FindAll(). Touch NativeObject
        # to force the bind NOW.
        $null = $de.NativeObject
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
        # Do NOT auto-follow a directory-returned EXTERNAL referral: even a
        # local-domain-rooted search could otherwise be redirected to a host the DN
        # guard never vetted.
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
        try { $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds(90) }  catch {}
        try { $searcher.ClientTimeout   = [TimeSpan]::FromSeconds(120) } catch {}
        $searcher.Filter   = '(objectCategory=computer)'
        $searcher.PageSize = 1000
        $searcher.SizeLimit = 0     # paging makes ADSI ignore SizeLimit; $Cap below is the real bound
        foreach ($a in 'name','distinguishedName','operatingSystem','userAccountControl','lastLogonTimestamp') { [void]$searcher.PropertiesToLoad.Add($a) }
        $col = $searcher.FindAll()
        $n = 0
        foreach ($res in $col) {
            # Cooperative cancel. The enumerator pulls a PAGE at a time, so a check here
            # is a check between pages - an operator pressing Cancel on a 20k-object
            # domain does not wait for the whole enumeration.
            if ($IsCancelled -and (& $IsCancelled)) { $cancelled = $true; break }
            if ($out.Count -ge $Cap) { $capped = $true; break }
            $pr = $res.Properties
            $name = if ($pr['name'].Count) { [string]$pr['name'][0] } else { '' }
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $dn  = if ($pr['distinguishedname'].Count) { [string]$pr['distinguishedname'][0] } else { '' }
            $os  = if ($pr['operatingsystem'].Count)   { [string]$pr['operatingsystem'][0] }   else { '' }
            # FAIL CLOSED on an unreadable userAccountControl (audit C2, matching adto):
            # UacKnown=$false means we CANNOT say whether this object is alive, and the
            # caller must render UNKNOWN rather than assume Enabled.
            $uacKnown = [bool]$pr['useraccountcontrol'].Count
            $uac = 0
            if ($uacKnown) { try { $uac = [int]$pr['useraccountcontrol'][0] } catch { $uacKnown = $false; $uac = 0 } }
            $llRaw = 0
            if ($pr['lastlogontimestamp'].Count) { try { $llRaw = [int64]$pr['lastlogontimestamp'][0] } catch { $llRaw = 0 } }
            $ll = [datetime]::MinValue
            if ($llRaw -gt 0) { try { $ll = [datetime]::FromFileTimeUtc($llRaw).ToLocalTime() } catch { $ll = [datetime]::MinValue } }
            [void]$out.Add([pscustomobject]@{
                Name          = $name.ToUpperInvariant()
                Dn            = $dn
                Os            = $os
                UacKnown      = [bool]$uacKnown
                Uac           = [int]$uac
                Enabled       = (($uac -band 2) -eq 0)
                LastLogon     = $ll
            })
            $n++
            if ($OnProgress -and ($n % 1000) -eq 0) { try { & $OnProgress $n } catch {} }
        }
    } catch {
        Add-HistReadError -Bag $errBag -Path ("LDAP query" + $(if ($SearchBase) { " ($SearchBase)" } else { ' (whole domain)' })) -ErrorRecord $_
    } finally {
        foreach ($o in @($col, $searcher, $de, $rootDse)) { if ($null -ne $o) { try { $o.Dispose() } catch {} } }
    }
    return @{ Rows = $out; Capped = $capped; Cancelled = $cancelled; Errors = [int]$errBag.Count; ErrorMessages = @($errBag.Messages) }
}

# The verdict table, isolated so it is unit-testable without a directory or a share.
#   AdAlive  : $true / $false / $null  ($null = AD status UNKNOWN, e.g. uac unreadable)
#   InAd     : was the host found in the AD enumeration at all
#   Touched  : did the audit trail show ANY touch inside the lookback
#   DaysAgo  : days since that touch (ignored when -not $Touched)
#   Unknown  : the audit read (or the AD read, for a host absent from AD) is INCOMPLETE
# FAIL CLOSED: whenever the answer rests on a read that did not fully succeed, the
# verdict is UNKNOWN - never COVERED. COVERED is a positive claim about a live host,
# and it is the one verdict a lead uses to STOP looking at a machine.
function Get-HistCoverageVerdict {
    param(
        [Nullable[bool]]$AdAlive,
        [bool]$InAd,
        [bool]$Touched,
        [int]$DaysAgo = 0,
        [int]$ThresholdDays = 30,
        [string]$UnknownReason = ''
    )
    if ($UnknownReason) { return $UnknownReason }
    if (-not $InAd) {
        # Reconciling the other direction: JANET has an opinion about a host the
        # directory has no object for. Touched -> that IS a ghost.
        if ($Touched) { return 'GHOST' }
        return 'DEAD OBJECT'
    }
    if ($null -eq $AdAlive) { return 'UNKNOWN (AD status unreadable)' }
    if (-not $AdAlive) {
        if ($Touched) { return 'GHOST' }
        return 'DEAD OBJECT'
    }
    if (-not $Touched) { return 'NEVER TOUCHED (live)' }
    if ($DaysAgo -le $ThresholdDays) { return 'COVERED' }
    return 'STALE (live)'
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # One place to turn a reader's error bag into operator-visible signal. A read
    # failure is NOT "no rows found" - it means the answer is UNKNOWN, so it is
    # reported at err level and named in the log. (audit 2026-07-24)
    $reportReadErrors = {
        param($ReadResult, $What)
        $n = [int]$ReadResult.Errors
        if ($n -le 0) { return }
        & $send @{ type='log'; level='err'; text="[$(Get-Date -Format 'HH:mm:ss')] $n read failure(s) while $What - this result is INCOMPLETE / UNKNOWN, NOT a clean empty answer. Do not read a missing row as 'never happened'." }
        foreach ($m in @($ReadResult.ErrorMessages)) { & $send @{ type='log'; level='warn'; text="    read failed: $m" } }
    }

    $loc = Resolve-HistRoot
    $root = $loc.Root
    & $send @{ type='log'; level=($(if ($loc.OnShare) { 'info' } else { 'warn' })); text="[$(Get-Date -Format 'HH:mm:ss')] Source: $($loc.Reason)." }
    # audit 2026-07-24: Resolve-HistRoot has always computed .Exists but NO caller read
    # it, so "share unreachable AND no local spool" rendered byte-identical to a genuinely
    # empty audit trail - zero rows, no warning, green status. Say it out loud up front;
    # each action below also folds it into its own read-failure state.
    if (-not $loc.Exists) {
        & $send @{ type='error'; text="Audit source NOT READABLE: $($loc.Root) does not exist or cannot be opened. Every empty result below is UNKNOWN, not evidence of no activity." }
    }
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
            return @{ rows=@(); summary=@{ total=0; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
        }
        # Validate the host token (parity with stale-hosts:561): a real host name starts
        # alphanumeric and is [A-Za-z0-9._-]. Reject anything else so a pasted control char
        # or path fragment never reaches the matcher. Read-only tool - defense-in-depth /
        # consistency, not a live exploit. (audit loop9->10 P3)
        if ($hostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') {
            & $send @{ type='log'; level='warn'; text="Invalid host name: $hostName" }
            return @{ rows=@(); summary=@{ total=0; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
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
        # audit 2026-07-24: a timeline with no rows over a source we could not READ is a
        # different fact from a host with no history. Track it and say which one this is.
        $readFailed = ((-not $loc.Exists) -or ([int]$res.Errors -gt 0))
        & $reportReadErrors $res "building the timeline for $hostName"
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
            if ($readFailed) {
                # The empty grid here is an I/O outcome, not an audit finding.
                & $send @{ type='error'; text="No audit rows returned for $hostName, but the audit source could not be read - this is UNKNOWN, not 'this host was never touched'. Fix the source and re-run." }
            } else {
                & $send @{ type='log'; level='warn'; text="No audit rows found for $hostName in the last $months month(s)." }
            }
        } else {
            & $send @{ type='log'; level=($(if ($readFailed) { 'warn' } else { 'ok' })); text="$($rows.Count) audit row(s) for $hostName ($($tools.Count) tool(s), $fails failure(s))$($(if ($readFailed) { ' - PARTIAL: some sources could not be read' } else { '' }))." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - the timeline may be missing older rows; narrow the month window." } }
        elseif ($capped) { & $send @{ type='log'; level='warn'; text="Display cap ($($script:HistDisplayCap)) reached - showing the newest rows; narrow the month window for the full history." } }
        & $send @{ type='status'; text="Done. $($rows.Count) row(s) for $hostName$($(if ($readFailed) { ' (READ ERRORS - incomplete)' } else { '' }))." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; tools=$tools.Count; failures=$fails; host=$hostName; months=$months; capped=($capped -or [bool]$res.Capped); readErrors=[int]$res.Errors; readFailed=[bool]$readFailed; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
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
        # audit 2026-07-24: "the fleet was quiet this week" and "we could not read the
        # audit trail this week" are opposite conclusions; they used to render the same.
        $readFailed = ((-not $loc.Exists) -or ([int]$res.Errors -gt 0))
        & $reportReadErrors $res "reading activity for the last $days day(s)"
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
            if ($readFailed) {
                & $send @{ type='error'; text="No audit rows returned for the last $days day(s), but the audit source could not be read - this is UNKNOWN, not 'nothing happened'." }
            } else {
                & $send @{ type='log'; level='warn'; text="No audit rows in the last $days day(s)." }
            }
        } else {
            & $send @{ type='log'; level=($(if ($readFailed) { 'warn' } else { 'ok' })); text="$($rows.Count) audit row(s) in the last $days day(s): $fails failure(s) ($failPct%), $($ops.Count) operator(s)$($(if ($readFailed) { ' - PARTIAL: some sources could not be read' } else { '' }))." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - results are incomplete across tools; shorten the window." } }
        elseif ($capped) { & $send @{ type='log'; level='warn'; text="Display cap ($($script:HistDisplayCap)) reached - showing the newest rows; shorten the window for the full set." } }
        & $send @{ type='status'; text="Done. $($rows.Count) row(s) in $days day(s)$($(if ($readFailed) { ' (READ ERRORS - incomplete)' } else { '' }))." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; failures=$fails; failPct=$failPct; operators=$ops.Count; days=$days; capped=($capped -or $res.Capped); readErrors=[int]$res.Errors; readFailed=[bool]$readFailed; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
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
        $usageRes = Read-HistUsageRows -Root $root -Months $tokens
        $usage = $usageRes.Rows
        # audit 2026-07-24: fold BOTH readers' failures in - an operator whose months
        # failed to read would otherwise show a confident zero on someone's activity report.
        $readErrors = [int]$res.Errors + [int]$usageRes.Errors
        $readFailed = ((-not $loc.Exists) -or ($readErrors -gt 0))
        & $reportReadErrors $res 'reading operator detail rows'
        & $reportReadErrors $usageRes 'reading the usage rollup'

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
        # JANET Web writes one row per tool PLUS an aggregate 'JANET-WEB' row (all
        # sharing one SessionId; historical rows use the TWO-era 'JANET-TWO' name);
        # the same shared *_usage.csv also holds the desktop
        # suite's SessionEnd rows (Tool = 'WPT'/'ACAS_Nemesis'/...). The old filter
        # (aggregate rows only) dropped every desktop session, so an operator who
        # works only in the desktop tools showed Sessions=0/HostsTouched=0. Group by
        # SessionId, count each once, and prefer the aggregate row's HostsTouched.
        #
        # audit 2026-07-24 (S4): ALSO accept RowType='Snapshot'. Write-JanetWebUsageSnapshot
        # emits live cumulative per-tool rows (~5 min) precisely so a server that is still
        # running - or was killed - is not invisible. This reader kept the old SessionEnd-only
        # filter, so the in-app History panel reported Sessions=0/HostsTouched=0 for every live
        # session while the external dashboard (which does consume Snapshot) showed it fine.
        # CORRECTION (fable re-audit, same day): an earlier draft of this comment said
        # "Snapshot writes per-tool rows ONLY, never an aggregate 'JANET-WEB' row" and leaned on
        # that to claim precedence was correct for free. That stopped being true LATER THE SAME
        # PASS, when Write-JanetWebUsageSnapshot was changed to also emit an aggregate row (so
        # reports' Tool='JANET-WEB' scope filter could still see a live session). The old
        # "aggregate wins" rule was then LAST-READ-WINS between two aggregate rows, and
        # Read-HistUsageRows enumerates newest-month-first and share-before-spool - so across a
        # month rollover, or a mid-session share blip, an OLDER cumulative Snapshot aggregate
        # could overwrite the final SessionEnd value and UNDERSTATE HostsTouched.
        # Fix: rank explicitly. SessionEnd aggregate > Snapshot aggregate > per-tool max.
        # Sessions are still counted once per SessionId, so nothing double-counts.
        $sessions = @{}   # sessionKey -> hashtable
        foreach ($u in $usage) {
            $rowType = [string]$u.RowType
            if ($rowType -ne 'SessionEnd' -and $rowType -ne 'Snapshot') { continue }
            $op    = [string]$u.Operator
            $sid   = ([string]$u.SessionId).Trim()
            $isAgg = ('JANET-WEB','JANET-TWO' -contains [string]$u.Tool)
            $isEnd = ($rowType -eq 'SessionEnd')
            # 2 = SessionEnd aggregate (authoritative), 1 = Snapshot aggregate (live, cumulative),
            # 0 = per-tool row of either type (only ever contributes via the max rule).
            $rank  = if ($isAgg -and $isEnd) { 2 } elseif ($isAgg) { 1 } else { 0 }
            $hosts = (ConvertTo-HistInt ([string]$u.HostsTouched))
            # Blank SessionId (legacy rows): synthesize a per-row key so unrelated
            # sessions are not collapsed together.
            $key = if ($sid) { $sid } else { ('__nosid_' + $op + '_' + ([string]$u.Timestamp) + '_' + [string]$u.Tool) }
            if (-not $sessions.ContainsKey($key)) {
                $sessions[$key] = @{ Operator=$op; HostsTouched=$hosts; AggRank=$rank; TS=$u.TS }
            } else {
                $s = $sessions[$key]
                # Higher-ranked aggregate always wins. Equal rank (two Snapshot aggregates from
                # different files) keeps the LARGER - the counters are cumulative, so the bigger
                # value is the later one regardless of which file order we happened to read in.
                if ($rank -gt [int]$s.AggRank) { $s.HostsTouched = $hosts; $s.AggRank = $rank }
                elseif ($rank -eq [int]$s.AggRank -and $hosts -gt [int]$s.HostsTouched) { $s.HostsTouched = $hosts }
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
            if ($readFailed) {
                & $send @{ type='error'; text="No operator activity returned, but the audit source could not be read - this is UNKNOWN, not 'nobody worked'." }
            } else {
                & $send @{ type='log'; level='warn'; text="No operator activity found in the last $months month(s)." }
            }
        } else {
            & $send @{ type='log'; level=($(if ($readFailed) { 'warn' } else { 'ok' })); text="$($rows.Count) operator(s): $totalActions action(s), $totalFails failure(s) over $months month(s)$($(if ($readFailed) { ' - PARTIAL: some sources could not be read' } else { '' }))." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - operator totals are partial (some tool directories were not scanned); narrow the window." } }
        if ($usageRes.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit on the usage rollup - session / hosts-touched totals are partial; narrow the window." } }
        & $send @{ type='status'; text="Done. $($rows.Count) operator(s)$($(if ($readFailed) { ' (READ ERRORS - incomplete)' } else { '' }))." }
        return @{ rows=@($rows); summary=@{ operators=$rows.Count; actions=$totalActions; failures=$totalFails; months=$months; capped=([bool]$res.Capped -or [bool]$usageRes.Capped); readErrors=$readErrors; readFailed=[bool]$readFailed; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # -------------------------------------------------------------- stale-hosts
    if ($ActionId -eq 'stale-hosts') {
        $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No valid hosts entered.' }
            return @{ rows=@(); summary=@{ total=0; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
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
        & $reportReadErrors $res 'scanning for last-touched'

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
        # audit 2026-07-24: the same false-verdict hazard, from the other direction. A
        # denied ACL, a share that dropped mid-walk, or a locked monthly CSV used to be
        # swallowed silently, so a host whose rows were never actually READ came out
        # NEVER TOUCHED - the loudest verdict on this board and the one a lead acts on
        # (schedule a patch run, open a ticket, chase an owner). Refuse to claim it when
        # the underlying read did not succeed; report UNKNOWN (read error) instead.
        $readFailed = ((-not $loc.Exists) -or ([int]$res.Errors -gt 0) -or [bool]$res.RootMissing)
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
            } elseif ($capped -or $readFailed) {
                # Capped wins the label when both are true: it is the more specific,
                # operator-actionable cause (narrow the window) of the two.
                $verdict = $(if ($capped) { 'UNKNOWN (capped)' } else { 'UNKNOWN (read error)' }); $unknown++
            } else {
                $verdict = 'NEVER TOUCHED'; $never++
            }
            $row = @{ _rk=("s{0}" -f $idx); Host=$t; LastTouched=$lastStr; DaysAgo=("$daysAgo"); LastTool=$tool; LastOperator=$op; Verdict=$verdict }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        & $send @{ type='log'; level=($(if ($stale -or $never -or $unknown) { 'warn' } else { 'ok' })); text="Staleness (threshold ${threshold}d, lookback ${lookback}mo): FRESH=$fresh, STALE=$stale, NEVER TOUCHED=$never, UNKNOWN=$unknown of $($targets.Count)." }
        if ($capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - some tool directories were not scanned; hosts with no match are shown as UNKNOWN (capped), not NEVER TOUCHED. Narrow the host list or lookback for reliable verdicts." } }
        elseif ($readFailed) { & $send @{ type='error'; text="The audit source could not be fully read - hosts with no matching row are shown as UNKNOWN (read error), NOT 'NEVER TOUCHED'. This board proves nothing about those hosts until the source is readable." } }
        if ($never -gt 0) { & $send @{ type='log'; level='info'; text="NEVER TOUCHED means no audit row within the ${lookback}-month lookback - not necessarily never in all history." } }
        & $send @{ type='status'; text="Done. FRESH=$fresh, STALE=$stale, NEVER=$never, UNKNOWN=$unknown of $($targets.Count)." }
        return @{ rows=@($rows); summary=@{ total=$targets.Count; fresh=$fresh; stale=$stale; never=$never; unknown=$unknown; capped=$capped; readErrors=[int]$res.Errors; readFailed=[bool]$readFailed; sourceReadable=[bool]$loc.Exists; thresholdDays=$threshold; lookbackMonths=$lookback; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # ------------------------------------------------------------ run-outcomes
    # The Run Outcomes Board. Pure value that was already on disk: Write-JanetWebRun
    # has written these cards since day one and nothing ever read them.
    if ($ActionId -eq 'run-outcomes') {
        $days = ConvertTo-HistInt ([string]$Params['days']); if ($days -le 0) { $days = 30 }
        if ($days -gt 365) { $days = 365 }
        $cutoff = (Get-Date).AddDays(-$days)

        & $send @{ type='status'; text="Reading per-run outcome cards for the last $days day(s)..." }
        $res = Read-HistRunRows -Root $root -MinDate $cutoff -Cap $script:HistReadCeiling
        # Same doctrine as every other action here: "no runs this month" and "we could
        # not read the run cards this month" are opposite conclusions. Never merge them.
        $readFailed = ((-not $loc.Exists) -or ([int]$res.Errors -gt 0) -or [bool]$res.RootMissing)
        & $reportReadErrors $res "reading the per-run cards for the last $days day(s)"

        $grouped = Group-HistRunOutcomes -Rows $res.Rows
        $ordered = @($grouped.Groups | Sort-Object -Property @{ Expression = { [int]$_.Runs } }, @{ Expression = { $_.Last } } -Descending)

        $totRuns = 0; $totHosts = 0; $totOk = 0; $totFail = 0; $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($a in $ordered) {
            $totRuns += [int]$a.Runs; $totHosts += [int]$a.HostsTotal
            $totOk   += [int]$a.Success; $totFail += [int]$a.Failed
            # Success rate over what was actually ATTEMPTED. HostsTotal is the fallback
            # for a card that recorded a fleet size but no per-host outcome split.
            $att = [int]$a.Success + [int]$a.Failed
            $den = if ($att -gt 0) { $att } else { [int]$a.HostsTotal }
            $pct = if ($den -gt 0) { [math]::Round((([double]$a.Success) / $den) * 100, 1) } else { 0 }
            $avg = if ([int]$a.Runs -gt 0) { [math]::Round((([double]$a.DurSum) / [int]$a.Runs), 1) } else { 0 }
            $idx++
            $row = @{
                _rk            = ("ro{0}" -f $idx)
                Action         = $(if ([string]::IsNullOrWhiteSpace([string]$a.Action)) { '(none)' } else { [string]$a.Action })
                Profile        = $(if ([string]::IsNullOrWhiteSpace([string]$a.Profile)) { '(none)' } else { [string]$a.Profile })
                Mode           = $(if ([string]::IsNullOrWhiteSpace([string]$a.Mode)) { '(none)' } else { [string]$a.Mode })
                Runs           = [int]$a.Runs
                HostsTotal     = [int]$a.HostsTotal
                Success        = [int]$a.Success
                Failed         = [int]$a.Failed
                SuccessPct     = $pct
                AvgDurationSec = $avg
                LastRun        = [string]$a.LastStr
                Operators      = [int]$a.Ops.Count
            }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }

        if ([int]$grouped.Deduped -gt 0) {
            & $send @{ type='log'; level='info'; text="$($grouped.Deduped) rolled-up group-card member row(s) de-duplicated: a group card is written one row PER MEMBER with the SAME counters, so summing them raw would multiply Success/Failed by the group size. Each card is counted ONCE." }
        }
        if ($rows.Count -eq 0) {
            if ($readFailed) {
                & $send @{ type='error'; text="No run cards returned for the last $days day(s), but the run-card source could not be read - this is UNKNOWN, not 'no runs happened'." }
            } else {
                & $send @{ type='log'; level='warn'; text="No per-run cards in the last $days day(s)." }
            }
        } else {
            $ovAtt = $totOk + $totFail
            $ovPct = if ($ovAtt -gt 0) { [math]::Round((([double]$totOk) / $ovAtt) * 100, 1) } else { 0 }
            & $send @{ type='log'; level=($(if ($readFailed) { 'warn' } else { 'ok' })); text="$($rows.Count) group(s): $totRuns run(s), $totOk success / $totFail failed ($ovPct%) over $days day(s)$($(if ($readFailed) { ' - PARTIAL: some sources could not be read' } else { '' }))." }
        }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit - the board is PARTIAL (whole tool directories may be unscanned); shorten the window." } }
        & $send @{ type='status'; text="Done. $($rows.Count) group(s), $totRuns run(s)$($(if ($readFailed) { ' (READ ERRORS - incomplete)' } else { '' }))." }
        $ovAtt2 = $totOk + $totFail
        return @{ rows=@($rows); summary=@{
            total=$rows.Count; runs=$totRuns; hosts=$totHosts; success=$totOk; failed=$totFail
            successPct=$(if ($ovAtt2 -gt 0) { [math]::Round((([double]$totOk) / $ovAtt2) * 100, 1) } else { 0 })
            deduped=[int]$grouped.Deduped; files=[int]$res.Files; days=$days
            capped=[bool]$res.Capped; readErrors=[int]$res.Errors; readFailed=[bool]$readFailed
            sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    # ------------------------------------------------------ coverage-reconcile
    # The Staleness Board only verdicts hosts the operator PASTES; wpt/ad-computers
    # already enumerates the whole domain but only to feed an OU picker. This joins
    # them so "you patched 400 hosts but 60 are dead AD objects" stops being a
    # by-hand diff between two grids.
    if ($ActionId -eq 'coverage-reconcile') {
        $searchBase = ([string]$Params['searchBase']).Trim()
        $threshold  = ConvertTo-HistInt ([string]$Params['thresholdDays']);  if ($threshold -le 0) { $threshold = 30 }
        $adStale    = ConvertTo-HistInt ([string]$Params['adStaleDays']);    if ($adStale   -le 0) { $adStale   = 90 }
        $lookback   = ConvertTo-HistInt ([string]$Params['lookbackMonths']); if ($lookback  -le 0) { $lookback  = 12 }

        # DN guard FIRST - before any bind is attempted (see Test-HistDnInLocalDomain).
        if (-not [string]::IsNullOrWhiteSpace($searchBase)) {
            $expectDom = Get-HistExpectedDomainSuffix
            if (-not (Test-HistDnInLocalDomain -Value $searchBase -ExpectDomainSuffix $expectDom)) {
                & $send @{ type='error'; text="Rejected search base '$searchBase': must be a plain distinguished name ending at this host's domain ($(if ($expectDom) { $expectDom } else { '<USERDNSDOMAIN not set>' })), e.g. OU=Squadron,$expectDom - no server prefix, no '/' path chars, and no foreign domain." }
                & $send @{ type='status'; text='Rejected: invalid search base.' }
                return @{ rows=@(); summary=@{ total=0; rejected=$true; readFailed=$true; sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
            }
        }

        # Operator-cancel bridge: the server injects the synchronized job hashtable as
        # $Params['__job']; its 'Cancel' flag lets the fleet enumeration stop promptly.
        # No __job (direct/test calls) -> the check is always $false.
        $cancelJob = $null
        if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
        $isCancelled = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

        & $send @{ type='status'; text=("Enumerating AD computer objects" + $(if ($searchBase) { " under $searchBase" } else { ' (whole domain)' }) + '...') }
        $progress = { param($n) & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] $n AD computer object(s) read..." } }.GetNewClosure()
        $ad = Read-HistAdComputers -SearchBase $searchBase -Credential $Credential -Cap $script:HistAdCeiling -IsCancelled $isCancelled -OnProgress $progress
        $adRows   = @($ad.Rows)
        $adFailed = ([int]$ad.Errors -gt 0)
        $adCapped = [bool]$ad.Capped
        if ($adFailed) {
            & $send @{ type='error'; text="AD enumeration FAILED - the fleet population is UNKNOWN, not empty. No host below can be called COVERED on the strength of a directory read that did not happen." }
            foreach ($m in @($ad.ErrorMessages)) { & $send @{ type='log'; level='warn'; text="    AD read failed: $m" } }
        }
        if ($ad.Cancelled) { & $send @{ type='log'; level='warn'; text='Cancelled by operator - the AD enumeration is PARTIAL, so hosts it never reached are reported UNKNOWN.' } }
        if ($adCapped)     { & $send @{ type='log'; level='warn'; text="AD enumeration capped at $($script:HistAdCeiling) object(s) - this is NOT the whole fleet. Narrow the search base; hosts beyond the cap are invisible to this board." } }
        elseif ($adRows.Count -ge $script:HistAdAdvisory) { & $send @{ type='log'; level='warn'; text="$($adRows.Count) computer object(s) returned - a large fleet read. Narrow the search base to reduce load." } }
        $adIncomplete = ($adFailed -or $adCapped -or [bool]$ad.Cancelled)

        # Optional pasted list: reconcile the OTHER direction (hosts JANET knows about
        # that the directory may have no live object for).
        $pasted = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)

        if ($adRows.Count -eq 0 -and $pasted.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='Nothing to reconcile: the AD enumeration returned no computer objects and no hosts were pasted.' }
            & $send @{ type='status'; text='Done. 0 host(s).' }
            return @{ rows=@(); summary=@{ total=0; adTotal=0; adFailed=[bool]$adFailed; adCapped=$adCapped; cancelled=[bool]$ad.Cancelled; readFailed=($adFailed -or -not $loc.Exists); sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
        }

        # ---- join in memory against the SAME audit-trail read stale-hosts uses ----
        $tokens = Get-HistMonthTokens -Back $lookback
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($a in $adRows) { [void]$set.Add((Get-HistShortName $a.Name)) }
        foreach ($t in $pasted) { [void]$set.Add((Get-HistShortName $t)) }
        # Inline (see host-timeline): a GetNewClosure() scriptblock does NOT inherit the
        # module's helper functions, so the matcher must be self-contained.
        $match = { param($t) $set.Contains(((([string]$t).Trim() -split '\.')[0]).ToUpper()) }.GetNewClosure()

        & $send @{ type='status'; text="Joining $($set.Count) host(s) against the audit trail over $lookback month(s)..." }
        $res = Read-HistoryRows -Root $root -Months $tokens -IncludeDetail $true -IncludeTouched $true -HostMatch $match -Cap $script:HistReadCeiling
        & $reportReadErrors $res 'reconciling the audit trail against the AD population'
        $auditCapped = [bool]$res.Capped
        $auditFailed = ((-not $loc.Exists) -or ([int]$res.Errors -gt 0) -or [bool]$res.RootMissing)

        $latest = @{}
        foreach ($r in $res.Rows) {
            $sn = Get-HistShortName $r.Target
            if (-not $sn) { continue }
            if (-not $latest.ContainsKey($sn) -or $r.TS -gt $latest[$sn].TS) {
                $latest[$sn] = [pscustomobject]@{ TS=$r.TS; Tool=[string]$r.Tool; Timestamp=[string]$r.Timestamp }
            }
        }

        # FAIL CLOSED. A capped or errored audit read means we did not look everywhere,
        # so EVERY verdict on this board is UNKNOWN - the alternative is telling a lead a
        # machine is COVERED on the strength of rows we never read. Capped wins the label
        # when both are true: it names the more specific, operator-actionable cause.
        $globalUnknown = ''
        if ($auditCapped)      { $globalUnknown = 'UNKNOWN (capped)' }
        elseif ($auditFailed)  { $globalUnknown = 'UNKNOWN (read error)' }

        $now = (Get-Date)
        $adStaleCutoff = $now.AddDays(-$adStale)
        $staleLabel = ('Stale-{0}d' -f $adStale)

        $built = New-Object System.Collections.ArrayList
        $adSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($a in ($adRows | Sort-Object -Property Name)) {
            $sn = Get-HistShortName $a.Name
            [void]$adSeen.Add($sn)
            $touched = $latest.ContainsKey($sn)
            $lastStr = ''; $daysAgo = ''; $tool = ''; $dAgo = 0
            if ($touched) {
                $info = $latest[$sn]
                $lastStr = $info.Timestamp; $tool = [string]$info.Tool
                $dAgo = [int][math]::Floor(($now - $info.TS).TotalDays)
                $daysAgo = "$dAgo"
            }
            # AdStatus. userAccountControl is authoritative for Disabled; the
            # lastLogonTimestamp overlay only ever fires on a READABLE, genuinely old
            # value - an absent timestamp is not evidence of death.
            $alive = $null; $status = 'UNKNOWN'
            if ($a.UacKnown) {
                if (-not $a.Enabled) { $status = 'Disabled'; $alive = $false }
                elseif ($a.LastLogon -gt [datetime]::MinValue -and $a.LastLogon -lt $adStaleCutoff) { $status = $staleLabel; $alive = $false }
                else { $status = 'Enabled'; $alive = $true }
            }
            $verdict = Get-HistCoverageVerdict -AdAlive $alive -InAd $true -Touched $touched -DaysAgo $dAgo -ThresholdDays $threshold -UnknownReason $globalUnknown
            [void]$built.Add(@{
                Host = $a.Name; AdStatus = $status
                LastAdLogon = $(if ($a.LastLogon -gt [datetime]::MinValue) { $a.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                LastTouched = $lastStr; DaysAgo = $daysAgo; LastTool = $tool; Verdict = $verdict
            })
        }
        # Pasted hosts the directory has no object for.
        foreach ($t in $pasted) {
            $sn = Get-HistShortName $t
            if ($adSeen.Contains($sn)) { continue }
            $touched = $latest.ContainsKey($sn)
            $lastStr = ''; $daysAgo = ''; $tool = ''; $dAgo = 0
            if ($touched) {
                $info = $latest[$sn]
                $lastStr = $info.Timestamp; $tool = [string]$info.Tool
                $dAgo = [int][math]::Floor(($now - $info.TS).TotalDays)
                $daysAgo = "$dAgo"
            }
            # An INCOMPLETE AD read cannot prove a host is absent from AD: it may simply
            # sit past the cap / beyond the point we were cancelled. UNKNOWN, not NOT IN AD.
            $reason = $globalUnknown
            $status = 'NOT IN AD'
            if (-not $reason -and $adIncomplete) { $reason = 'UNKNOWN (AD read incomplete)'; $status = 'UNKNOWN' }
            $verdict = Get-HistCoverageVerdict -AdAlive $null -InAd $false -Touched $touched -DaysAgo $dAgo -ThresholdDays $threshold -UnknownReason $reason
            [void]$built.Add(@{ Host = $sn; AdStatus = $status; LastAdLogon = ''; LastTouched = $lastStr; DaysAgo = $daysAgo; LastTool = $tool; Verdict = $verdict })
        }

        # Order by how much the verdict demands attention, so a display-capped board
        # still shows the rows worth acting on first.
        $rank = @{ 'GHOST'=0; 'NEVER TOUCHED (live)'=1; 'STALE (live)'=2; 'DEAD OBJECT'=3; 'COVERED'=5 }
        $ordered = @($built | Sort-Object -Property @{ Expression = { $r = $rank[[string]$_.Verdict]; if ($null -eq $r) { 4 } else { $r } } }, @{ Expression = { [string]$_.Host } })

        $counts = @{ covered=0; staleLive=0; never=0; ghost=0; dead=0; unknown=0 }
        foreach ($b in $ordered) {
            switch ([string]$b.Verdict) {
                'COVERED'              { $counts.covered++ }
                'STALE (live)'         { $counts.staleLive++ }
                'NEVER TOUCHED (live)' { $counts.never++ }
                'GHOST'                { $counts.ghost++ }
                'DEAD OBJECT'          { $counts.dead++ }
                default                { $counts.unknown++ }
            }
        }

        $displayCapped = $false
        $emitList = $ordered
        if ($ordered.Count -gt $script:HistDisplayCap) { $emitList = @($ordered | Select-Object -First $script:HistDisplayCap); $displayCapped = $true }
        $idx = 0
        $rows = New-Object System.Collections.ArrayList
        foreach ($b in $emitList) {
            $idx++
            $row = @{ _rk=("cv{0}" -f $idx); Host=[string]$b.Host; AdStatus=[string]$b.AdStatus; LastAdLogon=[string]$b.LastAdLogon; LastTouched=[string]$b.LastTouched; DaysAgo=[string]$b.DaysAgo; LastTool=[string]$b.LastTool; Verdict=[string]$b.Verdict }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }

        $readFailed = ($auditFailed -or $adFailed)
        & $send @{ type='log'; level=($(if ($counts.ghost -or $counts.never -or $counts.unknown) { 'warn' } else { 'ok' })); text="Coverage (threshold ${threshold}d, AD stale ${adStale}d, lookback ${lookback}mo) over $($ordered.Count) host(s): COVERED=$($counts.covered), STALE (live)=$($counts.staleLive), NEVER TOUCHED (live)=$($counts.never), GHOST=$($counts.ghost), DEAD OBJECT=$($counts.dead), UNKNOWN=$($counts.unknown)." }
        if ($globalUnknown) { & $send @{ type='error'; text="The audit trail could not be fully read - EVERY host on this board is '$globalUnknown'. UNKNOWN is not COVERED: this run proves nothing about fleet coverage until the source is readable." } }
        if ($counts.ghost -gt 0) { & $send @{ type='log'; level='warn'; text="$($counts.ghost) GHOST host(s): JANET touched a machine the directory says is disabled, stale, or has no object for. Those runs did work against something that should not be in the fleet." } }
        if ($displayCapped) { & $send @{ type='log'; level='warn'; text="Display cap ($($script:HistDisplayCap)) reached - showing the highest-attention rows first; narrow the search base for the full board." } }
        if ($res.Capped) { & $send @{ type='log'; level='warn'; text="Read ceiling ($($script:HistReadCeiling)) hit on the audit trail - hosts are reported UNKNOWN, not COVERED. Narrow the lookback or the search base." } }
        & $send @{ type='status'; text="Done. COVERED=$($counts.covered) / GHOST=$($counts.ghost) / UNKNOWN=$($counts.unknown) of $($ordered.Count)$($(if ($readFailed) { ' (READ ERRORS - incomplete)' } else { '' }))." }
        return @{ rows=@($rows); summary=@{
            total=$ordered.Count; shown=$rows.Count; adTotal=$adRows.Count; pasted=$pasted.Count
            covered=$counts.covered; staleLive=$counts.staleLive; never=$counts.never; ghost=$counts.ghost; dead=$counts.dead; unknown=$counts.unknown
            thresholdDays=$threshold; adStaleDays=$adStale; lookbackMonths=$lookback; searchBase=$searchBase
            adFailed=[bool]$adFailed; adCapped=$adCapped; cancelled=[bool]$ad.Cancelled
            capped=($auditCapped -or $displayCapped); readErrors=[int]$res.Errors; readFailed=[bool]$readFailed
            sourceReadable=[bool]$loc.Exists; source=$loc.Reason; onShare=$loc.OnShare } }
    }

    & $send @{ type='error'; text="Unknown action '$ActionId'." }
    return @{ rows=@(); summary=@{} }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
