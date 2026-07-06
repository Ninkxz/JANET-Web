# =============================================================================
#  JanetWeb.Logging.ps1  -  centralized-logging bridge for JANET Web
#
#  Logs EXACTLY like the desktop tools (the shared JANET LOGGING BLOCK):
#    * Same share root          : \\dm-tn-01\sh-usafe-automation$\JANET\Logs
#    * Same per-tool/per-user    : Logs\<Tool>\<user> - <COMPUTER>_<user>\<YYYY-MM>_detail.csv
#    * Same fleet rollup at root : Logs\<YYYY-MM>_usage.csv
#    * Same headers + ValidateSets (TouchHost/VulnPatched, Success/Failure/Skipped)
#    * Same local spool + replay : <JANET root>\JanetLocal\... captured when the
#                                  share is down, replayed to the share next launch.
#  So an action done through JANET Web lands in the same folder its desktop twin
#  would write to (acas -> ACAS_Nemesis, wpt -> WPT, ...). Context-based (no
#  ambient session) so it dot-sources safely into the server AND worker runspaces.
# =============================================================================

# The production share the desktop tools log to (NOT a JANET-TWO subfolder).
$script:JanetWebShareRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

# JANET Web tool id -> the desktop tool's JANET log folder name, so rows merge
# with the desktop tools' audit trail per tool. (Names from each tool's
# Start-JanetSession -Tool '<name>'.)
$script:JanetWebToolMap = @{
    acas       = 'ACAS_Nemesis'
    wpt        = 'WPT'
    reports    = 'Reports'
    adsearch   = 'AD_Search'
    message    = 'Remote_Message'
    restart    = 'Remote_Restart'
    dhcp       = 'DHCP_Scope'
    pkginstall = 'Remote_Pkg'
    secureboot = 'SecureBoot'
    # Desktop session-folder names (Start-JanetSession -Tool '<name>') for the two
    # tools added after this map was first written, so their rows land in the same
    # Logs\<folder> the desktop twin uses. upr matches the current desktop v1.1.3
    # ('Unsupported_Product_Remediator'); winupgrade's desktop bench build does not
    # log to the share yet, so we pick the convention-consistent underscore name.
    upr        = 'Unsupported_Product_Remediator'
    winupgrade = 'Windows_Upgrade'
    # JANET-TWO-native tools with no desktop twin: convention-consistent
    # underscore names (same rationale as winupgrade above). NOTE: this
    # convention is NOT retroactive - the three earlier native-only tools
    # (kev, c2c, biosfirmware) intentionally have no map entry, so
    # Resolve-JanetWebToolName falls through to their raw lowercase id
    # (Logs\kev, Logs\c2c, Logs\biosfirmware). Their rows already live under
    # those ids; adding entries here would split existing logs, so they stay.
    history    = 'Patch_History'
    patchlib   = 'Patch_Content'
}

function Resolve-JanetWebToolName {
    param([string]$ToolId)
    if ($ToolId -and $script:JanetWebToolMap.ContainsKey($ToolId)) { return $script:JanetWebToolMap[$ToolId] }
    if ([string]::IsNullOrWhiteSpace($ToolId)) { return 'JANET-TWO' }
    return ($ToolId -replace '[\\/:*?"<>|]', '_')
}

function Get-JanetWebUserFolderName {
    # Nemesis format "{user} - {COMPUTER}_{user}" - identical to the desktop tools'
    # Get-JanetUserFolderName so JANET Web writes into the same per-operator folder.
    $u = $env:USERNAME;     if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Unknown' }
    $c = $env:COMPUTERNAME; if ([string]::IsNullOrWhiteSpace($c)) { $c = 'UnknownPC' }
    return (("$u - ${c}_$u") -replace '[\\/:*?"<>|]', '_').Trim()
}

function Get-JanetWebOperatorIdentity {
    # Desktop-parity operator identity (WPT Get-JanetOperatorIdentity / ACAS
    # Resolve-NemOperatorIdentity): AD displayName looked up via DirectorySearcher,
    # then [adsi] LDAP, then bare-username fallthrough. Each strategy is
    # try/catch-bounded so an off-domain box falls through fast. Returns
    # @{ Edipi; DisplayName; Operator; NemesisFolder } where Operator is
    # "EDIPI - DisplayName" (bare EDIPI when lookup fails) and NemesisFolder is
    # the desktop ACAS per-operator folder name "<edipi> - <DisplayName>".
    # $edipiRaw keeps any .csa admin suffix so the on-disk Nemesis folder stays
    # byte-identical to the desktop tools' Get-JanetUserFolderName (parity: TWO and
    # desktop ACAS must write to the SAME per-operator folder). $edipi drops the
    # .csa suffix for the human-facing Operator/EDIPI label only.
    $edipiRaw = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($edipiRaw)) { $edipiRaw = 'Unknown' }
    $edipi = ($edipiRaw -replace '(?i)\.csa$', '')
    if ([string]::IsNullOrWhiteSpace($edipi)) { $edipi = $edipiRaw }

    $displayName = $null
    # Strategy 1: DirectorySearcher on sAMAccountName (most reliable on AD-joined boxes).
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$env:USERNAME))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['displayname'] -and $result.Properties['displayname'].Count -gt 0) {
            $displayName = [string]$result.Properties['displayname'][0]
        }
    } catch { $displayName = $null }

    # Strategy 2: [adsi]"LDAP://$(whoami /fqdn)" (SIM_Tool's classic pattern).
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $fqdn = (whoami /fqdn) 2>$null
            if ($fqdn -and ([string]$fqdn).Trim()) {
                $entry = [adsi]"LDAP://$(([string]$fqdn).Trim())"
                if ($entry -and $entry.Properties -and $entry.Properties['displayName']) {
                    $vals = $entry.Properties['displayName']
                    if ($vals.Count -gt 0) { $displayName = [string]$vals[0] }
                }
            }
        } catch { $displayName = $null }
    }

    # Strategy 3: bare username fallthrough. The comma is stripped ONLY for the
    # Operator CSV string (WPT convention: CSV-safe in one cell); the Nemesis
    # folder keeps the raw displayName (desktop ACAS preserves the comma, so
    # "1234567890 - Doe, John A CIV" must match the desktop twin's folder).
    $rawDisplayName = if ($displayName) { ([string]$displayName).Trim() } else { '' }
    $displayName = if ($rawDisplayName) { ($rawDisplayName -replace ',', '').Trim() } else { '' }
    $operator = $edipi
    if (-not [string]::IsNullOrWhiteSpace($displayName) -and $displayName -ne $edipi) { $operator = "$edipi - $displayName" }
    $folderSource = if ([string]::IsNullOrWhiteSpace($rawDisplayName)) { $env:USERNAME } else { $rawDisplayName }
    $nemFolder = (("$edipiRaw - $folderSource") -replace '[\\/:*?"<>|]', '_').Trim()  # $edipiRaw (keeps .csa) = desktop folder parity
    return @{ Edipi = $edipi; DisplayName = $displayName; Operator = $operator; NemesisFolder = $nemFolder }
}

function Test-JanetWebTcpPort {
    # One bounded TCP connect probe (shared by the share / host reachability gates).
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

function Test-JanetWebShare {
    # Quick reachability gate (probe the share server first so an unreachable share
    # doesn't hang on a 30s Test-Path), mirroring the desktop Test-JanetNetwork.
    param([string]$Root)
    try {
        if ($Root -notmatch '^\\\\([^\\]+)') { return (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue) }
        $server = $Matches[1]
        # Reachability gate: probe SMB/445 over TCP only. NEVER ICMP -- AFNET filters
        # it, and an ICMP false-UP (445 filtered but ping open) would defeat this anti-
        # hang pre-probe and let Test-Path hang on SMB. 445 down -> unreachable; audit
        # logging spools local + replays, so nothing is lost.
        if (-not (Test-JanetWebTcpPort -ComputerName $server -Port 445)) { return $false }
        return (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)
    } catch { return $false }
}

function Test-JanetWebHostReachable {
    # AFNET-safe host reachability for the SMB log/archive share gates: probe SMB/445
    # over TCP only. NEVER ICMP (AFNET filters it, and an ICMP false-UP would defeat
    # the anti-hang pre-probe). 445 unreachable -> caller spools local + replays.
    param([string]$ComputerName)
    return (Test-JanetWebTcpPort -ComputerName $ComputerName -Port 445)
}

# Cached (~30s) ping gate for the per-row share writers: a dead share is detected
# cheaply before each append attempt without paying a probe per row.
$script:JanetWebShareProbeAt = [datetime]::MinValue
$script:JanetWebShareProbeOk = $false
function Test-JanetWebShareCached {
    param([string]$Root)
    $now = Get-Date
    if (($now - $script:JanetWebShareProbeAt).TotalSeconds -lt 30) { return $script:JanetWebShareProbeOk }
    $ok = [bool](Test-JanetWebShare -Root $Root)
    $script:JanetWebShareProbeAt = $now
    $script:JanetWebShareProbeOk = $ok
    return $ok
}

function Test-JanetWebShareWritable {
    # WRITE-probe the share (not just listability): Test-Path returns true when a
    # share is visible even if the ACL blocks writes, so drop a GUID sentinel to
    # confirm rw access, then sweep orphan sentinels from prior sessions whose
    # Remove-Item lost the race. Mirrors the desktop Resolve-NemLogDir probe.
    # Returns @{ Writable=$bool; Reason='' }.
    param([string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root)) { return @{ Writable=$false; Reason='no share root' } }
    if (-not (Test-JanetWebShare -Root $Root)) { return @{ Writable=$false; Reason='share unreachable' } }
    try {
        if (-not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
            try { New-Item -ItemType Directory -Path $Root -Force -ErrorAction Stop | Out-Null } catch { return @{ Writable=$false; Reason='cannot create log root' } }
        }
        $sentinel = Join-Path $Root (".janet-two-write-test-{0:N}.tmp" -f [guid]::NewGuid())
        try {
            'ok' | Out-File -LiteralPath $sentinel -Encoding ASCII -ErrorAction Stop
            Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
        } catch { return @{ Writable=$false; Reason="write-probe failed: $($_.Exception.Message)" } }
        # Orphan sweep: sentinels older than 1h are unambiguously stale.
        try {
            Get-ChildItem -LiteralPath $Root -Filter '.janet-two-write-test-*.tmp' -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
                ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {} }
        } catch {}
        return @{ Writable=$true; Reason='' }
    } catch { return @{ Writable=$false; Reason=$_.Exception.Message } }
}

function New-JanetWebLogContext {
    <#  Per-session logging context (synchronized so it's shared across the
        action's worker runspaces). JanetRoot is the JANET install root (peer to
        Logs\ and Tools\) where the local JanetLocal spool lives, matching the
        desktop tools; pass Split-Path -Parent of the JANET Web folder. #>
    param(
        [string]$Operator  = '',
        [string]$Asi       = '',
        [string]$Version   = '1.0.0',
        [string]$JanetRoot = ''
    )
    # Resolve "EDIPI - DisplayName" once per session, like the desktop tools. A
    # caller-passed bare $env:USERNAME (the old default) is upgraded too.
    $ident = Get-JanetWebOperatorIdentity
    if ([string]::IsNullOrWhiteSpace($Operator) -or $Operator -eq $env:USERNAME) { $Operator = [string]$ident.Operator }
    $netRoot   = $script:JanetWebShareRoot
    # WRITE-probe (not just reachability) so a visible-but-read-only share drops us
    # to local-only with an operator-facing reason, like the desktop tools.
    $probe     = Test-JanetWebShareWritable -Root $netRoot
    $reachable = [bool]$probe.Writable

    # Local spool: <JANET root>\JanetLocal (exactly like the desktop tools). If we
    # weren't given a usable JANET root, fall back to the user profile.
    $janetLocal = $null
    if (-not [string]::IsNullOrWhiteSpace($JanetRoot)) { $janetLocal = Join-Path $JanetRoot 'JanetLocal' }
    if (-not $janetLocal) { $janetLocal = Join-Path $env:USERPROFILE 'Documents\JANET-TWO\JanetLocal' }

    $now = Get-Date
    $ctx = [hashtable]::Synchronized(@{
        SessionId  = ([guid]::NewGuid().ToString('N').Substring(0,8))   # 8 chars, like the desktop
        Operator   = $Operator
        Edipi      = [string]$ident.Edipi
        Asi        = $Asi
        Version    = $Version
        NetRoot    = $netRoot
        JanetLocal = $janetLocal
        UserFolder = (Get-JanetWebUserFolderName)
        NemesisFolder = ([string]$ident.NemesisFolder)   # ACAS per-operator folder "<edipi> - <DisplayName>"
        SourceHost = $env:COMPUTERNAME
        Month      = ($now.ToString('yyyy-MM'))
        LogStamp   = ($now.ToString('yyyy-MM-dd_HH-mm-ss'))   # per-session .log filename stamp
        OnShare    = $reachable
        ShareWarning = $(if ($reachable) { '' } else { "Log share unavailable ($($probe.Reason)). Session logs + CSV telemetry are saved locally only at '$janetLocal'." })
        StartedAt  = $now
        Hosts      = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
        Vulns      = 0
        Failures   = 0
        RunCount   = 0
        RunSuccess = 0
        RunFailed  = 0
        # Per-tool usage tallies (folderName -> @{Hosts;Vulns;Failures;First;Last}) so the
        # SessionEnd rollup emits one usage row PER TOOL used (desktop parity), not just one
        # aggregate JANET-TWO row. Populated under $Lock by Write-JanetAction.
        PerTool    = ([hashtable]::Synchronized(@{}))
        Lock       = (New-Object object)
    })

    # Share is back -> flush any rows captured locally during a prior outage.
    if ($reachable) { try { Invoke-JanetWebReplay -Context $ctx } catch {} }
    return $ctx
}

function Protect-JanetWebCsvField {
    # Formula-injection guard (leading = + - @ TAB gets an apostrophe prefix);
    # intentionally diverges from the desktop suite pending a suite-wide fix.
    param([string]$Value)
    if ($Value -and $Value -match '^[=+\-@\t]') { return ("'" + $Value) }
    return $Value
}

function ConvertTo-JanetWebCsvField {
    # Desktop convention (WPT ConvertTo-JanetCsvLine): comma/CR/LF -> space, then
    # trim - NOT RFC-4180 quoting - so ONE detail/usage rows are byte-convention-
    # identical to the desktop rows in the same shared CSVs.
    param([string]$Value)
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    return (Protect-JanetWebCsvField (($s -replace '[,\r\n]', ' ').Trim()))
}
function ConvertTo-JanetWebCsvLine { param([object[]]$Fields) return (($Fields | ForEach-Object { ConvertTo-JanetWebCsvField ([string]$_) }) -join ',') }

function ConvertTo-JanetWebMinField {
    # Minimal SIM/Nemesis-style escape used by the Runs + TouchedHosts telemetry
    # CSVs (strip CR/LF, comma -> semicolon, NO RFC-4180 quoting) so JANET Web rows
    # merge byte-compatibly into the same monthly/daily files the desktop tool writes.
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return (Protect-JanetWebCsvField (([string]$Value) -replace '[\r\n]+', ' ' -replace ',', ';'))
}

function Invoke-JanetWebHeaderEnsure {
    # Returns the path the caller should append the row to. Ported from the
    # desktop Invoke-JanetHeaderEnsure five-case logic:
    #   1. file missing          -> mkdir + header, return original
    #   2. file exists but EMPTY -> write the header (the original code early-
    #                               returned and left the file headerless)
    #   3. first line matches    -> no-op, return original
    #   4. stale header, rotation succeeds -> rename to <base>.legacy_<unix>.csv,
    #      fresh header, return original (6 tries, 200ms backoff capped at 4000ms
    #      to survive a peer tool's transient append lock)
    #   5. rotation stays locked -> route rows to a sister <base>.r<unix>.csv
    #      (reusing an existing matching sister) so new-schema rows don't get
    #      appended under the old header. Throws on I/O failure; callers retry/spool.
    param([string]$Path, [string]$Header)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        Add-Content -LiteralPath $Path -Value $Header -Encoding UTF8 -ErrorAction Stop
        return $Path
    }
    $first = $null
    try { $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop } catch {}
    $firstTrim = if ($null -ne $first) { ([string]$first).Trim() } else { '' }
    if ($firstTrim -eq '') {
        Add-Content -LiteralPath $Path -Value $Header -Encoding UTF8 -ErrorAction Stop
        return $Path
    }
    if ($firstTrim -eq $Header.Trim()) { return $Path }

    $stamp      = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
    $base       = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $legacyName = "$base.legacy_$stamp.csv"
    $rotated    = $false
    $delay      = 200
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try { Rename-Item -LiteralPath $Path -NewName $legacyName -ErrorAction Stop; $rotated = $true; break }
        catch {
            if ($attempt -lt 6) { Start-Sleep -Milliseconds $delay; $delay = [Math]::Min($delay * 2, 4000) }
        }
    }
    if ($rotated -or -not (Test-Path -LiteralPath $Path)) {
        Add-Content -LiteralPath $Path -Value $Header -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    # Persistently locked: redirect to a sister CSV, reusing one whose header
    # already matches so consecutive calls don't mint a new sister per second.
    $existingMatch = $null
    try {
        foreach ($cand in @(Get-ChildItem -LiteralPath $dir -Filter "$base.r*.csv" -File -ErrorAction SilentlyContinue)) {
            $candFirst = $null
            try { $candFirst = Get-Content -LiteralPath $cand.FullName -TotalCount 1 -ErrorAction Stop } catch {}
            if ($candFirst -and ([string]$candFirst).Trim() -eq $Header.Trim()) { $existingMatch = $cand.FullName; break }
        }
    } catch {}
    if ($existingMatch) { return $existingMatch }
    $sister = Join-Path $dir ("$base.r$stamp.csv")
    if (-not (Test-Path -LiteralPath $sister -ErrorAction SilentlyContinue)) {
        Add-Content -LiteralPath $sister -Value $Header -Encoding UTF8 -ErrorAction Stop
    }
    return $sister
}

function Add-JanetWebCsvRow {
    # Append one line: cheap cached ping-gate, then network with a short backoff;
    # on failure, mark the share down and spool the line locally so it's never
    # lost (replayed next run). Header-ensure may redirect to a sister CSV when a
    # stale-schema file stays locked - always append to the path it returns.
    param([string]$NetworkPath, [string]$LocalPath, [string]$Header, [string]$Line, $Context)
    [System.Threading.Monitor]::Enter($Context.Lock)
    try {
        if ($Context.OnShare) {
            if (-not (Test-JanetWebShareCached -Root $Context.NetRoot)) {
                $Context.OnShare = $false   # share went away mid-session -> spool locally
            } else {
                for ($try = 0; $try -lt 2; $try++) {
                    try {
                        $target = Invoke-JanetWebHeaderEnsure -Path $NetworkPath -Header $Header
                        Add-Content -LiteralPath $target -Value $Line -Encoding UTF8 -ErrorAction Stop
                        return
                    } catch { Start-Sleep -Milliseconds (60 * ($try + 1)) }
                }
                $Context.OnShare = $false   # share went away mid-session -> spool locally
            }
        }
        # local spool
        try {
            $target = Invoke-JanetWebHeaderEnsure -Path $LocalPath -Header $Header
            Add-Content -LiteralPath $target -Value $Line -Encoding UTF8 -ErrorAction Stop
        } catch {}
    } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
}

function Write-JanetAction {
    <#  ONE audit detail row -> Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv, exactly
        like the desktop tools. -Action/-Result are the fixed suite vocabularies
        (anything else throws at bind, by design). -Tool is the JANET Web tool id;
        it's mapped to the desktop tool's folder name. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [ValidateSet('TouchHost','VulnPatched')] [string]$Action,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Success','Failure','Skipped')] [string]$Result,
        [int]$ItemCount = 0,
        [string]$Detail = '',
        [string]$ToolVersion = ''
    )
    if (-not $Context) { return }
    try {
        $toolName = Resolve-JanetWebToolName -ToolId $Tool
        if ([string]::IsNullOrWhiteSpace($ToolVersion)) { $ToolVersion = [string]$Context.Version }

        # Session counters (same two-bucket model + rules as the desktop tools),
        # mutated under the context lock (writers run on concurrent runspaces).
        [System.Threading.Monitor]::Enter($Context.Lock)
        try {
            [void]$Context.Hosts.Add($Target)
            if ($Result -eq 'Failure') { $Context.Failures++ }
            if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') { $Context.Vulns += [int]$ItemCount }
            # Per-tool tally for the per-tool SessionEnd rollup. Skip non-host targets
            # ('N/A', '(custom command)', '') in the host count so it stays a real machine count.
            $pt = $Context.PerTool[$toolName]
            if (-not $pt) {
                $pt = @{ Hosts = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)); Vulns = 0; Failures = 0; First = (Get-Date); Last = (Get-Date) }
                $Context.PerTool[$toolName] = $pt
            }
            if ($Target -and $Target -ne 'N/A' -and $Target -ne '(custom command)') { [void]$pt.Hosts.Add($Target) }
            if ($Result -eq 'Failure') { $pt.Failures++ }
            if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') { $pt.Vulns += [int]$ItemCount }
            $pt.Last = Get-Date
        } finally { [System.Threading.Monitor]::Exit($Context.Lock) }

        $file = ((Get-Date).ToString('yyyy-MM') + '_detail.csv')   # month at write time (rollover-safe)
        $netFile   = Join-Path (Join-Path (Join-Path $Context.NetRoot    $toolName) $Context.UserFolder) $file
        $localFile = Join-Path (Join-Path (Join-Path $Context.JanetLocal $toolName) $Context.UserFolder) $file

        $header = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
        $line = ConvertTo-JanetWebCsvLine @(
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Context.SessionId, $Context.Operator, $Context.Asi,
            $toolName, $ToolVersion, $Action, $Target, $Result, $ItemCount, $Detail
        )
        Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $line -Context $Context
    } catch {
        # Never let a logging failure interrupt the actual operation.
    }
}

function Write-JanetWebRollup {
    # SessionEnd usage rows -> Logs\<YYYY-MM>_usage.csv (fleet rollup at the root).
    # Writes ONE row per tool used this session (Tool column = the desktop folder name,
    # so a lead sees "WPT touched 40 / ACAS_Nemesis patched 12" not just one blob) PLUS
    # the aggregate JANET-TWO row (kept for backward compatibility + the ClosingNotes).
    param([Parameter(Mandatory)] $Context, [string]$ClosingNotes = '')
    if (-not $Context) { return }
    try {
        $ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $file = ((Get-Date).ToString('yyyy-MM') + '_usage.csv')   # month at write time (rollover-safe)
        $netFile   = Join-Path $Context.NetRoot $file
        $localFile = Join-Path (Join-Path (Join-Path $Context.JanetLocal '_Rollup') $Context.UserFolder) $file
        $header = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

        $addRow = {
            param($tool, $hosts, $vulns, $fails, $durMin, $notes)
            $line = ConvertTo-JanetWebCsvLine @(
                $ts, $Context.SessionId, $Context.Operator, $Context.Asi,
                $tool, $Context.Version, 'SessionEnd', $hosts, $vulns, $fails, $durMin, $notes
            )
            Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $line -Context $Context
        }

        # Snapshot PerTool under the lock so a late worker append can't mutate mid-enumerate.
        $snap = @()
        [System.Threading.Monitor]::Enter($Context.Lock)
        try {
            foreach ($e in $Context.PerTool.GetEnumerator()) {
                $pt = $e.Value
                $snap += [pscustomobject]@{
                    Tool   = [string]$e.Key
                    Hosts  = $pt.Hosts.Count
                    Vulns  = [int]$pt.Vulns
                    Fails  = [int]$pt.Failures
                    DurMin = [math]::Round(($pt.Last - $pt.First).TotalMinutes, 1)
                }
            }
        } finally { [System.Threading.Monitor]::Exit($Context.Lock) }

        foreach ($s in $snap) { & $addRow $s.Tool $s.Hosts $s.Vulns $s.Fails $s.DurMin '' }

        # Aggregate JANET-TWO session row (carries the operator's closing notes).
        $durMin = [math]::Round(((Get-Date) - $Context.StartedAt).TotalMinutes, 1)
        & $addRow 'JANET-TWO' $Context.Hosts.Count $Context.Vulns $Context.Failures $durMin $ClosingNotes
    } catch {}
}

function Add-JanetWebTextLine {
    # Append a free-text line (the per-session .log narrative). Network-first with
    # a short backoff, then local spool, same as Add-JanetWebCsvRow but the file is
    # seeded with a multi-line header block on first create (not a CSV header) and
    # never header-rotated.
    param([string]$NetworkPath, [string]$LocalPath, [string[]]$HeaderBlock, [string]$Line, $Context)
    [System.Threading.Monitor]::Enter($Context.Lock)
    try {
        if ($Context.OnShare) {
            if (-not (Test-JanetWebShareCached -Root $Context.NetRoot)) {
                $Context.OnShare = $false
            } else {
                for ($try = 0; $try -lt 2; $try++) {
                    try {
                        $dir = Split-Path -Parent $NetworkPath
                        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
                        if (-not (Test-Path -LiteralPath $NetworkPath) -and $HeaderBlock) { Set-Content -LiteralPath $NetworkPath -Value $HeaderBlock -Encoding UTF8 -ErrorAction Stop }
                        Add-Content -LiteralPath $NetworkPath -Value $Line -Encoding UTF8 -ErrorAction Stop
                        return
                    } catch { Start-Sleep -Milliseconds (60 * ($try + 1)) }
                }
                $Context.OnShare = $false
            }
        }
        try {
            $dir = Split-Path -Parent $LocalPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null }
            if (-not (Test-Path -LiteralPath $LocalPath) -and $HeaderBlock) { Set-Content -LiteralPath $LocalPath -Value $HeaderBlock -Encoding UTF8 -ErrorAction SilentlyContinue }
            Add-Content -LiteralPath $LocalPath -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
    } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
}

function Write-JanetWebRun {
    <#  One (or N, for a rolled-up card) per-run summary row -> the daily Runs CSV
        Logs\<Tool>\ACAS-Nemesis-Runs_<YYYY-MM-DD>.csv, faithful to the desktop
        Write-NemRunCsvLine/Write-NemRunSummary (17-col v1.5.0 schema, min CSV
        escape so rows merge with desktop-written files). For a rolled-up Updater
        card pass -GroupMembers (the member display names): one row per member,
        sharing Timestamp/counters, GroupKey set, GroupSize=N. Bumps the session
        run counters used by the closing-notes summary. NEVER THROWS. #>
    param(
        [Parameter(Mandatory)] $Context,
        [string]$Tool = 'acas',
        [string]$RowType = 'Run',
        [string]$Action = '',
        [string]$Scope = '',
        [string]$Profile = '',
        [string]$Mode = '',
        [int]$HostsTotal = 0,
        [int]$Success = 0,
        [int]$Failed = 0,
        [int]$DurationSec = 0,
        [string]$Notes = '',
        [string]$GroupKey = '',
        [string[]]$GroupMembers = @()
    )
    if (-not $Context) { return }
    try {
        $toolName = Resolve-JanetWebToolName -ToolId $Tool
        $fileName = 'ACAS-Nemesis-Runs_' + (Get-Date -Format 'yyyy-MM-dd') + '.csv'
        $netFile   = Join-Path (Join-Path $Context.NetRoot    $toolName) $fileName
        $localFile = Join-Path (Join-Path $Context.JanetLocal $toolName) $fileName
        $header = 'Timestamp,User,Edipi,SessionId,Host,RowType,Action,Scope,Profile,Mode,HostsTotal,Success,Failed,DurationSec,Notes,GroupKey,GroupSize'
        $ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

        $members = @($GroupMembers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $rows = @()
        if ($members.Count -gt 0) {
            $size = $members.Count
            foreach ($m in $members) {
                $rows += ,@($ts, (ConvertTo-JanetWebMinField $Context.Operator), $Context.Edipi, $Context.SessionId, $Context.SourceHost,
                    $RowType, $Action, (ConvertTo-JanetWebMinField $m), (ConvertTo-JanetWebMinField $Profile), (ConvertTo-JanetWebMinField $Mode),
                    $HostsTotal, $Success, $Failed, $DurationSec, (ConvertTo-JanetWebMinField $Notes), (ConvertTo-JanetWebMinField $GroupKey), $size)
            }
        } else {
            $rows += ,@($ts, (ConvertTo-JanetWebMinField $Context.Operator), $Context.Edipi, $Context.SessionId, $Context.SourceHost,
                $RowType, $Action, (ConvertTo-JanetWebMinField $Scope), (ConvertTo-JanetWebMinField $Profile), (ConvertTo-JanetWebMinField $Mode),
                $HostsTotal, $Success, $Failed, $DurationSec, (ConvertTo-JanetWebMinField $Notes), (ConvertTo-JanetWebMinField $GroupKey), 1)
        }
        foreach ($r in $rows) {
            $line = ($r -join ',')
            Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $line -Context $Context
        }
        # Session run counters (drive the closing-notes summary), under the lock.
        if ($RowType -eq 'Run') {
            [System.Threading.Monitor]::Enter($Context.Lock)
            try {
                $Context.RunCount   = [int]$Context.RunCount   + 1
                $Context.RunSuccess = [int]$Context.RunSuccess + $Success
                $Context.RunFailed  = [int]$Context.RunFailed  + $Failed
            } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
        }
    } catch {}
}

function Write-JanetWebTouchedHost {
    <#  One per-host attribution row -> Logs\<Tool>\<userFolder>\TouchedHosts_<YYYY-MM>.csv
        (faithful to desktop Write-NemTouchedHostCsv): a lead can pivot "which
        machines did operator X touch this month" without grepping. min CSV escape,
        monthly rotation. NEVER THROWS. #>
    param(
        [Parameter(Mandatory)] $Context,
        [string]$Tool = 'acas',
        [Parameter(Mandatory)] [string]$Action,
        [Parameter(Mandatory)] [string]$TargetHost,
        [string]$Result = '',
        [string]$Detail = ''
    )
    if (-not $Context) { return }
    try {
        $toolName = Resolve-JanetWebToolName -ToolId $Tool
        $month = (Get-Date).ToString('yyyy-MM')
        $fileName = "TouchedHosts_$month.csv"
        # ACAS uses the Nemesis per-operator folder "<edipi> - <DisplayName>" so its rows
        # merge with the desktop twin's files; every other tool uses the standard UserFolder.
        $opFolder = if ($Tool -eq 'acas') { [string]$Context.NemesisFolder } else { [string]$Context.UserFolder }
        if ([string]::IsNullOrWhiteSpace($opFolder)) { $opFolder = $Context.UserFolder }
        $netFile   = Join-Path (Join-Path (Join-Path $Context.NetRoot    $toolName) $opFolder) $fileName
        $localFile = Join-Path (Join-Path (Join-Path $Context.JanetLocal $toolName) $opFolder) $fileName
        $header = 'Timestamp,Operator,Edipi,SessionId,SourceHost,Action,TargetHost,Result,Detail'
        $line = @(
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (ConvertTo-JanetWebMinField $Context.Operator), $Context.Edipi,
            $Context.SessionId, $Context.SourceHost, (ConvertTo-JanetWebMinField $Action),
            (ConvertTo-JanetWebMinField $TargetHost), (ConvertTo-JanetWebMinField $Result), (ConvertTo-JanetWebMinField $Detail)
        ) -join ','
        Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $line -Context $Context
    } catch {}
}

function Get-JanetWebSessionLogTarget {
    <#  Resolve the per-session .log path + display name for a tool, so the writer
        (Write-JanetWebSessionLog) and the UI transcript endpoint agree on ONE
        location. ACAS keeps its historical "ACASNemesis_<user>_<stamp>.log" name +
        Nemesis per-operator folder; every other tool uses "<ToolName>_<user>_<stamp>.log"
        in the standard UserFolder. Returns @{ ToolName; FileName; DisplayName; OpFolder; Net; Local }. #>
    param([Parameter(Mandatory)] $Context, [string]$Tool = 'acas')
    $toolName = Resolve-JanetWebToolName -ToolId $Tool
    if ($Tool -eq 'acas') {
        $fileName    = "ACASNemesis_$($env:USERNAME)_$($Context.LogStamp).log"
        $displayName = 'ACAS Nemesis'
        $opFolder    = [string]$Context.NemesisFolder
    } else {
        $fileName    = "${toolName}_$($env:USERNAME)_$($Context.LogStamp).log"
        $displayName = ($toolName -replace '_', ' ')
        $opFolder    = [string]$Context.UserFolder
    }
    if ([string]::IsNullOrWhiteSpace($opFolder)) { $opFolder = $Context.UserFolder }
    return @{
        ToolName = $toolName; FileName = $fileName; DisplayName = $displayName; OpFolder = $opFolder
        Net   = (Join-Path (Join-Path (Join-Path $Context.NetRoot    $toolName) $opFolder) $fileName)
        Local = (Join-Path (Join-Path (Join-Path $Context.JanetLocal $toolName) $opFolder) $fileName)
    }
}

function Write-JanetWebSessionLog {
    <#  Append one narrative line to the per-session transcript
        Logs\<Tool>\<userFolder>\<ToolName>_<user>_<stamp>.log, seeding a 3-line
        header on first write (faithful to desktop Open-NemAuditLog/Write-NemAudit).
        EVERY tool gets a transcript now (not just ACAS): the .log is the human-readable
        "what did JANET Web do this session" record the desktop tools each keep. ACAS
        keeps its historical filename + header + Nemesis per-operator folder so its rows
        merge with the desktop twin's files; every other tool uses "<ToolName>_..." and
        the standard "<user> - <COMPUTER>_<user>" folder its desktop twin writes to.
        NEVER THROWS. #>
    param(
        [Parameter(Mandatory)] $Context,
        [string]$Tool = 'acas',
        [Parameter(Mandatory)] [string]$Action,
        [string]$Target = 'N/A',
        [string]$Result = '',
        [string]$Detail = ''
    )
    if (-not $Context) { return }
    try {
        $tgt = Get-JanetWebSessionLogTarget -Context $Context -Tool $Tool
        $displayName = $tgt.DisplayName
        $netFile   = $tgt.Net
        $localFile = $tgt.Local
        $headerBlock = @(
            "=== $displayName (JANET Web) v$($Context.Version) ===",
            "Session $($Context.SessionId) started $($Context.StartedAt.ToString('yyyy-MM-dd HH:mm:ss'))",
            "Operator: $($Context.Operator)  (EDIPI: $($Context.Edipi))  on $($Context.SourceHost)"
        )
        $ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        # Scrub CR/LF (and the bracket delimiters) from narrative fields (audit#20) so a
        # JSON body key carrying \r\n can't inject forged transcript lines. The tamper-
        # relevant record (detail/usage CSVs) is separately sanitized; this keeps the
        # human transcript honest too.
        $scrub = { param($v) ([string]$v) -replace '[\r\n]+',' ' -replace '[\[\]]',' ' }
        $entry = "[$ts] [USER: $(& $scrub $Context.Operator)] [ACTION: $(& $scrub $Action)] [TARGET: $(& $scrub $Target)] [RESULT: $(& $scrub $Result)]"
        if ($Detail) { $entry += " [DETAIL: $(& $scrub $Detail)]" }
        Add-JanetWebTextLine -NetworkPath $netFile -LocalPath $localFile -HeaderBlock $headerBlock -Line $entry -Context $Context
    } catch {}
}

function Invoke-JanetWebReplay {
    # Flush rows captured to the local spool during a prior share outage up to the
    # share, then rename the local copies <name>.replayed_<stamp> as a paper trail
    # (mirrors the desktop replay-on-launch). Skips already-replayed files and
    # rotated *.legacy_*.csv archives.
    param([Parameter(Mandatory)] $Context)
    $local = $Context.JanetLocal
    if (-not $local -or -not (Test-Path -LiteralPath $local)) { return }
    try {
        # detail/Runs/TouchedHosts CSVs: JanetLocal\<Tool>\<userFolder>\*.csv -> Logs\<Tool>\<userFolder>\
        # usage CSV : JanetLocal\_Rollup\<userFolder>\*_usage.csv -> Logs\
        # .log transcript: JanetLocal\<Tool>\<userFolder>\*.log -> Logs\<Tool>\<userFolder>\ (copied WHOLE)
        foreach ($f in (Get-ChildItem -LiteralPath $local -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                ($_.Extension -eq '.csv' -or $_.Extension -eq '.log') -and
                $_.Name -notlike '*.replayed_*' -and $_.Name -notlike '*.legacy_*'
            })) {
            $rel = $f.FullName.Substring($local.TrimEnd('\').Length).TrimStart('\')
            $isUsage = ($rel -like '_Rollup\*' -or $f.Name -like '*_usage*.csv')
            $netFile = if ($isUsage) { Join-Path $Context.NetRoot $f.Name } else { Join-Path $Context.NetRoot $rel }
            try {
                $netDir = Split-Path -Parent $netFile
                if ($netDir -and -not (Test-Path -LiteralPath $netDir)) { New-Item -ItemType Directory -Path $netDir -Force -ErrorAction Stop | Out-Null }
                if ($f.Extension -eq '.log') {
                    # narrative transcript: header block is part of the body - append the
                    # whole file (NOT skip-1, which would lose the 3-line session header).
                    $all = Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop
                    if (@($all).Count -gt 0) { Add-Content -LiteralPath $netFile -Value $all -Encoding UTF8 -ErrorAction Stop }
                } else {
                    $lines = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop)
                    if ($lines.Count -gt 0) {
                        $header = $lines[0]
                        # creates/repairs the dest header; may redirect to a sister CSV
                        $dest = Invoke-JanetWebHeaderEnsure -Path $netFile -Header $header
                        $data = @($lines | Select-Object -Skip 1 | Where-Object { $_ -ne '' })
                        if ($data.Count -gt 0) { Add-Content -LiteralPath $dest -Value $data -Encoding UTF8 -ErrorAction Stop }
                    }
                }
                $rstamp = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
                try { Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + ".replayed_$rstamp") -ErrorAction Stop } catch {}
            } catch {}
        }
    } catch {}
}
