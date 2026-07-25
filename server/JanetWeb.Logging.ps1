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

# The production share the desktop tools log to (NOT a JANET Web subfolder).
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
    # JANET Web-native tools with no desktop twin: convention-consistent
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
    # 'JANET-WEB' is the empty-id fallback (both return sites below). Rows written
    # under the TWO-era name stay in Logs\JANET-TWO on the share; readers
    # (history/reports aggregate-row detection) accept both names.
    if ([string]::IsNullOrWhiteSpace($ToolId)) { return 'JANET-WEB' }
    $clean = ($ToolId -replace '[\\/:*?"<>|]', '_')
    # A dot-only id ('.', '..') survives the char-strip but would resolve a path
    # segment AT or ABOVE the log root, so treat it as empty and fall back.
    if ([string]::IsNullOrWhiteSpace($clean) -or $clean -match '^\.+$') { return 'JANET-WEB' }
    return $clean
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
#
# SCOPE (audit 2026-07-25 (fable re-audit follow-up) - documentation, no behaviour
# change): this cache and the re-arm timestamp below are $script:-scoped, and this
# file is dot-sourced SEPARATELY into the accept loop and into every worker runspace.
# So they are PER-RUNSPACE, not process-wide: each runspace pays its own first probe
# and keeps its own 30s / 120s clock. Do not read them as shared state. The only
# genuinely shared thing is $Context.OnShare, which lives in the synchronized context
# hashtable and is always mutated under $Context.Lock. Consequence to expect: after a
# re-arm, a runspace that has not re-probed can still see a stale local decision for
# up to one interval, and the OnShare flag can flap briefly while runspaces converge.
# That is bounded (<=30s) and self-correcting, and it is safe by construction - the
# pessimistic answer only spools a row locally, and the local spool replays.
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

# Re-arm probe for a session that was demoted to local-only.
# WHY (audit 2026-07-24): Add-JanetWebCsvRow / Add-JanetWebTextLine set
# OnShare=$false after ONE transient blip and NOTHING ever set it back, so a
# multi-hour session that lost the share for five seconds spooled every later row
# locally and only reached the share at the NEXT server launch. Re-probe at most
# every $script:JanetWebShareRearmSec and promote the session back when the share
# is WRITABLE again (a visible-but-read-only share must NOT re-arm - the same bar
# New-JanetWebLogContext uses at session start).
# Rows already spooled stay spooled: they replay - exactly once now, see
# Invoke-JanetWebReplay - at the next launch. Replaying them from here would mean
# every worker runspace doing bulk file I/O at once, racing each other's renames.
# NEVER THROWS (runs on the accept loop / worker path).
# The rate-limit timestamp is PER-RUNSPACE (see the scope note on the probe cache
# above), so the re-arm probe is paid once per runspace per interval, not once per
# process - deliberate: it keeps the check lock-free and every outcome is safe.
$script:JanetWebShareRearmAt  = [datetime]::MinValue
$script:JanetWebShareRearmSec = 120
function Test-JanetWebShareRearm {
    param($Context)
    try {
        if (-not $Context -or $Context.OnShare) { return }
        $now = Get-Date
        if (($now - $script:JanetWebShareRearmAt).TotalSeconds -lt $script:JanetWebShareRearmSec) { return }
        $script:JanetWebShareRearmAt = $now
        # Drop the 30s reachability cache first: a 'down' answer cached during the
        # outage would otherwise answer this probe and block the re-arm forever.
        $script:JanetWebShareProbeAt = [datetime]::MinValue
        $probe = Test-JanetWebShareWritable -Root $Context.NetRoot
        if (-not $probe.Writable) { return }
        # Flip the SHARED flag under the context lock (same discipline as every other
        # OnShare mutation); the slow probe above deliberately ran OUTSIDE the lock.
        [System.Threading.Monitor]::Enter($Context.Lock)
        try { $Context.OnShare = $true } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
    } catch {}
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
        $sentinel = Join-Path $Root (".janet-web-write-test-{0:N}.tmp" -f [guid]::NewGuid())
        try {
            'ok' | Out-File -LiteralPath $sentinel -Encoding ASCII -ErrorAction Stop
            Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
        } catch { return @{ Writable=$false; Reason="write-probe failed: $($_.Exception.Message)" } }
        # Orphan sweep: sentinels older than 1h are unambiguously stale.
        try {
            Get-ChildItem -LiteralPath $Root -Filter '.janet-*-write-test-*.tmp' -Force -ErrorAction SilentlyContinue |
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
    if (-not $janetLocal) {
        # Keep using an existing TWO-era profile spool (it may hold unreplayed rows);
        # fresh installs get the JANET-WEB name.
        $oldSpool = Join-Path $env:USERPROFILE 'Documents\JANET-TWO\JanetLocal'
        if (Test-Path -LiteralPath $oldSpool) { $janetLocal = $oldSpool }
        else { $janetLocal = Join-Path $env:USERPROFILE 'Documents\JANET-WEB\JanetLocal' }
    }

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
        # NOTE: 'Month' is deliberately NOT a stored key - see the ScriptProperty below.
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
        # aggregate JANET-WEB row. Populated under $Lock by Write-JanetAction.
        PerTool    = ([hashtable]::Synchronized(@{}))
        # Live-usage snapshot state (Write-JanetWebUsageSnapshot): UsageDirty is set by
        # Write-JanetAction whenever a tallied row lands; the snapshot writer clears it.
        UsageDirty     = $false
        LastSnapshotAt = $now
        Lock       = (New-Object object)
    })

    # Month resolves at READ time, not at session start (audit 2026-07-24). It was a
    # frozen string, so on a server left running across a month rollover the reader
    # that uses it (/api/logs/tail -> "$($lc.Month)_detail.csv") pointed at LAST
    # month's file while the writers - which all format the month per row - had moved
    # on, and the audit viewer went blank. A ScriptProperty keeps the ONE consumer's
    # "$($ctx.Month)" syntax working unchanged (verified through a worker runspace:
    # instance members ride along with the object) with no key for a stale value to
    # live in. Best-effort: if Add-Member ever fails, fall back to the old frozen key
    # rather than leaving the property undefined.
    try { $ctx | Add-Member -MemberType ScriptProperty -Name Month -Value { (Get-Date).ToString('yyyy-MM') } -Force -ErrorAction Stop }
    catch { $ctx['Month'] = $now.ToString('yyyy-MM') }

    # Share is back -> flush any rows captured locally during a prior outage.
    if ($reachable) { try { Invoke-JanetWebReplay -Context $ctx } catch {} }
    return $ctx
}

function Protect-JanetWebCsvField {
    # Formula-injection guard (leading = + - @ TAB CR gets an apostrophe prefix);
    # intentionally diverges from the desktop suite pending a suite-wide fix.
    # audit 2026-07-24: the CR sigil was missing here while all three sibling guards
    # (wpt Protect-WptCsvField, reports ConvertTo-ReportsCsvCell, reports IAVM map)
    # carry it. Today both callers normalise CR/LF before calling in, so nothing
    # leaks - this closes the DRIFT so a future caller that hands over raw text
    # inherits the same guard the siblings give.
    param([string]$Value)
    if ($Value -and $Value -match '^[=+\-@\t\r]') { return ("'" + $Value) }
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
    #      fresh header, return original (-RotateRetries tries, -RotateBackoffMs
    #      backoff doubling up to 4000ms, to survive a peer tool's transient
    #      append lock)
    #   5. rotation stays locked -> route rows to a sister <base>.r<unix>.csv
    #      (reusing an existing matching sister) so new-schema rows don't get
    #      appended under the old header. Throws on I/O failure; callers retry/spool.
    #
    # audit 2026-07-24: the retry ladder is now caller-tunable because it re-runs PER
    # ROW and the sleeping version (6 tries / 6.2s, twice per row = 12.4s) ran inside
    # Add-JanetWebCsvRow's context lock - the same lock the single-threaded accept
    # thread takes - so one locked stale-header file stalled the whole server. Callers
    # holding the lock pass -RotateBackoffMs 0 (no sleep at all); the un-locked replay
    # path keeps the patient ladder. Case 5 is the safety net either way: rows land
    # under a CORRECT header in a sister CSV instead of being lost or mis-columned.
    param([string]$Path, [string]$Header, [int]$RotateRetries = 6, [int]$RotateBackoffMs = 200)
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
    $delay      = $RotateBackoffMs
    $tries      = if ($RotateRetries -lt 1) { 1 } else { $RotateRetries }
    for ($attempt = 1; $attempt -le $tries; $attempt++) {
        try { Rename-Item -LiteralPath $Path -NewName $legacyName -ErrorAction Stop; $rotated = $true; break }
        catch {
            # Sleep ONLY when the caller allows it (audit 2026-07-24 - see the header).
            if ($attempt -lt $tries -and $delay -gt 0) { Start-Sleep -Milliseconds $delay; $delay = [Math]::Min($delay * 2, 4000) }
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

function Write-JanetWebLostRowSentinel {
    # Last-resort breadcrumb for the "audit row never lost" guarantee: if BOTH the
    # central share and the local spool write fail, drop one line to a %TEMP%
    # sentinel file so the loss is at least discoverable. Best-effort - wrapped so
    # this can never itself throw back into the caller.
    param([string]$LocalPath, [string]$Line)
    try {
        $sentinelDir = Join-Path $env:TEMP 'JanetWeb'
        if (-not (Test-Path -LiteralPath $sentinelDir)) { New-Item -ItemType Directory -Path $sentinelDir -Force -ErrorAction Stop | Out-Null }
        $sentinelFile = Join-Path $sentinelDir 'lost-rows.log'
        $entry = "{0}`t{1}`t{2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $LocalPath, $Line
        Add-Content -LiteralPath $sentinelFile -Value $entry -Encoding UTF8 -ErrorAction Stop
    } catch {}
}

function Add-JanetWebCsvRow {
    # Append one line: cheap cached ping-gate, then network with a short backoff;
    # on failure, mark the share down and spool the line locally so it's never
    # lost (replayed next run). Header-ensure may redirect to a sister CSV when a
    # stale-schema file stays locked - always append to the path it returns.
    param([string]$NetworkPath, [string]$LocalPath, [string]$Header, [string]$Line, $Context)
    # Rate-limited re-arm BEFORE the lock (audit 2026-07-24): a demoted session can
    # come back to the share, and the probe can block on SMB for seconds, so it must
    # not run while holding the lock the accept thread needs.
    Test-JanetWebShareRearm -Context $Context
    [System.Threading.Monitor]::Enter($Context.Lock)
    try {
        if ($Context.OnShare) {
            if (-not (Test-JanetWebShareCached -Root $Context.NetRoot)) {
                $Context.OnShare = $false   # share went away mid-session -> spool locally (re-armed by Test-JanetWebShareRearm)
            } else {
                for ($try = 0; $try -lt 2; $try++) {
                    try {
                        # -RotateBackoffMs 0: never sleep in the header-rotation ladder while
                        # this lock is held (audit 2026-07-24) - it stalled the accept thread
                        # for up to 12.4s PER ROW. Two immediate rename attempts, then the
                        # sister-CSV fallback keeps the row under a correct header.
                        $target = Invoke-JanetWebHeaderEnsure -Path $NetworkPath -Header $Header -RotateRetries 2 -RotateBackoffMs 0
                        Add-Content -LiteralPath $target -Value $Line -Encoding UTF8 -ErrorAction Stop
                        return
                    } catch {
                        # Back off WITHOUT holding the lock: Monitor::Wait releases it for the
                        # timeout and re-acquires before we continue (audit 2026-07-24), so a
                        # transient append lock no longer blocks the accept thread. Nothing
                        # pulses this object - the wait always ends on the timeout.
                        try { [void][System.Threading.Monitor]::Wait($Context.Lock, (60 * ($try + 1))) }
                        catch { Start-Sleep -Milliseconds (60 * ($try + 1)) }
                    }
                }
                $Context.OnShare = $false   # share went away mid-session -> spool locally (re-armed by Test-JanetWebShareRearm)
            }
        }
        # local spool
        try {
            # Same no-sleep-under-the-lock rule as the share path above (audit 2026-07-24).
            $target = Invoke-JanetWebHeaderEnsure -Path $LocalPath -Header $Header -RotateRetries 2 -RotateBackoffMs 0
            Add-Content -LiteralPath $target -Value $Line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Warning "JanetWeb: local spool write failed for '$LocalPath' - audit row not persisted: $($_.Exception.Message)"
            Write-JanetWebLostRowSentinel -LocalPath $LocalPath -Line $Line
        }
    } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
}

function Test-JanetWebHostTarget {
    <#  Is this audit -Target an actual MACHINE (so it belongs in a "hosts touched"
        count), or a non-host target that must not inflate it?

        audit 2026-07-24: the AGGREGATE Context.Hosts set had NO filter at all while
        the per-tool tally two lines below it carried a 2-literal blacklist, so the
        headline "hosts touched" number counted things that are not machines:
          reports -> "Dirty30 (12 hosts)", "Dirty 30 LDAP lookup (5 names)",
                     "C:\out\Dirty30.html", "AcasWeekly_2026-07.csv"
          engine  -> 'N/A' (the failed-action row), '(custom command)', '(start)'
        Both call sites now share THIS predicate, so the aggregate and the per-tool
        rollups agree on what a host is.

        Deliberately conservative - it only rejects shapes a NetBIOS name / FQDN /
        IPv4 literal can never have, so a real machine is never dropped:
        whitespace, a parenthesised label, a drive/UNC/URL path, or a report
        filename extension. 'HOST\Product' (upr) still counts: it is host-bearing,
        exactly as the server's TouchedHosts emit treats it. #>
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $t = ([string]$Target).Trim()
    if ($t -eq 'N/A' -or $t -eq '(custom command)') { return $false }   # the historical 2-literal blacklist
    if ($t -match '\s')          { return $false }   # "Dirty30 (12 hosts)" - no host name contains a space
    if ($t.StartsWith('('))      { return $false }   # '(start)' / '(end)' / other sentinel labels
    if ($t.StartsWith('\\') -or $t -match '^[A-Za-z]:[\\/]' -or $t -match '://' -or $t.Contains('/')) { return $false }  # UNC / drive path / URL
    if ($t -match '\.(csv|xlsx?|html?|pdf|log|txt|json|zip|xml|nessus)$') { return $false }   # bare report filename
    return $true
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
            # audit 2026-07-24: the aggregate host set gets the SAME non-host filter the
            # per-tool tally uses (report labels / file paths / 'N/A' are not machines).
            $isHost = Test-JanetWebHostTarget -Target $Target
            if ($isHost) { [void]$Context.Hosts.Add($Target) }
            if ($Result -eq 'Failure') { $Context.Failures++ }
            if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') { $Context.Vulns += [int]$ItemCount }
            # Per-tool tally for the per-tool SessionEnd rollup. Skip non-host targets
            # ('N/A', '(custom command)', report labels, file paths) in the host count so
            # it stays a real machine count.
            $pt = $Context.PerTool[$toolName]
            if (-not $pt) {
                $pt = @{ Hosts = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)); Vulns = 0; Failures = 0; First = (Get-Date); Last = (Get-Date) }
                $Context.PerTool[$toolName] = $pt
            }
            if ($isHost) { [void]$pt.Hosts.Add($Target) }
            if ($Result -eq 'Failure') { $pt.Failures++ }
            if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') { $pt.Vulns += [int]$ItemCount }
            $pt.Last = Get-Date
            $Context.UsageDirty = $true   # something new for the next live-usage snapshot
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
    # the aggregate JANET-WEB row (carries the ClosingNotes; readers also accept the
    # TWO-era 'JANET-TWO' name on historical rows).
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

        # Aggregate JANET-WEB session row (carries the operator's closing notes).
        $durMin = [math]::Round(((Get-Date) - $Context.StartedAt).TotalMinutes, 1)
        & $addRow 'JANET-WEB' $Context.Hosts.Count $Context.Vulns $Context.Failures $durMin $ClosingNotes
    } catch {}
}

function Write-JanetWebUsageSnapshot {
    <#  LIVE usage rows -> Logs\<YYYY-MM>_usage.csv, RowType='Snapshot', CUMULATIVE
        per-tool counters. WHY: the SessionEnd rollup only lands on a CLEAN server
        stop (finally block) - a JANET Web server left running for days writes NO
        usage rows the whole time, and a killed console / reboot loses the rollup
        outright, so the dashboard never sees the web activity even though the
        detail CSVs stream live. The dashboard's per-(SessionId,Tool) dedupe keeps
        the LATEST Snapshot and lets a SessionEnd row supersede the whole series,
        so re-emitting cumulative counts never double-counts.
        No-op unless Write-JanetAction tallied something since the last snapshot
        (UsageDirty) AND MinIntervalSec has elapsed. Call it cheaply and often
        (the server calls it every accept-loop pass). NEVER THROWS. #>
    param([Parameter(Mandatory)] $Context, [int]$MinIntervalSec = 300)
    if (-not $Context) { return }
    try {
        if (-not $Context.UsageDirty) { return }
        if (((Get-Date) - $Context.LastSnapshotAt).TotalSeconds -lt $MinIntervalSec) { return }

        # Snapshot PerTool under the lock (same idiom as the SessionEnd rollup).
        $snap = @()
        $aggHosts = 0; $aggVulns = 0; $aggFails = 0
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
            # Session-wide totals for the aggregate row, read under the same lock.
            $aggHosts = $Context.Hosts.Count
            $aggVulns = [int]$Context.Vulns
            $aggFails = [int]$Context.Failures
            $Context.UsageDirty = $false
            $Context.LastSnapshotAt = Get-Date
        } finally { [System.Threading.Monitor]::Exit($Context.Lock) }
        if ($snap.Count -eq 0) { return }

        $ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $file = ((Get-Date).ToString('yyyy-MM') + '_usage.csv')
        $netFile   = Join-Path $Context.NetRoot $file
        $localFile = Join-Path (Join-Path (Join-Path $Context.JanetLocal '_Rollup') $Context.UserFolder) $file
        $header = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'
        foreach ($s in $snap) {
            $line = ConvertTo-JanetWebCsvLine @(
                $ts, $Context.SessionId, $Context.Operator, $Context.Asi,
                $s.Tool, $Context.Version, 'Snapshot', $s.Hosts, $s.Vulns, $s.Fails, $s.DurMin, ''
            )
            Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $line -Context $Context
        }

        # Aggregate 'JANET-WEB' snapshot row - MIRRORS the SessionEnd rollup, which has
        # always written per-tool rows PLUS an aggregate row.
        #
        # audit 2026-07-24 (S4): without this, a live session had no aggregate row at all,
        # and readers that (correctly) scope themselves to JANET Web by filtering
        # Tool='JANET-WEB' - reports fleet-activity Pass A - could not see a running session
        # no matter what RowType they accepted. Per-tool rows are NOT usable for that scoping,
        # because Resolve-JanetWebToolName deliberately maps web tools onto the DESKTOP tool
        # names ('WPT', 'ACAS_Nemesis', ...) so both suites share one per-tool audit trail.
        # The dashboard is unaffected: it already ranks SessionEnd above Snapshot per
        # (SessionId,Tool), so this row supersedes cleanly and cannot double-count.
        $durMin = [math]::Round(((Get-Date) - $Context.StartedAt).TotalMinutes, 1)
        $aggLine = ConvertTo-JanetWebCsvLine @(
            $ts, $Context.SessionId, $Context.Operator, $Context.Asi,
            'JANET-WEB', $Context.Version, 'Snapshot', $aggHosts, $aggVulns, $aggFails, $durMin, ''
        )
        Add-JanetWebCsvRow -NetworkPath $netFile -LocalPath $localFile -Header $header -Line $aggLine -Context $Context
    } catch {}
}

function Add-JanetWebTextLine {
    # Append a free-text line (the per-session .log narrative). Network-first with
    # a short backoff, then local spool, same as Add-JanetWebCsvRow but the file is
    # seeded with a multi-line header block on first create (not a CSV header) and
    # never header-rotated.
    param([string]$NetworkPath, [string]$LocalPath, [string[]]$HeaderBlock, [string]$Line, $Context)
    Test-JanetWebShareRearm -Context $Context   # audit 2026-07-24 (see Add-JanetWebCsvRow)
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
                    } catch {
                        # Back off WITHOUT holding the lock (audit 2026-07-24, as above).
                        try { [void][System.Threading.Monitor]::Wait($Context.Lock, (60 * ($try + 1))) }
                        catch { Start-Sleep -Milliseconds (60 * ($try + 1)) }
                    }
                }
                $Context.OnShare = $false
            }
        }
        try {
            $dir = Split-Path -Parent $LocalPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
            if (-not (Test-Path -LiteralPath $LocalPath) -and $HeaderBlock) { Set-Content -LiteralPath $LocalPath -Value $HeaderBlock -Encoding UTF8 -ErrorAction Stop }
            Add-Content -LiteralPath $LocalPath -Value $Line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Warning "JanetWeb: local spool write failed for '$LocalPath' - audit row not persisted: $($_.Exception.Message)"
            Write-JanetWebLostRowSentinel -LocalPath $LocalPath -Line $Line
        }
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

        # audit 2026-07-24: Edipi + SourceHost go through the SAME min escaper as every
        # sibling field on the row. They are environment-derived (USERNAME / COMPUTERNAME
        # and an AD-shaped identity), so an embedded comma or CR/LF would desync the
        # column count or forge a whole extra audit row - the escaper only protects a row
        # if it is applied uniformly.
        $edipiF = ConvertTo-JanetWebMinField $Context.Edipi
        $srcF   = ConvertTo-JanetWebMinField $Context.SourceHost

        $members = @($GroupMembers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $rows = @()
        if ($members.Count -gt 0) {
            $size = $members.Count
            foreach ($m in $members) {
                $rows += ,@($ts, (ConvertTo-JanetWebMinField $Context.Operator), $edipiF, $Context.SessionId, $srcF,
                    (ConvertTo-JanetWebMinField $RowType), (ConvertTo-JanetWebMinField $Action), (ConvertTo-JanetWebMinField $m), (ConvertTo-JanetWebMinField $Profile), (ConvertTo-JanetWebMinField $Mode),
                    $HostsTotal, $Success, $Failed, $DurationSec, (ConvertTo-JanetWebMinField $Notes), (ConvertTo-JanetWebMinField $GroupKey), $size)
            }
        } else {
            $rows += ,@($ts, (ConvertTo-JanetWebMinField $Context.Operator), $edipiF, $Context.SessionId, $srcF,
                (ConvertTo-JanetWebMinField $RowType), (ConvertTo-JanetWebMinField $Action), (ConvertTo-JanetWebMinField $Scope), (ConvertTo-JanetWebMinField $Profile), (ConvertTo-JanetWebMinField $Mode),
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
        # audit 2026-07-24: Edipi + SourceHost through the SAME escaper as their row
        # siblings (see Write-JanetWebRun) - an unescaped field is a log-injection seam.
        $line = @(
            (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (ConvertTo-JanetWebMinField $Context.Operator), (ConvertTo-JanetWebMinField $Context.Edipi),
            $Context.SessionId, (ConvertTo-JanetWebMinField $Context.SourceHost), (ConvertTo-JanetWebMinField $Action),
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
    #
    # audit 2026-07-24: that rename was the ONLY "already replayed" marker and its
    # failure was swallowed, so one locked/denied rename silently re-uploaded the
    # WHOLE spool file at the next launch - duplicate rows in the audit trail of
    # record, with nothing to tell a lead the duplicates were an artifact. Now:
    #   * a '<name>.replayed' sidecar receipt is written when the rename fails, and
    #     any file carrying one is SKIPPED on the next pass (idempotent),
    #   * the rename is retried before falling back to the receipt,
    #   * if BOTH fail, the possible duplication is REPORTED (warning + the same
    #     %TEMP% sentinel the lost-row path uses) instead of happening silently.
    # Append-then-mark ordering is deliberate: the residual crash window (rows up,
    # process dies before marking) re-uploads and is reported, never loses rows.
    #
    # audit 2026-07-25 (fable re-audit follow-up): the receipt now has a LIFECYCLE.
    # It records replayedLines=<n> so a later pass replays only the tail (both the CSV
    # and the whole-file .log branch - the .log count is a whole-file line count because
    # its header block is part of the body), and it is DELETED as soon as the rename
    # that retires the spool file finally succeeds. Without that delete the receipt
    # outlived its file and made the next pass skip <n> brand-new rows in the recreated
    # spool file - silent loss, the failure mode the receipt exists to prevent.
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
            # Idempotence guard: a receipt means this file's rows already went up
            # (the rename that normally retires it could not be applied).
            #
            # CORRECTION (fable re-audit): the receipt used to be a bare "skip this file
            # FOREVER" marker, which turned a visible duplication bug into a SILENT LOSS one.
            # The spool path is deterministic (per month), so a file that survived the rename
            # keeps receiving NEW rows the next time OnShare demotes to local-only - and every
            # future replay skipped it on sight, so those rows never reached the share and
            # nothing said so. Losing audit rows silently is strictly worse than duplicating
            # them loudly. The receipt now records HOW MANY data lines were replayed, so a
            # later pass replays only the tail and re-stamps.
            $receipt = $f.FullName + '.replayed'
            $alreadyDone = 0
            if (Test-Path -LiteralPath $receipt -ErrorAction SilentlyContinue) {
                $counted = $false
                try {
                    $rl = @(Get-Content -LiteralPath $receipt -Encoding UTF8 -ErrorAction Stop)
                    foreach ($line in $rl) { if ($line -match '^\s*replayedLines\s*=\s*(\d+)\s*$') { $alreadyDone = [int]$Matches[1]; $counted = $true } }
                } catch { $alreadyDone = -1 }   # unreadable receipt: fail CLOSED, skip (old behaviour)
                if ($alreadyDone -lt 0) { continue }
                # A readable receipt with NO replayedLines= is a pre-fix (bare "skip me")
                # receipt. We cannot know how much of the file went up, so we replay it
                # whole - duplicating LOUDLY beats losing silently, the same call the
                # count itself was introduced to make - and we say so.
                # (audit 2026-07-25 (fable re-audit follow-up).)
                if (-not $counted) { Write-Warning "JanetWeb: replay receipt '$receipt' carries no replayedLines count - replaying '$($f.Name)' in full; rows may DUPLICATE (never lost)." }
            }
            $rel = $f.FullName.Substring($local.TrimEnd('\').Length).TrimStart('\')
            $isUsage = ($rel -like '_Rollup\*' -or $f.Name -like '*_usage*.csv')
            $netFile = if ($isUsage) { Join-Path $Context.NetRoot $f.Name } else { Join-Path $Context.NetRoot $rel }
            try {
                $netDir = Split-Path -Parent $netFile
                if ($netDir -and -not (Test-Path -LiteralPath $netDir)) { New-Item -ItemType Directory -Path $netDir -Force -ErrorAction Stop | Out-Null }
                # $alreadyDone = data lines a PREVIOUS pass already pushed for this same file
                # (non-zero only when that pass could not retire it). Replay just the tail.
                # A spool file only ever GROWS between passes, so a count larger than what
                # the file now holds means the receipt does not belong to these bytes (a
                # recreated spool file at the same deterministic path). Replay from the top
                # rather than skipping brand-new rows. (audit 2026-07-25 (fable re-audit
                # follow-up); the receipt cleanup below is the primary guard.)
                $sentCount = 0
                if ($f.Extension -eq '.log') {
                    # narrative transcript: header block is part of the body - append the
                    # whole file (NOT skip-1, which would lose the 3-line session header).
                    # So the count stamped below is a WHOLE-FILE line count, and the skip
                    # here is over the whole file too - the two must stay the same basis.
                    $all = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop)
                    $skip = if ($alreadyDone -gt $all.Count) { 0 } else { $alreadyDone }
                    $tail = @($all | Select-Object -Skip $skip)
                    if ($tail.Count -gt 0) { Add-Content -LiteralPath $netFile -Value $tail -Encoding UTF8 -ErrorAction Stop }
                    $sentCount = $all.Count
                } else {
                    $lines = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop)
                    if ($lines.Count -gt 0) {
                        $header = $lines[0]
                        # creates/repairs the dest header; may redirect to a sister CSV.
                        # This path holds NO lock, so it keeps the patient rotation ladder.
                        $dest = Invoke-JanetWebHeaderEnsure -Path $netFile -Header $header
                        $data = @($lines | Select-Object -Skip 1 | Where-Object { $_ -ne '' })
                        $skip = if ($alreadyDone -gt $data.Count) { 0 } else { $alreadyDone }
                        $tail = @($data | Select-Object -Skip $skip)
                        if ($tail.Count -gt 0) { Add-Content -LiteralPath $dest -Value $tail -Encoding UTF8 -ErrorAction Stop }
                        $sentCount = $data.Count
                    }
                }
                # Rows are on the share now - retire the local copy so it can never be
                # replayed twice. Two rename attempts (a peer runspace / AV can hold the
                # handle for a moment), then the sidecar receipt, then a loud report.
                $rstamp = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
                $retired = $false
                for ($rt = 0; $rt -lt 2 -and -not $retired; $rt++) {
                    try { Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + ".replayed_$rstamp") -ErrorAction Stop; $retired = $true }
                    catch { if ($rt -eq 0) { Start-Sleep -Milliseconds 150 } }   # no lock held on this path
                }
                if ($retired) {
                    # The spool file is gone, so its receipt MUST go with it (audit
                    # 2026-07-25 (fable re-audit follow-up)): spool paths are deterministic
                    # (per month for the CSVs, per session stamp for the .log), so the next
                    # local-only stretch recreates this exact path - and a leftover receipt
                    # would make the next pass skip that many BRAND-NEW rows. That is silent
                    # loss, the one failure the receipt exists to prevent. Best-effort; if
                    # the delete loses too, the count sanity check above still catches the
                    # common shape (a shorter recreated file).
                    try { if (Test-Path -LiteralPath $receipt -ErrorAction SilentlyContinue) { Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue } } catch {}
                } else {
                    try {
                        # replayedLines is load-bearing, not a comment: the next pass replays
                        # only lines BEYOND this count, so rows appended to this same spool file
                        # after a later share demotion still reach the share exactly once.
                        Set-Content -LiteralPath $receipt -Encoding UTF8 -ErrorAction Stop -Value @(
                            "replayed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -> $netFile",
                            "rename to *.replayed_$rstamp failed; this receipt is what stops a duplicate replay.",
                            "replayedLines=$sentCount"
                        )
                    } catch {
                        # Neither marker landed: the next launch WILL re-upload this file.
                        # Say so, in both operator-visible places, rather than doubling rows silently.
                        Write-Warning "JanetWeb: replayed '$($f.FullName)' to '$netFile' but could not retire the local copy - the next launch may DUPLICATE these rows."
                        Write-JanetWebLostRowSentinel -LocalPath $f.FullName -Line "DUPLICATE-RISK: replayed to '$netFile' but neither the rename nor the .replayed receipt could be written"
                    }
                }
            } catch {}
        }
    } catch {}
}
