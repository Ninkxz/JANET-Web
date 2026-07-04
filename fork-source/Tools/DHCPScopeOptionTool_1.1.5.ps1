<#
.NAME
    J.A.N.E.T. DHCP Scope Option Tool
.SYNOPSIS
    Joint Administration and Network Execution Toolkit - DHCP Scope Option Editor
.DESCRIPTION
    WinForms editor for IP-array DHCP scope options (006 DNS Servers, 003 Router,
    042 NTP, 044 WINS) on a remote Windows DHCP server. Replaces the manual
    dhcpmgmt.msc -> Scope Options -> Properties -> Add IP -> reorder workflow
    with a single GUI:

        1. Enter the DHCP server hostname and Connect.
        2. Pick a scope from the loaded list.
        3. Pick the option (006 default) - current values appear in an
           ordered list.
        4. Add an IP (e.g. the DR DNS server) using the entry box.
        5. Highlight it and use Up / Down / Top / Bottom to position
           it (DR-DNS workflow puts it at the bottom).
        6. APPLY commits the new ordered list to the scope via
           Set-DhcpServerv4OptionValue on a remote PSSession.

    Visual language: J.A.N.E.T. launcher theme (JANET.ps1). Purple +
    gold on near-black, Segoe UI typography, plain panels with subtle
    borders, sentence-case labels. Identical palette and font choices
    as RemoteMessageTool / SecureBootEnabler / ADSearchTool.
.AUTHOR
    THOMPSON, BRAXTON - 48 CS / SCOO
.VERSION
    1.1.5
.CHANGELOG
    v1.1.5 - 2026-05-10 - JANET replay filter widened to *_detail*.csv/*_usage*.csv so schema-rotation sister files (created when the legacy file is persistently locked) are drained on next launch instead of stranded.
    v1.1.4 - 2026-05-08 - JANET centralized-logging schema cleanup (single
                          SessionEnd rollup row; Snapshot rows retired) and
                          the WPT-themed Closing Notes prompt rolled across
                          the suite.
    v1.1.3 - 2026-04-30 - Fix: Apply / Bulk Apply throwing "ScopeId arrived
                          empty over WSMan." in the single-scope path (and
                          silently failing per-scope in Bulk).
         - Root cause: Invoke-OnDhcp declared its argument-array
           parameter as $Args, which collides with the PowerShell
           automatic variable $Args (unbound positional args).
           In a non-CmdletBinding function that collision is fragile;
           Invoke-Command -ArgumentList $Args could spread to the
           wrong/empty positional slots, so the remote
           param($scopeId, $optId, $values) bound $scopeId to ''.
         - Renamed the parameter to $Arguments and updated the four
           call sites (Load, Apply-Set, Apply-Remove, Bulk Apply) to
           use -Arguments. The whitespace guard added in 1.1.2 stays
           in place as a defensive net.
    v1.1.2 - 2026-04-30 - Bug fixes + JANET logging completion.
         - Fix: Load Values failing with "Cannot validate argument on
           parameter ScopeID. The argument is null or empty" on Server
           2019 / PS 5.1. Root cause: Get-DhcpServerv4Scope ScopeId is an
           [ipaddress] that, after PSRemoting deserialization, no longer
           round-trips through [string] reliably. Probe now projects
           ScopeId / SubnetMask via .IPAddressToString into a
           pscustomobject on the REMOTE side so a clean dotted-quad
           string crosses the wire.
         - Fix: Single-scope APPLY was sending raw string to
           Set-DhcpServerv4OptionValue -ScopeId while Load and Bulk both
           [ipaddress]-cast first. Apply now matches Load/Bulk plus a
           defensive null guard before the WSMan call.
         - Fix: JANET centralized logging was tagged "read-only, silent
           rollup" -- but Apply / Bulk Apply both mutate server state.
           Apply now calls Write-JanetAction (VulnPatched on success,
           Failure on error) per scope so the monthly rollup reflects
           real activity instead of always-zero counters.
         - UX: WSMan auth rejection on Apply / Bulk Apply now surfaces
           a hint listing the realistic causes (DHCP-Admins membership,
           stale launcher cred, auth-mode toggle, missing domain prefix,
           account lockout) rather than the bare WSMan transport error.
         - Cleanup: stale "v1.0" string in form title, header banner,
           startup log, and init log -- all now read from
           $JanetDHCP_ScopeVersion so the next bump is single-source.
    v1.1.1 - 2026-04-25 - Added JANET centralized logging (read-only, silent
                          rollup to \\dm-tn-01\sh-usafe-automation$\JANET\Logs).
                          Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
    v1.0 - April 2026 - First release.
         - "Use current session" checkbox in the credential strip. When
           ticked, Invoke-Command runs WITHOUT -Credential so WSMan
           authenticates as the logged-in user via Kerberos / NTLM.
           Use this when you've already opened PowerShell as your ADM
           account and -Credential keeps rejecting otherwise-valid
           creds with "username is incorrect" -- that error is usually
           a stale launcher cred file, wrong domain prefix, or
           second-hop auth. Skipping -Credential bypasses all three.
         - BULK APPLY footer (full-width strip below the columns).
           Multi-line IP textbox, three actions: APPEND TO BOTTOM,
           prepend to top, remove from each. Operates on every scope
           whose checkbox is ticked in the left column. Built for the
           DR-DNS workflow ("add 10.x.x.x at the bottom of option 006
           in every scope on this server"). Confirmation dialog lists
           every target scope and IP before commit; per-scope result
           (Changed / NoChange / Removed / Error) is logged.
         - Scope ListView now has CheckBoxes. Click-to-select still
           triggers the single-scope edit flow; checking a row marks
           it as a target for the bulk footer. All / None / Active /
           Invert quick-select buttons under the listview.
         - Auto-load option values when a scope row is clicked, when
           the option dropdown changes, or when the freeform option
           ID changes -- removes the "click Load Values to see what's
           there" extra step.
         - DHCP server hostname is a user-input field, never baked in.
           Connect button validates WSMan reachability (TCP 5985)
           before probing DhcpServer cmdlet availability via
           Invoke-Command.
         - Loads all IPv4 scopes (NetworkID / SubnetMask / Name /
           State / Description). Single-click selects the scope to
           edit.
         - Common-options dropdown (003, 006, 042, 044, 045) plus a
           freeform option-ID NumericUpDown for any IP-array option
           not in the dropdown. Tool is IP-array only -- hostname/string
           options (e.g. 015 Domain Name) are out of scope.
         - Current values pulled with Get-DhcpServerv4OptionValue
           and shown in a ListBox in their stored order. Add / Remove
           / Move Up / Move Down / Move Top / Move Bottom controls
           reorder the list in-memory; nothing hits the server until
           APPLY.
         - APPLY commits the full ordered IP array via
           Set-DhcpServerv4OptionValue -Value (the cmdlet replaces the
           whole option, which is the safe atomic update). Confirmation
           dialog shows the diff (added / removed / reordered) before
           the commit.
         - Inherits credentials from the J.A.N.E.T. launcher via
           $env:JANET_CRED_FILE (DPAPI, current-user-only). Set
           Credentials button is the manual override - same pattern as
           RemoteMessageTool.
         - Activity log on the right side captures every server call,
           every list mutation, and every APPLY result with timestamps.
           Per-session log file at <launcher>\Logs\JDHCP_<user>_<ts>.log.
#>

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v1.1.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\DHCP_Scope\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetDHCP_ScopeVersion = '1.1.5'

# === BEGIN JANET LOGGING BLOCK (paste from here) ===
$JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

$script:JanetSession   = $null
$script:JanetNetworkOk = $false

## Closure-safe getter — closures created with .GetNewClosure() under StrictMode 3
## cannot reliably resolve $script:Foo. Helpers used from inside closures must
## be declared at global scope so they are always visible.
function global:Get-JanetSession { return $script:JanetSession }

## X-block flag. Initialized $false in the form builder; set $true only by
## the Close Tool button handler. The FormClosing handler cancels any close
## that arrives without the flag set (X, Alt-F4, right-click-close), except
## WindowsShutDown which is allowed through so the OS doesn't nag-prompt the
## operator. Removes the per-host snapshot churn from the rollup CSV by
## guaranteeing every session ends through Stop-JanetSession.
function global:Get-JanetAllowClose { return $script:JanetAllowClose }
function global:Set-JanetAllowClose { param($Value) $script:JanetAllowClose = [bool]$Value }

function Get-JanetMonthFile {
    [CmdletBinding()]
    param([switch]$Detail)
    $month = Get-Date -Format 'yyyy-MM'
    if ($Detail) { return "${month}_detail.csv" } else { return "${month}_usage.csv" }
}

function Get-JanetLocalDir {
    ## Workspace-anchored fallback under $PSScriptRoot's parent (the JANET root,
    ## peer to Logs/ and Tools/). Never %USERPROFILE% / %PROGRAMDATA% /
    ## %LOCALAPPDATA% — keeps tool data next to the launcher so portable /
    ## kiosk installs stay self-contained.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\{0}\{1}" -f $script:JanetSession.Tool, $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Get-JanetLocalRollupDir {
    ## Local fallback for the fleet rollup (one row per session-snapshot or
    ## session-end). Lives at JanetLocal/_Rollup/<userfolder>/ so every tool
    ## a single operator runs writes to the same local rollup spool, mirroring
    ## the network behavior where the rollup is at the Logs/ root.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\_Rollup\{0}" -f $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Initialize-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = $env:USERNAME,
        [string]$ASI      = ''
    )
    ## Schema (simplified 2026-04-29): two-bucket action model. Every per-host
    ## action is either a TouchHost (just reached the box — message, scan, etc.)
    ## or a VulnPatched (changed the host's security state — patch, reboot,
    ## STIG apply, plugin remediation, package install, secure-boot enable).
    ## Rollup row carries: HostsTouched, VulnsPatched, Failures, DurationMin,
    ## ClosingNotes. ScriptsRun and Successes are deliberately gone — operators
    ## want simple totals, not categorical breakdowns.
    [PSCustomObject]@{
        StartTime    = Get-Date
        SessionId    = ([guid]::NewGuid().ToString('N').Substring(0,8))
        Operator     = $Operator
        ASI          = $ASI
        Tool         = $Tool
        Version      = $Version
        Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        VulnsPatched = 0
        Failures     = 0
    }
}

function Get-JanetUserFolderName {
    ## Per-user subfolder name in Nemesis format: "{user} - {COMPUTER}_{user}".
    ## Mirrors Tools/ACASNemesis/Logs/<this name>/ so every JANET tool produces
    ## the same per-operator folder pattern. Sanitizes any path-illegal char.
    $u = $env:USERNAME; if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Unknown' }
    $c = $env:COMPUTERNAME; if ([string]::IsNullOrWhiteSpace($c)) { $c = 'UnknownPC' }
    $name = "$u - ${c}_$u"
    return ($name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Add-JanetCsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$Line,
        [int]$MaxRetries     = 6,
        [int]$InitialDelayMs = 250
    )

    if ($script:JanetNetworkOk -eq $false -and $null -ne $script:JanetSession) {
        Write-JanetLocal -Path $LocalPath -Line $Line
        return
    }

    $delay = $InitialDelayMs
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $dir = Split-Path -Parent $NetworkPath
            if (-not (Test-Path $dir)) {
                [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
            }
            Add-Content -Path $NetworkPath -Value $Line -Encoding UTF8 -ErrorAction Stop
            return
        } catch {
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 8000)
            }
        }
    }

    if ($null -ne $script:JanetSession) { $script:JanetNetworkOk = $false }
    Write-JanetLocal -Path $LocalPath -Line $Line
}

function Write-JanetLocal {
    [CmdletBinding()]
    param([string]$Path, [string]$Line)
    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $Line -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host ("WARNING: JANET local fallback failed: $_") -ForegroundColor Yellow
    }
}

function Test-JanetNetwork {
    [CmdletBinding()]
    param([string]$Root = $JanetLogRoot)
    try {
        if ($Root -notmatch '^\\\\([^\\]+)') { return $false }
        $server = $Matches[1]
        $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) { return $false }
        return [bool](Test-Path $Root -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Get-JanetOperatorIdentity {
    ## Returns "EDIPI - DisplayName" or just EDIPI when display-name lookup
    ## fails. Three lookup strategies, tried in order:
    ##   1. DirectorySearcher with sAMAccountName filter — works on any
    ##      AD-joined machine, doesn't depend on `whoami /fqdn` returning a
    ##      usable FQDN. This is the most reliable on AFNET.
    ##   2. [adsi]"LDAP://$(whoami /fqdn)" — SIM_Tool's classic pattern,
    ##      kept as a fallback for environments where DirectorySearcher is
    ##      blocked by policy.
    ##   3. Win32_ComputerSystem.UserName — last resort, returns
    ##      "DOMAIN\username" which we strip to bare username.
    ## Comma stripped from displayName so the value is CSV-safe in one cell.
    [CmdletBinding()] param()
    $edipi = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($edipi)) { $edipi = 'Unknown' }

    $displayName = $null

    ## Strategy 1: DirectorySearcher (most reliable on AD-joined boxes)
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$env:USERNAME))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['displayname'] -and $result.Properties['displayname'].Count -gt 0) {
            $displayName = [string]$result.Properties['displayname'][0]
        }
    } catch { $displayName = $null }

    ## Strategy 2: [adsi]LDAP://whoami /fqdn (SIM_Tool's pattern)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $fqdn = (whoami /fqdn) 2>$null
            if ($fqdn -and $fqdn.Trim()) {
                $entry = [adsi]"LDAP://$($fqdn.Trim())"
                if ($entry -and $entry.Properties -and $entry.Properties['displayName']) {
                    $vals = $entry.Properties['displayName']
                    if ($vals.Count -gt 0) { $displayName = [string]$vals[0] }
                }
            }
        } catch { $displayName = $null }
    }

    ## Strategy 3: Win32_ComputerSystem.UserName (strip DOMAIN\ prefix)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $u = [string]$cs.UserName
            if ($u -and $u.Contains('\')) { $u = ($u -split '\\', 2)[1] }
            $displayName = $u
        } catch { $displayName = $null }
    }

    $displayName = if ($displayName) { ($displayName -replace ',', '').Trim() } else { '' }
    if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName -eq $edipi) {
        return $edipi
    }
    return "$edipi - $displayName"
}

function global:Start-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = (Get-JanetOperatorIdentity),
        [string]$ASI      = '',
        [switch]$SkipReplay
    )
    $script:JanetSession   = Initialize-JanetSession -Tool $Tool -Version $Version -Operator $Operator -ASI $ASI
    $script:JanetNetworkOk = Test-JanetNetwork

    if ($script:JanetNetworkOk -and -not $SkipReplay) {
        try { Invoke-JanetReplay } catch {
            Write-Host ("NOTE: JANET replay skipped: $_") -ForegroundColor Yellow
        }
    }
}

## Header strings for the two CSV families. Pinned here so every tool
## emits the exact same column order. Detail header has 10 columns; usage
## header has 10 columns. ConvertTo-JanetCsvLine uses the same comma-strip
## rules the data rows use, so the header line round-trips cleanly.
$script:JanetDetailHeader = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
$script:JanetUsageHeader  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

function Add-JanetCsvHeader {
    ## Ensures both the network and local fallback CSVs are ready to receive
    ## a row in the current schema. Returns the (possibly redirected) paths
    ## the caller must use for the subsequent Add-JanetCsvRow call —
    ## $.NetworkPath and $.LocalPath. See Invoke-JanetHeaderEnsure for the
    ## four-case rotation/redirect logic.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    $resolvedNet   = $NetworkPath
    $resolvedLocal = $LocalPath
    try { $resolvedNet   = Invoke-JanetHeaderEnsure -Path $NetworkPath -HeaderLine $HeaderLine } catch {}
    try { $resolvedLocal = Invoke-JanetHeaderEnsure -Path $LocalPath  -HeaderLine $HeaderLine } catch {}
    return [PSCustomObject]@{ NetworkPath = $resolvedNet; LocalPath = $resolvedLocal }
}

function Invoke-JanetHeaderEnsure {
    ## Returns the path the caller should write the row to. Five cases:
    ##   1. File missing         -> mkdir, write header, return original.
    ##   2. File exists, empty   -> write header, return original. (The
    ##                              original code skipped this branch and
    ##                              left the file headerless, which produced
    ##                              2026-04_usage.csv.)
    ##   3. First line matches   -> no-op, return original.
    ##   4. First line differs,
    ##      rotation succeeds    -> rename old to <name>.legacy_<unix>.csv,
    ##                              write fresh header, return original.
    ##                              Rename retries with bounded backoff
    ##                              (200ms -> 4000ms, 6 attempts) to survive
    ##                              a peer tool's transient append lock —
    ##                              without the retry, mismatched-schema
    ##                              rows leaked into the legacy file
    ##                              (2026-05_usage.csv).
    ##   5. First line differs,
    ##      rotation fails       -> create a fresh sister CSV at
    ##                              <name>.r<unix>.csv with the current
    ##                              header, return that path. New-schema
    ##                              rows go to the sister file instead of
    ##                              corrupting the legacy file. The legacy
    ##                              file stays in place as a paper trail.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    $first = $null
    try { $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop } catch {}
    $firstTrim = if ($null -ne $first) { $first.Trim() } else { '' }

    if ($firstTrim -eq '') {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }
    if ($firstTrim -eq $HeaderLine.Trim()) { return $Path }

    $stamp      = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
    $legacyName = ([IO.Path]::GetFileNameWithoutExtension($Path)) + ".legacy_$stamp.csv"
    $rotated    = $false
    $delay      = 200
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Rename-Item -LiteralPath $Path -NewName $legacyName -ErrorAction Stop
            $rotated = $true
            break
        } catch {
            if ($attempt -lt 6) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 4000)
            }
        }
    }
    if ($rotated -or -not (Test-Path -LiteralPath $Path)) {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    ## Persistently locked. Redirect writes to a sister CSV so new-schema
    ## rows don't pollute the legacy file. Reuses the rotation timestamp in
    ## the suffix so concurrent writers in the same second land in the same
    ## sister file (deterministic per-second naming).
    $dir    = Split-Path -Parent $Path
    $base   = [IO.Path]::GetFileNameWithoutExtension($Path)
    $sister = Join-Path $dir ("$base.r$stamp.csv")
    Write-Host ("WARNING: JANET schema rotation failed; routing rows to sister CSV: " + $sister) -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $sister -ErrorAction SilentlyContinue)) {
        Add-Content -Path $sister -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
    }
    return $sister
}

function Write-JanetAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('TouchHost','VulnPatched')] [string]$Action,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Success','Failure','Skipped')] [string]$Result,
        [int]$ItemCount = 0,
        [string]$Detail = ''
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Write-JanetAction called before Start-JanetSession; ignored." -ForegroundColor Yellow
        return
    }

    ## Two-bucket action model:
    ##   TouchHost   = reached the box for any reason (message, scan, ping,
    ##                 lookup). Counts toward HostsTouched only.
    ##   VulnPatched = changed the host's security state (patch, reboot,
    ##                 STIG apply, plugin remediation, package install,
    ##                 secure-boot enable). Counts toward HostsTouched AND
    ##                 adds ItemCount to VulnsPatched.
    ## Result='Failure' increments the Failures counter regardless of bucket.
    ## Snapshot HostsTouched count BEFORE adding this host so we can detect
    ## "first time we've seen this host this session" — the trigger for
    ## emitting a real-time row to the fleet rollup CSV.
    $beforeCount = $script:JanetSession.Hosts.Count
    [void]$script:JanetSession.Hosts.Add($Target)
    $afterCount  = $script:JanetSession.Hosts.Count
    $newHost = ($afterCount -gt $beforeCount)

    if ($Result -eq 'Failure') {
        $script:JanetSession.Failures++
    }
    if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') {
        ## Failed patches don't count as "vuln patched" — only successful or
        ## skipped (where skip means already-patched, still effectively applied).
        $script:JanetSession.VulnsPatched += [int]$ItemCount
    }

    ## Per-user detail CSV — Nemesis-style folder layout:
    ##   Logs/<Tool>/<user> - <COMPUTER>_<user>/<YYYY-MM>_detail.csv
    $userFolder = Get-JanetUserFolderName
    $netDir   = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
    $localDir = Get-JanetLocalDir
    $fileName = Get-JanetMonthFile -Detail
    $netFile   = Join-Path $netDir   $fileName
    $localFile = Join-Path $localDir $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetDetailHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        $Action,
        $Target,
        $Result,
        $ItemCount,
        $Detail
    )
    Add-JanetCsvRow -NetworkPath $netFile -LocalPath $localFile -Line $line

    ## Per-host rollup snapshots removed. The form's Close Tool button is
    ## the only egress (X / Alt-F4 cancel via FormClosing guard), so every
    ## session reaches Stop-JanetSession and writes exactly one SessionEnd
    ## row to <YYYY-MM>_usage.csv. The previous design emitted a Snapshot
    ## row on every distinct-host touch (crash-resilience for force-closes
    ## that no longer happen), which made bulk runs flood the rollup CSV
    ## with hundreds of intermediate rows.
}

function Write-JanetRollupSnapshot {
    [CmdletBinding()] param([string]$ClosingNotes = '')
    if ($null -eq $script:JanetSession) { return }
    $duration    = (Get-Date) - $script:JanetSession.StartTime
    $durationMin = [Math]::Round($duration.TotalMinutes, 1)

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        'SessionEnd',
        $script:JanetSession.Hosts.Count,
        $script:JanetSession.VulnsPatched,
        $script:JanetSession.Failures,
        $durationMin,
        $ClosingNotes
    )

    $fileName  = Get-JanetMonthFile
    $netFile   = Join-Path $JanetLogRoot              $fileName
    $localFile = Join-Path (Get-JanetLocalRollupDir)  $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetUsageHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath
    Add-JanetCsvRow    -NetworkPath $netFile -LocalPath $localFile -Line $line
}

function ConvertTo-JanetCsvLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]]$Fields)
    $clean = $Fields | ForEach-Object {
        $s = if ($null -eq $_) { '' } else { [string]$_ }
        ($s -replace '[,\r\n]', ' ').Trim()
    }
    return ($clean -join ',')
}

function global:Stop-JanetSession {
    [CmdletBinding()]
    param(
        [string]$ClosingNotes = '',
        [switch]$ShowDialog
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Stop-JanetSession called with no active session; ignored." -ForegroundColor Yellow
        return
    }

    if ($ShowDialog) {
        $dialogResult = Show-JanetClosingNotesForm
        if ($null -ne $dialogResult.ASI -and $dialogResult.ASI -ne '') {
            $script:JanetSession.ASI = $dialogResult.ASI
        }
        if ($null -ne $dialogResult.Notes) {
            $ClosingNotes = $dialogResult.Notes
        }
    }

    ## SessionEnd row — the only rollup row this tool writes. Schema
    ## matches $script:JanetUsageHeader (12 cols incl. SessionId + RowType).
    ## Exactly one row per session, written from Stop-JanetSession. The dashboard
    ## parser still groups by SessionId to absorb legacy v1.8.x logs that emitted
    ## intermediate Snapshot rows; new sessions never produce them.
    Write-JanetRollupSnapshot -ClosingNotes $ClosingNotes

    $script:JanetSession   = $null
    $script:JanetNetworkOk = $false
}

function Show-JanetClosingNotesForm {
    ## WPT-styled closing-notes prompt. Self-contained -- hard-codes the
    ## WPT dark palette so every tool gets identical look without depending
    ## on its own theme tables. Return shape ({ ASI; Notes }) is preserved
    ## so existing Stop-JanetSession callers keep working unchanged.
    [CmdletBinding()] param()
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing       -ErrorAction SilentlyContinue

    ## --- WPT theme palette (rgb values copy/pasted from WPT $script:WPT.UI.Theme)
    $cBg          = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    $cInput       = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    $cBorder      = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    $cAccent1     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    $cSuccess     = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    $cPanelLight  = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    $cTextPrimary = [System.Drawing.Color]::FromArgb(240, 240, 245)
    $cTextSec     = [System.Drawing.Color]::FromArgb(170, 168, 180)
    $cTextOnAcc   = [System.Drawing.Color]::FromArgb(255, 255, 255)

    $face       = 'Segoe UI'
    $fntBody    = New-Object System.Drawing.Font($face,  9)
    $fntPrompt  = New-Object System.Drawing.Font($face, 13, [System.Drawing.FontStyle]::Bold)
    $fntCaption = New-Object System.Drawing.Font($face,  8.25)
    $fntBtn     = New-Object System.Drawing.Font($face,  9, [System.Drawing.FontStyle]::Bold)

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'Closing Notes'
    $form.ClientSize      = New-Object System.Drawing.Size(640, 380)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition   = 'CenterScreen'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.BackColor       = $cBg
    $form.ForeColor       = $cTextPrimary
    $form.Font            = $fntBody
    $form.Topmost         = $true

    ## Immersive dark title bar -- same DwmSetWindowAttribute trick WPT uses.
    ## Silent fallthrough on builds that don't support attr 19/20.
    try {
        if (-not ('JanetClosingNotes.Dwm' -as [type])) {
            Add-Type -Namespace 'JanetClosingNotes' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction Stop
        }
    } catch {}
    $form.Add_HandleCreated({
        try {
            $hwnd = $form.Handle
            if ($hwnd -ne [System.IntPtr]::Zero) {
                $on = 1
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) | Out-Null
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4) | Out-Null
            }
        } catch {}
    }.GetNewClosure())

    ## Prompt + sub-hint (mirrors WPT's Show-WptClosingNotesDialog)
    $lblPrompt           = New-Object System.Windows.Forms.Label
    $lblPrompt.Text      = 'Anything worth noting from this session?'
    $lblPrompt.Location  = New-Object System.Drawing.Point(20, 16)
    $lblPrompt.Size      = New-Object System.Drawing.Size(600, 24)
    $lblPrompt.Font      = $fntPrompt
    $lblPrompt.ForeColor = $cAccent1
    $lblPrompt.BackColor = [System.Drawing.Color]::Transparent

    $lblHint           = New-Object System.Windows.Forms.Label
    $lblHint.Text      = 'Notes are appended to the JANET monthly usage CSV. Blank is fine.'
    $lblHint.Location  = New-Object System.Drawing.Point(20, 44)
    $lblHint.Size      = New-Object System.Drawing.Size(600, 18)
    $lblHint.Font      = $fntCaption
    $lblHint.ForeColor = $cTextSec
    $lblHint.BackColor = [System.Drawing.Color]::Transparent

    ## ASI / RFC field -- preserved from the legacy form because Stop-JanetSession
    ## reads .ASI off the result and writes it into the rollup CSV.
    $lblAsi           = New-Object System.Windows.Forms.Label
    $lblAsi.Text      = 'ASI / RFC #'
    $lblAsi.Location  = New-Object System.Drawing.Point(20, 78)
    $lblAsi.Size      = New-Object System.Drawing.Size(120, 16)
    $lblAsi.Font      = $fntCaption
    $lblAsi.ForeColor = $cTextSec
    $lblAsi.BackColor = [System.Drawing.Color]::Transparent

    $tbAsi             = New-Object System.Windows.Forms.TextBox
    $tbAsi.Location    = New-Object System.Drawing.Point(20, 96)
    $tbAsi.Size        = New-Object System.Drawing.Size(600, 24)
    $tbAsi.Font        = $fntBody
    $tbAsi.BackColor   = $cInput
    $tbAsi.ForeColor   = $cTextPrimary
    $tbAsi.BorderStyle = 'FixedSingle'

    ## Closing notes (multiline)
    $lblNotes           = New-Object System.Windows.Forms.Label
    $lblNotes.Text      = 'Closing notes'
    $lblNotes.Location  = New-Object System.Drawing.Point(20, 130)
    $lblNotes.Size      = New-Object System.Drawing.Size(120, 16)
    $lblNotes.Font      = $fntCaption
    $lblNotes.ForeColor = $cTextSec
    $lblNotes.BackColor = [System.Drawing.Color]::Transparent

    $tbNotes               = New-Object System.Windows.Forms.TextBox
    $tbNotes.Location      = New-Object System.Drawing.Point(20, 148)
    $tbNotes.Size          = New-Object System.Drawing.Size(600, 168)
    $tbNotes.Multiline     = $true
    $tbNotes.AcceptsReturn = $true
    $tbNotes.ScrollBars    = 'Vertical'
    $tbNotes.Font          = $fntBody
    $tbNotes.BackColor     = $cInput
    $tbNotes.ForeColor     = $cTextPrimary
    $tbNotes.BorderStyle   = 'FixedSingle'

    ## Buttons -- 'Submit && Exit' (Success green) + 'Skip' (PanelLight gray).
    ## Two-button rather than WPT's three-way: this dialog runs from FormClosing,
    ## so a 'Return to Tool' choice can't actually return; the form is already
    ## tearing down by the time we land here.
    $btnSubmit = New-Object System.Windows.Forms.Button
    $btnSubmit.Text         = 'Submit && Exit'
    $btnSubmit.Location     = New-Object System.Drawing.Point(380, 332)
    $btnSubmit.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSubmit.FlatStyle    = 'Flat'
    $btnSubmit.FlatAppearance.BorderSize = 0
    $btnSubmit.BackColor    = $cSuccess
    $btnSubmit.ForeColor    = $cTextOnAcc
    $btnSubmit.Font         = $fntBtn
    $btnSubmit.UseVisualStyleBackColor = $false
    $btnSubmit.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnSkip = New-Object System.Windows.Forms.Button
    $btnSkip.Text         = 'Skip'
    $btnSkip.Location     = New-Object System.Drawing.Point(505, 332)
    $btnSkip.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSkip.FlatStyle    = 'Flat'
    $btnSkip.FlatAppearance.BorderSize  = 1
    $btnSkip.FlatAppearance.BorderColor = $cBorder
    $btnSkip.BackColor    = $cPanelLight
    $btnSkip.ForeColor    = $cTextPrimary
    $btnSkip.Font         = $fntBtn
    $btnSkip.UseVisualStyleBackColor = $false
    $btnSkip.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.AcceptButton = $btnSubmit
    $form.CancelButton = $btnSkip
    $form.Controls.AddRange(@($lblPrompt, $lblHint, $lblAsi, $tbAsi, $lblNotes, $tbNotes, $btnSubmit, $btnSkip))

    $result = $form.ShowDialog()
    $asi   = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbAsi.Text }   else { '' }
    $notes = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbNotes.Text } else { '' }
    $form.Dispose()

    return [PSCustomObject]@{ ASI = $asi; Notes = $notes }
}

function Invoke-JanetReplay {
    [CmdletBinding()] param()

    if ($null -eq $script:JanetSession) { return }
    $userFolder = Get-JanetUserFolderName

    ## Two local spool locations to drain:
    ##   1. JanetLocal/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##      → Logs/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##   2. JanetLocal/_Rollup/<userfolder>/<YYYY-MM>_usage.csv
    ##      → Logs/<YYYY-MM>_usage.csv
    $detailLocal = Get-JanetLocalDir
    $rollupLocal = Get-JanetLocalRollupDir

    $sources = @()
    if (Test-Path $detailLocal) {
        $detailNet = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
        $sources += [PSCustomObject]@{ Local = $detailLocal; NetDir = $detailNet; Filter = '*_detail*.csv' }
    }
    if (Test-Path $rollupLocal) {
        $sources += [PSCustomObject]@{ Local = $rollupLocal; NetDir = $JanetLogRoot; Filter = '*_usage*.csv' }
    }

    foreach ($src in $sources) {
        $orphans = Get-ChildItem -Path $src.Local -File -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Name -like $src.Filter) -and ($_.Name -notlike '*.replayed_*') -and ($_.Name -notlike '*.legacy_*')
            }

        foreach ($orphan in $orphans) {
            if (-not (Test-Path $src.NetDir)) {
                try { [void](New-Item -ItemType Directory -Path $src.NetDir -Force -ErrorAction Stop) }
                catch { continue }
            }
            $netFile = Join-Path $src.NetDir $orphan.Name

            $replayOk = $true
            Get-Content -Path $orphan.FullName | ForEach-Object {
                ## Skip the local header row if the network file already has one —
                ## otherwise the rollup CSV ends up with a header line every time
                ## an orphan is replayed, which makes pivoting harder.
                if ($_ -like 'Timestamp,*' -and (Test-Path $netFile)) { return }
                try {
                    Add-Content -Path $netFile -Value $_ -Encoding UTF8 -ErrorAction Stop
                } catch {
                    $replayOk = $false
                }
            }

            if ($replayOk) {
                $stamp     = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
                $newName   = "$($orphan.Name).replayed_$stamp"
                try {
                    Rename-Item -LiteralPath $orphan.FullName -NewName $newName -ErrorAction Stop
                } catch {
                    Write-Host ("NOTE: Could not rename replayed file '$($orphan.FullName)': $_") -ForegroundColor Yellow
                }
            }
        }
    }
}

# === END JANET LOGGING BLOCK (paste to here) ===


#region === RESOLVE SCRIPT DIR ===
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }
#endregion

#region === LOGGING ===
$parentDir = Split-Path -Parent $global:ScriptDir
$global:LogDir = $null
foreach ($candidate in @((Join-Path $parentDir "Logs"), (Join-Path $global:ScriptDir "Logs"), $global:ScriptDir)) {
    try {
        if (-not (Test-Path $candidate)) { New-Item -Path $candidate -ItemType Directory -Force -EA Stop | Out-Null }
        $testFile = Join-Path $candidate ".janet_write_test"
        Set-Content -Path $testFile -Value "test" -EA Stop; Remove-Item $testFile -Force -EA SilentlyContinue
        $global:LogDir = $candidate; break
    } catch { continue }
}
if (-not $global:LogDir) { $global:LogDir = $global:ScriptDir }

$global:LogFile = Join-Path $global:LogDir ("JDHCP_{0}_{1}.log" -f $env:USERNAME, (Get-Date -Format "yyyy-MM-dd_HH-mm-ss"))
function Write-JLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try { Add-Content -Path $global:LogFile -Value "[$ts] [$Level] $Message" -EA SilentlyContinue } catch {}
}
Write-JLog "=== J.A.N.E.T. DHCP Scope Option Tool v$JanetDHCP_ScopeVersion starting ==="
Write-JLog "ScriptDir: $($global:ScriptDir) | User: $env:USERNAME | PS: $($PSVersionTable.PSVersion)"
#endregion

#region === COLORS / FONTS (Purple + Gold on Black - mirrors JANET.ps1) ===
$colors = @{
    Background    = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    Sidebar       = [System.Drawing.Color]::FromArgb(  7,   7,  11)
    TopBar        = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Panel         = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    PanelLight    = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    Input         = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    InputBorder   = [System.Drawing.Color]::FromArgb( 52,  46,  72)
    OutputBg      = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Border        = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    TextPrimary   = [System.Drawing.Color]::FromArgb(240, 240, 245)
    TextSecondary = [System.Drawing.Color]::FromArgb(170, 168, 180)
    TextDim       = [System.Drawing.Color]::FromArgb(110, 106, 125)
    Accent        = [System.Drawing.Color]::FromArgb(140, 100, 220)  ## #8C64DC purple
    AccentHover   = [System.Drawing.Color]::FromArgb(164, 128, 240)
    AccentDim     = [System.Drawing.Color]::FromArgb( 96,  68, 156)
    Success       = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    SuccessDim    = [System.Drawing.Color]::FromArgb( 50, 120,  65)
    Warning       = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger        = [System.Drawing.Color]::FromArgb(224,  80,  90)
    Cyan          = [System.Drawing.Color]::FromArgb( 88, 180, 210)
    Console       = [System.Drawing.Color]::FromArgb(164, 128, 240)  ## purple phosphor
    Gold          = [System.Drawing.Color]::FromArgb(218, 180,  82)  ## #DAB452
    GoldDim       = [System.Drawing.Color]::FromArgb(155, 125,  52)
}

$fonts = @{
    JTitle    = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    JSub      = New-Object System.Drawing.Font("Segoe UI", 9,  [System.Drawing.FontStyle]::Italic)
    Section   = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
    Label     = New-Object System.Drawing.Font("Segoe UI", 9.5)
    LabelBold = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
    Button    = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
    ButtonBig = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
    Small     = New-Object System.Drawing.Font("Segoe UI", 8.5)
    SmallBold = New-Object System.Drawing.Font("Segoe UI Semibold", 8.5)
    Tiny      = New-Object System.Drawing.Font("Segoe UI Semibold", 7.5)
    Console   = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 9)
    ConsoleSm = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 8.5)
}
#endregion

#region === GLOBAL STATE ===
$global:Cred = $null

if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $inherited = Import-Clixml -Path $env:JANET_CRED_FILE -ErrorAction Stop
        if ($inherited -is [System.Management.Automation.PSCredential]) {
            $global:Cred = $inherited
            Write-JLog "Inherited credential from J.A.N.E.T. launcher: $($inherited.UserName)" "INFO"
        }
    } catch {
        Write-JLog "Failed to import inherited credential: $($_.Exception.Message)" "WARN"
    }
}

$script:UseCurrentSession = $false  ## skip -Credential, run as logged-in user
$script:DhcpServer = $null     ## current connected server
$script:Scopes     = @()       ## last loaded scope list
$script:CurrentScopeId = $null ## selected ScopeId (IPAddress as string)
$script:CurrentOptionId = 6
$script:OriginalValues = @()   ## as-loaded values (for diff)
$script:WorkingValues  = New-Object System.Collections.ArrayList
$script:SuppressScopeLoad = $false  ## set by ItemCheck to squelch auto-load when a checkbox click also changes the ListView selection

## Common IP-array options (Type = IPv4Address)
$script:CommonOptions = @(
    [pscustomobject]@{ Id =  3; Name = "003 Router" }
    [pscustomobject]@{ Id =  6; Name = "006 DNS Servers" }
    [pscustomobject]@{ Id = 42; Name = "042 NTP Servers" }
    [pscustomobject]@{ Id = 44; Name = "044 WINS / NBNS Servers" }
    [pscustomobject]@{ Id = 45; Name = "045 NetBIOS over TCP/IP NBDD" }
)
#endregion

#region === FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text = "J.A.N.E.T. DHCP Scope Option Tool v$JanetDHCP_ScopeVersion"
$f.Size = New-Object System.Drawing.Size(1400, 900)
$f.MinimumSize = New-Object System.Drawing.Size(1280, 800)
## All full-width strips (header, cred, server, main, bulk, status) use this
## as their construction width so they exactly match the form's client area.
## Hardcoding 1400 was leaving them too wide / too narrow when the form was
## resized -- the right-anchored children rode the over-wide right edge off
## the visible window.
$winW = $f.ClientSize.Width
$f.StartPosition = "CenterScreen"
$f.BackColor = $colors.Background
$f.ForeColor = $colors.TextPrimary
$f.Font = $fonts.Label

#endregion

#region === HELPER BUILDERS ===
function New-StyledButton {
    param([string]$Text, [System.Drawing.Point]$Location, [System.Drawing.Size]$Size,
          [System.Drawing.Color]$BgColor, $FgColor = $null,
          [System.Drawing.Font]$Font = $fonts.Button)
    if (-not $FgColor) {
        $lum = (0.299 * $BgColor.R + 0.587 * $BgColor.G + 0.114 * $BgColor.B) / 255.0
        if ($lum -gt 0.55) { $FgColor = [System.Drawing.Color]::Black } else { $FgColor = [System.Drawing.Color]::White }
    }
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text; $btn.Location = $Location; $btn.Size = $Size
    $btn.BackColor = $BgColor; $btn.ForeColor = $FgColor
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.Font = $Font; $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $r = [Math]::Min(255, $BgColor.R + 30); $g = [Math]::Min(255, $BgColor.G + 30); $b = [Math]::Min(255, $BgColor.B + 30)
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($r, $g, $b)
    return $btn
}

function New-StyledTextBox {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size,
          [System.Drawing.Font]$Font = $fonts.Console)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = $Location; $t.Size = $Size
    $t.BackColor = $colors.Input; $t.ForeColor = $colors.TextPrimary
    $t.Font = $Font; $t.BorderStyle = 'FixedSingle'
    return $t
}

function New-StyledLabel {
    param([string]$Text, [System.Drawing.Point]$Location, [System.Drawing.Size]$Size,
          [System.Drawing.Color]$Fg = $colors.TextSecondary,
          [System.Drawing.Font]$Font = $fonts.Label)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Location = $Location; $l.Size = $Size
    $l.ForeColor = $Fg; $l.Font = $Font
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}
#endregion

#region === HEADER ===
$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Size = New-Object System.Drawing.Size($winW, 70)
$header.BackColor = $colors.TopBar
$header.Anchor = 'Top,Left,Right'
$f.Controls.Add($header)

$lblTitle = New-StyledLabel -Text "J.A.N.E.T. DHCP Scope Option Tool" `
    -Location (New-Object System.Drawing.Point(75, 12)) `
    -Size (New-Object System.Drawing.Size(700, 28)) -Fg $colors.Gold -Font $fonts.JTitle
$header.Controls.Add($lblTitle)

$lblSub = New-StyledLabel -Text "Joint Administration and Network Execution Toolkit" `
    -Location (New-Object System.Drawing.Point(77, 40)) `
    -Size (New-Object System.Drawing.Size(500, 16)) -Fg $colors.TextSecondary -Font $fonts.JSub
$header.Controls.Add($lblSub)

$lblVer = New-StyledLabel -Text "v$JanetDHCP_ScopeVersion  |  IP-Array Scope Option Editor  |  Bulk Apply" `
    -Location (New-Object System.Drawing.Point(77, 56)) `
    -Size (New-Object System.Drawing.Size(400, 12)) -Fg $colors.GoldDim -Font $fonts.Tiny
$header.Controls.Add($lblVer)

## Close Tool — top-right of the header (matches WPT pattern). Single
## sanctioned form egress: sets the X-block allow flag, then closes;
## FormClosing guard cancels every other origin.
$btnHdrCloseTool = New-StyledButton -Text "Close Tool" `
    -Location (New-Object System.Drawing.Point(($winW - 110 - 16), 20)) `
    -Size (New-Object System.Drawing.Size(110, 28)) -BgColor $colors.Danger `
    -FgColor ([System.Drawing.Color]::White) -Font $fonts.Button
$btnHdrCloseTool.Anchor = 'Top,Right'
$btnHdrCloseTool.Add_Click({
    Set-JanetAllowClose $true
    $f.Close()
}.GetNewClosure())
$header.Controls.Add($btnHdrCloseTool)

$goldLine = New-Object System.Windows.Forms.Panel
$goldLine.Location = New-Object System.Drawing.Point(0, 70)
$goldLine.Size = New-Object System.Drawing.Size($winW, 2)
$goldLine.BackColor = $colors.Gold
$goldLine.Anchor = 'Top,Left,Right'
$f.Controls.Add($goldLine)
#endregion

#region === CREDENTIAL STRIP ===
$credStrip = New-Object System.Windows.Forms.Panel
$credStrip.Location = New-Object System.Drawing.Point(0, 74)
$credStrip.Size = New-Object System.Drawing.Size($winW, 44)
$credStrip.BackColor = $colors.Panel
$credStrip.Anchor = 'Top,Left,Right'
$f.Controls.Add($credStrip)

$lblCredHdr = New-StyledLabel -Text "ADW CREDENTIALS" `
    -Location (New-Object System.Drawing.Point(15, 8)) `
    -Size (New-Object System.Drawing.Size(140, 14)) -Fg $colors.GoldDim -Font $fonts.Tiny
$credStrip.Controls.Add($lblCredHdr)

$btnSetCreds = New-StyledButton -Text "Set Credentials..." `
    -Location (New-Object System.Drawing.Point(15, 22)) `
    -Size (New-Object System.Drawing.Size(140, 20)) -BgColor $colors.Accent `
    -FgColor ([System.Drawing.Color]::White) -Font $fonts.Small
$credStrip.Controls.Add($btnSetCreds)

$lblCredStatus = New-Object System.Windows.Forms.Label
if ($global:Cred) {
    $lblCredStatus.Text = "Active: $($global:Cred.UserName)  (inherited from launcher)"
    $lblCredStatus.ForeColor = $colors.Success
} else {
    $lblCredStatus.Text = "No credentials set - required before connecting"
    $lblCredStatus.ForeColor = $colors.Danger
}
## Status label sits to the right of the checkbox, anchored Top,Left,Right so
## it stretches to fill the remaining strip width regardless of form size.
## Initial width is computed against the credStrip's construction-time width.
$lblCredStatus.Location = New-Object System.Drawing.Point(645, 22)
$lblCredStatus.Size = New-Object System.Drawing.Size(($credStrip.Width - 660), 18)
$lblCredStatus.Anchor = 'Top,Left,Right'
$lblCredStatus.Font = $fonts.LabelBold
$lblCredStatus.BackColor = [System.Drawing.Color]::Transparent
$credStrip.Controls.Add($lblCredStatus)

$btnSetCreds.Add_Click({
    $c = Get-Credential -Message "Enter your ADW / privileged admin credentials"
    if ($c) {
        $global:Cred = $c
        $lblCredStatus.Text = "Active: $($c.UserName)  (ADM)"
        $lblCredStatus.ForeColor = $colors.Success
        Write-JLog "Credentials set: $($c.UserName)"
    }
})

## "Use current session" checkbox: when ticked, Invoke-OnDhcp drops the
## -Credential parameter and lets WSMan use the logged-in user's Kerberos /
## NTLM token. Use this when you've already opened PowerShell as your ADM
## account (or any privileged account) and -Credential is rejecting your
## inherited / typed creds with "username is incorrect" -- that error
## usually means the cred file from the launcher was captured under a
## different user, or the password is stale, or the domain prefix is wrong.
## Skipping -Credential entirely sidesteps all three.
$chkUseSession = New-Object System.Windows.Forms.CheckBox
## Sits between the Set Creds button and the status label. Fixed left
## position; status label flexes to fill the rest of the strip.
$chkUseSession.Location = New-Object System.Drawing.Point(165, 22)
$chkUseSession.Size = New-Object System.Drawing.Size(470, 20)
$chkUseSession.Text = "Use current session  (run as logged-in user)"
$chkUseSession.ForeColor = $colors.Cyan
$chkUseSession.BackColor = [System.Drawing.Color]::Transparent
$chkUseSession.Font = $fonts.LabelBold
$chkUseSession.Checked = $false
$credStrip.Controls.Add($chkUseSession)

$chkUseSession.Add_CheckedChanged({
    $script:UseCurrentSession = $chkUseSession.Checked
    if ($chkUseSession.Checked) {
        $btnSetCreds.Enabled = $false
        $whoami = "$env:USERDOMAIN\$env:USERNAME"
        $lblCredStatus.Text = "Using current session: $whoami  (no -Credential)"
        $lblCredStatus.ForeColor = $colors.Cyan
        Log-Activity "Auth mode: current session ($whoami) -- -Credential will not be passed." $colors.Cyan
    } else {
        $btnSetCreds.Enabled = $true
        if ($global:Cred) {
            $lblCredStatus.Text = "Active: $($global:Cred.UserName)"
            $lblCredStatus.ForeColor = $colors.Success
        } else {
            $lblCredStatus.Text = "No credentials set - required before connecting"
            $lblCredStatus.ForeColor = $colors.Danger
        }
        Log-Activity "Auth mode: explicit credential ($(if ($global:Cred) { $global:Cred.UserName } else { 'none set' }))." $colors.TextDim
    }
})
#endregion

#region === SERVER STRIP (DHCP server hostname + Connect) ===
$srvStrip = New-Object System.Windows.Forms.Panel
$srvStrip.Location = New-Object System.Drawing.Point(0, 120)
$srvStrip.Size = New-Object System.Drawing.Size($winW, 56)
$srvStrip.BackColor = $colors.Panel
$srvStrip.Anchor = 'Top,Left,Right'
$f.Controls.Add($srvStrip)

$lblSrvHdr = New-StyledLabel -Text "DHCP SERVER" `
    -Location (New-Object System.Drawing.Point(15, 8)) `
    -Size (New-Object System.Drawing.Size(140, 14)) -Fg $colors.GoldDim -Font $fonts.Tiny
$srvStrip.Controls.Add($lblSrvHdr)

$lblSrvHint = New-StyledLabel -Text "Hostname or FQDN of the authorized DHCP server" `
    -Location (New-Object System.Drawing.Point(160, 8)) `
    -Size (New-Object System.Drawing.Size(400, 14)) -Fg $colors.TextDim -Font $fonts.Small
$srvStrip.Controls.Add($lblSrvHint)

$txtServer = New-StyledTextBox -Location (New-Object System.Drawing.Point(15, 24)) `
    -Size (New-Object System.Drawing.Size(280, 24))
$txtServer.Font = $fonts.Console
$srvStrip.Controls.Add($txtServer)

$btnConnect = New-StyledButton -Text "Connect" `
    -Location (New-Object System.Drawing.Point(305, 24)) `
    -Size (New-Object System.Drawing.Size(95, 24)) -BgColor $colors.Accent `
    -FgColor ([System.Drawing.Color]::White)
$srvStrip.Controls.Add($btnConnect)

$btnDisconnect = New-StyledButton -Text "Disconnect" `
    -Location (New-Object System.Drawing.Point(404, 24)) `
    -Size (New-Object System.Drawing.Size(95, 24)) -BgColor $colors.PanelLight
$btnDisconnect.Enabled = $false
$srvStrip.Controls.Add($btnDisconnect)

$lblSrvStatus = New-StyledLabel -Text "Not connected" `
    -Location (New-Object System.Drawing.Point(515, 28)) `
    -Size (New-Object System.Drawing.Size(800, 18)) -Fg $colors.TextDim -Font $fonts.LabelBold
$srvStrip.Controls.Add($lblSrvStatus)
#endregion

#region === MAIN CONTENT ===
$mainY = 182
$bulkH = 160     ## bulk-apply strip at the bottom of the form
$main = New-Object System.Windows.Forms.Panel
$main.Location = New-Object System.Drawing.Point(0, $mainY)
$main.Size = New-Object System.Drawing.Size($winW, ($f.ClientSize.Height - $mainY - 28 - $bulkH))
$main.BackColor = $colors.Background
$main.Anchor = 'Top,Left,Right,Bottom'
$f.Controls.Add($main)

## === LEFT COLUMN: Scopes ===
$colLeftW = 360
$pnlScopes = New-Object System.Windows.Forms.Panel
$pnlScopes.Location = New-Object System.Drawing.Point(10, 5)
$pnlScopes.Size = New-Object System.Drawing.Size($colLeftW, ($main.Height - 15))
$pnlScopes.BackColor = $colors.Panel
$pnlScopes.Anchor = 'Top,Left,Bottom'
$main.Controls.Add($pnlScopes)

$lblScopeHdr = New-StyledLabel -Text "SCOPES" `
    -Location (New-Object System.Drawing.Point(12, 10)) `
    -Size (New-Object System.Drawing.Size(260, 18)) -Fg $colors.Gold -Font $fonts.Section
$pnlScopes.Controls.Add($lblScopeHdr)

$lblScopeHint = New-StyledLabel -Text "Click a row to edit one scope. Check the box to include in BULK APPLY." `
    -Location (New-Object System.Drawing.Point(12, 32)) `
    -Size (New-Object System.Drawing.Size(340, 14)) -Fg $colors.TextSecondary -Font $fonts.Small
$pnlScopes.Controls.Add($lblScopeHint)

$lvScopes = New-Object System.Windows.Forms.ListView
$lvScopes.Location = New-Object System.Drawing.Point(12, 50)
$lvScopes.Size = New-Object System.Drawing.Size(($colLeftW - 24), ($pnlScopes.Height - 138))
$lvScopes.Anchor = 'Top,Left,Right,Bottom'
$lvScopes.View = 'Details'
$lvScopes.FullRowSelect = $true
$lvScopes.MultiSelect = $false
$lvScopes.HideSelection = $false
$lvScopes.GridLines = $false
$lvScopes.CheckBoxes = $true   ## per-row checkboxes for bulk-apply selection
$lvScopes.BackColor = $colors.Input
$lvScopes.ForeColor = $colors.TextPrimary
$lvScopes.Font = $fonts.Console
$lvScopes.BorderStyle = 'FixedSingle'
[void]$lvScopes.Columns.Add("Scope ID", 110)
[void]$lvScopes.Columns.Add("Name",     130)
[void]$lvScopes.Columns.Add("State",     60)
$pnlScopes.Controls.Add($lvScopes)

## Bulk-select button row (just below the listview)
$bulkBtnY = $pnlScopes.Height - 80
$btnSelAll = New-StyledButton -Text "All" `
    -Location (New-Object System.Drawing.Point(12, $bulkBtnY)) `
    -Size (New-Object System.Drawing.Size(60, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnSelAll.Anchor = 'Bottom,Left'
$pnlScopes.Controls.Add($btnSelAll)

$btnSelNone = New-StyledButton -Text "None" `
    -Location (New-Object System.Drawing.Point(76, $bulkBtnY)) `
    -Size (New-Object System.Drawing.Size(60, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnSelNone.Anchor = 'Bottom,Left'
$pnlScopes.Controls.Add($btnSelNone)

$btnSelActive = New-StyledButton -Text "Active" `
    -Location (New-Object System.Drawing.Point(140, $bulkBtnY)) `
    -Size (New-Object System.Drawing.Size(70, 26)) -BgColor $colors.SuccessDim -Font $fonts.Small
$btnSelActive.Anchor = 'Bottom,Left'
$pnlScopes.Controls.Add($btnSelActive)

$btnSelInvert = New-StyledButton -Text "Invert" `
    -Location (New-Object System.Drawing.Point(214, $bulkBtnY)) `
    -Size (New-Object System.Drawing.Size(70, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnSelInvert.Anchor = 'Bottom,Left'
$pnlScopes.Controls.Add($btnSelInvert)

$lblScopeCount = New-StyledLabel -Text "0 scopes  |  0 checked" `
    -Location (New-Object System.Drawing.Point(12, ($pnlScopes.Height - 40))) `
    -Size (New-Object System.Drawing.Size(($colLeftW - 24), 18)) -Fg $colors.TextSecondary -Font $fonts.LabelBold
$lblScopeCount.Anchor = 'Bottom,Left,Right'
$pnlScopes.Controls.Add($lblScopeCount)

## === MIDDLE COLUMN: Option editor ===
$colMidX = $colLeftW + 20
$colMidW = 540
$pnlOpt = New-Object System.Windows.Forms.Panel
$pnlOpt.Location = New-Object System.Drawing.Point($colMidX, 5)
$pnlOpt.Size = New-Object System.Drawing.Size($colMidW, ($main.Height - 15))
$pnlOpt.BackColor = $colors.Panel
## Fixed-width middle column. Was 'Top,Left,Right,Bottom' which made the
## panel grow horizontally with the form -- swallowing the activity log
## column and dragging the right-anchored reorder buttons off-screen. Only
## the right-most column (pnlLog) should absorb extra width.
$pnlOpt.Anchor = 'Top,Left,Bottom'
$main.Controls.Add($pnlOpt)

$lblOptHdr = New-StyledLabel -Text "SCOPE OPTION" `
    -Location (New-Object System.Drawing.Point(12, 10)) `
    -Size (New-Object System.Drawing.Size(260, 18)) -Fg $colors.Gold -Font $fonts.Section
$pnlOpt.Controls.Add($lblOptHdr)

$lblOptScope = New-StyledLabel -Text "No scope selected" `
    -Location (New-Object System.Drawing.Point(12, 32)) `
    -Size (New-Object System.Drawing.Size(($colMidW - 24), 14)) -Fg $colors.TextDim -Font $fonts.Small
$pnlOpt.Controls.Add($lblOptScope)

## Option dropdown + freeform option ID
$lblOptCommon = New-StyledLabel -Text "Option:" `
    -Location (New-Object System.Drawing.Point(12, 56)) `
    -Size (New-Object System.Drawing.Size(60, 18)) -Fg $colors.TextSecondary -Font $fonts.LabelBold
$pnlOpt.Controls.Add($lblOptCommon)

$cmbOption = New-Object System.Windows.Forms.ComboBox
$cmbOption.Location = New-Object System.Drawing.Point(75, 54)
$cmbOption.Size = New-Object System.Drawing.Size(230, 24)
$cmbOption.DropDownStyle = 'DropDownList'
$cmbOption.BackColor = $colors.Input
$cmbOption.ForeColor = $colors.TextPrimary
$cmbOption.Font = $fonts.Console
$cmbOption.FlatStyle = 'Flat'
foreach ($opt in $script:CommonOptions) { [void]$cmbOption.Items.Add($opt.Name) }
[void]$cmbOption.Items.Add("Other (specify ID) ...")
$cmbOption.SelectedIndex = 1   ## default 006 DNS Servers
$pnlOpt.Controls.Add($cmbOption)

$lblOptCustom = New-StyledLabel -Text "ID:" `
    -Location (New-Object System.Drawing.Point(315, 56)) `
    -Size (New-Object System.Drawing.Size(25, 18)) -Fg $colors.TextSecondary -Font $fonts.LabelBold
$pnlOpt.Controls.Add($lblOptCustom)

$numOptionId = New-Object System.Windows.Forms.NumericUpDown
$numOptionId.Location = New-Object System.Drawing.Point(340, 54)
$numOptionId.Size = New-Object System.Drawing.Size(55, 24)
$numOptionId.Minimum = 1
$numOptionId.Maximum = 254
$numOptionId.Value = 6
$numOptionId.BackColor = $colors.Input
$numOptionId.ForeColor = $colors.TextPrimary
$numOptionId.Font = $fonts.Console
$numOptionId.BorderStyle = 'FixedSingle'
$numOptionId.Enabled = $false  ## only enabled when "Other" selected
$pnlOpt.Controls.Add($numOptionId)

$btnLoadOpt = New-StyledButton -Text "Load Values" `
    -Location (New-Object System.Drawing.Point(405, 54)) `
    -Size (New-Object System.Drawing.Size(110, 24)) -BgColor $colors.Cyan
$btnLoadOpt.Enabled = $false
$pnlOpt.Controls.Add($btnLoadOpt)

## Current values list
$lblValsHdr = New-StyledLabel -Text "IP ADDRESS LIST  (order matters)" `
    -Location (New-Object System.Drawing.Point(12, 92)) `
    -Size (New-Object System.Drawing.Size(300, 14)) -Fg $colors.GoldDim -Font $fonts.Tiny
$pnlOpt.Controls.Add($lblValsHdr)

$lstValues = New-Object System.Windows.Forms.ListBox
$lstValues.Location = New-Object System.Drawing.Point(12, 110)
$lstValues.Size = New-Object System.Drawing.Size(($colMidW - 24 - 110), ($pnlOpt.Height - 240))
$lstValues.Anchor = 'Top,Left,Right,Bottom'
$lstValues.BackColor = $colors.Input
$lstValues.ForeColor = $colors.Console
$lstValues.Font = $fonts.Console
$lstValues.BorderStyle = 'FixedSingle'
$lstValues.SelectionMode = 'One'
$pnlOpt.Controls.Add($lstValues)

## Reorder buttons (right side of list)
$btnColX = $colMidW - 24 - 100 + 12 + 4
$btnUp = New-StyledButton -Text "Move Up" `
    -Location (New-Object System.Drawing.Point($btnColX, 110)) `
    -Size (New-Object System.Drawing.Size(100, 28)) -BgColor $colors.PanelLight
$btnUp.Anchor = 'Top,Right'
$pnlOpt.Controls.Add($btnUp)

$btnDown = New-StyledButton -Text "Move Down" `
    -Location (New-Object System.Drawing.Point($btnColX, 142)) `
    -Size (New-Object System.Drawing.Size(100, 28)) -BgColor $colors.PanelLight
$btnDown.Anchor = 'Top,Right'
$pnlOpt.Controls.Add($btnDown)

$btnTop = New-StyledButton -Text "Move Top" `
    -Location (New-Object System.Drawing.Point($btnColX, 174)) `
    -Size (New-Object System.Drawing.Size(100, 28)) -BgColor $colors.PanelLight
$btnTop.Anchor = 'Top,Right'
$pnlOpt.Controls.Add($btnTop)

$btnBottom = New-StyledButton -Text "Move Bottom" `
    -Location (New-Object System.Drawing.Point($btnColX, 206)) `
    -Size (New-Object System.Drawing.Size(100, 28)) -BgColor $colors.PanelLight
$btnBottom.Anchor = 'Top,Right'
$pnlOpt.Controls.Add($btnBottom)

$btnRemove = New-StyledButton -Text "Remove" `
    -Location (New-Object System.Drawing.Point($btnColX, 246)) `
    -Size (New-Object System.Drawing.Size(100, 28)) -BgColor $colors.Danger
$btnRemove.Anchor = 'Top,Right'
$pnlOpt.Controls.Add($btnRemove)

## Add IP row
$lblAddHdr = New-StyledLabel -Text "ADD IP ADDRESS" `
    -Location (New-Object System.Drawing.Point(12, ($pnlOpt.Height - 120))) `
    -Size (New-Object System.Drawing.Size(200, 14)) -Fg $colors.GoldDim -Font $fonts.Tiny
$lblAddHdr.Anchor = 'Bottom,Left'
$pnlOpt.Controls.Add($lblAddHdr)

$txtAddIp = New-StyledTextBox -Location (New-Object System.Drawing.Point(12, ($pnlOpt.Height - 100))) `
    -Size (New-Object System.Drawing.Size(220, 26))
$txtAddIp.Anchor = 'Bottom,Left'
$pnlOpt.Controls.Add($txtAddIp)

$btnAddIp = New-StyledButton -Text "Add" `
    -Location (New-Object System.Drawing.Point(240, ($pnlOpt.Height - 100))) `
    -Size (New-Object System.Drawing.Size(70, 26)) -BgColor $colors.Accent
$btnAddIp.Anchor = 'Bottom,Left'
$pnlOpt.Controls.Add($btnAddIp)

$btnAddBottom = New-StyledButton -Text "Add to Bottom" `
    -Location (New-Object System.Drawing.Point(318, ($pnlOpt.Height - 100))) `
    -Size (New-Object System.Drawing.Size(120, 26)) -BgColor $colors.AccentDim
$btnAddBottom.Anchor = 'Bottom,Left'
$pnlOpt.Controls.Add($btnAddBottom)

## APPLY + Reset buttons (bottom)
$btnApply = New-StyledButton -Text "APPLY  ->  COMMIT TO SCOPE" `
    -Location (New-Object System.Drawing.Point(12, ($pnlOpt.Height - 60))) `
    -Size (New-Object System.Drawing.Size(380, 38)) -BgColor $colors.Gold `
    -FgColor ([System.Drawing.Color]::Black) -Font $fonts.ButtonBig
$btnApply.Anchor = 'Bottom,Left'
$btnApply.Enabled = $false
$pnlOpt.Controls.Add($btnApply)

$btnReset = New-StyledButton -Text "Revert" `
    -Location (New-Object System.Drawing.Point(400, ($pnlOpt.Height - 60))) `
    -Size (New-Object System.Drawing.Size(115, 38)) -BgColor $colors.PanelLight
$btnReset.Anchor = 'Bottom,Left'
$btnReset.Enabled = $false
$pnlOpt.Controls.Add($btnReset)

## === RIGHT COLUMN: Activity log ===
$colRightX = $colMidX + $colMidW + 20
$pnlLog = New-Object System.Windows.Forms.Panel
$pnlLog.Location = New-Object System.Drawing.Point($colRightX, 5)
$pnlLog.Size = New-Object System.Drawing.Size(($winW - $colRightX - 15), ($main.Height - 15))
$pnlLog.BackColor = $colors.Panel
$pnlLog.Anchor = 'Top,Left,Right,Bottom'
$main.Controls.Add($pnlLog)

$lblLogHdr = New-StyledLabel -Text "ACTIVITY LOG" `
    -Location (New-Object System.Drawing.Point(12, 10)) `
    -Size (New-Object System.Drawing.Size(260, 18)) -Fg $colors.Gold -Font $fonts.Section
$pnlLog.Controls.Add($lblLogHdr)

$lblLogPath = New-StyledLabel -Text "Log: $global:LogFile" `
    -Location (New-Object System.Drawing.Point(12, 32)) `
    -Size (New-Object System.Drawing.Size(($pnlLog.Width - 24), 14)) -Fg $colors.TextDim -Font $fonts.Small
$lblLogPath.Anchor = 'Top,Left,Right'
$pnlLog.Controls.Add($lblLogPath)

$oLog = New-Object System.Windows.Forms.RichTextBox
$oLog.Location = New-Object System.Drawing.Point(12, 50)
$oLog.Size = New-Object System.Drawing.Size(($pnlLog.Width - 24), ($pnlLog.Height - 65))
$oLog.Anchor = 'Top,Left,Right,Bottom'
$oLog.ReadOnly = $true
$oLog.BackColor = $colors.OutputBg
$oLog.ForeColor = $colors.Console
$oLog.Font = $fonts.Console
$oLog.BorderStyle = 'None'
$pnlLog.Controls.Add($oLog)

function Log-Activity {
    param([string]$Message, [System.Drawing.Color]$Color = $colors.Console)
    $ts = (Get-Date).ToString("HH:mm:ss")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.SelectionColor = $colors.TextDim
    $oLog.AppendText("[$ts] ")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.SelectionColor = $Color
    $oLog.AppendText("$Message`r`n")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.ScrollToCaret()
    Write-JLog $Message
}
#endregion

#region === BULK APPLY STRIP (full-width footer) ===
## Sits between the main content panel and the status bar. Operates on the
## scopes whose checkbox is ticked in the left-column ListView, using the
## option ID currently selected in the middle column.
$bulkY = $f.ClientSize.Height - 24 - $bulkH
$pnlBulk = New-Object System.Windows.Forms.Panel
$pnlBulk.Location = New-Object System.Drawing.Point(0, $bulkY)
$pnlBulk.Size = New-Object System.Drawing.Size($winW, $bulkH)
$pnlBulk.BackColor = $colors.Panel
$pnlBulk.Anchor = 'Bottom,Left,Right'
$f.Controls.Add($pnlBulk)

## 2px gold accent line at the top of the strip - separates it visually
## from the activity log column above
$bulkTopLine = New-Object System.Windows.Forms.Panel
$bulkTopLine.Location = New-Object System.Drawing.Point(0, 0)
$bulkTopLine.Size = New-Object System.Drawing.Size($winW, 2)
$bulkTopLine.BackColor = $colors.GoldDim
$bulkTopLine.Anchor = 'Top,Left,Right'
$pnlBulk.Controls.Add($bulkTopLine)

$lblBulkHdr = New-StyledLabel -Text "BULK APPLY  ->  ALL CHECKED SCOPES" `
    -Location (New-Object System.Drawing.Point(15, 8)) `
    -Size (New-Object System.Drawing.Size(420, 18)) -Fg $colors.Gold -Font $fonts.Section
$pnlBulk.Controls.Add($lblBulkHdr)

$lblBulkSel = New-StyledLabel -Text "0 scopes checked" `
    -Location (New-Object System.Drawing.Point(440, 10)) `
    -Size (New-Object System.Drawing.Size(300, 16)) -Fg $colors.TextDim -Font $fonts.LabelBold
$pnlBulk.Controls.Add($lblBulkSel)

$lblBulkOpt = New-StyledLabel -Text "Option: (none)" `
    -Location (New-Object System.Drawing.Point(750, 10)) `
    -Size (New-Object System.Drawing.Size(300, 16)) -Fg $colors.TextDim -Font $fonts.LabelBold
$pnlBulk.Controls.Add($lblBulkOpt)

$lblBulkHint = New-StyledLabel -Text "One IPv4 per line. APPEND adds at the bottom of each scope's list (DR-DNS workflow). REMOVE deletes matching entries from each scope. Existing values are preserved." `
    -Location (New-Object System.Drawing.Point(15, 30)) `
    -Size (New-Object System.Drawing.Size(1100, 14)) -Fg $colors.TextSecondary -Font $fonts.Small
$pnlBulk.Controls.Add($lblBulkHint)

$txtBulkIps = New-StyledTextBox -Location (New-Object System.Drawing.Point(15, 50)) `
    -Size (New-Object System.Drawing.Size(820, 95))
$txtBulkIps.Multiline = $true
$txtBulkIps.ScrollBars = 'Vertical'
$txtBulkIps.WordWrap = $false
$pnlBulk.Controls.Add($txtBulkIps)

$btnBulkAppend = New-StyledButton -Text "APPEND TO BOTTOM (ALL CHECKED)" `
    -Location (New-Object System.Drawing.Point(850, 50)) `
    -Size (New-Object System.Drawing.Size(310, 28)) -BgColor $colors.Gold `
    -FgColor ([System.Drawing.Color]::Black) -Font $fonts.Button
$btnBulkAppend.Enabled = $false
$pnlBulk.Controls.Add($btnBulkAppend)

$btnBulkPrepend = New-StyledButton -Text "Prepend to top (all checked)" `
    -Location (New-Object System.Drawing.Point(850, 82)) `
    -Size (New-Object System.Drawing.Size(310, 28)) -BgColor $colors.Accent `
    -FgColor ([System.Drawing.Color]::White) -Font $fonts.Button
$btnBulkPrepend.Enabled = $false
$pnlBulk.Controls.Add($btnBulkPrepend)

$btnBulkRemove = New-StyledButton -Text "Remove from each (all checked)" `
    -Location (New-Object System.Drawing.Point(850, 114)) `
    -Size (New-Object System.Drawing.Size(310, 28)) -BgColor $colors.Danger `
    -FgColor ([System.Drawing.Color]::White) -Font $fonts.Button
$btnBulkRemove.Enabled = $false
$pnlBulk.Controls.Add($btnBulkRemove)

$btnBulkClearIps = New-StyledButton -Text "Clear" `
    -Location (New-Object System.Drawing.Point(1170, 50)) `
    -Size (New-Object System.Drawing.Size(80, 28)) -BgColor $colors.PanelLight -Font $fonts.Button
$pnlBulk.Controls.Add($btnBulkClearIps)

## Close Tool button moved to the header (top-right). Single egress
## matches the WPT pattern.

## Mark bulk strip controls as ready so Update-ScopeCountLabel can call
## Update-BulkButtons without NullRef during the earlier connect path.
$script:BulkBtnsReady = $true
#endregion

#region === STATUS BAR ===
$status = New-Object System.Windows.Forms.Panel
$status.Location = New-Object System.Drawing.Point(0, ($f.ClientSize.Height - 24))
$status.Size = New-Object System.Drawing.Size($winW, 24)
$status.BackColor = $colors.TopBar
$status.Anchor = 'Bottom,Left,Right'
$f.Controls.Add($status)

$lblStatus = New-StyledLabel -Text "Ready" `
    -Location (New-Object System.Drawing.Point(10, 4)) `
    -Size (New-Object System.Drawing.Size(800, 16)) -Fg $colors.TextSecondary -Font $fonts.Small
$status.Controls.Add($lblStatus)

$lblUser = New-StyledLabel -Text "User: $env:USERNAME    Host: $env:COMPUTERNAME" `
    -Location (New-Object System.Drawing.Point(900, 4)) `
    -Size (New-Object System.Drawing.Size(490, 16)) -Fg $colors.GoldDim -Font $fonts.Small
$lblUser.TextAlign = 'TopRight'
$lblUser.Anchor = 'Bottom,Right'
$status.Controls.Add($lblUser)
#endregion

#region === CORE LOGIC: Connect / Load Scopes / Load Option / Apply ===
function Get-SelectedOptionId {
    $sel = $cmbOption.SelectedIndex
    if ($sel -lt 0) { return $null }
    if ($sel -lt $script:CommonOptions.Count) {
        return [int]$script:CommonOptions[$sel].Id
    }
    return [int]$numOptionId.Value
}

function Set-EditorEnabled {
    param([bool]$Enabled)
    $btnLoadOpt.Enabled = $Enabled
    $cmbOption.Enabled  = $Enabled
    $numOptionId.Enabled = ($Enabled -and ($cmbOption.SelectedIndex -ge $script:CommonOptions.Count))
}

function Sync-WorkingToList {
    $lstValues.BeginUpdate()
    try {
        $lstValues.Items.Clear()
        for ($i = 0; $i -lt $script:WorkingValues.Count; $i++) {
            $val = $script:WorkingValues[$i]
            [void]$lstValues.Items.Add(("{0,2}.  {1}" -f ($i + 1), $val))
        }
    } finally { $lstValues.EndUpdate() }
    $btnApply.Enabled = ($script:CurrentScopeId -and -not (Compare-Lists $script:OriginalValues $script:WorkingValues -SameOrder))
    $btnReset.Enabled = $btnApply.Enabled
}

function Compare-Lists {
    param($A, $B, [switch]$SameOrder)
    if ($null -eq $A) { $A = @() }
    if ($null -eq $B) { $B = @() }
    $aArr = @($A); $bArr = @($B)
    if ($aArr.Count -ne $bArr.Count) { return $false }
    if ($SameOrder) {
        for ($i = 0; $i -lt $aArr.Count; $i++) { if ($aArr[$i] -ne $bArr[$i]) { return $false } }
        return $true
    }
    $aSorted = $aArr | Sort-Object
    $bSorted = $bArr | Sort-Object
    for ($i = 0; $i -lt $aSorted.Count; $i++) { if ($aSorted[$i] -ne $bSorted[$i]) { return $false } }
    return $true
}

function Test-Ipv4 {
    param([string]$Text)
    $ip = $null
    return [System.Net.IPAddress]::TryParse($Text.Trim(), [ref]$ip) -and $ip.AddressFamily -eq 'InterNetwork'
}

function Invoke-OnDhcp {
    param([scriptblock]$Script, [object[]]$Arguments = @())
    if (-not $script:DhcpServer) { throw "Not connected to a DHCP server." }
    if ($script:UseCurrentSession) {
        ## No -Credential -- WSMan picks up the current process's logged-in
        ## user via Kerberos (or NTLM fallback). This is the right path when
        ## the user is already in an elevated PowerShell session as their
        ## privileged ADM account, since passing -Credential would force a
        ## second-hop / re-auth that often fails with "username incorrect"
        ## even with valid credentials.
        Invoke-Command -ComputerName $script:DhcpServer `
                       -ScriptBlock $Script -ArgumentList $Arguments -ErrorAction Stop
    } else {
        if (-not $global:Cred) { throw "No credentials set. Click 'Set Credentials...' or check 'Use current session'." }
        Invoke-Command -ComputerName $script:DhcpServer -Credential $global:Cred -Authentication Default `
                       -ScriptBlock $Script -ArgumentList $Arguments -ErrorAction Stop
    }
}

$btnConnect.Add_Click({
    $srv = $txtServer.Text.Trim()
    if (-not $srv) {
        [System.Windows.Forms.MessageBox]::Show("Enter the DHCP server hostname or FQDN.", "Connect", 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $script:UseCurrentSession -and -not $global:Cred) {
        [System.Windows.Forms.MessageBox]::Show("Set credentials first, or check 'Use current session' to authenticate as the logged-in user.", "Connect", 'OK', 'Warning') | Out-Null
        return
    }
    $btnConnect.Enabled = $false
    $lblStatus.Text = "Connecting to $srv ..."
    $lblSrvStatus.Text = "Connecting ..."
    $lblSrvStatus.ForeColor = $colors.Warning
    $f.Refresh()
    try {
        $script:DhcpServer = $srv
        ## TCP reachability pre-check -- surfaces a specific "unreachable"
        ## error instead of the generic Invoke-Command remoting timeout.
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tcp.BeginConnect($srv, 5985, $null, $null)
            if (-not $iar.AsyncWaitHandle.WaitOne(3000, $false)) {
                throw "WSMan port 5985 on $srv did not respond within 3s."
            }
            $tcp.EndConnect($iar)
        } finally { $tcp.Close() }
        ## Probe: confirm DhcpServer module is present + we can list scopes
        $probe = Invoke-OnDhcp -Script {
            $mod = Get-Module -ListAvailable -Name DhcpServer | Select-Object -First 1
            if (-not $mod) { throw "DhcpServer PowerShell module is not installed on $env:COMPUTERNAME." }
            Import-Module DhcpServer -ErrorAction Stop
            ## Project ScopeId / SubnetMask to plain strings on the REMOTE
            ## side. If we ship the raw [ipaddress] objects back through
            ## PSRemoting, the local deserialized PSObject's [string] cast
            ## intermittently returns "" / "System.Net.IPAddress" / "0.0.0.0"
            ## on Server 2019 and Win10 PS5.1, which then trips
            ## Get-DhcpServerv4OptionValue's [ValidateNotNullOrEmpty()] on
            ## -ScopeId with "argument is null or empty". IPAddressToString
            ## is the canonical dotted-quad accessor and survives the wire.
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    ScopeId     = $_.ScopeId.IPAddressToString
                    SubnetMask  = $_.SubnetMask.IPAddressToString
                    Name        = [string]$_.Name
                    State       = [string]$_.State
                    Description = [string]$_.Description
                }
            }
            [pscustomobject]@{
                Host   = $env:COMPUTERNAME
                Module = $mod.Version.ToString()
                Scopes = @($scopes)
            }
        }
        $script:Scopes = @($probe.Scopes)
        $lvScopes.BeginUpdate()
        try {
            $lvScopes.Items.Clear()
            foreach ($sc in $script:Scopes) {
                $it = New-Object System.Windows.Forms.ListViewItem(([string]$sc.ScopeId))
                [void]$it.SubItems.Add([string]$sc.Name)
                [void]$it.SubItems.Add([string]$sc.State)
                $it.Tag = $sc
                if ("$($sc.State)" -ne "Active") { $it.ForeColor = $colors.TextDim }
                [void]$lvScopes.Items.Add($it)
            }
        } finally { $lvScopes.EndUpdate() }
        Update-ScopeCountLabel
        $lblScopeCount.ForeColor = $colors.Success
        $lblSrvStatus.Text = "Connected to $($probe.Host)  (DhcpServer v$($probe.Module))"
        $lblSrvStatus.ForeColor = $colors.Success
        $btnDisconnect.Enabled = $true
        Set-EditorEnabled $true
        Log-Activity "Connected to $srv -- $($script:Scopes.Count) scope(s) loaded." $colors.Success
        $lblStatus.Text = "Connected. Select a scope, then load an option."
    } catch {
        $script:DhcpServer = $null
        $lblSrvStatus.Text = "Connect failed: $($_.Exception.Message)"
        $lblSrvStatus.ForeColor = $colors.Danger
        Log-Activity "Connect failed: $($_.Exception.Message)" $colors.Danger
        $lblStatus.Text = "Connect failed."
    } finally {
        $btnConnect.Enabled = $true
    }
})

$btnDisconnect.Add_Click({
    $script:DhcpServer = $null
    $script:Scopes = @()
    $script:CurrentScopeId = $null
    $script:OriginalValues = @()
    $script:WorkingValues.Clear()
    $lvScopes.Items.Clear()
    $lstValues.Items.Clear()
    Update-ScopeCountLabel
    $lblScopeCount.ForeColor = $colors.TextSecondary
    $lblOptScope.Text = "No scope selected"
    $lblOptScope.ForeColor = $colors.TextDim
    $lblSrvStatus.Text = "Not connected"
    $lblSrvStatus.ForeColor = $colors.TextDim
    $btnDisconnect.Enabled = $false
    $btnApply.Enabled = $false
    $btnReset.Enabled = $false
    Set-EditorEnabled $false
    Log-Activity "Disconnected." $colors.TextDim
})

$cmbOption.Add_SelectedIndexChanged({
    $isCustom = ($cmbOption.SelectedIndex -ge $script:CommonOptions.Count)
    $numOptionId.Enabled = ($script:DhcpServer -and $isCustom)
    if (-not $isCustom -and $cmbOption.SelectedIndex -ge 0) {
        $numOptionId.Value = [int]$script:CommonOptions[$cmbOption.SelectedIndex].Id
    }
})

function Load-CurrentOption {
    [CmdletBinding()]
    param([switch]$Silent)
    if (-not $script:CurrentScopeId) {
        if (-not $Silent) {
            [System.Windows.Forms.MessageBox]::Show("Pick a scope from the left panel first.", "Load", 'OK', 'Warning') | Out-Null
        }
        return
    }
    $optId = Get-SelectedOptionId
    if (-not $optId) { return }
    $btnLoadOpt.Enabled = $false
    $lblStatus.Text = "Loading option $optId from scope $($script:CurrentScopeId) ..."
    $f.Refresh()
    try {
        $result = Invoke-OnDhcp -Script {
            param($scopeId, $optId)
            Import-Module DhcpServer -ErrorAction Stop
            ## Cast string -> [ipaddress] explicitly. Get-DhcpServerv4OptionValue
            ## binds ScopeId as IPAddress, and PowerShell parameter binding has
            ## been observed to choke on the cross-session string -> ipaddress
            ## coercion on some Server 2019 builds.
            $sid = [ipaddress]$scopeId
            ## Wrap in try/catch -- Get-DhcpServerv4OptionValue throws a
            ## terminating "value not found" error when the option has never
            ## been set on the scope, and -ErrorAction SilentlyContinue on
            ## remote cmdlets does not always swallow it across the PSSession
            ## boundary. We treat "not set" as empty list, not failure.
            try {
                $ov = Get-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
            } catch {
                return [pscustomobject]@{ Ok = $true; Values = @(); NotSet = $true; Err = $null }
            }
            $vals = @()
            if ($ov -and $ov.Value) {
                foreach ($v in @($ov.Value)) { $vals += [string]$v }
            }
            return [pscustomobject]@{ Ok = $true; Values = $vals; NotSet = $false; Err = $null }
        } -Arguments @($script:CurrentScopeId, $optId)

        $script:CurrentOptionId = $optId
        $script:OriginalValues = @($result.Values)
        $script:WorkingValues.Clear()
        foreach ($v in $script:OriginalValues) { [void]$script:WorkingValues.Add($v) }
        Sync-WorkingToList

        if ($result.NotSet) {
            Log-Activity "Option $optId on scope $($script:CurrentScopeId): not set (no values configured)." $colors.Warning
            $lblStatus.Text = "Option $optId not currently set on this scope."
        } elseif ($script:OriginalValues.Count -eq 0) {
            Log-Activity "Option $optId on scope $($script:CurrentScopeId): empty value list." $colors.Warning
            $lblStatus.Text = "Option $optId loaded (empty)."
        } else {
            Log-Activity "Loaded option $optId on scope $($script:CurrentScopeId): $($script:OriginalValues -join ', ')" $colors.Success
            $lblStatus.Text = "Option $optId loaded ($($script:OriginalValues.Count) value(s))."
        }
    } catch {
        Log-Activity "Load failed for option $optId on scope $($script:CurrentScopeId): $($_.Exception.Message)" $colors.Danger
        $lblStatus.Text = "Load failed -- see Activity Log."
    } finally {
        $btnLoadOpt.Enabled = $true
    }
}

## Suppress the auto-load when the selection change was triggered by a
## user clicking the checkbox column (ItemCheck fires before
## SelectedIndexChanged). Ticking a scope for bulk apply is not a
## request to fetch its current option values -- that would mean one
## WSMan round-trip per checked box.
$lvScopes.Add_ItemCheck({
    if (-not $script:DhcpServer) { return }
    $it = $lvScopes.Items[$_.Index]
    if ($null -ne $it -and -not $it.Selected) { $script:SuppressScopeLoad = $true }
})

$lvScopes.Add_SelectedIndexChanged({
    if ($lvScopes.SelectedItems.Count -eq 0) { return }
    $sc = $lvScopes.SelectedItems[0].Tag
    $script:CurrentScopeId = [string]$sc.ScopeId
    $lblOptScope.Text = "Scope: $($sc.ScopeId) / $($sc.SubnetMask)  --  $($sc.Name)  [$($sc.State)]"
    $lblOptScope.ForeColor = $colors.TextPrimary
    if ($script:SuppressScopeLoad) {
        $script:SuppressScopeLoad = $false
        return
    }
    Log-Activity "Scope selected: $($sc.ScopeId) ($($sc.Name))" $colors.Cyan
    ## Auto-load values for the currently selected option so the user sees
    ## what's there without an extra click. Silent so missing-scope path
    ## doesn't pop a dialog (we just selected one).
    Load-CurrentOption -Silent
})

$btnLoadOpt.Add_Click({ Load-CurrentOption })

## Reload values when the user switches the option selector to a different
## option (only if a scope is already selected -- otherwise wait for click).
$cmbOption.Add_SelectedIndexChanged({
    if ($script:CurrentScopeId) { Load-CurrentOption -Silent }
})
$numOptionId.Add_ValueChanged({
    if ($script:CurrentScopeId -and $cmbOption.SelectedIndex -ge $script:CommonOptions.Count) {
        Load-CurrentOption -Silent
    }
})

## ============================================================
## Bulk-select wiring -- All / None / Active / Invert + count
## ============================================================
function Update-ScopeCountLabel {
    $total = $lvScopes.Items.Count
    $checked = $lvScopes.CheckedItems.Count
    $word = if ($total -eq 1) { 'scope' } else { 'scopes' }
    $lblScopeCount.Text = "$total $word  |  $checked checked"
    $lblScopeCount.ForeColor = if ($checked -gt 0) { $colors.Gold } elseif ($total -gt 0) { $colors.Success } else { $colors.TextSecondary }
    if ($script:BulkBtnsReady) { Update-BulkButtons }
}

$lvScopes.Add_ItemChecked({ Update-ScopeCountLabel })

$btnSelAll.Add_Click({
    $lvScopes.BeginUpdate()
    try { foreach ($it in $lvScopes.Items) { $it.Checked = $true } }
    finally { $lvScopes.EndUpdate() }
})
$btnSelNone.Add_Click({
    $lvScopes.BeginUpdate()
    try { foreach ($it in $lvScopes.Items) { $it.Checked = $false } }
    finally { $lvScopes.EndUpdate() }
})
$btnSelActive.Add_Click({
    $lvScopes.BeginUpdate()
    try {
        foreach ($it in $lvScopes.Items) {
            $sc = $it.Tag
            $it.Checked = ("$($sc.State)" -eq "Active")
        }
    } finally { $lvScopes.EndUpdate() }
})
$btnSelInvert.Add_Click({
    $lvScopes.BeginUpdate()
    try { foreach ($it in $lvScopes.Items) { $it.Checked = -not $it.Checked } }
    finally { $lvScopes.EndUpdate() }
})

function Add-IpToWorking {
    param([string]$Ip, [switch]$ToBottom)
    if (-not (Test-Ipv4 $Ip)) {
        [System.Windows.Forms.MessageBox]::Show("'$Ip' is not a valid IPv4 address.", "Add IP", 'OK', 'Warning') | Out-Null
        return
    }
    $clean = ([System.Net.IPAddress]::Parse($Ip.Trim())).ToString()
    if ($script:WorkingValues -contains $clean) {
        Log-Activity "$clean already in list -- skipped." $colors.Warning
        return
    }
    if ($ToBottom -or $script:WorkingValues.Count -eq 0) {
        [void]$script:WorkingValues.Add($clean)
        $newIdx = $script:WorkingValues.Count - 1
    } else {
        $insertAt = if ($lstValues.SelectedIndex -ge 0) { $lstValues.SelectedIndex + 1 } else { $script:WorkingValues.Count }
        [void]$script:WorkingValues.Insert($insertAt, $clean)
        $newIdx = $insertAt
    }
    Sync-WorkingToList
    $lstValues.SelectedIndex = $newIdx
    Log-Activity "Added $clean (position $($newIdx + 1))." $colors.Accent
    $txtAddIp.Clear()
}

$btnAddIp.Add_Click({ Add-IpToWorking -Ip $txtAddIp.Text })
$btnAddBottom.Add_Click({ Add-IpToWorking -Ip $txtAddIp.Text -ToBottom })
$txtAddIp.Add_KeyDown({
    if ($_.KeyCode -eq 'Enter') {
        $_.SuppressKeyPress = $true
        Add-IpToWorking -Ip $txtAddIp.Text
    }
})

$btnRemove.Add_Click({
    $i = $lstValues.SelectedIndex
    if ($i -lt 0) { return }
    $val = $script:WorkingValues[$i]
    $script:WorkingValues.RemoveAt($i)
    Sync-WorkingToList
    if ($script:WorkingValues.Count -gt 0) {
        $lstValues.SelectedIndex = [Math]::Min($i, $script:WorkingValues.Count - 1)
    }
    Log-Activity "Removed $val." $colors.Warning
})

function Move-Working {
    param([int]$From, [int]$To)
    if ($From -lt 0 -or $From -ge $script:WorkingValues.Count) { return }
    $To = [Math]::Max(0, [Math]::Min($To, $script:WorkingValues.Count - 1))
    if ($From -eq $To) { return }
    $val = $script:WorkingValues[$From]
    $script:WorkingValues.RemoveAt($From)
    [void]$script:WorkingValues.Insert($To, $val)
    Sync-WorkingToList
    $lstValues.SelectedIndex = $To
    Log-Activity "Moved $val to position $($To + 1)." $colors.Cyan
}

$btnUp.Add_Click({     Move-Working -From $lstValues.SelectedIndex -To ($lstValues.SelectedIndex - 1) })
$btnDown.Add_Click({   Move-Working -From $lstValues.SelectedIndex -To ($lstValues.SelectedIndex + 1) })
$btnTop.Add_Click({    Move-Working -From $lstValues.SelectedIndex -To 0 })
$btnBottom.Add_Click({ Move-Working -From $lstValues.SelectedIndex -To ($script:WorkingValues.Count - 1) })

$btnReset.Add_Click({
    $script:WorkingValues.Clear()
    foreach ($v in $script:OriginalValues) { [void]$script:WorkingValues.Add($v) }
    Sync-WorkingToList
    Log-Activity "Working list reverted to last-loaded values." $colors.TextDim
})

$btnApply.Add_Click({
    if (-not $script:CurrentScopeId) { return }
    $optId = $script:CurrentOptionId
    $orig  = @($script:OriginalValues)
    $new   = @($script:WorkingValues.ToArray() | ForEach-Object { [string]$_ })

    $added    = @($new | Where-Object { $orig -notcontains $_ })
    $removed  = @($orig | Where-Object { $new -notcontains $_ })
    $reordered = (Compare-Lists $orig $new) -and -not (Compare-Lists $orig $new -SameOrder)

    $diff = @()
    if ($added.Count)   { $diff += "ADD:`r`n  + " + ($added -join "`r`n  + ") }
    if ($removed.Count) { $diff += "REMOVE:`r`n  - " + ($removed -join "`r`n  - ") }
    if ($reordered)     { $diff += "REORDER ONLY (same set, new order)" }
    if (-not $diff)     { $diff += "(no changes)" }
    $newOrderText = "NEW ORDER (top -> bottom):`r`n  " + (($new | ForEach-Object { ("{0,2}. {1}" -f ([Array]::IndexOf($new, $_) + 1), $_) }) -join "`r`n  ")

    $msg = @(
        "Server:  $($script:DhcpServer)"
        "Scope:   $($script:CurrentScopeId)"
        "Option:  $optId"
        ""
        ($diff -join "`r`n`r`n")
        ""
        $newOrderText
        ""
        "Apply this change to the live DHCP scope?"
    ) -join "`r`n"

    $resp = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm APPLY", 'YesNo', 'Question')
    if ($resp -ne 'Yes') {
        Log-Activity "APPLY cancelled by user." $colors.Warning
        return
    }

    $btnApply.Enabled = $false
    $lblStatus.Text = "Applying option $optId to scope $($script:CurrentScopeId) ..."
    $f.Refresh()
    try {
        if ([string]::IsNullOrWhiteSpace($script:CurrentScopeId)) {
            throw "Internal: CurrentScopeId is empty -- reselect a scope and try again."
        }
        if ($new.Count -eq 0) {
            Invoke-OnDhcp -Script {
                param($scopeId, $optId)
                Import-Module DhcpServer -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($scopeId)) { throw "ScopeId arrived empty over WSMan." }
                ## Same [ipaddress] cast used in Load/Bulk paths -- avoids the
                ## "argument is null or empty" parameter-binding error that
                ## Server 2019 throws when handed a raw string for -ScopeId.
                $sid = [ipaddress]$scopeId
                Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
            } -Arguments @($script:CurrentScopeId, $optId) | Out-Null
            Log-Activity "Option $optId removed from scope $($script:CurrentScopeId)." $colors.Success
        } else {
            Invoke-OnDhcp -Script {
                param($scopeId, $optId, $values)
                Import-Module DhcpServer -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($scopeId)) { throw "ScopeId arrived empty over WSMan." }
                $sid = [ipaddress]$scopeId
                Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -Value $values -Force -ErrorAction Stop
            } -Arguments @($script:CurrentScopeId, $optId, $new) | Out-Null
            Log-Activity "APPLY OK: option $optId on scope $($script:CurrentScopeId) -> $($new -join ', ')" $colors.Success
        }
        ## JANET central log: each successful Apply touches one host (the DHCP
        ## server) and changes its config state. Use the server name as the
        ## Target and stuff the scope/option into Detail so the dashboard can
        ## see what was changed without us inventing a third action bucket.
        try {
            Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Success `
                -ItemCount 1 -Detail ("scope=$($script:CurrentScopeId) opt=$optId values=" + ($new -join ';'))
        } catch {}
        $script:OriginalValues = $new
        Sync-WorkingToList
        $lblStatus.Text = "Apply succeeded."
    } catch {
        $msg = $_.Exception.Message
        $hint = ""
        ## WSMan returns "username or password is incorrect" for several
        ## conditions besides a bad password -- spell them out so the user
        ## doesn't keep retyping a credential that's not the actual problem.
        if ($msg -match 'username or password|access is denied|authentication') {
            $hint = "`r`n`r`nThis is a WSMan auth rejection. Common causes when Connect succeeded but Apply fails:`r`n" +
                    "  - Account has DHCP read but not write (not in 'DHCP Administrators' on $($script:DhcpServer))`r`n" +
                    "  - Stale credential inherited from the JANET launcher (click 'Set Credentials...' to refresh)`r`n" +
                    "  - 'Use current session' was toggled off between Connect and Apply -- creds are now different`r`n" +
                    "  - Username missing domain prefix (try DOMAIN\user or user@domain.com)`r`n" +
                    "  - Account locked out by repeated bad attempts (check AD)"
        }
        Log-Activity "APPLY FAILED: $msg" $colors.Danger
        if ($hint) { Log-Activity ($hint -replace "`r`n", " | ") $colors.Warning }
        try {
            Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Failure `
                -Detail ("scope=$($script:CurrentScopeId) opt=$optId err=$msg")
        } catch {}
        $lblStatus.Text = "Apply failed."
        [System.Windows.Forms.MessageBox]::Show("APPLY failed:`r`n$msg$hint", "Apply", 'OK', 'Error') | Out-Null
    } finally {
        $btnApply.Enabled = -not (Compare-Lists $script:OriginalValues $script:WorkingValues -SameOrder)
        $btnReset.Enabled = $btnApply.Enabled
    }
})
#endregion

#region === BULK APPLY LOGIC ===
function Update-BulkButtons {
    $checkedCount = $lvScopes.CheckedItems.Count
    $hasIps = -not [string]::IsNullOrWhiteSpace($txtBulkIps.Text)
    $optId = Get-SelectedOptionId
    $can = ($script:DhcpServer -and $checkedCount -gt 0 -and $hasIps -and $optId)
    $btnBulkAppend.Enabled  = $can
    $btnBulkPrepend.Enabled = $can
    $btnBulkRemove.Enabled  = $can
    $word = if ($checkedCount -eq 1) { 'scope' } else { 'scopes' }
    $lblBulkSel.Text = "$checkedCount $word checked"
    $lblBulkSel.ForeColor = if ($checkedCount -gt 0) { $colors.Gold } else { $colors.TextDim }
    if ($optId) {
        $lblBulkOpt.Text = "Option: $optId"
        $lblBulkOpt.ForeColor = $colors.Cyan
    } else {
        $lblBulkOpt.Text = "Option: (none)"
        $lblBulkOpt.ForeColor = $colors.TextDim
    }
}

$txtBulkIps.Add_TextChanged({ Update-BulkButtons })
$btnBulkClearIps.Add_Click({ $txtBulkIps.Clear() })

function Get-BulkIps {
    ## Parse multi-line / comma / whitespace separated IPs from the bulk
    ## textbox. Returns @{ Valid = @(); Invalid = @() }.
    $raw = $txtBulkIps.Text
    $valid = New-Object System.Collections.Generic.List[string]
    $invalid = New-Object System.Collections.Generic.List[string]
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($tok in ($raw -split "[,;\s\r\n]+")) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if (Test-Ipv4 $t) {
            $clean = ([System.Net.IPAddress]::Parse($t)).ToString()
            if ($seen.Add($clean)) { [void]$valid.Add($clean) }
        } else {
            [void]$invalid.Add($t)
        }
    }
    return @{ Valid = @($valid); Invalid = @($invalid) }
}

function Invoke-BulkApply {
    [CmdletBinding()]
    param([ValidateSet('Append','Prepend','Remove')][string]$Mode)

    if (-not $script:DhcpServer) {
        [System.Windows.Forms.MessageBox]::Show("Connect to a DHCP server first.", "Bulk Apply", 'OK', 'Warning') | Out-Null; return
    }
    $checkedItems = @($lvScopes.CheckedItems)
    if ($checkedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Check at least one scope in the left panel.", "Bulk Apply", 'OK', 'Warning') | Out-Null; return
    }
    $parsed = Get-BulkIps
    if ($parsed.Valid.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Enter at least one valid IPv4 address in the IP textbox.", "Bulk Apply", 'OK', 'Warning') | Out-Null; return
    }
    if ($parsed.Invalid.Count -gt 0) {
        $resp = [System.Windows.Forms.MessageBox]::Show(
            ("These tokens are not valid IPv4 addresses and will be ignored:`r`n  " + ($parsed.Invalid -join "`r`n  ") + "`r`n`r`nContinue with the valid ones?"),
            "Bulk Apply", 'YesNo', 'Warning')
        if ($resp -ne 'Yes') { return }
    }

    $optId = Get-SelectedOptionId
    if (-not $optId) {
        [System.Windows.Forms.MessageBox]::Show("Select an option ID first (middle column).", "Bulk Apply", 'OK', 'Warning') | Out-Null; return
    }

    $scopeIds = @($checkedItems | ForEach-Object { [string]$_.Tag.ScopeId })
    $ips = $parsed.Valid

    $modeLabel = switch ($Mode) {
        'Append'  { "APPEND to bottom of each scope's option $optId list" }
        'Prepend' { "PREPEND to top of each scope's option $optId list" }
        'Remove'  { "REMOVE these IPs from each scope's option $optId list (if present)" }
    }
    $confirm = @(
        "Server:  $($script:DhcpServer)"
        "Option:  $optId"
        "Action:  $modeLabel"
        "Scopes:  $($scopeIds.Count)"
        ("  " + ($scopeIds -join "`r`n  "))
        ""
        "IPs ($($ips.Count)):"
        ("  " + ($ips -join "`r`n  "))
        ""
        "Proceed?"
    ) -join "`r`n"
    $resp = [System.Windows.Forms.MessageBox]::Show($confirm, "Confirm BULK $($Mode.ToUpper())", 'YesNo', 'Question')
    if ($resp -ne 'Yes') { Log-Activity "Bulk $Mode cancelled by user." $colors.Warning; return }

    $btnBulkAppend.Enabled = $false; $btnBulkPrepend.Enabled = $false; $btnBulkRemove.Enabled = $false
    $lblStatus.Text = "Bulk $Mode running on $($scopeIds.Count) scope(s) ..."
    Log-Activity "BULK $($Mode.ToUpper()) starting -- option $optId, $($scopeIds.Count) scope(s), IPs: $($ips -join ', ')" $colors.Gold
    $f.Refresh()

    try {
        $results = Invoke-OnDhcp -Script {
            param($scopeIds, $optId, $ips, $mode)
            Import-Module DhcpServer -ErrorAction Stop
            $out = New-Object System.Collections.ArrayList
            foreach ($sidStr in $scopeIds) {
                $rec = [pscustomobject]@{
                    ScopeId = $sidStr; Status = ''; Before = @(); After = @(); Error = $null
                }
                try {
                    $sid = [ipaddress]$sidStr
                    $existing = @()
                    try {
                        $ov = Get-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
                        if ($ov -and $ov.Value) { $existing = @($ov.Value | ForEach-Object { [string]$_ }) }
                    } catch { $existing = @() }
                    $rec.Before = $existing

                    switch ($mode) {
                        'Append'  { $newList = @($existing) + @($ips | Where-Object { $existing -notcontains $_ }) }
                        'Prepend' { $newList = @($ips | Where-Object { $existing -notcontains $_ }) + @($existing) }
                        'Remove'  { $newList = @($existing | Where-Object { $ips -notcontains $_ }) }
                    }
                    $newList = @($newList)
                    $rec.After = $newList

                    ## Same-order equality test
                    $same = $true
                    if ($existing.Count -ne $newList.Count) { $same = $false }
                    else {
                        for ($i = 0; $i -lt $existing.Count; $i++) {
                            if ($existing[$i] -ne $newList[$i]) { $same = $false; break }
                        }
                    }

                    if ($same) {
                        $rec.Status = 'NoChange'
                    } elseif ($newList.Count -eq 0) {
                        Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
                        $rec.Status = 'Removed'
                    } else {
                        Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -Value $newList -Force -ErrorAction Stop
                        $rec.Status = 'Changed'
                    }
                } catch {
                    $rec.Status = 'Error'; $rec.Error = $_.Exception.Message
                }
                [void]$out.Add($rec)
            }
            return ,$out.ToArray()
        } -Arguments @($scopeIds, $optId, $ips, $Mode)

        $changed = @($results | Where-Object Status -in 'Changed','Removed').Count
        $nochg   = @($results | Where-Object Status -eq 'NoChange').Count
        $errs    = @($results | Where-Object Status -eq 'Error')

        foreach ($r in $results) {
            switch ($r.Status) {
                'Changed'  { Log-Activity "  [$($r.ScopeId)] $($r.Before.Count) -> $($r.After.Count) value(s): $($r.After -join ', ')" $colors.Success }
                'Removed'  { Log-Activity "  [$($r.ScopeId)] option $optId removed (list now empty)." $colors.Success }
                'NoChange' { Log-Activity "  [$($r.ScopeId)] no change (already in desired state)." $colors.TextDim }
                'Error'    { Log-Activity "  [$($r.ScopeId)] ERROR: $($r.Error)" $colors.Danger }
            }
            ## JANET central log: per-scope rollup. NoChange still counts as a
            ## TouchHost (we did reach the box), Changed/Removed are state
            ## changes (VulnPatched), Error is a Failure.
            try {
                switch ($r.Status) {
                    'Changed'  { Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Success -ItemCount 1 -Detail ("bulk-$Mode scope=$($r.ScopeId) opt=$optId") }
                    'Removed'  { Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Success -ItemCount 1 -Detail ("bulk-$Mode scope=$($r.ScopeId) opt=$optId removed") }
                    'NoChange' { Write-JanetAction -Action 'TouchHost'   -Target $script:DhcpServer -Result Skipped -Detail ("bulk-$Mode scope=$($r.ScopeId) opt=$optId no-change") }
                    'Error'    { Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Failure -Detail ("bulk-$Mode scope=$($r.ScopeId) opt=$optId err=$($r.Error)") }
                }
            } catch {}
        }

        $summary = "BULK $($Mode.ToUpper()) complete: $changed changed, $nochg unchanged, $($errs.Count) error(s)."
        Log-Activity $summary $(if ($errs.Count) { $colors.Warning } else { $colors.Success })
        $lblStatus.Text = $summary

        ## If the currently-edited single scope is in the checked set, refresh
        ## its in-memory values so the middle-column list reflects the new
        ## server-side state.
        if ($script:CurrentScopeId -and ($scopeIds -contains $script:CurrentScopeId) -and ($script:CurrentOptionId -eq $optId)) {
            Load-CurrentOption -Silent
        }
    } catch {
        $msg = $_.Exception.Message
        $hint = ""
        if ($msg -match 'username or password|access is denied|authentication') {
            $hint = "`r`n`r`nWSMan auth rejection. Same diagnostics as single-scope Apply:`r`n" +
                    "  - Account in 'DHCP Users' but not 'DHCP Administrators' on $($script:DhcpServer)`r`n" +
                    "  - Stale launcher credential (click 'Set Credentials...' to refresh)`r`n" +
                    "  - Auth mode toggled between Connect and now`r`n" +
                    "  - Missing domain prefix on username`r`n" +
                    "  - Account locked out"
        }
        Log-Activity "BULK $($Mode.ToUpper()) FAILED at the session level: $msg" $colors.Danger
        if ($hint) { Log-Activity ($hint -replace "`r`n", " | ") $colors.Warning }
        try { Write-JanetAction -Action 'VulnPatched' -Target $script:DhcpServer -Result Failure -Detail ("bulk-$Mode session-level err=$msg") } catch {}
        $lblStatus.Text = "Bulk $Mode failed."
        [System.Windows.Forms.MessageBox]::Show("Bulk $Mode failed:`r`n$msg$hint", "Bulk Apply", 'OK', 'Error') | Out-Null
    } finally {
        Update-BulkButtons
    }
}

$btnBulkAppend.Add_Click({  Invoke-BulkApply -Mode 'Append'  })
$btnBulkPrepend.Add_Click({ Invoke-BulkApply -Mode 'Prepend' })
$btnBulkRemove.Add_Click({  Invoke-BulkApply -Mode 'Remove'  })

## Keep the bulk action buttons in sync with the option ID changes too.
## (lvScopes.ItemChecked is already wired earlier and routes through
## Update-ScopeCountLabel -> Update-BulkButtons, so don't double-wire it.)
$cmbOption.Add_SelectedIndexChanged({ Update-BulkButtons })
$numOptionId.Add_ValueChanged({ Update-BulkButtons })
#endregion

#region === FORM SHOWN ===
$f.Add_Shown({
    Log-Activity "J.A.N.E.T. DHCP Scope Option Tool v$JanetDHCP_ScopeVersion initialized." $colors.Accent
    if ($global:Cred) { Log-Activity "Inherited credentials: $($global:Cred.UserName)" $colors.Success }
    else              { Log-Activity "No credentials -- 'Set Credentials...' or check 'Use current session' before connecting." $colors.Warning }
    Log-Activity "Tip: if -Credential keeps rejecting your ADM account, tick 'Use current session' to drop -Credential and auth as $env:USERDOMAIN\$env:USERNAME." $colors.TextDim
    Log-Activity "Single-scope edit: click a scope row -> values auto-load -> reorder -> APPLY." $colors.TextDim
    Log-Activity "Bulk edit: check scopes -> type IPs in footer -> APPEND / PREPEND / REMOVE." $colors.TextDim
    Update-BulkButtons
    $f.Activate()
})

## JANET centralized session (added in v1.1.1). Apply / Bulk Apply call
## Write-JanetAction per scope so the monthly rollup reflects real changes
## (HostsTouched = unique DHCP servers, VulnsPatched = per-scope mutations).
try { Start-JanetSession -Tool 'DHCP_Scope' -Version $JanetDHCP_ScopeVersion } catch {}

Set-JanetAllowClose $false
$f.Add_FormClosing({
    param($sender, $e)

    ## X-block: only the Close Tool button is allowed to actually close
    ## the form. Any other origin (X chrome button, Alt-F4, right-click
    ## title-bar Close) hits the FormClosing pipeline and gets cancelled
    ## here. WindowsShutDown is excepted — let the OS shut down cleanly
    ## instead of forcing the operator through the nag-prompt loop.
    if (-not (Get-JanetAllowClose) -and $e.CloseReason -ne [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        $e.Cancel = $true
        return
    }
}.GetNewClosure())

[void]$f.ShowDialog()
try { Stop-JanetSession } catch {}
#endregion