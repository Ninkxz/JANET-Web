<# 
.NAME
    ADSearchTool
.SYNOPSIS
    J.A.N.E.T. Active Directory Search Tool
.DESCRIPTION
    Active Directory Objects Search Tool without need for RSAT.
    Multithreaded via PowerShell Runspaces to prevent UI freezing.
    Search by User, Computer, Group, Org Box, Email, Manager, Bulk Computer
    Lookup, Base Users Export, or Last PC (DC Security-log scan).
    J.A.N.E.T. dark/gold theme.
.AUTHOR
    Created by: NGUYEN, HAI
    Edited by:  THOMPSON, BRAXTON - 48 CS
.VERSION
    3.3.3
.CHANGELOG
    v3.3.3 - 2026-06-06 - Fix: restore LDAP escaping in the search engine. v3.3.2
            moved Escape-LdapFilterValue to host script scope (just past the JANET
            END marker), but the search runs in a bare child runspace that cannot
            see host-scope functions, so every mode that called it (Computer,
            Group, Org Box, Email, Manager, Bulk Computer, Base Users) threw
            CommandNotFoundException — only User and Last PC still worked. The
            helper is now defined inline inside the search scriptblock so it
            resolves in the runspace, and the User mode (previously unescaped)
            now escapes givenName/sn/samaccountname too. Also fixed Base Users
            double-click/detail resolving the wrong account: the ListView is
            built from a re-sorted copy but row lookups read $script:cachedResults
            by position — the cache now holds the displayed (sorted) order.
    v3.3.2 - 2026-05-10 - Hygiene pass: (1) display version $script:VersionNumber
            aligned to 3.3.2 (was stuck on "3.3"); (2) Escape-LdapFilterValue
            extracted from inside the JANET LOGGING BLOCK so the canonical
            JANET region stays drop-in replaceable across tools — function
            now lives just past the END marker; (3) JANET replay filter
            widened to *_detail*.csv / *_usage*.csv so schema-rotation
            sister files are drained instead of stranded.
    v3.3.1 - 2026-05-08 - LDAP filter escape (RFC 4515) via Escape-LdapFilterValue:
            user-supplied search terms baked into "(attr=$value)" filters
            are now backslash-escaped on \, *, (, ), NUL so a value with
            parentheses or wildcards can no longer alter the filter shape.
            Plus JANET centralized-logging schema cleanup (single SessionEnd
            rollup row; Snapshot rows retired) and the WPT-themed Closing
            Notes prompt rolled across the suite.
    v3.3.0 - 2026-05-06 - Added "BY LAST PC" search mode. Given a name or
            EDIPI, scans every domain controller's Security log for
            Kerberos / logon events (4624, 4768, 4769, 4776) tagged with
            the user's sAMAccountName. Server-side XPath filter narrows
            the result set; PowerShell post-filters for exact SAM match
            or "<sam>@realm". Source IPs are reverse-resolved to host
            names; one row per (user x distinct PC), most-recent first.
            Default window is 14 days, configurable via the new
            "Days Back" input (1-90). Skips DCs that don't answer on
            TCP/135. Requires Security-log read access on the DCs;
            graceful error message when access is denied.
    v3.2.1 - 2026-04-25 - Added JANET centralized logging. Each launch now writes
            one row to \\dm-tn-01\sh-usafe-automation$\JANET\Logs\<YYYY-MM>_usage.csv
            (read-only tool — silent rollup, no closing-notes dialog).
            Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
    v3.1 - April 2026 - Purple + Gold on Black restyle under the J.A.N.E.T.
           tool suite. Unifies with the Workstation Patching Tool v48 and
           the Remote Message Tool v1.1 so the whole suite reads as one
           environment. No logic / search / async / export changes - pure
           visual layer.
         - Dark #0A0B0E surfaces, purple #8C64DC accent, gold #DAB452
           highlights, green success, operational red, icy info blue.
           All old $clr* names preserved as aliases so downstream code
           resolves.
         - Cascadia Mono (display / mono / buttons / eyebrows) + Segoe UI
           Variable Display (body copy) typography.
         - 4 L-shaped corner-bracket "brief box" cards around every panel
           instead of full rectangular borders. Each card carries an
           eyebrow "/ HEADER" with a dotted amber underline.
         - Scanline overlay on the header strip and the custom status bar.
         - Diagonal yellow/black caution stripe (HatchBrush) along the
           bottom of the primary SEARCH CTA.
         - Blinking pulse dots: an olive one in the status strip that
           animates at 720ms when a search is running and turns red on
           error; a second pulse dot in the header that turns olive when
           a launcher credential was inherited via $env:JANET_CRED_FILE.
         - Dark DWM title bar + rounded corners on Win11 for the main
           window and the object-detail popup.
         - Results list and Extended Info now live inside their own
           bracket cards; Update-SearchFieldVisibility moves the cards
           instead of the raw controls.
         - Ghost outline secondary buttons (SAVE / CLEAR / ABOUT /
           IMPORT TXT / CLEAR LIST), amber stripe CTA for SEARCH and
           EXPORT CSV, monospace radio labels in uppercase.
    v3.0 - J.A.N.E.T. theme overhaul (Thompson)
         - Added Bulk Computer Lookup (paste or import TXT, 200+ machines)
         - Location field parsing for Organization/Squadron identification
         - Batched LDAP queries for performance
         - CSV export for bulk results
         - Color-coded status (Active/Stale/Not Found)
    v2.2 - Added Search by Email and Search by Manager (Nguyen)
    v2.1 - Added multithreading via Runspaces (Nguyen)
    v2.0 - Added popup window on double-click (Nguyen)
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v3.2.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\AD_Search\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetAD_SearchVersion = '3.3.3'

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


# RFC 4515 LDAP filter escape — tool-specific helper, NOT part of the canonical
# JANET logging block. Extracted from inside the block in v3.3.2 so the JANET
# region stays drop-in replaceable across tools.
# Use this on every user-supplied or AD-derived string that gets baked into a
# "(attr=$value)" filter via string interpolation.
function Escape-LdapFilterValue {
    # Order matters: backslash must be escaped first so we don't double-escape
    # the backslashes we introduce for the others. NUL is escaped because
    # some directory implementations terminate-on-NUL otherwise.
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $r = $Value -replace '\\', '\5c'
    $r = $r     -replace '\*', '\2a'
    $r = $r     -replace '\(', '\28'
    $r = $r     -replace '\)', '\29'
    $r = $r     -replace "`0", '\00'
    return $r
}


# -- Hide Console --
Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
function Hide-Console {
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [void][Console.Window]::ShowWindow($consolePtr, 0)
}
Hide-Console

# ==========================================================================
#  GLOBALS
# ==========================================================================
$script:VersionNumber = "3.3.3"
$script:cachedResults = $null
$script:currentRunspace    = $null
$script:currentPowerShell  = $null
$script:currentAsyncResult = $null
$script:currentSearchType  = $null

# v3.1 - Inherit shared credential from the J.A.N.E.T. launcher if
# present. AD queries in this tool currently use the caller's token
# (no -Credential on ADSI searcher), so this slot is a passthrough for
# a future search-as-another-user mode. JANET.ps1 writes a DPAPI-
# encrypted CliXml file and exposes the path via $env:JANET_CRED_FILE.
$script:InheritedCred = $null
if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $ic = Import-Clixml -Path $env:JANET_CRED_FILE -ErrorAction Stop
        if ($ic -is [System.Management.Automation.PSCredential]) {
            $script:InheritedCred = $ic
        }
    } catch { <# fall back to current user #> }
}

if ($PSScriptRoot -and $PSScriptRoot -ne "") {
    $script:ScriptDir = $PSScriptRoot
} else {
    $script:ScriptDir = (Get-Location).Path
}

# ==========================================================================
#  THEME - Purple + Gold on Black
#  Mirrors JANET.ps1 + WPT. Old $clr* names are preserved as aliases so
#  the rest of the file resolves unchanged.
# ==========================================================================

# Surfaces (black with faint violet lean)
$cBg            = [System.Drawing.Color]::FromArgb(  8,   8,  12)
$cHeaderBg      = [System.Drawing.Color]::FromArgb(  6,   6,  10)   # title bar
$cPanel         = [System.Drawing.Color]::FromArgb( 16,  16,  22)   # Surface
$cPanelAlt      = [System.Drawing.Color]::FromArgb( 22,  22,  30)   # SurfaceAlt
$cInputBg       = [System.Drawing.Color]::FromArgb( 22,  22,  30)
$cConsoleBg     = [System.Drawing.Color]::FromArgb(  6,   6,  10)   # output / list
$cRowHover      = [System.Drawing.Color]::FromArgb( 30,  28,  40)
$cRowActive     = [System.Drawing.Color]::FromArgb( 40,  36,  54)

# Purple - primary accent
$cAccent        = [System.Drawing.Color]::FromArgb(140, 100, 220)   # #8C64DC purple
$cAccentHov     = [System.Drawing.Color]::FromArgb(164, 128, 240)
$cAccentDim     = [System.Drawing.Color]::FromArgb( 96,  68, 156)
$cAccentGlow    = [System.Drawing.Color]::FromArgb( 28,  20,  48)

# Status
$cGreen         = [System.Drawing.Color]::FromArgb( 92, 198, 120)   # success
$cGreenDim      = [System.Drawing.Color]::FromArgb( 60, 130,  78)
$cRed           = [System.Drawing.Color]::FromArgb(224,  80,  90)   # danger
$cOrange        = [System.Drawing.Color]::FromArgb(230, 180,  70)   # warning
$cInfo          = [System.Drawing.Color]::FromArgb( 88, 180, 210)   # info blue

# Text hierarchy (lavender-tinted whites)
$cText          = [System.Drawing.Color]::FromArgb(240, 240, 245)
$cTextDim       = [System.Drawing.Color]::FromArgb(170, 168, 180)
$cTextMuted     = [System.Drawing.Color]::FromArgb(110, 106, 125)
$cTextFaint     = [System.Drawing.Color]::FromArgb( 60,  56,  74)
$cTextOnAccent  = [System.Drawing.Color]::FromArgb(255, 255, 255)
$cBorder        = [System.Drawing.Color]::FromArgb( 38,  34,  52)
$cBorderStrong  = [System.Drawing.Color]::FromArgb( 52,  46,  72)

# Stripe (diagonal hatch on primary CTA)
$cStripeAmb     = [System.Drawing.Color]::FromArgb(140, 100, 220)   # purple stripe
$cStripeBlk     = [System.Drawing.Color]::FromArgb(  8,   8,  12)

# Legacy aliases - keep $clr* names so downstream references resolve
$clrFormBg      = $cBg
$clrHeaderBg    = $cHeaderBg
$clrPanelBg     = $cPanel
$clrInputBg     = $cInputBg
$clrInputText   = $cText
$clrGold        = $cAccent
$clrGoldDim     = $cAccentDim
$clrWhite       = $cText
$clrLightGray   = $cTextDim
$clrDimGray     = $cTextMuted
$clrBtnBg       = $cPanel
$clrBtnBorder   = $cBorderStrong
$clrListBg      = $cConsoleBg
$clrListSel     = $cRowHover
$clrWarning     = $cOrange
$clrError       = $cRed
$clrSuccess     = $cGreen

# Typography - Cascadia Mono display + Segoe UI Variable Display body
$_monoFace      = 'Cascadia Mono'
$_bodyFace      = 'Segoe UI Variable Display'
$fDisplayLg     = New-Object System.Drawing.Font($_monoFace, 14, [System.Drawing.FontStyle]::Bold)
$fDisplayMd     = New-Object System.Drawing.Font($_monoFace, 11, [System.Drawing.FontStyle]::Bold)
$fDisplaySm     = New-Object System.Drawing.Font($_monoFace, 10, [System.Drawing.FontStyle]::Bold)
$fEyebrow       = New-Object System.Drawing.Font($_monoFace,  9, [System.Drawing.FontStyle]::Bold)
$fEyebrowSm     = New-Object System.Drawing.Font($_monoFace,  8, [System.Drawing.FontStyle]::Bold)
$fMono          = New-Object System.Drawing.Font($_monoFace, 10)
$fMonoSm        = New-Object System.Drawing.Font($_monoFace,  9)
$fMonoTiny      = New-Object System.Drawing.Font($_monoFace,  8)
$fBody          = New-Object System.Drawing.Font($_bodyFace, 10)
$fBodyBold      = New-Object System.Drawing.Font($_bodyFace, 10, [System.Drawing.FontStyle]::Bold)
$fBodySm        = New-Object System.Drawing.Font($_bodyFace,  9)

# Legacy aliases - preserve $fnt* names
$fntTitle       = $fDisplayLg
$fntSubtitle    = $fMonoTiny
$fntLabel       = $fBody
$fntLabelBold   = $fEyebrow
$fntInput       = $fMono
$fntButton      = $fEyebrow
$fntRadio       = $fMonoSm
$fntResults     = $fMonoSm
$fntStatus      = $fMonoTiny
$fntBulk        = $fMonoSm

# ==========================================================================
#  UI HELPERS - mirror WPT / JANET / RemoteMessageTool helpers inline
# ==========================================================================

function Enable-DoubleBuffer {
    # DoubleBuffered is a protected property - reach it via reflection so
    # Paint handlers on panels don't flicker on resize.
    param($Control)
    try {
        $prop = $Control.GetType().GetProperty('DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic')
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function Set-JanetDarkTitleBar {
    # Win11 dark immersive title bar + rounded corners via DwmSetWindowAttribute.
    # No-ops silently on pre-21H2.
    param($Form)
    if (-not ('AdSearch.Dwm' -as [type])) {
        Add-Type -Namespace 'AdSearch' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }
    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }
    $enable = 1
    $null = [AdSearch.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [AdSearch.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)
    $round = 2
    $null = [AdSearch.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

function Add-CornerBrackets {
    # Paint 4 L-shaped amber corner brackets around a panel instead of a
    # full border - the signature WPT "brief box" look. Optional eyebrow
    # header "/ HEADER" with dotted amber underline at y=40.
    param(
        $Panel,
        [string]$Header = $null,
        $BracketColor = $null,
        [int]$BracketLen = 16,
        [int]$BracketThick = 2
    )
    if (-not $BracketColor) { $BracketColor = $cAccent }
    $underColor = [System.Drawing.Color]::FromArgb(90, $BracketColor.R, $BracketColor.G, $BracketColor.B)
    $hasHdr = -not [string]::IsNullOrWhiteSpace($Header)
    Enable-DoubleBuffer -Control $Panel
    $Panel.Add_SizeChanged({ $this.Invalidate() })
    $Panel.Add_Paint({
        param($sender, $e)
        $e.Graphics.SmoothingMode = 'HighQuality'
        $pen = New-Object System.Drawing.Pen($BracketColor, $BracketThick)
        try {
            $w = $sender.Width - 1
            $h = $sender.Height - 1
            $L = $BracketLen
            $e.Graphics.DrawLine($pen, 0, 0, $L, 0)
            $e.Graphics.DrawLine($pen, 0, 0, 0, $L)
            $e.Graphics.DrawLine($pen, ($w - $L), 0, $w, 0)
            $e.Graphics.DrawLine($pen, $w, 0, $w, $L)
            $e.Graphics.DrawLine($pen, 0, ($h - $L), 0, $h)
            $e.Graphics.DrawLine($pen, 0, $h, $L, $h)
            $e.Graphics.DrawLine($pen, ($w - $L), $h, $w, $h)
            $e.Graphics.DrawLine($pen, $w, ($h - $L), $w, $h)
        } finally { $pen.Dispose() }
        if ($hasHdr) {
            $dotPen = New-Object System.Drawing.Pen($underColor, 1)
            $dotPen.DashStyle = 'Dot'
            try {
                $e.Graphics.DrawLine($dotPen, 14, 40, ($sender.Width - 14), 40)
            } finally { $dotPen.Dispose() }
        }
    }.GetNewClosure())
    if ($hasHdr) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text      = "/ $($Header.ToUpperInvariant())"
        $hdr.Location  = New-Object System.Drawing.Point(14, 14)
        $hdr.Size      = New-Object System.Drawing.Size(($Panel.Width - 28), 22)
        $hdr.ForeColor = $BracketColor
        $hdr.BackColor = [System.Drawing.Color]::Transparent
        $hdr.Font      = $fEyebrow
        $hdr.Anchor    = 'Top,Left,Right'
        $Panel.Controls.Add($hdr)
    }
}

function Add-GridPaperBackground {
    # 1px dots on an $Spacing grid - technical-paper texture on content.
    param($Panel, [int]$Spacing = 18)
    $dotColor = [System.Drawing.Color]::FromArgb(18, $cTextMuted.R, $cTextMuted.G, $cTextMuted.B)
    Enable-DoubleBuffer -Control $Panel
    $Panel.Add_Paint({
        param($sender, $e)
        $brush = New-Object System.Drawing.SolidBrush($dotColor)
        try {
            for ($x = $Spacing; $x -lt $sender.Width; $x += $Spacing) {
                for ($y = $Spacing; $y -lt $sender.Height; $y += $Spacing) {
                    $e.Graphics.FillRectangle($brush, $x, $y, 1, 1)
                }
            }
        } finally { $brush.Dispose() }
    }.GetNewClosure())
    $Panel.Add_SizeChanged({ $this.Invalidate() })
}

function Add-ScanlineOverlay {
    # Subtle 1px horizontal lines every 3px - CRT feel for header/status.
    param($Panel)
    $lineColor = [System.Drawing.Color]::FromArgb(10, 255, 255, 255)
    Enable-DoubleBuffer -Control $Panel
    $Panel.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen($lineColor, 1)
        try {
            for ($y = 0; $y -lt $sender.Height; $y += 3) {
                $e.Graphics.DrawLine($pen, 0, $y, $sender.Width, $y)
            }
        } finally { $pen.Dispose() }
    }.GetNewClosure())
}

function Add-DiagonalStripe {
    # 4px yellow/black diagonal hatch along the bottom of a Button -
    # tactical primary CTA accent.
    param($Button, [int]$Height = 4)
    $c1 = $cStripeAmb
    $c2 = $cStripeBlk
    $Button.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush('WideDownwardDiagonal', $c2, $c1)
        try {
            $rect = New-Object System.Drawing.Rectangle(0, ($sender.Height - $Height), $sender.Width, $Height)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())
}

function New-PulseDot {
    # 8px status dot that BLINKS via Timer. State:
    #   Idle   - solid muted (no blink)
    #   Active - olive, blinks every ~720ms
    #   Alert  - amber, fast blink ~340ms
    #   Error  - red,   fast blink ~340ms
    # Dispose the timer on form close via $dot.Tag.Timer.
    param(
        [int]$X = 0, [int]$Y = 0, [int]$Size = 8,
        [ValidateSet('Active','Idle','Alert','Error')][string]$State = 'Idle'
    )
    $p = New-Object System.Windows.Forms.Panel
    $p.Location  = New-Object System.Drawing.Point($X, $Y)
    $p.Size      = New-Object System.Drawing.Size($Size, $Size)
    $p.BackColor = [System.Drawing.Color]::Transparent
    $c1 = switch ($State) {
        'Active' { $cGreen }
        'Alert'  { $cOrange }
        'Error'  { $cRed }
        default  { $cTextMuted }
    }
    $c2 = [System.Drawing.Color]::FromArgb(50, $c1.R, $c1.G, $c1.B)
    $p.Tag = @{ Phase = 0; State = $State; C1 = $c1; C2 = $c2 }
    $p.Add_Paint({
        param($sender, $e)
        $t = $sender.Tag
        $c = if ($t.Phase -eq 0 -or $t.State -eq 'Idle') { $t.C1 } else { $t.C2 }
        $e.Graphics.SmoothingMode = 'AntiAlias'
        $brush = New-Object System.Drawing.SolidBrush($c)
        try {
            $e.Graphics.FillEllipse($brush, 0, 0, ($sender.Width - 1), ($sender.Height - 1))
        } finally { $brush.Dispose() }
    }.GetNewClosure())
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert' -or $State -eq 'Error') { 340 } else { 720 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({
            $p.Tag.Phase = 1 - $p.Tag.Phase
            $p.Invalidate()
        }.GetNewClosure())
        $timer.Start()
        $p.Tag.Timer = $timer
    }
    return $p
}

function Set-PulseDotState {
    param($Dot, [ValidateSet('Active','Idle','Alert','Error')][string]$State)
    if (-not $Dot) { return }
    $t = $Dot.Tag
    if (-not $t) { return }
    if ($t.State -eq $State) { return }
    $t.State = $State
    $t.C1 = switch ($State) {
        'Active' { $cGreen }
        'Alert'  { $cOrange }
        'Error'  { $cRed }
        default  { $cTextMuted }
    }
    $t.C2 = [System.Drawing.Color]::FromArgb(50, $t.C1.R, $t.C1.G, $t.C1.B)
    if ($t.Timer) { $t.Timer.Stop(); $t.Timer.Dispose(); $t.Timer = $null }
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert' -or $State -eq 'Error') { 340 } else { 720 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({
            $Dot.Tag.Phase = 1 - $Dot.Tag.Phase
            $Dot.Invalidate()
        }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Dot.Invalidate()
}

function New-TacticalButton {
    # Flat amber CTA. Optional stripe hatch on the bottom edge.
    param(
        [string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H,
        $Bg = $null, $Fg = $null, $Font = $null, [switch]$Stripe
    )
    if (-not $Bg)   { $Bg   = $cAccent }
    if (-not $Fg) {
        $lum = (0.299 * $Bg.R + 0.587 * $Bg.G + 0.114 * $Bg.B) / 255.0
        if ($lum -gt 0.55) { $Fg = $cTextOnAccent } else { $Fg = $cText }
    }
    if (-not $Font) { $Font = $fDisplaySm }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Bg
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    if ($Stripe) { Add-DiagonalStripe -Button $b }
    return $b
}

function New-GhostButton {
    # Outline secondary button.
    param(
        [string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H,
        $Fg = $null, $Border = $null, $Font = $null
    )
    if (-not $Fg)     { $Fg     = $cTextDim }
    if (-not $Border) { $Border = $cBorderStrong }
    if (-not $Font)   { $Font   = $fEyebrowSm }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $Border
    $b.BackColor = $cPanel
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $cRowHover
    $b.FlatAppearance.MouseDownBackColor = $cRowActive
    return $b
}

# -- Tooltips --
$Tooltip = New-Object System.Windows.Forms.ToolTip
$ShowHelp = {
    Switch ($this.name) {
        "orgbox"        { $tip = "Enter partial/full name of Organizational box." }
        "firstname"     { $tip = "Enter partial/full user's first name." }
        "lastname"      { $tip = "Enter partial/full user's last name." }
        "edipi"         { $tip = "Enter partial/full user's EDIPI/DOD #." }
        "computername"  { $tip = "Enter partial/full computer's name." }
        "groupname"     { $tip = "Enter partial/full group name." }
        "emailaddress"  { $tip = "Enter partial/full email address to search." }
        "managername"   { $tip = "Enter partial/full manager's display name." }
        "mainsearch"    { $tip = "Click here to execute the search." }
        "save"          { $tip = "Click here to save/export current results." }
        "clear"         { $tip = "Click here to clear all fields." }
    }
    $Tooltip.SetToolTip($this,$tip)
}

# ==========================================================================
#  ASYNC SEARCH ENGINE
# ==========================================================================
function Start-AsyncSearch {
    param([string]$SearchType, [hashtable]$SearchParams)

    # Cancel any running search
    if ($script:currentPowerShell -ne $null) {
        try { $script:currentPowerShell.Stop(); $script:currentPowerShell.Dispose() } catch {}
        $script:currentPowerShell = $null
    }
    if ($script:currentRunspace -ne $null) {
        try { $script:currentRunspace.Close(); $script:currentRunspace.Dispose() } catch {}
        $script:currentRunspace = $null
    }

    $btnSearch.Enabled = $false
    $statusBar.Text = ("SEARCHING :: {0}  ::  please wait" -f $SearchType.ToUpper())
    if ($script:dotStatus) { Set-PulseDotState -Dot $script:dotStatus -State 'Active' }

    $script:currentRunspace = [RunspaceFactory]::CreateRunspace()
    $script:currentRunspace.ApartmentState = "STA"
    $script:currentRunspace.Open()

    $script:currentPowerShell = [PowerShell]::Create()
    $script:currentPowerShell.Runspace = $script:currentRunspace
    $script:currentSearchType = $SearchType

    $scriptBlock = {
        param($SearchType, $SearchParams)

        # Defined inline so it resolves inside this child runspace (host-scope
        # functions are NOT visible here). Mirrors the host Escape-LdapFilterValue.
        function Escape-LdapFilterValue {
            param([string]$Value)
            if ($null -eq $Value) { return '' }
            $r = $Value -replace '\\', '\5c'
            $r = $r     -replace '\*', '\2a'
            $r = $r     -replace '\(', '\28'
            $r = $r     -replace '\)', '\29'
            $r = $r     -replace "`0", '\00'
            return $r
        }

        $root = [ADSI]""
        $searcher = [ADSISEARCHER]$root
        $searcher.PageSize = 15000
        $results = @()

        switch ($SearchType) {
            "User" {
                $firstName = $SearchParams.FirstName
                $lastName  = $SearchParams.LastName
                $edipi     = $SearchParams.EDIPI
                $searcher.filter = "(&(objectCategory=person)(objectClass=user)(givenName=$(Escape-LdapFilterValue $firstName)*)(sn=$(Escape-LdapFilterValue $lastName)*)(samaccountname=$(Escape-LdapFilterValue $edipi)*))"
                $adResults = $searcher.FindAll()
                foreach ($user in $adResults) {
                    $props = @{}
                    foreach ($key in $user.Properties.PropertyNames) {
                        $val = $user.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $results += $props
                }
            }
            "Computer" {
                $computerName = $SearchParams.ComputerName
                $searcher.filter = "(&(objectCategory=Computer)(name=$(Escape-LdapFilterValue $computerName)*))"
                $adResults = $searcher.FindAll()
                foreach ($computer in $adResults) {
                    $props = @{}
                    foreach ($key in $computer.Properties.PropertyNames) {
                        $val = $computer.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $results += $props
                }
            }
            "Group" {
                $groupName = $SearchParams.GroupName
                $searcher.filter = "(&(objectCategory=group)(name=$(Escape-LdapFilterValue $groupName)*))"
                $adResults = $searcher.FindAll()
                foreach ($group in $adResults) {
                    $props = @{}
                    foreach ($key in $group.Properties.PropertyNames) {
                        $val = $group.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $results += $props
                }
            }
            "OrgBox" {
                $orgBoxName = $SearchParams.OrgBoxName
                $searcher.filter = "(&(objectCategory=person)(objectClass=user)(name=$(Escape-LdapFilterValue $orgBoxName)*))"
                $adResults = $searcher.FindAll()
                foreach ($orgBox in $adResults) {
                    $props = @{}
                    foreach ($key in $orgBox.Properties.PropertyNames) {
                        $val = $orgBox.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $results += $props
                }
            }
            "Email" {
                $emailAddress = $SearchParams.EmailAddress
                $searcher.filter = "(&(objectCategory=person)(objectClass=user)(mail=$(Escape-LdapFilterValue $emailAddress)*))"
                $adResults = $searcher.FindAll()
                foreach ($user in $adResults) {
                    $props = @{}
                    foreach ($key in $user.Properties.PropertyNames) {
                        $val = $user.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $results += $props
                }
            }
            "Manager" {
                $managerName = $SearchParams.ManagerName
                $searcher.filter = "(&(objectCategory=person)(objectClass=user)(displayName=$(Escape-LdapFilterValue $managerName)*))"
                $managerResults = $searcher.FindAll()
                if ($managerResults.Count -gt 0) {
                    $managerDN = $managerResults[0].Properties["distinguishedname"][0]
                    $reportSearcher = [ADSISEARCHER]$root
                    $reportSearcher.PageSize = 15000
                    # DN comes from AD result, but a CN that contains a literal
                    # `(`, `)`, `*`, `\` (rare but legal in AD when escaped) would
                    # corrupt the filter. Escape defensively.
                    $reportSearcher.filter = "(&(objectCategory=person)(objectClass=user)(manager=$(Escape-LdapFilterValue $managerDN)))"
                    $reportResults = $reportSearcher.FindAll()
                    $managerProps = @{}
                    foreach ($key in $managerResults[0].Properties.PropertyNames) {
                        $val = $managerResults[0].Properties[$key]
                        if ($val.Count -eq 1) { $managerProps[$key] = $val[0] } else { $managerProps[$key] = @($val) }
                    }
                    $managerProps["_isManager"] = $true
                    $managerProps["_directReportCount"] = $reportResults.Count
                    $results += $managerProps
                    foreach ($report in $reportResults) {
                        $props = @{}
                        foreach ($key in $report.Properties.PropertyNames) {
                            $val = $report.Properties[$key]
                            if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                        }
                        $props["_isManager"] = $false
                        $results += $props
                    }
                }
                return $results
            }
            "BulkComputer" {
                $machineList = $SearchParams.MachineList
                $now = Get-Date
                $staleThreshold = $now.AddDays(-90)

                # Clean and deduplicate the list
                $cleanList = @()
                foreach ($machine in $machineList) {
                    $m = $machine.Trim().ToUpper()
                    if ($m -ne "" -and $cleanList -notcontains $m) { $cleanList += $m }
                }

                # Track which machines were found
                $foundMachines = @{}

                # Helper: extract all OU levels from a DN into useful fields
                # Example DN: CN=PC001,OU=Workstations,OU=48CS,OU=Lakenheath,DC=AREA52,...
                # Returns: Squadron="48CS", ParentOU="Workstations", OUChain="Lakenheath > 48CS > Workstations"
                function Parse-OUFromDN {
                    param([string]$DN)
                    $ouPath = ($DN -split ",", 2)[1]
                    $ouParts = $ouPath -split ","
                    $ouNames = @()
                    foreach ($part in $ouParts) {
                        if ($part -match "^OU=(.+)$") { $ouNames += $Matches[1] }
                    }
                    # ouNames[0] = immediate parent (e.g. "Workstations")
                    # ouNames[1] = next level up (e.g. "48CS" - likely the squadron)
                    # ouNames[2] = next level up (e.g. "Lakenheath" - likely the base)
                    $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { "(Root)" }
                    # Squadron: skip generic container names, look for the real unit
                    $squadron = $parentOU
                    $genericNames = @("Workstations","Computers","Servers","Desktops","Laptops","Devices","Resources","Members")
                    if ($ouNames.Count -ge 2 -and $genericNames -contains $parentOU) {
                        $squadron = $ouNames[1]
                    }
                    # Build the full chain (reversed so top-level is first)
                    $reversed = @($ouNames)
                    [array]::Reverse($reversed)
                    $ouChain = $reversed -join " > "
                    if ($ouChain -eq "") { $ouChain = "(Root)" }

                    return @{
                        Squadron = $squadron
                        ParentOU = $parentOU
                        OUChain  = $ouChain
                        FullOU   = $ouPath
                    }
                }

                # Batch queries in groups of 50 for performance
                $batchSize = 50
                for ($i = 0; $i -lt $cleanList.Count; $i += $batchSize) {
                    $batch = $cleanList[$i..[math]::Min(($i + $batchSize - 1), ($cleanList.Count - 1))]

                    # Build OR filter for the batch
                    $filterParts = ""
                    foreach ($name in $batch) {
                        $filterParts += "(name=$(Escape-LdapFilterValue $name))"
                    }
                    if ($batch.Count -eq 1) {
                        $searcher.Filter = "(&(objectCategory=Computer)$filterParts)"
                    } else {
                        $searcher.Filter = "(&(objectCategory=Computer)(|$filterParts))"
                    }

                    try {
                        $adResults = $searcher.FindAll()
                        foreach ($entry in $adResults) {
                            $props = @{}
                            foreach ($key in $entry.Properties.PropertyNames) {
                                $val = $entry.Properties[$key]
                                if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                            }

                            $dn = $props.distinguishedname
                            $ouInfo = Parse-OUFromDN -DN $dn
                            $props["_squadron"] = $ouInfo.Squadron
                            $props["_parentOU"] = $ouInfo.ParentOU
                            $props["_ouChain"]  = $ouInfo.OUChain
                            $props["_fullOU"]   = $ouInfo.FullOU

                            $lastLogon = "Never"; $isStale = $true
                            try {
                                $tsVal = $props.lastlogontimestamp
                                if ($tsVal -ne $null -and $tsVal -gt 0) {
                                    $lastLogonDate = [DateTime]::FromFileTime([Int64]$tsVal)
                                    $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd HH:mm")
                                    if ($lastLogonDate -ge $staleThreshold) { $isStale = $false }
                                }
                            } catch {}
                            $props["_lastLogon"] = $lastLogon
                            $props["_isStale"]   = $isStale
                            $props["_status"]    = if ($isStale) { "Stale" } else { "Active" }

                            $pcName = "$($props.name)".ToUpper()
                            $foundMachines[$pcName] = $true
                            $results += $props
                        }
                    } catch {
                        # If batch fails, fall back to individual queries
                        foreach ($name in $batch) {
                            $searcher.Filter = "(&(objectCategory=Computer)(name=$(Escape-LdapFilterValue $name)))"
                            try {
                                $fallbackResults = $searcher.FindAll()
                                if ($fallbackResults.Count -gt 0) {
                                    foreach ($entry in $fallbackResults) {
                                        $props = @{}
                                        foreach ($key in $entry.Properties.PropertyNames) {
                                            $val = $entry.Properties[$key]
                                            if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                                        }
                                        $dn = $props.distinguishedname
                                        $ouInfo = Parse-OUFromDN -DN $dn
                                        $props["_squadron"] = $ouInfo.Squadron
                                        $props["_parentOU"] = $ouInfo.ParentOU
                                        $props["_ouChain"]  = $ouInfo.OUChain
                                        $props["_fullOU"]   = $ouInfo.FullOU
                                        $lastLogon = "Never"; $isStale = $true
                                        try {
                                            $tsVal = $props.lastlogontimestamp
                                            if ($tsVal -ne $null -and $tsVal -gt 0) {
                                                $lastLogonDate = [DateTime]::FromFileTime([Int64]$tsVal)
                                                $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd HH:mm")
                                                if ($lastLogonDate -ge $staleThreshold) { $isStale = $false }
                                            }
                                        } catch {}
                                        $props["_lastLogon"] = $lastLogon; $props["_isStale"] = $isStale
                                        $props["_status"] = if ($isStale) { "Stale" } else { "Active" }
                                        $foundMachines["$($props.name)".ToUpper()] = $true
                                        $results += $props
                                    }
                                }
                            } catch {}
                        }
                    }
                }

                # Add "Not Found" entries for machines that had no AD result
                foreach ($name in $cleanList) {
                    if (-not $foundMachines.ContainsKey($name)) {
                        $results += @{
                            name            = $name
                            _squadron       = "NOT FOUND"
                            _parentOU       = "N/A"
                            _ouChain        = "N/A"
                            _fullOU         = "N/A"
                            _lastLogon      = "N/A"
                            _isStale        = $false
                            _status         = "Not Found"
                            operatingsystem = "N/A"
                        }
                    }
                }
            }
            "BaseUsers" {
                $baseName = $SearchParams.BaseName
                $allFound = [System.Collections.ArrayList]::new()
                $seenDNs = @{}
                $searchedOUs = [System.Collections.ArrayList]::new()

                $rootDSE = [ADSI]"LDAP://RootDSE"
                $domainDN = $rootDSE.defaultNamingContext.ToString()

                # Step 1: Find the base-level OU (e.g. OU=Lakenheath)
                $ouSearcher = [ADSISEARCHER]$root
                $ouSearcher.PageSize = 1000
                $ouSearcher.Filter = "(&(objectCategory=organizationalUnit)(name=$(Escape-LdapFilterValue $baseName)*))"
                $baseOUs = @()
                try {
                    $baseOUResults = $ouSearcher.FindAll()
                    foreach ($ou in $baseOUResults) {
                        $baseOUs += "$($ou.Properties['distinguishedname'][0])"
                    }
                } catch {}

                # Step 2: Under each base OU, find child OUs for:
                #   - "Users" OUs (standard accounts, e.g. "Lakenheath AFB Users")
                #   - "Administrative" OUs (privileged accounts)
                #   - "AFB" OUs (privileged .adw/.adf accounts, e.g. "Lakenheath AFB")
                foreach ($baseOUDN in $baseOUs) {
                    $childSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $childSearcher.SearchRoot = [ADSI]"LDAP://$baseOUDN"
                    $childSearcher.PageSize = 1000
                    $childSearcher.SearchScope = "Subtree"
                    $childSearcher.Filter = "(&(objectCategory=organizationalUnit)(|(name=*Users*)(name=*Administrative*)(name=*AFB*)))"
                    try {
                        $childOUs = $childSearcher.FindAll()
                        foreach ($childOU in $childOUs) {
                            $childOUDN = "$($childOU.Properties['distinguishedname'][0])"
                            $childOUName = "$($childOU.Properties['name'][0])"
                            [void]$searchedOUs.Add($childOUDN)

                            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
                            $userSearcher.SearchRoot = [ADSI]"LDAP://$childOUDN"
                            $userSearcher.PageSize = 15000
                            $userSearcher.SearchScope = "Subtree"

                            # Users OU = pull all accounts
                            # AFB/Administrative OU (without "Users") = ONLY pull .adw/.adf/.adm/.ada/.adn accounts
                            if ($childOUName -match "Users") {
                                $userSearcher.Filter = "(&(objectCategory=person)(objectClass=user))"
                            } else {
                                $userSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(samaccountname=*.adw)(samaccountname=*.adf)(samaccountname=*.adm)(samaccountname=*.ada)(samaccountname=*.adn)(samaccountname=*.SA)))"
                            }
                            try {
                                $userResults = $userSearcher.FindAll()
                                foreach ($user in $userResults) {
                                    $dn = "$($user.Properties['distinguishedname'][0])"
                                    if (-not $seenDNs.ContainsKey($dn)) {
                                        $seenDNs[$dn] = $true
                                        [void]$allFound.Add($user)
                                    }
                                }
                            } catch {}
                        }
                    } catch {}
                }

                # If no matching OUs were found, return helpful error
                if ($searchedOUs.Count -eq 0) {
                    $msg = "No 'Users', 'Administrative', or 'AFB' OU found under '$baseName'.`n`n"
                    if ($baseOUs.Count -gt 0) {
                        $msg += "Found base OU(s):`n"
                        foreach ($b in $baseOUs) { $msg += "  $b`n" }
                        $msg += "`nBut none contained a child OU with 'Users', 'Administrative', or 'AFB' in the name.`n"
                        $msg += "`nCheck your AD structure for the correct OU names."
                    } else {
                        $msg += "No OU matching '$baseName' was found in the domain.`n"
                        $msg += "`nTry: LAKENHEATH, RAMSTEIN, SPANGDAHLEM, MILDENHALL"
                    }
                    return @(@{ _Error = $msg })
                }

                if ($allFound.Count -eq 0) {
                    $msg = "Searched the following OU(s) but found 0 user accounts:`n`n"
                    foreach ($s in $searchedOUs) { $msg += "  $s`n" }
                    return @(@{ _Error = $msg })
                }

                # Process all found users
                foreach ($user in $allFound) {
                    $props = @{}
                    foreach ($key in $user.Properties.PropertyNames) {
                        $val = $user.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }

                    # Determine privilege level by account name and display name
                    # NO group membership check (causes false positives)
                    $isPriv = $false
                    $privReason = ""
                    $sam = "$($props.samaccountname)"
                    $displayName = "$($props.displayname)"
                    $cn = "$($props.cn)"

                    # Check sAMAccountName for admin suffixes
                    $privSuffixes = @('.adw','.adf','.adm','.ada','.adn','.SA')
                    foreach ($suffix in $privSuffixes) {
                        if ($sam.EndsWith($suffix) -or $sam.EndsWith($suffix.ToUpper()) -or $sam.EndsWith($suffix.ToLower())) {
                            $isPriv = $true
                            $privReason = "Account suffix: $suffix"
                            break
                        }
                    }

                    # Also check for _adm, -adm patterns in the account name
                    if (-not $isPriv) {
                        if ($sam -like "*_adm" -or $sam -like "*-adm" -or $sam -like "*_ada" -or $sam -like "*-ada") {
                            $isPriv = $true
                            $privReason = "Account name pattern: admin suffix"
                        }
                    }

                    # Check displayName/CN for (ADM) indicator
                    if (-not $isPriv) {
                        if ($displayName -match "\(ADM\)" -or $cn -match "\(ADM\)" -or $displayName -match "^ADM[\s\-]") {
                            $isPriv = $true
                            $privReason = "Display name contains (ADM)"
                        }
                    }

                    $props["_isPrivileged"] = $isPriv
                    $props["_privLevel"]    = if ($isPriv) { "Privileged" } else { "Standard" }
                    $props["_privReason"]   = $privReason

                    # Parse OU
                    $dn = "$($props.distinguishedname)"
                    $ouParts = $dn -split ","
                    $ouNames = @()
                    foreach ($part in $ouParts) {
                        if ($part -match "^OU=(.+)$") { $ouNames += $Matches[1] }
                    }
                    $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { "(Root)" }
                    $props["_parentOU"] = $parentOU

                    # Parse org from location
                    $locVal = "$($props.location)"
                    $org = ""
                    if ($locVal -ne "" -and $locVal -match "ORGANIZATION:\s*([^;]+)") {
                        $org = $Matches[1].Trim()
                    }
                    $props["_organization"] = $org

                    # Email
                    $email = $props.mail
                    if ($email -eq $null) { $email = "" }
                    $props["_email"] = "$email"

                    # Track which Users OU this came from
                    $props["_sourceOU"] = ""
                    foreach ($sou in $searchedOUs) {
                        if ($dn -like "*$sou*") { $props["_sourceOU"] = $sou; break }
                    }

                    $results += $props
                }
            }
            "LastPC" {
                # Find which workstation a person was last logged into by
                # querying domain-controller Security logs for Kerberos /
                # logon events tagged with the user's sAMAccountName.
                #
                # Events queried:
                #   4624 - Account successfully logged on
                #   4768 - Kerberos TGT requested  (initial domain logon)
                #   4769 - Kerberos service ticket requested
                #   4776 - Credential validation (NTLM, has Workstation field)
                #
                # Server-side XPath filter (TargetUserName starts-with each
                # matched SAM) keeps the result set small. We then post-filter
                # for exact match or "<sam>@realm" form to avoid false
                # positives from prefix collisions.
                $firstName = "$($SearchParams.FirstName)"
                $lastName  = "$($SearchParams.LastName)"
                $edipi     = "$($SearchParams.EDIPI)"
                $daysBack  = if ($SearchParams.DaysBack) { [int]$SearchParams.DaysBack } else { 14 }
                if ($daysBack -lt 1)  { $daysBack = 1 }
                if ($daysBack -gt 90) { $daysBack = 90 }

                # Resolve user(s) using the same field semantics as the User
                # search. Cap to 5 to bound DC-log query work.
                $userFilter = "(&(objectCategory=person)(objectClass=user)"
                if ($firstName) { $userFilter += "(givenName=$firstName*)" }
                if ($lastName)  { $userFilter += "(sn=$lastName*)" }
                if ($edipi)     { $userFilter += "(samaccountname=$edipi*)" }
                $userFilter += ")"
                $searcher.filter = $userFilter
                $userResults = $searcher.FindAll()
                if ($userResults.Count -eq 0) {
                    return @(@{ _Error = "No matching user found.`n`nFirst Name: $firstName`nLast Name: $lastName`nEDIPI: $edipi" })
                }

                $maxUsers = 5
                $matchedUsers = @()
                $u_i = 0
                foreach ($u in $userResults) {
                    if ($u_i -ge $maxUsers) { break }
                    $matchedUsers += $u
                    $u_i++
                }
                $truncated = ($userResults.Count -gt $maxUsers)

                $samToDisplay = @{}
                $samToDN      = @{}
                $samEsc       = @()
                foreach ($mu in $matchedUsers) {
                    $sam = "$($mu.Properties['samaccountname'][0])"
                    if ($sam -eq "") { continue }
                    $samToDisplay[$sam] = "$($mu.Properties['displayname'][0])"
                    $samToDN[$sam]      = "$($mu.Properties['distinguishedname'][0])"
                    $sEsc = $sam -replace "&","&amp;" -replace "'","&apos;" -replace "<","&lt;" -replace ">","&gt;"
                    $samEsc += $sEsc
                }
                if ($samEsc.Count -eq 0) {
                    return @(@{ _Error = "Matched user record(s) had empty sAMAccountName." })
                }

                # Discover all writable domain controllers in the domain.
                $dcSearcher = [ADSISEARCHER]$root
                $dcSearcher.PageSize = 500
                $dcSearcher.Filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
                $dcs = @()
                foreach ($dc in $dcSearcher.FindAll()) {
                    $h = "$($dc.Properties['dnshostname'][0])"
                    if ($h -ne "") { $dcs += $h }
                }
                if ($dcs.Count -eq 0) {
                    return @(@{ _Error = "No domain controllers were discovered via LDAP." })
                }

                $daysBackMs = [int64]$daysBack * 86400000
                $startsWith = ($samEsc | ForEach-Object { "starts-with(Data, '$_')" }) -join " or "
                $xmlFilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776) and TimeCreated[timediff(@SystemTime) &lt;= $daysBackMs]] and EventData[Data[@Name='TargetUserName'] and ($startsWith)]]</Select>
  </Query>
</QueryList>
"@

                $allHits    = New-Object System.Collections.ArrayList
                $dcErrors   = New-Object System.Collections.ArrayList
                $dcsScanned = 0

                foreach ($dc in $dcs) {
                    # Quick TCP probe so we skip unreachable DCs fast. Port 135
                    # is RPC endpoint mapper, which Get-WinEvent uses for the
                    # initial bind. Mirrors the WPT reachability pattern.
                    $reachable = $false
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $iar = $tcp.BeginConnect($dc, 135, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(1500, $false)) {
                            try { $tcp.EndConnect($iar); $reachable = $true } catch {}
                        }
                        try { $tcp.Close() } catch {}
                    } catch {}

                    if (-not $reachable) {
                        [void]$dcErrors.Add("$dc :: TCP/135 unreachable")
                        continue
                    }

                    try {
                        $events = Get-WinEvent -ComputerName $dc -FilterXml $xmlFilter -MaxEvents 2000 -ErrorAction Stop
                        $dcsScanned++
                        foreach ($evt in $events) {
                            try {
                                $xml = [xml]$evt.ToXml()
                                $data = @{}
                                foreach ($d in $xml.Event.EventData.Data) {
                                    $data["$($d.Name)"] = "$($d.'#text')"
                                }
                                $tu = "$($data.TargetUserName)"
                                if ($tu -eq "" -or $tu -like "*$") { continue }

                                # Post-filter: exact SAM match (case-insensitive)
                                # or "<sam>@realm" form, to drop prefix
                                # collisions caught by the loose XPath.
                                $matchedSam = $null
                                foreach ($mu in $matchedUsers) {
                                    $sam = "$($mu.Properties['samaccountname'][0])"
                                    if ($sam -eq "") { continue }
                                    if ($tu -ieq $sam -or $tu -ilike "$sam@*") {
                                        $matchedSam = $sam
                                        break
                                    }
                                }
                                if (-not $matchedSam) { continue }

                                $ip  = "$($data.IpAddress)"
                                $wks = "$($data.WorkstationName)"
                                if ($wks -eq "") { $wks = "$($data.Workstation)" }
                                if ($ip -eq "::1" -or $ip -eq "127.0.0.1" -or $ip -eq "-") { $ip = "" }
                                if ($ip -like "::ffff:*") { $ip = $ip.Substring(7) }
                                if ($ip -eq "" -and $wks -eq "") { continue }

                                [void]$allHits.Add(@{
                                    Time      = $evt.TimeCreated
                                    EventId   = $evt.Id
                                    DC        = $dc
                                    IP        = $ip
                                    Wks       = $wks
                                    Sam       = $matchedSam
                                    LogonType = "$($data.LogonType)"
                                })
                            } catch {}
                        }
                    } catch {
                        [void]$dcErrors.Add("$dc :: $($_.Exception.Message)")
                    }
                }

                if ($allHits.Count -eq 0) {
                    $msg = "No matching logon events found across $dcsScanned of $($dcs.Count) DC(s) in the last $daysBack day(s)."
                    $msg += "`n`nMatched user(s):"
                    foreach ($mu in $matchedUsers) {
                        $msg += "`n  $($mu.Properties['displayname'][0])  ($($mu.Properties['samaccountname'][0]))"
                    }
                    if ($dcErrors.Count -gt 0) {
                        $msg += "`n`nDC errors:"
                        foreach ($e in $dcErrors) { $msg += "`n  $e" }
                        $msg += "`n`nIf every DC failed with 'access denied' you do not have permission to read the Security log on the DCs.  Re-launch from a privileged account."
                    }
                    return @(@{ _Error = $msg })
                }

                # Resolve IPs -> hostnames (cached). Reduce to one row per
                # (sam, computerName), keeping the most recent hit.
                $resolvedIp = @{}
                $byKey = @{}
                foreach ($h in $allHits) {
                    $hostName = ""
                    if ($h.IP -ne "" -and $h.IP -match "[\d\.:]") {
                        if (-not $resolvedIp.ContainsKey($h.IP)) {
                            try {
                                $resolvedIp[$h.IP] = [System.Net.Dns]::GetHostEntry($h.IP).HostName
                            } catch { $resolvedIp[$h.IP] = "" }
                        }
                        $hostName = $resolvedIp[$h.IP]
                    }
                    if ($hostName -eq "" -and $h.Wks -ne "") { $hostName = $h.Wks }
                    if ($hostName -eq "" -and $h.IP  -ne "") { $hostName = $h.IP }
                    if ($hostName -eq "") { continue }

                    $hostShort = ($hostName -split '\.')[0].ToUpper()
                    $key = "$($h.Sam.ToLower())|$hostShort"
                    if (-not $byKey.ContainsKey($key) -or $byKey[$key]._time -lt $h.Time) {
                        $byKey[$key] = @{
                            _sam          = $h.Sam
                            _computerName = $hostShort
                            _ipAddress    = $h.IP
                            _time         = $h.Time
                            _eventId      = $h.EventId
                            _dc           = $h.DC
                            _logonType    = $h.LogonType
                        }
                    }
                }

                $sorted = $byKey.Values | Sort-Object { $_._time } -Descending
                foreach ($row in $sorted) {
                    $row["_displayName"]       = $samToDisplay["$($row._sam)"]
                    $row["_distinguishedName"] = $samToDN["$($row._sam)"]
                    $row["_timeStr"]           = $row._time.ToString("yyyy-MM-dd HH:mm:ss")
                    $row["_dcShort"]           = ($row._dc -split '\.')[0].ToUpper()
                    $row["_daysBack"]          = $daysBack
                    $row["_dcsScanned"]        = $dcsScanned
                    $row["_dcsTotal"]          = $dcs.Count
                    $row["_eventCount"]        = $allHits.Count
                    $row["_userTruncated"]     = $truncated
                    $row["_dcErrors"]          = ($dcErrors -join "`n")
                    $results += $row
                }
            }
        }
        return $results
    }

    [void]$script:currentPowerShell.AddScript($scriptBlock)
    [void]$script:currentPowerShell.AddArgument($SearchType)
    [void]$script:currentPowerShell.AddArgument($SearchParams)

    $script:currentAsyncResult = $script:currentPowerShell.BeginInvoke()
    $searchTimer.Start()
}

# ==========================================================================
#  PROCESS SEARCH RESULTS (UI thread)
# ==========================================================================
function Process-SearchResults {
    param([string]$SearchType, [array]$Results)

    $script:cachedResults = $Results
    $listViewResults.Items.Clear()
    $listViewResults.Columns.Clear()

    switch ($SearchType) {
        "User" {
            $listViewResults.Columns.Add("Display Name", 350) | Out-Null
            foreach ($user in $Results) {
                $name = if ($user.displayname -eq $null) { $user.samaccountname } else { $user.displayname }
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                $item.ForeColor = $clrLightGray
                $listViewResults.Items.Add($item) | Out-Null
            }
            $txtBoxSearchResults.Text = "$($Results.Count) results found.`n`nFirst Name: $($txtBoxUserFirstName.Text.Trim())`nLast Name: $($txtBoxUserLastName.Text.Trim())`nEDIPI: $($txtBoxUserEDIPI.Text.Trim())`n`nDouble click a name to view extended information."
        }
        "Computer" {
            $listViewResults.Columns.Add("Computer Name", 350) | Out-Null
            foreach ($computer in $Results) {
                $item = New-Object System.Windows.Forms.ListViewItem($computer.name)
                $item.ForeColor = $clrLightGray
                $listViewResults.Items.Add($item) | Out-Null
            }
            $txtBoxSearchResults.Text = "$($Results.Count) results found.`n`nComputer Name: $($txtBoxComputerName.Text.Trim())`n`nDouble click a name to view extended information."
        }
        "Group" {
            $listViewResults.Columns.Add("Group Name", 350) | Out-Null
            foreach ($group in $Results) {
                $item = New-Object System.Windows.Forms.ListViewItem($group.name)
                $item.ForeColor = $clrLightGray
                $listViewResults.Items.Add($item) | Out-Null
            }
            $txtBoxSearchResults.Text = "$($Results.Count) results found.`n`nGroup Name: $($txtBoxGroupName.Text.Trim())`n`nDouble click a name to view extended information."
        }
        "OrgBox" {
            $listViewResults.Columns.Add("Org Box Name", 350) | Out-Null
            foreach ($orgBox in $Results) {
                $item = New-Object System.Windows.Forms.ListViewItem($orgBox.name)
                $item.ForeColor = $clrLightGray
                $listViewResults.Items.Add($item) | Out-Null
            }
            $txtBoxSearchResults.Text = "$($Results.Count) results found.`n`nOrg Box Name: $($txtBoxOrgBox.Text.Trim())`n`nDouble click a name to view extended information."
        }
        "Email" {
            $listViewResults.Columns.Add("Display Name", 250) | Out-Null
            $listViewResults.Columns.Add("Email Address", 300) | Out-Null
            foreach ($user in $Results) {
                $name = if ($user.displayname -eq $null) { $user.samaccountname } else { $user.displayname }
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                $item.ForeColor = $clrLightGray
                $emailVal = if ($user.mail -eq $null) { "N/A" } else { $user.mail }
                $item.SubItems.Add($emailVal) | Out-Null
                $listViewResults.Items.Add($item) | Out-Null
            }
            $txtBoxSearchResults.Text = "$($Results.Count) results found.`n`nEmail Search: $($txtBoxEmailAddress.Text.Trim())`n`nDouble click a name to view extended information."
        }
        "Manager" {
            $listViewResults.Columns.Add("Name", 300) | Out-Null
            $listViewResults.Columns.Add("Role", 150) | Out-Null
            if ($Results.Count -gt 0) {
                foreach ($person in $Results) {
                    $name = if ($person.displayname -eq $null) { $person.samaccountname } else { $person.displayname }
                    $item = New-Object System.Windows.Forms.ListViewItem($name)
                    $item.ForeColor = $clrLightGray
                    if ($person["_isManager"] -eq $true) {
                        $item.SubItems.Add("Manager") | Out-Null
                        $item.BackColor = $cPanelAlt
                        $item.ForeColor = $cAccent
                    } else {
                        $item.SubItems.Add("Direct Report") | Out-Null
                    }
                    $listViewResults.Items.Add($item) | Out-Null
                }
                $txtBoxSearchResults.Text = "Manager: $($Results[0].displayname)`nDirect Reports: $($Results[0]['_directReportCount'])`n`nThe first entry (gold) is the manager.`nDouble click a name to view extended information."
            } else {
                $txtBoxSearchResults.Text = "No manager found matching: $($txtBoxManagerName.Text.Trim())"
            }
        }
        "BulkComputer" {
            $listViewResults.Columns.Add("Computer Name", 130) | Out-Null
            $listViewResults.Columns.Add("Organization", 100) | Out-Null
            $listViewResults.Columns.Add("Location Info", 280) | Out-Null
            $listViewResults.Columns.Add("Squadron/OU", 110) | Out-Null
            $listViewResults.Columns.Add("Last Logon", 100) | Out-Null
            $listViewResults.Columns.Add("Status", 55) | Out-Null

            $activeCount = 0; $staleCount = 0; $notFound = 0
            foreach ($comp in $Results) {
                $pcName = $comp.name
                $item = New-Object System.Windows.Forms.ListViewItem($pcName)

                # Parse ORGANIZATION from the location field
                $locRaw = $comp.location
                $org = ""
                if ($locRaw -ne $null -and "$locRaw" -ne "") {
                    $locStr = "$locRaw"
                    if ($locStr -match "ORGANIZATION:\s*([^;]+)") {
                        $org = $Matches[1].Trim()
                    }
                }
                if ($org -eq "") { $org = $comp["_squadron"] }
                $item.SubItems.Add($org) | Out-Null

                # Full location string
                $locDisplay = if ($locRaw -ne $null) { "$locRaw" } else { "N/A" }
                $item.SubItems.Add($locDisplay) | Out-Null

                $item.SubItems.Add($comp["_squadron"]) | Out-Null
                $item.SubItems.Add($comp["_lastLogon"]) | Out-Null
                $item.SubItems.Add($comp["_status"]) | Out-Null

                if ($comp["_status"] -eq "Not Found") {
                    $item.ForeColor = $clrError; $notFound++
                } elseif ($comp["_status"] -eq "Stale") {
                    $item.ForeColor = $clrWarning; $staleCount++
                } elseif ($comp["_status"] -eq "Error") {
                    $item.ForeColor = $clrError; $notFound++
                } else {
                    $item.ForeColor = $clrSuccess; $activeCount++
                }
                $listViewResults.Items.Add($item) | Out-Null
            }

            # Build squadron breakdown summary - prefer Organization from location field
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("BULK COMPUTER SQUADRON LOOKUP")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("Total Searched:   $($Results.Count)")
            [void]$sb.AppendLine("Found in AD:      $($activeCount + $staleCount)")
            [void]$sb.AppendLine("  Active:         $activeCount")
            [void]$sb.AppendLine("  Stale (90+ d):  $staleCount")
            [void]$sb.AppendLine("Not Found in AD:  $notFound")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("")

            # Group by Organization extracted from location
            $orgGrouped = $Results | Where-Object { $_["_status"] -ne "Not Found" } | ForEach-Object {
                $locVal = $_.location
                $orgVal = ""
                if ($locVal -ne $null -and "$locVal" -ne "") {
                    if ("$locVal" -match "ORGANIZATION:\s*([^;]+)") { $orgVal = $Matches[1].Trim() }
                }
                if ($orgVal -eq "") { $orgVal = $_["_squadron"] }
                $_ | Add-Member -NotePropertyName "_org" -NotePropertyValue $orgVal -PassThru -Force
            } | Group-Object _org | Sort-Object Count -Descending

            [void]$sb.AppendLine("COMPUTERS PER ORGANIZATION")
            [void]$sb.AppendLine("----------------------------------------")
            foreach ($group in $orgGrouped) {
                [void]$sb.AppendLine("  $($group.Count.ToString().PadLeft(4))  $($group.Name)")
            }
            if ($notFound -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("NOT FOUND ($notFound):")
                [void]$sb.AppendLine("----------------------------------------")
                foreach ($nf in ($Results | Where-Object { $_["_status"] -eq "Not Found" })) {
                    [void]$sb.AppendLine("  $($nf.name)")
                }
            }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("Click Export CSV to save results.")
            [void]$sb.AppendLine("Double click a row for full details.")
            $txtBoxSearchResults.Text = $sb.ToString()

            # Auto-prompt for CSV export
            $exportNow = [System.Windows.Forms.MessageBox]::Show(
                "Scan complete: $($Results.Count) computers scanned.`n`n" +
                "Found: $($activeCount + $staleCount)  |  Not Found: $notFound`n" +
                "Organizations identified: $($orgGrouped.Count)`n`n" +
                "Export results to CSV now?",
                "Bulk Scan Complete", 'YesNo', 'Question')
            if ($exportNow -eq 'Yes') { Export-BulkCSV }
        }
        "BaseUsers" {
            # Check for error result
            if ($Results.Count -gt 0 -and $Results[0] -is [hashtable] -and $Results[0].ContainsKey("_Error")) {
                $txtBoxSearchResults.Text = $Results[0]["_Error"]
                $statusBar.Text = "Status: Base users search error."
                return
            }

            $listViewResults.Columns.Add("Display Name", 200) | Out-Null
            $listViewResults.Columns.Add("Account", 140) | Out-Null
            $listViewResults.Columns.Add("Privilege", 85) | Out-Null
            $listViewResults.Columns.Add("Organization", 100) | Out-Null
            $listViewResults.Columns.Add("Title", 140) | Out-Null
            $listViewResults.Columns.Add("Email", 180) | Out-Null

            $privCount = 0; $stdCount = 0
            # Sort: privileged first, then alphabetical
            $sorted = $Results | Sort-Object { $_["_isPrivileged"] } -Descending | Sort-Object { $_["_privLevel"] }, { $_.displayname }

            # The ListView is built from $sorted, but row-index lookups (detail
            # pane / double-click) read $script:cachedResults by position. Cache
            # the displayed order so the right account is resolved.
            $script:cachedResults = $sorted

            foreach ($user in $sorted) {
                $name = if ($user.displayname -ne $null) { "$($user.displayname)" } else { "$($user.samaccountname)" }
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                $item.SubItems.Add("$($user.samaccountname)") | Out-Null
                $item.SubItems.Add($user["_privLevel"]) | Out-Null
                $orgVal = $user["_organization"]
                if ($orgVal -eq "") { $orgVal = $user["_parentOU"] }
                $item.SubItems.Add($orgVal) | Out-Null
                $titleVal = $user.title
                if ($titleVal -eq $null) { $titleVal = "" }
                $item.SubItems.Add("$titleVal") | Out-Null
                $item.SubItems.Add($user["_email"]) | Out-Null

                if ($user["_isPrivileged"] -eq $true) {
                    $item.ForeColor = $clrWarning
                    $privCount++
                } else {
                    $item.ForeColor = $clrLightGray
                    $stdCount++
                }
                $listViewResults.Items.Add($item) | Out-Null
            }

            # Build summary
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("BASE USERS EXPORT")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("Base: $($txtBoxBaseName.Text.Trim())")
            [void]$sb.AppendLine("Total Users Found: $($Results.Count)")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("  PRIVILEGED:            $privCount")
            [void]$sb.AppendLine("    (.adw/.adf/.adm/.ada/.adn/.SA)")
            [void]$sb.AppendLine("    (display name with (ADM))")
            [void]$sb.AppendLine("  STANDARD:              $stdCount")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("SEARCHED OUs:")
            [void]$sb.AppendLine("----------------------------------------")
            if ($Results.Count -gt 0) {
                $sourceOUs = $Results | ForEach-Object { $_["_sourceOU"] } | Where-Object { $_ -ne "" } | Sort-Object -Unique
                if ($sourceOUs) {
                    foreach ($sou in $sourceOUs) {
                        $ouType = "Standard"
                        # OUs with "AFB" but NOT "Users" = privileged, or "Administrative" = privileged
                        if (($sou -match "AFB" -and $sou -notmatch "Users") -or $sou -match "Administrative") {
                            $ouType = "Privileged"
                        }
                        [void]$sb.AppendLine("  [$ouType] $sou")
                    }
                } else {
                    [void]$sb.AppendLine("  (source OU info not available)")
                }
            }
            [void]$sb.AppendLine("")

            # Privileged account details
            if ($privCount -gt 0) {
                [void]$sb.AppendLine("PRIVILEGED ACCOUNTS ($privCount)")
                [void]$sb.AppendLine("----------------------------------------")
                foreach ($user in $sorted) {
                    if ($user["_isPrivileged"] -eq $true) {
                        $sam = "$($user.samaccountname)"
                        $reason = $user["_privReason"]
                        [void]$sb.AppendLine("  $sam")
                        [void]$sb.AppendLine("    Reason: $reason")
                    }
                }
                [void]$sb.AppendLine("")
            }

            # Group by organization
            $orgGrouped = $Results | ForEach-Object {
                $o = $_["_organization"]
                if ($o -eq "") { $o = $_["_parentOU"] }
                $_ | Add-Member -NotePropertyName "_orgDisplay" -NotePropertyValue $o -PassThru -Force
            } | Group-Object _orgDisplay | Sort-Object Count -Descending

            [void]$sb.AppendLine("USERS PER ORGANIZATION")
            [void]$sb.AppendLine("----------------------------------------")
            foreach ($group in $orgGrouped) {
                $gPriv = @($group.Group | Where-Object { $_["_isPrivileged"] -eq $true }).Count
                $gStd  = $group.Count - $gPriv
                [void]$sb.AppendLine("  $($group.Count.ToString().PadLeft(4))  $($group.Name)  (P:$gPriv / S:$gStd)")
            }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("Amber = Privileged  |  Gray = Standard")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("Click Save or use Export CSV to export.")
            [void]$sb.AppendLine("Double click a row for full details.")
            $txtBoxSearchResults.Text = $sb.ToString()

            # Auto-prompt for CSV export
            $exportNow = [System.Windows.Forms.MessageBox]::Show(
                "Base Users scan complete.`n`n" +
                "Total: $($Results.Count)  |  Privileged: $privCount  |  Standard: $stdCount`n`n" +
                "Export results to CSV now?",
                "Base Users Export", 'YesNo', 'Question')
            if ($exportNow -eq 'Yes') { Export-BaseUsersCSV }
        }
        "LastPC" {
            if ($Results.Count -gt 0 -and $Results[0] -is [hashtable] -and $Results[0].ContainsKey("_Error")) {
                $txtBoxSearchResults.Text = $Results[0]["_Error"]
                $statusBar.Text = "STATUS :: LASTPC :: NO MATCH"
                return
            }

            $listViewResults.Columns.Add("User",       180) | Out-Null
            $listViewResults.Columns.Add("Computer",   140) | Out-Null
            $listViewResults.Columns.Add("IP Address", 110) | Out-Null
            $listViewResults.Columns.Add("Last Seen",  140) | Out-Null
            $listViewResults.Columns.Add("Event",       55) | Out-Null
            $listViewResults.Columns.Add("DC",          90) | Out-Null

            foreach ($row in $Results) {
                $name = "$($row['_displayName'])"
                if ($name -eq "") { $name = "$($row['_sam'])" }
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                $item.ForeColor = $clrLightGray
                $item.SubItems.Add("$($row['_computerName'])") | Out-Null
                $item.SubItems.Add("$($row['_ipAddress'])")    | Out-Null
                $item.SubItems.Add("$($row['_timeStr'])")      | Out-Null
                $item.SubItems.Add("$($row['_eventId'])")      | Out-Null
                $item.SubItems.Add("$($row['_dcShort'])")      | Out-Null
                $listViewResults.Items.Add($item) | Out-Null
            }

            $first = $Results[0]
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("LAST WORKSTATION LOOKUP")
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("First Name : $($txtBoxUserFirstName.Text.Trim())")
            [void]$sb.AppendLine("Last Name  : $($txtBoxUserLastName.Text.Trim())")
            [void]$sb.AppendLine("EDIPI      : $($txtBoxUserEDIPI.Text.Trim())")
            [void]$sb.AppendLine("Window     : last $($first['_daysBack']) day(s)")
            [void]$sb.AppendLine("DCs Scanned: $($first['_dcsScanned']) of $($first['_dcsTotal'])")
            [void]$sb.AppendLine("Events Found: $($first['_eventCount'])")
            [void]$sb.AppendLine("Distinct PCs: $($Results.Count)")
            if ($first['_userTruncated'] -eq $true) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("(Note: too many users matched the name; only the first")
                [void]$sb.AppendLine(" 5 were scanned.  Narrow the name or pass an EDIPI.)")
            }
            [void]$sb.AppendLine("========================================")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("Most recent first.  Double-click a row")
            [void]$sb.AppendLine("for the source DC, IP, and logon type.")
            if ($first['_dcErrors'] -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("DC errors (skipped):")
                [void]$sb.AppendLine("----------------------------------------")
                foreach ($ln in ("$($first['_dcErrors'])" -split "`n")) {
                    if ($ln.Trim() -ne "") { [void]$sb.AppendLine("  $ln") }
                }
            }
            $txtBoxSearchResults.Text = $sb.ToString()
        }
    }
    $listViewResults.AutoResizeColumns("HeaderSize")
}

# ==========================================================================
#  VISIBILITY TOGGLE
# ==========================================================================
function Update-SearchFieldVisibility {
    param([string]$ActiveSearch)

    # Hide all search input fields
    $lblUserFirstName.Visible    = $false; $txtBoxUserFirstName.Visible = $false; $txtBoxUserFirstName.Enabled = $false
    $lblUserLastName.Visible     = $false; $txtBoxUserLastName.Visible  = $false; $txtBoxUserLastName.Enabled  = $false
    $lblUserEDIPI.Visible        = $false; $txtBoxUserEDIPI.Visible     = $false; $txtBoxUserEDIPI.Enabled     = $false
    $lblComputer.Visible         = $false; $txtBoxComputerName.Visible  = $false; $txtBoxComputerName.Enabled  = $false
    $lblSecurityDistributionList.Visible = $false; $txtBoxGroupName.Visible = $false; $txtBoxGroupName.Enabled = $false
    $lblUser.Visible             = $false; $txtBoxOrgBox.Visible        = $false; $txtBoxOrgBox.Enabled        = $false
    $lblEmailAddress.Visible     = $false; $txtBoxEmailAddress.Visible  = $false; $txtBoxEmailAddress.Enabled  = $false
    $lblManagerName.Visible      = $false; $txtBoxManagerName.Visible   = $false; $txtBoxManagerName.Enabled   = $false
    $lblBaseName.Visible         = $false; $txtBoxBaseName.Visible      = $false; $txtBoxBaseName.Enabled      = $false
    $lblLastPCDays.Visible       = $false; $txtBoxLastPCDays.Visible    = $false; $txtBoxLastPCDays.Enabled    = $false
    $pnlBulk.Visible             = $false

    # Show search inputs panel for non-bulk, hide for bulk
    $pnlSearchInputs.Visible = ($ActiveSearch -ne "BulkComputer")

    switch ($ActiveSearch) {
        "User" {
            $lblUserFirstName.Visible = $true; $txtBoxUserFirstName.Visible = $true; $txtBoxUserFirstName.Enabled = $true
            $lblUserLastName.Visible  = $true; $txtBoxUserLastName.Visible  = $true; $txtBoxUserLastName.Enabled  = $true
            $lblUserEDIPI.Visible     = $true; $txtBoxUserEDIPI.Visible     = $true; $txtBoxUserEDIPI.Enabled     = $true
            $lblSearchDescription.Text = "Search for user accounts by first name, last name, or EDIPI number."
        }
        "Computer" {
            $lblComputer.Visible = $true; $txtBoxComputerName.Visible = $true; $txtBoxComputerName.Enabled = $true
            $lblSearchDescription.Text = "Search for computer objects by computer name."
        }
        "Group" {
            $lblSecurityDistributionList.Visible = $true; $txtBoxGroupName.Visible = $true; $txtBoxGroupName.Enabled = $true
            $lblSearchDescription.Text = "Search for security groups or distribution lists by name."
        }
        "OrgBox" {
            $lblUser.Visible = $true; $txtBoxOrgBox.Visible = $true; $txtBoxOrgBox.Enabled = $true
            $lblSearchDescription.Text = "Search for organizational boxes/accounts by name."
        }
        "Email" {
            $lblEmailAddress.Visible = $true; $txtBoxEmailAddress.Visible = $true; $txtBoxEmailAddress.Enabled = $true
            $lblSearchDescription.Text = "Search for user accounts by email address."
        }
        "Manager" {
            $lblManagerName.Visible = $true; $txtBoxManagerName.Visible = $true; $txtBoxManagerName.Enabled = $true
            $lblSearchDescription.Text = "Search for a manager's direct reports by display name."
        }
        "BulkComputer" {
            $pnlBulk.Visible = $true
            $lblSearchDescription.Text = "Paste computer names (one per line) or import a TXT file, then click Search."
        }
        "BaseUsers" {
            $lblBaseName.Visible = $true; $txtBoxBaseName.Visible = $true; $txtBoxBaseName.Enabled = $true
            $lblSearchDescription.Text = "Searches Users OU (standard) + AFB/Administrative OU (privileged). Separated by account suffix."
        }
        "LastPC" {
            $lblUserFirstName.Visible = $true; $txtBoxUserFirstName.Visible = $true; $txtBoxUserFirstName.Enabled = $true
            $lblUserLastName.Visible  = $true; $txtBoxUserLastName.Visible  = $true; $txtBoxUserLastName.Enabled  = $true
            $lblUserEDIPI.Visible     = $true; $txtBoxUserEDIPI.Visible     = $true; $txtBoxUserEDIPI.Enabled     = $true
            $lblLastPCDays.Visible    = $true; $txtBoxLastPCDays.Visible    = $true; $txtBoxLastPCDays.Enabled    = $true
            $lblSearchDescription.Text = "Find what workstation a person was last on. Scans DC Security logs for Kerberos / logon events. Requires DC log read access."
        }
    }

    # Adjust results cards position based on bulk panel visibility. The
    # listview and richtextbox live INSIDE the cards now, so we only move
    # the cards. Card headers ("/ RESULTS", "/ EXTENDED INFO") re-paint at
    # the new width automatically via Add_SizeChanged -> Invalidate.
    if ($ActiveSearch -eq "BulkComputer") {
        $cardResults.Location = New-Object System.Drawing.Point(243, 165)
        $cardResults.Size     = New-Object System.Drawing.Size(584, 602)
        $listViewResults.Location = New-Object System.Drawing.Point(12, 50)
        $listViewResults.Size     = New-Object System.Drawing.Size(560, 542)
        $cardExtended.Location = New-Object System.Drawing.Point(829, 165)
        $cardExtended.Size     = New-Object System.Drawing.Size(468, 602)
        $txtBoxSearchResults.Location = New-Object System.Drawing.Point(12, 50)
        $txtBoxSearchResults.Size = New-Object System.Drawing.Size(444, 542)
    } else {
        $cardResults.Location = New-Object System.Drawing.Point(3, 165)
        $cardResults.Size     = New-Object System.Drawing.Size(754, 602)
        $listViewResults.Location = New-Object System.Drawing.Point(12, 50)
        $listViewResults.Size     = New-Object System.Drawing.Size(730, 542)
        $cardExtended.Location = New-Object System.Drawing.Point(759, 165)
        $cardExtended.Size     = New-Object System.Drawing.Size(538, 602)
        $txtBoxSearchResults.Location = New-Object System.Drawing.Point(12, 50)
        $txtBoxSearchResults.Size = New-Object System.Drawing.Size(514, 542)
    }

    $listViewResults.Items.Clear()
    $listViewResults.Columns.Clear()
}

# ==========================================================================
#  MAIN FORM
# ==========================================================================
$ADSearchTool                    = New-Object System.Windows.Forms.Form
$ADSearchTool.ClientSize         = New-Object System.Drawing.Size(1300, 800)
$ADSearchTool.Text               = "J.A.N.E.T. - AD Search Tool v$($script:VersionNumber)"
$ADSearchTool.FormBorderStyle    = 'FixedSingle'
$ADSearchTool.MaximizeBox        = $false
$ADSearchTool.StartPosition      = 'CenterScreen'
$ADSearchTool.BackColor          = $cBg
$ADSearchTool.ForeColor          = $cText
$ADSearchTool.Font               = $fBody
Enable-DoubleBuffer -Control $ADSearchTool
$ADSearchTool.Add_HandleCreated({ Set-JanetDarkTitleBar -Form $ADSearchTool })
$ADSearchTool.Add_Load({ Set-JanetDarkTitleBar -Form $ADSearchTool })

# Clean up on close - stop all pulse-dot timers plus the search runspace
Set-JanetAllowClose $false
$ADSearchTool.Add_FormClosing({
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

    if ($searchTimer -ne $null) { $searchTimer.Stop() }
    foreach ($dot in @($script:dotStatus, $script:dotCred, $script:dotLive)) {
        if ($dot -and $dot.Tag -and $dot.Tag.Timer) {
            try { $dot.Tag.Timer.Stop(); $dot.Tag.Timer.Dispose() } catch {}
        }
    }
    if ($script:ClockTimer) { try { $script:ClockTimer.Stop(); $script:ClockTimer.Dispose() } catch {} }
    if ($script:currentPowerShell -ne $null) { try { $script:currentPowerShell.Stop(); $script:currentPowerShell.Dispose() } catch {} }
    if ($script:currentRunspace -ne $null) { try { $script:currentRunspace.Close(); $script:currentRunspace.Dispose() } catch {} }
})

# ==========================================================================
#  HEADER PANEL - tactical brand strip with scanline overlay
# ==========================================================================
$pnlHeader               = New-Object System.Windows.Forms.Panel
$pnlHeader.Location      = New-Object System.Drawing.Point(0, 0)
$pnlHeader.Size          = New-Object System.Drawing.Size(1300, 55)
$pnlHeader.BackColor     = $cHeaderBg
Add-ScanlineOverlay -Panel $pnlHeader

# Close Tool — top-right of the header strip (matches WPT pattern).
# Single sanctioned form egress: sets the X-block allow flag, then
# closes; FormClosing guard cancels every other origin.
$btnHdrCloseTool         = New-GhostButton -Text "CLOSE TOOL" -X 1180 -Y 15 -W 100 -H 24 -Fg $cRed
$btnHdrCloseTool.Anchor  = 'Top,Right'
$btnHdrCloseTool.Add_Click({
    Set-JanetAllowClose $true
    $ADSearchTool.Close()
}.GetNewClosure())
$pnlHeader.Controls.Add($btnHdrCloseTool)

# Eyebrow callsign - monospace, amber, uppercase
$lblEyebrow              = New-Object System.Windows.Forms.Label
$lblEyebrow.Text         = "/ JOINT ADMINISTRATION AND NETWORK EXECUTION TOOLKIT"
$lblEyebrow.Font         = $fEyebrowSm
$lblEyebrow.ForeColor    = $cAccent
$lblEyebrow.AutoSize     = $false
$lblEyebrow.Size         = New-Object System.Drawing.Size(700, 14)
$lblEyebrow.Location     = New-Object System.Drawing.Point(58, 4)
$lblEyebrow.BackColor    = [System.Drawing.Color]::Transparent

# Primary wordmark - Cascadia Mono, amber
$lblTitle                = New-Object System.Windows.Forms.Label
$lblTitle.Text           = "J.A.N.E.T."
$lblTitle.Font           = $fDisplayLg
$lblTitle.ForeColor      = $cAccent
$lblTitle.AutoSize       = $false
$lblTitle.Size           = New-Object System.Drawing.Size(160, 22)
$lblTitle.Location       = New-Object System.Drawing.Point(58, 18)
$lblTitle.BackColor      = [System.Drawing.Color]::Transparent

# Subtitle - mono small, muted
$lblSubtitle             = New-Object System.Windows.Forms.Label
$lblSubtitle.Text        = "AD SEARCH TOOL  //  DIRECTORY LOOKUP"
$lblSubtitle.Font        = $fMonoSm
$lblSubtitle.ForeColor   = $cTextDim
$lblSubtitle.AutoSize    = $false
$lblSubtitle.Size        = New-Object System.Drawing.Size(360, 16)
$lblSubtitle.Location    = New-Object System.Drawing.Point(220, 21)
$lblSubtitle.BackColor   = [System.Drawing.Color]::Transparent

# Version tag - mono tiny, faint
$lblVerTag               = New-Object System.Windows.Forms.Label
$lblVerTag.Text          = "v$($script:VersionNumber)"
$lblVerTag.Font          = $fMonoTiny
$lblVerTag.ForeColor     = $cTextFaint
$lblVerTag.AutoSize      = $false
$lblVerTag.Size          = New-Object System.Drawing.Size(80, 12)
$lblVerTag.Location      = New-Object System.Drawing.Point(220, 38)
$lblVerTag.BackColor     = [System.Drawing.Color]::Transparent

# Credential cluster - eyebrow label, blinking pulse dot, monospace state
# line. Sits right of the title cluster inside the 55px header strip.
# Layout (header height 55):
#   y=8  : eyebrow "/ CRED"   (mono 8 bold, muted)
#   y=26 : dot (8px) + state line (mono 9)
$credClusterX            = 640

$lblCredEyebrow          = New-Object System.Windows.Forms.Label
$lblCredEyebrow.Text     = "/ CRED"
$lblCredEyebrow.Font     = $fEyebrowSm
$lblCredEyebrow.ForeColor= $cAccent
$lblCredEyebrow.AutoSize = $false
$lblCredEyebrow.Size     = New-Object System.Drawing.Size(80, 14)
$lblCredEyebrow.Location = New-Object System.Drawing.Point($credClusterX, 8)
$lblCredEyebrow.BackColor= [System.Drawing.Color]::Transparent

# Dot blinks olive when a launcher credential was inherited via
# $env:JANET_CRED_FILE. Solid muted (Idle) when running standalone.
$credDotState            = if ($script:InheritedCred) { 'Active' } else { 'Idle' }
$script:dotCred          = New-PulseDot -X ($credClusterX) -Y 29 -Size 9 -State $credDotState

$lblCredState            = New-Object System.Windows.Forms.Label
if ($script:InheritedCred) {
    $lblCredState.Text      = ("INHERITED :: {0}" -f $script:InheritedCred.UserName)
    $lblCredState.ForeColor = $cGreen
} else {
    $lblCredState.Text      = "STANDALONE :: current user token"
    $lblCredState.ForeColor = $cTextDim
}
$lblCredState.Font       = $fMonoSm
$lblCredState.AutoSize   = $false
$lblCredState.Size       = New-Object System.Drawing.Size(540, 16)
$lblCredState.Location   = New-Object System.Drawing.Point(($credClusterX + 14), 26)
$lblCredState.BackColor  = [System.Drawing.Color]::Transparent

# Search description - moved down, still shown below radios when asked
$lblSearchDescription    = New-Object System.Windows.Forms.Label
$lblSearchDescription.Text = "Search for user accounts by first name, last name, or EDIPI number."
$lblSearchDescription.Font = $fMonoTiny
$lblSearchDescription.ForeColor = $cTextMuted
$lblSearchDescription.AutoSize  = $false
$lblSearchDescription.Size      = New-Object System.Drawing.Size(500, 18)
$lblSearchDescription.Location  = New-Object System.Drawing.Point(60, 38)
$lblSearchDescription.BackColor = [System.Drawing.Color]::Transparent
$lblSearchDescription.Visible   = $false

$pnlHeader.Controls.AddRange(@(
    $lblEyebrow, $lblTitle, $lblSubtitle, $lblVerTag,
    $script:dotCred, $lblCredEyebrow, $lblCredState,
    $lblSearchDescription
))

# ==========================================================================
#  SEARCH OPTIONS + ACTION BUTTONS PANEL (corner-bracket brief box)
# ==========================================================================
$pnlOptions              = New-Object System.Windows.Forms.Panel
$pnlOptions.Location     = New-Object System.Drawing.Point(0, 55)
$pnlOptions.Size         = New-Object System.Drawing.Size(1300, 55)
$pnlOptions.BackColor    = $cPanel
Add-CornerBrackets -Panel $pnlOptions -BracketLen 12 -BracketThick 1

# Small eyebrow label for the radio group ("SEARCH MODE")
$lblModeHdr              = New-Object System.Windows.Forms.Label
$lblModeHdr.Text         = "/ MODE"
$lblModeHdr.Font         = $fEyebrowSm
$lblModeHdr.ForeColor    = $cAccent
$lblModeHdr.Size         = New-Object System.Drawing.Size(60, 14)
$lblModeHdr.Location     = New-Object System.Drawing.Point(12, 4)
$lblModeHdr.BackColor    = [System.Drawing.Color]::Transparent

# Radio buttons - row 1 (tactical mono, amber check)
$RBUserSearch            = New-Object System.Windows.Forms.RadioButton
$RBUserSearch.Text       = "USERS"; $RBUserSearch.Font = $fntRadio; $RBUserSearch.ForeColor = $cText
$RBUserSearch.AutoSize   = $true; $RBUserSearch.Checked = $true
$RBUserSearch.Location   = New-Object System.Drawing.Point(75, 4); $RBUserSearch.BackColor = [System.Drawing.Color]::Transparent
$RBUserSearch.FlatStyle  = 'Flat'; $RBUserSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "User" })

$RBComputerSearch        = New-Object System.Windows.Forms.RadioButton
$RBComputerSearch.Text   = "COMPUTERS"; $RBComputerSearch.Font = $fntRadio; $RBComputerSearch.ForeColor = $cText
$RBComputerSearch.AutoSize = $true; $RBComputerSearch.Location = New-Object System.Drawing.Point(155, 4)
$RBComputerSearch.BackColor = [System.Drawing.Color]::Transparent; $RBComputerSearch.FlatStyle = 'Flat'
$RBComputerSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "Computer" })

$RBGroupSearch           = New-Object System.Windows.Forms.RadioButton
$RBGroupSearch.Text      = "GROUPS"; $RBGroupSearch.Font = $fntRadio; $RBGroupSearch.ForeColor = $cText
$RBGroupSearch.AutoSize  = $true; $RBGroupSearch.Location = New-Object System.Drawing.Point(265, 4)
$RBGroupSearch.BackColor = [System.Drawing.Color]::Transparent; $RBGroupSearch.FlatStyle = 'Flat'
$RBGroupSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "Group" })

$RBOrgBoxSearch          = New-Object System.Windows.Forms.RadioButton
$RBOrgBoxSearch.Text     = "ORG BOXES"; $RBOrgBoxSearch.Font = $fntRadio; $RBOrgBoxSearch.ForeColor = $cText
$RBOrgBoxSearch.AutoSize = $true; $RBOrgBoxSearch.Location = New-Object System.Drawing.Point(350, 4)
$RBOrgBoxSearch.BackColor = [System.Drawing.Color]::Transparent; $RBOrgBoxSearch.FlatStyle = 'Flat'
$RBOrgBoxSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "OrgBox" })

# Radio buttons - row 2
$RBEmailSearch           = New-Object System.Windows.Forms.RadioButton
$RBEmailSearch.Text      = "BY EMAIL"; $RBEmailSearch.Font = $fntRadio; $RBEmailSearch.ForeColor = $cText
$RBEmailSearch.AutoSize  = $true; $RBEmailSearch.Location = New-Object System.Drawing.Point(75, 28)
$RBEmailSearch.BackColor = [System.Drawing.Color]::Transparent; $RBEmailSearch.FlatStyle = 'Flat'
$RBEmailSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "Email" })

$RBManagerSearch         = New-Object System.Windows.Forms.RadioButton
$RBManagerSearch.Text    = "BY MANAGER"; $RBManagerSearch.Font = $fntRadio; $RBManagerSearch.ForeColor = $cText
$RBManagerSearch.AutoSize = $true; $RBManagerSearch.Location = New-Object System.Drawing.Point(170, 28)
$RBManagerSearch.BackColor = [System.Drawing.Color]::Transparent; $RBManagerSearch.FlatStyle = 'Flat'
$RBManagerSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "Manager" })

$RBBulkSearch            = New-Object System.Windows.Forms.RadioButton
$RBBulkSearch.Text       = "BULK COMPUTERS"; $RBBulkSearch.Font = $fntRadio; $RBBulkSearch.ForeColor = $cAccent
$RBBulkSearch.AutoSize   = $true; $RBBulkSearch.Location = New-Object System.Drawing.Point(290, 28)
$RBBulkSearch.BackColor  = [System.Drawing.Color]::Transparent; $RBBulkSearch.FlatStyle = 'Flat'
$RBBulkSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "BulkComputer" })

$RBBaseUsers             = New-Object System.Windows.Forms.RadioButton
$RBBaseUsers.Text        = "BASE USERS EXPORT"; $RBBaseUsers.Font = $fntRadio; $RBBaseUsers.ForeColor = $cAccent
$RBBaseUsers.AutoSize    = $true; $RBBaseUsers.Location = New-Object System.Drawing.Point(440, 28)
$RBBaseUsers.BackColor   = [System.Drawing.Color]::Transparent; $RBBaseUsers.FlatStyle = 'Flat'
$RBBaseUsers.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "BaseUsers" })

# "BY LAST PC" - given a name / EDIPI, scan DC Security logs for the
# last workstation(s) the user authenticated from. Requires read access
# to the Security log on the domain controllers.
$RBLastPCSearch          = New-Object System.Windows.Forms.RadioButton
$RBLastPCSearch.Text     = "BY LAST PC"; $RBLastPCSearch.Font = $fntRadio; $RBLastPCSearch.ForeColor = $cAccent
$RBLastPCSearch.AutoSize = $true; $RBLastPCSearch.Location = New-Object System.Drawing.Point(620, 28)
$RBLastPCSearch.BackColor = [System.Drawing.Color]::Transparent; $RBLastPCSearch.FlatStyle = 'Flat'
$RBLastPCSearch.Add_Click({ Update-SearchFieldVisibility -ActiveSearch "LastPC" })

# Primary SEARCH button - amber with diagonal caution stripe (tactical CTA)
$btnSearch               = New-TacticalButton -Text "SEARCH" -X 950 -Y 10 -W 90 -H 34 -Stripe -Font $fDisplaySm
$btnSearch.Name          = "mainsearch"
$btnSearch.add_MouseHover($ShowHelp)
$btnSearch.Add_Click({ ChooseSearchOptions })
$btnSearch.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# Secondary actions - ghost outline buttons
$btnExport               = New-GhostButton -Text "SAVE"  -X 1048 -Y 13 -W 72 -H 28
$btnExport.Name          = "save"
$btnExport.add_MouseHover($ShowHelp)

$btnClear                = New-GhostButton -Text "CLEAR" -X 1126 -Y 13 -W 72 -H 28 -Fg $cRed
$btnClear.Name           = "clear"
$btnClear.add_MouseHover($ShowHelp)

$btnAbout                = New-GhostButton -Text "ABOUT" -X 1204 -Y 13 -W 72 -H 28

$pnlOptions.Controls.AddRange(@(
    $lblModeHdr,
    $RBUserSearch, $RBComputerSearch, $RBGroupSearch, $RBOrgBoxSearch,
    $RBEmailSearch, $RBManagerSearch, $RBBulkSearch, $RBBaseUsers, $RBLastPCSearch,
    $btnSearch, $btnExport, $btnClear, $btnAbout
))

# ==========================================================================
#  SEARCH INPUT PANEL (for standard searches) - tactical brief box
# ==========================================================================
$pnlSearchInputs         = New-Object System.Windows.Forms.Panel
$pnlSearchInputs.Location = New-Object System.Drawing.Point(0, 110)
$pnlSearchInputs.Size    = New-Object System.Drawing.Size(600, 55)
$pnlSearchInputs.BackColor = $cPanel
Add-CornerBrackets -Panel $pnlSearchInputs -BracketLen 10 -BracketThick 1

# -- User fields --
$lblUserFirstName        = New-Object System.Windows.Forms.Label
$lblUserFirstName.Text   = "First Name"; $lblUserFirstName.Font = $fntLabel; $lblUserFirstName.ForeColor = $clrLightGray
$lblUserFirstName.AutoSize = $true; $lblUserFirstName.Location = New-Object System.Drawing.Point(7, 4)

$txtBoxUserFirstName     = New-Object System.Windows.Forms.TextBox
$txtBoxUserFirstName.Font = $fntInput; $txtBoxUserFirstName.Width = 170; $txtBoxUserFirstName.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxUserFirstName.BackColor = $clrInputBg; $txtBoxUserFirstName.ForeColor = $clrInputText; $txtBoxUserFirstName.BorderStyle = 'FixedSingle'
$txtBoxUserFirstName.CharacterCasing = "Upper"; $txtBoxUserFirstName.Name = "firstname"; $txtBoxUserFirstName.TabIndex = 1
$txtBoxUserFirstName.add_MouseHover($ShowHelp); $txtBoxUserFirstName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

$lblUserLastName         = New-Object System.Windows.Forms.Label
$lblUserLastName.Text    = "Last Name"; $lblUserLastName.Font = $fntLabel; $lblUserLastName.ForeColor = $clrLightGray
$lblUserLastName.AutoSize = $true; $lblUserLastName.Location = New-Object System.Drawing.Point(190, 4)

$txtBoxUserLastName      = New-Object System.Windows.Forms.TextBox
$txtBoxUserLastName.Font = $fntInput; $txtBoxUserLastName.Width = 170; $txtBoxUserLastName.Location = New-Object System.Drawing.Point(190, 26)
$txtBoxUserLastName.BackColor = $clrInputBg; $txtBoxUserLastName.ForeColor = $clrInputText; $txtBoxUserLastName.BorderStyle = 'FixedSingle'
$txtBoxUserLastName.CharacterCasing = "Upper"; $txtBoxUserLastName.Name = "lastname"; $txtBoxUserLastName.TabIndex = 2
$txtBoxUserLastName.add_MouseHover($ShowHelp); $txtBoxUserLastName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

$lblUserEDIPI            = New-Object System.Windows.Forms.Label
$lblUserEDIPI.Text       = "EDIPI/DOD #"; $lblUserEDIPI.Font = $fntLabel; $lblUserEDIPI.ForeColor = $clrLightGray
$lblUserEDIPI.AutoSize   = $true; $lblUserEDIPI.Location = New-Object System.Drawing.Point(373, 4)

$txtBoxUserEDIPI         = New-Object System.Windows.Forms.TextBox
$txtBoxUserEDIPI.Font    = $fntInput; $txtBoxUserEDIPI.Width = 170; $txtBoxUserEDIPI.Location = New-Object System.Drawing.Point(373, 26)
$txtBoxUserEDIPI.BackColor = $clrInputBg; $txtBoxUserEDIPI.ForeColor = $clrInputText; $txtBoxUserEDIPI.BorderStyle = 'FixedSingle'
$txtBoxUserEDIPI.Name = "edipi"; $txtBoxUserEDIPI.TabIndex = 3
$txtBoxUserEDIPI.add_MouseHover($ShowHelp); $txtBoxUserEDIPI.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Computer field --
$lblComputer             = New-Object System.Windows.Forms.Label
$lblComputer.Text        = "Computer Name"; $lblComputer.Font = $fntLabel; $lblComputer.ForeColor = $clrLightGray
$lblComputer.AutoSize    = $true; $lblComputer.Location = New-Object System.Drawing.Point(7, 4); $lblComputer.Visible = $false

$txtBoxComputerName      = New-Object System.Windows.Forms.TextBox
$txtBoxComputerName.Font = $fntInput; $txtBoxComputerName.Width = 350; $txtBoxComputerName.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxComputerName.BackColor = $clrInputBg; $txtBoxComputerName.ForeColor = $clrInputText; $txtBoxComputerName.BorderStyle = 'FixedSingle'
$txtBoxComputerName.CharacterCasing = "Upper"; $txtBoxComputerName.Name = "computername"
$txtBoxComputerName.Visible = $false; $txtBoxComputerName.Enabled = $false
$txtBoxComputerName.add_MouseHover($ShowHelp); $txtBoxComputerName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Group field --
$lblSecurityDistributionList = New-Object System.Windows.Forms.Label
$lblSecurityDistributionList.Text = "Security Group / Distribution List"; $lblSecurityDistributionList.Font = $fntLabel
$lblSecurityDistributionList.ForeColor = $clrLightGray; $lblSecurityDistributionList.AutoSize = $true
$lblSecurityDistributionList.Location = New-Object System.Drawing.Point(7, 4); $lblSecurityDistributionList.Visible = $false

$txtBoxGroupName         = New-Object System.Windows.Forms.TextBox
$txtBoxGroupName.Font    = $fntInput; $txtBoxGroupName.Width = 450; $txtBoxGroupName.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxGroupName.BackColor = $clrInputBg; $txtBoxGroupName.ForeColor = $clrInputText; $txtBoxGroupName.BorderStyle = 'FixedSingle'
$txtBoxGroupName.CharacterCasing = "Upper"; $txtBoxGroupName.Name = "groupname"
$txtBoxGroupName.Visible = $false; $txtBoxGroupName.Enabled = $false
$txtBoxGroupName.add_MouseHover($ShowHelp); $txtBoxGroupName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Org Box field --
$lblUser                 = New-Object System.Windows.Forms.Label
$lblUser.Text            = "Org Box Name"; $lblUser.Font = $fntLabel; $lblUser.ForeColor = $clrLightGray
$lblUser.AutoSize        = $true; $lblUser.Location = New-Object System.Drawing.Point(7, 4); $lblUser.Visible = $false

$txtBoxOrgBox            = New-Object System.Windows.Forms.TextBox
$txtBoxOrgBox.Font       = $fntInput; $txtBoxOrgBox.Width = 450; $txtBoxOrgBox.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxOrgBox.BackColor  = $clrInputBg; $txtBoxOrgBox.ForeColor = $clrInputText; $txtBoxOrgBox.BorderStyle = 'FixedSingle'
$txtBoxOrgBox.CharacterCasing = "Upper"; $txtBoxOrgBox.Name = "orgbox"
$txtBoxOrgBox.Visible    = $false; $txtBoxOrgBox.Enabled = $false
$txtBoxOrgBox.add_MouseHover($ShowHelp); $txtBoxOrgBox.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Email field --
$lblEmailAddress         = New-Object System.Windows.Forms.Label
$lblEmailAddress.Text    = "Email Address"; $lblEmailAddress.Font = $fntLabel; $lblEmailAddress.ForeColor = $clrLightGray
$lblEmailAddress.AutoSize = $true; $lblEmailAddress.Location = New-Object System.Drawing.Point(7, 4); $lblEmailAddress.Visible = $false

$txtBoxEmailAddress      = New-Object System.Windows.Forms.TextBox
$txtBoxEmailAddress.Font = $fntInput; $txtBoxEmailAddress.Width = 450; $txtBoxEmailAddress.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxEmailAddress.BackColor = $clrInputBg; $txtBoxEmailAddress.ForeColor = $clrInputText; $txtBoxEmailAddress.BorderStyle = 'FixedSingle'
$txtBoxEmailAddress.Name = "emailaddress"; $txtBoxEmailAddress.Visible = $false; $txtBoxEmailAddress.Enabled = $false
$txtBoxEmailAddress.add_MouseHover($ShowHelp); $txtBoxEmailAddress.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Manager field --
$lblManagerName          = New-Object System.Windows.Forms.Label
$lblManagerName.Text     = "Manager's Display Name"; $lblManagerName.Font = $fntLabel; $lblManagerName.ForeColor = $clrLightGray
$lblManagerName.AutoSize = $true; $lblManagerName.Location = New-Object System.Drawing.Point(7, 4); $lblManagerName.Visible = $false

$txtBoxManagerName       = New-Object System.Windows.Forms.TextBox
$txtBoxManagerName.Font  = $fntInput; $txtBoxManagerName.Width = 450; $txtBoxManagerName.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxManagerName.BackColor = $clrInputBg; $txtBoxManagerName.ForeColor = $clrInputText; $txtBoxManagerName.BorderStyle = 'FixedSingle'
$txtBoxManagerName.Name  = "managername"; $txtBoxManagerName.Visible = $false; $txtBoxManagerName.Enabled = $false
$txtBoxManagerName.add_MouseHover($ShowHelp); $txtBoxManagerName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Base Users field --
$lblBaseName             = New-Object System.Windows.Forms.Label
$lblBaseName.Text        = "Base / Location Name (e.g. LAKENHEATH, RAMSTEIN)"; $lblBaseName.Font = $fntLabel; $lblBaseName.ForeColor = $clrLightGray
$lblBaseName.AutoSize    = $true; $lblBaseName.Location = New-Object System.Drawing.Point(7, 4); $lblBaseName.Visible = $false

$txtBoxBaseName          = New-Object System.Windows.Forms.TextBox
$txtBoxBaseName.Font     = $fntInput; $txtBoxBaseName.Width = 350; $txtBoxBaseName.Location = New-Object System.Drawing.Point(7, 26)
$txtBoxBaseName.BackColor = $clrInputBg; $txtBoxBaseName.ForeColor = $clrInputText; $txtBoxBaseName.BorderStyle = 'FixedSingle'
$txtBoxBaseName.CharacterCasing = "Upper"; $txtBoxBaseName.Name = "basename"
$txtBoxBaseName.Visible  = $false; $txtBoxBaseName.Enabled = $false
$txtBoxBaseName.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

# -- Days-back field (LastPC mode only). Shares the row with the user
#    fields; visible only when LastPC is the active mode.
$lblLastPCDays           = New-Object System.Windows.Forms.Label
$lblLastPCDays.Text      = "Days Back"; $lblLastPCDays.Font = $fntLabel; $lblLastPCDays.ForeColor = $clrLightGray
$lblLastPCDays.AutoSize  = $true; $lblLastPCDays.Location = New-Object System.Drawing.Point(553, 4); $lblLastPCDays.Visible = $false

$txtBoxLastPCDays        = New-Object System.Windows.Forms.TextBox
$txtBoxLastPCDays.Font   = $fntInput; $txtBoxLastPCDays.Width = 40; $txtBoxLastPCDays.Location = New-Object System.Drawing.Point(553, 26)
$txtBoxLastPCDays.BackColor = $clrInputBg; $txtBoxLastPCDays.ForeColor = $clrInputText; $txtBoxLastPCDays.BorderStyle = 'FixedSingle'
$txtBoxLastPCDays.Name   = "lastpcdays"; $txtBoxLastPCDays.Text = "14"
$txtBoxLastPCDays.Visible = $false; $txtBoxLastPCDays.Enabled = $false
$txtBoxLastPCDays.Add_KeyDown({ if ($_.KeyCode -eq "Enter") { ChooseSearchOptions } })

$pnlSearchInputs.Controls.AddRange(@(
    $lblUserFirstName, $txtBoxUserFirstName, $lblUserLastName, $txtBoxUserLastName, $lblUserEDIPI, $txtBoxUserEDIPI,
    $lblComputer, $txtBoxComputerName, $lblSecurityDistributionList, $txtBoxGroupName,
    $lblUser, $txtBoxOrgBox, $lblEmailAddress, $txtBoxEmailAddress, $lblManagerName, $txtBoxManagerName,
    $lblBaseName, $txtBoxBaseName, $lblLastPCDays, $txtBoxLastPCDays
))

# ==========================================================================
#  BULK COMPUTER PANEL - tactical brief box, replaces inputs in Bulk mode.
#  Y range: 110..730 (width 240). Leaves y=730..770 clear for status room.
# ==========================================================================
$pnlBulk                = New-Object System.Windows.Forms.Panel
$pnlBulk.Location       = New-Object System.Drawing.Point(0, 110)
$pnlBulk.Size           = New-Object System.Drawing.Size(240, 620)
$pnlBulk.BackColor      = $cPanel
$pnlBulk.Visible        = $false
Add-CornerBrackets -Panel $pnlBulk -Header "MACHINE LIST" -BracketLen 14 -BracketThick 2

$btnImportTxt            = New-GhostButton -Text "IMPORT TXT" -X 130 -Y 14 -W 96 -H 22 -Font $fEyebrowSm
$btnImportTxt.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title = "Import Computer Names"
    if ($openDialog.ShowDialog() -eq 'OK') {
        try {
            $lines = [System.IO.File]::ReadAllLines($openDialog.FileName)
            $cleaned = @()
            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ($trimmed -ne "" -and $trimmed -notmatch "^#") {
                    $val = ($trimmed -split ",")[0].Trim().Trim('"')
                    if ($val -ne "" -and $val -notmatch "^(ComputerName|Computer Name|Name|Hostname)$") {
                        $cleaned += $val.ToUpper()
                    }
                }
            }
            $txtBulkList.Text = $cleaned -join "`r`n"
            $statusBar.Text = "IMPORTED :: $($cleaned.Count) HOSTNAMES"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error reading file: $($_.Exception.Message)", "Import Error", 'OK', 'Error')
        }
    }
})

$txtBulkList             = New-Object System.Windows.Forms.TextBox
$txtBulkList.Multiline   = $true; $txtBulkList.ScrollBars = 'Vertical'; $txtBulkList.WordWrap = $false
$txtBulkList.Font        = $fntBulk; $txtBulkList.Location = New-Object System.Drawing.Point(14, 50)
$txtBulkList.Size        = New-Object System.Drawing.Size(212, 510)
$txtBulkList.BackColor   = $cConsoleBg; $txtBulkList.ForeColor = $cText; $txtBulkList.BorderStyle = 'FixedSingle'
$txtBulkList.CharacterCasing = "Upper"

$lblBulkCount            = New-Object System.Windows.Forms.Label
$lblBulkCount.Text       = "00 TARGETS"; $lblBulkCount.Font = $fMonoTiny
$lblBulkCount.ForeColor  = $cTextDim; $lblBulkCount.AutoSize = $false
$lblBulkCount.Size       = New-Object System.Drawing.Size(120, 14)
$lblBulkCount.Location   = New-Object System.Drawing.Point(14, 564)
$lblBulkCount.BackColor  = [System.Drawing.Color]::Transparent

$txtBulkList.Add_TextChanged({
    $lines = $txtBulkList.Text -split "`r`n|`n|`r" | Where-Object { $_.Trim() -ne "" }
    $lblBulkCount.Text = ("{0:D2} TARGETS" -f [int]$lines.Count)
})

$btnExportCSV            = New-GhostButton -Text "EXPORT CSV" -X 14  -Y 584 -W 102 -H 28 -Font $fEyebrow
$btnExportCSV.Add_Click({ Export-BulkCSV })

$btnBulkClear            = New-GhostButton    -Text "CLEAR"      -X 124 -Y 584 -W 102 -H 28 -Font $fEyebrow -Fg $cRed
$btnBulkClear.Add_Click({ $txtBulkList.Text = "" })

$pnlBulk.Controls.AddRange(@($btnImportTxt, $txtBulkList, $lblBulkCount, $btnExportCSV, $btnBulkClear))

# ==========================================================================
#  RESULTS AREA - two brief-box cards side by side (Results | Extended Info)
#  Cards own their eyebrow headers; the listview and richtextbox live inside.
#  Y geometry: cards at y=165 h=602 (ends at 767). Status bar at y=770 h=28.
# ==========================================================================
$cardResults             = New-Object System.Windows.Forms.Panel
$cardResults.Location    = New-Object System.Drawing.Point(3, 165)
$cardResults.Size        = New-Object System.Drawing.Size(754, 602)
$cardResults.BackColor   = $cPanel
Add-CornerBrackets -Panel $cardResults -Header "RESULTS" -BracketLen 14 -BracketThick 2

$listViewResults         = New-Object System.Windows.Forms.ListView
$listViewResults.Location = New-Object System.Drawing.Point(12, 50)
$listViewResults.Size    = New-Object System.Drawing.Size(730, 542)
$listViewResults.View    = "Details"; $listViewResults.GridLines = $true; $listViewResults.FullRowSelect = $true
$listViewResults.MultiSelect = $false; $listViewResults.Scrollable = $true
$listViewResults.BackColor = $cConsoleBg; $listViewResults.ForeColor = $cTextDim
$listViewResults.BorderStyle = 'FixedSingle'
$listViewResults.Font    = $fMonoSm
$cardResults.Controls.Add($listViewResults)

$cardExtended            = New-Object System.Windows.Forms.Panel
$cardExtended.Location   = New-Object System.Drawing.Point(759, 165)
$cardExtended.Size       = New-Object System.Drawing.Size(538, 602)
$cardExtended.BackColor  = $cPanel
Add-CornerBrackets -Panel $cardExtended -Header "EXTENDED INFO" -BracketLen 14 -BracketThick 2

$txtBoxSearchResults     = New-Object System.Windows.Forms.RichTextBox
$txtBoxSearchResults.Location = New-Object System.Drawing.Point(12, 50)
$txtBoxSearchResults.Size = New-Object System.Drawing.Size(514, 542)
$txtBoxSearchResults.Font = $fntResults; $txtBoxSearchResults.BackColor = $cConsoleBg; $txtBoxSearchResults.ForeColor = $cAccentHov
$txtBoxSearchResults.BorderStyle = 'None'; $txtBoxSearchResults.ReadOnly = $true
$txtBoxSearchResults.Text = @"

J.A.N.E.T. AD SEARCH TOOL  v$($script:VersionNumber)
-------------------------------------------------
Created by: NGUYEN, HAI
Edited by:  THOMPSON, BRAXTON - 48 CS

BRIEF / HOW TO USE

1. Select a MODE (USERS, COMPUTERS, GROUPS,
   ORG BOXES, BY EMAIL, BY MANAGER,
   BULK COMPUTERS, BASE USERS EXPORT,
   BY LAST PC).

2. Enter partial or full criteria for the
   selected mode. For BULK COMPUTERS, paste
   hostnames one per line or import a TXT.
   For BY LAST PC, enter a name or EDIPI plus
   an optional Days Back window.

3. Click SEARCH.

4. Double-click a result row for extended info.

5. Click SAVE to export extended info or bulk
   results.

6. Click CLEAR to reset the inputs.

NEW in v3.3
  By Last PC  - Enter a name or EDIPI to find
  what workstation the user last authenticated
  from. Scans every domain controller's
  Security log for Kerberos / logon events
  (4624, 4768, 4769, 4776) tagged with the
  user's sAMAccountName, then reverse-resolves
  source IPs to host names.  Default window
  is 14 days; configurable 1 - 90.  Requires
  Security-log read access on the DCs.

NEW in v3.0
  Bulk Computers  - Paste or import a list of
  machines (200+) to identify the squadron for
  each. Uses the AD Location field to pull
  ORGANIZATION / USER / LAST UPDATE.
  Results can be exported to CSV for reporting.

"@
$cardExtended.Controls.Add($txtBoxSearchResults)

# -- STATUS BAR (custom panel with scanline overlay + blinking pulse dots) --
# Layout:
#   [8px] dotStatus (state-driven: Idle/Active/Error)
#   [ 18px onward ] $statusBar text
#   [ 1070..1150 ]  clock HH:mm:ss
#   [ 1200..1240 ]  "LIVE" label (green)
#   [ 1248..1256 ]  dotLive (always blinking olive - heartbeat/alive)
$pnlStatus               = New-Object System.Windows.Forms.Panel
$pnlStatus.Location      = New-Object System.Drawing.Point(0, 770)
$pnlStatus.Size          = New-Object System.Drawing.Size(1300, 30)
$pnlStatus.BackColor     = $cHeaderBg
Add-ScanlineOverlay -Panel $pnlStatus

# 1px amber accent hairline along the top of the status strip (matches
# the JANET launcher status bar).
$pnlStatusTop            = New-Object System.Windows.Forms.Panel
$pnlStatusTop.Dock       = 'Top'
$pnlStatusTop.Height     = 1
$pnlStatusTop.BackColor  = $cAccentDim
$pnlStatus.Controls.Add($pnlStatusTop)

# Status pulse dot + status text (state-driven - flips to Active olive blink
# during search, Error red blink on failure, else Idle). Close Tool button
# moved to the top-right of $pnlHeader, so the dot can sit at the far left
# of the status strip.
$script:dotStatus        = New-PulseDot -X 12 -Y 12 -Size 8 -State Idle
$pnlStatus.Controls.Add($script:dotStatus)

# Keep the $statusBar name so every downstream "$statusBar.Text = ..." keeps
# working unchanged. It's a Label now, not a StatusBar control.
$statusBar               = New-Object System.Windows.Forms.Label
$statusBar.Text          = "STATUS :: READY"
$statusBar.Font          = $fMonoTiny
$statusBar.ForeColor     = $cTextDim
$statusBar.BackColor     = [System.Drawing.Color]::Transparent
$statusBar.AutoSize      = $false
$statusBar.Size          = New-Object System.Drawing.Size(1040, 18)
$statusBar.Location      = New-Object System.Drawing.Point(28, 7)
$statusBar.TextAlign     = 'MiddleLeft'
$statusBar.AutoEllipsis  = $true
$pnlStatus.Controls.Add($statusBar)

# Clock readout - live HH:mm:ss in monospace
$lblClock                = New-Object System.Windows.Forms.Label
$lblClock.Text           = (Get-Date).ToString("HH:mm:ss")
$lblClock.Font           = $fMonoTiny
$lblClock.ForeColor      = $cTextDim
$lblClock.BackColor      = [System.Drawing.Color]::Transparent
$lblClock.AutoSize       = $false
$lblClock.Size           = New-Object System.Drawing.Size(80, 18)
$lblClock.Location       = New-Object System.Drawing.Point(1072, 7)
$lblClock.TextAlign      = 'MiddleRight'
$pnlStatus.Controls.Add($lblClock)

$script:ClockTimer       = New-Object System.Windows.Forms.Timer
$script:ClockTimer.Interval = 1000
$script:ClockTimer.Add_Tick({ $lblClock.Text = (Get-Date).ToString("HH:mm:ss") })
$script:ClockTimer.Start()

# Right-anchored LIVE heartbeat cluster - mirrors the JANET launcher's LOG
# indicator. Always-on blinking olive dot confirms the UI thread / timer
# pipeline is alive. Label is amber eyebrow "LIVE" in olive.
$lblLive                 = New-Object System.Windows.Forms.Label
$lblLive.Text            = "LIVE"
$lblLive.Font            = $fEyebrow
$lblLive.ForeColor       = $cGreen
$lblLive.BackColor       = [System.Drawing.Color]::Transparent
$lblLive.AutoSize        = $false
$lblLive.Size            = New-Object System.Drawing.Size(40, 20)
$lblLive.Location        = New-Object System.Drawing.Point(1200, 6)
$lblLive.TextAlign       = 'MiddleRight'
$pnlStatus.Controls.Add($lblLive)

$script:dotLive          = New-PulseDot -X 1246 -Y 12 -Size 8 -State Active
$pnlStatus.Controls.Add($script:dotLive)

# ==========================================================================
#  SEARCH TIMER (polls async completion)
# ==========================================================================
$searchTimer             = New-Object System.Windows.Forms.Timer
$searchTimer.Interval    = 200
$searchTimer.Add_Tick({
    if ($script:currentAsyncResult -ne $null -and $script:currentAsyncResult.IsCompleted) {
        $searchTimer.Stop()
        $didError = $false
        try {
            $results = $script:currentPowerShell.EndInvoke($script:currentAsyncResult)
            if ($script:currentPowerShell.Streams.Error.Count -gt 0) {
                $errorMsg = $script:currentPowerShell.Streams.Error[0].ToString()
                $txtBoxSearchResults.Text = "An error occurred during search:`n`n$errorMsg"
                $statusBar.Text = "STATUS :: SEARCH ERROR"
                $didError = $true
            } else {
                $resultArray = @($results)
                Process-SearchResults -SearchType $script:currentSearchType -Results $resultArray
                $statusBar.Text = ("STATUS :: OK  ::  {0:D3} RESULTS" -f [int]$resultArray.Count)
            }
        } catch {
            $txtBoxSearchResults.Text = "An error occurred: $($_.Exception.Message)"
            $statusBar.Text = "STATUS :: SEARCH ERROR"
            $didError = $true
        } finally {
            try { $script:currentPowerShell.Dispose(); $script:currentRunspace.Close(); $script:currentRunspace.Dispose() } catch {}
            $script:currentPowerShell = $null; $script:currentRunspace = $null; $script:currentAsyncResult = $null
            $btnSearch.Enabled = $true
            if ($script:dotStatus) {
                if ($didError) {
                    Set-PulseDotState -Dot $script:dotStatus -State 'Error'
                } else {
                    Set-PulseDotState -Dot $script:dotStatus -State 'Idle'
                }
            }
        }
    }
})

# ==========================================================================
#  ADD ALL CONTROLS TO FORM
# ==========================================================================
$ADSearchTool.Controls.AddRange(@(
    $pnlHeader, $pnlOptions, $pnlSearchInputs, $pnlBulk,
    $cardResults, $cardExtended,
    $pnlStatus
))

# ==========================================================================
#  EXPORT BULK CSV FUNCTION
# ==========================================================================
function Export-BulkCSV {
    if ($script:cachedResults -eq $null -or $script:cachedResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No bulk results to export. Run a Bulk Computer scan first.", "No Data", 'OK', 'Information')
        return
    }
    if (-not $RBBulkSearch.Checked) {
        [System.Windows.Forms.MessageBox]::Show("CSV export is available for Bulk Computer results.", "Wrong Mode", 'OK', 'Information')
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.Title = "Export Bulk Computer Scan Results"
    $saveDialog.FileName = "BulkComputerScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $saveDialog.InitialDirectory = $script:ScriptDir

    if ($saveDialog.ShowDialog() -eq 'OK') {
        try {
            $csvLines = [System.Collections.ArrayList]::new()
            [void]$csvLines.Add("ComputerName,Organization,Location,Squadron_OU,ParentOU,OUPath,OperatingSystem,LastLogon,Status,FullDNPath")

            foreach ($item in $script:cachedResults) {
                $cn = "$($item.name)" -replace '"','""'

                # Parse Organization from location
                $locRaw = $item.location
                $org = ""
                $locStr = ""
                if ($locRaw -ne $null -and "$locRaw" -ne "") {
                    $locStr = "$locRaw" -replace '"','""'
                    if ("$locRaw" -match "ORGANIZATION:\s*([^;]+)") { $org = $Matches[1].Trim() }
                }
                if ($org -eq "") { $org = "$($item['_squadron'])" }
                $org = $org -replace '"','""'

                $sq = "$($item['_squadron'])" -replace '"','""'
                $parentOU = "$($item['_parentOU'])" -replace '"','""'
                if ($parentOU -eq "") { $parentOU = "N/A" }
                $ouChain = "$($item['_ouChain'])" -replace '"','""'
                if ($ouChain -eq "") { $ouChain = "$($item['_fullOU'])" -replace '"','""' }
                $osVal = $item.operatingsystem
                if ($osVal -eq $null) { $osVal = "" }
                $os = "$osVal" -replace '"','""'
                $ll = "$($item['_lastLogon'])" -replace '"','""'
                $st = "$($item['_status'])" -replace '"','""'
                $fullDN = "$($item['_fullOU'])" -replace '"','""'
                [void]$csvLines.Add("""$cn"",""$org"",""$locStr"",""$sq"",""$parentOU"",""$ouChain"",""$os"",""$ll"",""$st"",""$fullDN""")
            }

            [System.IO.File]::WriteAllLines($saveDialog.FileName, $csvLines.ToArray())
            $statusBar.Text = "Status: Exported $($script:cachedResults.Count) records to $($saveDialog.FileName)"
            [System.Windows.Forms.MessageBox]::Show(
                "Exported $($script:cachedResults.Count) computer records to:`n`n$($saveDialog.FileName)",
                "Export Complete", 'OK', 'Information')
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Export Error", 'OK', 'Error')
        }
    }
}

# ==========================================================================
#  EXPORT BASE USERS CSV FUNCTION
# ==========================================================================
function Export-BaseUsersCSV {
    if ($script:cachedResults -eq $null -or $script:cachedResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No base user results to export.", "No Data", 'OK', 'Information')
        return
    }

    $baseName = $txtBoxBaseName.Text.Trim()
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvHeader = "DisplayName,sAMAccountName,PrivilegeLevel,PrivilegeReason,Organization,Title,Email,Department,Company,PayGrade,Base,OU"

    # Let user pick a save folder
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select folder to save Privileged and Standard user CSVs"
    $folderDialog.SelectedPath = $script:ScriptDir

    if ($folderDialog.ShowDialog() -ne 'OK') { return }

    $saveFolder = $folderDialog.SelectedPath

    try {
        # Split results
        $privUsers = @($script:cachedResults | Where-Object { $_["_isPrivileged"] -eq $true } | Sort-Object { $_.displayname })
        $stdUsers  = @($script:cachedResults | Where-Object { $_["_isPrivileged"] -ne $true } | Sort-Object { $_.displayname })

        # Helper to build CSV lines from a user array
        function Build-UserCSVLines {
            param([array]$Users)
            $lines = [System.Collections.ArrayList]::new()
            [void]$lines.Add($csvHeader)
            foreach ($item in $Users) {
                $dn   = "$($item.displayname)" -replace '"','""'
                $sam  = "$($item.samaccountname)" -replace '"','""'
                $pl   = "$($item['_privLevel'])" -replace '"','""'
                $pr   = "$($item['_privReason'])" -replace '"','""'
                $org  = "$($item['_organization'])" -replace '"','""'
                if ($org -eq "") { $org = "$($item['_parentOU'])" -replace '"','""' }
                $ti   = "$($item.title)" -replace '"','""'
                $em   = "$($item['_email'])" -replace '"','""'
                $dept = "$($item.department)" -replace '"','""'
                $comp = "$($item.company)" -replace '"','""'
                $pg   = "$($item.paygrade)" -replace '"','""'
                $base = "$($item.l)" -replace '"','""'
                $ou   = "$($item['_parentOU'])" -replace '"','""'
                [void]$lines.Add("""$dn"",""$sam"",""$pl"",""$pr"",""$org"",""$ti"",""$em"",""$dept"",""$comp"",""$pg"",""$base"",""$ou""")
            }
            return $lines.ToArray()
        }

        # Write Privileged CSV
        $privFile = Join-Path $saveFolder "BaseUsers_${baseName}_PRIVILEGED_${timestamp}.csv"
        $privLines = Build-UserCSVLines -Users $privUsers
        [System.IO.File]::WriteAllLines($privFile, $privLines)

        # Write Standard CSV
        $stdFile = Join-Path $saveFolder "BaseUsers_${baseName}_STANDARD_${timestamp}.csv"
        $stdLines = Build-UserCSVLines -Users $stdUsers
        [System.IO.File]::WriteAllLines($stdFile, $stdLines)

        $statusBar.Text = "Status: Exported $($privUsers.Count) privileged + $($stdUsers.Count) standard users to $saveFolder"
        [System.Windows.Forms.MessageBox]::Show(
            "Export complete! Two files created:`n`n" +
            "PRIVILEGED ($($privUsers.Count) accounts):`n$privFile`n`n" +
            "STANDARD ($($stdUsers.Count) accounts):`n$stdFile",
            "Base Users Export Complete", 'OK', 'Information')
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Export Error", 'OK', 'Error')
    }
}

# ==========================================================================
#  EVENT HANDLERS
# ==========================================================================

# -- Search dispatcher --
function ChooseSearchOptions {
    if ($RBUserSearch.Checked) {
        if ($txtBoxUserEDIPI.Text.Length -ge 10) {
            Start-AsyncSearch -SearchType "User" -SearchParams @{ FirstName=$txtBoxUserFirstName.Text.Trim(); LastName=$txtBoxUserLastName.Text.Trim(); EDIPI=$txtBoxUserEDIPI.Text.Trim() }
        } elseif ($txtBoxUserLastName.Text.Length -lt 2) {
            $txtBoxSearchResults.Text = "Please enter at least 2 characters for last name."
        } elseif ($txtBoxUserFirstName.Text.Length -ge 2 -or $txtBoxUserLastName.Text.Length -ge 2) {
            Start-AsyncSearch -SearchType "User" -SearchParams @{ FirstName=$txtBoxUserFirstName.Text.Trim(); LastName=$txtBoxUserLastName.Text.Trim(); EDIPI=$txtBoxUserEDIPI.Text.Trim() }
        } elseif ($txtBoxUserEDIPI.Text.Length -lt 10) {
            $txtBoxSearchResults.Text = "Please enter at least 10 characters for EDIPI."
        }
    }
    if ($RBComputerSearch.Checked) {
        if ($txtBoxComputerName.Text.Length -lt 4) { $txtBoxSearchResults.Text = "Please enter at least 4 characters for computer name." }
        else { Start-AsyncSearch -SearchType "Computer" -SearchParams @{ ComputerName=$txtBoxComputerName.Text.Trim() } }
    }
    if ($RBGroupSearch.Checked) {
        if ($txtBoxGroupName.Text.Length -lt 4) { $txtBoxSearchResults.Text = "Please enter at least 4 characters for group name." }
        else { Start-AsyncSearch -SearchType "Group" -SearchParams @{ GroupName=$txtBoxGroupName.Text.Trim() } }
    }
    if ($RBOrgBoxSearch.Checked) {
        if ($txtBoxOrgBox.Text.Length -lt 4) { $txtBoxSearchResults.Text = "Please enter at least 4 characters for org box name." }
        else { Start-AsyncSearch -SearchType "OrgBox" -SearchParams @{ OrgBoxName=$txtBoxOrgBox.Text.Trim() } }
    }
    if ($RBEmailSearch.Checked) {
        if ($txtBoxEmailAddress.Text.Length -lt 3) { $txtBoxSearchResults.Text = "Please enter at least 3 characters for email address." }
        else { Start-AsyncSearch -SearchType "Email" -SearchParams @{ EmailAddress=$txtBoxEmailAddress.Text.Trim() } }
    }
    if ($RBManagerSearch.Checked) {
        if ($txtBoxManagerName.Text.Length -lt 3) { $txtBoxSearchResults.Text = "Please enter at least 3 characters for manager's name." }
        else { Start-AsyncSearch -SearchType "Manager" -SearchParams @{ ManagerName=$txtBoxManagerName.Text.Trim() } }
    }
    if ($RBBulkSearch.Checked) {
        $lines = $txtBulkList.Text -split "`r`n|`n|`r" | Where-Object { $_.Trim() -ne "" }
        if ($lines.Count -lt 1) { $txtBoxSearchResults.Text = "Please enter or import computer names (one per line)." }
        else { Start-AsyncSearch -SearchType "BulkComputer" -SearchParams @{ MachineList = @($lines) } }
    }
    if ($RBBaseUsers.Checked) {
        if ($txtBoxBaseName.Text.Length -lt 3) { $txtBoxSearchResults.Text = "Please enter at least 3 characters for the base/location name.`n`nExamples: LAKENHEATH, RAMSTEIN, SPANGDAHLEM, MILDENHALL" }
        else { Start-AsyncSearch -SearchType "BaseUsers" -SearchParams @{ BaseName=$txtBoxBaseName.Text.Trim() } }
    }
    if ($RBLastPCSearch.Checked) {
        $hasName  = ($txtBoxUserFirstName.Text.Length -ge 2) -or ($txtBoxUserLastName.Text.Length -ge 2)
        $hasEdipi = ($txtBoxUserEDIPI.Text.Length -ge 10)
        if (-not ($hasName -or $hasEdipi)) {
            $txtBoxSearchResults.Text = "Please enter a first name + last name (>=2 chars each), or a 10-digit EDIPI."
        } else {
            $days = 14
            if ($txtBoxLastPCDays.Text.Trim() -match '^\d+$') { $days = [int]$txtBoxLastPCDays.Text.Trim() }
            Start-AsyncSearch -SearchType "LastPC" -SearchParams @{
                FirstName = $txtBoxUserFirstName.Text.Trim()
                LastName  = $txtBoxUserLastName.Text.Trim()
                EDIPI     = $txtBoxUserEDIPI.Text.Trim()
                DaysBack  = $days
            }
        }
    }
}

# -- Clear --
$btnClear.Add_Click({
    $listViewResults.Columns.Clear(); $listViewResults.Items.Clear()
    $txtBoxSearchResults.Text = ""; $txtBoxUserFirstName.Text = ""; $txtBoxUserLastName.Text = ""
    $txtBoxUserEDIPI.Text = ""; $txtBoxGroupName.Text = ""; $txtBoxComputerName.Text = ""
    $txtBoxOrgBox.Text = ""; $txtBoxEmailAddress.Text = ""; $txtBoxManagerName.Text = ""
    $txtBulkList.Text = ""; $txtBoxBaseName.Text = ""; $txtBoxLastPCDays.Text = "14"
    $script:cachedResults = $null
    $statusBar.Text = "STATUS :: READY"
    if ($script:dotStatus) { Set-PulseDotState -Dot $script:dotStatus -State 'Idle' }
})

# -- About --
$btnAbout.Add_Click({
    $txtBoxSearchResults.Text = @"

J.A.N.E.T. AD SEARCH TOOL  v$($script:VersionNumber)
-------------------------------------------------
Created by: NGUYEN, HAI
Edited by:  THOMPSON, BRAXTON - 48 CS

Searches use standard Windows Active Directory
Service Interfaces (ADSI). Remote Server
Administration Tools (RSAT) is NOT required.

CHANGELOG
v3.3 - Added BY LAST PC search mode (Thompson)
     - Find the workstation a user last logged on
       from by scanning every DC's Security log for
       Kerberos / logon events (4624, 4768, 4769,
       4776) tagged with the user's SAM.
     - Reverse-resolves source IPs to host names.
     - Default window 14 days, range 1-90.
     - Skips DCs that don't answer on TCP/135.
     - Requires Security-log read access on DCs.

v3.1 - Purple + Gold on Black restyle under J.A.N.E.T.
       Unifies with WPT + RemoteMessageTool v1.1.
     - Dark #0A0B0E surfaces + purple #8C64DC accent
       + gold #DAB452 highlights + green success
       + operational red.
     - Cascadia Mono display / mono / buttons +
       Segoe UI Variable Display body copy.
     - 4 L-shaped corner-bracket "brief box" cards
       replace full rectangular borders.
     - Scanline overlay on header + status strip.
     - Diagonal caution-stripe hatch on SEARCH CTA.
     - Blinking pulse dots (olive when searching,
       red on error) in the status strip + header
       CRED indicator (olive when launcher cred is
       inherited via `$env:JANET_CRED_FILE).
     - Dark DWM title bar + rounded corners on
       Win11 for the main form and popup window.

v3.0 - J.A.N.E.T. dark/gold theme (Thompson)
     - Added Bulk Computer Lookup with squadron ID
     - Location field parsing (ORGANIZATION/USER)
     - Batched LDAP queries for 200+ machines
     - CSV export for bulk results
     - Color-coded status (Active/Stale/Not Found)

v2.2 - Search by Email and Manager (Nguyen)
v2.1 - Multithreading via PowerShell Runspaces (Nguyen)
v2.0 - Popup window on double-click (Nguyen)
v1.x - Initial releases 2018-2019 (Nguyen)

"@
})

# -- Popup child window - tactical brief box on top of the main window --
# $userInfo is read from the caller's scope (dynamic scoping in PowerShell);
# the caller defines $userInfo before invoking this function.
Function popUpChildWindow($parentDisplayname) {
    $PopupForm = New-Object System.Windows.Forms.Form
    $PopupForm.ClientSize = New-Object System.Drawing.Size(520, 690)
    $PopupForm.BackColor  = $cBg
    $PopupForm.ForeColor  = $cText
    $PopupForm.Font       = $fBody
    $PopupForm.TopMost    = $false
    $PopupForm.FormBorderStyle = 'FixedSingle'
    $PopupForm.MaximizeBox = $false
    $PopupForm.MinimizeBox = $false
    $PopupForm.Text = $parentDisplayname
    $PopupForm.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $cx = $ADSearchTool.Location.X + [math]::Floor(($ADSearchTool.Width  - $PopupForm.Width)  / 2)
    $cy = $ADSearchTool.Location.Y + [math]::Floor(($ADSearchTool.Height - $PopupForm.Height) / 2)
    if ($cx -lt 0) { $cx = 0 }; if ($cy -lt 0) { $cy = 0 }
    $PopupForm.Location = New-Object System.Drawing.Point($cx, $cy)
    Enable-DoubleBuffer -Control $PopupForm
    $PopupForm.Add_HandleCreated({ Set-JanetDarkTitleBar -Form $PopupForm }.GetNewClosure())

    $card = New-Object System.Windows.Forms.Panel
    $card.Location = New-Object System.Drawing.Point(6, 6)
    $card.Size     = New-Object System.Drawing.Size(508, 678)
    $card.BackColor = $cPanel
    Add-CornerBrackets -Panel $card -Header "OBJECT DETAIL" -BracketLen 14 -BracketThick 2

    $popupText = New-Object System.Windows.Forms.RichTextBox
    $popupText.Multiline  = $true
    $popupText.ReadOnly   = $true
    $popupText.Location   = New-Object System.Drawing.Point(14, 50)
    $popupText.Size       = New-Object System.Drawing.Size(480, 618)
    $popupText.Font       = $fntResults
    $popupText.BackColor  = $cConsoleBg
    $popupText.ForeColor  = $cAccentHov
    $popupText.BorderStyle = 'None'
    $popupText.Text       = $userInfo
    $card.Controls.Add($popupText)

    $PopupForm.Controls.Add($card)
    $PopupForm.Show()
}

# -- Double-click handler for extended info --
$listViewResults.Add_ItemActivate({
    if ($script:cachedResults -eq $null -or $script:cachedResults.Count -eq 0) {
        $txtBoxSearchResults.Text = "No cached results. Please search again."; return
    }
    $txtBoxSearchResults.Text = ""
    if ($listViewResults.SelectedItems.Count -ne 1) { return }

    $selectedIndex = $listViewResults.SelectedIndices[0]
    $selectedItem = $script:cachedResults[$selectedIndex]

    # -- User/Email/Manager detail --
    if ($RBUserSearch.Checked -or $RBEmailSearch.Checked -or $RBManagerSearch.Checked) {
        if ($selectedItem.displayname -ne $null) {
            $managerDN = $selectedItem.manager
            $managerDisplayName = ""
            if ($managerDN -ne $null) { $managerDisplayName = ($managerDN -split ",")[0] -replace "CN=","" }

            $distinguishedName = $selectedItem.distinguishedname
            $email = $selectedItem.mail | Out-String; $email = $email -replace "`n",""

            $Groups = ""
            $userGroups = $selectedItem.memberof
            if ($userGroups -is [array]) { foreach ($ug in $userGroups) { $Groups += ($ug -split ",")[0].substring(3) + "`r`n" } }
            elseif ($userGroups -ne $null) { $Groups = ($userGroups -split ",")[0].substring(3) + "`r`n" }

            $userLastLogon = "N/A"
            try { $userLastLogon = [datetime]::FromFileTime([Int64]($selectedItem.lastlogon | Out-String)).ToString('g') } catch {}

            $lockedoutStatus = "No"
            if ($selectedItem.lockouttime -gt 0) { $lockedoutStatus = "Yes" }

            $userInfo = "`nDisplay Name: $($selectedItem.displayname)`nName: $($selectedItem.name)" +
                "`nFirst Name: $($selectedItem.givenname)  MI: $($selectedItem.initials)  Last: $($selectedItem.sn)" +
                "`nsAMAccountName: $($selectedItem.samaccountname)" +
                "`nEmployee ID: $($selectedItem.employeeid)" +
                "`n`nTitle: $($selectedItem.title)" +
                "`nCompany: $($selectedItem.company)" +
                "`nDepartment: $($selectedItem.department)" +
                "`nOffice: $($selectedItem.physicaldeliveryofficename)" +
                "`nPay Grade: $($selectedItem.paygrade)" +
                "`n`nManager: $managerDisplayName" +
                "`n`nDSN: $($selectedItem.telephonenumber)" +
                "`nCommercial: $($selectedItem.othertelephone)" +
                "`nMobile: $($selectedItem.mobile)" +
                "`nEmail: $email" +
                "`n`nBase: $($selectedItem.l)  Country: $($selectedItem.c)" +
                "`nBuilding: $($selectedItem.buildingname)  Room: $($selectedItem.roomnumber)" +
                "`n$($selectedItem.streetaddress)" +
                "`n`nAccount Created: $($selectedItem.whencreated)" +
                "`nLast Changed: $($selectedItem.whenchanged)" +
                "`nLast Logon: $userLastLogon" +
                "`nLogon Count: $($selectedItem.logoncount)" +
                "`nLocked Out: $lockedoutStatus" +
                "`n`nHome Share: $($selectedItem.homedirectory)" +
                "`n`nOU:`n$distinguishedName" +
                "`n`nGroups:`n$Groups"

            $txtBoxSearchResults.Text = $userInfo
            popUpChildWindow(($selectedItem.displayname | Out-String))
        } elseif ($selectedItem.samaccountname -ne $null) {
            $txtBoxSearchResults.Text = "Name: $($selectedItem.samaccountname)`nOU: $($selectedItem.distinguishedname)"
        }
    }

    # -- Computer detail --
    if ($RBComputerSearch.Checked) {
        $PCLastLogon = "N/A"
        try { $PCLastLogon = [datetime]::FromFileTime([Int64]($selectedItem.lastlogon | Out-String)).ToString('g') } catch {}
        $PCLastLogonTS = "N/A"
        try { $PCLastLogonTS = [datetime]::FromFileTime([Int64]($selectedItem.lastlogontimestamp | Out-String)).ToString('g') } catch {}
        $Groups = ""
        $PCGroups = $selectedItem.memberof
        if ($PCGroups -is [array]) { foreach ($pg in $PCGroups) { $Groups += ($pg -split ",")[0].substring(3) + "`r`n" } }
        elseif ($PCGroups -ne $null) { $Groups = ($PCGroups -split ",")[0].substring(3) + "`r`n" }

        $PCInfo = "Computer Name: $($selectedItem.name)`n`nOS: $($selectedItem.operatingsystem)" +
            "`nOS Version: $($selectedItem.operatingsystemversion)" +
            "`n`nLast Logon: $PCLastLogon`nLast Logon Timestamp: $PCLastLogonTS" +
            "`nLogon Count: $($selectedItem.logoncount)" +
            "`n`nCreated: $($selectedItem.whencreated)`nChanged: $($selectedItem.whenchanged)" +
            "`n`nDNS: $($selectedItem.dnshostname)" +
            "`nLocation: $($selectedItem.location)" +
            "`n`nOU: $($selectedItem.distinguishedname)" +
            "`n`nGroups:`n$Groups"
        $txtBoxSearchResults.Text = $PCInfo
    }

    # -- Group detail --
    if ($RBGroupSearch.Checked) {
        $members = ""; $memberCount = 0
        $gMembers = $selectedItem.member
        if ($gMembers -is [array]) { foreach ($gm in $gMembers) { $members += ($gm -split ",")[0].substring(3) + "`r`n" }; $memberCount = $gMembers.Count }
        elseif ($gMembers -ne $null) { $members = ($gMembers -split ",")[0].substring(3) + "`r`n"; $memberCount = 1 }
        $gManager = $selectedItem.managedby
        if ($gManager -ne $null) { $gManager = ($gManager -split ",")[0] -replace "CN=","" }

        $gInfo = "Group: $($selectedItem.name)`nTotal Members: $memberCount" +
            "`n`nOU: $($selectedItem.distinguishedname)" +
            "`nCreated: $($selectedItem.whencreated)`nChanged: $($selectedItem.whenchanged)" +
            "`nManager: $gManager`n`nMembers:`n$members"
        $txtBoxSearchResults.Text = $gInfo
    }

    # -- Org Box detail --
    if ($RBOrgBoxSearch.Checked) {
        $email = $selectedItem.mail | Out-String; $email = $email -replace "`n",""
        $lockedoutStatus = "No"; if ($selectedItem.lockouttime -gt 0) { $lockedoutStatus = "Yes" }
        $Groups = ""
        $ogGroups = $selectedItem.memberof
        if ($ogGroups -is [array]) { foreach ($og in $ogGroups) { $Groups += ($og -split ",")[0].substring(3) + "`r`n" } }
        elseif ($ogGroups -ne $null) { $Groups = ($ogGroups -split ",")[0].substring(3) + "`r`n" }

        $orgInfo = "Name: $($selectedItem.displayname)`nEmail: $email`nTitle: $($selectedItem.title)" +
            "`n`nLocked Out: $lockedoutStatus" +
            "`nCreated: $($selectedItem.whencreated)`nChanged: $($selectedItem.whenchanged)" +
            "`n`nOU: $($selectedItem.distinguishedname)" +
            "`n`nGroups:`n$Groups"
        $txtBoxSearchResults.Text = $orgInfo
    }

    # -- Bulk Computer detail --
    if ($RBBulkSearch.Checked) {
        $comp = $selectedItem
        if ($comp["_status"] -eq "Not Found" -or $comp["_status"] -eq "Error") {
            $txtBoxSearchResults.Text = "Computer: $($comp.name)`nStatus: $($comp['_status'])`n`nThis machine was not found in Active Directory.`nIt may have been decommissioned, renamed, or`nnot yet joined to the domain."
        } else {
            $PCLastLogonTS = "N/A"
            try { $PCLastLogonTS = [datetime]::FromFileTime([Int64]($comp.lastlogontimestamp | Out-String)).ToString('g') } catch {}
            $Groups = ""
            $cGroups = $comp.memberof
            if ($cGroups -is [array]) { foreach ($cg in $cGroups) { $Groups += ($cg -split ",")[0].substring(3) + "`r`n" } }
            elseif ($cGroups -ne $null) { $Groups = ($cGroups -split ",")[0].substring(3) + "`r`n" }

            $bulkInfo = "Computer: $($comp.name)" +
                "`nStatus: $($comp['_status'])" +
                "`n`n--- LOCATION / ORGANIZATION ---"

            $locRaw = $comp.location
            if ($locRaw -ne $null -and "$locRaw" -ne "") {
                $locStr = "$locRaw"
                $bulkInfo += "`nLocation: $locStr"
                if ($locStr -match "ORGANIZATION:\s*([^;]+)") {
                    $bulkInfo += "`nOrganization: $($Matches[1].Trim())"
                }
                if ($locStr -match "USER:\s*([^;]+)") {
                    $bulkInfo += "`nAssigned User: $($Matches[1].Trim())"
                }
                if ($locStr -match "LAST UPDATE:\s*(.+)") {
                    $bulkInfo += "`nLast Update: $($Matches[1].Trim())"
                }
            } else {
                $bulkInfo += "`nLocation: (not set)"
            }

            $ouChain = $comp['_ouChain']
            if ($ouChain -eq $null) { $ouChain = $comp['_fullOU'] }

            $bulkInfo += "`n`n--- OU INFO ---" +
                "`nSquadron/OU: $($comp['_squadron'])" +
                "`nParent OU:   $($comp['_parentOU'])" +
                "`nOU Path:     $ouChain" +
                "`n`n--- SYSTEM INFO ---" +
                "`nOS: $($comp.operatingsystem)" +
                "`nOS Version: $($comp.operatingsystemversion)" +
                "`n`n--- LOGON INFO ---" +
                "`nLast Logon: $($comp['_lastLogon'])" +
                "`nLast Logon Timestamp: $PCLastLogonTS" +
                "`n`nCreated: $($comp.whencreated)" +
                "`nChanged: $($comp.whenchanged)" +
                "`nDNS: $($comp.dnshostname)" +
                "`n`n--- FULL DN ---`n$($comp.distinguishedname)" +
                "`n`n--- GROUPS ---`n$Groups"
            $txtBoxSearchResults.Text = $bulkInfo
        }
    }

    # -- Base Users detail --
    if ($RBBaseUsers.Checked) {
        $user = $selectedItem
        $name = if ($user.displayname -ne $null) { "$($user.displayname)" } else { "$($user.samaccountname)" }

        $managerDN = $user.manager
        $managerName = ""
        if ($managerDN -ne $null) { $managerName = ($managerDN -split ",")[0] -replace "CN=","" }

        $Groups = ""
        $userGroups = $user.memberof
        if ($userGroups -is [array]) { foreach ($ug in $userGroups) { $Groups += ($ug -split ",")[0].substring(3) + "`r`n" } }
        elseif ($userGroups -ne $null) { $Groups = ($userGroups -split ",")[0].substring(3) + "`r`n" }

        $userLastLogon = "N/A"
        try { $userLastLogon = [datetime]::FromFileTime([Int64]($user.lastlogon | Out-String)).ToString('g') } catch {}

        $lockedoutStatus = "No"
        if ($user.lockouttime -gt 0) { $lockedoutStatus = "Yes" }

        $privLevel = $user["_privLevel"]
        $privReason = $user["_privReason"]
        if ($privReason -eq "") { $privReason = "N/A" }

        $userInfo = "--- ACCOUNT INFO ---" +
            "`nDisplay Name: $name" +
            "`nsAMAccountName: $($user.samaccountname)" +
            "`nEmployee ID: $($user.employeeid)" +
            "`n`n--- PRIVILEGE STATUS ---" +
            "`nLevel: $privLevel"
        if ($user["_isPrivileged"] -eq $true) {
            $userInfo += "`nReason: $privReason"
        }
        $userInfo += "`n`n--- POSITION ---" +
            "`nTitle: $($user.title)" +
            "`nCompany: $($user.company)" +
            "`nDepartment: $($user.department)" +
            "`nOffice: $($user.physicaldeliveryofficename)" +
            "`nPay Grade: $($user.paygrade)" +
            "`nOrganization: $($user['_organization'])" +
            "`n`nManager: $managerName" +
            "`n`n--- CONTACT ---" +
            "`nEmail: $($user['_email'])" +
            "`nDSN: $($user.telephonenumber)" +
            "`nCommercial: $($user.othertelephone)" +
            "`nMobile: $($user.mobile)" +
            "`n`nBase: $($user.l)  Country: $($user.c)" +
            "`n`n--- ACCOUNT STATUS ---" +
            "`nLast Logon: $userLastLogon" +
            "`nLogon Count: $($user.logoncount)" +
            "`nLocked Out: $lockedoutStatus" +
            "`nCreated: $($user.whencreated)" +
            "`nChanged: $($user.whenchanged)" +
            "`n`n--- OU ---`n$($user.distinguishedname)" +
            "`n`n--- GROUPS ---`n$Groups"

        $txtBoxSearchResults.Text = $userInfo
        popUpChildWindow($name)
    }

    # -- Last PC detail --
    if ($RBLastPCSearch.Checked) {
        $row = $selectedItem
        # Map LogonType numeric codes -> short labels for the helpdesk view.
        $logonType = "$($row['_logonType'])"
        $logonTypeName = switch ($logonType) {
            "2"  { "Interactive (console)" }
            "3"  { "Network" }
            "4"  { "Batch" }
            "5"  { "Service" }
            "7"  { "Unlock" }
            "8"  { "NetworkCleartext" }
            "9"  { "NewCredentials (RunAs)" }
            "10" { "RemoteInteractive (RDP)" }
            "11" { "CachedInteractive" }
            default { if ($logonType -eq "") { "(n/a)" } else { $logonType } }
        }
        $eventName = switch ("$($row['_eventId'])") {
            "4624" { "4624  Account logged on" }
            "4768" { "4768  Kerberos TGT requested" }
            "4769" { "4769  Kerberos service ticket" }
            "4776" { "4776  NTLM credential validation" }
            default { "$($row['_eventId'])" }
        }
        $detail = "--- USER ---" +
            "`nDisplay Name:    $($row['_displayName'])" +
            "`nsAMAccountName:  $($row['_sam'])" +
            "`nDN:              $($row['_distinguishedName'])" +
            "`n`n--- LAST WORKSTATION ---" +
            "`nComputer:        $($row['_computerName'])" +
            "`nIP Address:      $($row['_ipAddress'])" +
            "`nLast Seen:       $($row['_timeStr'])" +
            "`nLogon Type:      $logonTypeName" +
            "`n`n--- SOURCE EVENT ---" +
            "`nEvent:           $eventName" +
            "`nDC:              $($row['_dc'])" +
            "`n`n--- WINDOW ---" +
            "`nDays Back:       $($row['_daysBack'])" +
            "`nDCs Scanned:     $($row['_dcsScanned']) of $($row['_dcsTotal'])" +
            "`nTotal Events:    $($row['_eventCount'])"
        $txtBoxSearchResults.Text = $detail
    }
})

# -- Save/Export --
$btnExport.Add_Click({
    if ($script:cachedResults -eq $null -or $script:cachedResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to save. Please search first.", "No Data"); return
    }

    # For bulk results, use the dedicated CSV export function
    if ($RBBulkSearch.Checked) {
        Export-BulkCSV
        return
    }

    # For base users, use the dedicated CSV export function
    if ($RBBaseUsers.Checked) {
        Export-BaseUsersCSV
        return
    }

    # Standard save (RTF of selected item)
    if ($listViewResults.SelectedItems.Count -eq 1) {
        $si = $script:cachedResults[$listViewResults.SelectedIndices[0]]
        $fileName = ""
        if ($RBUserSearch.Checked -or $RBEmailSearch.Checked -or $RBManagerSearch.Checked) {
            $fileName = if ($si.displayname -ne $null) { $si.displayname | Out-String } else { $si.samaccountname | Out-String }
        }
        if ($RBComputerSearch.Checked -or $RBGroupSearch.Checked) { $fileName = $si.name | Out-String }
        if ($RBOrgBoxSearch.Checked) { $fileName = $si.displayname | Out-String }
        if ($RBLastPCSearch.Checked) {
            $disp = "$($si['_displayName'])"; if ($disp -eq "") { $disp = "$($si['_sam'])" }
            $fileName = "{0} - {1}" -f $disp, "$($si['_computerName'])"
        }
        $fileName = $fileName -replace "/", " " -replace ",", ""; $fileName = $fileName.Trim()
        $fn = Join-Path $script:ScriptDir "$fileName.rtf"
        $txtBoxSearchResults.SaveFile($fn)
        [System.Windows.Forms.MessageBox]::Show("Saved to $fn", "Content Saved")
    } else {
        [System.Windows.Forms.MessageBox]::Show("Double click a result row first, then click Save.", "No Selection")
    }
})

# ==========================================================================
#  SHOW FORM
# ==========================================================================
$ADSearchTool.Add_Shown({
    $ADSearchTool.Activate(); $txtBoxUserFirstName.Focus()
})

## JANET centralized session (added in v3.2.1). Read-only tool: silent rollup,
## no closing-notes dialog. Start fires immediately before the form opens.
try { Start-JanetSession -Tool 'AD_Search' -Version $JanetAD_SearchVersion } catch {}
[void]$ADSearchTool.ShowDialog()
try { Stop-JanetSession } catch {}