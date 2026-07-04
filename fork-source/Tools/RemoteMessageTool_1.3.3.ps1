<#
.NAME
    J.A.N.E.T. Remote Message Tool
.SYNOPSIS
    Joint Administration and Network Execution Toolkit - Mass Messenger
.DESCRIPTION
    WinForms mass messenger for sending MessageBox popups to logged-in users
    across many workstations in parallel over WinRM / PSSession. Features a
    Ping All reachability check, per-job wall-clock timeout, mid-send Cancel,
    and Pingable / Delivered / Undelivered XLSX export (pure .NET - no Excel
    COM or ImportExcel module required).

    Visual language: J.A.N.E.T. launcher theme (JANET.ps1). Dark navy
    background, blue accent, warm gold headings, Segoe UI typography,
    plain panels with subtle borders, sentence-case labels, green/red
    status. Identical palette and font choices as the launcher and the
    other sibling tools in Tools\.
.AUTHOR
    THOMPSON, BRAXTON - 48 CS / SCOO
.VERSION
    1.3.3
.CHANGELOG
    v1.3.3 - 2026-05-10 - JANET replay filter widened to *_detail*.csv/*_usage*.csv so schema-rotation sister files (created when the legacy file is persistently locked) are drained on next launch instead of stranded.
    v1.3.2 - 2026-05-08 - JANET centralized-logging schema cleanup (single
                          SessionEnd rollup row; Snapshot rows retired) and
                          the WPT-themed Closing Notes prompt rolled across
                          the suite.
    v1.3.1 - 2026-04-25 - Added JANET centralized logging. Per-host SendMessage
                          rows go to \\dm-tn-01\sh-usafe-automation$\JANET\Logs\Remote_Message\<YYYY-MM>_detail.csv;
                          one rollup row per session goes to <YYYY-MM>_usage.csv at
                          the log root. JANET closing-notes dialog captures ASI+notes
                          on form close. Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
    v1.2 - April 2026 - Reverted the v1.1 tactical/military aesthetic.
           Now matches the J.A.N.E.T. launcher (JANET.ps1) palette and
           typography exactly so the tool reads as part of the launcher
           family rather than a separate military-comms app. No logic,
           handler, runspace, XLSX, or cancel-path changes - pure revert
           of the visual layer from v1.1.
         - Palette reverted to navy #121218 + blue #5882FF accent + warm
           gold #FFC832 headings + olive-tinted green / red / orange
           status, matching $cBg / $cAccent / $cGold / $cGreen / $cRed
           in JANET.ps1.
         - Typography reverted to Segoe UI everywhere (Segoe UI Semibold
           for headings and buttons, Consolas only inside the target
           list / title / body / activity log textboxes).
         - Dropped corner brackets, grid-paper dot background, scanline
           overlay, and diagonal caution stripe on the SEND button.
           Panels are plain Panel surfaces now, matching JANET cards.
         - Section headers reverted to sentence-case bold gold labels
           (TARGET MACHINES, MESSAGE COMPOSER, ACTIVITY LOG), no "/"
           prefix, no dotted underline, no owner-drawn eyebrows.
         - SEND button reverted to flat gold-on-black Segoe UI Bold
           11pt, no hatched stripe. Cancel mode uses solid red.
         - Credential strip reverted to "ADW CREDENTIALS" label with a
           small "Set Credentials..." button and a plain status line -
           no Segoe MDL2 circle glyph, no "//" / "::" framing.
         - Stats readouts reverted to Segoe UI Bold 14pt plain integers
           (no zero-padding). Character counter reverted to "N chars",
           target count reverted to "N target(s)".
         - Startup toasts reverted to plain sentences.
         - Removed Set-DarkTitleBar / SetCompatibleTextRenderingDefault
           / Enable-DoubleBuffer helpers that were introduced for the
           tactical Paint handlers - unneeded without them.
    v1.1 - April 2026 - (superseded by v1.2) Tactical Operations
           restyle. Cascadia Mono, tactical amber, 4-corner-bracket
           "brief box" panels, grid-paper dots, scanlines, diagonal
           caution stripe on SEND, dark DWM title bar. Shipped briefly
           to match Tools\WPT\ then pulled - the tool belongs to the
           launcher family, not the WPT module.
    v1.0 - April 2026 - First stable release under J.A.N.E.T. tool suite.
         - Added [Application]::EnableVisualStyles() so NumericUpDown,
           ComboBox, and ScrollBars render with modern theming, matching
           the other J.A.N.E.T. sibling tools.
         - Target list dedup is now case-insensitive (HashSet<string>
           with StringComparer.OrdinalIgnoreCase). Previously "PC01" and
           "pc01" pasted in the same list sent two copies of the message.
         - msg.exe /TIME capped at 99999 seconds (~27 hrs). 999999 is
           rejected by msg.exe on some Windows builds with "Error 5
           getting session names", causing the require-OK branch to
           fail delivery. 99999 is "effectively forever" for a popup.
         - GDI handle hygiene: form-icon setup now disposes both source
           and resized Bitmap via try/finally (the returned HICON is
           still owned by the Icon object and released on form close).
         - Ping All wrapped in try/finally so the button label/enabled
           state always restore even if Test-Connection throws.
    v16  - October 2025 - Pre-1.0 iteration. Parallel runspace pool,
           per-job timeout, mid-send cancel, stats panel, export row,
           msg.exe broadcast with explorer.exe / qwinsta session
           detection, per-session fallback, pure .NET XLSX writer.
#>

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -AssemblyName System.IO.Compression -EA SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
[System.Windows.Forms.Application]::EnableVisualStyles()

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v1.3.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\Remote_Message\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetRemote_MessageVersion = '1.3.3'

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

$global:LogFile = Join-Path $global:LogDir ("JRMT_{0}_{1}.log" -f $env:USERNAME, (Get-Date -Format "yyyy-MM-dd_HH-mm-ss"))
function Write-JLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try { Add-Content -Path $global:LogFile -Value "[$ts] [$Level] $Message" -EA SilentlyContinue } catch {}
}
Write-JLog "=== J.A.N.E.T. Remote Message Tool v1.2 starting ==="
Write-JLog "ScriptDir: $($global:ScriptDir) | User: $env:USERNAME | PS: $($PSVersionTable.PSVersion)"
#endregion

#region === COLORS / FONTS (Purple + Gold on Black - mirrors JANET.ps1) ===
$colors = @{
    Background    = [System.Drawing.Color]::FromArgb(  8,   8,  12)  ## $cBg
    Sidebar       = [System.Drawing.Color]::FromArgb(  7,   7,  11)  ## $cSidebar
    TopBar        = [System.Drawing.Color]::FromArgb(  6,   6,  10)  ## $cHeaderBg
    Panel         = [System.Drawing.Color]::FromArgb( 16,  16,  22)  ## $cPanel / Surface
    PanelLight    = [System.Drawing.Color]::FromArgb( 30,  28,  40)  ## $cRowHover
    Input         = [System.Drawing.Color]::FromArgb( 22,  22,  30)  ## $cRowAlt
    InputBorder   = [System.Drawing.Color]::FromArgb( 52,  46,  72)  ## $cBorderStrong
    OutputBg      = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Border        = [System.Drawing.Color]::FromArgb( 38,  34,  52)  ## $cBorder
    TextPrimary   = [System.Drawing.Color]::FromArgb(240, 240, 245)  ## $cText
    TextSecondary = [System.Drawing.Color]::FromArgb(170, 168, 180)  ## $cTextDim
    TextDim       = [System.Drawing.Color]::FromArgb(110, 106, 125)  ## $cTextMuted
    Accent        = [System.Drawing.Color]::FromArgb(140, 100, 220)  ## #8C64DC - purple
    AccentHover   = [System.Drawing.Color]::FromArgb(164, 128, 240)
    AccentDim     = [System.Drawing.Color]::FromArgb( 96,  68, 156)
    Success       = [System.Drawing.Color]::FromArgb( 92, 198, 120)  ## $cGreen
    SuccessDim    = [System.Drawing.Color]::FromArgb( 50, 120,  65)  ## $cGreenDim
    Warning       = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger        = [System.Drawing.Color]::FromArgb(224,  80,  90)  ## $cRed
    Orange        = [System.Drawing.Color]::FromArgb(230, 180,  70)  ## = Warning
    Cyan          = [System.Drawing.Color]::FromArgb( 88, 180, 210)  ## $cInfo
    Console       = [System.Drawing.Color]::FromArgb(164, 128, 240)  ## purple phosphor
    Gold          = [System.Drawing.Color]::FromArgb(218, 180,  82)  ## #DAB452 - gold highlight
    GoldDim       = [System.Drawing.Color]::FromArgb(155, 125,  52)
    Purple        = [System.Drawing.Color]::FromArgb(140, 100, 220)  ## = Accent
}

## Typography: Segoe UI throughout (matching JANET.ps1's $fTitle, $fHeading,
## $fNormal, $fButton). Consolas only inside the target list, title box, body
## box, and activity log - where monospace actually helps read hostnames and
## tabular output.
$fonts = @{
    JTitle    = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)       ## $fTitle
    JSub      = New-Object System.Drawing.Font("Segoe UI", 9,  [System.Drawing.FontStyle]::Italic)     ## $fSubtitle
    Section   = New-Object System.Drawing.Font("Segoe UI Semibold", 11)                                ## $fHeading
    Label     = New-Object System.Drawing.Font("Segoe UI", 9.5)                                        ## $fNormal
    LabelBold = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
    Button    = New-Object System.Drawing.Font("Segoe UI Semibold", 9)                                 ## $fButton
    Small     = New-Object System.Drawing.Font("Segoe UI", 8.5)                                        ## $fSmall
    SmallBold = New-Object System.Drawing.Font("Segoe UI Semibold", 8.5)                               ## $fSmallBold
    Tiny      = New-Object System.Drawing.Font("Segoe UI Semibold", 7.5)                               ## $fBadge
    Console   = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 9)                            ## $fMono
    ConsoleSm = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 8.5)
}
#endregion

#region === GLOBAL STATE ===
$global:Cred = $null

# v17 - Inherit shared credential from J.A.N.E.T. launcher if present.
# JANET.ps1 sets $env:JANET_CRED_FILE to a DPAPI-encrypted CliXml file
# that only the same user on the same machine can decrypt. The Set
# Credentials button remains fully functional as a manual override.
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

$global:RunspacePool = $null
$global:ActiveJobs = @{}
$script:SendStats = @{ Sent = 0; Failed = 0; Total = 0 }
$script:SendResults = New-Object System.Collections.ArrayList
$script:LastSendMeta = @{}
$script:CancelRequested = $false
$script:MaxJobSeconds = 90        # per-job wall-clock timeout
$script:PSOpenTimeoutMs = 20000   # PSSession open timeout
$script:PSOpTimeoutMs = 45000     # PSSession operation timeout
#endregion

#region === FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text = "J.A.N.E.T. Remote Message Tool v1.2"
$f.Size = New-Object System.Drawing.Size(1400, 1000)
$f.MinimumSize = New-Object System.Drawing.Size(1300, 900)
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

function New-OutputBox {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location = $Location; $rtb.Size = $Size; $rtb.ReadOnly = $true
    $rtb.BackColor = $colors.OutputBg; $rtb.ForeColor = $colors.Console
    $rtb.Font = $fonts.Console; $rtb.BorderStyle = 'None'
    $cm = New-Object System.Windows.Forms.ContextMenuStrip
    $cm.BackColor = $colors.Panel; $cm.ForeColor = $colors.TextPrimary; $cm.Font = $fonts.Label
    $cmClear = $cm.Items.Add("Clear"); $cmClear.ForeColor = $colors.Warning
    $cmClear.Add_Click({ $rtb.Clear() }.GetNewClosure())
    $cmCopy = $cm.Items.Add("Copy All"); $cmCopy.ForeColor = $colors.Accent
    $cmCopy.Add_Click({ if ($rtb.Text) { [System.Windows.Forms.Clipboard]::SetText($rtb.Text) } }.GetNewClosure())
    $rtb.ContextMenuStrip = $cm
    return $rtb
}

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

#region === HEADER (J.A.N.E.T. branding - matches JANET.ps1) ===
$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Size = New-Object System.Drawing.Size(1400, 70)
$header.BackColor = $colors.TopBar
$header.Anchor = 'Top,Left,Right'
$f.Controls.Add($header)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "J.A.N.E.T. Remote Messager"
$lblTitle.Location = New-Object System.Drawing.Point(75, 12)
$lblTitle.Size = New-Object System.Drawing.Size(700, 28)
$lblTitle.ForeColor = $colors.Gold
$lblTitle.Font = $fonts.JTitle
$lblTitle.BackColor = [System.Drawing.Color]::Transparent
$header.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "Joint Administration and Network Execution Toolkit"
$lblSub.Location = New-Object System.Drawing.Point(77, 40)
$lblSub.Size = New-Object System.Drawing.Size(500, 16)
$lblSub.ForeColor = $colors.TextSecondary
$lblSub.Font = $fonts.JSub
$lblSub.BackColor = [System.Drawing.Color]::Transparent
$header.Controls.Add($lblSub)

$lblVer = New-Object System.Windows.Forms.Label
$lblVer.Text = "v1.2  |  Mass Messenger"
$lblVer.Location = New-Object System.Drawing.Point(77, 56)
$lblVer.Size = New-Object System.Drawing.Size(300, 12)
$lblVer.ForeColor = $colors.GoldDim
$lblVer.Font = $fonts.Tiny
$lblVer.BackColor = [System.Drawing.Color]::Transparent
$header.Controls.Add($lblVer)

## Close Tool — top-right of the header (matches WPT pattern). Single
## sanctioned form egress: sets the X-block allow flag, then closes;
## FormClosing guard cancels every other origin.
$btnHdrCloseTool = New-StyledButton -Text "Close Tool" `
    -Location (New-Object System.Drawing.Point(($f.ClientSize.Width - 110 - 16), 20)) `
    -Size (New-Object System.Drawing.Size(110, 28)) -BgColor $colors.Danger `
    -FgColor ([System.Drawing.Color]::White) -Font $fonts.Button
$btnHdrCloseTool.Anchor = 'Top,Right'
$btnHdrCloseTool.Add_Click({
    Set-JanetAllowClose $true
    $f.Close()
}.GetNewClosure())
$header.Controls.Add($btnHdrCloseTool)

# 2px gold accent line below the header - matches JANET.ps1
$goldLine = New-Object System.Windows.Forms.Panel
$goldLine.Location = New-Object System.Drawing.Point(0, 70)
$goldLine.Size = New-Object System.Drawing.Size(1400, 2)
$goldLine.BackColor = $colors.Gold
$goldLine.Anchor = 'Top,Left,Right'
$f.Controls.Add($goldLine)
#endregion

#region === CREDENTIAL STRIP ===
$credStrip = New-Object System.Windows.Forms.Panel
$credStrip.Location = New-Object System.Drawing.Point(0, 74)
$credStrip.Size = New-Object System.Drawing.Size(1400, 44)
$credStrip.BackColor = $colors.Panel
$credStrip.Anchor = 'Top,Left,Right'
$f.Controls.Add($credStrip)

$lblCredHdr = New-Object System.Windows.Forms.Label
$lblCredHdr.Text = "ADW CREDENTIALS"
$lblCredHdr.Location = New-Object System.Drawing.Point(15, 8)
$lblCredHdr.Size = New-Object System.Drawing.Size(140, 14)
$lblCredHdr.ForeColor = $colors.GoldDim; $lblCredHdr.Font = $fonts.Tiny
$credStrip.Controls.Add($lblCredHdr)

$btnSetCreds = New-StyledButton -Text "Set Credentials..." -Location (New-Object System.Drawing.Point(15, 22)) `
    -Size (New-Object System.Drawing.Size(140, 20)) -BgColor $colors.Accent -FgColor ([System.Drawing.Color]::White) -Font $fonts.Small
$credStrip.Controls.Add($btnSetCreds)

$lblCredStatus = New-Object System.Windows.Forms.Label
# v17 - reflect inherited credential from J.A.N.E.T. launcher at startup
if ($global:Cred) {
    $lblCredStatus.Text      = "Active: $($global:Cred.UserName)  (inherited from launcher)"
    $lblCredStatus.ForeColor = $colors.Success
} else {
    $lblCredStatus.Text      = "No credentials set - required before sending"
    $lblCredStatus.ForeColor = $colors.Danger
}
$lblCredStatus.Location = New-Object System.Drawing.Point(165, 22)
$lblCredStatus.Size = New-Object System.Drawing.Size(800, 18)
$lblCredStatus.Font = $fonts.LabelBold
$lblCredStatus.BackColor = [System.Drawing.Color]::Transparent
$credStrip.Controls.Add($lblCredStatus)

$btnSetCreds.Add_Click({
    $c = Get-Credential -Message "Enter your ADW / privileged admin credentials"
    if ($c) {
        $global:Cred = $c
        $lblCredStatus.Text = "Active: $($c.UserName)  (ADM)"
        $lblCredStatus.ForeColor = $colors.Success
        Log-Activity "Credentials set: $($c.UserName)" $colors.Success
    }
})
#endregion

#region === MAIN CONTENT CONTAINER ===
$mainY = 124
$main = New-Object System.Windows.Forms.Panel
$main.Location = New-Object System.Drawing.Point(0, $mainY)
$main.Size = New-Object System.Drawing.Size(1400, ($f.ClientSize.Height - $mainY - 28))
$main.BackColor = $colors.Background
$main.Anchor = 'Top,Left,Right,Bottom'
$f.Controls.Add($main)

# === LEFT COLUMN: Targets ===
$colLeftW = 340
$pnlTargets = New-Object System.Windows.Forms.Panel
$pnlTargets.Location = New-Object System.Drawing.Point(10, 5)
$pnlTargets.Size = New-Object System.Drawing.Size($colLeftW, ($main.Height - 15))
$pnlTargets.BackColor = $colors.Panel
$pnlTargets.Anchor = 'Top,Left,Bottom'
$main.Controls.Add($pnlTargets)

$lblTgtHdr = New-Object System.Windows.Forms.Label
$lblTgtHdr.Text = "TARGET MACHINES"
$lblTgtHdr.Location = New-Object System.Drawing.Point(12, 10)
$lblTgtHdr.Size = New-Object System.Drawing.Size(260, 18)
$lblTgtHdr.ForeColor = $colors.Gold; $lblTgtHdr.Font = $fonts.Section
$pnlTargets.Controls.Add($lblTgtHdr)

$lblTgtHint = New-Object System.Windows.Forms.Label
$lblTgtHint.Text = "Hostnames, comma or newline separated"
$lblTgtHint.Location = New-Object System.Drawing.Point(12, 32)
$lblTgtHint.Size = New-Object System.Drawing.Size(300, 14)
$lblTgtHint.ForeColor = $colors.TextSecondary; $lblTgtHint.Font = $fonts.Small
$pnlTargets.Controls.Add($lblTgtHint)

$txtTargets = New-Object System.Windows.Forms.TextBox
$txtTargets.Location = New-Object System.Drawing.Point(12, 50)
$txtTargets.Size = New-Object System.Drawing.Size(($colLeftW - 24), ($pnlTargets.Height - 122))
$txtTargets.Multiline = $true; $txtTargets.ScrollBars = "Vertical"
$txtTargets.BackColor = $colors.Input; $txtTargets.ForeColor = $colors.Console
$txtTargets.Font = $fonts.Console; $txtTargets.BorderStyle = 'FixedSingle'
$txtTargets.Anchor = 'Top,Left,Right,Bottom'
$pnlTargets.Controls.Add($txtTargets)

$btnImportY = $pnlTargets.Height - 62
$btnImport = New-StyledButton -Text "Import TXT" -Location (New-Object System.Drawing.Point(12, $btnImportY)) `
    -Size (New-Object System.Drawing.Size(85, 26)) -BgColor $colors.PanelLight -Font $fonts.Button
$btnImport.Anchor = 'Bottom,Left'
$pnlTargets.Controls.Add($btnImport)

$btnClearTgt = New-StyledButton -Text "Clear" -Location (New-Object System.Drawing.Point(103, $btnImportY)) `
    -Size (New-Object System.Drawing.Size(55, 26)) -BgColor $colors.Danger -Font $fonts.Button
$btnClearTgt.Anchor = 'Bottom,Left'
$pnlTargets.Controls.Add($btnClearTgt)

$btnPingAll = New-StyledButton -Text "Ping All" -Location (New-Object System.Drawing.Point(164, $btnImportY)) `
    -Size (New-Object System.Drawing.Size(75, 26)) -BgColor $colors.Cyan -Font $fonts.Button
$btnPingAll.Anchor = 'Bottom,Left'
$pnlTargets.Controls.Add($btnPingAll)

$lblTgtCount = New-Object System.Windows.Forms.Label
$lblTgtCount.Text = "0 targets"
$lblTgtCount.Location = New-Object System.Drawing.Point(248, ($btnImportY + 5))
$lblTgtCount.Size = New-Object System.Drawing.Size(120, 18)
$lblTgtCount.ForeColor = $colors.TextSecondary; $lblTgtCount.Font = $fonts.LabelBold
$lblTgtCount.Anchor = 'Bottom,Left'
$pnlTargets.Controls.Add($lblTgtCount)

$btnImport.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Text Files (*.txt)|*.txt|CSV (*.csv)|*.csv|All (*.*)|*.*"
    $dlg.Title = "Import Target List"
    if ($dlg.ShowDialog() -eq 'OK') {
        $lines = Get-Content $dlg.FileName -EA SilentlyContinue | Where-Object { $_.Trim() -ne "" }
        if ($lines) {
            $cur = $txtTargets.Text.Trim()
            if ($cur -and -not $cur.EndsWith("`n")) { $txtTargets.AppendText("`r`n") }
            $txtTargets.AppendText(($lines -join "`r`n"))
            Log-Activity "Imported $($lines.Count) host(s) from $([System.IO.Path]::GetFileName($dlg.FileName))" $colors.Accent
        }
    }
})
$btnClearTgt.Add_Click({ $txtTargets.Clear() })

function Get-Targets {
    # Case-insensitive dedup so PC01 and pc01 are treated as the same host
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.ArrayList
    foreach ($raw in ($txtTargets.Text -split "[,`r`n]+")) {
        $t = $raw.Trim()
        if ($t -ne "" -and $seen.Add($t)) { [void]$out.Add($t) }
    }
    return ,$out.ToArray()
}

$txtTargets.Add_TextChanged({
    $n = (Get-Targets).Count
    $lblTgtCount.Text = "$n target$(if($n -ne 1){'s'})"
    $lblTgtCount.ForeColor = if ($n -gt 0) { $colors.Success } else { $colors.TextSecondary }
})

# === MIDDLE COLUMN: Message composer ===
$colMidX = $colLeftW + 20
$colMidW = 500
$pnlMsg = New-Object System.Windows.Forms.Panel
$pnlMsg.Location = New-Object System.Drawing.Point($colMidX, 5)
$pnlMsg.Size = New-Object System.Drawing.Size($colMidW, ($main.Height - 15))
$pnlMsg.BackColor = $colors.Panel
$pnlMsg.Anchor = 'Top,Left,Bottom'
$main.Controls.Add($pnlMsg)

$lblMsgHdr = New-Object System.Windows.Forms.Label
$lblMsgHdr.Text = "MESSAGE COMPOSER"
$lblMsgHdr.Location = New-Object System.Drawing.Point(12, 10)
$lblMsgHdr.Size = New-Object System.Drawing.Size(260, 18)
$lblMsgHdr.ForeColor = $colors.Gold; $lblMsgHdr.Font = $fonts.Section
$pnlMsg.Controls.Add($lblMsgHdr)

$lblMT = New-Object System.Windows.Forms.Label
$lblMT.Text = "Title:"; $lblMT.Location = New-Object System.Drawing.Point(12, 34)
$lblMT.AutoSize = $true; $lblMT.ForeColor = $colors.TextSecondary; $lblMT.Font = $fonts.LabelBold
$pnlMsg.Controls.Add($lblMT)

$txtTitle = New-Object System.Windows.Forms.TextBox
$txtTitle.Location = New-Object System.Drawing.Point(12, 52)
$txtTitle.Size = New-Object System.Drawing.Size(($colMidW - 24), 24)
$txtTitle.Anchor = 'Top,Left,Right'
$txtTitle.Text = "Message from the 48 Communications Squadron"
$txtTitle.BackColor = $colors.Input; $txtTitle.ForeColor = $colors.TextPrimary
$txtTitle.Font = $fonts.Console; $txtTitle.BorderStyle = 'FixedSingle'
$pnlMsg.Controls.Add($txtTitle)

$lblMB = New-Object System.Windows.Forms.Label
$lblMB.Text = "Body:"; $lblMB.Location = New-Object System.Drawing.Point(12, 84)
$lblMB.AutoSize = $true; $lblMB.ForeColor = $colors.TextSecondary; $lblMB.Font = $fonts.LabelBold
$pnlMsg.Controls.Add($lblMB)

$lblCharCount = New-Object System.Windows.Forms.Label
$lblCharCount.Text = "0 chars"
$lblCharCount.Location = New-Object System.Drawing.Point(400, 84)
$lblCharCount.Size = New-Object System.Drawing.Size(80, 14)
$lblCharCount.ForeColor = $colors.TextDim; $lblCharCount.Font = $fonts.Small
$lblCharCount.TextAlign = 'TopRight'
$lblCharCount.Anchor = 'Top,Right'
$pnlMsg.Controls.Add($lblCharCount)

$txtBody = New-Object System.Windows.Forms.TextBox
$txtBody.Location = New-Object System.Drawing.Point(12, 102)
$txtBody.Size = New-Object System.Drawing.Size(($colMidW - 24), 218)
$txtBody.Anchor = 'Top,Left,Right'
$txtBody.Multiline = $true; $txtBody.ScrollBars = "Vertical"
$txtBody.BackColor = $colors.Input; $txtBody.ForeColor = $colors.TextPrimary
$txtBody.Font = $fonts.Console; $txtBody.BorderStyle = 'FixedSingle'
$pnlMsg.Controls.Add($txtBody)

$txtBody.Add_TextChanged({ $lblCharCount.Text = "$($txtBody.Text.Length) chars" })

$lblTO = New-Object System.Windows.Forms.Label
$lblTO.Text = "DISPLAY OPTIONS"
$lblTO.Location = New-Object System.Drawing.Point(12, 332)
$lblTO.Size = New-Object System.Drawing.Size(200, 14)
$lblTO.ForeColor = $colors.GoldDim; $lblTO.Font = $fonts.Tiny
$pnlMsg.Controls.Add($lblTO)

$chkRequireOK = New-Object System.Windows.Forms.CheckBox
$chkRequireOK.Location = New-Object System.Drawing.Point(12, 352)
$chkRequireOK.Size = New-Object System.Drawing.Size(460, 22)
$chkRequireOK.Text = "Require user to click OK (popup stays until dismissed)"
$chkRequireOK.ForeColor = $colors.Cyan; $chkRequireOK.Font = $fonts.LabelBold
$chkRequireOK.BackColor = [System.Drawing.Color]::Transparent
$pnlMsg.Controls.Add($chkRequireOK)

$lblToHint = New-Object System.Windows.Forms.Label
$lblToHint.Text = "When unchecked, message auto-dismisses after timeout below."
$lblToHint.Location = New-Object System.Drawing.Point(32, 374)
$lblToHint.Size = New-Object System.Drawing.Size(450, 14)
$lblToHint.ForeColor = $colors.TextSecondary; $lblToHint.Font = $fonts.Small
$pnlMsg.Controls.Add($lblToHint)

$lblTOSec = New-Object System.Windows.Forms.Label
$lblTOSec.Text = "Auto-dismiss timeout (seconds):"
$lblTOSec.Location = New-Object System.Drawing.Point(12, 398)
$lblTOSec.AutoSize = $true; $lblTOSec.ForeColor = $colors.TextSecondary; $lblTOSec.Font = $fonts.Label
$pnlMsg.Controls.Add($lblTOSec)

$numTimeout = New-Object System.Windows.Forms.NumericUpDown
$numTimeout.Location = New-Object System.Drawing.Point(220, 395)
$numTimeout.Size = New-Object System.Drawing.Size(70, 24)
$numTimeout.Minimum = 5; $numTimeout.Maximum = 3600; $numTimeout.Value = 60
$numTimeout.BackColor = $colors.Input; $numTimeout.ForeColor = $colors.TextPrimary
$numTimeout.BorderStyle = 'FixedSingle'; $numTimeout.Font = $fonts.Label
$pnlMsg.Controls.Add($numTimeout)

$chkRequireOK.Add_CheckedChanged({
    $numTimeout.Enabled = -not $chkRequireOK.Checked
    $lblTOSec.ForeColor = if ($chkRequireOK.Checked) { $colors.TextDim } else { $colors.TextSecondary }
})

$chkParallel = New-Object System.Windows.Forms.CheckBox
$chkParallel.Location = New-Object System.Drawing.Point(12, 428)
$chkParallel.Size = New-Object System.Drawing.Size(460, 22)
$chkParallel.Text = "Send in parallel (faster for large target lists)"
$chkParallel.Checked = $true
$chkParallel.ForeColor = $colors.TextSecondary; $chkParallel.Font = $fonts.Label
$chkParallel.BackColor = [System.Drawing.Color]::Transparent
$pnlMsg.Controls.Add($chkParallel)

# Send button - LARGE (toggles to Cancel when sending)
$btnSendY = $pnlMsg.Height - 70
$btnSend = New-StyledButton -Text "SEND MESSAGE TO TARGETS" `
    -Location (New-Object System.Drawing.Point(12, $btnSendY)) `
    -Size (New-Object System.Drawing.Size(($colMidW - 24), 50)) `
    -BgColor $colors.Accent
$btnSend.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$btnSend.Anchor = 'Bottom,Left,Right'
$pnlMsg.Controls.Add($btnSend)

# === RIGHT COLUMN: Activity Log + Stats + Export Row ===
$colRightX = $colMidX + $colMidW + 10
$pnlLog = New-Object System.Windows.Forms.Panel
$pnlLog.Location = New-Object System.Drawing.Point($colRightX, 5)
$pnlLog.Size = New-Object System.Drawing.Size(($f.ClientSize.Width - $colRightX - 15), ($main.Height - 15))
$pnlLog.BackColor = $colors.Panel
$pnlLog.Anchor = 'Top,Left,Right,Bottom'
$main.Controls.Add($pnlLog)

$lblLogHdr = New-Object System.Windows.Forms.Label
$lblLogHdr.Text = "ACTIVITY LOG"
$lblLogHdr.Location = New-Object System.Drawing.Point(12, 10)
$lblLogHdr.Size = New-Object System.Drawing.Size(200, 18)
$lblLogHdr.ForeColor = $colors.Gold; $lblLogHdr.Font = $fonts.Section
$pnlLog.Controls.Add($lblLogHdr)

# Stats panel
$statsPanel = New-Object System.Windows.Forms.Panel
$statsPanel.Location = New-Object System.Drawing.Point(12, 32)
$statsPanel.Size = New-Object System.Drawing.Size(($pnlLog.Width - 24), 50)
$statsPanel.Anchor = 'Top,Left,Right'
$statsPanel.BackColor = $colors.PanelLight
$pnlLog.Controls.Add($statsPanel)

$lblStatSent = New-Object System.Windows.Forms.Label
$lblStatSent.Text = "0"; $lblStatSent.Location = New-Object System.Drawing.Point(10, 5)
$lblStatSent.Size = New-Object System.Drawing.Size(80, 26); $lblStatSent.ForeColor = $colors.Success
$lblStatSent.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblStatSent.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatSent)
$lblStatSentCap = New-Object System.Windows.Forms.Label
$lblStatSentCap.Text = "SENT"; $lblStatSentCap.Location = New-Object System.Drawing.Point(10, 32)
$lblStatSentCap.Size = New-Object System.Drawing.Size(80, 14); $lblStatSentCap.ForeColor = $colors.TextSecondary
$lblStatSentCap.Font = $fonts.Tiny; $lblStatSentCap.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatSentCap)

$lblStatFail = New-Object System.Windows.Forms.Label
$lblStatFail.Text = "0"; $lblStatFail.Location = New-Object System.Drawing.Point(100, 5)
$lblStatFail.Size = New-Object System.Drawing.Size(80, 26); $lblStatFail.ForeColor = $colors.Danger
$lblStatFail.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblStatFail.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatFail)
$lblStatFailCap = New-Object System.Windows.Forms.Label
$lblStatFailCap.Text = "FAILED"; $lblStatFailCap.Location = New-Object System.Drawing.Point(100, 32)
$lblStatFailCap.Size = New-Object System.Drawing.Size(80, 14); $lblStatFailCap.ForeColor = $colors.TextSecondary
$lblStatFailCap.Font = $fonts.Tiny; $lblStatFailCap.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatFailCap)

$lblStatTotal = New-Object System.Windows.Forms.Label
$lblStatTotal.Text = "0"; $lblStatTotal.Location = New-Object System.Drawing.Point(190, 5)
$lblStatTotal.Size = New-Object System.Drawing.Size(80, 26); $lblStatTotal.ForeColor = $colors.Accent
$lblStatTotal.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblStatTotal.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatTotal)
$lblStatTotalCap = New-Object System.Windows.Forms.Label
$lblStatTotalCap.Text = "TOTAL"; $lblStatTotalCap.Location = New-Object System.Drawing.Point(190, 32)
$lblStatTotalCap.Size = New-Object System.Drawing.Size(80, 14); $lblStatTotalCap.ForeColor = $colors.TextSecondary
$lblStatTotalCap.Font = $fonts.Tiny; $lblStatTotalCap.TextAlign = 'MiddleCenter'
$statsPanel.Controls.Add($lblStatTotalCap)

$progSend = New-Object System.Windows.Forms.ProgressBar
$progSend.Location = New-Object System.Drawing.Point(280, 14)
$progSend.Size = New-Object System.Drawing.Size(($statsPanel.Width - 295), 24)
$progSend.Anchor = 'Top,Left,Right'
$progSend.Minimum = 0; $progSend.Maximum = 100; $progSend.Value = 0
$statsPanel.Controls.Add($progSend)

# Export row (dedicated, between stats panel and log box)
$lblExpHdr = New-Object System.Windows.Forms.Label
$lblExpHdr.Text = "EXPORT RESULTS:"
$lblExpHdr.Location = New-Object System.Drawing.Point(12, 92)
$lblExpHdr.Size = New-Object System.Drawing.Size(110, 16)
$lblExpHdr.ForeColor = $colors.GoldDim; $lblExpHdr.Font = $fonts.Tiny
$pnlLog.Controls.Add($lblExpHdr)

$btnExpSent = New-StyledButton -Text "Sent XLSX" -Location (New-Object System.Drawing.Point(125, 88)) `
    -Size (New-Object System.Drawing.Size(80, 24)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnExpSent.Anchor = 'Top,Left'; $btnExpSent.Enabled = $false
$pnlLog.Controls.Add($btnExpSent)

$btnExpFailed = New-StyledButton -Text "Failed XLSX" -Location (New-Object System.Drawing.Point(211, 88)) `
    -Size (New-Object System.Drawing.Size(85, 24)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnExpFailed.Anchor = 'Top,Left'; $btnExpFailed.Enabled = $false
$pnlLog.Controls.Add($btnExpFailed)

$btnExpAll = New-StyledButton -Text "All XLSX" -Location (New-Object System.Drawing.Point(302, 88)) `
    -Size (New-Object System.Drawing.Size(75, 24)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnExpAll.Anchor = 'Top,Left'; $btnExpAll.Enabled = $false
$pnlLog.Controls.Add($btnExpAll)

# Log box (pushed down to Y=118 to clear export row)
$oLog = New-OutputBox -Location (New-Object System.Drawing.Point(12, 118)) `
    -Size (New-Object System.Drawing.Size(($pnlLog.Width - 24), ($pnlLog.Height - 166)))
$oLog.Anchor = 'Top,Left,Right,Bottom'
$pnlLog.Controls.Add($oLog)

# Bottom log toolbar
$btnLogClear = New-StyledButton -Text "Clear Log" -Location (New-Object System.Drawing.Point(12, ($pnlLog.Height - 38))) `
    -Size (New-Object System.Drawing.Size(90, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnLogClear.Anchor = 'Bottom,Left'
$pnlLog.Controls.Add($btnLogClear)

$btnLogCopy = New-StyledButton -Text "Copy All" -Location (New-Object System.Drawing.Point(108, ($pnlLog.Height - 38))) `
    -Size (New-Object System.Drawing.Size(90, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnLogCopy.Anchor = 'Bottom,Left'
$pnlLog.Controls.Add($btnLogCopy)

$btnLogSave = New-StyledButton -Text "Save Log..." -Location (New-Object System.Drawing.Point(204, ($pnlLog.Height - 38))) `
    -Size (New-Object System.Drawing.Size(100, 26)) -BgColor $colors.PanelLight -Font $fonts.Small
$btnLogSave.Anchor = 'Bottom,Left'
$pnlLog.Controls.Add($btnLogSave)

$btnLogClear.Add_Click({ $oLog.Clear() })
$btnLogCopy.Add_Click({ if ($oLog.Text) { [System.Windows.Forms.Clipboard]::SetText($oLog.Text) } })
$btnLogSave.Add_Click({
    if (-not $oLog.Text) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Log|*.log|Text|*.txt|All|*.*"
    $dlg.FileName = "JRMT_ActivityLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    if ($dlg.ShowDialog() -eq 'OK') { $oLog.Text | Out-File $dlg.FileName -Encoding UTF8 }
})

$btnExpSent.BringToFront(); $btnExpFailed.BringToFront(); $btnExpAll.BringToFront(); $lblExpHdr.BringToFront()
#endregion

#region === RUNSPACE POOL ===
function Init-RunspacePool {
    if ($global:RunspacePool -and $global:RunspacePool.RunspacePoolStateInfo.State -eq 'Opened') { return }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $global:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 16, $iss, $Host)
    $global:RunspacePool.Open()
    Write-JLog "RunspacePool opened (1-16 threads)"
}

# Per-host scriptblock:
#   1. Ping check (always — populates Pingable in result)
#   2. New-PSSession with explicit OpenTimeout/OperationTimeout (avoids hangs)
#   3. Detect interactive sessions via Win32_Process (explorer.exe)
#   4. msg * broadcast via stdin pipe; per-session fallback if needed
$script:SendScriptBlock = {
    param($hostname, $cred, $msgTitle, $msgBody, $timeout, $requireOK, $openMs, $opMs)
    $result = @{ Host = $hostname; Success = $false; Sessions = 0; Pingable = $false; Error = $null; Detail = $null; Diagnostic = $null }

    # Ping
    try { $result.Pingable = [bool](Test-Connection -ComputerName $hostname -Count 1 -Quiet -EA SilentlyContinue) } catch { $result.Pingable = $false }
    if (-not $result.Pingable) { $result.Error = "Host not pingable"; return $result }

    try {
        # Explicit timeouts - prevents indefinite hangs on stuck WinRM
        $sessionOpts = New-PSSessionOption -OpenTimeout $openMs -OperationTimeout $opMs -CancelTimeout 5000
        $session = New-PSSession -ComputerName $hostname -Credential $cred -SessionOption $sessionOpts -EA Stop
        try {
            $sessionResult = Invoke-Command -Session $session -ScriptBlock {
                param($t, $b, $to, $req)
                $fullMsg = "$t`r`n`r`n$b"
                $diag = New-Object System.Collections.ArrayList
                $count = 0

                # Detect interactive sessions via explorer.exe
                $sessionIds = New-Object System.Collections.ArrayList
                try {
                    $explorerProcs = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -EA Stop)
                    foreach ($p in $explorerProcs) {
                        $sid = [string]$p.SessionId
                        if ($sid -and [int]$sid -gt 0 -and [int]$sid -lt 1000 -and $sessionIds -notcontains $sid) {
                            [void]$sessionIds.Add($sid)
                        }
                    }
                    [void]$diag.Add("explorer.count=$($explorerProcs.Count)")
                    [void]$diag.Add("explorer.ids=[$($sessionIds -join ',')]")
                } catch { [void]$diag.Add("explorer.exception=$($_.Exception.Message)") }

                # Fallback to qwinsta if explorer found nothing
                if ($sessionIds.Count -eq 0) {
                    try {
                        $qw = qwinsta 2>&1
                        $qwExit = $LASTEXITCODE
                        [void]$diag.Add("qw.exit=$qwExit")
                        if ($qwExit -eq 0 -and $qw) {
                            for ($i = 1; $i -lt @($qw).Count; $i++) {
                                $line = $qw[$i]
                                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                                if ($line -match '\s(\d+)\s+(Active|Disc)') {
                                    $sid = $matches[1]; $state = $matches[2]
                                    if ($state -eq 'Active' -and [int]$sid -gt 0 -and [int]$sid -lt 1000 -and $sessionIds -notcontains $sid) {
                                        [void]$sessionIds.Add($sid)
                                    }
                                }
                            }
                            [void]$diag.Add("qw.ids=[$($sessionIds -join ',')]")
                        }
                    } catch { [void]$diag.Add("qw.exception=$($_.Exception.Message)") }
                }

                if ($sessionIds.Count -eq 0) {
                    return @{ Count = 0; Error = "No interactive user sessions detected on target"; Diagnostic = ($diag -join ' | ') }
                }

                # msg * broadcast via stdin
                try {
                    if ($req) {
                        $bcastOut = $fullMsg | & msg.exe * "/TIME:99999" 2>&1
                    } else {
                        $bcastOut = $fullMsg | & msg.exe * "/TIME:$to" 2>&1
                    }
                    $bcastExit = $LASTEXITCODE
                    $bcastStr = ($bcastOut | Out-String).Trim()
                    [void]$diag.Add("msg*.exit=$bcastExit")
                    if ($bcastStr) {
                        $shortOut = if ($bcastStr.Length -gt 150) { $bcastStr.Substring(0,150) + '...' } else { $bcastStr }
                        [void]$diag.Add("msg*.out=$shortOut")
                    }
                    if ($bcastExit -eq 0 -and -not ($bcastStr -match 'Error|denied|not found|No session|Invalid')) {
                        $count = $sessionIds.Count
                    }
                } catch { [void]$diag.Add("msg*.exception=$($_.Exception.Message)") }

                # Per-session fallback
                if ($count -eq 0) {
                    [void]$diag.Add("fallback=per-session")
                    foreach ($sid in $sessionIds) {
                        try {
                            if ($req) {
                                $perOut = $fullMsg | & msg.exe $sid "/TIME:99999" 2>&1
                            } else {
                                $perOut = $fullMsg | & msg.exe $sid "/TIME:$to" 2>&1
                            }
                            $perExit = $LASTEXITCODE
                            $perStr = ($perOut | Out-String).Trim()
                            [void]$diag.Add("msg.$sid.exit=$perExit")
                            if ($perStr) {
                                $shortOut = if ($perStr.Length -gt 100) { $perStr.Substring(0,100) + '...' } else { $perStr }
                                [void]$diag.Add("msg.$sid.out=$shortOut")
                            }
                            if ($perExit -eq 0 -and -not ($perStr -match 'Error|denied|not found|No session|Invalid')) {
                                $count++
                            }
                        } catch { [void]$diag.Add("msg.$sid.exception=$($_.Exception.Message)") }
                    }
                }

                if ($count -eq 0) {
                    return @{ Count = 0; Error = "msg.exe delivery failed on all strategies"; Diagnostic = ($diag -join ' | ') }
                }
                return @{ Count = $count; Error = $null; Diagnostic = ($diag -join ' | ') }
            } -ArgumentList $msgTitle, $msgBody, $timeout, $requireOK -EA Stop

            $result.Sessions   = $sessionResult.Count
            $result.Success    = ($sessionResult.Count -gt 0)
            $result.Diagnostic = $sessionResult.Diagnostic
            if ($sessionResult.Error)                              { $result.Detail = $sessionResult.Error }
            if (-not $result.Success -and -not $result.Detail)     { $result.Detail = "No sessions received message" }
        } finally {
            Remove-PSSession $session -EA SilentlyContinue
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}
#endregion

#region === XLSX WRITER (pure .NET, no ImportExcel/Excel COM needed) ===
function Export-ToXlsx {
    param([Parameter(Mandatory=$true)][array]$Data,
          [Parameter(Mandatory=$true)][string]$Path,
          [string]$SheetName = "Results")
    if (-not $Data -or $Data.Count -eq 0) { throw "No data to export" }

    $escape = {
        param([string]$s)
        if ($null -eq $s) { return "" }
        return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&apos;')
    }
    function Get-ColLetter([int]$idx) {
        $s = ""; $n = $idx
        do { $s = ([char](([int][char]'A') + ($n % 26))).ToString() + $s; $n = [int]([Math]::Floor($n / 26)) - 1 } while ($n -ge 0)
        return $s
    }

    $columns = @($Data[0].PSObject.Properties.Name)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<row r="1">')
    for ($i = 0; $i -lt $columns.Count; $i++) {
        [void]$sb.AppendFormat('<c r="{0}1" t="inlineStr"><is><t>{1}</t></is></c>', (Get-ColLetter $i), (& $escape $columns[$i]))
    }
    [void]$sb.Append('</row>')
    $rowIdx = 2
    foreach ($item in $Data) {
        [void]$sb.AppendFormat('<row r="{0}">', $rowIdx)
        for ($i = 0; $i -lt $columns.Count; $i++) {
            $val = $item.($columns[$i])
            $text = if ($null -eq $val) { "" } else { $val.ToString() }
            [void]$sb.AppendFormat('<c r="{0}{1}" t="inlineStr"><is><t>{2}</t></is></c>', (Get-ColLetter $i), $rowIdx, (& $escape $text))
        }
        [void]$sb.Append('</row>')
        $rowIdx++
    }

    $sheetXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><worksheet xmlns=`"http://schemas.openxmlformats.org/spreadsheetml/2006/main`"><sheetData>$($sb.ToString())</sheetData></worksheet>"
    $workbookXml = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><workbook xmlns=`"http://schemas.openxmlformats.org/spreadsheetml/2006/main`" xmlns:r=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships`"><sheets><sheet name=`"$(& $escape $SheetName)`" sheetId=`"1`" r:id=`"rId1`"/></sheets></workbook>"
    $contentTypesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
    $rootRelsXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    $wbRelsXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'

    if (Test-Path $Path) { Remove-Item $Path -Force }
    $zipStream = [System.IO.File]::Create($Path)
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $parts = @{
            "[Content_Types].xml"          = $contentTypesXml
            "_rels/.rels"                  = $rootRelsXml
            "xl/workbook.xml"              = $workbookXml
            "xl/_rels/workbook.xml.rels"   = $wbRelsXml
            "xl/worksheets/sheet1.xml"     = $sheetXml
        }
        foreach ($name in $parts.Keys) {
            $entry  = $archive.CreateEntry($name)
            $stream = $entry.Open()
            $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
            $writer.Write($parts[$name])
            $writer.Flush(); $writer.Close(); $stream.Close()
        }
    } finally { $archive.Dispose(); $zipStream.Close() }
}
#endregion

#region === STATS / RESULTS / EXPORT ===
function Update-Stats {
    $lblStatSent.Text  = "$($script:SendStats.Sent)"
    $lblStatFail.Text  = "$($script:SendStats.Failed)"
    $lblStatTotal.Text = "$($script:SendStats.Total)"
    if ($script:SendStats.Total -gt 0) {
        $pct = [Math]::Min(100, [int](($script:SendStats.Sent + $script:SendStats.Failed) / $script:SendStats.Total * 100))
        $progSend.Value = $pct
    }
}

function Reset-Stats {
    $script:SendStats = @{ Sent = 0; Failed = 0; Total = 0 }
    $script:SendResults.Clear()
    $script:CancelRequested = $false
    $progSend.Value = 0
    Update-Stats
    $btnExpSent.Enabled = $false
    $btnExpFailed.Enabled = $false
    $btnExpAll.Enabled = $false
}

function Add-SendResult {
    param([string]$Hostname, [string]$Status, [bool]$Pingable = $false,
          [int]$Sessions = 0, [string]$Reason = "", [string]$Diagnostic = "")
    [void]$script:SendResults.Add([PSCustomObject]@{
        Timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Hostname     = $Hostname
        Pingable     = if ($Pingable)            { "Yes" } else { "No" }
        Delivered    = if ($Status -eq 'Sent')   { "Yes" } else { "No" }
        Undelivered  = if ($Status -eq 'Failed') { "Yes" } else { "No" }
        Sessions     = $Sessions
        MessageTitle = $script:LastSendMeta.Title
        Mode         = $script:LastSendMeta.Mode
        Reason       = $Reason
        Diagnostic   = $Diagnostic
    })

    ## JANET centralized logging (v1.3.1: two-bucket model). Sending a popup
    ## message reaches the host but doesn't change its security state ->
    ## TouchHost (counts toward HostsTouched only).
    if ($null -ne $script:JanetSession) {
        $janetResult = if ($Status -eq 'Sent') { 'Success' } elseif ($Status -eq 'Failed') { 'Failure' } else { 'Skipped' }
        try { Write-JanetAction -Action 'TouchHost' -Target $Hostname -Result $janetResult -Detail $Reason } catch {}
    }
}

function Enable-ExportButtons {
    $btnExpSent.Enabled   = (($script:SendResults | Where-Object { $_.Delivered   -eq 'Yes' }).Count -gt 0)
    $btnExpFailed.Enabled = (($script:SendResults | Where-Object { $_.Undelivered -eq 'Yes' }).Count -gt 0)
    $btnExpAll.Enabled    = ($script:SendResults.Count -gt 0)
}

function Export-Results {
    param([ValidateSet('Sent','Failed','All')][string]$Filter, [string]$FileNamePrefix)
    if ($script:SendResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export. Run a send or Ping All first.", "Nothing to Export", 0, 48); return
    }
    $subset = switch ($Filter) {
        'Sent'   { $script:SendResults | Where-Object { $_.Delivered   -eq 'Yes' } }
        'Failed' { $script:SendResults | Where-Object { $_.Undelivered -eq 'Yes' } }
        'All'    { $script:SendResults }
    }
    $subset = @($subset)
    if ($subset.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No '$Filter' rows in the current results.", "Nothing to Export", 0, 48); return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Excel Workbook|*.xlsx|All|*.*"
    $dlg.FileName = "${FileNamePrefix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            $projected = $subset | Select-Object Timestamp, Hostname, Pingable, Delivered, Undelivered, Sessions, MessageTitle, Mode, Reason, Diagnostic
            Export-ToXlsx -Data $projected -Path $dlg.FileName -SheetName $Filter
            Log-Activity "Exported $($subset.Count) row(s) ($Filter) to $($dlg.FileName)" $colors.Accent
        } catch {
            Log-Activity "Export failed: $_" $colors.Danger
            [System.Windows.Forms.MessageBox]::Show("Export failed: $_", "Error", 0, 16)
        }
    }
}

$btnExpSent.Add_Click({   Export-Results -Filter 'Sent'   -FileNamePrefix "JRMT_Delivered" })
$btnExpFailed.Add_Click({ Export-Results -Filter 'Failed' -FileNamePrefix "JRMT_Failed" })
$btnExpAll.Add_Click({    Export-Results -Filter 'All'    -FileNamePrefix "JRMT_AllResults" })
#endregion

#region === PING ALL ===
$btnPingAll.Add_Click({
    $tgts = Get-Targets
    if ($tgts.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Enter targets first.", "No Targets", 0, 48); return }
    $btnPingAll.Enabled = $false; $btnPingAll.Text = "Pinging..."
    Log-Activity "=== Ping check: $($tgts.Count) host(s) ===" $colors.Cyan
    Reset-Stats
    $script:LastSendMeta = @{ Title = "(ping only)"; Mode = "Ping Check"; Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
    $script:SendStats.Total = $tgts.Count
    $upCount = 0; $downCount = 0
    try {
        foreach ($h in $tgts) {
            $pingable = $false
            try { $pingable = [bool](Test-Connection -ComputerName $h -Count 1 -Quiet -EA SilentlyContinue) } catch {}
            if ($pingable) {
                Log-Activity "[$h] ONLINE" $colors.Success; $upCount++
                [void]$script:SendResults.Add([PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Hostname = $h
                    Pingable = "Yes"; Delivered = "N/A"; Undelivered = "N/A"; Sessions = 0
                    MessageTitle = $script:LastSendMeta.Title; Mode = $script:LastSendMeta.Mode
                    Reason = "Online - ping check only"; Diagnostic = ""
                })
            } else {
                Log-Activity "[$h] OFFLINE / not pingable" $colors.Danger; $downCount++
                [void]$script:SendResults.Add([PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Hostname = $h
                    Pingable = "No"; Delivered = "N/A"; Undelivered = "N/A"; Sessions = 0
                    MessageTitle = $script:LastSendMeta.Title; Mode = $script:LastSendMeta.Mode
                    Reason = "Host not pingable"; Diagnostic = ""
                })
            }
            [System.Windows.Forms.Application]::DoEvents()
        }
        Log-Activity "=== Ping complete: $upCount online, $downCount offline ===" $colors.Gold
    } finally {
        $btnPingAll.Enabled = $true; $btnPingAll.Text = "Ping All"
        $btnExpAll.Enabled = ($script:SendResults.Count -gt 0)
        $btnExpSent.Enabled = $false; $btnExpFailed.Enabled = $false
    }
})
#endregion

#region === SEND HANDLER (with cancel + per-job timeout) ===
function Set-SendButtonMode {
    param([ValidateSet('Send','Cancel','Disabled')][string]$Mode)
    switch ($Mode) {
        'Send' {
            $btnSend.Text = "SEND MESSAGE TO TARGETS"
            $btnSend.BackColor = $colors.Gold
            $btnSend.ForeColor = [System.Drawing.Color]::Black
            $btnSend.Enabled = $true
        }
        'Cancel' {
            $btnSend.Text = "CANCEL SEND IN PROGRESS"
            $btnSend.BackColor = $colors.Danger
            $btnSend.ForeColor = [System.Drawing.Color]::White
            $btnSend.Enabled = $true
        }
        'Disabled' {
            $btnSend.Enabled = $false
        }
    }
}

$btnSend.Add_Click({
    # If a send is in progress, this click means CANCEL
    if ($global:ActiveJobs.Count -gt 0) {
        $script:CancelRequested = $true
        Log-Activity "CANCEL requested - stopping in-flight jobs..." $colors.Warning
        Set-SendButtonMode -Mode Disabled
        foreach ($h in @($global:ActiveJobs.Keys)) {
            try { $global:ActiveJobs[$h].PS.Stop() } catch {}
        }
        return
    }

    # Preflight
    $tgts = Get-Targets
    if ($tgts.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Enter at least one target hostname.", "No Targets", 0, 48); return
    }
    if (-not $global:Cred) {
        [System.Windows.Forms.MessageBox]::Show("Set ADW credentials first.", "No Credentials", 0, 48); return
    }
    if ([string]::IsNullOrWhiteSpace($txtBody.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Message body is empty.", "No Message", 0, 48); return
    }
    if ([string]::IsNullOrWhiteSpace($txtTitle.Text)) {
        $txtTitle.Text = "Message from the 48 Communications Squadron"
    }

    $msgTitle = $txtTitle.Text
    $msgBody = $txtBody.Text
    $requireOK = $chkRequireOK.Checked
    $timeout = [int]$numTimeout.Value
    $useParallel = $chkParallel.Checked

    $mode = if ($requireOK) { "REQUIRE OK CLICK" } else { "Auto-dismiss after ${timeout}s" }
    $r = [System.Windows.Forms.MessageBox]::Show(
        "Send message to $($tgts.Count) target(s)?`r`n`r`nMode: $mode`r`nTitle: $msgTitle`r`n`r`nFirst few targets:`r`n$($tgts | Select-Object -First 5 | ForEach-Object { "  - $_" } | Out-String)",
        "Confirm Mass Send", 4, 32)
    if ($r -ne 'Yes') { return }

    Reset-Stats
    $script:SendStats.Total = $tgts.Count
    $script:LastSendMeta = @{ Title = $msgTitle; Mode = $mode; Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
    Update-Stats

    Log-Activity "=== Sending message to $($tgts.Count) target(s) ===" $colors.Gold
    Log-Activity "Mode: $mode" $colors.Cyan
    Log-Activity "Title: $msgTitle" $colors.TextSecondary
    Log-Activity "Timeouts: open=$([int]($script:PSOpenTimeoutMs/1000))s op=$([int]($script:PSOpTimeoutMs/1000))s job=$($script:MaxJobSeconds)s" $colors.TextDim

    if ($useParallel) {
        Set-SendButtonMode -Mode Cancel
        Init-RunspacePool
        $global:ActiveJobs = @{}
        foreach ($h in $tgts) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $global:RunspacePool
            [void]$ps.AddScript($script:SendScriptBlock)
            [void]$ps.AddArgument($h)
            [void]$ps.AddArgument($global:Cred)
            [void]$ps.AddArgument($msgTitle)
            [void]$ps.AddArgument($msgBody)
            [void]$ps.AddArgument($timeout)
            [void]$ps.AddArgument($requireOK)
            [void]$ps.AddArgument($script:PSOpenTimeoutMs)
            [void]$ps.AddArgument($script:PSOpTimeoutMs)
            $handle = $ps.BeginInvoke()
            $global:ActiveJobs[$h] = @{ PS = $ps; Handle = $handle; StartTime = (Get-Date) }
        }
        Log-Activity "Dispatched $($tgts.Count) parallel job(s)" $colors.Accent

        $script:SendTimer = New-Object System.Windows.Forms.Timer
        $script:SendTimer.Interval = 500
        $script:SendTimer.Add_Tick({
            $doneHosts = @()
            foreach ($h in @($global:ActiveJobs.Keys)) {
                $job = $global:ActiveJobs[$h]
                $age = ((Get-Date) - $job.StartTime).TotalSeconds

                # Per-job wall-clock timeout
                if (-not $job.Handle.IsCompleted -and $age -gt $script:MaxJobSeconds) {
                    Log-Activity "[$h] TIMEOUT after $([int]$age)s - aborting" $colors.Danger
                    try { $job.PS.Stop() } catch {}
                    try { $job.PS.Dispose() } catch {}
                    Add-SendResult -Hostname $h -Status 'Failed' -Pingable $false -Reason "Job timeout (>${script:MaxJobSeconds}s)" -Diagnostic "Aborted by per-job timeout"
                    $script:SendStats.Failed++
                    $doneHosts += $h
                    continue
                }

                # Cancellation - mark stopped jobs as cancelled
                if ($script:CancelRequested -and -not $job.Handle.IsCompleted -and $job.PS.InvocationStateInfo.State -in 'Stopping','Stopped') {
                    try { $job.PS.Dispose() } catch {}
                    Add-SendResult -Hostname $h -Status 'Failed' -Pingable $false -Reason "Cancelled by user" -Diagnostic ""
                    $script:SendStats.Failed++
                    Log-Activity "[$h] CANCELLED" $colors.Warning
                    $doneHosts += $h
                    continue
                }

                if ($job.Handle.IsCompleted) {
                    try {
                        $result = $job.PS.EndInvoke($job.Handle) | Select-Object -First 1
                        if ($result.Success) {
                            Log-Activity "[$h] Delivered to $($result.Sessions) session(s)" $colors.Success
                            $script:SendStats.Sent++
                            Add-SendResult -Hostname $h -Status 'Sent' -Pingable $result.Pingable -Sessions $result.Sessions -Reason "Delivered" -Diagnostic $result.Diagnostic
                        } else {
                            $msg = if ($result.Error) { $result.Error } elseif ($result.Detail) { $result.Detail } else { "Unknown failure" }
                            Log-Activity "[$h] FAILED: $msg" $colors.Danger
                            if ($result.Diagnostic) { Log-Activity "  diag: $($result.Diagnostic)" $colors.TextDim }
                            $script:SendStats.Failed++
                            Add-SendResult -Hostname $h -Status 'Failed' -Pingable $result.Pingable -Reason $msg -Diagnostic $result.Diagnostic
                        }
                    } catch {
                        $emsg = "$_"
                        if ($emsg -match 'PipelineStopped|stopped') {
                            Log-Activity "[$h] CANCELLED" $colors.Warning
                            Add-SendResult -Hostname $h -Status 'Failed' -Pingable $false -Reason "Cancelled by user" -Diagnostic ""
                        } else {
                            Log-Activity "[$h] EXCEPTION: $emsg" $colors.Danger
                            Add-SendResult -Hostname $h -Status 'Failed' -Pingable $false -Reason "EXCEPTION: $emsg" -Diagnostic ""
                        }
                        $script:SendStats.Failed++
                    } finally {
                        try { $job.PS.Dispose() } catch {}
                    }
                    $doneHosts += $h
                }
            }
            foreach ($h in $doneHosts) { $global:ActiveJobs.Remove($h) }
            Update-Stats

            # All done?
            if ($global:ActiveJobs.Count -eq 0) {
                $script:SendTimer.Stop(); $script:SendTimer.Dispose(); $script:SendTimer = $null
                $tag = if ($script:CancelRequested) { "(CANCELLED)" } else { "" }
                Log-Activity "=== Send complete $tag : $($script:SendStats.Sent) sent, $($script:SendStats.Failed) failed ===" $colors.Gold
                Set-SendButtonMode -Mode Send
                Enable-ExportButtons
                if ($script:SendResults.Count -gt 0) {
                    Log-Activity "Results ready: use Export buttons to save XLSX" $colors.Gold
                }
            }
        })
        $script:SendTimer.Start()
    } else {
        # Sequential
        Set-SendButtonMode -Mode Disabled
        foreach ($h in $tgts) {
            Log-Activity "[$h] Connecting..." $colors.TextSecondary
            [System.Windows.Forms.Application]::DoEvents()
            try {
                $result = & $script:SendScriptBlock $h $global:Cred $msgTitle $msgBody $timeout $requireOK $script:PSOpenTimeoutMs $script:PSOpTimeoutMs
                if ($result.Success) {
                    Log-Activity "[$h] Delivered to $($result.Sessions) session(s)" $colors.Success
                    $script:SendStats.Sent++
                    Add-SendResult -Hostname $h -Status 'Sent' -Pingable $result.Pingable -Sessions $result.Sessions -Reason "Delivered" -Diagnostic $result.Diagnostic
                } else {
                    $msg = if ($result.Error) { $result.Error } elseif ($result.Detail) { $result.Detail } else { "Unknown failure" }
                    Log-Activity "[$h] FAILED: $msg" $colors.Danger
                    if ($result.Diagnostic) { Log-Activity "  diag: $($result.Diagnostic)" $colors.TextDim }
                    $script:SendStats.Failed++
                    Add-SendResult -Hostname $h -Status 'Failed' -Pingable $result.Pingable -Reason $msg -Diagnostic $result.Diagnostic
                }
            } catch {
                Log-Activity "[$h] EXCEPTION: $_" $colors.Danger
                $script:SendStats.Failed++
                Add-SendResult -Hostname $h -Status 'Failed' -Pingable $false -Reason "EXCEPTION: $_" -Diagnostic ""
            }
            Update-Stats
            [System.Windows.Forms.Application]::DoEvents()
        }
        Log-Activity "=== Send complete: $($script:SendStats.Sent) sent, $($script:SendStats.Failed) failed ===" $colors.Gold
        Set-SendButtonMode -Mode Send
        Enable-ExportButtons
        if ($script:SendResults.Count -gt 0) {
            Log-Activity "Results ready: use Export buttons to save XLSX" $colors.Gold
        }
    }
})
#endregion

#region === FOOTER / CREDITS ===
$footer = New-Object System.Windows.Forms.Panel
$footer.Location = New-Object System.Drawing.Point(0, ($f.ClientSize.Height - 44))
$footer.Size = New-Object System.Drawing.Size($f.ClientSize.Width, 44)
$footer.BackColor = [System.Drawing.Color]::FromArgb(16, 16, 24)
$footer.Anchor = 'Bottom,Left,Right'
$f.Controls.Add($footer)

## Close Tool button moved to the header (top-right). Single egress
## matches the WPT pattern. Footer now shows credit + log path only.

$lblCredit = New-Object System.Windows.Forms.Label
$lblCredit.Text = "Created by: THOMPSON, BRAXTON - 48 CS"
$lblCredit.Location = New-Object System.Drawing.Point(10, 4)
$lblCredit.AutoSize = $true
$lblCredit.ForeColor = $colors.GoldDim; $lblCredit.Font = $fonts.Tiny
$footer.Controls.Add($lblCredit)

$lblLogPath = New-Object System.Windows.Forms.Label
$lblLogPath.Text = "Log: $($global:LogFile)"
$lblLogPath.Location = New-Object System.Drawing.Point(10, 22)
$lblLogPath.Size = New-Object System.Drawing.Size(($f.ClientSize.Width - 30), 14)
$lblLogPath.ForeColor = $colors.TextDim; $lblLogPath.Font = $fonts.Tiny
$lblLogPath.Anchor = 'Bottom,Left,Right'
$footer.Controls.Add($lblLogPath)
#endregion

#region === STARTUP / SHUTDOWN ===
Log-Activity "J.A.N.E.T. Remote Message Tool v1.2 ready" $colors.Gold
Log-Activity "Set credentials, enter targets, compose message, then Send (or Ping All to test reachability first)" $colors.TextSecondary

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

    Write-JLog "Form closing"
    try { if ($script:SendTimer) { $script:SendTimer.Stop(); $script:SendTimer.Dispose() } } catch {}
    try {
        foreach ($j in $global:ActiveJobs.Values) { try { $j.PS.Stop() } catch {}; try { $j.PS.Dispose() } catch {} }
        if ($global:RunspacePool) { $global:RunspacePool.Close(); $global:RunspacePool.Dispose() }
    } catch {}

    ## JANET centralized session close (added in v1.3.1). -ShowDialog presents
    ## the JANET closing-notes form so ASI + notes are captured for the rollup.
    try { Stop-JanetSession -ShowDialog } catch { Write-JLog "JANET Stop-JanetSession failed: $($_.Exception.Message)" }

    Write-JLog "=== Session ended ==="
})

## JANET centralized session (added in v1.3.1). Metric tool: per-host SendMessage
## rows recorded by Add-SendResult; rollup row written on FormClosing with dialog.
try { Start-JanetSession -Tool 'Remote_Message' -Version $JanetRemote_MessageVersion } catch { Write-JLog "JANET Start-JanetSession failed: $($_.Exception.Message)" }

[void]$f.ShowDialog()
#endregion