<#
.NAME
    J.A.N.E.T. Unsupported Product Remediator
.SYNOPSIS
    Joint Administration and Network Execution Toolkit — bulk remediation
    of Tenable / ACAS Unsupported & SEoL product findings.
.DESCRIPTION
    WinForms tool that consumes a Tenable / ACAS "Unsupported / SEoL Product
    Summary and Exploits by Platform" report (PDF or CSV) and bulk-remediates
    the listed unsupported / End-of-Life software across the affected hosts:

        * Uninstall  - native registry-based uninstall lifted from
                       WorkstationPatchingTool's Sw Mgr & Uninstaller tab,
                       parallelized across hosts via RunspacePool. Specialized
                       handlers for Microsoft 365 (SaRA), Adobe Acrobat (GUID-
                       based MSI w/ RunAsPPL guard), and a Tanium safety block.
                       Proven-only gating (v1.1.0): a scanned install is one-
                       click removable only when the catalog proves it EOL --
                       Proven=true (the regex pins an EOL product) OR the
                       installed version parses below VersionMaxExclusive.
                       Unproven family matches (.NET 8, current Firefox/Java,
                       SQL/Oracle) are listed as disabled "Review" rows --
                       surfaced for visibility, never one-click removed without
                       human sign-off.

    UNINSTALL-ONLY (v1.1.0). Update-class findings (catalog Updater set, e.g.
    M365 channel mismatch) are hidden from the Findings grid; remediate those
    with the WPT App Updater. Unsupported operating systems are listed read-
    only on the OS Findings tab with a CSV export, for handoff to whoever runs
    OS rebuilds.

    Visual language: J.A.N.E.T. launcher theme (JANET.ps1 / WPT v6.5.12). Purple
    + Gold on near-black, Cascadia Mono for headings + monospace, Segoe UI for
    body. Identical palette and typography as the launcher and sibling tools.

    Inputs:  PDF (primary fallback path; uses pdftotext.exe -layout) or CSV
             (Tenable export with IP / NetBIOS / DNS / Plugin / Plugin Name /
             Severity / Plugin Output / ... columns). CSV is preferred — exact
             matches come from Plugin Output. PDF mode uses the catalog regex.

    Catalog: ..\JanetLocal\UnsupportedProductCatalog.json. Editable. Reload
             button on the toolbar picks up changes without restarting.

    Spec:    docs/superpowers/specs/2026-05-07-unsupported-product-remediator-design.md
.AUTHOR
    THOMPSON, BRAXTON - 48 CS / SCOO
.VERSION
    1.1.2
.CHANGELOG
    v1.1.2 - 2026-06-18 - UI cleanup pass (NO behaviour change -- the scan /
                          proven-gate / uninstall pipeline is untouched). Fixes
                          blur + tab-strip artifacts that high-DPI displays exposed.
                        * DPI awareness (Set-UprDpiAware: PerMonitorV2 -> PerMonitor
                          -> System fallback, fired before EnableVisualStyles) so
                          WinForms renders at the monitor's native resolution
                          instead of being bitmap-stretched (blurry) on 125/150/
                          200% scaling. Recipe lifted from WPT 6.5.22.
                        * Dark immersive title bar on the main form (DwmSetWindow-
                          Attribute, attr 19/20 + rounded corners) + double-buffer
                          to cut resize flicker.
                        * Top-toolbar reflow: the right cluster (Threads / Reload
                          Catalog / Close Tool) is right-anchored off the live
                          client width, so "Reload Catalog" no longer clips behind
                          "Close Tool". Default form 1280->1340 (min 1320); Dry-run
                          caption trimmed to "Plan-only" with a tooltip.
                        * Tabs: the owner-drawn FlatButtons strip left the area
                          right of the last tab painted light (white) and rendered
                          soft tab text. Replaced with a HIDDEN native strip
                          (ItemSize 0,1, like WPT/STIG) + a custom flat-button nav
                          row driving SelectedIndex via Set-UprActiveTab -- crisp,
                          fully themed, no white.
                        * Corrected the stale window-title version constant (showed
                          v1.0.4 inside the 1.1.x file).
    v1.1.1 - 2026-06-17 - Host-target validation for jagged PDF reports. The
                          Tenable PDF's affected-host table wraps "DOMAIN\HOST"
                          and FQDNs across lines, so the parser could emit domain-
                          only strings (e.g. "S.USAF.MIL", "AREA52.AFNOAPPS.USAF.
                          MIL") or a truncated NetBIOS ("MSEKL-") as a connect
                          target -- a wasted WinRM attempt on a non-host. New
                          Test-UprValidTarget rejects bare domain/org tokens,
                          single-letter fragments, and leading/trailing-hyphen
                          labels; Get-FindingTargetFromHost now returns the first
                          VALID of DNS > NetBIOS > IP, so a garbage DNS fragment
                          falls through to a clean NetBIOS short name or the IP.
                          CSV input (clean columns) is unaffected. Mirrored to the
                          JANET ONE 'upr' module for parity.
    v1.1.0 - 2026-06-17 - Scope realigned to UNINSTALL-ONLY + proven-only gating;
                          registered in the JANET launcher.
                        * Update tab + updater delegation removed from the UI.
                          The tool now only uninstalls. Update-class findings
                          (catalog Updater != null, e.g. M365 channel mismatch)
                          are hidden from the Findings grid.
                        * Per-candidate proven gating. A scanned install is only
                          one-click-checkable when the catalog PROVES it EOL:
                          Proven=true (regex pins an EOL product) OR the installed
                          version parses below VersionMaxExclusive. Unproven family
                          matches (.NET 8, current Firefox/Java, SQL/Oracle) are
                          listed as disabled "Review" rows -- surfaced, never
                          one-click removed without human sign-off. Mirrors the
                          JANET ONE WPT Get-WptUnsupportedAction gate.
                        * Catalog: Proven flags added (Flash/Shockwave, perpetual
                          Office); .NET Core/Runtime/SDK/ASP.NET gated to
                          VersionMaxExclusive 8.0 so supported .NET 8/9 is never
                          auto-removed and SEoL .NET (<8) is proven-by-version.
                        * BUGFIX: PDF ingest returned 0 findings on report paths
                          with spaces/parentheses (e.g. "...Platform (1).pdf").
                          PS 5.1 Start-Process does not quote -ArgumentList array
                          elements, so pdftotext got mangled args and exited 99.
                          Now passes a single pre-quoted argument string.
                        * Registered in JANET_Config.json + JANET.ps1
                          Get-DefaultConfig (Category Patch); promoted from
                          Tools\Archive to live Tools\.
    v1.0.4 - 2026-05-10 - pdftotext.exe resolution made portable. Was a single
                          hardcoded path 'C:\Program Files\Git\mingw64\bin\
                          pdftotext.exe'; now walks a candidate list (Program
                          Files / Program Files (x86) / LocalAppData install /
                          C:\Tools) and falls through to PATH. Error message
                          updated to point at fixable locations. PDF ingest
                          no longer breaks on workstations with non-standard
                          Git for Windows installs.
                          Plus JANET replay filter widened to *_detail*.csv /
                          *_usage*.csv so schema-rotation sister files are
                          drained instead of stranded.
    v1.0.3 - 2026-05-10 - Renamed $UprVersion -> $JanetUnsupportedProductRemediatorVersion
                          for cross-tool naming consistency. No behavior change.
    v1.0.2 - 2026-05-08 - Host-class filter + WPT-style status strip.
                        * Findings tab gets a quick-filter sub-panel
                          (Hosts: All / Workstations (MSEKL/MSEKW) /
                          Non-Workstations) plus a Search box keyed on
                          Plugin / PluginName / Category, mirroring the
                          WPT Software Manager strip (line ~6412).
                        * Filter is global - the dropdown also clips host
                          enumeration on the Uninstall scan, the Update
                          dispatch list, and the OS Findings grid, so an
                          operator restricting to MSEKL/MSEKW won't
                          accidentally hit servers from a Tenable report
                          that mixes them.
                        * Status strip rebuilt to the WPT pattern: 8px
                          green pulse + SESSION (user@host) + TARGETS
                          (live count of filtered hosts) + FILTER label
                          + LOG path right-anchored. Height dropped 44->32
                          to match WPT 6.5.14 visual rhythm.
                        * Top toolbar gets a small cyan 'live' pulse
                          beside the Close Tool button, matching WPT's
                          top-strip heartbeat.
    v1.0.1 - 2026-05-08 - JANET centralized-logging schema cleanup (single
                          SessionEnd rollup row; Snapshot rows retired) and
                          the WPT-themed Closing Notes prompt rolled across
                          the suite.
    v1.0.0 - 2026-05-07 - First release.
            * Tabbed WinForms UI (Import & Findings / Uninstall / Update / OS
              Findings / History) themed to the J.A.N.E.T. launcher palette
              (Purple #8C64DC + Gold #DAB452 on near-black).
            * PDF parser via pdftotext.exe -layout, section-anchored regex
              scan, stops before Top-20 Exploitable / Exploitable Framework
              Breakdown so non-actionable rows stay out of the findings grid.
            * CSV parser uses Tenable's Plugin Output column to populate
              MatchedDisplayName / MatchedVersion / MatchedPath per host so
              the registry scan on Tab 2 can be skipped on hosts where the
              plugin output already pinpointed the install.
            * Bulk uninstall engine lifted from WorkstationPatchingTool 6.5.12
              (Sw Mgr & Uninstaller tab, lines ~6195-6494) and rewrapped in a
              RunspacePool. Tanium installations are explicitly skipped.
            * Bulk update delegates to existing JANET updaters (M365 force-
              update via OfficeC2RClient.exe; Chrome / Edge / Defender stubs
              wired to their per-product update commands).
            * Dry-run flag on the toolbar — uninstalls and updates log the
              planned action and skip the actual state change.
            * JANET centralized logging block lifted verbatim from
              RemoteMessageTool 1.3.1; per-host action rows go to
              \\dm-tn-01\sh-usafe-automation$\JANET\Logs\Unsupported_Product_Remediator\<...>\<YYYY-MM>_detail.csv,
              session rollup row written on close with closing-notes dialog.
            * Credential inheritance from $env:JANET_CRED_FILE when launched
              from JANET.ps1, otherwise prompts via Get-Credential on demand.
#>

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -AssemblyName System.IO.Compression -EA SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
###############################################################################
###            SHELL HELPERS  (DPI awareness / dark title bar / dbuf)        ###
###############################################################################
## Lifted from WorkstationPatchingTool 6.5.22 (Set-WptDpiAware / Set-Wpt-
## DarkTitleBar / Enable-WptDoubleBuffer -- the modular WPT v2.4.0 Theme.ps1
## P/Invoke helpers) and renamed Upr* so this tool stays self-contained. The
## '-as [type]' guards make every Add-Type idempotent on relaunch in the same
## PowerShell host. Set-UprDpiAware MUST run before the first window/control is
## created, so it fires here at load, before EnableVisualStyles -- otherwise
## Windows bitmap-stretches the 96-DPI window on 125/150/200% scaling (blur).

function Set-UprDpiAware {
    # Declare the process DPI-aware so WinForms renders at the monitor's native
    # resolution instead of being bitmap-scaled (blurry) by Windows. Best->worst
    # fallback: PerMonitorV2 (-4, Win10 1703+) -> PerMonitor (2, Win8.1+) -> System.
    if (-not ('UprDpi.Api' -as [type])) {
        Add-Type -Namespace 'UprDpi' -Name 'Api' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDpiAwarenessContext(System.IntPtr value);

[System.Runtime.InteropServices.DllImport("shcore.dll")]
public static extern int SetProcessDpiAwareness(int value);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();
'@ -ErrorAction SilentlyContinue
    }
    try { if ([UprDpi.Api]::SetProcessDpiAwarenessContext([System.IntPtr]::new(-4))) { return } } catch {}
    try { [void][UprDpi.Api]::SetProcessDpiAwareness(2); return } catch {}
    try { [void][UprDpi.Api]::SetProcessDPIAware() } catch {}
}

function Set-UprDarkTitleBar {
    # Flip the Windows title bar to dark (DWMWA_USE_IMMERSIVE_DARK_MODE attr
    # 19/20) + rounded corners on Win11 (DWMWA_WINDOW_CORNER_PREFERENCE 33 = round).
    param([Parameter(Mandatory)] $Form)
    if (-not ('Upr.Dwm' -as [type])) {
        Add-Type -Namespace 'Upr' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction SilentlyContinue
    }
    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }
    $enable = 1
    $null = [Upr.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Upr.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)
    $round = 2
    $null = [Upr.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

function Enable-UprDoubleBuffer {
    # Turn on the protected DoubleBuffered property via reflection to cut flicker
    # on resize. Silent no-op if the property is absent.
    param([Parameter(Mandatory)] $Control)
    try {
        $prop = $Control.GetType().GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'Instance, NonPublic')
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

## DPI awareness is a process-wide one-shot; fire it before EnableVisualStyles
## and before any window exists.
try { Set-UprDpiAware } catch {}
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

$JanetUnsupportedProductRemediatorVersion = '1.1.2'

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Lifted verbatim from RemoteMessageTool 1.3.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\... when share is
## unreachable; replays orphan rows on next launch with the share back up.

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
## WindowsShutDown which is allowed through.
function global:Get-JanetAllowClose { return $script:JanetAllowClose }
function global:Set-JanetAllowClose { param($Value) $script:JanetAllowClose = [bool]$Value }

function Get-JanetMonthFile {
    [CmdletBinding()]
    param([switch]$Detail)
    $month = Get-Date -Format 'yyyy-MM'
    if ($Detail) { return "${month}_detail.csv" } else { return "${month}_usage.csv" }
}

function Get-JanetUserFolderName {
    $u = $env:USERNAME; if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Unknown' }
    $cn = $env:COMPUTERNAME; if ([string]::IsNullOrWhiteSpace($cn)) { $cn = 'UnknownPC' }
    $name = "$u - ${cn}_$u"
    return ($name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Get-JanetLocalDir {
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
    [CmdletBinding()] param()
    $edipi = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($edipi)) { $edipi = 'Unknown' }

    $displayName = $null

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$env:USERNAME))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['displayname'] -and $result.Properties['displayname'].Count -gt 0) {
            $displayName = [string]$result.Properties['displayname'][0]
        }
    } catch { $displayName = $null }

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

$script:JanetDetailHeader = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
$script:JanetUsageHeader  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

function Add-JanetCsvHeader {
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

    $beforeCount = $script:JanetSession.Hosts.Count
    [void]$script:JanetSession.Hosts.Add($Target)

    if ($Result -eq 'Failure') {
        $script:JanetSession.Failures++
    }
    if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') {
        $script:JanetSession.VulnsPatched += [int]$ItemCount
    }

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

###############################################################################
###                          COLOR PALETTE & FONTS                          ###
###############################################################################
## Purple #8C64DC + Gold #DAB452 on near-black, matching JANET launcher
## (JANET.ps1) and WPT v6.5.12. Same key names as WPT so familiar call sites
## like $c.BG / $c.Accent / $c.Gold / $c.Danger work directly.

#region === COLOR PALETTE ===
$c = @{
    ## Surfaces
    BG         = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    TopBar     = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Panel      = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    PanelLight = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    Input      = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    InputBdr   = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    GridBg     = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    GridHdr    = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    GridAlt    = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    StatusBar  = [System.Drawing.Color]::FromArgb(  7,   7,  11)

    ## Text hierarchy
    White      = [System.Drawing.Color]::FromArgb(238, 232, 248)
    TextSec    = [System.Drawing.Color]::FromArgb(188, 180, 208)
    Dim        = [System.Drawing.Color]::FromArgb(128, 120, 150)

    ## Primary accent - PURPLE
    Accent     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    Purple     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    AccentHover= [System.Drawing.Color]::FromArgb(164, 128, 240)

    ## Secondary accent - GOLD
    Gold       = [System.Drawing.Color]::FromArgb(218, 180,  82)
    GoldHover  = [System.Drawing.Color]::FromArgb(238, 200, 110)
    GoldDim    = [System.Drawing.Color]::FromArgb(155, 125,  52)

    ## Status
    Success    = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    Warning    = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger     = [System.Drawing.Color]::FromArgb(224,  80,  90)
    Cyan       = [System.Drawing.Color]::FromArgb( 88, 180, 210)
    Console    = [System.Drawing.Color]::FromArgb( 92, 198, 120)
}
#endregion

#region === FONTS ===
$fn = @{
    Title    = New-Object System.Drawing.Font("Cascadia Mono", 13, [System.Drawing.FontStyle]::Bold)
    Sub      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    Label    = New-Object System.Drawing.Font("Segoe UI", 9)
    LabelB   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    Btn      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    BtnBig   = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    Console  = New-Object System.Drawing.Font("Cascadia Mono", 9)
    Small    = New-Object System.Drawing.Font("Segoe UI", 8)
    SmallB   = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    GrpHdr   = New-Object System.Drawing.Font("Cascadia Mono", 9, [System.Drawing.FontStyle]::Bold)
    Tab      = New-Object System.Drawing.Font("Cascadia Mono", 9, [System.Drawing.FontStyle]::Bold)
}
#endregion

###############################################################################
###                              GLOBALS                                    ###
###############################################################################
$global:Credentials = $null
$global:WSManOpt    = New-PSSessionOption -OperationTimeout 60000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
$global:UprFindings = @()
$global:UprCatalog  = $null
$global:UprDryRun   = $true
$global:UprThreads  = 8
$global:RSPool      = $null

$script:WorkspaceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) "Logs\UnsupportedProductRemediator"
if (-not (Test-Path -LiteralPath $script:WorkspaceRoot)) {
    try { New-Item -Path $script:WorkspaceRoot -ItemType Directory -Force | Out-Null } catch {}
}
$global:AuditLogPath = Join-Path $script:WorkspaceRoot ("session_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:CatalogPath  = Join-Path (Split-Path -Parent $PSScriptRoot) "JanetLocal\UnsupportedProductCatalog.json"

## Resolve pdftotext.exe dynamically. AFNET workstations are imaged with Git
## for Windows under "C:\Program Files\Git\..." but other workstations may have
## it elsewhere or only on PATH. Fall back through a candidate list, then PATH.
## Stays $null when nothing resolves — Parse-PdfFinding logs a clear error.
$script:PdfTextExe = $null
foreach ($candidate in @(
    'C:\Program Files\Git\mingw64\bin\pdftotext.exe',
    'C:\Program Files (x86)\Git\mingw64\bin\pdftotext.exe',
    "$env:LOCALAPPDATA\Programs\Git\mingw64\bin\pdftotext.exe",
    'C:\Tools\pdftotext.exe'
)) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue)) {
        $script:PdfTextExe = $candidate
        break
    }
}
if (-not $script:PdfTextExe) {
    $cmd = Get-Command pdftotext.exe -ErrorAction SilentlyContinue
    if ($cmd) { $script:PdfTextExe = $cmd.Source }
}

###############################################################################
###                       JANET CRED INHERITANCE                            ###
###############################################################################
## When launched from JANET.ps1, $env:JANET_CRED_FILE points to a DPAPI-encrypted
## CliXml. Import + populate $global:Credentials so the operator doesn't have
## to re-enter ADW creds. Falls through silently when launched standalone.

if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $inheritedCred = Import-Clixml -LiteralPath $env:JANET_CRED_FILE -ErrorAction Stop
        if ($inheritedCred -is [System.Management.Automation.PSCredential]) {
            $global:Credentials = $inheritedCred
        }
    } catch { }
}

###############################################################################
###                          HELPER FUNCTIONS                               ###
###############################################################################
#region === HELPERS ===
function New-Btn {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 140, [int]$H = 30,
          [System.Drawing.Color]$Bg = $c.Accent, [System.Drawing.Color]$Fg = $c.White, $Font = $fn.Btn)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text; $btn.Location = New-Object System.Drawing.Point($X, $Y)
    $btn.Size = New-Object System.Drawing.Size($W, $H)
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $Bg; $btn.ForeColor = $Fg; $btn.Font = $Font
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $r2 = [Math]::Min(255, $Bg.R + 25); $g2 = [Math]::Min(255, $Bg.G + 25); $b2 = [Math]::Min(255, $Bg.B + 25)
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($r2, $g2, $b2)
    return $btn
}

function New-Lbl {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 200, [int]$H = 18,
          $Font = $fn.Label, [System.Drawing.Color]$Fg = $c.TextSec)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text; $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size($W, $H); $lbl.ForeColor = $Fg; $lbl.Font = $Font
    $lbl.BackColor = [System.Drawing.Color]::Transparent
    return $lbl
}

function New-Tb {
    param([int]$X, [int]$Y, [int]$W, [int]$H = 24, [switch]$Multi, [switch]$ReadOnly)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point($X, $Y); $tb.Size = New-Object System.Drawing.Size($W, $H)
    $tb.BackColor = $c.Input; $tb.ForeColor = $c.White; $tb.Font = $fn.Label; $tb.BorderStyle = 'FixedSingle'
    if ($Multi) { $tb.Multiline = $true; $tb.ScrollBars = 'Vertical' }
    if ($ReadOnly) { $tb.ReadOnly = $true }
    return $tb
}

function New-Grp {
    param([string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H, [System.Drawing.Color]$Fg = $c.Cyan)
    $gb = New-Object System.Windows.Forms.GroupBox
    $gb.Text = "  $Text  "; $gb.Location = New-Object System.Drawing.Point($X, $Y)
    $gb.Size = New-Object System.Drawing.Size($W, $H); $gb.ForeColor = $Fg
    $gb.BackColor = $c.Panel; $gb.Font = $fn.GrpHdr
    return $gb
}

function New-Cb {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 160, [bool]$Checked = $false)
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $Text; $cb.Location = New-Object System.Drawing.Point($X, $Y)
    $cb.Size = New-Object System.Drawing.Size($W, 22)
    $cb.ForeColor = $c.White; $cb.BackColor = [System.Drawing.Color]::Transparent
    $cb.Font = $fn.Label; $cb.Checked = $Checked
    $cb.FlatStyle = 'Flat'
    return $cb
}

function New-Nud {
    param([int]$X, [int]$Y, [int]$W = 60, [int]$Min = 1, [int]$Max = 32, [int]$Value = 8)
    $nud = New-Object System.Windows.Forms.NumericUpDown
    $nud.Location = New-Object System.Drawing.Point($X, $Y); $nud.Size = New-Object System.Drawing.Size($W, 22)
    $nud.Minimum = $Min; $nud.Maximum = $Max; $nud.Value = $Value
    $nud.BackColor = $c.Input; $nud.ForeColor = $c.White; $nud.Font = $fn.Label
    return $nud
}

function Style-Grid($dgv) {
    $dgv.BackgroundColor = $c.GridBg; $dgv.GridColor = $c.InputBdr
    $dgv.BorderStyle = 'None'; $dgv.CellBorderStyle = 'SingleHorizontal'
    $dgv.EnableHeadersVisualStyles = $false
    $dgv.ColumnHeadersDefaultCellStyle.BackColor = $c.GridHdr
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $c.Gold
    $dgv.ColumnHeadersDefaultCellStyle.Font = $fn.LabelB
    $dgv.ColumnHeadersHeight = 28
    $dgv.DefaultCellStyle.BackColor = $c.GridBg
    $dgv.DefaultCellStyle.ForeColor = $c.White
    $dgv.DefaultCellStyle.SelectionBackColor = $c.Accent
    $dgv.DefaultCellStyle.SelectionForeColor = $c.White
    $dgv.DefaultCellStyle.Font = $fn.Small
    $dgv.AlternatingRowsDefaultCellStyle.BackColor = $c.GridAlt
    $dgv.RowHeadersVisible = $false
    $dgv.AllowUserToAddRows = $false; $dgv.AllowUserToDeleteRows = $false
    $dgv.SelectionMode = 'FullRowSelect'; $dgv.MultiSelect = $true
}

## Host-class filter — operators commonly want to exclude servers from
## bulk remediation. Workstations on this network use the MSEKL (laptop)
## or MSEKW (desktop) NetBIOS prefix; everything else (servers, generic
## VMs, printers, ...) is "Other". The dropdown on Tab 1 mutates
## $script:UprHostClassFilter; every host enumeration in the tool
## (Findings grid HostCount, Uninstall scan, Update dispatch, OS Findings
## grid) routes through Get-UprFilteredHosts so a "Workstations only"
## selection clips servers globally, not just visually.
$script:UprHostClassFilter = 'All'

function Get-UprHostClass {
    param($HostObj)
    if ($null -eq $HostObj) { return 'Other' }
    foreach ($name in @($HostObj.NetBIOSName, $HostObj.DNSName)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $bare = ($name -split '\.')[0]
        if ($bare -match '^(?i:MSEK[LW])') { return 'Workstation' }
    }
    return 'Other'
}

function Get-UprFilteredHosts {
    param($Finding)
    if ($null -eq $Finding -or $null -eq $Finding.Hosts) { return @() }
    switch ($script:UprHostClassFilter) {
        'Workstations (MSEKL/MSEKW)'         { return @($Finding.Hosts | Where-Object { (Get-UprHostClass $_) -eq 'Workstation' }) }
        'Non-Workstations (servers / other)' { return @($Finding.Hosts | Where-Object { (Get-UprHostClass $_) -eq 'Other' }) }
        default                              { return @($Finding.Hosts) }
    }
}

function Get-UprTotalFilteredHosts {
    if ($null -eq $global:UprFindings) { return 0 }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $global:UprFindings) {
        foreach ($h in (Get-UprFilteredHosts $f)) {
            $key = if ($h.NetBIOSName) { $h.NetBIOSName } elseif ($h.DNSName) { $h.DNSName } else { $h.IPAddress }
            if (-not [string]::IsNullOrWhiteSpace($key)) { [void]$set.Add($key) }
        }
    }
    return $set.Count
}

## Animated dot — small (8px) blinking circle. Lifted from
## WorkstationPatchingTool 6.5.14 New-WptPulseIndicator (line ~3531) and
## stripped to the legacy $c palette this tool already uses. Form close
## leaves the timer dangling but the form holds the only reference, so
## GC reclaims it; matches WPT's "no explicit dispose" behaviour.
function New-UprPulse {
    param(
        [int]$X = 0, [int]$Y = 0, [int]$Size = 8,
        [System.Drawing.Color]$Color = $c.Success,
        [int]$Interval = 700
    )
    $p = New-Object System.Windows.Forms.Panel
    $p.Location  = New-Object System.Drawing.Point($X, $Y)
    $p.Size      = New-Object System.Drawing.Size($Size, $Size)
    $p.BackColor = [System.Drawing.Color]::Transparent
    $c1 = $Color
    $c2 = [System.Drawing.Color]::FromArgb(40, $c1.R, $c1.G, $c1.B)
    $p.Tag = @{ Phase = 0; C1 = $c1; C2 = $c2 }
    $p.Add_Paint({
        param($sender, $e)
        $t = $sender.Tag
        $clr = if ($t.Phase -eq 0) { $t.C1 } else { $t.C2 }
        $e.Graphics.SmoothingMode = 'AntiAlias'
        $br = New-Object System.Drawing.SolidBrush $clr
        try { $e.Graphics.FillEllipse($br, 0, 0, ($sender.Width - 1), ($sender.Height - 1)) } finally { $br.Dispose() }
    })
    $tmr = New-Object System.Windows.Forms.Timer
    $tmr.Interval = $Interval
    $tmr.Add_Tick({ $p.Tag.Phase = 1 - $p.Tag.Phase; $p.Invalidate() }.GetNewClosure())
    $tmr.Start()
    $p.Tag.Timer = $tmr
    return $p
}

## Status-strip writer — recomputed on filter change, on report load, on
## scan/update completion. Reading $script:Upr* vars defensively so the
## function is callable before the strip controls are constructed.
function Update-StatusStrip {
    if ($null -ne $script:lblStatusTargets) {
        $script:lblStatusTargets.Text = "TARGETS: $(Get-UprTotalFilteredHosts)"
    }
    if ($null -ne $script:lblStatusFilter) {
        $script:lblStatusFilter.Text = "FILTER: $($script:UprHostClassFilter)"
        $script:lblStatusFilter.ForeColor = if ($script:UprHostClassFilter -eq 'All') { $c.Dim } else { $c.Cyan }
    }
}

function Log {
    param([string]$Msg, [string]$Lvl = 'INFO')
    if ($null -eq $script:rtbLog) { return }
    $ts = (Get-Date).ToString('HH:mm:ss')
    $line = "[$ts] $Msg`r`n"
    try {
        if (-not $script:rtbLog.IsHandleCreated) { $script:rtbLog.CreateControl() }
        $start = $script:rtbLog.TextLength
        $script:rtbLog.AppendText($line)
        $clr = switch ($Lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
        $script:rtbLog.Select($start, $line.Length)
        $script:rtbLog.SelectionColor = $clr
        $script:rtbLog.SelectionLength = 0
        $script:rtbLog.ScrollToCaret()
    } catch {
        try { $script:rtbLog.AppendText($line) } catch {}
    }
}

function Write-AuditLog {
    param([string]$Action, [string]$Target = 'N/A', [string]$Result = '', [string]$Detail = '')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "[$ts] [USER: $env:USERNAME] [ACTION: $Action] [TARGET: $Target] [RESULT: $Result]"
    if ($Detail) { $entry += " [DETAIL: $Detail]" }
    try { $entry | Out-File -FilePath $global:AuditLogPath -Append -Encoding UTF8 } catch {}

    ## Mirror to JANET centralized logging if a session is running.
    if ($null -ne $script:JanetSession -and $Target -and $Target -ne 'N/A') {
        try {
            $isStateChange = ($Action -like '*Uninstall*' -or $Action -like '*Update*' -or $Action -like '*Patch*')
            if ($isStateChange -and $Result -eq 'Success') {
                Write-JanetAction -Action 'VulnPatched' -Target $Target -Result 'Success' -ItemCount 1 -Detail "$Action`: $Detail"
            } elseif ($isStateChange -and $Result -eq 'Failed') {
                Write-JanetAction -Action 'VulnPatched' -Target $Target -Result 'Failure' -ItemCount 0 -Detail "$Action`: $Detail"
            } elseif ($isStateChange -and $Result -eq 'Skipped') {
                Write-JanetAction -Action 'VulnPatched' -Target $Target -Result 'Skipped' -ItemCount 0 -Detail "$Action`: $Detail"
            } else {
                Write-JanetAction -Action 'TouchHost' -Target $Target -Result 'Success' -ItemCount 0 -Detail "$Action`: $Detail"
            }
        } catch {}
    }
}

function Initialize-RunspacePool {
    if ($null -ne $global:RSPool) {
        try { $global:RSPool.Close(); $global:RSPool.Dispose() } catch {}
        $global:RSPool = $null
    }
    $global:RSPool = [RunspaceFactory]::CreateRunspacePool(1, [int]$global:UprThreads)
    $global:RSPool.ApartmentState = 'MTA'; $global:RSPool.Open()
}

function Test-HostReachable {
    param([string]$ComputerName, [int]$TimeoutMs = 3000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($ComputerName, 5985, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) { $tcp.EndConnect($iar); $tcp.Close(); return $true }
        try { $tcp.Close() } catch {}
        return $false
    } catch { return $false }
}
#endregion

###############################################################################
###                          CATALOG LOADER                                 ###
###############################################################################
#region === CATALOG ===
function Load-Catalog {
    if (-not (Test-Path -LiteralPath $script:CatalogPath)) {
        Log "Catalog not found at $script:CatalogPath - using empty catalog" 'WARN'
        $global:UprCatalog = [PSCustomObject]@{ Profiles = @(); OperatingSystemPluginNames = @() }
        return
    }
    try {
        $raw = Get-Content -LiteralPath $script:CatalogPath -Raw -Encoding UTF8
        $global:UprCatalog = $raw | ConvertFrom-Json
        if ($null -eq $global:UprCatalog.Profiles) { $global:UprCatalog | Add-Member -NotePropertyName Profiles -NotePropertyValue @() -Force }
        $global:UprCatalog.Profiles = @($global:UprCatalog.Profiles)
        if ($null -eq $global:UprCatalog.OperatingSystemPluginNames) {
            $global:UprCatalog | Add-Member -NotePropertyName OperatingSystemPluginNames -NotePropertyValue @() -Force
        }
        $global:UprCatalog.OperatingSystemPluginNames = @($global:UprCatalog.OperatingSystemPluginNames)
        Log "Catalog loaded: $($global:UprCatalog.Profiles.Count) profile(s), $($global:UprCatalog.OperatingSystemPluginNames.Count) OS pattern(s)" 'OK'
    } catch {
        Log "Failed to load catalog: $($_.Exception.Message)" 'ERR'
        $global:UprCatalog = [PSCustomObject]@{ Profiles = @(); OperatingSystemPluginNames = @() }
    }
}

function Get-CatalogProfileForFinding {
    param($Finding)
    if ($null -eq $global:UprCatalog -or $null -eq $global:UprCatalog.Profiles) { return $null }
    foreach ($p in $global:UprCatalog.Profiles) {
        $pluginOk = ($p.Plugin -eq '*' -or $p.Plugin -eq $Finding.Plugin)
        if (-not $pluginOk) { continue }
        try {
            if ($Finding.PluginName -match $p.PluginNameMatch) { return $p }
        } catch { continue }
    }
    return $null
}

function Test-IsOsFinding {
    param($PluginName)
    if ($null -eq $global:UprCatalog -or $null -eq $global:UprCatalog.OperatingSystemPluginNames) { return $false }
    foreach ($pat in $global:UprCatalog.OperatingSystemPluginNames) {
        try { if ($PluginName -match $pat) { return $true } } catch {}
    }
    return $false
}

function Get-UprCandidateAction {
    # Proven-only gate (v1.1.0): mirrors the JANET ONE WPT Get-WptUnsupportedAction
    # (JanetOne.wpt.psm1). Returns 'Uninstall' only when the catalog PROVES the
    # install is EOL -- Proven=true (the regex pins an EOL-by-definition product,
    # e.g. Flash / perpetual Office) OR the installed version parses below the
    # profile's VersionMaxExclusive (e.g. MSXML < 5, .NET < 8). Otherwise 'Review':
    # the row is surfaced but never one-click removed, so a supported in-market
    # build (.NET 8, current Firefox/Java) or a DBA-owned server (SQL/Oracle) is
    # never auto-uninstalled without human sign-off. A null profile (no catalog
    # match) is always 'Review'.
    param($Prof, [string]$Version)
    if ($null -eq $Prof) { return 'Review' }
    if ($Prof.Proven -eq $true) { return 'Uninstall' }
    $vmax = [string]$Prof.VersionMaxExclusive
    if (-not [string]::IsNullOrWhiteSpace($vmax)) {
        $vObj = $null; $maxObj = $null
        $clean = ($Version -replace '[^0-9\.]', '').Trim('.')
        if ([version]::TryParse($clean, [ref]$vObj) -and [version]::TryParse($vmax, [ref]$maxObj) -and ($vObj -lt $maxObj)) { return 'Uninstall' }
    }
    return 'Review'
}
#endregion

###############################################################################
###                            INPUT PARSERS                                ###
###############################################################################
#region === PARSERS ===
function Parse-CsvFinding {
    param([string]$Path)
    $rows = $null
    try { $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop } catch {
        Log "CSV import failed: $($_.Exception.Message)" 'ERR'
        return @()
    }
    if ($null -eq $rows -or $rows.Count -eq 0) { return @() }

    ## Required columns: Plugin, Plugin Name, IP Address, NetBIOS Name, DNS Name, Severity.
    ## Optional: Plugin Output (used for exact-match enrichment), MAC Address, OS CPE.
    $cols = @($rows[0].PSObject.Properties.Name)
    $havePluginOutput = ($cols -contains 'Plugin Output')

    $findings = @{}
    foreach ($row in $rows) {
        $pluginName = [string]$row.'Plugin Name'
        if ([string]::IsNullOrWhiteSpace($pluginName)) { continue }

        ## Filter to unsupported / SEoL detection plugins:
        $isUnsupported = ($pluginName -match '(?i)unsupported|SEoL|End[\- ]of[\- ]Life|EOL|out of support')
        if (-not $isUnsupported) {
            ## Also keep anything with a catalog match (some plugin names don't include the keyword)
            $tryMatch = $false
            foreach ($p in $global:UprCatalog.Profiles) {
                if ($pluginName -match $p.PluginNameMatch) { $tryMatch = $true; break }
            }
            if (-not $tryMatch) { continue }
        }

        $key = "$($row.Plugin)|$pluginName"
        if (-not $findings.ContainsKey($key)) {
            $cat = if (Test-IsOsFinding $pluginName) { 'OS' } elseif ($pluginName -match '(?i)SEoL|End[\- ]of[\- ]Life|EOL') { 'SEoLSoftware' } else { 'UnsupportedSoftware' }
            $findings[$key] = [PSCustomObject]@{
                Plugin     = [string]$row.Plugin
                PluginName = $pluginName
                Category   = $cat
                Severity   = [string]$row.Severity
                Hosts      = New-Object System.Collections.ArrayList
            }
        }
        $f = $findings[$key]

        $matched = $null
        $matchedVer = $null
        $matchedPath = $null
        if ($havePluginOutput -and $row.'Plugin Output') {
            $po = [string]$row.'Plugin Output'
            ## Tenable plugins often print:
            ##    Path : C:\Program Files\Foo\bar.exe
            ##    Installed version : 3.5.1
            ##    Product : Microsoft 365 Apps for enterprise
            $mPath  = [regex]::Match($po, '(?im)^\s*(?:Path|Installed location|Install Path)\s*:\s*(.+?)\s*$')
            $mVer   = [regex]::Match($po, '(?im)^\s*(?:Installed version|Version)\s*:\s*(.+?)\s*$')
            $mProd  = [regex]::Match($po, '(?im)^\s*(?:Product|Display Name|Name)\s*:\s*(.+?)\s*$')
            if ($mPath.Success)  { $matchedPath = $mPath.Groups[1].Value.Trim() }
            if ($mVer.Success)   { $matchedVer  = $mVer.Groups[1].Value.Trim() }
            if ($mProd.Success)  { $matched     = $mProd.Groups[1].Value.Trim() }
        }

        $h = [PSCustomObject]@{
            IPAddress          = [string]$row.'IP Address'
            NetBIOSName        = [string]$row.'NetBIOS Name'
            DNSName            = [string]$row.'DNS Name'
            OSCpe              = if ($cols -contains 'OS CPE') { [string]$row.'OS CPE' } else { '' }
            MAC                = if ($cols -contains 'MAC Address') { [string]$row.'MAC Address' } else { '' }
            MatchedDisplayName = $matched
            MatchedVersion     = $matchedVer
            MatchedPath        = $matchedPath
            CVE                = if ($cols -contains 'CVE') { [string]$row.CVE } else { '' }
        }
        [void]$f.Hosts.Add($h)
    }

    $findings.Values
}

function Parse-PdfFinding {
    param([string]$Path)
    if (-not $script:PdfTextExe -or -not (Test-Path -LiteralPath $script:PdfTextExe -ErrorAction SilentlyContinue)) {
        Log "pdftotext.exe not resolved. Install Git for Windows (any standard location), add pdftotext.exe to PATH, or drop it at C:\Tools\pdftotext.exe." 'ERR'
        return @()
    }
    $tmpTxt = [IO.Path]::Combine([IO.Path]::GetTempPath(), "upr_pdf_$([guid]::NewGuid().ToString('N')).txt")
    try {
        ## v1.1.0 fix: pass a single PRE-QUOTED argument string. PS 5.1
        ## Start-Process does NOT quote individual -ArgumentList array elements,
        ## so a report path containing spaces / parentheses (e.g. the browser's
        ## "...Platform (1).pdf") got split into bad args and pdftotext returned
        ## exit 99 (printed usage) with no output -> the Findings grid stayed
        ## empty. Quoting both paths in one string fixes it while keeping
        ## -NoNewWindow (no console flash) and the stderr capture.
        $argLine = '-layout "{0}" "{1}"' -f $Path, $tmpTxt
        $proc = Start-Process -FilePath $script:PdfTextExe -ArgumentList $argLine -Wait -PassThru -NoNewWindow -RedirectStandardError ($tmpTxt + '.err')
        if ($proc.ExitCode -ne 0) {
            Log "pdftotext returned exit $($proc.ExitCode)" 'ERR'
            return @()
        }
    } catch {
        Log "pdftotext invocation failed: $($_.Exception.Message)" 'ERR'
        return @()
    }
    if (-not (Test-Path -LiteralPath $tmpTxt)) { return @() }

    $allText = Get-Content -LiteralPath $tmpTxt -Raw

    ## Stop scanning before non-actionable trailing sections.
    $stopAnchors = @(
        'Top 20 Exploitable Vulnerabilities',
        'Top 20 Exploitable Hosts',
        'Exploitable Framework Breakdown',
        'Exploits by Platform'
    )
    $stopIdx = $allText.Length
    foreach ($s in $stopAnchors) {
        $i = $allText.IndexOf($s)
        if ($i -ge 0 -and $i -lt $stopIdx) { $stopIdx = $i }
    }
    $usefulText = $allText.Substring(0, $stopIdx)

    ## Section anchors: each section has a "...Count" header followed by a
    ## per-plugin table, then a "...Affected Hosts" header followed by the
    ## per-host table. Three sections in this report:
    ##   1. Unsupported / Security End of Life (SEoL) Operating Systems
    ##   2. Unsupported Software
    ##   3. Security End of Life (SEoL) Software
    $sections = @(
        @{ Name='OS';                   CountAnchor='Unsupported / Security End of Life (SEoL) Operating Systems Count'; HostsAnchor='Unsupported / Security End of Life (SEoL) Operating Systems Affected Hosts'; Category='OS' }
        @{ Name='UnsupportedSoftware';  CountAnchor='Unsupported Software Count';                                       HostsAnchor='Unsupported Software Affected Hosts';                                      Category='UnsupportedSoftware' }
        @{ Name='SEoLSoftware';         CountAnchor='Security End of Life (SEoL) Software Count';                       HostsAnchor='Security End of Life (SEoL) Software Affected Hosts';                      Category='SEoLSoftware' }
    )

    $findings = @{}
    foreach ($sec in $sections) {
        $countIdx = $usefulText.IndexOf($sec.CountAnchor)
        if ($countIdx -lt 0) { continue }
        $hostsIdx = $usefulText.IndexOf($sec.HostsAnchor, $countIdx)
        if ($hostsIdx -lt 0) { continue }
        ## Find the start of the next section's count anchor as the end-bound for the hosts table.
        $sectionEnd = $usefulText.Length
        foreach ($s2 in $sections) {
            if ($s2.Name -eq $sec.Name) { continue }
            $j = $usefulText.IndexOf($s2.CountAnchor, $hostsIdx)
            if ($j -ge 0 -and $j -lt $sectionEnd) { $sectionEnd = $j }
        }

        $countBlock = $usefulText.Substring($countIdx, $hostsIdx - $countIdx)
        $hostsBlock = $usefulText.Substring($hostsIdx, $sectionEnd - $hostsIdx)

        ## --- Per-plugin lines in the Count block. ---
        ## Format (after pdftotext -layout strips columns) is genuinely irregular:
        ## sometimes the plugin id, name, severity, and count all share one line;
        ## sometimes the name spans 2-3 lines; sometimes the plugin id is on its
        ## own line; sometimes a wrap word like "Unsupported" lands on the next
        ## line glued in front of a different plugin's id.
        ##
        ## Strategy: walk lines, accumulate a "pending" block of non-terminal
        ## lines, finalize when we hit a line ending in "<Severity> <Count>".
        ## Within the finalized block: extract first 4-7 digit token as the
        ## plugin id, whatever's left after stripping id+sev+count is the name.
        $rxNoise   = '(Plugin\s+Plugin\s+Name|Plugin Output|UNCLASSIFIED|^Lakenheath|SEoL_Product_Summary|Exploits by Platform|^Affected Hosts$|MAC Address\b|^IP Address|^NetBIOS Name|^DNS Name|^OS CPE|^Last Observed|^Steps to Remediate|^Plugin\s*$|^Plugin\s+Name\s*$|^Severity\s*$|^Total\s*$|^Unsupported Software Count$|^Unsupported / Security End of Life \(SEoL\) Operating Systems Count$|^Security End of Life \(SEoL\) Software Count$)'
        $rxSevTail = '\s+(?<sev>Critical|High|Medium|Low|Info)\s+(?<tot>\d+)\s*$'
        $rxIp4     = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

        $pending = New-Object System.Collections.ArrayList
        foreach ($ln in (($countBlock -split "`r?`n"))) {
            $s = $ln.Trim()
            if ($s -eq '' -or $s -match $rxNoise) { continue }
            if ($s -match $rxIp4) { break }   ## host block has leaked in — stop

            $tail = [regex]::Match($s, $rxSevTail)
            if (-not $tail.Success) {
                [void]$pending.Add($s)
                continue
            }

            ## Finalize: pending + this line up to the sev tail = the prelude.
            $sev   = $tail.Groups['sev'].Value
            $head  = $s.Substring(0, $tail.Index).Trim()
            $block = ($pending + @($head)) -join ' '
            $pending.Clear()
            ## Collapse whitespace.
            $block = ($block -replace '\s+', ' ').Trim()
            if ($block -eq '') { continue }

            ## Pluck the first 4-7 digit token as plugin id. Plugin ids that show
            ## up after the product-name word "365" get filtered out by requiring
            ## the digits to NOT immediately follow letters/numbers ("\D"-bounded).
            $plugin = ''
            $idMatch = [regex]::Match($block, '(?<![\w])(\d{4,7})(?![\w])')
            if ($idMatch.Success) { $plugin = $idMatch.Groups[1].Value }
            $name = ($block -replace '(?<![\w])\d{4,7}(?![\w])', ' ').Trim()
            $name = ($name -replace '\s+', ' ').Trim()
            ## Trim a trailing 'Unsupported' if it's a duplicate stray wrap.
            if ($name -match '(?i)Unsupported.*Unsupported$') { $name = $name -replace '\s+Unsupported$','' }
            ## A leading "Unsupported" wrap from previous row.
            $name = ($name -replace '^Unsupported\s+(?=Microsoft|Mozilla|Oracle|VMware|Apache|Adobe|Java|Sun|IBM|Cisco|Tenable|HP\b|Citrix|Symantec|Trend\b|McAfee)', '').Trim()
            if ($name.Length -lt 6) { continue }

            $key = "$plugin|$name"
            if (-not $findings.ContainsKey($key)) {
                $cat = $sec.Category
                if (Test-IsOsFinding $name) { $cat = 'OS' }
                $findings[$key] = [PSCustomObject]@{
                    Plugin       = $plugin
                    PluginName   = $name
                    Category     = $cat
                    SourceSection= $sec.Name
                    Severity     = $sev
                    Hosts        = New-Object System.Collections.ArrayList
                }
            }
        }

        ## --- Per-host rows in the Affected Hosts block. ---
        ## We treat any IP-shaped token as a host anchor and collect the
        ## following line fragments until the next IP or the end of the block.
        ## Hosts are added under the section's findings collectively (the PDF
        ## doesn't break out which host belongs to which plugin within the
        ## section), so we record them on every finding in this section.
        $rxIp = '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        $hostRows = New-Object System.Collections.ArrayList
        $currentHost = $null
        foreach ($ln in (($hostsBlock -split "`r?`n"))) {
            $line = $ln.TrimEnd()
            if ($line -match '^\s*$' -or $line -match 'UNCLASSIFIED|IP Address\s+NetBIOS|Plugin Name|Affected Hosts') { continue }
            if ($line -match $rxIp) {
                $ip = $Matches[1]
                if ($null -ne $currentHost) { [void]$hostRows.Add($currentHost) }
                $currentHost = [PSCustomObject]@{
                    IPAddress = $ip; NetBIOSName=''; DNSName=''; OSCpe=''; MAC=''
                    MatchedDisplayName=$null; MatchedVersion=$null; MatchedPath=$null; CVE=''
                }
                ## Try to pull the rest of the line as additional fields.
                $rest = $line.Substring($line.IndexOf($ip) + $ip.Length).Trim()
                if ($rest) {
                    if ($rest -match '\\(\S+)')                    { $currentHost.NetBIOSName = $Matches[1] }
                    if ($rest -match '([\w\-]+\.[\w\.\-]+\.\w+)')  { $currentHost.DNSName     = $Matches[1] }
                    if ($rest -match 'cpe:\S+')                    { $currentHost.OSCpe       = $Matches[0] }
                    if ($rest -match '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})') { $currentHost.MAC = $Matches[1] }
                }
            } elseif ($null -ne $currentHost) {
                if ($line -match '\\(\S+)' -and -not $currentHost.NetBIOSName)             { $currentHost.NetBIOSName = $Matches[1] }
                if ($line -match '([\w\-]+\.[\w\.\-]+\.\w+)' -and -not $currentHost.DNSName) { $currentHost.DNSName     = $Matches[1] }
                if ($line -match 'cpe:\S+' -and -not $currentHost.OSCpe)                   { $currentHost.OSCpe       = $Matches[0] }
                if ($line -match '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})' -and -not $currentHost.MAC) { $currentHost.MAC = $Matches[1] }
            }
        }
        if ($null -ne $currentHost) { [void]$hostRows.Add($currentHost) }

        ## Fan out the host list across every finding in this section. PDF
        ## mode loses the per-finding host attribution, but all findings in a
        ## section share the same affected-host pool; the operator picks the
        ## finding to remediate and the registry scan filters per host.
        $sectionFindings = @($findings.Values | Where-Object { $_.SourceSection -eq $sec.Name })
        foreach ($f in $sectionFindings) {
            foreach ($h in $hostRows) {
                ## Clone so per-finding mutation (e.g. MatchedDisplayName) doesn't bleed.
                $clone = $h | Select-Object *
                [void]$f.Hosts.Add($clone)
            }
        }
    }

    try { Remove-Item -LiteralPath $tmpTxt -Force -EA SilentlyContinue } catch {}
    $findings.Values
}

function Import-UprFinding {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Log "Input file does not exist: $Path" 'ERR'
        return @()
    }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        '.csv' { return @(Parse-CsvFinding -Path $Path) }
        '.pdf' { return @(Parse-PdfFinding -Path $Path) }
        default {
            Log "Unsupported input extension: $ext (use .csv or .pdf)" 'ERR'
            return @()
        }
    }
}
#endregion

###############################################################################
###                   BULK UNINSTALL & UPDATE SCRIPTBLOCKS                  ###
###############################################################################
## The per-host uninstall scriptblock is lifted (with adaptations) from
## WorkstationPatchingTool 6.5.12 lines ~6195-6494. Same handlers for M365 SaRA
## copy-and-run, Adobe Acrobat GUID-based MSI w/ RunAsPPL guard, generic MSI/
## EXE/Store. Tanium installations are explicitly skipped.

#region === SCRIPTBLOCKS ===
$global:UprUninstallBlock = {
    param($TargetHost, $Cred, $WSManOpt, $DisplayNameRegex, $VersionMaxExclusive, $DryRun)

    $r = @{
        Host = $TargetHost
        Reachable = $false
        Candidates = @()
        Actions = @()
        OverallResult = 'Unknown'
    }

    ## --- Reachability precheck (TCP 5985, 3s) ---
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($TargetHost, 5985, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne(3000, $false)
        if ($ok -and $tcp.Connected) { $tcp.EndConnect($iar); $tcp.Close(); $r.Reachable = $true }
        else { try { $tcp.Close() } catch {} }
    } catch { }

    if (-not $r.Reachable) {
        $r.OverallResult = 'Unreachable'
        return $r
    }

    ## --- Registry scan + match ---
    $candidates = @()
    try {
        $candidates = Invoke-Command -ComputerName $TargetHost -Credential $Cred -Authentication Negotiate -SessionOption $WSManOpt -EA Stop -ArgumentList $DisplayNameRegex, $VersionMaxExclusive -ScriptBlock {
            param($rx, $verMax)
            $apps = @()
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            foreach ($rp in $regPaths) {
                Get-ItemProperty $rp -EA SilentlyContinue | Where-Object {
                    $_.DisplayName -and $_.DisplayName.Trim() -ne '' -and $_.DisplayName -match $rx
                } | ForEach-Object {
                    $verOk = $true
                    if ($verMax) {
                        try {
                            $cur = [Version]( ($_.DisplayVersion -split '[^\d\.]' | Where-Object { $_ -match '^\d' } | Select-Object -First 1) )
                            $max = [Version]$verMax
                            if ($cur -ge $max) { $verOk = $false }
                        } catch { $verOk = $true }
                    }
                    if ($verOk) {
                        $type = if ($_.UninstallString -match 'msiexec') { 'MSI' } else { 'EXE' }
                        $apps += @{
                            Name            = $_.DisplayName
                            Version         = $_.DisplayVersion
                            Publisher       = $_.Publisher
                            Type            = $type
                            UninstallString = $_.UninstallString
                            QuietUninstall  = $_.QuietUninstallString
                            PSChildName     = $_.PSChildName
                        }
                    }
                }
            }
            return $apps
        }
    } catch {
        $r.OverallResult = "FAIL: scan -- $($_.Exception.Message)"
        return $r
    }

    if ($null -eq $candidates -or $candidates.Count -eq 0) {
        $r.OverallResult = 'NoCandidate'
        return $r
    }

    ## Tanium safety: never uninstall via this tool.
    $taniumHits = @($candidates | Where-Object { $_.Name -like '*Tanium*' })
    if ($taniumHits.Count -gt 0) {
        $r.Candidates = $candidates
        $r.OverallResult = 'Skipped (Tanium)'
        return $r
    }

    $r.Candidates = $candidates

    if ($DryRun) {
        $r.OverallResult = 'Skipped (DryRun)'
        foreach ($app in $candidates) {
            $r.Actions += @{ Name = $app.Name; Result = 'Skipped (DryRun)' }
        }
        return $r
    }

    ## --- Uninstall each matched candidate ---
    $success = 0; $failed = 0
    foreach ($app in $candidates) {
        $appResult = $null
        try {
            $appResult = Invoke-Command -ComputerName $TargetHost -Credential $Cred -Authentication Negotiate -SessionOption $WSManOpt -EA Stop -ArgumentList $app.Name, $app.Type, $app.UninstallString, $app.QuietUninstall, $app.PSChildName -ScriptBlock {
                param($name, $type, $unStr, $quietStr, $childName)
                try {
                    ## === Microsoft 365 handler ===
                    if ($name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                        $steps = @(); $c2rPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
                        $localCmd = "C:\Temp\Uninstall-M365.cmd"
                        if (Test-Path $localCmd -EA SilentlyContinue) {
                            $proc = Start-Process cmd.exe -ArgumentList "/c `"$localCmd`"" -Wait -PassThru -NoNewWindow
                            Get-ChildItem "C:\Temp\Uninstall-*.cmd" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
                            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (M365 package script exit $($proc.ExitCode))" }
                            $steps += "Package script non-zero exit -- trying built-in"
                        }
                        $setupExe = Join-Path $c2rPath "setup.exe"
                        if (Test-Path $setupExe) {
                            New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                            $xmlPath = "C:\Temp\OfficeRemoveAll.xml"
                            '<Configuration><Remove All="TRUE"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' | Out-File $xmlPath -Encoding ASCII -Force
                            $proc = Start-Process $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -PassThru -NoNewWindow
                            Remove-Item $xmlPath -Force -EA SilentlyContinue
                            if ($proc.ExitCode -eq 0) { return "OK (Office removed via setup.exe /configure)" }
                            $steps += "setup.exe /configure exit $($proc.ExitCode)"
                        }
                        if (-not [string]::IsNullOrWhiteSpace($unStr)) {
                            $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr`"" -Wait -PassThru -NoNewWindow
                            if ($proc.ExitCode -eq 0) { return "OK (Office removed via uninstall string)" }
                            $steps += "Uninstall string exit $($proc.ExitCode)"
                        }
                        return "FAIL (Office -- all methods attempted: $($steps -join ' | '))"
                    }
                    ## === Adobe Acrobat handler with RunAsPPL guard ===
                    if ($name -match 'Adobe Acrobat') {
                        $steps = @(); $removed = $false; $pplRestoreNeeded = $false; $pplOriginalValue = $null
                        $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        try {
                            try {
                                $pplVal = Get-ItemProperty $lsaKey -Name "RunAsPPL" -EA SilentlyContinue
                                if ($null -ne $pplVal -and $null -ne $pplVal.RunAsPPL) {
                                    $pplOriginalValue = $pplVal.RunAsPPL
                                    Remove-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Force -EA Stop
                                    $pplRestoreNeeded = $true
                                    $steps += "RunAsPPL removed (was: $pplOriginalValue)"
                                }
                            } catch {}
                            try {
                                $adobeSvcs = @('AdobeARMservice','AdobeUpdateService','AGSService')
                                foreach ($svc in $adobeSvcs) { $s = Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Stop-Service $svc -Force -EA SilentlyContinue } }
                                $adobeProcs = @('Acrobat','AcroCEF','AcroRd32','AdobeARM','AdobeCollabSync','armsvc')
                                foreach ($p in $adobeProcs) { Get-Process $p -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }
                            } catch {}
                            $adobeGuids = @()
                            $regPaths2 = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
                            foreach ($rp in $regPaths2) {
                                Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Adobe Acrobat' } | ForEach-Object {
                                    if ($_.UninstallString -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }
                                    if ($_.PSChildName -match '^\{') { $adobeGuids += $_.PSChildName }
                                }
                            }
                            $adobeGuids = @($adobeGuids | Select-Object -Unique)
                            foreach ($guid in $adobeGuids) {
                                $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { $removed = $true }
                            }
                        } finally {
                            if ($pplRestoreNeeded) {
                                try { New-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value $pplOriginalValue -PropertyType DWord -Force -EA Stop | Out-Null }
                                catch { $steps += "WARNING: RunAsPPL restore FAILED" }
                            }
                        }
                        if ($removed) { return "OK (Adobe removed via MSI -- $($adobeGuids.Count) GUID(s))" }
                        return "FAIL (Adobe -- $($steps -join ' | '))"
                    }
                    ## === Generic handlers ===
                    if ($type -eq 'Store') {
                        Get-AppxPackage -AllUsers -Name "*$name*" -EA SilentlyContinue | Remove-AppxPackage -AllUsers -EA Stop
                        return "OK (Store app removed)"
                    } elseif ($type -eq 'MSI') {
                        $guid = $unStr -replace '.*(\{[^\}]+\}).*', '$1'
                        if ($guid -match '^\{') {
                            $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (MSI exit $($proc.ExitCode))" }
                            else { return "WARN (MSI exit $($proc.ExitCode))" }
                        } else { return "FAIL: Could not extract MSI GUID" }
                    } else {
                        if (-not [string]::IsNullOrWhiteSpace($quietStr)) {
                            $proc = Start-Process cmd.exe -ArgumentList "/c `"$quietStr`"" -Wait -PassThru -NoNewWindow
                            return "OK (QuietUninstall exit $($proc.ExitCode))"
                        } elseif (-not [string]::IsNullOrWhiteSpace($unStr)) {
                            $exePath = ($unStr -split '/|--')[0].Trim('"').Trim()
                            if (Test-Path $exePath) {
                                $proc = Start-Process $exePath -ArgumentList "/S /silent /quiet /uninstall /norestart" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                return "OK (EXE exit $($proc.ExitCode))"
                            } else {
                                $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr /S /quiet /norestart`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                return "OK (CMD exit $($proc.ExitCode))"
                            }
                        } else { return "FAIL: No uninstall string available" }
                    }
                } catch { return "FAIL: $($_.Exception.Message)" }
            }
        } catch { $appResult = "FAIL: $($_.Exception.Message)" }

        $r.Actions += @{ Name = $app.Name; Result = $appResult }
        if ($appResult -like 'OK*') { $success++ } else { $failed++ }
    }

    if ($failed -eq 0) { $r.OverallResult = "OK ($success/$($candidates.Count))" }
    elseif ($success -eq 0) { $r.OverallResult = "FAIL (0/$($candidates.Count))" }
    else { $r.OverallResult = "PARTIAL ($success/$($candidates.Count))" }

    return $r
}

## v1.1.0: $global:UprUpdateBlock (updater delegation worker) removed -
## uninstall-only. Update-class remediation is handled by the WPT App Updater.
#endregion

###############################################################################
###                              MAIN FORM                                  ###
###############################################################################
$f = New-Object System.Windows.Forms.Form
$f.Text             = "J.A.N.E.T. - Unsupported Product Remediator v$JanetUnsupportedProductRemediatorVersion"
$f.Size             = New-Object System.Drawing.Size(1340, 800)
$f.MinimumSize      = New-Object System.Drawing.Size(1320, 720)
$f.StartPosition    = 'CenterScreen'
$f.BackColor        = $c.BG
$f.ForeColor        = $c.White
$f.Font             = $fn.Label
$f.FormBorderStyle  = 'Sizable'

## Crispness + theme parity with the rest of the JANET suite: kill flicker on
## resize and flip the title bar dark (the closing-notes dialog already does
## this). DPI awareness itself is set at script load in Set-UprDpiAware.
try { Enable-UprDoubleBuffer -Control $f } catch {}
$f.Add_HandleCreated({ try { Set-UprDarkTitleBar -Form $f } catch {} })

###############################################################################
###                            TOP TOOLBAR                                  ###
###############################################################################
#region === TOP TOOLBAR ===
$pnlTop = New-Object System.Windows.Forms.Panel
$pnlTop.Location = New-Object System.Drawing.Point(0, 0)
$pnlTop.Size     = New-Object System.Drawing.Size($f.ClientSize.Width, 56)
$pnlTop.Anchor   = 'Top,Left,Right'
$pnlTop.BackColor= $c.TopBar
$f.Controls.Add($pnlTop)

$lblTitle = New-Lbl -Text "Unsupported Product Remediator" -X 12 -Y 4 -W 360 -H 20 -Font $fn.Title -Fg $c.Gold
$lblSub   = New-Lbl -Text "PDF/CSV in - bulk uninstall of unsupported / SEoL software on the affected hosts" -X 14 -Y 28 -W 620 -H 18 -Font $fn.Sub -Fg $c.Dim
$pnlTop.Controls.AddRange(@($lblTitle, $lblSub))

## Close Tool — top-right corner of the top toolbar (matches WPT
## pattern). Single sanctioned form egress: sets the X-block allow
## flag, then closes; FormClosing guard cancels every other origin.
$btnHdrCloseTool = New-Btn -Text "Close Tool" -X ($f.ClientSize.Width - 120) -Y 4 -W 110 -H 24 -Bg $c.Danger
$btnHdrCloseTool.Anchor = 'Top,Right'
$btnHdrCloseTool.Add_Click({ Set-JanetAllowClose $true; $f.Close() }.GetNewClosure())
$pnlTop.Controls.Add($btnHdrCloseTool)

$lblFile  = New-Lbl -Text "Report:" -X 580 -Y 16 -W 50 -Font $fn.LabelB -Fg $c.TextSec
$btnLoad  = New-Btn -Text "Load PDF / CSV" -X 632 -Y 12 -W 130 -H 28 -Bg $c.Accent
$lblDryHdr = New-Lbl -Text "Dry-run:" -X 776 -Y 16 -W 56 -Font $fn.LabelB -Fg $c.TextSec
$cbDry    = New-Cb  -Text "Plan-only" -X 832 -Y 17 -W 90 -Checked $true
$ttTop    = New-Object System.Windows.Forms.ToolTip
$ttTop.SetToolTip($cbDry, "Plan-only (dry-run): the planned action is logged but no state change is made -- no uninstalls run.")

## Right cluster -- right-anchored, X computed from the LIVE client width so
## "Reload Catalog" never collides with / hides behind "Close Tool". (Bug fixed:
## the prior fixed X=1166,W=105 ran to x=1271, past the ~1264 client edge of the
## 1280 form AND over the right-anchored Close Tool at x=ClientWidth-120.) Order
## from the right edge: [Threads: NN] [Reload Catalog] [Close Tool].
$cw       = $f.ClientSize.Width
$lblConc  = New-Lbl -Text "Threads:" -X ($cw - 366) -Y 16 -W 58 -Font $fn.LabelB -Fg $c.TextSec
$nudConc  = New-Nud -X ($cw - 306) -Y 14 -W 54 -Min 1 -Max 32 -Value 8
$btnReload= New-Btn -Text "Reload Catalog" -X ($cw - 244) -Y 12 -W 112 -H 28 -Bg $c.GoldDim -Fg $c.White
$btnReload.Anchor = 'Top,Right'
$lblConc.Anchor   = 'Top,Right'
$nudConc.Anchor   = 'Top,Right'
$pnlTop.Controls.AddRange(@($lblFile, $btnLoad, $lblDryHdr, $cbDry, $lblConc, $nudConc, $btnReload))

$cbDry.Add_CheckedChanged({ $global:UprDryRun = [bool]$cbDry.Checked; Log "Dry-run = $($global:UprDryRun)" 'INFO' })
$nudConc.Add_ValueChanged({ $global:UprThreads = [int]$nudConc.Value })

## Top-strip live pulse — sits in the subtitle row, right edge. Mirrors
## the heartbeat on WPT 6.5.14's top strip (line ~5797-5805) so the
## sibling tools share a "running session" tell.
$pulseTop = New-UprPulse -X ($f.ClientSize.Width - 92) -Y 33 -Size 8 -Color $c.Success -Interval 1000
$pulseTop.Anchor = 'Top,Right'
$lblTopLive = New-Lbl -Text "live" -X ($f.ClientSize.Width - 78) -Y 29 -W 40 -H 16 -Font $fn.Small -Fg $c.Cyan
$lblTopLive.Anchor = 'Top,Right'
$pnlTop.Controls.AddRange(@($pulseTop, $lblTopLive))
#endregion

###############################################################################
###                             TAB CONTROL                                 ###
###############################################################################
## TabControl with the NATIVE STRIP HIDDEN (ItemSize 0,1) -- same approach as
## WPT 6.5.22 and STIG_Tool 1.3.5. A visible owner-drawn FlatButtons strip
## leaves the empty area right of the last tab painted in the light Windows
## theme colour (the "white toolbar" the operator saw), which DPI-awareness
## made starkly visible; there is no clean way to dark-paint that native area.
## Owner-drawn tab text also rendered soft (the "blurry tabs"). Instead the
## strip is hidden and a custom dark nav-button row ($pnlNav, built just below
## the page set) drives $tc.SelectedIndex -- crisp button text, fully themed.
$tc = New-Object System.Windows.Forms.TabControl
$tc.Location  = New-Object System.Drawing.Point(0, 88)
$tc.Size      = New-Object System.Drawing.Size($f.ClientSize.Width, ($f.ClientSize.Height - 120))
$tc.Anchor    = 'Top,Left,Right,Bottom'
$tc.Appearance= [System.Windows.Forms.TabAppearance]::FlatButtons
$tc.SizeMode  = [System.Windows.Forms.TabSizeMode]::Fixed
$tc.ItemSize  = New-Object System.Drawing.Size(0, 1)
$tc.BackColor = $c.BG
$tc.ForeColor = $c.White
$tc.Font      = $fn.Tab
$f.Controls.Add($tc)

$tabImport     = New-Object System.Windows.Forms.TabPage; $tabImport.Text     = "  Import & Findings  "; $tabImport.BackColor     = $c.BG
$tabUninstall  = New-Object System.Windows.Forms.TabPage; $tabUninstall.Text  = "  Uninstall  ";        $tabUninstall.BackColor  = $c.BG
$tabOs         = New-Object System.Windows.Forms.TabPage; $tabOs.Text         = "  OS Findings  ";      $tabOs.BackColor         = $c.BG
$tabHistory    = New-Object System.Windows.Forms.TabPage; $tabHistory.Text    = "  History  ";          $tabHistory.BackColor    = $c.BG

## v1.1.0: Update tab removed (uninstall-only). Tab order: Import / Uninstall / OS / History.
$tc.TabPages.AddRange(@($tabImport, $tabUninstall, $tabOs, $tabHistory))

###############################################################################
###                       CUSTOM DARK TAB NAV ROW                           ###
###############################################################################
## Horizontal flat-button nav replacing the hidden native tab strip (see the
## TabControl note above). Mirrors the WPT/STIG "hide strip, custom nav drives
## SelectedTab" pattern, laid out horizontally to keep UPR's top-tab feel.
$pnlNav = New-Object System.Windows.Forms.Panel
$pnlNav.Location  = New-Object System.Drawing.Point(0, 56)
$pnlNav.Size      = New-Object System.Drawing.Size($f.ClientSize.Width, 32)
$pnlNav.Anchor    = 'Top,Left,Right'
$pnlNav.BackColor = $c.BG
$f.Controls.Add($pnlNav)

$btnNavImport = New-Btn -Text "Import & Findings" -X 12  -Y 2 -W 178 -H 28 -Bg $c.Panel -Fg $c.TextSec -Font $fn.Tab
$btnNavUninst = New-Btn -Text "Uninstall"         -X 192 -Y 2 -W 178 -H 28 -Bg $c.Panel -Fg $c.TextSec -Font $fn.Tab
$btnNavOs     = New-Btn -Text "OS Findings"       -X 372 -Y 2 -W 178 -H 28 -Bg $c.Panel -Fg $c.TextSec -Font $fn.Tab
$btnNavHist   = New-Btn -Text "History"           -X 552 -Y 2 -W 178 -H 28 -Bg $c.Panel -Fg $c.TextSec -Font $fn.Tab
$pnlNav.Controls.AddRange(@($btnNavImport, $btnNavUninst, $btnNavOs, $btnNavHist))

## Active-tab styling + switching. The hidden native strip means these buttons
## are the only tab affordance; each click sets $tc.SelectedIndex and repaints
## the row so the active tab reads accent/white and the rest panel/dim.
$script:UprNavBtns = @($btnNavImport, $btnNavUninst, $btnNavOs, $btnNavHist)
function Set-UprActiveTab {
    param([int]$Index)
    if ($Index -lt 0 -or $Index -ge $tc.TabPages.Count) { return }
    $tc.SelectedIndex = $Index
    for ($i = 0; $i -lt $script:UprNavBtns.Count; $i++) {
        if ($i -eq $Index) { $script:UprNavBtns[$i].BackColor = $c.Accent; $script:UprNavBtns[$i].ForeColor = $c.White }
        else               { $script:UprNavBtns[$i].BackColor = $c.Panel;  $script:UprNavBtns[$i].ForeColor = $c.TextSec }
    }
}
$btnNavImport.Add_Click({ Set-UprActiveTab 0 })
$btnNavUninst.Add_Click({ Set-UprActiveTab 1 })
$btnNavOs.Add_Click(    { Set-UprActiveTab 2 })
$btnNavHist.Add_Click(  { Set-UprActiveTab 3 })
Set-UprActiveTab 0

###############################################################################
###                         TAB 1 - IMPORT & FINDINGS                       ###
###############################################################################
#region === TAB 1: IMPORT & FINDINGS ===
$lblF1Hdr = New-Lbl -Text "FINDINGS" -X 12 -Y 8 -W 200 -H 18 -Font $fn.GrpHdr -Fg $c.Gold
$lblF1Sub = New-Lbl -Text "Click a row, then switch to Uninstall / Update / OS Findings." -X 12 -Y 28 -W 720 -H 18 -Font $fn.Sub -Fg $c.Dim
$tabImport.Controls.AddRange(@($lblF1Hdr, $lblF1Sub))

## Filter strip — quick host-class filter + free-text search. Mirrors WPT
## Software Manager's filter row (line ~6412 in WorkstationPatchingTool
## 6.5.14): same panel BG, "Quick:" / "Search:" label pattern, count
## label on the right. The dropdown drives $script:UprHostClassFilter
## globally so Uninstall / Update / OS tabs all clip to the same set.
$pnlFilter = New-Object System.Windows.Forms.Panel
$pnlFilter.Location  = New-Object System.Drawing.Point(12, 50)
$pnlFilter.Size      = New-Object System.Drawing.Size(($tabImport.ClientSize.Width - 24), 36)
$pnlFilter.Anchor    = 'Top,Left,Right'
$pnlFilter.BackColor = [System.Drawing.Color]::FromArgb(16, 16, 30)
$tabImport.Controls.Add($pnlFilter)

$lblHostsHdr = New-Lbl -Text "Hosts:" -X 8 -Y 9 -W 44 -Font $fn.LabelB -Fg $c.Gold
$script:ddlHosts = New-Object System.Windows.Forms.ComboBox
$script:ddlHosts.Location      = New-Object System.Drawing.Point(54, 6)
$script:ddlHosts.Size          = New-Object System.Drawing.Size(280, 24)
$script:ddlHosts.BackColor     = $c.Input
$script:ddlHosts.ForeColor     = $c.White
$script:ddlHosts.DropDownStyle = 'DropDownList'
$script:ddlHosts.Font          = $fn.Label
[void]$script:ddlHosts.Items.AddRange(@(
    'All',
    'Workstations (MSEKL/MSEKW)',
    'Non-Workstations (servers / other)'
))
$script:ddlHosts.SelectedIndex = 0

$lblSearchHdr = New-Lbl -Text "Search:" -X 348 -Y 9 -W 52 -Font $fn.LabelB -Fg $c.TextSec
$script:txtSearch = New-Tb -X 402 -Y 6 -W 240 -H 24
$script:txtSearch.Font = $fn.Console

$script:lblFCount = New-Lbl -Text "" -X 660 -Y 9 -W 540 -H 18 -Font $fn.SmallB -Fg $c.Cyan

$pnlFilter.Controls.AddRange(@($lblHostsHdr, $script:ddlHosts, $lblSearchHdr, $script:txtSearch, $script:lblFCount))

$dgvFindings = New-Object System.Windows.Forms.DataGridView
$dgvFindings.Location = New-Object System.Drawing.Point(12, 92)
$dgvFindings.Size     = New-Object System.Drawing.Size(($tabImport.ClientSize.Width - 24), ($tabImport.ClientSize.Height - 122))
$dgvFindings.Anchor   = 'Top,Left,Right,Bottom'
Style-Grid $dgvFindings
$dgvFindings.AutoSizeColumnsMode = 'Fill'
[void]$dgvFindings.Columns.Add('Plugin', 'Plugin')
[void]$dgvFindings.Columns.Add('Category', 'Category')
[void]$dgvFindings.Columns.Add('PluginName', 'Plugin Name')
[void]$dgvFindings.Columns.Add('Severity', 'Severity')
[void]$dgvFindings.Columns.Add('HostCount', 'Host Count')
[void]$dgvFindings.Columns.Add('Profile', 'Catalog Match')
$dgvFindings.Columns['Plugin'].FillWeight     = 6
$dgvFindings.Columns['Category'].FillWeight   = 12
$dgvFindings.Columns['PluginName'].FillWeight = 50
$dgvFindings.Columns['Severity'].FillWeight   = 8
$dgvFindings.Columns['HostCount'].FillWeight  = 7
$dgvFindings.Columns['Profile'].FillWeight    = 17
$dgvFindings.SelectionMode = 'FullRowSelect'
$dgvFindings.MultiSelect   = $false
$tabImport.Controls.Add($dgvFindings)

function Refresh-FindingsGrid {
    $dgvFindings.Rows.Clear()
    if ($null -eq $global:UprFindings -or $global:UprFindings.Count -eq 0) {
        if ($null -ne $script:lblFCount) { $script:lblFCount.Text = "0 finding(s)" }
        Update-StatusStrip
        return
    }
    $textFilter = if ($null -ne $script:txtSearch) { $script:txtSearch.Text.Trim() } else { '' }
    $hostFilter = $script:UprHostClassFilter
    $sorted = @($global:UprFindings) | Sort-Object @{e='Category'}, @{e='Severity'; descending=$true}, @{e='PluginName'}
    $shown = 0
    foreach ($f in $sorted) {
        $hostsFiltered = Get-UprFilteredHosts $f
        ## When a host-class filter is active, hide findings whose entire
        ## affected-host set fell outside the filter — keeps the operator's
        ## attention on rows they can actually act on.
        if ($hostFilter -ne 'All' -and $hostsFiltered.Count -eq 0) { continue }
        if (-not [string]::IsNullOrWhiteSpace($textFilter)) {
            $hay = "$($f.Plugin) $($f.PluginName) $($f.Category)"
            if ($hay -notlike "*$textFilter*") { continue }
        }
        $prof = Get-CatalogProfileForFinding $f
        ## v1.1.0 uninstall-only: hide update-class findings (catalog Updater set,
        ## e.g. M365 channel mismatch). OS findings are exempt - they show on the
        ## OS Findings tab. Remediate update-class exposures with the WPT App Updater.
        if ($f.Category -ne 'OS' -and $null -ne $prof -and -not [string]::IsNullOrWhiteSpace([string]$prof.Updater)) { continue }
        $profText = if ($f.Category -eq 'OS') { 'N/A (OS)' } elseif ($null -ne $prof) { 'OK (uninstall-only)' } else { 'No match' }
        $idx = $dgvFindings.Rows.Add(@($f.Plugin, $f.Category, $f.PluginName, $f.Severity, $hostsFiltered.Count, $profText))
        $row = $dgvFindings.Rows[$idx]
        $row.Tag = $f
        $sevClr = switch ($f.Severity) {
            'Critical' { $c.Danger }
            'High'     { $c.Warning }
            'Medium'   { $c.Cyan }
            'Low'      { $c.Dim }
            default    { $c.TextSec }
        }
        $row.Cells['Severity'].Style.ForeColor = $sevClr
        if ($f.Category -eq 'OS') {
            $row.Cells['Category'].Style.ForeColor = $c.Warning
        } elseif ($f.Category -eq 'SEoLSoftware') {
            $row.Cells['Category'].Style.ForeColor = $c.Danger
        } else {
            $row.Cells['Category'].Style.ForeColor = $c.Accent
        }
        $row.Cells['Profile'].Style.ForeColor = if ($profText -like 'OK*') { $c.Success } elseif ($profText -like 'N/A*') { $c.Dim } else { $c.Warning }
        $shown++
    }
    if ($null -ne $script:lblFCount) {
        $bits = @("Showing $shown of $($global:UprFindings.Count) finding(s)")
        if ($hostFilter -ne 'All') { $bits += "hosts: $hostFilter" }
        if (-not [string]::IsNullOrWhiteSpace($textFilter)) { $bits += "search: '$textFilter'" }
        $script:lblFCount.Text = ($bits -join '  |  ')
    }
    Update-StatusStrip
}

$btnLoad.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Tenable report (*.csv;*.pdf)|*.csv;*.pdf|All files|*.*"
    $ofd.Title  = "Select Tenable Unsupported / SEoL report"
    if ($ofd.ShowDialog() -ne 'OK') { return }
    Log "Loading $($ofd.FileName)..." 'INFO'
    [System.Windows.Forms.Application]::DoEvents()
    $list = @(Import-UprFinding -Path $ofd.FileName)
    if ($list.Count -eq 0) { Log "No findings parsed from $($ofd.FileName)" 'WARN'; return }
    $global:UprFindings = $list
    Log "Parsed $($list.Count) finding(s) from $([IO.Path]::GetFileName($ofd.FileName))" 'OK'
    Write-AuditLog -Action "ReportImport" -Target "N/A" -Result "Success" -Detail "Findings=$($list.Count) Source=$([IO.Path]::GetFileName($ofd.FileName))"
    Refresh-FindingsGrid
    Refresh-OsTab
})

$dgvFindings.Add_SelectionChanged({
    if ($dgvFindings.SelectedRows.Count -eq 0) { return }
    $f = $dgvFindings.SelectedRows[0].Tag
    if ($null -eq $f) { return }
    Refresh-UninstallTab $f
})

$btnReload.Add_Click({ Load-Catalog; Refresh-FindingsGrid })

$script:ddlHosts.Add_SelectedIndexChanged({
    $script:UprHostClassFilter = [string]$script:ddlHosts.SelectedItem
    Log "Host filter -> $($script:UprHostClassFilter)" 'INFO'
    Refresh-FindingsGrid
    Refresh-OsTab
    if ($null -ne $script:UprUninstallFinding) { Refresh-UninstallTab $script:UprUninstallFinding }
})
$script:txtSearch.Add_TextChanged({ Refresh-FindingsGrid })
#endregion

###############################################################################
###                          TAB 2 - UNINSTALL                              ###
###############################################################################
#region === TAB 2: UNINSTALL ===
$lblU1Hdr  = New-Lbl -Text "BULK UNINSTALL" -X 12 -Y 8 -W 220 -H 18 -Font $fn.GrpHdr -Fg $c.Gold
$lblU1Sub  = New-Lbl -Text "Pick a finding on the Findings tab. Then Scan, review candidates, Uninstall." -X 12 -Y 28 -W 820 -H 18 -Font $fn.Sub -Fg $c.Dim
$lblU1Sel  = New-Lbl -Text "" -X 12 -Y 50 -W 820 -H 20 -Font $fn.LabelB -Fg $c.TextSec
$btnUScan  = New-Btn -Text "Scan Hosts" -X 12 -Y 76 -W 130 -H 28 -Bg $c.Accent
$btnUDoIt  = New-Btn -Text "Uninstall Selected" -X 148 -Y 76 -W 160 -H 28 -Bg $c.Danger
$btnUExp   = New-Btn -Text "Export Results" -X 314 -Y 76 -W 130 -H 28 -Bg $c.GoldDim
$btnUDoIt.Enabled = $false; $btnUExp.Enabled = $false
$tabUninstall.Controls.AddRange(@($lblU1Hdr, $lblU1Sub, $lblU1Sel, $btnUScan, $btnUDoIt, $btnUExp))

$dgvU = New-Object System.Windows.Forms.DataGridView
$dgvU.Location = New-Object System.Drawing.Point(12, 110)
$dgvU.Size     = New-Object System.Drawing.Size(($tabUninstall.ClientSize.Width - 24), ($tabUninstall.ClientSize.Height - 240))
$dgvU.Anchor   = 'Top,Left,Right,Bottom'
Style-Grid $dgvU
$dgvU.AutoSizeColumnsMode = 'Fill'
$colSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colSel.Name = 'Sel'; $colSel.HeaderText = ''
[void]$dgvU.Columns.Add($colSel)
[void]$dgvU.Columns.Add('Host',     'Host')
[void]$dgvU.Columns.Add('Display',  'Display Name')
[void]$dgvU.Columns.Add('Version',  'Version')
[void]$dgvU.Columns.Add('Type',     'Type')
[void]$dgvU.Columns.Add('Pub',      'Publisher')
[void]$dgvU.Columns.Add('Result',   'Result')
$dgvU.Columns['Sel'].FillWeight     = 4
$dgvU.Columns['Host'].FillWeight    = 18
$dgvU.Columns['Display'].FillWeight = 28
$dgvU.Columns['Version'].FillWeight = 9
$dgvU.Columns['Type'].FillWeight    = 6
$dgvU.Columns['Pub'].FillWeight     = 14
$dgvU.Columns['Result'].FillWeight  = 21
$dgvU.SelectionMode = 'FullRowSelect'
$tabUninstall.Controls.Add($dgvU)

$lblULogHdr = New-Lbl -Text "ACTIVITY" -X 12 -Y ($tabUninstall.ClientSize.Height - 124) -W 200 -Font $fn.GrpHdr -Fg $c.Gold
$lblULogHdr.Anchor = 'Bottom,Left'
$rtbU = New-Object System.Windows.Forms.RichTextBox
$rtbU.Location = New-Object System.Drawing.Point(12, ($tabUninstall.ClientSize.Height - 104))
$rtbU.Size     = New-Object System.Drawing.Size(($tabUninstall.ClientSize.Width - 24), 96)
$rtbU.Anchor   = 'Bottom,Left,Right'
$rtbU.BackColor= $c.Panel; $rtbU.ForeColor=$c.Console; $rtbU.Font = $fn.Console
$rtbU.ReadOnly = $true; $rtbU.BorderStyle='FixedSingle'
$tabUninstall.Controls.AddRange(@($lblULogHdr, $rtbU))
$script:rtbLog = $rtbU

$script:UprUninstallFinding = $null
$script:UprUninstallScans   = @()

function Refresh-UninstallTab {
    param($Finding)
    $script:UprUninstallFinding = $Finding
    $dgvU.Rows.Clear()
    $script:UprUninstallScans = @()
    $btnUDoIt.Enabled = $false; $btnUExp.Enabled = $false
    if ($null -eq $Finding) { $lblU1Sel.Text = ""; return }
    if ($Finding.Category -eq 'OS') {
        $lblU1Sel.Text = "OS finding selected. See OS Findings tab; uninstall not applicable."
        $lblU1Sel.ForeColor = $c.Warning
        return
    }
    $prof = Get-CatalogProfileForFinding $Finding
    $profStr = if ($null -ne $prof) { $prof.DisplayNameRegex + (if ($prof.VersionMaxExclusive) { "  (version < $($prof.VersionMaxExclusive))" } else { '' }) } else { '(no catalog match - scan will list every install on each host)' }
    $hostsFiltered = Get-UprFilteredHosts $Finding
    $hostStr = if ($script:UprHostClassFilter -eq 'All') {
        "$($hostsFiltered.Count) host(s)"
    } else {
        "$($hostsFiltered.Count) of $($Finding.Hosts.Count) host(s) [filter: $($script:UprHostClassFilter)]"
    }
    $lblU1Sel.Text = "[$($Finding.Plugin)] $($Finding.PluginName)  -  $hostStr  -  Match: $profStr"
    $lblU1Sel.ForeColor = if ($prof) { $c.Success } else { $c.Warning }
}

# A connect-target token is usable only if it's an IPv4 literal or a hostname/FQDN
# whose FIRST label is a plausible machine name -- NOT a bare domain fragment. The
# Tenable PDF's jagged affected-host table wraps "DOMAIN\HOST" + FQDNs across lines,
# so it can yield domain-only strings ("S.USAF.MIL", "AREA52.AFNOAPPS.USAF.MIL") or
# a truncated NetBIOS ("MSEKL-"). Reject those so the scan never WinRMs a non-host.
function Test-UprValidTarget {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $t = $Target.Trim()
    if ($t -match '[\\/\s]') { return $false }
    if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { return $true }
    $first = ($t -split '\.')[0]
    if ($first.Length -lt 2) { return $false }
    if ($first -match '(^-|-$)') { return $false }
    if ($first -match '^(?i:USAF|MIL|COM|NET|ORG|GOV|EDU|AF|ELX|AFNOAPP|AFNOAPPS|AREA\d+|LAKENHEATH|UNKNOWN)$') { return $false }
    return $true
}

# First VALID of DNS > NetBIOS > IP (validation-gated so a garbage DNS fragment from
# the jagged PDF falls through to a clean NetBIOS short name or the IP).
function Get-FindingTargetFromHost {
    param($HostObj)
    foreach ($cand in @($HostObj.DNSName, $HostObj.NetBIOSName, $HostObj.IPAddress)) {
        if ([string]::IsNullOrWhiteSpace($cand)) { continue }
        $t = ([string]$cand).Trim()
        if (Test-UprValidTarget $t) { return $t }
    }
    return $null
}

$btnUScan.Add_Click({
    $finding = $script:UprUninstallFinding
    if ($null -eq $finding) { [System.Windows.Forms.MessageBox]::Show("Pick a finding on the Findings tab first.", "No Finding") | Out-Null; return }
    if ($finding.Category -eq 'OS') { return }
    if (-not $global:Credentials) {
        $cred = Get-Credential -Message "Enter ADW admin credentials"
        if (-not $cred) { return }
        $global:Credentials = $cred
    }
    $prof = Get-CatalogProfileForFinding $finding
    $regex = if ($null -ne $prof) { $prof.DisplayNameRegex } else { '.*' }
    $verMax = if ($null -ne $prof) { $prof.VersionMaxExclusive } else { $null }

    $hostsToScan = Get-UprFilteredHosts $finding
    Log "==== SCAN: [$($finding.Plugin)] $($finding.PluginName) ====" 'INFO'
    Log "Regex: $regex  |  VersionMax: $verMax  |  Hosts: $($hostsToScan.Count) (filter: $($script:UprHostClassFilter))" 'INFO'
    if ($hostsToScan.Count -eq 0) {
        Log "No hosts match the active filter. Adjust the Hosts dropdown on the Findings tab." 'WARN'
        $btnUScan.Enabled = $true
        return
    }
    $btnUScan.Enabled = $false; $btnUDoIt.Enabled = $false; $btnUExp.Enabled = $false
    $dgvU.Rows.Clear()
    $script:UprUninstallScans = @()

    Initialize-RunspacePool
    $jobs = @()
    foreach ($hostObj in $hostsToScan) {
        $tgt = Get-FindingTargetFromHost $hostObj
        if (-not $tgt) { continue }

        ## CSV-mode shortcut: when MatchedDisplayName is populated, we can skip
        ## the registry scan and go straight to the uninstall step. For now we
        ## still scan to verify the install survived since the last Tenable run.
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $global:RSPool
        [void]$ps.AddScript({
            param($TargetHost, $Cred, $WSManOpt, $DisplayNameRegex, $VersionMaxExclusive)
            $r = @{ Host=$TargetHost; Reachable=$false; Candidates=@(); Error=$null }
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($TargetHost, 5985, $null, $null)
                $ok  = $iar.AsyncWaitHandle.WaitOne(3000, $false)
                if ($ok -and $tcp.Connected) { $tcp.EndConnect($iar); $tcp.Close(); $r.Reachable=$true }
                else { try { $tcp.Close() } catch {} }
            } catch {}
            if (-not $r.Reachable) { return $r }
            try {
                $r.Candidates = Invoke-Command -ComputerName $TargetHost -Credential $Cred -Authentication Negotiate -SessionOption $WSManOpt -EA Stop -ArgumentList $DisplayNameRegex, $VersionMaxExclusive -ScriptBlock {
                    param($rx, $verMax)
                    $apps = @()
                    $regPaths = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    )
                    foreach ($rp in $regPaths) {
                        Get-ItemProperty $rp -EA SilentlyContinue | Where-Object {
                            $_.DisplayName -and $_.DisplayName.Trim() -ne '' -and $_.DisplayName -match $rx
                        } | ForEach-Object {
                            $verOk = $true
                            if ($verMax) {
                                try {
                                    $cur = [Version]( ($_.DisplayVersion -split '[^\d\.]' | Where-Object { $_ -match '^\d' } | Select-Object -First 1) )
                                    $max = [Version]$verMax
                                    if ($cur -ge $max) { $verOk = $false }
                                } catch { $verOk = $true }
                            }
                            if ($verOk) {
                                $type = if ($_.UninstallString -match 'msiexec') { 'MSI' } else { 'EXE' }
                                $apps += @{
                                    Name=$_.DisplayName; Version=$_.DisplayVersion; Publisher=$_.Publisher
                                    Type=$type; UninstallString=$_.UninstallString
                                    QuietUninstall=$_.QuietUninstallString; PSChildName=$_.PSChildName
                                }
                            }
                        }
                    }
                    return $apps
                }
            } catch { $r.Error = $_.Exception.Message }
            return $r
        }).AddArgument($tgt).AddArgument($global:Credentials).AddArgument($global:WSManOpt).AddArgument($regex).AddArgument($verMax) | Out-Null
        $jobs += @{ PS=$ps; Handle=$ps.BeginInvoke(); Host=$tgt }
    }

    Log "Dispatched $($jobs.Count) scan job(s) (concurrency $($global:UprThreads))..." 'INFO'

    $totalCandidates = 0
    $provenCount = 0
    $reviewCount = 0
    $unreachable = 0
    foreach ($j in $jobs) {
        try {
            $r = $j.PS.EndInvoke($j.Handle)
            $j.PS.Dispose()
            if ($r -is [System.Collections.IList] -and $r.Count -eq 1) { $r = $r[0] }
            if (-not $r.Reachable) {
                $unreachable++
                $idx = $dgvU.Rows.Add(@($false, $j.Host, '(unreachable)', '', '', '', 'Unreachable'))
                $dgvU.Rows[$idx].Cells['Result'].Style.ForeColor = $c.Warning
                $dgvU.Rows[$idx].DefaultCellStyle.ForeColor = $c.Dim
                continue
            }
            if ($r.Error) {
                $idx = $dgvU.Rows.Add(@($false, $j.Host, '(scan error)', '', '', '', $r.Error))
                $dgvU.Rows[$idx].Cells['Result'].Style.ForeColor = $c.Danger
                continue
            }
            $cands = @($r.Candidates)
            if ($cands.Count -eq 0) {
                $idx = $dgvU.Rows.Add(@($false, $j.Host, '(no matching install)', '', '', '', 'NoCandidate'))
                $dgvU.Rows[$idx].Cells['Result'].Style.ForeColor = $c.Dim
                continue
            }
            foreach ($app in $cands) {
                $isTanium = ($app.Name -like '*Tanium*')
                ## Proven-only gate (v1.1.0): only catalog-proven EOL installs are
                ## one-click checkable. Unproven family matches (.NET 8, current
                ## Firefox/Java, SQL/Oracle) are listed as disabled "Review" rows --
                ## surfaced for the operator, never auto-removed without sign-off.
                $action    = Get-UprCandidateAction $prof $app.Version
                $isProven  = ($action -eq 'Uninstall')
                $checkable = ($isProven -and -not $isTanium)
                $idx = $dgvU.Rows.Add(@($checkable, $j.Host, $app.Name, $app.Version, $app.Type, $app.Publisher, ''))
                $row = $dgvU.Rows[$idx]
                $row.Tag = @{ Host = $j.Host; App = $app }
                if ($isTanium) {
                    $row.Cells['Sel'].Value = $false
                    $row.Cells['Sel'].ReadOnly = $true
                    $row.Cells['Result'].Value = 'Skipped (Tanium)'
                    $row.Cells['Result'].Style.ForeColor = $c.Warning
                    $row.DefaultCellStyle.ForeColor = $c.Dim
                } elseif (-not $isProven) {
                    $row.Cells['Sel'].Value = $false
                    $row.Cells['Sel'].ReadOnly = $true
                    $row.Cells['Result'].Value = 'Review (needs version/ACAS proof)'
                    $row.Cells['Result'].Style.ForeColor = $c.Cyan
                    $reviewCount++
                } else {
                    $provenCount++
                }
                $totalCandidates++
            }
        } catch {
            Log "Scan job for $($j.Host) errored: $($_.Exception.Message)" 'ERR'
        }
    }
    Log "Scan complete: $totalCandidates candidate(s) -- $provenCount one-click (proven EOL), $reviewCount review-only; $unreachable unreachable host(s)" 'OK'
    if ($provenCount -eq 0 -and $reviewCount -gt 0) { Log "No proven-EOL candidates. Review rows need version/ACAS confirmation before uninstall." 'WARN' }
    if ($totalCandidates -gt 0) { $btnUDoIt.Enabled = $true; $btnUExp.Enabled = $true }
    $btnUScan.Enabled = $true
    Write-AuditLog -Action "BulkScan" -Target "N/A" -Result "Success" -Detail "Plugin=$($finding.Plugin) Hosts=$($jobs.Count) Candidates=$totalCandidates Unreachable=$unreachable"
})

$btnUDoIt.Add_Click({
    $finding = $script:UprUninstallFinding
    if ($null -eq $finding) { return }
    $rowsToDo = @()
    foreach ($row in $dgvU.Rows) {
        if ($row.IsNewRow) { continue }
        if ($row.Cells['Sel'].Value -eq $true -and $null -ne $row.Tag) {
            $rowsToDo += $row
        }
    }
    if ($rowsToDo.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No candidates checked.", "Nothing to uninstall") | Out-Null; return }
    $hostList = (@($rowsToDo | ForEach-Object { $_.Tag.Host }) | Select-Object -Unique)
    $msg = "Uninstall $($rowsToDo.Count) item(s) across $($hostList.Count) host(s)?`r`n`r`nDry-run: $($global:UprDryRun)`r`nThis cannot be undone."
    $confirm = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm Uninstall", 'YesNo', 'Warning')
    if ($confirm -ne 'Yes') { return }

    Log "==== UNINSTALL: $($rowsToDo.Count) item(s) across $($hostList.Count) host(s) (DryRun=$($global:UprDryRun)) ====" 'INFO'
    $btnUDoIt.Enabled = $false; $btnUScan.Enabled = $false
    Initialize-RunspacePool
    $jobs = @()
    foreach ($row in $rowsToDo) {
        $row.Cells['Result'].Value = 'Uninstalling...'
        $row.Cells['Result'].Style.ForeColor = $c.Warning
        $tag = $row.Tag
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $global:RSPool
        [void]$ps.AddScript({
            param($TargetHost, $Cred, $WSManOpt, $App, $DryRun)
            $out = @{ Host=$TargetHost; AppName=$App.Name; Result='Unknown' }
            if ($DryRun) { $out.Result = 'Skipped (DryRun)'; return $out }
            try {
                $out.Result = Invoke-Command -ComputerName $TargetHost -Credential $Cred -Authentication Negotiate -SessionOption $WSManOpt -EA Stop -ArgumentList $App.Name, $App.Type, $App.UninstallString, $App.QuietUninstall, $App.PSChildName -ScriptBlock {
                    param($name, $type, $unStr, $quietStr, $childName)
                    try {
                        if ($name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                            $c2rPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
                            $localCmd = "C:\Temp\Uninstall-M365.cmd"
                            if (Test-Path $localCmd -EA SilentlyContinue) {
                                $proc = Start-Process cmd.exe -ArgumentList "/c `"$localCmd`"" -Wait -PassThru -NoNewWindow
                                Get-ChildItem "C:\Temp\Uninstall-*.cmd" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
                                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (M365 package script exit $($proc.ExitCode))" }
                            }
                            $setupExe = Join-Path $c2rPath "setup.exe"
                            if (Test-Path $setupExe) {
                                New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                                $xmlPath = "C:\Temp\OfficeRemoveAll.xml"
                                '<Configuration><Remove All="TRUE"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' | Out-File $xmlPath -Encoding ASCII -Force
                                $proc = Start-Process $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -PassThru -NoNewWindow
                                Remove-Item $xmlPath -Force -EA SilentlyContinue
                                if ($proc.ExitCode -eq 0) { return "OK (Office removed via setup.exe /configure)" }
                            }
                            if (-not [string]::IsNullOrWhiteSpace($unStr)) {
                                $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr`"" -Wait -PassThru -NoNewWindow
                                if ($proc.ExitCode -eq 0) { return "OK (Office removed via uninstall string)" }
                            }
                            return "FAIL (Office -- all methods attempted)"
                        }
                        if ($name -match 'Adobe Acrobat') {
                            $removed = $false; $pplRestoreNeeded = $false; $pplOriginalValue = $null
                            $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                            try {
                                try {
                                    $pplVal = Get-ItemProperty $lsaKey -Name "RunAsPPL" -EA SilentlyContinue
                                    if ($null -ne $pplVal -and $null -ne $pplVal.RunAsPPL) {
                                        $pplOriginalValue = $pplVal.RunAsPPL
                                        Remove-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Force -EA Stop
                                        $pplRestoreNeeded = $true
                                    }
                                } catch {}
                                try {
                                    foreach ($svc in @('AdobeARMservice','AdobeUpdateService','AGSService')) { $s = Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Stop-Service $svc -Force -EA SilentlyContinue } }
                                    foreach ($p in @('Acrobat','AcroCEF','AcroRd32','AdobeARM','AdobeCollabSync','armsvc')) { Get-Process $p -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }
                                } catch {}
                                $adobeGuids = @()
                                $regPaths2 = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
                                foreach ($rp in $regPaths2) {
                                    Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Adobe Acrobat' } | ForEach-Object {
                                        if ($_.UninstallString -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }
                                        if ($_.PSChildName -match '^\{') { $adobeGuids += $_.PSChildName }
                                    }
                                }
                                $adobeGuids = @($adobeGuids | Select-Object -Unique)
                                foreach ($guid in $adobeGuids) {
                                    $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                                    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { $removed = $true }
                                }
                            } finally {
                                if ($pplRestoreNeeded) { try { New-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value $pplOriginalValue -PropertyType DWord -Force -EA Stop | Out-Null } catch {} }
                            }
                            if ($removed) { return "OK (Adobe removed via MSI -- $($adobeGuids.Count) GUID(s))" }
                            return "FAIL (Adobe)"
                        }
                        if ($type -eq 'Store') {
                            Get-AppxPackage -AllUsers -Name "*$name*" -EA SilentlyContinue | Remove-AppxPackage -AllUsers -EA Stop
                            return "OK (Store app removed)"
                        } elseif ($type -eq 'MSI') {
                            $guid = $unStr -replace '.*(\{[^\}]+\}).*', '$1'
                            if ($guid -match '^\{') {
                                $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (MSI exit $($proc.ExitCode))" }
                                else { return "WARN (MSI exit $($proc.ExitCode))" }
                            } else { return "FAIL: Could not extract MSI GUID" }
                        } else {
                            if (-not [string]::IsNullOrWhiteSpace($quietStr)) {
                                $proc = Start-Process cmd.exe -ArgumentList "/c `"$quietStr`"" -Wait -PassThru -NoNewWindow
                                return "OK (QuietUninstall exit $($proc.ExitCode))"
                            } elseif (-not [string]::IsNullOrWhiteSpace($unStr)) {
                                $exePath = ($unStr -split '/|--')[0].Trim('"').Trim()
                                if (Test-Path $exePath) {
                                    $proc = Start-Process $exePath -ArgumentList "/S /silent /quiet /uninstall /norestart" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                    return "OK (EXE exit $($proc.ExitCode))"
                                } else {
                                    $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr /S /quiet /norestart`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                    return "OK (CMD exit $($proc.ExitCode))"
                                }
                            } else { return "FAIL: No uninstall string available" }
                        }
                    } catch { return "FAIL: $($_.Exception.Message)" }
                }
            } catch { $out.Result = "FAIL: $($_.Exception.Message)" }
            return $out
        }).AddArgument($tag.Host).AddArgument($global:Credentials).AddArgument($global:WSManOpt).AddArgument($tag.App).AddArgument([bool]$global:UprDryRun) | Out-Null
        $jobs += @{ PS=$ps; Handle=$ps.BeginInvoke(); Row=$row; Tag=$tag }
    }

    $okCount = 0; $failCount = 0; $skipCount = 0
    foreach ($j in $jobs) {
        try {
            $out = $j.PS.EndInvoke($j.Handle)
            $j.PS.Dispose()
            if ($out -is [System.Collections.IList] -and $out.Count -eq 1) { $out = $out[0] }
            $resStr = [string]$out.Result
            $j.Row.Cells['Result'].Value = $resStr
            if ($resStr -like 'OK*') {
                $j.Row.Cells['Result'].Style.ForeColor = $c.Success; $okCount++
                Write-AuditLog -Action "UnsupportedProductUninstall" -Target "$($j.Tag.Host)\$($j.Tag.App.Name)" -Result "Success" -Detail $resStr
            } elseif ($resStr -like 'Skipped*') {
                $j.Row.Cells['Result'].Style.ForeColor = $c.Dim; $skipCount++
                Write-AuditLog -Action "UnsupportedProductUninstall" -Target "$($j.Tag.Host)\$($j.Tag.App.Name)" -Result "Skipped" -Detail $resStr
            } else {
                $j.Row.Cells['Result'].Style.ForeColor = $c.Danger; $failCount++
                Write-AuditLog -Action "UnsupportedProductUninstall" -Target "$($j.Tag.Host)\$($j.Tag.App.Name)" -Result "Failed" -Detail $resStr
            }
            Add-HistoryRow -When (Get-Date) -Host $j.Tag.Host -Action 'Uninstall' -Item $j.Tag.App.Name -Result $resStr
        } catch {
            $j.Row.Cells['Result'].Value = "FAIL (job): $($_.Exception.Message)"
            $j.Row.Cells['Result'].Style.ForeColor = $c.Danger; $failCount++
        }
    }
    Log "==== DONE: $okCount succeeded, $failCount failed, $skipCount skipped ====" 'OK'
    $btnUDoIt.Enabled = $true; $btnUScan.Enabled = $true
})

$btnUExp.Add_Click({
    if ($dgvU.Rows.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "CSV|*.csv"
    $sfd.FileName = "UnsupportedProductUninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    $rows = @()
    foreach ($row in $dgvU.Rows) {
        if ($row.IsNewRow) { continue }
        $rows += [PSCustomObject]@{
            Host        = [string]$row.Cells['Host'].Value
            DisplayName = [string]$row.Cells['Display'].Value
            Version     = [string]$row.Cells['Version'].Value
            Type        = [string]$row.Cells['Type'].Value
            Publisher   = [string]$row.Cells['Pub'].Value
            Result      = [string]$row.Cells['Result'].Value
        }
    }
    $rows | Export-Csv -LiteralPath $sfd.FileName -NoTypeInformation -Encoding UTF8
    Log "Exported $($rows.Count) row(s) to $([IO.Path]::GetFileName($sfd.FileName))" 'OK'
})
#endregion

## v1.1.0: TAB 3 (Update) removed - this tool is uninstall-only. Update-class
## findings (catalog Updater set) are hidden on the Findings tab; remediate
## those with the WPT App Updater.

###############################################################################
###                          TAB 4 - OS FINDINGS                            ###
###############################################################################
#region === TAB 4: OS FINDINGS ===
$lblOsHdr = New-Lbl -Text "UNSUPPORTED OPERATING SYSTEMS  (read-only)" -X 12 -Y 8 -W 540 -Font $fn.GrpHdr -Fg $c.Gold
$lblOsSub = New-Lbl -Text "Out of scope for this tool. Hand the export to whoever runs OS rebuilds." -X 12 -Y 28 -W 800 -Font $fn.Sub -Fg $c.Dim
$btnOsExp = New-Btn -Text "Export CSV" -X 12 -Y 50 -W 130 -H 28 -Bg $c.GoldDim
$btnOsCpy = New-Btn -Text "Copy to Clipboard" -X 148 -Y 50 -W 150 -H 28 -Bg $c.Accent
$tabOs.Controls.AddRange(@($lblOsHdr, $lblOsSub, $btnOsExp, $btnOsCpy))

$dgvOs = New-Object System.Windows.Forms.DataGridView
$dgvOs.Location = New-Object System.Drawing.Point(12, 86)
$dgvOs.Size     = New-Object System.Drawing.Size(($tabOs.ClientSize.Width - 24), ($tabOs.ClientSize.Height - 100))
$dgvOs.Anchor   = 'Top,Left,Right,Bottom'
Style-Grid $dgvOs
$dgvOs.AutoSizeColumnsMode = 'Fill'
[void]$dgvOs.Columns.Add('Plugin', 'Plugin')
[void]$dgvOs.Columns.Add('PluginName', 'Finding')
[void]$dgvOs.Columns.Add('Severity', 'Severity')
[void]$dgvOs.Columns.Add('IP',     'IP')
[void]$dgvOs.Columns.Add('NetBIOS','NetBIOS')
[void]$dgvOs.Columns.Add('DNS',    'DNS')
[void]$dgvOs.Columns.Add('OSCpe',  'OS CPE')
[void]$dgvOs.Columns.Add('MAC',    'MAC')
$dgvOs.Columns['Plugin'].FillWeight     = 6
$dgvOs.Columns['PluginName'].FillWeight = 22
$dgvOs.Columns['Severity'].FillWeight   = 8
$dgvOs.Columns['IP'].FillWeight         = 10
$dgvOs.Columns['NetBIOS'].FillWeight    = 14
$dgvOs.Columns['DNS'].FillWeight        = 16
$dgvOs.Columns['OSCpe'].FillWeight      = 16
$dgvOs.Columns['MAC'].FillWeight        = 8
$tabOs.Controls.Add($dgvOs)

function Refresh-OsTab {
    $dgvOs.Rows.Clear()
    if ($null -eq $global:UprFindings) { return }
    foreach ($f in @($global:UprFindings | Where-Object { $_.Category -eq 'OS' })) {
        foreach ($h in (Get-UprFilteredHosts $f)) {
            $idx = $dgvOs.Rows.Add(@($f.Plugin, $f.PluginName, $f.Severity, $h.IPAddress, $h.NetBIOSName, $h.DNSName, $h.OSCpe, $h.MAC))
            $row = $dgvOs.Rows[$idx]
            $sevClr = switch ($f.Severity) { 'Critical' { $c.Danger }; 'High' { $c.Warning }; default { $c.TextSec } }
            $row.Cells['Severity'].Style.ForeColor = $sevClr
        }
    }
}

$btnOsExp.Add_Click({
    if ($dgvOs.Rows.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "CSV|*.csv"
    $sfd.FileName = "OS_Findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    $rows = @()
    foreach ($row in $dgvOs.Rows) {
        if ($row.IsNewRow) { continue }
        $rows += [PSCustomObject]@{
            Plugin     = [string]$row.Cells['Plugin'].Value
            PluginName = [string]$row.Cells['PluginName'].Value
            Severity   = [string]$row.Cells['Severity'].Value
            IPAddress  = [string]$row.Cells['IP'].Value
            NetBIOS    = [string]$row.Cells['NetBIOS'].Value
            DNS        = [string]$row.Cells['DNS'].Value
            OSCpe      = [string]$row.Cells['OSCpe'].Value
            MAC        = [string]$row.Cells['MAC'].Value
        }
    }
    $rows | Export-Csv -LiteralPath $sfd.FileName -NoTypeInformation -Encoding UTF8
    Write-AuditLog -Action "OsFindingsExport" -Target "N/A" -Result "Success" -Detail "$($rows.Count) row(s) -> $([IO.Path]::GetFileName($sfd.FileName))"
})

$btnOsCpy.Add_Click({
    if ($dgvOs.Rows.Count -eq 0) { return }
    $lines = @("Plugin`tFinding`tSeverity`tIP`tNetBIOS`tDNS`tOSCpe`tMAC")
    foreach ($row in $dgvOs.Rows) {
        if ($row.IsNewRow) { continue }
        $cells = @(
            [string]$row.Cells['Plugin'].Value, [string]$row.Cells['PluginName'].Value,
            [string]$row.Cells['Severity'].Value, [string]$row.Cells['IP'].Value,
            [string]$row.Cells['NetBIOS'].Value, [string]$row.Cells['DNS'].Value,
            [string]$row.Cells['OSCpe'].Value, [string]$row.Cells['MAC'].Value
        )
        $lines += ($cells -join "`t")
    }
    [System.Windows.Forms.Clipboard]::SetText(($lines -join "`r`n"))
})
#endregion

###############################################################################
###                            TAB 5 - HISTORY                              ###
###############################################################################
#region === TAB 5: HISTORY ===
$lblHHdr = New-Lbl -Text "SESSION HISTORY (last 200)" -X 12 -Y 8 -W 360 -Font $fn.GrpHdr -Fg $c.Gold
$lblHSub = New-Lbl -Text "Audit log: $($global:AuditLogPath)" -X 12 -Y 28 -W 1000 -Font $fn.Sub -Fg $c.Dim
$btnHClr = New-Btn -Text "Clear Grid" -X 12 -Y 50 -W 110 -H 28 -Bg $c.GoldDim
$btnHExp = New-Btn -Text "Export CSV" -X 128 -Y 50 -W 110 -H 28 -Bg $c.Accent
$tabHistory.Controls.AddRange(@($lblHHdr, $lblHSub, $btnHClr, $btnHExp))

$dgvH = New-Object System.Windows.Forms.DataGridView
$dgvH.Location = New-Object System.Drawing.Point(12, 86)
$dgvH.Size     = New-Object System.Drawing.Size(($tabHistory.ClientSize.Width - 24), ($tabHistory.ClientSize.Height - 100))
$dgvH.Anchor   = 'Top,Left,Right,Bottom'
Style-Grid $dgvH
$dgvH.AutoSizeColumnsMode = 'Fill'
[void]$dgvH.Columns.Add('When',    'When')
[void]$dgvH.Columns.Add('Host',    'Host')
[void]$dgvH.Columns.Add('Action',  'Action')
[void]$dgvH.Columns.Add('Item',    'Item')
[void]$dgvH.Columns.Add('Result',  'Result')
$dgvH.Columns['When'].FillWeight   = 12
$dgvH.Columns['Host'].FillWeight   = 18
$dgvH.Columns['Action'].FillWeight = 8
$dgvH.Columns['Item'].FillWeight   = 32
$dgvH.Columns['Result'].FillWeight = 30
$tabHistory.Controls.Add($dgvH)

$global:UprHistoryMax = 200

function Add-HistoryRow {
    param($When, $Host, $Action, $Item, $Result)
    if ($null -eq $dgvH) { return }
    $idx = $dgvH.Rows.Add(@(
        ($When.ToString('yyyy-MM-dd HH:mm:ss')),
        $Host, $Action, $Item, $Result
    ))
    $row = $dgvH.Rows[$idx]
    $clr = if ([string]$Result -like 'OK*') { $c.Success } elseif ([string]$Result -like 'Skipped*') { $c.Dim } else { $c.Danger }
    $row.Cells['Result'].Style.ForeColor = $clr
    while ($dgvH.Rows.Count -gt $global:UprHistoryMax) { $dgvH.Rows.RemoveAt(0) }
}

$btnHClr.Add_Click({ $dgvH.Rows.Clear() })
$btnHExp.Add_Click({
    if ($dgvH.Rows.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = "CSV|*.csv"
    $sfd.FileName = "UPR_History_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    $rows = @()
    foreach ($row in $dgvH.Rows) {
        if ($row.IsNewRow) { continue }
        $rows += [PSCustomObject]@{
            When   = [string]$row.Cells['When'].Value
            Host   = [string]$row.Cells['Host'].Value
            Action = [string]$row.Cells['Action'].Value
            Item   = [string]$row.Cells['Item'].Value
            Result = [string]$row.Cells['Result'].Value
        }
    }
    $rows | Export-Csv -LiteralPath $sfd.FileName -NoTypeInformation -Encoding UTF8
})
#endregion

###############################################################################
###                              STATUS BAR                                 ###
###############################################################################
#region === STATUS BAR ===
## WPT 6.5.14-style status strip (mirrors WorkstationPatchingTool line
## ~5832): 32px dark panel, 8px green pulse on the left, monospaced
## SESSION / TARGETS / FILTER labels, audit log path right-anchored.
## Close Tool button lives on the top toolbar.
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Location  = New-Object System.Drawing.Point(0, ($f.ClientSize.Height - 32))
$pnlStatus.Size      = New-Object System.Drawing.Size($f.ClientSize.Width, 32)
$pnlStatus.Anchor    = 'Bottom,Left,Right'
$pnlStatus.BackColor = $c.StatusBar
$f.Controls.Add($pnlStatus)

$pulseStatus = New-UprPulse -X 10 -Y 12 -Size 8 -Color $c.Success
$pnlStatus.Controls.Add($pulseStatus)

$script:lblStatusSession = New-Lbl -Text ("  SESSION: $env:USERNAME@$env:COMPUTERNAME") -X 22 -Y 8 -W 300 -H 18 -Font $fn.Console -Fg $c.TextSec
$script:lblStatusTargets = New-Lbl -Text "TARGETS: 0"  -X 326 -Y 8 -W 160 -H 18 -Font $fn.Console -Fg $c.TextSec
$script:lblStatusFilter  = New-Lbl -Text "FILTER: All" -X 490 -Y 8 -W 360 -H 18 -Font $fn.Console -Fg $c.Dim
$script:lblStatusLog     = New-Lbl -Text ("LOG: $($global:AuditLogPath)") -X 856 -Y 8 -W ($f.ClientSize.Width - 866) -H 18 -Font $fn.Small -Fg $c.GoldDim
$script:lblStatusLog.TextAlign = 'MiddleRight'
$script:lblStatusLog.Anchor    = 'Top,Left,Right'

$pnlStatus.Controls.AddRange(@($script:lblStatusSession, $script:lblStatusTargets, $script:lblStatusFilter, $script:lblStatusLog))
#endregion

###############################################################################
###                         STARTUP / SHUTDOWN                              ###
###############################################################################
$script:rtbLog = $rtbU

Load-Catalog
Refresh-FindingsGrid
Update-StatusStrip

Set-JanetAllowClose $false
$f.Add_FormClosing({
    param($sender, $e)
    if (-not (Get-JanetAllowClose) -and $e.CloseReason -ne [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        $e.Cancel = $true
        return
    }
    try { if ($global:RSPool) { $global:RSPool.Close(); $global:RSPool.Dispose() } } catch {}
    try { Stop-JanetSession -ShowDialog } catch { }
})

try { Start-JanetSession -Tool 'Unsupported_Product_Remediator' -Version $JanetUnsupportedProductRemediatorVersion } catch { }

Log "Unsupported Product Remediator v$JanetUnsupportedProductRemediatorVersion ready" 'OK'
Log "Click 'Load PDF / CSV' to ingest a Tenable Unsupported / SEoL report" 'INFO'

[void]$f.ShowDialog()
