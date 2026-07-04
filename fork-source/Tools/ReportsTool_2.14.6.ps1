<#
.SYNOPSIS
    J.A.N.E.T. Reports Tool - ACAS & Patch Cross-Reference.

.DESCRIPTION
    Import ACAS scan data (CSV, TSV, .nessus XML), cross-reference patch
    status, compare baseline-vs-comparison scans, view a dashboard of
    compliance metrics, and export XLSX / JSON / CSV reports.

    Palette, typography, and chrome are aligned with the WPT (Workstation
    Patching Tool) module and the J.A.N.E.T. launcher so all three tools
    read as one application.

.NOTES
    Author:   Braxton Thompson | 48CS | B.E.A.T. Contractor
    Version:  2.14.6
    Date:     June 2026

    v2.14.6 - 2026-06-11 - Fix: Dirty 30 inflated vuln counts (a host showing
                           "219" Criticals when the PDF bar reads 2 Crit / 19
                           High). Tenable renders the C/H/M/L breakdown as a
                           stacked bar; pdftotext glues a narrow segment's
                           label onto its neighbor ("2"+"19" -> "219") and
                           drops zero-count segments, so the old left-to-right
                           tail read mis-assigned counts - and a 2-number tail
                           like "190 316" failed the regex entirely, showing 0
                           vulns. The Score column extracts cleanly and equals
                           10*Crit + 10*High + 4*Med + 1*Low for this report;
                           new Resolve-Dirty30Severities uses that invariant to
                           un-glue the bar and recover the true split. Rows
                           already consistent with Score are left untouched.
                           The Crit-vs-High split can't be derived from Score
                           alone (both weigh 10), so those rows take a best
                           guess and get a "*" verify-flag in the HTML report.
                           Tail regex relaxed (score + >=1 bar number, groups
                           widened to {1,5}). Validated end-to-end against a
                           30-host production export (0 score-inconsistent rows).
    v2.14.5 - 2026-06-06 - Fix: Parse-Dirty30Input iterated 0..(Count-1) over
                           the IP-anchor list; on pasted text with no IPv4 line
                           that range expanded to 0,-1 and scanned the whole
                           blob as one bogus block, risking a mis-extracted
                           host before the line-walker fallback. Switched to a
                           count-guarded for-loop.
    v2.14.4 - 2026-05-12 - PMO owner classifier: split the joint
                           "1stACOS|PMO UE" rule into two rules so the
                           NIPR scan ("PMO UE. User Endpoints") attributes
                           to AFAS while the SIPR scan ("PMO-1stACOS_UE")
                           keeps its 1st ACOS owner. Operator caught this
                           while reviewing the Weekly Export brief - the
                           NIPR-side org chain on the same scan family is
                           AFAS, not 1st ACOS, so the PMO owner roll-up
                           was labeling NIPR work incorrectly. Same
                           data; right name on it now. Verified against
                           the operator's live ACAS_Calculations CSV
                           (NIPR 2 weeks -> AFAS, SIPR 2 weeks -> 1st ACOS).
    v2.14.3 - 2026-05-12 - Dirty 30 HTML report: hostname column bumped
                           from 13.5 -> 22 px (font-weight 700) so it
                           reads at PowerPoint projector distance.
                           Operator was clipping the rendered HTML into
                           commander slides and hostnames were illegible
                           past the front row. Row padding widened
                           (9/12 -> 12/14) and vertical-align changed to
                           middle so the larger text doesn't crash into
                           neighboring shorter cells; subtle 0.3 px
                           letter-spacing added so the monospace doesn't
                           feel cramped at the new size.
    v2.14.2 - 2026-05-12 - Weekly Export: MAJCOM VPH is now surfaced
                           alongside the base VPH in both the in-tool
                           preview and the HTML report. Operator note:
                           leadership was only seeing the base (in-house)
                           VPH on the dashboard and wanted MAJCOM's
                           vulns-per-host visible at a glance for
                           commander comparison.
                             * HTML MAJCOM card: new "VPH" row right
                               under "AR %", styled as a `row big` so it
                               reads at projector distance.
                             * HTML metric-row tile relabeled
                               "VPH (In-House)" -> "VPH (Base)" so the
                               contrast with MAJCOM VPH is obvious.
                             * WinForms MAJCOM mini-card: panel grew 90
                               -> 110 px to fit "VPH:" line (gold,
                               LabelBold) between AR % and G/B totals.
                             * WinForms metric tile renamed to
                               "VPH (Base)" to match.
                           Data already flowed through Parse-AcasScanRow
                           (MajcomTotals.Vph) so no parser changes were
                           required; the CSV export was already shipping
                           MAJCOM VPH.
    v2.14.1 - 2026-05-12 - New "CORA Vulnerabilities" tab for the commander
                           brief. Sits between Dirty 30 Triage and Future
                           Target IPs in the sidebar. Aggregates the
                           currently loaded ACAS findings (open + actionable
                           only - Patched and NOT OUR PATCH excluded) into
                           a single-page commander view:
                             * Headline tiles: Total Open Vulns, Critical,
                               High, Unique Hosts Affected, Vulns per Host,
                               and % of Network Affected (uses the same
                               $global:NetworkDeviceCount input as the
                               Remediation Plan tab).
                             * Top 15 "Biggest Hitters" cards - one per
                               PluginID, sorted by host count desc then
                               severity. Each card shows the vuln name,
                               severity chip, host count, and % of network.
                             * Self-contained HTML export to Documents\
                               JANET_Reports\CORA for projector / email use.
                               Includes inline SVG: horizontal bar chart of
                               top 15 vulns, severity donut, category bar.
                               No external chart libs - pure SVG so it works
                               on locked-down workstations.
                           Reuses the existing $global:AcasFindings load
                           path - no new import flow. Refreshes on tab
                           click + after every ACAS import.
    v2.14.0 - 2026-05-11 - Two major tabs added:
                           * WEEKLY EXPORT. Splits the monthly
                             ACAS_Calculations workbook into per-week
                             cards on two enclaves (NIPR / SIPR), with
                             Total Vulns, AR % with/without PMO, MAJCOM
                             score, and VPH broken out by category
                             (UEs / Servers / Infrastructure / Printers /
                             PMO with owner roll-up). Per-week and
                             all-weeks CSV / XLSX export. Self-contained
                             HTML report rendered to Documents\
                             JANET_Reports\WeeklyExport for projector use.
                           * DIRTY 30 TRIAGE. Ingests the Tenable Top 30
                             Worst Hosts report (paste from PDF viewer,
                             CSV, TXT, or auto-converted PDF where
                             pdftotext.exe is available), runs batched
                             LDAP queries against AD via the same
                             template as ADSearchTool BulkComputer, and
                             surfaces squadron + last AD logon + stale
                             detection (>90 days). Squadron pulled from
                             the AFNET `location` attribute's
                             ORGANIZATION: token, falling back to OU
                             walking. Optional WMI registry probe for
                             the last interactive user, auto-fired in
                             the same flow. HTML report mirrors the
                             mockup. Stale-data flag for empty weeks
                             whose MAJCOM row carried over from a prior
                             month.
                           Also: Weekly Export scrolling fix (AutoScroll
                           moved to the outer tab panel), Weekly HTML
                           projector tuning (headline numbers 26->40px,
                           grey text palette brightened), Dirty 30 PDF
                           paste parser hardened (block-based extraction
                           handles wrapped NetBIOS, wrapped DNS,
                           uppercase-only NetBIOS regex to stop case
                           transitions, score+vulns tail accepts 3-5
                           numbers).
    v2.13.5 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
                           *_usage*.csv so schema-rotation sister files
                           (created when the legacy file is persistently
                           locked) are drained on next launch instead of
                           stranded.

    v2.13.4 - 2026-05-08 - JANET centralized-logging schema cleanup (single
                           SessionEnd rollup row; Snapshot rows retired) and
                           the WPT-themed Closing Notes prompt rolled across
                           the suite.
    v2.13.3 - 2026-04-19 - Start tab home grid expanded to six cards
            so Remediation Plan has its own home tile alongside the
            other tabs. Layout is now 3 rows x 2 cols, in sidebar order:
            (ACAS Import, Remediation Plan) / (Scan Comparison, Future
            Target IPs) / (Dashboard, Export). Workflow tip updated to
            "Import ACAS data > Plan remediation > Compare scans >
            Check Dashboard > Export reports". Remediation card uses
            $colors.Orange so it stays visually distinct from the
            existing five accents.

    v2.13.2 - 2026-04-19 - Sidebar tab order tweak. Operator wanted
            Remediation Plan adjacent to ACAS Import (its primary feed).
            New order: Start / ACAS Import / Remediation Plan / Patch
            Cross-Ref / Future Target IPs / Dashboard / Export. Home
            cards on the Start tab dispatch by tab NAME, not numeric
            index (since v2.11.0), so the reorder doesn't misroute any
            buttons - no home-card edits needed.

    v2.13.1 - 2026-04-19 - Bug fixes for the Remediation Plan tab:
            * "Property Hostname cannot be found" on every card action +
              card target version stuck at "-". Root cause: plan rows are
              hashtables, and Select-Object -ExpandProperty <Key> doesn't
              traverse hashtable keys in PowerShell 5.1 (only PSCustomObject
              members). Replaced both sites with
              ForEach-Object { $_.Key } | Sort-Object -Unique.
              Empty-list guard added on Clipboard.SetText so it doesn't
              blow up on null when an action runs against an empty plan.
            * "Cannot overwrite variable PID because it is read-only" -
              fired in a tight loop while the Remediation Plan tab was
              being built. Build-RemediationPlan was using $pid as a
              local in two spots; PowerShell exposes $pid as a read-only
              automatic variable for the process ID and assignment throws.
              Renamed both uses to $pluginIdKey. (The same trap was
              already avoided in New-OtherVulnCard via $cardPluginId.)

    v2.13.0 - 2026-04-19 - Two operator follow-ups on the Remediation Plan
            card UI:
            * Tab order: Dashboard moved to sit just above Export, so the
              sidebar reads Start / ACAS Import / Future Target IPs /
              Patch Cross-Ref / Remediation Plan / Dashboard / Export.
            * Other-vuln grouping: under the main 2x3 cards, a new
              "COMMON OTHER VULNS (10+ hosts each)" section. Build-
              RemediationPlan now keeps a per-PluginID host set for
              every finding that lands in the Other bucket; any plugin
              affecting >= $script:OtherVulnGroupMinHosts (default 10)
              distinct hosts gets its own dynamic card with the same
              four actions (Copy Hosts, Export CSV, Nemesis, Mark
              Pushed). Mark Pushed records the PluginID in
              $script:OtherVulnPushed and suppresses the card until
              the next ACAS import or session restart. Right-click ->
              "Hide this card" does the same without the dialog.
              $script:panelRem.AutoScroll set so the page extends
              when many vuln-groups land.

    v2.12.1 - 2026-04-19 - Remediation Plan tab UI rework. Operator
            envisioned card-only "what big pushes" view; the v2.12.0 grid +
            filter bar were removed. Now: 2x3 grid of large cards, one per
            app (Chrome / Edge / Office / Defender / KB / Other). Each
            card shows the target version, big hosts-behind count, severity
            breakdown line, and four inline buttons - Copy Hosts, Export
            CSV, Nemesis, Mark Pushed. Right-click a card for the same
            actions plus Mark Skipped / Reset to Pending. Other is dimmed
            (catch-all - no clear push target). Status persistence is
            still session-only.

    v2.12.0 - 2026-04-19 - New "Remediation Plan" sidebar tab between
            Dashboard and Export. Aggregates whatever findings are loaded
            into a per-(host, app) action list:
            * Six cards across the top show "N hosts behind" on Chrome /
              Edge / Office / Defender / KB Updates / Other. Click a card
              to filter the grid; right-click for bulk actions.
            * Action grid: one row per (host, app) target. Columns:
              Hostname, App, Current, Target, Severity, Findings, Last
              Observed, Status, Pushed By, Pushed Date, Notes.
            * Hybrid target-version resolver: $script:TargetVersionOverrides
              hashtable at the top of the file (operator-edited, wins) ->
              highest version inferred from each finding's "Steps to
              Remediate" text -> $null.
            * Actions: Copy Hosts, Copy Host/App/Target triples, Export
              Selected CSV (file only when operator clicks Save), Mark
              Pushed (themed dialog) / Mark Skipped / Reset to Pending,
              Open Plugin in browser (Tenable plugin page), Open in
              Nemesis (clipboard + best-effort sibling-script launch).
            * Pushed/Skipped status is session-only; resets on relaunch.
              No JSON files written. No handoff folders. Single-script
              footprint preserved.
            Filename renamed to ReportsTool_2.12.0.ps1; JANET_Config.json
            and JANET.ps1 Get-DefaultConfig updated; Take-to-work mirror
            updated.
    v2.11.0 - 2026-04-19 - Code-quality + perf sweep:
            * Bug fixes: home cards now dispatch by tab name (used to
              silently misroute after Future Target IPs was inserted at
              tab index 2); mouse-wheel events on the Dashboard's per-host
              grid now forward to the outer AutoScroll panel at scroll
              boundaries (was a known scroll trap); DoEvents removed from
              the async ping/resolve loops (let users click mid-sweep and
              corrupt $global:HostStatus); dead JANET_Toolkit walk-up
              code in the debug-log init removed.
            * Performance: Excel export uses Range.Value2 batch-write
              instead of per-cell .Cells.Item(r,c) (~40k -> 4 COM round-
              trips per sheet); Refresh-Dashboard does one pass over
              AcasFindings + per-host hashtable tally instead of 9+ Where-
              Object scans + per-host re-filtering; SuspendLayout/Resume-
              Layout around AcasGrid / XrefGrid / gridHostSummary rebuilds
              kills paint flicker; mark/undo handlers use a Hostname|
              PluginID hashtable lookup instead of O(rows*findings).
            * Cleanup: Show-PatchedByDateDialog factored from the two
              identical inline dialogs; Refresh-HostDropdown unifies the
              ACAS + Xref dropdown rebuilders; Get-AcasHostList replaces
              the redundant $global:HostList cache; Show-JanetClosingNotes
              Form now uses the dark theme + dark title bar; bar-chart
              brand colors hoisted into the palette ($colors.BrandChrome
              etc.); v1-v2.10 changelog history condensed into the git log.
    v1.0 - v2.11.0: prior history in git log.
#>
Add-Type -AssemblyName System.Windows.Forms,System.Drawing

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v2.9.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\Reports\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetReportsVersion = '2.14.5'

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

try { Add-Type -AssemblyName Microsoft.VisualBasic } catch {}

#region === RESOLVE SCRIPT DIRECTORY ===
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }
#endregion

#region === INLINED UI KIT (self-contained) ===
# Verbatim copy of Tools\UI\Theme.ps1 + Controls.ps1 + Dialog.ps1 as of
# 2026-04-23. ReportsTool is now self-contained -- no runtime dot-sourcing
# of the shared UI kit, matching WorkstationPatchingTool_6.1.10.ps1 and
# STIG_Tool_1.1.0.ps1. Copy this .ps1 anywhere and it runs. If Tools\UI\ is
# edited later, re-inline the bodies below the "## --- From Tools\UI\..."
# banners here to keep the palette and factories in sync across the suite.
# $script:WPT is the namespace the inlined theme + control factories write
# into.
if (-not $script:WPT) {
    $script:WPT = @{
        ModuleRoot = $global:ScriptDir
        ToolsRoot  = $global:ScriptDir
        UI = @{
            Form     = $null
            Theme    = $null
            Fonts    = $null
            Icons    = $null
            Controls = @{}
            TabPages = @{}
            NavItems = @{}
        }
    }
}

## --- From Tools\UI\Theme.ps1 ---

function Initialize-WptTheme {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing      -ErrorAction SilentlyContinue

    Set-WptDpiAware

    try { [System.Windows.Forms.Application]::EnableVisualStyles() }           catch {}
    try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

    $c = { param($r,$g,$b) [System.Drawing.Color]::FromArgb($r, $g, $b) }

    $script:WPT.UI.Theme = [pscustomobject]@{
        Background      = & $c   8   8  12
        Sidebar         = & $c   6   6  10
        TitleBar        = & $c   6   6  10
        StatusBar       = & $c   7   7  11
        Surface         = & $c  16  16  22
        SurfaceAlt      = & $c  22  22  30
        SurfaceHover    = & $c  30  28  40
        SurfaceActive   = & $c  40  36  54

        Border          = & $c  38  34  52
        BorderStrong    = & $c  52  46  72
        BorderAccent    = & $c 140 100 220

        Accent1         = & $c 140 100 220
        Accent1Hover    = & $c 164 128 240
        Accent1Muted    = & $c  96  68 156
        Accent1Glow     = & $c  28  20  48

        Accent2         = & $c 218 180  82
        Accent2Hover    = & $c 238 200 110

        Success         = & $c  92 198 120
        SuccessHover    = & $c 120 220 148
        Warning         = & $c 230 180  70
        WarningHover    = & $c 248 200 100
        Danger          = & $c 224  80  90
        DangerHover     = & $c 244 110 118
        Info            = & $c  88 180 210

        TextPrimary     = & $c 240 240 245
        TextSecondary   = & $c 170 168 180
        TextMuted       = & $c 110 106 125
        TextFaint       = & $c  60  56  74
        TextDisabled    = & $c  60  56  74
        TextOnAccent    = & $c 255 255 255

        GridBgPrimary   = & $c  16  16  22
        GridBgAlt       = & $c  22  22  30
        GridHeader      = & $c  10  10  16
        GridSelection   = & $c  28  20  48
        GridLine        = & $c  38  34  52

        ConsoleBg       = & $c   6   6  10
        ConsoleFg       = & $c 164 128 240
        ConsoleMuted    = & $c  96  68 156

        StripeYellow    = & $c 140 100 220
        StripeBlack     = & $c   8   8  12

        BG              = & $c   8   8  12
        TopBar          = & $c   6   6  10
        Panel           = & $c  16  16  22
        PanelLight      = & $c  30  28  40
        Input           = & $c  22  22  30
        InputBdr        = & $c  52  46  72
        OutputBg        = & $c   6   6  10
        GridBg          = & $c  16  16  22
        GridHdr         = & $c  10  10  16
        GridAlt         = & $c  22  22  30
        White           = & $c 240 240 245
        TextSec         = & $c 170 168 180
        Dim             = & $c 110 106 125
        Accent          = & $c 140 100 220
        Gold            = & $c 218 180  82
        Console         = & $c 218 180  82
        Cyan            = & $c  88 180 210
        Purple          = & $c 218 180  82
        SidebarBg       = & $c   6   6  10
    }

    $mono = 'Cascadia Mono'
    $body = 'Segoe UI Variable Display'
    $bodyAlt = 'Segoe UI'

    $script:WPT.UI.Fonts = [pscustomobject]@{
        DisplayLg   = New-Object System.Drawing.Font($mono, 18, [System.Drawing.FontStyle]::Bold)
        DisplayMd   = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
        DisplaySm   = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)

        Eyebrow     = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        EyebrowDim  = New-Object System.Drawing.Font($mono,  8, [System.Drawing.FontStyle]::Regular)

        H1          = New-Object System.Drawing.Font($body, 18, [System.Drawing.FontStyle]::Bold)
        H2          = New-Object System.Drawing.Font($body, 14, [System.Drawing.FontStyle]::Bold)
        H3          = New-Object System.Drawing.Font($body, 11, [System.Drawing.FontStyle]::Bold)
        Body        = New-Object System.Drawing.Font($body, 10)
        BodyStrong  = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
        Caption     = New-Object System.Drawing.Font($body,  9)
        CaptionB    = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
        Tiny        = New-Object System.Drawing.Font($body,  8)

        Mono        = New-Object System.Drawing.Font($mono, 10)
        MonoSm      = New-Object System.Drawing.Font($mono,  9)
        MonoTiny    = New-Object System.Drawing.Font($mono,  8)

        Icon        = New-Object System.Drawing.Font('Segoe MDL2 Assets', 14)
        IconLarge   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 22)
        IconSmall   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)

        Title       = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
        Sub         = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Italic)
        Label       = New-Object System.Drawing.Font($body, 10)
        LabelB      = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
        Btn         = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        BtnBig      = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)
        Console     = New-Object System.Drawing.Font($mono, 10)
        Small       = New-Object System.Drawing.Font($body,  9)
        SmallB      = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
        GrpHdr      = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        Big         = New-Object System.Drawing.Font($body, 12, [System.Drawing.FontStyle]::Bold)
    }

    $script:WPT.UI.Icons = [pscustomobject]@{
        Settings  = [char]0xE713
        Target    = [char]0xE8FD
        Search    = [char]0xE721
        Package   = [char]0xE7B8
        AppIcon   = [char]0xECAA
        Upload    = [char]0xE898
        Keyboard  = [char]0xE7C1
        Sync      = [char]0xE895
        Mail      = [char]0xE8BD
        Broom     = [char]0xE74D
        Chart     = [char]0xE9D9
        Document  = [char]0xE8A5
        Info      = [char]0xE946
        Power     = [char]0xE7E8
        Lock      = [char]0xE72E
        User      = [char]0xE77B
        Check     = [char]0xE73E
        Dot       = [char]0xE915
        Shield    = [char]0xEA18
        Signal    = [char]0xE8F4
        Radio     = [char]0xE704
        Connect   = [char]0xE703
        Warning   = [char]0xE7BA
    }
}

function Set-WptDpiAware {
    [CmdletBinding()]
    param()

    if (-not ('WptDpi.Api' -as [type])) {
        Add-Type -Namespace 'WptDpi' -Name 'Api' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDpiAwarenessContext(System.IntPtr value);

[System.Runtime.InteropServices.DllImport("shcore.dll")]
public static extern int SetProcessDpiAwareness(int value);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();
'@ -ErrorAction SilentlyContinue
    }

    try {
        $ctx = [System.IntPtr]::new(-4)
        if ([WptDpi.Api]::SetProcessDpiAwarenessContext($ctx)) { return }
    } catch {}
    try {
        [void][WptDpi.Api]::SetProcessDpiAwareness(2)
        return
    } catch {}
    try {
        [void][WptDpi.Api]::SetProcessDPIAware()
    } catch {}
}

function Set-WptDarkTitleBar {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Form)

    if (-not ('Wpt.Dwm' -as [type])) {
        Add-Type -Namespace 'Wpt' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }

    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }

    $enable = 1
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)

    $round = 2
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

## --- From Tools\UI\Controls.ps1 ---

function Enable-WptDoubleBuffer {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Control)
    try {
        $prop = $Control.GetType().GetProperty(
            'DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic'
        )
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function New-WptButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Bg = $null, $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Bg)   { $Bg = $theme.Accent1 }
    if (-not $Fg) {
        $lum = (0.299 * $Bg.R + 0.587 * $Bg.G + 0.114 * $Bg.B) / 255.0
        if ($lum -gt 0.55) { $Fg = $theme.TextOnAccent }
        else               { $Fg = $theme.TextPrimary }
    }
    if (-not $Font) { $Font = $fonts.Btn }

    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Bg
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.TextAlign = 'MiddleCenter'
    $b.UseVisualStyleBackColor = $false
    $hover = [System.Drawing.Color]::FromArgb([Math]::Min(255,$Bg.R+28), [Math]::Min(255,$Bg.G+28), [Math]::Min(255,$Bg.B+28))
    $down  = [System.Drawing.Color]::FromArgb([Math]::Max(0,$Bg.R-20), [Math]::Max(0,$Bg.G-20), [Math]::Max(0,$Bg.B-20))
    $b.FlatAppearance.MouseOverBackColor = $hover
    $b.FlatAppearance.MouseDownBackColor = $down
    return $b
}

function New-WptLabel {
    [CmdletBinding()]
    param(
        [string]$Text = '',
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 18,
        $Font = $null, $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.Body }
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.Font      = $Font
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

function New-WptTextBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26,
        [switch]$Multi
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location    = New-Object System.Drawing.Point($X, $Y)
    $t.Size        = New-Object System.Drawing.Size($W, $H)
    $t.BackColor   = $theme.Input
    $t.ForeColor   = $theme.TextPrimary
    $t.Font        = $fonts.Mono
    $t.BorderStyle = 'FixedSingle'
    if ($Multi) { $t.Multiline = $true; $t.ScrollBars = 'Vertical' }
    return $t
}

function New-WptGroupBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
        $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text      = " $($Text.ToUpperInvariant()) "
    $g.Location  = New-Object System.Drawing.Point($X, $Y)
    $g.Size      = New-Object System.Drawing.Size($W, $H)
    $g.ForeColor = $Fg
    $g.BackColor = $theme.Surface
    $g.Font      = $fonts.Eyebrow
    return $g
}

function New-WptRichTextBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 600, [int]$H = 200
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $r = New-Object System.Windows.Forms.RichTextBox
    $r.Location    = New-Object System.Drawing.Point($X, $Y)
    $r.Size        = New-Object System.Drawing.Size($W, $H)
    $r.BackColor   = $theme.ConsoleBg
    $r.ForeColor   = $theme.ConsoleFg
    $r.Font        = $fonts.Mono
    $r.ReadOnly    = $true
    $r.BorderStyle = 'None'
    $r.WordWrap    = $false
    $r.ScrollBars  = 'Vertical'
    return $r
}

function New-WptCheckBox {
    [CmdletBinding()]
    param(
        [string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 250, [int]$H = 24,
        $Fg = $null, [bool]$Checked = $false
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.TextPrimary }

    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text       = $Text
    $c.Location   = New-Object System.Drawing.Point($X, $Y)
    $c.Size       = New-Object System.Drawing.Size($W, $H)
    $c.ForeColor  = $Fg
    $c.BackColor  = $theme.Surface
    $c.Font       = $fonts.Body
    $c.Checked    = $Checked
    $c.Cursor     = [System.Windows.Forms.Cursors]::Hand
    $c.Appearance = 'Button'
    $c.FlatStyle  = 'Flat'
    $c.FlatAppearance.BorderSize          = 0
    $c.FlatAppearance.CheckedBackColor    = $theme.Surface
    $c.FlatAppearance.MouseOverBackColor  = $theme.SurfaceHover
    $c.FlatAppearance.MouseDownBackColor  = $theme.SurfaceActive
    $c.TextAlign  = 'MiddleLeft'
    $c.Padding    = New-Object System.Windows.Forms.Padding(26, 0, 0, 0)
    $c.AutoSize   = $false

    $borderOff  = $theme.BorderStrong
    $borderOn   = $theme.Accent1
    $fillOn     = $theme.Accent1
    $checkFg    = $theme.TextOnAccent

    $c.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $box = 14
        $bx  = 4
        $by  = [int](($sender.Height - $box) / 2)

        if ($sender.Checked) {
            $fill = New-Object System.Drawing.SolidBrush($fillOn)
            try { $g.FillRectangle($fill, $bx, $by, $box, $box) }
            finally { $fill.Dispose() }
            $pen = New-Object System.Drawing.Pen($borderOn, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) }
            finally { $pen.Dispose() }
            $cp = New-Object System.Drawing.Pen($checkFg, 2)
            try {
                $p1 = New-Object System.Drawing.Point(($bx + 3),  ($by + 7))
                $p2 = New-Object System.Drawing.Point(($bx + 6),  ($by + 10))
                $p3 = New-Object System.Drawing.Point(($bx + 11), ($by + 4))
                $g.DrawLines($cp, @($p1, $p2, $p3))
            } finally { $cp.Dispose() }
        } else {
            $pen = New-Object System.Drawing.Pen($borderOff, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) }
            finally { $pen.Dispose() }
        }
    }.GetNewClosure())

    $c.Add_CheckedChanged({ $sender = $args[0]; $sender.Invalidate() })

    return $c
}

function New-WptComboBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26,
        [string[]]$Items = @()
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Location      = New-Object System.Drawing.Point($X, $Y)
    $cb.Size          = New-Object System.Drawing.Size($W, $H)
    $cb.BackColor     = $theme.Input
    $cb.ForeColor     = $theme.TextPrimary
    $cb.Font          = $fonts.Mono
    $cb.DropDownStyle = 'DropDownList'
    $cb.FlatStyle     = 'Flat'
    foreach ($i in $Items) { [void]$cb.Items.Add($i) }
    return $cb
}

function New-WptNumericUpDown {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 70, [int]$H = 26,
        [int]$Min = 0, [int]$Max = 100, [int]$Value = 0
    )
    $theme = $script:WPT.UI.Theme
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Location    = New-Object System.Drawing.Point($X, $Y)
    $n.Size        = New-Object System.Drawing.Size($W, $H)
    $n.Minimum     = $Min
    $n.Maximum     = $Max
    $n.Value       = $Value
    $n.BackColor   = $theme.Input
    $n.ForeColor   = $theme.TextPrimary
    $n.BorderStyle = 'FixedSingle'
    $n.Font        = $script:WPT.UI.Fonts.Mono
    return $n
}

function New-WptListBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 300, [int]$H = 200
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Location      = New-Object System.Drawing.Point($X, $Y)
    $lb.Size          = New-Object System.Drawing.Size($W, $H)
    $lb.BackColor     = $theme.Input
    $lb.ForeColor     = $theme.Accent1
    $lb.Font          = $fonts.Mono
    $lb.BorderStyle   = 'FixedSingle'
    $lb.SelectionMode = 'MultiExtended'
    return $lb
}

function New-WptTabPage {
    [CmdletBinding()]
    param([string]$Text)
    $theme = $script:WPT.UI.Theme
    $tp = New-Object System.Windows.Forms.Panel
    $tp.Tag       = $Text
    $tp.BackColor = $theme.Background
    $tp.Dock      = 'Fill'
    $tp.Visible   = $false
    $tp.Padding   = New-Object System.Windows.Forms.Padding(0)
    return $tp
}

function New-WptCard {
    [CmdletBinding()]
    param(
        [string]$Header,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
        $Fg = $null,
        [int]$Padding = 20,
        [int]$BracketLen = 18,
        [int]$BracketThick = 2
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }

    $card = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($X, $Y)
    $card.Size      = New-Object System.Drawing.Size($W, $H)
    $card.BackColor = $theme.Surface
    $card.Padding   = New-Object System.Windows.Forms.Padding($Padding)

    $bracketColor = $Fg
    $underColor   = [System.Drawing.Color]::FromArgb(90, $Fg.R, $Fg.G, $Fg.B)
    $hasHdr       = -not [string]::IsNullOrWhiteSpace($Header)

    $card.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'HighQuality'
        $pen = New-Object System.Drawing.Pen($bracketColor, $BracketThick)
        try {
            $w = $sender.Width  - 1
            $h = $sender.Height - 1
            $L = $BracketLen
            $g.DrawLine($pen, 0, 0, $L, 0)
            $g.DrawLine($pen, 0, 0, 0, $L)
            $g.DrawLine($pen, ($w - $L), 0, $w, 0)
            $g.DrawLine($pen, $w, 0, $w, $L)
            $g.DrawLine($pen, 0, ($h - $L), 0, $h)
            $g.DrawLine($pen, 0, $h, $L, $h)
            $g.DrawLine($pen, ($w - $L), $h, $w, $h)
            $g.DrawLine($pen, $w, ($h - $L), $w, $h)
        } finally { $pen.Dispose() }

        if ($hasHdr) {
            $dotPen = New-Object System.Drawing.Pen($underColor, 1)
            $dotPen.DashStyle = 'Dot'
            try {
                $g.DrawLine($dotPen, $Padding, 40, ($sender.Width - $Padding), 40)
            } finally { $dotPen.Dispose() }
        }
    }.GetNewClosure())

    if ($hasHdr) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text      = "/ $($Header.ToUpperInvariant())"
        $hdr.Location  = New-Object System.Drawing.Point($Padding, 14)
        $hdr.Size      = New-Object System.Drawing.Size(($W - $Padding * 2), 22)
        $hdr.ForeColor = $Fg
        $hdr.BackColor = [System.Drawing.Color]::Transparent
        $hdr.Font      = $fonts.Eyebrow
        $card.Controls.Add($hdr)
    }

    return $card
}

function New-WptHeading {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('H1','H2','H3')][string]$Level = 'H2',
        [int]$X = 0, [int]$Y = 0, [int]$W = 600, [int]$H = 30,
        $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.TextPrimary }
    $font = switch ($Level) {
        'H1' { $fonts.DisplayLg }
        'H2' { $fonts.DisplayMd }
        default { $fonts.DisplaySm }
    }
    $h = New-Object System.Windows.Forms.Label
    $h.Text      = $Text
    $h.Location  = New-Object System.Drawing.Point($X, $Y)
    $h.Size      = New-Object System.Drawing.Size($W, $H)
    $h.ForeColor = $Fg
    $h.BackColor = [System.Drawing.Color]::Transparent
    $h.Font      = $font
    return $h
}

function New-WptSeparator {
    [CmdletBinding()]
    param([int]$X = 0, [int]$Y = 0, [int]$W = 400, $Color = $null)
    $theme = $script:WPT.UI.Theme
    if (-not $Color) { $Color = $theme.Border }
    $s = New-Object System.Windows.Forms.Panel
    $s.Location  = New-Object System.Drawing.Point($X, $Y)
    $s.Size      = New-Object System.Drawing.Size($W, 1)
    $s.BackColor = $Color
    return $s
}

function New-WptIconLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][char]$Glyph,
        [int]$X = 0, [int]$Y = 0, [int]$W = 24, [int]$H = 24,
        $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg)   { $Fg   = $theme.TextPrimary }
    if (-not $Font) { $Font = $fonts.Icon }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = [string]$Glyph
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.Font      = $Font
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-WptPrimaryButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 180, [int]$H = 38,
        $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.DisplaySm }
    $b = New-WptButton -Text $Text.ToUpperInvariant() -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $Font
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover
    return $b
}

function New-WptGhostButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    if (-not $Font) { $Font = $fonts.Btn }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.BorderColor = $theme.Border
    $b.BackColor = [System.Drawing.Color]::Transparent
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $b.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    return $b
}

function New-WptStripeButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 220, [int]$H = 48,
        $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.DisplayMd }
    $b = New-WptButton -Text $Text.ToUpperInvariant() -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $Font
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover

    $stripeHeight = 4
    $stripeColor1 = $theme.StripeYellow
    $stripeColor2 = $theme.StripeBlack
    $b.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush('WideDownwardDiagonal', $stripeColor2, $stripeColor1)
        try {
            $rect = New-Object System.Drawing.Rectangle(0, ($sender.Height - $stripeHeight), $sender.Width, $stripeHeight)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())

    return $b
}

function New-WptBadge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 80, [int]$H = 20,
        $Fg = $null, $Bg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }
    if (-not $Bg) { $Bg = [System.Drawing.Color]::FromArgb(40, $Fg.R, $Fg.G, $Fg.B) }

    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text.ToUpperInvariant()
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = $Bg
    $l.Font      = $fonts.MonoTiny
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-WptPulseIndicator {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$Size = 10,
        [ValidateSet('Active','Idle','Alert')][string]$State = 'Idle'
    )
    $theme = $script:WPT.UI.Theme
    $p = New-Object System.Windows.Forms.Panel
    $p.Location  = New-Object System.Drawing.Point($X, $Y)
    $p.Size      = New-Object System.Drawing.Size($Size, $Size)
    $p.BackColor = [System.Drawing.Color]::Transparent

    $color1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $color2 = [System.Drawing.Color]::FromArgb(40, $color1.R, $color1.G, $color1.B)

    $p.Tag = @{ Phase = 0; State = $State; C1 = $color1; C2 = $color2 }

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
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
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

function Set-WptPulseState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Indicator,
        [ValidateSet('Active','Idle','Alert')][string]$State
    )
    $theme = $script:WPT.UI.Theme
    $t = $Indicator.Tag
    $t.State = $State
    $t.C1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $t.C2 = [System.Drawing.Color]::FromArgb(40, $t.C1.R, $t.C1.G, $t.C1.B)

    if ($t.Timer) { $t.Timer.Stop(); $t.Timer.Dispose(); $t.Timer = $null }
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({
            $Indicator.Tag.Phase = 1 - $Indicator.Tag.Phase
            $Indicator.Invalidate()
        }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Indicator.Invalidate()
}

function New-WptNavItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][char]$Icon,
        [Parameter(Mandatory)][int]$Index,
        [int]$Y = 0,
        [int]$W = 240, [int]$H = 42
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts

    $item = New-Object System.Windows.Forms.Panel
    $item.Location  = New-Object System.Drawing.Point(0, $Y)
    $item.Size      = New-Object System.Drawing.Size($W, $H)
    $item.BackColor = $theme.Sidebar
    $item.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $item.Tag       = @{ Key = $Key; IsActive = $false }

    $bar = New-Object System.Windows.Forms.Panel
    $bar.Location  = New-Object System.Drawing.Point(0, 6)
    $bar.Size      = New-Object System.Drawing.Size(3, ($H - 12))
    $bar.BackColor = $theme.Accent1
    $bar.Visible   = $false
    $item.Controls.Add($bar)

    $num = New-Object System.Windows.Forms.Label
    $num.Text      = '{0:D2}' -f $Index
    $num.Location  = New-Object System.Drawing.Point(16, 0)
    $num.Size      = New-Object System.Drawing.Size(24, $H)
    $num.Font      = $fonts.MonoSm
    $num.ForeColor = $theme.TextFaint
    $num.BackColor = [System.Drawing.Color]::Transparent
    $num.TextAlign = 'MiddleLeft'
    $item.Controls.Add($num)

    $ico = New-Object System.Windows.Forms.Label
    $ico.Text      = [string]$Icon
    $ico.Location  = New-Object System.Drawing.Point(44, 0)
    $ico.Size      = New-Object System.Drawing.Size(22, $H)
    $ico.Font      = $fonts.Icon
    $ico.ForeColor = $theme.TextSecondary
    $ico.BackColor = [System.Drawing.Color]::Transparent
    $ico.TextAlign = 'MiddleCenter'
    $item.Controls.Add($ico)

    $txt = New-Object System.Windows.Forms.Label
    $txt.Text      = $Label.ToUpperInvariant()
    $txt.Location  = New-Object System.Drawing.Point(72, 0)
    $txt.Size      = New-Object System.Drawing.Size(($W - 80), $H)
    $txt.Font      = $fonts.BodyStrong
    $txt.ForeColor = $theme.TextSecondary
    $txt.BackColor = [System.Drawing.Color]::Transparent
    $txt.TextAlign = 'MiddleLeft'
    $item.Controls.Add($txt)

    $item.Tag['Bar']  = $bar
    $item.Tag['Num']  = $num
    $item.Tag['Icon'] = $ico
    $item.Tag['Text'] = $txt

    $sidebarBg = $theme.Sidebar
    $hoverBg   = $theme.SurfaceHover
    $activeBg  = $theme.SurfaceActive
    $dimFg     = $theme.TextSecondary
    $faintFg   = $theme.TextFaint
    $onFg      = $theme.TextPrimary
    $accentFg  = $theme.Accent1

    $refreshVisual = {
        param($panel)
        $isActive = [bool]$panel.Tag['IsActive']
        $panel.Tag['Bar'].Visible = $isActive
        if ($isActive) {
            $panel.BackColor             = $activeBg
            $panel.Tag['Num'].ForeColor  = $accentFg
            $panel.Tag['Icon'].ForeColor = $accentFg
            $panel.Tag['Text'].ForeColor = $onFg
        } else {
            $panel.BackColor             = $sidebarBg
            $panel.Tag['Num'].ForeColor  = $faintFg
            $panel.Tag['Icon'].ForeColor = $dimFg
            $panel.Tag['Text'].ForeColor = $dimFg
        }
    }.GetNewClosure()
    $item.Tag['Refresh'] = $refreshVisual

    $findNavPanel = {
        param($startCtl)
        $p = $startCtl
        while ($p) {
            if ($p.Tag -is [hashtable] -and $p.Tag.ContainsKey('Key')) { return $p }
            $p = $p.Parent
        }
        return $null
    }.GetNewClosure()

    $onEnter = {
        param($sender, $e)
        $panel = & $findNavPanel $sender
        if (-not $panel) { return }
        if (-not [bool]$panel.Tag['IsActive']) {
            $panel.BackColor             = $hoverBg
            $panel.Tag['Num'].ForeColor  = $dimFg
            $panel.Tag['Icon'].ForeColor = $onFg
            $panel.Tag['Text'].ForeColor = $onFg
        }
    }.GetNewClosure()
    $onLeave = {
        param($sender, $e)
        $panel = & $findNavPanel $sender
        if (-not $panel) { return }
        & $panel.Tag['Refresh'] $panel
    }.GetNewClosure()

    $item.Add_MouseEnter($onEnter); $item.Add_MouseLeave($onLeave)
    foreach ($child in @($bar, $num, $ico, $txt)) {
        $child.Add_MouseEnter($onEnter)
        $child.Add_MouseLeave($onLeave)
    }
    return $item
}

function Set-WptNavItemActive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SidebarPanel,
        [Parameter(Mandatory)][string]$Key
    )
    foreach ($child in $SidebarPanel.Controls) {
        if ($child -is [System.Windows.Forms.Panel] -and $child.Tag -is [hashtable] -and $child.Tag.ContainsKey('Key')) {
            $child.Tag['IsActive'] = ($child.Tag['Key'] -eq $Key)
            & $child.Tag['Refresh'] $child
        }
    }
}

function New-WptGridPaperBackground {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Panel,
        [int]$Spacing = 16
    )
    $theme = $script:WPT.UI.Theme
    $dotColor = [System.Drawing.Color]::FromArgb(18, $theme.TextMuted.R, $theme.TextMuted.G, $theme.TextMuted.B)

    $Panel.Add_Paint({
        param($sender, $e)
        $brush = New-Object System.Drawing.SolidBrush($dotColor)
        try {
            $w = $sender.Width
            $h = $sender.Height
            for ($x = $Spacing; $x -lt $w; $x += $Spacing) {
                for ($y = $Spacing; $y -lt $h; $y += $Spacing) {
                    $e.Graphics.FillRectangle($brush, $x, $y, 1, 1)
                }
            }
        } finally { $brush.Dispose() }
    }.GetNewClosure())
}

function New-WptScanlineOverlay {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Panel)
    $theme = $script:WPT.UI.Theme
    $lineColor = [System.Drawing.Color]::FromArgb(10, 255, 255, 255)
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

## --- From Tools\UI\Dialog.ps1 ---

function Show-WptDialog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [Parameter(Position = 1)][string]$Title = 'J.A.N.E.T.',
        [Parameter(Position = 2)][object]$Buttons = 0,
        [Parameter(Position = 3)][object]$Icon = 0
    )

    $btnStr  = "$Buttons"
    $btnKind = 'OK'
    if     ($btnStr -eq '0' -or $btnStr -eq 'OK')                     { $btnKind = 'OK' }
    elseif ($btnStr -eq '1' -or $btnStr -eq 'OKCancel')               { $btnKind = 'OKCancel' }
    elseif ($btnStr -eq '3' -or $btnStr -eq 'YesNoCancel')            { $btnKind = 'YesNoCancel' }
    elseif ($btnStr -eq '4' -or $btnStr -eq 'YesNo')                  { $btnKind = 'YesNo' }

    $icnStr   = "$Icon"
    $iconKind = 'None'
    if     ($icnStr -eq '0'  -or $icnStr -eq 'None')                                { $iconKind = 'None' }
    elseif ($icnStr -eq '16' -or $icnStr -match '^(Error|Hand|Stop)$')              { $iconKind = 'Error' }
    elseif ($icnStr -eq '32' -or $icnStr -eq 'Question')                            { $iconKind = 'Question' }
    elseif ($icnStr -eq '48' -or $icnStr -match '^(Warning|Exclamation)$')          { $iconKind = 'Warning' }
    elseif ($icnStr -eq '64' -or $icnStr -match '^(Information|Asterisk|Info)$')    { $iconKind = 'Info' }

    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts

    $iconGlyph = ''
    $iconColor = $theme.Dim
    switch ($iconKind) {
        'Error'    { $iconGlyph = '!'; $iconColor = $theme.Danger }
        'Warning'  { $iconGlyph = '!'; $iconColor = $theme.Warning }
        'Question' { $iconGlyph = '?'; $iconColor = $theme.Accent1 }
        'Info'     { $iconGlyph = 'i'; $iconColor = $theme.Cyan }
    }
    $hasIcon = ($iconKind -ne 'None')

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = $Title
    $form.StartPosition   = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.ShowInTaskbar   = $false
    $form.BackColor       = $theme.Background
    $form.ForeColor       = $theme.TextPrimary
    $form.Font            = $fonts.Body
    $form.KeyPreview      = $true
    try { Enable-WptDoubleBuffer -Control $form } catch {}

    $marginX   = 24
    $marginY   = 18
    $iconW     = if ($hasIcon) { 56 } else { 0 }
    $titleH    = 36
    $accentH   = 2
    $btnRowH   = 56
    $maxTextW  = 460
    $btnW      = 100
    $btnH      = 30
    $btnSpacing = 10
    $btnRowRightInset = 24

    $btnCount = switch ($btnKind) {
        'OK'          { 1 }
        'OKCancel'    { 2 }
        'YesNo'       { 2 }
        'YesNoCancel' { 3 }
        default       { 1 }
    }
    $totalBtnW = ($btnCount * $btnW) + (($btnCount - 1) * $btnSpacing)
    $minBtnRowW = $marginX + $totalBtnW + $btnRowRightInset

    $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor `
             [System.Windows.Forms.TextFormatFlags]::NoPadding
    $measureBox = New-Object System.Drawing.Size($maxTextW, 2000)
    $msgSize = [System.Windows.Forms.TextRenderer]::MeasureText(
        $Message, $fonts.Body, $measureBox, $flags)
    $msgW = [Math]::Max(260, [Math]::Min($maxTextW, [int]$msgSize.Width + 4))
    $msgH = [Math]::Max(40,  [int]$msgSize.Height + 8)

    $contentW = $marginX + $iconW + $msgW + $marginX
    $clientW  = [Math]::Max([Math]::Max($contentW, $minBtnRowW), 440)
    $clientH  = $titleH + $accentH + $marginY + $msgH + $marginY + $btnRowH
    if ($clientH -lt 220) { $clientH = 220 }
    $form.ClientSize   = New-Object System.Drawing.Size($clientW, $clientH)
    $chromeH = [System.Windows.Forms.SystemInformation]::CaptionHeight + 16
    $form.MinimumSize  = New-Object System.Drawing.Size(($clientW + 16), ($clientH + $chromeH))

    $titleStrip = New-Object System.Windows.Forms.Panel
    $titleStrip.Dock      = 'Top'
    $titleStrip.Height    = $titleH
    $titleStrip.BackColor = $theme.Sidebar

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = "/ $($Title.ToUpperInvariant())"
    $lblTitle.Location  = New-Object System.Drawing.Point(20, 10)
    $lblTitle.Size      = New-Object System.Drawing.Size(($clientW - 40), 20)
    $lblTitle.Font      = $fonts.LabelB
    $lblTitle.ForeColor = $theme.Accent1
    $lblTitle.BackColor = [System.Drawing.Color]::Transparent
    $titleStrip.Controls.Add($lblTitle)

    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock      = 'Top'
    $accent.Height    = $accentH
    $accent.BackColor = $theme.Accent1

    $btnRow = New-Object System.Windows.Forms.Panel
    $btnRow.Dock      = 'Bottom'
    $btnRow.Height    = $btnRowH
    $btnRow.BackColor = $theme.Background
    $btnRow.Width     = $clientW

    $btnSpecs = @()
    switch ($btnKind) {
        'OK' {
            $btnSpecs = @(
                @{ Text='OK'; Result=[System.Windows.Forms.DialogResult]::OK; Bg=$theme.Accent }
            )
        }
        'OKCancel' {
            $btnSpecs = @(
                @{ Text='OK';     Result=[System.Windows.Forms.DialogResult]::OK;     Bg=$theme.Accent },
                @{ Text='Cancel'; Result=[System.Windows.Forms.DialogResult]::Cancel; Bg=$theme.PanelLight }
            )
        }
        'YesNo' {
            $btnSpecs = @(
                @{ Text='Yes'; Result=[System.Windows.Forms.DialogResult]::Yes; Bg=$theme.Success },
                @{ Text='No';  Result=[System.Windows.Forms.DialogResult]::No;  Bg=$theme.Danger }
            )
        }
        'YesNoCancel' {
            $btnSpecs = @(
                @{ Text='Yes';    Result=[System.Windows.Forms.DialogResult]::Yes;    Bg=$theme.Success },
                @{ Text='No';     Result=[System.Windows.Forms.DialogResult]::No;     Bg=$theme.Danger },
                @{ Text='Cancel'; Result=[System.Windows.Forms.DialogResult]::Cancel; Bg=$theme.PanelLight }
            )
        }
    }

    $firstX = $clientW - $totalBtnW - $btnRowRightInset
    $btnY   = [int](($btnRowH - $btnH) / 2)
    $btns   = @()
    for ($i = 0; $i -lt $btnSpecs.Count; $i++) {
        $spec = $btnSpecs[$i]
        $bg   = $spec['Bg']
        $fg   = if ($spec['Text'] -eq 'Cancel') { $theme.TextPrimary } else { $theme.TextOnAccent }
        $b = New-WptButton -Text $spec['Text'] `
                -X ($firstX + $i * ($btnW + $btnSpacing)) -Y $btnY -W $btnW -H $btnH `
                -Bg $bg -Fg $fg
        $b.DialogResult = $spec['Result']
        $b.Anchor       = 'Top,Right'
        $btnRow.Controls.Add($b)
        $btns += $b
    }
    $form.AcceptButton = $btns[0]
    foreach ($b in $btns) {
        if ($b.DialogResult -eq [System.Windows.Forms.DialogResult]::Cancel -or
            $b.DialogResult -eq [System.Windows.Forms.DialogResult]::No) {
            $form.CancelButton = $b
            break
        }
    }

    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Dock      = 'Fill'
    $contentPanel.BackColor = $theme.Background

    if ($hasIcon) {
        $lblIcon = New-Object System.Windows.Forms.Label
        $lblIcon.Size      = New-Object System.Drawing.Size(48, 48)
        $lblIcon.Location  = New-Object System.Drawing.Point($marginX, $marginY)
        $lblIcon.Text      = $iconGlyph
        $lblIcon.Font      = New-Object System.Drawing.Font('Cascadia Mono', 26, [System.Drawing.FontStyle]::Bold)
        $lblIcon.ForeColor = $iconColor
        $lblIcon.BackColor = [System.Drawing.Color]::Transparent
        $lblIcon.TextAlign = 'MiddleCenter'
        $contentPanel.Controls.Add($lblIcon)
    }

    $lblMsg = New-Object System.Windows.Forms.Label
    $lblMsg.Text      = $Message
    $lblMsg.Location  = New-Object System.Drawing.Point(($marginX + $iconW), $marginY)
    $lblMsg.Size      = New-Object System.Drawing.Size($msgW, $msgH)
    $lblMsg.Font      = $fonts.Body
    $lblMsg.ForeColor = $theme.TextPrimary
    $lblMsg.BackColor = [System.Drawing.Color]::Transparent
    $lblMsg.AutoSize  = $false
    $contentPanel.Controls.Add($lblMsg)

    $form.Controls.Add($contentPanel)
    $form.Controls.Add($btnRow)
    $form.Controls.Add($accent)
    $form.Controls.Add($titleStrip)

    $form.Add_HandleCreated({
        param($sender, $e)
        try { Set-WptDarkTitleBar -Form $sender } catch {}
    })

    $parent = $script:WPT.UI.Form
    try {
        $result = if ($parent -and -not $parent.IsDisposed) { $form.ShowDialog($parent) }
                  else                                      { $form.ShowDialog() }
    } finally {
        $form.Dispose()
    }
    return $result
}

class WptDialog {
    static [object] Show([string]$message) {
        return (Show-WptDialog -Message $message)
    }
    static [object] Show([string]$message, [string]$title) {
        return (Show-WptDialog -Message $message -Title $title)
    }
    static [object] Show([string]$message, [string]$title, [object]$buttons) {
        return (Show-WptDialog -Message $message -Title $title -Buttons $buttons)
    }
    static [object] Show([string]$message, [string]$title, [object]$buttons, [object]$icon) {
        return (Show-WptDialog -Message $message -Title $title -Buttons $buttons -Icon $icon)
    }
}

Set-WptDpiAware
Initialize-WptTheme
#endregion

#region === DEBUG LOG ===
# Logs land next to the script; mkdir is best-effort (read-only kiosks fall
# back to writing alongside the .ps1 itself).
$global:LogDir = Join-Path $global:ScriptDir "Logs"
try { if (-not (Test-Path $global:LogDir)) { New-Item -Path $global:LogDir -ItemType Directory -Force -EA Stop | Out-Null } } catch { $global:LogDir = $global:ScriptDir }
$global:SessionTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$global:DebugLogPath = Join-Path $global:LogDir "ReportsTool_${env:USERNAME}_$($global:SessionTimestamp).log"
function Write-DebugLog {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $entry = "[$ts] $Message"
    try { Add-Content -Path $global:DebugLogPath -Value $entry -EA SilentlyContinue } catch {}
}
Write-DebugLog "=== ReportsTool v2.14.0 starting ==="
Write-DebugLog "Log file: $($global:DebugLogPath)"
Write-DebugLog "Script dir: $($global:ScriptDir)"
Write-DebugLog "User: $env:USERNAME | Machine: $env:COMPUTERNAME"
Write-DebugLog "PowerShell: $($PSVersionTable.PSVersion)"

# v2.5 - Inherit shared credential from the J.A.N.E.T. launcher if
# present. ReportsTool currently operates only on local CSV/Nessus
# files, so this is a dormant passthrough until a future version
# queries MECM/WSUS directly. JANET.ps1 exposes the DPAPI-encrypted
# file path via $env:JANET_CRED_FILE.
$global:InheritedCred = $null
if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $ic = Import-Clixml -Path $env:JANET_CRED_FILE -ErrorAction Stop
        if ($ic -is [System.Management.Automation.PSCredential]) {
            $global:InheritedCred = $ic
            Write-DebugLog "Inherited credential from J.A.N.E.T. launcher: $($ic.UserName)"
        }
    } catch {
        Write-DebugLog "Failed to import inherited credential: $($_.Exception.Message)"
    }
}
#endregion

#region === COLOR PALETTE (aliased to shared UI kit) ===
# Historical $colors.* key names are preserved so every existing call site
# (~200 references) keeps working. Each alias points at the same Color
# object the shared kit uses, so ReportsTool, WPT, and STIG_Tool render
# identical purple + gold on black.
$__theme = $script:WPT.UI.Theme
$colors = @{
    Background     = $__theme.Background
    Sidebar        = $__theme.Sidebar
    SidebarHover   = $__theme.SurfaceHover
    SidebarActive  = $__theme.SurfaceActive
    TopBar         = $__theme.TitleBar
    Panel          = $__theme.Surface
    PanelLight     = $__theme.PanelLight
    Input          = $__theme.Input
    InputBorder    = $__theme.BorderStrong
    OutputBg       = $__theme.ConsoleBg
    GridBg         = $__theme.GridBgPrimary
    GridHeader     = $__theme.GridHeader
    TextPrimary    = $__theme.TextPrimary
    TextSecondary  = $__theme.TextSecondary
    TextDim        = $__theme.TextMuted
    Accent         = $__theme.Accent1          # primary purple #8C64DC
    AccentHover    = $__theme.Accent1Hover
    Success        = $__theme.Success
    Warning        = $__theme.Warning
    Danger         = $__theme.Danger
    DangerHover    = $__theme.DangerHover
    Orange         = [System.Drawing.Color]::FromArgb(232, 132, 45)   # High-severity tone (no shared alias)
    BrandChrome    = [System.Drawing.Color]::FromArgb( 66, 133, 244)
    BrandEdge      = [System.Drawing.Color]::FromArgb(  0, 120, 212)
    BrandApache    = [System.Drawing.Color]::FromArgb(210,  50,  45)
    BrandOffice    = [System.Drawing.Color]::FromArgb(217,  83,  30)
    Cyan           = $__theme.Cyan
    Console        = $__theme.Accent2          # gold console text
    Gold           = $__theme.Accent2          # #DAB452
    Purple         = $__theme.Accent1          # = primary purple accent
    CardBg         = $__theme.Surface
    CardBorder     = $__theme.Border
}
#endregion

#region === FONTS (aliased to shared UI kit) ===
# Preserve historical $fonts.* keys used across the form code while pointing
# every slot at the shared $script:WPT.UI.Fonts object. Two readouts still
# need custom sizes not present in the shared kit (CardValue 22pt, DashLg
# sized to match) - built inline here.
$__wfonts = $script:WPT.UI.Fonts
$fonts = @{
    Title     = $__wfonts.Title                # 13pt mono bold
    Subtitle  = $__wfonts.Eyebrow              # 9pt mono bold section headers
    NavBtn    = $__wfonts.MonoSm               # 9pt mono
    NavBtnAct = $__wfonts.Btn                  # 9pt mono bold
    Label     = $__wfonts.Body                 # 10pt body
    LabelBold = $__wfonts.BodyStrong
    Button    = $__wfonts.Btn
    Console   = $__wfonts.Mono                 # 10pt mono
    ConsoleSm = $__wfonts.MonoSm
    Small     = $__wfonts.Small
    SmallBold = $__wfonts.SmallB
    Section   = $__wfonts.Eyebrow
    CardTitle = $__wfonts.Btn
    CardValue = New-Object System.Drawing.Font('Cascadia Mono', 22, [System.Drawing.FontStyle]::Bold)
    CardSm    = $__wfonts.Small
    DashLg    = $__wfonts.DisplayLg            # 18pt mono bold
}
#endregion

#region === REMEDIATION PLAN: target-version overrides + helpers ===
# Hardcoded "what version each app should be at" registry. The Remediation
# Plan tab uses these as overrides on top of versions inferred from each
# ACAS finding's `Steps to Remediate` text.
#
# To bump a target when a new release lands: edit a value below and reload
# the tool. Set a value to $null to fall back to ACAS-inferred only.
#
# The Remediation Plan tab classifies every finding into one of these app
# families using the same Categorize-Finding logic as the rest of the tool,
# then computes (Hostname x App) -> (current versions seen, target version,
# severity, plugin IDs) rollups for the per-app cards + grid.
$script:TargetVersionOverrides = @{
    Chrome   = $null   # e.g. '130.0.6723.92'
    Edge     = $null   # e.g. '128.0.2739.42'
    Office   = $null   # e.g. '16.0.18127.20158'  (M365 Apps for Enterprise build)
    Defender = $null   # e.g. '1.413.392.0'
    KB       = $null   # KBs are per-month/per-product; usually leave $null
    Other    = $null
}

# Session-only "what's been pushed" tracker. Hostname|App -> @{ Status; By; Date; Notes }
# Resets on relaunch by design (no on-disk persistence in this version).
$script:RemediationStatus = @{}

# Operator-supplied total device count on the network. Used to render a
# "% of network" stat next to each Remediation Plan card so operators
# can see "324 hosts behind on Chrome = 7.7% of the fleet" instead of
# just a raw number. Persisted to a single-line text file at
# %LOCALAPPDATA%\JANET\reports_network_size.txt so the value survives
# tool relaunches. 0 = not set (no percentage rendered).
$global:NetworkDeviceCount = 0
$script:NetworkSizeFile    = Join-Path $env:LOCALAPPDATA 'JANET\reports_network_size.txt'

function Load-NetworkDeviceCount {
    try {
        if (Test-Path -LiteralPath $script:NetworkSizeFile) {
            $raw = (Get-Content -LiteralPath $script:NetworkSizeFile -Raw -ErrorAction Stop).Trim()
            $n = 0
            if ([int]::TryParse($raw, [ref]$n) -and $n -ge 0) {
                $global:NetworkDeviceCount = $n
            }
        }
    } catch {
        Write-DebugLog "[NET] Failed to load network size: $_"
    }
}

function Save-NetworkDeviceCount {
    try {
        $dir = Split-Path -Parent $script:NetworkSizeFile
        if (-not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -EA Stop)
        }
        Set-Content -LiteralPath $script:NetworkSizeFile -Value ([string]$global:NetworkDeviceCount) -Encoding UTF8 -EA Stop
    } catch {
        Write-DebugLog "[NET] Failed to save network size: $_"
    }
}

Load-NetworkDeviceCount

# Session-only suppression for "common Other vuln" cards once an operator
# marks a whole vuln-group as Pushed. Keyed by PluginID. Resets on relaunch.
$script:OtherVulnPushed = @{}

# Threshold: a vuln in Categorize-Finding's "Other" bucket only gets its own
# dynamic card on the Remediation Plan tab when this many distinct hosts have
# it. Below the threshold, the vuln just contributes to the main Other count.
$script:OtherVulnGroupMinHosts = 10
#endregion

#region === GLOBAL DATA ===
$global:AcasFindings  = [System.Collections.ArrayList]::new()
$global:BaselineScan  = [System.Collections.ArrayList]::new()
$global:ComparisonScan = [System.Collections.ArrayList]::new()
$global:ComparisonResults = [System.Collections.ArrayList]::new()
$global:HostStatus    = @{}
$global:ActiveView    = 'Online'
$global:ActiveTab     = $null
$global:TabPanels     = @{}
$global:NavButtons    = @()

# ===== Weekly Export state =====
# Parsed week blocks from the ACAS_Calculations workbook (two enclaves running
# in parallel — NIPR cols A-L, SIPR cols O-Z). Populated by
# Parse-AcasCalculationsWorkbook; consumed by Refresh-WeeklyExportTab.
$global:AcasCalcWeeks         = [System.Collections.ArrayList]::new()
$global:AcasCalcSourceFile    = $null
$global:AcasCalcActiveEnclave = 'NIPR'

# Scan-name -> category/owner classifier. ORDER MATTERS — first match wins,
# so PMO patterns precede the generic UEs/Servers matchers (otherwise e.g.
# "PMO UE. User Endpoints" would land under UEs instead of the right PMO
# owner). Note the NIPR vs SIPR split for the 1stACOS / AFAS family:
# NIPR's scan name is "PMO UE. User Endpoints" (owned by AFAS) and SIPR's
# is "PMO-1stACOS_UE_VULN" (owned by 1st ACOS) - same scan family, two
# owning org chains, so the rules separate them by scan-name token.
# Operators can rebind this from JANET_Config.json without editing the
# script.
# ===== Dirty 30 Triage state =====
# Parsed hosts (PSCustomObject: Hostname, IP, Score, Crit, High, Med, Low),
# AD lookup results (hashtable keyed by uppercase hostname), and the most
# recent last-logged-on-user probe results.
$global:Dirty30Hosts        = [System.Collections.ArrayList]::new()
$global:Dirty30AdResults    = @{}
$global:Dirty30LastUserMap  = @{}
$global:Dirty30SourceLabel  = $null
$global:Dirty30ActiveFilter = 'All'   # All | Stale | NotFound | <squadron name>

$global:AcasCategoryRules = @(
    # IGNORE bucket first — drops noise scans before they hit any category.
    # Scans tagged Ignore are excluded from week.Scans entirely, so they
    # don't pollute totals, category cards, or exports.
    @{ Pattern = 'ONBoarding|Onboarding|ISE Server|Enterprise_ESXI|VDI |VDI\.|VDI_|Bad Host|Lakenheath-Non-Reportable|Differential Scan'; Category = 'Ignore'; Owner = $null }

    @{ Pattern = 'PMO WEATHER';                                              Category = 'PMO'; Owner = 'Weather' }
    @{ Pattern = 'PMO AFLCMC_ELX|Servers\.Linux-PMO-ELX';                    Category = 'PMO'; Owner = 'AFLCMC / ELX' }
    @{ Pattern = 'PMO AFLCMC_ACAS|Servers\.Linux-PMO ACAS';                  Category = 'PMO'; Owner = 'AFLCMC / ACAS' }
    # SIPR side: scan name contains the literal "1stACOS" token. NIPR side
    # uses "PMO UE. User Endpoints" - same scan family but the org chain on
    # NIPR is AFAS, not 1st ACOS. Two rules so the owner column reflects
    # who actually owns the scan on each enclave (operator request 2026-05-12).
    @{ Pattern = '1stACOS';                                                  Category = 'PMO'; Owner = '1st ACOS' }
    @{ Pattern = 'PMO UE';                                                   Category = 'PMO'; Owner = 'AFAS' }
    @{ Pattern = 'UEs_Vuln|UE\.User Endpts';                                 Category = 'UEs'; Owner = $null }
    @{ Pattern = 'DCs Lakenheath|Server\.Windows|CES_Servers|48 CS Servers|ACAS SCANNERS|Servers\.Windows_Vuln'; Category = 'Servers'; Owner = $null }
    @{ Pattern = 'Infrastructure';                                           Category = 'Infrastructure'; Owner = $null }
    @{ Pattern = 'Printer';                                                  Category = 'Printers';       Owner = $null }
)
#endregion

#region === HELPER FUNCTIONS ===
function New-StyledButton {
    param([string]$Text, [System.Drawing.Point]$Location, [System.Drawing.Size]$Size,
          [System.Drawing.Color]$BgColor, $FgColor = $null,
          [System.Drawing.Font]$Font = $fonts.Button)
    if (-not $FgColor) {
        $lum = (0.299 * $BgColor.R + 0.587 * $BgColor.G + 0.114 * $BgColor.B) / 255.0
        if ($lum -gt 0.55) { $FgColor = [System.Drawing.Color]::FromArgb(12, 9, 3) } else { $FgColor = [System.Drawing.Color]::FromArgb(242, 244, 247) }
    }
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text; $btn.Location = $Location; $btn.Size = $Size
    $btn.BackColor = $BgColor; $btn.ForeColor = $FgColor
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.Font = $Font; $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $r = [Math]::Min(255, $BgColor.R + 30); $g = [Math]::Min(255, $BgColor.G + 30); $b2 = [Math]::Min(255, $BgColor.B + 30)
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($r, $g, $b2)
    $btn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb([Math]::Min(255,$BgColor.R+50), [Math]::Min(255,$BgColor.G+50), [Math]::Min(255,$BgColor.B+50))
    return $btn
}

function New-StyledGrid {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = $Location; $grid.Size = $Size
    $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.BackgroundColor = $colors.GridBg
    $grid.DefaultCellStyle.BackColor = $colors.GridBg
    $grid.DefaultCellStyle.ForeColor = $colors.TextPrimary
    $grid.DefaultCellStyle.SelectionBackColor = $colors.Accent
    $grid.DefaultCellStyle.Font = $fonts.Label
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $colors.GridHeader
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = $colors.Gold
    $grid.ColumnHeadersDefaultCellStyle.Font = $fonts.LabelBold
    $grid.GridColor = $colors.InputBorder; $grid.EnableHeadersVisualStyles = $false
    $grid.BorderStyle = 'None'; $grid.CellBorderStyle = 'SingleHorizontal'
    $grid.RowHeadersVisible = $false; $grid.ReadOnly = $true
    $grid.SelectionMode = 'FullRowSelect'; $grid.Anchor = 'Top,Left,Right,Bottom'
    return $grid
}

function New-OutputBox {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location = $Location; $rtb.Size = $Size; $rtb.ReadOnly = $true
    $rtb.BackColor = $colors.OutputBg; $rtb.ForeColor = $colors.Console
    $rtb.Font = $fonts.Console; $rtb.BorderStyle = 'None'; $rtb.Anchor = 'Top,Left,Right,Bottom'
    return $rtb
}

function Log($t) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    if ($script:statusOutput) {
        $script:statusOutput.AppendText("[$ts] $t`r`n")
        $script:statusOutput.SelectionStart = $script:statusOutput.Text.Length
        $script:statusOutput.ScrollToCaret()
    }
    Write-DebugLog $t
}

function Categorize-Finding {
    param([string]$VulnName, [string]$Solution, [string]$PluginID)
    $combined = "$VulnName $Solution".ToLower()
    if ($combined -match 'chrome|chromium|google chrome')          { return 'Chrome' }
    if ($combined -match 'edge|msedge|microsoft edge')            { return 'Edge' }
    if ($combined -match 'apache|log4j|tomcat|httpd|struts')      { return 'Apache' }
    if ($combined -match 'office|word|excel|outlook|powerpoint|visio|access|onenote|microsoft 365') { return 'Office' }
    if ($combined -match '\bkb\d{6,}\b|cumulative update|security update|servicing stack|\.net framework.*update') { return 'KB Patch' }
    if ($combined -match 'registry|regedit|reg key|group policy|gpo|local policy') { return 'Registry Fix' }
    if ($combined -match 'not a(n)?\s+(microsoft|windows)|third.party|vendor|contact.*vendor|no (patch|fix|update) available|eol|end.of.life|unsupported|adobe|java|firefox|vmware|cisco|oracle|apple') { return 'NOT OUR PATCH' }
    return 'Other'
}

function Parse-Severity {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Medium' }
    switch -Regex ($Value.Trim()) {
        '^4$|^critical'  { return 'Critical' }
        '^3$|^high'      { return 'High' }
        '^2$|^medium'    { return 'Medium' }
        '^1$|^low'       { return 'Low' }
        '^0$|^info|^none' { return 'Info' }
        default          { return $Value }
    }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return $colors.Danger }
        'High'     { return $colors.Orange }
        'Medium'   { return $colors.Warning }
        'Low'      { return $colors.Cyan }
        'Info'     { return $colors.TextDim }
        default    { return $colors.TextSecondary }
    }
}

function Get-StatusColor {
    param([string]$Status)
    switch ($Status) {
        'Patched'       { return $colors.Success }
        'NOT OUR PATCH' { return $colors.Purple }
        'Open'          { return $colors.Danger }
        default         { return $colors.TextSecondary }
    }
}

function Read-CsvRowsSafe {
    # Quote-aware CSV/TSV reader that handles newlines inside quoted fields.
    # Returns @{ Header = @(lowercase column names); Rows = @(@(fields...)) }.
    param([string]$FilePath)
    $result = @{ Header = @(); Rows = @() }
    # Sniff delimiter from the first non-empty physical line
    $delimiter = ","
    $sr = $null
    try {
        $sr = New-Object System.IO.StreamReader($FilePath)
        $firstLine = $sr.ReadLine()
        while ($firstLine -ne $null -and [string]::IsNullOrWhiteSpace($firstLine)) { $firstLine = $sr.ReadLine() }
        if ($firstLine) {
            $tabCount = ([regex]::Matches($firstLine, "`t")).Count
            $commaCount = ([regex]::Matches($firstLine, ',')).Count
            if ($tabCount -gt $commaCount) { $delimiter = "`t" }
        }
    } catch {
        Write-DebugLog "[CSV] Delimiter sniff failed: $_"
        return $result
    } finally {
        if ($sr) { $sr.Dispose() }
    }
    $parser = $null
    try {
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($FilePath)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(@($delimiter))
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        # Header
        if (-not $parser.EndOfData) {
            $hdr = $parser.ReadFields()
            if ($hdr) { $result.Header = @($hdr | ForEach-Object { ($_ -as [string]).Trim().Trim('"').ToLower() }) }
        }
        # Data rows
        $rowList = [System.Collections.ArrayList]::new()
        while (-not $parser.EndOfData) {
            try {
                $fields = $parser.ReadFields()
                if ($fields -and $fields.Count -gt 0) { [void]$rowList.Add(@($fields | ForEach-Object { ($_ -as [string]) })) }
            } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
                Write-DebugLog "[CSV] Malformed line skipped: $($parser.ErrorLineNumber)"
                continue
            }
        }
        $result.Rows = $rowList.ToArray()
    } catch {
        Write-DebugLog "[CSV] TextFieldParser failed: $_"
    } finally {
        if ($parser) { $parser.Close(); $parser.Dispose() }
    }
    return $result
}

function Find-AcasColumn {
    # Returns the first header index whose value matches any of $Patterns.
    param([string[]]$Header, [string[]]$Patterns)
    foreach ($p in $Patterns) {
        for ($i = 0; $i -lt $Header.Count; $i++) {
            if ($Header[$i] -match $p) { return $i }
        }
    }
    return -1
}

function Get-AcasColumnMap {
    param([string[]]$Header)
    # Prefer DNS name > hostname-like > IP as hostname fallback
    $iHost = Find-AcasColumn -Header $Header -Patterns @('^dns\.name$','^dns$','^dns_name$')
    if ($iHost -lt 0) { $iHost = Find-AcasColumn -Header $Header -Patterns @('^host$','^hostname$','^host name$','netbios','asset') }
    if ($iHost -lt 0) { $iHost = Find-AcasColumn -Header $Header -Patterns @('^ip\.address$','^ip address$','^ip$','^ipv4$') }
    $iPlugin = Find-AcasColumn -Header $Header -Patterns @('^plugin$','^plugin\.id$','^plugin id$','^pluginid$','nessus\.id','nessus id')
    $iVuln   = Find-AcasColumn -Header $Header -Patterns @('plugin\.name','plugin name','^name$','^vuln','vulnerability','^title$','synopsis')
    $iSev    = Find-AcasColumn -Header $Header -Patterns @('^severity$','^risk\.factor$','^risk factor$','^risk$','^threat$','^sev$')
    $iSol    = Find-AcasColumn -Header $Header -Patterns @('steps\.to\.remediate','^solution$','^fix$','remediation','^patch$')
    $iCVE    = Find-AcasColumn -Header $Header -Patterns @('^cve$','^cve\.id$','^cve id$')
    return @{ Host = $iHost; Plugin = $iPlugin; Vuln = $iVuln; Sev = $iSev; Sol = $iSol; CVE = $iCVE }
}

function Get-NessusCveList {
    param($ReportItem)
    $cveList = @()
    try {
        $nodes = $ReportItem.SelectNodes("cve")
        if ($nodes) {
            foreach ($cn in $nodes) {
                $v = $cn.InnerText.Trim()
                if ($v -and ($cveList -notcontains $v)) { $cveList += $v }
            }
        }
    } catch {}
    return ($cveList -join ', ')
}

function Read-XmlFileSafe {
    param([string]$FilePath)
    # SECURITY: .nessus files come from operator file-pickers (untrusted source).
    # Default XmlDocument settings can vary across .NET versions on PS 5.1
    # hosts — explicitly disable DTD processing and the external resolver to
    # prevent XXE / external-entity exfil / billion-laughs. Load via a
    # hardened XmlReader rather than LoadXml(string) so the protections apply
    # to the parse, not just to the loaded document's later resolutions.
    $fs = $null; $reader = $null
    try {
        $fs = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver   = $null
        $settings.MaxCharactersFromEntities = 0
        $reader = [System.Xml.XmlReader]::Create($fs, $settings)
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
        return $doc
    } catch {
        Write-DebugLog "[XML] Load failed: $_"
        return $null
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($fs)     { $fs.Dispose() }
    }
}

function Invoke-AsyncPingSweep {
    # Parallel ping sweep using runspaces; safe on PS 5.1. Updates $global:HostStatus in-place.
    param([string[]]$HostNames, [int]$TimeoutMs = 1500, [int]$MaxConcurrent = 32)
    if (-not $HostNames -or $HostNames.Count -eq 0) { return @{ Online = 0; Offline = 0 } }
    $online = 0; $offline = 0
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxConcurrent), $iss, $Host)
    $pool.Open()
    $jobs = [System.Collections.ArrayList]::new()
    try {
        foreach ($h in $HostNames) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($targetHost, $timeoutMs)
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($targetHost, $timeoutMs)
                    if ($reply -and $reply.Status -eq 'Success') { return @{ Host = $targetHost; Online = $true } }
                } catch {}
                return @{ Host = $targetHost; Online = $false }
            })
            [void]$ps.AddArgument($h)
            [void]$ps.AddArgument($TimeoutMs)
            $handle = $ps.BeginInvoke()
            [void]$jobs.Add(@{ PS = $ps; Handle = $handle; Host = $h })
        }
        # No DoEvents during EndInvoke: pumping the message queue mid-sweep
        # lets users click Clear/Import and corrupt $global:HostStatus while
        # workers are still writing into it. UI freezes for the sweep
        # duration (~1.5s * ceil(N/MaxConcurrent)) instead.
        foreach ($j in $jobs) {
            try {
                $res = $j.PS.EndInvoke($j.Handle)
                if ($res -and $res.Count -gt 0) {
                    $r = $res[0]
                    if ($r.Online) { $global:HostStatus[$r.Host] = 'Online'; $online++ }
                    else { $global:HostStatus[$r.Host] = 'Offline'; $offline++ }
                }
            } catch {
                $global:HostStatus[$j.Host] = 'Offline'; $offline++
            } finally {
                try { $j.PS.Dispose() } catch {}
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }
    return @{ Online = $online; Offline = $offline }
}

function Get-AcasHostList {
    # Sorted unique hostnames derived from current findings. Replaces the
    # previous $global:HostList cache (was rebuilt every import anyway).
    return @($global:AcasFindings | Select-Object -ExpandProperty Hostname -Unique | Sort-Object)
}

function Get-AcasFindingIndex {
    # Hostname|PluginID -> finding lookup, built fresh each call. Mark/undo
    # handlers used to do an O(rows*findings) nested loop; this collapses it
    # to O(findings) once + O(rows) lookups.
    $idx = @{}
    foreach ($f in $global:AcasFindings) { $idx["$($f.Hostname)|$($f.PluginID)"] = $f }
    return $idx
}

function Get-RemediationApp {
    # Map a finding's Category onto one of the six Remediation Plan card
    # buckets. Categorize-Finding already does the hard part - this just
    # collapses the categories into the smaller card surface.
    param([Parameter(Mandatory)][string]$Category)
    switch ($Category) {
        'Chrome'        { return 'Chrome' }
        'Edge'          { return 'Edge' }
        'Office'        { return 'Office' }
        'KB Patch'      { return 'KB' }
        'Registry Fix'  { return 'Other' }
        'Apache'        { return 'Other' }   # Apache lives on its own Excel sheet; not "push to latest" shaped.
        'NOT OUR PATCH' { return $null }     # Excluded from the plan entirely.
        default         { return 'Other' }
    }
    # Defender goes through its own classification - find Defender keywords
    # in the vuln name. Done outside the switch in Build-RemediationPlan.
}

function Get-VersionsFromText {
    # Extract every dotted version number ('NN.NN.NN[.NN]') from arbitrary
    # text and return the list, sorted descending by semver. Used to pull
    # the goal version out of the ACAS `Steps to Remediate` field. The
    # sort tolerates 4-segment versions and treats missing segments as 0.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $matches = [regex]::Matches($Text, '\b\d+(?:\.\d+){2,3}\b')
    if ($matches.Count -eq 0) { return @() }
    $list = @()
    foreach ($m in $matches) { if ($list -notcontains $m.Value) { $list += $m.Value } }
    return @($list | Sort-Object -Property @{ Expression = { Convert-VersionForSort $_ } } -Descending)
}

function Convert-VersionForSort {
    # Pad a version string to 4 segments and return as [System.Version] so
    # PowerShell's Sort-Object orders versions correctly (10.0.0 > 9.99.0).
    param([string]$Ver)
    if ([string]::IsNullOrWhiteSpace($Ver)) { return [System.Version]::new(0,0,0,0) }
    $parts = $Ver.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    try { return [System.Version]::new([int]$parts[0], [int]$parts[1], [int]$parts[2], [int]$parts[3]) }
    catch { return [System.Version]::new(0,0,0,0) }
}

function Get-AppFromFinding {
    # Combined classifier: takes a finding object and returns the bucket
    # name + a Defender-aware override (Categorize-Finding doesn't have a
    # Defender bucket; vuln-name-grep bridges that).
    param($Finding)
    $vn = ($Finding.VulnName -as [string]).ToLower()
    if ($vn -match 'defender|microsoft security essentials|antimalware') { return 'Defender' }
    return Get-RemediationApp -Category $Finding.Category
}

function Build-RemediationPlan {
    # Single pass over $global:AcasFindings. Returns @{ Rows = [...]; Summary = @{ Chrome=N; Edge=N; ... } }
    # Each row: @{ Hostname; App; CurrentVersions; TargetVersion; SeverityRank; MaxSeverity; LastObserved; PluginIDs; FindingCount; Status; By; Date; Notes }
    # CurrentVersions is whatever versions appear in any of the findings'
    # Plugin Output / Vuln Name; TargetVersion is override -> highest seen
    # in Steps to Remediate -> $null.
    $bucket = @{}                   # "$Host|$App" -> row hashtable
    $appTargets = @{}               # App -> highest seen target across all findings (pre-override)
    # Other-vuln-group tracking: for any finding that lands in the 'Other'
    # bucket, accumulate per-PluginID stats so the Remediation Plan tab can
    # surface "10+ host" vuln cards under the main Other card.
    $otherByPlugin = @{}            # PluginID -> @{ VulnName; Hosts<HashSet>; Severity; SeverityRank; Targets<List>; Solution; FindingCount }
    foreach ($f in $global:AcasFindings) {
        $app = Get-AppFromFinding -Finding $f
        if (-not $app) { continue }
        $key = "$($f.Hostname)|$app"
        if (-not $bucket.ContainsKey($key)) {
            $bucket[$key] = @{
                Hostname        = $f.Hostname
                App             = $app
                CurrentVersions = New-Object System.Collections.ArrayList
                TargetSeen      = New-Object System.Collections.ArrayList
                MaxSeverity     = 'Info'
                SeverityRank    = 0
                LastObserved    = ''
                PluginIDs       = New-Object System.Collections.ArrayList
                FindingCount    = 0
                Status          = 'Pending'
                By              = ''
                Date            = ''
                Notes           = ''
            }
        }
        $r = $bucket[$key]
        $r.FindingCount++
        if (-not $r.PluginIDs.Contains($f.PluginID)) { [void]$r.PluginIDs.Add($f.PluginID) }
        $sevRank = switch ($f.Severity) { 'Critical'{4} 'High'{3} 'Medium'{2} 'Low'{1} 'Info'{0} default{0} }
        if ($sevRank -gt $r.SeverityRank) { $r.SeverityRank = $sevRank; $r.MaxSeverity = $f.Severity }
        # Pull versions from Steps to Remediate (target) and Plugin Name (current).
        # ACAS plugin output sometimes embeds "Installed version : X.Y.Z" but
        # we don't import that field, so current is best-effort.
        foreach ($v in (Get-VersionsFromText -Text $f.Solution)) {
            if (-not $r.TargetSeen.Contains($v)) { [void]$r.TargetSeen.Add($v) }
            if (-not $appTargets.ContainsKey($app)) { $appTargets[$app] = $v }
            elseif ((Convert-VersionForSort $v) -gt (Convert-VersionForSort $appTargets[$app])) { $appTargets[$app] = $v }
        }
        foreach ($v in (Get-VersionsFromText -Text $f.VulnName)) {
            if (-not $r.CurrentVersions.Contains($v)) { [void]$r.CurrentVersions.Add($v) }
        }
        # Accumulate Other-bucket per-PluginID stats. NOTE: don't use $pid as
        # a local variable name - PowerShell exposes it as a read-only automatic
        # variable for the current process ID and assigning to it throws
        # "Cannot overwrite variable PID because it is read-only or constant".
        if ($app -eq 'Other') {
            $pluginIdKey = ($f.PluginID -as [string])
            if ([string]::IsNullOrWhiteSpace($pluginIdKey)) { continue }
            if (-not $otherByPlugin.ContainsKey($pluginIdKey)) {
                $otherByPlugin[$pluginIdKey] = @{
                    PluginID     = $pluginIdKey
                    VulnName     = ($f.VulnName -as [string])
                    Hosts        = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                    MaxSeverity  = 'Info'
                    SeverityRank = 0
                    TargetSeen   = New-Object System.Collections.ArrayList
                    Solution     = ($f.Solution -as [string])
                    FindingCount = 0
                }
            }
            $g = $otherByPlugin[$pluginIdKey]
            [void]$g.Hosts.Add($f.Hostname)
            $g.FindingCount++
            if ($sevRank -gt $g.SeverityRank) { $g.SeverityRank = $sevRank; $g.MaxSeverity = $f.Severity }
            foreach ($v in (Get-VersionsFromText -Text $f.Solution)) {
                if (-not $g.TargetSeen.Contains($v)) { [void]$g.TargetSeen.Add($v) }
            }
        }
    }
    # Apply override / inferred target to each row, and apply persisted Status.
    $rows = New-Object System.Collections.ArrayList
    foreach ($key in $bucket.Keys) {
        $r = $bucket[$key]
        $override = $script:TargetVersionOverrides[$r.App]
        if ($override) { $r.TargetVersion = $override }
        elseif ($appTargets.ContainsKey($r.App)) { $r.TargetVersion = $appTargets[$r.App] }
        else { $r.TargetVersion = $null }
        if ($script:RemediationStatus.ContainsKey($key)) {
            $s = $script:RemediationStatus[$key]
            $r.Status = $s.Status; $r.By = $s.By; $r.Date = $s.Date; $r.Notes = $s.Notes
        }
        [void]$rows.Add($r)
    }
    # Summary: count of unique hosts behind on each app.
    $summary = @{ Chrome=0; Edge=0; Office=0; Defender=0; KB=0; Other=0 }
    $hostsBy = @{ Chrome=@{}; Edge=@{}; Office=@{}; Defender=@{}; KB=@{}; Other=@{} }
    foreach ($r in $rows) {
        if ($r.Status -eq 'Pushed' -or $r.Status -eq 'Skipped') { continue }
        if (-not $hostsBy[$r.App].ContainsKey($r.Hostname)) {
            $hostsBy[$r.App][$r.Hostname] = $true
            $summary[$r.App]++
        }
    }
    # Build Other-vuln-group cards: PluginIDs with >= $script:OtherVulnGroupMinHosts
    # distinct hosts, minus any already marked Pushed by the operator. Sorted
    # by host count descending so the biggest pushes float to the top.
    $otherGroups = New-Object System.Collections.ArrayList
    foreach ($pluginIdKey in $otherByPlugin.Keys) {
        if ($script:OtherVulnPushed.ContainsKey($pluginIdKey)) { continue }
        $g = $otherByPlugin[$pluginIdKey]
        if ($g.Hosts.Count -lt $script:OtherVulnGroupMinHosts) { continue }
        $tgt = $null
        if ($g.TargetSeen.Count -gt 0) {
            $tgt = ($g.TargetSeen | Sort-Object -Property @{ Expression = { Convert-VersionForSort $_ } } -Descending | Select-Object -First 1)
        }
        [void]$otherGroups.Add(@{
            PluginID      = $g.PluginID
            VulnName      = $g.VulnName
            HostCount     = $g.Hosts.Count
            Hosts         = @($g.Hosts | Sort-Object)
            MaxSeverity   = $g.MaxSeverity
            SeverityRank  = $g.SeverityRank
            TargetVersion = $tgt
            Solution      = $g.Solution
            FindingCount  = $g.FindingCount
        })
    }
    $otherGroupsSorted = @($otherGroups | Sort-Object -Property @{ Expression = { -$_.SeverityRank } }, @{ Expression = { -$_.HostCount } })
    return @{
        Rows        = @($rows | Sort-Object -Property @{ Expression = { -$_.SeverityRank } }, App, Hostname);
        Summary     = $summary;
        OtherGroups = $otherGroupsSorted
    }
}

function Refresh-RemediationPlan {
    # Card-only refresh: rebuild plan, update each card's Target / Count /
    # Severity-breakdown / accent treatment from the current findings, and
    # rebuild the dynamic Other-vuln-group cards.
    if (-not $script:remCards -or $script:remCards.Count -eq 0) { return }
    $script:remPlan = Build-RemediationPlan
    # Keep the hint label in sync with whatever the operator typed.
    if ($script:lblNetSizeHint) {
        $script:lblNetSizeHint.Text = if ($global:NetworkDeviceCount -gt 0) {
            "$($global:NetworkDeviceCount) hosts on network"
        } else {
            "(empty = hide %)"
        }
    }
    foreach ($key in $script:remCards.Keys) {
        $entry = $script:remCards[$key]
        $count = [int]$script:remPlan.Summary[$key]
        $entry.Count.Text = "$count"
        # Per-card "% of network" - hidden unless operator set a network size.
        if ($entry.PctLabel -and $entry.PctSubLabel) {
            if ($global:NetworkDeviceCount -gt 0 -and $count -gt 0) {
                $pct = [Math]::Round(($count / $global:NetworkDeviceCount) * 100, 1)
                $entry.PctLabel.Text = "$pct%"
                $entry.PctSubLabel.Text = "of network"
                $entry.PctLabel.Visible = $true
                $entry.PctSubLabel.Visible = $true
            } else {
                $entry.PctLabel.Text = ""
                $entry.PctSubLabel.Text = ""
                $entry.PctLabel.Visible = $false
                $entry.PctSubLabel.Visible = $false
            }
        }
        $appRows = @($script:remPlan.Rows | Where-Object { $_.App -eq $key })
        # Plan rows are hashtables; -ExpandProperty doesn't traverse keys.
        # Pull TargetVersion via ForEach-Object instead.
        $tgtCandidates = @($appRows | ForEach-Object { $_.TargetVersion } | Where-Object { $_ })
        $tgt = if ($tgtCandidates.Count -gt 0) { $tgtCandidates[0] } else { $null }
        $entry.TargetLabel.Text = if ($tgt) { $tgt } else { '-' }
        $pendingRows = $appRows | Where-Object { $_.Status -ne 'Pushed' -and $_.Status -ne 'Skipped' }
        $crit = @($pendingRows | Where-Object { $_.MaxSeverity -eq 'Critical' }).Count
        $high = @($pendingRows | Where-Object { $_.MaxSeverity -eq 'High' }).Count
        $med  = @($pendingRows | Where-Object { $_.MaxSeverity -eq 'Medium' }).Count
        $low  = @($pendingRows | Where-Object { $_.MaxSeverity -eq 'Low' -or $_.MaxSeverity -eq 'Info' }).Count
        if ($entry.Disabled) {
            $entry.SeverityNote.Text = ""
        } elseif ($count -eq 0) {
            $entry.SeverityNote.Text = "All caught up"
            $entry.SeverityNote.ForeColor = $colors.Success
        } else {
            $parts = @()
            if ($crit -gt 0) { $parts += "$crit Critical" }
            if ($high -gt 0) { $parts += "$high High" }
            if ($med  -gt 0) { $parts += "$med Medium" }
            if ($low  -gt 0) { $parts += "$low Low" }
            $entry.SeverityNote.Text = ($parts -join '  |  ')
            $entry.SeverityNote.ForeColor = $colors.TextSecondary
        }
    }
    Refresh-OtherVulnCards
}

function Refresh-OtherVulnCards {
    # Tear down any previously-rendered dynamic Other-vuln cards, then build
    # a fresh set from $script:remPlan.OtherGroups. Cards land in 3 columns
    # below the main 2x3 grid; AutoScroll on $script:panelRem handles overflow.
    if (-not $script:panelRem) { return }
    if ($script:remOtherCardPanels) {
        foreach ($p in @($script:remOtherCardPanels)) {
            try { $script:panelRem.Controls.Remove($p); $p.Dispose() } catch {}
        }
    }
    $script:remOtherCardPanels = New-Object System.Collections.ArrayList
    $groups = if ($script:remPlan -and $script:remPlan.OtherGroups) { @($script:remPlan.OtherGroups) } else { @() }
    if ($groups.Count -eq 0) {
        $script:lblOtherEmpty.Visible = $true
        return
    }
    $script:lblOtherEmpty.Visible = $false
    $cardW = 380; $cardH = 200; $gapX = 20; $gapY = 22
    $originX = 10
    $originY = $script:remOtherSectionY + 50
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $g = $groups[$i]
        $col = $i % 3; $row = [Math]::Floor($i / 3)
        $cardX = $originX + ($col * ($cardW + $gapX))
        $cardY = $originY + ($row * ($cardH + $gapY))
        $card = New-OtherVulnCard -Group $g -X $cardX -Y $cardY -W $cardW -H $cardH
        $script:panelRem.Controls.Add($card)
        [void]$script:remOtherCardPanels.Add($card)
    }
}

function New-OtherVulnCard {
    # One card per "Other" vuln-group. Title is the vuln name (truncated
    # to fit), big number is host count, four action buttons run the same
    # Copy / Export / Nemesis / Mark Pushed flow scoped to that PluginID.
    param(
        [Parameter(Mandatory)] $Group,
        [int]$X, [int]$Y, [int]$W, [int]$H
    )
    $sevColor = Get-SeverityColor $Group.MaxSeverity
    $card = New-Object System.Windows.Forms.Panel
    $card.Location = [System.Drawing.Point]::new($X, $Y)
    $card.Size     = [System.Drawing.Size]::new($W, $H)
    $card.BackColor = $colors.CardBg
    $card.Tag = $Group.PluginID

    $accent = New-Object System.Windows.Forms.Panel
    $accent.Location = [System.Drawing.Point]::new(0, 0); $accent.Size = [System.Drawing.Size]::new($W, 4)
    $accent.BackColor = $sevColor
    $card.Controls.Add($accent)

    $tt = New-Object System.Windows.Forms.ToolTip
    $tt.SetToolTip($card, "Plugin $($Group.PluginID): $($Group.VulnName)")

    $vnText = ($Group.VulnName -as [string])
    if ($vnText.Length -gt 70) { $vnText = $vnText.Substring(0, 67) + '...' }
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = $vnText; $lblTitle.Location = [System.Drawing.Point]::new(16, 14)
    $lblTitle.Size = [System.Drawing.Size]::new($W - 32, 38); $lblTitle.Font = $fonts.LabelBold; $lblTitle.ForeColor = $colors.TextPrimary
    $card.Controls.Add($lblTitle)
    $tt.SetToolTip($lblTitle, "Plugin $($Group.PluginID): $($Group.VulnName)")

    $lblPid = New-Object System.Windows.Forms.Label
    $lblPid.Text = "Plugin $($Group.PluginID)  -  $($Group.MaxSeverity)"
    $lblPid.Location = [System.Drawing.Point]::new(16, 54)
    $lblPid.AutoSize = $true; $lblPid.Font = $fonts.Small; $lblPid.ForeColor = $sevColor
    $card.Controls.Add($lblPid)

    $lblCount = New-Object System.Windows.Forms.Label
    $lblCount.Text = "$($Group.HostCount)"; $lblCount.Location = [System.Drawing.Point]::new(16, 78)
    $lblCount.AutoSize = $true
    $lblCount.Font = New-Object System.Drawing.Font('Cascadia Mono', 28, [System.Drawing.FontStyle]::Bold)
    $lblCount.ForeColor = $colors.TextPrimary
    $card.Controls.Add($lblCount)

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text = "hosts affected"; $lblHint.Location = [System.Drawing.Point]::new(18, 130)
    $lblHint.AutoSize = $true; $lblHint.Font = $fonts.Small; $lblHint.ForeColor = $colors.TextSecondary
    $card.Controls.Add($lblHint)

    # % of network - same treatment as the main remediation cards. Skipped
    # entirely when the operator hasn't set a network size.
    if ($global:NetworkDeviceCount -gt 0 -and $Group.HostCount -gt 0) {
        $pct = [Math]::Round(($Group.HostCount / $global:NetworkDeviceCount) * 100, 1)
        $lblPct = New-Object System.Windows.Forms.Label
        $lblPct.Text = "$pct%"
        $lblPct.Location = [System.Drawing.Point]::new(110, 84)
        $lblPct.AutoSize = $true
        $lblPct.Font = New-Object System.Drawing.Font('Cascadia Mono', 18, [System.Drawing.FontStyle]::Bold)
        $lblPct.ForeColor = $sevColor
        $card.Controls.Add($lblPct)
        $lblPctSub = New-Object System.Windows.Forms.Label
        $lblPctSub.Text = "of network"
        $lblPctSub.Location = [System.Drawing.Point]::new(115, 116)
        $lblPctSub.AutoSize = $true
        $lblPctSub.Font = $fonts.Small
        $lblPctSub.ForeColor = $colors.TextSecondary
        $card.Controls.Add($lblPctSub)
    }

    if ($Group.TargetVersion) {
        $lblTgt = New-Object System.Windows.Forms.Label
        $lblTgt.Text = "Target: $($Group.TargetVersion)"
        $lblTgt.Location = [System.Drawing.Point]::new(150, 96)
        $lblTgt.AutoSize = $true; $lblTgt.Font = $fonts.Small; $lblTgt.ForeColor = $colors.TextSecondary
        $card.Controls.Add($lblTgt)
    }

    # Capture for closures. NOT named $pid - that's an automatic variable in PowerShell.
    $cardPluginId = [string]$Group.PluginID
    $btnY = $H - 38
    $btnCopy = New-StyledButton -Text "Copy Hosts" -Location ([System.Drawing.Point]::new(16, $btnY)) -Size ([System.Drawing.Size]::new(86, 28)) -BgColor $sevColor
    $btnCopy.Add_Click({ Copy-OtherVulnHosts -PluginID $cardPluginId }.GetNewClosure())
    $card.Controls.Add($btnCopy)
    $btnExp = New-StyledButton -Text "Export CSV" -Location ([System.Drawing.Point]::new(108, $btnY)) -Size ([System.Drawing.Size]::new(88, 28)) -BgColor $colors.PanelLight
    $btnExp.Add_Click({ Export-OtherVulnCsv -PluginID $cardPluginId }.GetNewClosure())
    $card.Controls.Add($btnExp)
    $btnNem = New-StyledButton -Text "Nemesis" -Location ([System.Drawing.Point]::new(202, $btnY)) -Size ([System.Drawing.Size]::new(76, 28)) -BgColor $colors.Purple
    $btnNem.Add_Click({ Open-OtherVulnInNemesis -PluginID $cardPluginId }.GetNewClosure())
    $card.Controls.Add($btnNem)
    $btnPush = New-StyledButton -Text "Mark Pushed" -Location ([System.Drawing.Point]::new(284, $btnY)) -Size ([System.Drawing.Size]::new(82, 28)) -BgColor $colors.Success
    $btnPush.Add_Click({ Mark-OtherVulnPushed -PluginID $cardPluginId }.GetNewClosure())
    $card.Controls.Add($btnPush)

    # Right-click: dismiss without action (just hides this card until the
    # next ACAS import or session restart).
    $menu = New-Object System.Windows.Forms.ContextMenuStrip
    $miCopy = $menu.Items.Add("Copy hosts");      $miCopy.Add_Click({ Copy-OtherVulnHosts -PluginID $cardPluginId }.GetNewClosure())
    $miExp  = $menu.Items.Add("Export CSV");      $miExp.Add_Click({ Export-OtherVulnCsv -PluginID $cardPluginId }.GetNewClosure())
    $miNem  = $menu.Items.Add("Open in Nemesis"); $miNem.Add_Click({ Open-OtherVulnInNemesis -PluginID $cardPluginId }.GetNewClosure())
    [void]$menu.Items.Add('-')
    $miMark = $menu.Items.Add("Mark Pushed");     $miMark.Add_Click({ Mark-OtherVulnPushed -PluginID $cardPluginId }.GetNewClosure())
    $miSkip = $menu.Items.Add("Hide this card");  $miSkip.Add_Click({ $script:OtherVulnPushed[$cardPluginId] = @{ Status = 'Skipped'; Date = (Get-Date).ToString('yyyy-MM-dd HH:mm') }; Refresh-OtherVulnCards }.GetNewClosure())
    $card.ContextMenuStrip = $menu

    return $card
}

function Get-OtherVulnGroup {
    # Look up a vuln-group by PluginID from the most recent plan.
    param([Parameter(Mandatory)][string]$PluginID)
    if (-not $script:remPlan -or -not $script:remPlan.OtherGroups) { return $null }
    return ($script:remPlan.OtherGroups | Where-Object { $_.PluginID -eq $PluginID } | Select-Object -First 1)
}

function Copy-OtherVulnHosts {
    param([Parameter(Mandatory)][string]$PluginID)
    $g = Get-OtherVulnGroup -PluginID $PluginID
    if (-not $g) { return }
    [System.Windows.Forms.Clipboard]::SetText(($g.Hosts -join "`r`n"))
    Log "Copied $($g.Hosts.Count) host(s) for plugin $PluginID to clipboard"
}

function Export-OtherVulnCsv {
    param([Parameter(Mandatory)][string]$PluginID)
    $g = Get-OtherVulnGroup -PluginID $PluginID
    if (-not $g) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "CSV Files|*.csv|All Files|*.*"
    $dlg.FileName = "OtherVuln_${PluginID}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('Hostname,PluginID,VulnName,Severity,TargetVersion')
    $esc = { param($v) if ($null -eq $v) { '' } else { '"' + ($v.ToString() -replace '"','""') + '"' } }
    foreach ($h in $g.Hosts) {
        [void]$lines.Add(((& $esc $h),(& $esc $g.PluginID),(& $esc $g.VulnName),(& $esc $g.MaxSeverity),(& $esc ($g.TargetVersion))) -join ',')
    }
    [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8)
    Log "Exported $($g.Hosts.Count) host(s) for plugin $PluginID to $(Split-Path $dlg.FileName -Leaf)"
}

function Open-OtherVulnInNemesis {
    param([Parameter(Mandatory)][string]$PluginID)
    $g = Get-OtherVulnGroup -PluginID $PluginID
    if (-not $g) { return }
    [System.Windows.Forms.Clipboard]::SetText(($g.Hosts -join "`r`n"))
    $nemesis = $null
    try {
        $candidates = Get-ChildItem -Path $global:ScriptDir -Filter 'ACAS Nemesis Tool_*.ps1' -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending
        if ($candidates) { $nemesis = $candidates[0].FullName }
    } catch {}
    if ($nemesis) {
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $nemesis) -WindowStyle Normal } catch { Log "Failed to launch Nemesis: $_" }
        Log "Sent $($g.Hosts.Count) host(s) for plugin $PluginID to clipboard and launched Nemesis."
        [WptDialog]::Show("Copied $($g.Hosts.Count) hostname(s) to clipboard and launched ACAS Nemesis Tool.`n`nPaste into Nemesis's host textbox to target.", "Open in Nemesis", 'OK', 'Information')
    } else {
        Log "Sent $($g.Hosts.Count) host(s) for plugin $PluginID to clipboard. Nemesis not found in $global:ScriptDir."
        [WptDialog]::Show("Copied $($g.Hosts.Count) hostname(s) to clipboard.`n`nACAS Nemesis Tool wasn't found alongside ReportsTool - launch it manually and paste the host list.", "Open in Nemesis", 'OK', 'Information')
    }
}

function Mark-OtherVulnPushed {
    # Marking Pushed suppresses the card by adding the PluginID to
    # $script:OtherVulnPushed; Build-RemediationPlan filters it out next call.
    param([Parameter(Mandatory)][string]$PluginID)
    $g = Get-OtherVulnGroup -PluginID $PluginID
    if (-not $g) { return }
    $r = Show-PatchedByDateDialog -HeaderText "Mark $($g.HostCount) hosts as Pushed for plugin $PluginID" -Title "Mark Pushed" -ConfirmButtonText "Mark Pushed"
    if (-not $r.OK) { return }
    $script:OtherVulnPushed[$PluginID] = @{ Status = 'Pushed'; By = $r.By; Date = $r.Date; Notes = '' }
    Log "Marked plugin $PluginID ($($g.HostCount) hosts) as Pushed - card hidden until next ACAS import."
    Refresh-RemediationPlan
}

function Get-RemediationRowsForApp {
    # Pending rows (i.e. not Pushed / not Skipped) for one app.
    param([Parameter(Mandatory)][string]$App)
    if (-not $script:remPlan) { $script:remPlan = Build-RemediationPlan }
    return @($script:remPlan.Rows | Where-Object { $_.App -eq $App -and $_.Status -ne 'Pushed' -and $_.Status -ne 'Skipped' })
}

function Get-RemediationRowsForAppAllStatuses {
    # All rows for one app, ignoring status. Used by Mark-RemediationStatus
    # so "Reset to Pending" can clear Pushed/Skipped flags.
    param([Parameter(Mandatory)][string]$App)
    if (-not $script:remPlan) { $script:remPlan = Build-RemediationPlan }
    return @($script:remPlan.Rows | Where-Object { $_.App -eq $App })
}

function Copy-RemediationHosts {
    # Newline-separated hostnames for one app's pending push list -> clipboard.
    # NOTE: plan rows are hashtables, so Select-Object -ExpandProperty doesn't
    # see their keys; have to read .Hostname via ForEach-Object.
    param([Parameter(Mandatory)][string]$App)
    $rows = Get-RemediationRowsForApp -App $App
    if ($rows.Count -eq 0) { [WptDialog]::Show("No hosts behind on $App.", "$App caught up", 'OK', 'Information'); return }
    $hosts = @($rows | ForEach-Object { $_.Hostname } | Sort-Object -Unique)
    if (-not $hosts -or $hosts.Count -eq 0) { [WptDialog]::Show("No hostnames found.", "Nothing to copy", 'OK', 'Information'); return }
    [System.Windows.Forms.Clipboard]::SetText(($hosts -join "`r`n"))
    Log "Copied $($hosts.Count) $App hostname(s) to clipboard"
}

function Export-RemediationCsv {
    # SaveFileDialog -> writes Hostname,App,Current,Target,Severity,Findings,
    # Last Observed,Status,Pushed By,Pushed Date,Notes for the app's pending list.
    param([Parameter(Mandatory)][string]$App)
    $rows = Get-RemediationRowsForApp -App $App
    if ($rows.Count -eq 0) { [WptDialog]::Show("No hosts behind on $App.", "$App caught up", 'OK', 'Information'); return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "CSV Files|*.csv|All Files|*.*"
    $dlg.FileName = "RemediationPlan_${App}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $headers = 'Hostname,App,Current Versions,Target Version,Severity,Finding Count,Last Observed,Status,Pushed By,Pushed Date,Notes'
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add($headers)
    $esc = { param($v) if ($null -eq $v) { '' } else { '"' + ($v.ToString() -replace '"','""') + '"' } }
    foreach ($r in $rows) {
        $cur = ($r.CurrentVersions -join '; ')
        $tgt = if ($r.TargetVersion) { $r.TargetVersion } else { '' }
        [void]$lines.Add(
            ((& $esc $r.Hostname),(& $esc $r.App),(& $esc $cur),(& $esc $tgt),(& $esc $r.MaxSeverity),
             (& $esc $r.FindingCount),(& $esc $r.LastObserved),(& $esc $r.Status),(& $esc $r.By),
             (& $esc $r.Date),(& $esc $r.Notes)) -join ','
        )
    }
    [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8)
    Log "Exported $($rows.Count) $App remediation row(s) to $(Split-Path $dlg.FileName -Leaf)"
}

function Mark-RemediationStatus {
    # Flip Status on every (host, app) row for the named app. -PromptForNotes
    # opens the shared Patched-by-date dialog when marking Pushed.
    param(
        [Parameter(Mandatory)][ValidateSet('Pending','Pushed','Skipped')][string]$Status,
        [Parameter(Mandatory)][string]$App,
        [switch]$PromptForNotes
    )
    $rows = if ($Status -eq 'Pending') { Get-RemediationRowsForAppAllStatuses -App $App } else { Get-RemediationRowsForApp -App $App }
    if ($rows.Count -eq 0) {
        [WptDialog]::Show("No $App rows to update.", "Nothing to mark", 'OK', 'Information')
        return
    }
    $by = $env:USERNAME
    $date = (Get-Date).ToString("yyyy-MM-dd HH:mm")
    $notes = ''
    if ($PromptForNotes -and $Status -eq 'Pushed') {
        $r = Show-PatchedByDateDialog -HeaderText "Mark all $App hosts ($($rows.Count)) as Pushed" -Title "Mark $App Pushed" -ConfirmButtonText "Mark Pushed"
        if (-not $r.OK) { return }
        $by = $r.By; $date = $r.Date
    }
    foreach ($row in $rows) {
        $key = "$($row.Hostname)|$($row.App)"
        if ($Status -eq 'Pending') { $script:RemediationStatus.Remove($key) | Out-Null }
        else { $script:RemediationStatus[$key] = @{ Status = $Status; By = $by; Date = $date; Notes = $notes } }
    }
    Log "Marked $($rows.Count) $App target(s) as $Status"
    Refresh-RemediationPlan
}

function Open-RemediationInNemesis {
    # Copy hostnames to clipboard + best-effort launch a sibling Nemesis script.
    param([Parameter(Mandatory)][string]$App)
    $rows = Get-RemediationRowsForApp -App $App
    if ($rows.Count -eq 0) { [WptDialog]::Show("No hosts behind on $App.", "$App caught up", 'OK', 'Information'); return }
    $hosts = @($rows | ForEach-Object { $_.Hostname } | Sort-Object -Unique)
    if (-not $hosts -or $hosts.Count -eq 0) { [WptDialog]::Show("No hostnames found.", "Nothing to send", 'OK', 'Information'); return }
    [System.Windows.Forms.Clipboard]::SetText(($hosts -join "`r`n"))
    $nemesis = $null
    try {
        $candidates = Get-ChildItem -Path $global:ScriptDir -Filter 'ACAS Nemesis Tool_*.ps1' -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending
        if ($candidates) { $nemesis = $candidates[0].FullName }
    } catch {}
    if ($nemesis) {
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $nemesis) -WindowStyle Normal } catch { Log "Failed to launch Nemesis: $_" }
        Log "Sent $($hosts.Count) $App host(s) to clipboard and launched Nemesis."
        [WptDialog]::Show("Copied $($hosts.Count) hostname(s) to clipboard and launched ACAS Nemesis Tool.`n`nPaste into Nemesis's host textbox to target.", "Open in Nemesis", 'OK', 'Information')
    } else {
        Log "Sent $($hosts.Count) $App host(s) to clipboard. Nemesis not found in $global:ScriptDir."
        [WptDialog]::Show("Copied $($hosts.Count) hostname(s) to clipboard.`n`nACAS Nemesis Tool wasn't found alongside ReportsTool - launch it manually and paste the host list.", "Open in Nemesis", 'OK', 'Information')
    }
}

function Add-MouseWheelForwarding {
    # WinForms trap: a DataGridView nested inside an AutoScroll panel swallows
    # mouse-wheel events even at its own scroll boundary, so the user can
    # scroll the outer panel down past the grid but never wheel back up. Hook
    # the grid's MouseWheel and forward to the nearest AutoScroll ancestor
    # whenever the grid itself is at the boundary in that direction.
    param([Parameter(Mandatory)] $Grid)
    $Grid.Add_MouseWheel({
        param($s, $e)
        $rc = $s.RowCount
        if ($rc -gt 0) {
            $first = $s.FirstDisplayedScrollingRowIndex
            try { $disp = $s.DisplayedRowCount($false) } catch { $disp = 0 }
            $atTop    = ($first -le 0)
            $atBottom = ($first -ge 0 -and ($first + $disp) -ge $rc)
            if (-not $atTop -and $e.Delta -gt 0) { return }
            if (-not $atBottom -and $e.Delta -lt 0) { return }
        }
        $parent = $s.Parent
        while ($parent -and -not $parent.AutoScroll) { $parent = $parent.Parent }
        if ($parent) {
            $cur = $parent.AutoScrollPosition
            $step = if ($e.Delta -gt 0) { -40 } else { 40 }
            $parent.AutoScrollPosition = New-Object System.Drawing.Point((-$cur.X), ((-$cur.Y) + $step))
        }
    }.GetNewClosure())
}

function Refresh-HostDropdown {
    # Repopulates a host-filter combo with '(All Hosts)' + every unique hostname.
    # Used by both the ACAS Import and Patch Cross-Ref tabs.
    param([Parameter(Mandatory)] $ComboBox)
    if (-not $ComboBox) { return }
    $current = $ComboBox.SelectedItem
    $ComboBox.Items.Clear()
    [void]$ComboBox.Items.Add('(All Hosts)')
    foreach ($h in Get-AcasHostList) { [void]$ComboBox.Items.Add($h) }
    if ($current -and $ComboBox.Items.Contains($current)) { $ComboBox.SelectedItem = $current }
    else { $ComboBox.SelectedIndex = 0 }
}

function Refresh-AcasHostDropdown { Refresh-HostDropdown -ComboBox $script:cmbHostFilter }

function Show-WelcomePanel { if ($script:pnlWelcome) { $script:pnlWelcome.Visible = $true; $script:pnlWelcome.BringToFront() } }
function Hide-WelcomePanel { if ($script:pnlWelcome) { $script:pnlWelcome.Visible = $false } }

function Ping-AllHosts {
    $hostArray = Get-AcasHostList
    if ($hostArray.Count -eq 0) { return }
    $count = $hostArray.Count
    Log "Pinging $count hosts (parallel)..."
    Write-DebugLog "[PING] Starting async ping sweep: $count hosts"
    $global:HostStatus.Clear()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-AsyncPingSweep -HostNames $hostArray -TimeoutMs 1500 -MaxConcurrent 32
    $sw.Stop()
    Log "Ping complete: $($result.Online) online, $($result.Offline) offline (in $([Math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
    Write-DebugLog "[PING] Done: online=$($result.Online) offline=$($result.Offline) elapsed=$([Math]::Round($sw.Elapsed.TotalSeconds, 2))s"
    Update-ViewButtons
}

function Update-ViewButtons {
    if (-not $script:btnViewOnline) { return }
    $onlineCount = @($global:HostStatus.Values | Where-Object { $_ -eq 'Online' }).Count
    $offlineCount = @($global:HostStatus.Values | Where-Object { $_ -eq 'Offline' }).Count
    $script:btnViewOnline.Text = "Online ($onlineCount)"
    $script:btnViewOffline.Text = "Offline ($offlineCount)"
    $script:btnViewAll.Text = "All ($((Get-AcasHostList).Count))"
}

function Set-ActiveView {
    param([string]$View)
    $global:ActiveView = $View
    foreach ($btn in @($script:btnViewAll, $script:btnViewOnline, $script:btnViewOffline)) {
        $btn.BackColor = $colors.PanelLight; $btn.ForeColor = $colors.TextSecondary
    }
    switch ($View) {
        'All'     { $script:btnViewAll.BackColor = $colors.Accent; $script:btnViewAll.ForeColor = [System.Drawing.Color]::White }
        'Online'  { $script:btnViewOnline.BackColor = $colors.Success; $script:btnViewOnline.ForeColor = [System.Drawing.Color]::White }
        'Offline' { $script:btnViewOffline.BackColor = $colors.Danger; $script:btnViewOffline.ForeColor = [System.Drawing.Color]::White }
    }
    Refresh-AcasGrid
}

function Get-FilteredFindings {
    $items = $global:AcasFindings
    # Apply online/offline view filter
    if ($global:HostStatus.Count -gt 0 -and $global:ActiveView -ne 'All') {
        $items = $items | Where-Object {
            $hostStat = $global:HostStatus[$_.Hostname]
            if ($global:ActiveView -eq 'Online')  { $hostStat -eq 'Online' }
            elseif ($global:ActiveView -eq 'Offline') { $hostStat -eq 'Offline' }
            else { $true }
        }
    }
    $hostFilter = if ($script:cmbHostFilter -and $script:cmbHostFilter.SelectedItem -and $script:cmbHostFilter.SelectedItem -ne '(All Hosts)') { $script:cmbHostFilter.SelectedItem } else { $null }
    $sevFilter  = if ($script:cmbSevFilter -and $script:cmbSevFilter.SelectedItem -and $script:cmbSevFilter.SelectedItem -ne '(All Severities)') { $script:cmbSevFilter.SelectedItem } else { $null }
    $catFilter  = if ($script:cmbCatFilter -and $script:cmbCatFilter.SelectedItem -and $script:cmbCatFilter.SelectedItem -ne '(All Categories)') { $script:cmbCatFilter.SelectedItem } else { $null }
    $statFilter = if ($script:cmbStatFilter -and $script:cmbStatFilter.SelectedItem -and $script:cmbStatFilter.SelectedItem -ne '(All Statuses)') { $script:cmbStatFilter.SelectedItem } else { $null }
    $searchText = if ($script:txtSearchFilter -and $script:txtSearchFilter.Text.Trim() -ne '') { $script:txtSearchFilter.Text.Trim().ToLower() } else { $null }
    if ($hostFilter) { $items = $items | Where-Object { $_.Hostname -eq $hostFilter } }
    if ($sevFilter)  { $items = $items | Where-Object { $_.Severity -eq $sevFilter } }
    if ($catFilter)  { $items = $items | Where-Object { $_.Category -eq $catFilter } }
    if ($statFilter) { $items = $items | Where-Object { $_.Status -eq $statFilter } }
    if ($searchText) {
        $items = $items | Where-Object {
            $_.VulnName.ToLower().Contains($searchText) -or $_.PluginID.ToLower().Contains($searchText) -or
            $_.Solution.ToLower().Contains($searchText) -or $_.Hostname.ToLower().Contains($searchText)
        }
    }
    return @($items)
}

function Refresh-AcasGrid {
    if (-not $script:gridAcas) { return }
    $items = Get-FilteredFindings
    if ($global:ActiveView -eq 'Offline') { $items = @($items | Sort-Object Hostname, Severity) }
    $script:gridAcas.SuspendLayout()
    try {
        $script:gridAcas.Rows.Clear()
        foreach ($f in $items) {
            $idx = $script:gridAcas.Rows.Add($f.Hostname, $f.PluginID, $f.VulnName, $f.Severity, $f.CVE, $f.Category, $f.Status, $f.Solution)
            $row = $script:gridAcas.Rows[$idx]
            $row.Cells[3].Style.ForeColor = Get-SeverityColor $f.Severity
            $row.Cells[6].Style.ForeColor = Get-StatusColor $f.Status
            if ($f.Category -eq 'NOT OUR PATCH') {
                $row.DefaultCellStyle.ForeColor = $colors.TextDim
                $row.Cells[5].Style.ForeColor = $colors.Purple
            }
        }
    } finally { $script:gridAcas.ResumeLayout() }
    if ($script:lblAcasCount) {
        $viewLabel = if ($global:HostStatus.Count -gt 0 -and $global:ActiveView -ne 'All') { " [$($global:ActiveView)]" } else { "" }
        $script:lblAcasCount.Text = "Showing $($items.Count) of $($global:AcasFindings.Count) findings$viewLabel"
    }
    if ($global:AcasFindings.Count -gt 0) { Hide-WelcomePanel } else { Show-WelcomePanel }
}

function Refresh-Dashboard {
    if (-not $script:dashPanel) { return }
    $autoFixCats = @{ 'Chrome'=$true; 'Edge'=$true; 'Office'=$true; 'KB Patch'=$true; 'Registry Fix'=$true }
    # Single pass — overall totals AND per-host breakdowns in one walk.
    $total = $global:AcasFindings.Count; $patched = 0; $notOurs = 0; $autoFix = 0
    $perHost = @{}   # Hostname -> tally hashtable
    foreach ($f in $global:AcasFindings) {
        $isPat = ($f.Status -eq 'Patched')
        $isNot = ($f.Category -eq 'NOT OUR PATCH')
        if ($isPat) { $patched++ }
        if ($isNot) { $notOurs++ }
        if (-not $isPat -and $autoFixCats.ContainsKey($f.Category)) { $autoFix++ }
        $h = $f.Hostname
        if (-not $perHost.ContainsKey($h)) {
            $perHost[$h] = @{ Total=0; Critical=0; High=0; Medium=0; Low=0; Info=0; Patched=0; NotOurs=0 }
        }
        $t = $perHost[$h]
        $t.Total++
        switch ($f.Severity) {
            'Critical' { $t.Critical++ }
            'High'     { $t.High++ }
            'Medium'   { $t.Medium++ }
            'Low'      { $t.Low++ }
            'Info'     { $t.Info++ }
        }
        if ($isPat) { $t.Patched++ }
        if ($isNot) { $t.NotOurs++ }
    }
    $remaining = $total - $patched - $notOurs
    if ($script:cardTotalVal)     { $script:cardTotalVal.Text     = "$total" }
    if ($script:cardAutoFixVal)   { $script:cardAutoFixVal.Text   = "$autoFix" }
    if ($script:cardPatchedVal)   { $script:cardPatchedVal.Text   = "$patched" }
    if ($script:cardRemainingVal) { $script:cardRemainingVal.Text = "$remaining" }
    if ($script:cardNotOursVal)   { $script:cardNotOursVal.Text   = "$notOurs" }
    $actionable = $total - $notOurs
    $patchRate  = if ($actionable -gt 0) { [Math]::Round(($patched / $actionable) * 100, 1) } else { 0 }
    if ($script:lblPatchRatePct) {
        $script:lblPatchRatePct.Text = "$patchRate%"
        if ($patchRate -ge 90)     { $script:lblPatchRatePct.ForeColor = $colors.Success }
        elseif ($patchRate -ge 50) { $script:lblPatchRatePct.ForeColor = $colors.Warning }
        else                       { $script:lblPatchRatePct.ForeColor = $colors.Danger }
    }
    if ($script:lblPatchRateDetail) { $script:lblPatchRateDetail.Text = "$patched of $actionable actionable findings patched ($notOurs excluded as NOT OUR PATCH)" }
    if ($script:pnlPatchRateFill -and $script:pnlPatchRateBar) {
        $fillWidth = if ($actionable -gt 0) { [Math]::Max(0, [int](($patchRate / 100.0) * $script:pnlPatchRateBar.Width)) } else { 0 }
        $script:pnlPatchRateFill.Width = $fillWidth
        if ($patchRate -ge 90)     { $script:pnlPatchRateFill.BackColor = $colors.Success }
        elseif ($patchRate -ge 50) { $script:pnlPatchRateFill.BackColor = $colors.Warning }
        else                       { $script:pnlPatchRateFill.BackColor = $colors.Danger }
    }
    Refresh-BarChart $script:panelSevBreakdown 'Severity'
    Refresh-BarChart $script:panelCatBreakdown 'Category'
    Refresh-BarChart $script:panelStatBreakdown 'Status'
    if ($script:gridHostSummary) {
        $script:gridHostSummary.SuspendLayout()
        try {
            $script:gridHostSummary.Rows.Clear()
            foreach ($h in ($perHost.Keys | Sort-Object)) {
                $t = $perHost[$h]
                $hOpen = $t.Total - $t.Patched - $t.NotOurs
                $act2  = $t.Total - $t.NotOurs
                $pr    = if ($act2 -gt 0) { [Math]::Round(($t.Patched / $act2) * 100, 0) } else { 100 }
                $idx   = $script:gridHostSummary.Rows.Add($h, $t.Total, $t.Critical, $t.High, $t.Medium, $t.Low, $t.Info, $t.Patched, $hOpen, $t.NotOurs, "$pr%")
                $row   = $script:gridHostSummary.Rows[$idx]
                if ($t.Critical -gt 0) { $row.Cells['Critical'].Style.ForeColor = $colors.Danger }
                if ($t.High     -gt 0) { $row.Cells['High'].Style.ForeColor     = $colors.Orange }
                if ($t.Medium   -gt 0) { $row.Cells['Medium'].Style.ForeColor   = $colors.Warning }
                if ($hOpen      -gt 0) { $row.Cells['Open'].Style.ForeColor     = $colors.Danger }
                if ($t.Patched  -gt 0) { $row.Cells['Patched'].Style.ForeColor  = $colors.Success }
                if ($t.NotOurs  -gt 0) { $row.Cells['Not Ours'].Style.ForeColor = $colors.Purple }
                if ($pr -ge 90)        { $row.Cells['Patch Rate'].Style.ForeColor = $colors.Success }
                elseif ($pr -ge 50)    { $row.Cells['Patch Rate'].Style.ForeColor = $colors.Warning }
                else                   { $row.Cells['Patch Rate'].Style.ForeColor = $colors.Danger }
            }
        } finally { $script:gridHostSummary.ResumeLayout() }
    }
}

function Refresh-BarChart {
    param($panel, [string]$GroupBy)
    if (-not $panel) { return }
    $panel.Controls.Clear()
    if ($global:AcasFindings.Count -eq 0) { return }
    $groups = $global:AcasFindings | Group-Object -Property $GroupBy | Sort-Object Count -Descending
    $maxVal = ($groups | Measure-Object -Property Count -Maximum).Maximum
    if ($maxVal -eq 0) { $maxVal = 1 }
    $y = 5; $barMaxWidth = $panel.Width - 160
    foreach ($g in $groups) {
        $barWidth = [Math]::Max(2, [int]([double]$g.Count / $maxVal * $barMaxWidth))
        $barColor = switch ($g.Name) {
            'Critical'      { $colors.Danger }
            'High'          { $colors.Orange }
            'Medium'        { $colors.Warning }
            'Low'           { $colors.Cyan }
            'Info'          { $colors.TextDim }
            'Chrome'        { $colors.BrandChrome }
            'Edge'          { $colors.BrandEdge }
            'Apache'        { $colors.BrandApache }
            'Office'        { $colors.BrandOffice }
            'KB Patch'      { $colors.Accent }
            'Registry Fix'  { $colors.Purple }
            'NOT OUR PATCH' { $colors.TextDim }
            'Patched'       { $colors.Success }
            'Open'          { $colors.Danger }
            default         { $colors.TextSecondary }
        }
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $g.Name; $lbl.Location = [System.Drawing.Point]::new(5, $y + 2)
        $lbl.Size = [System.Drawing.Size]::new(100, 18); $lbl.ForeColor = $colors.TextSecondary
        $lbl.Font = $fonts.Small; $lbl.TextAlign = 'MiddleRight'
        $panel.Controls.Add($lbl)
        $bar = New-Object System.Windows.Forms.Panel
        $bar.Location = [System.Drawing.Point]::new(110, $y + 2)
        $bar.Size = [System.Drawing.Size]::new($barWidth, 16); $bar.BackColor = $barColor
        $panel.Controls.Add($bar)
        $cntLbl = New-Object System.Windows.Forms.Label
        $cntLbl.Text = "$($g.Count)"; $cntLbl.Location = [System.Drawing.Point]::new(115 + $barWidth, $y + 2)
        $cntLbl.Size = [System.Drawing.Size]::new(45, 18); $cntLbl.ForeColor = $colors.TextPrimary; $cntLbl.Font = $fonts.SmallBold
        $panel.Controls.Add($cntLbl)
        $y += 24
    }
}

function Get-FilteredXrefFindings {
    $items = $global:ComparisonResults
    if ($items.Count -eq 0) { return @() }
    $hostFilter = if ($script:cmbXrefHostFilter -and $script:cmbXrefHostFilter.SelectedItem -and $script:cmbXrefHostFilter.SelectedItem -ne '(All Hosts)') { $script:cmbXrefHostFilter.SelectedItem } else { $null }
    $sevFilter  = if ($script:cmbXrefSevFilter -and $script:cmbXrefSevFilter.SelectedItem -and $script:cmbXrefSevFilter.SelectedItem -ne '(All Severities)') { $script:cmbXrefSevFilter.SelectedItem } else { $null }
    $deltaFilter = if ($script:cmbXrefDeltaFilter -and $script:cmbXrefDeltaFilter.SelectedItem -and $script:cmbXrefDeltaFilter.SelectedItem -ne '(All Changes)') { $script:cmbXrefDeltaFilter.SelectedItem } else { $null }
    $searchText = if ($script:txtXrefSearch -and $script:txtXrefSearch.Text.Trim() -ne '') { $script:txtXrefSearch.Text.Trim().ToLower() } else { $null }
    if ($hostFilter)  { $items = $items | Where-Object { $_.Hostname -eq $hostFilter } }
    if ($sevFilter)   { $items = $items | Where-Object { $_.Severity -eq $sevFilter } }
    if ($deltaFilter) { $items = $items | Where-Object { $_.Delta -eq $deltaFilter } }
    if ($searchText)  { $items = $items | Where-Object { $_.VulnName.ToLower().Contains($searchText) -or $_.PluginID.ToLower().Contains($searchText) -or $_.Hostname.ToLower().Contains($searchText) } }
    return @($items)
}

function Refresh-XrefGrid {
    if (-not $script:gridXref) { return }
    $items = Get-FilteredXrefFindings
    $script:gridXref.SuspendLayout()
    try {
        $script:gridXref.Rows.Clear()
        foreach ($f in $items) {
            $idx = $script:gridXref.Rows.Add($f.Hostname, $f.PluginID, $f.VulnName, $f.Severity, $f.CVE, $f.Category, $f.Delta)
            $row = $script:gridXref.Rows[$idx]
            $row.Cells[3].Style.ForeColor = Get-SeverityColor $f.Severity
            $deltaColor = switch ($f.Delta) { 'REMEDIATED' { $colors.Success } 'STILL OPEN' { $colors.Danger } 'NEW' { $colors.Cyan } default { $colors.TextSecondary } }
            $row.Cells[6].Style.ForeColor = $deltaColor
            $row.Cells[6].Style.Font = $fonts.LabelBold
            if ($f.Delta -eq 'REMEDIATED') { $row.DefaultCellStyle.ForeColor = $colors.Success }
            if ($f.Delta -eq 'NEW') { $row.Cells[5].Style.ForeColor = $colors.Cyan }
        }
    } finally { $script:gridXref.ResumeLayout() }
    # Summary tally: single pass over ComparisonResults instead of three.
    if ($script:lblXrefSummary) {
        $total = $global:ComparisonResults.Count
        if ($total -gt 0) {
            $remediated = 0; $stillOpen = 0; $newFindings = 0
            foreach ($r in $global:ComparisonResults) {
                switch ($r.Delta) {
                    'REMEDIATED' { $remediated++ }
                    'STILL OPEN' { $stillOpen++ }
                    'NEW'        { $newFindings++ }
                }
            }
            $remRate = if (($remediated + $stillOpen) -gt 0) { [Math]::Round(($remediated / ($remediated + $stillOpen)) * 100, 1) } else { 0 }
            $filterNote = if ($items.Count -lt $total) { "  (showing $($items.Count) filtered)" } else { "" }
            $script:lblXrefSummary.Text = "Remediated: $remediated  |  Still Open: $stillOpen  |  New: $newFindings  |  Remediation Rate: $remRate%$filterNote"
        } else {
            $script:lblXrefSummary.Text = "Load baseline and comparison scans, then click Compare to see what changed."
        }
    }
}

function New-AcasFinding {
    param([string]$Hostname,[string]$PluginID,[string]$VulnName,[string]$Severity,[string]$CVE,[string]$Category,[string]$Solution)
    $status = if ($Category -eq 'NOT OUR PATCH') { 'NOT OUR PATCH' } else { 'Open' }
    return [PSCustomObject]@{
        Hostname    = $Hostname
        PluginID    = $PluginID
        VulnName    = $VulnName
        Severity    = $Severity
        CVE         = $CVE
        Category    = $Category
        Status      = $status
        Solution    = $Solution
        PatchedDate = ''
        PatchedBy   = ''
    }
}

function Parse-AcasFile {
    # Unified parser returning fully-populated findings (Status/PatchedDate/PatchedBy included).
    # Handles .nessus XML and CSV/TSV with quoted multi-line fields via TextFieldParser.
    param([string]$FilePath)
    $findings = [System.Collections.ArrayList]::new()

    if ($FilePath -match '\.nessus$') {
        $nessusXml = Read-XmlFileSafe -FilePath $FilePath
        if (-not $nessusXml) { return $findings }
        $reports = $nessusXml.SelectNodes("//Report")
        if (-not $reports -or $reports.Count -eq 0) { $reports = $nessusXml.SelectNodes("//NessusClientData_v2/Report") }
        if (-not $reports) { return $findings }
        foreach ($report in $reports) {
            $reportHosts = $report.SelectNodes("ReportHost"); if (-not $reportHosts) { continue }
            foreach ($rh in $reportHosts) {
                $hostname = $rh.GetAttribute("name")
                $hostProps = $rh.SelectNodes("HostProperties/tag")
                if ($hostProps) {
                    $hostFqdn = $null; $hostIp = $null
                    foreach ($tag in $hostProps) {
                        $tn = $tag.GetAttribute("name")
                        if ($tn -eq "host-fqdn" -and $tag.InnerText.Trim()) { $hostFqdn = $tag.InnerText.Trim() }
                        elseif ($tn -eq "host-ip" -and $tag.InnerText.Trim()) { $hostIp = $tag.InnerText.Trim() }
                    }
                    if ($hostFqdn) { $hostname = $hostFqdn }
                    elseif ([string]::IsNullOrWhiteSpace($hostname) -and $hostIp) { $hostname = $hostIp }
                }
                if ([string]::IsNullOrWhiteSpace($hostname)) { continue }
                $items = $rh.SelectNodes("ReportItem"); if (-not $items) { continue }
                foreach ($item in $items) {
                    $pluginID = $item.GetAttribute("pluginID")
                    if ([string]::IsNullOrWhiteSpace($pluginID) -or $pluginID -eq "0") { continue }
                    $vulnName = $item.GetAttribute("pluginName")
                    if ([string]::IsNullOrWhiteSpace($vulnName)) {
                        $vn = $item.SelectSingleNode("plugin_name")
                        $vulnName = if ($vn) { $vn.InnerText.Trim() } else { "Unknown" }
                    }
                    $severity = "Medium"
                    $riskNode = $item.SelectSingleNode("risk_factor")
                    if ($riskNode -and $riskNode.InnerText.Trim()) { $severity = Parse-Severity $riskNode.InnerText.Trim() }
                    else { $sa = $item.GetAttribute("severity"); if ($sa) { $severity = Parse-Severity $sa } }
                    $solution = ""
                    $solNode = $item.SelectSingleNode("solution")
                    if ($solNode) { $solution = $solNode.InnerText.Trim() }
                    $cveVal = Get-NessusCveList -ReportItem $item
                    $category = Categorize-Finding -VulnName $vulnName -Solution $solution -PluginID $pluginID
                    [void]$findings.Add((New-AcasFinding -Hostname $hostname -PluginID $pluginID -VulnName $vulnName -Severity $severity -CVE $cveVal -Category $category -Solution $solution))
                }
            }
        }
        return $findings
    }

    # CSV/TSV path
    $data = Read-CsvRowsSafe -FilePath $FilePath
    if (-not $data.Header -or $data.Header.Count -eq 0) { Write-DebugLog "[PARSE] Empty header"; return $findings }
    $cols = Get-AcasColumnMap -Header $data.Header
    if ($cols.Host -lt 0 -or $cols.Plugin -lt 0) {
        Write-DebugLog "[PARSE] Missing hostname/plugin columns. Header: $($data.Header -join ',')"
        return $findings
    }
    foreach ($fields in $data.Rows) {
        if (-not $fields -or $fields.Count -le $cols.Host -or $fields.Count -le $cols.Plugin) { continue }
        $hostname = ($fields[$cols.Host] -as [string]).Trim()
        $pluginID = ($fields[$cols.Plugin] -as [string]).Trim()
        if ([string]::IsNullOrWhiteSpace($hostname) -or [string]::IsNullOrWhiteSpace($pluginID)) { continue }
        $vulnName = if ($cols.Vuln -ge 0 -and $fields.Count -gt $cols.Vuln) { ($fields[$cols.Vuln] -as [string]).Trim() } else { "Unknown" }
        $severity = if ($cols.Sev  -ge 0 -and $fields.Count -gt $cols.Sev)  { Parse-Severity ($fields[$cols.Sev] -as [string]) } else { "Medium" }
        $solution = if ($cols.Sol  -ge 0 -and $fields.Count -gt $cols.Sol)  { ($fields[$cols.Sol] -as [string]).Trim() } else { "" }
        $cveVal   = if ($cols.CVE  -ge 0 -and $fields.Count -gt $cols.CVE)  { ($fields[$cols.CVE] -as [string]).Trim() } else { "" }
        $category = Categorize-Finding -VulnName $vulnName -Solution $solution -PluginID $pluginID
        [void]$findings.Add((New-AcasFinding -Hostname $hostname -PluginID $pluginID -VulnName $vulnName -Severity $severity -CVE $cveVal -Category $category -Solution $solution))
    }
    return $findings
}

function Refresh-XrefHostDropdown { Refresh-HostDropdown -ComboBox $script:cmbXrefHostFilter }

function Show-PatchedByDateDialog {
    # Shared "Patched By / Patched Date" prompt used by Mark Patched (single)
    # and Mark All Visible: Patched (batch). Returns @{ OK; By; Date } or
    # @{ OK = $false } on cancel. Caller controls how many findings are
    # affected; this dialog only collects the metadata.
    param(
        [Parameter(Mandatory)][string]$HeaderText,
        [string]$Title = 'Mark as Patched',
        [string]$ConfirmButtonText = 'Mark Patched',
        [int]$Width = 420
    )
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = [System.Drawing.Size]::new($Width, 230)
    $form.StartPosition = 'CenterParent'
    $form.BackColor = $colors.Background; $form.ForeColor = $colors.TextPrimary
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false; $form.MinimizeBox = $false; $form.Font = $fonts.Label
    $form.Add_HandleCreated({ Set-WptDarkTitleBar -Form $form }.GetNewClosure())

    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Top'; $stripe.Height = 3; $stripe.BackColor = $colors.Accent
    $form.Controls.Add($stripe)

    $clientW = $Width - 36   # window chrome
    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text = $HeaderText; $lblHdr.Location = [System.Drawing.Point]::new(15, 18)
    $lblHdr.AutoSize = $true; $lblHdr.Font = $fonts.LabelBold; $lblHdr.ForeColor = $colors.Gold
    $form.Controls.Add($lblHdr)

    $lblBy = New-Object System.Windows.Forms.Label
    $lblBy.Text = 'Patched By:'; $lblBy.Location = [System.Drawing.Point]::new(15, 50)
    $lblBy.AutoSize = $true; $lblBy.Font = $fonts.Label; $lblBy.ForeColor = $colors.TextSecondary
    $form.Controls.Add($lblBy)
    $txtBy = New-Object System.Windows.Forms.TextBox
    $txtBy.Location = [System.Drawing.Point]::new(120, 47)
    $txtBy.Size = [System.Drawing.Size]::new(($clientW - 135), 24)
    $txtBy.BackColor = $colors.Input; $txtBy.ForeColor = $colors.TextPrimary
    $txtBy.Font = $fonts.Console; $txtBy.BorderStyle = 'FixedSingle'; $txtBy.Text = $env:USERNAME
    $form.Controls.Add($txtBy)

    $lblDt = New-Object System.Windows.Forms.Label
    $lblDt.Text = 'Patched Date:'; $lblDt.Location = [System.Drawing.Point]::new(15, 85)
    $lblDt.AutoSize = $true; $lblDt.Font = $fonts.Label; $lblDt.ForeColor = $colors.TextSecondary
    $form.Controls.Add($lblDt)
    $txtDt = New-Object System.Windows.Forms.TextBox
    $txtDt.Location = [System.Drawing.Point]::new(120, 82)
    $txtDt.Size = [System.Drawing.Size]::new(($clientW - 135), 24)
    $txtDt.BackColor = $colors.Input; $txtDt.ForeColor = $colors.TextPrimary
    $txtDt.Font = $fonts.Console; $txtDt.BorderStyle = 'FixedSingle'
    $txtDt.Text = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $form.Controls.Add($txtDt)

    $btnOk = New-StyledButton -Text $ConfirmButtonText -Location ([System.Drawing.Point]::new(120, 125)) -Size ([System.Drawing.Size]::new(140, 32)) -BgColor $colors.Success
    $btnOk.Add_Click({ $form.DialogResult = 'OK'; $form.Close() }.GetNewClosure())
    $form.Controls.Add($btnOk)
    $btnCa = New-StyledButton -Text 'Cancel' -Location ([System.Drawing.Point]::new(270, 125)) -Size ([System.Drawing.Size]::new(100, 32)) -BgColor $colors.PanelLight
    $btnCa.Add_Click({ $form.DialogResult = 'Cancel'; $form.Close() }.GetNewClosure())
    $form.Controls.Add($btnCa)

    $isOk = ($form.ShowDialog() -eq 'OK')
    $by = $txtBy.Text.Trim()
    $dt = $txtDt.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($by)) { $by = $env:USERNAME }
    if ([string]::IsNullOrWhiteSpace($dt)) { $dt = (Get-Date).ToString('yyyy-MM-dd HH:mm') }
    $form.Dispose()
    return @{ OK = $isOk; By = $by; Date = $dt }
}

# ============================================================================
# === WEEKLY EXPORT: parsing + metrics + export helpers ======================
# ============================================================================
# The ACAS_Calculations workbook is a monthly file with two side-by-side
# enclaves on every week block: NIPR (cols A-L, 0-11) and SIPR (cols O-Z,
# 15-25). The headers `RAW SCAN DATA: <range>` mark the top of each block
# per side, and rollup rows (`RAF Lakenheath In House TOTALS?`,
# `MAJCOM TOTALS?`, `AFNS ISN TOTALS?` — last is SIPR only) close it.
# Parsers below treat the two enclaves as independent streams so an empty
# NIPR week doesn't suppress SIPR data and vice versa.

function Read-AcasCsvMatrix {
    # Robust CSV reader that handles quoted fields with embedded commas
    # (the source file uses quoted "2,297"-style numbers). Returns an array
    # of string[] — positional access without inferring headers. Lighter
    # than Import-Csv here because we want columns indexed by number.
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch {
        Write-DebugLog "[WEEKLY] Microsoft.VisualBasic load failed: $_"
        return $null
    }
    $matrix = [System.Collections.ArrayList]::new()
    $parser = $null
    try {
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($FilePath)
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        while (-not $parser.EndOfData) {
            try { [void]$matrix.Add($parser.ReadFields()) }
            catch { [void]$matrix.Add(@()) } # keep row index alignment
        }
    } finally {
        if ($parser) { $parser.Dispose() }
    }
    return $matrix
}

function Get-AcasCellSafe {
    # Out-of-range -> ''; null -> ''. Always returns string.
    param($Row, [int]$Col)
    if ($null -eq $Row -or $Row.Length -le $Col) { return '' }
    $v = $Row[$Col]
    if ($null -eq $v) { return '' }
    return [string]$v
}

function ConvertTo-AcasInt {
    # "2,297" / "320 " / "N/A" / "Discovery" / '' -> int (0 on failure).
    param($Value)
    if ($null -eq $Value) { return 0 }
    $s = ([string]$Value).Trim().Replace(',', '')
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq 'N/A' -or $s -eq 'Discovery') { return 0 }
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }
    return 0
}

function ConvertTo-AcasDouble {
    # "97.54%" / "2.21" / "N/A" -> double (NaN on failure).
    param($Value)
    if ($null -eq $Value) { return [double]::NaN }
    $s = ([string]$Value).Trim().Replace(',', '').Replace('%', '')
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq 'N/A' -or $s -eq 'Discovery') { return [double]::NaN }
    $d = 0.0
    if ([double]::TryParse($s, [ref]$d)) { return $d }
    return [double]::NaN
}

function Get-AcasScanCategory {
    # Apply $global:AcasCategoryRules first-match-wins. Owner is non-null
    # only for PMO rules.
    param([string]$ScanName)
    foreach ($rule in $global:AcasCategoryRules) {
        if ($ScanName -match $rule.Pattern) {
            return @{ Category = $rule.Category; Owner = $rule.Owner }
        }
    }
    return @{ Category = 'Other'; Owner = $null }
}

function Parse-AcasScanRow {
    # Build a scan PSCustomObject off a CSV row at the given enclave column
    # range. Returns $null for rows that are obviously empty so the caller
    # doesn't pollute its scan list. Scans tagged Category=Ignore by
    # $global:AcasCategoryRules are also dropped silently so noise like
    # Onboarding / ESXI / VDI / ISE never appears in any total or export.
    param([Parameter(Mandatory)]$Row, [int]$ColStart, [string]$Name)
    $cat = Get-AcasScanCategory -ScanName $Name
    if ($cat.Category -eq 'Ignore') { return $null }
    $good     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 1))
    $bad      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 2))
    $crit     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 3))
    $high     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 4))
    $med      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 5))
    $low      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 6))
    $totalIps = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 7))
    $limboIps = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 8))
    $vph      = ConvertTo-AcasDouble (Get-AcasCellSafe $Row ($ColStart + 9))
    $arPct    = ConvertTo-AcasDouble (Get-AcasCellSafe $Row ($ColStart + 10))
    $sumAll = $good + $bad + $crit + $high + $med + $low + $totalIps
    if ($sumAll -eq 0 -and [double]::IsNaN($vph)) { return $null }

    return [PSCustomObject]@{
        Name       = $Name
        Good       = $good
        Bad        = $bad
        Crit       = $crit
        High       = $high
        Med        = $med
        Low        = $low
        TotalVulns = $crit + $high + $med + $low
        TotalIps   = $totalIps
        LimboIps   = $limboIps
        Vph        = $vph
        ArPct      = $arPct
        Category   = $cat.Category
        Owner      = $cat.Owner
    }
}

function Get-AcasDateRange {
    # Strip the leading "RAW SCAN DATA:" / dash chrome and trailing
    # whitespace, return just the date range.
    param([string]$HeaderText)
    if ($HeaderText -match 'RAW SCAN DATA:\s*-?\s*(.+?)\s*$') {
        return $Matches[1].Trim().TrimEnd(',').Trim()
    }
    return $HeaderText
}

function Parse-AcasCalculationsWorkbook {
    # Returns an ArrayList of week-block PSCustomObjects (one per enclave
    # per detected header). Empty/header-only weeks are still emitted so
    # the UI can show "no data" placeholders.
    param([string]$FilePath)
    $matrix = Read-AcasCsvMatrix -FilePath $FilePath
    if (-not $matrix -or $matrix.Count -eq 0) { return $null }

    $weeks = [System.Collections.ArrayList]::new()
    $sides = @(
        @{ Enclave = 'NIPR'; ColStart = 0  }
        @{ Enclave = 'SIPR'; ColStart = 15 }
    )

    foreach ($side in $sides) {
        # Locate every header on this enclave's side.
        $headerRows = @()
        for ($i = 0; $i -lt $matrix.Count; $i++) {
            $cell = Get-AcasCellSafe $matrix[$i] $side.ColStart
            if ($cell -match '^RAW SCAN DATA:') { $headerRows += $i }
        }

        for ($h = 0; $h -lt $headerRows.Count; $h++) {
            $startRow = $headerRows[$h]
            $endRow   = if ($h + 1 -lt $headerRows.Count) { $headerRows[$h + 1] - 1 } else { $matrix.Count - 1 }
            $headerText = Get-AcasCellSafe $matrix[$startRow] $side.ColStart

            $week = [PSCustomObject]@{
                Enclave       = $side.Enclave
                HeaderText    = $headerText
                DateRange     = Get-AcasDateRange $headerText
                StartRow      = $startRow
                EndRow        = $endRow
                Scans         = [System.Collections.ArrayList]::new()
                InHouseTotals = $null
                MajcomTotals  = $null
                Stale         = $false
                Warnings      = [System.Collections.ArrayList]::new()
            }

            $inScans = $false
            for ($r = $startRow + 1; $r -le $endRow; $r++) {
                $row = $matrix[$r]
                $name = (Get-AcasCellSafe $row $side.ColStart).Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                if ($name -eq 'BLANK') { continue }
                if ($name -match '^(SCAN NAMES|VULN SCAN)$') { $inScans = $true; continue }
                if ($name -in @('GOOD','BAD','BAD ','CRIT','HIGH','MED','LOW','WVI','RATE','30-D FILTER: CCRI')) { continue }
                if ($name -match '^EXEC\. SUMMARY') { continue }
                if ($name -match '^PMO ULI_GCCS') { continue }

                if ($name -match '^RAF Lakenheath In House TOTALS') {
                    $week.InHouseTotals = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                    continue
                }
                if ($name -match '^MAJCOM TOTALS') {
                    $week.MajcomTotals = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                    continue
                }
                # AFNS ISN row exists on the SIPR side of older workbooks but is
                # being merged into MAJCOM going forward (per operator). Skip
                # silently so it doesn't get parsed as a regular scan.
                if ($name -match '^AFNS ISN TOTALS') { continue }

                $scan = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                if ($scan) { [void]$week.Scans.Add($scan) }
            }

            # Stale-data heuristic: In-House row empty but MAJCOM populated.
            # Surfaces as a UI banner + blocks the export button.
            $ihEmpty = (-not $week.InHouseTotals) -or (
                $week.InHouseTotals.Good -eq 0 -and $week.InHouseTotals.Bad -eq 0 -and
                $week.InHouseTotals.TotalVulns -eq 0)
            $mjHas = $week.MajcomTotals -and (
                $week.MajcomTotals.Good -gt 0 -or $week.MajcomTotals.Bad -gt 0 -or
                $week.MajcomTotals.TotalVulns -gt 0)
            if ($ihEmpty -and $mjHas) {
                $week.Stale = $true
                [void]$week.Warnings.Add("In-House totals empty but MAJCOM row has data - possible carry-over from a previous month.")
            }

            [void]$weeks.Add($week)
        }
    }
    return $weeks
}

function Get-WeeklyCategoryMetrics {
    # Aggregate a week's scans by Category. VPH = host-count-weighted
    # average over rows where Vph != NaN. AR % = recomputed from raw G/B
    # sums (not an average of percentages) - audit-friendly.
    param([Parameter(Mandatory)]$Week)
    $byCat = @{}
    foreach ($scan in $Week.Scans) {
        $cat = $scan.Category
        if (-not $byCat.ContainsKey($cat)) {
            $byCat[$cat] = [PSCustomObject]@{
                Category   = $cat
                Good = 0; Bad = 0; Crit = 0; High = 0; Med = 0; Low = 0
                TotalVulns = 0; TotalIps = 0; LimboIps = 0
                VphNumerator = 0.0; VphHosts = 0; ScanCount = 0
            }
        }
        $b = $byCat[$cat]
        $b.Good += $scan.Good; $b.Bad += $scan.Bad
        $b.Crit += $scan.Crit; $b.High += $scan.High
        $b.Med  += $scan.Med;  $b.Low  += $scan.Low
        $b.TotalVulns += $scan.TotalVulns
        $b.TotalIps   += $scan.TotalIps
        $b.LimboIps   += $scan.LimboIps
        $b.ScanCount  += 1
        if (-not [double]::IsNaN($scan.Vph) -and $scan.TotalIps -gt 0) {
            $b.VphNumerator += $scan.Vph * $scan.TotalIps
            $b.VphHosts     += $scan.TotalIps
        }
    }
    foreach ($key in @($byCat.Keys)) {
        $b = $byCat[$key]
        $vph = if ($b.VphHosts -gt 0) { [Math]::Round($b.VphNumerator / $b.VphHosts, 2) } else { [double]::NaN }
        $ar  = if (($b.Good + $b.Bad) -gt 0) { [Math]::Round(($b.Good / ($b.Good + $b.Bad)) * 100, 2) } else { [double]::NaN }
        Add-Member -InputObject $b -NotePropertyName 'Vph'   -NotePropertyValue $vph -Force
        Add-Member -InputObject $b -NotePropertyName 'ArPct' -NotePropertyValue $ar  -Force
    }
    return $byCat
}

function Get-WeeklyPmoOwnerMetrics {
    # PMO scans grouped by Owner - same VPH/AR methodology as categories.
    param([Parameter(Mandatory)]$Week)
    $byOwner = @{}
    foreach ($scan in $Week.Scans) {
        if ($scan.Category -ne 'PMO') { continue }
        $owner = if ($scan.Owner) { $scan.Owner } else { 'PMO / Unknown' }
        if (-not $byOwner.ContainsKey($owner)) {
            $byOwner[$owner] = [PSCustomObject]@{
                Owner = $owner; Good = 0; Bad = 0
                TotalVulns = 0; TotalIps = 0
                VphNumerator = 0.0; VphHosts = 0; ScanCount = 0
                ScanNames = [System.Collections.ArrayList]::new()
            }
        }
        $o = $byOwner[$owner]
        $o.Good += $scan.Good; $o.Bad += $scan.Bad
        $o.TotalVulns += $scan.TotalVulns
        $o.TotalIps   += $scan.TotalIps
        $o.ScanCount  += 1
        [void]$o.ScanNames.Add($scan.Name)
        if (-not [double]::IsNaN($scan.Vph) -and $scan.TotalIps -gt 0) {
            $o.VphNumerator += $scan.Vph * $scan.TotalIps
            $o.VphHosts     += $scan.TotalIps
        }
    }
    foreach ($key in @($byOwner.Keys)) {
        $o = $byOwner[$key]
        $vph = if ($o.VphHosts -gt 0) { [Math]::Round($o.VphNumerator / $o.VphHosts, 2) } else { [double]::NaN }
        Add-Member -InputObject $o -NotePropertyName 'Vph' -NotePropertyValue $vph -Force
    }
    return $byOwner
}

function Get-WeeklyArWithoutPmo {
    # AR % excluding scans tagged Category=PMO. Used for the "AR w/o PMO"
    # metric tile.
    param([Parameter(Mandatory)]$Week)
    $good = 0; $bad = 0
    foreach ($scan in $Week.Scans) {
        if ($scan.Category -eq 'PMO') { continue }
        $good += $scan.Good; $bad += $scan.Bad
    }
    if (($good + $bad) -eq 0) { return [PSCustomObject]@{ Good = 0; Bad = 0; ArPct = [double]::NaN } }
    return [PSCustomObject]@{
        Good  = $good; Bad = $bad
        ArPct = [Math]::Round(($good / ($good + $bad)) * 100, 2)
    }
}

function Format-AcasNumber {
    # Pretty-print integers with commas; NaN -> "N/A".
    param($Value, [string]$Format = 'N0')
    if ($null -eq $Value) { return 'N/A' }
    if ($Value -is [double] -and [double]::IsNaN($Value)) { return 'N/A' }
    return ([double]$Value).ToString($Format)
}

function Format-AcasPercent {
    param($Value)
    if ($null -eq $Value) { return 'N/A' }
    if ($Value -is [double] -and [double]::IsNaN($Value)) { return 'N/A' }
    return ([double]$Value).ToString('0.00') + '%'
}

function Export-WeeklyToCsv {
    # Single-week CSV: raw scan rows + category roll-up + PMO owner
    # breakdown + the three TOTALS rows + (optional) stale warning. The
    # layout mirrors the source workbook so operators recognize the shape.
    param([Parameter(Mandatory)]$Week, [Parameter(Mandatory)][string]$Path)
    $lines = [System.Collections.ArrayList]::new()
    [void]$lines.Add("# ACAS Weekly Export - $($Week.Enclave) - $($Week.DateRange)")
    [void]$lines.Add("# Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERNAME on $env:COMPUTERNAME")
    if ($Week.Stale) {
        [void]$lines.Add("# WARNING: stale-data heuristic triggered - In-House totals empty but MAJCOM populated. Verify before publishing.")
    }
    [void]$lines.Add('')
    [void]$lines.Add('"SCAN","CATEGORY","OWNER","GOOD","BAD","CRIT","HIGH","MED","LOW","TOTAL VULNS","TOTAL IPS","LIMBO","VPH","AR %"')
    foreach ($s in $Week.Scans) {
        $nm = $s.Name -replace '"','""'
        $vphStr = if ([double]::IsNaN($s.Vph))   { 'N/A' } else { $s.Vph.ToString('0.00') }
        $arStr  = if ([double]::IsNaN($s.ArPct)) { 'N/A' } else { ($s.ArPct.ToString('0.00') + '%') }
        $own = if ($s.Owner) { $s.Owner } else { '' }
        [void]$lines.Add("`"$nm`",`"$($s.Category)`",`"$own`",$($s.Good),$($s.Bad),$($s.Crit),$($s.High),$($s.Med),$($s.Low),$($s.TotalVulns),$($s.TotalIps),$($s.LimboIps),`"$vphStr`",`"$arStr`"")
    }

    [void]$lines.Add('')
    [void]$lines.Add('# === BY CATEGORY ===')
    [void]$lines.Add('"CATEGORY","SCANS","GOOD","BAD","TOTAL VULNS","TOTAL IPS","VPH (WTD)","AR %"')
    $cats = Get-WeeklyCategoryMetrics -Week $Week
    foreach ($k in ($cats.Keys | Sort-Object)) {
        $c = $cats[$k]
        $vphStr = if ([double]::IsNaN($c.Vph))   { 'N/A' } else { $c.Vph.ToString('0.00') }
        $arStr  = if ([double]::IsNaN($c.ArPct)) { 'N/A' } else { ($c.ArPct.ToString('0.00') + '%') }
        [void]$lines.Add("`"$($c.Category)`",$($c.ScanCount),$($c.Good),$($c.Bad),$($c.TotalVulns),$($c.TotalIps),`"$vphStr`",`"$arStr`"")
    }

    [void]$lines.Add('')
    [void]$lines.Add('# === PMO BREAKDOWN BY OWNER ===')
    [void]$lines.Add('"OWNER","SCANS","GOOD","BAD","TOTAL VULNS","TOTAL IPS","VPH (WTD)","SCAN NAMES"')
    $owners = Get-WeeklyPmoOwnerMetrics -Week $Week
    foreach ($k in ($owners.Keys | Sort-Object)) {
        $o = $owners[$k]
        $vphStr = if ([double]::IsNaN($o.Vph)) { 'N/A' } else { $o.Vph.ToString('0.00') }
        $names  = ($o.ScanNames -join ' | ') -replace '"','""'
        [void]$lines.Add("`"$($o.Owner)`",$($o.ScanCount),$($o.Good),$($o.Bad),$($o.TotalVulns),$($o.TotalIps),`"$vphStr`",`"$names`"")
    }

    [void]$lines.Add('')
    [void]$lines.Add('# === ROLLUP ROWS ===')
    [void]$lines.Add('"LABEL","GOOD","BAD","CRIT","HIGH","MED","LOW","TOTAL VULNS","TOTAL IPS","LIMBO","VPH","AR %"')
    foreach ($pair in @(
        @{ Label = 'RAF Lakenheath In House TOTALS'; Row = $Week.InHouseTotals }
        @{ Label = 'MAJCOM TOTALS';                   Row = $Week.MajcomTotals  }
    )) {
        $r = $pair.Row
        if (-not $r) { continue }
        $vphStr = if ([double]::IsNaN($r.Vph))   { 'N/A' } else { $r.Vph.ToString('0.00') }
        $arStr  = if ([double]::IsNaN($r.ArPct)) { 'N/A' } else { ($r.ArPct.ToString('0.00') + '%') }
        [void]$lines.Add("`"$($pair.Label)`",$($r.Good),$($r.Bad),$($r.Crit),$($r.High),$($r.Med),$($r.Low),$($r.TotalVulns),$($r.TotalIps),$($r.LimboIps),`"$vphStr`",`"$arStr`"")
    }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($true))
}

function Get-WeeklySafeFileName {
    # Compose an export filename that includes the enclave and a date stamp
    # so SIPR data never lands in a NIPR-labeled workbook.
    param([Parameter(Mandatory)]$Week, [string]$Extension = 'csv')
    $range = ($Week.DateRange -replace '[^A-Za-z0-9_\- ]', '').Trim() -replace '\s+','_'
    if (-not $range) { $range = 'unknown' }
    return "ACAS_Weekly_${range}_$($Week.Enclave).$Extension"
}

function Render-WeeklyExportHtml {
    # Build a self-contained HTML report that mirrors
    # dev/weekly-export-mockup.html one-for-one: top bar, page subtitle,
    # NIPR/SIPR enclave toggle (JS-driven, scrolls to top on switch),
    # month summary strip, per-week cards (metrics + MAJCOM + category
    # cards + PMO owner roll-up), and stale flags. Both enclave panes are
    # embedded; client-side JS toggles which is visible.
    param([Parameter(Mandatory)][string]$Path)

    # Helper: build one enclave's pane HTML
    $renderPane = {
        param($enclave, $weeks)
        $sb = New-Object System.Text.StringBuilder

        # Month summary aggregates
        $monthGood = 0; $monthBad = 0; $monthVulns = 0
        $monthCrit = 0; $monthHigh = 0; $monthMed = 0; $monthLow = 0
        $monthMajVulns = 0; $bestMajAr = [double]::NaN
        $woGood = 0; $woBad = 0
        foreach ($w in $weeks) {
            if ($w.InHouseTotals) {
                $monthGood  += $w.InHouseTotals.Good
                $monthBad   += $w.InHouseTotals.Bad
                $monthVulns += $w.InHouseTotals.TotalVulns
                $monthCrit  += $w.InHouseTotals.Crit; $monthHigh += $w.InHouseTotals.High
                $monthMed   += $w.InHouseTotals.Med;  $monthLow  += $w.InHouseTotals.Low
            }
            if ($w.MajcomTotals) {
                $monthMajVulns += $w.MajcomTotals.TotalVulns
                if (-not [double]::IsNaN($w.MajcomTotals.ArPct)) {
                    if ([double]::IsNaN($bestMajAr) -or $w.MajcomTotals.ArPct -gt $bestMajAr) {
                        $bestMajAr = $w.MajcomTotals.ArPct
                    }
                }
            }
            $wo = Get-WeeklyArWithoutPmo -Week $w
            $woGood += $wo.Good; $woBad += $wo.Bad
        }
        $monthAr = if (($monthGood + $monthBad) -gt 0) { [Math]::Round(($monthGood / ($monthGood + $monthBad)) * 100, 2) } else { [double]::NaN }
        $woAr    = if (($woGood + $woBad) -gt 0)       { [Math]::Round(($woGood / ($woGood + $woBad)) * 100, 2) } else { [double]::NaN }

        [void]$sb.Append("<div class=`"toolbar`"><span class=`"src`">Enclave: <strong>$enclave</strong> &middot; $($weeks.Count) week(s) parsed</span></div>`n")
        [void]$sb.Append("<div class=`"month-strip`">`n")
        [void]$sb.Append("  <div class=`"month-tile`"><div class=`"label`">$enclave Total Vulns (Month)</div><div class=`"value`">$(Format-AcasNumber $monthVulns)</div><div class=`"sub`">CRIT $monthCrit &middot; HIGH $monthHigh &middot; MED $monthMed &middot; LOW $monthLow</div></div>`n")
        [void]$sb.Append("  <div class=`"month-tile green`"><div class=`"label`">AR % w/ PMO (Month)</div><div class=`"value`">$(Format-AcasPercent $monthAr)</div><div class=`"sub`">G $(Format-AcasNumber $monthGood) &middot; B $(Format-AcasNumber $monthBad)</div></div>`n")
        [void]$sb.Append("  <div class=`"month-tile cyan`"><div class=`"label`">AR % w/o PMO (Month)</div><div class=`"value`">$(Format-AcasPercent $woAr)</div><div class=`"sub`">G $(Format-AcasNumber $woGood) &middot; B $(Format-AcasNumber $woBad)</div></div>`n")
        [void]$sb.Append("  <div class=`"month-tile gold`"><div class=`"label`">MAJCOM Total Vulns</div><div class=`"value`">$(Format-AcasNumber $monthMajVulns)</div><div class=`"sub`">Best week AR: $(Format-AcasPercent $bestMajAr)</div></div>`n")
        [void]$sb.Append("</div>`n")

        if ($weeks.Count -eq 0) {
            [void]$sb.Append("<div class=`"empty-note`">No weeks parsed for $enclave. Load an ACAS_Calculations CSV in the Reports tool to populate.</div>")
            return $sb.ToString()
        }

        # Week cards
        $weekIdx = 0
        foreach ($w in $weeks) {
            $weekIdx++
            $hasData = ($w.Scans.Count -gt 0) -or ($w.InHouseTotals -and $w.InHouseTotals.TotalVulns -gt 0)
            $rangeEsc = ConvertTo-HtmlEscaped $w.DateRange
            $staleTag = if ($w.Stale) { "<span class=`"stale-tag`">STALE - data carry-over detected</span>" } else { '' }

            [void]$sb.Append("<div class=`"week`">`n")
            [void]$sb.Append("  <div class=`"week-head`">`n")
            [void]$sb.Append("    <div class=`"range`">Week $weekIdx &mdash; $rangeEsc</div>`n")
            [void]$sb.Append("    $staleTag`n")
            [void]$sb.Append("  </div>`n")
            [void]$sb.Append("  <div class=`"week-body`">`n")

            if (-not $hasData) {
                $msg = if ($w.Stale) { 'No populated scan rows. MAJCOM row has data - flagged as stale carry-over.' } else { 'No populated scan rows.' }
                [void]$sb.Append("    <div class=`"empty-note`">$msg</div>`n")
                [void]$sb.Append("  </div></div>`n")
                continue
            }

            # Metric tiles
            $arWith = if ($w.InHouseTotals) { $w.InHouseTotals.ArPct } else { [double]::NaN }
            $wo = Get-WeeklyArWithoutPmo -Week $w
            $vphHere = if ($w.InHouseTotals) { $w.InHouseTotals.Vph } else { [double]::NaN }
            $vulnsHere = if ($w.InHouseTotals) { $w.InHouseTotals.TotalVulns } else { 0 }
            $crit = if ($w.InHouseTotals) { $w.InHouseTotals.Crit } else { 0 }
            $high = if ($w.InHouseTotals) { $w.InHouseTotals.High } else { 0 }
            $med  = if ($w.InHouseTotals) { $w.InHouseTotals.Med  } else { 0 }
            $low  = if ($w.InHouseTotals) { $w.InHouseTotals.Low  } else { 0 }
            $good = if ($w.InHouseTotals) { $w.InHouseTotals.Good } else { 0 }
            $badH = if ($w.InHouseTotals) { $w.InHouseTotals.Bad  } else { 0 }

            [void]$sb.Append("    <div class=`"metric-row`">`n")
            [void]$sb.Append("      <div class=`"metric`"><div class=`"lbl`">Total Vulns</div><div class=`"val`">$(Format-AcasNumber $vulnsHere)</div><div class=`"delta`">CRIT $crit &middot; HIGH $high &middot; MED $med &middot; LOW $low</div></div>`n")
            [void]$sb.Append("      <div class=`"metric success`"><div class=`"lbl`">AR % w/ PMO</div><div class=`"val`">$(Format-AcasPercent $arWith)</div><div class=`"delta`">G $good &middot; B $badH</div></div>`n")
            [void]$sb.Append("      <div class=`"metric cyan`"><div class=`"lbl`">AR % w/o PMO</div><div class=`"val`">$(Format-AcasPercent $wo.ArPct)</div><div class=`"delta`">G $($wo.Good) &middot; B $($wo.Bad)</div></div>`n")
            [void]$sb.Append("      <div class=`"metric gold`"><div class=`"lbl`">VPH (Base)</div><div class=`"val`">$(Format-AcasNumber $vphHere -Format '0.00')</div><div class=`"delta`">vulns per host</div></div>`n")
            [void]$sb.Append("    </div>`n")

            # MAJCOM card
            $majVulns = if ($w.MajcomTotals) { $w.MajcomTotals.TotalVulns } else { 0 }
            $majAr = if ($w.MajcomTotals) { $w.MajcomTotals.ArPct } else { [double]::NaN }
            $majArClass = if (-not [double]::IsNaN($majAr) -and $majAr -lt 50) { 'v danger' } else { 'v' }
            $majGood = if ($w.MajcomTotals) { $w.MajcomTotals.Good } else { 0 }
            $majBad  = if ($w.MajcomTotals) { $w.MajcomTotals.Bad  } else { 0 }
            $majCrit = if ($w.MajcomTotals) { $w.MajcomTotals.Crit } else { 0 }
            $majHigh = if ($w.MajcomTotals) { $w.MajcomTotals.High } else { 0 }
            $majMed  = if ($w.MajcomTotals) { $w.MajcomTotals.Med  } else { 0 }
            $majLow  = if ($w.MajcomTotals) { $w.MajcomTotals.Low  } else { 0 }
            # MAJCOM VPH (operator request 2026-05-12): leadership needed the
            # MAJCOM-side vulns-per-host alongside the base figure so the two
            # numbers can be compared at a glance.
            $majVph  = if ($w.MajcomTotals) { $w.MajcomTotals.Vph } else { [double]::NaN }
            $majVphStr = if ([double]::IsNaN($majVph)) { 'N/A' } else { $majVph.ToString('0.00') }
            [void]$sb.Append("    <div class=`"majcom`">`n")
            [void]$sb.Append("      <div class=`"hdr`">MAJCOM Score ($enclave)</div>`n")
            [void]$sb.Append("      <div class=`"row big`"><span class=`"k`">Total Vulns</span><span class=`"v`">$(Format-AcasNumber $majVulns)</span></div>`n")
            [void]$sb.Append("      <div class=`"row big`"><span class=`"k`">AR %</span><span class=`"$majArClass`">$(Format-AcasPercent $majAr)</span></div>`n")
            [void]$sb.Append("      <div class=`"row big`"><span class=`"k`">VPH</span><span class=`"v`">$majVphStr</span></div>`n")
            [void]$sb.Append("      <div class=`"row`"><span class=`"k`">CRIT</span><span class=`"v`">$majCrit</span></div>`n")
            [void]$sb.Append("      <div class=`"row`"><span class=`"k`">HIGH</span><span class=`"v`">$majHigh</span></div>`n")
            [void]$sb.Append("      <div class=`"row`"><span class=`"k`">MED</span><span class=`"v`">$majMed</span></div>`n")
            [void]$sb.Append("      <div class=`"row`"><span class=`"k`">LOW</span><span class=`"v`">$majLow</span></div>`n")
            [void]$sb.Append("      <div class=`"row tiny`">G $majGood &middot; B $majBad</div>`n")
            [void]$sb.Append("    </div>`n")

            # Category cards
            $cats = Get-WeeklyCategoryMetrics -Week $w
            $catLineup = @(
                @{ Name = 'UEs';            Class = 'ue'  }
                @{ Name = 'Servers';        Class = 'srv' }
                @{ Name = 'Infrastructure'; Class = 'inf' }
                @{ Name = 'Printers';       Class = 'prn' }
                @{ Name = 'PMO';            Class = 'pmo' }
            )
            [void]$sb.Append("    <div class=`"cat-section`">`n")
            [void]$sb.Append("      <div class=`"cat-hdr`">VPH &amp; Totals by Category ($enclave)</div>`n")
            [void]$sb.Append("      <div class=`"cat-grid`">`n")
            foreach ($cdef in $catLineup) {
                $cd = $cats[$cdef.Name]
                if ($cd) {
                    $vphStr = if ([double]::IsNaN($cd.Vph)) { 'N/A' } else { $cd.Vph.ToString('0.00') + ' VPH' }
                    $stats = "Vulns $(Format-AcasNumber $cd.TotalVulns) &middot; G $($cd.Good) / B $($cd.Bad)<br/>AR $(Format-AcasPercent $cd.ArPct) &middot; $($cd.ScanCount) scan(s)"
                    [void]$sb.Append("        <div class=`"cat-card $($cdef.Class)`"><div class=`"name`">$($cdef.Name)</div><div class=`"vph`">$vphStr</div><div class=`"stats`">$stats</div></div>`n")
                } else {
                    [void]$sb.Append("        <div class=`"cat-card $($cdef.Class)`" style=`"opacity:0.45;`"><div class=`"name`">$($cdef.Name)</div><div class=`"vph`">&mdash;</div><div class=`"stats`">No scans this week</div></div>`n")
                }
            }
            [void]$sb.Append("      </div>`n")

            # PMO owner roll-up
            $owners = Get-WeeklyPmoOwnerMetrics -Week $w
            [void]$sb.Append("      <div class=`"pmo-owners`">`n")
            [void]$sb.Append("        <div class=`"ow-hdr`">PMO Breakdown by Owner</div>`n")
            if ($owners.Count -eq 0) {
                [void]$sb.Append("        <div class=`"ow-empty`">No PMO scans this week.</div>`n")
            } else {
                foreach ($k in ($owners.Keys | Sort-Object)) {
                    $o = $owners[$k]
                    $vphStr = if ([double]::IsNaN($o.Vph)) { 'N/A' } else { $o.Vph.ToString('0.00') }
                    $names = ConvertTo-HtmlEscaped (($o.ScanNames -join ', '))
                    [void]$sb.Append("        <div class=`"ow-row`"><div class=`"owner`">$(ConvertTo-HtmlEscaped $o.Owner)</div><div class=`"meta`">Scans $($o.ScanCount) &middot; VPH $vphStr &middot; Vulns $($o.TotalVulns) &middot; G $($o.Good) / B $($o.Bad)</div><div class=`"scans`">$names</div></div>`n")
                }
            }
            [void]$sb.Append("      </div>`n")  # /pmo-owners
            [void]$sb.Append("    </div>`n")    # /cat-section

            [void]$sb.Append("  </div></div>`n")  # /week-body /week
        }
        return $sb.ToString()
    }

    $niprWeeks = @($global:AcasCalcWeeks | Where-Object { $_.Enclave -eq 'NIPR' })
    $siprWeeks = @($global:AcasCalcWeeks | Where-Object { $_.Enclave -eq 'SIPR' })
    $niprPane  = & $renderPane 'NIPR' $niprWeeks
    $siprPane  = & $renderPane 'SIPR' $siprWeeks

    $sourceLabel = ConvertTo-HtmlEscaped ($global:AcasCalcSourceFile)
    if (-not $sourceLabel) { $sourceLabel = '(no source loaded)' } else { $sourceLabel = Split-Path $sourceLabel -Leaf }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $operator  = ConvertTo-HtmlEscaped $env:USERNAME
    $machine   = ConvertTo-HtmlEscaped $env:COMPUTERNAME

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET — Weekly ACAS Export — $generated</title>
<style>
  :root {
    --bg:          rgb(8,  8, 12);
    --panel:       rgb(18, 18, 26);
    --panel-light: rgb(30, 28, 40);
    --input:       rgb(22, 22, 30);
    --border:      rgb(38, 34, 52);
    --text:        rgb(240,240,245);
    /* Brightened from rgb(170,168,180) / rgb(120,118,135) so sub-text reads
       cleanly on a projector — same role in the palette, higher luminance. */
    --text-dim:    rgb(210,208,220);
    --text-faint:  rgb(180,178,195);
    --accent:      rgb(140,100,220);
    --success:     rgb( 92,198,120);
    --warning:     rgb(245,180, 70);
    --danger:      rgb(220, 92,100);
    --cyan:        rgb( 80,200,220);
    --gold:        rgb(238,196, 88);
    --orange:      rgb(232,140, 70);
  }
  * { box-sizing: border-box; }
  /* Base size bumped 13 -> 14 so everything that inherits gets a free bump. */
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 60px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 20px; font-weight: 600; color: var(--gold); }
  .topbar .subtitle { color: var(--text-dim); font-size: 13px; }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .topbar .meta .gen { color: var(--cyan); }
  .content { padding: 20px 28px; max-width: 1600px; margin: 0 auto; }
  .page-title { font-size: 26px; color: var(--gold); font-weight: 600; margin: 0 0 4px 0; }
  .page-subtitle { color: var(--text-dim); font-size: 13px; margin: 0 0 14px 0; }
  .source { background: var(--panel); border: 1px solid var(--border); padding: 11px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 14px; font-family: Consolas, monospace; }
  .source .file { color: var(--cyan); font-weight: 600; }
  .enclave-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; background: var(--panel); border: 1px solid var(--border); padding: 10px 14px; border-radius: 3px; }
  .enclave-bar .lbl { color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .enclave-toggle { display: inline-flex; background: var(--input); border: 1px solid var(--border); border-radius: 3px; overflow: hidden; }
  .enclave-toggle button { background: transparent; color: var(--text-dim); border: 0; padding: 9px 24px; cursor: pointer; font-size: 14px; font-weight: 600; min-width: 150px; font-family: inherit; }
  .enclave-toggle button.active.left { background: var(--accent); color: white; }
  .enclave-toggle button.active.right { background: var(--success); color: black; }
  .enclave-pane { display: none; }
  .enclave-pane.active { display: block; }
  .toolbar { background: var(--panel); border: 1px solid var(--border); padding: 11px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 14px; font-family: Consolas, monospace; }
  .toolbar .src strong { color: var(--gold); font-size: 14px; }
  /* === Top-of-page month summary === */
  .month-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
  .month-tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .month-tile.green { border-top-color: var(--success); }
  .month-tile.cyan { border-top-color: var(--cyan); }
  .month-tile.gold { border-top-color: var(--gold); }
  .month-tile .label { font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  /* Headline number - bumped 26 -> 40 for projector visibility. */
  .month-tile .value { font-size: 40px; font-weight: 800; color: var(--text); margin-top: 8px; line-height: 1.1; }
  .month-tile .sub { font-size: 13px; color: var(--text-dim); margin-top: 6px; }
  /* === Per-week cards === */
  .week { background: var(--panel); border: 1px solid var(--border); border-radius: 3px; margin-bottom: 20px; overflow: hidden; }
  .week-head { background: var(--panel-light); padding: 14px 18px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
  .week-head .range { font-size: 16px; font-weight: 600; color: var(--gold); flex: 1; }
  .week-head .stale-tag { font-size: 12px; color: var(--danger); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .week-body { padding: 18px; display: grid; grid-template-columns: 2.4fr 1fr; grid-template-rows: auto auto; gap: 16px; }
  .week-body > .cat-section { grid-column: 1 / -1; }
  .empty-note { grid-column: 1 / -1; color: var(--text-dim); font-style: italic; font-size: 13px; padding: 10px 4px; }
  .metric-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
  .metric { background: var(--input); border: 1px solid var(--border); border-left: 3px solid var(--accent); padding: 14px 16px; border-radius: 2px; }
  .metric.success { border-left-color: var(--success); }
  .metric.cyan { border-left-color: var(--cyan); }
  .metric.gold { border-left-color: var(--gold); }
  .metric .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.4px; font-weight: 600; }
  /* Per-week tile value - bumped 20 -> 32. */
  .metric .val { font-size: 32px; font-weight: 800; color: var(--text); margin-top: 6px; line-height: 1.1; }
  .metric .delta { font-size: 12px; color: var(--text-dim); margin-top: 4px; }
  /* === MAJCOM panel === */
  .majcom { background: var(--input); border: 1px solid var(--border); border-top: 3px solid var(--gold); padding: 14px 16px; border-radius: 2px; }
  .majcom .hdr { font-size: 13px; color: var(--gold); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }
  .majcom .row { display: flex; justify-content: space-between; margin: 7px 0; font-size: 14px; align-items: baseline; }
  .majcom .row .k { color: var(--text-dim); }
  .majcom .row .v { color: var(--text); font-weight: 600; }
  /* MAJCOM Total Vulns / AR % - bumped 17 -> 26. */
  .majcom .row.big .v { font-size: 26px; color: var(--gold); font-weight: 800; }
  .majcom .row.big .v.danger { color: var(--danger); }
  .majcom .row.tiny { font-size: 13px; color: var(--text-dim); margin-top: 10px; }
  /* === Category strip === */
  .cat-section { background: var(--input); border: 1px solid var(--border); border-top: 3px solid var(--cyan); border-radius: 2px; padding: 14px 16px; }
  .cat-hdr { font-size: 13px; color: var(--cyan); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
  .cat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
  .cat-card { background: var(--panel-light); border: 1px solid var(--border); border-radius: 2px; padding: 12px 14px; border-top: 2px solid var(--text-faint); }
  .cat-card.ue { border-top-color: var(--accent); }
  .cat-card.srv { border-top-color: var(--success); }
  .cat-card.inf { border-top-color: var(--cyan); }
  .cat-card.prn { border-top-color: var(--orange); }
  .cat-card.pmo { border-top-color: var(--gold); }
  .cat-card .name { font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
  /* Category VPH - bumped 18 -> 28. */
  .cat-card .vph { font-size: 28px; font-weight: 800; color: var(--text); margin-top: 6px; font-family: Consolas, monospace; line-height: 1.1; }
  .cat-card .stats { font-size: 12px; color: var(--text-dim); margin-top: 6px; line-height: 1.55; }
  /* === PMO owner breakdown === */
  .pmo-owners { margin-top: 12px; background: var(--input); border: 1px dashed var(--border); border-radius: 2px; padding: 10px 14px; }
  .pmo-owners .ow-hdr { font-size: 12px; color: var(--gold); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .pmo-owners .ow-empty { color: var(--text-dim); font-style: italic; font-size: 13px; padding: 4px 0; }
  .pmo-owners .ow-row { display: grid; grid-template-columns: 220px 1fr; gap: 10px; font-size: 13px; padding: 6px 0; align-items: baseline; border-top: 1px solid var(--border); }
  .pmo-owners .ow-row:first-of-type { border-top: 0; }
  .pmo-owners .ow-row .owner { color: var(--gold); font-weight: 700; font-size: 14px; }
  .pmo-owners .ow-row .meta { color: var(--text); font-family: Consolas, monospace; font-size: 12.5px; }
  .pmo-owners .ow-row .scans { grid-column: 1 / -1; color: var(--text-dim); font-size: 11.5px; padding-left: 12px; font-style: italic; }
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="title">J.A.N.E.T &mdash; Weekly ACAS Export</div>
    <div class="subtitle">Joint Administration and Network Execution Toolkit &middot; ReportsTool 2.14.0</div>
  </div>
  <div class="grow"></div>
  <div class="meta">
    <div>Generated <span class="gen">$generated</span></div>
    <div>by $operator on $machine</div>
  </div>
</div>

<div class="content">
  <h1 class="page-title">WEEKLY ACAS EXPORT</h1>
  <p class="page-subtitle">
    Per-week summary &middot; AR % with/without PMO &middot; MAJCOM score &middot; VPH by category (UEs / Servers / Infrastructure / Printers / PMO by owner). Two enclaves: NIPR (left side of workbook) and SIPR (right side, TT scans).
  </p>

  <div class="source">Source: <span class="file">$sourceLabel</span></div>

  <div class="enclave-bar">
    <span class="lbl">Enclave</span>
    <div class="enclave-toggle">
      <button class="active left" data-enclave="nipr">NIPR (In-House)</button>
      <button class="right" data-enclave="sipr">SIPR (TT scans)</button>
    </div>
  </div>

  <div id="pane-nipr" class="enclave-pane active">
$niprPane
  </div>
  <div id="pane-sipr" class="enclave-pane">
$siprPane
  </div>
</div>

<script>
  document.querySelectorAll('.enclave-toggle button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = btn.getAttribute('data-enclave');
      document.querySelectorAll('.enclave-toggle button').forEach(function (b) {
        b.classList.toggle('active', b === btn);
      });
      document.querySelectorAll('.enclave-pane').forEach(function (p) {
        p.classList.toggle('active', p.id === 'pane-' + target);
      });
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  });
</script>

</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($true))
}

function Get-WeeklyReportDir {
    $docs = [System.Environment]::GetFolderPath('MyDocuments')
    $dir = Join-Path $docs 'JANET_Reports\WeeklyExport'
    if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return $dir
}

function Open-WeeklyHtmlReport {
    if ($global:AcasCalcWeeks.Count -eq 0) { return }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Get-WeeklyReportDir
    $out = Join-Path $dir "WeeklyExport_$stamp.html"
    try {
        Render-WeeklyExportHtml -Path $out
        Log "Rendered Weekly HTML report -> $out"
        Start-Process $out
    } catch {
        Log "ERROR rendering Weekly HTML: $_"
        [WptDialog]::Show("HTML render failed: $_", "Error", 'OK', 'Error')
    }
}

# ============================================================================
# === DIRTY 30 TRIAGE: parse + AD lookup + optional last-user probe ==========
# ============================================================================
# Ingests the Tenable Dirty 30 (Top 30 Worst Hosts) report — either pasted
# text, a CSV export, or a hostname list — extracts the host short-names,
# fans them through a batched LDAP query (same OR-filter pattern as
# ADSearchTool BulkComputer), and surfaces squadron + last-logon + stale
# detection. Optional second pass probes each box's registry for the
# LastLoggedOnUser value over remote WMI (off by default — requires
# network reach to every target and is slow).

function Get-Dirty30PdfTextExe {
    # Resolve pdftotext.exe (Poppler / Git-for-Windows). AFNET workstations
    # are imaged with Git for Windows under "C:\Program Files\Git\..." so the
    # binary is usually already there. Falls through to PATH; returns $null
    # if nothing resolves (caller surfaces a clear error to the operator).
    foreach ($candidate in @(
        'C:\Program Files\Git\mingw64\bin\pdftotext.exe',
        'C:\Program Files (x86)\Git\mingw64\bin\pdftotext.exe',
        "$env:LOCALAPPDATA\Programs\Git\mingw64\bin\pdftotext.exe",
        'C:\Tools\pdftotext.exe'
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue)) {
            return $candidate
        }
    }
    $cmd = Get-Command pdftotext.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function ConvertFrom-Dirty30Pdf {
    # Convert a Tenable Dirty 30 PDF to text. If pdftotext.exe is present
    # we shell out for clean -layout output. If not (typical AFNET case),
    # we return $null and the caller routes the operator to the paste
    # workflow with friendly instructions - no scary "ERROR" dialog.
    param([Parameter(Mandatory)][string]$PdfPath)

    $exe = Get-Dirty30PdfTextExe
    if (-not $exe) {
        # AFNET-friendly fallback path: show a clear how-to dialog, then
        # let the operator copy from their PDF viewer and paste.
        $msg = "PDF auto-parsing isn't available on this machine (pdftotext.exe not found).`n`n" +
               "Easy workaround: copy the text out of the PDF yourself:`n`n" +
               "  1. Open the PDF in Adobe Reader / Edge / Chrome`n" +
               "  2. Press Ctrl+A to select all`n" +
               "  3. Press Ctrl+C to copy`n" +
               "  4. Come back here and click `"Paste from Clipboard`"`n`n" +
               "The parser handles whatever the viewer copies — wrapped lines, " +
               "split columns, missing LOW counts, all of it."
        [WptDialog]::Show($msg, "Paste the PDF text instead", 'OK', 'Information')
        Log "pdftotext.exe not found - prompted operator to paste from PDF viewer"
        return $null
    }
    $tmp = Join-Path $env:TEMP "janet_d30_$([guid]::NewGuid().ToString('N')).txt"
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList @('-layout', $PdfPath, $tmp) -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Log "WARN: pdftotext exit code $($proc.ExitCode); paste the PDF text instead"
            return $null
        }
        if (-not (Test-Path -LiteralPath $tmp)) {
            Log "WARN: pdftotext produced no output file; paste the PDF text instead"
            return $null
        }
        $text = Get-Content -LiteralPath $tmp -Raw
        return $text
    } catch {
        Log "WARN: pdftotext invocation failed ($_); paste the PDF text instead"
        return $null
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# --- Dirty 30 severity corrector ------------------------------------------
# Tenable "Top Worst Hosts" renders the Crit/High/Med/Low breakdown as a
# stacked bar. When a segment is narrow, pdftotext glues its label onto the
# next ("2"+"19" -> "219") and drops zero-count segments, so a naive
# left-to-right read inflates Critical (the "hundreds of vulns" bug) or, when
# only two numbers survive, fails to parse. The Score column extracts cleanly
# and for this report satisfies  Score = 10*Crit + 10*High + 4*Med + 1*Low;
# Resolve-Dirty30Severities uses that invariant to recover the true split.

function Get-D30IntSplits {
    # Every way to cut a digit-string into >=1 positive-integer pieces (no
    # leading-zero pieces). Returns an ArrayList of int[].
    param([string]$Digits)
    $out = New-Object System.Collections.ArrayList
    $n = $Digits.Length
    if ($n -eq 0) { return ,$out }
    $gaps   = $n - 1
    $combos = [int][math]::Pow(2, $gaps)
    for ($mask = 0; $mask -lt $combos; $mask++) {
        $pieces = New-Object System.Collections.ArrayList
        $cur = [string]$Digits[0]
        for ($g = 0; $g -lt $gaps; $g++) {
            if ((($mask -shr $g) -band 1) -eq 1) { [void]$pieces.Add($cur); $cur = '' }
            $cur = $cur + $Digits[$g + 1]
        }
        [void]$pieces.Add($cur)
        $ok = $true
        foreach ($p in $pieces) {
            if ($p.Length -eq 0) { $ok = $false; break }
            if ($p.Length -gt 1 -and $p[0] -eq '0') { $ok = $false; break }
        }
        if ($ok) {
            $ints = New-Object System.Collections.ArrayList
            foreach ($p in $pieces) { [void]$ints.Add([int]$p) }
            [void]$out.Add($ints.ToArray())
        }
    }
    return ,$out
}

function Get-D30SlotCombos {
    # Choose $J severity-slot indices from {0=Crit,1=High,2=Med,3=Low} in
    # strictly increasing order (models Tenable omitting zero-count segments
    # while preserving severity order). Returns an ArrayList of int[].
    param([int]$J)
    $res = New-Object System.Collections.ArrayList
    for ($a = 0; $a -lt 4; $a++) {
        if ($J -eq 1) { [void]$res.Add(@($a)); continue }
        for ($b = $a + 1; $b -lt 4; $b++) {
            if ($J -eq 2) { [void]$res.Add(@($a, $b)); continue }
            for ($c = $b + 1; $c -lt 4; $c++) {
                if ($J -eq 3) { [void]$res.Add(@($a, $b, $c)); continue }
                for ($d = $c + 1; $d -lt 4; $d++) {
                    if ($J -eq 4) { [void]$res.Add(@($a, $b, $c, $d)) }
                }
            }
        }
    }
    return ,$res
}

function Resolve-Dirty30Severities {
    # Recover true Crit/High/Med/Low from a Tenable bar that pdftotext glued
    # ("2"+"19" -> "219") or zero-collapsed, using the clean Score column and
    # the report invariant  Score = 10*Crit + 10*High + 4*Med + 1*Low.
    # Returns @{ Crit; High; Med; Low; Confidence } where Confidence is:
    #   asis       - naive read already matched the Score (untouched)
    #   corrected  - exactly one score-consistent reading found
    #   ambiguous  - several score-consistent readings (Crit-vs-High share
    #                weight 10 so Score can't split them); best guess returned,
    #                caller should flag for manual verification
    #   unresolved - no score-consistent reading; naive read returned as-is
    param([int]$Score, [string[]]$BarTokens)

    $nv = @(0, 0, 0, 0)
    $cap = [math]::Min(4, $BarTokens.Count)
    for ($i = 0; $i -lt $cap; $i++) {
        $t = 0; [void][int]::TryParse(($BarTokens[$i] -replace '[^\d]', ''), [ref]$t); $nv[$i] = $t
    }
    $naive = [PSCustomObject]@{ Crit = $nv[0]; High = $nv[1]; Med = $nv[2]; Low = $nv[3]; Confidence = 'asis' }

    if ($Score -le 0) { return $naive }
    $naiveSum = $nv[0]*10 + $nv[1]*10 + $nv[2]*4 + $nv[3]
    if ($naiveSum -eq $Score -and $BarTokens.Count -le 4) { return $naive }

    $seqs = New-Object System.Collections.ArrayList
    [void]$seqs.Add(@())
    foreach ($tok in $BarTokens) {
        $digits = ($tok -replace '[^\d]', '')
        if (-not $digits) { continue }
        $splits = Get-D30IntSplits $digits
        $next = New-Object System.Collections.ArrayList
        foreach ($partial in $seqs) {
            foreach ($pieces in $splits) { [void]$next.Add( @($partial + $pieces) ) }
        }
        $seqs = $next
    }

    $matches = New-Object System.Collections.ArrayList
    foreach ($seq in $seqs) {
        $J = @($seq).Count
        if ($J -lt 1 -or $J -gt 4) { continue }
        foreach ($combo in (Get-D30SlotCombos $J)) {
            $slots = @(0, 0, 0, 0)
            for ($k = 0; $k -lt $J; $k++) { $slots[$combo[$k]] = $seq[$k] }
            $sum = $slots[0]*10 + $slots[1]*10 + $slots[2]*4 + $slots[3]
            if ($sum -eq $Score) {
                $nSplit   = $J - $BarTokens.Count
                $leadOmit = $combo[0]
                $cost = $nSplit*1000 + $leadOmit*100 + $slots[0]
                [void]$matches.Add([PSCustomObject]@{
                    C = $slots[0]; H = $slots[1]; M = $slots[2]; L = $slots[3]
                    Cost = $cost; Key = ('{0}/{1}/{2}/{3}' -f $slots[0],$slots[1],$slots[2],$slots[3])
                })
            }
        }
    }
    if ($matches.Count -eq 0) {
        return [PSCustomObject]@{ Crit = $nv[0]; High = $nv[1]; Med = $nv[2]; Low = $nv[3]; Confidence = 'unresolved' }
    }
    $distinct = $matches | Group-Object Key | ForEach-Object { $_.Group[0] }
    $best = $distinct | Sort-Object Cost | Select-Object -First 1
    $conf = if (@($distinct).Count -eq 1) { 'corrected' } else { 'ambiguous' }
    return [PSCustomObject]@{ Crit = $best.C; High = $best.H; Med = $best.M; Low = $best.L; Confidence = $conf }
}

function Parse-Dirty30Input {
    # Auto-detect input format and extract hostnames. Returns ArrayList of
    # PSCustomObject (Hostname, IP, Score, Crit, High, Med, Low, VulnConfidence).
    # De-dupes by uppercase hostname. Order preserved (highest-score-first when
    # the source is a Tenable PDF with rows sorted by score). Bar counts route
    # through Resolve-Dirty30Severities to undo pdftotext digit-gluing.
    #
    # Recognized shapes:
    #   - CSV with "NetBIOS Name" or "Hostname" / "DNS Name" / "Score" columns
    #   - Tenable PDF pasted text: "AREA52.AFNOAPPS.USAF.MIL\MSEKT-927JYX2"
    #     and "msekt-927jyx2.area52.afnoapps.usaf.mil"
    #   - Plain one-host-per-line list
    param([Parameter(Mandatory)][string]$Text)

    $hosts = [System.Collections.ArrayList]::new()
    $seen  = @{}

    # --- Try CSV first (must have a header row and comma delimiters) ---
    $firstLine = ($Text -split "`r?`n", 2)[0]
    $looksCsv  = ($firstLine -match ',') -and ($firstLine -match '(?i)host|netbios|dns|name|score|ip')
    if ($looksCsv) {
        try {
            $rows = $Text | ConvertFrom-Csv
            foreach ($row in $rows) {
                $hostname = ''; $ip = ''; $score = 0
                $crit = 0; $high = 0; $med = 0; $low = 0
                foreach ($p in $row.PSObject.Properties.Name) {
                    $v = "$($row.$p)".Trim()
                    if (-not $v) { continue }
                    if (-not $hostname -and $p -match '(?i)netbios') {
                        $hostname = (($v -split '\\')[-1]).Trim()
                    } elseif (-not $hostname -and $p -match '(?i)^(hostname|host|computer)$') {
                        $hostname = (($v -split '\\')[-1] -split '\.')[0].Trim()
                    } elseif (-not $hostname -and $p -match '(?i)^dns') {
                        $hostname = ($v -split '\.')[0].Trim()
                    } elseif ($p -match '(?i)^ip') {
                        $ip = $v
                    } elseif ($p -match '(?i)^score$') {
                        $n = 0; if ([int]::TryParse(($v -replace ',',''), [ref]$n)) { $score = $n }
                    } elseif ($p -match '(?i)^crit') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $crit = $n }
                    } elseif ($p -match '(?i)^high') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $high = $n }
                    } elseif ($p -match '(?i)^med') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $med = $n }
                    } elseif ($p -match '(?i)^low') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $low = $n }
                    }
                }
                if ($hostname) {
                    $u = $hostname.ToUpper()
                    if (-not $seen.ContainsKey($u)) {
                        $seen[$u] = $true
                        [void]$hosts.Add([PSCustomObject]@{
                            Hostname = $u; IP = $ip; Score = $score
                            Crit = $crit; High = $high; Med = $med; Low = $low
                            VulnConfidence = 'asis'
                        })
                    }
                }
            }
        } catch {
            Write-DebugLog "[D30] CSV parse failed: $_"
        }
    }

    # --- Fallback: block-based parser for PDF/copy-paste text ---
    if ($hosts.Count -eq 0) {
        # Exclude domain-prefix words that the regex would otherwise match
        # against (e.g. "area52.afnoapps.usaf.mil" would otherwise yield
        # "AREA52" as a host).
        $domainPrefixes = @{
            'AREA52'     = $true; 'AFNOAPPS' = $true; 'USAF' = $true
            'AF'         = $true; 'MIL'       = $true; 'ELX'  = $true
            'LAKENHEATH' = $true; 'UNKNOWN'   = $true
        }

        # === Block-based extraction (handles Adobe Reader / browser PDF
        #     viewer Ctrl+A Ctrl+C as well as pdftotext output) ===
        # Walk the text, treat each IPv4-only line as the start of a host
        # record. Everything between two IPs is the record's "block". Within
        # the block: strip OS/CPE noise lines, concatenate the rest, then
        # regex-extract the hostname from the concatenated string. This
        # survives the nastier Tenable wrapping patterns - "52MSEKW3-" /
        # "AFAS03\52MSEKW" / "3-AFAS03" across three lines, DNS labels
        # split on a period, NetBIOS column wrapping across the backslash,
        # etc.
        $allLines = $Text -split "`r?`n"
        $ipPositions = @()
        for ($i = 0; $i -lt $allLines.Count; $i++) {
            if ($allLines[$i] -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b') {
                $ipPositions += $i
            }
        }

        # Lines that are CPE / OS-description / column-header noise and
        # should NOT contribute to the hostname zone. The trailing tail-of-
        # record numeric line is detected separately, not via this list.
        # Standalone "Windows" / "Linux" / "ARM" / "mil" lines are noise
        # too -- they're wrap-fragments from OS CPE or DNS suffix.
        $noiseRx = '(?i)^\s*(cpe:|ft:|>\s*Microsoft|>\s*Red Hat|Microsoft Windows|Windows\s+(?:11|10|Server|7|8)|Red Hat\s+Enterprise|Linux|enterprise(?:\s|$)|ise[~_]|ux:\d|x86_|x64-|2:\d|ARM\d|Server\s+20\d\d|IP Address|NetBIOS|DNS Name|OS CPE|UNCLASSIFIED|Top \d+ Worst|Score\s+Vulns|Dirty 30|Generated on|Tenable|Security Center|LAKENHEATH)\s*$|^\s*(Windows|Linux|ARM|ARM64|mil|Microsoft|Red Hat|enterprise)\s*$'

        # Score+vulns tail. Need at least 3 numbers (score + CRIT + HIGH);
        # MED and LOW optional - Tenable sometimes only shows 2 vuln
        # columns when the lower severities are zero, e.g. "298 16 117".
        # Hostname token is optional and must contain at least one letter
        # (so pure digits like "568" don't get captured as a host name).
        # Relaxed: Score + at least one bar number (Crit); High/Med/Low
        # optional, so a 2-token tail like "190 316" (Tenable dropped the zero
        # Med/Low segments) still matches. Groups widened to {1,5} so a glued
        # token ("219","316") is captured whole, then un-glued against Score by
        # Resolve-Dirty30Severities below.
        $tailRx = [regex]'^\s*(?:((?=[A-Z0-9\-\.]*[A-Z])[A-Za-z0-9][A-Za-z0-9\-\.]{2,40})\s+)?([\d,]{1,7})\s+(\d{1,5})(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?\s*$'

        for ($bIdx = 0; $bIdx -lt $ipPositions.Count; $bIdx++) {
            $startLine = $ipPositions[$bIdx]
            $endLine   = if ($bIdx + 1 -lt $ipPositions.Count) { $ipPositions[$bIdx + 1] - 1 } else { $allLines.Count - 1 }
            $block     = $allLines[$startLine..$endLine]
            if ($block.Count -eq 0) { continue }

            # First line: IP, sometimes IP + DNS hostname on the same line.
            $ip = ''
            if ($block[0] -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $Matches[1] }

            # Walk backwards from the end of the block looking for the tail
            # line (score + vuln numbers). Note: we don't require a hostname
            # token on the tail itself; many Tenable rows put it on a
            # separate prior line.
            $score = 0; $crit = 0; $high = 0; $med = 0; $low = 0
            $vulnConfidence = 'asis'
            $tailIdx = -1
            $tailHostname = ''
            for ($i = $block.Count - 1; $i -ge 0; $i--) {
                $tm = $tailRx.Match($block[$i])
                if ($tm.Success) {
                    $n = 0
                    if ([int]::TryParse($tm.Groups[2].Value.Replace(',',''), [ref]$n)) { $score = $n }
                    # Collect the bar tokens (Crit/High/Med/Low) exactly as
                    # pdftotext emitted them - possibly glued or zero-collapsed -
                    # and let Resolve-Dirty30Severities reconcile them with Score.
                    $barTokens = New-Object System.Collections.ArrayList
                    foreach ($gi in 3, 4, 5, 6) { if ($tm.Groups[$gi].Success -and $tm.Groups[$gi].Value) { [void]$barTokens.Add($tm.Groups[$gi].Value) } }
                    $sev = Resolve-Dirty30Severities -Score $score -BarTokens ($barTokens.ToArray())
                    $crit = $sev.Crit; $high = $sev.High; $med = $sev.Med; $low = $sev.Low; $vulnConfidence = $sev.Confidence
                    if ($tm.Groups[1].Success) {
                        $tailHostname = $tm.Groups[1].Value
                        if ($tailHostname -match '\.') { $tailHostname = ($tailHostname -split '\.')[0] }
                        $tailHostname = $tailHostname.ToUpper()
                        if ($domainPrefixes.ContainsKey($tailHostname)) { $tailHostname = '' }
                    }
                    $tailIdx = $i
                    break
                }
            }

            # Concatenate hostname-zone lines (everything before the tail,
            # noise-filtered). The first line keeps only its NON-IP portion
            # so e.g. "131.51.16.130 msek-as-ltac01p.elx.af." contributes
            # "msek-as-ltac01p.elx.af.".
            $hostZone = New-Object System.Text.StringBuilder
            $upper = if ($tailIdx -ge 0) { $tailIdx - 1 } else { $block.Count - 1 }
            for ($i = 0; $i -le $upper; $i++) {
                $line = $block[$i]
                if ($i -eq 0) {
                    # Strip the leading IP off the first line
                    $line = $line -replace '^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*', ''
                }
                $trimmed = $line.Trim()
                if (-not $trimmed) { continue }
                if ($trimmed -match $noiseRx) { continue }
                # Append with NO separator so split hostnames glue back
                # together: "52MSEKW3-" + "AFAS03\52MSEKW" + "3-AFAS03"
                # becomes "52MSEKW3-AFAS03\52MSEKW3-AFAS03"
                [void]$hostZone.Append($trimmed)
            }
            $zoneText = $hostZone.ToString()

            # Pull the hostname out of the zone. Prefer NetBIOS (anything
            # after a backslash) — UPPERCASE-only intentionally, so when
            # the zone text concatenates NetBIOS + DNS like
            # "\MSEKL-8BCCD54msekl-8bccd54.area52" the regex stops at the
            # case transition and only captures the NetBIOS form.
            $hostname = ''
            $nbMatches = [regex]::Matches($zoneText, '\\([A-Z0-9][A-Z0-9\-]{2,40})')
            if ($nbMatches.Count -gt 0) {
                # Longest match wins among NetBIOS candidates -
                # "52MSEKW3-AFAS03" beats any shorter "52MSEKW" fragment.
                $best = ''
                foreach ($m in $nbMatches) {
                    $cand = $m.Groups[1].Value
                    if ($cand -match '[A-Z]' -and $cand.Length -gt $best.Length) { $best = $cand }
                }
                $hostname = $best.ToUpper()
            }
            if (-not $hostname) {
                # DNS-style fallback: first label of "host.domain.tld"
                $dnsMatch = [regex]::Match($zoneText, '(?i)([a-z][a-z0-9\-]{2,40})\.[a-z][a-z0-9\-]*\.(?:afnoapps|usaf|af|mil|elx)')
                if ($dnsMatch.Success) { $hostname = $dnsMatch.Groups[1].Value.ToUpper() }
            }
            if (-not $hostname -and $tailHostname) { $hostname = $tailHostname }

            if (-not $hostname) { continue }
            if ($domainPrefixes.ContainsKey($hostname)) { continue }
            # Belt-and-suspenders: hostnames must contain at least one
            # letter (so pure-digit strings can't slip through any path).
            if ($hostname -notmatch '[A-Z]') { continue }
            if ($seen.ContainsKey($hostname)) { continue }

            $seen[$hostname] = $true
            [void]$hosts.Add([PSCustomObject]@{
                Hostname = $hostname; IP = $ip; Score = $score
                Crit = $crit; High = $high; Med = $med; Low = $low
                VulnConfidence = $vulnConfidence
            })
        }

        # If the block-based parser picked up at least one host, we're done.
        # The line-walker below is a safety net for inputs that don't have
        # IP-anchored blocks (e.g. pasted hostname-only lists).
        if ($hosts.Count -gt 0) { return $hosts }

        # === Pre-processing: heal wrapped Tenable PDF rows ===
        # pdftotext -layout breaks long fields across lines. Two specific
        # wraps we have to glue back together before the line-walker can
        # cope:
        #
        #   1. NetBIOS column ends with "\" on one line, hostname on the
        #      next:
        #          S.USAF.MIL\
        #          MSEKW-II522D89
        #      -> "S.USAF.MIL\MSEKW-II522D89"
        #
        #   2. DNS column wraps mid-label:
        #          msek-as-ltac01p.elx.af.
        #          mil
        #      -> "msek-as-ltac01p.elx.af.mil"
        $Text = $Text -replace '\\[ \t]*\r?\n[ \t]*', '\'
        $Text = $Text -replace '(\.)[ \t]*\r?\n[ \t]*([a-z0-9])', '$1$2'

        # Tenable PDF rows wrap across multiple lines after pdftotext -layout.
        # A typical entry looks like:
        #   131.51.33.109
        #   AREA52.AFNOAPPS.USAF.MIL\MSEKT-927JYX2     (post-join)
        #   MSEKT-927JYX2  1,470  17  125  12  2       <-- score + CRIT/HIGH/MED/LOW
        # The score+vulns "tail" is always alone on its own line in -layout
        # output; we treat that line as a record-terminator and walk back to
        # find the preceding hostname.
        #
        # Hostname patterns REQUIRE a leading letter so the score-tail regex
        # can't capture pure-digit Linux box scores like "568" as a host
        # name when the matching DNS row got eaten by wrapping.
        $netbiosLineRx = [regex]'(?i)\\\s*([A-Z][A-Z0-9\-]{2,31})\b'
        $dnsLineRx     = [regex]'(?i)\b([a-z][a-z0-9\-]{2,31})\.[a-z][a-z0-9\-]*\.(?:afnoapps|usaf|af|mil|elx)\b'
        # Score+vulns tail: "1,470 17 125 12 2" or "966 6 88 6" (LOW optional)
        # The hostname can also be on the same line: "MSEKT-927JYX2  1,470  17  125  12  2"
        $tailRx        = [regex]'^\s*(?:([A-Z][A-Z0-9\-]{2,31}|[a-z][a-z0-9\-]{2,31}(?:\.[a-z0-9\-\.]+)?)\s+)?([\d,]{1,7})\s+(\d{1,5})(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?\s*$'

        $lines = $Text -split "`r?`n"
        $pendingName = $null
        $pendingIP   = $null

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]

            # 1) Record IP if this line is purely an IPv4 address
            if ($line.Trim() -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $pendingIP = $line.Trim()
                continue
            }

            # 2) Try score+vulns tail FIRST — terminates a record. The line
            # may carry its own hostname (DNS-only Linux box) or be just the
            # numeric tail (Windows box where hostname was on a prior line).
            $tail = $tailRx.Match($line)
            if ($tail.Success) {
                $name = $pendingName
                if ($tail.Groups[1].Success) {
                    $tailName = $tail.Groups[1].Value
                    # If the leading token looks like a DNS hostname, take its
                    # first label; otherwise the whole thing IS the short name.
                    if ($tailName -match '\.') {
                        $tailName = ($tailName -split '\.')[0]
                    }
                    $tailName = $tailName.Trim().ToUpper()
                    if ($tailName -and -not $domainPrefixes.ContainsKey($tailName)) {
                        $name = $tailName
                    }
                }
                if ($name -and -not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    $score = 0; $null = [int]::TryParse($tail.Groups[2].Value.Replace(',',''), [ref]$score)
                    $barTokens = New-Object System.Collections.ArrayList
                    foreach ($gi in 3, 4, 5, 6) { if ($tail.Groups[$gi].Success -and $tail.Groups[$gi].Value) { [void]$barTokens.Add($tail.Groups[$gi].Value) } }
                    $sev = Resolve-Dirty30Severities -Score $score -BarTokens ($barTokens.ToArray())
                    [void]$hosts.Add([PSCustomObject]@{
                        Hostname = $name; IP = $pendingIP; Score = $score
                        Crit = $sev.Crit; High = $sev.High; Med = $sev.Med; Low = $sev.Low
                        VulnConfidence = $sev.Confidence
                    })
                }
                $pendingName = $null
                $pendingIP   = $null
                continue
            }

            # 3) Look for a NetBIOS hostname pattern (DOMAIN\HOST) - update
            # the pending name; later score+vulns line will commit it.
            $nb = $netbiosLineRx.Match($line)
            if ($nb.Success) {
                $candidate = $nb.Groups[1].Value.Trim().ToUpper()
                if (-not $domainPrefixes.ContainsKey($candidate)) {
                    $pendingName = $candidate
                }
                continue
            }

            # 4) DNS hostname pattern - only use it if we don't already have
            # a NetBIOS pending name (DNS is less reliable, can match domain
            # parts).
            if (-not $pendingName) {
                $dn = $dnsLineRx.Match($line)
                if ($dn.Success) {
                    $candidate = $dn.Groups[1].Value.Trim().ToUpper()
                    if (-not $domainPrefixes.ContainsKey($candidate)) {
                        $pendingName = $candidate
                    }
                }
            }
        }

        # If the multi-line tail walker didn't find anything (e.g. operator
        # pasted just a list of NetBIOS rows with no score column), fall back
        # to the simple hostname regex and zero-out the vuln counts. Score=0
        # in that case is honest about what we can pull from a hostname-only
        # source.
        if ($hosts.Count -eq 0) {
            foreach ($m in $netbiosLineRx.Matches($Text)) {
                $name = $m.Groups[1].Value.Trim().ToUpper()
                if ($domainPrefixes.ContainsKey($name)) { continue }
                if (-not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    [void]$hosts.Add([PSCustomObject]@{
                        Hostname = $name; IP = ''; Score = 0
                        Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis'
                    })
                }
            }
            foreach ($m in $dnsLineRx.Matches($Text)) {
                $name = $m.Groups[1].Value.Trim().ToUpper()
                if ($domainPrefixes.ContainsKey($name)) { continue }
                if (-not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    [void]$hosts.Add([PSCustomObject]@{
                        Hostname = $name; IP = ''; Score = 0
                        Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis'
                    })
                }
            }
            # Plain hostname-per-line list (last resort)
            if ($hosts.Count -eq 0) {
                foreach ($line in ($Text -split "`r?`n")) {
                    $t = $line.Trim()
                    if ($t -match '^[A-Za-z][A-Za-z0-9\-]{2,31}$') {
                        $name = $t.ToUpper()
                        if (-not $seen.ContainsKey($name)) {
                            $seen[$name] = $true
                            [void]$hosts.Add([PSCustomObject]@{
                                Hostname = $name; IP = ''; Score = 0
                                Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis'
                            })
                        }
                    }
                }
            }
        }
    }

    return $hosts
}

function Get-Dirty30AdInfo {
    # Batched LDAP lookup. Returns hashtable indexed by uppercase hostname:
    #   Hostname, DN, OS, Squadron, ParentOU, OUChain,
    #   LastLogon (string yyyy-MM-dd HH:mm or "Never"), IsStale, Status,
    #   LastUser ('' until probe runs).
    # Mirrors ADSearchTool BulkComputer logic (50/batch, OR-filter, generic-
    # parent skipping for squadron extraction, 90-day stale threshold).
    param([Parameter(Mandatory)][string[]]$Hostnames)

    $results = @{}
    $now = Get-Date
    $staleThreshold = $now.AddDays(-90)

    try {
        # Mirrors ADSearchTool's BulkComputer setup exactly: empty-string ADSI
        # binds to the default naming context, [ADSISEARCHER] is the
        # type-accelerator form, PageSize 15000 matches. No PropertiesToLoad
        # restriction — pulling all attributes is the same pattern that
        # ADSearchTool uses, and the OU parser only needs distinguishedname
        # + lastlogontimestamp + operatingsystem anyway.
        $root     = [ADSI]''
        $searcher = [ADSISEARCHER]$root
        $searcher.PageSize = 15000
    } catch {
        Log "[D30] LDAP connect failed: $_"
        return $results
    }

    $clean = @($Hostnames | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ } | Select-Object -Unique)
    $foundSet = @{}

    # Result-builder shared between the main OR-of-50 batch path and the
    # per-host fallback. The key bit (lifted from ADSearchTool BulkComputer
    # line ~2056): the AFNET "location" attribute on computer objects is
    # a semicolon-delimited blob like
    #   "ORGANIZATION: 48 CS; BUILDING: 100; ROOM: 200"
    # The squadron is the ORGANIZATION token, NOT the OU. Without parsing
    # it, every host falls back to its parent OU which is often just
    # "Workstations" / "Lakenheath AFB" - useless for squadron breakdown.
    $buildResult = {
        param($entry, $staleThreshold)
        $name = "$($entry.Properties['name'][0])".ToUpper()
        $dn   = "$($entry.Properties['distinguishedname'][0])"
        $os   = if ($entry.Properties['operatingsystem'].Count -gt 0) { "$($entry.Properties['operatingsystem'][0])" } else { '' }

        # OU walk (fallback if location's ORGANIZATION token is missing)
        $ouPath  = ($dn -split ',', 2)[1]
        $ouParts = $ouPath -split ','
        $ouNames = @()
        foreach ($part in $ouParts) {
            if ($part -match '^OU=(.+)$') { $ouNames += $Matches[1] }
        }
        $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { '(Root)' }
        $ouSquadron = $parentOU
        $generic = @('Workstations','Computers','Servers','Desktops','Laptops','Devices','Resources','Members')
        if ($ouNames.Count -ge 2 -and $generic -contains $parentOU) {
            $ouSquadron = $ouNames[1]
        }
        $reversed = @($ouNames); [array]::Reverse($reversed)
        $ouChain = if ($reversed.Count -gt 0) { $reversed -join ' > ' } else { '(Root)' }

        # AFNET "location" attribute - try to pull ORGANIZATION: <name>; out
        # of it. Same pattern ADSearchTool BulkComputer uses.
        $locRaw = ''
        if ($entry.Properties['location'].Count -gt 0) { $locRaw = "$($entry.Properties['location'][0])" }
        $orgFromLoc = ''
        if ($locRaw -and $locRaw -match 'ORGANIZATION:\s*([^;]+)') {
            $orgFromLoc = $Matches[1].Trim()
        }
        $squadron = if ($orgFromLoc) { $orgFromLoc } else { $ouSquadron }

        # description / department fallbacks - some AFNET sites populate
        # those instead of location. Last-ditch before falling to OU.
        if (-not $orgFromLoc -and $entry.Properties['department'].Count -gt 0) {
            $dep = "$($entry.Properties['department'][0])".Trim()
            if ($dep) { $squadron = $dep }
        }

        $lastLogon = 'Never'; $isStale = $true
        try {
            if ($entry.Properties['lastlogontimestamp'].Count -gt 0) {
                $tsVal = $entry.Properties['lastlogontimestamp'][0]
                if ($tsVal -gt 0) {
                    $lld = [DateTime]::FromFileTime([Int64]$tsVal)
                    $lastLogon = $lld.ToString('yyyy-MM-dd HH:mm')
                    if ($lld -ge $staleThreshold) { $isStale = $false }
                }
            }
        } catch {}

        return @{
            Key = $name
            Row = [PSCustomObject]@{
                Hostname     = $name
                DN           = $dn
                OS           = $os
                Squadron     = $squadron       # ORGANIZATION-parsed if available, else OU
                ParentOU     = $parentOU
                OUChain      = $ouChain
                LocationInfo = $locRaw         # Raw location string for display ("ORGANIZATION: 48 CS; BUILDING: 100; ...")
                LastLogon    = $lastLogon
                IsStale      = $isStale
                Status       = if ($isStale) { 'Stale' } else { 'Active' }
                LastUser     = ''
            }
        }
    }

    $batchSize = 50
    for ($i = 0; $i -lt $clean.Count; $i += $batchSize) {
        $batch = $clean[$i..[Math]::Min(($i + $batchSize - 1), ($clean.Count - 1))]
        $filterParts = ''
        foreach ($name in $batch) {
            $esc = $name -replace '\\','\5c' -replace '\*','\2a' -replace '\(','\28' -replace '\)','\29' -replace '/','\2f' -replace [char]0,'\00'
            $filterParts += "(name=$esc)"
        }
        $searcher.Filter = if ($batch.Count -eq 1) {
            "(&(objectCategory=Computer)$filterParts)"
        } else {
            "(&(objectCategory=Computer)(|$filterParts))"
        }
        try {
            $adResults = $searcher.FindAll()
            foreach ($entry in $adResults) {
                $built = & $buildResult $entry $staleThreshold
                $results[$built.Key] = $built.Row
                $foundSet[$built.Key] = $true
            }
        } catch {
            # Per-batch fallback - mirrors ADSearchTool BulkComputer (line
            # 1510 in ADSearchTool.ps1). If the OR-of-50 filter blows up
            # (too long, transient AD error, one bad escape), retry each
            # name in the batch individually. Don't lose the whole batch
            # over one bad apple.
            Log "[D30] LDAP batch $i failed ($_); retrying per-host"
            foreach ($name in $batch) {
                $searcher.Filter = "(&(objectCategory=Computer)(name=$(($name -replace '\\','\5c' -replace '\*','\2a' -replace '\(','\28' -replace '\)','\29' -replace [char]0,'\00'))))"
                try {
                    $fb = $searcher.FindAll()
                    foreach ($entry in $fb) {
                        $built = & $buildResult $entry $staleThreshold
                        $results[$built.Key] = $built.Row
                        $foundSet[$built.Key] = $true
                    }
                } catch {
                    Log "[D30] LDAP per-host fallback failed for $name : $_"
                }
            }
        }
    }

    # Not-Found placeholders so the grid stays aligned with the input list.
    foreach ($name in $clean) {
        if (-not $foundSet.ContainsKey($name)) {
            $results[$name] = [PSCustomObject]@{
                Hostname  = $name; DN = ''; OS = ''; LocationInfo = ''
                Squadron  = 'UNKNOWN'; ParentOU = 'N/A'
                OUChain   = 'no matching computer object'
                LastLogon = '—'; IsStale = $false
                Status    = 'Not Found'; LastUser = '—'
            }
        }
    }
    return $results
}

function Get-Dirty30LastLoggedOnUser {
    # Parallel WMI StdRegProv probe of each host's
    # HKLM\...\LogonUI\LastLoggedOnUser value. Returns hashtable indexed
    # by uppercase hostname; values are either "AREA52\j.smith" style
    # strings or marker tokens "— offline —" / "— timeout —" / "— error —".
    # Slow (network-bound), default-off — fired only when the operator
    # clicks "+ Probe Last-Logged-On User".
    param([Parameter(Mandatory)][string[]]$Hostnames, [int]$TimeoutSec = 8, [int]$MaxConcurrent = 16)

    $results = @{}
    foreach ($h in $Hostnames) { $results[$h.ToUpper()] = '—' }
    if ($Hostnames.Count -eq 0) { return $results }

    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrent)
    $pool.Open()

    $jobs = [System.Collections.ArrayList]::new()
    foreach ($h in $Hostnames) {
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        $sb = {
            param($Target)
            try {
                $opts = New-Object System.Management.ConnectionOptions
                $opts.Timeout = New-Object TimeSpan(0,0,5)
                $scope = New-Object System.Management.ManagementScope("\\$Target\root\default", $opts)
                $scope.Connect()
                $reg = New-Object System.Management.ManagementClass($scope,
                    (New-Object System.Management.ManagementPath('StdRegProv')), $null)
                $HKLM = 2147483650
                $keyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $valName = 'LastLoggedOnUser'
                $params = $reg.GetMethodParameters('GetStringValue')
                $params['hDefKey']     = $HKLM
                $params['sSubKeyName'] = $keyPath
                $params['sValueName']  = $valName
                $r = $reg.InvokeMethod('GetStringValue', $params, $null)
                if ($r.ReturnValue -eq 0 -and $r.sValue) {
                    return @{ Host = $Target; User = $r.sValue }
                }
                return @{ Host = $Target; User = '— no value —' }
            } catch {
                $m = $_.Exception.Message
                if ($m -match 'RPC|unavailable|not found|denied|0x8') { return @{ Host = $Target; User = '— offline —' } }
                return @{ Host = $Target; User = '— error —' }
            }
        }
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript($sb).AddArgument($h)
        $ps.RunspacePool = $pool
        $handle = $ps.BeginInvoke()
        [void]$jobs.Add(@{ Ps = $ps; Handle = $handle; Host = $h.ToUpper(); Done = $false })
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt ($TimeoutSec * 3)) {
        $allDone = $true
        foreach ($j in $jobs) {
            if ($j.Done) { continue }
            if ($j.Handle.IsCompleted) {
                try {
                    $r = $j.Ps.EndInvoke($j.Handle)
                    if ($r -and $r[0]) { $results[$j.Host] = $r[0].User }
                    else { $results[$j.Host] = '— no result —' }
                } catch {
                    $results[$j.Host] = '— error —'
                } finally {
                    try { $j.Ps.Dispose() } catch {}
                    $j.Done = $true
                }
            } else {
                $allDone = $false
            }
        }
        if ($allDone) { break }
        Start-Sleep -Milliseconds 100
    }
    # Anything still running gets marked timeout
    foreach ($j in $jobs) {
        if (-not $j.Done) {
            try { $j.Ps.Stop(); $j.Ps.Dispose() } catch {}
            $results[$j.Host] = '— timeout —'
        }
    }
    $pool.Close(); $pool.Dispose()
    return $results
}

function ConvertTo-HtmlEscaped {
    # Minimal HTML escape for table-cell text. Keeps the embedded report
    # safe from squadron names / OU paths that happen to contain & < > " '.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

function Render-Dirty30Html {
    # Build a single self-contained HTML file from the current
    # $global:Dirty30Hosts / $global:Dirty30AdResults / $global:Dirty30LastUserMap.
    # Mirrors dev/dirty30-triage-mockup.html one-for-one (dark theme, summary
    # tiles, squadron chip strip, status-color-coded grid) so the operator
    # gets the same polished view the mockup showed — without WinForms
    # rendering quirks (DataGridView alternating-row glitches, font sizing,
    # color rendering on different display scales).
    param([Parameter(Mandatory)][string]$Path)

    $totalParsed = $global:Dirty30Hosts.Count
    $activeCount = 0; $staleCount = 0; $notFoundCount = 0
    $sqCounts = @{}
    foreach ($h in $global:Dirty30Hosts) {
        $ad = $global:Dirty30AdResults[$h.Hostname]
        if (-not $ad) { continue }
        switch ($ad.Status) {
            'Active'    { $activeCount++ }
            'Stale'     { $staleCount++ }
            'Not Found' { $notFoundCount++ }
        }
        if ($ad.Status -ne 'Not Found') {
            if (-not $sqCounts.ContainsKey($ad.Squadron)) { $sqCounts[$ad.Squadron] = 0 }
            $sqCounts[$ad.Squadron]++
        }
    }
    $foundCount = $totalParsed - $notFoundCount

    # Top squadron tile content
    $topName = '—'; $topCount = 0
    foreach ($k in $sqCounts.Keys) { if ($sqCounts[$k] -gt $topCount) { $topName = $k; $topCount = $sqCounts[$k] } }
    $topSub = if ($foundCount -gt 0 -and $topCount -gt 0) {
        $pct = [Math]::Round(($topCount / $foundCount) * 100, 1)
        "$topCount of $foundCount found ($pct%)"
    } else { '' }

    # Squadron chip strip HTML
    $chipsHtml = New-Object System.Text.StringBuilder
    if ($sqCounts.Count -gt 0) {
        $sorted = $sqCounts.GetEnumerator() | Sort-Object Value -Descending
        foreach ($kv in $sorted) {
            $pct = if ($foundCount -gt 0) { [Math]::Round(($kv.Value / $foundCount) * 100, 1) } else { 0 }
            $name = ConvertTo-HtmlEscaped $kv.Key
            [void]$chipsHtml.Append("<div class=`"squad-chip`"><span class=`"name`">$name</span><span class=`"count`">$($kv.Value)</span><span class=`"frac`">$pct%</span></div>`n")
        }
    }
    if ($notFoundCount -gt 0) {
        [void]$chipsHtml.Append("<div class=`"squad-chip`" style=`"opacity: 0.6; border-color: var(--danger);`"><span class=`"name`" style=`"color: var(--danger);`">UNKNOWN</span><span class=`"count`">$notFoundCount</span><span class=`"frac`">Not Found</span></div>`n")
    }

    # Grid rows HTML
    $rowsHtml = New-Object System.Text.StringBuilder
    foreach ($h in $global:Dirty30Hosts) {
        $ad = $global:Dirty30AdResults[$h.Hostname]
        $vulnStr = if ($h.Score -gt 0 -or $h.Crit -gt 0 -or $h.High -gt 0) {
            "<span class=`"c`">$($h.Crit)</span> / <span class=`"h`">$($h.High)</span> / <span class=`"m`">$($h.Med)</span> / <span class=`"l`">$($h.Low)</span>"
        } else { '—' }
        # Tenable glued the Crit/High segments and Score can't split them (both
        # weigh 10); flag the best-guess split so the operator verifies it.
        if ($h.PSObject.Properties['VulnConfidence'] -and $h.VulnConfidence -eq 'ambiguous') {
            $vulnStr += '<sup title="Critical-vs-High split inferred from the Score (Tenable bar glued the segments) - verify against the PDF bar colors." style="color:#e8a23d;cursor:help;font-weight:700;">*</sup>'
        }
        $scoreStr = if ($h.Score -gt 0) { $h.Score.ToString('N0') } else { '—' }
        $lastAd = if ($ad) { ConvertTo-HtmlEscaped $ad.LastLogon } else { '' }
        $lastUserRaw = if ($global:Dirty30LastUserMap.ContainsKey($h.Hostname)) { $global:Dirty30LastUserMap[$h.Hostname] } elseif ($ad) { $ad.LastUser } else { '' }
        $lastUserEsc = ConvertTo-HtmlEscaped $lastUserRaw
        $lastUserClass = if ($lastUserRaw -match '^—' -or [string]::IsNullOrWhiteSpace($lastUserRaw)) { 'lastuser unknown' } else { 'lastuser' }
        $sq = if ($ad) { ConvertTo-HtmlEscaped $ad.Squadron } else { '' }
        # Prefer the AFNET location string ("ORGANIZATION: 48 CS; BUILDING:
        # 100; ...") over the bare OU chain - much more useful for the
        # operator at a glance. Falls back to OU when location is empty.
        $locValue = if ($ad -and $ad.PSObject.Properties['LocationInfo'] -and $ad.LocationInfo) { $ad.LocationInfo } elseif ($ad) { $ad.OUChain } else { '' }
        $ou = ConvertTo-HtmlEscaped $locValue
        $st = if ($ad) { $ad.Status } else { 'Unknown' }
        $badgeClass = switch ($st) {
            'Active'    { 'active' }
            'Stale'     { 'stale' }
            'Not Found' { 'notfound' }
            default     { 'active' }
        }
        $lastAdClass = if ($st -eq 'Stale') { 'lastad stale' } else { 'lastad' }
        $sqClass = if ($st -eq 'Not Found') { 'squad nf' } else { 'squad' }
        $rowOpacity = if ($st -eq 'Not Found') { 'style="opacity: 0.78;"' } else { '' }
        $hostname = ConvertTo-HtmlEscaped $h.Hostname

        [void]$rowsHtml.Append(@"
<tr $rowOpacity>
  <td class="host">$hostname</td>
  <td class="score">$scoreStr</td>
  <td class="vulns">$vulnStr</td>
  <td class="$lastAdClass">$lastAd</td>
  <td class="$lastUserClass">$lastUserEsc</td>
  <td class="$sqClass">$sq</td>
  <td class="ou">$ou</td>
  <td class="status"><span class="badge $badgeClass">$st</span></td>
</tr>
"@)
    }
    if ($totalParsed -eq 0) {
        [void]$rowsHtml.Append('<tr><td colspan="8" style="text-align:center; padding:20px; color: var(--text-faint); font-style: italic;">No hosts loaded.</td></tr>')
    }

    $sourceLabel = ConvertTo-HtmlEscaped ($global:Dirty30SourceLabel)
    if (-not $sourceLabel) { $sourceLabel = '(no source loaded)' }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $operator = ConvertTo-HtmlEscaped $env:USERNAME
    $machine  = ConvertTo-HtmlEscaped $env:COMPUTERNAME

    $chipsBlock = $chipsHtml.ToString()
    $rowsBlock  = $rowsHtml.ToString()

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET — Dirty 30 Triage — $generated</title>
<style>
  :root {
    --bg:          rgb(8,  8, 12);
    --panel:       rgb(18, 18, 26);
    --panel-light: rgb(30, 28, 40);
    --input:       rgb(22, 22, 30);
    --border:      rgb(38, 34, 52);
    --text:        rgb(240,240,245);
    /* Brightened from rgb(170,168,180) / rgb(120,118,135) so sub-text reads
       cleanly on a projector — matches the Weekly Export presentation tuning. */
    --text-dim:    rgb(210,208,220);
    --text-faint:  rgb(180,178,195);
    --accent:      rgb(140,100,220);
    --success:     rgb( 92,198,120);
    --warning:     rgb(245,180, 70);
    --danger:      rgb(220, 92,100);
    --cyan:        rgb( 80,200,220);
    --gold:        rgb(238,196, 88);
    --orange:      rgb(232,140, 70);
  }
  * { box-sizing: border-box; }
  /* Base font 13 -> 14 so everything that inherits gets a free bump. */
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 60px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 20px; font-weight: 600; color: var(--gold); }
  .topbar .subtitle { color: var(--text-dim); font-size: 13px; }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .topbar .meta .gen { color: var(--cyan); }
  .content { padding: 20px 28px; max-width: 1600px; margin: 0 auto; }
  .page-title { font-size: 26px; color: var(--gold); font-weight: 600; margin: 0 0 4px 0; }
  .page-subtitle { color: var(--text-dim); font-size: 13px; margin: 0 0 14px 0; }
  .source { background: var(--panel); border: 1px solid var(--border); padding: 11px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 18px; font-family: Consolas, monospace; }
  .source .file { color: var(--cyan); font-weight: 600; }
  .summary-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 18px; }
  .summary-tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .summary-tile.green { border-top-color: var(--success); }
  .summary-tile.gold { border-top-color: var(--gold); }
  .summary-tile.danger { border-top-color: var(--danger); }
  .summary-tile.warning { border-top-color: var(--warning); }
  .summary-tile .lbl { font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  /* Headline number - bumped 26 -> 40px for projector visibility, weight 700 -> 800. */
  .summary-tile .val { font-size: 40px; font-weight: 800; color: var(--text); margin-top: 8px; line-height: 1.1; }
  .summary-tile.green .val { color: var(--success); }
  .summary-tile.warning .val { color: var(--warning); }
  .summary-tile.danger .val { color: var(--danger); }
  .summary-tile.gold .val { color: var(--gold); font-size: 28px; }
  .summary-tile .sub { font-size: 13px; color: var(--text-dim); margin-top: 6px; }
  .squadron-strip { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--gold); padding: 14px 16px; margin-bottom: 18px; border-radius: 3px; }
  .squadron-strip h3 { margin: 0 0 10px 0; font-size: 13px; color: var(--gold); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
  .squadron-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .squad-chip { background: var(--input); border: 1px solid var(--border); padding: 8px 14px; border-radius: 2px; font-size: 13px; }
  .squad-chip .name { color: var(--gold); font-weight: 700; margin-right: 8px; }
  .squad-chip .count { color: var(--text); font-weight: 700; font-size: 15px; }
  .squad-chip .frac { color: var(--text-dim); font-size: 12px; margin-left: 6px; }
  table.grid { width: 100%; border-collapse: collapse; background: var(--panel); font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); font-weight: 700; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; padding: 10px 12px; text-align: left; border-bottom: 2px solid var(--border); position: sticky; top: 0; z-index: 2; }
  table.grid td { padding: 12px 14px; border-bottom: 1px solid var(--border); color: var(--text); vertical-align: middle; }
  table.grid tr:hover td { background: rgba(140,100,220,0.06); }
  /* Hostname column - bumped 13.5 -> 22px so it reads at PowerPoint
     projector distance (operator request 2026-05-12). Padding also
     widened (9/12 -> 12/14) so the bigger text doesn't crash row-to-row;
     vertical-align: middle keeps it centered against shorter neighbors. */
  td.host { font-family: Consolas, monospace; color: var(--cyan); font-weight: 700; font-size: 22px; letter-spacing: 0.3px; }
  td.score { font-weight: 800; color: var(--gold); font-size: 15px; }
  td.vulns { font-family: Consolas, monospace; font-size: 13px; }
  td.vulns .c { color: var(--danger); font-weight: 700; }
  td.vulns .h { color: var(--orange); font-weight: 700; }
  td.vulns .m { color: var(--warning); }
  td.vulns .l { color: var(--cyan); }
  td.squad { color: var(--gold); font-weight: 700; font-size: 13.5px; }
  td.squad.nf { color: var(--danger); }
  td.lastad { font-family: Consolas, monospace; font-size: 12.5px; }
  td.lastad.stale { color: var(--warning); }
  td.lastuser { font-family: Consolas, monospace; color: var(--accent); font-size: 12.5px; font-weight: 600; }
  td.lastuser.unknown { color: var(--text-dim); font-style: italic; }
  td.ou { font-size: 12px; color: var(--text-dim); font-family: Consolas, monospace; max-width: 320px; word-wrap: break-word; }
  td.status .badge { padding: 3px 10px; border-radius: 10px; font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; }
  td.status .badge.active   { background: rgba(92,198,120,0.18); color: var(--success); }
  td.status .badge.stale    { background: rgba(245,180,70,0.18); color: var(--warning); }
  td.status .badge.notfound { background: rgba(220,92,100,0.18); color: var(--danger); }
  /* Filter controls (in-browser, JS) */
  .filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; padding: 10px 14px; background: var(--panel); border: 1px solid var(--border); border-radius: 3px; }
  .filter-bar .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-right: 6px; font-weight: 600; }
  .pill-btn { background: var(--input); color: var(--text-dim); border: 1px solid var(--border); padding: 6px 14px; border-radius: 12px; cursor: pointer; font-size: 12.5px; font-family: inherit; font-weight: 600; }
  .pill-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
  .pill-btn.warning.active { background: var(--warning); border-color: var(--warning); color: black; }
  .pill-btn.danger.active { background: var(--danger); border-color: var(--danger); color: white; }
  .filter-bar .search { margin-left: auto; }
  .filter-bar input.search { background: var(--input); color: var(--text); border: 1px solid var(--border); padding: 7px 12px; border-radius: 2px; font-size: 13px; width: 260px; font-family: inherit; }
  .footer { margin-top: 18px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="title">J.A.N.E.T — Dirty 30 Triage</div>
    <div class="subtitle">Joint Administration and Network Execution Toolkit · ReportsTool 2.14.0</div>
  </div>
  <div class="grow"></div>
  <div class="meta">
    <div>Generated <span class="gen">$generated</span></div>
    <div>by $operator on $machine</div>
  </div>
</div>

<div class="content">
  <h1 class="page-title">DIRTY 30 TRIAGE</h1>
  <p class="page-subtitle">
    Top vulnerable hosts cross-referenced with Active Directory — squadron, last AD logon, stale detection (&gt; 90 days), and (where probed) the last interactive user.
  </p>

  <div class="source">Source: <span class="file">$sourceLabel</span></div>

  <div class="summary-strip">
    <div class="summary-tile">
      <div class="lbl">Hosts Parsed</div>
      <div class="val">$totalParsed</div>
      <div class="sub">from source</div>
    </div>
    <div class="summary-tile green">
      <div class="lbl">AD: Active</div>
      <div class="val">$activeCount</div>
      <div class="sub">logon &lt;= 90 days</div>
    </div>
    <div class="summary-tile warning">
      <div class="lbl">AD: Stale</div>
      <div class="val">$staleCount</div>
      <div class="sub">no logon &gt; 90 days</div>
    </div>
    <div class="summary-tile danger">
      <div class="lbl">AD: Not Found</div>
      <div class="val">$notFoundCount</div>
      <div class="sub">no matching computer object</div>
    </div>
    <div class="summary-tile gold">
      <div class="lbl">Top Squadron</div>
      <div class="val">$(ConvertTo-HtmlEscaped $topName)</div>
      <div class="sub">$(ConvertTo-HtmlEscaped $topSub)</div>
    </div>
  </div>

  <div class="squadron-strip">
    <h3>Hosts by Squadron / OU</h3>
    <div class="squadron-row">
$chipsBlock
    </div>
  </div>

  <div class="filter-bar">
    <span class="lbl">View</span>
    <button class="pill-btn active" data-filter="all">All ($totalParsed)</button>
    <button class="pill-btn warning" data-filter="stale">Stale ($staleCount)</button>
    <button class="pill-btn danger" data-filter="notfound">Not Found ($notFoundCount)</button>
    <div class="search"><input class="search" id="searchBox" type="text" placeholder="Filter by hostname / squadron / OU..." /></div>
  </div>

  <table class="grid" id="hostGrid">
    <thead>
      <tr>
        <th>Hostname</th>
        <th style="width:60px;">Score</th>
        <th style="width:130px;">Vulns (C/H/M/L)</th>
        <th style="width:120px;">Last AD Logon</th>
        <th style="width:160px;">Last User</th>
        <th style="width:90px;">Squadron</th>
        <th>OU / Location</th>
        <th style="width:90px;">Status</th>
      </tr>
    </thead>
    <tbody id="hostBody">
$rowsBlock
    </tbody>
  </table>

  <div class="footer">
    Self-contained snapshot. To refresh, re-run the AD lookup in the JANET Reports Tool and re-export.
  </div>
</div>

<script>
  // Client-side filter — pill buttons + free-text search across host/squad/OU
  var rows = Array.prototype.slice.call(document.querySelectorAll('#hostBody tr'));
  var currentFilter = 'all';
  var pills = document.querySelectorAll('.pill-btn');
  pills.forEach(function (p) {
    p.addEventListener('click', function () {
      pills.forEach(function (x) { x.classList.remove('active'); });
      p.classList.add('active');
      currentFilter = p.getAttribute('data-filter');
      applyFilters();
    });
  });
  document.getElementById('searchBox').addEventListener('input', applyFilters);

  function applyFilters() {
    var q = document.getElementById('searchBox').value.toLowerCase().trim();
    rows.forEach(function (r) {
      var badge = r.querySelector('.badge');
      var status = badge ? badge.textContent.toLowerCase() : '';
      var passFilter = true;
      if (currentFilter === 'stale')    { passFilter = status === 'stale'; }
      if (currentFilter === 'notfound') { passFilter = status === 'not found'; }
      var passSearch = true;
      if (q) { passSearch = r.textContent.toLowerCase().indexOf(q) !== -1; }
      r.style.display = (passFilter && passSearch) ? '' : 'none';
    });
  }
</script>

</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($true))
}

function Export-Dirty30Results {
    # CSV export of the merged Dirty 30 + AD + probe data, plus a blank
    # Notes column for operator follow-up.
    param([Parameter(Mandatory)][string]$Path)
    $lines = [System.Collections.ArrayList]::new()
    [void]$lines.Add("# Dirty 30 Triage — Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERNAME on $env:COMPUTERNAME")
    if ($global:Dirty30SourceLabel) { [void]$lines.Add("# Source: $($global:Dirty30SourceLabel)") }
    [void]$lines.Add('')
    [void]$lines.Add('"Hostname","IP","Score","Crit","High","Med","Low","Last AD Logon","Last User","Squadron","Location Info","OU Chain","Status","Notes"')
    foreach ($d30h in $global:Dirty30Hosts) {
        $ad = $global:Dirty30AdResults[$d30h.Hostname]
        $lastUser = if ($global:Dirty30LastUserMap.ContainsKey($d30h.Hostname)) { $global:Dirty30LastUserMap[$d30h.Hostname] } elseif ($ad) { $ad.LastUser } else { '' }
        $lastUser = "$lastUser" -replace '"','""'
        $sq = if ($ad) { $ad.Squadron } else { '?' }
        $ou = if ($ad) { ("$($ad.OUChain)" -replace '"','""') } else { '' }
        $loc = if ($ad -and $ad.PSObject.Properties['LocationInfo']) { ("$($ad.LocationInfo)" -replace '"','""') } else { '' }
        $st = if ($ad) { $ad.Status } else { 'Unknown' }
        $ll = if ($ad) { $ad.LastLogon } else { '' }
        [void]$lines.Add("`"$($d30h.Hostname)`",`"$($d30h.IP)`",$($d30h.Score),$($d30h.Crit),$($d30h.High),$($d30h.Med),$($d30h.Low),`"$ll`",`"$lastUser`",`"$sq`",`"$loc`",`"$ou`",`"$st`",`"`"")
    }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($true))
}
#endregion

#region === MAIN FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text = "J.A.N.E.T. Reports Tool v2.14.0 - ACAS & Patch Cross-Reference"
$f.Size = New-Object System.Drawing.Size(1400, 950)
$f.MinimumSize = New-Object System.Drawing.Size(1200, 800)
$f.StartPosition = "CenterScreen"
$f.BackColor = $colors.Background; $f.ForeColor = $colors.TextPrimary; $f.Font = $fonts.Label
$f.Add_HandleCreated({ Set-WptDarkTitleBar -Form $f })
$f.Add_Load({ Set-WptDarkTitleBar -Form $f })
$script:WPT.UI.Form = $f
#endregion

#region === UI: TOP BAR ===
$topBar = New-Object System.Windows.Forms.Panel
$topBar.Dock = 'Top'; $topBar.Height = 64; $topBar.BackColor = $colors.TopBar
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "J.A.N.E.T. Reports Tool"; $lblTitle.Location = [System.Drawing.Point]::new(20, 8)
$lblTitle.AutoSize = $true; $lblTitle.Font = $fonts.Title; $lblTitle.ForeColor = $colors.Gold
$topBar.Controls.Add($lblTitle)
$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text = "Joint Administration and Network Execution Toolkit"
$lblVersion.Location = [System.Drawing.Point]::new(20, 38); $lblVersion.AutoSize = $true
$lblVersion.Font = $fonts.Label; $lblVersion.ForeColor = $colors.TextSecondary
$topBar.Controls.Add($lblVersion)

## Close Tool — top-right of the top bar (matches WPT pattern). Single
## sanctioned form egress: sets the X-block allow flag, then closes;
## FormClosing guard cancels every other origin.
$btnCloseTool = New-StyledButton -Text 'Close Tool' `
    -Location ([System.Drawing.Point]::new(0, 18)) `
    -Size ([System.Drawing.Size]::new(110, 28)) -BgColor $colors.Danger `
    -FgColor ([System.Drawing.Color]::White)
$btnCloseTool.Anchor = 'Top,Right'
$btnCloseTool.Add_Click({
    Set-JanetAllowClose $true
    $f.Close()
}.GetNewClosure())
$topBar.Controls.Add($btnCloseTool)
$topBar.Add_Resize({
    $btnCloseTool.Location = [System.Drawing.Point]::new(($topBar.ClientSize.Width - 130), 18)
}.GetNewClosure())
$btnCloseTool.Location = [System.Drawing.Point]::new(($topBar.ClientSize.Width - 130), 18)

# Gold accent stripe at bottom edge of top bar
$topBarAccent = New-Object System.Windows.Forms.Panel
$topBarAccent.Dock = 'Bottom'; $topBarAccent.Height = 2; $topBarAccent.BackColor = $colors.Gold
$topBar.Controls.Add($topBarAccent)
#endregion

#region === UI: SIDEBAR ===
$sidebar = New-Object System.Windows.Forms.Panel
$sidebar.Dock = 'Left'; $sidebar.Width = 180; $sidebar.BackColor = $colors.Sidebar
$tabNames = @(
    @{ Name = 'Start'; Icon = "" }
    @{ Name = 'ACAS Import'; Icon = "" }
    @{ Name = 'Remediation Plan'; Icon = "" }
    @{ Name = 'Patch Cross-Ref'; Icon = "" }
    @{ Name = 'Weekly Export'; Icon = "" }
    @{ Name = 'Dirty 30 Triage'; Icon = "" }
    @{ Name = 'CORA Vulnerabilities'; Icon = "" }
    @{ Name = 'Future Target IPs'; Icon = "" }
    @{ Name = 'Dashboard'; Icon = "" }
    @{ Name = 'Export'; Icon = "" }
)
$navY = 15
foreach ($tab in $tabNames) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "  $($tab.Name)"; $btn.TextAlign = 'MiddleLeft'
    $btn.Location = [System.Drawing.Point]::new(5, $navY); $btn.Size = [System.Drawing.Size]::new(170, 38)
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $colors.Sidebar; $btn.ForeColor = $colors.TextSecondary
    $btn.Font = $fonts.NavBtn; $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.FlatAppearance.MouseOverBackColor = $colors.SidebarHover; $btn.Tag = $tab.Name
    $btn.Add_Click({
        $clickedTab = $this.Tag
        foreach ($nb in $global:NavButtons) {
            if ($nb.Tag -eq $clickedTab) { $nb.BackColor = $colors.SidebarActive; $nb.ForeColor = $colors.Gold; $nb.Font = $fonts.NavBtnAct }
            else { $nb.BackColor = $colors.Sidebar; $nb.ForeColor = $colors.TextSecondary; $nb.Font = $fonts.NavBtn }
        }
        foreach ($key in $global:TabPanels.Keys) { $global:TabPanels[$key].Visible = ($key -eq $clickedTab) }
        if ($global:TabPanels.ContainsKey($clickedTab)) { $global:TabPanels[$clickedTab].BringToFront() }
        $global:ActiveTab = $clickedTab
        if ($clickedTab -eq 'Dashboard') { Refresh-Dashboard }
        if ($clickedTab -eq 'Remediation Plan') { Refresh-RemediationPlan }
        if ($clickedTab -eq 'Weekly Export') { Refresh-WeeklyExportTab }
        if ($clickedTab -eq 'Dirty 30 Triage') { Refresh-Dirty30Tab }
        if ($clickedTab -eq 'CORA Vulnerabilities') { Refresh-CoraVulnTab }
    }.GetNewClosure())
    $sidebar.Controls.Add($btn); $global:NavButtons += $btn; $navY += 42
}
$script:statusOutput = New-OutputBox -Location ([System.Drawing.Point]::new(5, $navY + 20)) -Size ([System.Drawing.Size]::new(170, 260))
$script:statusOutput.Anchor = 'Top,Left,Bottom'
$sidebar.Controls.Add($script:statusOutput)

## Close Tool button moved to the top bar (top-right). Single egress
## matches the WPT pattern.
#endregion

#region === UI: CONTENT AREA ===
$contentArea = New-Object System.Windows.Forms.Panel
$contentArea.Dock = 'Fill'; $contentArea.BackColor = $colors.Background
$contentArea.Padding = New-Object System.Windows.Forms.Padding(10)
$f.Controls.Add($contentArea); $f.Controls.Add($sidebar); $f.Controls.Add($topBar)
#endregion

#region === TAB 1: ACAS IMPORT ===
$panelAcas = New-Object System.Windows.Forms.Panel
$panelAcas.Dock = 'Fill'; $panelAcas.BackColor = $colors.Background; $panelAcas.Visible = $false
$contentArea.Controls.Add($panelAcas); $global:TabPanels['ACAS Import'] = $panelAcas

$lblAcasHeader = New-Object System.Windows.Forms.Label
$lblAcasHeader.Text = "ACAS SCAN IMPORT"; $lblAcasHeader.Location = [System.Drawing.Point]::new(10, 8)
$lblAcasHeader.AutoSize = $true; $lblAcasHeader.Font = $fonts.Subtitle; $lblAcasHeader.ForeColor = $colors.Gold
$panelAcas.Controls.Add($lblAcasHeader)

$btnImportAcas = New-StyledButton -Text "Import ACAS CSV/TSV" -Location ([System.Drawing.Point]::new(10, 38)) -Size ([System.Drawing.Size]::new(180, 32)) -BgColor $colors.Accent
$panelAcas.Controls.Add($btnImportAcas)
$btnClearAcas = New-StyledButton -Text "Clear All" -Location ([System.Drawing.Point]::new(200, 38)) -Size ([System.Drawing.Size]::new(100, 32)) -BgColor $colors.Danger
$panelAcas.Controls.Add($btnClearAcas)
$btnLoadJson = New-StyledButton -Text "Load Saved Report (JSON)" -Location ([System.Drawing.Point]::new(310, 38)) -Size ([System.Drawing.Size]::new(200, 32)) -BgColor $colors.PanelLight
$panelAcas.Controls.Add($btnLoadJson)

$script:lblAcasCount = New-Object System.Windows.Forms.Label
$script:lblAcasCount.Text = "No findings loaded"; $script:lblAcasCount.Location = [System.Drawing.Point]::new(520, 44)
$script:lblAcasCount.AutoSize = $true; $script:lblAcasCount.Font = $fonts.SmallBold; $script:lblAcasCount.ForeColor = $colors.TextSecondary
$panelAcas.Controls.Add($script:lblAcasCount)

# === View toggle bar (Online / Offline / All) + Ping + Export ===
$viewBar = New-Object System.Windows.Forms.Panel
$viewBar.Location = [System.Drawing.Point]::new(10, 76); $viewBar.Size = [System.Drawing.Size]::new(1180, 34)
$viewBar.BackColor = $colors.Panel; $viewBar.Anchor = 'Top,Left,Right'
$panelAcas.Controls.Add($viewBar)

$lblView = New-Object System.Windows.Forms.Label; $lblView.Text = "VIEW:"; $lblView.Location = [System.Drawing.Point]::new(8, 8)
$lblView.AutoSize = $true; $lblView.Font = $fonts.SmallBold; $lblView.ForeColor = $colors.Gold; $viewBar.Controls.Add($lblView)

$script:btnViewOnline = New-StyledButton -Text "Online (0)" -Location ([System.Drawing.Point]::new(55, 3)) -Size ([System.Drawing.Size]::new(110, 26)) -BgColor $colors.Success
$script:btnViewOnline.Add_Click({ Set-ActiveView 'Online' }); $viewBar.Controls.Add($script:btnViewOnline)

$script:btnViewOffline = New-StyledButton -Text "Offline (0)" -Location ([System.Drawing.Point]::new(170, 3)) -Size ([System.Drawing.Size]::new(110, 26)) -BgColor $colors.PanelLight
$script:btnViewOffline.ForeColor = $colors.TextSecondary
$script:btnViewOffline.Add_Click({ Set-ActiveView 'Offline' }); $viewBar.Controls.Add($script:btnViewOffline)

$script:btnViewAll = New-StyledButton -Text "All (0)" -Location ([System.Drawing.Point]::new(285, 3)) -Size ([System.Drawing.Size]::new(90, 26)) -BgColor $colors.PanelLight
$script:btnViewAll.ForeColor = $colors.TextSecondary
$script:btnViewAll.Add_Click({ Set-ActiveView 'All' }); $viewBar.Controls.Add($script:btnViewAll)

$btnPingAll = New-StyledButton -Text "Re-Ping Hosts" -Location ([System.Drawing.Point]::new(400, 3)) -Size ([System.Drawing.Size]::new(120, 26)) -BgColor $colors.Cyan
$btnPingAll.Add_Click({ Ping-AllHosts; Refresh-AcasGrid }); $viewBar.Controls.Add($btnPingAll)

$btnExportExcel = New-StyledButton -Text "Export to Excel" -Location ([System.Drawing.Point]::new(535, 3)) -Size ([System.Drawing.Size]::new(130, 26)) -BgColor $colors.PanelLight
$btnExportExcel.Anchor = 'Top,Left'
$btnExportExcel.Add_Click({
    if ($global:AcasFindings.Count -eq 0) { [WptDialog]::Show("No findings to export.", "Empty", 'OK', 'Information'); return }

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        [WptDialog]::Show("ImportExcel module not found.`n`nInstall with:`n  Install-Module ImportExcel -Scope CurrentUser", "Module Missing", 'OK', 'Error')
        return
    }
    try { Import-Module ImportExcel -ErrorAction Stop } catch {
        [WptDialog]::Show("Failed to load ImportExcel:`n`n$_", "Module Error", 'OK', 'Error'); return
    }

    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Excel Files|*.xlsx|All Files|*.*"; $dlg.Title = "Export ACAS Report to Excel"
    $dlg.FileName = "ACAS_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    Log "Exporting to Excel: $(Split-Path $dlg.FileName -Leaf)"

    # ImportExcel/EPPlus appends to existing files; remove first to guarantee a clean book.
    if (Test-Path -LiteralPath $dlg.FileName) {
        try { Remove-Item -LiteralPath $dlg.FileName -Force -ErrorAction Stop } catch {
            Log "ERROR overwriting existing file: $_"
            [WptDialog]::Show("Cannot overwrite existing file (is it open in Excel?).`n`n$_", "Export Error", 'OK', 'Error')
            return
        }
    }

    $pkg = $null
    $exportOk = $false
    $onlineFindings = @(); $notOursFindings = @(); $apacheFindings = @(); $offlineFindings = @()

    # Original COM code stored colors in Excel's BGR order; converted here to RGB hex for EPPlus.
    $hdrBg    = '#0A0B0E'   # was 0x0E0B0A BGR
    $hdrFg    = '#FFB020'   # was 0x20B0FF BGR
    $blockBg  = '#080D11'   # was 0x110D08 BGR
    $subHdrFg = '#FFC94A'   # was 0x4AC9FF BGR
    $emptyFg  = '#6A6F78'   # was 0x786F6A BGR

    $applyHeaderBand = {
        param($ws, [int]$row, [int]$colCount)
        $rng = $ws.Cells[$row, 1, $row, $colCount]
        $rng.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $rng.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml($hdrBg))
        $rng.Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($hdrFg))
        $rng.Style.Font.Bold = $true
    }

    $writeTabular = {
        param($package, [string]$sheetName, $rows, [string]$path)
        $headers = @('Hostname','Plugin ID','Vuln Name','Severity','CVE','Category','Status','Solution')
        if (@($rows).Count -eq 0) {
            # Empty-set sheet: write headers manually so the tab is still useful.
            $ws = $package.Workbook.Worksheets.Add($sheetName)
            for ($i = 0; $i -lt $headers.Count; $i++) { $ws.Cells[1, $i + 1].Value = $headers[$i] }
            & $applyHeaderBand $ws 1 $headers.Count
            $ws.Cells[2, 1].Value = '(no findings)'
            $ws.Cells[2, 1].Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($emptyFg))
            for ($c = 1; $c -le $headers.Count; $c++) { $ws.Column($c).AutoFit() }
            return $package
        }
        $exportArgs = @{
            WorksheetName = $sheetName
            AutoSize      = $true
            FreezeTopRow  = $true
            PassThru      = $true
        }
        if ($null -eq $package) { $exportArgs.Path = $path } else { $exportArgs.ExcelPackage = $package }
        $newPkg = $rows | Export-Excel @exportArgs
        & $applyHeaderBand $newPkg.Workbook.Worksheets[$sheetName] 1 $headers.Count
        return $newPkg
    }

    $projectRows = {
        param($findings)
        ,@($findings | Select-Object `
            @{N='Hostname'; E={$_.Hostname}}, `
            @{N='Plugin ID';E={$_.PluginID}}, `
            @{N='Vuln Name';E={$_.VulnName}}, `
            @{N='Severity'; E={$_.Severity}}, `
            @{N='CVE';      E={$_.CVE}}, `
            @{N='Category'; E={$_.Category}}, `
            @{N='Status';   E={$_.Status}}, `
            @{N='Solution'; E={$_.Solution}})
    }

    try {
        # Filter logic (unchanged from COM version)
        $onlineFindings = if ($global:HostStatus.Count -gt 0) {
            @($global:AcasFindings | Where-Object { $global:HostStatus[$_.Hostname] -eq 'Online' -and $_.Category -ne 'NOT OUR PATCH' -and $_.Category -ne 'Apache' })
        } else { @($global:AcasFindings | Where-Object { $_.Category -ne 'NOT OUR PATCH' -and $_.Category -ne 'Apache' }) }
        $notOursFindings = @($global:AcasFindings | Where-Object { $_.Category -eq 'NOT OUR PATCH' })
        $apacheFindings  = @($global:AcasFindings | Where-Object { $_.Category -eq 'Apache' })
        $offlineFindings = if ($global:HostStatus.Count -gt 0) {
            @($global:AcasFindings | Where-Object { $global:HostStatus[$_.Hostname] -eq 'Offline' })
        } else { @() }

        # Sheets 1-3: tabular
        $pkg = & $writeTabular $null  'Vulnerabilities' (& $projectRows $onlineFindings)  $dlg.FileName
        $pkg = & $writeTabular $pkg   'NOT OUR PATCH'   (& $projectRows $notOursFindings) $dlg.FileName
        $pkg = & $writeTabular $pkg   'Apache'          (& $projectRows $apacheFindings)  $dlg.FileName

        # Sheet 4: Offline (grouped by host with banded blocks — built by direct cell access)
        $ws4 = $pkg.Workbook.Worksheets.Add('Offline')
        $offlineHosts = $offlineFindings | Group-Object -Property Hostname | Sort-Object Name
        $row = 1
        foreach ($hostGroup in $offlineHosts) {
            $ws4.Cells[$row, 1].Value = $hostGroup.Name
            $ws4.Cells[$row, 2].Value = "$($hostGroup.Count) finding(s) - OFFLINE"
            $bandRng = $ws4.Cells[$row, 1, $row, 8]
            $bandRng.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $bandRng.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml($blockBg))
            $bandRng.Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($hdrFg))
            $bandRng.Style.Font.Bold = $true
            $bandRng.Style.Font.Size = 11
            $row++

            $subHdrs = @('Plugin ID','Vuln Name','Severity','CVE','Category','Status','Solution')
            for ($c = 0; $c -lt $subHdrs.Count; $c++) {
                $cell = $ws4.Cells[$row, $c + 1]
                $cell.Value = $subHdrs[$c]
                $cell.Style.Font.Bold = $true
                $cell.Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($subHdrFg))
            }
            $row++

            foreach ($f in ($hostGroup.Group | Sort-Object Severity)) {
                $ws4.Cells[$row, 1].Value = $f.PluginID
                $ws4.Cells[$row, 2].Value = $f.VulnName
                $ws4.Cells[$row, 3].Value = $f.Severity
                $ws4.Cells[$row, 4].Value = $f.CVE
                $ws4.Cells[$row, 5].Value = $f.Category
                $ws4.Cells[$row, 6].Value = $f.Status
                $ws4.Cells[$row, 7].Value = $f.Solution
                $row++
            }
            $row++
        }
        if ($offlineHosts.Count -eq 0) {
            $ws4.Cells[1, 1].Value = "No offline machines detected"
            $ws4.Cells[1, 1].Style.Font.Color.SetColor([System.Drawing.ColorTranslator]::FromHtml($emptyFg))
        }
        for ($c = 1; $c -le 8; $c++) { $ws4.Column($c).AutoFit() }

        Close-ExcelPackage $pkg
        $pkg = $null
        $exportOk = $true
        Log "Excel exported: Vulns=$($onlineFindings.Count), NOT OUR PATCH=$($notOursFindings.Count), Apache=$($apacheFindings.Count), Offline=$($offlineFindings.Count)"
    } catch {
        Log "ERROR exporting Excel: $_"
        Write-DebugLog "[EXPORT EXCEL] EXCEPTION: $_"
        [WptDialog]::Show("Excel export failed.`n`nError: $_", "Export Error", 'OK', 'Error')
    } finally {
        if ($pkg) { try { Close-ExcelPackage $pkg -NoSave } catch {} }
    }

    if ($exportOk) {
        [WptDialog]::Show("Excel report exported!`n`nSheets:`n  Vulnerabilities: $($onlineFindings.Count)`n  NOT OUR PATCH: $($notOursFindings.Count)`n  Apache: $($apacheFindings.Count)`n  Offline: $($offlineFindings.Count)`n`n$($dlg.FileName)", "Exported", 'OK', 'Information')
    }
})
$viewBar.Controls.Add($btnExportExcel)

# Search bar
$searchBar = New-Object System.Windows.Forms.Panel
$searchBar.Location = [System.Drawing.Point]::new(10, 114); $searchBar.Size = [System.Drawing.Size]::new(1180, 32)
$searchBar.BackColor = $colors.Panel; $searchBar.Anchor = 'Top,Left,Right'
$panelAcas.Controls.Add($searchBar)
$lblSearch = New-Object System.Windows.Forms.Label
$lblSearch.Text = "Search:"; $lblSearch.Location = [System.Drawing.Point]::new(8, 7); $lblSearch.AutoSize = $true
$lblSearch.ForeColor = $colors.TextSecondary; $lblSearch.Font = $fonts.Small
$searchBar.Controls.Add($lblSearch)
$script:txtSearchFilter = New-Object System.Windows.Forms.TextBox
$script:txtSearchFilter.Location = [System.Drawing.Point]::new(55, 4); $script:txtSearchFilter.Size = [System.Drawing.Size]::new(350, 24)
$script:txtSearchFilter.BackColor = $colors.Input; $script:txtSearchFilter.ForeColor = $colors.TextPrimary
$script:txtSearchFilter.Font = $fonts.Console; $script:txtSearchFilter.BorderStyle = 'FixedSingle'
$searchBar.Controls.Add($script:txtSearchFilter)
$script:searchTimer = New-Object System.Windows.Forms.Timer
$script:searchTimer.Interval = 400
$script:searchTimer.Add_Tick({ $script:searchTimer.Stop(); Refresh-AcasGrid })
$script:txtSearchFilter.Add_TextChanged({ $script:searchTimer.Stop(); $script:searchTimer.Start() })

# Filter bar (two rows: dropdowns top, action buttons bottom)
$filterBar = New-Object System.Windows.Forms.Panel
$filterBar.Location = [System.Drawing.Point]::new(10, 150); $filterBar.Size = [System.Drawing.Size]::new(1180, 68)
$filterBar.BackColor = $colors.Panel; $filterBar.Anchor = 'Top,Left,Right'
$panelAcas.Controls.Add($filterBar)

# Row 1: filter dropdowns
$lblFHost = New-Object System.Windows.Forms.Label
$lblFHost.Text = "Host:"; $lblFHost.Location = [System.Drawing.Point]::new(8, 8); $lblFHost.AutoSize = $true; $lblFHost.ForeColor = $colors.TextSecondary; $lblFHost.Font = $fonts.Small
$filterBar.Controls.Add($lblFHost)
$script:cmbHostFilter = New-Object System.Windows.Forms.ComboBox
$script:cmbHostFilter.Location = [System.Drawing.Point]::new(42, 5); $script:cmbHostFilter.Size = [System.Drawing.Size]::new(200, 24)
$script:cmbHostFilter.BackColor = $colors.Input; $script:cmbHostFilter.ForeColor = $colors.TextPrimary; $script:cmbHostFilter.Font = $fonts.Small; $script:cmbHostFilter.DropDownStyle = 'DropDownList'
[void]$script:cmbHostFilter.Items.Add('(All Hosts)'); $script:cmbHostFilter.SelectedIndex = 0
$script:cmbHostFilter.Add_SelectedIndexChanged({ Refresh-AcasGrid }); $filterBar.Controls.Add($script:cmbHostFilter)

$lblFSev = New-Object System.Windows.Forms.Label; $lblFSev.Text = "Severity:"; $lblFSev.Location = [System.Drawing.Point]::new(252, 8); $lblFSev.AutoSize = $true; $lblFSev.ForeColor = $colors.TextSecondary; $lblFSev.Font = $fonts.Small; $filterBar.Controls.Add($lblFSev)
$script:cmbSevFilter = New-Object System.Windows.Forms.ComboBox
$script:cmbSevFilter.Location = [System.Drawing.Point]::new(310, 5); $script:cmbSevFilter.Size = [System.Drawing.Size]::new(140, 24)
$script:cmbSevFilter.BackColor = $colors.Input; $script:cmbSevFilter.ForeColor = $colors.TextPrimary; $script:cmbSevFilter.Font = $fonts.Small; $script:cmbSevFilter.DropDownStyle = 'DropDownList'
foreach ($s in @('(All Severities)','Critical','High','Medium','Low','Info')) { [void]$script:cmbSevFilter.Items.Add($s) }
$script:cmbSevFilter.SelectedIndex = 0; $script:cmbSevFilter.Add_SelectedIndexChanged({ Refresh-AcasGrid }); $filterBar.Controls.Add($script:cmbSevFilter)

$lblFCat = New-Object System.Windows.Forms.Label; $lblFCat.Text = "Category:"; $lblFCat.Location = [System.Drawing.Point]::new(460, 8); $lblFCat.AutoSize = $true; $lblFCat.ForeColor = $colors.TextSecondary; $lblFCat.Font = $fonts.Small; $filterBar.Controls.Add($lblFCat)
$script:cmbCatFilter = New-Object System.Windows.Forms.ComboBox
$script:cmbCatFilter.Location = [System.Drawing.Point]::new(520, 5); $script:cmbCatFilter.Size = [System.Drawing.Size]::new(150, 24)
$script:cmbCatFilter.BackColor = $colors.Input; $script:cmbCatFilter.ForeColor = $colors.TextPrimary; $script:cmbCatFilter.Font = $fonts.Small; $script:cmbCatFilter.DropDownStyle = 'DropDownList'
foreach ($c in @('(All Categories)','Chrome','Edge','Apache','Office','KB Patch','Registry Fix','NOT OUR PATCH','Other')) { [void]$script:cmbCatFilter.Items.Add($c) }
$script:cmbCatFilter.SelectedIndex = 0; $script:cmbCatFilter.Add_SelectedIndexChanged({ Refresh-AcasGrid }); $filterBar.Controls.Add($script:cmbCatFilter)

$lblFStat = New-Object System.Windows.Forms.Label; $lblFStat.Text = "Status:"; $lblFStat.Location = [System.Drawing.Point]::new(680, 8); $lblFStat.AutoSize = $true; $lblFStat.ForeColor = $colors.TextSecondary; $lblFStat.Font = $fonts.Small; $filterBar.Controls.Add($lblFStat)
$script:cmbStatFilter = New-Object System.Windows.Forms.ComboBox
$script:cmbStatFilter.Location = [System.Drawing.Point]::new(730, 5); $script:cmbStatFilter.Size = [System.Drawing.Size]::new(140, 24)
$script:cmbStatFilter.BackColor = $colors.Input; $script:cmbStatFilter.ForeColor = $colors.TextPrimary; $script:cmbStatFilter.Font = $fonts.Small; $script:cmbStatFilter.DropDownStyle = 'DropDownList'
foreach ($st in @('(All Statuses)','Open','Patched','NOT OUR PATCH')) { [void]$script:cmbStatFilter.Items.Add($st) }
$script:cmbStatFilter.SelectedIndex = 0; $script:cmbStatFilter.Add_SelectedIndexChanged({ Refresh-AcasGrid }); $filterBar.Controls.Add($script:cmbStatFilter)

$btnResetFilters = New-StyledButton -Text "Reset" -Location ([System.Drawing.Point]::new(880, 3)) -Size ([System.Drawing.Size]::new(70, 28)) -BgColor $colors.PanelLight
$btnResetFilters.Anchor = 'Top,Right'
$btnResetFilters.Add_Click({ $script:cmbHostFilter.SelectedIndex = 0; $script:cmbSevFilter.SelectedIndex = 0; $script:cmbCatFilter.SelectedIndex = 0; $script:cmbStatFilter.SelectedIndex = 0; $script:txtSearchFilter.Text = ''; Refresh-AcasGrid })
$filterBar.Controls.Add($btnResetFilters)

$btnMarkNotOurs = New-StyledButton -Text "Mark NOT OUR PATCH" -Location ([System.Drawing.Point]::new(960, 3)) -Size ([System.Drawing.Size]::new(160, 28)) -BgColor $colors.Cyan
$btnMarkNotOurs.Anchor = 'Top,Right'
$btnMarkNotOurs.Add_Click({
    if (-not $script:gridAcas -or $script:gridAcas.SelectedRows.Count -eq 0) { [WptDialog]::Show("Select one or more rows first.", "No Selection", 'OK', 'Warning'); return }
    $count = 0
    $idx = Get-AcasFindingIndex
    foreach ($row in $script:gridAcas.SelectedRows) {
        $key = "$($row.Cells[0].Value)|$($row.Cells[1].Value)"
        $finding = $idx[$key]
        if ($finding) { $finding.Category = 'NOT OUR PATCH'; $finding.Status = 'NOT OUR PATCH'; $count++ }
    }
    Log "Marked $count findings as NOT OUR PATCH"; Refresh-AcasGrid
})
$filterBar.Controls.Add($btnMarkNotOurs)

# Row 2: batch buttons (left) and per-selection buttons (right)
$btnBatchNotOurs = New-StyledButton -Text "Mark All Visible: NOT OUR PATCH" -Location ([System.Drawing.Point]::new(8, 35)) -Size ([System.Drawing.Size]::new(240, 28)) -BgColor $colors.Cyan
$btnBatchNotOurs.Add_Click({
    $filtered = Get-FilteredFindings; $actionable = @($filtered | Where-Object { $_.Status -ne 'NOT OUR PATCH' })
    if ($actionable.Count -eq 0) { [WptDialog]::Show("No actionable findings in the current filtered view.", "Nothing to Mark", 'OK', 'Information'); return }
    $confirm = [WptDialog]::Show("Mark $($actionable.Count) filtered finding(s) as NOT OUR PATCH?", "Confirm Batch Mark", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }
    foreach ($finding in $actionable) { $finding.Category = 'NOT OUR PATCH'; $finding.Status = 'NOT OUR PATCH' }
    Log "Batch marked $($actionable.Count) findings as NOT OUR PATCH"; Refresh-AcasGrid; Refresh-Dashboard
})
$filterBar.Controls.Add($btnBatchNotOurs)

$btnBatchPatched = New-StyledButton -Text "Mark All Visible: Patched" -Location ([System.Drawing.Point]::new(256, 35)) -Size ([System.Drawing.Size]::new(200, 28)) -BgColor $colors.Success
$btnBatchPatched.Add_Click({
    $filtered = Get-FilteredFindings; $actionable = @($filtered | Where-Object { $_.Status -ne 'Patched' -and $_.Status -ne 'NOT OUR PATCH' })
    if ($actionable.Count -eq 0) { [WptDialog]::Show("No actionable findings in the current filtered view.", "Nothing to Mark", 'OK', 'Information'); return }
    $r = Show-PatchedByDateDialog -HeaderText "Mark $($actionable.Count) filtered finding(s) as Patched" -Title "Batch Mark as Patched" -ConfirmButtonText "Mark All Patched"
    if (-not $r.OK) { return }
    foreach ($finding in $actionable) { $finding.Status = 'Patched'; $finding.PatchedDate = $r.Date; $finding.PatchedBy = $r.By }
    Log "Batch marked $($actionable.Count) findings as Patched (by: $($r.By))"; Refresh-AcasGrid; Refresh-Dashboard
})
$filterBar.Controls.Add($btnBatchPatched)

$btnMarkPatched = New-StyledButton -Text "Mark Patched" -Location ([System.Drawing.Point]::new(960, 35)) -Size ([System.Drawing.Size]::new(120, 28)) -BgColor $colors.Success
$btnMarkPatched.Anchor = 'Top,Right'
$btnMarkPatched.Add_Click({
    if (-not $script:gridAcas -or $script:gridAcas.SelectedRows.Count -eq 0) { [WptDialog]::Show("Select one or more rows first.", "No Selection", 'OK', 'Warning'); return }
    $r = Show-PatchedByDateDialog -HeaderText "Mark $($script:gridAcas.SelectedRows.Count) finding(s) as Patched" -Title "Mark as Patched" -ConfirmButtonText "Mark Patched" -Width 400
    if (-not $r.OK) { return }
    $count = 0
    $idx = Get-AcasFindingIndex
    foreach ($row in $script:gridAcas.SelectedRows) {
        $key = "$($row.Cells[0].Value)|$($row.Cells[1].Value)"
        $finding = $idx[$key]
        if ($finding) { $finding.Status = 'Patched'; $finding.PatchedDate = $r.Date; $finding.PatchedBy = $r.By; $count++ }
    }
    Log "Marked $count findings as Patched (by: $($r.By))"; Refresh-AcasGrid; Refresh-Dashboard
})
$filterBar.Controls.Add($btnMarkPatched)

$btnUndoStatus = New-StyledButton -Text "Undo Status" -Location ([System.Drawing.Point]::new(1090, 35)) -Size ([System.Drawing.Size]::new(90, 28)) -BgColor $colors.PanelLight
$btnUndoStatus.Anchor = 'Top,Right'
$btnUndoStatus.Add_Click({
    if (-not $script:gridAcas -or $script:gridAcas.SelectedRows.Count -eq 0) { [WptDialog]::Show("Select one or more rows first.", "No Selection", 'OK', 'Warning'); return }
    $confirm = [WptDialog]::Show("Reset $($script:gridAcas.SelectedRows.Count) finding(s) back to Open status?", "Confirm Undo", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }
    $count = 0
    $idx = Get-AcasFindingIndex
    foreach ($row in $script:gridAcas.SelectedRows) {
        $key = "$($row.Cells[0].Value)|$($row.Cells[1].Value)"
        $finding = $idx[$key]
        if ($finding) {
            $finding.Category = Categorize-Finding -VulnName $finding.VulnName -Solution $finding.Solution -PluginID $finding.PluginID
            $finding.Status = if ($finding.Category -eq 'NOT OUR PATCH') { 'NOT OUR PATCH' } else { 'Open' }
            $finding.PatchedDate = ""; $finding.PatchedBy = ""; $count++
        }
    }
    Log "Reset $count findings back to Open status"; Refresh-AcasGrid; Refresh-Dashboard
})
$filterBar.Controls.Add($btnUndoStatus)

# ACAS data grid
$script:gridAcas = New-StyledGrid -Location ([System.Drawing.Point]::new(10, 224)) -Size ([System.Drawing.Size]::new(1180, 446))
$script:gridAcas.Anchor = 'Top,Left,Right,Bottom'
foreach ($col in @(@{N='Hostname';W=130},@{N='PluginID';W=80},@{N='Vuln Name';W=300},@{N='Severity';W=80},@{N='CVE';W=110},@{N='Category';W=120},@{N='Status';W=100},@{N='Solution';W=260})) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $c.HeaderText = $col.N; $c.Width = $col.W; $c.Name = $col.N; [void]$script:gridAcas.Columns.Add($c)
}
$panelAcas.Controls.Add($script:gridAcas)

# === WELCOME / EMPTY STATE PANEL ===
$script:pnlWelcome = New-Object System.Windows.Forms.Panel
$script:pnlWelcome.Location = [System.Drawing.Point]::new(10, 224)
$script:pnlWelcome.Size = [System.Drawing.Size]::new(1180, 446)
$script:pnlWelcome.BackColor = $colors.Background
$script:pnlWelcome.Anchor = 'Top,Left,Right,Bottom'
$panelAcas.Controls.Add($script:pnlWelcome)
$script:pnlWelcome.BringToFront()

$welcomeCard = New-Object System.Windows.Forms.Panel
$welcomeCard.Size = [System.Drawing.Size]::new(520, 360)
$welcomeCard.Location = [System.Drawing.Point]::new(330, 40)
$welcomeCard.BackColor = $colors.CardBg
$script:pnlWelcome.Controls.Add($welcomeCard)

$welcomeAccent = New-Object System.Windows.Forms.Panel
$welcomeAccent.Location = [System.Drawing.Point]::new(0, 0); $welcomeAccent.Size = [System.Drawing.Size]::new(520, 3)
$welcomeAccent.BackColor = $colors.Gold
$welcomeCard.Controls.Add($welcomeAccent)

$lblWelcTitle = New-Object System.Windows.Forms.Label
$lblWelcTitle.Text = "J.A.N.E.T. Reports Tool"; $lblWelcTitle.Location = [System.Drawing.Point]::new(24, 20)
$lblWelcTitle.AutoSize = $true; $lblWelcTitle.Font = $fonts.Title; $lblWelcTitle.ForeColor = $colors.Gold
$welcomeCard.Controls.Add($lblWelcTitle)

$lblWelcSub = New-Object System.Windows.Forms.Label
$lblWelcSub.Text = "ACAS Reports & Patch Cross-Reference  |  v2.14.0"
$lblWelcSub.Location = [System.Drawing.Point]::new(24, 48); $lblWelcSub.AutoSize = $true
$lblWelcSub.Font = $fonts.Label; $lblWelcSub.ForeColor = $colors.TextSecondary
$welcomeCard.Controls.Add($lblWelcSub)

$welcomeDiv = New-Object System.Windows.Forms.Panel
$welcomeDiv.Location = [System.Drawing.Point]::new(24, 74); $welcomeDiv.Size = [System.Drawing.Size]::new(472, 1)
$welcomeDiv.BackColor = $colors.InputBorder
$welcomeCard.Controls.Add($welcomeDiv)

$lblQS = New-Object System.Windows.Forms.Label
$lblQS.Text = "QUICK START"; $lblQS.Location = [System.Drawing.Point]::new(24, 88)
$lblQS.AutoSize = $true; $lblQS.Font = $fonts.SmallBold; $lblQS.ForeColor = $colors.Gold
$welcomeCard.Controls.Add($lblQS)

$welcomeSteps = @(
    @{ Num="1"; Text="Import ACAS scan data (CSV, TSV, or .nessus); use Re-Ping Hosts to sort online vs offline when needed"; Color=$colors.Accent }
    @{ Num="2"; Text="Triage findings: filter by category, then batch-mark as NOT OUR PATCH or Patched"; Color=$colors.Purple }
    @{ Num="3"; Text="Compare scans on the Cross-Ref tab: load before/after ACAS exports to see what got fixed"; Color=$colors.Success }
    @{ Num="4"; Text="Check your compliance on the Dashboard tab (target: 90%+ patch rate)"; Color=$colors.Warning }
    @{ Num="5"; Text="Export reports on the Export tab for weekly submissions and documentation"; Color=$colors.Cyan }
)
$stepY = 114
foreach ($step in $welcomeSteps) {
    $lblNum = New-Object System.Windows.Forms.Label
    $lblNum.Text = $step.Num; $lblNum.Location = [System.Drawing.Point]::new(32, $stepY)
    $lblNum.Size = [System.Drawing.Size]::new(26, 26); $lblNum.Font = $fonts.LabelBold
    $lblNum.ForeColor = $colors.TextPrimary; $lblNum.TextAlign = 'MiddleCenter'; $lblNum.BackColor = $step.Color
    $welcomeCard.Controls.Add($lblNum)
    $lblStep = New-Object System.Windows.Forms.Label
    $lblStep.Text = $step.Text; $lblStep.Location = [System.Drawing.Point]::new(68, $stepY + 3)
    $lblStep.Size = [System.Drawing.Size]::new(430, 34); $lblStep.Font = $fonts.Label; $lblStep.ForeColor = $colors.TextSecondary
    $welcomeCard.Controls.Add($lblStep)
    $stepY += 40
}

$lblWelcTip = New-Object System.Windows.Forms.Label
$lblWelcTip.Text = "TIP: You can also load a previously saved JSON report using the purple button above."
$lblWelcTip.Location = [System.Drawing.Point]::new(24, 326); $lblWelcTip.AutoSize = $true
$lblWelcTip.Font = $fonts.Small; $lblWelcTip.ForeColor = $colors.TextDim
$welcomeCard.Controls.Add($lblWelcTip)

# === ACAS Import Button ===
$btnImportAcas.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "ACAS/Nessus Files|*.csv;*.tsv;*.nessus|CSV/TSV Files|*.csv;*.tsv|Nessus XML|*.nessus|All Files|*.*"
    $dlg.Title = "Select ACAS Export File"; $dlg.Multiselect = $true
    if ($dlg.ShowDialog() -ne 'OK') { return }

    $existingKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($ef in $global:AcasFindings) { [void]$existingKeys.Add("$($ef.Hostname)|$($ef.PluginID)") }

    foreach ($filePath in $dlg.FileNames) {
        $leaf = Split-Path $filePath -Leaf
        Log "Importing: $leaf"
        try {
            $parsed = Parse-AcasFile -FilePath $filePath
            if (-not $parsed -or $parsed.Count -eq 0) {
                Log "WARNING: No findings parsed from $leaf (check columns or format)"
                continue
            }
            $importCount = 0; $dupeCount = 0
            foreach ($f in $parsed) {
                $key = "$($f.Hostname)|$($f.PluginID)"
                if ($existingKeys.Contains($key)) { $dupeCount++; continue }
                [void]$existingKeys.Add($key)
                [void]$global:AcasFindings.Add($f)
                $importCount++
            }
            $dupeMsg = if ($dupeCount -gt 0) { " ($dupeCount duplicates skipped)" } else { "" }
            Log "Imported $importCount findings from $leaf$dupeMsg"
        } catch { Log "ERROR importing $leaf : $_" }
    }
    Refresh-AcasHostDropdown
    Set-ActiveView 'All'
    Refresh-AcasGrid; Refresh-Dashboard
})

$btnClearAcas.Add_Click({
    $result = [WptDialog]::Show("Clear all ACAS findings?", "Confirm Clear", 'YesNo', 'Warning')
    if ($result -ne 'Yes') { return }
    $global:AcasFindings.Clear(); $global:HostStatus.Clear()
    Refresh-AcasHostDropdown
    Refresh-AcasGrid; Refresh-Dashboard; Refresh-XrefGrid
    Update-ViewButtons; Set-ActiveView 'Online'
    Show-WelcomePanel
    Log "All data cleared"
})

$btnLoadJson.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "JSON Files|*.json|All Files|*.*"; $dlg.Title = "Load Saved Report"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $json = Get-Content $dlg.FileName -Raw -Encoding UTF8 | ConvertFrom-Json
        $global:AcasFindings.Clear()
        if ($json.Findings) {
            foreach ($item in $json.Findings) {
                [void]$global:AcasFindings.Add([PSCustomObject]@{
                    Hostname    = $item.Hostname
                    PluginID    = $item.PluginID
                    VulnName    = $item.VulnName
                    Severity    = $item.Severity
                    CVE         = $item.CVE
                    Category    = $item.Category
                    Status      = $item.Status
                    Solution    = $item.Solution
                    PatchedDate = $item.PatchedDate
                    PatchedBy   = $item.PatchedBy
                })
            }
        }
        Refresh-AcasHostDropdown
        Ping-AllHosts; Set-ActiveView 'Online'
        Refresh-AcasGrid; Refresh-XrefGrid; Refresh-Dashboard
        Log "Loaded report from $(Split-Path $dlg.FileName -Leaf): $($global:AcasFindings.Count) findings"
    } catch { Log "ERROR loading JSON: $_" }
})
#endregion

#region === TAB 2: PATCH CROSS-REFERENCE (SCAN COMPARISON) ===
$panelXref = New-Object System.Windows.Forms.Panel
$panelXref.Dock = 'Fill'; $panelXref.BackColor = $colors.Background; $panelXref.Visible = $false
$contentArea.Controls.Add($panelXref); $global:TabPanels['Patch Cross-Ref'] = $panelXref

$lblXrefHeader = New-Object System.Windows.Forms.Label; $lblXrefHeader.Text = "SCAN COMPARISON & CROSS-REFERENCE"; $lblXrefHeader.Location = [System.Drawing.Point]::new(10, 8); $lblXrefHeader.AutoSize = $true; $lblXrefHeader.Font = $fonts.Subtitle; $lblXrefHeader.ForeColor = $colors.Gold; $panelXref.Controls.Add($lblXrefHeader)

# === Row 1: Baseline scan ===
$lblBaseline = New-Object System.Windows.Forms.Label; $lblBaseline.Text = "BASELINE (Before):"; $lblBaseline.Location = [System.Drawing.Point]::new(10, 42); $lblBaseline.AutoSize = $true; $lblBaseline.Font = $fonts.LabelBold; $lblBaseline.ForeColor = $colors.Warning; $panelXref.Controls.Add($lblBaseline)
$btnLoadBaseline = New-StyledButton -Text "Load Baseline Scan" -Location ([System.Drawing.Point]::new(160, 38)) -Size ([System.Drawing.Size]::new(180, 30)) -BgColor $colors.PanelLight; $panelXref.Controls.Add($btnLoadBaseline)
$script:lblBaselineInfo = New-Object System.Windows.Forms.Label; $script:lblBaselineInfo.Text = "No file loaded"; $script:lblBaselineInfo.Location = [System.Drawing.Point]::new(350, 44); $script:lblBaselineInfo.AutoSize = $true; $script:lblBaselineInfo.Font = $fonts.Small; $script:lblBaselineInfo.ForeColor = $colors.TextDim; $panelXref.Controls.Add($script:lblBaselineInfo)

# === Row 2: Comparison scan ===
$lblComparison = New-Object System.Windows.Forms.Label; $lblComparison.Text = "COMPARISON (After):"; $lblComparison.Location = [System.Drawing.Point]::new(10, 76); $lblComparison.AutoSize = $true; $lblComparison.Font = $fonts.LabelBold; $lblComparison.ForeColor = $colors.Cyan; $panelXref.Controls.Add($lblComparison)
$btnLoadComparison = New-StyledButton -Text "Load Comparison Scan" -Location ([System.Drawing.Point]::new(160, 72)) -Size ([System.Drawing.Size]::new(180, 30)) -BgColor $colors.PanelLight; $panelXref.Controls.Add($btnLoadComparison)
$script:lblComparisonInfo = New-Object System.Windows.Forms.Label; $script:lblComparisonInfo.Text = "No file loaded"; $script:lblComparisonInfo.Location = [System.Drawing.Point]::new(350, 78); $script:lblComparisonInfo.AutoSize = $true; $script:lblComparisonInfo.Font = $fonts.Small; $script:lblComparisonInfo.ForeColor = $colors.TextDim; $panelXref.Controls.Add($script:lblComparisonInfo)

# === Row 3: Compare button + Clear + Summary ===
$btnRunCompare = New-StyledButton -Text "Compare Scans" -Location ([System.Drawing.Point]::new(10, 108)) -Size ([System.Drawing.Size]::new(160, 32)) -BgColor $colors.Cyan; $panelXref.Controls.Add($btnRunCompare)
$btnClearXref = New-StyledButton -Text "Clear" -Location ([System.Drawing.Point]::new(180, 108)) -Size ([System.Drawing.Size]::new(80, 32)) -BgColor $colors.Danger; $panelXref.Controls.Add($btnClearXref)
$btnApplyRemediated = New-StyledButton -Text "Apply Remediated to ACAS Import" -Location ([System.Drawing.Point]::new(270, 108)) -Size ([System.Drawing.Size]::new(260, 32)) -BgColor $colors.Warning; $panelXref.Controls.Add($btnApplyRemediated)

$script:lblXrefSummary = New-Object System.Windows.Forms.Label; $script:lblXrefSummary.Text = "Load baseline and comparison scans, then click Compare to see what changed."; $script:lblXrefSummary.Location = [System.Drawing.Point]::new(540, 114); $script:lblXrefSummary.AutoSize = $true; $script:lblXrefSummary.Font = $fonts.SmallBold; $script:lblXrefSummary.ForeColor = $colors.TextSecondary; $panelXref.Controls.Add($script:lblXrefSummary)

# === Search bar ===
$xrefSearchBar = New-Object System.Windows.Forms.Panel; $xrefSearchBar.Location = [System.Drawing.Point]::new(10, 148); $xrefSearchBar.Size = [System.Drawing.Size]::new(1180, 32); $xrefSearchBar.BackColor = $colors.Panel; $xrefSearchBar.Anchor = 'Top,Left,Right'; $panelXref.Controls.Add($xrefSearchBar)
$lblXrefS = New-Object System.Windows.Forms.Label; $lblXrefS.Text = "Search:"; $lblXrefS.Location = [System.Drawing.Point]::new(8, 7); $lblXrefS.AutoSize = $true; $lblXrefS.ForeColor = $colors.TextSecondary; $lblXrefS.Font = $fonts.Small; $xrefSearchBar.Controls.Add($lblXrefS)
$script:txtXrefSearch = New-Object System.Windows.Forms.TextBox; $script:txtXrefSearch.Location = [System.Drawing.Point]::new(55, 4); $script:txtXrefSearch.Size = [System.Drawing.Size]::new(350, 24); $script:txtXrefSearch.BackColor = $colors.Input; $script:txtXrefSearch.ForeColor = $colors.TextPrimary; $script:txtXrefSearch.Font = $fonts.Console; $script:txtXrefSearch.BorderStyle = 'FixedSingle'; $xrefSearchBar.Controls.Add($script:txtXrefSearch)
$script:xrefSearchTimer = New-Object System.Windows.Forms.Timer; $script:xrefSearchTimer.Interval = 400
$script:xrefSearchTimer.Add_Tick({ $script:xrefSearchTimer.Stop(); Refresh-XrefGrid })
$script:txtXrefSearch.Add_TextChanged({ $script:xrefSearchTimer.Stop(); $script:xrefSearchTimer.Start() })

# === Filter bar ===
$xrefFilterBar = New-Object System.Windows.Forms.Panel; $xrefFilterBar.Location = [System.Drawing.Point]::new(10, 184); $xrefFilterBar.Size = [System.Drawing.Size]::new(1180, 36); $xrefFilterBar.BackColor = $colors.Panel; $xrefFilterBar.Anchor = 'Top,Left,Right'; $panelXref.Controls.Add($xrefFilterBar)

$lblXFD = New-Object System.Windows.Forms.Label; $lblXFD.Text = "Delta:"; $lblXFD.Location = [System.Drawing.Point]::new(8, 8); $lblXFD.AutoSize = $true; $lblXFD.ForeColor = $colors.TextSecondary; $lblXFD.Font = $fonts.Small; $xrefFilterBar.Controls.Add($lblXFD)
$script:cmbXrefDeltaFilter = New-Object System.Windows.Forms.ComboBox; $script:cmbXrefDeltaFilter.Location = [System.Drawing.Point]::new(48, 5); $script:cmbXrefDeltaFilter.Size = [System.Drawing.Size]::new(150, 24); $script:cmbXrefDeltaFilter.BackColor = $colors.Input; $script:cmbXrefDeltaFilter.ForeColor = $colors.TextPrimary; $script:cmbXrefDeltaFilter.Font = $fonts.Small; $script:cmbXrefDeltaFilter.DropDownStyle = 'DropDownList'
foreach ($d in @('(All Changes)','REMEDIATED','STILL OPEN','NEW')) { [void]$script:cmbXrefDeltaFilter.Items.Add($d) }; $script:cmbXrefDeltaFilter.SelectedIndex = 0
$script:cmbXrefDeltaFilter.Add_SelectedIndexChanged({ Refresh-XrefGrid }); $xrefFilterBar.Controls.Add($script:cmbXrefDeltaFilter)

$lblXFH = New-Object System.Windows.Forms.Label; $lblXFH.Text = "Host:"; $lblXFH.Location = [System.Drawing.Point]::new(210, 8); $lblXFH.AutoSize = $true; $lblXFH.ForeColor = $colors.TextSecondary; $lblXFH.Font = $fonts.Small; $xrefFilterBar.Controls.Add($lblXFH)
$script:cmbXrefHostFilter = New-Object System.Windows.Forms.ComboBox; $script:cmbXrefHostFilter.Location = [System.Drawing.Point]::new(244, 5); $script:cmbXrefHostFilter.Size = [System.Drawing.Size]::new(200, 24); $script:cmbXrefHostFilter.BackColor = $colors.Input; $script:cmbXrefHostFilter.ForeColor = $colors.TextPrimary; $script:cmbXrefHostFilter.Font = $fonts.Small; $script:cmbXrefHostFilter.DropDownStyle = 'DropDownList'
[void]$script:cmbXrefHostFilter.Items.Add('(All Hosts)'); $script:cmbXrefHostFilter.SelectedIndex = 0; $script:cmbXrefHostFilter.Add_SelectedIndexChanged({ Refresh-XrefGrid }); $xrefFilterBar.Controls.Add($script:cmbXrefHostFilter)

$lblXFS = New-Object System.Windows.Forms.Label; $lblXFS.Text = "Severity:"; $lblXFS.Location = [System.Drawing.Point]::new(456, 8); $lblXFS.AutoSize = $true; $lblXFS.ForeColor = $colors.TextSecondary; $lblXFS.Font = $fonts.Small; $xrefFilterBar.Controls.Add($lblXFS)
$script:cmbXrefSevFilter = New-Object System.Windows.Forms.ComboBox; $script:cmbXrefSevFilter.Location = [System.Drawing.Point]::new(510, 5); $script:cmbXrefSevFilter.Size = [System.Drawing.Size]::new(140, 24); $script:cmbXrefSevFilter.BackColor = $colors.Input; $script:cmbXrefSevFilter.ForeColor = $colors.TextPrimary; $script:cmbXrefSevFilter.Font = $fonts.Small; $script:cmbXrefSevFilter.DropDownStyle = 'DropDownList'
foreach ($s in @('(All Severities)','Critical','High','Medium','Low','Info')) { [void]$script:cmbXrefSevFilter.Items.Add($s) }; $script:cmbXrefSevFilter.SelectedIndex = 0; $script:cmbXrefSevFilter.Add_SelectedIndexChanged({ Refresh-XrefGrid }); $xrefFilterBar.Controls.Add($script:cmbXrefSevFilter)

$btnXrefReset = New-StyledButton -Text "Reset" -Location ([System.Drawing.Point]::new(660, 3)) -Size ([System.Drawing.Size]::new(70, 28)) -BgColor $colors.PanelLight
$btnXrefReset.Add_Click({ $script:cmbXrefDeltaFilter.SelectedIndex = 0; $script:cmbXrefHostFilter.SelectedIndex = 0; $script:cmbXrefSevFilter.SelectedIndex = 0; $script:txtXrefSearch.Text = ''; Refresh-XrefGrid }); $xrefFilterBar.Controls.Add($btnXrefReset)

# === Comparison results grid ===
$script:gridXref = New-StyledGrid -Location ([System.Drawing.Point]::new(10, 226)) -Size ([System.Drawing.Size]::new(1180, 449)); $script:gridXref.Anchor = 'Top,Left,Right,Bottom'
foreach ($col in @(@{N='Hostname';W=160},@{N='PluginID';W=80},@{N='Vuln Name';W=300},@{N='Severity';W=80},@{N='CVE';W=110},@{N='Category';W=120},@{N='Delta';W=120})) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $c.HeaderText = $col.N; $c.Width = $col.W; $c.Name = $col.N; [void]$script:gridXref.Columns.Add($c)
}
$panelXref.Controls.Add($script:gridXref)

# === Load Baseline button handler ===
$btnLoadBaseline.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "ACAS/Nessus Files|*.csv;*.tsv;*.nessus|All Files|*.*"; $dlg.Title = "Select BASELINE Scan (Before Patching)"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $global:BaselineScan.Clear()
    $parsed = Parse-AcasFile -FilePath $dlg.FileName
    foreach ($f in $parsed) { [void]$global:BaselineScan.Add($f) }
    $uniqueHosts = ($global:BaselineScan | Select-Object -ExpandProperty Hostname -Unique).Count
    $script:lblBaselineInfo.Text = "$(Split-Path $dlg.FileName -Leaf)  |  $($global:BaselineScan.Count) findings  |  $uniqueHosts hosts"
    $script:lblBaselineInfo.ForeColor = $colors.Warning
    Log "Baseline loaded: $($global:BaselineScan.Count) findings from $(Split-Path $dlg.FileName -Leaf)"
    Write-DebugLog "[XREF] Baseline loaded: $($global:BaselineScan.Count) findings, $uniqueHosts hosts"
})

# === Load Comparison button handler ===
$btnLoadComparison.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "ACAS/Nessus Files|*.csv;*.tsv;*.nessus|All Files|*.*"; $dlg.Title = "Select COMPARISON Scan (After Patching)"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $global:ComparisonScan.Clear()
    $parsed = Parse-AcasFile -FilePath $dlg.FileName
    foreach ($f in $parsed) { [void]$global:ComparisonScan.Add($f) }
    $uniqueHosts = ($global:ComparisonScan | Select-Object -ExpandProperty Hostname -Unique).Count
    $script:lblComparisonInfo.Text = "$(Split-Path $dlg.FileName -Leaf)  |  $($global:ComparisonScan.Count) findings  |  $uniqueHosts hosts"
    $script:lblComparisonInfo.ForeColor = $colors.Cyan
    Log "Comparison loaded: $($global:ComparisonScan.Count) findings from $(Split-Path $dlg.FileName -Leaf)"
    Write-DebugLog "[XREF] Comparison loaded: $($global:ComparisonScan.Count) findings, $uniqueHosts hosts"
})

# === Compare Scans button handler ===
$btnRunCompare.Add_Click({
    if ($global:BaselineScan.Count -eq 0) { [WptDialog]::Show("Load a baseline scan first (the scan from BEFORE patching).", "No Baseline", 'OK', 'Warning'); return }
    if ($global:ComparisonScan.Count -eq 0) { [WptDialog]::Show("Load a comparison scan first (the scan from AFTER patching).", "No Comparison", 'OK', 'Warning'); return }

    Log "Comparing scans: $($global:BaselineScan.Count) baseline vs $($global:ComparisonScan.Count) comparison findings..."
    Write-DebugLog "[XREF] Starting comparison: baseline=$($global:BaselineScan.Count) comparison=$($global:ComparisonScan.Count)"
    $global:ComparisonResults.Clear()

    # Build lookup sets keyed on Hostname|PluginID
    $baselineKeys = [System.Collections.Generic.HashSet[string]]::new()
    $baselineLookup = @{}
    foreach ($f in $global:BaselineScan) {
        $key = "$($f.Hostname)|$($f.PluginID)"
        [void]$baselineKeys.Add($key)
        $baselineLookup[$key] = $f
    }
    $comparisonKeys = [System.Collections.Generic.HashSet[string]]::new()
    $comparisonLookup = @{}
    foreach ($f in $global:ComparisonScan) {
        $key = "$($f.Hostname)|$($f.PluginID)"
        [void]$comparisonKeys.Add($key)
        $comparisonLookup[$key] = $f
    }

    # REMEDIATED: in baseline but NOT in comparison (patched/fixed)
    foreach ($key in $baselineKeys) {
        if (-not $comparisonKeys.Contains($key)) {
            $f = $baselineLookup[$key]
            [void]$global:ComparisonResults.Add([PSCustomObject]@{ Hostname=$f.Hostname; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta='REMEDIATED'; Solution=$f.Solution })
        }
    }
    # STILL OPEN: in BOTH baseline AND comparison (not fixed)
    foreach ($key in $baselineKeys) {
        if ($comparisonKeys.Contains($key)) {
            $f = $comparisonLookup[$key]
            [void]$global:ComparisonResults.Add([PSCustomObject]@{ Hostname=$f.Hostname; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta='STILL OPEN'; Solution=$f.Solution })
        }
    }
    # NEW: in comparison but NOT in baseline (new findings)
    foreach ($key in $comparisonKeys) {
        if (-not $baselineKeys.Contains($key)) {
            $f = $comparisonLookup[$key]
            [void]$global:ComparisonResults.Add([PSCustomObject]@{ Hostname=$f.Hostname; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta='NEW'; Solution=$f.Solution })
        }
    }

    # Populate host dropdown from comparison results
    $script:cmbXrefHostFilter.Items.Clear(); [void]$script:cmbXrefHostFilter.Items.Add('(All Hosts)')
    $compHosts = $global:ComparisonResults | Select-Object -ExpandProperty Hostname -Unique | Sort-Object
    foreach ($h in $compHosts) { [void]$script:cmbXrefHostFilter.Items.Add($h) }
    $script:cmbXrefHostFilter.SelectedIndex = 0

    $remediated = @($global:ComparisonResults | Where-Object { $_.Delta -eq 'REMEDIATED' }).Count
    $stillOpen  = @($global:ComparisonResults | Where-Object { $_.Delta -eq 'STILL OPEN' }).Count
    $newCount   = @($global:ComparisonResults | Where-Object { $_.Delta -eq 'NEW' }).Count
    Log "Comparison complete: $remediated remediated, $stillOpen still open, $newCount new"
    Write-DebugLog "[XREF] Results: remediated=$remediated stillOpen=$stillOpen new=$newCount"

    Refresh-XrefGrid
})

# === Clear button handler ===
$btnClearXref.Add_Click({
    $global:BaselineScan.Clear(); $global:ComparisonScan.Clear(); $global:ComparisonResults.Clear()
    $script:lblBaselineInfo.Text = "No file loaded"; $script:lblBaselineInfo.ForeColor = $colors.TextDim
    $script:lblComparisonInfo.Text = "No file loaded"; $script:lblComparisonInfo.ForeColor = $colors.TextDim
    $script:cmbXrefHostFilter.Items.Clear(); [void]$script:cmbXrefHostFilter.Items.Add('(All Hosts)'); $script:cmbXrefHostFilter.SelectedIndex = 0
    Refresh-XrefGrid; Log "Cross-reference data cleared"
})

# === Apply Remediated to ACAS Import (mark matching findings as Patched) ===
$btnApplyRemediated.Add_Click({
    $remediated = @($global:ComparisonResults | Where-Object { $_.Delta -eq 'REMEDIATED' })
    if ($remediated.Count -eq 0) { [WptDialog]::Show("No remediated findings to apply.`nRun a scan comparison first.", "Nothing to Apply", 'OK', 'Information'); return }
    if ($global:AcasFindings.Count -eq 0) { [WptDialog]::Show("No ACAS findings loaded on the Import tab.`nImport ACAS data first.", "No Findings", 'OK', 'Warning'); return }
    $confirm = [WptDialog]::Show("Mark $($remediated.Count) remediated finding(s) as Patched on the ACAS Import tab?`n`nThis will match by Hostname + PluginID and set status to Patched.", "Confirm Apply", 'YesNo', 'Question')
    if ($confirm -ne 'Yes') { return }

    $remLookup = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($r in $remediated) { [void]$remLookup.Add("$($r.Hostname)|$($r.PluginID)") }

    $matchCount = 0
    foreach ($finding in $global:AcasFindings) {
        $key = "$($finding.Hostname)|$($finding.PluginID)"
        if ($remLookup.Contains($key) -and $finding.Status -ne 'Patched') {
            $finding.Status = 'Patched'
            $finding.PatchedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm")
            $finding.PatchedBy = "Scan Comparison"
            $matchCount++
        }
    }
    Log "Applied $matchCount remediated findings as Patched on ACAS Import tab"
    Write-DebugLog "[XREF APPLY] Marked $matchCount findings as Patched from scan comparison"
    Refresh-AcasGrid; Refresh-Dashboard
    [WptDialog]::Show("$matchCount finding(s) marked as Patched on the ACAS Import tab.`n`n($($remediated.Count) remediated in comparison, $matchCount matched in current ACAS data)", "Applied", 'OK', 'Information')
})
#endregion

#region === TAB 3: DASHBOARD ===
$script:dashPanel = New-Object System.Windows.Forms.Panel
$script:dashPanel.Dock = 'Fill'; $script:dashPanel.BackColor = $colors.Background; $script:dashPanel.Visible = $false; $script:dashPanel.AutoScroll = $true
$contentArea.Controls.Add($script:dashPanel); $global:TabPanels['Dashboard'] = $script:dashPanel
$lblDashHeader = New-Object System.Windows.Forms.Label; $lblDashHeader.Text = "DASHBOARD"; $lblDashHeader.Location = [System.Drawing.Point]::new(10, 8); $lblDashHeader.AutoSize = $true; $lblDashHeader.Font = $fonts.Subtitle; $lblDashHeader.ForeColor = $colors.Gold; $script:dashPanel.Controls.Add($lblDashHeader)

function New-DashCard { param([string]$Title, [string]$Value, [System.Drawing.Color]$ValueColor, [System.Drawing.Point]$Location)
    $card = New-Object System.Windows.Forms.Panel; $card.Location = $Location; $card.Size = [System.Drawing.Size]::new(210, 100); $card.BackColor = $colors.CardBg
    $acc = New-Object System.Windows.Forms.Panel; $acc.Location = [System.Drawing.Point]::new(0, 0); $acc.Size = [System.Drawing.Size]::new(210, 3); $acc.BackColor = $ValueColor; $card.Controls.Add($acc)
    $lt = New-Object System.Windows.Forms.Label; $lt.Text = $Title; $lt.Location = [System.Drawing.Point]::new(12, 12); $lt.AutoSize = $true; $lt.Font = $fonts.Small; $lt.ForeColor = $colors.TextSecondary; $card.Controls.Add($lt)
    $lv = New-Object System.Windows.Forms.Label; $lv.Text = $Value; $lv.Location = [System.Drawing.Point]::new(12, 34); $lv.AutoSize = $true; $lv.Font = $fonts.CardValue; $lv.ForeColor = $ValueColor; $card.Controls.Add($lv)
    return @{ Panel = $card; ValueLabel = $lv }
}
$cX = 10; $cY = 42; $cG = 220
$cardTotal = New-DashCard -Title "TOTAL FINDINGS" -Value "0" -ValueColor $colors.Accent -Location ([System.Drawing.Point]::new($cX, $cY)); $script:cardTotalVal = $cardTotal.ValueLabel; $script:dashPanel.Controls.Add($cardTotal.Panel)
$cardAutoFix = New-DashCard -Title "AUTO-FIXABLE" -Value "0" -ValueColor $colors.Warning -Location ([System.Drawing.Point]::new($cX+$cG, $cY)); $script:cardAutoFixVal = $cardAutoFix.ValueLabel; $script:dashPanel.Controls.Add($cardAutoFix.Panel)
$cardPatched = New-DashCard -Title "PATCHED" -Value "0" -ValueColor $colors.Success -Location ([System.Drawing.Point]::new($cX+$cG*2, $cY)); $script:cardPatchedVal = $cardPatched.ValueLabel; $script:dashPanel.Controls.Add($cardPatched.Panel)
$cardRemaining = New-DashCard -Title "REMAINING" -Value "0" -ValueColor $colors.Danger -Location ([System.Drawing.Point]::new($cX+$cG*3, $cY)); $script:cardRemainingVal = $cardRemaining.ValueLabel; $script:dashPanel.Controls.Add($cardRemaining.Panel)
$cardNotOurs = New-DashCard -Title "NOT OUR PATCH" -Value "0" -ValueColor $colors.Purple -Location ([System.Drawing.Point]::new($cX+$cG*4, $cY)); $script:cardNotOursVal = $cardNotOurs.ValueLabel; $script:dashPanel.Controls.Add($cardNotOurs.Panel)

# Patch Rate Compliance Bar
$pnlCB = New-Object System.Windows.Forms.Panel; $pnlCB.Location = [System.Drawing.Point]::new(10, 152); $pnlCB.Size = [System.Drawing.Size]::new(1160, 56); $pnlCB.BackColor = $colors.CardBg; $pnlCB.Anchor = 'Top,Left,Right'; $script:dashPanel.Controls.Add($pnlCB)
$lblCT = New-Object System.Windows.Forms.Label; $lblCT.Text = "OVERALL PATCH RATE"; $lblCT.Location = [System.Drawing.Point]::new(12, 4); $lblCT.AutoSize = $true; $lblCT.Font = $fonts.SmallBold; $lblCT.ForeColor = $colors.Gold; $pnlCB.Controls.Add($lblCT)
$script:lblPatchRatePct = New-Object System.Windows.Forms.Label; $script:lblPatchRatePct.Text = "0%"; $script:lblPatchRatePct.Location = [System.Drawing.Point]::new(180, -2); $script:lblPatchRatePct.AutoSize = $true; $script:lblPatchRatePct.Font = $fonts.DashLg; $script:lblPatchRatePct.ForeColor = $colors.TextDim; $pnlCB.Controls.Add($script:lblPatchRatePct)
$script:lblPatchRateDetail = New-Object System.Windows.Forms.Label; $script:lblPatchRateDetail.Text = "No findings loaded"; $script:lblPatchRateDetail.Location = [System.Drawing.Point]::new(12, 22); $script:lblPatchRateDetail.AutoSize = $true; $script:lblPatchRateDetail.Font = $fonts.Small; $script:lblPatchRateDetail.ForeColor = $colors.TextDim; $pnlCB.Controls.Add($script:lblPatchRateDetail)
$script:pnlPatchRateBar = New-Object System.Windows.Forms.Panel; $script:pnlPatchRateBar.Location = [System.Drawing.Point]::new(12, 40); $script:pnlPatchRateBar.Size = [System.Drawing.Size]::new(1136, 10); $script:pnlPatchRateBar.BackColor = $colors.InputBorder; $script:pnlPatchRateBar.Anchor = 'Top,Left,Right'; $pnlCB.Controls.Add($script:pnlPatchRateBar)
$script:pnlPatchRateFill = New-Object System.Windows.Forms.Panel; $script:pnlPatchRateFill.Location = [System.Drawing.Point]::new(0, 0); $script:pnlPatchRateFill.Size = [System.Drawing.Size]::new(0, 10); $script:pnlPatchRateFill.BackColor = $colors.TextDim; $script:pnlPatchRateBar.Controls.Add($script:pnlPatchRateFill)

# Breakdown panels
$lblSB = New-Object System.Windows.Forms.Label; $lblSB.Text = "SEVERITY BREAKDOWN"; $lblSB.Location = [System.Drawing.Point]::new(10, 220); $lblSB.AutoSize = $true; $lblSB.Font = $fonts.Section; $lblSB.ForeColor = $colors.Gold; $script:dashPanel.Controls.Add($lblSB)
$script:panelSevBreakdown = New-Object System.Windows.Forms.Panel; $script:panelSevBreakdown.Location = [System.Drawing.Point]::new(10, 245); $script:panelSevBreakdown.Size = [System.Drawing.Size]::new(540, 180); $script:panelSevBreakdown.BackColor = $colors.CardBg; $script:panelSevBreakdown.Anchor = 'Top,Left'; $script:dashPanel.Controls.Add($script:panelSevBreakdown)

$lblCB2 = New-Object System.Windows.Forms.Label; $lblCB2.Text = "CATEGORY BREAKDOWN"; $lblCB2.Location = [System.Drawing.Point]::new(570, 220); $lblCB2.AutoSize = $true; $lblCB2.Font = $fonts.Section; $lblCB2.ForeColor = $colors.Gold; $script:dashPanel.Controls.Add($lblCB2)
$script:panelCatBreakdown = New-Object System.Windows.Forms.Panel; $script:panelCatBreakdown.Location = [System.Drawing.Point]::new(570, 245); $script:panelCatBreakdown.Size = [System.Drawing.Size]::new(600, 240); $script:panelCatBreakdown.BackColor = $colors.CardBg; $script:panelCatBreakdown.Anchor = 'Top,Left,Right'; $script:dashPanel.Controls.Add($script:panelCatBreakdown)

$lblStB = New-Object System.Windows.Forms.Label; $lblStB.Text = "STATUS BREAKDOWN"; $lblStB.Location = [System.Drawing.Point]::new(10, 500); $lblStB.AutoSize = $true; $lblStB.Font = $fonts.Section; $lblStB.ForeColor = $colors.Gold; $script:dashPanel.Controls.Add($lblStB)
$script:panelStatBreakdown = New-Object System.Windows.Forms.Panel; $script:panelStatBreakdown.Location = [System.Drawing.Point]::new(10, 525); $script:panelStatBreakdown.Size = [System.Drawing.Size]::new(540, 120); $script:panelStatBreakdown.BackColor = $colors.CardBg; $script:panelStatBreakdown.Anchor = 'Top,Left'; $script:dashPanel.Controls.Add($script:panelStatBreakdown)

$btnRefreshDash = New-StyledButton -Text "Refresh Dashboard" -Location ([System.Drawing.Point]::new(570, 525)) -Size ([System.Drawing.Size]::new(160, 32)) -BgColor $colors.Cyan; $btnRefreshDash.Add_Click({ Refresh-Dashboard }); $script:dashPanel.Controls.Add($btnRefreshDash)

$lblHS = New-Object System.Windows.Forms.Label; $lblHS.Text = "PER-HOST SUMMARY"; $lblHS.Location = [System.Drawing.Point]::new(10, 660); $lblHS.AutoSize = $true; $lblHS.Font = $fonts.Section; $lblHS.ForeColor = $colors.Gold; $script:dashPanel.Controls.Add($lblHS)
$script:gridHostSummary = New-StyledGrid -Location ([System.Drawing.Point]::new(10, 685)) -Size ([System.Drawing.Size]::new(1160, 260)); $script:gridHostSummary.Anchor = 'Top,Left,Right'
foreach ($col in @(@{N='Hostname';W=150},@{N='Total';W=70},@{N='Critical';W=70},@{N='High';W=70},@{N='Medium';W=70},@{N='Low';W=60},@{N='Info';W=60},@{N='Patched';W=80},@{N='Open';W=80},@{N='Not Ours';W=80},@{N='Patch Rate';W=90})) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $c.HeaderText = $col.N; $c.Width = $col.W; $c.Name = $col.N; [void]$script:gridHostSummary.Columns.Add($c)
}
$script:dashPanel.Controls.Add($script:gridHostSummary)
# Forward wheel events at grid boundaries so the outer dashPanel keeps scrolling.
Add-MouseWheelForwarding -Grid $script:gridHostSummary

$script:dashResizeTimer = New-Object System.Windows.Forms.Timer; $script:dashResizeTimer.Interval = 250
$script:dashResizeTimer.Add_Tick({ $script:dashResizeTimer.Stop(); if ($global:ActiveTab -eq 'Dashboard' -and $global:AcasFindings.Count -gt 0) { Refresh-BarChart $script:panelSevBreakdown 'Severity'; Refresh-BarChart $script:panelCatBreakdown 'Category'; Refresh-BarChart $script:panelStatBreakdown 'Status' } })
$script:panelSevBreakdown.Add_Resize({ $script:dashResizeTimer.Stop(); $script:dashResizeTimer.Start() })
$script:panelCatBreakdown.Add_Resize({ $script:dashResizeTimer.Stop(); $script:dashResizeTimer.Start() })
$script:panelStatBreakdown.Add_Resize({ $script:dashResizeTimer.Stop(); $script:dashResizeTimer.Start() })
#endregion

#region === TAB 4: REMEDIATION PLAN ===
# Card-only "what big pushes do I need to do" overview. One card per app
# family - each card IS a push job: target version, hosts behind, severity
# breakdown, and inline actions (Copy Hosts / Export CSV / Open in Nemesis
# / Mark All Pushed). Other is dimmed because it's a catch-all without a
# clear push target. No per-host grid - that's what the ACAS Import tab is
# for. Hosts come out via Copy Hosts (clipboard) or Export CSV.
$script:panelRem = New-Object System.Windows.Forms.Panel
$script:panelRem.Dock = 'Fill'; $script:panelRem.BackColor = $colors.Background; $script:panelRem.Visible = $false
$script:panelRem.AutoScroll = $true   # Other vuln-group cards extend the page below the 2x3 main grid.
$contentArea.Controls.Add($script:panelRem); $global:TabPanels['Remediation Plan'] = $script:panelRem

$lblRemHeader = New-Object System.Windows.Forms.Label
$lblRemHeader.Text = "REMEDIATION PLAN"; $lblRemHeader.Location = [System.Drawing.Point]::new(10, 8)
$lblRemHeader.AutoSize = $true; $lblRemHeader.Font = $fonts.Subtitle; $lblRemHeader.ForeColor = $colors.Gold
$script:panelRem.Controls.Add($lblRemHeader)

$lblRemSub = New-Object System.Windows.Forms.Label
$lblRemSub.Text = "What needs pushed. Each card is one update job. Right-click a card for more options."
$lblRemSub.Location = [System.Drawing.Point]::new(180, 12); $lblRemSub.AutoSize = $true
$lblRemSub.Font = $fonts.Small; $lblRemSub.ForeColor = $colors.TextDim
$script:panelRem.Controls.Add($lblRemSub)

# === Network size input ===
# Operator-supplied total device count drives the "% of network" stat
# rendered next to each card's host count. Persisted between sessions
# (see Load-/Save-NetworkDeviceCount).
$lblNetSize = New-Object System.Windows.Forms.Label
$lblNetSize.Text = "Network size:"
$lblNetSize.Location = [System.Drawing.Point]::new(700, 11)
$lblNetSize.AutoSize = $true
$lblNetSize.Font = $fonts.Small
$lblNetSize.ForeColor = $colors.TextSecondary
$script:panelRem.Controls.Add($lblNetSize)

$script:txtNetSize = New-Object System.Windows.Forms.TextBox
$script:txtNetSize.Location = [System.Drawing.Point]::new(790, 8)
$script:txtNetSize.Size = [System.Drawing.Size]::new(70, 22)
$script:txtNetSize.BackColor = $colors.Input
$script:txtNetSize.ForeColor = $colors.TextPrimary
$script:txtNetSize.Font = $fonts.Console
$script:txtNetSize.BorderStyle = 'FixedSingle'
$script:txtNetSize.MaxLength = 6
$script:txtNetSize.Text = if ($global:NetworkDeviceCount -gt 0) { "$($global:NetworkDeviceCount)" } else { "" }
$script:txtNetSize.Add_KeyDown({
    if ($_.KeyCode -eq 'Enter') {
        $btnApplyNetSize.PerformClick()
        $_.SuppressKeyPress = $true
    }
}.GetNewClosure())
$script:panelRem.Controls.Add($script:txtNetSize)

$btnApplyNetSize = New-StyledButton -Text "Apply" -Location ([System.Drawing.Point]::new(866, 6)) -Size ([System.Drawing.Size]::new(60, 26)) -BgColor $colors.Accent
$btnApplyNetSize.Add_Click({
    $raw = $script:txtNetSize.Text.Trim()
    $n = 0
    if ($raw -eq '' -or $raw -eq '0') {
        $global:NetworkDeviceCount = 0
        Save-NetworkDeviceCount
        Log "Network size cleared; percentage hidden"
        Refresh-RemediationPlan
    } elseif ([int]::TryParse($raw, [ref]$n) -and $n -gt 0 -and $n -lt 1000000) {
        $global:NetworkDeviceCount = $n
        Save-NetworkDeviceCount
        Log "Network size set to $n device(s); percentages updated"
        Refresh-RemediationPlan
    } else {
        [WptDialog]::Show("Enter a positive integer (e.g. 4200) or leave blank to clear.", "Bad input", 'OK', 'Warning')
        $script:txtNetSize.Focus()
    }
})
$script:panelRem.Controls.Add($btnApplyNetSize)

$script:lblNetSizeHint = New-Object System.Windows.Forms.Label
$script:lblNetSizeHint.Text = if ($global:NetworkDeviceCount -gt 0) { "$($global:NetworkDeviceCount) hosts on network" } else { "(empty = hide %)" }
$script:lblNetSizeHint.Location = [System.Drawing.Point]::new(932, 11)
$script:lblNetSizeHint.AutoSize = $true
$script:lblNetSizeHint.Font = $fonts.Small
$script:lblNetSizeHint.ForeColor = $colors.TextDim
$script:panelRem.Controls.Add($script:lblNetSizeHint)

$btnRemRefresh = New-StyledButton -Text "Refresh" -Location ([System.Drawing.Point]::new(1100, 6)) -Size ([System.Drawing.Size]::new(90, 26)) -BgColor $colors.PanelLight
$btnRemRefresh.Anchor = 'Top,Right'
$btnRemRefresh.Add_Click({ Refresh-RemediationPlan })
$script:panelRem.Controls.Add($btnRemRefresh)

# === Cards (2 rows x 3 cols, big "push job" cards) ===
# Each card is one app family + its target version + an action button row.
# Other is dimmed (Disabled = $true) because catch-all has no clear push.
$script:remCardSpecs = @(
    @{ App='Chrome';   Color=$colors.Accent;        Disabled=$false },
    @{ App='Edge';     Color=$colors.Cyan;          Disabled=$false },
    @{ App='Office';   Color=$colors.Gold;          Disabled=$false },
    @{ App='Defender'; Color=$colors.Success;       Disabled=$false },
    @{ App='KB';       Color=$colors.Warning;       Disabled=$false },
    @{ App='Other';    Color=$colors.TextSecondary; Disabled=$true  }
)
$script:remCards = @{}
$cardW    = 380
$cardH    = 230
$cardGapX = 20
$cardGapY = 22
$cardOriginX = 10
$cardOriginY = 50
for ($i = 0; $i -lt $script:remCardSpecs.Count; $i++) {
    $spec = $script:remCardSpecs[$i]
    $col = $i % 3
    $row = [Math]::Floor($i / 3)
    $cardX = $cardOriginX + ($col * ($cardW + $cardGapX))
    $cardY = $cardOriginY + ($row * ($cardH + $cardGapY))
    $isDim  = [bool]$spec.Disabled
    $appName = [string]$spec.App
    $accentC = $spec.Color
    $titleFg = if ($isDim) { $colors.TextDim }       else { $colors.TextSecondary }
    $countFg = if ($isDim) { $colors.TextDim }       else { $accentC }
    $tgtFg   = if ($isDim) { $colors.TextDim }       else { $colors.TextPrimary }
    $sevFg   = if ($isDim) { $colors.TextDim }       else { $colors.TextSecondary }

    $card = New-Object System.Windows.Forms.Panel
    $card.Location = [System.Drawing.Point]::new($cardX, $cardY)
    $card.Size     = [System.Drawing.Size]::new($cardW, $cardH)
    $card.BackColor = $colors.CardBg; $card.Tag = $appName
    $script:panelRem.Controls.Add($card)

    $accent = New-Object System.Windows.Forms.Panel
    $accent.Location = [System.Drawing.Point]::new(0, 0); $accent.Size = [System.Drawing.Size]::new($cardW, 4)
    $accent.BackColor = $accentC
    $card.Controls.Add($accent)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = $appName.ToUpper(); $lblTitle.Location = [System.Drawing.Point]::new(20, 18)
    $lblTitle.AutoSize = $true; $lblTitle.Font = $fonts.Title; $lblTitle.ForeColor = $titleFg
    $card.Controls.Add($lblTitle)

    $lblTgtPrefix = New-Object System.Windows.Forms.Label
    $lblTgtPrefix.Text = "Push to"; $lblTgtPrefix.Location = [System.Drawing.Point]::new(20, 56)
    $lblTgtPrefix.AutoSize = $true; $lblTgtPrefix.Font = $fonts.Small; $lblTgtPrefix.ForeColor = $sevFg
    $card.Controls.Add($lblTgtPrefix)
    $lblTgt = New-Object System.Windows.Forms.Label
    $lblTgt.Text = "-"; $lblTgt.Location = [System.Drawing.Point]::new(80, 54)
    $lblTgt.AutoSize = $true; $lblTgt.Font = $fonts.LabelBold; $lblTgt.ForeColor = $tgtFg
    $card.Controls.Add($lblTgt)

    $lblCount = New-Object System.Windows.Forms.Label
    $lblCount.Text = "0"; $lblCount.Location = [System.Drawing.Point]::new(20, 80)
    $lblCount.AutoSize = $true
    $lblCount.Font = New-Object System.Drawing.Font('Cascadia Mono', 36, [System.Drawing.FontStyle]::Bold)
    $lblCount.ForeColor = $countFg
    $card.Controls.Add($lblCount)
    $lblCountSub = New-Object System.Windows.Forms.Label
    $lblCountSub.Text = "hosts behind"; $lblCountSub.Location = [System.Drawing.Point]::new(22, 138)
    $lblCountSub.AutoSize = $true; $lblCountSub.Font = $fonts.Small; $lblCountSub.ForeColor = $sevFg
    $card.Controls.Add($lblCountSub)

    # % of network labels - render to the right of the big host count when
    # $global:NetworkDeviceCount > 0. Refresh-RemediationPlan flips them on/off
    # and updates the text.
    $lblPct = New-Object System.Windows.Forms.Label
    $lblPct.Text = ""
    $lblPct.Location = [System.Drawing.Point]::new(155, 92)
    $lblPct.AutoSize = $true
    $lblPct.Font = New-Object System.Drawing.Font('Cascadia Mono', 22, [System.Drawing.FontStyle]::Bold)
    $lblPct.ForeColor = $countFg
    $card.Controls.Add($lblPct)
    $lblPctSub = New-Object System.Windows.Forms.Label
    $lblPctSub.Text = ""
    $lblPctSub.Location = [System.Drawing.Point]::new(160, 130)
    $lblPctSub.AutoSize = $true
    $lblPctSub.Font = $fonts.Small
    $lblPctSub.ForeColor = $sevFg
    $card.Controls.Add($lblPctSub)

    $lblSev = New-Object System.Windows.Forms.Label
    $lblSev.Text = ""; $lblSev.Location = [System.Drawing.Point]::new(20, 158)
    $lblSev.AutoSize = $true; $lblSev.Font = $fonts.SmallBold; $lblSev.ForeColor = $sevFg
    $card.Controls.Add($lblSev)

    # Action button row (all four buttons inline at the bottom).
    $btnY = $cardH - 38
    if ($isDim) {
        # Other: don't render action buttons, render a dimmed note instead.
        $lblDim = New-Object System.Windows.Forms.Label
        $lblDim.Text = "(catch-all - no clear push target)"; $lblDim.Location = [System.Drawing.Point]::new(20, $btnY + 8)
        $lblDim.AutoSize = $true; $lblDim.Font = $fonts.Small; $lblDim.ForeColor = $colors.TextDim
        $card.Controls.Add($lblDim)
    } else {
        $btnCopy = New-StyledButton -Text "Copy Hosts" -Location ([System.Drawing.Point]::new(20, $btnY)) -Size ([System.Drawing.Size]::new(86, 28)) -BgColor $accentC
        $btnCopy.Add_Click({ Copy-RemediationHosts -App $appName }.GetNewClosure())
        $card.Controls.Add($btnCopy)
        $btnExp = New-StyledButton -Text "Export CSV" -Location ([System.Drawing.Point]::new(112, $btnY)) -Size ([System.Drawing.Size]::new(88, 28)) -BgColor $colors.PanelLight
        $btnExp.Add_Click({ Export-RemediationCsv -App $appName }.GetNewClosure())
        $card.Controls.Add($btnExp)
        $btnNem = New-StyledButton -Text "Nemesis" -Location ([System.Drawing.Point]::new(206, $btnY)) -Size ([System.Drawing.Size]::new(76, 28)) -BgColor $colors.Purple
        $btnNem.Add_Click({ Open-RemediationInNemesis -App $appName }.GetNewClosure())
        $card.Controls.Add($btnNem)
        $btnPush = New-StyledButton -Text "Mark Pushed" -Location ([System.Drawing.Point]::new(288, $btnY)) -Size ([System.Drawing.Size]::new(72, 28)) -BgColor $colors.Success
        $btnPush.Add_Click({ Mark-RemediationStatus -Status 'Pushed' -App $appName -PromptForNotes }.GetNewClosure())
        $card.Controls.Add($btnPush)
    }

    $script:remCards[$appName] = @{
        Panel        = $card
        Accent       = $accent
        Title        = $lblTitle
        TargetLabel  = $lblTgt
        Count        = $lblCount
        PctLabel     = $lblPct
        PctSubLabel  = $lblPctSub
        SeverityNote = $lblSev
        Color        = $accentC
        Disabled     = $isDim
    }

    # Right-click menu - same actions plus reset.
    if (-not $isDim) {
        $menu = New-Object System.Windows.Forms.ContextMenuStrip
        $miCopy  = $menu.Items.Add("Copy hosts behind on $appName")
        $miCopy.Add_Click({ Copy-RemediationHosts -App $appName }.GetNewClosure())
        $miExp   = $menu.Items.Add("Export hosts behind on $appName (CSV)")
        $miExp.Add_Click({ Export-RemediationCsv -App $appName }.GetNewClosure())
        $miNem   = $menu.Items.Add("Open all in Nemesis")
        $miNem.Add_Click({ Open-RemediationInNemesis -App $appName }.GetNewClosure())
        [void]$menu.Items.Add('-')
        $miMark  = $menu.Items.Add("Mark all $appName hosts as Pushed...")
        $miMark.Add_Click({ Mark-RemediationStatus -Status 'Pushed' -App $appName -PromptForNotes }.GetNewClosure())
        $miSkip  = $menu.Items.Add("Mark all $appName hosts as Skipped")
        $miSkip.Add_Click({ Mark-RemediationStatus -Status 'Skipped' -App $appName }.GetNewClosure())
        $miReset = $menu.Items.Add("Reset $appName to Pending")
        $miReset.Add_Click({ Mark-RemediationStatus -Status 'Pending' -App $appName }.GetNewClosure())
        $card.ContextMenuStrip = $menu
    }
}

# === Common Other Vulns section (dynamic) ===
# Below the main 2x3, we render one card per Other-bucket vuln that hits >= 10
# distinct hosts. These cards are torn down + rebuilt on every refresh so the
# set stays in sync with current findings + Mark Pushed state.
$script:remOtherSectionY = 50 + 2 * (230 + 22) + 6   # 2 rows of cards plus gap
$script:lblOtherSection = New-Object System.Windows.Forms.Label
$script:lblOtherSection.Text = "COMMON OTHER VULNS  (10+ hosts each)"
$script:lblOtherSection.Location = [System.Drawing.Point]::new(10, $script:remOtherSectionY)
$script:lblOtherSection.AutoSize = $true; $script:lblOtherSection.Font = $fonts.Subtitle; $script:lblOtherSection.ForeColor = $colors.Gold
$script:panelRem.Controls.Add($script:lblOtherSection)

$script:lblOtherSectionSub = New-Object System.Windows.Forms.Label
$script:lblOtherSectionSub.Text = "Vulnerabilities in the Other bucket affecting many machines, broken out so each one is its own push job. Mark Pushed hides the card until the next ACAS import."
$script:lblOtherSectionSub.Location = [System.Drawing.Point]::new(10, $script:remOtherSectionY + 22)
$script:lblOtherSectionSub.Size = [System.Drawing.Size]::new(1180, 18); $script:lblOtherSectionSub.Font = $fonts.Small; $script:lblOtherSectionSub.ForeColor = $colors.TextDim
$script:panelRem.Controls.Add($script:lblOtherSectionSub)

# Tracker for the dynamic card panels so Refresh-RemediationPlan can tear them down.
$script:remOtherCardPanels = New-Object System.Collections.ArrayList

# Empty-state label, shown when no Other vulns hit the threshold.
$script:lblOtherEmpty = New-Object System.Windows.Forms.Label
$script:lblOtherEmpty.Text = "No Other vulns affect 10+ hosts. Anything in this bucket is currently a long-tail case."
$script:lblOtherEmpty.Location = [System.Drawing.Point]::new(10, $script:remOtherSectionY + 50)
$script:lblOtherEmpty.AutoSize = $true; $script:lblOtherEmpty.Font = $fonts.Label; $script:lblOtherEmpty.ForeColor = $colors.TextDim
$script:panelRem.Controls.Add($script:lblOtherEmpty)
#endregion

#region === TAB 4: EXPORT ===
$panelExport = New-Object System.Windows.Forms.Panel; $panelExport.Dock = 'Fill'; $panelExport.BackColor = $colors.Background; $panelExport.Visible = $false; $panelExport.AutoScroll = $true
$contentArea.Controls.Add($panelExport); $global:TabPanels['Export'] = $panelExport
$lblEH = New-Object System.Windows.Forms.Label; $lblEH.Text = "EXPORT & SAVE"; $lblEH.Location = [System.Drawing.Point]::new(10, 8); $lblEH.AutoSize = $true; $lblEH.Font = $fonts.Subtitle; $lblEH.ForeColor = $colors.Gold; $panelExport.Controls.Add($lblEH)

function New-ExportPanel { param([int]$Y, [string]$Title, [System.Drawing.Color]$TitleColor, [string]$Desc, [string]$BtnText, [System.Drawing.Color]$BtnColor, [System.Drawing.Color]$BtnFg = [System.Drawing.Color]::White, [scriptblock]$OnClick)
    $grp = New-Object System.Windows.Forms.Panel; $grp.Location = [System.Drawing.Point]::new(10, $Y); $grp.Size = [System.Drawing.Size]::new(1160, 90); $grp.BackColor = $colors.Panel; $grp.Anchor = 'Top,Left,Right'; $panelExport.Controls.Add($grp)
    $lt = New-Object System.Windows.Forms.Label; $lt.Text = $Title; $lt.Location = [System.Drawing.Point]::new(12, 8); $lt.AutoSize = $true; $lt.Font = $fonts.LabelBold; $lt.ForeColor = $TitleColor; $grp.Controls.Add($lt)
    $ld = New-Object System.Windows.Forms.Label; $ld.Text = $Desc; $ld.Location = [System.Drawing.Point]::new(12, 28); $ld.AutoSize = $true; $ld.Font = $fonts.Small; $ld.ForeColor = $colors.TextSecondary; $grp.Controls.Add($ld)
    $btn = New-StyledButton -Text $BtnText -Location ([System.Drawing.Point]::new(12, 52)) -Size ([System.Drawing.Size]::new(240, 30)) -BgColor $BtnColor -FgColor $BtnFg; $btn.Add_Click($OnClick); $grp.Controls.Add($btn)
}

$eY = 50
New-ExportPanel -Y $eY -Title "SAVE REPORT STATE (JSON)" -TitleColor $colors.Gold -Desc "Save all findings and status data to a JSON file." -BtnText "Save Report to JSON" -BtnColor $colors.PanelLight -OnClick {
    if ($global:AcasFindings.Count -eq 0) { [WptDialog]::Show("No findings to save.", "Empty", 'OK', 'Information'); return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "JSON Files|*.json"; $dlg.FileName = "ACAS_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $export = @{
            ExportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ExportedBy = $env:USERNAME
            Findings = @($global:AcasFindings | ForEach-Object { @{ Hostname=$_.Hostname; PluginID=$_.PluginID; VulnName=$_.VulnName; Severity=$_.Severity; CVE=$_.CVE; Category=$_.Category; Status=$_.Status; Solution=$_.Solution; PatchedDate=$_.PatchedDate; PatchedBy=$_.PatchedBy } })
        }
        $export | ConvertTo-Json -Depth 5 | Out-File $dlg.FileName -Encoding UTF8
        Log "Saved report to $(Split-Path $dlg.FileName -Leaf)"; [WptDialog]::Show("Report saved!`n$($dlg.FileName)", "Saved", 'OK', 'Information')
    } catch { Log "ERROR saving JSON: $_" }
}; $eY += 105

New-ExportPanel -Y $eY -Title "EXPORT FULL REPORT (CSV)" -TitleColor $colors.Gold -Desc "Export all findings with full columns." -BtnText "Export Full CSV" -BtnColor $colors.PanelLight -OnClick {
    if ($global:AcasFindings.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "CSV Files|*.csv"; $dlg.FileName = "ACAS_FullReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new(); [void]$lines.Add('"Host","PluginID","VulnName","Severity","Category","Status","PatchedDate","PatchedBy","Solution"')
        foreach ($f2 in $global:AcasFindings) { $ev = $f2.VulnName -replace '"','""'; $es = $f2.Solution -replace '"','""'; [void]$lines.Add("`"$($f2.Hostname)`",`"$($f2.PluginID)`",`"$ev`",`"$($f2.Severity)`",`"$($f2.Category)`",`"$($f2.Status)`",`"$($f2.PatchedDate)`",`"$($f2.PatchedBy)`",`"$es`"") }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8)
        Log "Exported full report: $($global:AcasFindings.Count) findings"; [WptDialog]::Show("Full report exported!`n$($global:AcasFindings.Count) findings", "Exported", 'OK', 'Information')
    } catch { Log "ERROR exporting: $_" }
}; $eY += 105

New-ExportPanel -Y $eY -Title "EXPORT 'NOT OUR PATCH' LIST" -TitleColor $colors.Purple -Desc "Export only NOT OUR PATCH findings." -BtnText "Export NOT OUR PATCH CSV" -BtnColor $colors.PanelLight -OnClick {
    $items = @($global:AcasFindings | Where-Object { $_.Category -eq 'NOT OUR PATCH' }); if ($items.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "CSV Files|*.csv"; $dlg.FileName = "NotOurPatch_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new(); [void]$lines.Add('"Host","PluginID","VulnName","Severity","Category","Solution"')
        foreach ($f2 in $items) { $ev = $f2.VulnName -replace '"','""'; $es = $f2.Solution -replace '"','""'; [void]$lines.Add("`"$($f2.Hostname)`",`"$($f2.PluginID)`",`"$ev`",`"$($f2.Severity)`",`"$($f2.Category)`",`"$es`"") }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8); Log "Exported NOT OUR PATCH: $($items.Count) findings"
    } catch { Log "ERROR exporting: $_" }
}; $eY += 105

New-ExportPanel -Y $eY -Title "EXPORT REMAINING VULNERABILITIES" -TitleColor $colors.Danger -Desc "Export only findings still Open." -BtnText "Export Remaining Vulns CSV" -BtnColor $colors.PanelLight -OnClick {
    $items = @($global:AcasFindings | Where-Object { $_.Status -eq 'Open' }); if ($items.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "CSV Files|*.csv"; $dlg.FileName = "RemainingVulns_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new(); [void]$lines.Add('"Host","PluginID","VulnName","Severity","Category","Solution"')
        foreach ($f2 in $items) { $ev = $f2.VulnName -replace '"','""'; $es = $f2.Solution -replace '"','""'; [void]$lines.Add("`"$($f2.Hostname)`",`"$($f2.PluginID)`",`"$ev`",`"$($f2.Severity)`",`"$($f2.Category)`",`"$es`"") }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8); Log "Exported remaining vulns: $($items.Count) findings"
    } catch { Log "ERROR exporting: $_" }
}; $eY += 105

New-ExportPanel -Y $eY -Title "EXPORT CURRENT FILTERED VIEW" -TitleColor $colors.Cyan -Desc "Export only findings matching current ACAS Import filters." -BtnText "Export Filtered View CSV" -BtnColor $colors.PanelLight -OnClick {
    $filtered = Get-FilteredFindings; if ($filtered.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "CSV Files|*.csv"; $dlg.FileName = "FilteredView_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new(); [void]$lines.Add('"Host","PluginID","VulnName","Severity","Category","Status","PatchedDate","PatchedBy","Solution"')
        foreach ($f2 in $filtered) { $ev = $f2.VulnName -replace '"','""'; $es = $f2.Solution -replace '"','""'; [void]$lines.Add("`"$($f2.Hostname)`",`"$($f2.PluginID)`",`"$ev`",`"$($f2.Severity)`",`"$($f2.Category)`",`"$($f2.Status)`",`"$($f2.PatchedDate)`",`"$($f2.PatchedBy)`",`"$es`"") }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8); Log "Exported filtered view: $($filtered.Count) findings"
    } catch { Log "ERROR exporting: $_" }
}; $eY += 105

New-ExportPanel -Y $eY -Title "EXPORT PER-HOST SUMMARY" -TitleColor $colors.Gold -Desc "Export summary CSV: one row per host with severity breakdown, patch status, and patch rate." -BtnText "Export Per-Host Summary CSV" -BtnColor $colors.PanelLight -OnClick {
    if ($global:AcasFindings.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "CSV Files|*.csv"; $dlg.FileName = "HostSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new(); [void]$lines.Add('"Hostname","Total","Critical","High","Medium","Low","Info","Patched","Open","Not Ours","Patch Rate"')
        $hostGroups = $global:AcasFindings | Group-Object -Property Hostname | Sort-Object Name
        foreach ($hg in $hostGroups) { $hf = $hg.Group; $ht = $hf.Count; $hC = @($hf | Where-Object { $_.Severity -eq 'Critical' }).Count; $hH = @($hf | Where-Object { $_.Severity -eq 'High' }).Count; $hM = @($hf | Where-Object { $_.Severity -eq 'Medium' }).Count; $hL = @($hf | Where-Object { $_.Severity -eq 'Low' }).Count; $hI = @($hf | Where-Object { $_.Severity -eq 'Info' }).Count; $hP = @($hf | Where-Object { $_.Status -eq 'Patched' }).Count; $hN = @($hf | Where-Object { $_.Category -eq 'NOT OUR PATCH' }).Count; $hO = $ht - $hP - $hN; $act = $ht - $hN; $pr = if ($act -gt 0) { [Math]::Round(($hP / $act) * 100, 0) } else { 100 }; [void]$lines.Add("`"$($hg.Name)`",$ht,$hC,$hH,$hM,$hL,$hI,$hP,$hO,$hN,`"$pr%`"") }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8); Log "Exported per-host summary: $($hostGroups.Count) hosts"
    } catch { Log "ERROR exporting host summary: $_" }
}
#endregion

#region === TAB 5: FUTURE TARGET IPs ===
# Imports a CSV of FQDN hostnames (e.g., AQC pre-target list), resolves IPs
# in parallel via DNS + ping, displays them in a grid, and offers one-click
# clipboard copy of the IP list for pasting into reports. The runspace pool
# pattern mirrors Invoke-AsyncPingSweep above.
$global:FutureTargets = [System.Collections.Generic.List[object]]::new()

function Invoke-AsyncIpResolve {
    param([string[]]$HostNames, [int]$TimeoutMs = 1500, [int]$MaxConcurrent = 32)
    if (-not $HostNames -or $HostNames.Count -eq 0) { return @() }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxConcurrent), $iss, $Host)
    $pool.Open()
    $jobs = [System.Collections.ArrayList]::new()
    $results = [System.Collections.ArrayList]::new()
    try {
        foreach ($h in $HostNames) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($targetHost, $timeoutMs)
                $r = @{ Host = $targetHost; IP = ''; Online = $false; Latency = -1; ResolveOk = $false }
                try {
                    $addrs = [System.Net.Dns]::GetHostAddresses($targetHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                    if ($addrs) { $r.IP = $addrs.IPAddressToString; $r.ResolveOk = $true }
                } catch {}
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($targetHost, $timeoutMs)
                    if ($reply -and $reply.Status -eq 'Success') {
                        $r.Online = $true
                        $r.Latency = [int]$reply.RoundtripTime
                        if ($reply.Address) { $r.IP = $reply.Address.IPAddressToString; $r.ResolveOk = $true }
                    }
                } catch {}
                return $r
            })
            [void]$ps.AddArgument($h)
            [void]$ps.AddArgument($TimeoutMs)
            $handle = $ps.BeginInvoke()
            [void]$jobs.Add(@{ PS = $ps; Handle = $handle; Host = $h })
        }
        # No DoEvents: see Invoke-AsyncPingSweep for rationale.
        foreach ($j in $jobs) {
            try {
                $res = $j.PS.EndInvoke($j.Handle)
                if ($res -and $res.Count -gt 0) { [void]$results.Add($res[0]) }
                else { [void]$results.Add(@{ Host = $j.Host; IP = ''; Online = $false; Latency = -1; ResolveOk = $false }) }
            } catch {
                [void]$results.Add(@{ Host = $j.Host; IP = ''; Online = $false; Latency = -1; ResolveOk = $false })
            } finally {
                try { $j.PS.Dispose() } catch {}
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }
    return $results
}

function Refresh-FutureGrid {
    if (-not $script:gridFuture) { return }
    $script:gridFuture.SuspendLayout()
    $script:gridFuture.Rows.Clear()
    foreach ($t in $global:FutureTargets) {
        $statusText = if ($t.Online) { 'Online' } elseif ($t.ResolveOk) { 'Offline' } else { 'DNS Failed' }
        $latText = if ($t.Latency -ge 0) { "$($t.Latency) ms" } else { '' }
        $idx = $script:gridFuture.Rows.Add($t.Hostname, $t.ASID, $t.IP, $statusText, $latText)
        $row = $script:gridFuture.Rows[$idx]
        $row.Cells['Status'].Style.ForeColor = switch ($statusText) {
            'Online'     { $colors.Success }
            'Offline'    { $colors.Warning }
            'DNS Failed' { $colors.Danger }
        }
    }
    $script:gridFuture.ResumeLayout()
    Update-FutureStatus
}

function Update-FutureStatus {
    if (-not $script:lblFutureStatus) { return }
    $total   = $global:FutureTargets.Count
    $online  = @($global:FutureTargets | Where-Object { $_.Online }).Count
    $offline = @($global:FutureTargets | Where-Object { -not $_.Online -and $_.ResolveOk }).Count
    $failed  = @($global:FutureTargets | Where-Object { -not $_.ResolveOk }).Count
    $script:lblFutureStatus.Text = "Loaded: $total   |   Online: $online   |   Offline: $offline   |   Unresolved: $failed"
}

function Get-FutureIpList {
    param([string]$Mode = 'All')
    switch ($Mode) {
        'Online'   { return @($global:FutureTargets | Where-Object { $_.Online -and $_.IP } | ForEach-Object { $_.IP }) }
        'Resolved' { return @($global:FutureTargets | Where-Object { $_.ResolveOk -and $_.IP } | ForEach-Object { $_.IP }) }
        default    { return @($global:FutureTargets | Where-Object { $_.IP } | ForEach-Object { $_.IP }) }
    }
}

function Copy-FutureToClipboard {
    param([string]$Text, [string]$Description)
    if ([string]::IsNullOrEmpty($Text)) {
        [WptDialog]::Show("Nothing to copy yet. Import a CSV and resolve IPs first.", "Empty", 'OK', 'Information')
        return
    }
    try {
        [System.Windows.Forms.Clipboard]::SetText($Text)
        Log "Copied to clipboard: $Description"
    } catch { Log "ERROR copying to clipboard: $_" }
}

$panelFuture = New-Object System.Windows.Forms.Panel
$panelFuture.Dock = 'Fill'; $panelFuture.BackColor = $colors.Background; $panelFuture.Visible = $false
$contentArea.Controls.Add($panelFuture); $global:TabPanels['Future Target IPs'] = $panelFuture

$lblFH = New-Object System.Windows.Forms.Label
$lblFH.Text = "FUTURE TARGET IPs"; $lblFH.Location = [System.Drawing.Point]::new(10, 8)
$lblFH.AutoSize = $true; $lblFH.Font = $fonts.Subtitle; $lblFH.ForeColor = $colors.Gold
$panelFuture.Controls.Add($lblFH)

$lblFSub = New-Object System.Windows.Forms.Label
$lblFSub.Text = "Import a hostname CSV (e.g., AQC pre-target list), resolve IPs, copy to clipboard."
$lblFSub.Location = [System.Drawing.Point]::new(10, 36); $lblFSub.AutoSize = $true
$lblFSub.Font = $fonts.Small; $lblFSub.ForeColor = $colors.TextSecondary
$panelFuture.Controls.Add($lblFSub)

$btnFImport = New-StyledButton -Text "Import CSV" -Location ([System.Drawing.Point]::new(10, 60)) -Size ([System.Drawing.Size]::new(140, 30)) -BgColor $colors.Accent
$panelFuture.Controls.Add($btnFImport)

$btnFResolve = New-StyledButton -Text "Resolve IPs" -Location ([System.Drawing.Point]::new(160, 60)) -Size ([System.Drawing.Size]::new(140, 30)) -BgColor $colors.Success
$panelFuture.Controls.Add($btnFResolve)

$btnFClear = New-StyledButton -Text "Clear" -Location ([System.Drawing.Point]::new(310, 60)) -Size ([System.Drawing.Size]::new(80, 30)) -BgColor $colors.Danger
$panelFuture.Controls.Add($btnFClear)

$btnFCopyAll = New-StyledButton -Text "Copy All IPs" -Location ([System.Drawing.Point]::new(410, 60)) -Size ([System.Drawing.Size]::new(140, 30)) -BgColor $colors.Gold
$panelFuture.Controls.Add($btnFCopyAll)

$btnFCopyOnline = New-StyledButton -Text "Copy Online IPs" -Location ([System.Drawing.Point]::new(560, 60)) -Size ([System.Drawing.Size]::new(150, 30)) -BgColor $colors.Cyan
$panelFuture.Controls.Add($btnFCopyOnline)

$btnFCopyHostIp = New-StyledButton -Text "Copy Host,IP CSV" -Location ([System.Drawing.Point]::new(720, 60)) -Size ([System.Drawing.Size]::new(160, 30)) -BgColor $colors.PanelLight
$panelFuture.Controls.Add($btnFCopyHostIp)

$btnFExport = New-StyledButton -Text "Export CSV" -Location ([System.Drawing.Point]::new(890, 60)) -Size ([System.Drawing.Size]::new(120, 30)) -BgColor $colors.PanelLight
$panelFuture.Controls.Add($btnFExport)

$script:lblFutureStatus = New-Object System.Windows.Forms.Label
$script:lblFutureStatus.Text = "Loaded: 0   |   Online: 0   |   Offline: 0   |   Unresolved: 0"
$script:lblFutureStatus.Location = [System.Drawing.Point]::new(10, 100); $script:lblFutureStatus.AutoSize = $true
$script:lblFutureStatus.Font = $fonts.SmallBold; $script:lblFutureStatus.ForeColor = $colors.TextSecondary
$panelFuture.Controls.Add($script:lblFutureStatus)

$script:gridFuture = New-StyledGrid -Location ([System.Drawing.Point]::new(10, 128)) -Size ([System.Drawing.Size]::new(1180, 480))
[void]$script:gridFuture.Columns.Add('Hostname', 'Hostname')
[void]$script:gridFuture.Columns.Add('ASID', 'ASID')
[void]$script:gridFuture.Columns.Add('IP', 'IP Address')
[void]$script:gridFuture.Columns.Add('Status', 'Status')
[void]$script:gridFuture.Columns.Add('Latency', 'Latency')
$script:gridFuture.Columns['Hostname'].AutoSizeMode = 'Fill'
$script:gridFuture.Columns['ASID'].Width = 80
$script:gridFuture.Columns['IP'].Width = 140
$script:gridFuture.Columns['Status'].Width = 110
$script:gridFuture.Columns['Latency'].Width = 90
$panelFuture.Controls.Add($script:gridFuture)

$btnFImport.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "CSV Files|*.csv|All Files|*.*"
    $dlg.Title  = "Select Future Target hostname CSV"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $rows = Import-Csv -Path $dlg.FileName -ErrorAction Stop
    } catch {
        Log "ERROR reading CSV: $_"; [WptDialog]::Show("Could not read CSV: $_", "Error", 'OK', 'Error'); return
    }
    if (-not $rows -or $rows.Count -eq 0) { Log "CSV is empty"; return }
    ## Detect the hostname column. Prefer 'Computer Name'; fall back to common variants.
    $first = $rows[0]
    $hostCol = $null
    foreach ($cand in @('Computer Name','ComputerName','Hostname','Host','FQDN','Name')) {
        if ($first.PSObject.Properties.Name -contains $cand) { $hostCol = $cand; break }
    }
    if (-not $hostCol) {
        [WptDialog]::Show("CSV has no recognizable hostname column. Expected one of: Computer Name, Hostname, Host, FQDN, Name.", "Bad CSV", 'OK', 'Warning'); return
    }
    $asidCol = if ($first.PSObject.Properties.Name -contains 'ASID Code') { 'ASID Code' } elseif ($first.PSObject.Properties.Name -contains 'ASID') { 'ASID' } else { $null }
    $global:FutureTargets.Clear()
    foreach ($r in $rows) {
        $h = ($r.$hostCol).ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        $asid = if ($asidCol) { ($r.$asidCol).ToString().Trim() } else { '' }
        [void]$global:FutureTargets.Add([PSCustomObject]@{
            Hostname  = $h
            ASID      = $asid
            IP        = ''
            Online    = $false
            Latency   = -1
            ResolveOk = $false
        })
    }
    Log "Imported $($global:FutureTargets.Count) hostnames from $(Split-Path $dlg.FileName -Leaf)"
    Refresh-FutureGrid
})

$btnFResolve.Add_Click({
    if ($global:FutureTargets.Count -eq 0) { Log "No hostnames loaded — import a CSV first."; return }
    $count = $global:FutureTargets.Count
    Log "Resolving $count hostnames (parallel DNS + ping)..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $hosts = @($global:FutureTargets | ForEach-Object { $_.Hostname })
    $results = Invoke-AsyncIpResolve -HostNames $hosts -TimeoutMs 1500 -MaxConcurrent 32
    $byHost = @{}
    foreach ($r in $results) { $byHost[$r.Host] = $r }
    foreach ($t in $global:FutureTargets) {
        if ($byHost.ContainsKey($t.Hostname)) {
            $r = $byHost[$t.Hostname]
            $t.IP        = $r.IP
            $t.Online    = $r.Online
            $t.Latency   = $r.Latency
            $t.ResolveOk = $r.ResolveOk
        }
    }
    $sw.Stop()
    $online   = @($global:FutureTargets | Where-Object { $_.Online }).Count
    $resolved = @($global:FutureTargets | Where-Object { $_.ResolveOk }).Count
    Log "Resolve complete: $resolved/$count IPs found, $online online (in $([Math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
    Refresh-FutureGrid
})

$btnFClear.Add_Click({
    $global:FutureTargets.Clear()
    Refresh-FutureGrid
    Log "Cleared Future Target IPs."
})

$btnFCopyAll.Add_Click({
    $ips = Get-FutureIpList -Mode 'Resolved'
    Copy-FutureToClipboard -Text ($ips -join "`r`n") -Description "$($ips.Count) IPs (all resolved)"
})

$btnFCopyOnline.Add_Click({
    $ips = Get-FutureIpList -Mode 'Online'
    Copy-FutureToClipboard -Text ($ips -join "`r`n") -Description "$($ips.Count) IPs (online only)"
})

$btnFCopyHostIp.Add_Click({
    $rows = @($global:FutureTargets | Where-Object { $_.IP } | ForEach-Object { "$($_.Hostname),$($_.IP)" })
    Copy-FutureToClipboard -Text (("Hostname,IP" + "`r`n") + ($rows -join "`r`n")) -Description "$($rows.Count) host/IP rows"
})

$btnFExport.Add_Click({
    if ($global:FutureTargets.Count -eq 0) { Log "Nothing to export."; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "CSV Files|*.csv"
    $dlg.FileName = "FutureTargetIPs_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $lines = [System.Collections.ArrayList]::new()
        [void]$lines.Add('"Hostname","ASID","IP","Status","LatencyMs"')
        foreach ($t in $global:FutureTargets) {
            $statusText = if ($t.Online) { 'Online' } elseif ($t.ResolveOk) { 'Offline' } else { 'DNS Failed' }
            $lat = if ($t.Latency -ge 0) { $t.Latency } else { '' }
            [void]$lines.Add("`"$($t.Hostname)`",`"$($t.ASID)`",`"$($t.IP)`",`"$statusText`",`"$lat`"")
        }
        [System.IO.File]::WriteAllLines($dlg.FileName, $lines, [System.Text.Encoding]::UTF8)
        Log "Exported Future Target IPs: $($global:FutureTargets.Count) rows"
    } catch { Log "ERROR exporting: $_" }
})
#endregion

#region === TAB 6: WEEKLY EXPORT ===
# Splits the monthly ACAS_Calculations workbook into per-week summary cards.
# Two enclaves (NIPR / SIPR) toggle via the top button strip. Each week
# shows: header card (date range + Export Week buttons + stale warning),
# 4 metric tiles (Total Vulns, AR w/ PMO, AR w/o PMO, VPH), MAJCOM mini-card,
# and 5 category cards (UEs, Servers, Infrastructure, Printers, PMO) with
# a PMO-by-owner roll-up underneath. Builds dynamically in
# Refresh-WeeklyExportTab so a new file load fully repaints.

$panelWeekly = New-Object System.Windows.Forms.Panel
$panelWeekly.Dock = 'Fill'
$panelWeekly.BackColor = $colors.Background
$panelWeekly.Visible = $false
$panelWeekly.AutoScroll = $true   # Wheel-scrolling has to live on the outermost panel; the inner pnlWeeklyContent had AutoScroll but never received wheel events because focus stayed on the form.
$contentArea.Controls.Add($panelWeekly)
$global:TabPanels['Weekly Export'] = $panelWeekly

$lblWeeklyHdr = New-Object System.Windows.Forms.Label
$lblWeeklyHdr.Text = "WEEKLY ACAS EXPORT"
$lblWeeklyHdr.Location = [System.Drawing.Point]::new(10, 8)
$lblWeeklyHdr.AutoSize = $true
$lblWeeklyHdr.Font = $fonts.Subtitle
$lblWeeklyHdr.ForeColor = $colors.Gold
$panelWeekly.Controls.Add($lblWeeklyHdr)

$lblWeeklySub = New-Object System.Windows.Forms.Label
$lblWeeklySub.Text = "Per-week summary, AR % with/without PMO, MAJCOM score, and VPH by category (UEs / Servers / Infrastructure / Printers / PMO by owner). Two enclaves: NIPR (left side of workbook) and SIPR (right side, TT scans)."
$lblWeeklySub.Location = [System.Drawing.Point]::new(10, 28)
$lblWeeklySub.Size = [System.Drawing.Size]::new(1160, 32)
$lblWeeklySub.Font = $fonts.Small
$lblWeeklySub.ForeColor = $colors.TextDim
$lblWeeklySub.Anchor = 'Top,Left,Right'
$panelWeekly.Controls.Add($lblWeeklySub)

# ===== Toolbar row =====
# Layout: Load | Export CSV | Export XLSX | Source label
# Source label is AutoSize so it grows with the filename; placing it last
# lets it extend rightward without overlapping the buttons. The earlier
# layout (label after Load, buttons right-anchored) had two bugs: (1)
# Anchor='Top,Right' snapshots a stale offset against the unsized invisible
# panel and pushes buttons off-screen, (2) even with right anchor working,
# the AutoSize source label would overlap the buttons at typical filename
# lengths. Both fixed by reordering.
$btnLoadCalc = New-StyledButton -Text "Load ACAS_Calculations CSV" -Location ([System.Drawing.Point]::new(10, 68)) -Size ([System.Drawing.Size]::new(220, 30)) -BgColor $colors.Accent
$panelWeekly.Controls.Add($btnLoadCalc)

$btnExportAllCsv = New-StyledButton -Text "Export All Weeks (CSV)" -Location ([System.Drawing.Point]::new(240, 68)) -Size ([System.Drawing.Size]::new(190, 30)) -BgColor $colors.PanelLight
$panelWeekly.Controls.Add($btnExportAllCsv)

$btnExportAllXlsx = New-StyledButton -Text "Export All Weeks (XLSX)" -Location ([System.Drawing.Point]::new(440, 68)) -Size ([System.Drawing.Size]::new(200, 30)) -BgColor $colors.PanelLight
$panelWeekly.Controls.Add($btnExportAllXlsx)

$btnWeeklyHtml = New-StyledButton -Text "Open HTML Report" -Location ([System.Drawing.Point]::new(650, 68)) -Size ([System.Drawing.Size]::new(160, 30)) -BgColor $colors.Gold -FgColor ([System.Drawing.Color]::Black)
$panelWeekly.Controls.Add($btnWeeklyHtml)
$btnWeeklyHtml.Add_Click({
    if ($global:AcasCalcWeeks.Count -eq 0) {
        [WptDialog]::Show("Load an ACAS_Calculations CSV first.", "No Data", 'OK', 'Information'); return
    }
    Open-WeeklyHtmlReport
})

$script:lblWeeklySource = New-Object System.Windows.Forms.Label
$script:lblWeeklySource.Text = "No workbook loaded. Click Load to pick a monthly ACAS_Calculations CSV."
$script:lblWeeklySource.Location = [System.Drawing.Point]::new(820, 75)
$script:lblWeeklySource.AutoSize = $true
$script:lblWeeklySource.Font = $fonts.Small
$script:lblWeeklySource.ForeColor = $colors.TextSecondary
$panelWeekly.Controls.Add($script:lblWeeklySource)

# ===== Enclave toggle row =====
$script:btnEnclaveNipr = New-Object System.Windows.Forms.Button
$script:btnEnclaveNipr.Text = "  NIPR  (Left side - In-House)"
$script:btnEnclaveNipr.TextAlign = 'MiddleLeft'
$script:btnEnclaveNipr.Location = [System.Drawing.Point]::new(10, 108)
$script:btnEnclaveNipr.Size = [System.Drawing.Size]::new(280, 36)
$script:btnEnclaveNipr.FlatStyle = 'Flat'
$script:btnEnclaveNipr.FlatAppearance.BorderSize = 0
$script:btnEnclaveNipr.BackColor = $colors.Accent
$script:btnEnclaveNipr.ForeColor = [System.Drawing.Color]::White
$script:btnEnclaveNipr.Font = $fonts.LabelBold
$script:btnEnclaveNipr.Cursor = [System.Windows.Forms.Cursors]::Hand
$panelWeekly.Controls.Add($script:btnEnclaveNipr)

$script:btnEnclaveSipr = New-Object System.Windows.Forms.Button
$script:btnEnclaveSipr.Text = "  SIPR  (Right side - TT scans)"
$script:btnEnclaveSipr.TextAlign = 'MiddleLeft'
$script:btnEnclaveSipr.Location = [System.Drawing.Point]::new(294, 108)
$script:btnEnclaveSipr.Size = [System.Drawing.Size]::new(280, 36)
$script:btnEnclaveSipr.FlatStyle = 'Flat'
$script:btnEnclaveSipr.FlatAppearance.BorderSize = 0
$script:btnEnclaveSipr.BackColor = $colors.PanelLight
$script:btnEnclaveSipr.ForeColor = $colors.TextSecondary
$script:btnEnclaveSipr.Font = $fonts.LabelBold
$script:btnEnclaveSipr.Cursor = [System.Windows.Forms.Cursors]::Hand
$panelWeekly.Controls.Add($script:btnEnclaveSipr)

$script:lblWeeklyEnclaveHint = New-Object System.Windows.Forms.Label
$script:lblWeeklyEnclaveHint.Text = "Showing NIPR.  Click to switch enclaves."
$script:lblWeeklyEnclaveHint.Location = [System.Drawing.Point]::new(584, 117)
$script:lblWeeklyEnclaveHint.AutoSize = $true
$script:lblWeeklyEnclaveHint.Font = $fonts.Small
$script:lblWeeklyEnclaveHint.ForeColor = $colors.TextDim
$panelWeekly.Controls.Add($script:lblWeeklyEnclaveHint)

# ===== Content host (week cards rebuild into this) =====
# Sizes itself in Refresh-WeeklyExportTab based on the rendered card stack
# height. Outer $panelWeekly has AutoScroll, so we just need this to be tall
# enough to expose all the cards; the parent panel handles wheel scrolling.
$script:pnlWeeklyContent = New-Object System.Windows.Forms.Panel
$script:pnlWeeklyContent.Location = [System.Drawing.Point]::new(10, 154)
$script:pnlWeeklyContent.Size = [System.Drawing.Size]::new(1160, 600)
$script:pnlWeeklyContent.BackColor = $colors.Background
$panelWeekly.Controls.Add($script:pnlWeeklyContent)

# ===== UI-building helpers (closures over the script-scope panel) =====
function New-WeeklyMetricTile {
    # Compact metric tile - label + big value + small delta. Returns a Panel
    # the caller positions. Border stripe at top is the only color carrier
    # so the tile reads dark like the rest of the tool.
    param([string]$Label, [string]$Value, [string]$Delta,
          [System.Drawing.Color]$StripeColor,
          [System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = $Location; $p.Size = $Size
    $p.BackColor = $colors.Input
    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Top'; $stripe.Height = 3; $stripe.BackColor = $StripeColor
    $p.Controls.Add($stripe)
    $lblL = New-Object System.Windows.Forms.Label
    $lblL.Text = $Label.ToUpper(); $lblL.Location = [System.Drawing.Point]::new(10, 10)
    $lblL.AutoSize = $true; $lblL.Font = $fonts.Small; $lblL.ForeColor = $colors.TextDim
    $p.Controls.Add($lblL)
    $lblV = New-Object System.Windows.Forms.Label
    $lblV.Text = $Value; $lblV.Location = [System.Drawing.Point]::new(10, 28)
    $lblV.AutoSize = $true; $lblV.Font = $fonts.CardValue; $lblV.ForeColor = $colors.TextPrimary
    $p.Controls.Add($lblV)
    if ($Delta) {
        $lblD = New-Object System.Windows.Forms.Label
        $lblD.Text = $Delta; $lblD.Location = [System.Drawing.Point]::new(10, 62)
        $lblD.AutoSize = $true; $lblD.Font = $fonts.Small; $lblD.ForeColor = $colors.TextDim
        $p.Controls.Add($lblD)
    }
    return $p
}

function New-WeeklyCategoryTile {
    # Smaller version for the "By Category" strip - emphasizes VPH.
    param([string]$Label, [string]$Vph, [string]$Stats,
          [System.Drawing.Color]$StripeColor, [bool]$Dimmed = $false,
          [System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = $Location; $p.Size = $Size
    $p.BackColor = $colors.PanelLight
    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Top'; $stripe.Height = 2; $stripe.BackColor = $StripeColor
    $p.Controls.Add($stripe)
    $lblL = New-Object System.Windows.Forms.Label
    $lblL.Text = $Label.ToUpper(); $lblL.Location = [System.Drawing.Point]::new(8, 8)
    $lblL.AutoSize = $true; $lblL.Font = $fonts.SmallBold
    $lblL.ForeColor = if ($Dimmed) { $colors.TextDim } else { $colors.TextSecondary }
    $p.Controls.Add($lblL)
    $lblV = New-Object System.Windows.Forms.Label
    $lblV.Text = $Vph; $lblV.Location = [System.Drawing.Point]::new(8, 24)
    $lblV.AutoSize = $true
    $lblV.Font = New-Object System.Drawing.Font('Cascadia Mono', 15, [System.Drawing.FontStyle]::Bold)
    $lblV.ForeColor = if ($Dimmed) { $colors.TextDim } else { $colors.TextPrimary }
    $p.Controls.Add($lblV)
    $lblS = New-Object System.Windows.Forms.Label
    $lblS.Text = $Stats; $lblS.Location = [System.Drawing.Point]::new(8, 52)
    $lblS.Size = [System.Drawing.Size]::new(($Size.Width - 16), 50)
    $lblS.Font = $fonts.Small
    $lblS.ForeColor = if ($Dimmed) { $colors.TextDim } else { $colors.TextDim }
    $p.Controls.Add($lblS)
    return $p
}

function Set-WeeklyEnclave {
    # Wire up active-button styling and trigger a repaint.
    param([string]$Enclave)
    $global:AcasCalcActiveEnclave = $Enclave
    if ($Enclave -eq 'NIPR') {
        $script:btnEnclaveNipr.BackColor = $colors.Accent; $script:btnEnclaveNipr.ForeColor = [System.Drawing.Color]::White
        $script:btnEnclaveSipr.BackColor = $colors.PanelLight; $script:btnEnclaveSipr.ForeColor = $colors.TextSecondary
        $script:lblWeeklyEnclaveHint.Text = "Showing NIPR.  Click SIPR to switch."
    } else {
        $script:btnEnclaveSipr.BackColor = $colors.Success; $script:btnEnclaveSipr.ForeColor = [System.Drawing.Color]::Black
        $script:btnEnclaveNipr.BackColor = $colors.PanelLight; $script:btnEnclaveNipr.ForeColor = $colors.TextSecondary
        $script:lblWeeklyEnclaveHint.Text = "Showing SIPR.  Click NIPR to switch."
    }
    Refresh-WeeklyExportTab
}

function Refresh-WeeklyExportTab {
    # Rebuild the week-card stack for the active enclave. Called from the
    # tab click handler, the Load button, and Set-WeeklyEnclave.
    if (-not $script:pnlWeeklyContent) { return }
    $panel = $script:pnlWeeklyContent
    $panel.SuspendLayout()
    try {
        foreach ($c in @($panel.Controls)) { $c.Dispose() }
        $panel.Controls.Clear()

        $weeks = @($global:AcasCalcWeeks | Where-Object { $_.Enclave -eq $global:AcasCalcActiveEnclave })
        if ($weeks.Count -eq 0) {
            $lbl = New-Object System.Windows.Forms.Label
            $lbl.Text = "No weeks parsed for $($global:AcasCalcActiveEnclave) yet. Load an ACAS_Calculations CSV to populate this view."
            $lbl.Location = [System.Drawing.Point]::new(10, 20)
            $lbl.AutoSize = $true; $lbl.Font = $fonts.Label; $lbl.ForeColor = $colors.TextDim
            $panel.Controls.Add($lbl)
            return
        }

        $y = 6
        $cardWidth = 1130

        # === Month summary strip (4 tiles) ===
        $monthGood = 0; $monthBad = 0; $monthVulns = 0; $monthCrit = 0; $monthHigh = 0; $monthMed = 0; $monthLow = 0
        $monthMajVulns = 0; $bestMajAr = [double]::NaN
        foreach ($w in $weeks) {
            if ($w.InHouseTotals) {
                $monthGood += $w.InHouseTotals.Good
                $monthBad  += $w.InHouseTotals.Bad
                $monthVulns += $w.InHouseTotals.TotalVulns
                $monthCrit += $w.InHouseTotals.Crit; $monthHigh += $w.InHouseTotals.High
                $monthMed  += $w.InHouseTotals.Med;  $monthLow  += $w.InHouseTotals.Low
            }
            if ($w.MajcomTotals) {
                $monthMajVulns += $w.MajcomTotals.TotalVulns
                if (-not [double]::IsNaN($w.MajcomTotals.ArPct)) {
                    if ([double]::IsNaN($bestMajAr) -or $w.MajcomTotals.ArPct -gt $bestMajAr) {
                        $bestMajAr = $w.MajcomTotals.ArPct
                    }
                }
            }
        }
        $monthAr = if (($monthGood + $monthBad) -gt 0) { [Math]::Round(($monthGood / ($monthGood + $monthBad)) * 100, 2) } else { [double]::NaN }
        $tileW = ([Math]::Floor(($cardWidth - 30) / 4))
        $sumX = 0
        $panel.Controls.Add((New-WeeklyMetricTile -Label "$($global:AcasCalcActiveEnclave) TOTAL VULNS (MONTH)" -Value (Format-AcasNumber $monthVulns) -Delta "CRIT $monthCrit  HIGH $monthHigh  MED $monthMed  LOW $monthLow" -StripeColor $colors.Accent -Location ([System.Drawing.Point]::new($sumX, $y)) -Size ([System.Drawing.Size]::new($tileW, 90))))
        $sumX += $tileW + 10
        $panel.Controls.Add((New-WeeklyMetricTile -Label "AR % WITH PMO (MONTH)" -Value (Format-AcasPercent $monthAr) -Delta "G $(Format-AcasNumber $monthGood)  B $(Format-AcasNumber $monthBad)" -StripeColor $colors.Success -Location ([System.Drawing.Point]::new($sumX, $y)) -Size ([System.Drawing.Size]::new($tileW, 90))))
        $sumX += $tileW + 10
        # Compute month AR w/o PMO across all weeks
        $woGood = 0; $woBad = 0
        foreach ($w in $weeks) {
            $wo = Get-WeeklyArWithoutPmo -Week $w
            $woGood += $wo.Good; $woBad += $wo.Bad
        }
        $woAr = if (($woGood + $woBad) -gt 0) { [Math]::Round(($woGood / ($woGood + $woBad)) * 100, 2) } else { [double]::NaN }
        $panel.Controls.Add((New-WeeklyMetricTile -Label "AR % WITHOUT PMO (MONTH)" -Value (Format-AcasPercent $woAr) -Delta "G $(Format-AcasNumber $woGood)  B $(Format-AcasNumber $woBad)" -StripeColor $colors.Cyan -Location ([System.Drawing.Point]::new($sumX, $y)) -Size ([System.Drawing.Size]::new($tileW, 90))))
        $sumX += $tileW + 10
        $panel.Controls.Add((New-WeeklyMetricTile -Label "MAJCOM TOTAL VULNS" -Value (Format-AcasNumber $monthMajVulns) -Delta ("Best week AR: " + (Format-AcasPercent $bestMajAr)) -StripeColor $colors.Gold -Location ([System.Drawing.Point]::new($sumX, $y)) -Size ([System.Drawing.Size]::new($tileW, 90))))
        $y += 100

        # === Week cards ===
        $weekIdx = 0
        foreach ($w in $weeks) {
            $weekIdx++

            $hasData = ($w.Scans.Count -gt 0) -or ($w.InHouseTotals -and $w.InHouseTotals.TotalVulns -gt 0)
            $cardHeight = if ($hasData) { 470 } else { 110 }

            # Card frame
            $card = New-Object System.Windows.Forms.Panel
            $card.Location = [System.Drawing.Point]::new(0, $y)
            $card.Size = [System.Drawing.Size]::new($cardWidth, $cardHeight)
            $card.BackColor = $colors.Panel
            $panel.Controls.Add($card)

            # Header strip
            $hdrBar = New-Object System.Windows.Forms.Panel
            $hdrBar.Location = [System.Drawing.Point]::new(0, 0)
            $hdrBar.Size = [System.Drawing.Size]::new($cardWidth, 44)
            $hdrBar.BackColor = $colors.PanelLight
            $card.Controls.Add($hdrBar)

            $lblWk = New-Object System.Windows.Forms.Label
            $lblWk.Text = "Week $weekIdx  -  $($w.DateRange)"
            $lblWk.Location = [System.Drawing.Point]::new(12, 14)
            $lblWk.AutoSize = $true; $lblWk.Font = $fonts.LabelBold; $lblWk.ForeColor = $colors.Gold
            $hdrBar.Controls.Add($lblWk)

            if ($w.Stale) {
                $lblWarn = New-Object System.Windows.Forms.Label
                $lblWarn.Text = "STALE - data carry-over detected"
                $lblWarn.Location = [System.Drawing.Point]::new(420, 16)
                $lblWarn.AutoSize = $true; $lblWarn.Font = $fonts.SmallBold; $lblWarn.ForeColor = $colors.Danger
                $hdrBar.Controls.Add($lblWarn)
            }

            $btnExWk = New-StyledButton -Text "Export Week CSV" -Location ([System.Drawing.Point]::new(($cardWidth - 170), 8)) -Size ([System.Drawing.Size]::new(160, 28)) -BgColor $colors.Accent
            if (-not $hasData) { $btnExWk.Enabled = $false; $btnExWk.BackColor = $colors.PanelLight; $btnExWk.ForeColor = $colors.TextDim }
            $btnExWk.Tag = $w
            $btnExWk.Add_Click({
                $week = $this.Tag
                $dlg = New-Object System.Windows.Forms.SaveFileDialog
                $dlg.Filter = "CSV Files|*.csv"
                $dlg.FileName = Get-WeeklySafeFileName -Week $week -Extension 'csv'
                if ($dlg.ShowDialog() -ne 'OK') { return }
                try {
                    Export-WeeklyToCsv -Week $week -Path $dlg.FileName
                    Log "Exported week $($week.Enclave) $($week.DateRange) -> $(Split-Path $dlg.FileName -Leaf)"
                    [WptDialog]::Show("Week exported.`n$($dlg.FileName)", "Exported", 'OK', 'Information')
                } catch { Log "ERROR exporting week: $_" }
            }.GetNewClosure())
            $hdrBar.Controls.Add($btnExWk)

            if (-not $hasData) {
                $lblEmpty = New-Object System.Windows.Forms.Label
                $msg = "No populated scan rows."
                if ($w.Stale) { $msg += "  MAJCOM row has data - flagged as stale carry-over." }
                $lblEmpty.Text = $msg
                $lblEmpty.Location = [System.Drawing.Point]::new(14, 62)
                $lblEmpty.AutoSize = $true; $lblEmpty.Font = $fonts.Small; $lblEmpty.ForeColor = $colors.TextDim
                $card.Controls.Add($lblEmpty)
                $y += $cardHeight + 10
                continue
            }

            # ---- 4 metric tiles on the card ----
            $arWith = if ($w.InHouseTotals) { $w.InHouseTotals.ArPct } else { [double]::NaN }
            $wo = Get-WeeklyArWithoutPmo -Week $w
            $vphHere = if ($w.InHouseTotals) { $w.InHouseTotals.Vph } else { [double]::NaN }
            $vulnsHere = if ($w.InHouseTotals) { $w.InHouseTotals.TotalVulns } else { 0 }
            $crit = if ($w.InHouseTotals) { $w.InHouseTotals.Crit } else { 0 }
            $high = if ($w.InHouseTotals) { $w.InHouseTotals.High } else { 0 }
            $med  = if ($w.InHouseTotals) { $w.InHouseTotals.Med  } else { 0 }
            $low  = if ($w.InHouseTotals) { $w.InHouseTotals.Low  } else { 0 }
            $good = if ($w.InHouseTotals) { $w.InHouseTotals.Good } else { 0 }
            $badH = if ($w.InHouseTotals) { $w.InHouseTotals.Bad  } else { 0 }

            $mY = 56
            $mTileW = 220; $mGap = 10
            $card.Controls.Add((New-WeeklyMetricTile -Label "Total Vulns" -Value (Format-AcasNumber $vulnsHere) -Delta "CRIT $crit  HIGH $high  MED $med  LOW $low" -StripeColor $colors.Accent -Location ([System.Drawing.Point]::new(12, $mY)) -Size ([System.Drawing.Size]::new($mTileW, 90))))
            $card.Controls.Add((New-WeeklyMetricTile -Label "AR % w/ PMO" -Value (Format-AcasPercent $arWith) -Delta "G $good  B $badH" -StripeColor $colors.Success -Location ([System.Drawing.Point]::new((12 + ($mTileW + $mGap) * 1), $mY)) -Size ([System.Drawing.Size]::new($mTileW, 90))))
            $card.Controls.Add((New-WeeklyMetricTile -Label "AR % w/o PMO" -Value (Format-AcasPercent $wo.ArPct) -Delta "G $($wo.Good)  B $($wo.Bad)" -StripeColor $colors.Cyan -Location ([System.Drawing.Point]::new((12 + ($mTileW + $mGap) * 2), $mY)) -Size ([System.Drawing.Size]::new($mTileW, 90))))
            $card.Controls.Add((New-WeeklyMetricTile -Label "VPH (Base)" -Value (Format-AcasNumber $vphHere -Format '0.00') -Delta "vulns per host" -StripeColor $colors.Gold -Location ([System.Drawing.Point]::new((12 + ($mTileW + $mGap) * 3), $mY)) -Size ([System.Drawing.Size]::new($mTileW, 90))))

            # ---- MAJCOM panel (right side of card) ----
            # Panel grew from 90 to 110 px tall to fit the new MAJCOM VPH row
            # added per operator request 2026-05-12 (leadership wanted MAJCOM
            # VPH visible alongside the base VPH tile).
            $majX = 12 + ($mTileW + $mGap) * 4 + 4
            $majW = $cardWidth - $majX - 12
            $maj = New-Object System.Windows.Forms.Panel
            $maj.Location = [System.Drawing.Point]::new($majX, $mY)
            $maj.Size = [System.Drawing.Size]::new($majW, 110)
            $maj.BackColor = $colors.Input
            $card.Controls.Add($maj)
            $majStripe = New-Object System.Windows.Forms.Panel
            $majStripe.Dock = 'Top'; $majStripe.Height = 3; $majStripe.BackColor = $colors.Gold
            $maj.Controls.Add($majStripe)
            $lblMajH = New-Object System.Windows.Forms.Label
            $lblMajH.Text = "MAJCOM SCORE ($($w.Enclave))"
            $lblMajH.Location = [System.Drawing.Point]::new(10, 10)
            $lblMajH.AutoSize = $true; $lblMajH.Font = $fonts.SmallBold; $lblMajH.ForeColor = $colors.Gold
            $maj.Controls.Add($lblMajH)
            $majVulns = if ($w.MajcomTotals) { $w.MajcomTotals.TotalVulns } else { 0 }
            $majAr    = if ($w.MajcomTotals) { $w.MajcomTotals.ArPct } else { [double]::NaN }
            $majVph   = if ($w.MajcomTotals) { $w.MajcomTotals.Vph } else { [double]::NaN }
            $lblMajV = New-Object System.Windows.Forms.Label
            $lblMajV.Text = "Vulns: $(Format-AcasNumber $majVulns)"
            $lblMajV.Location = [System.Drawing.Point]::new(10, 30)
            $lblMajV.AutoSize = $true; $lblMajV.Font = $fonts.Label; $lblMajV.ForeColor = $colors.TextPrimary
            $maj.Controls.Add($lblMajV)
            $lblMajAR = New-Object System.Windows.Forms.Label
            $lblMajAR.Text = "AR %: $(Format-AcasPercent $majAr)"
            $lblMajAR.Location = [System.Drawing.Point]::new(10, 50)
            $lblMajAR.AutoSize = $true; $lblMajAR.Font = $fonts.LabelBold
            $lblMajAR.ForeColor = if (-not [double]::IsNaN($majAr) -and $majAr -lt 50) { $colors.Danger } else { $colors.TextPrimary }
            $maj.Controls.Add($lblMajAR)
            $lblMajVph = New-Object System.Windows.Forms.Label
            $majVphStr = if ([double]::IsNaN($majVph)) { 'N/A' } else { $majVph.ToString('0.00') }
            $lblMajVph.Text = "VPH: $majVphStr"
            $lblMajVph.Location = [System.Drawing.Point]::new(10, 70)
            $lblMajVph.AutoSize = $true; $lblMajVph.Font = $fonts.LabelBold; $lblMajVph.ForeColor = $colors.Gold
            $maj.Controls.Add($lblMajVph)
            if ($w.MajcomTotals) {
                $lblMajD = New-Object System.Windows.Forms.Label
                $lblMajD.Text = "G $($w.MajcomTotals.Good)  B $($w.MajcomTotals.Bad)"
                $lblMajD.Location = [System.Drawing.Point]::new(10, 90)
                $lblMajD.AutoSize = $true; $lblMajD.Font = $fonts.Small; $lblMajD.ForeColor = $colors.TextDim
                $maj.Controls.Add($lblMajD)
            }

            # ---- By Category strip ----
            $catY = $mY + 100
            $lblCatHdr = New-Object System.Windows.Forms.Label
            $lblCatHdr.Text = "VPH && TOTALS BY CATEGORY"
            $lblCatHdr.Location = [System.Drawing.Point]::new(12, $catY)
            $lblCatHdr.AutoSize = $true; $lblCatHdr.Font = $fonts.SmallBold; $lblCatHdr.ForeColor = $colors.Cyan
            $card.Controls.Add($lblCatHdr)
            $catY += 22

            $cats = Get-WeeklyCategoryMetrics -Week $w
            $catLineup = @(
                @{ Name = 'UEs';            Color = $colors.Accent  }
                @{ Name = 'Servers';        Color = $colors.Success }
                @{ Name = 'Infrastructure'; Color = $colors.Cyan    }
                @{ Name = 'Printers';       Color = $colors.Orange  }
                @{ Name = 'PMO';            Color = $colors.Gold    }
            )
            $catTileW = 220
            $catGap = 10
            $catX = 12
            foreach ($cdef in $catLineup) {
                $catData = $cats[$cdef.Name]
                if ($catData) {
                    $vphStr = if ([double]::IsNaN($catData.Vph)) { "N/A" } else { $catData.Vph.ToString('0.00') + "  VPH" }
                    $stats  = "Vulns $(Format-AcasNumber $catData.TotalVulns)  -  G $($catData.Good) / B $($catData.Bad)`r`nAR $(Format-AcasPercent $catData.ArPct)  -  $($catData.ScanCount) scan(s)"
                    $card.Controls.Add((New-WeeklyCategoryTile -Label $cdef.Name -Vph $vphStr -Stats $stats -StripeColor $cdef.Color -Location ([System.Drawing.Point]::new($catX, $catY)) -Size ([System.Drawing.Size]::new($catTileW, 110))))
                } else {
                    $card.Controls.Add((New-WeeklyCategoryTile -Label $cdef.Name -Vph "-" -Stats "No scans this week" -StripeColor $cdef.Color -Dimmed $true -Location ([System.Drawing.Point]::new($catX, $catY)) -Size ([System.Drawing.Size]::new($catTileW, 110))))
                }
                $catX += $catTileW + $catGap
            }

            # ---- PMO owner breakdown ----
            $ownY = $catY + 118
            $owners = Get-WeeklyPmoOwnerMetrics -Week $w
            $ownPanel = New-Object System.Windows.Forms.Panel
            $ownPanel.Location = [System.Drawing.Point]::new(12, $ownY)
            $ownPanel.Size = [System.Drawing.Size]::new(($cardWidth - 24), 90)
            $ownPanel.BackColor = $colors.Input
            $card.Controls.Add($ownPanel)
            $ownStripe = New-Object System.Windows.Forms.Panel
            $ownStripe.Dock = 'Top'; $ownStripe.Height = 2; $ownStripe.BackColor = $colors.Gold
            $ownPanel.Controls.Add($ownStripe)
            $lblOwnHdr = New-Object System.Windows.Forms.Label
            $lblOwnHdr.Text = "PMO BREAKDOWN BY OWNER"
            $lblOwnHdr.Location = [System.Drawing.Point]::new(10, 6)
            $lblOwnHdr.AutoSize = $true; $lblOwnHdr.Font = $fonts.SmallBold; $lblOwnHdr.ForeColor = $colors.Gold
            $ownPanel.Controls.Add($lblOwnHdr)
            if ($owners.Count -eq 0) {
                $lblNo = New-Object System.Windows.Forms.Label
                $lblNo.Text = "No PMO scans this week."
                $lblNo.Location = [System.Drawing.Point]::new(10, 28)
                $lblNo.AutoSize = $true; $lblNo.Font = $fonts.Small; $lblNo.ForeColor = $colors.TextDim
                $ownPanel.Controls.Add($lblNo)
            } else {
                # Inline 1-line-per-owner: "Owner | Scans X | VPH Y | Vulns Z"
                $ownLineY = 28
                foreach ($k in ($owners.Keys | Sort-Object)) {
                    $o = $owners[$k]
                    $vphStr = if ([double]::IsNaN($o.Vph)) { "N/A" } else { $o.Vph.ToString('0.00') }
                    $line = New-Object System.Windows.Forms.Label
                    $line.Text = ("{0,-22}  Scans {1,-2}    VPH {2,-8}    Vulns {3,-7}    [G {4} / B {5}]" -f $o.Owner, $o.ScanCount, $vphStr, $o.TotalVulns, $o.Good, $o.Bad)
                    $line.Location = [System.Drawing.Point]::new(10, $ownLineY)
                    $line.AutoSize = $true; $line.Font = $fonts.Console; $line.ForeColor = $colors.TextPrimary
                    $ownPanel.Controls.Add($line)
                    $ownLineY += 16
                }
                $ownPanel.Size = [System.Drawing.Size]::new($ownPanel.Width, ([Math]::Max(60, $ownLineY + 8)))
            }

            # Recompute card height to fit content
            $card.Size = [System.Drawing.Size]::new($cardWidth, ($ownY + $ownPanel.Height + 16))
            $y += $card.Height + 12
        }
        # Resize the host panel so the outer $panelWeekly's AutoScroll
        # sees the full stack height and shows a scrollbar. Without this
        # the host panel stays at its default 600 px and the bottom cards
        # would be unreachable on smaller windows.
        $panel.Size = [System.Drawing.Size]::new($panel.Width, [Math]::Max(600, $y + 20))
    } finally {
        $panel.ResumeLayout()
    }
}

# ===== Button wiring =====
$btnLoadCalc.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "ACAS_Calculations CSV|*.csv|All Files|*.*"
    $dlg.Title = "Select ACAS_Calculations monthly workbook (CSV)"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    Log "Parsing $(Split-Path $dlg.FileName -Leaf)..."
    try {
        $weeks = Parse-AcasCalculationsWorkbook -FilePath $dlg.FileName
        if (-not $weeks) {
            [WptDialog]::Show("No weeks found in the workbook.`nCheck that the file has 'RAW SCAN DATA:' header rows.", "Parse Failed", 'OK', 'Warning')
            return
        }
        $global:AcasCalcWeeks.Clear()
        foreach ($w in $weeks) { [void]$global:AcasCalcWeeks.Add($w) }
        $global:AcasCalcSourceFile = $dlg.FileName
        $nipr = @($weeks | Where-Object { $_.Enclave -eq 'NIPR' }).Count
        $sipr = @($weeks | Where-Object { $_.Enclave -eq 'SIPR' }).Count
        $script:lblWeeklySource.Text = "Source: $(Split-Path $dlg.FileName -Leaf)  -  NIPR: $nipr week(s)  -  SIPR: $sipr week(s)"
        Log "Parsed $($weeks.Count) week-blocks (NIPR=$nipr, SIPR=$sipr) from $(Split-Path $dlg.FileName -Leaf)"
        Refresh-WeeklyExportTab
        # Auto-open the polished HTML view, matching the Dirty 30 flow.
        Open-WeeklyHtmlReport
    } catch {
        Log "ERROR parsing workbook: $_"
        [WptDialog]::Show("Parse error: $_", "Error", 'OK', 'Error')
    }
})

$script:btnEnclaveNipr.Add_Click({ Set-WeeklyEnclave 'NIPR' })
$script:btnEnclaveSipr.Add_Click({ Set-WeeklyEnclave 'SIPR' })

$btnExportAllCsv.Add_Click({
    if ($global:AcasCalcWeeks.Count -eq 0) {
        [WptDialog]::Show("Load an ACAS_Calculations CSV first.", "No Data", 'OK', 'Information'); return
    }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Choose a folder for per-week CSVs (one file per week, per enclave)"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $count = 0
    foreach ($w in $global:AcasCalcWeeks) {
        # Skip empty/stale weeks for bulk export - operator can still do them
        # individually from the per-week button.
        if ($w.Scans.Count -eq 0) { continue }
        $file = Join-Path $dlg.SelectedPath (Get-WeeklySafeFileName -Week $w -Extension 'csv')
        try {
            Export-WeeklyToCsv -Week $w -Path $file
            $count++
        } catch { Log "ERROR exporting $($w.Enclave) $($w.DateRange): $_" }
    }
    Log "Exported $count week file(s) to $($dlg.SelectedPath)"
    [WptDialog]::Show("Exported $count week file(s) to:`n$($dlg.SelectedPath)`n`nEmpty weeks were skipped.", "Done", 'OK', 'Information')
})

$btnExportAllXlsx.Add_Click({
    if ($global:AcasCalcWeeks.Count -eq 0) {
        [WptDialog]::Show("Load an ACAS_Calculations CSV first.", "No Data", 'OK', 'Information'); return
    }
    # ImportExcel is optional - degrade to CSV bundle if not present, matching
    # the pattern used by the existing Export tab buttons.
    $hasIE = $false
    try { if (Get-Module -ListAvailable -Name ImportExcel) { Import-Module ImportExcel -ErrorAction Stop; $hasIE = $true } } catch {}
    if (-not $hasIE) {
        [WptDialog]::Show("ImportExcel module not installed.`nFalling back to per-week CSV export.", "XLSX Unavailable", 'OK', 'Information')
        $btnExportAllCsv.PerformClick(); return
    }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Choose a folder for the per-enclave XLSX workbooks"
    if ($dlg.ShowDialog() -ne 'OK') { return }

    foreach ($enclave in 'NIPR','SIPR') {
        $weeks = @($global:AcasCalcWeeks | Where-Object { $_.Enclave -eq $enclave -and $_.Scans.Count -gt 0 })
        if ($weeks.Count -eq 0) { continue }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $out = Join-Path $dlg.SelectedPath "ACAS_Weekly_${enclave}_$stamp.xlsx"
        try {
            $monthRows = foreach ($w in $weeks) {
                $wo = Get-WeeklyArWithoutPmo -Week $w
                [PSCustomObject]@{
                    Week        = $w.DateRange
                    Enclave     = $w.Enclave
                    TotalVulns  = if ($w.InHouseTotals) { $w.InHouseTotals.TotalVulns } else { 0 }
                    'AR_w_PMO'  = if ($w.InHouseTotals) { $w.InHouseTotals.ArPct } else { $null }
                    'AR_wo_PMO' = $wo.ArPct
                    Vph         = if ($w.InHouseTotals) { $w.InHouseTotals.Vph } else { $null }
                    MajcomVulns = if ($w.MajcomTotals)  { $w.MajcomTotals.TotalVulns } else { 0 }
                    MajcomAr    = if ($w.MajcomTotals)  { $w.MajcomTotals.ArPct } else { $null }
                    Stale       = $w.Stale
                }
            }
            $monthRows | Export-Excel -Path $out -WorksheetName 'Month Summary' -AutoSize -BoldTopRow
            foreach ($w in $weeks) {
                $sheetName = ("Week_" + ($w.DateRange -replace '[^A-Za-z0-9_\- ]','' -replace '\s+','_'))
                if ($sheetName.Length -gt 31) { $sheetName = $sheetName.Substring(0, 31) }
                $w.Scans | Export-Excel -Path $out -WorksheetName $sheetName -AutoSize -BoldTopRow -Append:$false
            }
            Log "Exported $enclave workbook -> $out"
        } catch {
            Log "ERROR writing $enclave XLSX: $_"
        }
    }
    [WptDialog]::Show("XLSX workbooks written to:`n$($dlg.SelectedPath)`n`nOne workbook per enclave (NIPR / SIPR).", "Done", 'OK', 'Information')
})
#endregion

#region === TAB 7: DIRTY 30 TRIAGE ===
# Loads the Tenable Dirty 30 (Top 30 Worst Hosts) report, extracts hostnames,
# and runs them through an AD lookup to surface squadron + last AD logon +
# stale detection (>90 days). Optional second pass probes each box's
# registry for the last logged-on user (off by default - requires network
# reach to every target). Grid + filters + CSV export.

$panelDirty30 = New-Object System.Windows.Forms.Panel
$panelDirty30.Dock = 'Fill'
$panelDirty30.BackColor = $colors.Background
$panelDirty30.Visible = $false
$contentArea.Controls.Add($panelDirty30)
$global:TabPanels['Dirty 30 Triage'] = $panelDirty30

$lblD30Hdr = New-Object System.Windows.Forms.Label
$lblD30Hdr.Text = "DIRTY 30 TRIAGE"
$lblD30Hdr.Location = [System.Drawing.Point]::new(10, 8)
$lblD30Hdr.AutoSize = $true; $lblD30Hdr.Font = $fonts.Subtitle; $lblD30Hdr.ForeColor = $colors.Gold
$panelDirty30.Controls.Add($lblD30Hdr)

$lblD30Sub = New-Object System.Windows.Forms.Label
$lblD30Sub.Text = "Open the Tenable Dirty 30 PDF in any viewer, Ctrl+A then Ctrl+C, click Paste from Clipboard. Or load a CSV/TXT export. Run AD lookup to surface squadron, last AD logon, and stale machines. Optional probe gets the last interactive user from each host."
$lblD30Sub.Location = [System.Drawing.Point]::new(10, 28)
$lblD30Sub.Size = [System.Drawing.Size]::new(1160, 32)
$lblD30Sub.Font = $fonts.Small; $lblD30Sub.ForeColor = $colors.TextDim
$lblD30Sub.Anchor = 'Top,Left,Right'
$panelDirty30.Controls.Add($lblD30Sub)

# ===== Input stage: load button + paste textbox =====
$btnD30Load = New-StyledButton -Text "Load File (PDF / CSV / TXT)" -Location ([System.Drawing.Point]::new(10, 68)) -Size ([System.Drawing.Size]::new(210, 30)) -BgColor $colors.Accent
$panelDirty30.Controls.Add($btnD30Load)

$btnD30Paste = New-StyledButton -Text "Paste from Clipboard" -Location ([System.Drawing.Point]::new(230, 68)) -Size ([System.Drawing.Size]::new(170, 30)) -BgColor $colors.PanelLight
$panelDirty30.Controls.Add($btnD30Paste)

$btnD30Parse = New-StyledButton -Text "Parse Pasted Text" -Location ([System.Drawing.Point]::new(410, 68)) -Size ([System.Drawing.Size]::new(150, 30)) -BgColor $colors.PanelLight
$panelDirty30.Controls.Add($btnD30Parse)

$btnD30Clear = New-StyledButton -Text "Clear" -Location ([System.Drawing.Point]::new(570, 68)) -Size ([System.Drawing.Size]::new(70, 30)) -BgColor $colors.PanelLight
$panelDirty30.Controls.Add($btnD30Clear)

$script:txtD30Paste = New-Object System.Windows.Forms.TextBox
$script:txtD30Paste.Multiline = $true
$script:txtD30Paste.ScrollBars = 'Vertical'
$script:txtD30Paste.AcceptsReturn = $true
$script:txtD30Paste.Location = [System.Drawing.Point]::new(10, 105)
$script:txtD30Paste.Size = [System.Drawing.Size]::new(1160, 90)
$script:txtD30Paste.BackColor = $colors.Input
$script:txtD30Paste.ForeColor = $colors.TextPrimary
$script:txtD30Paste.Font = $fonts.Console
$script:txtD30Paste.BorderStyle = 'FixedSingle'
$script:txtD30Paste.Text = "Paste Dirty 30 PDF text here, or click Load to pick a CSV/TXT. The parser handles Tenable PDF rows like 'AREA52.AFNOAPPS.USAF.MIL\MSEKT-927JYX2', DNS rows like 'msekt-927jyx2.area52.afnoapps.usaf.mil', CSV with NetBIOS/Hostname/Score columns, or plain one-host-per-line lists."
$script:txtD30Paste.Anchor = 'Top,Left,Right'
$panelDirty30.Controls.Add($script:txtD30Paste)

# ===== Toolbar: AD lookup + probe + export + copy =====
$btnD30Lookup = New-StyledButton -Text "Run AD Lookup" -Location ([System.Drawing.Point]::new(10, 208)) -Size ([System.Drawing.Size]::new(160, 32)) -BgColor $colors.Cyan -FgColor ([System.Drawing.Color]::Black)
$btnD30Lookup.Enabled = $false
$panelDirty30.Controls.Add($btnD30Lookup)

$btnD30Probe = New-StyledButton -Text "+ Probe Last User" -Location ([System.Drawing.Point]::new(180, 208)) -Size ([System.Drawing.Size]::new(160, 32)) -BgColor $colors.PanelLight
$btnD30Probe.Enabled = $false
$panelDirty30.Controls.Add($btnD30Probe)

$btnD30Html = New-StyledButton -Text "Open HTML Report" -Location ([System.Drawing.Point]::new(350, 208)) -Size ([System.Drawing.Size]::new(160, 32)) -BgColor $colors.Gold -FgColor ([System.Drawing.Color]::Black)
$btnD30Html.Enabled = $false
$panelDirty30.Controls.Add($btnD30Html)

$btnD30Export = New-StyledButton -Text "Export CSV" -Location ([System.Drawing.Point]::new(520, 208)) -Size ([System.Drawing.Size]::new(110, 32)) -BgColor $colors.PanelLight
$btnD30Export.Enabled = $false
$panelDirty30.Controls.Add($btnD30Export)

$btnD30Copy = New-StyledButton -Text "Copy Hostnames" -Location ([System.Drawing.Point]::new(640, 208)) -Size ([System.Drawing.Size]::new(140, 32)) -BgColor $colors.PanelLight
$btnD30Copy.Enabled = $false
$panelDirty30.Controls.Add($btnD30Copy)

$script:lblD30Status = New-Object System.Windows.Forms.Label
$script:lblD30Status.Text = "No hosts loaded."
$script:lblD30Status.Location = [System.Drawing.Point]::new(790, 215)
$script:lblD30Status.AutoSize = $true; $script:lblD30Status.Font = $fonts.Small; $script:lblD30Status.ForeColor = $colors.TextDim
$panelDirty30.Controls.Add($script:lblD30Status)

# ===== Summary strip: 5 metric tiles =====
$d30TileY = 250
function New-D30Tile {
    param([string]$Label, [string]$Value, [string]$Sub, [System.Drawing.Color]$StripeColor,
          [System.Drawing.Color]$ValueColor, [System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = $Location; $p.Size = $Size; $p.BackColor = $colors.Panel
    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Top'; $stripe.Height = 3; $stripe.BackColor = $StripeColor
    $p.Controls.Add($stripe)
    $lblL = New-Object System.Windows.Forms.Label
    $lblL.Text = $Label.ToUpper(); $lblL.Location = [System.Drawing.Point]::new(10, 10)
    $lblL.AutoSize = $true; $lblL.Font = $fonts.Small; $lblL.ForeColor = $colors.TextDim
    $p.Controls.Add($lblL)
    $lblV = New-Object System.Windows.Forms.Label
    $lblV.Text = $Value; $lblV.Location = [System.Drawing.Point]::new(10, 28)
    $lblV.AutoSize = $true; $lblV.Font = $fonts.CardValue; $lblV.ForeColor = $ValueColor
    $p.Controls.Add($lblV)
    if ($Sub) {
        $lblS = New-Object System.Windows.Forms.Label
        $lblS.Text = $Sub; $lblS.Location = [System.Drawing.Point]::new(10, 62)
        $lblS.AutoSize = $true; $lblS.Font = $fonts.Small; $lblS.ForeColor = $colors.TextDim
        $p.Controls.Add($lblS)
    }
    $p.Tag = @{ ValueLabel = $lblV; SubLabel = $lblS }
    return $p
}
$d30TileW = 225; $d30Gap = 8
$script:tilesD30Parsed   = New-D30Tile -Label "Hosts Parsed"  -Value "0" -Sub "" -StripeColor $colors.Accent  -ValueColor $colors.TextPrimary -Location ([System.Drawing.Point]::new(10,                                  $d30TileY)) -Size ([System.Drawing.Size]::new($d30TileW, 90))
$script:tilesD30Active   = New-D30Tile -Label "AD: Active"    -Value "0" -Sub "" -StripeColor $colors.Success -ValueColor $colors.Success     -Location ([System.Drawing.Point]::new((10 + ($d30TileW + $d30Gap) * 1), $d30TileY)) -Size ([System.Drawing.Size]::new($d30TileW, 90))
$script:tilesD30Stale    = New-D30Tile -Label "AD: Stale"     -Value "0" -Sub "" -StripeColor $colors.Warning -ValueColor $colors.Warning     -Location ([System.Drawing.Point]::new((10 + ($d30TileW + $d30Gap) * 2), $d30TileY)) -Size ([System.Drawing.Size]::new($d30TileW, 90))
$script:tilesD30NotFound = New-D30Tile -Label "AD: Not Found" -Value "0" -Sub "" -StripeColor $colors.Danger  -ValueColor $colors.Danger      -Location ([System.Drawing.Point]::new((10 + ($d30TileW + $d30Gap) * 3), $d30TileY)) -Size ([System.Drawing.Size]::new($d30TileW, 90))
$script:tilesD30TopSquad = New-D30Tile -Label "Top Squadron"  -Value "—" -Sub "" -StripeColor $colors.Gold    -ValueColor $colors.Gold        -Location ([System.Drawing.Point]::new((10 + ($d30TileW + $d30Gap) * 4), $d30TileY)) -Size ([System.Drawing.Size]::new($d30TileW, 90))
$panelDirty30.Controls.Add($script:tilesD30Parsed)
$panelDirty30.Controls.Add($script:tilesD30Active)
$panelDirty30.Controls.Add($script:tilesD30Stale)
$panelDirty30.Controls.Add($script:tilesD30NotFound)
$panelDirty30.Controls.Add($script:tilesD30TopSquad)

# ===== Squadron breakdown strip (auto-rebuilds with chips) =====
$script:pnlD30Squadrons = New-Object System.Windows.Forms.FlowLayoutPanel
$script:pnlD30Squadrons.Location = [System.Drawing.Point]::new(10, ($d30TileY + 100))
$script:pnlD30Squadrons.Size = [System.Drawing.Size]::new(1160, 60)
$script:pnlD30Squadrons.BackColor = $colors.Panel
$script:pnlD30Squadrons.AutoScroll = $true
$script:pnlD30Squadrons.WrapContents = $true
$script:pnlD30Squadrons.Padding = New-Object System.Windows.Forms.Padding(8)
$script:pnlD30Squadrons.Anchor = 'Top,Left,Right'
$panelDirty30.Controls.Add($script:pnlD30Squadrons)

# ===== Filter bar =====
$d30FilterY = $d30TileY + 168
$lblD30Filter = New-Object System.Windows.Forms.Label
$lblD30Filter.Text = "VIEW"; $lblD30Filter.Location = [System.Drawing.Point]::new(10, ($d30FilterY + 6))
$lblD30Filter.AutoSize = $true; $lblD30Filter.Font = $fonts.SmallBold; $lblD30Filter.ForeColor = $colors.TextDim
$panelDirty30.Controls.Add($lblD30Filter)

function New-D30PillButton {
    param([string]$Text, [System.Drawing.Point]$Location, [System.Drawing.Color]$ActiveBg)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = $Location
    $b.Size = [System.Drawing.Size]::new(110, 28)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.BorderColor = $colors.InputBorder
    $b.BackColor = $colors.Input; $b.ForeColor = $colors.TextSecondary
    $b.Font = $fonts.Small
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    $b.Tag = @{ ActiveBg = $ActiveBg }
    return $b
}
$script:btnD30FilterAll      = New-D30PillButton -Text "All"        -Location ([System.Drawing.Point]::new( 60, $d30FilterY)) -ActiveBg $colors.Accent
$script:btnD30FilterStale    = New-D30PillButton -Text "Stale"      -Location ([System.Drawing.Point]::new(176, $d30FilterY)) -ActiveBg $colors.Warning
$script:btnD30FilterNotFound = New-D30PillButton -Text "Not Found"  -Location ([System.Drawing.Point]::new(292, $d30FilterY)) -ActiveBg $colors.Danger
$panelDirty30.Controls.Add($script:btnD30FilterAll)
$panelDirty30.Controls.Add($script:btnD30FilterStale)
$panelDirty30.Controls.Add($script:btnD30FilterNotFound)

$lblD30Search = New-Object System.Windows.Forms.Label
$lblD30Search.Text = "SEARCH"; $lblD30Search.Location = [System.Drawing.Point]::new(420, ($d30FilterY + 6))
$lblD30Search.AutoSize = $true; $lblD30Search.Font = $fonts.SmallBold; $lblD30Search.ForeColor = $colors.TextDim
$panelDirty30.Controls.Add($lblD30Search)

$script:txtD30Search = New-Object System.Windows.Forms.TextBox
$script:txtD30Search.Location = [System.Drawing.Point]::new(478, ($d30FilterY + 2))
$script:txtD30Search.Size = [System.Drawing.Size]::new(280, 24)
$script:txtD30Search.BackColor = $colors.Input
$script:txtD30Search.ForeColor = $colors.TextPrimary
$script:txtD30Search.Font = $fonts.Console
$script:txtD30Search.BorderStyle = 'FixedSingle'
$panelDirty30.Controls.Add($script:txtD30Search)

# ===== Results grid =====
$d30GridY = $d30FilterY + 38
$script:gridD30 = New-Object System.Windows.Forms.DataGridView
$script:gridD30.Location = [System.Drawing.Point]::new(10, $d30GridY)
$script:gridD30.Size = [System.Drawing.Size]::new(1160, 380)
$script:gridD30.BackgroundColor = $colors.GridBg
$script:gridD30.GridColor = $colors.InputBorder
$script:gridD30.BorderStyle = 'FixedSingle'
$script:gridD30.AllowUserToAddRows = $false
$script:gridD30.AllowUserToDeleteRows = $false
$script:gridD30.ReadOnly = $true
$script:gridD30.RowHeadersVisible = $false
$script:gridD30.SelectionMode = 'FullRowSelect'
$script:gridD30.MultiSelect = $false
$script:gridD30.AutoSizeColumnsMode = 'Fill'
$script:gridD30.EnableHeadersVisualStyles = $false
$script:gridD30.ColumnHeadersDefaultCellStyle.BackColor = $colors.GridHeader
$script:gridD30.ColumnHeadersDefaultCellStyle.ForeColor = $colors.Gold
$script:gridD30.ColumnHeadersDefaultCellStyle.Font = $fonts.SmallBold
$script:gridD30.DefaultCellStyle.BackColor = $colors.GridBg
$script:gridD30.DefaultCellStyle.ForeColor = $colors.TextPrimary
$script:gridD30.DefaultCellStyle.SelectionBackColor = $colors.SidebarActive
$script:gridD30.DefaultCellStyle.SelectionForeColor = $colors.TextPrimary
$script:gridD30.RowsDefaultCellStyle.BackColor = $colors.GridBg
$script:gridD30.AlternatingRowsDefaultCellStyle.BackColor = $colors.Panel
$script:gridD30.Anchor = 'Top,Left,Right,Bottom'
$script:gridD30.Font = $fonts.Small

foreach ($colDef in @(
    @{ Name = 'Hostname'; Header = 'Hostname'; Width = 110; Fill = 12 }
    @{ Name = 'Score';    Header = 'Score';    Width =  60; Fill =  6 }
    @{ Name = 'Vulns';    Header = 'Vulns (C/H/M/L)'; Width = 110; Fill = 11 }
    @{ Name = 'LastAd';   Header = 'Last AD Logon';   Width = 120; Fill = 12 }
    @{ Name = 'LastUser'; Header = 'Last User';       Width = 130; Fill = 14 }
    @{ Name = 'Squadron'; Header = 'Squadron';        Width =  90; Fill =  9 }
    @{ Name = 'OU';       Header = 'OU / Location';   Width = 240; Fill = 24 }
    @{ Name = 'Status';   Header = 'Status';          Width =  80; Fill =  8 }
)) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $colDef.Name; $col.HeaderText = $colDef.Header
    $col.Width = $colDef.Width; $col.FillWeight = $colDef.Fill
    [void]$script:gridD30.Columns.Add($col)
}
$panelDirty30.Controls.Add($script:gridD30)

# ===== Refresh function =====
function Refresh-Dirty30Tab {
    if (-not $script:gridD30) { return }

    # Determine which hosts to show based on active filter + search
    $search = $script:txtD30Search.Text.Trim().ToLower()
    $filtered = [System.Collections.ArrayList]::new()
    foreach ($d30h in $global:Dirty30Hosts) {
        $ad = $global:Dirty30AdResults[$d30h.Hostname]
        $status = if ($ad) { $ad.Status } else { 'Unknown' }
        $squadron = if ($ad) { $ad.Squadron } else { '' }
        $ouChain = if ($ad -and $ad.PSObject.Properties['LocationInfo'] -and $ad.LocationInfo) { $ad.LocationInfo } elseif ($ad) { $ad.OUChain } else { '' }

        $passFilter = switch ($global:Dirty30ActiveFilter) {
            'All'      { $true }
            'Stale'    { $status -eq 'Stale' }
            'NotFound' { $status -eq 'Not Found' }
            default    { $squadron -eq $global:Dirty30ActiveFilter }
        }
        if (-not $passFilter) { continue }

        if ($search) {
            $hay = "$($d30h.Hostname) $squadron $ouChain $status".ToLower()
            if ($hay -notmatch [regex]::Escape($search)) { continue }
        }
        [void]$filtered.Add($d30h)
    }

    # Repopulate grid
    $script:gridD30.SuspendLayout()
    try {
        $script:gridD30.Rows.Clear()
        foreach ($d30h in $filtered) {
            $ad = $global:Dirty30AdResults[$d30h.Hostname]
            $vulnStr = if ($d30h.Score -gt 0 -or $d30h.Crit -gt 0 -or $d30h.High -gt 0) {
                "$($d30h.Crit) / $($d30h.High) / $($d30h.Med) / $($d30h.Low)"
            } else { '—' }
            $scoreStr = if ($d30h.Score -gt 0) { $d30h.Score.ToString('N0') } else { '—' }
            $lastAd = if ($ad) { $ad.LastLogon } else { '' }
            $lastUser = if ($global:Dirty30LastUserMap.ContainsKey($d30h.Hostname)) { $global:Dirty30LastUserMap[$d30h.Hostname] } elseif ($ad) { $ad.LastUser } else { '' }
            $sq = if ($ad) { $ad.Squadron } else { '' }
            $ou = if ($ad -and $ad.PSObject.Properties['LocationInfo'] -and $ad.LocationInfo) { $ad.LocationInfo } elseif ($ad) { $ad.OUChain } else { '' }
            $st = if ($ad) { $ad.Status } else { '' }

            $rowIdx = $script:gridD30.Rows.Add($d30h.Hostname, $scoreStr, $vulnStr, $lastAd, $lastUser, $sq, $ou, $st)
            $row = $script:gridD30.Rows[$rowIdx]
            $row.Cells['Hostname'].Style.ForeColor = $colors.Cyan
            $row.Cells['Hostname'].Style.Font = $fonts.SmallBold
            $row.Cells['Score'].Style.ForeColor = $colors.Gold
            $row.Cells['Score'].Style.Font = $fonts.SmallBold
            $row.Cells['Squadron'].Style.ForeColor = $colors.Gold
            $row.Cells['OU'].Style.ForeColor = $colors.TextDim
            if ($st -eq 'Stale') {
                $row.Cells['Status'].Style.ForeColor = $colors.Warning
                $row.Cells['LastAd'].Style.ForeColor = $colors.Warning
            } elseif ($st -eq 'Active') {
                $row.Cells['Status'].Style.ForeColor = $colors.Success
            } elseif ($st -eq 'Not Found') {
                $row.Cells['Status'].Style.ForeColor = $colors.Danger
                $row.Cells['Squadron'].Style.ForeColor = $colors.Danger
            }
        }
    } finally {
        $script:gridD30.ResumeLayout()
    }

    # Update summary tiles
    $totalParsed = $global:Dirty30Hosts.Count
    $activeCount = 0; $staleCount = 0; $notFoundCount = 0
    $sqCounts = @{}
    foreach ($d30h in $global:Dirty30Hosts) {
        $ad = $global:Dirty30AdResults[$d30h.Hostname]
        if (-not $ad) { continue }
        switch ($ad.Status) {
            'Active'    { $activeCount++ }
            'Stale'     { $staleCount++ }
            'Not Found' { $notFoundCount++ }
        }
        if ($ad.Status -ne 'Not Found') {
            if (-not $sqCounts.ContainsKey($ad.Squadron)) { $sqCounts[$ad.Squadron] = 0 }
            $sqCounts[$ad.Squadron]++
        }
    }
    function Set-D30Tile { param($Tile, [string]$Value, [string]$Sub)
        $vl = $Tile.Tag.ValueLabel; $sl = $Tile.Tag.SubLabel
        if ($vl) { $vl.Text = $Value }
        if ($sl) { $sl.Text = $Sub }
    }
    $foundCount = $totalParsed - $notFoundCount
    Set-D30Tile $script:tilesD30Parsed   "$totalParsed" $(if ($global:Dirty30SourceLabel) { $global:Dirty30SourceLabel } else { '' })
    Set-D30Tile $script:tilesD30Active   "$activeCount" $(if ($foundCount -gt 0) { "logon <= 90 days" } else { '' })
    Set-D30Tile $script:tilesD30Stale    "$staleCount"  $(if ($foundCount -gt 0) { "no logon > 90 days" } else { '' })
    Set-D30Tile $script:tilesD30NotFound "$notFoundCount" $(if ($notFoundCount -gt 0) { "no matching object" } else { '' })

    # Top squadron
    $topName = '—'; $topCount = 0
    foreach ($k in $sqCounts.Keys) { if ($sqCounts[$k] -gt $topCount) { $topName = $k; $topCount = $sqCounts[$k] } }
    $topSub = if ($foundCount -gt 0 -and $topCount -gt 0) {
        $pct = [Math]::Round(($topCount / $foundCount) * 100, 1)
        "$topCount of $foundCount found ($pct%)"
    } else { '' }
    Set-D30Tile $script:tilesD30TopSquad $topName $topSub

    # Rebuild squadron chip strip
    $script:pnlD30Squadrons.Controls.Clear()
    if ($sqCounts.Count -gt 0) {
        $sorted = $sqCounts.GetEnumerator() | Sort-Object Value -Descending
        foreach ($kv in $sorted) {
            $chip = New-Object System.Windows.Forms.Button
            $pct = if ($foundCount -gt 0) { [Math]::Round(($kv.Value / $foundCount) * 100, 1) } else { 0 }
            $chip.Text = "$($kv.Key)  $($kv.Value)  ($pct`%)"
            $chip.AutoSize = $true
            $chip.FlatStyle = 'Flat'; $chip.FlatAppearance.BorderSize = 1
            $chip.FlatAppearance.BorderColor = $colors.InputBorder
            $chip.BackColor = $colors.Input
            $chip.ForeColor = $colors.Gold
            $chip.Font = $fonts.Small
            $chip.Cursor = [System.Windows.Forms.Cursors]::Hand
            $chip.Margin = New-Object System.Windows.Forms.Padding(4)
            $chip.Tag = $kv.Key
            $chip.Add_Click({
                $global:Dirty30ActiveFilter = $this.Tag
                Update-D30FilterButtons
                Refresh-Dirty30Tab
            }.GetNewClosure())
            $script:pnlD30Squadrons.Controls.Add($chip)
        }
    }
    if ($notFoundCount -gt 0) {
        $chip = New-Object System.Windows.Forms.Button
        $chip.Text = "UNKNOWN  $notFoundCount  (Not Found)"
        $chip.AutoSize = $true; $chip.FlatStyle = 'Flat'
        $chip.FlatAppearance.BorderColor = $colors.Danger
        $chip.BackColor = $colors.Input; $chip.ForeColor = $colors.Danger
        $chip.Font = $fonts.Small
        $chip.Cursor = [System.Windows.Forms.Cursors]::Hand
        $chip.Margin = New-Object System.Windows.Forms.Padding(4)
        $chip.Tag = 'NotFound'
        $chip.Add_Click({
            $global:Dirty30ActiveFilter = 'NotFound'
            Update-D30FilterButtons
            Refresh-Dirty30Tab
        }.GetNewClosure())
        $script:pnlD30Squadrons.Controls.Add($chip)
    }

    # Update status label
    $shown = $filtered.Count
    $script:lblD30Status.Text = if ($totalParsed -eq 0) {
        "No hosts loaded. Paste or load to begin."
    } elseif ($shown -lt $totalParsed) {
        "Showing $shown of $totalParsed hosts (filter: $($global:Dirty30ActiveFilter))"
    } else {
        "$totalParsed hosts loaded"
    }

    # Enable/disable buttons
    $hasHosts = $totalParsed -gt 0
    $hasAd = $global:Dirty30AdResults.Count -gt 0
    $btnD30Lookup.Enabled = $hasHosts
    $btnD30Probe.Enabled  = $hasAd
    $btnD30Html.Enabled   = $hasAd
    $btnD30Export.Enabled = $hasAd
    $btnD30Copy.Enabled   = $hasHosts
}

function Update-D30FilterButtons {
    # Visual highlight of the active pill
    foreach ($pair in @(
        @{ Btn = $script:btnD30FilterAll;      Filter = 'All' }
        @{ Btn = $script:btnD30FilterStale;    Filter = 'Stale' }
        @{ Btn = $script:btnD30FilterNotFound; Filter = 'NotFound' }
    )) {
        $b = $pair.Btn
        if ($global:Dirty30ActiveFilter -eq $pair.Filter) {
            $b.BackColor = $b.Tag.ActiveBg
            $b.ForeColor = if ($pair.Filter -eq 'Stale') { [System.Drawing.Color]::Black } else { [System.Drawing.Color]::White }
        } else {
            $b.BackColor = $colors.Input; $b.ForeColor = $colors.TextSecondary
        }
    }
}

# ===== Button wiring =====
$btnD30Load.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Dirty 30 files|*.pdf;*.csv;*.txt|PDF (Tenable)|*.pdf|CSV / TXT|*.csv;*.txt|All Files|*.*"
    $dlg.Title  = "Select Dirty 30 PDF / CSV / TXT"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        $ext = [System.IO.Path]::GetExtension($dlg.FileName).ToLower()
        $text = $null
        if ($ext -eq '.pdf') {
            # Route PDFs through pdftotext.exe (Poppler / Git for Windows).
            # Tenable PDFs render with column layout that -layout preserves
            # well enough for the regex parser to pull hostnames and scores.
            Log "Converting PDF to text via pdftotext.exe..."
            [System.Windows.Forms.Application]::DoEvents()
            $text = ConvertFrom-Dirty30Pdf -PdfPath $dlg.FileName
            if (-not $text) {
                # ConvertFrom-Dirty30Pdf already showed the error dialog.
                return
            }
        } else {
            $text = [System.IO.File]::ReadAllText($dlg.FileName)
        }
        $script:txtD30Paste.Text = $text
        $parsed = Parse-Dirty30Input -Text $text
        if ($parsed.Count -eq 0) {
            [WptDialog]::Show("No hostnames recognized in the file.`nExpected formats: Tenable Dirty 30 PDF, CSV with NetBIOS/Hostname column, or one host per line.", "Parse failed", 'OK', 'Warning')
            return
        }
        $global:Dirty30Hosts.Clear()
        foreach ($h in $parsed) { [void]$global:Dirty30Hosts.Add($h) }
        $global:Dirty30AdResults = @{}
        $global:Dirty30LastUserMap = @{}
        $global:Dirty30ActiveFilter = 'All'
        $global:Dirty30SourceLabel = (Split-Path $dlg.FileName -Leaf)
        Log "Parsed $($parsed.Count) host(s) from $(Split-Path $dlg.FileName -Leaf)"
        Update-D30FilterButtons
        Refresh-Dirty30Tab
    } catch {
        Log "ERROR loading Dirty 30 file: $_"
        [WptDialog]::Show("Load failed: $_", "Error", 'OK', 'Error')
    }
})

$btnD30Paste.Add_Click({
    try {
        $text = [System.Windows.Forms.Clipboard]::GetText()
        if ([string]::IsNullOrWhiteSpace($text)) {
            [WptDialog]::Show("Clipboard is empty.", "Nothing to paste", 'OK', 'Information')
            return
        }
        $script:txtD30Paste.Text = $text
        $btnD30Parse.PerformClick()
    } catch { Log "ERROR paste: $_" }
})

$btnD30Parse.Add_Click({
    $text = $script:txtD30Paste.Text
    if ([string]::IsNullOrWhiteSpace($text)) {
        [WptDialog]::Show("Paste box is empty.", "Nothing to parse", 'OK', 'Information')
        return
    }
    $parsed = Parse-Dirty30Input -Text $text
    if ($parsed.Count -eq 0) {
        [WptDialog]::Show("No hostnames recognized in the pasted text.`nExpected formats: NetBIOS (DOMAIN\HOST), DNS (host.domain), CSV, or one-per-line.", "Parse failed", 'OK', 'Warning')
        return
    }
    $global:Dirty30Hosts.Clear()
    foreach ($h in $parsed) { [void]$global:Dirty30Hosts.Add($h) }
    $global:Dirty30AdResults = @{}
    $global:Dirty30LastUserMap = @{}
    $global:Dirty30ActiveFilter = 'All'
    $global:Dirty30SourceLabel = "pasted text ($($parsed.Count) hosts)"
    Log "Parsed $($parsed.Count) host(s) from pasted text"
    Update-D30FilterButtons
    Refresh-Dirty30Tab
})

$btnD30Clear.Add_Click({
    $script:txtD30Paste.Text = ''
    $global:Dirty30Hosts.Clear()
    $global:Dirty30AdResults = @{}
    $global:Dirty30LastUserMap = @{}
    $global:Dirty30SourceLabel = $null
    $global:Dirty30ActiveFilter = 'All'
    Update-D30FilterButtons
    Refresh-Dirty30Tab
})

function Get-Dirty30ReportDir {
    # Discoverable, persistent location for the rendered HTML reports.
    # %USERPROFILE%\Documents\JANET_Reports\Dirty30 - works with OneDrive
    # if Documents is redirected, doesn't pollute %TEMP% (which Windows
    # cleans), and doesn't pollute the shared workspace.
    $docs = [System.Environment]::GetFolderPath('MyDocuments')
    $dir = Join-Path $docs 'JANET_Reports\Dirty30'
    if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return $dir
}

function Open-Dirty30HtmlReport {
    # Render to <Documents>\JANET_Reports\Dirty30\Dirty30_<timestamp>.html
    # and shell-launch in the default browser. The path is surfaced in
    # the toolbar status label so the operator can find it later, and
    # also logged to the JANET log strip.
    if ($global:Dirty30Hosts.Count -eq 0) { return }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Get-Dirty30ReportDir
    $out = Join-Path $dir "Dirty30_$stamp.html"
    try {
        Render-Dirty30Html -Path $out
        Log "Rendered HTML report -> $out"
        $script:lblD30Status.Text = "Report: $out"
        $script:lblD30Status.ForeColor = $colors.Cyan
        Start-Process $out
    } catch {
        Log "ERROR rendering HTML: $_"
        [WptDialog]::Show("HTML render failed: $_", "Error", 'OK', 'Error')
    }
}

$btnD30Lookup.Add_Click({
    if ($global:Dirty30Hosts.Count -eq 0) { return }
    Log "Running AD lookup for $($global:Dirty30Hosts.Count) host(s)..."
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $names = @($global:Dirty30Hosts | ForEach-Object { $_.Hostname })
        $global:Dirty30AdResults = Get-Dirty30AdInfo -Hostnames $names
        $found = @($global:Dirty30AdResults.Values | Where-Object { $_.Status -ne 'Not Found' }).Count
        Log "AD lookup complete: $found found, $($global:Dirty30AdResults.Count - $found) not found"
        Refresh-Dirty30Tab

        # Auto-probe last-logged-on-user on the active hosts in the
        # background. The probe is fast in parallel (~5-15 sec for 30
        # hosts) and gives operators what they actually want without an
        # extra click. Offline / unreachable boxes show "— offline —"
        # but everything else fills in. The manual "+ Probe Last User"
        # button still works for re-probing.
        $activeNames = @($global:Dirty30AdResults.Values |
            Where-Object { $_.Status -ne 'Not Found' } |
            ForEach-Object { $_.Hostname })
        if ($activeNames.Count -gt 0) {
            Log "Auto-probing last-logged-on-user on $($activeNames.Count) host(s)..."
            [System.Windows.Forms.Application]::DoEvents()
            try {
                $global:Dirty30LastUserMap = Get-Dirty30LastLoggedOnUser -Hostnames $activeNames
                $hits = @($global:Dirty30LastUserMap.Values | Where-Object { $_ -notmatch '^—' }).Count
                Log "Last-user probe complete: $hits successful, $($global:Dirty30LastUserMap.Count - $hits) offline/unreachable"
                Refresh-Dirty30Tab
            } catch {
                Log "WARN: auto-probe failed ($_); use the manual + Probe Last User button to retry"
            }
        }

        # Auto-open the polished HTML view - that's the primary
        # visualization; the in-tool grid is a quick preview but the HTML
        # mirrors the mockup. Open after probe so Last User is populated.
        Open-Dirty30HtmlReport
    } catch {
        Log "ERROR AD lookup: $_"
        [WptDialog]::Show("AD lookup failed: $_", "Error", 'OK', 'Error')
    }
})

$btnD30Html.Add_Click({ Open-Dirty30HtmlReport })

$btnD30Probe.Add_Click({
    if ($global:Dirty30AdResults.Count -eq 0) { return }
    $r = [WptDialog]::Show("Probe last logged-on user for $($global:Dirty30Hosts.Count) host(s)?`n`nThis hits each machine over WMI registry. May take 10-30 seconds. Offline boxes show as `"— offline —`".", "Confirm probe", 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }
    Log "Probing last logged-on user on $($global:Dirty30Hosts.Count) host(s)..."
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $names = @($global:Dirty30Hosts | ForEach-Object { $_.Hostname })
        $global:Dirty30LastUserMap = Get-Dirty30LastLoggedOnUser -Hostnames $names
        $hits = @($global:Dirty30LastUserMap.Values | Where-Object { $_ -notmatch '^—' }).Count
        Log "Last-user probe complete: $hits successful, $($global:Dirty30LastUserMap.Count - $hits) failed/offline"
        Refresh-Dirty30Tab
        # Re-open the HTML so the Last User column reflects the probe.
        Open-Dirty30HtmlReport
    } catch {
        Log "ERROR probe: $_"
    }
})

$btnD30Export.Add_Click({
    if ($global:Dirty30AdResults.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "CSV Files|*.csv"
    $dlg.FileName = "Dirty30_Triage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    try {
        Export-Dirty30Results -Path $dlg.FileName
        Log "Exported Dirty 30 results to $(Split-Path $dlg.FileName -Leaf)"
        [WptDialog]::Show("Exported $($global:Dirty30Hosts.Count) host(s) to:`n$($dlg.FileName)", "Done", 'OK', 'Information')
    } catch { Log "ERROR exporting: $_" }
})

$btnD30Copy.Add_Click({
    if ($global:Dirty30Hosts.Count -eq 0) { return }
    $names = ($global:Dirty30Hosts | ForEach-Object { $_.Hostname }) -join "`r`n"
    [System.Windows.Forms.Clipboard]::SetText($names)
    Log "Copied $($global:Dirty30Hosts.Count) hostname(s) to clipboard"
})

$script:btnD30FilterAll.Add_Click({
    $global:Dirty30ActiveFilter = 'All'
    Update-D30FilterButtons; Refresh-Dirty30Tab
})
$script:btnD30FilterStale.Add_Click({
    $global:Dirty30ActiveFilter = 'Stale'
    Update-D30FilterButtons; Refresh-Dirty30Tab
})
$script:btnD30FilterNotFound.Add_Click({
    $global:Dirty30ActiveFilter = 'NotFound'
    Update-D30FilterButtons; Refresh-Dirty30Tab
})
$script:txtD30Search.Add_TextChanged({ Refresh-Dirty30Tab })

# Initial filter button state
Update-D30FilterButtons
#endregion

#region === TAB: CORA VULNERABILITIES (commander brief) ===
# Aggregates the currently loaded $global:AcasFindings into a single-page
# "what's hitting us this week" view sized for a commander brief. Excludes
# closed and NOT OUR PATCH findings - what shows is what's still hitting us.
# In-tool view is a small preview (headline tiles + top-10 list); the
# polished deliverable is the HTML export which embeds inline SVG charts so
# it works on locked-down workstations without external chart libraries.

function Build-CoraSummary {
    # Single pass over open + actionable findings. Returns the hashtable that
    # both the preview tab and the HTML renderer consume so there is one
    # source of truth for the numbers shown to leadership.
    $hosts    = @{}
    $sevCount = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    $sevHosts = @{ Critical=@{}; High=@{}; Medium=@{}; Low=@{}; Info=@{} }
    $catData  = @{}     # Category -> @{ Count; Hosts<hashtable> }
    $byPlugin = @{}     # PluginID -> aggregate
    $considered = 0
    foreach ($f in $global:AcasFindings) {
        # Commander brief = current open state. Closed work and out-of-scope
        # vendor stuff would dilute the narrative.
        if ($f.Status -eq 'Patched') { continue }
        if ($f.Category -eq 'NOT OUR PATCH') { continue }
        $considered++

        $hosts[$f.Hostname] = $true

        $sev = $f.Severity
        if (-not $sevCount.ContainsKey($sev)) { $sevCount[$sev] = 0; $sevHosts[$sev] = @{} }
        $sevCount[$sev]++
        $sevHosts[$sev][$f.Hostname] = $true

        $cat = if ([string]::IsNullOrWhiteSpace($f.Category)) { 'Other' } else { $f.Category }
        if (-not $catData.ContainsKey($cat)) { $catData[$cat] = @{ Count = 0; Hosts = @{} } }
        $catData[$cat].Count++
        $catData[$cat].Hosts[$f.Hostname] = $true

        $pluginIdKey = ($f.PluginID -as [string])
        if ([string]::IsNullOrWhiteSpace($pluginIdKey)) { continue }
        # PowerShell 5.1 can't use `switch` as a parenthesized sub-expression
        # inside a hashtable literal, so compute the rank first.
        $thisRank = switch ($f.Severity) { 'Critical'{4} 'High'{3} 'Medium'{2} 'Low'{1} 'Info'{0} default{0} }
        if (-not $byPlugin.ContainsKey($pluginIdKey)) {
            $byPlugin[$pluginIdKey] = @{
                PluginID     = $pluginIdKey
                VulnName     = ($f.VulnName -as [string])
                Severity     = $f.Severity
                SeverityRank = $thisRank
                Hosts        = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                Category     = $cat
                Solution     = ($f.Solution -as [string])
                FindingCount = 0
            }
        }
        $g = $byPlugin[$pluginIdKey]
        [void]$g.Hosts.Add($f.Hostname)
        $g.FindingCount++
        # Track the worst severity seen for this plugin (some plugins span
        # severities depending on the host).
        if ($thisRank -gt $g.SeverityRank) { $g.SeverityRank = $thisRank; $g.Severity = $f.Severity }
    }

    $uniqueHosts = $hosts.Count
    $vph = if ($uniqueHosts -gt 0) { [Math]::Round($considered / $uniqueHosts, 2) } else { 0.0 }

    # Flatten plugins into a sortable list and pick the biggest hitters.
    $pluginList = New-Object System.Collections.ArrayList
    foreach ($k in $byPlugin.Keys) {
        $g = $byPlugin[$k]
        [void]$pluginList.Add([PSCustomObject]@{
            PluginID     = $g.PluginID
            VulnName     = $g.VulnName
            Severity     = $g.Severity
            SeverityRank = $g.SeverityRank
            HostCount    = $g.Hosts.Count
            FindingCount = $g.FindingCount
            Category     = $g.Category
            Solution     = $g.Solution
        })
    }
    $topVulns = @($pluginList |
        Sort-Object -Property @{ Expression = { -$_.HostCount } }, @{ Expression = { -$_.SeverityRank } }, VulnName |
        Select-Object -First 15)

    # Network % calc: shared with the Remediation Plan tab. 0 = hide.
    $netSize = $global:NetworkDeviceCount
    $netPct  = if ($netSize -gt 0 -and $uniqueHosts -gt 0) {
        [Math]::Round(($uniqueHosts / $netSize) * 100, 1)
    } else { [double]::NaN }

    return @{
        ConsideredFindings = $considered
        UniqueHosts        = $uniqueHosts
        Vph                = $vph
        SevCount           = $sevCount
        SevHosts           = @{
            Critical = $sevHosts['Critical'].Count
            High     = $sevHosts['High'].Count
            Medium   = $sevHosts['Medium'].Count
            Low      = $sevHosts['Low'].Count
            Info     = $sevHosts['Info'].Count
        }
        Categories         = $catData
        TopVulns           = $topVulns
        NetworkSize        = $netSize
        NetworkPct         = $netPct
        TotalLoaded        = $global:AcasFindings.Count
    }
}

function Render-CoraVulnHtml {
    # Self-contained HTML for the commander brief: top bar, headline tiles,
    # inline-SVG charts (top-15 horizontal bar, severity donut, category bar),
    # and a "biggest hitters" card grid that mirrors the layout the operator
    # described in the existing Remediation Plan UI - but with absolute host
    # counts and % of network instead of push targets.
    param([Parameter(Mandatory)][string]$Path)

    $s = Build-CoraSummary

    $netPctStr = if ([double]::IsNaN($s.NetworkPct)) { 'N/A' } else { ($s.NetworkPct.ToString('0.0') + '%') }
    $vphStr    = if ($s.UniqueHosts -gt 0) { $s.Vph.ToString('0.00') } else { 'N/A' }
    $netSubLbl = if ($s.NetworkSize -gt 0) { "$($s.UniqueHosts) of $($s.NetworkSize) hosts" } else { 'set Network size on Remediation Plan' }

    # === Top 15 horizontal bar chart (SVG) =================================
    $topBarSvg = New-Object System.Text.StringBuilder
    if ($s.TopVulns.Count -gt 0) {
        $maxHosts = ($s.TopVulns | Measure-Object -Property HostCount -Maximum).Maximum
        if ($maxHosts -le 0) { $maxHosts = 1 }
        $rowH = 30
        $svgW = 1100
        $svgH = ($s.TopVulns.Count * $rowH) + 20
        $labelW = 360
        $barX = $labelW + 8
        $barMaxW = $svgW - $barX - 220
        [void]$topBarSvg.Append("<svg viewBox=`"0 0 $svgW $svgH`" xmlns=`"http://www.w3.org/2000/svg`" class=`"chart`">`n")
        $rowIdx = 0
        foreach ($v in $s.TopVulns) {
            $y = 10 + ($rowIdx * $rowH)
            $rowIdx++
            $barW = [int](($v.HostCount / [double]$maxHosts) * $barMaxW)
            if ($barW -lt 2) { $barW = 2 }
            $fillVar = switch ($v.Severity) {
                'Critical' { 'var(--danger)' }
                'High'     { 'var(--orange)' }
                'Medium'   { 'var(--warning)' }
                'Low'      { 'var(--cyan)' }
                default    { 'var(--text-faint)' }
            }
            $nameTxt = ConvertTo-HtmlEscaped $v.VulnName
            if ($nameTxt.Length -gt 56) { $nameTxt = $nameTxt.Substring(0, 53) + '...' }
            $plugStr = ConvertTo-HtmlEscaped $v.PluginID
            $pctStr = if ($s.NetworkSize -gt 0) {
                ([Math]::Round(($v.HostCount / [double]$s.NetworkSize) * 100, 1).ToString('0.0') + '% of net')
            } else { '' }
            $countTxt = "$($v.HostCount) hosts"
            [void]$topBarSvg.Append("  <text x=`"6`" y=`"$($y + 19)`" class=`"barlbl`">$nameTxt</text>`n")
            [void]$topBarSvg.Append("  <text x=`"6`" y=`"$($y + 30)`" class=`"barsub`">Plugin $plugStr &middot; $($v.Severity)</text>`n")
            [void]$topBarSvg.Append("  <rect x=`"$barX`" y=`"$($y + 4)`" width=`"$barW`" height=`"22`" fill=`"$fillVar`" rx=`"2`" />`n")
            [void]$topBarSvg.Append("  <text x=`"$($barX + $barW + 8)`" y=`"$($y + 20)`" class=`"barval`">$countTxt</text>`n")
            if ($pctStr) {
                [void]$topBarSvg.Append("  <text x=`"$($barX + $barW + 110)`" y=`"$($y + 20)`" class=`"barpct`">$pctStr</text>`n")
            }
        }
        [void]$topBarSvg.Append("</svg>`n")
    } else {
        [void]$topBarSvg.Append('<div class="empty-note">No open vulnerabilities to chart. Import an ACAS scan and reopen this report.</div>')
    }

    # === Severity donut (SVG) =============================================
    $donutSvg = New-Object System.Text.StringBuilder
    $sevTotal = $s.SevCount['Critical'] + $s.SevCount['High'] + $s.SevCount['Medium'] + $s.SevCount['Low'] + $s.SevCount['Info']
    if ($sevTotal -gt 0) {
        $cx = 130; $cy = 130; $r = 90
        $circ = [Math]::PI * 2 * $r
        [void]$donutSvg.Append("<svg viewBox=`"0 0 260 260`" xmlns=`"http://www.w3.org/2000/svg`" class=`"donut`">`n")
        [void]$donutSvg.Append("  <circle cx=`"$cx`" cy=`"$cy`" r=`"$r`" fill=`"none`" stroke=`"var(--input)`" stroke-width=`"38`" />`n")
        $offset = 0.0
        foreach ($pair in @(
            @{ Name = 'Critical'; Color = 'var(--danger)'  }
            @{ Name = 'High';     Color = 'var(--orange)'  }
            @{ Name = 'Medium';   Color = 'var(--warning)' }
            @{ Name = 'Low';      Color = 'var(--cyan)'    }
            @{ Name = 'Info';     Color = 'var(--text-faint)' }
        )) {
            $count = $s.SevCount[$pair.Name]
            if ($count -le 0) { continue }
            $frac = $count / [double]$sevTotal
            $arc  = $circ * $frac
            $gap  = $circ - $arc
            $dashOffset = $circ * 0.25 - $offset
            [void]$donutSvg.Append("  <circle cx=`"$cx`" cy=`"$cy`" r=`"$r`" fill=`"none`" stroke=`"$($pair.Color)`" stroke-width=`"38`" stroke-dasharray=`"$arc $gap`" stroke-dashoffset=`"$dashOffset`" transform=`"rotate(-90 $cx $cy)`" />`n")
            $offset += $arc
        }
        $bigCount = $s.SevCount['Critical'] + $s.SevCount['High']
        [void]$donutSvg.Append("  <text x=`"$cx`" y=`"$($cy - 4)`" class=`"donut-big`" text-anchor=`"middle`">$bigCount</text>`n")
        [void]$donutSvg.Append("  <text x=`"$cx`" y=`"$($cy + 18)`" class=`"donut-sub`" text-anchor=`"middle`">Crit + High</text>`n")
        [void]$donutSvg.Append("</svg>`n")
    } else {
        [void]$donutSvg.Append('<div class="empty-note">No severity data.</div>')
    }

    # === Severity legend ==================================================
    $legendHtml = New-Object System.Text.StringBuilder
    foreach ($pair in @(
        @{ Name = 'Critical'; Class = 'crit' }
        @{ Name = 'High';     Class = 'high' }
        @{ Name = 'Medium';   Class = 'med'  }
        @{ Name = 'Low';      Class = 'low'  }
        @{ Name = 'Info';     Class = 'info' }
    )) {
        $c = $s.SevCount[$pair.Name]
        $h = $s.SevHosts[$pair.Name]
        $pct = if ($sevTotal -gt 0) { [Math]::Round(($c / [double]$sevTotal) * 100, 1) } else { 0 }
        [void]$legendHtml.Append("<div class=`"leg-row`"><span class=`"chip $($pair.Class)`">$($pair.Name)</span><span class=`"leg-count`">$c findings</span><span class=`"leg-sub`">$h hosts &middot; $pct%</span></div>`n")
    }

    # === Category bar chart (SVG) =========================================
    $catBarSvg = New-Object System.Text.StringBuilder
    $catList = New-Object System.Collections.ArrayList
    foreach ($k in $s.Categories.Keys) {
        [void]$catList.Add([PSCustomObject]@{
            Category  = $k
            Count     = $s.Categories[$k].Count
            HostCount = $s.Categories[$k].Hosts.Count
        })
    }
    $catSorted = @($catList | Sort-Object -Property @{ Expression = { -$_.Count } })
    if ($catSorted.Count -gt 0) {
        $maxCat = ($catSorted | Measure-Object -Property Count -Maximum).Maximum
        if ($maxCat -le 0) { $maxCat = 1 }
        $rowH = 28
        $svgW = 700
        $svgH = ($catSorted.Count * $rowH) + 16
        $labelW = 130
        $barX = $labelW + 6
        $barMaxW = $svgW - $barX - 140
        [void]$catBarSvg.Append("<svg viewBox=`"0 0 $svgW $svgH`" xmlns=`"http://www.w3.org/2000/svg`" class=`"chart`">`n")
        $catColors = @{
            'Chrome'        = 'rgb( 66,133,244)'
            'Edge'          = 'rgb(  0,120,212)'
            'Office'        = 'rgb(217, 83, 30)'
            'Apache'        = 'rgb(210, 50, 45)'
            'KB Patch'      = 'var(--accent)'
            'Registry Fix'  = 'var(--cyan)'
            'Other'         = 'var(--text-faint)'
        }
        $rowIdx = 0
        foreach ($c in $catSorted) {
            $y = 8 + ($rowIdx * $rowH)
            $rowIdx++
            $barW = [int](($c.Count / [double]$maxCat) * $barMaxW)
            if ($barW -lt 2) { $barW = 2 }
            $fill = if ($catColors.ContainsKey($c.Category)) { $catColors[$c.Category] } else { 'var(--accent)' }
            $catTxt = ConvertTo-HtmlEscaped $c.Category
            [void]$catBarSvg.Append("  <text x=`"6`" y=`"$($y + 18)`" class=`"barlbl`">$catTxt</text>`n")
            [void]$catBarSvg.Append("  <rect x=`"$barX`" y=`"$($y + 4)`" width=`"$barW`" height=`"20`" fill=`"$fill`" rx=`"2`" />`n")
            [void]$catBarSvg.Append("  <text x=`"$($barX + $barW + 8)`" y=`"$($y + 18)`" class=`"barval`">$($c.Count) ($($c.HostCount) hosts)</text>`n")
        }
        [void]$catBarSvg.Append("</svg>`n")
    } else {
        [void]$catBarSvg.Append('<div class="empty-note">No category data.</div>')
    }

    # === Biggest Hitters card grid =========================================
    $hitCards = New-Object System.Text.StringBuilder
    if ($s.TopVulns.Count -gt 0) {
        $rank = 0
        foreach ($v in $s.TopVulns) {
            $rank++
            $sevClass = switch ($v.Severity) {
                'Critical' { 'crit' }
                'High'     { 'high' }
                'Medium'   { 'med'  }
                'Low'      { 'low'  }
                default    { 'info' }
            }
            $pctStr = if ($s.NetworkSize -gt 0) {
                ([Math]::Round(($v.HostCount / [double]$s.NetworkSize) * 100, 1).ToString('0.0') + '%')
            } else { '-' }
            $name = ConvertTo-HtmlEscaped $v.VulnName
            $plug = ConvertTo-HtmlEscaped $v.PluginID
            $cat  = ConvertTo-HtmlEscaped $v.Category
            [void]$hitCards.Append("<div class=`"hit`">`n")
            [void]$hitCards.Append("  <div class=`"hit-head`"><span class=`"rank`">#$rank</span><span class=`"chip $sevClass`">$($v.Severity)</span><span class=`"cat`">$cat</span></div>`n")
            [void]$hitCards.Append("  <div class=`"hit-name`">$name</div>`n")
            [void]$hitCards.Append("  <div class=`"hit-meta`">Plugin $plug</div>`n")
            [void]$hitCards.Append("  <div class=`"hit-stat-row`"><div class=`"hit-stat`"><div class=`"big`">$($v.HostCount)</div><div class=`"sub`">hosts affected</div></div><div class=`"hit-stat`"><div class=`"big`">$pctStr</div><div class=`"sub`">of network</div></div></div>`n")
            [void]$hitCards.Append("</div>`n")
        }
    } else {
        [void]$hitCards.Append('<div class="empty-note">No vulnerabilities loaded. Import an ACAS scan from the ACAS Import tab to populate this report.</div>')
    }

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $operator  = ConvertTo-HtmlEscaped $env:USERNAME
    $machine   = ConvertTo-HtmlEscaped $env:COMPUTERNAME
    $netLabel  = if ($s.NetworkSize -gt 0) { "$($s.NetworkSize) hosts on network" } else { 'Network size not set (Remediation Plan > Network size to enable %)' }

    $tilesTotalVulns  = Format-AcasNumber $s.ConsideredFindings
    $tilesCrit        = Format-AcasNumber $s.SevCount['Critical']
    $tilesCritHosts   = $s.SevHosts['Critical']
    $tilesHigh        = Format-AcasNumber $s.SevCount['High']
    $tilesHighHosts   = $s.SevHosts['High']
    $tilesHosts       = Format-AcasNumber $s.UniqueHosts

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET &mdash; CORA Vulnerabilities &mdash; $generated</title>
<style>
  :root {
    --bg:          rgb(8,  8, 12);
    --panel:       rgb(18, 18, 26);
    --panel-light: rgb(30, 28, 40);
    --input:       rgb(22, 22, 30);
    --border:      rgb(38, 34, 52);
    --text:        rgb(240,240,245);
    --text-dim:    rgb(210,208,220);
    --text-faint:  rgb(160,158,178);
    --accent:      rgb(140,100,220);
    --success:     rgb( 92,198,120);
    --warning:     rgb(245,180, 70);
    --danger:      rgb(220, 92,100);
    --cyan:        rgb( 80,200,220);
    --gold:        rgb(238,196, 88);
    --orange:      rgb(232,140, 70);
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 60px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 20px; font-weight: 600; color: var(--gold); }
  .topbar .subtitle { color: var(--text-dim); font-size: 13px; }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .topbar .meta .gen { color: var(--cyan); }
  .content { padding: 20px 28px; max-width: 1600px; margin: 0 auto; }
  .page-title { font-size: 26px; color: var(--gold); font-weight: 600; margin: 0 0 4px 0; }
  .page-subtitle { color: var(--text-dim); font-size: 13px; margin: 0 0 14px 0; }
  .source { background: var(--panel); border: 1px solid var(--border); padding: 11px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 14px; font-family: Consolas, monospace; }
  .source .file { color: var(--cyan); font-weight: 600; }

  .tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 20px; }
  .tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .tile.crit  { border-top-color: var(--danger); }
  .tile.high  { border-top-color: var(--orange); }
  .tile.hosts { border-top-color: var(--cyan); }
  .tile.vph   { border-top-color: var(--gold); }
  .tile.net   { border-top-color: var(--success); }
  .tile .label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .tile .value { font-size: 38px; font-weight: 800; color: var(--text); margin-top: 8px; line-height: 1.1; }
  .tile .sub   { font-size: 12px; color: var(--text-dim); margin-top: 6px; }

  .row { display: grid; gap: 16px; margin-bottom: 20px; }
  .row.two { grid-template-columns: 1fr 1fr; }
  .row.split { grid-template-columns: 280px 1fr; }
  .panel { background: var(--panel); border: 1px solid var(--border); padding: 16px 18px; }
  .panel-hdr { font-size: 13px; color: var(--gold); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
  .panel.full { grid-column: 1 / -1; }
  .empty-note { color: var(--text-dim); font-style: italic; font-size: 13px; padding: 10px 4px; }

  svg.chart { width: 100%; height: auto; display: block; }
  svg.chart text.barlbl { fill: var(--text); font: 600 13px Segoe UI, sans-serif; }
  svg.chart text.barsub { fill: var(--text-faint); font: 400 10px Consolas, monospace; }
  svg.chart text.barval { fill: var(--text); font: 700 13px Consolas, monospace; }
  svg.chart text.barpct { fill: var(--cyan); font: 600 12px Consolas, monospace; }
  svg.donut { width: 260px; height: 260px; display: block; margin: 0 auto; }
  svg.donut text.donut-big { fill: var(--text); font: 800 36px Consolas, monospace; }
  svg.donut text.donut-sub { fill: var(--text-dim); font: 600 12px Segoe UI, sans-serif; text-transform: uppercase; letter-spacing: 0.5px; }

  .legend { display: flex; flex-direction: column; gap: 6px; }
  .leg-row { display: grid; grid-template-columns: 100px 110px 1fr; gap: 8px; align-items: baseline; padding: 6px 4px; border-top: 1px solid var(--border); }
  .leg-row:first-of-type { border-top: 0; }
  .leg-row .leg-count { font-family: Consolas, monospace; color: var(--text); font-weight: 700; font-size: 14px; }
  .leg-row .leg-sub { color: var(--text-dim); font-size: 12px; }
  .chip { display: inline-block; padding: 3px 10px; border-radius: 2px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .chip.crit { background: rgba(220,92,100,0.18); color: var(--danger); border: 1px solid rgba(220,92,100,0.45); }
  .chip.high { background: rgba(232,140,70,0.18); color: var(--orange); border: 1px solid rgba(232,140,70,0.45); }
  .chip.med  { background: rgba(245,180,70,0.18); color: var(--warning); border: 1px solid rgba(245,180,70,0.45); }
  .chip.low  { background: rgba(80,200,220,0.18); color: var(--cyan); border: 1px solid rgba(80,200,220,0.45); }
  .chip.info { background: rgba(160,158,178,0.18); color: var(--text-faint); border: 1px solid rgba(160,158,178,0.45); }

  .hitters-hdr { font-size: 22px; color: var(--gold); font-weight: 700; margin: 28px 0 10px 0; text-transform: uppercase; letter-spacing: 0.5px; }
  .hitters-sub { color: var(--text-dim); font-size: 12px; margin-bottom: 14px; }
  .hitters { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
  .hit { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--accent); padding: 14px 16px; }
  .hit-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .hit-head .rank { color: var(--gold); font-weight: 800; font-family: Consolas, monospace; font-size: 14px; }
  .hit-head .cat { color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-left: auto; }
  .hit-name { color: var(--text); font-weight: 600; font-size: 14px; line-height: 1.25; min-height: 36px; }
  .hit-meta { color: var(--text-faint); font-size: 11px; font-family: Consolas, monospace; margin-top: 4px; }
  .hit-stat-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); }
  .hit-stat .big { font-size: 26px; font-weight: 800; font-family: Consolas, monospace; color: var(--text); line-height: 1.1; }
  .hit-stat .sub { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px; }

  .footer { color: var(--text-faint); font-size: 11px; padding: 16px 4px 32px; text-align: center; }
</style>
</head>
<body>

<div class="topbar">
  <div>
    <div class="title">J.A.N.E.T &mdash; CORA Vulnerabilities &mdash; Commander Brief</div>
    <div class="subtitle">Open + actionable findings this scan &middot; ReportsTool $JanetReportsVersion</div>
  </div>
  <div class="grow"></div>
  <div class="meta">
    <div>Generated <span class="gen">$generated</span></div>
    <div>by $operator on $machine</div>
  </div>
</div>

<div class="content">
  <h1 class="page-title">CORA VULNERABILITIES &mdash; THIS WEEK</h1>
  <p class="page-subtitle">
    Filtered to open + in-scope findings (NOT OUR PATCH and already-patched rows excluded). Numbers reflect the most recently imported ACAS scan.
  </p>

  <div class="source">Network: <span class="file">$netLabel</span> &middot; Considered $($s.ConsideredFindings) of $($s.TotalLoaded) loaded findings</div>

  <div class="tiles">
    <div class="tile"><div class="label">Total Open Vulns</div><div class="value">$tilesTotalVulns</div><div class="sub">findings in scope</div></div>
    <div class="tile crit"><div class="label">Critical</div><div class="value">$tilesCrit</div><div class="sub">$tilesCritHosts hosts</div></div>
    <div class="tile high"><div class="label">High</div><div class="value">$tilesHigh</div><div class="sub">$tilesHighHosts hosts</div></div>
    <div class="tile hosts"><div class="label">Unique Hosts</div><div class="value">$tilesHosts</div><div class="sub">with open findings</div></div>
    <div class="tile vph"><div class="label">VPH</div><div class="value">$vphStr</div><div class="sub">vulns per host</div></div>
    <div class="tile net"><div class="label">% of Network</div><div class="value">$netPctStr</div><div class="sub">$netSubLbl</div></div>
  </div>

  <div class="row split">
    <div class="panel">
      <div class="panel-hdr">Severity Mix</div>
$($donutSvg.ToString())
      <div class="legend" style="margin-top: 12px;">
$($legendHtml.ToString())
      </div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Top 15 Vulnerabilities by Hosts Affected</div>
$($topBarSvg.ToString())
    </div>
  </div>

  <div class="row">
    <div class="panel full">
      <div class="panel-hdr">Vulns by Category</div>
$($catBarSvg.ToString())
    </div>
  </div>

  <div class="hitters-hdr">Biggest Hitters</div>
  <div class="hitters-sub">Top 15 plugin IDs by host count. Each card is a vulnerability hitting many machines &mdash; what to focus the next push on.</div>
  <div class="hitters">
$($hitCards.ToString())
  </div>

  <div class="footer">JANET ReportsTool $JanetReportsVersion &middot; CORA Vulnerabilities &middot; Self-contained HTML &middot; No external assets fetched</div>
</div>

</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($true))
}

function Get-CoraReportDir {
    $docs = [System.Environment]::GetFolderPath('MyDocuments')
    $dir = Join-Path $docs 'JANET_Reports\CORA'
    if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return $dir
}

function Open-CoraHtmlReport {
    if ($global:AcasFindings.Count -eq 0) {
        [WptDialog]::Show("No ACAS findings loaded. Import a scan on the ACAS Import tab first.", "No Data", 'OK', 'Information')
        return
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Get-CoraReportDir
    $out = Join-Path $dir "CORA_Vulnerabilities_$stamp.html"
    try {
        Render-CoraVulnHtml -Path $out
        Log "Rendered CORA HTML report -> $out"
        if ($script:lblCoraStatus) {
            $script:lblCoraStatus.Text = "Report: $out"
            $script:lblCoraStatus.ForeColor = $colors.Cyan
        }
        Start-Process $out
    } catch {
        Log "ERROR rendering CORA HTML: $_"
        [WptDialog]::Show("HTML render failed: $_", "Error", 'OK', 'Error')
    }
}

# ===== Tab UI =====
$panelCora = New-Object System.Windows.Forms.Panel
$panelCora.Dock = 'Fill'
$panelCora.BackColor = $colors.Background
$panelCora.Visible = $false
$panelCora.AutoScroll = $true
$contentArea.Controls.Add($panelCora)
$global:TabPanels['CORA Vulnerabilities'] = $panelCora

$lblCoraHdr = New-Object System.Windows.Forms.Label
$lblCoraHdr.Text = "CORA VULNERABILITIES"
$lblCoraHdr.Location = [System.Drawing.Point]::new(10, 8)
$lblCoraHdr.AutoSize = $true
$lblCoraHdr.Font = $fonts.Subtitle
$lblCoraHdr.ForeColor = $colors.Gold
$panelCora.Controls.Add($lblCoraHdr)

$lblCoraSub = New-Object System.Windows.Forms.Label
$lblCoraSub.Text = "Commander brief: what is hitting us this week. Open + in-scope findings only (NOT OUR PATCH and already-patched excluded). Click Open HTML Brief for the projector-friendly version with charts."
$lblCoraSub.Location = [System.Drawing.Point]::new(10, 28)
$lblCoraSub.Size = [System.Drawing.Size]::new(1160, 32)
$lblCoraSub.Font = $fonts.Small
$lblCoraSub.ForeColor = $colors.TextDim
$lblCoraSub.Anchor = 'Top,Left,Right'
$panelCora.Controls.Add($lblCoraSub)

$btnCoraHtml = New-StyledButton -Text "Open HTML Brief" -Location ([System.Drawing.Point]::new(10, 68)) -Size ([System.Drawing.Size]::new(220, 36)) -BgColor $colors.Gold
$btnCoraHtml.Add_Click({ Open-CoraHtmlReport })
$panelCora.Controls.Add($btnCoraHtml)

$btnCoraRefresh = New-StyledButton -Text "Refresh" -Location ([System.Drawing.Point]::new(240, 68)) -Size ([System.Drawing.Size]::new(100, 36)) -BgColor $colors.PanelLight
$btnCoraRefresh.Add_Click({ Refresh-CoraVulnTab })
$panelCora.Controls.Add($btnCoraRefresh)

$script:lblCoraStatus = New-Object System.Windows.Forms.Label
$script:lblCoraStatus.Text = "Import an ACAS scan on the ACAS Import tab to populate this brief."
$script:lblCoraStatus.Location = [System.Drawing.Point]::new(350, 77)
$script:lblCoraStatus.AutoSize = $true
$script:lblCoraStatus.Font = $fonts.Small
$script:lblCoraStatus.ForeColor = $colors.TextSecondary
$panelCora.Controls.Add($script:lblCoraStatus)

$script:pnlCoraTiles = New-Object System.Windows.Forms.Panel
$script:pnlCoraTiles.Location = [System.Drawing.Point]::new(10, 116)
$script:pnlCoraTiles.Size = [System.Drawing.Size]::new(1160, 100)
$script:pnlCoraTiles.BackColor = $colors.Background
$panelCora.Controls.Add($script:pnlCoraTiles)

$lblCoraHitHdr = New-Object System.Windows.Forms.Label
$lblCoraHitHdr.Text = "BIGGEST HITTERS  (top 10 plugins by hosts affected)"
$lblCoraHitHdr.Location = [System.Drawing.Point]::new(10, 228)
$lblCoraHitHdr.AutoSize = $true
$lblCoraHitHdr.Font = $fonts.Subtitle
$lblCoraHitHdr.ForeColor = $colors.Gold
$panelCora.Controls.Add($lblCoraHitHdr)

$script:pnlCoraHitters = New-Object System.Windows.Forms.Panel
$script:pnlCoraHitters.Location = [System.Drawing.Point]::new(10, 256)
$script:pnlCoraHitters.Size = [System.Drawing.Size]::new(1160, 460)
$script:pnlCoraHitters.BackColor = $colors.Background
$panelCora.Controls.Add($script:pnlCoraHitters)

function New-CoraTile {
    param([string]$Label, [string]$Value, [string]$Sub,
          [System.Drawing.Color]$StripeColor,
          [System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = $Location; $p.Size = $Size
    $p.BackColor = $colors.Panel
    $stripe = New-Object System.Windows.Forms.Panel
    $stripe.Dock = 'Top'; $stripe.Height = 3; $stripe.BackColor = $StripeColor
    $p.Controls.Add($stripe)
    $lblL = New-Object System.Windows.Forms.Label
    $lblL.Text = $Label.ToUpper(); $lblL.Location = [System.Drawing.Point]::new(10, 10)
    $lblL.AutoSize = $true; $lblL.Font = $fonts.Small; $lblL.ForeColor = $colors.TextDim
    $p.Controls.Add($lblL)
    $lblV = New-Object System.Windows.Forms.Label
    $lblV.Text = $Value; $lblV.Location = [System.Drawing.Point]::new(10, 28)
    $lblV.AutoSize = $true; $lblV.Font = $fonts.CardValue; $lblV.ForeColor = $colors.TextPrimary
    $p.Controls.Add($lblV)
    if ($Sub) {
        $lblS = New-Object System.Windows.Forms.Label
        $lblS.Text = $Sub; $lblS.Location = [System.Drawing.Point]::new(10, 70)
        $lblS.AutoSize = $true; $lblS.Font = $fonts.Small; $lblS.ForeColor = $colors.TextDim
        $p.Controls.Add($lblS)
    }
    return $p
}

function Refresh-CoraVulnTab {
    if (-not $script:pnlCoraTiles) { return }
    $s = Build-CoraSummary

    $tilePanel = $script:pnlCoraTiles
    $tilePanel.SuspendLayout()
    try {
        foreach ($c in @($tilePanel.Controls)) { $c.Dispose() }
        $tilePanel.Controls.Clear()
        $tileW = 185; $tileH = 95; $gap = 8
        $x = 0
        $netPctStr = if ([double]::IsNaN($s.NetworkPct)) { 'N/A' } else { ($s.NetworkPct.ToString('0.0') + '%') }
        $netSub = if ($s.NetworkSize -gt 0) { "$($s.UniqueHosts) of $($s.NetworkSize)" } else { 'set Network size' }
        $vphStr = if ($s.UniqueHosts -gt 0) { $s.Vph.ToString('0.00') } else { 'N/A' }
        $tileSpecs = @(
            @{ Label = 'Total Open Vulns'; Value = (Format-AcasNumber $s.ConsideredFindings); Sub = "of $($s.TotalLoaded) loaded"; Color = $colors.Accent }
            @{ Label = 'Critical';         Value = (Format-AcasNumber $s.SevCount['Critical']); Sub = "$($s.SevHosts['Critical']) hosts"; Color = $colors.Danger }
            @{ Label = 'High';             Value = (Format-AcasNumber $s.SevCount['High']);     Sub = "$($s.SevHosts['High']) hosts"; Color = $colors.Orange }
            @{ Label = 'Unique Hosts';     Value = (Format-AcasNumber $s.UniqueHosts);          Sub = 'with open findings'; Color = $colors.Cyan }
            @{ Label = 'VPH';              Value = $vphStr;                                     Sub = 'vulns per host'; Color = $colors.Gold }
            @{ Label = '% of Network';     Value = $netPctStr;                                  Sub = $netSub; Color = $colors.Success }
        )
        foreach ($t in $tileSpecs) {
            $tilePanel.Controls.Add((New-CoraTile -Label $t.Label -Value $t.Value -Sub $t.Sub -StripeColor $t.Color -Location ([System.Drawing.Point]::new($x, 0)) -Size ([System.Drawing.Size]::new($tileW, $tileH))))
            $x += $tileW + $gap
        }
    } finally {
        $tilePanel.ResumeLayout()
    }

    $hPanel = $script:pnlCoraHitters
    $hPanel.SuspendLayout()
    try {
        foreach ($c in @($hPanel.Controls)) { $c.Dispose() }
        $hPanel.Controls.Clear()
        $rows = @($s.TopVulns | Select-Object -First 10)
        if ($rows.Count -eq 0) {
            $lblE = New-Object System.Windows.Forms.Label
            $lblE.Text = "No vulnerabilities to show. Import an ACAS scan on the ACAS Import tab."
            $lblE.Location = [System.Drawing.Point]::new(8, 12)
            $lblE.AutoSize = $true; $lblE.Font = $fonts.Label; $lblE.ForeColor = $colors.TextDim
            $hPanel.Controls.Add($lblE)
        } else {
            $rowH = 42; $y = 0
            $maxHosts = ($rows | Measure-Object -Property HostCount -Maximum).Maximum
            if ($maxHosts -le 0) { $maxHosts = 1 }
            $rank = 0
            foreach ($v in $rows) {
                $rank++
                $row = New-Object System.Windows.Forms.Panel
                $row.Location = [System.Drawing.Point]::new(0, $y)
                $row.Size = [System.Drawing.Size]::new(1140, ($rowH - 4))
                $row.BackColor = $colors.Panel
                $hPanel.Controls.Add($row)

                $lblRank = New-Object System.Windows.Forms.Label
                $lblRank.Text = "#$rank"; $lblRank.Location = [System.Drawing.Point]::new(10, 10)
                $lblRank.AutoSize = $true; $lblRank.Font = $fonts.LabelBold; $lblRank.ForeColor = $colors.Gold
                $row.Controls.Add($lblRank)

                $sevColor = Get-SeverityColor $v.Severity
                $lblSev = New-Object System.Windows.Forms.Label
                $lblSev.Text = "  $($v.Severity)  "; $lblSev.Location = [System.Drawing.Point]::new(50, 10)
                $lblSev.AutoSize = $true; $lblSev.Font = $fonts.SmallBold; $lblSev.ForeColor = $sevColor
                $row.Controls.Add($lblSev)

                $name = $v.VulnName
                if ($name -and $name.Length -gt 70) { $name = $name.Substring(0, 67) + '...' }
                $lblName = New-Object System.Windows.Forms.Label
                $lblName.Text = $name; $lblName.Location = [System.Drawing.Point]::new(140, 4)
                $lblName.AutoSize = $true; $lblName.Font = $fonts.LabelBold; $lblName.ForeColor = $colors.TextPrimary
                $row.Controls.Add($lblName)

                $lblPlug = New-Object System.Windows.Forms.Label
                $lblPlug.Text = "Plugin $($v.PluginID)  -  $($v.Category)"
                $lblPlug.Location = [System.Drawing.Point]::new(140, 22)
                $lblPlug.AutoSize = $true; $lblPlug.Font = $fonts.Small; $lblPlug.ForeColor = $colors.TextDim
                $row.Controls.Add($lblPlug)

                $barTrack = New-Object System.Windows.Forms.Panel
                $barTrack.Location = [System.Drawing.Point]::new(720, 14); $barTrack.Size = [System.Drawing.Size]::new(180, 10)
                $barTrack.BackColor = $colors.InputBorder
                $row.Controls.Add($barTrack)
                $barFill = New-Object System.Windows.Forms.Panel
                $barFill.Location = [System.Drawing.Point]::new(0, 0)
                $fillW = [Math]::Max(2, [int](($v.HostCount / [double]$maxHosts) * 180))
                $barFill.Size = [System.Drawing.Size]::new($fillW, 10)
                $barFill.BackColor = $sevColor
                $barTrack.Controls.Add($barFill)

                $lblCnt = New-Object System.Windows.Forms.Label
                $lblCnt.Text = "$($v.HostCount) hosts"
                $lblCnt.Location = [System.Drawing.Point]::new(910, 10)
                $lblCnt.AutoSize = $true; $lblCnt.Font = $fonts.LabelBold; $lblCnt.ForeColor = $colors.TextPrimary
                $row.Controls.Add($lblCnt)

                $pctStr = if ($s.NetworkSize -gt 0) {
                    [Math]::Round(($v.HostCount / [double]$s.NetworkSize) * 100, 1).ToString('0.0') + '% of net'
                } else { '-' }
                $lblPct = New-Object System.Windows.Forms.Label
                $lblPct.Text = $pctStr
                $lblPct.Location = [System.Drawing.Point]::new(1010, 10)
                $lblPct.AutoSize = $true; $lblPct.Font = $fonts.Small; $lblPct.ForeColor = $colors.Cyan
                $row.Controls.Add($lblPct)

                $y += $rowH
            }
            $hPanel.Size = [System.Drawing.Size]::new($hPanel.Width, [Math]::Max(100, $y + 10))
        }
    } finally {
        $hPanel.ResumeLayout()
    }

    if ($s.ConsideredFindings -eq 0) {
        $script:lblCoraStatus.Text = "No open + in-scope findings. Import an ACAS scan to populate."
        $script:lblCoraStatus.ForeColor = $colors.TextSecondary
    } else {
        $netNote = if ($s.NetworkSize -gt 0) { " (network = $($s.NetworkSize))" } else { ' (Network size not set)' }
        $script:lblCoraStatus.Text = "Loaded $($s.ConsideredFindings) findings across $($s.UniqueHosts) hosts$netNote. Click Open HTML Brief for the full report."
        $script:lblCoraStatus.ForeColor = $colors.TextSecondary
    }
}
#endregion

#region === START TAB (landing panel) ===
# Registered as TabPanels['Start'] so it participates in the normal sidebar
# nav swap. Start is the first entry in $tabNames and gets activated at the
# bottom of this script via NavButtons[0].PerformClick().
$global:PanelHome = New-Object System.Windows.Forms.Panel
$global:PanelHome.Dock = 'Fill'; $global:PanelHome.BackColor = $colors.Background
$global:PanelHome.Visible = $false
$contentArea.Controls.Add($global:PanelHome)
$global:TabPanels['Start'] = $global:PanelHome

# Title
$lblHomeTitle = New-Object System.Windows.Forms.Label
$lblHomeTitle.Text = "Welcome to J.A.N.E.T. Reports Tool"
$lblHomeTitle.Location = [System.Drawing.Point]::new(30, 20); $lblHomeTitle.AutoSize = $true
$lblHomeTitle.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$lblHomeTitle.ForeColor = $colors.Gold
$global:PanelHome.Controls.Add($lblHomeTitle)

$lblHomeDesc = New-Object System.Windows.Forms.Label
$lblHomeDesc.Text = "ACAS vulnerability analysis, patch tracking, and compliance reporting. Select a section below to get started."
$lblHomeDesc.Location = [System.Drawing.Point]::new(30, 58); $lblHomeDesc.Size = [System.Drawing.Size]::new(900, 24)
$lblHomeDesc.Font = $fonts.Label; $lblHomeDesc.ForeColor = $colors.TextSecondary
$global:PanelHome.Controls.Add($lblHomeDesc)

# Divider
$homeDiv = New-Object System.Windows.Forms.Panel
$homeDiv.Location = [System.Drawing.Point]::new(30, 90); $homeDiv.Size = [System.Drawing.Size]::new(1100, 1)
$homeDiv.BackColor = $colors.InputBorder; $homeDiv.Anchor = 'Top,Left,Right'
$global:PanelHome.Controls.Add($homeDiv)

# Section card builder. Cards dispatch by tab NAME (not numeric index) so
# inserting a tab in $tabNames doesn't silently misroute the home buttons.
function New-HomeCard {
    param([int]$X, [int]$Y, [string]$Number, [string]$Title, [string]$Desc, [System.Drawing.Color]$AccentColor, [string]$BtnText, [string]$TabName)

    $card = New-Object System.Windows.Forms.Panel
    $card.Location = [System.Drawing.Point]::new($X, $Y); $card.Size = [System.Drawing.Size]::new(530, 140)
    $card.BackColor = $colors.CardBg
    $global:PanelHome.Controls.Add($card)

    $acc = New-Object System.Windows.Forms.Panel
    $acc.Location = [System.Drawing.Point]::new(0, 0); $acc.Size = [System.Drawing.Size]::new(4, 140)
    $acc.BackColor = $AccentColor
    $card.Controls.Add($acc)

    $lblN = New-Object System.Windows.Forms.Label
    $lblN.Text = $Number; $lblN.Location = [System.Drawing.Point]::new(18, 16)
    $lblN.Size = [System.Drawing.Size]::new(34, 34); $lblN.Font = $fonts.Subtitle
    $lblN.ForeColor = $colors.TextPrimary; $lblN.TextAlign = 'MiddleCenter'
    $lblN.BackColor = $AccentColor
    $card.Controls.Add($lblN)

    $lblT = New-Object System.Windows.Forms.Label
    $lblT.Text = $Title; $lblT.Location = [System.Drawing.Point]::new(64, 16)
    $lblT.AutoSize = $true; $lblT.Font = $fonts.Subtitle; $lblT.ForeColor = $AccentColor
    $card.Controls.Add($lblT)

    $lblD = New-Object System.Windows.Forms.Label
    $lblD.Text = $Desc; $lblD.Location = [System.Drawing.Point]::new(64, 44)
    $lblD.Size = [System.Drawing.Size]::new(450, 48); $lblD.Font = $fonts.Label
    $lblD.ForeColor = $colors.TextSecondary
    $card.Controls.Add($lblD)

    $btnGo = New-StyledButton -Text $BtnText -Location ([System.Drawing.Point]::new(64, 98)) -Size ([System.Drawing.Size]::new(160, 30)) -BgColor $AccentColor
    if ($AccentColor -eq $colors.Warning -or $AccentColor -eq $colors.Gold -or $AccentColor -eq $colors.Cyan) {
        $btnGo.ForeColor = [System.Drawing.Color]::FromArgb(18, 18, 24)
    }
    $btnGo.Tag = $TabName
    $btnGo.Add_Click({
        $name = [string]$this.Tag
        foreach ($nb in $global:NavButtons) {
            if ($nb.Tag -eq $name) { $nb.PerformClick(); break }
        }
    }.GetNewClosure())
    $card.Controls.Add($btnGo)
}

# Home grid: six cards, two per row, in sidebar order so the visual flow
# mirrors the sidebar nav (Import -> Remediation -> Cross-Ref -> Future
# Targets -> Dashboard -> Export).

# Row 1: ACAS Import + Remediation Plan
New-HomeCard -X 30  -Y 110 -Number "1" -Title "ACAS Import" -AccentColor $colors.Accent `
    -Desc "Import ACAS scan data from CSV, TSV, or .nessus files. Filter, triage, and export to multi-sheet Excel. Use Re-Ping Hosts to sort online vs offline when needed." `
    -BtnText "Open ACAS Import" -TabName 'ACAS Import'

New-HomeCard -X 580 -Y 110 -Number "2" -Title "Remediation Plan" -AccentColor $colors.Orange `
    -Desc "Card-only push-job overview. One card per app (Chrome / Edge / Office / Defender / KB / Other). Common Other vulns affecting >= 10 hosts get their own dynamic cards. Copy hosts, export CSV, hand off to Nemesis, mark Pushed." `
    -BtnText "Open Remediation Plan" -TabName 'Remediation Plan'

# Row 2: Scan Comparison + Future Target IPs
New-HomeCard -X 30  -Y 270 -Number "3" -Title "Scan Comparison" -AccentColor $colors.Cyan `
    -Desc "Load two ACAS scans (before and after patching) to see what got remediated, what's still open, and any new findings. Apply results back to ACAS Import." `
    -BtnText "Open Cross-Ref" -TabName 'Patch Cross-Ref'

New-HomeCard -X 580 -Y 270 -Number "4" -Title "Future Target IPs" -AccentColor $colors.Gold `
    -Desc "Resolve a hostname list (e.g., AQC pre-target CSV) to IPs in parallel via DNS + ping. Copy the result to clipboard or export a CSV." `
    -BtnText "Open Future Target IPs" -TabName 'Future Target IPs'

# Row 3: Dashboard + Export
New-HomeCard -X 30  -Y 430 -Number "5" -Title "Dashboard" -AccentColor $colors.Warning `
    -Desc "View compliance metrics: patch rate, severity breakdown, category breakdown, and per-host summary. Target 90%+ patch rate for compliance." `
    -BtnText "Open Dashboard" -TabName 'Dashboard'

New-HomeCard -X 580 -Y 430 -Number "6" -Title "Export" -AccentColor $colors.Success `
    -Desc "Save your work as JSON to reload later, or export CSV reports: full report, NOT OUR PATCH list, remaining vulns, filtered view, or per-host summary." `
    -BtnText "Open Export" -TabName 'Export'

# Row 4: Weekly Export + Dirty 30 Triage
New-HomeCard -X 30  -Y 590 -Number "7" -Title "Weekly Export" -AccentColor $colors.Purple `
    -Desc "Split the monthly ACAS_Calculations workbook into per-week cards. Two enclaves (NIPR / SIPR) with Total Vulns, AR % with/without PMO, MAJCOM score, and VPH broken out by category (UEs / Servers / Infrastructure / Printers / PMO by owner). Per-week CSV/XLSX export." `
    -BtnText "Open Weekly Export" -TabName 'Weekly Export'

New-HomeCard -X 580 -Y 590 -Number "8" -Title "Dirty 30 Triage" -AccentColor $colors.Cyan `
    -Desc "Load the Tenable Dirty 30 (Top 30 Worst Hosts) report - paste text, CSV, or TXT. Run AD lookup to see squadron, last AD logon, and stale machines. Optional probe gets the last interactive user from each host. Filter by Stale / Not Found / squadron, export CSV." `
    -BtnText "Open Dirty 30 Triage" -TabName 'Dirty 30 Triage'

# Workflow tip at bottom
$lblHomeTip = New-Object System.Windows.Forms.Label
$lblHomeTip.Text = "TYPICAL WORKFLOW:  Import ACAS data  >  Plan remediation  >  Compare scans  >  Check Dashboard  >  Export reports / Weekly summary"
$lblHomeTip.Location = [System.Drawing.Point]::new(30, 750); $lblHomeTip.AutoSize = $true
$lblHomeTip.Font = $fonts.SmallBold; $lblHomeTip.ForeColor = $colors.TextDim
$global:PanelHome.Controls.Add($lblHomeTip)

$lblHomeVersion = New-Object System.Windows.Forms.Label
$lblHomeVersion.Text = "v2.14.0  |  Use the sidebar to navigate between sections at any time"
$lblHomeVersion.Location = [System.Drawing.Point]::new(30, 772); $lblHomeVersion.AutoSize = $true
$lblHomeVersion.Font = $fonts.Small; $lblHomeVersion.ForeColor = $colors.TextDim
$global:PanelHome.Controls.Add($lblHomeVersion)
#endregion

#region === SHOW FORM ===
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

    if ($script:searchTimer) { $script:searchTimer.Stop(); $script:searchTimer.Dispose() }
    if ($script:xrefSearchTimer) { $script:xrefSearchTimer.Stop(); $script:xrefSearchTimer.Dispose() }
    if ($script:dashResizeTimer) { $script:dashResizeTimer.Stop(); $script:dashResizeTimer.Dispose() }
})
Log "ReportsTool v2.14.0 ready. Import ACAS data to begin."
# Activate the Start tab on launch so users land on the landing panel.
if ($global:NavButtons.Count -gt 0) { $global:NavButtons[0].PerformClick() }
$f.Add_Shown({ $f.Activate() })

## JANET centralized session (added in v2.9.1). Read-only tool: silent rollup.
try { Start-JanetSession -Tool 'Reports' -Version $JanetReportsVersion } catch {}
[void]$f.ShowDialog()
try { Stop-JanetSession } catch {}

Write-DebugLog "=== ReportsTool v2.14.0 session ended ==="
#endregion