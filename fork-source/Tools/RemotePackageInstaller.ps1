### Remote Package Installer
### Author: Braxton Thompson | 48CS/SCOO | B.E.A.T. Contractor
### Date: April 2026
### J.A.N.E.T. - RemotePackageInstaller v2.5.4
### Purpose: Deploy software packages (Deploy-Application.ps1) OR raw MSI
###          bundles to remote workstations via UNC share copy + Invoke-
###          Command. Layout matches WPT: left sidebar with brand/heartbeats/
###          user block, content area with grid-paper background and accent
###          rule, bottom status strip with scanline overlay.
###
### Changelog:
###   v2.5.4 - 2026-05-15 - SCAN button moved left of the root textbox.
###          User feedback: "There is a button hidden behind the root
###          thing." Previous layout had SCAN/RESCAN/SAVE all anchored to
###          the right of a stretched ROOT textbox, with an 8px X-gap
###          between the textbox right edge and SCAN's left edge. That
###          gap turned out to be smaller than the visual extent of the
###          textbox's fill color, so SCAN's purple body landed visually
###          under the textbox's right edge. Moved SCAN to X=70 (just
###          after the ROOT label) with Anchor=Top,Left — fixed position,
###          can never collide with the stretching textbox. RESCAN + SAVE
###          stay on the right. New row reads: ROOT [SCAN] [_textbox_] [RESCAN] [SAVE].
###
###   v2.5.3 - 2026-05-15 - File-path-as-package + per-MSI copy.
###          Operator pasted a direct UNC to a single .msi file into the
###          custom-folder textbox (\\fs\Apps\Patching\Foo.msi). My code
###          treated the file path as a "folder" and the deploy failed
###          with "MSI not found in copied bundle" because the copy
###          landed as a file at the destination instead of a folder.
###          Fixed two ways:
###            (1) Get-RpiResolvedMsiFolder + Update-RpiMsiList now
###                detect .msi-file paths, treat them as
###                (parent folder, [this one MSI selected]), and pre-check
###                only that file. Deploy-click symmetrically rewrites
###                pkgPath -> parent + msiList -> [leaf] before dispatch.
###            (2) MSI-mode deploy now copies ONLY the selected .msi files
###                (preserving subdir structure for entries like
###                'x64\foo.msi') instead of the whole folder. Previously,
###                pointing at \\fs\Apps\Patching\ would have copied the
###                entire patching share to every target. PSADT mode
###                unchanged - still copies the whole folder since
###                Deploy-Application.ps1 needs its siblings.
###            (3) Remote bundle folder name is now sanitized
###                (non-[a-zA-Z0-9._-] -> '_') so file-name leaves like
###                PowerShell-7.4.15-win-x64.msi don't produce a folder
###                name with a dot extension that confuses C:\Temp lookups.
###
###   v2.5.2 - 2026-05-15 - Visible SCAN button + sidebar version sync.
###          The ghost-style "Browse" button added in v2.5.0 was rendering
###          with a thin purple-on-dark outline that was hard to spot
###          against the card background — first user feedback was "I do
###          not see the scan button". Replaced with a filled purple SCAN
###          button styled to match DEPLOY's visual weight so it's
###          unmissable. Also fixed the sidebar version label which still
###          read v2.4.5 even though the title bar showed v2.5.1.
###
###   v2.5.1 - 2026-05-15 - MSI exit-code capture fix.
###          First real-world MSI run (PowerShell-7.4.15-win-x64.msi)
###          surfaced a host-failure row with "exit=" (empty) and Detail
###          "1 of 1 MSI(s) failed; first failure: ... (exit=)". Root
###          cause: Start-Process -Wait -PassThru can return $proc.ExitCode
###          = $null inside a remote PSSession because the handle is reaped
###          before we read the property. Replaced the launch with a direct
###          System.Diagnostics.ProcessStartInfo + WaitForExit() pattern,
###          which keeps the handle open until we explicitly read ExitCode.
###          Also surfaces the per-MSI Reason in the host's aggregate Detail
###          so the grid row tells the operator WHY it failed without
###          having to open the double-click detail popup.
###
###   v2.5.0 - 2026-05-15 - MSI bundle mode + Browse-for-root.
###          Operator picks any folder containing one or more .msi files
###          and the tool fans them out to each target via msiexec,
###          parallel across hosts. Also adds a Browse button next to
###          Rescan so the package root can be picked via folder dialog
###          instead of hand-typed (auto-rescans on confirm); Enter key
###          in the root textbox also triggers a rescan. Adds:
###          * "MSI bundle" toggle in Package Source card. When on, the
###            currently-resolved folder (combo-pick from root OR custom
###            folder) is rescanned for *.msi (recursive, depth 1) and a
###            CheckedListBox of discovered MSIs appears below the combo,
###            all checked by default ("auto-select"). Select All / Select
###            None mini-buttons toggle the whole set.
###          * MSI args textbox. Defaults to "/qn /norestart" so most
###            standard installers go silent + skip the reboot. Operator
###            can append per-bundle args (PROPERTY=value, transform refs,
###            ALLUSERS=1, etc.) without editing the script.
###          * Per-host runspace scriptblock gains a Mode branch ('PSADT'
###            vs 'MSI'). MSI path: after the folder is copied to
###            C:\Temp\<bundle>_<stamp>\, the remote scriptblock iterates
###            each selected MSI and shells `msiexec /i <file> $args /L*v
###            <logpath>`. Per-MSI exit code is parsed with the same
###            convention as PSADT (0/1641/3010 = success, 1602/1603/other
###            = failed, 1618 = 'Another install in progress' surfaced as
###            a clear reason). Host aggregate Status is Success only when
###            EVERY MSI returned success; otherwise Failed with the first
###            failing MSI surfaced in Detail and the full per-MSI table
###            captured in Output for the detail popup.
###          * Each MSI's /L*v log lands at
###            C:\Temp\<bundle>_<stamp>\<msi>.msiexec.log so post-mortem
###            on a stubborn box is one RDP away.
###          * Config persists msiMode, msiArgs, and the per-bundle MSI
###            selection set (filenames only) so the next launch starts
###            with the same picks if the folder still has the same files.
###          * Result grid + Detail popup unchanged in shape — MSI runs
###            populate the same per-host row + output stream, so the
###            existing export/retry/popout machinery just works.
###
###   v2.4.6 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
###          *_usage*.csv so schema-rotation sister files (created when
###          the legacy file is persistently locked) are drained on next
###          launch instead of stranded.
###
###   v2.4.5 - May 2026 - JANET centralized-logging schema cleanup
###          (single SessionEnd rollup row; Snapshot rows retired) and
###          the WPT-themed Closing Notes prompt rolled across the
###          suite.
###
###   v2.4.4 - May 2026 - Fix host-detail popup close paths:
###          * Operator report: "no close button — clicking the X
###            does no thing." Two real bugs:
###            (1) The bottom "Close" button's Add_Click handler
###                referenced $dlg without .GetNewClosure(), so the
###                $dlg variable wasn't visible at delegate-
###                invocation time and clicks silently no-op'd.
###            (2) The system title-bar X is unreliable across DPI
###                + dark-titlebar combos in PS 5.1 WinForms — same
###                class of bug the Nemesis tool just fixed (1.8.12).
###          * Fix:
###            - .GetNewClosure() on the bottom Close button
###            - $btnClose.DialogResult = OK so Enter + AcceptButton
###              wiring works, plus Esc routes through CancelButton
###            - New in-form X button at the top right of the dialog
###              (X=678 Y=8, W=28 H=28), red-on-hover, tab-stopped
###              out of the focus ring. Wired with .GetNewClosure()
###              and DialogResult=Cancel; assigned as $dlg.CancelButton
###              so Esc + the X both reliably close.
###          * Status badge shifted X=540->420, W=160->240 to make
###            room for the X button at top right.
###   v2.4.3 - May 2026 - Per-host detail popup:
###          * Double-click any row in the Deployment Results grid to
###            open a modal with everything captured for that host:
###            status, exit code, package, start/end/duration, repair
###            attempted/succeeded, and the full Deploy-Application.ps1
###            stdout+stderr in a scrollable monospace pane. "Copy
###            Output" button puts the captured text on the clipboard
###            for log-paste workflows.
###          * Per-host scriptblock now bubbles the captured Output
###            (previously $sub.Output, scoped to the inner
###            Invoke-Command) up to the outer result object, plus
###            stamps the Package name on each result.
###          * Drain timer stashes every full result in
###            $script:RpiHostDetails keyed by hostname. Cleared at
###            deploy start so the popup never shows stale data from
###            a prior run. Late-finishers after a Cancel still
###            populate the dictionary so the operator can inspect
###            what they returned.
###          * Header double-clicks (RowIndex=-1) and Queued/empty
###            rows are guarded — popup shows a friendly stub
###            ("runspace still in flight") instead of opening empty.
###   v2.4.2 - May 2026 - Live progress visibility + selectable concurrency:
###          * Status bar gains a Progress indicator that updates every
###            drain tick: "Progress: 12 / 120 (10%) | Live: 8". Color
###            shifts: Accent1 during run, Success at 100%, Warning on
###            cancel. Survives the run completion so the closing tally
###            stays visible until the next deploy starts.
###          * Per-host live step via a ConcurrentQueue[psobject] shared
###            across runspaces. Each scriptblock pushes intermediate
###            status messages ('Probing', 'Repairing', 'Copying',
###            'Deploying') so the grid paints live phase, not just
###            terminal status. Drain timer dequeues per tick.
###          * 'Probing' / 'Repairing' / 'Queued' added to the grid
###            color switch with appropriate theme colors.
###          * Concurrency selector (NumericUpDown 1-32, default 8) in
###            the action bar replaces the v2.4.0 hardcode. Operator
###            picks how many hosts run at once — 1 for cautious / first
###            deploy, 8 for typical fleet runs, 16-32 for big fast
###            pushes against responsive boxes. Cred status label
###            shrunk W=360 -> W=220 to fit.
###   v2.4.1 - May 2026 - WinRM-via-DCOM bootstrap recovery path:
###          * When a host's TCP probe finds 5985 closed but 445 open,
###            the per-host runspace now attempts an inline WinRM
###            repair via DCOM (port 135) before giving up. Pattern
###            ported from WPT 6.3.0 WinRMBootstrapBlock.
###          * Steps: 2-attempt CIM-over-DCOM connect, ChangeStartMode
###            -> Auto, StartService, then `winrm quickconfig -force
###            -quiet -skipNetworkProfileCheck` via Win32_Process.Create,
###            then re-probe 5985 with a 30-second budget.
###          * On success, deploy continues normally. Result hashtable
###            gains RepairAttempted + RepairSucceeded fields; drain
###            timer logs a [REPAIRED] / [REPAIR-FAILED] tag prefix
###            so the operator can spot which hosts needed it.
###          * Hosts where DCOM is also unreachable (e.g. RPC blocked)
###            fail with a clear "DCOM repair connect failed" reason.
###   v2.4.0 - May 2026 - Parallel deploy via RunspacePool:
###          * Sequential for/DoEvents loop replaced with a bounded
###            RunspacePool (max 8 concurrent by default). On a 50-host
###            fleet, wall-clock drops from ~25 min to ~2-3 min.
###          * Per-host work (TCP probe, PSDrive map, package copy,
###            WinRM Invoke-Command, PSADT exit-code parse, cleanup)
###            moves into a single self-contained scriptblock that runs
###            inside each runspace.
###          * 400ms drain timer in the WinForms message loop polls
###            completion and updates the grid + counters on the UI
###            thread. Hosts paint live as they finish, in completion
###            order — not dispatch order.
###          * Cancel-mid-run: clicking the Deploy button while a run
###            is in flight sets a cancellation flag. Drain timer
###            finalizes early and shows a [CANCELLED] run summary.
###            In-flight runspaces complete in the background; we do
###            NOT call .Stop() on them because that can leave a target
###            mid-MSI-install.
###          * Grid seeded with "Queued" rows for every host before
###            dispatch so the operator sees the full target list
###            immediately and can watch each row transition to
###            Success / Failed / Deferred as runspaces return.
###          * RunspacePool + drain timer cleaned up in FormClosing.
###   v2.3.3 - May 2026 - Quality-of-life fixes:
###          * Case-insensitive target dedup (HashSet[OrdinalIgnoreCase])
###            so MSEKL-ABC and msekl-abc collapse to one host.
###          * OneDrive launch-path warning at startup; sync can hold
###            file locks during package copy and race with config saves.
###          * PSADT exit code 60012 (user deferred) split out as its
###            own 'Deferred' grid status (Warning color), tracked in
###            run summary, and mapped to JANET 'Skipped' instead of
###            'Failure' in the centralized log.
###   v2.3.2 - May 2026 - Reliability port from WPT 6.4.1:
###          * TCP reachability probe (5985 then 445) replaces
###            Test-Connection ICMP, which AFNET GPO blocks by default
###            and was failing every host with "ping failed".
###          * Bounded New-PSSessionOption (OperationTimeout 180s,
###            OpenTimeout 15s, CancelTimeout 5s, IdleTimeout 60s) so
###            one hung host can no longer stall the deploy loop on
###            the default 4-minute WinRM timeout.
###          * Authentication=Negotiate on New-PSSession (Kerberos
###            first, NTLM fallback).
###          * Layout fix: contentBody is pre-sized before children
###            are added so right-anchored buttons (Import/Clear,
###            Rescan/Save/Browse, Export/Retry/Deploy) stay on-screen.
###          * Removed dead WPT.config.json usage-journal block; the
###            JANET centralized logging block at the top of the file
###            has been the only real telemetry path since v2.3.1.
###   v2.3.1 - April 2026 - JANET centralized logging block.
###   v2.2 - April 2026 - Restructured layout to match WPT MainForm:
###          * Left sidebar (brand block + section anchors + user block)
###          * Content host with top strip, accent rule, divider,
###            grid-paper dot background
###          * Status strip with scanline overlay
###          * Four heartbeat indicators (brand, content, status, session)
###          * EXECUTE DEPLOY button pulses when ready to fire
###   v2.1 - April 2026 - First restyle to match WPT dark theme.
###   v2.0 - March 2026 - First full GUI restyle.
###   v1.0 - October 2025 - Initial release.

Add-Type -AssemblyName System.Windows.Forms -EA SilentlyContinue
Add-Type -AssemblyName System.Drawing -EA SilentlyContinue
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v2.3.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\Remote_Pkg\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetRemote_PkgVersion = '2.5.4'

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
        ## v2.3.2: TCP 445 (SMB) probe instead of Test-Connection ICMP.
        ## Block kept inline so the JANET logging region stays self-contained
        ## (no dependency on Test-RpiReachable defined later in the file).
        $tc = $null; $reachable = $false
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($server, 445, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                $reachable = $true
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if (-not $reachable) { return $false }
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

try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

#region === RESOLVE SCRIPT DIRECTORY ===
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }

#endregion

#region === LOGGING ===
$global:LogDir = Join-Path (Split-Path $global:ScriptDir -Parent) "Logs"
try { if (-not (Test-Path $global:LogDir)) { New-Item -Path $global:LogDir -ItemType Directory -Force -EA Stop | Out-Null } } catch { $global:LogDir = $global:ScriptDir }
$global:SessionTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$global:PatcherLogPath = Join-Path $global:LogDir "RemotePackageInstaller_${env:USERNAME}_$($global:SessionTimestamp).log"

function Write-RpiAuditLog {
    param([string]$Target, [string]$Package, [string]$Result, [string]$Detail = "")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$ts] [USER: $env:USERNAME] [TARGET: $Target] [PKG: $Package] [RESULT: $Result]"
    if ($Detail) { $entry += " [DETAIL: $Detail]" }
    try { $entry | Out-File -FilePath $global:PatcherLogPath -Append -Encoding UTF8 } catch {}
}
#endregion

#region === USAGE JOURNAL (shared with WPT) === REMOVED
# Removed in v2.3.2. Superseded by the JANET centralized logging block at
# the top of this file (Initialize-JanetSession / Add-JanetCsvRow,
# $JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'). The old
# block read a .\WPT.config.json that never existed in this repo, and the
# schema it expected (cfg.logging.networkLogShare*) didn't match WPT's own
# top-level usageCsvShare/logShare keys, so it silently no-op'd anyway.
#endregion

#region === REMOTING (WPT-canonical patterns) ===
# Ported from WPT 6.4.1 in v2.3.2. AFNET workstations block inbound ICMP by
# GPO, so Test-Connection returns false for every host even when WinRM (5985)
# and SMB (445) are wide open. Use a TCP probe instead. Bounded PSSession
# options keep a single hung host from stalling the deploy loop on default
# 4-minute WinRM timeouts.

$script:WSManOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000

function Test-RpiReachable {
    # Returns $true as soon as either WinRM (5985) or SMB (445) accepts a TCP
    # connection within $TimeoutMs. Independent of ICMP/firewall echo policy.
    param([string]$Computer, [int]$TimeoutMs = 1500)
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) {
                $tc.Close(); return $true
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}
#endregion

#region === THEME (matches WPT dark theme) ===
$mkColor = { param($r,$g,$b) [System.Drawing.Color]::FromArgb($r,$g,$b) }

$theme = [pscustomobject]@{
    # ---- Surfaces ----
    Background     = & $mkColor  10  11  14    # #0A0B0E
    Sidebar        = & $mkColor   7   8  11
    TitleBar       = & $mkColor   5   6   9
    StatusBar      = & $mkColor   7   8  11
    Surface        = & $mkColor  18  19  24
    SurfaceAlt     = & $mkColor  24  26  33
    SurfaceHover   = & $mkColor  30  33  42
    SurfaceActive  = & $mkColor  42  46  58
    # ---- Borders ----
    Border         = & $mkColor  34  37  45
    BorderStrong   = & $mkColor  50  55  68
    # ---- Primary accent (purple) ----
    Accent1        = & $mkColor 140 100 220    # #8C64DC
    Accent1Hover   = & $mkColor 170 130 232    # #AA82E8
    Accent1Muted   = & $mkColor 107  72 176    # #6B48B0
    Accent1Glow    = & $mkColor  42  28  68    # deep purple tint
    # ---- Secondary accent (gold) ----
    Accent2        = & $mkColor 218 180  82    # #DAB452
    Accent2Hover   = & $mkColor 232 198 110
    # ---- Status palette ----
    Success        = & $mkColor 127 178  94
    SuccessHover   = & $mkColor 154 202 118
    Warning        = & $mkColor 242 184  75
    Danger         = & $mkColor 229  72  77
    DangerHover    = & $mkColor 248 102 107
    Info           = & $mkColor 115 180 211
    # ---- Text hierarchy ----
    TextPrimary    = & $mkColor 242 244 247
    TextSecondary  = & $mkColor 160 165 174
    TextMuted      = & $mkColor 106 111 120
    TextFaint      = & $mkColor  62  67  76
    TextOnAccent   = & $mkColor  12   9   3
    # ---- Grid ----
    GridBg         = & $mkColor  18  19  24
    GridAlt        = & $mkColor  23  25  31
    GridHeader     = & $mkColor  12  13  17
    GridSelection  = & $mkColor  42  28  68    # purple tint on selected rows
    GridLine       = & $mkColor  34  37  45
    # ---- Console ----
    ConsoleBg      = & $mkColor   5   6   9
    ConsoleFg      = & $mkColor 218 180  82    # gold text on black
    # ---- Stripe accent on primary CTA ----
    StripeGold     = & $mkColor 218 180  82
    StripeBlack    = & $mkColor  10  11  14
}

$mono = 'Cascadia Mono'
$body = 'Segoe UI Variable Display'

$fonts = [pscustomobject]@{
    DisplayLg   = New-Object System.Drawing.Font($mono, 18, [System.Drawing.FontStyle]::Bold)
    DisplayMd   = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
    DisplaySm   = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)
    Eyebrow     = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
    EyebrowDim  = New-Object System.Drawing.Font($mono,  8)
    Body        = New-Object System.Drawing.Font($body, 10)
    BodyStrong  = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
    Caption     = New-Object System.Drawing.Font($body,  9)
    CaptionB    = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
    Tiny        = New-Object System.Drawing.Font($body,  8)
    Mono        = New-Object System.Drawing.Font($mono, 10)
    MonoSm      = New-Object System.Drawing.Font($mono,  9)
    MonoTiny    = New-Object System.Drawing.Font($mono,  8)
    Icon        = New-Object System.Drawing.Font('Segoe MDL2 Assets', 14)
    IconSmall   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)
}
#endregion

#region === GLOBALS ===
$global:Credentials   = $null
$global:PackageMap    = @{}
$global:DeployResults = [System.Collections.ArrayList]::new()

# Default package root - sits next to this script under JANET\Tools\Packages.
# This is the FALLBACK; the user's saved preference (if any) overrides below.
$DefaultPackageRoot = Join-Path $global:ScriptDir "Packages"
if (-not (Test-Path $DefaultPackageRoot)) {
    try { New-Item -Path $DefaultPackageRoot -ItemType Directory -Force | Out-Null } catch {}
}

# Persistence file - lives next to the script. Holds the user's saved
# package-root preference so they don't have to reset it every launch.
$global:RpiConfigPath = Join-Path $global:ScriptDir "RemotePackageInstaller.config.json"

function Read-RpiConfig {
    # Returns a hashtable of saved settings, or @{} if no config file exists
    # / the file is corrupt. Never throws - bad config falls back to defaults.
    if (-not (Test-Path $global:RpiConfigPath)) { return @{} }
    try {
        $raw = Get-Content -LiteralPath $global:RpiConfigPath -Raw -EA Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json -EA Stop
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
        return $h
    } catch {
        return @{}
    }
}

function Save-RpiConfig {
    # Persists the current package-source UI state to disk so the next launch
    # of the tool starts where the operator left off. Writes UTF-8 with BOM
    # so the file matches the .ps1 sealing convention.
    ##
    ## v2.5.0: msiMode + msiArgs + msiSelection added. msiSelection is the
    ## set of MSI filenames (no path) that were checked at save time —
    ## restored on next launch if the folder still has the same files; new
    ## files default to checked, missing files are dropped.
    $msiSel = @()
    if ($script:clbMsi) {
        for ($i = 0; $i -lt $script:clbMsi.Items.Count; $i++) {
            if ($script:clbMsi.GetItemChecked($i)) { $msiSel += [string]$script:clbMsi.Items[$i] }
        }
    }
    $cfg = [pscustomobject]@{
        packageRoot  = if ($txtRoot)        { $txtRoot.Text.Trim() }        else { $DefaultPackageRoot }
        useCustom    = if ($chkCustom)      { [bool]$chkCustom.Checked }    else { $false }
        customPath   = if ($txtCustom)      { $txtCustom.Text.Trim() }      else { '' }
        msiMode      = if ($script:chkMsiMode) { [bool]$script:chkMsiMode.Checked } else { $false }
        msiArgs      = if ($script:txtMsiArgs) { $script:txtMsiArgs.Text.Trim() }   else { '/qn /norestart' }
        msiSelection = $msiSel
        savedAt      = (Get-Date).ToString('s')
        savedBy      = $env:USERNAME
    }
    try {
        $json = $cfg | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText($global:RpiConfigPath, $json, (New-Object System.Text.UTF8Encoding($true)))
        return $true
    } catch {
        return $false
    }
}

# Apply saved config (if any) over the default. We override only the strings
# we recognize so a partial / older config file still loads cleanly.
$savedCfg = Read-RpiConfig
if ($savedCfg.ContainsKey('packageRoot') -and -not [string]::IsNullOrWhiteSpace($savedCfg['packageRoot'])) {
    $DefaultPackageRoot = [string]$savedCfg['packageRoot']
    if (-not (Test-Path $DefaultPackageRoot)) {
        try { New-Item -Path $DefaultPackageRoot -ItemType Directory -Force | Out-Null } catch {}
    }
}
#endregion

#region === REFLECTION + DWM HELPERS ===
function Enable-RpiDoubleBuffer {
    param([Parameter(Mandatory)]$Control)
    try {
        $prop = $Control.GetType().GetProperty('DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic')
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function Set-RpiDarkTitleBar {
    param([Parameter(Mandatory)]$Form)
    if (-not ('Rpi.Dwm' -as [type])) {
        Add-Type -Namespace 'Rpi' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }
    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }
    $enable = 1
    $null = [Rpi.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Rpi.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)
    $round = 2
    $null = [Rpi.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}
#endregion

#region === CONTROL FACTORY ===
function New-RpiLabel {
    param(
        [string]$Text = '',
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 18,
        $Font = $null, $Fg = $null
    )
    if (-not $Font) { $Font = $fonts.Body }
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.Font      = $Font
    return $l
}

function New-RpiTextBox {
    param([int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26, [switch]$Multi)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location    = New-Object System.Drawing.Point($X, $Y)
    $t.Size        = New-Object System.Drawing.Size($W, $H)
    $t.BackColor   = $theme.SurfaceAlt
    $t.ForeColor   = $theme.TextPrimary
    $t.Font        = $fonts.Mono
    $t.BorderStyle = 'FixedSingle'
    if ($Multi) { $t.Multiline = $true; $t.ScrollBars = 'Vertical' }
    return $t
}

function New-RpiComboBox {
    param([int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26)
    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Location      = New-Object System.Drawing.Point($X, $Y)
    $cb.Size          = New-Object System.Drawing.Size($W, $H)
    $cb.BackColor     = $theme.SurfaceAlt
    $cb.ForeColor     = $theme.TextPrimary
    $cb.Font          = $fonts.Mono
    $cb.DropDownStyle = 'DropDownList'
    $cb.FlatStyle     = 'Flat'
    return $cb
}

function New-RpiButton {
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Bg = $null, $Fg = $null, $Font = $null
    )
    if (-not $Bg)   { $Bg   = $theme.Accent1 }
    if (-not $Fg)   { $Fg   = $theme.TextOnAccent }
    if (-not $Font) { $Font = $fonts.DisplaySm }
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
    $hover = [System.Drawing.Color]::FromArgb([Math]::Min(255,$Bg.R+28), [Math]::Min(255,$Bg.G+28), [Math]::Min(255,$Bg.B+28))
    $down  = [System.Drawing.Color]::FromArgb([Math]::Max(0,$Bg.R-20), [Math]::Max(0,$Bg.G-20), [Math]::Max(0,$Bg.B-20))
    $b.FlatAppearance.MouseOverBackColor = $hover
    $b.FlatAppearance.MouseDownBackColor = $down
    return $b
}

function New-RpiGhostButton {
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Fg = $null
    )
    if (-not $Fg) { $Fg = $theme.TextSecondary }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $theme.BorderStrong
    $b.BackColor = $theme.Background
    $b.ForeColor = $Fg
    $b.Font      = $fonts.DisplaySm
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $b.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    return $b
}

function New-RpiStripeButton {
    # Primary CTA. Purple base with a diagonal gold/black stripe along the bottom 4px.
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 220, [int]$H = 44
    )
    $b = New-RpiButton -Text $Text -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextPrimary -Font $fonts.DisplayMd
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover
    $stripeH = 4
    $stripe1 = $theme.StripeGold
    $stripe2 = $theme.StripeBlack
    $b.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush('WideDownwardDiagonal', $stripe2, $stripe1)
        try {
            $rect = New-Object System.Drawing.Rectangle(0, ($sender.Height - $stripeH), $sender.Width, $stripeH)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())
    return $b
}

function New-RpiCheckBox {
    param(
        [string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 250, [int]$H = 24,
        $Fg = $null, [bool]$Checked = $false
    )
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
    $c.FlatAppearance.BorderSize         = 0
    $c.FlatAppearance.CheckedBackColor   = $theme.Surface
    $c.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $c.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    $c.TextAlign = 'MiddleLeft'
    $c.Padding   = New-Object System.Windows.Forms.Padding(26, 0, 0, 0)
    $c.AutoSize  = $false

    $borderOff = $theme.BorderStrong
    $borderOn  = $theme.Accent1
    $fillOn    = $theme.Accent1
    $checkFg   = $theme.TextOnAccent
    $c.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $box = 14; $bx = 4; $by = [int](($sender.Height - $box) / 2)
        if ($sender.Checked) {
            $fill = New-Object System.Drawing.SolidBrush($fillOn)
            try { $g.FillRectangle($fill, $bx, $by, $box, $box) } finally { $fill.Dispose() }
            $pen = New-Object System.Drawing.Pen($borderOn, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) } finally { $pen.Dispose() }
            $cp = New-Object System.Drawing.Pen($checkFg, 2)
            try {
                $p1 = New-Object System.Drawing.Point(($bx + 3),  ($by + 7))
                $p2 = New-Object System.Drawing.Point(($bx + 6),  ($by + 10))
                $p3 = New-Object System.Drawing.Point(($bx + 11), ($by + 4))
                $g.DrawLines($cp, @($p1, $p2, $p3))
            } finally { $cp.Dispose() }
        } else {
            $pen = New-Object System.Drawing.Pen($borderOff, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) } finally { $pen.Dispose() }
        }
    }.GetNewClosure())
    $c.Add_CheckedChanged({ $args[0].Invalidate() })
    return $c
}

function New-RpiCard {
    # Surface panel with 4 L-shaped corner brackets.
    # Optional Header renders as `/ HEADER` eyebrow with dotted underline.
    param(
        [string]$Header,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
        $Fg = $null,
        [int]$Padding = 18,
        [int]$BracketLen = 16,
        [int]$BracketThick = 2
    )
    if (-not $Fg) { $Fg = $theme.Accent1 }
    $card = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($X, $Y)
    $card.Size      = New-Object System.Drawing.Size($W, $H)
    $card.BackColor = $theme.Surface
    $card.Padding   = New-Object System.Windows.Forms.Padding($Padding)
    Enable-RpiDoubleBuffer -Control $card

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
            $g.DrawLine($pen, 0, 0, $L, 0); $g.DrawLine($pen, 0, 0, 0, $L)
            $g.DrawLine($pen, ($w - $L), 0, $w, 0); $g.DrawLine($pen, $w, 0, $w, $L)
            $g.DrawLine($pen, 0, ($h - $L), 0, $h); $g.DrawLine($pen, 0, $h, $L, $h)
            $g.DrawLine($pen, ($w - $L), $h, $w, $h); $g.DrawLine($pen, $w, ($h - $L), $w, $h)
        } finally { $pen.Dispose() }
        if ($hasHdr) {
            $dotPen = New-Object System.Drawing.Pen($underColor, 1)
            $dotPen.DashStyle = 'Dot'
            try { $g.DrawLine($dotPen, $Padding, 34, ($sender.Width - $Padding), 34) }
            finally { $dotPen.Dispose() }
        }
    }.GetNewClosure())

    if ($hasHdr) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text      = "/ $($Header.ToUpperInvariant())"
        $hdr.Location  = New-Object System.Drawing.Point($Padding, 10)
        $hdr.Size      = New-Object System.Drawing.Size(($W - $Padding * 2), 20)
        $hdr.ForeColor = $Fg
        $hdr.BackColor = [System.Drawing.Color]::Transparent
        $hdr.Font      = $fonts.Eyebrow
        $card.Controls.Add($hdr)
    }
    return $card
}

function New-RpiSeparator {
    param([int]$X = 0, [int]$Y = 0, [int]$W = 200, $Color = $null)
    if (-not $Color) { $Color = $theme.Border }
    $s = New-Object System.Windows.Forms.Panel
    $s.Location  = New-Object System.Drawing.Point($X, $Y)
    $s.Size      = New-Object System.Drawing.Size($W, 1)
    $s.BackColor = $Color
    return $s
}

function New-RpiPulseIndicator {
    # Small blinking status dot
    param(
        [int]$X = 0, [int]$Y = 0, [int]$Size = 10,
        [ValidateSet('Active','Idle','Alert')][string]$State = 'Idle'
    )
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
        try { $e.Graphics.FillEllipse($brush, 0, 0, ($sender.Width - 1), ($sender.Height - 1)) }
        finally { $brush.Dispose() }
    }.GetNewClosure())
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({ $p.Tag.Phase = 1 - $p.Tag.Phase; $p.Invalidate() }.GetNewClosure())
        $timer.Start()
        $p.Tag.Timer = $timer
    }
    return $p
}

function Set-RpiPulseState {
    param([Parameter(Mandatory)]$Indicator,
          [ValidateSet('Active','Idle','Alert')][string]$State)
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
        $timer.Add_Tick({ $Indicator.Tag.Phase = 1 - $Indicator.Tag.Phase; $Indicator.Invalidate() }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Indicator.Invalidate()
}

function Add-RpiScanlineOverlay {
    # Subtle 1px lines every 3px - scanline texture
    param([Parameter(Mandatory)]$Panel)
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

function Add-RpiGridPaperBackground {
    # 1px dots on a grid - subtle technical-paper texture
    param([Parameter(Mandatory)]$Panel, [int]$Spacing = 18)
    $dotColor = [System.Drawing.Color]::FromArgb(18, $theme.TextMuted.R, $theme.TextMuted.G, $theme.TextMuted.B)
    $Panel.Add_Paint({
        param($sender, $e)
        $brush = New-Object System.Drawing.SolidBrush($dotColor)
        try {
            $w = $sender.Width; $h = $sender.Height
            for ($x = $Spacing; $x -lt $w; $x += $Spacing) {
                for ($y = $Spacing; $y -lt $h; $y += $Spacing) {
                    $e.Graphics.FillRectangle($brush, $x, $y, 1, 1)
                }
            }
        } finally { $brush.Dispose() }
    }.GetNewClosure())
}

function Start-RpiButtonPulse {
    # Makes a button "blink" by alternating BackColor at ~900ms cadence.
    # Used for the primary CTA when all preconditions are met.
    param(
        [Parameter(Mandatory)]$Button,
        $ColorA = $null,
        $ColorB = $null,
        [int]$Interval = 900
    )
    if (-not $ColorA) { $ColorA = $theme.Accent1 }
    if (-not $ColorB) { $ColorB = $theme.Accent1Hover }
    if ($Button.Tag -and $Button.Tag.PulseTimer) {
        $Button.Tag.PulseTimer.Stop()
        $Button.Tag.PulseTimer.Dispose()
        $Button.Tag.PulseTimer = $null
    }
    $tag = @{ Phase = 0 }
    $Button.Tag = $tag
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $Interval
    $timer.Add_Tick({
        $tag.Phase = 1 - $tag.Phase
        $Button.BackColor = if ($tag.Phase -eq 0) { $ColorA } else { $ColorB }
    }.GetNewClosure())
    $timer.Start()
    $tag.PulseTimer = $timer
    $Button.BackColor = $ColorA
}

function Stop-RpiButtonPulse {
    param([Parameter(Mandatory)]$Button, $SolidColor = $null)
    if (-not $SolidColor) { $SolidColor = $theme.Accent1 }
    if ($Button.Tag -and $Button.Tag.PulseTimer) {
        $Button.Tag.PulseTimer.Stop()
        $Button.Tag.PulseTimer.Dispose()
        $Button.Tag.PulseTimer = $null
    }
    $Button.BackColor = $SolidColor
}
#endregion

#region === DOMAIN HELPERS ===
function Write-RpiLog {
    param([string]$Message)
    $ts = (Get-Date).ToString("HH:mm:ss")
    if ($script:outputBox) {
        $script:outputBox.AppendText("[$ts] $Message`r`n")
        $script:outputBox.SelectionStart = $script:outputBox.Text.Length
        $script:outputBox.ScrollToCaret()
    }
}

function Update-RpiPackageList {
    $comboPackage.Items.Clear()
    $global:PackageMap = @{}
    $root = $txtRoot.Text.Trim()
    if (-not (Test-Path $root)) {
        $lblResolved.Text = "PACKAGE ROOT NOT FOUND"
        $lblResolved.ForeColor = $theme.Danger
        Update-RpiStatusStrip
        Update-RpiReadyPulse
        return
    }
    try {
        $dirs = Get-ChildItem -Path $root -Directory -EA Stop | Sort-Object Name
        ## v2.5.0: surface folders that contain EITHER Deploy-Application.ps1
        ## OR one-or-more .msi files. Pure-MSI bundles (no PSADT wrapper) now
        ## show up in the combo so the operator can flip on chkMsiMode and
        ## fan them out without forcing a custom-folder browse.
        foreach ($d in $dirs) {
            $hasDeploy = $null -ne (Get-ChildItem -Path $d.FullName -Filter "Deploy-Application.ps1" -Recurse -EA SilentlyContinue | Select-Object -First 1)
            $hasMsi    = $null -ne (Get-ChildItem -Path $d.FullName -Filter "*.msi" -Recurse -Depth 1 -EA SilentlyContinue | Select-Object -First 1)
            if ($hasDeploy -or $hasMsi) {
                $global:PackageMap[$d.Name] = $d.FullName
                [void]$comboPackage.Items.Add($d.Name)
            }
        }
        if ($comboPackage.Items.Count -gt 0) {
            $comboPackage.SelectedIndex = 0
            $lblResolved.Text = "// $($global:PackageMap[$comboPackage.SelectedItem])"
            $lblResolved.ForeColor = $theme.Success
        } else {
            $lblResolved.Text = "NO PACKAGES (LOOKED FOR DEPLOY-APPLICATION.PS1 OR *.MSI)"
            $lblResolved.ForeColor = $theme.Warning
        }
        Write-RpiLog "Loaded $($comboPackage.Items.Count) packages from root (PSADT + MSI bundles)"
    } catch {
        Write-RpiLog "Failed to enumerate packages: $($_.Exception.Message)"
        $lblResolved.Text = "ERROR LOADING PACKAGES"
        $lblResolved.ForeColor = $theme.Danger
    }
    Update-RpiStatusStrip
    Update-RpiSidebarStats
    Update-RpiReadyPulse
}

function Get-RpiResolvedPackagePath {
    if ($chkCustom.Checked) { return $txtCustom.Text.Trim() }
    if ($comboPackage.SelectedItem) { return $global:PackageMap[$comboPackage.SelectedItem.ToString()] }
    return $null
}

#region === MSI BUNDLE MODE (v2.5.0) ===
## Three small helpers + one selection dialog. The "folder" is whatever
## Get-RpiResolvedPackagePath returns (combo subfolder OR custom folder) —
## MSI mode is a deploy-time interpretation layered on top, not a third
## source of truth. The selection lives on the hidden $script:clbMsi so
## Save-RpiConfig has a single thing to enumerate.

function Get-RpiResolvedMsiFolder {
    ## Returns the FOLDER backing MSI mode. Handles three shapes:
    ##   - directory path  -> the directory itself
    ##   - .msi file path  -> the file's parent directory (and stashes the leaf
    ##                        in $script:RpiSingleMsiFile so Update-RpiMsiList
    ##                        knows to show only that one item pre-checked)
    ##   - anything else / nonexistent -> $null
    ## v2.5.3: file-path handling fixes the case where the user pasted a
    ## direct UNC to a single .msi into the custom-folder textbox.
    $script:RpiSingleMsiFile = $null
    $p = $null
    try { $p = Get-RpiResolvedPackagePath } catch {}
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $item = $null
    try { $item = Get-Item -LiteralPath $p -ErrorAction Stop } catch { return $null }
    if ($item.PSIsContainer) { return $p }
    if ($item.Extension -ieq '.msi') {
        $script:RpiSingleMsiFile = $item.Name
        return $item.DirectoryName
    }
    return $null
}

function Get-RpiMsiInFolder {
    ## Recurse one level — most MSI bundles ship the .msi at root, but some
    ## have subfolders per arch (e.g. x64\foo.msi). Anything deeper is almost
    ## always vendor noise (Drivers\, etc.). PowerShell 5.1: -Depth IS available
    ## on Get-ChildItem here.
    param([string]$Folder)
    if ([string]::IsNullOrWhiteSpace($Folder) -or -not (Test-Path -LiteralPath $Folder)) {
        return @()
    }
    try {
        return @(Get-ChildItem -LiteralPath $Folder -Filter '*.msi' -File -Recurse -Depth 1 -ErrorAction Stop |
                 Sort-Object -Property FullName)
    } catch {
        return @()
    }
}

function Update-RpiMsiList {
    ## Rescans the currently-resolved folder, repopulates $script:clbMsi, and
    ## updates the summary label. Honors a $PreserveSelection that holds the
    ## set of filenames that should remain checked (intersected with what's
    ## actually present). If $PreserveSelection is null, all discovered MSIs
    ## are checked — that's the "auto-select" UX the user asked for.
    param([string[]]$PreserveSelection)

    $folder = Get-RpiResolvedMsiFolder
    $script:RpiMsiFolder = $folder
    $script:clbMsi.Items.Clear()

    if (-not $folder) {
        $script:lblMsiSummary.Text      = "// MSI mode: source folder not resolved"
        $script:lblMsiSummary.ForeColor = $theme.Warning
        return
    }

    ## v2.5.3: if the user pointed the custom path at a single .msi file,
    ## Get-RpiResolvedMsiFolder stashed the leaf into $script:RpiSingleMsiFile
    ## and returned the parent. Show ONLY that file (don't scan the parent for
    ## siblings) and pre-check it.
    if ($script:RpiSingleMsiFile) {
        $shouldCheck = $true
        if ($null -ne $PreserveSelection -and $PreserveSelection.Count -gt 0) {
            $shouldCheck = ($PreserveSelection -contains $script:RpiSingleMsiFile)
        }
        [void]$script:clbMsi.Items.Add($script:RpiSingleMsiFile, $shouldCheck)
        Update-RpiMsiSummary
        return
    }

    $msis = Get-RpiMsiInFolder -Folder $folder
    if ($msis.Count -eq 0) {
        $script:lblMsiSummary.Text      = "// MSI mode: no .msi files in $folder"
        $script:lblMsiSummary.ForeColor = $theme.Warning
        return
    }

    ## Filenames stored in clbMsi are RELATIVE to $folder so the per-host
    ## scriptblock can rebuild the path on the remote (C:\Temp\<bundle>_<stamp>\<rel>).
    ## Folder-recursive search means some entries may be subpath like "x64\foo.msi".
    $folderFull = (Resolve-Path -LiteralPath $folder).Path.TrimEnd('\') + '\'
    foreach ($m in $msis) {
        $rel = $m.FullName
        if ($rel.StartsWith($folderFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $rel.Substring($folderFull.Length)
        } else {
            $rel = $m.Name
        }
        $shouldCheck = $true
        if ($null -ne $PreserveSelection -and $PreserveSelection.Count -gt 0) {
            $shouldCheck = ($PreserveSelection -contains $rel)
        }
        [void]$script:clbMsi.Items.Add($rel, $shouldCheck)
    }

    Update-RpiMsiSummary
}

function Update-RpiMsiSummary {
    if (-not $script:lblMsiSummary) { return }
    if (-not $script:chkMsiMode -or -not $script:chkMsiMode.Checked) {
        $script:lblMsiSummary.Text      = "// MSI mode off"
        $script:lblMsiSummary.ForeColor = $theme.TextFaint
        return
    }
    $total = $script:clbMsi.Items.Count
    $sel   = $script:clbMsi.CheckedItems.Count
    $folder = $script:RpiMsiFolder
    if (-not $folder) {
        $script:lblMsiSummary.Text      = "// MSI mode: no folder resolved"
        $script:lblMsiSummary.ForeColor = $theme.Warning
        return
    }
    if ($total -eq 0) {
        $script:lblMsiSummary.Text      = "// MSI mode: no .msi files in $folder"
        $script:lblMsiSummary.ForeColor = $theme.Warning
        return
    }
    $colorFg = if ($sel -gt 0) { $theme.Success } else { $theme.Warning }
    $script:lblMsiSummary.Text      = "// MSI mode: $sel of $total selected in $folder"
    $script:lblMsiSummary.ForeColor = $colorFg
}

function Get-RpiResolvedMsiList {
    ## Returns the relative MSI filenames currently checked. Used by the
    ## deploy click and persistence layer.
    $list = New-Object System.Collections.Generic.List[string]
    if (-not $script:clbMsi) { return @() }
    for ($i = 0; $i -lt $script:clbMsi.Items.Count; $i++) {
        if ($script:clbMsi.GetItemChecked($i)) { $list.Add([string]$script:clbMsi.Items[$i]) }
    }
    return $list.ToArray()
}

function Show-RpiMsiPickerDialog {
    ## Modal selection dialog. Hosts a real (visible) CheckedListBox bound to
    ## the same items as the hidden $script:clbMsi; on OK, copies the new
    ## check state back into $script:clbMsi and refreshes the summary.
    if (-not $script:RpiMsiFolder) {
        [System.Windows.Forms.MessageBox]::Show(
            "Resolve a folder first (pick a package from the root combo, or browse to a custom folder), then check 'MSI bundle' and click Pick MSIs.",
            "MSI Folder Not Resolved", 'OK', 'Information') | Out-Null
        return
    }
    if ($script:clbMsi.Items.Count -eq 0) {
        ## Folder may have been populated with MSIs after the mode toggle —
        ## opportunistic rescan before bailing.
        Update-RpiMsiList
        if ($script:clbMsi.Items.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No .msi files found in:`n$($script:RpiMsiFolder)`n`nDrop the installers in that folder (or a one-level subfolder) and try again.",
                "No MSIs Found", 'OK', 'Warning') | Out-Null
            return
        }
    }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text             = "Select MSIs - $($script:RpiMsiFolder)"
    $dlg.StartPosition    = 'CenterParent'
    $dlg.ClientSize       = New-Object System.Drawing.Size(640, 460)
    $dlg.MinimumSize      = New-Object System.Drawing.Size(520, 360)
    $dlg.BackColor        = $theme.Background
    $dlg.ForeColor        = $theme.TextPrimary
    $dlg.Font             = $fonts.Body
    $dlg.MaximizeBox      = $false
    $dlg.FormBorderStyle  = 'Sizable'
    Enable-RpiDoubleBuffer -Control $dlg
    $dlg.Add_HandleCreated({ try { Set-RpiDarkTitleBar -Form $dlg } catch {} })

    $lbl = New-RpiLabel -Text "MSI FILES (RECURSIVE, DEPTH 1)" -X 14 -Y 12 -W 400 -H 16 -Font $fonts.Eyebrow -Fg $theme.Accent2
    $dlg.Controls.Add($lbl)

    $clbPick = New-Object System.Windows.Forms.CheckedListBox
    $clbPick.Location      = New-Object System.Drawing.Point(14, 34)
    $clbPick.Size          = New-Object System.Drawing.Size(612, 350)
    $clbPick.Anchor        = 'Top,Left,Right,Bottom'
    $clbPick.BackColor     = $theme.SurfaceAlt
    $clbPick.ForeColor     = $theme.TextPrimary
    $clbPick.Font          = $fonts.Mono
    $clbPick.BorderStyle   = 'FixedSingle'
    $clbPick.CheckOnClick  = $true
    $clbPick.IntegralHeight = $false
    for ($i = 0; $i -lt $script:clbMsi.Items.Count; $i++) {
        [void]$clbPick.Items.Add([string]$script:clbMsi.Items[$i], $script:clbMsi.GetItemChecked($i))
    }
    $dlg.Controls.Add($clbPick)

    $btnAll = New-RpiGhostButton -Text "Select All" -X 14 -Y 396 -W 110 -H 30 -Fg $theme.Accent2
    $btnAll.Anchor = 'Bottom,Left'
    $dlg.Controls.Add($btnAll)
    $btnAll.Add_Click({
        for ($i = 0; $i -lt $clbPick.Items.Count; $i++) { $clbPick.SetItemChecked($i, $true) }
    }.GetNewClosure())

    $btnNone = New-RpiGhostButton -Text "Select None" -X 132 -Y 396 -W 110 -H 30
    $btnNone.Anchor = 'Bottom,Left'
    $dlg.Controls.Add($btnNone)
    $btnNone.Add_Click({
        for ($i = 0; $i -lt $clbPick.Items.Count; $i++) { $clbPick.SetItemChecked($i, $false) }
    }.GetNewClosure())

    $btnOk = New-RpiGhostButton -Text "OK" -X 408 -Y 396 -W 100 -H 30 -Fg $theme.Success
    $btnOk.Anchor       = 'Bottom,Right'
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlg.Controls.Add($btnOk)
    $dlg.AcceptButton = $btnOk

    $btnCancel = New-RpiGhostButton -Text "Cancel" -X 516 -Y 396 -W 100 -H 30 -Fg $theme.Danger
    $btnCancel.Anchor       = 'Bottom,Right'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.Add($btnCancel)
    $dlg.CancelButton = $btnCancel

    if ($dlg.ShowDialog($f) -eq [System.Windows.Forms.DialogResult]::OK) {
        for ($i = 0; $i -lt $clbPick.Items.Count; $i++) {
            $script:clbMsi.SetItemChecked($i, $clbPick.GetItemChecked($i))
        }
        Update-RpiMsiSummary
        Update-RpiReadyPulse
    }
    try { $dlg.Dispose() } catch {}
}
#endregion

function Get-RpiComputerList {
    $computers = @()
    $raw = $txtManual.Text
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        Write-RpiLog "Raw target input: '$raw'"
        $lines = $raw.Split([string[]]@("`r`n","`n","`r"), [StringSplitOptions]::RemoveEmptyEntries)
        foreach ($line in $lines) {
            $parts = $line.Split(',', [StringSplitOptions]::RemoveEmptyEntries)
            foreach ($p in $parts) {
                $t = $p.Trim()
                if ($t -ne "") { $computers += $t }
            }
        }
    }
    ## v2.3.3: case-insensitive dedup. Sort-Object -Unique uses the default
    ## ordinal comparer, so "MSEKL-ABC" and "mseKL-abc" survive as two
    ## entries and we'd deploy to the same host twice. Use a HashSet with
    ## OrdinalIgnoreCase to collapse case variants to whichever spelling
    ## the operator typed first.
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $deduped = New-Object System.Collections.Generic.List[string]
    foreach ($c in $computers) {
        if ($seen.Add($c)) { $deduped.Add($c) }
    }
    $computers = @($deduped | Sort-Object)
    Write-RpiLog "Parsed $($computers.Count) target(s): $($computers -join ', ')"
    return $computers
}

function Update-RpiResultGrid {
    param([string]$Hostname, [string]$Status, [string]$Detail = "")
    $existing = $null
    foreach ($row in $gridResults.Rows) {
        if ($row.Cells["Host"].Value -eq $Hostname) { $existing = $row; break }
    }
    if ($existing) {
        $existing.Cells["Status"].Value = $Status.ToUpperInvariant()
        $existing.Cells["Detail"].Value = $Detail
        $existing.Cells["Time"].Value   = (Get-Date).ToString("HH:mm:ss")
    } else {
        $idx = $gridResults.Rows.Add($Hostname, $Status.ToUpperInvariant(), $Detail, (Get-Date).ToString("HH:mm:ss"))
        $existing = $gridResults.Rows[$idx]
    }
    switch ($Status) {
        "Success"   { $existing.DefaultCellStyle.ForeColor = $theme.Success }
        "Failed"    { $existing.DefaultCellStyle.ForeColor = $theme.Danger }
        "Deferred"  { $existing.DefaultCellStyle.ForeColor = $theme.Warning }
        "Deploying" { $existing.DefaultCellStyle.ForeColor = $theme.Warning }
        "Repairing" { $existing.DefaultCellStyle.ForeColor = $theme.Warning }    # v2.4.2 (DCOM repair in flight)
        "Copying"   { $existing.DefaultCellStyle.ForeColor = $theme.Info }
        "Probing"   { $existing.DefaultCellStyle.ForeColor = $theme.TextSecondary }   # v2.4.2
        "Queued"    { $existing.DefaultCellStyle.ForeColor = $theme.TextMuted }       # v2.4.2
        default     { $existing.DefaultCellStyle.ForeColor = $theme.TextSecondary }
    }
}

function Update-RpiStatusStrip {
    if (-not $script:lblStatTargets) { return }
    $tgts = @($txtManual.Text -split "[`r`n,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }).Count
    $pkgs = if ($comboPackage) { [int]$comboPackage.Items.Count } else { 0 }
    $script:lblStatTargets.Text = "Targets: $tgts"
    $script:lblStatPkgs.Text    = "Packages: $pkgs"
}

function Update-RpiSidebarStats {
    # Keeps the sidebar /SESSION block in sync with current tool state.
    if (-not $script:lblSideTgtCount) { return }
    $tgts = @($txtManual.Text -split "[`r`n,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }).Count
    $script:lblSideTgtCount.Text = "$tgts"
    $script:lblSideTgtCount.ForeColor = if ($tgts -gt 0) { $theme.TextPrimary } else { $theme.TextMuted }

    $pkgPath = $null
    try { $pkgPath = Get-RpiResolvedPackagePath } catch {}
    if ($pkgPath) {
        $leaf = Split-Path $pkgPath -Leaf
        if ($leaf.Length -gt 28) { $leaf = $leaf.Substring(0, 25) + "..." }
        $script:lblSidePkgName.Text      = $leaf
        $script:lblSidePkgName.ForeColor = $theme.TextPrimary
    } else {
        $script:lblSidePkgName.Text      = 'none'
        $script:lblSidePkgName.ForeColor = $theme.TextMuted
    }
}

function Update-RpiReadyPulse {
    # Pulse the Deploy button when all preconditions are met:
    # credentials loaded + at least one target + package resolved.
    # v2.5.0: in MSI mode, also require >=1 MSI checked. Otherwise the
    # operator clicks Deploy and gets a "no MSIs selected" modal — pulsing
    # while incomplete is dishonest.
    if (-not $script:btnRunInstall) { return }
    $hasCreds   = [bool]$global:Credentials
    $tgtCount   = @($txtManual.Text -split "[`r`n,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }).Count
    $hasTargets = $tgtCount -gt 0
    $pkgPath    = Get-RpiResolvedPackagePath
    $hasPkg     = $pkgPath -and (Test-Path $pkgPath -EA SilentlyContinue)
    $msiOk      = $true
    if ($script:chkMsiMode -and $script:chkMsiMode.Checked) {
        $msiOk = ($script:clbMsi -and $script:clbMsi.CheckedItems.Count -gt 0)
    }
    $ready      = $hasCreds -and $hasTargets -and $hasPkg -and $msiOk
    if ($ready) { Start-RpiButtonPulse -Button $script:btnRunInstall }
    else        { Stop-RpiButtonPulse  -Button $script:btnRunInstall }
}
#endregion

#region === MAIN FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text              = "J.A.N.E.T.  Remote Package Installer  v2.5.4"
$f.ClientSize        = New-Object System.Drawing.Size(1360, 800)
$f.MinimumSize       = New-Object System.Drawing.Size(1200, 720)
$f.AutoScaleMode     = [System.Windows.Forms.AutoScaleMode]::Dpi
$f.AutoScaleDimensions = New-Object System.Drawing.SizeF(96.0, 96.0)
$f.StartPosition     = "CenterScreen"
$f.BackColor         = $theme.Background
$f.ForeColor         = $theme.TextPrimary
$f.Font              = $fonts.Body
$f.FormBorderStyle   = 'Sizable'
Enable-RpiDoubleBuffer -Control $f
$f.Add_HandleCreated({ try { Set-RpiDarkTitleBar -Form $f } catch {} })
$f.Add_Load({ try { Set-RpiDarkTitleBar -Form $f } catch {} })

#endregion

#region === STATUS STRIP (bottom) ===
$statusBar = New-Object System.Windows.Forms.Panel
$statusBar.Dock      = 'Bottom'
$statusBar.Height    = 32
$statusBar.BackColor = $theme.StatusBar
Enable-RpiDoubleBuffer -Control $statusBar

$statusTopEdge = New-Object System.Windows.Forms.Panel
$statusTopEdge.Dock      = 'Top'
$statusTopEdge.Height    = 1
$statusTopEdge.BackColor = $theme.Border
$statusBar.Controls.Add($statusTopEdge)

Add-RpiScanlineOverlay -Panel $statusBar

# Leftmost heartbeat. If it stops blinking the UI thread is stuck.
$statusHeartbeat = New-RpiPulseIndicator -X 10 -Y 12 -Size 8 -State 'Active'
$statusBar.Controls.Add($statusHeartbeat)

$lblStatUser = New-RpiLabel -Text "  User: $env:USERNAME" -X 22 -Y 8 -W 240 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
$script:lblStatTargets = New-RpiLabel -Text "Targets: 0"  -X 272 -Y 8 -W 150 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
$script:lblStatPkgs    = New-RpiLabel -Text "Packages: 0" -X 432 -Y 8 -W 150 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted

## v2.4.2: deploy progress indicator. Empty until the first run starts;
## drain timer paints "Progress: 12 / 120 (10%) | Live: 8" each tick.
$script:lblStatProgress = New-RpiLabel -Text "" -X 592 -Y 8 -W 290 -H 18 -Font $fonts.MonoSm -Fg $theme.Accent1

# Initial form ClientWidth = 1360 -> statusBar Width = 1360. Log label anchored
# both sides to stretch. Right-anchored from (X=890) so right-distance = 20.
$lblStatLog = New-RpiLabel -Text ("Log: " + (Split-Path $global:PatcherLogPath -Leaf)) -X 890 -Y 8 -W 450 -H 18 -Font $fonts.MonoSm -Fg $theme.TextFaint
$lblStatLog.TextAlign = 'MiddleRight'
$lblStatLog.Anchor    = 'Top,Left,Right'

$statusBar.Controls.AddRange(@($lblStatUser, $script:lblStatTargets, $script:lblStatPkgs, $script:lblStatProgress, $lblStatLog))
$f.Controls.Add($statusBar)
#endregion

#region === SIDEBAR (left) ===
$sidebar = New-Object System.Windows.Forms.Panel
$sidebar.Dock      = 'Left'
$sidebar.Width     = 252
$sidebar.BackColor = $theme.Sidebar
Enable-RpiDoubleBuffer -Control $sidebar

$sidebarEdge = New-Object System.Windows.Forms.Panel
$sidebarEdge.Dock      = 'Right'
$sidebarEdge.Width     = 1
$sidebarEdge.BackColor = $theme.Border
$sidebar.Controls.Add($sidebarEdge)

# ---- Brand block ----
$brand = New-Object System.Windows.Forms.Panel
$brand.Location  = New-Object System.Drawing.Point(0, 20)
$brand.Size      = New-Object System.Drawing.Size(252, 100)
$brand.BackColor = $theme.Sidebar

$lblBrandMark = New-RpiLabel -Text 'J.A.N.E.T.' -X 22 -Y 14 -W 180 -H 28 -Font $fonts.DisplayLg -Fg $theme.Accent1
$lblBrandSub  = New-RpiLabel -Text 'Remote Pkg Installer' -X 22 -Y 48 -W 220 -H 16 -Font $fonts.Caption -Fg $theme.TextSecondary
$lblBrandVer  = New-RpiLabel -Text 'v2.5.4' -X 22 -Y 68 -W 220 -H 16 -Font $fonts.MonoTiny -Fg $theme.TextFaint

# Blinking brand heartbeat
$brandHeartbeat = New-RpiPulseIndicator -X 210 -Y 22 -Size 10 -State 'Active'
$brand.Controls.AddRange(@($lblBrandMark, $lblBrandSub, $lblBrandVer, $brandHeartbeat))

$brandSep = New-RpiSeparator -X 20 -Y 128 -W 212 -Color $theme.Border

# ---- Session stats block ----
# Live summary of what the tool currently has loaded.
$infoHost = New-Object System.Windows.Forms.Panel
$infoHost.Location  = New-Object System.Drawing.Point(0, 144)
$infoHost.Size      = New-Object System.Drawing.Size(252, 440)
$infoHost.BackColor = $theme.Sidebar
$infoHost.Anchor    = 'Top,Left,Bottom'

$lblSessHdr = New-RpiLabel -Text '/ SESSION' -X 22 -Y 4 -W 200 -H 16 -Font $fonts.Eyebrow -Fg $theme.TextMuted
$infoHost.Controls.Add($lblSessHdr)

$lblTgtLabel   = New-RpiLabel -Text 'Targets loaded'  -X 22 -Y 30 -W 180 -H 16 -Font $fonts.Caption  -Fg $theme.TextMuted
$script:lblSideTgtCount = New-RpiLabel -Text '0' -X 22 -Y 48 -W 180 -H 22 -Font $fonts.DisplayMd -Fg $theme.TextPrimary
$infoHost.Controls.AddRange(@($lblTgtLabel, $script:lblSideTgtCount))

$lblPkgLabel   = New-RpiLabel -Text 'Package'        -X 22 -Y 82 -W 180 -H 16 -Font $fonts.Caption  -Fg $theme.TextMuted
$script:lblSidePkgName = New-RpiLabel -Text 'none' -X 22 -Y 100 -W 210 -H 18 -Font $fonts.Mono -Fg $theme.TextSecondary
$infoHost.Controls.AddRange(@($lblPkgLabel, $script:lblSidePkgName))

$lblRunLabel   = New-RpiLabel -Text 'Last run'       -X 22 -Y 130 -W 180 -H 16 -Font $fonts.Caption -Fg $theme.TextMuted
$script:lblSideLastRun = New-RpiLabel -Text '--' -X 22 -Y 148 -W 210 -H 16 -Font $fonts.MonoSm -Fg $theme.TextFaint
$infoHost.Controls.AddRange(@($lblRunLabel, $script:lblSideLastRun))

$lblStatsLabel = New-RpiLabel -Text 'Success / Failed' -X 22 -Y 180 -W 200 -H 16 -Font $fonts.Caption -Fg $theme.TextMuted
$script:lblSideSuccess = New-RpiLabel -Text '0'  -X 22 -Y 198 -W 70 -H 22 -Font $fonts.DisplayMd -Fg $theme.Success
$script:lblSideSep     = New-RpiLabel -Text '/'  -X 94 -Y 198 -W 14 -H 22 -Font $fonts.DisplayMd -Fg $theme.TextFaint
$script:lblSideFailed  = New-RpiLabel -Text '0'  -X 110 -Y 198 -W 70 -H 22 -Font $fonts.DisplayMd -Fg $theme.Danger
$infoHost.Controls.AddRange(@($lblStatsLabel, $script:lblSideSuccess, $script:lblSideSep, $script:lblSideFailed))

# ---- User / session block at bottom ----
# Height dropped from 140 to 92 — the bottom Close Tool button moved to
# $closeHost (top-right) so the block no longer needs to reserve room.
$userBlock = New-Object System.Windows.Forms.Panel
$userBlock.Location  = New-Object System.Drawing.Point(0, ($sidebar.ClientSize.Height - 92))
$userBlock.Size      = New-Object System.Drawing.Size(252, 92)
$userBlock.BackColor = $theme.Sidebar
$userBlock.Anchor    = 'Bottom,Left,Right'

$userSep = New-RpiSeparator -X 20 -Y 0 -W 212 -Color $theme.Border
$userBlock.Controls.Add($userSep)

$lblUser = New-RpiLabel -Text "User: $env:USERNAME" -X 22 -Y 16 -W 212 -H 16 -Font $fonts.MonoSm -Fg $theme.TextPrimary
$lblCredTag = New-RpiLabel -Text 'Creds:' -X 22 -Y 40 -W 54 -H 16 -Font $fonts.MonoSm -Fg $theme.TextMuted
$pulseCred = New-RpiPulseIndicator -X 78 -Y 44 -Size 8 -State 'Idle'
$lblCred = New-RpiLabel -Text 'none' -X 92 -Y 40 -W 140 -H 16 -Font $fonts.MonoSm -Fg $theme.TextMuted
$lblHost = New-RpiLabel -Text "Host: $env:COMPUTERNAME" -X 22 -Y 64 -W 212 -H 16 -Font $fonts.MonoTiny -Fg $theme.TextFaint

## Sidebar Close Tool removed: the docked-Right $btnClose in $closeHost
## (top of $contentTop) is the single egress. Keeps WPT's one-button rule.

$userBlock.Controls.AddRange(@($lblUser, $lblCredTag, $pulseCred, $lblCred, $lblHost))

$sidebar.Controls.AddRange(@($brand, $brandSep, $infoHost, $userBlock))
#endregion

#region === CONTENT HOST (center/right) ===
$contentHost = New-Object System.Windows.Forms.Panel
$contentHost.Dock      = 'Fill'
$contentHost.BackColor = $theme.Background
Enable-RpiDoubleBuffer -Control $contentHost

# Top strip - blinking "live" indicator in a docked-Right sub-panel so positioning
# doesn't depend on a Resize handler firing at the right time.
$contentTop = New-Object System.Windows.Forms.Panel
$contentTop.Dock      = 'Top'
$contentTop.Height    = 36
$contentTop.BackColor = $theme.Background

# live indicator (rightmost) + close button (just left of it). Docked Right
# panels stack from outside in; liveHost is added last so it ends up at the
# outermost (true right) edge with closeHost to its left.
$liveHost = New-Object System.Windows.Forms.Panel
$liveHost.Dock      = 'Right'
$liveHost.Width     = 80
$liveHost.BackColor = $theme.Background
$contentHeartbeat = New-RpiPulseIndicator -X 8 -Y 14 -Size 10 -State 'Active'
$lblLive = New-RpiLabel -Text 'live' -X 26 -Y 12 -W 48 -H 16 -Font $fonts.MonoTiny -Fg $theme.TextFaint
$liveHost.Controls.AddRange(@($contentHeartbeat, $lblLive))

# Close button - styled X glyph that matches the dark theme. Provided in
# addition to the OS title-bar close so operators have a clear, on-canvas
# way to exit. Click closes the form, which runs the FormClosing handler
# (timer cleanup + audit log).
$closeHost = New-Object System.Windows.Forms.Panel
$closeHost.Dock      = 'Right'
$closeHost.Width     = 130
$closeHost.BackColor = $theme.Background
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text      = 'CLOSE TOOL'
$btnClose.Font      = $fonts.DisplaySm
$btnClose.Location  = New-Object System.Drawing.Point(6, 4)
$btnClose.Size      = New-Object System.Drawing.Size(118, 28)
$btnClose.FlatStyle = 'Flat'
$btnClose.FlatAppearance.BorderSize = 1
$btnClose.FlatAppearance.BorderColor = $theme.BorderStrong
$btnClose.BackColor = $theme.Background
$btnClose.ForeColor = $theme.TextSecondary
$btnClose.Cursor    = [System.Windows.Forms.Cursors]::Hand
$btnClose.UseVisualStyleBackColor = $false
$btnClose.FlatAppearance.MouseOverBackColor = $theme.Danger
$btnClose.FlatAppearance.MouseDownBackColor = $theme.DangerHover
$btnClose.TabStop   = $false
$btnClose.Add_MouseEnter({ $args[0].ForeColor = [System.Drawing.Color]::White }.GetNewClosure())
$btnClose.Add_MouseLeave({ $args[0].ForeColor = $theme.TextSecondary }.GetNewClosure())
# FormClosing handler is gated on Get-JanetAllowClose (line 2891). Without
# flipping the flag first, the close gets cancelled and the form stays open.
# Match the pattern used by the sidebar Close Tool button (line 1685).
$btnClose.Add_Click({
    Set-JanetAllowClose $true
    $f.Close()
}.GetNewClosure())
$closeHost.Controls.Add($btnClose)

# Order matters: closeHost docked first => ends up LEFT of liveHost.
$contentTop.Controls.Add($closeHost)
$contentTop.Controls.Add($liveHost)

# Accent rule (2px) + divider (1px) under the top strip
$contentAccentRule = New-Object System.Windows.Forms.Panel
$contentAccentRule.Dock      = 'Top'
$contentAccentRule.Height    = 2
$contentAccentRule.BackColor = $theme.Accent1Muted

$contentDivider = New-Object System.Windows.Forms.Panel
$contentDivider.Dock      = 'Top'
$contentDivider.Height    = 1
$contentDivider.BackColor = $theme.Border

# Body (grid-paper background). No Padding, no AutoScroll - those confuse the
# anchor engine when combined with absolute-positioned children, which was
# hiding the log card and letting cards bleed toward the right edge.
$contentBody = New-Object System.Windows.Forms.Panel
$contentBody.Dock      = 'Fill'
$contentBody.BackColor = $theme.Background
# Pre-size to expected runtime dimensions BEFORE adding children. Without this,
# the panel sits at the default 200x100 while children are added, so each
# Anchor=Top,Left,Right child stores a right-distance of (200 - X - W) — a
# large negative number. When contentBody later docks Fill and resizes to
# ~1108w, every child grows to ~1988w and any right-anchored button inside
# them gets pushed off-screen.
$contentBody.Size      = New-Object System.Drawing.Size(1108, 729)
Enable-RpiDoubleBuffer -Control $contentBody
Add-RpiGridPaperBackground -Panel $contentBody -Spacing 18

# contentBody width at default = Form.Client(1360) - sidebar(252) = 1108.
# Cards sit at X=14 with symmetric 14px right margin => W = 1080.
# contentBody height = Form.Client(800) - statusBar(32) - top(36) - rule(2) - div(1) = 729
$cardW = 1080
$cardX = 14

$cardTargets = New-RpiCard -Header "Target Workstations" -X $cardX -Y 10 -W $cardW -H 130 -Fg $theme.Accent1
$cardTargets.Anchor = 'Top,Left,Right'
$contentBody.Controls.Add($cardTargets)

$lblTgtCap = New-RpiLabel -Text "ENTER HOSTNAMES - ONE PER LINE OR COMMA-SEPARATED" -X 18 -Y 40 -W 700 -H 14 -Font $fonts.MonoTiny -Fg $theme.TextMuted
$cardTargets.Controls.Add($lblTgtCap)

$txtManual = New-RpiTextBox -X 18 -Y 56 -W ($cardW - 150) -H 60 -Multi
$txtManual.Anchor = 'Top,Left,Right'
$cardTargets.Controls.Add($txtManual)

$btnBrowseComp = New-RpiGhostButton -Text "Import" -X ($cardW - 124) -Y 56 -W 106 -H 28 -Fg $theme.Accent1
$btnBrowseComp.Anchor = 'Top,Right'
$cardTargets.Controls.Add($btnBrowseComp)

$btnClearTgts = New-RpiGhostButton -Text "Clear" -X ($cardW - 124) -Y 88 -W 106 -H 28
$btnClearTgts.Anchor = 'Top,Right'
$cardTargets.Controls.Add($btnClearTgts)

# Package card - gold accent
# v2.5.0: H 160 -> 220 to add the MSI bundle row (chkMsiMode + msi args +
# Pick MSIs button). Downstream pnlActions / cardGrid Y values shifted +60
# to match. cardLog is anchored Bottom so it stays glued to the form edge.
$cardPkg = New-RpiCard -Header "Package Source" -X $cardX -Y 150 -W $cardW -H 220 -Fg $theme.Accent2
$cardPkg.Anchor = 'Top,Left,Right'
$contentBody.Controls.Add($cardPkg)

# v2.5.4: ROOT row redone. SCAN now lives LEFT of the textbox (anchored
# Top,Left so it stays put), with the textbox stretching to its right.
# Previous layout had SCAN/RESCAN/SAVE all anchored right of a stretched
# textbox, and the textbox's BackColor visually overlapped the buttons
# even though the X math left an 8px gap — user feedback: "There is a
# button hidden behind the root thing". Pulling SCAN to the left eliminates
# the conflict entirely.
$lblRoot = New-RpiLabel -Text "ROOT" -X 18 -Y 46 -W 50 -H 22 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$cardPkg.Controls.Add($lblRoot)

$btnBrowseRoot = New-RpiButton -Text "SCAN" -X 70 -Y 42 -W 110 -H 30 -Bg $theme.Accent1 -Fg $theme.TextOnAccent
$btnBrowseRoot.Anchor = 'Top,Left'
$cardPkg.Controls.Add($btnBrowseRoot)

# Textbox starts after SCAN and stretches to leave clear room for RESCAN +
# SAVE on the right. Right offset = 244 (RESCAN 234 width offset + 10 gap).
$txtRoot = New-RpiTextBox -X 190 -Y 44 -W ($cardW - 434) -H 26
$txtRoot.Text   = $DefaultPackageRoot
$txtRoot.Anchor = 'Top,Left,Right'
$cardPkg.Controls.Add($txtRoot)

$btnRefresh = New-RpiGhostButton -Text "Rescan" -X ($cardW - 234) -Y 42 -W 100 -H 30 -Fg $theme.Accent1
$btnRefresh.Anchor = 'Top,Right'
$cardPkg.Controls.Add($btnRefresh)

# Save button - persists current package-source preferences (root path + custom toggle + custom path)
# to RemotePackageInstaller.config.json so they're restored on next launch.
$btnSaveDefault = New-RpiGhostButton -Text "Save" -X ($cardW - 124) -Y 42 -W 100 -H 30 -Fg $theme.Accent2
$btnSaveDefault.Anchor = 'Top,Right'
$cardPkg.Controls.Add($btnSaveDefault)

$chkCustom = New-RpiCheckBox -Text "Use custom package folder" -X 18 -Y 78 -W 220 -H 24
$cardPkg.Controls.Add($chkCustom)

$txtCustom = New-RpiTextBox -X 240 -Y 80 -W ($cardW - 380) -H 26
$txtCustom.Enabled = $false
$txtCustom.Visible = $false   # hide when chkCustom is off (matches Browse btn)
$txtCustom.Anchor  = 'Top,Left,Right'
$cardPkg.Controls.Add($txtCustom)

$btnBrowseCustom = New-RpiGhostButton -Text "Browse" -X ($cardW - 134) -Y 78 -W 116 -H 30
$btnBrowseCustom.Enabled = $false
$btnBrowseCustom.Visible = $false   # hide entirely when chkCustom is off (no ghost rectangle)
$btnBrowseCustom.Anchor  = 'Top,Right'
$cardPkg.Controls.Add($btnBrowseCustom)

$lblPkg = New-RpiLabel -Text "PKG" -X 18 -Y 118 -W 50 -H 22 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$cardPkg.Controls.Add($lblPkg)

$comboPackage = New-RpiComboBox -X 70 -Y 116 -W 460 -H 26
$cardPkg.Controls.Add($comboPackage)

$lblResolved = New-RpiLabel -Text "// no package resolved" -X 542 -Y 120 -W ($cardW - 560) -H 18 -Font $fonts.MonoSm -Fg $theme.TextFaint
$lblResolved.Anchor = 'Top,Left,Right'
$cardPkg.Controls.Add($lblResolved)

## v2.5.0: MSI BUNDLE ROW.
## chkMsiMode flips the deploy flow into "treat the resolved folder as a bag
## of .msi files and install each one via msiexec on the target". Independent
## of chkCustom — works against both the combo-picked subfolder of the root
## AND the custom folder. When on, an in-form CheckedListBox of discovered
## MSIs replaces the visual emphasis of the combo (combo stays usable for
## changing folders); a 'Pick MSIs' button pops a modal selection dialog with
## Select All / None. msi-args defaults to "/qn /norestart".
$script:chkMsiMode = New-RpiCheckBox -Text "MSI bundle (auto-install all .msi)" -X 18 -Y 158 -W 280 -H 24 -Fg $theme.Accent2
$cardPkg.Controls.Add($script:chkMsiMode)

$lblMsiArgs = New-RpiLabel -Text "MSI ARGS" -X 310 -Y 162 -W 70 -H 18 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$cardPkg.Controls.Add($lblMsiArgs)

$script:txtMsiArgs = New-RpiTextBox -X 384 -Y 158 -W ($cardW - 530) -H 26
$script:txtMsiArgs.Text   = '/qn /norestart'
$script:txtMsiArgs.Anchor = 'Top,Left,Right'
$cardPkg.Controls.Add($script:txtMsiArgs)

$script:btnPickMsi = New-RpiGhostButton -Text "Pick MSIs" -X ($cardW - 140) -Y 156 -W 122 -H 30 -Fg $theme.Accent2
$script:btnPickMsi.Anchor = 'Top,Right'
$cardPkg.Controls.Add($script:btnPickMsi)

$script:lblMsiSummary = New-RpiLabel -Text "// MSI mode off" -X 18 -Y 188 -W ($cardW - 36) -H 18 -Font $fonts.MonoSm -Fg $theme.TextFaint
$script:lblMsiSummary.Anchor = 'Top,Left,Right'
$cardPkg.Controls.Add($script:lblMsiSummary)

## Backing store for the operator's MSI selection. Populated by the Pick MSIs
## dialog and by the auto-select-all behavior when chkMsiMode flips on. Keys
## are msi filenames (Leaf only) relative to whatever folder is currently
## resolved. Hidden CheckedListBox (script-scope) is what Save-RpiConfig reads.
$script:RpiMsiFolder = $null   # absolute path of the folder we last enumerated
$script:clbMsi       = New-Object System.Windows.Forms.CheckedListBox
$script:clbMsi.Visible = $false   # never shown; lives off-screen as the canonical selection store
$cardPkg.Controls.Add($script:clbMsi)

# Action bar
# v2.5.0: Y shifted 320 -> 380 (+60) to make room for the MSI bundle row.
$pnlActions = New-Object System.Windows.Forms.Panel
$pnlActions.Location  = New-Object System.Drawing.Point($cardX, 380)
$pnlActions.Size      = New-Object System.Drawing.Size($cardW, 52)
$pnlActions.BackColor = $theme.Background
$pnlActions.Anchor    = 'Top,Left,Right'
$contentBody.Controls.Add($pnlActions)

$btnSetCred = New-RpiGhostButton -Text "Set Credentials" -X 0 -Y 10 -W 160 -H 32 -Fg $theme.Accent1
$pnlActions.Controls.Add($btnSetCred)

## v2.4.2: cred status width trimmed from 360 -> 220 to make room for
## the parallel concurrency selector (PARALLEL: [N]) before the
## right-anchored button cluster.
$lblCredStatus = New-RpiLabel -Text "// no credentials loaded" -X 170 -Y 16 -W 220 -H 20 -Font $fonts.MonoSm -Fg $theme.Warning
$pnlActions.Controls.Add($lblCredStatus)

## v2.4.2: parallel concurrency selector. Defaults to 8 (the historical
## hardcode). Range 1-32 — 32 is the practical ceiling, beyond which
## SMB / WinRM negotiation contention on a 10G AFNET fleet starts to
## cause more retries than the extra parallelism saves.
$lblParallel = New-RpiLabel -Text "PARALLEL" -X 410 -Y 14 -W 80 -H 20 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$pnlActions.Controls.Add($lblParallel)

$script:numParallel = New-Object System.Windows.Forms.NumericUpDown
$script:numParallel.Location  = New-Object System.Drawing.Point(490, 12)
$script:numParallel.Size      = New-Object System.Drawing.Size(60, 24)
$script:numParallel.Minimum   = 1
$script:numParallel.Maximum   = 32
$script:numParallel.Value     = 8
$script:numParallel.BackColor = $theme.Surface
$script:numParallel.ForeColor = $theme.TextPrimary
$script:numParallel.Font      = $fonts.Body
$script:numParallel.TextAlign = 'Center'
$pnlActions.Controls.Add($script:numParallel)

# Right-cluster of buttons. Positioned explicitly from cardW so the anchor
# engine only has to track deltas on resize - no Add_Layout closure needed.
# btnRunInstall    at X = cardW-240         = 840 (W=240)
# btnRetryFailed   at X = 840-10-130        = 700 (W=130)
# btnExportResults at X = 700-8-110         = 582 (W=110)
$btnExportResults = New-RpiGhostButton -Text "Export" -X 582 -Y 10 -W 110 -H 32
$btnExportResults.Anchor = 'Top,Right'
$pnlActions.Controls.Add($btnExportResults)

$btnRetryFailed = New-RpiGhostButton -Text "Retry Failed" -X 700 -Y 10 -W 130 -H 32 -Fg $theme.Warning
$btnRetryFailed.Anchor = 'Top,Right'
$pnlActions.Controls.Add($btnRetryFailed)

$script:btnRunInstall = New-RpiStripeButton -Text "Deploy" -X 840 -Y 4 -W 240 -H 44
$script:btnRunInstall.Anchor = 'Top,Right'
$pnlActions.Controls.Add($script:btnRunInstall)

# Results grid card (purple accent). Anchor Top,Left,Right only - card keeps
# its initial height regardless of body resize, so it won't swallow the log
# card below.
# v2.5.0: Y shifted 382 -> 442 (+60) and H 220 -> 160 to make room for the
# taller Package Source card and keep the log card's bottom anchor happy.
# 160px still fits the column headers + ~5 rows comfortably; the Pop Out
# button is for operators who want to see more.
$cardGrid = New-RpiCard -Header "Deployment Results" -X $cardX -Y 442 -W $cardW -H 160 -Fg $theme.Accent1
$cardGrid.Anchor = 'Top,Left,Right'
$contentBody.Controls.Add($cardGrid)

# Pop Out button - reparents the grid into a floating Form so operators can
# watch the run while resizing/moving freely. Pattern matches the ACAS
# Nemesis Updater 'Pop Out Log' button: single grid instance, reparented in
# place, restored on close. Re-clicking while popped out brings it forward.
# Filled gold style so it's actually visible against the dark card surface.
# Sits at Y=6 (well above the dotted underline at Y=34) with H=24 - tall
# enough for crisp text rendering. Anchored Top,Right so it tracks the card.
$btnGridPopOut = New-RpiButton -Text 'Pop Out' -X ($cardW - 124) -Y 6 -W 100 -H 24 -Bg $theme.Accent2 -Fg $theme.TextOnAccent -Font $fonts.DisplaySm
$btnGridPopOut.Anchor = 'Top,Right'
$cardGrid.Controls.Add($btnGridPopOut)
$btnGridPopOut.BringToFront()

$gridResults = New-Object System.Windows.Forms.DataGridView
$gridResults.Location  = New-Object System.Drawing.Point(14, 46)
# v2.5.0: H 160 -> 100 to fit inside the shorter Deployment Results card
# (cardGrid H 220 -> 160). Pop Out floats it in a sizable child form for
# operators who want a larger view of an in-flight run.
$gridResults.Size      = New-Object System.Drawing.Size(($cardW - 28), 100)
# Card height is fixed, so grid fills the card horizontally only.
$gridResults.Anchor    = 'Top,Left,Right'
$gridResults.BackgroundColor = $theme.GridBg
$gridResults.GridColor = $theme.GridLine
$gridResults.BorderStyle = 'None'
$gridResults.CellBorderStyle = 'SingleHorizontal'
$gridResults.EnableHeadersVisualStyles = $false
$gridResults.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHeader
$gridResults.ColumnHeadersDefaultCellStyle.ForeColor = $theme.Accent1
$gridResults.ColumnHeadersDefaultCellStyle.Font      = $fonts.Eyebrow
$gridResults.ColumnHeadersHeight = 28
$gridResults.RowTemplate.Height  = 24
$gridResults.DefaultCellStyle.BackColor          = $theme.GridBg
$gridResults.DefaultCellStyle.ForeColor          = $theme.TextPrimary
$gridResults.DefaultCellStyle.SelectionBackColor = $theme.GridSelection
$gridResults.DefaultCellStyle.SelectionForeColor = $theme.TextPrimary
$gridResults.DefaultCellStyle.Font               = $fonts.Mono
$gridResults.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAlt
$gridResults.RowHeadersVisible     = $false
$gridResults.AllowUserToAddRows    = $false
$gridResults.AllowUserToDeleteRows = $false
$gridResults.AllowUserToResizeRows = $false
$gridResults.ReadOnly              = $true
$gridResults.SelectionMode         = 'FullRowSelect'
$gridResults.MultiSelect           = $false
Enable-RpiDoubleBuffer -Control $gridResults
foreach ($col in @(
    @{N='Host';   W=200},
    @{N='Status'; W=110},
    @{N='Detail'; W=600},
    @{N='Time';   W=110}
)) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.Name = $col.N
    $c.HeaderText = $col.N.ToUpperInvariant()
    $c.Width = $col.W
    [void]$gridResults.Columns.Add($c)
}
$cardGrid.Controls.Add($gridResults)

# Pop-Out behaviour: reparent the SAME gridResults instance into a floating
# Form. All Update-RpiResultGrid call sites already operate on $gridResults
# directly, so the live deploy keeps streaming into the popped-out grid
# without any code-path changes. On close, the grid is restored into the
# original card. Tracked at $script:RpiGridPopOutForm so re-clicking while
# popped out brings the existing window forward instead of double-popping.
$script:RpiGridPopOutForm = $null
$script:RpiGridOrigParent = $cardGrid
$script:RpiGridOrigLoc    = $gridResults.Location
$script:RpiGridOrigSize   = $gridResults.Size
$script:RpiGridOrigAnchor = $gridResults.Anchor

$btnGridPopOut.Add_Click({
    # Toggle: if the popout exists, this click is "Bring Back" -> close the
    # popout, which fires its FormClosing handler and reparents the grid
    # back into the card. If no popout exists, this click is "Pop Out" ->
    # create a new floating Form and lift the grid into it.
    if ($script:RpiGridPopOutForm) {
        try { $script:RpiGridPopOutForm.Close() } catch {}
        return
    }

    $popForm = New-Object System.Windows.Forms.Form
    $popForm.Text          = 'JANET - Deployment Results'
    $popForm.Size          = New-Object System.Drawing.Size(1200, 640)
    $popForm.StartPosition = 'CenterParent'
    $popForm.BackColor     = $theme.Background
    $popForm.ForeColor     = $theme.TextPrimary
    $popForm.Font          = $fonts.Body
    $popForm.MinimumSize   = New-Object System.Drawing.Size(700, 400)
    $popForm.ShowInTaskbar = $true
    Enable-RpiDoubleBuffer -Control $popForm
    $popForm.Add_HandleCreated({ try { Set-RpiDarkTitleBar -Form $popForm } catch {} }.GetNewClosure())
    $popForm.Add_Load({         try { Set-RpiDarkTitleBar -Form $popForm } catch {} }.GetNewClosure())

    $popPanel = New-Object System.Windows.Forms.Panel
    $popPanel.Dock      = 'Fill'
    $popPanel.BackColor = $theme.Surface
    $popPanel.Padding   = New-Object System.Windows.Forms.Padding(10, 10, 10, 10)
    $popForm.Controls.Add($popPanel)

    # Lift the SAME control out of the card and dock it inside the popout.
    $script:RpiGridOrigParent.Controls.Remove($gridResults)
    $gridResults.Dock     = 'Fill'
    $gridResults.Anchor   = [System.Windows.Forms.AnchorStyles]::None
    $gridResults.Location = New-Object System.Drawing.Point(0, 0)
    $popPanel.Controls.Add($gridResults)

    $btnGridPopOut.Text      = 'Bring Back'
    $btnGridPopOut.BackColor = $theme.Warning
    $btnGridPopOut.ForeColor = $theme.TextOnAccent

    $popForm.Add_FormClosing({
        param($sender, $e)
        try {
            if ($gridResults -and $gridResults.Parent) {
                $gridResults.Parent.Controls.Remove($gridResults)
            }
            $gridResults.Dock     = 'None'
            $gridResults.Location = $script:RpiGridOrigLoc
            $gridResults.Size     = $script:RpiGridOrigSize
            $gridResults.Anchor   = $script:RpiGridOrigAnchor
            $script:RpiGridOrigParent.Controls.Add($gridResults)
        } catch {}
        $script:RpiGridPopOutForm = $null
        $btnGridPopOut.Text      = 'Pop Out'
        $btnGridPopOut.BackColor = $theme.Accent2
        $btnGridPopOut.ForeColor = $theme.TextOnAccent
    }.GetNewClosure())

    $script:RpiGridPopOutForm = $popForm
    $popForm.Show($f)
}.GetNewClosure())

## v2.4.3: double-click any row to drill into the host's full deploy
## detail (output, exit code, repair info, timing). Header double-clicks
## land on RowIndex=-1 — ignore those.
$gridResults.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    $row = $gridResults.Rows[$e.RowIndex]
    $hostCell = $row.Cells['Host'].Value
    if ([string]::IsNullOrWhiteSpace([string]$hostCell)) { return }
    Show-RpiHostDetail -Hostname ([string]$hostCell)
})

# Execution log card
$cardLog = New-RpiCard -Header "Execution Log" -X $cardX -Y 612 -W $cardW -H 100 -Fg $theme.Accent2
$cardLog.Anchor = 'Left,Right,Bottom'
$contentBody.Controls.Add($cardLog)

$script:outputBox = New-Object System.Windows.Forms.RichTextBox
$script:outputBox.Location    = New-Object System.Drawing.Point(14, 46)
$script:outputBox.Size        = New-Object System.Drawing.Size(($cardW - 28), 46)
$script:outputBox.Anchor      = 'Top,Left,Right,Bottom'
$script:outputBox.ReadOnly    = $true
$script:outputBox.BackColor   = $theme.ConsoleBg
$script:outputBox.ForeColor   = $theme.ConsoleFg
$script:outputBox.Font        = $fonts.Mono
$script:outputBox.BorderStyle = 'None'
$script:outputBox.WordWrap    = $false
$script:outputBox.ScrollBars  = 'Vertical'
$cardLog.Controls.Add($script:outputBox)

# Assemble content host (dock order: fill last)
$contentHost.Controls.Add($contentBody)
$contentHost.Controls.Add($contentDivider)
$contentHost.Controls.Add($contentAccentRule)
$contentHost.Controls.Add($contentTop)

# Assemble form (bottom+left first, fill last)
$f.Controls.Add($contentHost)
$f.Controls.Add($sidebar)
$f.Controls.Add($statusBar)
#endregion

#region === EVENT HANDLERS ===
$openFile = New-Object System.Windows.Forms.OpenFileDialog
$openFile.Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
$btnBrowseComp.Add_Click({
    if ($openFile.ShowDialog() -eq "OK") {
        try {
            $lines = Get-Content $openFile.FileName -EA Stop |
                Where-Object { $_.Trim() -ne "" } |
                ForEach-Object { ($_ -split "[,;]")[0].Trim() } |
                Where-Object { $_ -ne "" }
            $lines = @($lines)
            if ($lines.Count -gt 0) {
                $existing = $txtManual.Text.Trim()
                $newText = ($lines -join ", ")
                if ($existing) { $txtManual.Text = "$existing, $newText" }
                else { $txtManual.Text = $newText }
                Write-RpiLog "Imported $($lines.Count) computer(s) from $(Split-Path $openFile.FileName -Leaf)"
                Update-RpiStatusStrip
                Update-RpiReadyPulse
            } else {
                Write-RpiLog "File contained no valid hostnames"
            }
        } catch {
            Write-RpiLog "Failed to read file: $($_.Exception.Message)"
        }
    }
})

$btnClearTgts.Add_Click({
    $txtManual.Clear()
    Update-RpiStatusStrip
    Update-RpiSidebarStats
    Update-RpiReadyPulse
    Write-RpiLog "Cleared target list"
})
$txtManual.Add_TextChanged({ Update-RpiStatusStrip; Update-RpiSidebarStats; Update-RpiReadyPulse })

$folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
$btnBrowseCustom.Add_Click({
    if ($folderDialog.ShowDialog() -eq "OK") {
        $txtCustom.Text = $folderDialog.SelectedPath
        $lblResolved.Text = "// $($txtCustom.Text)"
        $lblResolved.ForeColor = $theme.Success
        ## v2.5.0: custom folder just changed -> rescan if MSI mode is on.
        if ($script:chkMsiMode -and $script:chkMsiMode.Checked) { Update-RpiMsiList }
        Update-RpiReadyPulse
    }
})
$txtCustom.Add_TextChanged({
    if ($script:chkMsiMode -and $script:chkMsiMode.Checked) { Update-RpiMsiList }
    Update-RpiReadyPulse
})

$chkCustom.Add_CheckedChanged({
    $txtCustom.Enabled       = $chkCustom.Checked
    $btnBrowseCustom.Enabled = $chkCustom.Checked
    # Hide entirely when off so the disabled outline doesn't ghost on the card.
    $txtCustom.Visible       = $chkCustom.Checked
    $btnBrowseCustom.Visible = $chkCustom.Checked
    $comboPackage.Enabled    = -not $chkCustom.Checked
    $txtRoot.Enabled         = -not $chkCustom.Checked
    $btnRefresh.Enabled      = -not $chkCustom.Checked
    if ($chkCustom.Checked) {
        if ($txtCustom.Text) {
            $lblResolved.Text = "// $($txtCustom.Text)"; $lblResolved.ForeColor = $theme.Success
        } else {
            $lblResolved.Text = "// custom folder not set"; $lblResolved.ForeColor = $theme.Warning
        }
    } else {
        $p = Get-RpiResolvedPackagePath
        if ($p) { $lblResolved.Text = "// $p"; $lblResolved.ForeColor = $theme.Success }
        else    { $lblResolved.Text = "// no package resolved"; $lblResolved.ForeColor = $theme.TextFaint }
    }
    ## v2.5.0: the folder behind MSI mode changed — rescan if MSI mode is on.
    if ($script:chkMsiMode -and $script:chkMsiMode.Checked) { Update-RpiMsiList }
    Update-RpiReadyPulse
})

## v2.5.0: MSI mode wiring. When the user flips chkMsiMode on, scan the
## currently-resolved folder and auto-check every .msi found. Off resets
## the summary label. Pick MSIs always opens the modal selection dialog.
$script:chkMsiMode.Add_CheckedChanged({
    if ($script:chkMsiMode.Checked) {
        Update-RpiMsiList   # auto-select-all: $PreserveSelection is null, every msi gets checked
    } else {
        ## Don't clear the items — keep the operator's selection so toggling
        ## back on restores their checked set. Only the summary label resets.
        Update-RpiMsiSummary
    }
    Update-RpiReadyPulse
})

$script:btnPickMsi.Add_Click({
    ## If MSI mode is off, flip it on so the picker has something to pick.
    if (-not $script:chkMsiMode.Checked) {
        $script:chkMsiMode.Checked = $true   # triggers Update-RpiMsiList
    } else {
        ## Ensure the list is in sync with whatever folder is currently
        ## resolved before showing the dialog.
        Update-RpiMsiList -PreserveSelection (Get-RpiResolvedMsiList)
    }
    Show-RpiMsiPickerDialog
})

$script:txtMsiArgs.Add_TextChanged({ Update-RpiReadyPulse })

$btnRefresh.Add_Click({ Update-RpiPackageList })

## v2.5.0: Browse button auto-rescans on pick. Reuses the existing
## $folderDialog instance defined for the custom-folder browse (single
## FolderBrowserDialog shared across both controls is fine; SelectedPath
## is the only piece of state we read).
$btnBrowseRoot.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($txtRoot.Text) -and (Test-Path -LiteralPath $txtRoot.Text.Trim())) {
        $folderDialog.SelectedPath = $txtRoot.Text.Trim()
    }
    if ($folderDialog.ShowDialog() -eq 'OK') {
        $txtRoot.Text = $folderDialog.SelectedPath
        Update-RpiPackageList
        Write-RpiLog "Package root -> $($txtRoot.Text)"
    }
})

## v2.5.0: pressing Enter in txtRoot fires a rescan too — common reflex
## after pasting a path.
$txtRoot.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $e.SuppressKeyPress = $true
        Update-RpiPackageList
    }
})

$btnSaveDefault.Add_Click({
    if (Save-RpiConfig) {
        $rootDesc = if ($chkCustom.Checked) { $txtCustom.Text.Trim() } else { $txtRoot.Text.Trim() }
        Write-RpiLog "Saved package source preference -> $(Split-Path $global:RpiConfigPath -Leaf)"
        Write-RpiLog "    Root        : $($txtRoot.Text.Trim())"
        Write-RpiLog "    Use custom  : $($chkCustom.Checked)"
        if ($chkCustom.Checked) { Write-RpiLog "    Custom path : $($txtCustom.Text.Trim())" }
        Write-RpiAuditLog -Target 'CONFIG' -Package 'N/A' -Result 'saved' -Detail "root=$rootDesc"
    } else {
        Write-RpiLog "Failed to save preferences to $($global:RpiConfigPath)"
    }
})

$comboPackage.Add_SelectedIndexChanged({
    $p = Get-RpiResolvedPackagePath
    if ($p) { $lblResolved.Text = "// $p"; $lblResolved.ForeColor = $theme.Success }
    else    { $lblResolved.Text = "// no package resolved"; $lblResolved.ForeColor = $theme.TextFaint }
    ## v2.5.0: combo selection changed -> the folder backing MSI mode changed.
    if ($script:chkMsiMode -and $script:chkMsiMode.Checked) { Update-RpiMsiList }
    Update-RpiReadyPulse
})

$btnSetCred.Add_Click({
    $global:Credentials = Get-Credential -Message "Enter credentials for remote package installs"
    if ($global:Credentials) {
        $lblCredStatus.Text = "// $($global:Credentials.UserName.ToUpperInvariant())"
        $lblCredStatus.ForeColor = $theme.Success
        $lblCred.Text = $global:Credentials.UserName
        $lblCred.ForeColor = $theme.Success
        Set-RpiPulseState -Indicator $pulseCred -State 'Active'
        Write-RpiLog "Credentials set: $($global:Credentials.UserName)"
    } else {
        $lblCredStatus.Text = "// no credentials loaded"
        $lblCredStatus.ForeColor = $theme.Warning
        $lblCred.Text = "none"
        $lblCred.ForeColor = $theme.TextMuted
        Set-RpiPulseState -Indicator $pulseCred -State 'Idle'
    }
    Update-RpiReadyPulse
})

#region === PARALLEL DEPLOY (RunspacePool, v2.4.0) ===
# Lift-and-shift from WPT 6.4.1's bulk-remoting engine. Replaces the
# sequential for/DoEvents loop. Each host runs in its own runspace from a
# bounded pool; a 400ms drain timer in the WinForms message loop polls
# completion and updates the grid on the UI thread.
#
# Cancel semantics: clicking the button while a run is in flight sets
# $script:RpiDeployState.Cancelled = $true. The drain timer stops dispatching
# new UI updates and short-circuits to the run-summary path. In-flight
# runspaces continue to completion in the background — we do NOT call
# .Stop() on them, because that can leave a target box mid-MSI-install with
# no rollback. "Cancel" here means "I'm done watching; whatever's running
# will finish quietly."

$script:RpiDeployState = $null

# v2.4.3: hostname -> full per-host result hashtable. Populated by the drain
# timer as each runspace returns. Read by the CellDoubleClick handler on
# $gridResults to drive Show-RpiHostDetail. Cleared at deploy start so the
# popup never shows stale data from a previous run.
$script:RpiHostDetails = @{}

# Per-host scriptblock. Runs inside an isolated runspace — NO outer-scope
# vars are visible. Everything it needs comes via .AddArgument().
# Returns a [pscustomobject] with the structured result the drain timer
# consumes. Mirrors the per-host body of the old sequential for-loop.
#
# v2.4.2: $StepQueue is a [ConcurrentQueue[psobject]] shared across all
# runspaces. Each scriptblock pushes intermediate step messages onto it
# ('Probing', 'Repairing', 'Copying', 'Deploying') so the drain timer can
# paint live status into the grid as work progresses, not only at terminal.
$script:RpiDeployHostScript = {
    param(
        [string]$Computer,
        [string]$PkgPath,
        [string]$PkgName,
        [System.Management.Automation.PSCredential]$Credential,
        $WSManOpt,
        $StepQueue,
        ## v2.5.0: deploy mode + MSI-bundle inputs. $Mode is 'PSADT' (legacy,
        ## runs Deploy-Application.ps1 in the copied folder) or 'MSI' (runs
        ## msiexec /i on each selected file). $MsiList is the array of file
        ## paths RELATIVE to $PkgPath (e.g. 'foo.msi' or 'x64\bar.msi') and
        ## $MsiArgs is the msiexec arg string (e.g. '/qn /norestart').
        [string]$Mode = 'PSADT',
        [string[]]$MsiList = @(),
        [string]$MsiArgs = '/qn /norestart'
    )

    $pushStep = {
        param([string]$Step, [string]$Detail = '')
        if ($StepQueue) {
            [void]$StepQueue.Enqueue([pscustomobject]@{
                Hostname = $Computer
                Step     = $Step
                Detail   = $Detail
            })
        }
    }

    $r = [pscustomobject]@{
        Hostname        = $Computer
        Status          = 'Failed'
        Reason          = ''
        Detail          = ''
        ExitCode        = $null
        Output          = ''
        Package         = $PkgName
        RepairAttempted = $false
        RepairSucceeded = $false
        StartTime       = (Get-Date)
        EndTime         = $null
    }

    $driveName       = "JANET_$($Computer -replace '[^a-zA-Z0-9]','')"
    $session         = $null
    $remoteSharePath = $null

    try {
        ## 1. Probe 5985 (the port we actually need for WinRM). Inlined
        ## because the runspace can't see Test-RpiReachable from outer scope.
        & $pushStep 'Probing' 'TCP probe 5985'
        $winrmOpen = $false
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                $winrmOpen = $true; $tc.Close()
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }

        if (-not $winrmOpen) {
            ## 1a. WinRM closed. Probe SMB (445) — if THAT's open we have a
            ## DCOM-repair side-channel. Ported from WPT 6.3.0 WinRMBootstrap
            ## block (v2.4.1).
            $smbOpen = $false
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, 445, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                    $smbOpen = $true; $tc.Close()
                }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }

            if (-not $smbOpen) {
                $r.Reason = 'Machine is offline or unreachable (no TCP on 5985 or 445)'
                return $r
            }

            ## 1b. SMB open + WinRM closed -> attempt DCOM bootstrap of WinRM.
            ## Two-attempt CIM connect (RPC ephemeral-port flake on first try
            ## against busy AFNET subnets), then ChangeStartMode + StartService
            ## + winrm quickconfig (with -skipNetworkProfileCheck so a Public-
            ## profile NIC can't silently block the firewall rule), then
            ## re-probe 5985 with a 30s budget.
            & $pushStep 'Repairing' 'DCOM bootstrap of WinRM'
            $r.RepairAttempted = $true
            $opt = New-CimSessionOption -Protocol DCOM
            $cim = $null
            for ($attempt = 1; $attempt -le 2 -and -not $cim; $attempt++) {
                try {
                    $cim = New-CimSession -ComputerName $Computer -Credential $Credential -SessionOption $opt -OperationTimeoutSec 30 -ErrorAction Stop
                } catch {
                    if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
                }
            }
            if (-not $cim) {
                $r.Reason = 'WinRM closed; DCOM repair connect failed (port 135 unreachable or RPC blocked)'
                return $r
            }
            try {
                $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
                if ($svc.StartMode -ne 'Auto') {
                    try { Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName ChangeStartMode -Arguments @{ StartMode = 'Automatic' } -ErrorAction Stop | Out-Null } catch {}
                }
                if ($svc.State -ne 'Running') {
                    try { Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName StartService -ErrorAction Stop | Out-Null } catch {}
                    Start-Sleep -Seconds 2
                }
                $cmd = 'cmd.exe /c winrm quickconfig -force -quiet -skipNetworkProfileCheck >C:\Windows\Temp\rpi_winrm_repair.log 2>&1'
                try { Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop | Out-Null } catch {}
                Start-Sleep -Seconds 3

                $deadline = (Get-Date).AddSeconds(30)
                do {
                    $tc = $null
                    try {
                        $tc = New-Object System.Net.Sockets.TcpClient
                        $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected) {
                            $winrmOpen = $true; $tc.Close()
                        }
                    } catch {}
                    finally { if ($tc) { try { $tc.Close() } catch {} } }
                    if (-not $winrmOpen -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
                } while (-not $winrmOpen -and (Get-Date) -lt $deadline)

                if ($winrmOpen) {
                    $r.RepairSucceeded = $true
                } else {
                    $r.Reason = 'WinRM still closed after 30s post-repair probe; DCOM bootstrap did not take'
                    return $r
                }
            } catch {
                $r.Reason = "DCOM repair error: $($_.Exception.Message)"
                return $r
            } finally {
                try { Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue } catch {}
            }
        }

        ## 2. Mount C$ admin share with supplied credential.
        & $pushStep 'Copying' 'Mounting C$ + copying package'
        if (Get-PSDrive -Name $driveName -EA SilentlyContinue) {
            Remove-PSDrive -Name $driveName -Force -EA SilentlyContinue
        }
        New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$Computer\C`$" -Credential $Credential -EA Stop | Out-Null

        $remoteBase = "${driveName}:\Temp"
        if (-not (Test-Path $remoteBase)) {
            New-Item -ItemType Directory -Force -Path $remoteBase | Out-Null
        }

        ## 3. Copy package to the target's C:\Temp\<pkg>_<stamp>\.
        ## PSADT mode: copy the whole folder (Deploy-Application.ps1 needs its
        ## siblings).
        ## MSI mode: copy ONLY the selected .msi files (preserving any 1-level
        ## subdir like x64\foo.msi). Avoids dragging unrelated content when
        ## the operator points at a busy share like \\fs\Apps\Patching.
        $stamp            = Get-Date -Format 'yyyyMMddHHmmss'
        $safePkgName      = ($PkgName -replace '[^a-zA-Z0-9._-]','_')
        $remoteFolderName = "${safePkgName}_$stamp"
        $remoteSharePath  = Join-Path $remoteBase $remoteFolderName
        $remoteLocalPath  = "C:\Temp\$remoteFolderName"

        if ($Mode -eq 'MSI') {
            ## Create the destination first, then copy each selected MSI by
            ## name (preserving subdir structure for entries like 'x64\foo.msi').
            New-Item -ItemType Directory -Force -Path $remoteSharePath -EA Stop | Out-Null
            foreach ($rel in $MsiList) {
                $srcFile = Join-Path $PkgPath $rel
                if (-not (Test-Path -LiteralPath $srcFile)) {
                    ## Don't fail the whole host yet — the per-MSI loop on the
                    ## remote will flag this as 'MSI not found in copied bundle'
                    ## with the rel name. Just skip the copy.
                    continue
                }
                $dstFile = Join-Path $remoteSharePath $rel
                $dstDir  = Split-Path $dstFile -Parent
                if (-not (Test-Path -LiteralPath $dstDir)) {
                    New-Item -ItemType Directory -Force -Path $dstDir -EA Stop | Out-Null
                }
                Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force -EA Stop
            }
        } else {
            Copy-Item -Path $PkgPath -Destination $remoteSharePath -Recurse -Force -EA Stop
        }

        ## 4. Open WinRM session and run the package (mode-dependent).
        if ($Mode -eq 'MSI') {
            & $pushStep 'Deploying' "Running $($MsiList.Count) MSI(s) via msiexec"
        } else {
            & $pushStep 'Deploying' 'Running Deploy-Application.ps1'
        }
        $session = New-PSSession -ComputerName $Computer -Credential $Credential `
            -Authentication Negotiate -SessionOption $WSManOpt -EA Stop

        if ($Mode -eq 'MSI') {
            ## v2.5.0: MSI bundle mode. For each selected MSI (filename relative
            ## to the copied bundle root), shell `msiexec /i <full> $MsiArgs
            ## /L*v <log>` on the remote and capture per-MSI exit codes. Host
            ## aggregate Status is Success only when EVERY MSI returned a
            ## success exit (0/1641/3010). Per-MSI summary lands in $res.Output
            ## so the double-click detail popup tells the operator exactly
            ## which one failed and where the verbose log lives on the box.
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath, $MsiList, $MsiArgs -ScriptBlock {
                param($destPath, $msiList, $msiArgs)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
                }
                try {
                    Get-ChildItem -Path $destPath -Filter *.msi -Recurse -EA SilentlyContinue | Unblock-File
                    $perMsi        = New-Object System.Collections.Generic.List[pscustomobject]
                    $sb            = New-Object System.Text.StringBuilder
                    $sawRebootInit = $false
                    $sawReboot     = $false
                    $firstFailMsi  = $null
                    $firstFailExit = $null

                    foreach ($rel in $msiList) {
                        $full = Join-Path $destPath $rel
                        $leaf = [System.IO.Path]::GetFileNameWithoutExtension($rel)
                        $logFile = Join-Path $destPath ($leaf + '.msiexec.log')
                        if (-not (Test-Path -LiteralPath $full)) {
                            $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$null; Status='Failed'; Reason='MSI not found in copied bundle' })
                            if (-not $firstFailMsi) { $firstFailMsi = $rel }
                            [void]$sb.AppendLine("[$rel] MISSING after copy")
                            continue
                        }

                        ## ArgumentList as a single string keeps PS 5.1 from
                        ## mangling embedded quotes around paths with spaces.
                        ## msiexec doesn't care about arg quoting nuances as
                        ## long as /i's value is quoted.
                        $argList = '/i "{0}" /L*v "{1}" {2}' -f $full, $logFile, $msiArgs

                        ## Direct ProcessStartInfo + WaitForExit pattern.
                        ## Start-Process -Wait -PassThru can return $proc.ExitCode = $null
                        ## inside a remote PSSession (handle reaped before we
                        ## read it), which is exactly what burned the first
                        ## real run (PowerShell-7.4.15-win-x64.msi came back
                        ## with "exit="). System.Diagnostics.Process keeps the
                        ## handle open until we explicitly WaitForExit, so
                        ## ExitCode is reliably populated.
                        $exit = $null
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName        = "$env:SystemRoot\System32\msiexec.exe"
                        $psi.Arguments       = $argList
                        $psi.UseShellExecute = $false
                        $psi.CreateNoWindow  = $true
                        $proc = $null
                        try {
                            $proc = [System.Diagnostics.Process]::Start($psi)
                        } catch {
                            $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$null; Status='Failed'; Reason="msiexec failed to launch: $($_.Exception.Message)" })
                            if (-not $firstFailMsi) { $firstFailMsi = $rel }
                            [void]$sb.AppendLine("[$rel] LAUNCH FAILED - $($_.Exception.Message)")
                            continue
                        }
                        if ($proc) {
                            $proc.WaitForExit()
                            $exit = $proc.ExitCode
                            try { $proc.Dispose() } catch {}
                        }

                        $status = 'Failed'
                        $reason = ''
                        switch ($exit) {
                            0       { $status = 'Success'; $reason = 'Success' }
                            1641    { $status = 'Success'; $reason = 'Success (reboot initiated)'; $sawRebootInit = $true }
                            3010    { $status = 'Success'; $reason = 'Success (reboot required)';  $sawReboot = $true }
                            1602    { $status = 'Failed';  $reason = 'User cancelled (1602)' }
                            1603    { $status = 'Failed';  $reason = "Fatal install error (1603) - see $logFile" }
                            1605    { $status = 'Failed';  $reason = 'Unknown product (1605)' }
                            1618    { $status = 'Failed';  $reason = 'Another install in progress (1618)' }
                            1619    { $status = 'Failed';  $reason = 'Package open failed (1619) - corrupt or locked' }
                            1638    { $status = 'Failed';  $reason = 'Another version is installed (1638)' }
                            default {
                                if ($null -eq $exit) { $status = 'Failed'; $reason = 'msiexec failed to launch (no exit code)' }
                                else                 { $status = 'Failed'; $reason = "msiexec exit $exit - see $logFile" }
                            }
                        }
                        $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$exit; Status=$status; Reason=$reason })
                        if ($status -ne 'Success' -and -not $firstFailMsi) {
                            $firstFailMsi  = $rel
                            $firstFailExit = $exit
                        }
                        [void]$sb.AppendLine("[$rel] exit=$exit  $reason")
                    }

                    $totalCount   = $perMsi.Count
                    $successCount = @($perMsi | Where-Object { $_.Status -eq 'Success' }).Count
                    $failCount    = $totalCount - $successCount

                    if ($totalCount -eq 0) {
                        $res.Status = 'Failed'
                        $res.Reason = 'No MSIs to install (empty selection)'
                    } elseif ($failCount -eq 0) {
                        $res.Status = 'Success'
                        if ($sawRebootInit)   { $res.Reason = "All $totalCount MSI(s) succeeded (reboot initiated)"; $res.ExitCode = 1641 }
                        elseif ($sawReboot)   { $res.Reason = "All $totalCount MSI(s) succeeded (reboot required)";  $res.ExitCode = 3010 }
                        else                  { $res.Reason = "All $totalCount MSI(s) succeeded";                    $res.ExitCode = 0 }
                    } else {
                        ## Pull the first-failure reason out of $perMsi so the
                        ## grid row's Detail tells the operator WHY it failed,
                        ## not just "exit=" / "exit=1603" without context.
                        $firstFailReason = ''
                        $ff = $perMsi | Where-Object { $_.Msi -eq $firstFailMsi -and $_.Status -ne 'Success' } | Select-Object -First 1
                        if ($ff) { $firstFailReason = $ff.Reason }
                        $exitTag = if ($null -eq $firstFailExit) { 'no exit code' } else { "exit=$firstFailExit" }
                        $res.Status   = 'Failed'
                        $res.Reason   = "$failCount of $totalCount MSI(s) failed: $firstFailMsi ($exitTag) - $firstFailReason"
                        $res.ExitCode = $firstFailExit
                    }
                    $res.Output = $sb.ToString().TrimEnd()
                    return $res
                } catch {
                    $res.Reason = "Terminating error: $($_.Exception.Message)"
                    return $res
                }
            } -EA Stop
        } else {
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath -ScriptBlock {
                param($destPath)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
                }
                try {
                    Get-ChildItem -Path $destPath -Filter *.ps1 -Recurse -EA SilentlyContinue | Unblock-File
                    $deploy = Get-ChildItem -Path $destPath -Filter 'Deploy-Application.ps1' -Recurse -File -EA SilentlyContinue | Select-Object -First 1
                    if (-not $deploy) {
                        $res.Reason = 'Deploy-Application.ps1 not found in package'
                        return $res
                    }
                    Set-Location $deploy.DirectoryName
                    $global:LASTEXITCODE = 0
                    $output   = & $deploy.FullName -DeployMode NonInteractive 2>&1
                    $exitCode = $LASTEXITCODE
                    $outStr   = ($output | Out-String).TrimEnd()
                    $res.Output   = $outStr
                    $res.ExitCode = $exitCode

                    # Same exit-code conventions as v2.3.3 sequential path:
                    #   0 / 1641 / 3010 = Success
                    #   60012           = Deferred (user clicked Defer)
                    #   anything else   = Failed
                    $successExits = @(0, 1641, 3010)
                    $softFail     = $outStr -match '(?im)^\s*(ERROR|FAILED|FAILURE)\b'
                    if ($successExits -contains $exitCode) {
                        if ($softFail) {
                            $res.Status = 'Failed'
                            $res.Reason = "Exit $exitCode but output contained ERROR/FAILED tokens"
                        } else {
                            $res.Status = 'Success'
                            $res.Reason = switch ($exitCode) {
                                3010 { 'Success (reboot required)' }
                                1641 { 'Success (reboot initiated)' }
                                default { 'Success' }
                            }
                        }
                    } elseif ($exitCode -eq 60012) {
                        $res.Status = 'Deferred'
                        $res.Reason = 'User deferred install (PSADT 60012)'
                    } else {
                        $res.Status = 'Failed'
                        $res.Reason = "Non-zero exit code: $exitCode"
                    }
                    return $res
                } catch {
                    $res.Reason = "Terminating error: $($_.Exception.Message)"
                    return $res
                }
            } -EA Stop
        }

        ## 5. Map invokeResult onto $r.
        $sub = $invokeResult
        if ($sub -is [System.Array]) {
            $sub = $sub | Where-Object { $_ -and $_.PSObject.Properties['Status'] } | Select-Object -First 1
        }
        if ($sub) {
            $r.Status   = $sub.Status
            $r.Reason   = $sub.Reason
            $r.ExitCode = $sub.ExitCode
            $r.Output   = $sub.Output    # v2.4.3: preserve full Deploy-Application.ps1 output for the detail popup
            $detail = $sub.Reason
            if ($null -ne $sub.ExitCode) { $detail = "$detail (exit=$($sub.ExitCode))" }
            $r.Detail = $detail
        } else {
            $r.Status = 'Failed'
            $r.Reason = 'Unknown remote error (no structured result)'
            $r.Detail = $r.Reason
        }
    } catch {
        $r.Status = 'Failed'
        $r.Reason = $_.Exception.Message
        $r.Detail = $r.Reason
    } finally {
        if ($remoteSharePath -and (Test-Path $remoteSharePath -EA SilentlyContinue)) {
            Remove-Item $remoteSharePath -Recurse -Force -EA SilentlyContinue
        }
        if ($session) { Remove-PSSession -Session $session -EA SilentlyContinue }
        Remove-PSDrive -Name $driveName -Force -EA SilentlyContinue
        $r.EndTime = (Get-Date)
    }

    return $r
}

function Start-RpiParallelDeploy {
    # Builds a RunspacePool, BeginInvokes one PowerShell per host. Returns
    # the state object the drain timer polls. Caller is responsible for
    # starting the drain timer.
    # v2.5.0: -Mode/-MsiList/-MsiArgs flow through to the per-host scriptblock.
    param(
        [string[]]$Computers,
        [string]$PkgPath,
        [string]$PkgName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$MaxConcurrent = 8,
        [string]$Mode = 'PSADT',
        [string[]]$MsiList = @(),
        [string]$MsiArgs = '/qn /norestart'
    )
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrent, $iss, $Host)
    $pool.ApartmentState = 'STA'
    $pool.Open()

    ## v2.4.2: shared step queue. Per-host scriptblocks enqueue intermediate
    ## status messages here; drain timer dequeues each tick and paints the
    ## grid. ConcurrentQueue is thread-safe by design — no locking needed.
    $stepQueue = [System.Collections.Concurrent.ConcurrentQueue[psobject]]::new()

    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($comp in $Computers) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:RpiDeployHostScript)
        [void]$ps.AddArgument($comp)
        [void]$ps.AddArgument($PkgPath)
        [void]$ps.AddArgument($PkgName)
        [void]$ps.AddArgument($Credential)
        [void]$ps.AddArgument($script:WSManOpt)
        [void]$ps.AddArgument($stepQueue)
        [void]$ps.AddArgument($Mode)
        [void]$ps.AddArgument($MsiList)
        [void]$ps.AddArgument($MsiArgs)
        $async = $ps.BeginInvoke()
        $jobs.Add([pscustomobject]@{
            Computer    = $comp
            PowerShell  = $ps
            Async       = $async
            Done        = $false
            Result      = $null
        })
    }

    return [pscustomobject]@{
        Pool          = $pool
        Jobs          = $jobs
        StepQueue     = $stepQueue
        PkgName       = $PkgName
        Total         = $Computers.Count
        MaxConcurrent = $MaxConcurrent
        Successes     = 0
        Failures      = 0
        Deferreds     = 0
        Cancelled     = $false
        RunStart      = (Get-Date)
        FinalizeFired = $false
    }
}

function Step-RpiDeployDrain {
    # Timer tick handler. Iterates jobs, EndInvokes any that just finished,
    # updates the grid + counters, and finalizes when all are done OR when
    # cancellation is requested. Runs on the UI thread.
    if ($null -eq $script:RpiDeployState) { return }
    $st = $script:RpiDeployState

    if ($st.FinalizeFired) { return }   # belt-and-suspenders against re-entry

    ## v2.4.2: drain step queue first. Each runspace pushes intermediate
    ## status messages ('Probing', 'Repairing', 'Copying', 'Deploying') so
    ## the grid shows live per-host phase, not just terminal status. Order
    ## within a single host is preserved by ConcurrentQueue's FIFO; ordering
    ## across hosts is best-effort but doesn't matter — each row is keyed
    ## by hostname.
    if ($st.StepQueue) {
        $msg = $null
        while ($st.StepQueue.TryDequeue([ref]$msg)) {
            if ($st.Cancelled) { continue }
            try { Update-RpiResultGrid -Hostname $msg.Hostname -Status $msg.Step -Detail $msg.Detail } catch {}
        }
    }

    foreach ($job in $st.Jobs) {
        if ($job.Done) { continue }
        if (-not $job.Async.IsCompleted) { continue }

        $job.Done = $true
        $res = $null
        try {
            $out = $job.PowerShell.EndInvoke($job.Async)
            if ($out -and $out.Count -gt 0) { $res = $out[0] }
        } catch {
            $res = [pscustomobject]@{
                Hostname = $job.Computer
                Status   = 'Failed'
                Reason   = "Runspace error: $($_.Exception.Message)"
                Detail   = "Runspace error: $($_.Exception.Message)"
                ExitCode = $null
            }
        } finally {
            try { $job.PowerShell.Dispose() } catch {}
        }
        $job.Result = $res

        ## v2.4.3: stash the full result for double-click drilldown.
        ## Done unconditionally — even cancelled-late finishers populate
        ## the dictionary, so the operator can still inspect what they
        ## actually returned.
        if ($null -ne $res) { $script:RpiHostDetails[$job.Computer] = $res }

        if ($st.Cancelled) { continue }   # don't paint UI for late finishers after cancel

        ## Update grid + counters on the UI thread.
        $comp     = $job.Computer
        $status   = if ($res) { $res.Status } else { 'Failed' }
        $detail   = if ($res -and $res.Detail) { $res.Detail } else { 'Unknown remote error (no structured result)' }
        Update-RpiResultGrid -Hostname $comp -Status $status -Detail $detail

        ## v2.4.1: prefix the log line when a DCOM bootstrap fired so the
        ## operator can see at a glance which hosts needed WinRM repaired.
        $repairTag = if ($res -and $res.PSObject.Properties['RepairAttempted'] -and $res.RepairAttempted) {
            if ($res.RepairSucceeded) { '[REPAIRED] ' } else { '[REPAIR-FAILED] ' }
        } else { '' }

        switch ($status) {
            'Success'  {
                $st.Successes++
                Write-RpiLog "${repairTag}[$comp] SUCCESS (exit=$($res.ExitCode)) $($res.Reason)"
                Write-RpiAuditLog -Target $comp -Package $st.PkgName -Result 'success' -Detail "exit=$($res.ExitCode)"
            }
            'Deferred' {
                $st.Deferreds++
                Write-RpiLog "${repairTag}[$comp] DEFERRED (exit=$($res.ExitCode)) $($res.Reason)"
                Write-RpiAuditLog -Target $comp -Package $st.PkgName -Result 'deferred' -Detail "exit=$($res.ExitCode)"
            }
            default    {
                $st.Failures++
                Write-RpiLog "${repairTag}[$comp] FAILED: $detail"
                Write-RpiAuditLog -Target $comp -Package $st.PkgName -Result 'failed' -Detail $detail
            }
        }

        ## Live sidebar update: refresh Success/Failed counters as each host
        ## completes instead of waiting until the whole batch is done. The
        ## drain timer is on the UI thread, so this is safe to update directly.
        if ($script:lblSideSuccess) { $script:lblSideSuccess.Text = "$($st.Successes)" }
        if ($script:lblSideFailed)  { $script:lblSideFailed.Text  = "$($st.Failures)"  }

        [void]$global:DeployResults.Add([PSCustomObject]@{
            Hostname = $comp
            Status   = $status
            Package  = $st.PkgName
            Time     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        })

        if ($null -ne $script:JanetSession) {
            $janetResult = switch ($status) {
                'Success'  { 'Success' }
                'Failed'   { 'Failure' }
                'Deferred' { 'Skipped' }
                default    { 'Skipped' }
            }
            $itemCount = if ($janetResult -eq 'Success') { 1 } else { 0 }
            try { Write-JanetAction -Action 'VulnPatched' -Target $comp -Result $janetResult -ItemCount $itemCount -Detail $st.PkgName } catch {}
        }
    }

    ## v2.4.2: refresh aggregate progress label every tick.
    Update-RpiProgressLabel

    ## Finalize when all jobs done OR when operator cancelled.
    $allDone = -not ($st.Jobs | Where-Object { -not $_.Done })
    if ($st.Cancelled -or $allDone) {
        $st.FinalizeFired = $true
        $script:RpiDrainTimer.Stop()
        Complete-RpiParallelDeploy
    }
}

function Update-RpiProgressLabel {
    ## Paints "Progress: 12 / 120 (10%) | Live: 8" into the status bar.
    ## Called every drain tick during a run, plus once on completion to
    ## leave a final tally on screen.
    if (-not $script:lblStatProgress) { return }
    $st = $script:RpiDeployState
    if ($null -eq $st) {
        $script:lblStatProgress.Text      = ''
        $script:lblStatProgress.ForeColor = $theme.TextMuted
        return
    }
    $done = $st.Successes + $st.Failures + $st.Deferreds
    $pct  = if ($st.Total -gt 0) { [int](($done / $st.Total) * 100) } else { 0 }
    $live = ($st.Jobs | Where-Object { -not $_.Done }).Count
    if ($live -gt $st.MaxConcurrent) { $live = $st.MaxConcurrent }
    $tag  = if ($st.Cancelled) { ' [CANCELLED]' } else { '' }
    $script:lblStatProgress.Text      = "Progress: $done / $($st.Total) ($pct%) | Live: $live$tag"
    $script:lblStatProgress.ForeColor = if ($st.Cancelled) { $theme.Warning }
                                        elseif ($pct -eq 100) { $theme.Success }
                                        else { $theme.Accent1 }
}

function Show-RpiHostDetail {
    ## v2.4.3: modal popup with everything we know about a host's deploy.
    ## Shown when the operator double-clicks a row in $gridResults. Pulls
    ## the structured result out of $script:RpiHostDetails (populated by
    ## the drain timer). Read-only; close to dismiss.
    param([Parameter(Mandatory)][string]$Hostname)

    $detail = $script:RpiHostDetails[$Hostname]
    if ($null -eq $detail) {
        ## Could be a host whose runspace hasn't returned yet (still
        ## Probing / Copying / Deploying), or a Queued row that hasn't
        ## been touched. Show a stub instead of opening an empty form.
        [System.Windows.Forms.MessageBox]::Show(
            "No detail captured for $Hostname yet. The runspace is still in flight, or the host was never dispatched.",
            "Host Detail", 'OK', 'Information') | Out-Null
        return
    }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text              = "Host Detail: $Hostname"
    $dlg.ClientSize        = New-Object System.Drawing.Size(720, 540)
    $dlg.StartPosition     = 'CenterParent'
    $dlg.FormBorderStyle   = 'FixedDialog'
    $dlg.MaximizeBox       = $false
    $dlg.MinimizeBox       = $false
    $dlg.BackColor         = $theme.Background
    $dlg.ForeColor         = $theme.TextPrimary
    $dlg.Font              = $fonts.Body
    Enable-RpiDoubleBuffer -Control $dlg
    $dlg.Add_HandleCreated({ try { Set-RpiDarkTitleBar -Form $dlg } catch {} })

    ## Status badge — colored to match grid conventions.
    $statusColor = switch ($detail.Status) {
        'Success'  { $theme.Success }
        'Failed'   { $theme.Danger  }
        'Deferred' { $theme.Warning }
        default    { $theme.TextSecondary }
    }
    $lblHost = New-RpiLabel -Text $Hostname.ToUpperInvariant() -X 18 -Y 14 -W 380 -H 22 -Font $fonts.DisplayMd -Fg $theme.TextPrimary
    $dlg.Controls.Add($lblHost)
    ## v2.4.4: status badge shifted left from X=540 W=160 (right edge 700)
    ## to X=420 W=240 (right edge 660) to make room for the in-form X close
    ## button at top-right (X=678 W=28). The system title-bar X is unreliable
    ## across DPI / dark-titlebar combos — operators reported clicking it
    ## had no effect. The in-form X is the dependable exit.
    $lblStatus = New-RpiLabel -Text $detail.Status.ToUpperInvariant() -X 420 -Y 16 -W 240 -H 22 -Font $fonts.DisplayMd -Fg $statusColor
    $lblStatus.TextAlign = 'MiddleRight'
    $dlg.Controls.Add($lblStatus)

    ## v2.4.4: in-form X close button at the top right, mimicking the
    ## standard window chrome but as a real form control we control. Set
    ## DialogResult so AcceptButton/CancelButton wiring + the Esc key all
    ## actually close the dialog.
    $btnXClose = New-Object System.Windows.Forms.Button
    $btnXClose.Text                          = "X"
    $btnXClose.Location                      = New-Object System.Drawing.Point(678, 8)
    $btnXClose.Size                          = New-Object System.Drawing.Size(28, 28)
    $btnXClose.FlatStyle                     = 'Flat'
    $btnXClose.FlatAppearance.BorderSize     = 0
    $btnXClose.BackColor                     = $theme.Background
    $btnXClose.ForeColor                     = $theme.TextSecondary
    $btnXClose.Font                          = $fonts.DisplayMd
    $btnXClose.Cursor                        = [System.Windows.Forms.Cursors]::Hand
    $btnXClose.UseVisualStyleBackColor       = $false
    $btnXClose.FlatAppearance.MouseOverBackColor = $theme.Danger
    $btnXClose.FlatAppearance.MouseDownBackColor = $theme.Danger
    $btnXClose.TabStop                       = $false
    $btnXClose.DialogResult                  = [System.Windows.Forms.DialogResult]::Cancel
    $btnXClose.Add_Click({ $dlg.Close() }.GetNewClosure())
    $dlg.Controls.Add($btnXClose)

    ## Metadata grid: Package / Exit / Started / Ended / Duration / Repair.
    $exitTxt = if ($null -ne $detail.ExitCode) { "$($detail.ExitCode)" } else { '—' }
    $startTxt = if ($detail.StartTime) { ([datetime]$detail.StartTime).ToString('HH:mm:ss') } else { '—' }
    $endTxt   = if ($detail.EndTime)   { ([datetime]$detail.EndTime).ToString('HH:mm:ss')   } else { '—' }
    $durTxt   = if ($detail.StartTime -and $detail.EndTime) {
        $sec = [int](([datetime]$detail.EndTime) - ([datetime]$detail.StartTime)).TotalSeconds
        "${sec}s"
    } else { '—' }
    $repairTxt = if ($detail.RepairAttempted) {
        if ($detail.RepairSucceeded) { 'attempted, succeeded' } else { 'attempted, FAILED' }
    } else { 'not needed' }

    $metaY = 50
    $metaPairs = @(
        @{ K = 'Package';  V = $detail.Package },
        @{ K = 'Exit';     V = $exitTxt },
        @{ K = 'Reason';   V = (if ($detail.Reason) { $detail.Reason } else { '—' }) },
        @{ K = 'Started';  V = $startTxt },
        @{ K = 'Ended';    V = $endTxt },
        @{ K = 'Duration'; V = $durTxt },
        @{ K = 'Repair';   V = $repairTxt }
    )
    foreach ($p in $metaPairs) {
        $kLbl = New-RpiLabel -Text "$($p.K):" -X 18 -Y $metaY -W 90 -H 18 -Font $fonts.MonoSm -Fg $theme.TextSecondary
        $vLbl = New-RpiLabel -Text "$($p.V)"  -X 110 -Y $metaY -W 590 -H 18 -Font $fonts.MonoSm -Fg $theme.TextPrimary
        $dlg.Controls.AddRange(@($kLbl, $vLbl))
        $metaY += 22
    }

    ## Output card — the full Deploy-Application.ps1 stdout/stderr.
    $cardOut = New-RpiCard -Header 'Deploy-Application.ps1 Output' -X 14 -Y ($metaY + 8) -W 692 -H (440 - $metaY) -Fg $theme.Accent2
    $dlg.Controls.Add($cardOut)

    $txtOut = New-Object System.Windows.Forms.RichTextBox
    $txtOut.Location    = New-Object System.Drawing.Point(14, 46)
    $txtOut.Size        = New-Object System.Drawing.Size(($cardOut.Width - 28), ($cardOut.Height - 60))
    $txtOut.ReadOnly    = $true
    $txtOut.BackColor   = $theme.ConsoleBg
    $txtOut.ForeColor   = $theme.ConsoleFg
    $txtOut.Font        = $fonts.Mono
    $txtOut.BorderStyle = 'None'
    $txtOut.WordWrap    = $false
    $txtOut.ScrollBars  = 'Both'
    $txtOut.Text        = if ($detail.Output) { $detail.Output } else { '(no output captured — host failed before Deploy-Application.ps1 was invoked)' }
    $cardOut.Controls.Add($txtOut)

    ## Footer: Copy + Close.
    $btnCopy = New-RpiGhostButton -Text "Copy Output" -X 470 -Y 500 -W 130 -H 30 -Fg $theme.Accent1
    $btnCopy.Add_Click({
        try {
            [System.Windows.Forms.Clipboard]::SetText([string]$detail.Output)
        } catch {}
    }.GetNewClosure())
    $dlg.Controls.Add($btnCopy)

    $btnClose = New-RpiStripeButton -Text "Close" -X 610 -Y 496 -W 96 -H 38
    ## v2.4.4: .GetNewClosure() so $dlg is captured into the delegate scope
    ## — without it the click handler silently no-ops because $dlg is not
    ## visible at delegate-invocation time. DialogResult so Esc + the
    ## CancelButton/AcceptButton wiring all close the form.
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnClose.Add_Click({ $dlg.Close() }.GetNewClosure())
    $dlg.Controls.Add($btnClose)
    $dlg.AcceptButton = $btnClose
    $dlg.CancelButton = $btnXClose

    [void]$dlg.ShowDialog($f)
    $dlg.Dispose()
}

function Complete-RpiParallelDeploy {
    # Single exit point for both natural completion and operator-cancel.
    if ($null -eq $script:RpiDeployState) { return }
    $st = $script:RpiDeployState

    $durationSec = [int]((Get-Date) - $st.RunStart).TotalSeconds
    $deferredFragment = if ($st.Deferreds -gt 0) { ", $($st.Deferreds) deferred" } else { '' }
    $cancelTag = if ($st.Cancelled) { ' [CANCELLED]' } else { '' }
    Write-RpiLog "=== Deployment complete$cancelTag : $($st.Successes) success, $($st.Failures) failed$deferredFragment ($durationSec s) ==="
    Write-RpiAuditLog -Target 'BULK' -Package $st.PkgName -Result ($(if ($st.Cancelled) { 'cancelled' } else { 'complete' })) -Detail "$($st.Successes) success, $($st.Failures) failed$deferredFragment, $durationSec s"

    if ($script:lblSideSuccess) {
        $script:lblSideSuccess.Text = "$($st.Successes)"
        $script:lblSideFailed.Text  = "$($st.Failures)"
        $script:lblSideLastRun.Text = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    ## v2.4.2: paint final progress label BEFORE clearing state, so the
    ## status bar leaves the closing tally visible (X/Y (100%) | Live: 0)
    ## or [CANCELLED] tag) until the next deploy starts.
    Update-RpiProgressLabel

    ## Reset Deploy button. Pool is closed lazily — runspaces still in flight
    ## will close it themselves when their work returns. This prevents a
    ## deadlock if Pool.Close() is called while jobs are mid-Invoke.
    try { $st.Pool.Close() } catch {}
    try { $st.Pool.Dispose() } catch {}
    $script:RpiDeployState = $null

    $script:btnRunInstall.Enabled = $true
    $script:btnRunInstall.Text    = 'Deploy'
    if ($st.Failures -eq 0 -and -not $st.Cancelled) {
        Set-RpiPulseState -Indicator $pulseCred -State 'Active'
    } else {
        Set-RpiPulseState -Indicator $pulseCred -State 'Alert'
    }
    Update-RpiReadyPulse
}

## Drain timer ticks every 400ms — same cadence as WPT's bulk poll. Tight
## enough that the UI feels live, loose enough that we're not consuming
## a noticeable amount of CPU on a 50-host run.
$script:RpiDrainTimer          = New-Object System.Windows.Forms.Timer
$script:RpiDrainTimer.Interval = 400
$script:RpiDrainTimer.Add_Tick({ Step-RpiDeployDrain })
#endregion

$script:btnRunInstall.Add_Click({
    ## v2.4.0: button doubles as Cancel during a run. If a deploy is in
    ## flight, this click sets the cancellation flag and bails. Drain timer
    ## sees the flag and finalizes early.
    if ($null -ne $script:RpiDeployState -and -not $script:RpiDeployState.FinalizeFired) {
        Write-RpiLog '=== Cancellation requested by operator. In-flight hosts will complete quietly. ==='
        $script:RpiDeployState.Cancelled = $true
        $script:btnRunInstall.Enabled    = $false
        $script:btnRunInstall.Text       = 'Cancelling...'
        return
    }

    $computers = @(Get-RpiComputerList)
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No target computers entered.", "No Targets", 'OK', 'Warning')
        return
    }
    if (-not $global:Credentials) {
        [System.Windows.Forms.MessageBox]::Show("Set credentials first.", "No Credentials", 'OK', 'Warning')
        return
    }
    if ($chkCustom.Checked -and [string]::IsNullOrWhiteSpace($txtCustom.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Custom package folder is empty. Browse to a package folder or uncheck 'Use custom package folder'.", "Package Error", 'OK', 'Warning')
        return
    }
    if (-not $chkCustom.Checked -and -not $comboPackage.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show("No package selected. Click Rescan and pick a package, or use a custom folder.", "Package Error", 'OK', 'Warning')
        return
    }
    $pkgPath = Get-RpiResolvedPackagePath
    if (-not $pkgPath -or -not (Test-Path $pkgPath)) {
        [System.Windows.Forms.MessageBox]::Show("Package folder not found:`n$pkgPath", "Package Error", 'OK', 'Error')
        return
    }

    ## v2.5.0: MSI mode preconditions. Resolve mode + MSI list up front so the
    ## per-host runspaces all get the same selection snapshot.
    $deployMode = 'PSADT'
    $msiList    = @()
    $msiArgs    = '/qn /norestart'
    if ($script:chkMsiMode -and $script:chkMsiMode.Checked) {
        $deployMode = 'MSI'
        $msiList    = @(Get-RpiResolvedMsiList)
        if ($msiList.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "MSI mode is on but no .msi files are selected. Click 'Pick MSIs' to choose at least one installer, then try again.",
                "No MSIs Selected", 'OK', 'Warning') | Out-Null
            return
        }
        if ($script:txtMsiArgs) { $msiArgs = $script:txtMsiArgs.Text.Trim() }
        if ([string]::IsNullOrWhiteSpace($msiArgs)) { $msiArgs = '/qn /norestart' }

        ## v2.5.3: pkgPath can point at a SINGLE .msi file when the operator
        ## pasted a direct file path into the custom-folder textbox. The deploy
        ## scriptblock expects pkgPath = folder + msiList = relative leaves, so
        ## rewrite to (parent folder, [leaf]) here.
        $pkgItem = Get-Item -LiteralPath $pkgPath -ErrorAction SilentlyContinue
        if ($pkgItem -and -not $pkgItem.PSIsContainer -and $pkgItem.Extension -ieq '.msi') {
            $pkgPath = $pkgItem.DirectoryName
            $msiList = @($pkgItem.Name)
        }
    }

    $pkgName = Split-Path $pkgPath -Leaf
    $total = $computers.Count
    $gridResults.Rows.Clear()
    $global:DeployResults.Clear()
    $script:RpiHostDetails.Clear()    # v2.4.3: drop stale per-host details from prior run

    if ($deployMode -eq 'MSI') {
        Write-RpiLog "=== Deploying MSI bundle '$pkgName' ($($msiList.Count) MSI(s)) to $total target(s) ==="
        Write-RpiLog "MSI args: $msiArgs"
        foreach ($m in $msiList) { Write-RpiLog "  + $m" }
        Write-RpiAuditLog -Target "BULK" -Package "$pkgName (MSI x$($msiList.Count))" -Result "starting" -Detail "$total targets, args=$msiArgs"
    } else {
        Write-RpiLog "=== Deploying '$pkgName' to $total target(s) ==="
        Write-RpiAuditLog -Target "BULK" -Package $pkgName -Result "starting" -Detail "$total targets"
    }

    $script:btnRunInstall.Enabled = $true
    $script:btnRunInstall.Text    = 'Cancel'
    # Pause the ready-pulse during the run; show Alert on the creds pulse instead
    Stop-RpiButtonPulse -Button $script:btnRunInstall
    Set-RpiPulseState -Indicator $pulseCred -State 'Alert'

    ## Seed the grid with a "Queued" row per host so the operator sees the
    ## full target list immediately. Drain timer overwrites each row as the
    ## corresponding runspace returns.
    foreach ($comp in $computers) {
        Update-RpiResultGrid -Hostname $comp -Status 'Queued' -Detail '...'
    }

    ## v2.4.2: concurrency from the operator-selectable NumericUpDown.
    ## v2.5.0: mode + MSI inputs forwarded so the runspace scriptblock picks
    ## the right deploy path.
    $maxConc = [int]$script:numParallel.Value
    $script:RpiDeployState = Start-RpiParallelDeploy `
        -Computers $computers -PkgPath $pkgPath -PkgName $pkgName `
        -Credential $global:Credentials -MaxConcurrent $maxConc `
        -Mode $deployMode -MsiList $msiList -MsiArgs $msiArgs

    Write-RpiLog "Dispatched $($computers.Count) host(s) to runspace pool (max $maxConc concurrent). Click Cancel to abort dispatch — in-flight hosts will complete quietly."
    $script:RpiDrainTimer.Start()
    Update-RpiProgressLabel    # paint initial 0 / N progress immediately
})

$btnRetryFailed.Add_Click({
    $failedHosts = @()
    foreach ($row in $gridResults.Rows) {
        if ($row.Cells["Status"].Value -eq "FAILED") {
            $failedHosts += $row.Cells["Host"].Value
        }
    }
    if ($failedHosts.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No failed deployments to retry.", "Nothing to Retry", 'OK', 'Information')
        return
    }
    $txtManual.Text = $failedHosts -join ", "
    Write-RpiLog "Loaded $($failedHosts.Count) failed hosts for retry. Click Deploy to retry."
    Update-RpiStatusStrip
    Update-RpiSidebarStats
    Update-RpiReadyPulse
})

$btnExportResults.Add_Click({
    # Matches WPT's export pattern: PSCustomObject rows -> Export-Csv -NoTypeInformation.
    if ($gridResults.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.", "Empty", 'OK', 'Information')
        return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = 'CSV|*.csv'
    $sfd.Title    = 'Export Deployment Results'
    $sfd.FileName = "RPI_DeployResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    try {
        $rows = foreach ($row in $gridResults.Rows) {
            [pscustomobject]@{
                Host   = $row.Cells['Host'].Value
                Status = $row.Cells['Status'].Value
                Detail = $row.Cells['Detail'].Value
                Time   = $row.Cells['Time'].Value
            }
        }
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Write-RpiLog "Exported $($gridResults.Rows.Count) row(s) to $(Split-Path $sfd.FileName -Leaf)"
    } catch {
        Write-RpiLog "Export failed: $($_.Exception.Message)"
    }
})

# Clean shutdown - stop all heartbeat timers + button pulse. Centralized
# JANET logging (Stop-JanetSession) flushes its own state via the closing
# dialog, so nothing needed here on the usage side.
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

    ## Close the floating Deployment Results popout (if open) FIRST. Its
    ## FormClosing handler reparents $gridResults back into the card; doing
    ## that before the main form disposes prevents a stray reference to a
    ## torn-down parent.
    if ($script:RpiGridPopOutForm) {
        try { $script:RpiGridPopOutForm.Close() } catch {}
        $script:RpiGridPopOutForm = $null
    }

    foreach ($p in @($brandHeartbeat, $contentHeartbeat, $statusHeartbeat, $pulseCred)) {
        if ($p -and $p.Tag -and $p.Tag.Timer) {
            try { $p.Tag.Timer.Stop(); $p.Tag.Timer.Dispose() } catch {}
        }
    }
    if ($script:btnRunInstall -and $script:btnRunInstall.Tag -and $script:btnRunInstall.Tag.PulseTimer) {
        try { $script:btnRunInstall.Tag.PulseTimer.Stop(); $script:btnRunInstall.Tag.PulseTimer.Dispose() } catch {}
    }

    ## v2.4.0: stop drain timer + close runspace pool. If a deploy is in
    ## flight when the form closes, in-flight runspaces will complete in
    ## the background after the host process holds them open via Pool.Close()
    ## blocking until they return. We don't await — operator wants out.
    try { if ($script:RpiDrainTimer) { $script:RpiDrainTimer.Stop(); $script:RpiDrainTimer.Dispose() } } catch {}
    if ($null -ne $script:RpiDeployState) {
        try { $script:RpiDeployState.Pool.Close()   } catch {}
        try { $script:RpiDeployState.Pool.Dispose() } catch {}
    }

    ## JANET centralized session close (added in v2.3.1). -ShowDialog presents
    ## the JANET closing-notes form so ASI + notes are captured for the rollup.
    try { Stop-JanetSession -ShowDialog } catch {}
})
#endregion

#region === STARTUP ===
Write-RpiLog "RemotePackageInstaller v2.5.4 initialized."

## v2.3.3: warn if the tool was launched from a OneDrive-synced location.
## Real-world failure mode (seen on the 1521131426E box): packages live in
## ...\OneDrive - United States Air Force\Desktop\J.A.N.E.T\Tools\Packages
## and OneDrive aggressively uploads anything written there. During a deploy
## the package copy can hit a sync-induced file lock, and saved config files
## can race with sync. Detect once at launch and surface as a single warning
## line so the operator at least knows.
if ($global:ScriptDir -like '*OneDrive*' -or $global:ScriptDir -like '*\OneDrive -*') {
    Write-RpiLog "WARNING: Tool is running from a OneDrive-synced path ($global:ScriptDir). Sync can hold file locks during package copy and race with config saves. Consider relocating to a non-synced folder (e.g. C:\Tools\J.A.N.E.T)."
}

## JANET centralized session (added in v2.3.1). Metric tool: per-host
## InstallPackage rows recorded in the deploy loop; rollup row written
## on FormClosing with dialog.
try { Start-JanetSession -Tool 'Remote_Pkg' -Version $JanetRemote_PkgVersion } catch {}
Write-RpiLog "Set credentials and select a package to begin."
Write-RpiLog "Log file: $($global:PatcherLogPath)"
# Apply remaining saved-config fields (custom toggle + custom path). The
# packageRoot was applied earlier at $DefaultPackageRoot resolution; here we
# restore the rest of the UI state so the operator picks up exactly where
# they left off. CheckedChanged event fires automatically and re-syncs the
# enabled-states of the dependent controls.
if ($savedCfg.ContainsKey('customPath') -and -not [string]::IsNullOrWhiteSpace([string]$savedCfg['customPath'])) {
    $txtCustom.Text = [string]$savedCfg['customPath']
}
if ($savedCfg.ContainsKey('useCustom') -and [bool]$savedCfg['useCustom']) {
    $chkCustom.Checked = $true
}
## v2.5.0: msiArgs first (so Update-RpiMsiList sees the persisted value), then
## msiMode (its CheckedChanged handler triggers the rescan with PreserveSelection).
if ($savedCfg.ContainsKey('msiArgs') -and -not [string]::IsNullOrWhiteSpace([string]$savedCfg['msiArgs'])) {
    $script:txtMsiArgs.Text = [string]$savedCfg['msiArgs']
}
$savedMsiSelection = $null
if ($savedCfg.ContainsKey('msiSelection')) {
    ## ConvertFrom-Json on a string array yields object[]; coerce to string[]
    ## to keep Update-RpiMsiList's -contains check predictable.
    $savedMsiSelection = @($savedCfg['msiSelection'] | ForEach-Object { [string]$_ })
}
if ($savedCfg.ContainsKey('msiMode') -and [bool]$savedCfg['msiMode']) {
    $script:chkMsiMode.Checked = $true
    ## Re-run the scan with the saved selection AFTER the package combo has
    ## been populated below. Stash so the call after Update-RpiPackageList
    ## can wire it up.
    $script:RpiPendingMsiSelection = $savedMsiSelection
}
if ($savedCfg.Count -gt 0) {
    Write-RpiLog "Loaded saved package source preference from $(Split-Path $global:RpiConfigPath -Leaf)"
}

Update-RpiPackageList

## v2.5.0: now that the combo is populated and a default selection has fired
## (which already triggered Update-RpiMsiList with auto-select-all), re-apply
## the saved checkbox state so the operator's prior picks survive a restart.
if ($script:chkMsiMode.Checked -and $script:RpiPendingMsiSelection) {
    Update-RpiMsiList -PreserveSelection $script:RpiPendingMsiSelection
    $script:RpiPendingMsiSelection = $null
}
Update-RpiStatusStrip
Update-RpiSidebarStats
Update-RpiReadyPulse
#endregion

#region === SHOW FORM ===
$f.Add_Shown({ $f.Activate() })
[void]$f.ShowDialog()
Write-RpiAuditLog -Target "SYSTEM" -Package "N/A" -Result "session_ended"
$f.Dispose()
#endregion