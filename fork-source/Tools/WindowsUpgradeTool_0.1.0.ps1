<#
.NAME
    J.A.N.E.T. Windows Upgrade Tool
.SYNOPSIS
    Joint Administration and Network Execution Toolkit - Feature Update Deployer
.DESCRIPTION
    Standalone WinForms bench build (the precursor we iterate on BEFORE porting
    the engine into J.A.N.E.T. ONE). Folds three hand-run scripts into one
    credential-aware GUI that drives Windows feature-update work across a fleet
    of remote machines over WinRM:

      1. PIN target release   - writes the WindowsUpdate "TargetReleaseVersion"
         policy (TargetReleaseVersion=1, ProductVersion, TargetReleaseVersionInfo)
         so Windows Update will only offer up to the named feature build
         (default: Windows 11 24H2). Replaces the old Add_reg.txt script.
      2. UNPIN target release - removes those three values and the now-empty
         WindowsUpdate policy key so the machine tracks its normal ring again.
         Replaces the old Del_reg.txt script.
      3. INSTALL feature CAB  - copies a feature-update .cab/.msu to C:\Temp on
         each target and installs it with DISM /Online /Add-Package, optionally
         issuing a delayed reboot. Replaces the 25H2 KB5054156 List.txt pusher.

    Operator conveniences requested:
      - "Set Credentials" button. Empty = current Windows session (CAC/Kerberos);
        set = every operation runs -Credential <that account>.
      - GUI computer-list management: type/paste-to-add, import from a .txt,
        remove/clear, automatic de-dupe. No more editing three .txt files.
      - Live per-host results grid. A .NET ping (latency or Unreachable) runs
        BEFORE the operation, then Status/Detail columns update in real time.

    Threading model (also the contract the JANET ONE port will mirror):
      Worker runspaces from a RunspacePool do ALL the network work and NEVER
      touch a WinForms control. They push immutable update records onto a
      thread-safe ConcurrentQueue. A WinForms.Timer on the UI thread drains the
      queue each tick and writes the grid. This is the only safe way to update
      WinForms from background work (no Control.Invoke marshalling needed).

    Native exit codes: DISM (and shutdown) are launched through
    ProcessStartInfo, NOT the call operator, because PS 5.1 wraps a native
    command's stderr in ErrorRecord objects which Invoke-Command then reports as
    remote errors and corrupts the exit code. ProcessStartInfo bypasses that.
.AUTHOR
    THOMPSON, BRAXTON - 48 CS / SCOO
.VERSION
    0.1.0
.CHANGELOG
    v0.1.0 - 2026-06-16 - Initial standalone bench build. Three hand-run scripts
             (Add_reg / Del_reg target-version pin + the 25H2 CAB+DISM pusher)
             folded into one credential-aware WinForms tool with GUI host
             management, .NET ping pre-check, RunspacePool dispatch, live results
             grid, dry-run, Cancel, and CSV export. PS 5.1 / WinForms.
           - Post-build adversarial review hardening: (1) a run no longer hangs
             if a worker runspace dies without reporting - the poll timer also
             finishes once all runspace handles complete, and any row left
             non-terminal is marked FAILED 'worker ended without result';
             (2) the post-install reboot is launched via ProcessStartInfo and
             its REAL exit code reported, so a blocked/failed reboot reads
             'REBOOT FAILED' instead of a false 'reboot issued'; (3) a reboot
             suppressed by Cancel reads 'REBOOT SKIPPED (cancelled)' instead of
             a plain DONE; (4) C:\Temp creation uses -ErrorAction Stop; fixed the
             dead DWM dark-titlebar type guard ('WUTDwm' -> 'WUT.Dwm').
           - UI pass: added a live "What this does" panel that explains the
             selected operation in plain language (esp. Pin), plain-language
             radio labels, and hover tooltips. Rebuilt the config column on
             nested docking (Top stack / Bottom action bar / Fill host list) -
             this also fixes a layout bug where the computer list computed to a
             negative height in the original fixed-pixel layout. Companion
             how-to: WindowsUpgradeTool_HOWTO.md.
           - Second-review fixes: (1) Add-Computers now strips '#' comments per
             line BEFORE tokenizing, so an imported "# header" line no longer
             leaks its words in as bogus hostnames; (2) taller default window +
             chrome-aware MinimumSize so the computer list stays usable down to
             the smallest size (the prior min could collapse the list to 0 rows);
             (3) the progress count label is reconciled to total when the
             handle-backstop finishes a run.
           - Cleanup + UX pass: de-duped the text-input styling into Set-DarkInput
             and dropped the redundant '| Out-String' in the DISM/shutdown output
             capture (no behavior change). New guardrails/UX: Add-Computers now
             rejects tokens that are not bare host/IP names (logs how many were
             skipped); Delete key removes selected computers; Clear asks for
             confirmation; RUN and Test Ping are disabled until the list has at
             least one target; DataGridView cell tooltips are enabled so long
             Detail text is readable on hover.
           - Scenario chooser: a "I'm doing: [24H2 upgrade | 25H2 update]"
             dropdown at the top of the config column. Picking a scenario shows
             its numbered step-by-step in the (renamed) "Guide" panel and
             pre-selects the matching operation + defaults (Pin/Windows 11/24H2,
             or Install CAB + Reboot). The Guide panel is now a scrollable
             read-only TextBox; Manual mode keeps the per-operation explanation.
             Changing the operation by hand drops the chooser back to Manual.
#>

# --- Requires Windows PowerShell 5.1, WinRM enabled on targets, run elevated ---

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}

# ============================================================================
#  STATE (script scope so event handlers + worker submission share it)
# ============================================================================
$script:Cred           = $null     # $null => current Windows session (CAC)
$script:RunspacePool   = $null
$script:Jobs           = New-Object System.Collections.ArrayList   # @{PS;Handle;Host}
$script:UpdateQueue    = $null      # ConcurrentQueue[object] of update records
$script:Sync           = [hashtable]::Synchronized(@{ Cancel = $false })
$script:RowMap         = @{}        # hostname -> DataGridViewRow
$script:Running        = $false
$script:CompletedCount = 0
$script:TotalCount     = 0
$script:ToolVersion    = '0.1.0'
$script:ApplyingScenario = $false   # guard: scenario chooser is setting the op radios

# Step-by-step text surfaced by the Scenario chooser (see Set-GuideText). Built by
# -join so the closing delimiter is never an indented here-string terminator.
$script:Steps24H2 = @(
    '24H2 UPGRADE  -  pin, then let Windows Update install',
    '',
    '1. Set Credentials (ADW account), or leave on the current Windows session.',
    '2. Add your target computers to the Computers list.',
    '3. Operation = Pin. Product = Windows 11, Version = 24H2 (set in the Operation box).',
    '4. Tick Dry-run, RUN, review the grid. Untick Dry-run, RUN for real.',
    '5. On each target: reboot, then Settings > Windows Update > Check for updates.',
    '   Windows Update now offers up to 24H2 and installs it (or it arrives on your',
    '   WSUS / MECM update ring).',
    '6. Verify: winver shows 24H2 (or re-run Test Ping / the grid).',
    '',
    'Note: Pin sets a CEILING; it does not push the install - machines move on their',
    'next Windows Update / MECM check. To later allow 25H2, run Unpin first.'
) -join "`r`n"

$script:Steps25H2 = @(
    '25H2 UPDATE  -  install the 25H2 enablement package KB5054156 (aka the 25H2 upgrade)',
    '',
    '1. Stage the KB5054156 .cab on this admin box (or a share it can read).',
    '2. Set Credentials (ADW account), or leave on the current Windows session.',
    '3. Add your target computers to the Computers list.',
    '4. If the machines are pinned to 24H2, run Unpin first (keeps WU policy consistent;',
    '   DISM installs regardless of the pin).',
    '5. Operation = Install a feature update package: Browse and pick the KB5054156 .cab;',
    '   tick Reboot target ~10s after install.',
    '6. Tick Dry-run, RUN, review. Untick Dry-run, RUN for real.',
    '7. Each target: DISM /Add-Package installs, then reboots. Verify winver = 25H2.'
) -join "`r`n"

# ============================================================================
#  THEME (JANET dark + purple/gold, matching WPT / Remote Restart Scheduler)
# ============================================================================
$Theme = @{
    Background    = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    Sidebar       = [System.Drawing.Color]::FromArgb(  7,   7,  11)
    TopBar        = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Panel         = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    Input         = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    OutputBg      = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Border        = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    TextPrimary   = [System.Drawing.Color]::FromArgb(240, 240, 245)
    TextSecondary = [System.Drawing.Color]::FromArgb(170, 168, 180)
    TextDim       = [System.Drawing.Color]::FromArgb(110, 106, 125)
    Accent        = [System.Drawing.Color]::FromArgb(140, 100, 220)
    AccentHover   = [System.Drawing.Color]::FromArgb(164, 128, 240)
    AccentDim     = [System.Drawing.Color]::FromArgb( 96,  68, 156)
    Success       = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    Warning       = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger        = [System.Drawing.Color]::FromArgb(224,  80,  90)
    DangerHover   = [System.Drawing.Color]::FromArgb(240, 104, 114)
    Cyan          = [System.Drawing.Color]::FromArgb( 88, 180, 210)
    Gold          = [System.Drawing.Color]::FromArgb(218, 180,  82)
}

# ============================================================================
#  IMMERSIVE DARK TITLE BAR (same DwmSetWindowAttribute trick the suite uses)
# ============================================================================
if (-not ('WUT.Dwm' -as [type])) {
    Add-Type -Namespace WUT -Name Dwm -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
}
function Set-DarkTitleBar($frm) {
    try {
        $on = 1
        [WUT.Dwm]::DwmSetWindowAttribute($frm.Handle, 20, [ref]$on, 4) | Out-Null  # Win10 2004+
        [WUT.Dwm]::DwmSetWindowAttribute($frm.Handle, 19, [ref]$on, 4) | Out-Null  # older builds
    } catch {}
}

# ============================================================================
#  WORKER SCRIPTBLOCK (runs in a RunspacePool runspace - NEVER touches the UI)
#  param order MUST match the AddArgument order in Start-Run exactly.
# ============================================================================
$script:Worker = {
    param(
        [string]$Computer,
        [string]$Op,            # Ping | Pin | Unpin | InstallCab
        $Cred,                  # PSCredential or $null
        [string]$TargetVer,
        [string]$ProductName,
        [string]$CabPath,
        [string]$CabName,
        [bool]$Reboot,
        [bool]$AttemptOffline,
        [bool]$DryRun,
        $Queue,                 # ConcurrentQueue[object]
        $Sync                   # synchronized hashtable (Cancel flag)
    )

    $pingText = ''
    # Nested helper: enqueue one update record. Reads $Queue/$Computer/$pingText
    # from the enclosing scope at call time (PowerShell dynamic scoping).
    function Send($status, $detail, $done) {
        $Queue.Enqueue([pscustomobject]@{
            Computer = $Computer
            Ping     = $pingText
            Status   = $status
            Detail   = $detail
            Done     = [bool]$done
        })
    }

    # A cancel that landed while this host was still queued: bail immediately.
    if ($Sync['Cancel'] -and $Op -ne 'Ping') {
        Send 'Cancelled' 'Cancelled before start' $true
        return
    }

    # ---- Ping pre-check: .NET Ping with a fixed 1s timeout (crisp, no hang) --
    $online = $false
    try {
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $reply  = $pinger.Send($Computer, 1000)
        if ($reply -and $reply.Status -eq 'Success') {
            $pingText = "$($reply.RoundtripTime) ms"
            $online   = $true
        } else {
            $pingText = 'Unreachable'
        }
    } catch {
        $pingText = 'DNS/error'
    }

    if ($Op -eq 'Ping') {
        if ($online) { Send 'Online'  "ICMP reply in $pingText" $true }
        else         { Send 'Offline' 'No ICMP reply (1s timeout)' $true }
        return
    }

    Send 'Pinged' '' $false

    if (-not $online -and -not $AttemptOffline) {
        Send 'Skipped' 'Offline (ping failed). Tick "Attempt even if offline" to force.' $true
        return
    }

    $authNote = if ($null -ne $Cred) { "as $($Cred.UserName)" } else { 'current session' }

    try {
        switch ($Op) {

            'Pin' {
                if ($DryRun) {
                    Send 'DRY-RUN' "Would pin Windows Update target to $ProductName $TargetVer ($authNote)." $true
                    break
                }
                Send 'Working' "Writing TargetReleaseVersion policy ($ProductName $TargetVer)..." $false
                $sb = {
                    param($tv, $prod)
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -PropertyType DWord  -Value 1    -Force | Out-Null
                    New-ItemProperty -Path $regPath -Name 'ProductVersion'           -PropertyType String -Value $prod -Force | Out-Null
                    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -PropertyType String -Value $tv   -Force | Out-Null
                    "ProductVersion=$prod; TargetReleaseVersionInfo=$tv"
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000
                $ic = @{
                    ComputerName   = $Computer
                    ScriptBlock    = $sb
                    ArgumentList   = @($TargetVer, $ProductName)
                    Authentication = 'Negotiate'
                    SessionOption  = $so
                    ErrorAction    = 'Stop'
                }
                if ($null -ne $Cred) { $ic.Credential = $Cred }
                $out = Invoke-Command @ic
                Send 'DONE' "Pinned: $out. Reboot target, then run Check for updates." $true
            }

            'Unpin' {
                if ($DryRun) {
                    Send 'DRY-RUN' "Would remove the TargetReleaseVersion policy ($authNote)." $true
                    break
                }
                Send 'Working' 'Removing TargetReleaseVersion policy...' $false
                $sb = {
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                    if (Test-Path $regPath) {
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'ProductVersion'           -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -ErrorAction SilentlyContinue
                        $remaining = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).PSObject.Properties |
                            Where-Object { $_.Name -notlike 'PS*' }
                        if (-not $remaining) {
                            Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                            'policy values removed; empty WindowsUpdate key removed'
                        } else {
                            'policy values removed; key kept (other values present)'
                        }
                    } else {
                        'policy key not present (nothing to remove)'
                    }
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000
                $ic = @{
                    ComputerName   = $Computer
                    ScriptBlock    = $sb
                    Authentication = 'Negotiate'
                    SessionOption  = $so
                    ErrorAction    = 'Stop'
                }
                if ($null -ne $Cred) { $ic.Credential = $Cred }
                $out = Invoke-Command @ic
                Send 'DONE' "$out" $true
            }

            'InstallCab' {
                if ($DryRun) {
                    $rb = if ($Reboot) { 'then reboot (10s delay)' } else { 'no reboot' }
                    Send 'DRY-RUN' "Would copy $CabName to C:\Temp and run DISM /Add-Package; $rb ($authNote)." $true
                    break
                }
                Send 'Working' 'Opening remote session...' $false
                # OperationTimeout 0 = no per-operation cap (DISM can run for minutes).
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000
                $sp = @{
                    ComputerName   = $Computer
                    Authentication = 'Negotiate'
                    SessionOption  = $so
                    ErrorAction    = 'Stop'
                }
                if ($null -ne $Cred) { $sp.Credential = $Cred }
                $session = New-PSSession @sp
                try {
                    Send 'Working' 'Ensuring C:\Temp exists...' $false
                    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                        if (-not (Test-Path -Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -ErrorAction Stop | Out-Null }
                    }

                    Send 'Working' "Copying $CabName to C:\Temp..." $false
                    Copy-Item -Path $CabPath -Destination 'C:\Temp\' -ToSession $session -Force -ErrorAction Stop

                    Send 'Working' 'Installing with DISM /Add-Package...' $false
                    $res = Invoke-Command -Session $session -ArgumentList $CabName -ScriptBlock {
                        param($name)
                        $cab = Join-Path 'C:\Temp' $name
                        $o = @{ ExitCode = $null; Output = ''; Error = '' }
                        try {
                            # ProcessStartInfo (not & dism) - see header note on PS 5.1
                            # stderr-wrapping corrupting native exit codes.
                            $psi = New-Object System.Diagnostics.ProcessStartInfo
                            $psi.FileName               = 'dism.exe'
                            $psi.Arguments              = "/Online /Add-Package /PackagePath:`"$cab`" /Quiet /NoRestart"
                            $psi.UseShellExecute        = $false
                            $psi.RedirectStandardOutput = $true
                            $psi.RedirectStandardError  = $true
                            $psi.CreateNoWindow         = $true
                            $p = [System.Diagnostics.Process]::Start($psi)
                            $stdout = $p.StandardOutput.ReadToEnd()
                            $stderr = $p.StandardError.ReadToEnd()
                            $p.WaitForExit()
                            $o.ExitCode = $p.ExitCode
                            $o.Output   = ($stdout + $stderr).Trim()
                        } catch {
                            $o.Error = $_.Exception.Message
                        }
                        return $o
                    }

                    if ($res.Error) {
                        Send 'FAILED' "DISM launch error: $($res.Error)" $true
                    }
                    elseif ($res.ExitCode -eq 0 -or $res.ExitCode -eq 3010) {
                        $note = if ($res.ExitCode -eq 3010) { 'installed (reboot required)' } else { 'installed (exit 0)' }
                        if ($Reboot -and -not $Sync['Cancel']) {
                            Send 'Working' "$note; issuing reboot (10s)..." $false
                            # Delayed reboot via shutdown.exe run through ProcessStartInfo so we
                            # capture its REAL exit code - the /t 10 lets the WinRM call return
                            # BEFORE the box goes down (clean session teardown). We report the
                            # actual reboot result rather than assuming it was issued.
                            try {
                                $rb = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                                    $o = @{ ExitCode = $null; Error = '' }
                                    try {
                                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                                        $psi.FileName               = 'shutdown.exe'
                                        $psi.Arguments              = '/r /t 10 /f /c "JANET Windows Upgrade Tool: feature update installed"'
                                        $psi.UseShellExecute        = $false
                                        $psi.RedirectStandardOutput = $true
                                        $psi.RedirectStandardError  = $true
                                        $psi.CreateNoWindow         = $true
                                        $sp = [System.Diagnostics.Process]::Start($psi)
                                        $sout = $sp.StandardOutput.ReadToEnd()
                                        $serr = $sp.StandardError.ReadToEnd()
                                        $sp.WaitForExit()
                                        $o.ExitCode = $sp.ExitCode
                                        if ($sp.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                                    } catch {
                                        $o.Error = $_.Exception.Message
                                    }
                                    return $o
                                }
                                if ($rb.ExitCode -eq 0) {
                                    Send 'DONE' "$CabName $note; reboot issued (10s)" $true
                                } else {
                                    Send 'DONE' "$CabName $note; REBOOT FAILED (shutdown exit $($rb.ExitCode)): $($rb.Error)" $true
                                }
                            } catch {
                                Send 'DONE' "$CabName $note; REBOOT FAILED to issue: $($_.Exception.Message)" $true
                            }
                        }
                        elseif ($Reboot -and $Sync['Cancel']) {
                            Send 'DONE' "$CabName $note; REBOOT SKIPPED (cancelled)" $true
                        }
                        else {
                            Send 'DONE' "$CabName $note" $true
                        }
                    }
                    else {
                        $msg = [string]$res.Output
                        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) }
                        Send 'FAILED' "DISM exit $($res.ExitCode): $msg" $true
                    }
                }
                finally {
                    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
                }
            }
        }
    }
    catch {
        Send 'FAILED' $_.Exception.Message $true
    }
}

# ============================================================================
#  SMALL UI HELPERS
# ============================================================================
function New-FlatButton([string]$text, [int]$x, [int]$y, [int]$w, [int]$h, $back, $fore, $hover) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text     = $text
    $b.Location = New-Object System.Drawing.Point($x, $y)
    $b.Size     = New-Object System.Drawing.Size($w, $h)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    if ($hover) { $b.FlatAppearance.MouseOverBackColor = $hover }
    $b.BackColor = $back
    $b.ForeColor = $fore
    $b.Font   = New-Object System.Drawing.Font('Segoe UI', 9)
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $b
}
function New-Label([string]$text, [int]$x, [int]$y, [int]$w, [int]$h, $fore) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Location = New-Object System.Drawing.Point($x, $y)
    $l.Size = New-Object System.Drawing.Size($w, $h)
    $l.ForeColor = $fore
    $l.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    return $l
}
function Set-DarkInput($ctrl) {
    # Shared styling for the text inputs (de-dups the repeated 3-line block).
    $ctrl.BackColor = $Theme.Input
    $ctrl.ForeColor = $Theme.TextPrimary
    $ctrl.BorderStyle = 'FixedSingle'
}

# ============================================================================
#  FORM + LAYOUT
# ============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text          = "J.A.N.E.T. - Windows Upgrade Tool  (v$($script:ToolVersion) bench build)"
$form.StartPosition = 'CenterScreen'
$form.ClientSize    = New-Object System.Drawing.Size(1100, 986)
$form.MinimumSize   = New-Object System.Drawing.Size(1000, 966)   # outer; refined on Shown
$form.BackColor     = $Theme.Background
$form.ForeColor     = $Theme.TextPrimary
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9)

$cfgW = 460   # config column width
$logH = 120   # bottom log panel height

# ---- bottom log panel (docked Bottom, full width) --------------------------
$pnlLog = New-Object System.Windows.Forms.Panel
$pnlLog.Dock      = 'Bottom'
$pnlLog.Height    = $logH
$pnlLog.BackColor = $Theme.TopBar

$lblProg = New-Label '0 / 0' 12 10 220 18 $Theme.TextSecondary
$lblProg.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$pnlLog.Controls.Add($lblProg)

$pb = New-Object System.Windows.Forms.ProgressBar
$pb.Location = New-Object System.Drawing.Point(238, 10)
$pb.Size     = New-Object System.Drawing.Size(($form.ClientSize.Width - 360), 18)
$pb.Style    = 'Continuous'
$pb.Anchor   = 'Top,Left,Right'
$pb.Maximum  = 100
$pnlLog.Controls.Add($pb)

$btnExport = New-FlatButton 'Export CSV' ($form.ClientSize.Width - 112) 6 100 26 $Theme.Input $Theme.TextPrimary $Theme.Border
$btnExport.Anchor = 'Top,Right'
$pnlLog.Controls.Add($btnExport)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location   = New-Object System.Drawing.Point(12, 36)
$txtLog.Size       = New-Object System.Drawing.Size(($form.ClientSize.Width - 24), ($logH - 46))
$txtLog.Multiline  = $true
$txtLog.ReadOnly   = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.BackColor  = $Theme.OutputBg
$txtLog.ForeColor  = $Theme.TextSecondary
$txtLog.BorderStyle = 'FixedSingle'
$txtLog.Font       = New-Object System.Drawing.Font('Consolas', 9)
$txtLog.Anchor     = 'Top,Left,Right,Bottom'
$pnlLog.Controls.Add($txtLog)

# ---- left config column (docked Left, full remaining height) ----------------
# Built with nested docking (Top stack / Bottom action bar / Fill host list) so
# the host list absorbs spare space. The fixed top stack (~522px) + log panel
# bound how small the list can get, so MinimumSize is chosen (and refined on
# Shown for the real titlebar/border chrome) to keep the list usable at the floor.
$pnlConfig = New-Object System.Windows.Forms.Panel
$pnlConfig.Dock      = 'Left'
$pnlConfig.Width     = $cfgW
$pnlConfig.BackColor = $Theme.Sidebar

# Shared tooltip for plain-language hover help
$tip = New-Object System.Windows.Forms.ToolTip
$tip.AutoPopDelay = 30000; $tip.InitialDelay = 350; $tip.ReshowDelay = 100

# ===== fixed top stack ======================================================
$pnlCfgTop = New-Object System.Windows.Forms.Panel
$pnlCfgTop.Dock = 'Top'
$pnlCfgTop.Height = 578
$pnlCfgTop.BackColor = $Theme.Sidebar

# Scenario chooser (drives the Guide panel + pre-selects the matching operation).
# A slim selector at the very top: "I'm doing: [ 24H2 upgrade | 25H2 update ]".
$grpScenario = New-Object System.Windows.Forms.GroupBox
$grpScenario.Text = 'Scenario'
$grpScenario.Location = New-Object System.Drawing.Point(14, 8)
$grpScenario.Size = New-Object System.Drawing.Size(432, 50)
$grpScenario.ForeColor = $Theme.Gold
$lblScenario = New-Label "I'm doing:" 14 22 66 20 $Theme.TextSecondary
$cmbScenario = New-Object System.Windows.Forms.ComboBox
$cmbScenario.Location = New-Object System.Drawing.Point(84, 19)
$cmbScenario.Size = New-Object System.Drawing.Size(334, 24)
$cmbScenario.DropDownStyle = 'DropDownList'
$cmbScenario.FlatStyle = 'Flat'
$cmbScenario.BackColor = $Theme.Input
$cmbScenario.ForeColor = $Theme.TextPrimary
[void]$cmbScenario.Items.Add('-- Manual (pick an operation below) --')
[void]$cmbScenario.Items.Add('24H2 upgrade  -  Pin to Windows 11 24H2')
[void]$cmbScenario.Items.Add('25H2 update  -  Install KB5054156 (25H2 enablement)')
$tip.SetToolTip($cmbScenario, "Pick the job you are doing to see its step-by-step in the Guide panel`r`nand pre-select the matching operation. Leave on Manual to drive the operations yourself.")
$grpScenario.Controls.AddRange(@($lblScenario, $cmbScenario))
$pnlCfgTop.Controls.Add($grpScenario)

# Credentials group
$grpCred = New-Object System.Windows.Forms.GroupBox
$grpCred.Text = 'Credentials'
$grpCred.Location = New-Object System.Drawing.Point(14, 64)
$grpCred.Size = New-Object System.Drawing.Size(432, 72)
$grpCred.ForeColor = $Theme.Gold
$btnSetCred = New-FlatButton 'Set Credentials...' 14 22 150 28 $Theme.Accent $Theme.TextPrimary $Theme.AccentHover
$btnClearCred = New-FlatButton 'Use Session' 174 22 120 28 $Theme.Input $Theme.TextPrimary $Theme.Border
$lblCred = New-Label 'Auth: current Windows session' 14 52 404 16 $Theme.TextSecondary
$tip.SetToolTip($btnSetCred, "Run every operation as a specific account (e.g. a domain admin).`nLeave unset to use the account this tool is already running as.")
$tip.SetToolTip($btnClearCred, 'Forget the saved account and go back to the current Windows session.')
$grpCred.Controls.AddRange(@($btnSetCred, $btnClearCred, $lblCred))
$pnlCfgTop.Controls.Add($grpCred)

# Operation group
$grpOp = New-Object System.Windows.Forms.GroupBox
$grpOp.Text = 'Operation'
$grpOp.Location = New-Object System.Drawing.Point(14, 142)
$grpOp.Size = New-Object System.Drawing.Size(432, 210)
$grpOp.ForeColor = $Theme.Gold

$rbPin = New-Object System.Windows.Forms.RadioButton
$rbPin.Text = 'Pin to a feature version (stay on / hold at)'
$rbPin.Location = New-Object System.Drawing.Point(14, 24)
$rbPin.Size = New-Object System.Drawing.Size(400, 20)
$rbPin.ForeColor = $Theme.TextPrimary
$rbPin.Checked = $true

$lblProduct = New-Label 'Product:' 34 50 60 20 $Theme.TextSecondary
$txtProduct = New-Object System.Windows.Forms.TextBox
$txtProduct.Location = New-Object System.Drawing.Point(98, 48)
$txtProduct.Size = New-Object System.Drawing.Size(140, 22)
$txtProduct.Text = 'Windows 11'
Set-DarkInput $txtProduct

$lblVer = New-Label 'Version:' 252 50 52 20 $Theme.TextSecondary
$txtVersion = New-Object System.Windows.Forms.TextBox
$txtVersion.Location = New-Object System.Drawing.Point(306, 48)
$txtVersion.Size = New-Object System.Drawing.Size(108, 22)
$txtVersion.Text = '24H2'
Set-DarkInput $txtVersion

$rbUnpin = New-Object System.Windows.Forms.RadioButton
$rbUnpin.Text = 'Unpin (remove the version hold)'
$rbUnpin.Location = New-Object System.Drawing.Point(14, 82)
$rbUnpin.Size = New-Object System.Drawing.Size(400, 20)
$rbUnpin.ForeColor = $Theme.TextPrimary

$rbCab = New-Object System.Windows.Forms.RadioButton
$rbCab.Text = 'Install a feature update package (CAB/MSU via DISM)'
$rbCab.Location = New-Object System.Drawing.Point(14, 112)
$rbCab.Size = New-Object System.Drawing.Size(400, 20)
$rbCab.ForeColor = $Theme.TextPrimary

$lblCab = New-Label 'CAB:' 34 140 36 20 $Theme.TextSecondary
$txtCab = New-Object System.Windows.Forms.TextBox
$txtCab.Location = New-Object System.Drawing.Point(72, 138)
$txtCab.Size = New-Object System.Drawing.Size(258, 22)
Set-DarkInput $txtCab
$btnBrowse = New-FlatButton 'Browse' 336 137 78 24 $Theme.Input $Theme.TextPrimary $Theme.Border

$chkReboot = New-Object System.Windows.Forms.CheckBox
$chkReboot.Text = 'Reboot target ~10s after install'
$chkReboot.Location = New-Object System.Drawing.Point(72, 168)
$chkReboot.Size = New-Object System.Drawing.Size(342, 20)
$chkReboot.ForeColor = $Theme.TextPrimary
$chkReboot.Checked = $true

$tip.SetToolTip($rbPin,   'Hold these PCs at a chosen Windows feature version. Windows Update will not move them to a newer feature release until you Unpin.')
$tip.SetToolTip($rbUnpin, 'Remove the hold so these PCs follow normal Windows Update again.')
$tip.SetToolTip($rbCab,   'Push a feature-update .cab/.msu and install it with DISM (e.g. the 25H2 enablement package).')
$grpOp.Controls.AddRange(@($rbPin, $lblProduct, $txtProduct, $lblVer, $txtVersion, $rbUnpin, $rbCab, $lblCab, $txtCab, $btnBrowse, $chkReboot))
$pnlCfgTop.Controls.Add($grpOp)

# Guide group: shows the selected scenario's step-by-step, or (Manual) the
# plain-language explanation of the selected operation. Text set by Set-GuideText.
# A read-only multiline TextBox (not a Label) so the longer step lists scroll.
$grpHelp = New-Object System.Windows.Forms.GroupBox
$grpHelp.Text = 'Guide  -  what this does / step-by-step'
$grpHelp.Location = New-Object System.Drawing.Point(14, 358)
$grpHelp.Size = New-Object System.Drawing.Size(432, 130)
$grpHelp.ForeColor = $Theme.Cyan
$txtGuide = New-Object System.Windows.Forms.TextBox
$txtGuide.Location = New-Object System.Drawing.Point(12, 18)
$txtGuide.Size = New-Object System.Drawing.Size(410, 104)
$txtGuide.Multiline = $true
$txtGuide.ReadOnly = $true
$txtGuide.WordWrap = $true
$txtGuide.ScrollBars = 'Vertical'
$txtGuide.BorderStyle = 'None'
$txtGuide.TabStop = $false
$txtGuide.BackColor = $Theme.Sidebar
$txtGuide.ForeColor = $Theme.TextSecondary
$txtGuide.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$grpHelp.Controls.Add($txtGuide)
$pnlCfgTop.Controls.Add($grpHelp)

# Options group
$grpOpts = New-Object System.Windows.Forms.GroupBox
$grpOpts.Text = 'Options'
$grpOpts.Location = New-Object System.Drawing.Point(14, 494)
$grpOpts.Size = New-Object System.Drawing.Size(432, 78)
$grpOpts.ForeColor = $Theme.Gold

$chkDryRun = New-Object System.Windows.Forms.CheckBox
$chkDryRun.Text = 'Dry-run (no changes)'
$chkDryRun.Location = New-Object System.Drawing.Point(14, 22)
$chkDryRun.Size = New-Object System.Drawing.Size(190, 20)
$chkDryRun.ForeColor = $Theme.TextPrimary

$chkOffline = New-Object System.Windows.Forms.CheckBox
$chkOffline.Text = 'Attempt even if offline'
$chkOffline.Location = New-Object System.Drawing.Point(210, 22)
$chkOffline.Size = New-Object System.Drawing.Size(210, 20)
$chkOffline.ForeColor = $Theme.TextPrimary

$lblThreads = New-Label 'Max concurrent:' 14 50 110 20 $Theme.TextSecondary
$numThreads = New-Object System.Windows.Forms.NumericUpDown
$numThreads.Location = New-Object System.Drawing.Point(128, 48)
$numThreads.Size = New-Object System.Drawing.Size(64, 22)
$numThreads.Minimum = 1
$numThreads.Maximum = 64
$numThreads.Value = 16
$numThreads.BackColor = $Theme.Input; $numThreads.ForeColor = $Theme.TextPrimary
$tip.SetToolTip($chkDryRun, 'Walk through every step and report what WOULD happen, without changing any target.')
$tip.SetToolTip($chkOffline, 'By default offline PCs are skipped. Tick to try the operation anyway.')
$grpOpts.Controls.AddRange(@($chkDryRun, $chkOffline, $lblThreads, $numThreads))
$pnlCfgTop.Controls.Add($grpOpts)

# ===== bottom action bar ====================================================
$pnlCfgBottom = New-Object System.Windows.Forms.Panel
$pnlCfgBottom.Dock = 'Bottom'
$pnlCfgBottom.Height = 52
$pnlCfgBottom.BackColor = $Theme.Sidebar
$btnPing   = New-FlatButton 'Test Ping' 14  10 130 32 $Theme.Input  $Theme.Cyan        $Theme.Border
$btnRun    = New-FlatButton 'RUN'       152 10 168 32 $Theme.Accent $Theme.TextPrimary $Theme.AccentHover
$btnCancel = New-FlatButton 'Cancel'    328 10 118 32 $Theme.Danger $Theme.TextPrimary $Theme.DangerHover
$btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnCancel.Enabled = $false
$tip.SetToolTip($btnPing, 'Connectivity test only - ping every computer, change nothing.')
$tip.SetToolTip($btnRun, 'Run the selected operation against every computer in the list.')
$pnlCfgBottom.Controls.AddRange(@($btnPing, $btnRun, $btnCancel))

# ===== computers group (fills the middle) ===================================
$grpHosts = New-Object System.Windows.Forms.GroupBox
$grpHosts.Text = 'Computers'
$grpHosts.Dock = 'Fill'
$grpHosts.ForeColor = $Theme.Gold
$grpHosts.Padding = New-Object System.Windows.Forms.Padding(12, 4, 12, 8)

# bottom strip inside the group: add / import / remove / clear + count
$pnlHostBtns = New-Object System.Windows.Forms.Panel
$pnlHostBtns.Dock = 'Bottom'
$pnlHostBtns.Height = 64
$pnlHostBtns.BackColor = $Theme.Sidebar

$txtAddHost = New-Object System.Windows.Forms.TextBox
$txtAddHost.Location = New-Object System.Drawing.Point(2, 6)
$txtAddHost.Size = New-Object System.Drawing.Size(226, 22)
Set-DarkInput $txtAddHost
$txtAddHost.Anchor = 'Top,Left,Right'

$btnAdd    = New-FlatButton 'Add'    234 5 76 24 $Theme.Accent $Theme.TextPrimary $Theme.AccentHover
$btnImport = New-FlatButton 'Import' 318 5 82 24 $Theme.Input  $Theme.TextPrimary $Theme.Border
$btnAdd.Anchor = 'Top,Right'; $btnImport.Anchor = 'Top,Right'

$lblHostCount = New-Label '0 computers' 2 40 200 18 $Theme.TextSecondary
$btnRemove = New-FlatButton 'Remove' 234 38 76 22 $Theme.Input $Theme.TextPrimary $Theme.Border
$btnClear  = New-FlatButton 'Clear'  318 38 82 22 $Theme.Input $Theme.TextPrimary $Theme.Border
$btnRemove.Anchor = 'Top,Right'; $btnClear.Anchor = 'Top,Right'
$tip.SetToolTip($txtAddHost, "Type or paste computer names (spaces, commas or new lines all work), then Add.`nLines starting with # are ignored.")
$tip.SetToolTip($btnImport, 'Load computer names from a .txt file (one per line).')
$pnlHostBtns.Controls.AddRange(@($txtAddHost, $btnAdd, $btnImport, $lblHostCount, $btnRemove, $btnClear))

$lstComputers = New-Object System.Windows.Forms.ListBox
$lstComputers.Dock = 'Fill'
$lstComputers.SelectionMode = 'MultiExtended'
$lstComputers.BackColor = $Theme.Input
$lstComputers.ForeColor = $Theme.TextPrimary
$lstComputers.BorderStyle = 'FixedSingle'
$lstComputers.IntegralHeight = $false

# add Fill first, then Bottom, so the list claims whatever space is left
$grpHosts.Controls.Add($lstComputers)
$grpHosts.Controls.Add($pnlHostBtns)

# Assemble: Fill added first (docks last), then Bottom bar, then Top stack.
$pnlConfig.Controls.Add($grpHosts)
$pnlConfig.Controls.Add($pnlCfgBottom)
$pnlConfig.Controls.Add($pnlCfgTop)

# ---- results grid (fills the remaining center/right) ------------------------
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.ReadOnly = $true
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $true
$grid.ShowCellToolTips = $true   # truncated Detail cells show full text on hover
$grid.AutoSizeColumnsMode = 'None'
$grid.BackgroundColor = $Theme.OutputBg
$grid.GridColor = $Theme.Border
$grid.BorderStyle = 'None'
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = $Theme.TopBar
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.Gold
$grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.ColumnHeadersHeight = 28
$grid.DefaultCellStyle.BackColor = $Theme.Panel
$grid.DefaultCellStyle.ForeColor = $Theme.TextPrimary
$grid.DefaultCellStyle.SelectionBackColor = $Theme.AccentDim
$grid.DefaultCellStyle.SelectionForeColor = $Theme.TextPrimary
$grid.RowsDefaultCellStyle.BackColor = $Theme.Panel
$grid.AlternatingRowsDefaultCellStyle.BackColor = $Theme.Input

$colComputer = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colComputer.Name = 'colComputer'; $colComputer.HeaderText = 'Computer'; $colComputer.Width = 170
$colPing = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPing.Name = 'colPing'; $colPing.HeaderText = 'Ping'; $colPing.Width = 90
$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.Name = 'colStatus'; $colStatus.HeaderText = 'Status'; $colStatus.Width = 100
$colDetail = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDetail.Name = 'colDetail'; $colDetail.HeaderText = 'Detail'; $colDetail.AutoSizeMode = 'Fill'; $colDetail.FillWeight = 100
[void]$grid.Columns.Add($colComputer)
[void]$grid.Columns.Add($colPing)
[void]$grid.Columns.Add($colStatus)
[void]$grid.Columns.Add($colDetail)

# Add docked controls so the Fill grid claims the remaining space last.
# (WinForms docks in reverse z-order: last added is docked first against its edge.)
$form.Controls.Add($grid)
$form.Controls.Add($pnlConfig)
$form.Controls.Add($pnlLog)

# ============================================================================
#  CORE FUNCTIONS
# ============================================================================
function Add-Log([string]$msg) {
    $ts = [DateTime]::Now.ToString('HH:mm:ss')
    $txtLog.AppendText("[$ts] $msg`r`n")
}

function Sync-HostCount {
    $lblHostCount.Text = "$($lstComputers.Items.Count) computers"
    # Keep RUN / Test Ping disabled until there is at least one target.
    if (-not $script:Running) {
        $hasHosts = $lstComputers.Items.Count -gt 0
        $btnRun.Enabled  = $hasHosts
        $btnPing.Enabled = $hasHosts
    }
}

function Remove-SelectedHosts {
    if ($script:Running) { return }
    for ($i = $lstComputers.SelectedIndices.Count - 1; $i -ge 0; $i--) {
        $lstComputers.Items.RemoveAt($lstComputers.SelectedIndices[$i])
    }
    Sync-HostCount
}

function Add-Computers([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    # Comments first: '#' starts a comment to end-of-line (a full '# header' line
    # OR a trailing 'host1 # note'). '#' is not a legal host char, so this is safe.
    # Only THEN tokenize the remainder on whitespace / comma / semicolon.
    $parts = New-Object System.Collections.Generic.List[string]
    $skipped = 0
    foreach ($line in ($text -split '\r?\n')) {
        $l = $line
        $hash = $l.IndexOf('#')
        if ($hash -ge 0) { $l = $l.Substring(0, $hash) }
        $l = $l.Trim()
        if (-not $l) { continue }
        foreach ($tok in ($l -split '[\s,;]+')) {
            $t = $tok.Trim()
            if (-not $t) { continue }
            # Accept only a bare host/IP token; reject pasted junk such as UNC
            # paths, URLs, or email addresses rather than adding them as targets.
            if ($t -match '^[A-Za-z0-9._-]+$') { [void]$parts.Add($t) }
            else { $skipped++ }
        }
    }
    $existing = @($lstComputers.Items | ForEach-Object { $_.ToString().ToLowerInvariant() })
    $added = 0
    foreach ($p in $parts) {
        $key = $p.ToLowerInvariant()
        if ($existing -notcontains $key) {
            [void]$lstComputers.Items.Add($p)
            $existing += $key
            $added++
        }
    }
    Sync-HostCount
    if ($added)   { Add-Log "Added $added computer(s)." }
    if ($skipped) { Add-Log "Skipped $skipped invalid name(s)." }
}

function Set-StatusColor($row, [string]$status) {
    $c = switch -Wildcard ($status) {
        'DONE'      { $Theme.Success }
        'Online'    { $Theme.Success }
        'DRY-RUN'   { $Theme.Gold }
        'FAILED'    { $Theme.Danger }
        'Offline'   { $Theme.Danger }
        'Skipped'   { $Theme.Warning }
        'Cancelled' { $Theme.Warning }
        'Working'   { $Theme.Cyan }
        'Pinged'    { $Theme.TextSecondary }
        'Queued'    { $Theme.TextDim }
        default     { $Theme.TextPrimary }
    }
    $row.Cells['colStatus'].Style.ForeColor = $c
}

function Set-GuideText {
    # The Scenario chooser drives this panel: index 1/2 show a scenario's
    # step-by-step; Manual (index 0 / -1) shows the plain-language explanation of
    # the operation currently selected in the Operation box.
    $idx = if ($cmbScenario) { $cmbScenario.SelectedIndex } else { 0 }
    if ($idx -eq 1) { $txtGuide.Text = $script:Steps24H2; $txtGuide.Select(0, 0); return }
    if ($idx -eq 2) { $txtGuide.Text = $script:Steps25H2; $txtGuide.Select(0, 0); return }

    if ($rbPin.Checked) {
        $txtGuide.Text =
            "PIN = hold these PCs at a feature version. It writes the Windows Update for " +
            "Business 'Target Release Version' policy, so Windows Update will keep offering " +
            "monthly quality/security fixes but will NOT move the PC to a newer feature " +
            "release (e.g. it stays on Windows 11 24H2 and refuses 25H2) until you Unpin. " +
            "Set Product (e.g. Windows 11) and Version (e.g. 24H2) to the build you want them held at."
    }
    elseif ($rbUnpin.Checked) {
        $txtGuide.Text =
            "UNPIN = release the hold. It removes that 'Target Release Version' policy so the " +
            "PC follows its normal Windows Update path again and can move up to newer feature " +
            "builds. Run this to reverse a Pin before you roll out a newer version."
    }
    else {
        $txtGuide.Text =
            "INSTALL = push a feature-update package. It copies the selected .cab/.msu to " +
            "C:\Temp on each PC and installs it with DISM /Add-Package (e.g. the 25H2 " +
            "enablement package). With the box ticked, each PC reboots ~10s after a " +
            "successful install. This changes the OS build directly - it does NOT respect a Pin."
    }
    $txtGuide.Select(0, 0)
}

function Update-OpControls {
    $pin = $rbPin.Checked
    $cab = $rbCab.Checked
    $txtProduct.Enabled = $pin
    $txtVersion.Enabled = $pin
    $txtCab.Enabled = $cab
    $btnBrowse.Enabled = $cab
    $chkReboot.Enabled = $cab
    Set-GuideText
}

function Apply-Scenario([int]$idx) {
    # Map a chosen scenario onto the matching operation + sensible defaults, then
    # refresh the Guide. The ApplyingScenario guard stops the radio CheckedChanged
    # handlers from bouncing the chooser back to Manual while we set them here.
    $script:ApplyingScenario = $true
    try {
        if ($idx -eq 1) {
            $rbPin.Checked   = $true
            $txtProduct.Text = 'Windows 11'
            $txtVersion.Text = '24H2'
        }
        elseif ($idx -eq 2) {
            $rbCab.Checked    = $true
            $chkReboot.Checked = $true
        }
    } finally {
        $script:ApplyingScenario = $false
    }
    Update-OpControls
}

function Set-RunningUI([bool]$running) {
    $btnRun.Enabled = -not $running
    $btnPing.Enabled = -not $running
    $btnCancel.Enabled = $running
    $rbPin.Enabled = -not $running
    $rbUnpin.Enabled = -not $running
    $rbCab.Enabled = -not $running
    $btnSetCred.Enabled = -not $running
    $btnClearCred.Enabled = -not $running
    $btnImport.Enabled = -not $running
    $btnAdd.Enabled = -not $running
    $btnRemove.Enabled = -not $running
    $btnClear.Enabled = -not $running
    $numThreads.Enabled = -not $running
    if (-not $running) { Update-OpControls; Sync-HostCount }
}

function Drain-Queue {
    if (-not $script:UpdateQueue) { return }
    $obj = $null
    while ($script:UpdateQueue.TryDequeue([ref]$obj)) {
        $row = $script:RowMap[$obj.Computer]
        if ($null -ne $row) {
            if ($obj.Ping)   { $row.Cells['colPing'].Value = $obj.Ping }
            if ($obj.Status) {
                $row.Cells['colStatus'].Value = $obj.Status
                Set-StatusColor $row $obj.Status
            }
            if ($null -ne $obj.Detail -and $obj.Detail -ne '') { $row.Cells['colDetail'].Value = $obj.Detail }
        }
        if ($obj.Done) { $script:CompletedCount++ }
    }
}

function Finish-Run {
    try { $timer.Stop() } catch {}
    Drain-Queue   # final sweep of anything still queued
    foreach ($j in $script:Jobs) {
        try { [void]$j.PS.EndInvoke($j.Handle) } catch {}
        try { $j.PS.Dispose() } catch {}
    }
    $script:Jobs.Clear()
    try {
        if ($script:RunspacePool) {
            $script:RunspacePool.Close(); $script:RunspacePool.Dispose(); $script:RunspacePool = $null
        }
    } catch {}
    $script:Running = $false
    Set-RunningUI $false
    $pb.Value = 100
    # Reconcile the count label with the 100% bar (the handle-backstop can finish
    # a run while CompletedCount is still short of total).
    $lblProg.Text = "$($script:TotalCount) / $($script:TotalCount)"

    # Backstop: any row that never received a terminal record (a worker runspace
    # that died before reporting) is marked FAILED so it is visible and counted
    # rather than leaving the run looking incomplete.
    foreach ($r in $grid.Rows) {
        $st = [string]$r.Cells['colStatus'].Value
        if ($st -eq '' -or $st -eq 'Queued' -or $st -eq 'Working' -or $st -eq 'Pinged') {
            $r.Cells['colStatus'].Value = 'FAILED'
            Set-StatusColor $r 'FAILED'
            if ([string]::IsNullOrEmpty([string]$r.Cells['colDetail'].Value)) {
                $r.Cells['colDetail'].Value = 'worker ended without result'
            }
        }
    }

    # Tally from the grid
    $done = 0; $fail = 0; $skip = 0
    foreach ($r in $grid.Rows) {
        switch -Wildcard ([string]$r.Cells['colStatus'].Value) {
            'DONE'      { $done++ }
            'Online'    { $done++ }
            'DRY-RUN'   { $done++ }
            'FAILED'    { $fail++ }
            'Offline'   { $fail++ }
            'Skipped'   { $skip++ }
            'Cancelled' { $skip++ }
        }
    }
    Add-Log "FINISHED. OK=$done  Failed=$fail  Skipped/Cancelled=$skip"
}

function Start-Run([string]$op) {
    if ($script:Running) { return }

    $hosts = @($lstComputers.Items | ForEach-Object { $_.ToString() })
    if ($hosts.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('Add at least one computer first.', 'No targets',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    $dryRun         = $chkDryRun.Checked
    $attemptOffline = $chkOffline.Checked
    $reboot         = $chkReboot.Checked
    $targetVer      = $txtVersion.Text.Trim()
    $productName    = $txtProduct.Text.Trim()
    $cabPath        = $txtCab.Text.Trim()
    $cabName        = ''

    if ($op -eq 'Pin') {
        if ([string]::IsNullOrWhiteSpace($productName) -or [string]::IsNullOrWhiteSpace($targetVer)) {
            [void][System.Windows.Forms.MessageBox]::Show('Product and Version are required to pin a target release.', 'Missing input',
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
    }
    if ($op -eq 'InstallCab') {
        if (-not $dryRun) {
            if ([string]::IsNullOrWhiteSpace($cabPath) -or -not (Test-Path -LiteralPath $cabPath)) {
                [void][System.Windows.Forms.MessageBox]::Show('Select a valid CAB/MSU file to install.', 'Missing package',
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
        }
        if ($cabPath) { $cabName = Split-Path -Leaf $cabPath }
    }

    # Build a friendly operation label + confirmation
    $opLabel = switch ($op) {
        'Pin'        { "PIN to $productName $targetVer" }
        'Unpin'      { 'UNPIN (remove target version policy)' }
        'InstallCab' { "INSTALL $cabName" + $(if ($reboot) { ' + REBOOT' } else { '' }) }
        'Ping'       { 'PING (connectivity test)' }
        default      { $op }
    }
    $credLabel = if ($script:Cred) { "as $($script:Cred.UserName)" } else { 'current Windows session' }
    $mode = if ($dryRun) { ' [DRY-RUN]' } else { '' }

    if ($op -ne 'Ping') {
        $warn = ''
        if ($op -eq 'InstallCab' -and $reboot -and -not $dryRun) {
            $warn = "`r`n`r`nWARNING: targets will REBOOT ~10 seconds after a successful install."
        }
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Operation: $opLabel$mode`r`nTargets: $($hosts.Count)`r`nAuth: $credLabel$warn`r`n`r`nProceed?",
            'Confirm', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    # Build the results grid
    $grid.Rows.Clear()
    $script:RowMap = @{}
    foreach ($h in $hosts) {
        $idx = $grid.Rows.Add($h, '', 'Queued', '')
        $rowObj = $grid.Rows[$idx]
        $script:RowMap[$h] = $rowObj
        Set-StatusColor $rowObj 'Queued'
    }

    # Fresh pool, queue, counters
    $max = [int]$numThreads.Value
    try { if ($script:RunspacePool) { $script:RunspacePool.Close(); $script:RunspacePool.Dispose() } } catch {}
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $script:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $max, $iss, $Host)
    $script:RunspacePool.Open()
    $script:Jobs = New-Object System.Collections.ArrayList
    $script:UpdateQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $script:Sync['Cancel'] = $false
    $script:CompletedCount = 0
    $script:TotalCount = $hosts.Count
    $script:Running = $true
    Set-RunningUI $true
    $pb.Value = 0
    $lblProg.Text = "0 / $($hosts.Count)"
    Add-Log "START $opLabel$mode on $($hosts.Count) target(s) ($credLabel), $max threads."

    foreach ($h in $hosts) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $script:RunspacePool
        [void]$ps.AddScript($script:Worker)
        [void]$ps.AddArgument($h)
        [void]$ps.AddArgument($op)
        [void]$ps.AddArgument($script:Cred)
        [void]$ps.AddArgument($targetVer)
        [void]$ps.AddArgument($productName)
        [void]$ps.AddArgument($cabPath)
        [void]$ps.AddArgument($cabName)
        [void]$ps.AddArgument([bool]$reboot)
        [void]$ps.AddArgument([bool]$attemptOffline)
        [void]$ps.AddArgument([bool]$dryRun)
        [void]$ps.AddArgument($script:UpdateQueue)
        [void]$ps.AddArgument($script:Sync)
        $handle = $ps.BeginInvoke()
        [void]$script:Jobs.Add(@{ PS = $ps; Handle = $handle; Host = $h })
    }

    $timer.Start()
}

function Export-Results {
    if ($grid.Rows.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to export yet.', 'Export',
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV (*.csv)|*.csv'
    $sfd.FileName = "WindowsUpgrade_results_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).csv"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $rows = foreach ($r in $grid.Rows) {
            [pscustomobject]@{
                Computer = $r.Cells['colComputer'].Value
                Ping     = $r.Cells['colPing'].Value
                Status   = $r.Cells['colStatus'].Value
                Detail   = $r.Cells['colDetail'].Value
            }
        }
        $rows | Export-Csv -LiteralPath $sfd.FileName -NoTypeInformation -Encoding UTF8
        Add-Log "Exported $($grid.Rows.Count) row(s) to $($sfd.FileName)"
    }
}

# ============================================================================
#  POLL TIMER (UI thread: drains worker updates into the grid)
# ============================================================================
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    Drain-Queue
    if ($script:TotalCount -gt 0) {
        $val = [int](100 * $script:CompletedCount / $script:TotalCount)
        if ($val -lt 0) { $val = 0 }
        if ($val -gt 100) { $val = 100 }
        $pb.Value = $val
        $lblProg.Text = "$($script:CompletedCount) / $($script:TotalCount)"
    }
    if ($script:Running) {
        if ($script:CompletedCount -ge $script:TotalCount) {
            Finish-Run
        }
        else {
            # Backstop against a worker that ended without enqueuing a terminal
            # record: if every runspace handle has completed, reconcile and finish
            # instead of ticking forever (which would hang the UI in 'Running').
            $allHandlesDone = $script:Jobs.Count -gt 0
            foreach ($j in $script:Jobs) { if (-not $j.Handle.IsCompleted) { $allHandlesDone = $false; break } }
            if ($allHandlesDone) { Finish-Run }
        }
    }
})

# ============================================================================
#  EVENT WIRING
# ============================================================================
$btnSetCred.Add_Click({
    $c = Get-Credential -Message 'Enter credentials for remote operations (Cancel = use current session)'
    if ($c) {
        $script:Cred = $c
        $lblCred.Text = "Auth: $($c.UserName)"
        $lblCred.ForeColor = $Theme.Gold
        Add-Log "Credentials set: $($c.UserName)"
    }
})
$btnClearCred.Add_Click({
    $script:Cred = $null
    $lblCred.Text = 'Auth: current Windows session'
    $lblCred.ForeColor = $Theme.TextSecondary
    Add-Log 'Credentials cleared (using current session).'
})

$btnBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'Update packages (*.cab;*.msu)|*.cab;*.msu|All files (*.*)|*.*'
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtCab.Text = $ofd.FileName }
})

$btnAdd.Add_Click({ Add-Computers $txtAddHost.Text; $txtAddHost.Clear(); $txtAddHost.Focus() })
$txtAddHost.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $_.SuppressKeyPress = $true
        Add-Computers $txtAddHost.Text; $txtAddHost.Clear()
    }
})
$btnImport.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Add-Computers (Get-Content -LiteralPath $ofd.FileName -Raw)
    }
})
$btnRemove.Add_Click({ Remove-SelectedHosts })
$lstComputers.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Delete) { Remove-SelectedHosts }
})
$btnClear.Add_Click({
    if ($lstComputers.Items.Count -gt 0) {
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Remove all $($lstComputers.Items.Count) computer(s) from the list?", 'Clear list',
            [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { $lstComputers.Items.Clear(); Sync-HostCount }
    }
})

# A manual operation change drops the Scenario chooser back to Manual so the Guide
# reflects what the operator is actually doing; scenario-driven changes (guarded by
# ApplyingScenario) just refresh the controls without touching the chooser.
$OnOpRadioChanged = {
    if ($script:ApplyingScenario) { Update-OpControls; return }
    if ($cmbScenario.SelectedIndex -gt 0) { $cmbScenario.SelectedIndex = 0 }   # fires Apply-Scenario 0 -> Update-OpControls
    else { Update-OpControls }
}
$rbPin.Add_CheckedChanged($OnOpRadioChanged)
$rbUnpin.Add_CheckedChanged($OnOpRadioChanged)
$rbCab.Add_CheckedChanged($OnOpRadioChanged)
$cmbScenario.Add_SelectedIndexChanged({ Apply-Scenario $cmbScenario.SelectedIndex })

$btnPing.Add_Click({ Start-Run 'Ping' })
$btnRun.Add_Click({
    $op = if ($rbPin.Checked) { 'Pin' } elseif ($rbUnpin.Checked) { 'Unpin' } elseif ($rbCab.Checked) { 'InstallCab' } else { 'Pin' }
    Start-Run $op
})
$btnCancel.Add_Click({
    if (-not $script:Running) { return }
    $script:Sync['Cancel'] = $true
    $btnCancel.Enabled = $false
    Add-Log 'CANCEL requested - queued targets will skip; in-flight operations finish.'
})
$btnExport.Add_Click({ Export-Results })

$form.Add_FormClosing({
    if ($script:Running) {
        $r = [System.Windows.Forms.MessageBox]::Show('A run is in progress. Cancel it and exit?', 'Busy',
            [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { $_.Cancel = $true; return }
        $script:Sync['Cancel'] = $true
    }
    try { $timer.Stop() } catch {}
    try { foreach ($j in $script:Jobs) { try { $j.PS.Stop() } catch {}; try { $j.PS.Dispose() } catch {} } } catch {}
    try { if ($script:RunspacePool) { $script:RunspacePool.Close(); $script:RunspacePool.Dispose() } } catch {}
})

$form.Add_Shown({
    Set-DarkTitleBar $form
    # MinimumSize is an OUTER size but the layout budget is in CLIENT pixels, so
    # derive the floor from the realized non-client chrome: keep >= ~860px of
    # client height (leaves the host list usable) regardless of DPI/theme.
    try {
        $chrome = $form.Size.Height - $form.ClientSize.Height
        $form.MinimumSize = New-Object System.Drawing.Size(1000, (916 + $chrome))
    } catch {}
    $cmbScenario.SelectedIndex = 0   # default to Manual; fires Apply-Scenario -> seeds the Guide
    Update-OpControls
    Sync-HostCount
    Add-Log "J.A.N.E.T. Windows Upgrade Tool v$($script:ToolVersion) ready. Set credentials (or use current session), add computers, pick an operation, then RUN."
    $form.Activate()
})

[void]$form.ShowDialog()
$form.Dispose()
