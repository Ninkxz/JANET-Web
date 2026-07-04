<#
.SYNOPSIS
    J.A.N.E.T. Launcher - Joint Administration and Network Execution Toolkit.
.DESCRIPTION
    Master launcher for the J.A.N.E.T. tool suite. JSON-driven tool registry,
    auto-discovery, shared credential inheritance (DPAPI-encrypted handoff to
    child tool processes via environment variable), in-app log viewer, config
    editor, process tracking, dark immersive chrome, Purple + Gold on Black
    theme shared across every tool.

    Shared credential flow:
      1. User clicks "Set Creds" in the toolbar.
      2. Get-Credential prompt captures a PSCredential.
      3. Credential is serialized via Export-Clixml (DPAPI-encrypted, user+
         machine scoped) to %LOCALAPPDATA%\JANET\Session\janet_cred.xml.
      4. Launch-Tool spawns each child process via ProcessStartInfo and sets
         JANET_CRED_FILE + JANET_CRED_USER environment variables on the child
         only (not the launcher's own env).
      5. Tools Import-Clixml the file at startup and populate their own
         credential slots. Their own "Set Credentials" buttons remain as
         manual overrides.
      6. On launcher close, the credential file is scrubbed from disk.

    Changelog:
      v3.7.5 - April 2026 - Rebuild after file loss. Purple + Gold on Black
               palette applied (purple #8C64DC structure, gold #DAB452
               highlights, black #08080C surfaces with violet lean). Header
               gets purple+gold gradient glow, gold accent line, gold version
               chip. Toolbar eyebrow labels + Discover button in gold. Tool
               cards keep purple brackets with gold header text.
      v3.7.4 - Per-Monitor-V2 DPI awareness (crisp text + correct WinForms
               measurement), SetCompatibleTextRenderingDefault(false) for
               native TextRenderer. SizeChanged -> Invalidate on every
               custom-Paint panel to kill duplicate-bracket artifacts.
      v3.7.3 - Bumped form to 1040x720 so the right utility cluster has real
               breathing room. Button font switched to Segoe UI Variable
               Display Bold 10pt for crisp native rendering.
      v3.7.2 - Button.Image + TextImageRelation instead of overlay labels
               for the right-cluster icons (no more drift between glyph and
               text across buttons).
      v3.7.1 - Corner-bracket tool cards with numbered index, MDL2 icons,
               pulse status dot, stripe LAUNCH button.
      v3.7.0 - Shared credential system: Set Creds stripe button in the
               toolbar, DPAPI-encrypted handoff file, env-var injection on
               every spawned tool process.
      v3.6.x - Dark tactical visual system, corner-bracket cards, eyebrow
               labels, monospace data + variable body text.
      v3.0.x - JSON-driven config, auto-discover, log viewer.

.NOTES
    Author:   Braxton Thompson | 48CS/SCOO | B.E.A.T. Contractor
    Version:  3.7.5
    Date:     April 2026
#>

# ---------------------------------------------------------------------------
# DPI AWARENESS - MUST run before any HWND is created (before WinForms loads).
# ---------------------------------------------------------------------------
# Per-Monitor-V2 (Win10 1703+) is preferred: crisp text rendering at native
# DPI, correct WinForms measurement. Falls back to V1 Per-Monitor, then to
# legacy SetProcessDPIAware for older Windows.
if (-not ('Janet.Interop.DpiHelper' -as [type])) {
    Add-Type -Namespace 'Janet.Interop' -Name 'DpiHelper' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern int SetProcessDpiAwarenessContext(System.IntPtr value);
public static readonly System.IntPtr PER_MONITOR_AWARE_V2 = new System.IntPtr(-4);
public static readonly System.IntPtr PER_MONITOR_AWARE    = new System.IntPtr(-3);
public static readonly System.IntPtr SYSTEM_AWARE         = new System.IntPtr(-2);
'@
}
$dpiOk = $false
try {
    $rc = [Janet.Interop.DpiHelper]::SetProcessDpiAwarenessContext([Janet.Interop.DpiHelper]::PER_MONITOR_AWARE_V2)
    if ($rc -ne 0) { $dpiOk = $true }
} catch {}
if (-not $dpiOk) {
    try {
        $rc = [Janet.Interop.DpiHelper]::SetProcessDpiAwarenessContext([Janet.Interop.DpiHelper]::PER_MONITOR_AWARE)
        if ($rc -ne 0) { $dpiOk = $true }
    } catch {}
}
if (-not $dpiOk) {
    try { [Janet.Interop.DpiHelper]::SetProcessDPIAware() | Out-Null } catch {}
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# SetCompatibleTextRenderingDefault(false) routes Button/Label text through
# GDI TextRenderer (same ClearType pipeline as native Windows controls).
# The .NET default is true (GDI+ DrawString) which looks softer.
# Must be called before any IWin32Window exists.
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}
[System.Windows.Forms.Application]::EnableVisualStyles()

#region === GLOBALS ===
$script:LauncherVersion = "v3.7.5"
$script:ScriptDir       = $(if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $PWD.Path })
$script:ConfigPath      = Join-Path $script:ScriptDir "JANET_Config.json"
$script:LogDir          = Join-Path $script:ScriptDir "Logs"
$script:RunningProcs    = @{}
$script:CurrentUser     = $env:USERNAME
$script:LogErrorShown   = $false
$script:MissingToolCount= 0
$script:ToolRows        = @()

# Shared credential - persisted DPAPI-encrypted at %LOCALAPPDATA%\JANET\Session
$script:Credential      = $null
$script:CredSessionDir  = Join-Path $env:LOCALAPPDATA "JANET\Session"
$script:CredFile        = Join-Path $script:CredSessionDir "janet_cred.xml"
# Scrub any stale file from a previously crashed launcher.
if (Test-Path $script:CredFile) {
    try { Remove-Item $script:CredFile -Force -EA Stop } catch {}
}

# Ensure log dir exists (fallback to Documents\JANET_Logs).
if (-not (Test-Path $script:LogDir)) {
    try {
        New-Item -Path $script:LogDir -ItemType Directory -Force -EA Stop | Out-Null
    } catch {
        $script:LogDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "JANET_Logs"
        if (-not (Test-Path $script:LogDir)) {
            New-Item -Path $script:LogDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null
        }
    }
}

#endregion

#region === LOGGING ===
$script:LogFile = Join-Path $script:LogDir ("Launcher_{0}_{1}.log" -f $script:CurrentUser, (Get-Date -Format "yyyy-MM-dd"))

function Write-Log {
    param([string]$Action, [string]$Detail = "")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[{0}] [USER: {1}] [{2}] {3}" -f $timestamp, $script:CurrentUser, $Action, $Detail
    try {
        Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8 -EA Stop
    } catch {
        if (-not $script:LogErrorShown) {
            $script:LogErrorShown = $true
            [System.Windows.Forms.MessageBox]::Show(
                "Logging failed:`n$($_.Exception.Message)`n`nLog path: $($script:LogFile)",
                "Log Error", "OK", "Warning"
            )
        }
    }
}

Write-Log "LAUNCHER_START" "JANET Launcher $($script:LauncherVersion) starting"
#endregion

#region === COLOR PALETTE - Purple + Gold on Black ===
# Purple owns structure (brackets, buttons, icons).
# Gold owns highlights (eyebrow labels, version chip, Discover, header line).
# Surfaces carry a faint violet lean so black reads distinct from #000000.

# Surfaces
$cBg          = [System.Drawing.Color]::FromArgb(  8,   8,  12)
$cHeaderBg    = [System.Drawing.Color]::FromArgb(  6,   6,  10)
$cSidebar     = [System.Drawing.Color]::FromArgb(  7,   7,  11)
$cPanel       = [System.Drawing.Color]::FromArgb( 16,  16,  22)
$cRow         = [System.Drawing.Color]::FromArgb( 16,  16,  22)
$cRowAlt      = [System.Drawing.Color]::FromArgb( 22,  22,  30)
$cRowHover    = [System.Drawing.Color]::FromArgb( 30,  28,  40)
$cRowActive   = [System.Drawing.Color]::FromArgb( 40,  36,  54)

# Purple - primary accent
$cAccent      = [System.Drawing.Color]::FromArgb(140, 100, 220)
$cAccentHov   = [System.Drawing.Color]::FromArgb(164, 128, 240)
$cAccentDim   = [System.Drawing.Color]::FromArgb( 96,  68, 156)
$cAccentGlow  = [System.Drawing.Color]::FromArgb( 28,  20,  48)

# Gold - secondary accent
$cGold        = [System.Drawing.Color]::FromArgb(218, 180,  82)
$cGoldHov     = [System.Drawing.Color]::FromArgb(238, 200, 110)
$cGoldDim     = [System.Drawing.Color]::FromArgb(155, 125,  52)
$cGoldFaint   = [System.Drawing.Color]::FromArgb( 82,  68,  34)

# Status
$cGreen       = [System.Drawing.Color]::FromArgb( 92, 198, 120)
$cGreenHov    = [System.Drawing.Color]::FromArgb(134, 218, 142)
$cGreenDim    = [System.Drawing.Color]::FromArgb( 50, 120,  65)
$cRed         = [System.Drawing.Color]::FromArgb(224,  80,  90)
$cRedHov      = [System.Drawing.Color]::FromArgb(244, 110, 118)
$cOrange      = [System.Drawing.Color]::FromArgb(230, 180,  70)
$cInfo        = [System.Drawing.Color]::FromArgb( 88, 180, 210)

# Text
$cText        = [System.Drawing.Color]::FromArgb(240, 240, 245)
$cTextDim     = [System.Drawing.Color]::FromArgb(170, 168, 180)
$cTextMuted   = [System.Drawing.Color]::FromArgb(110, 106, 125)
$cTextDark    = [System.Drawing.Color]::FromArgb( 60,  56,  74)
$cTextOnAccent= [System.Drawing.Color]::FromArgb(255, 255, 255)
$cTextOnGold  = [System.Drawing.Color]::FromArgb( 16,  14,   8)

# Structure
$cBorder      = [System.Drawing.Color]::FromArgb( 38,  34,  52)
$cBorderStrong= [System.Drawing.Color]::FromArgb( 52,  46,  72)

# Stripe (purple diagonal hatch)
$cStripeBlk   = [System.Drawing.Color]::FromArgb(  8,   8,  12)
$cStripeAmb   = [System.Drawing.Color]::FromArgb(140, 100, 220)
#endregion

#region === FONTS ===
$fDisplayLg   = New-Object System.Drawing.Font("Cascadia Mono", 18, [System.Drawing.FontStyle]::Bold)
$fDisplayMd   = New-Object System.Drawing.Font("Cascadia Mono", 13, [System.Drawing.FontStyle]::Bold)
$fDisplaySm   = New-Object System.Drawing.Font("Cascadia Mono", 10, [System.Drawing.FontStyle]::Bold)
$fEyebrow     = New-Object System.Drawing.Font("Cascadia Mono",  9, [System.Drawing.FontStyle]::Bold)
$fEyebrowDim  = New-Object System.Drawing.Font("Cascadia Mono",  8, [System.Drawing.FontStyle]::Regular)
$fMono        = New-Object System.Drawing.Font("Cascadia Mono", 10)
$fMonoSm      = New-Object System.Drawing.Font("Cascadia Mono",  9)
$fMonoTiny    = New-Object System.Drawing.Font("Cascadia Mono",  8)
$fBody        = New-Object System.Drawing.Font("Segoe UI Variable Display", 10)
$fBodyStrong  = New-Object System.Drawing.Font("Segoe UI Variable Display", 10, [System.Drawing.FontStyle]::Bold)
$fCaption     = New-Object System.Drawing.Font("Segoe UI Variable Display",  9)
$fTiny        = New-Object System.Drawing.Font("Segoe UI Variable Display",  8)
$fIcon        = New-Object System.Drawing.Font("Segoe MDL2 Assets", 14)
$fIconLg      = New-Object System.Drawing.Font("Segoe MDL2 Assets", 20)
$fIconSm      = New-Object System.Drawing.Font("Segoe MDL2 Assets", 11)

# Legacy aliases
$fTitle       = $fDisplayLg
$fSubtitle    = $fCaption
$fHeading     = $fDisplayMd
$fNormal      = $fBody
$fSmall       = $fCaption
$fSmallBold   = $fEyebrow
$fButton      = $fEyebrow
$fToolName    = New-Object System.Drawing.Font("Segoe UI Variable Display", 11.5, [System.Drawing.FontStyle]::Bold)
$fBadge       = $fMonoTiny
#endregion

#region === MDL2 ICON REGISTRY ===
$icoSettings  = [char]0xE713
$icoTarget    = [char]0xE8FD
$icoSearch    = [char]0xE721
$icoPackage   = [char]0xE7B8
$icoApp       = [char]0xECAA
$icoUpload    = [char]0xE898
$icoSync      = [char]0xE895
$icoMail      = [char]0xE8BD
$icoBroom     = [char]0xE74D
$icoChart     = [char]0xE9D9
$icoDoc       = [char]0xE8A5
$icoInfo      = [char]0xE946
$icoPower     = [char]0xE7E8
$icoLock      = [char]0xE72E
$icoUser      = [char]0xE77B
$icoCheck     = [char]0xE73E
$icoDot       = [char]0xE915
$icoShield    = [char]0xEA18
$icoSignal    = [char]0xE8F4
$icoRadio     = [char]0xE704
$icoWarning   = [char]0xE7BA
$icoRefresh   = [char]0xE72C
$icoFolder    = [char]0xE8B7

function Get-ToolGlyph {
    param($toolDef)
    $key = ("$($toolDef.Name) $($toolDef.Script) $($toolDef.Category)").ToLowerInvariant()
    switch -Regex ($key) {
        'patch|update'            { return $icoSync }
        'adsearch|ad-search'      { return $icoSearch }
        'user|logged|edipi'       { return $icoUser }
        'report|acas|nessus'      { return $icoChart }
        'message|mail'            { return $icoMail }
        'package|deploy|install'  { return $icoPackage }
        'secureboot|shield|bios'  { return $icoShield }
        'stig|compliance'         { return $icoShield }
        'admin|remote|ops'        { return $icoSignal }
        'clean|uninstall|broom'   { return $icoBroom }
        'config|settings'         { return $icoSettings }
        default                   { return $icoApp }
    }
}
#endregion

#region === UI HELPERS ===
function Enable-DoubleBuffer {
    param($Control)
    try {
        $prop = $Control.GetType().GetProperty(
            'DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic'
        )
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function ConvertTo-GlyphBitmap {
    param(
        [Parameter(Mandatory)][char]$Glyph,
        [Parameter(Mandatory)][System.Drawing.Color]$Color,
        [int]$Size = 16
    )
    $bmp = New-Object System.Drawing.Bitmap $Size, $Size
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.Clear([System.Drawing.Color]::Transparent)
        $g.SmoothingMode     = 'AntiAlias'
        $g.TextRenderingHint = 'AntiAlias'
        $glyphFont = New-Object System.Drawing.Font("Segoe MDL2 Assets", ([float]($Size * 0.72)))
        $brush     = New-Object System.Drawing.SolidBrush($Color)
        $sf        = New-Object System.Drawing.StringFormat
        $sf.Alignment     = 'Center'
        $sf.LineAlignment = 'Center'
        $rect = New-Object System.Drawing.RectangleF(0, 0, $Size, $Size)
        try {
            $g.DrawString([string]$Glyph, $glyphFont, $brush, $rect, $sf)
        } finally {
            $brush.Dispose(); $glyphFont.Dispose(); $sf.Dispose()
        }
    } finally { $g.Dispose() }
    return $bmp
}

function New-EyebrowLabel {
    param([string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 120, [int]$H = 18, $Fg = $null)
    if (-not $Fg) { $Fg = $cGold }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text.ToUpperInvariant()
    $l.Font      = $fEyebrow
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.AutoSize  = $false
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.TextAlign = 'MiddleLeft'
    return $l
}

function New-IconLabel {
    param(
        [char]$Glyph, [int]$X = 0, [int]$Y = 0, [int]$W = 24, [int]$H = 24,
        $Fg = $null, $Font = $null
    )
    if (-not $Fg) { $Fg = $cText }
    if (-not $Font) { $Font = $fIcon }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = [string]$Glyph
    $l.Font      = $Font
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.AutoSize  = $false
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-CornerBracketCard {
    <#
    .SYNOPSIS
        Surface panel with L-shaped corner brackets in each corner plus an
        optional eyebrow header with a dotted underline.
    #>
    param(
        [string]$Header,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 120,
        $BracketColor = $null,
        $HeaderColor  = $null,
        [int]$Padding = 20,
        [int]$BracketLen = 16,
        [int]$BracketThick = 2
    )
    if (-not $BracketColor) { $BracketColor = $cAccent }
    if (-not $HeaderColor)  { $HeaderColor  = $cGold }
    $card = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($X, $Y)
    $card.Size      = New-Object System.Drawing.Size($W, $H)
    $card.BackColor = $cPanel
    Enable-DoubleBuffer $card
    $card.Add_SizeChanged({ $this.Invalidate() })

    $underColor = [System.Drawing.Color]::FromArgb(
        70, $BracketColor.R, $BracketColor.G, $BracketColor.B)
    $hasHdr = -not [string]::IsNullOrWhiteSpace($Header)

    $card.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics; $g.SmoothingMode = 'HighQuality'
        $pen = New-Object System.Drawing.Pen($BracketColor, $BracketThick)
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
        $hdr.Text          = "/ $($Header.ToUpperInvariant())"
        $hdr.Location      = New-Object System.Drawing.Point($Padding, 14)
        $hdr.Size          = New-Object System.Drawing.Size(($W - $Padding * 2), 22)
        $hdr.ForeColor     = $HeaderColor
        $hdr.BackColor     = [System.Drawing.Color]::Transparent
        $hdr.Font          = $fEyebrow
        $hdr.AutoEllipsis  = $true
        $hdr.Anchor        = 'Top,Left,Right'
        $card.Controls.Add($hdr)
    }
    return $card
}

function New-GhostButton {
    param(
        [string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 80, [int]$H = 28,
        $Fg = $null, $Border = $null
    )
    if (-not $Fg)     { $Fg     = $cTextDim }
    if (-not $Border) { $Border = $cBorder }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $Border
    $b.BackColor = $cBg
    $b.ForeColor = $Fg
    $b.Font      = $fEyebrow
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $cRowHover
    $b.FlatAppearance.MouseDownBackColor = $cRowActive
    return $b
}

function New-PrimaryButton {
    param([string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 120, [int]$H = 34, $Font = $null)
    if (-not $Font) { $Font = $fDisplaySm }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $cAccent
    $b.ForeColor = $cTextOnAccent
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.TextAlign = 'MiddleCenter'
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $cAccentHov
    $b.FlatAppearance.MouseDownBackColor = $cAccentDim
    return $b
}

function New-StripeButton {
    param([string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 34, $Font = $null)
    if (-not $Font) { $Font = $fDisplaySm }
    $b = New-PrimaryButton -Text $Text -X $X -Y $Y -W $W -H $H -Font $Font
    $stripeH = 4
    $c1 = $cStripeAmb
    $c2 = $cStripeBlk
    $b.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush(
            'WideDownwardDiagonal', $c2, $c1)
        try {
            $rect = New-Object System.Drawing.Rectangle(
                0, ($sender.Height - $stripeH), $sender.Width, $stripeH)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())
    return $b
}

function New-PulseDot {
    param([int]$X = 0, [int]$Y = 0, [int]$Size = 8,
          [ValidateSet('Active','Idle','Alert','Error')][string]$State = 'Idle')
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
        try { $e.Graphics.FillEllipse($brush, 0, 0, ($sender.Width - 1), ($sender.Height - 1)) }
        finally { $brush.Dispose() }
    }.GetNewClosure())
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert' -or $State -eq 'Error') { 340 } else { 720 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({ $p.Tag.Phase = 1 - $p.Tag.Phase; $p.Invalidate() }.GetNewClosure())
        $timer.Start()
        $p.Tag.Timer = $timer
    }
    return $p
}

function Set-PulseDotState {
    param($Dot, [ValidateSet('Active','Idle','Alert','Error')][string]$State)
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
        $timer.Add_Tick({ $Dot.Tag.Phase = 1 - $Dot.Tag.Phase; $Dot.Invalidate() }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Dot.Invalidate()
}

function Add-GridPaperBackground {
    param($Panel, [int]$Spacing = 16)
    $dotColor = [System.Drawing.Color]::FromArgb(22, $cTextMuted.R, $cTextMuted.G, $cTextMuted.B)
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

function Set-JanetDarkTitleBar {
    param($Form)
    if (-not ('Janet.Dwm' -as [type])) {
        Add-Type -Namespace 'Janet' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }
    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }
    $enable = 1
    $null = [Janet.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Janet.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)
    $round = 2
    $null = [Janet.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

# Legacy helper kept for the config editor / log viewer dialogs.
function New-StyledButton {
    param(
        [string]$Text, [int]$Width = 90, [int]$Height = 30,
        [System.Drawing.Color]$BgColor   = $cAccent,
        [System.Drawing.Color]$HoverColor = $cAccentHov,
        [System.Drawing.Color]$ForeColor = $cTextOnAccent
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text      = $Text
    $btn.Size      = New-Object System.Drawing.Size($Width, $Height)
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.FlatAppearance.MouseOverBackColor  = $HoverColor
    $btn.FlatAppearance.MouseDownBackColor  = $HoverColor
    $btn.BackColor = $BgColor
    $btn.ForeColor = $ForeColor
    $btn.Font      = $fBodyStrong
    $btn.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $btn
}

function New-BadgeLabel {
    param(
        [string]$Text,
        [System.Drawing.Color]$BadgeColor = $cAccentDim,
        [System.Drawing.Color]$TextColor  = $cText
    )
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text      = "  $Text  "
    $lbl.Font      = $fBadge
    $lbl.ForeColor = $TextColor
    $lbl.BackColor = $BadgeColor
    $lbl.AutoSize  = $true
    $lbl.Padding   = New-Object System.Windows.Forms.Padding(4, 2, 4, 2)
    $lbl.TextAlign = 'MiddleCenter'
    return $lbl
}
#endregion

#region === CONFIG MANAGEMENT ===
# Get-DefaultConfig is the fallback used when JANET_Config.json is missing or
# unreadable. It MUST mirror JANET_Config.json's tool registry — when a tool is
# added/renamed/version-bumped in the JSON, update this function in the same
# commit. A drift here causes the launcher to silently drop tools the next time
# the JSON is regenerated from defaults.
function Get-DefaultConfig {
    return @{
        SuiteName = "J.A.N.E.T. - Joint Administration and Network Execution Toolkit"
        Version   = "1.0"
        ToolsDir  = "Tools"
        Tools     = @(
            @{
                Name        = "WorkstationPatchingTool"
                Script      = "WorkstationPatchingTool_6.5.22.ps1"
                Description = "MECM-driven workstation patching. Bulk scan and patch via RunspacePool, MECM app management (install/uninstall/reinstall/repair), Deploy-Application.ps1 package push, KB scanning and installation, application updaters (M365, Defender, Chrome, Edge), remote messaging, reboot scheduling. CSV export for all results. (Themed v47 with Purple+Gold UI, TCP reachability, WSMan timeouts.)"
                Icon        = ""
                Category    = "Patch"
            },
            @{
                Name        = "ACAS Nemesis Tool"
                Script      = "ACAS Nemesis Tool_1.10.10.ps1"
                Description = "ACAS-driven vulnerability remediation. Per-vulnerability Updater cards with profile dropdowns (M365 Force/User-Visible, Chrome, Edge, Defender) + per-card Verify button. KB Installer with MECM (CIM targeted) / UsoClient method dropdown. Daily Runs CSV on the shared log share with closing-notes dialog and SIM-style AD displayName + EDIPI operator identity."
                Icon        = ""
                Category    = "Patch"
            },
            @{
                Name        = "STIG_Tool"
                Script      = "STIG_Tool_1.3.5.ps1"
                Description = "PowerSTIG-backed DSC compliance. Evaluate, review, apply, and verify STIG baselines against Windows 10/11 clients, Server 2019/2022, Windows Firewall, and Defender Antivirus. Per-rule skip lists, dry-run preview, System Restore point before apply, XLSX and CKL (STIG Viewer) exports."
                Icon        = ""
                Category    = "Compliance"
            },
            @{
                Name        = "ReportsTool"
                Script      = "ReportsTool_2.14.6.ps1"
                Description = "ACAS and patch reporting. Import ACAS CSV or .nessus scan files, cross-reference patch logs, scan-to-scan delta, severity dashboard, per-host summary, batch triage, CSV export. Weekly Export: monthly ACAS_Calculations workbook split into per-week NIPR / SIPR cards with Total Vulns, AR % with/without PMO, MAJCOM score, VPH by category (UEs / Servers / Infrastructure / Printers / PMO with owner roll-up); polished HTML report for presentations. Dirty 30 Triage: ingest Tenable Top 30 Worst Hosts (paste from PDF viewer, CSV, or TXT) and fan through AD bulk lookup to surface squadron, last AD logon, stale detection, and last interactive user."
                Icon        = ""
                Category    = "Reports"
            },
            @{
                Name        = "RemotePackageInstaller"
                Script      = "RemotePackageInstaller.ps1"
                Description = "Remote software deployment. Push Deploy-Application.ps1 packages OR raw MSI bundles to workstations via UNC share copy and Invoke-Command. MSI bundle mode auto-selects every .msi in the chosen folder and fans them out via msiexec. Package root auto-discovery, credential management, parallel execution, progress tracking, retry failed targets, structured audit logging, and result export."
                Icon        = ""
                Category    = "Patch"
            },
            @{
                Name        = "RemoteMessageTool"
                Script      = "RemoteMessageTool_1.3.3.ps1"
                Description = "Remote mass messaging. Send MessageBox popups to logged-in users across workstations in parallel over WinRM. Ping-all reachability check, per-job timeout with mid-send cancel, case-insensitive target dedup, and Pingable/Delivered/Undelivered XLSX export (pure .NET, no Excel dependency)."
                Icon        = ""
                Category    = "Admin"
            },
            @{
                Name        = "SecureBootEnabler"
                Script      = "SecureBootEnabler.ps1"
                Description = "Remote Secure Boot enablement. Deploy BIOS configuration payloads to Dell, HP, and Lenovo machines via CIM/DCOM scheduled tasks (SYSTEM context, no WinRM dependency). Up to 50 concurrent targets, dry-run mode, per-machine result polling, and CSV export."
                Icon        = ""
                Category    = "Admin"
            },
            @{
                Name        = "ADSearchTool"
                Script      = "ADSearchTool.ps1"
                Description = "Active Directory search without RSAT. Query users, computers, groups, org boxes, email addresses, and manager chains via raw LDAP. Bulk computer lookup (200+ machines with batched queries and location/squadron parsing), base-users export with privileged vs. standard account separation, and CSV export."
                Icon        = ""
                Category    = "Admin"
            },
            @{
                Name        = "DHCPScopeOptionTool"
                Script      = "DHCPScopeOptionTool_1.1.5.ps1"
                Description = "DHCP scope option editor. WinForms GUI for IP-array options (006 DNS, 003 Router, 042 NTP, 044 WINS) on a remote Windows DHCP server via PSSession. Loads all IPv4 scopes, auto-loads current values, in-memory reorder (Up/Down/Top/Bottom) with pre-commit diff confirmation, and bulk-apply footer (append/prepend/remove across every checked scope) for DR-DNS rollouts. 'Use current session' credential bypass for Kerberos/NTLM, per-session log file."
                Icon        = ""
                Category    = "Admin"
            },
            @{
                Name        = "RemoteRestartScheduler"
                Script      = "RemoteRestartScheduler_1.6.0.ps1"
                Description = "Mass scheduled restart with staggered dispatch and pre-restart user warnings. Distributes restarts across a configurable window (default 4000 machines over 60 min starting 02:00 AM) and fires shutdown.exe /m \\HOST /r /t SECONDS per machine so Windows shows a countdown popup before each host reboots. Burst mode (default): every command is fan-out submitted to the pool ASAP with a per-host /t computed at submit time as time-until-that-host's-restart, so 4000 machines dispatch in ~1-2 min and the restart stagger is preserved by Windows itself. Targets paste/CSV import with case-insensitive dedup; side-by-side Exception List (never-restart) with separate CSV import and cross-session persistence to JanetLocal\Remote_Restart\<user>\exceptions.txt. Compute Schedule preview grid + Save Plan CSV, Dry-Run mode, RunspacePool dispatch (1-128 threads, default 32), Cancel Pending, Abort Already-Dispatched (shutdown /a fan-out), Results CSV export. v1.4.0 adds an optional (default ON) User Consent Prompt: an Accept/Decline dialog on the logged-on user's desktop (one-shot interactive scheduled task) before each restart; no response or no user proceeds, Decline skips the host, choice read back over WinRM and shown in the grid + CSV."
                Icon        = ""
                Category    = "Admin"
            },
            @{
                Name        = "UnsupportedProductRemediator"
                Script      = "UnsupportedProductRemediator_1.1.2.ps1"
                Description = "Tenable/ACAS unsupported & SEoL remediation (uninstall-only). Ingest an Unsupported / SEoL Product Summary report (PDF via pdftotext, or Tenable CSV), auto-extract the affected hosts per finding, bulk-scan those hosts over WinRM (RunspacePool) for the matching installed product, and one-click uninstall it. Proven-EOL gating: one-click only when the catalog proves end-of-life (Proven flag e.g. Flash / perpetual Office, or installed version below cutoff e.g. MSXML < 5 / .NET < 8); ambiguous family matches (.NET 8, current Firefox/Java) and DBA-owned servers (SQL/Oracle) are surfaced as disabled Review rows. Per-product handlers (Microsoft 365 SaRA, Adobe Acrobat GUID-MSI with RunAsPPL guard, Store/MSI/EXE), Tanium safety block, host-class filter, dry-run default, per-host audit log + History, CSV export. OS findings listed read-only. Catalog: JanetLocal\UnsupportedProductCatalog.json (editable, Reload Catalog button)."
                Icon        = ""
                Category    = "Patch"
            },
            @{
                Name        = "WindowsUpgradeTool"
                Script      = "WindowsUpgradeTool_0.1.0.ps1"
                Description = "Windows 11 feature-update deployer (bench build). Three selectable remote operations over WinRM: PIN a target release (writes HKLM WindowsUpdate TargetReleaseVersion=1 + ProductVersion + TargetReleaseVersionInfo; default 24H2), UNPIN (removes them), and INSTALL CAB (New-PSSession + Copy-Item -ToSession to C:\Temp + DISM /Online /Add-Package /Quiet /NoRestart with optional delayed reboot, e.g. the 25H2 enablement package). Set Credentials (null = current CAC session), GUI host management (type/paste/import + case-insensitive dedupe), .NET ping pre-check + RunspacePool fan-out with a live progress grid, dry-run, Cancel, CSV export. Purple+Gold theme + dark titlebar."
                Icon        = ""
                Category    = "Patch"
            }
        )
    }
}

function Load-Config {
    if (Test-Path $script:ConfigPath) {
        try {
            $json = Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
            $json.Tools = @($json.Tools)
            Write-Log "CONFIG_LOADED" "Loaded $($json.Tools.Count) tools from config"
            return $json
        } catch {
            Write-Log "CONFIG_ERROR" $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to parse config:`n$($_.Exception.Message)`n`nLoading defaults.",
                "Config Error", "OK", "Warning"
            )
            return Get-DefaultConfig
        }
    } else {
        $default = Get-DefaultConfig
        Save-Config $default
        Write-Log "CONFIG_CREATED" "Created default config with $($default.Tools.Count) tools"
        return $default
    }
}

function Save-Config($config) {
    try {
        $config | ConvertTo-Json -Depth 5 | Set-Content $script:ConfigPath -Encoding UTF8 -Force
        Write-Log "CONFIG_SAVED" "Config saved with $($config.Tools.Count) tools"
    } catch {
        Write-Log "CONFIG_SAVE_ERROR" $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to save config:`n$($_.Exception.Message)",
            "Save Error", "OK", "Error"
        )
    }
}
#endregion

#region === SHARED CREDENTIAL MANAGEMENT ===
function Set-LauncherCredential {
    $cred = Get-Credential -Message "Enter credentials to share with J.A.N.E.T. tools"
    if (-not $cred) {
        Write-Log "CRED_CANCEL" "User cancelled credential prompt"
        return $false
    }
    $script:Credential = $cred
    try {
        if (-not (Test-Path $script:CredSessionDir)) {
            New-Item -Path $script:CredSessionDir -ItemType Directory -Force -EA Stop | Out-Null
        }
        $cred | Export-Clixml -Path $script:CredFile -Force -EA Stop
        Write-Log "CRED_SET" "Shared credential set for $($cred.UserName)"
        return $true
    } catch {
        Write-Log "CRED_ERROR" "Failed to persist credential: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to save credential file:`n$($_.Exception.Message)",
            "Credential Error", "OK", "Error"
        )
        return $false
    }
}

function Clear-LauncherCredential {
    $script:Credential = $null
    if (Test-Path $script:CredFile) {
        try { Remove-Item $script:CredFile -Force -EA Stop } catch {
            Write-Log "CRED_CLEAR_ERROR" $_.Exception.Message
        }
    }
    Write-Log "CRED_CLEAR" "Shared credential cleared"
}
#endregion

#region === SCRIPT PATH RESOLUTION ===
# Resolves a tool's Script field to an absolute file path.
# Tries the literal path first; if missing, falls back to "{base}_*.ps1" and
# returns the highest-versioned match. Returns $null if nothing is found.
function Resolve-ToolScript {
    param([string]$ScriptRef)

    if ([string]::IsNullOrWhiteSpace($ScriptRef)) { return $null }

    $toolsDir = Join-Path $script:ScriptDir "Tools"

    $literalCandidates = @()
    if ([System.IO.Path]::IsPathRooted($ScriptRef)) {
        $literalCandidates += $ScriptRef
    } else {
        $literalCandidates += (Join-Path $toolsDir $ScriptRef)
        $literalCandidates += (Join-Path $script:ScriptDir $ScriptRef)
    }
    foreach ($p in $literalCandidates) {
        if (Test-Path $p -PathType Leaf) { return (Resolve-Path $p).Path }
    }

    $leaf = Split-Path $ScriptRef -Leaf
    $base = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
    $ext  = [System.IO.Path]::GetExtension($leaf)
    if ([string]::IsNullOrEmpty($ext)) { $ext = ".ps1" }

    $searchDirs = @()
    if ([System.IO.Path]::IsPathRooted($ScriptRef)) {
        $searchDirs += (Split-Path $ScriptRef -Parent)
    } else {
        $sub = Split-Path $ScriptRef -Parent
        if ($sub) {
            $searchDirs += (Join-Path $toolsDir $sub)
            $searchDirs += (Join-Path $script:ScriptDir $sub)
        } else {
            $searchDirs += $toolsDir
            $searchDirs += $script:ScriptDir
        }
    }

    $collected = @()
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        $found = Get-ChildItem -Path $dir -Filter "$($base)_*$ext" -File -EA SilentlyContinue
        foreach ($f in $found) { $collected += $f }
    }
    if ($collected.Count -eq 0) { return $null }

    $ranked = $collected | ForEach-Object {
        $stem    = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
        $verPart = $stem.Substring($base.Length + 1)
        $verObj  = $null
        if ($verPart -match '^\d+(\.\d+){0,3}$') {
            try { $verObj = [Version]$verPart } catch { $verObj = $null }
        }
        [PSCustomObject]@{
            File    = $_
            Version = $verObj
            Mtime   = $_.LastWriteTime
        }
    } | Sort-Object `
        @{Expression={ if ($_.Version) { $_.Version } else { [Version]'0.0' } }; Descending=$true}, `
        @{Expression='Mtime'; Descending=$true}

    return $ranked[0].File.FullName
}
#endregion

#region === AUTO-DISCOVER ===
function Discover-Scripts {
    param($config)
    $registered = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $registeredBases = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $config.Tools) {
        $scriptFile = Split-Path $t.Script -Leaf
        [void]$registered.Add($scriptFile)
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)
        [void]$registeredBases.Add($stem)
    }
    [void]$registered.Add("JANET.ps1")
    [void]$registeredBases.Add("JANET")

    $candidates = @()
    $toolsDir = Join-Path $script:ScriptDir "Tools"
    $searchDirs = @()
    if (Test-Path $toolsDir) { $searchDirs += $toolsDir }
    $searchDirs += $script:ScriptDir
    foreach ($dir in $searchDirs) {
        $ps1Files = Get-ChildItem -Path $dir -Filter "*.ps1" -File -EA SilentlyContinue |
            Where-Object {
                if ($registered.Contains($_.Name)) { return $false }
                $candStem = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                if ($candStem -match '^(.+?)_\d+(\.\d+){0,3}$') {
                    if ($registeredBases.Contains($Matches[1])) { return $false }
                }
                return $true
            }
        foreach ($file in $ps1Files) {
            $lines = Get-Content $file.FullName -TotalCount 30 -EA SilentlyContinue
            $headerText = ($lines | Out-String)
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $displayName = $stem
            $scriptRef   = $file.Name
            if ($stem -match '^(.+?)_\d+(\.\d+){0,3}$') {
                $displayName = $Matches[1]
                $scriptRef   = "$($Matches[1]).ps1"
                if ($registeredBases.Contains($Matches[1])) { continue }
            }
            $desc = "Discovered script - $($file.Name)"
            if ($headerText -match '(?i)Purpose:\s*(.+)') { $desc = $Matches[1].Trim() }
            elseif ($headerText -match '(?i)Description:\s*(.+)') { $desc = $Matches[1].Trim() }
            elseif ($headerText -match '(?i)SYNOPSIS\s+(.+)') { $desc = $Matches[1].Trim() }
            $candidates += @{
                Name        = $displayName
                Description = $desc
                Script      = $scriptRef
                Icon        = ""
                Category    = ""
            }
            [void]$registered.Add($file.Name)
            [void]$registeredBases.Add($displayName)
        }
    }
    return $candidates
}

function Show-DiscoveryDialog {
    $cfg = Load-Config
    $candidates = Discover-Scripts $cfg

    if ($candidates.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No new scripts found in the tool suite directory.`n`nAll .ps1 files are already registered.",
            "Auto-Discover", "OK", "Information"
        )
        Write-Log "DISCOVER" "No unregistered scripts found"
        return $false
    }

    Write-Log "DISCOVER" "Found $($candidates.Count) unregistered script(s)"

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "Auto-Discover Scripts"
    $dlg.Size            = New-Object System.Drawing.Size(660, 480)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $cBg
    $dlg.ForeColor       = $cText
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.Font            = $fBody
    $dlg.Add_Shown({ Set-JanetDarkTitleBar -Form $dlg })

    $pnlHdr = New-Object System.Windows.Forms.Panel
    $pnlHdr.Size      = New-Object System.Drawing.Size(660, 44)
    $pnlHdr.Location  = New-Object System.Drawing.Point(0, 0)
    $pnlHdr.BackColor = $cHeaderBg
    $dlg.Controls.Add($pnlHdr)

    $pnlAmber = New-Object System.Windows.Forms.Panel
    $pnlAmber.Dock = 'Top'; $pnlAmber.Height = 2; $pnlAmber.BackColor = $cGold
    $pnlHdr.Controls.Add($pnlAmber)

    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text      = "/ DISCOVERED SCRIPTS"
    $lblHdr.Font      = $fEyebrow
    $lblHdr.ForeColor = $cGold
    $lblHdr.AutoSize  = $false
    $lblHdr.Size      = New-Object System.Drawing.Size(400, 44)
    $lblHdr.Location  = New-Object System.Drawing.Point(18, 0)
    $lblHdr.TextAlign = 'MiddleLeft'
    $pnlHdr.Controls.Add($lblHdr)

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text      = "Found $($candidates.Count) script(s) not in config. Check the ones to add:"
    $lblInfo.Font      = $fCaption
    $lblInfo.ForeColor = $cTextDim
    $lblInfo.AutoSize  = $false
    $lblInfo.Size      = New-Object System.Drawing.Size(620, 22)
    $lblInfo.Location  = New-Object System.Drawing.Point(18, 52)
    $dlg.Controls.Add($lblInfo)

    $lstDisc = New-Object System.Windows.Forms.CheckedListBox
    $lstDisc.Location      = New-Object System.Drawing.Point(18, 82)
    $lstDisc.Size          = New-Object System.Drawing.Size(620, 260)
    $lstDisc.BackColor     = $cPanel
    $lstDisc.ForeColor     = $cText
    $lstDisc.Font          = $fMono
    $lstDisc.BorderStyle   = 'FixedSingle'
    $lstDisc.CheckOnClick  = $true
    foreach ($c in $candidates) {
        $display = "{0}    -    {1}" -f $c.Name, $c.Script
        [void]$lstDisc.Items.Add($display, $true)
    }
    $dlg.Controls.Add($lstDisc)

    $lblPreview = New-Object System.Windows.Forms.Label
    $lblPreview.Text      = ""
    $lblPreview.Font      = $fCaption
    $lblPreview.ForeColor = $cTextDim
    $lblPreview.AutoSize  = $false
    $lblPreview.Size      = New-Object System.Drawing.Size(620, 36)
    $lblPreview.Location  = New-Object System.Drawing.Point(18, 348)
    $dlg.Controls.Add($lblPreview)

    $lstDisc.Add_SelectedIndexChanged({
        $idx = $lstDisc.SelectedIndex
        if ($idx -ge 0 -and $idx -lt $candidates.Count) {
            $lblPreview.Text = "Description: $($candidates[$idx].Description)"
        }
    })

    $btnAdd = New-StripeButton -Text "Add Selected" -X 18 -Y 398 -W 160 -H 34
    $btnAdd.Add_Click({
        $addCount = 0
        $toolsList = [System.Collections.ArrayList]@($cfg.Tools)
        for ($i = 0; $i -lt $lstDisc.Items.Count; $i++) {
            if ($lstDisc.GetItemChecked($i)) {
                [void]$toolsList.Add($candidates[$i])
                $addCount++
            }
        }
        if ($addCount -gt 0) {
            $cfg.Tools = $toolsList.ToArray()
            Save-Config $cfg
            Write-Log "DISCOVER_ADD" "Added $addCount discovered tool(s) to config"
        }
        $dlg.DialogResult = 'OK'; $dlg.Close()
    })
    $dlg.Controls.Add($btnAdd)

    $btnCancel = New-GhostButton -Text "Cancel" -X 190 -Y 400 -W 100 -H 30
    $btnCancel.Add_Click({ $dlg.DialogResult = 'Cancel'; $dlg.Close() })
    $dlg.Controls.Add($btnCancel)

    $result = $dlg.ShowDialog()
    return ($result -eq 'OK')
}
#endregion

#region === ARCHIVE ===
# Scans Tools\Archive for .ps1 files and returns hashtables shaped like config tools.
# Script is set to the absolute path so Launch-Tool / Resolve-ToolScript run them directly.
function Get-ArchivedTools {
    $archiveDir = Join-Path (Join-Path $script:ScriptDir "Tools") "Archive"
    if (-not (Test-Path $archiveDir)) { return @() }

    $items = @()
    $files = Get-ChildItem -Path $archiveDir -Filter "*.ps1" -File -EA SilentlyContinue |
        Sort-Object Name
    foreach ($file in $files) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $displayName = $stem
        if ($stem -match '^(.+?)_\d+(\.\d+){0,3}$') { $displayName = $Matches[1] }

        $lines = Get-Content $file.FullName -TotalCount 30 -EA SilentlyContinue
        $headerText = ($lines | Out-String)
        $desc = "Archived tool - $($file.Name)"
        if ($headerText -match '(?i)Purpose:\s*(.+)')         { $desc = $Matches[1].Trim() }
        elseif ($headerText -match '(?i)Description:\s*(.+)') { $desc = $Matches[1].Trim() }
        elseif ($headerText -match '(?i)SYNOPSIS\s+(.+)')     { $desc = $Matches[1].Trim() }

        $items += @{
            Name        = $displayName
            Description = $desc
            Script      = $file.FullName
            FileName    = $file.Name
            Modified    = $file.LastWriteTime
        }
    }
    return $items
}

function Show-ArchiveDialog {
    $items = Get-ArchivedTools
    $archiveDir = Join-Path (Join-Path $script:ScriptDir "Tools") "Archive"

    if ($items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No archived tools found.`n`nDrop .ps1 files into:`n$archiveDir",
            "Archive", "OK", "Information"
        )
        Write-Log "ARCHIVE_OPEN" "Archive dialog opened, no tools present"
        return
    }

    Write-Log "ARCHIVE_OPEN" "Archive dialog opened with $($items.Count) tool(s)"

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "J.A.N.E.T / ARCHIVE"
    $dlg.Size            = New-Object System.Drawing.Size(680, 500)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $cBg
    $dlg.ForeColor       = $cText
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.Font            = $fBody
    $dlg.Add_Shown({ Set-JanetDarkTitleBar -Form $dlg })

    $pnlHdr = New-Object System.Windows.Forms.Panel
    $pnlHdr.Size      = New-Object System.Drawing.Size(680, 44)
    $pnlHdr.Location  = New-Object System.Drawing.Point(0, 0)
    $pnlHdr.BackColor = $cHeaderBg
    $dlg.Controls.Add($pnlHdr)

    $pnlAmber = New-Object System.Windows.Forms.Panel
    $pnlAmber.Dock = 'Top'; $pnlAmber.Height = 2; $pnlAmber.BackColor = $cGold
    $pnlHdr.Controls.Add($pnlAmber)

    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text      = "/ ARCHIVED TOOLS"
    $lblHdr.Font      = $fEyebrow
    $lblHdr.ForeColor = $cGold
    $lblHdr.AutoSize  = $false
    $lblHdr.Size      = New-Object System.Drawing.Size(400, 44)
    $lblHdr.Location  = New-Object System.Drawing.Point(18, 0)
    $lblHdr.TextAlign = 'MiddleLeft'
    $pnlHdr.Controls.Add($lblHdr)

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text      = "Found $($items.Count) archived tool(s). Double-click or select and press Launch."
    $lblInfo.Font      = $fCaption
    $lblInfo.ForeColor = $cTextDim
    $lblInfo.AutoSize  = $false
    $lblInfo.Size      = New-Object System.Drawing.Size(640, 22)
    $lblInfo.Location  = New-Object System.Drawing.Point(18, 52)
    $dlg.Controls.Add($lblInfo)

    $lstArc = New-Object System.Windows.Forms.ListBox
    $lstArc.Location    = New-Object System.Drawing.Point(18, 82)
    $lstArc.Size        = New-Object System.Drawing.Size(640, 280)
    $lstArc.BackColor   = $cPanel
    $lstArc.ForeColor   = $cText
    $lstArc.Font        = $fMono
    $lstArc.BorderStyle = 'FixedSingle'
    foreach ($it in $items) {
        $display = "{0,-32} {1,-36} {2}" -f $it.Name, $it.FileName, $it.Modified.ToString("yyyy-MM-dd")
        [void]$lstArc.Items.Add($display)
    }
    if ($lstArc.Items.Count -gt 0) { $lstArc.SelectedIndex = 0 }
    $dlg.Controls.Add($lstArc)

    $lblPreview = New-Object System.Windows.Forms.Label
    $lblPreview.Text      = ""
    $lblPreview.Font      = $fCaption
    $lblPreview.ForeColor = $cTextDim
    $lblPreview.AutoSize  = $false
    $lblPreview.Size      = New-Object System.Drawing.Size(640, 36)
    $lblPreview.Location  = New-Object System.Drawing.Point(18, 368)
    $dlg.Controls.Add($lblPreview)

    $updatePreview = {
        $idx = $lstArc.SelectedIndex
        if ($idx -ge 0 -and $idx -lt $items.Count) {
            $lblPreview.Text = "Description: $($items[$idx].Description)"
        }
    }
    $lstArc.Add_SelectedIndexChanged($updatePreview)
    & $updatePreview

    $launchSelected = {
        $idx = $lstArc.SelectedIndex
        if ($idx -lt 0 -or $idx -ge $items.Count) { return }
        $pick = $items[$idx]
        Write-Log "ARCHIVE_LAUNCH" "Launching archived '$($pick.FileName)'"
        Launch-Tool @{
            Name   = "[ARCHIVE] $($pick.Name) ($($pick.FileName))"
            Script = $pick.Script
        }
    }

    $lstArc.Add_DoubleClick($launchSelected)

    $btnLaunch = New-StripeButton -Text "Launch" -X 18 -Y 418 -W 160 -H 34
    $btnLaunch.Add_Click($launchSelected)
    $dlg.Controls.Add($btnLaunch)

    $btnFolder = New-GhostButton -Text "Open Folder" -X 190 -Y 420 -W 140 -H 30 -Fg $cGold -Border $cGold
    $btnFolder.Add_Click({
        try { Start-Process -FilePath "explorer.exe" -ArgumentList "`"$archiveDir`"" | Out-Null }
        catch { Write-Log "ARCHIVE_FOLDER_ERROR" $_.Exception.Message }
    })
    $dlg.Controls.Add($btnFolder)

    $btnClose = New-GhostButton -Text "Close" -X 558 -Y 420 -W 100 -H 30
    $btnClose.Add_Click({ $dlg.DialogResult = 'Cancel'; $dlg.Close() })
    $dlg.Controls.Add($btnClose)

    [void]$dlg.ShowDialog()
}
#endregion

#region === CONFIG EDITOR ===
function Show-ConfigEditor {
    $cfg = Load-Config
    Write-Log "CONFIG_EDITOR" "Opened config editor"

    $editor = New-Object System.Windows.Forms.Form
    $editor.Text            = "J.A.N.E.T / CONFIG EDITOR"
    $editor.Size            = New-Object System.Drawing.Size(820, 620)
    $editor.StartPosition   = 'CenterParent'
    $editor.BackColor       = $cBg
    $editor.ForeColor       = $cText
    $editor.FormBorderStyle = 'Sizable'
    $editor.Font            = $fBody
    $editor.Add_Shown({ Set-JanetDarkTitleBar -Form $editor })

    # Header
    $pnlHdr = New-Object System.Windows.Forms.Panel
    $pnlHdr.Dock = 'Top'; $pnlHdr.Height = 44; $pnlHdr.BackColor = $cHeaderBg
    $editor.Controls.Add($pnlHdr)
    $pnlAmb = New-Object System.Windows.Forms.Panel
    $pnlAmb.Dock = 'Top'; $pnlAmb.Height = 2; $pnlAmb.BackColor = $cGold
    $pnlHdr.Controls.Add($pnlAmb)
    $lblH = New-Object System.Windows.Forms.Label
    $lblH.Text = "/ CONFIG EDITOR"; $lblH.Font = $fEyebrow; $lblH.ForeColor = $cGold
    $lblH.BackColor = [System.Drawing.Color]::Transparent
    $lblH.AutoSize = $false; $lblH.Size = New-Object System.Drawing.Size(400, 44)
    $lblH.Location = New-Object System.Drawing.Point(18, 0); $lblH.TextAlign = 'MiddleLeft'
    $pnlHdr.Controls.Add($lblH)

    # Left: tool list
    $lstTools = New-Object System.Windows.Forms.ListBox
    $lstTools.Location   = New-Object System.Drawing.Point(18, 58)
    $lstTools.Size       = New-Object System.Drawing.Size(240, 440)
    $lstTools.BackColor  = $cPanel
    $lstTools.ForeColor  = $cText
    $lstTools.Font       = $fMono
    $lstTools.BorderStyle= 'FixedSingle'
    $lstTools.Anchor     = 'Top,Left,Bottom'
    foreach ($t in $cfg.Tools) { [void]$lstTools.Items.Add($t.Name) }
    $editor.Controls.Add($lstTools)

    # Right: editor fields
    $rx = 280
    New-EyebrowLabel -Text "NAME" -X $rx -Y 58 -W 100 -Fg $cGold | ForEach-Object { $editor.Controls.Add($_) }
    $txtName = New-Object System.Windows.Forms.TextBox
    $txtName.Location = New-Object System.Drawing.Point($rx, 78); $txtName.Size = New-Object System.Drawing.Size(480, 26)
    $txtName.BackColor = $cRowAlt; $txtName.ForeColor = $cText; $txtName.Font = $fMono
    $txtName.BorderStyle = 'FixedSingle'; $txtName.Anchor = 'Top,Left,Right'
    $editor.Controls.Add($txtName)

    New-EyebrowLabel -Text "SCRIPT" -X $rx -Y 114 -W 100 -Fg $cGold | ForEach-Object { $editor.Controls.Add($_) }
    $txtScript = New-Object System.Windows.Forms.TextBox
    $txtScript.Location = New-Object System.Drawing.Point($rx, 134); $txtScript.Size = New-Object System.Drawing.Size(480, 26)
    $txtScript.BackColor = $cRowAlt; $txtScript.ForeColor = $cText; $txtScript.Font = $fMono
    $txtScript.BorderStyle = 'FixedSingle'; $txtScript.Anchor = 'Top,Left,Right'
    $editor.Controls.Add($txtScript)

    New-EyebrowLabel -Text "CATEGORY" -X $rx -Y 170 -W 100 -Fg $cGold | ForEach-Object { $editor.Controls.Add($_) }
    $txtCategory = New-Object System.Windows.Forms.TextBox
    $txtCategory.Location = New-Object System.Drawing.Point($rx, 190); $txtCategory.Size = New-Object System.Drawing.Size(480, 26)
    $txtCategory.BackColor = $cRowAlt; $txtCategory.ForeColor = $cText; $txtCategory.Font = $fMono
    $txtCategory.BorderStyle = 'FixedSingle'; $txtCategory.Anchor = 'Top,Left,Right'
    $editor.Controls.Add($txtCategory)

    New-EyebrowLabel -Text "DESCRIPTION" -X $rx -Y 226 -W 140 -Fg $cGold | ForEach-Object { $editor.Controls.Add($_) }
    $txtDesc = New-Object System.Windows.Forms.TextBox
    $txtDesc.Location = New-Object System.Drawing.Point($rx, 246); $txtDesc.Size = New-Object System.Drawing.Size(480, 120)
    $txtDesc.BackColor = $cRowAlt; $txtDesc.ForeColor = $cText; $txtDesc.Font = $fBody
    $txtDesc.BorderStyle = 'FixedSingle'; $txtDesc.Multiline = $true; $txtDesc.WordWrap = $true
    $txtDesc.ScrollBars = 'Vertical'
    $txtDesc.Anchor = 'Top,Left,Right'
    $editor.Controls.Add($txtDesc)

    # Selection handler
    $selIdx = -1
    $loadSelected = {
        $idx = $lstTools.SelectedIndex
        if ($idx -lt 0) { return }
        $script:selIdx = $idx
        $t = $cfg.Tools[$idx]
        $txtName.Text     = $t.Name
        $txtScript.Text   = $t.Script
        $txtCategory.Text = if ($t.Category) { $t.Category } else { "" }
        $txtDesc.Text     = $t.Description
    }
    $lstTools.Add_SelectedIndexChanged($loadSelected)

    # Bottom buttons
    $btnSave = New-StripeButton -Text "Save" -X $rx -Y 390 -W 120 -H 34
    $btnSave.Anchor = 'Bottom,Left'
    $btnSave.Add_Click({
        $idx = $lstTools.SelectedIndex
        if ($idx -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Select a tool first.", "No Selection", "OK", "Information")
            return
        }
        $cfg.Tools[$idx].Name        = $txtName.Text
        $cfg.Tools[$idx].Script      = $txtScript.Text
        $cfg.Tools[$idx].Category    = $txtCategory.Text
        $cfg.Tools[$idx].Description = $txtDesc.Text
        Save-Config $cfg
        # Refresh list
        $lstTools.Items.Clear()
        foreach ($t in $cfg.Tools) { [void]$lstTools.Items.Add($t.Name) }
        $lstTools.SelectedIndex = $idx
        [System.Windows.Forms.MessageBox]::Show("Saved.", "Config", "OK", "Information")
    })
    $editor.Controls.Add($btnSave)

    $btnAdd = New-GhostButton -Text "Add New" -X ($rx + 130) -Y 392 -W 110 -H 30 -Fg $cGold -Border $cGold
    $btnAdd.Anchor = 'Bottom,Left'
    $btnAdd.Add_Click({
        $newTool = [PSCustomObject]@{
            Name        = "NewTool"
            Description = "Describe this tool"
            Script      = "NewTool.ps1"
            Icon        = ""
            Category    = ""
        }
        $list = [System.Collections.ArrayList]@($cfg.Tools)
        [void]$list.Add($newTool)
        $cfg.Tools = $list.ToArray()
        $lstTools.Items.Clear()
        foreach ($t in $cfg.Tools) { [void]$lstTools.Items.Add($t.Name) }
        $lstTools.SelectedIndex = $lstTools.Items.Count - 1
    })
    $editor.Controls.Add($btnAdd)

    $btnRemove = New-GhostButton -Text "Remove" -X ($rx + 250) -Y 392 -W 100 -H 30 -Fg $cRed -Border $cRed
    $btnRemove.Anchor = 'Bottom,Left'
    $btnRemove.Add_Click({
        $idx = $lstTools.SelectedIndex
        if ($idx -lt 0) { return }
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Remove '$($cfg.Tools[$idx].Name)' from config?",
            "Confirm Remove", "YesNo", "Question"
        )
        if ($confirm -eq 'Yes') {
            $list = [System.Collections.ArrayList]@($cfg.Tools)
            $list.RemoveAt($idx)
            $cfg.Tools = $list.ToArray()
            $lstTools.Items.RemoveAt($idx)
            Save-Config $cfg
        }
    })
    $editor.Controls.Add($btnRemove)

    $btnClose = New-GhostButton -Text "Close" -X ($rx + 660 - 40) -Y 504 -W 100 -H 30
    $btnClose.Anchor = 'Bottom,Right'
    $btnClose.Add_Click({ $editor.Close() })
    $editor.Controls.Add($btnClose)

    [void]$editor.ShowDialog()
    $editor.Dispose()
}
#endregion

#region === LOG VIEWER ===
function Show-LogViewer {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "J.A.N.E.T / LOG VIEWER"
    $dlg.Size            = New-Object System.Drawing.Size(920, 620)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $cBg
    $dlg.ForeColor       = $cText
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.Font            = $fBody
    $dlg.Add_Shown({ Set-JanetDarkTitleBar -Form $dlg })

    # Header
    $pnlHdr = New-Object System.Windows.Forms.Panel
    $pnlHdr.Dock = 'Top'; $pnlHdr.Height = 44; $pnlHdr.BackColor = $cHeaderBg
    $dlg.Controls.Add($pnlHdr)
    $pnlAmb = New-Object System.Windows.Forms.Panel
    $pnlAmb.Dock = 'Top'; $pnlAmb.Height = 2; $pnlAmb.BackColor = $cGold
    $pnlHdr.Controls.Add($pnlAmb)
    $lblH = New-Object System.Windows.Forms.Label
    $lblH.Text = "/ LOG VIEWER"; $lblH.Font = $fEyebrow; $lblH.ForeColor = $cGold
    $lblH.BackColor = [System.Drawing.Color]::Transparent
    $lblH.AutoSize = $false; $lblH.Size = New-Object System.Drawing.Size(400, 44)
    $lblH.Location = New-Object System.Drawing.Point(18, 0); $lblH.TextAlign = 'MiddleLeft'
    $pnlHdr.Controls.Add($lblH)

    # File picker strip
    $pnlPicker = New-Object System.Windows.Forms.Panel
    $pnlPicker.Dock = 'Top'; $pnlPicker.Height = 44
    $pnlPicker.BackColor = $cSidebar
    $dlg.Controls.Add($pnlPicker)

    $cboLog = New-Object System.Windows.Forms.ComboBox
    $cboLog.Location      = New-Object System.Drawing.Point(18, 10)
    $cboLog.Size          = New-Object System.Drawing.Size(500, 24)
    $cboLog.DropDownStyle = 'DropDownList'
    $cboLog.FlatStyle     = 'Flat'
    $cboLog.BackColor     = $cPanel
    $cboLog.ForeColor     = $cText
    $cboLog.Font          = $fMono
    $cboLog.Anchor        = 'Top,Left,Right'
    $pnlPicker.Controls.Add($cboLog)

    $btnRefresh = New-GhostButton -Text "Refresh" -X 530 -Y 10 -W 80 -H 26
    $btnRefresh.Anchor = 'Top,Right'
    $pnlPicker.Controls.Add($btnRefresh)
    $btnCopy = New-GhostButton -Text "Copy" -X 620 -Y 10 -W 70 -H 26
    $btnCopy.Anchor = 'Top,Right'
    $pnlPicker.Controls.Add($btnCopy)
    $btnFolder = New-GhostButton -Text "Folder" -X 700 -Y 10 -W 80 -H 26 -Fg $cGold -Border $cGold
    $btnFolder.Anchor = 'Top,Right'
    $pnlPicker.Controls.Add($btnFolder)

    # Content viewer
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock        = 'Fill'
    $rtb.ReadOnly    = $true
    $rtb.BackColor   = $cHeaderBg
    $rtb.ForeColor   = $cTextDim
    $rtb.Font        = $fMonoSm
    $rtb.BorderStyle = 'None'
    $rtb.WordWrap    = $false
    $dlg.Controls.Add($rtb)

    $populate = {
        $cboLog.Items.Clear()
        $logs = Get-ChildItem -Path $script:LogDir -Filter "*.log" -File -EA SilentlyContinue |
            Sort-Object LastWriteTime -Descending
        foreach ($lf in $logs) {
            $sizeKB = [Math]::Round($lf.Length / 1024, 1)
            $display = "$($lf.Name)  ($sizeKB KB, $($lf.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
            [void]$cboLog.Items.Add($display)
        }
        if ($cboLog.Items.Count -gt 0) { $cboLog.SelectedIndex = 0 }
    }

    $load = {
        $rtb.Clear()
        $idx = $cboLog.SelectedIndex
        if ($idx -lt 0) { return }
        $display = $cboLog.SelectedItem.ToString()
        $fileName = ($display -split '\s{2}')[0].Trim()
        $filePath = Join-Path $script:LogDir $fileName
        if (-not (Test-Path $filePath)) { return }
        try {
            $content = Get-Content $filePath -Raw -EA Stop
            # Line-by-line syntax highlighting
            foreach ($line in ($content -split "`r?`n")) {
                $col = $cTextDim
                if     ($line -match '\[ERROR\]|ERROR|FAILED|FAIL') { $col = $cRed }
                elseif ($line -match '\[OK\]|SUCCESS|COMPLETE|LAUNCH') { $col = $cGreen }
                elseif ($line -match '\[WARN\]|WARNING') { $col = $cOrange }
                elseif ($line -match '^\[\d{4}-\d{2}-\d{2}') {
                    $ts = ($line -split '\]')[0] + ']'
                    $rtb.SelectionColor = $cGold
                    $rtb.AppendText($ts)
                    $rest = $line.Substring($ts.Length)
                    $rtb.SelectionColor = $cTextDim
                    $rtb.AppendText($rest + "`r`n")
                    continue
                }
                $rtb.SelectionColor = $col
                $rtb.AppendText($line + "`r`n")
            }
            $rtb.SelectionStart = $rtb.TextLength
            $rtb.ScrollToCaret()
        } catch {
            $rtb.AppendText("Failed to load: $($_.Exception.Message)")
        }
    }

    $cboLog.Add_SelectedIndexChanged($load)
    $btnRefresh.Add_Click({ & $populate; & $load })
    $btnCopy.Add_Click({
        if (-not [string]::IsNullOrEmpty($rtb.Text)) {
            [System.Windows.Forms.Clipboard]::SetText($rtb.Text)
        }
    })
    $btnFolder.Add_Click({ Start-Process explorer.exe $script:LogDir })

    & $populate
    & $load

    [void]$dlg.ShowDialog()
    $dlg.Dispose()
}
#endregion

#region === Launch-Tool ===
function Launch-Tool {
    param($toolDef)
    $name = $toolDef.Name

    # Guard against double-launch
    if ($script:RunningProcs.ContainsKey($name)) {
        $existing = $script:RunningProcs[$name]
        if (-not $existing.HasExited) {
            Write-Log "LAUNCH_BLOCKED" "'$name' already running (PID $($existing.Id))"
            [System.Windows.Forms.MessageBox]::Show(
                "'$name' is already running (PID $($existing.Id)).",
                "Already Running", "OK", "Information"
            )
            return
        } else {
            $script:RunningProcs.Remove($name)
        }
    }

    # Resolve path (version-aware: falls back to "{base}_*.ps1" if literal is missing)
    $scriptPath = Resolve-ToolScript $toolDef.Script
    if (-not $scriptPath) {
        Write-Log "LAUNCH_ERROR" "Script not found: $($toolDef.Script)"
        [System.Windows.Forms.MessageBox]::Show(
            "Script not found:`n$($toolDef.Script)",
            "Path Error", "OK", "Warning"
        )
        return
    }

    # Use ProcessStartInfo so we can set per-child env vars without polluting
    # the launcher's own env.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName         = "powershell.exe"
    $psi.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $psi.UseShellExecute  = $false

    # Win32 CreateProcess rejects UNC paths as WorkingDirectory -- launching
    # from a share drive like \\server\share\... fails with "The directory
    # name is invalid." Fall back to the Windows system dir when the script's
    # parent is UNC or otherwise unreachable. The child script resolves its
    # own paths via $PSScriptRoot, so CWD is not semantically important.
    $parentDir = Split-Path $scriptPath -Parent
    $isUnc     = $parentDir -and ($parentDir.StartsWith('\\'))
    $isLocal   = $parentDir -and (Test-Path -LiteralPath $parentDir -ErrorAction SilentlyContinue)
    if ($parentDir -and -not $isUnc -and $isLocal) {
        $psi.WorkingDirectory = $parentDir
    } else {
        $psi.WorkingDirectory = $env:SystemRoot
    }

    if ($script:Credential -and (Test-Path $script:CredFile)) {
        $psi.EnvironmentVariables["JANET_CRED_FILE"] = $script:CredFile
        $psi.EnvironmentVariables["JANET_CRED_USER"] = $script:Credential.UserName
    }
    $psi.EnvironmentVariables["JANET_LAUNCHER"] = $script:LauncherVersion

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $script:RunningProcs[$name] = $proc
        $credTag = if ($script:Credential) { " (with shared creds: $($script:Credential.UserName))" } else { "" }
        Write-Log "LAUNCH" "Launched '$name' (PID $($proc.Id)) from '$scriptPath'$credTag"
    } catch {
        Write-Log "LAUNCH_ERROR" "Failed to launch '$name': $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to launch '$name':`n$($_.Exception.Message)",
            "Launch Error", "OK", "Error"
        )
    }
}
#endregion

#region === Build-ToolList ===
function Build-ToolList {
    param($scrollPanel, $config)

    $scrollPanel.SuspendLayout()
    $scrollPanel.Controls.Clear()
    $script:ToolRows = @()
    $tools = @($config.Tools)

    if ($tools.Count -eq 0) {
        $emptyCard = New-CornerBracketCard -Header "NO TOOLS REGISTERED" `
            -X 20 -Y 20 -W ($scrollPanel.ClientSize.Width - 40) -H 120 `
            -BracketColor $cOrange -HeaderColor $cOrange
        $emptyCard.Anchor = 'Top,Left,Right'
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text      = "Use the Discover button to auto-detect scripts in Tools\, or open Config to register tools manually."
        $lbl.Font      = $fCaption
        $lbl.ForeColor = $cTextDim
        $lbl.BackColor = [System.Drawing.Color]::Transparent
        $lbl.AutoSize  = $false
        $lbl.Size      = New-Object System.Drawing.Size(($scrollPanel.ClientSize.Width - 80), 40)
        $lbl.Location  = New-Object System.Drawing.Point(20, 56)
        $lbl.TextAlign = 'TopLeft'
        $emptyCard.Controls.Add($lbl)
        $scrollPanel.Controls.Add($emptyCard)
        $scrollPanel.ResumeLayout()
        return
    }

    $y         = 12
    $rowH      = 100
    $sbarW     = [System.Windows.Forms.SystemInformation]::VerticalScrollBarWidth
    $rightPad  = $sbarW + 14
    $rowW      = $scrollPanel.ClientSize.Width - 12 - $rightPad
    $btnW      = 120
    $btnRightMargin = 18
    $descLeft  = 112
    $descRight = $btnW + $btnRightMargin + 16
    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.AutoPopDelay = 10000
    $toolTip.InitialDelay = 400
    $toolTip.ReshowDelay  = 200
    $toolTip.BackColor    = $cPanel
    $toolTip.ForeColor    = $cText
    $script:MissingToolCount = 0

    for ($i = 0; $i -lt $tools.Count; $i++) {
        $tool  = $tools[$i]
        $glyph = Get-ToolGlyph $tool

        # Resolve (version-aware: falls back to "{base}_*.ps1" if literal is missing)
        $resolvedPath   = Resolve-ToolScript $tool.Script
        $scriptExists   = [bool]$resolvedPath
        $scriptFileDate = ""
        if ($scriptExists) {
            try {
                $fileInfo = Get-Item $resolvedPath -EA SilentlyContinue
                $scriptFileDate = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            } catch {}
        } else {
            $script:MissingToolCount++
        }

        # Card: purple brackets (or red if missing), gold header text
        $bracketColor = if ($scriptExists) { $cAccent } else { $cRed }
        $headerColor  = if ($scriptExists) { $cGold } else { $cRed }
        $card = New-CornerBracketCard -Header $tool.Name `
            -X 12 -Y $y -W $rowW -H $rowH `
            -BracketColor $bracketColor -HeaderColor $headerColor -Padding 20
        $card.Anchor = 'Top,Left,Right'
        $card.AccessibleName = $(if ($scriptExists) { "available" } else { "missing" })

        # Index
        $lblIdx = New-Object System.Windows.Forms.Label
        $lblIdx.Text      = "{0:D2}" -f ($i + 1)
        $lblIdx.Font      = $fMonoSm
        $lblIdx.ForeColor = $cTextDark
        $lblIdx.BackColor = [System.Drawing.Color]::Transparent
        $lblIdx.AutoSize  = $false
        $lblIdx.Size      = New-Object System.Drawing.Size(28, 22)
        $lblIdx.Location  = New-Object System.Drawing.Point(20, 52)
        $lblIdx.TextAlign = 'MiddleLeft'
        $card.Controls.Add($lblIdx)

        # Icon
        $iconFg = if ($scriptExists) { $cAccent } else { $cTextMuted }
        $iconLbl = New-IconLabel -Glyph $glyph -X 48 -Y 44 -W 42 -H 42 -Fg $iconFg -Font $fIconLg
        $card.Controls.Add($iconLbl)

        # Pulse dot
        $dotState = if ($scriptExists) { 'Idle' } else { 'Error' }
        $statusDot = New-PulseDot -X 96 -Y 60 -Size 8 -State $dotState
        $card.Controls.Add($statusDot)
        $card.Tag = @{ Name = $tool.Name; Dot = $statusDot; Exists = $scriptExists; Button = $null }

        # Description
        $descWidth = $rowW - $descLeft - $descRight
        $lblDesc = New-Object System.Windows.Forms.Label
        $lblDesc.Text      = $tool.Description
        $lblDesc.Font      = $fBody
        $lblDesc.ForeColor = $(if ($scriptExists) { $cTextDim } else { $cTextDark })
        $lblDesc.BackColor = [System.Drawing.Color]::Transparent
        $lblDesc.AutoSize  = $false
        $lblDesc.Size      = New-Object System.Drawing.Size($descWidth, 20)
        $lblDesc.Location  = New-Object System.Drawing.Point($descLeft, 52)
        $lblDesc.TextAlign = 'MiddleLeft'
        $lblDesc.Anchor    = 'Top,Left,Right'
        $lblDesc.AutoEllipsis = $true
        $toolTip.SetToolTip($lblDesc, $tool.Description)
        $card.Controls.Add($lblDesc)

        # Path + date — show the actual resolved filename so versioned twins surface in the UI
        $displayLeaf = if ($scriptExists) { Split-Path $resolvedPath -Leaf } else { Split-Path $tool.Script -Leaf }
        $pathText = $displayLeaf.ToUpperInvariant()
        if ($scriptExists -and $displayLeaf -ne (Split-Path $tool.Script -Leaf)) {
            $pathText = "$($tool.Script.ToUpperInvariant())  >>  $($displayLeaf.ToUpperInvariant())"
        }
        if ($scriptFileDate -ne "") { $pathText += "   MODIFIED $scriptFileDate" }
        $lblPath = New-Object System.Windows.Forms.Label
        $lblPath.Text      = $pathText
        $lblPath.Font      = $fMonoTiny
        $lblPath.ForeColor = $(if ($scriptExists) { $cTextDark } else { $cRed })
        $lblPath.BackColor = [System.Drawing.Color]::Transparent
        $lblPath.AutoSize  = $false
        $lblPath.Size      = New-Object System.Drawing.Size($descWidth, 16)
        $lblPath.Location  = New-Object System.Drawing.Point($descLeft, 74)
        $lblPath.TextAlign = 'MiddleLeft'
        $lblPath.Anchor    = 'Top,Left,Right'
        $lblPath.AutoEllipsis = $true
        if (-not $scriptExists) { $toolTip.SetToolTip($lblPath, "File not found: $resolvedPath") }
        $card.Controls.Add($lblPath)

        # LAUNCH button
        if ($scriptExists) {
            $btnLaunch = New-StripeButton -Text "Launch" -W $btnW -H 38
        } else {
            $btnLaunch = New-GhostButton -Text "Missing" -W $btnW -H 38 -Fg $cRed -Border $cRed
            $btnLaunch.Font = $fBodyStrong
            $btnLaunch.AutoEllipsis = $true
            $toolTip.SetToolTip($btnLaunch, "Script not found: $($tool.Script)")
        }
        $btnLaunch.Location = New-Object System.Drawing.Point(($rowW - $btnW - $btnRightMargin), 48)
        $btnLaunch.Anchor   = 'Top,Right'
        $btnLaunch.Tag      = $i
        $btnLaunch.Enabled  = $scriptExists
        $btnLaunch.Add_Click({
            $idx = [int]$this.Tag
            $cfg = Load-Config
            $tools = @($cfg.Tools)
            if ($idx -lt $tools.Count) { Launch-Tool $tools[$idx] }
        })
        $card.Controls.Add($btnLaunch)
        $card.Tag.Button = $btnLaunch

        $scrollPanel.Controls.Add($card)
        $y += $rowH + 12
    }

    $scrollPanel.ResumeLayout()
    Update-StatusBar
}
#endregion

# ---------------------------------------------------------------------------
# MAIN FORM
# ---------------------------------------------------------------------------
$script:config = Load-Config

$form = New-Object System.Windows.Forms.Form
$form.Text            = "J.A.N.E.T / LAUNCHER  $($script:LauncherVersion)"
$form.Size            = New-Object System.Drawing.Size(1180, 720)
$form.MinimumSize     = New-Object System.Drawing.Size(880, 520)
$form.StartPosition   = 'CenterScreen'
$form.BackColor       = $cBg
$form.ForeColor       = $cText
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox     = $true
$form.Font            = $fBody
Enable-DoubleBuffer $form
$form.Add_Shown({ Set-JanetDarkTitleBar -Form $form })

# -----  HEADER  -----
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock      = 'Top'
$pnlHeader.Height    = 90
$pnlHeader.BackColor = $cHeaderBg
Enable-DoubleBuffer $pnlHeader
$form.Controls.Add($pnlHeader)

# Gold accent line at the top
$pnlAccentLine = New-Object System.Windows.Forms.Panel
$pnlAccentLine.Dock      = 'Top'
$pnlAccentLine.Height    = 2
$pnlAccentLine.BackColor = $cGold
$pnlHeader.Controls.Add($pnlAccentLine)

# Purple + gold gradient glows + dotted underline
$pnlHeader.Add_Paint({
    param($sender, $e)
    $gLeft = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point(0, 0)),
        (New-Object System.Drawing.Point(([int]($sender.Width * 0.35)), 0)),
        [System.Drawing.Color]::FromArgb(14, $cAccent.R, $cAccent.G, $cAccent.B),
        [System.Drawing.Color]::FromArgb(0, $cAccent.R, $cAccent.G, $cAccent.B))
    try { $e.Graphics.FillRectangle($gLeft, 0, 0, ([int]($sender.Width*0.35)), $sender.Height) }
    finally { $gLeft.Dispose() }
    $gRight = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point(([int]($sender.Width * 0.7)), 0)),
        (New-Object System.Drawing.Point($sender.Width, 0)),
        [System.Drawing.Color]::FromArgb(0, $cGold.R, $cGold.G, $cGold.B),
        [System.Drawing.Color]::FromArgb(10, $cGold.R, $cGold.G, $cGold.B))
    try { $e.Graphics.FillRectangle($gRight, ([int]($sender.Width*0.7)), 0, ([int]($sender.Width*0.3)+1), $sender.Height) }
    finally { $gRight.Dispose() }
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, $cAccent.R, $cAccent.G, $cAccent.B), 1)
    $pen.DashStyle = 'Dot'
    try { $e.Graphics.DrawLine($pen, 0, ($sender.Height - 1), $sender.Width, ($sender.Height - 1)) }
    finally { $pen.Dispose() }
}.GetNewClosure())
$pnlHeader.Add_SizeChanged({ $this.Invalidate() })

# [ 01 ] station index
$lblIdx = New-Object System.Windows.Forms.Label
$lblIdx.Text      = "[ 01 ]"
$lblIdx.Font      = $fEyebrow
$lblIdx.ForeColor = $cAccent
$lblIdx.BackColor = [System.Drawing.Color]::Transparent
$lblIdx.AutoSize  = $false
$lblIdx.Size      = New-Object System.Drawing.Size(48, 22)
$lblIdx.Location  = New-Object System.Drawing.Point(22, 16)
$lblIdx.TextAlign = 'MiddleLeft'
$pnlHeader.Controls.Add($lblIdx)

# Signal icon
$lblSignal = New-IconLabel -Glyph $icoSignal -X 22 -Y 44 -W 32 -H 32 -Fg $cAccent -Font $fIconLg
$pnlHeader.Controls.Add($lblSignal)

# Title
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "J.A.N.E.T / LAUNCHER"
$lblTitle.Font      = $fDisplayMd
$lblTitle.ForeColor = $cText
$lblTitle.BackColor = [System.Drawing.Color]::Transparent
$lblTitle.AutoSize  = $false
$lblTitle.Size      = New-Object System.Drawing.Size(500, 26)
$lblTitle.Location  = New-Object System.Drawing.Point(92, 18)
$lblTitle.TextAlign = 'MiddleLeft'
$pnlHeader.Controls.Add($lblTitle)

# Subtitle
$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text      = "Joint Administration and Network Execution Toolkit"
$lblSubtitle.Font      = $fCaption
$lblSubtitle.ForeColor = $cTextDim
$lblSubtitle.BackColor = [System.Drawing.Color]::Transparent
$lblSubtitle.AutoSize  = $false
$lblSubtitle.Size      = New-Object System.Drawing.Size(520, 18)
$lblSubtitle.Location  = New-Object System.Drawing.Point(92, 44)
$lblSubtitle.TextAlign = 'MiddleLeft'
$pnlHeader.Controls.Add($lblSubtitle)

# Operator line
$lblOperator = New-Object System.Windows.Forms.Label
$lblOperator.Text      = ("OPERATOR {0}   /   STATION {1}" -f $env:USERNAME.ToUpperInvariant(), $env:COMPUTERNAME.ToUpperInvariant())
$lblOperator.Font      = $fMonoTiny
$lblOperator.ForeColor = $cTextDark
$lblOperator.BackColor = [System.Drawing.Color]::Transparent
$lblOperator.AutoSize  = $false
$lblOperator.Size      = New-Object System.Drawing.Size(520, 16)
$lblOperator.Location  = New-Object System.Drawing.Point(92, 64)
$lblOperator.TextAlign = 'MiddleLeft'
$pnlHeader.Controls.Add($lblOperator)

# Version chip (gold bg, dark text)
$lblVer = New-Object System.Windows.Forms.Label
$lblVer.Text      = $script:LauncherVersion.ToUpperInvariant()
$lblVer.Font      = $fEyebrow
$lblVer.ForeColor = $cTextOnGold
$lblVer.BackColor = $cGold
$lblVer.AutoSize  = $false
$lblVer.Size      = New-Object System.Drawing.Size(76, 22)
$lblVer.Location  = New-Object System.Drawing.Point(($form.ClientSize.Width - 100), 18)
$lblVer.TextAlign = 'MiddleCenter'
$lblVer.Anchor    = 'Top,Right'
$pnlHeader.Controls.Add($lblVer)

# Live clock
$lblClock = New-Object System.Windows.Forms.Label
$lblClock.Text      = (Get-Date).ToString("HH:mm:ss")
$lblClock.Font      = $fMonoSm
$lblClock.ForeColor = $cTextMuted
$lblClock.BackColor = [System.Drawing.Color]::Transparent
$lblClock.AutoSize  = $false
$lblClock.Size      = New-Object System.Drawing.Size(80, 16)
$lblClock.Location  = New-Object System.Drawing.Point(($form.ClientSize.Width - 96), 46)
$lblClock.TextAlign = 'MiddleRight'
$lblClock.Anchor    = 'Top,Right'
$pnlHeader.Controls.Add($lblClock)

$script:ClockTimer = New-Object System.Windows.Forms.Timer
$script:ClockTimer.Interval = 1000
$script:ClockTimer.Add_Tick({ $lblClock.Text = (Get-Date).ToString("HH:mm:ss") })
$script:ClockTimer.Start()

# -----  TOOLBAR  -----
$pnlToolbar = New-Object System.Windows.Forms.Panel
$pnlToolbar.Size      = New-Object System.Drawing.Size(1024, 52)
$pnlToolbar.Location  = New-Object System.Drawing.Point(0, 91)
$pnlToolbar.BackColor = $cBg
$pnlToolbar.Anchor    = 'Top,Left,Right'
Enable-DoubleBuffer $pnlToolbar
$form.Controls.Add($pnlToolbar)

# SET CREDS (stripe button - purple, primary session-gating action)
$btnSetCred = New-StripeButton -Text "Set Creds" -X 18 -Y 9 -W 120 -H 34
$pnlToolbar.Controls.Add($btnSetCred)

# CRED cluster
$dotCred = New-PulseDot -X 152 -Y 22 -Size 8 -State Idle
$pnlToolbar.Controls.Add($dotCred)

$lblCredEyebrow = New-EyebrowLabel -Text "CRED" -X 164 -Y 8 -W 50 -H 14 -Fg $cGold
$pnlToolbar.Controls.Add($lblCredEyebrow)

$lblCredStatus = New-Object System.Windows.Forms.Label
$lblCredStatus.Text      = "not set"
$lblCredStatus.Font      = $fMonoSm
$lblCredStatus.ForeColor = $cRed
$lblCredStatus.BackColor = [System.Drawing.Color]::Transparent
$lblCredStatus.AutoSize  = $false
$lblCredStatus.Size      = New-Object System.Drawing.Size(140, 20)
$lblCredStatus.Location  = New-Object System.Drawing.Point(164, 24)
$lblCredStatus.TextAlign = 'MiddleLeft'
$lblCredStatus.AutoEllipsis = $true
$pnlToolbar.Controls.Add($lblCredStatus)

$updateCredCluster = {
    if ($script:Credential) {
        $lblCredStatus.Text      = $script:Credential.UserName
        $lblCredStatus.ForeColor = $cGreen
        Set-PulseDotState -Dot $dotCred -State 'Active'
    } else {
        $lblCredStatus.Text      = "not set"
        $lblCredStatus.ForeColor = $cRed
        Set-PulseDotState -Dot $dotCred -State 'Idle'
    }
}

$btnSetCred.Add_Click({
    $ok = Set-LauncherCredential
    if ($ok) { & $updateCredCluster }
})

# Right-click cred value to clear
$cmCred = New-Object System.Windows.Forms.ContextMenuStrip
$cmCred.BackColor = $cPanel
$cmCred.ForeColor = $cText
$miClear = $cmCred.Items.Add("Clear shared credentials")
$miClear.Add_Click({
    Clear-LauncherCredential
    & $updateCredCluster
})
$lblCredStatus.ContextMenuStrip = $cmCred

# RUN cluster
$dotRun = New-PulseDot -X 320 -Y 22 -Size 8 -State Idle
$pnlToolbar.Controls.Add($dotRun)

$lblRunEyebrow = New-EyebrowLabel -Text "RUN" -X 332 -Y 8 -W 36 -H 14 -Fg $cGold
$pnlToolbar.Controls.Add($lblRunEyebrow)

$lblRunCount = New-Object System.Windows.Forms.Label
$lblRunCount.Text      = "0 idle"
$lblRunCount.Font      = $fMonoSm
$lblRunCount.ForeColor = $cTextMuted
$lblRunCount.BackColor = [System.Drawing.Color]::Transparent
$lblRunCount.AutoSize  = $false
$lblRunCount.Size      = New-Object System.Drawing.Size(80, 20)
$lblRunCount.Location  = New-Object System.Drawing.Point(332, 24)
$lblRunCount.TextAlign = 'MiddleLeft'
$pnlToolbar.Controls.Add($lblRunCount)

# Stop All (hidden until something is running)
$btnStopAll = New-GhostButton -Text "Stop" -X 420 -Y 13 -W 64 -H 28 -Fg $cRed -Border $cRed
$btnStopAll.Visible = $false
$btnStopAll.Add_Click({
    $running = @($script:RunningProcs.GetEnumerator() | Where-Object { -not $_.Value.HasExited })
    if ($running.Count -eq 0) { return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Stop all $($running.Count) running tool(s)?`n`n$($running.ForEach({ $_.Key }) -join ', ')",
        "Confirm Stop All", "YesNo", "Question"
    )
    if ($confirm -eq 'Yes') {
        foreach ($entry in $running) {
            try {
                $entry.Value.Kill()
                Write-Log "STOP_TOOL" "Stopped '$($entry.Key)' (PID $($entry.Value.Id))"
            } catch {
                Write-Log "STOP_ERROR" "Failed to stop '$($entry.Key)': $($_.Exception.Message)"
            }
        }
        $script:RunningProcs.Clear()
    }
})
$pnlToolbar.Controls.Add($btnStopAll)

# Right utility cluster with Image+Text buttons
$applyGlyph = {
    param($Button, [char]$Glyph, $Color)
    $Button.Image             = ConvertTo-GlyphBitmap -Glyph $Glyph -Color $Color -Size 16
    $Button.ImageAlign        = 'MiddleLeft'
    $Button.TextAlign         = 'MiddleLeft'
    $Button.TextImageRelation = 'ImageBeforeText'
    $Button.Padding           = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
    $Button.Font              = $fBodyStrong
    $Button.AutoEllipsis      = $true
}

$btnArchive = New-GhostButton -Text "Archive" -X 494 -Y 13 -W 130 -H 30 -Fg $cGold -Border $cGold
$btnArchive.Anchor = 'Top,Right'
& $applyGlyph $btnArchive $icoFolder $cGold
$btnArchive.Add_Click({ Show-ArchiveDialog })
$pnlToolbar.Controls.Add($btnArchive)

$btnDiscover = New-GhostButton -Text "Discover" -X 634 -Y 13 -W 140 -H 30 -Fg $cGold -Border $cGold
$btnDiscover.Anchor = 'Top,Right'
& $applyGlyph $btnDiscover $icoSync $cGold
$btnDiscover.Add_Click({
    $changed = Show-DiscoveryDialog
    if ($changed) {
        $script:config = Load-Config
        Build-ToolList -scrollPanel $pnlScroll -config $script:config
    }
})
$pnlToolbar.Controls.Add($btnDiscover)

$btnRefresh = New-GhostButton -Text "Refresh" -X 780 -Y 13 -W 124 -H 30
$btnRefresh.Anchor = 'Top,Right'
& $applyGlyph $btnRefresh $icoRefresh $cTextDim
$btnRefresh.Add_Click({
    $script:config = Load-Config
    Build-ToolList -scrollPanel $pnlScroll -config $script:config
})
$pnlToolbar.Controls.Add($btnRefresh)

$btnLogs = New-GhostButton -Text "Logs" -X 910 -Y 13 -W 100 -H 30
$btnLogs.Anchor = 'Top,Right'
& $applyGlyph $btnLogs $icoDoc $cTextDim
$btnLogs.Add_Click({ Show-LogViewer })
$pnlToolbar.Controls.Add($btnLogs)

$btnConfig = New-GhostButton -Text "Config" -X 1016 -Y 13 -W 116 -H 30
$btnConfig.Anchor = 'Top,Right'
& $applyGlyph $btnConfig $icoSettings $cTextDim
$btnConfig.Add_Click({
    Show-ConfigEditor
    $script:config = Load-Config
    Build-ToolList -scrollPanel $pnlScroll -config $script:config
})
$pnlToolbar.Controls.Add($btnConfig)

# Dotted pinstripe separator
$pnlSep = New-Object System.Windows.Forms.Panel
$pnlSep.Size      = New-Object System.Drawing.Size(1024, 2)
$pnlSep.Location  = New-Object System.Drawing.Point(0, 143)
$pnlSep.BackColor = $cBg
$pnlSep.Anchor    = 'Top,Left,Right'
$form.Controls.Add($pnlSep)
$pnlSep.Add_Paint({
    param($sender, $e)
    $dotColor = [System.Drawing.Color]::FromArgb(60, $cAccent.R, $cAccent.G, $cAccent.B)
    $pen = New-Object System.Drawing.Pen($dotColor, 1)
    $pen.DashStyle = 'Dot'
    try { $e.Graphics.DrawLine($pen, 0, 0, $sender.Width, 0) }
    finally { $pen.Dispose() }
}.GetNewClosure())
$pnlSep.Add_SizeChanged({ $this.Invalidate() })

# -----  SCROLLABLE TOOL LIST  -----
$pnlScroll = New-Object System.Windows.Forms.Panel
$pnlScroll.Location   = New-Object System.Drawing.Point(0, 145)
$pnlScroll.Size       = New-Object System.Drawing.Size(1024, 500)
$pnlScroll.AutoScroll = $true
$pnlScroll.BackColor  = $cBg
$pnlScroll.Anchor     = 'Top,Left,Right,Bottom'
Enable-DoubleBuffer $pnlScroll
Add-GridPaperBackground -Panel $pnlScroll -Spacing 18
$form.Controls.Add($pnlScroll)

# -----  POLLING TIMER  -----
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({
    $runningCount = 0
    foreach ($row in $pnlScroll.Controls) {
        if ($row -isnot [System.Windows.Forms.Panel]) { continue }
        $tag = $row.Tag
        if (-not ($tag -is [hashtable]) -or -not $tag.ContainsKey('Name')) { continue }
        if (-not $tag.Exists) { continue }
        $toolName  = $tag.Name
        $statusDot = $tag.Dot
        $launchBtn = $tag.Button

        if ($script:RunningProcs.ContainsKey($toolName)) {
            $proc = $script:RunningProcs[$toolName]
            if (-not $proc.HasExited) {
                $runningCount++
                if ($statusDot) { Set-PulseDotState -Dot $statusDot -State 'Active' }
                if ($launchBtn) {
                    $launchBtn.Text      = "RUNNING"
                    $launchBtn.BackColor = $cGreenDim
                    $launchBtn.ForeColor = $cText
                    $launchBtn.FlatAppearance.MouseOverBackColor = $cGreenDim
                    $launchBtn.Enabled   = $false
                }
            } else {
                $script:RunningProcs.Remove($toolName)
                Write-Log "TOOL_EXITED" "'$toolName' process exited (code $($proc.ExitCode))"
                if ($statusDot) { Set-PulseDotState -Dot $statusDot -State 'Idle' }
                if ($launchBtn) {
                    $launchBtn.Text      = "LAUNCH"
                    $launchBtn.BackColor = $cAccent
                    $launchBtn.ForeColor = $cTextOnAccent
                    $launchBtn.FlatAppearance.MouseOverBackColor = $cAccentHov
                    $launchBtn.Enabled   = $true
                }
            }
        } else {
            if ($statusDot) { Set-PulseDotState -Dot $statusDot -State 'Idle' }
            if ($launchBtn -and $launchBtn.Enabled) {
                $launchBtn.Text      = "LAUNCH"
                $launchBtn.BackColor = $cAccent
                $launchBtn.ForeColor = $cTextOnAccent
                $launchBtn.FlatAppearance.MouseOverBackColor = $cAccentHov
            }
        }
    }

    if ($runningCount -gt 0) {
        Set-PulseDotState -Dot $dotRun -State 'Active'
        $lblRunCount.Text      = ("{0} active" -f $runningCount)
        $lblRunCount.ForeColor = $cGreen
        $btnStopAll.Visible    = $true
    } else {
        Set-PulseDotState -Dot $dotRun -State 'Idle'
        $lblRunCount.Text      = "0 idle"
        $lblRunCount.ForeColor = $cTextMuted
        $btnStopAll.Visible    = $false
    }
})
$timer.Start()

# -----  STATUS BAR HELPER (must exist before Build-ToolList)  -----
function Update-StatusBar {
    if (-not $lblStatus) { return }
    $missingStr = if ($script:MissingToolCount -gt 0) { ("   |   MISSING {0}" -f $script:MissingToolCount) } else { "" }
    $lblStatus.Text = ("TOOLS {0}{1}   |   {2}" -f $script:config.Tools.Count, $missingStr, $script:ScriptDir)
}

# -----  INITIAL TOOL LIST BUILD  -----
Build-ToolList -scrollPanel $pnlScroll -config $script:config

# -----  STATUS BAR  -----
$pnlStatusBar = New-Object System.Windows.Forms.Panel
$pnlStatusBar.Dock      = 'Bottom'
$pnlStatusBar.Height    = 30
$pnlStatusBar.BackColor = $cHeaderBg
Enable-DoubleBuffer $pnlStatusBar
$form.Controls.Add($pnlStatusBar)

$pnlStatusBar.Add_Paint({
    param($sender, $e)
    $lineColor = [System.Drawing.Color]::FromArgb(8, 255, 255, 255)
    $pen = New-Object System.Drawing.Pen($lineColor, 1)
    try {
        for ($y = 0; $y -lt $sender.Height; $y += 3) {
            $e.Graphics.DrawLine($pen, 0, $y, $sender.Width, $y)
        }
    } finally { $pen.Dispose() }
}.GetNewClosure())
$pnlStatusBar.Add_SizeChanged({ $this.Invalidate() })

$pnlStatusTop = New-Object System.Windows.Forms.Panel
$pnlStatusTop.Dock      = 'Top'
$pnlStatusTop.Height    = 1
$pnlStatusTop.BackColor = $cGoldDim
$pnlStatusBar.Controls.Add($pnlStatusTop)

$lblStatus = New-Object System.Windows.Forms.Label
$missingStr = if ($script:MissingToolCount -gt 0) { ("   |   MISSING {0}" -f $script:MissingToolCount) } else { "" }
$lblStatus.Text      = ("TOOLS {0}{1}   |   {2}" -f $script:config.Tools.Count, $missingStr, $script:ScriptDir)
$lblStatus.Font      = $fMonoTiny
$lblStatus.ForeColor = $cTextMuted
$lblStatus.BackColor = [System.Drawing.Color]::Transparent
$lblStatus.AutoSize  = $false
$lblStatus.Size      = New-Object System.Drawing.Size(700, 28)
$lblStatus.Location  = New-Object System.Drawing.Point(14, 2)
$lblStatus.TextAlign = 'MiddleLeft'
$pnlStatusBar.Controls.Add($lblStatus)

$dotLog = New-PulseDot -X 0 -Y 11 -Size 8 -State Active
$dotLog.Anchor = 'Top,Right'
$pnlStatusBar.Controls.Add($dotLog)

$lblLogIndicator = New-Object System.Windows.Forms.Label
$lblLogIndicator.Text      = "LOG"
$lblLogIndicator.Font      = $fEyebrow
$lblLogIndicator.ForeColor = $cGreen
$lblLogIndicator.BackColor = [System.Drawing.Color]::Transparent
$lblLogIndicator.AutoSize  = $false
$lblLogIndicator.Size      = New-Object System.Drawing.Size(40, 20)
$lblLogIndicator.Location  = New-Object System.Drawing.Point(0, 5)
$lblLogIndicator.TextAlign = 'MiddleRight'
$lblLogIndicator.Anchor    = 'Top,Right'
$pnlStatusBar.Controls.Add($lblLogIndicator)

$positionLogIndicator = {
    $w = $pnlStatusBar.ClientSize.Width
    $lblLogIndicator.Location = New-Object System.Drawing.Point(($w - 58), 5)
    $dotLog.Location          = New-Object System.Drawing.Point(($w - 18), 11)
}
& $positionLogIndicator

# -----  RESIZE HANDLER  -----
$form.Add_Resize({
    $pnlToolbar.Width = $form.ClientSize.Width
    $pnlSep.Width     = $form.ClientSize.Width
    $pnlScroll.Size   = New-Object System.Drawing.Size(
        ($form.ClientSize.Width - 16),
        ($form.ClientSize.Height - $pnlScroll.Location.Y - $pnlStatusBar.Height)
    )
    if ($lblLogIndicator -and $dotLog) { & $positionLogIndicator }
})

# -----  CLEANUP  -----
$form.Add_FormClosing({
    $timer.Stop()
    $timer.Dispose()
    if ($script:ClockTimer) {
        $script:ClockTimer.Stop()
        $script:ClockTimer.Dispose()
    }
    $allDots = @($dotCred, $dotRun, $dotLog)
    foreach ($row in $pnlScroll.Controls) {
        if ($row -is [System.Windows.Forms.Panel] -and $row.Tag -is [hashtable] -and $row.Tag.Dot) {
            $allDots += $row.Tag.Dot
        }
    }
    foreach ($d in $allDots) {
        if ($d -and $d.Tag -and $d.Tag.Timer) {
            try { $d.Tag.Timer.Stop(); $d.Tag.Timer.Dispose() } catch {}
        }
    }
    try { Clear-LauncherCredential } catch {}
    Write-Log "LAUNCHER_STOP" "JANET Launcher closed"
})

# -----  SHOW  -----
[void]$form.ShowDialog()
$form.Dispose()
