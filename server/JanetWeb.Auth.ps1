# =============================================================================
#  JanetWeb.Auth.ps1  -  operator credential handling for JANET Web
#
#  Same model the WinForms tools use: the operator clicks "Set Credentials",
#  the SERVER-SIDE Get-Credential dialog pops on their interactive desktop, and
#  they pick their ADW cert via "More choices > Smart Card". The resulting
#  PSCredential is held in the server's memory (never written to disk by
#  us, never sent to the browser) and handed to each tool action as -Credential.
#  When no credential is set, actions run as the operator's current Kerberos
#  identity (the CAC-bound ticket) - the no-typing path.
#
#  The Get-Credential dialog appears because the server runs in the
#  operator's own interactive session (localhost, as them) - exactly like the
#  tools. The browser only ever triggers it and reads back the username.
# =============================================================================

function Prompt-JanetWebCredential {
    <#  Pop the smartcard/credential picker and return a status object.
        The caller (server route) stores the returned credential in server state. #>
    param([string]$Message = 'Select your ADW credential for JANET Web remote operations')
    # Get-Credential is a desktop dialog and runs synchronously on the single accept
    # thread - if the server was started without an interactive desktop (detached /
    # Session 0 / over WinRM) it can NEVER render and would hang the whole server.
    # Bail with a clear message instead. (Launch JANET Web from your own PowerShell
    # console so the smartcard picker can appear; see Launch JANET Web.cmd.)
    if (-not [Environment]::UserInteractive) {
        return @{ ok = $false; cred = $null; user = ''; message = 'JANET Web was started without an interactive desktop, so the smartcard picker cannot appear. Relaunch it from your own PowerShell console (or use "Launch JANET Web.cmd") to set ADW credentials - or run read-only as your current Kerberos identity.' }
    }
    # If this PowerShell is configured to prompt for credentials in the CONSOLE
    # (ShellIds\...\ConsolePrompting = True), Get-Credential renders as typed text
    # in the console instead of the GUI smartcard picker - so nothing pops up on the
    # desktop and the browser POST just hangs waiting on console input. Detect that
    # one config up front and tell the operator exactly how to restore the picker,
    # instead of leaving the click looking like it did nothing.
    try {
        $cp = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name ConsolePrompting -ErrorAction SilentlyContinue).ConsolePrompting
        if ("$cp" -eq 'True') {
            return @{ ok = $false; cred = $null; user = ''; message = 'The smartcard picker cannot appear: this PowerShell is set to prompt for credentials in the console (ConsolePrompting=True), which suppresses the GUI dialog. Restore it from an elevated PowerShell: Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" ConsolePrompting False  - then relaunch JANET Web. (Or run read-only as your current Kerberos identity.)' }
        }
    } catch {}
    # Best-effort: raise a top-most, invisible owner window to the foreground right
    # before the prompt so the Windows credential dialog appears OVER the browser.
    # CredUI parents to the foreground window; without this nudge it can open hidden
    # behind the browser, which looks like "no popup appeared". Mirrors the file
    # picker's foreground trick; falls back silently to a plain Get-Credential.
    #
    # A bare SetForegroundWindow is NOT enough: Windows' foreground lock refuses a
    # focus steal from a background console (the server) while the browser is the
    # foreground app, so the dialog still opens behind it. Defeat the lock the
    # documented way - zero SPI_SETFOREGROUNDLOCKTIMEOUT and AttachThreadInput our
    # thread to the current foreground thread for the duration of the focus change.
    $fgOwner = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        try {
            # Add-Type compiles this into the AppDomain once per process; all
            # references live in this file, so rename namespace + call sites together.
            Add-Type -Namespace JWeb -Name FgWin -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
[DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
[DllImport("user32.dll", SetLastError=true)] public static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);
'@ -ErrorAction Stop
        } catch {}   # already defined on a later call - fine
        $fgOwner = New-Object System.Windows.Forms.Form
        $fgOwner.TopMost = $true; $fgOwner.ShowInTaskbar = $false; $fgOwner.Opacity = 0
        $fgOwner.FormBorderStyle = 'FixedToolWindow'; $fgOwner.StartPosition = 'CenterScreen'
        $fgOwner.Size = New-Object System.Drawing.Size(1, 1)
        $fgOwner.Show(); $fgOwner.Activate(); $fgOwner.BringToFront()
        try {
            $h = $fgOwner.Handle
            [JWeb.FgWin]::SystemParametersInfoW(0x2001, 0, [IntPtr]::Zero, 0) | Out-Null   # SPI_SETFOREGROUNDLOCKTIMEOUT = 0
            $fg       = [JWeb.FgWin]::GetForegroundWindow()
            $procId   = [uint32]0
            $fgThread = [JWeb.FgWin]::GetWindowThreadProcessId($fg, [ref]$procId)
            $myThread = [JWeb.FgWin]::GetCurrentThreadId()
            $attached = $false
            if ($fgThread -ne 0 -and $fgThread -ne $myThread) { $attached = [JWeb.FgWin]::AttachThreadInput($myThread, $fgThread, $true) }
            [JWeb.FgWin]::ShowWindow($h, 5)       | Out-Null   # SW_SHOW
            [JWeb.FgWin]::BringWindowToTop($h)    | Out-Null
            [JWeb.FgWin]::SetForegroundWindow($h) | Out-Null
            if ($attached) { [JWeb.FgWin]::AttachThreadInput($myThread, $fgThread, $false) | Out-Null }
        } catch {}
        [System.Windows.Forms.Application]::DoEvents()
    } catch {}
    try {
        $cred = Get-Credential -Message $Message -ErrorAction Stop
        if (-not $cred) {
            return @{ ok = $false; cred = $null; user = ''; message = 'Cancelled - no credential selected.' }
        }
        # Smartcard / cert-backed creds round-trip fine but an EMPTY password
        # SecureString means it is unusable for WinRM.
        # audit 2026-07-28: the two claims this comment used to make were both
        # false and worth correcting rather than trusting. (1) It said the tools
        # detect this because "GetNetworkCredential throws" - verified on PS 5.1
        # that it does NOT throw on a cert-format credential; the IsNullOrEmpty
        # test below is what actually decides, and the catch is near-dead.
        # (2) It said this avoids "leaving the decrypted password on the heap" -
        # GetNetworkCredential() marshals the secret into an immutable
        # System.String that cannot be zeroed, so it stays on the managed heap
        # until GC. Do NOT read this as a no-cleartext path: the tool modules
        # decrypt the same way on every AD call (adsearch, adto, c2c, history,
        # wpt), so the process already holds cleartext in normal operation and
        # this probe adds nothing measurable. Left as-is deliberately - swapping
        # to a $cred.Password.Length test would be equivalent, not safer.
        $usable = $true
        try {
            $probe = $cred.GetNetworkCredential()
            $usable = [bool]($probe -and (-not [string]::IsNullOrEmpty($probe.Password)))
            $probe  = $null
        } catch { $usable = $false }
        if (-not $usable) {
            return @{ ok = $false; cred = $null; user = $cred.UserName; message = 'That credential has no usable password (smartcard with no PIN-derived secret). Pick again or run as your current identity.' }
        }
        return @{ ok = $true; cred = $cred; user = $cred.UserName; message = "Credential set: $($cred.UserName)" }
    } catch {
        return @{ ok = $false; cred = $null; user = ''; message = "Credential capture failed: $($_.Exception.Message)" }
    } finally {
        try { if ($fgOwner) { $fgOwner.Close(); $fgOwner.Dispose() } } catch {}
    }
}

function Get-JanetWebCredentialStatus {
    # Summarize the current credential for the status bar (no secret material).
    param($Credential)
    if ($Credential -is [System.Management.Automation.PSCredential]) {
        return @{ set = $true; user = $Credential.UserName; mode = 'explicit (ADW)' }
    }
    return @{ set = $false; user = "$env:USERDOMAIN\$env:USERNAME"; mode = 'current Kerberos (CAC)' }
}
