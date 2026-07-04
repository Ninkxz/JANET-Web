#Requires -Version 5.1
<#
.SYNOPSIS
    Internal launcher for J.A.N.E.T. TWO. DO NOT run this directly - double-click
    "Launch JANET TWO.cmd" instead. The .cmd pins the classic blue console (conhost,
    -STA) that the server-side "Set Credentials" smartcard picker needs; launching
    this .ps1 from another host (PowerShell 7, an IDE terminal) can stop that picker
    from appearing. (If you do run it directly it will try to self-heal by relaunching
    in conhost.)
.DESCRIPTION
    Mints a per-launch session token, starts the built-in HttpListener server
    bound to 127.0.0.1 only, and opens your browser to the tokenized URL.

    PURE POWERSHELL - no modules to install, no third-party software. Uses only
    the .NET HttpListener that ships with Windows (PowerShell 5.1 and 7). Suited
    to a locked-down AFNET box. Runs entirely as YOU on localhost - the same
    security model as the WinForms tools. The originals in ..\Tools\ are never
    touched; their engines are reused by the modules under .\modules\.

    The loopback listener binds fine as a normal (non-elevated) user. Launch it
    from the PowerShell session you do admin work in, so remote actions run under
    the same context (and you can pick your ADW cert via Set Credentials).
.PARAMETER Port
    Loopback port to listen on. Default 8089.
.PARAMETER Asi
    Optional ASI to stamp on this session's JANET log rollup.
.PARAMETER NoBrowser
    Start the server without auto-opening the browser.
#>
[CmdletBinding()]
param(
    [int]$Port = 8089,
    [string]$Asi = '',
    [string]$PackagesRoot = '',   # where the Remote Package Installer lists packages from (default: .\Packages)
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# --- pin the CLASSIC blue console (conhost), NOT Windows Terminal ---------------
# The server-side "Set Credentials" smartcard picker (Get-Credential) does not
# reliably surface under Windows Terminal's ConPTY host - it can open hidden or not
# at all - and a bare DOUBLE-CLICK of this .ps1 (or "Run with PowerShell") opens a
# plain, often black console that is easy to mistake for the wrong host. The
# intended launcher "Launch JANET TWO.cmd" pins conhost and sets the sentinel below.
# This guard also self-heals a direct launch: if we are under Windows Terminal OR we
# were spawned straight from Explorer (double-click / Run with PowerShell), relaunch
# in a fresh conhost window and stop this instance. The JANETTWO_CONHOST sentinel
# (set by the .cmd, and here before relaunch) prevents any relaunch loop, and the
# UserInteractive gate keeps headless/automation launches from spawning a window.
$janetSpawnedByExplorer = $false
try {
    $janetMeProc     = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
    $janetParentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($janetMeProc.ParentProcessId)" -ErrorAction Stop
    $janetSpawnedByExplorer = ($janetParentProc.Name -eq 'explorer.exe')
} catch {}
if ([Environment]::UserInteractive -and -not $env:JANETTWO_CONHOST -and ($env:WT_SESSION -or $janetSpawnedByExplorer -or $PSVersionTable.PSEdition -eq 'Core')) {
    $env:JANETTWO_CONHOST = '1'
    $fwd = @('powershell.exe', '-NoExit', '-STA', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $fwd += "-$($kv.Key)" }
        } else {
            $fwd += "-$($kv.Key)"; $fwd += ('"{0}"' -f $kv.Value)
        }
    }
    try {
        Start-Process conhost.exe -ArgumentList $fwd | Out-Null
        Write-Host 'JANET TWO: relaunched in the classic console (conhost) so the credential picker appears. You can close this window.' -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not relaunch via conhost: $($_.Exception.Message). If 'Set Credentials' shows nothing, run 'Launch JANET TWO.cmd' instead."
    }
    return
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

# First-run self-heal: strip the "Mark of the Web" (came-from-another-computer tag)
# off our own files BEFORE the server + engine modules are dot-sourced/imported.
# Without it, a copied/extracted deployment trips a security prompt per script and
# loads in Constrained Language Mode (which breaks the .NET calls in some engines,
# e.g. ACAS analyze -> "AuthorizationManager check failed"). The launcher .cmd also
# does this before we start; this covers a direct `-File JanetTwo.Internal.ps1` launch.
# Unblock-File is a built-in signed cmdlet, so it runs even under lockdown. Silent.
try { Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue } catch {}

# No dependency check needed - JANET TWO uses only built-in .NET (HttpListener).

# Interactive-session check: the Set Credentials smartcard picker + file pickers
# are desktop dialogs that can only appear when this runs in YOUR interactive
# console. If it was started detached / non-interactively, warn loudly (the server
# still runs read-only as your Kerberos identity; credential set will be refused).
if (-not [Environment]::UserInteractive) {
    Write-Warning 'JANET TWO was started in a NON-INTERACTIVE session. "Set Credentials" (the ADW smartcard picker) and the file pickers will NOT work. Launch it from your own PowerShell console - or double-click "Launch JANET TWO.cmd" - for full functionality.'
}

# --- session token (per launch) ------------------------------------------------
$token = [guid]::NewGuid().ToString('N')
$url   = "http://127.0.0.1:$Port/?t=$token"

Write-Host ""
Write-Host "  J.A.N.E.T. TWO" -ForegroundColor Yellow
Write-Host "  pure PowerShell (no modules)  |  http://127.0.0.1:$Port  (loopback only)" -ForegroundColor DarkGray
Write-Host "  Open: $url" -ForegroundColor Cyan
Write-Host "  (Ctrl+C in this window stops the server.)" -ForegroundColor DarkGray
Write-Host ""

# --- open the browser shortly after the listener comes up ----------------------
if (-not $NoBrowser) {
    $opener = [powershell]::Create()
    [void]$opener.AddScript({
        param($u, $p)
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Milliseconds 250
            try {
                $c = New-Object System.Net.Sockets.TcpClient
                $c.Connect('127.0.0.1', [int]$p); $c.Close()
                Start-Process $u; break
            } catch {}
        }
    }).AddArgument($url).AddArgument($Port)
    [void]$opener.BeginInvoke()
}

# --- start (blocks until Ctrl+C) -----------------------------------------------
. (Join-Path $Root 'server\JanetTwo.Server.ps1')
Start-JanetTwoServer -Root $Root -Port $Port -Token $token -Asi $Asi -PackagesRoot $PackagesRoot
