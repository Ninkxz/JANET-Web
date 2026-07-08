#Requires -Version 5.1
<#
.SYNOPSIS
    Internal launcher for JANET Web. DO NOT run this directly - double-click
    "Launch JANET Web.cmd" instead. The .cmd pins the classic blue console (conhost,
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
    security model as the WinForms tools. Self-contained: the tool engines live
    under .\modules\ (one .psm1 per tool), no external source to fork from.

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
# intended launcher "Launch JANET Web.cmd" pins conhost and sets the sentinel below.
# This guard also self-heals a direct launch: if we are under Windows Terminal OR we
# were spawned straight from Explorer (double-click / Run with PowerShell), relaunch
# in a fresh conhost window and stop this instance. The JANETWEB_CONHOST sentinel
# (set by the .cmd, and here before relaunch) prevents any relaunch loop, and the
# UserInteractive gate keeps headless/automation launches from spawning a window.
# "Launch JANET Web.cmd" and this script must keep agreeing on the sentinel name -
# rename them together or not at all.
$janetSpawnedByExplorer = $false
try {
    $janetMeProc     = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
    $janetParentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($janetMeProc.ParentProcessId)" -ErrorAction Stop
    $janetSpawnedByExplorer = ($janetParentProc.Name -eq 'explorer.exe')
} catch {}
if ([Environment]::UserInteractive -and -not $env:JANETWEB_CONHOST -and ($env:WT_SESSION -or $janetSpawnedByExplorer -or $PSVersionTable.PSEdition -eq 'Core')) {
    $env:JANETWEB_CONHOST = '1'
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
        Write-Host 'JANET Web: relaunched in the classic console (conhost) so the credential picker appears. You can close this window.' -ForegroundColor Yellow
    } catch {
        Write-Warning "Could not relaunch via conhost: $($_.Exception.Message). If 'Set Credentials' shows nothing, run 'Launch JANET Web.cmd' instead."
    }
    return
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

# First-run self-heal: strip the "Mark of the Web" (came-from-another-computer tag)
# off our own files BEFORE the server + engine modules are dot-sourced/imported.
# Without it, a copied/extracted deployment trips a security prompt per script and
# loads in Constrained Language Mode (which breaks the .NET calls in some engines,
# e.g. ACAS analyze -> "AuthorizationManager check failed"). The launcher .cmd also
# does this before we start; this covers a direct -File launch of this internal script.
# Unblock-File is a built-in signed cmdlet, so it runs even under lockdown. Silent.
try { Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue } catch {}

# No dependency check needed - JANET Web uses only built-in .NET (HttpListener).

# Interactive-session check: the Set Credentials smartcard picker + file pickers
# are desktop dialogs that can only appear when this runs in YOUR interactive
# console. If it was started detached / non-interactively, warn loudly (the server
# still runs read-only as your Kerberos identity; credential set will be refused).
if (-not [Environment]::UserInteractive) {
    Write-Warning 'JANET Web was started in a NON-INTERACTIVE session. "Set Credentials" (the ADW smartcard picker) and the file pickers will NOT work. Launch it from your own PowerShell console - or double-click "Launch JANET Web.cmd" - for full functionality.'
}

# --- resolve a bindable loopback port ------------------------------------------
# The browser-opener, the printed URL and the server must all agree on ONE port. If the
# requested port is already taken (a stale JANET instance still holding it, or another
# app), silently advance to the next free one so the GUI still comes up instead of the
# listener failing to bind and nothing opening. This probes a RAW TCP bind; a
# urlacl / Access-Denied HttpListener failure is a different problem and is still
# surfaced with guidance by the server itself.
function Resolve-JanetFreePort {
    param([int]$Start)
    for ($p = $Start; $p -lt ($Start + 12); $p++) {
        $l = $null
        try {
            $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, $p)
            $l.Start(); $l.Stop(); return $p
        } catch { } finally { if ($l) { try { $l.Stop() } catch {} } }
    }
    return $Start   # ponytail: none free in range -> let the server bind + report the real error
}
$resolvedPort = Resolve-JanetFreePort -Start $Port
if ($resolvedPort -ne $Port) {
    Write-Host "  Port $Port was busy - using $resolvedPort instead." -ForegroundColor Yellow
    $Port = $resolvedPort
}
# ponytail: tiny TOCTOU between this probe and the server's bind; harmless on single-user loopback.

# --- session token (per launch) ------------------------------------------------
$token = [guid]::NewGuid().ToString('N')
$url   = "http://127.0.0.1:$Port/?t=$token"

Write-Host ""
Write-Host "  JANET Web" -ForegroundColor Yellow
Write-Host "  pure PowerShell (no modules)  |  http://127.0.0.1:$Port  (loopback only)" -ForegroundColor DarkGray
Write-Host "  If your browser does not open on its own, click or paste this:" -ForegroundColor DarkGray
Write-Host "  $url" -ForegroundColor Cyan
Write-Host "  (Ctrl+C in this window stops the server.)" -ForegroundColor DarkGray
Write-Host ""

# --- open the browser shortly after the listener comes up ----------------------
# Runs on a background runspace: poll the loopback port until the listener is up, then
# open the default browser. Two robustness fixes for locked-down boxes: (1) wait up to
# ~60s, not 10s - a copied deployment's first run does an Unblock-File sweep + module
# load + AV scan before the listener binds; (2) try THREE ways to open the URL, because
# a plain Start-Process <url> silently no-ops on machines with no http:// default-browser
# association (common on freshly imaged/managed hosts), whereas explorer / cmd start
# resolve it. The tokenized URL is also printed above, so a total miss is still one click.
if (-not $NoBrowser) {
    $opener = [powershell]::Create()
    [void]$opener.AddScript({
        param($u, $p)
        $up = $false
        for ($i = 0; $i -lt 240; $i++) {
            Start-Sleep -Milliseconds 250
            try {
                $c = New-Object System.Net.Sockets.TcpClient
                $c.Connect('127.0.0.1', [int]$p); $c.Close()
                $up = $true; break
            } catch {}
        }
        if (-not $up) { return }
        foreach ($opn in @(
            { Start-Process $u -ErrorAction Stop },
            { Start-Process 'explorer.exe' -ArgumentList $u -ErrorAction Stop },
            { Start-Process 'cmd.exe' -ArgumentList '/c','start','""',$u -ErrorAction Stop }
        )) {
            try { & $opn; break } catch {}
        }
    }).AddArgument($url).AddArgument($Port)
    [void]$opener.BeginInvoke()
}

# --- start (blocks until Ctrl+C) -----------------------------------------------
. (Join-Path $Root 'server\JanetWeb.Server.ps1')
Start-JanetWebServer -Root $Root -Port $Port -Token $token -Asi $Asi -PackagesRoot $PackagesRoot
