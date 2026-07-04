@echo off
rem ============================================================================
rem  Launch JANET TWO in a real, interactive, STA PowerShell console.
rem
rem  Double-click this (or run it). It opens a normal PowerShell window and runs
rem  the server there, so:
rem    * the "Set Credentials" smartcard picker and the file pickers can appear
rem      on your desktop (they need an interactive session), and
rem    * Ctrl+C in that window stops the server.
rem
rem  %~dp0 is THIS file's folder, so it works no matter where JANET TWO lives.
rem  Pass-through args work too, e.g.:  "Launch JANET TWO.cmd" -Port 8090
rem ============================================================================

rem  --- FIRST-RUN SELF-HEAL: clear the "Mark of the Web" -----------------------
rem  When this folder is copied/extracted from another machine, every file gets a
rem  hidden "came from another computer" tag. On a locked-down box that (1) pops a
rem  PowerShell security prompt for EACH script at launch and (2) loads the scripts
rem  in Constrained Language Mode, which breaks ACAS analyze ("AuthorizationManager
rem  check failed"). Unblock-File is a built-in, Microsoft-signed cmdlet, so it runs
rem  even before anything is trusted. Best-effort + silent; it strips the tag off
rem  this whole folder (including this .cmd) so the very next launch is clean.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" 1>nul 2>nul

rem  --- FORCE THE CLASSIC BLUE CONSOLE -----------------------------------------
rem  Launch through conhost.exe so JANET TWO ALWAYS opens in the legacy blue
rem  Windows PowerShell 5.1 window. On Win11 the default terminal is often Windows
rem  Terminal (the dark icon), which hosts the console via ConPTY - and there the
rem  server-side Get-Credential smartcard picker can fail to surface. The classic
rem  conhost host pops the picker reliably, so we pin it explicitly. The sentinel
rem  tells JanetTwo.Internal.ps1 we are ALREADY in conhost, so its own Windows-Terminal
rem  guard does not relaunch a second window.
set "JANETTWO_CONHOST=1"
start "JANET TWO" conhost.exe powershell.exe -NoExit -STA -ExecutionPolicy Bypass -File "%~dp0JanetTwo.Internal.ps1" %*
