# JANET Web - UI Rebuild Spec: wpt

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The Workstation Patching Tool (WPT) is a single-window WinForms admin console in J.A.N.E.T.'s dark purple/gold "tactical" theme. The window has a 32px top strip (heartbeat "live" indicator + red Close Tool button), a 252px left sidebar of numbered icon nav items, a central hidden-header TabControl holding 17 pages, and a 32px bottom status strip (heartbeat + SESSION + TARGETS + LOG path). The operator must Set Credentials, accept a Yes/No responsibility acknowledgment, and click START SESSION on the Start tab before any other tab is reachable (session gating). A shared global host list (built on the Targets tab via paste/TXT/ACAS-CSV/XLSX import) feeds every operational tab. The signature experience is the live "activity run": an operation is launched from a tab's toolbar button (e.g. Scan All / Patch Selected / Reboot Selected), an optional MessageBox confirmation appears, then per-host work is dispatched across a RunspacePool via PowerShell.BeginInvoke; a WinForms Timer polls every 300-600ms, draining completed jobs and painting each host's result into its own DataGridView row with semantic color coding (green OK / amber warning-or-work-pending / red error / dim placeholder), updating an "X / N" progress label, while a separate colorized RichTextBox activity log streams timestamped lines. Buttons disable during a run and re-enable on completion. Engine work is isolated in global scriptblocks (ScanBlock/PatchBlock/RebootBlock/WinRMBootstrapBlock) plus per-tab Invoke-Command blocks, all returning a per-host hashtable the UI maps to grid cells.

---

# Workstation Patching Tool (WPT) -- UI/UX Rebuild Spec for JANET Web

Source: `X:\J.A.N.E.T\Tools\WorkstationPatchingTool_6.5.22.ps1` (WinForms desktop, PowerShell 5.1). This spec describes the **frontend and run experience** to reproduce in the pure-PowerShell web-local re-front. The engine is re-forked separately; section 5 names the entry points it must serve.

## 1. Window + Navigation Layout

A single top-level form, title `J.A.N.E.T. Workstation Patching Tool v<version>`, launches **Maximized** (default ClientSize 1280x740, MinimumSize 1100x680, CenterScreen). Background near-black `RGB(8,8,12)`. Four docked regions:

1. **Top strip (32px, docked top).** Minimal dark bar. Right-anchored: an animated heartbeat **pulse dot + "live"** label (answers "is the UI thread alive?"), and a red **Close Tool** button. There is no title/logo here -- the wordmark lives in the sidebar.
2. **Left sidebar (252px wide).** Brand block at top, a hairline divider, then a vertical, scrollable list of **numbered icon nav items** (Segoe MDL2 glyphs), and a pinned bottom user block (`User:`, `Status:`, `Host:`). The sidebar is the ONLY navigation -- the underlying TabControl's header strip is hidden (ItemSize height 1, FlatButtons, BackColor=ForeColor). Clicking a nav item sets `$tc.SelectedTab`; the selected item gets an accent bar + active styling via an `UpdateSidebar` refresh.
3. **Content area (center).** A standard TabControl filling the area right of the sidebar, holding the 17 pages below.
4. **Status strip (32px, docked bottom).** Heartbeat pulse + `SESSION: idle` (becomes `SESSION: user@host` once started) + `TARGETS: N` + right-anchored `LOG: <audit path>`.

**Tabs, in nav order** (the nav spec order is authoritative):

1. **Start** -- landing/about, credentials, acknowledgment, START SESSION, session info, info dialogs. Always reachable.
2. **Targets** -- build the shared host list.
3. **Bulk Scan & Patch** -- the core scan->patch->reboot fleet grid.
4. **Software Manager** -- single-host registry software scan + native uninstall.
5. **SCCM App Manager** -- per-host CCM_Application Install/Uninstall/Reinstall/Repair.
6. **KB Scanner** -- installed-hotfix inventory + MECM cycle/download triggers + KB install.
7. **App Updater** -- bulk third-party app update grid.
8. **Cleanup** -- temp-file / stale-profile cleanup with dry-run.
9. **Reg Key Fixes** -- checkbox-list registry remediation scan + apply.
10. **Log4j Finder** -- scan hosts for `log4j-*.jar`.
11. **Remote Message** -- popup message to logged-in users.
12. **Reboot Countdown** -- scheduled reboot with warning popups.
13. **Reports** -- session stat cards + Action History + report files.
14. **Heal** -- one-click MECM/WMI/WU agent remediation.
15. **WinRM Setup** -- enable/repair WinRM across hosts.
16. **Usage** -- usage metrics grid.
17. **Logs** -- global colorized activity log.

**Session gating (critical UX):** every tab except Start has `AlwaysOpen=false`. The nav click handler, and the TabControl `SelectedIndexChanged`, check `$global:SessionStarted`; if false they pop a MessageBox ("Complete the setup and click START SESSION...") and snap back to Start. JANET Web must replicate this lockout.

## 2. Per-Tab Controls + Workflow

**Start tab** (`pnlAbout` on near-black panel): tool name (gold 16pt bold), full JANET name (dim), version (green). Group boxes: **AUTHOR** (credit line, cyan); **CREDENTIALS (Required)** (amber) -- `Set Credentials` button -> `Get-Credential` modal, a credentials-status label (red "No credentials set" -> green username), and a **Threads** NumericUpDown (1-30, default 10); **RESPONSIBILITY ACKNOWLEDGMENT (Required)** (red) -- wrapped warning text + Yes/No radio buttons + status label. A full-width green **START SESSION** button. On click: validate creds set (else red label + MessageBox), validate Yes checked (else MessageBox), set `$global:ThreadCount`, `$global:SessionStarted=$true`, call `Start-JanetSession`, update status strip to `SESSION: user@host`, relabel the button "SESSION STARTED" and disable it + the inputs, fill the **SESSION INFORMATION** group (operator, time, creds, threads, audit path, PS version), and refresh the sidebar to unlock tabs. Bottom row: three flat buttons **Change Log / About / How To Use** open themed read-only scroll dialogs.

**Targets tab**: a **TARGET WORKSTATIONS** group (gold). Left: label "Paste hostnames (one per line, comma, or space separated)", a multiline console-font textbox, and a button row -- **Add to List** (green), **Import TXT** (CSV/TXT), **Import ACAS** (Nessus CSV, auto-detects DNS Name/NetBIOS/IP column, dedups), **Import XLSX** (parses the .xlsx zip's sharedStrings/sheet1 XML directly -- no Excel/COM), **Clear All** (red). A `N workstation(s) loaded` count label (green when >0). Right: a multi-select ListBox of loaded hosts + **Remove Selected** (red). `Parse-Hosts` splits on `[,\r\n\s]+` and uniques. Every mutation rewrites `$global:ComputerList` and updates the status-strip TARGETS count.

**Bulk Scan & Patch tab** (the centerpiece): a top action panel and a second selection panel above a 10-column grid. See sections 3 + 4.

**Software Manager / SCCM App Manager / KB Scanner / App Updater / Cleanup / Reg Key Fixes / Log4j Finder / Heal / WinRM Setup**: each is a "toolbar panel + (optional filter panel) + results DataGridView + status label" layout. Operator picks/inherits hosts, clicks a scan button, watches rows fill, then selects rows / clicks an action. KB Scanner grid = Host/KB ID/Description/Installed On/Installed By/Source plus **Scan Installed KBs / Trigger MECM Cycles / Push & Download / Export CSV** and a filter box. Cleanup has checkboxes (clean temp / delete stale profiles + age NumericUpDown / **DRY RUN** default-on), a targets sub-list with **Sync** from the main list, a results grid (Host/TempMB/Files/Prof Found/Removed/Skip/Status), a **Run Cleanup**/**Stop** pair, and a dedicated "LIVE EXECUTION (what the script is doing right now)" RichTextBox. Heal grid = Host/MECM/SW Center/WMI/WU/Reboot/Last Check-In/Overall/Detail with **Health Scan All / Restart CcmExec / Repair WMI / Reset WU / Trigger Check-In / gpupdate /force**.

**Remote Message tab**: Send To dropdown (`-- All Targets --` + hosts), Title, multiline Message, Timeout NumericUpDown (0=user must click OK), **Send Message**, status label, and a MESSAGE LOG textbox. Delivery is via a per-host scheduled task running a VBS `Popup` as the logged-in user (msg.exe is unreliable on hardened AFNET).

**Reboot Countdown tab**: Send To, Total Time (min), Warn Every (min), warnings-only vs auto-reboot, Cancel Countdown, Send Warning Now.

**Reports tab**: a **SESSION STATISTICS** row of 7 big-number cards (Scanned / Updates / Installed / Uninstalled / Reinstalled / Repaired / Reboots, each colored), an **ACTION HISTORY** grid (Time/Action/Target/Result/Detail) colored by action type + result keyword, a **REPORT FILES** grid (double-click to open), and Refresh / Export to CSV / Export Summary / Clear.

**Logs tab**: a single full-bleed read-only colorized RichTextBox -- the global activity sink.

## 3. THE RUN MODEL + ACTIVITY VIEW (preserve exactly)

This is the heart of JANET Web. Every bulk operation is the same machine; web-local must stream the same way (SSE/long-poll into per-host rows + a log pane).

**Launch + confirm.** Operator clicks a toolbar button (Bulk tab: **Scan All** green, **Patch Selected** amber, **Reboot Selected** red; plus **Patch All Needing**, **Ping Sweep** purple, **Repair WinRM** cyan, **App Manager**, **Host Details**, **Export CSV**; selection row: Select All / Deselect / Select With Updates). Guards fire ordered MessageBoxes: no targets -> "No Targets"; no credentials -> "No Credentials"; nothing selected -> "Nothing Selected". Then a YesNo confirmation scaled to risk -- patch uses the warning icon ("Patch N workstation(s)? Reboot will be suppressed."), reboot uses the stop icon ("REBOOT N workstation(s)? This is immediate and forced."), WinRM repair spells out the DCOM steps. Only "Yes" proceeds.

**Dispatch.** Action button(s) disable. Each target row resets to a dim placeholder (`Scanning...`/`Patching...`/`Rebooting...`, forecolor `RGB(90,90,130)` or amber). `Initialize-RunspacePool` builds a pool sized `1..$global:ThreadCount` (MTA). Per host: `$ps=[PowerShell]::Create(); $ps.RunspacePool=$RSPool; $ps.AddScript($global:ScanBlock).AddArgument($comp).AddArgument($cred).AddArgument('Negotiate'); $handle=$ps.BeginInvoke()` -- stored in a `$script:ScanJobs[host]` hashtable. A `=== Bulk scan started: N ===` banner hits the log and `Write-AuditLog` records the start.

**Stream-back (the timer drain).** A `System.Windows.Forms.Timer` (Interval 300-600ms) ticks: for each job whose `Handle.IsCompleted`, it `EndInvoke`+`Dispose`, removes the job, normalizes an array result to `[0]`, finds the grid row whose Host cell equals `$res.Host`, and **paints that row's cells + colors** (section 4). It calls `Track-Action` per host (feeds Reports), updates the progress label to `"Scanning: $done / $total"`, and logs a per-host line. When the jobs hashtable empties: `Timer.Stop()+Dispose()`, re-enable buttons, flip the label to green `"Scan complete: N workstation(s)"`, log `=== complete ===`. JANET Web equivalent: a per-host worker pool whose completions push row-update events to the client, with a final "complete" event.

**Cancel / abort.** No global Cancel button on the Bulk tab -- re-entry is prevented by disabled buttons; some tabs (Cleanup) expose an explicit **Stop**. `FormClosing` is the master teardown: stop+dispose every `$script:*Timer`, `Stop()`+`Dispose()` every in-flight PowerShell in every `*Jobs` hashtable, then close+dispose the RunspacePool. The window X / Alt-F4 are intercepted and cancelled -- only the **Close Tool** button (after a Closing Notes dialog) actually closes, guaranteeing audit/usage rows are written.

**Post-reboot monitor.** After a reboot wave, a "Monitor N workstation(s) until back online?" prompt opens a modal **Reboot Monitor**: a grid (Server/Phase/Status/Pings/Downtime/Time) polling TCP reachability every 3s, tracking each host through Waiting-offline -> offline -> back-online, showing a live downtime timer and elapsed counter, beeping (`Console.Beep`) when a host returns, and announcing "All workstation(s) back online!".

## 4. Activity Log + Results Grid Detail

**Activity log.** Read-only RichTextBox, near-black `OutputBg RGB(6,6,10)`, monospace. `Log($msg,$lvl)` appends `"[HH:mm:ss] msg\r\n"`, colors the line by level -- **OK** green `(92,198,120)`, **WARN** amber `(230,180,70)`, **ERR** red `(224,80,90)`, default lavender `(164,128,240)` -- then `ScrollToCaret` to auto-tail. Section banners are `=== ... ===`. Per-tab variants (`SwLog/CleanLog/KBLog/MsgLog`) write into that tab's own pane AND mirror to the global log.

**Results grid.** Themed via `Style-Grid`: gold bold headers on `GridHdr` near-black, white cells, lavender selection, alternating row shade, no row headers, FullRowSelect, single horizontal cell border. Bulk grid columns: **[ Sel checkbox]** | **Host** | **Up** (Online/Offline) | **C:** (e.g. `120GB (38%)`) | **Reb** (reboot pending) | **MECM** (update count) | **WU** (Windows Update count) | **App** (app count) | **Scan** | **Patch**. Semantics:
- One **row per host**, identity = the Host cell value (results are matched back by hostname).
- **Per-cell color** (`Cells[i].Style.ForeColor`): Online green / Offline red; drive green if >20% free else amber, Error red; reboot `YES` amber / `No` green / Error red; `N update(s)`/`N app(s)` amber (work pending) vs `Current` green vs Error red; Scan `Scanned` green; Patch placeholder dim -> `Triggered: 2 upd, 1 app` green / `Nothing to patch` green / `Error: ...` red; reboot `Reboot sent` green / `Reboot failed` red.
- Each scanned row stashes its full result hashtable in `row.Tag`; **double-click** a row or click **Host Details** opens read-only `Show-HostScanDetails` (pending KB/MECM names, pending app names, drive, last boot, reboot state, scan error) with an "Open App Manager" handoff.

**Progress + status.** There is **no progress-bar control** -- the single `X / N` status label per tab IS the progress indicator (amber while running, green on completion). The bottom status strip (SESSION/TARGETS/LOG) is always visible. The Reports tab aggregates the run via 7 stat cards + the colorized Action History grid.

## 5. Targets, Credentials, Shared State

- **Host list:** `$global:ComputerList` (array of hostnames) is the single shared target list, built on Targets and consumed everywhere. Operational tabs re-sync their host dropdowns / sub-lists in `Add_Enter` and offer a **Sync** from the main list (Cleanup). Remote Message/Reboot dropdowns prepend `-- All Targets --`.
- **Credentials:** one `[pscredential]` (`$global:Credentials`) from `Get-Credential`, reused for every remote op (passed as `.AddArgument($cred)` with `Authentication = 'Negotiate'`). JANET inheritance: at startup, if `$env:JANET_CRED_FILE` exists, `Import-Clixml` populates creds and updates the Start labels (button becomes "Override Credentials").
- **Threads:** `$global:ThreadCount` (1-30) sizes every RunspacePool.
- **Session/telemetry:** `$global:SessionStarted` gates nav; `$global:ActionHistory` + `$global:Stats` feed Reports; `Write-AuditLog` + `Start-JanetSession`/`Publish-WptUsageCsvRow` record centralized JANET telemetry.

## 6. Engine Functions the UI Calls

Re-fork these to serve the same UI (each returns a per-host hashtable the frontend maps to grid cells):
- `$global:ScanBlock(Computer,Cred,Auth)` -> `{Host,Online,DriveOK/Free/Size/Pct,RebootOK/RebootPending,LastBoot,UpdatesOK/UpdateNames,WuOK/WuNames,AppsOK/AppNames,Error}` -- TCP-probe 5985/445, then bounded PSSession querying disk, reboot-pending, CCM updates, WUA scan, app inventory.
- `$global:PatchBlock` -> `{Host,Reachable,UpdatesTriggered,AppsTriggered,Error}`.
- `$global:RebootBlock` -> `{Host,Success,Message}`.
- `$global:WinRMBootstrapBlock(Computer,Cred)` -> `{Host,Success,PostProbeOk,Steps[],Error}`.
- Helpers: `Initialize-RunspacePool`, `Parse-Hosts`, `Track-Action`, `Test-WorkstationReachable`, `Show-RebootMonitor`, `Show-HostScanDetails`, `Show-AppManager`, `Log`/`Write-AuditLog`. Inline Invoke-Command blocks back Remote Message (scheduled-task VBS popup), KB triggers (`SMS_Client TriggerSchedule`), and SCCM App Manager (`CCM_Application` via `Invoke-CimMethod`).

## 7. Visual Theme + UX Details to Preserve

**Palette:** background `(8,8,12)`, surfaces `(16,16,22)`/`(22,22,30)`, **Accent1 purple `(140,100,220)`**, **Accent2 gold `(218,180,82)`**, Success green `(92,198,120)`, Warning amber `(230,180,70)`, Danger red `(224,80,90)`, Info cyan `(88,180,210)`, primary text `(240,240,245)`, console lavender `(164,128,240)`. **Fonts:** Segoe UI for labels/buttons (bold for headings, gold 16pt tool title), a monospace console font for logs/grids/host lists. Group-box headers are uppercase, colored by purpose (gold = primary, cyan = info, amber = caution, red = destructive). Buttons are flat with auto-contrast text and hover states; destructive actions are always red. **UX to keep:** the "live" heartbeat + status strip as always-on liveness cues; X/Alt-F4 blocked so audit always writes; numbered sidebar nav; the dim-placeholder->colored-result row transition; per-cell (not per-row) status coloring; the X/N label as progress; confirmation severity scaling; double-click-row drill-down; the post-reboot beep-on-return monitor; "DRY RUN" defaulting on for Cleanup.