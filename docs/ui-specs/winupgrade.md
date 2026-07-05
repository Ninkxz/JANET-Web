# JANET Web - UI Rebuild Spec: Windows Upgrade Tool

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The Windows Upgrade Tool is a single-window WinForms admin console (JANET dark purple/gold theme) that pins/unpins a Windows feature-version ceiling via the Windows Update for Business "TargetReleaseVersion" registry policy and/or pushes a feature-update CAB/MSU to remote PCs over WinRM with DISM. It is NOT tabbed: a fixed left config column (Scenario chooser, Credentials, Operation radios, Guide panel, Options) sits beside a live results DataGridView, with a docked bottom log/progress panel. The operator picks a scenario or operation, sets credentials (or uses the current session), pastes/imports computer names, optionally dry-runs, then clicks RUN. Work fans out across a RunspacePool (one runspace per host, default 16 concurrent); each worker pings then performs the op and enqueues status records onto a ConcurrentQueue that a 250 ms UI timer drains into the grid (per-host rows, colour-coded Status, a Ping/Detail column), driving a progress bar and "done/total" counter. A Cancel button sets a synchronized flag (queued hosts skip, in-flight finish); results export to CSV. Reproducing this live activity-run experience is the core of the rebuild.

---

# Windows Upgrade Tool - UI/UX Rebuild Spec (id: winupgrade)

Source: `X:\J.A.N.E.T\Tools\WindowsUpgradeTool_0.1.0.ps1` (v0.1.0 "bench build"). This is the desktop WinForms front end to recreate faithfully for JANET Web (pure-PowerShell web-local). The engine is re-forked separately; this spec captures the operator-facing window and the live run experience.

## 1. Window + navigation layout

There is **one window, no tabs**. Title: `J.A.N.E.T. - Windows Upgrade Tool  (v0.1.0 bench build)`. ClientSize 1100x986, centered, dark immersive titlebar (DWM). MinimumSize is recomputed on Shown to keep ~916px client height so the host list stays usable.

The window is a three-zone dock layout:

- **Left config column** (`pnlConfig`, Dock=Left, width 460, sidebar near-black). Itself a nested dock: a fixed **top stack** (height 578) holds Scenario / Credentials / Operation / Guide / Options group boxes in that vertical order; a fixed **bottom action bar** (height 52) holds Test Ping / RUN / Cancel; the **Fill** area between them is the **Computers** group (host list + add/import/remove/clear strip).
- **Center/right results grid** (`grid`, Dock=Fill) - the per-host DataGridView, claims all remaining width.
- **Bottom log panel** (`pnlLog`, Dock=Bottom, height 120, full width) - count label, progress bar, Export CSV, and the activity log textbox.

Rebuild as: left sidebar form column, main results table to its right, sticky footer with progress + log. The host list must absorb spare vertical space.

## 2. Per-section controls + workflow

Top-to-bottom in the left column (each is a gold-headed GroupBox):

**Scenario** - label "I'm doing:" + a DropDownList combo with: `-- Manual (pick an operation below) --`, `24H2 upgrade  -  Pin to Windows 11 24H2`, `25H2 update  -  Install KB5054156 (25H2 enablement)`. Choosing 1 or 2 calls Apply-Scenario: it pre-selects the matching Operation radio and seeds defaults (24H2 -> Pin, Product "Windows 11", Version "24H2"; 25H2 -> Install CAB + Reboot ticked), and loads that scenario's step-by-step into the Guide. Manual lets the operator drive. Changing an operation radio by hand snaps the chooser back to Manual (guarded by `ApplyingScenario`).

**Credentials** - `Set Credentials...` (accent/purple) opens Get-Credential; on success stores a PSCredential, updates the `lblCred` label to "Auth: <user>" in gold, logs it. `Use Session` clears it back to "Auth: current Windows session" (grey). This is the auth used for every remote op; null = current Windows session (CAC-friendly).

**Operation** - three radio buttons (mutually exclusive): `Pin to a feature version (stay on / hold at)` (default checked) with **Product** (default "Windows 11") and **Version** (default "24H2") text boxes; `Unpin (remove the version hold)`; `Install a feature update package (CAB/MSU via DISM)` with a **CAB** path box + **Browse** button + `Reboot target ~10s after install` checkbox (checked). Update-OpControls enables only the inputs relevant to the checked radio.

**Guide - what this does / step-by-step** (cyan header) - read-only multiline scrolling textbox. Shows the chosen scenario's numbered steps, or in Manual a plain-language paragraph explaining the selected operation (PIN/UNPIN/INSTALL). This is operator hand-holding; preserve the explanatory copy.

**Options** - `Dry-run (no changes)` checkbox, `Attempt even if offline` checkbox, and `Max concurrent:` NumericUpDown (1-64, default 16).

**Action bar** - `Test Ping` (cyan text), `RUN` (bold, accent/purple), `Cancel` (red, disabled until running).

**Computers** (Fill) - a multi-select ListBox fills the group; a bottom strip has an add textbox + `Add` (accent) + `Import` buttons (row 1) and a "<n> computers" count label + `Remove` + `Clear` buttons (row 2). Enter in the add box adds; Delete key removes selected; Clear confirms via MessageBox.

**Operator flow:** pick scenario (or Manual) -> set credentials or leave on session -> add/import computers -> choose operation + fill its inputs -> optionally tick Dry-run -> click RUN (or Test Ping first) -> confirm -> watch the grid/log fill -> Export CSV.

## 3. THE RUN MODEL + ACTIVITY VIEW (most important)

**Launch.** `Test Ping` -> `Start-Run 'Ping'` (no confirmation). `RUN` -> resolves the checked radio to `Pin` / `Unpin` / `InstallCab` and calls `Start-Run`.

**Validation + confirmation.** Start-Run requires >=1 host (else an info MessageBox). Pin requires Product+Version; InstallCab requires an existing CAB/MSU path (skipped if Dry-run). For every non-Ping op a **Yes/No "Confirm" MessageBox** appears summarising: `Operation: <label><[DRY-RUN]>`, `Targets: <count>`, `Auth: <user | current Windows session>`, plus a blank-line **WARNING: targets will REBOOT ~10 seconds after a successful install** when CAB+reboot and not dry-run. The op label reads like `PIN to Windows 11 24H2`, `UNPIN (remove target version policy)`, `INSTALL KB5054156.cab + REBOOT`. No on Confirm aborts.

**Grid build + fan-out.** On confirm the grid is cleared and re-seeded one row per host (`RowMap` maps hostname -> row), each starting **Queued** (dim). A fresh `RunspacePool(1, MaxConcurrent)`, a `ConcurrentQueue[object]`, and a synchronized `$Sync['Cancel']=$false` are created; counters reset; `Set-RunningUI $true` disables all inputs and enables Cancel; progress bar -> 0; log gets `START <label> on <n> target(s) (<auth>), <max> threads.` Then for each host a `[powershell]` is created on the pool with the `$script:Worker` scriptblock and **13 positional arguments in this exact order**: Computer, Op, Cred, TargetVer, ProductName, CabPath, CabName, Reboot, AttemptOffline, DryRun, Queue, Sync; `BeginInvoke` starts it. A `System.Windows.Forms.Timer` (250 ms) starts.

**Worker (never touches UI).** Each runspace: optional early cancel bail; a .NET `Ping` with a 1s timeout (sets the Ping cell text - "<n> ms" / "Unreachable" / "DNS/error"); for Ping op reports Online/Offline and returns; otherwise enqueues `Pinged`, and if offline and not "Attempt offline" enqueues `Skipped`. Then the op runs - Pin/Unpin via `Invoke-Command` writing/removing the HKLM WindowsUpdate `TargetReleaseVersion`/`ProductVersion`/`TargetReleaseVersionInfo` policy; InstallCab via `New-PSSession`, ensure `C:\Temp`, `Copy-Item -ToSession`, `dism.exe /Online /Add-Package /Quiet /NoRestart` through ProcessStartInfo (exit 0 or 3010 = success), then optional `shutdown.exe /r /t 10`. Throughout it calls a nested `Send(status, detail, done)` that enqueues a record `{Computer, Ping, Status, Detail, Done}`. Dry-run paths emit a single `DRY-RUN` "Would..." record.

**Stream-back (Drain-Queue, every 250 ms).** The timer dequeues all pending records: writes Ping, Status (re-coloured by Set-StatusColor), and Detail into the mapped row; increments `CompletedCount` on Done records. It then sets the progress bar to `100*Completed/Total` and the count label to `Completed / Total`. When `Completed >= Total` - or, as a backstop, when **every runspace handle reports IsCompleted** - it calls `Finish-Run`.

**Finish-Run.** Stops the timer, final Drain, EndInvoke/Dispose all runspaces, closes the pool, sets bar to 100 and label to `Total / Total`. Any row still blank/Queued/Working/Pinged is forced to **FAILED** ("worker ended without result") so nothing looks unfinished. It tallies and logs `FINISHED. OK=<n>  Failed=<n>  Skipped/Cancelled=<n>` (DONE/Online/DRY-RUN count OK; FAILED/Offline count failed; Skipped/Cancelled count skipped).

**Cancel/abort.** `Cancel` sets `$Sync['Cancel']=$true`, disables itself, logs `CANCEL requested - queued targets will skip; in-flight operations finish.` Queued workers emit `Cancelled before start`; in-flight ops complete but a pending reboot is skipped (`REBOOT SKIPPED (cancelled)`). Closing the window mid-run prompts "A run is in progress. Cancel it and exit?".

**Activity view (the three coordinated surfaces).**
- **Results grid:** read-only, full-row-select, no row headers, alternating row shading, cell tooltips on (truncated Detail shows full text on hover). Columns: **Computer** (170), **Ping** (90), **Status** (100), **Detail** (fill). Gold bold column headers on a dark bar. Row Status colours: DONE/Online green, DRY-RUN gold, FAILED/Offline red, Skipped/Cancelled amber, Working cyan, Pinged secondary-grey, Queued dim. Detail carries the live narrative ("Copying KB to C:\Temp...", "Installing with DISM...", "DISM exit 3010: installed (reboot required)...; reboot issued (10s)").
- **Bottom log panel:** bold `Completed / Total` label, full-width continuous progress bar, `Export CSV` button (top-right), and a Consolas read-only multiline log with `[HH:mm:ss]` lines for high-level milestones only (START / Added N / CANCEL / FINISHED / Exported), not per-host chatter (that lives in the grid).

## 4. Targets, credentials, shared state

**Host list** is the single source of targets. `Add-Computers` accepts free text: splits on newlines, strips `#` comments (full-line or trailing), tokenizes on whitespace/comma/semicolon, accepts only `^[A-Za-z0-9._-]+$` tokens (rejects UNC/URL/email "junk", logging "Skipped N invalid name(s)"), and dedupes case-insensitively against existing items. Import reads a `.txt` (one per line) through the same parser. Remove deletes selected (button or Delete key); Clear confirms then empties. The count label and RUN/Test Ping enablement track item count.

**Credentials** are a single `$script:Cred` PSCredential (or null). Set via Get-Credential; cleared back to session. Passed into every `Invoke-Command`/`New-PSSession` as `Credential` when non-null; null = current Windows session.

**Shared/cross-section state** (script scope so handlers + workers share it): Cred, RunspacePool, Jobs list, UpdateQueue (ConcurrentQueue), Sync (synchronized hashtable with Cancel), RowMap (host->row), Running flag, CompletedCount, TotalCount, ApplyingScenario guard. The Scenario chooser and Operation radios are bidirectionally linked through ApplyingScenario.

## 5. Engine functions / scriptblocks the UI calls

The UI's work entry point is `Start-Run [op]` which submits the `$script:Worker` scriptblock per host. Re-fork the engine to expose, per host: a **Ping** check; **Pin** (write WUfB TargetReleaseVersion policy: TargetReleaseVersion=1 DWord, ProductVersion=<product>, TargetReleaseVersionInfo=<version>); **Unpin** (remove those values / empty key); **InstallCab** (copy CAB to C:\Temp, `dism /Online /Add-Package`, optional delayed reboot). Each must stream `{Computer, Ping, Status, Detail, Done}` progress records (status vocabulary: Queued, Pinged, Working, DONE, DRY-RUN, FAILED, Skipped, Cancelled, Online, Offline). Supporting UI functions: Drain-Queue, Finish-Run, Set-StatusColor, Set-RunningUI, Add-Computers, Sync-HostCount, Apply-Scenario, Set-GuideText, Update-OpControls, Export-Results, plus the 250 ms poll timer. Keep the args/contract identical so the same UI can drive the re-forked engine.

## 6. Notable UX details + visual theme

Preserve: the Scenario->Guide hand-holding and the per-operation plain-language Guide text; Dry-run that reports "Would..." in gold rows before the real run; the explicit reboot WARNING in the confirm dialog; the FAILED backstop so a dead worker never leaves a run "stuck"; cooperative Cancel semantics (queued skip, in-flight finish, reboot suppressed); cell tooltips for long Detail; delimiter-flexible host paste with #comments and junk rejection; live count + done/total + progress; CSV export naming `WindowsUpgrade_results_<yyyyMMdd_HHmmss>.csv`; FormClosing busy-guard.

**Theme (JANET dark purple/gold):** Background ARGB(8,8,12), Sidebar (7,7,11), Panel (16,16,22), Input (22,22,30), OutputBg (6,6,10), Border (38,34,52). Text primary (240,240,245), secondary (170,168,180), dim (110,106,125). Accent/purple (140,100,220) + hover (164,128,240) + dim (96,68,156). Success green (92,198,120), Warning amber (230,180,70), Danger red (224,80,90) + hover (240,104,114), Cyan (88,180,210), Gold (218,180,82). Fonts: Segoe UI 9 for chrome (RUN bold 10, count label bold 9), gold bold column headers, **Consolas 9** for the activity log. Buttons are flat, borderless, hand cursor, with hover background colours. Group headers gold (Guide header cyan). Immersive dark titlebar via DwmSetWindowAttribute on Shown.

---

## 7. v0.2.0 additions - upgrade-failure diagnosis + memory-exhaustion fix

Engine `JanetWeb.winupgrade.psm1` is now v0.2.0; desktop source is `WindowsUpgradeTool_0.2.0.ps1`. Two new operations and a Pin option were added; both UIs implement them identically.

- **Pin** gained a **"Also trigger a Windows Update scan after pinning"** checkbox (`runWu`). The Pin guide now also names the equivalent gpedit policy: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Update > **Select the Target Feature Update** (Enabled, Product + Version). After writing the policy, if ticked, the worker kicks the WU agent (`Start-ScheduledTask '\Microsoft\Windows\WindowsUpdate\' 'Scheduled Start'`, UsoClient `StartScan` fallback) - the "then run Windows Update" step. A trigger failure never fails the pin.
- **Check Upgrade Errors** (`checkupgrade`, read-only, exposed via a **Check Errors** button next to Test Ping). Reads `C:\$WINDOWS.~BT\Sources\Panther\setuperr.log` over WinRM (shared FileStream so an in-flight upgrade does not lock it out) and classifies it: **MEMORY** (out-of-memory build failure - E_OUTOFMEMORY `0x8007000E` / out-of-memory text; amber), **ERRORS** (other setup error; amber), **CLEAN** (log present, no errors; green), **NO LOG** (no recent in-place upgrade attempt; grey), **FAILED** (read error). No confirm, no admin-session guard, **no audit row**.
- **Set Page File** (`setpagefile`, destructive radio op, default 16384 MB / 16 GB, range 1024-131072). Disables `Win32_ComputerSystem.AutomaticManagedPagefile` and sets/creates `Win32_PageFileSetting` for C: to a fixed `InitialSize = MaximumSize = sizeMb` via WMI (`-EnableAllPrivileges`), then optionally reboots `shutdown /r /t 10` (required to apply). Success status is **NEEDS REBOOT** (amber). Gated behind admin session + a reboot-warning confirm; honors Dry-run; audits as **TouchHost**. The scripted form of sysdm.cpl > Performance Settings > Advanced > Virtual memory.

**Worker positional args are now 15** (desktop AddArgument order = TWO `$argFactory` order = worker `param()` order): Computer, Op, Cred, TargetVer/Product, ProductName/Version, CabPath, CabName, (TWO only: CabFromShare,) Reboot, AttemptOffline, DryRun, **RunWu, SizeMb**, (Queue, Sync) / (CancelJob, StepQueue). Status vocabulary gains **MEMORY, ERRORS, CLEAN, NO LOG, NEEDS REBOOT** (plus live phases Reading / PageFile / Scanning).

**Typical workflow:** Pin to 24H2 (+ run WU) -> if the in-place upgrade fails, **Check Errors** across the fleet -> on the hosts flagged **MEMORY**, run **Set Page File** -> re-run the feature update.