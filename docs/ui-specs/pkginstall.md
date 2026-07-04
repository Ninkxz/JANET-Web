# JANET TWO - UI Rebuild Spec: pkginstall

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The Remote Package Installer (J.A.N.E.T. v2.5.4) is a single-window WinForms operator console for fanning out PSADT package deployments (or raw MSI bundles) to many AD workstations in parallel. It is NOT tab-based: the right pane is a vertical stack of bracketed "cards" (Target Workstations, Package Source, an action bar, Deployment Results grid, Execution Log) over a dark purple/gold theme, with a fixed left sidebar (brand, live SESSION stats, user/cred block) and a bottom status strip (heartbeat, target/package counts, live deploy progress, log path). The workflow is linear top-to-bottom: paste/import target hostnames, pick a package root + package (or custom folder, or toggle MSI-bundle mode and pick MSIs), Set Credentials, choose a parallelism level, then click the pulsing Deploy CTA. The run model is the heart of the tool: a RunspacePool fans out one PowerShell-per-host scriptblock, a 400ms WinForms drain timer polls completion and a shared ConcurrentQueue of intermediate step messages, and streams live per-host status into a colour-coded DataGridView (Queued->Probing->Repairing/Copying->Deploying->Success/Failed/Deferred) plus a timestamped Execution Log, a sidebar Success/Failed tally, and a "Progress: done/total (pct%) | Live: N" status line. The Deploy button becomes a Cancel button mid-run; cancel stops watching but lets in-flight hosts finish. Double-clicking a grid row opens a read-only Host Detail modal with full stdout/exit/timing/repair info; the grid can also pop out into its own floating window.

---

# Remote Package Installer (pkginstall) -- UI/UX Rebuild Spec

Source: `X:\J.A.N.E.T\Tools\RemotePackageInstaller.ps1` (J.A.N.E.T. Remote Package Installer **v2.5.4**). This is a single-window WinForms console. There are **no tabs** -- the operator works top-to-bottom through a vertical stack of bracketed "cards" in the right content pane, with a persistent left sidebar and bottom status strip. Rebuild it as a JANET ONE web-local page that reproduces this exact layout and, above all, the live "activity run" experience.

## 1. Window + navigation layout

Main form: title `J.A.N.E.T.  Remote Package Installer  v2.5.4`, ClientSize **1360x800**, min 1200x720, centered, sizable, dark title bar, DPI-aware. Background `#0A0B0E`. Three docked regions:

- **Left Sidebar** (docked Left, width **252**, bg `#07080B`, 1px right border):
  - **Brand block**: `J.A.N.E.T.` mark (18pt bold mono, purple `#8C64DC`), subtitle `Remote Pkg Installer`, version `v2.5.4`, and a blinking purple **heartbeat dot** (UI-alive telltale).
  - **/ SESSION block**: live stats -- **Targets loaded** (big number), **Package** (resolved leaf name, mono), **Last run** (timestamp), and **Success / Failed** big-number counters (green `#7FB25E` / red `#E5484D`). These update live during a run.
  - **User/session block** (bottom): `User: <name>`, `Creds:` + pulse dot + username (turns green when creds loaded), `Host: <computer>`.
- **Bottom Status Strip** (docked Bottom, height **32**, bg `#07080B`, 1px top border, scanline overlay): blinking **heartbeat dot** (leftmost -- if it stops, UI thread is stuck), `User: <name>`, `Targets: N`, `Packages: N`, the live **`Progress: 12 / 120 (10%) | Live: 8`** label (purple in-flight / green at 100% / amber `[CANCELLED]`), and right-aligned `Log: <filename>`.
- **Content Host** (Fill): a 36px top strip with a **CLOSE TOOL** button and a blinking `live` indicator (right), a 2px purple accent rule + 1px divider, then a grid-paper-textured body holding the card stack.

The card stack, in order (each a surface panel `#121318` with 4 L-shaped corner brackets, a `/ HEADER` eyebrow + dotted underline, accent-coloured):
1. **Target Workstations** (purple) -- host entry.
2. **Package Source** (gold) -- root/package/custom/MSI selection.
3. **Action bar** (not a card) -- credentials, parallelism, Deploy/Retry/Export.
4. **Deployment Results** (purple) -- the live grid + Pop Out.
5. **Execution Log** (gold) -- the streaming console.

## 2. Per-tab (per-card) controls + workflow

**Card 1 -- Target Workstations.** Caption `ENTER HOSTNAMES - ONE PER LINE OR COMMA-SEPARATED`; a multiline textbox (`$txtManual`); right-stacked ghost buttons **Import** (OpenFileDialog .txt/.csv -- first comma/semicolon field per line, appended to existing) and **Clear**. TextChanged live-updates status strip, sidebar count, and Deploy-readiness pulse. Parsing (`Get-RpiComputerList`) splits on newlines+commas, trims, **case-insensitive dedups**, sorts.

**Card 2 -- Package Source.** Rows:
- **ROOT** row: a `SCAN` filled button (purple) left of the `$txtRoot` path textbox (prefilled with default root), then ghost **Rescan** and **Save** (gold) buttons right. SCAN opens a FolderBrowserDialog then rescans; Enter in the textbox also rescans; Save persists prefs to `RemotePackageInstaller.config.json`.
- **Use custom package folder** checkbox: when on, reveals a custom-path textbox + **Browse** and disables the root combo/root textbox/rescan.
- **PKG** row: `$comboPackage` dropdown (populated by `Update-RpiPackageList`: subfolders of root containing `Deploy-Application.ps1` OR `*.msi`) + a `// <resolved path>` label (green when resolved, amber/red on problems).
- **MSI bundle row**: `MSI bundle (auto-install all .msi)` checkbox (gold), **MSI ARGS** textbox (default `/qn /norestart`), **Pick MSIs** ghost button, and a `// MSI mode off` summary label. Toggling MSI mode on scans the resolved folder and auto-checks every `.msi`; Pick MSIs opens the picker modal. The actual selection lives on a hidden CheckedListBox (`$script:clbMsi`).

**Action bar.** **Set Credentials** ghost button (left) + `// <USER>` cred-status label (amber when none, green when set); **PARALLEL** eyebrow + NumericUpDown (1-32, default 8); right cluster **Export**, **Retry Failed** (amber), and the gold-striped **Deploy** CTA (44px tall).

Operator flow: paste/import hosts -> set/confirm root and pick package (or custom folder, or flip MSI mode and pick MSIs + args) -> Set Credentials -> choose parallelism -> click Deploy (which pulses once all preconditions are met).

## 3. THE RUN MODEL + ACTIVITY VIEW (preserve exactly)

**Launch.** The only run control is **Deploy** (`$script:btnRunInstall`). It **pulses (glows) only when ready**: creds loaded AND >=1 target AND a package resolved AND (in MSI mode) >=1 MSI checked. On click it validates in order, each failure raising its own MessageBox warning: "No Targets", "No Credentials", empty custom folder, no package selected, package folder not found, "No MSIs Selected". **There is no separate yes/no confirm** -- passing validation dispatches immediately.

**Dispatch.** Clears the grid and result lists; **seeds one `QUEUED / ...` row per host** so the full target list is visible instantly; logs a `=== Deploying '<pkg>' to N target(s) ===` banner (plus MSI args + per-file lines in MSI mode); changes the Deploy button label to **`Cancel`**; sets the cred pulse to **Alert**; reads PARALLEL; calls `Start-RpiParallelDeploy`.

**Engine.** `Start-RpiParallelDeploy` opens an STA `RunspacePool(1, max)`, and `BeginInvoke`s one `[powershell]` per host running `$script:RpiDeployHostScript`, passing (computer, pkgPath, pkgName, credential, WSManOpt, a shared `ConcurrentQueue`, mode, msiList, msiArgs). It returns a **state object** (Jobs list, StepQueue, Total, Successes/Failures/Deferreds, Cancelled, RunStart, FinalizeFired). The per-host scriptblock: probes WinRM **5985** -> if closed, probes SMB **445** and attempts a **DCOM WinRM bootstrap repair** -> copies the package -> runs `Deploy-Application.ps1` (PSADT mode) or `msiexec /i` per selected file (MSI mode). It **pushes intermediate step messages** (`Probing`, `Repairing`, `Copying`, `Deploying`) onto the queue and returns a structured `pscustomobject` (Status, Reason, Detail, ExitCode, Output, RepairAttempted/Succeeded, Start/End).

**Streaming back.** A **400ms** `System.Windows.Forms.Timer` (`$script:RpiDrainTimer`) ticks `Step-RpiDeployDrain` on the UI thread. Each tick: (a) drains all queued **step messages** and repaints those host rows with the live phase; (b) `EndInvoke`s any completed jobs, sets the row to terminal status, increments the right counter, writes a per-host log line (`[host] SUCCESS (exit=0)...`, with a `[REPAIRED]`/`[REPAIR-FAILED]` prefix when a bootstrap fired), appends to `$global:DeployResults`, mirrors to JANET metrics, and stashes the full result in `$script:RpiHostDetails`; (c) repaints the status-strip progress label; (d) **live-updates** the sidebar Success/Failed counters. Finalize fires when all jobs are done OR cancelled: timer stops, `Complete-RpiParallelDeploy` writes the summary banner, updates sidebar Last run + final tally, leaves the final progress text on the strip, closes the pool, resets the button to `Deploy`, and sets the cred pulse to Active (all-success) or Alert.

**Cancel/abort.** Clicking the button mid-run sets `state.Cancelled = $true`, disables it, shows **`Cancelling...`**, and the drain short-circuits to the summary. **In-flight runspaces are deliberately NOT killed** -- they finish quietly so no target is left mid-MSI-install. Cancel means "I'm done watching."

**Activity view -- three synchronized surfaces:**
- **Deployment Results DataGridView** (purple card). Columns **HOST** (200) / **STATUS** (110) / **DETAIL** (600) / **TIME** (110, HH:mm:ss). Read-only, full-row-select, single horizontal cell borders, alternating row bg, no row headers, 24px rows, header bg `#0C0D11` with purple text. **One row per host, keyed by hostname** (`Update-RpiResultGrid` upserts), so each row mutates through its lifecycle. **Row colour by status**: QUEUED muted grey, PROBING secondary grey, REPAIRING/DEPLOYING amber `#F2B84B`, COPYING info-blue `#73B4D3`, SUCCESS green `#7FB25E`, FAILED red `#E5484D`, DEFERRED amber. **Double-click a row** -> `Show-RpiHostDetail` modal (720x540): host title + colour-matched STATUS badge, metadata grid (Package / Exit / Reason / Started / Ended / Duration / Repair), a console-styled RichTextBox with the full `Deploy-Application.ps1`/msiexec output, **Copy Output** + **Close**, plus an in-form X. A gold **Pop Out** button reparents the SAME grid into a floating 1200x640 window (it keeps streaming); re-click brings it back.
- **Execution Log** (gold card): read-only RichTextBox, **black bg + gold monospace text** (console look), no wrap, vertical scroll. `Write-RpiLog` prepends `[HH:mm:ss]` and auto-scrolls. Carries the dispatch banner, every per-host result line, the cancellation notice, and the `=== Deployment complete : X success, Y failed (Ns) ===` summary.
- **Status strip + sidebar**: live `Progress: done/total (pct%) | Live: N` (purple/green/amber-cancelled); sidebar Success/Failed big numbers + Last run. There is **no determinate progress bar** -- the fraction/percent text, the per-row grid, and the live counters together convey progress.

## 4. Targets / host-list / credential / shared state

Targets live only in `$txtManual`; `Get-RpiComputerList` parses (newline/comma split, trim, case-insensitive HashSet dedup, sort). Import appends; Clear empties; **Retry Failed** harvests all `FAILED` grid rows back into the textbox for a re-run. Credentials come from a `Get-Credential` modal stored in `$global:Credentials`; the cred-status label and the sidebar cred pulse reflect loaded state. Shared/cross-state: `$global:PackageMap` (name->folder), `$global:DeployResults` (export source), `$script:RpiHostDetails` (drill-down store), `$script:clbMsi` (hidden MSI selection), `$script:RpiDeployState` (the live run), and config persistence (`Read-RpiConfig`/`Save-RpiConfig` -> `RemotePackageInstaller.config.json`: root, useCustom, customPath, msiMode, msiArgs, msiSelection) restored on launch. A JANET centralized session (`Start-JanetSession 'Remote_Pkg'` ... `Stop-JanetSession -ShowDialog`) records per-host `VulnPatched` metrics and a closing-notes rollup.

## 5. Engine functions / scriptblocks the UI calls

Re-fork the engine to expose these entry points behind the same UI: `Start-RpiParallelDeploy` (fan-out), `$script:RpiDeployHostScript` (per-host work: probe->repair->copy->PSADT/MSI), `Step-RpiDeployDrain` (poll+stream), `Complete-RpiParallelDeploy` (finalize), `Update-RpiResultGrid` (row upsert+colour), `Update-RpiProgressLabel`, `Update-RpiStatusStrip` / `Update-RpiSidebarStats` / `Update-RpiReadyPulse`, `Get-RpiComputerList`, `Update-RpiPackageList` / `Get-RpiResolvedPackagePath`, the MSI helpers (`Update-RpiMsiList`, `Get-RpiResolvedMsiList`, `Get-RpiResolvedMsiFolder`, `Update-RpiMsiSummary`, `Show-RpiMsiPickerDialog`, `Get-RpiMsiInFolder`), `Show-RpiHostDetail`, `Write-RpiLog`, `Write-RpiAuditLog`, `Read-RpiConfig`/`Save-RpiConfig`, `Test-RpiReachable`, and the JANET session trio. For a web rebuild, the equivalent is: a POST `/deploy` that launches the runspace fan-out and returns a run id; a streaming endpoint (SSE/WebSocket/long-poll on a ~400ms cadence) carrying step + terminal events keyed by hostname; and a per-host detail endpoint backed by the same structured result.

## 6. UX details + visual theme to preserve

**Theme.** Near-black surfaces (`Background #0A0B0E`, `Surface #121318`, `Sidebar/StatusBar #07080B`, `Console #050609`). **Purple primary accent `#8C64DC`** (+ hover `#AA82E8`, muted `#6B48B0`), **gold secondary `#DAB452`**. Status palette: success `#7FB25E`, warning `#F2B84B`, danger `#E5484D`, info `#73B4D3`. Text hierarchy: primary `#F2F4F7`, secondary `#A0A5AE`, muted `#6A6F78`, faint `#3E434C`; on-accent near-black `#0C0903`. Grid: bg `#121318`, alt `#171921`, header `#0C0D11`, selection purple-tint `#2A1C44`. **Fonts**: `Cascadia Mono` for display/eyebrow/mono (DisplayLg 18 bold ... MonoTiny 8) and `Segoe UI Variable Display` for body; console text is gold mono on black.

**Details to keep.** Bracketed cards with `/ HEADER` eyebrow + dotted underline; grid-paper body texture + scanline overlay; three blinking heartbeat dots (brand, content `live`, status strip) as liveness telltales; the gold-striped Deploy CTA that pulses only when ready and morphs Deploy->Cancel->Cancelling...; the immediate Queued-rows seeding; `[REPAIRED]`/`[REPAIR-FAILED]` log tagging; row double-click drill-down + grid pop-out; Retry Failed and CSV Export; pre-flight validation as individual MessageBox warnings (no single confirm); the OneDrive-path startup warning; and the **guarded close** -- only the **CLOSE TOOL** button closes the form (X/Alt-F4/title-bar Close are cancelled), and FormClosing runs the JANET closing-notes rollup. The single egress + one-CTA discipline is intentional and should carry into the web rebuild.