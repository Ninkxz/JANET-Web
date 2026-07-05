# JANET Web - UI Rebuild Spec: acas

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The ACAS Nemesis Tool is a PowerShell 5.1 WinForms desktop app for AFNET vulnerability remediation: an operator imports Tenable/ACAS-Nessus CSV exports, the tool maps each finding to a known "update profile," and pushes remediations to ONLY the hosts each vulnerability affects via a runspace-pool/Invoke-Command fan-out. The window is a dark tactical-HUD shell (near-black background, purple #8C64DC primary accent, gold #DAB452 secondary, Cascadia Mono display type) with a full-width gold-striped top bar, a 210px numbered left sidebar (NOT a TabControl -- each "tab" is a Dock=Fill Visible=$false Panel swapped on nav click), a bottom status strip, and 8 sections in order: Start, Targets, Updater, Not Updatable, KB Installer, Vulnerabilities, Logs, Backbone. The signature experience is the Updater tab: one card per vulnerability with a Run/Verify button, plus Run-All (sequential) and Bulk-Run (parallel) orchestrators, all streaming per-host colour-coded results into a pop-out RichTextBox "Updater Log" driven by a 250ms WinForms drain Timer that EndInvokes completed runspace jobs, tallies success/fail, updates a status line, and writes a Runs CSV summary on completion. Every tab past Start is session-gated (must Set Credentials + acknowledge + Start Session first), and the title-bar X is blocked in favor of an explicit Close Tool button.

---

# ACAS Nemesis Tool -- UI/UX Rebuild Spec (tool id: `acas`)

Source studied: `X:\J.A.N.E.T\Tools\ACAS Nemesis Tool_1.10.10.ps1` (v1.10.10). This is a Windows PowerShell 5.1 WinForms app for AFNET vulnerability remediation. The operator imports Tenable/ACAS-Nessus CSV exports; the tool maps each finding to an "update profile" and pushes remediations to **only** the hosts each vulnerability affects, streaming per-host results live. The whole point to preserve is the **live activity run experience** on the Updater tab.

## 1. Window + Navigation Layout

**Main form** (`Show-NemMainForm`): title `ACAS Nemesis Tool  vX.Y.Z`, ClientSize 1440x850, MinimumSize 1280x760, DPI auto-scale, CenterScreen, Sizable, dark immersive title bar (DWM attr 19/20). FormClosing **blocks the title-bar X / Alt-F4** (UserClosing) unless an internal `NemAllowClose` latch is set by the Close Tool buttons; on a real close it runs a closing-notes dialog then JANET rollup.

Layout is four docked regions (NOT a TabControl):
- **Top bar** (Dock=Top, h=64, near-black `#06060A`): gold `#DAB452` wordmark "J.A.N.E.T. ACAS Nemesis Tool", grey subtitle "Joint Administration and Network Execution Toolkit - vX.Y.Z", a 2px **gold accent stripe** along the bottom edge, and a top-right red **Close Tool** button (`Invoke-NemCloseFlow`).
- **Sidebar** (Dock=Left, w=210, `#06060A`): a scrollable nav host of numbered items, and a bottom User/Status/Host block (`User: <name>`, a status dot + `idle/active`, `Host: <computer>`), separated by a 1px border.
- **Status strip** (Dock=Bottom, h=32, `#07070B`): three mono labels -- `Session: idle`, `Targets: 0`, and a right-aligned last-log message; a 1px top border.
- **Content host** (Dock=Fill): holds one Dock=Fill, `Visible=$false` Panel per nav key. Nav click sets the chosen panel visible, the rest hidden, and marks the nav item active.

**Nav items** (`New-WptNavItem`): each 209x42, with a 3px left accent bar (visible only when active), a two-digit mono index (`01`...`08`), a Segoe MDL2 glyph, and an uppercased label. States: idle (sidebar bg, muted), hover (`SurfaceHover`, primary text), active (`SurfaceActive` bg, purple accent bar + purple index/icon, primary text).

**Tabs in order** (the `$navSpec` array):
1. **Start** (gear) -- credentials, acknowledgment, Start Session; gateway to everything else.
2. **Targets** (bullseye) -- "Data Import": import ACAS/Nessus CSVs to populate targets + findings.
3. **Updater** (refresh) -- the primary action surface: one card per vulnerability, smart-dispatch runs.
4. **Not Updatable** (ballot-X) -- read-only cards for vulns with no matched profile.
5. **KB Installer** (lightning) -- install Windows KB rollups parsed from the CSV.
6. **Vulnerabilities** (warning) -- raw findings grid; checkboxes gate which findings feed Updater/KB.
7. **Logs** (menu) -- tail of the session audit log.
8. **Backbone** (info) -- reference: per-profile mechanism notes + workflow walkthrough.

Every nav click except Start runs a **session gate**: if `Session.Started` is false it shows `Show-NemSessionGateDialog` (a Warning MessageBox: "Session not started... Open the Start tab and click Start Session") and refuses the switch.

## 2. Per-Tab Controls + Workflow

**Start** (`Add-NemStartTab`): Title "Start Session". An **Activation card** (Surface panel, FixedSingle) with a left column of status lines (CREDENTIALS / ACKNOWLEDGE / USER / LOG FILE / SHARE LOG, each red/green/muted by state), a vertical divider, and a right column with a large **Start Session** button (disabled until ready), a sub-hint, and a gate hint `[+] credentials   [-] acknowledge`. Below: a **Credentials card** ("Set Credentials" button -> `Get-Credential`, status "not set"/username) and an **Acknowledgment card** (blurb + "I acknowledge responsibility for remote operations" checkbox). Bottom: **Change Log** and **How To Use** buttons (`Show-NemInfoDialog`, always available, no gate). Flow: Set Credentials -> tick acknowledge -> Start Session enables -> click -> opens audit log (`Open-NemAuditLog`, share-with-local-failover MessageBoxes), starts JANET session, opens the runspace pool, button becomes "Session Active".

**Targets** (`Add-NemTargetsTab`): Title "Data Import". A **tile strip** (Targets Loaded / ACAS Findings / Unique Hosts / Last Import). Action row: hero **Import ACAS CSV** (multi-select OpenFileDialog -> `Import-WptAcasCsv` -> `Get-WptAcasTargetHosts`; archives a copy, drops `msek-*` server hosts via `Test-NemIsServer`, dedups case-insensitively), **Clear All** (confirm MessageBox), **Remove Selected**. Body: an "TARGETS LIST (N)" eyebrow + a multi-select monospace ListBox of hostnames. Importing also accumulates `AcasFindings` used by Vulnerabilities/Updater/KB.

**Updater** (`Add-NemUpdaterTab`) -- see 3.

**Not Updatable** (`Add-NemNotUpdatableTab`): same card layout as Updater minus Run/dropdown/log. Tile strip (Total Not Patchable / Critical / High / Hosts Affected) + Refresh Cards. Info-only view of what ACAS flagged that this tool can't remediate.

**KB Installer** (`Add-NemKBInstallerTab`): Title " KB Installer". Action bar: Rescan Findings, Select All, Deselect All, Select Critical/High, a **Method** dropdown (`MECM (CIM targeted)` default / `UsoClient Trigger`), an **MSU file** path + Browse (enabled only for MECM), a **Suppress auto-reboot** checkbox, and a parsed/selected count label. A checkbox **DataGridView** (Select / Host / KB / Severity / Plugin / CVE). Run groups checked rows by host, dispatches one job per host with its KB list.

**Vulnerabilities** (`Add-NemVulnerabilitiesTab`): Title "Vulnerabilities". Toolbar: Select All, Deselect All, **Select Critical/High Only**, Reload Findings, a count label, and a note that deselected rows are excluded from Updater/KB runs. A **DataGridView** (AutoGenerateColumns off, FullRowSelect, alternating row colours, gold headers): **Select** (checkbox, w50) / **Host** (w260) / **Severity** (w80) / **Plugin** (Fill) / **CVE** (Fill) / **Solution** (Fill, wrap). Checkbox commit handled via `CurrentCellDirtyStateChanged` -> `CommitEdit`.

**Logs** (`Add-NemLogsTab`): path label, **Refresh** (tails last 500 lines of the audit `.log`), **Open Log Folder**, and a read-only mono TextBox; auto-refreshes on tab show.

**Backbone** (`Add-NemBackboneTab`): Refresh Content + Copy to Clipboard, and a read-only scrollable mono RichTextBox of auto-generated per-profile mechanism notes + the full workflow; rebuilt on each visit to pick up newly-registered profiles.

## 3. THE RUN MODEL + ACTIVITY VIEW (the part to preserve exactly)

**Updater header** (h~260): Title "Updater" + sub "One card per vulnerability. Each Run pushes ONLY to the hosts that vuln affects." A **6-tile summary strip** (Total Vulns / Patchable / Not Patchable / Critical / High / Med+Low). An **action button row**: ghost-styled **Refresh Cards**, **Pre-Flight Services**; gold **Run All (Sequential)**, **Bulk Run (Parallel)**; red **Cancel Run** (disabled until a run starts); ghost **Pop Out Log**; and a right-side **status label** ("Idle"). A **Log4j source** override textbox + hint. Below: a `FlowLayoutPanel` (TopDown, scrollable) of vuln cards.

**Vuln card** (`New-NemVulnCard`, Surface panel, FixedSingle, ~96px, 14px bottom margin): a 4px **severity-coloured top accent**; row 1 = `[SEVERITY]` badge + optional `[ROLLUP xN]` / `[EXPERIMENTAL]` badge + plugin DisplayName (ellipsis, CVE/member tooltip); row 2 = a profile **dropdown** (if >1 profile) or label, and a right-aligned `N host(s)` (affected-host tooltip); right column = **Run on N host(s)** + **Verify** buttons (disabled, greyed "No profile" when nothing mapped). The card's `Tag` exposes RunButton/VerifyButton/Vuln/ProfileCombo for the orchestrators.

**Launch (per card)** -> `Start-NemVulnRun`: gates on session + open pool; enforces a **single-run lock** (rejects if any job besides `_counters` is outstanding or `updTimer` exists, with a "run already in progress" MessageBox); resolves the affected host list; calls `Set-NemVulnCardRunEnabled $false` (locks every card's Run+Verify), enables Cancel, sets the status label amber ("Running '<profile>' for [<vuln>] on N host(s)..."), and writes a banner to the log RTB. It resets `$s.Jobs` to `@{ _counters = @{Success;Failed;Total;VulnDisplay;ProfileName;AuditPrefix;ModeLabel;StartedAt;GroupKey;GroupMembers} }`. For each target it does `[powershell]::Create()`, `.RunspacePool = $s.Pool`, `AddScript(<per-host scriptblock>)` (inline TCP 5985/445 probe -> bounded PSSession via Negotiate -> rehydrate the profile scriptblock; package/Log4j source overrides passed as args), `AddArgument(...)`, then **`$ps.BeginInvoke()`**, storing `$s.Jobs[guid] = @{PS;Async;Target}`.

**Stream-back (drain Timer)**: a `System.Windows.Forms.Timer` ('updTimer') at **250ms** (`Get-NemDrainInterval`). Each Tick walks `$s.Jobs`, and for any job whose `.Async.IsCompleted` is true it `EndInvoke`s, classifies the returned string (`FAIL*` = failure, anything else = OK), increments `_counters.Success/Failed`, and **appends one colour-coded line to the RichTextBox**: `SelectionColor = Success(green)` or `Danger(red)`, `AppendText("<target> : <result>\r\n")`, then resets SelectionColor. It writes an audit row (`Write-NemAudit "<prefix>.Target"`) and a JANET `VulnPatched` metric. To stay responsive it caps work at **`Get-NemDrainCap` (3)** completed jobs per tick (a hung share otherwise froze the UI). When no jobs remain besides `_counters`, the timer stops/disposes, prints a **Complete banner** (`Complete [<vuln>] <mode>: X succeeded, Y failed`), writes one **Runs-CSV summary row** via `Write-NemRunSummary` (rolled-up group cards fan out one row per member), re-enables cards, disables Cancel, and sets the status label green (0 failures) or amber.

**Activity log surface**: a single read-only monospace **RichTextBox** ("Updater Log", `updRtbLog`), near-black bg, vertical scroll, no wrap. It is the ONE log control reparented at runtime: on first Updater visit a deferred 1ms timer rebuilds cards and **auto-pops the log into a floating dark-titlebar window** (`Show-NemUpdaterLogPopOut`) so cards get full height; **Pop Out Log** does the same on demand; closing the pop-out reparents it back into a hidden wrap panel. Banners are 40-equals-sign blocks. There is **no determinate progress bar** -- progress is shown by (a) the run status label, (b) the bottom status strip, and (c) per-host lines accumulating in the log.

**Run All** (`Start-NemRunAll`): builds a queue of card Run buttons, **confirms** ("Run All will sequentially execute N card action(s). Continue?"), prints amber RUN ALL banners, `PerformClick()`s card 1, then a **500ms orchestrator timer** waits until `$s.Jobs` is empty AND `updTimer/rebTimer/rebVerifyTimer` are all gone before dequeuing and clicking the next; status reads "Run All: i of N completed, starting next...". Cancel sets a `RunAllCancelled` flag the orchestrator honours.

**Bulk Run** (`Start-NemBulkRunAll`): submits every patchable card's (host,profile) tuple into the pool **in parallel** under one shared drain timer (reboot cards skipped). Shares the single-run lock and the Cancel button.

**KB Installer run**: groups checked grid rows by host, dispatches one job/host with its KB list, branches MECM (CCM_SoftwareUpdate CIM query + InstallUpdates, MSU fallback) vs UsoClient Trigger; honours suppress-reboot; same banner+drain+per-host-line pattern (own `kbTimer`).

**Cancel** (shared red button): stops the preflight timer, sets `RunAllCancelled`, `PS.Stop()/Dispose()` on every job, wipes `$s.Jobs`, tears down **every** drain timer (`updTimer/rebTimer/rebVerifyTimer/kbTimer`), writes a warning "CANCELLED by operator (N job(s) stopped)" banner, re-enables cards, disables Cancel, status "Cancelled".

`Invoke-NemUpdateRun` is the single-target programmatic path (Invoke-Command wrapper returning `OK*`/`FAIL*`) for callers that don't drive the card UI.

## 4. Targets / Host-List / Credentials / Shared State

State lives in `$script:Nemesis` (an ordered dict; use `Get-NemState`, note `.Contains` vs hashtable `.ContainsKey`). Key cross-tab fields: `Targets` (hostname list, ListBox on Targets), `AcasFindings` (parsed CSV rows feeding Vulnerabilities/Updater/KB), `Credentials` (PSCredential from Start; may be `$null` -> ambient Kerberos), `Session` (Started/Success/Failed/RunCount), `Pool` (runspace pool), `Jobs` (in-flight async handles + `_counters`), `Config.LogDir/LogFile`, `UI.Controls` (all named controls), `UI.NavItems`, `LastImportFile/Time`. Host scope is independent of finding selection: deselecting rows on Vulnerabilities excludes them from runs; `Test-NemIsServer` drops `msek-*` server hosts at import. Credentials are set once on Start and reused for every remote dispatch.

## 5. Engine Functions the UI Calls (re-fork entry points)

Run: `Start-NemVulnRun`, `Invoke-NemUpdateRun`, `Invoke-NemRemote`, `Start-NemRunAll`, `Start-NemBulkRunAll`, `Start-NemRebootRun`/`Start-NemRebootVerify`, KB-install run fn, `Start-NemServicesPreflight`, `Set-NemVulnCardRunEnabled`. Data/classify: `Import-WptAcasCsv`, `Get-WptAcasTargetHosts`, `Test-NemIsServer`, `Get-NemVulnCardEntries`, `Get-NemProfileMatchTable`, `Get-WptAppUpdateProfiles`/`Get-WptAppUpdateProfile`, `Resolve-NemProfileScriptText`, `Get-NemLog4jSourcePath`/`Get-NemPackageSourcePath`. Cards/tiles: `Update-NemVulnCards`, `Update-NemNonUpdatableCards`, `Update-NemUpdaterSummary`, `New-NemVulnCard`, `New-NemDashTile`. Logging/telemetry: `Write-NemAudit`, `Write-NemRunSummary`, `Write-NemRunCsvLine`, `Open-NemAuditLog`, plus JANET `Start-JanetSession`/`Write-JanetAction`/`Stop-JanetSession`. Shell: `Get-NemState`, `Show-NemSessionGateDialog`, `Show-NemInfoDialog`, `Show-NemClosingNotesDialog`, `Invoke-NemCloseFlow`. For the web re-fork, each run entry point should emit the same event stream the drain timer consumes (per-host `{target, ok|fail, result}` plus start/complete/cancel banners and a final summary) so the activity view reproduces 1:1.

## 6. Visual Theme + UX Details to Preserve

Theme (`$script:Nemesis.UI.Theme`): Background `#08080C`, Sidebar/TitleBar `#06060A`, Surface `#101016`, SurfaceAlt `#16161E`, SurfaceActive `#28243A`; Border `#26223A`; **Accent1 purple `#8C64DC`** (nav/headers/primary), **Accent2 gold `#DAB452`** (loud run actions, DGV headers, accent stripe); Success green `#5CC678`, Warning amber `#E6B446`, Danger red `#E0505A`, Info cyan `#58B4D2`; TextPrimary `#F0F0F5`, TextSecondary `#AAA8B4`, TextMuted `#6E6A7D`, TextFaint `#3C384A`. Fonts: **Cascadia Mono** for display/titles/data/log (DisplayLg 18pt bold, hero tiles 22pt bold), **Segoe UI Variable Display** (-> Segoe UI) for body, **Segoe MDL2 Assets** for icons. Severity colour map is consistent across cards, grids, and log lines. Preserve: tactical numbered nav with active accent bar; session gating; the pop-out/re-dockable log; live hero tiles; the blocked-X + explicit Close Tool egress; closing-notes (ASI/RFC) dialog; Change Log / How To Use info dialogs; the green/red per-host streaming; the single shared Cancel; and the share-with-local-failover logging messaging.