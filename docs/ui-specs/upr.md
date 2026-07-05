# JANET Web - UI Rebuild Spec: upr

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The Unsupported Product Remediator (UPR) is a single-window, dark-purple WinForms admin tool that ingests a Tenable/ACAS "Unsupported & SEoL" report (PDF or CSV), parses it into a findings catalog, and lets an operator bulk-uninstall proven end-of-life software from the affected hosts over WinRM. The window is a fixed top toolbar + a custom dark 4-button nav row (the native tab strip is hidden) driving a 4-page TabControl (Import & Findings, Uninstall, OS Findings, History) + a bottom status strip. The whole experience pivots on a live "activity run": the operator picks a finding, clicks Scan Hosts (fans out a RunspacePool of per-host WinRM registry scans), reviews a results DataGridView where each row is a per-host install candidate colour-coded by outcome with only catalog-PROVEN-EOL rows pre-checked, then clicks Uninstall Selected (a Yes/No confirm with a dry-run notice), and watches per-row Result cells transition Uninstalling... -> OK/WARN/FAIL while a monospaced ACTIVITY log streams timestamped, severity-coloured lines. A Plan-only dry-run checkbox, thread count, host-class filter and inherited credentials are shared global state across all tabs.

---

# Unsupported Product Remediator (upr) -- UI/UX Rebuild Spec

Source: `X:\J.A.N.E.T\Tools\UnsupportedProductRemediator_1.1.2.ps1`. This spec describes the FRONTEND and run experience to reproduce in JANET Web (pure-PowerShell web-local). Engine logic is re-forked separately; the entry points are named in section 5.

## 1. Window + Navigation Layout

**Main form** (`$f`): title `J.A.N.E.T. - Unsupported Product Remediator v<ver>`, size 1340x800, MinimumSize 1320x720, CenterScreen, Sizable, dark background `$c.BG (8,8,12)`. DPI-aware, double-buffered, dark title bar. Close is guarded: a `Set-JanetAllowClose` flag + a `FormClosing` handler `$e.Cancel = $true` for every close origin EXCEPT the sanctioned red **Close Tool** button (top-right of toolbar) and OS shutdown.

The window is four stacked regions:

1. **Top toolbar** (`$pnlTop`, 56px, `$c.TopBar`): gold bold title "Unsupported Product Remediator" (Cascadia Mono 13) + dim italic subtitle "PDF/CSV in - bulk uninstall of unsupported / SEoL software on the affected hosts". Center-left cluster: `Report:` label + **Load PDF / CSV** button (purple Accent). `Dry-run:` label + **Plan-only** checkbox (CHECKED by default, tooltip explains no state change). Right-anchored cluster (computed from live client width, order from right edge): `[Threads: NN]` NumericUpDown (1-32, default 8) * **Reload Catalog** button (GoldDim) * **Close Tool** button (red Danger). A small blinking "live" pulse dot sits at the right of the subtitle row.
2. **Custom nav row** (`$pnlNav`, 32px at y=56): four flat buttons -- **Import & Findings**, **Uninstall**, **OS Findings**, **History** -- each 178x28. The native TabControl strip is HIDDEN (`ItemSize 0,1`, FlatButtons); these buttons are the only tab affordance. `Set-UprActiveTab($i)` sets `$tc.SelectedIndex` and repaints: active button = purple Accent bg / white text, others = Panel bg / TextSec text.
3. **TabControl** (`$tc`, y=88, fills to bottom): four TabPages in order -- `tabImport`, `tabUninstall`, `tabOs`, `tabHistory`. (A 5th "Update" tab was removed in v1.1.0 -- the tool is uninstall-only.)
4. **Status strip** (`$pnlStatus`, 32px bottom, `$c.StatusBar`): green blinking pulse dot + monospaced `SESSION: user@host` * `TARGETS: N` * `FILTER: All/...` (cyan when not All) * right-anchored `LOG: <auditPath>` in GoldDim. Updated by `Update-StatusStrip` on filter change / load / run completion.

## 2. Per-Tab Controls + Workflow

### Tab 1 -- Import & Findings
Header "FINDINGS" (gold) + hint "Click a row, then switch to Uninstall / Update / OS Findings." A **filter strip** (`$pnlFilter`, dark panel): `Hosts:` label + dropdown (`All`, `Workstations (MSEKL/MSEKW)`, `Non-Workstations (servers / other)`) + `Search:` label + free-text textbox (Cascadia Mono) + a cyan live count label ("Showing X of Y finding(s)  |  hosts: ...  |  search: '...'"). Below: **`$dgvFindings`** DataGridView (Fill, single full-row select), columns in order: **Plugin** (w6), **Category** (w12), **Plugin Name** (w50), **Severity** (w8), **Host Count** (w7), **Catalog Match** (w17). Colour-coding: Severity text Critical=red/High=amber/Medium=cyan/Low=dim; Category OS=amber, SEoLSoftware=red, else Accent purple; Catalog Match "OK (uninstall-only)"=green, "N/A (OS)"=dim, "No match"=amber. Update-class findings (catalog has an Updater) are HIDDEN here.

**Flow:** Load PDF/CSV (toolbar) -> `Import-UprFinding` parses -> `Refresh-FindingsGrid` + `Refresh-OsTab`. Operator filters/searches, clicks a finding row -> `SelectionChanged` -> `Refresh-UninstallTab` populates the selection banner on Tab 2. The Hosts dropdown mutates the global `$script:UprHostClassFilter`, re-clipping every tab.

### Tab 2 -- Uninstall (the core)
Header "BULK UNINSTALL" + hint "Pick a finding on the Findings tab. Then Scan, review candidates, Uninstall." A selection summary label `$lblU1Sel` shows `[plugin] name - N host(s) - Match: <regex> (version < X)` (green if catalog match, amber if none). Three buttons: **Scan Hosts** (purple Accent), **Uninstall Selected** (red Danger, disabled until candidates exist), **Export Results** (GoldDim, disabled until candidates exist). Then the **results grid** `$dgvU` (see section 3), and at the bottom a gold "ACTIVITY" header over the **`$rtbU` activity log** RichTextBox.

### Tab 3 -- OS Findings (read-only)
Header "UNSUPPORTED OPERATING SYSTEMS (read-only)" + "Out of scope for this tool. Hand the export to whoever runs OS rebuilds." Buttons **Export CSV** (GoldDim) and **Copy to Clipboard** (Accent). `$dgvOs` columns: Plugin, Finding, Severity, IP, NetBIOS, DNS, OS CPE, MAC -- one row per (OS finding x affected host), Severity colour-coded. `Refresh-OsTab` rebuilds from filtered OS-category findings.

### Tab 4 -- History
Header "SESSION HISTORY (last 200)" + dim "Audit log: <path>". Buttons **Clear Grid** (GoldDim) and **Export CSV** (Accent). `$dgvH` columns: When, Host, Action, Item, Result (Result colour-coded OK=green/Skipped=dim/else red). `Add-HistoryRow` appends every uninstall outcome and trims to 200 rows.

## 3. The Run Model + Activity View (preserve faithfully)

This is the heart of JANET Web. Two stages, both on the shared RunspacePool.

**Launch -- Scan (`Scan Hosts`/`$btnUScan`):** Guards in order: no finding -> MessageBox "No Finding"; OS finding -> no-op; no `$global:Credentials` -> `Get-Credential -Message "Enter ADW admin credentials"`. Resolves the catalog profile (`DisplayNameRegex`, `VersionMaxExclusive`), computes `Get-UprFilteredHosts`. If zero hosts -> amber WARN log and abort. Otherwise disables buttons, clears `$dgvU`, calls `Initialize-RunspacePool`, and for each valid target (`Get-FindingTargetFromHost` + `Test-UprValidTarget`) creates a `[PowerShell]` bound to `$global:RSPool` and `BeginInvoke()`s a scriptblock: TCP-probe port 5985 (3s), then `Invoke-Command -Authentication Negotiate -SessionOption $WSManOpt` reading the three Uninstall registry hives, returning candidate installs matching the regex/version gate. Logs `==== SCAN: [plugin] name ====`, regex/host counts, and `Dispatched N scan job(s) (concurrency 8)...`. Results are drained synchronously via `EndInvoke()` in a foreach loop, each host's row added live. Summary log: `Scan complete: N candidate(s) -- X one-click (proven EOL), Y review-only; Z unreachable host(s)`. Enables Uninstall/Export if any candidates.

**Launch -- Uninstall (`Uninstall Selected`/`$btnUDoIt`):** Collects checked rows; none -> MessageBox "Nothing to uninstall". Confirmation MessageBox (YesNo, Warning icon): `Uninstall N item(s) across M host(s)?\n\nDry-run: <bool>\nThis cannot be undone.` On Yes: log `==== UNINSTALL: ... (DryRun=<bool>) ====`, disable buttons, set each target row's Result to `Uninstalling...` (amber), `Initialize-RunspacePool`, `BeginInvoke()` a per-row worker scriptblock that (unless DryRun -> `Skipped (DryRun)`) `Invoke-Command`s the product-specific uninstall. `EndInvoke()` drains, writes each Result cell, tallies, mirrors to audit + History. Final log `==== DONE: X succeeded, Y failed, Z skipped ====`; re-enable buttons.

**No progress bar, no cancel/abort** in the original -- the EndInvoke drain blocks the UI thread. **JANET Web should keep the launch->confirm->per-host-stream semantics but make the drain async, adding a progress bar (done/total) and a cancel button** while preserving the live per-row Result transitions and the colour-coded streaming log.

**Activity view -- two surfaces:**
- **Results grid `$dgvU`** (Fill): columns in order **Sel** (checkbox, w4), **Host** (w18), **Display Name** (w28), **Version** (w9), **Type** (w6), **Publisher** (w14), **Result** (w21). Row semantics = one row per (host, matching install); hosts with no match still get a synthetic row. Row/cell states & colours: **Unreachable** -> Result "Unreachable" amber, row dimmed; **scan error** -> Result = error red; **(no matching install)** -> "NoCandidate" dim; **Tanium** -> checkbox off+ReadOnly, "Skipped (Tanium)" amber, row dimmed; **unproven match** -> checkbox off+ReadOnly, "Review (needs version/ACAS proof)" cyan; **proven EOL** -> checkbox PRE-CHECKED (only one-click-removable rows). During uninstall: `Uninstalling...` amber -> `OK (...)` green / `WARN (...)`/`FAIL...` red / `Skipped (DryRun)` dim. Selection highlight purple.
- **Activity log `$rtbU`** (read-only RichTextBox, Cascadia Mono 9, green console text on Panel bg, FixedSingle). Global `Log($msg,$lvl)` appends `[HH:mm:ss] msg` and colours by level: OK=green, WARN=amber, ERR=red, INFO=console green; auto-scrolls. `==== ... ====` banners delimit sections. (`$script:rtbLog` is the shared log sink -- in JANET Web this maps to an SSE/polling log pane.)

## 4. Targets, Credentials, Cross-Tab State

- **Targets** come from parsed findings: each finding has `Hosts[]` with DNSName/NetBIOSName/IPAddress/OSCpe/MAC. There is no manual host-list textbox; the report defines the host set. `Get-FindingTargetFromHost` picks the first VALID of DNS->NetBIOS->IP; `Test-UprValidTarget` rejects domain fragments / truncated NetBIOS.
- **Host-class filter** (`$script:UprHostClassFilter`, global, default `All`): MSEKL/MSEKW prefix => Workstation, else Other. `Get-UprFilteredHosts` routes EVERY enumeration (findings host count, scan set, OS grid, status TARGETS) through it, so "Workstations only" clips servers tool-wide, not just visually.
- **Credentials** (`$global:Credentials`): inherited from the JANET launcher via `$env:JANET_CRED_FILE` (DPAPI CliXml, `Import-Clixml`) if present; otherwise lazily prompted via `Get-Credential` on first Scan; cached for the session. WinRM uses `-Authentication Negotiate` + a pre-built `$global:WSManOpt` session option (60s op timeout).
- **Shared state**: `$global:UprDryRun` (Plan-only checkbox), `$global:UprThreads` (Threads NUD), `$global:UprFindings`, `$global:UprCatalog`, selected finding `$script:UprUninstallFinding`. The status strip and findings count reflect these globally.

## 5. Engine Functions / Scriptblocks (work entry points)

- `Import-UprFinding -Path` -- parse Tenable PDF (via resolved `pdftotext.exe`) or CSV into finding objects (Plugin, Category [OS/SEoLSoftware/...], PluginName, Severity, Hosts[]).
- `Load-Catalog` -- read `JanetLocal\UnsupportedProductCatalog.json` -> `Profiles[]` (Plugin, PluginNameMatch, DisplayNameRegex, VersionMaxExclusive, Updater, Proven) + `OperatingSystemPluginNames[]`.
- `Get-CatalogProfileForFinding -Finding` / `Test-IsOsFinding` -- match finding->profile.
- Proven-only gate (inlined in the scan worker) -- `'Uninstall'` only when catalog PROVES EOL, else `'Review'`.
- `Get-UprFilteredHosts` / `Get-UprHostClass` / `Get-UprTotalFilteredHosts` -- host-class filtering.
- `Initialize-RunspacePool` -- 1..UprThreads MTA pool for both stages.
- **Scan scriptblock** (per host) -- TCP 5985 probe + WinRM registry enumeration of the 3 Uninstall hives.
- **Uninstall scriptblock** (per row) -- WinRM uninstall: bespoke M365 ClickToRun (`setup.exe /configure` remove-all XML), Adobe Acrobat (RunAsPPL-aware service/process stop + MSI GUID sweep), generic Store/MSI (`msiexec /x {guid} /qn`) / EXE (QuietUninstallString or `/S /silent /quiet`); honours DryRun.
- `Log`, `Write-AuditLog` (mirrors to JANET `Write-JanetAction`), `Add-HistoryRow`, `Refresh-FindingsGrid/UninstallTab/OsTab`, `Update-StatusStrip`, `Start/Stop-JanetSession`.

## 6. UX Details + Visual Theme

**Preserve:** Plan-only default ON; proven-EOL pre-check vs. read-only Review/Tanium rows; the YesNo confirm restating scope + dry-run + "cannot be undone"; the `==== banner ====` log rhythm; per-row Result colour transitions; the blinking pulse dots; TARGETS/FILTER status counts; per-grid CSV export + OS clipboard copy with timestamped filenames; the guarded single-egress close.

**Theme (blood/purple JANET):** near-black surfaces (BG 8,8,12; Panel 16,16,22; StatusBar 7,7,11). Primary accent PURPLE `(140,100,220)`, secondary GOLD `(218,180,82)`. Status: Success green `(92,198,120)`, Warning amber `(230,180,70)`, Danger red `(224,80,90)`, Cyan `(88,180,210)`. Text White `(238,232,248)` / Sec `(188,180,208)` / Dim `(128,120,150)`. Fonts: titles/headers/tabs/logs **Cascadia Mono** (mono), body **Segoe UI**. Grids: gold bold headers (28px), alternating row bg, purple selection, no row headers, no user add/delete. Buttons are flat, colour-keyed by intent (Accent=primary/scan, Danger=destructive/close, GoldDim=secondary/export). For JANET Web map: purple buttons -> primary CTA, red -> destructive (with confirm), gold -> secondary; the RichTextBox log -> a streaming console pane; the DataGridViews -> themed HTML tables with the same column order, colour rules, and checkbox selection.