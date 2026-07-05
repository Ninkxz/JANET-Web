# JANET Web - UI Rebuild Spec: message

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The Remote Message Tool (J.A.N.E.T. Remote Messager v1.2 / file v1.3.3) is a single-window WinForms mass-popup-message dispatcher: it broadcasts a Title+Body to interactive user sessions on a list of Windows hosts over WinRM via msg.exe, with auto-dismiss or require-OK display modes. The UI is NOT tab-based -- it is a fixed three-column dashboard (Targets | Message Composer | Activity Log) sitting under a JANET-branded gold-on-black header and an ADW credential strip, with a footer credit/log-path bar. The whole point of the tool is the live "activity run" experience: clicking SEND fires one runspace-pool job per host (or sequential), and results stream back in real time into a colour-coded RichTextBox activity log, three big stat tiles (SENT / FAILED / TOTAL), and a progress bar, while the SEND button toggles into a red CANCEL button. There is no on-screen results grid (no DataGridView); per-host result rows are accumulated in memory and surfaced via three XLSX export buttons (Sent / Failed / All). A Ping All pre-flight tests reachability into the same log+stats surface. The theme is JANET's purple+gold-on-near-black with Cascadia/Consolas mono only in the data fields and log.

---

# Remote Message Tool -- UI/UX Rebuild Spec (tool id: `message`)

Source: `X:\J.A.N.E.T\Tools\RemoteMessageTool_1.3.3.ps1`. Window title `J.A.N.E.T. Remote Message Tool v1.2`; header tagline `v1.2 | Mass Messenger`. This is a **single-window, three-column dashboard** -- there are no tabs and no DataGridView. The operator works left-to-right (pick targets -> compose -> send) while results stream into the right column. Re-create the *look and the live run experience* exactly; the engine is re-forked separately.

## 1. Window + Navigation Layout

Fixed `Form`: 1400x1000, `MinimumSize` 1300x900, `CenterScreen`, BackColor near-black `#08080C`. Vertical band stack (top->bottom), all anchored to stretch horizontally:

1. **Header band** (y0, h70, `#06060A`): gold 15pt bold title `J.A.N.E.T. Remote Messager`; grey 9pt italic subtitle `Joint Administration and Network Execution Toolkit`; tiny gold-dim `v1.2  |  Mass Messenger`. Top-right red **Close Tool** button (110x28, anchored Top,Right). A **2px gold accent line** sits directly under the header (y70).
2. **Credential strip** (y74, h44, panel `#101016`): tiny gold-dim label `ADW CREDENTIALS`; purple **Set Credentials...** button (140x20); a bold status label (green when set, red when not).
3. **Main content panel** (y124 -> bottom-28, anchored all sides) containing the three columns.
4. **Footer** (bottom, h44, `#101018`): gold-dim credit `Created by: THOMPSON, BRAXTON - 48 CS`; dim `Log: <path>`.

The three columns inside main (each a `Panel` BackColor `#101016`, anchored Top,Left,Bottom so they grow vertically):
- **Left -- TARGET MACHINES** (x10, width 340).
- **Middle -- MESSAGE COMPOSER** (x360, width 500).
- **Right -- ACTIVITY LOG** (x870 -> fill, anchored Top,Left,Right,Bottom).

Each column has a gold 11pt-semibold section header (`TARGET MACHINES` / `MESSAGE COMPOSER` / `ACTIVITY LOG`).

## 2. Per-Tab (Per-Column) Controls + Workflow

### Left column -- TARGET MACHINES
- Hint label `Hostnames, comma or newline separated`.
- Large multiline **targets TextBox** (`$txtTargets`, vertical scroll, Cascadia/Consolas mono, dark input bg, anchored to fill the panel).
- Bottom row buttons: **Import TXT** (panel-light), **Clear** (red), **Ping All** (cyan), and a live **count label** `N target(s)` (green when >0, grey when 0).
- **Import TXT** -> OpenFileDialog (`*.txt;*.csv;*.*`), appends non-blank lines, logs `Imported N host(s) from <file>`.
- `Get-Targets` parses the box on `[,CRLF]+`, trims, **case-insensitive dedup** (so `PC01`/`pc01` collapse). `TextChanged` recomputes the count live.

Workflow: paste or import hostnames -> optionally **Ping All** to pre-test reachability -> proceed to compose.

### Middle column -- MESSAGE COMPOSER
- **Title** TextBox `$txtTitle`, pre-filled `Message from the 48 Communications Squadron` (mono).
- **Body** label with a right-aligned dim **char counter** `N chars` (updates on TextChanged); large multiline **Body** TextBox `$txtBody` (vertical scroll, mono).
- **DISPLAY OPTIONS** (gold-dim caption):
  - Cyan checkbox **`Require user to click OK (popup stays until dismissed)`** -- when checked, disables the timeout field and dims its label; sends `msg.exe /TIME:99999`.
  - Hint `When unchecked, message auto-dismisses after timeout below.`
  - **Auto-dismiss timeout (seconds)** label + `NumericUpDown` (min 5, max 3600, default 60).
  - Checkbox **`Send in parallel (faster for large target lists)`**, checked by default.
- **SEND MESSAGE TO TARGETS** -- large (476x50) primary button, gold bg / black text, Segoe UI 11pt bold, anchored Bottom. Toggles to a red **CANCEL SEND IN PROGRESS** while running (`Set-SendButtonMode`).

Workflow: type Title/Body -> choose display mode + parallel -> click SEND.

### Right column -- ACTIVITY LOG (the run surface; see 3).

## 3. The Run Model + Activity View (most important)

### Launch points
- **Ping All** (left). Validates targets exist (`No Targets` MessageBox otherwise), disables itself (`Pinging...`), `Reset-Stats`, sets `Total`, then loops hosts **sequentially on the UI thread** with `Test-Connection -Count 1 -Quiet`, calling `Application::DoEvents()` per host so the log paints live. Each host logs `[host] ONLINE` (green) or `[host] OFFLINE / not pingable` (red) and records a result row with Delivered/Undelivered = `N/A`. Ends with gold `=== Ping complete: N online, M offline ===`; enables only **All XLSX**.
- **SEND** (middle). Preflight MessageBoxes if: no targets (`No Targets`), no credentials (`No Credentials`), empty body (`No Message`); empty title auto-fills the default. Then a **Yes/No confirm** `Confirm Mass Send` showing the target count, mode string (`REQUIRE OK CLICK` or `Auto-dismiss after Ns`), title, and `First few targets:` (first 5). On **Yes**: `Reset-Stats`, set `Total`, stash `LastSendMeta`, log a gold `=== Sending message to N target(s) ===` banner + cyan mode + grey title/timeout lines.

### Parallel path (default)
`Set-SendButtonMode Cancel` (button turns red), `Init-RunspacePool` (1-16 threads). For each host build a `[powershell]::Create()` bound to the pool, `AddScript($SendScriptBlock)` + args (host, cred, title, body, timeout, requireOK, openMs=20000, opMs=45000), `BeginInvoke()`, track in `$global:ActiveJobs[host]=@{PS,Handle,StartTime}`. Log accent `Dispatched N parallel job(s)`.

A **500ms `System.Windows.Forms.Timer`** polls every tick:
- **Per-job 90s wall-clock timeout** -> Stop+Dispose, log red `[host] TIMEOUT after Ns - aborting`, record Failed.
- **Cancel** (CancelRequested + job Stopping/Stopped) -> Dispose, log amber `[host] CANCELLED`, record `Cancelled by user`.
- **Completed** -> `EndInvoke`; on Success log green `[host] Delivered to K session(s)` + record Sent; on failure log red `[host] FAILED: <reason>` + a dim `  diag: <diagnostic>` line + record Failed.
- Each tick: `Update-Stats`. When `ActiveJobs` empties: stop/dispose timer, log gold `=== Send complete [(CANCELLED)] : X sent, Y failed ===`, revert button to SEND, `Enable-ExportButtons`, log `Results ready: use Export buttons to save XLSX`.

Clicking the (now red) button mid-run sets `CancelRequested=$true`, logs amber `CANCEL requested - stopping in-flight jobs...`, disables the button, and `.Stop()`s every active PS.

### Sequential path (parallel unchecked)
Button Disabled; loop hosts inline invoking `$SendScriptBlock` directly with `DoEvents()` between hosts (live log, no mid-run cancel). Same logging/recording; ends identically.

### Activity view composition (right column, top->bottom)
- **Stats strip** (`#1E1C28`): three big tiles side-by-side -- **SENT** (green 14pt bold + tiny caption), **FAILED** (red), **TOTAL** (purple) -- and a stretching **ProgressBar** (0-100). `Update-Stats` writes counts and sets progress = `floor((Sent+Failed)/Total*100)`.
- **EXPORT RESULTS** row: `Sent XLSX`, `Failed XLSX`, `All XLSX` (disabled until rows exist).
- **Activity log** `RichTextBox` (read-only, OutputBg `#06060A`, default purple text, mono, borderless): `Log-Activity` prefixes a dim grey `[HH:mm:ss]` then the message in a **semantic colour** (gold banner / cyan mode / green delivered / red failed / dim diag / amber cancelled / accent dispatch). Auto-scrolls. Right-click menu: **Clear** (amber), **Copy All** (accent).
- **Log toolbar**: Clear Log, Copy All, Save Log... (SaveFileDialog -> UTF8 `.log`, default `JRMT_ActivityLog_<ts>.log`).

**There is no on-screen grid.** Per-host rows live in `$script:SendResults` (ArrayList) and become the XLSX. For JANET Web, preserve the streaming colour log + climbing tiles + progress + send->cancel toggle; an on-screen results table mirroring the XLSX columns with green/red row tinting is an acceptable enhancement but the log is canonical.

## 4. Targets / Credentials / Shared State
- **Targets** are a single free-text box (paste/import), parsed/deduped by `Get-Targets`; the live count drives the green/grey label.
- **Credentials**: `$global:Cred` (PSCredential). Inherited at startup from the JANET launcher via `$env:JANET_CRED_FILE` (DPAPI-encrypted CliXml, same-user/same-machine only) -- status shows `Active: <user> (inherited from launcher)` in green. **Set Credentials...** runs `Get-Credential` and overrides, status -> `Active: <user> (ADM)`. SEND blocks with `No Credentials` if unset.
- **Shared/run state** (`$script:` / `$global:`): `SendStats{Sent,Failed,Total}`, `SendResults` (the export rows), `LastSendMeta{Title,Mode,Timestamp}`, `CancelRequested`, `ActiveJobs`, `RunspacePool`, tunables `MaxJobSeconds=90`, `PSOpenTimeoutMs=20000`, `PSOpTimeoutMs=45000`. `Reset-Stats` clears all and disables exports at the start of every Ping/Send.

## 5. Engine Functions / Scriptblocks the UI Calls
- **`$script:SendScriptBlock`** (per-host work entry): params `hostname,cred,msgTitle,msgBody,timeout,requireOK,openMs,opMs`. Pings; opens `New-PSSession` with explicit Open/Operation/Cancel timeouts; `Invoke-Command` detects interactive sessions (explorer.exe SessionIds 1-999, `qwinsta` fallback) then broadcasts the combined `"Title`r`n`r`nBody"` via `msg.exe * /TIME:<99999|timeout>`, with a **per-session `msg.exe <sid>` fallback**; returns `@{Host,Success,Sessions,Pingable,Error,Detail,Diagnostic}`. Re-fork to return this same shape.
- **`Init-RunspacePool`** (1-16 threads), **`Get-Targets`**, **`Add-SendResult`** (appends the 10-col row + JANET `Write-JanetAction -Action TouchHost`), **`Update-Stats`/`Reset-Stats`**, **`Enable-ExportButtons`**, **`Export-Results`/`Export-ToXlsx`** (pure-.NET XLSX, no Excel dependency), **`Set-SendButtonMode`**, **`Log-Activity`**.
- **JANET session hooks**: `Start-JanetSession -Tool 'Remote_Message'` at startup; `Stop-JanetSession -ShowDialog` on close (closing-notes/ASI capture); `Write-JanetAction` per host (metric-only `TouchHost` two-bucket model).

### XLSX / result-row schema (the "results grid")
`Timestamp, Hostname, Pingable(Yes/No/N/A), Delivered(Yes/No/N/A), Undelivered, Sessions, MessageTitle, Mode, Reason, Diagnostic`. Row semantics: **Sent** = Delivered Yes; **Failed** = Undelivered Yes; **Ping-only** = both N/A. Exports: `JRMT_Delivered_<ts>.xlsx` (Sent), `JRMT_Failed_<ts>.xlsx`, `JRMT_AllResults_<ts>.xlsx`.

## 6. UX Details + Theme
- **Theme**: purple+gold on near-black. Bg `#08080C`, panels `#101016`, panel-light `#1E1C28`, input `#16161E`, output `#06060A`. Accent/purple `#8C64DC`, gold `#DAB452`/dim `#9B7D34`, success green `#5CC678`, danger red `#E0505A`, warning/orange amber `#E6B446`, cyan `#58B4D2`, console-purple `#A480F0`, text `#F0F0F5`/dim `#AAA8B4`/muted `#6E6A7D`.
- **Fonts**: Segoe UI / Segoe UI Semibold for chrome; **Cascadia Mono,Consolas** only in targets box, title, body, and activity log.
- **Buttons** (`New-StyledButton`): flat, borderless, hand cursor, auto-contrast foreground (luminance test), +30 RGB hover.
- **UX to preserve**: live char counter; live target counter with colour; require-OK checkbox disabling the timeout field; the gold->red SEND/CANCEL toggle; confirm dialog previewing first 5 targets; dim `diag:` follow-up lines under failures; export buttons that light only when matching rows exist; **locked egress** -- only the header **Close Tool** sets the allow-close flag, while the FormClosing guard cancels X/Alt-F4/title-bar close (except OS shutdown) and fires the JANET closing-notes dialog; footer shows the active log path.