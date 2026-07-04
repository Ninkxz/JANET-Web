# JANET TWO - UI Rebuild Spec: restart

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

Remote Restart Scheduler is a single-window, dark-themed WinForms admin tool for staggered/mass remote workstation reboots across a fleet, with optional pre-restart user warnings and an Accept/Decline consent prompt. The window is a fixed 1400x1000 (min 1280x880) form with a gold-on-near-black header (title + subtitle + a globally-visible red "Close Tool" button + a top-right credentials strip), a 9-cell live stats bar row beneath it (Total / Pending / Awaiting / In-Flight / Sent / Declined / Failed / Aborted / Skipped), and a 3-tab TabControl filling the rest: Targets, Schedule, Run / Results. The operator pastes/imports hostnames + an exception list on Targets, sets restart time / lead-minutes / concurrency / consent / burst-vs-time-gated / rolling / server-skip / dry-run on Schedule and clicks Compute Schedule, then on Run/Results clicks Start Dispatch to launch a RunspacePool fan-out of `Invoke-Command { shutdown /r /t ... }`. The whole point of the tool is the live activity run: a colour-coded per-host results DataGridView whose rows recolour as each host transitions Pending -> In-Flight -> Dispatched/Failed/Declined/Aborted, a timestamped colour-coded activity log RichTextBox docked at the bottom, live Now/Next + Elapsed/ETA status lines, the live stats counters, and Cancel Pending / Abort Already-Dispatched controls, plus an auto-opening Reboot Verification Monitor that pings each host to confirm it actually went down and came back.

---

# Remote Restart Scheduler -- UI/UX Rebuild Spec (tool id: `restart`)

Source: `X:\J.A.N.E.T\Tools\RemoteRestartScheduler_1.6.0.ps1`. This spec describes the **frontend the operator sees and the live run experience**. Engine logic (the actual WinRM dispatch) is re-forked separately; the named functions below are the work entry points the UI calls.

## 1. Window + Navigation Layout

A single top-level `Form`: title `"J.A.N.E.T. Remote Restart Scheduler v<ver>"`, size **1400x1000**, minimum **1280x880**, centred, dark background (`#08080C`), Segoe UI. Dark title bar via DwmSetWindowAttribute. The chrome **X is blocked** while work is active (FormClosing guard); the only sanctioned exit is a red **Close Tool** button.

Vertical stack (top to bottom):

1. **Header** (Dock=Top, height 64, `#06060A`): red **Close Tool** button at top-left (112x36); gold title `J.A.N.E.T. Remote Restart Scheduler` (Segoe UI 15 Bold); grey italic subtitle "Staggered mass restart with pre-restart user warnings..."; and a **credentials strip** anchored top-right -- `Set Credentials...` (purple) + `Clear` (grey) buttons over a status label that reads green `as: USER` / green `USER (inherited from J.A.N.E.T.)` / cyan `current Windows session (CAC)`.
2. **Stats bar** (Dock=Top, height 56, `#07070B`): a right-anchored inner panel of **nine stat cards** (each 110px: small dim caption + large value, Segoe UI Semibold 14): **Total, Pending, Awaiting** (cyan), **In-Flight** (cyan), **Sent** (green), **Declined** (amber), **Failed** (red), **Aborted** (amber), **Skipped** (dim grey). Updated every tick via `Refresh-StatsLabels`; buckets always sum to Total.
3. **TabControl** (Dock=Fill) with three tabs in order: **`  Targets  `**, **`  Schedule  `**, **`  Run / Results  `**.

The intended workflow is strictly left-to-right: Targets -> Schedule -> (Compute) -> Start Dispatch on Run/Results. A startup log line states it: "Workflow: Targets -> Schedule -> Compute -> Start Dispatch".

## 2. Per-Tab Controls + Workflow

### Tab 1 -- Targets
Layout: a **210px right rail** + a **Fill center** split vertically by a `SplitContainer` (~60/40).

- **Center, left panel ("Target machines", gold heading):** hint "Paste hostnames (one per line, or comma/space/tab separated). Case-insensitive dedup."; a large multiline monospaced TextBox (`MaxLength=0` so huge fleet pastes aren't truncated, dark input bg).
- **Center, right panel ("Exception list (never restart)", red heading):** hint "Filtered out of any plan. Persists between launches."; a red-text multiline TextBox.
- **Right rail buttons (top to bottom):** `Import targets CSV...` (purple), `Clear targets` (grey), `Import exceptions CSV...` (dim purple), `Clear exceptions` (grey, YesNo confirm), **`Apply`** (green, 188x40), `Test single host...` (gold), `Split targets -> N CSVs...` (dim purple). Below: cyan **"N unique target(s)"** and red **"N in exception list"** counters, then an explanatory help paragraph.

Flow: paste/import hostnames + exceptions -> **Apply** (`Apply-Targets`: dedup, filter exceptions, persist exceptions to disk, refresh counts) -> move to Schedule. `Test single host...` runs one synchronous `shutdown.exe`/`Invoke-ShutdownDirect` and shows the exit code; `Split targets` writes N balanced CSVs to run on N dispatcher boxes.

### Tab 2 -- Schedule
A vertical form of labelled fields (label at x=20, control at x=250):

- **Restart time (all machines)** -- DateTimePicker, custom `yyyy-MM-dd  HH:mm`, spin (ShowUpDown). All machines share one restart time.
- **Pre-restart warning (minutes)** -- NumericUpDown 1-60, default 15.
- **Dispatch concurrency (threads)** -- NumericUpDown 1-256, default 96.
- **Burst mode** checkbox (gold, default ON) + two hint lines: ON = fire all commands ASAP, each host gets its own countdown so stagger is preserved; OFF = one command per tick, exactly LeadMinutes before each restart.
- **Dry run** checkbox (amber) -- logs commands only, contacts no hosts. **Skip unreachable (pre-flight ping)** checkbox (cyan, default ON) on the same row.
- **Skip servers** checkbox (gold, default ON) + editable **regex pattern** textbox + hint (default matches server name prefixes, keeps workstation prefixes).
- **Require user consent** checkbox (gold, default ON) + **Prompt window (min)** (1-60, def 5) + **Accept grace (sec)** (10-3600, def 60) + hint: a one-time task shows an Accept/Decline dialog in the user's session; no response or no user -> proceed; Decline -> skip.
- **Rolling / go-fast** checkbox (cyan, default OFF) + **Restart grace after approve (sec)** + hint: reboot each host ~grace sec after IT approves rather than converging on the scheduled time.
- **Begin at the scheduled time** checkbox (OFF) -- leave tool open; auto-starts the wave at the time above.
- **Warning message ({LEAD} -> minutes)** -- multiline TextBox with a default mandatory-maintenance message.
- **Buttons:** **`Compute Schedule`** (purple), `Save Plan CSV...` (grey), `Schedule as Windows Task...` (gold). Then a gold **plan summary** label and a **plan preview DataGridView** (Host / Dispatch at / Restart at / Status / Result).

Flow: set parameters -> **Compute Schedule** (`Build-Plan`) -> summary "N machines | ALL restart at ... | Dispatch begins ... | M-min warning per host", grids populate, stats reset (Total=Pending=N). `Schedule as Windows Task...` arms a one-shot task (YesNo confirm; rejects CAC identities for unattended runs).

### Tab 3 -- Run / Results
See sections 3 below -- this is the activity view.

## 3. THE RUN MODEL + ACTIVITY VIEW (the core)

### Launch
The green **Start Dispatch** toolbar button (`btnStart`). On click:
- If a "Begin at the scheduled time" countdown is armed and future -> the button becomes a live **`Starts in HH:MM:SS`** countdown and auto-`PerformClick()`s at zero (re-reads the picker each tick so the operator can push it earlier/later).
- If no plan exists -> **auto-computes** one from current Targets + Schedule settings (no "compute first" popup). If no targets: MessageBox warning "No targets applied...".
- Captures consent/rolling/burst/concurrency **once at arm time** (mid-run toggles can't change in-flight policy).
- `Init-RunspacePool` (1..MaxConcurrency), runs **Server-Skip gate** (`Apply-ServerSkipGate`, instant regex name match -> Skipped-Server) then **pre-flight ping gate** (`Invoke-PreflightPingGate`, parallel ICMP -> Unreachable) -- both before any WinRM, and both feed their own stat buckets.
- Logs "Dispatch armed. N machines, concurrency ..., burst ..., dry-run ..., consent ..., transport ..." and starts the **tick timer** (250 ms in burst/rolling, 1000 ms time-gated).

### Streaming
`Tick-Dispatch` runs every tick:
1. `Reap-CompletedJobs` -- `EndInvoke`s any finished async job, sets that row's **Status + Result**, bumps the **Stats** counter, and writes a per-host **activity-log line**.
2. For each `Pending` row, up to the concurrency cap, submits a job: **direct path** (`Submit-DispatchJob`) = `Invoke-Command -ComputerName HOST [-Credential] -Authentication Negotiate { shutdown /r /t <leadSeconds> /c <msg> /f }`. `leadSeconds`: burst = seconds-until-this-host's-RestartAt (floored 60); time-gated = leadx60 only once `DispatchAt<=Now`; rolling = grace. **Consent path** (`Submit-ConsentJob`): launch on-target Accept/Decline agent (`Consent-Launching`->`Awaiting-Consent`), poll its result file (`Consent-Polling`), then on Accepted/Timeout/No-User (`Consent-Approved`) fire the same dispatch; Declined -> skip.
3. Updates Now/Next + Elapsed/ETA labels, recolours grid rows (`Tint-RunRows`), refreshes stats and progress.

Row status lifecycle: `Pending -> In-Flight -> Dispatched | Already-Scheduled(rc=1190) | Failed | Unreachable | Skipped-Server`; consent adds `Consent-Launching/Awaiting-Consent/Consent-Polling/Consent-Approved/Declined`; abort adds `Aborted/Abort Failed`; cancel adds `Cancelled`.

**Auto-stop:** when `ActiveJobs` is empty and every row is terminal -- DispatchActive=false, re-enable Start, log "Dispatch complete in <dur>. Sent=... Declined=... Failed=... Aborted=... Skipped=...", freeze the timer. On a real run it auto-opens the Reboot Verification Monitor; in auto-mode it self-deletes the scheduled task and closes.

### Confirmations
Start has **no** confirm. MessageBox warnings guard missing targets/plan. **Abort Already-Dispatched** -> YesNo "Send `shutdown /a` to N machines?". Schedule-as-Task -> YesNo. Closing mid-dispatch -> "A dispatch is in progress... Force close anyway?".

### Cancel / Abort
- **Cancel Pending** (amber): marks all not-yet-dispatched rows `Cancelled` (in-flight commands keep running on targets), recomputes Pending/Awaiting, logs in amber. Re-clicking Start later revives Cancelled rows to Pending.
- **Abort Already-Dispatched** (red): `Send-RemoteAbortFanOut` issues `shutdown /m \\HOST /a` to every Dispatched/Already-Scheduled row.

### The activity surface (Run/Results tab)
- **Top toolbar** (`FlowLayoutPanel`, auto-size, wraps): Start Dispatch (green) | Cancel Pending (amber, disabled until running) | Abort Already-Dispatched (red, disabled until dispatched) | Verify Reboots (cyan) | Export Results CSV... (grey) | Close Tool (grey). Plus a **Now/Next** two-line panel (gold "Now: yyyy-MM-dd HH:mm:ss" over grey "Next: HOST at TIME (in ...)" / "Queue: N pending | in-flight M | burst mode" / "Awaiting user consent: N host(s)") and a **progress** two-line panel (cyan "Elapsed HH:MM:SS | Done x/y (z%)" over grey "ETA HH:MM:SS | finish ~HH:MM", flipping to "Completed in ... (100%)" / "Finished at ..." on done). **No ProgressBar control** -- progress is numeric via these labels + stats + grid fill.
- **Results grid** (`gridRun`, Dock=Fill, read-only, FullRowSelect, no row headers, Fill columns): **Host | Dispatch at | Restart at | Status | Result**. One row per host. `Tint-RunRows` recolours the **Status cell foreground** each tick: Dispatched=green; Already-Scheduled/Aborted/Declined=amber; Failed/Abort-Failed/Unreachable=red; In-Flight/Consent-Launching/Awaiting-Consent/Consent-Polling=cyan; Consent-Approved=gold; Skipped-Server=dim grey. **Result** holds the detail (`OK (rc=0)`, `Already scheduled (rc=1190)`, `rc=... <hint>`, `Declined by DOMAIN\user`, `Prompt shown to ...`, `No response within window - proceeding`, `Cancelled before restart`).
- **Activity log** (`oLog`, Dock=Bottom, 240px, read-only RichTextBox, near-black bg, monospaced, purple text): one **timestamped colour-coded line per event** -- dim-grey `[HH:mm:ss] ` prefix then a coloured tag/message (`SENT`, `ALREADY`, `FAIL`, `DECLINED`, `ACCEPTED`, `TIMEOUT`, `NO-USER`, `PROMPT`, `ABORT OK`, `ABORT FAIL`, etc.), auto-scrolls; right-click = **Clear / Copy All**. `Log-Activity` writes here and mirrors to the on-disk log.

### Reboot Verification Monitor (auto-opens on real runs)
A separate **modeless** dialog so the Run tab stays usable. Header summary line + a DataGridView **Host | State | Went down | Came back | Last ping** (sorting disabled to keep rows pinned). It pings each host on an interval and recolours **State** in plain language: `RESTARTED - confirmed/went down and came back` (green), `Back online (likely restarted)` (gold), `Offline - restarting now` (cyan), `Restart sent - waiting for it to go down` / `Online - restart not sent yet` (amber), `No reply to any ping` (red). Toolbar: `Ping now` (purple) | `Verify (WinRM)` (gold, boot-time check) | `Export CSV...` (grey) | `Stop` (amber) | `Close` (grey) + a "Ping every (s)" NumericUpDown. Functions: `Invoke-RebootMonitorTick`, `Get-RebootStateDisplay`, `Update-RebootMonitorGrid`, `Start-RebootVerifyPass`, `Complete-RebootMonitor`.

## 4. Targets / Credentials / Shared State
- **Targets**: free paste + CSV import, parsed by `ConvertTo-HostList` (split on newline/comma/space/tab, case-insensitive dedup). **Exception list** is filtered out of every plan and **persisted to disk** between launches. `$script:Targets` / `$script:Exceptions` / `$script:Plan` / `$script:Stats` are shared across tabs.
- **Credentials**: header strip. `Set Credentials...` -> `Get-Credential` (offers Smart Card / CAC). `Clear` wipes in-memory **and** the launcher cred file. On startup, `Import-RrsJanetCredential` inherits `$env:JANET_CRED_FILE`. When a cred is set -> `Invoke-Command -Credential` (WinRM); when none -> current-session Kerberos (fine on CAC-bound admin boxes). `Refresh-CredStatus` drives the label/button text.
- **Plan rows** are shared objects mutated in place; the same plan backs both the Schedule preview grid and the Run grid (`Render-PlanGrids`).

## 5. Engine Functions the UI Calls
`Build-Plan`, `Apply-Targets`, `ConvertTo-HostList`, `Load-TargetsFromCsv`/`Save-PlanCsv`, `Split-TargetsToCsv`, `Apply-ServerSkipGate`, `Invoke-PreflightPingGate`, `Init-RunspacePool`, `Submit-DispatchJob`, `Submit-ConsentJob`, `Reap-CompletedJobs`, `Tick-Dispatch`, `Invoke-ShutdownDirect`, `Send-RemoteAbortFanOut`, `Get-ShutdownErrorHint`, `Get-EffectiveMessage`, the reboot-monitor set, the schedule-as-task set (`Invoke-RrsScheduleAsTask`/`New-RrsTaskXml`/`Register-RrsScheduledTask`/`Start-RrsAutoDispatch`), and the UI-refresh set (`Refresh-StatsLabels`, `Tint-RunRows`, `Update-ProgressLabels`, `Log-Activity`). For the web rebuild, each maps to a server endpoint; `Tick-Dispatch`/`Reap-CompletedJobs` map to a polling/SSE stream of per-host result objects `{Host, Status, Result, RestartAt, DispatchAt}` plus a stats snapshot and an append-only colour-tagged log stream.

## 6. UX Details + Theme
**Preserve:** the nine-cell live stats bar; the per-host colour-coded results grid with Status recolouring; the timestamped colour-coded auto-scrolling activity log with Clear/Copy-All; Now/Next + Elapsed/ETA numeric progress (no bar); Cancel-vs-Abort distinction; auto-open Reboot Monitor; the close-guard while running; dry-run safety; exception-list persistence; consent prompt flow; auto-compute on Start.

**Theme (`$colors`):** near-black backgrounds (`#08080C`/`#07070B`/`#06060A`), panels `#101016`/`#1E1C28`, inputs `#16161E`. Accents: **Gold `#DAB452`** (headings/active), **Success green `#5CC678`**, **Warning amber `#E6B446`**, **Danger red `#E0505A`**, **Cyan `#58B4D2`** (in-progress/info), **Accent purple `#8C64DC`**, console text purple `#A480F0`. Text: primary `#F0F0F5`, secondary `#AAA8B4`, dim `#6E6A7D`. **Fonts:** Segoe UI / Segoe UI Semibold for chrome (title 15 Bold, stat 14, section 11), Cascadia Mono->Consolas for the textboxes/grids/log. Buttons are flat, borderless, hover-lighten, with foreground auto-picked black/white by background luminance.