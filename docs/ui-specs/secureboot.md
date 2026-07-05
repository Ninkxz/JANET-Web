# JANET Web - UI Rebuild Spec: secureboot

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

Secure Boot Enabler is a single-window (non-tabbed) J.A.N.E.T. WinForms tool for remotely enabling UEFI Secure Boot on up to 50 Dell/HP/Lenovo machines at once. The 1200x760 dark "purple + gold on black" window is laid out as a fixed three-zone frame (top bar / status strip / body) with the body split into a tall left "Targets" card (one hostname per line, live count) and a right column of stacked cards: "Settings" (BIOS password + Show toggle, parallel-jobs spinner, Dry Run checkbox), an action bar (run-state pulse, status line, Export CSV / Clear / the big striped "Enable Secure Boot" CTA), and a "Results" DataGridView with a custom flat progress track beneath it. The whole point of the tool is the live activity run: clicking Enable validates input, seeds one Pending grid row per host, then a 800 ms System.Windows.Forms.Timer drives a Start-Job queue (concurrency = parallel-jobs value), flips rows Pending -> Running -> a terminal status, color-codes each row by status, advances the progress bar, and updates a "Running/Queued/Done" status line until a completion MessageBox summarizes success/skipped/error counts. Each live job drops a password-bearing payload .ps1 onto the target's C$ admin share, runs it as SYSTEM via a one-shot scheduled task over a DCOM CIM session, and polls a result JSON. Credential is inherited from the JANET launcher; per-host results feed JANET centralized logging.

---

# Secure Boot Enabler -- UI/UX Rebuild Spec (tool id: `secureboot`)

This is a **single-window, non-tabbed** J.A.N.E.T. WinForms tool. It enables UEFI Secure Boot remotely on up to 50 Dell/HP/Lenovo machines in one batched, live run. The frontend's whole value is the **live activity run** (per-host result rows streaming in, color-coded, with a progress track and status line). Rebuild that faithfully.

## 1. Window + Navigation Layout

**Main window** (`$form`): size `1200 x 760`, `MinimumSize 1200 x 680`, `CenterScreen`. Title is `"J.A.N.E.T // Secure Boot"`, or `"J.A.N.E.T // Secure Boot  -  running as <user>"` when a credential was inherited. Dark immersive Win11 title bar + rounded corners via `DwmSetWindowAttribute`. Background near-black `RGB(8,8,12)`. Shown modally via `ShowDialog`.

There are **no tabs**. The window is a fixed three-zone Dock frame, with the body subdivided into "cards." In order:

1. **Top bar** (`Dock=Top`, height 72, `RGB(6,6,10)`, 1px purple accent underline). Left: title label (13pt bold mono) + eyebrow "Remote BIOS config for Dell, HP, Lenovo" (dim). Right, anchored Top,Right (laid out by a `Add_Layout` handler): a **pulsing status dot** (green=idle/ready, red=alert on error), a ghost **"Changelog"** button, and a danger-colored ghost **"Close Tool"** button.
2. **Body** (`Dock=Fill`, padding 14,12,14,8, no scroll -- layout is tuned to fit). Holds four cards (below).
3. **Status strip** (`Dock=Bottom`, height 50, `RGB(7,7,11)`, 1px top border). Three mono captions: `user: <username>`, `targets: <N>` (live), and `creds: <name> (inherited)` or `creds: caller token`.

### Body cards
- **Targets card** -- left column, `X=14 Y=12 W=320 H=576`, anchored `Top,Left,Bottom`, accent = Info (teal).
- **Settings card** -- right column top, `X=344 Y=12 W=822 H=178`, anchored `Top,Left,Right`, accent = purple.
- **Action bar card** -- `X=344 Y=202 W=822 H=60`, anchored `Top,Left,Right`, accent = purple.
- **Results card** -- `X=344 Y=268 W=822 H=320`, anchored `Top,Left,Right,Bottom`, accent = purple.

A "card" = a `Surface` panel `RGB(16,16,22)` with **4 L-shaped corner brackets** painted in its accent color, a `/ HEADER` eyebrow label (9pt bold mono caps) at top-left, and a dotted accent underline at y=38.

## 2. Per-tab (per-card) Controls + Workflow

### Targets card
- Caption "One hostname per line - up to 50."
- Multiline textbox `$txtMachines` (vertical scroll, mono font, dark `SurfaceAlt` bg). Anchored to fill the card.
- Live count label `"N / 50"` (turns red `> 50`); a `TextChanged` handler also updates the status strip `targets: N`.
- Ghost **"Clear"** button (danger color, bottom-right) empties the list.

### Settings card (three rows)
- **Row 1 -- BIOS password:** eyebrow "BIOS password", password textbox `$txtPass` (`UseSystemPasswordChar`), a **"Show"** checkbox toggling masking, and a faint note "Leave blank if none is set."
- **Row 2 -- Parallel jobs:** eyebrow "Parallel jobs", a `NumericUpDown` `$numJobs` (Min 1, Max 10, default 5), note "Concurrent machines (1 - 10)."
- **Row 3 -- Dry Run:** a warning-colored checkbox `$chkDry`: "Dry Run - connectivity + manufacturer detection only. No BIOS write."

### Action bar card
- Left: a run-state **pulse dot** `$pulseMission` + a status label `$lblStatus` ("Ready" initially).
- Right cluster (anchored Top,Right, positioned by `Add_Layout` with 18px margin, in this visual order left-to-right): ghost **"Export CSV"**, ghost **"Clear"** (danger), and the **primary striped CTA "Enable Secure Boot"** (`W=240 H=44`, purple with a diagonal hatch stripe across the bottom 4px).

### Results card
- A read-only `DataGridView` `$dgv` (see 3) + a custom 3px progress track `$progress` flush beneath it.

**Operator flow:** paste hostnames -> set/leave BIOS password -> choose parallel count -> optionally tick Dry Run -> click **Enable Secure Boot** -> watch rows stream in -> read the summary MessageBox -> optionally **Export CSV** -> **Clear** to reset.

## 3. THE RUN MODEL + ACTIVITY VIEW (most important -- preserve exactly)

### Launch + confirmations
The **only** launch button is the striped **"Enable Secure Boot"** CTA. On click (`$btnRun.Add_Click`):
1. Read textbox lines -> trim -> uppercase -> unique.
2. Validation gauntlet, each a blocking `MessageBox` that aborts with no work started:
   - 0 hosts -> "Input Required" warning.
   - `> 50` hosts -> "Limit Exceeded" (tells operator how many to remove).
   - Any host failing `^[A-Za-z0-9._-]+$` -> "Invalid Target Name."
   - (live only) password containing `, ' " `` ` `` -> "Unsupported Password Character."
   - (live only) empty password -> Yes/No "No Password" confirm ("Works only if the BIOS has no password set.").
3. Snapshot `$script:RunIsDry = $chkDry.Checked` (so a mid-run toggle can't mix live+dry). Clear grid; reset `$script:Jobs={}`, `$script:JobTasks={}`, `$script:Queue` (a `Queue[string]`), `$script:RowMap={}`, `$script:Completed=0`, `$script:Total=count`; set `$progress.Maximum=Total`, `Value=0`.
4. Add one grid row per host: `Computer, 'Pending', '-','-','-','-', ''`; record `RowMap[host]=rowIndex`; enqueue host.
5. Disable CTA (text -> "RUNNING..."), **lock** `chkDry`/`numJobs`/`txtPass`, set status "Starting N target(s)...", pulse -> Active, and **start `$script:PollTimer`** (a `System.Windows.Forms.Timer`, `Interval = 800ms`).

There is **no RunspacePool/BeginInvoke/Invoke-Command from the UI**, and **no Cancel/Abort button**. Work is background `Start-Job`s; the only stop is **Close Tool**, whose handler kills its own jobs and cleans up orphaned SYSTEM tasks/temp files on targets.

### The poll loop (`$PollTimer.Add_Tick`) -- runs every 800ms
- **Feed:** while `Jobs.Count < numJobs.Value` and queue non-empty: dequeue a host, set its row Status='Running', and `Start-Job`:
  - **Dry-run job:** opens a DCOM `CimSession` (with inherited cred if present), reads `Win32_ComputerSystem.Manufacturer`, returns `Status='DryRun'` (or `'Error'` if unreachable -- a red dry-run predicts a live failure).
  - **Live job:** marshals the BIOS password as a `SecureString` across the job boundary; writes the `$script:Payload` (a `.ps1` baking `$BIOSPassword` + `$ResultPath`) to `\\host\C$\Windows\Temp\<task>.ps1`; `icacls`-locks it to SYSTEM+Administrators; opens a DCOM CimSession; `Register-ScheduledTask` + `Start-ScheduledTask` as SYSTEM (RunLevel Highest, 5-min limit); polls `SecureBoot_<host>.json` for 90s @ 4s; classifies Success/Skipped/Error/Timeout; cleans up task + both temp files in `finally`. Task name (`SBE_<rand>`) is generated in the parent and tracked in `$JobTasks` for orphan cleanup.
- **Harvest:** for each job in state Completed/Failed: `Receive-Job`, write its `Computer/Status/Manufacturer/Before/After/SetResult/Error` into the mapped row (or mark Error on exception), `Remove-Job`, `Completed++`, advance `$progress.Value`, and log to JANET (`Write-JanetAction -Action 'VulnPatched' -Result Success/Skipped/Failure`; dry-run rows are NOT logged).
- **Status line:** `"Running: N   Queued: N   Done: N / Total"` in accent purple; `$dgv.Refresh()`.
- **Completion** (Total>0, queue empty, jobs empty): stop timer; re-enable CTA + locked inputs; pulse -> Active (no errors) or Alert (any error); status -> `"Complete - X success, Y skipped, Z error/timeout"` (green/red); and a **summary MessageBox**: Success / Already Enabled / Dry Run / Error-Timeout / Total.

### Activity view = the Results grid + progress track (NOT a text log)
`$dgv`: `BackgroundColor RGB(16,16,22)`, `BorderStyle None`, `CellBorderStyle SingleHorizontal`, header row 30px (9pt bold purple caps on `RGB(10,10,16)`, no wrap), row height 24, mono cells, alternating row shading `RGB(22,22,30)`, `FullRowSelect`, `MultiSelect=false`, read-only, no add/delete/resize, `AutoSizeColumnsMode=Fill`.

**Columns in order** (FillWeight): `COMPUTER`(110) * `STATUS`(70) * `MANUFACTURER`(95) * `BEFORE`(85) * `AFTER`(85) * `RESULT`(75, field `SetResult`) * `ERROR / NOTES`(265).

**Row color coding** (`RowPrePaint`, by Status -> dim "glow" bg + bright fg): Success=green on `RGB(18,50,24)`; Skipped=teal on `RGB(10,65,65)`; Error=red on `RGB(64,16,18)`; Timeout=amber on `RGB(62,48,14)`; Running=blue/info on `RGB(12,42,68)`; DryRun=purple on `RGB(44,34,68)`; else neutral.

**Progress track** `$progress`: a 3px `Panel` flush under the grid, hand-painted (native ProgressBar avoided -- renders white when empty). Fills left->right with purple `Accent1` to fraction `Value/Maximum`; invisible at `Maximum=0`. Anchored `Left,Right,Bottom`.

**Secondary buttons:** **Clear** wipes rows, resets progress/status/pulse. **Export CSV** (warns if empty) opens a `SaveFileDialog` defaulting to `SecureBoot_Results_<yyyyMMdd_HHmmss>.csv`, writes all rows (Computer/Status/Manufacturer/Before/After/SetResult/Error) via `Export-Csv -NoTypeInformation -UTF8`, then confirms.

## 4. Targets / Credentials / Shared State
- **Targets:** free-text, one host per line, capped at 50, allow-list-validated (`A-Za-z0-9._-`), uppercased + de-duped at Run. Live count drives both the card label and the status strip.
- **Credentials:** inherited from the JANET launcher session as a shared `PSCredential` (`$script:InheritedCred`); if its password isn't extractable (e.g. smartcard) it silently falls back to the caller token. The credential flows into every CIM session and the scheduled-task run; it is also used at close-time for orphan cleanup. Title bar + status strip reflect the active identity.
- **Shared/run state** (script-scope): `$Jobs`, `$JobTasks`, `$Queue`, `$RowMap`, `$Completed`, `$Total`, `$RunIsDry`, `$Payload`, `$PollTimer`, plus the JANET session handle. Inputs (`numJobs`/`chkDry`/`txtPass`) are locked for a run's duration.

## 5. Engine Functions / Scriptblocks the UI Calls
Re-fork these as the work entry points behind the same UI:
- **`$script:Payload`** -- the here-string scriptblock dropped to the target and run as SYSTEM. Detects manufacturer, reads current Secure Boot state, applies a **brick-safety gate** (skips non-UEFI / non-GPT boot paths), dispatches to the OEM branch, writes a result JSON (`Manufacturer/CurrentValue/SetResult/NewValue/Error/Skipped/Timestamp`), and self-deletes.
- **`Enable-LenovoSecureBoot`** -- `Lenovo_BiosSetting` get / `Lenovo_SetBiosSetting` set / `Lenovo_SaveBiosSettings` commit.
- **`Enable-HPSecureBoot`** -- HP WMI branch.
- **`Enable-DellSecureBoot`** -- Dell `SetAttribute` (Status 0 = success).
- **`New-Result`** -- standardized result object builder.
- **Dry-run / live `Start-Job` scriptblocks** -- the per-host preflight and the full task-delivery flow (see 3).
- **`$PollTimer.Add_Tick`** -- the orchestration loop (queue feed + harvest).
- **JANET:** `Start-JanetSession 'SecureBoot'`, `Write-JanetAction 'VulnPatched'`, `Stop-JanetSession -ShowDialog`; `Set/Get-JanetAllowClose` for the close guard.

The web rebuild should expose an engine that, per host, returns the same `{Computer,Status,Manufacturer,Before,After,SetResult,Error}` shape so the streaming grid stays identical; concurrency = the parallel-jobs value; Dry Run is a connectivity+manufacturer probe only.

## 6. Notable UX Details + Visual Theme
- **Theme:** "Purple + Gold on Black," mirroring the JANET launcher. Background `RGB(8,8,12)`; Surface `RGB(16,16,22)`; primary accent **purple `#8C64DC` (140,100,220)**; secondary gold `#DAB452`; Success green `(92,198,120)`, Warning amber `(230,180,70)`, Danger red `(224,80,90)`, Info teal `(88,180,210)`. Text: primary `(240,240,245)`, secondary `(170,168,180)`, muted/faint greys.
- **Fonts:** body = **Segoe UI Variable Display**; mono/display/eyebrow = **Cascadia Mono** (titles bold). Eyebrow/header labels are uppercased.
- **Custom-painted controls:** corner-bracket cards; ghost buttons (1px border, hover fill); striped primary CTA (diagonal hatch stripe); hand-drawn checkboxes (purple fill + checkmark); hand-painted flat progress; pulsing status dots (Active green / Idle grey / Alert red). All panels double-buffered.
- **Close discipline:** an **X-block guard** -- only the explicit "Close Tool" button may close the form; the chrome X, Alt-F4, and title-bar Close are cancelled in `FormClosing` (OS shutdown excepted). On legitimate close: stop/dispose timers, kill only this tool's jobs, unregister orphaned SYSTEM scheduled tasks and remove temp files on targets, and run `Stop-JanetSession -ShowDialog` (the JANET ASI/closing-notes capture form).
- **Changelog viewer:** a resizable modal (`760x560`, dark title bar) with a read-only RichTextBox; version headers (`^v\d+\.\d+`) recolored purple/bold, bullets dim; Esc/Enter dismiss.
- **Disabled-during-run affordance:** CTA text becomes "RUNNING..." and Dry Run / Parallel jobs / password are greyed until completion -- a clear, unmistakable busy state.