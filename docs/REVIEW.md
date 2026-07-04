# JANET + JANET ONE - Review Notes (basis for JANET TWO)

The "what makes them tick" review. Per-tool UI specs: `docs\ui-specs\`. Build guide: `docs\HANDOFF.md`.

---

# Part A - The desktop JANET hub / launcher

# JANET TWO -- Suite-Level HUB/Launcher Spec (mirrors JANET desktop `JANET.ps1` v3.7.5)

Source studied: `X:\J.A.N.E.T\JANET.ps1` (launcher, v3.7.5, ~2206 lines) and `X:\J.A.N.E.T\JANET_Config.json` (tool registry). This spec captures the **suite-level experience** ("how you run everything") so JANET TWO can reproduce it.

---

## 1. Identity / Branding

- **Suite name (long):** `J.A.N.E.T. - Joint Administration and Network Execution Toolkit`
- **Header title:** `J.A.N.E.T / LAUNCHER` (note the ` / ` separator convention used on EVERY window title: `J.A.N.E.T / <SCREEN>`, e.g. `J.A.N.E.T / CONFIG EDITOR`, `J.A.N.E.T / LOG VIEWER`, `J.A.N.E.T / ARCHIVE`).
- **Subtitle:** `Joint Administration and Network Execution Toolkit`
- **Version chip:** launcher version (`v3.7.5`) shown as gold-background / dark-text pill, top-right of header.
- **Operator line (header):** `OPERATOR <USERNAME>   /   STATION <COMPUTERNAME>` (uppercased) -- establishes who/where, military-ops framing.
- **Station index eyebrow:** `[ 01 ]` in purple, top-left of header.
- **Author/attribution:** `Braxton Thompson | 48CS/SCOO | B.E.A.T. Contractor`.
- **Tone:** dark tactical / "operations console" -- eyebrow labels prefixed with `/`, ALL-CAPS labels, monospace data, corner-bracket cards, pulse status dots, diagonal-hatch stripe on primary buttons.

## 2. Theme -- "Purple + Gold on Black"

Role split: **Purple owns structure** (brackets, primary buttons, icons). **Gold owns highlights** (eyebrow labels, version chip, Discover/Archive buttons, header accent line, header text on cards). **Surfaces** are near-black with a faint violet lean (so it reads distinct from pure #000).

| Token | RGB / Hex | Use |
|---|---|---|
| `cBg` | 8,8,12 (#08080C) | app background |
| `cHeaderBg` | 6,6,10 | header/status bar/log viewer surfaces |
| `cSidebar` | 7,7,11 | toolbar/picker strips |
| `cPanel` | 16,16,22 | cards, list/combo backgrounds |
| `cRow` / `cRowAlt` | 16,16,22 / 22,22,30 | rows, textbox fields |
| `cRowHover` / `cRowActive` | 30,28,40 / 40,36,54 | hover/press |
| `cAccent` (purple) | 140,100,220 (#8C64DC) | primary buttons, brackets, icons |
| `cAccentHov` / `cAccentDim` | 164,128,240 / 96,68,156 | hover/press |
| `cAccentGlow` | 28,20,48 | header gradient glow (left) |
| `cGold` | 218,180,82 (#DAB452) | eyebrow labels, version chip, accent line, card headers |
| `cGoldHov` / `cGoldDim` / `cGoldFaint` | 238,200,110 / 155,125,52 / 82,68,34 | gold variants |
| `cGreen` | 92,198,120 | active/running status, success log lines |
| `cGreenDim` | 50,120,65 | RUNNING button bg |
| `cRed` | 224,80,90 | missing-tool / error |
| `cOrange` | 230,180,70 | warn / alert pulse |
| `cInfo` | 88,180,210 | info |
| `cText` | 240,240,245 | primary text |
| `cTextDim` | 170,168,180 | secondary |
| `cTextMuted` | 110,106,125 | tertiary |
| `cTextDark` | 60,56,74 | faintest (path/index) |
| `cTextOnAccent` | 255,255,255 | text on purple |
| `cTextOnGold` | 16,14,8 | text on gold chip |
| `cBorder` / `cBorderStrong` | 38,34,52 / 52,46,72 | borders |
| `cStripeAmb` / `cStripeBlk` | 140,100,220 / 8,8,12 | diagonal hatch on stripe buttons |

**Fonts:** Display/data = `Cascadia Mono` (Bold 18/13/10 for display, 9/8 for eyebrows, 10/9/8 plain for mono data). Body/UI = `Segoe UI Variable Display` (10 regular/bold, 9 caption, 8 tiny). Tool-card name = Segoe UI Variable Display 11.5 Bold. Icons = `Segoe MDL2 Assets` (14/20/11). For web (JANET TWO): map Cascadia Mono -> a mono webfont (e.g. Cascadia Code/JetBrains Mono), Segoe UI Variable -> system UI stack, MDL2 glyphs -> an icon set.

**Signature visual motifs to reproduce in CSS:**
- **Corner-bracket cards** -- L-shaped 16px brackets in all four corners (purple when healthy, red when missing), 2px thick; optional `/ HEADER` eyebrow in gold with a dotted underline divider at y~40.
- **Stripe button** -- solid purple primary button with a 4px `WideDownwardDiagonal` hatch strip along the bottom edge (purple-on-black). This is the LAUNCH / primary-action button.
- **Pulse dot** -- small filled circle that blinks between full color and a 50%-alpha version on a timer (Idle=muted/no-pulse, Active=green/720ms, Alert=orange/340ms, Error=red/340ms).
- **Grid-paper background** -- faint 1px dots on an 18px grid behind the scrollable tool list.
- **Header gradient glow** -- purple radial-ish linear gradient on the left 35%, gold gradient on the right 30%, dotted underline at the bottom edge; a 2px solid gold accent line across the very top.
- **Status-bar scanlines** -- faint horizontal lines every 3px + 1px gold-dim top border.
- **Dark immersive chrome** -- `Set-JanetDarkTitleBar` uses DWM attributes 19/20 (dark mode) + 33 (rounded corners) on every window. Web equivalent: dark theme + rounded window framing.
- **DPI awareness** -- Per-Monitor-V2 for crisp text (desktop-only concern; N/A for web).

## 3. Home / Landing UX -- how the 12 tools are presented & launched

The landing screen is a **single vertical scrolling list of full-width tool cards** (NOT a tile grid). Layout top->bottom:

1. **Header band (90px):** station index `[ 01 ]`, signal icon, `J.A.N.E.T / LAUNCHER` title, subtitle, operator/station line, live `HH:mm:ss` clock (1s timer), gold version chip.
2. **Toolbar (52px):** session + utility actions (see 6).
3. **Dotted purple separator.**
4. **Scrollable tool list** (`AutoScroll`, grid-paper bg) -- one **corner-bracket card per tool**, ~100px tall, full width, stacked with 12px gaps.
5. **Status bar (30px, docked bottom):** `TOOLS <count>   |   MISSING <n>   |   <scriptDir>` on the left; a green pulsing `LOG` indicator on the right.

**Each tool card contains:**
- Gold `/ <TOOLNAME>` eyebrow header with dotted underline.
- Two-digit index `01`..`12` (mono, faint).
- A category-derived MDL2 glyph (see 5 glyph mapping).
- A pulse status dot (Idle when present/idle, Error when the script file is missing, Active while running).
- The tool **Description** (single line, auto-ellipsis, full text on hover tooltip).
- A path line: the **resolved actual filename** uppercased + `MODIFIED <date>`; if the resolved file differs from the registered `Script` (version fallback fired), it shows `REGISTERED.PS1  >>  RESOLVED_x.y.z.PS1`.
- A right-aligned **LAUNCH** stripe button. If the script can't be found, the card flips to red brackets/header, the dot goes Error, and the button becomes a disabled red **"Missing"** ghost button with a "Script not found" tooltip.

**Launching:** clicking LAUNCH calls `Launch-Tool` for that tool (config is re-read fresh on each click so edits take effect without restart). Double-launch is blocked with an "already running" messagebox. While running, the card's button shows **RUNNING** (green-dim, disabled), the dot pulses Active, and the toolbar RUN cluster counts active tools.

**Empty state:** if zero tools registered, a single orange corner-bracket "NO TOOLS REGISTERED" card explains to use Discover or Config.

**For JANET TWO (web):** reproduce as a scrolling column of full-width cards with the bracket/eyebrow/glyph/dot/description/path/LAUNCH anatomy. LAUNCH = navigate to that tool's SPA page (instead of spawning a process). Preserve the live clock, operator/station line, RUN/active counter, and TOOLS/MISSING status bar.

## 4. Tool registry -- schema, versioned filenames, resolution

**`JANET_Config.json` schema (root):**
```json
{
  "SuiteName": "J.A.N.E.T. - Joint Administration and Network Execution Toolkit",
  "Version": "1.0",
  "ToolsDir": "Tools",
  "Tools": [ { tool }, ... ]
}
```
**Each tool object:** `Name` (display + the running-process key, must be unique), `Script` (filename, usually versioned), `Description` (long, shown on card + tooltip + config editor), `Icon` (always `""` in practice -- glyph is derived from category/name, not this field), `Category` (`Patch` | `Compliance` | `Reports` | `Admin` -- drives the glyph and is the only grouping signal).

**The 12 registered tools (Name / Script / Category):**
1. WorkstationPatchingTool / `WorkstationPatchingTool_6.5.22.ps1` / Patch
2. ACAS Nemesis Tool / `ACAS Nemesis Tool_1.10.10.ps1` / Patch
3. STIG_Tool / `STIG_Tool_1.3.5.ps1` / Compliance
4. ReportsTool / `ReportsTool_2.14.6.ps1` / Reports
5. RemotePackageInstaller / `RemotePackageInstaller.ps1` / Patch (unversioned)
6. RemoteMessageTool / `RemoteMessageTool_1.3.3.ps1` / Admin
7. SecureBootEnabler / `SecureBootEnabler.ps1` / Admin (unversioned)
8. ADSearchTool / `ADSearchTool.ps1` / Admin (unversioned)
9. DHCPScopeOptionTool / `DHCPScopeOptionTool_1.1.5.ps1` / Admin
10. RemoteRestartScheduler / `RemoteRestartScheduler_1.6.0.ps1` / Admin
11. UnsupportedProductRemediator / `UnsupportedProductRemediator_1.1.2.ps1` / Patch
12. WindowsUpgradeTool / `WindowsUpgradeTool_0.1.0.ps1` / Patch

**Versioned-filename convention & `Script` field resolution (`Resolve-ToolScript`):**
- Tools live under `<ScriptDir>\Tools\`. The `Script` value is the canonical (usually versioned) filename, e.g. `STIG_Tool_1.3.5.ps1`. Per user's versioning rule: a bump = new `Tools\` file + archive old + update the JSON `Script` field.
- Resolution order: (1) try the literal `Script` path under `Tools\` then `<ScriptDir>`; (2) if missing, glob `"{base}_*.ps1"` (base = filename without the `_x.y.z` version suffix) across `Tools\` then `<ScriptDir>`, parse the `_<version>` portion as a `[Version]`, and return the **highest version** (tie-break by most-recent LastWriteTime). So even if the JSON points at a stale exact name, the launcher self-heals to the newest matching versioned file and surfaces the swap on the card (`REGISTERED >> RESOLVED`). Absolute paths in `Script` are run as-is (used by the Archive feature).
- **Config load/fallback:** `Load-Config` reads the JSON; on parse failure it warns and falls back to `Get-DefaultConfig` (an in-code mirror of the registry that MUST be kept in sync with the JSON in the same commit -- drift silently drops tools). If the JSON is absent, the default is written out.
- **Auto-discover** (`Discover-Scripts`): scans `Tools\` + root for unregistered `*.ps1` (dedup by exact name and by version-base), reads the first 30 lines of each to pull a description from `Purpose:` / `Description:` / `SYNOPSIS`, and offers them in a checklist to append to config.
- **Archive** (`Get-ArchivedTools`): scans `Tools\Archive\*.ps1`, lists name/file/modified-date, and can launch any archived script directly by absolute path.

**For JANET TWO:** keep the same registry shape (`Name`/`Description`/`Category` + a route/engine reference instead of a `.ps1` filename -- e.g. one `.psm1` engine per tool, matching the existing JANET ONE pattern). Preserve category-as-grouping, the long descriptions verbatim, and a config/registry editor.

## 5. Navigation & glyph mapping

- Navigation is **flat** -- no sidebar tree, no tabs; everything is the single scrolling card list plus modal dialogs (Config Editor, Log Viewer, Discover, Archive) opened from the toolbar.
- **Glyph derivation** (`Get-ToolGlyph`, regex over `Name+Script+Category`, MDL2 codepoints): patch/update->Sync (0xE895); adsearch->Search (0xE721); user/logged/edipi->User (0xE77B); report/acas/nessus->Chart (0xE9D9); message/mail->Mail (0xE8BD); package/deploy/install->Package (0xE7B8); secureboot/shield/bios/stig/compliance->Shield (0xEA18); admin/remote/ops->Signal (0xE8F4); clean/uninstall->Broom (0xE74D); config/settings->Settings (0xE713); default->App (0xECAA).

## 6. Shared launch / credential / logging / admin-session behavior

**Toolbar actions (left->right):** `Set Creds` (purple stripe), CRED cluster (dot + `CRED` eyebrow + username/"not set"), RUN cluster (dot + `RUN` eyebrow + "N active/idle"), hidden `Stop` (red, appears when >=1 running). Right-aligned utility buttons (glyph+text ghost buttons): `Archive` (gold), `Discover` (gold), `Refresh`, `Logs`, `Config`.

**Shared credential flow (the suite-wide session-gating mechanic):**
1. `Set Creds` -> `Get-Credential` prompt captures a `PSCredential`.
2. Serialized via `Export-Clixml` (DPAPI-encrypted, user+machine scoped) to `%LOCALAPPDATA%\JANET\Session\janet_cred.xml`.
3. `Launch-Tool` spawns each child tool via `ProcessStartInfo` and injects `JANET_CRED_FILE` + `JANET_CRED_USER` env vars **on the child only** (plus `JANET_LAUNCHER` = launcher version). Launcher's own env stays clean.
4. Tools `Import-Clixml` at startup to pre-fill their credential slots; each tool still keeps a manual "Set Credentials" override.
5. On launcher close (and on startup, to clear stale files), the cred file is scrubbed from disk (`Clear-LauncherCredential`). Right-click the CRED status to clear mid-session.
- UI feedback: CRED dot Active/green + username when set; Idle/red "not set" otherwise.

**Launch mechanics (`Launch-Tool`):** resolves path (version-aware), blocks double-launch, spawns `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<resolved>"` via `ProcessStartInfo` (`UseShellExecute=false`). WorkingDirectory falls back to `%SystemRoot%` when the script's parent is a UNC/share path (Win32 `CreateProcess` rejects UNC CWD -- relevant because X:\ is an SMB share); child resolves its own paths via `$PSScriptRoot`. Tracks the live `Process` in `$RunningProcs[Name]`.

**Process tracking & live state:** a 2s polling timer walks the cards, flips each LAUNCHRUNNING/disabled, updates the per-card pulse dot, updates the RUN counter, and reaps exited processes (logs exit code). A 1s timer drives the header clock. `Stop` kills all running children (with confirm). All timers/pulse-dot timers disposed on close.

**Logging:** per-day, per-user file at `<ScriptDir>\Logs\Launcher_<user>_<yyyy-MM-dd>.log` (fallback `Documents\JANET_Logs`). Entry format `[yyyy-MM-dd HH:mm:ss] [USER: <name>] [<ACTION>] <detail>`. Actions include `LAUNCHER_START/STOP`, `CONFIG_LOADED/SAVED/ERROR`, `CRED_SET/CLEAR/ERROR`, `LAUNCH`/`LAUNCH_BLOCKED`/`LAUNCH_ERROR`, `TOOL_EXITED`, `STOP_TOOL`, `DISCOVER*`, `ARCHIVE*`. Built-in **Log Viewer** dialog: dropdown of `*.log` (newest first, size/mtime), syntax-highlighted (gold timestamps, red ERROR/FAIL, green SUCCESS/LAUNCH, orange WARN), Refresh/Copy/Folder.

**Admin/operator session:** identity is the Windows `$env:USERNAME` / `$env:COMPUTERNAME` shown in the header and stamped into every log line (no separate login). The "admin session" is effectively the shared-credential handoff that flows the operator's elevated/CAC creds down to every tool launched in that session.

**For JANET TWO (web):** the credential handoff maps to a **server-side session** that holds the operator's creds once (set via a "Set Creds" action) and passes them to each tool's engine call -- same "set once, every tool inherits, scrubbed on logout" contract. Keep per-user/per-day server logging with the same action vocabulary and an in-app log viewer, the operator/station banner, the running/active indicator, and the Config + Discover + Archive utilities (Discover/Archive can map to "register a new engine" / "run a retired engine").

## 7. JANET TWO parity checklist (per the JANET ONE parity rule)

Reproduce, suite-level: the long suite name + `/`-delimited window titling; Purple+Gold-on-Black theme with corner-bracket cards, stripe primary buttons, pulse dots, grid-paper bg, header glow, gold version chip; the operator/station banner + live clock; the **scrolling full-width tool-card list** (NOT a grid) with eyebrow/index/glyph/dot/description/path/LAUNCH; the registry schema (`Name`/`Description`/`Category` + engine ref) with category grouping and version-aware resolution + self-heal; set-once shared-credential session inherited by every tool and scrubbed on exit; per-user/per-day logging + in-app log viewer; RUN/active tracking + Stop-all; and the Config editor / Discover / Archive utilities. Mirror feature-for-feature -- no partial port.

---

# Part B - JANET ONE architecture: KEEP vs REBUILD

# JANET ONE -- study for JANET TWO (KEEP the plumbing, REBUILD the per-tool UI)

JANET ONE is a zero-dependency, pure-PowerShell local web re-front of the whole JANET desktop suite. The whole stack is worth reusing wholesale. What lost the desktop usability is one specific layer: the **manifest-driven generic renderer** in `web/js/app.js` that turns every tool/action into the same cookie-cutter "form on top, grid below, log at bottom." JANET TWO should keep the entire server/auth/logging/streaming backbone and the Emit/manifest contract, and replace only the generic SPA renderer with faithful, bespoke per-tool views.

Key files (all under `X:\J.A.N.E.T ONE\`):
- `Start-JanetOne.ps1` -- launcher: mints per-launch token, conhost pin (so the smartcard picker renders), Unblock-File self-heal, loopback bind, opens browser to `http://127.0.0.1:<port>/?t=<token>`.
- `server\JanetOne.Server.ps1` (~54 KB) -- the HttpListener server, all routes, token gate, runspace job model, reaper, upload/browse, packages endpoints.
- `server\JanetOne.Auth.ps1` -- `Prompt-JanetOneCredential` (server-side `Get-Credential` smartcard picker, null-PIN probe), `Show-JanetOneFileDialog` (STA WinForms picker, SetForegroundWindow), `Get-JanetOneCredentialStatus`.
- `server\JanetOne.Logging.ps1` -- central JANET CSV audit bridge (same share, schema, per-tool/per-user folders, local spool + replay).
- `server\tool-registry.json` -- full tool catalog (id/name/category/icon/ported/beta/summary).
- `web\index.html` + `web\js\app.js` (2815 lines) + `web\js\help-content.js` -- the SPA.

## HttpListener server design
- Built-in `System.Net.HttpListener`, binds **`http://127.0.0.1:<port>/` only** (loopback; no admin, no URL ACL needed). Single accept thread.
- **Heartbeat accept loop**: one async `BeginGetContext` stays armed; `WaitOne(2000)` slices so Ctrl+C is honored and the job reaper runs on a maintenance tick even with no client traffic. Requests are still handled strictly on the one thread.
- `IdleConnection` timeout bumped to 20 min so the blocking smartcard pick doesn't get dropped by http.sys mid-pick.
- Static assets (`web/`) served openly (UI code only, no token) with a **path-traversal guard** (resolved path must stay under `web/` with a trailing-sep prefix check). Adds `Referrer-Policy: no-referrer` + `X-Content-Type-Options: nosniff` to every response.
- Bounded body/stream copy everywhere (25 MB action body cap, 1 GB upload cap) so a chunked/lying Content-Length can't blow memory.

### All /api routes
- `GET /api/tools` -- registry merged with live manifests (id, name, category, icon, summary, version, ported, beta, actions).
- `GET /api/cred` * `POST /api/cred` * `DELETE /api/cred` -- credential status / pop smartcard picker / clear.
- `POST /api/session/start` -- record responsibility ack (`{ack:'yes'}`) -> `state.AckGiven`.
- `POST /api/session/end` -- closing notes + ASI/RFC -> SessionNotes Runs row + shutdown rollup.
- `GET /api/status` -- session + logging-health (onShare/localOnly, shareWarning, counters, packages/Log4j paths).
- `GET /api/logs/tail?tool=&n=` -- last N rows of this operator's current-month detail CSV (ping-gated, tailed).
- `POST /api/upload` -- raw body = file bytes, name in `X-Janet-Filename` header; stream-copies to a fresh temp dir, returns server path (binary-safe). Reserved-name/traversal sanitized.
- `GET /api/tool/pkginstall/packages?kind=psadt|msi` and `GET /api/tool/pkginstall/msis?path=` -- server-owned package/MSI enumeration (UNC ping-gated).
- `GET /api/tool/<id>/manifest`.
- `POST /api/tool/<id>/action/<actionId>` -- validates action id against the manifest (ACAS has an extra by-id allowlist), enforces the destructive gate, spawns the worker -> `{jobId}`.
- `GET /api/job/<jobId>/events?since=N` -- incremental event poll (`{status, nextSince, events[]}`).
- `POST /api/job/<jobId>/cancel` -- sets `job.Cancel=$true`, status -> `cancelling` (graceful).

## Per-launch token security model
- Token = `[guid]::NewGuid().ToString('N')` minted per launch, passed as `?t=` in the opened URL.
- Browser strips `?t=` into `sessionStorage` and `history.replaceState`s it out of the address bar; thereafter sends it as the `X-Janet-Token` header (and `?t=` is still accepted, e.g. for `sendBeacon` cancels which can't set headers).
- Server checks `/api/*` with a **constant-time compare**: length check, then XOR-OR fold over every char (no early return), so no timing oracle. Bad/missing token -> 403.

## Plug-in contract (the part to KEEP verbatim)
Each tool is `modules\JanetOne.<id>.psm1` exporting exactly two functions:
- `Get-JanetToolManifest` -> `@{ id; name; category; icon; summary; version?; statefulRunspace?; actions=@(...) }`. Each action: `@{ id; label; kind; destructive; description?; confirm?; inputs=@(...); columns=@(...) }`. Input types seen: `hostlist, text, textarea, int, bool, select (options/optionsFrom/optionsArg), file, filelist, folder, savefile, hostpick, msi-checklist`.
- `Invoke-JanetToolAction -ActionId -Params -Credential -Emit` -> returns `@{ rows=@(); summary=@{} }`.

**Emit event contract** (`& $Emit @{ type=... }`):
| type | fields | effect |
|---|---|---|
| `status` | text | status-bar line |
| `progress` | done,total | progress bar |
| `row` | action columns (+ optional `_rk`, `id`) | upsert a grid row |
| `log` | text, level | activity-log line |
| `audit` | action,target,result,itemCount,detail | writes `Write-JanetAction` (TouchHost/VulnPatched * Success/Failure/Skipped); ACAS also fans out session-log + touched-host + run CSVs |
| `run` | scope/profile/mode/hostsTotal/success/failed/durationSec/groupKey/groupMembers | ACAS daily Runs CSV |
| `final` | result | emitted automatically on return |
| `error` | text | error line (server-emitted on throw) |

**`__job` cancel hashtable**: the server injects `$Params['__job']` (the synchronized job hashtable). Engines poll `$job.Cancel` during a fan-out, break, and `BeginStop` in-flight WinRM children. Engines that ignore it just work (cancel becomes best-effort).

## Background runspace job + polling streaming model
- Each action POST creates a synchronized `$job` (`Events` = synchronized ArrayList, `Status`, `Result`, `Cancel`, timestamps), spawns a `[powershell]` worker (own runspace, or a **persistent per-tool STA runspace** when the manifest sets `statefulRunspace` so `$script:` parse/scan state survives across actions -- serialized one action at a time via a `Busy` slot, 409 if busy).
- Worker dot-sources logging + imports the module (skipped for stateful), builds the `$Emit` closure, runs the action, appends a `final` event, maps status (`running->done`, `cancelling->cancelled`, throw->`error`).
- Client polls `/events?since=N`; server returns the **status snapshot taken BEFORE the events snapshot** (so a terminal status never arrives without its final event), plus `nextSince`. Client maintains one independent poller per run (`pollRun(key,gen)` with a generation guard) -- multiple actions stream concurrently and keep running across tab switches.
- **Reaper** (`reapJobs`) runs on the tick, on events, on action POST, on cancel: drains finished runspaces, frees stateful Busy slots, evicts jobs 5 min after **FinishedAt** (never the job a current request is about). Transactional start (BeginInvoke failure frees the slot and drops the job).

## Central-audit-CSV logging bridge
- Logs to the **same** share/schema/folders as the desktop tools: `\\dm-tn-01\sh-usafe-automation$\JANET\Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv`, fleet rollup `Logs\<YYYY-MM>_usage.csv`. Tool-id->desktop-folder map (`acas->ACAS_Nemesis`, `wpt->WPT`, ...). Operator identity resolved "EDIPI - DisplayName" (DirectorySearcher -> LDAP -> fallback).
- Context-based (`New-JanetOneLogContext`, synchronized) so it dot-sources into server AND worker runspaces. Cached ~30s ping gate, write-probe (sentinel), **local spool + replay** when the share is down, header-ensure with legacy rotation/sister-CSV. Desktop CSV byte conventions (comma->space/semicolon, not RFC-4180) so ONE rows merge with desktop rows. ACAS gets the full per-host/transcript/run fan-out.

## Session gate (ack + cred)
- HTML `#session-gate` overlay mirrors the desktop WPT START tab: Set Credentials (ADW) + a Yes/No responsibility radio. "Start Admin Session" enables only when **cred set AND ack=yes**; it POSTs `/session/start`. A read-only **"Start Active Directory Search"** bypass opens only `adsearch` and leaves the rest locked.
- Server enforces the gate authoritatively: a `destructive` action is refused (403) unless `AckGiven && Cred` -- so the read-only bypass can never reach a state-changing action even if the browser is tampered with.

## File upload
- Browser-native upload (`/api/upload`, drag-drop + `<input type=file>`, returns a server temp path so path-based engines work unchanged). (The old server-side `/api/browse` desktop picker was removed -- browser-native pickers cover every tool.)

## SPA structure (the generic renderer = the thing to REBUILD)
- Vanilla JS, no build step. `TOOL_CATEGORIES` group the left nav; `TAB_GROUPS` maps each tool to a per-tool rail/command-bar layout that *tries* to mirror the original desktop tabs (e.g. `wpt` -> Bulk scan & patch / Software manager / SCCM app manager / KB scanner / ...).
- **But the body is one generic template for every action**: `selectAction` builds a form by looping `action.inputs` (one `<input>/<textarea>/<select>/dropzone` per declared type), hoists `hostlist` inputs into one shared Targets box, and renders one results `<table>` driven by a `gridSpecFor(toolId,actionId)` "spec." Cells are colored by regex on the column name (`genericCell`) unless a hand-written spec exists.
- The desktop-specific richness only exists where someone hand-coded a `WPT_*_SPEC` or a bespoke view (the ACAS Remediation card view, the Bulk-Scan host-detail inspector, the Software Manager filter bar). Everything else is form+grid+log. That generic uniformity is exactly why each tool "lost its bespoke tabs/workflow/activity-run feel."

---

# KEEP vs REBUILD (the candid call)

## KEEP wholesale (proven, reusable backbone)
The entire non-UI stack is excellent and should be carried into JANET TWO unchanged or near-unchanged: zero-dependency pure-PowerShell HttpListener server, loopback bind, per-launch token with constant-time compare, the runspace-worker + `/events?since=` polling streaming model (incl. the status-before-events ordering, generation guards, reaper, stateful per-tool runspaces, graceful `__job` cancel), the central JANET CSV logging bridge (share/schema/spool/replay), the credential/session model (server-side smartcard picker, in-memory only, ack+cred destructive gate), file upload + server-side browse, and the **manifest + Emit event contract** (`status/progress/row/log/audit/run/final` + `__job`). The plug-in boundary (`Get-JanetToolManifest` / `Invoke-JanetToolAction`) is the right seam -- keep it; the engines don't change.

## REBUILD (what made the UI "too simple")
Replace the **generic manifest-driven renderer** with faithful per-tool views. Specifically:
1. **One cookie-cutter form+grid per action** -- kill the assumption that every action = a flat field form over a single table. Build bespoke layouts per tool that reproduce the desktop's panels, multi-pane workflows, and side-by-side controls.
2. **Bespoke desktop tabs, not a generic rail** -- each tool gets its own real tabbed workspace mirroring its WinForms TabControl (WPT's Bulk Scan & Patch toolbar, Reports' 9 sections, STIG's Scan/Apply/Verify/CKLB/Reports, Restart's Targets/Schedule/Run-Results), with the tab's own toolbar of context buttons -- not auto-derived from `TAB_GROUPS` + `columns`.
3. **Regex-colored generic grids** -- `genericCell` colors cells by guessing from the column name. Replace with per-tool grid components that know their columns, types, drill-downs, and row actions (the hand-written `WPT_*_SPEC`s prove the pattern; JANET TWO must make that the rule, not the exception).
4. **The "activity-run feel"** -- the desktop tools feel like a live operation console (rich per-host detail, structured inspectors, contextual act-on-selection). Only ACAS Remediation and WPT Bulk-Scan got that here. Every tool in JANET TWO needs its bespoke run/results experience, not the shared form->grid->log shell.
5. **Shared-Targets hoisting** flattens tools whose original had purpose-built target panels (Restart's Targets tab, DHCP's connect/scope panel, AD Search's mode radios). Rebuild those as the tool's own first-class target UI.
6. **Manifest-as-UI** -- inputs/columns drive the whole UI, so a tool can only be as expressive as the generic input vocabulary. JANET TWO should let each tool own its view (the manifest can still describe actions for routing/audit), so nothing is clamped to the lowest-common-denominator form.

Net: JANET TWO = JANET ONE's server/auth/logging/streaming/contract **kept intact**, with the SPA's single generic renderer **swapped for a bespoke view per tool** that restores the desktop tabs, workflows, and console feel.
