# J.A.N.E.T. TWO -- Build Handoff

> Pure-PowerShell, zero-outside-dependency, web-local re-front of the JANET suite.
> **Mandate:** keep JANET ONE's proven backend/plumbing; rebuild the frontend so **each tool gets a FAITHFUL, bespoke per-tool view** that mirrors its desktop WinForms tool -- its screens, tabs, run controls, and above all the live **activity run** (activity log + colour-coded results grid + progress + per-host rows). **No generic renderer.**

> **Owner-confirmed decisions (2026-06-18):** (1) engines are **RE-FORKED fresh** from the desktop `fork-source/Tools/*.ps1` -- NOT reused from JANET ONE's `modules/*.psm1` (those are a bug-fix cross-check only); (2) the frontend is **faithful per-tool views**, no generic renderer; (3) this kickoff delivered the review + scaffold + this handoff; the per-tool build follows.

## How to use this handoff (doc map)

Read in order:
1. **`README.md`** -- one-page orientation + the locked decisions.
2. **`docs/REVIEW.md`** -- what makes the desktop JANET hub and JANET ONE tick (the KEEP-vs-REBUILD detail behind section 1).
3. **`docs/ui-specs/<tool>.md`** -- the faithful UI rebuild spec for each of the 12 tools (screens, run model, live activity view). **Open the tool's spec before you build its view.**
4. **This file** -- the architecture, the shared component kit, the build order, the rules.

**Start here:** do **Build step 0** (plumbing lift + the cross-cutting component kit), then build **Remote Message** (step 1) as the reference pattern every later tool copies.

> Provenance: generated 2026-06-18 from a 15-agent review of the desktop JANET suite (12 tools + hub) and JANET ONE. The `docs/ui-specs/` files are the detailed per-tool companions to this document.

---

## 0. The one-sentence thesis

JANET ONE took the backends but not the usability: a single manifest-driven SPA made every tool a cookie-cutter form-over-grid. JANET TWO **reuses the plumbing verbatim** and **rebuilds the UI as one bespoke view per tool**, where every view is COMPOSED from a small library of shared, desktop-grade components -- so we get desktop fidelity *without* a lowest-common-denominator renderer.

## 1. What we KEEP verbatim (the plumbing) vs REBUILD (the UI)

**KEEP (lift `JanetOne.*` -> `JanetTwo.*`, rename only):**
- `System.Net.HttpListener` server, loopback-only bind (`http://127.0.0.1:<port>/`), single accept thread + 2 s heartbeat loop, per-launch GUID token (`?t=` -> `sessionStorage` + `history.replaceState`, `X-Janet-Token`, constant-time compare), static-asset path-traversal guard + security headers.
- Background-runspace worker + **`/api/job/<id>/events?since=N` polling** streaming model: synchronized `$job.Events` ArrayList, **status snapshot taken BEFORE events snapshot**, `nextSince` cursor, one independent client poller per run with a **generation guard**, runs survive tab/tool switches.
- **Reaper** (drains finished runspaces, frees stateful Busy slots, evicts 5 min after FinishedAt, never the job a request is about) + transactional `BeginInvoke` start.
- **Stateful per-tool persistent STA runspace** (`statefulRunspace` flag, serialized via a Busy slot, 409 when busy) for tools whose `$script:` parse/scan state must survive across actions (reports, stig).
- **Graceful cancel** via injected `$Params['__job']` synchronized hashtable (engine polls `__job.Cancel`, BeginStops in-flight WinRM children; `running -> cancelling -> cancelled`), `sendBeacon` cancel on unload.
- **Credential/session model:** server-side `Get-Credential` ADW smartcard picker on the operator's interactive desktop (`JanetOne.Auth.ps1`: `Prompt-JanetOneCredential` null-PIN probe; `Show-JanetOneFileDialog` STA file/folder picker; `Get-JanetOneCredentialStatus`), PSCredential in server memory only, fall back to current Kerberos/CAC.
- **Server-side session gate:** responsibility ack (`POST /session/start` -> `AckGiven`) AND set credential required for destructive actions (403 otherwise); read-only (AD Search) bypasses; **server flag is authoritative**.
- **Central CSV logging bridge** (`JanetOne.Logging.ps1`): same share/schema/per-tool/per-user folders + byte conventions as the desktop tools so rows merge; EDIPI->DisplayName identity, cached ping gate + write-probe, local spool + replay-on-launch.
- File upload (`/api/upload`, binary-safe, returns a server temp path) + helper endpoints (`/api/status`, `/api/logs/tail`, package/MSI enumeration).
- **The plug-in contract itself** (see 4) and sandboxed report rendering (`iframe srcdoc`, `allow-scripts` WITHOUT `allow-same-origin`).

**REBUILD (these are the root cause of "too simple"):**
- The generic `selectAction()` form renderer, `gridSpecFor()`/`genericCell()` regex-coloured default grids, `TAB_GROUPS`-synthesized rails, shared-Targets hoisting, and the single form->grid->log shell. Replace with **bespoke per-tool views over a shared component library**, and treat the manifest as **routing/audit metadata only -- never the UI source of truth**.

## 2. The triad: how one faithful tool is built

Every tool is three artifacts wired by the unchanged contract:

```
web/js/views/<id>.view.js   bespoke UI: real tabs, toolbars, grids (composes shared components)
modules/JanetTwo.<id>.psm1  engine: RE-FORKED from fork-source/Tools/<DesktopTool>.ps1
server/ + tool-registry.json the REUSED contract (no per-tool server code)
```

- **View** registers itself: `JanetViews.register('<id>', { mount(host, ctx){...}, unmount(){...} })`. Lazy-loaded by the router on first nav (one `<script>` injection). Owns the tool's desktop layout and its own per-tool state (active tab, grid sort/widths/filter, last scan rows). Talks to the server ONLY through `ctx`.
- **Engine** RE-FORKED fresh from the desktop `.ps1` (the JANET ONE `.psm1` is a *bug-fix cross-check*, not the source). Exports the two contract functions verbatim. Desktop global scriptblocks (`$script:WptScanBlock`, ...) become RunspacePool worker blocks; the desktop WinForms Timer-drain becomes `-Emit` calls. **The engine never touches UI; it only emits.**
- **Contract** is reused verbatim -- adding a tool = a `tool-registry.json` row + a `.psm1` + a `.view.js`, **zero server changes**.

## 3. Cross-cutting components (the desktop-grade kit)

Per-tool views **compose** these; they do not reinvent them. This is how we get fidelity without a generic renderer.

| Component | Responsibility |
|---|---|
| **AppShell + StatusStripFooter** | Suite frame: brand band (operator/station, live clock, version chip), launcher hub (single vertical column of corner-bracket tool cards -- NOT a tile grid), global cred/session host, bottom status strip (SESSION + TARGETS + LOG path + heartbeat), guarded single Close-Tool egress. |
| **TabHost** | Panel-swap navigation host covering all desktop nav styles (hidden-header TabControl, sidebar, mode-radio field-swap, single-card-stack). Per-panel lazy build + **keep-alive** (a panel's grid/log/live run survives switching away). Session-gate locking of non-Start panels. |
| **CredSessionBar** | Set Credentials (server-side smartcard picker via `/api/cred`), status pill (inherited/explicit/current-Kerberos), responsibility-ack + START SESSION (`/session/start`), gate state mirroring the authoritative server flag, optional "use current session" toggle (dhcp). |
| **TargetManager** | First-class host-list panel: paste (line/comma/space), Import TXT/CSV/ACAS(Nessus)/XLSX(OOXML), exception list, live count, de-dupe, invalid-name rejection. Backs `ctx.targets`; supports shared-targets opt-in AND tool-owned bespoke target panels. `hostpick` single-host variant. |
| **RunBar** | Per-tool command bar: primary CTA (disable-on-launch, re-enable-on-final, optional **morph-to-Cancel**), secondary-button slot (Export/Pop-Out/Select-With-X), pre-flight guards (no targets / no creds / nothing selected). Wires CTA->`ctx.run()`, Cancel->`ctx.cancel()`. |
| **ConfirmDialog / ArmingDialog** | Themed modal (replaces raw MessageBox). Severity-scaled, restates host count + consequence + dry-run state. **ArmingDialog** adds typed-confirmation (STIG "APPLY"), elevation/restore-point/DSC-LCM pre-flight, danger banner. |
| **ResultsGrid** | Colour-coded per-entity DataGrid: one row per entity keyed **`_rk` \|\| host \|\| id** (upsert), driven by a **per-tool ColumnSpec** (`{key,label,width,type,colorRule(value,row)}`) with per-CELL and whole-ROW colouring. Checkbox-select + Select-All / Select-With-X / Select-Critical-High, clickable-header sort, drag-resize columns, `row.Tag` full-result cache, double-click RowDetail, **Pop-Out** floating window that keeps streaming. Type-aware, **NOT regex-on-name**. |
| **ActivityLog** | Colour-coded streaming console: mono near-black pane, `[HH:mm:ss] msg` per `log` event (OK/WARN/ERR/default), `=== banner ===` lines, auto-tail, right-click Clear/Copy-All/Save, re-parentable into a pop-out. |
| **ProgressStatusStrip** | Progress signal: `X / N` label that turns green on completion (canonical JANET indicator) + optional thin custom-fill bar (Value/Maximum) for STIG/secureboot/winupgrade + per-tab phase label + tri-state completion summary. |
| **StatCards** | Big-number metric tiles / hero-dashboard strip (eyebrow / mono number / caption / coloured top accent) recomputed live from run events or collection state, plus manually-drawn rate bars (Reports patch-rate). |
| **RunController** | Non-visual shared streaming client behind `ctx.run()`: POSTs the action, owns the per-run state, runs ONE `pollRun(key,gen)` ~400 ms with the generation guard, reduces `status/progress/row/log/audit/run/final`, buffers off-screen runs, exposes `subscribe(handlers)` so a bespoke view binds events to ITS components. Graceful cancel + `sendBeacon`-on-unload. **This is the keep-verbatim JANET ONE streaming model wrapped as a reusable controller.** |
| **ThemeKit + ControlFactory** | Shared JANET tactical look (purple `#8C64DC` + gold `#DAB452` on near-black, Cascadia Mono display + Segoe UI body, corner-bracket cards, pulse/heartbeat dots, striped CTA, scanline status strip) as CSS vars + styled primitives (button/ghost/label/input/card/pulse-dot/dark-titlebar). |

**The `ctx` object** handed to every `mount(host, ctx)`:
```
ctx.session     // gate state (ack, cred, mode), authoritative-server-mirrored
ctx.targets     // shared TargetManager model (opt-in per view)
ctx.run(actionId, params, opts)  // -> RunController run handle (subscribe to events)
ctx.cancel(jobId)
ctx.confirm(opts) / ctx.arm(opts)
ctx.components   // factories: ResultsGrid, ActivityLog, RunBar, StatCards, TabHost, ...
ctx.theme        // ThemeKit tokens + ControlFactory
```

## 4. The plugin contract (KEEP VERBATIM -- engines are reused, only the UI is rebuilt)

`modules/JanetTwo.<id>.psm1` exports exactly two functions:

1. **`Get-JanetToolManifest`** -> `@{ id; name; category; icon; summary; version?; statefulRunspace?; actions=@( @{ id; label; kind('stream-table'|'table'|'single'|'form'|'export'); destructive=$bool; description?; confirm?; inputs=@(@{name;type;required;default?;...}); columns=@('Col',...) } ) }`. Input `type` in `hostlist,text,textarea,int,bool,select,file,filelist,folder,savefile,hostpick,msi-checklist`. **In JANET TWO the manifest drives ROUTING + AUDIT + the confirm/destructive flags only -- the VIEW owns presentation.**
2. **`Invoke-JanetToolAction -ActionId -Params -Credential -Emit`** -> `@{ rows=@(...); summary=@{...} }`. Server injects `$Params['__job']` (synchronized job hashtable; engine polls `$job.Cancel`).

**Emit event vocabulary (unchanged):**
- `status{text}` -- phase / status line
- `progress{done,total}` -- X / N + bar
- `row{<columns> +optional _rk/id}` -- upsert into the view's grid
- `log{text,level}` -- colour-coded activity line
- `audit{action,target,result,itemCount,detail}` -> `Write-JanetAction` TouchHost/VulnPatched - Success/Failure/Skipped
- `run{scope,profile,mode,hostsTotal,success,failed,durationSec,groupKey,groupMembers}` -- ACAS Runs CSV
- `final{result}` (auto on return) / `error{text}` (server on throw)

**Streaming flow (unchanged):** action POST creates `$job` (synchronized `Events`, Status, Result, Cancel, StartedAt/FinishedAt) -> spawns a `[powershell]` worker on its own runspace (or the persistent per-tool STA runspace when `statefulRunspace`, serialized via Busy slot, 409 if busy) -> worker dot-sources logging, imports the module, builds `$Emit` (appends to `job.Events` + writes audit/run CSVs), runs `Invoke-JanetToolAction`, appends `final`, stamps FinishedAt. Client returns `{jobId}` and starts ONE `pollRun(key,gen)`; server returns `{status,nextSince,events[]}` with **status snapshot BEFORE events** so a terminal status never arrives without its final event.

## 5. How the activity run streams into a bespoke view

The view declares the event->component mapping (the stream is generic; the presentation is bespoke):

```
run = ctx.run('bulk-scan', { targets, threads }, { confirm })
run.subscribe({
  status:   t   => strip.setStatus(t),
  progress: p   => strip.setProgress(p.done, p.total),
  row:      r   => grid.upsert(r),         // keyed _rk||host||id, painted by THIS view's ColumnSpec
  log:      l   => activityLog.append(l),
  final:    f   => view.onComplete(f.result)   // re-enable, green status, summary cards
})
```

A card-per-item run (ACAS), a host-detail inspector (WPT), a pop-out log (ACAS/pkginstall), or a second live grid (Restart Reboot-Verification Monitor) are all just view-owned components fed by the SAME stream. **No per-view fetch/polling** -- everything goes through RunController so the JANET ONE guarantees (ordering, upsert key, generation guard, cancel, tab-switch survival) are preserved by construction.

## 6. Navigation & state model

- **Nav styles -> one panel-swap (TabHost):** WPT/STIG (hidden-header TabControl -> tab rail), ACAS/Reports/Restart (sidebar panel-swap), AD Search (mode radios -> field swap), single-window tools (pkginstall/message/dhcp/secureboot/winupgrade -> card stack).
- **Keep-alive:** a panel keeps its grid/log DOM and its live run when you switch away -- a running operation is never lost.
- **State split:** cross-tab shared state (targets, cred/session, an active run's results) lives on `ctx`; per-tab UI state (sort, widths, filter, active scan rows) lives on the view.
- **Gating:** server-side 403 until ack+cred for destructive actions is authoritative; the view mirrors it for UX. Read-only tools (AD Search) bypass cleanly.

## 7. Stack rules (non-negotiable)

- Windows **PowerShell 5.1 must parse everything**; PS7-compatible too.
- `.ps1`/`.psm1` saved **UTF-8 with BOM**; **source ASCII-only** (no smart quotes/em-dashes/box glyphs in source -- emoji icons live ONLY in `tool-registry.json` data).
- **Zero third-party software** (built-in .NET + cmdlets only; no PSGallery/npm/build step). Frontend is framework-free vanilla JS/CSS served as static assets.
- Remote scriptblocks pass values via `param()` + `-ArgumentList` (never `$using:`). Avoid the `"$var:..."` drive-qualified interpolation trap (`"$($var):..."`).
- **Parse + BOM + ASCII lint gate after EVERY engine edit:** `[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$null,[ref]$e); $e` + first-3-bytes == `EF BB BF` + non-ASCII scan.
- Server stays single accept-thread + 2 s heartbeat loop (Ctrl+C + reaper run with no traffic). Shared SMB workspace (`X:\`) -- coordinate destructive ops.
- **Do NOT modify `X:\J.A.N.E.T`** (desktop suite) -- reference only; tools were copied into `fork-source/Tools/`.

## 8. Build order (small representative tool first, heavies last)

0. **Plumbing lift + cross-cutting kit** -- rename `JanetOne.*` server/auth/logging -> `JanetTwo.*`, `Start-JanetTwo.ps1`, `tool-registry.json`, minimal `index.html`; build the full component library + view-registry + lazy loader; verify shell + stub view + mocked stream.
1. **Remote Message (REFERENCE TOOL)** -- small, self-contained, exercises the whole shared pipeline (TargetManager, RunBar morph-to-Cancel, ConfirmDialog, RunController parallel stream, ActivityLog, StatCards, ProgressStrip, Ping-All). **This is the blueprint every later tool copies.**
2. Secure Boot Enabler -- single-window card stack; ResultsGrid status-pill rows + custom progress bar + completion modal + Start-Job-queue run variant.
3. DHCP Scope Options -- dual-workflow window, "use current session" toggle, detailed-diff confirm, synchronous batch replayed into ActivityLog.
4. AD Search -- read-only path (gate bypass), mode-radio field-swap, async single-shot runspace, per-mode grid rebuild + RowDetail popup.
5. Windows Upgrade -- worker-never-touches-UI + ConcurrentQueue drain, reboot-warning confirm, cooperative Cancel, Computer/Ping/Status/Detail grid.
6. Remote Package Installer -- in-place row lifecycle (Queued->Probing->Copying->Deploying->terminal), Pop-Out grid, RowDetail stdout, Retry-Failed, sidebar tallies.
7. Unsupported Product Remediator -- two-stage Scan->Uninstall, proven-EOL gated rows, dry-run default, catalog ingestion (WPT fan-out warm-up).
8. Remote Restart Scheduler -- 3-tab workflow, 9-cell live StatCards bar, burst/time-gated/rolling, consent flow, Cancel-Pending vs Abort, auto-opening Reboot Verification Monitor (second live grid).
9. ACAS Nemesis -- card-per-vulnerability, Run/Verify/Run-All/Bulk-Run on shared RunController, pop-out re-dockable log, hero tiles, KB Installer.
10. **Workstation Patching (THE BIG ONE)** -- 17 tabs, canonical Bulk grid, all sub-views, Host-Details inspector, Reboot Monitor, Reports stat cards + Action History. Built late on a battle-tested kit.
11. Reports -- 9-section sidebar, **stateful runspace** (parse/scan state via Busy-slot persistent STA runspace), import/triage/dashboard/Dirty-30/CrossRef/export.
12. STIG -- built LAST: 10-tab lifecycle, synchronous run mapped onto streaming, custom progress bar, heaviest **ArmingDialog** gating (typed-APPLY, elevation, restore-point, DSC LCM, reboot-pending), per-rule Review grid w/ editable CKL metadata, DISA exports, stateful runspace.

## 9. Risks & mitigations

1. **Cookie-cutter creep** (rebuilding the generic renderer in disguise) -> hand-author the first tool bespoke; code-review every view for real desktop-faithful tabs/toolbars/grids; ColumnSpec colour rules hand-written per column, never regex-on-name; manifest = routing/audit only.
2. **No live remote validation from dev box** -> JANET ONE `.psm1` behavioural cross-check; unit-test pure helpers; mock `window.fetch` (POST + events) for the client pipeline; flag on-AFNET validation as an explicit handoff step.
3. **PS 5.1 / BOM / ASCII regressions** -> parse+BOM+ASCII lint gate after every engine edit; no glyphs in source.
4. **Streaming re-implemented per view & drifting** -> forbid per-view polling; all runs through RunController; keep status-before-events ordering, `_rk||host||id` upsert, generation guard verbatim.
5. **Grid row-identity collisions** (multi-row-per-host missing `_rk`) -> ResultsGrid requires explicit `keyMode`; specs with `hostCol != Host` must emit `_rk`; dev-time duplicate-key assert.
6. **Scope explosion on heavy tools** -> front-load small tools to harden the kit; WPT/Reports/STIG last; reuse the stateful Busy-slot model verbatim.
7. **Credential picker needs an interactive desktop** -> keep the `UserInteractive` bail + clear message; document launch-from-console; read-only tools stay usable on Kerberos.
8. **Monolithic `app.js` returning** -> one file per tool under `web/js/views/`, lazy-loaded; shared logic only in components; no view imports another view.
9. **Runspace/poller leaks via bespoke views** -> views never own runspaces (server does) or pollers (RunController does); reaper + 5-min eviction + Busy-slot freeing stay server-side; pop-out windows reparent the SAME DOM, they don't start a second run.

## 10. Definition of done (per tool)

A tool is done when: its view reproduces the desktop tool's **tabs/toolbars/run controls**; the **live activity run** matches the desktop feel (activity log + colour-coded grid + progress + per-host rows + confirm/arming); the engine **parses on 5.1, is UTF-8 BOM + ASCII source**, and emits the full event vocabulary; the client pipeline is **mock-verified end-to-end**; and remote-exec paths are flagged for **on-AFNET live validation**. Parity is feature-for-feature (per the JANET ONE-parity rule) -- no partial ports, no "optional follow-ups".

---

## 11. Next-session kickoff -- concrete Phase 0 checklist

Phase 0 stands up the plumbing + the shared kit with **no tool yet**, verified against a mocked job stream. Do it in order; run the parse+BOM+ASCII gate after every `.ps1`/`.psm1` edit. Commit small (per component / per tool) and push to `bth0mp/J.A.N.E.T-TWO` as you go.

**0a. Lift the plumbing (rename only -- do NOT redesign):**
- [ ] `X:\J.A.N.E.T ONE\server\JanetOne.Server.ps1` -> `server\JanetTwo.Server.ps1`; rename `JanetOne*` identifiers/log prefixes to `JanetTwo*`; keep every route + the token / reaper / runspace-streaming logic otherwise byte-identical.
- [ ] `JanetOne.Auth.ps1` -> `server\JanetTwo.Auth.ps1`; `JanetOne.Logging.ps1` -> `server\JanetTwo.Logging.ps1` -- KEEP the same central-CSV share/schema so JANET TWO rows merge with the suite (do NOT fork the log location).
- [ ] `Start-JanetOne.ps1` -> `Start-JanetTwo.ps1` (default port **8089** so it doesn't clash with JANET ONE's 8088); `Launch JANET ONE.cmd` -> `Launch JANET TWO.cmd` (keep the conhost pin + Unblock-File self-heal).
- [ ] New `server\tool-registry.json`: all 12 tools, `ported:false` initially (flip per tool as built).
- [ ] VERIFY: `Start-JanetTwo.ps1` boots, serves a stub `web\index.html`, `GET /api/tools` returns the registry, the `?t=` token gate works.

**0b. Build the cross-cutting kit (the desktop-grade components):**
- [ ] `web\css\janet.css` = **ThemeKit** (port the JANET tactical tokens -- the shared look).
- [ ] `web\js\shell.js` = **AppShell** + router + **view-registry** (`JanetViews.register(id,{mount,unmount})`) + lazy loader + the `ctx` object + **RunController** (extract the JANET ONE `app.js` streaming client: POST action, ONE `pollRun(key,gen)` ~400ms, generation guard, status-before-events ordering, `_rk||host||id` upsert, graceful cancel + `sendBeacon`). RunController is the ONLY code that fetches/polls.
- [ ] `web\js\components\`: ControlFactory, CredSessionBar, TargetManager, RunBar, ConfirmDialog (+ArmingDialog), ResultsGrid (ColumnSpec-driven, type-aware colour rules, explicit `keyMode`), ActivityLog, ProgressStatusStrip, StatCards, TabHost.
- [ ] VERIFY with a STUB view + a **mocked job stream** (mock `window.fetch`: `POST /api/tool/.../action/...` -> `{jobId}`; `GET /api/job/<id>/events` -> a scripted `status`/`row`/`log`/`final` sequence) so every component renders a live run with no real engine.

**0c. Build step 1 = Remote Message (THE REFERENCE TOOL):**
- [ ] Re-fork `fork-source\Tools\RemoteMessageTool_1.3.3.ps1` -> `modules\JanetTwo.message.psm1` (cross-check `X:\J.A.N.E.T ONE\modules\JanetOne.message.psm1`); export the two contract functions; the desktop send-loop becomes a RunspacePool worker that `-Emit`s `row`/`log`/`progress`/`audit`.
- [ ] Build `web\js\views\message.view.js` per `docs\ui-specs\message.md`: three-column dashboard (TargetManager + composer + ActivityLog), RunBar CTA morph-to-Cancel, ConfirmDialog, StatCards (Sent/Failed/Total), Ping-All pre-flight.
- [ ] Flip `message` -> `ported:true`; verify end-to-end on the mocked stream; flag remote-exec for on-AFNET validation. **Lock this view in as THE pattern**, then replicate for the other 11 in build-order.

**Phase 0 done when:** shell + kit + RunController render a mocked live run, Remote Message works end-to-end (mocked), and the parse/BOM/ASCII gate is green.

---

### Appendix A -- File map (target)
```
J.A.N.E.T TWO\
  Start-JanetTwo.ps1
  server\  JanetTwo.Server.ps1  JanetTwo.Auth.ps1  JanetTwo.Logging.ps1  tool-registry.json
  modules\ JanetTwo.<id>.psm1   (x12, RE-FORKED from fork-source\Tools)
  web\
    index.html
    css\  janet.css   (ThemeKit)
    js\
      shell.js        (AppShell, router, view-registry, RunController, ctx)
      components\     (TabHost, CredSessionBar, TargetManager, RunBar, ConfirmDialog,
                       ResultsGrid, ActivityLog, ProgressStatusStrip, StatCards, ControlFactory)
      views\          (<id>.view.js  x12 -- bespoke, lazy-loaded, one per tool)
  fork-source\        (read-only fork basis: JANET.ps1, JANET_Config.json, Tools\*.ps1)
  docs\               (HANDOFF.md, REVIEW.md, ui-specs\<tool>.md)
```

### Appendix B -- Reference artifacts (in place, do not modify)
- Plumbing to lift: `X:\J.A.N.E.T ONE\server\JanetOne.Server.ps1`, `JanetOne.Auth.ps1`, `JanetOne.Logging.ps1`.
- Streaming/contract reference: `X:\J.A.N.E.T ONE\web\js\app.js` (the renderer to NOT copy; the streaming client to extract into RunController).
- Engine cross-checks (bug-fixed, not the fork source): `X:\J.A.N.E.T ONE\modules\JanetOne.<id>.psm1`.
- Fork source of truth: `X:\J.A.N.E.T TWO\fork-source\Tools\*.ps1` (desktop WinForms tools).
- Per-tool faithful UI specs to author next: `X:\J.A.N.E.T TWO\docs\ui-specs\<tool>.md`.