# JANET Web - View Authoring Contract

How to write a faithful per-tool view (`web/js/views/<id>.view.js`) that composes the
shared kit. Read this + the tool's `docs/ui-specs/<id>.md` + its engine manifest
(`modules/JanetWeb.<id>.psm1` -> `Get-JanetToolManifest`) + the three reference views
(`web/js/views/message.view.js`, `secureboot.view.js`, `dhcp.view.js`) before building.
Vanilla JS, no build step, no frameworks.

## Registration

```js
(function () {
  'use strict';
  JanetViews.register('<id>', {
    mount: function (host, ctx) { /* build DOM into `host`; stash refs on `this` */ },
    unmount: function () { /* unsubscribe + remove root */ }
  });
})();
```

## The `ctx` object (handed to mount)

- `ctx.toolId`, `ctx.toolName`, `ctx.manifest` (the tool's manifest object, or null)
- `ctx.ui` - ControlFactory (themed primitives, below)
- `ctx.components` - the component kit (below)
- `ctx.util` - helpers (below)
- `ctx.session` - `.state` = `{ ack, credSet, active, adOnly, user, mode, logRoot, onShare, localOnly }`;
  `.onChange(fn)`, `.setCred()`, `.clearCred()`. **Do NOT build a credential control - it is universal in the shell header.** Views only READ `ctx.session.state.credSet` (e.g. a destructive-action guard).
- `ctx.run(actionId, params, opts)` -> run handle. **The ONLY way to talk to the server. Never fetch/poll.**
  - `opts.keyOf(ev) -> key` - CRITICAL: when the engine streams multiple rows that share the same
    `Host`/server value (e.g. one row per scope/app/vuln), pass `keyOf` so RunController keys rows by
    the real per-row id (else all rows collapse into one). Default key is `_rk || Host || host || id`.
  - `opts.destructive` - defaults from the manifest action's `destructive` flag.
  - handle: `{ key, state, subscribe(handlers) -> unsubscribe, cancel() }`
    (audit 2026-07-25: this used to document a `jobId` ON THE HANDLE. There is none -
    `makeHandle` never exposed it. The job id lives on the run-state: `handle.state.jobId`.)
  - `handle.state` = the live run-state `{ rows:{}, order:[], log:[], status, progress, done, total, active, ... }`
  - `handle.subscribe(handlers)` replays current state immediately, then streams. Handlers (all optional):
    `reset(rs)`, `status(text)`, `progress({done,total,pct})`, `row(rowData)`, `log({text,level})`,
    `error({text})`, `final(result)`, `active(bool)`.
    (audit 2026-07-25: an `audit(ev)` handler was documented here but is dispatched NOWHERE -
    `reduce()` has no `audit` case. A view that registered one would simply never be called.)
- `ctx.confirm(opts) -> Promise<bool>` - themed modal. `{ title, body (HTML ok), list:[lines], okText, cancelText, danger }`.
  `cancelText:null` => one-button notice (resolves true on OK). Use for validation notices + Yes/No confirms.
- `ctx.arm(opts) -> Promise<bool>` - danger ArmingDialog. `{ title, body, banner, preflight:[{label,ok}], confirmWord, okText, cancelText }`.
  `confirmWord` requires the operator to type it (e.g. STIG "APPLY") to enable the go button.

## `ctx.util`

`el(tag,cls,txt)`, `qs(sel,root)`, `sleep(ms)`, `fileStamp()`, `clockStr()`,
<!-- audit 2026-07-25: `clickable(node,fn,opts)` was listed here and does not exist anywhere in
     web/js. The only occurrences of the word are comments and the `is-clickable` CSS class. -->

`parseHosts(text)->[]` (dedup), `targetModel(initial)` (a DOM-free host-list model),
`downloadBlob(name,mime,content)`, `buildXlsx(headers,rows,sheet)->Uint8Array`,
`downloadXlsx(filename,headers,rows,sheet)`.

## `ctx.ui` (ControlFactory) - themed primitives

`button(label,{variant:'gold'|'go'|'danger'|'cyan'|'ghost', size:'sm', title, onClick, disabled, type})`,
`ghostButton(label,opts)`, `ctaButton(label,{title,onClick})` (big striped CTA),
`input({type,value,placeholder,title,onInput})`, `textarea({value,placeholder,rows,onInput})`,
`number({value,min,max,step,title,onInput})`, `select({options:[{value,label}]|[str], value, onChange})`,
`checkbox(labelText,{checked,onChange,color,title})` -> a `<label>` with `._cb` (the input),
`label(text)`, `field(labelText,control,hint)`, `sectionHeader(text)`, `eyebrow(text)`,
`card({title,pad})` (corner-bracket panel), `dot(state)`, `pill(text,cls)`.

## `ctx.components` - the kit (compose these; do not reinvent)

- **ResultsGrid**`({ columns, keyMode, selectable, rowClass(row), onRowClick(row), title, popOut, toolbarButtons:[btn] })`
  -> `{ el, upsert(row), clear(), rows(), order(), getChecked(), selectAll(on), selectWhere(fn) }`.
  (audit 2026-07-25: `setSort(key,dir)` was documented here and has never existed. Sorting is
  driven by the clickable column header only.)
  - column: `{ key, label, width, type:'text'|'bool'|'status', render(row)->cell, colorRule(value,row)->cssClass, sortVal(row), title }`
  - cell: `{ text, cls:'st-ok'|'st-bad'|'st-warn'|'st-info'|'cell-dim', title, bar:{pct,cls} }`. Colour is HAND-WRITTEN per column (colorRule/render), never regex-on-name.
  - keyMode: `{ rk:true }` (use `_rk`) | `{ hostCol:'Host' }` | a `function(row)->key`. **Match the keyOf you pass to ctx.run.**
  - rowClass(row) -> `'row-ok'|'row-bad'|'row-warn'|''` for whole-row tint.
- **ActivityLog**`({ title, defaultName, toolbar })` -> `{ el, pane, append({text,level}), banner(text), clear(), copyAll(), save() }`.
  levels: `ok` (green), `err` (red), `warn`/`amber`, `info`/`mode` (cyan), `banner`/`gold` (gold), `accent` (purple), `diag`/`dim` (grey).
- **StatCards**`({ cards:[{key,label,color:'ok'|'bad'|'gold'|'cyan'|'accent', value}] })` -> `{ el, set(key,v), setAll(obj), reset() }`.
- **ProgressStatusStrip**`({ showCount, showBar, phase })` -> `{ el, setProgress(done,total), setPct(pct), setPhase(text), reset() }`. The count greens at done>=total.
- **TargetManager**`({ model, hint, placeholder, importLabel, importAccept, pingAll, onPingAll, onImport(n,name), onClear, countNoun, max })`
  -> `{ el, model, hosts(), count(), getText(), setText(t), focus(), setPingEnabled(on), setPingLabel(txt) }`. Pass `ctx.util.targetModel('')` for a tool-owned list.
- **RunBar**`({ label, cancelLabel, morphToCancel, title, guards:[()->msgOrNull], onGuardFail(msg), onRun, onCancel, secondary:[btn], cta:bool })`
  -> `{ el, cta, setActive(on), setStatus(txt,cls) }`. Guards run before onRun; return a message string to block (the view shows it via onGuardFail).
  (audit 2026-07-25: `secondary`, `setLabel(txt)` and `attach(handle)` were all documented as
  returned members. `runbar.js` returns four members and never has returned those three.)
- **ConfirmDialog** / **ArmingDialog** - usually via `ctx.confirm` / `ctx.arm`.
- **TabHost**`({ rail:'left'|'top', tabs:[{ id, label, build(panelEl, tabApi), locked }], onTab(id) })`
  -> `{ el, select(id), setLocked(id,on), setBadge(id,text), activeId() }`. Panels build lazily on first open and KEEP ALIVE (DOM + live runs survive tab switches). Use for multi-tab/multi-screen tools.

## Run pattern (every action)

```js
var handle = ctx.run('<actionId>', { /* params matching the manifest inputs */ }, { keyOf: function(ev){ return ev.<RowKey> || ev.Host; } });
handle.subscribe({
  status:   t => prog.setPhase(t),
  progress: p => prog.setProgress(p.done, p.total),
  row:      r => grid.upsert(r),          // colour via the grid's ColumnSpec
  log:      l => activityLog.append(l),
  final:    res => { /* summary / re-enable */ },
  active:   a => runbar.setActive(a)
});
```

## Rules (non-negotiable)

1. **No per-tool credential control** - the shell header owns the single universal Set Credentials.
   Destructive actions guard on `ctx.session.state.credSet` and confirm via `ctx.confirm`/`ctx.arm`.
2. **No fetch/poll in the view** - all server I/O via `ctx.run`. The view only `subscribe`s.
3. **Multi-row-per-host grids** - pass `keyOf` to `ctx.run` AND a matching `keyMode` to ResultsGrid.
4. **Faithful to the ui-spec** - reproduce the desktop tool's screens/tabs/run-controls/activity view.
   Use TabHost for tabbed tools; ResultsGrid for result grids; ActivityLog for streaming consoles.
5. **Action ids / param names / columns come from the engine manifest** (`Get-JanetToolManifest`). Read it.
6. **Compose the kit; match the look** - no bespoke palette; reuse `ctx.ui`/`ctx.components`.
7. The view must `mount()` without throwing and clean up in `unmount()` (unsubscribe + remove its root).
