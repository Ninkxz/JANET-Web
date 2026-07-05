# JANET Web - Session 4 Handoff (ponytail-audit applied + UI density/log-drawer pass)

State as of 2026-06-19. The session that ran a whole-repo over-engineering audit and
applied it, then did a UI pass: fill the browser window + a click-to-open bottom
activity-log drawer across the suite. Read this + the `project-janet-two` and
`project-janet-two-ui-pass` auto-memories to continue. Prior handoffs:
`docs/SESSION-3-HANDOFF.md` (review-pass-complete state), `docs/VIEW-CONTRACT.md` (kit API).

## Where the project stands

- **Suite is still 11 tools** (no tools added/removed this session): wpt, acas, pkginstall,
  winupgrade, upr, secureboot, restart, message, adsearch, dhcp[beta], reports[stateful].
- **Git**: branch `main`, everything pushed to `bth0mp/J.A.N.E.T-TWO` (HEAD `1540127`). Tree clean.
- Net this session: 24 files, +163 / -289 lines.

## What this session did (commit by commit, all on origin/main)

**A. /ponytail-audit applied** (whole-repo over-engineering hunt; 27 findings, 25 applied, 2 declined):
- `5d75add` engines dead code: reports `Write-JanetDebug` no-op stub + 11 calls; write-only
  `Baseline/ComparisonSourceFile`; unreachable `TargetVersionOverrides` branch. pkginstall: removed
  the uninvoked `export-results` action (manifest+function+dispatch). message: dead `requirePing`
  param + `threads` override. adsearch: redundant `cleanList` rebuild. upr: uninvoked
  `Get-UprCandidateAction`. wpt: uninvoked `$script:WptSessionSplat`.
- `605ab9d` web dead code: shell.js `Janet.util.clickable`, `Janet.theme`, `RunController.anyActive`/
  `.subscribe`; promoted `esc` -> `Janet.util.esc` and aliased the 10 view copies; progressstrip
  `setPct`; runbar `attach`; wpt.view `successDetailColumns/RowClass`, collapsed `annotateBulkRow`
  if/else, removed inert `destructive:true`; acas.view `doBulk` inline + dead `lastSummary`;
  upr.view `selectedFinding.category/.rk`; adsearch.view `dim`.
- `9b14383` acas `import-acas` reuses the shared `ConvertFrom-AcasCsv` (per source; run-verified).
- `ee3a940` reports: marked the two probe loops as intentional mirrors (DECLINED the fanout dedup).
- **2 DECLINED (documented with `ponytail:` comments in-code):** (1) restart's duplicated remote
  shutdown scriptblock - site 1 runs inside a `CreateDefault()` runspace worker with no module
  scope, so a shared `$script:` block would be `$null` there and BREAK reboot. (2) reports
  `Invoke-JanetHostFanout` - the two parallel-runspace loops differ in all 4 exit paths
  (rows/counters/audit/LastUser-map); a callback fanout would bury the cancel/deadline contract on
  the riskiest path for zero behavior gain. The prior author deliberately mirrored them.

**B. UI density + activity-log drawer pass:**
- `a14898e` **viewport fill (universal CSS)** + WPT run-tabs log moved full-width to the bottom.
- `ac21f51`/`ddafd92` log docked full-width at the bottom of all single-screen tools (message,
  dhcp, winupgrade, adsearch, pkginstall).
- `7d43d9c` -> `9ce3aa4` -> `b8f1961` the bottom log became a **click-to-open drawer** (tried
  auto-expand-on-run first; user wanted click instead): compact ~57px bar with a live latest-line
  peek, the WHOLE bar clickable, expands to a 340px full-width scrollable pane, collapses on click.
- `717695a` fixed the open pane shrinking to content width (dock must be `flex-direction:column`);
  made content-heavy WPT tabs (Software Manager / Center) scroll instead of cramming
  (`min-height:100%` lays + grid `min-height`); converted Reboot/Message tab logs to drawers.
- `1540127` acas shared log moved to a root-level drawer below the TabHost (visible on every tab).

## The UI architecture (carry forward)

- **Viewport fill** is CSS-only in `web/css/janet.css`: `.j-tabhost` grows to fill `#j-view-host`
  width; `.j-tabpanels` is a flex column so the active `.j-tabpanel` fills height; `.j-grid-wrap`
  fills its holder width. Don't regress these.
- **The log drawer** is the `.j-logdock` CSS class + a hook in `web/js/components/activitylog.js`:
  the component toggles `is-open` on its nearest `.j-logdock` ancestor (whole `.j-al-toolbar` is
  clickable; Clear/Copy/Save are excluded). Collapsed = `flex:0 0 auto` (~57px bar) with a peek
  span; open = `flex:0 0 340px` full-width scrollable pane. **No-op when a log isn't inside a
  `.j-logdock`** (so undocked tabbed-tool logs are unaffected).
- **To dock a tool's log:** put its log card-> add class `j-logdock` (drop the inline fixed
  `flex:0 0 NNNpx`), append it to the view ROOT below the work content (above any footer). For a
  tabbed tool, dock ONE shared log at the root below the TabHost (see acas.view.js).
- **GOTCHA (bit us twice):** if the `.j-actlog` is wrapped in a holder div inside the dock, BOTH
  the `.j-logdock` AND the holder must be `flex-direction:column`, or the log pane shrinks to its
  content width instead of filling. (Other tools append `log.el` directly to the dock card.)

## Locked rules (do not regress - same as Session 3)

1. Universal credentials - ONE Set Credentials in the shell header; no per-tool cred control.
2. All runs via `ctx.run` -> RunController; views never fetch/poll. Multi-row-per-host grids pass
   `keyOf` to `ctx.run` AND a matching `keyMode` to ResultsGrid.
3. Engines `.ps1`/`.psm1` are UTF-8 **with BOM + ASCII-only**; PS 5.1 must parse. Run the
   parse+BOM+ASCII gate after EVERY engine edit. (`.js`/`.css` are NOT BOM/ASCII-gated - vanilla
   JS, UTF-8; the codebase already uses Unicode in JS, e.g. tile emoji + the drawer chevrons.)
4. Do NOT modify `X:\J.A.N.E.T` or `X:\J.A.N.E.T ONE`. Shared SMB drive - coordinate destructive ops.
5. Push with a one-time `git -c http.extraHeader="Authorization: Basic <base64 bth0mp:token>"
   push origin main`; keep creds OUT of `.git/config`. Owner pastes the token.
6. Launch via `Launch JANET Web.cmd`.

## LESSONS (new this session)

- **CSS is browser-cached.** `_devtest.html?cb=<n>` only busts the HTML; `<link href=janet.css>` is
  NOT cache-busted, so a CSS edit needs a HARD refresh (Ctrl+Shift+R) or you see new JS against old
  CSS = broken layout. In the preview, force it via `link.href='/css/janet.css?cb='+Date.now()`
  after each reload. (Open item: consider versioning the CSS link so operators never hard-refresh.)
- **The X: SMB share can drop mid-session.** When `\\192.168.1.2\code` disconnects, the working dir
  vanishes and EVERY shell command (Bash + PowerShell) returns exit 1 with no output - it's not the
  command, it's the mount. Reconnect with `net use X: \\192.168.1.2\code`. Nothing was lost (file
  edits are on the share; only git commit/push needs the drive).
- **Flex pane-shrink:** a flex item with no width directive inside a `display:flex` ROW shrinks to
  content width. The fix everywhere was `flex-direction:column` on the container (see the GOTCHA above).
- **Devtest mock catalog is partial.** `_devtest.html` REGISTRY has only: _stub, message, secureboot,
  dhcp, winupgrade, wpt, acas, restart, reports. **adsearch, pkginstall, upr are NOT mocked** - they
  can't be driven on :8091; they get static review + `node --check` only.

## Verification cadence (what works)

- JS: `node --check web/js/...` catches syntax. Then drive via the Claude Preview MCP against the
  `janet-two-dev` python static server on **8091** (`X:\.claude\launch.json`), URL
  `http://127.0.0.1:8091/_devtest.html?cb=<n>`; re-point the CSS link to bust the cache; `preview_eval`
  for DOM read-outs + an in-page error trap. `preview_screenshot` still hangs - use eval measurements.
  Devtest cred gate: click "Set Credentials" in the header (mock-sets credSet) to get past run guards.
- Engines: after every edit run the gate -
  `[System.Management.Automation.Language.Parser]::ParseFile` (0 errors on PS 5.1) + first 3 bytes
  == EF BB BF + non-ASCII scan == 0.

## What remains

1. **Finish the log-drawer rollout** on the last TWO tabbed tools: **restart** (it has TWO logs -
   dispatch + monitor; live-verifiable, it's in the devtest catalog) and **upr** (NOT in the catalog
   -> static review + `node --check`). Dock pattern = acas.view.js (root-level `.j-logdock` below
   the TabHost; remember the holder-must-be-column gotcha).
2. **On-AFNET live validation** of the remote-exec paths - unchanged from Session 3 (the real test
   of the derived engines; the 2 declined audit items are both on remote paths and changed NO behavior).
3. Optional: cache-bust the production `janet.css` `<link>` so operators don't have to hard-refresh.
