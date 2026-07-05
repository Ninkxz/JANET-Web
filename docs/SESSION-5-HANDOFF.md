# JANET Web - Session 5 Handoff (desktop-parity restoration + ponytail cut + launcher icons)

State as of 2026-06-20. This session ran a full desktop->TWO **parity audit** (all 11
tools vs their desktop originals), restored every high/medium-value gap it found,
applied one ponytail-audit cut, and reskinned the launcher. Read this + the
`project-janet-two`, `project-janet-two-parity`, and `project-janet-two-ui-pass`
auto-memories to continue. Prior handoffs: `docs/SESSION-4-HANDOFF.md` (UI/log-drawer
pass + ponytail-audit), `docs/VIEW-CONTRACT.md` (the kit API), `docs/SESSION-3-HANDOFF.md`
(earlier review history).

## Where the project stands

- **Still 11 tools** (wpt, acas, pkginstall, winupgrade, upr, secureboot, restart,
  message, adsearch, dhcp[beta], reports). STIG remains intentionally dropped.
- **Git**: branch `main`, everything pushed to `bth0mp/J.A.N.E.T-TWO`, **HEAD `1995e44`**,
  tree clean. Session start was `03161aa`.
- The desktop originals in `X:\J.A.N.E.T\Tools\` are untouched (read-only reference).

## What this session did (commit by commit, all on origin/main)

**A. Parity audit + restoration** (desktop tools vs TWO; ~88% parity found, all high/med
gaps now closed):
- `1a5ba93` finish the log-drawer rollout (restart's 2 logs + upr) - last item from session 4.
- `ebe0b19` acas: **reboot cards** (manifested the dormant `schedule-reboot`/`verify-post-reboot`
  engine actions; Reboot-category cards render Reboot Now/Verify + editable warning) + auto-patch
  Incl-Experimental / Prefer-Software-Center options.
- `c7c4cb0` acas: REBOOT summary tile + Copy Plan on unpatchable cards. (Per-finding selection
  gate deliberately NOT built - ponytail comment in `buildVulnsTab`: card-level gating covers it.)
- `9903aed` reports: **Download XLSX** on every export (ArtifactBar chokepoint -> all reports).
  AFNET-safe: client-side `Janet.util.buildXlsx`, NOT ImportExcel.
- `2cec5ca` reports: Dashboard aggregate metric cards + patch-rate bar (summed client-side from
  the per-host rows).
- `193c945` upr: **operator-editable catalog** - `Get-UprCatalog` reads `<root>\JanetLocal\
  UnsupportedProductCatalog.json` ($PSScriptRoot-resolved) with embedded-default fallback, read
  per-call; + `reload-catalog` action + Reload button. (Was hard-coded/inert.)
- `b8197ec` restart: exception list **persists** (localStorage) + Import CSV + Clear.
- `a110fb3` wpt: post-reboot **monitor after Bulk "Reboot Selected"** (refactored `startMonitor(hostsArg)`,
  exposed via a mount-level ref; offers "Monitor reboots?" -> switches to Reboot Countdown tab).
- `50a5974` wpt: **Import ACAS CSV** on the Targets tab (host-column auto-detect:
  NetBIOS>DNS>Host>Hostname>IP, never bare "Name"; FQDN->short; dedup).
- `2a4546e` adsearch: Base Users export splits into PRIVILEGED + STANDARD CSVs.
- `b3eab47` wpt: App Updater **Apply to Selected** (verify grid selectable -> apply to checked subset).

**B. ponytail-audit cut:**
- `0f3b3a0` consolidate all hand-rolled CSV into **`Janet.util.parseCsv` / `Janet.util.toCsv`**
  (web/js/shell.js, next to parseHosts/downloadBlob/buildXlsx). Collapsed ~11 call sites; removed
  local parseCsv/parseCsvLite/csvOf + every inline quote-join. Net ~-30 lines.

**C. New shared capability + features:**
- `7fe4211` **`ResultsGrid.setFilter(predicate)`** - hides non-matching rows in place; composes with
  upsert/sort/select; counter shows "N shown / M". No-op when unset (every existing grid unchanged).
  First caller: reports ACAS-Import Severity + free-text filter.
- `fd59ed2` wpt Software Manager quick-filter dropdown (2nd `setFilter` caller).
- `cc57ec6` shell launch-gate **"AD Search (read-only)"** button - 3rd gate action; read-only bypass
  straight into AD Search (no cred/admin session), mirrors JANET ONE. Sets `adOnly` then `openTool('adsearch')`.
- `1995e44` launcher **uses the original WPT icon set** - Segoe MDL2 Assets glyphs (the exact registry
  WPT's sidebar nav uses) instead of emoji. `tool-registry.json` stores the MDL2 codepoint as a HEX
  string (keeps JSON ASCII); `shell.js` `iconGlyph()` converts hex->glyph (non-hex like emoji renders
  verbatim - back-compat); CSS `.j-tc-icon`/`.j-th-icon` -> font-family 'Segoe MDL2 Assets', gold.
  Icon map: wpt E895, acas EA18, pkginstall E7B8, winupgrade E898, upr E74D, secureboot E72E,
  restart E7E8, message E8BD, adsearch E721, dhcp E703, reports E9D9.

## New patterns/capabilities to reuse (carry forward)

- **CSV: never hand-roll.** Use `ctx.util.parseCsv(text)->{headers,rows}` and
  `ctx.util.toCsv(headers, rows[, keys])` (rows = value-arrays OR objects+keys).
- **Grid filtering:** `grid.setFilter(fn)` (fn(row)->bool; null clears). Hides rows in place.
- **Launcher icons:** add a tool's icon as a Segoe MDL2 Assets hex codepoint in
  `server/tool-registry.json` (+ the `_devtest.html` catalog to keep dev in sync). WPT's full
  glyph registry is in `X:\J.A.N.E.T\Tools\WorkstationPatchingTool_6.5.22.ps1` ~line 2907.
- **Read-only gate bypass:** gate buttons set `Session.adOnly` then optionally `openTool(<tool>)`.

## Locked rules (do NOT regress)

1. Universal credentials - ONE Set Credentials in the shell header; no per-tool cred control.
2. All runs via `ctx.run` -> RunController; views never fetch/poll. Multi-row-per-host grids pass
   `keyOf` to ctx.run AND a matching `keyMode` to ResultsGrid.
3. Engines `.ps1`/`.psm1` are UTF-8 **with BOM + ASCII-only**; PS 5.1 must parse. Run the
   parse+BOM+ASCII gate after EVERY engine edit. (`.js`/`.css`/`.json` are NOT BOM/ASCII-gated -
   but keep `tool-registry.json` ASCII by using HEX icon codes, not raw glyphs.)
4. Do NOT modify `X:\J.A.N.E.T` or `X:\J.A.N.E.T ONE`. Shared SMB drive - coordinate destructive ops.
5. Push with a one-time `git -c http.extraHeader="Authorization: Basic <base64 bth0mp:token>"
   push origin main`; keep creds OUT of `.git/config`. Owner pastes the token per session.
6. Launch via `Launch JANET Web.cmd`.

## LESSONS (new this session)

- **shell.js + web/js/components/*.js are cached BOOTSTRAP scripts** (static `<script>` in the page).
  The dev-preview browser caches them HARD - a view edit (`web/js/views/*.view.js`) reloads on
  navigation, but a `shell.js`/`resultsgrid.js`/`xlsx.js` edit does NOT show on a normal reload.
  To verify a bootstrap/component edit: fetch the served file (`XHR /js/...?cb=`) + string-check it,
  unit-test the logic inline, or eval the served component to redefine it, then SPA-navigate (no
  full reload). A production launch always gets fresh files. Operators with the app open need a refresh.
- **devtest catalog != production catalog.** `_devtest.html` has its OWN inline tool catalog (and it
  does NOT include adsearch/pkginstall/upr). The real catalog is `server/tool-registry.json`. Keep
  them in sync for launcher-level changes (icons), and temp-add a tool to the devtest catalog to drive
  an open-path test, then revert.
- **Verify-by-temp-mock pattern works well:** to exercise an unmocked engine action in devtest, add a
  handler/row to `_devtest.html` temporarily, drive it, then REVERT (confirm `git status` clean before commit).
- ponytail call held: stopped restoring at the value line (remaining items are low-value/covered/
  remote-unverifiable) rather than build polish to fill time.

## What remains (all LOW-value / covered / deferred - confirm before building)

- **On-AFNET live validation** of the remote-exec paths - the real outstanding test; only the owner
  can run it. The 2026-06-19 declined audit items + all new remote work need this pass.
- **restart**: WinRM `LastBootUpTime` verify fallback - DEFER to the AFNET pass (remote, not
  devtest-verifiable, enhancement over the working ping verify). Compute/Save-Plan + split-targets -
  covered by dry-run + the results-CSV export.
- **wpt**: Log4j jar-source field (needs an engine param); SCCM App Manager quick-filter (cheap now
  via `setFilter`); Usage Publish-Now (session auto-publishes server-side); App Manager handoff.
- **pkginstall**: editable package root persistence - COVERED by the existing "Custom package path" field.
- **reports tail**: ping sweep + Online/Offline bucketing (MEDIUM, but needs an engine ping action;
  bucketing now cheap via `setFilter`); bar charts (the dashboard cards already show the numbers);
  Nemesis hand-off (web mismatch - operator opens acas + imports); Dirty-30 auto-flow + Top-Squadron
  tile; ASID column (needs a host->ASID input-model rework).

## Verification cadence (what works - unchanged)

- JS: `node --check web/js/...`. Then drive via the Claude Preview MCP against the `janet-two-dev`
  python static server on **8091** (`X:\.claude\launch.json`), URL `http://127.0.0.1:8091/_devtest.html?cb=<n>`;
  re-point the CSS `<link>` with a `?cb=` buster after each reload (CSS is cached). `preview_screenshot`
  hangs - use `preview_eval` DOM read-outs. Click "Set Credentials" / a gate button to get past run guards.
  Mocked + live-verifiable: message/secureboot/dhcp/winupgrade/wpt/acas/restart/reports. NOT mocked
  (static + node --check): adsearch/pkginstall/upr. Bootstrap/component edits: see LESSONS above.
- Engines: after every edit run the gate - `[System.Management.Automation.Language.Parser]::ParseFile`
  (0 errors on PS 5.1) + first 3 bytes == EF BB BF + non-ASCII scan == 0.
