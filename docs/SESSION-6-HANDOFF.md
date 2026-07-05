# JANET Web - Session 6 Handoff (Command Sidebar + ponytail cleanup + launcher rename + WPT Beta tab)

State as of 2026-06-23. This session shipped the **Command Sidebar** shell, a
**ponytail-audit cleanup**, a **launcher rename**, and a new **WPT Beta tab** of
experimental AFNET-unproven remediations; it also analysed the Lakenheath vuln
report (paused) and produced a take-to-work zip. Read this + `docs/SESSION-5-HANDOFF.md`
(parity restoration + launcher icons), `docs/VIEW-CONTRACT.md` (the kit API), and the
`project-janet-two*` auto-memories to continue.

## Where the project stands

- **Still 11 tools** (wpt, acas, pkginstall, winupgrade, upr, secureboot, restart,
  message, adsearch, dhcp[beta], reports). STIG remains intentionally dropped.
- **Git**: branch `main`, everything pushed to `bth0mp/J.A.N.E.T-TWO`, **HEAD `c490f62`**,
  tree clean, in sync. Session start was `c72f6d7`.
- The desktop originals in `X:\J.A.N.E.T\Tools\` are untouched (read-only reference).
- **Launcher entry point is now `Launch JANET Web.cmd` -> `JanetWeb.Internal.ps1`**
  (renamed from `Start-JanetWeb.ps1`).

## What this session did (commit by commit, all on origin/main)

- `096f074` **wpt SCCM App Manager quick-filter** - a quick-filter dropdown on the
  Software Center Apps tab (desktop `ddlAmFilter`: All/Chrome/Edge/Microsoft 365/Teams/
  Tanium), `Name`-substring via `grid.setFilter`. Mirrors the Software Manager sibling.
- `2ccba06` **Command Sidebar** - replaced the flat launchpad + `< Tools` back-to-hub with
  a persistent left **sidebar** (brand->home, "Filter tools" box, category-grouped tool nav,
  session/log foot) + a **top bar** (breadcrumb + the universal Set Credentials + clock).
  Data-driven from `/tools` (`renderNav()`/`setNavActive()` in shell.js). Chosen from three
  browser demo concepts (sidebar / icon-rail+palette / top-bar); the other two were throwaway.
- `81b1ab6` **ponytail-audit cleanup** (-51 net lines, zero behaviour change): removed the
  inherited "not ported" scaffold (the `ported` flag + every false branch across registry/
  shell/server/css); trimmed TabHost (dropped unused lock/badge/onTab/activeId + the duplicate
  tabApi - **kept `select`, it IS called externally by restart/wpt**); dropped RunBar
  `cta:false`/`setLabel`, ResultsGrid `setSort`, shell exports (`Janet.api`/`RunController`/
  `uploadFile`), `JanetViews.has/get`, `RunController.get`, `ctx.cancel`, dead `rs.checked`;
  message `C_card{box}` -> `ui.card({title})`; acas 3x inline severity -> one `sevCell(key)`;
  wpt `findManifestAction` -> `Array.find`. (Skipped the two `secHdr` findings - net-negative.)
- `4e5a23c` + `39cb399` **launcher rename**: `Start-JanetWeb.ps1` -> `JanetWeb.Internal.ps1`
  (the inviting `Start-J...` name lured people into running the `.ps1` directly, where the
  Get-Credential smartcard picker may not surface). The `.cmd` is now the lone obvious entry;
  the self-heal relaunch guard also fires under **PowerShell 7 (PSEdition Core)** now.
- `c490f62` **WPT Beta tab** - a new tab of EXPERIMENTAL, AFNET-unproven remediations,
  isolated from the proven tabs (see below).

## New patterns / capabilities (carry forward)

- **Command Sidebar:** the shell is `#j-shell` = `#j-sidebar` (grouped nav, filter, foot) +
  `#j-main` (`#j-topbar` breadcrumb/cred/clock + `#j-mainbody` hub|tool). `renderNav()` groups
  tools by `category` in registry order; `openTool` sets the breadcrumb + active row; the brand
  click = `backToHub` (home). Adding a tool = a registry entry; the nav is data-driven.
- **WPT Beta tab (`buildBeta`):** metadata-driven (`BETA` array: profile + methods + optional
  input + how-to). A **method dropdown** (hidden when single), a **per-fix How-to modal**, and an
  **input box that shows only when the selected fix/method needs it**. It reuses the proven
  `app-update-verify`/`app-update-apply` actions - those now thread an optional **`method` + `arg`**
  through `WptAppUpdateBlock` via `-ArgumentList` (paramless proven profiles ignore the extra args,
  backward-compatible). Beta `[BETA] ...` profiles live in `Get-WptAppUpdateProfiles` but surface
  ONLY in the Beta tab, never in App Updater. Adobe is method-aware (`param($Method,$Arg)`: `sc` ->
  ConfigMgr cycles or a named CCM_Application install; else the direct Adobe updater task/AdobeARM).
  Beta fixes: Adobe Acrobat/Reader update (Software Center OR direct), SMB Signing require (reg),
  RDP require NLA (reg), ICMP Timestamp block (firewall). All local mechanisms, no internet.
  Verify is read-only; Apply is destructive (admin session) + an experimental confirm.
- **Take-to-work zip:** `X:\JANET Web Take to work\` holds runtime only (cmd + `JanetWeb.Internal.ps1`
  + server/ + modules/ + web/ minus `_devtest.html`/`_stub.view.js` + empty Packages/ + JanetLocal/);
  excludes `.git`/`fork-source`/`docs`/`.claude`/README. Zipped to
  `X:\Archive\JANETTWO_TakeToWork_<date>_<time>.zip`.

## Locked rules (do NOT regress)

1. Universal credentials - ONE Set Credentials, now in the **top bar**; no per-tool cred control.
2. All runs via `ctx.run` -> RunController; views never fetch/poll. Multi-row-per-host grids pass
   `keyOf` to ctx.run AND a matching `keyMode` to ResultsGrid.
3. Engines `.ps1`/`.psm1` are UTF-8 **with BOM + ASCII-only**; PS 5.1 must parse. Run the
   parse+BOM+ASCII gate after EVERY engine edit. (`.js`/`.css`/`.json` are NOT gated.)
4. Do NOT modify `X:\J.A.N.E.T` or `X:\J.A.N.E.T ONE`. Shared SMB drive - coordinate destructive ops.
5. **PUSH WITH PLAIN `git push origin main`** - this box has `credential.helper = manager`
   (Windows Credential Manager) with a cached PAT, so no token is needed. **Do NOT use the old
   `git -c http.extraHeader="Authorization: Basic <token>"` one-time-header** - it OVERRIDES the
   credential manager and breaks the moment the pasted token lapses (that was the root cause of the
   recurring "need a new token"). If the cached PAT ever truly expires, GCM pops a one-time Windows
   login prompt; re-auth there once. See `reference_gitea` memory.
6. Launch via `Launch JANET Web.cmd` (it pins conhost + `-STA` so the credential picker surfaces).
   Tool icons = Segoe MDL2 hex codepoint in `tool-registry.json` (keep ASCII) + the `_devtest.html`
   catalog in sync.

## LESSONS (new this session)

- **Push = plain `git push`, never the token header.** (Rule 5.) The one-time header was the entire
  reason tokens "kept expiring" - it bypassed the working credential manager.
- **shell.js + components are cached bootstrap scripts** - verify a shell/component edit by
  temp-cache-busting the `<script>`/`<link>` in `_devtest.html` (add `?cb=...`, drive, then REVERT),
  not a plain reload. View files (`*.view.js`) reload on SPA navigation.
- **devtest mock != production** - `_devtest.html` has its own inline catalog (8 tools + `_stub`,
  in a different order) and its own `buildEvents` action mocks. To exercise an unmocked engine
  action, temp-add a handler to `buildEvents`, drive, then REVERT (confirm `git status` clean).
- **TabHost `select` is public** - restart/wpt call `tabs.select(id)` to switch tabs
  programmatically; do not remove it.
- ponytail call held: skipped the `secHdr` audit findings because "fixing" them adds lines.

## What remains

- **On-AFNET live validation** - the real outstanding test; only the owner can run it. NOW INCLUDES
  the **WPT Beta tab efficacy** (Adobe Software-Center vs direct, SMB/NLA reg, ICMP firewall) - these
  are deliberately unproven; validate on one host, then a small set, before fleet use.
- **Lakenheath remediation (paused)** - see `project-janet-two-lakenheath-remediation` memory.
  ~81% of the 5,679 findings are JANET-addressable; all 218 Criticals are (Java + EOL). The Beta tab
  now covers several gaps (Adobe, SMB, NLA, ICMP). Offered-not-done: slice the CSV into per-family
  target host-lists; the report imports straight into ACAS Nemesis / Reports.
- **reports tail** (low): ping sweep + Online/Offline bucketing, Dirty-30 auto-flow, ASID column.
- Possible Beta-tab follow-ons: Java/Firefox/NVIDIA profiles, a staged-MSP Adobe path, more reg fixes
  (the Beta mechanism takes new fixes as `Get-WptAppUpdateProfiles` entries + a `BETA` array row).

## Verification cadence (unchanged)

- JS: `node --check web/js/...`. Drive via the Claude Preview MCP against the `janet-two-dev`
  python static server on **8091** (`X:\.claude\launch.json`), `http://127.0.0.1:8091/_devtest.html?cb=<n>`;
  re-point the CSS `<link>`/bootstrap `<script>` with `?cb=` after each reload (cached). Click
  Set Credentials / Start Admin Session to pass run guards. `preview_screenshot` hangs - use
  `preview_eval` DOM read-outs.
- Engines: after every edit run the gate - `[System.Management.Automation.Language.Parser]::ParseFile`
  (0 errors on PS 5.1) + first 3 bytes == EF BB BF + non-ASCII-beyond-BOM scan == 0.
