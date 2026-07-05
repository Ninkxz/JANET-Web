# JANET Web - Session 2 Handoff (build complete, 12/12 imported)

State as of 2026-06-19. The build session that lifted the plumbing, built the shared kit,
and imported all 12 tools. Read this + the `project-janet-two` auto-memory to continue.

## Where the project stands

- **12 / 12 tools ported.** Engines (`modules/JanetWeb.<id>.psm1`) + bespoke views
  (`web/js/views/<id>.view.js`) for: wpt, acas, pkginstall, winupgrade, upr, secureboot,
  restart, message, adsearch, dhcp[beta], reports[stateful], stig[beta/stateful].
- **Plumbing** lifted rename-only from JANET ONE: `server/JanetWeb.Server.ps1` / `.Auth.ps1` /
  `.Logging.ps1` (SAME central-CSV share + tool->folder map), `Start-JanetWeb.ps1` (port 8089),
  `Launch JANET Web.cmd`. Token gate, runspace job streaming, reaper, stateful-runspace slots,
  graceful `__job` cancel - all intact.
- **Shared kit** (`web/`): `css/janet.css` (ThemeKit, desktop palette purple #8C64DC + gold
  #DAB452), `js/shell.js` (AppShell + launch gate + horizontal category-tab hub + router +
  `JanetViews.register` lazy loader [cache-busted] + `ctx` + **RunController** = the JANET ONE
  streaming client extracted verbatim), `js/components/*` (ControlFactory, ResultsGrid,
  ActivityLog, StatCards, ProgressStatusStrip, TargetManager, RunBar, ConfirmDialog/ArmingDialog,
  TabHost, xlsx.js). The authoring contract is `docs/VIEW-CONTRACT.md`.
- **Git**: ~9 local commits (`f093ea2` .. `f92b4e1`), branch `main`, **NOT yet pushed** to
  `bth0mp/J.A.N.E.T-TWO` (owner hadn't supplied the Gitea user+token at session end). Push with a
  one-time `git -c http.extraHeader="Authorization: Basic <base64 user:token>" push origin main`;
  keep creds OUT of `.git/config` (repo is on the shared SMB drive).

## Locked decisions / rules (do not regress)

1. **Universal credentials** - ONE Set Credentials in the shell header (top-right). No per-tool
   cred control ever ([[feedback_janet_two_universal_cred]]).
2. **Launcher hub** = horizontal category tabs (All + per-category). Owner is choosing among 3
   layout options (sidebar rail / launchpad tiles / search-first) - implement the pick next.
3. **Engines**: `.ps1`/`.psm1` are UTF-8 **with BOM + ASCII-only**; PS 5.1 must parse. Run the
   parse+BOM+ASCII gate after every engine edit. Engines for builds 4-12 were DERIVED from the
   proven JANET ONE psm1 via transform (they can't be offline-verified; reproduction beat hand-
   transcription). message/secureboot/dhcp were re-derived from the desktop. Owner may request a
   from-scratch desktop re-derivation on any tool.
4. **All runs via `ctx.run` -> RunController**; views never fetch/poll. Multi-row-per-host grids
   MUST pass `keyOf` to `ctx.run` + a matching `keyMode` to ResultsGrid (handoff risk #5 - hit it
   live in DHCP: every row shared `Host`, collapsing scopes; fixed by keying on `ScopeId`).
5. **Launch via `Launch JANET Web.cmd`** (forces classic blue conhost so the smartcard
   Get-Credential picker surfaces; double-click of the .ps1 now self-heals into conhost too). The
   credential dialog is foregrounded so it cannot hide behind the browser.

## Verification level

- All 12 engines import cleanly through the real server; all 12 manifests served (wpt 29 actions,
  reports 23, stig 13, etc.). Gate green.
- All 12 views **mount in-browser with ZERO console errors**; tab views build + switch tabs.
- **Deep run-stream verified**: message (send/ping), secureboot (dry+live), dhcp (connect/load/
  apply/bulk). The other 9 are **mount-verified + manifest-wired**; their remote-exec runs are
  flagged for on-AFNET live validation.

## Per-tool REVIEW TODOs (engine lacks an action -> scaffolded in the view)

- **wpt**: reboot-countdown + post-reboot beep-monitor; Reports/Usage/Logs tabs (telemetry-only).
- **stig**: per-rule Review grid not populated (needs a streaming get-rule-catalog action) +
  editable CKL metadata cells + skip-list save/load.
- **acas**: run-vulnerability host-lists (uses key-based `patch-selected` instead); KB Installer.
- **reports**: `acas-load-report` grid repaint (engine returns counts only); Dirty-30 PDF (paste
  text workaround - no in-browser PDF parse).
- **restart**: delayed-start arming; auto-opening reboot monitor (rendered as an in-tab grid).
- **winupgrade/pkginstall**: engines emit one final row/host (no live "Copying..." phase narrative).

## How to run / verify

- Operator: double-click `Launch JANET Web.cmd` -> blue conhost -> browser opens to the tokenized
  loopback URL. Set Credentials (ADW smartcard) for destructive tools; "Browse tools (read-only)"
  for read-only.
- Dev mocked verification: `web/_devtest.html` mocks `window.fetch` with scripted job streams +
  skips the gate; served by the `janet-two-dev` python static entry in `X:\.claude\launch.json`
  (Claude Preview MCP). Drive via `preview_eval` DOM read-outs (preview_screenshot reverts to `/`).
- Real-server smoke: start `Start-JanetWebServer -Port <free>` on a spare port, navigate the
  preview to `http://127.0.0.1:<port>/?t=<token>`, "Browse tools", click each card -> mount check.
  (8089 may be held by the operator's running instance; use a different port to avoid the http.sys
  bind conflict.)

## Immediate next steps

1. Push the 9 commits (owner provides Gitea user+token).
2. Implement the chosen hub layout (sidebar / launchpad / search-first / hybrid) in `shell.js`
   `renderHub` + `janet.css`; verify in-browser.
3. Owner review pass tool-by-tool; deepen the scaffolded TODOs above as desired.
4. On-AFNET live validation of the remote-exec paths (the real test of the derived engines).
