# JANET Web - Session 3 Handoff (review pass COMPLETE, suite is 11 tools)

State as of 2026-06-19. The session that pushed the backlog, reskinned the launcher as a
launchpad, ran the full tool-by-tool review (deepening every scaffolded TODO), and removed
the STIG tool. Read this + the `project-janet-two` auto-memory to continue. Prior handoff:
`docs/SESSION-2-HANDOFF.md` (build-complete state); kit API: `docs/VIEW-CONTRACT.md`.

## Where the project stands

- **Suite is 11 tools** (STIG was REMOVED this session, owner decision): wpt, acas, pkginstall,
  winupgrade, upr, secureboot, restart, message, adsearch, dhcp[beta], reports[stateful].
  Engines `modules/JanetWeb.<id>.psm1` + bespoke views `web/js/views/<id>.view.js`.
- **Launcher hub** is now a flat **launchpad of corner-bracket icon tiles** (38px icon, category
  eyebrow, name, 3-line summary, hover-lift, gold focus, not-ported dimmed). In `web/js/shell.js`
  `renderHub` (`.j-launchpad`) + `web/css/janet.css`. Replaced the horizontal category-tab page.
- **Review pass COMPLETE.** Every per-tool scaffolded TODO from SESSION-2-HANDOFF was addressed.
- **Git**: branch `main`, all work pushed to `bth0mp/J.A.N.E.T-TWO`. Working tree clean.

## What this session did (commit by commit, all on origin/main)

- Pushed the 10 backlog commits (`..a6a562c`).
- `1c25158`  Launchpad hub (renderHub + janet.css).
- `8b5c75a`  WPT Reboot Countdown: new engine actions `reboot-schedule` (shutdown /r /t + logged-on
  user popup, re-arms cleanly) + `reboot-abort` (shutdown /a); faithful countdown tab (total-time /
  warn-every / auto-vs-warnings-only, Arm/Send-Warning-Now/Cancel, client countdown + warn-every-N
  popups, post-reboot ping monitor + WebAudio beep). ALSO fixed a latent bug (see Lessons).
- `d1d1499`  WPT Reports / Usage / Logs tabs via a view-level Telemetry accumulator that wraps
  `ctx.run` ONCE so every action on every tab is recorded (no shell change).
- `ce205da`  ACAS run-vulnerability host-lists: analyze now emits each card's `hosts`; card runs
  dispatch against the EXPLICIT (operator-reviewable) host list - one card -> run-vulnerability,
  checked/runnable sets -> run-all-parallel/sequential. Removed key-based patch-selected. Latent fix.
- `a2f4814`  ACAS KB Installer: new engine actions `kb-scan-findings` (regex-extract KBs from CSV
  findings) + `kb-install` (per-host KB map; AcasKbInstallBlock lifts WPT's WptKbInstallBlock
  MECM+MSU and adds UsoClient). New KB INSTALLER tab. Latent fix.
- `e2aecc3`  restart delayed-start arming ("Begin at the scheduled time" countdown that auto-fires
  launchDispatch) + auto-open Reboot Verification Monitor on dispatch completion. View-only.
- `18b0d63`  reports acas-load-report now STREAMS each loaded finding (like acas-parse-file) so the
  findings grid repaints on load (was a counts-only summary row).
- `aae185f`  reports Dirty-30 PDF: best-effort dependency-free client extractor (inflate
  /FlateDecode via the browser's DecompressionStream + pull PDF literal-string text), falls back to
  manual paste under 30 chars (scanned/image PDFs).
- `696ec20`  winupgrade live per-host phase narrative (Copying / DISM / Pinning / Unpinning /
  Rebooting) via a shared ConcurrentQueue step-queue (the pattern pkginstall already used).
  pkginstall was already done and was NOT touched.
- `56fab49`  Removed the STIG tool (registry entry + logging folder-map; deleted engine + view +
  ui-spec). Disposed of the live panelOf crash with it.

## Locked decisions / rules (do not regress)

1. **Universal credentials** - ONE Set Credentials in the shell header. No per-tool cred control.
2. **All runs via `ctx.run` -> RunController**; views never fetch/poll. Multi-row-per-host grids
   pass `keyOf` to `ctx.run` AND a matching `keyMode` to ResultsGrid.
3. **Engines**: `.ps1`/`.psm1` are UTF-8 **with BOM + ASCII-only**; PS 5.1 must parse. Run the
   parse+BOM+ASCII gate after EVERY engine edit. (Server `.ps1` count too, e.g. JanetWeb.Logging.ps1.)
4. **Do NOT modify** `X:\J.A.N.E.T` or `X:\J.A.N.E.T ONE`. Shared SMB drive - coordinate destructive ops.
5. **Push** with a one-time `git -c http.extraHeader="Authorization: Basic <base64 user:token>"
   push origin main`; keep creds OUT of `.git/config`. User is `bth0mp`. Owner pastes the token.
6. **Launch** via `Launch JANET Web.cmd` (blue conhost so the smartcard Get-Credential picker surfaces).

## LESSONS (carry forward)

- **Mount-clean != run-clean.** The 9 derived tools were mount-verified only; their RUN paths
  carried latent bugs. Three were found + fixed this session by DRIVING the runs:
  1. WPT called `ctx.targets.getText()` (11 sites) but the shared model only exposes `.raw`
     (getText() is a TargetManager-COMPONENT method). Every WPT run would have thrown on AFNET.
  2. ACAS declared its cross-tab refs (`importStatus` etc.) `= null` AFTER the TabHost was
     constructed; TabHost auto-builds tab 0 in its constructor, so buildImportTab assigned those
     refs and the `= null` line then clobbered them -> doImport hit a null importStatus. Declare
     cross-tab refs BEFORE the TabHost.
  3. `ui.select` defaults to its LAST option unless an explicit `value` is passed.
  When reviewing a tool, set targets + cred, fire the run, and read `RunController.get(<key>)` +
  the DOM. Don't trust a clean mount.
- **Streaming sub-phases out of a runspace worker** = a shared `ConcurrentQueue` passed to the
  worker (a `$pushStep` helper enqueues {Hostname, Step, Detail}) that the harvest loop drains each
  pass and streams as a phase row keyed by Host. pkginstall + winupgrade both use this. Reuse it.
- **DecompressionStream** hangs on bytes past the deflate stream - use the dict's direct `/Length`
  for exact bytes and race a timeout. `CompressionStream('deflate')` is the in-browser inverse,
  handy for building synthetic test PDFs.

## Verification cadence (what works)

- Per tool, extend `web/_devtest.html`: add it to the mock catalog (REGISTRY) + a manifest branch
  + mocked action streams in `buildEvents`. (acas, restart, reports, wpt, winupgrade now mocked.)
- Drive via Claude Preview MCP `preview_eval` against the `janet-two-dev` python static server on
  **8091** (`X:\.claude\launch.json`), URL `http://127.0.0.1:8091/_devtest.html?cb=<n>`. Set file
  inputs via a DataTransfer object (Chromium allows it). Read `RunController.get(key)` + DOM + an
  in-page error trap (`window.addEventListener('error'/'unhandledrejection')`). `preview_screenshot`
  still hangs (it reverts to `/` which shows the gate); use eval read-outs instead. The dev server
  sometimes stops - `preview_start` to revive (the serverId changes).
- After every engine edit run the gate: `[System.Management.Automation.Language.Parser]::ParseFile`
  (0 errors on PS 5.1) + first 3 bytes == EF BB BF + non-ASCII scan == 0.

## What remains

- **On-AFNET live validation** of the remote-exec paths - the real test of the derived engines
  (the new reboot-schedule/abort, kb-install MECM/UsoClient, winupgrade DISM phases, ACAS
  run-vulnerability/run-all, etc. can only be confirmed against real hosts).
- Incidental `stig` mentions intentionally LEFT in place: WPT's reg-key STIG/CVE fixes (a separate
  feature, not the removed tool) and illustrative comments (server "reports/stig" stateful examples,
  the ArmingDialog "APPLY" note). The historical `docs/HANDOFF.md` + `docs/SESSION-2-HANDOFF.md`
  still say "12/12" - they are dated snapshots, not corrected.
- No open per-tool TODOs. Future work is owner-directed (new features, polish, or AFNET findings).
