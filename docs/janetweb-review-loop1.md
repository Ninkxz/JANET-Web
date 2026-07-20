# JANET Web — review loop 1 (2026-07-20)

*New loop series (janetweb-loopN). Prior series: `fable-review-2026-07-12-loop*`,
`prod-review-loop*` (loops 1–40, closed via `loop-rollup-2026-07-12.md`).*

**Baseline:** Pester 980/980 green (617s, pre-change). Tree clean at `52b0a3b`.

## Opus deep-dive: server/auth/token layer — verdict YELLOW

Scope: `server/JanetWeb.Server.ps1`, `JanetWeb.Auth.ps1`, `JanetWeb.Logging.ps1`,
`tool-registry.json`, launcher + `DO NOT RUN - JanetWeb.Internal.ps1`, token flow in
`web/js/shell.js` + views.

### P2-1 — admin session never disarms server-side — CONFIRMED → **FIXED this loop**
`JanetWeb.Server.ps1` — `AckGiven` init `$false`, set `$true` at `/api/session/start`,
**never cleared**. `POST /api/session/end` recorded notes only; `DELETE /api/cred`
dropped the cred but not the ack. Consequences: (1) "End Session" left the destructive
gate (`$state.AckGiven -and $state.Cred`) armed for the process lifetime — false
"I locked it" signal; (2) ack + clear-cred + later re-`POST /cred` re-armed with **no
fresh responsibility ack** (ack was a one-time-per-process flag).
Fix: `/session/end` now drops `AckGiven`+`Cred` (responds `disarmed=true`, notes row
still written first); `DELETE /cred` drops `AckGiven`; `shell.js` gained
`session.disarm()` + `clearCred` mirrors (clears `janetweb_ack`/`janetweb_session`);
acas End Session flow calls `ctx.session.disarm()` and says so in the log.
Regression: `tests/Server.SessionDisarm.Tests.ps1` (11 asserts).

### P3-2 — report-preview popup is same-origin with token access — comment fixed, sandbox → roadmap
`reports.view.js:127` (`openHtmlSandboxed`) claimed "sandboxed... NOT allow-same-origin";
reality: plain `window.open` → same-origin, inherits `sessionStorage` (incl. token),
navigated to `/api/report-preview` served with `script-src 'unsafe-inline'`
(`JanetWeb.Server.ps1:409`). Sole barrier against report-field XSS→token-theft is
`ConvertTo-HtmlEscaped` on every data field (spot-audit: holds today).
This loop: replaced the lying comment with a SECURITY NOTE naming the real contract.
Roadmap item: render via `srcdoc` + `sandbox="allow-scripts"` iframe backstop.

### P3-3 — token on a child-process command line — OPEN (accepted-for-now)
`DO NOT RUN - JanetWeb.Internal.ps1:126,158-163`: tokenized URL rides the
`cmd.exe /c start` fallback's command line (same-user-readable process table) + console.
Low (loopback single-operator). Candidate: drop the cmd.exe fallback.

### P3-4 — no Host-header validation (DNS rebinding) — OPEN (defense-in-depth)
Rebound page reaches the socket but not `/api` (custom `X-Janet-Token` header + no CORS
= blocked). Candidate: reject `Host` ≠ `127.0.0.1:<port>`/`localhost:<port>`.

### P3-5 — token is a v4 GUID not labeled CSPRNG — accepted (122 random bits, loopback).

### Verified solid (on record)
Token never touches disk/SMB; constant-time token compare, fail-closed; destructive
gate default-deny incl. acas by-id set; path traversal closed (read+write, Windows
quirks); CSV/log injection guarded; CSRF blocked by header+no-CORS; cred memory-only.

## Workstream: acas Chrome-updater always-OK chip (open since wpt 6.5.33) — **CLOSED**

1. `modules/JanetWeb.acas.psm1:208` `'Google Chrome - Update'` Script fired
   `GoogleUpdate.exe /ua` blind and returned `OK (Chrome update triggered, exit N)`
   unconditionally — no policy-block detect, no GoogleUpdater-migration support
   (modern boxes: `FAIL: GoogleUpdate.exe not found`), no staged-update detect.
   Ported wpt 6.5.33's honest Script (blocker pre-checks, `GoogleUpdaterTaskSystem*`
   first, before/after poll, `new_chrome.exe`), with wpt's `PENDING` returns converted
   to acas-native `UNCONFIRMED*` — a raw `PENDING` would classify **green** through
   `$script:AcasOkOf`. Profile name kept (match-table + alternates untouched).
2. **Worker rewrap defect (found this loop):** `$script:AcasUpdateWorker`
   (`JanetWeb.acas.psm1:~1990` post-edit) rewrapped ANY unchanged-version result as
   `UNCONFIRMED: ... async update may still be in progress` — including hard `FAIL:`
   from the profile Script. A **permanent** blocker (policy, missing updater) rendered
   amber "maybe still in progress", for **every** profile. Fix: FAIL*/SKIP*/UNCONFIRMED*
   Script results now pass through (markers appended) ahead of both the probe-error
   wrap and the async rewrap; OK-claiming Scripts still require probe proof.
   acas bumped **1.11.3 → 1.11.4**.
   Regression: `tests/Acas.ChromeProfile.Tests.ps1` (22 asserts) + version-pin updates
   in `Acas.FixJava.Tests.ps1` / `Acas.SpecExec.Tests.ps1`.

## SECRET parity
- SECRET parity: acas honest-Chrome Script + AcasUpdateWorker FAIL/SKIP/UNCONFIRMED
  passthrough (JanetSec acas fork has the same copied profile registry; drop the
  Software-Center pointer text or point it at the SIPR-valid alternate — no SCCM there).
- SECRET parity: session-end/cred-delete server-side disarm (same handler shape in
  the JanetSec server) + shell disarm mirror.
- (wpt, this repo, next loop candidate) `Microsoft Edge - Update` in BOTH wpt and acas
  still has the old always-OK Script shape — same honest port applies.
