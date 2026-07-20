# JANET Web — review loop 4 (2026-07-20)

**Baseline:** 1054/1054 at loop-3 close (`f152c19`); tree untouched between loops.

## Opus adversarial self-review of loop-3 (`902a00c`, `7c79666`) — verdict GREEN

No P1/P2; both fixes correct, isolated, revert-caught by tests.

CSP sandbox (checked-clean): `sandbox` in an **enforcing** response header is honored
on a top-level document (the ignored-in-meta / ignored-in-report-only caveats don't
apply — `JanetWeb.Server.ps1:261` sets the real `Content-Security-Policy`). Opaque
origin genuinely closes token theft: `sessionStorage` access throws for the popup, and
`window.opener.sessionStorage` is cross-origin-blocked. Report's inline script is
pure-DOM; grep of `reports.psm1` for `<script src`/`<link`/`href=`/`src=`/`@import`/
`url(`/`<img>` returns nothing — every report is fully inline, so nothing breaks under
the opaque origin. Interstitial carries nothing sensitive; redirect is a same-origin
GET to the one-shot GUID; sandbox applies to the loaded doc, not the opener's navigation.

Audit-map (checked-clean): the change is the ONLY `-AuditResultOf` supplier
(`wpt.psm1:6402`); the app-update-verify sibling and the `Invoke-WptFanOut` binary
default are untouched. `'Skipped'` is a legal `-Result` (`Logging.ps1:428`
`ValidateSet('Success','Failure','Skipped')` — the TouchHost/VulnPatched constraint is
on `-Action`, not `-Result`). `$r.Status -eq 'Skipped'` is reachable (`:3359` maps
`SKIP*`). Version pins consistent (only `Wpt.EdgeProfile` exact-pins 6.8.2).

Notes carried forward (no defect):
- **F7 (wording):** an opaque-origin doc can still *issue* a request to `/api` — the
  real guarantee is "token-less + response unreadable (no CORS)", not "request
  blocked". Comment wording only; behavior holds.
- **F8 → new ranked item 7:** the sandbox silently breaks if a future report adds
  `window.print()`, `<a download>`, or any `<script src>`/`<link>`/`<img src="/">`.
  None exist today. Add a static "reports stay resource-free" guard test so the
  constraint is discoverable before someone trips it.
- **F9 → live-fire caveat (carried):** header-delivered sandbox is old Chromium; a
  single Dirty-30 preview smoke on real AFNET Edge retires the residual concern.
- **F14 (pre-existing):** a Skipped host audits Skipped but still counts under the run
  summary's Failed tally (`OkOf` = Status -eq 'OK'); mirrors the long-standing Pending
  behavior — the two surfaces answer different questions. Folds into ranked item 6.

## Sonnet mechanical re-verify (loop-3 fixes at `f152c19`) — all 5 PASS

133/133 across 9 suites; BOM+parse clean; `$reportCsp` leads `sandbox allow-scripts;`
with no `allow-same-origin`; SPA `$csp` has no sandbox; audit map sends Pending+Skipped
→ Skipped with Failure else-arm; disarm lines present; no cert files; Gate suite boots a
real server → confirms the edited CSP line still boots.

## Workstream: roadmap item 3 — Host-header guard — **CLOSED** (`2b7423f`)

Empirically grounded: a raw-socket probe (loopback, 4 Host values against an IP-literal
`HttpListener` prefix) **confirmed http.sys ignores the Host string** — `evil.example.com`
was served 200. So the DNS-rebinding read affordance on the token-less surfaces (static
UI, report-preview) was real. Guard at the top of the request loop
(`JanetWeb.Server.ps1`, after `$verb`, before static + `/api` dispatch): serve only
`127.0.0.1:$Port` / `localhost:$Port`; everything else (incl. missing Host) → 421
Misdirected, no content. `-ne` is case-insensitive in PS (correct for hostnames).
The loopback bind + token was already the real gate; this removes the same-origin read
path a rebound page would use. Regression: `Server.HostHeader.Tests.ps1` (8, real server
+ raw sockets — proves 421 on token/static/preview surfaces, fires before the token
gate, both legit names still 200).

## SECRET parity
- SECRET parity: Host-header guard (JanetSec server has the same IP-literal listener
  prefix + request loop — identical exposure).
- Carried: report-preview CSP sandbox, wpt audit-Skipped, session disarm, honest
  Chrome/Edge + worker passthrough.
