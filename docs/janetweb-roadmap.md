# JANET Web roadmap — improvement-loop ledger

*Living doc; drives the structured audit/design/implement/verify loop (mirrors
`X:\POWER\docs\power-roadmap.md`). Series started loop 1 (2026-07-20). Prior loop
history (different series naming, loops 1–40): `docs/fable-review-2026-07-12-loop*.md`,
`docs/prod-review-loop*.md`, rolled up in `docs/loop-rollup-2026-07-12.md`.*

*Baseline at series start: 21 tools · 3 server files · 980 Pester green · HEAD `52b0a3b`.*

## Standing rules (from the operator, enforced every loop)
- PS 5.1 + UTF-8 BOM on every script; ASCII-only bodies; no new external deps.
- Destructive actions stay fail-closed: confirm-word + self-guard + wrong-box guard +
  IPv4 target guards. Never weakened.
- Set Credentials is UNIVERSAL (shell header); sidebar keeps wpt, acas first; dark
  theme default; Beta Lab stays dead.
- Local commits only (push on operator say-so). Take-to-work ONLY via gated
  `Sync-TakeToWork.ps1`; certs never ship. Shared SMB tree: commit own paths only.
- Subagents: Opus (adversarial/deep-dive) or Sonnet (re-verify/sweep). Never Haiku/Fable.
- Every change worth mirroring to SIPR gets a "SECRET parity:" line in the loop review doc.

## Ranked open items
1. ~~Edge always-OK Script~~ — **CLOSED loop 2** (`3dea8b8`): honest port in BOTH
   modules (wpt 6.8.1 / acas 1.11.5).
2. ~~Report-preview sandbox backstop~~ — **CLOSED loop 3** (`902a00c`): CSP
   `sandbox allow-scripts` on the preview response (opaque origin — simpler than the
   srcdoc-iframe rebuild). Live-fire caveat: eyeball a report preview in-browser.
3. **Host-header validation** (loop-1 P3-4, defense-in-depth) — reject `Host` other
   than `127.0.0.1:<port>` / `localhost:<port>` on the listener.
4. **Token on child-process command line** (loop-1 P3-3) — drop/replace the
   `cmd.exe /c start` browser-open fallback in the launcher.
5. **SECRET parity backlog** — see per-loop review docs ("SECRET parity:" lines);
   currently: c2c durability trio (pre-series), acas honest-Chrome + worker
   passthrough, session disarm, honest-Edge (wpt+acas; re-route SC pointers for
   SIPR), report-preview CSP sandbox, wpt audit-Skipped fix.
6. **SKIP-books-green reporting note** (loop-2 Opus P3-3, pre-existing) — `AcasOkOf`
   counts `SKIP*` as OK so run-all "patched" tallies include not-installed hosts;
   split SKIP out of the tallies if the operator wants stricter counts.

## Loop ledger
- **Loop 1 (DONE 2026-07-20):** roadmap created + Opus adversarial deep-dive on the
  server/auth/token layer → `janetweb-review-loop1.md` (YELLOW). Found & fixed **1 P2**
  (admin session never disarmed server-side: `/session/end` notes-only, ack sticky for
  process lifetime, cred re-set re-armed without fresh ack → both handlers now disarm,
  client mirrors, acas flow announces DISARMED) + honest-comment fix for the
  report-preview pseudo-sandbox (P3-2; backstop → ranked item 2). **Workstream: closed
  the acas Chrome-updater always-OK chip** (open since wpt 6.5.33): honest Script port
  (blocker pre-checks, GoogleUpdater task, before/after poll, staged detect;
  PENDING→UNCONFIRMED at the port boundary) **+ found & fixed the AcasUpdateWorker
  rewrap defect** (hard FAILs rendered amber "async may still be in progress" for every
  profile → FAIL/SKIP/UNCONFIRMED passthrough, fail-closed ordering). acas
  **1.11.3→1.11.4**. Tests: +2 files (`Acas.ChromeProfile` 22 asserts,
  `Server.SessionDisarm` 11), 2 version-pin updates. Pester 980→**1002** green
  post-change (that run enumerated files before the disarm suite landed; its 11
  asserts green in a targeted run — loop 2's baseline records the consolidated count).
  3 P3s accepted/deferred to ranked items. SECRET parity ×3 noted, not executed.
  *(Consolidated count landed in loop 2: 1013/1013.)*
- **Loop 2 (DONE 2026-07-20):** Opus adversarial self-review of the loop-1 commits →
  `janetweb-review-loop2.md` (**GREEN, 0 P1/P2** — round-trip, passthrough ordering,
  and mid-flight cred capture all traced clean: workers get the PSCredential at
  dispatch, background runspaces can't see `$state`, listener is serial, so End
  Session can't strip an in-flight run). Sonnet mechanical re-verify: all 5 checks
  PASS (122/122 targeted, guards tightened-not-weakened, no cert files, BOM/parse/
  ASCII clean). **Workstream: closed ranked item 1 — honest Edge updater Scripts in
  BOTH modules** (`3dea8b8`): policy + service pre-checks, exe-first trigger with
  `MicrosoftEdgeUpdateTaskMachineUA*` fallback, 90s before/after poll, staged
  `new_msedge.exe` detect; wpt speaks PENDING, acas speaks UNCONFIRMED (boundary
  rule pinned by tests). wpt **6.8.0→6.8.1**, acas **1.11.4→1.11.5**; old acas
  exact-version pins → floor asserts (Opus P3-2). Tests: +2 files (`Wpt.EdgeProfile`
  12, `Acas.EdgeProfile` 17). Pester 1013→**1042** green (clean post-change full
  suite). New ranked item 6 (SKIP-books-green tallies). SECRET parity: honest-Edge
  added to the backlog.
- **Loop 3 (DONE 2026-07-20):** Opus adversarial self-review of the loop-2 Edge port
  → `janetweb-review-loop3.md` (**GREEN** — wpt live-scriptblock dispatch traced
  safe, WOW6432Node-first key order confirmed, exe-first fast-fail upheld; the acas
  no-PENDING test verified genuine). Its P3-1 **fixed in-loop** (`7c79666`, wpt
  **6.8.1→6.8.2**): wpt app-update audit booked `Skipped` hosts as **Failure** in
  the Runs CSV (only Pending was special-cased; pre-existing since 6.5.33) — both
  non-attempt states now audit Skipped, Failure else-arm pinned. P3-2/P3-3 (wording)
  accepted with rationale. Sonnet re-verify at loop start: all 5 PASS (122/122).
  **Workstream: closed ranked item 2 — report-preview XSS backstop** (`902a00c`):
  CSP `sandbox allow-scripts` on the preview response → opaque origin (no
  sessionStorage token, no same-origin /api even on an escaping miss); report's
  pure-DOM inline script verified sandbox-compatible; SPA CSP untouched;
  `allow-same-origin` banned by test; chose the one-header fix over the srcdoc-
  iframe rebuild. Tests: +`Server.ReportPreviewSandbox` (10) + 2 audit-map asserts.
  Pester 1042→**1054** green. Process fix adopted: one full-suite run after the
  last code commit (stop racing). SECRET parity: +preview sandbox, +audit-Skipped.
