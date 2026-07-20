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
1. **Edge always-OK Script** — `'Microsoft Edge - Update'` in BOTH `JanetWeb.wpt.psm1:1121`
   and `JanetWeb.acas.psm1` still fires `MicrosoftEdgeUpdate.exe /ua` and returns OK
   unconditionally — same defect shape the Chrome profiles just lost. Same honest port
   applies (policy key `Policies\Microsoft\EdgeUpdate`, staged `new_msedge.exe`).
2. **Report-preview sandbox backstop** (loop-1 P3-2) — same-origin popup with token
   access + `unsafe-inline` CSP; escaping is the sole XSS barrier. Render via
   `srcdoc` + `sandbox="allow-scripts"` iframe.
3. **Host-header validation** (loop-1 P3-4, defense-in-depth) — reject `Host` other
   than `127.0.0.1:<port>` / `localhost:<port>` on the listener.
4. **Token on child-process command line** (loop-1 P3-3) — drop/replace the
   `cmd.exe /c start` browser-open fallback in the launcher.
5. **SECRET parity backlog** — see per-loop review docs ("SECRET parity:" lines);
   currently: c2c durability trio (pre-series), acas honest-Chrome + worker
   passthrough, session disarm.

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
