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
3. ~~Host-header validation~~ — **CLOSED loop 4** (`2b7423f`): probe-confirmed
   exposure, 421 on any Host but `127.0.0.1:<port>`/`localhost:<port>`.
4. **Token on child-process command line** (loop-1 P3-3) — drop/replace the
   `cmd.exe /c start` browser-open fallback in the launcher.
5. **SECRET parity backlog** — see per-loop review docs ("SECRET parity:" lines);
   currently: c2c durability trio (pre-series), acas honest-Chrome + worker
   passthrough, session disarm, honest-Edge (wpt+acas; re-route SC pointers for
   SIPR), report-preview CSP sandbox, wpt audit-Skipped fix, Host-header guard.
6. **SKIP-books-green reporting note** (loop-2 Opus P3-3 + loop-4 F14, pre-existing) —
   `AcasOkOf` counts `SKIP*` as OK so acas run-all "patched" tallies include
   not-installed hosts; symmetrically wpt's run summary counts a Skipped host under
   Failed while its audit says Skipped. Reconcile the tallies if the operator wants
   stricter counts.
9. **c2c memoized local-identity staleness** (loop-8 Opus P3-2, pre-existing) —
   `Get-JanetC2cLocalIdentity` caches the dispatcher IP set for the module lifetime; a
   mid-lifetime DHCP lease change could stale the self-guard's IP entries (name/FQDN
   still catch self). Negligible on a server-hosted dispatcher; re-resolve per-wave if
   ever run on a DHCP client.
7. ~~Report-resource-free guard~~ — **CLOSED loop 7** (`928d1ba`): static guard
   (`Reports.SandboxResourceFree.Tests.ps1`, 12) asserts the report module stays
   self-contained + the server CSP still leads `sandbox allow-scripts`.
8. ~~Host-guard test gaps + non-default-port note~~ — **CLOSED loop 6** (`2c96c16`):
   empty/absent-Host + cancel-route cases pinned (probe-first), F1 comment added.
10. **Benign-on-self unguarded set (do NOT re-flag)** (loop-10 audit) — these destructive
    fan-outs deliberately lack a self-guard because acting on self is harmless/desirable
    (no reboot/lockout/dispatch-abort, no software install/remove): wpt `reboot-abort`,
    `winrm-bootstrap`, `healer-*` (restart-ccm/wmi-repair/wu-reset/gpupdate/ccm-repair/
    rdp-rebind), `remote-message`, `cleanup-disk`, `maintenance-unlock`; acas
    `preflight-services`; restart `abort-scheduled`. A future self-guard sweep will
    re-flag them — this is the standing "by design" answer. Guarding them would remove
    legitimate dispatcher self-repair/self-abort.

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
- **Loop 4 (DONE 2026-07-20):** Opus adversarial self-review of the loop-3 fixes →
  `janetweb-review-loop4.md` (**GREEN**, 0 P1/P2 — enforcing-header sandbox honored,
  opaque-origin token-theft closure confirmed, report engine emits zero external
  resources, audit-map change isolated + `'Skipped'` a legal `-Result`). Forward
  notes captured: F7 (wording), F8 → new ranked item 7 (report-resource-free guard),
  F9 (live-fire smoke), F14 → folded into item 6. Sonnet re-verify: all 5 PASS
  (133/133). **Workstream: closed ranked item 3 — Host-header guard** (`2b7423f`):
  a raw-socket probe **confirmed** http.sys serves an IP-literal listener regardless
  of Host (`evil.example.com` → 200), upgrading loop-1's speculative item to
  confirmed-exposed; guard fails closed at the top of the request loop (before static
  AND /api) — only `127.0.0.1:$Port`/`localhost:$Port` served, else **421**. Tests:
  +`Server.HostHeader` (9, real server + raw sockets). Pester 1054→**1063** green
  (authoritative single post-commit run). New ranked item 7. SECRET parity:
  +Host-header guard.
- **Loop 5 (DONE 2026-07-20):** Opus adversarial self-review of the loop-4 Host-guard
  → `janetweb-review-loop5.md` (**GREEN**, 0 P1/P2 — the availability risk cleared
  against every real caller: sendBeacon/SPA fetches same-origin, launcher poll raw-TCP,
  prod port always ≥8089 so no bare-Host omission). Sonnet re-verify: all 5 PASS
  (65/65). **Workstream: fresh deep-dive on `upr`** (destructive Unsupported Product
  Remediator, never loop-reviewed) → **found solid** on every pattern (confirm-word,
  dual-path self-guard, DNS-mismatch hard-abort, cmd-less uninstall-string decompose,
  protected-agent skip, live-requires-selection refusal). Honest clean-deep-dive
  outcome = **lock in the untested fail-closed behavior** (`373e7cc`): added
  `Upr.LiveSelectionRefuse.Tests.ps1` (**9** asserts — the critical live-uninstall-
  requires-selection refusal on BOTH paths, which had zero behavioral coverage; real
  dispatcher, zero WinRM) + a comment-accuracy fix (shared `$UprWorkerBlock` was
  mislabeled "report-uninstall only"; the DNS-mismatch abort guards both). No tool
  behavior changed → no version bump. Pester 1063→**1072** green (authoritative single
  post-commit run). New ranked item 8 (Opus F1/F6 Host-guard gaps). SECRET parity:
  +upr refuse coverage + worker comment.
  *(Loops 1–5 pushed to gitea.bth0mp.com/bth0mp/JANET-Web master on operator
  instruction after loop 5; the loop series otherwise commits local-only.)*
- **Loop 6 (DONE 2026-07-20):** Opus adversarial self-review of the loop-5 upr refuse
  tests → `janetweb-review-loop6.md` (**GREEN**, 0 P1/P2 — all three dispatcher paths
  traced non-vacuous: each `Should Match 'Refused'` doubles as proof the parse succeeded
  and the live gate fired; the dry-run negative would flip visibly if mis-scoped). No
  Sonnet re-verify (loop 5 changed no destructive code — test+comment only). **Workstream:
  closed ranked item 8 — the loop-4 Opus F1/F6 Host-guard gaps** (`2c96c16`), probe-first:
  a raw-socket probe fixed exact behavior, then pinned empty-Host→421, HTTP/1.0-no-Host→421
  (both reach our guard), HTTP/1.1-no-Host→400 (http.sys, asserted NOT 200), the legit
  beacon-cancel `POST .../cancel?t=` + good Host→200 (guard doesn't break sendBeacon), and
  — beyond the note — a FOREIGN Host on the cancel route→**421 before the `?t=` carve-out**
  (a rebound page can't abuse the beacon token carrier). Plus the F1 non-default-port
  comment. `Server.HostHeader` 9→14 asserts; comment-only server edit, no behavior change.
  Pester 1072→**1077** green (the baseline run raced the edits and returned 1077 too —
  known SMB file-race; 1072 is the loop-5-close baseline on the untouched tree). No new
  ranked items. SECRET parity: +extended Host-guard cases.
- **Loop 7 (DONE 2026-07-20):** Opus adversarial self-review of the loop-6 Host-guard
  tests → `janetweb-review-loop7.md` (**GREEN**, 0 P1/P2 — cancel-route 200 traced to a
  real idempotent-cancel contract, foreign-Host 421 to the guard-before-`?t=` ordering,
  raw-socket helper can only fail-closed). Accepted P3 F3 (empty-Host asserts pin exact
  421, http.sys-build-dependent, false-RED only). No Sonnet re-verify (loop 6 = test +
  comment). **Workstream: closed ranked item 7 — report-preview sandbox-resource-free
  guard** (`928d1ba`): `Reports.SandboxResourceFree.Tests.ps1` (12) statically asserts
  the report module stays self-contained (no external script/link/img/iframe, no
  src=/href=/download= attr, no @import/url()/print) AND the server CSP still leads
  `sandbox allow-scripts`, coupling the guard to what it guards so the loop-3 backstop
  can't silently rot. HTML-context-anchored patterns (a `$src` PS var is not a false
  positive — caught during authoring). Test-only, no version bump. Pester 1077→**1089**
  green (authoritative post-commit run). No new ranked items. **Backlog note:** item 7
  was the last cheap concretely-scoped tracked item — remaining are decision-gated
  (SECRET parity) or low-value speculative (item 4 token-on-cmdline, item 6 SKIP-tally);
  loop 8+ rotates to fresh tool deep-dives (acas/reports/c2c engines have unreviewed
  depth). SECRET parity: +report sandbox resource-free guard.
- **Loop 8 (DONE 2026-07-20):** Opus adversarial **deep-dive on c2c (C2C Nemesis
  v1.15.1)** — the richest destructive surface, never loop-reviewed → `janetweb-review-
  loop8.md` (**GREEN**, 0 P1/P2). Verified CLEAN with evidence: BitLocker recovery-key
  never leaks (no `.RecoveryPassword` access anywhere), add→escrow→enable fail-closed
  order, self-guard + wrong-box + confirm-word + target-token allowlist uniform through
  one guarded fan-out, cert expiry/persistence, no RCE, no fail-open. **The one gap
  (P3) fixed** (`fb7611f`, c2c **1.15.1→1.15.2**): escrow-failure orphan protector when
  the added protector's id is unresolvable (near-impossible) — re-enumerate + remove
  only RP protectors absent from the pre-Add `$beforeIds` snapshot (never a pre-existing
  one); strictly additive to a previously-orphaning state, zero regression risk. Tests
  (`C2c.Enable`): `bothfailblankid` (orphan removed, no leak, still FAIL) + (e3)
  pre-existing-never-removed + (e) resolved-id pin. Sonnet re-verify: **7/7 PASS**
  (150 c2c tests green, guards unweakened, additive-only, no key leak, no cert files).
  Lockscreen version pin → floor assert. Pester 1089→**1091** green (authoritative
  post-commit run). New ranked item 9 (c2c DHCP-stale local identity, negligible).
  SECRET parity: +c2c orphan-protector fix.
- **Loop 9 (DONE 2026-07-20):** Opus self-review of the loop-8 c2c fix →
  `janetweb-review-loop9.md` (**GREEN**, deeper pass — `$beforeIds` scope/population,
  resolved-id byte-identity, fail-closed-on-throw, remoting-safety, test non-vacuity all
  confirmed). **Workstream: Opus deep-dive on the wpt destructive engine** (the #1 tool,
  non-Chrome/Edge paths, never reviewed) → **YELLOW, one P2**: `app-update-apply` — which
  runs Custom Command (arbitrary remote PowerShell) — was the ONLY destructive dispatcher
  lacking `Remove-WptSelfTargets`; on the dispatcher the wrong-box guard is a no-op (self
  dialed by its own name), so an operator `Restart-Computer` in the wave would kill the
  HttpListener mid-dispatch (self-guarded arbitrary RCE against the dispatcher). **Fixed**
  (`aadab75`, wpt **6.8.2→6.8.3**): all 3 gapped dispatchers (app-update-apply P2 +
  app-action/unsupported-uninstall P3 — the latter removing the same Java self-guarded
  `fix-java` removes) now drop the dispatcher before fan-out via the proven 8-call-site
  block; + a `confirm=` dialog on the arbitrary-RCE action (its only one missing).
  Everything else in the engine verified CLEAN (uninstall-string decompose, Install-KB
  traversal-safe, token allowlist, fan-out creds, fail-closed). `app-update-verify`
  (read-only) stays unguarded. Tests: `Wpt.SelfGuardApply` (9, real dispatcher, zero
  WinRM); Edge exact pin → floor. Sonnet re-verify: **7/7 PASS** (8→11 self-guard call
  sites, helpers untouched, no weakening, no cert files). Pester 1091→**1100** green
  (authoritative post-commit run). No new ranked items. SECRET parity: +3 wpt self-guards
  + confirm string.
- **Loop 10 (DONE 2026-07-20):** Opus self-review of the loop-9 wpt self-guards →
  `janetweb-review-loop10.md` (**GREEN**; no over-guard, `$totalUnits` correct, tests
  non-vacuous, `confirm=` decorative-parity; N1 fixed, N2 accepted). Opus deep-dive on
  **remoteadmin** (Run Script = the same RCE class as wpt Custom Command) → **GREEN**: it
  is the REFERENCE self-guard implementation (drops the dispatcher before fan-out) and
  already 40+-assert tested; no fix. **Workstream: suite-wide self-guard-coverage audit**
  (Sonnet swept every tool's destructive actions, extending the loop-9 finding). Flagged 16
  unguarded destructive fan-outs; applying the repo's HARM-DRIVEN philosophy (guard only
  when self-action reboots/locks-out/aborts-dispatch or installs/removes software) left **3
  GENUINE gaps — fixed** (`f4ab266`): pkginstall **deploy-psadt**+**deploy-msi-bundle**
  (v2.5.7→**2.5.8**, arbitrary package install on the dispatcher, zero self-guard infra →
  new identity helper + unconditional drop) and wpt **clean-user-apps** (v6.8.3→**6.8.4**,
  deletes dispatcher app binaries → LIVE-only guard). The other 13 are benign-on-self,
  unguarded by design (documented). Corrected the loop-9 "the ONLY" comment (clean-user-apps
  was also unguarded — settled by reading source when the two agents disagreed) + N1.
  Sonnet re-verify: **8/8 PASS** (guards additive/filter-not-wipe, wrong-box untouched,
  12 wpt call sites, no cert files). Tests: `PkgInstall.SelfGuard` (8) + `Wpt.SelfGuardApply`
  clean-user-apps cases (3, incl. hermetic dry-run-not-guarded via faked worker). Pester
  1100→**1111** green (authoritative post-commit run). **New ranked item 10** (benign-on-self
  unguarded set — do NOT re-flag). SECRET parity: +pkginstall deploy guard + wpt
  clean-user-apps guard.
- **Loop 11 (DONE 2026-07-20):** Opus self-review of the loop-10 self-guards →
  `janetweb-review-loop11.md` (**GREEN**; the two bypass risks probed both clear — the
  pkginstall identity-set unary-comma is present so `.Contains` stays case-insensitive, and
  the `[bool]'false'` gotcha can't bypass the guard since `$dry` drives both guard and mode;
  one P3 surfaced). Opus deep-dive on **winupgrade** (9 destructive actions, feature-update
  reboots — the largest unreviewed destructive tool) → **GREEN**: self-guard 1:1 with all 9
  destructive actions before the single BeginInvoke, CAB leaf-sanitized + DISM no-shell,
  pin writes value-only to a hardcoded key, wrong-box uniform across all 5 reboot sites,
  fail-closed throughout; already 7-file tested. One accepted P3 (non-exploitable DISM
  interpolation — NTFS charset prevents it; PS 5.1 lacks ArgumentList; not worth touching
  working destructive code). **Workstream: the coercion fix** (`0b1a7c8`, wpt 6.8.4→**6.8.5**)
  — both deep-dives GREEN, so the deliverable is the one REAL item the self-review found:
  `clean-user-apps`+`cleanup-disk` coerced `dryrun` with raw `[bool]` (`[bool]'false'` is
  `$true` in PS → a `'false'` STRING silently ran dry, and for clean-user-apps ALSO skipped
  its live-only self-guard). Routed both through the existing `ConvertTo-WptBool` (a
  destructive-mode trust boundary; no new infra; UI JSON-bool path unchanged). Tests:
  `Wpt.SelfGuardApply` dryrun-string cases (2). Pester 1111→**1113** green (authoritative
  post-commit run). No new ranked items. SECRET parity: +wpt dryrun coercion fix.

## Coverage status (after loop 11)
Every most-used and most-dangerous tool now carries a documented adversarial review with a
GREEN (or fixed-to-green) verdict: server/auth/token (loop 1), wpt profiles (1-3) + full
engine (9) + self-guard audit (10), acas (self-guard-tested + Chrome/Edge), upr (5), c2c (8),
reports sandbox (3,7), remoteadmin (10), winupgrade (11); plus a suite-wide self-guard audit
(10). The destructive-action contract (confirm-word + self-guard + wrong-box + fail-closed)
is now enforced AND test-pinned uniformly. Remaining backlog is decision-gated (SECRET parity)
or low-value speculative (items 4/6/9) + the benign-on-self do-not-re-flag set (item 10).
Loop 12+ candidates: the still-undeepdived smaller destructive tools (adto AD-writes,
secureboot, dhcp, biosfirmware, certdeploy), correctness (not security) deep-dives on the
read/report paths, or SECRET-parity execution if the operator signs off.
