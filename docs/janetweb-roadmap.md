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
6. **SKIP-books-green reporting note** (loop-2 Opus P3-3 + loop-4 F14) — **acas half REFUTED
   (loop-25 deep-dive):** `AcasOkOf` (`:2354`) DOES return OK for `SKIP*`, but its only consumer
   checks `$isSkip` first (`:2473`), so skips land in skipCount with a 'Skipped' audit, NEVER in
   okCount — no false-clean today (the predicate is a latent hazard if reused raw, not a live bug).
   Remaining: wpt's run summary counting a Skipped host under Failed while its audit says Skipped —
   reconcile if the operator wants stricter counts.
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
11. ~~Complete the reports host-key normalization sweep~~ — **CLOSED loop 14** (`1c3cdb9`):
    remediation-refresh app-aggregate + export-poam counter normalized; every host tally
    now agrees with CORA.
12. ~~IAVM-map CSV formula-injection guard~~ — **CLOSED loop 14** (`1c3cdb9`):
    `Write-ReportsIavmMap` `$q` now carries the `=+-@` prefix guard.
10. **Benign-on-self unguarded set (do NOT re-flag)** (loop-10 audit) — these destructive
    fan-outs deliberately lack a self-guard because acting on self is harmless/desirable
    (no reboot/lockout/dispatch-abort, no software install/remove): wpt `reboot-abort`,
    `winrm-bootstrap`, `healer-*` (restart-ccm/wmi-repair/wu-reset/gpupdate/ccm-repair/
    rdp-rebind), `remote-message`, `cleanup-disk`, `maintenance-unlock`; acas
    `preflight-services`; restart `abort-scheduled`. A future self-guard sweep will
    re-flag them — this is the standing "by design" answer. Guarding them would remove
    legitimate dispatcher self-repair/self-abort.
13. ~~wpt kb-install loose KB-match (substring wrong-update bind)~~ — **CLOSED loop 22** (`Test-WptKbNameMatch`,
    wpt 6.8.6): anchored ArticleID-exact / bounded-Name-token match so a shorter requested KB
    (KB5034) can't substring-match a longer article (KB5034123), install the wrong update, and
    skip the MSU fallback. Also fail-closed on a null InstallUpdates ReturnValue.
14. ~~wpt kb-install reports an unverified async MECM trigger as "Installed"~~ — **CLOSED loop 23**
    (`Get-WptKbInstallResult`, wpt 6.8.7): any MECM trigger now reads "Triggered (verify)", only a
    confirmed MSU exit-0 reads "Installed"; the view surfaces the Result and counts only confirmed
    installs. **Follow-on (14b, open):** the `VulnPatched` audit action still books Success for a
    MECM-only trigger — the operator-facing false-clean (Result label + installed count) is closed,
    but the audit taxonomy overstates; re-plumb the fan-out per-row audit action to distinguish
    trigger-vs-confirmed when the audit surface is next worked.
15. ~~wpt M365 C2R "Verified" goes green on a FAILED update~~ — **CLOSED loop 24**
    (`Get-WptC2rVerified`, wpt 6.8.8): Verified now requires the key fresh AND `LastScenarioResult`
    = success; fresh-but-failed reads NOT verified, unknown reads $null. No more green-on-failure.
16. **wpt Chrome/Edge "Verified" = "registry touched in 14 days", not "current"** (loop-22 Fable
    deep-dive, CONFIRMED, by-design-weak) — `New-WptUpdateClientVerify :875` has no target/baseline
    version compare, so a browser updated 10 days ago reads Verified while a newer security build is
    what ACAS flagged. Fix: accept an expected-min-version and compare, or relabel "Recently updated".
17. **wpt verify-patch KB filter article-leg unanchored** (loop-22 Fable deep-dive, CONFIRMED, LOW) —
    `:2468` `"KB$art" -match [regex]::Escape($f)` is an unanchored substring, so a KB filter can show
    a different update's row as Installed in the filtered verify view (mitigated: the full update
    Name is shown). Fix: anchor the article leg (exact) while keeping the free-text Name filter.
18. ~~acas Verify/dry-run rows light the PATCHED stat card, incl. still-vulnerable hosts~~ — **CLOSED
    loop 26** (`Get-AcasVerifyRowStatus`, acas 1.11.7): the verify branch now prefixes UNCONFIRMED
    unless the probe confirms the host is current ([fresh]), so a [stale]/indeterminate host is amber
    and out of the PATCHED tally instead of counting as patched.
19. ~~acas schedule-reboot books VulnPatched Success at schedule time~~ — **CLOSED loop 28** (acas
    1.11.9): schedule-reboot now audits `TouchHost` (scheduling a pending, abortable reboot is a touch,
    not a confirmed patch); VulnPatched stays on the actual patch-install/update confirmations.
20. **acas default-open classification of empty/foreign worker output** (loop-25 Fable deep-dive,
    SPECULATIVE) — empty EndInvoke / first-item output → `'OK (no output)'` (`:2464`); no reachable
    leak in shipped workers, but a future profile emitting stray output gets booked patched. Default
    unknown/empty → UNCONFIRMED; read the LAST output item, not the first.
21. ~~acas kb-install shares wpt's loop-22 bugs, unfixed~~ — **CLOSED loop 27** (`Test-AcasKbNameMatch`,
    acas 1.11.8): ported wpt's anchored KB-match (`KB<num>(?!\d)`) + inline `$kbMatch` mirror + the
    null-ReturnValue fail-close into AcasKbInstallBlock. acas↔wpt kb-install now at parity.
22. **c2c fix host rollup masks a known-non-compliant SKIP pillar as FIXED** (loop-29 Fable deep-dive,
    CONFIRMED, HIGH — F1) — `c2c :2333-2343`: SKIP only surfaces at host level when EVERY result is
    SKIP, so Firewall FIXED + Encryption SKIP ("route desk-side", definitely non-compliant, untouched)
    → host **FIXED**, `fixed++`, VulnPatched Success audit. Fix: any SKIP alongside successes → a mixed/
    skip-aware host status + a skip-aware summary/audit.
23. **c2c Patches fix reports a MECM trigger (KICKED) as fixed** (loop-29 Fable deep-dive, CONFIRMED,
    HIGH — F2) — `:2063-2068` emits KICKED merely because the SUM scan/eval trigger was accepted; no
    re-verify (async). Rolls up as FIXED (`:2333`/`:3060`) + fleet "FIXED: N" + VulnPatched Success. The
    wpt/acas trigger!=done sibling. Fix: distinct TRIGGERED status excluded from the fixed count, or a
    delayed CCM_SoftwareUpdate re-check.
24. **c2c per-pillar fleet tally folds NOT VERIFIED / SKIP / IN PROGRESS into "nochange"** (loop-29
    Fable deep-dive, CONFIRMED — F3) — `:3059-3061`: a PkiRoots push where every added cert vanished
    on re-read (the durability trio's loud NOT VERIFIED) rolls up as "nochange 3" — the trio's signal
    degraded to "nothing needed doing"; host-level NOT VERIFIED rows also fit no summary bucket
    (`:3135-3145`). Fix: dedicated skip/inprogress/notVerified buckets in both tallies.
25. ~~c2c Patches SCAN missing-data default reads compliant~~ — **CLOSED loop 30** (`Test-C2cUpdateOverdue`,
    c2c 1.15.4): a missing update with no usable timestamp now counts OVERDUE (fail-closed); the
    non-datetime-Deadline deserialize glitch also now falls through to StartTime. c2c scan fully fail-closed.
26. **c2c AntiMalware FIX: unknown signature age → "ALREADY PROTECTED"** (loop-29 Fable deep-dive,
    CONFIRMED — F6) — `:1885`/`:1960`: the sig heal gates on `($null -ne $ageHours) -and (...)`, so an
    unreadable age skips the heal and lands NOCHANGE/"ALREADY PROTECTED"; the SCAN treats the same
    unknown age as FAIL (`:802`). Fix: null age on the fix path → FAIL/UNVERIFIED, mirroring the scan.
    NOTE: entangled with items 22/23/24 (the honest UNVERIFIED status routes through the same fix-rollup
    buckets) — best fixed together in a dedicated c2c fix-rollup-taxonomy loop.
27. ~~winupgrade upgrade-drive "STAGED" contaminated by stale staging → reboots an un-staged host~~ —
    **CLOSED loop 36** (winupgrade 0.5.5): the `PHASE:STAGED` re-read now classifies the ~BT tree
    (`Get-WinUpgradeStagingClass` rule) and counts staged only when not Stale, so a rolled-back tree no
    longer triggers a reboot. **Follow-on (27b, open):** the generic CBS/WU/PFRO pending-reboot markers
    (checked first) can still read a non-feature-update pending as staged; demoting them is nuanced (a CBS
    RebootPending can be a completed feature update, so demoting risks a false-negative). Requires a
    feature-update-specific pending signal.
28. ~~winupgrade bypass (MoSetup) value asserted but never read-back-verified~~ — **CLOSED loop 33**
    (winupgrade 0.5.4): `$pinReadSb` now reads the MoSetup value (`BypassPresent`); Pin requires it set
    when bypass requested ("BYPASS NOT VERIFIED"), Unpin requires it gone ("NOT REMOVED ... bypass"), so
    a silently-failed ACL no longer reports the unsupported bypass set/removed. (F8 SPECULATIVE remains:
    ForceDiscovery / AutoFix policy re-writes the TRV pin with no read-back.)
29. **winupgrade AutoFix marks fixes applied before confirming + all-failed reads "NO CHANGES"**
    (loop-31 Fable deep-dive, CONFIRMED, HIGH — F5) — `'repair'` added to `$fixes` BEFORE DISM/SFC run
    (`:2804`); a DISM exception still → FIXED "Applied: repair"; a needed driver-removal that fails →
    "NO CHANGES / no fixes necessary". Fix: add fix keys only on confirmed success, track failed attempts
    → FAILED/PARTIAL, Ok=$false on any fail.
30. ~~winupgrade Diagnose verdict READY ignores disk/RAM/Secure Boot fails its own scan reported~~ —
    **CLOSED loop 32** (`Get-WinUpgradeDiagnoseVerdict`, winupgrade 0.5.3): a `[FAIL] Disk`/`RAM`/`Secure
    Boot` host now reads a distinct NOT READY (after NEEDS POLICY, before READY); summary names the reason.
31. ~~**winupgrade unparseable sfc output → 'no violations' → CLEAN**~~ **CLOSED loop 37** (winupgrade
    0.5.6): the no-match `else` in `Get-WinUpgradeRepairVerdict` (`:668`) and its inline mirror (`:2685`)
    now default to `'unknown'` → PARTIAL (never CLEAN), + an `[WARN] output not recognized` report line.
    `Winupgrade.RepairVerdict.Tests.ps1` (8) is the helper's first coverage.
32. **upr verify skips registry keys with no DisplayName** (loop-35 Fable deep-dive, SPECULATIVE) —
    `upr :1127` `if (-not $it.DisplayName) { continue }` fires before the PSChildName/GUID compare, so a
    half-torn uninstall (key survives with DisplayName deleted, files on disk) could read as gone → OK
    while a file-based Tenable plugin still flags it. Couldn't demonstrate a product that does this. Fix:
    match PSChildName/GUID even on DisplayName-less keys.
33. **upr end-of-run status "N ok, M failed" counts reachable hosts, not removals** (loop-35 Fable
    deep-dive, display-only) — `upr :1292`: on the uninstall path `emit.ok=$true` whenever the host was
    enumerated even if every uninstall FAILED, and the honest host-level `auditResult='Failure'` is
    discarded, so "5 ok, 0 failed" can print over a run that removed nothing. The rows, per-app Failure
    audits, and `itemCount` stay honest (no product is ever COUNTED removed) — a wording hazard. Fix:
    word the uninstall status as "N host(s) processed" / surface the removed count.

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
- **Loop 12 (DONE 2026-07-20):** Opus self-review of the loop-11 dryrun coercion →
  `janetweb-review-loop12.md` (**GREEN**; full truth-table walk, `'false'`-string test
  non-vacuous; one accepted P3 — unrecognized dryrun→live, non-UI-reachable + self-guard
  backstopped). **Workstream: Opus deep-dive on adto** — the suite's only DESTRUCTIVE-via-LDAP
  tool (userAccountControl writes, a different risk class from WinRM fan-out) → **YELLOW, 3
  fixed** (`68ca436`, adto **0.2.1→0.2.2**). CLEAN: no LDAP-filter injection, DN bind-redirect
  guard on every write path, UAC read-modify-write with a 6-bit allowlist (no escalation write),
  confirm gates, IAO RBAC bound to the Windows launching identity. **F1 (P2/borderline P1):**
  `fix` set ACCOUNTDISABLE on ANY in-domain DN with no object-type guard — a crafted plan
  naming a **DC or a privileged (adminCount>=1) / break-glass account** would disable it (DoS of
  a critical AD object). Added a pre-write refusal for a DC (`SERVER_TRUST` bit) or
  `adminCount>=1` (PROTECTED row + Skipped audit; normal objects unaffected). **F2 (P2):**
  `validate-iao` reported VALIDATED with no post-commit re-read (fail-open) → now re-reads,
  VALIDATED only if the stamp persisted else FAILED. **F3 (P3):** bind-redirect rejections now
  audited. First adto behavior suite `AdTo.WriteGuards.Tests.ps1` (8, `New-AdToEntry` shimmed —
  no directory bound; non-vacuous via the fake's Committed flag). Sonnet re-verify: **PASS**
  (guards additive, all existing gates intact, no cert files). Pester 1113→**1121** green
  (authoritative post-commit run). Accepted F4 (baseline re-read perf nit). No new ranked
  items. SECRET parity: +adto F1/F2/F3.
- **Loop 13 (DONE 2026-07-20):** Opus self-review of the loop-12 adto guards →
  `janetweb-review-loop13.md` (**GREEN**; SERVER_TRUST catches a writable DC, no
  workstation false-positive, adminCount `"0"+` trick correct, F2 `[string]`-cast dodges
  the multi-valued `-match` hazard). Its **P3 fixed** (`0331e66`, adto **0.2.2→0.2.3**):
  a **read-only DC (RODC)** slipped the F1 guard (carries `PARTIAL_SECRETS_ACCOUNT`
  0x04000000, not SERVER_TRUST, not adminCount-protected) → added the bit + made adminCount
  parse fail-CLOSED. **Workstream: correctness deep-dive on the reports engine** (the
  operator's daily deliverable — the risk is a silent MISCOUNT) → **YELLOW, fixed**
  (`e0a5d51`, reports **2.14.20→2.14.21**). Verified CORRECT: KEV exact-match (not
  substring), empty-KEV surfaced, CSV formula-guards on all deliverable exporters,
  div-by-zero guards, Dirty-30, CORA dedup. **P2 (systemic):** CORA deduped hosts by the
  normalized audit key but ~7 sibling tallies keyed on the RAW hostname → the same host
  set reported DIFFERENT totals across the tool (short+FQDN), and the posture digest was
  self-contradictory (deduped UniqueHosts vs raw HostsWithKev). Normalized the HEADLINE
  count sites (posture-digest KEV map, sla-aging, command-brief KEV, remediation-plan,
  kb-needed) to `Get-ReportsAuditHostKey`. Test `Reports.HostCountAgreement` (a two-name
  host = 1 host across sla-aging/kb-needed, agreeing; digest HostsWithKev=1 via CSV).
  Self-review (Fable, inline) confirmed the one display side-effect (kb-needed CSV shows
  normalized keys) is consistent with CORA. Pester 1121→**1127** green. **New ranked items
  11** (complete the reports host-key sweep — thirdparty/iavm/export-poam) **+ 12** (IAVM-map
  CSV formula guard). SECRET parity: +adto RODC guard + reports host-count normalization.
  *(Operator mid-loop: loop → 15-min cadence + prefer Fable model for agents, from loop 14.)*
- **Loop 14 (DONE 2026-07-20):** first loop under Fable-preferred / 15-min cadence — the
  self-review of loop-13 (`0331e66`/`e0a5d51`) and the workstream were done **inline by
  Fable**, no Opus/Sonnet. Self-review **GREEN** (RODC bit correct, adminCount fail-closed
  only fires on unparseable, the kb-needed CSV normalized-key display is consistent with
  CORA). **Workstream: closed ranked items 11 + 12** (`1c3cdb9`, reports **2.14.21→2.14.22**)
  — completed the host-key normalization sweep (remediation-refresh app-aggregate at `:4776`,
  which re-aggregates independently of the loop-13 upstream fix and needed its own; export-poam
  "Finding N" counter at `:6254`/`:6295`) so EVERY host tally agrees with CORA, and added the
  `=+-@` formula-injection guard to `Write-ReportsIavmMap` (`:872`) so IavmMap.csv matches every
  other exporter. Tests (`Reports.HostCountAgreement`): remediation-refresh TargetCount==1 for a
  two-name host + IAVM Title-`=`-prefixed + clean-Title-unchanged. Pester 1127→**1130** green.
  **Reports correctness is now COMPLETE** (all host counts key on `Get-ReportsAuditHostKey`; all
  CSV exporters carry the formula guard). No new ranked items. SECRET parity: +reports sweep
  tail + IAVM guard.
- **Loop 15 (DONE 2026-07-20):** Fable-inline. Self-review of loop-14 → **GREEN** (reports
  sweep live, export-poam counter aligned on all 3 sites, IAVM `$q` returns correctly).
  **Workstream: deep-dive on secureboot** (Enable Secure Boot — a UEFI firmware write that
  leaves hosts pending reboot; the highest-consequence un-reviewed destructive tool) →
  **YELLOW, fixed**. Verified CLEAN: positive UEFI+GPT **brick-safety** skip (`:352`),
  self-guard before fan-out (`:1139`), wrong-box hard-abort BEFORE the password-bearing C$
  drop (`:571`), fail-closed result polling (`:702`), BIOS-password script self-delete
  (`:410`). **The gap:** `enable-secure-boot` was `destructive:true` but had NO typed
  confirm-word — the one destructive tool missing the second barrier every sibling has
  (remoteadmin 'RUN', c2c/adto 'FIX'); a live fleet firmware write fired from the button on
  one click. Fixed (`4ab8c05`, secureboot **1.6.0→1.6.1**): manifest `confirm=` + a view-side
  danger dialog requiring the operator to type **ENABLE**, gated to the LIVE path (Dry Run
  ungated) — the loop-9 wpt pattern. Additive-only, no existing guard touched (verified).
  Test `Secureboot.ConfirmWord` (manifest confirm + version + the view requires
  `confirmWord: 'ENABLE'` positioned inside `if (!isDry)` before `ctx.run`); Scan pin → floor.
  Pester 1130→**1137** green. **Every destructive tool now carries the full contract**
  (confirm-word + self-guard + wrong-box + fail-closed) — secureboot was the last gap.
  No new ranked items. SECRET parity: +secureboot enable typed-confirm barrier.
- **Loop 16 (DONE 2026-07-20):** Fable-inline. Self-review of loop-15 → **GREEN** (secureboot
  confirm-word additive; all 6 guards intact). **Workstream: deep-dive on certdeploy** (DoD
  trust-root push over WinRM, offline/local-bundle) → **GREEN** — verified the full contract
  (typed `DEPLOY` + self-guard + DNS wrong-box hard-abort before the C$ round-trip + additive-
  only install with non-CA-anchor rejection + persistence re-verify) AND the one removal path
  (opt-in `prunePki`, triple-gated: expired + retired-DoD regex + not-legacy-keep, CA-store
  only). **Fix was in the TEST, not the tool** (`fac190f`, test-only, certdeploy stays 1.4.0):
  the guard-copy sync check (`$legacyKeep` prune-exclusion must equal the master allowlist, or
  the prune could delete a cert deploy just pushed) was loose (source-substring, one-direction)
  → rewrote to extract the actual `$legacyKeep = @(...)` array and assert exact SET EQUALITY
  both ways. Pester **1137** (test-only, count unchanged). **Destructive-tool coverage COMPLETE**
  — every destructive tool now has a full-contract review; the 3 removal paths (upr uninstall,
  adto/c2c writes, certdeploy prune) are allowlisted + gated + sync-guarded. No new ranked
  items. SECRET parity: +certdeploy prune-sync test precision.
- **Loop 17 (DONE 2026-07-20):** Fable-inline. Self-review of loop-16 → **GREEN** (certdeploy
  prune-sync test-only, count unchanged). **Pivot: destructive surface exhausted → correctness
  of the remediation ROUTING.** Workstream: deep-dive on the acas match engine
  (`Get-AcasVulnGroups` over `Get-AcasProfileMatchTable`) — the classifier that turns a finding's
  plugin name into the auto-patch profile. A MIS-ROUTE is worse than a miscount: it runs the WRONG
  fix (or a no-op) on a real vuln. → **GREEN** (`:1642-1657`): first-match-wins with specific
  rules above generic, and each rule's `Exclude` tokens checked BEFORE its keyword — the exclusions
  are the only thing stopping the dangerous look-alike mis-routes (Edge WebView2→Edge, Symantec→
  Defender, Chrome Remote Desktop→Chrome, Access Database Engine/LibreOffice→M365). **The gap
  (coverage, not correctness) → FIXED** (`bb9e9c2`, test-only, acas stays v1.11.5): the routing
  itself was untested (only the individual profiles were) — a future match-table edit could
  silently reintroduce a mis-route. `Acas.MatchTableRouting.Tests.ps1` (13) drives the REAL router
  with synthetic findings: 4 positive routes (incl. specific-beats-generic) + 5 exclusion
  non-routes (the safety-critical half) + 4 structural "the Exclude list is present" assertions.
  Pester **1137→1150** green. No new ranked items. SECRET parity: +acas match-table routing test.
- **Loop 18 (DONE 2026-07-20):** Fable-inline. Self-review of loop-17 → **GREEN** (routing test-
  only, 13/13). **Workstream: CSV-INGESTION robustness** — the front of the offline/CSV-fed
  pipeline, where a mis-parsed row silently corrupts every downstream number. Deep-dive on
  `ConvertFrom-AcasCsv` (`:1507`, the acas import parser for the most-used remediation tool) →
  **GREEN**: `Import-Csv -Encoding UTF8` (native BOM + quoted/embedded-comma fields), missing/
  renamed column returns empty (no throw), host token whitelist-validated before it can become a
  remote target, msek-* servers skipped, and a **loud wrong-template hint** when rows parse but
  none map to a host (the column-mismatch case surfaces instead of importing zero). **The gap
  (coverage) → FIXED** (test-only, acas stays v1.11.5): the parser — the pipeline's front door —
  was untested end-to-end (only `Test-AcasHostToken` was, in isolation). `Acas.CsvIngestion.Tests.ps1`
  pins the robustness contract: correct host-pick (DNS>NetBIOS>IP) + field mapping, quoted
  embedded-comma survival, missing-column tolerance, server-skip, garbled-token rejection, and the
  wrong-template warn hint. Pester **1150→1165** green. No new ranked items. SECRET parity:
  +acas CSV-ingestion robustness test.
- **Loop 19 (DONE 2026-07-21):** Fable-inline. Self-review of loop-18 → **GREEN** (CSV-ingestion
  test-only, authoritative 1165). **Workstream: the OTHER CSV front door** — reports'
  `Parse-AcasFile` (`:1382`), a separate importer from acas's, same offline/CSV robustness
  questions. Verified GREEN on encoding (`Read-CsvRowsSafe` uses StreamReader UTF-8+BOM-detect +
  TextFieldParser quoted/multiline/malformed-tolerant), flexible column resolution
  (`Get-AcasColumnMap`, `[\s._]`-tolerant synonyms), and DNS>NetBIOS>IP per-row host fallback.
  **The gap (correctness) → FIXED** (`:1456`, reports **2.14.22→2.14.23**): when the header parsed
  but host and/or plugin column couldn't resolve (wrong template / renamed columns), it did
  `return $findings` **empty with NO warn** — a silent zero-import that reads as a clean fleet (the
  false-comfort undercount the offline constraint is vulnerable to). acas already guarded this;
  reports didn't. Fixed additively: a `warn` naming the missing column(s), `$Emit`-gated (all 3
  callers pass it). `Reports.WrongTemplateHint.Tests.ps1` (5) drives the real parser via temp CSVs
  + captured `-Emit`: wrong-template warns + names missing columns, plugin-only-missing, positive
  control (parses, no false warn), + exact 2.14.23 pin; prior exact pin in HostCountAgreement → `-ge`
  floor. Pester **1165→1170** green. Both importers now fail LOUD on a wrong template. No new
  ranked items. SECRET parity: +reports wrong-template hint (Parse-AcasFile).
- **Loop 20 (DONE 2026-07-21):** Fable-inline. Self-review of loop-19 → **GREEN** (wrong-template
  warn sits after the empty-header early-return, never false-warns; authoritative 1170). **Workstream:
  COMPLETE the reports host-key normalization sweep** (standing open item since loop 14). Loops 13-14
  normalized compare/closure/CORA host counts; the tail was `Build-RemediationPlan` (`:1793`), the
  Remediation Plan. **The gap (correctness) → FIXED** (reports **2.14.23→2.14.24**): the per-(host,app)
  bucket key (`:1802`) and per-app summary host count (`:1878`) were keyed on the RAW hostname, so a
  short+FQDN pair of one box made TWO plan rows + counted TWO hosts — while the ADJACENT Other-group
  count (`:1852-1855`) had ALREADY been normalized in loop 13 (proof it was an oversight, not intent).
  The bucket key also doubles as the session status key (read `:1868`, written `:5998`), so the fix
  normalizes THREE coupled sites (bucket + summary + status setter) on `Get-ReportsAuditHostKey` — or
  a marked status would land on a key the reader never checks. Raw first-seen Hostname kept for
  display; only the KEY folds. `Reports.RemediationPlanHostKey.Tests.ps1` (4) drives the real builder:
  short+FQDN (FQDN-first) → 1 row + `Summary.Chrome==1`; distinct hosts → `==2` (no over-merge);
  normalized-key status reads back onto the folded row; + exact 2.14.24 pin (loop-19 pin → floor).
  Pester **1170→1174** green. **Host-key normalization sweep COMPLETE** for the per-app rollups.
  No new ranked items. SECRET parity: +Build-RemediationPlan host-key fold.
- **Loop 21 (DONE 2026-07-21):** Fable-inline. Self-review of loop-20 → **GREEN** (grep confirms the
  3 normalized sites are the ONLY `"$Hostname|$app"` key consumers; no status orphaned). **Workstream:
  deep-dive on the remediation-SLA aging math** (drives prioritization + the RMF POA&M export).
  Verified CORRECT: safe baseline loader (positive-int overrides only, so a typo can't force
  everything overdue), `Get-ReportsSlaDeadline` KEV-override + severity map, and the bucket rule
  (date-only today, floored age clamped >=0, `soon=max(3,ceil(25%))`, OVERDUE at `dueIn<0`,
  deadline-day = DUE-SOON). **The finding (durability) → FIXED**: the boundary rule was HAND-DUPLICATED
  across the two operator-facing SLA views — sla-aging (`:6188`) and the Executive Command Brief
  (`:7078`) — identical today but a latent drift the moment one copy is edited, and untested.
  Consolidated into one pure helper `Get-ReportsSlaBucket -Deadline -Age` (`:992`); both sites call
  it. Behavior-identical → **NO version bump** (manifest version = behavioral-change signal; this is
  internal single-source-of-truth consolidation). `Reports.SlaBucket.Tests.ps1` (18) pins every edge:
  threshold transitions, deadline-day boundary, the 3-day floor beating 25% on short KEV windows, the
  zero-deadline no-divide guard, + the severity-map/KEV override. Pester **1174→1192** green. The
  two SLA dashboards can no longer drift. No new ranked items. SECRET parity: +Get-ReportsSlaBucket
  consolidation.
- **Loop 22 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-21 →
  **GREEN** (SLA consolidation byte-identical). **Workstream: fresh deep-dive on wpt** (most-used
  tool, 480KB, no prior loop-era review) — a bounded Fable worker on ONE question: can wpt report a
  host PATCHED when it isn't (false-clean)? Verified each finding in-code. **Spine is fail-closed**
  (kb-scan exact `-eq`, failed Get-HotFix → Missing, verify-patch timeout ≠ Installed). **4 CONFIRMED
  false-cleans found**; fixed the crispest, ranked the rest (items 14-17, #14 highest). **FIXED**
  (wpt **6.8.5→6.8.6**): kb-install matched requested KBs with `-like "*$kb*"` (`:2740`), so KB5034
  bound an update named ...KB5034123..., installed the WRONG update, marked the real KB handled, and
  skipped the MSU fallback; a null InstallUpdates ReturnValue was also counted as success. New
  canonical `Test-WptKbNameMatch` (exact ArticleID or bounded Name token `KB<num>(?!\d)`); remote
  scriptblock mirrors it inline; trigger now fail-closed (`$null -ne $rv -and [int]$rv -eq 0`). No
  guard weakened (DNS wrong-box `:2726`, self-guard `:5983` untouched); all 117 wpt tests green.
  `Wpt.KbMatch.Tests.ps1` (11) pins the rule (bug case + boundaries + normalization) + exact 6.8.6
  pin (SelfGuardApply exact → floor). Pester **1192→1203** green — BUT the authoritative run first
  surfaced a **1-test regression** (1202/1203): the KB-match commit gratuitously reworded the
  InstallUpdates rejection message ("rejected"→"not confirmed"), breaking `FixVerify2` (`Should Match
  'rejected'`); the pre-commit gate was a `Wpt.*`-only glob that misses FixVerify2. Repaired at
  loop-23 start (`c9b22d1`): wording restored, null-fail-close kept + finally tested. 4 new ranked
  items (14-17). SECRET parity: +kb-install KB-match anchoring + null-rv fail-close.
- **Loop 23 (DONE 2026-07-21):** Fable-inline. **Repaired the loop-22 regression FIRST** (`c9b22d1`,
  above) + added its missing null-fail-close test. **Workstream: roadmap item 14** (highest-harm wpt
  false-clean) → **CLOSED**. kb-install reported an unverified async MECM trigger as "Installed"
  (server `:6035` + view `wpt.view.js:87` counted every no-error host installed). **FIXED** (wpt
  **6.8.6→6.8.7**): pure `Get-WptKbInstallResult` (`:2734`) — any MECM trigger → `Triggered (verify)`
  (errs toward verify, never over-claims), confirmed MSU exit-0 → `Installed`, else `No change`; the
  view now surfaces `r.Result` and counts only a confirmed `Installed`. No guard weakened; 138 wpt +
  FixVerify2 green. `Wpt.KbInstallResult.Tests.ps1` (8) pins the helper + view static asserts + exact
  6.8.7 pin (KbMatch 6.8.6 exact → floor). Pester **1203→1212** green (0 fail — also re-validated the
  loop-22 repair). Pre-commit gate corrected to
  full wpt + FixVerify2. Follow-on: the VulnPatched audit still books Success for a MECM-only trigger
  (label + Detail close the visible false-clean; audit taxonomy is a smaller follow-up to item 14).
  SECRET parity: +honest kb-install label (Get-WptKbInstallResult + view).
- **Loop 24 (DONE 2026-07-21):** Fable-inline. Self-review of loop-23 → **GREEN** (grepped the whole
  test tree for old kb-install view assertions per the loop-22 lesson; authoritative 1212/0-fail).
  **Workstream: roadmap item 15** (next wpt verify false-clean) → **CLOSED**. The M365 C2R verify
  (`$script:M365C2RVerify:854`) decided Verified from ONLY the ClickToRun\Configuration key mtime
  (`<7 days`), but C2R bumps that key on every attempt INCLUDING failures — a failed Force Update read
  Verified with the OLD vulnerable version. **FIXED** (wpt **6.8.7→6.8.8**): pure `Get-WptC2rVerified`
  (`:846`) — Verified TRUE only when fresh AND `LastScenarioResult` shows success, `$null` when no
  timestamp/unknown (never over-claims), `$false` when stale/failed; scriptblock mirrors it inline +
  surfaces the result in Detail. Read-only verify path, no guard involved; 134 wpt tests green.
  `Wpt.C2rVerify.Tests.ps1` (9) pins every case incl. fresh+Failure→$false + exact 6.8.8 pin
  (KbInstallResult 6.8.7 exact → floor). Pester **1212→1221** green. SECRET parity: +honest M365
  C2R verify. wpt verify cluster: #13/#14/#15 done; #16 (Chrome/Edge recency), #17 (verify-patch
  filter), #14b (audit taxonomy) remain.
- **Loop 25 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-24 →
  **GREEN**. **Workstream: diversified to acas** (remediation engine) — a bounded Fable worker on "where
  does un-remediated read as patched?" found 4 false-cleans + **REFUTED item 6** (SKIP-as-OK: the
  predicate returns OK for SKIP* but the only consumer checks skip FIRST, so skips never hit okCount —
  updated item 6). **FIXED** (acas **1.11.5→1.11.6**) the highest-harm cluster: kb-install reported an
  async MECM trigger / UsoClient fire as **OK** (+ VulnPatched audit + PATCHED stat) and let a partial
  install mask a real error (`:2663`). Pure `Get-AcasKbInstallStatus` (`:2588`) — error→FAIL (never
  masked), trigger/fire→UNCONFIRMED (AcasOkOf amber, out of the tally), confirmed MSU→OK, skip→SKIP;
  worker mirrors it inline (module-less runspace) + `$usoTriggered` flag. No guard weakened; 163 acas +
  FixVerify2 + FixGuards green. `Acas.KbInstallStatus.Tests.ps1` (9) + FixVerify2 rv=0 corrected `^OK`→
  `^UNCONFIRMED` (it pinned the false-clean) + exact 1.11.6 pin (EdgeProfile exact → floor). Pester
  **1221→1230** green. **4 new ranked items (18-21).** SECRET parity: +honest acas kb-install status.
- **Loop 26 (DONE 2026-07-21):** Fable-inline. Self-review of loop-25 → **GREEN**. **Workstream:
  roadmap item 18** (HIGH, top remaining acas false-clean) → **CLOSED**. "Verify" is a read-only dry-run,
  but its rows feed the shared run binder that lights the PATCHED stat card for any OK row
  (`acas.view.js:742`); the verify branch (`acas:1947`) returned `"v=.. [fresh|stale|n/a].."` with no
  status prefix → `AcasUpdateRowOf:2367` classified OK → every reachable host counted PATCHED, incl.
  `[stale]` (Verified=$false = still on the old vulnerable version). **FIXED** (acas **1.11.6→1.11.7**):
  pure `Get-AcasVerifyRowStatus` (`:2359`) — fresh→OK, stale/n/a→UNCONFIRMED; the verify branch mirrors
  it inline (`$prefix='UNCONFIRMED '` when not fresh) → amber row + out of the tally. One module-side
  change fixes grid + stat. Read-only path, no guard; 156 acas + FixVerify2 green. `Acas.VerifyRowStatus.
  Tests.ps1` (5) pins the verdict + static prefix assert + exact 1.11.7 pin (KbInstallStatus 1.11.6
  exact → floor). Pester **1230→1235** green. SECRET parity: +honest acas verify row. Remaining acas
  items: 19 (schedule-reboot audit), 20 (spec default-open), 21 (acas kb-install KB-match+null-rv).
- **Loop 27 (DONE 2026-07-21):** Fable-inline. Self-review of loop-26 → **GREEN**. **Workstream:
  roadmap item 21** (proven port) → **CLOSED**. The acas kb-install MECM scriptblock carried the
  byte-identical wpt loop-22 bugs: loose `-like "*$kb*"` KB-match (`:2667/2669` — wrong update + skipped
  MSU fallback) and `$null -eq $rv -or` fail-open (`:2670` — null InstallUpdates return counted as a
  trigger). **FIXED** (acas **1.11.7→1.11.8**): canonical `Test-AcasKbNameMatch` (`:2596`, port of
  `Test-WptKbNameMatch`) + inline `$kbMatch` mirror; null-rv fail-close (`$null -ne $rv -and`, null-safe
  message). No guard weakened; 180 acas + FixVerify2 + FixGuards green. `Acas.KbMatch.Tests.ps1` (11,
  mirrors wpt) + FixVerify2 acas NULL case (`-Rv -1` → FAIL, `ReturnValue=<null>`) + exact 1.11.8 pin
  (VerifyRowStatus 1.11.7 exact → floor). Pester **1235→1247** green. **acas↔wpt kb-install parity
  complete** (KB-match + null-rv + honest status). SECRET parity: +acas kb-install KB-match + null-rv.
- **Loop 28 (DONE 2026-07-21):** Fable-inline. Self-review of loop-27 → **GREEN**. **Workstream: roadmap
  item 19** (the LAST confirmed acas false-clean) → **CLOSED**. `schedule-reboot` fires `shutdown /r /t
  300` (reboot 5 min out, abortable; rc=1190 "already scheduled" also OK) but booked a **VulnPatched
  Success** audit at SCHEDULE time (`:3384`) — a false compliance record (inspector sees "patched" for a
  merely-queued reboot); `verify-post-reboot` already audits TouchHost. **FIXED** (acas **1.11.8→1.11.9**):
  demote schedule-reboot to `-AuditAction 'TouchHost'` (scheduling is a touch, not a patch); VulnPatched
  stays on actual patch-install/update confirmations. One line, no guard weakened (self-guard, DNS
  wrong-box, admin gate intact); 194 acas + guards + gate green. `Acas.RebootAudit.Tests.ps1` (5) isolates
  the handler block: TouchHost not VulnPatched + verify-post-reboot stays TouchHost + exact 1.11.9 pin
  (KbMatch 1.11.8 exact → floor). Pester **1247→1252** green. **acas false-clean cluster COMPLETE**
  (all confirmed items fixed; only spec item 20 remains). SECRET parity: +schedule-reboot TouchHost audit.
- **Loop 29 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-28 →
  **GREEN**. **Workstream: fresh deep-dive on c2c** (C2C Nemesis, compliance-readiness tool, never
  loop-era reviewed) — worker read all 3,344 lines: **scan verdict fail-closed + durability trio
  correct**, but **6 CONFIRMED false-compliants** on the fix roll-ups + import. **FIXED F4** (c2c
  **1.15.2→1.15.3**): the import summary counted Compliant as `total - nonCompliant` (`:2500`), folding
  "Not Assessed"/"Error"/"Unknown" rows into the **Compliant** count quoted up-chain. Now Compliant is
  counted only on explicit `^Compliant`; unknown states go to a new `other` bucket (surfaced in the log
  + summary). Read-only import path; full c2c set green. `C2c.ImportCompliance.Tests.ps1` (7) drives the
  real import (unknown row → other not Compliant; all-explicit → other=0) + exact 1.15.3 pin (C2c.Enable
  1.15.2 exact → floor). Pester **1252→1259** green. **5 new ranked items (22-26)** (F1/F2 high-harm
  next). SECRET parity: +c2c import compliant-count honesty.
- **Loop 30 (DONE 2026-07-21):** Fable-inline. Self-review of loop-29 → **GREEN**. **Workstream: c2c
  deep-dive item 25 (F5)** → **CLOSED** (chose the independent finding over the entangled fix-rollup
  cluster 22/23/24). The Patches SCAN overdue predicate (`:873-876`) counted a MISSING update
  (ComplianceState=0) with null Deadline AND null StartTime as within-grace → pillar **PASS** however old
  (and a non-datetime Deadline dropped from the StartTime path too). **FIXED** (c2c **1.15.3→1.15.4**):
  pure `Test-C2cUpdateOverdue` (`:622`) — datetime Deadline past→overdue, else datetime StartTime older
  than grace→overdue, else (no usable timestamp on a missing update)→**overdue** (fail-closed); scan worker
  mirrors it inline. Read-only scan path; full c2c set green. `C2c.PatchOverdue.Tests.ps1` (10) pins the
  rule incl. the fail-closed cases + static mirror assert + exact 1.15.4 pin (ImportCompliance 1.15.3
  exact → floor). Pester **1259→1269** green. **c2c scan verdict now FULLY fail-closed.** Remaining
  c2c items: 22/23/24 (entangled fix-rollup buckets), 26 (AntiMalware fix unknown-age). SECRET parity:
  +c2c Patches overdue fail-close.
- **Loop 31 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-30 →
  **GREEN**. **Diversified off c2c** (the remaining c2c items 22/23/24/26 are entangled in the fix-rollup
  buckets — a dedicated-loop overhaul). **Fresh deep-dive on winupgrade** (feature-update pin/push, never
  loop-reviewed): worker verified the core fail-closed (Pin/Unpin read-back, install-updates nonce-gated,
  `[int]`/`[version]` compares, unreachable→error), found **7 CONFIRMED false-cleans** on the edges.
  **FIXED F1** (winupgrade **0.5.1→0.5.2**): upgrade-drive discarded a thrown pin error (`:2187`) and
  reported green "Pinned + triggered" `Ok=$true` (`:2282-2290`) while triggering WU UNPINNED (host can
  upgrade to the wrong build). Now a failed pin **aborts the drive** before the trigger → `PIN FAILED`,
  `Ok=$false`. No guard weakened; 168 winupgrade + FixVerify3 green. `WinUpgrade.Drive.Tests.ps1` +
  `-PinThrows` shim flag + F1 test (thrown pin → PIN FAILED, no TRIGGER/REBOOT) + exact 0.5.2 pin. Pester
  **1269→1271** green. **5 new ranked items (27-31)** (F2/F5 high-harm next). SECRET parity:
  +winupgrade upgrade-drive pin-fail abort.
- **Loop 32 (DONE 2026-07-21):** Fable-inline. Self-review of loop-31 → **GREEN**. **Workstream:
  winupgrade deep-dive item 30 (F6)** → **CLOSED** (cleanest high-visibility winupgrade item — the
  operator go/no-go verdict). The Diagnose verdict (`:2376-2380`) checked ONLY CPU/TPM/[BLOCK]/policy —
  it IGNORED the `[FAIL] Disk`/`[FAIL] RAM`/`[FAIL] Secure Boot` lines its own scan emitted, so a disk-
  short host read **READY** and the upgrade failed on disk. **FIXED** (winupgrade **0.5.2→0.5.3**): pure
  `Get-WinUpgradeDiagnoseVerdict` (`:995`) adds `$diskFail/$ramFail/$sbFail` + a distinct `NOT READY`
  branch (after NEEDS POLICY, before READY — only reclassifies falsely-READY hosts); the runspace worker
  mirrors it inline + the summary appends `disk LOW`/`RAM LOW`/`Secure Boot off`. Read-only verdict; 179
  winupgrade + FixVerify3 green. `Winupgrade.DiagnoseVerdict.Tests.ps1` (11) pins every verdict incl. the
  higher-precedence ones still winning + static mirror assert + exact 0.5.3 pin (Drive 0.5.2 exact →
  floor). Pester **1271→1282** green. Remaining winupgrade items: 27 (staging reboot, HIGH), 28
  (bypass read-back), 29 (AutoFix, HIGH), 31 (sfc, LOW). SECRET parity: +winupgrade Diagnose disk gate.
- **Loop 33 (DONE 2026-07-21):** Fable-inline. Self-review of loop-32 → **GREEN**. **Workstream:
  winupgrade item 28 (F3+F4)** → **CLOSED** (closing a confirmed backlog item vs a 5th deep-dive). The
  Pin/Unpin TRV core read-back-verifies, but the CPU/TPM **bypass** (MoSetup) value was ASSERTED and
  never verified: Pin baked "BYPASS SET" (`:984`) with `$pinOk` (`:1157`) checking only the TRV trio;
  Unpin appended "bypass key removed" (`:1250`) after a SilentlyContinue delete, read-back checking only
  the trio — so a restrictive ACL leaves the unsupported bypass STILL ARMED while the row says removed
  (security-relevant). **FIXED** (winupgrade **0.5.3→0.5.4**): `$pinReadSb` now reads the MoSetup value
  (`BypassPresent`); Pin requires it set when `$Bypass` (else "BYPASS NOT VERIFIED"); Unpin requires it
  gone when `$RemoveBypass` (else "NOT REMOVED ... bypass"). Additive/fail-closed; 198 winupgrade +
  FixVerify2/3 green. `FixVerify2` FIX-2 harness gains `-Bypass`/`-RemoveBypass` + 4 cases + exact 0.5.4
  pin (DiagnoseVerdict 0.5.3 exact → floor). Pester **1282→1287** green. Remaining winupgrade items:
  27 (staging reboot, HIGH), 29 (AutoFix, HIGH), 31 (sfc, LOW). SECRET parity: +winupgrade bypass read-back.
- **Loop 34 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-33 →
  **GREEN**. **Diversified workstream TYPE to SECURITY:** a fresh deep-dive on the server/auth/token
  boundary (loopback HttpListener + token-gated `/api` = the execution surface), un-reviewed since loops
  1-4. **Verdict GREEN — boundary solid:** constant-time-compared token centrally enforced on every
  `/api` route (destructive actions +session-gated, default-DENY); canonicalize-and-root-checked static
  serve (no traversal); custom-header token + Host guard defeat CSRF/DNS-rebinding; loopback-only bind;
  bounded bodies; no XSS/IEX; report-preview sandbox intact; the `?t=` carrier (item 4 neighborhood) is
  well-contained (no-referrer + SPA-strip + header-only for real routes). **The one actionable item
  (defense-in-depth) → FIXED:** the session token + report-preview retrieval key were `[guid]::NewGuid()`
  (CSPRNG-backed on Windows but implementation-dependent). New pure `New-JanetWebSecureToken`
  (`Server.ps1:95`) mints 256-bit hex from `RandomNumberGenerator`; rid uses it, launcher inlines a
  mirror. 76 server tests green. `Server.SecureToken.Tests.ps1` (6): helper format/distinctness + static
  launcher/rid CSPRNG asserts. No version bump (server files). Pester **1287→1293** green. SECRET
  parity: +CSPRNG access-credential mint.
- **Loop 35 (DONE 2026-07-21):** Fable-inline + one parallel Fable worker. Self-review of loop-34 →
  **GREEN**. **Fresh deep-dive on upr** (Unsupported Product Remediator, 127KB, un-reviewed): **verdict
  GREEN** — the removed decision is fail-closed and honest (exit-code gated AND a mandatory registry
  re-verify after every OK that demotes to FAIL if still-present/unreadable; skips/rejects/unreachables
  bucketed; audit books VulnPatched only when ≥1 really removed). **The one defensible hardening (SPEC
  edge) → FIXED** (upr **1.2.2→1.2.3**): the verify fail-closed on a THROW (catch) but a non-throwing
  EMPTY `$vout` hit `[bool]$null.Present`=$false="removed" (`:1133`). Pure `Get-UprVerifyResult` (`:119`)
  — `$null` verify → "could NOT be verified", never OK; worker mirrors the null-check inline. 36 upr
  tests green. `Upr.VerifyResult.Tests.ps1` (6) pins the fail-close + still-present/gone/reboot + exact
  1.2.3 pin. Pester **1293→1299** green. 2 new ranked items (32-33, both spec/display). SECRET
  parity: +upr verify fail-close.
- **Loop 36 (DONE 2026-07-21):** Fable-inline. Self-review of loop-35 → **GREEN**. **Closed a deferred
  HIGH-harm item: winupgrade #27 (F2)** → the `rebootWhenStaged` re-read set `Staged=true` off a BARE
  `Test-Path 'C:\$WINDOWS.~BT\Sources'` (`:2278`), so a ROLLED-BACK (stale) ~BT tree made an un-staged
  host read staged and get REBOOTED (back on the old build). **FIXED** (winupgrade **0.5.4→0.5.5**): the
  `PHASE:STAGED` re-read now CLASSIFIES the ~BT tree inline (mirror of `Get-WinUpgradeStagingClass`:
  rollback marker/age/setup process) and counts staged ONLY when not `Stale`. Coverage: classifier
  decision unit-tested (Diagnose24h2), reboot gate proven by Drive INVARIANT #4, + `WinUpgrade.StagingReboot.
  Tests.ps1` (8) pins the classifier reboot contract + a static assert the re-read classifies + exact
  0.5.5 pin (FixVerify2 0.5.4 exact → floor). Full winupgrade + FixVerify2/3 green. Pester **1299→1307**
  green. **Left ranked (27b):** the generic CBS/WU/PFRO pending-reboot can still read a non-feature-update
  pending as staged (nuanced — CBS can be a completed feature update). SECRET parity: +staging classifier.
- **Loop 37 (DONE 2026-07-21):** Fable-inline. Self-review of loop-36 → **GREEN**. **Closed the last cheap
  false-clean: winupgrade #31 (F7)** → the DISM+SFC repair verdict's no-match `else` defaulted an
  UNPARSEABLE `sfc /scannow` (localized OS / truncated / unrecognized) to `'no violations'` → **CLEAN**, so
  a verify path reported a healthy component store when the result was actually unknown. **FIXED**
  (winupgrade **0.5.5→0.5.6**): unmatched sfc → `'unknown'` in both `Get-WinUpgradeRepairVerdict` (`:668`,
  the pure tested twin) AND its inline mirror (`:2685`, the code that runs across the module-less runspace);
  `'unknown'` joins **PARTIAL** (`:672`/`:2689`, an existing status — no consumer switch touched) and is
  never CLEAN, + an `[WARN] output not recognized - repair state UNKNOWN` report line. `Winupgrade.
  RepairVerdict.Tests.ps1` (NEW, 8) is the helper's FIRST coverage (fix case + 4 known outcomes + two-twin
  static assert + exact 0.5.6 pin; loop-36 StagingReboot exact pin → floor). winupgrade + RepairVerdict +
  StagingReboot + Diagnose24h2 + Drive + FixVerify2/3 **101** green. Pester **1307→1315** green. Backlog
  now: the c2c cluster (22/23/24/26, a bucket-taxonomy redesign) + winupgrade #29 (AutoFix, needs a shim
  harness) — both deferred as non-trivial. SECRET parity: +winupgrade repair-verdict fail-close.

## Coverage status (after loop 13)
Both destructive surfaces reviewed + test-pinned: WinRM fan-out (confirm + self-guard +
wrong-box + fail-closed) and LDAP AD-write (DN-redirect + protected-object incl. RODC +
fail-closed re-read). Reviewed tools: server/auth (1), wpt profiles (1-3)+engine (9)+audit
(10), acas, upr (5), c2c (8), reports sandbox (3,7)+**correctness (13)**, remoteadmin (10),
winupgrade (11), adto (12-13). Remaining: the reports host-key sweep tail (item 11), the
IAVM CSV guard (item 12), the last small destructive tools (secureboot/dhcp/biosfirmware/
certdeploy — GREEN-ish in the loop-10 audit, not deep-dived), more correctness deep-dives on
read paths, or SECRET-parity execution on operator sign-off.
