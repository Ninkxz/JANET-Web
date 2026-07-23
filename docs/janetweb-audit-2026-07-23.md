# JANET Web — Full Per-Module Improvement Audit (2026-07-23)

Ten parallel audit passes: one per big module (wpt, reports, winupgrade, c2c, acas), three
covering the mid/small module groups, one on the server + tool registry, one on the frontend
(shell, components, all 21 views). Focus: real bugs, simplify/delete, efficiency, and
consistency against the suite's established guard patterns. Per-module guard copies (the
pool-runspace source-injection constraint) were treated as by-design and not reported.
All findings verified against actual code with file:line; two findings were cross-checked
and reframed/dropped during synthesis (see notes at bottom).

## Verdict

No P1s. The suite's destructive-action contract (self-guard, wrong-box abort, typed
confirms, TCP gates, fail-closed verdicts) is broadly intact — the findings are the
*asymmetries*: guards and verdict fixes applied to one block/module but missed in its
sibling. 7 real bugs (all P3-severity reporting/verdict defects, no data-loss class),
~15 high-value simplifications, ~10 efficiency wins, ~12 consistency gaps.

## Top 10 by value

| # | Finding | Where |
|---|---------|-------|
| 1 | `message` self-guard loses its case-insensitive comparer (`return $set` without the unary comma — the exact parity-ledger row-9 class, missed in this one web copy). Case-mismatched dispatcher name slips the guard → `msg.exe` on the JANET box. | JanetWeb.message.psm1:92,113 |
| 2 | `wpt cleanup-disk` books Success when every profile delete failed (false-clean; loop50 fixed this in `clean-user-apps` via `Get-WptCleanStatus` but `WptCleanBlock` still sets Success unconditionally). | JanetWeb.wpt.psm1:3302 (helper at :909) |
| 3 | `wpt bulk-scan` counts a DNS-mismatched wrong-box host as scan Success (`Online=$true` pre-set at :1921 survives the mismatch return; snapshot persists the bogus row). Fix: `-OkOf { $r.Online -and -not $r.DnsMismatch }`. | JanetWeb.wpt.psm1:1921,2010-2013,5449 |
| 4 | `acas` full-update path ignores `Verified=$true` when the version string didn't move — idempotent/no-op remediations on already-compliant hosts render UNCONFIRMED amber and drop out of the PATCHED tally. | JanetWeb.acas.psm1:2150-2157 (verify-only branch does it right at :2018-2028) |
| 5 | `certdeploy` legacy-intermediates allowlist is literalized in 3 places; a 5th cert added only to the hashtable would be pushed by deploy and **deleted by the prunePki companion in the same round-trip**. Inject the allowlist into `$CertDeployCompanionsSrc` from the single hashtable. | JanetWeb.certdeploy.psm1:139-144 vs :470-476 |
| 6 | `certdeploy check` builds its want-set from ALL bundle thumbprints (no expiry filter) while deploy filters expired non-allowlisted — a dead anchor in the bundle shows hosts MISSING forever, unfixable via Deploy. Latent (shipped bundle has 0 expired). | JanetWeb.certdeploy.psm1:286-294 vs :258-282 |
| 7 | `secureboot` live enable has **no server-side** typed-ENABLE check — the gate is view-side only (loop-15 design); loop62 moved dhcp (`APPLY`) and pkginstall (`DEPLOY`) server-side but secureboot was never retrofitted. A direct API call arms a fleet firmware write. | JanetWeb.secureboot.psm1:1116-1207 (cf. dhcp:1181, pkginstall:758) |
| 8 | Server route-level share gates use the UNCACHED 1.5s TCP probe on the single-threaded accept loop (logs/tail, transcript, pkginstall lists, ACAS archive) while `Test-JanetWebShareCached` (30s cache) already exists — one dead share stalls every request per poll. | JanetWeb.Server.ps1:636,658,752,787,877,887 |
| 9 | Frontend: repeated same-key runs accumulate live subscriptions (reports view especially — every `refreshList()` adds a handler; N refreshes → N+1 duplicate log lines/stat counts). wpt:320 / acas:325 show the intended `if (unsub) unsub()` fix. | web/js/views/reports.view.js:302-319 et al. |
| 10 | `wpt`: nine bespoke ~70-line RunspacePool harvest loops re-implement `Invoke-WptFanOut` (~650 lines); an `-OnResult` callback + ISS injection on the unified helper collapses all nine. | JanetWeb.wpt.psm1:5677-6666 (helper at :4866) |

## Remaining findings by module

### wpt (JanetWeb.wpt.psm1)
- Inline TCP probe copy-pasted in ~14 worker blocks and the DNS-name guard in ~10, though five harvesters already prove ISS injection works (~150-200 lines removable). :1911 et al.
- Destructive blocks spend a dedicated WinRM round-trip on the DNS-name check; `WptRebootScheduleBlock:2166` proves the fold-into-first-call pattern. One round-trip saved per host per destructive action.
- `maintenance-unlock` (:3848) rewrites logon rights/banner with NO wrong-box abort while its sibling `maintenance-lock` (:3748) has one. Same gap in `WptWuResetBlock:2643` and `WptRdpRebindBlock:2733`.
- Instant `reboot` (manifest :76-83) has no `confirm` while the gentler `reboot-schedule` does.
- `New-WptRowEvent` (:549, the type/Type collision-proof helper) used in only 2 of ~30 row-emit sites.

### reports (JanetWeb.reports.psm1)
- BUG: `acas-host-summary` keys the per-host tally on RAW hostname (:6093) — short+FQDN pairs split rows and halve PatchRate; every sibling rollup folds via `Get-ReportsAuditHostKey`.
- CSV formula-guard hand-rolled 6× (:875,:2225,:2258,:3395,:6167,:6280) while `ConvertTo-ReportsCsvCell` (:4210) already does guard+quote. Collapse all six.
- Host-count columns disagree across sibling reports: 4 views normalize the host key, 5 don't (:4918,:5002,:5206,:5310,:7186) — same fleet, different affected-host counts per report.
- UNC 445 pre-gate on output writes exists only in the weekly actions; dirty30/cora/command-brief/posture-digest writes (:4465,:4486,:4798,:7240,:7340) can hang the serialized reports runspace on a dead share.
- Route-bucket classifier copy-pasted in 5 handlers; severity-rank map redefined ~7×; `Test-Path` missing `-LiteralPath` at :1948 (lone offender).
- `Compare-AcasScans` makes two redundant full passes (:1567-1568); posture-digest recomputes the findings set ~5× per run.

### winupgrade (JanetWeb.winupgrade.psm1)
- Pin/Unpin/UpgradeDrive/RepairHealth open 3-5 fresh WinRM sessions per host per action; `InstallCab` (:1314) proves the one-`New-PSSession` pattern. Highest-value efficiency win in the module.
- Reboot scriptblock copy-pasted 5× (:1383,:1528,:2309,:2722,:2926); the :2309 copy is already fully parameterized — hoist to `$script:WinUpgradeRebootBlock`.
- Wrong-box abort guards every reboot but not the destructive WRITE blocks: ForceDiscovery WU-reset (:2466), SetPageFile (:1486), Pin/Unpin, InstallCab DISM.
- gpupdate/UsoClient success lines logged even on non-zero native exit (:2515,:2521).
- Diagnose queries 4 WU services with 8 provider calls (:1776-1790); fleet rollup hardcodes 26100 where rows use `$minBuild` (:3908); AutoFix branch drops `-LiteralPath` on `$WINDOWS.~BT` paths (:2814,:2881).

### c2c (JanetWeb.c2c.psm1)
- BUG (reporting): `NOT VERIFIED` host status (:2424) counted in no fix-summary bucket (:3233-3243) — the loudest fail-closed state is invisible in the done-line and totals don't reconcile.
- The staged Defender package (50-150 MB) is SHA-256 hashed on EVERY fix action (:2779 via :2847), including fixes that never touch AntiMalware. Gate to fix-antimalware/run-all (cert bundle already gated this way at :2866).
- `$script:C2cVersionBlock` (:3252-3331) lacks the DNS-mismatch guard both the scan (:1156) and fix (:1442) workers carry — can report the wrong machine's product versions.
- Manifest `fix-pki` text says Client Authentication EKU; the code correctly uses Server Authentication (:2254). Text-only fix.
- Scan re-implements `Get-C2cBool` inline (:3497); a few `-LiteralPath` omissions (:2099,:2118,:2362).

### acas (JanetWeb.acas.psm1)
- Same CSV fully re-parsed at 7 call sites per operator session — memoize on path+size+mtime.
- `AcasKbInstallBlock` (:2787) is the only session worker without the NetBIOS NTLM fallback its siblings use (:1991,:2300,:2396) — hosts the patch path recovers will fail kb-install.
- Fleet-wide `auto-patch`/`run-vulnerability`/`schedule-reboot`/`preflight-services` declare destructive but no `confirm`, while narrower kb-install has one; preflight's own comment promises a confirm it doesn't declare.
- `preflight-services` worker (:2357) is the lone destructive worker without the wrong-box abort (low: it only ensures services Running+Auto).
- DNS-name guard costs an extra round-trip (:2044, :2213+:2219); 4 near-identical rowOf scriptblocks and a duplicated reboot/verify switch arm (:3714-3791 vs :3479-3568).

### upr / restart / certdeploy
- BUG (upr): findings sorted by severity STRING descending (:1824,:1885) — Critical/High land at the bottom. Map to numeric rank.
- upr: M365 handler still writes/executes from world-writable `C:\Temp` (:1014-1018) — same TOCTOU class audit#11 removed for `.cmd`; use %ProgramData% per-run dir.
- upr: parsed-finding cache (:206-262) is dead under fresh-runspace-per-action — ~60 LOC deletable.
- restart: four hand-rolled pool ping/monitor loops beside `Invoke-RrsFanOut` (:1281,:1480,:1752,:1913).
- restart: consent-off burst fleet reboot has no typed confirm word (soft asymmetry).
- certdeploy: three ~90-line harvest loops near-identical (:1048,:1369,:1617) — extract `Invoke-CertDeployFanOut`; wrong-box guard is a separate round-trip in every action (:910,:1148,:1476) — fold into the main scriptblock (atomically safer for deploy too).

### small modules
- adto: baseline JSON re-read+parsed once per AD object during whole-domain scans (:393) — pass the attribute in from the already-loaded `$baseline`.
- sysadmin: sweep worker (:234-371) lacks the read-only DNS soft-warn biosfirmware (:158) and remoteadmin (:278) carry — wrong-box facts reported under the dialed name.
- biosfirmware: read-only scan emits `TouchHost` audit rows (:257), inflating the TouchedHosts freshness trail every other read-only tool deliberately leaves alone.
- patchlib: two full recursive share walks per package folder (:188-201) — fold to one.
- winrmbridge: revert payload computed for the read-only `check` action (:239).
- CLEAN: history, remoteadmin, kev, javafix, specfix, troubleshoot.

### secureboot / adsearch / dhcp / pkginstall
- secureboot: enable path has no per-host wall-clock watchdog (:1247-1344) though its own scan (:1043) and pkginstall both have one; the worker's C$ SMB steps are unbounded.
- adsearch: dead credentialed RootDSE bind in BaseUsers (:666-667); `$results +=` O(n²) on the one uncapped path (:808) compounded by a per-user OU rescan (:803-806); redundant first sort (:813).
- dhcp: destructive apply/bulk remote scripts (:405,:424) lack the wrong-box `$env:COMPUTERNAME` abort secureboot and pkginstall both carry; option-not-present detection copy-pasted 3× (2 consolidatable).
- pkginstall: fully CLEAN except `ConvertTo-JanetMsiList`/`Get-JanetMsiListDropped` duplicated predicate (:156-171) — single pass returning Kept+Dropped.

### server (JanetWeb.Server.ps1) — no bugs
- Static assets re-read from disk and re-sent in full every request — no ETag/Last-Modified/304 path (:254-279,:422-424).
- ACAS CSV archive `Copy-Item` runs synchronously on the accept thread (:869-897) — move into the spawned worker.
- Dead `$job.RS` close branches (:301,:1084 — key never assigned); duplicated runspace-drain logic (:1081-1088 vs :298-308); UNC-probe idiom hand-rolled ~5× — one `Test-JanetWebPathReachable` helper.
- `pkginstall/msis|packages` enumerate operator paths with no confinement (token-gated, read-only, arbitrary paths are by-design for the tool — at minimum comment the intent).
- CLEAN: accept-loop races, token/host gates, cancel lifecycle, registry↔module↔view mapping, endpoint liveness.

### frontend (shell/components/views)
- Subscription accumulation on re-run (Top-10 #9).
- O(n²) full-grid re-scan per streamed row in certdeploy (:296,:427) and winupgrade (:1138,:1499) — kev (:174) and wpt (:324) already do O(1) running counters.
- WPT irreversible one-clicks use plain confirm, not the typed ArmingDialog every sibling uses: cleanup-disk permanent delete (:1409), per-user app delete (:2400), maintenance HARD-LOCK (:2511) — wpt itself types RUN and REBOOT elsewhere.
- ~15 copy-pasted CSV-export blocks → one `ctx.util.exportCsv`; identical `unmount` teardown in ~18 views → fold into `JanetViews.register`; `lockInputs` reimplemented ~13×.
- c2c.view.js:459 defines a local `esc()` duplicating `Janet.util.esc`; certdeploy.view.js:73 has a fallback `esc` that returns UNESCAPED (dead, but a trap).
- CLEAN: no unescaped host/server data in any innerHTML/confirm sink; all CSV via the formula-escaping `toCsv`; no dead components; TargetManager listener lifecycle correct.

## Fix pass (same day)

Nine parallel fix agents (one per disjoint file set) applied the findings; every agent ran its
module's Pester files green before handing back, and the combined tree passed the full suite,
a whole-repo parse sweep, and node --check on every JS file. 43 files, +2271/-1604.

**All 7 bugs fixed.** All consistency guards added (wrong-box aborts in wpt x3 / winupgrade x5 /
dhcp x2 / acas preflight / c2c version block / sysadmin soft-warn; secureboot server-side ENABLE
gate + enable watchdog; restart server-side RESTART gate — its view collected the word but never
sent it and the server never checked; acas confirm strings on the 6 fleet actions). All efficiency
items fixed (session reuse, cached probes, 304s, CSV memo, Defender-hash gating, folded DNS
round-trips, O(1) stream tallies). Simplifications: CSV-guard/route-bucket/severity-rank
consolidation in reports, reboot-block + $get hoists in winupgrade, Invoke-RrsPingSweep,
Invoke-CertDeployFanOut, Invoke-AcasReboot*Wave + rowOf hoists, dead upr cache deleted, dead
server RS branches deleted, ~15 view export blocks -> ctx.util.exportCsv, ~17 verbatim unmounts
-> registration default, New-WptRowEvent adopted at ~35 emit sites.

**Extra fixes found during the pass:** dirty30 CSV export skipped quote-doubling on 3 columns
(fixed by the consolidation); ConfirmDialog silently ignores confirmWord, so wpt's custom-command
typed-RUN gate was inert — now routed through ctx.arm.

**Deferred (documented, not attempted):** wpt nine-fan-out collapse + ISS probe injection (blocked
partly by static-analysis test pins), posture-digest recompute caching, lockInputs consolidation,
c2c legacy $labelOf retirement, 3 wpt DNS-probe folds pinned verbatim by Wpt.SelfGuardAndClean
static asserts, module version bumps pinned exactly by tests (wpt 6.8.19, reports 2.14.24,
acas 1.11.17, secureboot 1.6.6, restart 1.5.0-beta10 — bump with their test pins next loop).
Follow-up flagged: wpt has more bare track(run.subscribe()) one-shots of the same leak class
(app-update-apply, unsupported-uninstall, sccm-*, maintenance-unlock, host-info, eventlog-scan).

## Synthesis notes
- Secureboot "missing typed confirm" was cross-checked against `Secureboot.ConfirmWord.Tests.ps1`: the loop-15 gate is deliberately manifest-string + view-dialog only; the finding was reframed to "server-side enforcement missing (loop62 retrofitted dhcp/pkginstall but not secureboot)".
- ACAS's informational note about server-side CSV escaping was verified satisfied (`Protect-JanetWebCsvField`, JanetWeb.Logging.ps1:279) and dropped.
- One agent's claim that "no sibling module uses typed confirm words" was wrong (dhcp/pkginstall/others do); its underlying wpt finding (instant reboot lacks confirm while reboot-schedule has one) was independently valid and kept.
