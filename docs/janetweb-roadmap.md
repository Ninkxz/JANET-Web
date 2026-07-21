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
34. ~~**acas reboot-selected books VulnPatched at reboot-schedule time**~~ **CLOSED loop 38** (acas 1.11.10):
    the in-card reboot arm (`:3630`) audited `VulnPatched` Success for an abortable scheduled reboot — the
    same false-compliance record loop28 fixed on the `schedule-reboot` sibling but missed here. Now
    `TouchHost`, matching both siblings. `Acas.RebootAudit.Tests.ps1` extended.
35. **acas verify probes equate "registry key recently modified" with "patched"** (loop-38 Fable deep-dive,
    CONFIRMED, HIGH) — Office/Chrome/Edge/Java/Store Verify set `Verified=$true` from key `LastWriteTime`
    recency (`:129`/`:157`/`:459`/`:568`), never vs the required version; a verify-only run lights the PATCHED
    tile (OK row) for a still-vulnerable host, and a *failed* Office C2R update refreshes the same key's mtime
    → reads fresh. The known "copied-registry always-OK" chip, generalized. Verify-only audits TouchHost (harm
    = the stat card / verdict, not the ledger). Fix: compare an actual installed version, or `Verified=$null`
    → UNCONFIRMED when indeterminate. **Office C2R slice CLOSED loop 40** (acas 1.11.12): `Get-AcasC2rVerified`
    ported from wpt's loop24 fix — Verified true only when fresh AND `LastScenarioResult` succeeded. **Remaining
    (open):** the Chrome/Edge (`:157`) / Java (`:459`) / Store (`:568`) mtime slices — lower-risk (match wpt's
    accepted mtime approach, keys not bumped on failed attempts the way C2R's is).
36. ~~**acas "bumped" success = any pre≠post string inequality**~~ **CLOSED loop 39** (acas 1.11.11): new pure
    `Get-AcasBumpVerdict` + inline worker mirror (`:2084`) — a post in {error,n/a,not installed} or a
    `[version]`-parseable downgrade → UNCONFIRMED (never OK/VulnPatched); `'none'` (Log4j clean) and
    non-version state transitions (spec-exec → COMPLIANT) stay confirmed. `Acas.BumpVerdict.Tests.ps1` (11).
37. **acas Log4j Verify scans only 2 hardcoded paths but claims a recursive clean** (loop-38 Fable deep-dive,
    CONFIRMED, MED) — `:945-975`: Verify checks only HID + Adobe dirs, reports `Verified=$true` "recursive scan"
    while the remediation Script recurses all of `C:\Program Files*`. Verify-only on a host with a vulnerable
    `log4j-core` elsewhere reads OK/PATCHED. Fix: make Verify recurse like the Script.
38. **acas null/empty worker/probe result defaults to 'OK (no output)'** (loop-38 Fable deep-dive, LOW/latent)
    — `:2483-2484`/`:1956`/`:2034`/`:2130`: ambiguity resolves toward OK/exit-0, not UNCONFIRMED. No live
    trigger (every worker returns a string) but the wrong direction for this tool. Harden toward UNCONFIRMED.
39. **acas Chrome/Edge in-Script proof is direction-agnostic** (loop-38 Fable deep-dive, LOW) — `:280-282`/
    `:353-356`: `$cur -ne $before` → "OK (updated X→Y)" even when Y<X (rollback/channel switch during the poll).
    String compare, not `[version]`+greater-than. Same class as item36, in the profile Script.

_(items 40–50: loop-40 wpt Fable deep-dive — worker-CONFIRMED, re-verify in-code before acting. wpt.psm1 lines.)_
40. **wpt app-update profiles self-report OK on a mere trigger / ignored native exit code → VulnPatched** (HIGH)
    — the systemic gap: success is classified from the Script's `OK…` prefix (`:3427`), so M365 Force/User
    Visible `:915-916`/`:1224-1225` (`"OK (...exit $ExitCode)"`, code never tested), Trellix `:955`/`:967`
    (`& $cmd 2>&1 | Out-Null` never throws → "ePO sync sent" on invocation, catch dead), and SC-trigger profiles
    `:1269`/`:1051`/`:1720` (`Invoke-CimMethod | Out-Null` discards `CCM_Application.Install` rv; sibling `:4643`
    checks it) all book VulnPatched/Success. The kb-install honest-outcome discipline (loop22/23) never swept
    across the app-update catalog. Fix: gate each profile's OK on the exit code / rv, else PENDING. **M365 slice
    CLOSED loop 43** (wpt 6.8.11): both M365 profiles now FAIL on a nonzero OfficeC2RClient exit (`Wpt.M365Update.
    Tests.ps1`). **Remaining (open):** the Trellix `$LASTEXITCODE` gate + the SC-trigger profiles' discarded rv.
41. ~~**wpt app-update-verify marks Status='Verified' regardless of `$res.Verified`**~~ **CLOSED loop 41** (wpt
    6.8.9): new pure `Get-WptVerifyOk` (mirrors `Get-AcasVerifyRowStatus`) — the OkOf now requires reachable
    AND `Verified -eq $true`; a reachable-but-not-verified host audits Skipped (checked, not current), not
    Failure. `Wpt.VerifyApp.Tests.ps1` (9).
42. ~~**wpt bulk-patch: null WMI ReturnValue = accepted**~~ **CLOSED loop 42** (wpt 6.8.10): swept ALL five
    CCM-trigger sites (bulk-patch update `:2001` + app `:2027`, the SC App/Update trigger action `:3913`/`:3923`,
    and `WptAppActionBlock` `:4671`) to accept a trigger ONLY on a non-null `[int] 0` via new pure
    `Get-WptRvAccepted` + inline mirrors — matching kb-install's loop22 null fail-close. `Wpt.BulkPatchRv.Tests.ps1`
    (8). _(The deeper "a merely-accepted async trigger books VulnPatched, not a confirmed install" → item51.)_
43. **wpt Oracle Java SC Verify = JavaSoft key mtime <30d, no version target** (HIGH) — `:1312`; the jvm.dll
    version at `:1300` is displayed, never compared. item35 class, wpt side.
44. ~~**wpt clean-user-apps Status='Success' even when every deletion failed**~~ **CLOSED loop 50** (wpt
    6.8.12): new pure `Get-WptCleanStatus(Found, Removed, DryRun)` + inline worker mirror — found>0/removed=0 →
    **Failed**, partial → **Partial**, all-removed/nothing-found → Success. The action OkOf (Success/Dry Run OK
    only) + fan-out Failure-audit drop Partial/Failed out of the clean bucket automatically. `Wpt.CleanStatus.
    Tests.ps1` (8). (The sibling disk-cleanup worker's unconditional Success is different semantics, left as-is.)
45. ~~**wpt verify-and-clean deletes the Uninstall reg key even when FilesRemain**~~ **CLOSED loop 51** (wpt
    6.8.13): the `$verifyClean` key-removal (`:4250`) is now gated on `-not $filesRemain` — the key is removed
    only when the product's files are actually gone; if files remain the key is KEPT (deleting it would blind
    every later registry-driven scan into reading the still-installed product as clean). `Wpt.VerifyClean.
    Tests.ps1` (5).
46. ~~**wpt Adobe Acrobat 'Removed' if ANY one GUID uninstalled**~~ **CLOSED loop 52** (wpt 6.8.14): the Adobe
    branch now counts per-GUID success/failure (`:4364`) — all GUIDs removed → Removed; some failed while others
    succeeded → **Attention** (a not-clean bucket; `$isOk` at `:5265` requires an exact Removed); all failed →
    the default Failed. Failing GUIDs' exit codes ride in the detail. `Wpt.AdobeUninstall.Tests.ps1` (6).
47. **wpt browser-client Verify = Clients{GUID} mtime <14d, version-blind** (MED) — `:898`; item35 class, wpt
    side. Less wrong than C2R (Omaha usually rewrites only on a real install — confirm whether a failed update
    bumps the key).
48. **wpt fix-java empty engine result (null row) → NOCHANGE → ok + audit Success** (LOW) — `:5841`; engine-
    absent/thrown cases already fail closed (`:4436`/`:5835`).
49. **wpt verify-patch counts 'no SCCM client' / 'no matching updates' toward "N verified"** (LOW) — `:2501`/
    `:6225`; an update absent from CCM can mean installed OR never-deployed.
50. **wpt Chrome/Edge internet updater direction-agnostic downgrade** (LOW) — `:1126`/`:1201`: `$cur -ne
    $before` → "OK (updated X→Y)" on a pv downgrade during the poll. Raw string, not `[version]` forward. Same
    class as item39 (acas). (wpt's degraded-read path IS guarded — `$cur -and` + PENDING — so unlike acas item36
    it's only the downgrade sliver.)
51. **wpt bulk-patch / SC-trigger book VulnPatched for a merely-ACCEPTED async trigger, not a confirmed install**
    (loop-40 dive + loop-42 follow-on, HIGH) — a CCM InstallUpdates/Install rv=0 means the client ACCEPTED the
    request, not that the patch installed; `:5356` (bulk-patch) audits VulnPatched/Success on acceptance. Same
    trigger≠patched class as item40. kb-install's answer is honest — it books MECM triggers as "Triggered
    (verify)", never Installed. Fix: audit accepted-but-unconfirmed triggers as a touch/pending, reserve
    VulnPatched for a verified install (or add a post-trigger verify).

_(items 52–57: loop-44 c2c Fable deep-dive — worker-CONFIRMED unless noted, re-verify before acting. c2c.psm1 lines.)_
52. ~~**c2c Monitoring fix books MONITORED off the service being Running, ignoring the Tanium-INSTALLED half**~~
    **CLOSED loop 45** (c2c 1.15.6): new pure `Get-C2cMonitoringVerdict` + inline worker mirror — a
    running-but-not-installed box (orphaned service / unreadable uninstall registry) is now NOT VERIFIED (never
    FIXED), aligning the fix verdict with the scan's installed-AND-running PASS. `C2c.MonitoringVerdict.Tests.ps1`
    (6).
53. ~~**c2c scan AntiMalware sig-age `[int]$null → 0` coercion can read READY**~~ **CLOSED loop 46** (c2c
    1.15.7): both the scan (`:830`) and fix (`:1914`) now guard the fallback — `elseif ($null -ne
    $mp.AntivirusSignatureAge)` — so a null age stays `$null` (freshness gate treats it as stale), never a
    false-fresh 0. New pure `Get-C2cSigAgeHours` + inline mirrors. `C2c.SigAge.Tests.ps1` (7).
54. **c2c AntiMalware fixer books NOCHANGE "already protected" when sig age is unknown** (LOW) — `:1975-1981`;
    the scan FAILs the same state (`:818` requires non-null age). Narrow trigger.
55. ~~**c2c audit books host Status PARTIAL as `Success`**~~ **CLOSED loop 47** (c2c 1.15.8): new pure
    `Get-C2cHostAuditResult` — a PARTIAL host (always ≥1 pillar FAIL) now audits `Failure`, and only a
    fully-FIXED host counts as a patched item (itemCount). `C2c.AuditResult.Tests.ps1` (10).
56. **c2c version-check ordinal string fallback can report a below-target host as NEWER** (LOW, read-only) —
    `:3248-3255`: `1.8.0_51` vs `1.8.0_491` → CompareOrdinal '5'>'4' → NEWER though 51 < 491. Any non-`a.b.c.d`
    scheme.
57. **c2c Firewall PASS/NOCHANGE on an empty `Get-NetFirewallProfile`** (SPECULATIVE) — `:761`/`:1460`: an
    empty non-throwing collection → `$off.Count -eq 0` → PASS with zero profiles read; the netsh fallback DOES
    assert 3+3 (`:776`/`:1484`). No known empty-non-throw path. _(F2/F6 from the dive refine the known cluster:
    the per-pillar SUMMARY tally `:3084` folds SKIP/NOT VERIFIED/IN PROGRESS into `nochange` — items 22/24.)_

_(items 58–59: loop-48 certdeploy Fable deep-dive — worker-CONFIRMED, re-verify before acting. certdeploy.psm1 lines.)_
58. ~~**certdeploy DEPLOY: a trust-anchor-guard-rejected (non-CA) but ABSENT cert reads ALREADY/INSTALLED**~~
    **CLOSED loop 49** (certdeploy 1.4.2): `Get-CertDeployResultToken` now emits **REJECTED** when `Rejected>0`
    (after FAIL/NOT VERIFIED, before INSTALLED/ALREADY) → row Status `REJECTED (non-CA)` (error level, own
    summary bucket) → audit Failure/itemCount 0. The guard itself (correctly refusing a non-CA anchor) is
    unchanged; only the classification. `CertDeploy.Tests.ps1` +6; two bug-pinning CaValidation tests corrected.
59. **certdeploy scan-cert-management: registry-denied probes → green "None detected"** (LOW/advisory) —
    `:1461-1495` all detection primitives are `-ErrorAction SilentlyContinue`, so a session-capable but
    registry-denied credential yields `Err=''` → `Get-CertDeployReconcilerVerdict` 'None detected — a manual
    .Default push WILL persist' (`:640`/`:664`) when a reconciler could be present and strip on reboot. Fix:
    distinguish "read the reconcilers, found none" from "couldn't read them" (probe error → unknown/CHECK ERROR).
    _(F4/F5 from the dive = SPECULATIVE structural gaps — blank-thumbprint escapes re-verify; zero-item bundle →
    ALREADY — no realistic trigger, defensive-only, not separately ranked.)_

_(items 60–61: loop-53 adto Fable deep-dive — worker-CONFIRMED, re-verify before acting. adto.psm1 lines.)_
60. ~~**adto scan reads a null/unreadable userAccountControl as COMPLIANT**~~ **CLOSED loop 54** (adto 0.2.5):
    `ConvertTo-AdToObject` now carries a `UacReadable` flag (false when the raw attr is null/empty), and
    `Test-AdToCompliance` fires a fail-closed **`uacUnreadable`** hit (→ NON-COMPLIANT) + skips the four UAC
    bad-bit rules when unreadable; non-UAC rules still run; missing key → readable (back-compat).
    `AdTo.WriteGuards.Tests.ps1` +4.
61. ~~**adto baseline overlay silently disables a rule on a typo**~~ **CLOSED loop 55** (adto 0.2.6): `:84-92`
    `Get-AdToBaseline` now **merges** each overlay rule onto the embedded default (fail-closed `enabled=$true` base
    for unknown rule names), overriding only fields the overlay explicitly provides (`$null -ne $r.<field>`). An
    overlay tuning one knob (or a typo) no longer nulls `enabled`/`appliesTo`; an explicit `"enabled": false` still
    disables. +4 tests (real temp overlay, `Get-AdToBaselinePath`-only shim). _(F4/F5 = speculative low:
    adminCount null-read guard-bypass `:513`, admin-pattern-miss categorization `:118`; not ranked.)_

62. ~~**secureboot AlreadyPending re-books Success**~~ **CLOSED loop 59** (secureboot 1.6.4): added
    `elseif ($result.SetResult -eq 'AlreadyPending') { 'Skipped' }` to the resolvedStatus chain — the classify already
    routes `Skipped` → `skipCount`/audit `Skipped`/itemCount 0, so a re-run against a staged host no longer books a
    fresh `VulnPatched/Success/itemCount=1` or inflates "N enabled". Returned `Skipped` field aligned to status. +3
    tests (static analysis). _(from loop-57 dive)_
63. **secureboot "Success"/"N enabled" wording = staged pending-reboot, not enabled** (P3) — `:718`, `:1315`. Heavily
    mitigated (After col + audit detail carry "(pending reboot)"; confirm text says "PENDING A REBOOT"), but the bare
    enum + summary word "enabled" and the **Lenovo** read-back-reflects-staged case (`:184`) omit the pending marker.
    Fix: unconditional "(pending reboot)" marker on every non-error live result + "staged" summary wording. _(loop-57 dive)_
64. ~~**secureboot `Get-SbeBool` fails open toward LIVE for `dry_run`**~~ **CLOSED loop 58** (secureboot 1.6.3): new
    `Get-SbeDryRunSafe` at the destructive call site — the live path requires an absent value (manifest default) or an
    explicit recognized false token; any present-but-unrecognized token stays DRY (fail-safe). `Get-SbeBool` left
    untouched (shared by attemptOffline/allowEmptyPassword where `$false`-default is correct). +5 behavioral tests. _(loop-57 dive)_
65. **secureboot scan summary drops `Cancelled` rows** (P3) — `:1051-1057` tallies only the seven named verdicts;
    operator-cancelled hosts (`:1038`) are excluded so `counts` ≠ `total`. Not false-clean (nothing marked
    compliant). Fix: add `Cancelled` to the tally list. _(loop-57 dive)_
66. **secureboot icacls lock on the password payload is best-effort** (P3) — `:601` `icacls ... 2>$null | Out-Null`;
    on failure the plaintext BIOS password sits on `C$\Windows\Temp` with inherited ACLs for ~90s (self-delete +
    finally are backstops). Hardening only. Fix: check icacls exit, abort host on failure. _(loop-57 dive)_

67. ~~**pkginstall msiexec 1638 booked a false VulnPatched Success**~~ **CLOSED loop 60** (pkginstall 2.5.9): an
    all-1638 host ("another version already installed"; msiexec refused, nothing installed, version unverified) now
    resolves to `'AlreadyInstalled'` → harvest `skipCount` + audit `Skipped`/itemCount 0, not `Success`/VulnPatched.
    +5 tests (static analysis). _(from loop-60 pkginstall dive)_
68. ~~**pkginstall PSADT branch pre-seeds `$LASTEXITCODE=0`**~~ **CLOSED loop 61** (pkginstall 2.5.10): pre-seed
    `$global:LASTEXITCODE=$null` and catch a null exit as `Failed` ("returned no exit code ... cannot confirm the
    install ran") BEFORE the success-exit check — a deploy script that returns without `exit`/`Exit-Script` is no
    longer a false Success/VulnPatched. +3 tests (static analysis, incl. an ordering assert). _(loop-60 dive)_
69. ~~**pkginstall has NO confirm-word on either destructive deploy action**~~ **CLOSED loop 62** (pkginstall 2.5.11):
    fail-closed module gate `if ([string]$Params['confirm'] -ne 'DEPLOY') { refuse }` at the shared dispatch (before
    target parsing / self-guard / fan-out) + a required `confirm` "Type DEPLOY to arm" input on both deploy actions
    (adto pattern, no JS). Case-insensitive like adto's `-ne 'FIX'`. +5 tests. _(loop-60 dive)_
70. ~~**pkginstall `ConvertTo-JanetMsiList` silent partial drop**~~ **CLOSED loop 63** (pkginstall 2.5.12): new
    `Get-JanetMsiListDropped` (inverse filter) surfaces dropped rooted/`..` entries; the caller warns per drop and
    **refuses** a non-blank selection that dropped to empty rather than escalating to install-every-`*.msi`; a blank
    selection keeps the intentional install-everything path. +5 tests. **pkginstall dive COMPLETE (67-70).** _(loop-60
    dive; P3-5 cancel + S1/S2 = accepted)_

71. ~~**upr generic uninstall handlers: MSI-GUID injection + Store false-clean**~~ **CLOSED loop 64** (upr 1.2.4):
    the generic-MSI + Adobe handlers extracted a GUID with a loose `\{[^}]+\}` and interpolated it into a raw msiexec
    `ArgumentList` string (crafted `UninstallString` could inject switches under the operator cred) → routed the
    generic-MSI path through the injection-safe `Invoke-SafeUninstall`, and tightened Adobe's 3 GUID extractions to a
    strict hex pattern + discrete args (static assert widened the fix to the class). The dead Store branch returned an
    unconditional `OK (Store app removed)` invisible to the registry re-verify → removed (future `Store` type
    fail-closes via EXE), "Store" dropped from the manifest. +4 tests. _(loop-64 upr dive; core else fail-closed)_
72. **upr 3010 reboot flag lost for Adobe/M365 OK strings** (P3) — those handlers' OK strings don't embed the exit
    code, so a reboot-pending removal reports plain OK (missing advisory, NOT a false-clean — the registry re-verify
    confirms the product is gone). Fix: surface the exit code / a `3010` token from the Adobe/M365 handlers. _(loop-64 dive)_
73. **upr IPv4 wrong-box skip + empty-probe-proceed** (P3, speculative/by-design) — IPv4-literal targets skip the DNS
    wrong-box name check and an empty COMPUTERNAME probe proceeds; documented house pattern (self-guard still checks
    NIC-IP membership). No change strictly required. _(loop-64 dive)_

74. ~~**dhcp bulk ReadError laundered to Success**~~ **CLOSED loop 65** (dhcp 1.1.9): the remote bulk script fail-closes
    a read failure as `Status='ReadError'` (declines to write), but the local handler counted it in no bucket, both
    audit `switch` defaults booked `TouchHost/Success`, and the summary read "0 error(s)". Now the counter's tail is a
    fail-closed catch-all + both defaults book Failure + explicit `ReadError → Failure`. +3 tests. _(loop-65 dhcp dive)_
75. ~~**dhcp destructive actions have NO self-guard and NO confirm-word**~~ **CLOSED loop 66** (dhcp 1.1.10): the 4
    write actions (apply + bulk-*) now refuse fail-closed BEFORE any DHCP session unless the operator typed `APPLY`
    (case-insensitive), and refuse when the target resolves to the box running JANET (`Get-DhcpLocalIdentity`/
    `Test-DhcpHostIsSelf`, mirroring pkginstall). `connect`/`load` stay ungated. +6 tests. _(loop-65 dive)_
76. ~~**dhcp `dryRun` fails OPEN on unrecognized values**~~ **CLOSED loop 67** (dhcp 1.1.11): new
    `Get-DhcpDryRunSafe` at both dryRun sites — the live path requires an absent value (manifest default) or an
    explicit recognized false; any present-but-unrecognized token stays DRY. `$asBool` left untouched (removeOption
    still uses it, where unrecognized→false is safe). +5 behavioral tests. _(loop-65 dive)_
77. ~~**dhcp non-numeric `optionId` silently retargets option 6 (DNS)**~~ **CLOSED loop 69** (dhcp 1.1.13): the shared
    optionId parse now aborts (rejected, no DHCP session) when the value is present-but-unparseable AND the action is
    destructive (`$isDestructive`, reused from the loop-66 gate); a read-only `load` still warns-and-defaults. +3
    behavioral tests. _(loop-65 dive)_
78. ~~**dhcp apply null-result → Changed/Success**~~ **CLOSED loop 68** (dhcp 1.1.12): a null remote apply result
    coerced `[bool]$null.Removed=$false` → `Status='Changed'`/Success for an unconfirmable change. Now a null
    `$applyCall.Result` books Failure (`Status='Error'`, `failed=1`, "change NOT confirmed"), mirroring the catch. +2
    behavioral tests. _(loop-65 dive; the post-write-verify half split to item 80)_
79. **dhcp bulk doesn't reconcile returned records vs requested scopes** (P3) — a missing scope in the result set gets
    no row/audit/error (summary "0 error(s)"). Fix: emit an Error/abandoned row per requested scope with no returned
    record. _(loop-65 dive)_
80. **dhcp apply/bulk have NO post-write re-read verification** (P2, NEW) — neither re-reads the option after the
    Set/Remove to confirm the value actually became the intended one (only a *pre*-write stale check on bulk); success
    is inferred from "the cmdlet didn't throw." Fix: a mandatory post-write re-read + compare (upr's re-verify pattern).
    The most valuable remaining dhcp hardening; a bigger add — its own loop. _(loop-65 dive; split from item 78)_

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
  StagingReboot + Diagnose24h2 + Drive + FixVerify2/3 **101** green. **The authoritative run caught a
  regression the scoped set missed** — `WinUpgrade.VersionAndRemediation.Tests.ps1` had PINNED the old
  fail-open (its own note flagged it "a false-negative risk, not enshrined as correct"); updated to assert
  the fail-close in a follow-up (`3b4597b`). Pester **1307→1315** green. Backlog
  now: the c2c cluster (22/23/24/26, a bucket-taxonomy redesign) + winupgrade #29 (AutoFix, needs a shim
  harness) — both deferred as non-trivial. SECRET parity: +winupgrade repair-verdict fail-close.
- **Loop 38 (DONE 2026-07-21):** Fable-inline synthesis + one Fable deep-dive worker on **acas** (the
  most-used remediation tool, 242KB, never loop-era-reviewed). Self-review of loop-37 → **GREEN**. Worker read
  the full 3,696-line module; I re-verified every finding in-code. acas is largely fail-closed (thrown probe →
  UNCONFIRMED, version-unchanged → UNCONFIRMED, self-classified FAIL/SKIP authoritative, DNS wrong-box abort,
  KB-install exemplary, unreachable/cred-fail → FAIL, fan-out three-way `$isSkip`). **Closed F1 (item34):** the
  in-card `reboot-selected` arm (`:3630`) booked a **VulnPatched Success audit at reboot-SCHEDULE time** —
  scheduling an abortable `shutdown /r /t 300` (rc=1190 "already scheduled" also OK) is a TOUCH, not a
  confirmed patch. loop28 (item19) fixed this exact false-compliance record on the `schedule-reboot` sibling
  (`:3389`) but MISSED this by-key arm; `verify-post-reboot` (`:3644`) also audits TouchHost. **FIXED** (acas
  **1.11.9→1.11.10**): `TouchHost`, matching both siblings; the row was already honest ('scheduled'). `Acas.
  RebootAudit.Tests.ps1` extended — the reboot-selected sub-block isolated + pinned TouchHost/not-VulnPatched
  (all 3 reboot arms now pinned so no sibling drifts again); exact pin → 1.11.10 (all other acas tests are
  floors). acas reboot/verify/profile/KB set **69** green. Pester **1315→1318** green. **Ranked F2–F6 as items
  35–39** (verify=mtime-recency HIGH, "bumped"=string-inequality MED-HIGH, Log4j partial-scan MED, null→OK
  latent, direction-agnostic Script proof LOW) — each needs its own design pass (F2/F4 can't be one-liners
  without regressing non-version profiles). SECRET parity: +acas reboot-selected TouchHost audit fix.
- **Loop 39 (DONE 2026-07-21):** Fable-inline. Self-review of loop-38 → **GREEN**. **Closed a confirmed
  backlog false-clean: acas F4/item36** — the update worker declared a `"bumped"` (→ OK → PATCHED tile +
  VulnPatched Success audit) on ANY `preV -ne postV` string inequality (`:2084`), so a post-verify probe that
  degraded to `'error'` (caught probe, Defender `:204`), `'n/a'` (vanished Office key `:123`), or `'not
  installed'` (`:146`/`:562`), or a numeric DOWNGRADE, booked a confirmed patch for a host whose state was
  unknown. **FIXED** (acas **1.11.10→1.11.11**): new PURE `Get-AcasBumpVerdict` (`:2361` area) + inline worker
  mirror (`:2084`) → `'unconfirmed'` when post ∈ {error,n/a,not installed} or `[version]`-parseable downgrade
  (post ≤ pre), else `'confirmed'`; deliberately left confirmed = `'none'` (Log4j clean) + non-version state
  transitions (spec-exec → COMPLIANT, doesn't parse as `[version]`), so no real bump/install/clean/transition
  is masked. `Acas.BumpVerdict.Tests.ps1` (NEW, 11) pins degraded/downgrade→unconfirmed + the 4 confirmed
  shapes + a static mirror assert + exact 1.11.11 (RebootAudit exact pin → floor). Full acas verify/profile set
  **122** green; grepped all tests for touched symbols (loop-37/38 lesson). Pester **1318→1329** green.
  **Remaining acas backlog:** items 35 (verify=mtime-recency, HIGH — needs per-profile required-version
  compare), 37 (Log4j partial-scan), 38 (null→OK latent), 39 (direction-agnostic Script proof). SECRET
  parity: +acas bump-verdict degraded/downgrade fail-close.
- **Loop 40 (DONE 2026-07-21):** Fable-inline synthesis + one Fable deep-dive worker on **wpt** (most-used,
  485KB). Self-review of loop-39 → **GREEN**. The dive's actionable immediate: **acas lags wpt** — wpt hardened
  its M365 C2R verify in loop24 (fresh AND `LastScenarioResult` succeeded, because C2R bumps the key on failed
  attempts too), but acas's Office C2R verify (`:129`) still used bare mtime-recency, the confirmed worst-case
  slice of item35. **FIXED** (acas **1.11.11→1.11.12**): new pure `Get-AcasC2rVerified` ported from
  `Get-WptC2rVerified` + inline generated-scriptblock mirror — Verified true only when fresh AND scenario
  succeeded, `$false` on stale/failed, `$null` on unknown. `Acas.C2rVerify.Tests.ps1` (NEW, 10, mirrors
  `Wpt.C2rVerify`); BumpVerdict exact pin → floor. acas verify/profile set **76** green; all-tests symbol grep
  clean. Pester **1329→1339** green. **The wpt dive also produced a rich backlog (items 40–50)** — systemic
  finding: wpt classifies success from the profile Script's `OK…` prefix, so the honest-outcome discipline
  applied to kb-install (loop22/23) + C2R verify (loop24) was never swept across the app-update profile catalog
  (items 40/41/42 are HIGH). SECRET parity: +acas Office C2R scenario-success verify; wpt items are parity
  candidates once closed.
- **Loop 41 (DONE 2026-07-21):** Fable-inline. Self-review of loop-40 → **GREEN**. **Closed wpt item41 (HIGH)**
  from the loop-40 dive, completing the C2R-verify work: `WptAppUpdateBlock` set `Status='Verified'` for ANY
  returned probe (`:3421`), and the `app-update-verify` OkOf keyed off that (`:6441`), so a reachable host that
  read `Verified=No` (stale, still-vulnerable) counted in "N verified" and booked a TouchHost Success audit —
  the row was honest, the tally/audit over-reported. **FIXED** (wpt **6.8.8→6.8.9**): new pure `Get-WptVerifyOk`
  (mirrors `Get-AcasVerifyRowStatus`) → ok only when reachable AND `Verified -eq $true`; a reachable-but-not-
  verified host now audits Skipped (checked, not current), not Failure (matching wpt's PENDING→Skipped). Helper
  is controller-side (no inline mirror). `Wpt.VerifyApp.Tests.ps1` (NEW, 9) pins the predicate + the handler
  wiring; C2rVerify exact pin → floor. wpt set **78** green; all-tests symbol grep (incl. `app-update-verify`)
  clean. Pester **1339→1348** green. **Remaining wpt HIGH:** item40 (systemic OK-on-trigger), item42 (bulk-patch
  null-RV), item43 (Java SC mtime). SECRET parity: +wpt verify-tally honors the Verified verdict.
- **Loop 42 (DONE 2026-07-21):** Fable-inline. Self-review of loop-41 → **GREEN**. **Closed wpt item42 (HIGH)** —
  bulk-patch (and, the static assert revealed, three sibling CCM-trigger sites) counted a host triggered off a
  NULL client-SDK ReturnValue, which then booked a VulnPatched/Success audit; a method that returned nothing did
  NOT confirm acceptance (kb-install already fail-closes on null, loop22 `:2819`; these didn't). **FIXED** (wpt
  **6.8.9→6.8.10**): swept ALL five sites (bulk-patch `:2001`/`:2027`, SC App/Update trigger `:3913`/`:3923`,
  `WptAppActionBlock` `:4671`) to accept ONLY a non-null `[int] 0` via new pure `Get-WptRvAccepted` + inline
  mirrors; rejected-rv messages now print `<null>` not a coerced 0. The regression test's module-wide static
  assert is what surfaced the 3 extra sites — the honest scope of the class (loop-37 lesson generalized). Also
  overrode one worker "GREEN" (WptAppActionBlock) on in-code evidence its null path → OK=true→VulnPatched.
  `Wpt.BulkPatchRv.Tests.ps1` (NEW, 8); VerifyApp exact pin → floor. wpt set **59** + guards **24** green. Pester
  **1348→1356** green. **NEW item51** (HIGH): the deeper trigger≠patched semantic — a merely-accepted async CCM
  trigger books VulnPatched, not a confirmed install (same class as item40). SECRET parity: +wpt null-rv
  fail-close across the CCM-trigger scriptblocks.
- **Loop 43 (DONE 2026-07-21):** Fable-inline. Self-review of loop-42 → **GREEN**. **Closed item40's M365 slice
  (HIGH, the worker's top finding)** — both `Microsoft 365 - Force Update` (`:939`) and `Update (User Visible)`
  (`:1248`) profiles triggered `OfficeC2RClient.exe /update` then `return "OK (…exit $($proc.ExitCode))"`, the
  exit code interpolated but NEVER tested, so a nonzero exit (real failure) read OK → VulnPatched in
  app-update-apply. **FIXED** (wpt **6.8.10→6.8.11**): both Scripts FAIL on a nonzero exit; exit 0 stays
  OK-triggered (the paired `M365C2RVerify` scenario-success gate, loop24, confirms completion). `Wpt.M365Update.
  Tests.ps1` (NEW, 7) static-analyses both profile blocks + asserts the old form is gone module-wide;
  BulkPatchRv exact pin → floor. wpt set **57** green; grep clean. Pester **1356→1363** green. **item40 residual
  (open):** Trellix `$LASTEXITCODE` gate + SC-trigger discarded rv. The clean-port vein is thinning — next loop
  weighs a fresh dive (c2c/remoteadmin/adto) vs the narrower closes. SECRET parity: +wpt M365 exit-code gate.
- **Loop 44 (DONE 2026-07-21):** Fable-inline synthesis + one Fable deep-dive worker on **c2c** (C2C Nemesis,
  276KB, never comprehensively loop-era-dived). Self-review of loop-43 → **GREEN**. Worker traced the scan,
  all six fixers, rollup, tally, audit, version check; I re-verified F1. c2c is largely fail-closed (escrow-first
  BitLocker, RTP re-eval, patch-overdue/import fail-closes, scan CHECK-ERRORS-never-READY, self/wrong-box
  guards). **Closed F1 (HIGH):** the AntiMalware fixer's `Get-MpComputerStatus`-unavailable else-branch
  (`:1982`) booked **FIXED** off a mere WinDefend/Sense service flip with RTP/mode/signatures all unread — a
  broken-Defender host (the ones most likely non-compliant) read AntiMalware PROTECTED → host FIXED →
  VulnPatched Success. **FIXED** (c2c **1.15.4→1.15.5**): a change we can't confirm is **NOT VERIFIED**, the
  existing fail-closed state — the host rollup maps it to a NOT VERIFIED host status (never FIXED, `:2360`) and
  the audit switch to `Failure`/itemCount 0 (`:3090`). Static-analysis test (a behavioral harness needed a
  `Get-Command` shim that leaked into the sibling scan tests + timed out the suite; NOT VERIFIED rollup/audit is
  covered by PkiRoots+rollup tests). c2c set **109** green; PatchOverdue exact pin → floor. Pester
  **1363→1367** green. **Ranked items 52–57** (F5 Monitoring same-class HIGH, F3 sig-age coercion, F4/F7/F8 low,
  F9 speculative; F2/F6 refine the 22/24 tally/rollup cluster). SECRET parity: +c2c AntiMalware unavailable
  fail-close.
- **Loop 45 (DONE 2026-07-21):** Fable-inline. Self-review of loop-44 → **GREEN**. **Closed c2c item52 (F5, HIGH)**
  — the same partial-signal class as loop-44's F1: the Monitoring fixer booked FIXED/NOCHANGE (MONITORED) off the
  client service being Running (`:1447-1451`), ignoring `$ti.Installed`, though the scan's Monitoring PASS
  (`:751`) requires installed AND running. A running-but-not-installed box (orphaned service / unreadable
  uninstall registry) read MONITORED / host FIXED / VulnPatched Success with Detail literally "Tanium not
  installed", while the scan would still quarantine it. **FIXED** (c2c **1.15.5→1.15.6**): new pure
  `Get-C2cMonitoringVerdict` (not-running→FAIL; running-but-not-installed→NOT VERIFIED; installed+running+change→
  FIXED; else→NOCHANGE) + inline worker mirror — aligns the fix verdict with the scan (a MONITORED verdict now
  genuinely means the box passes). `C2c.MonitoringVerdict.Tests.ps1` (NEW, 6, pure-helper branches + static
  mirror assert); loop-44 exact pin → floor. c2c set **85** green. Pester **1367→1373** green. **Principle:** a
  fix verdict must match the scan verdict, else FIXED doesn't mean "will pass" — the general lesson for the c2c
  pillar tail. SECRET parity: +c2c Monitoring installed-half fail-close.
- **Loop 46 (DONE 2026-07-21):** Fable-inline. Self-review of loop-45 → **GREEN**. **Closed c2c item53 (F3, MED)**
  on the safety-critical scan READY verdict: the AntiMalware scan (`:830`) and fix (`:1914`) fell back to
  `[int]$mp.AntivirusSignatureAge * 24` in an `else`, and `[int]$null` coerces to 0 (no throw), so an unreadable
  signature age manufactured a 0-hour "fresh" age → PASS → READY, defeating the `$null -ne $ageHours` guard.
  **FIXED** (c2c **1.15.6→1.15.7**): both sites guard the fallback — `elseif ($null -ne
  $mp.AntivirusSignatureAge)` — so a null age stays `$null` (treated as stale, fail-closed); new pure
  `Get-C2cSigAgeHours` + inline mirrors (same `[int]`-cast-guard discipline as acas spec-exec).
  `C2c.SigAge.Tests.ps1` (NEW, 7, pure helper + static assert both sites guarded); Monitoring exact pin → floor.
  c2c set **71** green. Pester **1373→1380** green. **c2c tail now low/read-only** (items 54–57 + 22/24 cluster)
  — loop 47 weighs a fresh dive (remoteadmin/adto/secureboot/reports) vs the tail. SECRET parity: +c2c sig-age
  null-coercion fail-close.
- **Loop 47 (DONE 2026-07-21):** Fable-inline. Self-review of loop-46 → **GREEN**. Re-verified F2/item24 (the
  summary tally folding NOT VERIFIED/SKIP into `nochange`) — it's **view-coupled** (`perPillar` is returned in
  the run summary `:3215` for the view), so a coordinated JS change, not a one-file edit; deferred. **Closed the
  definite c2c item55 (F7):** the audit emit (`:3135`) mapped host Status `PARTIAL {'Success'}` + itemCount 1,
  but the rollup only reaches PARTIAL when `failed>=1` — so a host with a failing pillar was booked VulnPatched
  **Success** in the ledger (a false-compliance record, the loop-38 audit-honesty class). **FIXED** (c2c
  **1.15.7→1.15.8**): new pure `Get-C2cHostAuditResult` — FIXED→Success, NO CHANGE/SKIPPED/OFFLINE→Skipped, else
  (PARTIAL/FAILED/NOT VERIFIED)→**Failure**; only a fully-FIXED host counts as a patched item. Called directly
  (controller-side, no mirror). `C2c.AuditResult.Tests.ps1` (NEW, 10); SigAge exact pin → floor. c2c set **58**
  green. Pester **1380→1390** green. **c2c high-harm findings all closed (F1/F5/F3/F7)** — loop 48 should open a
  fresh dive on an un-reviewed acting tool (certdeploy/adto/remoteadmin) rather than grind the tail (item54/56/57
  + the 22/24 view-coupled cluster). SECRET parity: +c2c PARTIAL audits Failure.
- **Loop 48 (DONE 2026-07-21):** Fable-inline synthesis + one Fable deep-dive worker on **certdeploy** (Cert
  Deploy, 110KB, un-reviewed acting tool — installs DoD trust anchors). Self-review of loop-47 → **GREEN**. The
  dive found certdeploy's core solidly fail-closed (fresh-handle per-thumbprint re-verify, INSTALLED needs
  Added>0, NOT VERIFIED on stripped certs, hex/case-proof compares, CHECK-on-unreadable-store fails NOISY). But
  **closed F1:** the CHECK worker parses the wanted thumbprints from JSON on the target, and a null/undeserialized
  want-set made `Get-CertDeployStoreMissing` skip every store group (`:552`) → 0 present/0 missing/no Err → the
  admin side read **ALL PRESENT** for a host whose stores were never inspected. **FIXED** (certdeploy
  **1.4.0→1.4.1**): the reader counts usable (hex, non-blank) thumbprints and returns an `Err` when 0 — the
  bundle always carries certs, so a zero-count want-set is a deserialization failure, mapped to CHECK ERROR. The
  guard is in the injected store-reader (fails closed remote + local). `CertDeploy.Tests.ps1` +4 (null/empty/
  blank → Err; real want doesn't trigger); two 1.4.0 exact pins → floors. certdeploy set **83** green. Pester
  **1390→1395** green. **Ranked items 58/59** (F2 rejected-anchor-reads-ALREADY MED-HIGH, F3 reconciler
  registry-denied-reads-green LOW; F4/F5 speculative structural, not ranked). SECRET parity: +certdeploy
  want-set-empty → Err.
- **Loop 49 (DONE 2026-07-21):** Fable-inline. Self-review of loop-48 → **GREEN**. **Closed certdeploy item58
  (F2)**, completing the tool's deploy honesty: `Add-CertDeployBundleToStores` correctly refuses a non-CA cert
  destined for a trust-anchor store (`:382`) but `Get-CertDeployResultToken` ignored the `Rejected` count, so a
  refused-and-ABSENT anchor read `ALREADY`/`INSTALLED` → a clean VulnPatched Success while the anchor stayed
  absent (the guard was right, the reporting lied). **FIXED** (certdeploy **1.4.1→1.4.2**): the classifier emits
  **REJECTED** when `Rejected>0` (after FAIL/NOT VERIFIED, before INSTALLED/ALREADY) → row `REJECTED (non-CA)`
  (error level + own summary bucket) → audit Failure/0; honest non-rejection tokens unchanged. `CertDeploy.Tests.
  ps1` +6; two CaValidation tests that had pinned the old rejected→INSTALLED/ALREADY corrected (loop-37 lesson);
  loop-48 exact pin → floor. certdeploy set **73** green. Pester **1395→1401** green. **Both certdeploy real dive
  false-cleans (F1/F2) now closed** — remaining item59 (F3, LOW/advisory) + F4/F5 (speculative). SECRET parity:
  +certdeploy REJECTED token.
- **Loop 50 (DONE 2026-07-21):** Fable-inline. Self-review of loop-49 → **GREEN**. **Closed wpt item44 (MED-HIGH)**
  from the loop-40 dive (chose a still-open wpt item on the most-used tool over a fresh dive on a niche tool):
  `WptCleanUserAppsBlock` set the row Status **unconditionally** to `'Success'` on a live run (`:3655`), so a
  host where every app-binary deletion FAILED (locked app → `found>0, removed=0`) read Success + ok tile +
  VulnPatched Success while nothing was removed. **FIXED** (wpt **6.8.11→6.8.12**): new pure `Get-WptCleanStatus`
  (found>0/removed=0 → Failed; partial → Partial; all-removed/nothing-found → Success) + inline worker mirror;
  the OkOf (Success/Dry Run OK only) + fan-out Failure-audit drop Partial/Failed automatically. `Wpt.CleanStatus.
  Tests.ps1` (NEW, 8); M365Update exact pin → floor. The static assert surfaced a sibling (disk-cleanup `:3250`)
  with the same line but DIFFERENT semantics (best-effort maintenance) — narrowed the assert, didn't widen the
  fix. wpt set **40** green. Pester **1401→1409** green. **Remaining wpt:** item43 (Java SC mtime, HIGH), 45–47
  (MED), 48–50 (LOW), 51 (trigger≠patched, HIGH). SECRET parity: +wpt clean-user-apps honest status.
- **Loop 51 (DONE 2026-07-21):** Fable-inline. Self-review of loop-50 → **GREEN**. **Closed wpt item45 (MED,
  fleet-level)** — a distinctive self-blinding false-clean: the software-uninstall verify-and-clean pass removed
  the product's Uninstall registry key **unconditionally** (`:4250`), even when `$filesRemain` (the install
  folder still present). So a still-installed product (row correctly 'Attention') lost its registry entry, and
  every later registry-driven scan (Software Scan / unsupported-product / ACAS) then read the host clean —
  corrupting the detection substrate other tools rely on. **FIXED** (wpt **6.8.12→6.8.13**): the key-removal is
  gated on `-not $filesRemain` — removed only when files are actually gone (genuinely orphaned); if files remain
  it's KEPT with a note. The 'Attention' verdict is unchanged. `Wpt.VerifyClean.Tests.ps1` (NEW, 5, static —
  the block is an inline module-less scriptblock); CleanStatus exact pin → floor. wpt set **29** +
  SoftwareUninstall **3** green. Pester **1409→1414** green. **Remaining wpt:** item43 (Java SC mtime, HIGH),
  46/47 (MED), 48–50 (LOW), 51 (trigger≠patched, HIGH). SECRET parity: +wpt verify-clean files-gone gate.
- **Loop 52 (DONE 2026-07-21):** Fable-inline. Self-review of loop-51 → **GREEN**. **Closed wpt item46 (MED)** in
  the same software-uninstall path: Adobe Acrobat registers multiple MSI product-code GUIDs, and the branch set
  `$removed=$true` on ANY one GUID uninstalling (`:4364`) with per-GUID failures untracked → read a clean
  `Removed` (counter `:5265` books ok) for a PARTIAL uninstall while Adobe stayed installed via the failed GUIDs.
  **FIXED** (wpt **6.8.13→6.8.14**): the branch counts per-GUID success/failure — all removed → Removed; some
  failed while others succeeded → **Attention** (not-clean, `$isOk` requires exact Removed); all failed → default
  Failed; failing GUIDs' exit codes in the detail. `Wpt.AdobeUninstall.Tests.ps1` (NEW, 6, static — inline
  module-less branch); VerifyClean exact pin → floor. wpt set **16** green. Pester **1414→1420** green.
  **Remaining wpt:** item43 (Java SC mtime, HIGH — the last non-trivial one), 47 (MED), 48–50 (LOW), 51
  (trigger≠patched, HIGH). SECRET parity: +wpt Adobe partial → Attention.
- **Loop 53 (DONE 2026-07-21):** Fable-inline synthesis + one Fable deep-dive worker on **adto** (AD-TO
  compliance, 42KB, un-loop-era-dived). Self-review of loop-52 → **GREEN**. The dive confirmed the **write** paths
  are genuinely fail-closed (the fix's FIXED verdict re-binds a fresh DirectoryEntry and compares the re-read UAC
  to the computed target, not "write didn't throw"; validate-iao re-reads the stamp; audit maps only FIXED/
  VALIDATED → Success). The false-cleans are read-side, one `[int]$null → 0` coercion. **Closed F1 (HIGH):** the
  fix path read UAC via `[int]("0"+[string]…Value)`, so a null/unreadable UAC (a non-account object, or an
  ACL-denied read) coerced to `$cur=0` → a clear-op rule computed `$fx.Uac=0` → row **NO CHANGE "already
  compliant"** (bits never read); worse, a set-op rule with `$cur=0` **wrote** a corrupting full UAC (wiping
  NORMAL_ACCOUNT) before the re-read caught it. **FIXED** (adto **0.2.3→0.2.4**): a `$null` raw UAC → **FAILED**
  + Failure audit BEFORE any computation/write — closing the false verdict AND the corrupting write. `AdTo.
  WriteGuards.Tests.ps1` +3. adto set **12** green. Pester **1420→1423** green. **Ranked items 60/61** (F2
  scan-side same coercion → COMPLIANT MED-HIGH, F3 overlay silent-disable MED; F4/F5 speculative). SECRET parity:
  +adto null-UAC fail-close.
- **Loop 54 (DONE 2026-07-21):** Fable-inline. Self-review of loop-53 → **GREEN**. **Closed adto item60 (F2)**,
  the scan-side twin of loop-53's F1 (same `[int]$null → 0` coercion, different function): `ConvertTo-AdToObject`
  (`:370`) folded an ACL-hidden UAC to `Uac=0`, so `Test-AdToCompliance`'s bad-bit rules read no violations → a
  Service account (excluded from the smartcard rule) with a hidden UAC scanned **COMPLIANT** while live it had
  PASSWD_NOTREQD. **FIXED** (adto **0.2.4→0.2.5**): `ConvertTo-AdToObject` carries `UacReadable`, and
  `Test-AdToCompliance` fires a fail-closed **`uacUnreadable`** hit (→ NON-COMPLIANT) + skips the four UAC
  bad-bit rules when unreadable; non-UAC rules still run; missing key → readable (back-compat). `AdTo.WriteGuards.
  Tests.ps1` +4 (direct `Test-AdToCompliance` calls). adto set **16** green. Pester **1423→1427** green. **Both
  adto null-UAC false-cleans (F1/F2) closed**; remaining item61 (F3, overlay silent-disable, MED) + F4/F5
  speculative. SECRET parity: +adto scan UacReadable / uacUnreadable hit.
- **Loop 55 (DONE 2026-07-21):** self-review of loop-54 → GREEN. Workstream = adto **item61 (F3)**, the last real
  adto dive finding: `Get-AdToBaseline` (`:84-92`) merged an overlay's `rules` by **replacing** the rule entry, so
  an overlay tuning one field (or a typo) nulled the others — a missing `enabled` became `[bool]$null=$false`
  (rule OFF), a missing `appliesTo` became `@($null)` (never fires) — silently scanning every violating object
  **COMPLIANT**. **FIXED** (adto **0.2.5→0.2.6**): the overlay now **merges** onto the embedded default (fail-closed
  `enabled=$true` base for unknown rule names), overriding only fields it explicitly provides; an explicit
  `"enabled": false` still disables. `AdTo.WriteGuards.Tests.ps1` +4 (real temp overlay, `Get-AdToBaselinePath`-only
  shim — `Test-Path`/`Get-Content` stay real). adto set **20** green. Pester **1427→1431** green. **adto dive
  complete** (F1/F2/F3 closed; F4/F5 speculative). SECRET parity: +adto overlay merge-not-replace.
- **Loop 56 (DONE 2026-07-21):** self-review of loop-55 → GREEN. Workstream = fresh **Fable deep-dive on
  remoteadmin** (last sharp un-dived destructive surface: Open C$ + Run Script). **Core is fail-closed** — no
  P1/P2: worker + aggregator default to Failed/Failure, book Success only on exact `Status -eq 'Success'`, null
  Status → `''` → Failure/itemCount 0; no coercion; all four safety guards (admin-gate, self-guard incl. NIC IPv4,
  target-validation, wrong-box hard-abort) present + correctly ordered before fan-out. Acted on **C1 (P3)**: the
  fan-out result-binding (`:473`) took `Select-Object -First 1` of `EndInvoke`, but the worker returns its result
  as the **last** stream object (`return $r`, `:306`) — a future/operator stray leak would build the row
  (Host/Status/Output) from the stray. **FIXED** (remoteadmin **1.0.1→1.0.2**): `-First 1` → `-Last 1`.
  `RemoteAdmin.Tests.ps1` +2 (stray-leaking fake worker proves the row comes from the return; version pin). set
  **31** green. C2 (open-cshare "Opened") + S1 (run-script "didn't throw") left **by-design** (dive-judged; S1
  fix would ADD coercion risk). Pester **1431→1433** green. **remoteadmin dive complete.** SECRET parity: +remoteadmin
  fan-out `-Last 1` result-binding.
- **Loop 57 (DONE 2026-07-21):** self-review of loop-56 → GREEN. Workstream = fresh **Fable deep-dive on secureboot**
  (last un-dived acting/hardening tool: enable Secure Boot via SYSTEM scheduled task + read-only scan). **Core is
  fail-closed** — no P1: task Register/Start failure → Error, vendor null/nonzero → error, Unknown a hard stop,
  wrong-box hard-abort before the payload drop, scan scores every failure away from compliant, no coercions, full
  safety stack (confirm-word + admin-gate + 50-host refusal + allow-list + self-guard + wrong-box + in-payload
  brick-safety). Acted on **P2 stale-result replay**: the enable worker polled a result JSON named from the
  **hostname alone** (`SecureBoot_<host>.json`, `:505`) and pre-deleted a stale prior-run file best-effort/unverified
  (`:594`); if that delete ever silently failed, the first-file-with-`SetResult` poll (`:627`) could replay an old
  `SetResult=0` JSON as this run's Success. **FIXED** (secureboot **1.6.1→1.6.2**): name the result file with the
  already-per-run-unique `$taskName` (`SBE_<random>`, which already names `$scriptFile`) → cross-run collision
  impossible, poll can only read this run's own result. `Secureboot.Scan.Tests.ps1` +3 (static analysis; exact pin
  moved here, ConfirmWord floored). set **35** green. 5 P3s ranked **items 62–66** (AlreadyPending re-books Success,
  staged-vs-enabled wording, `dry_run` fail-open, Cancelled tally gap, best-effort icacls) — none a hard firmware
  false-clean. Pester **1433→1436** green. **secureboot dive complete.** SECRET parity: +secureboot per-run
  `$taskName`-based result filename.
- **Loop 58 (DONE 2026-07-21):** self-review of loop-57 → GREEN. Workstream = targeted fix of **item 64**, the one
  loop-57 dive finding that's a **destructive fail-open**: the enable read `dry_run` via the shared `Get-SbeBool`,
  which resolves any unrecognized token to `$false` → a LIVE firmware write, so a typo (`'ture'`, `'dry'`) on the
  dry-run selector silently went live. **FIXED** (secureboot **1.6.2→1.6.3**): new `Get-SbeDryRunSafe` at the
  destructive call site — live only on an absent value (manifest `default=$false`) or an explicit recognized false
  token; any present-but-unrecognized token stays DRY. `Get-SbeBool` untouched (shared by attemptOffline/
  allowEmptyPassword where `$false`-default is correct — false-sibling, fixed the site not the helper).
  `Secureboot.ConfirmWord.Tests.ps1` +5 behavioral (exact pin moved here; Scan floored). set **40** green. Remaining
  secureboot items 62/63/65/66 (P3, none a hard firmware false-clean). Pester **1436→1441** green. SECRET parity:
  +secureboot `Get-SbeDryRunSafe` fail-closed dry_run parse.
- **Loop 59 (DONE 2026-07-21):** self-review of loop-58 → GREEN. Workstream = close **item 62** (last secureboot
  audit-honesty false-clean): the three vendor branches short-circuit an already-staged host with
  `SetResult='AlreadyPending'` and **return before re-firing** the set/save (this run writes nothing), but
  `New-Result` has no `Skipped` property so the resolvedStatus chain fell through to `'Success'` → a re-run booked a
  fresh `VulnPatched/Success/itemCount=1` and inflated "N enabled". **FIXED** (secureboot **1.6.3→1.6.4**): added
  `AlreadyPending → 'Skipped'` to the resolvedStatus chain (the classify already routes `Skipped` → skipCount/audit
  `Skipped`/itemCount 0); returned `Skipped` field aligned to status. `Secureboot.Scan.Tests.ps1` +3 (static
  analysis; exact pin moved here, ConfirmWord floored). set **43** green. Remaining secureboot items 63/65/66 (P3
  wording/tally/hardening). Pester **1441→1444** green. SECRET parity: +secureboot `AlreadyPending → Skipped`.
- **Loop 60 (DONE 2026-07-21):** self-review of loop-59 → GREEN. Workstream = fresh **Fable deep-dive on pkginstall**
  (most substantial un-dived destructive tool — MSI/PSADT push+install). **Core fail-closed** (Status inits Failed,
  null exit → Failed, copy SHA256-verified, no coercions, self/wrong-box/IPv4 guards pinned). Acted on **P2-2** (item
  67): msiexec **1638** ("another version already installed" — install did NOT run, version unverified) was mapped to
  `AlreadyCompliant` → all-1638 host Status `Success` → `VulnPatched/Success/itemCount=1`, a false patch for an
  untouched, possibly-vulnerable host. **FIXED** (pkginstall **2.5.8→2.5.9**): all-1638 host → `'AlreadyInstalled'` →
  harvest `skipCount` + audit `Skipped`/itemCount 0 (mirrors loop-59 AlreadyPending); mixed wave stays Success with an
  "already installed, version unverified" note. `Pkginstall.MsiList.Tests.ps1` +5 (static analysis; exact pin moved
  here, SelfGuard floored). set **30** green. 3 more findings ranked **items 68** (PSADT `$LASTEXITCODE=0` pre-seed,
  HIGH), **69** (no confirm-word on the destructive deploy — hard-rule gap, HIGH), **70** (MSI-list silent partial
  drop). Pester **1444→1449** green. SECRET parity: +pkginstall all-1638 → AlreadyInstalled/Skipped.
- **Loop 61 (DONE 2026-07-21):** self-review of loop-60 → GREEN. Workstream = close **item 68** (pkginstall's second
  false-clean): the PSADT deploy branch pre-seeded `$global:LASTEXITCODE=0`, so a `Deploy-Application.ps1` that
  returned without `exit`/`Exit-Script` left the 0 → `$exitCode=0` → Status `Success` + VulnPatched though nothing
  installed. **FIXED** (pkginstall **2.5.9→2.5.10**): pre-seed `$null` and catch a null exit as `Failed`
  ("returned no exit code ... cannot confirm the install ran") BEFORE the success-exit check. `Pkginstall.MsiList.
  Tests.ps1` +3 (static analysis incl. an ordering assert; exact pin moved here, all-1638 Describe floored). set
  **33** green. Both pkginstall dive false-cleans (67/68) closed; remaining item 69 (no confirm-word — hard-rule
  gap, HIGH — next pick) + item 70 (MSI-list silent drop). **Full-suite catch (loop-37 lesson):** the module change
  broke 3 EXISTING *behavioral* PSADT tests in `FixVerify3.Tests.ps1` that faked a "success exit" by NOT calling
  `exit` and relying on the old pre-seed `0` — the exact bug fixed. `Invoke-Psadt` updated to append a real
  `exit 0` (as PSADT `Exit-Script` does) + a behavioral no-exit → Failed test added (commit `26f82ecb7`). Pester
  **1449→1453** green. SECRET parity: +pkginstall PSADT `$LASTEXITCODE=$null` pre-seed + null-exit → Failed.
- **Loop 62 (DONE 2026-07-21):** self-review of loop-61 → GREEN. Workstream = close **item 69**, a stated-hard-rule
  gap: pkginstall was the ONLY destructive tool with no typed confirm-word (fleet-wide software install armed by one
  click once an admin session existed). **FIXED** (pkginstall **2.5.10→2.5.11**): fail-closed module gate at the
  shared `Invoke-JanetToolAction` dispatch — `if ([string]$Params['confirm'] -ne 'DEPLOY') { refuse rejected }` before
  any target parsing / self-guard / fan-out — plus a required `confirm` "Type DEPLOY to arm" input on both deploy
  actions (adto input+gate pattern, no JS). Case-insensitive, matching adto's `-ne 'FIX'`. `PkgInstall.SelfGuard.
  Tests.ps1` +5 (blank/wrong confirm → rejected; DEPLOY → reaches self-guard; `Invoke-Pkg` injects the word so
  existing self-guard tests still reach the guard; exact pin moved here, PSADT Describe floored). subset **59** green.
  pkginstall now has the full destructive guard stack (confirm-word + self-guard + wrong-box + IPv4); remaining item
  70 (MSI-list silent drop, P3). Pester **1453→1458** green. SECRET parity: +pkginstall DEPLOY confirm-word gate.
- **Loop 63 (DONE 2026-07-21):** self-review of loop-62 → GREEN. Workstream = close **item 70** (last pkginstall dive
  finding): `ConvertTo-JanetMsiList` silently dropped rooted/`..` entries, so a partial list booked "All N succeeded"
  for fewer MSIs and an all-invalid non-blank list fell through to install-every-`*.msi` (scope escalation).
  **FIXED** (pkginstall **2.5.11→2.5.12**): new pure `Get-JanetMsiListDropped` (inverse filter) surfaces the drops;
  the caller warns per dropped entry and **refuses** a non-blank selection that dropped to empty; a blank selection
  keeps the intentional install-everything path. `Pkginstall.MsiList.Tests.ps1` +5 (behavioral helper incl. a
  kept+dropped=all-lines sync invariant + caller-wiring static asserts; exact pin moved here, SelfGuard gate floored).
  subset **64** green. **pkginstall dive COMPLETE — all 4 findings (67-70) closed; full destructive guard stack +
  honest result plumbing.** Pester **1458→1463** green. SECRET parity: +pkginstall `Get-JanetMsiListDropped` +
  warn-per-drop + refuse-all-dropped.
- **Loop 64 (DONE 2026-07-21):** self-review of loop-63 → GREEN. Workstream = fresh **Fable deep-dive on upr**
  (Unsupported Product Remediator — bulk-uninstall over WinRM). **Core fail-closed** — mandatory post-uninstall
  registry re-verify catches a lying uninstaller, exit-code-gated OK, sound proven-gating (RemoveSet only restricts),
  no coercions, all four safety guards. Acted on **item 71**: (1) the generic-MSI + Adobe handlers extracted a GUID
  with loose `\{[^}]+\}` and interpolated it into a raw msiexec `ArgumentList` string (injection under operator cred) →
  routed generic-MSI through the injection-safe `Invoke-SafeUninstall`; a static assert caught the SAME flaw in the
  Adobe handler (loop-42 class-widen) → strict hex GUID + discrete args; (2) removed the dead Store branch's
  unconditional `OK (Store app removed)` false-clean landmine (future `Store` → EXE fail-close) + dropped "Store" from
  the manifest. **FIXED** (upr **1.2.3→1.2.4**): `Upr.VerifyResult.Tests.ps1` +4 (static analysis; `Get-SafeUninstallPlan`
  injection-safety already proven by `UninstallStringParse`). subset **40** green. Items 72 (3010 label) + 73 (IPv4
  wrong-box, by-design) ranked. Pester **1463→1467** green. SECRET parity: +upr Invoke-SafeUninstall routing /
  strict-GUID + Store-branch removal.
- **Loop 65 (DONE 2026-07-21):** self-review of loop-64 → GREEN. Workstream = fresh **Fable deep-dive on dhcp**
  (DHCP scope-option admin, 4 destructive server-config actions, thinly tested). **First non-fail-closed core in a
  while** — found a real **P1** (item 74): the remote bulk script fail-closes a read failure as `Status='ReadError'`
  (declines to write), but the local `Invoke-JanetDhcpBulk` handler counted it in no bucket, both audit `switch`
  defaults booked `TouchHost/Success`, and the summary read "0 error(s)" — so refusing to touch 20 scopes reported
  clean + wrote 20 Success audit rows. **FIXED** (dhcp **1.1.8→1.1.9**): counter tail → fail-closed catch-all
  (`else { $errs++ }`), both bulk audit `switch` defaults → Failure, explicit `ReadError → Failure`. `Dhcp.IpValidation.
  Tests.ps1` +3 (behavioral — shim the remote call → ReadError audits Failure + `summary.failed`; static — no default
  books Success). subset **11** green. Dive found dhcp materially under-guarded — **items 75-79** ranked (no self-guard/
  confirm-word HIGH, dryRun fail-open, optionId retarget, apply null + no post-write verify, scope reconciliation);
  **dhcp needs a follow-up hardening loop.** Pester **1467→1470** green. SECRET parity: +dhcp bulk fail-closed
  counter/default + ReadError handling.
- **Loop 66 (DONE 2026-07-21):** self-review of loop-65 → GREEN. Workstream = close **item 75**, the dhcp hard-rule
  gap: it was the only destructive engine with no self-guard and no typed confirm-word (target filter admitted
  localhost/127.0.0.1/the dispatcher's own name). **FIXED** (dhcp **1.1.9→1.1.10**): the 4 write actions (apply +
  bulk-*) now refuse fail-closed BEFORE any DHCP session unless the operator typed `APPLY` (case-insensitive), and
  refuse when `$server` resolves to the local machine (`Get-DhcpLocalIdentity`/`Test-DhcpHostIsSelf`, mirroring
  pkginstall/upr); `connect`/`load` stay ungated; no JS. `Dhcp.IpValidation.Tests.ps1` +6 (behavioral: no/wrong
  confirm → rejected, self target → self-guard rejected; + Test-DhcpHostIsSelf + manifest confirm inputs; exact pin
  moved here, ReadError Describe floored). **loop-37 lesson applied up front** — grepped every test; FixVerify/
  FixVerify3 drive dhcp sub-functions directly (below the gate), unaffected; ran all 3 files = **54** green. Remaining
  dhcp items 76-79. Pester **1470→1476** green. SECRET parity: +dhcp Test-DhcpHostIsSelf self-guard + APPLY confirm-word.
- **Loop 67 (DONE 2026-07-21):** self-review of loop-66 → GREEN. Workstream = close **item 76** (dhcp dryRun
  fail-open, secureboot loop-58 class): the dryRun selector on the destructive write actions used the shared `$asBool`,
  which resolves any unrecognized token to `$false` → a LIVE write, so a typo (`'TRUE '`, `'checked'`, `'dry'`)
  silently wrote to a live DHCP server. **FIXED** (dhcp **1.1.10→1.1.11**): new module function `Get-DhcpDryRunSafe`
  (mirroring `Get-SbeDryRunSafe`) at both dryRun sites — live only on an absent value (manifest default) or an
  explicit recognized false; any present-but-unrecognized token stays DRY. `$asBool` untouched (removeOption still
  uses it — false sibling, fixed the sites not the helper). `Dhcp.IpValidation.Tests.ps1` +5 behavioral (exact pin
  moved here, confirm/self-guard Describe floored). Ran all 3 dhcp-touching files = **59** green. Remaining dhcp items
  77-79 (78 = apply null-result/no post-write verify, the last real false-clean). Pester **1476→1481** green. SECRET
  parity: +dhcp `Get-DhcpDryRunSafe` fail-closed dryRun parse.
- **Loop 68 (DONE 2026-07-21):** self-review of loop-67 → GREEN (+ corrected loop-67 count 1479→1481, a miscount).
  Workstream = close **item 78** (the last dhcp false-clean): `Invoke-JanetDhcpApply` read the write result via
  `Select -First 1`; a null/empty result made `[bool]$null.Removed=$false` → `Status='Changed'` → a clean
  VulnPatched/Success for an unconfirmable change. **FIXED** (dhcp **1.1.11→1.1.12**): a null `$applyRes` books
  Failure (`Status='Error'`, `failed=1`, "change NOT confirmed"), mirroring the catch. `Dhcp.IpValidation.Tests.ps1`
  +2 behavioral (two-seam shim: valid pre-read, empty write → Error/Failure; exact pin moved here, dryRun Describe
  floored). Ran all 3 dhcp-touching files = **61** green. The post-write-verify half split to **item 80** (the most
  valuable remaining dhcp hardening — its own loop). Remaining dhcp items 77/79/80. Pester **1481→1483** green.
  SECRET parity: +dhcp apply null-result → Failure guard.
- **Loop 69 (DONE 2026-07-21):** self-review of loop-68 → GREEN. Workstream = close **item 77** (dhcp non-numeric
  optionId retargets option 6/DNS): the shared optionId parse warned + defaulted to option 6 (DNS Servers) even on a
  destructive write, so an operator who meant option 60/66 and typo'd would live-replace the scope's DNS servers on the
  wrong option. **FIXED** (dhcp **1.1.12→1.1.13**): hoisted the gate's action set into `$isDestructive`; the optionId
  parse's non-numeric branch now aborts (rejected, no DHCP session) on the destructive path while a read-only `load`
  still warns-and-defaults. `Dhcp.IpValidation.Tests.ps1` +3 behavioral (apply + bulk non-numeric optionId → rejected;
  exact pin moved here, null-result Describe floored). Ran all 3 dhcp-touching files = **64** green. Remaining dhcp
  items 79 (P3 reconciliation) + 80 (P2 post-write verify, the last substantive hardening). Pester **1483→1486** green.
  SECRET parity: +dhcp `$isDestructive` optionId abort.
- **Loop 70 (DONE 2026-07-21) — NEW THEME "informative failures":** per operator directive, shift from making
  failures HONEST (loops 37-69) to making them INFORMATIVE — when something can't be done, surface WHY + HOW to fix.
  Only 2 of ~21 tools translated errors to guidance (restart `Get-RrsShutdownErrorHint`, dhcp `Get-JanetWsmanAuthHint`);
  the rest showed bare `"FAIL: <msg>"`. **Built** shared `JanetWeb.troubleshoot.psm1` → `Get-JanetTroubleshootHint`
  (generalizes restart's mapper; Kerberos 0x80090351 / TrustedHosts / access-denied-vs-logon-failure / DNS / RPC-135 /
  C$-445 / timeout / no-cred / disk / file-lock; most-specific-first; `''` on unknown — never guesses). **First wire:**
  remoteadmin `$emitResult` (1.0.2→1.0.3) — a failed host now carries the hint in a `Hint` row field + audit
  (`TROUBLESHOOT:`) + err log (`FIX:`), raw error preserved. +9 helper tests +1 behavioral. subset **41** green.
  Pester **1486→~1496** green. Rollout: wire each tool's failure path loop-by-loop (wpt/acas/pkginstall first).
  SECRET parity: the whole engine + each tool wire.
- **Loop 71 (DONE 2026-07-21) — informative-failures theme:** self-review of loop-70 → GREEN. Workstream = wire the
  hint into **acas** (highest-traffic). `Invoke-AcasFanOut` is the generic fan-out behind every acas remote action, so
  one wire covers them all: on a genuine per-host failure it runs the raw worker result through `Get-JanetTroubleshootHint`
  and attaches it to a `Hint` row field + a new err log (`FIX:`) — both untruncated; raw result preserved; the 160-char
  audit detail left as-is. The fan-out previously logged nothing per host, so a recognized failure now also gets a
  visible drawer line. **Purely additive** (success/skip untouched). acas **1.11.12→1.11.13**; `Acas.FanOutHint.Tests.
  ps1` +3 behavioral (real fan-out, synthetic failing/succeeding `$Work`; exact pin moved here, C2rVerify floored).
  **Ran all 186 acas tests** = green (fan-out is shared). Pester **~1496→~1499** green. Next tool: wpt. SECRET parity:
  +acas fan-out hint wire.
- **Loop 72 (DONE 2026-07-21) — informative-failures theme:** self-review of loop-71 → GREEN. Workstream = wire the
  hint into **wpt** (the other most-used). `Invoke-WptFanOut` is wpt's generic fan-out (same callback shape as
  `Invoke-AcasFanOut`), so one wire covers its actions: on a failure it runs the raw error (else the audit detail)
  through `Get-JanetTroubleshootHint` and attaches it to a `Hint` row field + an err log (`FIX:`); the audit-detail
  string is computed once and reused (removing a latent double-eval of `$AuditDetail`); raw error preserved.
  **Purely additive** (ok rows byte-identical). wpt **6.8.14→6.8.15**; `Wpt.FanOutHint.Tests.ps1` +5 (static analysis,
  matching wpt's fan-out test style; exact pin moved here, AdobeUninstall floored). **Ran all 182 wpt tests** = green
  (a self-inflicted test-regex bug caught + fixed). Pester **~1499→~1504** green. Next: pkginstall. SECRET parity:
  +wpt fan-out hint wire.
- **Loop 73 (DONE 2026-07-21) — informative-failures theme:** self-review of loop-72 → GREEN. Workstream = wire the
  hint into **pkginstall** (destructive; 4th tool). No generic fan-out helper — its own harvest loop (`:1042-1068`);
  after the count switch it computes `$isFail = ($status -notin ok/skip set)` and, on a failure, runs the best error
  text (`$detail` else `$reason` else `$output`) through `Get-JanetTroubleshootHint` and attaches it to a `Hint` row
  field + the existing per-host err log (`FIX:`). **Purely additive** (ok/deferred/skipped untouched). pkginstall
  **2.5.12→2.5.13**; `Pkginstall.MsiList.Tests.ps1` +4 (static analysis; exact pin moved here, loop-63 Describe
  floored). **Ran full pkginstall suite (47) + FixVerify3 PSADT (21)** = green. Pester **~1504→~1508** green. Next:
  upr. SECRET parity: +pkginstall harvest hint wire.
- **Loop 74 (DONE 2026-07-21) — informative-failures theme:** self-review of loop-73 → GREEN. Workstream = wire the
  hint into **upr** (destructive uninstall; 5th tool). Its fan-out harvest (`:1245-1272`) is multi-row (the `$EmitRows`
  callback returns several candidate rows per host); the host-level connection error is in `$res.Error`. Hoisted
  `$ok` above the row loop; on a host-level failure (`(-not $ok) -and $res.Error`) it runs the raw error through
  `Get-JanetTroubleshootHint` and attaches the hint to **each** emitted row's `Hint` field + an err log (`FIX:`, was
  only a warn before). **Purely additive** (ok hosts untouched; per-candidate uninstall failures deferred). upr
  **1.2.4→1.2.5**; `Upr.VerifyResult.Tests.ps1` +4 (static analysis; exact pin moved here, loop-64 Describe floored).
  **Ran full upr suite (44)** = green. Pester **~1508→~1512** green. Next: dhcp. SECRET parity: +upr harvest hint wire.

## Coverage status (after loop 13)
Both destructive surfaces reviewed + test-pinned: WinRM fan-out (confirm + self-guard +
wrong-box + fail-closed) and LDAP AD-write (DN-redirect + protected-object incl. RODC +
fail-closed re-read). Reviewed tools: server/auth (1), wpt profiles (1-3)+engine (9)+audit
(10), acas, upr (5), c2c (8), reports sandbox (3,7)+**correctness (13)**, remoteadmin (10),
winupgrade (11), adto (12-13). Remaining: the reports host-key sweep tail (item 11), the
IAVM CSV guard (item 12), the last small destructive tools (secureboot/dhcp/biosfirmware/
certdeploy — GREEN-ish in the loop-10 audit, not deep-dived), more correctness deep-dives on
read paths, or SECRET-parity execution on operator sign-off.
