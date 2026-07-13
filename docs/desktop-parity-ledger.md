# JANET Web -> Desktop Parity Ledger

Seeded from the 2026-07-11 and 2026-07-12 (loops 1-8) Fable audits during the Experimental->production merge.
Every Web defect fixed must end **CLOSED-BOTH** (fixed in Web AND Desktop) or **CLOSED-WEB-ONLY** with a
checked reason. Rows marked **CHECK** are mandatory Phase-2 work: a Sonnet agent locates the equivalent code
in JANET Desktop (`Tools\` versioned suite) and either fixes it (Desktop versioning rules) or records why it
doesn't apply.

Legend - Desktop status: **CHECK** = must verify in Desktop this cycle-block · **WEB-ONLY** = structurally
cannot exist in Desktop (no web server / browser UI / Web-only tool) · **CLOSED-BOTH** · **CLOSED-WEB-ONLY**.

| # | Finding (sev) | Web fix (file) | In Desktop? | Status |
|---|---------------|----------------|-------------|--------|
| 1 | mpam offline Defender gate: Authenticode+MS-signer+product-id+50MB (P2) | c2c.psm1 | field script `fix-defender` ported from Desktop | **CHECK** |
| 2 | PkiRdp Server-Auth EKU + HasPrivateKey + bind-before-clear (P2) | c2c.psm1 | Desktop `fix-pki`/RDP-cert | **CHECK** |
| 3 | Java vendor gate (Oracle/Sun-only) + strict-GUID msiexec (P2) | c2c.psm1 fix-java | Desktop `fix-java` (origin script) | **CHECK** (also Phase-2 Cycle 1/2) |
| 4 | BitLocker resume escrow-first, key never leaked (P2) | c2c.psm1 | Desktop `fix-bitlocker` | **CHECK** |
| 5 | MDE onboarding blob expiry advisory (P2) | c2c.psm1 | Desktop Defender onboarding | **CHECK** |
| 6 | Offline Defender SHA256 validate->push pin (P3->design) | c2c.psm1 | Desktop offline-Defender push | **CHECK** |
| 7 | adto FIX/IAO buttons dead - isRunning() (P3) | adto.view.js | AD-TO is a Web-only tool (no Desktop twin) | **CLOSED-WEB-ONLY** (Web-only tool) |
| 8 | SHA256 pin fail-closed on empty + -LiteralPath x2 (P3) | c2c.psm1 | Desktop offline-Defender push | **CHECK** |
| 9 | Self-guard case-sensitivity: `return ,$set` HashSet (P2) | 11 identity helpers | Desktop self-guard helpers (if present) | **CHECK** |
| 10 | Per-NIC try/catch in identity enumeration (P3) | 11 identity helpers | Desktop NIC-enumeration self-guard | **CHECK** |
| 11 | adsearch SearchBase LDAP bind-redirect (P1) | adsearch.psm1 | Desktop AD-search tool `SearchBase` bind | **CHECK** |
| 12 | adto fix/validate credentialed dn bind-redirect (P1) | adto.psm1 | AD-TO Web-only tool | **CLOSED-WEB-ONLY** (Web-only tool) |
| 13 | upr manual-uninstall (+report-uninstall) missing dispatcher self-guard - could uninstall software from the JANET box itself (P2; the merge reverted a broken port) | upr.psm1 1.2.2 (`fbbdd94`, loop22): `Get-UprLocalIdentity`+`Test-UprHostIsSelf`, drop self before BOTH uninstall fan-outs; scans stay self-inclusive; `tests/Upr.SelfGuard.Tests.ps1` (4) | YES - loop-26 sweep CONFIRMED PRESENT: `UnsupportedProductRemediator_1.1.4.ps1` `$btnUDoIt.Add_Click` (:2673) fans out uninstalls (:2693-2719) with ONLY a DNS-mismatch guard - no self/local-box drop | **DESKTOP-MIRROR-QUEUED** (Web closed; Desktop fix ready - drop self before `$hostList` in `$btnUDoIt.Add_Click`; new versioned tool next cycle) |
| 14 | dhcp diffText() stored XSS (P2) | dhcp.view.js | Desktop has no browser UI (no innerHTML sink) | **CLOSED-WEB-ONLY** (no web UI) |
| 15 | winupgrade self-guard scoped to reboot only (P2) | winupgrade.psm1 | Desktop Windows-upgrade tool reboot guard | **CHECK** |
| 16 | Fail-closed admin-session gate (P2, design) | server/JanetWeb.Server.ps1 | Web-only (no HTTP server in Desktop) | **CLOSED-WEB-ONLY** (Web-only server) |
| 17 | DN-guard local-domain suffix + boundary + RFC-4514 escape (P2/P3) | adsearch.psm1 | Desktop AD-search bind guard | **CHECK** |
| 18 | CSV formula-injection: client toCsv + wpt snapshot (P2) | shell.js, wpt.psm1 | Desktop CSV exporters | **CHECK** |
| 19 | wpt bulk pools missing Test-WptHostReachable injection (P2) | wpt.psm1 | Desktop patch tool pool dispatch | **CHECK** |
| 20 | wpt maintenance-lock missing self-guard (P3) | wpt.psm1 | Desktop maintenance-lock (if present) | **CHECK** |
| 21 | kev add-kev write ungated -> destructive=$true (P3) | kev.psm1 | Web-only (server gate + Web-only tool) | **CLOSED-WEB-ONLY** (Web-only gate) |
| 22 | run-script wrong-box DNS-mismatch hard-abort (P2) | remoteadmin.psm1 | Desktop remote-exec / RunScript tool | **CHECK** |
| 23 | ReferralChasing=None on AD searchers (design) | adsearch.psm1 | Desktop AD-search searchers | **CHECK** |

## Phase-2 mandatory follow-ups (CHECK rows)
Rows 1-6, 8-11, 13, 15, 17-20, 22-23 require a Desktop-mirror pass: locate the equivalent code in
`JANET Desktop\Tools\`, and if the defect exists, fix it under Desktop versioning rules (new versioned
`Tools\` file, archive the old, update `JANET_Config.json` Script field, PS 5.1 + BOM, scoped commit). The
c2c field-script fixes (1-6, 8: mpam/PKI/Java/BitLocker/MDE/Defender-pin) are highest priority because those
scripts ORIGINATED in Desktop ("the four field ScanFix ports") and almost certainly still carry the same P2s.

## Web-only (closed, reasoned)
Rows 7, 12 (AD-TO is a net-new Web tool, no Desktop twin), 14 (XSS needs a browser DOM - Desktop has none),
16 (HTTP admin-session gate - Desktop has no server), 21 (add-kev gate is the Web server gate). None have a
Desktop code path to fix.

## Loop-3 Desktop-mirror attempt (C2C P2s -> C2CNemesisTool) - BLOCKED by concurrent WIP
Analyzed `C2CNemesisTool_2.4.1.ps1` against ledger rows 1-6/8. **Desktop has 5 of the 6 defects** (the field
scripts originated there): row 1 mpam gate (regex was UNANCHORED + no product-id), **row 2 PkiRdp - the tool
used the WRONG EKU (Client-Auth 1.3.6.1.5.5.7.3.2 instead of Server-Auth ...3.1), no HasPrivateKey, and
cleared the old listener before binding**, row 3 Java residue removed unconditionally (no Oracle/Sun gate),
row 4 BitLocker RESUME path had no escrow-first, row 6/8 no SHA256 pin (TOCTOU). Row 5 (MDE blob expiry) was
NOT present (new). A fixed `C2CNemesisTool_2.5.0.ps1` with all six mirrored from the Web c2c reference was
prepared and **parked at `X:\J.A.N.E.T\dev\proposed-security-mirror\C2CNemesisTool_2.5.0.ps1`** (parse-clean,
BOM).

**NOT COMMITTED - collision:** the Desktop repo has uncommitted work NOT authored by this loop - untracked
`Tools\C2CNemesisTool_2.4.0.ps1` + `_2.4.1.ps1` (a C2C version line in progress; committed config still points
to 2.3.0) and a 68-line uncommitted `dev\Sync-TakeToWork.ps1` edit. Per the hard rule (never merge over
concurrent work), the Desktop tree was RESTORED (2.4.1 un-archived, config reverted to 2.3.0) and nothing was
committed. Ledger rows 1-4, 6, 8 status -> **BLOCKED-DESKTOP-WIP** (defect confirmed present + fix prepared,
awaiting the owner to commit/reconcile the 2.4.x line, then land 2.5.0). Row 5 -> the Desktop tool lacks the
MDE path (the prepared 2.5.0 adds it as new). These remain OPEN in the ledger - not closed - until the Desktop
commit is unblocked.

## Loop-5 finding (NEW) - ACAS destructive actions can target the operator/dispatcher box -> CLOSED-BOTH
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 24 | ACAS schedule-reboot/kb-install/App-Update waves lacked a self-guard - could reboot/patch the JANET dispatcher (Web) or the operator's own workstation (Desktop) mid-run (P2) | acas.psm1 1.11.1: schedule-reboot + kb-install `Test-AcasHostIsSelf` drop; `Select-AcasNonSelfHosts` broadened to unconditional | YES - `ACAS Nemesis Tool` had 4 unguarded dispatchers | **CLOSED-BOTH** (Desktop 1.10.14: `Get-NemLocalIdentity`+`Test-NemHostIsSelf` drop in all 4, archived 1.10.13, config+JANET.ps1 repointed) |

## Loop-8 finding (NEW) - message `send` could WinRM-loopback and popup the dispatcher -> Web CLOSED, Desktop BLOCKED
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 25 | `message` send (destructive) had no dispatcher self-guard - a target resolving to this box would pop msg.exe on the JANET console host itself (WinRM loopback); last self-guard-parity gap in the suite (P3) | message.psm1 1.3.4 (`5699bfb6`): `Get-JanetMessageLocalIdentity`+`Test-JanetMessageHostIsSelf` drop self BEFORE fan-out, gated to `send`; ping stays self-inclusive; 7 tests | YES - loop-26 sweep CONFIRMED PRESENT: `RemoteMessageTool_1.3.3.ps1` `Get-Targets` (:1225) returns the raw list (no self-drop); `$btnSend.Add_Click` (:1858) fans out `Invoke-Command` per host (:1911) unfiltered | **DESKTOP-MIRROR-QUEUED** (Web closed; Desktop fix ready - drop self in `Get-Targets`/`$btnSend.Add_Click`; new versioned tool next cycle) |

## Loop-9 finding (NEW) - DN bind-redirect guard accepted a trailing control char -> Web CLOSED, Desktop folds into rows 11/17
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 26 | DN guard `Test-Ad{Search,To}DnInLocalDomain` used a `$`-anchored suffix match; .NET `$` also matches before a trailing newline, so `...DC=MIL\n` slipped past (not exploitable - suffix+DC-count pin still forces a local bind - but it is the security boundary from rows 11/17) (P3) | adsearch.psm1 3.3.6 + adto.psm1 0.2.1 (`2e6a4a55b`): reject `[\x00-\x1f]` before the anchor, all 3 byte-identical guard copies; `tests/AdDnGuard.ControlChar.Tests.ps1` (12) | Depends on the Desktop DN-guard existing first - rows 11/17 (adsearch/adto DN-guard) are themselves still CHECK/BLOCKED, so there is no Desktop guard yet to harden | **DEFERRED-INTO rows 11/17** (when the base DN-guard is mirrored to `ADSearchTool.ps1`, include this control-char reject; no standalone Desktop action) |

## Loop-10 finding (NEW) - history host-timeline input-validation parity -> Web CLOSED-WEB-ONLY
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 27 | history `host-timeline` validated the `host` input for non-empty only, while sibling `stale-hosts` gates on `^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`; read-only tool, value only reaches an in-memory short-name compare (non-exploitable) - a defense-in-depth consistency gap (P3) | history.psm1 1.0.2 (`c303351a4`): apply the same regex + warn on the host-timeline input | NO - `history` is a Web-only tool (a read-only Audit Explorer over the JANET audit trail / usage rollup); JANET Desktop has no equivalent | **CLOSED-WEB-ONLY** (Web-only tool, no Desktop twin) |

## Loop-11 finding (NEW) - reflected XSS in RunBar invalid-hostname guard dialogs -> Web fix, Desktop N/A
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 28 | RunBar host guard interpolated the invalid-hostname list `bad` into a confirm-dialog string body without `esc()`; `confirmdialog.js:57` assigns a string body via innerHTML -> a HOST_RE-failing token (operator-typed OR an imported ACAS/scan hostname CSV cell) like `<img src=x onerror=...>` fires on the run click. 7 occurrences / 1 root cause / 4 views (P2) | 4 non-colliding sites fixed `7bdc8dad4` via `bad.map(esc)` (mirrors dhcp.view.js:352): beta.view.js:113, biosfirmware.view.js:79, secureboot.view.js:104+177; node --check clean, suite 822 | NO - browser-DOM innerHTML sink; JANET Desktop has no web UI/DOM (same as row 14 dhcp XSS) | **CLOSED-WEB-ONLY** (no Desktop DOM) |
| 29 | Same XSS pattern, 3 more occurrences in certdeploy.view.js RunBar guards | FIXED (loop25): all 3 invalid-hostname guards now `bad.slice(0,5).map(esc).join(', ')` - landed with the PKI-boxes feature once the operator directed the certdeploy WIP be committed | NO - browser-DOM sink, Web-only | **CLOSED-WEB-ONLY** (no Desktop DOM) |

## Loop-12 finding (NEW) - server layer audited GREEN; one P3 fail-fast hardening -> Web-only
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 30 | Server token gate is fail-closed, but a Mandatory `[string]$Token=''` makes every request 403 silently (server up-but-dead) rather than failing at launch (P3, operability/latent-trap - NOT a bypass; spot-verified the gate cannot be tricked open) | Server.ps1 (`d4e08e26d`): `throw` at server start if `[string]::IsNullOrEmpty($Token)`, before any listener setup | NO - JANET Desktop has no HTTP server / listener / token (same as row 16, the fail-closed admin gate) | **CLOSED-WEB-ONLY** (no HTTP server in Desktop) |

## Loop-18 finding (NEW) - c2c Patches fix success under-reported in the host rollup -> Web CLOSED, Desktop deferred
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 31 | c2c per-host status rollup counted only FIXED/STARTED as a fix, omitting the Patches success token KICKED, so a lone successful fix-patches reported host Status 'NO CHANGE' + audited Skipped/0 while the sibling per-pillar tally counted it fixed - result-honesty bug on a quarantine pillar's success path (P2, safe direction - never a false success) | c2c.psm1 1.15.1 (`54f3432`): add KICKED to the :2292 fixed-class filter, aligning it with :3012 | YES - loop-26 sweep CONFIRMED PRESENT in `C2CNemesisTool_2.4.2.ps1` `$script:C2cFixBlock` rollup (:3424): `$fixed` counts only FIXED/STARTED, omits KICKED (label map :3457 confirms Patches->KICKED); the sibling per-pillar tally (:4979) already has KICKED (partial port) | **DESKTOP-MIRROR-QUEUED** (Web closed; one-line fix ready at :3424 - `$_.Result -in @('FIXED','STARTED','KICKED')`; land in the next C2C version bump) |

## Loop-19 findings (NEW) - acas correctness: false-green UNCONFIRMED row + reboot-selected empty-filter -> Web CLOSED, Desktop deferred
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 32 | acas update-row verdict rendered `UNCONFIRMED` (async Chrome/Edge/Office /ua, version unchanged in-session) as a green `OK`, contradicting `AcasOkOf` (which excludes it from the count) + the audit - a false per-row "verified" on the common patch path (P1, bounded: aggregate count/audit stayed honest) | acas.psm1 1.11.2 (`7969703`): add an `UNCONFIRMED` branch to both row builders (:2131,:2937); `tests/Acas.RowVerdict.Tests.ps1` (5) | NO - loop-26 sweep verified `ACAS Nemesis Tool_1.10.14.ps1` has NO `UNCONFIRMED` token; the async case is a suffix on `$resultStr` and the SAME `$resultStr` drives BOTH row render (:6687-94/:8264-72) AND audit/count (`-like 'FAIL*'`) - one source of truth, so the green-row/failed-audit SPLIT is structurally impossible there | **CLOSED-WEB-ONLY** (Desktop shares one source of truth for row+audit; the split can't occur) |
| 33 | acas `reboot-selected` applied its host-subset filter only `if allow.Count -gt 0`, so a non-empty filter whose tokens all canonicalize to empty reverted to the FULL group host union - a destructive reboot of every affected host, not the intended subset (P2, empty-set-as-all) | acas.psm1 1.11.2 (`7969703`): apply the intersection unconditionally when `hosts` is provided (parity with the correct patch-selected sibling), so empty -> No-targets return | NO - loop-26 sweep: the Desktop `ACAS Nemesis Tool` has NO reboot host-subset filter feature (`Start-NemRebootRun` :6790 always dispatches the whole affected-host group `@($Vuln.Hosts)`); there is no pick-a-subset filter that could canonicalize to empty and expand to ALL. (It also already has a v1.10.14 `Test-NemHostIsSelf` self-guard on reboot.) | **CLOSED-WEB-ONLY** (no subset-filter feature in Desktop; defect can't occur) |

## Loop-20 finding (NEW) - wpt reboot self-guard missing on 3 reboot-capable actions -> Web CLOSED, Desktop deferred
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 34 | wpt applied the dispatcher self-guard (`Remove-WptSelfTargets`) on reboot/reboot-schedule/fix-java but NOT on 3 other reboot-capable actions, so a target list incl. the JANET dispatcher could reboot the HttpListener box: bulk-patch FORCED (CCM reboot-if-needed, MID-DISPATCH - **P1**), registry-key-apply reboot-after (~1h shutdown /r /f on self - P2), kb-install reboot-enabled (MSU/wusa no /norestart - P2) | wpt.psm1 6.6.1 (`8b4cdf2`): drop the dispatcher before fan-out in all 3, gated to the reboot-capable sub-mode; 3 regression tests in Wpt.SelfGuardAndClean | YES - loop-26 sweep CONFIRMED the Desktop `WorkstationPatchingTool` had ZERO self-guard on all 4 reboot-capable actions | **CLOSED-BOTH** (Desktop `WorkstationPatchingTool_6.5.26` (`56193af7`, loop26): `Get-WptLocalIdentity`+`Test-WptHostIsSelf` drop self before all 4 reboot-capable dispatches [Reboot Selected / Scheduled / KB-with-reboot / STIG reboot-after]; archived 6.5.25, config repointed) |

## Loop-21 findings (NEW) - reports campaign-verify false-closes an unscanned host + host-key collision -> Web CLOSED (P1), Desktop deferred
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 35 | reports `campaign-verify` treated a campaign host ABSENT from the fresh scan as scan-confirmed REMEDIATED, then persisted `verified-closed` - a still-open vuln on an unscanned host (offline / scoped export) silently dropped off compliance (**P1**, closure false-positive) | reports.psm1 2.14.17 (`7e65664`): add `$hostsPresent`; an absent-host key -> NOT-SCANNED state, never remediated, blocks verified-closed; Reports.Campaign V1/V2 corrected + new V3 regression | MAYBE - the Desktop `ReportsTool_2.14.7.ps1` shares the reports feature set and may have the same campaign/closure verify; check its absent-host handling when Desktop is unblocked | **CLOSED-WEB / DESKTOP-DEFERRED** (operator status-quo on the Desktop mirror) |
| 36 | `Get-ReportsAuditHostKey` folds any non-IP name to its pre-dot short name, so two distinct hosts sharing a short NetBIOS name across domains/bases (`web01.us` vs `web01.eu` -> `WEB01`) collide in closure/compare/campaign (P2, deliberate FQDN/short fold - needs a key-model change + full test sweep, its own cycle) | NOT fixed - documented; a correct fix (IP discriminator or 2-label fold) is a cross-cutting key-model change | MAYBE - Desktop ReportsTool likely uses the same short-name key | **OPEN-WEB (own cycle) / DESKTOP-DEFERRED** |
| 37 | reports `Build-CoraSummary` counts unique hosts by RAW hostname (no key normalization), so a mixed FQDN/short export double-counts a host (inflated UniqueHosts, deflated VPH) - shifts denominators, not closure (P3) | NOT fixed - documented; cheap fix (normalize via Get-ReportsAuditHostKey) deferred as low-value | MAYBE - Desktop ReportsTool | **OPEN-WEB (low value) / DESKTOP-DEFERRED** |

## Loop-23 finding (NEW) - remoteadmin case-sensitive target dedup -> Web CLOSED
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 38 | remoteadmin `Get-RemoteAdminTargets` used case-SENSITIVE `Select-Object -Unique`, so host1/HOST1 both survived and the arbitrary operator block would run TWICE on the same host (double side effects) (P3) | remoteadmin.psm1 1.0.1 (`2a6f7dc`): order-preserving HashSet(OrdinalIgnoreCase) dedup; regression test | NO - JANET Desktop has no arbitrary-remote-script tool (RemotePackageInstaller/RemoteRestartScheduler are purpose-specific, not a run-script equivalent) | **CLOSED-WEB-ONLY** (no Desktop run-script twin; minor P3) |
