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
| 1 | mpam offline Defender gate: Authenticode+MS-signer+product-id+50MB (P2) | c2c.psm1 | Desktop had sig/signer/size but NO product-identity check | **CLOSED-BOTH** (C2CNemesisTool 2.4.4 `472daff4`, loop28: `Test-C2cDefenderPackage` now also requires OriginalFilename~mpam OR ProductName~antimalware\|defender) |
| 2 | PkiRdp Server-Auth EKU + HasPrivateKey + bind-before-clear (P2) | c2c.psm1 | YES - Desktop 2.4.3 used the WRONG EKU (Client-Auth ...3.2), no HasPrivateKey, cleared before bind (spot-verified) | **CLOSED-BOTH** (2.4.4 `472daff4`, loop28: Server-Auth EKU ...3.1 + HasPrivateKey + bind-FIRST; clears run only on a successful bind) |
| 3 | Java vendor gate (Oracle/Sun-only) + strict-GUID msiexec (P2) | c2c.psm1 fix-java | YES - loop-28 sweep verified `C2CNemesisTool_2.4.3` Java block (:3216-3239) is IDENTICAL to Web: `Publisher -match '(?i)oracle|sun microsystems'` gate + `msiexec /x` only on `^\{[0-9A-Fa-f-]+\}$` strict-GUID; non-GUID entries marked MANUAL (never auto-run) | **CLOSED-BOTH** (already correct in Desktop - no change needed; verified loop28) |
| 4 | BitLocker resume escrow-first, key never leaked (P2) | c2c.psm1 | YES - Desktop Enable path was hardened but the RESUME path could resume into TPM-only unescrowed | **CLOSED-BOTH** (2.4.4 `472daff4`, loop28: resume now escrows via `$escrowFirst` BEFORE Resume-BitLocker, SKIPs if escrow fails; recovery password never emitted) |
| 5 | MDE onboarding blob expiry advisory (P2) | c2c.psm1 | YES - Desktop MdeOnboard path existed but had NO blob-cert expiry check | **CLOSED-BOTH** (2.4.4 `472daff4`, loop28: parses the blob cert, emits an IN PROGRESS advisory when NotAfter is past) |
| 6 | Offline Defender SHA256 validate->push pin (P3->design) | c2c.psm1 | YES - Desktop ran mpam-fe.exe unverified after copy (TOCTOU), no SHA256 | **CLOSED-BOTH** (2.4.4 `472daff4`, loop28: SHA-256 pin computed admin-side, threaded to the worker, re-hashed on target before exec; fail-closed on missing/mismatch) |
| 7 | adto FIX/IAO buttons dead - isRunning() (P3) | adto.view.js | AD-TO is a Web-only tool (no Desktop twin) | **CLOSED-WEB-ONLY** (Web-only tool) |
| 8 | SHA256 pin fail-closed on empty + -LiteralPath x2 (P3) | c2c.psm1 | YES - same offline-Defender push as row 6 (fails open, -Path globbing) | **CLOSED-BOTH** (2.4.4 `472daff4`, loop28: `-not $ExpectHash` -> NOT executed [fail-closed on empty]; Copy-Item/Remove-Item switched to -LiteralPath) |
| 9 | Self-guard case-sensitivity: `return ,$set` HashSet (P2) | 11 identity helpers | Desktop self-guard helpers (if present) | **CHECK** |
| 10 | Per-NIC try/catch in identity enumeration (P3) | 11 identity helpers | Desktop NIC-enumeration self-guard | **CHECK** |
| 11 | adsearch SearchBase LDAP bind-redirect (P1) | adsearch.psm1 | Desktop AD-search tool `SearchBase` bind | **CHECK** |
| 12 | adto fix/validate credentialed dn bind-redirect (P1) | adto.psm1 | AD-TO Web-only tool | **CLOSED-WEB-ONLY** (Web-only tool) |
| 13 | upr manual-uninstall (+report-uninstall) missing dispatcher self-guard - could uninstall software from the JANET box itself (P2; the merge reverted a broken port) | upr.psm1 1.2.2 (`fbbdd94`, loop22): `Get-UprLocalIdentity`+`Test-UprHostIsSelf`, drop self before BOTH uninstall fan-outs; scans stay self-inclusive; `tests/Upr.SelfGuard.Tests.ps1` (4) | YES - `UnsupportedProductRemediator_1.1.4` uninstall had only a DNS-mismatch guard, no self-drop | **CLOSED-BOTH** (Desktop `UnsupportedProductRemediator_1.1.5` (`f14911fa`, loop27): `Get-UprLocalIdentity`+`Test-UprHostIsSelf` drop self before the `$btnUDoIt` uninstall fan-out; scan untouched, DNS-guard intact; archived 1.1.4, config repointed) |
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
| 25 | `message` send (destructive) had no dispatcher self-guard - a target resolving to this box would pop msg.exe on the JANET console host itself (WinRM loopback); last self-guard-parity gap in the suite (P3) | message.psm1 1.3.4 (`5699bfb6`): `Get-JanetMessageLocalIdentity`+`Test-JanetMessageHostIsSelf` drop self BEFORE fan-out, gated to `send`; ping stays self-inclusive; 7 tests | YES - `RemoteMessageTool_1.3.3` send fanned out unfiltered (no self-drop) | **CLOSED-BOTH** (Desktop `RemoteMessageTool_1.3.4` (`f14911fa`, loop27): `Get-MsgLocalIdentity`+`Test-MsgHostIsSelf` drop self in `$btnSend.Add_Click` only - `Get-Targets` is shared with the read-only Ping All so it stays self-inclusive; archived 1.3.3, config repointed) |

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
| 31 | c2c per-host status rollup counted only FIXED/STARTED as a fix, omitting the Patches success token KICKED, so a lone successful fix-patches reported host Status 'NO CHANGE' + audited Skipped/0 while the sibling per-pillar tally counted it fixed - result-honesty bug on a quarantine pillar's success path (P2, safe direction - never a false success) | c2c.psm1 1.15.1 (`54f3432`): add KICKED to the :2292 fixed-class filter, aligning it with :3012 | YES - `C2CNemesisTool_2.4.2` `$script:C2cFixBlock` rollup (:3424) counted only FIXED/STARTED, omitting KICKED | **CLOSED-BOTH** (Desktop `C2CNemesisTool_2.4.3` (`f14911fa`, loop27): rollup now counts KICKED alongside FIXED/STARTED; archived 2.4.2, config repointed) |

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

## Loop-29 (operator request) - BitLocker FVE (GPO) policy asserted on EVERY path -> CLOSED-BOTH
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 39 | The v7.11 GPO fix (`Set-FvePolicy` - assert the 24 `HKLM\SOFTWARE\Policies\Microsoft\FVE` values that unblock Enable-BitLocker + force AD/Entra recovery-key escrow) was scoped to the ENABLE path only; an already-encrypted or suspended-then-resumed box did NOT get its scanner-flagged FVE GPO values healed. Reference `BitLocker-TPM-ScanFix v7.11` runs Set-FvePolicy unconditionally at the top, before any BitLocker cmdlet (parity gap, operator-raised) | c2c.psm1 (loop29): moved one memoized `& $assertFve` above the per-volume loop so the GPO policy heals on ALL paths (already-On / in-progress / resume / enable); the destructive ENABLE still fail-closes on a policy-write failure and heal/resume paths note the FVE result; `C2c.Enable.Tests.ps1` 3 SKIP-path tests updated to assert policy IS healed (Add/Enable still uncalled) | YES - exact same `$assertFve`-in-enable-branch scoping | **CLOSED-BOTH** (Desktop `C2CNemesisTool_2.4.5`: same move above the volume loop; archived 2.4.4, config repointed; 24 FVE values byte-identical to the reference) |

## Loop-29 Desktop-parity sweep (rows 9,10,15,17-20,22-23 verdicted) - actionable findings for next cycles
A read-only Sonnet sweep verdicted the remaining CHECK rows against the current committed Desktop tools. Results feeding subsequent loop cycles (NOT yet landed):
- **Row 9 (`return ,$set`) - PRESENT, real fail-open (not the assumed already-fixed):** all 5 `Get-*LocalIdentity` helpers (WPT 6.5.26, ACAS 1.10.14, upr 1.1.5, message 1.3.4, c2c) use a bare `return $set`, collapsing the OrdinalIgnoreCase HashSet to a case-SENSITIVE `Object[]` -> a case-mismatched dispatcher name would not self-match. `RemoteRestartScheduler_1.6.1` has the identical bug. Fix: `return ,$set` (+ cache-hit return) in all.
- **Row 10 (per-NIC try/catch) - PRESENT (robustness):** 4 helpers wrap the whole NIC loop in one try/catch (one bad NIC drops all later NICs' IPs); nest the try INSIDE the foreach. ACAS has no NIC block (N/A).
- **Row 22/38 CORRECTION - PRESENT, newly identified live RCE feature:** WPT 6.5.26 App Updater "Custom Command" (`btnAU2Apply`/`$wrapperSb` ~11157-11331) runs operator-typed PowerShell via `Invoke-Command` against every selected host with NEITHER a self-guard NOR the wrong-box DNS check that already exists elsewhere in the same file (6227/7216). Highest-severity sweep finding - this is a Desktop run-script twin after all.
- **Row 18 (CSV formula-injection) - MIXED/PRESENT:** ADSearchTool (`Export-BulkCSV`/`Export-BaseUsersCSV`) and WPT (Software/KB/BulkScan exports) have NO `=+-@` neutralizer; ReportsTool 2.14.7 has `Protect-CsvFormula` but `Export-OtherVulnCsv`/`Export-Dirty30Results` bypass it. Port the helper + thread through untreated cells.
- **Row 23 (ReferralChasing=None) - PRESENT (design/P3):** 5 ADSearchTool searchers unset. **Row 17 (DN-guard) - ABSENT (no SearchBase input surface in Desktop; structurally N/A).** **Rows 2/15/5a/5b/20 - ALREADY-FIXED or ABSENT** (WindowsUpgradeTool guard correctly reboot-scoped; WPT pools use inline probes by design; no WPT maintenance-lock feature).

## Loop-30/31 (operator feature) - Spectre/BHI (CVE-2022-0001) check+enable into WPT + ACAS -> CLOSED-BOTH
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 40 | No automated remediation for CVE-2022-0001 (Intel BHI) - a recurring Tenable/ACAS finding (plugin 302873). Operator asked for a check + one-click enable in WPT and ACAS (feature, not defect) | NEW shared engine `JanetWeb.specfix.psm1` (pool-injectable, same contract as javafix): `Get-JanetSpecExecState` (COMPLIANT/DRIFT/VULNERABLE) + `Invoke-JanetSpecExecRemediation`. WPT 6.6.2 (`5f37f17`): `spec-exec-scan` (read-only) + `spec-exec-enable` (destructive, self-guarded via Remove-WptSelfTargets BEFORE fan-out, confirm-gated, fail-closed). ACAS 1.11.3 (`5f37f17`): profile `Spectre/BHI Mitigation - Enable (CVE-2022-0001)` (NeedsSpecFix + ForbidSelf), CVE-2022-0001/Spectre/BHI match rule | YES - both tools exist in Desktop | **CLOSED-BOTH** (see rows 41/42) |
| 41 | **CORRECTION** - the loop-30 engine wrote FeatureSettingsOverride=0 FLAT (Microsoft runtime-enable). The Desktop WPT reference (RegKeyFixCatalog['BHI'], v6.5.20, 43-host fleet evidence) proved a flat write does NOT clear Tenable 302873 and STRIPS the BHI bit. **My Web engine had the exact bug Desktop already fixed.** | specfix engine rewritten (`6f663e0`): ENABLE ORs the BHI bit **0x00800000** INTO the existing FeatureSettingsOverride (preserves Spectre/Meltdown posture bits 0x48/0x2048), Mask=3, reads back, FIXED only on a COMPLIANT readback. Verdict COMPLIANT/DRIFT/VULNERABLE (OR-based). WPT tests rewritten (stateful shimmed registry + preserve-bits case). Suite 940/940. | Desktop WPT was ALREADY correct | **CLOSED-BOTH** (Web now matches the fleet-proven Desktop logic; operator-approved OR-0x800000 strategy) |
| 42 | Desktop WPT `RegKeyFixCatalog['BHI']` already does the correct OR-0x800000 scan+apply+reboot (Reg Key Fixes tab); Desktop ACAS force-classified CVE-2022-0001 as info-only 'Unpatchable' (no Run button) | n/a (Desktop-side) | **WPT: already present** (no change - would duplicate the existing BHI remediation). **ACAS: added** `ACAS Nemesis Tool_1.10.15` (`a03058d8`): the same OR-0x800000 enable profile + Verify, carved 'Speculative Execution'/'Intel BHI'/'Spectre' out of `$unpatchPatterns` so the finding reaches Patchable (Run+Verify); kept Oracle Database/Meltdown/ZombieLoad unpatchable | **CLOSED-BOTH** (WPT already-ahead; ACAS mirrored). Edge: a plugin name with BOTH a kept token AND a BHI token stays Unpatchable (first-match-wins; defensible - needs microcode) |

## Loop-32 (operator feature) - Windows Upgrade tool: OS Version audit rule + HTTPS fleet installer -> CLOSED-BOTH
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 43 | Windows Upgrade scan had no OS Version AUDIT rule (operator: pass/fail on Win11 + 24H2+ + Enterprise, no partial) | winupgrade 0.5.0 (`2047a43`): `os-audit` action - Gen11 (build>=22000) + Rel24H2 (build>=26100) + EntEdition (EditionID EXACTLY 'Enterprise'); PASS only if all three, else FAIL + failing-check list; read-only/self-inclusive. Tests: full verdict matrix | YES | **CLOSED-BOTH** (`WindowsUpgradeTool_0.5.0` `45ed5a51`: OsAudit op, same 3 checks inline, smoke-tested 26100/Ent=PASS, Pro/23H2/Win10/EnterpriseS all FAIL) |
| 44 | Operator asked to add the HTTPS installer (`X:\References\HTTPS_Installer.ps1`) as a clickable action | winupgrade 0.5.0 (`2047a43`): `install-updates` action - transport cascade WinRM HTTPS 5986 -> HTTP 5985 -> WMI/DCOM 135, JANET_WUA SYSTEM scheduled task driving the ported WUA COM driver, optional Microsoft Update, result.json poll; destructive + confirm + **self-guarded** (drop self BEFORE fan-out - installs+reboots); ResultCode->Status never fakes success. PILOT-PENDING (live WSUS). Tests: manifest/confirm/self-guard/result.json round-trip | YES | **CLOSED-BOTH** (`WindowsUpgradeTool_0.5.0` `45ed5a51`: InstallUpdates op, same cascade + WUA driver + SYSTEM task; self-guard joins the reboot-capable drop-self set; arg-order verified; PILOT-PENDING WMI/DCOM bootstrap noted) |

## Loop-33 audit hardening (rows 40-44 follow-ups) -> CLOSED-BOTH
The loop-33 adversarial audit of THIS session's new code (prod-review-loop33.md, YELLOW - no P1/security
hole, zero regressions) found and fixed:
| # | Finding (sev) | Web fix | Desktop | Status |
|---|---------------|---------|---------|--------|
| 45 | ACAS spec-exec profile UNREACHABLE on the auto-patch path - the `$unpatchPatterns` carve-out shipped to Desktop 1.10.15 was never applied to Web (Unpatchable classify runs before the match table) (P2, feature-breaker) | acas.psm1 `365e03c`: carved 'Speculative Execution'/'Intel BHI'/'Spectre' out of `$unpatchPatterns` -> parity with Desktop | already carved in 1.10.15 | **CLOSED-BOTH** |
| 46 | install-updates WMI/DCOM stale-`result.json` race -> false Installed + no wrong-box guard (P2) | winupgrade 0.5.1 `bab69ab`: driver stamps per-run Nonce + Host=COMPUTERNAME; worker rejects nonce mismatch (keeps polling) + Host mismatch (WrongBox, Ok=$false); stale file deleted up front. Verified: no path to a false Installed. +7 tests | `WindowsUpgradeTool_0.5.1` `b3d445e8`: same nonce/Host reject | **CLOSED-BOTH** (live WMI/DCOM PILOT-PENDING) |
| 47 | install-updates left JANET_WUA SYSTEM task + driver.ps1 + result.json on every target (P3) | winupgrade 0.5.1 `bab69ab`: Unregister-ScheduledTask + remove files after harvest, both transports (best-effort) | `0.5.1` `b3d445e8`: same | **CLOSED-BOTH** |
| 48 | Desktop WindowsUpgradeTool `Test-HostIsSelf` self-guard IP hole - matched only loopback + shortname, not bound NIC IPs -> pasting the tool host's own IP as an install target bypassed the guard (P2, Desktop-only) | Web `Get-WinUpgradeLocalIdentity` already enumerated bound IPs (no defect) | `0.5.1` `b3d445e8`: ported `Get-JanetLocalIdentity` (COMPUTERNAME/FQDN/resolved IPs/bound IPv4/loopback) into Test-HostIsSelf; smoke-tested own IP -> True | **CLOSED-BOTH** (Web was already clean; Desktop closed) |
| 49 | `[int]$fso/$mask` cast could throw on an exotic REG_SZ/QWORD FeatureSettingsOverride (P3, fail-closed today) | specfix.psm1 + acas.psm1 Verify `bab69ab`: guarded cast -> non-numeric treated absent -> VULNERABLE | ACAS `1.10.16` `b3d445e8`: same guard in readState + Verify | **CLOSED-BOTH** |
