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
| 13 | upr manual-uninstall missing self-guard (P1) | upr.psm1 | Desktop UPR uninstall (Web upr has no self-guard yet - port deferred) | **CHECK** |
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
| 25 | `message` send (destructive) had no dispatcher self-guard - a target resolving to this box would pop msg.exe on the JANET console host itself (WinRM loopback); last self-guard-parity gap in the suite (P3) | message.psm1 1.3.4 (`5699bfb6`): `Get-JanetMessageLocalIdentity`+`Test-JanetMessageHostIsSelf` drop self BEFORE fan-out, gated to `send`; ping stays self-inclusive; 7 tests | YES - `RemoteMessageTool_1.3.3.ps1` is the exact twin and shares the gap | **BLOCKED-DESKTOP-WIP** (Desktop tool is one of 19 files the concurrent Live-Usage Snapshot sync is live-rewriting; versioning it would collide - mirror deferred until `X:\J.A.N.E.T` is clean. 3rd consecutive cycle blocked) |

## Loop-9 finding (NEW) - DN bind-redirect guard accepted a trailing control char -> Web CLOSED, Desktop folds into rows 11/17
| # | Finding (sev) | Web fix | In Desktop? | Status |
|---|---------------|---------|-------------|--------|
| 26 | DN guard `Test-Ad{Search,To}DnInLocalDomain` used a `$`-anchored suffix match; .NET `$` also matches before a trailing newline, so `...DC=MIL\n` slipped past (not exploitable - suffix+DC-count pin still forces a local bind - but it is the security boundary from rows 11/17) (P3) | adsearch.psm1 3.3.6 + adto.psm1 0.2.1 (`2e6a4a55b`): reject `[\x00-\x1f]` before the anchor, all 3 byte-identical guard copies; `tests/AdDnGuard.ControlChar.Tests.ps1` (12) | Depends on the Desktop DN-guard existing first - rows 11/17 (adsearch/adto DN-guard) are themselves still CHECK/BLOCKED, so there is no Desktop guard yet to harden | **DEFERRED-INTO rows 11/17** (when the base DN-guard is mirrored to `ADSearchTool.ps1`, include this control-char reject; no standalone Desktop action) |
