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
