# JANET Web + SECRET - Session Handoff (2026-06-28/29)

This documents a full working session on the two web-local JANET forks:
- **JANET Web** - `X:\JANET Web` (NIPR / AFNET; has SCCM/MECM). Git branch `main`, Gitea remote.
- **JANET SECRET** - `X:\shh-JANET` (SIPR / SECRET; NO SCCM/MECM/WSUS). Git branch `master`, **local-only (no remote)**.

Everything below is **committed locally** and **runtime-untested** - it needs validation on a real on-network (SIPR/AFNET) host before operational use. All code passed: PS 5.1 AST parse + UTF-8 BOM + ASCII-only body + `node --check`, and adversarial Opus review.

---

## 1. What shipped this session (in order)

### A. Light / dark theme (both forks)
- Sun/moon toggle in the top bar (next to the clock); choice persists in `localStorage['janet-theme']`; a no-flash inline script in `index.html` applies it before first paint. **Dark stays the default.**
- Mechanism: `web/css/janet.css` palette was already CSS custom properties; the ~22 hardcoded near-black fills/borders were tokenized (their dark values are unchanged, so the dark theme renders identically) and a purely-additive `[data-theme="light"]` block flips the whole palette. 2-pass adversarial review fixed a P1 (classification banner was white-on-pink/invisible in light) + the armed-CANCEL red stripes + sub-AA accent/status colors (all now >= WCAG AA).
- **Wave 1 follow-up:** per-tool views/components inlined their own colors; those were tokenized too (acas/dhcp/pkginstall/reports + activitylog/resultsgrid + the heartbeat dot). Fixed a real bug: TWO `upr.view.js` referenced NON-EXISTENT tokens `var(--bg2)/var(--fg)/var(--border)` whose hardcoded fallbacks always applied (its paste box never flipped). One literal kept on purpose: the `reports` report-preview popup window does not load `janet.css`, so `var()` can't resolve there.

### B. PIRS round-2 adoptions (the four chosen tiers)
From a 60-capability re-audit of the PSAB PIRS console (everything previously adopted verified intact):
- **Host Info enrichment** (both wpt): `quser` session state (Active / Idle Nm / AWAY >=15m / Disconnected) on the Logged-on-user row; `(LOW SPACE <30GB)` and `(REBOOT RECOMMENDED >5d)` flags.
- **Host-list exclude filter** (shared TargetManager): negative-substring filter -> mass actions receive the filtered set.
- **Conditional Restart** (both restart): opt-in `onlyIfPending` gate (probe CBS/WU/PendingFileRenameOperations over WinRM; default OFF; probes before hold/consent; fail-closed; audited Skipped).
- **Disk Cleanup deltas** (both wpt): added `SoftwareDistribution\Download`; C: free before/after delta (reported only when both snapshots captured).
- **TWO-only SCCM polish:** ccmsetup return-code -> plain-language table on healer-ccm-repair; new read-only `verify-patch` action (polls CCM_SoftwareUpdate EvaluationState, clamped, graceful no-op without SCCM) + a Verify Patch tab.

### C. Cross-tool improvement waves (98-finding audit -> Wave 2 = 46 quick-wins)
- **Audit integrity:** acas verify/dry-runs audit `TouchHost` not `VulnPatched`; acas `PARTIAL` classifies Failure (was masked Success); restart `verify-boottime` maps `Info` -> Skipped/Failure (`Info` was rejected by the audit ValidateSet); read-only Ping/os-findings stop auditing; wpt Custom-Command pre-run -> Skipped; upr uninstall host-audit de-duplicated.
- **AFNET reachability:** winupgrade + adsearch ICMP -> TCP 5985/445 over WinRM; reports Dirty-30 last-user probe DCOM -> CIM-over-WSMan.
- **Exclude-filter SAFETY:** restart / secureboot / biosfirmware were submitting the RAW textarea, so the new exclude filter was BYPASSED (excluded hosts were still rebooted / firmware-written / scanned). Now submit the filtered set; secureboot cap/status count the filtered set.
- **Robustness/UX:** dhcp timeouts + Cancel + CSV export + load-error surfacing; pkginstall per-host install-timeout + cancelled-MSI=Skipped; adsearch results filter + refusal banner + input parity + bounded reverse-DNS + SearchBase bind; reports STATUS column + correct banner + Mark-All-Visible + streamed-row de-dup; biosfirmware activity-log + error handler; beta truthful registry summary.

---

## 2. Commits this session

**SECRET (`X:\shh-JANET`, branch master, local-only):**
- `bc46416` theme  -  `2d89db9` PIRS r2  -  `283b151` theme-correctness (W1)  -  `12a4b6f` tools hardening (W2)

**TWO (`X:\JANET Web`, branch main):**
- `858c07e` theme  -  `c7a97a3` PIRS r2  -  `c4ca946` theme-correctness (W1)  -  `e3f69fe` tools hardening (W2)

Tool versions bumped: TWO wpt 6.5.28 / SEC wpt 6.5.27; TWO restart 1.5.0-beta6 / SEC restart 1.5.0-beta5.

---

## 3. Important caveats / watch-outs

- **Runtime-untested.** All changes are static-verified + reviewed; the remote-exec paths (WinRM, CIM, reboot/firmware/uninstall) need on-network validation.
- **Git sync:** SECRET has NO remote (local commits only). TWO has a Gitea remote (`100.119.34.30:3000/bth0mp/J.A.N.E.T-TWO`) but **push needs your token** - not pushed.
- **TWO has 3 pre-existing FOREIGN uncommitted files** left untouched on purpose (verified 2-day-old, not from this session): `modules/JanetWeb.beta.psm1`, `web/js/views/beta.view.js`, `web/js/help-content.js`. Review/commit them on their own merits.

---

## 4. Next: Wave 3 backlog (28 bigger items - in progress / next)

Highest priority: **`upr` "Uninstall Selected" ignores the operator's row selection** (re-scans and removes ALL proven candidates on ALL actionable hosts - both forks). Then: SECRET wpt fan-out per-host watchdog (port from TWO); wpt Bulk-Scan 6->1 WinRM round-trip consolidation; acas preflight RPC->WinRM+credential; restart+message ICMP->TCP; SECRET KB-scan Present/Missing verdict + compliance %; reports SECRET STATUS column/stream; SECRET upr paste-ingest; secureboot DCOM->WinRM; biosfirmware -> SECRET port; plus perf items. Full list + the raw audit JSON are referenced in the agent memory (`project-janet-improvements`).
