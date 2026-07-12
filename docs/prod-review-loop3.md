# Production Review - Loop 3 (Phase 2, cycle 1) - 2026-07-12

First Phase-2 audit after the Experimental->production merge completed (loop 2). Changed surface = the whole
merge: 9 hardened source files, 2 new tools (adto, winrmbridge), the fail-closed gate now over prod's 22-tool
set. 4 reviewers: (A) fail-closed gate x prod tools [Opus], (B) the 2 new tools in prod context [Opus],
(C) merged-fix coherence on prod's real code paths [Sonnet], (D) full re-verify + suite [Opus]. Every P2/P3
spot-verified.

**Rating: GREEN.** No P1, no P2. The merge introduced no regression and no hole. One pre-existing P3 advisory
(not a merge product). 22/22 tools load, registry valid, all changed files parse clean, **full suite 739/0**.

## What was verified
- **Fail-closed gate is inert against the current registry (no regression, no hole).** All ~160 actions
  across all 22 tools carry an EXPLICIT `destructive` boolean - zero absent - so the new default-deny never
  fires on a current action: no read-only workflow was newly gated (P2 regression = NONE), and every
  install/reboot/uninstall/remote-write/arbitrary-exec action is `destructive=$true` and gated (P1 hole =
  NONE). The gate only protects FUTURE unflagged actions. Gate logic + acas by-id handling confirmed at
  `server/JanetWeb.Server.ps1:737-747`.
- **The 2 new tools (adto, winrmbridge) are sound in production.** Destructive flags correct (adto fix/
  validate-iao=$true, winrmbridge enable/revert=$true -> gated); adto DN-guard wired + RFC-4514 escape-aware
  before every credentialed bind, no `/`-form or serverless-foreign-DC bypass, ReferralChasing=None;
  winrmbridge self-guard (`Test-WinRmBridgeSelfTarget`) before every CimSession, host-token charset gate,
  static here-string payloads (no operator-string interpolation); both views interpolate only integers/static
  keys into the one raw-HTML sink, remote strings go to the textContent grid (no XSS); no missing-dependency
  runtime gap.
- **All 6 c2c P2 fixes + the merged guards are CONFIRMED-LIVE on prod's real code paths** (not dead code): mpam
  gate called admin-side before any host is dialed + TOCTOU re-hash before Start-Process; PkiRdp EKU-first +
  bind-before-clear; Java vendor gate + strict-GUID msiexec; BitLocker escrowFirst fail-closed before every
  Enable/resume; MDE blob expiry advisory; adsearch DN-guard called + ReferralChasing on all 6 searchers; wpt
  Protect-WptCsvCell + pool injection + maintenance self-guard; remoteadmin wrong-box abort between session
  and Invoke-Command; server gate; shell.js toCsv + dhcp esc(). No dangling cross-port references.
- **22/22 tools Import + manifest OK, `tool-registry.json` valid (20 original + adto + winrmbridge), all
  changed PS/JS parse clean, full Pester 739/0.**

## P3 (advisory - documented, pre-existing, NOT a merge regression, NOT fixing this cycle)
**wpt `healer-trigger-checkin` / `kb-trigger-mecm` / `kb-push-download` run ungated (`destructive=$false`) yet
issue remote MECM WMI `SMS_Client.TriggerSchedule` cycle-nudges** (schedule GUIDs ...113/114/108/021/022).
They issue no DIRECT install/reboot; the authors deliberately drew the destructive line at the direct
`CCM_SoftwareUpdatesManager.InstallUpdates` call (`kb-install`=$true). Internally consistent and unchanged by
the merge (ungated before it too). Residual: triggering assignment-evaluation (114) CAN cause a client to
install a past-deadline update, so there is indirect state-change potential. Accepted design line for now -
flagged for a conscious confirm-decision; gating them would add friction to routine scan/checkin workflows and
would be *tightening* an existing intentional boundary, not closing a merge regression. Ledger row added.

## Verdict
The merge landed clean on all axes it was meant to guard. No fix required this cycle. Proceeding to the
Desktop-parity mirror (ledger backlog: c2c P2s -> C2CNemesisTool first) and the pre-assigned Cycle-1 design
(Java-fix-into-WPT).
