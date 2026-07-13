# Production Review - Loop 22 (Phase 2, cycle 20) - 2026-07-13

Both real backlogs remain operator-deferred (status-quo, loop 13). The big-tool deep-correctness sweep is
complete (c2c/acas/wpt/reports, 4-for-4). This cycle closed a KNOWN-OPEN ledger item instead of a fresh
audit: ledger row 13 (upr dispatcher self-guard) had been CHECK/"port deferred" since the merge (a broken
port that called an undefined `Test-UprHostIsSelf` was reverted). Non-colliding; upr is committed.

**Rating: GREEN.** One known-open self-guard gap closed on a destructive tool. Suite 882/882.

## FIXED - upr uninstall dispatcher self-guard (commit fbbdd94, closes ledger row 13 Web side)
UPR's two destructive actions - `report-uninstall` and `manual-uninstall` - PERMANENTLY remove software
from each target over WinRM. upr had the DNS-mismatch hard-abort (stops acting on the WRONG remote host)
but NO dispatcher self-guard, so an operator who listed the JANET host itself (correct DNS) would
uninstall software FROM THE BOX THIS LISTENER RUNS ON - it could strip software the dispatcher needs.
Every other destructive host-targeting tool (wpt/acas/c2c/message) already drops self before fan-out; upr
was the lone gap (P2 - a software uninstall, not an immediate self-reboot, but a real unintended
destructive action on the dispatcher).
- Added `Get-UprLocalIdentity` (cached case-insensitive HashSet: shortname/FQDN/all NIC IPv4/loopback) +
  `Test-UprHostIsSelf` (IPv4-literal-safe), self-contained. Drop self from BOTH uninstall waves BEFORE
  fan-out (short-circuits `total=0` if only the dispatcher was targeted); the read-only report-scan /
  manual-scan stay self-inclusive.
- upr 1.2.1 -> 1.2.2; `Test-UprHostIsSelf` exported; `tests/Upr.SelfGuard.Tests.ps1` (4: predicate
  self/loopback -> true, remote -> false [no over-drop]; manual-uninstall self-only dry-run -> total=0 +
  Self-guard warn, no fan-out).

## Self-guard parity - now complete across ALL destructive host-targeting tools
With upr closed, every destructive host-targeting engine in the suite drops the dispatcher before its
wave: restart, remoteadmin, winupgrade, secureboot, certdeploy, wpt (all 7 reboot-capable, loop20), acas,
c2c, message (loop8), winrmbridge, beta, pkginstall (wrong-box), adto (DN-guard), and now upr. The
loop-8 self-guard-parity sweep's one deferred item (upr) is closed.

## Verdict
The known-open upr self-guard gap (ledger row 13, open since the merge) is closed and regression-locked;
self-guard coverage across destructive tools is now complete. Open work all operator-deferred (certdeploy
XSS-3, Desktop-parity backlog incl. the new likely-shared UnsupportedProductRemediator self-guard, the
reports host-key own-cycle item, certdeploy owner P2). Suite 882/882.
