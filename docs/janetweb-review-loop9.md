# JANET Web — review loop 9 (2026-07-20)

**Baseline:** 1091/1091 at loop-8 close (`a415ec2`); tree untouched between loops
(baseline re-run confirms). Local-only commits.

## Opus adversarial self-review of loop-8 (`fb7611f` c2c escrow-orphan fix) — verdict GREEN

Deeper pass than the loop-8 Sonnet mechanical sweep. All probed subtleties CLEAN:
`$beforeIds` is always in scope AND populated whenever the new cleanup runs (assigned before
`$weAdded=$true`, same `else` branch; the outer catch is unreachable once `$weAdded` is set
because the only statement after it is a swallowing inner try/catch). The resolved-id (common)
path is behaviorally byte-identical — relocating the `try` inward changes nothing since the
`if ($newKpId)` predicate can't throw. Cleanup re-read throw → still returns `Ok=$false` →
callers never reach Enable (fail-closed; worst case the orphan persists, never a false
success). Remoting-safe (no `$using:`, block-local vars, cmdlets resolve in the same remote
context). Test `bothfailblankid` non-vacuous (`{LATE-KP}` reachable ONLY via the new branch).
Even verified the Lockscreen floor assert parses correctly (member-access binds tighter than
the cast). One pre-existing/accepted P3 (concurrent-add window, identical to the add-time
diff). Nothing to fix.

## Opus adversarial deep-dive: wpt destructive engine (v6.8.2, the #1 tool) — verdict YELLOW

Scope: the destructive paths NOT reviewed in loops 1–3 (Install-KB, Custom Command, software
uninstall, clean-user-apps, maintenance, fan-out, app-action). Verified CLEAN with evidence:
uninstall-string decomposition reuses the safe upr pattern (no `cmd /c` on operator/CSV text;
strict-`{GUID}` before msiexec; real exit codes; the old fail-open `| Out-Null` is gone;
verify-and-clean re-reads); Install-KB normalizes `KB\d+`, MSU copied via `Split-Path -Leaf`
(no traversal), MECM ReturnValue checked; target-token allowlist
`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$` before any WinRM connect; fan-out creds in-memory only,
runspaces disposed, cancel honored; a thrown probe is never booked success (fail-closed);
Custom Command is intended authorized RCE and is otherwise well-built (SHA-256 + 200-char
forensic audit per host).

### The finding — self-guard gap — **FIXED this loop** (`aadab75`, wpt **6.8.2→6.8.3**)
- **F1 (P2):** `app-update-apply` (handler `JanetWeb.wpt.psm1:6349`) was the ONLY destructive
  dispatcher lacking `Remove-WptSelfTargets`. It runs the Custom Command profile (arbitrary
  remote PowerShell) and force-update/uninstall profiles. On the dispatcher the per-block
  wrong-box guard is a no-op (self dialed by its own correct name → no mismatch), so an
  operator `Restart-Computer` with the JANET host in the wave would kill the HttpListener
  mid-dispatch — self-guarded arbitrary RCE against the dispatcher.
- **F2 (P3, folded in):** `app-action` (SCCM Install/Uninstall/…) and `unsupported-uninstall`
  had the same gap. The inconsistency was sharp: `fix-java` IS self-guarded, yet
  `unsupported-uninstall` (which removes the SAME Oracle Java) was not.
Fix: all three drop the dispatcher BEFORE fan-out via the identical `Remove-WptSelfTargets`
block the other 8 destructive actions use (→ total 0 + Self-guard warn when only self was
dialed). unsupported-uninstall's guard is on the pairs-derived `$hostList` (the dispatcher's
`targets` gate is non-empty-only, not a self-guard).
- **F3 (P3, folded in):** `app-update-apply` was the one destructive action with no `confirm=`
  string; added one naming the arbitrary-PowerShell risk + the self-guard.
`app-update-verify` (read-only, `destructive=$false`) stays unguarded — no over-guard.
Regression `Wpt.SelfGuardApply.Tests.ps1` (9): each dispatcher emptied against a self-only
target (loopback + shortname), built-in profile also dropped, confirm string asserted, verify
sibling unchanged — all drive the real dispatcher, zero WinRM.

## SECRET parity
- SECRET parity: the 3 wpt self-guards + the app-update-apply confirm string — the JanetSec
  wpt fork has the same dispatchers and the same gap; mirror all three + the confirm.
- Carried (unexecuted): Host-header guard (+extended cases), report-preview CSP sandbox
  (+resource-free guard), wpt audit-Skipped, session disarm, honest Chrome/Edge + worker
  passthrough, upr refuse coverage + worker comment, c2c orphan-protector fix.
