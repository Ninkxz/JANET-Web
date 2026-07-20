# JANET Web — review loop 10 (2026-07-20)

**Baseline:** 1100/1100 at loop-9 close (`8a2d6ad`); tree untouched between loops
(baseline re-run confirms). Local-only commits.

## Opus adversarial self-review of loop-9 (`aadab75` wpt self-guards) — verdict GREEN

Deeper pass. CLEAN: no over-guard (only the destructive APPLY is blocked; read-only
`app-update-verify` stays usable on self); `$totalUnits` rework arithmetically correct
(`$hostList` is a strict subset of `$byHost.Keys`, no KeyNotFound); guard placed before
job-array construction in all three; tests non-vacuous (the unsupported-uninstall test
reaches the REAL pairs guard, not the dispatcher `targets` gate); `confirm=` is
decorative-parity (the view builds its own dialog — no double-prompt). Two P3s: **N1**
(unsupported-uninstall self-only return omitted `selfSkipped`) — **fixed this loop**; N2
(Edge floor-assert now permits any ≥6.8.2) — acceptable, the newest file pins exact.

## Opus deep-dive: remoteadmin (Open C$ + Run Script, RCE surface) — verdict GREEN

Chosen as the natural follow-through to loop-9 (Run Script = the same arbitrary-remote-
PowerShell class as wpt Custom Command). Result: **remoteadmin is the REFERENCE
implementation** of the very protection loop-9 found missing in wpt — Run Script drops the
dispatcher via `Remove-RemoteAdminSelfTargets` BEFORE the runspace pool
(`JanetWeb.remoteadmin.psm1:383`), with a belt-and-suspenders identity set (name/FQDN/
loopback + every bound NIC IPv4), view-side typed-`RUN` confirm + `destructive:true` +
fail-closed server gate, wrong-box guard with correct IPv4 carve-out, strict token
allowlist, in-memory creds, SHA-256 forensic audit, uniformly fail-closed status. Open C$
is a correctly-flagged read-only Explorer launch with strict name validation. Already
thoroughly tested (RemoteAdmin.Tests.ps1, 40+ asserts incl. the multi-homed NIC-IP slip).
No fix needed. One cosmetic P3 (wrong-box IPv4 classifier accepts out-of-range octets like
`999.1.1.1`) errs safe and is shared by several tools' identical carve-out regex — skipped
(churn for zero security gain).

## Workstream: suite-wide self-guard-coverage audit → 3 genuine gaps fixed (`f4ab266`)

Sonnet swept EVERY tool's `destructive=$true` actions for the dispatcher self-guard,
extending the loop-9 finding. Raw result: 16 destructive fleet-fan-out actions without a
self-guard. **But the sweep over-reports** — the repo's self-guard philosophy (explicit in
`maintenance-lock` hardlock-only / `registry-key-apply` reboot-after-only / `bulk-patch`
forced-only comments) is HARM-DRIVEN: guard when acting on SELF would reboot, lock out, or
abort the dispatch, or install/remove software; leave benign-on-self actions unguarded so
the dispatcher can still self-heal/self-message. Applying that yardstick:

**3 GENUINE gaps (self-action is actually harmful) — FIXED:**
- `pkginstall` **deploy-psadt** + **deploy-msi-bundle** (v2.5.7→**2.5.8**): install a
  package (PSADT `Deploy-Application.ps1` / `msiexec /i`) on every target, with NO
  self-guard infra at all (only a wrong-box compare, which self passes). Installing
  arbitrary software on the JANET host (a package can reboot it) = the wpt-Custom-Command
  harm class. Added `Get-PkgInstallLocalIdentity`+`Test-PkgInstallHostIsSelf` (mirrors
  c2c/upr/remoteadmin) + an unconditional self-drop before the runspace pool.
- `wpt` **clean-user-apps** (v6.8.3→**6.8.4**): a LIVE clean deletes app binaries from
  every user profile — the harm class of the already-guarded `fix-java`/
  `unsupported-uninstall`, but unguarded. Guard the LIVE path only (dry-run on self is a
  harmless preview), mirroring `maintenance-lock` hardlock-only. Also corrected the loop-9
  comment falsely claiming app-update-apply was "the ONLY" unguarded dispatcher.

**13 benign-on-self, unguarded BY DESIGN (no change — documented so future sweeps don't
re-flag):** wpt `reboot-abort`/`winrm-bootstrap`/`healer-restart-ccm`/`healer-wmi-repair`/
`healer-wu-reset`/`healer-gpupdate`/`healer-ccm-repair`/`healer-rdp-rebind`/`remote-message`/
`cleanup-disk`/`maintenance-unlock`; acas `preflight-services` (sets services Running —
desirable on self); restart `abort-scheduled` (`shutdown /a` — cancels a reboot, desirable
on self). None reboots/locks-out/aborts-dispatch; guarding them would remove legitimate
self-repair/self-abort.

Tests: `PkgInstall.SelfGuard.Tests.ps1` (9, incl. the identity NIC-IP superset) +
`Wpt.SelfGuardApply` clean-user-apps cases (live-guarded / dry-run-not-guarded via a faked
worker block / no-apps). Plus N1. All drive the real dispatcher; the guard short-circuits
before any WinRM.

## SECRET parity
- SECRET parity: the pkginstall deploy self-guard (+ helpers) and the wpt clean-user-apps
  live self-guard — the JanetSec forks have the same actions and the same gaps; mirror both
  (and the benign-on-self classification, so SIPR doesn't over-guard).
- Carried (unexecuted): Host-header guard (+extended cases), report-preview CSP sandbox
  (+resource-free guard), wpt audit-Skipped, session disarm, honest Chrome/Edge + worker
  passthrough, upr refuse coverage, c2c orphan-protector fix, wpt loop-9 3 self-guards +
  confirm.
