# JANET Web — review loop 11 (2026-07-20)

**Baseline:** 1111/1111 at loop-10 close (`(close)`); tree untouched between loops.
Local-only commits.

## Opus adversarial self-review of loop-10 (`f4ab266` pkginstall+wpt self-guards) — verdict GREEN

Deeper than the loop-10 Sonnet sweep. Two specific BYPASS risks probed and CLEARED:
- **Identity-set case-sensitivity (the highest-risk item):** `Get-PkgInstallLocalIdentity`
  has the unary-comma on BOTH return paths (`pkginstall.psm1:109`/`:124`), so the caller gets
  the real `OrdinalIgnoreCase` HashSet — a `WS-SELF` dispatcher dialed as `ws-self` IS caught.
  No case-sensitive-Object[] bypass.
- **`[bool]'false'` coercion on clean-user-apps dryrun:** real PS gotcha, but CANNOT bypass
  the self-guard — the same `$dry` drives both the guard (`if (-not $dry)`) and the worker's
  mode, so a mis-coerced live→dry flip means "no deletion," not "guard skipped on a live run."
Also CLEAN: pkginstall guard reachable only by the 2 deploy actions (action-gate at `:709`
precedes it — no over-guard); N1 `$guarded` in scope; token-validation-before-self-guard
ordering correct. **One P3 surfaced → FIXED this loop:** the raw `[bool]$Params['dryrun']`
should use the existing `ConvertTo-WptBool` (a `'false'` STRING mis-coerces to live→dry).

## Opus deep-dive: winupgrade (9 destructive actions, feature-update reboots) — verdict GREEN

Largest unreviewed destructive tool. No P1/P2. Verified CLEAN with evidence:
- **Self-guard complete:** the shared `$mutatesTarget` list (`winupgrade.psm1:3454`) is a
  1:1 match with the manifest's 9 `destructive:true` actions (install-updates/pin/unpin/
  forcediscovery/upgrade-drive/installcab/setpagefile/repair-health/auto-fix); the drop runs
  before the single `BeginInvoke` (`:3680`); identity set absorbs bound-NIC IPv4 literals.
- **CAB push:** name is `Split-Path -Leaf` (`:3479`), DISM via `ProcessStartInfo` (no shell),
  `Test-Path -LiteralPath` existence gate.
- **pin/unpin:** hardcoded `HKLM:\...\WindowsUpdate` key path; operator text lands only as
  value DATA, never a key path; fail-closed re-read (`:1129`).
- **Wrong-box + IPv4 carve-out uniform across all 5 reboot sites**; setpagefile fully numeric
  (clamped 1024-131072); target-token allowlist before connect; cred in-memory; fail-closed
  (missing/stale result.json = Timeout, not success). Already 7-file tested (incl.
  `Winupgrade.SelfGuard.Tests.ps1`).
- **Accepted P3 (no change):** DISM `/PackagePath:"$cab"` interpolates the leaf into a quoted
  arg — not exploitable (NTFS filenames can't contain `"`, existence-gated), and PS 5.1's
  `ProcessStartInfo` has no `ArgumentList` (that's .NET Core), so a discrete-array rewrite
  isn't available without swapping to the call operator (a bigger change to a working
  destructive path). Documented as reviewed-clean; not worth touching for a non-hole.

## Workstream: the loop-10-self-review coercion fix (`0b1a7c8`, wpt 6.8.4→6.8.5)

Both deep-dives GREEN, both tools well-tested → the deliverable is the one REAL item: the
`dryrun` trust-boundary coercion. `clean-user-apps` (:6253) + `cleanup-disk` (:6219) used raw
`[bool]$Params['dryrun']`; `[bool]'false'` is `$true` in PS, so a `'false'` STRING (operator
means LIVE) silently ran dry — and for clean-user-apps that ALSO skipped its live-only
self-guard. Routed both through the existing `ConvertTo-WptBool` (no new infra; the JSON-bool
UI path is unchanged). Regression: `dryrun='false'` STRING → LIVE → self-guard fires;
`dryrun='true'` STRING → stays dry (hermetic faked worker).

## SECRET parity
- SECRET parity: the wpt dryrun coercion fix (clean-user-apps + cleanup-disk) — the JanetSec
  wpt fork has the same raw `[bool]` pattern.
- winupgrade needs no parity change (GREEN). The DISM discrete-args P3, if ever taken, applies
  to the SIPR winupgrade fork too.
- Carried (unexecuted): all prior SECRET-parity items (Host-header, sandbox, disarm, honest
  Chrome/Edge, upr refuse, c2c orphan, wpt loop-9/10 self-guards + confirm, pkginstall guard).
