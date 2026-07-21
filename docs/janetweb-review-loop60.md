# JANET Web — review loop 60 (2026-07-21)

Fable-inline synthesis over one Fable adversarial deep-dive worker on **pkginstall** (Package Installer — the most
substantial un-dived *destructive* tool: pushes + installs MSI/PSADT packages fleet-wide over WinRM). Self-review of
loop-59 → **GREEN**. Baseline: loop-59 authoritative **1444** (pkginstall subset 30 green after fix).

## Self-review of loop-59 (secureboot AlreadyPending → Skipped) — GREEN
The new branch follows the existing `Skipped`-before-`Error` ordering (AlreadyPending branches carry `Err=''`, so no
error is masked); `Skipped = ($resolvedStatus -eq 'Skipped')` is unchanged for all prior cases and only flips
AlreadyPending's field to match; the classify routes `Skipped` → skipCount/audit-Skipped/itemCount-0 with the detail
preserved. Nothing to reopen.

## Workstream: Fable deep-dive on pkginstall — core fail-closed, one false-clean closed
The dive traced push/install result → row Status → audit and all safety layers. **Core is largely fail-closed and
better than most of the fleet:** Status inits to `'Failed'` (`:191`), null/unread msiexec exit → Failed (`:525`),
harvest switch-default → Failure (`:984`/`:999`), both catches → Failed, copy-to-share is SHA256/tree-verified before
execution, and **zero `[int]("0"+...)`/`-as [int]` coercions** (grep-verified). Self-guard, wrong-box, and IPv4/
hostname target validation all present + test-pinned. Three CONFIRMED findings; I acted on the purest false-clean.

### Finding acted on — P2-2 msiexec 1638 false-clean (CONFIRMED, re-verified in-code)
Per-MSI exit **1638** ("another version already installed") was mapped to `'AlreadyCompliant'` (`:523`); an all-1638
host then aggregated to `$res.Status='Success'` (`:549-552`) → harvest `okCount++`, audit `VulnPatched/Success/
itemCount=1` (`:981`,`:995-1002`). But 1638 means msiexec **REFUSED to install** because a *different* version is
present — nothing changed on the box, and the installed version is **never compared** to the package (no
ProductVersion check exists), so it's often the OLD, still-vulnerable version. The DoD audit trail thus recorded a
host **VulnPatched/Success** while the installer touched nothing and the vuln may remain — the campaign's exact class.

### Fix (pkginstall 2.5.8 → 2.5.9)
An all-1638 host (`failCount=0 && successCount=0 && installedCount==totalCount`) now resolves to a new host status
**`'AlreadyInstalled'`** — the harvest routes it to `skipCount++` + audit **`Skipped`/itemCount 0** + warn log (never
`VulnPatched/Success`), mirroring the loop-59 secureboot `AlreadyPending → Skipped` fix. The per-MSI status token +
reasons were reworded to drop the unverified "compliant" claim ("install did NOT run; version NOT verified
compliant"). A **mixed** wave (some real installs + some 1638) stays `Success` — real work happened — with an
"(N already installed, version unverified)" note instead of "already compliant". +5 tests (static analysis — the
per-MSI mapping + aggregate live inside the module-less runspace worker `$RpiDeployHostScript`): all-1638 → Status
`AlreadyInstalled`; harvest → `skipCount`; audit → `Skipped`; the old "treated as already compliant" wording gone;
exact `2.5.9` pin (SelfGuard's 2.5.8 floored). set **30** green.

### Findings NOT acted on this loop (ranked backlog)
- **item 68 (P2-1)** — the PSADT deploy branch pre-seeds `$global:LASTEXITCODE=0` (`:600`), so a hand-rolled
  `Deploy-Application.ps1` that returns without `exit` books Success though nothing installed. Fix: seed `$null`/
  sentinel, treat a null exit as Failed. HIGH — genuine false-clean.
- **item 69 (P2-3)** — **no confirm-word gate** on either destructive deploy action; pkginstall is the *only*
  destructive tool in the suite lacking one (adto FIX/VALIDATE, secureboot ENABLE, c2c, certdeploy, winrmbridge all
  have it). Other layers (admin-gate, self-guard, wrong-box, IPv4) present — a missing layer, not an unguarded path.
  Fix: module `if ($Params['confirm'] -ne 'DEPLOY') { refuse }` + `confirmWord` in the view. HIGH — hard-rule gap.
- **item 70 (P3-4)** — `ConvertTo-JanetMsiList` silently drops invalid entries; a partial list can then book "All N
  succeeded", and an all-dropped list falls through to the install-every-`*.msi` fallback (scope escalation). Fix:
  count rejected entries and warn/refuse when a non-empty list filtered smaller. (P3-5 cancel + S1/S2 = accepted.)

## SECRET parity
- **SECRET parity:** if a JanetSec pkginstall fork exists it shares the MSI aggregate + harvest — mirror the all-1638
  → `AlreadyInstalled` → Skipped mapping so an all-refused host isn't booked a false VulnPatched Success.
