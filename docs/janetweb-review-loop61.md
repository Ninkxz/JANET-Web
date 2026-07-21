# JANET Web — review loop 61 (2026-07-21)

Fable-inline. Self-review of loop-60 → **GREEN**. Baseline: loop-60 authoritative **1449** (pkginstall subset 33 green after fix).

## Self-review of loop-60 (pkginstall all-1638 → AlreadyInstalled/Skipped) — GREEN
Per-MSI statuses ∈ {Success, Failed, AlreadyInstalled}, so `failCount=0 && successCount=0 && installedCount==totalCount`
is exactly "every MSI refused"; a reboot code (1641/3010) makes successCount≥1 → stays the Success branch (1638
noted, not dominant); harvest routes `AlreadyInstalled` → skipCount/audit-Skipped/itemCount-0/warn; summary
`total=ok+fail+deferred+skipped` still holds; no stale `$compliantCount`/`AlreadyCompliant` refs. Nothing to reopen.

## Workstream: close item 68 — pkginstall's second false-clean (the PSADT LASTEXITCODE pre-seed)
Pairing with loop 60 (like secureboot's two false-cleans in loops 58-59): close both of pkginstall's dive false-cleans
before pivoting.

### Finding (CONFIRMED — re-verified in-code)
The PSADT deploy branch pre-seeded `$global:LASTEXITCODE = 0` (`:606`) before `& $deploy.FullName ...` (`:607`),
then `$exitCode = $LASTEXITCODE` (`:608`). `& script.ps1` **only** updates `$LASTEXITCODE` when the script calls
`exit`/`Exit-Script` (or ends on a native command). A `Deploy-Application.ps1` that returns without one leaves the
pre-seeded **0** → `$exitCode=0` ∈ `$successExits` (`:618-620`) → `Status='Success'` + `VulnPatched` though nothing
installed. The soft-fail regex (`:619`, anchored `^\s*(ERROR|FAILED)`) doesn't rescue it — PowerShell error records
render as `Write-Error : ...` / `Cmdlet : ...`, never line-start `ERROR`. The tool accepts any folder containing a
`Deploy-Application.ps1` (custom package path), so a broken/hand-rolled deploy script trips it.

### Fix (pkginstall 2.5.9 → 2.5.10)
Pre-seed `$global:LASTEXITCODE = $null` (not 0), and add a first branch `if ($null -eq $exitCode) { Failed }` **before**
the success-exit check — a deploy script that set no exit code is booked `Failed` ("returned no exit code ... cannot
confirm the install ran"), never a false Success. A terminating error still routes to the existing catch; a real
PSADT package (always `Exit-Script` → `exit`) is unaffected. +3 tests (static analysis — the branch is inside the
module-less runspace worker `$RpiDeployHostScript`): pre-seed is `$null` not `0`; the null-exit branch precedes the
success-exit check (so a null can't match exit 0); "returned no exit code" reason present; exact `2.5.10` pin (the
loop-60 all-1638 Describe floored). set **33** green.

### Full-suite catch — the loop-37 lesson recurred
My pkginstall subset (MsiList/SelfGuard/WrongBoxGuard) missed a fourth pkginstall test file: `FixVerify3.Tests.ps1`
**behaviorally** extracts the deploy block via AST and runs it against a real temp package. Its 3 PSADT soft-fail
tests faked a "success exit" by **not** calling `exit` and relying on the old pre-seed `0` — the exact bug I fixed —
so the module change turned them `Failed` (3 full-suite failures caught before finalize). Fix: `Invoke-Psadt` now
appends a real `exit 0` (as PSADT `Exit-Script` does) so the soft-fail scenarios model reality, plus a new behavioral
`It` covering the no-exit → `Failed` path (a stronger regression than my MsiList static asserts). Commit `26f82ecb7`.
**Lesson (again): grep ALL tests for the touched path — here `RpiDeployHostScript`/`LASTEXITCODE`/`exitCode` — before
finalizing; a behavioral test can pin the old behavior.** Full suite 1449 → **1453** green.

## pkginstall backlog after loop 61
Both dive false-cleans (item 67 all-1638, item 68 PSADT null-exit) are now closed. Remaining: **item 69** (no
confirm-word on the destructive deploy — hard-rule gap, HIGH) and **item 70** (MSI-list silent partial drop, P3).
item 69 is the natural next pick — it's a stated-hard-rule violation on the most destructive tool.

## SECRET parity
- **SECRET parity:** if a JanetSec pkginstall fork exists it shares the PSADT deploy branch — mirror the
  `$LASTEXITCODE=$null` pre-seed + the null-exit → Failed guard so a no-exit deploy script isn't a false Success.
