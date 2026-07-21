# JANET Web — review loop 68 (2026-07-21)

Fable-inline. Self-review of loop-67 → **GREEN**. Baseline: loop-67 authoritative **1481** (dhcp-touching files 61 green after fix).

## Self-review of loop-67 (dhcp Get-DhcpDryRunSafe) — GREEN
null/'' → live default; bool passthrough; `{false,0,no,off}` → live; everything else → dry. Both dryRun sites call it;
`$asBool` untouched (removeOption safe). 5 behavioral cases + FixVerify/FixVerify3 (explicit `-DryRun` bool, below the
parse) = 61 green. (Corrected the loop-67 count: the dryRun Describe is +5 tests → 1476→1481, not the 1479 first
estimated.) Nothing to reopen.

## Workstream: close item 78 — the last real dhcp false-clean (apply null-result → Changed/Success)
`Invoke-JanetDhcpApply` read the write result as `$applyRes = @($applyCall.Result | Select-Object -First 1)[0]`
(`:853`). A **null/empty** result — the remote apply confirmed neither a Set nor a Remove (an error that didn't throw,
a lost/empty pipeline; the inner `[powershell]` can complete with error records but no thrown exception) — made
`$applyRes=$null`, then `[bool]$null.Removed` = `$false` → `$status='Changed'` (`:854`) → an **unconditional
VulnPatched/Success** (`:858`) + row `Status='Changed'` + `summary.ok=1`, for a change that could not be confirmed. The
classic null→benign coercion false-clean (root-cause class (a)/(c)).

### Fix (dhcp 1.1.11 → 1.1.12)
Guard the null result immediately after the `Select-Object -First 1`: `if ($null -eq $applyRes)` books **Failure**
(audit `VulnPatched/Failure/itemCount=0` "change NOT confirmed", row `Status='Error'`, `summary.failed=1`) and returns
before the Success path — mirroring the function's own `catch` block. A real result (with a `Removed` property) proceeds
unchanged. +2 tests (`Dhcp.IpValidation.Tests.ps1`, behavioral — mirroring the FixVerify3 two-seam shim: the pre-read
returns a valid current state so the write is reached, and the write returns an **empty** result → `Status='Error'`,
`failed=1`, `ok=0`, audit `Failure`). Ran all 3 dhcp-touching files = **61** green.

## dhcp backlog after loop 68
- **item 77 (P2):** non-numeric `optionId` on a destructive action silently retargets option 6 (DNS) — abort instead.
- **item 79 (P3):** bulk doesn't reconcile returned records vs requested scopes.
- **item 80 (P2, NEW):** apply/bulk have **no post-write re-read** verifying the option actually became the intended
  value (only a *pre*-write stale check on bulk) — the dive's other half of item 78. A mandatory post-write compare
  (like upr's re-verify) is a bigger add and warrants its own loop. This is the most valuable remaining dhcp hardening.
dhcp now has confirm-word + self-guard + fail-closed dryRun + fail-closed bulk-status + fail-closed apply null-result.

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork (if present) shares `Invoke-JanetDhcpApply` — mirror the null-result →
  Failure guard so an apply that returns nothing isn't booked a false Changed/Success.
