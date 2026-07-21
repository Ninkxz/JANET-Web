# JANET Web — review loop 69 (2026-07-21)

Fable-inline. Self-review of loop-68 → **GREEN**. Baseline: loop-68 authoritative **1483** (dhcp-touching files 64 green after fix).

## Self-review of loop-68 (dhcp apply null-result → Failure) — GREEN
`if ($null -eq $applyRes)` books Failure/Error/`failed=1` and returns before the Success path, mirroring the catch; a
real result (with a `Removed` property) proceeds to Changed/Removed unchanged; the behavioral two-seam-shim test proves
an empty write result → Error/Failure. Nothing to reopen.

## Workstream: close item 77 — a non-numeric optionId retargeting option 6 (DNS) on a destructive write
`Invoke-JanetToolAction`'s shared optionId parse (`:1199-1211`): a present-but-unparseable optionId **warned and fell
back to option 6** (006 DNS Servers). For a read-only `load` that's acceptable (it changes nothing), but for a
destructive `apply`/`bulk-*` write it means an operator who intended option 60/66 and typo'd (`'6o'`, `'xyz'`) would
**live-replace the scope's DNS servers** on the wrong option — a wrong-target destructive write, audited Success.

### Fix (dhcp 1.1.12 → 1.1.13)
Hoisted the gate's action set into `$isDestructive = $ActionId -in @('apply','bulk-append','bulk-prepend','bulk-remove')`
(one definition, reused by the confirm/self-guard gate and here). The optionId parse's non-numeric branch now:
`elseif ($isDestructive) { err "refusing a destructive write rather than defaulting to option 6 (DNS Servers)"; return
rejected }` — abort before any DHCP session; the read-only `else` still warns-and-defaults (unchanged). +3 tests
(`Dhcp.IpValidation.Tests.ps1`, behavioral): exact `1.1.13` pin; `apply` with `optionId='6o'` → rejected + the
"not numeric … DNS" err log; `bulk-append` with `optionId='xyz'` → rejected. loop-68 pin floored; ran all 3
dhcp-touching files = **64** green.

## dhcp backlog after loop 69
- **item 79 (P3):** bulk doesn't reconcile returned records vs requested scopes (a missing scope → no row/audit/error).
- **item 80 (P2):** apply/bulk have no post-write re-read verification (only a *pre*-write stale check on bulk) — the
  upr-style mandatory re-read + compare. The most valuable remaining dhcp hardening; a bigger add, its own loop.
dhcp now fail-closes: bulk ReadError, confirm-word, self-guard, dryRun, apply null-result, and destructive
optionId-retarget. The dive's substantive findings are all closed except the post-write verify (item 80) and the P3
reconciliation (item 79).

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork (if present) shares the optionId parse — mirror the `$isDestructive` abort
  so a non-numeric optionId can't silently retarget option 6 (DNS) on a write.
