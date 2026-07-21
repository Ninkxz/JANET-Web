# JANET Web — review loop 66 (2026-07-21)

Fable-inline. Self-review of loop-65 → **GREEN**. Baseline: loop-65 authoritative **1470** (dhcp-touching files 54 green after fix).

## Self-review of loop-65 (dhcp bulk ReadError → Failure) — GREEN
The counter is a fail-closed catch-all (ReadError/Error/Stale/unknown → `$errs`; legit statuses still bucket
correctly); both audit `switch` defaults book Failure with explicit `ReadError → Failure`; the behavioral test proves
ReadError → Failure + `summary.failed=1`. Nothing to reopen.

## Workstream: close item 75 — the dhcp destructive-guard hard-rule gap
The loop-65 dive found dhcp was the **only** destructive engine in the suite with **no self-guard and no typed
confirm-word** — the target filter (`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`) admits `localhost`, `127.0.0.1`, and the
dispatcher's own name, so a DHCP scope-option rewrite could be aimed at the box running JANET, armed by one click once
an admin session existed. (Mitigated only incidentally: a non-DHCP wrong box fails via `Import-Module DhcpServer -EA
Stop`.) The prompt lists self-guards + confirm-words among the established destructive patterns to never lack.

### Fix (dhcp 1.1.9 → 1.1.10)
For the 4 write actions (`apply`, `bulk-append`, `bulk-prepend`, `bulk-remove`), added — fail-closed, server-side,
**before any DHCP session** (right after `$server` validation, before the option-id parse and the action switch):
1. **Confirm-word**: a required `confirm` manifest input ("Type APPLY to arm") on each of the 4 actions + a gate
   `if ([string]$Params['confirm'] -ne 'APPLY') { refuse rejected }` (case-insensitive, matching adto's `-ne 'FIX'`).
2. **Self-guard**: `Get-DhcpLocalIdentity` + `Test-DhcpHostIsSelf` (mirroring `Get-PkgInstallLocalIdentity`/
   `Test-PkgInstallHostIsSelf` — COMPUTERNAME + FQDN + short + loopback + `127.*` + every bound NIC IPv4) → refuse when
   `$server` resolves to the local machine (`rejected=$true; selfSkipped=1`).
`connect`/`load` are read-only and stay ungated. No JS change (the `confirm` input renders in the form).

### Tests
+6 (`Dhcp.IpValidation.Tests.ps1`, behavioral via `Invoke-JanetToolAction`): exact `1.1.10` pin; all 4 destructive
actions declare a required `confirm` input while `connect`/`load` do not; `Test-DhcpHostIsSelf` (loopback + this box →
self, a remote name → not); `apply` with no confirm → rejected + the "type APPLY" log; a wrong confirm → rejected; a
correct `APPLY` + a **self** target (`127.0.0.1`) → self-guard rejected (`selfSkipped=1`). The loop-65 ReadError pin
migrated to a floor. **loop-37 lesson applied:** grepped every test for the dhcp actions first — `FixVerify`/
`FixVerify3` also import dhcp but drive `Invoke-JanetDhcpApply`/`Invoke-DhcpLoad` **directly** (below the dispatch
gate), so they're unaffected; ran all three files = **54** green.

## dhcp backlog after loop 66
Items 76 (dryRun fail-open), 77 (optionId retarget), 78 (apply null + no post-write verify), 79 (scope
reconciliation) remain — all P2/P3 from the loop-65 dive. dhcp now has the confirm-word + self-guard; item 76
(dryRun fail-open, the secureboot loop-58 class) is the next natural pick.

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork (if present) shares `Invoke-JanetToolAction` + the deploy manifests —
  mirror the `Test-DhcpHostIsSelf` self-guard + the `APPLY` confirm-word gate on the 4 write actions.
