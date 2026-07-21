# JANET Web — review loop 41 (2026-07-21)

Fable-inline. Self-review of loop-40 → **GREEN**. Baseline: loop-40 authoritative **1339** green (confirmed).

## Self-review of loop-40 (acas Office C2R verify port) — GREEN
`Get-AcasC2rVerified` is a line-for-line port of the proven `Get-WptC2rVerified`; the generated-scriptblock
mirror computes `$scenarioResult` from `$p.LastScenarioResult` and applies the identical null/stale/success
logic (static assert pins `LastScenarioResult` present + the old mtime-only line gone); the Detail path is
unchanged. 76-test acas set + 1339 authoritative confirm no regression. Nothing to reopen.

## Workstream: close wpt item41 — app-update-verify counts a host ok only when actually verified
The cleanest of the three HIGH wpt items from the loop-40 dive, and it *completes* the loop-40 C2R work:
my C2R fix makes acas's probe return `Verified=$false` on a failed scenario, but wpt's verify path would
swallow the equivalent. Item41 is also the exact thing acas already does right (`Get-AcasVerifyRowStatus`),
so it has a clear precedent.

### Finding (CONFIRMED — re-verified in-code)
`WptAppUpdateBlock` sets `$r.Status = 'Verified'` unconditionally for any probe that returned without throwing
(`:3421`) — the real `$res.Verified` verdict is captured into `$r.Verified` but never gates the status. The
`app-update-verify` action's OkOf was `($r.Reachable -and $r.Status -eq 'Verified')` (`:6441`), so **every
reachable host that returned a probe counted ok** and booked a `TouchHost` Success audit — including a host at
a stale, still-vulnerable version whose probe read `Verified=No`. The per-host row rendered `Verified=No`
honestly (`:6443`), but the "N verified" tally and the audit over-reported. (Audit action is TouchHost, so the
harm is the verify tile/summary + the ledger's Success count, not a false VulnPatched.)

### Fix (wpt 6.8.8 → 6.8.9)
New pure `Get-WptVerifyOk($Reachable, $Verified)` → ok only when `reachable AND $Verified -eq $true` (mirrors
acas `Get-AcasVerifyRowStatus`). The handler's OkOf now calls it, and a new `AuditResultOf` audits a
reachable-but-not-verified host as **Skipped** (checked, not current — no action), unreachable/errored as
Failure — matching wpt's own app-update PENDING→Skipped pattern (`:6509`), so routine not-yet-patched hosts
don't inflate the Failure count. `AuditDetail` now also carries the Verified verdict. The fan-out's OkOf runs
controller-side (module loaded), so the helper is directly callable — no inline-mirror needed here.

### Version + tests
- `Wpt.VerifyApp.Tests.ps1` (NEW, 9): the pure predicate at every branch (Verified $true→ok; $false→not-ok
  [the fix]; $null→not-ok; unreachable→not-ok) + static asserts that the handler OkOf calls the helper, the old
  Status-only predicate is gone, and a not-verified host audits Skipped; exact pin 6.8.9 (Wpt.C2rVerify exact
  pin → floor).
- wpt verify/profile/self-guard/KB set **78** green; grepped all tests for the touched symbols
  (`Get-WptVerifyOk`, `Status -eq 'Verified'`, `6.8.8`, `app-update-verify`) — the only affected files are the
  two I edited; ChromeProfiles + SelfGuardApply reference the action for routing/self-guard and pass unchanged.

## Remaining wpt backlog (from the loop-40 dive)
item40 (HIGH, profiles OK on trigger / ignored exit code → VulnPatched — the systemic one), item42 (HIGH,
bulk-patch null-RV), item43 (HIGH, Java SC mtime verify), items 44–50 (MED/LOW). item41 is now closed.

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares `WptAppUpdateBlock` + the app-update-verify handler — mirror
  `Get-WptVerifyOk`, the OkOf change, and the Skipped AuditResultOf.
