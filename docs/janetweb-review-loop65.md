# JANET Web — review loop 65 (2026-07-21)

Fable-inline synthesis over one Fable adversarial deep-dive worker on **dhcp** (DHCP scope-option admin — four
destructive server-config actions, thinly tested). Self-review of loop-64 → **GREEN**. Baseline: loop-64 authoritative
**1467** (dhcp subset 11 green after fix).

## Self-review of loop-64 (upr generic-handler hardening) — GREEN
The generic-MSI path routes `$unStr` (which carries `msiexec`+GUID) through `Get-SafeUninstallPlan`'s Msi form → safe
discrete `/x {strictGUID}`; Adobe's strict `\{[0-9A-Fa-f\-]{8,}\}` still matches real product codes (Adobe test
passed) but rejects a `{GUID /switch}`; a future `Store` type falls to the EXE `else` → Reject → FAIL. Nothing to reopen.

## Workstream: Fable dive on dhcp — a real P1 false-clean (first non-fail-closed core in a while)
The remote-side read handling is exemplary (ReadError refusal, stale re-read guard, empty-collapse guard) and **both
dry-run paths are truly read-only** (verified: apply returns before any write; bulk's `Set-`/`Remove-` are reachable
only in the non-`$dryRun` else; the preview uses the SAME list math as the live write). But the LOCAL bulk result
handler laundered the remote's own fail-closed refusals.

### Finding acted on — P1 bulk ReadError laundered to Success (CONFIRMED, re-verified in-code)
`Invoke-JanetDhcpBulk`: the remote `$script:DhcpBulkScript` returns `Status='ReadError'` when it declines to write
because it could not read the current option value (RPC blip / DHCP-Administrators permission failure). The local
handler betrayed it three ways: (1) the counter (`:981-983`) bucketed only `Error/Stale` as errors — `ReadError`
matched **nothing**, uncounted; (2) both audit `switch` **defaults** (`:995` dry, `:1004` live) booked
`TouchHost/Success` — a refused, unwritten scope audited as a **successful** touch (the switch-default→Success root
cause); (3) the summary (`:1024-1031`) read "0 error(s)" with `summary.failed=0`. So refusing to touch 20 scopes
reported clean and wrote 20 Success rows to the JANET audit CSV.

### Fix (dhcp 1.1.8 → 1.1.9)
The counter's final branch is now a **fail-closed catch-all** (`else { $errs++ }` — anything not a change or a genuine
no-change is an error, so `ReadError` + any future status counts); both bulk audit `switch` defaults book **Failure**
(never Success), each with an explicit `ReadError → Failure` case ("REFUSED: could not read current value"). The
summary/warn then reflect the errors (they key off `$errs`). +3 tests: **behavioral** (shim `Invoke-JanetOnDhcp-
Cancelable` to return a `ReadError` record → the audit is `Failure`, `summary.failed=1`, `summary.ok=0`, the row keeps
its honest `ReadError` status) + **static** (no bulk audit default books Success). dhcp subset **11** green.

## dhcp backlog after loop 65 — a follow-up hardening loop is warranted
The dive found several more real issues (dhcp is under-guarded vs the rest of the fleet):
- **item 75 (P2):** no self-guard AND no typed confirm-word on the destructive apply/bulk actions — the target filter
  admits `localhost`/`127.0.0.1`/the dispatcher's own name; every other destructive engine has a pinned self-guard.
  (Mitigated: a non-DHCP wrong box fails closed via `Import-Module DhcpServer -EA Stop`.) *Hard-rule gap — next pick.*
- **item 76 (P2):** `dryRun` fails OPEN on unrecognized values (secureboot loop-58 class) — `Get-SbeDryRunSafe`-style fix.
- **item 77 (P2):** non-numeric `optionId` on a destructive action silently retargets option 6 (DNS) — abort instead.
- **item 78 (P2):** apply null remote result coerces to `Changed`/Success; **no post-write re-read** verifies the option
  actually became the intended value on either apply or bulk — add a post-write compare.
- **item 79 (P3):** bulk doesn't reconcile returned records vs requested scopes (a missing scope → no row/audit/error).

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork (if present) shares `Invoke-JanetDhcpBulk` — mirror the fail-closed counter
  catch-all + the `switch`-default→Failure + `ReadError` handling.
