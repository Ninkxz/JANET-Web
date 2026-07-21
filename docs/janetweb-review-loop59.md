# JANET Web — review loop 59 (2026-07-21)

Fable-inline. Self-review of loop-58 → **GREEN**. Baseline: loop-58 authoritative **1441** (secureboot subset 43 green after fix).

## Self-review of loop-58 (secureboot Get-SbeDryRunSafe) — GREEN
null/'' → live default; bool passthrough; `{false,0,no,off}` (case/space-normalized) → live; everything else → dry.
The only changed call site is `$isDry`, whose downstream consumers (`:1237` DryRun check, summary) are unchanged;
`Get-SbeBool` untouched so `attemptOffline`/`allowEmptyPassword` are unaffected. 5 tests + 1441 confirm no regression.
Nothing to reopen.

## Workstream: close item 62 — AlreadyPending re-books Success
The next audit-honesty finding from the loop-57 secureboot dive: a re-run against an already-staged host booked a
fresh Success though this run wrote nothing.

### Finding (CONFIRMED — re-verified in-code)
The three vendor payload branches (Lenovo `:161-164`, HP, Dell) short-circuit an already-staged host with
`New-Result -SetResult 'AlreadyPending'` and **return before re-firing** the set/save — so this run writes nothing.
But `New-Result` (`:137`) has **no `Skipped` property**, so `$result.Skipped` is `$null`, and the resolvedStatus
chain (`:722`) — `Unknown → Skipped=$true → Error → else Success` — fell through to **`'Success'`**. The classify
(`:1249-1290`, driven entirely by `$res.Status`) then did `okCount++`, `auditResult='Success'`, `itemCount=1`, and
the summary said "Done. N **enabled**". So each re-run double-books a VulnPatched/Success/itemCount-1 audit and
inflates the enabled count for work it didn't do (not a lie about firmware *state* — the enable is genuinely staged —
but a false attribution of *this run's* action).

### Fix (secureboot 1.6.3 → 1.6.4)
Added `elseif ($result.SetResult -eq 'AlreadyPending') { 'Skipped' }` to the resolvedStatus chain (before the Success
fallthrough). The classify already routes `Status='Skipped'` → `skipCount++`, `auditResult='Skipped'`, `itemCount=0`,
and out of the "N enabled" count — so the one-branch fix corrects the whole honesty chain (verified in-code, not
assumed). Also aligned the returned `Skipped` field to `($resolvedStatus -eq 'Skipped')` so Status/Skipped never
disagree (the field isn't consumed downstream today — defensive against a future consumer). +3 tests (static
analysis — the resolvedStatus mapping is inline in the module-less runspace worker): AlreadyPending→'Skipped';
non-Success → itemCount 0; Skipped routes to `$isSkip`; exact `1.6.4` pin (ConfirmWord's 1.6.3 floored). set **43** green.

## secureboot backlog after loop 59
Items 63/65/66 remain (P3): staged-vs-enabled wording (63), Cancelled scan-tally gap (65), best-effort icacls (66).
None is a hard firmware false-clean. secureboot's two audit-honesty false-cleans (item 62 re-run inflation, and the
loop-58 dry_run fail-open) are now closed; the trio (adto/remoteadmin/secureboot) is audited clean with its real
findings addressed.

## SECRET parity
- **SECRET parity:** if a JanetSec secureboot fork exists it shares the resolvedStatus chain — mirror the
  `AlreadyPending → Skipped` branch so a re-run against a staged host doesn't book a fresh Success.
