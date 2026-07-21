# JANET Web — review loop 56 (2026-07-21)

Fable-inline synthesis over one Fable adversarial deep-dive worker on **remoteadmin** (the last sharp un-dived
destructive surface: Open C$ + Run Script). Self-review of loop-55 → **GREEN**. Baseline: loop-55 authoritative
**1431** (pending the in-flight authoritative run; adto subset 20 + remoteadmin subset 31 green).

## Self-review of loop-55 (adto overlay merge-not-replace) — GREEN
The merge handles malformed overlay rules (a string/array/null rule → `$r.enabled` is `$null` → keeps defaults),
treats `null`-valued JSON fields as omitted (kept), and case-insensitive `ContainsKey`/key-set updates the existing
entry rather than duplicating. Every consumer (`Test-AdToCompliance`'s `$fire`) still sees all three rule fields
present, as under the old replace. Nothing to reopen.

## Workstream: Fable deep-dive on remoteadmin — core is fail-closed
The dive traced every result→Status→audit path and all four safety layers. **No P1/P2 false-clean.** The worker
and aggregator default to `Failed`/`Failure` and book `Success` only on an exact `Status -eq 'Success'` match; a
null/blank/unknown Status coerces to `''` → Failure, itemCount 0 (`:452-457`). No `[int]("0"+...)`, no `-as [int]`,
no switch-default→Success, no Success-booking catch. Safety verified fail-closed and correctly ordered before
fan-out: admin-session gate (server default-deny, `Server.ps1:843-852`, run-script `destructive=$true`); self-guard
`Remove-RemoteAdminSelfTargets` (`:184-195`, incl. every bound NIC IPv4 + loopback, runs before fan-out); target
validation `Test-RemoteAdminComputerName` (`:81-85`, anchored regex rejects UNC/injection); wrong-box hard-abort
(`:274-290`, IP-literal correctly bypasses DNS indirection).

### Finding acted on — C1 (P3, CONFIRMED)
`Invoke-JanetToolAction` (`:473`): `$res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1`. The worker returns
its result hashtable as the **last** stream object (`return $r`, `:306`). Today nothing leaks earlier (all worker
statements assign or pipe to `Out-String`), so `-First 1` == `-Last 1` at runtime — but on a run-*arbitrary*-code
tool, if a future edit or the operator's script ever leaks a stray object before the return, `-First 1` builds the
row (`Host`/`Status`/`Output` all from `$res.*`, `:444-448`) from the stray. **Fix:** `-Last 1` — always the return.

### Findings NOT acted on (by design)
- **C2 (P3)** open-cshare reports `Opened` + audit `Success` when `explorer.exe` launches regardless of whether the
  C$ share is actually reachable. The dive judged this **acceptable-by-design**: the action is non-destructive,
  JANET reads/writes nothing, the operator visually verifies the Explorer window, the Status honestly claims only a
  launch, and the audit correctly records that an admin-share access was launched. Left as-is.
- **S1 (speculative)** run-script `Success` means "the scriptblock didn't throw," not "the operator's intent
  succeeded" — inherent to a run-arbitrary-code tool (no process exit code exists for a scriptblock). The dive
  explicitly warns *against* "fixing" this with invented exit-code parsing (would introduce coercion risk). Left.

## Fix (remoteadmin 1.0.1 → 1.0.2)
`-First 1` → `-Last 1` at `:473`, with a comment tying it to the worker's `return $r`. +1 behavioral test: a fake
worker that emits `'STRAY-LEAK-OBJECT'` before returning the result → the row must be built from the return
(`Host=WS-REMOTE`, `Status=Success`, `Output=ran on WS-REMOTE`), which fails under `-First 1` and passes under
`-Last 1`. +1 version pin (`1.0.2`). remoteadmin set **31** green (was 29).

## remoteadmin backlog after loop 56
None actionable — the tool is fail-closed. C2/S1 are by-design (documented above). No further remoteadmin dive
unless a concrete new lead surfaces.

## SECRET parity
- **SECRET parity:** if a JanetSec remoteadmin fork exists it shares the `Invoke-JanetToolAction` fan-out
  result-binding — mirror `-Last 1` (bind the row from the worker's returned result, not the first stream object).
