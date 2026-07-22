# JANET Web — review loop 85 (2026-07-22)

**Theme: informative failures / remediation.** Fable-inline + a Fable self-review of loop 84. Baseline: loop-84
authoritative **1567**.

## Self-review of loop-84 — **P0 CONFIRMED: the upr run STILL aborts; loop-84's "fixed" claim was false**
Loop 84's headline was fixing the upr uninstall crash (P1: the per-candidate hint threw inside a
`.GetNewClosure()`'d block). The self-review executed the *actual* run and found it **still dies** — one statement
later, at the row emit:

`modules\JanetWeb.upr.psm1` `& $Send (@{ type='row' } + $row)` — a candidate row carries an app `Type` key
(`Type=[string]$cand.Type`, `:1472`/`:1490`), and on PS 5.1 a `@{}` literal is a **case-INSENSITIVE** Hashtable,
so adding the event key `type` when the row already holds `Type` is a duplicate-key `ArgumentException` ("Item has
already been added. Key in dictionary: 'type'"). Reproduced: `@{ type='row' } + @{ Type='EXE' }` throws. It fires
on EVERY candidate row → aborts every fan-out (report/manual × scan/uninstall) at the first candidate; only
all-unreachable runs (host rows carry no `Type`) mask it. So loop-84's P1 fix swapped a `CommandNotFoundException`
abort for an `ArgumentException` abort, and its static tests never emitted a `Type`-bearing row. **Pre-existing**
(the emit line predates loop 84), but loop 84 CLAIMED to have un-broken the run and did not.

### Fix P0 (upr 1.2.7 → 1.2.8) — a case-sensitive emit merge
The row must reach the case-sensitive JS view carrying BOTH the event `type='row'` and the app `Type='MSI'`. A
case-insensitive Hashtable can't hold both; a **case-SENSITIVE** `System.Collections.Hashtable` can, and
`ConvertTo-Json` (the server's emit serializer, `Server.ps1:283`) renders them as distinct JSON keys. Added
`New-UprRowEvent` (module scope — all 6 emit sites are in `Invoke-UprFanOut`/`Invoke-JanetToolAction`, none in
closures) and swapped all `@{ type='row' } + $row` emits to it. Verified end-to-end: a 2-candidate reached host now
emits both rows (was: 1 then abort); each carries `type=row` + `Type=MSI`. **The regression test EXECUTES the
emit** (the coverage loop 84 lacked) + asserts the old merge really throws on 5.1.

## Workstream: F2 — a successful Oracle-Java removal was audited VulnPatched Failure (deferred from loop 84)
The `fix-java` REMOVE profile's Verify probe reads post=`'not installed'`, which `Get-AcasBumpVerdict`'s degraded-
sentinel list (`error`/`n/a`/`not installed` = "probe couldn't read a version") rewrote to `unconfirmed` → audited
**Failure** for a genuine removal. True for an UPDATE; wrong for a REMOVAL where `'not installed'` is success.

### Fix F2 (acas 1.11.13 → 1.11.14) — a profile-intent flag, gated so ONLY removals get the pass
Added `PostRemovedOk` to the Java-remove profile; `Get-AcasBumpVerdict` gained a `-PostRemovedOk` switch (and the
worker's inline mirror reads `$prof.PostRemovedOk`, already in scope at `:1876`) that books post=`'not installed'`
as `confirmed` — but ONLY the literal `'not installed'`, and ONLY when the flag is set. **The Chrome false-clean
guard is provably intact** (verified: an UPDATE profile with no flag → update→not-installed/error/n-a/downgrade all
still `unconfirmed`; the flag does NOT rescue error/n-a/downgrade; a real forward bump stays confirmed). Removal-
aware diff wording (`removed: … (confirmed gone)`). Canonical + inline mirror kept in sync (their convention).

## Tests
`Upr.VerifyResult.Tests.ps1` +5 (P0: EXECUTED emit no-throw + both keys, old-merge-gone, root-cause-throws,
case-sensitive), pin 1.2.8. `Acas.BumpVerdict.Tests.ps1` +7 (F2 behavioral incl. the Chrome-guard-intact cases +
inline-mirror + profile-flag), pin 1.11.14; `Acas.FanOutHint` loop-71 pin floored. **loop-37 lesson:** ran the full
acas suite (193) + upr + the full suite.

## The recurring lesson (recorded)
Three consecutive loops shipped a "fix" whose GREEN static tests never executed the failing path (loop 82→83 closure
scope, loop 83→84 Type collision). **A source-regex test cannot catch a runtime failure.** Every hint/emit wire that
runs inside a fan-out now gets a behavioral test that invokes the real code path.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the upr-fork `New-UprRowEvent` case-sensitive emit (its rows carry
  the same `Type` key), (b) the acas-fork F2 `PostRemovedOk` profile flag + bump-verdict gate (both canonical + inline
  mirror). Verify the SIPR forks share these exact shapes before mirroring.
