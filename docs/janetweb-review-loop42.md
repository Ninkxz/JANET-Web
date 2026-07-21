# JANET Web — review loop 42 (2026-07-21)

Fable-inline. Self-review of loop-41 → **GREEN**. Baseline: loop-41 authoritative **1348** green (confirmed).

## Self-review of loop-41 (wpt verify-tally honesty) — GREEN
`Get-WptVerifyOk` = reachable AND `Verified -eq $true`; the AuditResultOf routes a reachable-probe-ran-but-not-
verified host → Skipped and everything else not-ok → Failure; a thrown probe yields Status='Failed' (not
'Verified') → Failure, never Skipped. All branches covered by the 9 tests + 1348 authoritative. Nothing to reopen.

## Workstream: close wpt item42 — a null client-SDK ReturnValue never confirms a trigger
The cleanest remaining wpt HIGH (item40's M365 is complicated by OfficeC2RClient returning unreliable exit
codes; item43 needs a required-version target). item42 is a proven-precedent fail-close: kb-install already
fail-closes on a null rv (loop22, `:2819`: "a method that returned nothing did NOT confirm acceptance"), and
bulk-patch didn't.

### Finding (CONFIRMED — re-verified in-code) + the sweep the static assert forced
The bulk-patch update path (`:2001`) rejected only a non-null NONZERO rv (a null fell through to counted), and
the app path (`:2027`) counted `$null -eq $rv -or 0` — so a null ReturnValue (the CCM method returned nothing)
counted as triggered and booked a VulnPatched/Success audit. Writing the regression test's static assert
(the old forms are gone from the module) immediately surfaced **three more instances of the identical fail-open**:
the Software Center App/Update trigger action (`:3913`/`:3923`, null→`Result='Triggered'`) and `WptAppActionBlock`
(`:4671`, null→`OK=true`→VulnPatched via app-update-apply). So the fix became a **comprehensive 5-site sweep**,
not just the two the worker flagged — the honest scope of the class.

### Fix (wpt 6.8.9 → 6.8.10)
All five sites now accept a trigger ONLY on a non-null `[int] 0`. New pure `Get-WptRvAccepted($ReturnValue)`
(`non-null AND [int] -eq 0`) is the canonical predicate; the five remote scriptblocks (module-less runspaces)
mirror the one-liner inline, comment-linked. Rejected-rv messages now print `<null>` instead of coercing a null
to `ReturnValue=0`. Matches kb-install's loop22 decision uniformly. Note: this closes the *null-rv* fail-open;
the deeper "a merely-accepted async CCM trigger books VulnPatched rather than a confirmed install" is a separate,
larger semantic (kb-install books MECM triggers as "Triggered (verify)") — ranked as **item51**.

### Version + tests
- `Wpt.BulkPatchRv.Tests.ps1` (NEW, 8): the pure predicate (0→accepted; null/1/-1→not) + static asserts both
  old null-accepting forms (`$null -eq $rv -or …`, `$null -ne $rv -and … -ne 0`) are gone module-wide and the
  fail-closed form recurs ≥2×; exact pin 6.8.10 (Wpt.VerifyApp exact pin → floor).
- wpt bulk-patch/verify/guard/KB set **59** + guards **24** green; grepped all tests for the touched symbols and
  the affected actions (SelfGuardApply/Guards/KbInstallResult) — none assert a null-rv→ok, all pass.

## Remaining wpt backlog
item40 (HIGH, M365/Trellix/SC profiles OK on trigger / ignored exit code — needs the unreliable-exit-code
analysis + likely a post-trigger verify), item43 (HIGH, Java SC mtime verify), items 44–50 (MED/LOW), and NEW
**item51** (bulk-patch/SC book VulnPatched for a merely-accepted async trigger, not a confirmed install).

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares the CCM-trigger scriptblocks — mirror `Get-WptRvAccepted` and
  the five inline null-rv fail-closes.
