# Design - Loop 4 - Behavioral self-guard test (end-to-end Test-*HostIsSelf)

## Goal
The loop-3 P2 was a *behavioral* failure: `Test-*HostIsSelf` returned FALSE for the dispatcher's own
hostname in variant case, so a destructive action could hit the JANET server itself. The loop-3 parity test
(`SelfGuard.IdentityParity.Tests.ps1`) locks the identity-SET structure (HashSet + comparer + the 4 loopback
literals) but does NOT exercise the guard FUNCTION - the `.Contains()` call, the `^127\.` / `^::1$` regex
branches, and the shortname-alias branch. A regression that keeps the set intact but breaks the function
(e.g. `.Contains()` -> `-ceq`, a dropped regex branch, an inverted return) would pass the parity test and
still reopen the wrong-box hole. This design adds the missing end-to-end behavioral coverage - the test that
would have caught the P2 directly.

## Surface (one NEW test file; ZERO production code changed)
`tests/SelfGuard.HostIsSelf.Tests.ps1` (UTF-8 BOM). For each of the 12 modules, discover its
`Test-*HostIsSelf` function in module scope (same `Get-Command -Name 'Test-*HostIsSelf'` +
`$_.ModuleName -eq $mod.Name` filter idiom the parity test proved correct) and assert:
- **SELF (exact):** `Test-*HostIsSelf $env:COMPUTERNAME` -> `$true`.
- **SELF (case-variant - THE P2 SCENARIO):** both `Test-*HostIsSelf ($env:COMPUTERNAME.ToUpper())` AND
  `...ToLower()` -> `$true`. Asserting BOTH guarantees the case-insensitive path is exercised on ANY box
  regardless of the stored casing (a hostname is never all-digits, so at least one differs from the seed).
- **SELF (loopback literals):** `127.0.0.1`, `localhost`, `::1` -> each `$true`.
- **FOREIGN:** a name that cannot be this box - `'DEFINITELY-NOT-THIS-BOX-zzq9'` -> `$false` (guards against
  an over-broad guard that returns true for everything, which would silently drop every real target).
- **EMPTY/whitespace:** `''` -> `$false` (every guard early-returns false on blank).

## Risks / non-goals
- **Zero production risk** - additive test only; no `.psm1` touched.
- **No live-domain dependency** - uses only `$env:COMPUTERNAME` and loopback literals, all resolvable on the
  dev box with no AD. The FQDN/NIC-IP self-match branches are host-specific -> still pilot-observable, not
  asserted here (documented).
- **Complements, does not duplicate, the parity test** - that one pins the SET; this one pins the FUNCTION
  behavior. Together they bracket the P2 class from both ends.
- The FOREIGN probe uses a fixed improbable literal; it is theoretically not self unless someone names their
  box `DEFINITELY-NOT-THIS-BOX-zzq9` - accepted (documented in-file).

## Test plan
- The file IS the test. Run standalone + full suite -> green (815 + the new cases). PS 5.1 parse-clean, BOM.
- Prove it bites: the implementer confirms that reverting the loop-3 comma fix in one module flips that
  module's case-variant assertion RED (behavioral proof, distinct from the parity test's set-level proof),
  then reverts - no production change committed.
