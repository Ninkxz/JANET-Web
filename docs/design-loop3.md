# Design - Loop 3 - Lock the self-guard identity-set parity with a test

## Goal
Loops 1-3 unified the wrong-box self-guard across all 12 tools: every `Get-*LocalIdentity` helper now
returns the same 5 identity classes, and each iteration's re-verification agent has hand-confirmed that
by hand. Nothing in the Pester suite ASSERTS it. A future edit that drops an identity class from one
helper (e.g. removes the unconditional loopback-literal line, or renames the `$set` var so a partial set
returns) would silently reopen the fail-OPEN gap - a pasted own-identity target slipping the self-guard -
and the suite would stay green. This design cements the invariant we spent three loops establishing.

## Surface (one NEW test file; ZERO production code changed)
`tests/SelfGuard.IdentityParity.Tests.ps1` (UTF-8 BOM). For each of the 12 modules that ship a
self-guard identity helper (acas, beta, c2c, certdeploy, pkginstall, remoteadmin, restart, secureboot,
upr, winrmbridge, winupgrade, wpt):
1. `Import-Module -Force -PassThru`, then DISCOVER the helper by pattern inside the module's own session
   state (`& $mod { Get-Command -CommandType Function -Name 'Get-*LocalIdentity' }`) rather than hardcoding
   12 differing function names - self-maintaining if a name changes.
2. Invoke it in module scope and assert the returned set is non-empty AND `.Contains()` each of the
   UNCONDITIONAL base identities every helper builds regardless of host/NIC state:
   `$env:COMPUTERNAME`, `localhost`, `127.0.0.1`, `::1`. (These four are the loopback-literal seed present
   in all 12 - safe to assert on any host, including this dev box, with no live domain.)
3. Assert the set is a case-insensitive `HashSet[string]` (the OrdinalIgnoreCase comparer is load-bearing:
   an operator pasting `LOCALHOST` or a mixed-case hostname must still match self).

## Risks / non-goals
- **Zero production risk** - additive test only; no `.psm1` touched.
- **No live-domain dependency** - asserts only the unconditional literals, not DNS/FQDN/bound-NIC entries
  (those vary per host and are pilot-observable, not unit-assertable). The per-NIC throw path still can't
  be faithfully faked without a flaky adapter -> remains pilot-only, documented.
- **Discovery, not hardcoding** - if a module legitimately renames its helper the test follows it; if a
  module LOSES its helper entirely (parity regression) the discovery returns null and the test FAILS loudly,
  which is exactly the signal we want.
- Non-goal: consolidating the 12 near-duplicate helpers into one shared function (bigger refactor, deferred
  in design-loop2). This test makes that future consolidation SAFE by pinning the contract first.

## Test plan
- The new file IS the test. Run it standalone + as part of the full suite -> must be green (803 + the new
  cases). PS 5.1 parse-clean, BOM present.
- Sanity: temporarily break one helper locally (drop a base identity) and confirm the test goes RED, then
  revert - proving it actually guards the invariant (done by the implementer, not committed).
