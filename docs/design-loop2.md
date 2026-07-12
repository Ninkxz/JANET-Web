# Design - Loop 2 - Per-NIC isolation in every self-guard identity set (parity sweep)

## Goal
The loop-2 FIX hardened `Get-WptLocalIdentity` so one flaky/virtual NIC can't abort the whole
bound-NIC IPv4 enumeration. The other **11** tool modules that build a local-identity set
(`acas`, `beta`, `c2c`, `certdeploy`, `pkginstall`, `remoteadmin`, `restart`, `secureboot`, `upr`,
`winrmbridge`, `winupgrade`) all carry the **identical** un-hardened block: a single outer
`try { foreach ($nic ...) { ... } } catch {}`. If any adapter throws inside the loop (a half-torn-down
virtual/VPN NIC returning on `GetIPProperties()`), the `catch` swallows it and the **remaining** NICs
are never enumerated - so the host's own bound IPv4 addresses can be MISSING from the identity set.

Why that matters: the identity set is what the wrong-box self-guard uses to recognize "this target IS
me." A missing bound IP means an operator who pastes the host's own IP literal as a target slips the
self-guard and the tool treats its own box as a remote host. Fail-safe would be to INCLUDE more, not
fewer, identities; a truncated set fails **open** for that one paste path. Closing it fleet-wide is a
pure hardening parity sweep - the exact change already reviewed and shipped for WPT.

## Surface (11 `.psm1` files; identical minimal transform, additive)
In each module's identity helper, wrap the **loop body** (the `OperationalStatus` check + inner
`foreach ($ua ...)`) in its own `try { ... } catch {}` inside `foreach ($nic in ...GetAllNetworkInterfaces())`,
leaving the existing outer `try/catch` in place (belt and suspenders). `continue` still targets the
`foreach` (a `try` does not intercept it). Base identity entries (COMPUTERNAME / FQDN / DNS / loopback)
and the `HashSet` logic are untouched. Byte-for-byte the same edit as `fe9d224` made to `wpt.psm1`.

## Risks / non-goals
- **No guard weakened** - strictly widens the cases where enumeration completes; can only ADD
  identities to the self-guard set, never remove. A per-NIC throw is now skipped instead of aborting.
- **Not a behavior change on healthy hosts** - with no throwing NIC the output set is identical.
- **No new dependency, no new surface** - same reflection API already in every module.
- Non-goal: refactoring the 12 near-duplicate helpers into one shared function. That's a bigger,
  riskier consolidation (module-scope/pool-runspace injection concerns) - deferred, noted here.

## Test plan
- PS 5.1 parse-clean (`PSParser::Tokenize` = 0) + `Import-Module -Force` for all 11 edited modules.
- UTF-8 BOM preserved on every file.
- Full Pester suite green (the identity helpers are exercised by the existing self-guard tests; the
  per-NIC path has no healthy-host behavior change, so no new unit test is warranted - a throwing NIC
  can't be faithfully faked without a live flaky adapter -> that specific path is pilot-observable only).
