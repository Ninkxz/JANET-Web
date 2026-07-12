# Fable 5 Review - Loop 3 of 8 - 2026-07-12

Scope: everything since the loop-2 audit (`git diff 974329e..HEAD`) - two commits, `fe9d224` (3 cheap P3
hardenings: fail-closed SHA256 pin on empty hash, `-LiteralPath` on the tamper-branch delete, per-NIC
try/catch in `Get-WptLocalIdentity`) and `8327c0d` (the same per-NIC isolation propagated to the other 11
identity helpers). 13 files: 12 `.psm1` + `docs/design-loop2.md`. Four reviewers - two Opus deep-dives (the
fail-closed pin data-path; the 11-file NIC-parity transform), one Sonnet blast-radius sweep, one Opus
re-verification of all 11 prior fixes. The discipline this iteration: "did the mechanical hardening break a
real dispatch flow, mis-nest a `continue`, or blank an identity set."

**Rating (delta audit): GREEN.** The two commits under review introduced no P1/P2 - all four reviewers
independently CLEAN, zero regressions, no weakened guards. **BUT the DESIGN-step parity test surfaced a
pre-existing P2 (below), fixed this same iteration** - so the iteration's net finding is **1 P2 found + fixed**.

> ## ADDENDUM - P2 found during the DESIGN step (pre-existing, fixed in `80b2cb5`)
> Building the identity-parity lock test (design-loop3) exposed a real self-guard degradation the delta-audit
> could not see (it predates loop-2, living in the helpers' return statements, untouched by fe9d224/8327c0d):
> **11 of 12 `Get-*LocalIdentity` helpers returned their `OrdinalIgnoreCase` HashSet BARE** (`return $set`).
> PowerShell unrolls a returned non-string `IEnumerable` to `Object[]`, so every caller's
> `$self.Contains($Target)` ran against a plain array - whose `.Contains()` is case-SENSITIVE - silently
> defeating the comparer. Verified directly: all 12 `Test-*HostIsSelf` use the `.Contains()` METHOD (not the
> case-insensitive `-contains` operator), so a dispatcher hostname/FQDN typed in non-matching case (routine on
> case-insensitive Windows) would NOT be recognized as self, and a destructive action (reboot / install /
> cert-push / C2C-fix) could run against the JANET server itself mid-wave. IP-literal (`^127\.`, `^::1$`, NIC-IP
> digits) and same-case paths still matched -> P2, not P1. `remoteadmin.psm1` was the ONLY correct one
> (`return ,$set`, with a comment at :137-139 naming this exact gotcha); the pattern was copied to 11 modules
> without the guarding comma. **Fix:** propagated the unary-comma idiom to both return sites (cached-guard +
> final) in all 11. The new `tests/SelfGuard.IdentityParity.Tests.ps1` was RED for 11/12 before, green for 12/12
> after (full suite 803 -> 815). This is the single most valuable finding of the loop so far - a genuine
> self-guard fail-OPEN, caught by test-driven design.

## What was verified (evidence, not assertion)
- **Fail-closed pin is safe (no false-negative).** `Resolve-C2cDefenderPackage` sets `Sha256` and `Path` in
  the SAME expression on the OK branch (`c2c.psm1:2880`); the two reject branches set BOTH empty. There is no
  branch that arms the offline rung (`if ($OfflineDefPath ...)` at `:2446`) with an empty pin, so the new
  `if ((-not $ExpectHash) -or ...)` abort can never fire on a legitimate package - it only fails closed on a
  hypothetical mis-wire. Arg/param alignment re-counted: **19 `AddArgument` (`:3222-3226`) === 19 params
  (`:1403`)**; inner block 3===3 (`:2450-2451`). No drift from the loop-2 edits.
- **`continue`-in-nested-`try` is correct - EMPIRICALLY confirmed on this box's PS 5.1** (5.1.26100.8655):
  `continue` is a `FlowControlException` that a general `catch {}` does not intercept, so the per-adapter
  `continue` still advances the `foreach ($nic)` and is not swallowed by the new inner catch. No infinite loop,
  no skipped `$set.Add`.
- **Identity sets are additive-only and now uniform.** All base identity classes (COMPUTERNAME/localhost/
  loopback literals, `GetHostName`, FQDN, DNS `GetHostAddresses`) sit BEFORE and OUTSIDE the NIC loop -
  untouched. Programmatic count: all **12** helpers (11 + wpt) now carry exactly one of each of the 5 identity
  classes - the residual self-guard parity gap is closed. Cache-var names consistent per file (no rename typo
  that could return an empty set).
- **Blast radius contained.** Exactly the 13 expected files changed - no view `.js`, no engine action, no
  manifest, no test. All 12 modules `ParseFile` clean + `Import-Module -Force` + `Get-JanetToolManifest`
  non-empty. Diff grep for `Invoke-Expression` / string-built commands / `innerHTML` / unanchored host-cert
  `-match` / weakened confirm-words / removed self-guard: **none**.
- **All 11 prior fixes CLOSED-AND-CLEAN at HEAD** (loop-1 1-7 + loop-2 8-11): mpam gate rungs + anchored
  MS-signer regex, PkiRdp Server-Auth EKU + HasPrivateKey + FQDN-anchored match + bind-before-clear, Java
  vendor gate + strict-GUID msiexec, BitLocker escrow-first no-leak, MDE expiry advisory, SHA256 pin,
  adto `isRunning()`, and the fail-closed pin / `-LiteralPath` / per-NIC guards. No guard disturbed.

## P3 (priority-ordered)

**FIX (cheap, no-risk):**
1. **`c2c.psm1:2473` - the `finally { Remove-Item $Pkg ... }`** cleanup still uses positional `-Path`, while
   its sibling early-return delete at `:2460` was hardened to `-LiteralPath` in loop-2. Inert today (`$Pkg`
   is the fixed literal `C:\Windows\Temp\mpam-fe.exe`, not attacker-controlled), but a consistency gap two
   reviewers independently flagged. Trivial: add `-LiteralPath`.

**DOCUMENT as accepted / deferred (not fixing this iteration):**
2. **`beta.psm1` ships without a UTF-8 BOM** (first bytes `23 20` = `# `). Pre-existing (non-BOM at `974329e`
   and earlier `2490c87`), NOT regressed by loop-2. PS 5.1 reads it correctly today because the file is pure
   ASCII, but the suite standard is BOM-on-every-`.ps1`. Queued for a later loop as a standalone encoding fix
   (re-encoding is a whole-file diff - keep it off a hardening commit). Note: adding a BOM is safe only if the
   file stays ASCII; verify before applying.
3. Prior documented fail-safe residuals unchanged and re-accepted: Java `$javaKey` normalizer granularity
   (`design-loop1`/`loop2` docs), BitLocker resume skip on non-domain hosts (pilot note), PkiRdp first-label
   host match (far tighter than the prior unanchored substring). All fail-safe (under-action, never wrong
   action); risk > reward for a P3-for-P3 change.

## Verdict
Loop-2's hardening did exactly what it claimed - strictly additive parity + fail-closed tightening, identical
behavior on healthy hosts, and it genuinely closed the fail-OPEN NIC-enumeration case. Nothing to remediate
beyond the one-line `finally` consistency tidy.
