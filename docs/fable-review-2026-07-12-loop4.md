# Fable 5 Review - Loop 4 of 8 - 2026-07-12

Scope: everything since the loop-3 audit (`git diff cd601c3..HEAD`) - three commits: `e85e675`
(`-LiteralPath` on the mpam `finally`), `80b2cb5` (the P2 return-comma fix in 11 identity helpers + the new
`SelfGuard.IdentityParity.Tests.ps1`), `3e27ed3` (the loop-3 report addendum). The functional delta is 22
one-character `,` additions + one new test. Panel right-sized to that delta: one Opus comma-regression
deep-dive, one Sonnet test-correctness + blast-radius sweep, one Opus re-verification of all 12 prior fixes.

**Rating: GREEN.** No P1, no P2. The loop-3 P2 fix is a clean win with zero regressions, the new test is a
correct load-bearing guard, and all 12 prior fixes hold.

## What was verified (evidence, not assertion)
- **`return ,$set` introduced NO regression - clean win.** Every consumer of all 12 helpers was enumerated
  across `modules\` AND `tests\`: all touch the returned set ONLY via `.Contains()` (HashSet-native, now
  correctly case-insensitive), `.Add()`, or pipeline enumeration. No index access (`[0]`), no `.Length`, no
  `+`/`+=`, no `@()`-wrapping, no array-type assumption. Two tests (`RemoteAdmin.Tests.ps1:175` `.Add()`,
  and the WPT dead-assignment) actually REQUIRE a HashSet - the old `Object[]` would have thrown on `.Add()`.
  Empirically confirmed on PS 5.1: `$self = Get-X` receives the actual `HashSet[String]` (Count>0,
  OrdinalIgnoreCase intact), NOT a nested single-element wrapper.
- **The parity test BITES - proven, not assumed.** A throwaway Fixed/Broken harness showed the case-flip
  probe (`.Contains('LOCALHOST') | Should Be $true`) goes RED on a bare-return regression and green with the
  comma; the exact-case membership checks pass either way, so the case-insensitive probe is the real guard.
  The `$_.ModuleName -eq $mod.Name` discovery filter is necessary (helpers auto-export and leak across the
  shared Pester process) and correct - ran live 12/12 green. Pester 3.4-compatible, 12 independent `It`s.
- **Blast radius contained.** `git diff cd601c3..HEAD` = exactly the 11 module return-lines + c2c's `finally`
  `-LiteralPath` + the new test + 2 docs. No view `.js`, no engine action, no manifest. BOM present on all
  changed modules except beta (pre-existing non-BOM, unchanged). All import clean + `Get-JanetToolManifest`
  non-empty. Diff grep for `Invoke-Expression` / `innerHTML` / weakened confirm-word / removed self-guard: none.
- **All 12 prior fixes CLOSED-AND-CLEAN at HEAD** (loop-1 1-7, loop-2 8-11, loop-3 P2 #12): mpam gate rungs +
  anchored MS-signer regex, PkiRdp Server-Auth EKU + HasPrivateKey + FQDN-anchored match + bind-before-clear,
  Java vendor gate + strict-GUID msiexec, BitLocker escrow-first no-leak, MDE expiry advisory, SHA256 pin
  (**19=19** outer / **3=3** inner re-counted, `-LiteralPath` edits shifted nothing), adto `isRunning()`, the
  fail-closed pin, both `-LiteralPath` deletes, per-NIC try/catch on all 12, and the unary-comma on both
  return sites of all 12. The return-comma edits disturbed no base identity entry, DNS/FQDN add, or NIC guard.

## P3 (document only - no fix warranted)
1. **`c2c.psm1:2288` - the Java uninstall msiexec `-ArgumentList` is a single interpolated string**
   (`"/x $($key.PSChildName) /qn /norestart"`), not a literal string array (the loop-1 note called it "array
   args"). **Not a vulnerability**: `$key.PSChildName` is gated at `:2286` by `^\{[0-9A-Fa-f-]+\}$` (hex, dash,
   braces only - no whitespace, quotes, or separators), so the string tokenizes to exactly `/x {GUID} /qn
   /norestart` with zero injectable content. The strict-GUID gate IS the guard; string-vs-array is cosmetic
   here. Converting a destructive msiexec call for zero security gain is a net risk - documented, not touched.
2. Prior fail-safe residuals unchanged and re-accepted: `beta.psm1` pre-existing non-BOM (queued as a
   standalone encoding fix); Java `$javaKey` normalizer granularity; BitLocker resume skip on non-domain hosts
   (pilot note); PkiRdp first-label host match. All fail-safe (under-action, never wrong action).

## Verdict
The loop-3 remediation - a real self-guard P2 - landed cleanly and is now locked by a test that provably
bites. Nothing to remediate this iteration. Proceeding to DESIGN.
