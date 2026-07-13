# Design - Loop 36 - Desktop self-guard fail-open: `return ,$set` across all identity helpers

Highest-value backlog item (loop-29 sweep rows 9/10). Every Desktop `Get-*LocalIdentity` helper builds a
`HashSet[string]` with an OrdinalIgnoreCase comparer, and each `Test-*HostIsSelf` caller does
`$self.Contains($Target)`. But all 7 current Desktop tools `return $set` / `return $script:XxxLocalIdentity`
**bare** - PowerShell auto-enumerates the HashSet on return, so the caller receives a plain `Object[]`,
losing the case-insensitive comparer. `Object[].Contains()` (System.Array IList) is ordinal case-SENSITIVE,
so a dispatcher hostname supplied in a different case than `$env:COMPUTERNAME` (e.g. pasted `hades` vs
`HADES`) is NOT recognized as self -> the self-guard FAILS OPEN and a destructive remediation can hit the
operator's own console. This is the integrity of the ENTIRE Desktop self-guard layer (reboot, uninstall,
message, BitLocker, spec-exec, Custom Command, install-updates all depend on it).

The Web side already does this correctly (`return ,$set` with an explicit "comma stops PowerShell unrolling"
comment, e.g. acas.psm1:2538, upr.psm1:1552). So this is **Desktop-only**; ledger rows 9/10 close CLOSED-BOTH
(Web already-correct, Desktop fixed).

## Affected (both the cache-hit AND fresh return paths in each):
| Tool | cache-hit | fresh |
|------|-----------|-------|
| WorkstationPatchingTool_6.5.27 | 1657 | 1675 |
| ACAS Nemesis Tool_1.10.16 | 2290 | 2300 |
| C2CNemesisTool_2.4.5 | 2358 | 2376 |
| UnsupportedProductRemediator_1.1.5 | 283 | 301 |
| RemoteMessageTool_1.3.4 | 125 | 143 |
| RemoteRestartScheduler_1.6.1 | 1800 | 1810 |
| WindowsUpgradeTool_0.5.1 | 3678 | 3699 |

## Fix (per tool - mechanical, low-risk):
1. `return $set` -> `return ,$set` and `return $script:XxxLocalIdentity` -> `return ,$script:XxxLocalIdentity`
   (the unary comma wraps the HashSet in a 1-element array so it is NOT unrolled; the caller keeps the typed
   HashSet + its OrdinalIgnoreCase comparer). Mirror the Web comment.
2. (row 10, P3 robustness) Nest the per-NIC `try/catch` INSIDE the `foreach ($nic in ...)` loop where the
   helper enumerates bound NIC IPv4s, so one NIC's GetIPProperties() throw skips only that NIC instead of
   aborting the whole enumeration (which would silently drop later NICs' IPs from the self set - a smaller
   fail-open). Keep the outer try too. Skip this sub-fix for any helper that has no NIC-enumeration block
   (e.g. an ACAS variant that mirrors the Web restart.psm1 design).

## Approach
One Opus agent applies the 2-line return fix (+ NIC try/catch nesting where present) to all 7 tools, each
version-bumped (new versioned file, old archived to Tools\Archive\, JANET_Config.json Script mapping updated,
header + $version var + .CHANGELOG bumped), PS 5.1 parse-clean + BOM. The KEY validation (no Pester on the
monoliths): after re-source, `(Get-XxxLocalIdentity).GetType().Name` is `HashSet\`1` (NOT Object[]), and a
case-mismatched self name -> `Test-XxxHostIsSelf` returns True. I gate: confirm every return flipped, the
HashSet type is preserved, config maps to the new versions, and no unrelated behavior changed. Web unchanged.
Version bumps: WPT 6.5.28, ACAS 1.10.17, C2C 2.4.6, upr 1.1.6, message 1.3.5, RRS 1.6.2, WinUpgrade 0.5.2.
