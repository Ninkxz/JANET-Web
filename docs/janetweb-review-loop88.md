# JANET Web — review loop 88 (2026-07-22)

**Theme: verify honesty (the fix that never fired).** Fable-inline + TWO Fable subagents (a self-review of loop
87 + a fresh wpt deep-dive). Baseline: loop-87 authoritative **1599**.

## Self-review of loop-87 — **P1: my loop-87 fix was RUNTIME-INERT (and so was the bug it "fixed")**
The self-review EXECUTED the generated probe against the real Edge key and found the fix never fires:
`$mod = $key.LastWriteTime` where `$key = Get-Item <registry-path>` — **`Get-Item` on a registry key returns
`Microsoft.Win32.RegistryKey`, which has NO `LastWriteTime` member** (verified: the property is absent, value
null). So `$mod` is ALWAYS `$null`, the verdict short-circuits at `if ($null -eq $mod) { $null }`, and every
Chrome/Edge verify on every host returns `Verified=$null` / `LastUpdated='n/a'` — pre AND post loop 87. My loop-87
ClientState/`LastInstallerResult` logic was correct but unreachable; the pre-existing "mtime-only false-clean" it
claimed to fix also never fired (fail-SAFE — always indeterminate, never a false green). The loop-87 tests were
static + canonical-only and NEVER executed a generated probe against a key — the exact static-test blind spot.

### Fix (acas 1.11.16→1.11.17, wpt 6.8.16→6.8.17) — a REAL timestamp source
Grounded in the live registry: the sibling `ClientState\{GUID}` carries `LastCheckSuccess` (a unix-epoch value =
the last SUCCESSFUL update check). Both probes now derive `$mod` from `LastCheckSuccess`
(`(New-Object DateTime 1970,1,1,0,0,0,Utc).AddSeconds([double]$lcs).ToLocalTime()`) instead of the dead
`Get-Item.LastWriteTime`, keep the `LastInstallerResult=0` success gate, and **fold in the loop-87 self-review's #2
and #3**: the empty-string guard (`"$v" -ne ''`) and a range-safe cast (`[int64]` / `TryParse` — a UInt32 DWORD
overflows `[int]`). **Verified END-TO-END against a sandbox HKCU key** (the test the self-review said was missing):
fresh+success→`$true` with a REAL `LastUpdated` date, fresh+failure→`$false`, stale→`$false`, no-signal→`$null`,
on BOTH acas and wpt. The Chrome/Edge verify now actually works.

### Tests
`Acas.ClientVerify.Tests.ps1` +5 (a new Describe that **EXECUTES** a generated probe against a real HKCU sandbox
key — creates `...\Clients\{G}` + `...\ClientState\{G}`, runs the acas AND wpt probes, asserts the verdict, cleans
up). Static assertions updated to require the `LastCheckSuccess` read and assert the dead `$key.LastWriteTime` line
is gone. `Wpt.C2rVerify.Tests.ps1` updated + pin 6.8.17. loop-87 acas (1.11.16) + wpt (6.8.16) pins re-pinned to the
new versions. **loop-37 lesson:** touches acas + wpt — ran both + the full suite.

## wpt deep-dive (the #1 tool) — findings, ranked; the top P1 DEFERRED
- **P1 (DEFERRED to loop 89, top priority) — `sccm-available` / `sccm-install-available` crash on the row emit.**
  `wpt.psm1:5056/:5097` build `$row = @{ … Type=… }` then `& $send (@{ type='row' } + $row)` — the SAME
  case-insensitive `type`/`Type` duplicate-key `ArgumentException` as the upr P0 (loop 85). EXECUTED-confirmed by
  the agent. On the INSTALL path the crash lands AFTER the destructive CCM trigger → per-item VulnPatched audits
  lost. software-scan already fixed this (renamed to `'Install Type'`, `:5188`); the two SCCM dispatchers were
  missed. Fix (own loop): a case-sensitive emit merge (à la upr's `New-UprRowEvent`, NO JS change) OR rename +
  update `wpt.view.js:2447/2468`. Not this loop — two P1s + a JS-touching change is how incomplete fixes ship.
- **P2 (backlog) — `cleanup-disk` / live `clean-user-apps` have NO wrong-box (DNS-mismatch) guard** while every
  other destructive wpt block does (patch/kb/reg/uninstall/maintenance/…). Profile-DELETING path → stale DNS could
  delete profiles on the wrong machine. (Loop-86-style guard; own loop.)
- **P2/P3 (backlog) — Oracle Java Software-Center verify is freshness-only** (`:1374`, JavaSoft subkey mtime, 30-day
  window, no success/version signal) — same false-clean class, and likely ALSO inert (same `Get-Item.LastWriteTime`
  dead read).
- **P3 (backlog)** — bool-coercion sweep incomplete (`hardlock`/`rebootafter`/`noreboot`/… use raw `[bool]`, so an
  API `"false"` string applies the destructive toggle — loop-11 fixed only `dryrun`); `Get-WptThreadCount` degrades
  garbage to 1 thread (`:534`).

## SECRET parity
- **SECRET parity:** mirror the client-verify REAL-timestamp fix (LastCheckSuccess + LastInstallerResult + range/empty
  guards) to both the acas and wpt SIPR forks. The deferred wpt P1s (sccm type/Type, cleanup-disk DNS guard) also
  apply to the SIPR wpt fork.
