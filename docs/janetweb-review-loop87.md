# JANET Web — review loop 87 (2026-07-22)

**Theme: verify honesty (false-clean).** Fable-inline + a Fable re-verify of loop 86's destructive guard.
Baseline: loop-86 authoritative **1585**.

## Re-verify of loop-86 (kb-install wrong-box guard, a destructive/security path) — **SAFE at runtime**
A Fable re-verify executed the ACTUAL `AcasKbInstallBlock` text in a module-less runspace (production shape) with
shimmed session cmdlets — 14/14 runtime checks passed, no confirmed issues: a mismatch aborts with NO install
firing and cleans up its session (proved `return` from a `try` runs the `finally` — twice); the abort string
parses clean through the real rowOf (`Result=FAIL`, all counts 0, `AcasOkOf`→False); the matching-box /
case-whitespace / shortname / empty-probe / IP-literal flows all proceed correctly; it matches the update-worker
guard verbatim (and is actually stronger — it probes the very session that installs). (It also correctly noticed
and attributed this loop's concurrent acas edits to "a loop-87 session" — the shared-workspace discipline held.)

## Workstream: the mtime-only Chrome/Edge verify was a false-clean (acas 1.11.15→1.11.16, wpt 6.8.15→6.8.16)
`New-AcasClientVerify` (`:185`) and its wpt twin `New-WptUpdateClientVerify` (`:941`) computed
`Verified = (Clients\{GUID} key mtime < 14 days)` — mtime freshness ALONE. Omaha/EdgeUpdate writes `Clients\{GUID}`
on every update CHECK, and a failed/no-op update leaves the OLD `pv`, so a recently-touched host read
`Verified=$true` with an OLD, still-vulnerable version — a false-clean; a verify-only run then lit the PATCHED tile.
Same class loop 40 fixed for Office C2R.

### Fix — mirror the loop-40 C2R pattern: fresh AND the last install SUCCEEDED
Grounded in the real registry on this box: the sibling `ClientState\{GUID}` carries **`LastInstallerResult`** (0 =
the last install succeeded) — the exact analog of C2R's `LastScenarioResult`. Added a canonical
`Get-AcasClientVerified` (pure, testable, same shape as `Get-AcasC2rVerified`): `Verified` is `$true` only when
fresh AND `LastInstallerResult -eq 0`; `$false` when stale or the last install failed; `$null` when no signal
(indeterminate — never a false-clean OK). Both generated remote probes now read the sibling ClientState
(`$p -replace '\Clients\','\ClientState\'`) and mirror the canonical inline. Verified behaviorally: fresh+success→
True, **fresh+failure→False (the fix)**, fresh+no-signal→null, stale→False.

### Tests
`Acas.ClientVerify.Tests.ps1` (NEW, +10, modeled on `Acas.C2rVerify.Tests.ps1`): the canonical `Get-AcasClientVerified`
behaviorally (incl. the false-clean case + REG_SZ "0" tolerance) + a static assertion the acas probe reads the
ClientState/LastInstallerResult gate (and the old mtime-only line is gone from `New-AcasClientVerify` specifically).
`Wpt.C2rVerify.Tests.ps1` +4 (static on the wpt probe + exact 6.8.16 pin). loop-86 acas pin (1.11.15) and the wpt
fan-out pin (6.8.15) floored. **loop-37 lesson:** the change touches acas + wpt — ran both + the full suite.

## Out of scope / backlog
- The **Store-app EXPERIMENTAL verify** (`acas:628`, `Microsoft.WindowsApp`) is a SEPARATE mtime-only case (APPX
  install-folder mtime) — same false-clean class, but a Store app has NO Omaha `ClientState`/`LastInstallerResult`
  analog, so there's no clean success signal; it's an experimental profile. Left as-is; noted as low-priority backlog.
- The two loop-85 self-review latent items (PSCustomObject-row guard in `New-UprRowEvent`; canonical/mirror
  pre==post divergence) remain backlog.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — the client-verify false-clean fix in BOTH the acas fork
  (`Get-AcasClientVerified` + `New-AcasClientVerify`) and the wpt fork (`New-WptUpdateClientVerify`). Both SIPR forks
  likely share the mtime-only shape.
