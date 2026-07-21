# JANET Web — review loop 46 (2026-07-21)

Fable-inline. Self-review of loop-45 → **GREEN**. Baseline: loop-45 authoritative **1373** green (confirmed).

## Self-review of loop-45 (c2c Monitoring installed-half fail-close) — GREEN
`Get-C2cMonitoringVerdict` (FAIL/NOT VERIFIED/FIXED/NOCHANGE) matches the inline mirror (static assert); the
service-absent branch is unchanged (its installed-checks were already present); only the service-exists branch
gained the NOT VERIFIED gate. 85 c2c + 1373 confirm no regression. Nothing to reopen.

## Workstream: close c2c item53 (F3) — an unreadable signature age is `$null`, not a false-fresh 0
The highest-rated remaining c2c item, on the safety-critical scan READY verdict (the quarantine go/no-go).

### Finding (CONFIRMED code — re-verified in-code)
The AntiMalware scan (`:830`) and fix (`:1914`) derive the Defender signature age in hours from
`MpComputerStatus`. When `AntivirusSignatureLastUpdated` is missing, both fall back in an `else` to
`[int]$mp.AntivirusSignatureAge * 24` — and **`[int]$null` coerces to 0** (no throw), so an *unreadable*
signature age (both the timestamp and the age null) manufactured a 0-hour "fresh" age that passed the
AntiMalware freshness gate → scan PASS → **READY**, defeating the downstream `$null -ne $ageHours` guard (0 is
not null). Trigger is SPECULATIVE (needs a partial `MSFT_MpComputerStatus` with both fields null), but the code
is objectively wrong — a coercion manufacturing a false-fresh signal on the operator's quarantine go/no-go.

### Fix (c2c 1.15.6 → 1.15.7)
Both sites now guard the fallback: `elseif ($null -ne $mp.AntivirusSignatureAge)`, so a null age stays `$null`,
which the freshness gate treats as stale (fail-closed → the pillar FAILs / the host doesn't read READY). New
pure `Get-C2cSigAgeHours(LastUpdated, SignatureAge)` is the canonical computation (datetime wins; else a real
age → days×24; else `$null`); the module-less scan + fix workers mirror the datetime/age logic inline. Same
`[int]`-cast-guard hardening as acas's spec-exec.

### Version + tests
- `C2c.SigAge.Tests.ps1` (NEW, 7): the pure helper (null age → null [the fix], real age → days×24, a genuine 0
  still allowed, a datetime winning over the age fallback) + a static assert both sites are null-guarded and the
  unguarded `[int]$mp.AntivirusSignatureAge` coercion is gone; exact pin 1.15.7 (Monitoring exact pin → floor).
- c2c sig-age/Monitoring/AntiMalware/taskord set **71** green — the existing `AntivirusSignatureAge * 24`
  fallback scan tests (which use a real age, so the `elseif` still fires) pass unchanged; grep clean.

## Remaining c2c backlog
item54 (F4, AntiMalware fixer NOCHANGE on unknown age — the fixer sibling of this scan fix, LOW), item55 (F7,
audit PARTIAL→Success, LOW), item56 (F8, version ordinal fallback, read-only), item57 (F9, Firewall empty,
speculative); F2/F6 refine the known items 22/24 tally/rollup cluster. The c2c tail is now low/read-only —
loop 47 weighs a fresh dive on an un-reviewed tool vs. these.

## SECRET parity
- **SECRET parity:** the JanetSec c2c fork shares the AntiMalware scan + fix — mirror `Get-C2cSigAgeHours` and
  the two inline `elseif ($null -ne …AntivirusSignatureAge)` guards.
