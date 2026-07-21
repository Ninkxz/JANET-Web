# JANET Web — review loop 76 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-75 → **GREEN**. Baseline: loop-75 authoritative **1516**.

## Self-review of loop-75 (dhcp hint upgrade) — GREEN
The 5 dhcp catches swapped from the thin `Get-JanetWsmanAuthHint` to the shared `Get-JanetTroubleshootHint` (drop-in
signature); the dead function retired; behavior-preserving for recognized-auth errors, strictly adds coverage; 68
dhcp-touching + 1516 full green. Nothing to reopen.

## Workstream: wire the hint into secureboot (7th tool; destructive enable path)
secureboot has two harvests — the read-only scan (`:1009`, `CHECK ERROR` verdict) and the destructive **ENABLE**
harvest (`:1262-1296`). The enable harvest carries the raw WinRM/auth/BIOS error in `$res.Error`, with a four-way
classify (`$isOk`/`$isSkip`/`$isUnknown`/`$isDryR`) already computed.

### Fix (secureboot 1.6.4 → 1.6.5) — purely additive
On a real enable failure (`(-not $isOk) -and (-not $isSkip) -and (-not $isUnknown) -and (-not $isDryR) -and
$res.Error`), the raw error runs through `Get-JanetTroubleshootHint -Server $res.Computer` and: (1) attaches to the
row's `Hint` field; (2) appends `| FIX: $hint` to the existing per-host err log. Raw error preserved; ok/skip/unknown/
dry-run rows compute no hint. secureboot imports `JanetWeb.troubleshoot`.

### Tests
+4 (`Secureboot.Scan.Tests.ps1`, static analysis — the enable harvest runs inside the fan-out over a real
RunspacePool, no swappable seam): exact `1.6.5` pin; secureboot imports the engine; the `$hint` is computed only for
the four-way-failure condition and the row carries `Hint = [string]$hint`; the err log appends `| FIX: $hint`.
loop-59 Describe floored. **loop-37 lesson:** ran the full secureboot suite (**47** green — the enable harvest is
shared by every enable run; the change is additive and touches neither the scan nor the classify).

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), pkginstall (73), upr (74), dhcp (75), **secureboot (76)** — 7 remote-
acting tools. Next: c2c, certdeploy. Also open: secureboot's read-only **scan CHECK ERROR** path (a probe failure
could carry a WinRM error worth hinting); fold restart's numeric-code hints into the shared engine; per-candidate upr
failures; enrich raw detail; grow the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec secureboot fork shares the enable harvest — mirror the hint wire (import
  `JanetWeb.troubleshoot`, `$hint` on the four-way failure condition, `Hint` row field + `FIX:` err log).
