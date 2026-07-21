# JANET Web — review loop 77 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-76 → **GREEN**. Baseline: loop-76 authoritative **1520**.

## Self-review of loop-76 (secureboot enable-harvest hint) — GREEN
Additive: hint on the four-way failure condition (`-not $isOk/$isSkip/$isUnknown/$isDryR -and $res.Error`), attached
to a `Hint` row field + the existing err log (`FIX:`); ok/skip/unknown/dry-run untouched; full secureboot suite (47)
green. Nothing to reopen.

## Workstream: wire the hint into c2c (8th tool; destructive Mass-Fix)
c2c per-host results use `$res.Status`/`$res.Detail` (the raw error lands in `.Detail`, e.g. `"Session:
<exception>"`, `"Probe: <exception>"`, `"wrong-box guard probe failed: …"`). The destructive **Mass-Fix / run-all**
harvest is `$emitResult` (`:3135-3156`), and `Get-C2cHostAuditResult` already classifies each host's status
(`Failure` for OFFLINE/ERROR/FAILED/PARTIAL, etc.).

### Fix (c2c 1.15.8 → 1.15.9) — purely additive
Hoisted `$auditResult = Get-C2cHostAuditResult $res.Status` to the top of `$emitResult` (was computed just before the
audit — same value), so the hint can classify before the row is emitted. On a host whose audit result is `Failure`,
the raw `$res.Detail` runs through `Get-JanetTroubleshootHint -Server $res.Host` and: (1) attaches to the row's `Hint`
field; (2) emits an err log `"$host : $status - $detail | FIX: $hint"`. Raw detail preserved; a `FIXED`/`NOCHANGE`
host computes no hint (its detail is the report, not an error). c2c imports `JanetWeb.troubleshoot`. (Scoped to the
Mass-Fix harvest; c2c's scan/version/other fan-outs have their own emissions — noted as follow-ups.)

### Tests
+4 (`C2c.AuditResult.Tests.ps1`, static analysis — the harvest runs inside the fan-out over a real RunspacePool):
exact `1.15.9` pin; c2c imports the engine; the `$hint` is computed only for `$auditResult -eq 'Failure' -and
$res.Detail` and the row carries `Hint=[string]$hint`; the err log is gated on `$hint` and carries `FIX: $hint`.
loop-47 pin floored. **loop-37 lesson:** `C2c.AuditResult` (14) green; the full c2c suite ran in the background to
confirm the shared harvest change regressed nothing.

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), pkginstall (73), upr (74), dhcp (75), secureboot (76), **c2c (77)** —
8 remote-acting tools. Next: **certdeploy** (the last on the primary list). Then follow-ups: c2c scan/other harvests,
secureboot scan CHECK ERROR, fold restart's numeric-code hints into the shared engine, per-candidate upr failures,
enrich raw detail, grow the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec c2c fork shares the Mass-Fix harvest — mirror the hint wire (import
  `JanetWeb.troubleshoot`, `$hint` on the `Failure` audit result, `Hint` row field + `FIX:` err log).
