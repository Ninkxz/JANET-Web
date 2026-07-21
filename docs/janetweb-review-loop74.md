# JANET Web — review loop 74 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-73 → **GREEN**. Baseline: loop-73 ~**1508**.

## Self-review of loop-73 (pkginstall harvest hint) — GREEN
Additive: `$isFail` is the inverse of the count switch, `$hint` computed only on a failure, attached to a `Hint` row
field + the existing err log (`FIX:`); ok/deferred/skipped untouched; full pkginstall + FixVerify3 PSADT suites green.
Nothing to reopen.

## Workstream: wire the hint into upr (destructive uninstall; 5th tool)
upr's fan-out harvest (`:1245-1272`) is more nuanced than the others: the per-host `$EmitRows` callback returns a
**multi-row** result (a host can have several candidate products) plus `.ok`/`.detail`/`.auditResult`. The host-level
connection failure is in `$res.Error` (unreachable / worker error, set at `:1249`/`:1254`).

### Fix (upr 1.2.4 → 1.2.5) — purely additive
`$ok = [bool]$emit.ok` is hoisted above the row loop so the hint can ride with the rows. On a host-level failure
(`(-not $ok) -and $res.Error`), the raw error is run through `Get-JanetTroubleshootHint -Server $res.Host` and: (1)
attached to **each** emitted row's `Hint` field (guarded `$row -is [hashtable]`); (2) emitted as an err log
`"$host : $err | FIX: $hint"` — upr's harvest previously only emitted a *warn* for a worker error, so a recognized
host failure now gets a proper err line with the fix. Raw error preserved; ok hosts compute no hint. upr imports
`JanetWeb.troubleshoot`. (Scoped to the host-level error; a per-candidate uninstall failure carries its error in the
candidate result, not `$res.Error` — a later enrichment could hint those too.)

### Tests
+4 (`Upr.VerifyResult.Tests.ps1`, static analysis): exact `1.2.5` pin; upr imports the engine; the hint is computed
only for `(-not $ok) -and $res.Error` and attached to `$row['Hint']`; the err log is gated on `$hint` and carries
`FIX: $hint`. loop-64 Describe floored. **loop-37 lesson:** ran the full upr suite (**44** green — the harvest is
shared by upr's scan/uninstall actions; the change is additive).

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), pkginstall (73), **upr (74)** — the two most-used tools + remoteadmin
(generic fan-outs), the package installer (own harvest), and now the unsupported remover (own multi-row fan-out).
Next: dhcp, secureboot, c2c, certdeploy. Also open: hint per-candidate upr failures; enrich raw detail; grow the
signature set.

## SECRET parity
- **SECRET parity:** the JanetSec upr fork shares the fan-out harvest — mirror the hint wire (import
  `JanetWeb.troubleshoot`, `$hint` on `(-not $ok) -and $res.Error`, `Hint` row field + `FIX:` err log).
