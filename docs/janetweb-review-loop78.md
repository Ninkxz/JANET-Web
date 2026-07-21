# JANET Web — review loop 78 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-77 → **GREEN**. Baseline: loop-77 authoritative **1524**.

## Self-review of loop-77 (c2c Mass-Fix harvest hint) — GREEN
Additive: `$auditResult` hoisted to the top of `$emitResult` (a pure move — same value), `$hint` computed only
for a `Failure` host, attached to a `Hint` row field + an err log (`FIX:`); FIXED/NOCHANGE hosts untouched; raw
`$res.Detail` preserved. Full c2c suite (284) + full suite (1524) green. Nothing to reopen.

## Workstream: wire the hint into certdeploy (9th tool; destructive DEPLOY) — LAST on the primary list
certdeploy's per-host DEPLOY results use `$res.Status`/`$res.Detail`; the raw error lands in `.Detail`
(`"Session: <exception>"`, `"Probe: <exception>"`, `"worker error: …"`, `"per-host timeout …"`, the wrong-box
guard failure). The destructive **deploy** harvest is `$emitResult` (`:1331`), and its `$auditResult` switch
already classifies each host's status (`Failure` = the default bucket: FAILED / NOT VERIFIED / REJECTED (non-CA)).

### Fix (certdeploy 1.4.2 → 1.4.3) — purely additive
Hoisted `$auditResult = switch ([string]$res.Status) {…}` above the row build (was computed just after the row,
switching on `$row.Status` — same value), so the hint can classify before the row is emitted. On a host whose
audit result is `Failure`, the raw `$detail` runs through `Get-JanetTroubleshootHint -Server $res.Host` and:
(1) attaches to the row's `Hint` field; (2) emits an err log `"$host : $status - $detail | FIX: $hint"`. Raw
detail preserved (the existing info/ok/warn/error per-host log line is unchanged); a ROOTS INSTALLED / ALREADY
PRESENT / SKIPPED / OFFLINE host computes no hint. certdeploy imports `JanetWeb.troubleshoot` at module scope.
(Scoped to the deploy harvest; the read-only `check`/`scan` fan-outs surface CHECK ERROR rows with their own
emission shapes — noted as follow-ups.)

### Tests
+4 (`CertDeploy.Tests.ps1`, static analysis — the harvest runs inside the fan-out over a real RunspacePool, no
swappable-worker seam; the hint's behavior is proven behaviorally in `Troubleshoot.Hint.Tests.ps1`): exact
`1.4.3` pin; certdeploy imports the engine; the `$hint` is computed only for `$auditResult -eq 'Failure' -and
$detail` and the row carries `Detail=$detail; Hint=[string]$hint`; the err log is gated on `$hint` and carries
`FIX: $hint`. loop-49's exact pin (`1.4.2`) migrated to a floor. Full certdeploy suite (6 files, 59) green.

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), pkginstall (73), upr (74), dhcp (75), secureboot (76), c2c (77),
**certdeploy (78)** — **9 remote-acting tools; the primary-list rollout is COMPLETE.** Follow-ups (next loops):
c2c scan/version harvests, certdeploy check/scan CHECK ERROR rows, secureboot read-only scan CHECK ERROR, **fold
restart's numeric-code `Get-RrsShutdownErrorHint` signatures into the shared engine and have restart delegate**
(restart is the last ad-hoc mapper), per-candidate upr failures, enrich raw detail where a tool swallows it, grow
the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec certdeploy fork shares the deploy harvest — mirror the hint wire (import
  `JanetWeb.troubleshoot`, hoist `$auditResult`, `$hint` on the `Failure` audit result, `Hint` row field +
  `FIX:` err log). Plus the whole `JanetWeb.troubleshoot.psm1` engine mirror to X:\shh-JANET (still pending —
  tracked since loop 70).
