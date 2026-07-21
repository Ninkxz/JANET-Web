# JANET Web — review loop 73 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-72 → **GREEN**. Baseline: loop-72 ~**1504**.

## Self-review of loop-72 (wpt fan-out hint) — GREEN
Additive: hint computed only on failure, attached to a guarded `Hint` row field + a `FIX:` err log gated on `$hint`;
the audit-detail string is computed once and reused (removed a latent double-eval); ok rows byte-identical; all 182
wpt tests green. Nothing to reopen.

## Workstream: wire the hint into pkginstall (destructive; 4th tool)
pkginstall doesn't use a generic fan-out helper — it has its own harvest loop (`:1042-1068`) processing each host's
`$res` (with `.Status`/`.Detail`/`.Reason`/`.Output`/`.ExitCode`). The failure detail is already assembled at `:1015`
(`$res.Detail`, else `$res.Reason`, else "Unknown remote error").

### Fix (pkginstall 2.5.12 → 2.5.13) — purely additive
After the count switch, the harvest computes `$isFail = ($status -notin @('Success','Success (warnings)','Deferred',
'AlreadyInstalled'))` and, on a failure, runs the best error text (`$detail`, else `$reasonTxt`, else `$outputTxt`)
through `Get-JanetTroubleshootHint -Server $j.Host`. The hint is added to the row as a `Hint` field and appended to the
existing per-host err log (`… | FIX: $hint`). The raw detail/reason/output are preserved everywhere; ok/deferred/
skipped rows compute no hint. pkginstall imports `JanetWeb.troubleshoot`.

### Tests
+4 (`Pkginstall.MsiList.Tests.ps1`, static analysis — matching the wpt fan-out test style, since the harvest runs
inside the module-less fan-out over a real RunspacePool): exact `2.5.13` pin; pkginstall imports the engine;
`$isFail` + `$hint = if ($isFail) { Get-JanetTroubleshootHint … }` + `Hint=$hint` in the row; the err log appends the
`FIX:` hint. loop-63 Describe floored. **loop-37 lesson:** ran the full pkginstall suite (**47** green) + FixVerify3
(the pkginstall PSADT test, **21** green — my harvest change is additive and doesn't touch the worker block).

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), **pkginstall (73)** — the two most-used tools + remoteadmin (generic
fan-outs) and now the destructive package installer (its own harvest). Next: upr (uninstall harvest), dhcp, secureboot,
c2c, certdeploy. Also open: enrich raw detail where swallowed; grow the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec pkginstall fork shares the harvest — mirror the hint wire (import
  `JanetWeb.troubleshoot`, `$isFail`/`$hint`, `Hint` row field + `FIX:` err log).
