# JANET Web — review loop 72 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-71 → **GREEN**. Baseline: loop-71 ~**1499**.

## Self-review of loop-71 (acas fan-out hint) — GREEN
Purely additive: the hint is computed only for a non-ok non-skip host, attached to a guarded `Hint` row field + a new
`FIX:` err log; classify/audit/counters unchanged; all 186 acas tests green. Nothing to reopen.

## Workstream: wire the hint into wpt (the other most-used tool)
`Invoke-WptFanOut` (`:4802`) is wpt's generic fan-out — same callback shape as `Invoke-AcasFanOut` (`$OkOf`/`$RowOf`/
`$AuditDetail`/`$AuditResultOf`/`$LogOf`), `$res` a hashtable with `.Host`/`.Error`. So one wire covers wpt's
fan-out-based actions.

### Fix (wpt 6.8.14 → 6.8.15) — purely additive
The harvest (`:4847-4858`) now, on a failure (`-not $ok`), runs the raw error (`$res.Error`, else the audit-detail
string) through `Get-JanetTroubleshootHint -Server $res.Host` and: (1) attaches it to the row `Hint` field (guarded
`$row -is [hashtable]`, computed *before* the row is emitted so it rides with it); (2) emits an err log
`"$host : $err | FIX: $hint"`. The audit-detail string is now computed once (`$auditDetailStr`) and reused for both the
hint fallback and the (unchanged) audit emission — no double-eval of `$AuditDetail`. Raw error preserved everywhere;
ok rows compute no hint and emit no extra log.

### Tests
+5 (`Wpt.FanOutHint.Tests.ps1`, **static analysis** — matching wpt's existing fan-out test style, `Wpt.ChromeProfiles`,
since the fan-out runs a real RunspacePool and wpt has no behavioral fan-out harness): exact `6.8.15` pin; wpt imports
`JanetWeb.troubleshoot`; the hint is computed only for a failure and attached to `$row['Hint']`; the `FIX:` err log is
gated on `$hint`; the audit-detail string is computed once and the raw error preserved. `Wpt.AdobeUninstall` pin
floored. **loop-37 lesson:** the fan-out is shared by every wpt fan-out action, so I ran **all 182 wpt tests** = green
(one self-inflicted test-regex bug — `[^}]*` couldn't cross the `}` in the log text's `$(if…)` — caught and fixed).

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), **wpt (72)** — the two most-used tools plus remoteadmin, all via their generic
fan-outs. Next: pkginstall, upr, dhcp, secureboot, c2c, certdeploy (per-tool harvests; some have their own fan-out,
some emit per-host inline). Also open: enrich raw detail where a tool swallows it; grow the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares `Invoke-WptFanOut` — mirror the hint wire (import
  `JanetWeb.troubleshoot`, attach the `Hint` row field + `FIX:` err log on a failure).
