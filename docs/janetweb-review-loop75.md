# JANET Web — review loop 75 (2026-07-21)

**Theme: informative failures** (loop 70). Fable-inline. Self-review of loop-74 → **GREEN**. Baseline: loop-74 authoritative **1512**.

## Self-review of loop-74 (upr harvest hint) — GREEN
Additive: `$ok` hoisted, hint on `(-not $ok) -and $res.Error`, attached to each emitted row's `Hint` field + a `FIX:`
err log (was a bare warn); ok hosts untouched; full upr suite (44) green. Nothing to reopen.

## Workstream: upgrade dhcp's failure hints (6th tool)
dhcp was a special case: it already had a **thin, auth-only** `Get-JanetWsmanAuthHint` (`:340`) used in **5**
failure-path catches (connect `:570`, load `:617`, bulk read `:673`, apply `:897`, another `:1064`). It only matched
`username or password|access is denied|authentication` — so a DNS/RPC/SMB/timeout failure on a DHCP server got no hint.

### Fix (dhcp 1.1.13 → 1.1.14) — a consolidating upgrade
Retired the thin local function and swapped all 5 call sites to the shared `Get-JanetTroubleshootHint` (a strict
superset — same `-Message`/`-Server` signature, so a drop-in). Now every dhcp failure path gets the full signature set
(auth **plus** DNS/RPC/SMB/timeout/no-credential/disk/file-lock), and the codebase has one fewer ad-hoc hint mapper —
dhcp now shares the fleet engine like the other five wired tools. dhcp imports `JanetWeb.troubleshoot`. The existing
`if ($hint) { " -- $hint" }` log format is kept (dhcp's convention); the win is coverage + consolidation.

### Tests
+4 (`Dhcp.IpValidation.Tests.ps1`, static analysis): exact `1.1.14` pin; dhcp imports the engine; ≥5 catch sites use
`$hint = Get-JanetTroubleshootHint`; the dead `function Get-JanetWsmanAuthHint` **and** its `= Get-JanetWsmanAuthHint
-Message` calls are gone. loop-69 Describe floored. **loop-37 lesson:** ran `Dhcp.IpValidation` + `FixVerify` +
`FixVerify3` (**68** green) — the swap is behavior-preserving for recognized-auth errors and strictly adds coverage;
the loop-65 behavioral ReadError test (bulk harvest, a different path) is unaffected.

## Rollout status (informative-failures theme)
Wired: remoteadmin (70), acas (71), wpt (72), pkginstall (73), upr (74), **dhcp (75)** — and dhcp's is also a
consolidation (one fewer ad-hoc mapper). Next: secureboot, c2c, certdeploy. Also: restart still has its own richer
`Get-RrsShutdownErrorHint` (the gold standard — leave it, or later fold its text signatures into the shared engine and
delegate); per-candidate upr failures; enrich raw detail; grow the signature set.

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork shares the failure catches — mirror the swap to
  `Get-JanetTroubleshootHint` + the retirement of the thin local hint.
