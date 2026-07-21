# JANET Web — review loop 70 (2026-07-21)

**New theme (operator directive):** *when something CANNOT be done, surface WHY and HOW to fix it* — richer error
detail, context, and actionable troubleshooting, not a bare cryptic error. This is the successor to the fail-closed
campaign (loops 37-69): those made failures HONEST (report Failure, not Success); this makes them INFORMATIVE.

Fable-inline. Baseline: loop-69 authoritative **1486**.

## Finding: only 2 of ~21 tools translate errors into guidance
Every JANET tool acts on remote hosts over WinRM/SMB, so a failure surfaces as a cryptic WinRM/RPC/auth/DNS string.
Grep found the pattern already exists — but ad-hoc in only two tools: restart's `Get-RrsShutdownErrorHint` (a rich
text+code mapper — the gold standard) and dhcp's `Get-JanetWsmanAuthHint` (a thin one). Every other tool surfaces
`"FAIL: $($_.Exception.Message)"` — the raw message with **no guidance**. The architecture already supports a shared
helper: wpt/acas/c2c `Import-Module (Join-Path $PSScriptRoot 'JanetWeb.javafix.psm1')` — a sibling helper module
pattern.

## Workstream: build the shared engine + wire the first tool
### New shared module — `JanetWeb.troubleshoot.psm1` → `Get-JanetTroubleshootHint -Message <raw> [-Server]`
Generalizes restart's mapper into one importable helper. Maps the failure signatures the whole fleet hits, most-
specific-first, `''` when unknown (never guesses): Kerberos `0x80090351` (realm/TrustedHosts/CAC-fallback);
TrustedHosts; **access-denied vs logon-failure** (privilege vs bad credential — a distinction operators need);
name-not-resolved (a specific "…cannot be resolved" inside a generic WinRM wrapper is matched as DNS *before* the
generic WinRM-config signature); WinRM-not-enabled/5985; RPC-unavailable (135); bad-netpath/C$ (445); timeout;
no-credential; disk-full; file-locked. Pure — **9 unit tests** (incl. blank/unknown → `''`, most-specific-first,
server-name interpolation).

### First wire — remoteadmin `$emitResult` (remoteadmin 1.0.2 → 1.0.3)
remoteadmin now `Import-Module`s the helper and, on a non-Success host with an error, runs the raw error through it.
The hint is carried in a new `Hint` row field, the persisted audit detail (`| TROUBLESHOOT: …`), and the operator err
log (`| FIX: …`) — **alongside** the raw error, never replacing it. `$emitResult` runs in module scope (not the remote
worker), so the imported helper is callable. +1 behavioral test (loop-56 worker-swap harness: a `0x80090351` session
error → the row/audit/log carry the realm/TrustedHosts hint; the raw `0x80090351` is preserved). Full remoteadmin +
troubleshoot subset **41** green.

## Design choices (flagged to the operator)
- Hint is added **alongside** the raw error, never in place of it (troubleshooting needs both).
- Started on remoteadmin (cleanest testable seam) rather than a message-catalog file — a PS function is testable,
  greppable, and lives with the code.
- `''`-on-unknown, not a guess: a wrong hint is worse than none.

## Rollout (the ongoing theme, loop-by-loop)
Wire the hint into each tool's failure path — **wpt/acas/pkginstall first** (highest-traffic) — then upr, dhcp,
secureboot, c2c, certdeploy. Complementary: enrich the raw detail where a tool swallows it (full exception + inner,
exit code, host, *which step*), and grow the signature set as field failures surface.

## SECRET parity
- **SECRET parity:** the whole `JanetWeb.troubleshoot.psm1` + `Get-JanetTroubleshootHint` engine, and each tool's
  failure-path wire, should mirror to the SIPR fork — the SIPR transports (Trellix/Tanium) hit the same WinRM/auth
  errors.
