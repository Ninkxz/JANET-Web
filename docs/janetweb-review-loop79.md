# JANET Web — review loop 79 (2026-07-21)

**Theme: informative failures** (loop 70) — follow-up phase (primary 9-tool rollout closed loop 78).
Fable-inline. Self-review of loop-78 → **GREEN**. Baseline: loop-78 authoritative **1528**.

## Self-review of loop-78 (certdeploy deploy-harvest hint) — GREEN
Additive: `$auditResult` status switch hoisted to the top of `$emitResult` (a pure move — same value),
`$hint` computed only for a `Failure` host (FAILED/NOT VERIFIED/REJECTED), attached to a `Hint` row field
+ an err log (`FIX:`); INSTALLED/ALREADY/SKIPPED/OFFLINE hosts untouched, raw detail preserved. Full
certdeploy suite (59) + full suite (1528) green. Nothing to reopen.

## Workstream: fold restart's numeric-code mapper into the shared engine + have restart delegate
restart was the **last ad-hoc hint mapper** (loop-70's premise = one shared engine, not per-tool copies;
dhcp's thin mapper was retired loop 75). `Get-RrsShutdownErrorHint` (`:1002`) had two halves:
- **6 detail-string branches** (Kerberos / TrustedHosts / WinRM-client / name-resolution / access-denied /
  logon-failure) — pure DUPLICATES of the shared engine.
- **A numeric `$Code` switch** (shutdown.exe return codes) — some tool-specific sentinels (0/1115/1116/1190/
  -1/-3/-4), some general Win32 codes (5/53/1314/1722/1727), and 3 the shared engine LACKED.

### Fix A — enrich the shared engine (`JanetWeb.troubleshoot.psm1`) with restart's missing knowledge
- **NEW privilege-not-held signature** (`1314\b|ERROR_PRIVILEGE_NOT_HELD|SeRemoteShutdownPrivilege|
  SeShutdownPrivilege|required privilege is not held|privilege not held`), placed after access-denied — a
  genuinely distinct failure class (authenticated, maybe even local-admin, but lacks the one user right the
  action needs). Points at secpol.msc → User Rights Assignment / GPO.
- **RPC 1727** (`1727|RPC_S_NO_MORE_ENDPOINTS|no more endpoints`) folded into the existing RPC-unavailable
  signature (same endpoint-mapper cause); hint text extended.
- **ERROR_BAD_NETPATH** token added to the SMB signature (bare `53` deliberately NOT added — too ambiguous
  as a substring).
- restart's extra phrasings preserved on delegation: `unknown security error` → Kerberos signature,
  `could not be found` → name-resolution signature.

### Fix B — restart delegates (restart 1.5.0-beta8 → beta9)
The 6 duplicated detail-string branches replaced with one call: `if ($Detail) { $h =
Get-JanetTroubleshootHint -Message $Detail; if ($h) { return $h } }`, then fall through to the (unchanged)
numeric `$Code` switch for the tool-specific / no-usable-detail cases. restart imports the engine at module
scope. **Behavior preserved** — every Detail that matched the old branches now matches the engine's superset;
any non-matching Detail falls to the numeric switch exactly as before. Net deletion (~18 lines of dup gone).

### Tests
- `Troubleshoot.Hint.Tests.ps1` +5 (behavioral): privilege-not-held is distinct from access-denied; RPC 1727;
  ERROR_BAD_NETPATH; unknown-security-error → Kerberos; could-not-be-found → name-resolution.
- `Restart.Guards.Tests.ps1` +4 (behavioral + static): a detail-string failure returns the shared hint
  (incl. privilege-not-held the old mapper never had); the numeric switch still owns 1190/1115/1314/unknown;
  restart imports the engine + delegates in the mapper; the 6 duplicated branches are gone; manifest beta9.
- **loop-37 lesson:** the engine change is shared by ALL wired tools, so I ran the engine + restart + every
  engine-consumer test file (12 files, 210) green, plus the full suite.

## Rollout status (informative-failures theme)
Primary 9-tool wire COMPLETE (loops 70-78). **Follow-up phase begins:** loop 79 = restart mapper folded/
delegated (the last ad-hoc mapper is gone — the engine is now the single source of hint truth). Remaining
follow-ups: c2c scan/version harvests, certdeploy check/scan CHECK ERROR rows, secureboot read-only scan
CHECK ERROR, per-candidate upr failures, enrich raw detail where a tool swallows it, grow the signature set.

## SECRET parity
- **SECRET parity:** mirror the shared-engine enrichment (privilege-not-held signature, RPC 1727,
  ERROR_BAD_NETPATH, unknown-security-error, could-not-be-found) to X:\shh-JANET's troubleshoot engine, and
  the restart-fork mapper delegation. (Still pending: the whole-engine mirror to the SIPR fork, tracked
  since loop 70.)
