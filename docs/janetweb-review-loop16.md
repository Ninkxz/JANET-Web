# JANET Web — review loop 16 (2026-07-20)

**Baseline:** 1137/1137 at loop-15 close. Fable-inline. Local-only commits.
*(Operator mid-loop reaffirmed: JANET Web is a SOLO, OFFLINE, non-internet, CSV-fed
standalone PS tool. Nothing this loop — or the series — adds an internet dependency;
all data is local files, all fan-out is LAN WinRM.)*

## Self-review of loop-15 (`4ab8c05` secureboot confirm-word) — verdict GREEN (inline)
Diff is strictly additive (module +confirm line +version, view +ENABLE dialog); all six
existing guards (self-guard, wrong-box ×2, brick-safety ×2, self-delete) present post-change.
The ENABLE confirm is gated to `if (!isDry)` before `ctx.run`; Dry Run stays ungated. No
re-verify agent — additive change, covered by the 32/32 secureboot suite.

## Deep-dive: certdeploy (DoD trust-root push over WinRM, offline) — verdict GREEN

Full destructive contract, verified with file:line evidence:
- **Confirm:** `destructive:true` + manifest `confirm=` + a required typed `DEPLOY` input
  (`:72-78`).
- **Self-guard:** `Test-JanetCertDeployHostIsSelf` drops the dispatcher before fan-out.
- **Wrong-box:** DNS mismatch HARD abort BEFORE the C$ round-trip.
- **Additive-only install** (`Add-CertDeployBundleToStores :339`): adds only-missing by
  thumbprint, **never removes**; a **trust-anchor guard** rejects a non-CA cert from Root/CA
  (`:382`, an operator bundle can't push a leaf as a fleet anchor); **persistence re-verify**
  on a fresh ReadOnly handle → NotVerified on absent (`:402-412`).
- **Expiry census** excludes dead anchors unless the opt-in `includeExpired`; the 4
  LegacyIntermediates are the narrow audited exception (expired-but-required).
- **The one REMOVAL path — opt-in `prunePki`** (`:458-481`): triple-gated —
  `NotAfter < now` AND subject matches `^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD`
  AND thumbprint not in `$legacyKeep`, in `Cert:\LocalMachine\CA` ONLY. Cannot touch a Root,
  a non-expired cert, a non-DoD cert, or a cert deploy itself pushes.

**The finding — test precision (not a tool defect) → FIXED** (`fac190f`, test-only): the
guard-copy sync test (the `$legacyKeep` prune-exclusion list must equal the master
`CertDeployLegacyIntermediates`, else the prune could delete a cert deploy just pushed) was
one-directional and matched a loose source-substring (a comment would satisfy it). Rewrote it
to extract the ACTUAL `$legacyKeep = @( ... )` array from the companion source and assert exact
SET EQUALITY with the master in both directions (missing → deletes a pushed cert; extra →
silently exempts a cert from pruning). 59/59 certdeploy suite green.

## Destructive-tool coverage — COMPLETE
Every destructive tool in JANET Web now has a documented review with the full contract
verified and test-pinned: wpt, acas, upr, c2c, adto, remoteadmin, winupgrade, secureboot,
pkginstall, restart, winrmbridge, certdeploy (+ dhcp single-server / biosfirmware were
N/A-or-guarded in the loop-10 self-guard audit). The removal paths (upr uninstall, c2c/adto
writes, certdeploy prune) are the most-scrutinized: allowlisted, gated, and sync-guarded.

## SECRET parity
- SECRET parity: the certdeploy prune-sync test precision — the JanetSec certdeploy fork
  (if present) shares `$legacyKeep`/`CertDeployLegacyIntermediates`; mirror the bidirectional
  set-equality assertion.
- Carried (unexecuted): all prior SECRET-parity items.
