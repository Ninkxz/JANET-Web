# Production Review - Loop 15 (Phase 2, cycle 13) - 2026-07-13

Both real backlogs remain operator-deferred (status-quo, loop 13): the stale certdeploy WIP and the
Desktop-parity mirror. No new committed Web delta since loop 14; the Web attack surface is audited end to
end (loops 3-12) with the highest-value properties regression-locked (gate; read + write path traversal,
loops 13-14). With security work exhausted or deferred, this cycle fixed the one concrete recurring
OPERATIONAL defect instead of manufacturing marginal test churn.

**Rating: GREEN.** No code change; a maintenance win. Suite unchanged at 848/848 (nothing testable
touched - `git gc` only rewrites `.git` internals, not the working tree).

## Fixed - prod `.git` bloat from ~40 failed auto-repacks
Every commit this loop tripped `geometric-repack: rename ... Permission denied` (an SMB lock on one pack
file blocked git's background auto-maintenance), so each commit's new pack was left un-consolidated. This
compounded badly:

| metric | before | after `git gc` |
|--------|--------|----------------|
| packs | **67** | **2** |
| loose objects | 1171 (all prune-packable) | 0 |
| in-pack objects | 76,693 (duplicate-laden) | 2,050 |
| `.git` size | **171 MB** | **4.1 MB** |

`git gc` succeeded cleanly (exit 0) - the manual path does not hit the same lock as the on-commit
auto-repack. `git fsck --connectivity-only` = exit 0 (only harmless "dangling tree" unreferenced objects,
no corruption). HEAD (`50c3281`), branch, and the working tree (incl. the untouched concurrent certdeploy
WIP) are all intact.

**Recurrence:** now at 2 packs / 0 loose, far under the default auto-gc thresholds (50 packs / 6700
loose), so the per-commit error will NOT retrigger for many commits. If it eventually returns, a periodic
`git gc` clears it; disabling `gc.auto` would stop the attempts entirely but that is a config change left
to the operator (not made here). Not a defect with a Desktop twin -> no ledger row.

## Note on the plateau
The Web codebase is now comprehensively audited (22 tools + views, server boundary), the top security
properties are regression-tested, and `.git` is healthy. The genuinely high-value remaining work - the
Desktop-parity mirror (blocked 10 cycles by the concurrent telemetry sync) and the certdeploy XSS-3 +
owner P2 (stale WIP) - is entirely gated on the two concurrent sessions committing. Until one unblocks,
cycles will keep delivering durable insurance (regression coverage, repo/operational health) rather than
new security fixes, which would be manufactured churn on already-GREEN code.

## Verdict
Web GREEN, 848/848, `.git` reclaimed 167 MB and consolidated 67->2 packs. Open work all operator-deferred.
Next cycle: re-check both trees for an unblocking commit; else continue durable maintenance/coverage.
