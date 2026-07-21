# JANET Web — design loop 81 (2026-07-21)

## Decision 1 — finish the read-only CHECK ERROR wiring on certdeploy (both read-only actions)
Loop 80 wired the first read-only scan (secureboot). certdeploy has TWO read-only fan-outs — `check` (per-host
store read) and `scan-cert-management` (per-host reconciler probe) — and both surface a host-level **CHECK ERROR**
row carrying the raw probe/session/DNS error. They're the same tool, same pattern, same CHECK ERROR concept, so
wiring both in one loop is one cohesive workstream (as loop 75 did all 5 dhcp call sites at once).

## Decision 2 — hint in the harvest, keyed on the per-action CHECK ERROR indicator
Both harvests build the row via a pure builder (`Get-CertDeployCheckRow` / `Get-CertDeployScanRow`) and then emit
it. The CHECK ERROR indicator differs by action: the check row's status is `$row.Status`, the scan row's is
`$row.Reconciler` (the reconciler cell carries OFFLINE / CHECK ERROR per its contract). So the predicate is
per-action: `$status -eq 'CHECK ERROR'` (check) / `$rec -eq 'CHECK ERROR'` (scan). Both compute the hint from
`$row.Detail` (the raw error) in `$emitResult` after the row is built — consistent with the secureboot/c2c wires,
not inside the "pure, admin-side" row builders.

## Decision 3 — scope to CHECK ERROR; the other statuses self-explain
check's other statuses — ALL PRESENT / MISSING N / OFFLINE — are either success or already-actionable (OFFLINE
= "No TCP on 5985/5986/445"). scan's other verdicts — InstallRoot / GPO / None detected / OFFLINE — are
informational reconciler outcomes, not errors. Only CHECK ERROR carries a cryptic WinRM/session/DNS string the
operator can act on. So the hint is scoped to CHECK ERROR on both paths; every other row is byte-identical.

## Decision 4 — mutate the row conditionally (the row comes from a shared builder)
Unlike the deploy harvest (loop 78), which built the row from an inline literal and set `Hint=[string]$hint`
unconditionally, the read-only rows come from the pure builders, so I mutate `$row['Hint'] = [string]$hint` only
when a hint exists (the acas loop-71 pattern). A non-CHECK-ERROR row carries no `Hint` key — additive, and the UI
hint rendering keys off presence. The raw `Detail` is untouched; a single err `FIX:` line rides the existing
per-host log.

## Decision 5 — static analysis; the CORRECT per-tool glob (a loop-78 lesson)
Both harvests run inside a fan-out over a real RunspacePool with no swappable-worker seam, so the wire is pinned
by static analysis (behavior proven in `Troubleshoot.Hint.Tests.ps1`): each harvest's `CHECK ERROR`-only
predicate computes the hint, the `$row['Hint']` mutation appears exactly twice (unique to the read-only paths —
deploy uses a row literal), and the row-based `FIX:` err log appears exactly twice. **Lesson caught this loop:**
the per-tool glob `CertDeploy.*.Tests.ps1` silently EXCLUDES `CertDeploy.Tests.ps1` itself (the `.*.` requires a
middle segment); the correct glob is `CertDeploy*.Tests.ps1` (5 files, 97). certdeploy 1.4.3 → 1.4.4; the new
Describe holds the exact pin, loop-78's 1.4.3 pin floored. Next: c2c scan/version harvests, per-candidate upr
failures.
