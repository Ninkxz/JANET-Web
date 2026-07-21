# JANET Web — design loop 50 (2026-07-21)

## Decision 1 — a still-open wpt HIGH/MED over a fresh dive on a smaller tool
certdeploy's two real dive false-cleans (F1/F2) are closed, and the remaining un-dived acting tools
(adto/remoteadmin/secureboot) are smaller and less-used, so a fresh dive there yields lower-impact findings.
Meanwhile the loop-40 wpt dive — on the *most-used* tool — left items 43–51 open, several HIGH/MED. Closing one
of those beats diving a niche tool: same effort, higher operator reach. item44 is the cleanest of them, a
definite audit-honesty false-clean with a contained fix.

## Decision 2 — Success must mean "removed what it found"
clean-user-apps' one job is deleting app binaries. It already tracks the honest numbers — `$found` paths that
existed, `$removed` actually deleted, with a locked-app failure logged as ERR and left uncounted — but threw
them away and hardcoded Success. The fix is to derive Status from those numbers: all-removed (or nothing to
remove) is Success; a live run that removed nothing it found is Failed; a partial is Partial. Same principle as
loops 44/47: a not-fully-succeeded action must not read Success.

## Decision 3 — the OkOf/audit are already correct; only the status lied
A pleasant property: the action's OkOf is `Status in {Success, Dry Run OK}` and the fan-out books a non-ok host
as Failure, so introducing distinct Partial/Failed statuses makes them non-ok and Failure-audited with zero
changes to the OkOf or audit wiring. The false-clean was entirely in the status determination; I verified the
downstream is honest rather than assuming it.

## Decision 4 — the static assert found the class boundary, and I respected it
Writing the "no unconditional Success" assert flagged a *second* worker with the same line — but that one is the
disk-cleanup/maintenance action, where Success means "the maintenance ran" and a locked-profile skip is a
legitimate best-effort outcome, not a failure. Applying the removed-vs-found rule there would false-FAIL a
successful temp/cache clean. So unlike loop 42 (where the assert correctly widened the fix to a whole class),
here the assert flagged a *false* sibling — different semantics — and the right call was to narrow the assert,
not widen the fix. The lesson: a shared code shape is a prompt to check whether it's the same bug, not proof
that it is.

## Decision 5 — pure helper + version
The status is a clean function of two ints and a bool, so `Get-WptCleanStatus` is unit-tested at every branch
and the module-less worker carries the inline mirror. A live host that removed nothing now reads Failed instead
of Success — behavioral — so wpt 6.8.11 → 6.8.12, M365Update exact pin → floor, the new test holds the exact
pin. wpt clean/guard/verify set (40) green; authoritative run gates.
