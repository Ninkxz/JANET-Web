# JANET Web — design loop 8 (2026-07-20)

## Decision 1 — rotate to a fresh destructive-tool deep-dive (c2c)
Loop 7 exhausted the last cheap tracked item, so per the loop-7 note the backlog rotates to
fresh deep-dives. c2c was the highest-value unreviewed target: the richest destructive
surface in the suite (BitLocker enable with recovery-key escrow, PKI push, antimalware,
patches) and never loop-reviewed. wpt/acas had their Chrome/Edge paths reviewed loops 1–3;
upr was reviewed loop 5. c2c's recovery-key handling is the single highest-consequence code
in the whole app (a leak or a lockout is catastrophic), so it earned the Opus pass.

## Decision 2 — implement the P3 despite it being near-impossible, BECAUSE it is provably safe
The instinct (and ponytail's "does this need to exist?") says skip a near-impossible-edge fix
in safety-critical code. The deciding factor was the risk profile of the CHANGE, not the
likelihood of the TRIGGER:
- The new branch runs ONLY when `$weAdded && $newKpId==''` — a state where the current code
  does nothing (leaves the orphan). So it cannot alter any currently-reachable behavior;
  every existing scenario resolves a real id and takes the unchanged branch. Zero regression
  risk to tested paths.
- The removal is gated by the SAME `$beforeIds` pre-Add snapshot the existing add-time diff
  already trusts — so it introduces no new safety assumption. If `$beforeIds` were wrong, the
  existing code would already be unsafe.
A fix that is strictly additive to an un-exercised fail-closed state, reusing the existing
safety invariant, in the most safety-critical path, is worth banking even for a rare trigger.
Had it required changing a reachable code path, the call would have been to skip it.

## Decision 3 — the test must prove BOTH halves
An orphan-cleanup that could strip a pre-existing (legitimately escrowed) protector would be
a P1 lockout risk — worse than the orphan it fixes. So the `bothfailblankid` scenario proves
the orphan IS removed (`{LATE-KP}` in RemoveIds) AND the (e3) `preexistbothfail` case proves a
pre-existing protector is NEVER removed (it routes to reuse, so the cleanup branch is
unreachable for it). The `Leaked` assert stays on the new scenario so the fix can't
accidentally surface the recovery password. Both directions, or the test is worthless.

## Decision 4 — non-vacuity of the new scenario
`{LATE-KP}` can only enter RemoveIds through the new re-enumeration branch (the shimmed
Add returns an empty KeyProtector so `$newKpId` stays blank; the only other Remove path needs
a resolved id). So without the fix the assert fails — the test genuinely exercises the new
code, it doesn't pass on the old behavior.

## Versioning
c2c `1.15.1 → 1.15.2` (manifest version; patch — a fail-closed defense-in-depth fix on an
existing pillar). `C2c.Enable` keeps the exact pin (this loop's file); `C2c.Lockscreen`
converted to a `-ge` floor assert (the wpt-suite precedent) to stop the cross-file version
churn on every c2c bump.
