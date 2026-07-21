# JANET Web — design loop 36 (2026-07-21)

## Decision 1 — close a deferred HIGH-harm item; the fresh-deep-dive vein is thinning
Two consecutive GREEN deep-dives (server, upr) on a well-built codebase say the marginal fresh review
now yields "GREEN + a nit". The confirmed backlog, by contrast, still holds real HIGH-harm items. So
loop 36 closes one — winupgrade #27, which actually REBOOTS a host on a false signal, the most
operationally harmful open finding.

## Decision 2 — #27 over the c2c cluster because the classifier already exists
Of the deferred HIGH items, #27 is the one whose fix is already 90% built: `Get-WinUpgradeStagingClass`
is a pure, TESTED classifier, and the AutoFix `clearStaging` path already applies its logic inline. The
bug is simply that the reboot-path re-read never used it — it bare-Test-Path'd the ~BT tree. The c2c
cluster is a from-scratch bucket-taxonomy overhaul; #27 is wiring in an existing, proven classifier.

## Decision 3 — classify, only reboot on Active/Recent
The distinction the reboot needs is exactly the one the classifier makes: a rolled-back attempt (a
rollback marker, or an old tree with no setup process) is Stale and must NOT count as staged; a running
setup or a recent tree is genuinely mid-upgrade/awaiting-reboot. So the re-read now computes the class
inline and sets staged = (class ne Stale). Same rule the AutoFix clearStaging path uses, kept in lockstep.

## Decision 4 — scope to the confirmed harm; leave the pending-reboot sibling ranked
The bare ~BT Test-Path is the CONFIRMED "reboots a stale host" harm. The generic CBS/WU/PFRO
pending-reboot markers (checked first) can also read a non-feature-update pending as staged, but a CBS
RebootPending CAN be a completed feature-update, so demoting it risks a false-negative (not rebooting a
genuinely-staged host whose ~BT was already consumed). That trade-off deserves its own analysis; I fixed
the unambiguous case and ranked the sibling (27b) rather than over-reach.

## Decision 5 — test what's testable; the remote scriptblock is static-pinned
The re-read runs on the target in a shimmed-away scriptblock, so an end-to-end "stale ~BT -> no reboot"
can't run in the Drive harness. But the chain is covered piecewise by proven tests: the classifier
decision (unit-tested, Diagnose24h2), the reboot gate on Staged=false (Drive INVARIANT #4), and — new
this loop — the classifier's reboot contract restated for clarity plus a static assertion that the
re-read now carries the classification, not a bare Test-Path. Honest about the seam; each piece is pinned.

## Decision 6 — version bump, full winupgrade regression pass
A changed staged determination is behavioral (a stale-~BT host that would have rebooted now won't):
winupgrade 0.5.4 -> 0.5.5, the loop-33 FixVerify2 exact pin -> floor, the loop-36 test holds the exact
pin. Reboot-when-staged is destructive, so I ran the full winupgrade + FixVerify2/3 set — Drive INVARIANTs
#4/#5 (the reboot gate) and the self-guard/DNS wrong-box guards all green. Fable-inline.
