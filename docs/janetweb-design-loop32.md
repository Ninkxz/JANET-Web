# JANET Web — design loop 32 (2026-07-21)

## Decision 1 — stay on winupgrade, take the cleanest high-visibility item
Loop 31 opened winupgrade with five findings. F6 (Diagnose READY ignores disk/RAM/Secure Boot) is the
one the operator LOOKS AT — the go/no-go verdict — so a false READY there directly causes a wasted,
failed upgrade. It's also the cleanest of the remaining: three marker checks and one verdict branch,
versus the staging classifier (#27, touches the remote signal + reboot invariant) or the multi-site
AutoFix tracking (#29). Best visibility-per-risk for one loop.

## Decision 2 — the scan already knows; the verdict just wasn't listening
The scan emits `[FAIL] Disk` / `[FAIL] RAM` / `[FAIL] Secure Boot` — the data was there, the verdict
threw it away. The fix is to make the verdict read the markers it was ignoring, not to gather anything
new. Cheapest possible correct fix.

## Decision 3 — NOT READY between NEEDS POLICY and READY: minimal precedence disturbance
Placing the new branch as the LAST gate before READY means it only reclassifies hosts that were
falsely READY. BLOCKED / HW INCOMPAT / NEEDS POLICY hosts keep their (already-honest) verdicts. I
deliberately did NOT surface disk before policy — that would change the verdict for a policy-missing +
disk-short host and reorder the documented precedence for no false-clean benefit. A distinct NOT READY
(not folding into HW INCOMPAT) keeps the reason legible: CPU/TPM is a hardware-incompat problem, disk/
RAM/Secure Boot is a capacity/firmware problem the operator fixes differently.

## Decision 4 — surface the reason, don't just downgrade
The summary line now appends `disk LOW` / `RAM LOW` / `Secure Boot off`, so a NOT READY host tells the
operator WHY. A verdict that flips to NOT READY without saying which check failed would just move the
confusion.

## Decision 5 — canonical helper + inline mirror (runspace boundary)
The verdict is derived inside `$script:WinUpgradeWorker`, which runs in a module-less fan-out runspace,
so it can't call the helper. Same pattern as every prior runspace-boundary fix: `Get-WinUpgradeDiagnose
Verdict` is the pure tested spec, the worker mirrors it inline comment-linked, and a static assertion
pins that the mirror carries the new checks. The helper test covers the logic at every branch.

## Decision 6 — version bump, full winupgrade regression pass
A changed verdict is behavioral (a host that read READY may now read NOT READY): winupgrade 0.5.2 ->
0.5.3, the loop-31 exact pin -> floor, loop-32 test holds the exact pin. Ran the full 179-test winupgrade
+ FixVerify3 set (the loop-22 wide-gate lesson) — Diagnose24h2 / FleetStatus / SelfGuard all still green.
Fable-inline; a verdict-gate fix on a mapped finding needs no agent.
