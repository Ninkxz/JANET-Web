# JANET Web — design loop 31 (2026-07-21)

## Decision 1 — diversify, because the rest of c2c is one entangled change
After F4 (import) and F5 (scan) — the two independent c2c findings — the remaining four all live in
the fix-rollup buckets and interlock (F6's honest UNVERIFIED status is swallowed by F3's tally). That's
a single holistic bucket-taxonomy overhaul, not four picks, and it deserves a dedicated loop rather than
a rushed slice that half-fixes and leaves the surfaces inconsistent. So loop 31 goes to a fresh tool.

## Decision 2 — winupgrade, a consequential tool never loop-reviewed
winupgrade pins/pushes OS feature updates and can reboot hosts — high consequence, rich status/verify
surface, and never loop-era deep-dived. Same bounded-Fable-worker pattern, one question: does it report
pinned/upgraded/on-target when it isn't. The worker confirmed the core (pin read-back, install-updates,
version compares, unreachable handling) is genuinely fail-closed, and found the false-cleans on the
edges (upgrade-drive, AutoFix, Diagnose, bypass).

## Decision 3 — fix F1, the clearest highest-harm one; rank the rest
Of seven, F1 is the crispest textbook false-clean: the pin THREW, the error was literally discarded,
and the row reported green "Pinned + triggered". It's also the most dangerous, because the trigger
still fired UNPINNED — the host can upgrade to the wrong build. F2/F5 are higher-touch (staging
classifier, multi-site fix tracking) and get their own loops.

## Decision 4 — no pin, no drive: abort, don't just annotate
The tempting minimal fix is to surface the pin error and set Ok=$false but still trigger. That's wrong:
an unpinned WU trigger is actively harmful (upgrades to the latest build, defeating the pin). The
correct fail-closed behavior is to ABORT the drive on a failed pin — no trigger at all — and report PIN
FAILED. The pin is a precondition, not a decoration.

## Decision 5 — test the real worker via the existing shim, not a reimplementation
`WinUpgrade.Drive.Tests.ps1` already drives the real `$script:WinUpgradeWorker` with Invoke-Command
shadowed. I extended that proven harness with a `-PinThrows` flag (the pin phase throws) rather than
building a new one, and asserted the wired behavior: thrown pin → PIN FAILED, Ok=$false, and crucially
NO TRIGGER and NO REBOOT recorded. It exercises the actual control flow, not a copy of it.

## Decision 6 — version bump, full winupgrade regression pass
Aborting on a failed pin changes an observable outcome (green DRIVEN → PIN FAILED), so winupgrade
0.5.1 → 0.5.2; the new Drive test holds the exact pin. upgrade-drive is destructive, so I ran the full
168-test winupgrade + FixVerify3 set (the loop-22 wide-gate lesson), confirming the self-guard and DNS
wrong-box guards still hold. Fable-inline; the fix is one control-flow guard on a mapped finding.
