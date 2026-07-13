# Design - Loop 23 (Phase 2, cycle 21) - 2026-07-13

## Why: the correctness/safety lens on the highest-consequence tool
The deep-correctness lens is 4-for-4 on the big destructive orchestrators (c2c/acas/wpt/reports) and the
self-guard parity + upr backlog are closed. The one destructive tool with the HIGHEST blast radius that
has never had a deep pass is `remoteadmin` (519 lines, v1.0.0): its `run-script` action executes an
ARBITRARY operator-supplied PowerShell script on remote hosts over WinRM. A targeting or wrong-box bug
there runs the operator's code on the WRONG machine - the worst possible outcome.

## Value calibration (honest)
remoteadmin is SMALL and already HARDENED - it has `Remove-RemoteAdminSelfTargets` (dispatcher self-guard)
and a post-New-PSSession `$env:COMPUTERNAME` wrong-box probe, plus a RemoteAdmin.Tests.ps1. So the
marginal find-rate is lower than the big-tool audits. But the CONSEQUENCE is the highest in the suite, so
verifying the guards are not just present but CORRECT and correctly ORDERED is worth a focused pass:
- **Wrong-box abort ordering (top)**: does a name mismatch between the dialed host and the answering box
  HARD-ABORT before the `Invoke-Command $sb` that runs the operator script - or could a mismatch fall
  through and run the code on the wrong box?
- **Self-guard application**: is `Remove-RemoteAdminSelfTargets` actually CALLED on run-script AND
  open-cshare before any session opens - or just defined? (Can the operator's script run on the dispatcher?)
- **Script/input handling**: is the script passed as a scriptblock/ArgumentList (not string-concatenated)?
- **Result honesty**: can run-script report success when the remote script failed, or conflate error with
  output?

## Decision rule
- Script runs on the wrong box or the dispatcher, a wrong-box abort that doesn't actually abort, or a
  false-success = **P1**, fixed this cycle (gated, tested, suite green). Meaningful logic error = P2.
- Any fix gets a targeted regression test (the self-guard/wrong-box helpers are pure and testable via the
  module session state). If clean, a documented safety all-clear on the most dangerous tool.

One focused, right-sized Opus reviewer (small file, highest consequence). Non-colliding: remoteadmin is
committed. Every P1/P2 spot-verified by me before any fix.
