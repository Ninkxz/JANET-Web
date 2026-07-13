# Production Review - Loop 23 (Phase 2, cycle 21) - 2026-07-13

Value pick (design-loop23.md): the deep correctness/SAFETY lens on `remoteadmin` (519 lines, v1.0.0) -
the HIGHEST-consequence tool (run-script executes an arbitrary operator PowerShell block on remote hosts
over WinRM). Small + already self-guarded, so lower find-rate, but the consequence is the highest in the
suite. One focused Opus reviewer. Both backlogs operator-deferred; remoteadmin is committed (non-colliding).

**Rating: GREEN.** The three critical guards - wrong-box hard-abort, dispatcher self-guard, and
script-as-scriptblock isolation - are all correct and correctly ordered. No P1/P2. One P3 landed. Suite
883/883.

## Verified CORRECT (deep, the catastrophic paths) - I personally spot-verified the top one
- **Wrong-box abort ordering (P1-critical):** after New-PSSession, the remote `$env:COMPUTERNAME` probe
  (`:273`) runs on the SAME session BEFORE the operator block; a name mismatch (`:274`) -> Remove-PSSession
  -> `return $r` (`:278`), a hard return that never reaches the operator `Invoke-Command $sb` (`:295`); a
  probe THROW also returns (`:285`). The operator's arbitrary code CANNOT run on a wrong/mismatched box.
  IPv4-literal targets skip the probe (no DNS indirection) but the self-guard already dropped any local IP;
  IPv6 can never become a target. *Spot-verified against the code: the mismatch/throw both return before
  :295 - no fall-through.*
- **Self-guard:** `Remove-RemoteAdminSelfTargets` is CALLED for run-script (`:379`) BEFORE any runspace/
  session, early-exits if all targets are self - the operator block can't run on the dispatcher. open-cshare
  needs no self-guard (it only Explorer-browses `\\host\C$` in the operator's own session, no remote code).
- **Script/input handling:** the operator body travels as a string ARGUMENT and becomes a scriptblock via
  `[scriptblock]::Create` in the worker - never string-concatenated into a wrapping command. Host tokens
  validated before becoming a ComputerName.
- **Result honesty:** terminating errors + worker faults -> Failed (not swallowed); aborted/skipped ->
  non-success; no host double-emitted or dropped.
- **Gating/credential:** run-script destructive=$true (server gate engages); credential only via
  -Credential, logs carry username only; open-cshare leaks no credential, can't target a malformed host.

## P3 FIXED (commit 2a6f7dc) - case-insensitive target dedup
`Get-RemoteAdminTargets` used `Select-Object -Unique` (case-SENSITIVE), so `host1` and `HOST1` both
survived and the operator's arbitrary block would run TWICE on the same physical host (double side
effects - meaningful for a run-arbitrary-script tool). Replaced with an order-preserving
`HashSet(OrdinalIgnoreCase)` dedup. remoteadmin 1.0.0->1.0.1; regression test added.

## P3 documented (not changed)
- run-script reports `Success` on a non-terminating remote error / non-zero native exit code - a
  documented design choice; the error text IS surfaced in the Output column (no data loss). A stricter
  `CompletedWithErrors` status is UI-coupled (view + summary + audit), left for a deliberate cycle.
- NetBIOS-vs-DNS short-name skew can false-abort a legit host - errs SAFE (never runs on a wrong box),
  no change.

## Verdict
The most dangerous tool in the suite is sound: an arbitrary operator script cannot run on the wrong box
or the dispatcher, and a wrong-box abort genuinely aborts. One minor double-run defect fixed. The deep
correctness/safety lens has now covered every high-consequence tool. Ledger row 38 added. Suite 883/883.
