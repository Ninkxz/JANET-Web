# Design - Loop 26 (Phase 2, cycle 22) - 2026-07-13

## Milestone: the Desktop-mirror mandate is UNBLOCKED
For ~20 cycles the Desktop-parity mirror was blocked - a concurrent "Live-Usage Snapshot" telemetry sync
left all `X:\J.A.N.E.T\Tools\*.ps1` uncommitted, so any versioned mirror would have swept in that work.
This cycle that resolved: the operator directed "commit everything", so the concurrent Tools work + the
new C2CNemesisTool 2.4.2 PKI mirror all committed (Desktop HEAD ed02604f), and both repos pushed to the
new gitea.bth0mp.com. **Desktop is now clean/committed** - a versioned mirror can finally land safely
(scoped commit, no concurrent work to sweep).

## This cycle: start clearing the deferred mirror backlog
The ledger carries many CHECK/DEFERRED rows - Web security fixes whose Desktop twin was never mirrored
because Desktop was blocked. Highest value = the safety-critical recent fixes with clear Desktop twins:
- **wpt reboot self-guards (row 34)** -> WorkstationPatchingTool (loop-6 recon: 0 self-guard on
  reboot-capable actions - a self-reboot of the operator box). HIGHEST (wrong-box reboot).
- **upr uninstall self-guard (row 13)** -> UnsupportedProductRemediator (wrong-box software removal).
- **message send self-guard (row 25)** -> RemoteMessageTool.
- **acas UNCONFIRMED false-green + reboot empty-filter (rows 32-33)** -> ACAS Nemesis Tool.
- **c2c KICKED rollup (row 31)** -> C2CNemesisTool 2.4.2 (just versioned).

## Approach
A Sonnet sweep (this cycle) LOCATES each defect in the current committed Desktop tools and verdicts it
PRESENT / ABSENT / ALREADY-FIXED with exact locations + the minimal fix - because the concurrent session
may have already changed some tools, so each must be checked, not assumed. I then GATE + land the
highest-priority CONFIRMED mirror(s) under Desktop versioning rules (new versioned Tools\ file, archive
the old, update JANET_Config.json Script field + JANET.ps1 if present, PS 5.1 + BOM, scoped commit), and
update the ledger row to CLOSED-BOTH (or CLOSED-WEB-ONLY if the defect genuinely doesn't exist there).

## Decision rule
- A PRESENT wrong-box reboot/uninstall self-guard gap = land the mirror this cycle (top priority).
- Lower-severity PRESENT items (false-green display, rollup mislabel) = land as capacity allows; else
  queue with the exact location recorded so the next cycle lands them fast.
- ABSENT / ALREADY-FIXED -> ledger row CLOSED-WEB-ONLY / CLOSED-BOTH with the checked reason.
Every touched row ends CLOSED-BOTH or CLOSED-WEB-ONLY - no silent-open. Scoped commits only; never sweep
any (now-unlikely) concurrent work.
