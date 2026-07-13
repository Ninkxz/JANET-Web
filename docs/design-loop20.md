# Design - Loop 20 (Phase 2, cycle 18) - 2026-07-13

## Why: correctness lens on the third (and largest) destructive orchestrator
The deep CORRECTNESS lens has now found REAL, surface-audit-missed bugs in both big destructive tools:
loop 18 c2c (a success token omitted from a rollup -> "NO CHANGE"), loop 19 acas (UNCONFIRMED rendered a
false-green "OK"; reboot-selected reverted to ALL group hosts on an empty filter). Two-for-two - the lens
is genuine value. This cycle applies it to `wpt` (6006 lines, v6.6.0) - the Workstation Patching Tool,
the LARGEST tool and the third destructive fleet orchestrator (it patches + reboots workstations).

## Why not churn
wpt has the RICHEST destructive surface in the suite - bulk-patch, reboot, reboot-schedule, reboot-abort,
kb-install, deploy-install, fix-java, and STIG-fix with an optional ~1h force-reboot. That is a lot of
reboot-capable paths, each of which must (a) self-guard the dispatcher, (b) target only the selected
hosts, and (c) roll results up honestly. The exact bug classes just found in acas/c2c apply directly:
- **Self-guard coverage** across EVERY reboot-capable action (acas's analog gap was a P2 - a reboot path
  that skipped the drop). A missing/late Remove-WptSelfTargets = a self-reboot kills the HttpListener.
- **Empty-filter-as-all** targeting (the acas reboot-selected P2) on any of wpt's reboot/patch actions.
- **Rollup/verdict honesty** (the KICKED/UNCONFIRMED class): a success or pending token falling through
  to a false-green row, or omitted from the tally so a real change shows "NO CHANGE".
- **STIG-fix read-back + force-reboot**: can the compliance read-back false-report success, and is the
  ~1h force-reboot scheduled ONLY on hosts that actually succeeded (never a failed host, never self)?
- **reboot-schedule/abort pairing** (can abort miss a scheduled reboot?) + **pool source injection**.

## Decision rule
- A missing self-guard on a reboot action, a wrong/unselected host rebooted-or-patched, a false-success,
  a false-green row, a STIG false-compliant, or a missing injection = **P1**, fixed this cycle (gated,
  tested, suite green). Meaningful logic error = P2.
- Any fix gets a targeted regression test where the logic is a pure/extractable helper (wpt's host-list,
  self-guard, and row-classifier helpers are unit-testable via the module session state, as with the
  loop-16/17/19 tests). If clean, a documented deep-correctness all-clear on wpt.

One focused Opus reviewer. Non-colliding: wpt is committed, not the certdeploy WIP zone. Every P1/P2
spot-verified by me against the code before any fix.
