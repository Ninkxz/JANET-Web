# JANET Web — design loop 28 (2026-07-21)

## Decision 1 — finish the acas cluster: take item 19
Item 19 is the last CONFIRMED false-clean from the loop-25 deep-dive (item 20 is speculative with no
reachable trigger). Closing it makes the whole acas remediation-tally + audit surface honest on every
confirmed path — worth a loop for the closure, and the fix is small and clearly correct.

## Decision 2 — the audit must say what happened, not what's hoped
The grid row already honestly reads "reboot scheduled"; the lie is only in the audit action, which
claimed VulnPatched. Scheduling an abortable, 5-minutes-out reboot is not patching a vulnerability —
it's a touch. The fix is to make the audit action match the truth the row already tells.

## Decision 3 — TouchHost, and let VulnPatched be earned elsewhere
The valid audit actions are TouchHost and VulnPatched. A scheduled reboot is TouchHost. I deliberately
did NOT upgrade verify-post-reboot to VulnPatched to "compensate" — confirming a reboot happened isn't
the same as confirming a specific vuln's patch applied, and that's a debatable claim I won't introduce
this loop. VulnPatched stays where it's earned: the actual patch-install and update-profile
confirmations. Reboots are touches on both sides (schedule and verify), which is internally consistent.

## Decision 4 — one line, because the bug is one line
The worker already returns the honest "scheduled" string; the RowOf/OkOf already classify it; the only
wrong thing is the fan-out's AuditAction argument. Changing that one argument is the whole fix — no new
status, no view change, no re-plumb. Resisting the urge to "improve" the surrounding reboot flow is the
lazy-correct call.

## Decision 5 — static test on the isolated handler block
The audit action is an inline argument in the action handler, not a function, so the test isolates the
`schedule-reboot` handler block from the module source and asserts it carries TouchHost and not
VulnPatched (and that verify-post-reboot stays TouchHost). The handler's self-guard and gate behavior
are already exercised by Acas.SelfGuard and Server.Gate, so this test targets exactly the one thing
that changed.

## Decision 6 — version bump, full destructive regression pass
An audit-action change is behavioral (the compliance record differs): acas 1.11.8 -> 1.11.9, pin
migrated. schedule-reboot is destructive, so I ran the full 194-test acas + FixGuards + Server.Gate set
(the loop-22 wide-gate lesson) to confirm the self-guard, DNS wrong-box abort, and admin gate still
hold. Fable-inline; a one-line audit-honesty fix on a mapped finding needs no agent.
