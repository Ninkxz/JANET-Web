# JANET Web — design loop 65 (2026-07-21)

## Decision 1 — dive the under-tested destructive tool
The dived destructive tools (adto, remoteadmin, secureboot, pkginstall, upr) all had fail-closed cores. dhcp is the
next substantial destructive tool (four server-config write actions) and, tellingly, had only an IP-validation test —
minimal coverage on a tool that mutates DHCP option values on remote servers. Thin tests + high destructive surface
predicted findings, and the dive delivered a real P1 (the first non-fail-closed core in several loops).

## Decision 2 — fix the laundering at the local handler, where the honesty was lost
The remote script is the honest part: it distinguishes "option does not exist" from "read failed" and, on a read
failure, returns `ReadError` and writes nothing — a textbook fail-closed refusal. The bug is entirely in the LOCAL
handler that consumes those records: it neither counted nor audited `ReadError` as anything, so the remote's careful
refusal evaporated into a clean report. So the fix belongs where the status is interpreted, not in the (correct)
remote script.

## Decision 3 — make BOTH status→outcome mappings fail-closed, not just patch ReadError
The root cause is that the handler has TWO independent mappings of the same `$status` — a counter if/elseif and an
audit switch — and `ReadError` fell through both. Patching only `ReadError` would leave the next new status to drift
the same way. So the counter's tail becomes a catch-all `else { $errs++ }` (unknown → error) and both switch defaults
become `Failure` (unknown → failure). Now an unrecognized status can never again be silently counted-clean or
audited-Success; the explicit `ReadError` cases just give an honest "REFUSED: could not read" detail on top. This is
the campaign's standing lesson: a switch/if default on a destructive result must fail toward Failure, never Success.

## Decision 4 — behavioral test via the shimmable remote seam
Unlike the recent runspace-scriptblock fixes, the bulk handler's result-processing runs LOCALLY over records returned
by `Invoke-JanetOnDhcpCancelable`, which is a shimmable module function. So the regression test is genuinely
behavioral: shadow that call to return a single `ReadError` record and assert the emitted audit is `Failure`, the
summary counts it as failed with zero ok, and the row keeps its honest `ReadError` status — end-to-end proof the
refusal is no longer laundered. A static assert (no bulk audit default books Success) backstops the fail-closed
default. Because a refused scope's audit moves from Success to Failure, this is behavioral: dhcp 1.1.8 → 1.1.9.

## Decision 5 — scope this loop to the P1; rank the rest honestly
The dive found dhcp materially under-guarded: no self-guard, no confirm-word, a dry-run fail-open, an option-id
retarget, and no post-write verification — five more real items (75-79). That's a follow-up hardening loop's worth,
and item 75 (the self-guard + confirm-word hard-rule gap) is the natural next pick. Bundling them into this loop would
break the one-workstream discipline and under-test each; ranking them keeps the honest record that dhcp is not yet
done.
