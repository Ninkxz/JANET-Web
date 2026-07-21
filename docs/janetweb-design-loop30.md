# JANET Web — design loop 30 (2026-07-21)

## Decision 1 — take the independent finding, defer the entangled cluster
The loop-29 c2c deep-dive left five findings. Three of them (F1 SKIP-masked FIXED, F2 trigger-as-fixed,
F3 NOT-VERIFIED→nochange) all live in the fix-rollup host-status + pillar-tally buckets and are
interdependent — fixing F2 (KICKED not counted fixed) without F3 (a pending bucket) would just make
KICKED vanish. Doing one in isolation risks a half-fix, so that cluster deserves its own dedicated loop.
F5 is independent, so it's the clean single-loop pick this iteration.

## Decision 2 — closing the last scan-side hole keeps the scan fully fail-closed
The deep-dive praised the scan verdict as fail-closed everywhere except F5. Fixing F5 makes that true
without exception, which matters because the scan is what drives the READY posture number. A tool whose
scan is 100% fail-closed is a stronger claim than one with a single silent PASS hole.

## Decision 3 — fail closed: an un-ageable MISSING update is overdue
The bug is that "within grace" was the default for any update the predicate couldn't classify. For a
compliance tool the default must invert: a missing security patch you can't prove is within grace is
overdue. It's still a real missing update (ComplianceState=0) — the only question is age, and absent
evidence the conservative answer is "overdue", not "fine".

## Decision 4 — rewrite the predicate as if/elseif/else, not two OR'd clauses
The original two-clause OR had the `(-not $_.Deadline)` guard that silently dropped a non-datetime
Deadline from the StartTime path. Restructuring to if(datetime Deadline)/elseif(datetime StartTime)/else
makes each case explicit, fixes the deserialize-glitch drop for free, and puts the fail-closed default
in the visible `else`. Clearer AND more correct than patching the OR.

## Decision 5 — canonical helper + inline mirror (runspace boundary)
The Patches check runs on the target in the single-round-trip scan scriptblock, a module-less runspace,
so it can't call `Test-C2cUpdateOverdue`. Same pattern as the kb-install/verify helpers: the helper is
the pure tested spec (deadline/startTime/fail-closed cases), the scan worker mirrors it inline,
comment-linked, and a static assertion pins that the worker references the rule.

## Decision 6 — version bump, full c2c regression pass
A changed scan verdict is behavioral (a host that read PASS may now read FAIL): c2c 1.15.3 -> 1.15.4,
ImportCompliance exact pin -> floor, loop-30 test holds the exact pin. c2c is a destructive tool, so I
ran the full c2c set (the loop-22 wide-gate lesson), confirming no existing scan test depended on the
old silent-PASS behavior. Fable-inline; a fail-closed predicate rewrite on a mapped finding needs no agent.
