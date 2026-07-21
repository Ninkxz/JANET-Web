# JANET Web — design loop 44 (2026-07-21)

## Decision 1 — diversify to c2c; a fresh dive on the un-reviewed destructive compliance tool
Six consecutive acas/wpt verify-honesty loops had thinned that vein to nuanced items, and my loop-43 doc flagged
weighing a fresh dive. c2c — a destructive Comply-to-Connect remediation tool with six pillar fixes and a
quarantine-predictor scan, never comprehensively loop-era false-clean-reviewed — was the highest-harm fresh
target: a pillar reported FIXED/compliant or a host READY when it isn't is the worst class here. The dive
followed the acas/wpt pattern (Fable worker over the full module, I re-verify in-code).

## Decision 2 — fix F1, the clearest HIGH-harm pillar false-clean
The dive returned nine findings; F1 is the cleanest high-harm close. It's a pillar (AntiMalware — a quarantine
pillar) booking FIXED off a partial signal (a service flip) precisely when it CAN'T see the real state
(Get-MpComputerStatus absent), on exactly the hosts most likely broken. And the fix is nearly free: c2c already
has a NOT VERIFIED fail-closed state that the host rollup (`:2360`) and audit switch (`:3090`) both handle
correctly — the else-branch just wasn't using it. So the fix is one verdict token (FIXED → NOT VERIFIED) that
reuses proven machinery. F5 (Monitoring, the same class) and the rest are ranked.

## Decision 3 — NOT VERIFIED is the right verdict (not FAIL, not SKIP)
We DID make a change (flipped the service), so it's not a clean FAIL, and it's not a no-op SKIP. NOT VERIFIED is
exactly "a change was made but its success couldn't be confirmed" — the semantics PkiRoots uses for certs added
but absent on re-read. Reusing it keeps the host rollup and audit honest (NOT VERIFIED → not FIXED → not a
Success/VulnPatched) with zero new verdict plumbing.

## Decision 4 — static analysis over a leaking behavioral harness
I first wrote a behavioral harness driving the real fix block with `Get-MpComputerStatus` hidden — but hiding it
requires shimming `Get-Command`, and that shim leaked into the sibling AntiMalware *scan* tests (they hit the
SecurityCenter2 fallback and failed, and the leaked state hung RunAll/ImportAndFix into a suite timeout). The
honest, non-invasive test is static analysis of the else-branch (books NOT VERIFIED, old blind FIXED gone),
with the NOT VERIFIED → rollup → audit mapping already behaviorally covered by the PkiRoots and rollup tests.
Chasing a behavioral test that corrupts its neighbors is worse than a precise static one.

## Decision 5 — version + honest ranking
A host that read FIXED now reads NOT VERIFIED — behavioral — so c2c 1.15.4 → 1.15.5, the loop-30 patch-overdue
exact pin → floor, the new test holds the exact pin. The c2c set (109 across 5 files) is green; the full
authoritative run gates the close. The dive's other eight findings are ranked as items 52–57 (+ F2/F6 refining
the known items 22/24 cluster) — several are low/read-only/speculative, F5 is the next real one. A rich,
honestly-triaged backlog is the dive's product; each needs in-code re-verification before it's acted on.
