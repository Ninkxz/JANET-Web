# Design - Loop 19 (Phase 2, cycle 17) - 2026-07-13

## Why: same correctness lens, next destructive orchestrator
Loop 18's deep CORRECTNESS audit of c2c found a real P2 (a success token omitted from a host rollup ->
a successful fix reported "NO CHANGE") that 15 cycles of SURFACE auditing never caught. That validates
the lens as genuine value, not churn. This cycle applies it to the second-biggest destructive tool:
`acas` (3384 lines, v1.11.1) - the ACAS Nemesis fleet patch/reboot/KB orchestrator.

## Why not churn
Prior acas passes cleared the surface classes (injection, XSS, gating; the self-guard was fixed + tested
in loop 5). A correctness lens on a 3384-line tool that REBOOTS and PATCHES production endpoints is real,
unexhausted risk:
- **Host targeting** (top): does each destructive action dial EXACTLY a finding's affected hosts?
  Intersection/allow-list correctness, FQDN-vs-short canonicalization consistency across import ->
  targeting -> self-guard -> wrong-box guard. A wrong-host reboot/patch is the worst outcome.
- **KB-install grouping + method fallback**: per-host KB grouping (no cross-assign), the ArticleID/Name
  match (no wrong-KB via loose substring), and honest MECM->UsoClient->wusa fallback reporting.
- **Reboot scheduling + verify honesty**: can verify-post-reboot FALSE-report a host as "came back"?
  The same KICKED-class rollup omission that bit c2c - is every success token counted, every failure
  surfaced?
- **Pool-runspace source injection** (known gotcha): every worker calls only helpers actually injected
  into its bare runspace, else a host is wrongly reported errored/no-op'd.
- **Partial-failure honesty** + **finding->remediation routing**.

## Decision rule
- A wrong-host reboot/patch, a false-success, a false "verified", or a missing source injection = **P1**,
  fixed this cycle (gated, tested, suite green). Meaningful logic error = P2.
- Any fix gets a targeted regression test where the logic is extractable/callable (pure helpers like the
  host-list/targeting functions are unit-testable via the module session state, as with the loop-16/17
  destructive-tool tests). If clean, a documented deep-correctness all-clear on acas.

One focused Opus reviewer. Non-colliding: acas is committed, not the certdeploy WIP zone. Every P1/P2
spot-verified by me against the code before any fix.
