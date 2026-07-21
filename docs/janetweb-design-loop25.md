# JANET Web — design loop 25 (2026-07-21)

## Decision 1 — diversify to acas via the same bounded-worker pattern
Three wpt loops was enough; acas is the other most-used tool and the actual remediation engine, where a
false "patched" is the highest-stakes false-clean. The wpt worker pattern paid off, so I reused it:
one Fable worker, scoped to a single question (where does un-remediated read as patched), during the
loop-24 suite wait. It found four false-cleans AND refuted a standing roadmap suspicion — both valuable.

## Decision 2 — verify the worker, including its refutation
A subagent finding is a lead, not a verdict — so I re-read each in code, and that includes the
refutation: item 6 (SKIP-as-OK) is real in the predicate but dead at the only call site (skip is
checked first). Recording a refutation honestly is as useful as a fix: it stops a future loop chasing
a non-bug, and flags the predicate as a latent hazard without pretending it's live.

## Decision 3 — fix the status cluster (findings 1-3) as one coherent workstream
The three kb-install false-cleans (trigger→OK, uso→OK, partial→OK) are all one code region (the status
determination), all the same class (accepted != confirmed; a partial must not mask a failure), and all
the acas sibling of what wpt loops 22-23 already fixed. Fixing them together is one honest change, not
three; the proven wpt shape (UNCONFIRMED for triggers, errors always win) ports directly.

## Decision 4 — UNCONFIRMED, because acas already speaks it
acas's AcasOkOf already treats `UNCONFIRMED*` as not-ok and the UI renders it amber, so the honest
label needs no new UI state — a trigger returns UNCONFIRMED and falls out of the patched tally for
free. Errors return FAIL (never masked). This is the minimum change that stops the false-clean using
machinery the tool already has.

## Decision 5 — inline mirror, because the runspace has no module
The worker runs in a `CreateDefault` runspace (no module imported), so it can't call
`Get-AcasKbInstallStatus`. Same boundary as the wpt remote scriptblocks: the helper is the canonical
tested spec, the worker mirrors it inline, comment-linked. The real worker's status is also exercised
end-to-end by FixVerify2's shim, so both the pure rule and the wired path are covered.

## Decision 6 — correct the test that pinned the false-clean
FixVerify2 asserted rv=0 → `^OK` ("happy path unchanged") — it had encoded the bug. Correcting it to
`^UNCONFIRMED` is part of the fix, not collateral: a trigger is not a happy-path install. Documented in
the test so the change reads as intent.

## Decision 7 — scope: status only; rank the rest
The same block also has the loose KB-match and null-rv (wpt loop-22 siblings) and the verify-inflates-
PATCHED and schedule-reboot-audit issues. All real, all different concerns; folding them in would blow
the diff and the test surface. One workstream, one fix, one test — the rest become ranked items 18-21.
acas 1.11.5 → 1.11.6 (a changed status is behavioral); pin migrated; ran the full acas set (the
loop-22 wide-gate lesson) since kb-install is destructive.
