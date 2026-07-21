# JANET Web — design loop 42 (2026-07-21)

## Decision 1 — the proven-precedent HIGH over the nuanced ones
Of the three open wpt HIGH items, item42 was the one with an in-repo precedent to mirror rather than a design
question to open: kb-install already decided (loop22) that a null client-SDK ReturnValue must fail closed, with
an explicit comment. item40 (M365 profiles report OK ignoring the exit code) is complicated because
OfficeC2RClient's exit code is often 0-regardless and the real signal is a post-trigger verify — a bigger
change. item43 (Java SC mtime verify) needs a required-version target, the same unresolved question as acas
item35's non-C2R slices. So item42 is the clean close this loop.

## Decision 2 — let the static assert define the true scope
I initially scoped the fix to the two bulk-patch sites the worker cited. The regression test's static assert —
"the old null-accepting form is gone from the module" — failed, which is exactly what that assert is for: it
surfaced three more instances of the identical fail-open (the SC App/Update trigger action and
WptAppActionBlock). A false-clean of this shape is a *class*, not two lines; fixing only the flagged instances
would have left the same bug live elsewhere and shipped a test that lies about coverage. So the fix became a
5-site sweep. This is the loop-37 lesson generalized: the module-wide assert is the honest scope-finder.

## Decision 3 — override one worker "GREEN" on evidence
The worker called WptAppActionBlock GREEN. Re-verified in-code, its null-rv path returned OK=true and flows to
app-update-apply's VulnPatched audit — the same fail-open. A subagent verdict is a lead, not a ruling; the code
showed the null case slips, so I fixed it. The block still re-reads and surfaces the post-invoke EvaluationState;
only the null-rv OK verdict changed (to fail-closed).

## Decision 4 — pure helper + inline mirrors (module-less remote scriptblocks)
The RV check runs inside remote Invoke-Command scriptblocks (module-less), so `Get-WptRvAccepted` is the tested
canonical and each of the five sites carries the one-liner inline under a keep-in-sync comment. The static
assert pins that no old null-accepting form survives and the fail-closed form recurs, so the mirrors can't drift
back. A one-line predicate arguably doesn't need a helper, but making the fail-closed decision a single named,
tested source of truth is worth it when it's mirrored five times.

## Decision 5 — scope the null-rv fix; rank the trigger-vs-patched semantic
item42 as fixed closes the *null-rv* fall-through. The worker also noted the deeper issue that a merely-accepted
async CCM trigger (rv=0) books VulnPatched rather than a confirmed install — but that's the same trigger≠patched
semantic as item40, and kb-install's own answer ("Triggered (verify)") shows it's a distinct, larger change. I
ranked it as item51 rather than smuggle it into a null-rv loop. Version: a null-rv host that read triggered now
reads rejected — behavioral — so wpt 6.8.9 → 6.8.10, VerifyApp exact pin → floor.
