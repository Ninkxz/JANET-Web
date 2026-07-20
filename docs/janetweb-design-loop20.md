# JANET Web — design loop 20 (2026-07-21)

## Decision 1 — close the standing sweep, not open a new thread
The roadmap has carried "reports host-key normalization sweep completion" since loop 14. Loop 20
finishes it rather than starting a fresh deep-dive: the Remediation Plan was the last per-app host
rollup still keyed on the raw hostname, and the fix pattern (Get-ReportsAuditHostKey) is already
proven and consistent with the rest of the tool.

## Decision 2 — a real over-count, verified against the code beside it
This is a genuine correctness bug (per-app host summary over-counts a short+FQDN pair), and the
proof it's an oversight rather than intent is three lines below the gap: the Other-group host count
in the SAME function was already normalized in loop 13. Matching the main bucket to it removes an
internal inconsistency, so the fix is low-risk and self-justifying.

## Decision 3 — normalize all THREE coupled sites or none
The bucket key is also the session status key. Normalizing only the count would leave the status
setter writing a raw key the (now-normalized) reader can't find, silently dropping "Pushed" marks.
So the fix is bucket key + summary count + status setter together — one uniform key space — or it
would trade a count bug for a status bug.

## Decision 4 — fold direction follows the established repo decision
Short-fold can in theory merge two distinct boxes that share a short name across domains. The repo
already decided (loops 13-14, the Other-group count, the Get-ReportsHostKeyCollisions guard) that
short-fold is intended and ambiguity is surfaced separately. Loop 20 follows that decision for
consistency rather than inventing a new policy — the Remediation Plan should agree with CORA.

## Decision 5 — keep the raw first-seen Hostname for display
The bucket still stores `Hostname = $f.Hostname` (raw, first-seen) so the plan row shows a real
hostname; only the KEY folds. Display unchanged, counting corrected.

## Decision 6 — test the fold via the real builder, FQDN-first
The regression test drives the actual `Build-RemediationPlan` over seeded findings. It seeds the
FQDN variant FIRST deliberately: a raw short name already equals its own normalized key, so only a
first-seen FQDN row makes the pre-fix bucket key differ from the post-fix one — i.e. the only
ordering that actually fails before the fix and passes after. It also asserts distinct hosts still
count as two (no over-merge) and that a normalized-key status reads back onto the folded row.

## Decision 7 — version bump, Fable-inline
A changed operator-facing count is behavioral: reports 2.14.23 → 2.14.24, loop-19 exact pin → floor,
loop-20 test holds the exact pin. Reading one function, spotting the raw-key tail, and a symmetric
3-site normalization + test is inline Fable work; no agent warranted on a non-destructive read path.
