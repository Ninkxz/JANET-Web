# JANET Web — design loop 61 (2026-07-21)

## Decision 1 — close pkginstall's second false-clean before pivoting
The loop-60 dive left two false-cleans (items 67, 68) and a safety gap (69). Loop 60 closed 67; this loop closes 68,
finishing pkginstall's false-clean pair in the same run of loops — the same discipline applied to secureboot's two in
loops 58-59. The confirm-word gap (69) is a coherent separate unit (module gate + JS view) for the next loop.

## Decision 2 — the exit code is authoritative, so the pre-seed must be honest
The whole PSADT branch is built on "the exit code is authoritative" (a deliberate loop-era decision that reversed an
earlier output-scraping false-FAIL). But that only holds if an *absent* exit code is distinguishable from a real 0.
Pre-seeding 0 collapses "the script explicitly succeeded (exit 0)" and "the script never reported anything" into the
same value — and the latter then inherits the former's Success. Pre-seeding `$null` keeps them distinct: a real
`exit 0` sets 0; a no-exit return leaves `$null`. This is the minimal change that makes the authoritative-exit-code
design actually honest.

## Decision 3 — null is Failed, and caught first
A run whose script set no exit code cannot be confirmed to have installed anything, so it is `Failed`, not Success and
not Deferred — fail-closed, matching the MSI branch's null-exit handling. The null check goes *first* in the if/elseif
chain so a `$null` can never fall through to `@(0,1641,3010) -contains $exitCode` (which is `$false` for `$null`
anyway, but relying on that is fragile — an explicit first branch states the intent and gives an honest operator
message instead of the generic "Non-zero exit code:" that the trailing `else` would have produced). A terminating
error is still handled by the existing catch, so this branch is specifically "ran to completion, reported nothing".

## Decision 4 — static analysis with an ordering assert; version
The branch lives inside `$script:RpiDeployHostScript`, a module-less runspace scriptblock (the loop-57/59/60
constraint), so the test is static analysis. Beyond asserting the pre-seed is `$null` (and the old `= 0` is gone),
the load-bearing assert is *ordering*: `$null -eq $exitCode` must appear before `$successExits -contains $exitCode`
in the source, proving a null is intercepted before it can reach the success check. Because a no-exit deploy's audit
moves from Success/itemCount-1 to Failed/itemCount-0, this is behavioral: pkginstall 2.5.9 → 2.5.10, the newest
bump's Describe holds the exact pin and the loop-60 all-1638 Describe floors.
