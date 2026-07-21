# JANET Web — design loop 68 (2026-07-21)

## Decision 1 — close the last dhcp false-clean
Of the remaining dhcp items, 78's null-result aspect is the one that actually reports a change that didn't happen as a
clean Success — a false-clean, the campaign's core class. It goes ahead of the option-id retarget (a wrong-target
write, real but narrower) and the scope reconciliation (an accounting gap). It's also contained and testable via the
same shimmable seam loop 65 used.

## Decision 2 — split item 78: fix the acute false-clean, rank the verify
The dive's item 78 bundled two things: (a) a null apply result coercing to Changed/Success, and (b) no post-write
re-read verifying the option actually became the intended value. (a) is an acute false-clean with a one-guard fix;
(b) is a mandatory-verify feature — the upr-style re-read-and-compare — that touches both the apply and bulk remote
scripts and deserves its own careful loop. So this loop closes (a) and ranks (b) as a new item 80. Shipping the
one-guard fix now is honest and low-risk; folding in the verify would balloon the change and under-test it.

## Decision 3 — a null result is Failure, guarded like the catch
The remote apply script returns a `{ Removed = $bool }` record on success. No record means the apply produced
nothing — indistinguishable from an error except that it didn't throw. The honest verdict is the same one the
function's `catch` already books: Failure, Status='Error', `failed=1`, an audit that says the change was not confirmed.
So the null-result branch is a copy of the catch's shape, placed right where the null first becomes indistinguishable
from a real "not removed" (`[bool]$null.Removed`=`$false`). A real record still flows to the existing Changed/Removed
logic untouched.

## Decision 4 — behavioral test via the two-seam shim
`FixVerify3` already proves the pattern: shadow `Invoke-JanetOnDhcp` (the pre-read) and `Invoke-JanetOnDhcpCancelable`
(the write) and drive the real `Invoke-JanetDhcpApply`. I mirrored that in the dhcp test file with the pre-read
returning a valid current state (so the diff is non-empty and the write is actually reached) and the write returning
an **empty** result — the exact null-result condition — and asserted `Status='Error'`, `failed=1`, `ok=0`, and a
Failure audit whose detail says "NOT confirmed". Because an apply that returns nothing now books Failure instead of a
false Changed/Success, this is behavioral: dhcp 1.1.11 → 1.1.12, the newest Describe holds the exact pin and the
loop-67 dryRun Describe floors.

## Decision 5 — a counting correction, recorded
Loop 67's docs estimated 1479; the dryRun Describe is five It's, so the real count was 1481 (confirmed by the
authoritative run). I corrected the loop-67 ledger and changelog rather than let a wrong number stand — the same
honesty the false-clean campaign is about, applied to the bookkeeping. Loop 68 (+2) lands at 1483.
