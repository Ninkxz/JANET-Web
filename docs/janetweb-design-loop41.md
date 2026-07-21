# JANET Web — design loop 41 (2026-07-21)

## Decision 1 — take the wpt HIGH item that completes loop-40 and has a precedent
Of the three HIGH wpt items the loop-40 dive ranked (40 systemic-OK-on-trigger, 41 verify-tally, 42
bulk-patch null-RV), item41 is the cleanest first close: it directly *completes* loop-40 (my acas C2R fix
makes a probe return Verified=$false; item41 is wpt swallowing exactly that verdict), and it's the one thing
acas already solved identically (`Get-AcasVerifyRowStatus`), so the fix has a proven shape to mirror rather
than inventing one. item40 is bigger (many profiles) and item42 is a separate null-RV sweep; each gets its own
loop.

## Decision 2 — fix the predicate, not the Status field
wpt's model separates "the verify probe ran" (`Status='Verified'`) from "the host is current" (the `Verified`
column). That's a legitimate model — the row already shows `Verified=No` honestly. The bug is purely that the
ok/tally/audit predicate keyed off "the probe ran" instead of the verdict. So the minimal correct fix is the
OkOf (require `$Verified -eq $true`), leaving Status and the row display alone. Changing Status='Verified' to
mean the verdict would have been a larger, riskier refactor touching the row semantics for no extra correctness.

## Decision 3 — a not-verified host is Skipped, not Failed
Requiring `Verified=$true` for ok means a reachable Verified=No host becomes not-ok. Auditing that as Failure
would be wrong and noisy — the verify *succeeded*; the host is simply not-yet-current, which is the normal
state for most of a fleet on any given week. So the new AuditResultOf mirrors wpt's own PENDING→Skipped
pattern: reachable-but-not-verified → Skipped (checked, no action booked), only unreachable/DNS-mismatch/
probe-threw → Failure. This keeps the false-clean closed without manufacturing a false-failure.

## Decision 4 — pure helper (controller-side, so no inline mirror)
Unlike the acas/winupgrade verdict helpers, the fan-out's OkOf runs controller-side in `Invoke-WptFanOut`
(module loaded), so `Get-WptVerifyOk` is called directly — there is no module-less runspace here and thus no
inline mirror to keep in lockstep. The pure helper is unit-tested at every branch; the handler wiring (OkOf
calls the helper, the old predicate is gone, not-verified audits Skipped) is pinned by static block isolation,
the established wpt pattern for inline action-handler scriptblocks.

## Decision 5 — version + verification
The "N verified" tally and the audit results change for verify runs — behavioral, so wpt 6.8.8 → 6.8.9, the
loop-40 C2rVerify exact pin → floor, the new VerifyApp test holds the exact pin. Ran the wpt verify/profile/
self-guard/KB set (78 green) and grepped all tests for the touched symbols including the action id
`app-update-verify` (loop-37/38 lesson) — ChromeProfiles + SelfGuardApply reference it for routing/self-guard
and are unaffected.
