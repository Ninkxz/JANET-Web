# JANET Web — design loop 49 (2026-07-21)

## Decision 1 — finish the certdeploy dive's real findings before moving on
Loop 48 closed F1 and left F2 (the other real, worker-CONFIRMED false-clean) ranked. Closing it now completes
certdeploy's deploy honesty in one pair of loops rather than leaving a known false-clean open while chasing a
fresh tool. F2's real-world trigger is narrow (the shipped DoD bundle is all v3 CA certs, so nothing is
rejected), but the tool must be honest for any operator-supplied bundle, and the fix is contained.

## Decision 2 — the guard is right; only the reporting lies
The trust-anchor guard refusing a non-CA cert for Root/CA is a *correct security control* — a leaf/end-entity
cert must never be pushed as a fleet-wide trust anchor. So the fix is not to the guard; it's that a
refused-and-absent anchor was being *classified* as ALREADY/INSTALLED. The honest classification is that the
deploy did not achieve "all present" (a wanted anchor is absent), which is exactly the audit-honesty principle
of loops 38/44/47: a not-fully-succeeded action must not book Success.

## Decision 3 — REJECTED outranks INSTALLED/ALREADY
A deploy that adds 3 valid CAs and rejects 1 non-CA is not a clean INSTALLED — the host's trust posture is
incomplete. So REJECTED sits above INSTALLED and ALREADY in the classifier (below FAIL and NOT VERIFIED, which
are more urgent). The granular "+3 added, 1 rejected" truth stays in the row Detail and the RejectDetail; the
host-level token/status/audit just stop reading clean. Same shape as the c2c PARTIAL fix (loop 47): a mixed
result with any failure component is not a Success.

## Decision 4 — complete the wiring, not just the token
A new token is only honest if the whole chain honors it: the token→row-Status switch maps REJECTED to a
distinct `REJECTED (non-CA)` status (so the row and tile show it), the level map colors it error, a `rejected`
summary bucket counts it (so it isn't invisible in the run summary), and — the load-bearing part — the audit's
`default` branch already books any non-clean status as Failure with itemCount 0, so REJECTED books Failure for
free. I verified each link rather than stopping at the classifier.

## Decision 5 — correct the tests that pinned the bug
Two CaValidation tests asserted the old rejected→INSTALLED/ALREADY tokens — they had encoded the false-clean as
expected behavior (their titles said "Token ALREADY"). That's the loop-37 lesson: a test can lie. I corrected
them to REJECTED with a note, and broad-grepped every test for the token so I could confirm the only other
INSTALLED/ALREADY assertions are `Rejected=0` cases that correctly stay unchanged. Version: a rejected-anchor
host moves from a clean/Skipped audit to Failure — behavioral — so certdeploy 1.4.1 → 1.4.2, loop-48 exact pin
→ floor, the new test holds the exact pin.
