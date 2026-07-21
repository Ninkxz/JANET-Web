# JANET Web — design loop 54 (2026-07-21)

## Decision 1 — finish the pair: F2 is F1's scan-side twin
Loop 53 closed F1 (the fix path reading a null UAC as "already compliant" + corrupt-writing it) and left F2 (the
scan reading a null UAC as COMPLIANT) ranked. They share one root — `[int]("0" + [string]$null) = 0` — in two
functions. Closing F2 now finishes adto's null-UAC honesty in a pair, so no half of the coercion is left open.

## Decision 2 — a distinct verdict, not a silent pass or a fake bad-bit
The honest handling of an unreadable UAC is neither "assume compliant" (the bug) nor "assume every bad bit is
set" (over-flagging a benign account as if it had PASSWD_NOTREQD + DONT_EXPIRE + reversible-encryption). It's a
third state: *we could not confirm*. So the fix adds a dedicated `uacUnreadable` hit that makes the object
NON-COMPLIANT for the right reason, and skips the four UAC bad-bit rules rather than letting a 0 masquerade as
their answer. The operator sees "userAccountControl absent/unreadable" and knows to check ACLs, not a fabricated
list of violations.

## Decision 3 — carry the signal in the object, decide in the pure function
The read (`ConvertTo-AdToObject`) is where "unreadable" is known; the verdict (`Test-AdToCompliance`) is where it
matters. Rather than smuggle a sentinel into the `Uac` int (0 is a valid value and the `$disabled` math still
needs a real int), I added a separate `UacReadable` boolean — the read sets it, the pure verdict function reads
it. `Test-AdToCompliance` stays pure and injectable, so the fix is unit-testable directly with a hand-built
object; and a caller that predates the flag defaults to readable, so nothing silently starts failing.

## Decision 4 — a synthetic hit, not a configurable rule
`uacUnreadable` bypasses the `$fire` machinery (which checks a baseline `enabled`/`appliesTo`) and adds directly
to the hit list. That's deliberate: you cannot "disable" the fact that a read failed — a fail-closed signal must
not be silenceable by the operator-editable overlay (which is itself item61's weakness). So it's a hard-wired
hit, not a baseline rule.

## Decision 5 — behavioral test via the pure function; version
`Test-AdToCompliance` takes an injectable `$Now` and a plain hashtable object, so the fix is behaviorally tested
directly: unreadable → NON-COMPLIANT + the hit; a readable no-bad-bits UAC → no over-flag; a readable
PASSWD_NOTREQD still flagged (the bad-bit path still works, proving the guard didn't disable it); a missing key →
readable. A service account with a hidden UAC that scanned COMPLIANT now scans NON-COMPLIANT — behavioral — so
adto 0.2.4 → 0.2.5, the sole exact pin updated. item61 (overlay silent-disable) + F4/F5 stay ranked.
