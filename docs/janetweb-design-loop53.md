# JANET Web — design loop 53 (2026-07-21)

## Decision 1 — diversify to a fresh dive; adto over grinding the wpt tail
The remaining wpt items are nuanced (item43/51 need per-finding version targets or a big semantic change) or
weak/low, and I'd done six wpt loops. adto — the AD-TO compliance tool that writes userAccountControl over LDAP
— was un-loop-era-false-clean-dived and destructive (a false "compliant" or a wrong UAC write is an
access-control problem), so a fresh dive there restarts the productive find→fix cycle on new ground.

## Decision 2 — the dive answered the question I opened it with, in the reassuring direction
I spawned the dive specifically asking whether the fix path re-reads to confirm the UAC change (the discipline
validate-iao got in loop 12) or trusts the write. The answer: it DOES re-read (fresh-bind, compares to the
computed target) — the write paths are genuinely fail-closed. That's a valuable GREEN, and it redirected the
loop to where the real bug was: the read side.

## Decision 3 — fix F1, the one that both lies AND can corrupt
Of the read-side coercion findings, F1 is the highest-harm: it's on the destructive fix path, it books "already
compliant" for an object whose UAC was never read, and — the part that lifts it above a pure false-clean — a
set-op rule on the coerced `$cur=0` writes a full UAC that wipes NORMAL_ACCOUNT on a read-denied object. My
null-check fires before any computation or write, so it closes the false verdict AND prevents the corrupting
write in one guard. F2 (the scan reading COMPLIANT) shares the root coercion but is a separate function with a
different remedy (a distinct non-compliant/unknown verdict, touching Test-AdToCompliance) — ranked.

## Decision 4 — the sentinel is the null, not the zero
The coercion `[int]("0" + [string]$null)` deliberately turns null into 0 to avoid a throw. But 0 is a *valid
int*, indistinguishable from a real UAC of 0 — except a real account's UAC is never 0 (NORMAL_ACCOUNT alone is
0x200). So the honest signal is the raw `.Value` being `$null`, checked before the coercion, not the computed 0
after. Reading `$rawUac` and testing `$null -eq $rawUac` is precise; testing `$cur -eq 0` after would also work
but conflates "unreadable" with a (nonexistent) legitimate zero. I keyed off the null.

## Decision 5 — behavioral test via the existing fake harness; version
The adto tests drive `Invoke-AdToFix` with a fake DirectoryEntry (`New-FakeDe`), so the fix is behaviorally
testable — except `New-FakeDe` types `-Uac [int]` (can't be null), so I built a null-UAC fake inline and
asserted: a null-UAC object → FAILED (not "already compliant"), nothing committed (the corrupting write is
prevented), and a Failure audit. A real UAC (512) still FIXES — the existing test proves no over-block. A
null-UAC object that read "already compliant" now reads FAILED — behavioral — so adto 0.2.3 → 0.2.4, the sole
exact pin updated (adto has one test file). F2/F3 ranked as items 60/61; F4/F5 speculative, noted.
