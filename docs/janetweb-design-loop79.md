# JANET Web — design loop 79 (2026-07-21)

## Decision 1 — this is a de-duplication, not a new feature
loop 70 built the shared engine on the premise "one engine, not per-tool copies", and retired dhcp's thin
mapper in loop 75. restart's `Get-RrsShutdownErrorHint` was the LAST ad-hoc mapper, and its 6 detail-string
branches are byte-for-byte the same failure classes the shared engine already handles. So the primary act is
deletion: restart delegates its text matching to the engine. The only *addition* is the small slice of
restart's knowledge the engine genuinely lacked.

## Decision 2 — what to fold UP into the engine vs keep in restart
Split restart's numeric `$Code` switch by generality:
- **General, shareable, and MISSING from the engine** → fold up: privilege-not-held (1314 /
  SeRemoteShutdownPrivilege), RPC no-more-endpoints (1727), ERROR_BAD_NETPATH. Any tool acting over
  WinRM/RPC can hit these, so the engine is the right home.
- **General but already in the engine** (5→access-denied, 1722→RPC, 53's SMB cause) → nothing to do.
- **Tool-specific shutdown.exe sentinels** (0, 1115 shutdown-in-progress, 1116 no-shutdown, 1190
  already-scheduled, -1/-3/-4 tool internals) → stay in restart. These are meaningless to any other tool and
  would pollute a general engine. restart keeps its numeric switch for exactly these.

## Decision 3 — privilege-not-held is a DISTINCT tier, not a flavor of access-denied
ERROR_ACCESS_DENIED (5) and ERROR_PRIVILEGE_NOT_HELD (1314) are different: access-denied = "you are not
trusted here" (not a local admin / UAC filtering); privilege-not-held = "you ARE trusted, but you lack this
one user right" (a local admin can still lack SeRemoteShutdownPrivilege if a GPO stripped it). They point at
different fixes (group membership vs User Rights Assignment), so the hint is a separate signature with its own
fix text, placed right after access-denied. Their regexes are disjoint (no token overlap), so the order
between them is safe either way.

## Decision 4 — bare `53` is NOT a safe engine token, but `ERROR_BAD_NETPATH` is
The engine matches on arbitrary raw error text, so a bare 2-3 digit number is a false-positive magnet (`53`
appears inside timestamps, byte counts, other codes). restart can use bare `53` safely because it only
reaches the numeric switch with an *actual shutdown.exe return code*, never free text. So the engine gets the
named token `ERROR_BAD_NETPATH` only; restart keeps `53` in its switch. Same reasoning kept `1314\b` (word-
boundaried) as the riskiest numeric I allowed into the engine, guarded by the boundary + 5 named aliases.

## Decision 5 — delegate-then-fallback preserves behavior exactly; test both arms
The rewritten mapper tries the engine on `$Detail` first (richest, plain-language), and ONLY if it returns
'' falls to the numeric switch — the same precedence restart always had (its old text branches ran before the
switch and fell through on no match). So no input changes outcome class: a matching Detail gets an equal-or-
richer hint, a non-matching Detail hits the same numeric code as before. The regression test drives BOTH arms
(a detail string → shared hint; a bare code → numeric switch) behaviorally, plus static assertions that the
duplicated branches are gone and the delegation call is present. restart 1.5.0-beta8 → beta9 (beta line
continues its own numbering). The engine's own +5 tests pin the folded signatures. **restart was the last
ad-hoc mapper — after this loop the engine is the single source of hint truth.**
