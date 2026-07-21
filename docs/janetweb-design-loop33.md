# JANET Web — design loop 33 (2026-07-21)

## Decision 1 — close a confirmed backlog item, don't grow the backlog
After four tools' worth of false-clean deep-dives (wpt/acas/c2c/winupgrade) there's an ~11-item
confirmed backlog. A fifth deep-dive would surface more real bugs but grow the queue; at this point
CLOSING a confirmed item is worth more. Of the open winupgrade items, F3+F4 (bypass read-back) is the
cleanest AND testable AND security-relevant — the best backlog item to retire this loop.

## Decision 2 — extend the module's own read-back gate, don't invent one
The Pin/Unpin core already read-back-verifies the TRV trio and refuses DONE on a mismatch — the exact
pattern the bypass value needed. The fix just extends that gate to one more value: `$pinReadSb` reads
the MoSetup value, Pin requires it set when bypass was requested, Unpin requires it gone when removal
was requested. No new verification machinery, just close the gap in the existing one.

## Decision 3 — the Unpin case is the security one; both matter
Pin asserting "BYPASS SET" while it isn't leads to a later hardware-blocked upgrade failure (annoying).
Unpin asserting "bypass key removed" while it stays armed is worse: an admin cleaning up the
Microsoft-unsupported bypass believes the host is back to a supported stance when the unsupported
config persists. Both are read-back gaps; fixing them together is one coherent change.

## Decision 4 — additive and fail-closed: no bypass requested, no change
The verify only fires when `$Bypass` / `$RemoveBypass` is set, so a normal Pin/Unpin is byte-for-byte
unchanged (the pre-existing read-back tests stay green untouched). A missing/false BypassPresent on a
requested bypass fails the row rather than reporting DONE — the same fail-closed stance as the TRV verify.

## Decision 5 — reuse the existing FixVerify2 Pin/Unpin harness
FixVerify2 already drives the real Pin/Unpin worker with the read-back (PINREAD) shimmed. I added a
`-Bypass` / `-RemoveBypass` flag (positional args 17 / 19) and four cases that feed a read-back with
BypassPresent true/false and assert DONE vs FAILED. It exercises the real worker's verify+gate logic,
not a reimplementation — the same harness that already proves the TRV read-back.

## Decision 6 — version bump + full regression pass
A new read-back requirement is behavioral (a Pin/Unpin that used to report DONE can now FAIL):
winupgrade 0.5.3 -> 0.5.4, the loop-32 exact pin -> floor, the loop-33 test holds the exact pin. Pin/
Unpin are destructive, so I ran the full 198-test winupgrade + FixVerify2/3 set green. Fable-inline; a
read-back extension on a mapped finding, reusing an existing harness, needs no agent.
