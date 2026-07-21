# JANET Web — design loop 27 (2026-07-21)

## Decision 1 — take item 21, the crispest remaining acas item
Of the three open acas items, 21 is a PROVEN port: I fixed the byte-identical bugs in wpt loop 22, so
the fix shape, the helper, and the test are all known-good. Highest confidence, lowest risk, and it
brings the two sibling kb-install workers into parity — a good use of a loop over the more involved
item 19 (audit-timing re-plumb).

## Decision 2 — port, don't reinvent
The acas and wpt kb-install MECM blocks are the same code with different variable plumbing. The wpt
loop-22 fix (anchored ArticleID-exact / bounded-Name-token match + null-rv fail-close) drops in
directly. `Test-AcasKbNameMatch` is `Test-WptKbNameMatch` verbatim in a different module (acas loads
in its own runspace and can't import wpt), and the inline `$kbMatch` mirror is identical. Reuse the
proven shape rather than derive a new one.

## Decision 3 — inline mirror, because the runspace has no module
Same boundary as every kb-install/verify fix: the MECM match runs over WinRM in a module-less context,
so the canonical `Test-AcasKbNameMatch` is the tested spec and the scriptblock mirrors it inline,
comment-linked. The null-rv fail-close is a one-line predicate flip in that same scriptblock.

## Decision 4 — test both the rule and the wired path
`Acas.KbMatch.Tests.ps1` pins the pure `Test-AcasKbNameMatch` (mirroring the wpt test), and FixVerify2
gains an acas NULL-ReturnValue case driven through the real worker shim — the `-Rv -1` sentinel added
in loop 23 already makes the acas mock return a result with no ReturnValue member, so the wired
fail-close is exercised end-to-end, not just the predicate.

## Decision 5 — version bump + pin migration, full acas regression pass
Anchored matching changes which update installs and the null-rv change flips a trigger to a rejection,
both behavioral: acas 1.11.7 → 1.11.8, loop-26 exact pin → floor, loop-27 test holds the exact pin.
kb-install is destructive, so I ran the full 180-test acas + FixVerify2 + FixGuards set (the loop-22
wide-gate lesson), confirming the self-guard and reachability→FAIL paths are intact. Fable-inline; a
proven port needs no agent.
