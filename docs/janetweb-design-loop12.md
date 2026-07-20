# JANET Web — design loop 12 (2026-07-20)

## Decision 1 — deep-dive a DIFFERENT destructive surface (AD writes, not WinRM)
Every prior deep-dive targeted a WinRM fan-out tool (the self-guard/wrong-box/fail-closed
contract). adto is the suite's only DESTRUCTIVE-via-LDAP tool — it writes to AD objects
directly. Its risk class is different (LDAP/DN injection, wrong-OBJECT writes, UAC bit
clobber, privilege), so the self-guard contract doesn't apply and a fresh review was warranted.
The payoff: a real P2 (fix has no protected-object guard) that no self-guard sweep would have
found.

## Decision 2 — F1 fix: refuse DC + adminCount, not "re-derive the finding"
Opus offered two F1 fixes: (a) refuse DC/privileged objects before the write, or (b) re-run
`Test-AdToCompliance` server-side and apply only rules that actually fire. (b) is more thorough
(closes "wrong object for a rule that doesn't apply" generally) but a bigger change — it moves
the trust model from "trust the client plan" to "re-derive server-side," touching the whole
fix flow. (a) closes the CATASTROPHIC path (disabling a DC or break-glass admin) with a small,
surgical, easily-tested guard and no change to the legitimate flow. Chose (a) for this loop;
(b) is a candidate follow-up if the operator wants defense against non-catastrophic
wrong-object writes too. Match the fix size to the harm being closed.

## Decision 3 — guard the WHOLE write to a DC/admin, not just ACCOUNTDISABLE
The catastrophic rules are the two that SET ACCOUNTDISABLE (staleObject/inactiveEnabled), but
the guard refuses ANY adto-fix write to a DC or adminCount object — because this bulk-
remediation tool has no legitimate business modifying a domain controller or an
AdminSDHolder-protected object at all (those are deliberate manual actions). Simpler policy,
fail-safe direction, no legitimate use blocked (a stale WORKSTATION never has SERVER_TRUST or
adminCount).

## Decision 4 — F2: mirror the fix path's existing re-read
The fix path already re-reads UAC post-commit and gates FIXED vs FAILED. validate-iao didn't —
it trusted a non-throwing CommitChanges(). The fix is to copy the pattern that already exists
one function up: re-bind, confirm the stamp is present, report VALIDATED only then. Consistency
within the same module, and it matches the c2c persistence-verify model established earlier.

## Decision 5 — build the first adto behavior test harness
adto had only a DN-guard unit test; the fix/validate write logic was untested. Since I'm
adding safety guards to a destructive AD-write path, the guards need real regression coverage.
Shimmed `New-AdToEntry` (the only LDAP bind point) plus the DN/domain/IAO helpers in module
scope — the same idiom the WinRM tools use for New-PSSession — so the write logic runs against
fake DirectoryEntry objects (Properties indexer + CommitChanges) with no directory contact. The
F1 tests assert the fake's `Committed` flag ($false for DC/admin = write skipped, $true for
normal = write happened), which is the non-vacuous proof the guard actually gates the write.

## Versioning
adto `0.2.1 → 0.2.2` (behavioral: adds two guards + a fail-closed re-read). `AdTo.WriteGuards`
holds the exact pin. No other tool touched.
