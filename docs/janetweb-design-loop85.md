# JANET Web — design loop 85 (2026-07-22)

## Decision 1 — F2 (the deferred acas Java-remove false-Failure) gets its own careful loop
loop 84 confirmed but deferred F2: a successful Oracle-Java removal (`fix-java` profile) is audited VulnPatched
**Failure**. The removal's Verify probe reads post=`'not installed'`, which the bump-verdict classifier lists as a
degraded sentinel (`'error'`/`'n/a'`/`'not installed'` = "the probe could not read a current version"). True for an
UPDATE; wrong for a REMOVAL, where `'not installed'` is the SUCCESS state. It was deferred because the classifier is
delicate — the Chrome false-clean guard (loop 39/40) depends on `'not installed'` staying degraded for updates.

## Decision 2 — a profile-intent flag, gated so ONLY removals get the pass
The distinguishing fact is profile INTENT: a removal expects `'not installed'`; an update does not. So a profile
flag `PostRemovedOk` declares "post=`'not installed'` is a confirmed removal here". The gate is
`$PostRemovedOk -and post -eq 'not installed'` → confirmed; everything else falls through the UNCHANGED degraded/
downgrade logic. This is surgical: an UPDATE profile (no flag) is byte-identical, so the Chrome guard — an update —
is provably unaffected (verified: update→not-installed/error/n-a/downgrade all still `unconfirmed`). Only the
literal `'not installed'` is rescued; `error`/`n/a`/a downgrade are NOT (a removal that errored is still a failure).

## Decision 3 — fix BOTH the canonical fn and the inline mirror (their keep-in-sync convention)
`Get-AcasBumpVerdict` is the pure canonical twin; the update worker inlines it (module-less runspace — can't call
the fn). Both got the same gate. The canonical fn gains a `-PostRemovedOk` switch (unit-testable); the inline
mirror reads `$prof.PostRemovedOk` (the profile object is already in the worker's scope at `:1876`, alongside the
existing `NeedsJavaFix`/`NeedsSpecFix` flag-reads) and applies `$bumpRemovedOk`. A static test asserts the mirror
carries the same gate, matching how the file already tests its inline/canonical parity.

## Decision 4 — removal-aware diff wording
On a confirmed removal the result diff reads `removed: 8.0.301 -> not installed (confirmed gone)` rather than the
misleading `bumped: 8.0.301 -> not installed`. Cosmetic but honest; the row still renders OK/Success.

## Decision 5 — tests prove the fix AND the guard; the profile carries the flag
`Acas.BumpVerdict.Tests.ps1` +7 (behavioral): the flagged removal → confirmed; the SAME pre/post WITHOUT the flag
stays unconfirmed (the Chrome guard); the flag does NOT rescue error/n-a/downgrade; a real forward bump with the
flag on is still confirmed; the inline mirror carries the gate; the Java-remove profile declares the flag; exact
1.11.14 pin. The loop-71 exact pin (`Acas.FanOutHint`, 1.11.13) floored. acas 1.11.13 → 1.11.14. **loop-37 lesson:**
ran the full acas suite + the full suite. The Chrome false-clean guard (`Acas.ChromeProfile.Tests.ps1`) is part of
that run and stays green.
