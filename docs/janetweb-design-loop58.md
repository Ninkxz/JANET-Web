# JANET Web — design loop 58 (2026-07-21)

## Decision 1 — take the destructive fail-open first
The loop-57 dive left five P3s on secureboot. Item 64 — dry_run failing open toward the live firmware write — is the
one that touches the campaign's non-negotiable rule (destructive actions stay fail-closed). A "reported dry-run but
actually wrote firmware" is more dangerous than the other four audit-wording gaps, so it goes first even at P3.

## Decision 2 — fix the call site, not the shared helper
`Get-SbeBool` is used for three params (`attemptOffline`, `dry_run`, `allowEmptyPassword`). For the other two, an
unrecognized token resolving to `$false` is fine — a scan that doesn't attempt offline hosts, a run that doesn't
allow an empty password, both fail SAFE at `$false`. Only for `dry_run` does `$false` mean the DANGEROUS thing (live
write). So this is a false-sibling: the same helper, opposite safety polarity per caller. Changing `Get-SbeBool`'s
default would wrongly flip the other two. The fix is a dedicated parser at the destructive call site (loop-50/54
lesson: narrow to the real site, don't widen a shared shape).

## Decision 3 — live requires positive non-dry, everything ambiguous stays dry
`Get-SbeDryRunSafe` inverts the failure polarity for this one selector: the live path is entered only on an *absent*
value or an *explicit, recognized* false token. `absent -> live` is kept deliberately — the manifest declares
`dry_run default=$false` and the view always sends it, so a normal "click Enable" still runs live; flipping absent to
dry would break every real enable. The change is precisely the present-but-unrecognized case: `'ture'`, `'dry'`,
`'2'`, `'maybe'` now stay dry instead of silently going live. The live write must be *asked for*, not *fallen into*.

## Decision 4 — a pure helper so the test is behavioral
Unlike the loop-57 filename fix (inline in a runspace scriptblock → static analysis), this logic factors cleanly into
a pure function, so it gets the preferred behavioral unit test: five `It`s driving `Get-SbeDryRunSafe` directly across
absent/empty, explicit-false, explicit-true, and the unrecognized-token class that is the actual fix. The
unrecognized cases would return `$false` (live) under the old `Get-SbeBool` and return `$true` (dry) now — a real
behavioral delta, so secureboot bumps 1.6.2 → 1.6.3. Per the suite convention the newest bump's file holds the exact
pin: it moves to ConfirmWord (the enable-safety test file, where this fix belongs) and the loop-57 Scan pin floors.
