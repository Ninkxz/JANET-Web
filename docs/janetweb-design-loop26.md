# JANET Web — design loop 26 (2026-07-21)

## Decision 1 — take item 18, the highest-harm remaining acas false-clean
The loop-25 deep-dive left four ranked items; 18 is HIGH and the same class the recent loops target (a
not-remediated host shown as patched). It's also self-contained and finishes making the acas
remediation-tally surface honest on its worst paths, so it's the clear pick over the lower-harm 19-21.

## Decision 2 — fix it at the source (the verify string), not the view
The false-clean surfaces in the view's PATCHED counter, but the root is that the verify branch returns
an unclassified string that AcasUpdateRowOf reads as OK. Prefixing the string with UNCONFIRMED when the
host isn't confirmed-current fixes BOTH the grid row color and the stat card in one place, and keeps the
row honest everywhere it's consumed — better than special-casing the view to exclude verify rows.

## Decision 3 — only [fresh] is OK; stale AND n/a are UNCONFIRMED
Three probe verdicts, and only one is "verified good": fresh (Verified=$true, confirmed current). Stale
(Verified=$false) is a CONFIRMED old version — the actual false-clean — and n/a (Verified=$null) can't
be confirmed. Both must fall out of the patched tally. UNCONFIRMED is the right bucket: it's not an
error (FAIL), it's "not green", which acas already renders amber and AcasOkOf already excludes.

## Decision 4 — reuse the existing classification machinery
No new status vocabulary or view state: AcasUpdateRowOf already maps a leading `UNCONFIRMED` token to
Result UNCONFIRMED, AcasOkOf already excludes it, the UI already renders it amber. The fix is to make
the verify string speak that existing language. Minimum change, maximum reuse.

## Decision 5 — canonical helper + inline mirror (runspace boundary)
The verify branch runs in a module-less fan-out runspace, so it can't call `Get-AcasVerifyRowStatus`.
Same pattern as the kb-install status and the wpt helpers: the helper is the pure, tested spec; the
branch mirrors it inline; a static assertion pins that the branch carries the prefix. The rule is one
line, but it's a false-clean decision on a remediation surface, so it earns the test.

## Decision 6 — read-only path, still a full acas regression pass
Verify is read-only (no fan-out mutation), so no self-guard/confirm applies — but the change lives in
the shared update/verify worker, so I ran the full 156-test acas + FixVerify2 set, not just the new
file. acas 1.11.6 -> 1.11.7 (a changed row classification is behavioral); pin migrated. Fable-inline;
no agent needed for a one-line classification fix on an already-mapped finding.
