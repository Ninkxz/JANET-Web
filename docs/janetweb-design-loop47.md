# JANET Web — design loop 47 (2026-07-21)

## Decision 1 — verify the "natural follow-on" before committing to it
Loops 44–46 added NOT VERIFIED verdicts, so completing their honesty by fixing the summary tally (F2/item24)
looked like the obvious next step. But re-verifying it in-code, the `perPillar` tally dict is returned in the run
summary for the view to consume, not just formatted into a text line — so it's genuinely view-coupled, and a
correct fix (a new bucket the view renders) needs a coordinated JS change, not a one-file edit. A finding being
"the natural follow-on" doesn't make it contained; I checked, and it isn't. So I pivoted to the definite item.

## Decision 2 — the definite audit-honesty bug over a speculative fresh dive
Of the c2c tail, item55/F7 is the one DEFINITE, high-confidence bug: a PARTIAL host — which by the rollup's own
definition always contains a pillar FAIL — was booked VulnPatched Success in the audit ledger. That's the exact
false-compliance-record class this whole series targets (loop-38 reboot-selected, loop-44 NOT VERIFIED), and the
audit ledger is what an inspector reads. A fresh dive on a less-used tool would be speculative and lower-impact;
closing a certain false-clean beats hunting an uncertain one, especially when it completes the c2c audit-honesty
story alongside the loop-44/45 NOT VERIFIED work.

## Decision 3 — PARTIAL → Failure (the honest bucket in a 3-value enum)
The audit result enum is Success / Failure / Skipped — there is no "Partial". A PARTIAL host did real work (some
pillars FIXED) but still has a FAIL, so it is neither a clean Success nor a no-op Skipped. Failure is the honest
bucket: the remediation did not fully succeed, and the host is still non-compliant on a pillar, so it should read
as a failure to follow up — not a Success. The granular "4 of 5 fixed" truth lives in the row Detail and the
per-pillar tally; the host-level compliance record just stops lying. itemCount drops PARTIAL too, so only a
fully-FIXED host counts as a patched host.

## Decision 4 — pure helper, called directly (controller-side)
Unlike the c2c fixers, the audit emit runs in the fan-out harvest on the controller (module loaded), so
`Get-C2cHostAuditResult` is called directly — no module-less runspace, no inline mirror to keep in lockstep.
It's a pure switch, unit-tested at every status, with a static assert that the old inline `PARTIAL {'Success'}`
and `FIXED -or PARTIAL` itemCount forms are gone so the emit can't drift back.

## Decision 5 — the c2c dive is done; diversify next
With F1/F5/F3/F7 closed, every HIGH/MED c2c dive finding is fixed; the remainder is one LOW verdict sibling
(item54), a read-only display nit (item56), a speculative one (item57), and the view-coupled cluster (22/24).
That's the signal to stop grinding: loop 48 should open a fresh dive on an un-reviewed acting tool
(certdeploy installs certs, adto writes AD, remoteadmin runs scripts) to restart the productive find→fix cycle,
rather than mine a tail with no high-harm left. Version: PARTIAL hosts move from Success to Failure in the
ledger — behavioral — so c2c 1.15.7 → 1.15.8, SigAge exact pin → floor, new test holds the pin.
