# JANET Web — design loop 37 (2026-07-21)

## Decision 1 — close the last cheap false-clean; the HIGH items left are hard
Recon over the open backlog: the c2c cluster (22/23/24/26) is a bucket-taxonomy overhaul entangled with a
DELIBERATE loop-18 "KICKED-as-FIXED" decision and view-coupled summary buckets — a redesign, not a fix;
winupgrade #29 (AutoFix) needs a new shim harness. #31 alone is a self-contained fail-open in a PURE,
easily-driven helper. So loop 37 closes #31 and leaves the nuanced items ranked for a dedicated pass.

## Decision 2 — `unknown`, not `no violations`, as the no-match default
The bug is a verify path treating "couldn't parse the result" as "confirmed healthy." The honest default
for an unrecognized `sfc` summary is `unknown`. Everything else follows: the classifier already fails
FAILED on a dism/sfc error and PARTIAL on could-not-fix/blocked — `unknown` belongs with those, not with
the confirmed-clean case.

## Decision 3 — map `unknown` to PARTIAL, not a new status enum
The verdict `Status` is consumed by a caller/switch. A new `UNKNOWN` enum would need a case in every
consumer or it renders as nothing. PARTIAL already means "not fully resolved / needs a look" and is already
handled, so `unknown` → PARTIAL closes the false-clean with zero consumer risk. The distinction the operator
needs — *why* it's not clean — is carried by the `sfc='unknown'` detail and the new `[WARN] ... output not
recognized` report line, not by inventing a status. Lazy + safe: reuse the status the UI already knows.

## Decision 4 — fix both twins, keep the runspace pattern intact
`Get-WinUpgradeRepairVerdict` is the pure tested twin; the worker runs an inline mirror (the remote
runspace is module-less). The mirror is the code that actually executes, so fixing only the helper would
have left the runtime fail-open. Both carry the identical change under the existing "keep in sync" comment,
and a static assert pins that the module holds the unknown handling in both places.

## Decision 5 — version + coverage
An unparseable-sfc host that read CLEAN now reads PARTIAL — behavioral, so winupgrade 0.5.5 → 0.5.6. The
helper was UNtested; the new `Winupgrade.RepairVerdict.Tests.ps1` establishes its first coverage (the fix
case + the four known outcomes + the two-twin static assert) and holds the exact 0.5.6 pin, with the
loop-36 exact pin migrated to a floor. Repair-health is a read/verify path (non-destructive), so the
winupgrade + FixVerify2/3 set (101 green) is the appropriate regression scope; no destructive-path re-run
needed this loop.
