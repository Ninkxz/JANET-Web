# JANET Web — design loop 1 (2026-07-20)

## Decision 1 — port wpt's honest Chrome Script into acas WITHOUT renaming the profile
wpt 6.5.33 split its Chrome profile into two new names and deleted the old one; acas
already had a distinct Software-Center alternate (`'Google Chrome - Software Center'`),
so the defect was only the Script body. Keeping the `'Google Chrome - Update'` name
keeps `Get-AcasProfileMatchTable` routing, view wiring, and operator muscle-memory
untouched — the smallest diff that kills the defect. Renaming would have bought
consistency with wpt naming at the cost of a 4-file rename sweep. Skipped; add only if
operators report confusion between the forks' profile pickers.

## Decision 2 — PENDING → UNCONFIRMED translation at the port boundary
acas's classifier (`$script:AcasOkOf`, row builders at `JanetWeb.acas.psm1:2218/3024`)
knows `FAIL*`/`UNCONFIRMED*`/`SKIP*`; anything else books **green**. wpt's honest
Script speaks `PENDING*` (wpt's classifier maps it to an amber Pending state). A
verbatim port would have reintroduced always-OK one layer up. Rule captured in the
regression test: the acas Chrome Script must never contain the string `PENDING`.

## Decision 3 — worker passthrough ordering (fail-closed preserved)
In `$script:AcasUpdateWorker`, the self-classified passthrough
(`FAIL*`/`SKIP*`/`UNCONFIRMED*` → return as-is + `<<PRE/POST>>` markers) sits **before**
the thrown-probe UNCONFIRMED wrap and the unchanged-version rewrap. Rationale: a Script
that already declared failure/skip/unproven is authoritative — a probe error or an
unchanged version adds nothing and previously *downgraded* hard FAILs to transient-
looking amber. OK-claiming Scripts keep the full probe-proof ladder (probe-err →
UNCONFIRMED; unchanged → UNCONFIRMED; bump → confirmed OK). No path got greener;
two paths got honestly redder (FAIL stays FAIL) — fail-closed direction only.

## Decision 4 — session disarm is server-authoritative, client-mirrored
The fix lands in the two server handlers (the authoritative gate), not the views.
`/session/end` writes the SessionNotes row BEFORE disarming (notes survive), then
drops ack+cred and answers `disarmed=true`. `DELETE /cred` drops the ack because the
ack was given FOR that credential. Client work is mirror-only (`session.disarm()`,
`clearCred` ack-clear, acas dialog copy) so the ADMIN strip can't show a stale armed
state; the server would be safe even if the mirror were skipped.

## Decision 5 — P3-2 comment-only this loop
The report-preview sandbox backstop (`srcdoc` + `sandbox="allow-scripts"`) changes how
the preview window loads (fetch-then-embed vs navigate) and interacts with the inline
Dirty-30 script + print flow — too much surface to change un-reviewed alongside two
security fixes. This loop ships the truth (comment names the real barrier and the P1
rule for unescaped fields); the backstop is a ranked roadmap item.

## Versioning
acas `1.11.3 → 1.11.4` (manifest `version` field, normal git edit — JANET Web
convention; no new versioned file, that is the desktop convention). Old exact-version
test pins updated in place (`Acas.FixJava.Tests.ps1`, `Acas.SpecExec.Tests.ps1`),
matching how 1.11.1→1.11.3 bumps were done.
