# JANET Web — design loop 38 (2026-07-21)

## Decision 1 — a fresh deep-dive on acas, the most-used tool never loop-era-reviewed for false-cleans
The loop era (30–37) covered c2c, winupgrade, upr, and the server/auth boundary; acas — the headline
vuln-scan-import + remediation tool, and by the operator's note the most-used alongside wpt — had only its
loops-1–13 review. Its false-clean surface (a row that ends OK lights a PATCHED tile and books a VulnPatched
audit) is the highest-harm class in the whole app, so it was the right fresh target. I ran the dive with a
Fable worker over the full 3,696-line module and re-verified every finding in-code (a finding is a lead, not
a verdict).

## Decision 2 — fix F1 (the one confirmed false *audit-ledger* record), rank the rest
The dive returned one CONFIRMED false-compliance audit (F1) and five verify-honesty gaps (F2–F6). F1 is the
cleanest, highest-confidence close: it has a *precedent* — loop28 fixed the identical bug on the sibling
`schedule-reboot` arm and even documented why — the fix is a one-token change, and it's the only finding that
writes a wrong entry to the permanent audit ledger (F2–F6 mislight the PATCHED stat card / operator verdict on
verify-only runs, which audit TouchHost). Per the one-workstream cadence I fixed F1 and ranked F2–F6 as items
35–39 rather than half-doing the harder ones.

## Decision 3 — why F2/F4 are NOT one-liners (deferred deliberately)
F4 ("bumped" = any string inequality) looks like a quick `[version]` compare, but the verify path is shared by
profiles whose "version" is not a version at all — spec-exec returns COMPLIANT/VULNERABLE/DRIFT, others return
build strings — so forcing a `[version]` parse would regress them to UNCONFIRMED. F2 (mtime-recency as
"patched") is the known "copied-registry always-OK" chip and needs each probe to learn the required version to
compare against — a per-profile design change. Both deserve their own loop with their own regression tests, not
a rushed slice riding F1.

## Decision 4 — pin the whole reboot-arm audit-action family, not just the one line
The bug was a sibling drifting from a fixed twin. So the regression test isolates the `reboot-selected`
sub-block by static analysis (mirroring the existing `schedule-reboot`/`verify-post-reboot` block tests) and
pins it to TouchHost / not-VulnPatched. Now all three reboot arms have their audit action pinned, so no future
sibling can silently drift back. The block isolation had to terminate on a line-start `} else {` because the
inline `rowOf` carries a `} else { 'scheduled' }` a bare match would stop at — a small precision point the
first test run caught.

## Decision 5 — version + scope
A changed audit action is behavioral (the ledger now records TouchHost, not VulnPatched, for this arm): acas
1.11.9 → 1.11.10. Only `Acas.RebootAudit.Tests.ps1` held the exact pin (all other acas tests are floors), and
since this is itself a reboot-audit fix it stays the exact-pin holder, updated to 1.11.10. Applying the loop-37
lesson, I grepped *all* tests for the touched symbols (`reboot-selected`, `VulnPatched`, `1.11.9`) before
finalizing: the only other hits are a synthetic c2c audit event and a gate test, neither affected. acas
reboot/verify/profile/KB test set green (69).
