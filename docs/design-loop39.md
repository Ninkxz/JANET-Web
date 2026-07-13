# Design - Loop 39 - ReportsTool host-key collision: AMBIGUOUS guard on the compliance-mutation paths (rows 36/37)

Ledger row 36 (P2, compliance-closure integrity): `Get-ReportsAuditHostKey` folds any non-IP hostname to
its short NetBIOS name, so two DISTINCT hosts sharing a short label across domains (`web01.us…` /
`web01.eu…` -> `WEB01`) collide. At the safety-critical sites this can mark a still-open vuln on one physical
host as REMEDIATED/Patched. Row 37 (P3): `Build-CoraSummary` counts unique hosts by RAW hostname (never
keyed), so one host exported short vs FQDN double-counts.

## What NOT to do (the trap)
Do NOT change `Get-ReportsAuditHostKey`'s core fold. Its "short name + its own FQDN -> one key" behavior is
CORRECT (a legitimate single-host alias) and is pinned by `Reports.HostKeyAndClosure.Tests.ps1`. Loosening
it (IP/domain-strict) would FALSELY REOPEN compliance whenever a host is exported short in one scan and FQDN
in another - the opposite, equally-bad failure. The bug is the COLLISION (2+ distinct FQDNs on one short
label), not the fold.

## The fix (additive, reuses the proven loop24 pattern)
A `Get-ReportsHostKeyCollisions` helper + the AMBIGUOUS verdict already exist and are proven in
`campaign-verify` (the loop24 P2 fix). Generalize that SAME pattern to the two unguarded safety-critical
sites, fixing the CLASSIFY path and the MUTATE path TOGETHER (the recon's hard requirement - fixing display
alone leaves the auto-close exploitable):

1. **`Compare-AcasScans`** (baseline/comparison loops ~1483/1490, feeding `acas-run-compare` +
   `acas-prove-closure`): compute the collision set over the scan hostnames; a baseline key whose short host
   is collided is classified **AMBIGUOUS**, never REMEDIATED. Mirror the campaign-verify AMBIGUOUS branch
   (5396-5406). Additive: only DEMOTES a false REMEDIATED to AMBIGUOUS, never invents a new closure and never
   reopens a legitimately-closed one.
2. **`acas-apply-remediated`** (~5709/5713 - the ONLY site that writes `finding.Status='Patched'`): it builds
   its OWN keys, so it needs its own collision guard - SKIP flipping any finding whose host-key is in the
   collision set (leave it open, surfaced). This is the mutation guard; without it the false-close persists
   even after #1.
3. **`Build-CoraSummary`** (~2253, row 37): route the host accumulation through `Get-ReportsAuditHostKey`
   (keep a representative display name per key). Safe with the same "still folds true aliases" contract, and
   it fixes the double-count. Independent of #1/#2 but cheap to bundle.

## Explicitly deferred (documented, not faked)
The IP discriminator (the only thing that could disambiguate two `WEB01`s in an AFNET short-name-only export)
requires threading an `IP` field through `New-AcasFinding`/`Parse-AcasFile` (today the parser discards the IP
once any name string exists) - a schema change, its own cycle. Until then AMBIGUOUS-and-surface (never
silent-close) is the correct terminal behavior. Record this in the ledger + a code comment; do NOT fake a
disambiguation the data can't support.

## Tests (Pester 3.4)
Extend `Reports.HostKeyCollision.Tests.ps1` (do NOT weaken `Reports.HostKeyAndClosure.Tests.ps1` - the fold
contract must stay green):
- `Compare-AcasScans` / `acas-run-compare`: a collided short key with the vuln STILL OPEN on the other
  physical host -> classified AMBIGUOUS, NOT REMEDIATED (the core false-close regression test).
- `acas-apply-remediated`: a collided-key finding is NOT flipped to `Patched` (mutation guard).
- A NON-collided remediation still flips REMEDIATED/Patched normally (no over-guard - proves we didn't break
  legitimate closure).
- `Build-CoraSummary`: one host as `WEB01` + `web01.us.af.mil` counts as ONE unique host (row 37).
Full suite green.

## Desktop mirror
Rows 35/36/37 are a standing **DESKTOP-DEFERRED** (operator status-quo on the reports-campaign mirror, per
row 35). Keep that: fix Web this cycle; note in the ledger that the Desktop ReportsTool reports-campaign
mirror remains operator-deferred (not silently open - explicitly deferred with the row-35 precedent).

## Gate
I personally verify: the fold is UNCHANGED; #1 and #2 both landed (classify + mutate together); the guard is
ADDITIVE (a non-collided host still closes normally - no false-reopen); the collision helper is the proven
loop24 one (not a new fork). Opus implements; I gate every diff + spot-verify the AMBIGUOUS demotion and the
apply-remediated skip against the code. Suite green per commit.
