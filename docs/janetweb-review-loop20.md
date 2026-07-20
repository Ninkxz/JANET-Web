# JANET Web — review loop 20 (2026-07-21)

**Baseline:** 1170/1170 at loop-19 close (authoritative). Fable-inline. Local-only commits.

## Self-review of loop-19 (`b26bd6f` reports wrong-template hint, `9b0ac89` docs) — verdict GREEN (inline)
The new `warn` sits AFTER the empty-header early-return (`:1454`), so a legitimately empty/headerless
CSV returns before it and never false-warns; a valid CSV whose header resolves host+plugin but has
zero data rows passes the guard and imports zero silently (a real empty scan, correctly quiet).
Additive, `$Emit`-gated, non-destructive read path. Authoritative suite landed at the documented
1170/1170. No re-verify agent warranted. GREEN.

## Correctness deep-dive: reports host-key normalization sweep completion (Build-RemediationPlan)

The roadmap's standing open item was "reports host-key normalization sweep completion." Loops 13-14
normalized the compare/closure/CORA host counts (Get-ReportsAuditHostKey: IPv4-whole, else pre-dot
short name upper) so one physical box exported as `WEB01` and `web01.dom` counts once. The tail was
`Build-RemediationPlan` (`JanetWeb.reports.psm1:1793`), the operator-facing Remediation Plan:

- **The gap** (`:1802`, `:1878`): the per-(host,app) `$bucket` key was `"$($f.Hostname)|$app"` and
  the per-app summary host count was keyed on the RAW `$r.Hostname`. So a short+FQDN pair of one host
  made TWO buckets → TWO plan rows and a per-app summary that counted it as TWO hosts. The evidence it
  was a genuine tail, not intentional: the ADJACENT Other-group per-plugin host count in the SAME
  function (`:1852-1855`) was ALREADY normalized in loop 13 with the comment "count DISTINCT hosts -
  key on the normalized audit key so a short+FQDN pair of one host is not counted twice (agrees with
  CORA)." The main bucket was simply missed.
- **The coupling**: the bucket key doubles as the session-only remediation status key
  (`$script:RemediationStatus`, init `@{}` `:515`, read `:1868`, written by the mark-remediation
  action `:5998`). So a complete fix has to normalize THREE coupled sites or a marked status lands on
  a key the reader never checks.

**FIXED** (reports **2.14.23 → 2.14.24**), normalizing the host key at all three:
- `:1802` bucket key → `"$(Get-ReportsAuditHostKey $f.Hostname)|$app"` (keeps the raw first-seen
  Hostname for display) — folds short+FQDN to ONE plan row.
- `:1878` summary count → keyed on `Get-ReportsAuditHostKey $r.Hostname` (defense-in-depth; rows are
  already one-per-normalized-host after the bucket fix).
- `:5998` status setter → builds the key the SAME normalized way, so a status marked on an
  FQDN-display row is found by the reader.

The fold direction matches the repo's established decision (loops 13-14 + the Other-group count):
short-fold is INTENDED; the separate `Get-ReportsHostKeyCollisions` guard surfaces genuinely
ambiguous short names. Normalizing here makes the Remediation Plan agree with CORA and with the
Other-group count beside it, instead of over-counting per-app hosts.

`Reports.RemediationPlanHostKey.Tests.ps1` (4) drives the real `Build-RemediationPlan` over seeded
findings: a short+FQDN pair (FQDN seeded FIRST, the only ordering that exercises the fold) → ONE
Chrome row + `Summary.Chrome == 1`; two distinct hosts → `== 2` (no over-merge); a status seeded on
the normalized `WEB01|Chrome` key reads back onto the folded row (proving the reader normalizes, and
by symmetry the setter must write the same key); + the exact `2.14.24` manifest pin. The loop-19
exact `2.14.23` pin was converted to a `-ge` floor (repo convention: only the newest bump's own test
holds the exact pin).

## Correctness/security coverage — where it stands
Destructive surfaces reviewed + test-pinned (loops 1-16). Read-path correctness now covers both CSV
front doors (loops 18-19), remediation routing (loop 17), and host-count consistency across compare/
closure/CORA (loops 13-14) AND now the Remediation Plan (this loop) — the host-key normalization
sweep is complete for the per-app rollups. Remaining candidates: KEV/SLA-deadline math, the `.nessus`
XML parse branch of Parse-AcasFile, or SECRET-parity execution.

## SECRET parity
- SECRET parity: the Build-RemediationPlan host-key fold — the JanetSec reports fork shares
  `Build-RemediationPlan` + the mark-remediation setter; mirror the 3-site normalization + test.
- Carried (unexecuted): all prior SECRET-parity items (reports wrong-template hint, acas CSV-ingestion
  + match-table routing tests, and everything earlier).
