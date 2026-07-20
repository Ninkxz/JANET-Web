# JANET Web — review loop 18 (2026-07-20)

**Baseline:** 1150/1150 at loop-17 close. Fable-inline. Local-only commits.

## Self-review of loop-17 (`bb9e9c2` acas match-table routing test) — verdict GREEN (inline)
Test-only (`Acas.MatchTableRouting.Tests.ps1`, 13 tests), drives the real router, no behavior
touched, acas stayed v1.11.5. Re-ran it: 13/13. No destructive/security code in the change, so no
re-verify agent. GREEN.

## Correctness deep-dive: acas CSV INGESTION (ConvertFrom-AcasCsv) — verdict GREEN → coverage locked in

The pivot in loop 17 was from destructive-execution safety to pipeline correctness (routing). This
loop moves one step further UP the pipeline: the CSV import itself — `ConvertFrom-AcasCsv`
(`JanetWeb.acas.psm1:1507`), the front door of the offline/CSV-fed flow for the most-used tool.
Everything downstream (routing, host counts, KEV, SLA math) is built on the finding rows this
parser emits, so a row mis-parsed here is a silent corruption of every number after it. Verified
CORRECT with file:line evidence:

- **Encoding** (`:1521`): `Import-Csv -LiteralPath $pp -Encoding UTF8 -ErrorAction Stop`. UTF-8
  exports decode correctly WITH or WITHOUT a BOM regardless of the box's ANSI code page — Import-Csv
  strips the BOM so it never folds into the first column header. (A drop to Get-Content-default or
  ANSI would corrupt `DNS Name` → the host lookup misses → every finding silently drops.)
- **Quoted/embedded-comma fields** (`:1521`,`:1528`): handled natively by Import-Csv /
  ConvertFrom-Csv — a `"CVE-a, CVE-b"` cell stays one field on one row.
- **Missing/renamed column** (`:1535-1541`): `$getCol` reads via `PSObject.Properties[$colName]`
  and returns `''` when the column is absent — no throw. A finding with an empty plugin name
  degrades to NotUpdatable downstream (visible, no Run button), never a crash or a wrong route.
- **Host-token whitelist BEFORE target** (`:1556`): the chosen host is run through
  `Test-AcasHostToken` (bare short host or IPv4 literal only) before it becomes a finding — a
  garbled/hostile cell (embedded space/switch/UNC/pipe) is rejected as no-host, never forwarded to
  a remote call. The IP column, which is NOT normalized, is covered by this same gate.
- **Server skip** (`:1557`): `msek-*` hosts are counted as skipped, not imported.
- **Loud wrong-template hint** (`:1569-1571`): when rows parse but NONE map to a host
  (`$noHostSkipped -eq $allRows.Count` — renamed/absent host columns, wrong export template) a
  `warn` fires pointing at the column headers, so the operator sees "wrong template" instead of a
  silent zero-finding import that reads as "clean fleet."

**The gap (coverage, not correctness) → FIXED** (test-only, acas stays v1.11.5): the parser — the
pipeline's front door — was untested end-to-end; only `Test-AcasHostToken` was covered, in
isolation. A careless edit (dropping `-Encoding UTF8`, weakening the token gate, removing the
wrong-template hint) would silently corrupt every import with nothing to catch it.
`Acas.CsvIngestion.Tests.ps1` (15) drives the real parser: well-formed field mapping + host-pick
precedence (DNS>NetBIOS>IP), quoted embedded-comma survival, missing-column tolerance, server-skip,
garbled-token rejection, the wrong-template warn hint, and — via a real temp UTF-8 **BOM** file
through the `-Paths` import path — the `-Encoding UTF8` decode (the offline constraint: real ACAS
exports are UTF-8, often with a BOM).

Note (test-authoring): the filter-count assertions use `@($x | Where-Object {...}).Count`, not
`(@($x) | Where-Object {...}).Count` — in PS 5.1 the latter returns `$null` (not 1) when exactly one
PSCustomObject matches, because a lone object has no `.Count` member. Two assertions were caught by
this on first run and corrected.

## Correctness/security coverage — where it stands
Both destructive surfaces reviewed + test-pinned (loops 1-16). The operator-facing correctness
pipeline is now covered at THREE points, front-to-back: CSV ingestion (this loop, acas import),
remediation routing (loop 17, acas match-table exclusions), and host-count consistency (loops
13-14, reports). Remaining correctness candidates: the KEV/SLA-deadline math beyond host counts,
the reports Parse-CsvFinding path (the reports tool's own CSV front door — same robustness
questions, different parser), or SECRET-parity execution (operator sign-off).

## SECRET parity
- SECRET parity: the acas CSV-ingestion robustness test — the JanetSec acas fork shares
  `ConvertFrom-AcasCsv` + `$AcasColumnMap`; mirror the ingestion assertions (esp. the BOM decode
  and the wrong-template hint).
- Carried (unexecuted): all prior SECRET-parity items.
