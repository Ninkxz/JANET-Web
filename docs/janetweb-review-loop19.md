# JANET Web — review loop 19 (2026-07-21)

**Baseline:** 1165/1165 at loop-18 close (authoritative). Fable-inline. Local-only commits.

## Self-review of loop-18 (`5326327` CSV-ingestion test, `62028c1` docs) — verdict GREEN (inline)
Both commits were test/docs-only — `Acas.CsvIngestion.Tests.ps1` (15) plus review/design/ledger.
No module code, no destructive/security path touched, acas stayed v1.11.5. Authoritative suite
landed at the documented 1165/1165. No re-verify agent warranted. GREEN.

## Correctness deep-dive: reports CSV front door (Parse-AcasFile) — one real gap, FIXED

Loop 18 pinned the acas import parser; this loop reviews the OTHER CSV front door — reports'
`Parse-AcasFile` (`JanetWeb.reports.psm1:1382`), a separate parser feeding the reports tool
(import/compare/triage/dashboards). Same offline/CSV-fed robustness questions, different code.

**What held up (verified GREEN):**
- **Encoding** (`Read-CsvRowsSafe`, `:1263`): reads via `System.IO.StreamReader` (default ctor →
  UTF-8 with BOM auto-detection) and `Microsoft.VisualBasic.FileIO.TextFieldParser` (also
  BOM-detecting). A UTF-8 export with or without a BOM decodes correctly; the BOM never folds into
  the first header. (Contrast: several NON-finding reference reads in the file use `Get-Content
  -Raw` without `-Encoding UTF8` — but those either strip the BOM defensively (IavmMap `:822`) or
  read ASCII-only reference data (KEV catalog), so no finding-count impact.)
- **Quoted / multi-line / embedded-comma fields** (`:1288-1305`): TextFieldParser with
  `HasFieldsEnclosedInQuotes=$true`; a malformed line is skipped (`MalformedLineException`), not
  fatal — one bad row never drops the whole import.
- **Flexible column resolution** (`Get-AcasColumnMap`, `:1324`): host/plugin/vuln/sev/sol/cve
  matched with `[\s._]`-tolerant patterns and many synonyms (`DNS Name`/`Host`/`NetBIOS`/`IP
  Address` for host; `Plugin`/`Plugin ID`/`Nessus ID` for plugin), so template variance maps.
- **Per-row host fallback** (`:1471-1476`): DNS → NetBIOS → IP before a row is dropped, so a
  blank-DNS AFNET Nessus row still counts.

**The gap (correctness/robustness) → FIXED** (`reports.psm1:1456`, reports **2.14.22 → 2.14.23**):
when the header parsed but the host and/or plugin column could NOT be resolved (`$cols.Host -lt 0
-or $cols.Plugin -lt 0` — a wrong export template / renamed columns), the parser did `return
$findings` **empty with no `$Emit` warning**. A wrong-template CSV imported ZERO findings SILENTLY —
which reads to the operator as a clean fleet, the exact false-comfort undercount the offline/CSV
constraint is vulnerable to. acas's `ConvertFrom-AcasCsv` already guards the same case with a loud
hint; reports didn't. Fixed additively: a `warn` naming which column is missing (host and/or
plugin), gated on `$Emit` (all 3 callers — `:4464`,`:5545`,`:5576` — pass it). No change to what
imports on a valid CSV; the only new behavior is the diagnostic on the previously-silent path
(hence the version bump).

`Reports.WrongTemplateHint.Tests.ps1` (5) drives the REAL `Parse-AcasFile` against temp CSVs:
no-host/plugin header → 0 findings + a `could not find` warn; the hint names both missing columns;
plugin-only-missing names just the plugin column (and not host); a correct template parses findings
with NO false warn; plus the exact `2.14.23` manifest pin. The prior exact pin in
`Reports.HostCountAgreement.Tests.ps1` was converted to a `-ge '2.14.22'` floor (repo convention:
older files floor-assert, the newest bump's own test holds the exact pin).

## Correctness/security coverage — where it stands
Both destructive surfaces reviewed + test-pinned (loops 1-16). The read-path correctness pipeline
is now covered at BOTH CSV front doors (acas import loop 18, reports import this loop), remediation
routing (loop 17), and host-count consistency (loops 13-14). Both importers now fail LOUD on a
wrong template instead of silently importing zero. Remaining candidates: KEV/SLA-deadline math, the
`.nessus` XML path robustness (Parse-AcasFile's XML branch), or SECRET-parity execution.

## SECRET parity
- SECRET parity: the reports wrong-template hint — the JanetSec reports fork shares `Parse-AcasFile`
  / `Get-AcasColumnMap`; mirror the loud warn on unresolved host/plugin columns + the regression
  test.
- Carried (unexecuted): all prior SECRET-parity items (acas CSV-ingestion + match-table routing
  tests, and everything earlier).
