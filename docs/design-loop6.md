# Design - Loop 6 - CSV formula-injection parity for the remaining CSV writers

## Goal
`reports.psm1` neutralizes spreadsheet formula injection on every CSV cell it emits (prefix a `'` on any
value starting with `= + - @`, tab, or CR - documented "audit P3/#5" at reports.psm1:872/2099/3261/5954).
But `wpt.psm1:596` writes the fleet-snapshot CSV (`wpt-bulkscan_*.csv`) via a RAW `ConvertTo-Csv
-NoTypeInformation` over objects whose `Host`, `OS`, `Build` fields are HARVESTED FROM REMOTE hosts (WMI
`Win32_OperatingSystem.Caption`, host names). A compromised/misconfigured fleet host can set its OS caption
(or other attribute) to `=cmd|'/c calc'!A1` / `=HYPERLINK(...)` / `@SUM(...)`; when the operator opens the
snapshot in Excel/Sheets it executes - a remote-to-operator code path the rest of the suite already guards.
This closes the parity gap in the CSV writers that currently lack the neutralizer.

## Surface
1. **Enumerate every CSV writer** (`ConvertTo-Csv` / `Export-Csv` / hand-built CSV lines like
   `ConvertTo-JanetCsvLine` in `server\JanetWeb.Logging.ps1`) across modules + server, and identify which
   ones emit REMOTE/scanner-derived free-text WITHOUT the formula guard. Known gap: `wpt.psm1:596`. Suspected:
   the shared `ConvertTo-JanetCsvLine` (Logging.ps1:284) neutralizes comma/CR/LF delimiters but may not
   neutralize the FORMULA-leading chars. Confirm reports.psm1 is fully covered (it is, by inspection).
2. **Add a small pure neutralizer** where missing (mirror reports.psm1's exact rule: if a string starts with
   `=`, `+`, `-`, `@`, tab, or CR -> prefix a single `'`). Prefer one helper per module that lacks it
   (`wpt.psm1`; and `Logging.ps1` if its writer is a gap), matching the existing style. Apply it to the
   remote-derived string fields before they reach the CSV (for wpt: `Host`/`OS`/`Build` in the `$objs`
   projection at :580-589; numeric/bool count fields don't need it but neutralizing all string fields is
   harmless and simplest).

## Risks / non-goals
- **Additive, fail-safe** - only PREFIXES a `'` on formula-leading cells; never drops or mangles data
  (Excel shows the literal, strips the leading `'` on display of a normal value). No behavior change for
  benign cells. No security guard weakened.
- **Not a data-format break** - the `'`-prefix is the industry-standard CSV formula-injection mitigation and
  is what reports.psm1 already emits, so downstream consumers already tolerate it.
- Non-goal: re-guarding reports.psm1 (already covered) or changing the CSV SCHEMA/columns.

## Test plan
- New `tests\Csv.FormulaInjection.Tests.ps1` (Pester 3.4, BOM): unit-test the neutralizer(s) - a cell
  `=cmd|'/c calc'!A1`, `+1`, `-1+1`, `@SUM(A)`, a leading tab and CR each gets a `'` prefix; a benign
  `WIN-ABC` / `Microsoft Windows 11 Pro` / `10.0.26100` / `` (blank) is unchanged. If a shared writer is
  fixed, assert an object round-trips with the dangerous cell neutralized.
- Full Pester suite green; PS 5.1 parse-clean + BOM on every changed .ps1; changed modules still load and
  `Get-JanetToolManifest` non-empty.
- The live "open the snapshot in Excel" step is pilot-observable, not unit-tested - the unit test asserts the
  emitted CSV cell is neutralized, which is the verifiable invariant.
