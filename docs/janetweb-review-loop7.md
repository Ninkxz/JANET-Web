# JANET Web — review loop 7 (2026-07-20)

**Baseline:** 1077/1077 at loop-6 close (`d204496`); tree untouched between loops
(baseline re-run confirms — see ledger). Local-only commits.

## Opus adversarial self-review of loop-6 (`2c96c16` Host-guard gap tests) — verdict GREEN

No P1/P2. Traced the two headline asserts to real code contracts:
- **cancel-route 200** (`Server.HostHeader.Tests.ps1` cancel case): the cancel handler
  (`JanetWeb.Server.ps1:~1076-1092`) matches on route shape, looks up `$state.Jobs['none']`
  → `$null`, skips the running-job block, and **unconditionally** falls through to
  `{ ok=$true }` (200). Cancel is deliberately idempotent — unknown/finished id → 200,
  never 404. Durable contract, not incidental.
- **foreign-Host cancel → 421** proves guard-before-`?t=`-carve-out ordering (guard at
  `:397`, token/`?t=` path at `:452`). Genuine.
- `Invoke-RawRequest` can only fail-CLOSED (RST/timeout → `''` → assert RED, never a false
  green); `Connection: close` makes `ReadToEnd` return promptly; tiny responses can't
  truncate the status line. Comment-only server edit pure (4 comment lines, 0 deletions,
  BOM+parse clean). Test isolation intact (new asserts before the teardown It).

Accepted P3 (not fixed):
- **F3 — empty/absent-Host asserts pin exact 421** which is http.sys-build-dependent (an
  empty Host reaching our loop → 421 today; a future build could 400 it). **Test-only
  fragility that can ONLY false-RED, never false-green** — the product stays fail-closed
  either way (400 and 421 both non-served). Left exact-421 because it documents that OUR
  guard (not http.sys) handles the empty-Host case, and it was empirically probed on the
  target box; the HTTP/1.1-no-Host case already uses the build-independent `Not Match '200'`.

## Workstream: roadmap item 7 — report-preview sandbox-resource-free guard — **DONE** (`928d1ba`)

Banks the loop-4 Opus F8 note. The loop-3 report-preview backstop (`sandbox allow-scripts`
opaque origin) silently breaks if a report render function ever references an external
sub-resource or needs a sandbox permission the CSP omits — and nothing caught that at edit
time. Verified the current surface is clean (grep of `JanetWeb.reports.psm1`:
`<img`/`<link`/`<iframe`/`@import`/`url(`/attribute `src=`/`href=`/`download=`/`.print(` all
zero; exactly one attribute-free inline `<script>`). Added
`Reports.SandboxResourceFree.Tests.ps1` (12 asserts): statically asserts the module stays
self-contained + re-asserts the server CSP still leads with `sandbox allow-scripts`, so the
guard and the thing it guards can't drift apart. Patterns are HTML-context-anchored
(whitespace before an attribute name), so the PowerShell `$src = ConvertTo-HtmlEscaped(...)`
at `reports.psm1:3383` is not a false positive (caught + fixed during authoring — the first
draft's bare `src=` regex tripped on that var). ponytail ceiling documented in the test: a
string-concatenated external ref could slip a source grep; the common paste-an-`<img>` /
add-a-print-button case is caught; upgrade path is to render each `Render-*Html` function.
Test-only, no module change, no version bump.

## SECRET parity
- SECRET parity: the report-preview CSP sandbox + this resource-free guard apply to the
  JanetSec reports fork (same preview route + render functions) — mirror when its harness is up.
- Carried (unexecuted): Host-header guard (+extended cases), report-preview CSP sandbox,
  wpt audit-Skipped, session disarm, honest Chrome/Edge + worker passthrough, upr refuse
  coverage + worker comment.
