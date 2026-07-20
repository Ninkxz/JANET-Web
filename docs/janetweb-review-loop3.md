# JANET Web — review loop 3 (2026-07-20)

**Baseline:** 1042/1042 (verified on the identical tree at loop-2 close; tree
untouched between loops). HEAD at loop start: `5821e15`.

## Opus adversarial self-review of loop-2 (`3dea8b8`) — verdict GREEN

Checked-clean (on record): **wpt dispatch is structurally different from acas and
safe** — wpt hands the live scriptblock to `Invoke-Command` (`JanetWeb.wpt.psm1:6395`
→ `:3349`), whose remote serialization re-parses the source text; nested `$getPv` +
parent-scope `$ckeys` survive (empirically proven equivalent round-trip). wpt
classifier `:3359` handles all three new dialect strings (OK/SKIP/PENDING→FAIL else)
— empirically verified. Edge registry specifics correct: policy key + per-app
`Update{56EB18F8...}` value; **WOW6432Node-first key order is right** (the Edge
updater is 32-bit Omaha, so Clients lives under WOW6432Node on x64). **Exe-first
fast-fail on a Disabled `edgeupdate` service is the right call** — the UA task
re-launches the same exe through the same core service, so a task fallback adds zero
coverage; the task branch correctly exists only for exe-missing. acas dialect: no
PENDING leak (the one PENDING near the profile is a comment above the Script block,
outside `.ToString()`), full worker-passthrough/row-builder trace clean. Version/
floor-assert conversions relaxed only manifest-load asserts, nothing load-bearing.

P3 findings (all pre-existing, shared with the accepted Chrome pattern):
- **P3-1 — FIXED this loop** (`7c79666`, wpt **6.8.1→6.8.2**): wpt's app-update
  `AuditResultOf` (`:6402`) booked a `Skipped` status as audit **Failure** (only
  Pending was special-cased) — a not-installed SKIP host showed Skipped in the UI
  but Failure in the Runs CSV. Both non-attempt states now audit Skipped; the
  Failure else-arm is pinned by test.
- **P3-2 — accepted (cosmetic):** "services disabled (edgeupdate/edgeupdatem)" FAIL
  text names both services but only `edgeupdate` is checked; core-service Disabled
  blocks updates regardless. Mirrors the Chrome `gupdate/gupdatem` wording.
- **P3-3 — accepted (wording):** a Beta/Dev-only Edge host reports
  `SKIP: Edge (machine-level) not installed` — imprecise wording, correct behavior
  for stable-channel remediation.

## Sonnet mechanical re-verify (loops 1–2 fixes at HEAD `5821e15`) — all 5 PASS

122/122 across 9 suites; BOM+parse clean on both modules + server; no always-OK
strings anywhere in either module (0 matches), UNCONFIRMED/PENDING dialects in
place; disarm handlers intact (`:579-580`, `:462`); no cert-extension files in any
loop commit; registry order wpt→acas intact, 21 tools, no beta tool.

## Workstream: roadmap item 2 — report-preview XSS backstop — **CLOSED** (`902a00c`)

`GET /api/report-preview` (JanetWeb.Server.ps1:405) now serves with
`sandbox allow-scripts; ...` leading its CSP: the document gets an OPAQUE origin, so
a script smuggled past `ConvertTo-HtmlEscaped` cannot read the SPA's sessionStorage
token (storage access throws for opaque origins) and cannot call `/api` same-origin.
The report's single inline script is pure-DOM (pill filters/search — verified no
storage/fetch/print usage), so `allow-scripts` keeps it working; the SPA's strict
sha256-pinned CSP is untouched (no sandbox — the shell needs its origin);
`allow-same-origin` is banned by test. One-shot delete-on-read + pre-token route
placement unchanged (pinned). Escaping stays the first line; the sandbox is the
backstop. Regression: `Server.ReportPreviewSandbox.Tests.ps1` (10 asserts; one
sloppy comment-matching anchor caught and fixed pre-commit).
**Live-fire caveat:** render-in-browser pass (report opens, filters work under the
sandboxed CSP) still to be eyeballed next time the operator opens a report preview.

## SECRET parity
- SECRET parity: report-preview CSP `sandbox allow-scripts` backstop (JanetSec
  server has the same preview route shape).
- SECRET parity: wpt audit-map Skipped fix (JanetSec wpt fork shares the
  AuditResultOf shape).
- Carried: session disarm, honest Chrome + worker passthrough, honest Edge.
