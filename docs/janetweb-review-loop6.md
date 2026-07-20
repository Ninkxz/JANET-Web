# JANET Web — review loop 6 (2026-07-20)

**Baseline:** 1072/1072 at loop-5 close (`7b31229`); tree untouched between loops
(baseline re-run confirms — see ledger). *Note: loops 1–5 were pushed to
`gitea.bth0mp.com/bth0mp/JANET-Web` (master, one-time operator instruction); loop-6
returns to local-only commits.*

## Opus adversarial self-review of loop-5 (`373e7cc` upr refuse coverage) — verdict GREEN

No P1/P2. The core question — do the new tests prove the fail-closed behavior or pass
vacuously — was answered by tracing all three dispatcher paths against the exact params:
- **manual live+no-selection** reaches the refuse at `JanetWeb.upr.psm1:1657` before
  `Build-UprManualHostJobs`; `Build-UprManualProfiles('SomeApp')` yields 1 profile so the
  empty-profile early-return isn't taken; the `Should Match 'Refused'` assert is
  load-bearing (an empty parse returns total 0 with NO error key → assert fails).
- **manual dry-run self-only** takes the warn path (no refuse), then the self-guard drops
  `127.0.0.1` (`^127\.` branch) → total 0; the negative `Has-RefuseLog=$false` assert would
  visibly flip if the gate were mis-scoped to fire in dry-run.
- **report live+no-selection** — the 1-row CSV `Plugin Name` matches `Parse-CsvFinding`'s
  `(?i)unsupported` filter (catalog-independent); missing `Plugin Output` column only skips
  version extraction (gated behind `$havePluginOutput`), doesn't break parsing → 1 finding
  → refuse at `:1885`. The `Should Match 'Refused'` proves both parse-success AND
  live-gate-fire.
Comment fix confirmed accurate (`$UprWorkerBlock` is the `-Work` block for both dispatchers,
DNS-mismatch abort guards both). Comment-only module edit, no byte-shift, no version bump
needed (no test pins upr's version). Pester 3.4 mechanics clean (temp CSV in Describe body,
cleanup It runs last). Only note: the already-corrected 10→9 assert count.

## Workstream: roadmap item 8 — close the loop-4 Host-guard test gaps + F1 note — **DONE** (`2c96c16`)

Banked the two Opus loop-4 P3 notes with a probe-first pass (same discipline as the guard
itself). A raw-socket probe against a booted server established exact behavior, then each
outcome was pinned:
- empty Host value → **421** (reaches our guard); HTTP/1.0 no-Host → **421** (reaches our
  guard); HTTP/1.1 no-Host → **400** (http.sys pre-rejects — asserted NOT 200). All
  fail-closed.
- legit beacon-cancel `POST /api/job/<id>/cancel?t=<token>` + good Host → **200** (the guard
  does NOT break the sendBeacon path — F6b).
- cancel route + FOREIGN Host → **421 BEFORE the `?t=` carve-out** — a rebound page can't use
  the beacon token carrier either. Stronger than F6 asked for; now pinned.
Plus the F1 comment: the guard assumes a non-default port (browser omits the port from Host
on 80/443); the 8089..8100 launcher bind guarantees it. `Server.HostHeader.Tests.ps1`
9 → 14 asserts; comment-only server edit, no behavior change.

## SECRET parity
- SECRET parity: the extended Host-guard cases (empty/absent Host, cancel-route Host-guard)
  apply to the JanetSec server's identical guard — mirror when the SIPR test harness is up.
- Carried (unexecuted): Host-header guard, report-preview CSP sandbox, wpt audit-Skipped,
  session disarm, honest Chrome/Edge + worker passthrough, upr refuse coverage + worker
  comment.
