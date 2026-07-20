# JANET Web — review loop 5 (2026-07-20)

**Baseline:** 1063/1063 at loop-4 close (`f4387a6`); tree untouched between loops
(baseline re-run confirms — see ledger).

## Opus adversarial self-review of loop-4 (`2b7423f` Host-header guard) — verdict GREEN

No P1/P2. The primary risk — an availability regression from failing a legitimate
caller closed — was traced against EVERY real caller and cleared: `navigator.sendBeacon`
unload-cancel uses a relative URL (inherits the page's `127.0.0.1:$Port` origin), all
SPA `fetch`/`window.open` are same-origin, the launcher readiness poll is raw TCP (no
Host header), and both Pester harnesses use HttpWebRequest (Host = URL authority). The
production port is always ≥8089, so no browser ever sends a bare `Host: 127.0.0.1`
(scheme-default-port omission). Missing Host casts to `''` → 421 (no throw); 421 ships
the same hardened headers via `$writeBytes`' null-CSP default.

Accepted P3 notes (tracked, not fixed this loop):
- **F1 → ranked note:** the guard assumes a non-default port; if the operator ever
  hardcodes `-Port 80/443` the UI would 421 itself. Worth a one-line code comment.
- **F6 → ranked item 8:** Host-guard test gaps — (a) a truly ABSENT Host header, (b)
  the legit `POST /api/job/<id>/cancel?t=` cancel route with a good Host. Both cheap
  opportunistic adds to `Server.HostHeader.Tests.ps1`.
- The commit message said "8 asserts"; the suite is actually **9** (a bare-IP wrong-port
  case was added). Cosmetic; the ledger records 9.

## Sonnet mechanical re-verify (loop-4 guard at `f4387a6`) — all 5 PASS

65/65 across 6 server suites (all boot a real server → the edited request loop still
boots); BOM+parse clean; guard at `:393` sits before static (`:402`) before token gate
(`:447`); destructive gate / disarm / ack-required all undisturbed; commit touched only
the two expected files, no cert files.

## Workstream: fresh deep-dive on `upr` (Unsupported Product Remediator, destructive) + fail-closed coverage — **DONE** (`<fix sha>`)

Read the whole module (1933 lines). **upr is genuinely well-hardened** — findings on
record: confirm-word + `destructive:true` in the manifest on both uninstall actions;
pre-fan-out dispatcher self-guard (`Test-UprHostIsSelf`) on report-uninstall AND
manual-uninstall; DNS-mismatch **hard-abort** in the shared worker (removes nothing on a
wrong-box answer); uninstall-string **decomposed** into exe+discrete-args (never
`cmd /c` — LPE-safe, its own test); protected-agent + Tanium skip; and the key
fail-closed gate — **a LIVE uninstall with no operator selection is REFUSED** on both
paths (the worker's `$null RemoveSet => remove-all` legacy path is reachable only in
dry-run/preview). No security gap found.

Two deliverables:
1. **Fix (comment accuracy):** the worker's uninstall-pass comment read
   `(report-uninstall only)`, but `$UprWorkerBlock` is SHARED — both dispatchers call it
   with `$DoUninstall=$true`, so the DNS-mismatch hard-abort guards BOTH. Corrected the
   comment so a future reader doesn't assume the manual path is unguarded (it is guarded).
2. **Test-coverage growth (the real value):** before this loop the critical
   live-uninstall-requires-selection refusal had **zero** behavioral coverage (only the
   self-guard drop was tested). Added `Upr.LiveSelectionRefuse.Tests.ps1` (9 asserts;
   the fix commit message mis-stated 10 — the ledger records the true count):
   manual-uninstall live + no selection → Refused/total 0/no fan-out; manual dry-run does
   NOT refuse (self-guard still short-circuits, no host contact); report-uninstall live +
   no selection (fed a one-row in-memory "Unsupported" CSV so findings>0) → Refused before
   any host is dialed. No tool behavior changed, so no version bump (comment + tests only).

## SECRET parity
- SECRET parity: the `Upr.LiveSelectionRefuse` coverage + the shared-worker comment fix
  apply to the JanetSec upr fork (same dispatcher shape) — mirror the tests when the SIPR
  fork's test harness is stood up.
- Carried (unexecuted): Host-header guard, report-preview CSP sandbox, wpt audit-Skipped,
  session disarm, honest Chrome/Edge + worker passthrough.
