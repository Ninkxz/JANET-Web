# Design - Loop 11 (Phase 2, cycle 9) - 2026-07-12

## Why this cycle is a value pick, not another rotation audit
Both collision zones are frozen for the 6th cycle: the concurrent certdeploy "companions" WIP is
unchanged (already reviewed GREEN in loop 9) and Desktop is still 19-dirty (mirror mandate blocked). No
new committed Web delta since loop 10. Re-running the per-module rotation audit over byte-identical code
adds nothing. So per the Cycle-3+ mandate ("single highest-value improvement per hour"), this cycle takes
the one high-severity audit AXIS that has never been done comprehensively.

## The pick: a suite-wide XSS / HTML-injection sweep across all 22 views
Every prior audit checked XSS **per-module, during that module's rotation slot** - so no single pass has
ever looked at all 22 `web/js/views/*.view.js` at once. XSS is the top browser-risk class for this SPA:
each view renders engine output that legitimately carries untrusted content - AD attribute values
(displayName/description/DN/memberOf), scanner text, certificate Subjects/thumbprints, remote hostnames,
file paths, operator free-text - any of which can contain `<img src=x onerror=...>`. A grep shows ~30
raw `.innerHTML` assignments across the views; a missed unescaped sink among them is exactly the kind of
gap a rotation audit can skip.

The shared safe sinks are `ResultsGrid` (`td.textContent`), `ActivityLog` (`createTextNode`), and the
`esc()` HTML-escaper (shell.js). The sweep classifies EVERY innerHTML / outerHTML / insertAdjacentHTML /
document.write / string-body-dialog sink as SAFE (static literal, `= ''` clear, or `esc()`-wrapped) or
FLAG (raw engine/AD/scanner/operator data reaching HTML), with a data-origin trace and a concrete
payload for each flag.

## Decision rule
- Any FLAG where a plausible engine/AD/scanner value reaches innerHTML unescaped = **P1**, fixed this
  cycle (wrap in `esc()` or switch to `textContent`/DOM node), gated, tested, suite green.
- All-SAFE = a documented comprehensive all-clear (real assurance value: the first whole-surface XSS
  proof), recorded in docs/prod-review-loop11.md. No flaky regex "innerHTML lint" is added - a heuristic
  that can't distinguish `innerHTML='<b>static</b>'` from `innerHTML=userData` would be noise, not a
  guard (ponytail: don't ship a flimsy check).

Right-sized to ONE focused Opus reviewer (one cross-cutting class, not a 4-way fan-out). Non-colliding:
touches views, not the concurrent certdeploy module.
