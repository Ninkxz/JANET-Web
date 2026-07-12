# Production Review - Loop 11 (Phase 2, cycle 9) - 2026-07-12

Value pick (design-loop11.md): the first COMPREHENSIVE XSS sweep of all 22 `web/js/views/*.view.js` in a
single pass (prior audits only checked XSS per-module during rotation). One right-sized Opus reviewer
classified every HTML-injection sink (~30 `.innerHTML`, all confirm-dialog string bodies, `document.write`;
no `.outerHTML`/`.insertAdjacentHTML` exist) to origin. Desktop still blocked (6th cycle); no new committed
Web delta since loop 10.

**Rating: YELLOW -> GREEN after fix.** No P1. One SYSTEMIC P2 (7 occurrences, 1 root cause, 4 views) -
the 4 non-colliding sites FIXED this cycle; the 3 in certdeploy.view.js DEFERRED (concurrent WIP).
Everything else across all 22 views is XSS-safe. Suite 822/822.

## The finding (P2) - unescaped invalid-hostname list in RunBar guard dialogs
The RunBar host guard builds a `'title|body'` string interpolating the list of invalid host tokens
(`bad`) WITHOUT `esc()`. `onGuardFail` splits on `|` and passes `body` to `ctx.confirm({ body })`;
`confirmdialog.js:57` assigns a STRING body via `innerHTML` (the app's only intentional raw-HTML sink).
A token that fails `HOST_RE` by definition contains chars outside `[A-Za-z0-9.\-_]` (e.g. `<>`), so a
malformed target reaches innerHTML raw and `<img src=x onerror=...>` fires on the run-button click.
- **Data origin:** `targets.hosts()` - operator free-text in the Targets box, OR (the sharper vector)
  an imported ACAS/scan hostname CSV/TXT cell. Legit AD/scanner hostnames pass HOST_RE and never enter
  `bad`; only a malformed token does. **P2** (operator/import-adjacent, requires a malformed token +
  a click); nudges toward P1 under a threat model where imported scan files are untrusted.
- **Spot-verified:** the sink (`confirmdialog.js:55-59` string body -> innerHTML), the `bad` origin
  (HOST_RE-failing tokens only), and the already-correct sibling `dhcp.view.js:352` (`bad.map(esc)`).

### Fixed this cycle (commit 7bdc8dad4) - mirror dhcp's `.map(esc)`
- `beta.view.js:113` -> `.map(esc)` (local `esc` bound at :59)
- `biosfirmware.view.js:79` -> `.map(Janet.util.esc)`
- `secureboot.view.js:104` + `:177` -> `.map(Janet.util.esc)`
`node --check` clean on all three; suite 822/822 (JS-only change).

### DEFERRED - certdeploy.view.js:131 / :142 / :154 (same pattern, 3 occurrences)
`certdeploy.view.js` is part of the concurrent uncommitted "companions" WIP (`M` in the working tree).
A scoped `git commit -- certdeploy.view.js` would sweep in that session's edits, so per the hard rule it
was NOT touched. The 3 occurrences carry the identical fix (`bad.slice(0,5).map(esc)` - certdeploy binds
a local `esc` at :70). **To land when the WIP commits, or hand to the owner.** Ledger row 29.

## Everything else - GREEN (whole-surface XSS all-clear)
No remote scanner / AD attribute / certificate Subject-thumbprint / file-path field reaches `innerHTML`
unescaped in ANY view. Every dialog that renders engine data (biosfirmware baselines, acas cards, c2c
pillars, adto scan, dhcp, reports routes, upr findings, message, winupgrade) escapes with `esc`/`escHtml`,
emits only numeric counts, or builds a `textContent`/DOM-node body. `ResultsGrid` (textContent) and
`ActivityLog` (createTextNode) remain safe sinks. `reports.view.js:140` `document.write` writes only an
`esc`'d title (the report HTML is generated server-side, not written client-side).

## No flaky lint added
A regex "no unescaped innerHTML" lint can't distinguish `innerHTML='<b>static</b>'` from
`innerHTML=userData` and would be noise. The durable guard here is the fix + this documented all-clear,
not a heuristic that cries wolf. (ponytail: don't ship a flimsy check.)

## Desktop parity
This is a browser-DOM `innerHTML` sink. JANET Desktop tools have no web UI / DOM (same structural reason
as ledger row 14, the dhcp diffText XSS) - there is no Desktop code path. **CLOSED-WEB-ONLY** for the 4
fixed views; the deferred certdeploy 3 are likewise Web-only once landed.

## Verdict
Web XSS surface is now comprehensively proven and GREEN except the 3 certdeploy occurrences blocked by
concurrent WIP. Suite 822/822. Open: Desktop-mirror backlog (blocked 6th cycle), certdeploy XSS-3
(deferred), certdeploy owner confirm-string P2 (flagged loop 9).
