# JANET Web — design loop 3 (2026-07-20)

## Decision 1 — CSP `sandbox` directive over an srcdoc iframe rebuild
Loop 1 deferred the report-preview backstop because the assumed fix (fetch HTML,
embed in a `srcdoc` + `sandbox="allow-scripts"` iframe) rewrites the preview flow:
new fetch path, iframe sizing, print behavior through an iframe, popup-blocker
interplay. The shipped fix is one header change: the `sandbox allow-scripts` CSP
directive applied to the `/api/report-preview` RESPONSE gives the top-level document
an opaque origin — the same isolation the iframe would have bought (no
sessionStorage, no same-origin /api) with zero client-flow change, native print
intact, and the existing one-shot GUID capability untouched. The view keeps its
`window.open` + redirect shape; only the comment changed.

## Decision 2 — verify the report script's sandbox-compatibility before shipping
`sandbox` breaks documents that rely on their origin. Checked before the change:
the generated report contains exactly one inline script (reports.psm1:3302) doing
pure DOM filtering — no sessionStorage/localStorage, no fetch/XHR, no
window.print(). So `allow-scripts` alone suffices; `allow-modals`/`allow-popups`
deliberately omitted (YAGNI — a future report script that alert()s will hit the
pinned CSP test and force a conscious decision).

## Decision 3 — fix Opus P3-1 (audit Skipped) in-loop; accept P3-2/P3-3
P3-1 is a data-honesty defect in the audit CSV (Skipped booked as Failure — an
operator reviewing Runs would chase phantom failures on not-installed hosts) with a
one-line, test-pinnable fix — inside this loop's budget. P3-2/P3-3 are message
wording on paths whose behavior is correct, mirrored from the accepted Chrome
pattern; changing them buys no operator decision-quality. Accepted with rationale
in the review doc rather than churning three modules' strings.

## Decision 4 — same-loop version bump moves the exact pin
wpt bumped twice this series (6.8.1 Edge port loop 2, 6.8.2 audit fix loop 3). Per
the floor-assert convention: the newest bump's test file carries the exact pin, so
`Wpt.EdgeProfile.Tests.ps1`'s manifest Describe moved 6.8.1→6.8.2 in the same
commit as the bump (its Edge-Script asserts are version-agnostic).

## Process note — stop racing the full suite
Loops 2–3 both started a full-suite run that my own later edits invalidated
(enumeration/execution race on this slow share). Going forward: targeted suites
during the loop, ONE full-suite run after the last code commit, recorded in the
ledger. (This loop's authoritative run happens after `7c79666`.)
