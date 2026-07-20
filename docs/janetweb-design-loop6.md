# JANET Web — design loop 6 (2026-07-20)

## Decision 1 — bank the cheap tracked gaps, not a new deep-dive
Item 8 (the Opus loop-4 F1/F6 Host-guard notes) is small, and the temptation is to skip it
for something meatier. But the loop-4 Host guard is a security control, and Opus explicitly
named the two coverage gaps; closing them is higher-value than a new speculative surface. A
loop spent hardening the previous loop's security work with pinned tests is a good loop.

## Decision 2 — probe before asserting (again)
The absent/empty-Host behavior depends on http.sys internals (Opus noted an HTTP/1.1 no-Host
request is 400'd before our guard). Rather than assume, a raw-socket probe established the
exact status for each case:
| request | result | who rejects |
|---|---|---|
| empty Host value (HTTP/1.1) | 421 | our guard |
| HTTP/1.0, no Host | 421 | our guard |
| HTTP/1.1, no Host | 400 | http.sys (pre-loop) |
The tests assert the observed truth, not a guessed one. The HTTP/1.1-no-Host case asserts
`Should Not Match '200'` (rejected, regardless of which layer rejects) rather than a specific
code we don't own.

## Decision 3 — the cancel-route test earns a bonus guarantee
F6b asked only that the guard not BREAK the legit beacon-cancel path (good Host → not 421).
The probe also showed a FOREIGN Host on the cancel route 421s BEFORE the `?t=` token carve-out
runs — meaning a DNS-rebound page cannot abuse the one route that accepts a query-string token.
That's a stronger property than the note asked for, so it's pinned as its own assert.

## Decision 4 — comment-only server edit, no version/behavior change
Both the F1 note and the guard are comments/tests; no request-loop behavior changed. The
server carries no per-tool manifest version, so nothing to bump. Deliverable is coverage +
a discoverability comment.

## Process — reviewer cadence right-sized
Loop 5 was test+comment only (no destructive-path code change), so this loop ran the Opus
self-review but skipped the Sonnet re-verify (whose trigger is "previous loop touched
destructive-action or security paths" — loop 5 added coverage OF a destructive path but
changed no destructive code). Loop 6's own change is likewise test+comment, so loop 7 will
again need only the Opus pass unless it touches live code.
