# Production Review - Loop 12 (Phase 2, cycle 10) - 2026-07-12

Value pick (design-loop12.md): the first DEDICATED adversarial audit of the SERVER LAYER - the trust
boundary every tool sits behind - after loops 3-11 covered all 22 tool modules + views. One Opus
reviewer over `server\JanetWeb.Server.ps1` (1027), `JanetWeb.Auth.ps1` (124), `JanetWeb.Logging.ps1`
(816). Desktop still blocked (7th cycle); no new committed Web delta since loop 11.

**Rating: GREEN.** The boundary is well-built - no P1/P2. Top-priority classes (static-file path
traversal, token auth, destructive gate) are all correct and the reviewer could not break them (verified
against code + a live PowerShell test of the traversal guard). One P3 belt-and-suspenders landed. Suite
822/822.

## What was verified CLEAN
- **Static-file path traversal (top priority) - DEFEATED.** `$req.Url.AbsolutePath` -> TrimStart('/') ->
  `Join-Path $webDir` -> **`Resolve-Path -LiteralPath` (canonicalize) BEFORE** the containment check
  `$resolved.StartsWith($webGuard + separator, OrdinalIgnoreCase)` -> `Test-Path -Leaf`. Two independent
  layers (Uri collapses `..`/`\`; Resolve-Path+StartsWith rejects escapes). Empirically ran the guard
  against `../../../../Windows/win.ini`, `..\..\`, `....//`, `/js/../../server/JanetWeb.Auth.ps1`,
  `C:/Windows/win.ini`, a UNC share path, and `/../web2/x.js` - **every traversal SERVED=False**.
  Content-type allowlisted; underscore/dev assets 404'd.
- **Token auth - SOUND.** Token = `[guid]::NewGuid('N')` (Windows crypto UUID, 122 bits - not the weak
  `Get-Random`); **constant-time compare** (length precheck + XOR-accumulate, no early return); required
  on every `/api` route (the only pre-token routes are static UI assets and a one-shot GUID-keyed
  report-preview, both intentional). Token never written to disk/log/header/error body; `no-referrer`.
- **Destructive gate - FAIL-CLOSED confirmed.** `$isDestructive=$true` default, downgraded only on a
  positive manifest `destructive=$false` read via `IDictionary.Contains` (correct for hashtables);
  missing flag -> gated; 403 unless ack + credential. No route bypasses it; unknown ids 404 first.
- **Request/response - CLEAN.** Every response header is a static constant (no request value echoed ->
  no response splitting); no redirects; error bodies are JSON+nosniff (no HTML reflection); exceptions
  go to console only (no path leak); all body sinks size-capped (bounded stream-copy defeats lying
  Content-Length); no `Invoke-Expression`/command/path interpolation of request data; upload filename
  hardened (Split-Path -Leaf + reserved-name + `\A...\z`-anchored subdir).
- **WebSocket - N/A** (none exists; job progress is token-gated HTTP long-poll; CSRF blocked by the
  mandatory custom `X-Janet-Token` header + no CORS).
- **Logging - CLEAN.** Tool->folder via char-stripping + dot-only fallback (no path traversal); CRLF
  sanitized in every CSV/transcript field (no log injection/row forgery); no token/credential logged
  (param key names only); CSV formula-injection neutralizer on both field encoders.

## P3 FIXED this cycle (commit d4e08e26d)
A Mandatory `[string]$Token` still accepts `''`. With an empty token the gate at ~:371 never matches
(the `$tok -and` short-circuits), so EVERY request 403s and the server looks up-but-dead. **Spot-verified
this is fail-CLOSED, NOT a bypass** (the reviewer's "zero-length match -> tokenOk=true" was inaccurate;
the `$tok -and` prevents it). But it fails silently, so added a one-line `throw` at server start to fail
loudly on a misconfigured launch. Not currently reachable (launcher passes a 32-char GUID); latent-trap
removal + operability. Trivial precondition, no dedicated test (ponytail).

## Accepted residuals (P3, documented - no change)
- Symlink planted INSIDE `web\` would be followed (requires write access to the repo + symlink priv - an
  attacker who has that already owns the code). - Token transiently in the launch-URL address bar
  (inherent to loopback+browser bootstrap; mitigated by `?t=` stripping + no-referrer). - Single-threaded
  accept loop is slow-loris-able by a local process (loopback + single operator; long idle timeout is a
  smartcard-picker constraint).

## Desktop parity
The entire server layer is Web-only - JANET Desktop has no HTTP server / listener / token / static-asset
route (same structural reason as ledger row 16, the fail-closed admin gate). **CLOSED-WEB-ONLY.**

## Verdict
The JANET Web trust boundary is comprehensively audited and GREEN - path traversal, auth, and destructive
gating all hold under adversarial testing. Combined with the loop-11 whole-surface XSS all-clear and the
loops 3-10 per-tool GREEN, the Web attack surface is now covered end to end. Open: Desktop-mirror backlog
(blocked 7th cycle), certdeploy XSS-3 (deferred, concurrent WIP), certdeploy owner confirm-string P2.
