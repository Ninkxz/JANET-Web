# JANET Web — review loop 34 (2026-07-21)

**Baseline:** 1287/1287 at loop-33 close (authoritative, 0 fail). Fable-inline + one parallel Fable
worker. Local-only commits.

## Self-review of loop-33 (`4a21b07` bypass read-back, `5ed3fca` docs) — verdict GREEN (inline)
Additive/fail-closed read-back extension (only ADDS a verify — can't weaken a guard); a normal Pin/Unpin
is byte-for-byte unchanged (pre-existing read-back tests untouched); 198 winupgrade + FixVerify2/3 green.
Authoritative 1287/0-fail (FixVerify2 gained 5 tests; I'd estimated 6 — corrected). GREEN.

## Fresh SECURITY deep-dive: server/auth/token boundary (parallel Fable worker) → verdict GREEN
Diversified off correctness/false-cleans to the app's execution boundary — the loopback HttpListener +
token-gated `/api` routes that dispatch destructive WinRM. A bounded Fable worker traced `Auth.ps1` +
`Server.ps1` (+ the launcher token gen); I verified in-code. **The boundary is solid — no exploitable
gap:**
- **Token:** 122-bit per-launch value, compared **constant-time** (length gate + XOR-accumulate,
  `Server.ps1:454-456`), enforced by a **single central gate** ahead of every tool/action/cred/session/
  upload/job route; destructive actions carry an ADDITIONAL fail-closed session gate (default-DENY).
- **Static serve:** `Get-JanetWebAssetPath` canonicalizes (`Resolve-Path`) then requires the resolved
  path to start with the web root + separator AND be a leaf — `..`/absolute/UNC/sibling-prefix all →
  404. Upload write-paths are traversal- and device-name-safe.
- **CSRF / DNS-rebinding:** state-changing POSTs require the token in a **custom header** (sessionStorage,
  not a cookie) a cross-origin page can't set without a preflight the server never satisfies; the loop-4
  Host guard (421 on any Host but loopback) fronts every route incl. report-preview.
- **Bind:** loopback IP-literal only (`http://127.0.0.1:$Port/`), no `+`/`*`/`0.0.0.0`.
- **Bodies bounded** (upload 1 GB, action/preview 25 MB, incl. chunked); errors are JSON + `nosniff`, no
  HTML reflection; no `Invoke-Expression`; `actionId` allowlisted before dispatch; report-preview served
  under the loop-3 `sandbox allow-scripts` CSP with an opaque origin.
- The `?t=` URL token carrier (roadmap item 4's neighborhood) is confirmed **well-contained**:
  `Referrer-Policy: no-referrer`, the SPA strips it after first paint, and `?t=` is honored ONLY for the
  job-cancel POST — every other `/api` route demands the `X-Janet-Token` header.

## The one actionable item (defense-in-depth) → FIXED: explicit CSPRNG for the access credentials
The session token (launcher `:125`) and the report-preview retrieval key (`Server.ps1:722`) were
`[guid]::NewGuid().ToString('N')`. On Windows GUIDv4 IS CSPRNG-backed (`UuidCreate`), so this is NOT
exploitable — but for the app's core access credentials the unpredictability should be a documented
crypto guarantee, not a reliance on the GUID implementation detail. New pure `New-JanetWebSecureToken`
(`Server.ps1:95`) mints 32 bytes (256 bits) from `RandomNumberGenerator` as lowercase hex; the
report-preview rid uses it, and the (no-modules) launcher inlines a comment-linked mirror for the
session token. No behavior change beyond a longer/explicitly-random credential; 76 server tests green.

`Server.SecureToken.Tests.ps1` (6): the helper produces 64 lowercase hex chars, differs across calls,
never empty; + static assertions the rid uses the helper and the launcher mints from
`RandomNumberGenerator` (no `[guid]::NewGuid()` for the token). No tool-version bump (server files
aren't manifest-versioned).

## SECRET parity
- SECRET parity: the CSPRNG access-credential mint — the JanetSec server + launcher share the token
  gen; mirror `New-JanetWebSecureToken` + the launcher inline.
- Carried (unexecuted): the winupgrade/c2c/acas/wpt remediation-honesty series; SLA bucket; host-key
  fold; wrong-template hint; CSV-ingestion + routing.
