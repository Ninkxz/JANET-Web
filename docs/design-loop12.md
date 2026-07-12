# Design - Loop 12 (Phase 2, cycle 10) - 2026-07-12

## Why: audit the boundary, not just the tools behind it
7th consecutive cycle with both collision zones frozen (certdeploy WIP uncommitted, Desktop 19-dirty). No
new committed Web delta. All 22 tool modules + all 22 views are audited-GREEN across loops 3-11, plus a
comprehensive XSS pass (loop 11), self-guard parity (loop 8), DN-guard hardening (loop 9-10), CSV
injection, and cert-CA validation. The one high-value axis NEVER given a dedicated pass is the SERVER
LAYER itself - the trust boundary every tool sits behind.

## The pick: adversarial audit of server/*.ps1
`JanetWeb.Server.ps1` (HttpListener + router + static-asset file server + destructive gate),
`JanetWeb.Auth.ps1` (token), `JanetWeb.Logging.ps1` (audit bridge). I have been auditing the tools BEHIND
the boundary without auditing the boundary. Highest-risk classes, hardest first:
1. **Static-file path traversal** - the #1 risk: can a crafted asset URL (`..%2f`, absolute, UNC, null
   byte, double-encoded, backslash) escape the web root and read arbitrary disk files (the token file,
   other repos on the SMB drive)? Is canonicalization (`GetFullPath` + `StartsWith` containment) done
   BEFORE the read?
2. **Token auth** - RNG quality (crypto vs `Get-Random`), constant-time compare, required on every route
   incl. static + WS, on-disk ACL/lifetime, leak surfaces.
3. **Destructive admin-session gate** - re-confirm fail-closed (default-gated, 403 unless armed).
4. **Request/response** - header injection / response splitting, body reflection, DoS, verb handling.
5. **WebSocket** - Origin validation (cross-origin WS hijack), frame parsing, token gating.
6. **Logging** - log-filename path traversal, log injection, secret/token in a log.

## Decision rule
- Path traversal or auth-bypass = **P1**, fixed this cycle (canonicalize+contain, or crypto-RNG +
  constant-time compare), gated, tested, suite green.
- Meaningful weakening = P2, fixed. Defense-in-depth = P3, fix the cheap ones, document the rest.
- Anything needing a live domain = pilot-pending, never faked.

Right-sized to ONE focused Opus reviewer (deep single-area audit). Non-colliding: server/, not the
concurrent certdeploy zone.
