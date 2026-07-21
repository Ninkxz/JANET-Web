# JANET Web — design loop 34 (2026-07-21)

## Decision 1 — diversify the workstream TYPE: security, not another false-clean
After ~12 loops of correctness/false-clean fixes across five tools, the highest-value un-reviewed
surface is the security boundary — the loopback listener + token-gated `/api` that dispatches
destructive WinRM. A hole there dwarfs any false-clean (up to fleet RCE). It's also the loop-prompt's
explicit deep-dive alternative and hadn't had a loop-era pass since loops 1-4.

## Decision 2 — a GREEN deep-dive is a real result; don't invent a fix
The boundary came back solid: constant-time token, central enforcement, canonicalized static serve,
custom-header CSRF defense, loopback bind, bounded bodies. Confirming that with file:line evidence is
itself the deliverable — a security review that finds nothing exploitable is valuable, and inventing a
"fix" for a non-gap would be theater. So the loop's finding is GREEN, documented.

## Decision 3 — do the one honest hardening: explicit CSPRNG for the credentials
The deep-dive's single actionable item is defense-in-depth, not a vuln: the access credentials were
`[guid]::NewGuid()`. It's CSPRNG-backed on Windows, so not exploitable — but a security credential
should derive its unpredictability from a documented crypto contract (`RandomNumberGenerator`), not an
implementation detail that a future runtime change could (however improbably) alter. Ponytail says never
simplify away a security measure; making the guarantee explicit is a legitimate, minimal one.

## Decision 4 — mint from RandomNumberGenerator, 256-bit hex
32 bytes from `RandomNumberGenerator.Create().GetBytes()` → 64 lowercase hex chars. More entropy than
the 122-bit GUID and an explicit CSPRNG. The constant-time compare already handles any length, so the
longer token is transparent to the gate.

## Decision 5 — canonical helper + no-modules launcher mirror
The report-preview rid lives in the server module → it calls `New-JanetWebSecureToken` directly (real
in-module use, unit-tested). The session token is minted in the launcher, which runs "pure PowerShell,
no modules" — so it inlines a comment-linked mirror, exactly the helper-is-spec + inline-mirror pattern
used for every runspace boundary this series. A static assertion pins that the launcher uses the CSPRNG
and dropped `[guid]::NewGuid()`.

## Decision 6 — no version bump, dot-source unit test
Server files aren't manifest-versioned tools, so nothing to bump. The test dot-sources Server.ps1 (the
same load the Server.Gate test uses) to call the pure helper directly, asserting format + distinctness,
plus source-level assertions on the launcher/rid. Ran the full server test set (Gate, ReportPreview
sandbox, SecureToken) green — the rid change is transparent to the report-preview flow. Fable-inline;
the deep-dive was a parallel Fable worker, the hardening a one-helper change verified in-code.
