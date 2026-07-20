# JANET Web — design loop 4 (2026-07-20)

## Decision 1 — probe before hardening
Roadmap item 3 was carried as "defense-in-depth" from the loop-1 Opus review, which
called DNS-rebinding SPECULATIVE/mitigated. Rather than add a guard on faith, ran a
raw-socket probe against a throwaway `HttpListener` with the production IP-literal
prefix: a foreign `Host: evil.example.com` was served 200 (http.sys matches the
IP-literal prefix by destination ip:port, not by Host). That upgraded the item from
speculative to confirmed-exposed and justified the guard. The probe script lived in
the scratchpad, not the repo.

## Decision 2 — 421 Misdirected Request, not 403/404
421 is the semantically correct status for "this server is not authoritative for the
requested Host" (RFC 7540 §9.1.2 / general HTTP). 403 would imply an auth failure
(there's no auth on the static surface) and 404 would imply a missing resource. 421
also reads clearly in a log when someone is probing.

## Decision 3 — guard placement: top of the loop, before EVERYTHING
The guard sits before the static-asset branch, not just before `/api`. The rebind
target is precisely the token-less surface (static UI + report-preview), so guarding
only `/api` would leave the actual affordance open. Fail-closed on a missing Host too
(`-ne` both names) — no legitimate local browser omits Host on HTTP/1.1.

## Decision 4 — exact-authority match, not a suffix/regex
Only two literal strings match: `127.0.0.1:$Port` and `localhost:$Port`. No
`StartsWith`/regex (which invites `127.0.0.1.evil.com` or `localhost:$Port@evil`
bypass thinking). The launcher only ever dials `http://127.0.0.1:$Port/`, and a human
typing `localhost:$Port` is the only other legit case. If the operator ever needs a
different bind name, it's a one-line allowlist add with a conscious edit.

## Decision 5 — Host guard is a NEW server capability, not a tool bump
No tool version changes this loop (the guard is in the server request loop, which
carries no per-tool manifest version). The change is additive and covered by its own
boot-a-real-server test.

## Decision 6 — F8 (report-resource-free guard) deferred to a ranked item, not scope-crept
Opus's F8 (a static test that reports stay fully inline so the sandbox stays valid) is
a good cheap guard, but loop 4's one workstream is the Host-header guard. Per the
one-workstream-per-loop rule it becomes ranked item 7 rather than riding this commit.
