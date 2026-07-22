# JANET Web — design loop 86 (2026-07-22)

## Decision 1 — close the destructive-path safety gap (the cadence's explicit priority)
The loop-84 acas deep-dive flagged (and I re-verified) that `AcasKbInstallBlock` — a DESTRUCTIVE worker that
triggers MECM `InstallUpdates`, copies+runs an MSU via `wusa`, or fires `UsoClient StartInstall`, and can reboot
when `NoReboot` is off — was the ONLY destructive acas fan-out MISSING the wrong-box (DNS-mismatch) guard its
siblings carry (update worker `:2004`, reboot workers `:2174`/`:2201`). Stale DNS or a reused IP means the operator
dials WS01 but the session lands on WS02 → KBs (and a reboot) install on the WRONG machine. Destructive-tool
hardening (wrong-box / self / IPv4 guards, "never weaken them") is a named cadence priority; here we ADD a missing
one. This is the loop's workstream — chosen over the other backlog item (the mtime-only verify) because it's a
safety gap on a destructive path.

## Decision 2 — mirror the established guard verbatim; place it inside the try (finally cleans the session)
The guard is copied from the update worker (`:1999-2010`): before any install, `Invoke-Command { $env:COMPUTERNAME }`
and compare to the dialed shortname; HARD ABORT (return FAIL) on mismatch. Design invariants kept identical to the
siblings: an **IPv4-literal target skips** the compare (`-notmatch '^\d{1,3}(\.\d{1,3}){3}$'` — no shortname to
match, no DNS indirection possible), and an **empty probe proceeds** (don't regress a readable-name failure into a
false abort). Placed as the FIRST statement inside the existing `try { … } finally { Remove-PSSession }`, so the
abort `return` runs the finally and cleans up the session — no duplicated teardown.

## Decision 3 — the FAIL string carries the block's markers so the row parses correctly
The kb-install worker returns marker-tagged strings (`<<MECM=n>> <<MSU=n>> <<SKIP=n>> <<KBS=…>>`) that the rowOf
parses. The abort return uses the same all-zero markers as the offline/session-failed returns
(`FAIL <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=$kbList>> DNS mismatch: … ABORTED, no KBs installed`), so the row
renders as a FAIL with a clear reason and zero counts — nothing is booked installed.

## Decision 4 — tests: replica-behavioral + static-presence (the wrong-box guard convention)
The worker runs in a module-less runspace (no WinRM in unit scope), so — matching
`PkginstallSecureboot.WrongBoxGuard.Tests.ps1` — the guard's DECISION is tested behaviorally via verbatim replica
functions (IPv4-skip → no abort; matching shortname → no abort, case-insensitive; different name → abort; empty
probe → no abort), AND a STATIC assertion scoped to the `AcasKbInstallBlock` body pins that the guard is PRESENT
(the `$Computer -notmatch` IPv4 skip, the `$env:COMPUTERNAME` compare, and the `ABORTED, no KBs installed` return)
so a future removal is caught. acas 1.11.14 → 1.11.15; the new Describe holds the exact pin, loop-85's 1.11.14
(BumpVerdict) floored.

## Decision 5 — verify no collateral; the remaining backlog stays tracked
Ran the full acas suite + the full suite. The other two backlog items — the mtime-only verify in
`New-AcasClientVerify:185` (shared with wpt `:941`, a false-clean class) and (now done) F2 — remain: the mtime-only
verify is the next candidate, a correctness/false-clean fix touching the two most-used tools, deserving its own loop.
