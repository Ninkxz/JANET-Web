# JANET Web — design loop 71 (2026-07-21)

## Decision 1 — wire the generic fan-out, not each action
acas has ~a dozen remote actions, but they all fan out through one function, `Invoke-AcasFanOut`, with per-action
behavior injected via callbacks (`$RowOf`/`$OkOf`/`$AuditDetailOf`). So the hint belongs in the fan-out harvest, once
— every current and future acas action inherits it. This is the highest-leverage single wire in the fleet: one edit,
all of the most-used tool's failure paths.

## Decision 2 — attach where it's untruncated, not in the capped audit detail
The fan-out truncates the audit `detail` to 160 chars; the hints are longer than that, so appending there would just
be cut off. So the hint goes to two untruncated surfaces instead: the row `Hint` field (for the grid/view) and a new
err log line (for the live activity drawer). The audit detail keeps the raw result. remoteadmin's audit isn't
truncated, so there the hint went into the audit too — the surface is chosen per tool by what can actually carry it.

## Decision 3 — add the missing per-host log, but only for recognized failures
The fan-out emitted a row + audit per host but no log, so failures were only visible in the grid. Emitting an err log
for a recognized failure (one with a hint) both surfaces the failure in the drawer and delivers the FIX line. I scoped
it to `$hint`-present rather than every failure, to keep this loop additive and low-risk (a blanket per-host failure
log is a separate, larger UX change); an unrecognized failure still shows in the row as before.

## Decision 4 — additive only; guard the row shape
The classify (`$isSkip`/`$ok`/fail), the row, the audit result/count, and the counters are all unchanged — the hint is
computed after them and only read. The `Hint` field is added by mutating the row hashtable, guarded by
`$row -is [hashtable]` so a callback that ever returned a non-hashtable can't throw. Success and skip rows compute no
hint and emit no extra log, so the common path is byte-identical.

## Decision 5 — behavioral test through the real fan-out; the loop-37 lesson
`Invoke-AcasFanOut` runs a real RunspacePool, so a test can pass a `$Work` scriptblock that returns a canned
`FAIL: …0x80090351…` and drive the actual harvest — asserting the row gains a realm/TrustedHosts `Hint`, an err `FIX:`
log fires, the raw error is preserved, and the audit is still `Failure`; a success `$Work` gets neither. Because the
fan-out is shared by every acas action, I ran all 186 acas tests, not just the new file — the change is additive, so
none regressed. acas 1.11.12 → 1.11.13; the new Describe holds the exact pin, C2rVerify floors. Next tool: wpt.
