# JANET Web — design loop 73 (2026-07-21)

## Decision 1 — the destructive installer next, its own harvest
With the two generic fan-outs wired (acas, wpt) and remoteadmin, pkginstall is the highest-value next target: it's
destructive (fleet-wide software install), so its failures matter, and it's a tool I know cold from loops 60-63. Unlike
acas/wpt it has no shared fan-out helper — it hand-rolls a harvest loop — so the wire is placed in that loop directly,
but the shape is the same: compute the hint on a failure, attach it to the row and the log.

## Decision 2 — the failure predicate is the inverse of the existing count switch
The harvest already classifies each host via a count switch (`Success`/`Success (warnings)` → ok, `Deferred`/
`AlreadyInstalled` → skip, default → fail). A failure is exactly "status not in that ok/skip set", so `$isFail` is a
one-liner that reuses the same status literals — no new source of truth for "did this host fail". The hint is computed
only when `$isFail`, so success and skip rows are untouched.

## Decision 3 — feed the mapper the richest error text available
pkginstall assembles the per-host detail at read time: `$res.Detail` (the primary, e.g. a per-MSI exit table or a copy
failure), falling back to `$res.Reason` (early-return offline/repair paths set Reason not Detail), then the popup
`$res.Output`. The hint uses the same precedence — `$detail`, else `$reasonTxt`, else `$outputTxt` — so it matches on
whatever text actually carried the error, and the raw text stays in the row/audit unchanged.

## Decision 4 — reuse the existing err log, add a row field
pkginstall already emits a per-host err log for failures, so the hint is appended there (`… | FIX: $hint`) rather than
adding a second log line — one line, error then fix. The row gains a `Hint` field for the grid/view. The audit detail
is left as-is (it already carries the raw detail); the untruncated row+log carry the hint.

## Decision 5 — static analysis, matching the tool's convention; run the whole suite
The harvest sits inside `Invoke-JanetToolAction`'s fan-out over a real RunspacePool with no swappable worker seam
(unlike remoteadmin/acas), and pkginstall's other harvest tests are static source assertions, so the wire is pinned by
static analysis — proportionate, since the hint's behavior is already behaviorally proven elsewhere. Because the harvest
is shared by every pkginstall deploy action, I ran the full pkginstall suite (47) plus the FixVerify3 pkginstall PSADT
test (21) — the change is additive and touches neither the worker block nor the classify, so nothing regressed.
pkginstall 2.5.12 → 2.5.13; the new Describe holds the exact pin, the loop-63 Describe floors. Next tool: upr.
