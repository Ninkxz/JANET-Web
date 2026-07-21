# JANET Web — design loop 51 (2026-07-21)

## Decision 1 — the fleet-level false-clean next
Of the open wpt dive items, item45 is distinctive: it's not a per-host status lie (the row correctly says
Attention) but a corruption of the *detection substrate* — deleting a still-installed product's uninstall
registry key blinds every later registry-driven scan (Software Scan, unsupported-product, ACAS) into reading
the host clean. That's a broader blast radius than a single mis-worded status, and the fix is contained, so it
was the right next close.

## Decision 2 — gate the destructive write on the ground truth already computed
The verify-clean pass already establishes the ground truth: `$filesRemain` from a Test-Path of the install
folder. The bug was simply that the registry-key deletion didn't consult it. The fix reuses that exact signal —
remove the key only when files are gone (a genuinely orphaned key), keep it with a note when files remain. No
new probe, no new state; the honest condition was already in hand and just wasn't gating the write. The row's
Attention verdict is untouched, so the operator-facing outcome is unchanged — only the fleet-scan-corrupting
side effect is removed.

## Decision 3 — keep it, don't null it, when uncertain
The choice when files remain is between deleting the key (blinds scans) and keeping it (a possibly-stale entry
lingers). Keeping is the fail-closed direction: a lingering uninstall key at worst makes a scan *over-report*
(the product looks present when a later manual cleanup removed it), which is noisy but safe; deleting it makes a
scan *under-report* (a present product looks gone), which is the false-clean. When unsure, prefer the error that
surfaces the problem over the one that hides it.

## Decision 4 — static analysis for a remote-scriptblock control-flow guard
`$verifyClean` is an inline scriptblock inside the module-less uninstall worker, doing Test-Path/Remove-Item
against a live registry — not a pure function and not cheaply shimmable. The fix is a control-flow guard, so I
pinned it the way the certdeploy-M365 and want-set changes were: static analysis of the isolated block asserting
the Remove-Item is inside the files-gone branch, the KEPT note precedes any removal, and the old unconditional
shape is gone. Behavioral where the code factors into a pure function (loop 50's Get-WptCleanStatus); static
where it's I/O-bound remote logic — matched to the code, not forced.

## Decision 5 — version + scope
A still-installed product's key is no longer deleted — behavioral (a fleet scan that would have read the host
clean now sees the product) — so wpt 6.8.12 → 6.8.13, CleanStatus exact pin → floor, the new test holds the
exact pin. wpt verify-clean/clean/guard set (29) + SoftwareUninstall (3) green; the pre-existing
orphaned-key-cleaned assertion still holds because that note stays in the files-gone branch. Authoritative run
gates the close.
