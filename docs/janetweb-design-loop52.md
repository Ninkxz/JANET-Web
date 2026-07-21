# JANET Web — design loop 52 (2026-07-21)

## Decision 1 — the same uninstall path, the same audit-honesty class
item46 sits in the same software-uninstall worker as loop 51's item45 and is the same class as loops 44/47/50:
a not-fully-succeeded removal must not read as a clean success. Adobe is the one multi-GUID product in the
uninstall catalog, so "any-one-GUID-ok → Removed" quietly turned a partial removal into a clean one. Closing it
alongside item45 finishes the uninstall path's honesty in a pair.

## Decision 2 — Removed requires every GUID; partial is Attention
Adobe's several product-code GUIDs are all part of one product — removing one and leaving two means Adobe is
still installed. So `Removed` must require every GUID to uninstall. A partial is not `Failed` (some real removal
happened) and certainly not `Removed`; it's `Attention`, the existing not-clean bucket the verify-clean path
already uses for FilesRemain. The all-failed case already fell to the per-name default `Failed`, so only the
partial case needed a new branch.

## Decision 3 — the downstream already fail-closes on non-Removed
A pleasant repeat of loop 50's property: the software-uninstall ok predicate is `$isOk = ($rst -eq 'Removed')`
(`:5265`) — an exact match. So introducing `Attention` for a partial makes it non-ok and audited not-Success
with zero changes to the counter or audit. I verified that exact-match rather than assuming a partial would be
handled; the false-clean was entirely in the branch reading `Removed` too eagerly.

## Decision 4 — track the failures, surface the codes
The branch discarded per-GUID outcomes (`$removed=$true` on any success). The fix counts `$adobeOk`/`$adobeFail`
and appends each failed GUID's exit code to the step detail, so the operator sees which product code resisted
removal — the granular truth an Attention row should carry. This mirrors the "keep the honest numbers" move in
loop 50 (found vs removed): the data was available, it just wasn't consulted.

## Decision 5 — static analysis, version, scope
The Adobe branch is an inline scriptblock in the module-less uninstall worker, so — like the verify-clean and
M365 fixes — it's pinned by static analysis of the isolated block (per-GUID failure counted, partial →
Attention before Removed, ok predicate exact-Removed). A partial Adobe removal now reads Attention instead of a
clean Removed — behavioral — so wpt 6.8.13 → 6.8.14, VerifyClean exact pin → floor, the new test holds the exact
pin. wpt uninstall/guard set (16) green; authoritative run gates. Remaining wpt: item43 (Java SC mtime, HIGH,
needs a version target — the last non-trivial one), item47 (MED), 48–50 (LOW), 51 (trigger≠patched, HIGH).
