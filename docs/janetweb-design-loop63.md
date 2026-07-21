# JANET Web — design loop 63 (2026-07-21)

## Decision 1 — finish the pkginstall dive
Items 67-69 are closed; item 70 is the last loop-60 finding. Closing it now completes pkginstall's dive in one clean
sweep (two false-cleans, a confirm-word, and this drop/escalation), so the tool can be left audited-clean rather than
with a known partial-as-clean open. It's P3 but carries a real scope-escalation edge (all-invalid → install
everything), which lifts it above a pure accounting gap.

## Decision 2 — an inverse-filter helper, not a changed return type
`ConvertTo-JanetMsiList` returns the kept list and is used by tests expecting an array; changing it to also report
drops would break its contract. Instead I added `Get-JanetMsiListDropped`, the exact logical inverse of its predicate
(rooted OR `..`, vs. not-rooted AND not-`..`). Two small twins are simpler than one richer return, and the caller
already had the raw blob to pass to both. The behavioral test asserts kept.Count + dropped.Count equals the non-blank
line count for a mixed input — a cheap invariant that catches the twins drifting out of sync.

## Decision 3 — warn on partial, refuse on total; blank stays install-everything
Three cases, three behaviors. A partial drop (some kept, some dropped) **warns** per dropped entry and proceeds with
the survivors — the operator asked for those, and the drops are now visible instead of silent. An all-dropped
*non-blank* selection **refuses** — the operator did specify MSIs, they were all invalid, and silently installing the
whole bundle instead is a scope escalation, so fail-closed is right. A **blank** selection (no drops) keeps the
existing intentional install-everything fallback with its warn. The distinguisher is `Get-JanetMsiListDropped` being
non-empty, which only a non-blank-with-invalid-entries input produces.

## Decision 4 — refuse only inside the non-single-leaf branch
The MSI mode has a `$singleMsiLeaf` shortcut (operator pasted a direct `.msi` file path) that overrides `$msiList`
entirely; the drop logic doesn't apply there. So the warn/refuse lives in the `else` of that branch, keeping the
single-file path untouched. The refuse returns the same summary shape as the sibling msiArgs-abort in the same block
(`total=$targets.Count; ok=0; failed=0; deferred=0`), plus `rejected=$true`.

## Decision 5 — behavioral helper + static caller wiring; version
`Get-JanetMsiListDropped` is pure, so it gets the preferred behavioral test. The caller warn/refuse lives in
`Invoke-JanetToolAction` after the confirm gate, self-guard, and pkgPath resolution — reachable only with a real
bundle path and a surviving target, so a full behavioral test is disproportionate; the wiring is pinned by static
analysis (uses the helper, refuses gated on the empty survivor list, the refuse message). Because an all-invalid
selection now refuses instead of installing everything, this is behavioral: pkginstall 2.5.11 → 2.5.12, the newest
bump's Describe holds the exact pin and the loop-62 gate Describe floors. The pkginstall dive is complete.
