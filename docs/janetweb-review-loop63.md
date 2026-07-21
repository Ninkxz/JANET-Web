# JANET Web — review loop 63 (2026-07-21)

Fable-inline. Self-review of loop-62 → **GREEN**. Baseline: loop-62 authoritative **1458** (pkginstall+ subset 64 green after fix).

## Self-review of loop-62 (pkginstall DEPLOY confirm-word gate) — GREEN
The gate sits before target parsing so a wrong/missing confirm never touches a host; `[string]$Params['confirm']` on
a missing key → `''` → refuse (fail-closed); case-insensitive `-ne` matches the convention; `Invoke-JanetToolAction`
is the sole runtime dispatch (no bypass). 59 subset green. Nothing to reopen.

## Workstream: close item 70 — the last pkginstall dive finding
`ConvertTo-JanetMsiList` (`:153-155`) silently drops rooted / `..`-traversal entries. Two harms (CONFIRMED in-code):
1. **Partial-as-clean:** a pasted list with a dropped entry installs fewer MSIs than the operator listed but the host
   reports "All N succeeded" (N = the survivor count) with no notice that an entry was rejected.
2. **Scope escalation:** an all-invalid non-blank selection drops to empty, hits the `Count -eq 0` fallback (`:892`),
   and installs **every** `*.msi` in the bundle — a far broader action than the operator's (malformed) selection.

### Fix (pkginstall 2.5.11 → 2.5.12)
New pure `Get-JanetMsiListDropped` — the inverse of the `ConvertTo-JanetMsiList` predicate — returns the dropped
(rooted/`..`) entries. The caller (MSI mode, non-single-leaf) now **warns per dropped entry** so a partial selection
is visible, and **refuses** (returns, no fan-out) when a non-blank selection dropped to empty — rather than escalating
to whole-bundle install. A **blank** selection produces no drops and keeps the intentional install-everything path.
+5 tests: behavioral `Get-JanetMsiListDropped` (blank/all-valid → none; mixed → exactly the rooted/`..` entries; the
kept + dropped counts cover every non-blank line, proving the two predicates stay in sync; all-invalid → all dropped
+ `ConvertTo` empty) plus static asserts of the caller wiring (uses the helper, refuses when the survivor list is
empty, the "refusing rather than installing the whole bundle" message). Exact `2.5.12` pin (loop-62 gate Describe
floored). subset **64** green.

## pkginstall dive COMPLETE
All four loop-60 dive findings closed: item 67 (all-1638 false-clean), 68 (PSADT no-exit false-clean), 69 (missing
confirm-word), 70 (silent MSI-list drop / scope escalation). pkginstall carries the full destructive-tool guard stack
and its result plumbing is honest end-to-end. No further pkginstall workstream unless a concrete new lead surfaces.

## SECRET parity
- **SECRET parity:** the JanetSec pkginstall fork (if present) shares `ConvertTo-JanetMsiList` + the MSI-mode caller —
  mirror `Get-JanetMsiListDropped`, the per-drop warn, and the refuse-when-all-dropped guard.
