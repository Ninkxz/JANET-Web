# JANET Web — review loop 52 (2026-07-21)

Fable-inline. Self-review of loop-51 → **GREEN**. Baseline: loop-51 authoritative **1414** green (confirmed).

## Self-review of loop-51 (wpt verify-clean self-blinding fail-close) — GREEN
The uninstall-key removal is now gated inside the files-gone (`else`) branch; when files remain the key is KEPT
with a note; the 'Attention' row verdict (driven by FilesRemain) is unchanged. 29 + 3 (SoftwareUninstall) + 1414
confirm no regression. Nothing to reopen.

## Workstream: close wpt item46 — a partial Adobe Acrobat uninstall is Attention, not a clean Removed
Another wpt dive item, in the same software-uninstall path as loop 51.

### Finding (CONFIRMED — re-verified in-code)
Adobe Acrobat registers multiple MSI product-code GUIDs across both Uninstall hives, so the uninstall branch
(`:4353`) `msiexec /x` each. It set `$removed=$true` if **any one** GUID uninstalled (`:4364`), with per-GUID
failures **not** tracked, and read `'Removed'` (`:4369`). So a **partial** uninstall — one GUID gone, others
failed/locked — reported a clean `Removed`, which the software-uninstall counter (`:5265`, `$isOk = ($rst -eq
'Removed')`) books ok + audits Success, while Adobe was still installed via the failed GUIDs. It also `continue`s
before the verify-clean, so no files-gone backstop.

### Fix (wpt 6.8.13 → 6.8.14)
The branch now counts per-GUID success/failure: **all** GUIDs removed → `Removed`; some failed while others
succeeded → **`Attention`** (an already-used not-clean bucket — `$isOk` requires an exact `Removed`, so Attention
is not counted ok and audits not-Success); all failed → the default `Failed` (unchanged). The failing GUIDs'
exit codes ride in the step detail.

### Version + tests
- `Wpt.AdobeUninstall.Tests.ps1` (NEW, 6): static analysis that per-GUID failures are counted (`$adobeFail++`),
  a partial removal → `Attention` not `Removed` (the Attention check precedes the Removed assignment), and the
  uninstall ok predicate is exact-`Removed`. (Static — the Adobe branch is an inline scriptblock in the
  module-less uninstall worker.) `VerifyClean` exact pin → floor.
- wpt Adobe/verify-clean/uninstall/guard set **16** green — `SoftwareUninstall` unchanged; grep clean (the only
  other 'Adobe Acrobat' hit is a reports test using it as product data).

## Remaining wpt backlog (from the loop-40 dive)
item43 (Java SC mtime verify, HIGH — needs a version target), item47 (browser-client mtime, MED), item48/49/50
(LOW), item51 (trigger≠patched, HIGH).

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares the Adobe Acrobat uninstall branch — mirror the per-GUID
  success/failure count and the partial → Attention verdict.
