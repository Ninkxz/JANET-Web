# JANET Web — review loop 51 (2026-07-21)

Fable-inline. Self-review of loop-50 → **GREEN**. Baseline: loop-50 authoritative **1409** green (confirmed).

## Self-review of loop-50 (wpt clean-user-apps honest status) — GREEN
`Get-WptCleanStatus` matches the inline mirror; the OkOf (Success/Dry Run OK only) + fan-out Failure-audit drop
Partial/Failed automatically; the sibling disk-cleanup worker (different semantics) was correctly left as-is.
40 wpt + 1409 confirm no regression. Nothing to reopen.

## Workstream: close wpt item45 — verify-and-clean removes the uninstall reg key only when files are gone
Another still-open wpt dive item, and a distinctive one: a *fleet-level* self-blinding false-clean.

### Finding (CONFIRMED — re-verified in-code)
The software-uninstall verify-and-clean pass (`$verifyClean`, `:4244`) confirms the install folder is gone and
removes the orphaned uninstall registry key from the three Uninstall hives. The key removal (`:4250-4259`) was
**unconditional** — it ran even when `$filesRemain` was true (the install folder still existed). So a
still-installed product (files present) lost its registry entry; the row correctly showed `Attention`, but every
later **registry-driven** scan — Software Scan, unsupported-product, ACAS registry detection — then read the host
as *not having the product*: a fleet-level false-clean that hides a product the uninstall did **not** actually
remove. Worse than a per-host status lie, because it corrupts the detection substrate other tools rely on.

### Fix (wpt 6.8.12 → 6.8.13)
The key is now removed **only** when the product's files are actually gone (the key is genuinely orphaned). If
files remain, the key is **KEPT** with a note — the product is still installed and deleting its registry entry
would blind future scans. The row's `Attention` verdict is unchanged; only the destructive registry write is now
gated on the files actually being gone.

### Version + tests
- `Wpt.VerifyClean.Tests.ps1` (NEW, 5): static analysis that the `Remove-Item` of the uninstall key is gated
  inside the files-gone (`else`) branch, the `KEPT` note precedes any `Remove-Item`, and the old unconditional
  form is gone. (Static because `$verifyClean` is an inline scriptblock in the module-less uninstall worker — the
  certdeploy/M365 precedent for remote-scriptblock logic.) `CleanStatus` exact pin → floor.
- wpt verify-clean/clean/guard set **29** + `SoftwareUninstall` **3** green — the pre-existing `orphaned
  uninstall key cleaned` assertion still holds (that note stays in the files-gone branch); grep clean.

## Remaining wpt backlog (from the loop-40 dive)
item43 (Java SC mtime verify, HIGH — needs a version target), item46 (Adobe GUID, MED), item47 (browser-client
mtime, MED), item48/49/50 (LOW), item51 (trigger≠patched, HIGH).

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares the software-uninstall verify-and-clean pass — mirror the
  files-gone gate on the uninstall-key removal.
