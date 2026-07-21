# JANET Web — review loop 37 (2026-07-21)

Fable-inline. Self-review of loop-36 → **GREEN**. Baseline: loop-36 authoritative **1307** green (0 failed).

## Self-review of loop-36 (staging-reboot classifier) — GREEN
The `PHASE:STAGED` re-read now classifies the `~BT` tree inline (rollback marker / age / setup process,
mirror of `Get-WinUpgradeStagingClass`) and counts staged only when not `Stale`. Re-checked: the inline
mirror matches the pure classifier (static assert + classifier unit test both in the 1307), the reboot
gate on `Staged=false` is proven by Drive INVARIANT #4, and the fix is localized to the one re-read.
No regression, no new hole. Nothing to reopen.

## Workstream: winupgrade #31 — an UNPARSEABLE `sfc /scannow` no longer reads CLEAN (a false-clean)

### Finding (CONFIRMED, fail-open)
`Get-WinUpgradeRepairVerdict` (the DISM+SFC component-store repair verdict used by the repair-health /
AutoFix path) classifies the `sfc /scannow` text into `no violations` / `repaired` / `could not fix` /
`blocked`. The classifier's final `else` defaulted **any unmatched text** to `'no violations'`:

- `modules\JanetWeb.winupgrade.psm1:668` (pure helper) — `else { $sfc = 'no violations' }`
- `modules\JanetWeb.winupgrade.psm1:2685` (the inline MIRROR that actually runs in the remote,
  module-less runspace) — `else { $sfcV='no violations' }`

`'no violations'` then fell through to `else { $status = 'CLEAN' }` (`:675` / `:2691`). So a localized OS
(sfc emits its summary in the box's UI language), a truncated capture, or any output the four patterns
miss reported the component store **CLEAN** when the repair result was in fact **unknown** — a fail-open
in a health/verify path (the operator sees "clean" and stops looking).

Likelihood is LOW on an en-US fleet (the patterns match English), but the direction is wrong: a verify
step must not upgrade "couldn't read the result" to "confirmed healthy."

### Fix (fail-closed, both twins)
- Unmatched sfc text → `'unknown'` (was `'no violations'`), in the helper (`:668`) and the mirror (`:2685`).
- `'unknown'` joins the **PARTIAL** branch (`:672` / `:2689`) — a status the caller already renders,
  chosen over a new enum value so no consumer switch needs a new case. `'unknown'` is now explicitly
  *not confirmed clean*, never CLEAN.
- The mirror's `switch ($sfcV)` gains an `'unknown'` case → `[WARN] sfc /scannow: output not recognized -
  repair state UNKNOWN, NOT confirmed clean`, so the report line matches the verdict.
- Known outcomes unchanged: no-violations→CLEAN, repaired→REPAIRED, unable-to-fix→PARTIAL, dism-error→FAILED.

`Get-WinUpgradeRepairVerdict` is the pure canonical twin (no runtime call site — the worker runs the inline
mirror across the runspace boundary); both carry the identical change, comment-linked "keep in sync."

### Version + tests
- winupgrade **0.5.5 → 0.5.6** (behavioral: an unparseable-sfc host that read CLEAN now reads PARTIAL).
- `tests\Winupgrade.RepairVerdict.Tests.ps1` (NEW, 8) — establishes the first coverage for the verdict:
  unparseable/empty sfc → unknown/PARTIAL (never CLEAN), the four known outcomes hold, a static assert the
  module carries the unknown handling in both twins, exact `0.5.6` pin.
- Loop-36 `WinUpgrade.StagingReboot` exact `0.5.5` pin → floor `-ge 0.5.5` (newest bump holds the exact pin).
- winupgrade + RepairVerdict + StagingReboot + Diagnose24h2 + Drive + FixVerify2/3: **101/101** green.

## SECRET parity
- **SECRET parity:** winupgrade repair-verdict fail-close — an unparseable `sfc /scannow` reads `unknown`/
  PARTIAL, not CLEAN (helper `:668`/`:672` + inline mirror `:2685`/`:2689` + the `'unknown'` report line).
