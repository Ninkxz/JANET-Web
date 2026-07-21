# JANET Web — review loop 23 (2026-07-21)

**Baseline:** loop-22 authoritative suite came back **1202/1203 — ONE failure** (not the clean 1203
I'd projected). Fable-inline. Local-only commits.

## Self-review of loop-22 — caught a REGRESSION I introduced (`fde4d6c`)
The loop-22 authoritative run failed `FixVerify2.Tests.ps1` > "NON-ZERO ReturnValue => NOT counted as
installed, the rejection is reported". Cause: the loop-22 KB-match commit ALSO reworded the
kb-install InstallUpdates rejection message ("...rejected...NOT installed" → "...not confirmed...NOT
confirmed") — a gratuitous change unrelated to the KB-match fix — and `FixVerify2` asserts
`Should Match 'rejected'`. My pre-commit check ran only `Wpt.*.Tests.ps1` (117 green); FixVerify2
isn't a `Wpt.*` file, so it was missed. Two lessons banked: (1) don't reword strings that aren't the
point of the change; (2) the pre-commit gate must be the FULL suite (or at least grep the assertion
space), not a name-glob subset.

**Repair** (`c9b22d1`, loop-22-repair): restored the original "rejected...NOT installed" wording while
KEEPING the loop-22 null-ReturnValue fail-close (a null return still reports rejected, now with
`ReturnValue=<null>`). And I added the missing regression test for that null-fail-close — the loop-22
change added the behavior untested — via a `-Rv -1` sentinel in the FixVerify2 shim (the method result
comes back with no ReturnValue member → `$rv` is `$null` → rejected, not counted). FixVerify2 green.

## Workstream (roadmap item 14, the loop-22 deep-dive's highest-harm false-clean) → FIXED
kb-install reported an unverified async MECM trigger as **"Installed"** and the view counted it — the
worst of the wpt verify false-cleans, because it also books a `VulnPatched` Success audit. Evidence:
- server `RowOf.Result` (`:6035`): `'Installed'` when `(MECMInstalled + MSUInstalled) -gt 0`, but
  `MECMInstalled` = MECM `InstallUpdates` *trigger accepted* (the async install can fail later).
- view (`wpt.view.js:87`, pre-fix): `asBool(r.Success) ? 'Installed' : 'Failed'` + `add.installed = 1`
  on any no-error host — it ignored the server Result entirely and counted every trigger as installed.

**Fix** (wpt **6.8.6 → 6.8.7**):
- New pure helper `Get-WptKbInstallResult -ErrorCount -MecmTriggered -MsuInstalled` (`:2734`): errors
  win; **any** MECM trigger → `Triggered (verify)` (errs toward verify, never over-claims — even
  alongside an MSU install, since part is unconfirmed); a confirmed MSU install (wusa exit 0/3010)
  alone → `Installed`; else `No change`. RowOf now calls it (server-local, no mirror needed).
- View (`:87`): surfaces the server `Result` (`String(r.Result || <legacy fallback>)`) and gates
  `add.installed` on `/^installed$/i` — a "Triggered (verify)" host no longer inflates the installed
  count. Backward-compatible fallback if a row lacks Result.

No guard weakened: the DNS wrong-box hard-abort and dispatcher self-guard are untouched; the change is
label/summary honesty only. All 138 wpt + FixVerify2 tests green post-change.

`Wpt.KbInstallResult.Tests.ps1` (8) pins the helper's five outcomes (incl. mixed MECM+MSU → verify)
+ static assertions that the view reads `r.Result` and gates the counter on a confirmed Installed +
the exact 6.8.7 pin. Loop-22 KbMatch exact 6.8.6 pin → `-ge` floor.

## Not fixed this loop (still ranked)
The `VulnPatched` audit action still books Success for a MECM-only trigger (the Detail distinguishes
MECM/MSU counts, and the Result column now says "Triggered (verify)", so the operator-facing false-clean
is closed — but the audit taxonomy overstates). Left as a follow-on to item 14. Items 15 (M365 mtime
verify), 16 (Chrome/Edge recency verify), 17 (verify-patch filter) unchanged.

## SECRET parity
- SECRET parity: the honest kb-install label — the JanetSec wpt fork shares the kb-install RowOf +
  view; mirror `Get-WptKbInstallResult` + the view Result-surfacing + the null-fail-close test.
- Carried (unexecuted): kb-install KB-match anchoring (loop 22), Get-ReportsSlaBucket, host-key fold,
  wrong-template hint, CSV-ingestion + routing tests, and everything earlier.
