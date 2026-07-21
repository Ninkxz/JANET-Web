# JANET Web — review loop 43 (2026-07-21)

Fable-inline. Self-review of loop-42 → **GREEN**. Baseline: loop-42 authoritative **1356** green (confirmed).

## Self-review of loop-42 (wpt null-RV fail-close sweep) — GREEN
`Get-WptRvAccepted` = non-null AND `[int] 0`; all five sites mirror it (static assert confirms both old
null-accepting forms gone module-wide + the fail-closed form recurs); the updates-path catch sets `$rv=-1` →
rejected; the WptAppActionBlock restructure returns OK=true only on accept while still surfacing the post-invoke
EvaluationState; rejected messages print `<null>`. 59+24+1356 confirm no regression. Nothing to reopen.

## Workstream: close item40's M365 slice — the OK is gated on the OfficeC2RClient exit code
The worker's **top-ranked HIGH finding**, and a concrete one (unlike the async-completion depth): both M365
app-update profiles interpolated the exit code into an OK string but never tested it.

### Finding (CONFIRMED — re-verified in-code)
`Microsoft 365 - Force Update` (`:939`) and `Microsoft 365 - Update (User Visible)` (`:1248`) triggered
`OfficeC2RClient.exe /update` then `return "OK (Office update triggered, exit $($proc.ExitCode))"` — the exit
code is only *interpolated*, never gated. In app-update-apply, that `OK…` prefix (`:3427`) → ok → a
**VulnPatched Success** audit. So a nonzero OfficeC2RClient exit (a real failure — e.g. a scenario conflict,
a blocked update, the service dead) read OK and booked a patch for a host whose Office was not updated.

### Fix (wpt 6.8.10 → 6.8.11)
Both profile Scripts now `FAIL` on a nonzero exit; exit 0 stays `OK (…exit 0)`. Exit 0 means the update was
accepted/started — the paired `M365C2RVerify` (which since loop24 gates Verified on `LastScenarioResult`
success, and which acas's loop-40 port now mirrors) confirms actual completion. This closes the nonzero-exit
false-clean; the deeper "an accepted async trigger still books VulnPatched on exit 0" is the trigger≠patched
semantic, **item51**.

### Version + tests
- `Wpt.M365Update.Tests.ps1` (NEW, 7): static analysis that both M365 profile blocks gate on
  `$proc.ExitCode -ne 0 → FAIL` and that the old unconditional `OK (…exit $($proc.ExitCode))` form appears
  nowhere in the module; exact pin 6.8.11 (Wpt.BulkPatchRv exact pin → floor). Remote profile Scripts are
  module-less, so static analysis is the established pattern.
- wpt M365/bulk-patch/verify/profile set **57** green; grepped all tests for the touched string/version — only
  the two files I edited.

## Remaining wpt backlog
item40 residual: the Trellix profile (`& $cmd 2>&1 | Out-Null` never throws on nonzero → "ePO sync sent") and
the SC-trigger profiles (`Invoke-CimMethod | Out-Null` discards rv) — the same ignored-signal class, different
mechanisms; item43 (Java SC mtime verify, needs a version target); item51 (trigger≠patched semantic); items
44–50 (MED/LOW).

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares the M365 profiles — mirror the `$proc.ExitCode` gate in both
  the Force Update and User Visible Scripts.
