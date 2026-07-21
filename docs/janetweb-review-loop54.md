# JANET Web — review loop 54 (2026-07-21)

Fable-inline. Self-review of loop-53 → **GREEN**. Baseline: loop-53 authoritative **1423** green (confirmed).

## Self-review of loop-53 (adto null-UAC fix-path fail-close) — GREEN
The fix reads `$rawUac`, and on `$null` books FAILED + a Failure audit + `continue` before any computation or
write; `$cur = [int]$rawUac` only when non-null; a real UAC (512) proceeds → FIXED (existing test). 12 adto +
1423 confirm no regression. Nothing to reopen.

## Workstream: close adto item60 (F2) — the scan-side twin of the loop-53 fix
Same `[int]$null → 0` coercion root as F1, in a different function; completes adto's null-UAC honesty.

### Finding (CONFIRMED — re-verified in-code)
`ConvertTo-AdToObject` (`:370`) read UAC via `[int]("0" + [string](& $get 'useraccountcontrol'))`. An ACL-hidden
UAC is simply absent from the `DirectorySearcher` result → `$get` returns `$null` → `Uac=0`. Then
`Test-AdToCompliance`'s bad-bit rules (`:180-182`: `$uac -band DONT_EXPIRE / PASSWD_NOTREQD / ENCRYPTED_TEXT_PWD`,
all `-ne 0`) read false → no bad-bit hits. A **Service** account (excluded in the default baseline from the
`smartcardNotRequired` rule that otherwise catches `uac=0`) with a hidden UAC + a populated description + recent
logon + a valid recert stamp then scanned **COMPLIANT** while live it had PASSWD_NOTREQD set. (The dive noted null
lastLogon and null recert DO fail closed — UAC was the one attribute where "unreadable" read as "no bad bits".)

### Fix (adto 0.2.4 → 0.2.5)
`ConvertTo-AdToObject` now carries `UacReadable` (`$false` when the raw attribute is null/empty).
`Test-AdToCompliance` fires a fail-closed **`uacUnreadable`** hit (→ NON-COMPLIANT) when `UacReadable` is false and
**skips the four UAC bad-bit rules** (a 0 reads as no-bad-bits and can't be trusted). The non-UAC rules (inactive,
description, manager, recert) still run. An object built without the key defaults to readable (back-compat for
any hand-built caller/test).

### Version + tests
- `AdTo.WriteGuards.Tests.ps1` +4 (direct `Test-AdToCompliance` calls with injectable `$Now`): unreadable →
  NON-COMPLIANT + `uacUnreadable`; a readable no-bad-bits UAC → no over-flag; a readable PASSWD_NOTREQD (0x20)
  still flagged (the real bad-bit path works); a missing key → readable. Sole exact pin → 0.2.5.
- adto set **16** green; grepped all tests — only `AdTo.WriteGuards` touches the compliance/scan functions.

## Remaining adto backlog
item61 (F3, baseline overlay silently disables a rule on a typo → COMPLIANT, MED) + F4/F5 (speculative). Both
adto null-UAC false-cleans (F1 fix path / F2 scan) are now closed.

## SECRET parity
- **SECRET parity:** if a JanetSec adto fork exists it shares `ConvertTo-AdToObject` + `Test-AdToCompliance` —
  mirror the `UacReadable` flag and the `uacUnreadable` fail-closed hit.
