# JANET Web — review loop 55 (2026-07-21)

Fable-inline. Self-review of loop-54 → **GREEN**. Baseline: loop-54 authoritative **1427** green (reconfirmed by the redundant relaunch `bl7odduub`).

## Self-review of loop-54 (adto scan null-UAC fail-close) — GREEN
`ConvertTo-AdToObject` sets `UacReadable` from the raw attribute; `Test-AdToCompliance` fires the `uacUnreadable`
hit + skips the four UAC bad-bit rules only when unreadable; a real UAC (e.g. PASSWD_NOTREQD 0x20) still runs the
bit-checks (its test proves it); a missing key defaults readable (back-compat). 16 adto + 1427 confirmed no
regression. Nothing to reopen.

## Workstream: close adto item61 (F3) — the last real adto dive finding
The operator-editable baseline overlay (`JanetLocal\adto-baseline.json`) could silently disable a rule on a typo.

### Finding (CONFIRMED — re-verified in-code)
`Get-AdToBaseline` (`:84-92`) merged an overlay's `rules` by **replacing** the whole rule entry:
```
$def.rules[$rn] = @{ enabled=[bool]$r.enabled; appliesTo=@($r.appliesTo); requiresIao=[bool]$r.requiresIao }
```
An overlay entry tuning ONE field — e.g. `"passwordNotRequired": { "requiresIao": true }` — omits the others, so
`[bool]$null` made `enabled=$false` (**rule OFF**) and `@($null)` made `appliesTo` an array that contains no
category (**never fires**). Either way every violating object then scanned **COMPLIANT** with no trace, from a
plausible operator edit or a single mistyped key. (This is exactly why loop-54's `uacUnreadable` was deliberately
made non-overlay-silenceable — item61 is the overlay's own weakness.)

### Fix (adto 0.2.5 → 0.2.6)
`Get-AdToBaseline` now **merges** each overlay rule onto the embedded default (or a fail-closed
`enabled=$true` base for a rule name not in the defaults), overriding only the fields the overlay **explicitly**
provides (`$null -ne $r.<field>`). A missing `enabled`/`appliesTo` keeps the default; an **explicit**
`"enabled": false` still disables (intentional override honored). Scalar/array top-level overlays (inactiveDays,
patterns, iaoValidators) were already `$null`-guarded and are unchanged.

### Version + tests
- `AdTo.WriteGuards.Tests.ps1` +4 (real temp overlay file, `Get-AdToBaselinePath`-only shim so `Test-Path`/
  `Get-Content` stay real): omit-enabled keeps default `enabled=true`; omit-appliesTo keeps default (`-contains
  'User'`); the provided `requiresIao` IS applied; an explicit `enabled=false` still disables. Sole exact pin → 0.2.6.
- adto set **20** green; grepped all tests — only `AdTo.WriteGuards` touches `Get-AdToBaseline`.

## adto backlog after loop 55
Both null-UAC false-cleans (F1 fix-path / F2 scan) and the overlay silent-disable (F3) are now closed. Remaining
= F4/F5 (speculative, un-reproduced). The adto dive is effectively complete; next adto touch should be a fresh
deep-dive only if a concrete lead surfaces.

## SECRET parity
- **SECRET parity:** if a JanetSec adto fork exists it shares `Get-AdToBaseline` — mirror the merge-not-replace
  overlay logic (a partial overlay rule must not null `enabled`/`appliesTo`).
