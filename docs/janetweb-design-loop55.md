# JANET Web — design loop 55 (2026-07-21)

## Decision 1 — merge, don't replace
The root of F3 is that the overlay loop treated an operator's rule entry as a *complete* rule, when in practice an
operator tunes one knob (turn on `requiresIao`, narrow `appliesTo`) and expects the rest to stand. Replace-semantics
turned every omitted field into a destructive default (`[bool]$null=$false`, `@($null)`). Merge-semantics — start
from the embedded default, override only what's present — matches operator intent and makes a typo inert instead of
silently disabling a control. It's also the standard, least-surprising way to layer config.

## Decision 2 — "explicitly provided" = `$null -ne $r.field`
`ConvertFrom-Json` gives a PSCustomObject whose absent properties read `$null` and whose present `false`/`[]` read
as real values. So `$null -ne $r.enabled` cleanly separates *omitted* (keep default) from *set to false* (honor it).
That preserves the operator's power to genuinely disable a rule while removing the accidental one. An empty
`"appliesTo": []` is treated as an explicit "applies to nothing" — intentional, and visible in the merged baseline.

## Decision 3 — unknown rule name defaults enabled, not off
An overlay rule name not in the embedded defaults merges onto a `{ enabled=$true; appliesTo=@(); requiresIao=$false }`
base rather than a disabled one. Fail-closed: a future/renamed rule an operator references shouldn't come up OFF. It
still fires nothing until `appliesTo` is set, but it's not silently suppressed.

## Decision 4 — leave the fail-closed synthetic hits alone
loop-54's `uacUnreadable` (and the null lastLogon/recert fail-closes) bypass the baseline `$fire`/overlay entirely.
This fix does NOT route them through the overlay — a read-failure signal must stay un-silenceable. F3 only hardens
how *configurable* rules load; the hard-wired honesty signals are unchanged.

## Decision 5 — behavioral test via the real load path; version
The overlay is read from disk, so the test writes a real temp JSON and shims only `Get-AdToBaselinePath` (adto-
specific) — `Test-Path`/`Get-Content` stay real, avoiding the loop-44 shim-leak class. Four cases pin the merge:
omit-enabled keeps default, omit-appliesTo keeps default, provided field applies, explicit false still disables. An
operator's one-field tune to a rule no longer disables it — behavioral — so adto 0.2.5 → 0.2.6, the sole exact pin
updated. F4/F5 stay ranked; the adto dive is otherwise complete.
