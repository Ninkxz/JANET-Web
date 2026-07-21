# JANET Web — design loop 67 (2026-07-21)

## Decision 1 — take the dhcp fail-open next
Of the remaining loop-65 dhcp items, 76 (dryRun fail-open) is a live fail toward a destructive write on an ambiguous
input — the same class secureboot's loop-58 closed — so it goes ahead of the option-id retarget and the apply
null-result. A destructive-mode selector that silently goes live on a typo is a safety defect, not a polish item.

## Decision 2 — a dedicated fail-closed parse at the dryRun sites, not the shared helper
`$asBool` serves both `removeOption` and `dryRun`. For `removeOption`, an unrecognized token resolving to `$false`
fails safe (don't remove). For `dryRun`, `$false` is the DANGEROUS value (a live write). Same helper, opposite safety
polarity per caller — a false sibling. So, exactly as secureboot did (kept `Get-SbeBool`, added `Get-SbeDryRunSafe`),
I leave `$asBool` untouched and add a dedicated `Get-DhcpDryRunSafe` used only at the two dryRun sites. Changing
`$asBool` would wrongly flip `removeOption`.

## Decision 3 — live requires positive non-dry; unrecognized stays dry
`Get-DhcpDryRunSafe` mirrors the secureboot semantics: the live path is entered only on an *absent* value (the
manifest `dryRun default=$false`, preserved by the caller's `ContainsKey` guard so a normal apply still runs live) or
an *explicit recognized* false token. The precise behavior that changed is the present-but-unrecognized case —
`'dry'`, `'checked'`, `'TRUE '`, `'2'` now stay dry instead of silently going live. The live write must be asked for,
not fallen into.

## Decision 4 — a module function, not an inline scriptblock, so the test is behavioral
My first cut was an inline `$asDryRun` scriptblock local to `Invoke-JanetToolAction` — which would only be
static-testable. I refactored it to a module-level `Get-DhcpDryRunSafe` (beside the loop-66 self-guard helpers), so it
gets the preferred behavioral unit test: five cases driving it directly across absent/empty, explicit-false,
explicit-true, and the unrecognized-token class that is the fix — cases that return `$false` (live) under `$asBool`
and return `$true` (dry) now. Because a typo'd dry-run now stays dry instead of writing live, this is behavioral: dhcp
1.1.10 → 1.1.11, the newest Describe holds the exact pin and the loop-66 confirm/self-guard Describe floors.

## Decision 5 — the loop-37 lesson, again
Before editing I confirmed which tests touch the dryRun path. The two dryRun call sites are in `Invoke-JanetToolAction`;
`FixVerify`/`FixVerify3` drive `Invoke-JanetDhcpApply`/`Invoke-JanetDhcpBulk` with an explicit typed `-DryRun` bool
(below the `$Params` parse), so they never reach `Get-DhcpDryRunSafe` — unaffected. Ran all three dhcp-touching files
to confirm. Items 77-79 remain; 78 (apply null-result → Changed/Success + no post-write verify) is the last real dhcp
false-clean and the most valuable next pick.
