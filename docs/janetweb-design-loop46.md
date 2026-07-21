# JANET Web — design loop 46 (2026-07-21)

## Decision 1 — close the highest-rated remaining c2c item on the safety-critical surface
The c2c dive's tail (items 53–57) is mostly low/read-only/speculative, but F3/item53 is the one MED, and it sits
on the scan's READY verdict — the operator's quarantine go/no-go, the highest-stakes read in the tool. A
coercion that manufactures a false-fresh signature signal there is worth closing even though its exact trigger
is speculative: the code is objectively wrong, and "the scan says READY" is the signal an operator trusts to not
quarantine a box.

## Decision 2 — the bug is `[int]$null → 0`, a classic coercion fail-open
`[int]$null` returns 0 without throwing, so a `try/catch` around it is useless (there's nothing to catch), and 0
then reads as a 0-hour "fresh" age that passes the freshness gate and defeats the `$null -ne $ageHours` guard
downstream. The fix is to never enter the coercion when the source is null — `else` → `elseif ($null -ne
$mp.AntivirusSignatureAge)` — so a null age leaves `$ageHours` at its `$null` initial value, which the gate
treats as stale (fail-closed). This is the same `[int]`-cast-guard discipline acas's spec-exec verify uses
(a non-numeric value is treated as absent/vulnerable, never compliant).

## Decision 3 — fix both mirror sites; a false-clean is a class
The identical coercion is in the scan (`:830`) and the fix (`:1914`). Fixing only the scan would leave the fixer
(which drives the same freshness decision to update signatures / call NOCHANGE) still fooled. Both get the guard,
and the static assert pins that the unguarded form appears nowhere and the guarded form recurs — so neither
mirror can drift back. (item54/F4 — the fixer booking NOCHANGE "already protected" on an unknown age — is the
verdict-level sibling; this loop fixes the age *computation* both share, item54 is the fixer's verdict handling,
ranked separately.)

## Decision 4 — pure helper, deterministic where it counts
`Get-C2cSigAgeHours` centralizes the computation and is unit-tested at the branch that matters: null age → null
(the fix), a real age → days×24, a genuine 0 still allowed (a real fresh age isn't falsely failed), and a
datetime winning over the age fallback. The datetime branches use `Get-Date` so I test them loosely (a 3-hour-old
stamp reads ~3h); the fix itself — the SignatureAge fallback — is fully deterministic. The module-less workers
carry the inline mirror; the static assert keeps the twins honest.

## Decision 5 — version + the tail
A host with an unreadable age that read fresh/READY now reads stale — behavioral — so c2c 1.15.6 → 1.15.7, the
loop-45 Monitoring exact pin → floor, the new test holds the exact pin. c2c set (71) green; authoritative run
gates. After this the c2c tail is genuinely low/read-only/speculative (items 54–57 + the 22/24 cluster), so loop
47 should weigh a fresh dive on an un-reviewed tool (remoteadmin/adto/secureboot/reports) against grinding the
tail — the disciplined call once a tool's high-harm findings are closed.
