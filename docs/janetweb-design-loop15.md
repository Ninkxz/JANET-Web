# JANET Web — design loop 15 (2026-07-20)

## Decision 1 — deep-dive the next un-reviewed destructive tool (secureboot)
Reports correctness is done (loops 13-14). secureboot was the highest-consequence un-deep-dived
destructive tool: a firmware write that leaves hosts pending reboot and can brick a non-UEFI/MBR
box. It's exactly the kind of tool where the full destructive contract must hold. It mostly did —
but the review found a real gap (no typed confirm-word), which is the point of doing the pass.

## Decision 2 — the gap IS a gap, not a nit
One could argue the server admin-session ack + the big-red-button UI is "enough". It isn't, by the
repo's own contract: CLAUDE.md lists "confirm-word typed in the view" as a required element of a
destructive remote action, and EVERY other destructive tool has it (remoteadmin 'RUN', c2c/adto
'FIX', wpt Custom Command 'RUN', pkginstall/upr confirm gates). secureboot was the outlier. An
accidental click on a pre-filled form (targets loaded, password entered) would have fired a live
fleet firmware write with no second barrier. For a firmware change that reboots hosts, the typed
word is warranted.

## Decision 3 — manifest confirm= AND view-side typed word (the loop-9 wpt pattern)
Two pieces: (a) a manifest `confirm=` string — the module-level, testable declaration that this
action is confirm-gated (documents intent, gives a Pester pin); (b) the view-side `confirmWord:
'ENABLE'` danger dialog — the ACTUAL barrier the operator hits (the manifest string is not the
prompt source; the view builds its own, exactly as Opus confirmed for wpt in loop 10). Adding both
matches the established pattern and keeps the module honest about the tool being confirm-gated.

## Decision 4 — gate the confirm to LIVE, not Dry Run
Dry Run is a TCP + WinRM-manufacturer preflight that writes NO firmware. Gating it behind a typed
word would be friction for a harmless action — and it's consistent with the existing empty-password
gate, which is already `!isDry`. So the ENABLE confirm sits inside `if (!isDry)`, and the test pins
that placement (it must be after `if (!isDry) {` and before `ctx.run`).

## Decision 5 — Fable-inline, additive-only, no re-verify agent
Per the operator directive, the deep-dive and fix were done inline by Fable. The change is strictly
additive (a new confirm string + a new view dialog); it touches no existing guard (self-guard,
wrong-box, brick-safety, fail-closed, self-delete all unchanged), so a mechanical re-verify sweep
would only re-confirm what the diff plainly shows. The 32/32 secureboot suite (incl. the existing
wrong-box + scan tests still green) covers it.

## Versioning
secureboot `1.6.0 → 1.6.1` (behavioral: adds the confirm barrier). `Secureboot.ConfirmWord` holds
the exact pin; `Secureboot.Scan`'s exact pin → floor assert (wpt-suite precedent).
