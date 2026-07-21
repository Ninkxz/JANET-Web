# JANET Web — design loop 64 (2026-07-21)

## Decision 1 — dive a fresh destructive tool
The acting/hardening tools adto, remoteadmin, secureboot, and pkginstall are all dived and clean. upr is the next
substantial un-dived *destructive* tool (bulk-uninstall over WinRM, two destructive actions), so the campaign's
false-clean and destructive-safety lenses both apply. The dive found the uninstall/verify/audit core genuinely
fail-closed — the honest result is that upr was already hardened where it counts — so the workstream is the two real
handler-level weaknesses the dive substantiated, not a manufactured false-clean.

## Decision 2 — reuse the proven safe plan, don't re-invent GUID validation
The codebase already solved MSI-string injection once (`Get-SafeUninstallPlan`, the P2-5 fix, mirror-tested in
`Upr.UninstallStringParse.Tests`) and routed the QuietUninstall and generic-EXE handlers through it — but the
generic-MSI handler was left interpolating a loosely-extracted GUID into a raw ArgumentList string. The fix is simply
to route it through the same helper, so it inherits the already-proven discrete-arg, strict-hex-GUID safety rather
than getting a new bespoke validator. Consistency across the handlers is the point.

## Decision 3 — let the static assert widen the fix to the class
My "the old raw `msiexec -ArgumentList "/x` form is gone" assert failed on a SECOND occurrence — the Adobe handler,
which the dive hadn't flagged, shared the exact loose-`\{[^}]+\}` extraction + raw-ArgumentList pattern. That is the
loop-42 lesson working as intended: a class-level assert catches siblings of the reported instance. Rather than
narrow the assert to the one handler, I fixed the Adobe handler too — its three GUID extractions to the strict hex
pattern and its `Start-Process` to discrete args. Two instances of one vulnerability class, closed together.

## Decision 4 — delete the dead Store false-clean, don't maintain it
The Store branch is a textbook false-clean (unconditional OK invisible to verify) but is dead code today. The options
were to make it fail-closed or delete it. I deleted it: it's unreachable, the manifest's "Store" claim was itself
inaccurate, and a future `Type='Store'` now fail-closes down the existing EXE path (no UninstallString → Reject →
FAIL) — so removal is strictly safer than leaving a broken unconditional-OK branch as a landmine for a future
enumerator change to arm. Maintaining verify-for-Appx logic on a dead path would be building for a phantom.

## Decision 5 — static analysis, matched to the remote scriptblock; version
Both handlers live inside the remote WinRM uninstall `Invoke-Command` scriptblock (module-less, runs on the target),
so — like the loop-57/59/60 fixes — the regression test is static analysis of the module source, while the *safety*
of the plan it now routes through is already behaviorally proven by `UninstallStringParse`. The proximity assert was
made robust by anchoring on the branch's own `} else {` rather than a char count (a comment had pushed it past a
fixed window — corrected). Because the reachable uninstall path changed (raw-string → safe-plan) and the manifest
handler set changed, upr bumps 1.2.3 → 1.2.4; it holds the only upr version pin, updated in place. Items 72/73 ranked.
