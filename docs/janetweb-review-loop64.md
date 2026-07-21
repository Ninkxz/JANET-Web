# JANET Web — review loop 64 (2026-07-21)

Fable-inline synthesis over one Fable adversarial deep-dive worker on **upr** (Unsupported Product Remediator —
bulk-uninstalls proven-EOL products over WinRM; two destructive actions). Self-review of loop-63 → **GREEN**. Baseline:
loop-63 authoritative **1463** (upr subset 40 green after fix).

## Self-review of loop-63 (pkginstall Get-JanetMsiListDropped) — GREEN
The helper is the exact inverse of `ConvertTo-JanetMsiList`'s predicate (kept+dropped=all-lines invariant proves it);
the caller warns per drop and refuses only an all-dropped non-blank selection; blank → install-everything path;
`$singleMsiLeaf` untouched. Nothing to reopen.

## Workstream: Fable dive on upr — core fail-closed, generic handlers hardened
The dive traced uninstall → verify → audit and all guards. **Core is genuinely fail-closed:** every "OK" is
exit-code-gated (0/3010 only) and passes a **mandatory post-uninstall registry re-verify** (`Get-UprVerifyResult`;
`$null`/unreadable → "could NOT be verified", still-present → "still present" — a lying uninstaller is caught); the
post-verify result feeds both row + audit, so a demoted FAIL can't be counted removed; **proven-gating is sound**
(RemoveSet/TargetFilter only restrict, never promote a Review to Uninstall); no coercions; all four safety guards
present + fail-closed. Two hardening findings acted on (one widened to its class):

### Finding acted on — MSI-GUID argument injection (P3, reachable, CONFIRMED)
The generic-MSI handler extracted a GUID with the loose `\{[^\}]+\}` (anything but `}` — allows spaces/switches
before the first brace) and interpolated it into a single `Start-Process msiexec -ArgumentList "/x $guid ..."`. A
crafted registry `UninstallString` GUID could inject extra msiexec switches under the **operator's** credential
(precondition: local admin on the target to write the key). **Fix:** route through the already-proven-safe
`Invoke-SafeUninstall`/`Get-SafeUninstallPlan` (rebuilds `/x {GUID}` from a STRICT hex-GUID as **discrete** arg
tokens — proven in `Upr.UninstallStringParse.Tests`), matching the sibling QuietUninstall/EXE branches.
**A static assert then caught the SAME flaw in the Adobe handler** (same loose pattern × 3 extractions + raw
`ArgumentList` string) — the loop-42 lesson: the assert widened the fix to the whole class. Tightened Adobe's 3 GUID
extractions to the strict hex pattern + discrete `Start-Process` args.

### Finding acted on — Store false-clean landmine (P2 latent, CONFIRMED)
The Store branch did `Get-AppxPackage | Remove-AppxPackage; return "OK (Store app removed)"` — a no-match pipeline
throws nothing and returns **unconditional OK with nothing removed**, and the registry re-verify can't see Appx (it's
not in the Uninstall hives). Dead today (the enumerator only sets Type MSI/EXE), but the manifest advertised "Store".
**Fix:** removed the dead branch (a future `Type='Store'` now fail-closes down the EXE path → no UninstallString →
Reject → FAIL) and dropped "Store" from the manifest handler description (2 places).

### Version + tests (upr 1.2.3 → 1.2.4)
+4 (`Upr.VerifyResult.Tests.ps1`, static analysis — both handlers live in the remote uninstall scriptblock): the MSI
branch reaches `Invoke-SafeUninstall` before its `} else {`; the raw `msiexec -ArgumentList "/x` form is gone; the
Store unconditional-OK + `type -eq 'Store'` are gone; the manifest (summary + report-uninstall description) no longer
says "Store". `Get-SafeUninstallPlan`'s injection safety is already behaviorally proven by `UninstallStringParse`.
Exact `1.2.4` pin updated in place (only upr version pin). upr subset **40** green.

## upr backlog after loop 64
- **item 72 (P3):** 3010 (reboot-required) flag lost for the Adobe/M365 OK strings (they don't embed the exit code),
  so a reboot-pending removal reports plain OK — a missing advisory, NOT a false-clean (the registry re-verify
  confirms the product is actually gone). Fix: surface the exit code / a `3010` token from those handlers.
- **item 73 (P3, speculative/by-design):** IPv4-literal targets skip the DNS wrong-box name check and an empty probe
  proceeds — documented house pattern (self-guard still checks NIC-IP membership); no change strictly required.

## SECRET parity
- **SECRET parity:** the JanetSec upr fork (if present) shares the generic + Adobe uninstall handlers — mirror the
  Invoke-SafeUninstall routing / strict-GUID + discrete-args, and the Store-branch removal.
