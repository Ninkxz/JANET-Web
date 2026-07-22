# JANET Web — review loop 86 (2026-07-22)

**Theme: destructive-tool hardening.** Fable-inline + a Fable self-review of loop 85. Baseline: loop-85
authoritative **1579**.

## Self-review of loop-85 (upr P0 emit + acas F2) — **CLEAN, verified at RUNTIME**
After three consecutive loops where a "fix"'s green STATIC tests hid a runtime failure on the fixed path, the
self-review executed the actual code. Verdict: **both loop-85 fixes work at runtime and survive execution.**
- `New-UprRowEvent`: the old `@{ type='row' } + $row` re-proved to throw on 5.1; the case-sensitive event
  round-trips through the server's `ConvertTo-Json` (`:283`) with both `"type":"row"` and `"Type":"MSI"` distinct;
  the stored row is unaffected (throwaway copy).
- F2 inline mirror: executed the LIVE mirror text against the real profile table — the Java-remove case yields OK,
  the Chrome false-clean guard holds (update→unconfirmed), `'error'` is not rescued, and the mirror agrees with the
  canonical fn on all cases. Exactly 1 of 18 profiles carries `PostRemovedOk`; `$postRemovedOk` re-inits per
  invocation (no stickiness).

The behavioral tests (loop 85's lesson) are why these survived — the recurring static-test blind spot is closed.
**Two PLAUSIBLE latent items (not regressions, not triggerable today) → BACKLOG:** (1) `New-UprRowEvent` would
silently drop a PSCustomObject row (`.Keys` is $null → 1-key event) — but all 6 emit sites pass `@{}` literals, so
not reachable; a defensive `-is [hashtable]` guard would harden it. (2) canonical-vs-mirror divergence in the
contract-excluded `pre==post=='not installed'` region (the fn returns confirmed, the mirror returns UNCONFIRMED
"version unchanged"); fail-closed, low severity, arguably pre-existing.

## Workstream: kb-install wrong-box guard — a destructive-path safety gap (acas 1.11.14 → 1.11.15)
`AcasKbInstallBlock` (`:2729`) is a DESTRUCTIVE fan-out worker — MECM `InstallUpdates`, `wusa` MSU install,
`UsoClient StartInstall`, and a reboot when `NoReboot` is off — that was the ONLY destructive acas worker MISSING
the wrong-box (DNS-mismatch) guard its siblings carry (update `:2004`, reboot `:2174`/`:2201`). Stale DNS / a reused
IP → the operator dials WS01, the session lands on WS02, KBs install on the WRONG machine.

### Fix — add the guard, verbatim from the update worker
Inside the existing `try { … } finally { Remove-PSSession }`, before any install: `Invoke-Command {
$env:COMPUTERNAME }` compared to the dialed shortname; HARD ABORT (return a marker-tagged
`FAIL … DNS mismatch: … ABORTED, no KBs installed`) on mismatch. Invariants identical to the siblings — an
IPv4-literal target skips the compare (no shortname/DNS indirection), an empty probe proceeds (don't regress a
readable-name failure into a false abort). The abort `return` runs the `finally` (session cleanup); the all-zero
markers make the row a clean FAIL with nothing booked installed.

### Tests
`Acas.KbInstallStatus.Tests.ps1` +6 (matching `PkginstallSecureboot.WrongBoxGuard.Tests.ps1`): the guard's DECISION
tested behaviorally via verbatim replica functions (IPv4-skip / matching-shortname / different-name / empty-probe /
case-insensitive), AND a STATIC assertion scoped to the `AcasKbInstallBlock` body that the guard is PRESENT (IPv4
skip + `$env:COMPUTERNAME` compare + the `ABORTED, no KBs installed` return) — a future removal is caught. exact
1.11.15 pin; loop-85's 1.11.14 (BumpVerdict) floored. **loop-37 lesson:** ran the full acas suite (199) + full suite.

## SECRET parity
- **SECRET parity:** mirror the `AcasKbInstallBlock` wrong-box guard to X:\shh-JANET's acas fork (its kb-install
  worker shares the same destructive shape and likely the same gap). Verify the SIPR fork has the guard before/after.

## Remaining acas backlog (tracked, not started)
- **mtime-only verify** in `New-AcasClientVerify:185` (wpt shares it at `:941`): a verify-only run books a Chrome/Edge
  host OK on registry-key freshness alone, without confirming the version is current — the false-clean class loop 40
  fixed for Office C2R. Touches the two most-used tools; the next natural workstream, its own loop.
- The two loop-85 self-review latent items above (PSCustomObject-row guard; canonical/mirror pre==post divergence).
