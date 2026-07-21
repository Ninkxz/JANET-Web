# JANET Web — review loop 62 (2026-07-21)

Fable-inline. Self-review of loop-61 → **GREEN**. Baseline: loop-61 authoritative **1453** (pkginstall+ subset 59 green after fix).

## Self-review of loop-61 (pkginstall PSADT null pre-seed) — GREEN
A real PSADT always `Exit-Script`s (sets an exit code) → unaffected; a no-exit script → `$null` → the new first
branch → Failed; a throw still routes to the existing catch. The FixVerify3 behavioral test proves both `exit 0` →
Success(warnings) and no-exit → Failed, and the harness now models a real `exit 0`. Nothing to reopen.

## Workstream: close item 69 — the missing pkginstall confirm-word (hard-rule gap)
The loop-60 dive found pkginstall is the **only** destructive tool in the suite with **no typed confirm-word** — a
direct violation of the stated hard rule ("destructive actions stay fail-closed: confirm-word + self-guard +
wrong-box"). Pushing/installing arbitrary software fleet-wide was armed by a single click once an admin session
existed. The other layers (server admin-session gate, self-guard, wrong-box hard-abort, IPv4/hostname validation) are
all present — this was a **missing layer**, not an unguarded path.

### Fix (pkginstall 2.5.10 → 2.5.11) — the adto pattern, no JS
Both deploy actions (`deploy-psadt`, `deploy-msi-bundle`) gain a required `confirm` manifest input ("Type DEPLOY to
arm"), and `Invoke-JanetToolAction` gains a fail-closed gate at the **single shared dispatch** (after the unknown-
action check, **before** any target parsing / self-guard / fan-out): `if ([string]$Params['confirm'] -ne 'DEPLOY')
{ refuse (rejected=$true, no rows) }`. Case-insensitive `-ne` matches the established convention (adto `-ne 'FIX'`,
secureboot ENABLE). No JS change — the `confirm` input renders in the form like any other field; the module gate is
the server-side barrier. The server admin-session gate + self-guard + wrong-box + IPv4 guards are untouched.

### Tests
+5 (`PkgInstall.SelfGuard.Tests.ps1`): version 2.5.11 exact; both actions declare a required `confirm` input; a
blank confirm → rejected + no fan-out + the "type DEPLOY" refuse log; a wrong word (`INSTALL`) → rejected while
lowercase `deploy` is accepted (documents the case-insensitive convention); a correct `DEPLOY` passes the gate and
reaches the self-guard. **`Invoke-Pkg` now injects `confirm='DEPLOY'` by default** so the 3 existing self-guard tests
still reach the self-guard (a test can set `confirm` explicitly to exercise the gate) — the loop-37 lesson applied
proactively: I grepped every test for the deploy action IDs first (only SelfGuard hits the gate; FixVerify3 runs the
extracted block directly, bypassing it). Exact pin moved to the gate Describe; the loop-61 PSADT Describe floored.
pkginstall+ subset **59** green.

## pkginstall backlog after loop 62
Item **70** (MSI-list silent partial drop, P3) is the last dive finding. pkginstall now has the full destructive-tool
guard stack (confirm-word + self-guard + wrong-box + IPv4) and both its false-cleans closed.

## SECRET parity
- **SECRET parity:** the JanetSec pkginstall fork (if present) shares `Invoke-JanetToolAction` + the deploy manifests
  — mirror the `DEPLOY` confirm input + the `$Params['confirm'] -ne 'DEPLOY'` fail-closed gate.
