# JANET Web — review loop 15 (2026-07-20)

**Baseline:** 1130/1130 at loop-14 close. Fable-inline (no Opus/Sonnet agents; baseline ran
in background). Local-only commits.

## Self-review of loop-14 (`1c3cdb9` reports sweep + IAVM guard) — verdict GREEN (inline, Fable)
Read-only reports change. Confirmed: the remediation-refresh app-aggregate normalization is
live (manual run showed TargetCount=1 for a two-name host); the export-poam counter key is
aligned on increment (`:6262/6263`) AND read (`:6295`) — the only three counter sites, so no
0-count bug; the IAVM `$q` multi-line scriptblock returns its last expression correctly and is
tested (`=`-Title prefixed, clean-Title unchanged). No re-verify agent — read-only path, and the
change was covered by the agreement + IAVM tests.

## Deep-dive: secureboot (Enable Secure Boot — UEFI firmware write) — verdict YELLOW → fixed

A high-consequence destructive tool: it writes a UEFI Secure Boot firmware setting, leaves each
host **pending a reboot**, and on a non-UEFI/MBR box could leave it unbootable. Verified CLEAN
with file:line evidence:
- **Brick-safety (the headline):** before any write it positively verifies UEFI firmware mode
  (`$env:firmware_type -eq 'UEFI'`) AND a **GPT** system/boot disk, and SKIPs anything it can't
  confirm safe (`:352-377`) — the exact guard against "enable on MBR/legacy → unbootable".
- **Self-guard** drops the dispatcher BEFORE the RunspacePool (`:1139-1149`, `Test-JanetSbeHostIsSelf`).
- **Wrong-box** hard-abort BEFORE the password-bearing C$ drop (`:536/571` — "ABORTED, Secure
  Boot task not armed").
- **Fail-closed** result polling: missing/unreadable result JSON → Error/Timeout, never success
  (`:702-729`).
- **BIOS-password hygiene:** the payload script self-deletes the instant the result is written
  (`:410`), with launcher/close backstops.

**The gap (fixed) — no typed confirm-word.** The enable action was `destructive:true` (so the
server admin-session gate applies) but had NO typed confirm-word — the second barrier every
sibling destructive tool carries (remoteadmin 'RUN', c2c/adto 'FIX', wpt Custom Command 'RUN').
The view fired a live fleet firmware write straight from the "ENABLE SECURE BOOT" button on one
click (only an empty-password gate existed, and only when no password). A high-consequence
firmware write deserves the typed barrier. Fixed (`4ab8c05`, secureboot **1.6.0→1.6.1**):
- Manifest `confirm=` string on `enable-secure-boot` (module-level pin, naming the ENABLE word +
  the reboot consequence).
- View-side danger dialog requiring the operator to type **ENABLE**, gated to the LIVE path only
  (Dry Run is a harmless TCP+manufacturer preflight → deliberately ungated, consistent with the
  empty-password gate being live-only). Mirrors the loop-9 wpt approach (manifest confirm +
  view-side typed word).
Test `Secureboot.ConfirmWord`: manifest confirm + version; the view requires `confirmWord: 'ENABLE'`
positioned inside `if (!isDry)` before `ctx.run`; scan stays non-destructive/un-gated.

## SECRET parity
- SECRET parity: the secureboot enable typed-confirm barrier (manifest confirm + view ENABLE
  dialog) — the JanetSec secureboot fork has the same enable action + view.
- Carried (unexecuted): all prior SECRET-parity items.
