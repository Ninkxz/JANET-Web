# JANET Web — review loop 12 (2026-07-20)

**Baseline:** 1113/1113 at loop-11 close (`a7533e8`); tree untouched between loops.
Local-only commits.

## Opus adversarial self-review of loop-11 (`0b1a7c8` dryrun coercion) — verdict GREEN

Full truth-table walk of `ConvertTo-WptBool` on the clean-user-apps/cleanup-disk dryrun:
absent → dry (default preserved); JSON `$false`/`$true` unchanged (UI path byte-identical);
string `'false'`/`'0'`/`'no'`/`'off'` → LIVE (the fix); `'true'`/`'1'`/`'yes'`/`'on'` → dry.
The `'false'`-string test is non-vacuous (old `[bool]'false'=$true` would go dry, leave the
target, and NOT fire the self-guard → test would fail). **Accepted P3 (Finding A, no change):**
an *unrecognized* dryrun token (`'maybe'`) coerces to LIVE — fail-open on the dry/live axis,
but non-UI-reachable (manifest types dryrun as bool) and the self-guard still backstops the
dispatcher; keep-as-is recommended. Precision note recorded: the `confirm=` string is a
UI-side dialog, so the self-guard (not confirm) is the real server-side backstop on a non-UI
path.

## Opus deep-dive: adto (AD-WRITE tool — userAccountControl over LDAP) — verdict YELLOW → 3 fixed

First deep-dive of a tool whose destructive surface is **AD writes**, not WinRM fan-out — a
different risk class. Verified CLEAN with evidence: **no LDAP filter injection** (scan Filter
is a hardcoded constant; targets located by full DN, never an operator-built filter); the
**DN bind-redirect guard `Test-AdToDnInLocalDomain` is applied on every WRITE path** (scan
SearchBase + each fix dn + each validate dn), rejects `/`, control chars incl. the trailing-`\n`
`$`-anchor bypass, strips RFC-4514 `\`-escapes before the boundary/DC-count checks,
`ReferralChasing=None`; **UAC read-modify-write is correct** (`-bor`/`-band -bnot` on live value,
6-entry writable-bit allowlist — no TRUSTED_FOR_DELEGATION/PASSWD_NOTREQD-set path, so no UAC
privilege-escalation write reachable); confirm gates (`FIX`/`VALIDATE`) + `destructive:true`;
the IAO RBAC gate binds to the **Windows launching identity** (fail-closed, empty allow-list
denies all); credential in-memory only.

Three gaps found — **all fixed** (`68ca436`, adto **0.2.1→0.2.2**):
- **F1 (P2, borderline P1) — protected-object guard.** `Invoke-AdToFix` (`adto.psm1:478`)
  applied client-plan rules to any in-domain DN with **no object-type guard** — a crafted or
  fat-fingered plan naming a **DC computer object or a privileged (adminCount>=1) / break-glass
  account** would get ACCOUNTDISABLE set (DoS of a critical AD object). The DN guard proves
  in-domain, not criticality; the UAC allowlist constrains WHICH bits, not WHICH objects. Added
  a pre-write refusal for a DC (`SERVER_TRUST` bit in its own UAC) or `adminCount>=1`, with a
  PROTECTED row + Skipped audit. Normal objects unaffected (test proves no over-block).
- **F2 (P2) — fail-closed IAO validate.** `Invoke-AdToValidate` committed the recert stamp then
  reported VALIDATED with **no post-commit re-read** (fail-open), unlike the fix path. Now
  re-reads and reports VALIDATED only when the stamp persisted, else FAILED.
- **F3 (P3) — audit the redirect refusal.** Both bind-redirect reject branches (fix + validate)
  now emit a Skipped audit event (a plan steering a credentialed write at a foreign DN is a
  security event, not just a UI row).

New `AdTo.WriteGuards.Tests.ps1` (first adto behavior suite): F1 DC+adminCount PROTECTED /
normal FIXED; F2 VALIDATED-on-persist vs FAILED-on-non-persist; F3 reject audited. New-AdToEntry
+ DN/domain/IAO helpers shimmed in module scope — no real directory bound.

Deferred (accepted): F4 (Get-AdToBaseline re-read per row — perf nit, no security impact).

## SECRET parity
- SECRET parity: the adto F1 protected-object guard + F2 fail-closed validate + F3 reject audit
  — the JanetSec adto fork (if present) has the same write paths; mirror all three.
- SECRET parity: (carried) the loop-11 wpt dryrun coercion fix.
- Carried (unexecuted): all prior SECRET-parity items.
