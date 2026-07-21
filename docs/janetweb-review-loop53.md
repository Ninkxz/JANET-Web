# JANET Web — review loop 53 (2026-07-21)

Fable-inline synthesis + one Fable deep-dive worker on adto. Self-review of loop-52 → **GREEN**.
Baseline: loop-52 authoritative **1420** green (confirmed).

## Self-review of loop-52 (wpt Adobe partial-uninstall) — GREEN
The Adobe branch counts per-GUID success/failure; a partial → Attention → not-ok (`$isOk` exact-Removed) →
audit not-Success; all-ok → Removed; all-fail → default Failed. 16 wpt + 1420 confirm no regression. Nothing to
reopen.

## Workstream: fresh false-clean deep-dive on adto (AD-TO compliance, 42KB, v0.2.3)
Diversified from the wpt grind. A Fable worker traced the whole module; I re-verified F1 in-code. The headline
is reassuring: the two **write** paths are genuinely fail-closed — the dive confirmed the fix's FIXED verdict
re-binds a *fresh* DirectoryEntry and compares the re-read UAC to the computed target (`$ok = ($ver -eq
$fx.Uac)`, not "write didn't throw"), and validate-iao likewise re-reads the stamp; the audit maps only
FIXED/VALIDATED → Success. The false-cleans are all on the **read** side, one `[int]$null → 0` coercion.

### F1 (FIXED this loop) — a null/unreadable userAccountControl reads "already compliant" + can corrupt-write
`:500` + `:525-526`. The fix path read UAC via `[int]("0" + [string]$de.Properties['userAccountControl'].Value)`.
A null/absent/unreadable UAC — a non-account object (group/OU/contact, no UAC, but binds and passes the DN
guard) or an ACL-denied read — coerced to `$cur=0` with no exception. `Get-AdToFixedUac` computes a clear-op rule
as `0 -band -bnot bit = 0` → `$fx.Uac -eq $cur` → row **NO CHANGE "already compliant"**, asserting compliance of
bits never read. And a **set-op** rule (`smartcardNotRequired`) with `$cur=0` would **write** `0x40000` as the
full UAC — wiping NORMAL_ACCOUNT on a read-denied object (the re-read then reports FAILED, but the corrupting
write already landed). **FIXED** (adto 0.2.3 → 0.2.4): read the raw UAC and, when `$null`, book **FAILED**
("absent/unreadable - compliance NOT evaluated, nothing changed") + a Failure audit **before** any computation
or write — closing both the false "already compliant" and the corrupting write. A real account's UAC is always
non-zero, so a legitimate object is unaffected.

### Ranked backlog (worker-CONFIRMED unless noted; re-verify before acting)
- **item60 (F2, MED-HIGH)** — scan-side: `ConvertTo-AdToObject` (`:370`) reads UAC via the same `[int]("0"+
  [string]…)` coercion, and a DirectorySearcher result missing the (ACL-hidden) attribute folds to `Uac=0` →
  `Test-AdToCompliance` (`:180-185`) sees no DONT_EXPIRE / PASSWD_NOTREQD / reversible-encryption → **COMPLIANT**.
  A service account with a hidden UAC + populated description + recent logon + valid recert stamp reads
  compliant while live it has PASSWD_NOTREQD. (null lastLogon `:173` and null recert `:187` DO fail closed —
  UAC is the one attribute where unreadable = no-bad-bits.) Fix: a null UAC → a distinct non-COMPLIANT/unknown.
- **item61 (F3, MED)** — `Get-AdToBaseline` overlay merge (`:84-92`): an overlay rule entry omitting `enabled`
  gets `[bool]$null=$false` and one omitting `appliesTo` gets `@($null)` (never fires), so a typo in the
  operator-editable `adto-baseline.json` silently turns a rule OFF — every violating object scans COMPLIANT with
  no trace (whole-file parse failure DOES fall back + note it, but the per-rule silent-off doesn't). Fix: default
  a missing `enabled` to true / warn, and log disabled overlay rules.
- **F4/F5 (SPECULATIVE, low)** — adminCount null-read guard-bypass (`:513`, same coercion, but nulls are
  legit-absent on normal objects so it can't be fully closed), and the admin-pattern-miss categorization
  downgrade (`:118`, inherent to the heuristic, header-disclaimed). Noted, not separately ranked.

### adto GREEN surfaces (worker-verified)
Fix FIXED verdict (fresh-bind re-read vs computed target); validate-iao (fresh-bind stamp re-read); audit
mapping (only FIXED/VALIDATED → Success); the IAO gate (empty allow-list refuses everyone); scan enumeration
error (partial results returned `rejected=$true`, never a clean summary); the protected-object + bind-redirect
guards.

## SECRET parity
- **SECRET parity:** if a JanetSec adto fork exists it shares `Invoke-AdToFix` — mirror the null-UAC → FAILED
  fail-close.
