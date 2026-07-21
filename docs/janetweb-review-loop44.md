# JANET Web — review loop 44 (2026-07-21)

Fable-inline synthesis + one Fable deep-dive worker on c2c. Self-review of loop-43 → **GREEN**.
Baseline: loop-43 authoritative **1363** green (confirmed).

## Self-review of loop-43 (wpt M365 exit-code gate) — GREEN
Both M365 profiles now `FAIL` on a nonzero OfficeC2RClient exit and return `OK (…exit 0)` otherwise; the
paired M365C2RVerify (scenario-success, honest) is untouched. Static assert + 57 + 1363 confirm no regression.
Nothing to reopen.

## Workstream: fresh false-clean deep-dive on c2c (C2C Nemesis, 276KB, v1.15.4)
A Fable worker traced the scan probe/verdict, all six fixers, host rollup, tally, audit, version check, cert
bundle, and WinRM heal; I re-verified the top finding in-code. c2c is largely fail-closed and heavily hardened
(escrow-first BitLocker, RTP re-eval, patch-overdue F5, import F4, scan CHECK-ERRORS-never-READY, self/wrong-box
guards). The dive found a set of pillar-verdict false-cleans.

### F1 (FIXED this loop) — AntiMalware books FIXED with zero end-state verification when Get-MpComputerStatus is unavailable
`:1982-1984`. The main AntiMalware branch (Get-MpComputerStatus present) verifies end-state — FAIL if
Active-but-RTP-off, FIXED only on a confirmed heal (`:1975-1981`). But the else-branch (the Defender PS provider
absent, `Get-Command Get-MpComputerStatus` empty — common on the very hosts that are non-compliant) booked
**FIXED** off a mere WinDefend/Sense service flip, with RTP / running mode / signatures all unread. So a
broken-Defender host read AntiMalware PROTECTED → host rollup FIXED (`:2361`) → **VulnPatched Success** audit.
**FIXED** (c2c 1.15.4 → 1.15.5): a service change we cannot confirm is **NOT VERIFIED** (the existing
fail-closed state PkiRoots uses). The host rollup maps NOT VERIFIED → NOT VERIFIED host status (never FIXED,
`:2360`) and the audit switch maps that → `Failure` / itemCount 0 (`:3090`), so the false PROTECTED/VulnPatched
is gone. Static-analysis test (a behavioral harness would need to shim `Get-Command`, which leaks into the
sibling scan tests; the NOT VERIFIED rollup/audit mapping is behaviorally covered by the PkiRoots + rollup tests).

### Ranked backlog (worker-CONFIRMED unless noted; re-verify before acting)
- **item52 (F5, HIGH)** — Monitoring fix books MONITORED/host-FIXED off the re-read service being Running
  (`:1444-1451`), ignoring the Tanium-INSTALLED half (`$ti.Installed` is Detail-text only). The scan's
  Monitoring PASS (`:751`) requires installed AND running. So an orphaned service without registered software
  (registry read failed / half-uninstall) → MONITORED with Detail literally "Tanium not installed". Same class
  as F1 — a pillar FIXED off a partial signal.
- **item53 (F3, MED)** — scan AntiMalware `$ageHours = [int]$mp.AntivirusSignatureAge * 24` (`:815`, mirror
  fixer `:1893`): a null property coerces to 0 (no throw), defeating the `$null -ne $ageHours` guard → sigFresh
  → PASS → READY on a host with unreadable signature state. CONFIRMED path, SPECULATIVE trigger (both timestamp
  and age null together). Fix: guard the coercion (`$null` age stays `$null`, not 0).
- **item54 (F4, LOW)** — AntiMalware fixer books NOCHANGE "already protected" when sig age is unknown
  (`:1975-1981`); the scan FAILs the same state (`:818` requires non-null). Narrow trigger.
- **item55 (F7, LOW)** — audit books host Status PARTIAL as `Success` (`:3091`); PARTIAL contains ≥1 pillar
  FAIL. Row Detail still shows the FAIL. Fix: PARTIAL → a non-Success audit result.
- **item56 (F8, LOW, read-only)** — version-check ordinal string fallback (`:3248-3255`): `1.8.0_51` vs
  `1.8.0_491` → CompareOrdinal '5'>'4' → NEWER (reads OK) though 51 < 491. Any non-`a.b.c.d` scheme.
- **item57 (F9, SPECULATIVE)** — Firewall scan/fix PASS on an empty (non-throwing) `Get-NetFirewallProfile`
  (`:761`/`:1460`); the netsh fallback DOES assert 3+3 (`:776`/`:1484`). No known empty-non-throw path.
- **F2 / F6 refine existing items 22/24** — the host-status rollup handles NOT VERIFIED correctly (`:2360`),
  but the per-pillar SUMMARY tally (`:3084`) folds SKIP / NOT VERIFIED / IN PROGRESS into `nochange`, so the
  summary line calls them compliant. This is the known view-coupled cluster (items 22 rollup / 24 tally).

### c2c GREEN surfaces (worker-verified)
Encryption fix genuinely escrow-first fail-closed (failed escrow → protector removed, Enable never reached,
STARTED/FIXED require a post-Enable/resume re-read); Firewall fix re-verifies after Set-NetFirewallProfile;
PkiRoots re-verifies persistence + fail-closed classifier + all-expired refused admin-side; scan verdict
(any quarantine-pillar ERROR → CHECK ERRORS never READY, zero checks → ERROR, patch-overdue fail-closed,
offline-def FIXED requires a re-read within budget); wrong-box/self-guard abort before change.

## SECRET parity
- **SECRET parity:** the JanetSec c2c fork shares the AntiMalware fixer — mirror the unavailable-branch
  FIXED → NOT VERIFIED fail-close. items 52–57 are parity candidates once closed.
