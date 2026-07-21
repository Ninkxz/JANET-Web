# JANET Web — review loop 32 (2026-07-21)

**Baseline:** 1271/1271 at loop-31 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-31 (`ed0ada3` upgrade-drive pin-fail abort, `43800d0` docs) — verdict GREEN (inline)
Fail-closed control-flow guard (no pin → no drive); 168 winupgrade + FixVerify3 green, self-guard + DNS
wrong-box intact. Authoritative 1271/0-fail. GREEN.

## Workstream (winupgrade deep-dive F6, item 30) → FIXED: Diagnose READY no longer ignores disk/RAM/Secure Boot
The Diagnose action's one-word verdict is the operator's GO/NO-GO signal ("READY = all clear to Pin /
Force Discovery"). It derived from the report markers but tested ONLY CPU/TPM/[BLOCK]/policy
(`JanetWeb.winupgrade.psm1:2376-2380`, pre-fix) — the `[FAIL] Disk` / `[FAIL] RAM` / `[FAIL] Secure Boot`
lines its own scan emitted (`:1584-1597`) never reached the verdict. Scenario: supported CPU/TPM, policy
set, 10 GB free → verdict **READY**; the operator pins + drives, and the upgrade fails on disk.

Chose F6 over the other winupgrade items: it's the operator-facing go/no-go verdict (highest visibility),
the fix is clean and self-contained (add three marker checks + one verdict branch), and it has an
existing test surface. #27 (staging classifier) touches the remote signal + reboot invariant, and #29
(AutoFix) is multi-site — both get their own loops.

**Fix** (winupgrade **0.5.2 → 0.5.3**): a pure canonical `Get-WinUpgradeDiagnoseVerdict` (`:995`) adds
`$diskFail`/`$ramFail`/`$sbFail` and a distinct `NOT READY` branch, inserted AFTER `NEEDS POLICY` and
BEFORE `READY` — so it only reclassifies hosts that were falsely READY (BLOCKED/HW-INCOMPAT/NEEDS-POLICY
hosts are untouched; the precedence is otherwise unchanged). The runspace worker (which derives the
verdict in a module-less fan-out runspace) mirrors it inline, comment-linked, and the summary line now
appends `disk LOW` / `RAM LOW` / `Secure Boot off` so the operator sees the reason. Read-only verdict —
no destructive fan-out touched. 179 winupgrade + FixVerify3 tests green.

`Winupgrade.DiagnoseVerdict.Tests.ps1` (11) pins the helper at every verdict: all-PASS → READY, each of
Disk/RAM/Secure-Boot fail → NOT READY (the fix), and the higher-precedence verdicts (HW INCOMPAT,
BLOCKED, NEEDS POLICY, ON) still win over a disk fail — plus a static assert the worker mirror carries
`$diskFail`/`$sbFail` + a `'NOT READY'` branch + the exact 0.5.3 pin (WinUpgrade.Drive 0.5.2 exact → floor).

## winupgrade false-clean status
Fixed: F1 (upgrade-drive pin-fail abort, loop 31), F6 (Diagnose disk/RAM/SecureBoot, this loop). Remaining
(items 27-29, 31): 27 (F2, stale-staging reboots un-staged host — HIGH), 28 (F3+F4, bypass value asserted-
not-verified), 29 (F5, AutoFix premature FIXED — HIGH), 31 (F7, sfc unparseable→clean — LOW). 27/29 are
the high-harm next picks.

## SECRET parity
- SECRET parity: the Diagnose disk/RAM/Secure Boot verdict gate — mirror `Get-WinUpgradeDiagnoseVerdict`
  + the inline worker mirror to the JanetSec winupgrade fork if present.
- Carried (unexecuted): winupgrade upgrade-drive pin-fail abort; the c2c/acas/wpt remediation-honesty
  series; SLA bucket; host-key fold; wrong-template hint; CSV-ingestion + routing.
