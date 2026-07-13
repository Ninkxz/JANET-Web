# Production Review - Loop 20 (Phase 2, cycle 18) - 2026-07-13

Value pick (design-loop20.md): the deep CORRECTNESS lens - now 2-for-2 (c2c loop18, acas loop19) -
applied to `wpt` (6006 lines, v6.6.0), the LARGEST tool and third destructive fleet orchestrator. One
Opus reviewer. Every P1/P2 spot-verified by me. Both backlogs operator-deferred; wpt is committed
(non-colliding).

**Rating: YELLOW -> GREEN after fix.** Rollup/verdict honesty, STIG read-back, reboot/abort pairing, and
pool source-injection all VERIFIED CORRECT (no false-green/omitted-token bug here). One systemic defect:
the dispatcher self-guard was missing on 3 of wpt's reboot-capable actions. All fixed. Suite 877/877.

## FIXED - self-guard coverage gap on 3 reboot-capable actions (commit 8b4cdf2)
`Remove-WptSelfTargets` (the drop that reboot/reboot-schedule/fix-java apply before fan-out) was ABSENT
from three other actions that can reboot a target, so a target list including the JANET dispatcher host
could reboot the box running the HttpListener:
- **P1 bulk-patch FORCED** (`:4986`): forced mode sets `IsRebootIfNeeded` on app installs -> the target
  CCM client can reboot the dispatcher MID-DISPATCH, killing the listener and abandoning the rest of the
  ~1h fan-out. The exact failure the guard exists to prevent. *Spot-verified: no Remove-WptSelfTargets in
  the bulk-patch case; forced -> reboot-if-needed at the patch block.*
- **P2 registry-key-apply reboot-after** (`:5829`): a successful STIG apply arms `shutdown /r /f` ~1h out
  on self (delayed, so not mid-dispatch, but still an unexpected dispatcher reboot). *Spot-verified: the
  1h reboot is correctly gated on `$r.Success -and $DoReboot` - the read-back can't false-report success
  - only the self-exclusion was missing.*
- **P2 kb-install reboot-ENABLED** (`:5493`): with `noreboot` unchecked, the MSU/wusa fallback runs
  without `/norestart` and reboots self. *Spot-verified: MECM path doesn't force reboot; the MSU branch
  is the vector.*

Fix: drop the dispatcher via `Remove-WptSelfTargets` BEFORE fan-out in each, gated to the reboot-capable
sub-mode only (`forced` / `rebootafter` / `-not noreboot`) so non-invasive patch, no-reboot-after apply,
and reboot-suppressed KB installs are untouched - mirrors the existing guards. wpt 6.6.0->6.6.1; 3
regression tests (self-only target -> total=0/selfSkipped=1/Self-guard warn) added to
Wpt.SelfGuardAndClean.

## P3 documented (not fixed)
kb-install MECM match uses `$_.Name -like "*$kb*"` (unanchored substring) OR exact `ArticleID`. A
truncated KB token (e.g. `500` -> `KB500` -> matches `KB5001234`...) could select extra updates. Requires
malformed operator input; low value. A word-boundary match would remove it.

## Verified CORRECT (deep) - no action
- **Rollup/verdict honesty (KICKED/UNCONFIRMED class): CLEAN here.** fix-java counts both FIXED and
  NOCHANGE; app-action/sccm-install key on Triggered; a "Skipped: not applicable" returns Ok=$false
  (counted failure, not false green); bulk-patch only counts a trigger on ReturnValue 0/null; app-update
  audits Pending as Skipped. Bulk-scan renders a failed channel as literal "Error", not a silent 0.
- **Empty-set-treated-as-all: CLEAN.** ConvertTo-JanetHostList returns @() for empty; every action returns
  "No valid targets" on count 0; each self-guard branch returns on empty - none revert to "all".
- **reboot-schedule/abort pairing: CLEAN.** abort issues `shutdown /a` (cancels any pending shutdown,
  no task-name coupling to mismatch). Abort correctly does NOT self-guard (cancelling is non-destructive).
- **STIG read-back: CLEAN** (write+read-back in one scriptblock, -EA Stop, int64 compare of the exact
  written key; 1h reboot gated on verified success).
- **Pool source injection: CLEAN.** Only Test-WptHostReachable needs injection; all 8 call sites verified
  - the pools that call it inject it; the pools that don't, inline their own TCP reachability.
- **DNS-mismatch hard-abort** present on every destructive remote block.

## Verdict
wpt's verdict/state logic is sound; the one systemic defect (incomplete reboot self-guard coverage) is
closed - all 7 reboot-capable actions now drop the dispatcher. The correctness lens is now 3-for-3 across
the destructive orchestrators. Ledger row 34 added (Desktop WorkstationPatchingTool deferred). Suite 877/877.
