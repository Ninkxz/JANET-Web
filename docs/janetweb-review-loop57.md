# JANET Web — review loop 57 (2026-07-21)

Fable-inline synthesis over one Fable adversarial deep-dive worker on **secureboot** (the last un-dived
acting/hardening tool: enables UEFI Secure Boot via a SYSTEM scheduled task over WinRM + a read-only fleet scan).
Self-review of loop-56 → **GREEN**. Baseline: loop-56 authoritative **1433** (secureboot subset 35 green after fix).

## Self-review of loop-56 (remoteadmin -Last 1 result-binding) — GREEN
`-Last 1` always yields the worker's `return $r` (terminal → last stream object); empty output → `$null` →
handled at `:476`; a throw → catch at `:474`; `$res` is consumed only by `$emitResult`. The new stray-leak test
passed in the full 1433 run. Nothing to reopen.

## Workstream: Fable deep-dive on secureboot — core is fail-closed
The dive traced the enable payload → JSON result → row Status → audit, the scan probe → verdict → summary counts,
and the server destructive gate. **No P1.** Verified fail-closed: task Register/Start failure → `Error` (`:700-705`);
no-result = Timeout = Failure; corrupt/fieldless file = Error; C$-unreadable = Error ("may have run but could not be
read"); Dell null/nonzero Status → error, HP null Return fails `-eq 0` → error, Lenovo requires both set+save = the
string 'Success'; **no `[int]("0"+...)`/`-as [int]` coercions** (the one `[int]` scan cast sits in a try→'Unknown'
catch); payload switch-default books Error not Success; Unknown is a distinct hard-stop (Skipped-not-OK, itemCount 0).
Scan scores every failure away from compliant (OFFLINE / CHECK ERROR / BLOCKED / Unknown, all Scan-test-pinned).
Full safety stack on enable: confirm-word (view) + admin-session server gate + 50-host refusal + hostname allow-list
+ self-guard (all bound IPv4s + `127.*`) + wrong-box hard-abort *before* the payload drop + in-payload brick-safety
UEFI+GPT check. The guards backstop each other (a CNAME slipping the self-guard is caught by the wrong-box compare).

### Finding acted on — P2 stale-result replay (CONFIRMED, re-verified in-code)
`$script:SbeLiveWorker`: the result JSON is named `SecureBoot_<host>.json` — **hostname only** (`:505`), no per-run
nonce. The pre-run delete (`:594`) is `-EA SilentlyContinue` and never verifies success; the poll (`:627-631`)
accepts the **first** file that parses with a `SetResult` field. If a prior run's cleanup failed (stale
`SetResult=0, Error=''`) AND today's pre-run delete also silently fails, the first poll tick (~4s) reads the OLD JSON
→ books `Status='Success'` + `VulnPatched/Success/itemCount=1` even though today's task never ran (the real result is
written later and deleted unread in `finally`). Low trigger probability (two consecutive cleanup failures) but the
path is fully traced and the outcome is the exact false-clean class. **`$taskName` (`SBE_<random>`, `:1196`) is
already per-run unique and already names `$scriptFile` (`:510`)** — only the result file wasn't using it.

### Fix (secureboot 1.6.1 → 1.6.2)
`$resultFile = "SecureBoot_${comp}.json"` → `"SecureBoot_${comp}_${taskName}.json"` (`:505`). `$remotePath`,
`$uncPath` (poll read + `finally` cleanup), and the payload's baked `$ResultPath` all derive from `$resultFile`, so
one line propagates everywhere and makes a cross-run filename collision **impossible** — the poll can only ever read
this run's own result. Chosen over a delete-verify (fail-closed abort on a stuck stale file) because it eliminates
the shared-filename root cause structurally and has no clock/skew dependency. +3 tests (static analysis — the worker
is a module-less runspace scriptblock, not directly invokable without live SMB): resultFile references `$taskName`;
old hostname-only form gone; exact `1.6.2` pin (ConfirmWord's exact pin floored). secureboot set **35** green (was 32).

### Findings NOT acted on (ranked P3, tracked)
- **AlreadyPending re-books Success** (`:161-262` → `:718-721` → `:1263`): a re-run against an already-staged host
  books a fresh `VulnPatched/Success/itemCount=1` though this run wrote nothing. Fix later: map `AlreadyPending` →
  `Skipped` (bucket exists). *item 62.*
- **"Success"/"N enabled" wording = staged pending-reboot, not on** (`:718`, `:1315`): heavily mitigated (After
  column + audit detail carry "(pending reboot)"; confirm text says "PENDING A REBOOT"), but the bare enum + summary
  word "enabled" and the **Lenovo** read-back-reflects-staged case omit the pending marker. Fix later: unconditional
  "(pending reboot)" marker + "staged" wording. *item 63.*
- **`Get-SbeBool` fails open toward LIVE for `dry_run`** (`:1076-1082`→`:1155`): an unrecognized token → `$false` →
  live firmware write; only bites a direct API caller (view sends canonical). Fix later: strict `dry_run` parse. *item 64.*
- **Scan summary drops `Cancelled` rows** (`:1051-1057`): accounting gap, not false-clean (nothing marked
  compliant). Fix later: add `Cancelled` to the tally. *item 65.*
- **icacls lock on the password payload is best-effort** (`:601`): hardening only (self-delete + finally backstop).
  *item 66.*
- **Confirm-word is view-side only** (speculative): matches the suite convention (c2c 'FIX', remoteadmin 'RUN' too);
  accepted pattern, not a deviation. A server-side confirm param would close the last gap. *noted, not ranked.*

## SECRET parity
- **SECRET parity:** if a JanetSec secureboot fork exists it shares `$script:SbeLiveWorker` — mirror the per-run
  `$taskName`-based result filename so a stale prior-run JSON can't be replayed as this run's Success.
