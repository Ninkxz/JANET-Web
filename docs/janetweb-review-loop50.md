# JANET Web — review loop 50 (2026-07-21)

Fable-inline. Self-review of loop-49 → **GREEN**. Baseline: loop-49 authoritative **1401** green (confirmed).

## Self-review of loop-49 (certdeploy REJECTED-anchor honesty) — GREEN
`Get-CertDeployResultToken` emits REJECTED on `Rejected>0` at the right precedence; the status switch →
`REJECTED (non-CA)`, level error, summary bucket, audit default→Failure — all links verified; the corrected
CaValidation tests pass. 73 certdeploy + 1401 confirm no regression. Nothing to reopen.

## Workstream: close wpt item44 — clean-user-apps is Success only when it actually removed what it found
Rather than a fresh dive on a smaller tool, I closed a still-open MED-HIGH item from the loop-40 wpt dive (wpt is
the most-used tool; items 43–51 remain).

### Finding (CONFIRMED — re-verified in-code)
`WptCleanUserAppsBlock` counts `$found` app-binary paths that existed per user profile and `$removed` that were
actually deleted; a locked/running app's `Remove-Item` throws → ERR event, `$removed` **not** incremented
(`:3625-3626`). The row Status was set **unconditionally** to `'Success'` on a live run (`:3655`, was `:3601`).
So a host where every deletion FAILED — Chrome running in all profiles → `found>0, removed=0` — read Status
Success, satisfied the OkOf, and booked a **VulnPatched Success** audit while nothing was removed. The Detail
("0 binary path(s) removed") was honest; the status/tally/audit were the false-clean.

### Fix (wpt 6.8.11 → 6.8.12)
New pure `Get-WptCleanStatus(Found, Removed, DryRun)`: dry → Dry Run OK; nothing found or all removed → Success;
some removed → **Partial**; found>0 but none removed → **Failed**. The module-less worker mirrors it inline. The
action's OkOf already accepts only `Success`/`Dry Run OK` and the fan-out audits a non-ok host as Failure, so
Partial/Failed drop out of the clean bucket **automatically** — no OkOf/audit change needed. Detail now shows
"N of M removed".

### The sibling that is NOT the same bug
The static assert surfaced a second unconditional-Success line (`:3250`) — but that's the disk-cleanup /
maintenance worker (Temp/Cache free + best-effort stale-profile removal). Its "Success" legitimately means the
maintenance ran; a locked profile it couldn't delete is an expected best-effort skip, not a failure — applying
the clean-user-apps logic there would *false-FAIL* a successful temp/cache cleanup. So the fix is scoped to
clean-user-apps and the assert made specific. (A totally-failed maintenance run reading Success is a separate,
nuanced question — noted, not ranked, since its Success semantics differ.)

### Version + tests
- `Wpt.CleanStatus.Tests.ps1` (NEW, 8): the pure status at every branch (found>0/removed=0 → Failed [the fix],
  partial, all-removed, nothing-found, dry) + static asserts the OkOf accepts only Success/Dry Run OK and the
  worker gates on removed-vs-found; M365Update exact pin → floor.
- wpt clean/M365/guard/verify set **40** green; grepped all tests — the only other reference (SelfGuardApply)
  shims the whole block, unaffected.

## Remaining wpt backlog (from the loop-40 dive)
item43 (Java SC mtime verify, HIGH — needs a version target), item45 (verify-and-clean reg-key self-blinding,
MED), item46 (Adobe GUID, MED), item47 (browser-client mtime, MED), item48/49/50 (LOW), item51 (trigger≠patched,
HIGH).

## SECRET parity
- **SECRET parity:** the JanetSec wpt fork shares `WptCleanUserAppsBlock` — mirror `Get-WptCleanStatus` and the
  inline removed-vs-found status gate.
