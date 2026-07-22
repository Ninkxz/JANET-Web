# JANET Web — design loop 90 (2026-07-22)

## Decision 1 — close the destructive-path safety gap (the cadence's explicit priority)
The loop-88 wpt deep-dive flagged (and I re-verified) that two DESTRUCTIVE workers lacked the wrong-box
(DNS-mismatch) guard every sibling carries: `WptCleanBlock` (cleanup-disk — deletes temp files, caches, and stale
user PROFILES via WMI `.Delete()`/CIM/takeown/rd/robocopy/ProfileList) and `WptCleanUserAppsBlock` (deletes
per-profile app binaries via takeown+remove). A stale DNS or a reused IP means the operator dials WS01, the session
lands on WS02, and profiles/binaries are deleted on the WRONG machine — irreversibly. This is the loop's
workstream; profile/binary DELETION is the highest-consequence unguarded destructive path in wpt.

## Decision 2 — mirror `WptPatchBlock`'s guard verbatim, first statement inside the try
The guard is copied from `WptPatchBlock` (`:2060`): before any deletion, `Invoke-Command { $env:COMPUTERNAME }`
compared to the dialed shortname; HARD ABORT on mismatch. Invariants identical to the siblings — an IPv4-literal
target skips the compare (`-notmatch '^\d{1,3}(\.\d{1,3}){3}$'` — no shortname/DNS indirection), an empty probe
proceeds (don't regress a readable-name failure into a false abort). Placed as the FIRST statement inside each
block's existing `try { … } finally { Remove-PSSession }` — before even the read-only free-space snapshot in
WptCleanBlock — so NOTHING runs on the wrong box, and the abort `return` runs the finally (session cleanup). The
abort sets `$r.Detail` (the blocks' error convention) → `DNS mismatch … ABORTED, nothing cleaned` / `… nothing
removed`, so the row renders a clean Failed with nothing deleted.

## Decision 3 — tests: replica-behavioral + static-presence (the kb-install guard convention)
`WptRebootBlock`'s DNS-guard test can execute the real block because it uses `Invoke-Command -ComputerName` (no
session). The clean blocks have a TCP-reachability pre-check + `New-PSSession` BEFORE the guard, so a fake hostname
returns 'Offline' before the guard ever runs — behavioral execution is fragile. So — matching the kb-install guard
(loop 86) and `PkginstallSecureboot.WrongBoxGuard` — the guard DECISION is tested via a verbatim replica function
(IPv4-skip / matching-shortname-case-insensitive / different-name / empty-probe) AND a STATIC assertion that BOTH
blocks contain the guard (the `$env:COMPUTERNAME` session probe + the `ABORTED, nothing cleaned`/`nothing removed`
returns) so a future removal is caught.

## Decision 4 — verify no collateral; the rest of the wpt backlog stays tracked
wpt 6.8.18 → 6.8.19; loop-89's 6.8.18 pin floored. Ran the wpt guard suite + the full suite. Remaining wpt
backlog: the freshness-only Oracle-Java verify (likely also inert — the loop-88 dead-`Get-Item.LastWriteTime`
class), the systemic dead-registry-mtime sweep (C2R verifies, reboot-pending age), and the bool-coercion sweep
(hardlock/rebootafter/noreboot raw `[bool]`). Each is its own loop.
