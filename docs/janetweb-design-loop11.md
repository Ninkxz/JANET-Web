# JANET Web — design loop 11 (2026-07-20)

## Decision 1 — deep-dive the last large unreviewed destructive tool (winupgrade)
Ten loops in, the destructive surface is nearly all reviewed. winupgrade was the biggest
remaining gap: 9 destructive actions, feature-update reboots, DISM CAB push — high blast
radius. Reviewing it GREEN meaningfully completes the destructive-tool coverage. (It also
directly tested the loop-10 audit's winupgrade "YES" row, which the sweep asserted but I
hadn't independently deep-verified.)

## Decision 2 — accept the winupgrade DISM P3 rather than manufacture a change
Opus's one winupgrade finding (DISM `/PackagePath:"$cab"` string interpolation) is NOT
exploitable: the leaf is `Split-Path -Leaf` of a `Test-Path`-verified file, and NTFS
filenames cannot contain `"`. The "fix" (discrete argument array) isn't even available on
PS 5.1 — `ProcessStartInfo.ArgumentList` is .NET Core only; the alternative (rewrite to the
call operator) is a non-trivial change to a working destructive path for zero real gain.
ponytail: don't touch working destructive code to guard against a platform-impossible input.
Documented reviewed-clean instead.

## Decision 3 — the loop's code change is the coercion fix, because it's the one REAL item
When both deep-dives come back GREEN on well-tested tools, the disciplined move is NOT to
invent a change — but the loop-10 self-review surfaced a genuine (if narrow) trust-boundary
bug: raw `[bool]$Params['dryrun']` mis-coerces the STRING `'false'` to `$true`. For
clean-user-apps that flips a live delete to a dry no-op AND skips the live-only self-guard.
ponytail explicitly does NOT simplify away input validation at trust boundaries, and the
`/api` dryrun param is exactly that (it selects a destructive vs preview mode). The fix uses
an EXISTING coercer (`ConvertTo-WptBool`) — no new infra, minimal diff. That is a real fix,
not a manufactured one.

## Decision 4 — fix both dryrun sites, not just the self-guarded one
`clean-user-apps` (self-guarded) and `cleanup-disk` (benign-on-self, not self-guarded) share
the identical raw-`[bool]` pattern. Fixing only the self-guarded one would leave the same
coercion bug in its sibling and re-create the inconsistency the loop-10 audit was about.
Both go through `ConvertTo-WptBool`.

## Decision 5 — the UI never hits this, but the boundary should still be robust
The web UI sends JSON booleans (real `[bool] $false`), so this bug is unreachable from the
SPA. It's fixed anyway because the `/api` surface is the documented execution boundary and a
future non-UI caller (script, test harness, another tool) sending `'false'` should get LIVE,
not a silent dry no-op. Robust-at-the-boundary over relies-on-the-current-caller.

## Versioning
wpt `6.8.4 → 6.8.5` (behavioral: dryrun coercion). `Wpt.SelfGuardApply` holds the exact pin
(6.8.5). No winupgrade version change (reviewed-clean, no code change).
