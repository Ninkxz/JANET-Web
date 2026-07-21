# JANET Web — review loop 58 (2026-07-21)

Fable-inline. Self-review of loop-57 → **GREEN**. Baseline: loop-57 authoritative **1436** (secureboot subset 40 green after fix).

## Self-review of loop-57 (secureboot per-run result filename) — GREEN
`$taskName` is in worker scope (a param); `$remotePath`/`$uncPath`/the payload's baked `$ResultPath`/the `finally`
cleanup all derive from `$resultFile`, so the rename propagates to write + poll + cleanup consistently; `SBE_<random>`
is per-run so sequential/concurrent runs never collide. Static test confirms the naming; 1436 confirms no regression.
Nothing to reopen.

## Workstream: close item 64 — secureboot dry_run fails OPEN toward the LIVE write
A targeted improvement from the fresh loop-57 backlog, chosen because it's a **destructive-action fail-open** — the
one dive finding that touches the "destructive stays fail-closed" hard rule.

### Finding (CONFIRMED — re-verified in-code)
`Invoke-JanetToolAction` read the dry-run selector via the **shared** `Get-SbeBool` (`:1080`):
`$isDry = Get-SbeBool $Params['dry_run'] $false` (`:1159`). `Get-SbeBool` returns `true` only for
`{true,1,yes,on}` and **`false` for everything else** — so any present-but-unrecognized token (`'ture'`, `'dry'`,
`'y'`, a typo) → `$isDry=$false` → **LIVE firmware write** on a host the operator meant to preflight. Only bites a
direct API caller (the bundled view sends canonical values), but a destructive-mode selector must not fail open.
`Get-SbeBool` is **shared** by `attemptOffline` (`:937`) and `allowEmptyPassword` (`:1174`) where a `$false` default
is correct — so the fix must be at the `dry_run` call site, not the helper (false-sibling caution, loop-50/54 lesson).

### Fix (secureboot 1.6.2 → 1.6.3)
New dedicated `Get-SbeDryRunSafe`: the **live** path requires an *absent* value (the manifest's documented
`default=$false`, so a normal enable still runs) or an *explicit recognized false* token (`false/0/no/off`); any
present-but-**unrecognized** token resolves to **dry** (fail-safe). `$isDry = Get-SbeDryRunSafe $Params['dry_run']`.
`Get-SbeBool` untouched. +5 behavioral tests (pure helper — the preferred test type): absent/empty → live; explicit
false tokens → live; explicit true tokens → dry; **unrecognized token → dry** (the fix; `Get-SbeBool` would have gone
live). Exact `1.6.3` pin lives in ConfirmWord (enable-safety file); the loop-57 Scan pin (1.6.2) migrated to a floor.
secureboot set **40** green (was 35).

## secureboot backlog after loop 58
Items 62/63/65/66 remain (P3): AlreadyPending re-books Success (62), staged-vs-enabled wording (63), Cancelled tally
gap (65), best-effort icacls (66). None is a hard firmware false-clean; 62 is the next-most-valuable (audit honesty).

## SECRET parity
- **SECRET parity:** if a JanetSec secureboot fork exists it shares the enable dry-run parse — mirror
  `Get-SbeDryRunSafe` so an unrecognized `dry_run` token stays DRY instead of silently going live.
