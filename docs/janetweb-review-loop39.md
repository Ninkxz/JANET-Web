# JANET Web — review loop 39 (2026-07-21)

Fable-inline. Self-review of loop-38 → **GREEN**. Baseline: loop-38 authoritative **1318** green (confirmed).

## Self-review of loop-38 (acas reboot-selected audit) — GREEN
The fix changed one audit action `VulnPatched → TouchHost` at `:3630`. `TouchHost` is a valid audit-action
ValidateSet value already used by both sibling reboot arms; the row and RunAction are unchanged and nothing
branches on the VulnPatched-vs-TouchHost distinction for this arm. Scoped 69 + authoritative 1318 confirm no
breakage. Nothing to reopen.

## Workstream: close acas F4 / item36 — a degraded post-probe is no longer a confirmed "bump"
Rather than a fresh dive that might return GREEN, loop 39 closes a CONFIRMED false-clean the loop-38 acas dive
surfaced. It's the highest-harm of the ranked F2–F6 that's tractable without a per-profile redesign.

### Finding (CONFIRMED, MED-HIGH)
The acas update worker confirms a remediation by comparing the verify probe's version before/after the update:
`:2084` declared a `"bumped"` (→ OK → lights the PATCHED tile + books a **VulnPatched Success** audit) on ANY
`preV -ne postV` — a raw string inequality, not `[version]`, not directional. So a post-probe that **degraded**
to a sentinel it emits when it could NOT read a current version — `'error'` (a caught probe, e.g. Defender
`:204` / Store `:571`), `'n/a'` (a vanished Office Configuration key `:123`), `'not installed'` (`:146`/`:562`)
— or a numeric **downgrade**, was an inequality → booked as a confirmed patch. Trigger: a Defender update whose
post-verify throws internally returns `Version='error'`; `pre='1.401.x'`, `post='error'` → `"bumped"` → OK →
VulnPatched Success for a host whose patch state is actually unknown.

### Fix (fail-closed, pure helper + inline mirror)
New pure `Get-AcasBumpVerdict($PreV,$PostV)` (`:2361` area): returns `'unconfirmed'` when `PostV ∈
{error, n/a, not installed}` or when both parse as `[version]` and `postVer <= preVer` (downgrade / no forward
progress); `'confirmed'` otherwise. Deliberately **not** degraded / left confirmed: `'none'` (Log4j clean —
`pre=2.14 → post=none` is a real fix) and non-version **state transitions** (spec-exec `VULNERABLE/DRIFT →
COMPLIANT` doesn't parse as `[version]`, so it's untouched). The update worker runs in a module-less fan-out
runspace and can't call the helper, so it mirrors the same logic inline at `:2084`, comment-linked "keep in
sync"; on `'unconfirmed'` it returns a distinct `UNCONFIRMED:` string (amber, out of the ok/patched tally).
The caller has already ruled out `preV == postV` (the existing version-unchanged UNCONFIRMED at `:2076`).

### Why the scope is exactly this (and not F2)
The unambiguous core of the false-clean is a post-probe that *cannot confirm a forward version*. The three
degraded sentinels and a numeric downgrade are that, universally, with zero per-profile knowledge — safe to
guard globally. F2 (verify = mtime-recency: `Verified=$true` without comparing the required version) needs each
probe taught the finding's required version; it stays ranked (item35). F4 does **not** try to check the
required version — only that post reports a readable version that moved forward — so it can't regress the
non-version profiles.

### Version + tests
- acas **1.11.10 → 1.11.11** (behavioral: a degraded-post host that read OK now reads UNCONFIRMED).
- `Acas.BumpVerdict.Tests.ps1` (NEW, 11): degraded-post (`error`/`n/a`/`not installed`) and downgrade →
  unconfirmed; forward bump / install-missing / Log4j-`none` / spec-exec transition → confirmed; a static
  assert the worker mirror carries the degraded list + downgrade check; exact `1.11.11` pin. RebootAudit exact
  pin → floor.
- acas verify/profile set (BumpVerdict + Chrome/Edge/SpecExec/Log4j/RebootAudit/VerifyRowStatus/VerifyAndTargets
  /KbMatch/FixJava): **122** green — the profiles whose verify path this touches all pass, no real bump masked.
- Applied the loop-37/38 lesson: grepped all tests for `bumped`/`Get-AcasBumpVerdict`/`1.11.10` before
  finalizing; the only hits classify already-formed OK strings (downstream of the worker), unaffected.

## SECRET parity
- **SECRET parity:** the JanetSec acas fork shares the update worker's pre/post bump logic — mirror
  `Get-AcasBumpVerdict` and the inline degraded/downgrade guard at its equivalent of `:2084`.
