# JANET Web — review loop 27 (2026-07-21)

**Baseline:** 1235/1235 at loop-26 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-26 (`41d29ad` verify-row status, `97b254a` docs) — verdict GREEN (inline)
Read-only verify-branch classification change (stale/n/a → UNCONFIRMED prefix), pinned by the pure
`Get-AcasVerifyRowStatus` unit test + a static prefix assert; no destructive guard. Authoritative
1235/0-fail. GREEN.

## Workstream (roadmap item 21) → FIXED: acas kb-install inherits wpt's loop-22 hardening
The acas kb-install MECM remote scriptblock carried the byte-identical bugs wpt fixed in loop 22:
- **loose KB-match** (`JanetWeb.acas.psm1:2667, :2669`, pre-fix): `$_.Name -like "*$kb*" -or
  $_.ArticleID -eq ($kb -replace '^KB','')`. The `-like "*$kb*"` substring let a requested `KB5034`
  match an update named `...(KB5034123)` → the WRONG update triggered, the real KB marked handled, the
  MSU fallback skipped.
- **null-ReturnValue fail-open** (`:2670`, pre-fix): `if ($null -eq $rv -or [int]$rv -eq 0)` counted a
  null `InstallUpdates` return (a method that returned nothing) as a successful trigger.

**Fix** (acas **1.11.7 → 1.11.8**), porting the proven wpt loop-22 shape:
- Canonical `Test-AcasKbNameMatch` (`:2596`) — exact normalized ArticleID, or the Name's KB token
  bounded by a negative-digit lookahead `KB<num>(?!\d)` so a shorter KB can't prefix-match a longer
  article. The MECM scriptblock mirrors it inline as `$kbMatch` (runs over WinRM, can't call the fn —
  comment-linked); both `-like` sites now use `& $kbMatch`.
- Null-rv fail-close: `$null -ne $rv -and [int]$rv -eq 0`, with a null-safe `ReturnValue=<null>` in the
  rejection message.

No guard weakened (self-guard, reachability→FAIL, session-fail→FAIL untouched); 180 acas + FixVerify2 +
FixGuards tests green. `Acas.KbMatch.Tests.ps1` (11) mirrors the wpt KB-match test (bug case + boundary
+ normalization) + exact 1.11.8 pin (loop-26 VerifyRowStatus 1.11.7 exact → floor). `FixVerify2` gains
an acas NULL-ReturnValue case (`-Rv -1` sentinel → method result with no ReturnValue → FAIL, reported
`ReturnValue=<null>`), matching the wpt null-case added in loop 23. acas rv=5 still `^FAIL` + rejected.

## acas ↔ wpt kb-install parity — now aligned
Both kb-install workers now share: anchored KB-match (wpt loop 22 / acas loop 27), null-rv fail-close
(same), and honest status/label (wpt loop 23 / acas loop 25). The two sibling remediation paths are
consistent. Remaining acas items from the loop-25 deep-dive: 19 (schedule-reboot books VulnPatched at
schedule time — the last confirmed acas false-clean), 20 (SPECULATIVE default-open output).

## SECRET parity
- SECRET parity: the acas kb-install KB-match + null-rv — the JanetSec acas fork shares
  AcasKbInstallBlock; mirror `Test-AcasKbNameMatch` + the inline `$kbMatch` + the null fail-close.
- Carried (unexecuted): honest acas verify row + kb-install status (acas), honest M365 C2R verify +
  kb-install label + KB-match (wpt), SLA bucket, host-key fold, wrong-template hint, CSV-ingestion.
