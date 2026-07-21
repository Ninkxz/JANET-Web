# JANET Web — review loop 26 (2026-07-21)

**Baseline:** 1230/1230 at loop-25 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-25 (`9203148` acas kb-install status, `d387f55` docs) — verdict GREEN (inline)
The trigger→UNCONFIRMED status change is exercised end-to-end by FixVerify2's shim (rv=0 now
`^UNCONFIRMED`) and the pure `Get-AcasKbInstallStatus` unit test; the destructive guards were untouched
and the 163-test acas+FixVerify2+FixGuards run was green. Authoritative 1230/0-fail. GREEN.

## Workstream (roadmap item 18, HIGH — top remaining acas false-clean) → FIXED
"Verify Selected" / "Verify" is a read-only dry-run ("check current state, change nothing"), but its
result rows flow through the SAME run binder as patching, and that binder lights the PATCHED stat card
for any row whose Result is OK (`acas.view.js:742` `if (res === 'OK') { stat.patched++ }`). The verify
branch (`JanetWeb.acas.psm1:1947`, pre-fix) returned `"v=$ver last=$last [$flag]$detail"` with NO
status prefix — `$flag` ∈ fresh/stale/n/a — so `AcasUpdateRowOf` (`:2367`, classifies by leading token)
made Result `OK` for EVERY reachable host, including `[stale]` ones where `Verified=$false` means the
host is still on the OLD, vulnerable version. Running a diagnostic Verify counted still-vulnerable hosts
as **patched** — a false-clean, and the highest-harm one left from the loop-25 acas deep-dive.

**Fix** (acas **1.11.6 → 1.11.7**): pure canonical `Get-AcasVerifyRowStatus -Verified` (`:2359`) —
`$true` (fresh/current) → `OK` (legitimately verified good); `$false` (stale) or `$null` (indeterminate)
→ `UNCONFIRMED`. The verify branch mirrors it inline (runs in a module-less runspace, can't call the fn
— comment-linked): `$prefix = if ($ver2 -eq $true) { '' } else { 'UNCONFIRMED ' }`, so a non-fresh row
becomes `"UNCONFIRMED v=.. [stale].."` → `AcasUpdateRowOf` Result `UNCONFIRMED` → amber grid row AND out
of the patched tally (AcasOkOf treats `UNCONFIRMED*` as not-ok). One module-side change fixes both
surfaces; the Detail still shows the version + `[stale]` so the operator sees the state.

Read-only verify path — no destructive guard involved. All 156 acas + FixVerify2 tests green.

`Acas.VerifyRowStatus.Tests.ps1` (5) pins the verdict (fresh→OK, **stale→UNCONFIRMED** the false-clean
fix, n/a→UNCONFIRMED) + a static assert the verify branch carries the `'UNCONFIRMED '` prefix + the
exact 1.11.7 pin (loop-25 KbInstallStatus 1.11.6 exact → floor).

## acas false-clean status (from the loop-25 deep-dive)
Fixed: kb-install trigger/partial (loop 25), verify-inflates-PATCHED (this loop, item 18). Refuted:
item 6 (SKIP-as-OK). Remaining: item 19 (schedule-reboot books VulnPatched at schedule time),
item 20 (SPECULATIVE default-open output), item 21 (acas kb-install KB-match + null-rv, wpt loop-22
siblings). The acas remediation-tally surface is now honest on its two highest-harm paths.

## SECRET parity
- SECRET parity: the honest acas verify row — the JanetSec acas fork shares the verify branch +
  AcasUpdateRowOf; mirror `Get-AcasVerifyRowStatus` + the inline UNCONFIRMED prefix.
- Carried (unexecuted): honest acas kb-install status (loop 25), honest M365 C2R verify + kb-install
  label + KB-match (wpt), SLA bucket, host-key fold, wrong-template hint, CSV-ingestion + routing.
