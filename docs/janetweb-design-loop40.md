# JANET Web — design loop 40 (2026-07-21)

## Decision 1 — diversify to wpt; act on the cross-tool parity gap it exposed
Three straight acas-touching loops warranted rotating to wpt (the co-most-used tool). The dive's highest-value
immediate result wasn't a wpt bug at all — it was that acas *lags* a fix wpt already shipped: wpt's loop24 C2R
verify hardening (fresh AND scenario succeeded) has an exact counterpart missing in acas's Office C2R verify.
Porting a proven, already-tested pattern to close a confirmed HIGH-harm false-clean in acas is higher-value and
far lower-risk than opening a fresh wpt fix mid-dive, so that became the loop's fix.

## Decision 2 — the worker "stalled" (0 bytes / 30 min); I did the dive inline, then reconciled
The wpt worker's transcript file stayed 0 bytes well past the acas dive's ~5-min runtime, so I treated it as
stuck and did the lead-1 analysis inline (wpt's Chrome/Edge bump is NOT the acas degraded-sentinel defect — the
`$cur -and` guard + PENDING/Skipped handling make it fail-closed; only a downgrade is a residual). The worker
then completed (~7 min; the JSONL only flushes at the end) and independently confirmed exactly that lead-1
verdict, plus 11 more findings. Lesson: a 0-byte worker transcript is not proof of a stall — the flush is
terminal. I still lost nothing: the inline read and the worker agreed, and the inline read is what produced the
acas C2R port.

## Decision 3 — port wpt's helper shape verbatim for parity
`Get-AcasC2rVerified` is a line-for-line analogue of `Get-WptC2rVerified` (same params, same `$null`/`$false`/
success logic), and the acas test mirrors `Wpt.C2rVerify.Tests.ps1` case-for-case. Keeping the two tools'
C2R-verify verdicts identical means a future reviewer reads one and knows both, and the SECRET-parity port is
mechanical. The generated remote scriptblock mirrors it inline (module-less WinRM runspace), the established
pattern.

## Decision 4 — scope the fix to the C2R slice; rank the rest honestly
item35 (acas verify = mtime-recency) spans Office C2R + Chrome/Edge/Java/Store. Only the C2R key is provably
bumped on failed attempts (wpt's loop24 evidence + the worker's trigger), so only that slice is an unambiguous
false-clean; the others match wpt's own accepted mtime approach and stay ranked. And the wpt dive's 11 other
findings are ranked as items 40–50 rather than folded in — several are HIGH (the systemic "OK on trigger"
class, the unconditional verify Status, bulk-patch null-RV) and each deserves its own loop with in-code
re-verification first. A rich, honestly-ranked backlog is the dive's real product.

## Decision 5 — version + verification
A verify verdict that used to read Verified on a failed-but-fresh key now reads $false/$null — behavioral, so
acas 1.11.11 → 1.11.12, the loop-39 BumpVerdict exact pin → floor, the new C2rVerify test holds the exact pin.
Ran the acas verify/profile set (76 green) and grepped all tests for the touched symbols (`Get-AcasC2rVerified`,
`1.11.11`, `LastScenarioResult`) — the only other `1.11.11` hit is a KB number, a regex false-positive.
