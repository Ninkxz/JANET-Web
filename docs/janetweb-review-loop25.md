# JANET Web — review loop 25 (2026-07-21)

**Baseline:** 1221/1221 at loop-24 close (authoritative, 0 fail). Fable-inline + one parallel Fable
worker. Local-only commits.

## Self-review of loop-24 (`be80c78` M365 C2R verify, `39b8b23` docs) — verdict GREEN (inline)
Read-only verify-path change (registry-read verdict), no destructive guard, tested at every boundary,
authoritative 1221/0-fail. GREEN.

## Fresh deep-dive: acas remediation false-cleans (parallel Fable worker)
Diversified off wpt (3 loops) to acas, the remediation ENGINE, with a bounded Fable worker on ONE
question: where does a not-actually-remediated host get counted/displayed as patched? I verified every
finding in-code before acting. The worker also usefully REFUTED a standing suspicion (roadmap item 6).

**Refuted / honest (confirmed by re-read):**
- **item 6 (SKIP counted as OK) — REFUTED for the acas tally.** `AcasOkOf` (`:2354`) does return true
  for `SKIP*`, but its only consumer checks `$isSkip` FIRST (`:2473`), so skips land in skipCount with
  a 'Skipped' audit (itemCount 0), never in okCount. No false-clean today — the predicate is a loaded
  gun if ever reused raw, but not fired. Item 6 updated.
- Unreachable / session-failed / timed-out hosts are FAIL everywhere (never folded into success);
  the app-update profile engine is genuinely fail-closed (self-classified FAIL/SKIP/UNCONFIRMED is
  authoritative; version-unchanged-after-trigger → UNCONFIRMED); run-summary excludes skips.

## Workstream → FIXED: acas kb-install status honesty (the acas sibling of wpt loops 22-23)
The kb-install worker's status (`:2663`, pre-fix) was
`if (errors>0 AND installed=0 AND skipped=0){'FAIL'} elseif(installed=0 AND skipped>0){'SKIP'} else{'OK'}`
with `$installed = mecmInstalled + msuInstalled` and `$mecmInstalled = $mecm.Triggered` (`:2638`).
Three CONFIRMED false-cleans, all here:
- **MECM async trigger → OK** — an accepted `InstallUpdates` trigger (the async install can fail later)
  set `installed>0` → `OK` → okCount++, `VulnPatched` Success audit, PATCHED stat card. (= wpt item 14.)
- **UsoClient fire-and-forget → OK** — the usoclient path tracked nothing (installed=0, skipped=0,
  errors=0) → fell to `else{'OK'}`. A pure fire, exit never checked, booked patched.
- **partial failure → OK** — `FAIL` required `installed=0`, so any confirmed install masked a real
  error (KB1 installed, KB2 MSU exit 1603 → OK with the failure buried in Detail).

**Fix** (acas **1.11.5 → 1.11.6**): pure canonical `Get-AcasKbInstallStatus` (`:2588`) — any error →
`FAIL` (never masked by a partial install); a MECM trigger or UsoClient fire with no confirmed install
→ `UNCONFIRMED` (AcasOkOf treats `UNCONFIRMED*` as NOT ok, so it's amber and OUT of the OK/patched
tally); a confirmed MSU exit-0 install → `OK`; only skips → `SKIP`. The worker mirrors it inline (runs
in a `CreateDefault` module-less runspace, can't call the fn — comment-linked), with a `$usoTriggered`
flag for the fire path. No guard weakened (self-guard, DNS wrong-box, reachability→FAIL untouched);
163 acas + FixVerify2 + FixGuards tests green.

`Acas.KbInstallStatus.Tests.ps1` (9) pins every outcome (trigger→UNCONFIRMED, uso→UNCONFIRMED,
MSU→OK, mixed→UNCONFIRMED, error-masks-nothing→FAIL, skip→SKIP, nothing→SKIP) + the exact 1.11.6 pin
(EdgeProfile 1.11.5 exact → floor). `FixVerify2` acas rv=0 expectation corrected from `^OK` to
`^UNCONFIRMED` — it had pinned the false-clean.

## Ranked, not fixed this loop (new items 18-21)
- **18 (HIGH)** — acas Verify/dry-run rows light the PATCHED stat card, INCLUDING `[stale]`
  (still-vulnerable) hosts: the verify branch (`:1941`) returns `"v=.. last=.. [stale].."` with no
  FAIL/UNCONFIRMED prefix → classified OK → `stat.patched++` (acas.view.js:742). Verify is diagnostic;
  it must not inflate patched. Fix: classify verify from the probe's `Verified`/stale flag, or stop
  feeding verify rows into `stat.patched`.
- **19** — `schedule-reboot` books `VulnPatched` Success at SCHEDULE time (`:2127`, fan-out `:3314`),
  before the (abortable, 5-min-out) reboot happens; `verify-post-reboot` exists and is honest, so book
  `VulnPatched` from THAT, and audit scheduling as `RebootScheduled`/`TouchHost`.
- **20 (SPECULATIVE)** — default-open classification: empty/first-item worker output → `'OK (no
  output)'` (`:2464`); no reachable leak in shipped workers, but a future profile emitting stray output
  gets booked patched. Default unknown/empty → UNCONFIRMED; read the LAST output item.
- **21** — acas kb-install shares wpt's loop-22 bugs UNFIXED: loose `-like "*$kb*"` KB-match (`:2631/2633`)
  and null-ReturnValue-as-success (`:2634`). Port `Test-WptKbNameMatch` anchoring + the null fail-close.

## SECRET parity
- SECRET parity: the honest acas kb-install status — the JanetSec acas fork shares AcasKbInstallBlock;
  mirror `Get-AcasKbInstallStatus` + the inline status + `$usoTriggered`.
- Carried (unexecuted): honest M365 C2R verify, honest kb-install label + KB-match (wpt), SLA bucket,
  host-key fold, wrong-template hint, CSV-ingestion + routing tests, and everything earlier.
