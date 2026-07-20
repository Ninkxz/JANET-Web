# JANET Web — review loop 2 (2026-07-20)

**Baseline:** loop-1 close at `d584aee`; targeted re-verify 122/122; the full-suite
baseline pass raced this loop's edits (mixed-state) — the post-change clean pass is
the authoritative count (see ledger).

## Opus adversarial self-review of loop-1 commits (02ffc03, 8e283ae) — verdict GREEN

No P1/P2. Checked-clean (on record): Script scriptblock→string→scriptblock
round-trip through `$script:AcasUpdateWorker` (extract `JanetWeb.acas.psm1:1908`,
rehydrate `:1962`; nested `$getPv` survives, no `$using:`, no here-strings);
passthrough operator precedence is the correct per-term `-like` chain (`:2057`);
every result-string consumer (`AcasUpdateRowOf` `:2365/:3171`, `AcasOkOf` `:2354`,
`$isSkip` harvest `:2473`, marker parsers) classifies the new shapes identically;
no caller depended on FAIL-rewrap-as-UNCONFIRMED; **mid-flight credential capture is
safe** — tool workers get the PSCredential by reference at dispatch
(`JanetWeb.Server.ps1:980/:983` `.AddArgument($state.Cred)`), background runspaces
cannot see `$state`, and the listener loop is serial, so End Session's null cannot
reach an in-flight destructive run; `setCred` (account switch) keeps the ack — only
the explicit Clear button forces a fresh ack; UI strips repaint via the onChange
listeners; disarm fires only on the success path after notes are recorded.

P3 notes (no code change):
- **P3-1** `'/installsource scheduler'` as one arg element with an embedded space —
  byte-faithful to the field-proven wpt profile; `/installsource` is telemetry-only.
  Kept for parity (Edge port uses the same form).
- **P3-2** exact-version pin brittleness — already resolved this loop: old acas pins
  converted to floor asserts (`-ge`), matching the 2026-07-16 wpt precedent.
- **P3-3 (pre-existing)** `AcasOkOf` books `SKIP*` green — consistent convention
  (nothing-to-remediate ≠ failure) but run-all "patched" tallies include SKIPs.
  Noted for a future reporting-honesty pass if the operator wants SKIP split out.

## Sonnet mechanical re-verify of loop-1 fixes — all 5 checks PASS

122/122 across 10 targeted suites (incl. Server.Gate 9/9, Server.PathTraversal 9/9);
BOM `EF BB BF` + 0 parse errors on all 6 touched scripts; destructive-gate patterns
intact and strictly tightened (`Select-AcasNonSelfHosts` × 5 call sites, server gate
`:807` requires ack+cred, session/start still needs an explicit ack body); no
cert-extension files in any loop-1 commit; diffs ASCII-only.

## Workstream: roadmap item 1 — Edge always-OK Scripts — **CLOSED** (`3dea8b8`)

`'Microsoft Edge - Update'` in BOTH `JanetWeb.wpt.psm1` (was `:1121`) and
`JanetWeb.acas.psm1` (was `:293`) fired `MicrosoftEdgeUpdate.exe /ua` and returned
`OK (Edge update triggered, exit N)` unconditionally. Both ported to the honest
shape: EdgeUpdate policy pre-check (`UpdateDefault`/`Update{56EB18F8-...}` = 0 →
FAIL), `edgeupdate` service check, exe-first trigger (both Program Files locations;
`MicrosoftEdgeUpdateTaskMachineUA*` task fallback — Edge has no GoogleUpdater-style
migration, so exe-first is the canonical order), 90s before/after version poll,
staged `new_msedge.exe` detection. wpt speaks `PENDING*` (native amber), acas speaks
`UNCONFIRMED*` (a raw PENDING books green through `AcasOkOf` — same boundary rule as
the loop-1 Chrome port, pinned by test). wpt **6.8.0→6.8.1**, acas **1.11.4→1.11.5**.
Regression: `Wpt.EdgeProfile.Tests.ps1` (12) + `Acas.EdgeProfile.Tests.ps1` (17);
targeted wpt+acas suites 139/139 green.

## SECRET parity
- SECRET parity: honest Edge Script for JanetSec wpt+acas forks (rides with the
  loop-1 Chrome/worker-passthrough parity item; adjust FAIL routing — no SCCM on
  SIPR, so point blockers at the WinRM Install-KB / package path instead of
  Software Center).
- SECRET parity: (carried from loop 1) session disarm + honest Chrome + worker
  passthrough — still not executed.
