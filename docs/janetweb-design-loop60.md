# JANET Web — design loop 60 (2026-07-21)

## Decision 1 — pivot to a fresh destructive tool, pick the pure false-clean
secureboot's audit-honesty items are closed, so this loop pivots off it. reports is the biggest un-dived tool but is
7,487 lines with host-key normalization already heavily test-pinned (4 host-key test files) — too broad and largely
worked. pkginstall is the most substantial un-dived *destructive* tool (arbitrary software fleet-wide) and a well-
sized single-worker target. The dive returned three real findings; I took P2-2 (the 1638 false-clean) because it's
the campaign's purest class — a `VulnPatched/Success` audit for a host the installer never touched — fully contained
in the module and cleanly pinnable, over P2-1 (narrower trigger) and P2-3 (a UI+module confirm-word, a separate unit).

## Decision 2 — 1638 is neither success nor failure: it's Skipped
msiexec 1638 = "another version already installed"; the install did not run. The old code called it
`AlreadyCompliant` and folded it into Success — asserting a compliance it never checked (there is no installed-
ProductVersion comparison anywhere in the module). The honest state is the same one loop 59 landed for secureboot's
already-staged host: *we did nothing this run and can't confirm the target is compliant* → **Skipped**, itemCount 0,
not a Failure (nothing broke) and not a Success (nothing was patched, and it may still be vulnerable).

## Decision 3 — reuse the existing skip machinery, fix at the aggregate + harvest
The harvest already has a three-way ok / `Deferred`(→Skipped) / fail(default) shape with a live `$skipCount` and a
`Skipped` audit bucket (exactly like loop 59's classify). So the fix is: give the all-1638 host a distinct status
`AlreadyInstalled`, and add one branch each to the harvest count switch (`→ $skipCount`), the audit switch
(`→ 'Skipped'`), and the log-level ternary (`→ warn`, so it isn't logged red as an error). I verified the harvest's
`itemCount = Success ? 1 : 0` gate means a Skipped audit automatically books itemCount 0 — no separate change needed.

## Decision 4 — split the all-1638 case out, keep the mixed case Success
The aggregate set `$res.Status='Success'` unconditionally at the top of the `failCount=0` branch, then refined the
reason. I split the all-refused case (`successCount=0 && installedCount==totalCount`) into its own `elseif` *before*
that, setting `AlreadyInstalled`. A **mixed** wave (some MSIs installed, some 1638) stays `Success` deliberately —
real installs happened, so the host genuinely had a patch action; the 1638 members are surfaced in the reason
("N already installed, version unverified") rather than claimed compliant. The pure false-clean is the all-1638 host;
over-reaching to fail/skip a host that did install real packages would be a new inaccuracy.

## Decision 5 — static analysis, matched to inline runspace logic; version
The per-MSI mapping and the aggregate live inside `$script:RpiDeployHostScript`, a module-less runspace scriptblock
added via `AddScript` and not invokable without live WinRM (the loop-57/59 constraint; the SelfGuard test only
exercises the pre-fan-out self-target short-circuit). So the regression test is static analysis of the whole chain:
all-1638 → Status `AlreadyInstalled`, harvest → `$skipCount`, audit → `'Skipped'`, and the old "treated as already
compliant" wording removed. Because an all-1638 host's audit moves from Success/itemCount-1 to Skipped/itemCount-0,
this is behavioral: pkginstall 2.5.8 → 2.5.9, the newest bump's file (MsiList) holds the exact pin and the SelfGuard
pin floors. P2-1/P2-3/P3-4 are ranked items 68/69/70.
