# Production Review - Loop 19 (Phase 2, cycle 17) - 2026-07-13

Value pick (design-loop19.md): the same deep CORRECTNESS lens that found a real c2c P2 in loop 18,
applied to `acas` (3384 lines, v1.11.1) - the ACAS Nemesis fleet patch/reboot/KB orchestrator. One Opus
reviewer, correctness-focused. Every P1/P2 spot-verified by me against the code. Both backlogs
operator-deferred; acas is committed (non-colliding).

**Rating: YELLOW -> GREEN after fix.** Host targeting, KB per-host grouping, verify-post-reboot honesty,
Java source-injection, and self-guard ordering all VERIFIED CORRECT. Two real bugs fixed (a false-green
row cell + an empty-filter-reverts-to-all reboot). Suite 874/874.

## P1 FIXED - UNCONFIRMED update rows displayed a false green "OK" (commit 7969703)
The async updaters (Chrome/Edge/Office `/ua`) trigger a BACKGROUND update, so the on-disk version does
not change during the WinRM session and the worker emits a distinct `UNCONFIRMED: ...` token.
`$script:AcasOkOf` (`:2120`) excludes UNCONFIRMED from the OK count (intended amber, per the `:2118-19`
comment) - but both row builders (`$script:AcasUpdateRowOf :2131`, inline run-vulnerability `rowOf :2937`)
only branched `FAIL*`/`SKIP*`/else->`OK`, so UNCONFIRMED fell through to a green `OK`. Effect: on the
COMMON Chrome/Edge/Office patch path the per-host row cell showed `OK` (green) while the run banner said
"0 ok, N failed" and every audit row was `Failure`. The per-row verdict - what the operator scans to call
a host done - was a false "OK". *Spot-verified: :2120 excludes UNCONFIRMED; :2131/:2937 fell through to
OK.* Fix: add the `UNCONFIRMED` branch to both row builders so the cell matches the count predicate.
Bounded (the aggregate count + audit were already honest - only the display cell lied).

## P2 FIXED - reboot-selected reverted to ALL group hosts on an all-empty filter
`reboot-selected` (`:3281-84`) applied its host-subset filter only `if ($allow.Count -gt 0)`. A non-empty
`hosts` filter whose tokens ALL canonicalize to empty (blank/garbled) left `$allow` empty -> filter
skipped -> `$targets` stayed the group's FULL host union -> a destructive reboot of every affected host,
not the operator's intended subset (the empty-set-treated-as-all pattern, on a reboot). *Spot-verified
against the correct sibling patch-selected (`:2744-48`), which applies the filter unconditionally and
short-circuits on empty.* Fix: apply the intersection unconditionally when `hosts` is provided, so an
empty result falls through to the existing No-targets return (`:3294`). The reboot self-guard still runs
after, but now the set is correctly bounded to the operator's subset.

## P3 documented (not fixed)
A KB matched in MECM but whose `InstallUpdates` is rejected (`Triggered=0`) stays in `$handled`, so the
uploaded-.msu fallback is never tried for it (`:2400-07`). Reported honestly as `FAIL` (not a false
success) - just a missed fallback retry. Basing `$handled` on `Triggered>0` would recover it; low value,
left as-is.

## Verified CORRECT (deep) - no action
- **Host targeting** derives from the CSV finding set for every auto path; every empty target list returns
  early (6 sites) rather than fanning out to all. No cross-product host merge in the rollup. Hostname
  canonicalization consistent across import/targeting/self-guard/wrong-box guard.
- **KB per-host grouping** cannot cross-assign (ordered `$byHost`, each job carries its own `$kbArr`);
  ArticleID/Name match can't hit a wrong KB (KBs normalized to `KB\d{6,8}`); `noreboot` honored on every
  install path.
- **verify-post-reboot is honest**: unreachable-after-10-min -> FAIL, still-pending -> FAIL, timeouts ->
  FAIL; never reads as success.
- **Java-engine pool-runspace injection complete + fail-closed** (all 5 dispatchers pass `AcasJavaFixSrc`;
  worker aborts FAIL if a NeedsJavaFix run lacks the source). Profile/Verify scripts are self-contained
  literal text. The known injection gotcha is clean.
- **Self-guard ordering correct**: self dropped BEFORE the job array in schedule-reboot/reboot-selected/
  kb-install and via Select-AcasNonSelfHosts in all ForbidSelf paths. No false-success from a failed
  profile script; SKIP classified before OK so a no-op is never audited as a patch.

## Verdict
acas core correctness is sound: it cannot reboot/patch a host not on a finding (targeting verified), it
cannot false-report a reboot as verified, and the source-injection gotcha is clean. Two real display/
targeting bugs fixed. Ledger rows 32-33 added (Desktop ACAS Nemesis Tool deferred). Suite 874/874.
