# Production Review - Loop 5 (Phase 2, cycle 3) - 2026-07-12

Audit of the loop-4 delta (acas Cycle-2: Java-remove profile + the new `Select-AcasNonSelfHosts` self-guard
mechanism) PLUS a CONCURRENT commit that landed on prod master from another session (77a7b1aa
`fix(logging): live usage Snapshots`, author bth0mp, touching Server.ps1/Logging.ps1). 3 reviewers:
(A) acas destructive self-guard gap + Cycle-2 soundness [Opus], (B) the concurrent logging change vs the
fail-closed gate [Opus], (C) full re-verify + suite [Sonnet]. Every P2 spot-verified.

**Rating: YELLOW.** No P1. One P2 (a pre-existing acas self-guard gap, found this cycle - the free-choice fix
target) + one P3. The concurrent logging change is CLEAN and did not disturb the gate. The Cycle-2 mechanism
is correct and non-regressive.

## Concurrent-work handling
A parallel session committed `77a7b1aa` to prod master (a live-usage-snapshot logging feature) interleaved
between this loop's two loop-4 commits. It is COMMITTED (not uncommitted), my loop-4 commits are intact, and
my loop-4 commit was scoped (never swept their files). Audited (reviewer B): self-contained, adds no HTTP
route, leaves the fail-closed gate byte-unchanged (Server.ps1:744-753), path-traversal-safe, CSV-injection
neutralized (`Protect-JanetWebCsvField`), no secret leak, lock-safe. **No findings.** All my subsequent commits
this cycle are scoped `git commit -- <paths>`.

## P2 (fix this cycle) - acas destructive actions can target the JANET dispatcher itself
The self-guard `Select-AcasNonSelfHosts` (`acas.psm1:1159`) early-returns the host list UNCHANGED unless the
profile is `ForbidSelf` (:1162) - and ONLY the loop-4 Java-Remove profile sets that flag. So:
- **`schedule-reboot` (:3034) - UNGUARDED (headline).** Builds targets and issues `shutdown /r /t 300` per host
  with NO self-drop. An operator who includes the dispatcher `shutdown /r`'s the JANET box -> the HttpListener
  dies mid-wave (server self-loss). Its SIBLING `reboot-selected` (:3274) DOES self-guard (drop+warn) - so this
  is an inconsistency, not an absence. *Spot-verified: :3034 no guard vs :3274 guard.*
- **`kb-install` (:3170) - UNGUARDED.** Windows KB servicing on the live dispatcher; MECM `InstallUpdates`
  (:2395) may reboot per deployment policy. P2.
- **App-Update patch paths (:2747/2863/2912/2983/3011)** - `Select-AcasNonSelfHosts` is a no-op for their
  (non-ForbidSelf) profiles, so a patch wave can force-close Office / restart Chrome-Edge / restart Java
  services / msiexec on the dispatcher. No OS reboot -> listener survives -> **P3** (app/service disruption).

**Fix (recommended, minimal, this cycle):** (1) add the direct `Test-AcasHostIsSelf` drop+warn (mirror :3274)
to `schedule-reboot` and `kb-install`; (2) remove the `ForbidSelf` early-return at :1162 so
`Select-AcasNonSelfHosts` drops self for ALL destructive update profiles (covers the 5 patch dispatchers at
once). Read-only paths (analyze, verify-post-reboot, verify-selected, kb-scan-findings, group-findings,
findings-for-host, list-profiles, preflight-services) do NOT call the guard and must stay self-inclusive.

## Cycle-2 (loop-4) verified sound
The Java-Remove alternate profile fails closed without the injected engine; `Select-AcasNonSelfHosts`'s early
return means every non-ForbidSelf profile + every pre-existing action is byte-for-byte unchanged; engine
source threaded through all 5 job-arg sites; Verify borrowed cleanly from the SC profile. Non-regressive.

## Desktop parity
Desktop ACAS (`ACAS Nemesis Tool_1.10.13.ps1`) heavily patches/reboots remote hosts (247 state-change hits)
with minimal self-guard (1 hit) and has NO concurrent WIP -> the same gap likely exists there and the mirror
is NOT blocked. Desktop mirror to be done this cycle (drop the local box from its patch/reboot waves).

## Fix order
1. P2: acas schedule-reboot + kb-install self-guard (mirror :3274) + broaden `Select-AcasNonSelfHosts`; version
   bump; tests. Desktop-mirror the same to ACAS Nemesis Tool.
Suite green + BOM per commit; scoped commits (concurrent session active).
