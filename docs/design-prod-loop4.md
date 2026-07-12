# Design - Prod Loop 4 (Phase-2 Cycle 2) - Java fix into ACAS Nemesis

## Goal
Give ACAS Nemesis a one-click **Remove Oracle/Sun Java** remediation for Java findings, driven by the SAME
shared engine (`modules\JanetWeb.javafix.psm1`) that c2c and wpt now use - no third copy of the logic.

## Context (acas as found)
acas has a **remediation-matching engine** (`modules\JanetWeb.acas.psm1` ~L1092): named profiles, each with a
`Desc` + a `Script` run per host, matched to ACAS/Tenable findings (by product pattern / plugin id) and
dispatched through the self-guarded `AcasUpdateWorker` runspace pool (`Test-AcasHostIsSelf` drops the
dispatcher before job-array build, ~L2937/L3177). It already ships an `'Oracle Java - Software Center'` profile
(~L258) that INSTALLS a patched Java via SCCM Software Center for "Oracle Java SE CPU vulnerabilities" (matches
`*Java*`/`*Oracle JRE*`, detects the JavaSoft registry keys). This design adds the REMOVAL path.

## Surface (`modules\JanetWeb.acas.psm1`)
1. **Import the shared engine** at module load (`Import-Module (Join-Path $PSScriptRoot 'JanetWeb.javafix.psm1')
   -Force`) and capture `$script:AcasJavaFixSrc = Get-JanetJavaFixSrc`, exactly as c2c/wpt do.
2. **Add a new remediation profile** `'Oracle Java - Remove (fix-java)'` (name TBD) to the profile table,
   mapped to the SAME Java findings the Software-Center profile matches (reuse its product patterns / the
   Oracle Java SE plugin-id set - study how the existing Java profile's finding->profile match works and mirror
   its mapping so the same findings surface this remediation as an option). Its `Script` dot-sources the
   injected `$AcasJavaFixSrc` on the target and calls `Invoke-JanetJavaRemediation` (the vendor-gated,
   Oracle/Sun-only removal) - returning acas's standard update-row shape. If the two Java profiles would
   collide on the same finding, make removal an explicit alternate (both selectable), not a silent override of
   the install path.
3. **Guard parity**: the new profile dispatches through the existing `AcasUpdateWorker` path, so it inherits
   `Test-AcasHostIsSelf` (dispatcher dropped) + the admin-session destructive gate (the acas remediation
   actions that run profiles are `destructive=$true`) + the wrong-box handling acas already has. Confirm the
   engine source is injected into the pool `InitialSessionState`/args so the worker can dot-source it (bare
   runspace, no module scope) - fail-closed if absent.
4. **Version-bump acas** 1.10.12 -> 1.11.0 (manifest + any internal version string).

## Risks / non-goals
- **Reuse, do not fork** - one shared engine; the vendor gate + strict-GUID guard live only in javafix.psm1.
- **Never remediate self** - the removal must ride acas's existing `Test-AcasHostIsSelf` dispatcher drop; a
  Java uninstall on the JANET host is forbidden.
- **Do not change the existing Software-Center profile** - the removal is ADDITIVE (an alternate remediation),
  not a replacement; operators keep the install-patched-Java option.
- Non-goal: changing acas's finding-import/matching heuristic beyond mapping the Java findings to the new
  profile. Live remediation needs a real host with Oracle Java -> pilot-pending; the vendor-gate logic is
  unit-testable offline (shared with c2c/wpt tests) and the profile wiring is testable via the manifest +
  self-guard.

## Test plan
- New acas tests (Pester 3.4, BOM): the new Java-removal profile exists + maps to the Java findings; its
  remediation Script references the shared engine (`Invoke-JanetJavaRemediation`); the dispatch drops the
  dispatcher (self-guard) before fan-out; acas manifest loads at 1.11.0. The shared vendor gate is already
  covered by javafix/c2c/wpt tests (one engine).
- c2c's + wpt's existing Java tests stay GREEN (shared engine unchanged). Full production Pester suite green.
- PS 5.1 parse-clean + UTF-8 BOM on acas.psm1.
