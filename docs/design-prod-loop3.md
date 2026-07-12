# Design - Prod Loop 3 (Phase-2 Cycle 1) - Java fix into WPT via a shared engine

## Goal
Give the Workstation Patching Tool a first-class **Fix Java** remediation, reusing c2c's already-hardened,
vendor-gated (Oracle/Sun-only) Java removal logic WITHOUT copy-pasting it. One shared engine, two callers.

## Why a shared engine (not copy-paste)
c2c's Java remediation (the `fix-java` pillar) is a security-critical path: it was hardened in the audit with
a **vendor gate** (only remove JavaSoft residue when a matching Oracle/Sun-published Uninstall entry exists,
`(?i)oracle|sun microsystems`) and a **strict-GUID msiexec** guard (`^\{[0-9A-Fa-f-]+\}$`). Duplicating it into
wpt would fork the security logic - a future fix to one wouldn't reach the other. Extract ONE copy.

## Surface
1. **Extract the Java-removal logic into a shared, POOL-INJECTABLE source** in `modules\JanetWeb.c2c.psm1`
   (or a small shared module both import). Both c2c and wpt fan work into a `[runspacefactory]` pool that has
   no module scope, so the shared logic must be an injectable `$script:JavaFixSrc`-style source string (the
   established `$script:*Src` idiom) that each worker dot-sources - AND callable in module scope for tests.
   Define `Invoke-JanetJavaRemediation` (name TBD) that takes the same inputs c2c's fix-java uses and returns
   the same result rows. c2c's existing `fix-java` pillar is refactored to call this shared function (via its
   injected source) - its BEHAVIOR must be byte-identical (the vendor gate + strict-GUID guard preserved,
   verified by c2c's existing tests staying green).
2. **Wire a new wpt action `fix-java`**: manifest entry `destructive=$true`; dispatcher applies the SAME guard
   parity as wpt's other destructive host actions - `Remove-WptSelfTargets` (drop the dispatcher) BEFORE fan-out
   + a typed-confirm gate matching wpt's convention. The worker dot-sources the shared `$script:JavaFixSrc` and
   runs the remediation per host, using `Test-WptHostReachable` (already pool-injected) for reachability.
3. **Version-bump wpt** (6.5.33 -> 6.6.0, new action) and its manifest.

## Risks / non-goals
- **Do not weaken the c2c Java guards** - the vendor gate and strict-GUID msiexec are the security controls;
  the extraction must preserve them exactly. c2c's fix-java behavior stays identical (gate on its tests).
- **Self-guard + confirm parity is mandatory** - wpt fix-java uninstalls software on remote hosts; it must
  drop the dispatcher (self-guard) and require a typed confirm + the admin-session gate (destructive=$true),
  exactly like wpt's other uninstall actions. Never a Java uninstall on the JANET host itself.
- Non-goal: changing what Java gets removed or the detection heuristic - pure extraction + wiring.
- Live remediation needs a real host with Oracle Java -> pilot-pending; the vendor-gate/GUID logic is
  unit-testable offline (registry-shaped fixtures) and c2c's existing Java tests must stay green.

## Test plan
- c2c's existing Java tests stay GREEN (behavior-preserving extraction).
- New wpt tests: the `fix-java` action is `destructive=$true`; the dispatcher is dropped by the self-guard
  before fan-out; the shared engine's vendor gate rejects a non-Oracle/Sun JavaSoft residue and accepts an
  Oracle one; the strict-GUID guard rejects a malformed ProductCode. Offline/unit-scope (no real host).
- Full production Pester suite green; PS 5.1 parse-clean + BOM; wpt manifest loads at 6.6.0.
