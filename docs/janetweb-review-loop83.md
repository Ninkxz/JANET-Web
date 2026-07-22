# JANET Web — review loop 83 (2026-07-21)

**Theme: informative failures** (loop 70) — final follow-up. Fable-inline + a Fable adversarial subagent on
loop-82. Baseline: loop-82 authoritative **1559**.

## Self-review of loop-82 (AD-object exclusion + c2c read-only wires) — **2 confirmed leaks + 1 asymmetry, all fixed**
A Fable subagent executed the loop-82 functions on PS 5.1. Verdict: the c2c scan wire is **SAFE** (CHECK ERRORS is
the only path hinted; DNS-MISMATCH-collapsed detail correctly yields ''), the version-check version-number
protection is **SAFE** (a version string is unreachable from healthy statuses — engine call count 0, measured), and
the regex is **not** a ReDoS risk (linear to 1 MB). But:

**2 CONFIRMED leaks (loop-82's AD-object fix was incomplete) — FIXED.** My loop-82 lookahead only guarded the ONE
`computer…could not be found` alternative; AD errors phrased differently bypassed it via sibling alternatives:
- `Cannot find the computer account 'WS01$' in Active Directory` → leaked to the DNS hint via `cannot find the computer`.
- `The computer account … could not be found …; the SID could not be resolved` → leaked via `could not be resolved`.
**Fix:** a dedicated **AD-object signature placed ABOVE name-resolution** — `computer\s+(?:account|object).{0,80}?
(?:could not be found|…)|(?:could not be found|cannot find).{0,80}?in Active Directory` — matching all AD phrasings
FIRST and returning a proper **AD hint** (reset the computer account / rejoin the domain) instead of a wrong DNS
hint or ''. Verified: 7 AD-object forms (incl. both leaks + plural "accounts") now route to the AD hint; genuine
short/long-FQDN host-not-found + "server name could not be resolved" still route to DNS.

**1 minor asymmetry — FIXED.** version-check's no-TCP OFFLINE detail (`No TCP on 5985/5986/445 (1.5s timeouts)`)
matched the generic timeout signature → a misleading "retry / raise the per-host timeout" hint for a host that is
simply absent; the scan wire deliberately excludes OFFLINE as self-explanatory. **Fix:** scoped the version-check
hint to `$wasError` (the pre-collapse `ERROR` status — a real session/query failure carrying a WinRM error),
instead of `$lvl -eq 'error'` (which included genuine offline). A genuine no-TCP OFFLINE now gets no hint; a
worker/session error still does. This also strictly tightens the version-number protection. c2c 1.15.10 → 1.15.11.

## Workstream: per-candidate upr uninstall failures + the MSI signature-set growth (the LAST follow-up item)
Loop 74 wired upr's HOST-level failure. The deferred piece: a reached host where an individual EOL product fails to
uninstall (`$cand.Result` = `FAIL (… exit 1603)`, `rejected: executable not found`, …). Two coupled halves:

### Fix A — grow the engine's signature set (MSI/uninstaller exit codes; general to upr/wpt/pkginstall)
The engine was inert on ALL 5 real per-candidate FAIL shapes (verified). Added 5 signatures after file-locked:
**1618** (another install running → wait), **1605** (unknown product → already removed / stale entry), **1603**
(fatal → locked file / pending reboot / capture `/l*v`), **executable-not-found / process-did-not-start**
(uninstaller gone → orphaned registry entry), **unparseable/empty uninstall string** (safe-guard rejected → vendor
uninstaller). **Boundary hardening (caught in-loop):** a bare `\b1603\b` false-matches a dotted version segment
(`16.0.1603` — `.` is a word boundary!); replaced `\b` with `(?<![\d.])CODE(?![\d.])` on ALL SIX numeric codes
(1314/1722/1727 too) — a dotted version no longer false-matches, real "exit 1603" / "returned 1314" still do, and
the loop-80 KB/byte-count exclusions still hold.

### Fix B — wire upr's per-candidate Result through the engine (upr 1.2.5 → 1.2.6)
In `New-UprEmitRows` (`:1460`), on the EXISTING `$candResult -eq 'Failure'` classifier, run `$resultTxt` through the
engine → `$row['Hint']` + a per-candidate `FIX:` err log. Distinct from the host-level hint (mutually exclusive:
host-failure returns `ok=$false`, a reached host returns `ok=$true`), so no overwrite. Additive; an OK/Skipped
candidate is byte-identical.

### Tests
`Troubleshoot.Hint.Tests.ps1`: updated the loop-82 AD test (now asserts the AD hint + the 2 leaks + plural), +MSI
signatures, +dotted-version false-match guard. `Upr.VerifyResult.Tests.ps1` +3 (per-candidate wire, static).
`C2c.AuditResult.Tests.ps1`: pin → 1.15.11, version predicate → `$wasError`. **loop-37 lesson:** engine change
shared — ran engine + all consumers + upr (274) green; full c2c + full suite in the background.

## Rollout status (informative-failures theme)
**The follow-up list is COMPLETE.** All 9 destructive tools (70-78), restart delegation (79), read-only scans
(secureboot 80, certdeploy 81, c2c 82), and now per-candidate upr failures (83) are wired, on a shared engine
hardened across three self-reviews. Future loops: grow the signature set as new real failures surface; the theme's
core rollout is done.

## SECRET parity
- **SECRET parity:** mirror to X:\shh-JANET — (a) the AD-object signature + the dotted-version-safe numeric
  boundaries + the 5 MSI/uninstaller signatures in the troubleshoot engine, (b) the c2c-fork version-check
  `$wasError` scoping, (c) the upr-fork per-candidate hint wire. (Whole-engine mirror still pending, tracked since
  loop 70.)
