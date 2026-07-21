# JANET Web — review loop 35 (2026-07-21)

**Baseline:** 1293/1293 at loop-34 close (authoritative, 0 fail). Fable-inline + one parallel Fable
worker. Local-only commits.

## Self-review of loop-34 (`1b10620` CSPRNG credential mint, `e4b4a9e` docs) — verdict GREEN (inline)
Additive: a longer, explicitly-random access credential; the constant-time compare handles any length,
and the report-preview rid change is transparent to that flow (76 server tests green). No boundary guard
weakened. Authoritative 1293/0-fail. GREEN.

## Fresh deep-dive: upr (Unsupported Product Remediator) false-cleans (parallel Fable worker) → verdict GREEN
An un-reviewed 127KB destructive tool (SEoL/unsupported-product uninstall). A bounded Fable worker hunted
"does upr report a product REMOVED when it isn't"; I verified in-code. **The removed decision is
fail-closed and honest end-to-end:**
- **Exit-code gated:** a per-product handler returns `OK` only on exit 0 (MSI/EXE also 3010); everything
  else → `WARN`/`FAIL`/`Skipped` (`:1001-1093`). A null ExitCode is never `[int]`-coerced (`$null -eq 0`
  is `$false` in PS 5.1) → not OK.
- **Mandatory post-verify:** after EVERY `OK`, it re-enumerates the remote uninstall registry (HKLM +
  WOW6432Node + HKCU) for that product and rewrites to `FAIL (still present)` if found or
  `FAIL (could NOT be verified)` if the re-read throws (`:1109-1146`). A lying exit-0 uninstaller is
  caught here.
- **msiexec codes:** 1605/1618/1602 → `WARN`, not removed; 3010 → OK only AFTER the verify confirms the
  key is gone.
- **Tally:** `uninstalledCount` counts only `Uninstall + not DryRun + Result -like OK*`; unreachable /
  error / reject (unparseable uninstall string) / skip each get their own bucket, itemCount 0; the audit
  books `VulnPatched` Success ONLY when ≥1 install was really removed (`:1443-1450`). Guards (self-guard,
  DNS wrong-box, confirm, proven-gate, only-removes-less) intact.

**The one defensible hardening (SPECULATIVE edge) → FIXED:** the verify demoted an `OK` to FAIL when the
re-read THREW (catch, `:1135`), but a non-throwing EMPTY (`$null`) `Invoke-Command` result hit
`$stillPresent = [bool]$vout.Present` → `[bool]$null` = `$false` = "not present" = a silent OK (`:1133`,
pre-fix). The verify is what makes upr trustworthy, so a `$null`/unreadable result must fail CLOSED.

**Fix** (upr **1.2.2 → 1.2.3**): pure `Get-UprVerifyResult` (`:119`) — a `$null` VerifyOut → `$stillPresent
= $null` → "could NOT be verified" (never "removed"); the worker mirrors it inline (`$stillPresent = if
($null -eq $vout) { $null } else { [bool]$vout.Present }`). The throw-catch fail-close is unchanged; this
just closes the empty-result twin. 36 upr tests green.

`Upr.VerifyResult.Tests.ps1` (6): `$null` verify → "could NOT be verified" AND never `^OK` (the fix);
still-present → FAIL; confirmed-gone → OK; reboot-required; + the exact 1.2.3 pin.

## Ranked, not fixed (new items 32-33; both SPECULATIVE/display)
- **32** — upr verify skips registry keys with no DisplayName (`:1127` `if (-not $it.DisplayName)
  { continue }`), before the PSChildName/GUID compare. A half-torn uninstall (key survives with
  DisplayName deleted, files on disk) could read as gone → OK while a file-based Tenable plugin still
  flags it. SPECULATIVE (couldn't demonstrate a product that does this). Fix: match PSChildName/GUID even
  on DisplayName-less keys.
- **33** — the end-of-run status `"Done. N ok, M failed"` (`:1292`) counts REACHABLE hosts, not removals:
  on the uninstall path `emit.ok=$true` whenever the host was enumerated even if every uninstall FAILED,
  and the honest host-level `auditResult='Failure'` is discarded (`$EmitHostAudit=$false`). So "5 ok, 0
  failed" can print over a run that removed nothing. Display-only (the rows, per-app Failure audits, and
  `itemCount` stay honest — no product is ever COUNTED removed). Fix: word the uninstall status as "N
  host(s) processed" / surface the removed count, or fold `auditResult` into the ok/failed split.

## SECRET parity
- SECRET parity: the upr verify fail-close — the JanetSec upr fork (if present) shares the uninstall
  worker; mirror `Get-UprVerifyResult` + the inline null-check.
- Carried (unexecuted): the CSPRNG credential mint; the winupgrade/c2c/acas/wpt remediation-honesty
  series; SLA bucket; host-key fold; wrong-template hint; CSV-ingestion + routing.
