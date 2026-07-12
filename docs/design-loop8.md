# Design - Loop 8 (final) - Lock the run-script wrong-box guard with a test

## Goal
Loop-8's P2 fix added the wrong-box DNS-mismatch hard-abort to `run-script` (remoteadmin) - the suite's most
dangerous action (arbitrary operator PowerShell). It was the ONE destructive worker missing that guard; it is
now also the one missing its TEST. The other six wrong-box guards are pinned by
`PkginstallSecureboot.WrongBoxGuard.Tests.ps1`, `Restart.Guards.Tests.ps1`, `Wpt.Guards.Tests.ps1`,
`FixGuards.Tests.ps1`. Bring run-script to test parity so the guard on the highest-consequence action can't
silently regress.

## Surface (one NEW test file; ZERO production change)
`tests/RemoteAdmin.WrongBoxGuard.Tests.ps1` (Pester 3.4, UTF-8 BOM), following the exact house pattern
(`PkginstallSecureboot.WrongBoxGuard.Tests.ps1`): replicate VERBATIM, as small pure test functions, the two
expressions the run-script worker uses (remoteadmin.psm1 ~:269-276) -
- expected-name: `if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }`
  (IPv4 literal -> '' -> guard skipped; FQDN -> first label; bare host -> itself),
- hard-abort boolean: `[bool]($Expected -and ($Answering.Trim().ToUpper() -ne ([string]$Expected).Trim().ToUpper()))`
- and assert: IP-literal -> blank expected (guard skipped, no abort even against a different answerer);
  FQDN -> shortname; bare -> itself; hostname mismatch -> abort; case-insensitive match -> no abort.
Unit-scope only - no `New-PSSession`/`Invoke-Command`/host contact (identical discipline to the sibling file).

## Risks / non-goals
- **Zero production risk** - additive test; no `.psm1`/`.js` touched.
- **Contract-pinning, not behavior-proving of the live probe** - the actual remote `$env:COMPUTERNAME` probe
  needs a live session (pilot-pending, exactly as for the six sibling guards); this test locks the
  decision logic that decides abort-vs-run, which is the part a future edit could silently break.
- Non-goal: refactoring the (now 7) inline wrong-box guards into a shared helper - a bigger cross-worker /
  pool-runspace-injection change; the per-file replica tests are the established house pattern and stay.

## Test plan
- The file IS the test. Full Pester suite green (895 + the new cases). PS 5.1 parse-clean + BOM.
