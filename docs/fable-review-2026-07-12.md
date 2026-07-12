# Fable 5 Review - JANET Web Experimental (delta audit) - 2026-07-12

Focused adversarial audit of everything that changed in `X:\JANET Web Experimental` since the 2026-07-11
full audit (`docs/fable-review-2026-07-11-full.md`): the v1.14.0 field-script ports (commit `8783791`) and
the v1.15.0 offline-Defender rung (`b891938`) - **+711 lines in `c2c.psm1`** - plus a re-verification that
yesterday's remediation still holds. Four parallel reviewers; every P2 below was re-read and spot-verified
against the code by the synthesizer (**[V]**). HEAD at audit = `1ad9cb3`.

**The remediation holds.** All eight fixes from the 2026-07-11 audit are confirmed **present-and-correct**
with current line numbers - the v1.14/v1.15 commits touched only `c2c.psm1` + its tests/view, so nothing was
reverted (ACAS `schedule-reboot` self-guard `acas:2935`; UPR strict-GUID + self-guards `upr:938/1315`; adto
IAO Windows-identity + recert-append + SearchBase gate `adto:461/482/342`; server `/session/end` disarm
`Server:497`; WPT reboot-path self-guards + app-update IPv4 `wpt:4910/3147`; WinRM Bridge listener-safety +
view `list:` + token gate; certdeploy CHECK/DEPLOY parity; reports full-cell CSV guard + row ceiling + IAVM
escape). **The injection hunt on the new code came back CLEAN** - the Java `fix-java` uninstaller uses the
registry key *name* under an anchored hex pattern and never touches `UninstallString`, so it did NOT repeat
the UPR loose-GUID P1.

**Overall rating: YELLOW.** No reachable P1/RCE. The findings are a cluster of P2s **entirely inside the new
v1.14/v1.15 field-script ports** - one binary-execution validation weakness (gated behind write access to the
operator box's own staging folder) and five reliability/availability/functional bugs faithfully carried over
from the field scripts. All contained and cheap.

## P2

**[P2] [V]** `modules/JanetWeb.c2c.psm1:2791-2798` (`Test-C2cDefenderPackage`) - **the offline `mpam-fe.exe`
gate accepts ANY Microsoft-signed EXE >=50 MB, not a Defender definition package.** The Authenticode check is
genuine (`Status -eq 'Valid'` + subject org checked + 50 MB floor, admin-side before the push), but (a) nothing
verifies the file IS a definition installer (no `OriginalFilename`/`ProductName`/product check), so any
Microsoft-signed 50 MB+ binary renamed `mpam-fe.exe` - an old signed installer with a known LPE, a signed
LOLBin - passes and is **executed as admin on every host whose online sources fail**; and (b) the signer test
`"$($sig.SignerCertificate.Subject)" -notmatch 'O=Microsoft Corporation'` is an **unanchored substring** (a DN
embedding that literal, e.g. `O=Microsoft Corporational Services`, matches). The rung also arms **implicitly by
file presence** (no discrete opt-in beyond the run-wide `FIX`). Exposure requires write access to the
dispatcher's `Packages\DefenderDefinitions` - but that IS the whole trust boundary for fleet-wide admin exec.
Fix: verify the MS Defender product identity (OriginalFilename/ProductName), anchor the O RDN (or pin the
Microsoft cert thumbprint), pin a SHA256 at validation and re-check it at push (also closes the TOCTOU below),
and make the offline rung a discrete opt-in.

**[P2] [V]** `modules/JanetWeb.c2c.psm1:2193` (PkiRdp) - **rebinds the RDP listener on the CLIENT
Authentication EKU, not SERVER Authentication.** The replacement-cert filter requires EKU
`1.3.6.1.5.5.7.3.2` (Client Auth); a TLS server listener needs `1.3.6.1.5.5.7.3.1` (Server Auth). On a host
whose only hostname-matching `My`-store cert is a workstation/802.1x client-auth cert (a common DoD machine
template), its *working* self-signed RDP cert is classed `self-signed` (`:2189`) and replaced with a
client-auth-only cert -> Schannel/NLA handshake fails -> **RDP outage**. Compounding P3s on the same path:
the destructive `Remove-Item` + `Set-ItemProperty ''` (`:2198-2199`) run BEFORE the `Set-CimInstance` bind
(`:2200`), so a bind throw leaves a no-cert window; and the host match `$_.DnsNameList -match $env:COMPUTERNAME`
(`:2192`) is an unanchored regex that can select a different host's cert (`FOO-HOST1` matches `HOST1`). Fix:
require Server-Auth EKU + `HasPrivateKey`, anchor the name match, and bind before clearing.

**[P2]** `modules/JanetWeb.c2c.psm1:2253-2261` (Java JavaSoft sweep) - **no Oracle/Sun vendor gate, so it
deletes registry state of compliant non-Oracle Java 8.** The Oracle/Sun publisher filter guards only the
*Uninstall* section (`:2234`); the `HKLM\SOFTWARE\JavaSoft` cleanup runs on any `OLD` verdict. But JavaSoft
keys are not Oracle-exclusive - Amazon Corretto 8 and Temurin 8 register `1.8.0_xxx` there, and their update
numbers (e.g. `1.8.0_452`) are ALWAYS below Oracle's 491 bar (which is Oracle-specific numbering) -> a current,
supported Corretto/Temurin 8 host has its version key deleted and `CurrentVersion` repointed, breaking
registry-based JVM discovery, while the confirm text (`:205`) promises "OpenJDK/Temurin/Corretto ... never
touched." Fix: gate the JavaSoft sweep on an Oracle/Sun publisher/vendor check, or only prune keys whose
uninstall entry was itself matched.

**[P2] [V]** `modules/JanetWeb.c2c.psm1:575 vs the embedded blob at :580` - **the MDE onboarding blob's
signing cert is already EXPIRED, and the comment says otherwise.** Decoding `$script:C2cMdeOnboardingBlob`:
leaf `CN=CloudClientAuthentication-FF.usgovcloudapp.net`, **NotAfter 2026-01-07** (expired ~6 months ago),
yet the code comment (`:575`) claims "expires Jan 2027." The blob's `sig` and `sha256sig` fields are also
byte-identical (impossible for a real SHA1+SHA256 pair - a capture error). So the last MDE-onboarding heal
rung is effectively **dead** (hosts stick at `IN PROGRESS`), and the wrong comment tells operators not to
re-capture until 2027. Fix: re-capture the onboarding payload from a healthy host, correct the comment, and
add a startup/scan warning when the embedded blob's cert is past `NotAfter`.

**[P2] [V]** `modules/JanetWeb.c2c.psm1:1846-1863` (BitLocker resume) - **the Off+FullyEncrypted resume path
adds a TPM protector and resumes protection WITHOUT the escrow-first/recovery-protector check the enable paths
have.** If the volume ends with only the TPM protector, a later PCR change / TPM clear sends the box to the
recovery screen with no escrowed key -> unrecoverable. (Lower probability than the enable path - a
previously-FullyEncrypted volume usually already carries a recovery protector - but it is not verified here,
unlike `$escrowFirst` at `:1683-1727`.) Fix: before adding the TPM protector + resuming, confirm a
RecoveryPassword protector exists and is escrowed (reuse the `$escrowFirst` guard), else SKIP with a note.

**[P2] [V]** `web/js/views/adto.view.js:277,301` - **`isRunning()` is called but never defined, so the FIX /
IAO VALIDATE buttons are dead.** `doFix()` and `doValidate()` open with `if (isRunning()) return;`, but this
view never defines `isRunning` (the clear button at `:196` inlines `run && run.state && run.state.active`
instead). In a strict-mode IIFE with no such global, the first line throws `ReferenceError`, the promise
rejects unhandled, and clicking the buttons does nothing with no feedback. Fails closed (not exploitable), but
the entire AD Nemesis remediation UI is inoperable. Fix: define `function isRunning(){ return !!(run && run.state && run.state.active); }` in the view (one line).

## P3

- `c2c.psm1:600-611` (`$C2cJavaSrc`) + `:2293` - the Java verdict gate marks the **2.x Java Auto Updater OLD**
  (it ships WITH a compliant 8u491 install) and condemns a bare-major `8` / `Java 8` folder with no update
  evidence; both should be `UNKNOWN` (never-touch), matching the tool's own philosophy.
- `c2c.psm1:2259,2300` - Java key/folder removal uses `Remove-Item -Path` (not `-LiteralPath`) and PS 5.1
  `-Recurse` follows directory junctions; a planted junction under `Program Files\Java` -> arbitrary deletion.
  (Requires admin on the target already -> P3.)
- `c2c.psm1:2148-2153 vs :2686-2691` - the PkiExpired legacy-keep list is a hard-coded duplicate of
  `$C2cLegacyIntermediates`; currently byte-identical, but drift (a 5th intermediate added to the push
  allowlist only) would make PkiExpired prune what fix-pki re-pushes. No test on the sync invariant.
- `c2c.psm1:579` - the MDE onboarding blob (orgId + gateway + public certs; no private key) is committed in
  git; anyone with repo access could onboard rogue devices into the USGov tenant (telemetry/portal surface).
  Mitigated: `$blobUsable` refuses a blob whose orgId != target and only writes when the policy key is empty
  post-gpupdate.
- `c2c.psm1:2791 + :2395` - TOCTOU: `Resolve-C2cDefenderPackage` validates once at action start; the per-host
  `Copy-Item -ToSession` re-reads the file later with no SHA256 pin, so a mid-run swap is pushed unvalidated.
- `c2c.psm1:1811-1817` - the data-volume dedup silently removes a *pre-existing* second RecoveryPassword
  protector (the kept one is escrowed, so no lockout, but a previously-recorded key ID is invalidated unnoted).
- `web/js/views/c2c.view.js` (`applyScanSummary`) - a read-only scan merges every flagged host into Target
  Computers, which the target-driven destructive utilities (`doJavaFix`/`doLockscreenFix`) then dial; the
  operator's typed set and the dispatched set can diverge after a wide scan. Mitigated by log line + live
  counts + arm dialog; defense-in-depth intact.
- `modules/JanetWeb.wpt.psm1:490` - `Get-WptLocalIdentity` is the one self-guard identity set that does NOT
  enumerate bound-NIC IPv4 (ACAS/UPR/pkginstall/WinRM Bridge all do now) - an OOB-NIC IP literal could slip
  WPT's self-guard. Parity fix.

## Verified clean

- **Injection (new c2c code):** `fix-java` uses the registry key NAME under anchored `^\{[0-9A-Fa-f-]+\}$`,
  never `UninstallString`; msiexec/gpupdate/mpam-fe run via `Start-Process -FilePath` with constant/array args,
  no shell; Sense/DiagTrack via `Restart-Service -Name` (hardcoded); all cross-boundary values (`$MdeBlob`,
  `$offlineDefPath`, `$JavaSrc`) travel as typed `AddArgument`/`-ArgumentList` scalars, never dot-sourced.
- **BitLocker recovery-key leakage:** none - `$escrowFirst` never reads `.RecoveryPassword`; the stale-TPM
  removal filter `'(?i)Tpm'` never matches a RecoveryPassword protector; no key material reaches any row/log.
- **XSS (new/changed views):** `adto.view.js`, `winrmbridge.view.js`, and the `c2c.view.js` delta are clean -
  AD/host data reaches the grid via `{text:}` -> `textContent`; dialog bodies interpolate only numbers /
  hardcoded constants / `esc()`; the scan-bucket drill-down passes a DOM `Node` (the non-innerHTML branch).
- **Pool-runspace / ArgumentList wiring:** all four boundaries match after v1.14/v1.15 added params (scan
  probe 8/8, `$probeSb` 10/10 incl. `$coamsChecksJson`/`$coamsSrc`, fix worker 18/18 incl. `PkiCompanions`,
  `$fixSb` 11/11); COAMS threaded Config->JSON->ConvertFrom-Json; `$emitResult` synthetic records never build
  phantom buckets.
- **Self-guard + confirm + server gating:** case-sensitive `FIX`/`VALIDATE` re-checks fire first on every new
  destructive path; `Test-JanetC2cHostIsSelf` drops the dispatcher; adto IAO gate checks the Windows identity
  running JANET against the (empty-by-default, fail-closed) `iaoValidators` list; PKI companions only run when
  the real dispatcher passes `$PkiCompanions=$true` (test/direct callers never touch live cert state).
- **Secrets:** `adto-baseline.json` + `DefenderDefinitions/README.txt` carry no credentials (the MDE blob is
  public certs, flagged separately at P3).

## Recommendations (priority order)

1. **Harden the offline mpam-fe gate (P2):** verify the MS Defender product identity, anchor the signer O RDN
   (or pin the thumbprint), pin+recheck a SHA256 across validation->push, and make the rung a discrete opt-in.
2. **PkiRdp (P2):** filter on Server-Auth EKU + `HasPrivateKey`, anchor the host match, bind before clearing.
3. **Java sweep (P2):** gate the JavaSoft registry cleanup on an Oracle/Sun vendor check; treat the 2.x updater
   and bare-major folders as UNKNOWN.
4. **MDE blob (P2):** re-capture the onboarding payload, fix the expiry comment, warn when the embedded cert is
   past NotAfter.
5. **BitLocker resume (P2):** require an escrowed recovery protector before adding TPM + resuming.
6. **adto.view.js (P2):** define `isRunning()` - one line, restores the AD Nemesis remediation UI.
7. **P3 sweep:** Java `-LiteralPath` + junction guard, PkiExpired keep-list test, WPT bound-NIC parity, mpam
   SHA256 pin (folded into #1).
