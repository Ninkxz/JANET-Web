# Fable 5 Review - Loop 1 of 8 - 2026-07-12

Loop 1's audit is the full delta audit completed immediately before this loop began (committed `de30727`,
`docs/fable-review-2026-07-12.md`) - four parallel Opus/Sonnet reviewers over the v1.14.0/v1.15.0 c2c field-script
ports (+711 lines) plus a re-verification pass, every P2 spot-verified against the code. This file is the loop-1
record; see that doc for the full evidence.

**Rating: YELLOW.** No reachable P1/RCE (the injection hunt on the new code came back clean - `fix-java` uses the
registry key name under an anchored hex pattern, never `UninstallString`). All prior remediation confirmed
present-and-correct. Six P2s, all inside the new field-script ports; all contained + fixable.

## Confirmed P2s (loop-1 fix queue, priority order)

1. **`c2c.psm1:2791` Test-C2cDefenderPackage** [V] - the offline `mpam-fe.exe` gate accepts ANY Microsoft-signed
   EXE >=50 MB (no Defender product-identity check; unanchored `O=Microsoft Corporation` substring; arms by
   file-presence). Fleet admin exec if the dispatcher's `Packages\DefenderDefinitions` is writable.
2. **`c2c.psm1:2193` PkiRdp** [V] - rebinds the RDP listener on CLIENT-Auth EKU `1.3.6.1.5.5.7.3.2` (needs
   SERVER-Auth `.3.1`) -> RDP outage; also destructive-before-bind (`:2198-2200`) + unanchored host match (`:2192`).
3. **`c2c.psm1:2253` Java JavaSoft sweep** - no Oracle/Sun vendor gate -> deletes compliant Corretto/Temurin 8
   registry state (their `1.8.0_452` numbering is always below Oracle's 491 bar).
4. **`c2c.psm1:575` MDE onboarding blob** [V] - embedded signing cert NotAfter 2026-01-07 (expired), comment
   wrongly says Jan 2027, `sig`==`sha256sig` capture error -> onboarding heal rung dead. Blob re-capture is
   pilot-pending (needs a live host); fix the comment + add an expiry warning now.
5. **`c2c.psm1:1846` BitLocker resume** [V] - Off+FullyEncrypted resume adds a TPM protector + resumes WITHOUT the
   escrow-first/recovery-protector check the enable paths have -> TPM-only lockout risk.
6. **`web/js/views/adto.view.js:277,301`** [V] - `isRunning()` called but never defined -> FIX / IAO-VALIDATE
   buttons throw a silent ReferenceError; AD Nemesis remediation UI inoperable (fails closed). One-line fix.

## Cheap P3s to fold in
- `wpt.psm1:490` Get-WptLocalIdentity - the one self-guard identity set without bound-NIC IPv4 enumeration (parity).
- `c2c.psm1:2259,2300` Java removal uses `Remove-Item -Path` not `-LiteralPath` (glob/junction hardening).

## Verified clean
Injection (all new c2c paths), BitLocker key-leakage, XSS in adto/winrmbridge/c2c views, pool-runspace +
ArgumentList/COAMS wiring (all 4 boundaries match after the new params), server gating + self-guards + confirm,
no committed secrets (the MDE blob is public certs). All eight 2026-07-11 fixes present-and-correct.
