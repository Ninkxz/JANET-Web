# Fable 5 Review - Loop 2 of 8 - 2026-07-12

Scope: the loop-1 remediation itself (commits `602ecba` + `2490c87`; `git diff f3bcf47 HEAD`) - +117 lines in
`c2c.psm1` (PkiRdp reorder, Java vendor gate, BitLocker resume escrow, mpam gate + SHA256 pin), the WPT
bound-NIC add, and the `adto.view.js` fix. Nothing changed externally. Three reviewers (2 Opus deep +
regression, 1 Sonnet sweep); the discipline this iteration was "did hardening one path break or weaken another."

**Rating: GREEN.** No P1, no P2. All three reviewers independently confirm the loop-1 fixes are strictly
tightening / fail-closed, with **zero regressions** and **no weakened guards** - the regression pass verified
each of the 7 fixes CLOSED-AND-CLEAN (incl. the 19=19 arg/param alignment, the PKI-companions gating, and the
BitLocker recovery-key-never-leaked invariant), and confirmed **no existing test goes red**. The six loop-1 P2s
are closed. What remains are fail-safe P3 residuals.

## P3 (priority-ordered)

**FIX (cheap, no-risk):**
1. **`c2c.psm1:2456` - SHA256 pin short-circuits on an EMPTY `$ExpectHash`.** Not reachable today
   (`Resolve-C2cDefenderPackage` only sets a non-empty `Sha256` on the same branch that sets a non-empty `Path`,
   and exec is gated on that path), but the on-target guard should fail-closed on empty so the pin can't
   decouple if a future change threads an empty hash: `if ((-not $ExpectHash) -or ($actual -ne $ExpectHash))`.
2. **`wpt.psm1:501-508` - the bound-NIC `foreach` is wrapped in ONE `try/catch`**, so a per-adapter throw
   (a flaky/virtual NIC) skips its siblings. Never disables the guard (the unconditional COMPUTERNAME/loopback/
   DNS entries precede it and the set is cached), but wrapping the inner body per-NIC is the correct idiom.
3. **`c2c.psm1:2458` - redundant `Remove-Item $Pkg`** in the tamper branch lacks `-LiteralPath` (dead-weight:
   `$Pkg` is the fixed literal `C:\Windows\Temp\mpam-fe.exe` and the `finally` already deletes it). Trivial tidy.

**DOCUMENT as accepted fail-safe residuals (not fixing - risk > reward for a P3-for-P3 change):**
4. `c2c.psm1:2273` - the Java `$javaKey` normalizer collapses every 9+ major to `major|0` (loses update
   granularity) and the Oracle-8 `floor(patch/10)` map is scheme-fragile. Both are **fail-safe** (under-removal,
   never a wrong deletion) and low-impact (OpenJDK/Corretto/Temurin rarely write `HKLM\SOFTWARE\JavaSoft`).
5. `c2c.psm1:1853` - BitLocker resume escrow-first SKIPs a suspended-but-encrypted OS volume on a
   **non-domain-joined** host (no AD/Entra to escrow to). Intentional lockout-avoidance trade; AFNET fleet is
   domain-joined, so real impact ~nil. Pilot note: standalone hosts need manual escrow before resume.
6. `c2c.psm1:2218` - PkiRdp first-label host match could select a foreign cert whose first DNS label equals
   COMPUTERNAME. Requires pre-existing local admin to plant, and is far tighter than the prior unanchored
   substring `-match`. Residual.

## Verified clean
`Test-C2cDefenderPackage` fail-closed at every rung with the VersionInfo inside the Authenticode hash boundary
(OriginalFilename/ProductName can't be spoofed without breaking the MS signature); PkiRdp bind-before-clear (old
listener intact on failure) + correct Server-Auth EKU + HasPrivateKey; SHA256 pin correctly ordered
(re-hash before Start-Process) + 19=19 arg alignment; Java Uninstall msiexec removal (strict GUID + array args)
UNCHANGED, the vendor gate confined to the JavaSoft residue loop; BitLocker enable-path + no-leak invariant
untouched; `adto.view.js isRunning()` a faithful extraction (engine untouched); WPT bound-NIC purely additive.
