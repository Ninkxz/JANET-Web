# Production Review - Loop 4 (Phase 2, cycle 2) - 2026-07-12

Audit of the loop-3 delta (commit 5f160d88 - Java remediation extracted to the shared engine
`modules\JanetWeb.javafix.psm1`, c2c refactored to delegate, new guarded `wpt fix-java` action). 4 reviewers:
(A) shared engine + c2c refactor [Opus], (B) wpt fix-java guard parity [Opus], (C) regression sweep / c2c
pillar integrity [Sonnet], (D) full re-verify of the 6 P2s + merged guards [Opus].

**Rating: GREEN.** No P1, no P2. The extraction is behavior-preserving; the new action has full guard parity;
no other c2c pillar was disturbed; all merged fixes hold; **full suite 752/0**.

## Verified
- **Shared engine security guards intact + verbatim on the live path** (`javafix.psm1`): the vendor gate
  (`(?i)oracle|sun microsystems` - JavaSoft residue removed ONLY when a matching Oracle/Sun Uninstall entry
  exists; OpenJDK/Temurin/Corretto/Adoptium never touched) and the strict-GUID msiexec guard
  (`^\{[0-9A-Fa-f-]+\}$` before `msiexec /x`, fed the registry subkey name not the untrusted UninstallString).
  No residue-removal or msiexec path bypasses a guard. No `Invoke-Expression`; `[scriptblock]::Create` only on
  the module's own constant source. Multi-point fail-closed if the engine isn't injected.
- **c2c behavior-preserving**: the ~130-line inline Java block was deleted whole and replaced by a 4-line
  delegation to `Invoke-JanetJavaRemediation`; the removed body is byte-identical to the engine body; row shape
  / detection heuristic (8u491 bar) / what-is-removed unchanged. c2c's 21 Java tests pass exercising the shared
  engine via the `Get-C2cJavaVerdict` delegator. c2c's OTHER 8 pillars (monitoring/firewall/antimalware/
  patches/encryption-BitLocker/pki/lockscreen) are byte-UNCHANGED (diff = only the 2 Java hunks).
- **wpt `fix-java` full guard parity**: `destructive=$true` + admin-session gated server-side; `Remove-WptSelfTargets`
  drops the dispatcher BEFORE fan-out (filtered list fanned, never uninstalls Java on the JANET host);
  wrong-box DNS-mismatch hard-abort before the remediation; engine + `Test-WptHostReachable` both pool-injected
  (fail-closed if absent); strict host-token validation; args aligned 4=4.
- **All 6 c2c P2s + merged guards CLOSED-AND-CLEAN** (mpam gate, PkiRdp EKU+bind-first, Java vendor gate [now
  in the engine], BitLocker escrowFirst, MDE advisory, SHA256 pin, fail-closed server gate, run-script
  wrong-box, adsearch DN-guard+ReferralChasing, wpt CSV+injection+self-guard, shell.js/dhcp esc, adto/winrmbridge
  guards). 22/22 tools Import + manifest OK; full Pester 752/0.

## P3 (cheap tidy, applied this cycle)
`javafix.psm1:139` empty-product-key cleanup uses `Remove-Item -Path` instead of `-LiteralPath` (verbatim from
the pre-extraction c2c original - a pre-existing residual, NOT introduced by the extraction; inert because
JavaSoft product-key names carry no `[]` wildcard metacharacters, and it's gated behind a vendor-gated OK
removal). Same class as the loop-2/3 `-LiteralPath` hardenings; tidy to `-LiteralPath` for consistency now that
the code is centralized in the shared engine.

## Verdict
The Cycle-1 Java-into-WPT shared-engine refactor is clean and complete. Applying the one cheap P3, then the
pre-assigned Cycle-2 design (Java-fix-into-ACAS-Nemesis). Desktop C2C mirror remains BLOCKED (owner's 2.4.x WIP
still uncommitted - re-checked this cycle).
