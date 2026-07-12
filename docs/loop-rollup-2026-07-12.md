# Fable 5 Loop Rollup - 8 iterations - 2026-07-12

Autonomous audit-and-design loop over `X:\JANET Web Experimental` (isolated; production `X:\JANET Web` and
SECRET `X:\shh-JANET` never touched). Each iteration: SCOPE -> full adversarial Fable audit (3-4 Opus/Sonnet
reviewers + a re-verification agent, every P1/P2 spot-verified by me against the code) -> FIX -> one DESIGN
improvement -> WRAP. Every commit local; suite green before each.

## Rating + finding trajectory

| Loop | Rating | P1 | P2 | P3 | What the audit was looking at |
|------|--------|----|----|----|-------------------------------|
| 1 | YELLOW | 0 | (baseline) | - | first full audit; field-script ports + core c2c (mpam gate, PkiRdp EKU, Java vendor gate, BitLocker escrow, MDE expiry, SHA256 pin, adto view) - 7 fixes |
| 2 | GREEN  | 0 | 0 | 3 | audit of the loop-1 remediation - clean; 3 cheap P3 hardenings |
| 3 | GREEN* | 0 | 1 | 1 | delta clean, but the design-step parity test surfaced a real P2 (11/12 identity helpers returned a bare HashSet -> case-SENSITIVE self-guard) - fixed |
| 4 | GREEN  | 0 | 0 | 1 | clean; behavioral self-guard test added |
| 5 | **RED**| **3**| **2**| - | **rotated the lens to under-audited surface** (views, server core, adsearch/adto/upr/winupgrade): LDAP bind-redirect x2, upr self-guard gap, dhcp stored-XSS, winupgrade reboot-scoped guard - all fixed |
| 6 | YELLOW | 0 | 1 | 2 | audit of the loop-5 fixes: serverless-DC bind-redirect bypass + escaped-comma false-positive + dhcp self-XSS - fixed |
| 7 | YELLOW | 0 | 2 | 3 | rotated to engines/threading/XSS: client-CSV formula-injection (biosfirmware live), wpt pool-injection break, DN child-subdomain bypass, kev ungated write, wpt maintenance-lock - fixed |
| 8 | YELLOW | 0 | 1 | 2 | final deep pass: run-script wrong-box gap (arbitrary RCE), DN escaping-blind DC-count (2 P3) - fixed |

`*` loop 3's delta was GREEN; the P2 was found by the iteration's own design-step test (recorded as an addendum).

**Totals found AND fixed across 8 loops:** 3 P1 + 7 P2 + ~13 P3 (plus loop-1's baseline batch), 0 left open.

## Loop 1 -> Loop 8: what changed
- **Open P1/P2 at end: 0.** Every P1/P2 the audits surfaced was spot-verified and remediated in the same
  iteration, with a re-verification agent each loop confirming all prior fixes still held (loop 8: all 26
  CLOSED-AND-CLEAN).
- **Rating arc is not a regression story.** GREEN in loops 2-4 reflected a stabilized *delta*; the RED in
  loop 5 was the audit finally reaching surface six c2c-focused passes hadn't touched (the 3 P1 LDAP
  bind-redirect / self-guard holes were PRE-EXISTING, not introduced). Loops 6-8 (YELLOW) were the tail:
  each fix's own subtle residuals (bind-redirect variants, escaping-blindness, a wrong-box gap on the most
  dangerous action) found and tightened. The trend is convergent - findings got narrower and more expert
  each loop, ending at a single subtle wrong-box gap.
- **Test coverage: ~803 -> 903 passing** (66 files), with 8 NEW security-invariant suites added by the design
  steps: identity-set parity, behavioral HostIsSelf, manifest destructive-flag contract, DN bind-redirect
  guard, LDAP referral-chasing, CSV formula-injection, and the run-script wrong-box guard - so the hard-won
  invariants can't silently regress.

## Security posture, end state
Hardened and locked: the credentialed AD-bind path (DN validation -> local-domain suffix -> exact-domain
component boundary -> RFC-4514 escape-aware -> no referral chase), the wrong-box DNS-mismatch hard-abort on
ALL 7 destructive workers (incl. run-script), the fail-closed server admin-session gate, self-guard parity +
case-insensitive matching across all 12 tools, the offline-Defender Authenticode+SHA256-pinned exec path,
BitLocker escrow-first (key never leaked), CSV formula-injection neutralized on every writer (server + shared
client `toCsv`), and XSS closed at the one raw-HTML sink (esc()/textContent everywhere else).

## Open / carry-forward (documented, none are open P1/P2)
- **Pilot-pending (need a live domain/host to validate, never faked):** on-target SHA256 re-hash, PkiRdp
  cert-store swap, BitLocker escrow against real TPM/AAD/AD, the server gate's end-to-end HTTP path, the
  wrong-box remote `$env:COMPUTERNAME` probes, ReferralChasing runtime refusal.
- **Deferred hardenings (defense-in-depth, not defects):** DN-guard multi-domain trusted-domain allowlist;
  LDAP signing/sealing (`AuthenticationTypes`) on the bind; browser-launch token off the process command line
  (`Server.ps1:159-161` - operator-local trust model).
- **Cosmetic:** `beta.psm1` ships without a UTF-8 BOM (pre-existing, pure-ASCII so PS 5.1 reads it fine);
  winrmbridge's guard is named `Test-WinRmBridgeSelfTarget` vs the `Test-*HostIsSelf` convention.

## Method note
The single highest-value move of the campaign was ROTATING the adversarial lens when the delta ran dry
(loop 5): re-scanning the same changed surface a fifth time would have stayed GREEN and missed the 3 real
P1s living in the never-deeply-audited view/server/AD-engine code. Breadth-of-surface beat depth-on-delta.
