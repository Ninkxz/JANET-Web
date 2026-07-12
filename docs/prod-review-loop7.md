# Production Review - Loop 7 (Phase 2, cycle 5) - 2026-07-12

Desktop-mirror mandate is BLOCKED this cycle (a concurrent suite-wide "Live-Usage Snapshot" telemetry sync is
still rewriting all 11 Desktop tools - `X:\J.A.N.E.T` has 19 uncommitted items incl. ADSearchTool). So this
cycle ROTATED the audit onto the least-covered Web tools: reports.psm1 (41 actions), certdeploy/dhcp/secureboot,
and message/sysadmin/biosfirmware/patchlib/history/kev. 4 reviewers (2 Opus, 1 Sonnet, 1 Opus re-verify).
Every P2 spot-verified.

**Rating: YELLOW.** No P1. One P2 (certdeploy trust-anchor validation) + several P3 defense-in-depth gaps.
The bulk of the surface is well-hardened; suite 781/0.

## P2 (fix this cycle) - certdeploy pushes trust anchors to LocalMachine\Root with no CA validation
`Add-CertDeployBundleToStores` (`certdeploy.psm1:339-350`) reconstructs each bundle cert from base64 and calls
`$st.Add($cert)` with NO chain/EKU/BasicConstraints/thumbprint check - only the upstream expiry filter. The
store can be `Root` (a trust anchor). The `certBundleFolder` input is operator-controlled and may be a UNC
path, so an operator pointed at (or mistyping onto) a hostile share pushes arbitrary root CAs fleet-wide -
enabling MITM/code-trust; additive install means it persists. **P2 not P1** because the destructive path is
admin-session-gated + requires the exact case-sensitive confirm word `DEPLOY` + self-guard + wrong-box abort,
and a safe default DoD bundle ships (used when the folder is blank). *Spot-verified: :339-350 adds every cert
unvalidated; :227-230 operator folder "always wins".*
**Fix (non-breaking):** before adding to the TRUST-ANCHOR stores (Root + CertificationAuthority/Intermediate),
require the cert to be an actual CA (`BasicConstraints` CA=true) - legit DoD roots/intermediates pass, a
leaf/end-entity cert can no longer be installed as a trust anchor; surface each added cert's Subject+thumbprint
in the deploy result so the operator can verify what they trusted. Residual (an operator deliberately trusting
a self-signed CA from a chosen folder) is inherent to the tool's purpose + admin/DEPLOY-gated -> documented.

## P3 (defense-in-depth - fix the cheap ones, document the rest)
- **reports `Export-AcasFindingsCsvText:2101`**: `PatchedBy` (operator EDIPI free-text) is quote-wrapped but
  NOT run through the formula-injection `$guard` like the sibling exporters. Cheap fix - wrap the 6 cells. **FIX.**
- **reports `Get-WeeklySafeFileName:2180`**: `$Week.Enclave` interpolated into a filename unsanitized - but it's
  a hard-coded `'NIPR'/'SIPR'` literal today (not attacker-controlled). Sanitize defensively. **FIX (cheap).**
- **message.psm1**: no self-guard - an operator can pop a message on the JANET dispatcher itself (WinRM
  loopback). Low impact (a popup, not a reboot) but an inconsistency with the suite's self-guard pattern
  (`send` is destructive=$true). **DOCUMENT** (queue a self-guard add for a later cycle - moderate change).
- **patchlib.psm1**: `extraPath`/`csvPaths` accept an arbitrary operator local path (enumerate/read any
  locally-readable file), and both actions are `destructive=$false` so no admin gate applies. Loopback-only
  listener caps this to an existing local session; the tool's purpose IS scanning operator-chosen folders.
  **DOCUMENT as accepted** (restricting it would break the feature; no host touched).
- **WinRM `SkipCACheck/SkipCNCheck` on 5986-only hosts** (certdeploy/dhcp/secureboot + suite-wide): the
  encrypted transport's server identity isn't TLS-validated; Kerberos/Negotiate mutual auth mitigates when a
  domain cred is used. Documented AFNET self-signed-WinRM posture -> **pilot-pending** (needs a live domain to
  assess; never faked).

## Verified clean (this rotation)
reports.psm1 (best-hardened: `ConvertTo-HtmlEscaped` on all scanner/AD HTML, CSV neutralizers, `-LiteralPath`
inputs, no injection, read-only labels honest, no secret leak); dhcp (fully parameterized cmdlets, IP
round-trip-validated, fail-closed reads, admin-gated writes); secureboot (BIOS password never on a command
line/log/row, wrong-box guard precedes the password drop, self-guard + brick-safety); sysadmin/biosfirmware/
history/kev (read-only or atomic-locked-validated writes, correct gating, no injection). No private-key
exposure anywhere.

## Fix order (Web; Desktop mirror deferred - blocked)
1. P2 certdeploy: BasicConstraints CA-check on trust-anchor stores + surface added-cert subjects.
2. P3 reports: PatchedBy CSV guard + Enclave filename sanitize.
Suite green + BOM per commit; scoped commits (concurrent Web session was active earlier this run).
Desktop mirror of these = deferred until `X:\J.A.N.E.T` is clean.
