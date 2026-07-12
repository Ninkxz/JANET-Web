# Production Review - Loop 9 (Phase 2, cycle 7) - 2026-07-12

Desktop-mirror mandate BLOCKED for the 4th consecutive cycle (`X:\J.A.N.E.T` still 19-dirty - the
Live-Usage Snapshot telemetry sync holds every `Tools\*.ps1`). The prod certdeploy area is also occupied
by a concurrent uncommitted "companions" feature. So this cycle audited the LEAST-recently-covered,
NON-colliding Web surface + did a read-only safety review of the concurrent certdeploy WIP. 3 reviewers:
(A) Opus read-only certdeploy-WIP safety, (B) Opus adsearch+adto adversarial, (C) Sonnet sweep of
patchlib/sysadmin/biosfirmware/winrmbridge/history. Every P2 spot-verified.

**Rating: GREEN.** No P1/P2 anywhere in scope. One P3 landed (DN-guard control-char hardening). The
concurrent certdeploy WIP does NOT re-open the trust-anchor hole (one P2 truthfulness gap flagged to the
owner, not mine to fix). Suite 818/818.

## A. Concurrent certdeploy "companions" WIP - GREEN (trust-anchor hole NOT re-opened)
Read-only review (the code is uncommitted, authored by another session - I did not touch it). The new
`Invoke-CertDeployCompanions` path (expired-CA prune + RDP listener rebind) NEVER installs a cert into a
trust-anchor store, never calls the bundle-add path, and runs strictly AFTER the CA-validated install
behind the same DEPLOY/admin/self-guard/wrong-box gates. `Test-CertDeployIsCa` (625bbfa2) is intact. No
new path/UNC input, no new XSS sink, expiry filter unchanged.
- **FLAG TO OWNER (P2, their code):** the module-level `confirm` string still reads "...never removes
  anything" while companions DO remove certs (CA-store prune + RDP store clear). The browser arm-dialog
  discloses removal, but a non-UI caller sees the false authorization text. Truthfulness/authorization
  integrity - worth fixing when they commit. (Also 2x P3: RDP rebind doesn't exclude self-signed; the
  legacy-keep allowlist is duplicated - both non-anchor, test-mitigated.)

## B. adsearch + adto - GREEN (all prior P1 DN-bind-redirect fixes hold)
Every operator filter value routes through RFC-4515 `Escape-LdapFilterValue`; the DN guard
`Test-Ad{Search,To}DnInLocalDomain` fronts EVERY credentialed bind (SearchBase, adto fix/validate) with
RFC-4514 escaping, local-domain suffix + DC-count pin, and `ReferralChasing=None` on all 8 searchers;
adto writes are triple-gated (admin-session + confirm-word + DN-guard, plus IAO allow-list); both views
render AD values through `textContent`/`createTextNode` (XSS-safe); no secret leak. 3 P3 nits (IAO RBAC
= process-owner [correct under loopback single-op model]; arbitrary in-domain plan DN [not escalation];
dead `esc` import) - informational, no exploit.

### P3 FIXED this cycle - DN guard rejects control chars (commit 2e6a4a55b)
.NET regex `$` also matches immediately BEFORE a trailing newline, so `OU=x,DC=AREA52,DC=MIL\n` slipped
past the component-boundary anchor. Not exploitable (the DC= suffix+count pin still forces a local bind),
but this guard is the security boundary that carried a prior P1 - control chars have no place in a DN.
Added `if ($Value -match '[\x00-\x1f]') { return $false }` before the anchor check, in all THREE
byte-identical copies (adto module-level, adsearch module-level, adsearch inline bare-runspace engine).
adsearch 3.3.5->3.3.6, adto 0.2.0->0.2.1, `tests/AdDnGuard.ControlChar.Tests.ps1` (12).

## C. Sweep - patchlib / sysadmin / biosfirmware / winrmbridge / history - GREEN
All host-token inputs regex-validated before WinRM; remote probes are static scriptblocks (no
interpolation); credentials only via `-Credential` splat (never on a command line/log); CSV exports go
through the shared formula-injection-safe `toCsv()`; view innerHTML sinks are static or `esc()`-escaped.
winrmbridge (the only module here with destructive actions) is admin-gated + self-guarded before any
session, with typed confirm words. One optional P3: history `host` field lacks the regex parity its
sibling `stale-hosts` has - verified non-exploitable (value only hits an in-memory string compare, never
a path/command). Deferred as cosmetic; can land opportunistically.

## Concurrent-work handling
The certdeploy WIP (4 files, +companions) stayed untouched; I committed ONLY my adsearch/adto/test paths
(scoped). Desktop untouched (blocked). No concurrent work swept.

## Verdict
Web GREEN and hardened; self-guard parity (loop 8) + DN-guard control-char tightening (loop 9) both
landed. The AD bind-redirect boundary is now clean against the .NET trailing-newline quirk. Only open
items: the Desktop-mirror backlog (blocked 4th cycle) and the owner's certdeploy P2 confirm-string gap
(flagged). Next cycle: re-check Desktop cleanliness; if still blocked, continue non-colliding Web
hardening (history regex parity is a cheap candidate) or a design pick.
