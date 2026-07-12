# Production Review - Loop 8 (Phase 2, cycle 6) - 2026-07-12

Desktop-mirror mandate remains BLOCKED (the concurrent suite-wide "Live-Usage Snapshot" telemetry
sync still holds `X:\J.A.N.E.T` dirty - 19 uncommitted items, every `Tools\*.ps1` live-modified,
incl. `RemoteMessageTool_1.3.3.ps1`, the exact twin this cycle's fix would mirror into). So the cycle
value was a suite-wide SELF-GUARD PARITY SWEEP - enumerate every destructive host-targeting engine and
confirm each drops the dispatcher before fan-out. 2 Opus agents: (A) re-verify the loop-7 delta +
full suite; (B) the parity enumeration + fix the one gap found. Every P2 spot-verified.

**Rating: GREEN.** No P1/P2/P3 in the loop-7 delta (audit A: certdeploy CA-check + reports P3s are
correct, additive, non-regressive). One pre-existing self-guard gap found + fixed (`message` send).
Suite 806/806 (789 loop-7 baseline + 7 new message tests + 10 from a concurrent certdeploy WIP).

## A. Re-verify - loop-7 delta SOUND (no regressions)
- **certdeploy CA-check** (`625bbfa2`): `Test-CertDeployIsCa` fires only on the anchor stores
  (Root/CA `Anchor=$true`; Disallowed `Anchor=$false` untouched); fail-closed on null/throw/absent
  BasicConstraints; a rejected cert `continue`s AFTER `wantedTps.Add` but BEFORE `addedTps.Add`/`$st.Add`
  so accounting never inflates `verified`. Legit CA still installs (non-breaking). The two edited
  fixtures add `CA=true` to `New-TestCert` to exercise mechanics - assertions unchanged, not gutted.
- **reports P3s** (`82c45b8c`): all 10 ACAS-findings CSV cells now run through `$guard`; 10-col header
  unchanged (no shape change); legit values (numeric PluginID, "Critical", ISO dates) pass verbatim.
  `Get-WeeklySafeFileName` strips `[^A-Za-z0-9_\-]` from Enclave, empty->`ENC`.
- 22 tools, 23 modules import 0-fail; certdeploy 1.3.0 / acas 1.11.1 / wpt 6.6.0 live; merged guards
  (acas self-guard, fail-closed Java gate, shared javafix engine, c2c guards) all inside the green suite.

## B. Self-guard parity sweep - `message` was the ONLY gap (fixed)
Enumerated all 16 modules with a `destructive=$true` action. Every host-targeting fan-out already
drops self EXCEPT `message`:

| Verdict | Modules |
|---------|---------|
| Self-guarded (drop before fan-out) | restart, remoteadmin, winupgrade, secureboot, certdeploy, wpt, acas, c2c, upr*, pkginstall*, adto**, winrmbridge, beta |
| N-A (no host fan-out) | kev (writes local KevCatalog.txt), dhcp (edits a purpose-built DHCP *server*, not an OS state-change on the console host) |
| **GAP -> FIXED** | **message (send)** |

\* upr/pkginstall use a wrong-box COMPUTERNAME guard (documented). \*\* adto uses a DN-domain guard
`Test-AdToDnInLocalDomain`. `beta` (unlisted in the brief) was checked - already wired
`Test-JanetBetaHostIsSelf`.

**Fix (`message` 1.3.3 -> 1.3.4, commit `5699bfb6`):** the destructive `send` action WinRM-connected to
every target and popped msg.exe on all interactive sessions, with no dispatcher self-guard - a target
resolving to this box (WinRM loopback) would message the JANET console host itself. Added
`Get-JanetMessageLocalIdentity` (cached case-insensitive HashSet: shortname/FQDN/all NIC IPv4/loopback)
+ `Test-JanetMessageHostIsSelf` (IPv4-literal-safe: exact NIC-IP set match or `^127\.`; shortname-alias
branch gated behind `TryParse` so a literal never aliases). Drop is gated to `send` only, runs BEFORE any
session opens, short-circuits if empty; read-only `ping` stays self-inclusive (no over-drop, proven
end-to-end). `tests/Message.SelfGuard.Tests.ps1` = 7, all green. No existing guard weakened.

## Concurrent-work handling (reported, nothing swept)
Mid-cycle a concurrent `bth0mp` session began an uncommitted certdeploy feature in prod
(`certdeploy.psm1` + `certdeploy.view.js` + `CertDeploy.ExpiryVerifyScan.Tests.ps1` modified, new
`CertDeploy.Companions.Tests.ps1` - +10 tests). My first full run caught a test file mid-write -> a
single transient failure that did NOT reproduce (re-run 806/806). Per the hard rule I committed ONLY my
own paths (`message.psm1` + its test, scoped) and left the certdeploy WIP untouched. My commit is
isolated at HEAD; their work sits uncommitted on top.

## Desktop parity - message self-guard = BLOCKED-DESKTOP-WIP
`RemoteMessageTool_1.3.3.ps1` is the exact Desktop twin and DOES share the gap - but it is one of the 19
files the concurrent telemetry sync is live-rewriting (shows `M`). Versioning it (new `_1.3.4` + archive
+ config repoint) would collide, so the mirror is deferred until `X:\J.A.N.E.T` is clean. Ledger row 25
= **BLOCKED-DESKTOP-WIP** (defect confirmed present, fix ready, awaiting the owner to commit the sync).
This is the 3rd consecutive cycle (loops 6-8) the Desktop-parity mandate is blocked by that sync.

## Verdict
Web is GREEN and self-guard parity is now COMPLETE across all destructive host-targeting engines. The
loop-7 delta holds. The only open item is the Desktop mirror backlog, blocked suite-wide by a concurrent
sync - reported every cycle, never swept. Next cycle: re-check Desktop cleanliness; when clear, land the
backlog (message 1.3.4 self-guard mirror + ADSearchTool DN-guard [highest-value] + the rest).
