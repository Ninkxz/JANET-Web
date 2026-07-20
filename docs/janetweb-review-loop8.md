# JANET Web — review loop 8 (2026-07-20)

**Baseline:** 1089/1089 at loop-7 close (`c0d8c48`); tree untouched between loops
(baseline re-run confirms). Local-only commits.

## Self-review of loop-7 (`928d1ba` report sandbox-resource-free static test) — clean
Test-only, no product code. Verified non-vacuous: the `<script>` anchor assert requires a
real match (report not empty), and the CSP assert targets the `$reportCsp` assignment so it
fails if `sandbox allow-scripts` is ever removed. Single-file, HTML-context-anchored
patterns (no PS-var false positive). No Opus agent spent — a 12-assert static grep with no
product change is below the adversarial-review threshold; documented here instead.

## Opus adversarial deep-dive: c2c (C2C Nemesis v1.15.1, destructive multi-pillar) — verdict GREEN

First loop review of the tool. All destructive pillars funnel through ONE dispatcher → ONE
fix fn → ONE worker → ONE remote round-trip, making the guard surface small and auditable.
Checked-CLEAN with file:line evidence (on record):
- **BitLocker escrow order + fail-closed + key-leak (the headline):** exact
  add→escrow(Entra→AD)→enable order; on both-escrow-fail a protector WE added is removed and
  Enable is never reached; post-enable state re-read (still-decrypted = FAIL). The recovery
  password is NEVER read — every KeyProtector access reads only `.KeyProtectorType` /
  `.KeyProtectorId` (GUID); no `.RecoveryPassword` access anywhere; Detail says only
  "escrowed to Entra|AD". No leak into any result/report/audit/log. Suspended-OS resume is
  escrow-gated (no TPM-only lockout).
- **Self-guard + wrong-box on EVERY pillar** (structural via the shared fan-out): dispatcher
  dropped before any runspace (`Test-JanetC2cHostIsSelf`, all NIC IPv4s); wrong-box compares
  remote `$env:COMPUTERNAME` after session open, before the fix runs — mismatch = SKIPPED,
  thrown probe = FAILED (fail-closed); IP-literal carve-out correct.
- **Confirm-word** `-cne 'FIX'` is the FIRST statement, before any CSV parse / host contact,
  on run-all too.
- **Target-token allowlist** `^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$` applied at every ingress AND
  re-applied to the resolved dispatch list; CSV tokens serve only as a HashSet filter, never
  reach a WinRM connect.
- **Cert push:** expired anchors excluded (except the audited LegacyIntermediates allowlist);
  persistence re-verified with a fresh ReadOnly handle → NOT VERIFIED on added-but-absent.
- **No RCE:** no Invoke-Expression; the 3 Start-Process sites use fixed paths / constant args /
  strict-GUID-gated msiexec; Defender offline pkg has an Authenticode + TOCTOU SHA256 re-hash.
- **No fail-open:** every pillar catch → FAIL; FVE-policy write error aborts the enable.

### The one gap — P3 orphan protector — **FIXED this loop** (`fb7611f`, c2c **1.15.1→1.15.2**)
In `$escrowFirst`, if `Add-BitLockerKeyProtector` succeeds but its return yields no resolvable
protector id (`$newKpId` blank — near-impossible), the escrow-failure cleanup's
`if ($newKpId){Remove}` was skipped, orphaning the just-added UNescrowed RP protector on a
still-decrypted volume. Already fail-closed (no Enable, no key leak, no lockout) — a
defense-in-depth gap in the most safety-critical path. Fix: on `$weAdded` + blank id,
re-enumerate the volume's RP protectors and remove ONLY those absent from the pre-Add
`$beforeIds` snapshot — same safety basis as the add-time diff, so a pre-existing escrowed
protector is never stripped. **Strictly additive**: runs only in the previously-orphaning
state; every id-resolved path is byte-unchanged (zero regression risk).
Tests (`C2c.Enable`): `bothfailblankid` proves the orphan is re-enumerated + removed
(`{LATE-KP}`), Enable unreachable, FAIL, no leak; (e3) proves a pre-existing protector is
never touched; (e) now also pins the resolved-id remove (`{NEW-KP}`).

Deferred P3 (accepted): memoized local identity can stale on a mid-lifetime DHCP change —
negligible on a server-hosted dispatcher (name/FQDN still catch self). → ranked note only.

## SECRET parity
- SECRET parity: the c2c orphan-protector cleanup — the JanetSec c2c fork carries the same
  `$escrowFirst` block; mirror the fix + `bothfailblankid` scenario.
- Carried (unexecuted): Host-header guard (+extended cases), report-preview CSP sandbox
  (+resource-free guard), wpt audit-Skipped, session disarm, honest Chrome/Edge + worker
  passthrough, upr refuse coverage + worker comment.
