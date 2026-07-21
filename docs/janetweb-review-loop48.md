# JANET Web — review loop 48 (2026-07-21)

Fable-inline synthesis + one Fable deep-dive worker on certdeploy. Self-review of loop-47 → **GREEN**.
Baseline: loop-47 authoritative **1390** green (confirmed).

## Self-review of loop-47 (c2c PARTIAL audit fail-close) — GREEN
`Get-C2cHostAuditResult` (FIXED→Success; NO CHANGE/SKIPPED/OFFLINE→Skipped; else→Failure) matches the direct
call; itemCount FIXED-only; NOT VERIFIED→Failure (consistent with loop 44). 58 c2c + 1390 confirm no regression.
Nothing to reopen.

## Workstream: fresh false-clean deep-dive on certdeploy (Cert Deploy, 110KB, v1.4.0)
A Fable worker read the full 1654-line module and traced every path that can emit INSTALLED / ALREADY / ALL
PRESENT / None detected; I re-verified F1 in-code. certdeploy is **solidly fail-closed** on its core: the deploy
re-verify opens a *fresh* ReadOnly store handle and per-thumbprint HashSet-compares (`:402-416`), INSTALLED
structurally requires `Added > 0`, a throwing/empty re-read dumps all added thumbprints into NotVerified →
NOT VERIFIED → audit Failure; thumbprint compares are hex-stripped + OrdinalIgnoreCase everywhere; expiry never
converts absence into presence; CHECK on an unreadable *store* fails NOISY (every cert MISSING); unreachable/
cred-fail/cancelled never fold compliant. The dive found two real false-cleans.

### F1 (FIXED this loop) — an undeserialized/empty want-set → ALL PRESENT for an uninspected host
`:904-914` → reader `:551-554`. The CHECK worker parses the wanted thumbprints from JSON on the target
(`$want = $ThumbJson | ConvertFrom-Json`, catch → `$null`) and calls `Get-CertDeployStoreMissing -WantThumbs
$want`. A null / undeserialized want-set makes the reader skip every store group (`$wantTps.Count -eq 0 →
continue`, `:552`) — **nothing compared** → 0 present / 0 missing / no `Err`. The admin-side Err guard (`:924`,
which the comment says exists precisely to "never report a store we never actually read as ALL PRESENT") only
covered "helper unavailable", so this fell through to `Ok=$true` → **ALL PRESENT** for a host whose stores were
never inspected — the operator sees a compliant trust-anchor posture that was never checked, and no roots get
deployed. Trigger: any remote `ConvertFrom-Json` failure / a payload missing the three props (a hardened/CLM
target where the reader dot-source succeeds but the JSON pipe errors). **FIXED** (certdeploy 1.4.0 → 1.4.1):
`Get-CertDeployStoreMissing` now counts the usable (hex, non-blank) thumbprints across Root/CA/Disallowed and
returns an `Err` when that count is 0 — the bundle always carries certs, so a zero-count want-set is a
deserialization failure, not "nothing to check". The check worker already maps `Err` → CHECK ERROR. The guard
lives in the injected store-reader source, so it fails closed both remotely and locally.

### Ranked backlog (worker-CONFIRMED unless noted; re-verify before acting)
- **item58 (F2, MED-HIGH)** — DEPLOY: a wanted cert absent from the store but rejected by the trust-anchor
  (non-CA) guard is `$rejected++; continue` (`:382-387`) — not counted failed or NotVerified — so the classifier
  (`:424-432`) reads Added=0 → **ALREADY** ("all present") or, mixed, **INSTALLED** (audit Success), while the
  rejected anchor is genuinely absent; the `| REJECTED n` rides only in Detail. Trigger: any Root/CA-destined
  cert without BasicConstraints CA=true — notably an **X.509 v1 root** (no extensions → fail-closed "not a CA"),
  rejected on every host forever while every deploy reads ALREADY. Fix: a wanted-but-refused-and-absent anchor
  must not produce an "all present" status/audit (a distinct REJECTED status, out of the clean bucket).
- **item59 (F3, LOW/advisory)** — scan-cert-management: every detection primitive is `-ErrorAction
  SilentlyContinue` (`:1462`/`:1470`/`:1492`), so a session-capable but registry-denied credential yields
  `irName=''`/`$gp=0`/`Err=''` → **'None detected — a manual .Default push WILL persist'** (`:640`/`:664`),
  when InstallRoot/GPO pruning could be present and would strip on reboot. Fix: distinguish "read the
  reconcilers and found none" from "couldn't read the reconcilers" (a probe error → CHECK ERROR / unknown).
- **F4/F5 (SPECULATIVE, structural)** — a bundle entry with a blank `t` thumbprint escapes the re-verify yet
  counts toward INSTALLED (`:373`/`:390`/`:412`), and a remote bundle deserializing to zero items in all three
  groups classifies ALREADY ("all 0 already present", `:360`/`:431`). Neither has a realistic trigger
  (`X509.Thumbprint` is always populated; the admin-side abort guarantees pushCount ≥1), but both lack a
  `Total==0 → FAIL` backstop / key-off-the-recomputed-thumbprint. Defensive-only; noted, not separately ranked.

## SECRET parity
- **SECRET parity:** the JanetSec certdeploy fork (if present) shares `Get-CertDeployStoreMissing` — mirror the
  want-set-empty → Err guard.
