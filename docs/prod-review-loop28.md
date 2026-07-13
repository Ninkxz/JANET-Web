# Production Review - Loop 28 (Phase 2, cycle 24) - 2026-07-13

Continued the Desktop-mirror backlog: the c2c field-script P2s (ledger rows 1-6, 8) - the mandate's
HIGHEST-priority mirror ("those scripts ORIGINATED in Desktop"). A Sonnet sweep verdicted each against
the CURRENT committed Desktop C2C 2.4.3 (the operator's 2.4.x line may have incorporated some); an Opus
agent mirrored the PRESENT ones; I personally spot-verified every security-critical bit.

**Rating: GREEN.** No new Web findings (Web audited/green 908/908, unchanged). Five security hardenings
mirrored to Desktop C2C 2.4.4; the sixth (Java) verified already-correct. No regressions.

## Sweep verdicts (rows 1-6, 8 against C2CNemesisTool_2.4.3)
| Row | Fix | Verdict | Outcome |
|-----|-----|---------|---------|
| 2 | PkiRdp Server-Auth EKU + HasPrivateKey + bind-first | **PRESENT (CRITICAL)** - wrong EKU (Client-Auth ...3.2), no HasPrivateKey, clear-before-bind | MIRRORED |
| 4 | BitLocker resume escrow-first | PRESENT (Enable hardened, RESUME not) | MIRRORED |
| 6/8 | Offline-Defender SHA256 pin / fail-closed / -LiteralPath | PRESENT (ran mpam unverified, TOCTOU) | MIRRORED |
| 1 | mpam product-identity gate | PRESENT (sig/signer/size ok, no product-id) | MIRRORED |
| 5 | MDE blob expiry advisory | PRESENT (path exists, no expiry check) | MIRRORED |
| 3 | Java Oracle/Sun gate + strict-GUID | **ALREADY-FIXED** (identical to Web) | CLOSED-BOTH (no change) |

## LANDED - C2CNemesisTool 2.4.4 (commit 472daff4) -> rows 1/2/4/5/6/8 CLOSED-BOTH
- **PkiRdp (row 2, CRITICAL):** was Client-Auth EKU 1.3.6.1.5.5.7.3.2, no HasPrivateKey, cleared the RDP
  store BEFORE binding (dead-listener window). Now Server-Auth 1.3.6.1.5.5.7.3.1 + HasPrivateKey, BIND
  FIRST inside try/catch; clears run only on a successful bind, a failure leaves the old listener intact.
  *Spot-verified: EKU :3229, HasPrivateKey :3228, bind :3237 BEFORE clears :3238-39.*
- **BitLocker resume (row 4):** could resume into a TPM-only, UNescrowed state. Now escrows (Entra/AD)
  before resume, SKIPs if escrow fails. *Spot-verified: `$escrowFirst` :2860 before Resume-BitLocker :2882.*
- **Offline-Defender SHA256 (rows 6/8):** ran mpam-fe.exe unverified after copy. Now pinned admin-side +
  re-hashed on target before exec, fail-closed on missing/mismatch, -LiteralPath. *Spot-verified: pin
  :1277, worker param :2407 + AddArgument tail :5313 ALIGNED, fail-closed gate :3446, ArgumentList↔param
  :3438/3439.*
- **mpam product-id (row 1):** *Spot-verified :1262 (OriginalFilename~mpam / ProductName~antimalware|defender).*
- **MDE advisory (row 5):** *Spot-verified :3057-3059 (X509Certificate2 from blob, IN PROGRESS on expiry).*
2.4.3 -> 2.4.4; archived; config repointed; PS 5.1 parse-clean (0 errors) + BOM. Java/expiry-filter/prune/
self-guard/confirm-word untouched.

## Desktop-mirror backlog status
The c2c field-script P2 block (rows 1-6, 8) is now fully CLOSED. Combined with loops 26-27 (WPT/upr/
message self-guards + c2c KICKED), the security-critical + originated-in-Desktop mirrors are DONE. The
remaining CHECK rows (9, 10, 15, 17-20, 22-23) are lower-severity design/parity items - a later sweep
verdicts each (several - e.g. the `,$set` HashSet self-guard rows 9/10 - are likely already satisfied by
the Test-*HostIsSelf helpers just mirrored). Web unchanged/green (908/908).

## Verdict
The single most security-critical Desktop mirror of the session - the PkiRdp wrong-EKU/dead-listener bug
plus BitLocker-escrow and malware-package pinning - is landed and gated. Rows 1-6, 8 CLOSED-BOTH.
