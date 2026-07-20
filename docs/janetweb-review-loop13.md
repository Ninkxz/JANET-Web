# JANET Web — review loop 13 (2026-07-20)

**Baseline:** 1121/1121 at loop-12 close (`bbcd33c`); tree untouched between loops.
Local-only commits. *(Operator mid-loop: switch the loop to 15-min cadence + prefer the
Fable model for agents going forward — applies from loop 14.)*

## Opus self-review of loop-12 (`68ca436` adto write-guards) — verdict GREEN → 1 gap fixed

Deeper pass than the loop-12 Sonnet sweep. Confirmed: SERVER_TRUST (0x2000) genuinely catches
a writable DC (UAC 0x82000), no false-positive over-block of a workstation (WORKSTATION_TRUST
0x1000 doesn't set the bit); the `"0"+` adminCount trick handles absent (→0, not refused) and
explicit-0 (de-protected → not refused) correctly; F2's `[string]`-cast-before-`-match` avoids
the multi-valued `-match` hazard; F3 audit shape matches the consumer contract; the normal path
is byte-for-byte unchanged.
- **P3 → FIXED (`0331e66`, adto 0.2.2→0.2.3):** a **read-only DC (RODC)** slipped the F1 guard
  — it carries `PARTIAL_SECRETS_ACCOUNT` (0x04000000), NOT `SERVER_TRUST`, and DCs aren't
  adminCount-protected, so an RODC computer object could be disabled (breaks a branch office's
  auth). Added the bit to the `$isDc` test + made the adminCount parse fail-CLOSED (refuse on
  an unparseable value). Test: an RODC-shaped object is now PROTECTED.

## Correctness deep-dive: reports engine (the operator's daily deliverable) — verdict YELLOW → fixed

A CORRECTNESS (not security) review — the risk is a silent MISCOUNT that misleads remediation
priority, which nobody notices. Verified CORRECT: **KEV match is exact, not substring**
(`CVE-2021-4428` ≠ `CVE-2021-44228`, full-token regex + HashSet.Contains); empty KEV catalog is
surfaced (warn banner, not a silent all-clear); **CSV formula-injection guard present on all
report deliverable exporters**; div-by-zero guarded everywhere (VPH/NetworkPct/squadron%);
Dirty-30 renders Tenable's own order (no sort/truncate bug); the CORA host dedup + AMBIGUOUS
collision guard (loop39/40) holds; the SLA ledger `firstSeen` key is already normalized.

**P2 (systemic) — FIXED (`e0a5d51`, reports 2.14.20→2.14.21):** CORA was taught (loop39) to
dedup hosts by the normalized audit key `Get-ReportsAuditHostKey` (IPv4 whole, else short-upper —
`WEB01` and `web01.dom` fold to ONE host), but ~7 sibling host tallies kept keying on the RAW
hostname. So the SAME host set reported DIFFERENT host totals across the tool whenever short +
FQDN forms mixed (the exact AFNET condition the collision work exists for) — and the posture
digest was internally self-contradictory (deduped `UniqueHosts` vs raw `HostsWithKev` in the
same file). Normalized the **headline** count sites (key on the normalized value, keep the raw
name for per-finding display): posture-digest KEV host map (`:7225`), sla-aging per-host
(`:6157`), command-brief KEV hosts (`:7050`), remediation-plan Hosts/KevHosts (`:1833`),
kb-needed (`:5040`). Test `Reports.HostCountAgreement.Tests.ps1`: a two-name-form host reports 1
host across sla-aging + kb-needed (they agree) and the digest's `HostsWithKev` == 1 (proven via
the digest CSV).

Accepted P3s: IAVM-map writer omits the CSV formula guard (config file, CVE regex-validated, low
impact); unknown severity counted in totals but not the 5 tiles (edge); SLA due-day-inclusive
boundary (by-design). → the IAVM CSV guard is worth a small follow-up.

## New ranked items
- **Item 11 — complete the reports host-key normalization sweep:** the remaining lower-impact
  count sites use the same raw-key pattern — the thirdparty/iavm app-aggregate (`~4773`/`4777`),
  export-poam per-host counter (`~6246`), and verify the command-brief/planner ACTION paths feed
  the fixed aggregations. Bounded follow-up; not worth touching every corner of the 7,410-line
  file in one pass.
- **Item 12 — IAVM-map CSV formula-injection guard:** `Write-ReportsIavmMap` (`:872`) quote-wraps
  but omits the `=+-@` prefix guard every other exporter carries. Low impact but a guard
  regression vs the file's own standard.

## SECRET parity
- SECRET parity: adto RODC guard extension + fail-closed adminCount (JanetSec adto fork, if
  present, shares the write path).
- SECRET parity: reports host-count normalization (JanetSec reports fork shares Get-ReportsAuditHostKey).
- Carried (unexecuted): all prior SECRET-parity items.
