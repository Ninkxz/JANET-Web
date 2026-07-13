# Production Review - Loop 26 (Phase 2, cycle 22) - 2026-07-13

**Milestone: the Desktop-mirror mandate is UNBLOCKED** (see design-loop26.md). After ~20 cycles blocked
by a concurrent uncommitted telemetry sync, the operator's "commit everything" landed the Desktop tree
(HEAD ed02604f) + pushed both repos to gitea.bth0mp.com. So this cycle finally started clearing the
deferred Desktop-mirror backlog. No Web CODE change (Web is exhaustively audited/green at 908/908 from
the prior cycle); all work this cycle is Desktop + ledger.

**Rating: GREEN.** One high-value Desktop mirror LANDED, two ledger rows CLOSED-WEB-ONLY (verified
absent), three CONFIRMED-PRESENT and queued with exact locations. No regressions.

## Sweep - Sonnet mapped the highest-value safety mirrors against the current committed Desktop tools
| Web fix | Desktop tool | Verdict | Outcome |
|---------|--------------|---------|---------|
| wpt reboot self-guards (row 34) | WorkstationPatchingTool_6.5.25 | **PRESENT** (0 self-guard, all 4 reboot actions) | **MIRRORED this cycle** |
| upr uninstall self-guard (row 13) | UnsupportedProductRemediator_1.1.4 | PRESENT (`$btnUDoIt.Add_Click` :2673, only DNS-mismatch guard) | QUEUED (fix ready) |
| message send self-guard (row 25) | RemoteMessageTool_1.3.3 | PRESENT (`Get-Targets` :1225 / `$btnSend` :1858 unfiltered) | QUEUED (fix ready) |
| c2c KICKED rollup (row 31) | C2CNemesisTool_2.4.2 | PRESENT (`$script:C2cFixBlock` rollup :3424 omits KICKED) | QUEUED (one-line fix) |
| acas UNCONFIRMED false-green (row 32) | ACAS Nemesis Tool_1.10.14 | **ABSENT** (one `$resultStr` drives BOTH row + audit - no split possible) | **CLOSED-WEB-ONLY** |
| acas reboot empty-filter (row 33) | ACAS Nemesis Tool_1.10.14 | **ABSENT** (no reboot subset-filter feature; always dispatches the whole group) | **CLOSED-WEB-ONLY** |

## LANDED - WorkstationPatchingTool 6.5.26 dispatcher self-guard (commit 56193af7) -> row 34 CLOSED-BOTH
The Desktop WPT had NO self/local-box exclusion, so an operator whose target list included the JANET
dispatcher / their own workstation would reboot it mid-dispatch. Mirrored the Web wpt fix (loop20) +
reused the ACAS Nemesis Tool's `Get-NemLocalIdentity`/`Test-NemHostIsSelf` pattern:
- Added global `Get-WptLocalIdentity` + `Test-WptHostIsSelf` (cached HashSet: COMPUTERNAME/FQDN/all NIC
  IPv4/loopback; IPv4-literal-safe). *Spot-verified: helper at :1657, `^127\.` + `TryParse`-gated
  shortname branch.*
- Drop self BEFORE dispatch at all 4 reboot-capable sites (Reboot Selected :12690, Scheduled :7600,
  KB-with-reboot :7846 [only when reboot not suppressed], STIG reboot-after :9119 [guards the schedule]).
  Read-only paths unguarded. *Spot-verified all 4 call sites drop self.*
- 6.5.25 -> 6.5.26 (+changelog); archived 6.5.25; config repointed; PS 5.1 parse-clean (0 errors) + BOM.

## Verdict
The Desktop mirror is moving again. This cycle: 1 landed (row 34 CLOSED-BOTH), 2 CLOSED-WEB-ONLY (verified
absent), 3 CONFIRMED-PRESENT + queued (rows 13/25/31 with exact locations + ready fixes). Next cycles land
the queued three (each a new versioned Desktop tool). Web unchanged/green (908/908).
