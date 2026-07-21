# JANET Web — review loop 28 (2026-07-21)

**Baseline:** 1247/1247 at loop-27 close (authoritative, 0 fail). Fable-inline. Local-only commits.

## Self-review of loop-27 (`f20faab` acas KB-match+null-rv port, `c891952` docs) — verdict GREEN (inline)
The port only tightens matching and fail-closes a null ReturnValue — strictly safer. Pinned by
`Acas.KbMatch.Tests.ps1` (mirror of wpt) + the new FixVerify2 acas NULL case, the destructive guards
untouched, 180 acas+FixVerify2+FixGuards green, authoritative 1247/0-fail. GREEN.

## Workstream (roadmap item 19, the LAST confirmed acas false-clean) → FIXED
`schedule-reboot` fires `shutdown.exe /r /t 300` — a reboot 5 minutes out and ABORTABLE (`shutdown /a`),
and rc=1190 "already scheduled" also returns OK (`JanetWeb.acas.psm1:2134/2155`). But the fan-out
booked a **VulnPatched Success** audit at SCHEDULE time (`:3384`, pre-fix `-AuditAction 'VulnPatched'`).
An inspector reading the audit log would see a host recorded as *patched* when all that happened was a
reboot got queued (and might be aborted, or the staged update might not apply). That's a false
compliance record — the last confirmed false-clean from the loop-25 acas deep-dive.

Evidence it's an anomaly: `verify-post-reboot` (`:3422`), which actually CONFIRMS the reboot happened,
already audits `TouchHost` — the more-confirmed action is the more-conservative audit, inverted.

**Fix** (acas **1.11.8 → 1.11.9**): demote schedule-reboot to `-AuditAction 'TouchHost'`. Scheduling a
reboot is a touch (contacted + queued the host), not a confirmed patch; `VulnPatched` stays on the
actual patch-install / update-profile confirmations (kb-install MSU exit-0, the update engine), which
book their own honest audits. One line. No guard weakened — the schedule-reboot self-guard (exercised
by `Acas.SelfGuard.Tests.ps1`), the DNS wrong-box hard-abort (`:2145`), and the admin-session gate
(`Server.Gate.Tests.ps1`) are all intact; 194 acas + guards + gate tests green.

`Acas.RebootAudit.Tests.ps1` (5) isolates the schedule-reboot handler block and asserts it audits
`TouchHost` and NOT `VulnPatched`, that verify-post-reboot stays `TouchHost`, + the exact 1.11.9 pin
(loop-27 KbMatch 1.11.8 exact → floor).

## acas false-clean cluster — COMPLETE (confirmed items)
The loop-25 acas deep-dive found 4 false-cleans + 2 speculative + 1 refutation. All CONFIRMED ones are
now fixed: kb-install trigger/partial (loop 25), verify-inflates-PATCHED (loop 26), kb-install KB-match
+ null-rv (loop 27), schedule-reboot audit timing (this loop). Item 6 refuted. Only item 20 remains —
SPECULATIVE, no reachable trigger in the shipped workers (a latent hazard for a future profile that
emits stray output). The acas remediation tally + audit surface is honest on every confirmed path.

## SECRET parity
- SECRET parity: the schedule-reboot TouchHost audit — the JanetSec acas fork shares the
  schedule-reboot handler; mirror the `-AuditAction 'TouchHost'` demotion.
- Carried (unexecuted): acas kb-install KB-match + null-rv, honest verify row + kb-install status;
  wpt honest M365 C2R verify + kb-install label + KB-match; SLA bucket; host-key fold; wrong-template
  hint; CSV-ingestion + routing.
