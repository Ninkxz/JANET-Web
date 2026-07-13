# Design - Loop 21 (Phase 2, cycle 19) - 2026-07-13

## Why: the correctness lens on the last large complex tool
The deep CORRECTNESS lens is now 3-for-3 - it found a real, surface-audit-missed logic bug in each of the
three destructive orchestrators (c2c KICKED rollup, acas UNCONFIRMED false-green + empty-filter reboot,
wpt missing self-guards). This cycle finishes the sweep of the big tools with `reports` (7236 lines,
v2.14.16) - the reporting/analytics tool (POA&M, IAVM burndown, closure, campaign, Dirty30, posture
digest, routing).

## Value calibration (honest)
reports is READ-ONLY (no destructive action) and is already the MOST-tested tool (11 Reports.*.Tests.ps1),
so the marginal find-rate is lower than the destructive audits. But it is the last large complex tool and
its NUMBERS drive real compliance decisions and remediation work, so a wrong answer still matters:
- **Closure false-positive (top)**: a finding wrongly marked remediated silently drops a still-open
  vulnerability off the compliance report - the worst outcome for a read-only tool (a host absent from a
  newer scan treated as "fixed" vs "not scanned"; a plugin/CVE key mismatch closing the wrong item; a
  host-key collision).
- **Host-key attribution / dedupe**: two different hosts collapsing to one key (FQDN/short/IP/case), or
  one host splitting in two - miscounting host totals or merging findings.
- **Routing**: a finding sent to the wrong fixer (OS finding -> ACAS instead of Windows Upgrade; an
  actionable finding marked non-actionable and dropped).
- **IAVM/CVE mapping + burndown math**: a CVE mapped to the wrong IAVA, an unmapped CVE dropped, a
  burndown percentage over the wrong denominator, a "closed this period" double-count.
- **Severity/counts + export fidelity**: a CVSS-band off-by-one, or an aggregate that doesn't match its
  detail rows.

## Decision rule
- A false closure hiding an open vuln, a wrong compliance number, or a misrouted/dropped actionable
  finding = **P1**, fixed this cycle (gated, tested, suite green). Meaningful logic error = P2.
- Any fix gets a targeted regression test (reports' helpers are pure and heavily unit-tested already, so
  a new case slots into the existing pattern). If clean, a documented deep-correctness all-clear that
  finishes the big-tool sweep.

One focused Opus reviewer, told to hunt the gaps the 11 existing test files MISS (not re-report surface).
Non-colliding: reports is committed. Every P1/P2 spot-verified by me before any fix.
