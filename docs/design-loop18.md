# Design - Loop 18 (Phase 2, cycle 16) - 2026-07-13

## Why: a different lens on the highest-blast-radius tool
14th cycle with both real backlogs operator-deferred and both collision zones frozen. The Web surface is
audited end to end, the top security properties are regression-locked (loops 13-14), and the two
destructive tools that shipped without tests are now covered (loops 16-17). Rather than drift into
low-value read-only-tool coverage, this cycle applies the one lens NOT yet used: a deep CORRECTNESS /
LOGIC audit of `c2c` (3460 lines) - the largest, most destructive tool (Comply-to-Connect quarantine
predictor + multi-pillar remediation orchestrator).

## Why this is not churn
Prior c2c passes cleared the SURFACE classes (injection, XSS, gating, self-guards). A correctness lens is
genuinely different: it hunts bugs where the code is well-formed and safe but computes the WRONG answer
or leaves a host half-remediated. On a 3460-line destructive orchestrator that is real, unexhausted risk:
- **Verdict miscategorization** (top): the tool predicts C2C quarantine per the TASKORD 26-0822 model (5
  quarantine pillars + 2 audit-only + Tanium=attest). A pillar assigned the WRONG tier is a silent
  logic bug a surface audit skips - and a QUARANTINE pillar mislabeled Audit/Info would FALSELY CLEAR a
  host that will actually be quarantined (dangerous false-negative: the operator believes they are
  compliant and gets quarantined anyway).
- **Pool-runspace source injection** (known gotcha, per memory): the verdict + java logic ride as
  `$script:*Src` strings dot-sourced into bare workers; a worker path missing the injection -> the
  function is absent -> blank/ERROR verdict or a fail-open fix.
- **Per-pillar fix targeting**: each fix must intersect the submitted hosts against the CSV-re-derived
  flagged set as an allow-list. A set-logic / hostname-canonicalization bug could fix a host for a pillar
  it was never flagged for, or silently drop one that should be fixed; run-all could cross-wire pillars.
- **Partial-failure honesty**: a BitLocker/Defender/PKI fix reporting SUCCESS on a partial apply, or the
  AMRunningMode guard inverted (force-RTP a Passive/EDR-Block box it should leave protected).

## Decision rule
- A verdict false-clear, a wrong/dropped destructive target, a false-success, or a missing source
  injection = **P1**, fixed this cycle (gated, tested, suite green). Meaningful logic error = P2.
- If the audit finds a fix, I add a targeted regression test for the corrected logic (the verdict/tier
  map and targeting set-logic are pure and unit-testable). If clean, a documented deep-correctness
  all-clear on the crown-jewel tool - real assurance, not churn.

Right-sized to ONE focused Opus reviewer. Non-colliding: c2c is committed, not the certdeploy WIP zone.
Every P1/P2 is spot-verified against the code by me before any fix.
