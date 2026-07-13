# Design - Loop 28 (Phase 2, cycle 24) - 2026-07-13

## Continue the Desktop-mirror backlog: the c2c field-script P2s (ledger rows 1-6, 8)
Loops 26-27 landed the safety-critical self-guard + correctness mirrors (WPT, upr, message, c2c KICKED).
The remaining CHECK rows are the older c2c field-script P2s from the 2026-07-12 delta audit - the
mandate's HIGHEST priority ("those scripts ORIGINATED in Desktop and almost certainly still carry the
same P2s"): mpam offline-Defender gate, PkiRdp Server-Auth EKU, Java vendor gate, BitLocker resume
escrow-first, MDE blob expiry, offline-Defender SHA256 pin.

## Why a sweep first (not a blind mirror)
The operator committed the Desktop C2C 2.4.x line + I just versioned 2.4.3 (PKI boxes + KICKED). The
2.4.x concurrent work OR the parked 2.5.0 security-mirror may already have incorporated some of these six
fixes. The loop-3 analysis found "5 of 6 present" in the 2.4.1 PREDECESSOR - but that was before the
operator's 2.4.x evolution. So each must be verdicted against the CURRENT committed 2.4.3, not assumed
present. A Sonnet sweep (this cycle) verdicts each PRESENT / ALREADY-FIXED / ABSENT with exact locations
+ the minimal fix.

## Approach
- Sweep -> for each of the six, PRESENT / ALREADY-FIXED / ABSENT in 2.4.3.
- For the PRESENT set, mirror them into a new versioned C2CNemesisTool 2.4.4 (Opus implements the
  hardenings from the Web c2c reference; I gate each - these are security-sensitive cert/malware paths,
  so I spot-verify the EKU OID, the publisher gate, the escrow ordering, the SHA256 fail-closed myself).
  Archive 2.4.3, config -> 2.4.4, PS 5.1 + BOM, scoped commit.
- ALREADY-FIXED -> ledger row CLOSED-BOTH (checked). ABSENT -> CLOSED-WEB-ONLY with reason.
- Never weaken an existing guard; keep the narrow prune / expiry guards intact.

## Decision rule
- A PRESENT PkiRdp WRONG-EKU (Client-Auth instead of Server-Auth) or a BitLocker enable-before-escrow /
  recovery-key leak = highest severity, mirror this cycle. Unpinned/unvalidated Defender push = high.
  Java loose-removal = medium. MDE advisory = low.
- If several are PRESENT, land them together in one 2.4.4 (they share the fix-worker), gated per-fix.
Every touched row ends CLOSED-BOTH or CLOSED-WEB-ONLY. Scoped commit; Desktop is clean so no sweep risk.
