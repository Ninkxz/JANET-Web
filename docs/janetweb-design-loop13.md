# JANET Web — design loop 13 (2026-07-20)

## Decision 1 — diversify to a CORRECTNESS deep-dive, not another security one
Twelve loops covered the destructive (WinRM + LDAP) security surface thoroughly. The highest
remaining operator value isn't a P3 on a rarely-used destructive tool — it's the *numbers* in
the reports the operator reads every day. A silent miscount there misdirects patching and
nobody notices (worse than a crash). So loop 13's workstream is a correctness review of the
reports engine. Different analytical mode, different bug class — and it found a real systemic P2.

## Decision 2 — fix the HEADLINE host-count sites, rank the tail
The deep-dive found ~7 sibling tallies keying on the raw hostname while CORA deduped by the
normalized key. The temptation is to normalize ALL of them at once. But this is a 7,410-line
file that generates byte-faithful operator reports, and mid-fix I found MORE sites than the
initial list (an app-aggregate at ~4773/4777). Chasing every corner in one pass risks a slip in
operator-critical output and a sprawling diff. So I fixed the headline counts the operator acts
on FIRST (posture-digest self-contradiction, SLA hosts, command-brief KEV hosts, remediation
TargetCount, kb-needed) and RANKED the tail (item 11). A partial-but-tested-and-safe fix beats a
complete-but-risky one; the ranked item keeps the rest tracked.

## Decision 3 — key on normalized, DISPLAY raw (except top-host lists)
The fix normalizes the COUNT key only; per-finding display rows keep the raw hostname (they name
a specific finding). The one exception is "top KEV hosts"-style lists, where the normalized key
(short-upper) becomes the display too — consistent with how CORA already presents hosts. So the
change is bounded: it corrects host *counts* and, in a couple of rollup lists, shows short-upper
names — never alters report structure.

## Decision 4 — fold the RODC gap in (self-review of the immediately-prior commit)
Per the established cadence (fix what the self-review confirms + one workstream), the RODC gap is
a confirmed defect in the guard I shipped last loop, so it's fixed this loop — not ranked. It's
a 2-line completion (add PARTIAL_SECRETS_ACCOUNT to the DC test) closing a real
infrastructure-disabling hole, plus the adminCount fail-closed flip. Two small commits keep the
two concerns (adto guard vs reports counts) logically separate.

## Decision 5 — the agreement test is the real proof
The value claim is "all host counts agree." The test seeds ONE logical host in two name forms and
asserts sla-aging + kb-needed both report 1 (and agree), and the posture digest's HostsWithKev ==
1 (parsed from the digest CSV — the self-contradiction made observable). Before the fix each read
2. That's a cross-report invariant test, not a per-function unit test — it guards the *agreement*,
which is the property that was broken.

## Versioning
adto `0.2.2→0.2.3`, reports `2.14.20→2.14.21` (both behavioral). Each fix's own test file holds
the exact version pin.

## Process note — operator mid-loop directive
The operator asked (mid-loop) to move the loop to a 15-minute cadence and to prefer the Fable
model for agents. Applied to the cron immediately; the Fable-model preference applies from loop
14 (this loop's agents had already run on Opus). The review/re-verify cadence is unchanged — only
which model runs the agents.
