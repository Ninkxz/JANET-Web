# JANET Web — design loop 69 (2026-07-21)

## Decision 1 — a wrong-target write is worth closing even at P2
Item 77 isn't a false-clean (the write does happen and is reported honestly) — it's a *wrong-target* write: the tool
silently changes a different option than the operator asked for, and that option happens to be DNS servers, the single
most disruptive DHCP option to clobber. On a destructive engine, "silently do the wrong thing" ranks with "falsely
report the right thing." Of the remaining dhcp items it's the one with a small, self-contained fix; 79 and 80 are
larger.

## Decision 2 — the default is only safe for a read
Defaulting a missing/garbled optionId to 6 was a deliberate desktop-parity convenience, and for the read-only `load`
action it stays exactly that — it just reads option 6 and shows it, changing nothing. The defect is purely that the
same convenience runs on the destructive path, where "read option 6" becomes "overwrite option 6". So the fix is
polarity-by-action, not a blanket removal: keep warn-and-default for `load`, abort for the four write actions.

## Decision 3 — reuse the destructive-action set, don't re-list it
Loop 66 introduced the exact action set for the confirm/self-guard gate. Rather than repeat the literal list at the
optionId parse (two lists that could drift), I hoisted it into a single `$isDestructive` computed once at the gate and
read again here. One source of truth for "is this a write". The abort returns the same `rejected=$true` summary shape
the gate uses.

## Decision 4 — abort before the DHCP session, like the other guards
The optionId parse already sits after the confirm/self-guard gate and before the action switch, so returning here costs
nothing and opens no session — consistent with every other dhcp refusal this run of loops added. The read-only branch
is unchanged, so `load` behaves exactly as before.

## Decision 5 — behavioral tests through the dispatcher; version
The abort is reachable through `Invoke-JanetToolAction`, so the tests are behavioral: an `apply` and a `bulk-append`
with a non-numeric optionId (and a valid confirm + remote target, so they clear the gate) are rejected, with the apply
case asserting the "not numeric … DNS" error so the message names the risk. Because a destructive action now refuses
instead of retargeting option 6, this is behavioral: dhcp 1.1.12 → 1.1.13, the newest Describe holds the exact pin and
the loop-68 null-result Describe floors. Items 79 (P3 reconciliation) and 80 (P2 post-write verify) remain; 80 is the
last substantive dhcp hardening and warrants its own loop.
