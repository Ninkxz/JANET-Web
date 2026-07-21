# JANET Web — design loop 29 (2026-07-21)

## Decision 1 — diversify to c2c, the highest-stakes false-clean surface
Seven loops on wpt/acas remediation honesty was enough concentration. c2c is a compliance-readiness
tool never loop-era deep-dived, and for a compliance tool a false "compliant" is worse than a false
"patched" — it's the number that goes up-chain as the readiness posture. Same bounded-Fable-worker
pattern, applied to a fresh, high-consequence surface.

## Decision 2 — verify, then fix the crispest of six
The worker found the scan verdict genuinely fail-closed and the durability trio correct — but six
confirmed false-compliants on the fix roll-ups and import. I re-read each. Loop discipline is one
fix + one test, and these six span very different blast radii (import count vs destructive-fix
rollup vs audit), so I fixed the crispest high-harm one and ranked the rest 22-26.

## Decision 3 — F4 over F1/F2, because it's the headline number at lowest risk
F1 (SKIP-masked FIXED) and F2 (trigger-as-fixed) are higher-touch — they live in the destructive-fix
host-status rollup and the audit, needing the wide destructive regression pass and careful new status
vocabulary. F4 is a 2-line arithmetic bug on the READ-ONLY import path, and it's the single most
up-chain-quoted number ("N Compliant"). Best harm-per-risk for one loop; F1/F2 get their own.

## Decision 4 — fail closed: Compliant only on explicit ^Compliant
The bug was defining Compliant as the complement of Non-Compliant, which quietly swept every unknown
state into the pass count. The fix inverts that to a positive match: a host is Compliant only if its
cell says so. Everything else that isn't explicitly Non-Compliant becomes `other` — visible, not
silently passed. That's the fail-closed posture a compliance tool owes its headline number.

## Decision 5 — surface `other`, don't hide it
The unknown hosts don't just leave the Compliant count — they get a named bucket in the log line and
the summary hash, so the operator sees "N unknown/other" instead of those hosts vanishing. A
compliance count that drops hosts is its own kind of dishonest.

## Decision 6 — no helper, test the wired path
The count is used in exactly one place, so a helper would be abstraction for its own sake; the fix is
inline. The test drives the REAL import action (Invoke-JanetToolAction 'import') with a synthetic CSV
carrying a "Not Assessed" row and asserts the summary — the wired path, not a reimplementation — plus
an all-explicit no-regression case. c2c 1.15.2 -> 1.15.3; pin migrated; full c2c set run (destructive
tool, wide gate). Fable-inline throughout.
