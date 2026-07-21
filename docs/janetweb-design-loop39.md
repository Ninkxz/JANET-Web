# JANET Web — design loop 39 (2026-07-21)

## Decision 1 — close a confirmed backlog false-clean over another fresh dive
The loop-38 acas dive left five ranked findings (items 35–39). With a confirmed high-harm false-clean already
in hand, closing one beats a fresh wpt dive that — on a tool as worn as wpt — likely returns GREEN. I picked
F4/item36 because it is the highest-harm of the ranked five that is *tractable this loop*: F2 (mtime-recency)
needs a per-profile required-version redesign, but F4 is a single shared comparison with an unambiguous core.

## Decision 2 — guard the *unambiguous* core, not the required-version question
The honest signal a "bump" needs is: did POST report a readable version that moved forward? Two things falsify
that with zero per-profile knowledge — a post that degraded to a sentinel the probe emits when it *couldn't
read* a version (`error`/`n/a`/`not installed`), and a numeric downgrade. Guarding exactly those closes the
false-clean without touching the harder "is this the version the finding demands" question (F2). So F4 stays a
small, safe, global change and F2 keeps its own item.

## Decision 3 — what must stay confirmed (the regression traps)
Three legitimate "bumps" are non-obvious and must not be masked: installing a missing product
(`pre='not installed' → post=version` — a degraded *pre* is fine, only a degraded *post* falsifies), Log4j
clean (`post='none'` means no vulnerable jars — good, not degraded), and spec-exec's state transition
(`VULNERABLE → COMPLIANT` — not a `[version]` at all). The design leaves all three confirmed: the degraded set
is matched on POST only, `'none'` is deliberately excluded, and the downgrade check fires only when *both*
sides parse as `[version]` (so non-version state strings never reach it). Tests pin each of these three.

## Decision 4 — pure helper + inline mirror (the runspace boundary again)
The comparison lives inside `AcasUpdateWorker`, which runs in the module-less `CreateDefault` fan-out pool, so
it can't call a module function. Same pattern as `Get-WinUpgradeRepairVerdict`: a pure `Get-AcasBumpVerdict`
carries the canonical logic and is unit-tested directly; the worker mirrors it inline under a "keep in sync"
comment; a static source assertion pins that the mirror carries the degraded list and the downgrade check so
the twins can't silently drift.

## Decision 5 — version + verification scope
A degraded-post host that read OK now reads UNCONFIRMED — behavioral, so acas 1.11.10 → 1.11.11, and since the
prior exact pin lived in the just-shipped RebootAudit test I migrated it to a floor and the new BumpVerdict test
holds the exact pin. Because the change is in the shared verify path of *every* profile, I ran the full profile
set (Chrome/Edge/SpecExec/Log4j + verify/row/target tests, 122 green) — not just the new file — to prove no
real bump, state transition, or clean-state is masked, and grepped all tests for the touched symbols before
finalizing (loop-37/38 lesson).
