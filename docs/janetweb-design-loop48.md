# JANET Web — design loop 48 (2026-07-21)

## Decision 1 — diversify to a fresh dive; certdeploy over the c2c tail
With every HIGH/MED c2c dive finding closed (loops 44–47), grinding the c2c tail (low/read-only/speculative +
the view-coupled cluster) was low-value. certdeploy was the strongest un-reviewed acting tool: 110KB (the
largest un-dived), it *installs DoD trust anchors* over WinRM so a false "certs present/installed" is a real PKI
posture gap, and it's adjacent to the c2c PkiRoots work just reviewed. Fresh dives have been this series' highest
-yield move; this restarts that cycle.

## Decision 2 — fix F1, the clearest CHECK false-clean
The dive found the core deploy verify + NOT VERIFIED persistence path solidly fail-closed (a rare, reassuring
GREEN core). Of the two real false-cleans, F1 is the cleaner high-harm close: it's on the CHECK scan — the
operator's read of which hosts are missing trust anchors — and it makes a host read ALL PRESENT *without its
stores ever being compared*, the worst kind of scan false-clean (a compliant verdict for an uninspected host).
F2 (guard-rejected anchor) is real but its trigger (a non-CA / X.509-v1 cert in the Root/CA bundle) is narrower
for the actual DoD bundle, and its fix is a classification redesign; ranked.

## Decision 3 — fix at the reader, guarded on "zero usable thumbprints"
The false-clean is that the reader compares *nothing* and reports 0 missing. The tool's own comment already
states the invariant ("never report a store we never actually read as ALL PRESENT") — the code just didn't
enforce it for an empty want-set, only for a missing helper. The bundle *always* carries thumbprints (a Root at
minimum), so a want-set that yields zero usable (hex, non-blank) thumbprints is definitionally a deserialization
failure, not "nothing to check" — an Err, which the existing admin-side path already routes to CHECK ERROR.
Putting the guard in `Get-CertDeployStoreMissing` (the injected store-reader) means it fails closed both on the
remote target and in any local caller, and it's directly unit-testable (the reader is dot-sourced + already
tested with a `StoreOpener` shim). No new plumbing, no view coupling.

## Decision 4 — count *usable* thumbprints, not array length
The subtle correctness point: `@($want.Root).Count` on a `$null` want is 1 (`@($null)` wraps to a one-element
array), which would defeat the guard. So the count mirrors what the reader itself treats as a thumbprint —
hex-stripped, non-blank — so a null want, an all-empty want, and a blank-only want all count 0 and all fail
closed, while a single real thumbprint counts 1 and proceeds. The test pins each of those four cases.

## Decision 5 — version + honest ranking
A host whose want-set didn't deserialize now reads CHECK ERROR instead of ALL PRESENT — behavioral — so
certdeploy 1.4.0 → 1.4.1; the two pre-existing 1.4.0 exact pins → floors, the new test holds the exact pin.
certdeploy set (83) green; authoritative run gates. F2/F3 ranked as items 58/59; F4/F5 are speculative
structural gaps with no realistic trigger, noted for a defensive touch but not separately ranked — a dive's
value is an honest triage, not a padded backlog.
