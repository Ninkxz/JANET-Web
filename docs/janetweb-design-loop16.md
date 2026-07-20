# JANET Web — design loop 16 (2026-07-20)

## Decision 1 — verify the "full contract" claim on the tool I asserted it for
Loop 15 closed with "every destructive tool now carries the full contract." certdeploy was
one I'd asserted that for (via the loop-10 self-guard audit + the c2c durability-trio port)
but never deep-dived standalone. The disciplined move is to VERIFY the claim, not carry it.
It held — certdeploy is GREEN — but the verification surfaced a genuine (test-side) weakness
worth closing, which is the point of actually doing the pass instead of trusting the ledger.

## Decision 2 — the removal path is where a cert tool earns scrutiny
An additive-only cert push is low-risk (worst case: an extra trust anchor). The DANGEROUS
operation is DELETION — pruning a trust anchor that's actually needed breaks chain validation
fleet-wide. So the review weight went on `prunePki`: the triple-gate (expired + retired-DoD
pattern + not-legacy-keep, CA-store only) is sound, and — critically — the exclusion of the 4
legacy-keeps the tool itself pushes is what stops it from deleting its own work.

## Decision 3 — fix the TEST, not the tool (the tool was right)
The prune logic is correct. The gap was that its safety-critical invariant — guard-copy
`$legacyKeep` == master `CertDeployLegacyIntermediates` — was checked loosely (source-substring,
one direction). A trust-anchor deletion path deserves a precise, bidirectional drift guard: a
MISSING legacy-keep means the prune deletes a pushed cert (the catastrophic direction); an
EXTRA thumbprint silently exempts a cert from pruning (the quieter direction). Extracting the
actual array literal and asserting set-equality both ways closes both. This is real
test-coverage growth on a removal path, not a manufactured change.

## Decision 4 — no version bump (test-only)
The module is unchanged, so certdeploy stays v1.4.0. Bumping a tool version for a test
strengthening would be misleading (it implies a behavior change). The convention bumps on
behavioral changes; this isn't one.

## Decision 5 — Fable-inline, no agents
Per the directive: the deep-dive and the test hardening were done inline by Fable. A cert-tool
contract verification + a regex-extraction test refinement don't benefit from a second model.

## Offline posture (operator reaffirmation this loop)
certdeploy reads the trust bundle from the LOCAL `Packages\DoD-Certs` folder (or an operator
folder) — no download, no CDL/CRL fetch, no internet. It installs over LAN WinRM. This matches
the whole-app posture: offline, CSV/local-file-fed, loopback UI. No loop in this series has
added an outbound internet dependency.
