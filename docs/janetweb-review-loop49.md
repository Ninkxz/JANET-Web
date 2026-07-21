# JANET Web — review loop 49 (2026-07-21)

Fable-inline. Self-review of loop-48 → **GREEN**. Baseline: loop-48 authoritative **1395** green (confirmed).

## Self-review of loop-48 (certdeploy want-set-empty fail-close) — GREEN
`Get-CertDeployStoreMissing` counts usable (hex, non-blank) thumbprints and returns `Err` when 0; the guard is
in the injected store-reader source (remote + local); a real 1-thumbprint want proceeds normally. 83 certdeploy
+ 1395 confirm no regression. Nothing to reopen.

## Workstream: close certdeploy item58 (F2) — a guard-rejected absent anchor is REJECTED, not clean
The 2nd of certdeploy's two real dive findings, completing the tool's deploy honesty.

### Finding (CONFIRMED — re-verified in-code)
`Add-CertDeployBundleToStores` refuses a wanted cert that fails `Test-CertDeployIsCa` (a non-CA cert destined
for the Root/CA trust-anchor store — e.g. an X.509 v1 root with no BasicConstraints): `$rejected++; continue`
(`:382-387`), **correctly** — a non-CA must never enter a trust-anchor store. It returns `Rejected`/`RejectDetail`
(`:418`), but `Get-CertDeployResultToken` (`:424-433`) **never read `Rejected`**, so the refused-and-ABSENT
anchor fell through to `ALREADY` ("all present") or, mixed with real adds, `INSTALLED` → a clean VulnPatched
**Success** while the anchor stayed absent. The guard was right; the *reporting* was the false-clean. Trigger: any
Root/CA cert without CA=true — notably an X.509 v1 root, rejected on every host forever while each deploy read
ALREADY. (Two existing CaValidation tests had *pinned* this — their titles literally said "Token ALREADY" —
the loop-37 lesson: tests can encode the bug.)

### Fix (certdeploy 1.4.1 → 1.4.2)
`Get-CertDeployResultToken` now returns **REJECTED** when `Rejected > 0` — out of the clean bucket, after
FAIL/NOT VERIFIED, before INSTALLED/ALREADY, so a rejection makes the result not-clean even when other certs
added. The token maps to a `'REJECTED (non-CA)'` row Status (error level; its own `rejected` summary bucket;
`RejectDetail` surfaced), which the audit's `default` branch books as **Failure**, itemCount 0. Honest tokens
for every non-rejection case are unchanged.

### Version + tests
- `CertDeploy.Tests.ps1` +6: REJECTED with nothing added (not ALREADY) and alongside real adds (not INSTALLED);
  the non-rejection tokens (INSTALLED/ALREADY/NOT VERIFIED/FAIL) unchanged; static asserts the token→Status map
  and the audit-default-Failure. Two `CaValidation` tests that pinned the old rejected→INSTALLED/ALREADY
  corrected to REJECTED. loop-48 exact pin → floor.
- certdeploy set **73** green; broad-grepped all tests for the token/classifier — the only affected are the two
  bug-pinning tests (corrected); every other INSTALLED/ALREADY assertion is a `Rejected=0` case, correctly
  unchanged.

## Remaining certdeploy backlog
item59 (F3, scan-cert-management registry-denied → green "None detected", LOW/advisory); F4/F5 speculative
structural (not ranked). Both of certdeploy's real dive false-cleans (F1/F2) are now closed.

## SECRET parity
- **SECRET parity:** the JanetSec certdeploy fork shares `Get-CertDeployResultToken` + the deploy status/audit
  wiring — mirror the REJECTED token, its `REJECTED (non-CA)` row Status, and the summary bucket.
