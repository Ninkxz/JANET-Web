# JANET Web — review loop 67 (2026-07-21)

Fable-inline. Self-review of loop-66 → **GREEN**. Baseline: loop-66 authoritative **1476** (dhcp-touching files 59 green after fix).

## Self-review of loop-66 (dhcp self-guard + confirm-word) — GREEN
The gate (`if $ActionId -in the 4 write actions { confirm-word; self-guard }`) sits after `$server` validation and
before the option-id parse / action switch, so a missing word or self-target never opens a DHCP session; `connect`/
`load` stay ungated; `Test-DhcpHostIsSelf` mirrors pkginstall. Behavioral tests + FixVerify/FixVerify3 (direct
sub-function calls, below the gate) = 54 green. Nothing to reopen.

## Workstream: close item 76 — dhcp dryRun fails OPEN (the secureboot loop-58 class)
Continuing the dhcp hardening. The dry-run selector on the destructive write actions used the shared `$asBool`
(`^(?i:1|true|yes|on)$`), which resolves **any** unrecognized token to `$false`. For `removeOption` that direction is
safe, but for `dryRun` `$false` means the DANGEROUS thing — a **live** write. So a typo on the dry-run selector
(`'TRUE '` with a trailing space, `'checked'`, `'dry'`) silently wrote to a live DHCP server, exactly the secureboot
loop-58 fail-open.

### Fix (dhcp 1.1.10 → 1.1.11)
New module function **`Get-DhcpDryRunSafe`** (mirroring `Get-SbeDryRunSafe`): the live path requires an *absent* value
(the manifest `dryRun default=$false`, handled by the caller's `ContainsKey` guard) or an *explicit recognized false*
token (`false/0/no/off`); any present-but-**unrecognized** value resolves to **dry** (fail-safe). Both dryRun parse
sites (apply `:1265`, bulk `:1304`) now call it instead of `$asBool`. `$asBool` is **left untouched** — `removeOption`
still uses it (a false-sibling; the destructive-polarity flip is only for dryRun, so the fix is at the dryRun sites,
not the shared helper). Extracted as a real function (not an inline scriptblock) so it's directly behaviorally testable.

### Tests
+5 (`Dhcp.IpValidation.Tests.ps1`, behavioral — the preferred type for a pure helper): exact `1.1.11` pin;
absent/empty → live; explicit false tokens → live; explicit true tokens → dry; a present-but-unrecognized token
(`'dry'`, `'checked'`, `'TRUE '`, `'maybe'`, `'2'`, `'y'`) → **dry** (the fix; `$asBool` would have gone live). The
loop-66 confirm/self-guard pin migrated to a floor. Ran all 3 dhcp-touching files = **59** green.

## dhcp backlog after loop 67
Items 77 (optionId retarget), 78 (apply null-result + no post-write verify), 79 (scope reconciliation) remain — all
from the loop-65 dive. dhcp now has confirm-word + self-guard + fail-closed dryRun + fail-closed bulk-status. Item 78
(apply null-result → Changed/Success, and no post-write re-read) is the most valuable remaining (an actual
false-clean), item 77 next.

## SECRET parity
- **SECRET parity:** the JanetSec dhcp fork (if present) shares the dryRun parse — mirror `Get-DhcpDryRunSafe` so an
  unrecognized dryRun token stays DRY instead of silently going live.
