# Fable 5 Review - JANET Web Experimental (this session's work) - 2026-07-11

Scope: the six commits added in `X:\JANET Web Experimental` this session on top of baseline `05e894e`
(C2C Phase 0 scan-buckets `34e9c89`; AD Nemesis `c96cc9e`/`b2497bc`/`27f8292`; WinRM Bridge `99efd66`;
C2C COAMS `ee8c809`; audit-trail `219c97f`). The base app was reviewed 2026-07-07; this audit covers only
the new code. The full Pester suite passes **772/772** and the two new JS views parse clean.

The new work is well-tested and the security-critical logic (revert-first bridge scripts, UAC-flip
calculation, IAO fail-closed gate, shared scan/import aggregator, COAMS registry evaluation) is unit-backed
and correct where I could exercise it. What holds this off GREEN is concentrated in the newest,
security-sensitive feature - the AD Nemesis RBAC + writes: the IAO express-permission gate authenticates the
**session credential, not the human**, which collapses under the service-account deployment this session
was explicitly built for; the IAO recert write **overwrites** its target attribute (data loss); and the
tool's editable ruleset (`adto-baseline.json`) is **not tracked in git**, so the whole point of a shippable
baseline is lost. All three are contained and cheap. Overall rating: **YELLOW**.

## Findings

**[P2]** `modules/JanetWeb.adto.psm1:447-451` (Invoke-AdToValidate) - **the IAO express-permission gate
authenticates the SESSION CREDENTIAL, not the operator.** `$who = $Credential.UserName` (else `$env:USERNAME`)
is matched against `iaoValidators`. JANET's model stores ONE `PSCredential` per session, and this session's
own direction (point #1: "on a server using a service account") makes that credential a *shared service
account*. In that deployment the gate checks the service account's name, so it is all-or-nothing for everyone
who shares it - either the service account is an "IAO" and every operator can validate, or it is not and
nobody can. Even with personal creds, the fallback `$env:USERNAME` is the server-process identity, not the
person at the keyboard. Net: the "only an IAO may validate" guarantee is not per-person. Fix: authenticate the
individual (e.g. the smartcard/UPN of the interactive operator, or an explicit per-action IAO credential),
not the shared session credential; or resolve IAO membership by AD group against that individual. Until then,
document that IAO gating is only meaningful when each operator sets their own credential.

**[P2]** `modules/JanetWeb.adto.psm1:466` (Invoke-AdToValidate) - **the recert stamp OVERWRITES the target
attribute.** `$de.Properties[$attr].Value = $stamp` replaces the whole value of `recertifyAttribute`
(default **`info`**, the AD "Notes" field). Any existing content in that field is destroyed, and a second
validation overwrites the prior stamp (no history). `info` is a general-purpose notes field many orgs populate
with other data. Fix: read-modify-write to APPEND the stamp (strip a prior `TO-VALIDATED:` line first), or -
better - move the stamp to a dedicated/unused attribute so validation never touches operator notes. The read
side already tolerates extra text (`Get-AdToRecertDate` regex-extracts the stamp), so appending is a small change.

**[P2]** `JanetLocal/adto-baseline.json` - **the AD Nemesis ruleset is NOT tracked in git.** `JanetLocal/` is
gitignored and `c2c-baseline.json` is present only because `.gitignore` explicitly negates it (README: "ships
with JANET, .gitignore-negated like the KEV catalog"). `adto-baseline.json` got no such negation, so
`git ls-files JanetLocal/` lists c2c-baseline but not adto-baseline. The embedded defaults keep the tool
*working*, but the whole design is "operators edit the baseline to match the real TO" - and an untracked file
does not travel in take-to-work, so there is nothing to edit on the target. Fix: add a `.gitignore` negation
for `adto-baseline.json` (mirroring c2c-baseline) and commit the shipped starter file.

**[P3]** `modules/JanetWeb.adto.psm1`, `modules/JanetWeb.winrmbridge.psm1`, and the four new `tests/*.ps1` -
**no UTF-8 BOM.** Every base `.ps1`/`.psm1` carries a BOM (`ef bb bf`); these new files start at their first
ASCII byte. Today they are 0% non-ASCII so PowerShell 5.1 parses them correctly - this is a latent risk, not a
live bug: the moment a non-ASCII character (em-dash, smart quote, "->" typed as an arrow) lands in one, PS 5.1's
ANSI default will mis-decode it. Fix: re-save all six new files as UTF-8 with BOM to match the suite (and add a
BOM assertion to CI if one does not already exist).

**[P3]** `modules/JanetWeb.adto.psm1:417-427` (Invoke-AdToFix) - **fixers apply the planned UAC flip without
re-evaluating the finding at write time (TOCTOU).** The fixer re-reads `userAccountControl`, computes the flip,
and writes - a correct *write* verify - but never re-checks that the object still *fails* the rule. For the
disable rules (`inactiveEnabled` / `staleObject`) that means an account which became active between the scan and
the fix is still disabled from the stale plan. Low probability (operator-armed, admin-gated), but the disable
path is the highest-consequence fix. Fix: for the disable rules, re-read the driving attribute
(`lastLogonTimestamp`) at write time and skip if it no longer breaches the threshold.

**[P3]** `modules/JanetWeb.winrmbridge.psm1` (enable/revert result rows + audit) - **the audit records the task
PUSH, not the bridge outcome.** A successful `Register-ScheduledTask`/`Start-ScheduledTask` over DCOM emits
`Status=BRIDGING`/`REVERTING` and an `audit result=Success`, but the SYSTEM task that actually stands up (or
tears down) the 5986 listener runs asynchronously and may fail. So the audit trail can say "bridge enabled"
when no listener came up. This mirrors the base review's scheduler P3 (fired-ok-on-acceptance). Mitigation
exists (the read-only Check action verifies real state); the fix is to have Check drive the audit outcome, or
have the enable payload write a result breadcrumb the tool re-reads.

**[P3]** `modules/JanetWeb.adto.psm1:461` (Invoke-AdToValidate), `:410` (Invoke-AdToFix) - **no DN validation
before the LDAP bind.** `New-AdToEntry -Dn $dn` interpolates a client-supplied DN straight into `LDAP://$dn`.
It is admin-gated and the DN comes from the tool's own scan, so risk is low, but there is no well-formedness or
scope check (an arbitrary DN binds an arbitrary object). Hardening only: validate the DN shape and, ideally,
that it sits under the scanned base.

## Checked and clean

- **The shared scan/import aggregator (Phase 0) does not diverge.** `Get-C2cImportPlan` and the scan both feed
  `Get-C2cPlanFromRecords` + `Get-C2cPlanSummary`; the import suite (`C2c.ImportAndFix`) and the new
  `C2c.ScanBuckets` both pass, and READY hosts never pollute the buckets (empty Failed/Audit -> absent).
- **COAMS follows the pool-runspace injection pattern correctly.** `Test-C2cCoamsChecks` is dot-sourced into the
  remote `$probeSb` exactly like `taniumInstalledSrc`, checks cross the WinRM boundary as JSON, and the
  `expected`-not-`equals` field name avoids the `$hashtable.Equals()` method collision (regression-tested). The
  pool-runspace verdict test still passes, so the added probe args did not break the isolation contract.
- **WinRM Bridge target scripts are revert-first, self-cleaning, self-guarded, injection-free** (base64 + int
  only), with a short-lived cert; 15/15. `Test-WinRmBridgeSelfTarget` blocks the dispatcher.
- **`Get-AdToFixedUac` preserves unrelated UAC bits, is idempotent, and never auto-guesses** description /
  manager / SPN / recert. `Test-AdToIaoAuthorized` **fails closed** on an empty allow-list and normalizes
  `DOMAIN\` / `@domain`.
- **No XSS introduced.** The new grids render via the shared `ResultsGrid` (textContent); the `ctx.confirm`
  bodies in the adto/winrmbridge views interpolate only numbers and constants, never AD- or host-derived free text.
- **Audit rows** are now emitted by the new destructive actions (AdToFix / AdToIaoValidate / WinRmBridge-*).

## Consistency / packaging

- **Baseline packaging is the main inconsistency**: `c2c-baseline.json` is git-negated and shipped;
  `adto-baseline.json` is not (P2 above). The COAMS addition also did not update the tracked `c2c-baseline.json`
  to document the new `coamsRegistryChecks` key - embedded defaults cover it, but the shipped sample is now
  behind the code.
- **BOM convention** (P3) - the six new files diverge from the suite standard.
- **Desktop twin not updated**: `C2CNemesisTool_2.3.0.ps1` did not receive the Phase 0 scan-buckets or COAMS
  changes; the web and desktop C2C tools have drifted (known, deferred).
- **Registry summaries** for `adto`/`winrmbridge` are written and accurate; the `adto` summary was updated when
  fixers/IAO landed. Good.

## Recommendations

1. **Fix the IAO identity source** so the express permission is per-person, or document it as personal-credential-only. (P2)
2. **Make the recert write APPEND** (or use a dedicated attribute) so IAO validation never clobbers `info`/Notes. (P2)
3. **Track `adto-baseline.json`** via a `.gitignore` negation so the editable ruleset ships. (P2)
4. **Re-save the six new files as UTF-8-with-BOM**; consider a BOM check in CI. (P3)
5. **Re-check the finding at fix time for the disable rules** (TOCTOU on `inactiveEnabled`/`staleObject`). (P3)
6. **Drive the WinRM Bridge audit outcome from verified state**, and add DN validation on the AD write paths. (P3)
7. **Before production**: pilot the WinRm Bridge DCOM remote-exec and the AD LDAP writes on 2-3 boxes - these paths are unit-tested at the logic layer but never exercised against a live domain.
