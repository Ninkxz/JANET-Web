# Design - Loop 7 - Close the LDAP referral-chasing residual (AD-bind hardening capstone)

## Goal
Loops 5-7 hardened WHERE the credentialed AD bind can point (DN validation -> local-domain suffix ->
exact-domain component boundary). The last documented residual on that path (loop-7 audit, "informational"):
every `System.DirectoryServices.DirectorySearcher` in adsearch/adto leaves `ReferralChasing` at the .NET
default `External`, so even a search rooted at the validated local domain can follow a directory-returned
EXTERNAL referral to another server - a residual redirect of the search (and, under a credential, the auth)
to a host the DN guard never vetted. Set it to `None`, completing the AD-bind hardening arc.

## Surface (adsearch.psm1 + adto.psm1; additive, one property per searcher)
1. Find every `New-Object System.DirectoryServices.DirectorySearcher` (or `[adsisearcher]`) in `adsearch.psm1`
   (the main engine searcher, the LastPC user-resolution searcher, BaseUsers/BulkComputer searchers) and
   `adto.psm1` (the scan searcher). Immediately after construction set
   `$searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None`.
2. Do NOT change the bind constructors, the DN guard, or the search filters/scope - only add the one property.

## Risks / non-goals
- **Functionally inert in a single AD domain** - a DC serves its whole domain with no referrals, so FindAll/
  FindOne results are identical; `None` only stops the searcher from auto-following a referral to ANOTHER
  server. This is exactly the single-domain scope the DN guard's pilot assumption already enforces, so it
  adds no new restriction the suite doesn't already document.
- **Multi-domain note (pilot):** in a multi-domain forest a cross-domain object resolved via referral would
  no longer auto-resolve - consistent with the DN guard's single-domain pilot (a real multi-domain deployment
  needs the trusted-domain allowlist already noted). Documented, not a regression of current behavior.
- **No credential/bind change** - avoids touching the (untestable-offline) DirectoryEntry constructor; this is
  a pure searcher-property hardening. Keeps blast radius to one line per searcher.
- Non-goal: LDAP signing/sealing on the bind (`AuthenticationTypes`) - higher live-DC risk, deferred with a
  rollup note.

## Test plan
- Verifiable offline at the property level: a small test constructs a `DirectorySearcher`, sets the property
  the same way, and asserts `.ReferralChasing -eq 'None'`; and (where a searcher is reachable in module scope)
  asserts the shipped code sets it. The live "referral is not chased" behavior needs a directory -> documented
  pilot-pending; the property-set is the verifiable invariant.
- Full Pester suite green; PS 5.1 parse-clean + BOM; adsearch/adto still load + `Get-JanetToolManifest`
  non-empty.
