# Fable 5 Review - Loop 6 of 8 - 2026-07-12

Scope: the loop-5 remediation itself (`git diff 5591bbc..HEAD`) - 4 commits: the fail-closed admin gate
(`Server.ps1`), the two LDAP DN-guards (adsearch + adto), the two self-guard wirings (upr + winupgrade),
the dhcp XSS escape, and the new manifest-flag test. 4 reviewers (2 Opus deep - the central gate, and the
DN/self-guards; 1 Sonnet XSS+blast-radius; 1 Opus re-verify of all 17 prior fixes). Every P2/P3 below was
spot-verified by me against the actual code.

**Rating: YELLOW.** No P1. One P2 + two P3 - all on the loop-5 DN-guard / dhcp changes (i.e. my own loop-5
fixes were incomplete/over-broad in two ways). The central fail-closed gate is CORRECT for all 6 action
classes, and all 17 prior fixes remain CLOSED-AND-CLEAN.

## The central gate is CORRECT (highest-stakes change - verified clean)
The fail-closed gate (`Server.ps1:743-751`) was traced for all 6 action classes + edge cases: manifest
`$true`->gated, `$false`->ungated, OMITTED->gated (fail-closed), acas-by-id destructive->gated, acas-by-id
read-only->ungated, and manifest-wins-over-by-id (`preflight-services` stays gated). Confirmed manifests are
raw hashtables so the `IDictionary.Contains` branch runs (not the mis-detecting PSObject fallback), all 183
`destructive` flags are real booleans (no string-`'false'` truthiness trap), `Select-Object -First 1` prevents
an array `.Contains`, and ack+credential are both required with the 404 upstream backstop. No auth bypass, no
mis-gated read-only action.

## P2 (fix this iteration)

**P2-1. Serverless DC-locator bind-redirect BYPASSES the loop-5 DN guard.** The guard
(`adsearch.psm1:296`, `adto.psm1:342`/`:423`/`:487`) rejects a value containing `/` or `\`, which blocks the
EXPLICIT-server form (`evilhost/DC=x`, `LDAP://evil`) - but a value like `DC=evil,DC=com` or
`CN=x,DC=evil,DC=com` PASSES (starts with `[A-Za-z]{1,8}=`, no `/`). It is prefixed `LDAP://` and bound with
NO explicit server; ADSI serverless binding derives the domain from the `DC=` components and calls
`DsGetDcName` to locate a DC for THAT domain -> a credentialed bind lands on the attacker's `evil.com` DC
(coerced auth / credential exposure) - exactly what the guard claims to prevent. Affects all four guard sites;
worst on `adto.psm1:423`/`:487` (fix/validate bind the operator's AD CREDENTIAL). My loop-5 guard (copied from
the pre-existing scan guard `:342`) only ever addressed the `/` form. *Exploitability is LOW on a hardened
AFNET (foreign `.com` unlikely to DNS-resolve / outbound auth blocked), but the control must actually enforce
its claim.* **Fix:** require the DN/SearchBase to END WITH the JANET host's own domain suffix (derived from
`$env:USERDNSDOMAIN` -> `DC=..,DC=..`), rejecting any foreign-domain `DC=` tail; fail-closed if the local
domain can't be derived and the value is non-blank. Multi-domain/cross-forest targets would need a
trusted-domain allowlist -> pilot-pending note.

## P3 (fix this iteration - cheap)

**P3-1. Escaped-comma DN false-positive (`[/\\]` over-rejects legitimate DNs).** The same four guards reject
a literal `\`, but RFC 4514 escapes special chars in an RDN value with `\` - so `CN=Smith\, John,OU=Users,
DC=area52,DC=mil` (the pervasive "Last, First" CN convention) is REJECTED. Fail-safe (no security impact) but
a real functional regression: comma/plus/semicolon-CN accounts can never be fixed or IAO-recertified through
JANET (worst on the validate path). `\` is NOT a bind-redirect character (the vectors are `/` and the
serverless-DC form P2-1 now handles). **Fix:** drop `\` from the reject class - block only `/`. Folded into
the P2-1 guard edit.

**P3-2. `dhcp.view.js:352` unescaped `body:` interpolation.** The "Check IPs" dialog builds
`'Not valid IPv4: ' + bad.join(', ')` into the ConfirmDialog `body` (-> `innerHTML`). `bad` derives from the
operator's OWN bulk-IP textarea (local input), so this is self-XSS/pastejacking only (P3, not the remote-data
class the loop-5 fix targeted). **Fix:** `esc(bad.join(', '))` for consistency/defense-in-depth.

## Verified clean
- dhcp XSS fix (`diffText()` `esc()`) complete for its remote-data sink; the ConfirmDialog `list:` path is
  textContent-safe (`confirmdialog.js:62-66`); no sibling remote-data sink missed; activity log uses
  `createTextNode`.
- Self-guards correctly wired: upr manual path now calls `Test-UprHostIsSelf` (common self forms closed);
  winupgrade `$mutatesTarget` classification verified handler-by-handler (all 8 mutate, all 5 excluded are
  read-only) - no self-target hole, no over-gate. (Pre-existing name/IP self-detection edge cases - a CNAME
  alias of self, zoned IPv6 - remain across ALL self-guards; inherent, documented, not a loop-5 regression.)
- Blast radius exactly the 8 expected files; BOMs intact on all changed .psm1/.ps1; Manifest.DestructiveFlag
  test 22/22 and genuinely Pester-3.4-shaped; no `Invoke-Expression`/weakened-confirm/removed-guard/new-sink.
- All 17 prior fixes (loops 1-5) CLOSED-AND-CLEAN; four test suites internally consistent with current code.

## Fix order
1. P2-1 + P3-1 (same guard edit): the four DN-guard sites - drop `\`, add local-domain-suffix requirement.
   Opus-implemented, gated, + an offline unit test (fake `$env:USERDNSDOMAIN`, assert accept/reject).
2. P3-2: dhcp.view.js:352 `esc()`.
Each: PS5.1 parse-clean + BOM, full Pester green before commit.
