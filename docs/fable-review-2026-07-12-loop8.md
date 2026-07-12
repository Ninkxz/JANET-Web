# Fable 5 Review - Loop 8 of 8 (final) - 2026-07-12

Scope: the loop-7 remediation (`git diff f50cb4e..HEAD`) PLUS a final deep "where is the last bug"
adversarial pass over the highest-consequence paths (run-script RCE, c2c remote-exec/cert/key, certdeploy,
BitLocker) and a full re-verify of all 26 prior fixes. 4 reviewers (2 Opus deep, 1 Sonnet sweep, 1 Opus
re-verify). Every P2/P3 below was spot-verified by me against the actual code.

**Rating: YELLOW.** No P1. One P2 (a wrong-box gap on the single most dangerous action, found by the final
deep pass) + two P3 (escaping-blind edge cases my own loop-7 DN-count fix introduced). All 26 prior fixes
(loops 1-7) remain CLOSED-AND-CLEAN; the delta's other four fixes (shell.js CSV, wpt injection/self-guard,
kev gate, ReferralChasing) are CLEAN.

## P2 (fix first)

**P2-1. `run-script` (remoteadmin) is the ONLY destructive fan-out missing the wrong-box DNS-mismatch
HARD-ABORT.** `$script:RemoteAdminScriptBlock` opens `New-PSSession @splat` (`remoteadmin.psm1:265`) and goes
STRAIGHT to `Invoke-Command -Session $sess -ScriptBlock ([scriptblock]::Create($ScriptText))` (`:274-275`)
with NOTHING in between. Its sibling destructive workers BOTH verify, right after the session opens and before
any action, that the box that answered is the box that was dialed - c2c fix worker (`c2c.psm1:1454-1469`,
queries remote `$env:COMPUTERNAME`, on mismatch `Remove-PSSession` + `SKIPPED "DNS MISMATCH ... ABORTED"`, with
an IP-literal carve-out) and certdeploy deploy worker (`certdeploy.psm1:997-1012`, identical). run-script runs
ARBITRARY operator PowerShell, so the gap is the highest-consequence one in the suite. **Exploit:** operator
targets `WKS123`; DNS resolves it to a different live host (stale AD/DNS record, DHCP lease reassignment, name
collision) - `Test-RemoteAdminHostIsSelf('WKS123')` is false (a third-party name isn't a dispatcher identity),
so the self-guard keeps it - and the arbitrary block runs with the ADW credential on the WRONG box. Worst case:
`WKS123` is a CNAME/A-record pointing at one of the dispatcher's own NIC IPs (a service/alias name not in the
identity set) -> the block runs on the JANET host itself, killing the HttpListener mid-dispatch (the exact P1
outcome the self-guard exists to prevent, via a vector the name-based self-guard structurally can't cover).
**Fix:** mirror the sibling guard between `:266` and `:268` - probe `$env:COMPUTERNAME` (same
`^\d{1,3}(\.\d{1,3}){3}$` IP-literal carve-out), on mismatch `Remove-PSSession` + `Status='Skipped'`/
`DNS MISMATCH` and return WITHOUT running the block. *Verified: remoteadmin.psm1:264-280 vs c2c.psm1:1454-1469.*

## P3 (fix this iteration - same root cause)

**P3-A. DN-guard DC-counter is not RFC-4514 escaping-aware -> a false-ACCEPT to an ANCESTOR domain.** The
loop-7 counter `([regex]::Matches($Value,'(?i)(^|,)DC=')).Count` (`adto.psm1:281-282`, `adsearch.psm1:200-201`
module + `:240-241` inline) treats an ESCAPED comma `\,` as a component separator, which LDAP does not.
`CN=x\,DC=area52,DC=mil` PASSES (executed: `True`, dcCount=2) but LDAP parses RDN1 = `CN="x,DC=area52"` (the
`\,` is a literal comma inside the CN value), so the only real domain component is `DC=mil` -> the serverless
credentialed bind resolves to the PARENT `mil`, not area52.mil. The escaped comma manufactures a fake boundary
that satisfies the `(^|,)...$` anchor AND inflates the count. Bounded to ANCESTOR domains (the string must end
in the local suffix), needs parent-domain DC-locator control -> P3, but it defeats the commit's "EXACT local
domain" claim. **Fix:** strip escaped pairs before the boundary/count: `$bare = $Value -replace '\\.', ''`
then run the `(^|,)...$` anchor and the DC-count on `$bare`. (Verified: after stripping, `CN=x\,DC=area52,
DC=mil` -> `CN=xDC=area52,DC=mil`, the suffix is no longer at a boundary -> correctly REJECTED.)

**P3-B. Same root cause -> a false-REJECT of a legit escaped DN (fail-safe direction).**
`CN=Report\,DC=Legacy,OU=x,DC=area52,DC=mil` is over-counted (dcCount=3 vs 2) and wrongly rejected, denying a
legit scan/recert of an object whose CN legally contains `,DC=`. Rare, over-restrictive (not a security hole),
fixed by the SAME escape-strip. (Verified accept-after-fix.)

**P3-C (test gap, folded in). The "byte-identical" test only compares the two adsearch copies**
(`AdBindRedirect.Guard.Tests.ps1:94-101`), never the third (`adto.psm1` `Test-AdToDnInLocalDomain`), so a
non-corpus logic drift in the adto copy wouldn't be caught. **Fix:** extend the test to body-compare the adto
copy too, and add `CN=x\,DC=area52,DC=mil` to the reject corpus.

## Verified clean (final pass)
- **run-script RCE boundary** otherwise tight: admin-session gated (`destructive=$true`), ScriptText NEVER run
  locally (dispatcher only PARSES it; the sole execution is `Invoke-Command -Session` against a remote session),
  targets strictly validated, self-guard wired before WinRM, output capped, script SHA256+preview audited.
- **c2c** offline Defender push (Authenticode + >=50MB + MS-signer + product-id admin-side, SHA256 pin
  re-hashed on target before Start-Process; other Start-Process are fixed OS binaries / strict-GUID msiexec);
  **BitLocker** escrow-first, recovery key never read/logged, Enable gated on escrow success; **certdeploy**
  additive-by-thumbprint trust-root push (by design), 4-thumbprint expired-CA allowlist still narrow.
- Cross-cutting: every `[scriptblock]::Create` consumes module-internal `$script:*Src`, never remote/operator
  strings; no `Invoke-Expression` on tainted input; self-guards wired into every destructive fan-out EXCEPT
  the run-script wrong-box gap (P2-1).
- Loop-7 delta items 2-5 CLEAN: shell.js `q()` neutralizer (no double-guard with history's csvGuard, no
  downstream-parser round-trip, covers ALL toCsv callers not just 5), wpt injection (both pools correct, all 8
  pool sites enumerated - only these 2 were gaps), wpt maintenance-lock guard, kev gate, ReferralChasing=None
  (functionally inert single-domain, no GC/cross-domain path relies on referral).
- All 26 prior fixes CLOSED-AND-CLEAN; 8 regression-test files reference only live symbols.

## Coverage note (honest, for the rollup)
Automated (8 suites, ~889 cases): identity-set parity + case-insensitive HostIsSelf, manifest destructive-flag
contract, mpam package-pin shape + reject paths, DN-guard accept/reject corpus, ReferralChasing property +
coverage, CSV formula-neutralizer, wpt self-guard/clean. Pilot-pending / not unit-tested (need a live host or
HTTP loop): the on-target SHA256 re-hash, the server fail-closed gate's HTTP behavior, BitLocker escrow, PkiRdp
cert-store swap, the wrong-box DNS probe (this loop's P2-1 fix included), and the web-side esc()/CSV changes.

## Fix order
1. P2-1 run-script wrong-box guard (mirror c2c.psm1:1454-1469).
2. P3-A/B DN-guard escape-strip (`-replace '\\.',''` before boundary/count, all 3 copies) + P3-C test.
Each: PS 5.1 parse-clean + BOM, full Pester green before commit.
