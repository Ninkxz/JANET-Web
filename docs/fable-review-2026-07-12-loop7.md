# Fable 5 Review - Loop 7 of 8 - 2026-07-12

Scope: the loop-6 remediation (`git diff f3b0828..HEAD`) was small/hardening-only, so - as in loop 5 - one
reviewer covered the delta and three ROTATED onto surface six loops never deep-audited: the smaller engines
(message/kev/sysadmin/biosfirmware/patchlib/history), the runspace-pool THREADING in the big fan-out engines
(c2c/wpt/acas), and the remaining view/component XSS sinks (targetmanager, palette, 7 views). Plus an Opus
re-verify of all 20 prior fixes. Every P2/P3 below was spot-verified by me against the actual code.

**Rating: YELLOW.** No P1. Two P2 (one live-exploitable security gap, one functional bug) + three P3. All
20 prior fixes remain CLOSED-AND-CLEAN; the XSS discipline (esc()/textContent) holds across all 9 newly-audited
UI files; the c2c/acas fan-out engines are clean on arg/param, source-injection, races, and self-guard.

## P2 (fix first)

**P2-1. Client-side CSV export has NO formula-injection neutralizer - the systemic version of the loop-6
wpt fix.** `web/js/shell.js:125` `toCsv`'s cell serializer `q()` does RFC-4180 quoting ONLY; it never prefixes
a leading `= + - @` / tab / CR. FIVE views export remote-harvested rows straight through it -
`biosfirmware.view.js`, `sysadmin.view.js`, `message.view.js`, `kev.view.js`, `patchlib.view.js` - and only
`history.view.js` has its own local `csvGuard`. **biosfirmware is live-exploitable:** `biosfirmware.psm1:164`
`Manufacturer`/`Model`/`ProductName`/`InstalledBIOS` come from the target's `Win32_ComputerSystem`/
`Win32_BIOS` SMBIOS strings, which a compromised endpoint fully controls - a box reporting Model
`=cmd|'/c calc'!A1` lands it verbatim in `BiosFirmware_Results_*.csv`; opening it in Excel executes in the
operator's context. **Fix:** add the neutralizer once, inside `q()` (covers headers + every cell + every
`toCsv` caller). *Verified: shell.js:124-131; biosfirmware.psm1:164; the 5 view export calls.*

**P2-2. wpt `unsupported-scan` / `unsupported-uninstall` are NON-FUNCTIONAL (source-injection gap).**
`Test-WptHostReachable` is a module-scope function (`wpt.psm1:3202`) invisible to a bare pool runspace;
`Invoke-WptSingleHostCancelable` correctly injects it via `SessionStateFunctionEntry` (`:3231-3232`). But
`$script:WptSoftwareScanBlock` (calls it at `:3846`) and `$script:WptSoftwareUninstallBlock` (`:3914`) are
also fanned out through SEPARATE direct pools at the `unsupported-scan` action (`:5181-5188`) and
`unsupported-uninstall` (`:5288-5296`), each building `$iss` via `CreateDefault()` with NO function injection.
Every host throws "Test-WptHostReachable is not recognized"; the `EndInvoke` try/catch swallows it into a
per-host "worker error" row, so it LOOKS like generic host failures rather than a code bug - but both bulk
features are completely broken as shipped. **Fix:** inject `Test-WptHostReachable` into those two pools'
`$iss` (mirror `:3231-3232`); audit every other `CreateRunspacePool` site in wpt for the same omission.
*Verified: block defs `:3844`/`:3912` (first line calls the helper, no self-dot-source); pools `:5181`/`:5288`
use CreateDefault; contrast `:3230-3232`.*

## P3 (fix this iteration)

**P3-1. Loop-6 DN guard's suffix match has no LEFT component-boundary anchor.** `([regex]::Escape($suffix) +
'$')` (`adto.psm1:270`, `adsearch.psm1:193` module + `:225` inline) anchors only the right end, so a
CHILD-subdomain-prepended DN like `DC=evil,DC=area52,DC=mil` PASSES (ends with `DC=area52,DC=mil`) yet its real
serverless-bind domain is the distinct child `evil.area52.mil` - steerable to an attacker DC if they control
DNS for a subdomain of the local zone (P3: needs attacker DNS + client-supplied DN). Also `CN=ABDC=AREA52,
DC=MIL` matches as a substring (downgrades to parent `MIL`; not attacker-controllable, a correctness
curiosity). The fix comment INACCURATELY claims child domains are rejected. **Fix:** anchor the suffix at a
component boundary (`(^|,)`) AND reject any value carrying an extra `DC=` component beyond the expected suffix
(enforce EXACT local domain, matching the comment); correct the comment. Extend the guard test.

**P3-2. `kev.psm1:60` `add-kev` is `destructive=$false` but WRITES the shared KEV catalog.** Its handler
(`:315`) writes `JanetLocal\KevCatalog.txt`; under the loop-5 fail-closed doctrine, `destructive=$false` means
"read-only, runs ungated" - so this state-changing write runs with NO admin session, unlike every other write
in the suite. The write itself is well-validated (`Test-KevCveId` `^CVE-\d{4}-\d{4,}$`, fixed path, atomic
temp+rename under a lock, add-only) so blast radius is bounded (P3, catalog pollution -> xref false-positives;
no injection/traversal). **Fix:** flip to `destructive=$true` so the persistent write rides the admin-session
gate. (The manifest test asserts the flag is PRESENT, not CORRECT - this is a value bug it can't catch.)

**P3-3. wpt `maintenance-lock` missing the self-guard.** `Remove-WptSelfTargets` (`wpt.psm1:533`) is applied
before fan-out for forced-patch/reboot/reboot-schedule/reg-apply, but NOT for `maintenance-lock` (`:5645`)
even with `HardLock=true` - so the dispatcher host could get its own interactive-logon lock/banner applied,
locking an admin out of the console (not destructive to the running service). **Fix:** wire the same
`Remove-WptSelfTargets` guard before the maintenance-lock fan-out.

## Documented (not fixing this iteration)
- **ReferralChasing (informational).** adsearch/adto `DirectorySearcher.ReferralChasing` is never set -> stays
  .NET default `External`, so even a local-suffix bind could be chased to an external referral. Defense-in-depth
  residual; setting `= None` is a future single-domain hardening (pilot).
- **DN-guard multi-domain allowlist (pilot-pending, unchanged from loop 6).**
- **Stale test comment:** `SelfGuard.IdentityParity.Tests.ps1:29-36` narrates the pre-loop-3 state; the
  assertions are correct. Trivial comment refresh (folded into the FIX batch).

## Clean (verified this loop)
message send (msg.exe via STDIN + array args, targets regex-validated, `$cap` int-clamped - no injection),
sysadmin (well-known SID, fixed paths, read-only), biosfirmware/patchlib/history engines (no IEX/scriptblock/
shell/Filter injection, no traversal on any write, patchlib never writes), no secret leak in any of the six;
c2c fan-out (19=19/9=9/8=8 + nested 11/10/2 arg counts, all `$script:*Src` injected, single-consumer polling,
self-guard before dispatch), acas fan-out (5 worker pairs arg-matched, self-contained workers, self-guard
before dispatch); XSS clean across targetmanager/palette + 7 views (every dynamic body esc()'d or a textContent
DOM node). All 20 prior fixes CLOSED-AND-CLEAN.

## Fix order
1. P2-1 shell.js `q()` neutralizer (covers all 5 views).
2. P2-2 wpt inject `Test-WptHostReachable` into the two bulk pools (+ audit all pool sites).
3. P3-1 DN-guard component-boundary anchor (adto + adsearch module & inline; extend test; fix comment).
4. P3-2 kev `add-kev` -> `destructive=$true`.
5. P3-3 wpt `maintenance-lock` self-guard.
6. (doc) refresh the stale IdentityParity test comment.
Each: PS 5.1 parse-clean + BOM, full Pester green before commit.
