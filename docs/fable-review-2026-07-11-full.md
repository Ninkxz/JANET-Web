# Fable 5 Review - JANET Web Experimental (FULL codebase) - 2026-07-11

Full adversarial audit of the entire `X:\JANET Web Experimental` tree - all 22 module `.psm1`, the server core,
and the ~20-view SPA (~60k lines) - conducted by eight parallel subsystem reviewers, with every P1/P2 in this
report spot-verified against the actual code (grep/read) by the synthesizer. Findings are tagged **[V]** (I
re-verified the code myself) or **[R]** (reviewer-reported with a code quote, not independently re-verified).

The suite is, overall, strongly engineered on the axes that matter: LDAP filter injection is escaped everywhere,
BitLocker recovery keys never leak, the SecureBoot password payload is injection-safe, XXE is hardened, the SPA
renders data via `textContent`, `esc()` is complete, cert installs are additive-only, and `restart` is a clean
reference implementation of the dispatcher self-guard. But guard PARITY is uneven - the self-guard and the
IPv4-DNS-skip that `restart`/`winupgrade` do correctly are missing on several sibling destructive paths - and
one shipped tool carries an argument-injection vector reachable through a low-privilege-writable registry key.

**Overall rating: RED as-audited -> YELLOW after remediation.** The two RED drivers (ACAS `schedule-reboot`
self-kill P1-a, UPR msiexec injection P1-b) and P1-c plus most P2s were fixed this session - see **Remediation
status** below. What remains is P3 hardening and one data-limited P2 (reports campaign coverage).

## Remediation status (2026-07-11, this session)

**Fixed + tested:**
- **P1-a** ACAS `schedule-reboot` self-guard added (`0b227ae`).
- **P1-b** UPR generic-MSI + Adobe removals routed through strict-GUID + array args (`0b227ae`); aligns with the
  existing `Upr` "safe uninstall-string decomposition" test intent.
- **P1-c** AD Nemesis IAO gate now authenticates the Windows identity running JANET, not the session credential (`0b227ae`).
- **P2** server `/session/end` clears `AckGiven`+`Cred` (`b1af821`); WPT forced-`bulk-patch` + `registry-key-apply`(reboot)
  self-guards + app-update IPv4 skip (`b1af821`); UPR + pkginstall dispatcher self-guards ported from `restart` (`3cdf560`);
  WinRM Bridge no longer destroys a pre-existing 5986 listener + view XSS routed through `list:` + `-Force` task cleanup (`a90dd87`);
  adto recert write APPENDS instead of overwrites (`a90dd87`); certdeploy CHECK want-set now matches DEPLOY's expiry filter (`cfb4474`).
- **P3** ACAS identity gains bound-NIC IPv4 (`cfb4474`); the 6 new files re-saved UTF-8+BOM; `adto-baseline.json`
  git-negated so it ships; stale COAMS comment fixed (`cfb4474`/`a90dd87`).

**Documented, not code-fixed (data/design limitation):**
- **P2 reports campaign** - a finding-only export can't distinguish "scanned + clean" from "not scanned" (the
  conservative code fix regressed the core remediation-confirmation flow, so it was reverted); added an operator
  coverage-caveat warning instead (`cfb4474`).

**P3 hardening fixed (`77ad6fd`):** reports 'Export Full CSV' now formula-guards every cell (incl. PluginID);
WinRM Bridge self-guard gains bound-NIC enumeration + hostname-token validation; winupgrade inline OOM
classifier separates the authoritative `0x8007000E` code from a free-text phrase (no confident misdirect to
the destructive page-file fix); adto `SearchBase` validated as a plain DN before the credentialed bind.

**Still open (P3, lowest priority / inherent):** reports unbounded CSV load + IAVM-writer escape; c2c Patches
no-deadline `StartTime` dead-branch (lower confidence); server manifest-only gating + single-thread accept loop
+ pkginstall path enumeration (largely inherent to the loopback single-operator model). Plus the standing
recommendation: a **controlled live-domain pilot** of the WinRM Bridge DCOM path and the AD Nemesis LDAP writes.

The original findings below are retained verbatim as the as-audited record.

## P1

**[P1-a] [V]** `modules/JanetWeb.acas.psm1:2914` - **`schedule-reboot` fan-out has NO dispatcher self-guard.**
`Test-AcasHostIsSelf` is applied only on the `reboot-selected` path (`:3154`); the first-class `schedule-reboot`
manifest action dispatches `$targets` straight into `AcasRebootWorker` with no self-filter. The in-worker
DNS-mismatch guard does not catch this - the dispatcher's own name resolves to itself, so the compare passes. A
target list that includes the JANET host (short/FQDN/NIC-IP) reboots the box the server runs on, killing the
HttpListener mid-wave and abandoning the rest of the wave + its audit events. This is the 2026-07-07 P1, fixed for
`reboot-selected` but never ported to `schedule-reboot`. Fix: drop self before dispatch, exactly as `:3154` does.

**[P1-b] [V]** `modules/JanetWeb.upr.psm1:1069` (generic-MSI) and `:1037-1043` (Adobe) - **msiexec argument-injection
via a user-writable uninstall string.** These two removal branches extract the product code with a LOOSE pattern
`$unStr -replace '.*(\{[^\}]+\}).*','$1'` (and `-match '(\{[^\}]+\})'`) - `[^\}]+` admits spaces, `=`, quotes, and
paths - then shell it as a single-string arg: `Start-Process msiexec -ArgumentList "/x $guid /qn /norestart"`. The
rest of the file deliberately routes MSI removals through the STRICT-GUID decomposer (`Get-SafeUninstallPlan`,
GUID `[0-9A-Fa-f\-]{8,}`, `:938`) "so metacharacters are never interpreted" - these two branches are the outliers.
The scan enumerates **HKCU** uninstall keys (`:786`, user-writable), so a low-privilege user can pre-plant an
`UninstallString` like `{<guid> TRANSFORMS=\\evil\x.mst}`; when an operator later runs a Proven-EOL uninstall on
that host (any product whose DisplayName misses the M365 regex falls into the generic branch), the injected
`TRANSFORMS=` (a custom-action vector) runs under the operator's admin WinRM credential. Fix: route both branches
through the strict-GUID decomposer.

**[P1-c] [V]** `modules/JanetWeb.adto.psm1:447` (Invoke-AdToValidate) - **the IAO "express permission" gate
authenticates the SESSION/SERVICE credential, not the human.** The suite's only RBAC control resolves identity as
`$Credential.UserName` (else `$env:USERNAME`) and matches it against `iaoValidators`. This session's own direction
made the credential a shared service account; in that mode, if the account is on the allow-list, EVERY operator
sharing the launcher passes the "IAO-only" gate, and the recert audit is attributed to the account, not the person.
The control is defeated exactly in the deployment it was built for. (Flagged independently by two reviewers and the
session review.) AD Nemesis is pre-pilot, so this is a design fix to land before it ships, not a live breach. Fix:
authenticate the individual operator (smartcard/UPN or AD-group membership of the interactive user), not the shared
session credential.

## P2

**[P2] [V]** `server/JanetWeb.Server.ps1:485-495` (with the gate at `:731`) - **"End Admin Session" never disarms
the destructive gate.** `$state.AckGiven` is set `$true` at `:400` and reset nowhere; `/api/session/end` records
only `ClosingNotes`, clearing neither `AckGiven` nor `Cred` (cleared solely by a separate `DELETE /api/cred`). So
after an operator "ends" their session, the ack+cred gate stays open for the rest of the launch - a leftover tab or
replayed request can still drive destructive actions. Fix: clear `AckGiven` (and ideally `Cred`) in `/session/end`.

**[P2] [V]** `modules/JanetWeb.wpt.psm1:4899` (forced `bulk-patch`) and `:5646` (`registry-key-apply` w/ reboot) -
**reboot-capable handlers lack the dispatcher self-guard.** `Remove-WptSelfTargets` is called only at `:4925`
(reboot) and `:4945` (reboot-schedule). Forced bulk-patch sets `IsRebootIfNeeded=$true` and reg-apply arms a 1-hour
scheduled reboot - both reboot the dispatcher if it is in the target list (DNS guard can't catch self). Delayed
self-kill. Fix: call `Remove-WptSelfTargets` in both handlers.

**[P2] [V]** `modules/JanetWeb.wpt.psm1:3144` (`WptAppUpdateBlock`) - **app-update apply / Custom Command
DNS-mismatch guard lacks the IPv4-literal skip** the 9 other workers received. An IPv4-literal target hard-aborts
("DNS Mismatch") on the most flexible destructive path - a false-negative that silently skips a reachable box. Fix:
add the `-notmatch '^\d{1,3}(\.\d{1,3}){3}$'` wrapper.

**[P2] [V]** `modules/JanetWeb.upr.psm1` (fan-out ~`:1299`) - **no dispatcher self-guard on the EOL-uninstall
fan-out** (`grep IsSelf` = 0 hits). A Tenable report or pasted host list that includes the JANET box makes UPR open
a loopback session to itself and permanently uninstall proven-EOL software from the dispatcher. Fix: port
`restart`'s `Test-*HostIsSelf` drop.

**[P2] [R]** `modules/JanetWeb.pkginstall.psm1` (entry `:674-687`) - **no dispatcher self-guard on the install
fan-out.** Same class; a package that reboots (MSI 1641/3010, PSADT) on the dispatcher kills the server. Lower blast
radius (additive install) but the reboot path is real.

**[P2] [R]** `modules/JanetWeb.reports.psm1:5334-5336` (campaign-verify) - **a host's absence from a re-scan is
counted as scan-confirmed remediation.** A key not present in the new (possibly scoped/partial) scan is
unconditionally `REMEDIATED`, inflating `closedPct` and auto-flipping a campaign to `verified-closed` with a Success
audit - an operator/ISSM acts on a false "100% closed." Fix: check host coverage against the new scan's scope
before counting absence as closure.

**[P2] [V]** `modules/JanetWeb.winrmbridge.psm1:41,72` (revert + enable scripts) - **the bridge destroys a
pre-existing production 5986 listener.** Both scripts `Get-ChildItem WSMan:\localhost\Listener | Where Transport=HTTPS
| Remove-Item` - ALL HTTPS listeners, not just the JANET-tagged one - and revert never restores. A target that
legitimately had a 5986 listener loses it permanently, violating the "self-reverting, GPO stays authoritative"
contract. [new tool] Fix: only create/remove a listener the tool itself added (tag by cert/thumbprint), and skip if
a foreign HTTPS listener already exists.

**[P2] [V]** `web/js/views/winrmbridge.view.js:118` - **DOM-XSS: regex-REJECTED host names reflected unescaped into
a confirm `body`.** `body: 'Not valid: ' + v.bad.slice(0,5).join(', ')` - `v.bad` is precisely the target-list
entries that FAILED the safe regex (so they contain `< > " '`), and `confirmdialog.js:57` renders a string `body`
via `innerHTML`. The target list is TXT/CSV-importable (attacker-influenceable), so `<img src=x onerror=...>` in a
host list executes in the operator's session. This is the ONE unescaped `body` caller in the SPA. [new tool - my
code; corrects the session review's "no XSS" claim] Fix: `esc()` each entry or pass via the `list:` (textContent) field.

**[P2] [V]** `modules/JanetWeb.adto.psm1:466` (Invoke-AdToValidate) - **the recert stamp OVERWRITES its attribute.**
`$de.Properties[$attr].Value = $stamp` replaces the whole value of `recertifyAttribute` (default `info`, the Notes
field), destroying any existing content and keeping no history. [new tool] Fix: read-modify-append, or use a
dedicated attribute.

**[P2] [V]** `modules/JanetWeb.adto.psm1:408-427` (Invoke-AdToFix) - **mass account-disable runs off a stale plan
(TOCTOU) and has no RBAC gate.** `fix` disables accounts because the scan's plan said so, without re-checking the
finding at write time, and is gated only by a typed `FIX` (no IAO check for this higher-blast-radius op). An account
that logged on between scan and fix is still disabled. [new tool] Fix: re-evaluate the driving attribute at write
time for the disable rules.

**[P2] [R]** `modules/JanetWeb.certdeploy.psm1:170/279` - **CHECK and DEPLOY disagree on expired certs.** CHECK's
want-set includes expired non-allowlisted certs; DEPLOY excludes them - so a bundle with any expired non-allowlisted
`.cer` makes CHECK perpetually report `MISSING N` for certs DEPLOY will never push. (c2c's `Get-C2cCertBundle`
excludes them correctly; certdeploy is the asymmetric copy.) Fix: apply the same expiry filter to CHECK's want-set.

**[P2] [R]** `modules/JanetWeb.acas.psm1:1794-1808` (AcasRebootWorker) - **ambient-token reboot fallback with no
credential.** When `$Cred` is null the worker reboots via the server process's ambient token. The server DOES gate
`reboot-selected`/`schedule-reboot` behind ack+cred (`server:260,730` `$acasByIdDestructive`), so this null-cred
path should be unreachable for those actions - defense-in-depth only, but latent if the engine is ever invoked
outside the server gate.

## P3 (hardening / correctness / consistency)

- **[V]** `server/JanetWeb.Server.ps1:741` - malformed action JSON is caught-and-ignored, so the action runs with
  empty params instead of a 400 (2026-07-07 item c, CONFIRMED-STILL-PRESENT). The `/schedule` route did this right.
- **[R]** `server:730` - the destructive gate is wholly manifest-`destructive`-driven (+ the hardcoded ACAS by-id
  allowlist); a tool that omits `destructive:true` reaches the engine ungated. Gating correctness is delegated to
  per-tool manifest hygiene.
- **[R]** `server:290-303` - single-threaded accept loop: one slow upload / share read / `Get-Credential` picker
  freezes all request handling (loopback single-operator mitigates).
- **[R]** `server:673-696` - `pkginstall/msis?path=` enumerates an operator-supplied arbitrary local/UNC path with no
  root confinement (token-gated, runs as operator).
- **[R]** `reports.psm1:2095` - `PluginID` (raw ACAS cell) is not formula-escaped on the "Export Full CSV" path
  (other 3 cells are); `:872` IAVM-map writer and `:1283` unbounded CSV load (no row ceiling; history caps at 50k).
- **[R]** `acas.psm1:1059` - ACAS self-guard identity omits the bound-NIC IPv4 enumeration that `winupgrade:364`
  added (audit P3-1): a pasted OOB-NIC IP literal can slip the (fixed) `reboot-selected` self-guard.
- **[R]** `winupgrade.psm1:1187` - OOM classifier also matches free-text "out of memory" / "insufficient memory",
  misdirecting a non-page-file failure to the destructive `SetPageFile` fix.
- **[V/R]** `winrmbridge.psm1` - `-Force` revert orphans its own `-Revert-Force` task (revert deletes only `-Enable`/
  `-Revert`; Check probes only `-Revert`); self-guard omits NIC/DNS enumeration; targets bypass the suite's hostname
  format regex before `New-CimSession`. [new tool]
- **[R]** `adto.psm1:351` - operator `SearchBase` bound as `LDAP://$searchBase` unvalidated (bind-redirect, not
  filter injection; adsearch shares the pattern); `:459` `validate-iao` writes to any plan DN with no scope re-check.
- **[R]** `c2c.psm1:861` - the Patches no-deadline grace branch tests `StartTime`, which `CCM_SoftwareUpdate` does not
  expose in the standard ClientSDK schema, so a no-deadline overdue update may never count -> possible false PASS on a
  quarantine-tier pillar (lower confidence; bounded by the "MECM-deployed only" caveat).
- **[V]** `c2c.psm1:301` - stale comment says COAMS check is `@{ ...; equals?; ... }` but the code reads `expected`
  (`:304`); an operator following the comment writes `equals`, silently ignored -> COAMS presence-only, false PASS
  (Info-tier, so misleading not dangerous). [my code]
- **[R]** `restart.psm1:408` - message quote-escaping doubles only TRAILING backslashes; an interior `\"` can close the
  `/c` region early (operator-supplied text, so low impact).
- **[V]** New `.psm1`/`.ps1` files (adto, winrmbridge, the four new tests) lack the suite's UTF-8 BOM - currently 0%
  non-ASCII so they parse, but a latent decode bug the moment a non-ASCII char lands.
- **[V]** `JanetLocal/adto-baseline.json` is untracked (unlike git-negated `c2c-baseline.json`) - the editable ruleset
  will not ship in take-to-work.

## Verified clean (the strong parts)

- **Injection**: LDAP filters RFC-4515-escaped at every site in adsearch + reports Dirty30 (adto's filter is a static
  literal); no request input reaches `Invoke-Expression`/`Start-Process`/`ScriptBlock::Create` in the server (params
  passed as objects via `AddArgument`); WPT host tokens regex-gated before `New-PSSession`, uninstall strings passed as
  discrete `-ArgumentList` elements; ACAS/winupgrade `/c` strings are literals with sanitized/int-only fields; message
  via stdin pipe; dhcp is the most-hardened module (dotted-quad round-trip, empty-collapse guard).
- **Secrets**: BitLocker recovery password is escrow-first/fail-closed and never read or emitted; SecureBoot password
  is upstream-rejected on metacharacters, single-quote-escaped with doubling, and self-deletes.
- **Self-guard/DNS reference paths**: `restart` (full identity set + IPv4-skip), `winupgrade` (bound-NIC identity),
  the 9 fixed WPT workers, ACAS `reboot-selected`, `beta`, remoteadmin, c2c/certdeploy/secureboot destructive fan-outs.
- **Verify classifiers fail closed** (WPT/ACAS: thrown probe -> UNCONFIRMED/Failed, never Success). Custom commands are
  SHA256-audited. UPR proven-only gating + dry-run default + fail-closed re-enum. pkginstall SHA256-verifies packages.
  kev CVE-regex-validates before atomic persist. beta task-name validated + self-guarded.
- **SPA**: `resultsgrid`/`activitylog` render via `textContent`/`createTextNode`; `confirmdialog` preflight/list via
  `el()`; `esc()` covers all five chars; every other data-into-innerHTML caller escapes.
- **Server**: constant-time-enough token compare (fixed-length GUID), `Resolve-Path` + trailing-separator prefix
  static-file guard, upload filename/subdir sanitization + bounded copy, CSV formula guard in the log bridge,
  `Resolve-JanetWebToolName` now rejects `..`/dot-only (2026-07-07 item d FIXED), `?t=` honored only on the cancel
  beacon (item e FIXED). This copy has NO scheduler, so 2026-07-07 items a/b are not present.
- **Reports**: XXE hardened (DtdProcessing=Prohibit, null resolver, entity caps); burndown/SLA/ledger math sound;
  history reader traversal/DoS-safe (50k ceiling, LiteralPath, regex-validated host).
- **c2c new code**: the Phase-0 shared scan/import aggregator does not diverge; COAMS source-injection into the remote
  probe follows the `taniumInstalledSrc` pattern with correct ArgumentList/param order (10/10 outer, 13/13 fix chain)
  and no pool-runspace module-scope leak.

## Recommendations (priority order)

1. **P1-a**: add the `schedule-reboot` dispatcher self-guard (copy ACAS `:3154`). Block reboots-of-self.
2. **P1-b**: route UPR generic-MSI + Adobe removals through the strict-GUID decomposer (kill the `[^\}]+` injection).
3. **P1-c**: fix the AD Nemesis IAO identity source before the tool pilots.
4. **P2 self-guard parity**: add `Remove-WptSelfTargets` to forced bulk-patch + reg-apply-reboot; add self-guards to UPR
   and pkginstall fan-outs. Add the WPT app-update IPv4 skip.
5. **P2 server**: clear `AckGiven`/`Cred` on `/session/end`; return 400 on malformed action JSON.
6. **P2 new tools**: fix the WinRM Bridge listener-destroy + the view XSS; make the adto recert write append; gate/re-check the adto disable path.
7. **P2 reports/certdeploy**: fix campaign false-closure; align certdeploy CHECK/DEPLOY expiry filter.
8. **P3 sweep**: BOM the new files, track `adto-baseline.json`, fix the stale COAMS comment, formula-escape the reports PluginID cell, strengthen the ACAS/winrmbridge self-guard identity.
