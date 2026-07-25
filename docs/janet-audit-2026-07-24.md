# JANET Web — full per-module audit, 2026-07-24

**Method.** 26 independent Opus 5 agents, one per module plus the core server/auth, the
logging subsystem, the frontend shell, and the cross-cutting seams. Each agent read its
module in full plus its view and tests, was given the environment's specific hazards
(GPO-blocked ICMP, PowerShell hashtable key case-collisions, the `return ,$set` unary-comma
class, pool-runspace helper injection), was told the 2026-07-23 audit's findings were all
already fixed, and was instructed to drop any finding it could not tie to concrete
triggering inputs.

**Baseline.** Full Pester suite before the audit: **122 files, 1640 tests, 0 failures.**
Every finding below is in code that a fully green test suite passes. That is the single
most important structural fact in this report: the suite asserts *static text* — that a
profile name is present, that a literal appears in a scriptblock — and almost never asserts
*behaviour*. The three systemic defects below were each invisible to 1640 passing tests.

**Scale.** ~168 findings across 24 modules plus the server, logging, frontend and packaging.
This document leads with the systemic families — each verified first-hand by executing the
code, not taken on an agent's word — then the per-module ledger, then ten recommendations.

**Corroboration.** Three findings were reached independently by two agents that never saw
each other's work (the self-guard drift, the inert confirm gate, and the orphaned Snapshot
rows). I re-derived all three directly before writing them up; the self-guard result below
is a live execution on this host, not an inference.

---

## Part 1 — Systemic findings (verified first-hand)

### S1. [P1] The self-guard is bypassed in 7 of 12 modules — `return $set` drops the case-insensitive comparer

Each module that can act destructively builds a `HashSet[string]` of every name that means
"this is the JANET host itself" — shortname, FQDN, all bound IPs, loopback — using
`[StringComparer]::OrdinalIgnoreCase`, then caches it and returns it. Seven modules return
it **bare**:

```powershell
$script:AcasLocalIdentity = $set
return $set                        # <-- PowerShell unrolls the HashSet to Object[]
```

PowerShell enumerates an `IEnumerable` when it is written to the output stream, so the
caller never receives the HashSet — it receives an `Object[]`, whose `.Contains()` is
ordinal **case-sensitive**. The guard then only matches a target whose case exactly equals
`$env:COMPUTERNAME`. The five modules that write `return ,$set` (unary comma suppresses
unrolling) are correct.

Verified live on this host (`HADES`), calling each module's real guard predicate:

| module | source form | returned type | `'HADES'` | `'hades'` | result |
|---|---|---|---|---|---|
| acas | `return $set` | Object[] | True | **False** | **BYPASSED** |
| c2c | `return $set` | Object[] | True | **False** | **BYPASSED** |
| certdeploy | `return $set` | Object[] | True | **False** | **BYPASSED** |
| restart | `return $set` | Object[] | True | **False** | **BYPASSED** |
| secureboot | `return $set` | Object[] | True | **False** | **BYPASSED** |
| winupgrade | `return $set` | Object[] | True | **False** | **BYPASSED** |
| wpt | `return $set` | Object[] | True | **False** | **BYPASSED** |
| message | `return ,$set` | HashSet | True | True | guard holds |
| pkginstall | `return ,$set` | HashSet | True | True | guard holds |
| remoteadmin | `return ,$set` | HashSet | True | True | guard holds |
| dhcp | `return ,$set` | HashSet | True | True | guard holds |
| upr | `return ,$set` | HashSet | True | True | guard holds |

**Concrete trigger.** Any target list that names the JANET host in a case other than the
one `$env:COMPUTERNAME` reports. That is not exotic: Tanium exports and `import-pki-hosts`
supply lowercase, AD queries return mixed case, and an operator typing `hades` by hand is
the common path. The consequence per module is the module's own worst action performed on
the operator's own console: acas reboots/installs KBs/removes Java on it, winupgrade
deletes `$WINDOWS.~BT` and drives a feature update on it, certdeploy writes its trust store,
restart reboots it mid-wave, secureboot writes its firmware config.

This is the same defect fixed in `message.psm1` in a prior loop. It was fixed *in that one
file*; the other seven copies were never swept.

**Fix.** Add the unary comma to all seven, and add one behavioural test per module —
`Test-XHostIsSelf ($env:COMPUTERNAME.ToLower())` must be `$true` — so a future copy-paste
regresses loudly. The existing tests pass on all seven broken modules today.

Sites: `acas.psm1:1399`, `c2c.psm1:1354`, `certdeploy.psm1:730`, `restart.psm1:202`,
`secureboot.psm1:114`, `winupgrade.psm1:417`, `wpt.psm1:594`.

### S2. [P1] Two typed-confirm gates are inert — `ctx.confirm` silently ignores `confirmWord`

`ctx.confirm` maps to `ConfirmDialog` (`shell.js:1053`). `ConfirmDialog`
(`confirmdialog.js:101-115`) never reads `opts.confirmWord` — only `ArmingDialog` implements
the typed box (`:142-150`, disabling the go button at `:156`). So a view that passes
`confirmWord` to `ctx.confirm` renders a plain OK/Cancel dialog and the operator is never
asked to type anything. Nothing warns; the option is silently dropped.

Routing audit of every `confirmWord` site:

| view | line | dialog | status |
|---|---|---|---|
| **remoteadmin** | 221 | `ctx.confirm` | **INERT** — gate on fleet-wide arbitrary remote PowerShell |
| **secureboot** | 326 | `ctx.confirm` | **INERT** — gate on a fleet firmware write |
| certdeploy | 403 | `ctx.arm` | correct |
| pkginstall | 367 | `ctx.arm` | correct |
| restart | 644, 792 | `ctx.arm` | correct |
| upr | 584, 943 | `ctx.arm` | correct |
| wpt | 1268, 1450, 2460 | `ctx.arm` | correct |

`wpt.view.js:1260-1261` carries this comment:

> `// audit 2026-07-23: custom commands must go through ctx.arm - ConfirmDialog`
> `// ignores confirmWord, so the typed-RUN gate passed to ctx.confirm was inert.`

The 2026-07-23 audit found this exact bug, fixed the one call site it was looking at, and
left the root cause in place — so the other two sites still carry it. remoteadmin has no
server-side confirm check either (`remoteadmin.psm1:370` is the only destructive fleet
writer in the suite without one), so for arbitrary remote code execution the *only* barrier
is a dialog that does not implement its own gate.

**Fix.** Make `ConfirmDialog` either honour `confirmWord` or throw when handed one — a
silently-ignored safety parameter is the failure mode that produced all three instances.
Then route remoteadmin and secureboot through `ctx.arm`, and add the server-side confirm
check to `run-script`.

### S3. [P1] `test-single-host` reboots a machine with no confirmation of any kind

`restart.view.js:584`:

```js
var tr = ctx.run('test-single-host', { hostname: h, leadSeconds: 60, message: 'TEST: ...', dryRun: testDryRun });
```

`doTestSingle` (`:579-597`) calls `ctx.run` directly — no `ctx.arm`, no `ctx.confirm`, no
dialog. The adjacent Dry-run checkbox is created with no `checked: true`
(`restart.view.js:353`), so it defaults **off**. The action declares `destructive = $true`
(`restart.psm1:98`) and the dispatcher has no confirm-word check (`:1689`).

**Concrete trigger.** Operator types a hostname into the Single-Host Test box and clicks
"Test single host…". That machine reboots in 60 seconds. The label says *test*, the button
says *Test single host…*, and the tooltip says "Fire one synchronous shutdown /r" — but
nothing in the flow asks the operator to confirm, and the dry-run default means the safe
reading of "test" is the wrong one. Every other reboot path in the module is behind
`ctx.arm` with a typed `RESTART`.

**Fix.** Default the Dry-run checkbox to checked, and route the live path through `ctx.arm`
with a typed confirm naming the single host.

### S4. [P2] JANET Web's own in-app readers ignore Snapshot rows

Found independently by the logging agent and the history agent, which is why it is here
rather than in the ledger. Both framed it as "the Snapshot fix un-blinds nothing" — that
overstates it, and the distinction matters:

- The **external JanetDashboard v4** *does* consume Snapshot rows (it dedupes per
  `SessionId|Tool`, ranking SessionEnd > Snapshot). The 2026-07-12 fix works there, which is
  what it was written for.
- JANET Web's **own in-app views** do not. `history.psm1:519` and `reports.psm1:6893` both
  hard-filter `if ([string]$_.RowType -ne 'SessionEnd') { return }` and drop everything else.

So the operator-facing History and Reports panels *inside JANET Web* still show Sessions=0 /
HostsTouched=0 for any session that is currently running or was killed — while the external
dashboard shows it correctly. The writer-side fix was simply never mirrored into the two
in-app readers.

**Fix.** Accept `Snapshot` in both readers with the dashboard's existing precedence — newest
Snapshot per `SessionId`, superseded by `SessionEnd` once the session closes — so a session
is counted exactly once and the in-app view agrees with the dashboard.

---

## Part 2 — Per-module ledger

Severity: **P1** data loss / acts on the wrong box / security / an answer an operator would
trust that is silently wrong. **P2** real bug in a plausible path. **P3** robustness/UX.
**P4** nit.

### wpt (6761 ln) — 4 findings
- **P1** `bulk-scan` never injects `Test-WptRemoteNameMatch`; every online host returns an all-`Error` row, the guard is inert, and the run still reports "N ok" — `wpt.psm1:5722` (worker `:2172`)
- **P2** `kb-install` books Success + `VulnPatched` for hosts where the KB was skipped and never verified — `:6302`
- **P3** `healer-ccm-repair` reinstalls the ConfigMgr client with no wrong-box guard — `:2620`
- **P3** `fix-java` / `spec-exec-scan` / `spec-exec-enable` declared in the manifest, unreachable from the view — `:316,326,335`

### reports (7582 ln) — 5 findings
- **P2** `acas-host-summary` double-counts a Patched + NOT-OUR-PATCH finding; Open goes negative and PatchRate is overstated — `:6180-6192`
- **P3** `acas-ping-hosts` records never-probed hosts as *confirmed* offline, feeding the "Offline (host down)" export — `:6800, :6824`
- **P3** `weekly-export-csv` single-week write is the only output write with no TCP-445 pre-gate; on a dead UNC it blocks the whole serialized runspace — `:4796`
- **P3** `iavm-board` groups on the raw multi-value IAVA string → a phantom compound bulletin — `:5375-5395`
- **P3** Grid "Offline only" counts Unresolved as offline while the export excludes it; `markAllVisible` then bulk-triages unresolved hosts — `reports.view.js:517,478`

### acas (3973 ln) — 4 findings
- **P1** dispatcher self-guard comparer lost — see **S1** — `:1399`
- **P2** `kb-install` rowOf has no UNCONFIRMED branch: ships `Result='OK'` (green) while the audit books Failure — `:3837`
- **P2** MSU fallback passes an unquoted package path to `wusa.exe`; any filename with a space fails fleet-wide — `:3020`
- **P4** `patch-selected`/`reboot-selected`/`verify-selected` server-whitelisted but unreachable from the view — `:3366,:3880`

### winupgrade (3972 ln) — 9 findings
- **P1** `auto-fix` deletes drivers/`$WINDOWS.~BT` and writes policy with **no wrong-box abort** (the guard sits only at the reboot step) — `:2794`
- **P1** supported-CPU regex rejects 4-digit Intel 11th–13th gen mobile SKUs → false HW-INCOMPAT, and `auto-fix` then writes the MoSetup bypass on supported hardware — `:501`
- **P2** no-op remediations book `VulnPatched` Success — `:3864`
- **P2** 64 GB *free*-disk gate misapplies Win11's 64 GB *total*-storage minimum; its own fix text says 25 GB — `:496,:1660`
- **P2** RepairHealth DISM/SFC and InstallUpdates SYSTEM-task registration run before any wrong-box check — `:2684,:3185`
- **P2** `upgrade-drive` silently rewrites an unrecognised free-text version to 24H2 and drives to it — `:3509-3511`
- **P3** `Get-WinUpgradeDrivePlan` hardcodes 26100 while the worker uses `$MinBuild` — `:466`
- **P3** `PIN FAILED` / `ON 25H2` render uncoloured — `winupgrade.view.js:206,236-242`
- **P3** RepairHealth watchdog 3600 s < its own advertised DISM+SFC runtime → false FAILED — `:3541`

### c2c (3631 ln) — 5 findings
- **P1** self-guard comparer lost — see **S1** — `:1354`
- **P2** `fix-antimalware` books "already protected / NO CHANGE" when signature age is unreadable — the state the scan fail-closes on — `:1965`
- **P3** `NOT VERIFIED` rows have no colour class and no tally bucket — `c2c.view.js:1175-1188`
- **P3** done-line folds `NOT ATTESTING` into "CHECK ERRORS"; an all-NOT-ATTESTING fleet renders green — `c2c.view.js:546`
- **P4** `run-all` manifest omits `prunePki`/`fixRdp` inputs the view posts and the engine reads — `:225-234`

### restart (1982 ln) — 6 findings
- **P1** `test-single-host` fires a live reboot with zero confirmation — see **S3** — `restart.view.js:352`
- **P1** self-guard comparer lost — see **S1** — `:202`
- **P2** backslash-before-quote in the countdown message escapes the `/c` token → `shutdown.exe` argument injection (`/s`, `/t 0`, lost `/f`) — `:415` (copy `:971`)
- **P2** `verify-boottime` bare `HH:mm` parses to *today* → cross-midnight verify reports the whole fleet "Did NOT restart - confirmed" — `:1926`
- **P3** Exceptions (never-restart) entries failing the host-token filter are silently discarded and the host is rebooted — `:1392`
- **P3** consent staging dir grants Modify to Authenticated Users while the executed agent script lives in it — cross-user TOCTOU — `:589`

### upr (1981 ln) — 5 findings
- **P2** relaxed (pasted-PDF) parser never sets `HostAttribution` → least-exact mode reports ATTRIB="exact" — `:688`
- **P2** Targeted-Removal M365 handler uses `<Remove All="TRUE"/>` — removes *every* C2R Office product, not the selected candidate — `:993`
- **P3** `Decision='Abandoned'` rows land in no tally bucket — `upr.view.js:630,675`
- **P4** Adobe handler re-reads the uninstall key without `-LiteralPath`, feeding a globbed GUID to `msiexec /x` — `:1041`
- **P4** `pdftotext` failure paths leak `%TEMP%` files — `:487`

### adsearch (1895 ln) — 9 findings
- **P1** `search-user` emits unconditional `(givenName=*)`/`(sn=*)` presence clauses — `.adm`/`.adw`/service accounts are invisible even on an exact EDIPI search — `:419`
- **P2** groups over 1500 members report `MemberCount = 0` (AD range retrieval renames the key to `member;range=0-1499`) — `:1321`
- **P2** LastPC files a clean "no matching events" DC as a DC error and never increments `$dcsScanned` — bogus coverage + false "you lack permission" hint — `:970`
- **P2** LastPC zero-hit exit omits `_Failure`, so an all-DCs-denied scan audits as Skipped / "Done. No results." — `:1112`
- **P3** no `ClientTimeout`/`ServerTimeLimit` on any of the six searchers — `:347-348`
- **P3** no disposal at 13 `FindAll()` sites; BaseUsers leaks 3 objects per child OU — `:420`
- **P3** Base Users renders non-replicated `lastLogon` (shows "never") where every other action uses `lastLogonTimestamp` — `:1494`
- **P3** view never reads `summary.failed` → a rejected SearchBase paints amber "NO RESULTS" not red "SEARCH ERROR" — `adsearch.view.js:503`
- **P3** `search-manager` takes `[0]` of an N-match wildcard with no ambiguity warning — `:497`

### certdeploy (1671 ln) — 5 findings
- **P1** self-guard comparer lost — see **S1**; proven live — `:730`
- **P2** disallowed (untrust) push has no guard and labels its adds `| trusted:` while the arm dialog promises "never removes anything" — `:1263`
- **P2** `NOT VERIFIED` / `REJECTED (non-CA)` fall into no stat bucket → a fleet reconciler strip closes green with 0/0/0 — `certdeploy.view.js:283-284`
- **P3** expired-in-bundle badge reads `sum.ExpiredCount`; module returns `expiredCount` → permanently inert — `certdeploy.view.js:336`
- **P4** cancelled `scan-cert-management` hosts reported as `CHECK ERROR` — `:1638`

*Verified clean:* legacy allowlist genuinely single-source; no `.cer` in the take-to-work zip; TCP-only reachability; wrong-box abort in all three remote scriptblocks; RawData push cannot carry a private key.

### secureboot (1410 ln) — 6 findings
- **P1** typed-ENABLE barrier inert end-to-end — see **S2** — `secureboot.view.js:323,326,354`
- **P1** enable path never suspends BitLocker (zero BitLocker/TPM references in the module) → every TPM-protected host hits the recovery screen on the pending reboot — `:383`
- **P2** self-guard comparer lost — see **S1** — `:114`
- **P3** post-run C$ diagnosis probes the share after the credentialed PSDrive is removed → real timeouts misreported as "permission denied" — `:720`
- **P3** brick-safety refusals render green and tally as "already enabled" — `:374-378`
- **P4** Dry Run tooltip advertises DCOM, which the worker refuses to use — `secureboot.view.js:158`

### dhcp (1356 ln) — 6 findings
- **P1** view never sends `confirm`, so every apply/bulk-* is refused server-side — the destructive half of the tool is inert — `dhcp.view.js:342,362` vs `:1202`
- **P1** bulk results collapse into one bogus row (`,$out.ToArray()` survives the `[powershell]` handle; `@($bulkCall.Result)` unrolls one level) — successful multi-scope writes book 0 changed / 1 failure — `:543,:1009`
- **P2** "Remove option" unusable: view posts loaded IPs alongside the checkbox, module refuses the combination — `dhcp.view.js:337` vs `:1301`
- **P3** editing the server field after Connect silently retargets load/apply/bulk — `dhcp.view.js:293`
- **P4** `expectedOld` (the whole optimistic-concurrency guard) undeclared in the manifest — `:1311`
- **P4** dry run previews `WouldRemove` where the live path books `NoChange` — `:723`

### pkginstall (1272 ln) — 4 findings
- **P1** payload staged in world-writable `C:\Temp` under a predictable name, MOTW-stripped, then executed as the deploy credential — local privilege escalation — `:392-394`
- **P2** view drops `Success (warnings)` / `AlreadyInstalled` from its terminal set — soft-failed and refused installs uncounted and uncoloured — `pkginstall.view.js:53-56`
- **P3** `Copy-Item -Path $PkgPath` treats the operator package path as a wildcard — `:439`
- **P3** `installTimeoutMin` manifest input never posted by the custom view — the 30-min cap is unraisable — `pkginstall.view.js:382-390`

### adto (648 ln) — 9 findings
- **P2** "Only show NON-COMPLIANT" makes tiles/dialog report the bad count as the total — `adto.view.js:241`
- **P2** "never logged on = maximally stale" has no object-age floor — a pre-staged account is flagged and auto-DISABLED — `:185`
- **P2** no `__job` cancel bridge (only module in the suite without one) — CANCEL inert, destructive loops unabortable, no search timeout — `:402,460,500,605`
- **P2** runbar never locked during fix/validate — clicking SCAN mid-fix detaches the live destructive run's result stream — `adto.view.js:266`
- **P3** `uacUnreadable` fail-closed hit wired only into the User/Admin/Service branch — `:190` vs `:202`
- **P3** DirectoryEntry/DirectorySearcher never disposed — `:434-473`
- **P3** fix/validate REJECTED text blames the operator's DN when the cause is an unset `USERDNSDOMAIN` — `:510,613`
- **P4** dead local `$needIao` — `:166`
- **P4** `Object` column truncates a CN with an RFC-4514 escaped comma — `:503,608`

### history (635 ln) — 5 findings
- **P1** every read failure swallowed (`catch { $rows = @() }`, bare `catch {}`) → stale-hosts emits a false NEVER TOUCHED and host-timeline says "no rows" on a failed read — `:244,276,334`
- **P2** usage reader ignores Snapshot rows — see **S4** — `:519`
- **P2** `Resolve-HistRoot` computes `Exists` and no caller reads it — share down reports identically to a genuinely empty trail — `:153`
- **P2** view drops the `UNKNOWN (capped)` verdict; status line turns green on a fully-capped run — `history.view.js:29`
- **P3** `Read-HistUsageRows` is the only unbounded read — `:307`

*Verified clean:* writer↔reader schema, datetime sorting, no key collision, no path traversal. No `History*.Tests.ps1` exists.

### sysadmin (566 ln) — 4 findings
- **P1** DNS-guard wrapper double-wraps the probe payload; all three sweeps return wrong data — localadmin AdminCount always 1, rebootpending 100% false-positive, certexpiry false-CLEAN on multi-cert hosts — `:300`
- **P3** `days = 0` silently rewritten to 90; `TryParse` result discarded — `:440`
- **P4** clean cert hosts logged amber — `:489`
- **P4** redundant `Remove-PSSession` in the probe catch — `:308`

### remoteadmin (538 ln) — 6 findings
- **P1** typed-RUN gate on fleet-wide arbitrary RCE is inert — see **S2** — `remoteadmin.view.js:221`
- **P2** no server-side confirm-word gate on `run-script`; the only destructive fleet writer without one — `:370`
- **P2** `-ErrorAction Stop` on the operator's Invoke-Command discards all output the block already produced — `:303`
- **P3** advertised `#` comment syntax does not exist — comment words become live targets — `remoteadmin.view.js:120`
- **P3** `(run-script)` audit sentinel unrecognized → phantom host in TouchedHosts — `:419`
- **P3** no `MaximumReceivedDataSizePerCommand` — one chatty host buffers unbounded — `:263`

### patchlib (516 ln) — 5 findings
- **P2** crossref renders MISSING for content it never scanned — `:450`
- **P2** product-name matching is a raw substring test, so any multi-word name (including the view's own "Google Chrome" placeholder) misses every real package folder — `:493`
- **P3** `-PackagesRoot` leg dedupes by raw string → FQDN/relative aliases double-count — `:128`
- **P4** every folder walked twice per inventory — `:232`
- **P4** view re-materializes the whole grid per streamed row — `patchlib.view.js:157`

### message (509 ln) — 5 findings
- **P2** watchdog clock stamped at *enqueue* — a saturated pool false-times-out its own backlog — `:418`
- **P2** destructive send has no wrong-box guard; the remote block never verifies it landed on the dialed host — `:189`
- **P3** "nobody logged on" and operator-requested TCP skips booked as Failure though a Skipped verdict exists — `:221`
- **P3** watchdog/cancel-abandoned hosts reported as `Unreachable` — an unmeasured network claim — `:459`
- **P4** `$okOf` dead in both branches — `:375`

### kev (417 ln) — 9 findings
- **P1** ACAS KEV badging silently reports "no known-exploited groups" when the catalog is missing/unreadable — `acas.psm1:3293,3356`
- **P2** no catalog-age signal — a months-old snapshot yields a green all-clear — `:107,299,408`
- **P2** xref streams "Not listed" rows before the empty-catalog hard stop; grid/cards/CSV read as all-clear — `:388-393`
- **P3** manifest declares an IAVA column no grid or export renders — `:41`
- **P3** add-kev per-CVE Status rows streamed and discarded — `kev.view.js:281-292`
- **P3** multi-CVE cells inherit the row's Year column — `:262`
- **P4** add-kev `total` computed by arithmetic instead of the merged count — `:364`
- **P4** `$script:kevFinal` smuggles the merged list out of the lock body — `:350`
- **P4** header-detection fallback scans all rows per column — `:244-247`

### biosfirmware (333 ln) — 3 findings
Read-only module; no flash/apply path exists, so flash-safety controls are N/A, not missing.
- **P2** DNS-mismatch guard has no IPv4-literal exemption — every IP-address target falsely "skipped" — `:159-160`
- **P3** "unbaselined model" roll-up conflates no-baseline with unreadable-BIOS — `:318,326`
- **P4** operator cancel emits rows but no progress event — `:294-295`

### winrmbridge (306 ln) — 11 findings
- **P2** every enable/revert audit row is discarded — action id outside the TouchHost/VulnPatched ValidateSet — `:294`
- **P2** revert destroys ANY HTTPS listener once our cert exists, including one provisioned during the bridge window — `:46`
- **P2** temp listener + firewall rule opened to every network, every profile, every NIC (no `-RemoteAddress`/`-Profile`) — `:85`
- **P2** `check` reports Bridge=ACTIVE from a scheduled task's existence, never probes 5986 — `:268`
- **P2** CIM sessions leak on every failure path — no `finally` — `:292`
- **P2** operator Cancel is a no-op — never reads `$Params['__job']` (16/16 peers do) — `:221`
- **P3** `threads` declared and posted but never read; the loop is strictly serial — `:246`
- **P3** DCOM attempted whenever any of 4 ports answers; port 135 never required, connect untimed — `:253`
- **P3** manifest promises "flags LEFTOVER bridges"; module never emits LEFTOVER — `:166`
- **P3** `Start-ScheduledTask` failure swallowed while the row still says BRIDGING — `:282`
- **P4** "TCP TCP 5985" double-prefixed label — `:271`

### specfix / troubleshoot / javafix (436 ln) — 6 findings
- **P2** javafix books `FIXED` (+VulnPatched Success) on a host where it removed nothing — `javafix.psm1:193-194`
- **P2** javafix verdicts every non-8/non-9+ dotted version OLD, so Oracle's current `Java Auto Updater` (2.8.491.9) is msiexec-removed on compliant hosts — `javafix.psm1:54`
- **P2** javafix filesystem sweep has no vendor gate — deletes a non-Oracle JDK 8 tree the header promises is never touched — `javafix.psm1:169`
- **P3** troubleshoot maps 0x8009030E to "wrong password" and lacks the real 0x8009030C — `troubleshoot.psm1:38`
- **P3** wpt `fix-java` defaults an empty engine result to NOCHANGE/Success while `spec-exec-enable` defaults to FAIL — `wpt.psm1:6157`
- **P4** javafix repoints JavaSoft CurrentVersion via a lexical version-string sort — `javafix.psm1:145`

### core server + auth (1303 ln) — 3 findings
No P1. Path traversal, auth gating, dispatch name-resolution and listener-death paths were
examined specifically and came back clean.
- **P2** static assets sent with Last-Modified but no Cache-Control → heuristic caching serves stale JS/CSS after an update — `Server.ps1:465`
- **P3** a URL containing `<` `>` `|` `"` throws in `Path::GetFileName` → 500 + stack trace instead of 404 — `Server.ps1:45`
- **P3** startup wipe of shared `%TEMP%\JanetWeb\uploads` destroys a concurrent instance's live uploads — `Server.ps1:159`

### logging (815 ln) — 8 findings
- **P2** Snapshot rows have no consumer — see **S4** — `Logging.ps1:528-530`
- **P2** `OnShare` demotes to local-only on one transient failure and never re-arms for the session — `:403`
- **P2** aggregate `HostsTouched` counts file paths and report labels as machines — `:442`
- **P3** `/api/logs/tail` reads a month frozen at server start — the viewer goes blank after a rollover — `:252`
- **P3** header-rotation retry ladder sleeps up to 12.4 s holding the global context lock the accept thread also takes — `:398`
- **P3** replay is at-least-once: a swallowed rename duplicates a whole spool file into the trail — `:807-811`
- **P3** `reports fleet-activity` misses header-ensure sister files (history was fixed, reports was not) — `reports.psm1:6888`
- **P4** `Edipi`/`SourceHost` bypass the escaper every sibling field uses — `:699,648`

### frontend core (shell + components + help, ~3600 ln) — 10 findings
**XSS: CLEAN.** 73 innerHTML-class sinks — 42 are clears, 17 literal, 4 numeric-only, and
all 3 fleet-derived sinks are `esc()`'d. Registry↔view↔help contract intact.
- **P1** remoteadmin inert gate — see **S2** — `remoteadmin.view.js:221`
- **P2** dhcp writes refused server-side — `dhcp.view.js:342`
- **P2** secureboot gate inert client-side and auto-satisfied server-side — `secureboot.view.js:326`
- **P2** failed manifest fetch swallowed → destructive runs downgraded to non-destructive, wpt drops its confirm dialog entirely — `shell.js:983`
- **P2** `setLoading(true)` never cleared → grid spins "Loading…" forever on a zero-row result — `winupgrade.view.js:909`
- **P3** the app's only fetch has no timeout/abort — `shell.js:167`
- **P3** modals have no accessible name and no focus trap — `confirmdialog.js:40`
- **P4** TabHost renders tabs as plain buttons — no tablist/tab/tabpanel roles — `tabhost.js:32`
- **P4** secureboot reads a `confirm` param it never declares — `secureboot.psm1:1195`
- **P4** dead code: unused `SUITE` (`shell.js:532`), duplicate `defaultUnmount`, remoteadmin guides misfiled under wpt

### cross-cutting seams + packaging — 12 findings

The guard-drift analysis independently reproduced **S1** by executing all 13 identity
helpers and getting the same 7-of-13 split — arrived at separately from my own run above.

**Guard-helper drift matrix.** 4 families examined: self-guard identity (13 copies),
wrong-box `$env:COMPUTERNAME` abort (~30 sites across 13 modules), TCP 445/5985 probe (~20
copies), CSV formula-escape (4 copies). Duplication is by design; **divergence** is the
finding. Three real divergences plus one masked:
- the unary-comma comparer loss, 7/13 — **S1**
- `acas` is the only identity set missing the bound-NIC IPv4 enumeration — `acas.psm1:1390-1397`
- `biosfirmware` is the only wrong-box guard without the IP-literal carve-out — `biosfirmware.psm1:159-161`
- `Protect-JanetWebCsvField` omits the CR sigil its 3 siblings carry (currently masked) — `Logging.ps1:283`

*Clean:* the TCP-probe family (two idioms, both correct) and the confirm-word family (4
Trim/case combinations, none unsafe — but two are each documented as "the suite idiom").

**Packaging findings:**
- **P2** 38 of 47 archived take-to-work zips carry **183 certificate files each**; sync never retires them — `Sync-TakeToWork.ps1:106`. *Verified independently:* the newest cert-bearing cut is `2026-07-15_082744.zip`, i.e. the 2026-07-17 no-certs policy holds for every cut made after it, but no pre-policy cut was ever purged. The archive is the folder a zip gets grabbed from for a trip.
- **P3** the cert gate is a 4-extension allowlist — `.pfx/.p12/.pem/.der` ship silently — `Sync-TakeToWork.ps1:35`
- **P3** sync gates only on cert extensions: no parse sweep, no test run before zipping — `Sync-TakeToWork.ps1:84-101`
- **P2** shipped README documents `tests\`, `docs\` and a "shipped DoD trust bundle" the zip does not contain — `README.md:57-65`
- **P2** README claims 18 tools; the registry has 21, seven unlisted — `README.md:5,71`
- **P3** `biosfirmware`, `history` and `patchlib` have **zero tests**; no test anywhere asserts case-insensitive self-guard matching — `tests\Message.SelfGuard.Tests.ps1:25,30`
- **P4** `.gitignore` still promises certs "ride along in every take-to-work cut" — `.gitignore:14-19`

---

## Part 3 — The ten to implement

Ordered by risk retired per unit of work.

**1. Sweep the self-guard family and pin it with a behavioural test.**
Add the unary comma at the seven sites in S1, then add one test per module asserting
`Test-XHostIsSelf($env:COMPUTERNAME.ToLower())` is `$true`. Retires seven P1s and is the
highest-value change in this list. ~30 minutes.

**2. Make silently-ignored safety parameters impossible.**
`ConfirmDialog` must honour `confirmWord` or throw when handed one; then route remoteadmin
and secureboot through `ctx.arm` and add the missing server-side confirm to `run-script`.
The prior audit fixed one instance of this and left two — fixing the root is what stops the
third.

**3. Confirm-gate `test-single-host`, and default its Dry-run box to checked.**
A button labelled "test" that reboots a production machine on one click, with no dialog, is
the sharpest edge in the suite.

**4. Introduce a shared guard library with injected copies generated from one source.**
The duplication is deliberate — pool runspaces cannot see module functions — but today the
copies are hand-maintained and three separate families have now drifted (self-guard,
confirm routing, TCP probe). Keep one canonical definition and generate the injected copies
from it, so drift becomes impossible rather than merely detectable.

**5. Adopt an explicit "unverified" state across every tool that reports a verdict.**
The single most repeated finding in this audit is *not knowing* rendering as *fine*: kev
reports no known-exploited vulns when the catalog is unreadable; c2c books "already
protected" when signature age is unreadable; history reports NEVER TOUCHED on a failed
read; certdeploy and c2c have NOT-VERIFIED rows with no colour and no bucket; adsearch
paints a failed search amber "no results". Make the unverified state a first-class value
that every roll-up, colour map and CSV must handle, and refuse to compile a green summary
that contains one.

**6. Wire the Snapshot rows into the two in-app readers.**
The external dashboard already handles them; JANET Web's own History and Reports panels do
not, so they under-report every live session while the dashboard beside them is correct.
Small change, and it removes a contradiction an operator will eventually notice and distrust.

**7. Add behavioural tests, not text-presence tests.**
1640 tests pass on all of the above. The suite asserts that literals appear in scriptblocks.
Start with the classes that actually bit: guard predicates (S1), dialog routing (S2),
version comparison as `[version]` not string, and tally arithmetic that must never emit a
negative or exceed its denominator. Ten of these would have caught most of Part 2.

**8. Stop staging executable payloads in world-writable paths.**
pkginstall stages into `C:\Temp` under a predictable name, strips MOTW, then executes as the
deploy credential; upr has the same shape. Stage into an ACL'd directory under
`%ProgramData%` created with an explicit DACL, and verify the payload hash after copy.

**9. Fix version and identity comparison wherever it is a string compare.**
winupgrade's CPU regex, biosfirmware's BIOS strings, javafix's Java versions, patchlib's
substring product match. These produce confidently wrong answers about the fleet — the
winupgrade one both blocks supported hardware and writes a bypass on it.

**10. Purge the pre-policy take-to-work archive and widen the cert gate.**
38 of 47 archived zips carry 183 certificates each. The 2026-07-17 policy stopped new cuts
from including them but never retired the old ones, and the archive is exactly where
somebody reaches for a zip. Purge the superseded cuts, and widen the gate's 4-extension
allowlist so `.pfx/.p12/.pem/.der` cannot ship silently. Then add a parse sweep and a test
run to the gate, so packaging cannot ship code that does not load.

*Runner-up, worth doing but cut for the ten:* give long-running remote calls a uniform
timeout and cancel path — adsearch has no searcher timeout, adto no `__job` bridge at all,
remoteadmin no output cap, winrmbridge's Cancel is a no-op, shell.js's fetch has no abort.
Each is small alone; together they are why one bad host can wedge a console the operator
then force-closes mid-write.

---

## Appendix — what was verified clean

Worth recording, because it bounds the blast radius: **frontend XSS** (73 sinks, all
fleet-derived ones escaped); **core server path traversal, auth gating, and dispatch
name-resolution**; **certdeploy's legacy-intermediates allowlist** (genuinely single-source)
and its private-key handling; **the take-to-work zip's exclusion of certificates**;
**history's writer↔reader schema and datetime sorting**; and **TCP-only reachability** in
every module that was checked for it except the sites listed above.

---

# Part 4 — Fix pass and independent re-audit (same day)

All ten recommendations were implemented, then re-audited by a **different model (Fable 5)**
given the list of claimed fixes and told to verify each independently rather than trust it.
That second pass is what this section is really about: it found defects the fix pass missed,
including two that the fix instructions themselves caused.

## Method

- 4 systemic fixes applied by hand across many files.
- 26 fix agents — one per module plus core server / logging / frontend / packaging — with
  **non-overlapping file ownership** so they could run concurrently without clobbering.
- 13 Fable 5 re-audit agents, read-only, each told to verify every claimed fix, hunt for
  regressions, and judge whether the new tests are behavioural or merely source-text.

## Test suite

| Point | Files | Tests | Failed |
|---|---|---|---|
| Baseline (before any fix) | 122 | 1640 | 0 |
| After fix pass + re-audit fixes | 143 | 2157 | 0 |

The baseline is the important number: **1640 tests passed while every defect in Parts 1-2 was
live.** The suite asserted static text. New tests were verified to FAIL when their fix is
reverted — several agents proved this explicitly by reverting the module in a scratch copy.

## What the re-audit caught that the fix pass did not

### [P1] sysadmin `_rk` child-scope collision — modules/JanetWeb.sysadmin.psm1:534
`$emitResult` is invoked with `&`, a child scope, so `$rk++` on an `[int]` wrote a child-scope
local and the parent counter never advanced. **Every host got `_rk='r1'`.** The view keys rows
by `_rk` and the grid upserts by it, so each host silently REPLACED the previous: the stat
cards said N hosts while the grid and the CSV export showed one. For a local-admin membership
audit that is a silently wrong answer, not a cosmetic bug. Pre-existing, and missed by the fix
agent that edited this very block — `remoteadmin.psm1:514` already carried the identical fix
*with an explanatory comment*. Fixed with a reference-type counter; reproduced before and
after (1 distinct key for 3 hosts, then 3).

### [P2] The remoteadmin fix rested on a false claim — modules/JanetWeb.remoteadmin.psm1
The comment justifying the new server-side gate said run-script "was the only destructive
fleet writer in the suite with no server-side confirm word". It was not: wpt's
`app-update-apply` with the **Custom Command** profile is equivalent-severity fleet-wide
arbitrary remote PowerShell and had no server-side word either. Both now have one; the false
comment is corrected in place rather than quietly deleted.

### [P3] Every typed-confirm gate was case-INSENSITIVE — 8 modules
`-ne` folds case, so `confirm='run'` passed a gate whose own error text says "type RUN
(exactly)" — proven by probe against the live gate. Standardised to `-cne` across all eight.
Three tests had to be corrected because they *pinned the weaker behaviour*, one explicitly
asserting that lowercase `deploy` must be accepted "matching adto's `-ne 'FIX'`".

### [P3] The Snapshot precedence bug this audit's own fix introduced — modules/JanetWeb.history.psm1
The S4 fix accepted `RowType='Snapshot'` in the readers, justified by a comment stating that
Snapshot "writes per-tool rows ONLY, never an aggregate 'JANET-WEB' row". That was true when
written and became false **later in the same pass**, when the writer was changed to emit an
aggregate row so reports' scope filter could still see a live session. The dedupe was then
last-read-wins between two aggregate rows, and files are read newest-month-first — so across a
month rollover or a mid-session share blip, an older cumulative Snapshot could overwrite the
final SessionEnd value and understate HostsTouched. Now ranked explicitly: **SessionEnd
aggregate > Snapshot aggregate > per-tool max.**

### [MEDIUM] The 30s fetch timeout aborted the credential prompt — web/js/shell.js
Recommendation 10 asked for a fetch timeout. `POST /api/cred` blocks on a console
`Get-Credential` that is **operator-paced** — the server deliberately extends its idle timeout
to 20 minutes for exactly this. The 30s client abort turned any slower-than-30s credential
pick into a silent failure: the error is swallowed, there is no periodic refresh, so the UI
showed "no credential" while the credential *had* been set server-side. `uploadFile` was
excluded; `/cred` should have been too. Now excluded, with the rule stated as: never abort a
request whose duration is a human's to decide.

### [MEDIUM] The replay-idempotence fix traded duplication for silent loss — server/JanetWeb.Logging.ps1
The `.replayed` receipt was a bare "skip this file forever" marker. The spool path is
deterministic per month, so a file that survived the rename keeps receiving NEW rows on the
next local-only demotion — and every future replay skipped it on sight. Losing audit rows
silently is strictly worse than duplicating them loudly. The receipt now records
`replayedLines=<n>` and later passes replay only the tail. Verified live: 2 rows replayed,
2 appended, 4 total on the share, zero duplication.

## Verified clean by the re-audit

- **Path-traversal containment byte-identical** after the leaf-extraction change, confirmed
  with a live hostile battery (`..%2f`, `%2e%2e`, backslashes, `C:/`, UNC, overlong-UTF8, ADS,
  8.3, trailing dot/space). The regex leaf-strip also incidentally closed a *pre-existing* ADS
  bypass of the underscore-asset block.
- **`Monitor::Wait` introduced no race** — the lock is released only between complete append
  attempts, no invariant spans the Wait, and the lock is never nested.
- **13/13 self-guards** pass behaviourally in lower, upper and exact case, on both the cold and
  the cached return path.
- **All 18 `confirmWord` call sites** reach ArmingDialog; a stray future `ctx.confirm` carrying
  a confirmWord would now render the gate rather than silently drop it.
- **LDAP filter and DN escaping fully intact** after the filter-builder refactor, verified with
  injection probes rather than by reading.
- **Both LPE staging fixes sound** — the DACL is protected before the first payload byte, and
  the `New-Item`-to-`Set-Acl` window is not exploitable.
- **The shutdown.exe escaper** survived 20 targeted hostile inputs plus 3300 random cases
  parsed back through the real `CommandLineToArgvW`.
- **The two loosened gates were independently justified**: the CPU regex admits only 4-digit
  `1x`-leading Core SKUs (all Win11-supported; 1st-gen is 3-digit, 2nd-7th lead with 2-7), and
  25 GB is correct because 64 GB is Win11's *total-storage* minimum while the module gates
  *free* space.

## Still open (deliberately not actioned)

- `secureboot`'s `manage-bde` fallback fails OPEN when the BitLocker cmdlets are absent and
  `manage-bde` output is unreadable, empty, or localized. The main path is sound and the
  fallback is dead on a cmdlet-bearing fleet, but the Detail text ("no protected volume to
  suspend") is dishonest about an unknown state.
- BitLocker is suspended before the manufacturer switch, so an unsupported OEM or a rejected
  write leaves the host unprotected for one reboot with no firmware change to show for it.
- wpt's new "EVERY host failed" banner counts *skipped* hosts, so an all-skipped kb-install run
  reads as a total failure while the audit trail stays honest.
- A `#` comment or `(annotation)` in restart's never-restart Exceptions box now hard-aborts the
  whole wave. It fails safe and names the entry, but those annotations are common in host lists.
- `certdeploy` Check can never read green under the new default-OFF distrust push.
- The same Untrusted-to-Disallowed push is still un-gated in c2c's fix-pki/run-all — the two
  tools now embody opposite judgments about whether it needs arming.
- **X:\Archive holds 38 of 47 take-to-work zips carrying 183 certificates each**, all
  pre-dating the 2026-07-17 no-certs policy. Untouched deliberately: it is the operator's data
  and the operator's call.

## The lesson worth keeping

Three of the six defects above were introduced or justified by the fix pass itself, and two of
those were caused by my own instructions. A fix pass is not self-verifying, and neither is a
green suite. What caught them was a different model, told what was claimed and asked to prove
it — and in every case the proof was behavioural: a probe, a revert, a fuzz, a reproduction.


---

# Part 5 - The shim-leak sweep (2026-07-25)

Three independent Fable agents flagged the same idiom in the test suite, so I verified it
myself with a `New-Module` probe rather than trusting the reports:

```
baseline                            : REAL
after defining shim                 : SHIM
after Remove-Item function:script:X : SHIM   <-- silently did nothing
after Remove-Item function:X        : (CommandNotFound - removed the REAL function)
```

`Remove-Item function:script:X` is **inert**: the function provider has no scope qualifier in
its paths, so the path names a non-existent item and `-EA SilentlyContinue` swallows the error.
The naive correction is worse - the unqualified form destroys the module's genuine function.
The only correct teardown is snapshot-and-restore: capture the real `ScriptBlock` first, then
`Set-Item function:script:X` it back (`Set-Item` **does** honour the qualifier), and clear a
name that had no function behind it with the unqualified `Remove-Item`.

**Converted:** 22 files, 52 sites (51 mechanical, `RemoteAdmin.Tests.ps1:256` by hand - its
shim block and teardown live in two separate `& $m { }` invocations). Plus one site the sweep
was told to leave alone that turned out to be a genuine leak: `AdTo.WriteGuards.Tests.ps1` F3
had no `Restore-AdToFns` after its block, so a `New-AdToEntry` stub that *throws* escaped the
`It`. It was green only because the next Describe re-shimmed the same three names - green by
accident of file order.

**Tests whose result changed: zero.** Per-test comparison across all 2316 tests: no new, no
missing, no flips. **There was no false green hiding behind the leak.** That is a real finding,
not a null result - it says the leak never changed an outcome, because in every file the later
tests either re-shim the same names before use or never touch the leaked seam.

To rule out the opposite conclusion - that the *fix* is also a no-op - the module function
table was probed after running a file, before vs after:

| File | Before conversion | After |
|---|---|---|
| `Wpt.Guards` | leaked `Invoke-Command`, `Test-Path` stubs | none |
| `Sysadmin` | leaked `Test-SysadminReachable` **stub** (115 chars) + 3 cmdlet shims | only the **real** `Test-SysadminReachable` (721 chars) |

So the leak was real, is now closed, and closing it broke nothing. No `modules/`, `server/` or
`web/` file was touched by the sweep.
