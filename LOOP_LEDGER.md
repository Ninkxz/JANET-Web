# JANET Web — maintenance loop ledger

Running list of findings from unattended audit/fix sessions. Severity: P1 (acts
wrongly / unsafe / suite-blocking), P2 (wrong result in a reachable case), P3
(cosmetic, dead code, hygiene).

Rotation for AUDIT units — advance one step per audit, oldest first:
`acas` · `c2c` · `certdeploy` · `dhcp` · `history` · `patchlib` · **`pkginstall`
· `remoteadmin` · `upr`** *(covered 2026-08-02)* · `reports` · `restart` ·
`secureboot` · `sysadmin` · `winrmbridge` · `winupgrade` · `wpt` ·
`server/routing/token-gate`

Next audit unit starts at: **`reports`**.

---

## Session 2026-08-02 (18:08–18:58)

### FIXED

**P1 — full Pester suite red at session start.** `commit b5f67f6fc`
`tests\History.CoverageReconcile.Tests.ps1:295` — the locked-CSV test built its
path from `(Get-Date).ToString('yyyy-MM')`, but `New-CovAuditTree` files each
touch under *its own* month. `$script:LiveTouch` is `DaysAgo = 3`, so on the
1st–3rd of any month the fixture writes `<last month>_detail.csv` and the test
opened a path that does not exist — `File::Open` threw before a single
assertion ran. Latent since it was written; fired today (2026-08-02).
Second half: `lookbackMonths = 1` scans the current month only
(`Get-HistMonthTokens`, `modules\JanetWeb.history.psm1:258`), so even with the
path corrected the reader would never have opened the locked file and the
read-error assertion would have failed for the opposite reason. Test-only — the
product reads months correctly.

**P2 — `healer-wu-reset` left a Disabled service disabled.** `commit d6e8da702`
`modules\JanetWeb.wpt.psm1` — the reset stops wuauserv/bits/cryptsvc, clears
SoftwareDistribution/catroot2, then `Start-Service`, which THROWS on a Disabled
service. Disabled is exactly the state a "Windows Update is broken" host is
often in and one of the reasons an operator reaches for this healer. Restores
StartType before starting and reports the re-enable as its own step.
wpt 6.10.6 → 6.10.7; `Log4jJarVersion.Tests.ps1`'s exact wpt pin demoted to a
floor (that file guards the jar sweep, not wpt's version).

**P3 — upr uninstall wrong-box guard failed OPEN on an empty name.** `commit 25b8c7a3f`
`modules\JanetWeb.upr.psm1:913` — the DNS-mismatch check ran only
`if ($actualName -and ...)`, so a remote whose ComputerName deserialized blank
skipped the check and the PERMANENT uninstall proceeded on an unverified box —
the case where we know least about the machine. `remoteadmin.psm1:329` already
fails closed on an unusable probe. Now matches.

**P3 — upr booked FAIL on hosts that ARE remediated.** `commit 25b8c7a3f`
`modules\JanetWeb.upr.psm1:1209/1217/1224` — only 0/3010 counted as success, so
msiexec 1641 (removed, reboot initiated) and 1605 (ERROR_UNKNOWN_PRODUCT — not
installed, i.e. the state an uninstall is *trying* to reach) wrote a
`VulnPatched/Failure` audit row for a clean host. Two catalog profiles resolving
to the same MSI hit this every run. pkginstall already treats 0/1641/3010 as
success (`:764`). Safe to accept because the registry re-verify is the real
arbiter and still fails closed. 1605 accepted on the msiexec path only.

**P3 — `[int]::TryParse` zeroing in two modules.** `commit 25b8c7a3f`
`upr.psm1:307`, `remoteadmin.psm1:478,481` — TryParse zeroes its `[ref]` on
failure and the result was adopted unconditionally, so a non-numeric value
became 0 and was then clamped: `timeoutSeconds='5m'` silently became 15 s and
abandoned every host whose block ran longer, while the remote blocks kept
executing. `pkginstall.psm1:1008` already guards this.

**P2 — a normal M365 removal outran the WinRM timeout and booked itself FAIL.** `commit 071b63156`
`modules\JanetWeb.upr.psm1:782` — the shared worker opened every session with a
flat `OperationTimeout = 300000` for BOTH phases. The scan can afford that (it
still has the fan-out watchdog); the uninstall phase cannot — the watchdog is
deliberately disabled there "for uninstall runs that legitimately run long"
(`:1335`), so the session cap was the only bound and nobody sized it for the
work. An M365 `setup.exe /configure` runs 8–15 min inside one blocking
`Invoke-Command` (`:936`): at 300 s WSMan killed the client, the row booked
`FAIL <WSMan timeout>`, a `VulnPatched/Failure` audit row was written, the
verify never ran, and the broken session failed every remaining candidate on
that host — while setup.exe was still successfully removing Office. Sized to
the phase: 30 min uninstall (pkginstall's default for the same blocking-deploy
problem, `:1024`), 5 min scan. upr 1.2.11 → 1.2.12.

**P2 — upr's permanent-removal actions had no server-side confirm word.**
*(was OPERATOR DECISION; operator approved 2026-08-03)*
`report-uninstall` and `manual-uninstall` are the suite's only permanent-removal
actions, and the barrier in front of them was a browser dialog. The view *did*
make the operator type `UNINSTALL` (`upr.view.js` `confirmWord`), but it never
POSTED the word and the module never read `$Params['confirm']` — so a stale tab,
a non-UI client, or a replayed POST inside an already-armed admin session
uninstalled fleet-wide with no typed barrier at all. remoteadmin has enforced a
typed `RUN` server-side since `:446`, pkginstall a typed `DEPLOY` at `:881`.
Fixed: `Test-UprLiveUninstallArmed` — one helper called from BOTH dispatcher
paths (two copies is how the report and manual paths drift), `-cne` so
`uninstall` is refused, and LIVE-only so a dry run is not gated (gating a dry run
trains the operator to type the word by reflex, which is how a typed barrier
stops being one). The view now posts the word it already collected.
Proven through the real dispatcher, not just the helper: a live `manual-uninstall`
with no `confirm` returns `rejected=$true`, zero rows, and an error log; the same
call with the word proceeds past the gate. upr 1.2.12 → 1.2.13.
*Note: `Upr.LiveSelectionRefuse.Tests.ps1` needed `confirm='UNINSTALL'` added to
two fixtures — arming now precedes the selection gate, so an unarmed fixture
stopped one gate early and never reached the one it was testing.*

---

## Session 2026-08-03 (continuation)

### FIXED

**P1 — scan-compare scored an UNSCANNED host as REMEDIATED, and that write stamps
`Patched`.** `modules\JanetWeb.reports.psm1:1642`
`Compare-AcasScans` defined REMEDIATED as "this baseline key is not in the
comparison", with the only demotion being a cross-domain short-name collision.
Nothing checked whether the **host itself** appeared in the comparison scan.
A box powered off during the after-patch window — or dropped by a scoped export —
had **every** baseline finding scored REMEDIATED, and unlike the other consumers
this path MUTATES: `acas-apply-remediated` (`:5975-5984`) then stamps
`Status='Patched'` / `PatchedBy='Scan Comparison'`. The fleet reads clean on
evidence never collected.
**Textbook sweep failure:** `campaign-verify:5621` already guards exactly this
with a NOT-SCANNED bucket, its comment reading *"loop21 P1 … would else
FALSE-CLOSE"*. The guard was written once and never swept to the sibling that
writes. Same rule, same helper, same conservative direction now. NOT SCANNED is
its own Delta, so the apply filter (`Delta -eq 'REMEDIATED'`) excludes it with no
change needed there; it is counted, surfaced in a warn log, and filterable
(AMBIGUOUS was never filterable either — added while there). reports 2.15.2 →
2.16.0. New behavioural test `Reports.CompareNotScanned.Tests.ps1`.
*Inherited trade-off, same as the precedent: a host scanned and now 100% clean
also has no comparison rows, so it lands in NOT SCANNED. That is the safe error —
it asks for a re-scan instead of closing a finding blind.*

**P3 — a cancelled or unverified host was painted with the success colour.**
`web\js\views\pkginstall.view.js:58`, `web\js\views\remoteadmin.view.js:16,200`
pkginstall mapped `Skipped` to `row-ok` (green) though the module emits it for a
never-dispatched host and for an MSI cancelled in flight whose outcome its own
comment calls *"genuinely UNKNOWN"*. remoteadmin had no `skipped` case at all, so
the wrong-box abort — the row that most needs to stand out — was the blandest in
the grid. New class-scoped `ViewRowClassHonesty.Tests.ps1` sweeps every view for
the shape. secureboot is a **declared exception** (its `Skipped` = already-enabled
/ already-pending, the desired state) and is pinned so nobody "completes" the
sweep by breaking it.

**P3 — a lost exit code booked a removed product as FAIL.**
`modules\JanetWeb.upr.psm1:1057`
`Start-Process -Wait -PassThru` can return `ExitCode=$null` inside a remote
PSSession (handle reaped early); `$null -eq 0` is false, so a genuinely removed
product came back `FAIL (MSI exit )` and skipped the registry verify — the only
step that proves removal. Now retried once, then reported UNKNOWN and routed
**into** the fail-closed verify, which arbitrates (still present ⇒ FAIL,
unreadable ⇒ FAIL), so it cannot manufacture a clean. upr 1.2.13 → 1.2.14.
*Deliberately NOT converted to pkginstall's `ProcessStartInfo` pattern: .NET
Framework's `ProcessStartInfo` has no `ArgumentList`, so it needs a hand-quoted
argument STRING — and these args come from a registry UninstallString a low-priv
user can plant. Discrete tokens are the whole LPE defence here; a quoting bug
would undo it.*

### Checked and clean (do not re-investigate)

- 37 test files lack a UTF-8 BOM, but every one is pure ASCII, so the missing BOM
  cannot mis-decode under PS 5.1. All shipping code in `modules\` and `server\`
  has its BOM.
- `reports` correctness audit: SLA day-math and DUE-SOON/OVERDUE boundaries,
  ledger carry/prune, divide-by-zero guards on every percentage, POA&M column
  alignment (26/26), IAVM multi-bulletin split, ping tri-state, burndown
  ordering, `[Int64]` on lastlogontimestamp, TryParse throughout (no
  culture-bare `::Parse`).
- `reports` wiring audit: all 41 manifest actions have dispatcher branches, all
  41 are invoked by the view, every grid column binds to a property the module
  emits. No unreachable branches, no blank-column bindings.

---

### OPEN — carried to a later session

**P2 — `Read-ReportsAuditTouchIndex` swallows every read failure.**
`modules\JanetWeb.reports.psm1:1793-1826` — `catch { $data = @() }` on
Import-Csv plus `-EA SilentlyContinue` and bare `catch {}` on all three directory
walks, so `scan-closure-proof` renders confident causation numbers over audit
files it never read. One denied operator folder yields zero touches for those
hosts: a host JANET *did* patch is reported "closed by something else", and a
still-open finding on a touched host drops off the next-day worklist. This is the
same "denied path renders as no activity" defect v2.15.2 fixed in squadron-rollup
with an error bag (`:6964-6972`) — this sibling reader was left on the old
pattern. *Another instance of the sweep failure; worth doing next.*

**P2 — import dedupe keys on the RAW hostname while every consumer normalizes.**
`modules\JanetWeb.reports.psm1:4582-4587` — the import dedupe uses
`Hostname|PluginID` raw, but ledger/compare/apply/CORA all fold the host through
`Get-ReportsAuditHostKey`. One physical box carried as both `WEB01` and
`web01.dom` keeps two live rows per plugin, inflating open counts, SLA aging and
burndown totals while `UniqueHosts` (normalized) stays right — so VPH is skewed
in both directions at once.

**P3 — `Categorize-Finding` matches unanchored substrings.**
`modules\JanetWeb.reports.psm1:694,696` — `word` matches "password", `edge`
matches "knowledge", bare `access` matches "restrict access…". A blank-admin-
password finding buckets as `Office` and the Remediation Router then offers to
fix it with an Office update. Feeds Router, Planner, Third-Party Catalog,
campaigns and the command brief identically.

**P2 — "All weeks" weekly CSV export is unreachable from the UI.**
`reports.view.js:1731`, `psm1:4745-4791` — the view never sends `OutputPath` (no
field exists), so the AllWeeks branch ships each CSV only inside `rows[].Csv`
while the ArtifactBar reads only `summary.csv`. Operator ticks "All weeks",
clicks Export, gets zero files and a log line telling them to supply an
OutputPath the UI cannot supply.

**P3 — streamed rows nobody renders.** `campaign-verify` streams up to 800
per-finding verdict rows (STILL-OPEN / MANUAL-ATTESTED / NOT-SCANNED /
AMBIGUOUS) and `export-poam` streams 500 preview rows, both to subscriptions with
no `row` handler and no grid — the actionable part of a verify is computed,
shipped, and dropped. Also: `sla-aging` builds `summary.perHost` that nothing
reads, and three actions declare a `colorblind` param the view never sends.

**P3 — IAVM add wipes operator input on a rejected CVE.** `psm1:4635-4642` /
`view:625-629` — invalid CVE returns `invalid=1` with no `saveError`; the view
checks only `saveError`, so it clears the typed CVE/IAVA/title and banners
"0 mapping(s)" as if it worked.

**P3 — pre-verification state changes happen before the wrong-box guard.**
`modules\JanetWeb.pkginstall.psm1:308-372, :376-552` — the DCOM WinRM bootstrap
(service → Auto, started, `winrm quickconfig -force`) and the full C$ payload
copy both run BEFORE the wrong-box guard, which only gates the execute (`:589`,
`:732`). Stale DNS pointing a name at the wrong machine means JANET permanently
enables/reconfigures WinRM on a box the operator never intended. The install
itself is correctly aborted and the payload is cleaned in `finally`; the WinRM
enablement is never rolled back.

**P3 — `Start-Process -Wait -PassThru` inside a remote PSSession.**
`modules\JanetWeb.upr.psm1:998-1002, :1111, :1175` — can return
`ExitCode = $null` when the handle is reaped early, which upr's own sibling
documents and engineers around (`pkginstall.psm1:621-624` uses raw
`ProcessStartInfo`). `$null -eq 0` is false → "FAIL (MSI exit )" with an empty
exit tag on a genuinely removed product. Fail-closed direction, but a known
false-FAIL source.

**P3 — IPv4-literal targets skip wrong-box verification entirely.**
`remoteadmin.psm1:319`, `pkginstall.psm1:255`, `upr.psm1:910` — all three treat
"the box answering at that IP IS the box". A reused DHCP lease is precisely the
operator-mistake class this suite guards against elsewhere. Shared design
decision across three tools; changing it is a design call, not a bug fix.

**P3 — UI misrepresents non-success rows.** `web\js\views\pkginstall.view.js:58`
paints `Skipped` with `row-ok` (green), including operator-cancelled hosts and
in-flight MSI cancels whose outcome is genuinely UNKNOWN
(`pkginstall.psm1:1302,1314`). `web\js\views\remoteadmin.view.js:16-23,:200`
handles no `Skipped` case at all, so the wrong-box DNS-mismatch abort — the row
that most needs to stand out — renders as the blandest in the grid.

**P3 — dead code in upr.** `:63` manifest declares a `search` input and `:1920`
reads `$Params['search']`, but `upr.view.js:405-424` filters client-side and
never posts it. `Get-UprVerifyResult` (`:145-152`) is never called at runtime
and not exported — the uninstall worker re-implements it inline (`:1269-1281`),
so two copies must be kept in lockstep by hand.

**P3 — `open-cshare` reports "Opened" almost unconditionally.**
`remoteadmin.psm1:396-412` — `Start-Process explorer.exe <UNC>` returns without
throwing even for an unreachable host, so the `catch` → 'Failed' branch is
effectively unreachable.

---

### Verified clean (do not re-report)

`pkginstall` core: the 1638 mixed-bundle hoist, msiexec exit map, copy-vs-execute
SHA gate, watchdog/cancel/leak-sweep accounting, `Select-Object -First 1` reap,
per-runspace PSDrive collisions. Server admin gate is fail-closed (destructive
unless `destructive=$false`, `JanetWeb.Server.ps1:1591-1600`); constant-time
token compare (`:1064-1071`); no action in these three manifests is wrongly
marked non-destructive. Targets are always passed as parameters, never
interpolated into a command string. msiList traversal rejected; staging dirs
GUID-named, exclusively created, DACL'd SYSTEM+Admins, SHA256-gated. UPR never
shells raw UninstallStrings. Credentials travel only as PSCredential. upr's
uninstall verify reads all three hives incl. WOW6432Node and fails closed. No
PS7 syntax in any of the three modules. All manifest actions have dispatcher
branches; no orphan branches; every param the views send is read.
