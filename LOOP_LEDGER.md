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

### OPEN — carried to a later session

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
