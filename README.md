# JANET Web

A pure-PowerShell, zero-outside-dependency, operator-launched web app for endpoint
administration and vulnerability remediation. It is the reference implementation
of the JANET suite: **21 tools** covering patching, ACAS/Tenable and Comply-to-Connect
remediation, AD account-management compliance, package push, Windows upgrade,
hardening (Secure Boot, BIOS firmware, PKI trust roots), restart scheduling,
remote messaging and hands-on-keyboard admin, AD search, DHCP, and reporting
(KEV cross-check, plus read-only patch history and sysadmin sweeps).

JANET Web binds a `System.Net.HttpListener` to `127.0.0.1` only, serves a static
vanilla-JS SPA, and runs each tool's logic through a background runspace that
streams progress back to the browser. No third-party software, no install step,
and the JANET host itself makes no internet calls - suitable for a locked-down /
air-gapped AFNET workstation. (The exceptions are opt-in: the Workstation
Patching "Vendor MSI" and "Internet - Google Update" Chrome profiles have the
*target* download from the vendor, and the KEV lookup links open public sites in
your browser when clicked.)

## Download and use

Get the latest **`JANET-Web-<date>.zip`** from this repository's **Releases**
page. That zip is the ready-to-run build (no tests, dev docs or certificates).

1. Extract it anywhere.
2. Double-click **`Launch JANET Web.cmd`**. Your browser opens at a `127.0.0.1`
   address; closing the console window stops JANET Web.
3. Read-only tools work straight away. For anything that changes a machine,
   click **Set Credentials**, then **Start Admin Session**.
4. Add the site files some features need, on your own machine: the DoD / LTMA
   certificate bundles into `Packages\DoD-Certs\` and `Packages\PKI-Fix\Certs\`,
   patched Log4j jars (a `log4j-api` and a `log4j-core` at 2.26.1 or later) into
   `Packages\Log4j\NewFiles\`, and `mpam-fe.exe` into
   `Packages\DefenderDefinitions\`. Each of those features stays off until its
   files are there.

## Requirements

- **Windows PowerShell 5.1** (the bootstrap script is `#Requires -Version 5.1`).
  Not PowerShell 7: if it is started under 7 or Windows Terminal it relaunches
  itself in the classic `conhost` console (see below).
- A modern browser on the same machine (it opens to a `127.0.0.1` URL).
- For remote actions: WinRM to the targets (TCP 5985, or 5986 for HTTPS) and SMB
  (TCP 445). Reachability checks are TCP connects to those ports, not ICMP,
  because AFNET filters ping. The one exception is the Reports tool's Resolve
  Target IPs and ACAS Ping Hosts actions: they try an ICMP echo first to measure
  latency and fall back to the same TCP probe, so a dropped ping never marks a
  host offline on its own.
- An account with admin rights on the targets for anything destructive.
- For the test suite only: **Pester 3.4.0** (not Pester 5).

## Tools

All 21, grouped by the `category` field in `server\tool-registry.json` - that file
is the single source of truth; this list mirrors it exactly.

| Category | Tools |
| --- | --- |
| Remediation (8) | Workstation Patching (`wpt`), ACAS Nemesis (`acas`), C2C Nemesis (`c2c`), AD Nemesis (`adto`), Package Installer (`pkginstall`), Windows Upgrade (`winupgrade`), Unsupported Remediator (`upr`), Patch Content (`patchlib`) |
| Hardening (3) | Secure Boot Enabler (`secureboot`), BIOS Firmware (`biosfirmware`), Cert Deploy (`certdeploy`) |
| Lifecycle (1) | Restart Scheduler (`restart`) |
| Operations (3) | Remote Message (`message`), WinRM Bridge (`winrmbridge`), Remote Admin (`remoteadmin`) |
| Directory (1) | AD Search (`adsearch`) |
| Network (1) | DHCP Scope Options (`dhcp`, beta) |
| Reporting (4) | Reports (`reports`), KEV Cross-Check (`kev`), Patch History (`history`), Sysadmin Sweeps (`sysadmin`) |

## Launch it

Double-click **`Launch JANET Web.cmd`**. It:

1. Best-effort strips the "Mark of the Web" off every file in the folder
   (`Unblock-File`), so a copied/extracted deployment doesn't trip a security
   prompt per script or load under Constrained Language Mode.
2. Forces the classic blue console (`conhost.exe`) instead of Windows Terminal,
   because the server-side "Set Credentials" smartcard picker
   (`Get-Credential`) does not reliably surface under Windows Terminal's ConPTY
   host.
3. Runs `DO NOT RUN - JanetWeb.Internal.ps1`, which mints a per-launch session
   token, starts the server, and opens your browser to the tokenized URL.

`Ctrl+C` in that console window stops the server. The internal script is prefixed
`DO NOT RUN - ` because **`Launch JANET Web.cmd` is the only supported entry point**.
If it is run directly anyway, it tries to self-heal: under Windows Terminal,
under PowerShell 7, or when started straight from Explorer (double-click /
"Run with PowerShell") it relaunches itself in conhost. It does not detect other
hosts, such as an IDE terminal running Windows PowerShell 5.1 - there it runs in
place, and the "Set Credentials" picker may not appear.

Everything runs as YOU, on localhost, the same security model as the desktop
WinForms tools - no elevation, no service account.

## Admin session model

Every *destructive* action (patch, reboot, uninstall, registry apply, etc.) is
gated server-side, not just in the browser: **Set Credentials** (stores a
`PSCredential` for the session) plus **Start Admin Session** (an explicit
responsibility acknowledgement) must both be live, or the server rejects the
action with a 403. Read-only actions (scans, queries, AD search, reporting) never
require a session.

Credentials live in server memory for the life of the session only - they are
never written to disk.

## Safety rules for destructive actions

Actions that change a remote machine are built to these rules, and new ones must
be too - copy an existing implementation (`JanetWeb.restart.psm1`,
`JanetWeb.upr.psm1`) rather than starting fresh:

- **Wrong-box guard** - the remote's own `$env:COMPUTERNAME` is compared to the
  name that was dialed; a mismatch (stale DNS, reused IP) aborts before anything
  runs.
- **Self-guard** - the machine running JANET Web is dropped from the target list,
  so an operator can't reboot or uninstall the dispatcher out from under itself.
- **Typed confirm word** in the browser for the dangerous ones, plus
  `destructive=$true` in the tool manifest so the server gate applies.
- **Fail closed** - where a change can be checked in the same action, state is
  re-read and success is reported only when it is confirmed (UPR re-reads the
  registry after an uninstall; an unreadable result is a failure, not "removed").
  An unreadable value is never an implied all-clear: KEV Cross-Check refuses to
  run on an empty catalog rather than report "no overlap". Restart is the
  exception by design - it reports what `shutdown.exe` returned, and the reboot
  itself is confirmed later with **Verify Reboots** or **Verify (WinRM Boot Time)**.

Known gap: WinRM Bridge Enable/Revert has the self-guard, the confirm word and
`destructive=$true`, but no wrong-box guard, and it reports BRIDGING/REVERTING as
soon as its scheduled task starts - run its **Check** action to confirm.

## Logs

Each tool adds rows to a monthly detail CSV per operator
(`<Tool>\<user folder>\<YYYY-MM>_detail.csv`, every row tagged with its session
id) and writes a `.log` transcript per session; the server also keeps a fleet
usage rollup (`<YYYY-MM>_usage.csv` at the log root). The primary target is the
production share (`\\dm-tn-01\sh-usafe-automation$\JANET\Logs`). If that can't be
reached or written, logging falls back to a local spool in the `JanetLocal\`
folder *next to* the `JANET Web` folder (not the one inside it) - the same layout
as the desktop tools - and spooled rows are replayed to the share on a later
launch. Use the **Patch History** tool to browse the audit trail (per-host
timeline, recent activity, per-operator summary, staleness) without touching the
raw CSVs.

## Tests

A Pester suite lives under `tests\` and covers the destructive-action gates, the
remediation/campaign/POA&M engines, the DNS-mismatch and self-reboot guards, and
the input-hardening (traversal, CSV-injection, upload sanitization) checks.
Remote calls (`Invoke-Command`, PSSessions) are shimmed, so no test reaches
another machine. Some tests do open local connections: the `Server.*` tests start
a live server on `127.0.0.1`, and some guard tests run real TCP reachability
probes against this box.

**Pester 3.4.0**, not Pester 5 - the v3 syntax (`Should Be`, `Invoke-Pester -Script`)
is what the suite and the packaging gate both use. Run it with the runner:

```powershell
.\Run-Tests.ps1                 # everything (about ten minutes)
.\Run-Tests.ps1 -Contract       # the Platform.* contract files only (fast pre-flight)
.\Run-Tests.ps1 -Area wpt       # every test file with 'wpt' in its name
.\Run-Tests.ps1 -Detailed       # list each failed test, not just the totals
```

`tests\` is **dev-side only**: it is deliberately not part of the take-to-work
copy (see below). `Sync-TakeToWork.ps1` still runs it before it will write a zip.

## Layout

```
JANET Web\
  modules\        24 engine .psm1 - one per tool (21) plus three shared engines
                   (javafix, specfix, troubleshoot) reused by several tools
  server\         HTTP host with the /api token check and admin-session gate (JanetWeb.Server.ps1),
                   Set Credentials smartcard prompt (JanetWeb.Auth.ps1),
                   logging bridge (JanetWeb.Logging.ps1), tool-registry.json
  web\            The static SPA (index.html, js\components, js\views) - no build step
  JanetLocal\     Seed catalogs (KEV, C2C baseline, AD TO baseline, SLA baseline,
                   IAVM map, BIOS firmware) and runtime state (campaigns, SLA ledger)
  tests\          Pester test suite            - DEV-SIDE ONLY, not shipped
  docs\           Review notes + per-tool UI specs (ui-specs\) - DEV-SIDE ONLY, not shipped
  Packages\       Local staging for patch content (PSADT / MSI / MSU / CAB / EXE)
                   + the DoD-Certs\ and PKI-Fix\Certs\ trust-bundle folders
  Run-Tests.ps1                        Pester runner (whole suite, -Contract, -Area)
  LOOP_LEDGER.md                       Running audit/fix ledger and stable checkpoints
  Sync-TakeToWork.ps1                  Builds the gated take-to-work zip (see below)
  DO NOT RUN - JanetWeb.Internal.ps1   Session/token bootstrap + server start (do NOT run directly)
  Launch JANET Web.cmd                 The actual entry point - double-click this
```

Tool registry (id, name, category, icon, summary) is `server\tool-registry.json`.

Runtime state under `JanetLocal\` (campaigns, the SLA ledger, local log spool) is
git-ignored; only the seed catalogs listed above are tracked.

## Adding a tool

Each tool is three pieces that must agree on its id:

1. `modules\JanetWeb.<id>.psm1`, exporting `Get-JanetToolManifest` (id, name,
   version, actions and their inputs/columns) and
   `Invoke-JanetToolAction -ActionId -Params -Credential -Emit` - the only two
   functions the server calls (some modules export extra helpers for the tests).
2. An entry in `server\tool-registry.json`.
3. `web\js\views\<id>.view.js` (see `docs\VIEW-CONTRACT.md`).

The `Platform.*` contract tests check that every registered tool has all three.
In the sidebar, `wpt` and then `acas` stay first.

## Conventions

- **PowerShell 5.1 only** - no `&&`, ternary, `??` or `?.`.
- `.ps1` / `.psm1` files are saved as **UTF-8 with BOM** with an ASCII-only body.
  The engine modules and server scripts follow this; a few older scripts and
  tests predate the rule and don't yet.
- Any change to a module bumps the `version` in its manifest. The newest bump's
  test pins that version exactly; older tests that pinned it drop to a floor
  (`-ge`). (Remote Message and Sysadmin Sweeps have no version pin yet.)
- Commits are conventional (`fix(web wpt): ...`) with a body explaining why.
- Deliberate shortcuts carry a `ponytail:` comment naming the limit and the
  upgrade path.
- CSV exports guard against Excel formula injection (a leading `= + - @`); keep
  that when touching any exporter.

## Take-to-work copy

`Sync-TakeToWork.ps1` stages a clean copy, gates it, and zips it to
`X:\Archive\JANETWEB_TakeToWork_<stamp>.zip`. What the zip actually contains:

```
Launch JANET Web.cmd, DO NOT RUN - JanetWeb.Internal.ps1, README.md
modules\  server\  web\                 whole trees
Packages\                               the full folder skeleton + non-certificate
                                        payloads (READMEs, PKI-Fix scripts)
JanetLocal\<top-level files>            every top-level file except sla-ledger.json
                                        and cert/key files: the seed catalogs plus
                                        any top-level runtime files present (e.g.
                                        manifest-cache.json). Subfolders (campaigns\)
                                        and sla-ledger.json stay here.
```

Not in the zip: `tests\`, `docs\`, and - since the 2026-07-17 policy - **any
certificate or key container, anywhere**. `Packages\DoD-Certs\` and
`Packages\PKI-Fix\Certs\` ship as empty folder skeletons (the sync withholds
every cert and fails the cut if one is staged anyway). The public DoD CA `.cer`
files under `Packages\DoD-Certs\` *are* tracked in this repository - the policy
keeps them out of the zip, not out of git. `Packages\DefenderDefinitions\`
is empty for a different reason: `mpam-fe.exe` is a ~150 MB blob that is not kept
in the repo at all.

**Both gaps are closed on-site: after unpacking, the operator drops the DoD/LTMA
cert bundles and `mpam-fe.exe` into those folders ON THE WORK MACHINE.** Until
then Cert Deploy / the C2C PKI fixer and the offline Defender rung fail closed on
the empty folder by design - that is expected, not a broken copy.

Three gates must pass or no zip is written: no certificate staged (and no
private-key container anywhere in the tree), every staged `.ps1`/`.psm1` parses,
and the Pester suite is green. Run `.\Sync-TakeToWork.ps1 -GateOnly` to exercise
all three without producing a zip.

> The sync never prunes `X:\Archive` - decide with the operator before removing
> anything there.

## Repository

The primary remote is the self-hosted Gitea (`origin`). This GitHub repository is
a **private** copy of it (remote name `github` in the local clone), carrying the
full history and the `stable-*` checkpoint tags.

JANET SECRET (`shh-JANET`) and JACK are hard forks of this code base: fixes made
here do not reach them on their own and have to be ported by hand.
