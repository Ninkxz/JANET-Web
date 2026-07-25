# JANET Web

A pure-PowerShell, zero-outside-dependency, operator-launched web app for endpoint
administration and vulnerability remediation. It is the reference implementation
of the JANET suite: **21 tools** covering patching, ACAS/Tenable and Comply-to-Connect
remediation, AD account-management compliance, package push, Windows upgrade,
hardening (Secure Boot, BIOS firmware, PKI trust roots), restart scheduling,
remote messaging and hands-on-keyboard admin, AD search, DHCP, and read-only
reporting (KEV, patch history, sysadmin sweeps).

JANET Web binds a `System.Net.HttpListener` to `127.0.0.1` only, serves a static
vanilla-JS SPA, and runs each tool's logic through a background runspace that
streams progress back to the browser. No third-party software, no install step,
no external network calls - suitable for a locked-down / air-gapped AFNET
workstation.

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
`DO NOT RUN - ` because **`Launch JANET Web.cmd` is the only supported entry point** -
but if it is run directly anyway (double-click, IDE terminal, PowerShell 7) it is
self-healing: it detects it's not in conhost and relaunches itself there.

Everything runs as YOU, on localhost, the same security model as the desktop
WinForms tools - no elevation, no service account.

## Admin session model

Every *destructive* action (patch, reboot, uninstall, registry apply, etc.) is
gated server-side, not just in the browser: **Set Credentials** (stores a
`PSCredential` for the session) plus **Start Admin Session** (an explicit
responsibility acknowledgement) must both be live, or the server rejects the
action with a 403. Read-only actions (scans, queries, AD search, reporting) never
require a session.

## Logs

Each tool writes a per-session detail CSV plus a fleet usage rollup. The primary
target is the production share
(`\\dm-tn-01\sh-usafe-automation$\JANET\Logs`); if that's unreachable, logging
falls back to a local spool under `JanetLocal\` (same layout as the desktop
tools). Use the **Patch History** tool to browse the audit trail (per-host
timeline, recent activity, per-operator summary, staleness) without touching the
raw CSVs.

## Tests

A Pester suite lives under `tests\` and covers the destructive-action gates, the
remediation/campaign/POA&M engines, the DNS-mismatch and self-reboot guards, and
the input-hardening (traversal, CSV-injection, upload sanitization) checks.
**Pester 3.4.0**, not Pester 5 - the v3 syntax below is what the suite and the
packaging gate both use:

```powershell
Invoke-Pester -Path .\tests
```

`tests\` is **dev-side only**: it is deliberately not part of the take-to-work
copy (see below). `Sync-TakeToWork.ps1` still runs it before it will write a zip.

## Layout

```
JANET Web\
  modules\        24 engine .psm1 - one per tool (21) plus three shared engines
                   (javafix, specfix, troubleshoot) reused by several tools
  server\         HTTP host (JanetWeb.Server.ps1), auth/session gate (JanetWeb.Auth.ps1),
                   logging bridge (JanetWeb.Logging.ps1), tool-registry.json
  web\            The static SPA (index.html, js\components, js\views) - no build step
  JanetLocal\     Seed catalogs (KEV, C2C baseline, AD TO baseline, SLA baseline,
                   IAVM map, BIOS firmware) and runtime state (campaigns, SLA ledger)
  tests\          Pester test suite            - DEV-SIDE ONLY, not shipped
  docs\           Review notes + per-tool UI specs (ui-specs\) - DEV-SIDE ONLY, not shipped
  Packages\       Local staging for patch content (PSADT / MSI / MSU / CAB / EXE)
                   + the DoD-Certs\ and PKI-Fix\Certs\ trust-bundle folders
  Sync-TakeToWork.ps1                  Builds the gated take-to-work zip (see below)
  DO NOT RUN - JanetWeb.Internal.ps1   Session/token bootstrap + server start (do NOT run directly)
  Launch JANET Web.cmd                 The actual entry point - double-click this
```

Tool registry (id, name, category, icon, summary) is `server\tool-registry.json`.

## Take-to-work copy

`Sync-TakeToWork.ps1` stages a clean copy, gates it, and zips it to
`X:\Archive\JANETWEB_TakeToWork_<stamp>.zip`. What the zip actually contains:

```
Launch JANET Web.cmd, DO NOT RUN - JanetWeb.Internal.ps1, README.md
modules\  server\  web\                 whole trees
Packages\                               the full folder skeleton + non-certificate
                                        payloads (READMEs, PKI-Fix scripts)
JanetLocal\<top-level files>            reference catalogs only; runtime state
                                        (campaigns\, sla-ledger.json) stays here
```

Not in the zip: `tests\`, `docs\`, and - since the 2026-07-17 policy - **any
certificate or key container, anywhere**. `Packages\DoD-Certs\` and
`Packages\PKI-Fix\Certs\` ship as empty folder skeletons (the sync withholds
every cert and fails the cut if one is staged anyway). `Packages\DefenderDefinitions\`
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

> Archived cuts made **before 2026-07-17** predate the no-certificates policy and
> do still contain the trust bundle. They are left alone deliberately - decide
> with the operator before pruning anything in `X:\Archive`.
