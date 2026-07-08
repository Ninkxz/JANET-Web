# JANET Web

A pure-PowerShell, zero-outside-dependency, operator-launched web app for endpoint
administration and vulnerability remediation. It is the reference implementation
of the JANET suite: 18 tools covering patching, ACAS/Tenable remediation, package
push, Windows upgrade, hardening, restart scheduling, remote messaging, AD search,
DHCP, and read-only reporting (dashboard, KEV, C2C readiness, patch history,
sysadmin sweeps).

JANET Web binds a `System.Net.HttpListener` to `127.0.0.1` only, serves a static
vanilla-JS SPA, and runs each tool's logic through a background runspace that
streams progress back to the browser. No third-party software, no install step,
no external network calls - suitable for a locked-down / air-gapped AFNET
workstation.

## Launch it

Double-click **`Launch JANET Web.cmd`**. It:

1. Best-effort strips the "Mark of the Web" off every file in the folder
   (`Unblock-File`), so a copied/extracted deployment doesn't trip a security
   prompt per script or load under Constrained Language Mode.
2. Forces the classic blue console (`conhost.exe`) instead of Windows Terminal,
   because the server-side "Set Credentials" smartcard picker
   (`Get-Credential`) does not reliably surface under Windows Terminal's ConPTY
   host.
3. Runs `JanetWeb.Internal.ps1`, which mints a per-launch session token, starts
   the server, and opens your browser to the tokenized URL.

`Ctrl+C` in that console window stops the server. Running `JanetWeb.Internal.ps1`
directly (double-click, IDE terminal, PowerShell 7) is self-healing - it detects
it's not in conhost and relaunches itself there.

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
the input-hardening (traversal, CSV-injection, upload sanitization) checks:

```powershell
Invoke-Pester -Path .\tests
```

## Layout

```
JANET Web\
  modules\        One engine .psm1 per tool (18) - the actual remediation/report logic
  server\         HTTP host (JanetWeb.Server.ps1), auth/session gate (JanetWeb.Auth.ps1),
                   logging bridge (JanetWeb.Logging.ps1), tool-registry.json
  web\            The static SPA (index.html, js\components, js\views) - no build step
  JanetLocal\     Seed catalogs (KEV, C2C baseline, SLA baseline, IAVM map, BIOS
                   firmware baseline) and runtime state (campaigns, sessions)
  tests\          Pester test suite
  docs\           Current review notes + per-tool UI specs (ui-specs\)
  Packages\       Local staging for patch content (PSADT / MSI / MSU / CAB / EXE)
  JanetWeb.Internal.ps1     Session/token bootstrap + server start (do not run directly)
  Launch JANET Web.cmd      The actual entry point - double-click this
```

Tool registry (id, name, category, icon, summary) is `server\tool-registry.json`.
