# J.A.N.E.T. TWO

A pure-PowerShell, **zero-outside-dependency**, web-local re-front of the whole JANET
sysadmin tool suite -- the successor to **JANET ONE**.

## Why JANET TWO exists

JANET ONE proved the architecture (a `System.Net.HttpListener` server + static
HTML/CSS/JS + one engine module per tool, no external software -- the key requirement
for locked-down / air-gapped accreditation). **But** it rendered every tool through a
single *generic, manifest-driven* SPA: one cookie-cutter form + grid per action. That
made every tool look and feel the same and **lost the real usability of the desktop
JANET tools** -- their bespoke tabbed screens, the way you run things, and especially the
live **activity-run** experience (activity log + colour-coded results grid + progress +
per-host rows).

**JANET TWO keeps the proven backend/plumbing but rebuilds the frontend so each tool
gets a FAITHFUL, bespoke per-tool view that mirrors its desktop WinForms tool** -- the
screens, tabs, run controls, and the live activity/results view -- tool by tool. No
generic renderer.

## Decisions (locked for this build)

- **Backend (engines):** RE-FORK each engine fresh from the desktop `Tools\*.ps1` source
  of truth (see `fork-source\`). We do *not* reuse JANET ONE's `modules\*.psm1` -- though
  `X:\J.A.N.E.T ONE\modules\` is a useful cross-check (it already fixed many bugs).
- **Frontend:** faithful **per-tool views** mirroring each desktop tool's UX. The shared
  building blocks (run/command bar, activity-log panel, results grid, target manager,
  credential/session bar, confirm/arming dialog, progress strip) are reused by every
  per-tool view -- desktop fidelity *without* a cookie-cutter generic renderer.
- **Plumbing:** REUSE JANET ONE's proven web-local plumbing -- the HttpListener server,
  per-launch loopback token security, the background-runspace streaming + polling model,
  the central-audit-CSV logging bridge, the credential/session gate, and the
  `-Emit` streaming event contract (`status` / `progress` / `row` / `log` / `audit` /
  `final`). Reference it in place at `X:\J.A.N.E.T ONE\` (server\, web\).
- **Stack rules:** Windows PowerShell 5.1 must parse everything; `.ps1`/`.psm1` are
  UTF-8 **with BOM** and **ASCII-only source**; zero third-party software.
- **Do NOT modify `X:\J.A.N.E.T`** (the desktop suite) -- it is reference only; we copied
  the tools out into `fork-source\`.

## Layout

```
J.A.N.E.T TWO\
  fork-source\            Copied-in JANET tools (the fork basis + UI reference)
    JANET.ps1             The desktop hub/launcher (suite-level UX reference)
    JANET_Config.json     Desktop tool registry
    Tools\                The 12 desktop WinForms tools (.ps1)
  docs\
    HANDOFF.md            >> The build guide (how to build JANET TWO). START HERE.
    REVIEW.md             What makes JANET and JANET ONE tick (review notes)
    ui-specs\             One faithful UI-rebuild spec per tool (<tool>.md)
  server\, web\, modules\   The built runtime: HttpListener server, static SPA, one engine module per tool
```

## The 18 tools

- **Remediation** — Workstation Patching, ACAS Nemesis, Package Installer,
  Windows Upgrade, Unsupported Remediator, Patch Content
- **Hardening** — Secure Boot Enabler, BIOS Firmware, STIG Checker
- **Lifecycle** — Restart Scheduler
- **Operations** — Remote Message
- **Directory** — AD Search
- **Network** — DHCP Scope Options
- **Reporting** — Reports, KEV Cross-Check, C2C Readiness, Patch History
- **Beta** — Beta Lab (staging area for experimental, read-only fixes)

(Source of truth: `server\tool-registry.json`.)

## Status

Built. All 18 tools have bespoke per-tool views over the pure-PowerShell backend
(`server\` HttpListener, `web\` static SPA, one `modules\` engine per tool).
`docs\HANDOFF.md`, `docs\REVIEW.md`, and the per-tool `docs\ui-specs\*.md` are the
review + UI-spec basis it was built from. Remaining: on-AFNET live validation.
