# JANET Web - UI Spec: Cert Deploy (tool id: `certdeploy`)

Net-new JANET Web tool (no desktop twin). A **proactive** DoD/LTMA trust-root
deployment tool: push the DoD trust bundle to ANY host list to get **ahead** of
PKI Trust Roots non-compliance. Independent of C2C failure status - even a host
that is not failing yet but carries the PKI tag should get the roots (it will go
non-compliant later). This is the operator's LTMA `certs.ps1` workflow, not a
failure remediator (that is C2C Nemesis).

## Layout (single frame, sysadmin/secureboot idiom)

A `display:flex` column: a `main` row (left rail + right results) over a shared
bottom **activity-log dock** (`j-logdock`). Credentials are **universal** (shell
header, top-right) - this view renders **no** per-tool credential control.

### Left rail (`flex:0 0 400px`)
- **TARGETS** card - a `TargetManager` (paste one host/line; comma/space/semicolon
  ok; `#` comment) with **Import TXT**.
- **Options** card:
  - **DoD/LTMA trust bundle folder** text input. Blank = the shipped
    `Packages\DoD-Certs` bundle (hint shown). A server-readable folder with
    `root\*.cer` -> Root, `Intermediate\*.cer` -> CA, `Untrusted\*.cer` ->
    Disallowed (loose `*.cer` -> Root).
  - **Import C2C export -> load all PKI-tagged hosts** (gold button + hidden file
    input, `.csv`). Uploads the Tanium "C2C Compliance Status" CSV, runs
    `import-pki-hosts`, and merges every PKI-tagged host into the target list.
  - **Attempt even if offline** checkbox + **Max concurrent** (1-32) + a status line.
- **Actions** card - two `RunBar`s:
  - **CHECK TRUST CERTS** (read-only; morph-to-cancel). Guards: >=1 host, valid
    hostnames. No admin session, no confirm.
  - **DEPLOY TRUST CERTS** (destructive; morph-to-cancel). Guards add
    `ctx.session.state.credSet` (admin session required). `onRun` opens an
    `ctx.arm({ confirmWord: 'DEPLOY' })` dialog restating that it **additively
    installs** the DoD roots and **never removes** anything, then dials.

### Right column (`flex:1`)
- **StatCards**: HOSTS / ALL PRESENT-INSTALLED / MISSING-FAILED / OFFLINE-ERRORS.
- **Head** card: Export CSV + Clear.
- **CERT DEPLOY RESULTS** card - a `ResultsGrid` (`keyMode hostCol:'Host'`)
  columns **Host / Ping / Status / Missing / Detail**, colour-coded by Status, over
  a `ProgressStatusStrip`.

## Actions (engine `JanetWeb.certdeploy.psm1`)

| id | destructive | what |
|----|-------------|------|
| `check` | `false` | Read the bundle admin-side once; per host open each LocalMachine store **ReadOnly** and report MISSING roots per store. Status `ALL PRESENT` / `MISSING N` / `OFFLINE` / `CHECK ERROR`. Detail = `Root x / CA y / Disallowed z missing` + example missing subjects. Never writes a store. |
| `deploy` | `true` | Confirm word **DEPLOY** (exact, case-sensitive) is the FIRST gate; read the bundle admin-side (abort if empty). Per host: reachability, wrong-box HARD abort, self-guard (dispatcher dropped), then ONE WinRM round-trip that **additively** installs Root/CA/Disallowed (adds only-missing by thumbprint, **never removes**). Status `ROOTS INSTALLED` / `ROOTS ALREADY PRESENT` / `FAILED` / `OFFLINE` / `SKIPPED`. Per-host watchdog + operator cancel. Emits a `VulnPatched` audit per host. |
| `import-pki-hosts` | `false` | Local parse only (no WinRM). Parse the Tanium C2C CSV and return EVERY host whose Compliance cell names **PKI Trust Roots** in ANY line - audit OR failed, compliant OR non-compliant. Summary `{ total, pkiTagged, hosts:[...] }`; one streamed row per PKI-tagged host. |

## Status -> colour (view)

`ALL PRESENT` / `ROOTS INSTALLED` / `ROOTS ALREADY PRESENT` -> ok (green row).
`MISSING N` / `FAILED` -> warn/bad. `OFFLINE` / `SKIPPED` -> warn.
`CHECK ERROR` / `Cancelled` -> bad. `Queued` -> info.

## Safety

- **Never removes** a certificate: `Add-CertDeployBundleToStores` only adds
  thumbprints not already present (copied verbatim from the C2C `fix-pki` helper).
- **Self-guard**: the JANET dispatcher host is dropped from every deploy run.
- **Wrong-box**: a DNS mismatch HARD-aborts a deploy host (SKIPPED) before any
  write; the read-only check soft-skips it as CHECK ERROR.
- **Admin gate**: `deploy` is `destructive=true`, so the server session-gates it
  exactly like every other destructive action; the confirm word DEPLOY is enforced
  server-side too.
- Reachability is **TCP-only** (5985 then 445) - AFNET drops ICMP.
