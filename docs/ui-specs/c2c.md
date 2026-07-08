# JANET Web - UI Spec: c2c (C2C Nemesis)

> Renamed 2026-07-08: display name **C2C Readiness -> C2C Nemesis** (tool id `c2c`
> is unchanged - routes, registry keys, view registration and log/export names all
> stay `c2c` / "C2C Readiness Scan").

> Net-new JANET Web tool (no desktop twin). Read-only Comply-to-Connect quarantine
> predictor. This is a standard `stream-table` tool: paste targets, run one action,
> watch per-host verdict rows stream in and the full per-check report fill the
> activity log. Reuse the shared stream-table view (same as wpt / winupgrade /
> biosfirmware) - no bespoke UI.

## Summary

**C2C Nemesis** (tool id `c2c`, category **Reporting**, icon `E72E`) predicts
whether each host would be **QUARANTINED** under AFI/MPTO **Comply-to-Connect rule
3.B.2.B**. It fans out over WinRM, runs **one consolidated read-only probe per
host** (11 C2C checks in a single `Invoke-Command` round-trip), emits **one result
row per host** (`Host / Ping / Status / Detail`), and streams the **full 11-line
per-check report** to the activity log for colouring. It **changes nothing** and
**needs no admin session** (read-only, like the WPT ping / bulk-scan and the
Windows Upgrade Diagnose action).

## Action

- **`scan` - "C2C Readiness Scan"** (read-only, `destructive=false`), columns
  `Host, Ping, Status, Detail`.
- **Inputs:** `targets` (hostlist, required), `attemptOffline` (bool, default
  false), `threads` (int, default 16; clamped 1-32).

## The 11 checks

Each check runs inside the one probe (its own try/catch, so a single failure ->
that check = `ERROR`, never aborting the probe) and yields a status
`PASS / FAIL / EXT / ERROR` plus a short Detail. **9 are scored locally; 2 are
EXT** (external - reported, never scored).

| # | Pillar | Mechanism (read-only, on the target) | PASS when |
|---|--------|--------------------------------------|-----------|
| 1 | Monitoring | `Get-Service` the Tanium client service (`taniumService`, default "Tanium Client") | service Running (not found/stopped -> FAIL) |
| 2 | Firewall | `Get-NetFirewallProfile` (Domain/Private/Public); fallback `netsh advfirewall show allprofiles state` | all three profiles Enabled (else FAIL lists the disabled ones) |
| 3 | AntiMalware | `Get-MpComputerStatus` (Defender, NIPR); fallback `root\SecurityCenter2` AntiVirusProduct | RealTimeProtectionEnabled AND AntivirusSignatureAge <= `sigMaxAgeDays` (default 7); Detail carries RTP + sig age + sig version |
| 4 | Patches | `CCM_SoftwareUpdate` in `root\ccm\ClientSDK` (`InstallState != Installed` AND `ApplicabilityState != NotApplicable`) - the exact wpt query | 0 pending (else FAIL count). CCM absent -> ERROR "MECM/CCM not queryable" |
| 5 | Vuln | **EXT** - not endpoint-determinable | n/a - "Scored server-side (ARAD/ACAS) - remediate via ACAS / Reports / KEV / UPR" |
| 6 | Encryption | `Get-BitLockerVolume` for `$env:SystemDrive`; fallback `manage-bde -status` | ProtectionStatus On; Detail carries ProtectionStatus + VolumeStatus |
| 7 | AppWhitelist | AppLocker via `Get-AppLockerPolicy -Effective` (any RuleCollection EnforcementMode=Enabled); else WDAC via `Win32_DeviceGuard` (`CodeIntegrityPolicyEnforcementStatus >= 2`) | either enforcing (audit-only -> FAIL with a note; neither -> FAIL) |
| 8 | Agents | patch agent `Get-Service CcmExec` Running AND >=1 `securityAgentServices` Running | both true; Detail names both states |
| 9 | PkiRoots | compare `Cert:\LocalMachine\Root` thumbprints against `dodRootThumbprints` | every required thumbprint present (else FAIL lists how many/which). **Empty baseline -> EXT** "configure DoD root thumbprints in c2c-baseline.json" |
| 10 | COAMS | **EXT** - server-side ARAD/ePO asset tags, not endpoint-readable | n/a - "ARAD/ePO server-side tags (7) - not endpoint-readable" |
| 11 | Hostname | test `$env:COMPUTERNAME` against `hostnamePatterns` (default `^MSEKL`, `^MSEKW` = Lakenheath laptop/workstation) | matches any pattern (else FAIL "<name> does not match naming convention"); Detail notes the authoritative verdict is ARAD-side |

## Verdict (computed admin-side)

Count `FAIL` among the 9 scored checks (EXT pillars Vuln + COAMS are shown but
**never** count):

- **READY** - 0 FAIL and 0 ERROR.
- **QUARANTINE RISK** - >= 1 FAIL (Detail lists the failing pillars).
- **CHECK ERRORS** - 0 FAIL but >= 1 ERROR (a pillar could not be evaluated).
- **OFFLINE** - host unreachable (TCP 5985/445). With `attemptOffline` ticked the
  probe still tries a session; a connect/session failure surfaces as `ERROR`.

`Detail` is a short summary, e.g. `3 FAIL: Firewall, Encryption, PkiRoots | EXT:
Vuln, COAMS`. The activity log receives the full 11-line report, each line prefixed
`[PASS]` / `[FAIL]` / `[EXT]` / `[ERROR]` so the view colours it (PASS -> ok,
FAIL -> error, ERROR -> warn, EXT -> info).

## Config (baseline)

`JanetLocal\c2c-baseline.json` ships with JANET (`.gitignore`-negated like the KEV
catalog) so it travels in take-to-work. The engine loads the embedded defaults and
overlays the file if present, so it works even if the file is missing. Defaults:

```json
{
  "sigMaxAgeDays": 7,
  "taniumService": "Tanium Client",
  "securityAgentServices": ["masvc", "mfemms", "macmnsvc", "WinDefend", "Sense"],
  "hostnamePatterns": ["^MSEKL", "^MSEKW"],
  "dodRootThumbprints": []
}
```

The tool **never writes** this file (no SMB atomic-write hazard) - operators edit
the JSON by hand and re-run. Leaving `dodRootThumbprints` empty is intentional: the
PkiRoots check reports **EXT** (not FAIL) until real DoD root thumbprints are
configured, so an un-configured baseline never manufactures a false quarantine.

## Run model / reuse

Standard suite fan-out (shared with wpt / winupgrade / biosfirmware): `.NET`
TcpClient reachability pre-check (5985 then 445, 1.5s), a RunspacePool
BeginInvoke fan-out with a per-host watchdog and the operator-cancel bridge
(`$Params['__job']`), a single-round-trip probe, and the session-based
DNS-mismatch guard (never a PTR lookup). Read-only: no audit rows are emitted
(mirrors the Windows Upgrade Diagnose action).

## Action side (v1.4.0) - Import + per-pillar fixes + Run All

Actions that extend the read-only scan with the ACTION half of Comply-to-Connect.
(v1.4.0 split the old monolithic `fix` into six per-pillar actions + `run-all`.)

### `import` - "Import C2C Compliance CSV" (read-only, `destructive=false`)

Columns `Host, Compliance, Failed, Audit, Fqdn`. Inputs: `csvPath`
(type `file`, CSV) and/or `csvText` (type `textarea`, pasted CSV). Local parse -
**no WinRM, no credential**.

Parses the Tanium **"C2C Compliance Status"** export. The `Compliance` cell is
multiline inside one quoted CSV cell: the first line is `Compliant` /
`Non-Compliant`, following lines are rule names (`Failed Rule[ N] - <name>` /
`Audit Rule[ N] - <name>`). Each rule is stripped of its prefix and mapped to a
canonical pillar (recording Failed vs Audit):

| Rule name (stripped) | Canonical pillar | Routing |
|---|---|---|
| Continuous / Endpoint Monitoring, Tanium | **Monitoring** | fixable HERE (Fix Monitoring: heal Tanium client service) |
| Host / Endpoint Firewall, Firewall | **Firewall** | fixable HERE (Fix Firewall: enable disabled profiles) |
| Endpoint Data At Rest Encryption, Bitlocker | **Encryption** | fixable HERE (Fix Encryption: resume / ENABLE BitLocker) |
| Anti-malware, MDE Health | **AntiMalware** | fixable HERE (Fix AntiMalware: heal Defender / MDE) |
| PKI Trust Roots | **PkiRoots** | fixable HERE (Fix PKI Roots: add DoD roots from .sst) |
| Patching Compliance, Patching | **Patches** | endpoint-kickable HERE (Fix Patches: MECM scan / eval) |
| Vulnerability Compliance, Vulnerabilities | **Vuln** | ACAS / Reports / KEV tools |
| OS Version | **OSVersion** | Windows Upgrade tool |
| STIG Check | **STIG** | Reports / STIG |
| *(anything else)* | *verbatim stripped name* | review manually |

FQDN -> short name for targeting (FQDN kept for display/export). De-duplicates by
host, worst row wins (Non-Compliant over Compliant; tie -> more failed pillars).
Summary: `@{ total; compliant; nonCompliant; nonCompliantHosts=@(...);
pillars=@(@{ name; failedCount; hosts=@(...); routing });
runAllPlan=@(@{ host; pillars=@(...) }) }`. `runAllPlan` is each non-compliant host
plus ONLY its endpoint-fixable failed pillars - the exact JSON the view hands the
`run-all` action verbatim. The view can also load a pillar's failing hosts straight
into the target list. Unknown rules are surfaced verbatim, never dropped.

The view renders an **IMPORT C2C COMPLIANCE CSV** card (file picker + Import) below
Target Computers: after import it shows per-pillar count chips and buttons -
"Load ALL non-compliant -> targets" plus one "Load `<Pillar>` hosts" button per
endpoint-fixable pillar - each replacing the Target Computers list - and a
**RUN ALL (N hosts, M fixes)** button (only when `runAllPlan` is non-empty).

### Per-pillar fixes + `run-all` (**destructive**, `destructive=true`)

The monolithic `fix` action was split (v1.4.0, clean break - the `fix` id is
removed). There are now **six per-pillar actions** plus **run-all**. All are
`destructive=true`, columns `Host, Ping, Status, Detail`, server admin-session gate,
and require `confirm` == exact `FIX`. Shared safety on every one: rejects 0 valid
targets (same token regex as scan); **self-guard** drops any dispatcher-local target
(short/FQDN/`localhost`/`127.*`/`::1`) with a `SKIPPED` row; **wrong-box guard**
compares the answering box's name to the dialed short name and aborts that host with
`SKIPPED` "DNS MISMATCH"; 300s per-host watchdog; operator-cancel bridge. A single
per-host worker (`C2cFixBlock`) and a single fan-out are shared - the per-pillar
actions pass a one-pillar set applied to every target; run-all passes each host's OWN
set. The worker takes the pillar list PER host job (the set may differ per host).

**Per-pillar action ids / labels / inputs** (each: `targets` hostlist required;
`confirm`; `threads` default 8 clamped 1-16; `attemptOffline` default false):

| Action id | Label | Extra inputs | What changes on the endpoint |
|---|---|---|---|
| `fix-monitoring` | Fix Monitoring (Tanium) | - | Tanium client service (name from `taniumService`) -> Automatic + Started; verify. Result MONITORED / ALREADY MONITORED / FAIL (not installed). |
| `fix-firewall` | Fix Firewall | - | `Set-NetFirewallProfile -Enabled True` on any disabled profile (netsh fallback); verify all 3 on. FIREWALL ENABLED / ALREADY ENABLED / FAIL. |
| `fix-antimalware` | Fix AntiMalware (Defender) | - | WinDefend/Sense Automatic + Started; enable RTP; `Update-MpSignature` if age > 7d; re-read. PROTECTED / ALREADY PROTECTED / FAIL. Missing MDE Sense is a note. |
| `fix-patches` | Fix Patches (MECM cycle) | - | `Invoke-CimMethod root\ccm SMS_Client TriggerSchedule` {..113} then {..108}. PATCH CYCLE KICKED / FAIL (root\ccm unreachable). |
| `fix-encryption` | Fix Encryption (BitLocker) | `enableEncryption` (bool, default false) | Resume suspended protectors (PROTECTION RESUMED / ALREADY ENCRYPTED). If `enableEncryption` and FullyDecrypted: FVE policy assert -> reuse/add RecoveryPassword protector -> escrow Entra-first / AD fallback -> Enable-BitLocker XtsAes256 (ENCRYPTION STARTED). Escrow-first, fail-closed; TPM-ready + domain-joined only; recovery password never emitted. |
| `fix-pki` | Fix PKI Roots | `sstPath` (file, **required**) | Add DoD roots from the .sst to `X509Store('Root','LocalMachine')` - additive only. ROOTS INSTALLED (added N of M) / ROOTS ALREADY PRESENT / FAIL. The .sst is read + validated `X509Certificate2Collection` **admin-side, once, before any host is dialed** (bad bundle aborts). |

**Result labels**: the underlying raw tokens (FIXED / NOCHANGE / STARTED / KICKED /
SKIP / FAIL / IN PROGRESS) stay machine-stable and drive the host-status rollup; a
per-pillar label map turns them into the pillar-flavoured display labels above (only
what streams to the row Detail + the per-check report). Log line levels: `FAIL` ->
error, `SKIP` -> warn, `ALREADY*` / `IN PROGRESS` -> info, everything else -> ok.

### `run-all` - "RUN ALL - Fix Imported Non-Compliant Hosts"

Inputs: `plan` (type `textarea`, the import's `runAllPlan` JSON, required);
`enableEncryption` (bool, default false); `sstPath` (file, **required only if a
planned host includes PkiRoots** - validated up front, missing/invalid aborts the
whole run, nothing dialed); `confirm`; `threads`; `attemptOffline`. The engine
validates the plan JSON: unknown pillar names are dropped per host with a warn log
line; a host left with zero fixable pillars gets an info row
`nothing endpoint-fixable (Vuln/OSVersion/STIG route elsewhere)` and is never dialed;
each dialed host runs ONLY its planned pillars. Self-guard + wrong-box + watchdog +
cancel exactly like the per-pillar fixes. Summary adds per-pillar `fixed/nochange/fail`
tallies (`perPillar`) alongside the per-status host counts.

**Host Status** (both paths) = FIXED (>=1 FIXED/STARTED/KICKED, 0 FAIL) / NO CHANGE
(all NOCHANGE/SKIP) / PARTIAL (mix with FAIL) / FAILED (all failed or session error)
/ OFFLINE / SKIPPED. Emits a `VulnPatched` audit row per host.

The view's **FIX ACTIONS (per pillar)** card carries one Run button per pillar
(Encryption row has the indented ENABLE-BitLocker checkbox; PKI Roots row has the
`.sst` picker), plus one shared threads / attempt-offline / `FIX` confirm input and a
CANCEL RUN button. Each row arms via its own `ctx.arm` preflight dialog then sends its
own action id. The **RUN ALL** button (in the Import card) arms a dialog listing the
per-pillar host counts, states encryption only STARTS if the enable box is ticked, and
passes the plan JSON plus the card's `enableEncryption` / `sstPath` settings.
