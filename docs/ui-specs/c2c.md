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
| 1 | Monitoring | `Get-C2cTaniumInstalled` (scan the 64- and 32-bit HKLM Uninstall keys for a DisplayName matching "Tanium") AND `Get-Service` the Tanium client service (`taniumService`, default "Tanium Client") | software installed AND service Running. Detail states BOTH facts, e.g. `Tanium installed (v...); service Running` / `Tanium not installed; service not installed` / `Tanium installed (v...); service Stopped` |
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

## Action side (v1.6.0) - Import-driven fix CARDS + Run All + Version Check

Actions that extend the read-only scan with the ACTION half of Comply-to-Connect.
The fix workflow is **import-driven and ACAS-styled**: importing the Tanium CSV
populates one **card per fixable pillar**, each carrying its OWN affected-host list
(mirroring the ACAS Nemesis Updater's one-card-per-vulnerability idiom), with a
**RUN ALL** over the checked cards.

**v1.6.0 changes vs v1.5.0:**
- **`fix-pki` is BACK** as a folder/`.cer`-bundle DoD-roots installer (replacing the
  removed `.sst` mechanism). PkiRoots is a **fixable** pillar again - the import routes
  it "fixable HERE" and it re-enters the run-all plan. The engine reads a cert bundle
  folder **admin-side once** before dialing any host: `<folder>\root\*.cer` -> **Root**,
  `<folder>\Intermediate\*.cer` -> **CA**, `<folder>\Untrusted\*.cer` -> **Disallowed**,
  loose `<folder>\*.cer` -> **Root** (case-insensitive). Missing folder / zero certs ->
  ABORT, nothing dialed. Per host the certs are added **ADDITIVELY** (only thumbprints
  not already present; nothing is ever removed). Endpoint-fixable set is now **six**;
  **action count is 10** (scan + import + 6 fix-* + run-all + version-check). `sstPath`
  stays gone - `certBundleFolder` replaces it.
- **Shipped DoD trust bundle + auto-default (finalized v1.6.0)** - the repo now ships the
  base bundle at **`Packages\DoD-Certs`** (subfolders `Root\` `Intermediate\` `Untrusted\`,
  89 `.cer`). Both `fix-pki` and `run-all` DEFAULT their cert-bundle path to it: when
  `certBundleFolder` is blank/whitespace the engine falls back to
  **`Get-C2cDefaultCertBundlePath`** (= `$PSScriptRoot\..\Packages\DoD-Certs`, mirroring
  `Get-C2cBaselinePath`) **only when that folder exists and holds >=1 `.cer`**. An
  operator-supplied path ALWAYS wins; the resolver **`Resolve-C2cCertBundleFolder`** tags
  the source `operator-supplied` / `shipped default` and the engine logs which bundle was
  used + its cert count. Only when BOTH the supplied path is blank AND the shipped default
  is missing/empty does the prior behaviour hold: `fix-pki` **ABORTS** with a clear error,
  `run-all` **SKIPS** PkiRoots per host. Net effect: one-click `fix-pki` (nothing typed)
  just works against the shipped bundle.
- **`version-check`** (read-only) - per host read BOTH uninstall hives for a product
  DisplayName substring and compare the DisplayVersion to an optional target.
- **WinRM-heal** (opt-in `winrmHeal`, default off, RPC-based, often blocked) - a shared
  best-effort pre-step wired into the fix fan-out AND version-check that tries remote SCM
  recovery of a stopped WinRM service for a host whose TCP 5985 probe failed, then
  re-probes. Self-guarded (never acts on the dispatcher; reuses `Test-JanetC2cHostIsSelf`).

(History: v1.5.0 dropped the `.sst` fixer + made Monitoring verify Tanium is installed;
v1.4.0 split the old monolithic `fix` into per-pillar actions + `run-all`. Monitoring
still verifies the Tanium software is installed via the uninstall registry - the probe
helper is now `Get-C2cInstalledProduct -Match <substr>` with `Get-C2cTaniumInstalled` a
thin wrapper, so scan check #1, `fix-monitoring` and `version-check` share ONE probe.)

### `version-check` - "Version Check (read-only)" (`destructive=false`)

Columns `Host, Ping, Installed, Version, Status, Detail`. Inputs: `targets` (hostlist,
required), `productMatch` (text, required - DisplayName substring), `targetVersion`
(text, optional), `winrmHeal` (bool, default false), `threads` (int, default 16; 1-32),
`attemptOffline` (bool, default false). Per host: TCP reachability (+ optional WinRM-heal),
then `Invoke-Command` reads both the 64- and 32-bit uninstall hives via the shared
`Get-C2cInstalledProduct`. Status = **UP TO DATE / OUTDATED / NEWER** (System.Version
compare when both parse, else ordinal string compare) when a target is given, else
**INSTALLED / NOT INSTALLED**; unreachable -> **OFFLINE**. No admin session, no confirm.

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
| Continuous / Endpoint Monitoring, Tanium | **Monitoring** | fixable HERE (Fix Monitoring: verify Tanium installed + heal client service) |
| Host / Endpoint Firewall, Firewall | **Firewall** | fixable HERE (Fix Firewall: enable disabled profiles) |
| Endpoint Data At Rest Encryption, Bitlocker | **Encryption** | fixable HERE (Fix Encryption: resume / ENABLE BitLocker) |
| Anti-malware, MDE Health | **AntiMalware** | fixable HERE (Fix AntiMalware: heal Defender / MDE) |
| Patching Compliance, Patching | **Patches** | endpoint-kickable HERE (Fix Patches: MECM scan / eval) |
| PKI Trust Roots | **PkiRoots** | fixable HERE (Fix PKI Trust Roots: install the DoD trust bundle .cer into Root/CA/Disallowed) |
| Vulnerability Compliance, Vulnerabilities | **Vuln** | ACAS / Reports / KEV tools |
| OS Version | **OSVersion** | Windows Upgrade tool |
| STIG Check | **STIG** | Reports / STIG |
| *(anything else)* | *verbatim stripped name* | review manually |

FQDN -> short name for targeting (FQDN kept for display/export). De-duplicates by
host, worst row wins (Non-Compliant over Compliant; tie -> more failed pillars).
Summary: `@{ total; compliant; nonCompliant; nonCompliantHosts=@(...);
pillars=@(@{ name; failedCount; hosts=@(...); routing });
runAllPlan=@(@{ host; pillars=@(...) }) }`. `runAllPlan` is each non-compliant host
plus ONLY its endpoint-fixable failed pillars (PkiRoots is fixable again in v1.6.0, so it
DOES enter the plan) - the exact JSON the view intersects with the checked cards for the
`run-all` action. Unknown rules are surfaced verbatim, never dropped.

The view renders an **IMPORT C2C COMPLIANCE CSV** card (file picker + Import) below
Target Computers, plus **hero StatCards** that populate after import: Total hosts /
Non-Compliant / Fixable hosts (distinct hosts with >=1 fixable pillar = `runAllPlan`
length) / Routed-only (non-compliant minus fixable). After import the view builds one
**FIX CARD per fixable pillar** present (see below).

### Import-driven fix CARDS + `run-all` (**destructive**, `destructive=true`)

There are **five per-pillar actions** plus **run-all**. All are `destructive=true`,
columns `Host, Ping, Status, Detail`, server admin-session gate, and require
`confirm` == exact `FIX`. Shared safety on every one: rejects 0 valid targets (same
token regex as scan); **self-guard** drops any dispatcher-local target
(short/FQDN/`localhost`/`127.*`/`::1`) with a `SKIPPED` row; **wrong-box guard**
compares the answering box's name to the dialed short name and aborts that host with
`SKIPPED` "DNS MISMATCH"; 300s per-host watchdog; operator-cancel bridge. A single
per-host worker (`C2cFixBlock`) and a single fan-out are shared - the per-card fix
passes a one-pillar set applied to that pillar's imported hosts; run-all passes each
host's OWN checked set. The worker takes the pillar list PER host job.

**Per-pillar action ids / labels / inputs** (each: `targets` hostlist required;
`confirm`; `threads` default 8 clamped 1-16; `attemptOffline` default false):

| Action id | Label | Extra inputs | What changes on the endpoint |
|---|---|---|---|
| `fix-monitoring` | Fix Monitoring (Tanium) | - | Verify Tanium software installed (uninstall registry, `Get-C2cTaniumInstalled`); heal the client service (name from `taniumService`) -> Automatic + Started; verify. Result MONITORED / ALREADY MONITORED / FAIL. FAIL cases: service ABSENT but installed -> "repair via Software Center/MECM"; neither installed nor service -> "deploy from Software Center/MECM". No service is ever created. |
| `fix-firewall` | Fix Firewall | - | `Set-NetFirewallProfile -Enabled True` on any disabled profile (netsh fallback); verify all 3 on. FIREWALL ENABLED / ALREADY ENABLED / FAIL. |
| `fix-antimalware` | Fix AntiMalware (Defender) | - | WinDefend/Sense Automatic + Started; enable RTP; `Update-MpSignature` if age > 7d; re-read. PROTECTED / ALREADY PROTECTED / FAIL. Missing MDE Sense is a note. |
| `fix-patches` | Fix Patches (MECM cycle) | - | `Invoke-CimMethod root\ccm SMS_Client TriggerSchedule` {..113} then {..108}. PATCH CYCLE KICKED / FAIL (root\ccm unreachable). |
| `fix-encryption` | Fix Encryption (BitLocker) | `enableEncryption` (bool, default false) | Resume suspended protectors (PROTECTION RESUMED / ALREADY ENCRYPTED). If `enableEncryption` and FullyDecrypted: FVE policy assert -> reuse/add RecoveryPassword protector -> escrow Entra-first / AD fallback -> Enable-BitLocker XtsAes256 (ENCRYPTION STARTED). Escrow-first, fail-closed; TPM-ready + domain-joined only; recovery password never emitted. |
| `fix-pki` | Fix PKI Trust Roots | `certBundleFolder` (text, optional - blank auto-uses the shipped `Packages\DoD-Certs` bundle) | Read the DoD trust bundle folder admin-side once (root\ -> Root, Intermediate\ -> CA, Untrusted\ -> Disallowed, loose *.cer -> Root); a BLANK path falls back to the shipped default (`Get-C2cDefaultCertBundlePath`). Only a supplied-blank AND missing/empty default ABORTS before any dial. Per host open each store ReadWrite and add ONLY thumbprints not already present (never remove). ROOTS INSTALLED / ROOTS ALREADY PRESENT / FAIL. |

All fix actions also carry the opt-in `winrmHeal` (bool, default false) toggle - the
RPC-based best-effort WinRM-service recovery for hosts whose 5985 probe fails (often
blocked; never targets the dispatcher). `fix-pki`'s `certBundleFolder` is the folder/`.cer`
replacement for the removed `.sst` mechanism (base64 certs cross the WinRM boundary; the
`X509Store` add is ADDITIVE by thumbprint). The installer is `Add-C2cBundleToStores` (an
injectable store-opener makes the additive-only guard unit-testable against a fake store).

**Result labels**: the underlying raw tokens (FIXED / NOCHANGE / STARTED / KICKED /
SKIP / FAIL / IN PROGRESS) stay machine-stable and drive the host-status rollup; a
per-pillar label map turns them into the pillar-flavoured display labels above (only
what streams to the row Detail + the per-check report). Log line levels: `FAIL` ->
error, `SKIP` -> warn, `ALREADY*` / `IN PROGRESS` -> info, everything else -> ok.

### `run-all` - "RUN ALL - Fix Imported Non-Compliant Hosts"

Inputs: `plan` (type `textarea`, the import's `runAllPlan` JSON, required);
`enableEncryption` (bool, default false); `certBundleFolder` (text, **optional** - only
needed if a host plans PkiRoots, and a BLANK value auto-uses the shipped
`Packages\DoD-Certs` default); `winrmHeal` (bool, default false); `confirm`; `threads`;
`attemptOffline`. (There is **no `sstPath`** input anymore.) The engine validates the plan
JSON: non-endpoint-fixable pillar names are dropped per host with a warn log line (Vuln /
OSVersion / STIG); if a host plans **PkiRoots but no valid cert bundle** could be resolved
(none supplied AND the shipped `Packages\DoD-Certs` default missing/empty), PkiRoots is
skipped for that host with an info note (the run continues); a host left with
zero fixable pillars gets an info/SKIPPED row
`nothing endpoint-fixable (Vuln/OSVersion/STIG route elsewhere)` and is never dialed;
each dialed host runs ONLY its planned pillars. Self-guard + wrong-box + watchdog +
cancel exactly like the per-pillar fixes. Summary adds per-pillar `fixed/nochange/fail`
tallies (`perPillar`) alongside the per-status host counts.

**Host Status** (both paths) = FIXED (>=1 FIXED/STARTED/KICKED, 0 FAIL) / NO CHANGE
(all NOCHANGE/SKIP) / PARTIAL (mix with FAIL) / FAILED (all failed or session error)
/ OFFLINE / SKIPPED. Emits a `VulnPatched` audit row per host.

### View - the fix cards (ACAS Updater idiom)

After a successful import the view renders, under a **FIXABLE HERE** section, one
compact card per fixable pillar present (Monitoring / Firewall / Encryption /
AntiMalware / Patches / **PKI Trust Roots**). Each card = a checkbox (checked by default)
+ the pillar title + its affected-host count (click to review the host list in a dialog)
+ a per-card **Fix on N** button that dispatches `fix-<pillar>` with `targets` = that
pillar's imported hosts. The **Encryption** card carries the ENABLE-BitLocker toggle; the
**PKI Trust Roots** card uses the shared **PKI cert bundle folder** path input in the
fix-card header, which now DEFAULTS to the shipped bundle - its placeholder/hint reads
"leave blank -> shipped DoD bundle (Packages\DoD-Certs)", so one-click fix-pki works with
nothing typed; type a folder only to override (applies to the PKI card and RUN ALL). Under a **ROUTED
ELSEWHERE** section, non-runnable info cards show Vuln / OSVersion / STIG with their host
counts (never dialed). A **Select all / Select none** pair, a single shared `FIX` confirm
input + threads / attempt-offline / a shared **Recover WinRM (RPC)** toggle + the PKI
cert bundle path + CANCEL RUN, and a prominent **RUN ALL** button live in the fix-card
header. RUN ALL builds the plan from the CHECKED fixable cards (each host mapped to only
its own checked failed pillars, intersected with the imported `runAllPlan`) and arms a
`ctx.arm` dialog listing the per-pillar host counts (encryption only STARTS if the
Encryption card's ENABLE toggle is ticked; PkiRoots is skipped per host if no bundle
folder is set). A separate read-only **VERSION CHECK** card (productMatch + optional
targetVersion + a WinRM-heal toggle) runs `version-check` across the Target Computers
list. Credentials stay universal (no per-tool cred control). All runs stream into the
shared Results grid + Activity log; Export CSV is retained.
