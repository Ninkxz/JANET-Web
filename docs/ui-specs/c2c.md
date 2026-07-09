# JANET Web - UI Spec: c2c (C2C Nemesis)

> Renamed 2026-07-08: display name **C2C Readiness -> C2C Nemesis** (tool id `c2c`
> is unchanged - routes, registry keys, view registration and log/export names all
> stay `c2c` / "C2C Readiness Scan").

> **v1.8.0 (2026-07-09) - TASKORD 26-0822 realignment: tiered verdict, MDE Org ID,
> encryption/patch rule fixes, new OS Version audit check:** The scan's verdict now
> matches the authoritative **C2C TASKORD 26-0822** Tanium dashboard instead of a
> blanket "any FAIL -> quarantine" rule. Each of the 11 checks carries a fixed
> **tier** (`$script:C2cPillarTier`): **5 QUARANTINE** (Firewall, AntiMalware,
> Patches, Encryption, Vuln[EXT]) are the only checks that can produce **QUARANTINE
> RISK**; **2 AUDIT** (PKI Trust Roots, OS Version - OS Version is a brand-new check)
> are shown and still fixer-remediable but never quarantine; **3 INFO** (AppWhitelist,
> Agents, COAMS) are JANET-only advisory checks stricter than the TASKORD baseline;
> **Monitoring** is its own **ATTEST** tier - a dead/uninstalled Tanium client now
> drives a dedicated **NOT ATTESTING** verdict instead of being lumped into
> QUARANTINE RISK. Three checks were corrected to match the TASKORD rule text instead
> of JANET's stricter prior reading: **AntiMalware** now PASSes on installed +
> signatures < 7 days (168h, strict) + a matching **MDE Org ID**
> (`99557BCC-8DC2-443B-AF2E-08C9162C01BB`, hardcoded program-wide, not base-specific) -
> RunningMode / RTP / Sense-onboarded stay advisory-only, never a fail; **Encryption**
> now scores the **C: / OS volume's Protection Status alone** (other fixed volumes are
> advisory, not scored - was previously all-fixed-volumes-FullyEncrypted); **Patches**
> fixes a no-op WMI filter bug (`InstallState`/`ApplicabilityState` are
> `CCM_Application` properties, always `$null` on `CCM_SoftwareUpdate`, so the old
> filter silently passed every pending row) - the correct query is `ComplianceState=0`,
> plus a new `graceDays` baseline key (default 7) before an overdue update fails the
> check (was previously any-pending-fails). The `Firewall` netsh fallback now fails
> CLOSED (`ERROR`) instead of falsely PASSing on unparseable output. Import now
> aggregates each host's **Audit**-rule CSV findings into a parallel `auditPillars`
> summary (kept separate from the quarantine-relevant `pillars`), and the `run-all`
> plan can proactively remediate an audit-only fixable pillar (PkiRoots) on an
> otherwise-Compliant host. Module **1.7.2 -> 1.8.0**.

> **v1.8.0 (2026-07-08) - fixes are TARGET-DRIVEN; import is now OPTIONAL:**
> The **TARGET COMPUTERS** list is the single source of truth for every action -
> the read-only Scan / Version Check AND the destructive fixes. The **six fixable
> pillar cards** (Monitoring / Firewall / Encryption / AntiMalware / Patches / PKI
> Trust Roots) now render **immediately at mount** (no import required); each
> pillar's per-card **Fix** and the prominent **FIX SELECTED PILLARS ON TARGET
> LIST** run-all dial `targets.hosts()`. Anything you can put in Target Computers is
> fixable (this delivers the LTMA "push the DoD cert bundle to any host list"
> workflow: type hosts, run Fix PKI). The **CSV import is now purely a convenience**:
> on import the view (a) auto-loads the non-compliant hosts into Target Computers
> (merged, never clobbering typed hosts), (b) auto-checks + **badges** each pillar a
> host failed ("N flagged by import", click to review the flagged hosts), and (c)
> logs the routed-elsewhere pillars (Vuln / OSVersion / STIG). Import NEVER gates the
> cards or the ability to run a fix.
>
> **Import "cards do not load" fix:** the run-bus final-summary contract was verified
> end-to-end correct (engine returns `@{rows;summary}`; the server emits
> `@{type='final';result=$res}`; `RunController.reduce` dispatches `final` with
> `ev.result`, so `res.summary` is the import summary - identical to the working ACAS
> pattern). The real defect was architectural: card rendering AND every fix path were
> hard-gated on the import bucket (`lastImport` / per-card `data.hosts`), and
> `RunController.dispatch` **silently swallows any handler exception**, so a single
> throw inside the import callback left the operator with an empty "No fix cards yet"
> panel and no way to fix. The rework removes that gate entirely (cards are always
> present + target-driven) and wraps the import-summary apply in try/catch that logs
> instead of failing silently. **No engine or param/plan shape changed** (per-card
> fix still sends `targets`; run-all still sends `plan=[{host,pillars}]`), so the
> Pester suite is untouched (569/569).

> **v1.7.0 (2026-07-08) - two pillar-correctness fixes (real fleet evidence):**
> (1) **Encryption covers ALL FIXED VOLUMES**, not just the system drive. The scan
> check FAILs if any fixed volume is decrypted (removable/USB excluded); the fixer
> iterates every fixed volume - the OS volume keeps the TPM + escrow-first enable
> flow, fixed DATA volumes enable escrow-first with NO TPM protector + auto-unlock.
> (2) **AntiMalware honours `AMRunningMode`** - a Passive / EDR Block Mode box that is
> primary-managed by MDE Sense (RTP off is CORRECT) now PASSes and the fixer no
> longer force-enables RTP against the MDE config. New baseline key `sigMaxAgeHours`
> (default 24; falls back to `sigMaxAgeDays * 24`).

> **v1.7.0 hardening (same version, same feature - correctness only):**
> (a) the Encryption ENABLE consent (checkbox label + tooltip, per-card preflight, and
> both the fix-encryption + RUN ALL arm dialogs) now discloses that ticking enable starts
> full-volume encryption on the OS **and** fixed DATA volumes, not just the OS drive;
> (b) the AntiMalware fixer re-evaluates the running mode after the WinDefend/Sense heal +
> re-read and forces RTP for a box that transitioned Disabled->Active - a box that ends
> Active-but-RTP-off is FAIL, never FIXED; (c) the scan-check `manage-bde` fallback PASSes
> only on Fully Encrypted (Protection On + Conversion Status Fully Encrypted / 100%), not
> Protection On alone.

> JANET Web tool (with a desktop twin, C2CNemesisTool). Read-only Comply-to-Connect quarantine
> predictor. This is a standard `stream-table` tool: paste targets, run one action,
> watch per-host verdict rows stream in and the full per-check report fill the
> activity log. Reuse the shared stream-table view (same as wpt / winupgrade /
> biosfirmware) - no bespoke UI.

## Summary

**C2C Nemesis** (tool id `c2c`, category **Reporting**, icon `E72E`) predicts
whether each host would be **QUARANTINED** under AFI/MPTO **Comply-to-Connect rule
3.B.2.B**, aligned to the authoritative **C2C TASKORD 26-0822** Tanium dashboard:
only **5 of the 11 checks** (the QUARANTINE tier) actually drive that verdict, **2**
are shown as audit-only (never quarantine), **3** are JANET-only advisory info, and
Monitoring (Tanium) has its own dedicated **NOT ATTESTING** outcome. It fans out
over WinRM, runs **one consolidated read-only probe per host** (11 C2C checks in a
single `Invoke-Command` round-trip), emits **one result row per host** (`Host / Ping
/ Status / Detail`), and streams the **full 11-line per-check report** to the
activity log for colouring. It **changes nothing** and **needs no admin session**
(read-only, like the WPT ping / bulk-scan and the Windows Upgrade Diagnose action).

## Action

- **`scan` - "C2C Readiness Scan"** (read-only, `destructive=false`), columns
  `Host, Ping, Status, Detail`.
- **Inputs:** `targets` (hostlist, required), `attemptOffline` (bool, default
  false), `threads` (int, default 16; clamped 1-32).

## The 11 checks

Each check runs inside the one probe (its own try/catch, so a single failure ->
that check = `ERROR`, never aborting the probe) and yields a status
`PASS / FAIL / EXT / ERROR` plus a short Detail. Every pillar also carries a fixed
**tier** (`$script:C2cPillarTier`) that the verdict keys off ADMIN-SIDE - the check
bodies themselves are tier-agnostic, tiering is applied purely when the verdict and
report tag are computed:

- **QUARANTINE** (5: Firewall, AntiMalware, Patches, Encryption, Vuln) - the ONLY
  pillars the TASKORD 26-0822 dashboard actually quarantines on. Vuln always emits
  `EXT`, so it can never itself contribute a scored FAIL.
- **AUDIT** (2: PkiRoots, OsVersion) - shown, still fixer-remediable (PkiRoots), but
  a FAIL here NEVER quarantines (mirrors the dashboard's own "you cannot be
  non-compliant for audit rules").
- **INFO** (3: AppWhitelist, Agents, COAMS) - JANET-only advisory checks, stricter
  than the TASKORD baseline; a FAIL here is shown but never quarantines.
- **ATTEST** (1: Monitoring) - a dead/uninstalled Tanium client cannot report
  compliance to the dashboard at all, so it drives its own **NOT ATTESTING** verdict
  rather than `QUARANTINE RISK`.

| # | Pillar | Tier | Mechanism (read-only, on the target) | PASS when |
|---|--------|------|---------------------------------------|-----------|
| 1 | Monitoring | ATTEST | `Get-C2cTaniumInstalled` (scan the 64- and 32-bit HKLM Uninstall keys for a DisplayName matching "Tanium") AND `Get-Service` the Tanium client service (`taniumService`, default "Tanium Client") | software installed AND service Running. Detail states BOTH facts, e.g. `Tanium installed (v...); service Running` / `Tanium not installed; service not installed` / `Tanium installed (v...); service Stopped`. A FAIL/ERROR here (with no Quarantine-tier FAIL) drives `NOT ATTESTING`, not `QUARANTINE RISK` |
| 2 | Firewall | QUARANTINE | `Get-NetFirewallProfile` (Domain/Private/Public); fallback `netsh advfirewall show allprofiles state`, requiring all 3 profile headers AND 3 `State` lines to parse - **fails CLOSED** (`ERROR` "netsh output not parseable") rather than the old false-PASS on unparseable output | all three profiles Enabled (else FAIL lists the disabled ones) |
| 3 | AntiMalware | QUARANTINE | TASKORD rule 1. Endpoint-read the MDE Org ID (`HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status`->`OrgId`, fallback the ATP root key), normalize (strip braces/whitespace, uppercase) and compare to the hardcoded program-wide tenant `$script:C2cMdeOrgId` = `99557BCC-8DC2-443B-AF2E-08C9162C01BB`. `Get-MpComputerStatus` for install/signature-age; fallback `root\SecurityCenter2` AntiVirusProduct (Defender-only - a healthy 3rd-party-only AV FAILs, named, because TASKORD requires Defender specifically) | **installed** (Get-MpComputerStatus succeeds, or SecurityCenter2 has an enabled+current Defender product) **AND** signature age **< 7 days** (168h, strict) **AND** the endpoint's MDE Org ID matches. FAIL names every gap: `sig age Xh >= 7 days`, `MDE OrgId <found\|missing> != required <reqOrg>`. RunningMode / RTP / Sense-onboarded / product+engine version / a breach of the old `sigMaxAgeHours` fleet budget are now ALL advisory-only Detail - NEVER a fail (e.g. a Passive / EDR Block Mode box, or an Active-but-RTP-off box, PASSes if installed + fresh + correctly tenanted) |
| 4 | Patches | QUARANTINE | TASKORD rule 5. `SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState=0` (0=ciNotPresent=applicable-not-installed) in `root\ccm\ClientSDK` - **fixes a no-op filter bug**: the old query tested `InstallState`/`ApplicabilityState`, which are `CCM_Application` properties that are always `$null` on `CCM_SoftwareUpdate`, so every pending row silently passed the old filter. `overdue` = a pending update whose MECM `Deadline` has passed, or (no deadline) whose `StartTime` is older than the `graceDays` baseline key (default 7) | `overdue` count is 0 (Detail: `0 overdue update(s); M pending within 7-day grace`, plus a caveat that this is MECM-deployed updates only - Tanium scans the full patch list independently). FAIL names the overdue count; a pending-but-in-grace update is never itself a fail. CCM absent -> ERROR "MECM/CCM not queryable" |
| 5 | Vuln | QUARANTINE (EXT) | **EXT** - not endpoint-determinable | n/a - "AQC Score (filtered) must be < 25 - the #1 fleet quarantine driver; NOT verifiable by this scan (import the Tanium C2C CSV, or remediate via ACAS / Reports / KEV / UPR)" |
| 6 | Encryption | QUARANTINE | TASKORD rule 2. Identify the **C: / OS volume alone** (`VolumeType -eq 'OperatingSystem'`, else the volume whose MountPoint matches `$env:SystemDrive`) out of the enumerated fixed volumes (`Get-BitLockerVolume` correlated with fixed drive type - `Get-Volume` DriveType Fixed, else `Win32_Volume` DriveType=3; removable/USB/network/optical excluded, letterless system/EFI/recovery partitions skipped); fallback `manage-bde -status` on the system drive | that ONE volume's `ProtectionStatus -eq 'On'` - the entire TASKORD rule 2 score. Other fixed volumes not On, or the OS volume still mid-conversion (Protection On but not yet FullyEncrypted), are appended as `advisory (not scored): D: Off/FullyDecrypted; C: On but EncryptionInProgress(42%)` - shown, never a fail. `manage-bde` fallback: PASS on `Protection Status: Protection On` alone (Conversion Status is advisory detail, not scored) |
| 7 | AppWhitelist | INFO | AppLocker via `Get-AppLockerPolicy -Effective` (any RuleCollection EnforcementMode=Enabled); else WDAC via `Win32_DeviceGuard` (`CodeIntegrityPolicyEnforcementStatus >= 2`) | either enforcing (audit-only -> FAIL with a note; neither -> FAIL). Not a TASKORD rule - advisory only, never quarantines |
| 8 | Agents | INFO | patch agent `Get-Service CcmExec` Running AND >=1 `securityAgentServices` Running | both true; Detail names both states. Not a TASKORD rule - advisory only, never quarantines |
| 9 | PkiRoots | AUDIT | compare `Cert:\LocalMachine\Root` thumbprints against `dodRootThumbprints` | every required thumbprint present (else FAIL lists how many/which). **Empty baseline -> EXT** "configure DoD root thumbprints in c2c-baseline.json". Audit tier: a FAIL is shown as `[AUDIT]` (never `[FAIL]`) and stays fixer-remediable (`fix-pki`) but never quarantines |
| 10 | COAMS | INFO | **EXT** - server-side ARAD/ePO asset tags, not endpoint-readable | n/a - "ARAD/ePO server-side tags (7) - not endpoint-readable" |
| 11 | OsVersion | AUDIT | TASKORD rule 6 (NEW check, replaces the removed base-specific Hostname check). One registry read: `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (NOT the slow `Get-ComputerInfo`, and NOT `ProductName` - it still reports "Windows 10" on an 11 box; `CurrentBuildNumber` is authoritative) | Windows 11 (`CurrentBuildNumber >= 22000`) AND release 24H2+ (build >= 26100) AND `EditionID -eq 'Enterprise'` (exact match - Pro / EnterpriseS(LTSC) / Education FAIL). FAIL names every gap and routes to the Windows Upgrade tool. Audit tier: shown as `[AUDIT]`, never quarantines |

## Verdict (computed admin-side, TASKORD-tiered)

`Get-C2cVerdict` scores **only the QUARANTINE tier** (Firewall / AntiMalware /
Patches / Encryption / Vuln); AUDIT (PkiRoots, OsVersion) and INFO (AppWhitelist,
Agents, COAMS) FAIL/ERROR are advisory-only and never change the verdict:

```
qFail  = count(FAIL  where tier==Quarantine)   # Vuln is always EXT, so never contributes
qErr   = count(ERROR where tier==Quarantine)
monBad = Monitoring.Status in (FAIL, ERROR)

if     qFail >= 1 : QUARANTINE RISK   (Ok=false)
elif   qErr  >= 1 : CHECK ERRORS      (Ok=false)
elif   monBad     : NOT ATTESTING     (Ok=false)
else              : READY             (Ok=true)
```

- **QUARANTINE RISK** - >= 1 quarantine-tier FAIL (Detail lists the failing
  pillars). Outranks everything else, including a simultaneous Monitoring failure.
- **CHECK ERRORS** - 0 quarantine FAIL but >= 1 quarantine-tier ERROR (a
  quarantine-relevant pillar could not be evaluated). An AUDIT/INFO-tier ERROR (e.g.
  AppWhitelist, OsVersion) never triggers this and never demotes an otherwise-READY
  host.
- **NOT ATTESTING** - every quarantine pillar passes but Monitoring (Tanium) is
  FAIL/ERROR: the box is invisible to the C2C dashboard and cannot attest
  compliance, which is a materially different problem than a quarantine-triggering
  FAIL (and gets its own status rather than being lumped into QUARANTINE RISK).
- **READY** - 0 of the above. Any AUDIT/INFO findings are still shown, just
  advisory.
- **OFFLINE** - host unreachable (TCP 5985/445). With `attemptOffline` ticked the
  probe still tries a session; a connect/session failure surfaces as `ERROR`
  (rolled up to `CHECK ERRORS` on the result row).

`Detail` stacks its parts in order: the FAIL count/list, the ERROR count/list, then
either the NOT ATTESTING sentence (`Tanium not reporting - compliance cannot be
attested to the C2C dashboard`) or the READY sentence (`all quarantine pillars
pass`), then `AUDIT: <names>`, `INFO: <names>`, `EXT: <names>` - and, on a READY
verdict, `AQC/Vuln not endpoint-verifiable - import the Tanium C2C CSV to score the
#1 quarantine driver` (a READY scan never claims the server-side AQC score was
actually verified). E.g. `2 FAIL: Firewall, Encryption | AUDIT: PkiRoots | EXT:
Vuln, COAMS`.

The activity log receives the full 11-line report, each line prefixed with its
**display tag** (`Get-C2cDisplayTag`): a Quarantine/Attest-tier line keeps its raw
status (`[PASS]` / `[FAIL]` / `[ERROR]` / `[EXT]`); an Audit- or Info-tier FAIL/ERROR
is re-tagged `[AUDIT]` / `[INFO]` instead, so the report never paints an advisory
finding as red as a quarantine failure. The view colours by tag: `[PASS]` -> ok
(green), `[FAIL]` -> error (red), `[ERROR]` -> warn (amber), `[EXT]` / `[AUDIT]` /
`[INFO]` -> info (neutral - same bucket as EXT).

## Config (baseline)

`JanetLocal\c2c-baseline.json` ships with JANET (`.gitignore`-negated like the KEV
catalog) so it travels in take-to-work. The engine loads the embedded defaults and
overlays the file if present, so it works even if the file is missing. Defaults:

```json
{
  "sigMaxAgeDays": 7,
  "sigMaxAgeHours": 24,
  "graceDays": 7,
  "taniumService": "Tanium Client",
  "securityAgentServices": ["masvc", "mfemms", "macmnsvc", "WinDefend", "Sense"],
  "hostnamePatterns": ["^MSEKL", "^MSEKW"],
  "dodRootThumbprints": []
}
```

`sigMaxAgeHours` (v1.7.0, default 24) no longer decides AntiMalware PASS/FAIL - the
TASKORD-mandated 7-day (168h, strict) bar does that now, hardcoded. `sigMaxAgeHours`
is now (a) an advisory fleet-budget note in Detail when breached but still inside
the 7-day TASKORD bar, and (b) still the threshold the `fix-antimalware` action uses
to decide whether to `Update-MpSignature`; if omitted it falls back to
`sigMaxAgeDays * 24`. `graceDays` (v1.8.0, default 7) is the Patching grace window
in DAYS: a pending MECM update only fails the scan once it is past its enforcement
`Deadline` or, absent a deadline, once its `StartTime` is older than `graceDays`.

The MDE Org ID (`99557BCC-8DC2-443B-AF2E-08C9162C01BB`) is **not** a baseline key -
it is the hardcoded module constant `$script:C2cMdeOrgId` (the program-wide C2C
tenant, identical for every base under TASKORD 26-0822), threaded into the probe's
`ArgumentList`. It is deliberately NOT read from `c2c-baseline.json` and cannot be
overridden per base, unlike the removed base-specific `hostnamePatterns`.

The tool **never writes** this file (no SMB atomic-write hazard) - operators edit
the JSON by hand and re-run. Leaving `dodRootThumbprints` empty is intentional: the
PkiRoots check reports **EXT** (not FAIL) until real DoD root thumbprints are
configured, so an un-configured baseline never manufactures a false quarantine
(and, being Audit tier, a configured-but-failing PkiRoots never quarantines either).

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
auditPillars=@(@{ name; failedCount; hosts=@(...); routing; audit=true });
runAllPlan=@(@{ host; pillars=@(...); auditPillars=@(...) }) }`. `pillars` is the
**Failed**-rule aggregation only (quarantine-relevant); `auditPillars` (v1.8.0) is
the same shape built from each host's **Audit**-rule findings (PKI Trust Roots, OS
Version) - kept separate so the CSV's own Failed/Audit split stays honest (an audit
finding is never counted as a compliance failure). `runAllPlan` is built from EVERY
imported record, not just non-compliant ones: each host's endpoint-fixable Failed
pillars UNION its endpoint-fixable Audit pillars (currently only PkiRoots is both
fixable and an audit rule), with the audit subset also called out on that plan entry
as `auditPillars` - so an otherwise-Compliant host that only fails the PKI audit
rule still gets a `run-all` plan entry and can be proactively remediated (`fix-pki`)
without ever being called a quarantine risk. This is the exact JSON the view
intersects with the checked cards for the `run-all` action. Unknown rules are
surfaced verbatim, never dropped.

The view renders an **IMPORT C2C COMPLIANCE CSV** card (file picker + Import) below
Target Computers, plus **hero StatCards** that populate after import: Total hosts /
Non-Compliant / Fixable hosts (distinct hosts with >=1 fixable pillar = `runAllPlan`
length - can now exceed Non-Compliant, since an audit-only proactive fix can target a
Compliant host) / Routed-only (non-compliant minus fixable, floored at 0). After
import the view builds one **FIX CARD per fixable pillar** present (see below).

### Import-driven fix CARDS + `run-all` (**destructive**, `destructive=true`)

There are **six per-pillar actions** (Monitoring, Firewall, AntiMalware, Patches, Encryption, PkiRoots) plus **run-all**. All are `destructive=true`,
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
| `fix-antimalware` | Fix AntiMalware (Defender) | - | WinDefend/Sense Automatic + Started; force RTP (`Set-MpPreference`) ONLY when `AMRunningMode` is Active - never in Passive / EDR Block Mode (MDE Sense primary); `Update-MpSignature` when sig age > `sigMaxAgeHours` (default 24); re-read. The running mode is RE-EVALUATED from the re-read (a box that starts Disabled and transitions to Active once WinDefend is started - the first status read can lag - has RTP forced there and re-verified); a box that ENDS Active-but-RTP-off is reported FAIL, never FIXED. Only an Active-with-RTP-on or a compliant Passive/EDR end-state reports PROTECTED / ALREADY PROTECTED (a Passive/EDR box with Sense + fresh sigs -> NOCHANGE). Detail reports RunningMode + versions + last-update + age-hours. Missing MDE Sense is a note. |
| `fix-patches` | Fix Patches (MECM cycle) | - | `Invoke-CimMethod root\ccm SMS_Client TriggerSchedule` {..113} then {..108}. PATCH CYCLE KICKED / FAIL (root\ccm unreachable). |
| `fix-encryption` | Fix Encryption (BitLocker) | `enableEncryption` (bool, default false) | Iterates EVERY FIXED volume (removable/USB never touched; one `Encryption` result per volume so the host rolls up FIXED / PARTIAL / FAILED / NO CHANGE). Per volume: On -> ALREADY ENCRYPTED; suspended -> RESUME (PROTECTION RESUMED); EncryptionInProgress -> IN PROGRESS(%); FullyDecrypted -> SKIP unless `enableEncryption`. ENABLE, **OS volume**: FVE policy assert (once/host) -> reuse/add RecoveryPassword protector -> escrow Entra-first / AD fallback -> Enable-BitLocker TPM + XtsAes256 (ENCRYPTION STARTED); TPM-ready + domain-joined only. ENABLE, **fixed DATA volume**: requires the OS volume BitLocker-on first (else SKIP); escrow-first exactly like OS but NO TPM protector; Enable-BitLocker XtsAes256 full-volume; dedup to one escrowed recovery protector; best-effort `Enable-BitLockerAutoUnlock`. Escrow-first, fail-closed; recovery password never emitted. |
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

### View - the fix cards (TARGET-DRIVEN, v1.8.0)

The view renders **all six fixable pillar cards immediately at mount**, under a
**FIXABLE PILLARS (target-driven)** section - Monitoring / Firewall / Encryption /
AntiMalware / Patches / **PKI Trust Roots**. No import is required. Each card = a
checkbox (**UNCHECKED by default** - the operator opts each pillar in) + the pillar title + description, and a per-card
**Fix `<pillar>` on N target host(s)** button whose count updates **live** from the
Target Computers list (subscribed via `targets.model.onChange`). Per-card Fix
dispatches `fix-<pillar>` with `targets` = **`targets.hosts().join('\n')`** (the
Target Computers list), NOT an import bucket. If the target list is empty the button
is disabled and the guard alerts *"Add hosts to Target Computers first (type / paste
/ Import TXT, or Import a C2C CSV to auto-load them)."* Because every fixer is
**verify-first** (NO CHANGE where a host is already compliant), the per-card and
run-all arm dialogs state that running a pillar against a host that does not need it
is safe.

A prominent **FIX SELECTED PILLARS ON TARGET LIST (N host(s))** button is the
target-driven run-all: it builds `plan = targets.hosts().map(h => ({host:h,
pillars:<checked fixable pillars>}))` and dispatches `run-all` with
`{ plan, enableEncryption, certBundleFolder, winrmHeal, confirm, threads,
attemptOffline }`. Its arm dialog lists the checked pillars + the target host count +
the destructive/BitLocker disclosure + the verify-first safety note.

The **Encryption** card carries the ENABLE-BitLocker toggle - its label + tooltip and
the per-card / run-all preflight + arm dialogs DISCLOSE that ticking it starts
XtsAes256 FULL-VOLUME encryption on EVERY FullyDecrypted FIXED volume: the OS volume
(TPM) AND fixed DATA volumes (D:, E:, ... via recovery-password + AD/Entra escrow +
auto-unlock), an hours-long background operation; removable / USB drives are never
touched. The **PKI Trust Roots** card uses the shared **PKI cert bundle folder** path
input in the fix-card header (defaults to the shipped `Packages\DoD-Certs` bundle -
placeholder "leave blank -> shipped DoD bundle"); one-click Fix PKI against any host
list is the LTMA workflow. The header also holds a **Check all / Check none** pair, a
single shared `FIX` confirm input + threads / attempt-offline / a shared **Recover
WinRM (RPC)** toggle + **CANCEL RUN**.

**Import is optional and additive.** The **IMPORT C2C COMPLIANCE CSV (optional)**
card (below the fix cards) still shows the hero StatCards. On a successful import the
view: (a) **merges** the summary's `nonCompliantHosts` **plus every host carrying an
endpoint-fixable AUDIT finding** (v1.8.0 - e.g. a Compliant box still missing a PKI
trust root) into Target Computers (never clobbering hosts the operator typed -
de-duped case-insensitively, logs how many were new); (b) for each fixable pillar
with `failedCount > 0` - taken from EITHER the Failed aggregation OR the v1.8.0
`auditPillars` aggregation (so PkiRoots can badge purely from an audit-only finding
on an otherwise-compliant host) - records a **badge** ("N flagged by import", cyan,
click to review that pillar's flagged hosts in a dialog); the checkbox itself stays
**UNCHECKED** (import never auto-ticks a pillar - the operator opts in explicitly,
same as the always-on cards); (c) logs the AUDIT-rule findings on their own line
(`AUDIT findings (advisory, non-quarantine): PkiRoots N (audit -> ...)`, distinct
from the Failed-pillar log lines) and the routed-elsewhere pillars (Vuln / OSVersion
/ STIG) shown under a **ROUTED ELSEWHERE (from import)** section as non-runnable
info cards. The import `final` handler is wrapped in try/catch so a malformed
summary logs an error to the activity log + status line instead of silently
no-op'ing (the run bus's `dispatch` swallows handler throws).

A separate read-only **VERSION CHECK** card (productMatch + optional targetVersion +
a WinRM-heal toggle) runs `version-check` across the Target Computers list.
Credentials stay universal (no per-tool cred control). All runs stream into the
shared Results grid + Activity log; Export CSV is retained.
