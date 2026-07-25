# JANET suite — capability audit (2026-07-25)

**What this is.** The 2026-07-24 audit hunted defects. This one hunts *additions*: what the
operator still does by hand, what the suite cannot do at all, and what one implementation has
that the other lacks. Seven agents (4 × Opus 5, 3 × Fable 5) across remediation, compliance,
reporting, AD/identity, platform, desktop↔web parity, and operator workflow.

Every agent was held to the same rule: **an asserted gap must name where it looked and failed to
find the feature.** A wrong "this is missing" costs more than a missed idea — it sends us
building something that already exists. Claims below marked VERIFIED were re-checked by hand
against the source, not taken from the agent report.

---

## Part 0 — The three convergences

These emerged from agents that could not see each other's work. Convergence across independent
domains is the strongest signal in the audit, and none of it was visible from any single vantage.

### C1. The scheduler that the code tells operators to use, and that does not exist

Three agents hit this from different directions:

- **Reporting** — nightly burndown snapshots are impossible, so a trend chart has three
  irregular hand-clicked points.
- **Remediation** — the manifest *instructs* operators to arm it: `reports.psm1:429` and `:441`
  both say "can be armed on the off-hours Scheduler", and `:4134` renders that instruction into
  the generated HTML footer.
- **Workflow** — the restart countdown is a client-side `setInterval` (`restart.view.js:709-731`)
  that dies with the browser tab; the tooltip says "Leave the tool open".

VERIFIED: no scheduler route, no timer, no `schtasks` anywhere under `server\`. The desktop
twin has it (`RemoteRestartScheduler_1.6.3.ps1:3079` `Register-RrsScheduledTask`).

**Note the disagreement.** The parity agent argued the desktop's Schedule-as-Windows-Task should
*not* be ported, because it exists to survive the GUI closing and the web server process
persists; porting it would add a service-account credential-export path for no gain. The
remediation agent wanted a full scheduler tool. The workflow agent wanted the narrowest version:
move the already-confirmed armed countdown server-side, no disk persistence, hard-expire if the
session ends. **The workflow agent's scoping is right** — it closes the actual gap without
creating an unattended-credential surface.

### C2. Fail-closed doctrine binds only what the tool touches

Two agents, different pillars, same shape:

- **Compliance** — "escrow-first, fail-closed" is C2C's stated BitLocker doctrine, but it only
  applies to volumes JANET *changes*. A volume already `On` short-circuits to `ALREADY ENCRYPTED`
  (`c2c.psm1:169` manifest, verdict `:677`) and its key protectors are never enumerated.
  VERIFIED: `msFVE`, `RecoveryInformation`, `RecoveryGuid` — **zero hits across both repos**.
  Nothing has ever checked AD-side escrow.
- **AD/identity** — `adto` fails closed on an unreadable `userAccountControl`, but
  `adsearch`'s bulk computer lookup cannot even *see* account status: VERIFIED `$bulkAttrs`
  (`adsearch.psm1:610`) never loads `userAccountControl`.

The installed base — every box encrypted by MECM, by imaging, or by a tech before JANET existed
— is the population most likely to be TPM-only with no escrowed key, and it is exactly the
population the tool never inspects.

### C3. The test suite asserts text, not behaviour — measured

The 07-24 audit's organising insight was that ~1,640 green tests coexisted with every audited
defect. The platform agent quantified why, across 148 files / 2,269 `It` / 4,553 `Should`:

| Measure | Value |
|---|---|
| `Should Throw` | **0** (VERIFIED) — error paths are untested or hand-rolled |
| `It` blocks that call no function, only regex source | **163 (7.2%)** |
| Files that mirror module logic and load neither module nor server | **9** |
| `Save-ShimState`/`Restore-ShimState` copy-pasted into | **22 files** |
| Tests referencing `server/tool-registry.json` | **0** (VERIFIED) |
| Views with any test contact | 6 of 21; **all 12 components have none** |
| Pester `Mock` used | 0 times |

Worst single example: `Server.ReportPreviewSandbox.Tests.ps1:75-77` asserts
`$view -match 'Never add allow-same-origin'` — a string that exists **only in a comment**. The
test is titled "names the sandbox backstop and the never-add rule". It tests documentation.

And `docs/VIEW-CONTRACT.md` has silently rotted: VERIFIED that `setSort` and `setLabel` are
documented but exist nowhere in `web/js`. (Its `ctx.util.clickable` claim could not be
reproduced — present in neither docs nor code.)

---

## Part 1 — Ranked additions

Ordered by (severity of the gap) × (evidence quality) ÷ (effort). Effort is the agents'.

| # | Addition | Where | Effort | Why here |
|---|---|---|---|---|
| 1 | **BitLocker escrow audit** — read-only census reconciling endpoint protectors against AD `msFVE-RecoveryInformation` | new action on `c2c` | M | The unaudited installed base. Reduces lockout risk rather than creating it |
| 2 | **Port 3 desktop fixes** (see Part 2) | desktop | S each | Live defects, one already fixed in Web today |
| 3 | **Secure Boot pre-flight parity** — BitLocker/TPM/escrow columns on `scan-secure-boot` | extend existing | S | Scan says READY for hosts the enable path refuses at write time |
| 4 | **Contract-conformance harness** | `tests/` + runner | M | Makes C3 impossible to recur; see Part 3 |
| 5 | **Server-side armed runs** (narrow scheduler) | server + `restart` | M | Closes C1 without an unattended-credential surface |
| 6 | **"Use hosts in…" universal harvest** | `resultsgrid.js` | S–M | Receiving side already universal; only 3 senders in 21 tools |
| 7 | **Run Outcomes Board** — read the Runs CSV nothing reads | new action on `history` | S | Pure value already on disk |
| 8 | **Fleet coverage reconciliation** — AD population × audit trail | new action on `history` | M | "You patched 400 hosts, 60 are dead AD objects" |
| 9 | **Fleet software version baseline** — CURRENT/OUTDATED/ABSENT vs editable baseline | new action on `wpt` | S–M | ~99% of scan findings are third-party version vulns |
| 10 | **Scan coverage** — which machines does Tenable never see | new action on `reports` | M | Every report starts from hosts *inside* the import |
| 11 | **In-app help for the 7 tools with none** | `help-content.js` | S | VERIFIED: c2c, adto, patchlib, certdeploy, winrmbridge, kev, sysadmin — 4 destructive |
| 12 | **Fleet KB rollback** | new action on `wpt` | S | VERIFIED absent on *both* sides; engine exists, MSXML-gated |

### On #1 — handle the keys carefully

Both the compliance agent and I want the same guard: the recovery password must never reach a
row, a log line, or the audit CSV. Pin it with a test asserting no emitted field matches
`\d{6}(-\d{6}){7}`. **A fix for a key-visibility gap must not itself leak keys.**

### On #12 — the riskiest thing in this list

`wusa /uninstall` against a servicing-stack update can leave a host unserviceable, and removing
a security KB re-opens what it closed. Ship with: hard refusal on any KB whose description
matches `Servicing Stack`, dry-run default true, `/norestart` always, and an explicit warning
row naming the CVEs the KB was closing. VERIFIED the removal engine already exists at
`wpt.psm1:4608` but is reachable only through the MSXML-gated single-host path.

---

## Part 2 — Desktop defects found while looking for features

The parity agent was asked for capability gaps and returned three **live defects**, all of the
class we fixed in Web. This reframes the answer to "what can we add": some of the best additions
are ports of fixes already made.

| Defect | Evidence | Severity |
|---|---|---|
| **C2C accepts a leaf cert as a trust anchor** | VERIFIED: 0 hits for `BasicConstraints`/`CertificateAuthority` in `C2CNemesisTool_2.4.8.ps1`; Web has 8 | **This is the bug closed in Web earlier today. Still live on desktop.** |
| **C2C pushes to `Disallowed` unconditionally** | VERIFIED `:1507` iterates Root, CA, Disallowed with no gate; Web makes it opt-in, default OFF | Silently blacklists whatever sits in the bundle's `Untrusted\` |
| **ACAS mis-routes findings** — no exclude lists | Desktop `:2936-2939` matches bare `'Office'`, `'Chrome'`, `'Defender'`; Web has `Exclude=` lists at `acas.psm1:1492-1499` | **LibreOffice → `OfficeC2RClient /update`; Symantec → `Update-MpSignature`. Both return success and mark the finding fresh having fixed nothing.** |
| **UPR lacks the safe-uninstall plan** | VERIFIED: 0 hits for `Get-SafeUninstallPlan`; 4 sites interpolate `$guid` into an argument string, **plus 6 `cmd.exe` shell-outs** | See correction below |

> **CORRECTION (2026-07-25, after implementation).** This row originally said the agent's
> `cmd.exe /c "$unStr"` claim was "not reproduced — re-check before acting". **That was my error,
> not the agent's.** There are **six** such sites, confirmed at `Archive\UnsupportedProductRemediator_1.1.8.ps1`
> lines 2032, 2093, 2101, 2873, 2925, 2933. My grep searched for the literal string `cmd.exe /c`,
> but the code reads `Start-Process cmd.exe -ArgumentList "/c \`"$unStr\`""` — the `/c` is a
> separate argument with backtick-escaped quotes, so that literal never appears in the source and
> my pattern could not have matched. A negative grep result is only as good as the pattern; I
> reported the absence of a match as the absence of a defect. The agent was right and I published
> a correction to it that was itself wrong.

The mis-routing one is the worst day-to-day: it is a false green in production, the exact
failure mode this audit sequence exists to eliminate.

---

## Part 3 — The harness (#4), specifically

Four pieces, landed one per commit, TestKit and runner first:

0. **`tests/_Janet.TestKit.ps1`** — one corrected `Save-ShimState`/`Restore-ShimState` instead of
   22 copies, plus an AST lifter generalising `Secureboot.BitLockerRefuse.Tests.ps1:313-316` so
   module-less here-string payloads can be **executed** instead of regexed. This is what converts
   the 163 text-only `It`s and 9 mirror files into real tests over time.
1. **`Platform.ManifestContract.Tests.ps1`** — parse `tool-registry.json` (today: zero coverage),
   load every tool as the server does, assert over all 186 actions: ids resolve and are unique,
   `destructive` present, every input has a `type` from a closed set. Replaces the 22 exact
   version-pin assertions that break on every bump and prove nothing.
2. **`Platform.GuardParity.Tests.ps1`** — AST-hash the 13 `Get-*LocalIdentity` / `Test-*HostIsSelf`
   pairs and every injected `$script:*Src` block. **Duplication stays by design; divergence
   becomes a red test.** This is the structural fix for the whole `return ,$set` class.
3. **`Platform.ViewContract.Tests.ps1`** — generalise `Wpt.FanOutInjection.Tests.ps1:251-258`
   from wpt to all 21 views, asserting on *call sites, never comments*.

**Two risks the agent named and I agree with.** Test 2 will fail on day one — land it with
current divergences as an explicit shrinking allowlist or it becomes permanently red and
ignored. And `Sync-TakeToWork.ps1:24-30` refuses to cut a zip on a red suite, so a half-landed
harness blocks packaging.

---

## Part 4 — Explicitly not worth building

Recorded so it stops being re-litigated every audit.

| Rejected | Reason |
|---|---|
| **STIG_Tool → Web** | PowerSTIG is a PSGallery module tree; hard-blocked by no-third-party-modules. The *evidence* half (CKLB ingest, CKL/POA&M export) is portable and pure data — that part is worth doing |
| **VulnPatchTool → Web** | Needs live NIST NVD + a CAC-gated DoD ECPR session. Both outbound-internet-at-runtime. Cannot run on AFNET |
| **BetaTool → Web** | Empty placeholder by design |
| **`winrmbridge` → Desktop** | Runs server-side under a service account; a CAC desktop identity cannot bootstrap it. Architecturally web-only |
| **`remoteadmin` Open C$ → Desktop** | Exists because a browser cannot launch Explorer. On desktop, `Win+R \\host\C$` is native |
| **Desktop UPR Store/Appx handler → Web** | Web deliberately removed it (`upr.psm1:1197-1200`): the no-match pipeline returned OK having removed nothing. Divergence in the correct direction — fix is to remove it on desktop |
| **`wsusscn2.cab` offline WUA scanning** | Genuinely absent, but redundant: MECM is authoritative and `winupgrade/install-updates` already drives WUA |
| **Per-host campaign tracker** | `reports` already ships `remediation-plan`, `campaign-create/-verify`, `sla-aging`, `export-poam`, `burndown` |

**Corrections to the README's own implications:** `os-audit`, `install-updates`, `repair-health`,
`auto-fix` and `error-report` are all **present on desktop** WindowsUpgradeTool; `search-last-pc`
is **present on desktop** ADSearchTool. Do not build these.

---

## Part 5 — Cheap wins under an hour each

- **C2C PkiRoots ships inert.** VERIFIED `dodRootThumbprints = @()` (`c2c.psm1:300`), so the check
  emits "configure this in the baseline" instead of a verdict — while `certdeploy` already
  computes the accurate answer from the shipped bundle. Point one at the other.
- **`history/operator-summary` reads `VulnsPatched` into memory and drops it.** One column answers
  "who patched the most vulns".
- **`xlsx.js` exists and reports never uses it.** VERIFIED: a dependency-free OOXML writer built
  so Web matches the desktop's pure-.NET exports, and the weekly export still says CSV-only.
- **Desktop KEVCrossCheck 1.0.1 lacks Web's catalog-staleness gate** — a stale desktop catalog
  renders a green all-clear.

---

## Verification log

Claims I re-checked by hand rather than trusting: `$bulkAttrs` missing `userAccountControl`;
`$script:AdToUac` 8 flags; `pwdLastSet` absent; no desktop adto twin; Runs CSV write-only;
`xlsx.js` unused by reports; no scheduler; `msFVE` zero hits; `ALREADY ENCRYPTED` short-circuit;
`dodRootThumbprints` empty; secureboot scan columns; `wusa /uninstall` MSXML-only; MECM
client-side only; desktop C2C guard absent + `Disallowed` ungated; desktop UPR missing safe plan;
handoff senders = 3; 7 tools without help; `Should Throw` = 0; registry untested; VIEW-CONTRACT
rot.

**One agent claim did not reproduce** and is flagged in place: `ctx.util.clickable` in
VIEW-CONTRACT.md.

**One "did not reproduce" was my own bad grep.** The desktop UPR `cmd.exe` sites are real — all
six of them — and I wrongly reported them as unconfirmed because I searched for a literal that
the source does not contain. See the correction in Part 2. The lesson generalises beyond this
one line: **in this codebase a negative grep is weak evidence**, because the same construct is
spelled several ways (`Start-Process cmd.exe -ArgumentList "/c ..."`, escaped quotes, arguments
assembled in variables). Confirming a defect by finding it is sound; confirming its absence by
failing to find it is not. Where absence matters, execute the code path or parse the AST — which
is exactly what the three new desktop tests now do.
