# JANET Web — review loop 40 (2026-07-21)

Fable-inline synthesis + one Fable deep-dive worker on wpt. Self-review of loop-39 → **GREEN**.
Baseline: loop-39 authoritative **1329** green (confirmed).

## Self-review of loop-39 (acas bump-verdict) — GREEN
The inline worker mirror matches the pure `Get-AcasBumpVerdict` (static assert pins it); the degraded set is
matched on POST only (a degraded *pre* like `not installed → version` stays a confirmed install); `none`
(Log4j clean) is excluded; the downgrade check fires only when both parse as `[version]`; line 2075's both-`n/a`
early-return is upstream and unaffected. No profile treats `error`/`n/a`/`not installed` as a good state.
Nothing to reopen.

## Workstream: wpt deep-dive → port wpt's proven C2R fix back to acas (item35 Office-C2R slice)
A Fable worker read wpt (the most-used tool, 485KB) end-to-end. The dive's immediate actionable was that **acas
lags wpt**: wpt hardened its M365 C2R verify in loop24 (item15) — `Verified` true only when the ClickToRun key
is fresh AND `LastScenarioResult` succeeded, because C2R bumps that key on failed attempts too — but acas's
identical Office C2R verify (`:129`) still used bare mtime-recency (`<7 days`). That's the confirmed worst-case
slice of acas item35 (a failed Office update reads Verified with the OLD version, lighting the PATCHED tile on a
verify-only run).

### FIXED this loop (acas 1.11.11 → 1.11.12)
New pure `Get-AcasC2rVerified` (ported from `Get-WptC2rVerified`): Verified true only when fresh AND
`LastScenarioResult` matched success; `$false` when stale or the scenario failed; `$null` when there's no
timestamp or the result is unknown (never over-claims). `New-AcasOfficeC2RVerify`'s generated remote scriptblock
mirrors it inline (runs over WinRM), comment-linked. `Acas.C2rVerify.Tests.ps1` (10, mirrors `Wpt.C2rVerify`).
This closes the Office-C2R slice of item35; the Chrome/Edge/Java/Store acas verify slices remain (lower-risk —
they match wpt's own accepted mtime approach, whose keys aren't bumped on failed attempts the way C2R's is).

## wpt dive findings — ranked backlog (items 40–50; worker-CONFIRMED, re-verify before acting)
The systemic takeaway: wpt classifies success from the profile Script's self-reported `OK…` prefix (`:3427`), so
the honest-outcome discipline applied to kb-install (loop22/23) and C2R verify (loop24) was **never swept across
the app-update profile catalog**. (I re-verified finding 1 in-code: `:915-916` interpolates the exit code into
the OK string but never tests it — confirmed.)

- **item40 (HIGH)** — profiles self-report OK on a mere trigger / ignored native exit code → VulnPatched: M365
  Force Update & User Visible `:915-916`/`:1224-1225` (`"OK (Office update triggered, exit $ExitCode)"`, code
  never tested); Trellix `:955`/`:967` (`& $cmd ... 2>&1 | Out-Null` never throws on nonzero, catch is dead
  code → "ePO sync sent" on mere invocation); SC-trigger profiles Java/Chrome/Adobe `:1269`/`:1051`/`:1720`
  (`Invoke-CimMethod | Out-Null` discards `CCM_Application.Install` ReturnValue — the sibling `:4643` checks rv).
- **item41 (HIGH)** — app-update-verify sets `$r.Status='Verified'` unconditionally (`:3421`) regardless of
  `$res.Verified`, so Verified=No / n/a hosts count in "N ok" (`:6441`) and audit Success (`:4776`). (Note: my
  loop-40 acas C2R fix returns Verified=$false on a failed scenario — acas's verify-only path honors that via
  `Get-AcasVerifyRowStatus`; wpt's `:3421` would swallow it. wpt needs the same honoring.)
- **item42 (HIGH)** — bulk-patch treats a null WMI/CIM ReturnValue as accepted (`:1989`/`:2016`) and books a
  mere trigger as VulnPatched/Success (`:5356`) — the exact loop22/23 kb-install fix (`:2808` fails closed on
  null) never swept to bulk-patch.
- **item43 (HIGH)** — Oracle Java SC Verify = JavaSoft key mtime `<30d` (`:1312`), no version target, no
  success gate (the jvm.dll version at `:1300` is displayed, never compared). item35 class, wpt side.
- **item44 (MED-HIGH)** — clean-user-apps host Status='Success' even when every Remove-Item failed (`:3590`/
  `:3601`/`:6341`); the detail ("0 removed") is honest, the status/tally/audit are not.
- **item45 (MED, fleet-level)** — verify-and-clean deletes the product's Uninstall registry key even when
  FilesRemain (`:4192`/`:4325`) → self-blinding: the row is 'Attention' (counted failure, good) but every later
  registry-driven scan reads the host clean.
- **item46 (MED)** — Adobe Acrobat branch reports 'Removed' if ANY one GUID uninstalled (`:4298`/`:4303`);
  failing GUIDs invisible, and it `continue`s before the verify-clean files-gone check.
- **item47 (MED)** — browser-client Verify = Clients{GUID} key mtime `<14d` (`:898`), version-blind (item35
  class, wpt side; less wrong than C2R since Omaha usually only rewrites on a real install — needs confirming).
- **item48 (LOW)** — fix-java empty engine result (null row) → NOCHANGE → ok + audit Success (`:5841`).
- **item49 (LOW)** — verify-patch counts 'no SCCM client' / 'no matching updates' hosts toward "N verified"
  (`:2501`/`:6225`).
- **item50 (LOW)** — Chrome/Edge internet updater direction-agnostic: a pv downgrade during the 90s poll reads
  "OK (updated X→Y)" (`:1126`/`:1201`); raw string `-ne`, not `[version]` forward. Same class as acas item39.

### wpt GREEN surfaces (worker-verified, not findings)
kb-install (null RV fail-closed `:2808`, MECM = "Triggered (verify)" not "Installed", anchored KB match); M365
C2R Verify (the loop24 fix, mirrored); Defender/Trellix Verify (content-date, unparseable → $null); registry-fix
scan/apply; generic msiexec/EXE uninstall exit-code gating + files-gone re-check; WptScanBlock per-channel OK
(broken host → Error, never clean 0); WptAppActionBlock (rv-checked); unreachable/cred-fail/DNS-mismatch/
timeout/cancel all book their own Failure buckets.

## SECRET parity
- **SECRET parity:** the JanetSec acas fork shares `New-AcasOfficeC2RVerify` — mirror `Get-AcasC2rVerified` +
  the inline scenario-success gate. The wpt items 40–50 are parity candidates for the JanetSec wpt fork once
  each is closed here.
