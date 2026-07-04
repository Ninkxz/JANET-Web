###############################################################################
###  J.A.N.E.T. Workstation Patching Tool (WPT)
###  Joint Administration and Network Execution Toolkit
###############################################################################
###
###  Author:   Braxton Thompson | 48CS/SCOO | B.E.A.T. Contractor
###  Email:    braxton.thompson.1.ctr@us.af.mil
###  Date:     May 2026
###  Version:  6.5.22
###
###  Purpose:  MECM-driven workstation patching GUI with bulk scan/patch,
###            Deploy-Application.ps1 package push, software management,
###            KB scanning/installation, remote messaging, reboot countdown,
###            and parallel RunspacePool execution.
###
###############################################################################
###  TAB ORDER & CAPABILITIES:
###############################################################################
###
###  [Start]            - Session gating. Set credentials, acknowledge
###                        responsibility, configure package root + thread count.
###                        Must complete before accessing other tabs.
###
###  [Targets]          - Import workstation hostnames. Paste, import from TXT,
###                        or import ACAS/Nessus CSV (DNS > NetBIOS > IP priority).
###                        Remove selected. Target list shared across all tabs.
###
###  [Bulk Scan & Patch] - Scan all targets via RunspacePool. Shows online/offline,
###                        C: drive space, reboot pending, MECM updates, MECM apps.
###                        Patch selected or all needing. Reboot selected.
###
###  [Sw Mgr & Uninstaller] - Registry-based software scan on a single host.
###                        Shows Win32 (MSI/EXE) and Store apps with versions.
###                        Quick filter (Chrome, Edge, M365, Teams, Tanium, Adobe).
###                        Native uninstall with product-specific handlers for
###                        Microsoft 365 (C2R + package script) and Adobe Acrobat
###                        (RunAsPPL fix, multi-GUID sweep).
###
###  [SCCM App Manager] - Query MECM CCM_Application on a single host. Shows
###                        install state, evaluation state, percentage. Install,
###                        uninstall, reinstall, repair via CCM_Application methods.
###                        Quick filter (Chrome, Edge, M365, Teams, Tanium).
###
###  [Pkg Deploy]       - Push Deploy-Application.ps1 packages from a network
###                        share. Auto-discovers packages in the configured root.
###                        RunspacePool parallel deployment to all targets.
###
###  [KB Scanner]        - Scan all targets for installed Windows KBs (Get-HotFix).
###                        RunspacePool parallel. Filter by KB ID, host, description.
###                        KB Install section: MECM-first with MSU fallback.
###                        Trigger MECM cycles. Push & download pending updates.
###
###  [App Updater]       - Push application updates to targets. Built-in profiles:
###                        Microsoft 365 (OfficeC2RClient.exe), Windows Defender
###                        (Update-MpSignature), Chrome, Edge. Custom command option.
###
###  [Remote Message]    - Send popup messages to workstation users. Single target
###                        or all. Configurable title, body, timeout.
###
###  [60 Reboot Msg]     - Experimental countdown reboot with periodic warnings.
###                        Configurable total time, warning interval. Auto-reboot
###                        or warnings-only mode. Cancel sends notice to users.
###
###  [Reports]           - Session statistics (8 counters). Action history grid
###                        with export to CSV. Report files browser.
###
###  [Logs]              - Real-time activity log for the current session.
###
###  [About]             - Tool info, credits, and full changelog.
###
###############################################################################
###  CONFIGURATION (edit these values for your environment)
###############################################################################
###
###  $global:DefaultThreads    - Line ~146. RunspacePool thread count (1-50).
###                              Higher = faster scans, more network load.
###
###  M365 Package Share        - Line ~1353. UNC path to Microsoft 365 uninstall
###                              package (.cmd scripts). Used by Sw Mgr handler.
###                              \\msek-fs-01v\Apps\10. Patching\...
###
###  Remote Message Title      - Line ~1714. Default popup title for Remote
###                              Message tab. Currently "Message from the 48
###                              Communications Squadron."
###
###  ACAS CSV Columns          - Line ~973. Regex patterns for auto-detecting
###                              DNS Name, NetBIOS Name, IP Address columns in
###                              ACAS/Nessus CSV exports.
###
###  Quick Filter Lists        - Sw Mgr: Line ~1156. SCCM App Mgr: Line ~2747.
###                              Add/remove app names for the dropdown filters.
###
###  App Updater Profiles      - Line ~2760. Hashtable of update profiles with
###                              descriptions and scriptblocks. Add new profiles
###                              by following the existing pattern.
###
###############################################################################
###  CHANGELOG:
###############################################################################
###
###  v6.5.22 - 2026-06-06 - Multi-agent code-review fixes.
###          (1) CRITICAL: Track-Action mapped every patch/app op to dead
###              JANET -Action values ('PatchHost'/'InstallPackage'), which
###              threw at param-bind and -- swallowed by the surrounding
###              try/catch -- silently dropped EVERY patch / install / uninstall
###              / reinstall / repair centralized audit row. Remapped to the
###              2-bucket schema ('VulnPatched'); widened the success-result
###              regex to accept 'sent'/'triggered'. 'Scan'/'Reboot' stay
###              untracked (unchanged).
###          (2) Re-entrancy guards on the KBInstall / KBScan / Cleanup /
###              RegKey-Scan / RegKey-Apply drain timers: a tick that pumped
###              DoEvents via the logging helpers could re-enter itself,
###              double-counting results, calling EndInvoke on a disposed
###              PowerShell, and NRE'ing on self-teardown.
###          (3) FormClosing now stops/disposes the RegKey timers and the
###              RkScan / RkApply / RkPost / install / KB job runspaces too
###              (were leaked; a stray tick could hit the disposed RunspacePool).
###          (4) RegKey auto-reboot accepts shutdown.exe exit 1190
###              (ERROR_SHUTDOWN_IS_SCHEDULED) as success.
###
###  v6.5.21 - 2026-06-06 - Fix: the JRE version-detection helper assigned
###          to $home, a read-only PowerShell automatic variable, so the
###          whole block threw every time it ran. Renamed the local to
###          $javaHome. (The identical block in ACAS Nemesis was fixed too.)
###
###  v6.5.20 - 2026-05-28 - Tenable triage additions sourced from the
###          28 May fleet scan (~1500 hosts). Three new remediation
###          hooks land in two existing structures -- no new tabs,
###          no new globals.
###
###          (1) RegKeyFixCatalog: 'Edge_ImportSearchEngine' entry
###              for STIG EDGE-00-000022 / SV-235739r960963_rule.
###              Writes HKLM:\SOFTWARE\Policies\Microsoft\Edge
###              \ImportSearchEngine = 0 (DWord). Hits the noCCE
###              compliance finding Tenable flagged on 1489 hosts.
###              No reboot.
###
###          (2) AppUpdateProfiles: 'Windows Unquoted Service Path
###              - Remediate' enumerates HKLM\SYSTEM\CurrentControl
###              Set\Services\*, finds ImagePath values whose
###              executable contains spaces and isn't already
###              quoted, rewrites with quotes around the exe
###              portion (preserves args). Stashes the pre-edit
###              value at HKLM\SOFTWARE\JANET\WPT\UnquotedSvcPath
###              \<svc>\OriginalImagePath as a rollback breadcrumb.
###              Skips entries already well-formed. Targets Tenable
###              plugin 63155 (~322 hosts).
###
###          (3) AppUpdateProfiles: 'MSXML 4.0 - Uninstall'
###              MsiExec /x of the known MSXML 4.0 SP3 Parser +
###              Service Pack product GUIDs (32/64-bit). Pair with
###              the v6.5.19 Sw Mgr detection. Targets Tenable
###              plugin 62758 (~26 hosts).
###
###          DEFERRED this round per operator direction:
###            - Java (Tenable Oracle JRE CPUs): Oracle's binary
###              is SSO-gated post 8u201; the only clean fleet
###              move is an Adoptium / MS OpenJDK swap, which is a
###              project, not a WPT button.
###            - .NET Core EoL cleanup (plugin 172179): a working
###              dotnet-core-uninstall MSI staging profile was
###              built and then pulled back out for now. If it
###              returns, the controller-side Copy-Item -ToSession
###              staging pattern from the v6.5.3 Log4j profile is
###              the template; mirror $Log4jSrcPath as a
###              $DotnetSrcPath wrapper param and substitute a
###              $msiPath literal. Both of these are slated for
###              the ACAS Nemesis tool instead.
###
###          SECOND BATCH (28 May, sourced from the ESS ALL-UEs
###          scan -- 908 hosts / 3092 findings):
###
###          (4) RegKeyFix framework gains an OrBits value mode.
###              A value def can now carry { OrBits = <int> }
###              instead of { Expected = <int> }; scan compliance
###              becomes (current -band OrBits) == OrBits and apply
###              reads the current value, bitwise-ORs the bits, and
###              writes it back -- preserving any bits already set
###              instead of clobbering them. $getDefsArrayRk carries
###              OrBits through to the scan/apply scriptblocks; both
###              the RegKeyScanBlock compliance check and the
###              RegKeyApplyBlock write + readback honor it. Expected
###              mode is unchanged for every other catalog entry.
###
###          (5) BHI Remediation BUG FIX (CVE-2022-0001, plugin
###              302873, 575 hosts). The catalog entry was writing
###              FeatureSettingsOverride = 8264 (0x2048) via a flat
###              overwrite. 0x2048 does NOT contain the BHI bit
###              (0x800000), so the old fix (a) never cleared the
###              plugin and (b) would have STRIPPED the BHI bit from
###              any host that already had 0x800000 set. The 28 May
###              scan proved (a): 43 hosts at exactly 0x2048 were
###              still flagged. Switched the override value to the
###              new OrBits mode (OrBits = 0x800000) so it sets the
###              BHI bit while preserving the existing Spectre/
###              Meltdown bits: 0x48 -> 0x800048 (Rec 3, HT on),
###              0x2048 -> 0x802048 (Rec 2, HT off), 0x800000 stays
###              as-is. Mask stays Expected = 3. Reboot still
###              required for the kernel to read the new value.
###
###          (6) AppUpdateProfiles: 'Office VBA Project Access -
###              Disable (AccessVBOM)' (plugin 123461, ~17 hosts).
###              Walks every loaded HKEY_USERS hive (real S-1-5-21-*
###              SIDs, skipping *_Classes), every Office 14.0/15.0/
###              16.0 install, the common VBA apps (Word/Excel/
###              PowerPoint/Outlook/Access/Publisher), and flips
###              AccessVBOM 1 -> 0 (the Office secure default; does
###              NOT disable macros). Originals stashed at
###              HKLM:\SOFTWARE\JANET\WPT\OfficeVBOM\<SID>\<ver-app>.
###              Scope is loaded hives only (matches the scanner);
###              re-run after off-line users log on. Verify acts as
###              a dry run -- lists which SID/app pairs are hot.
###
###          DEFERRED (batch 2): Oracle Java SE CPUs (315 findings
###          across 9 plugins) -- same SSO-gated-installer problem
###          as batch 1; the clean move is an Adoptium/MS OpenJDK
###          swap, a project not a button. NVIDIA GPU driver (97)
###          left alone -- driver pushes are too risky for a blanket
###          script. SSL self-signed / untrusted cert (312) are
###          per-service cert problems, not blanket-scriptable.
###
###  v6.5.19 - 2026-05-28 - Sw Mgr tab extended to surface MSXML
###          across every place Tenable plugin 62758 ("Microsoft
###          XML Parser (MSXML) and XML Core Services Unsupported")
###          actually hits, not just the standard Add/Remove keys
###          the existing scan reads:
###            1) Existing 3 Uninstall hives (HKLM 64-bit, HKLM
###               WOW6432Node, HKCU) -- already covered.
###            2) NEW: KB-style updates under
###                 HKLM:\SOFTWARE\Microsoft\Updates\Microsoft XML Core Services *\KB*
###               registered as Type='KB' so they dispatch to a
###               wusa /uninstall handler instead of msiexec.
###            3) NEW: Orphan COM DLLs --
###                 C:\Windows\System32\msxml*.dll
###                 C:\Windows\SysWOW64\msxml*.dll
###               registered as Type='DLL' with the full path
###               stuffed into UninstallString. These are the
###               leftover-from-a-partial-removal artifacts that
###               Tenable scans the filesystem for; no Uninstall
###               key, so previous WPT versions couldn't see them.
###               MSXML 6 OS-bundled DLLs (msxml6.dll on Vista+)
###               are filtered out -- the OS owns them and SFC
###               will restore them; Type='DLL (OS-protected)'
###               surfaces them read-only so operators don't try.
###          Quick-filter dropdown gains 'MSXML / XML Core Services'
###          which matches against Name like *MSXML* / *XML Parser* /
###          *XML Core Services* / *XML 4* / *XML 6*.
###          Uninstall click handler gets a per-type dispatch ahead
###          of the existing MSI/EXE/Store branch:
###            Type='KB'                    -> wusa /uninstall /kb:<n> /quiet /norestart
###            Type='DLL'                   -> stop dependent svcs,
###                                            regsvr32 /u /s <path>,
###                                            takeown + icacls grant,
###                                            Remove-Item -Force
###            Type='DLL (OS-protected)'    -> refuse with explanation
###          Standard MSI MSXML 4.0 SP3 entries fall through the
###          existing MSI branch unchanged (msiexec /x {GUID} /qn).
###          The KB / DLL / OS-protected types are colorized in the
###          grid (Cyan / Warning / Dim) so they stand out from the
###          MSI/EXE/Store rows.
###
###  v6.5.18 - 2026-05-27 - Log4j updater + Finder tightened against
###          a real Tenable scan output. Test host (msekl-9pl6cf3)
###          had log4j-api/core 2.17.2 and 2.25.3 jars sitting in
###          Backup_<ts>\ subdirs left behind by previous runs of
###          the v6.4.2 updater; Tenable flagged them because its
###          plugin doesn't care about path -- only filename version.
###          v6.5.17's Finder classifier was using >= 2.17 = Patched
###          (the upstream Log4Shell line) so those backups showed
###          as green even though Tenable was screaming. Two fixes:
###            1) Get-Log4jVulnState bar raised from "2.17+" to
###               "2.25.4 exactly" so Finder reports match Tenable
###               plugins 306549/306550 (the bar the existing
###               updater was already chasing).
###            2) 'Apache Log4j - Replace Vulnerable Jars' App
###               Updater profile Script + Verify rewritten to
###               recurse under each target lib path instead of
###               only enumerating its top level. Live jars (the
###               ones the bundled service has open) still get the
###               stop-service + back-up-then-replace flow. Stale
###               jars found inside any \Backup_* subdir get
###               deleted in place (no point creating a Backup of
###               a Backup -- recursive backups were the bug). Any
###               file already named log4j-(api|core)-2.25.4.jar
###               is left alone whether it's live or archived, so
###               re-runs are idempotent and don't create new
###               Backup_<ts>\ folders unless something genuinely
###               needs swapping.
###          Verify scriptblock now also recurses so its "STILL-
###          VULNERABLE" detail string surfaces the backup-folder
###          jars that v6.4.2-v6.5.17 hid behind a non-recursive
###          Get-ChildItem.
###
###  v6.5.17 - 2026-05-27 - New "Log4j Finder" tab. Fans out to each
###          target via RunspacePool (same pattern as Bulk Scan / KB
###          Scanner) and enumerates `log4j-*.jar` under common Java
###          install roots: C:\Program Files, C:\Program Files (x86),
###          C:\ProgramData, C:\Users, C:\Java, C:\jdk*, C:\jre*,
###          C:\opt, C:\apps. Recursive Get-ChildItem with -Filter and
###          -EA SilentlyContinue; per-host result is a list of
###          @{ Path; Component; Version; LastWriteTime; SizeKB }.
###          Version is parsed from the filename via the regex
###          log4j-(api|core|1\.2|to-slf4j|jul|...)-(\d+\.\d+\.\d+)\.jar
###          (no JNDI class probe, no SHA-256 hashing -- v6.5.17 is a
###          discovery-only pass; the existing "Apache Log4j - Replace
###          Vulnerable Jars" App Updater profile remains the
###          remediation path for the two known target install
###          locations).
###          UI: header bar (Scan / Cancel / Export CSV / target count
###          / progress), text filter, host roll-up grid (Host /
###          Status / Jar Count / Vulnerable? / Notes), double-click
###          drill-down dialog showing per-jar Path + Component +
###          Version + LastWriteTime + SizeKB. Row colorization:
###          green = no jars, gold = jars present but all 2.17+,
###          red = 1.x or pre-2.17 2.x present. Vulnerability
###          classification is free (purely derived from the parsed
###          version string -- no extra disk I/O); still labelled
###          "advisory" since the deterministic check is JndiLookup.class
###          presence, not version.
###          Sidebar entry uses the Shield icon, slotted between Reg
###          Key Fixes and Remote Message.
###          $JanetWptVersion bumped to 6.5.17 and the sidebar brand
###          label now binds to that variable instead of the stale
###          'v6.5.14' literal that lingered through 6.5.15 / 6.5.16.
###
###  v6.5.16 - 2026-05-14 - Close-tool dialog matches the ACAS Nemesis
###          "Submit Logs + Close Tool" prompt. Show-WptClosingNotesDialog
###          retitled and widened (640x560) with a new header block above
###          the notes textbox:
###            * Operator: <EDIPI - DisplayName>
###            * Session summary: N host(s) touched, N vuln(s) patched,
###              N failure(s)  (live values pulled off the JANET session)
###            * Log share / Local only: <LogDir>  (amber on local fallback)
###            * "Submitting will flush these artifacts to the share:"
###              followed by a 4-bullet list naming the WPT_<user>_<ts>.log,
###              TouchedHosts_<YYYY-MM>.csv, JANET <YYYY-MM>_detail.csv /
###              <YYYY-MM>_usage.csv, and the legacy WPT-UsageV2-<YYYY-MM>.csv.
###          Three-button outcome semantics unchanged — buttons renamed
###          'Submit Logs + Close' / 'Submit (skip notes)' / 'Cancel Close'
###          but still flow through Invoke-WptClosingFlow as Submit / Force
###          / Cancel exactly as before, and the return shape stays
###          { Choice; Notes }.
###
###          Per-admin log folder lives on the share, like
###          ACAS Nemesis. New $script:WptLogShare =
###          \\dm-tn-01\sh-usafe-automation$\JANET\Logs\WPT plus a
###          Resolve-WptLogTarget write-probe (sentinel create + delete
###          + orphan sweep) at the LOGGING region. When the probe wins,
###          the per-session .log and the per-operator monthly TouchedHosts
###          CSV land at:
###            \\dm-tn-01\sh-usafe-automation$\JANET\Logs\WPT\
###                <EDIPI> - <DisplayName>\WPT_<user>_<ts>.log
###                <EDIPI> - <DisplayName>\TouchedHosts_<YYYY-MM>.csv
###          which sit next to the centralized <YYYY-MM>_detail.csv that
###          the JANET LOGGING BLOCK already drops there. Lead can pivot
###          "what hosts did operator X touch this month" from a single
###          share folder without grepping daily session logs, identical
###          to the ACAS Nemesis layout.
###          Fallback: when the share is unreachable or write-denied, the
###          tool keeps using the local $global:LogDir under
###          <JANET-root>\Logs\WPT\ (or <JANET-root>\Tools\Logs\ as a
###          last resort), so locked-down workstations don't break.
###          TouchedHosts filename normalized: WPT_TouchedHosts_<YYYY-MM>.csv
###          -> TouchedHosts_<YYYY-MM>.csv (per-tool subfolder makes the
###          old "WPT_" prefix redundant; matches Nemesis exactly).
###
###  v6.5.15 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
###          *_usage*.csv so schema-rotation sister files (created when the
###          legacy file is persistently locked) are drained on next launch
###          instead of stranded.
###
###  v6.5.14 - 2026-05-08 - JANET centralized-logging schema cleanup
###          (single SessionEnd rollup row; Snapshot rows retired)
###          and the WPT-themed Closing Notes prompt rolled across
###          the suite.
###
###  v6.5.13 - 2026-05-07 - App Updater + Usage Log tab layout sweep
###          (same pattern as the v6.5.11 Heal pass + v6.5.12 WinRM
###          pass). Both tabs had the New-Lbl title-clip bug; both now
###          carry explicit -H 28 on the title labels and the Sub
###          labels are trimmed 1200 -> 1000.
###
###          App Updater:
###            - $tabAppUpd2.Size: hard-coded (1170, 660) -> $tc.Size.
###              The 1170 width didn't match the TabControl's actual
###              1034 design width, so $grpAU2Prof + $lblAU2Sub (no
###              Right anchor) clipped past the right edge once docked.
###            - $grpAU2Prof: trimmed 1170 -> 1002 + Top,Left,Right
###              anchor so the group stretches with the form.
###            - $script:lblAU2Desc: trimmed 1140 -> 982 +
###              Top,Left,Right anchor.
###            - $script:txtAU2Custom: trimmed 1050 -> 902.
###            - $script:dgvAU2: trimmed 1140 -> 1002.
###            - $script:lblAU2Prog: trimmed 334 -> 200 with
###              AutoEllipsis + MiddleLeft alignment.
###            - $grpAU2Log + $script:rtbAU2Log: trimmed 1140 -> 1002 /
###              1120 -> 982.
###
###          Usage Log:
###            - $tabUsage: pre-sized to $tc.Size (was unsized, so
###              anchored children captured offsets against the default
###              200x100 -- same root cause as the Heal/WinRM/close-button
###              regressions).
###            - $grpUsageSession: trimmed 720 -> 560 (with internal
###              labels 680 -> 520) to make horizontal room for ACTION
###              COUNTS at the right.
###            - $grpUsageCounts: moved X 750 -> 584 (right of the
###              trimmed Session group with a 10px gap) and anchored
###              Top,Right so it tracks the right edge on form resize.
###              Width 434 -> 432 for a clean 14px right margin.
###            - $grpUsageLog: widened 720 -> 1002, moved Y 330 -> 376
###              (now sits cleanly below ACTION COUNTS instead of
###              column-overlapping it), and anchored
###              Top,Left,Right,Bottom so it stretches with the form
###              instead of leaving a wide empty band on the right.
###          PATCH bump: AppUpdater + Usage tab visual regressions.
###
###  v6.5.12 - 2026-05-07 - WinRM Setup tab layout fixes (same pattern
###          as the v6.5.11 Heal tab pass):
###            1. $lblWinRMTitle clipping at the top -- added explicit
###               -H 28 to fit the 13pt Cascadia Mono Title font.
###            2. $tabWinRM was at WinForms' default 200x100 while
###               anchored children were added, so Top,Right offsets
###               for $script:dgvWinRM + $grpWinRMLog captured against
###               the tiny parent. Once $tabWinRM docked into $tc and
###               grew to ~1030 wide, the grid + log group landed
###               several hundred pixels past the visible right edge.
###               Fix: $tabWinRM.Size = $tc.Size BEFORE adding
###               children.
###            3. Design widths trimmed to fit within tabWinRM design
###               width (1030): dgvWinRM 1170 -> 1002, grpWinRMLog
###               1170 -> 1002, rtbWinRMLog 1150 -> 982, lblWinRMSub
###               1200 -> 1000.
###            4. $script:lblWinRMProg trimmed (460 -> 200) and now
###               anchored Top,Right with AutoEllipsis + MiddleRight
###               so it sits at the row's right edge regardless of
###               form size and truncates long messages cleanly.
###          PATCH bump: WinRM-tab visual regressions.
###
###  v6.5.11 - 2026-05-07 - Heal tab layout fixes:
###            1. $lblHealTitle was clipping at the top -- New-Lbl
###               defaulted -H to 18 while -Font $fn.Title (13pt bold
###               Cascadia Mono) needs ~28px to render the full glyph
###               height. Added explicit -H 28.
###            2. Same anchor regression as the v6.5.9 close-button fix:
###               $tabHeal stayed at WinForms' default 200x100 while
###               anchored children were added, so Top,Right offsets
###               for $script:dgvHeal + $grpHealLog captured against
###               the tiny parent. Once $tabHeal docked into $tc and
###               grew to ~1030 wide, those offsets pushed the grid +
###               log group several hundred pixels past the visible
###               right edge. Fix: $tabHeal.Size = $tc.Size BEFORE
###               adding children, so anchors capture against the real
###               TabPage geometry.
###            3. Design widths trimmed to fit within the design tabHeal
###               width (1030): dgvHeal 1170 -> 1002, grpHealLog 1170
###               -> 1002, rtbHealLog 1150 -> 982. Anchors still grow
###               them with the form on resize.
###            4. $script:lblHealProg now anchored Top,Right with
###               AutoEllipsis + MiddleRight alignment so it sits at
###               the right edge of the row regardless of form width
###               and truncates long completion messages cleanly
###               instead of clipping past the visible area.
###          PATCH bump: Heal-tab visual regressions.
###
###  v6.5.10 - 2026-05-07 - Closing-notes UX overhaul. Three issues with
###          the v6.5.8/6.5.9 flow:
###            1. The notes dialog only fired when $global:SessionStarted
###               was true, so an operator who opened the tool, looked
###               around, and clicked Close Tool got no chance to leave a
###               note for the next session.
###            2. The dialog ran from inside FormClosing, _after_ the
###               Legacy cleanup handler had already disposed timers,
###               jobs, and RSPool. Picking 'Return to Tool' (Cancel) at
###               that point couldn't reverse the teardown -- the form
###               stayed open but in a broken state.
###            3. Notes never made it into $global:AuditLogPath. They
###               only landed in the WPT CSV (Publish-WptUsageCsvRow)
###               and the JANET centralized rollup, both of which are
###               session-gated.
###          Fix: moved the dialog into the Close Tool click handler.
###          Cancel ('Return to Tool') now bails before any teardown.
###          Submit/Force stash the outcome on $script:WptCloseOutcome
###          and proceed to $f.Close(). The FormClosing handler picks
###          the outcome up and writes it to the audit log file via
###          Write-AuditLog -Action 'ClosingNotes' (always, regardless
###          of session state) plus the WPT CSV + JANET session close
###          (still session-gated, those rows are session-rollup).
###          PATCH bump: closing-flow correctness + audit reach.
###
###  v6.5.9  - 2026-05-07 - Fix: Close Tool button (and the live-pulse
###          + "live" label) were invisible in v6.5.8 because they were
###          added to $topBar BEFORE $topBar was parented to the form.
###          With $topBar still at its default 200x100 size, WinForms
###          captured a large negative right-anchor offset for each
###          right-anchored child, and once $topBar docked to the form's
###          true client width, the children landed several hundred
###          pixels off the right edge of the visible window. Reordered
###          the TOP STRIP region so $f.Controls.Add($topBar) runs first
###          and the children are positioned against
###          $topBar.ClientSize.Width (now correct), so the red Close
###          Tool button renders where it was always meant to: top-right,
###          immediately to the left of the live indicator. Click flow
###          unchanged -- still routes through Set-JanetAllowClose +
###          $f.Close(), which fires the FormClosing handlers that pop
###          Show-WptClosingNotesDialog and append the operator's notes
###          to the audit log via Publish-WptUsageCsvRow +
###          Stop-JanetSession. PATCH bump: visibility regression fix.
###
###  v6.5.8  - 2026-05-07 - Close Tool button moved to top-right of the
###          form. Was sitting at the bottom of the sidebar userBlock
###          (below User / Status / Host) -- discoverability was weak
###          (below the scrollable nav) and at certain window heights it
###          overlapped the user-info labels. Now lives in the TOP STRIP
###          region anchored Top,Right, just left of the "live"
###          heartbeat indicator. Click handler unchanged (still calls
###          Set-JanetAllowClose + $f.Close()). Sidebar userBlock
###          AddRange shrunk from 4 controls (lblOpName, lblOpState,
###          lblOpHost, btnCloseTool) to 3.
###          Also caught up the 6 user-facing version strings that had
###          drifted across earlier between-session edits -- file
###          header / $JanetWptVersion / form title / Start-tab Version
###          label (was stuck at 6.3.0) / sidebar brand version / boot
###          log -- all now read v6.5.8 consistently.
###          PATCH bump: UI relocation + version-string cleanup.
###
###  v6.5.7  - 2026-05-06 - Sister-CSV spam fix in JANET logging.
###          Operator hit "WARNING: JANET schema rotation failed; routing
###          rows to sister CSV: ...2026-05_usage.r<unix>.csv" once per
###          audit row when the share's legacy 2026-05_usage.csv was
###          locked by a peer process. The redirect path was generating
###          a fresh <base>.r<stamp>.csv per call (stamp = current Unix
###          second), so each row produced a NEW sister file — dozens
###          of near-empty sisters piling up in the share's Logs folder.
###          Fix: before creating a sister, scan <Logs>\<base>.r*.csv
###          for one whose first line matches the current header. If
###          found, reuse it silently. Only mint + warn when none
###          exists. Net effect: at most ONE sister CSV per (operator,
###          schema) pair instead of one per call, and the warning
###          fires once instead of every audit write.
###          Same fix applied to ACAS Nemesis Tool 1.8.11.
###
###  v6.5.6  - 2026-05-06 - Apache Log4j profile: 2.25.3 -> 2.25.4.
###          Updated $newApi / $newCore constants from log4j-api/core
###          -2.25.3.jar to -2.25.4.jar across the App Updater Apply
###          handler, Apply2 handler, profile script literal, profile
###          Desc, Verify regex, Verify Detail string, and the App
###          Updater "Drop ... at this path" hint.
###          The 2.25.4 release adds fixes for plugins 306549
###          (XmlLayout invalid output, CVE-2026-34480) and 306550
###          (SSL hostname verification bypass, CVE-2026-34477) on
###          top of 282519 (MitM, CVE-2025-68161). All three plugins
###          will now clear via the profile's Verify path.
###          Operators must drop log4j-api-2.25.4.jar +
###          log4j-core-2.25.4.jar at the source path (default
###          <JANET-root>\Tools\Packages\Log4j\NewFiles\) before
###          running. Old 2.25.3 jars on the share will produce a
###          "FAIL: source jar missing on share" up front rather than
###          stopping a service.
###
###  v6.5.5  - 2026-05-06 - App Updater: Cancel button.
###          New $script:btnAU2Cancel between Apply and Select All
###          (Danger color, disabled by default). Enabled while a
###          Verify or Apply run is in progress; click prompts a
###          confirm dialog, then:
###            * Apply path: PowerShell.Stop() + Dispose() on every
###              entry in $script:AU2Jobs, stops + disposes the
###              drain timer, marks any 'Applying...' row as
###              'Cancelled', re-enables Apply.
###            * Verify path: sets $script:AU2VerifyCancelled which
###              the Verify foreach checks at the top of every
###              iteration. Mid-Invoke-Command calls aren't
###              interruptible but the DoEvents pump inside the
###              loop fires the click handler, so the flag is set
###              before the next iteration starts and the loop
###              breaks cleanly.
###          Audit row 'AppUpdate / Cancelled / stopped=N' written
###          on cancel so the Nemesis-style TouchedHosts CSV
###          records the operator action.
###          Button row Y unchanged at 440; positions shifted right
###          to fit Cancel at X=478 (Select All -> 586, Deselect
###          All -> 694, lblAU2Prog -> 816 W=334).
###
###  v6.5.4  - 2026-05-06 - Log4j default path: Tools\Packages, not
###          root\Packages. The fleet convention is
###          <JANET-root>\Tools\Packages\Log4j\NewFiles\ — Packages\
###          is a sibling of WorkstationPatchingTool_*.ps1 inside
###          the Tools folder, NOT one level up next to Tools\.
###          v6.5.2's resolver did Join-Path on Split-Path
###          $global:ScriptDir -Parent, which walked up out of
###          Tools\ before joining 'Packages\Log4j\NewFiles' — wrong
###          spot. Now joins directly onto $global:ScriptDir.
###          Operator-typed overrides unaffected.
###
###  v6.5.3  - 2026-05-06 - Log4j: stage jars over the session.
###          v6.5.2's path-override approach interpreted the textbox
###          as a remote-side path: the swap script ran on the
###          target and called Test-Path against it. That works
###          only when the remote can reach the path itself —
###          fails when the path is a controller-local one (e.g.
###          C:\Users\<edipi>\Documents\Code\J.A.N.E.T\Packages\
###          Log4j\NewFiles) or a UNC the remote can't double-hop
###          authenticate to.
###          Fix: textbox is now interpreted as a CONTROLLER-side
###          path. The Apply handler pre-validates the jars exist
###          there from THIS workstation. The runspace wrapper
###          (now using New-PSSession + Invoke-Command -Session
###          instead of one-shot Invoke-Command -ComputerName)
###          opens a session, mkdirs C:\Windows\Temp\janet-log4j-
###          stage-<guid>\ on the remote, Copy-Item -ToSession
###          pushes both jars over the authenticated session, then
###          regex-substitutes the remote stage dir into the
###          script's $sourceShare literal before invoking. The
###          finally block tears down the stage dir on the remote
###          regardless of swap outcome.
###          Result: Log4j Apply works whether WPT runs from local
###          disk, a UNC share, or a mapped drive — operator just
###          points the textbox at where the jars live on THEIR
###          machine. No more remote-side share access needed.
###
###  v6.5.2  - 2026-05-06 - Log4j profile: operator-overrideable
###          source path. Default no longer hardcoded to
###          \\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\
###          NewFiles — now auto-resolves to <JANET-root>\Packages\
###          Log4j\NewFiles based on the WPT script location, so
###          the path follows wherever JANET is installed. New
###          $global:Log4jDefaultSource exposes that resolved path.
###          The App Updater tab's existing Custom Command textbox
###          is now dual-purpose: when the Log4j profile is picked,
###          the label switches to "Jar source:" and the box pre-
###          fills with $global:Log4jDefaultSource. Operator can
###          edit it before clicking Apply. The Apply handler does
###          a single-quote-safe regex substitution on the registry
###          scriptblock to bake the operator's path in before
###          [ScriptBlock]::Create. Empty-path guard prompts the
###          operator instead of falling silently to the embedded
###          fallback.
###
###  v6.5.1  - 2026-05-06 - App Updater log: scroll fix.
###          Operator couldn't scroll back through the App Updater
###          log to read older entries. Two issues:
###          (1) BorderStyle 'None' rendered the scroll bar
###              against the near-black OutputBg with matching
###              color — effectively invisible. Same fix the
###              Cleanup tab applied in v6.1.7. Now FixedSingle.
###          (2) AU2Log called ScrollToCaret() on every line, so
###              while a Verify/Apply was emitting output, every
###              new line yanked the view back to the bottom and
###              defeated any manual scroll-up. Now uses a Win32
###              GETSCROLLINFO probe to detect whether the
###              operator is parked at the tail before appending;
###              auto-follows only if so. Standard chat-window
###              "follow tail unless I scrolled up" pattern.
###          Also: ScrollBars 'Both' (was 'Vertical') — WordWrap
###          is off so long lines need horizontal scrolling too.
###
###  v6.5.0  - 2026-05-06 - App Updater consolidation.
###          Legacy "App Updater" tab removed. The "App Updater v2"
###          tab is now the single "App Updater", with every Legacy
###          capability ported in:
###          (1) Custom Command pseudo-profile + textbox — pick
###              "Custom Command" from the profile combo and the
###              textbox accepts free-form PowerShell. Validated as
###              a scriptblock at apply time. Verify is unavailable
###              for Custom Command (no canonical state to query).
###          (2) TCP reachability probe (5985 -> 445, 1.5s each)
###              before every Invoke-Command on Verify and Apply
###              paths. Unreachable hosts fail fast (~1.5s) instead
###              of stalling on the WSMan default ~3-minute timeout.
###          (3) -SessionOption $global:WSManOpt on Verify;
###              equivalent New-PSSessionOption in the Apply
###              wrapper runspace (operation 180s / open 15s /
###              cancel 5s / idle 60s).
###          (4) Per-host audit fan-out — Write-AuditLog with
###              -Action 'AppUpdate' -Target <host> on every
###              completion. Feeds the Nemesis-style TouchedHosts
###              CSV from v6.4.0; previously only an aggregate
###              'AppUpdate2 / Started' row hit the audit log.
###              Track-Action also renamed AppUpdate2 -> AppUpdate.
###          (5) Auto-refresh on tab enter — populates the grid
###              from $global:ComputerList if it's empty (matches
###              the Cleanup tab's Add_Enter pattern).
###          Sidebar entry "App Updater v2" removed. Pre-existing
###          $tabUpdater variable name retired. UsageSummary mapping
###          keeps the AppUpdate2 -> AppUpdate alias so older
###          monthly CSV rows still aggregate cleanly.
###
###  v6.4.3  - 2026-05-06 - App Updater v2: anchor + layout fix.
###          The Verify Selected / Apply to Selected / Load Targets
###          button row was sliding off the bottom of the tab page on
###          smaller monitors and at non-maximized form sizes — the
###          operator had to manually resize the form to bring the
###          row back into view.
###          Root cause: the AU2 tab page was never pre-sized before
###          its child controls' Anchor properties were captured. At
###          Controls.AddRange time the TabPage was still at WinForms
###          default (200x100), so 'Bottom' anchors stored negative
###          distances and bottom-anchored controls landed off-screen.
###          The button row also had no Anchor at all (defaulted to
###          Top,Left), pinning it to a fixed Y from the top.
###          Fix: pre-size $tabAppUpd2 to (1170, 660) up front. Anchor
###          dgvAU2 Top,Left,Right,Bottom so the grid grows. Anchor
###          every button + lblAU2Prog Bottom,Left so the row sticks
###          to the form bottom. Anchor $grpAU2Log Bottom,Left,Right
###          (was Top,Left,Right,Bottom) so the log stays a fixed-
###          height bar at the bottom instead of stretching over the
###          buttons.
###
###  v6.4.2  - 2026-05-06 - App Updater v2: Apache Log4j profile.
###          Port of Log4J_Plugin_282519 v2.ps1 (Code/Log4j Mitm/) into
###          the App Updater v2 profile registry. Replaces vulnerable
###          log4j-api-2.* / log4j-core-2.* jars with 2.25.3 in the two
###          paths the original script targets — HID Global Credential
###          Management Client + Adobe Experience Manager Forms
###          Designer. Stops the bundled service before the swap, backs
###          up old jars to a Backup_<ts> subdir, copies new jars from
###          a UNC source share (default
###          \\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles),
###          restarts the service in a finally block so a failed swap
###          doesn't leave the service down. Verify reports per-host
###          jar inventory and a Verified flag that's true only when
###          every jar in the target paths is exactly 2.25.3.
###          Drop the two replacement jars at JANET\Packages\Log4j\
###          NewFiles\ on the AFNET automation share before running
###          the profile. Source jars in this repo at Code/Log4j Mitm/
###          NewFiles/ for reference.
###
###  v6.4.1  - 2026-05-05 - Cleanup tab: hardened manual delete tier.
###          Office vNext license entitlement files
###          (AppData\Local\Microsoft\Office\Licenses\EXCatalog*) use
###          base64 UTF-16 names whose full path can exceed Win32
###          MAX_PATH (260 chars), causing Remove-Item -Recurse to
###          abort mid-walk with "Could not find a part of the path".
###          A separate failure mode: ACLs the .adw account can't
###          traverse without taking ownership first.
###          Manual tier now does, in order: takeown /R + icacls
###          /grant *S-1-5-32-544:(F) /T -> Remove-Item -Recurse ->
###          cmd `rd /s /q` -> robocopy /MIR with empty source dir
###          (long-path-native). The ProfileList SID-key removal is
###          attempted unconditionally so a profile detaches from
###          Windows' registry view even if a few inert bytes remain
###          in the folder. Result line gains a "Manual=partial(key-
###          only)" status for that case.
###
###  v6.4.0  - 2026-05-05 - ACAS Nemesis-style per-operator logging.
###          Logs/ now contains a "<EDIPI> - <DisplayName>" subfolder
###          per operator (resolved via Get-JanetOperatorIdentity, AD
###          displayName lookup with three-strategy fallback). The
###          session WPT_<user>_<ts>.log file lives in that subfolder.
###          Aggregate WPT-UsageV2-<YYYY-MM>.csv stays at LogDir root.
###          New WPT_TouchedHosts_<YYYY-MM>.csv per-operator CSV: every
###          Write-AuditLog call with a real -Target (any value other
###          than 'N/A') fans out a structured row matching Nemesis's
###          TouchedHosts schema (Timestamp, Operator, Edipi, SessionId,
###          SourceHost, Action, TargetHost, Result, Detail). Schema
###          alignment lets a lead pivot WPT and Nemesis activity in
###          one CSV join. Cleanup tab profile delete now does a
###          three-tier fallback (WMI .Delete -> Remove-CimInstance ->
###          manual ProfileList SID-key + folder removal) so empty-
###          message WMI exceptions on Win10/11 stop blocking removals.
###          Reports tab + Open Folder button point at the per-user
###          subfolder instead of the flat Logs root.
###
###  v6.3.0  - 2026-05-01 - Reg Key Fixes tab + WinRM bootstrap
###          hardening (Ninkxz/WinRM-fix + Ninkxz/RegKeyFixes-BHI ports).
###
###          (1) New "Reg Key Fixes" tab: catalog-driven registry-value
###          remediation framework. Ships with BHI Remediation
###          (CVE-2022-0001) entry that writes
###          FeatureSettingsOverride=8264 + FeatureSettingsOverrideMask=3
###          under HKLM\...\Memory Management. Per-host scan, apply, and
###          verify run through the runspace pool with the same drain-
###          timer pattern as Bulk Scan. Status semantics: Patched /
###          Vulnerable / Drifted / Unreachable. Optional auto-reboot
###          1h after apply uses the scheduled-task-as-logged-in-user
###          notify pattern from Remote Message. Add new fixes by
###          appending entries to $global:RegKeyFixCatalog.
###
###          (2) WinRMBootstrapBlock hardened: 2-attempt DCOM connect
###          (RPC ephemeral-port flake on busy AFNET subnets),
###          -skipNetworkProfileCheck on quickconfig (CRITICAL: without
###          it, quickconfig silently refuses to add the firewall rule
###          when any NIC is on the Public profile -- common on laptops
###          post-VPN -- so 5985 stays closed), and a 30s post-probe
###          poll budget instead of one short probe.
###
###          (3) New "Repair WinRM" button on Bulk Scan tab: bootstraps
###          WinRM via DCOM on selected rows whose Online cell shows
###          'No'. Online hosts are skipped. Same path as the WinRM
###          Setup tab but operates inline against the bulk grid.
###
###  v6.2.6  - 2026-04-29 - Bulk Scan host drill-down + dual-channel
###          update detection. Two changes shipped together:
###
###          (1) Direct Windows Update Agent scan added to ScanBlock.
###          The previous single-source scan (CCM_SoftwareUpdate) only
###          surfaced updates SCCM had a deployment for; machines pulling
###          straight from WSUS / Microsoft Update showed as "Current"
###          even when a real Windows Update was pending. Fix: parallel
###          query via Microsoft.Update.Session COM
###          ("IsInstalled=0 and IsHidden=0 and Type='Software'"). Result
###          lands in a new WuNames[] / WuOK pair on the scan hashtable.
###          Bulk grid now has a "WU" column (logical index 9, displayed
###          right after MECM via DisplayIndex=6). 'Updates' header
###          relabeled to 'MECM' for channel clarity. OperationTimeout
###          bumped 30s -> 180s because WUA search can legitimately take
###          30-90s on a healthy box. Select-With-Updates and Patch-All-
###          Needing now fire on either MECM or WU pending counts.
###
###          (2) Per-host drill-down inspector. Double-click any scanned
###          row (or click the new "Host Details" button) to open a modal
###          inspector that lists MECM updates / direct WU updates / app
###          updates in three sections, with drive %, last boot, and
###          reboot state on the header. Copy-to-Clipboard and Export-CSV
###          on the inspector both include all three channels (CSV gets
###          a Channel column with values MECM / WU / App / None). Open-
###          App-Manager button hands off to Show-AppManager. Offline
###          rows also stash their result on $row.Tag so the inspector
###          works for unreachable hosts. New function: Show-HostScanDetails.
###
###  v6.2.4  - 2026-04-29 - Stop the Reboot Countdown format-error spam.
###          Line ~5576's countdown label updater used
###          "{0:D2}:{1:D2}:{2:D2}" -f [Math]::Floor($remaining.TotalHours),
###          $remaining.Minutes, $remaining.Seconds. Problem: D2 only works
###          with integer types and [Math]::Floor() returns a [double]. PS
###          5.1 threw "Error formatting a string: Format specifier was
###          invalid." every timer tick (every 1 second) for the entire
###          countdown duration -- noise but not a logic bug. Fixed by
###          casting all three values with [int]:
###            "{0:D2}:{1:D2}:{2:D2}" -f
###                 [int][Math]::Floor($remaining.TotalHours),
###                 [int]$remaining.Minutes,
###                 [int]$remaining.Seconds
###          Reboot countdown logic itself was already working correctly
###          (warnings deliver, timer expires, Restart-Computer fires) --
###          this just kills the cosmetic exception flood. PATCH bump.
###
###  v6.2.3  - 2026-04-27 - Reboot warnings actually deliver now.
###          Send-RebootWarning's $warnSB and the Cancel countdown's
###          $cancelSB were silently failing on a chunk of endpoints.
###          Three reasons, all fixed by mirroring the proven Remote
###          Message scriptblock pattern:
###            1. No try/catch inside the remote scriptblock. If
###               anything threw on the target (no logged-in user,
###               Register-ScheduledTask refused, etc.) the caller
###               saw a generic Invoke-Command error - or in the
###               "no user logged in" path, an early `return` made
###               the failure look like silent success.
###            2. 1-step `Register-ScheduledTask -Action -Principal
###               -Force` is flakier than the 2-step pattern; some
###               Windows builds reject parameter set validation
###               and the task never registers. Switched to
###               `New-ScheduledTask -Action $action -Principal
###               $principal` followed by `Register-ScheduledTask
###               -InputObject $task` (matches the working Remote
###               Message path).
###            3. No success/fail string contract. The caller now
###               returns "OK (scheduled task as <user>)" or
###               "FAIL: <reason>" so RbLog can distinguish silent
###               failure from real success.
###          Warning popup icon (Wscript.Shell.Popup type 48 =
###          Exclamation) preserved. Cancel popup icon (type 64 =
###          Information) preserved. PATCH bump: regression fix.
###
###  v6.2.2  - 2026-04-27 - Operator-name fix. The rollup CSV was logging a
###          Microsoft-Account session token (e.g. @@B9s-HOxYfdw0TOwRb...) in
###          the Operator column because $global:Credentials.UserName returned
###          that token instead of a username. Now defers to the canonical
###          block's Get-JanetOperatorIdentity helper, which mirrors SIM_Tool's
###          AD lookup (LDAP -> Win32_ComputerSystem -> $env:USERNAME) and
###          formats as "EDIPI - DisplayName". Same change applies to every
###          tool via the canonical block re-stamp; WPT was the only tool
###          that explicitly overrode -Operator.
###
###  v6.2.1  - 2026-04-27 - Bug fix: when the operator clicks Cancel (or X's)
###          the closing-notes dialog, the JANET rollup row now still lands.
###          Previously the early-return on Cancel skipped Stop-JanetSession,
###          producing a JANET\Logs\WPT\<YYYY-MM>_detail.csv detail row but
###          NO row in the fleet rollup at JANET\Logs\<YYYY-MM>_usage.csv.
###          The legacy WPT-specific Publish-WptUsageCsvRow still skips on
###          Cancel as before — only the JANET centralized rollup changed.
###
###  v6.2.0  - Added JANET centralized logging. Every WPT session now writes
###          one row to the fleet-wide monthly rollup at
###          \\dm-tn-01\sh-usafe-automation$\JANET\Logs\<YYYY-MM>_usage.csv,
###          and one row per host action to
###          \\dm-tn-01\sh-usafe-automation$\JANET\Logs\WPT\<YYYY-MM>_detail.csv.
###          Falls back to %USERPROFILE%\Documents\WPT\ when the share is
###          unreachable; replays orphan rows on next launch when reachable.
###          Hooks: Track-Action (per-host detail rows), btnStartSession
###          click handler (Start-JanetSession), $f.Add_FormClosing (Stop-
###          JanetSession reusing the existing closing-notes dialog).
###          Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
###
###  v6.1.10 - Restore launch-maximized. Operator report after v6.1.9:
###          Live Execution panel renders correctly, but the overall
###          window launches at 1280x740 centered on a much larger
###          monitor, so the content looks cramped and they have to
###          drag-resize the window to see everything fit. This
###          re-introduces $f.WindowState = Maximized (which v6.1.2
###          had removed). The v6.1.9 manual layout callback is wired
###          to Form.Resize, so the Cleanup tab content expands
###          correctly as the maximized window draws. Operators who
###          prefer a windowed view can still click Restore Down.
###          PATCH bump: cosmetic/UX fix, no feature change.
###
###  v6.1.9 - Cleanup tab Live Execution panel STILL not visible after
###          v6.1.8. Root cause analysis: the v6.1.8 anchor-toggle walk
###          (Anchor=None then back to original) does force WinForms to
###          re-capture offsets, but it re-captures them against the
###          control's CURRENT Bounds -- which were already wrong from
###          the initial broken layout. The bad geometry carried
###          through; rtbCleanExec stayed positioned off-screen.
###          New approach: bypass the anchor system entirely for the
###          Cleanup tab. Added $SetCleanupLayout, a scriptblock that
###          explicitly SetBounds()'s every major Cleanup control based
###          on the tab's actual current ClientSize. Wired it to both
###          Form.Shown (initial render) and Form.Resize (window size
###          changes). Controls repositioned:
###            * grpCleanCfg        (top-left, fixed 600 wide)
###            * grpCleanTargets    (top-right, fills remaining width)
###            * dgvClean           (middle-left, fixed 600 wide)
###            * rtbCleanExec       (middle-right, fills remaining)
###            * rtbCleanLog        (bottom, full width)
###            * plus all three section title labels
###          Design-time pixel coordinates + Anchor values are left in
###          place as harmless fallbacks; the SetBounds call on Shown
###          overrides them before the user sees the tab.
###          Also promoted grpCleanCfg/grpCleanTargets/lblCleanGridTitle/
###          lblCleanExecTitle/lblCleanLogTitle to $script: scope so
###          the layout callback can find them reliably from inside
###          event-handler scope (WinForms event handlers in PowerShell
###          lose access to closure-local variables).
###          Logs-tab / other-tab fix from v6.1.8 (anchor-toggle walk
###          for Right/Bottom anchored controls) is kept as-is -- it
###          works for controls whose design bounds fit the default
###          200x100 TabPage, which is most of the file.
###          PATCH bump: targeted layout fix, no API change.
###
###  v6.1.8 - Global layout fix: Right/Bottom anchors were broken across
###          every tab, not just Cleanup. v6.1.7 testing confirmed the
###          profile scan now correctly finds 13 stale profiles on the
###          operator's test VM (Prof Found=13, Temp cleanup reporting
###          16,943MB / 9,645 files -- the underlying logic is solid).
###          But three UI bugs remained, all tracing to the same root
###          cause:
###          * Live Execution panel invisible -- Anchor='Top,Right,Bottom'
###            with offsets captured against a 0x0 parent pushed X off
###            screen when the tab actually got its real size.
###          * CLEANUP TARGETS panel cut off at the right edge -- same
###            issue with Anchor='Top,Left,Right'; panel stretched to
###            ~2100px wide inside a ~1000px tab, Import button clipped.
###          * Logs tab unscrollable -- rtbLog with
###            Anchor='Top,Left,Right,Bottom' physically grew to roughly
###            2700x1400, so its scrollbars clipped off the visible tab
###            area entirely.
###          Root cause: WinForms anchor offsets are captured relative
###          to the PARENT container's size at the moment the Anchor
###          property is set. Controls in this file set their anchors
###          before being added to a TabPage, AND the TabPage has no
###          parent (no size) until its TabControl renders -- so every
###          Right/Bottom-anchored control captured offsets against 0x0.
###          Fix: added a form-Shown handler that walks the entire
###          control tree and, for any control whose Anchor uses Right
###          or Bottom, toggles Anchor to None and back to the original
###          value. That forces the layout engine to re-capture offsets
###          against the parent's now-correct size. Top/Left-only
###          anchored controls are untouched (always stable).
###          Also: rtbLog now explicitly sets ScrollBars=ForcedVertical
###          and BorderStyle=FixedSingle as belt-and-suspenders, so
###          scrolling works even if the anchor fix regresses.
###          PATCH bump: UI fix triad, no API change.
###
###  v6.1.7 - Cleanup tab: three bugs that were hiding the stale-profile
###          functionality. After v6.1.6 shipped, operator test showed
###          "Profiles found: 0" on a VM with 13 obvious 31-day-old
###          profiles, no Live Execution panel visible on the tab, and
###          none of the per-profile diagnostic lines I'd added in
###          v6.1.6 making it to the UI.
###          * PSSession remoting was eating every per-profile event.
###            The scriptblock was passing the local
###            System.Collections.Concurrent.ConcurrentQueue through
###            -ArgumentList into the remote session. Remoting serializes
###            it to a deserialized PSCustomObject on the remote end;
###            Enqueue() calls on that copy silently fail (swallowed by
###            try/catch), so all "Found N candidate(s)" / "Keep:" /
###            "Stale:" lines from the remote scope went into the void.
###            Refactored: events collected in a local
###            List[hashtable] inside the remote block, returned with
###            the result, then the local worker re-emits each one via
###            $Emit (which writes to the real in-process queue the UI
###            timer drains). Same pattern applied to the temp block.
###          * Live Execution panel was invisible. BorderStyle was None
###            with BackColor=OutputBg (near-black) on a near-black
###            tab, so the control rendered indistinguishable from the
###            surrounding empty area. Operator reported "there is no
###            Live Execution box" -- it was literally unseeable.
###            Switched rtbCleanExec + rtbCleanLog BorderStyle to
###            FixedSingle. Also removed a dead duplicate property-set
###            line under rtbCleanLog that was copy-paste residue.
###          * Profile age classification switched from "first available
###            signal" to "oldest of all available signals." Rationale:
###            on live AFNET hosts every individual signal can be bumped
###            by SOMETHING -- folder mtime by Defender/ESS/Search/GPO/
###            OneDrive, NTUSER.DAT by GPO evaluating user context or
###            any Reg.exe Load/Unload cycle, LastUseTime occasionally
###            stuck. Using the oldest available signal means if ANY
###            signal says "hasn't been touched in a long time," we
###            trust it -- an actively used profile bumps ALL three.
###            Each profile now logs its full signal spread
###            (NTUSER.DAT=date / LastUseTime=date / folder-mtime=date)
###            plus which signal was chosen as the oldest, so operators
###            can audit classification decisions at a glance.
###            Still-Loaded profiles still skip the delete with a
###            "reboot to unload" warning as the safety net against
###            false-positive on active sessions.
###          PATCH bump: bug fix triad, no API change.
###
###  v6.1.6 - Cleanup tab: stale profile detection actually works now.
###          Operators reported the Cleanup tab found temp files fine but
###          never flagged any stale profiles, even with the threshold
###          set to 30 days on hosts with obviously stale accounts.
###          Root cause: the age check was reading the profile folder's
###          LastWriteTime, which on live AFNET hosts is bumped constantly
###          by Defender/ESS scans, Windows Update, Search indexing,
###          Group Policy, and OneDrive/Teams/Outlook cache writes -- a
###          profile with zero human logons for a year still read "today",
###          so every candidate got "Keep". Folder mtime was never a real
###          logon signal.
###          * Age source replaced with a prioritized check:
###              1) NTUSER.DAT LastWriteTime (the registry hive is
###                 written on logoff when the profile service unloads
###                 it; not touched by background scanners)
###              2) Win32_UserProfile.LastUseTime (parsed from CIM
###                 datetime via ManagementDateTimeConverter)
###              3) folder LastWriteTime (last resort only)
###          * `-not $_.Loaded` dropped from the pre-filter. Profiles
###            stuck in the loaded state (disconnected RDP, SYSTEM-
###            owned transient loads, MECM service accounts) used to be
###            silently excluded from the candidate count. They now
###            appear in the log as "Stale but LOADED" with guidance to
###            reboot, counted in Skipped rather than hidden.
###          * Log lines now carry age in days and the source tag
###            (src=NTUSER.DAT / LastUseTime / folder-mtime) so
###            operators can see which signal fired on each profile.
###          PATCH bump: bug fix only, no API change.
###
###  v6.1.5 - Fix: Cleanup tab blew up with "A Using variable cannot be
###          retrieved. A Using variable can be used only with
###          Invoke-Command, Start-Job, or InlineScript in the script
###          workflow." The Cleanup scriptblock was passing
###          `$using:EventQueue` as an Invoke-Command -ArgumentList
###          value, which only works when the enclosing scope is itself
###          being dispatched to a remote / job context. Our Cleanup
###          block is dispatched via `$ps.AddScript(...).BeginInvoke()`
###          in a RunspacePool worker, so `$using:` has no binding
###          context there. Fixed two sites in $global:CleanBlock by
###          passing the plain parameter name `$EventQueue` (already in
###          the worker's scope). PATCH bump: regression fix, no API
###          change.
###
###  v6.1.4 - Documentation pass (audit / reviewer friendly).
###          * New FILE MAP section right under the changelog lists
###            every #region in the file with a one-line purpose so
###            reviewers can jump to any topic without reading the
###            table of contents from the code itself.
###          * Every one of the 46 #region blocks now has a 79-char
###            banner immediately above it (3 lines: top divider,
###            centered title, top divider again) plus a multi-line
###            docstring explaining what the region does, what it
###            defines (vars, functions), and what it interacts with.
###          * Zero behavior / API / state changes. Pure readability
###            improvement. PATCH bump.
###
###  v6.1.3 - Targets tab symmetry + Remove Selected color.
###          * lbxTargets Y and H matched to the paste textbox: both
###            now start at Y=40 and are 140 tall. Previously the
###            listbox ran 22->210 while the paste box ran 40->180,
###            making the left and right halves of the row look
###            mismatched.
###          * btnRemove (Remove Selected) moved up to Y=186 to sit in
###            the same row as the paste-side buttons, bumped to
###            H=26 to match them, and repainted red (Danger) to
###            signal destructive intent.
###          * PATCH bump: cosmetic only.
###
###  v6.1.2 - Revert v6.1.1's forced maximize. Operator wanted a well-
###          sized default window, not one that slams itself to full
###          screen on launch. Kept the v6.1.1 ClientSize 1280x740 +
###          MinimumSize 1100x680 since those are a better fit for
###          1366x768 laptops than the v5 era 1440x850 defaults.
###          AUTHOR label change from v6.1.1 kept as-is. PATCH bump:
###          behavior revert.
###
###  v6.1.1 - Visual: launch maximized, shrink restored-size defaults,
###          relabel Start tab "CREDITS" group to "AUTHOR".
###          * $f.WindowState = Maximized at start, so WPT uses the full
###            working area on the operator's primary monitor instead
###            of floating centered on a 1440x850 rectangle.
###          * ClientSize 1440x850 -> 1280x740 and MinimumSize
###            1280x760 -> 1100x680 (both restore-down fallbacks; sized
###            for 1366x768 laptops which are the smallest common
###            AFNET endpoint).
###          * Start tab group "CREDITS" relabeled to "AUTHOR" -- more
###            accurate for what that row actually shows (one line of
###            author contact info).
###          * PATCH bump: cosmetic only, no feature / state changes.
###
###  v6.1.0 - Consolidate About / How To Use / Change Log into Start-tab
###          popup buttons. Frees two sidebar nav slots; same content,
###          one click away from the landing tab.
###          Added:
###            * $script:WPT_AboutText / WPT_ChangeLogText /
###              WPT_HowToUseText string constants (STATIC INFO TEXT
###              region, right after MODULAR DIALOGS)
###            * Show-WptAboutDialog helper alongside the existing
###              Show-WptChangeLogDialog / Show-WptHowToUseDialog (both
###              from inlined Tools\UI\Dialog.Info.ps1)
###            * Three buttons at the bottom of the Start tab below
###              Session Information: Change Log (purple border), About
###              (cyan border), How To Use (gold border). All open the
###              themed Show-WptInfoDialog with scrollable read-only
###              text; parented to the main form.
###          Removed:
###            * TAB: HOW TO USE (the scrollable tbHowTo TextBox)
###            * TAB: ABOUT & CHANGELOG (pnlAboutHeader + rtbChangelog
###              + the $changelogText array)
###            * $tabHowTo + $tabAbout from $tc.Controls.AddRange
###            * HowToUse + About entries from $navSpec
###            * $tabHowTo from the Legacy $navTabTargets2 helper array
###            * $tabHowTo + $tabAbout refs in the SelectedIndexChanged
###              session-gate (only Start tab is pre-session now)
###          MINOR bump: new feature (popup dialogs), no breaking state
###          changes. Users lose the dedicated tabs but gain buttons
###          that do the same thing from the landing page.
###
###  v6.0.0 - BREAKING: Remove Package Deploy tab + scriptblock.
###          Deploy-Application.ps1 pushes are now handled by J.A.N.E.T.'s
###          standalone Remote Package Installer tool; duplicating that
###          surface in WPT created two code paths to maintain with no
###          user-visible benefit.
###          Removed:
###            * TAB 3: PACKAGE DEPLOY (UI + Load-Packages function)
###            * $global:DeployBlock scriptblock
###            * PACKAGE DEPLOY EVENT HANDLER (btnDeployPkg click)
###            * $global:DefaultPkgRoot, $global:PackageMap
###            * Start tab PACKAGE ROOT DIRECTORY group box +
###              $script:txtStartPkgRoot / $btnBrowsePkg /
###              $script:lblPkgRootStatus
###            * Pkg Deploy stat card (7 cards now instead of 8; Reboots
###              shifted left into the vacated X slot)
###            * PkgsDeployed counter in $global:Stats / $script:WPT.Stats
###            * 'PkgDeploy' case in Track-Action switch + history color
###            * $tabPkg / Package Deploy nav entry / Load-Packages call
###              from Start Session handler
###            * $script:DeployTimer / $script:DeployJobs references in
###              the form-closing cleanup loop
###          Start tab layout: CREDENTIALS / ACK / START SESSION /
###          SESSION INFORMATION groups shifted up ~86px to close the
###          gap the PACKAGE ROOT group used to occupy.
###          Rollback: full deleted region bodies live in
###          Archive\WPT-superseded-2026-04-21\WorkstationPatchingTool
###          Legacy.ps1 alongside the older v46 production copy.
###          MAJOR bump: user-visible feature removal.
###
###  v5.1.3 - Cleanup tab: adopt SrA Tennesen Garrett's proven AFNET
###          profile-delete technique.
###          * Filter swapped to Get-WmiObject Win32_UserProfile with
###            LocalPath like 'C:\Users\%' + parent-equals check.
###          * Exclude list is now Public, Administrator, USAF_Admin,
###            the current session account ($env:USERNAME), its base
###            form (stripped .adw), and its .adw form -- so whether
###            the operator authenticated with bth0mp or bth0mp.adw,
###            both accounts are always protected.
###          * Age by folder LastWriteTime (what File Explorer shows
###            as "Date modified") instead of Win32_UserProfile.
###            LastUseTime, which drifts on detached profiles.
###          * Deletion via $profile.Delete() method -- the native
###            Win32_UserProfile method the reference script invokes.
###            Same underlying behavior as Remove-CimInstance.
###          * Temp file cleanup, dry-run toggle, day threshold,
###            per-host parallelization, and live/summary logs all
###            unchanged. Only the profile-filter + delete path
###            changed. PATCH bump: behavior-preserving improvement.
###
###  v5.1.2 - Fix: sidebar nav was unscrollable.
###          v5.1.1 disabled $navHost.AutoScroll to kill the gray scrollbar,
###          but 19 items * 32px still overflows the nav host on shorter
###          window heights - bottom items (Reports, Heal, WinRM Setup,
###          Usage, Logs, About) were unreachable. Re-enabled AutoScroll
###          and added a ShowScrollBar(SB_BOTH, false) P/Invoke wired on
###          HandleCreated + Layout so the default gray scrollbar stays
###          hidden while MouseWheel scrolling keeps working. Drag-to-
###          scroll is sacrificed; wheel + keyboard arrows are the input
###          path. PATCH bump: regression fix.
###
###  v5.1.1 - Visual polish: remove three theme seams.
###          * Dropped the 1px violet-border divider panel at the bottom
###            of the top strip and the top of the bottom status strip.
###            Both read as light horizontal bars against the near-black
###            background instead of the subtle separators they were
###            supposed to be. Strips now flow flush into the content.
###          * Disabled AutoScroll on the sidebar nav host and shrunk
###            each New-WptNavItem from 40px to 32px (+ matching Y
###            stride). All 19 nav entries now fit without the default
###            gray scrollbar that didn't match the Purple+Gold theme.
###          * PATCH bump: cosmetic only, no state/API changes.
###
###  v5.1.0 - Inherit JANET launcher credentials.
###          * On startup, read $env:JANET_CRED_FILE (the DPAPI-encrypted
###            Export-Clixml file JANET.ps1 writes under
###            %LOCALAPPDATA%\JANET\Session\janet_cred.xml). If present and
###            valid, pre-populate $global:Credentials, flip the Start tab
###            status label to "<user> (inherited from J.A.N.E.T.)" in
###            success color, relabel the "Set Credentials" button to
###            "Override Credentials", and update the Session Information
###            panel. Audit row "CredentialInherit".
###          * Falls through silently when launched directly (no env vars);
###            manual Set Credentials flow unchanged.
###          * MINOR bump: additive new feature, no state/schema changes.
###
###  v5.0.0 - First release under semver. Resets the old v1..v47.1 line.
###          ----------------------------------------------------------
###          This is the build that promoted "WorkstationPatchingTool
###          Testing.ps1" (v47.1) to the main WorkstationPatchingTool.ps1
###          after the Legacy-core + modular-skin rebuild. Everything
###          below the line labelled v47.1 is pre-semver build history;
###          kept for context. All future edits bump semver (MAJOR for
###          breaking tab/state changes, MINOR for new tabs or features,
###          PATCH for fixes).
###          ----------------------------------------------------------
###          Contents snapshot at v5.0.0 (mirrors v47.1 scope):
###            * Legacy v47 engine (state, runspace pool, remoting, all
###              bulk ops, MECM/WU/WMI integrations, every original tab
###              handler) - byte-identical to the Legacy monolith.
###            * Modular v2.4.0 visual layer: Purple (#8C64DC) + Gold
###              (#DAB452) on near-black palette, Cascadia Mono headings,
###              DPI awareness + DWM dark title bar + rounded corners,
###              double-buffer reflection helper, themed control
###              factories, themed dialogs.
###            * Main-form shell: sidebar with J.A.N.E.T. wordmark +
###              numbered iconed nav, minimal 32px top strip with "live"
###              heartbeat, bottom status strip (SESSION / TARGETS /
###              LOG). Gold-stripe top bar removed; Start-tab
###              NAVIGATE-TO-SECTION card column removed.
###            * Phase 3 additive tabs (built on Legacy patterns):
###                - Heal: one-click remediation for stuck MECM/WMI/WU
###                  (Restart CcmExec / Repair WMI / Reset WU / Trigger
###                  Check-In / gpupdate / Health Scan).
###                - WinRM Setup: DCOM-based WinRM bootstrap for hosts
###                  that can't answer on 5985.
###                - App Updater v2: profile registry (M365x2 / Defender
###                  / Chrome / Edge) with Verify (query current version
###                  + last-updated) and Apply.
###                - Usage: operator + session observability + Publish
###                  Now button.
###            * Closing-flow infrastructure: additive FormClosing
###                handler -> Show-WptClosingNotesDialog -> append one
###                aggregated row to WPT-UsageV2-<YYYY-MM>.csv. AD
###                DisplayName lookup via DirectorySearcher (no RSAT
###                dependency). Legacy's existing cleanup handler
###                (timers/jobs/pool) runs untouched alongside.
###          ----------------------------------------------------------
###          Fixes vs the immediate pre-promote build:
###            * DataGridViewColumnCollection[0] = (New-Object
###              DataGridViewCheckBoxColumn) was a NotSupportedException
###              on Heal / WinRM Setup / App Updater v2 at form init;
###              replaced with the .Add($checkboxColumn) pattern.
###
###  v47.1  - Phase 1 reskin. Legacy core (state, config, logging, runspace
###           pool, remoting, operations, MECM/WU/WMI integrations, all tab
###           handlers) stays byte-identical. Visual layer swapped to the
###           modular WPT v2.4.0 look:
###           * Palette repointed to Purple (#8C64DC) + Gold (#DAB452) on
###             near-black with violet lean. Legacy's $c.* keys preserved so
###             every call site keeps working. Matching $script:WPT.UI.Theme
###             PSCustomObject populated via inlined Initialize-WptTheme for
###             modular factories.
###           * Typography switched to Cascadia Mono for headings, numbered
###             nav, group-box titles, console output, and status strip.
###             Segoe UI retained for body/label text.
###           * Added DPI awareness + dark title bar (DwmSetWindowAttribute)
###             + double-buffer reflection helper from modular Theme.ps1.
###             Fired at script load (idempotent on relaunch).
###           * Inlined every modular themed factory (New-WptButton /
###             Label / TextBox / GroupBox / RichTextBox / CheckBox / ComboBox /
###             NumericUpDown / ListBox / TabPage / Card / Heading / Separator /
###             IconLabel / Primary/Ghost/StripeButton / Badge / PulseIndicator /
###             NavItem / GridPaperBackground / ScanlineOverlay / DataGridView /
###             grid helpers) and every modular dialog (Show-WptDialog /
###             ClosingNotes / Info / ChangeLog / HowToUse). Phase 2 migrates
###             per-tab call sites; Phase 1 keeps Legacy's New-Btn / New-Lbl /
###             New-Grp / etc. intact.
###           * Main-form shell reshape: gold-stripe top header (logos +
###             "J.A.N.E.T. Workstation Patching Tool" title + subtitle)
###             removed; minimal 32px top strip with "live" heartbeat kept.
###             Sidebar widened 130->252px; wordmark block + numbered nav via
###             New-WptNavItem (01 START / 02 HOW TO USE / ...); user block
###             (user + status + host) pinned to sidebar bottom. Bottom
###             status strip (SESSION / TARGETS / LOG path) added.
###           * Start tab middle "NAVIGATE TO SECTION" nav-card column
###             removed - sidebar handles navigation. $script:NavCards kept
###             as empty array for legacy-reference safety.
###           * Session-gating preserved: Start / How To Use / About reachable
###             pre-session; all others require credentials + ack + Start.
###  v47    - AFNET hardening pass. Five structural fixes so the tool actually
###           works on hosts behind the AFNET Defender Firewall / ESS GPO:
###           1) ICMP reachability replaced with a TCP probe of WinRM (5985)
###              then SMB (445). Test-Connection / Test-Connection-backed ping
###              sweeps returned false on every workstation because the inbound
###              ICMP Echo rule is blocked by GPO, so every Scan/Patch/Deploy/
###              KBInstall/Clean run reported "Offline" and short-circuited.
###              New Test-WorkstationReachable helper used in main-thread code;
###              each RunspacePool scriptblock carries an inline TCP probe.
###           2) New $global:WSManOpt (30s Operation / 15s Open / 5s Cancel /
###              60s Idle). Threaded through every New-PSSession and
###              Invoke-Command -ComputerName call so a single unreachable
###              host no longer hangs a runspace thread for ~3 minutes on
###              WSMan defaults. Each runspace block also creates a local
###              copy for use inside the runspace.
###           3) Remote Message: removed the msg.exe * first-try branch.
###              AllowRemoteRPC=0 and Session 0 isolation on hardened AFNET
###              workstations made msg.exe return exit 0 while silently
###              dropping messages, or fail with "Error 5 getting session
###              names". The scheduled-task-as-logged-in-user path is now
###              the sole delivery method.
###           4) DeployBlock and the KB MSU fallback no longer mount
###              \\host\C$ via New-PSDrive + Copy-Item. They use
###              Copy-Item -ToSession over the PSSession that was already
###              authenticated, so hosts with AutoShareWks=0 or SMB 445
###              blocked at the host firewall still receive packages.
###              Same change applied to the M365 Sw Mgr pre-copy handler
###              in Sw Mgr & Uninstaller.
###           5) PatchBlock no longer writes HKLM:\SOFTWARE\Policies\
###              Microsoft\Windows\WindowsUpdate\AU. The v43 save/restore
###              of NoAutoRebootWithLoggedOnUsers + AlwaysAutoRebootAt
###              ScheduledTime fought GPO (which would clobber the value
###              on next refresh anyway) and tripped ACAS/Tanium policy-
###              drift monitoring. Reboot suppression is already handled
###              by MECM's own install arguments (IsRebootIfNeeded=$false
###              on CCM_Application; CCM_SoftwareUpdatesManager.InstallUpdates
###              does not auto-reboot at trigger time).
###           Bumped version.
###  v46    - Internal.
###  v45    - Added Cleanup tab:
###           * Clears temp files (Windows\Temp, C:\Temp, per-user %TEMP%,
###             INetCache, Prefetch) across all loaded targets in parallel.
###           * Deletes user profiles whose LastUseTime is older than N days
###             (default 60, range 7-730). Uses Win32_UserProfile native method.
###           * Auto-excludes system/service accounts, default profiles, and
###             currently-loaded (in-use) profiles.
###           * DRY RUN mode on by default -- reports what would be deleted
###             without actually deleting. Double-confirmation on live deletes.
###  v44    - Bulk Scan App column fix:
###           Now only counts MECM apps that ARE installed AND have an update
###           pending. Previously, NotInstalled apps in Software Center were
###           flagged as needing a "patch", producing misleading counts.
###           Both ScanBlock and PatchBlock use matching filter criteria so
###           "Patch Needing" patches exactly what the scan reported.
###  v43    - Code review fixes:
###           * CRITICAL: Adobe uninstall RunAsPPL removal now wrapped in
###             try/finally to guarantee LSASS protection is always restored.
###           * Initialize-RunspacePool now disposes existing pool before
###             creating a new one (prevents handle/runspace leaks).
###           * Stale $result variable in uninstall and message loops now
###             initialized to $null at the top of each iteration.
###           * Removed deprecated WMIC fallback from M365 and Adobe
###             uninstall handlers (slow, triggers MSI self-repair).
###           * PatchBlock now saves and restores existing WU reboot policy
###             values instead of blindly overwriting them.
###           * Added documentation comment about HKCU limitation in
###             remote software scans (scans admin hive, not interactive user).
###  v42    - Added How To Use tab. Renamed sidebar labels to full names.
###  v1-3   - Initial build, Start page, session gating, auth hardcoded.
###  v4-6   - Tab reorder, App Manager logging, quick filter dropdown.
###  v7-9   - Fixed column widths, scrollbars, layout fitting without fullscreen.
###  v10    - ACAS CSV import on Targets tab.
###  v11    - Remote Message tab.
###  v12-14 - Reboot Message tab (experimental), layout fixes.
###  v15-17 - About/Changelog tab, sidebar fixes, tab renames.
###  v18-22 - KB Scanner tab with parallel scan, install section, MECM triggers.
###  v23    - KB Scanner: Trigger MECM Cycles + Push & Download buttons.
###  v24-29 - Software Manager tab, M365/Adobe handlers, log fixes.
###  v30-32 - Tab renames (SCCM App Manager, Sw Mgr & Uninstaller), quick filter.
###  v33-35 - App Updater tab (M365/Defender/Chrome/Edge/Custom).
###  v36    - Full documentation pass. Configuration section. Inline comments.
###
###############################################################################
###  FILE MAP - jump-to reference for reviewers and future auditors.
###  Every region in this script is listed below with a one-line purpose.
###  Find a topic, then search for the #region banner (each has a 79-char
###  ### divider immediately above it so scrolling for them is easy).
###############################################################################
###
###  [INFRASTRUCTURE]
###    RESOLVE SCRIPT DIRECTORY       - Finds $global:ScriptDir via 3-way
###                                     fallback ($PSScriptRoot ->
###                                     MyInvocation -> CWD).
###    LOGGING                        - Audit-log file path + Write-AuditLog
###                                     function. Per-session log under
###                                     .\Logs\WPT_<user>_<timestamp>.log.
###    MODULAR SHELL HELPERS          - DPI awareness + DWM dark title bar
###                                     + DoubleBuffered reflection helper.
###                                     Called once at script load.
###    $script:WPT BOOTSTRAP + THEME  - Initializes $script:WPT state hash
###                                     with UI.Theme / UI.Fonts / UI.Icons
###                                     PSCustomObjects (the modular shape
###                                     all New-Wpt* factories read from).
###    COLOR PALETTE                  - $c hashtable. Legacy-style key
###                                     names (BG / Panel / Accent / Gold /
###                                     ...) repointed to the Purple #8C64DC
###                                     + Gold #DAB452 on near-black palette.
###    FONTS                          - $fn hashtable. Cascadia Mono for
###                                     headings / console / nav; Segoe UI
###                                     for body/labels.
###    GLOBALS                        - $global:Credentials, ComputerList,
###                                     RSPool, ThreadCount, Stats,
###                                     ActionHistory, WSManOpt, etc.
###                                     Shared state every tab reads/writes.
###    SESSION STATS TRACKING         - Track-Action + Update-StatLabels.
###                                     Every action in every tab calls
###                                     Track-Action which appends to
###                                     $global:ActionHistory + bumps
###                                     $global:Stats counters.
###    HELPER FUNCTIONS               - New-Btn / New-Lbl / New-Tb / New-Grp
###                                     / Style-Grid / Log / Parse-Hosts /
###                                     Initialize-RunspacePool. Legacy-
###                                     style factories used by most tabs.
###    MODULAR THEMED FACTORIES       - New-WptButton / New-WptLabel /
###                                     New-WptGroupBox / New-WptCard /
###                                     New-WptNavItem / ... and the
###                                     New-WptDataGridView + Set-WptGridStyle
###                                     grid factories. Inlined from
###                                     modular Tools\UI\Controls.ps1 and
###                                     Tools\UI\Grid.ps1. Consumed by the
###                                     sidebar nav, Heal tab, WinRM Setup
###                                     tab, App Updater v2 tab, and Usage
###                                     tab.
###    MODULAR DIALOGS                - Show-WptDialog (MessageBox clone),
###                                     Show-WptClosingNotesDialog,
###                                     Show-WptInfoDialog / ChangeLog /
###                                     HowToUse / AboutDialog. Inlined
###                                     from Tools\UI\Dialog*.ps1.
###    STATIC INFO TEXT               - $script:WPT_AboutText /
###                                     WPT_ChangeLogText / WPT_HowToUseText
###                                     here-strings. Backing content for
###                                     the three Start-tab popup buttons.
###
###  [OPERATION SCRIPTBLOCKS - run inside RunspacePool workers]
###    BULK SCAN SCRIPTBLOCK          - $global:ScanBlock. Per-host MECM
###                                     update + app + disk + reboot probe.
###    BULK PATCH SCRIPTBLOCK         - $global:PatchBlock. Triggers MECM
###                                     install on pending updates + apps.
###    BULK REBOOT SCRIPTBLOCK        - $global:RebootBlock. Remote reboot
###                                     via Restart-Computer -Force.
###    HEAL SCRIPTBLOCKS              - $global:HealthScanBlock plus 5
###                                     remediation blocks (RestartCcmExec,
###                                     WmiRepair, WuReset, TriggerCheckIn,
###                                     GpUpdate). Consumed by the Heal
###                                     tab.
###    WINRM BOOTSTRAP SCRIPTBLOCK    - $global:WinRMBootstrapBlock. Uses
###                                     DCOM (port 135) to flip the target's
###                                     WinRM service to Auto + start it +
###                                     run winrm quickconfig remotely.
###                                     Consumed by the WinRM Setup tab.
###
###  [AUXILIARY FORMS / DIALOGS]
###    REBOOT MONITOR                 - Show-RebootMonitor modal form.
###                                     Tracks reboot timeouts per host
###                                     with a live countdown + status.
###    APP MANAGER DIALOG             - Show-AppManager modal form used by
###                                     the SCCM App Manager tab's per-host
###                                     application pane.
###
###  [MAIN FORM SHELL]
###    MAIN FORM                      - $f = the top-level Form. Default
###                                     1280x740 client area; launches
###                                     centered, windowed (not maximized).
###    TOP STRIP                      - Minimal 32px top bar, right-anchored
###                                     "live" heartbeat pulse + label.
###    STATUS STRIP                   - Bottom 32px strip with heartbeat,
###                                     SESSION label, TARGETS count, LOG
###                                     path.
###    TAB CONTROL                    - Hidden-header TabControl ($tc).
###                                     Active tab switched by sidebar nav
###                                     buttons rather than tab headers.
###
###  [TAB BUILDERS - one region per tab]
###    TAB 0: START / ABOUT           - Landing tab. Author, credentials
###                                     (Required), responsibility ack,
###                                     START SESSION button, session
###                                     information. Bottom-row popup
###                                     buttons: Change Log / About /
###                                     How To Use.
###    TAB 1: TARGETS                 - Paste hostnames, Import TXT,
###                                     Import ACAS CSV, Import XLSX.
###                                     Shared target list ($global:ComputerList).
###    TAB 2: BULK SCAN & PATCH       - Parallel scan + patch + reboot
###                                     against $global:ComputerList.
###                                     10-column grid (Host, Online,
###                                     Drive, Reboot, Updates, Apps,
###                                     Scan, Patch, ...).
###    TAB: SOFTWARE MANAGER          - Per-host Win32/Store software
###                                     inventory via registry + native
###                                     uninstall. Specialized handlers
###                                     for M365 C2R and Adobe Acrobat.
###    TAB: REMOTE MESSAGE            - Scheduled-task-as-logged-in-user
###                                     popup delivery (msg.exe is
###                                     unreliable on hardened AFNET).
###    TAB: REBOOT MESSAGE            - Experimental countdown-based
###                                     reboot with periodic warning
###                                     popups.
###    TAB: KB SCANNER                - Parallel Get-HotFix scan +
###                                     filter. KB Install section: MECM
###                                     trigger first, MSU fallback.
###    TAB: APP UPDATER               - Legacy built-in profile pushes
###                                     (M365 / Defender / Chrome / Edge
###                                     + Custom Command).
###    TAB: CLEANUP                   - Temp file sweep + stale-profile
###                                     deletion (AFNET-aware filter per
###                                     SrA Tennesen script, v5.1.3).
###                                     DRY RUN on by default.
###    TAB 4: ACTIVITY LOG            - Read-only live log mirror. Every
###                                     tab's Log "..." calls append here.
###    TAB 5: SCCM APP MANAGER        - Per-host MECM CCM_Application
###                                     query + Install / Uninstall /
###                                     Reinstall / Repair via CCM
###                                     methods.
###    TAB 6: REPORTS & STATS         - Live stat cards (Scans, Updates,
###                                     Installs, Uninstalls, ...), full
###                                     action history grid, CSV exports,
###                                     report files list.
###    TAB: HEAL (v47.1+)             - One-click remediation for stuck
###                                     MECM/WMI/WU. Health scan grid +
###                                     5 action buttons feeding the
###                                     Heal scriptblocks.
###    TAB: WINRM SETUP (v47.1+)      - Pre-probe + DCOM-based WinRM
###                                     bootstrap grid. For hosts that
###                                     can't answer on 5985.
###    APP UPDATER PROFILE REGISTRY   - $global:AppUpdateProfiles hash
###                                     with 5 named profiles (Script +
###                                     Verify scriptblocks each).
###                                     Consumed by App Updater v2.
###    TAB: APP UPDATER v2 (v47.1+)   - Profile registry UI parallel to
###                                     the Legacy App Updater tab. Adds
###                                     a Verify button that queries
###                                     current version + last-updated
###                                     per host.
###    CLOSING FLOW + USAGE CSV       - Get-WptOperatorFullName (ADSI
###                                     DisplayName lookup),
###                                     Resolve-WptUsageCsvPath,
###                                     Get-WptUsageSummary,
###                                     Publish-WptUsageCsvRow. Wires a
###                                     second FormClosing handler that
###                                     writes one aggregated row to
###                                     WPT-UsageV2-<YYYY-MM>.csv.
###    TAB: USAGE LOG (v47.1+)        - Session observability tab + manual
###                                     "Publish Now" button (fires the
###                                     same closing flow on demand).
###
###  [WIRING / FORM LIFECYCLE - bottom of the script]
###    ASSEMBLE TABS                  - $tc.Controls.AddRange of every
###                                     tab page in display order.
###    WIRE NAV CARDS TO TABS         - Legacy-era mapping (NavCards were
###                                     removed; loop iterates the empty
###                                     $script:NavCards array now).
###    SIDEBAR NAVIGATION             - Builds the J.A.N.E.T. wordmark,
###                                     numbered/iconed nav items (via
###                                     New-WptNavItem), user block.
###                                     Wires click-to-switch-tab with
###                                     session gating (only Start is
###                                     always reachable pre-session).
###    BULK SCAN/PATCH/REBOOT HANDLERS - btnScanAll / btnPatchSel /
###                                     btnRebootSel / btnPingSweep click
###                                     handlers. Dispatch scriptblocks
###                                     through $script:RSPool with timer-
###                                     based polling for completion.
###    FORM CLEANUP & SHOW            - FormClosing cleanup (timers, jobs,
###                                     pool disposal), JANET credential
###                                     inherit block, Add_Shown startup
###                                     logs, and the final ShowDialog.
###
###############################################################################

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v6.2.0. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\WPT\ when share is
## unreachable; replays orphan rows on next launch with the share back up.
$JanetWptVersion = '6.5.22'

# === BEGIN JANET LOGGING BLOCK (paste from here) ===
$JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

$script:JanetSession   = $null
$script:JanetNetworkOk = $false

## Closure-safe getter — closures created with .GetNewClosure() under StrictMode 3
## cannot reliably resolve $script:Foo. Helpers used from inside closures must
## be declared at global scope so they are always visible.
function global:Get-JanetSession { return $script:JanetSession }

## X-block flag. Initialized $false in the form builder; set $true only by
## the Close Tool button handler. The FormClosing handler cancels any close
## that arrives without the flag set (X, Alt-F4, right-click-close), except
## WindowsShutDown which is allowed through so the OS doesn't nag-prompt the
## operator. Removes the per-host snapshot churn from the rollup CSV by
## guaranteeing every session ends through Stop-JanetSession.
function global:Get-JanetAllowClose { return $script:JanetAllowClose }
function global:Set-JanetAllowClose { param($Value) $script:JanetAllowClose = [bool]$Value }

function Get-JanetMonthFile {
    [CmdletBinding()]
    param([switch]$Detail)
    $month = Get-Date -Format 'yyyy-MM'
    if ($Detail) { return "${month}_detail.csv" } else { return "${month}_usage.csv" }
}

function Get-JanetLocalDir {
    ## Workspace-anchored fallback under $PSScriptRoot's parent (the JANET root,
    ## peer to Logs/ and Tools/). Never %USERPROFILE% / %PROGRAMDATA% /
    ## %LOCALAPPDATA% — keeps tool data next to the launcher so portable /
    ## kiosk installs stay self-contained.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\{0}\{1}" -f $script:JanetSession.Tool, $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Get-JanetLocalRollupDir {
    ## Local fallback for the fleet rollup (one row per session-snapshot or
    ## session-end). Lives at JanetLocal/_Rollup/<userfolder>/ so every tool
    ## a single operator runs writes to the same local rollup spool, mirroring
    ## the network behavior where the rollup is at the Logs/ root.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\_Rollup\{0}" -f $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Initialize-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = $env:USERNAME,
        [string]$ASI      = ''
    )
    ## Schema (simplified 2026-04-29): two-bucket action model. Every per-host
    ## action is either a TouchHost (just reached the box — message, scan, etc.)
    ## or a VulnPatched (changed the host's security state — patch, reboot,
    ## STIG apply, plugin remediation, package install, secure-boot enable).
    ## Rollup row carries: HostsTouched, VulnsPatched, Failures, DurationMin,
    ## ClosingNotes. ScriptsRun and Successes are deliberately gone — operators
    ## want simple totals, not categorical breakdowns.
    [PSCustomObject]@{
        StartTime    = Get-Date
        SessionId    = ([guid]::NewGuid().ToString('N').Substring(0,8))
        Operator     = $Operator
        ASI          = $ASI
        Tool         = $Tool
        Version      = $Version
        Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        VulnsPatched = 0
        Failures     = 0
    }
}

function Get-JanetUserFolderName {
    ## Per-user subfolder name in Nemesis format: "{user} - {COMPUTER}_{user}".
    ## Mirrors Tools/ACASNemesis/Logs/<this name>/ so every JANET tool produces
    ## the same per-operator folder pattern. Sanitizes any path-illegal char.
    $u = $env:USERNAME; if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Unknown' }
    $c = $env:COMPUTERNAME; if ([string]::IsNullOrWhiteSpace($c)) { $c = 'UnknownPC' }
    $name = "$u - ${c}_$u"
    return ($name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Add-JanetCsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$Line,
        [int]$MaxRetries     = 6,
        [int]$InitialDelayMs = 250
    )

    if ($script:JanetNetworkOk -eq $false -and $null -ne $script:JanetSession) {
        Write-JanetLocal -Path $LocalPath -Line $Line
        return
    }

    $delay = $InitialDelayMs
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $dir = Split-Path -Parent $NetworkPath
            if (-not (Test-Path $dir)) {
                [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
            }
            Add-Content -Path $NetworkPath -Value $Line -Encoding UTF8 -ErrorAction Stop
            return
        } catch {
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 8000)
            }
        }
    }

    if ($null -ne $script:JanetSession) { $script:JanetNetworkOk = $false }
    Write-JanetLocal -Path $LocalPath -Line $Line
}

function Write-JanetLocal {
    [CmdletBinding()]
    param([string]$Path, [string]$Line)
    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $Line -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host ("WARNING: JANET local fallback failed: $_") -ForegroundColor Yellow
    }
}

function Test-JanetNetwork {
    [CmdletBinding()]
    param([string]$Root = $JanetLogRoot)
    try {
        if ($Root -notmatch '^\\\\([^\\]+)') { return $false }
        $server = $Matches[1]
        $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) { return $false }
        return [bool](Test-Path $Root -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Get-JanetOperatorIdentity {
    ## Returns "EDIPI - DisplayName" or just EDIPI when display-name lookup
    ## fails. Three lookup strategies, tried in order:
    ##   1. DirectorySearcher with sAMAccountName filter — works on any
    ##      AD-joined machine, doesn't depend on `whoami /fqdn` returning a
    ##      usable FQDN. This is the most reliable on AFNET.
    ##   2. [adsi]"LDAP://$(whoami /fqdn)" — SIM_Tool's classic pattern,
    ##      kept as a fallback for environments where DirectorySearcher is
    ##      blocked by policy.
    ##   3. Win32_ComputerSystem.UserName — last resort, returns
    ##      "DOMAIN\username" which we strip to bare username.
    ## Comma stripped from displayName so the value is CSV-safe in one cell.
    [CmdletBinding()] param()
    $edipi = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($edipi)) { $edipi = 'Unknown' }

    $displayName = $null

    ## Strategy 1: DirectorySearcher (most reliable on AD-joined boxes)
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$env:USERNAME))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['displayname'] -and $result.Properties['displayname'].Count -gt 0) {
            $displayName = [string]$result.Properties['displayname'][0]
        }
    } catch { $displayName = $null }

    ## Strategy 2: [adsi]LDAP://whoami /fqdn (SIM_Tool's pattern)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $fqdn = (whoami /fqdn) 2>$null
            if ($fqdn -and $fqdn.Trim()) {
                $entry = [adsi]"LDAP://$($fqdn.Trim())"
                if ($entry -and $entry.Properties -and $entry.Properties['displayName']) {
                    $vals = $entry.Properties['displayName']
                    if ($vals.Count -gt 0) { $displayName = [string]$vals[0] }
                }
            }
        } catch { $displayName = $null }
    }

    ## Strategy 3: Win32_ComputerSystem.UserName (strip DOMAIN\ prefix)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $u = [string]$cs.UserName
            if ($u -and $u.Contains('\')) { $u = ($u -split '\\', 2)[1] }
            $displayName = $u
        } catch { $displayName = $null }
    }

    $displayName = if ($displayName) { ($displayName -replace ',', '').Trim() } else { '' }
    if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName -eq $edipi) {
        return $edipi
    }
    return "$edipi - $displayName"
}

function global:Start-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = (Get-JanetOperatorIdentity),
        [string]$ASI      = '',
        [switch]$SkipReplay
    )
    $script:JanetSession   = Initialize-JanetSession -Tool $Tool -Version $Version -Operator $Operator -ASI $ASI
    $script:JanetNetworkOk = Test-JanetNetwork

    if ($script:JanetNetworkOk -and -not $SkipReplay) {
        try { Invoke-JanetReplay } catch {
            Write-Host ("NOTE: JANET replay skipped: $_") -ForegroundColor Yellow
        }
    }
}

## Header strings for the two CSV families. Pinned here so every tool
## emits the exact same column order. Detail header has 10 columns; usage
## header has 10 columns. ConvertTo-JanetCsvLine uses the same comma-strip
## rules the data rows use, so the header line round-trips cleanly.
$script:JanetDetailHeader = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
$script:JanetUsageHeader  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

function Add-JanetCsvHeader {
    ## Ensures both the network and local fallback CSVs are ready to receive
    ## a row in the current schema. Returns the (possibly redirected) paths
    ## the caller must use for the subsequent Add-JanetCsvRow call —
    ## $.NetworkPath and $.LocalPath. See Invoke-JanetHeaderEnsure for the
    ## four-case rotation/redirect logic.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    $resolvedNet   = $NetworkPath
    $resolvedLocal = $LocalPath
    try { $resolvedNet   = Invoke-JanetHeaderEnsure -Path $NetworkPath -HeaderLine $HeaderLine } catch {}
    try { $resolvedLocal = Invoke-JanetHeaderEnsure -Path $LocalPath  -HeaderLine $HeaderLine } catch {}
    return [PSCustomObject]@{ NetworkPath = $resolvedNet; LocalPath = $resolvedLocal }
}

function Invoke-JanetHeaderEnsure {
    ## Returns the path the caller should write the row to. Five cases:
    ##   1. File missing         -> mkdir, write header, return original.
    ##   2. File exists, empty   -> write header, return original. (The
    ##                              original code skipped this branch and
    ##                              left the file headerless, which produced
    ##                              2026-04_usage.csv.)
    ##   3. First line matches   -> no-op, return original.
    ##   4. First line differs,
    ##      rotation succeeds    -> rename old to <name>.legacy_<unix>.csv,
    ##                              write fresh header, return original.
    ##                              Rename retries with bounded backoff
    ##                              (200ms -> 4000ms, 6 attempts) to survive
    ##                              a peer tool's transient append lock —
    ##                              without the retry, mismatched-schema
    ##                              rows leaked into the legacy file
    ##                              (2026-05_usage.csv).
    ##   5. First line differs,
    ##      rotation fails       -> create a fresh sister CSV at
    ##                              <name>.r<unix>.csv with the current
    ##                              header, return that path. New-schema
    ##                              rows go to the sister file instead of
    ##                              corrupting the legacy file. The legacy
    ##                              file stays in place as a paper trail.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    $first = $null
    try { $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop } catch {}
    $firstTrim = if ($null -ne $first) { $first.Trim() } else { '' }

    if ($firstTrim -eq '') {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }
    if ($firstTrim -eq $HeaderLine.Trim()) { return $Path }

    $stamp      = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
    $legacyName = ([IO.Path]::GetFileNameWithoutExtension($Path)) + ".legacy_$stamp.csv"
    $rotated    = $false
    $delay      = 200
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Rename-Item -LiteralPath $Path -NewName $legacyName -ErrorAction Stop
            $rotated = $true
            break
        } catch {
            if ($attempt -lt 6) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 4000)
            }
        }
    }
    if ($rotated -or -not (Test-Path -LiteralPath $Path)) {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    ## Persistently locked. Redirect writes to a sister CSV so new-schema
    ## rows don't pollute the legacy file.
    ##
    ## v6.5.7 fix: reuse an existing sister whose first line already matches
    ## the current header instead of minting a new one each call. Pre-fix
    ## behavior: $stamp is generated per call, so every consecutive call
    ## that hit a fresh second (i.e. nearly every call) produced a new
    ## <base>.r<unix>.csv, piling up dozens of sister files in the share's
    ## Logs folder ("WARNING: JANET schema rotation failed..." spam in the
    ## console). Now we scan once for an existing matching sister; only
    ## create + warn when one doesn't exist.
    $dir  = Split-Path -Parent $Path
    $base = [IO.Path]::GetFileNameWithoutExtension($Path)

    $existingMatch = $null
    try {
        $candidates = @(Get-ChildItem -LiteralPath $dir -Filter "$base.r*.csv" -File -ErrorAction SilentlyContinue)
        foreach ($cand in $candidates) {
            $candFirst = $null
            try { $candFirst = Get-Content -LiteralPath $cand.FullName -TotalCount 1 -ErrorAction Stop } catch {}
            if ($candFirst -and $candFirst.Trim() -eq $HeaderLine.Trim()) {
                $existingMatch = $cand.FullName
                break
            }
        }
    } catch {}

    if ($existingMatch) {
        ## Silent reuse — no warning spam.
        return $existingMatch
    }

    $sister = Join-Path $dir ("$base.r$stamp.csv")
    Write-Host ("WARNING: JANET schema rotation failed; routing rows to sister CSV: " + $sister) -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $sister -ErrorAction SilentlyContinue)) {
        Add-Content -Path $sister -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
    }
    return $sister
}

function Write-JanetAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('TouchHost','VulnPatched')] [string]$Action,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Success','Failure','Skipped')] [string]$Result,
        [int]$ItemCount = 0,
        [string]$Detail = ''
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Write-JanetAction called before Start-JanetSession; ignored." -ForegroundColor Yellow
        return
    }

    ## Two-bucket action model:
    ##   TouchHost   = reached the box for any reason (message, scan, ping,
    ##                 lookup). Counts toward HostsTouched only.
    ##   VulnPatched = changed the host's security state (patch, reboot,
    ##                 STIG apply, plugin remediation, package install,
    ##                 secure-boot enable). Counts toward HostsTouched AND
    ##                 adds ItemCount to VulnsPatched.
    ## Result='Failure' increments the Failures counter regardless of bucket.
    ## Snapshot HostsTouched count BEFORE adding this host so we can detect
    ## "first time we've seen this host this session" — the trigger for
    ## emitting a real-time row to the fleet rollup CSV.
    $beforeCount = $script:JanetSession.Hosts.Count
    [void]$script:JanetSession.Hosts.Add($Target)
    $afterCount  = $script:JanetSession.Hosts.Count
    $newHost = ($afterCount -gt $beforeCount)

    if ($Result -eq 'Failure') {
        $script:JanetSession.Failures++
    }
    if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') {
        ## Failed patches don't count as "vuln patched" — only successful or
        ## skipped (where skip means already-patched, still effectively applied).
        $script:JanetSession.VulnsPatched += [int]$ItemCount
    }

    ## Per-user detail CSV — Nemesis-style folder layout:
    ##   Logs/<Tool>/<user> - <COMPUTER>_<user>/<YYYY-MM>_detail.csv
    $userFolder = Get-JanetUserFolderName
    $netDir   = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
    $localDir = Get-JanetLocalDir
    $fileName = Get-JanetMonthFile -Detail
    $netFile   = Join-Path $netDir   $fileName
    $localFile = Join-Path $localDir $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetDetailHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        $Action,
        $Target,
        $Result,
        $ItemCount,
        $Detail
    )
    Add-JanetCsvRow -NetworkPath $netFile -LocalPath $localFile -Line $line

    ## Per-host rollup snapshots removed. The form's Close Tool button is
    ## the only egress (X / Alt-F4 cancel via FormClosing guard), so every
    ## session reaches Stop-JanetSession and writes exactly one SessionEnd
    ## row to <YYYY-MM>_usage.csv. The previous design emitted a Snapshot
    ## row on every distinct-host touch (crash-resilience for force-closes
    ## that no longer happen), which made bulk runs flood the rollup CSV
    ## with hundreds of intermediate rows.
}

function Write-JanetRollupSnapshot {
    [CmdletBinding()] param([string]$ClosingNotes = '')
    if ($null -eq $script:JanetSession) { return }
    $duration    = (Get-Date) - $script:JanetSession.StartTime
    $durationMin = [Math]::Round($duration.TotalMinutes, 1)

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        'SessionEnd',
        $script:JanetSession.Hosts.Count,
        $script:JanetSession.VulnsPatched,
        $script:JanetSession.Failures,
        $durationMin,
        $ClosingNotes
    )

    $fileName  = Get-JanetMonthFile
    $netFile   = Join-Path $JanetLogRoot              $fileName
    $localFile = Join-Path (Get-JanetLocalRollupDir)  $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetUsageHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath
    Add-JanetCsvRow    -NetworkPath $netFile -LocalPath $localFile -Line $line
}

function ConvertTo-JanetCsvLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]]$Fields)
    $clean = $Fields | ForEach-Object {
        $s = if ($null -eq $_) { '' } else { [string]$_ }
        ($s -replace '[,\r\n]', ' ').Trim()
    }
    return ($clean -join ',')
}

function global:Stop-JanetSession {
    [CmdletBinding()]
    param(
        [string]$ClosingNotes = '',
        [switch]$ShowDialog
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Stop-JanetSession called with no active session; ignored." -ForegroundColor Yellow
        return
    }

    if ($ShowDialog) {
        $dialogResult = Show-JanetClosingNotesForm
        if ($null -ne $dialogResult.ASI -and $dialogResult.ASI -ne '') {
            $script:JanetSession.ASI = $dialogResult.ASI
        }
        if ($null -ne $dialogResult.Notes) {
            $ClosingNotes = $dialogResult.Notes
        }
    }

    ## SessionEnd row — the only rollup row this tool writes. Schema
    ## matches $script:JanetUsageHeader (12 cols incl. SessionId + RowType).
    ## Exactly one row per session, written from Stop-JanetSession. The dashboard
    ## parser still groups by SessionId to absorb legacy v1.8.x logs that emitted
    ## intermediate Snapshot rows; new sessions never produce them.
    Write-JanetRollupSnapshot -ClosingNotes $ClosingNotes

    $script:JanetSession   = $null
    $script:JanetNetworkOk = $false
}

function Show-JanetClosingNotesForm {
    ## WPT-styled closing-notes prompt. Self-contained -- hard-codes the
    ## WPT dark palette so every tool gets identical look without depending
    ## on its own theme tables. Return shape ({ ASI; Notes }) is preserved
    ## so existing Stop-JanetSession callers keep working unchanged.
    [CmdletBinding()] param()
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing       -ErrorAction SilentlyContinue

    ## --- WPT theme palette (rgb values copy/pasted from WPT $script:WPT.UI.Theme)
    $cBg          = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    $cInput       = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    $cBorder      = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    $cAccent1     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    $cSuccess     = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    $cPanelLight  = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    $cTextPrimary = [System.Drawing.Color]::FromArgb(240, 240, 245)
    $cTextSec     = [System.Drawing.Color]::FromArgb(170, 168, 180)
    $cTextOnAcc   = [System.Drawing.Color]::FromArgb(255, 255, 255)

    $face       = 'Segoe UI'
    $fntBody    = New-Object System.Drawing.Font($face,  9)
    $fntPrompt  = New-Object System.Drawing.Font($face, 13, [System.Drawing.FontStyle]::Bold)
    $fntCaption = New-Object System.Drawing.Font($face,  8.25)
    $fntBtn     = New-Object System.Drawing.Font($face,  9, [System.Drawing.FontStyle]::Bold)

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'Closing Notes'
    $form.ClientSize      = New-Object System.Drawing.Size(640, 380)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition   = 'CenterScreen'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.BackColor       = $cBg
    $form.ForeColor       = $cTextPrimary
    $form.Font            = $fntBody
    $form.Topmost         = $true

    ## Immersive dark title bar -- same DwmSetWindowAttribute trick WPT uses.
    ## Silent fallthrough on builds that don't support attr 19/20.
    try {
        if (-not ('JanetClosingNotes.Dwm' -as [type])) {
            Add-Type -Namespace 'JanetClosingNotes' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction Stop
        }
    } catch {}
    $form.Add_HandleCreated({
        try {
            $hwnd = $form.Handle
            if ($hwnd -ne [System.IntPtr]::Zero) {
                $on = 1
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) | Out-Null
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4) | Out-Null
            }
        } catch {}
    }.GetNewClosure())

    ## Prompt + sub-hint (mirrors WPT's Show-WptClosingNotesDialog)
    $lblPrompt           = New-Object System.Windows.Forms.Label
    $lblPrompt.Text      = 'Anything worth noting from this session?'
    $lblPrompt.Location  = New-Object System.Drawing.Point(20, 16)
    $lblPrompt.Size      = New-Object System.Drawing.Size(600, 24)
    $lblPrompt.Font      = $fntPrompt
    $lblPrompt.ForeColor = $cAccent1
    $lblPrompt.BackColor = [System.Drawing.Color]::Transparent

    $lblHint           = New-Object System.Windows.Forms.Label
    $lblHint.Text      = 'Notes are appended to the JANET monthly usage CSV. Blank is fine.'
    $lblHint.Location  = New-Object System.Drawing.Point(20, 44)
    $lblHint.Size      = New-Object System.Drawing.Size(600, 18)
    $lblHint.Font      = $fntCaption
    $lblHint.ForeColor = $cTextSec
    $lblHint.BackColor = [System.Drawing.Color]::Transparent

    ## ASI / RFC field -- preserved from the legacy form because Stop-JanetSession
    ## reads .ASI off the result and writes it into the rollup CSV.
    $lblAsi           = New-Object System.Windows.Forms.Label
    $lblAsi.Text      = 'ASI / RFC #'
    $lblAsi.Location  = New-Object System.Drawing.Point(20, 78)
    $lblAsi.Size      = New-Object System.Drawing.Size(120, 16)
    $lblAsi.Font      = $fntCaption
    $lblAsi.ForeColor = $cTextSec
    $lblAsi.BackColor = [System.Drawing.Color]::Transparent

    $tbAsi             = New-Object System.Windows.Forms.TextBox
    $tbAsi.Location    = New-Object System.Drawing.Point(20, 96)
    $tbAsi.Size        = New-Object System.Drawing.Size(600, 24)
    $tbAsi.Font        = $fntBody
    $tbAsi.BackColor   = $cInput
    $tbAsi.ForeColor   = $cTextPrimary
    $tbAsi.BorderStyle = 'FixedSingle'

    ## Closing notes (multiline)
    $lblNotes           = New-Object System.Windows.Forms.Label
    $lblNotes.Text      = 'Closing notes'
    $lblNotes.Location  = New-Object System.Drawing.Point(20, 130)
    $lblNotes.Size      = New-Object System.Drawing.Size(120, 16)
    $lblNotes.Font      = $fntCaption
    $lblNotes.ForeColor = $cTextSec
    $lblNotes.BackColor = [System.Drawing.Color]::Transparent

    $tbNotes               = New-Object System.Windows.Forms.TextBox
    $tbNotes.Location      = New-Object System.Drawing.Point(20, 148)
    $tbNotes.Size          = New-Object System.Drawing.Size(600, 168)
    $tbNotes.Multiline     = $true
    $tbNotes.AcceptsReturn = $true
    $tbNotes.ScrollBars    = 'Vertical'
    $tbNotes.Font          = $fntBody
    $tbNotes.BackColor     = $cInput
    $tbNotes.ForeColor     = $cTextPrimary
    $tbNotes.BorderStyle   = 'FixedSingle'

    ## Buttons -- 'Submit && Exit' (Success green) + 'Skip' (PanelLight gray).
    ## Two-button rather than WPT's three-way: this dialog runs from FormClosing,
    ## so a 'Return to Tool' choice can't actually return; the form is already
    ## tearing down by the time we land here.
    $btnSubmit = New-Object System.Windows.Forms.Button
    $btnSubmit.Text         = 'Submit && Exit'
    $btnSubmit.Location     = New-Object System.Drawing.Point(380, 332)
    $btnSubmit.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSubmit.FlatStyle    = 'Flat'
    $btnSubmit.FlatAppearance.BorderSize = 0
    $btnSubmit.BackColor    = $cSuccess
    $btnSubmit.ForeColor    = $cTextOnAcc
    $btnSubmit.Font         = $fntBtn
    $btnSubmit.UseVisualStyleBackColor = $false
    $btnSubmit.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnSkip = New-Object System.Windows.Forms.Button
    $btnSkip.Text         = 'Skip'
    $btnSkip.Location     = New-Object System.Drawing.Point(505, 332)
    $btnSkip.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSkip.FlatStyle    = 'Flat'
    $btnSkip.FlatAppearance.BorderSize  = 1
    $btnSkip.FlatAppearance.BorderColor = $cBorder
    $btnSkip.BackColor    = $cPanelLight
    $btnSkip.ForeColor    = $cTextPrimary
    $btnSkip.Font         = $fntBtn
    $btnSkip.UseVisualStyleBackColor = $false
    $btnSkip.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.AcceptButton = $btnSubmit
    $form.CancelButton = $btnSkip
    $form.Controls.AddRange(@($lblPrompt, $lblHint, $lblAsi, $tbAsi, $lblNotes, $tbNotes, $btnSubmit, $btnSkip))

    $result = $form.ShowDialog()
    $asi   = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbAsi.Text }   else { '' }
    $notes = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbNotes.Text } else { '' }
    $form.Dispose()

    return [PSCustomObject]@{ ASI = $asi; Notes = $notes }
}

function Invoke-JanetReplay {
    [CmdletBinding()] param()

    if ($null -eq $script:JanetSession) { return }
    $userFolder = Get-JanetUserFolderName

    ## Two local spool locations to drain:
    ##   1. JanetLocal/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##      → Logs/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##   2. JanetLocal/_Rollup/<userfolder>/<YYYY-MM>_usage.csv
    ##      → Logs/<YYYY-MM>_usage.csv
    $detailLocal = Get-JanetLocalDir
    $rollupLocal = Get-JanetLocalRollupDir

    $sources = @()
    if (Test-Path $detailLocal) {
        $detailNet = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
        $sources += [PSCustomObject]@{ Local = $detailLocal; NetDir = $detailNet; Filter = '*_detail*.csv' }
    }
    if (Test-Path $rollupLocal) {
        $sources += [PSCustomObject]@{ Local = $rollupLocal; NetDir = $JanetLogRoot; Filter = '*_usage*.csv' }
    }

    foreach ($src in $sources) {
        $orphans = Get-ChildItem -Path $src.Local -File -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Name -like $src.Filter) -and ($_.Name -notlike '*.replayed_*') -and ($_.Name -notlike '*.legacy_*')
            }

        foreach ($orphan in $orphans) {
            if (-not (Test-Path $src.NetDir)) {
                try { [void](New-Item -ItemType Directory -Path $src.NetDir -Force -ErrorAction Stop) }
                catch { continue }
            }
            $netFile = Join-Path $src.NetDir $orphan.Name

            $replayOk = $true
            Get-Content -Path $orphan.FullName | ForEach-Object {
                ## Skip the local header row if the network file already has one —
                ## otherwise the rollup CSV ends up with a header line every time
                ## an orphan is replayed, which makes pivoting harder.
                if ($_ -like 'Timestamp,*' -and (Test-Path $netFile)) { return }
                try {
                    Add-Content -Path $netFile -Value $_ -Encoding UTF8 -ErrorAction Stop
                } catch {
                    $replayOk = $false
                }
            }

            if ($replayOk) {
                $stamp     = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
                $newName   = "$($orphan.Name).replayed_$stamp"
                try {
                    Rename-Item -LiteralPath $orphan.FullName -NewName $newName -ErrorAction Stop
                } catch {
                    Write-Host ("NOTE: Could not rename replayed file '$($orphan.FullName)': $_") -ForegroundColor Yellow
                }
            }
        }
    }
}

# === END JANET LOGGING BLOCK (paste to here) ===

###############################################################################
###                        RESOLVE SCRIPT DIRECTORY                         ###
###############################################################################
## Determines where the script is running from via a three-way fallback
## ($PSScriptRoot -> MyInvocation -> CWD) so ISE, shortcut, and dot-source
## launches all agree. Downstream code uses $global:ScriptDir to locate
## the adjacent .\Logs\ folder and any future Images\ / Packages\ paths.
#region === RESOLVE SCRIPT DIRECTORY ===
## Determines where the script is running from. Used for finding Images/,
## Logs/, and Packages/ folders. Tries $PSScriptRoot, then MyInvocation, then CWD.
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }
#endregion

###############################################################################
###                                LOGGING                                  ###
###############################################################################
## Per-session audit log at <LogDir>\<EDIPI - DisplayName>\WPT_<user>_<ts>.log.
## Mirrors ACAS Nemesis logging exactly: each operator gets a subfolder under
## the resolved LogDir named "<EDIPI> - <DisplayName>" (via Get-JanetOperatorIdentity).
## The session .log lives in the subfolder. Write-AuditLog appends structured
## key=value rows AND fans out per-host calls (any -Target that isn't 'N/A')
## to a per-operator monthly TouchedHosts_<YYYY-MM>.csv in the same subfolder,
## so a lead can pivot "which hosts did operator X touch this month" without
## grepping daily session logs.
##
## v6.5.16 — LogDir resolution mirrors ACAS Nemesis's Resolve-NemLogTarget:
##   1. Primary share at $script:WptLogShare —
##      \\dm-tn-01\sh-usafe-automation$\JANET\Logs\WPT. WRITE-probed
##      (sentinel file create + delete) so an ACL-blocked share doesn't
##      silently look writable. Orphan sweep nukes leftover sentinels older
##      than 1 hour.
##   2. <JANET-root>\Logs\WPT\ local fallback (peer to the share path).
##   3. <JANET-root>\Tools\Logs\ legacy fallback (where pre-v6.5.16
##      sessions wrote — kept so an operator with no share access doesn't
##      lose a working layout).
## Whichever wins becomes $global:LogDir; the per-admin subfolder + session
## .log path are derived from it. The JANET LOGGING BLOCK still writes the
## centralized <YYYY-MM>_detail.csv via $JanetLogRoot independently, so the
## three artifacts end up in the same per-admin folder on the share:
##   <share>\WPT\<EDIPI - DisplayName>\WPT_<user>_<ts>.log
##   <share>\WPT\<EDIPI - DisplayName>\TouchedHosts_<YYYY-MM>.csv
##   <share>\WPT\<EDIPI - DisplayName>\<YYYY-MM>_detail.csv
#region === LOGGING ===
$script:WptLogShare = Join-Path $JanetLogRoot 'WPT'

function global:Resolve-WptLogTarget {
    <#
        Returns @{ Path = '<path>'; IsFallback = $bool }. Sets $global:LogDir.
        Tries the share first (write-probed), then the local <JANET-root>\Logs\WPT,
        then the legacy local <JANET-root>\Tools\Logs. NEVER throws — locked-down
        workstations land on the legacy fallback and keep working.
    #>
    [CmdletBinding()] param()

    $share = $script:WptLogShare
    try {
        if ($share -and (Test-Path -LiteralPath $share -ErrorAction Stop)) {
            ## Write-probe: create + delete a sentinel. Catches ACL-allow-list
            ## shares where Test-Path returns $true but Add-Content throws.
            $sentinel = Join-Path $share (".wpt-write-test-{0:N}.tmp" -f [guid]::NewGuid())
            try {
                'ok' | Out-File -LiteralPath $sentinel -Encoding ASCII -ErrorAction Stop
                Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue

                ## Orphan sweep: prior sessions whose Remove-Item lost the
                ## race against AV / process kill / sync agent. 1-hour grace
                ## is generous; any sentinel older is unambiguously orphaned.
                try {
                    Get-ChildItem -LiteralPath $share -Filter '.wpt-write-test-*.tmp' -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
                        ForEach-Object {
                            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
                        }
                } catch {}

                $global:LogDir = $share
                return @{ Path = $share; IsFallback = $false }
            } catch {
                ## Share visible but not writable — drop to local fallback.
            }
        }
    } catch {
        ## Share unreachable — drop to local fallback.
    }

    ## Local fallback. Prefer <JANET-root>\Logs\WPT (mirrors share layout);
    ## fall through to legacy <JANET-root>\Tools\Logs if the parent dir
    ## doesn't exist and we can't create it.
    $janetRoot = Split-Path -Parent $global:ScriptDir
    $localShareMirror = Join-Path $janetRoot 'Logs\WPT'
    try {
        if (-not (Test-Path -LiteralPath $localShareMirror)) {
            [void](New-Item -Path $localShareMirror -ItemType Directory -Force -ErrorAction Stop)
        }
        $global:LogDir = $localShareMirror
        return @{ Path = $localShareMirror; IsFallback = $true }
    } catch {}

    ## Legacy: pre-v6.5.16 wrote here. Walk up looking for a "Logs" dir.
    $searchDir = $global:ScriptDir
    for ($i = 0; $i -lt 4; $i++) {
        $candidate = Join-Path $searchDir 'Logs'
        if (Test-Path $candidate) { $global:LogDir = $candidate; return @{ Path = $candidate; IsFallback = $true } }
        $parent = Split-Path $searchDir -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $searchDir) { break }
        $searchDir = $parent
    }
    $legacy = Join-Path $janetRoot 'Logs'
    try { if (-not (Test-Path $legacy)) { [void](New-Item -Path $legacy -ItemType Directory -Force -ErrorAction Stop) } } catch { $legacy = $global:ScriptDir }
    $global:LogDir = $legacy
    return @{ Path = $legacy; IsFallback = $true }
}

$global:LogDir = $null
$script:WptLogTarget = Resolve-WptLogTarget

## v6.5.4: default Log4j replacement-jar source path — sits inside
## the Tools folder next to WPT itself, NOT one level up. The fleet
## convention is <JANET-root>\Tools\Packages\Log4j\NewFiles\, with
## Packages\ as a sibling of WorkstationPatchingTool_*.ps1 inside
## Tools\. (v6.5.2 mistakenly went up one level and resolved to
## <JANET-root>\Packages\..., which doesn't match where the jars
## actually live.) Operator can override per-run via the textbox
## under the Log4j profile in the App Updater tab.
## v6.5.3 staging: this is interpreted as a CONTROLLER-side path
## — the wrapper stages the jars to the remote target via
## Copy-Item -ToSession over the existing WinRM session, so JANET
## running from local disk works fine.
$global:Log4jDefaultSource = Join-Path $global:ScriptDir 'Packages\Log4j\NewFiles'

## Per-operator subfolder ("EDIPI - DisplayName") matches ACAS Nemesis +
## SIM_Tool layout. Get-JanetOperatorIdentity (defined earlier in the
## JANET LOGGING BLOCK above) does the AD displayName lookup with a
## three-strategy fallback. If the lookup or subfolder create fails, we
## drop back to the flat LogDir so the session never blocks on logging.
$global:OperatorFolderName = $null
try { $global:OperatorFolderName = Get-JanetOperatorIdentity } catch {}
if ([string]::IsNullOrWhiteSpace($global:OperatorFolderName)) { $global:OperatorFolderName = $env:USERNAME }
$global:OperatorFolderName = ($global:OperatorFolderName -replace '[\\/:*?"<>|]', '_').Trim()

$global:UserLogDir = Join-Path $global:LogDir $global:OperatorFolderName
try {
    if (-not (Test-Path -LiteralPath $global:UserLogDir)) {
        New-Item -Path $global:UserLogDir -ItemType Directory -Force -EA Stop | Out-Null
    }
} catch {
    $global:UserLogDir = $global:LogDir
}

$global:SessionTS = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$global:AuditLogPath = Join-Path $global:UserLogDir "WPT_${env:USERNAME}_$($global:SessionTS).log"

## Mirror Nemesis Get-NemCsvEscape: strip CR/LF, swap commas for semicolons.
## SIM-style — no RFC-4180 quoting; keeps every row a single-line single-cell
## value so downstream awk/grep don't have to parse quoted fields.
function global:Get-WptCsvEscape {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '[\r\n]+', ' ' -replace ',', ';'
}

## Mirror Nemesis Write-NemTouchedHostCsv. One row per per-host audit event.
## Path: <UserLogDir>\TouchedHosts_<YYYY-MM>.csv. Schema lines up with
## Nemesis so a lead can join across both tools by Edipi+SessionId.
## Filename matches Nemesis exactly — the per-tool subfolder (\WPT\)
## already disambiguates the tool, so the old "WPT_" filename prefix was
## redundant and made the layout visually different from \ACAS_Nemesis\.
## NEVER THROWS — the .log is the authoritative record; this is convenience.
function global:Write-WptTouchedHostCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [string] $TargetHost,
        [string] $Result = '',
        [string] $Detail = ''
    )
    if ([string]::IsNullOrWhiteSpace($global:AuditLogPath)) { return }
    $userDir = $null
    try { $userDir = Split-Path -Parent $global:AuditLogPath } catch { return }
    if ([string]::IsNullOrWhiteSpace($userDir)) { return }

    $month   = (Get-Date).ToString('yyyy-MM')
    $csvPath = Join-Path $userDir "TouchedHosts_$month.csv"

    $opLabel = if ($global:OperatorFolderName) { $global:OperatorFolderName } else { $env:USERNAME }
    $sid     = if ($global:SessionTS) { $global:SessionTS } else { '-' }

    $line = @(
        (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'),
        (Get-WptCsvEscape $opLabel),
        $env:USERNAME,
        $sid,
        $env:COMPUTERNAME,
        (Get-WptCsvEscape $Action),
        (Get-WptCsvEscape $TargetHost),
        (Get-WptCsvEscape $Result),
        (Get-WptCsvEscape $Detail)
    ) -join ','

    $header = 'Timestamp,Operator,Edipi,SessionId,SourceHost,Action,TargetHost,Result,Detail'

    try {
        if (-not (Test-Path -LiteralPath $csvPath -ErrorAction SilentlyContinue)) {
            try {
                if (-not (Test-Path -LiteralPath $userDir -ErrorAction SilentlyContinue)) {
                    [void](New-Item -ItemType Directory -Path $userDir -Force -ErrorAction Stop)
                }
            } catch {}
            try { Add-Content -Path $csvPath -Value $header -Encoding UTF8 -ErrorAction Stop } catch {}
        }
        Add-Content -Path $csvPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {}
}

function Write-AuditLog {
    param([string]$Action, [string]$Target = "N/A", [string]$Result = "", [string]$Detail = "")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "[$ts] [USER: $env:USERNAME] [ACTION: $Action] [TARGET: $Target] [RESULT: $Result]"
    if ($Detail) { $entry += " [DETAIL: $Detail]" }
    try { $entry | Out-File -FilePath $global:AuditLogPath -Append -Encoding UTF8 } catch {}

    ## Mirror Nemesis Write-NemAudit fan-out: any audit row with a real Target
    ## (i.e., a hostname or hostname\thing — anything that isn't the 'N/A'
    ## aggregate placeholder) also writes a row to the per-operator monthly
    ## TouchedHosts CSV. Aggregate calls (Track-Action without -Target,
    ## SessionStart, SessionEnd, BulkScan summary, etc.) skip the fan-out.
    if ($Target -and $Target -ne 'N/A') {
        try { Write-WptTouchedHostCsv -Action $Action -TargetHost $Target -Result $Result -Detail $Detail } catch {}
    }
}
#endregion

###############################################################################
###               MODULAR SHELL HELPERS  (DPI / dark bar / dbuf)            ###
###############################################################################
## P/Invoke helpers imported from the modular WPT v2.4.0 Tools\UI\Theme.ps1:
##   * Set-WptDpiAware       - declares the PS process DPI-aware (must run
##                             before any window is created)
##   * Set-WptDarkTitleBar   - flips the Windows title bar to dark via
##                             DwmSetWindowAttribute (attr 19 + 20) +
##                             rounded corners on Win11 (attr 33)
##   * Enable-WptDoubleBuffer - turns on the protected DoubleBuffered
##                              property via reflection to kill flicker
## Called once at load with DPI-aware, EnableVisualStyles,
## SetCompatibleTextRenderingDefault wrapped in try/catch so relaunches
## in the same PS host don't throw on the second Add_Type / init call.
#region === MODULAR SHELL HELPERS (DPI, dark title bar, double-buffer) ===
## Imported verbatim from modular WPT v2.4.0 Tools\UI\Theme.ps1 and
## Tools\UI\Controls.ps1. All P/Invoke calls are wrapped at their call sites
## so a DWM failure on an older build of Windows never blocks tool boot.

function Set-WptDpiAware {
    <#
    .SYNOPSIS
        Declare the PowerShell process DPI-aware so WinForms renders at the
        monitor's native resolution instead of being bitmap-scaled by Windows.

    .DESCRIPTION
        On 125% / 150% / 200% Windows scaling settings, a non-DPI-aware process
        is rendered at the default (96 DPI) and Windows blows up the resulting
        bitmap to match the monitor. Text inside Flat-style buttons + any
        owner-drawn text becomes visibly blurry.

        Windows 10 1703+ exposes SetProcessDpiAwarenessContext which supports
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (value -4). Older builds
        fall back to shcore.dll!SetProcessDpiAwareness (PROCESS_PER_MONITOR_
        DPI_AWARE = 2) or user32!SetProcessDPIAware.

        MUST be called before the first window is created in the process. All
        three APIs are no-ops / fail silently if awareness is already set (e.g.
        on a relaunch inside the same PowerShell session), so the try/catch
        stack is safe to re-run.
    #>
    [CmdletBinding()]
    param()

    if (-not ('WptDpi.Api' -as [type])) {
        Add-Type -Namespace 'WptDpi' -Name 'Api' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDpiAwarenessContext(System.IntPtr value);

[System.Runtime.InteropServices.DllImport("shcore.dll")]
public static extern int SetProcessDpiAwareness(int value);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetProcessDPIAware();
'@ -ErrorAction SilentlyContinue
    }

    ## Try best -> worst fallback chain
    try {
        ## DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4  (Win10 1703+)
        $ctx = [System.IntPtr]::new(-4)
        if ([WptDpi.Api]::SetProcessDpiAwarenessContext($ctx)) { return }
    } catch {}
    try {
        ## PROCESS_PER_MONITOR_DPI_AWARE = 2  (Win8.1+)
        [void][WptDpi.Api]::SetProcessDpiAwareness(2)
        return
    } catch {}
    try {
        ## SetProcessDPIAware = system-wide awareness (pre-Win8.1)
        [void][WptDpi.Api]::SetProcessDPIAware()
    } catch {}
}

function Set-WptDarkTitleBar {
    <#
    .SYNOPSIS
        Enable dark immersive title bar + rounded corners via DwmSetWindowAttribute.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Form)

    if (-not ('Wpt.Dwm' -as [type])) {
        Add-Type -Namespace 'Wpt' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }

    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }

    $enable = 1
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)

    ## Windows 11: DWMWA_WINDOW_CORNER_PREFERENCE=33, DWMWCP_ROUND=2
    $round = 2
    $null = [Wpt.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

function Enable-WptDoubleBuffer {
    <#
    .SYNOPSIS
        Turn on DoubleBuffered for a Form / Panel / Control via reflection.

    .DESCRIPTION
        `DoubleBuffered` is a `protected` property on System.Windows.Forms.Control,
        so PowerShell's direct property-access syntax ($form.DoubleBuffered = $true)
        throws "property cannot be found on this object". Reflection reaches the
        non-public setter and sets it for real. Dramatically reduces flicker on
        resize for containers with custom Paint handlers (sidebar, cards,
        grid-paper background, scanline overlays).

        Silently no-ops on controls that lack the property (some custom types).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Control)
    try {
        $prop = $Control.GetType().GetProperty(
            'DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic'
        )
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {
        ## Non-fatal; double-buffering is cosmetic.
    }
}

## Call DPI awareness immediately so every subsequent window in this
## process is DPI-aware from the start. If it throws (e.g. already set by
## a prior launch in the same PS host), swallow silently - this is a
## process-wide one-shot.
try { Set-WptDpiAware } catch {}
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}
#endregion

###############################################################################
###           $script:WPT BOOTSTRAP + MODULAR THEME / FONTS / ICONS         ###
###############################################################################
## Seeds the $script:WPT ordered hash (ModuleRoot / ToolsRoot / Config /
## Credentials / Targets / Pool / Session / Stats / ActionHistory /
## LogQueue / LogSinks / LogFile / LogShare / AcasFindings / Cancellation
## / UI.{Form, Theme, Fonts, Icons, Controls, TabPages}) and defines
## Initialize-WptTheme, which populates UI.Theme (PSCustomObject, with
## both modular keys like Accent1 and Legacy-compatible aliases like BG)
## + UI.Fonts (PSCustomObject with DisplayLg/Eyebrow/Mono/Icon/Caption/
## modular alias Title/Btn/etc.) + UI.Icons (Segoe MDL2 glyph registry).
## Called once at script load so every later New-Wpt* factory can read
## theme data without re-initializing.
#region === $script:WPT BOOTSTRAP + MODULAR THEME/FONTS/ICONS ===
## The modular Controls.ps1 / Grid.ps1 / Dialog*.ps1 factories inlined below
## read theme + font data from $script:WPT.UI.Theme / .Fonts / .Icons.
## Legacy's $c / $fn hashtables (defined just below) stay put for the 100+
## Legacy call sites that reference them. Both structures are populated with
## the same Purple/Gold palette; $script:WPT's "backward-compatible aliases"
## section inside Initialize-WptTheme means $c.BG and
## $script:WPT.UI.Theme.BG resolve to identical Color objects.

## Module-scope state. Initialize-WptTheme populates UI.Theme/.Fonts/.Icons;
## other fields pre-declared $null so later code stays StrictMode-legal even
## though we are not enabling StrictMode.
$script:WPT = [ordered]@{
    ModuleRoot      = $null
    ToolsRoot       = $null
    Config          = $null
    Credentials     = $null
    Targets         = @()
    Pool            = $null
    PoolThreadCount = 0
    RunId           = $null
    Session         = @{
        Started   = $false
        StartTime = $null
        User      = $env:USERNAME
    }
    Stats           = @{
        Scanned         = 0
        Updated         = 0
        AppsInstalled   = 0
        AppsUninstalled = 0
        AppsReinstalled = 0
        AppsRepaired    = 0
        Reboots         = 0
    }
    ActionHistory   = [System.Collections.ArrayList]::new()
    LogQueue        = $null
    LogSinks        = @{}
    LogFile         = $null
    LogErrorShown   = $false
    LogShare        = $null
    AcasFindings    = $null
    Cancellation    = @{ RequestedAt = $null; Token = $null }
    UI              = @{
        Form     = $null
        Theme    = $null
        Fonts    = $null
        Icons    = $null
        Controls = @{}
        TabPages = @{}
    }
}

## Verbatim copy of modular WPT v2.4.0 Tools\UI\Theme.ps1 Initialize-WptTheme,
## with the Set-WptDpiAware / EnableVisualStyles / SetCompatibleTextRenderingDefault
## calls stripped (Task 1.4's MODULAR SHELL HELPERS region already invoked them
## at script load). Everything else is byte-identical.
function Initialize-WptTheme {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing      -ErrorAction SilentlyContinue

    $c = { param($r,$g,$b) [System.Drawing.Color]::FromArgb($r, $g, $b) }

    $script:WPT.UI.Theme = [pscustomobject]@{
        Background      = & $c   8   8  12
        Sidebar         = & $c   6   6  10
        TitleBar        = & $c   6   6  10
        StatusBar       = & $c   7   7  11
        Surface         = & $c  16  16  22
        SurfaceAlt      = & $c  22  22  30
        SurfaceHover    = & $c  30  28  40
        SurfaceActive   = & $c  40  36  54

        Border          = & $c  38  34  52
        BorderStrong    = & $c  52  46  72
        BorderAccent    = & $c 140 100 220

        Accent1         = & $c 140 100 220
        Accent1Hover    = & $c 164 128 240
        Accent1Muted    = & $c  96  68 156
        Accent1Glow     = & $c  28  20  48

        Accent2         = & $c 218 180  82
        Accent2Hover    = & $c 238 200 110

        Success         = & $c  92 198 120
        SuccessHover    = & $c 120 220 148
        Warning         = & $c 230 180  70
        WarningHover    = & $c 248 200 100
        Danger          = & $c 224  80  90
        DangerHover     = & $c 244 110 118
        Info            = & $c  88 180 210

        TextPrimary     = & $c 240 240 245
        TextSecondary   = & $c 170 168 180
        TextMuted       = & $c 110 106 125
        TextFaint       = & $c  60  56  74
        TextDisabled    = & $c  60  56  74
        TextOnAccent    = & $c 255 255 255

        GridBgPrimary   = & $c  16  16  22
        GridBgAlt       = & $c  22  22  30
        GridHeader      = & $c  10  10  16
        GridSelection   = & $c  28  20  48
        GridLine        = & $c  38  34  52

        ConsoleBg       = & $c   6   6  10
        ConsoleFg       = & $c 164 128 240
        ConsoleMuted    = & $c  96  68 156

        StripeYellow    = & $c 140 100 220
        StripeBlack     = & $c   8   8  12

        ## Backward-compatible aliases (match Legacy's $c keys)
        BG              = & $c   8   8  12
        TopBar          = & $c   6   6  10
        Panel           = & $c  16  16  22
        PanelLight      = & $c  30  28  40
        Input           = & $c  22  22  30
        InputBdr        = & $c  52  46  72
        OutputBg        = & $c   6   6  10
        GridBg          = & $c  16  16  22
        GridHdr         = & $c  10  10  16
        GridAlt         = & $c  22  22  30
        White           = & $c 240 240 245
        TextSec         = & $c 170 168 180
        Dim             = & $c 110 106 125
        Accent          = & $c 140 100 220
        Gold            = & $c 218 180  82
        Console         = & $c 218 180  82
        Cyan            = & $c  88 180 210
        Purple          = & $c 218 180  82
        SidebarBg       = & $c   6   6  10
    }

    $mono    = 'Cascadia Mono'
    $body    = 'Segoe UI Variable Display'
    $bodyAlt = 'Segoe UI'

    $script:WPT.UI.Fonts = [pscustomobject]@{
        DisplayLg   = New-Object System.Drawing.Font($mono, 18, [System.Drawing.FontStyle]::Bold)
        DisplayMd   = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
        DisplaySm   = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)

        Eyebrow     = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        EyebrowDim  = New-Object System.Drawing.Font($mono,  8, [System.Drawing.FontStyle]::Regular)

        H1          = New-Object System.Drawing.Font($body, 18, [System.Drawing.FontStyle]::Bold)
        H2          = New-Object System.Drawing.Font($body, 14, [System.Drawing.FontStyle]::Bold)
        H3          = New-Object System.Drawing.Font($body, 11, [System.Drawing.FontStyle]::Bold)
        Body        = New-Object System.Drawing.Font($body, 10)
        BodyStrong  = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
        Caption     = New-Object System.Drawing.Font($body,  9)
        CaptionB    = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
        Tiny        = New-Object System.Drawing.Font($body,  8)

        Mono        = New-Object System.Drawing.Font($mono, 10)
        MonoSm      = New-Object System.Drawing.Font($mono,  9)
        MonoTiny    = New-Object System.Drawing.Font($mono,  8)

        Icon        = New-Object System.Drawing.Font('Segoe MDL2 Assets', 14)
        IconLarge   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 22)
        IconSmall   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)

        ## v48a aliases - match Legacy's $fn keys
        Title       = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
        Sub         = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Italic)
        Label       = New-Object System.Drawing.Font($body, 10)
        LabelB      = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
        Btn         = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        BtnBig      = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)
        Console     = New-Object System.Drawing.Font($mono, 10)
        Small       = New-Object System.Drawing.Font($body,  9)
        SmallB      = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
        GrpHdr      = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        Big         = New-Object System.Drawing.Font($body, 12, [System.Drawing.FontStyle]::Bold)
    }

    $script:WPT.UI.Icons = [pscustomobject]@{
        Settings  = [char]0xE713
        Target    = [char]0xE8FD
        Search    = [char]0xE721
        Package   = [char]0xE7B8
        AppIcon   = [char]0xECAA
        Upload    = [char]0xE898
        Keyboard  = [char]0xE7C1
        Sync      = [char]0xE895
        Mail      = [char]0xE8BD
        Broom     = [char]0xE74D
        Chart     = [char]0xE9D9
        Document  = [char]0xE8A5
        Info      = [char]0xE946
        Power     = [char]0xE7E8
        Lock      = [char]0xE72E
        User      = [char]0xE77B
        Check     = [char]0xE73E
        Dot       = [char]0xE915
        Shield    = [char]0xEA18
        Signal    = [char]0xE8F4
        Radio     = [char]0xE704
        Connect   = [char]0xE703
        Warning   = [char]0xE7BA
    }
}

## Populate $script:WPT.UI.{Theme,Fonts,Icons} at script load so any downstream
## code (Controls.ps1 factories, Task 1.8 main form shell) finds them ready.
Initialize-WptTheme
#endregion

###############################################################################
###                              COLOR PALETTE                              ###
###############################################################################
## Legacy-style $c hashtable consumed by ~100 tab-builder call sites
## (grpFoo.ForeColor = $c.Cyan, New-Grp -Fg $c.Gold, $row.Cells[n].Style.
## ForeColor = $c.Danger, etc.). Keys (BG / TopBar / Panel / Input /
## Accent / Gold / Success / Warning / Danger / Cyan / ...) are
## Legacy-compatible so every pre-v5 call site keeps working unchanged;
## RGB values were repointed (v47.1) to the modular Purple #8C64DC +
## Gold #DAB452 on near-black with faint violet lean. The same palette
## is also exposed via $script:WPT.UI.Theme (PSCustomObject) for
## modular-style call sites that use Theme.Accent1 / .Border / etc.
#region === COLOR PALETTE ===
## Purple + Gold on Black palette, repointed from modular WPT v2.4.0's
## Initialize-WptTheme (Tools\UI\Theme.ps1). Legacy's existing call sites
## ($c.BG, $c.Accent, $c.Panel, etc.) continue to work because the keys
## were preserved; only the RGB triples changed. Additional keys from
## the modular palette are appended at the bottom for Phase 2 / Phase 3
## restyle use.
$c = @{
    ## ---- Surfaces (near-black with faint violet lean) ----
    BG         = [System.Drawing.Color]::FromArgb(  8,   8,  12)   ## Background
    TopBar     = [System.Drawing.Color]::FromArgb(  6,   6,  10)   ## TitleBar
    SidebarBg  = [System.Drawing.Color]::FromArgb(  6,   6,  10)   ## Sidebar
    Panel      = [System.Drawing.Color]::FromArgb( 16,  16,  22)   ## Surface
    PanelLight = [System.Drawing.Color]::FromArgb( 22,  22,  30)   ## SurfaceAlt
    Input      = [System.Drawing.Color]::FromArgb( 30,  28,  40)   ## SurfaceHover
    InputBdr   = [System.Drawing.Color]::FromArgb( 38,  34,  52)   ## Border
    OutputBg   = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    GridBg     = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    GridHdr    = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    GridAlt    = [System.Drawing.Color]::FromArgb( 30,  28,  40)

    ## ---- Text hierarchy ----
    White      = [System.Drawing.Color]::FromArgb(238, 232, 248)   ## TextPrimary
    TextSec    = [System.Drawing.Color]::FromArgb(188, 180, 208)   ## TextSecondary
    Dim        = [System.Drawing.Color]::FromArgb(128, 120, 150)   ## TextMuted

    ## ---- Primary accent: PURPLE #8C64DC ----
    Accent     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    Purple     = [System.Drawing.Color]::FromArgb(140, 100, 220)

    ## ---- Secondary accent: GOLD #DAB452 ----
    Gold       = [System.Drawing.Color]::FromArgb(218, 180,  82)

    ## ---- Semantic status ----
    Success    = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    Warning    = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger     = [System.Drawing.Color]::FromArgb(224,  80,  90)
    Cyan       = [System.Drawing.Color]::FromArgb( 88, 180, 210)   ## Info
    Console    = [System.Drawing.Color]::FromArgb( 92, 198, 120)   ## reuse Success green

    ## ---- Phase 2 additions (used by modular-themed factories) ----
    AccentHover   = [System.Drawing.Color]::FromArgb(164, 128, 240)
    AccentMuted   = [System.Drawing.Color]::FromArgb( 96,  68, 156)
    AccentGlow    = [System.Drawing.Color]::FromArgb( 28,  20,  48)
    GoldHover     = [System.Drawing.Color]::FromArgb(238, 200, 110)
    BorderStrong  = [System.Drawing.Color]::FromArgb( 52,  46,  72)
    BorderAccent  = [System.Drawing.Color]::FromArgb(140, 100, 220)
    SurfaceActive = [System.Drawing.Color]::FromArgb( 40,  36,  54)
    StatusBar     = [System.Drawing.Color]::FromArgb(  7,   7,  11)
}
#endregion

###############################################################################
###                                  FONTS                                  ###
###############################################################################
## Legacy-style $fn hashtable. Cascadia Mono for Title / GrpHdr / SideNav
## / Console; Segoe UI for Label / LabelB / Btn / Small / Sub. Consumed
## throughout Legacy tab builders. Modular-style equivalents live in
## $script:WPT.UI.Fonts (DisplayLg / Eyebrow / Mono / Body / etc.)
## populated by Initialize-WptTheme.
#region === FONTS ===
## Fonts repointed from modular WPT v2.4.0. Segoe UI stays for body/label
## text; Cascadia Mono is used for headings, console output, and numbered
## nav (matches the modular build's technical feel). Keys preserved so
## Legacy's $fn.Title / $fn.Btn / ... sites keep working.
$fn = @{
    Title    = New-Object System.Drawing.Font("Cascadia Mono", 13, [System.Drawing.FontStyle]::Bold)
    Sub      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    Label    = New-Object System.Drawing.Font("Segoe UI", 9)
    LabelB   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    Btn      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    BtnBig   = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    Console  = New-Object System.Drawing.Font("Cascadia Mono", 9)
    Small    = New-Object System.Drawing.Font("Segoe UI", 8)
    SmallB   = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    GrpHdr   = New-Object System.Drawing.Font("Cascadia Mono", 9, [System.Drawing.FontStyle]::Bold)
    SideNav  = New-Object System.Drawing.Font("Cascadia Mono", 8)
    SideNavB = New-Object System.Drawing.Font("Cascadia Mono", 8.5, [System.Drawing.FontStyle]::Bold)
}
#endregion

###############################################################################
###                                GLOBALS                                  ###
###############################################################################
## Shared state every tab reads and writes:
##   $global:Credentials    - set by the Start tab Set Credentials button,
##                            or inherited at startup from JANET via
##                            $env:JANET_CRED_FILE (v5.1.0+).
##   $global:ComputerList   - array of target hostnames. Populated by the
##                            Targets tab; consumed by every operation.
##   $global:RSPool         - the RunspacePool. Created by
##                            Initialize-RunspacePool; used by every
##                            parallel-per-host scriptblock dispatch.
##   $global:ThreadCount    - pool thread count, set on the Start tab.
##   $global:IsRunning      - reentrance guard for long-running ops.
##   $global:SessionStarted - set $true when the operator clicks START
##                            SESSION. Session-gates the sidebar nav.
##   $global:Stats          - counters bumped by Track-Action.
##   $global:ActionHistory  - ArrayList of every tracked action row.
##                            Rendered by the Reports tab history grid
##                            and by the Usage closing-flow aggregator.
##   $global:WSManOpt       - PSSession options (bounded timeouts).
## Also defines Test-WorkstationReachable (TCP 5985 / 445 probe, not
## ICMP, because AFNET Defender GPO blocks inbound Echo).
#region === GLOBALS ===
$global:Credentials    = $null
$global:AuthMethod     = "Negotiate"
$global:ComputerList   = @()
$global:RSPool         = $null
$global:ThreadCount    = 10
$global:IsRunning      = $false
$global:SessionStarted = $false
$global:Stats = @{
    Scanned=0; Updated=0; AppsInstalled=0; AppsUninstalled=0;
    AppsReinstalled=0; AppsRepaired=0; Reboots=0
}
$global:ActionHistory = [System.Collections.ArrayList]::new()

## v47 AFNET hardening: WinRM session options (bounded timeouts so a single
## unreachable host cannot hang a runspace thread for minutes on default timeouts).
$global:WSManOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000

## v47 AFNET hardening: Reachability check that does NOT depend on ICMP.
## The Windows Defender Firewall GPO on AFNET workstations blocks inbound ICMP
## Echo by default, so Test-Connection returns false for every host. This helper
## probes WinRM (5985) first, then SMB (445), which are the only two ports this
## tool actually uses for remoting / file copy. Returns $true as soon as either
## opens within $TimeoutMs; otherwise $false.
function Test-WorkstationReachable {
    param([string]$Computer, [int]$TimeoutMs = 1500)
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) {
                $tc.Close(); return $true
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}
#endregion

###############################################################################
###                         SESSION STATS TRACKING                          ###
###############################################################################
## Track-Action is the canonical "I just did something" entry point for
## every tab in the tool. It:
##   1. Bumps the appropriate counter in $global:Stats (Scanned / Updated
##      / AppsInstalled / AppsUninstalled / AppsReinstalled / AppsRepaired
##      / Reboots). Unknown actions still get journaled.
##   2. Appends a PSCustomObject row to $global:ActionHistory with Time /
##      Action / Target / Result / Detail.
##   3. Calls Update-StatLabels to refresh the Reports tab live cards.
##   4. Calls Write-AuditLog for persistent on-disk audit.
## Anywhere in the script that performs a remote operation should call
## Track-Action after the operation finishes (success or failure).
#region === SESSION STATS TRACKING ===
function Track-Action {
    param([string]$Action, [string]$Target, [string]$Result, [string]$Detail = "")
    switch ($Action) {
        'Scan'        { $global:Stats.Scanned++ }
        'PatchUpdate' { $global:Stats.Updated++ }
        'PatchApp'    { $global:Stats.AppsInstalled++ }
        'Install'     { $global:Stats.AppsInstalled++ }
        'Uninstall'   { $global:Stats.AppsUninstalled++ }
        'Reinstall'   { $global:Stats.AppsReinstalled++ }
        'Repair'      { $global:Stats.AppsRepaired++ }
        'Reboot'      { $global:Stats.Reboots++ }
    }
    [void]$global:ActionHistory.Add([PSCustomObject]@{
        Time    = (Get-Date).ToString("HH:mm:ss")
        Action  = $Action
        Target  = $Target
        Result  = $Result
        Detail  = $Detail
    })
    Update-StatLabels
    Write-AuditLog -Action $Action -Target $Target -Result $Result -Detail $Detail

    ## JANET centralized logging (added in v6.2.0). Maps WPT's internal
    ## Action names to the JANET schema and emits one detail row per call.
    ## 'Scan' and 'Reboot' are not JANET-tracked. No-op when no session.
    $janetAction = switch ($Action) {
        'PatchUpdate' { 'VulnPatched' }
        'PatchApp'    { 'VulnPatched' }
        'Install'     { 'VulnPatched' }
        'Uninstall'   { 'VulnPatched' }
        'Reinstall'   { 'VulnPatched' }
        'Repair'      { 'VulnPatched' }
        default       { $null }   # 'Scan'/'Reboot' stay untracked (unchanged design)
    }
    if ($null -ne $janetAction -and $null -ne $script:JanetSession) {
        $itemCount = 0
        if ($janetAction -eq 'VulnPatched' -and -not [string]::IsNullOrWhiteSpace($Detail)) {
            $itemCount = ($Detail -split ',' | Where-Object { $_.Trim() }).Count
        }
        $janetResult = if ($Result -match '(?i)^(success|ok|pass|sent|triggered)') { 'Success' }
                       elseif ($Result -match '(?i)^skip')           { 'Skipped' }
                       else                                           { 'Failure' }
        try {
            Write-JanetAction -Action $janetAction -Target $Target -Result $janetResult -ItemCount $itemCount -Detail $Detail
        } catch {
            ## Never let a logging failure interrupt the actual operation.
            Write-Host ("WARNING: JANET Write-JanetAction failed: $_") -ForegroundColor Yellow
        }
    }
}

function Update-StatLabels {
    if ($null -eq $script:lblStatScanned) { return }
    $script:lblStatScanned.Text     = "$($global:Stats.Scanned)"
    $script:lblStatUpdated.Text     = "$($global:Stats.Updated)"
    $script:lblStatInstalled.Text   = "$($global:Stats.AppsInstalled)"
    $script:lblStatUninstalled.Text = "$($global:Stats.AppsUninstalled)"
    $script:lblStatReinstalled.Text = "$($global:Stats.AppsReinstalled)"
    $script:lblStatRepaired.Text    = "$($global:Stats.AppsRepaired)"
    $script:lblStatReboots.Text     = "$($global:Stats.Reboots)"
    if ($null -ne $script:lblHistCount) {
        $script:lblHistCount.Text = "$($global:ActionHistory.Count) action(s) recorded"
    }
}
#endregion

###############################################################################
###                            HELPER FUNCTIONS                             ###
###############################################################################
## Legacy-style control factories + utility functions used by most tabs:
##   New-Btn / New-Lbl / New-Tb / New-Grp - flat-styled WinForms
##     Button / Label / TextBox / GroupBox matching the $c palette.
##     Not corner-bracketed (that's New-WptCard in the modular factories).
##   Style-Grid           - applies palette + font to an existing
##     DataGridView. Modern equivalent is Set-WptGridStyle.
##   Log                  - writes to the Activity Log tab's RichTextBox
##     (color-coded by level: OK=green, WARN=amber, ERR=red, default=
##     console green) and forwards to Write-AuditLog.
##   Parse-Hosts          - tokenizes a blob of pasted text into a unique
##     hostname array (splits on comma/whitespace/newline).
##   Initialize-RunspacePool - lazy pool init. Disposes existing pool
##     before creating a new one (v43 leak fix). Thread count pulled from
##     $global:ThreadCount.
#region === HELPER FUNCTIONS ===
function New-Btn {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 140, [int]$H = 30,
          [System.Drawing.Color]$Bg = $c.Accent, [System.Drawing.Color]$Fg = $c.White, $Font = $fn.Btn)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text; $btn.Location = New-Object System.Drawing.Point($X, $Y)
    $btn.Size = New-Object System.Drawing.Size($W, $H)
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $Bg; $btn.ForeColor = $Fg; $btn.Font = $Font
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $r2 = [Math]::Min(255, $Bg.R + 25); $g2 = [Math]::Min(255, $Bg.G + 25); $b2 = [Math]::Min(255, $Bg.B + 25)
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($r2, $g2, $b2)
    return $btn
}

function New-Lbl {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 200, [int]$H = 18,
          $Font = $fn.Label, [System.Drawing.Color]$Fg = $c.TextSec)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text; $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size($W, $H); $lbl.ForeColor = $Fg; $lbl.Font = $Font
    return $lbl
}

function New-Tb {
    param([int]$X, [int]$Y, [int]$W, [int]$H = 24, [switch]$Multi)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point($X, $Y); $tb.Size = New-Object System.Drawing.Size($W, $H)
    $tb.BackColor = $c.Input; $tb.ForeColor = $c.White; $tb.Font = $fn.Label; $tb.BorderStyle = 'FixedSingle'
    if ($Multi) { $tb.Multiline = $true; $tb.ScrollBars = 'Vertical' }
    return $tb
}

function New-Grp {
    param([string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H, [System.Drawing.Color]$Fg = $c.Cyan)
    $gb = New-Object System.Windows.Forms.GroupBox
    $gb.Text = "  $Text  "; $gb.Location = New-Object System.Drawing.Point($X, $Y)
    $gb.Size = New-Object System.Drawing.Size($W, $H); $gb.ForeColor = $Fg
    $gb.BackColor = $c.Panel; $gb.Font = $fn.GrpHdr
    return $gb
}

function Log($msg, $lvl = 'INFO') {
    if ($null -eq $script:rtbLog) { return }
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    try {
        if (-not $script:rtbLog.IsHandleCreated) { $script:rtbLog.CreateControl() }
        $start = $script:rtbLog.TextLength
        $script:rtbLog.AppendText($line)
        $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
        $script:rtbLog.Select($start, $line.Length)
        $script:rtbLog.SelectionColor = $clr
        $script:rtbLog.SelectionLength = 0
        $script:rtbLog.ScrollToCaret()
    } catch {
        try { $script:rtbLog.AppendText($line) } catch {}
    }
}

function Parse-Hosts([string]$Text) {
    return @($Text -split "[,\r\n\s]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | Select-Object -Unique)
}

## v43 FIX: Dispose existing RunspacePool before creating a new one to prevent
## handle/runspace leaks across repeated scan/install operations.
function Initialize-RunspacePool {
    if ($null -ne $script:RSPool) {
        try { $script:RSPool.Close(); $script:RSPool.Dispose() } catch {}
        $script:RSPool = $null
    }
    $script:RSPool = [RunspaceFactory]::CreateRunspacePool(1, $global:ThreadCount)
    $script:RSPool.ApartmentState = 'MTA'; $script:RSPool.Open()
}

function Style-Grid($dgv) {
    $dgv.BackgroundColor = $c.GridBg; $dgv.GridColor = $c.InputBdr
    $dgv.BorderStyle = 'None'; $dgv.CellBorderStyle = 'SingleHorizontal'
    $dgv.EnableHeadersVisualStyles = $false
    $dgv.ColumnHeadersDefaultCellStyle.BackColor = $c.GridHdr
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $c.Gold
    $dgv.ColumnHeadersDefaultCellStyle.Font = $fn.LabelB
    $dgv.ColumnHeadersHeight = 28
    $dgv.DefaultCellStyle.BackColor = $c.GridBg
    $dgv.DefaultCellStyle.ForeColor = $c.White
    $dgv.DefaultCellStyle.SelectionBackColor = $c.Accent
    $dgv.DefaultCellStyle.Font = $fn.Small
    $dgv.AlternatingRowsDefaultCellStyle.BackColor = $c.GridAlt
    $dgv.RowHeadersVisible = $false
    $dgv.AllowUserToAddRows = $false; $dgv.AllowUserToDeleteRows = $false
    $dgv.SelectionMode = 'FullRowSelect'; $dgv.MultiSelect = $true
    $dgv.AutoSizeColumnsMode = 'Fill'
}
#endregion

###############################################################################
###                        MODULAR THEMED FACTORIES                         ###
###############################################################################
## Inlined from modular WPT v2.4.0 Tools\UI\Controls.ps1 (factories) and
## Grid.ps1 (grid helpers). All read theme/font data from
## $script:WPT.UI.Theme / .Fonts (populated by Initialize-WptTheme).
## ~25 factories total:
##   New-WptButton / New-WptPrimaryButton / New-WptGhostButton /
##     New-WptStripeButton - flat buttons with hover + auto-contrast.
##   New-WptLabel / New-WptTextBox / New-WptRichTextBox /
##     New-WptCheckBox / New-WptComboBox / New-WptNumericUpDown /
##     New-WptListBox - themed inputs.
##   New-WptGroupBox      - flat group box (no corner brackets).
##   New-WptCard          - corner-bracketed panel with optional header.
##     Used by modular-style tabs for the "tactical" look.
##   New-WptTabPage / New-WptHeading / New-WptSeparator /
##     New-WptIconLabel / New-WptBadge / New-WptPulseIndicator /
##     Set-WptPulseState - structural widgets.
##   New-WptNavItem / Set-WptNavItemActive - numbered sidebar nav items
##     with accent-bar active state + hover.
##   New-WptGridPaperBackground / New-WptScanlineOverlay - decorative
##     Paint handlers.
##   New-WptDataGridView / Set-WptGridStyle / Add-WptGridColumn -
##     themed DataGridView with AutoResizeColumns on SizeChanged.
#region === MODULAR THEMED FACTORIES (Phase 2 migration targets) ===
## Below are 24 themed control factory functions verbatim from
## modular WPT v2.4.0 Tools\UI\Controls.ps1 for Phase 2 per-tab restyle tasks.
## Theme and Fonts initialized by Task 1.5a; these factories reference them.

function New-WptButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Bg = $null, $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Bg)   { $Bg = $theme.Accent1 }
    if (-not $Fg) {
        ## Auto-contrast: if the background is bright, use dark text;
        ## if dark (PanelLight, SurfaceAlt, etc.), use light text. Kills the
        ## "dark text on dark button" unreadability problem for callers that
        ## pass -Bg $theme.PanelLight / $theme.Surface / etc. without -Fg.
        $lum = (0.299 * $Bg.R + 0.587 * $Bg.G + 0.114 * $Bg.B) / 255.0
        if ($lum -gt 0.55) { $Fg = $theme.TextOnAccent }
        else               { $Fg = $theme.TextPrimary }
    }
    if (-not $Font) { $Font = $fonts.Btn }

    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Bg
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.TextAlign = 'MiddleCenter'
    $b.UseVisualStyleBackColor = $false
    $hover = [System.Drawing.Color]::FromArgb([Math]::Min(255,$Bg.R+28), [Math]::Min(255,$Bg.G+28), [Math]::Min(255,$Bg.B+28))
    $down  = [System.Drawing.Color]::FromArgb([Math]::Max(0,$Bg.R-20), [Math]::Max(0,$Bg.G-20), [Math]::Max(0,$Bg.B-20))
    $b.FlatAppearance.MouseOverBackColor = $hover
    $b.FlatAppearance.MouseDownBackColor = $down
    return $b
}

function New-WptLabel {
    [CmdletBinding()]
    param(
        [string]$Text = '',
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 18,
        $Font = $null, $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.Body }
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.Font      = $Font
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

function New-WptTextBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26,
        [switch]$Multi
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location    = New-Object System.Drawing.Point($X, $Y)
    $t.Size        = New-Object System.Drawing.Size($W, $H)
    $t.BackColor   = $theme.Input
    $t.ForeColor   = $theme.TextPrimary
    $t.Font        = $fonts.Mono
    $t.BorderStyle = 'FixedSingle'
    if ($Multi) { $t.Multiline = $true; $t.ScrollBars = 'Vertical' }
    return $t
}

function New-WptGroupBox {
    ## Legacy - prefer New-WptCard for new code
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
        $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text      = " $($Text.ToUpperInvariant()) "
    $g.Location  = New-Object System.Drawing.Point($X, $Y)
    $g.Size      = New-Object System.Drawing.Size($W, $H)
    $g.ForeColor = $Fg
    $g.BackColor = $theme.Surface
    $g.Font      = $fonts.Eyebrow
    return $g
}

function New-WptRichTextBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 600, [int]$H = 200
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $r = New-Object System.Windows.Forms.RichTextBox
    $r.Location    = New-Object System.Drawing.Point($X, $Y)
    $r.Size        = New-Object System.Drawing.Size($W, $H)
    $r.BackColor   = $theme.ConsoleBg
    $r.ForeColor   = $theme.ConsoleFg
    $r.Font        = $fonts.Mono
    $r.ReadOnly    = $true
    $r.BorderStyle = 'None'
    $r.WordWrap    = $false
    $r.ScrollBars  = 'Vertical'
    return $r
}

function New-WptCheckBox {
    <#
    .SYNOPSIS
        Owner-drawn tactical checkbox. Paints an amber box + check glyph
        that's visible on the dark theme (the default FlatStyle=Flat check
        is invisible on dark backgrounds - the square renders white/black
        and the check vanishes).

    .DESCRIPTION
        Uses Appearance='Button' so WinForms doesn't try to paint the
        native check square at all. We then custom-draw in the Paint
        handler: a 14px box on the left, amber border when unchecked,
        filled amber with a white check glyph when checked.

        Still a real CheckBox internally, so .Checked and
        .CheckedChanged work exactly like the standard control.
    #>
    [CmdletBinding()]
    param(
        [string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 250, [int]$H = 24,
        $Fg = $null, [bool]$Checked = $false
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.TextPrimary }

    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text       = $Text
    $c.Location   = New-Object System.Drawing.Point($X, $Y)
    $c.Size       = New-Object System.Drawing.Size($W, $H)
    $c.ForeColor  = $Fg
    $c.BackColor  = $theme.Surface               ## solid, not transparent
    $c.Font       = $fonts.Body
    $c.Checked    = $Checked
    $c.Cursor     = [System.Windows.Forms.Cursors]::Hand
    $c.Appearance = 'Button'                     ## no native checkbox square
    $c.FlatStyle  = 'Flat'
    $c.FlatAppearance.BorderSize          = 0
    $c.FlatAppearance.CheckedBackColor    = $theme.Surface
    $c.FlatAppearance.MouseOverBackColor  = $theme.SurfaceHover
    $c.FlatAppearance.MouseDownBackColor  = $theme.SurfaceActive
    $c.TextAlign  = 'MiddleLeft'
    $c.Padding    = New-Object System.Windows.Forms.Padding(26, 0, 0, 0)
    $c.AutoSize   = $false

    ## Closure captures for Paint
    $borderOff  = $theme.BorderStrong
    $borderOn   = $theme.Accent1
    $fillOn     = $theme.Accent1
    $checkFg    = $theme.TextOnAccent

    $c.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $box = 14
        $bx  = 4
        $by  = [int](($sender.Height - $box) / 2)

        if ($sender.Checked) {
            $fill = New-Object System.Drawing.SolidBrush($fillOn)
            try { $g.FillRectangle($fill, $bx, $by, $box, $box) }
            finally { $fill.Dispose() }
            $pen = New-Object System.Drawing.Pen($borderOn, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) }
            finally { $pen.Dispose() }
            ## Check glyph - 3-segment tick
            $cp = New-Object System.Drawing.Pen($checkFg, 2)
            try {
                $p1 = New-Object System.Drawing.Point(($bx + 3),  ($by + 7))
                $p2 = New-Object System.Drawing.Point(($bx + 6),  ($by + 10))
                $p3 = New-Object System.Drawing.Point(($bx + 11), ($by + 4))
                $g.DrawLines($cp, @($p1, $p2, $p3))
            } finally { $cp.Dispose() }
        } else {
            $pen = New-Object System.Drawing.Pen($borderOff, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) }
            finally { $pen.Dispose() }
        }
    }.GetNewClosure())

    ## Force a repaint on toggle so the Paint handler runs
    $c.Add_CheckedChanged({ $sender = $args[0]; $sender.Invalidate() })

    return $c
}

function New-WptComboBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26,
        [string[]]$Items = @()
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Location      = New-Object System.Drawing.Point($X, $Y)
    $cb.Size          = New-Object System.Drawing.Size($W, $H)
    $cb.BackColor     = $theme.Input
    $cb.ForeColor     = $theme.TextPrimary
    $cb.Font          = $fonts.Mono
    $cb.DropDownStyle = 'DropDownList'
    $cb.FlatStyle     = 'Flat'
    foreach ($i in $Items) { [void]$cb.Items.Add($i) }
    return $cb
}

function New-WptNumericUpDown {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 70, [int]$H = 26,
        [int]$Min = 0, [int]$Max = 100, [int]$Value = 0
    )
    $theme = $script:WPT.UI.Theme
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Location    = New-Object System.Drawing.Point($X, $Y)
    $n.Size        = New-Object System.Drawing.Size($W, $H)
    $n.Minimum     = $Min
    $n.Maximum     = $Max
    $n.Value       = $Value
    $n.BackColor   = $theme.Input
    $n.ForeColor   = $theme.TextPrimary
    $n.BorderStyle = 'FixedSingle'
    $n.Font        = $script:WPT.UI.Fonts.Mono
    return $n
}

function New-WptListBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 300, [int]$H = 200
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Location      = New-Object System.Drawing.Point($X, $Y)
    $lb.Size          = New-Object System.Drawing.Size($W, $H)
    $lb.BackColor     = $theme.Input
    $lb.ForeColor     = $theme.Accent1        ## amber text in lists -- tactical
    $lb.Font          = $fonts.Mono
    $lb.BorderStyle   = 'FixedSingle'
    $lb.SelectionMode = 'MultiExtended'
    return $lb
}

function New-WptTabPage {
    <#
    .SYNOPSIS
        Tab-like content container. Name is kept for continuity but this
        now returns a Panel, not a TabPage - v48.2 abandoned the hidden-
        TabControl trick in favor of sidebar-driven Panel swap.

    .DESCRIPTION
        Each "tab" is a Dock=Fill Panel living in a shared content host.
        Nav click sets .Visible=$true on one panel and $false on the rest.
        Nothing to clip, no DPI-dependent offsets, no tab strip to hide.

        The tab's name is stored on .Tag so MainForm's activateByIndex
        can look it up if it needs to.
    #>
    [CmdletBinding()]
    param([string]$Text)
    $theme = $script:WPT.UI.Theme
    $tp = New-Object System.Windows.Forms.Panel
    $tp.Tag       = $Text
    $tp.BackColor = $theme.Background
    $tp.Dock      = 'Fill'
    $tp.Visible   = $false
    $tp.Padding   = New-Object System.Windows.Forms.Padding(0)
    return $tp
}

function New-WptCard {
    <#
    .SYNOPSIS
        "Brief box" - a Surface panel with corner brackets instead of a full border.

    .DESCRIPTION
        Draws 4 L-shaped corner brackets in Accent1 instead of a full rectangle
        outline. This is the signature tactical-HUD look. A thin dotted line
        runs along the inside top beneath the header for visual structure.

    .PARAMETER Header
        Shown as an eyebrow in monospace bold. Force-uppercased.

    .PARAMETER Fg
        Corner bracket + header color (default Accent1 amber).
    #>
    [CmdletBinding()]
    param(
        [string]$Header,
        [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
        $Fg = $null,
        [int]$Padding = 20,
        [int]$BracketLen = 18,
        [int]$BracketThick = 2
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }

    $card = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($X, $Y)
    $card.Size      = New-Object System.Drawing.Size($W, $H)
    $card.BackColor = $theme.Surface
    $card.Padding   = New-Object System.Windows.Forms.Padding($Padding)

    ## Owner-drawn corner brackets + dotted header underline
    $bracketColor = $Fg
    $underColor   = [System.Drawing.Color]::FromArgb(90, $Fg.R, $Fg.G, $Fg.B)  ## 35% alpha
    $hasHdr       = -not [string]::IsNullOrWhiteSpace($Header)

    $card.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'HighQuality'
        $pen = New-Object System.Drawing.Pen($bracketColor, $BracketThick)
        try {
            $w = $sender.Width  - 1
            $h = $sender.Height - 1
            $L = $BracketLen
            ## Top-left
            $g.DrawLine($pen, 0, 0, $L, 0)
            $g.DrawLine($pen, 0, 0, 0, $L)
            ## Top-right
            $g.DrawLine($pen, ($w - $L), 0, $w, 0)
            $g.DrawLine($pen, $w, 0, $w, $L)
            ## Bottom-left
            $g.DrawLine($pen, 0, ($h - $L), 0, $h)
            $g.DrawLine($pen, 0, $h, $L, $h)
            ## Bottom-right
            $g.DrawLine($pen, ($w - $L), $h, $w, $h)
            $g.DrawLine($pen, $w, ($h - $L), $w, $h)
        } finally { $pen.Dispose() }

        if ($hasHdr) {
            ## Dotted underline beneath the header at y=38
            $dotPen = New-Object System.Drawing.Pen($underColor, 1)
            $dotPen.DashStyle = 'Dot'
            try {
                $g.DrawLine($dotPen, $Padding, 40, ($sender.Width - $Padding), 40)
            } finally { $dotPen.Dispose() }
        }
    }.GetNewClosure())

    if ($hasHdr) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text      = "/ $($Header.ToUpperInvariant())"
        $hdr.Location  = New-Object System.Drawing.Point($Padding, 14)
        $hdr.Size      = New-Object System.Drawing.Size(($W - $Padding * 2), 22)
        $hdr.ForeColor = $Fg
        $hdr.BackColor = [System.Drawing.Color]::Transparent
        $hdr.Font      = $fonts.Eyebrow
        $card.Controls.Add($hdr)
    }

    return $card
}

function New-WptHeading {
    <#
    .SYNOPSIS
        Bracketed tactical section header: [ 03 / SECTION TITLE ]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('H1','H2','H3')][string]$Level = 'H2',
        [int]$X = 0, [int]$Y = 0, [int]$W = 600, [int]$H = 30,
        $Fg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.TextPrimary }
    $font = switch ($Level) {
        'H1' { $fonts.DisplayLg }
        'H2' { $fonts.DisplayMd }
        default { $fonts.DisplaySm }
    }
    $h = New-Object System.Windows.Forms.Label
    $h.Text      = $Text
    $h.Location  = New-Object System.Drawing.Point($X, $Y)
    $h.Size      = New-Object System.Drawing.Size($W, $H)
    $h.ForeColor = $Fg
    $h.BackColor = [System.Drawing.Color]::Transparent
    $h.Font      = $font
    return $h
}

function New-WptSeparator {
    [CmdletBinding()]
    param([int]$X = 0, [int]$Y = 0, [int]$W = 400, $Color = $null)
    $theme = $script:WPT.UI.Theme
    if (-not $Color) { $Color = $theme.Border }
    $s = New-Object System.Windows.Forms.Panel
    $s.Location  = New-Object System.Drawing.Point($X, $Y)
    $s.Size      = New-Object System.Drawing.Size($W, 1)
    $s.BackColor = $Color
    return $s
}

function New-WptIconLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][char]$Glyph,
        [int]$X = 0, [int]$Y = 0, [int]$W = 24, [int]$H = 24,
        $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg)   { $Fg   = $theme.TextPrimary }
    if (-not $Font) { $Font = $fonts.Icon }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = [string]$Glyph
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.Font      = $Font
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-WptPrimaryButton {
    <#
    .SYNOPSIS
        Flat amber CTA - tactical primary action.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 180, [int]$H = 38,
        $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.DisplaySm }
    $b = New-WptButton -Text $Text.ToUpperInvariant() -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $Font
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover
    return $b
}

function New-WptGhostButton {
    <#
    .SYNOPSIS
        Outline-style secondary button.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Fg = $null, $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    if (-not $Font) { $Font = $fonts.Btn }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.BorderColor = $theme.Border
    $b.BackColor = [System.Drawing.Color]::Transparent
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $b.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    return $b
}

function New-WptStripeButton {
    <#
    .SYNOPSIS
        Primary button with a diagonal yellow/black caution stripe accent
        along the bottom 4px - the "launch" button in a tactical tool.

    .DESCRIPTION
        Diagonal hatching painted via GDI+ HatchBrush (ForwardDiagonal). The
        stripe spans the full button width, 4px tall, anchored to the bottom.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 220, [int]$H = 48,
        $Font = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Font) { $Font = $fonts.DisplayMd }
    $b = New-WptButton -Text $Text.ToUpperInvariant() -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $Font
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover

    ## Diagonal stripe at the bottom
    $stripeHeight = 4
    $stripeColor1 = $theme.StripeYellow
    $stripeColor2 = $theme.StripeBlack
    $b.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush('WideDownwardDiagonal', $stripeColor2, $stripeColor1)
        try {
            $rect = New-Object System.Drawing.Rectangle(0, ($sender.Height - $stripeHeight), $sender.Width, $stripeHeight)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())

    return $b
}

function New-WptBadge {
    <#
    .SYNOPSIS
        Small uppercase monospace tag for status / category pills.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 80, [int]$H = 20,
        $Fg = $null, $Bg = $null
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts
    if (-not $Fg) { $Fg = $theme.Accent1 }
    if (-not $Bg) { $Bg = [System.Drawing.Color]::FromArgb(40, $Fg.R, $Fg.G, $Fg.B) }

    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text.ToUpperInvariant()
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = $Bg
    $l.Font      = $fonts.MonoTiny
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-WptPulseIndicator {
    <#
    .SYNOPSIS
        Small animated status dot (6px). Blinks at ~1.2s cycle.

    .DESCRIPTION
        Stores a Forms.Timer on the control's Tag. Caller is responsible for
        calling .Tag.Timer.Stop()/Dispose() on form close (MainForm handles
        this generically via the $script:WPT.UI.Controls cleanup loop).

        Three modes available via -State:
          Active   - blinks Success green
          Idle     - solid TextMuted (no animation)
          Alert    - blinks Danger red (fast)
    #>
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$Size = 10,
        [ValidateSet('Active','Idle','Alert')][string]$State = 'Idle'
    )
    $theme = $script:WPT.UI.Theme
    $p = New-Object System.Windows.Forms.Panel
    $p.Location  = New-Object System.Drawing.Point($X, $Y)
    $p.Size      = New-Object System.Drawing.Size($Size, $Size)
    $p.BackColor = [System.Drawing.Color]::Transparent

    $color1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $color2 = [System.Drawing.Color]::FromArgb(40, $color1.R, $color1.G, $color1.B)

    $p.Tag = @{ Phase = 0; State = $State; C1 = $color1; C2 = $color2 }

    $p.Add_Paint({
        param($sender, $e)
        $t = $sender.Tag
        $c = if ($t.Phase -eq 0 -or $t.State -eq 'Idle') { $t.C1 } else { $t.C2 }
        $e.Graphics.SmoothingMode = 'AntiAlias'
        $brush = New-Object System.Drawing.SolidBrush($c)
        try {
            $e.Graphics.FillEllipse($brush, 0, 0, ($sender.Width - 1), ($sender.Height - 1))
        } finally { $brush.Dispose() }
    }.GetNewClosure())

    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({
            $p.Tag.Phase = 1 - $p.Tag.Phase
            $p.Invalidate()
        }.GetNewClosure())
        $timer.Start()
        $p.Tag.Timer = $timer
    }
    return $p
}

function Set-WptPulseState {
    <#
    .SYNOPSIS
        Change the pulse dot's state at runtime (e.g. Idle -> Active when
        the session starts).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Indicator,
        [ValidateSet('Active','Idle','Alert')][string]$State
    )
    $theme = $script:WPT.UI.Theme
    $t = $Indicator.Tag
    $t.State = $State
    $t.C1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $t.C2 = [System.Drawing.Color]::FromArgb(40, $t.C1.R, $t.C1.G, $t.C1.B)

    if ($t.Timer) { $t.Timer.Stop(); $t.Timer.Dispose(); $t.Timer = $null }
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({
            $Indicator.Tag.Phase = 1 - $Indicator.Tag.Phase
            $Indicator.Invalidate()
        }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Indicator.Invalidate()
}

function New-WptNavItem {
    <#
    .SYNOPSIS
        Tactical numbered nav item: [ 03 ]  * ICON  LABEL   with left accent bar.

    .DESCRIPTION
        Layout:
          +-----+---+----+------------------+
          | bar | # | ico| LABEL            |
          +-----+---+----+------------------+
          bar: 3px wide, accent color, visible only when active
          #:   monospace two-digit index (01, 02, ...)
          ico: Segoe MDL2 glyph
          label: uppercased body text

        States:
          idle     - sidebar bg, muted text
          hover    - SurfaceHover bg, primary text
          active   - SurfaceActive bg, amber accent bar + amber icon, primary text

    .PARAMETER Index
        1-based index shown left of the icon as "01", "02", etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][char]$Icon,
        [Parameter(Mandatory)][int]$Index,
        [int]$Y = 0,
        [int]$W = 240, [int]$H = 42
    )
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts

    $item = New-Object System.Windows.Forms.Panel
    $item.Location  = New-Object System.Drawing.Point(0, $Y)
    $item.Size      = New-Object System.Drawing.Size($W, $H)
    $item.BackColor = $theme.Sidebar
    $item.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $item.Tag       = @{ Key = $Key; IsActive = $false }

    ## Left accent bar (3px, visible only when active)
    $bar = New-Object System.Windows.Forms.Panel
    $bar.Location  = New-Object System.Drawing.Point(0, 6)
    $bar.Size      = New-Object System.Drawing.Size(3, ($H - 12))
    $bar.BackColor = $theme.Accent1
    $bar.Visible   = $false
    $item.Controls.Add($bar)

    ## Index number (monospace, left of icon)
    $num = New-Object System.Windows.Forms.Label
    $num.Text      = '{0:D2}' -f $Index
    $num.Location  = New-Object System.Drawing.Point(16, 0)
    $num.Size      = New-Object System.Drawing.Size(24, $H)
    $num.Font      = $fonts.MonoSm
    $num.ForeColor = $theme.TextFaint
    $num.BackColor = [System.Drawing.Color]::Transparent
    $num.TextAlign = 'MiddleLeft'
    $item.Controls.Add($num)

    ## Icon glyph
    $ico = New-Object System.Windows.Forms.Label
    $ico.Text      = [string]$Icon
    $ico.Location  = New-Object System.Drawing.Point(44, 0)
    $ico.Size      = New-Object System.Drawing.Size(22, $H)
    $ico.Font      = $fonts.Icon
    $ico.ForeColor = $theme.TextSecondary
    $ico.BackColor = [System.Drawing.Color]::Transparent
    $ico.TextAlign = 'MiddleCenter'
    $item.Controls.Add($ico)

    ## Label text (uppercased)
    $txt = New-Object System.Windows.Forms.Label
    $txt.Text      = $Label.ToUpperInvariant()
    $txt.Location  = New-Object System.Drawing.Point(72, 0)
    $txt.Size      = New-Object System.Drawing.Size(($W - 80), $H)
    $txt.Font      = $fonts.BodyStrong
    $txt.ForeColor = $theme.TextSecondary
    $txt.BackColor = [System.Drawing.Color]::Transparent
    $txt.TextAlign = 'MiddleLeft'
    $item.Controls.Add($txt)

    ## Store refs for the activate/hover logic
    $item.Tag['Bar']  = $bar
    $item.Tag['Num']  = $num
    $item.Tag['Icon'] = $ico
    $item.Tag['Text'] = $txt

    ## Palette captures for closures
    $sidebarBg = $theme.Sidebar
    $hoverBg   = $theme.SurfaceHover
    $activeBg  = $theme.SurfaceActive
    $dimFg     = $theme.TextSecondary
    $faintFg   = $theme.TextFaint
    $onFg      = $theme.TextPrimary
    $accentFg  = $theme.Accent1

    $refreshVisual = {
        param($panel)
        $isActive = [bool]$panel.Tag['IsActive']
        $panel.Tag['Bar'].Visible = $isActive
        if ($isActive) {
            $panel.BackColor             = $activeBg
            $panel.Tag['Num'].ForeColor  = $accentFg
            $panel.Tag['Icon'].ForeColor = $accentFg
            $panel.Tag['Text'].ForeColor = $onFg
        } else {
            $panel.BackColor             = $sidebarBg
            $panel.Tag['Num'].ForeColor  = $faintFg
            $panel.Tag['Icon'].ForeColor = $dimFg
            $panel.Tag['Text'].ForeColor = $dimFg
        }
    }.GetNewClosure()
    $item.Tag['Refresh'] = $refreshVisual

    ## Helper: walk up from the hovered control to the nav-item Panel.
    ## The earlier "$sender -is Panel" shortcut was wrong -- the accent BAR
    ## is also a Panel, and hovering over it made $panel = $bar which has a
    ## null Tag, crashing with "Cannot index into a null array" on the next
    ## Tag access. Nav items are uniquely identified by having a Tag that's
    ## a hashtable containing a 'Key' entry; walk parents until we find one.
    $findNavPanel = {
        param($startCtl)
        $p = $startCtl
        while ($p) {
            if ($p.Tag -is [hashtable] -and $p.Tag.ContainsKey('Key')) { return $p }
            $p = $p.Parent
        }
        return $null
    }.GetNewClosure()

    $onEnter = {
        param($sender, $e)
        $panel = & $findNavPanel $sender
        if (-not $panel) { return }
        if (-not [bool]$panel.Tag['IsActive']) {
            $panel.BackColor             = $hoverBg
            $panel.Tag['Num'].ForeColor  = $dimFg
            $panel.Tag['Icon'].ForeColor = $onFg
            $panel.Tag['Text'].ForeColor = $onFg
        }
    }.GetNewClosure()
    $onLeave = {
        param($sender, $e)
        $panel = & $findNavPanel $sender
        if (-not $panel) { return }
        & $panel.Tag['Refresh'] $panel
    }.GetNewClosure()

    $item.Add_MouseEnter($onEnter); $item.Add_MouseLeave($onLeave)
    foreach ($child in @($bar, $num, $ico, $txt)) {
        $child.Add_MouseEnter($onEnter)
        $child.Add_MouseLeave($onLeave)
    }
    return $item
}

function Set-WptNavItemActive {
    <#
    .SYNOPSIS
        Activate one nav item and deactivate all its siblings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SidebarPanel,
        [Parameter(Mandatory)][string]$Key
    )
    foreach ($child in $SidebarPanel.Controls) {
        if ($child -is [System.Windows.Forms.Panel] -and $child.Tag -is [hashtable] -and $child.Tag.ContainsKey('Key')) {
            $child.Tag['IsActive'] = ($child.Tag['Key'] -eq $Key)
            & $child.Tag['Refresh'] $child
        }
    }
}

function New-WptGridPaperBackground {
    <#
    .SYNOPSIS
        Attach a Paint handler to a Panel that draws 1px dots on a 16x16 grid.

    .DESCRIPTION
        Gives content areas a subtle technical-paper texture. The dot color is
        a heavily alpha-faded TextMuted so it reads as texture, not noise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Panel,
        [int]$Spacing = 16
    )
    $theme = $script:WPT.UI.Theme
    $dotColor = [System.Drawing.Color]::FromArgb(18, $theme.TextMuted.R, $theme.TextMuted.G, $theme.TextMuted.B)

    $Panel.Add_Paint({
        param($sender, $e)
        $brush = New-Object System.Drawing.SolidBrush($dotColor)
        try {
            $w = $sender.Width
            $h = $sender.Height
            for ($x = $Spacing; $x -lt $w; $x += $Spacing) {
                for ($y = $Spacing; $y -lt $h; $y += $Spacing) {
                    $e.Graphics.FillRectangle($brush, $x, $y, 1, 1)
                }
            }
        } finally { $brush.Dispose() }
    }.GetNewClosure())
}

function New-WptScanlineOverlay {
    <#
    .SYNOPSIS
        Paint subtle horizontal 1px lines every 3px with low alpha - gives
        a panel a CRT/scanline feel.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Panel)
    $theme = $script:WPT.UI.Theme
    $lineColor = [System.Drawing.Color]::FromArgb(10, 255, 255, 255)
    $Panel.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen($lineColor, 1)
        try {
            for ($y = 0; $y -lt $sender.Height; $y += 3) {
                $e.Graphics.DrawLine($pen, 0, $y, $sender.Width, $y)
            }
        } finally { $pen.Dispose() }
    }.GetNewClosure())
}

## --- Grid factories from modular Tools\UI\Grid.ps1 ---

function New-WptDataGridView {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 800, [int]$H = 400,
        [switch]$ReadOnly
    )
    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Location = New-Object System.Drawing.Point($X, $Y)
    $dgv.Size     = New-Object System.Drawing.Size($W, $H)
    if ($ReadOnly) { $dgv.ReadOnly = $true }
    Set-WptGridStyle -DataGridView $dgv

    ## WinForms Fill-mode column distribution is computed once, when a column
    ## is added - it isn't re-run after Anchor-driven resizes. That's why the
    ## last few columns on wide grids end up clipped off the right edge at
    ## certain DPI / window widths. Force a Fill recalculation on every
    ## SizeChanged so the columns always match the current DGV width.
    $dgv.Add_SizeChanged({
        param($sender, $e)
        try {
            $sender.AutoResizeColumns([System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill)
        } catch {}
    })

    return $dgv
}

function Set-WptGridStyle {
    <#
    .SYNOPSIS
        Apply the dark theme to an existing DataGridView.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $DataGridView)
    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts

    $dgv = $DataGridView
    $dgv.BackgroundColor   = $theme.GridBg
    $dgv.GridColor         = $theme.InputBdr
    $dgv.BorderStyle       = 'None'
    $dgv.CellBorderStyle   = 'SingleHorizontal'
    $dgv.EnableHeadersVisualStyles = $false
    $dgv.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHdr
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $theme.Gold
    $dgv.ColumnHeadersDefaultCellStyle.Font      = $fonts.LabelB
    $dgv.ColumnHeadersHeight = 28
    $dgv.DefaultCellStyle.BackColor               = $theme.GridBg
    $dgv.DefaultCellStyle.ForeColor               = $theme.White
    $dgv.DefaultCellStyle.SelectionBackColor      = $theme.Accent
    $dgv.DefaultCellStyle.Font                    = $fonts.Small
    $dgv.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAlt
    $dgv.RowHeadersVisible       = $false
    $dgv.AllowUserToAddRows      = $false
    $dgv.AllowUserToDeleteRows   = $false
    $dgv.SelectionMode           = 'FullRowSelect'
    $dgv.MultiSelect             = $true
    $dgv.AutoSizeColumnsMode     = 'Fill'
    ## Suppress horizontal scroll. Combined with Fill mode this forces all
    ## columns to always fit in the visible DGV width, shrinking proportionally
    ## rather than letting the right-most columns clip off the edge.
    $dgv.ScrollBars              = 'Vertical'
}

function Add-WptGridColumn {
    <#
    .SYNOPSIS
        Add a text column to a DataGridView with a sensible fill weight.
    .NOTES
        -HeaderText '' is respected (previous behavior fell through to $Name because
        [string]::Empty is falsy). Pass '' explicitly when you want a headerless
        column, e.g. a row-select checkbox.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $DataGridView,
        [Parameter(Mandatory)][string]$Name,
        [string]$HeaderText = $null,
        [int]$FillWeight = 10,
        [switch]$Checkbox
    )
    if ($Checkbox) {
        $col = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    } else {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    }
    $col.Name       = $Name
    ## Honor explicit empty HeaderText (caller wants a headerless column).
    ## Only fall back to $Name when the caller didn't pass -HeaderText at all.
    if ($PSBoundParameters.ContainsKey('HeaderText')) {
        $col.HeaderText = $HeaderText
    } else {
        $col.HeaderText = $Name
    }
    $col.FillWeight = $FillWeight
    [void]$DataGridView.Columns.Add($col)
    return $col
}

#endregion

###############################################################################
###                             MODULAR DIALOGS                             ###
###############################################################################
## Inlined from modular Tools\UI\Dialog.ps1 / Dialog.Closing.ps1 /
## Dialog.Info.ps1:
##   Show-WptDialog            - themed MessageBox replacement (one
##     overloaded signature that accepts Message / Title / Buttons /
##     Icon). Also exposed via the WptDialog class for drop-in
##     [WptDialog]::Show(...) call-site compatibility.
##   Show-WptClosingNotesDialog - the Submit / Force / Cancel three-way
##     dialog that fires on form close (Start-tab popup buttons can also
##     trigger it via the Usage tab's Publish Now button).
##   Show-WptInfoDialog        - scroll-capable read-only dialog with
##     title + body + Close button. Used by the three info popups.
##   Show-WptChangeLogDialog / Show-WptHowToUseDialog /
##     Show-WptAboutDialog     - thin wrappers that invoke
##     Show-WptInfoDialog with the content constants from the STATIC
##     INFO TEXT region.
#region === MODULAR DIALOGS (Show-WptInfoDialog, ClosingNotes, etc.) ===
## Verbatim copy of modular WPT v2.4.0 Tools\UI\Dialog.ps1, Dialog.Closing.ps1,
## and Dialog.Info.ps1. Used by the Phase 1 shell closing flow and available
## to Phase 2 for swapping Legacy's [MessageBox]::Show sites with themed
## dialogs.

## --- From Tools\UI\Dialog.ps1 ---

function Show-WptDialog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [Parameter(Position = 1)][string]$Title = 'J.A.N.E.T.',
        [Parameter(Position = 2)][object]$Buttons = 0,
        [Parameter(Position = 3)][object]$Icon = 0
    )

    ## --- Normalize $Buttons ------------------------------------------------
    $btnStr  = "$Buttons"
    $btnKind = 'OK'
    if     ($btnStr -eq '0' -or $btnStr -eq 'OK')                     { $btnKind = 'OK' }
    elseif ($btnStr -eq '1' -or $btnStr -eq 'OKCancel')               { $btnKind = 'OKCancel' }
    elseif ($btnStr -eq '3' -or $btnStr -eq 'YesNoCancel')            { $btnKind = 'YesNoCancel' }
    elseif ($btnStr -eq '4' -or $btnStr -eq 'YesNo')                  { $btnKind = 'YesNo' }

    ## --- Normalize $Icon ---------------------------------------------------
    $icnStr   = "$Icon"
    $iconKind = 'None'
    if     ($icnStr -eq '0'  -or $icnStr -eq 'None')                                { $iconKind = 'None' }
    elseif ($icnStr -eq '16' -or $icnStr -match '^(Error|Hand|Stop)$')              { $iconKind = 'Error' }
    elseif ($icnStr -eq '32' -or $icnStr -eq 'Question')                            { $iconKind = 'Question' }
    elseif ($icnStr -eq '48' -or $icnStr -match '^(Warning|Exclamation)$')          { $iconKind = 'Warning' }
    elseif ($icnStr -eq '64' -or $icnStr -match '^(Information|Asterisk|Info)$')    { $iconKind = 'Info' }

    $theme = $script:WPT.UI.Theme
    $fonts = $script:WPT.UI.Fonts

    ## --- Icon glyph + color per kind --------------------------------------
    $iconGlyph = ''
    $iconColor = $theme.Dim
    switch ($iconKind) {
        'Error'    { $iconGlyph = '!'; $iconColor = $theme.Danger }
        'Warning'  { $iconGlyph = '!'; $iconColor = $theme.Warning }
        'Question' { $iconGlyph = '?'; $iconColor = $theme.Accent1 }
        'Info'     { $iconGlyph = 'i'; $iconColor = $theme.Cyan }
    }
    $hasIcon = ($iconKind -ne 'None')

    ## --- Create the form --------------------------------------------------
    $form = New-Object System.Windows.Forms.Form
    $form.Text            = $Title
    $form.StartPosition   = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.ShowInTaskbar   = $false
    $form.BackColor       = $theme.Background
    $form.ForeColor       = $theme.TextPrimary
    $form.Font            = $fonts.Body
    $form.KeyPreview      = $true
    try { Enable-WptDoubleBuffer -Control $form } catch {}

    ## --- Layout constants -------------------------------------------------
    $marginX   = 24
    $marginY   = 18
    $iconW     = if ($hasIcon) { 56 } else { 0 }
    $titleH    = 36
    $accentH   = 2
    $btnRowH   = 56
    $maxTextW  = 460
    $btnW      = 100
    $btnH      = 30
    $btnSpacing = 10
    $btnRowRightInset = 24

    ## --- Count buttons to compute the minimum required width --------------
    ## (Done up here instead of after form-sizing so we can guarantee the
    ## dialog is wide enough to actually show the button row. Previously
    ## a short message + YesNo buttons ended up clipping the "Yes" / "No"
    ## labels because $clientW was derived purely from message+icon.)
    $btnCount = switch ($btnKind) {
        'OK'          { 1 }
        'OKCancel'    { 2 }
        'YesNo'       { 2 }
        'YesNoCancel' { 3 }
        default       { 1 }
    }
    $totalBtnW = ($btnCount * $btnW) + (($btnCount - 1) * $btnSpacing)
    $minBtnRowW = $marginX + $totalBtnW + $btnRowRightInset

    ## --- Measure the message so the form auto-sizes ----------------------
    $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor `
             [System.Windows.Forms.TextFormatFlags]::NoPadding
    $measureBox = New-Object System.Drawing.Size($maxTextW, 2000)
    $msgSize = [System.Windows.Forms.TextRenderer]::MeasureText(
        $Message, $fonts.Body, $measureBox, $flags)
    $msgW = [Math]::Max(260, [Math]::Min($maxTextW, [int]$msgSize.Width + 4))
    $msgH = [Math]::Max(40,  [int]$msgSize.Height + 8)

    ## Pick the widest of: content (icon+message), button row, and an
    ## absolute floor. This is the fix for the Confirm-Clear-All cutoff.
    $contentW = $marginX + $iconW + $msgW + $marginX
    $clientW  = [Math]::Max([Math]::Max($contentW, $minBtnRowW), 440)
    $clientH  = $titleH + $accentH + $marginY + $msgH + $marginY + $btnRowH
    ## Floor of 220 (was 170). Short-message YesNo dialogs like "Confirm Update"
    ## were rendering at the absolute minimum and clipping the button row off
    ## the bottom on some Win11 DPI configurations -- operators reported the
    ## App Updater confirmation had no visible Yes / No buttons. Extra headroom
    ## guarantees the docked btnRow is always on-screen.
    if ($clientH -lt 220) { $clientH = 220 }
    $form.ClientSize   = New-Object System.Drawing.Size($clientW, $clientH)
    ## Also pin MinimumSize so no layout / scaling pass can shrink the form
    ## below the height we calculated. ClientSize + border/titlebar chrome.
    $chromeH = [System.Windows.Forms.SystemInformation]::CaptionHeight + 16
    $form.MinimumSize  = New-Object System.Drawing.Size(($clientW + 16), ($clientH + $chromeH))

    ## --- Title strip (mono accent header) --------------------------------
    $titleStrip = New-Object System.Windows.Forms.Panel
    $titleStrip.Dock      = 'Top'
    $titleStrip.Height    = $titleH
    $titleStrip.BackColor = $theme.Sidebar

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = "/ $($Title.ToUpperInvariant())"
    $lblTitle.Location  = New-Object System.Drawing.Point(20, 10)
    $lblTitle.Size      = New-Object System.Drawing.Size(($clientW - 40), 20)
    $lblTitle.Font      = $fonts.LabelB
    $lblTitle.ForeColor = $theme.Accent1
    $lblTitle.BackColor = [System.Drawing.Color]::Transparent
    $titleStrip.Controls.Add($lblTitle)

    ## --- Amber accent hairline below title -------------------------------
    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock      = 'Top'
    $accent.Height    = $accentH
    $accent.BackColor = $theme.Accent1

    ## --- Button row (docked bottom) --------------------------------------
    $btnRow = New-Object System.Windows.Forms.Panel
    $btnRow.Dock      = 'Bottom'
    $btnRow.Height    = $btnRowH
    $btnRow.BackColor = $theme.Background
    ## Pin Width to $clientW *before* buttons are added. Anchor='Top,Right'
    ## records distance-from-right at add time; if the panel is still at its
    ## default 200-wide size, that distance is computed against the wrong
    ## width, and when Dock='Bottom' later grows the panel to $clientW the
    ## anchored buttons slide right by the delta and render off-screen. This
    ## is what made the "Confirm Update" dialog appear with no Yes/No buttons
    ## even after the clientH floor bump -- the buttons were there, just off
    ## the right edge of the panel.
    $btnRow.Width     = $clientW

    $btnSpecs = @()
    switch ($btnKind) {
        'OK' {
            $btnSpecs = @(
                @{ Text='OK'; Result=[System.Windows.Forms.DialogResult]::OK; Bg=$theme.Accent }
            )
        }
        'OKCancel' {
            $btnSpecs = @(
                @{ Text='OK';     Result=[System.Windows.Forms.DialogResult]::OK;     Bg=$theme.Accent },
                @{ Text='Cancel'; Result=[System.Windows.Forms.DialogResult]::Cancel; Bg=$theme.PanelLight }
            )
        }
        'YesNo' {
            $btnSpecs = @(
                @{ Text='Yes'; Result=[System.Windows.Forms.DialogResult]::Yes; Bg=$theme.Success },
                @{ Text='No';  Result=[System.Windows.Forms.DialogResult]::No;  Bg=$theme.Danger }
            )
        }
        'YesNoCancel' {
            $btnSpecs = @(
                @{ Text='Yes';    Result=[System.Windows.Forms.DialogResult]::Yes;    Bg=$theme.Success },
                @{ Text='No';     Result=[System.Windows.Forms.DialogResult]::No;     Bg=$theme.Danger },
                @{ Text='Cancel'; Result=[System.Windows.Forms.DialogResult]::Cancel; Bg=$theme.PanelLight }
            )
        }
    }

    ## Button geometry uses the constants defined at the top of this
    ## function (so $clientW could be sized to accommodate them earlier).
    $firstX = $clientW - $totalBtnW - $btnRowRightInset
    $btnY   = [int](($btnRowH - $btnH) / 2)
    $btns   = @()
    for ($i = 0; $i -lt $btnSpecs.Count; $i++) {
        $spec = $btnSpecs[$i]
        $bg   = $spec['Bg']
        $fg   = if ($spec['Text'] -eq 'Cancel') { $theme.TextPrimary } else { $theme.TextOnAccent }
        $b = New-WptButton -Text $spec['Text'] `
                -X ($firstX + $i * ($btnW + $btnSpacing)) -Y $btnY -W $btnW -H $btnH `
                -Bg $bg -Fg $fg
        $b.DialogResult = $spec['Result']
        $b.Anchor       = 'Top,Right'
        $btnRow.Controls.Add($b)
        $btns += $b
    }
    $form.AcceptButton = $btns[0]
    foreach ($b in $btns) {
        if ($b.DialogResult -eq [System.Windows.Forms.DialogResult]::Cancel -or
            $b.DialogResult -eq [System.Windows.Forms.DialogResult]::No) {
            $form.CancelButton = $b
            break
        }
    }

    ## --- Content area (Dock=Fill): icon + message ------------------------
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Dock      = 'Fill'
    $contentPanel.BackColor = $theme.Background

    if ($hasIcon) {
        $lblIcon = New-Object System.Windows.Forms.Label
        $lblIcon.Size      = New-Object System.Drawing.Size(48, 48)
        $lblIcon.Location  = New-Object System.Drawing.Point($marginX, $marginY)
        $lblIcon.Text      = $iconGlyph
        $lblIcon.Font      = New-Object System.Drawing.Font('Cascadia Mono', 26, [System.Drawing.FontStyle]::Bold)
        $lblIcon.ForeColor = $iconColor
        $lblIcon.BackColor = [System.Drawing.Color]::Transparent
        $lblIcon.TextAlign = 'MiddleCenter'
        $contentPanel.Controls.Add($lblIcon)
    }

    $lblMsg = New-Object System.Windows.Forms.Label
    $lblMsg.Text      = $Message
    $lblMsg.Location  = New-Object System.Drawing.Point(($marginX + $iconW), $marginY)
    $lblMsg.Size      = New-Object System.Drawing.Size($msgW, $msgH)
    $lblMsg.Font      = $fonts.Body
    $lblMsg.ForeColor = $theme.TextPrimary
    $lblMsg.BackColor = [System.Drawing.Color]::Transparent
    $lblMsg.AutoSize  = $false
    $contentPanel.Controls.Add($lblMsg)

    ## Assemble. Add Fill LAST so Top/Bottom docks claim their strips first.
    $form.Controls.Add($contentPanel)
    $form.Controls.Add($btnRow)
    $form.Controls.Add($accent)
    $form.Controls.Add($titleStrip)

    ## Dark immersive title bar (matches the main form's Win11 chrome)
    $form.Add_HandleCreated({
        param($sender, $e)
        try { Set-WptDarkTitleBar -Form $sender } catch {}
    })

    ## Show modal, centered on the main window if present.
    $parent = $script:WPT.UI.Form
    try {
        $result = if ($parent -and -not $parent.IsDisposed) { $form.ShowDialog($parent) }
                  else                                      { $form.ShowDialog() }
    } finally {
        $form.Dispose()
    }
    return $result
}

## -----------------------------------------------------------------------
## Drop-in replacement wrapper for [System.Windows.Forms.MessageBox]::Show
## -----------------------------------------------------------------------
## Defined as a PowerShell 5.1 class with static Show() overloads so call
## sites only need the type name swapped:
##
##     [System.Windows.Forms.MessageBox]::Show($msg, 'Title', 4, 48)
##              becomes
##     [WptDialog]::Show($msg, 'Title', 4, 48)
##
## Every overload returns a DialogResult, preserving the compare-to-'Yes'
## pattern the tabs already use.
## Return type is [object] rather than [System.Windows.Forms.DialogResult]
## because PS 5.1 resolves class method signatures at parse time, before
## WinForms is guaranteed loaded. [object] boxes the DialogResult cleanly
## and callers still compare to the string 'Yes' / 'No' / 'OK' / 'Cancel'.
class WptDialog {
    static [object] Show([string]$message) {
        return (Show-WptDialog -Message $message)
    }
    static [object] Show([string]$message, [string]$title) {
        return (Show-WptDialog -Message $message -Title $title)
    }
    static [object] Show([string]$message, [string]$title, [object]$buttons) {
        return (Show-WptDialog -Message $message -Title $title -Buttons $buttons)
    }
    static [object] Show([string]$message, [string]$title, [object]$buttons, [object]$icon) {
        return (Show-WptDialog -Message $message -Title $title -Buttons $buttons -Icon $icon)
    }
}

## --- From Tools\UI\Dialog.Closing.ps1 ---

function Show-WptClosingNotesDialog {
    [CmdletBinding()]
    param()

    $state = Get-WptState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## v6.5.16: dialog widened + retitled to mirror ACAS Nemesis's
    ## "Submit Logs + Close Tool" prompt. New header block (operator,
    ## session summary, log share path) + the explicit "Submitting will
    ## flush these artifacts to the share" bullet list above the notes
    ## textbox. Three-button outcome semantics unchanged: Submit / Force
    ## / Cancel still flow through Invoke-WptClosingFlow exactly as
    ## before, and the return shape is still { Choice; Notes }.

    ## --- Pull live session context for the header block --------------------
    $opLabel = if ($global:OperatorFolderName) { $global:OperatorFolderName } else { $env:USERNAME }
    $userTag = if ($env:USERNAME) { $env:USERNAME } else { 'unknown' }
    $month   = (Get-Date).ToString('yyyy-MM')

    ## Hosts / vulns / failures come straight off the live JANET session
    ## (Get-JanetSession is the closure-safe getter from the JANET LOGGING
    ## BLOCK). When the operator never clicked Start Session these come
    ## back zero, which is the right thing to show.
    $hosts = 0; $vulns = 0; $fails = 0
    try {
        $js = Get-JanetSession
        if ($js) {
            $hosts = [int]$js.Hosts.Count
            $vulns = [int]$js.VulnsPatched
            $fails = [int]$js.Failures
        }
    } catch {}

    ## Log share line — prefer the live $global:LogDir resolved at boot via
    ## Resolve-WptLogTarget. The lblPathIsFallback flag drives the color so
    ## a local-only fallback path lights up amber instead of green.
    $logDirShow = if ($global:LogDir) { [string]$global:LogDir } else { '(unresolved)' }
    $isFallback = $false
    try { if ($script:WptLogTarget) { $isFallback = [bool]$script:WptLogTarget.IsFallback } } catch {}

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = 'WPT - Submit Logs + Close Tool'
    $dlg.ClientSize      = New-Object System.Drawing.Size(640, 560)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.MinimizeBox     = $false
    $dlg.BackColor       = $theme.Background
    $dlg.ForeColor       = $theme.TextPrimary
    $dlg.Font            = $fonts.Body
    $dlg.Topmost         = $true
    if ($state.UI.Form -and $state.UI.Form.Icon) { $dlg.Icon = $state.UI.Form.Icon }
    try { Set-WptDarkTitleBar -Form $dlg } catch {}
    $dlg.Add_HandleCreated({ try { Set-WptDarkTitleBar -Form $dlg } catch {} })

    ## --- Header block (mirrors Show-NemClosingNotesDialog) ----------------
    ## Operator line (Accent1, like Nemesis lblOperator).
    $lblOperator = New-WptLabel `
        -Text ("Operator:  $opLabel") `
        -X 20 -Y 16 -W 600 -H 22 -Font $fonts.Body -Fg $theme.Accent1

    ## Session summary line (Accent2 / Success, like Nemesis lblSummary).
    $lblSummary = New-WptLabel `
        -Text ("Session summary: {0} host(s) touched, {1} vuln(s) patched, {2} failure(s)" -f $hosts, $vulns, $fails) `
        -X 20 -Y 42 -W 600 -H 22 -Font $fonts.Body -Fg $theme.Success

    ## Log share path. Color amber when we're on a local fallback so the
    ## operator knows the artifacts won't reach the share until next launch.
    $pathFg = if ($isFallback) { $theme.Warning } else { $theme.TextMuted }
    $pathPrefix = if ($isFallback) { 'Local only:' } else { 'Log share:' }
    $lblPath = New-WptLabel `
        -Text ("$pathPrefix  $logDirShow") `
        -X 20 -Y 68 -W 600 -H 18 -Font $fonts.Caption -Fg $pathFg

    ## "What will get flushed" header + 4-bullet list — verbatim copy of
    ## Nemesis's lblWhatSubmits / lblBullets pattern, paths swapped to
    ## WPT's actual artifacts.
    $lblWhatSubmits = New-WptLabel `
        -Text 'Submitting will flush these artifacts to the share:' `
        -X 20 -Y 94 -W 600 -H 18 -Font $fonts.Body -Fg $theme.TextSecondary

    $bullet = "  - <edipi - operator>\WPT_${userTag}_<ts>.log         (per-session transcript, every audit line)`r`n" +
              "  - <edipi - operator>\TouchedHosts_$month.csv         (one row per host this session touched)`r`n" +
              "  - <edipi - operator>\${month}_detail.csv             (JANET per-action centralized rollup)`r`n" +
              "  - JANET ${month}_usage.csv                          (centralized per-session rollup row)`r`n" +
              "  - WPT-UsageV2-$month.csv                            (legacy fleet-wide aggregate, LogDir root)"
    $lblBullets = New-WptLabel -Text $bullet `
        -X 20 -Y 116 -W 600 -H 90 -Font $fonts.Caption -Fg $theme.TextMuted

    ## --- Notes prompt + textbox (the original WPT body) -------------------
    $lblPrompt = New-WptLabel -Text 'Anything worth noting from this session?' `
        -X 20 -Y 216 -W 600 -H 22 -Font $fonts.DisplayMd -Fg $theme.Accent1
    $lblHint = New-WptLabel `
        -Text 'Notes are saved to the shared usage log alongside the session totals. Blank is fine.' `
        -X 20 -Y 244 -W 600 -H 18 -Font $fonts.Caption -Fg $theme.TextSecondary

    $txtNotes = New-Object System.Windows.Forms.TextBox
    $txtNotes.Location      = New-Object System.Drawing.Point(20, 268)
    $txtNotes.Size          = New-Object System.Drawing.Size(600, 220)
    $txtNotes.Multiline     = $true
    $txtNotes.AcceptsReturn = $true
    $txtNotes.ScrollBars    = 'Vertical'
    $txtNotes.BackColor     = $theme.Input
    $txtNotes.ForeColor     = $theme.TextPrimary
    $txtNotes.BorderStyle   = 'FixedSingle'
    $txtNotes.Font          = $fonts.Body

    ## --- Buttons (three-way, semantics unchanged) -------------------------
    ## Names mirror Nemesis's three buttons but keep WPT's outcomes:
    ##   Submit Logs + Close   == 'Submit' (notes go to audit + CSVs)
    ##   Submit (skip notes)   == 'Force'  (flush with empty notes, no validation)
    ##   Cancel Close          == 'Cancel' (return to tool, no flush)
    $btnSubmit = New-WptButton -Text 'Submit Logs + Close' -X 20  -Y 508 -W 190 -H 36 -Bg $theme.Success    -Font $fonts.Btn
    $btnForce  = New-WptButton -Text 'Submit (skip notes)' -X 220 -Y 508 -W 190 -H 36 -Bg $theme.PanelLight -Font $fonts.Btn
    $btnCancel = New-WptButton -Text 'Cancel Close'        -X 470 -Y 508 -W 150 -H 36 -Bg $theme.Danger     -Font $fonts.Btn

    $dlg.Controls.AddRange(@(
        $lblOperator, $lblSummary, $lblPath, $lblWhatSubmits, $lblBullets,
        $lblPrompt, $lblHint, $txtNotes,
        $btnSubmit, $btnForce, $btnCancel
    ))

    ## Default result: if the operator clicks the window close (X), treat as Cancel
    ## so we don't accidentally flush on an OS-level close. Esc = Cancel.
    $dlg.Tag = @{ Choice = 'Cancel'; Notes = '' }
    $dlg.CancelButton = $btnCancel

    ## GetNewClosure on each handler so the nested $dlg/$txtNotes references
    ## survive across Add_Click delegate dispatch (PS 5.1 + StrictMode).
    ## Each handler writes the outcome to $dlg.Tag as a hashtable -- the
    ## dialog object is the same reference in both scopes, so the caller
    ## reads it back after ShowDialog returns. Notes never need to cross
    ## a script-scope boundary.
    $btnSubmit.Add_Click({
        $dlg.Tag = @{ Choice = 'Submit'; Notes = [string]$txtNotes.Text }
        $dlg.Close()
    }.GetNewClosure())

    $btnForce.Add_Click({
        $dlg.Tag = @{ Choice = 'Force'; Notes = '' }
        $dlg.Close()
    }.GetNewClosure())

    $btnCancel.Add_Click({
        $dlg.Tag = @{ Choice = 'Cancel'; Notes = '' }
        $dlg.Close()
    }.GetNewClosure())

    [void]$dlg.ShowDialog($state.UI.Form)
    $outcome = $dlg.Tag
    $dlg.Dispose()
    ## Always return a hashtable, even on unexpected Tag shape (e.g., a
    ## future caller that sets $dlg.Tag to something else somewhere).
    if (-not $outcome -or -not ($outcome -is [hashtable])) {
        return [pscustomobject]@{ Choice = 'Cancel'; Notes = '' }
    }
    return [pscustomobject]@{ Choice = [string]$outcome.Choice; Notes = [string]$outcome.Notes }
}

function Invoke-WptClosingFlow {
    [CmdletBinding()]
    param()

    $outcome = Show-WptClosingNotesDialog
    $choice  = [string]$outcome.Choice
    $notes   = [string]$outcome.Notes
    if ($choice -eq 'Cancel') {
        ## Cancel path: no flush, no audit entry. Operator is going back.
        return $false
    }

    ## Flush the journal. Notes come straight from the dialog outcome --
    ## no script-scope round trip, so the text the operator typed actually
    ## arrives here intact.
    try {
        if ($choice -eq 'Force') {
            $result = Publish-WptUsageJournal -Force
        } else {
            $result = Publish-WptUsageJournal -Notes $notes
        }

        if ($result -and $result.Flushed -gt 0) {
            Write-WptAudit -Action 'UsageFlush' -Target $result.Path -Result 'OK' -Detail "Rows=$($result.Flushed) Choice=$choice"
        } elseif ($result) {
            Write-WptAudit -Action 'UsageFlush' -Result 'Skipped' -Detail "$($result.Reason) Choice=$choice"
        }
    } catch {
        Write-WptAudit -Action 'UsageFlush' -Result 'Failed' -Detail $_.Exception.Message
    }

    return $true
}

## --- From Tools\UI\Dialog.Info.ps1 ---

function Show-WptInfoDialog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$BodyText
    )

    $state = Get-WptState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = $Title
    $dlg.ClientSize      = New-Object System.Drawing.Size(820, 620)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(640, 480)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.MaximizeBox     = $true
    $dlg.MinimizeBox     = $false
    $dlg.BackColor       = $theme.Background
    $dlg.ForeColor       = $theme.TextPrimary
    $dlg.Font            = $fonts.Body
    if ($state.UI.Form -and $state.UI.Form.Icon) { $dlg.Icon = $state.UI.Form.Icon }
    try { Set-WptDarkTitleBar -Form $dlg } catch {}
    $dlg.Add_HandleCreated({ try { Set-WptDarkTitleBar -Form $dlg } catch {} })

    ## Title label (top)
    $lblTitle = New-WptLabel -Text $Title -X 20 -Y 14 -W 780 -H 26 -Font $fonts.DisplayMd -Fg $theme.Accent1
    $lblTitle.Anchor = 'Top,Left,Right'

    ## Thin divider rule under the title
    $pnlRule = New-Object System.Windows.Forms.Panel
    $pnlRule.Location  = New-Object System.Drawing.Point(20, 46)
    $pnlRule.Size      = New-Object System.Drawing.Size(780, 1)
    $pnlRule.BackColor = $theme.Border
    $pnlRule.Anchor    = 'Top,Left,Right'

    ## Scrollable read-only body
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location    = New-Object System.Drawing.Point(20, 56)
    $rtb.Size        = New-Object System.Drawing.Size(780, 510)
    $rtb.Anchor      = 'Top,Left,Right,Bottom'
    $rtb.BackColor   = $theme.Surface
    $rtb.ForeColor   = $theme.TextPrimary
    $rtb.Font        = $fonts.Mono
    $rtb.ReadOnly    = $true
    $rtb.ScrollBars  = 'Vertical'
    $rtb.BorderStyle = 'None'
    $rtb.WordWrap    = $true
    $rtb.Text        = $BodyText
    ## Snap caret back to top so the dialog opens at the newest entry.
    $rtb.SelectionStart = 0
    $rtb.ScrollToCaret()

    ## Close button (bottom-right)
    $btnClose = New-WptButton -Text 'Close' -X 700 -Y 576 -W 100 -H 32 -Bg $theme.PanelLight -Font $fonts.Btn
    $btnClose.Anchor = 'Bottom,Right'
    $btnClose.Add_Click({ $dlg.Close() }.GetNewClosure())
    $dlg.CancelButton = $btnClose

    $dlg.Controls.AddRange(@($lblTitle, $pnlRule, $rtb, $btnClose))
    [void]$dlg.ShowDialog($state.UI.Form)
    $dlg.Dispose()
}

function Show-WptChangeLogDialog {
    [CmdletBinding()]
    param()
    Show-WptInfoDialog -Title 'WPT - Change Log' -BodyText $script:WPT_ChangeLogText
}

function Show-WptHowToUseDialog {
    [CmdletBinding()]
    param()
    Show-WptInfoDialog -Title 'WPT - How to Use' -BodyText $script:WPT_HowToUseText
}

function Show-WptAboutDialog {
    [CmdletBinding()]
    param()
    Show-WptInfoDialog -Title 'WPT - About' -BodyText $script:WPT_AboutText
}

#endregion

###############################################################################
###                            STATIC INFO TEXT                             ###
###############################################################################
## v6.1.0: About / How To Use / Change Log were tabs in v6.0.0 and earlier;
## promoted to Start-tab popup buttons so they don't take up sidebar room.
## Content constants ($script:WPT_AboutText / WPT_ChangeLogText /
## WPT_HowToUseText) are here-strings maintained independently of the
## dialog helpers that render them.
#region === STATIC INFO TEXT (v6.1.0 - backing constants for popups) ===
## v6.1.0: About / How To Use / Change Log were tabs in v6.0.0 and earlier;
## promoted to Start-tab popup buttons so they don't take up sidebar room.
## Content constants live here so they can be maintained independently of
## the dialog helpers that render them.

$script:WPT_AboutText = @"
J.A.N.E.T. Workstation Patching Tool (WPT)
Joint Administration and Network Execution Toolkit

Version 6.1.0  -  April 2026

Author:   Braxton Thompson
Team:     48CS/SCOO  -  B.E.A.T. Contractor
Email:    braxton.thompson.1.ctr@us.af.mil

Purpose:
    MECM-driven workstation patching GUI with bulk scan/patch, software
    management, KB scanning/installation, remote messaging, reboot
    countdown, heal / remediation, WinRM bootstrap, App Updater v2
    profile registry, shared usage CSV logging, and parallel
    RunspacePool execution.

Inherits shared credentials from the J.A.N.E.T. launcher via
`$env:JANET_CRED_FILE` when launched from JANET.ps1. Falls back to the
manual Set Credentials flow when launched standalone.

Semantic versioning (MAJOR.MINOR.PATCH):
    MAJOR - breaking changes to tabs, state, or CSV schema
    MINOR - new tabs or features, additive only
    PATCH - bug fixes, visual polish, wording

See the Change Log button for version-by-version history.
"@

$script:WPT_ChangeLogText = @"
v6.1.0 - Consolidated About / How To Use / Change Log into Start-tab
         popup buttons. Removed the two sidebar tabs to free up nav
         space. Same content, one click away from the landing tab.

v6.0.0 - BREAKING: Removed Package Deploy tab + `$global:DeployBlock`
         scriptblock + all Package Deploy surface area. Duplicating
         J.A.N.E.T.'s Remote Package Installer tool inside WPT had no
         upside. Start tab reflowed; Reports card count 8 -> 7.

v5.1.3 - Cleanup tab: adopt the SrA Tennesen Garrett AFNET profile
         filter. Exclusions: Public / Administrator / USAF_Admin /
         current session account (both .adw and stripped forms). Age
         by folder LastWriteTime. Native Win32_UserProfile.Delete()
         method.

v5.1.2 - Fix: sidebar nav was unscrollable after v5.1.1. Re-enabled
         AutoScroll but hid the default gray scrollbar via
         user32!ShowScrollBar P/Invoke. MouseWheel + arrow keys work;
         drag-to-scroll is the tradeoff.

v5.1.1 - Visual polish: dropped the 1px violet-tinted divider panels
         at top-strip bottom and status-strip top (both read as light
         horizontal bars against the near-black bg). Shrunk nav items
         40 -> 32 px.

v5.1.0 - Inherit JANET launcher credentials. Reads
         `$env:JANET_CRED_FILE` at startup, Imports the DPAPI-encrypted
         Export-Clixml file, pre-populates `$global:Credentials`,
         flips the Start tab status label + button, writes a
         CredentialInherit audit row. Falls through silently when
         launched directly.

v5.0.0 - First release under semver. Reset from the pre-semver
         v1..v47.1 line. This is the build that promoted the Legacy-
         core + modular-skin rebuild to production.

==================================================================
  Pre-semver build history (v47.1 rebuild era)
==================================================================

v47.1 - Legacy-core + modular-skin rebuild. Palette (Purple #8C64DC +
        Gold #DAB452 on near-black with violet lean), Cascadia Mono
        for headings + nav + group titles + console, DPI awareness +
        DWM dark title bar + rounded corners, double-buffer helper,
        themed control factories, themed dialogs (Show-WptInfoDialog
        / ClosingNotes / ChangeLog / HowToUse). Main-form shell:
        sidebar with J.A.N.E.T. wordmark + numbered iconed nav +
        user block, 32px top strip with live heartbeat, 32px bottom
        status strip (SESSION / TARGETS / LOG). Phase 3 additive
        tabs: Heal, WinRM Setup, App Updater v2, Usage Log. Closing-
        flow infrastructure: additive FormClosing -> closing notes
        dialog -> append one aggregated row to WPT-UsageV2-
        <YYYY-MM>.csv. AD DisplayName lookup via DirectorySearcher.

v47   - AFNET hardening. TCP reachability (WinRM 5985, SMB 445)
        instead of ICMP Echo (blocked by Defender GPO). Bounded
        WSMan timeouts on every New-PSSession / Invoke-Command.
        Remote Message: scheduled-task-as-logged-in-user replaces
        msg.exe *. Deploy + KB MSU: Copy-Item -ToSession instead of
        \\host\C`$ mount. PatchBlock no longer writes WU reboot
        policy registry keys (fought GPO, tripped ACAS monitoring).

v46   - Internal.

v45   - Cleanup tab. Temp files (Windows\Temp, C:\Temp, per-user
        %TEMP%, INetCache, Prefetch) + stale user profiles older
        than N days (default 60). DRY RUN on by default.

v44   - Bulk Scan App column: only count INSTALLED MECM apps that
        have an update pending; stop flagging NotInstalled apps.

v43   - Code review fixes: Adobe RunAsPPL try/finally, Initialize-
        RunspacePool dispose before re-create, stale `$result` vars
        initialized per iteration, removed deprecated WMIC fallback
        from M365/Adobe uninstall, save/restore WU reboot policy.

v42   - Added How To Use tab; sidebar labels spelled out.

v41 and earlier - Original build (v1-v40+): Start/About with session
        gating, Bulk Scan + Patch, Software Manager, SCCM App Manager,
        KB Scanner, App Updater, Remote Message, Reboot Countdown,
        Reports, ACAS CSV import, Activity Log.
"@

$script:WPT_HowToUseText = @"
GETTING STARTED
   1. Click Set Credentials on the Start tab and enter your ADW admin
      account. (If launched from the J.A.N.E.T. launcher with shared
      creds set, this is already filled in.)
   2. Paste or import your workstation hostnames on the Targets tab.
   3. Select YES for the responsibility acknowledgment on the Start tab.
   4. Click START SESSION to unlock all tabs.

TARGETS TAB  --  Manage your workstation list.
   - Paste hostnames one per line, comma, or space separated and
     click Add to List.
   - Import from a TXT file or ACAS/Nessus CSV. Auto-detects DNS
     Name, NetBIOS, or IP columns.
   - Your target list is shared across every tab.

BULK SCAN AND PATCH TAB  --  Scan + patch multiple workstations.
   1. Click Scan All to check each workstation for MECM updates, apps,
      disk space, and reboot status.
   2. Use Select With Updates to check only machines that need patching.
   3. Click Patch Selected to push available updates and apps. Reboot
      is suppressed automatically.
   4. When ready, Reboot Selected restarts the patched machines.
   5. Use Ping Sweep for a quick online / offline check.

SOFTWARE MANAGER TAB  --  View + uninstall software on one workstation.
   1. Select a workstation and click Scan Software.
   2. Use the quick filter or search box to find specific applications.
   3. Select apps and click Uninstall Selected. Microsoft 365 and
      Adobe Acrobat have specialized native uninstall handlers built
      in.

SCCM APP MANAGER TAB  --  Manage MECM-deployed applications.
   - Query Apps: load all MECM apps with install / eval state,
     version, progress.
   - Refresh Status: updates the grid without clearing it.
   - Install / Uninstall / Reinstall / Repair: select apps and click
     the action button. Reinstall runs an uninstall first, waits 10
     seconds, then triggers a fresh install.

KB SCANNER TAB  --  View installed Windows updates; install new ones.
   - Scan Installed KBs queries all targets for installed hotfixes.
   - Trigger MECM Cycles forces clients to scan + evaluate compliance.
   - Push and Download triggers the download phase for pending updates
     (does not install).
   - KB Install: enter KB numbers, optionally provide an MSU file.
     Tries MECM first, MSU fallback.

APP UPDATER TAB (and APP UPDATER V2)  --  Push application updates.
   - Built-in profiles: M365 Force, M365 User Visible, Defender,
     Chrome, Edge, Custom Command.
   - App Updater v2 adds a Verify step (queries current version +
     last-updated per host after applying).

HEAL TAB (v47.1+)  --  One-click fixes for stuck workstations.
   - Health Scan All: MECM / WMI / WU / Reboot / Check-In per host.
   - Restart CcmExec, Repair WMI (winmgmt /salvagerepository),
     Reset WU, Trigger Check-In (MachinePolicy + SWUpdatesScan),
     gpupdate /force /wait:60.

WINRM SETUP TAB (v47.1+)  --  Bootstrap WinRM via DCOM.
   - Pre-Probe Selected: tests TCP 5985 (no creds needed) to see
     which targets need bootstrapping.
   - Bootstrap Selected: requires local-admin creds + DCOM/RPC
     (port 135) reachable. Flips WinRM service to Auto + starts it
     + runs winrm quickconfig remotely via Win32_Process.Create.

REMOTE MESSAGE TAB  --  Popup messages to workstation users.
   - Single target or all. Configurable title, body, timeout.

REBOOT COUNTDOWN TAB  --  Warnings + auto-reboot.
   - Total time + warning interval. Cancel Countdown stops the timer
     and sends a cancellation notice.

CLEANUP TAB  --  Temp files + stale profile deletion.
   - Temp: Windows\Temp, C:\Temp, per-user %TEMP%, INetCache, Prefetch.
   - Profiles: older than N days (default 60). v5.1.3+ uses the SrA
     Tennesen Garrett AFNET filter (protects Public, Administrator,
     USAF_Admin, current session account + both .adw / stripped
     forms). Age by folder LastWriteTime. Native .Delete() method.
   - DRY RUN on by default. Double confirmation on live deletes.

USAGE TAB (v47.1+)  --  Session observability + manual publish.
   - Shows operator (with AD DisplayName lookup), run id, CSV target
     path, action counts.
   - On form close (Submit), one aggregated row is written to
     WPT-UsageV2-<YYYY-MM>.csv. Publish Now fires the same flow on
     demand.

REPORTS TAB  --  Session statistics + action history.
   - Live stat cards for scans, updates, installs, uninstalls,
     reinstalls, repairs, reboots.
   - Action History grid: every action with timestamps. Export to CSV.
   - Export Summary: totals-only report with your name + session date.

LOGS TAB  --  Real-time activity log for this session.
   - Every action from every tab, timestamped + color coded.

SESSION INFORMATION on the Start tab shows the active operator, start
time, credentials username, thread count, and audit log path. Updates
when you click START SESSION.
"@
#endregion

###############################################################################
###                         BULK SCAN SCRIPTBLOCK                           ###
###############################################################################
## $global:ScanBlock - one-shot per-host probe submitted to the runspace
## pool by the btnScanAll click handler. For each computer:
##   1. TCP reachability probe (5985 then 445, not ICMP).
##   2. PSSession with bounded timeouts.
##   3. Remote Invoke-Command: C: drive free space / % free; pending reboot
##      (CBS, WU, PFRO, SCCM registry markers); MECM updates pending (
##      CCM_SoftwareUpdate where ComplianceState=0); MECM apps with pending
##      updates (CCM_Application where InstallState=Installed + ApplicabilityState=Applicable).
##   4. Returns a hashtable: Host / Online / DriveOK / DriveFree / DrivePct /
##      RebootOK / RebootPending / UpdatesOK / UpdateNames / AppsOK / AppNames.
## Result hashtable shape is consumed by the BULK SCAN/PATCH/REBOOT EVENT
## HANDLERS region's timer-based poller which paints the Bulk Scan grid.
#region === BULK SCAN SCRIPTBLOCK ===
$global:ScanBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; DriveOK=$false; DriveFree=0; DriveSize=0; DrivePct=0
            RebootOK=$false; RebootPending=$false; LastBoot=""; UpdatesOK=$false; UpdateNames=@()
            WuOK=$false; WuNames=@()
            AppsOK=$false; AppNames=@(); Error="" }
    ## v47 AFNET: TCP reachability (WinRM/SMB) instead of ICMP ping.
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { return $r }
    $r.Online = $true
    ## v47 AFNET: Bounded WinRM timeouts -- default OpenTimeout can hang ~3 min.
    ## v6.2.6: OperationTimeout bumped to 180000 because the WUA scan
    ## (Microsoft.Update.Session.Search) can legitimately take 30-90s on
    ## healthy machines and longer on machines with WSUS issues. Other
    ## queries (disk, reboot, CCM) finish in <2s so the bump only
    ## affects the slow per-host WU search.
    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sess = $null
    try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop }
    catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        try {
            $disk = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA Stop
                @{ Size=[Math]::Truncate($d.Size/1GB); Free=[Math]::Truncate($d.FreeSpace/1GB) }
            }
            $r.DriveSize = $disk.Size; $r.DriveFree = $disk.Free
            $r.DrivePct = if ($disk.Size -gt 0) { [Math]::Truncate($disk.Free / $disk.Size * 100) } else { 0 }
            $r.DriveOK = $true
        } catch {}
        try {
            $rb = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem -EA Stop
                $lb = $os.LastBootUpTime.ToString("g")
                $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                $wuau = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                $sccm = $false
                try {
                    $ccm = Invoke-WmiMethod -Namespace ROOT\ccm\ClientSDK -Class CCM_ClientUtilities -Name DetermineIfRebootPending -EA Stop
                    $sccm = $ccm.IsHardRebootPending -or $ccm.RebootPending
                } catch {}
                @{ Pending=($cbs -or $wuau -or $sccm); LastBoot=$lb }
            }
            $r.RebootPending = $rb.Pending; $r.LastBoot = $rb.LastBoot; $r.RebootOK = $true
        } catch {}
        try {
            $upd = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace root/CCM/ClientSDK -EA Stop |
                    Where-Object { $_.InstallState -ne 'Installed' -and $_.ApplicabilityState -ne 'NotApplicable' } |
                    Select-Object -ExpandProperty Name)
            }
            $r.UpdateNames = @($upd); $r.UpdatesOK = $true
        } catch {}
        ## v6.2.6: Direct Windows Update Agent scan via COM. CCM_SoftwareUpdate
        ## above only sees updates SCCM has approved/deployed; on machines
        ## that pull straight from WSUS or Microsoft Update (no MECM
        ## deployment), pending updates were invisible. This catches them.
        ## Search filter excludes already-installed and hidden updates,
        ## software updates only (drivers excluded). Note: search hits the
        ## endpoint configured by GPO -- WSUS server if UseWUServer=1, else
        ## Microsoft Update directly. Wrapped in try/catch because WUA can
        ## fault when the WU service is broken (0x80244022 etc).
        try {
            $wu = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
                $titles = @()
                foreach ($u in $found.Updates) { $titles += [string]$u.Title }
                ,$titles
            }
            $r.WuNames = @($wu); $r.WuOK = $true
        } catch { $r.WuNames = @(); $r.WuOK = $false }
        try {
            ## v44: Only report apps that ARE installed AND have an update available.
            ## Prior logic flagged apps that were simply NotInstalled (in Software Center but never installed)
            ## as needing a "patch", which produced misleading patch counts.
            ## Criteria: InstallState = Installed (app is on the machine) AND the MECM evaluation
            ## signals an update/revision change is pending (EvaluationState not None/InstallComplete).
            $apps = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop |
                    Where-Object {
                        $_.InstallState -eq 'Installed' -and
                        $_.ApplicabilityState -eq 'Applicable' -and
                        $_.IsPreflightOnly -eq $false -and
                        $_.EvaluationState -ne 0 -and
                        $_.EvaluationState -ne 1 -and
                        $_.EvaluationState -ne 12
                    } |
                    Select-Object -ExpandProperty Name)
            }
            $r.AppNames = @($apps); $r.AppsOK = $true
        } catch {}
    } finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}
#endregion

###############################################################################
###                        BULK PATCH SCRIPTBLOCK                           ###
###############################################################################
## $global:PatchBlock - per-host "install the pending stuff we found in
## the scan". Triggers CCM_SoftwareUpdatesManager.InstallUpdates against
## the list of pending CCM_SoftwareUpdate objects, and CCM_Application.
## Install methods against the list of pending apps. Reboot suppression
## is delegated to MECM itself (IsRebootIfNeeded=$false on application
## install; InstallUpdates does not auto-reboot at trigger time).
## Matching filter criteria to $global:ScanBlock so "patch exactly what
## the scan reported" is true by construction.
## Returns: Host / Reachable / Error / UpdatesTriggered / AppsTriggered.
#region === BULK PATCH SCRIPTBLOCK ===
## v47 AFNET: Reboot suppression is handled by MECM's own install arguments
## (IsRebootIfNeeded=$false on CCM_Application; WU installs via CCM_SoftwareUpdatesManager
## do not auto-reboot at the trigger point). The v43 WU registry policy save/restore
## was (a) fighting GPO, (b) tripping ACAS/Tanium policy-drift monitoring, and
## (c) ineffective anyway -- the GPO refresh would clobber it mid-run. Removed.
$global:PatchBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth)
    $r = @{ Host=$Computer; Reachable=$false; UpdatesTriggered=0; AppsTriggered=0; Error="" }
    ## v47 AFNET: TCP reachability instead of ICMP.
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Error = "Offline"; return $r }
    $r.Reachable = $true
    $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sess = $null
    try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop }
    catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        $updResult = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $updates = Get-WmiObject -Namespace "ROOT\ccm\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop
            if ($updates) {
                Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$updates) -Namespace ROOT\ccm\ClientSDK | Out-Null
                return @($updates).Count
            }
            return 0
        }
        $r.UpdatesTriggered = $updResult
        $appResult = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $count = 0
            ## v44: Only patch apps that ARE installed AND have an update pending.
            ## Matches ScanBlock logic so "Patch Needing" actually patches what the scan reported.
            $apps = Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop |
                Where-Object {
                    $_.InstallState -eq 'Installed' -and
                    $_.ApplicabilityState -eq 'Applicable' -and
                    $_.IsPreflightOnly -eq $false -and
                    $_.EvaluationState -ne 0 -and
                    $_.EvaluationState -ne 1 -and
                    $_.EvaluationState -ne 12
                }
            foreach ($app in $apps) {
                try {
                    $param = @{
                        EnforcePreference = [UINT32]0; Id = "$($app.Id)"
                        IsMachineTarget = [System.Convert]::ToBoolean($app.IsMachineTarget)
                        IsRebootIfNeeded = $false; Priority = 'High'; Revision = "$($app.Revision)"
                    }
                    Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Install -Arguments $param | Out-Null
                    $count++
                } catch {}
            }
            return $count
        }
        $r.AppsTriggered = $appResult
    } catch { $r.Error = $_.Exception.Message }
    finally {
        ## v47 AFNET: WU policy restore removed along with the save. MECM install
        ## arguments already handle reboot suppression; local registry policy is GPO-owned.
        Remove-PSSession $sess -EA SilentlyContinue
    }
    return $r
}
#endregion

###############################################################################
###                        BULK REBOOT SCRIPTBLOCK                          ###
###############################################################################
## $global:RebootBlock - per-host immediate force reboot via Restart-
## Computer -Force. No delay, no countdown (countdown is a separate
## feature on the Reboot Countdown tab).
## Returns: Host / Success / Message.
#region === BULK REBOOT SCRIPTBLOCK ===
$global:RebootBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Message="" }
    try {
        Restart-Computer -ComputerName $Computer -Credential $Cred -Force -EA Stop
        $r.Success = $true; $r.Message = "Reboot command sent"
    } catch { $r.Message = $_.Exception.Message }
    return $r
}
#endregion

## v6.0.0: Package Deploy scriptblock ($global:DeployBlock) removed along
## with the Package Deploy tab. Standalone package deployment is handled
## by J.A.N.E.T.'s Remote Package Installer tool. If rollback is ever
## needed, the full scriptblock is preserved in
## Archive\WPT-superseded-2026-04-21\WorkstationPatchingTool Legacy.ps1.

###############################################################################
###                          HEAL SCRIPTBLOCKS                              ###
###############################################################################
## Six scriptblocks for the Heal tab, ported from modular WPT v2.4.0
## Tools\WPT\Operations\Heal.ps1. All take ($Computer, $Credential,
## $AuthMethod, $RunId) and return a hashtable with Host + Success /
## Detail / action-specific fields.
##   $global:HealthScanBlock     - probe: MECM state (Missing/Stopped/
##     Running), SWCenter state (Healthy/NotRunning/Broken/Missing),
##     WMI state (OK/Broken), WU state (OK/Disabled/Broken), RebootState
##     (None/Pending + age), LastCheckIn, Overall verdict (Healthy/
##     Degraded/Broken/Offline).
##   $global:RestartCcmExecBlock - Stop/Start CcmExec service.
##   $global:WmiRepairBlock      - winmgmt /salvagerepository.
##   $global:WuResetBlock        - stop wuauserv + cryptsvc + bits +
##     msiserver, rename SoftwareDistribution + catroot2 with a
##     wpt-bak-<timestamp> suffix, restart services.
##   $global:TriggerCheckInBlock - SMS_Client.TriggerSchedule for
##     MachinePolicy (...022) + SWUpdatesScan (...113).
##   $global:GpUpdateBlock       - gpupdate.exe /force /wait:60.
#region === HEAL SCRIPTBLOCKS (v47.1 Phase 3 - modular-ported) ===
## Ported verbatim from modular WPT v2.4.0 Tools\WPT\Operations\Heal.ps1.
## Assigned to $global: vars so RunspacePool workers can consume them the
## same way they consume $global:ScanBlock / $global:PatchBlock / etc.
## Timeout params from the modular signature are hardcoded in-line to match
## Legacy's $global:WSManOpt (30000/15000/5000/60000) so the caller only
## needs to pass ($Computer, $Credential, $AuthMethod, $RunId).

## --- Health scan: one round-trip probe of MECM/WMI/WU/Reboot/Check-in.
$global:HealthScanBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{
        Host        = $Computer
        Online      = $false
        MecmState   = 'Unknown'
        ClientVer   = ''
        SwCenter    = 'Missing'
        WmiState    = 'Unknown'
        WuState     = 'Unknown'
        RebootState = 'Unknown'
        RebootAge   = ''
        LastCheckIn = ''
        Overall     = 'Unknown'
        Error       = ''
        RunId       = $RunId
        StartTime   = (Get-Date)
    }
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Overall = 'Offline'; $r.Error = 'Unreachable'; $r.EndTime = Get-Date; return $r
    }
    $r.Online = $true
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $sess = $null
    try {
        $sess = New-PSSession -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $opt -ErrorAction Stop
    } catch {
        $r.Error = "Session: $($_.Exception.Message)"; $r.Overall = 'Broken'; $r.EndTime = Get-Date; return $r
    }
    try {
        $probe = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
            $o = @{
                MecmInstalled = $false; MecmRunning = $false; ClientVer = ''
                SwCenterExe   = ''
                WmiOK         = $false; WmiErr = ''
                WuSvcStartup  = ''; WuSvcStatus = ''; TrustedInstallerOK = $false
                RebootPending = $false; RebootReasons = @(); PendingDays = 0
                LastPolicyReq = ''
            }
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {
                $o.MecmInstalled = $true
                try { $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\CCM' -Name ClientVersion -ErrorAction Stop).ClientVersion; $o.ClientVer = [string]$v } catch {}
                try { $svc = Get-Service CcmExec -ErrorAction Stop; $o.MecmRunning = ($svc.Status -eq 'Running') } catch {}
                foreach ($p in @('C:\Windows\CCM\SCClient.exe','C:\Windows\CCM\ClientUX\SCClient.exe')) { if (Test-Path $p) { $o.SwCenterExe = $p; break } }
            }
            try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; if ($cs) { $o.WmiOK = $true } } catch { $o.WmiErr = $_.Exception.Message }
            try { $svcWu = Get-Service wuauserv -ErrorAction Stop; $o.WuSvcStatus = [string]$svcWu.Status; $o.WuSvcStartup = [string]$svcWu.StartType } catch {}
            try { $svcTi = Get-Service TrustedInstaller -ErrorAction Stop; $o.TrustedInstallerOK = [bool]$svcTi } catch {}
            $reasons = New-Object System.Collections.ArrayList; $oldestMark = $null
            try { $cbs = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop; [void]$reasons.Add('CBS'); if (-not $oldestMark -or $cbs.LastWriteTime -lt $oldestMark) { $oldestMark = $cbs.LastWriteTime } } catch {}
            try { $wu = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop; [void]$reasons.Add('WU'); if (-not $oldestMark -or $wu.LastWriteTime -lt $oldestMark) { $oldestMark = $wu.LastWriteTime } } catch {}
            try { $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop; if ($pfro.PendingFileRenameOperations) { [void]$reasons.Add('PFRO') } } catch {}
            try { $ccm = Invoke-WmiMethod -Namespace 'ROOT\ccm\ClientSDK' -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Stop; if ($ccm.IsHardRebootPending -or $ccm.RebootPending) { [void]$reasons.Add('SCCM') } } catch {}
            if ($reasons.Count -gt 0) {
                $o.RebootPending = $true; $o.RebootReasons = @($reasons)
                if ($oldestMark) { $o.PendingDays = [int]((Get-Date) - $oldestMark).TotalDays }
            }
            try { $lph = Get-CimInstance -Namespace 'root\ccm' -ClassName CCM_Client -ErrorAction Stop; if ($lph -and $lph.LastHinvChangeTime) { $o.LastPolicyReq = $lph.LastHinvChangeTime.ToString('yyyy-MM-dd HH:mm') } } catch {}
            if ([string]::IsNullOrWhiteSpace($o.LastPolicyReq)) { try { $sched = Get-ChildItem 'C:\Windows\CCM\Logs\ClientIDManagerStartup.log' -ErrorAction Stop; $o.LastPolicyReq = $sched.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } catch {} }
            return $o
        }
        if (-not $probe.MecmInstalled) { $r.MecmState = 'Missing' }
        elseif (-not $probe.MecmRunning) { $r.MecmState = 'Stopped' }
        else { $r.MecmState = 'Running' }
        $r.ClientVer = [string]$probe.ClientVer
        if (-not $probe.MecmInstalled) { $r.SwCenter = 'Missing' }
        elseif ([string]::IsNullOrWhiteSpace($probe.SwCenterExe)) { $r.SwCenter = 'Broken' }
        elseif (-not $probe.MecmRunning) { $r.SwCenter = 'NotRunning' }
        else { $r.SwCenter = 'Healthy' }
        $r.WmiState = if ($probe.WmiOK) { 'OK' } else { 'Broken' }
        if ($probe.WuSvcStartup -eq 'Disabled') { $r.WuState = 'Disabled' }
        elseif (-not $probe.TrustedInstallerOK) { $r.WuState = 'Broken' }
        elseif ($probe.WuSvcStartup) { $r.WuState = 'OK' }
        if ($probe.RebootPending) {
            $r.RebootState = 'Pending'
            $r.RebootAge = if ([int]$probe.PendingDays -gt 0) { "$($probe.PendingDays)d" } else { '<1d' }
        } else { $r.RebootState = 'None' }
        $r.LastCheckIn = [string]$probe.LastPolicyReq
        if ($r.MecmState -eq 'Missing' -or $r.WmiState -eq 'Broken') { $r.Overall = 'Broken' }
        elseif ($r.MecmState -eq 'Stopped' -or $r.WuState -eq 'Disabled' -or $r.WuState -eq 'Broken' -or $r.SwCenter -eq 'Broken' -or ([int]$probe.PendingDays -gt 14)) { $r.Overall = 'Degraded' }
        else { $r.Overall = 'Healthy' }
    } catch {
        $r.Error = $_.Exception.Message; $r.Overall = 'Broken'
    } finally { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    $r.EndTime = Get-Date
    return $r
}

## --- Restart MECM client (CcmExec) service.
$global:RestartCcmExecBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{ Host=$Computer; Action='RestartCcmExec'; Success=$false; Detail=''; RunId=$RunId; StartTime=(Get-Date) }
    try {
        Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $global:WSManOpt -ErrorAction Stop -ScriptBlock {
            $svc = Get-Service CcmExec -ErrorAction Stop
            if ($svc.Status -eq 'Running') { Stop-Service CcmExec -Force -ErrorAction Stop }
            Start-Sleep -Seconds 2
            Start-Service CcmExec -ErrorAction Stop
            $svc2 = Get-Service CcmExec -ErrorAction Stop
            if ($svc2.Status -ne 'Running') { throw "CcmExec did not reach Running state (status=$($svc2.Status))" }
        }
        $r.Success = $true; $r.Detail = 'CcmExec restarted'
    } catch { $r.Detail = $_.Exception.Message }
    $r.EndTime = Get-Date; return $r
}

## --- WMI salvage (winmgmt /salvagerepository).
$global:WmiRepairBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{ Host=$Computer; Action='WmiRepair'; Success=$false; ExitCode=$null; FailedSteps=@(); Detail=''; RunId=$RunId; StartTime=(Get-Date) }
    try {
        $out = Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $global:WSManOpt -ErrorAction Stop -ScriptBlock {
            $result = & winmgmt /salvagerepository 2>&1 | Out-String
            [pscustomobject]@{ Output = $result; Exit = $LASTEXITCODE }
        }
        $r.ExitCode = $out.Exit
        if ($null -eq $out.Exit) {
            $r.FailedSteps = @('winmgmt did not execute (no exit code)')
            $r.Detail = "winmgmt /salvagerepository did not run. Output: $($out.Output.Trim())"
        } elseif ($out.Exit -eq 0) {
            $r.Success = $true; $r.Detail = "winmgmt /salvagerepository exit=0; $($out.Output.Trim())"
        } else {
            $r.FailedSteps = @("winmgmt exit=$($out.Exit)")
            $r.Detail = "winmgmt /salvagerepository exit=$($out.Exit); $($out.Output.Trim())"
        }
    } catch {
        $r.FailedSteps = @("Invoke-Command: $($_.Exception.Message)"); $r.Detail = $_.Exception.Message
    }
    $r.EndTime = Get-Date; return $r
}

## --- Windows Update reset (stop services, rename caches, restart services).
$global:WuResetBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{ Host=$Computer; Action='WuReset'; Success=$false; CompletedSteps=@(); FailedSteps=@(); Detail=''; RunId=$RunId; StartTime=(Get-Date) }
    try {
        $out = Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $global:WSManOpt -ErrorAction Stop -ScriptBlock {
            $completed = New-Object System.Collections.ArrayList
            $failed    = New-Object System.Collections.ArrayList
            $criticalFailed = $false; $wuRestarted = $false
            foreach ($svc in 'wuauserv','cryptsvc','bits','msiserver') {
                try { Stop-Service $svc -Force -ErrorAction Stop; [void]$completed.Add("stopped $svc") }
                catch { [void]$failed.Add("stop-$svc failed: $($_.Exception.Message)") }
            }
            foreach ($dir in 'C:\Windows\SoftwareDistribution','C:\Windows\System32\catroot2') {
                if (Test-Path $dir) {
                    $bak = "$dir.wpt-bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
                    try { Rename-Item $dir $bak -Force -ErrorAction Stop; [void]$completed.Add("renamed $dir") }
                    catch { [void]$failed.Add("rename-$dir failed: $($_.Exception.Message)") }
                }
            }
            foreach ($svc in 'cryptsvc','bits','msiserver','wuauserv') {
                try {
                    Start-Service $svc -ErrorAction Stop
                    [void]$completed.Add("started $svc")
                    if ($svc -eq 'wuauserv') { $wuRestarted = $true }
                } catch {
                    [void]$failed.Add("start-$svc failed: $($_.Exception.Message)")
                    if ($svc -in 'wuauserv','cryptsvc') { $criticalFailed = $true }
                }
            }
            return [pscustomobject]@{ Completed=@($completed.ToArray()); Failed=@($failed.ToArray()); CriticalFailed=[bool]$criticalFailed; WuRestarted=[bool]$wuRestarted }
        }
        $r.CompletedSteps = @($out.Completed); $r.FailedSteps = @($out.Failed)
        $r.Success = ($out.WuRestarted -and -not $out.CriticalFailed)
        $r.Detail = if ($r.Success) { "WU reset OK. Steps: $(($r.CompletedSteps -join ' | '))" }
                    else           { "WU reset degraded. Failed: $(($r.FailedSteps -join ' | '))" }
    } catch {
        $r.FailedSteps = @("Invoke-Command: $($_.Exception.Message)"); $r.Detail = $_.Exception.Message
    }
    $r.EndTime = Get-Date; return $r
}

## --- Trigger MECM MachinePolicy + SW Updates Scan cycles.
$global:TriggerCheckInBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{ Host=$Computer; Action='TriggerCheckIn'; Success=$false; FailedSteps=@(); Detail=''; RunId=$RunId; StartTime=(Get-Date) }
    try {
        $out = Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $global:WSManOpt -ErrorAction Stop -ScriptBlock {
            $schedules = @{
                '{00000000-0000-0000-0000-000000000022}' = 'MachinePolicy'
                '{00000000-0000-0000-0000-000000000113}' = 'SWUpdatesScan'
            }
            $ok = New-Object System.Collections.ArrayList; $bad = New-Object System.Collections.ArrayList
            foreach ($g in $schedules.Keys) {
                try {
                    Invoke-WmiMethod -Namespace 'root\ccm' -Class SMS_Client -Name TriggerSchedule -ArgumentList $g -ErrorAction Stop | Out-Null
                    [void]$ok.Add($schedules[$g])
                } catch { [void]$bad.Add("$($schedules[$g]): $($_.Exception.Message)") }
            }
            return [pscustomobject]@{ Succeeded=@($ok); Failed=@($bad) }
        }
        if (@($out.Succeeded).Count -gt 0) {
            $r.Success = $true
            $r.Detail = "Triggered: $(@($out.Succeeded) -join ', ')"
            if (@($out.Failed).Count -gt 0) {
                $r.FailedSteps = @($out.Failed)
                $r.Detail += " (partial - some failed: $(@($out.Failed) -join '; '))"
            }
        } else {
            $r.FailedSteps = @($out.Failed); $r.Detail = "No schedules triggered: $(@($out.Failed) -join '; ')"
        }
    } catch {
        $r.FailedSteps = @("Invoke-Command: $($_.Exception.Message)"); $r.Detail = $_.Exception.Message
    }
    $r.EndTime = Get-Date; return $r
}

## --- gpupdate /force /wait:60.
$global:GpUpdateBlock = {
    param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [string]$RunId)
    $r = @{ Host=$Computer; Action='GpUpdate'; Success=$false; ExitCode=$null; FailedSteps=@(); Detail=''; RunId=$RunId; StartTime=(Get-Date) }
    try {
        $out = Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $global:WSManOpt -ErrorAction Stop -ScriptBlock {
            $text = & gpupdate.exe /force /wait:60 2>&1 | Out-String
            [pscustomobject]@{ Output = $text; Exit = $LASTEXITCODE }
        }
        $r.ExitCode = $out.Exit
        $summary = ($out.Output -split "`r?`n") | Where-Object { $_ -match '(updated|error|failed|successfully)' } | Select-Object -First 3
        $summaryStr = ($summary -join ' | ').Trim()
        if ($null -eq $out.Exit) {
            $r.FailedSteps = @('gpupdate.exe did not execute (no exit code)'); $r.Detail = "gpupdate did not run. Output: $summaryStr"
        } elseif ($out.Exit -eq 0) {
            $r.Success = $true; $r.Detail = "gpupdate exit=0; $summaryStr"
        } else {
            $r.FailedSteps = @("gpupdate exit=$($out.Exit)"); $r.Detail = "gpupdate exit=$($out.Exit); $summaryStr"
        }
    } catch {
        $r.FailedSteps = @("Invoke-Command: $($_.Exception.Message)"); $r.Detail = $_.Exception.Message
    }
    $r.EndTime = Get-Date; return $r
}
#endregion

###############################################################################
###                     WINRM BOOTSTRAP SCRIPTBLOCK                         ###
###############################################################################
## $global:WinRMBootstrapBlock - the "fix what Tanium can't" primitive.
## For hosts where WinRM isn't answering on 5985, we use DCOM (port 135)
## as a side channel to flip the target's WinRM service StartMode to
## Auto + start it + run winrm quickconfig remotely via
## Win32_Process.Create, then re-probe TCP 5985 to confirm the fix took.
## Prerequisites on the target:
##   - DCOM (port 135) reachable from the operator's workstation
##   - Local-admin credentials
##   - Windows Firewall allows RPC dynamic range (AFNET GPO usually does)
## Returns: Host / Steps (ArrayList, flattened to array at return) /
## Success / Error / PostProbeOk.
#region === WINRM BOOTSTRAP SCRIPTBLOCK (v47.1 Phase 3 - modular-ported) ===
## Ported from modular WPT v2.4.0 Tools\WPT\Integrations\WinRMBootstrap.ps1
## and hardened in v6.3.0 (Ninkxz/WinRM-fix) for AFNET reliability:
##   - 2-attempt DCOM connect with 2s gap (RPC ephemeral-port negotiation
##     can flake on first try against busy AFNET subnets)
##   - `-skipNetworkProfileCheck` on quickconfig (CRITICAL: without it,
##     quickconfig silently refuses to add the firewall rule whenever any
##     NIC is on the Public profile -- common on laptops post-VPN -- and
##     5985 stays closed)
##   - 30s polling budget on the post-probe (quickconfig is async via
##     Win32_Process.Create and can take 5-30s; one short probe would
##     false-fail on slow hosts)
$global:WinRMBootstrapBlock = {
    param([string]$Computer, [pscredential]$Credential)
    $r = @{
        Host        = $Computer
        Steps       = New-Object System.Collections.ArrayList
        Success     = $false
        Error       = ''
        PostProbeOk = $false
        StartTime   = (Get-Date)
    }
    $addStep = { param($s) [void]$r.Steps.Add($s) }
    $opt = New-CimSessionOption -Protocol DCOM
    $cim = $null
    $lastErr = $null
    for ($attempt = 1; $attempt -le 2 -and -not $cim; $attempt++) {
        try {
            $cim = New-CimSession -ComputerName $Computer -Credential $Credential -SessionOption $opt -OperationTimeoutSec 30 -ErrorAction Stop
        } catch {
            $lastErr = $_.Exception.Message
            if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
        }
    }
    if (-not $cim) {
        $r.Error = "DCOM connect failed (2 attempts): $lastErr"; & $addStep $r.Error
        $r.Steps = @($r.Steps); $r.EndTime = Get-Date; return $r
    }
    & $addStep "DCOM CIM session opened"
    try {
        $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        if (-not $svc) {
            $r.Error = "WinRM service not found on host (unusual)"; & $addStep $r.Error
            return $r
        }
        & $addStep "WinRM service found - StartMode=$($svc.StartMode), State=$($svc.State)"
        if ($svc.StartMode -ne 'Auto') {
            try {
                $chg = Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName ChangeStartMode -Arguments @{ StartMode = 'Automatic' } -ErrorAction Stop
                if ($chg.ReturnValue -eq 0) { & $addStep "StartMode set to Automatic" }
                else { & $addStep "ChangeStartMode returned code $($chg.ReturnValue)" }
            } catch { & $addStep "ChangeStartMode failed: $($_.Exception.Message)" }
        }
        if ($svc.State -ne 'Running') {
            try {
                $start = Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName StartService -ErrorAction Stop
                if ($start.ReturnValue -eq 0) { & $addStep "WinRM service start requested" }
                else { & $addStep "StartService returned code $($start.ReturnValue)" }
                Start-Sleep -Seconds 2
            } catch { & $addStep "StartService failed: $($_.Exception.Message)" }
        } else { & $addStep "Service already running - skipping start" }
        $logPath = 'C:\Windows\Temp\wpt_winrm_bootstrap.log'
        $cmd     = "cmd.exe /c winrm quickconfig -force -quiet -skipNetworkProfileCheck >""$logPath"" 2>&1"
        try {
            $proc = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
            if ($proc.ReturnValue -eq 0) { & $addStep "winrm quickconfig queued (PID $($proc.ProcessId))"; Start-Sleep -Seconds 3 }
            else { & $addStep "Win32_Process.Create returned code $($proc.ReturnValue)" }
        } catch { & $addStep "quickconfig failed: $($_.Exception.Message)" }
        ## 30s poll budget; quickconfig is async and can take 5-30s.
        $deadline      = (Get-Date).AddSeconds(30)
        $probeAttempts = 0
        do {
            $probeAttempts++
            $tc = $null
            try {
                $tc  = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected) { $r.PostProbeOk = $true }
            } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
            if (-not $r.PostProbeOk -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        } while (-not $r.PostProbeOk -and (Get-Date) -lt $deadline)
        if ($r.PostProbeOk) { & $addStep "Post-probe: WinRM 5985 reachable (attempt $probeAttempts)" }
        else                { & $addStep "Post-probe: WinRM 5985 still not reachable after $probeAttempts probe(s) over 30s" }
        $r.Success = $r.PostProbeOk
    } catch {
        $r.Error = $_.Exception.Message; & $addStep "Bootstrap error: $($r.Error)"
    } finally {
        if ($cim) { try { Remove-CimSession $cim -ErrorAction SilentlyContinue } catch {} }
        $r.Steps = @($r.Steps); $r.EndTime = Get-Date
    }
    return $r
}
#endregion

###############################################################################
###                             REBOOT MONITOR                              ###
###############################################################################
## Show-RebootMonitor - modal form that tracks reboot progress for a
## given target list. Polls each host with a TCP probe + an Invoke-
## Command uptime check; shows per-host State (Offline / Booting /
## LoggedIn / Timed Out) with timestamps. Cancellable. Called from the
## Bulk Reboot flow after the reboot has been dispatched if the
## operator opts to monitor.
#region === REBOOT MONITOR ===
function Show-RebootMonitor {
    param([string[]]$ServerList)
    if ($ServerList.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Reboot Monitor"; $dlg.ClientSize = New-Object System.Drawing.Size(680, 400)
    $dlg.BackColor = $c.BG; $dlg.ForeColor = $c.White; $dlg.Font = $fn.Label
    $dlg.StartPosition = 'CenterScreen'; $dlg.TopMost = $true
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false
    $lblSt = New-Lbl -Text "Waiting for workstation(s) to reboot and return..." -X 10 -Y 8 -W 500 -Font $fn.LabelB -Fg $c.Warning
    $lblEl = New-Lbl -Text "Elapsed: 0:00" -X 560 -Y 10 -W 110 -Font $fn.Small -Fg $c.Dim
    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Location = New-Object System.Drawing.Point(6, 34); $dgv.Size = New-Object System.Drawing.Size(666, 310)
    Style-Grid $dgv; $dgv.ReadOnly = $true
    foreach ($col in @(@{N='Server';F=30},@{N='Phase';F=18},@{N='Status';F=16},@{N='Pings';F=8},@{N='Downtime';F=10},@{N='Time';F=10})) {
        $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $cc.Name = $col.N; $cc.HeaderText = $col.N; $cc.FillWeight = $col.F; [void]$dgv.Columns.Add($cc)
    }
    $monState = @{}
    foreach ($srv in $ServerList) {
        $idx = $dgv.Rows.Add($srv, "Waiting offline", "Rebooting...", "0", "--", (Get-Date).ToString("HH:mm:ss"))
        $dgv.Rows[$idx].Cells[2].Style.ForeColor = $c.Warning
        $monState[$srv] = @{ Phase='WaitOff'; Pings=0; Row=$idx; Down=$null }
    }
    $btnCl = New-Btn -Text "Close" -X 560 -Y 354 -W 110 -H 30 -Bg $c.Danger
    $startTime = Get-Date
    $tmr = New-Object System.Windows.Forms.Timer; $tmr.Interval = 3000
    $tmr.Add_Tick({
        $elapsed = (Get-Date) - $startTime
        $lblEl.Text = "Elapsed: $([Math]::Floor($elapsed.TotalMinutes)):$($elapsed.Seconds.ToString('00'))"
        $allDone = $true
        foreach ($srv in $ServerList) {
            $st = $monState[$srv]; if ($st.Phase -eq 'Done') { continue }
            $allDone = $false; $st.Pings++
            $row = $dgv.Rows[$st.Row]; $row.Cells[3].Value = $st.Pings.ToString()
            $row.Cells[5].Value = (Get-Date).ToString("HH:mm:ss")
            ## v47 AFNET: Use TCP reachability helper (ICMP blocked by Defender GPO).
            $online = Test-WorkstationReachable -Computer $srv -TimeoutMs 1200
            if ($st.Phase -eq 'WaitOff') {
                if (-not $online) { $st.Phase = 'WaitOn'; $st.Down = Get-Date; $row.Cells[1].Value = "Offline"; $row.Cells[2].Value = "Offline"; $row.Cells[2].Style.ForeColor = $c.Danger }
            } elseif ($st.Phase -eq 'WaitOn') {
                if ($online) {
                    $st.Phase = 'Done'; $dt = (Get-Date) - $st.Down
                    $row.Cells[1].Value = "Back online"; $row.Cells[2].Value = "Online"; $row.Cells[2].Style.ForeColor = $c.Success; $row.Cells[1].Style.ForeColor = $c.Success
                    $row.Cells[4].Value = "$([Math]::Floor($dt.TotalMinutes)):$($dt.Seconds.ToString('00'))"
                    try { [Console]::Beep(800,200); [Console]::Beep(1000,150) } catch {}
                } else {
                    $dt = (Get-Date) - $st.Down; $row.Cells[4].Value = "$([Math]::Floor($dt.TotalMinutes)):$($dt.Seconds.ToString('00'))"
                }
            }
        }
        if ($allDone) { $tmr.Stop(); $lblSt.Text = "All workstation(s) back online!"; $lblSt.ForeColor = $c.Success }
    })
    $btnCl.Add_Click({ $tmr.Stop(); $tmr.Dispose(); $dlg.Close() })
    $dlg.Add_FormClosing({ $tmr.Stop(); $tmr.Dispose() })
    $dlg.Controls.AddRange(@($lblSt, $lblEl, $dgv, $btnCl))
    $tmr.Start(); $dlg.ShowDialog() | Out-Null; $dlg.Dispose()
}
#endregion

###############################################################################
###                       HOST DRILL-DOWN DIALOG (Experimental)             ###
###############################################################################
## Show-HostScanDetails - modal form launched from the Bulk Scan grid
## (double-click row, or "Host Details" button). Surfaces the full per-
## host scan result that ScanBlock already collects but Bulk Scan only
## counts: pending KB/MECM update names, pending app names, drive, last
## boot, reboot-pending state, and any scan-side error. Read-only -- this
## is a "what would I actually be patching on this box" inspector. The
## "Open App Manager" button hands off to Show-AppManager for live
## CCM_Application actions on the same host.
#region === HOST DRILL-DOWN DIALOG ===
function Show-HostScanDetails {
    param([hashtable]$Result)
    if (-not $Result) {
        [System.Windows.Forms.MessageBox]::Show("This row has no scan data yet. Run Scan All first, then double-click a scanned row.","No Scan Data",0,64)
        return
    }
    $h = [string]$Result.Host

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Host Details - $h"
    $dlg.ClientSize = New-Object System.Drawing.Size(900, 620)
    $dlg.BackColor = $c.BG; $dlg.ForeColor = $c.White; $dlg.Font = $fn.Label
    $dlg.StartPosition = 'CenterScreen'; $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false

    ## Header strip - host name and one-line summary
    $lblHost = New-Lbl -Text $h -X 10 -Y 8 -W 700 -H 28 -Font $fn.Title -Fg $c.Cyan
    $online = if ($Result.Online) { 'Online' } else { 'Offline' }
    $onlineFg = if ($Result.Online) { $c.Success } else { $c.Danger }
    $lblOnline = New-Lbl -Text $online -X 720 -Y 14 -W 80 -H 22 -Font $fn.LabelB -Fg $onlineFg

    ## Status grid: drive / reboot / last boot / error
    $pnlSt = New-Object System.Windows.Forms.Panel
    $pnlSt.Location = New-Object System.Drawing.Point(10, 40); $pnlSt.Size = New-Object System.Drawing.Size(880, 70)
    $pnlSt.BackColor = $c.Panel

    $driveTxt = if ($Result.DriveOK) { "$($Result.DriveFree) GB free / $($Result.DriveSize) GB  ($($Result.DrivePct)%)" } else { 'Drive: error / unreachable' }
    $driveFg  = if ($Result.DriveOK) { if ($Result.DrivePct -gt 20) { $c.Success } else { $c.Warning } } else { $c.Danger }
    $rebootTxt = if ($Result.RebootOK) { if ($Result.RebootPending) { 'Reboot pending: YES' } else { 'Reboot pending: No' } } else { 'Reboot: unknown' }
    $rebootFg  = if ($Result.RebootOK) { if ($Result.RebootPending) { $c.Warning } else { $c.Success } } else { $c.Dim }
    $lastBoot = if ([string]::IsNullOrWhiteSpace($Result.LastBoot)) { '--' } else { [string]$Result.LastBoot }

    $lblD1 = New-Lbl -Text "C: drive"     -X 10 -Y  6 -W 110 -Font $fn.Small -Fg $c.Dim
    $lblD2 = New-Lbl -Text $driveTxt      -X 10 -Y 24 -W 320 -Font $fn.LabelB -Fg $driveFg
    $lblR1 = New-Lbl -Text "Reboot state" -X 350 -Y  6 -W 160 -Font $fn.Small -Fg $c.Dim
    $lblR2 = New-Lbl -Text $rebootTxt     -X 350 -Y 24 -W 220 -Font $fn.LabelB -Fg $rebootFg
    $lblB1 = New-Lbl -Text "Last boot"    -X 580 -Y  6 -W 160 -Font $fn.Small -Fg $c.Dim
    $lblB2 = New-Lbl -Text $lastBoot      -X 580 -Y 24 -W 290 -Font $fn.Label -Fg $c.TextSec
    $pnlSt.Controls.AddRange(@($lblD1,$lblD2,$lblR1,$lblR2,$lblB1,$lblB2))

    if (-not [string]::IsNullOrWhiteSpace($Result.Error)) {
        $lblErr = New-Lbl -Text "Scan error: $($Result.Error)" -X 10 -Y 48 -W 860 -Font $fn.Small -Fg $c.Danger
        $pnlSt.Controls.Add($lblErr)
    }

    ## v6.2.6: Three sections -- MECM updates (top-left, CCM_SoftwareUpdate),
    ## Direct WU (bottom-left, Microsoft.Update.Session), and Apps (right,
    ## CCM_Application). MECM and WU are separated so the operator can see
    ## which channel a pending item came through; overlap is possible but
    ## informative.
    ## --- MECM Software Updates (top-left) ---
    $uCount = @($Result.UpdateNames).Count
    $uHdr = if ($Result.UpdatesOK) { if ($uCount -gt 0) { "MECM Software Updates  ($uCount)" } else { "MECM Software Updates  (current)" } } else { "MECM Software Updates  (scan error)" }
    $uFg  = if ($Result.UpdatesOK) { if ($uCount -gt 0) { $c.Warning } else { $c.Success } } else { $c.Danger }
    $lblU = New-Lbl -Text $uHdr -X 10 -Y 120 -W 430 -Font $fn.LabelB -Fg $uFg

    $dgvU = New-Object System.Windows.Forms.DataGridView
    $dgvU.Location = New-Object System.Drawing.Point(10, 142); $dgvU.Size = New-Object System.Drawing.Size(430, 180)
    $dgvU.ReadOnly = $true; $dgvU.RowHeadersVisible = $false; $dgvU.AllowUserToAddRows = $false
    Style-Grid $dgvU
    $colU = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colU.Name = 'Update'; $colU.HeaderText = 'Update / KB (MECM)'; $colU.AutoSizeMode = 'Fill'; [void]$dgvU.Columns.Add($colU)
    foreach ($n in @($Result.UpdateNames)) { [void]$dgvU.Rows.Add([string]$n) }
    if ($Result.UpdatesOK -and $uCount -eq 0) { [void]$dgvU.Rows.Add('(no pending MECM updates)'); $dgvU.Rows[0].DefaultCellStyle.ForeColor = $c.Dim }

    ## --- Direct Windows Update Agent (bottom-left) ---
    $wCount = @($Result.WuNames).Count
    $wHdr = if ($Result.WuOK) { if ($wCount -gt 0) { "Direct Windows Update  ($wCount)" } else { "Direct Windows Update  (current)" } } else { "Direct Windows Update  (scan error)" }
    $wFg  = if ($Result.WuOK) { if ($wCount -gt 0) { $c.Warning } else { $c.Success } } else { $c.Danger }
    $lblW = New-Lbl -Text $wHdr -X 10 -Y 332 -W 430 -Font $fn.LabelB -Fg $wFg

    $dgvW = New-Object System.Windows.Forms.DataGridView
    $dgvW.Location = New-Object System.Drawing.Point(10, 354); $dgvW.Size = New-Object System.Drawing.Size(430, 198)
    $dgvW.ReadOnly = $true; $dgvW.RowHeadersVisible = $false; $dgvW.AllowUserToAddRows = $false
    Style-Grid $dgvW
    $colW = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colW.Name = 'WuTitle'; $colW.HeaderText = 'Windows Update title'; $colW.AutoSizeMode = 'Fill'; [void]$dgvW.Columns.Add($colW)
    foreach ($n in @($Result.WuNames)) { [void]$dgvW.Rows.Add([string]$n) }
    if ($Result.WuOK -and $wCount -eq 0) { [void]$dgvW.Rows.Add('(no pending Windows Updates)'); $dgvW.Rows[0].DefaultCellStyle.ForeColor = $c.Dim }
    if (-not $Result.WuOK) { [void]$dgvW.Rows.Add('(WUA scan failed -- WU service may be broken)'); $dgvW.Rows[0].DefaultCellStyle.ForeColor = $c.Danger }

    ## --- Pending Apps (right, full height) ---
    $aCount = @($Result.AppNames).Count
    $aHdr = if ($Result.AppsOK) { if ($aCount -gt 0) { "Pending App Updates  ($aCount)" } else { "Pending App Updates  (current)" } } else { "Pending App Updates  (scan error)" }
    $aFg  = if ($Result.AppsOK) { if ($aCount -gt 0) { $c.Warning } else { $c.Success } } else { $c.Danger }
    $lblA = New-Lbl -Text $aHdr -X 460 -Y 120 -W 430 -Font $fn.LabelB -Fg $aFg

    $dgvA = New-Object System.Windows.Forms.DataGridView
    $dgvA.Location = New-Object System.Drawing.Point(460, 142); $dgvA.Size = New-Object System.Drawing.Size(430, 410)
    $dgvA.ReadOnly = $true; $dgvA.RowHeadersVisible = $false; $dgvA.AllowUserToAddRows = $false
    Style-Grid $dgvA
    $colA = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colA.Name = 'App'; $colA.HeaderText = 'Application'; $colA.AutoSizeMode = 'Fill'; [void]$dgvA.Columns.Add($colA)
    foreach ($n in @($Result.AppNames)) { [void]$dgvA.Rows.Add([string]$n) }
    if ($Result.AppsOK -and $aCount -eq 0) { [void]$dgvA.Rows.Add('(no pending apps)'); $dgvA.Rows[0].DefaultCellStyle.ForeColor = $c.Dim }

    ## Footer buttons
    $btnAm = New-Btn -Text "Open App Manager" -X 10  -Y 568 -W 160 -H 30 -Bg $c.Cyan
    $btnCp = New-Btn -Text "Copy to Clipboard" -X 178 -Y 568 -W 160 -H 30 -Bg $c.PanelLight
    $btnEx = New-Btn -Text "Export CSV"        -X 346 -Y 568 -W 120 -H 30 -Bg $c.Accent
    $btnCl = New-Btn -Text "Close"             -X 780 -Y 568 -W 110 -H 30 -Bg $c.Danger

    $btnAm.Add_Click({ Show-AppManager -TargetHost $h }.GetNewClosure())
    $btnCp.Add_Click({
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Host: $h")
        [void]$sb.AppendLine("Scan time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("Online: $online")
        [void]$sb.AppendLine("Drive: $driveTxt")
        [void]$sb.AppendLine("Reboot: $rebootTxt")
        [void]$sb.AppendLine("Last boot: $lastBoot")
        if (-not [string]::IsNullOrWhiteSpace($Result.Error)) { [void]$sb.AppendLine("Error: $($Result.Error)") }
        [void]$sb.AppendLine(""); [void]$sb.AppendLine("=== MECM Software Updates ($uCount) ===")
        foreach ($n in @($Result.UpdateNames)) { [void]$sb.AppendLine("  $n") }
        [void]$sb.AppendLine(""); [void]$sb.AppendLine("=== Direct Windows Update ($wCount) ===")
        foreach ($n in @($Result.WuNames)) { [void]$sb.AppendLine("  $n") }
        [void]$sb.AppendLine(""); [void]$sb.AppendLine("=== Pending Apps ($aCount) ===")
        foreach ($n in @($Result.AppNames)) { [void]$sb.AppendLine("  $n") }
        try { [System.Windows.Forms.Clipboard]::SetText($sb.ToString()) } catch {}
    }.GetNewClosure())
    $btnEx.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_HostDetails_${h}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        if ($sfd.ShowDialog() -eq 'OK') {
            $rows = @()
            foreach ($n in @($Result.UpdateNames)) { $rows += [PSCustomObject]@{ Host=$h; Channel='MECM'; Name=$n } }
            foreach ($n in @($Result.WuNames))     { $rows += [PSCustomObject]@{ Host=$h; Channel='WU';   Name=$n } }
            foreach ($n in @($Result.AppNames))    { $rows += [PSCustomObject]@{ Host=$h; Channel='App';  Name=$n } }
            if ($rows.Count -eq 0) { $rows += [PSCustomObject]@{ Host=$h; Channel='None'; Name='(host is current)' } }
            $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation
        }
    }.GetNewClosure())
    $btnCl.Add_Click({ $dlg.Close() })

    $dlg.Controls.AddRange(@($lblHost, $lblOnline, $pnlSt, $lblU, $dgvU, $lblW, $dgvW, $lblA, $dgvA, $btnAm, $btnCp, $btnEx, $btnCl))
    $dlg.ShowDialog() | Out-Null
    $dlg.Dispose()
}
#endregion

###############################################################################
###                          APP MANAGER DIALOG                             ###
###############################################################################
## Show-AppManager - modal form used by the SCCM App Manager tab. Lists
## all CCM_Application objects on a single host with install state,
## evaluation state, version, and progress. Per-row action buttons:
## Install / Uninstall / Reinstall (uninstall + 10s wait + install) /
## Repair. Actions run over a PSSession back to the target and trigger
## the appropriate CCM_Application method.
#region === APP MANAGER DIALOG ===
function Show-AppManager {
    param([string]$TargetHost)
    if ([string]::IsNullOrWhiteSpace($TargetHost)) { return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $auth = "Negotiate"
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "App Manager - $TargetHost"; $dlg.ClientSize = New-Object System.Drawing.Size(900, 620)
    $dlg.BackColor = $c.BG; $dlg.ForeColor = $c.White; $dlg.Font = $fn.Label
    $dlg.StartPosition = 'CenterScreen'; $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false
    $lblAmStatus = New-Lbl -Text "Querying MECM apps on $TargetHost..." -X 10 -Y 8 -W 700 -Font $fn.LabelB -Fg $c.Cyan
    $lblAmCount = New-Lbl -Text "" -X 10 -Y 30 -W 400 -Font $fn.Small -Fg $c.Dim
    $dgvApps = New-Object System.Windows.Forms.DataGridView
    $dgvApps.Location = New-Object System.Drawing.Point(6, 52); $dgvApps.Size = New-Object System.Drawing.Size(886, 420)
    $dgvApps.ReadOnly = $true; Style-Grid $dgvApps
    foreach ($col in @(@{N='Name';H='Application';F=22},@{N='InstallState';H='State';F=9},@{N='Applicable';H='Appl';F=8},@{N='EvalState';H='Eval';F=12},@{N='Version';H='Ver';F=9},@{N='Result';H='Result';F=13})) {
        $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.FillWeight = $col.F; [void]$dgvApps.Columns.Add($cc)
    }
    $btnAmRefresh = New-Btn -Text "Refresh" -X 6 -Y 480 -W 100 -H 30 -Bg $c.Accent
    $btnAmInstall = New-Btn -Text "Install Selected" -X 114 -Y 480 -W 140 -H 30 -Bg $c.Success
    $btnAmUninstall = New-Btn -Text "Uninstall Selected" -X 262 -Y 480 -W 150 -H 30 -Bg $c.Danger
    $btnAmReinstall = New-Btn -Text "Reinstall Selected" -X 420 -Y 480 -W 150 -H 30 -Bg $c.Warning
    $btnAmRepair = New-Btn -Text "Repair Selected" -X 578 -Y 480 -W 140 -H 30 -Bg $c.Purple
    $btnAmClose = New-Btn -Text "Close" -X 790 -Y 480 -W 100 -H 30 -Bg $c.PanelLight
    $rtbAmLog = New-Object System.Windows.Forms.RichTextBox
    $rtbAmLog.Location = New-Object System.Drawing.Point(6, 518); $rtbAmLog.Size = New-Object System.Drawing.Size(886, 92)
    $rtbAmLog.BackColor = $c.OutputBg; $rtbAmLog.ForeColor = $c.Console; $rtbAmLog.Font = $fn.Console
    $rtbAmLog.ReadOnly = $true; $rtbAmLog.BorderStyle = 'None'
    $AmLog = {
        param([string]$msg, [string]$lvl = 'INFO')
        $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"
        $start = $rtbAmLog.TextLength; $rtbAmLog.AppendText($line)
        $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
        $rtbAmLog.Select($start, $line.Length); $rtbAmLog.SelectionColor = $clr
        $rtbAmLog.SelectionLength = 0; $rtbAmLog.ScrollToCaret()
    }
    $QueryApps = {
        $dgvApps.Rows.Clear()
        $lblAmStatus.Text = "Querying MECM apps on $TargetHost..."; $lblAmStatus.ForeColor = $c.Cyan
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $sess = New-PSSession -ComputerName $TargetHost -Credential $global:Credentials -Authentication $auth -SessionOption $global:WSManOpt -EA Stop
            try {
                $apps = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                    @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop |
                        Select-Object Name, InstallState, ApplicabilityState, EvaluationState, Id, Revision, IsMachineTarget, SoftwareVersion)
                }
                $installed = 0; $available = 0
                foreach ($app in $apps) {
                    $idx = $dgvApps.Rows.Add(); $row = $dgvApps.Rows[$idx]
                    $row.Cells['Name'].Value = $app.Name; $row.Cells['InstallState'].Value = $app.InstallState
                    $row.Cells['Applicable'].Value = $app.ApplicabilityState; $row.Cells['Version'].Value = $app.SoftwareVersion
                    $row.Cells['Result'].Value = "--"
                    $row.Tag = @{ Id=$app.Id; Revision=$app.Revision; IsMachineTarget=$app.IsMachineTarget }
                    $evalMap = @{0='None';1='Available';2='Submitted';3='Detecting';4='PreDownload';5='Downloading';6='Wait Install';7='Installing';8='Pending Reboot';9='Pending Reboot';10='Wait Reboot';11='Verifying';12='Complete';13='Error';14='Wait Window';15='Wait Logon';16='Wait Logoff'}
                    $evalText = $evalMap[[int]$app.EvaluationState]
                    if ([string]::IsNullOrWhiteSpace($evalText)) { $evalText = "Unknown ($($app.EvaluationState))" }
                    $row.Cells['EvalState'].Value = $evalText
                    if ($app.InstallState -eq 'Installed') { $row.Cells['InstallState'].Style.ForeColor = $c.Success; $installed++ }
                    elseif ($app.InstallState -eq 'NotInstalled') { $row.Cells['InstallState'].Style.ForeColor = $c.Warning; $available++ }
                    else { $row.Cells['InstallState'].Style.ForeColor = $c.Cyan }
                }
                $lblAmStatus.Text = "Found $($apps.Count) app(s) on $TargetHost"; $lblAmStatus.ForeColor = $c.Success
                $lblAmCount.Text = "$installed installed, $available not installed, $($apps.Count) total"
                & $AmLog "Queried $($apps.Count) MECM app(s): $installed installed, $available available" 'OK'
            } finally { Remove-PSSession $sess -EA SilentlyContinue }
        } catch {
            $lblAmStatus.Text = "Query failed: $($_.Exception.Message)"; $lblAmStatus.ForeColor = $c.Danger
            & $AmLog "Query failed: $($_.Exception.Message)" 'ERR'
        }
    }
    $InvokeAppAction = {
        param([string]$Action)
        if ($dgvApps.SelectedRows.Count -eq 0) { & $AmLog "Select one or more apps in the grid first." 'WARN'; return }
        $selectedApps = @()
        foreach ($row in $dgvApps.SelectedRows) { $selectedApps += @{ Name=$row.Cells['Name'].Value; Row=$row; Meta=$row.Tag } }
        $appNames = ($selectedApps | ForEach-Object { $_.Name }) -join ", "
        $confirm = [System.Windows.Forms.MessageBox]::Show("$Action $($selectedApps.Count) app(s) on ${TargetHost}?`n`n$appNames","Confirm $Action",4,48)
        if ($confirm -ne 'Yes') { return }
        & $AmLog "--- $Action $($selectedApps.Count) app(s) on $TargetHost ---"
        try {
            $sess = New-PSSession -ComputerName $TargetHost -Credential $global:Credentials -Authentication $auth -SessionOption $global:WSManOpt -EA Stop
            try {
                foreach ($app in $selectedApps) {
                    $app.Row.Cells['Result'].Value = "Running..."; $app.Row.Cells['Result'].Style.ForeColor = $c.Warning
                    [System.Windows.Forms.Application]::DoEvents()
                    $appId = $app.Meta.Id; $appRev = $app.Meta.Revision; $appMachine = $app.Meta.IsMachineTarget; $appName = $app.Name
                    if ($Action -eq 'Reinstall') {
                        & $AmLog "  $appName : Uninstalling..." 'INFO'
                        $app.Row.Cells['Result'].Value = "Uninstalling..."
                        [System.Windows.Forms.Application]::DoEvents()
                        try {
                            Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine -EA Stop -ScriptBlock {
                                param($id, $rev, $machine)
                                $p = @{ EnforcePreference=[UINT32]0; Id=$id; IsMachineTarget=[System.Convert]::ToBoolean($machine); IsRebootIfNeeded=$false; Priority='High'; Revision=$rev }
                                Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Uninstall -Arguments $p -EA Stop | Out-Null
                            }
                            & $AmLog "  $appName : Uninstall triggered, waiting 10s..." 'OK'
                            Start-Sleep -Seconds 10
                        } catch { & $AmLog "  $appName : Uninstall error: $($_.Exception.Message)" 'ERR' }
                        & $AmLog "  $appName : Installing..." 'INFO'
                        $app.Row.Cells['Result'].Value = "Installing..."
                        [System.Windows.Forms.Application]::DoEvents()
                        try {
                            Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine -EA Stop -ScriptBlock {
                                param($id, $rev, $machine)
                                $p = @{ EnforcePreference=[UINT32]0; Id=$id; IsMachineTarget=[System.Convert]::ToBoolean($machine); IsRebootIfNeeded=$false; Priority='High'; Revision=$rev }
                                Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Install -Arguments $p -EA Stop | Out-Null
                            }
                            $app.Row.Cells['Result'].Value = "Reinstall triggered"; $app.Row.Cells['Result'].Style.ForeColor = $c.Success
                            & $AmLog "  $appName : Reinstall triggered" 'OK'
                        } catch {
                            $app.Row.Cells['Result'].Value = "Install failed"; $app.Row.Cells['Result'].Style.ForeColor = $c.Danger
                            & $AmLog "  $appName : Install error: $($_.Exception.Message)" 'ERR'
                        }
                    } else {
                        try {
                            Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine, $Action -EA Stop -ScriptBlock {
                                param($id, $rev, $machine, $method)
                                $p = @{ EnforcePreference=[UINT32]0; Id=$id; IsMachineTarget=[System.Convert]::ToBoolean($machine); IsRebootIfNeeded=$false; Priority='High'; Revision=$rev }
                                Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName $method -Arguments $p -EA Stop | Out-Null
                            }
                            $app.Row.Cells['Result'].Value = "$Action triggered"; $app.Row.Cells['Result'].Style.ForeColor = $c.Success
                            & $AmLog "  $appName : $Action triggered" 'OK'
                        } catch {
                            $app.Row.Cells['Result'].Value = "$Action failed"; $app.Row.Cells['Result'].Style.ForeColor = $c.Danger
                            & $AmLog "  $appName : $Action error: $($_.Exception.Message)" 'ERR'
                        }
                    }
                }
            } finally { Remove-PSSession $sess -EA SilentlyContinue }
        } catch { & $AmLog "Session error: $($_.Exception.Message)" 'ERR' }
        & $AmLog "--- $Action complete ---"
    }
    $btnAmRefresh.Add_Click({ & $QueryApps })
    $btnAmInstall.Add_Click({ & $InvokeAppAction "Install" })
    $btnAmUninstall.Add_Click({ & $InvokeAppAction "Uninstall" })
    $btnAmReinstall.Add_Click({ & $InvokeAppAction "Reinstall" })
    $btnAmRepair.Add_Click({ & $InvokeAppAction "Repair" })
    $btnAmClose.Add_Click({ $dlg.Close() })
    $dlg.Controls.AddRange(@($lblAmStatus, $lblAmCount, $dgvApps, $btnAmRefresh, $btnAmInstall, $btnAmUninstall, $btnAmReinstall, $btnAmRepair, $btnAmClose, $rtbAmLog))
    $dlg.Add_Shown({ & $QueryApps })
    $dlg.ShowDialog() | Out-Null; $dlg.Dispose()
}
#endregion

###############################################################################
###                               MAIN FORM                                 ###
###############################################################################
## $f = the top-level WinForms Form. Default ClientSize 1280x740,
## MinimumSize 1100x680, launches CenterScreen (not maximized). Sets
## $script:WPT.UI.Form = $f so modular dialog helpers can parent
## themselves correctly. Actual child population (top strip, status
## strip, tab control, sidebar) happens in the regions that follow;
## FORM CLEANUP & SHOW at the bottom wires FormClosing handlers and
## calls ShowDialog.
#region === MAIN FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text = "J.A.N.E.T. Workstation Patching Tool v$JanetWptVersion"
## v6.1.2: Window opens at a sensible default size on the primary monitor
## instead of forcing maximized. Default size reduced from v5's 1440x850
## so the Start tab content doesn't float inside an oversized rectangle
## on 1366x768 laptops (smallest common AFNET display). MinimumSize
## lowered to match so operators on 1280x720 remote sessions can still
## drag the window into view. Operators who want full-screen can click
## Maximize; we no longer force it.
$f.ClientSize    = New-Object System.Drawing.Size(1280, 740)
$f.MinimumSize   = New-Object System.Drawing.Size(1100, 680)
$f.StartPosition = "CenterScreen"
## v6.1.10: restore launch-maximized. v6.1.2 removed this, but with the
## v6.1.9 Cleanup-tab manual SetBounds layout in place, the tab now fills
## whatever ClientSize it gets -- so launching at the default 1280x740
## leaves the content looking cramped on big monitors, forcing operators
## to drag-resize to see everything. Maximize makes it fit the display on
## launch; operators who want a smaller window can still Restore Down.
$f.WindowState   = [System.Windows.Forms.FormWindowState]::Maximized
$f.BackColor = $c.BG; $f.ForeColor = $c.White; $f.Font = $fn.Label
## v47.1: wire the form into $script:WPT.UI.Form so modular dialog helpers
## (Show-WptClosingNotesDialog, etc.) can parent themselves correctly.
$script:WPT.UI.Form = $f
#endregion

###############################################################################
###                               TOP STRIP                                 ###
###############################################################################
## 32px dark bar docked to the top of the form. Right-anchored heartbeat
## pulse + "live" label -- primary purpose is "is the UI thread still
## alive?" at a glance. No title / logo / subtitle here; those live in
## the sidebar brand block.
#region === TOP STRIP (minimal, live indicator) ===
## v47.1: Legacy's gold-stripe header (icon + "J.A.N.E.T. Workstation Patching
## Tool" title + subtitle + gif) was removed. The wordmark/subtitle/version
## now live in the sidebar, so the top area just needs a minimal strip with
## a right-anchored "live" heartbeat indicator.
$topBar = New-Object System.Windows.Forms.Panel
$topBar.Dock      = 'Top'
$topBar.Height    = 32
$topBar.BackColor = $c.BG

## v6.5.9: Add $topBar to the form BEFORE creating its right-anchored
## children. Previously the children were created against
## $f.ClientSize.Width while $topBar was still unparented (default
## 200px wide), so WinForms froze a large negative right-anchor offset
## and the button + pulse + live label rendered hundreds of pixels
## off-screen on a maximized window. Adding $topBar first means it
## docks to the form's true client width before any child is anchored.
$f.Controls.Add($topBar)

## Thin 1px divider along the bottom of the top strip (visual separator).
## v5.1.1: $topBarDivider removed - the 1px violet-border line read as a
## light bar against the near-black bg and just looked like a visual seam.
## Top strip blends into the sidebar/content below without it.

## "live" heartbeat: pulse dot + label, anchored top-right.
$topPulse = New-WptPulseIndicator -X ($topBar.ClientSize.Width - 80) -Y 12 -Size 8 -State 'Active'
$topPulse.Anchor = 'Top,Right'

$lblLive = New-WptLabel -Text 'live' -X ($topBar.ClientSize.Width - 62) -Y 10 -W 40 -H 16 `
    -Font $script:WPT.UI.Fonts.MonoTiny -Fg $script:WPT.UI.Theme.TextFaint
$lblLive.Anchor    = 'Top,Right'
$lblLive.BackColor = [System.Drawing.Color]::Transparent

## v6.5.8: Close Tool moved here from the sidebar bottom (was overlapping
## the user block on shorter window heights, and discoverability was
## weak below the scrollable nav). Sits to the left of the live
## indicator, anchored Top,Right so it tracks the right edge on resize.
##
## v6.5.10: Closing-notes prompt moved from FormClosing into the click
## handler. Previously the dialog ran inside FormClosing _after_ the
## Legacy cleanup handler had already disposed timers/jobs/RSPool, so
## "Return to Tool" couldn't actually return -- the tool was already in
## a half-torn-down state. It also only fired when SessionStarted was
## true, so the operator couldn't add notes from a pre-session abort.
## Now: click → notes dialog → if Cancel ('Return to Tool'), bail out
## with the form still healthy; if Submit/Force, stash the outcome on
## $script:WptCloseOutcome and let FormClosing run to completion. The
## FormClosing handler below picks the outcome up and writes it to the
## audit log (always) plus the WPT CSV / JANET session close (only when
## a session was started).
$btnCloseTool = New-WptButton -Text 'Close Tool' -X ($topBar.ClientSize.Width - 200) -Y 4 -W 110 -H 24 -Bg $script:WPT.UI.Theme.Danger
$btnCloseTool.Anchor = 'Top,Right'
$btnCloseTool.Font   = $script:WPT.UI.Fonts.SmallB
$btnCloseTool.Add_Click({
    try {
        $outcome = Show-WptClosingNotesDialog
    } catch {
        ## If the dialog itself blows up, fall through to a Force-style
        ## close so a busted dialog never traps the operator inside the
        ## tool with no exit.
        $outcome = [pscustomobject]@{ Choice = 'Force'; Notes = '' }
    }
    if ([string]$outcome.Choice -eq 'Cancel') {
        ## 'Return to Tool' -- operator changed their mind. Leave the
        ## form running, no audit / CSV / JANET writes.
        return
    }
    $script:WptCloseOutcome = $outcome
    Set-JanetAllowClose $true
    $f.Close()
}.GetNewClosure())

$topBar.Controls.AddRange(@($btnCloseTool, $topPulse, $lblLive))
#endregion

###############################################################################
###                             STATUS STRIP                                ###
###############################################################################
## 32px dark bar docked to the bottom of the form. Always-visible
## indicators:
##   - heartbeat pulse (leftmost)
##   - $script:lblStatusSession - "SESSION: idle" pre-start, updated to
##     "SESSION: <user>@<host>" by the Start Session click handler.
##   - $script:lblStatusTargets - "TARGETS: <count>", updated whenever
##     $global:ComputerList changes.
##   - $script:lblStatusLog     - anchored right, shows the active
##     audit log path so the operator can tail it if needed.
#region === STATUS STRIP (bottom) ===
## Bottom status strip: heartbeat + session + targets + log path.
## Session label is updated from the Start-Session handler; targets label
## is updated anywhere $global:ComputerList changes; log path is set once.
$statusBar = New-Object System.Windows.Forms.Panel
$statusBar.Dock      = 'Bottom'
$statusBar.Height    = 32
$statusBar.BackColor = $script:WPT.UI.Theme.StatusBar

## v5.1.1: $statusTopEdge removed - same visual-seam issue as the top strip.
## Status bar now sits flush against the content above it.

$statusHeartbeat = New-WptPulseIndicator -X 10 -Y 12 -Size 8 -State 'Active'
$statusBar.Controls.Add($statusHeartbeat)

$script:lblStatusSession = New-WptLabel -Text '  SESSION: idle' -X 22 -Y 8 -W 300 -H 18 `
    -Font $script:WPT.UI.Fonts.MonoSm -Fg $script:WPT.UI.Theme.TextMuted
$script:lblStatusSession.BackColor = [System.Drawing.Color]::Transparent

$script:lblStatusTargets = New-WptLabel -Text 'TARGETS: 0' -X 330 -Y 8 -W 160 -H 18 `
    -Font $script:WPT.UI.Fonts.MonoSm -Fg $script:WPT.UI.Theme.TextMuted
$script:lblStatusTargets.BackColor = [System.Drawing.Color]::Transparent

$script:lblStatusLog = New-WptLabel -Text '' -X 500 -Y 8 -W 800 -H 18 `
    -Font $script:WPT.UI.Fonts.MonoTiny -Fg $script:WPT.UI.Theme.TextFaint
$script:lblStatusLog.BackColor = [System.Drawing.Color]::Transparent
$script:lblStatusLog.TextAlign = 'MiddleRight'
$script:lblStatusLog.Anchor    = 'Top,Left,Right'
if ($global:AuditLogPath) { $script:lblStatusLog.Text = "LOG: $($global:AuditLogPath)" }

$statusBar.Add_Resize({
    $script:lblStatusLog.Location = New-Object System.Drawing.Point(500, 8)
    $script:lblStatusLog.Size     = New-Object System.Drawing.Size(($statusBar.Width - 520), 18)
})

$statusBar.Controls.AddRange(@($script:lblStatusSession, $script:lblStatusTargets, $script:lblStatusLog))
$f.Controls.Add($statusBar)
#endregion

###############################################################################
###                    TAB CONTROL  (hidden headers)                        ###
###############################################################################
## $tc - a standard WinForms TabControl sized to fill the content area
## to the right of the sidebar. Tab strip is hidden (ItemSize height=1,
## SizeMode=Fixed, Appearance=FlatButtons, BackColor=ForeColor so the
## strip visually disappears). The operator switches tabs exclusively
## via the sidebar nav buttons -- the underlying TabControl just holds
## the pages.
#region === TAB CONTROL (hidden headers) ===
$script:SideW = 252   ## widened from Legacy's 130 for modular-style nav w/ icons + numbered index
$tc = New-Object System.Windows.Forms.TabControl
$tc.Location = New-Object System.Drawing.Point(($script:SideW - 3), 32)
$tc.Size = New-Object System.Drawing.Size(($f.ClientSize.Width - $script:SideW + 6), ($f.ClientSize.Height - 64))
$tc.Anchor = 'Top,Left,Right,Bottom'
$tc.Appearance = [System.Windows.Forms.TabAppearance]::FlatButtons
$tc.BackColor = $c.BG; $tc.ForeColor = $c.BG
$tc.ItemSize = New-Object System.Drawing.Size(0, 1)
$tc.SizeMode = [System.Windows.Forms.TabSizeMode]::Fixed
$tc.Padding = New-Object System.Drawing.Point(0, 0)
#endregion

###############################################################################
###                          TAB 0: START / ABOUT                           ###
###############################################################################
## The landing tab. Always reachable pre-session (session-gated tabs are
## unreachable until START SESSION is clicked). Contains:
##   - AUTHOR group                 (static credit line)
##   - CREDENTIALS (Required) group - Set Credentials button (or
##     "Override Credentials" if inherited from JANET),
##     credentials-status label, threads NumericUpDown.
##   - RESPONSIBILITY ACKNOWLEDGMENT (Required) group - Yes/No radios.
##   - START SESSION button - gates credentials + ack, then flips
##     $global:SessionStarted = $true, populates Session Info, enables
##     the rest of the sidebar.
##   - SESSION INFORMATION group    (operator, session time, creds,
##     threads, audit path, PowerShell version).
##   - Three bottom-row buttons (v6.1.0): Change Log / About /
##     How To Use  - each opens a scroll-capable Show-WptInfoDialog.
#region === TAB 0: START / ABOUT ===
$script:tabStartAbout = New-Object System.Windows.Forms.TabPage; $script:tabStartAbout.BackColor = $c.BG

## v47.1: Legacy's middle "NAVIGATE TO SECTION" nav-card column was removed
## from the Start tab - its job (jumping to other tabs) is now fully covered
## by the modular sidebar added in Task 1.8a. We keep $script:NavCards as an
## empty array so any legacy references (the WIRE NAV CARDS TO TABS loop and
## the Start-Session dim/brighten pass) iterate zero items and stay harmless.
$script:NavCards = @()

$pnlAbout = New-Object System.Windows.Forms.Panel; $pnlAbout.Location = New-Object System.Drawing.Point(4, 4)
$pnlAbout.Size = New-Object System.Drawing.Size(1180, 680); $pnlAbout.Anchor = 'Top,Left,Right,Bottom'; $pnlAbout.BackColor = $c.Panel
$lblToolName = New-Object System.Windows.Forms.Label; $lblToolName.Text = "Workstation Patching Tool"
$lblToolName.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblToolName.ForeColor = $c.Gold; $lblToolName.AutoSize = $true; $lblToolName.Location = New-Object System.Drawing.Point(20, 8)
$lblToolFull = New-Object System.Windows.Forms.Label; $lblToolFull.Text = "J.A.N.E.T. - Joint Administration and Network Execution Toolkit"
$lblToolFull.Font = $fn.Sub; $lblToolFull.ForeColor = $c.Dim; $lblToolFull.AutoSize = $true; $lblToolFull.Location = New-Object System.Drawing.Point(22, 40)
$lblVersion = New-Object System.Windows.Forms.Label; $lblVersion.Text = "Version 6.5.14"
$lblVersion.Font = $fn.LabelB; $lblVersion.ForeColor = $c.Success; $lblVersion.AutoSize = $true; $lblVersion.Location = New-Object System.Drawing.Point(22, 58)
$grpCredits = New-Grp -Text "AUTHOR" -X 14 -Y 80 -W 900 -H 46 -Fg $c.Cyan
$lblCreator = New-Object System.Windows.Forms.Label; $lblCreator.Text = "Braxton Thompson  |  48CS/SCOO  |  braxton.thompson.1.ctr@us.af.mil"
$lblCreator.Font = $fn.Small; $lblCreator.ForeColor = $c.White; $lblCreator.AutoSize = $true; $lblCreator.Location = New-Object System.Drawing.Point(12, 22)
$grpCredits.Controls.Add($lblCreator)
## v6.0.0: PACKAGE ROOT DIRECTORY group removed along with the Package
## Deploy tab. The UNC path was only consumed by that tab's Load-Packages
## routine. Deploy-Application.ps1 pushes now happen in J.A.N.E.T.'s
## standalone Remote Package Installer tool.
$grpCreds = New-Grp -Text "CREDENTIALS (Required)" -X 14 -Y 132 -W 900 -H 100 -Fg $c.Warning
$lblCredHint = New-Object System.Windows.Forms.Label; $lblCredHint.Text = "You must set ADW admin credentials before starting a session."
$lblCredHint.Font = $fn.Small; $lblCredHint.ForeColor = $c.White; $lblCredHint.AutoSize = $true; $lblCredHint.Location = New-Object System.Drawing.Point(12, 22)
$script:btnSetCredStart = New-Btn -Text "Set Credentials" -X 12 -Y 44 -W 150 -H 30 -Bg $c.Accent -Font $fn.BtnBig
$script:lblCredStatus = New-Lbl -Text "No credentials set" -X 170 -Y 50 -W 300 -Font $fn.LabelB -Fg $c.Warning
$lblThreadLblStart = New-Lbl -Text "Threads:" -X 480 -Y 52 -W 55
$script:nudThreads = New-Object System.Windows.Forms.NumericUpDown; $script:nudThreads.Location = New-Object System.Drawing.Point(540, 48)
$script:nudThreads.Size = New-Object System.Drawing.Size(48, 24); $script:nudThreads.Minimum = 1; $script:nudThreads.Maximum = 30
$script:nudThreads.Value = 10; $script:nudThreads.BackColor = $c.Input; $script:nudThreads.ForeColor = $c.White
$script:btnSetCredStart.Add_Click({
    $global:Credentials = Get-Credential -Message "Enter admin credentials for remote workstation operations"
    if ($global:Credentials) { $script:lblCredStatus.Text = $global:Credentials.UserName; $script:lblCredStatus.ForeColor = $c.Success; Log "Credentials set: $($global:Credentials.UserName)" 'OK' }
})
$grpCreds.Controls.AddRange(@($lblCredHint, $script:btnSetCredStart, $script:lblCredStatus, $lblThreadLblStart, $script:nudThreads))
$grpAck = New-Grp -Text "RESPONSIBILITY ACKNOWLEDGMENT (Required)" -X 14 -Y 238 -W 900 -H 100 -Fg $c.Danger
$lblAckText = New-Object System.Windows.Forms.Label
$lblAckText.Text = "This tool performs remote patching, application management, reboots, and package deployment across workstations. Incorrect use can disrupt end-user systems. Do you accept responsibility and confirm you understand the impact of these operations?"
$lblAckText.Font = $fn.Small; $lblAckText.ForeColor = $c.White; $lblAckText.AutoSize = $false
$lblAckText.Size = New-Object System.Drawing.Size(870, 36); $lblAckText.Location = New-Object System.Drawing.Point(12, 22)
$script:rbAckYes = New-Object System.Windows.Forms.RadioButton; $script:rbAckYes.Text = "Yes, I understand and accept responsibility"
$script:rbAckYes.ForeColor = $c.Success; $script:rbAckYes.Font = $fn.LabelB; $script:rbAckYes.AutoSize = $true; $script:rbAckYes.Location = New-Object System.Drawing.Point(12, 62)
$script:rbAckNo = New-Object System.Windows.Forms.RadioButton; $script:rbAckNo.Text = "No"
$script:rbAckNo.ForeColor = $c.Danger; $script:rbAckNo.Font = $fn.LabelB; $script:rbAckNo.AutoSize = $true; $script:rbAckNo.Location = New-Object System.Drawing.Point(400, 62)
$script:lblAckStatus = New-Lbl -Text "Select Yes or No before starting." -X 12 -Y 80 -W 400 -Font $fn.Small -Fg $c.Warning
$script:rbAckYes.Add_CheckedChanged({ if ($script:rbAckYes.Checked) { $script:lblAckStatus.Text = "Acknowledged."; $script:lblAckStatus.ForeColor = $c.Success } })
$script:rbAckNo.Add_CheckedChanged({ if ($script:rbAckNo.Checked) { $script:lblAckStatus.Text = "You must accept responsibility to use this tool."; $script:lblAckStatus.ForeColor = $c.Danger } })
$grpAck.Controls.AddRange(@($lblAckText, $script:rbAckYes, $script:rbAckNo, $script:lblAckStatus))
$script:btnStartSession = New-Btn -Text "START SESSION" -X 14 -Y 344 -W 900 -H 44 -Bg $c.Success
$script:btnStartSession.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$script:btnStartSession.FlatAppearance.BorderSize = 2; $script:btnStartSession.FlatAppearance.BorderColor = $c.Success
$script:btnStartSession.Add_Click({
    if (-not $global:Credentials) { $script:lblCredStatus.Text = "You must set credentials first!"; $script:lblCredStatus.ForeColor = $c.Danger; [System.Windows.Forms.MessageBox]::Show("Click 'Set Credentials' and enter your admin credentials before starting.","Credentials Required",0,48); return }
    if (-not $script:rbAckYes.Checked) {
        if ($script:rbAckNo.Checked) { $script:lblAckStatus.Text = "You cannot proceed without accepting responsibility."; $script:lblAckStatus.ForeColor = $c.Danger; [System.Windows.Forms.MessageBox]::Show("You selected 'No'. You must accept responsibility to use this tool.","Acknowledgment Required",0,48) }
        else { $script:lblAckStatus.Text = "Select Yes or No before starting."; $script:lblAckStatus.ForeColor = $c.Warning; [System.Windows.Forms.MessageBox]::Show("Please select Yes or No for the responsibility acknowledgment.","Acknowledgment Required",0,48) }
        return
    }
    ## v6.0.0: package-root resolution removed (Package Deploy tab gone).
    $global:ThreadCount = [int]$script:nudThreads.Value
    $global:SessionStarted = $true

    ## JANET centralized session (added in v6.2.0). Starts after the operator
    ## has accepted credentials + ack and clicked START SESSION, so we don't
    ## record empty rows for users who launch WPT and bail on the Start tab.
    ## v6.2.2: dropped the explicit -Operator override. $global:Credentials.UserName
    ## was returning a Microsoft-Account session token (e.g. @@B9s-HOxYf...) that
    ## made the rollup CSV unreadable. Letting Start-JanetSession default to
    ## Get-JanetOperatorIdentity yields "EDIPI - DisplayName" via AD lookup, same
    ## pattern SIM_Tool uses; falls back to $env:USERNAME if AD is unreachable.
    try {
        Start-JanetSession -Tool 'WPT' -Version $JanetWptVersion
    } catch {
        Log "JANET Start-JanetSession failed: $($_.Exception.Message)" 'WARN'
    }
    ## Bottom status strip updates (v47.1): show session user@host in lavender
    ## primary text to indicate session is live.
    if ($script:lblStatusSession) {
        $script:lblStatusSession.Text      = "  SESSION: $env:USERNAME@$env:COMPUTERNAME"
        $script:lblStatusSession.ForeColor = $script:WPT.UI.Theme.TextPrimary
    }
    $script:btnStartSession.Text = "SESSION STARTED"; $script:btnStartSession.ForeColor = $c.Dim; $script:btnStartSession.BackColor = $c.PanelLight
    $script:btnStartSession.FlatAppearance.BorderColor = $c.Dim; $script:btnStartSession.Enabled = $false
    $script:btnSetCredStart.Enabled = $false; $script:nudThreads.Enabled = $false
    $script:rbAckYes.Enabled = $false; $script:rbAckNo.Enabled = $false
    $script:lblSIUser.Text = "Operator:  $env:USERNAME"; $script:lblSITime.Text = "Session:   $(Get-Date -Format 'g')"
    $script:lblSICred.Text = "Credentials: $($global:Credentials.UserName)"; $script:lblSICred.ForeColor = $c.Success
    $script:lblSIAuth.Text = "Threads: $([int]$script:nudThreads.Value)"
    ## v47.1: NavCards column removed; the foreach-dim-cards loop and the
    ## $script:lblNavLocked visibility toggle that used to live here are gone
    ## with it. The modular sidebar's session-gating handles unlock visuals.
    & $UpdateSidebar
    Log "=== SESSION STARTED === Creds: $($global:Credentials.UserName) | Threads: $global:ThreadCount" 'OK'
    Write-AuditLog -Action "SessionStart" -Result "Started" -Detail "User=$($global:Credentials.UserName) Threads=$global:ThreadCount"
})
$grpSession = New-Grp -Text "SESSION INFORMATION" -X 14 -Y 394 -W 900 -H 100 -Fg $c.Cyan
$script:lblSIUser = New-Lbl -Text "Operator:  $env:USERNAME" -X 12 -Y 24 -W 400 -Font $fn.Label -Fg $c.Cyan
$script:lblSITime = New-Lbl -Text "Session:   $(Get-Date -Format 'g')" -X 12 -Y 44 -W 400 -Font $fn.Label -Fg $c.White
$script:lblSICred = New-Lbl -Text "Credentials: (not set)" -X 420 -Y 24 -W 400 -Font $fn.Small -Fg $c.Dim
$script:lblSIAuth = New-Lbl -Text "Threads: --" -X 420 -Y 44 -W 400 -Font $fn.Small -Fg $c.Dim
$lblSILog = New-Lbl -Text "Audit: $($global:AuditLogPath)" -X 12 -Y 64 -W 870 -Font $fn.Small -Fg $c.Dim
$lblSIPSVer = New-Lbl -Text "PowerShell: $($PSVersionTable.PSVersion.ToString())" -X 12 -Y 80 -W 300 -Font $fn.Small -Fg $c.Dim
$grpSession.Controls.AddRange(@($script:lblSIUser, $script:lblSITime, $script:lblSICred, $script:lblSIAuth, $lblSILog, $lblSIPSVer))

## v6.1.0: Info buttons row -- replaces the About and How To Use tabs.
## Below Session Information (grpSession ends at Y=494). Three buttons in
## one row call modular Show-Wpt*Dialog helpers to pop themed read-only
## dialogs. Content lives in $script:WPT_AboutText / ChangeLogText /
## HowToUseText (region just above).
$script:btnInfoChangeLog = New-Btn -Text "Change Log" -X 14  -Y 510 -W 290 -H 36 -Bg $c.PanelLight -Font $fn.BtnBig
$script:btnInfoAbout     = New-Btn -Text "About"      -X 318 -Y 510 -W 290 -H 36 -Bg $c.PanelLight -Font $fn.BtnBig
$script:btnInfoHowTo     = New-Btn -Text "How To Use" -X 622 -Y 510 -W 292 -H 36 -Bg $c.PanelLight -Font $fn.BtnBig
$script:btnInfoChangeLog.FlatAppearance.BorderSize = 1; $script:btnInfoChangeLog.FlatAppearance.BorderColor = $c.Accent
$script:btnInfoAbout.FlatAppearance.BorderSize     = 1; $script:btnInfoAbout.FlatAppearance.BorderColor     = $c.Cyan
$script:btnInfoHowTo.FlatAppearance.BorderSize     = 1; $script:btnInfoHowTo.FlatAppearance.BorderColor     = $c.Gold
$script:btnInfoChangeLog.ForeColor = $c.Accent
$script:btnInfoAbout.ForeColor     = $c.Cyan
$script:btnInfoHowTo.ForeColor     = $c.Gold
$script:btnInfoChangeLog.Add_Click({ try { Show-WptChangeLogDialog } catch { [System.Windows.Forms.MessageBox]::Show("Change Log dialog failed: $($_.Exception.Message)","Error",0,16) } })
$script:btnInfoAbout.Add_Click({     try { Show-WptAboutDialog     } catch { [System.Windows.Forms.MessageBox]::Show("About dialog failed: $($_.Exception.Message)","Error",0,16) } })
$script:btnInfoHowTo.Add_Click({     try { Show-WptHowToUseDialog  } catch { [System.Windows.Forms.MessageBox]::Show("How To Use dialog failed: $($_.Exception.Message)","Error",0,16) } })

$pnlAbout.Controls.AddRange(@($lblToolName, $lblToolFull, $lblVersion, $grpCredits, $grpCreds, $grpAck, $script:btnStartSession, $grpSession, $script:btnInfoChangeLog, $script:btnInfoAbout, $script:btnInfoHowTo))
$script:tabStartAbout.Controls.Add($pnlAbout)
#endregion

## v6.1.0: TAB: HOW TO USE removed. Content is now accessed via the
## "How To Use" button on the Start tab (Show-WptHowToUseDialog popup
## backed by $script:WPT_HowToUseText defined above).

###############################################################################
###                             TAB 1: TARGETS                              ###
###############################################################################
## Owner of $global:ComputerList - the shared target list every
## operation reads. Four input paths:
##   - Paste hostnames (multiline textbox + Add to List)
##   - Import TXT file (one-per-line list)
##   - Import ACAS CSV (auto-detects DNS Name / NetBIOS / IP columns
##     and de-dupes)
##   - Import XLSX (Excel workbook, first column)
## Output side: shared listbox ($script:lbxTargets) + Remove Selected
## (red, destructive) + Clear All. Per-action counts flow to the
## STATUS STRIP's TARGETS label.
#region === TAB 1: TARGETS ===
$tabTargets = New-Object System.Windows.Forms.TabPage; $tabTargets.BackColor = $c.BG
$grpTargets = New-Grp -Text "TARGET WORKSTATIONS" -X 6 -Y 6 -W 1100 -H 260 -Fg $c.Gold
$grpTargets.Anchor = 'Top,Left,Right'
$lblPaste = New-Lbl -Text "Paste hostnames (one per line, comma, or space separated):" -X 10 -Y 22 -W 400 -Font $fn.Small
$script:txtPaste = New-Tb -X 10 -Y 40 -W 440 -H 140 -Multi; $script:txtPaste.Font = $fn.Console; $script:txtPaste.ForeColor = $c.Cyan
$btnAdd = New-Btn -Text "Add to List" -X 10 -Y 186 -W 90 -H 26 -Bg $c.Success
$btnImport = New-Btn -Text "Import TXT" -X 104 -Y 186 -W 84 -H 26 -Bg $c.PanelLight
$btnImportAcas = New-Btn -Text "Import ACAS" -X 192 -Y 186 -W 88 -H 26 -Bg $c.Purple
$btnImportXlsx = New-Btn -Text "Import XLSX" -X 284 -Y 186 -W 88 -H 26 -Bg $c.Cyan; $btnImportXlsx.ForeColor = [System.Drawing.Color]::Black
$btnClear = New-Btn -Text "Clear All" -X 376 -Y 186 -W 74 -H 26 -Bg $c.Danger
$lblCount = New-Lbl -Text "0 workstation(s) loaded" -X 10 -Y 218 -W 200 -Font $fn.SmallB -Fg $c.Dim
## v6.1.3: lbxTargets shrunk + aligned to match the paste textbox next to
## it (both H=140, both Y=40). Previously the listbox started at Y=22 and
## ran 188 tall, making the left and right halves of the row asymmetric.
$script:lbxTargets = New-Object System.Windows.Forms.ListBox; $script:lbxTargets.Location = New-Object System.Drawing.Point(460,40)
$script:lbxTargets.Size = New-Object System.Drawing.Size(626,140); $script:lbxTargets.BackColor = $c.Input; $script:lbxTargets.ForeColor = $c.Cyan
$script:lbxTargets.Font = $fn.Console; $script:lbxTargets.SelectionMode = 'MultiExtended'
## v6.1.3: Remove Selected moved up to Y=186 to align with the paste-side
## button row, and repainted red (Danger) to signal "destructive - removes
## items from the list".
$btnRemove = New-Btn -Text "Remove Selected" -X 460 -Y 186 -W 130 -H 26 -Bg $c.Danger; $btnRemove.Font = $fn.Small
$btnAdd.Add_Click({
    $names = Parse-Hosts $script:txtPaste.Text
    foreach ($n in $names) { if ($script:lbxTargets.Items -notcontains $n) { [void]$script:lbxTargets.Items.Add($n) } }
    $global:ComputerList = @($script:lbxTargets.Items); $script:txtPaste.Clear()
    $lblCount.Text = "$($global:ComputerList.Count) workstation(s) loaded"
    $lblCount.ForeColor = if ($global:ComputerList.Count -gt 0) { $c.Success } else { $c.Dim }
    Log "Added $($names.Count) host(s). Total: $($global:ComputerList.Count)"
})
$btnImport.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "Text/CSV|*.txt;*.csv|All|*.*"
    if ($ofd.ShowDialog() -eq 'OK') {
        $lines = Get-Content $ofd.FileName -EA Stop | ForEach-Object { ($_ -split "[,;]")[0].Trim() } | Where-Object { $_ -ne "" }
        foreach ($n in $lines) { if ($script:lbxTargets.Items -notcontains $n) { [void]$script:lbxTargets.Items.Add($n) } }
        $global:ComputerList = @($script:lbxTargets.Items)
        $lblCount.Text = "$($global:ComputerList.Count) workstation(s) loaded"; $lblCount.ForeColor = $c.Success
        Log "Imported $($lines.Count) from $(Split-Path $ofd.FileName -Leaf). Total: $($global:ComputerList.Count)" 'OK'
    }
})
$btnImportAcas.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "ACAS CSV|*.csv|All|*.*"; $ofd.Title = "Select ACAS / Nessus CSV Export"
    if ($ofd.ShowDialog() -ne 'OK') { return }
    try {
        $csv = @(Import-Csv -Path $ofd.FileName -EA Stop)
        if ($csv.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("CSV is empty or could not be parsed.","Import Error"); return }
        $headers = $csv[0].PSObject.Properties.Name
        $colDNS = $headers | Where-Object { $_ -match '(?i)^DNS\s*Name$|^FQDN$|^DNS$' } | Select-Object -First 1
        $colNetBIOS = $headers | Where-Object { $_ -match '(?i)^NetBIOS\s*Name$|^NetBIOS$|^Host\s*Name$' } | Select-Object -First 1
        $colIP = $headers | Where-Object { $_ -match '(?i)^IP\s*Address$|^IP$|^Host$' } | Select-Object -First 1
        if (-not $colDNS -and -not $colNetBIOS -and -not $colIP) {
            $colList = ($headers | Select-Object -First 10) -join ", "
            [System.Windows.Forms.MessageBox]::Show("Could not find DNS Name, NetBIOS Name, or IP Address columns.`n`nColumns found: $colList","ACAS Import Error"); return
        }
        $added = 0; $skipped = 0; $hostnames = @{}
        foreach ($row in $csv) {
            $hostname = $null
            if ($colDNS -and -not [string]::IsNullOrWhiteSpace($row.$colDNS)) { $hostname = $row.$colDNS.Trim() }
            elseif ($colNetBIOS -and -not [string]::IsNullOrWhiteSpace($row.$colNetBIOS)) { $hostname = $row.$colNetBIOS.Trim() }
            elseif ($colIP -and -not [string]::IsNullOrWhiteSpace($row.$colIP)) { $hostname = $row.$colIP.Trim() }
            if (-not [string]::IsNullOrWhiteSpace($hostname)) { $hostnames[$hostname] = $true }
        }
        foreach ($h in $hostnames.Keys) { if ($script:lbxTargets.Items -notcontains $h) { [void]$script:lbxTargets.Items.Add($h); $added++ } else { $skipped++ } }
        $global:ComputerList = @($script:lbxTargets.Items)
        $lblCount.Text = "$($global:ComputerList.Count) workstation(s) loaded"; $lblCount.ForeColor = $c.Success
        $colUsed = if ($colDNS) { "DNS Name" } elseif ($colNetBIOS) { "NetBIOS Name" } else { "IP Address" }
        Log "ACAS Import: $added new, $skipped duplicates from $(Split-Path $ofd.FileName -Leaf) (primary column: $colUsed). Total: $($global:ComputerList.Count)" 'OK'
        Write-AuditLog -Action "ImportACAS" -Result "Success" -Detail "$added added, $skipped skipped, $($hostnames.Count) unique from $($csv.Count) rows"
    } catch { [System.Windows.Forms.MessageBox]::Show("Failed to parse ACAS CSV:`n$($_.Exception.Message)","Import Error"); Log "ACAS Import failed: $($_.Exception.Message)" 'ERR' }
})
$btnImportXlsx.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Excel Files|*.xlsx|All|*.*"
    $ofd.Title = "Select XLSX Vulnerabilities Export"
    if ($ofd.ShowDialog() -ne 'OK') { return }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -EA Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ofd.FileName)
        try {
            $ssEntry = $zip.Entries | Where-Object { $_.FullName -eq 'xl/sharedStrings.xml' } | Select-Object -First 1
            $sharedStrings = @()
            if ($ssEntry) {
                $sr = New-Object System.IO.StreamReader($ssEntry.Open())
                $ssXml = [xml]$sr.ReadToEnd(); $sr.Close(); $sr.Dispose()
                $ns = New-Object System.Xml.XmlNamespaceManager($ssXml.NameTable)
                $ns.AddNamespace('s', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main')
                $siNodes = $ssXml.SelectNodes('//s:si', $ns)
                foreach ($si in $siNodes) { $sharedStrings += $si.InnerText }
            }
            $sheetEntry = $zip.Entries | Where-Object { $_.FullName -match '^xl/worksheets/sheet1\.xml$' } | Select-Object -First 1
            if (-not $sheetEntry) { [System.Windows.Forms.MessageBox]::Show("Could not find sheet1 in the XLSX file.","Import Error"); return }
            $sr2 = New-Object System.IO.StreamReader($sheetEntry.Open())
            $sheetXml = [xml]$sr2.ReadToEnd(); $sr2.Close(); $sr2.Dispose()
            $ns2 = New-Object System.Xml.XmlNamespaceManager($sheetXml.NameTable)
            $ns2.AddNamespace('s', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main')
            $rows = $sheetXml.SelectNodes('//s:sheetData/s:row', $ns2)
            if ($rows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Sheet is empty.","Import Error"); return }
            $GetCellValue = {
                param($cell)
                $val = $cell.v
                if ($null -eq $val) { return "" }
                if ($cell.t -eq 's' -and $sharedStrings.Count -gt 0) {
                    $idx = [int]$val
                    if ($idx -lt $sharedStrings.Count) { return $sharedStrings[$idx] }
                }
                return $val
            }
            $GetColLetter = { param($ref); ($ref -replace '[0-9]', '') }
            $headerRow = $rows[0]
            $headerCells = $headerRow.SelectNodes('s:c', $ns2)
            $hostCol = $null; $hostColName = ""
            foreach ($cell in $headerCells) {
                $headerVal = & $GetCellValue $cell
                if ($headerVal -match '(?i)^Host\s*Name$|^DNS\s*Name$|^NetBIOS\s*Name$|^Computer\s*Name$|^Host$|^FQDN$|^IP\s*Address$|^IP$|^DNS$|^NetBIOS$') {
                    $hostCol = & $GetColLetter $cell.r; $hostColName = $headerVal; break
                }
            }
            if (-not $hostCol) {
                $colList = @(); foreach ($cell in $headerCells) { $colList += & $GetCellValue $cell }
                [System.Windows.Forms.MessageBox]::Show("Could not find a hostname column in the first row.`n`nColumns found: $(($colList | Select-Object -First 15) -join ', ')","XLSX Import Error"); return
            }
            $hostnames = @{}
            for ($ri = 1; $ri -lt $rows.Count; $ri++) {
                $dataCells = $rows[$ri].SelectNodes('s:c', $ns2)
                foreach ($cell in $dataCells) {
                    $colLetter = & $GetColLetter $cell.r
                    if ($colLetter -eq $hostCol) { $val = & $GetCellValue $cell; if (-not [string]::IsNullOrWhiteSpace($val)) { $hostnames[$val.Trim()] = $true }; break }
                }
            }
            if ($hostnames.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No hostnames found in column '$hostColName'.","XLSX Import"); return }
            $added = 0; $skipped = 0
            foreach ($h in $hostnames.Keys) { if ($script:lbxTargets.Items -notcontains $h) { [void]$script:lbxTargets.Items.Add($h); $added++ } else { $skipped++ } }
            $global:ComputerList = @($script:lbxTargets.Items)
            $lblCount.Text = "$($global:ComputerList.Count) workstation(s) loaded"; $lblCount.ForeColor = $c.Success
            Log "XLSX Import: $added new, $skipped duplicates from $(Split-Path $ofd.FileName -Leaf) (column: $hostColName). Total: $($global:ComputerList.Count)" 'OK'
            Write-AuditLog -Action "ImportXLSX" -Result "Success" -Detail "$added added, $skipped skipped, $($hostnames.Count) unique"
        } finally { $zip.Dispose() }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to parse XLSX:`n$($_.Exception.Message)","Import Error")
        Log "XLSX Import failed: $($_.Exception.Message)" 'ERR'
    }
})
$btnClear.Add_Click({ $script:lbxTargets.Items.Clear(); $global:ComputerList = @(); $lblCount.Text = "0 workstation(s) loaded"; $lblCount.ForeColor = $c.Dim; Log "Target list cleared." })
$btnRemove.Add_Click({ $sel = @($script:lbxTargets.SelectedItems); foreach ($i in $sel) { $script:lbxTargets.Items.Remove($i) }; $global:ComputerList = @($script:lbxTargets.Items); $lblCount.Text = "$($global:ComputerList.Count) workstation(s) loaded" })
$grpTargets.Controls.AddRange(@($lblPaste, $script:txtPaste, $btnAdd, $btnImport, $btnImportAcas, $btnImportXlsx, $btnClear, $lblCount, $script:lbxTargets, $btnRemove))
$tabTargets.Controls.Add($grpTargets)
#endregion

###############################################################################
###                       TAB 2: BULK SCAN & PATCH                          ###
###############################################################################
## The core "scan fleet, then patch what needs it" workflow. 10-column
## grid ($script:dgvBulk):
##   [sel] Host | Online | C: Drive | Reboot Pending | Updates | Apps |
##   Scan Status | Patch Status
## Toolbar buttons (wired in BULK SCAN/PATCH/REBOOT EVENT HANDLERS
## region near the bottom of the file):
##   Scan All      - fire $global:ScanBlock per host via RSPool.
##   Select With Updates - auto-check rows where Updates > 0 or Apps > 0.
##   Patch Selected - fire $global:PatchBlock per checked row.
##   Reboot Selected - fire $global:RebootBlock per checked row, then
##                     optionally launch Show-RebootMonitor.
##   Ping Sweep    - TCP probe only (fast online/offline refresh).
##   Export CSV    - dump grid contents to disk.
#region === TAB 2: BULK SCAN & PATCH ===
$tabBulk = New-Object System.Windows.Forms.TabPage; $tabBulk.BackColor = $c.BG
$pnlAct = New-Object System.Windows.Forms.Panel; $pnlAct.Location = New-Object System.Drawing.Point(6,6); $pnlAct.Size = New-Object System.Drawing.Size(1100,40); $pnlAct.BackColor = $c.Panel; $pnlAct.Anchor = 'Top,Left,Right'
$script:btnScanAll = New-Btn -Text "Scan All" -X 6 -Y 4 -W 120 -H 30 -Bg $c.Success -Font $fn.BtnBig
$script:btnPatchSel = New-Btn -Text "Patch Selected" -X 134 -Y 4 -W 140 -H 30 -Bg $c.Warning -Font $fn.BtnBig
$script:btnRebootSel = New-Btn -Text "Reboot Selected" -X 282 -Y 4 -W 140 -H 30 -Bg $c.Danger -Font $fn.BtnBig
$btnExport = New-Btn -Text "Export CSV" -X 430 -Y 4 -W 110 -H 30 -Bg $c.Accent
$script:lblBulkProg = New-Lbl -Text "Load targets on Targets tab, then Scan All." -X 560 -Y 10 -W 500 -Font $fn.Small -Fg $c.Dim
$pnlAct.Controls.AddRange(@($script:btnScanAll, $script:btnPatchSel, $script:btnRebootSel, $btnExport, $script:lblBulkProg))
$pnlSel = New-Object System.Windows.Forms.Panel; $pnlSel.Location = New-Object System.Drawing.Point(6,50); $pnlSel.Size = New-Object System.Drawing.Size(1100,32); $pnlSel.BackColor = [System.Drawing.Color]::FromArgb(16,16,30); $pnlSel.Anchor = 'Top,Left,Right'
$btnSelAll = New-Btn -Text "Select All" -X 6 -Y 4 -W 90 -H 24 -Bg $c.PanelLight; $btnSelAll.Font = $fn.Small
$btnSelNone = New-Btn -Text "Deselect" -X 102 -Y 4 -W 80 -H 24 -Bg $c.PanelLight; $btnSelNone.Font = $fn.Small
$btnSelUpd = New-Btn -Text "Select With Updates" -X 188 -Y 4 -W 150 -H 24 -Bg $c.PanelLight; $btnSelUpd.Font = $fn.Small
$script:btnPingSweep = New-Btn -Text "Ping Sweep" -X 344 -Y 4 -W 100 -H 24 -Bg $c.Purple; $script:btnPingSweep.Font = $fn.Small
$btnAppMgr = New-Btn -Text "App Manager" -X 452 -Y 4 -W 110 -H 24 -Bg $c.Cyan; $btnAppMgr.Font = $fn.Small
$btnAppMgr.Add_Click({ $host2 = $null; if ($script:dgvBulk.SelectedRows.Count -gt 0) { $host2 = $script:dgvBulk.SelectedRows[0].Cells[1].Value }; if ([string]::IsNullOrWhiteSpace($host2)) { [System.Windows.Forms.MessageBox]::Show("Click a row in the grid first.","No Host Selected"); return }; Show-AppManager -TargetHost $host2 })
## v6.2.6: per-host drill-down (KBs + apps from cached scan result)
$btnHostDetails = New-Btn -Text "Host Details" -X 730 -Y 4 -W 110 -H 24 -Bg $c.Purple; $btnHostDetails.Font = $fn.SmallB
$btnHostDetails.Add_Click({
    if ($script:dgvBulk.SelectedRows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Click a row in the grid first.","No Host Selected"); return }
    $row = $script:dgvBulk.SelectedRows[0]
    if ($null -eq $row.Tag) { [System.Windows.Forms.MessageBox]::Show("This host has not been scanned yet. Run Scan All first.","Not Scanned",0,64); return }
    Show-HostScanDetails -Result $row.Tag
})
$btnSelAll.Add_Click({ foreach ($row in $script:dgvBulk.Rows) { $row.Cells[0].Value = $true } })
$btnSelNone.Add_Click({ foreach ($row in $script:dgvBulk.Rows) { $row.Cells[0].Value = $false } })
$btnSelUpd.Add_Click({ foreach ($row in $script:dgvBulk.Rows) { $has = ($row.Cells[5].Value -like '*update*') -or ($row.Cells[6].Value -like '*app*') -or ($row.Cells[9].Value -like '*update*'); $row.Cells[0].Value = $has } })
$script:btnPatchNeeding = New-Btn -Text "Patch All Needing" -X 570 -Y 4 -W 150 -H 24 -Bg $c.Warning; $script:btnPatchNeeding.Font = $fn.SmallB
$script:btnPatchNeeding.Add_Click({
    if ($script:dgvBulk.Rows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No scan results. Run Scan All first.","Nothing to Patch"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $needing = @()
    foreach ($row in $script:dgvBulk.Rows) { $hasWork = ($row.Cells[5].Value -like '*update*') -or ($row.Cells[6].Value -like '*app*') -or ($row.Cells[9].Value -like '*update*'); $row.Cells[0].Value = $hasWork; if ($hasWork) { $needing += $row.Cells[1].Value } }
    if ($needing.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("All workstations are current -- nothing needs patching.","All Current"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Patch $($needing.Count) workstation(s) that have pending updates/apps?`n`nReboot will be suppressed.", "Confirm Patch All Needing", 4, 48)
    if ($confirm -ne 'Yes') { return }
    $auth = "Negotiate"
    $script:btnPatchNeeding.Enabled = $false; $script:btnPatchSel.Enabled = $false; $script:btnScanAll.Enabled = $false
    foreach ($srv in $needing) { foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[1].Value -eq $srv) { $row.Cells[8].Value = "Patching..."; $row.Cells[8].Style.ForeColor = $c.Warning; break } } }
    Log "=== Patching $($needing.Count) workstation(s) with pending updates/apps ==="
    $script:PatchJobs = @{}
    foreach ($comp in $needing) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($global:PatchBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($auth); $script:PatchJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:PatchTotal = $needing.Count
    $script:PatchTimer = New-Object System.Windows.Forms.Timer; $script:PatchTimer.Interval = 600
    $script:PatchTimer.Add_Tick({
        foreach ($key in @($script:PatchJobs.Keys)) {
            $job = $script:PatchJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() } catch { $res = @{ Host=$key; Reachable=$false; Error=$_.ToString(); UpdatesTriggered=0; AppsTriggered=0 } }
            $script:PatchJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null; foreach ($r in $script:dgvBulk.Rows) { if ($r.Cells[1].Value -eq $res.Host) { $row = $r; break } }
            if ($null -eq $row) { continue }
            if ($res.Error) { $row.Cells[8].Value = "Error: $($res.Error)"; $row.Cells[8].Style.ForeColor = $c.Danger }
            elseif ($res.UpdatesTriggered -eq 0 -and $res.AppsTriggered -eq 0) { $row.Cells[8].Value = "Nothing to patch"; $row.Cells[8].Style.ForeColor = $c.Success }
            else { $parts = @(); if ($res.UpdatesTriggered -gt 0) { $parts += "$($res.UpdatesTriggered) upd" }; if ($res.AppsTriggered -gt 0) { $parts += "$($res.AppsTriggered) app" }; $row.Cells[8].Value = "Triggered: $($parts -join ', ')"; $row.Cells[8].Style.ForeColor = $c.Success }
            Log "  $($res.Host): Upd=$($res.UpdatesTriggered) App=$($res.AppsTriggered) $($res.Error)"
            if ($res.UpdatesTriggered -gt 0) { for ($ui = 0; $ui -lt $res.UpdatesTriggered; $ui++) { Track-Action -Action 'PatchUpdate' -Target $res.Host -Result 'Triggered' } }
            if ($res.AppsTriggered -gt 0) { for ($ai = 0; $ai -lt $res.AppsTriggered; $ai++) { Track-Action -Action 'PatchApp' -Target $res.Host -Result 'Triggered' } }
        }
        $done = $script:PatchTotal - $script:PatchJobs.Count; $script:lblBulkProg.Text = "Patching: $done / $script:PatchTotal"
        if ($script:PatchJobs.Count -eq 0) { $script:PatchTimer.Stop(); $script:PatchTimer.Dispose(); $script:btnPatchNeeding.Enabled = $true; $script:btnPatchSel.Enabled = $true; $script:btnScanAll.Enabled = $true; $script:lblBulkProg.Text = "Patch complete: $script:PatchTotal workstation(s)"; $script:lblBulkProg.ForeColor = $c.Success; Log "=== Patch All Needing complete ===" }
    })
    $script:PatchTimer.Start()
})
## v6.3.0 (Ninkxz/WinRM-fix): Repair WinRM bootstraps WinRM via DCOM on
## selected rows whose Online cell shows 'No'. Same runspace pool +
## drain-timer pattern as Patch All Needing. Online hosts are skipped --
## if 5985 already answers there's nothing to bootstrap.
$script:btnRepairWinRM = New-Btn -Text "Repair WinRM" -X 850 -Y 4 -W 130 -H 24 -Bg $c.Cyan; $script:btnRepairWinRM.Font = $fn.SmallB
$script:btnRepairWinRM.Add_Click({
    if ($script:dgvBulk.Rows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No rows in the grid. Run Scan All or Ping Sweep first so we know which hosts are offline.","Nothing to Repair") | Out-Null; return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials") | Out-Null; return }
    $targets = @()
    foreach ($row in $script:dgvBulk.Rows) {
        if ($row.Cells[0].Value -eq $true) {
            $online = [string]$row.Cells[2].Value
            if ($online -ne 'Yes' -and $online -ne 'Online') { $targets += [string]$row.Cells[1].Value }
        }
    }
    if ($targets.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Tick the rows you want to repair first.`n`nRepair WinRM only acts on selected rows whose status is NOT online. If a row is already online there's nothing to bootstrap.","Nothing Selected") | Out-Null; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Attempt WinRM bootstrap on $($targets.Count) host(s)?`n`nThis uses DCOM (port 135) to:`n  - Set the WinRM service to Automatic`n  - Start the service`n  - Run winrm quickconfig -force -quiet -skipNetworkProfileCheck`n  - Re-probe port 5985`n`nFails gracefully on hosts that don't answer on DCOM either.","Repair WinRM",4,48)
    if ($confirm -ne 'Yes') { return }
    $script:btnRepairWinRM.Enabled = $false; $script:btnScanAll.Enabled = $false; $script:btnPatchSel.Enabled = $false
    foreach ($srv in $targets) { foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[1].Value -eq $srv) { $row.Cells[8].Value = "Repairing WinRM..."; $row.Cells[8].Style.ForeColor = $c.Warning; break } } }
    Log "=== WinRM bootstrap on $($targets.Count) host(s) ==="
    Initialize-RunspacePool
    $script:RepairJobs = @{}
    foreach ($comp in $targets) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:WinRMBootstrapBlock).AddArgument($comp).AddArgument($global:Credentials)
        $script:RepairJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() }
    }
    $script:RepairTotal = $targets.Count
    $script:RepairTimer = New-Object System.Windows.Forms.Timer; $script:RepairTimer.Interval = 600
    $script:RepairTimer.Add_Tick({
        foreach ($key in @($script:RepairJobs.Keys)) {
            $job = $script:RepairJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Success=$false; Error=$_.ToString(); PostProbeOk=$false; Steps=@() } }
            $script:RepairJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null; foreach ($r2 in $script:dgvBulk.Rows) { if ($r2.Cells[1].Value -eq $res.Host) { $row = $r2; break } }
            if ($null -eq $row) { continue }
            if ($res.Success -and $res.PostProbeOk) {
                $row.Cells[8].Value = "WinRM up"; $row.Cells[8].Style.ForeColor = $c.Success
                $row.Cells[2].Value = "Yes";      $row.Cells[2].Style.ForeColor = $c.Success
                Log "  $($res.Host): WinRM bootstrap succeeded" 'OK'
                Track-Action -Action 'WinRMBootstrap' -Target $res.Host -Result 'OK' -Detail (($res.Steps -join '; '))
            } elseif ($res.Error) {
                $row.Cells[8].Value = "Error: $($res.Error)"; $row.Cells[8].Style.ForeColor = $c.Danger
                Log "  $($res.Host): $($res.Error)" 'ERR'
                Track-Action -Action 'WinRMBootstrap' -Target $res.Host -Result 'Fail' -Detail $res.Error
            } else {
                $row.Cells[8].Value = "Bootstrap ran - 5985 still closed"; $row.Cells[8].Style.ForeColor = $c.Warning
                Log "  $($res.Host): bootstrap ran but WinRM still not reachable" 'WARN'
                Track-Action -Action 'WinRMBootstrap' -Target $res.Host -Result 'Partial' -Detail (($res.Steps -join '; '))
            }
            foreach ($s in @($res.Steps)) { Log "    $($res.Host): $s" }
        }
        $done = $script:RepairTotal - $script:RepairJobs.Count
        $script:lblBulkProg.Text = "Repairing WinRM: $done / $script:RepairTotal"
        if ($script:RepairJobs.Count -eq 0) {
            $script:RepairTimer.Stop(); $script:RepairTimer.Dispose()
            $script:btnRepairWinRM.Enabled = $true; $script:btnScanAll.Enabled = $true; $script:btnPatchSel.Enabled = $true
            $script:lblBulkProg.Text = "WinRM repair complete: $script:RepairTotal host(s). Re-scan to refresh."
            $script:lblBulkProg.ForeColor = $c.Success
            Log "=== WinRM bootstrap complete ===" 'OK'
        }
    })
    $script:RepairTimer.Start()
})
$pnlSel.Controls.AddRange(@($btnSelAll, $btnSelNone, $btnSelUpd, $script:btnPatchNeeding, $script:btnPingSweep, $btnAppMgr, $btnHostDetails, $script:btnRepairWinRM))
$script:dgvBulk = New-Object System.Windows.Forms.DataGridView
$script:dgvBulk.Location = New-Object System.Drawing.Point(6, 86); $script:dgvBulk.Size = New-Object System.Drawing.Size(1100, 560)
$script:dgvBulk.Anchor = 'Top,Left,Right,Bottom'; $script:dgvBulk.ReadOnly = $false; Style-Grid $script:dgvBulk
$script:dgvBulk.AutoSizeColumnsMode = 'None'; $script:dgvBulk.ScrollBars = 'Both'
$colChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn; $colChk.Name = "Sel"; $colChk.HeaderText = ""; $colChk.Width = 35; $colChk.TrueValue = $true; $colChk.FalseValue = $false; [void]$script:dgvBulk.Columns.Add($colChk)
## v6.2.6: 'Updates' header relabeled to 'MECM' for channel clarity
## (CCM_SoftwareUpdate). New 'WU' column reflects the direct Windows
## Update Agent scan -- machines that pull from WSUS / Microsoft Update
## without an SCCM deployment used to show as 'Current' in the old Upd
## column. The WU column is appended at logical index 9 (so existing
## Cells[1..8] references stay valid) and visually shifted to display
## index 6 -- right after MECM, before Apps.
foreach ($col in @(@{N='Host';H='Host';W=170},@{N='Online';H='Up';W=65},@{N='Drive';H='C:';W=110},@{N='Reboot';H='Reb';W=55},@{N='Updates';H='MECM';W=95},@{N='Apps';H='App';W=70},@{N='ScanSt';H='Scan';W=75},@{N='PatchSt';H='Patch';W=130})) {
    $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; $cc.ReadOnly = $true; [void]$script:dgvBulk.Columns.Add($cc)
}
$colWu = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colWu.Name = 'WU'; $colWu.HeaderText = 'WU'; $colWu.Width = 90; $colWu.ReadOnly = $true; [void]$script:dgvBulk.Columns.Add($colWu)
$colWu.DisplayIndex = 6   ## visually slot between MECM (display 5) and Apps (was display 6 -> shifts to 7)
$script:dgvBulk.Add_CurrentCellDirtyStateChanged({ if ($script:dgvBulk.IsCurrentCellDirty) { $script:dgvBulk.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })
## v6.2.6: double-click any data cell (not the checkbox column, not header) to open Host Details.
$script:dgvBulk.Add_CellDoubleClick({
    param($s, $e)
    if ($e.RowIndex -lt 0) { return }
    if ($e.ColumnIndex -le 0) { return }   ## ignore checkbox column
    $row = $script:dgvBulk.Rows[$e.RowIndex]
    if ($null -eq $row.Tag) { [System.Windows.Forms.MessageBox]::Show("This host has not been scanned yet. Run Scan All first.","Not Scanned",0,64); return }
    Show-HostScanDetails -Result $row.Tag
})
$tabBulk.Controls.AddRange(@($pnlAct, $pnlSel, $script:dgvBulk))
#endregion

###############################################################################
###                    TAB: SOFTWARE MANAGER  (Sw Mgr & Uninstaller)        ###
###############################################################################
## Single-host registry-based software scan + native uninstall. Reads
## HKLM:\...\Uninstall, HKLM:\SOFTWARE\WOW6432Node\...\Uninstall, and
## HKCU (admin hive via PSSession; this scans the interactive user's
## hive only if credentials were set to that user -- documented limit).
## Quick filter: Chrome / Edge / M365 / Teams / Tanium / Adobe.
## Specialized uninstall handlers:
##   - Microsoft 365 (Click-to-Run): OfficeC2RClient.exe /update + the
##     SaRA M365 uninstall package script, copied over the PSSession.
##   - Adobe Acrobat: RunAsPPL removal (wrapped in try/finally so LSASS
##     protection is always restored), multi-GUID MsiExec sweep to
##     catch siblings.
#region === TAB: SOFTWARE MANAGER (Sw Mgr & Uninstaller) ===
## v43 NOTE (HKCU limitation): When scanning via Invoke-Command, HKCU refers to the
## admin account's registry hive (the credential used for the remote session), NOT the
## interactive user's hive. Per-user Store apps and HKCU-installed software for the
## logged-in user may not appear in scan results. This is a known WinRM limitation.
$tabSoftware = New-Object System.Windows.Forms.TabPage; $tabSoftware.BackColor = $c.BG
$pnlSwBar = New-Object System.Windows.Forms.Panel; $pnlSwBar.Location = New-Object System.Drawing.Point(6, 6)
$pnlSwBar.Size = New-Object System.Drawing.Size(1100, 42); $pnlSwBar.BackColor = $c.Panel; $pnlSwBar.Anchor = 'Top,Left,Right'
$lblSwHost = New-Lbl -Text "Host:" -X 6 -Y 12 -W 40 -Font $fn.LabelB -Fg $c.TextSec
$script:ddlSwHost = New-Object System.Windows.Forms.ComboBox; $script:ddlSwHost.Location = New-Object System.Drawing.Point(48, 8)
$script:ddlSwHost.Size = New-Object System.Drawing.Size(220, 24); $script:ddlSwHost.BackColor = $c.Input; $script:ddlSwHost.ForeColor = $c.Cyan
$script:ddlSwHost.DropDownStyle = 'DropDownList'; $script:ddlSwHost.Font = $fn.Label
$script:btnSwScan = New-Btn -Text "Scan Software" -X 278 -Y 6 -W 130 -H 30 -Bg $c.Accent -Font $fn.BtnBig
$script:btnSwUninstall = New-Btn -Text "Uninstall Selected" -X 416 -Y 6 -W 150 -H 30 -Bg $c.Danger; $script:btnSwUninstall.Enabled = $false
$btnSwExport = New-Btn -Text "Export CSV" -X 574 -Y 6 -W 100 -H 30 -Bg $c.Success; $btnSwExport.Enabled = $false
$script:lblSwProg = New-Lbl -Text "Select a target host, then click Scan." -X 690 -Y 12 -W 400 -Font $fn.Small -Fg $c.Dim
$pnlSwBar.Controls.AddRange(@($lblSwHost, $script:ddlSwHost, $script:btnSwScan, $script:btnSwUninstall, $btnSwExport, $script:lblSwProg))
$pnlSwFilter = New-Object System.Windows.Forms.Panel; $pnlSwFilter.Location = New-Object System.Drawing.Point(6, 52)
$pnlSwFilter.Size = New-Object System.Drawing.Size(1100, 32); $pnlSwFilter.BackColor = [System.Drawing.Color]::FromArgb(16,16,30); $pnlSwFilter.Anchor = 'Top,Left,Right'
$lblSwQuickFilter = New-Lbl -Text "Quick:" -X 6 -Y 7 -W 40 -Font $fn.LabelB -Fg $c.Gold
$script:ddlSwQuickFilter = New-Object System.Windows.Forms.ComboBox; $script:ddlSwQuickFilter.Location = New-Object System.Drawing.Point(48, 4)
$script:ddlSwQuickFilter.Size = New-Object System.Drawing.Size(180, 24); $script:ddlSwQuickFilter.BackColor = $c.Input; $script:ddlSwQuickFilter.ForeColor = $c.White
$script:ddlSwQuickFilter.DropDownStyle = 'DropDownList'; $script:ddlSwQuickFilter.Font = $fn.Label
[void]$script:ddlSwQuickFilter.Items.AddRange(@("All Applications","Chrome","Edge","Microsoft 365","Microsoft Teams","Tanium","Adobe","MSXML / XML Core Services"))
$script:ddlSwQuickFilter.SelectedIndex = 0
$lblSwFilter = New-Lbl -Text "Search:" -X 240 -Y 7 -W 50 -Font $fn.LabelB -Fg $c.TextSec
$script:txtSwFilter = New-Tb -X 292 -Y 4 -W 200 -H 24; $script:txtSwFilter.Font = $fn.Console
$script:lblSwCount = New-Lbl -Text "" -X 850 -Y 7 -W 240 -Font $fn.SmallB -Fg $c.Dim
$pnlSwFilter.Controls.AddRange(@($lblSwQuickFilter, $script:ddlSwQuickFilter, $lblSwFilter, $script:txtSwFilter, $script:lblSwCount))
$script:dgvSw = New-Object System.Windows.Forms.DataGridView
$script:dgvSw.Location = New-Object System.Drawing.Point(6, 88); $script:dgvSw.Size = New-Object System.Drawing.Size(1100, 400)
$script:dgvSw.Anchor = 'Top,Left,Right,Bottom'; $script:dgvSw.ReadOnly = $true; Style-Grid $script:dgvSw
$script:dgvSw.AutoSizeColumnsMode = 'None'; $script:dgvSw.ScrollBars = 'Both'; $script:dgvSw.MultiSelect = $true
foreach ($col in @(@{N='Name';H='Application';W=300},@{N='Version';H='Version';W=110},@{N='Publisher';H='Publisher';W=200},@{N='InstallDate';H='Installed';W=85},@{N='Type';H='Type';W=75},@{N='Size';H='Size';W=70})) {
    $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvSw.Columns.Add($cc)
}
$lblSwLogTitle = New-Lbl -Text "SOFTWARE LOG" -X 10 -Y 494 -W 200 -Font $fn.LabelB -Fg $c.Gold; $lblSwLogTitle.Anchor = 'Left,Bottom'
$script:rtbSwLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbSwLog.Location = New-Object System.Drawing.Point(6, 512); $script:rtbSwLog.Size = New-Object System.Drawing.Size(1100, 140)
$script:rtbSwLog.Anchor = 'Left,Right,Bottom'; $script:rtbSwLog.BackColor = $c.OutputBg; $script:rtbSwLog.ForeColor = $c.Console
$script:rtbSwLog.Font = $fn.Console; $script:rtbSwLog.ReadOnly = $true; $script:rtbSwLog.BorderStyle = 'None'; $script:rtbSwLog.WordWrap = $false; $script:rtbSwLog.ScrollBars = 'Vertical'
function SwLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbSwLog) { try { if (-not $script:rtbSwLog.IsHandleCreated) { $script:rtbSwLog.CreateControl() }; $script:rtbSwLog.AppendText($line) } catch {} }
    Log "[SoftwareMgr] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents()
}
$script:SwAllResults = @(); $script:SwCurrentHost = ""
function Populate-SwGrid {
    $script:dgvSw.Rows.Clear()
    $quickFilter = $script:ddlSwQuickFilter.SelectedItem; $textFilter = $script:txtSwFilter.Text.Trim()
    $data = $script:SwAllResults
    if ($quickFilter -and $quickFilter -ne "All Applications") {
        if ($quickFilter -eq 'MSXML / XML Core Services') {
            ## v6.5.19: MSXML appears under several different display
            ## names depending on whether it's a standalone redist, a
            ## chained install, or a KB package. Match all of them.
            $data = @($data | Where-Object {
                $_.Name -like '*MSXML*' -or
                $_.Name -like '*XML Parser*' -or
                $_.Name -like '*XML Core Services*' -or
                $_.Name -like '*XML 4*' -or
                $_.Name -like '*XML 6*'
            })
        } else {
            $data = @($data | Where-Object { $_.Name -like "*$quickFilter*" -or $_.Publisher -like "*$quickFilter*" })
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($textFilter)) { $data = @($data | Where-Object { $_.Name -like "*$textFilter*" -or $_.Publisher -like "*$textFilter*" -or $_.Version -like "*$textFilter*" }) }
    foreach ($sw in ($data | Sort-Object Name)) {
        $idx = $script:dgvSw.Rows.Add(); $row = $script:dgvSw.Rows[$idx]
        $row.Cells['Name'].Value = $sw.Name; $row.Cells['Version'].Value = $sw.Version
        $row.Cells['Publisher'].Value = $sw.Publisher; $row.Cells['InstallDate'].Value = $sw.InstallDate
        $row.Cells['Type'].Value = $sw.Type; $row.Cells['Size'].Value = $sw.Size; $row.Tag = $sw
        switch ($sw.Type) {
            'MSI'                 { $row.Cells['Type'].Style.ForeColor = $c.Success }
            'EXE'                 { $row.Cells['Type'].Style.ForeColor = $c.Cyan }
            'Store'               { $row.Cells['Type'].Style.ForeColor = $c.Purple }
            'KB'                  { $row.Cells['Type'].Style.ForeColor = $c.Cyan }
            'DLL'                 { $row.Cells['Type'].Style.ForeColor = $c.Warning }
            'DLL (OS-protected)'  { $row.Cells['Type'].Style.ForeColor = $c.Dim }
        }
    }
    $filterLabel = if ($quickFilter -eq "All Applications") { "" } else { " (filter: $quickFilter)" }
    $script:lblSwCount.Text = "Showing $($data.Count) of $($script:SwAllResults.Count)$filterLabel"; $script:lblSwCount.ForeColor = $c.Cyan
}
$script:txtSwFilter.Add_TextChanged({ Populate-SwGrid })
$script:ddlSwQuickFilter.Add_SelectedIndexChanged({ if ($script:SwAllResults.Count -eq 0) { return }; Populate-SwGrid })
$tabSoftware.Add_Enter({
    $current = $script:ddlSwHost.SelectedItem; $script:ddlSwHost.Items.Clear()
    foreach ($comp in $global:ComputerList) { [void]$script:ddlSwHost.Items.Add($comp) }
    if ($current -and $script:ddlSwHost.Items.Contains($current)) { $script:ddlSwHost.SelectedItem = $current }
    elseif ($script:ddlSwHost.Items.Count -gt 0) { $script:ddlSwHost.SelectedIndex = 0 }
})
$script:btnSwScan.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($script:ddlSwHost.SelectedIndex -lt 0) { [System.Windows.Forms.MessageBox]::Show("Select a target host.","No Host"); return }
    $target = $script:ddlSwHost.SelectedItem; $script:SwCurrentHost = $target; $script:SwAllResults = @(); $script:dgvSw.Rows.Clear()
    $script:btnSwUninstall.Enabled = $false; $btnSwExport.Enabled = $false; $script:txtSwFilter.Clear(); $script:ddlSwQuickFilter.SelectedIndex = 0
    $script:lblSwProg.Text = "Scanning $target..."; $script:lblSwProg.ForeColor = $c.Warning
    SwLog "========================================"; SwLog "Scanning software on $target..."
    [System.Windows.Forms.Application]::DoEvents()
    try {
        ## v43 NOTE: HKCU paths scan the remoting admin's hive, not the interactive user's.
        $software = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ScriptBlock {
            $allApps = @()
            $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
            foreach ($rp in $regPaths) {
                Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } | ForEach-Object {
                    $type = if ($_.UninstallString -match 'msiexec') { 'MSI' } else { 'EXE' }
                    $sizeKB = if ($_.EstimatedSize) { "$([Math]::Round($_.EstimatedSize / 1024, 1)) MB" } else { "" }
                    $allApps += @{ Name=$_.DisplayName; Version=$_.DisplayVersion; Publisher=$_.Publisher; InstallDate=$_.InstallDate; Type=$type; Size=$sizeKB; UninstallString=$_.UninstallString; QuietUninstall=$_.QuietUninstallString; PSChildName=$_.PSChildName }
                }
            }
            Get-AppxPackage -AllUsers -EA SilentlyContinue | ForEach-Object {
                $allApps += @{ Name=$_.Name; Version=$_.Version; Publisher=$_.Publisher; InstallDate=""; Type="Store"; Size=""; UninstallString=""; QuietUninstall=""; PSChildName=$_.PackageFullName }
            }

            ## v6.5.19: MSXML KB-package detection. The MSXML 4 SP3
            ## servicing line ships its hotfixes under HKLM:\SOFTWARE\
            ## Microsoft\Updates\Microsoft XML Core Services *\KB*
            ## (parent key one of "Microsoft XML Core Services 4.0
            ## Service Pack 3" / "Microsoft XML Parser 4 ..." / etc.)
            ## These don't appear under the regular Uninstall hive so
            ## without this branch the operator can't see them.
            try {
                $msxmlParents = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Updates' -EA SilentlyContinue | Where-Object {
                    $_.PSChildName -like '*MSXML*' -or
                    $_.PSChildName -like '*XML Core Services*' -or
                    $_.PSChildName -like '*XML Parser*'
                })
                foreach ($parent in $msxmlParents) {
                    Get-ChildItem -LiteralPath $parent.PSPath -EA SilentlyContinue | Where-Object { $_.PSChildName -like 'KB*' } | ForEach-Object {
                        $kbProp = Get-ItemProperty -LiteralPath $_.PSPath -EA SilentlyContinue
                        $kbName = if ($kbProp.PackageName) { [string]$kbProp.PackageName } else { "$($parent.PSChildName) ($($_.PSChildName))" }
                        $kbDate = if ($kbProp.InstalledDate) { [string]$kbProp.InstalledDate } else { '' }
                        $allApps += @{
                            Name             = $kbName
                            Version          = ''
                            Publisher        = 'Microsoft Corporation'
                            InstallDate      = $kbDate
                            Type             = 'KB'
                            Size             = ''
                            ## UninstallString stuffed with the KB number so
                            ## the WPT-side dispatch can wusa /uninstall it.
                            UninstallString  = $_.PSChildName
                            QuietUninstall   = ''
                            PSChildName      = $_.PSChildName
                        }
                    }
                }
            } catch {}

            ## v6.5.19: MSXML orphan-DLL detection. Tenable plugin 62758
            ## scans the FILESYSTEM, so msxml4*.dll / msxml3*.dll files
            ## left behind by partial removals get flagged even with no
            ## Add/Remove entry pointing at them.
            ## msxml6*.dll is OS-bundled (Vista+, %WINDIR%\System32) --
            ## SFC will restore it and removing it bricks Windows; we
            ## surface it as Type='DLL (OS-protected)' so the operator
            ## can SEE it (and know not to chase it) but the uninstall
            ## handler refuses to touch it.
            $dllDirs = @('C:\Windows\System32', 'C:\Windows\SysWOW64')
            foreach ($dir in $dllDirs) {
                if (-not (Test-Path -LiteralPath $dir)) { continue }
                try {
                    $msxmlDlls = @(Get-ChildItem -LiteralPath $dir -Filter 'msxml*.dll' -File -Force -EA SilentlyContinue)
                } catch { continue }
                foreach ($d in $msxmlDlls) {
                    $isOsBundled = ($d.Name -match '^msxml6[a-z]?\.dll$')
                    $dllType = if ($isOsBundled) { 'DLL (OS-protected)' } else { 'DLL' }
                    $verInfo = ''
                    try { $verInfo = [string]$d.VersionInfo.FileVersion } catch {}
                    $sizeStr = "$([Math]::Round($d.Length / 1KB, 0)) KB"
                    $bitness = if ($dir -like '*SysWOW64*') { '32-bit' } else { '64-bit' }
                    $allApps += @{
                        Name             = "$($d.Name) [$bitness] - $($d.FullName)"
                        Version          = $verInfo
                        Publisher        = 'Microsoft Corporation'
                        InstallDate      = $d.LastWriteTime.ToString('yyyy-MM-dd')
                        Type             = $dllType
                        Size             = $sizeStr
                        ## UninstallString stuffed with the full DLL path so
                        ## the dispatch can regsvr32 /u + delete it.
                        UninstallString  = $d.FullName
                        QuietUninstall   = ''
                        PSChildName      = $d.Name
                    }
                }
            }

            return $allApps
        }
        $script:SwAllResults = @($software | ForEach-Object {
            [PSCustomObject]@{ Name=if($_ -is [hashtable]){$_['Name']}else{$_.Name}; Version=if($_ -is [hashtable]){$_['Version']}else{$_.Version}; Publisher=if($_ -is [hashtable]){$_['Publisher']}else{$_.Publisher}; InstallDate=if($_ -is [hashtable]){$_['InstallDate']}else{$_.InstallDate}; Type=if($_ -is [hashtable]){$_['Type']}else{$_.Type}; Size=if($_ -is [hashtable]){$_['Size']}else{$_.Size}; UninstallString=if($_ -is [hashtable]){$_['UninstallString']}else{$_.UninstallString}; QuietUninstall=if($_ -is [hashtable]){$_['QuietUninstall']}else{$_.QuietUninstall}; PSChildName=if($_ -is [hashtable]){$_['PSChildName']}else{$_.PSChildName} }
        })
        SwLog "$target : $($script:SwAllResults.Count) application(s) found" 'OK'; Populate-SwGrid
        if ($script:SwAllResults.Count -gt 0) { $script:btnSwUninstall.Enabled = $true; $btnSwExport.Enabled = $true }
        $script:lblSwProg.Text = "$($script:SwAllResults.Count) apps on $target"; $script:lblSwProg.ForeColor = $c.Success
        SwLog "========================================"
    } catch { SwLog "FAILED: $($_.Exception.Message)" 'ERR'; $script:lblSwProg.Text = "Scan failed"; $script:lblSwProg.ForeColor = $c.Danger }
    Write-AuditLog -Action "SoftwareScan" -Target $target -Result "Complete" -Detail "$($script:SwAllResults.Count) apps"
})
$script:btnSwUninstall.Add_Click({
    if (-not $global:Credentials) { return }
    if ([string]::IsNullOrWhiteSpace($script:SwCurrentHost)) { return }
    if ($script:dgvSw.SelectedRows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Select one or more applications to uninstall.","No Selection"); return }
    $target = $script:SwCurrentHost; $selected = @()
    foreach ($row in $script:dgvSw.SelectedRows) { if ($null -ne $row.Tag) { $selected += $row.Tag } }
    if ($selected.Count -eq 0) { return }
    $appNames = ($selected | ForEach-Object { $_.Name }) -join "`n  "
    $confirm = [System.Windows.Forms.MessageBox]::Show("Uninstall $($selected.Count) application(s) from ${target}?`n`n  $appNames`n`nThis uses the native uninstaller (not MECM). Cannot be undone!","Confirm Uninstall",4,48)
    if ($confirm -ne 'Yes') { return }
    $script:btnSwUninstall.Enabled = $false
    SwLog "========================================"; SwLog "Uninstalling $($selected.Count) app(s) on $target"; SwLog "========================================"
    $success = 0; $failed = 0
    foreach ($app in $selected) {
        ## v43 FIX: Initialize $result to prevent stale value from previous iteration
        $result = $null
        SwLog "Uninstalling: $($app.Name) ($($app.Type))..."
        if ($app.Name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
            ## v47 AFNET: Copy over PSSession instead of \\$target\C$. Admin share
            ## is disabled or firewall-blocked on many hardened AFNET workstations.
            ## The share path itself stays configurable -- change here if the
            ## package store moves off msek-fs-01v.
            $pkgShare = "\\msek-fs-01v\Apps\10. Patching\#_Remote Patching Scripts\J.A.N.E.T\Tools\Packages\SDC NIPR - Microsoft 365 Apps for Enterprise - 220914"
            $m365Sess = $null
            try {
                if (Test-Path -LiteralPath $pkgShare -EA SilentlyContinue) {
                    $m365Sess = New-PSSession -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop
                    Invoke-Command -Session $m365Sess -EA Stop -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -Force -EA Stop | Out-Null } }
                    $pkgFiles = @(Get-ChildItem -LiteralPath $pkgShare -File -EA SilentlyContinue)
                    foreach ($pf in $pkgFiles) {
                        Copy-Item -LiteralPath $pf.FullName -Destination "C:\Temp\$($pf.Name)" -ToSession $m365Sess -Force -EA SilentlyContinue
                    }
                    SwLog "  Copied M365 package ($($pkgFiles.Count) files) to $target`:C:\Temp\ via PSSession"
                } else { SwLog "  M365 package not found at share -- will use built-in methods" }
            } catch { SwLog "  Pre-copy failed: $($_.Exception.Message) -- will use built-in methods" }
            finally { if ($m365Sess) { Remove-PSSession $m365Sess -EA SilentlyContinue } }
        }
        try {
            $result = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ArgumentList $app.Name, $app.Type, $app.UninstallString, $app.QuietUninstall, $app.PSChildName -ScriptBlock {
                param($name, $type, $unStr, $quietStr, $childName)
                try {
                    ## === v6.5.19: MSXML / KB / orphan-DLL handlers ===
                    ## OS-protected DLL: refuse early so the operator gets
                    ## a clear "this is a Windows file, fix the OS, not the
                    ## file" message instead of a confusing access-denied.
                    if ($type -eq 'DLL (OS-protected)') {
                        return "FAIL: $($name) is an OS-bundled Windows component (SFC will restore it; removing it bricks XML/COM-dependent apps). Tenable plugin 62758 against MSXML 6 OS-bundled means upgrade Windows, not remove the DLL."
                    }
                    ## KB-package uninstall: the Updates registry hive entry
                    ## stuffed the KB number (e.g. KB2758694) into $unStr at
                    ## scan time. wusa handles the actual servicing-stack work.
                    if ($type -eq 'KB') {
                        $kb = if ($unStr -match '^KB(\d+)$') { $Matches[1] } else { ($unStr -replace '\D','') }
                        if ([string]::IsNullOrWhiteSpace($kb)) { return "FAIL: KB number not parseable from '$unStr'" }
                        $wusaArgs = "/uninstall /kb:$kb /quiet /norestart"
                        $proc = Start-Process -FilePath 'wusa.exe' -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow -EA Stop
                        switch ($proc.ExitCode) {
                            0       { return "OK (wusa /uninstall /kb:$kb succeeded)" }
                            3010    { return "OK (wusa /uninstall /kb:$kb succeeded, reboot required)" }
                            2359303 { return "OK (KB$kb was not actually installed -- nothing to remove)" }
                            default { return "FAIL (wusa /uninstall /kb:$kb exit $($proc.ExitCode))" }
                        }
                    }
                    ## Orphan DLL: unregister COM, take ownership, delete.
                    ## $unStr was stuffed with the full DLL path at scan time.
                    if ($type -eq 'DLL') {
                        $dllPath = $unStr
                        if ([string]::IsNullOrWhiteSpace($dllPath) -or -not (Test-Path -LiteralPath $dllPath)) {
                            return "FAIL: DLL path not present ($dllPath)"
                        }
                        $steps = @()
                        ## Stop services likely to hold msxml*.dll open.
                        ## Best-effort -- if none are running, nothing happens.
                        $svcCandidates = @('MSExchangeTransport','W3SVC','wuauserv','BITS','wmiApSrv')
                        foreach ($s in $svcCandidates) {
                            $svc = Get-Service -Name $s -EA SilentlyContinue
                            if ($svc -and $svc.Status -eq 'Running') {
                                try { Stop-Service -Name $s -Force -EA SilentlyContinue; $steps += "stopped $s" } catch {}
                            }
                        }
                        ## regsvr32 /u against the matching bitness's regsvr32.
                        ## SysWOW64 DLLs need C:\Windows\SysWOW64\regsvr32.exe;
                        ## System32 DLLs use C:\Windows\System32\regsvr32.exe.
                        $regsvr = if ($dllPath -like '*\SysWOW64\*') { 'C:\Windows\SysWOW64\regsvr32.exe' } else { 'C:\Windows\System32\regsvr32.exe' }
                        try {
                            $rp = Start-Process -FilePath $regsvr -ArgumentList "/u /s `"$dllPath`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                            $steps += "regsvr32 /u exit=$($rp.ExitCode)"
                        } catch { $steps += "regsvr32 /u threw: $($_.Exception.Message)" }
                        ## Take ownership + grant Administrators full control,
                        ## then delete. takeown / icacls bypass the default
                        ## TrustedInstaller ACL that blocks straight Remove-Item.
                        try {
                            $to = Start-Process -FilePath 'takeown.exe' -ArgumentList "/f `"$dllPath`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                            $steps += "takeown exit=$($to.ExitCode)"
                            $ic = Start-Process -FilePath 'icacls.exe' -ArgumentList "`"$dllPath`" /grant Administrators:F /C" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                            $steps += "icacls exit=$($ic.ExitCode)"
                        } catch { $steps += "ACL adjust threw: $($_.Exception.Message)" }
                        try {
                            Remove-Item -LiteralPath $dllPath -Force -EA Stop
                            $steps += 'deleted'
                            return "OK (DLL removed: $dllPath) Steps: $($steps -join ' | ')"
                        } catch {
                            return "FAIL (DLL delete blocked -- $($_.Exception.Message)) Steps: $($steps -join ' | ')"
                        }
                    }

                    ## === Microsoft 365 handler ===
                    if ($name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                        $steps = @(); $c2rPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
                        $localCmd = "C:\Temp\Uninstall-M365.cmd"
                        $steps += "Checking for package script at $localCmd"
                        if (Test-Path $localCmd -EA SilentlyContinue) {
                            $steps += "Package script found -- executing..."; $proc = Start-Process cmd.exe -ArgumentList "/c `"$localCmd`"" -Wait -PassThru -NoNewWindow; $steps += "Script exit: $($proc.ExitCode)"
                            Get-ChildItem "C:\Temp\Uninstall-*.cmd" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
                            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (M365 removed via package script, exit $($proc.ExitCode)) Steps: $($steps -join ' | ')" }
                            $steps += "Non-zero exit -- trying built-in methods..."
                        } else { $steps += "No package script at C:\Temp -- trying built-in methods" }
                        $setupExe = Join-Path $c2rPath "setup.exe"
                        if (Test-Path $setupExe) {
                            $steps += "Found setup.exe at $setupExe"; New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                            $xmlPath = "C:\Temp\OfficeRemoveAll.xml"
                            '<Configuration><Remove All="TRUE"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' | Out-File $xmlPath -Encoding ASCII -Force
                            $steps += "Created removal XML"; $proc = Start-Process $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -PassThru -NoNewWindow; $steps += "setup.exe exit: $($proc.ExitCode)"
                            Remove-Item $xmlPath -Force -EA SilentlyContinue
                            if ($proc.ExitCode -eq 0) { return "OK (Office removed via setup.exe /configure) Steps: $($steps -join ' | ')" }
                        }
                        $c2rExe = Join-Path $c2rPath "OfficeClickToRun.exe"
                        if (Test-Path $c2rExe) {
                            $steps += "Trying OfficeClickToRun.exe..."; $c2rReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -EA SilentlyContinue
                            $prodIds = @(); if ($c2rReg.ProductReleaseIds) { $prodIds = @($c2rReg.ProductReleaseIds -split ',') }; if ($prodIds.Count -eq 0) { $prodIds = @("O365ProPlusRetail") }
                            $culture = if ($c2rReg.ClientCulture) { $c2rReg.ClientCulture } else { "en-us" }
                            foreach ($prodId in $prodIds) { $removeStr = "${prodId}.16_${culture}_x-none"; $c2rArgs = "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=$removeStr DisplayLevel=False"; $proc = Start-Process $c2rExe -ArgumentList $c2rArgs -Wait -PassThru -NoNewWindow; if ($proc.ExitCode -eq 0) { return "OK (Office removed via C2R -- $removeStr) Steps: $($steps -join ' | ')" } }
                        }
                        ## v43: Removed deprecated WMIC fallback (slow, triggers MSI self-repair)
                        if (-not [string]::IsNullOrWhiteSpace($unStr)) { $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr`"" -Wait -PassThru -NoNewWindow; if ($proc.ExitCode -eq 0) { return "OK (Office removed via uninstall string) Steps: $($steps -join ' | ')" } }
                        return "FAIL (Office -- all methods attempted) Steps: $($steps -join ' | ')"
                    }
                    ## === Adobe Acrobat handler ===
                    ## v43 CRITICAL FIX: RunAsPPL removal/restoration wrapped in try/finally
                    ## to guarantee LSASS protection is always restored even on error.
                    if ($name -match 'Adobe Acrobat') {
                        $steps = @(); $removed = $false; $pplRestoreNeeded = $false; $pplOriginalValue = $null
                        $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        try {
                            try { $pplVal = Get-ItemProperty $lsaKey -Name "RunAsPPL" -EA SilentlyContinue; if ($null -ne $pplVal -and $pplVal.RunAsPPL -ne $null) { $pplOriginalValue = $pplVal.RunAsPPL; Remove-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Force -EA Stop; $pplRestoreNeeded = $true; $steps += "RunAsPPL removed (was: $pplOriginalValue)" } } catch {}
                            try { $adobeSvcs = @('AdobeARMservice','AdobeUpdateService','AGSService'); foreach ($svc in $adobeSvcs) { $s = Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Stop-Service $svc -Force -EA SilentlyContinue } }; $adobeProcs = @('Acrobat','AcroCEF','AcroRd32','AdobeARM','AdobeCollabSync','armsvc'); foreach ($p in $adobeProcs) { Get-Process $p -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }; $steps += "Adobe processes killed" } catch {}
                            $adobeGuids = @(); $regPaths2 = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
                            foreach ($rp in $regPaths2) { Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Adobe Acrobat' } | ForEach-Object { if ($_.UninstallString -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }; if ($_.PSChildName -match '^\{') { $adobeGuids += $_.PSChildName } } }
                            $adobeGuids = @($adobeGuids | Select-Object -Unique)
                            foreach ($guid in $adobeGuids) { $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow; if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { $removed = $true } }
                        } finally {
                            ## v43: Always restore RunAsPPL regardless of success/failure
                            if ($pplRestoreNeeded) { try { New-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value $pplOriginalValue -PropertyType DWord -Force -EA Stop | Out-Null; $steps += "RunAsPPL restored to $pplOriginalValue" } catch { $steps += "WARNING: RunAsPPL restore FAILED" } }
                        }
                        if ($removed) { return "OK (Adobe removed via MSI -- $($adobeGuids.Count) GUID(s)) Steps: $($steps -join ' | ')" }
                        ## v43: Removed deprecated WMIC fallback
                        return "FAIL (Adobe -- all methods attempted) Steps: $($steps -join ' | ')"
                    }
                    ## === Generic uninstall handlers ===
                    if ($type -eq 'Store') { Get-AppxPackage -AllUsers -Name "*$name*" -EA SilentlyContinue | Remove-AppxPackage -AllUsers -EA Stop; return "OK (Store app removed)" }
                    elseif ($type -eq 'MSI') { $guid = $unStr -replace '.*(\{[^\}]+\}).*', '$1'; if ($guid -match '^\{') { $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow; if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (MSI exit $($proc.ExitCode))" } else { return "WARN (MSI exit $($proc.ExitCode))" } } else { return "FAIL: Could not extract MSI GUID" } }
                    else {
                        if (-not [string]::IsNullOrWhiteSpace($quietStr)) { $proc = Start-Process cmd.exe -ArgumentList "/c `"$quietStr`"" -Wait -PassThru -NoNewWindow; return "OK (QuietUninstall exit $($proc.ExitCode))" }
                        elseif (-not [string]::IsNullOrWhiteSpace($unStr)) { $exePath = ($unStr -split '/|--')[0].Trim('"').Trim(); if (Test-Path $exePath) { $proc = Start-Process $exePath -ArgumentList "/S /silent /quiet /uninstall /norestart" -Wait -PassThru -NoNewWindow -EA SilentlyContinue; return "OK (EXE exit $($proc.ExitCode))" } else { $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr /S /quiet /norestart`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue; return "OK (CMD exit $($proc.ExitCode))" } }
                        else { return "FAIL: No uninstall string available" }
                    }
                } catch { return "FAIL: $($_.Exception.Message)" }
            }
            if ($result -like "OK*") { SwLog "$($app.Name) : $result" 'OK'; $success++ } else { SwLog "$($app.Name) : $result" 'ERR'; $failed++ }
            if ($app.Name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                SwLog "  Cleaning M365 registry entries on $target..."
                try {
                    $regClean = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ScriptBlock {
                        $regPaths3 = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
                        $removed2 = 0; foreach ($rp in $regPaths3) { Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus|Microsoft Office' } | ForEach-Object { try { Remove-Item -LiteralPath $_.PSPath -Recurse -Force -EA Stop; $removed2++ } catch {} } }; return $removed2
                    }
                    SwLog "  Removed $regClean leftover M365 registry key(s)" 'OK'
                } catch { SwLog "  Registry cleanup failed: $($_.Exception.Message)" 'ERR' }
            }
        } catch {
            SwLog "$($app.Name) : FAILED - $($_.Exception.Message)" 'ERR'; $failed++
            $result = "FAIL: $($_.Exception.Message)"
        }
        ## v43 FIX: $result is now always set (initialized at top, set in catch)
        Write-AuditLog -Action "SoftwareUninstall" -Target "$target\$($app.Name)" -Result $(if ($result -like "OK*") { "Success" } else { "Failed" }) -Detail $result
        [System.Windows.Forms.Application]::DoEvents()
    }
    SwLog "========================================"; SwLog "Uninstall complete: $success removed, $failed failed"; SwLog "========================================"
    $script:btnSwUninstall.Enabled = $true
    if ($success -gt 0) { SwLog "Re-scanning to refresh list..."; $script:btnSwScan.PerformClick() }
})
$btnSwExport.Add_Click({
    if ($script:SwAllResults.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "Software_$($script:SwCurrentHost)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq 'OK') { $script:SwAllResults | Select-Object Name, Version, Publisher, InstallDate, Type, Size | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8; SwLog "Exported $($script:SwAllResults.Count) entries to $(Split-Path $sfd.FileName -Leaf)" 'OK'; Write-AuditLog -Action "SoftwareExport" -Target $script:SwCurrentHost -Result "Success" -Detail $sfd.FileName }
})
$tabSoftware.Controls.AddRange(@($pnlSwBar, $pnlSwFilter, $script:dgvSw, $lblSwLogTitle, $script:rtbSwLog))
#endregion

## v6.0.0: TAB 3: PACKAGE DEPLOY removed. Deploy-Application.ps1 pushes
## are handled by J.A.N.E.T.'s standalone Remote Package Installer tool.
## Full region body preserved in Archive\WPT-superseded-2026-04-21\ for
## rollback reference.

###############################################################################
###                          TAB: REMOTE MESSAGE                            ###
###############################################################################
## Send popup messages to logged-in users on target workstations. Title
## + body + timeout. Single target (selected from ComputerList) or all.
## Delivery path: scheduled-task-as-logged-in-user -- the msg.exe *
## first-try branch was removed in v47 because hardened AFNET hosts
## (AllowRemoteRPC=0 + Session 0 isolation) silently drop msg.exe
## deliveries with exit 0.
#region === TAB: REMOTE MESSAGE ===
$tabRemMsg = New-Object System.Windows.Forms.TabPage; $tabRemMsg.BackColor = $c.BG
$grpMsg = New-Grp -Text "REMOTE MESSAGE" -X 6 -Y 6 -W 1100 -H 300 -Fg $c.Gold; $grpMsg.Anchor = 'Top,Left,Right'
$lblMsgDesc = New-Lbl -Text "Send a popup message to logged-in users on remote workstations." -X 10 -Y 22 -W 600 -Font $fn.Small -Fg $c.Dim
$lblMsgTarget = New-Lbl -Text "Send To:" -X 10 -Y 50 -W 60 -Font $fn.LabelB -Fg $c.TextSec
$script:ddlMsgTarget = New-Object System.Windows.Forms.ComboBox; $script:ddlMsgTarget.Location = New-Object System.Drawing.Point(75, 46); $script:ddlMsgTarget.Size = New-Object System.Drawing.Size(400, 24); $script:ddlMsgTarget.BackColor = $c.Input; $script:ddlMsgTarget.ForeColor = $c.Cyan; $script:ddlMsgTarget.DropDownStyle = 'DropDownList'
[void]$script:ddlMsgTarget.Items.Add("-- All Targets --"); $script:ddlMsgTarget.SelectedIndex = 0
$lblMsgTitle = New-Lbl -Text "Title:" -X 10 -Y 80 -W 60 -Font $fn.LabelB -Fg $c.TextSec
$script:txtMsgTitle = New-Tb -X 75 -Y 78 -W 500; $script:txtMsgTitle.Text = "Message from the 48 Communications Squadron."
$lblMsgBody = New-Lbl -Text "Message:" -X 10 -Y 110 -W 60 -Font $fn.LabelB -Fg $c.TextSec
$script:txtMsgBody = New-Tb -X 75 -Y 108 -W 700 -H 110 -Multi; $script:txtMsgBody.Font = $fn.Console
$lblMsgTimeout = New-Lbl -Text "Timeout:" -X 10 -Y 228 -W 60 -Font $fn.LabelB -Fg $c.TextSec
$script:nudMsgTimeout = New-Object System.Windows.Forms.NumericUpDown; $script:nudMsgTimeout.Location = New-Object System.Drawing.Point(75, 226); $script:nudMsgTimeout.Size = New-Object System.Drawing.Size(70, 24); $script:nudMsgTimeout.Minimum = 0; $script:nudMsgTimeout.Maximum = 3600; $script:nudMsgTimeout.Value = 0; $script:nudMsgTimeout.BackColor = $c.Input; $script:nudMsgTimeout.ForeColor = $c.White
$lblMsgTimeoutHint = New-Lbl -Text "seconds (0 = no timeout, user must click OK)" -X 150 -Y 230 -W 350 -Font $fn.Small -Fg $c.Dim
$btnMsgSend = New-Btn -Text "Send Message" -X 10 -Y 260 -W 150 -H 30 -Bg $c.Accent -Font $fn.BtnBig
$script:lblMsgStatus = New-Lbl -Text "" -X 170 -Y 266 -W 500 -Font $fn.Small -Fg $c.Dim
$grpMsg.Controls.AddRange(@($lblMsgDesc, $lblMsgTarget, $script:ddlMsgTarget, $lblMsgTitle, $script:txtMsgTitle, $lblMsgBody, $script:txtMsgBody, $lblMsgTimeout, $script:nudMsgTimeout, $lblMsgTimeoutHint, $btnMsgSend, $script:lblMsgStatus))
$lblMsgLogTitle = New-Lbl -Text "MESSAGE LOG" -X 10 -Y 312 -W 200 -Font $fn.LabelB -Fg $c.Gold
$script:rtbMsgLog = New-Object System.Windows.Forms.TextBox; $script:rtbMsgLog.Location = New-Object System.Drawing.Point(6, 332); $script:rtbMsgLog.Size = New-Object System.Drawing.Size(1100, 300)
$script:rtbMsgLog.Anchor = 'Top,Left,Right,Bottom'; $script:rtbMsgLog.BackColor = $c.OutputBg; $script:rtbMsgLog.ForeColor = $c.Console; $script:rtbMsgLog.Font = $fn.Console; $script:rtbMsgLog.ReadOnly = $true; $script:rtbMsgLog.Multiline = $true; $script:rtbMsgLog.ScrollBars = 'Vertical'; $script:rtbMsgLog.BorderStyle = 'None'; $script:rtbMsgLog.WordWrap = $false
function MsgLog($msg, $lvl = 'INFO') { $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"; if ($null -ne $script:rtbMsgLog) { try { if (-not $script:rtbMsgLog.IsHandleCreated) { $script:rtbMsgLog.CreateControl() }; $script:rtbMsgLog.Text += $line; $script:rtbMsgLog.SelectionStart = $script:rtbMsgLog.TextLength; $script:rtbMsgLog.ScrollToCaret() } catch {} }; Log "[RemMsg] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents() }
$tabRemMsg.Add_Enter({ $current = $script:ddlMsgTarget.SelectedItem; $script:ddlMsgTarget.Items.Clear(); [void]$script:ddlMsgTarget.Items.Add("-- All Targets --"); foreach ($comp in $global:ComputerList) { [void]$script:ddlMsgTarget.Items.Add($comp) }; if ($current -and $script:ddlMsgTarget.Items.Contains($current)) { $script:ddlMsgTarget.SelectedItem = $current } else { $script:ddlMsgTarget.SelectedIndex = 0 } })
$btnMsgSend.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    $body = $script:txtMsgBody.Text.Trim(); if ([string]::IsNullOrWhiteSpace($body)) { [System.Windows.Forms.MessageBox]::Show("Enter a message body.","No Message"); return }
    $title = $script:txtMsgTitle.Text.Trim(); if ([string]::IsNullOrWhiteSpace($title)) { $title = "Message from the 48 Communications Squadron." }
    $timeout = [int]$script:nudMsgTimeout.Value
    $targets = @(); $selected = $script:ddlMsgTarget.SelectedItem
    if ($selected -eq "-- All Targets --") { $targets = @($global:ComputerList) } else { $targets = @($selected) }
    if ($targets.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded. Add workstations on the Targets tab.","No Targets"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Send message to $($targets.Count) workstation(s)?`n`nTitle: $title`nTimeout: $(if ($timeout -eq 0) { 'None (user must click OK)' } else { "$timeout seconds" })","Confirm Send",4,48)
    if ($confirm -ne 'Yes') { return }
    $btnMsgSend.Enabled = $false; $script:lblMsgStatus.Text = "Sending to $($targets.Count) workstation(s)..."; $script:lblMsgStatus.ForeColor = $c.Warning
    MsgLog "========================================"; MsgLog "Sending message to $($targets.Count) workstation(s)"; MsgLog "Title: $title"; MsgLog "========================================"
    $success = 0; $failed = 0
    foreach ($target in $targets) {
        ## v43 FIX: Initialize $result to prevent stale value from previous iteration
        $result = $null
        MsgLog "Sending to $target..."
        try {
            $result = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ArgumentList $title, $body, $timeout -ScriptBlock {
                param($t, $b, $to)
                ## v47 AFNET: msg.exe path removed. On hardened AFNET workstations
                ## AllowRemoteRPC=0 and Session 0 isolation make msg.exe *
                ## return exit 0 while silently delivering nothing, or fail with
                ## "Error 5 getting session names". The scheduled-task path below
                ## runs as the logged-in user via Task Scheduler and is the only
                ## reliable delivery method. Skip straight to it.
                try {
                    $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName; if ([string]::IsNullOrWhiteSpace($loggedIn)) { return "FAIL: No user logged in" }
                    New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                    $vbsName = "WPT_Msg_$(Get-Random).vbs"; $vbsPath = "C:\Temp\$vbsName"; $timeoutVal = if ($to -gt 0) { $to } else { 0 }
                    $vbsContent = 'Set oShell = CreateObject("Wscript.Shell")' + "`r`n" + 'oShell.Popup "' + ($b -replace '"','""') + '", ' + $timeoutVal + ', "' + ($t -replace '"','""') + '", 64' + "`r`n"
                    [System.IO.File]::WriteAllText($vbsPath, $vbsContent)
                    $taskName = "WPT_Message_$(Get-Random)"; $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
                    $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited; $task = New-ScheduledTask -Action $action -Principal $principal
                    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -EA Stop | Out-Null; Start-ScheduledTask -TaskName $taskName -EA Stop; Start-Sleep -Seconds 3
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue
                    Start-Job -ScriptBlock { param($p); Start-Sleep -Seconds 120; Remove-Item $p -Force -EA SilentlyContinue } -ArgumentList $vbsPath | Out-Null
                    return "OK (scheduled task as $loggedIn)"
                } catch { return "FAIL: $($_.Exception.Message)" }
            }
            if ("$result" -like "OK*") { MsgLog "Message delivered to $target : $result" 'OK'; $success++ } else { MsgLog "FAILED on ${target}: $result" 'ERR'; $failed++ }
        } catch {
            MsgLog "FAILED on ${target}: $($_.Exception.Message)" 'ERR'; $failed++
            $result = "FAIL: $($_.Exception.Message)"
        }
        ## v43 FIX: $result is now always set before this audit log call
        Write-AuditLog -Action "RemoteMessage" -Target $target -Result $(if ($result -like "OK*") { "Sent" } else { "Failed" }) -Detail $title
        [System.Windows.Forms.Application]::DoEvents()
    }
    MsgLog "========================================"; MsgLog "Complete: $success delivered, $failed failed"; MsgLog "========================================"
    $script:lblMsgStatus.Text = "$success sent, $failed failed"; $script:lblMsgStatus.ForeColor = if ($failed -eq 0) { $c.Success } else { $c.Warning }; $btnMsgSend.Enabled = $true
})
$tabRemMsg.Controls.AddRange(@($grpMsg, $lblMsgLogTitle, $script:rtbMsgLog))
#endregion

###############################################################################
###                   TAB: REBOOT MESSAGE  (Experimental)                   ###
###############################################################################
## Countdown-based reboot with periodic warning popups to the end user.
## Configurable total time + warning interval. Two modes:
##   - Warnings only   - fires Send-RebootWarning popups at each interval,
##                       does NOT reboot.
##   - Auto-reboot     - final interval invokes Execute-Reboot (Restart-
##                       Computer -Force) after the countdown.
## Cancel Countdown stops the timer and pushes a cancellation notice to
## the end user. "Send Warning Now" fires an immediate out-of-cycle
## warning.
#region === TAB: REBOOT MESSAGE (Experimental) ===
$tabRebootMsg = New-Object System.Windows.Forms.TabPage; $tabRebootMsg.BackColor = $c.BG
$grpReboot = New-Grp -Text "SCHEDULED REBOOT WITH WARNINGS (Experimental)" -X 6 -Y 6 -W 1100 -H 320 -Fg $c.Danger; $grpReboot.Anchor = 'Top,Left,Right'
$lblRbDesc = New-Lbl -Text "Send countdown warnings to workstation users, then reboot automatically when the timer expires." -X 10 -Y 22 -W 700 -Font $fn.Small -Fg $c.Dim
$lblRbTarget = New-Lbl -Text "Send To:" -X 10 -Y 50 -W 60 -Font $fn.LabelB -Fg $c.TextSec
$script:ddlRbTarget = New-Object System.Windows.Forms.ComboBox; $script:ddlRbTarget.Location = New-Object System.Drawing.Point(75, 46); $script:ddlRbTarget.Size = New-Object System.Drawing.Size(400, 24); $script:ddlRbTarget.BackColor = $c.Input; $script:ddlRbTarget.ForeColor = $c.Cyan; $script:ddlRbTarget.DropDownStyle = 'DropDownList'
[void]$script:ddlRbTarget.Items.Add("-- All Targets --"); $script:ddlRbTarget.SelectedIndex = 0
$lblRbTotal = New-Lbl -Text "Total Time:" -X 10 -Y 82 -W 75 -Font $fn.LabelB -Fg $c.TextSec
$script:nudRbTotal = New-Object System.Windows.Forms.NumericUpDown; $script:nudRbTotal.Location = New-Object System.Drawing.Point(90, 80); $script:nudRbTotal.Size = New-Object System.Drawing.Size(60, 24); $script:nudRbTotal.Minimum = 5; $script:nudRbTotal.Maximum = 240; $script:nudRbTotal.Value = 60; $script:nudRbTotal.BackColor = $c.Input; $script:nudRbTotal.ForeColor = $c.White
$lblRbTotalHint = New-Lbl -Text "minutes until reboot" -X 155 -Y 84 -W 150 -Font $fn.Small -Fg $c.Dim
$lblRbInterval = New-Lbl -Text "Warn Every:" -X 310 -Y 82 -W 80 -Font $fn.LabelB -Fg $c.TextSec
$script:nudRbInterval = New-Object System.Windows.Forms.NumericUpDown; $script:nudRbInterval.Location = New-Object System.Drawing.Point(395, 80); $script:nudRbInterval.Size = New-Object System.Drawing.Size(60, 24); $script:nudRbInterval.Minimum = 1; $script:nudRbInterval.Maximum = 60; $script:nudRbInterval.Value = 15; $script:nudRbInterval.BackColor = $c.Input; $script:nudRbInterval.ForeColor = $c.White
$lblRbIntHint = New-Lbl -Text "minutes between warnings" -X 460 -Y 84 -W 180 -Font $fn.Small -Fg $c.Dim
$script:chkRbAutoReboot = New-Object System.Windows.Forms.CheckBox; $script:chkRbAutoReboot.Text = "Auto-reboot when timer expires"; $script:chkRbAutoReboot.Location = New-Object System.Drawing.Point(10, 112); $script:chkRbAutoReboot.Size = New-Object System.Drawing.Size(250, 22); $script:chkRbAutoReboot.ForeColor = $c.Warning; $script:chkRbAutoReboot.FlatStyle = 'Flat'; $script:chkRbAutoReboot.Checked = $true
$script:lblRbCountdown = New-Object System.Windows.Forms.Label; $script:lblRbCountdown.Text = "00:00:00"; $script:lblRbCountdown.ForeColor = $c.Dim
$script:lblRbCountdown.Font = New-Object System.Drawing.Font("Segoe UI", 28, [System.Drawing.FontStyle]::Bold); $script:lblRbCountdown.AutoSize = $true; $script:lblRbCountdown.Location = New-Object System.Drawing.Point(650, 40)
$script:lblRbState = New-Lbl -Text "Idle -- configure and click Start Countdown" -X 650 -Y 102 -W 400 -H 20 -Font $fn.Label -Fg $c.Dim
$script:lblRbNextWarn = New-Lbl -Text "" -X 650 -Y 122 -W 400 -H 20 -Font $fn.Small -Fg $c.Dim
$script:btnRbStart = New-Btn -Text "Start Countdown" -X 10 -Y 142 -W 150 -H 32 -Bg $c.Success -Font $fn.BtnBig
$script:btnRbCancel = New-Btn -Text "Cancel Countdown" -X 168 -Y 142 -W 150 -H 32 -Bg $c.Danger -Font $fn.BtnBig; $script:btnRbCancel.Enabled = $false
$script:btnRbSendNow = New-Btn -Text "Send Warning Now" -X 326 -Y 142 -W 150 -H 32 -Bg $c.Warning; $script:btnRbSendNow.Enabled = $false
$lblRbSchedule = New-Lbl -Text "Warning Schedule Preview:" -X 10 -Y 182 -W 200 -Font $fn.LabelB -Fg $c.Gold
$script:rtbRbSchedule = New-Object System.Windows.Forms.TextBox; $script:rtbRbSchedule.Location = New-Object System.Drawing.Point(10, 200); $script:rtbRbSchedule.Size = New-Object System.Drawing.Size(1070, 110)
$script:rtbRbSchedule.BackColor = $c.OutputBg; $script:rtbRbSchedule.ForeColor = $c.Console; $script:rtbRbSchedule.Font = $fn.Console; $script:rtbRbSchedule.ReadOnly = $true; $script:rtbRbSchedule.Multiline = $true; $script:rtbRbSchedule.ScrollBars = 'Vertical'; $script:rtbRbSchedule.BorderStyle = 'None'; $script:rtbRbSchedule.WordWrap = $false
$UpdateRbPreview = { $total = [int]$script:nudRbTotal.Value; $interval = [int]$script:nudRbInterval.Value; $lines = @(); $t = 0; while ($t -lt $total) { $remaining = $total - $t; $lines += "  T+$($t.ToString('D3')) min  |  Warning: 'Your workstation will reboot in $remaining minute(s). Please save all work.'"; $t += $interval }; $lines += "  T+$($total.ToString('D3')) min  |  ** REBOOT EXECUTED **"; $script:rtbRbSchedule.Text = $lines -join "`r`n" }
$script:nudRbTotal.Add_ValueChanged($UpdateRbPreview); $script:nudRbInterval.Add_ValueChanged($UpdateRbPreview); & $UpdateRbPreview
$grpReboot.Controls.AddRange(@($lblRbDesc, $lblRbTarget, $script:ddlRbTarget, $lblRbTotal, $script:nudRbTotal, $lblRbTotalHint, $lblRbInterval, $script:nudRbInterval, $lblRbIntHint, $script:chkRbAutoReboot, $script:lblRbCountdown, $script:lblRbState, $script:lblRbNextWarn, $script:btnRbStart, $script:btnRbCancel, $script:btnRbSendNow, $lblRbSchedule, $script:rtbRbSchedule))
$lblRbLogTitle = New-Lbl -Text "REBOOT COUNTDOWN LOG" -X 10 -Y 332 -W 250 -Font $fn.LabelB -Fg $c.Gold
$script:rtbRbLog = New-Object System.Windows.Forms.TextBox; $script:rtbRbLog.Location = New-Object System.Drawing.Point(6, 352); $script:rtbRbLog.Size = New-Object System.Drawing.Size(1100, 280)
$script:rtbRbLog.Anchor = 'Top,Left,Right,Bottom'; $script:rtbRbLog.BackColor = $c.OutputBg; $script:rtbRbLog.ForeColor = $c.Console; $script:rtbRbLog.Font = $fn.Console; $script:rtbRbLog.ReadOnly = $true; $script:rtbRbLog.Multiline = $true; $script:rtbRbLog.ScrollBars = 'Vertical'; $script:rtbRbLog.BorderStyle = 'None'; $script:rtbRbLog.WordWrap = $false
function RbLog($msg, $lvl = 'INFO') { $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"; if ($null -ne $script:rtbRbLog) { try { if (-not $script:rtbRbLog.IsHandleCreated) { $script:rtbRbLog.CreateControl() }; $script:rtbRbLog.Text += $line; $script:rtbRbLog.SelectionStart = $script:rtbRbLog.TextLength; $script:rtbRbLog.ScrollToCaret() } catch {} }; Log "[RebootMsg] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents() }
$script:RbTimer = $null; $script:RbEndTime = $null; $script:RbNextWarnTime = $null; $script:RbInterval = 15; $script:RbTargets = @(); $script:RbWarnsSent = 0; $script:RbSending = $false
function Send-RebootWarning { param([string[]]$Targets, [int]$MinutesLeft)
    $msgText = "Your workstation will reboot in $MinutesLeft minute(s).`n`nPlease save all open work immediately.`n`nThis is an automated message from the 48 Communications Squadron."
    $msgTitle = "REBOOT WARNING - $MinutesLeft Minute(s) Remaining"; $timeout = 45
    ## v6.2.3: rewritten to mirror the proven Remote Message scriptblock --
    ## inner try/catch returns "OK ..." or "FAIL: ..." strings so the caller
    ## actually knows whether the popup deployed; 2-step New-ScheduledTask
    ## + Register-ScheduledTask -InputObject pattern (the 1-step
    ## Register-ScheduledTask -Action -Principal path is flakier across
    ## Windows builds and was silently failing on some endpoints); icon
    ## type 48 (warning/exclamation) preserved.
    $warnSB = {
        param($t, $b, $to)
        try {
            $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
            if ([string]::IsNullOrWhiteSpace($loggedIn)) { return "FAIL: No user logged in" }
            New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
            $vbsName = "WPT_RbWarn_$(Get-Random).vbs"; $vbsPath = "C:\Temp\$vbsName"
            $timeoutVal = if ($to -gt 0) { $to } else { 0 }
            $vbsContent = 'Set oShell = CreateObject("Wscript.Shell")' + "`r`n" + 'oShell.Popup "' + ($b -replace '"','""') + '", ' + $timeoutVal + ', "' + ($t -replace '"','""') + '", 48' + "`r`n"
            [System.IO.File]::WriteAllText($vbsPath, $vbsContent)
            $taskName = "WPT_RbWarn_$(Get-Random)"
            $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
            $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
            $task = New-ScheduledTask -Action $action -Principal $principal
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -EA Stop | Out-Null
            Start-ScheduledTask -TaskName $taskName -EA Stop
            Start-Sleep -Seconds 3
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue
            Start-Job -ScriptBlock { param($p); Start-Sleep -Seconds 120; Remove-Item $p -Force -EA SilentlyContinue } -ArgumentList $vbsPath | Out-Null
            return "OK (scheduled task as $loggedIn)"
        } catch { return "FAIL: $($_.Exception.Message)" }
    }
    foreach ($target in $Targets) {
        RbLog "Sending $MinutesLeft-min warning to $target..."
        $result = $null
        try {
            $result = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ArgumentList $msgTitle, $msgText, $timeout -ScriptBlock $warnSB
            if ("$result" -like "OK*") { RbLog "Warning delivered to $target - $MinutesLeft min remaining : $result" 'OK' }
            else                       { RbLog "Warning FAILED on ${target}: $result" 'ERR' }
        } catch {
            RbLog "Warning FAILED on ${target}: $($_.Exception.Message)" 'ERR'
        }
    }
    $script:RbWarnsSent++
}
function Execute-Reboot { param([string[]]$Targets)
    RbLog "========================================"; RbLog "TIMER EXPIRED -- EXECUTING REBOOT"; RbLog "========================================"
    foreach ($target in $Targets) { RbLog "Rebooting $target..."
        try { Restart-Computer -ComputerName $target -Credential $global:Credentials -Force -EA Stop; RbLog "Reboot command sent to $target" 'OK'; Track-Action -Action 'Reboot' -Target $target -Result 'Sent' -Detail 'Scheduled reboot countdown'; Write-AuditLog -Action "ScheduledReboot" -Target $target -Result "Sent" } catch { RbLog "Reboot FAILED on ${target}: $($_.Exception.Message)" 'ERR' }
    }; RbLog "Reboot commands sent to $($Targets.Count) workstation(s)."
}
$tabRebootMsg.Add_Enter({ $current = $script:ddlRbTarget.SelectedItem; $script:ddlRbTarget.Items.Clear(); [void]$script:ddlRbTarget.Items.Add("-- All Targets --"); foreach ($comp in $global:ComputerList) { [void]$script:ddlRbTarget.Items.Add($comp) }; if ($current -and $script:ddlRbTarget.Items.Contains($current)) { $script:ddlRbTarget.SelectedItem = $current } else { $script:ddlRbTarget.SelectedIndex = 0 } })
$script:btnRbStart.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    $selected = $script:ddlRbTarget.SelectedItem; if ($selected -eq "-- All Targets --") { $script:RbTargets = @($global:ComputerList) } else { $script:RbTargets = @($selected) }
    if ($script:RbTargets.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $totalMin = [int]$script:nudRbTotal.Value; $script:RbInterval = [int]$script:nudRbInterval.Value; $autoReboot = $script:chkRbAutoReboot.Checked
    $targetList = ($script:RbTargets | Select-Object -First 5) -join ", "; if ($script:RbTargets.Count -gt 5) { $targetList += " +$($script:RbTargets.Count - 5) more" }
    $confirmMsg = "Start $totalMin-minute reboot countdown on $($script:RbTargets.Count) workstation(s)?`n`n$targetList`n`nWarnings every $($script:RbInterval) min."
    if ($autoReboot) { $confirmMsg += "`nAuto-reboot ENABLED at expiration." } else { $confirmMsg += "`nAuto-reboot DISABLED (warnings only)." }
    $confirm = [System.Windows.Forms.MessageBox]::Show($confirmMsg,"Confirm Countdown",4,48); if ($confirm -ne 'Yes') { return }
    $script:btnRbStart.Enabled = $false; $script:btnRbCancel.Enabled = $true; $script:btnRbSendNow.Enabled = $true
    $script:nudRbTotal.Enabled = $false; $script:nudRbInterval.Enabled = $false; $script:ddlRbTarget.Enabled = $false; $script:chkRbAutoReboot.Enabled = $false
    $script:RbEndTime = (Get-Date).AddMinutes($totalMin); $script:RbNextWarnTime = Get-Date; $script:RbWarnsSent = 0
    RbLog "========================================"; RbLog "COUNTDOWN STARTED: $totalMin minutes on $($script:RbTargets.Count) workstation(s)"; RbLog "Warns every $($script:RbInterval) min | Auto-reboot: $autoReboot"; RbLog "Expires at: $($script:RbEndTime.ToString('HH:mm:ss'))"; RbLog "========================================"
    $minutesLeft = [Math]::Ceiling(($script:RbEndTime - (Get-Date)).TotalMinutes); Send-RebootWarning -Targets $script:RbTargets -MinutesLeft $minutesLeft; $script:RbNextWarnTime = (Get-Date).AddMinutes($script:RbInterval)
    $script:RbTimer = New-Object System.Windows.Forms.Timer; $script:RbTimer.Interval = 1000
    $script:RbTimer.Add_Tick({
        if ($script:RbSending) { return }; $now = Get-Date; $remaining = $script:RbEndTime - $now
        if ($remaining.TotalSeconds -le 0) {
            $script:RbTimer.Stop(); $script:RbTimer.Dispose(); $script:RbTimer = $null; $script:lblRbCountdown.Text = "00:00:00"; $script:lblRbCountdown.ForeColor = $c.Danger
            $script:lblRbState.Text = "COUNTDOWN EXPIRED"; $script:lblRbState.ForeColor = $c.Danger; $script:lblRbNextWarn.Text = ""
            if ($script:chkRbAutoReboot.Checked) { Execute-Reboot -Targets $script:RbTargets } else { RbLog "Timer expired. Auto-reboot is OFF -- no reboot sent." 'WARN' }
            $script:btnRbStart.Enabled = $true; $script:btnRbCancel.Enabled = $false; $script:btnRbSendNow.Enabled = $false
            $script:nudRbTotal.Enabled = $true; $script:nudRbInterval.Enabled = $true; $script:ddlRbTarget.Enabled = $true; $script:chkRbAutoReboot.Enabled = $true; return
        }
        ## v6.2.4: cast [Math]::Floor (returns [double]) to [int]; the
        ## {0:D2} formatter requires an integer type. Without the cast,
        ## every timer tick threw "Error formatting a string: Format
        ## specifier was invalid." once per second -- cosmetic spam that
        ## flooded the host's output stream during long countdowns but
        ## didn't affect the countdown / warning / reboot logic.
        $script:lblRbCountdown.Text = "{0:D2}:{1:D2}:{2:D2}" -f [int][Math]::Floor($remaining.TotalHours), [int]$remaining.Minutes, [int]$remaining.Seconds
        $minutesLeft = [Math]::Ceiling($remaining.TotalMinutes)
        $script:lblRbCountdown.ForeColor = if ($minutesLeft -le 5) { $c.Danger } elseif ($minutesLeft -le 15) { $c.Warning } else { $c.Success }
        $script:lblRbState.Text = "RUNNING -- $($script:RbWarnsSent) warning(s) sent"; $script:lblRbState.ForeColor = $c.Success
        if ($now -ge $script:RbNextWarnTime -and $remaining.TotalSeconds -gt 30) { $script:RbSending = $true; Send-RebootWarning -Targets $script:RbTargets -MinutesLeft $minutesLeft; $script:RbNextWarnTime = (Get-Date).AddMinutes($script:RbInterval); $script:RbSending = $false }
        $nextIn = $script:RbNextWarnTime - $now
        if ($nextIn.TotalSeconds -gt 0 -and $remaining.TotalSeconds -gt 30) { $script:lblRbNextWarn.Text = "Next warning in $([Math]::Floor($nextIn.TotalMinutes)):$($nextIn.Seconds.ToString('00'))"; $script:lblRbNextWarn.ForeColor = $c.Cyan } else { $script:lblRbNextWarn.Text = "Final warning sent"; $script:lblRbNextWarn.ForeColor = $c.Warning }
    }); $script:RbTimer.Start()
})
$script:btnRbCancel.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Cancel the reboot countdown?`n`nNo reboot will occur.","Confirm Cancel",4,48); if ($confirm -ne 'Yes') { return }
    if ($null -ne $script:RbTimer) { $script:RbTimer.Stop(); $script:RbTimer.Dispose(); $script:RbTimer = $null }
    $script:lblRbCountdown.Text = "CANCELLED"; $script:lblRbCountdown.ForeColor = $c.Warning; $script:lblRbState.Text = "Countdown cancelled by operator"; $script:lblRbState.ForeColor = $c.Warning; $script:lblRbNextWarn.Text = ""
    RbLog "========================================"; RbLog "COUNTDOWN CANCELLED by operator after $($script:RbWarnsSent) warning(s)" 'WARN'; RbLog "========================================"
    ## v6.2.3: cancellation scriptblock rewritten to mirror Remote Message
    ## (try/catch inside, 2-step Register-ScheduledTask, OK/FAIL contract).
    $cancelSB = {
        try {
            $cm = "The scheduled reboot has been CANCELLED.`n`nNo restart is required at this time."
            $ct = "Reboot Cancelled"
            $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
            if ([string]::IsNullOrWhiteSpace($loggedIn)) { return "FAIL: No user logged in" }
            New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
            $vbsName = "WPT_Cancel_$(Get-Random).vbs"; $vbsPath = "C:\Temp\$vbsName"
            $vbsContent = 'Set oShell = CreateObject("Wscript.Shell")' + "`r`n" + 'oShell.Popup "' + ($cm -replace '"','""') + '", 30, "' + ($ct -replace '"','""') + '", 64' + "`r`n"
            [System.IO.File]::WriteAllText($vbsPath, $vbsContent)
            $taskName = "WPT_Cancel_$(Get-Random)"
            $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
            $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
            $task = New-ScheduledTask -Action $action -Principal $principal
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -EA Stop | Out-Null
            Start-ScheduledTask -TaskName $taskName -EA Stop
            Start-Sleep -Seconds 3
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue
            Start-Job -ScriptBlock { param($p); Start-Sleep -Seconds 60; Remove-Item $p -Force -EA SilentlyContinue } -ArgumentList $vbsPath | Out-Null
            return "OK (scheduled task as $loggedIn)"
        } catch { return "FAIL: $($_.Exception.Message)" }
    }
    foreach ($target in $script:RbTargets) {
        $result = $null
        try {
            $result = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ScriptBlock $cancelSB
            if ("$result" -like "OK*") { RbLog "Cancellation notice sent to $target : $result" 'OK' }
            else                       { RbLog "Cancellation FAILED on ${target}: $result" 'ERR' }
        } catch {
            RbLog "Could not notify ${target}: $($_.Exception.Message)" 'ERR'
        }
    }
    $script:btnRbStart.Enabled = $true; $script:btnRbCancel.Enabled = $false; $script:btnRbSendNow.Enabled = $false
    $script:nudRbTotal.Enabled = $true; $script:nudRbInterval.Enabled = $true; $script:ddlRbTarget.Enabled = $true; $script:chkRbAutoReboot.Enabled = $true
})
$script:btnRbSendNow.Add_Click({ if ($null -eq $script:RbEndTime) { return }; $remaining = $script:RbEndTime - (Get-Date); if ($remaining.TotalSeconds -le 0) { return }; $minutesLeft = [Math]::Ceiling($remaining.TotalMinutes); RbLog "Manual warning triggered by operator"; Send-RebootWarning -Targets $script:RbTargets -MinutesLeft $minutesLeft })
$tabRebootMsg.Controls.AddRange(@($grpReboot, $lblRbLogTitle, $script:rtbRbLog))
#endregion

###############################################################################
###                             TAB: KB SCANNER                             ###
###############################################################################
## Two sections stacked vertically:
##   SCAN - parallel Get-HotFix across $global:ComputerList. Grid has
##          Host / HotfixID / Description / InstalledOn / InstalledBy.
##          Filter bar on top (by KB ID, by host, by description).
##   INSTALL - enter a KB number (or list), optionally provide an MSU
##             file path. Per-host flow: (1) MECM first -- trigger
##             MachinePolicy + SWUpdatesScan cycles, look for pending
##             CCM_SoftwareUpdate matching the KB, install via
##             CCM_SoftwareUpdatesManager.InstallUpdates; (2) MSU
##             fallback -- copy MSU over the PSSession to C:\Temp,
##             wusa.exe install /quiet /norestart.
##   Also: Trigger MECM Cycles (no install), Push & Download (forces
##   the WU agent to download pending updates without installing).
#region === TAB: KB SCANNER ===
$tabKB = New-Object System.Windows.Forms.TabPage; $tabKB.BackColor = $c.BG
$pnlKBBar = New-Object System.Windows.Forms.Panel; $pnlKBBar.Location = New-Object System.Drawing.Point(6, 6); $pnlKBBar.Size = New-Object System.Drawing.Size(1100, 42); $pnlKBBar.BackColor = $c.Panel; $pnlKBBar.Anchor = 'Top,Left,Right'
$script:btnKBScan = New-Btn -Text "Scan Installed KBs" -X 6 -Y 6 -W 150 -H 30 -Bg $c.Accent -Font $fn.BtnBig
$btnKBExport = New-Btn -Text "Export CSV" -X 164 -Y 6 -W 100 -H 30 -Bg $c.Success; $btnKBExport.Enabled = $false
$script:btnKBTrigger = New-Btn -Text "Trigger MECM Cycles" -X 272 -Y 6 -W 155 -H 30 -Bg $c.Cyan; $script:btnKBTrigger.ForeColor = [System.Drawing.Color]::Black
$script:btnKBPushDownload = New-Btn -Text "Push & Download" -X 435 -Y 6 -W 135 -H 30 -Bg $c.Warning; $script:btnKBPushDownload.ForeColor = [System.Drawing.Color]::Black
$script:lblKBTargetCount = New-Lbl -Text "Targets: 0" -X 585 -Y 12 -W 100 -Font $fn.SmallB -Fg $c.Dim
$script:lblKBProg = New-Lbl -Text "Load targets on Targets tab, then Scan." -X 690 -Y 12 -W 400 -Font $fn.Small -Fg $c.Dim
$pnlKBBar.Controls.AddRange(@($script:btnKBScan, $btnKBExport, $script:btnKBTrigger, $script:btnKBPushDownload, $script:lblKBTargetCount, $script:lblKBProg))
$script:btnKBTrigger.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Trigger MECM Software Update cycles on $($global:ComputerList.Count) workstation(s)?","Confirm MECM Cycles",4,48); if ($confirm -ne 'Yes') { return }
    $script:btnKBTrigger.Enabled = $false; KBLog "========================================"; KBLog "Triggering MECM cycles on $($global:ComputerList.Count) target(s)..."; KBLog "========================================"
    $success = 0; $failed = 0
    foreach ($target in $global:ComputerList) { KBLog "Triggering cycles on $target..."
        try { Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ScriptBlock {
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000113}" -EA SilentlyContinue | Out-Null
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000114}" -EA SilentlyContinue | Out-Null
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000021}" -EA SilentlyContinue | Out-Null
        }; KBLog "$target : MECM cycles triggered" 'OK'; $success++ } catch { KBLog "$target : FAILED - $($_.Exception.Message)" 'ERR'; $failed++ }
        [System.Windows.Forms.Application]::DoEvents()
    }
    KBLog "========================================"; KBLog "MECM Cycles: $success triggered, $failed failed"; KBLog "========================================"
    $script:btnKBTrigger.Enabled = $true; Write-AuditLog -Action "MECMCycles" -Result "Complete" -Detail "$success/$($global:ComputerList.Count) triggered"
})
$script:btnKBPushDownload.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Push all pending MECM updates to DOWNLOAD on $($global:ComputerList.Count) workstation(s)?","Confirm Download Push",4,48); if ($confirm -ne 'Yes') { return }
    $script:btnKBPushDownload.Enabled = $false; KBLog "========================================"; KBLog "Pushing update downloads on $($global:ComputerList.Count) target(s)..."; KBLog "========================================"
    $success = 0; $failed = 0; $totalPending = 0
    foreach ($target in $global:ComputerList) { KBLog "Querying pending updates on $target..."
        try { $result = Invoke-Command -ComputerName $target -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -EA Stop -ScriptBlock {
            $pending = @(Get-WmiObject -Namespace "ROOT\ccm\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop)
            if ($pending.Count -eq 0) { return @{ Count=0; Error="" } }
            try { Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000108}" -EA SilentlyContinue | Out-Null; Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000114}" -EA SilentlyContinue | Out-Null; return @{ Count=$pending.Count; Error="" } } catch { return @{ Count=$pending.Count; Error=$_.Exception.Message } }
        }
            $cnt = if ($result -is [hashtable]) { $result['Count'] } else { $result.Count }; $err = if ($result -is [hashtable]) { $result['Error'] } else { $result.Error }
            if ($cnt -eq 0) { KBLog "$target : No pending updates (fully current)" 'OK' } elseif ([string]::IsNullOrWhiteSpace($err)) { KBLog "$target : $cnt pending update(s) -- download triggered" 'OK'; $totalPending += $cnt } else { KBLog "$target : $cnt pending but trigger failed: $err" 'ERR'; $failed++; continue }
            $success++
        } catch { KBLog "$target : FAILED - $($_.Exception.Message)" 'ERR'; $failed++ }
        [System.Windows.Forms.Application]::DoEvents()
    }
    KBLog "========================================"; KBLog "Download push: $success hosts, $totalPending total pending updates, $failed failed"; KBLog "========================================"
    $script:btnKBPushDownload.Enabled = $true; Write-AuditLog -Action "KBDownloadPush" -Result "Complete" -Detail "$success hosts, $totalPending pending, $failed failed"
})
$pnlKBFilter = New-Object System.Windows.Forms.Panel; $pnlKBFilter.Location = New-Object System.Drawing.Point(6, 52); $pnlKBFilter.Size = New-Object System.Drawing.Size(1100, 32); $pnlKBFilter.BackColor = [System.Drawing.Color]::FromArgb(16,16,30); $pnlKBFilter.Anchor = 'Top,Left,Right'
$lblKBFilter = New-Lbl -Text "Filter:" -X 6 -Y 7 -W 45 -Font $fn.LabelB -Fg $c.TextSec
$script:txtKBFilter = New-Tb -X 52 -Y 4 -W 200 -H 24; $script:txtKBFilter.Font = $fn.Console
$lblKBFilterHint = New-Lbl -Text "Type to filter by KB, host, or description" -X 260 -Y 7 -W 300 -Font $fn.Small -Fg $c.Dim
$lblKBHostFilter = New-Lbl -Text "Host:" -X 560 -Y 7 -W 40 -Font $fn.LabelB -Fg $c.TextSec
$script:ddlKBHost = New-Object System.Windows.Forms.ComboBox; $script:ddlKBHost.Location = New-Object System.Drawing.Point(600, 4); $script:ddlKBHost.Size = New-Object System.Drawing.Size(200, 24); $script:ddlKBHost.BackColor = $c.Input; $script:ddlKBHost.ForeColor = $c.Cyan; $script:ddlKBHost.DropDownStyle = 'DropDownList'; $script:ddlKBHost.Font = $fn.Label
[void]$script:ddlKBHost.Items.Add("-- All Hosts --"); $script:ddlKBHost.SelectedIndex = 0
$script:lblKBCount = New-Lbl -Text "" -X 820 -Y 7 -W 260 -Font $fn.SmallB -Fg $c.Dim
$pnlKBFilter.Controls.AddRange(@($lblKBFilter, $script:txtKBFilter, $lblKBFilterHint, $lblKBHostFilter, $script:ddlKBHost, $script:lblKBCount))
$script:dgvKB = New-Object System.Windows.Forms.DataGridView; $script:dgvKB.Location = New-Object System.Drawing.Point(6, 88); $script:dgvKB.Size = New-Object System.Drawing.Size(1100, 280)
$script:dgvKB.Anchor = 'Top,Left,Right'; $script:dgvKB.ReadOnly = $true; Style-Grid $script:dgvKB; $script:dgvKB.AutoSizeColumnsMode = 'None'; $script:dgvKB.ScrollBars = 'Both'
foreach ($col in @(@{N='Host';H='Host';W=160},@{N='HotFixID';H='KB ID';W=100},@{N='Description';H='Description';W=160},@{N='InstalledOn';H='Installed On';W=110},@{N='InstalledBy';H='Installed By';W=200},@{N='Source';H='Source';W=140})) { $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvKB.Columns.Add($cc) }
$grpKBInstall = New-Grp -Text "KB INSTALL (MECM first, MSU fallback)" -X 6 -Y 372 -W 1100 -H 148 -Fg $c.Warning; $grpKBInstall.Anchor = 'Left,Right,Bottom'
$lblKBTargetKBs = New-Lbl -Text "Target KBs:" -X 10 -Y 24 -W 80 -Font $fn.LabelB -Fg $c.TextSec
$script:txtKBTargetKBs = New-Tb -X 95 -Y 22 -W 400 -H 24; $script:txtKBTargetKBs.Font = $fn.Console; $script:txtKBTargetKBs.ForeColor = $c.Cyan
$lblKBTargetHint = New-Lbl -Text "Comma or space separated (e.g. KB5060999, KB5062552)" -X 502 -Y 26 -W 400 -Font $fn.Small -Fg $c.Dim
$lblKBMsuPath = New-Lbl -Text "MSU Path:" -X 10 -Y 54 -W 80 -Font $fn.LabelB -Fg $c.TextSec
$script:txtKBMsuPath = New-Tb -X 95 -Y 52 -W 400 -H 24; $script:txtKBMsuPath.Font = $fn.Console; $script:txtKBMsuPath.ForeColor = $c.Cyan
$btnKBBrowseMsu = New-Btn -Text "Browse" -X 500 -Y 52 -W 70 -H 24 -Bg $c.PanelLight; $btnKBBrowseMsu.Font = $fn.Small
$lblKBMsuHint = New-Lbl -Text "Optional: UNC or local path to .msu file for fallback install" -X 576 -Y 56 -W 400 -Font $fn.Small -Fg $c.Dim
$btnKBBrowseMsu.Add_Click({ $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "Windows Update|*.msu|All|*.*"; $ofd.Title = "Select MSU Update File"; if ($ofd.ShowDialog() -eq 'OK') { $script:txtKBMsuPath.Text = $ofd.FileName } })
$script:chkKBSuppressReboot = New-Object System.Windows.Forms.CheckBox; $script:chkKBSuppressReboot.Text = "Suppress auto-reboot after install"; $script:chkKBSuppressReboot.Location = New-Object System.Drawing.Point(10, 84); $script:chkKBSuppressReboot.Size = New-Object System.Drawing.Size(260, 22); $script:chkKBSuppressReboot.ForeColor = $c.Warning; $script:chkKBSuppressReboot.FlatStyle = 'Flat'; $script:chkKBSuppressReboot.Checked = $true
$lblKBMethod = New-Lbl -Text "Method: Try MECM CCM_SoftwareUpdate first. If KB not in MECM and MSU path provided, copy + wusa.exe fallback." -X 280 -Y 86 -W 700 -Font $fn.Small -Fg $c.Dim
$script:btnKBInstall = New-Btn -Text "Install KBs" -X 10 -Y 112 -W 140 -H 30 -Bg $c.Warning; $script:btnKBInstall.Font = $fn.BtnBig
$script:lblKBInstallStatus = New-Lbl -Text "" -X 160 -Y 118 -W 800 -Font $fn.Small -Fg $c.Dim
$grpKBInstall.Controls.AddRange(@($lblKBTargetKBs, $script:txtKBTargetKBs, $lblKBTargetHint, $lblKBMsuPath, $script:txtKBMsuPath, $btnKBBrowseMsu, $lblKBMsuHint, $script:chkKBSuppressReboot, $lblKBMethod, $script:btnKBInstall, $script:lblKBInstallStatus))
$script:btnKBInstall.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $kbInput = $script:txtKBTargetKBs.Text.Trim(); if ([string]::IsNullOrWhiteSpace($kbInput)) { [System.Windows.Forms.MessageBox]::Show("Enter one or more KB numbers to install.","No KBs"); return }
    $kbList = @($kbInput -split '[,\s;]+' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ -ne '' })
    $kbList = @($kbList | ForEach-Object { if ($_ -notmatch '^KB') { "KB$_" } else { $_ } }); if ($kbList.Count -eq 0) { return }
    $msuPath = $script:txtKBMsuPath.Text.Trim(); $suppressReboot = $script:chkKBSuppressReboot.Checked
    $confirm = [System.Windows.Forms.MessageBox]::Show("Install $($kbList.Count) KB(s) on $($global:ComputerList.Count) workstation(s)?","Confirm KB Install",4,48); if ($confirm -ne 'Yes') { return }
    $confirm2 = [System.Windows.Forms.MessageBox]::Show("Are you sure? This will push updates to $($global:ComputerList.Count) workstation(s).","Final Confirmation",4,48); if ($confirm2 -ne 'Yes') { return }
    $script:btnKBInstall.Enabled = $false; $script:lblKBInstallStatus.Text = "Installing..."; $script:lblKBInstallStatus.ForeColor = $c.Warning
    KBLog "========================================"; KBLog "KB INSTALL: $($kbList -join ', ') on $($global:ComputerList.Count) target(s)"; KBLog "========================================"
    Initialize-RunspacePool; $script:installJobs = @{}
    $script:installBlock = {
        param([string]$Computer, [pscredential]$Cred, [string]$Auth, [string[]]$KBs, [string]$MsuPath, [bool]$NoReboot)
        $r = @{ Host=$Computer; MECMFound=0; MECMInstalled=0; MSUInstalled=0; Skipped=0; Errors=@(); Details=@() }
        ## v47 AFNET: TCP reachability instead of ICMP.
        $reachable = $false
        foreach ($port in 5985,445) {
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }
            if ($reachable) { break }
        }
        if (-not $reachable) { $r.Errors += "Offline"; return $r }
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $sess = $null; try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop } catch { $r.Errors += "Session failed: $($_.Exception.Message)"; return $r }
        try {
            $mecmResult = Invoke-Command -Session $sess -ArgumentList (,$KBs) -EA Stop -ScriptBlock { param([string[]]$targetKBs); $found = @(); $allUpdates = @()
                try { $allUpdates = @(Get-WmiObject -Namespace "ROOT\ccm\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop) } catch { return @{ Found=@(); Error="MECM query failed: $($_.Exception.Message)" } }
                foreach ($kb in $targetKBs) { $match = @($allUpdates | Where-Object { $_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','') }); if ($match.Count -gt 0) { $found += $kb } }
                if ($found.Count -gt 0) { $toInstall = @($allUpdates | Where-Object { $dominated = $false; foreach ($kb in $found) { if ($_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','')) { $dominated = $true; break } }; $dominated })
                    if ($toInstall.Count -gt 0) { try { Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$toInstall) -Namespace ROOT\ccm\ClientSDK -EA Stop | Out-Null; return @{ Found=$found; Triggered=$toInstall.Count; Error="" } } catch { return @{ Found=$found; Triggered=0; Error="Install trigger failed: $($_.Exception.Message)" } } } }
                return @{ Found=$found; Triggered=0; Error="" }
            }
            if ($mecmResult.Found.Count -gt 0) { $r.MECMFound = $mecmResult.Found.Count; if ($mecmResult.Triggered -gt 0) { $r.MECMInstalled = $mecmResult.Triggered; $r.Details += "MECM: Triggered $($mecmResult.Triggered) update(s)" }; if ($mecmResult.Error) { $r.Errors += $mecmResult.Error } }
            $handledByMECM = @(); if ($mecmResult.Found) { $handledByMECM = @($mecmResult.Found) }; $remaining = @($KBs | Where-Object { $handledByMECM -notcontains $_ })
            if ($remaining.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($MsuPath)) {
                foreach ($kb in $remaining) { $r.Details += "MSU fallback for $kb..."
                    try { if (-not (Test-Path $MsuPath -EA Stop)) { $r.Errors += "MSU file not found: $MsuPath"; continue }
                        ## v47 AFNET: Copy over PSSession instead of SMB admin share.
                        Invoke-Command -Session $sess -EA Stop -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -Force -EA Stop | Out-Null } }
                        $msuName = Split-Path $MsuPath -Leaf
                        Copy-Item -LiteralPath $MsuPath -Destination "C:\Temp\$msuName" -ToSession $sess -Force -EA Stop
                        $wusaArgs = "C:\Temp\$msuName /quiet"; if ($NoReboot) { $wusaArgs += " /norestart" }
                        $exitCode = Invoke-Command -Session $sess -ArgumentList $wusaArgs -EA Stop -ScriptBlock { param($args2); $proc = Start-Process -FilePath "wusa.exe" -ArgumentList $args2 -Wait -PassThru -NoNewWindow -EA Stop; return $proc.ExitCode }
                        if ($exitCode -eq 0 -or $exitCode -eq 3010) { $r.MSUInstalled++; $r.Details += "MSU $kb : Installed" } elseif ($exitCode -eq 2359302) { $r.Skipped++; $r.Details += "MSU $kb : Already installed" } else { $r.Errors += "MSU $kb exit code $exitCode" }
                        Invoke-Command -Session $sess -ArgumentList $msuName -EA SilentlyContinue -ScriptBlock { param($n); Remove-Item "C:\Temp\$n" -Force -EA SilentlyContinue }
                    } catch { $r.Errors += "MSU $kb : $($_.Exception.Message)" }
                }
            } elseif ($remaining.Count -gt 0) { foreach ($kb in $remaining) { $r.Skipped++; $r.Details += "$kb not in MECM, no MSU path -- skipped" } }
        } finally { Remove-PSSession $sess -EA SilentlyContinue }; return $r
    }
    foreach ($comp in $global:ComputerList) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($script:installBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument("Negotiate").AddArgument($kbList).AddArgument($msuPath).AddArgument($suppressReboot); $script:installJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:installTotal = $script:installJobs.Count; $script:KBInstallTimer = New-Object System.Windows.Forms.Timer; $script:KBInstallTimer.Interval = 500
    $script:totalMECM = 0; $script:totalMSU = 0; $script:totalSkip = 0; $script:totalErr = 0; $script:KBInstallTickBusy = $false
    $script:KBInstallTimer.Add_Tick({
        if ($script:KBInstallTickBusy) { return }
        $script:KBInstallTickBusy = $true
        try {
        foreach ($key in @($script:installJobs.Keys)) { $job = $script:installJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            $res = $null; try { $raw = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose(); if ($raw -is [System.Collections.IEnumerable]) { $res = @($raw) | Select-Object -First 1 } else { $res = $raw } } catch { KBLog "$key : EndInvoke error - $($_.Exception.Message)" 'ERR'; $script:totalErr++; $script:installJobs.Remove($key); continue }
            $script:installJobs.Remove($key); if ($null -eq $res) { KBLog "$key : No result" 'ERR'; $script:totalErr++; continue }
            $hostName = if ($res -is [hashtable]) { $res['Host'] } else { $res.Host }; $details = if ($res -is [hashtable]) { @($res['Details']) } else { @($res.Details) }; $errors = if ($res -is [hashtable]) { @($res['Errors']) } else { @($res.Errors) }
            $mecmInst = if ($res -is [hashtable]) { [int]$res['MECMInstalled'] } else { [int]$res.MECMInstalled }; $msuInst = if ($res -is [hashtable]) { [int]$res['MSUInstalled'] } else { [int]$res.MSUInstalled }; $skipped = if ($res -is [hashtable]) { [int]$res['Skipped'] } else { [int]$res.Skipped }
            foreach ($d in $details) { if ($d) { KBLog "$hostName : $d" 'OK' } }; foreach ($e in $errors) { if ($e) { KBLog "$hostName : ERROR - $e" 'ERR' } }
            $script:totalMECM += $mecmInst; $script:totalMSU += $msuInst; $script:totalSkip += $skipped; $script:totalErr += $errors.Count
        }
        $done = $script:installTotal - $script:installJobs.Count; $script:lblKBInstallStatus.Text = "Installing: $done / $($script:installTotal)"
        if ($script:installJobs.Count -eq 0) { if ($null -ne $script:KBInstallTimer) { $script:KBInstallTimer.Stop(); $script:KBInstallTimer.Dispose(); $script:KBInstallTimer = $null }; $script:btnKBInstall.Enabled = $true
            $script:lblKBInstallStatus.Text = "Done: MECM=$($script:totalMECM) MSU=$($script:totalMSU) Skipped=$($script:totalSkip) Errors=$($script:totalErr)"; $script:lblKBInstallStatus.ForeColor = if ($script:totalErr -eq 0) { $c.Success } else { $c.Warning }
            KBLog "========================================"; KBLog "KB Install complete: MECM=$($script:totalMECM), MSU=$($script:totalMSU), Skipped=$($script:totalSkip), Errors=$($script:totalErr)"; KBLog "========================================"
            Write-AuditLog -Action "KBInstall" -Result "Complete" -Detail "MECM=$($script:totalMECM) MSU=$($script:totalMSU) Skip=$($script:totalSkip) Err=$($script:totalErr)" }
        } finally { $script:KBInstallTickBusy = $false }
    }); $script:KBInstallTimer.Start()
})
$pnlKBStats = New-Object System.Windows.Forms.Panel; $pnlKBStats.Location = New-Object System.Drawing.Point(6, 524); $pnlKBStats.Size = New-Object System.Drawing.Size(1100, 28); $pnlKBStats.BackColor = $c.Panel; $pnlKBStats.Anchor = 'Left,Right,Bottom'
$script:lblKBStats = New-Lbl -Text "" -X 10 -Y 5 -W 900 -Font $fn.Small -Fg $c.Dim; $pnlKBStats.Controls.Add($script:lblKBStats)
$lblKBLogTitle = New-Lbl -Text "KB SCANNER LOG" -X 10 -Y 556 -W 200 -Font $fn.LabelB -Fg $c.Gold; $lblKBLogTitle.Anchor = 'Left,Bottom'
$script:rtbKBLog = New-Object System.Windows.Forms.TextBox; $script:rtbKBLog.Location = New-Object System.Drawing.Point(6, 574); $script:rtbKBLog.Size = New-Object System.Drawing.Size(1100, 78)
$script:rtbKBLog.Anchor = 'Left,Right,Bottom'; $script:rtbKBLog.BackColor = $c.OutputBg; $script:rtbKBLog.ForeColor = $c.Console; $script:rtbKBLog.Font = $fn.Console; $script:rtbKBLog.ReadOnly = $true; $script:rtbKBLog.Multiline = $true; $script:rtbKBLog.ScrollBars = 'Vertical'; $script:rtbKBLog.BorderStyle = 'None'; $script:rtbKBLog.WordWrap = $false
function KBLog($msg, $lvl = 'INFO') { $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"; if ($null -ne $script:rtbKBLog) { try { if (-not $script:rtbKBLog.IsHandleCreated) { $script:rtbKBLog.CreateControl() }; $script:rtbKBLog.Text += $line; $script:rtbKBLog.SelectionStart = $script:rtbKBLog.TextLength; $script:rtbKBLog.ScrollToCaret() } catch {} }; Log "[KBScan] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents() }
$script:KBAllResults = @()
function Populate-KBGrid {
    $script:dgvKB.Rows.Clear(); $textFilter = $script:txtKBFilter.Text.Trim(); $hostFilter = $script:ddlKBHost.SelectedItem; $data = $script:KBAllResults
    if ($hostFilter -and $hostFilter -ne "-- All Hosts --") { $data = @($data | Where-Object { $_.Host -eq $hostFilter }) }
    if (-not [string]::IsNullOrWhiteSpace($textFilter)) { $data = @($data | Where-Object { $_.Host -like "*$textFilter*" -or $_.HotFixID -like "*$textFilter*" -or $_.Description -like "*$textFilter*" -or $_.InstalledBy -like "*$textFilter*" }) }
    foreach ($kb in $data) { $idx = $script:dgvKB.Rows.Add(); $row = $script:dgvKB.Rows[$idx]; $row.Cells['Host'].Value = $kb.Host; $row.Cells['HotFixID'].Value = $kb.HotFixID; $row.Cells['Description'].Value = $kb.Description; $row.Cells['InstalledOn'].Value = $kb.InstalledOn; $row.Cells['InstalledBy'].Value = $kb.InstalledBy; $row.Cells['Source'].Value = $kb.Source
        switch -Wildcard ($kb.Description) { '*Security*' { $row.Cells['Description'].Style.ForeColor = $c.Warning }; '*Update*' { $row.Cells['Description'].Style.ForeColor = $c.Cyan }; '*Hotfix*' { $row.Cells['Description'].Style.ForeColor = $c.Purple }; default { $row.Cells['Description'].Style.ForeColor = $c.Dim } }
    }; $script:lblKBCount.Text = "Showing $($data.Count) of $($script:KBAllResults.Count)"; $script:lblKBCount.ForeColor = $c.Cyan
}
$script:txtKBFilter.Add_TextChanged({ Populate-KBGrid }); $script:ddlKBHost.Add_SelectedIndexChanged({ Populate-KBGrid })
$script:btnKBScan.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $script:btnKBScan.Enabled = $false; $script:KBAllResults = @(); $script:dgvKB.Rows.Clear(); $btnKBExport.Enabled = $false; $script:lblKBStats.Text = ""; $script:txtKBFilter.Clear()
    $script:ddlKBHost.Items.Clear(); [void]$script:ddlKBHost.Items.Add("-- All Hosts --"); $script:ddlKBHost.SelectedIndex = 0
    $script:lblKBProg.Text = "Scanning $($global:ComputerList.Count) workstation(s)..."; $script:lblKBProg.ForeColor = $c.Warning
    KBLog "========================================"; KBLog "KB Scan started on $($global:ComputerList.Count) workstation(s)"; KBLog "========================================"
    Initialize-RunspacePool; $script:kbJobs = @{}
    $script:kbBlock = { param([string]$Computer, [pscredential]$Cred, [string]$Auth); $r = @{ Host=$Computer; KBs=@(); Error="" }
        ## v47 AFNET: TCP reachability instead of ICMP.
        $reachable = $false
        foreach ($port in 5985,445) {
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }
            if ($reachable) { break }
        }
        if (-not $reachable) { $r.Error = "Offline"; return $r }
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop
            try { $kbs = Invoke-Command -Session $sess -EA Stop -ScriptBlock { Get-HotFix -EA SilentlyContinue | ForEach-Object { @{ HotFixID=$_.HotFixID; Description=$_.Description; InstalledOn=if($_.InstalledOn){$_.InstalledOn.ToString("yyyy-MM-dd")}else{""}; InstalledBy=$_.InstalledBy; Source=$_.CSName } } }; $r.KBs = @($kbs) } finally { Remove-PSSession $sess -EA SilentlyContinue }
        } catch { $r.Error = $_.Exception.Message }; return $r
    }
    foreach ($comp in $global:ComputerList) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($script:kbBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument("Negotiate"); $script:kbJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:kbTotal = $script:kbJobs.Count; $script:KBTimer = New-Object System.Windows.Forms.Timer; $script:KBTimer.Interval = 500; $script:KBTickBusy = $false
    $script:KBTimer.Add_Tick({
        if ($script:KBTickBusy) { return }
        $script:KBTickBusy = $true
        try {
        $newResults = $false
        foreach ($key in @($script:kbJobs.Keys)) { $job = $script:kbJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            $res = $null; try { $raw = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose(); if ($raw -is [System.Collections.IEnumerable]) { $res = @($raw) | Select-Object -First 1 } else { $res = $raw } } catch { KBLog "$key : EndInvoke error" 'ERR'; $script:kbJobs.Remove($key); continue }
            $script:kbJobs.Remove($key); if ($null -eq $res) { continue }
            $hostName = if ($res -is [hashtable]) { $res['Host'] } else { $res.Host }; $kbError = if ($res -is [hashtable]) { $res['Error'] } else { $res.Error }; $kbArray = if ($res -is [hashtable]) { $res['KBs'] } else { $res.KBs }
            if (-not [string]::IsNullOrWhiteSpace($kbError)) { KBLog "$hostName : FAILED - $kbError" 'ERR' }
            else { $kbList2 = @($kbArray); KBLog "$hostName : $($kbList2.Count) KB(s) found" 'OK'
                foreach ($kb in $kbList2) { $kbID = if($kb -is [hashtable]){$kb['HotFixID']}else{$kb.HotFixID}; $kbDesc = if($kb -is [hashtable]){$kb['Description']}else{$kb.Description}; $kbDate = if($kb -is [hashtable]){$kb['InstalledOn']}else{$kb.InstalledOn}; $kbBy = if($kb -is [hashtable]){$kb['InstalledBy']}else{$kb.InstalledBy}; $kbSrc = if($kb -is [hashtable]){$kb['Source']}else{$kb.Source}
                    $script:KBAllResults += [PSCustomObject]@{ Host=$hostName; HotFixID=$kbID; Description=$kbDesc; InstalledOn=$kbDate; InstalledBy=$kbBy; Source=$kbSrc }
                }; if (-not $script:ddlKBHost.Items.Contains($hostName)) { [void]$script:ddlKBHost.Items.Add($hostName) }; $newResults = $true
            }
        }
        $done = $script:kbTotal - $script:kbJobs.Count; $script:lblKBProg.Text = "Scanning: $done / $($script:kbTotal)"
        if ($newResults) { $script:lblKBCount.Text = "$($script:KBAllResults.Count) KBs from $done host(s)"; $script:lblKBCount.ForeColor = $c.Cyan }
        if ($script:kbJobs.Count -eq 0) { if ($null -ne $script:KBTimer) { $script:KBTimer.Stop(); $script:KBTimer.Dispose(); $script:KBTimer = $null }; $script:btnKBScan.Enabled = $true; Populate-KBGrid
            $uniqueKBs = ($script:KBAllResults | Select-Object -ExpandProperty HotFixID -Unique).Count; $hostsScanned = ($script:KBAllResults | Select-Object -ExpandProperty Host -Unique).Count
            $script:lblKBStats.Text = "Total: $($script:KBAllResults.Count) entries | $uniqueKBs unique KBs | $hostsScanned host(s) scanned"; $script:lblKBStats.ForeColor = $c.Cyan
            $script:lblKBProg.Text = "Scan complete: $($script:kbTotal) workstation(s)"; $script:lblKBProg.ForeColor = $c.Success; if ($script:KBAllResults.Count -gt 0) { $btnKBExport.Enabled = $true }
            KBLog "========================================"; KBLog "Complete: $($script:KBAllResults.Count) KBs from $hostsScanned host(s), $uniqueKBs unique"; KBLog "========================================"
            Write-AuditLog -Action "KBScan" -Result "Complete" -Detail "$($script:KBAllResults.Count) KBs, $hostsScanned hosts" }
        } finally { $script:KBTickBusy = $false }
    }); $script:KBTimer.Start()
})
$btnKBExport.Add_Click({ if ($script:KBAllResults.Count -eq 0) { return }; $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "KB_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; if ($sfd.ShowDialog() -eq 'OK') { $script:KBAllResults | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8; KBLog "Exported $($script:KBAllResults.Count) entries" 'OK' } })
$tabKB.Add_Enter({ $cnt = $global:ComputerList.Count; $script:lblKBTargetCount.Text = "Targets: $cnt"; $script:lblKBTargetCount.ForeColor = if ($cnt -gt 0) { $c.Success } else { $c.Warning }; foreach ($comp in $global:ComputerList) { if (-not $script:ddlKBHost.Items.Contains($comp)) { [void]$script:ddlKBHost.Items.Add($comp) } } })
$tabKB.Controls.AddRange(@($pnlKBBar, $pnlKBFilter, $script:dgvKB, $grpKBInstall, $pnlKBStats, $lblKBLogTitle, $script:rtbKBLog))
#endregion

## v6.5.0: Legacy App Updater tab removed. The v2 tab below (renamed
## to just "App Updater" in the sidebar + tab control) absorbs every
## Legacy capability: per-host Verify, parallel apply via
## RunspacePool, profile registry, plus the Custom Command path
## ported from Legacy. WSMan session options + TCP reachability
## probe + per-host audit fan-out also brought into v2 from the
## same pass — see the rewritten App Updater region further below.

###############################################################################
###                 TAB: CLEANUP  (Temp Files + Stale Profiles)             ###
###############################################################################
## Two independent cleanup operations, either or both checkable:
##   1. Temp file cleanup - Windows\Temp, C:\Temp, per-user %TEMP%,
##      per-user INetCache, Windows\Prefetch. Reports MB + file count
##      per host.
##   2. Stale profile deletion - v5.1.3: SrA Tennesen Garrett AFNET-
##      aware filter. Excludes Public / Administrator / USAF_Admin /
##      current session account (both .adw and stripped forms). Age
##      by folder LastWriteTime (matches File Explorer's Modified
##      column). Deletion via Win32_UserProfile.Delete() native method.
## DRY RUN on by default (reports without deleting); live mode requires
## a second confirmation. Layout: 2x2 grid (config / targets / results
## grid / live execution panel) with a summary log below.
#region === TAB: CLEANUP (Temp Files + Stale Profiles) ===
## v45: Cleanup tab. Two operations:
##   1. Temp file cleanup: clears C:\Windows\Temp, C:\Temp, all user %TEMP%, and Windows prefetch.
##   2. Stale profile deletion: removes user profiles whose LastUseTime is older than N days (default 60).
## Excludes system/service accounts and currently-loaded profiles automatically.
##
## Layout: 2x2 grid
##   Top-left:  Config panel (checkboxes, days, dry run, run button)
##   Top-right: Targets panel (paste/import/clear, uses global ComputerList by default,
##              but can be overridden with a Cleanup-specific subset)
##   Bottom-left:  Results grid (per-host outcomes)
##   Bottom-right: Live execution panel (real-time per-host script progress)
$tabCleanup = New-Object System.Windows.Forms.TabPage; $tabCleanup.BackColor = $c.BG

## === TOP-LEFT: CONFIG PANEL ===
$grpCleanCfg = New-Grp -Text "CLEANUP OPERATIONS" -X 6 -Y 6 -W 600 -H 240 -Fg $c.Gold
$lblCleanDesc = New-Lbl -Text "Remove temp files and/or stale user profiles." -X 10 -Y 22 -W 560 -Font $fn.Small -Fg $c.Dim
$script:chkCleanTemp = New-Object System.Windows.Forms.CheckBox
$script:chkCleanTemp.Text = "Clean temp files (Windows\Temp, C:\Temp, per-user %TEMP%, Prefetch)"
$script:chkCleanTemp.Location = New-Object System.Drawing.Point(10, 48); $script:chkCleanTemp.Size = New-Object System.Drawing.Size(570, 22)
$script:chkCleanTemp.ForeColor = $c.Cyan; $script:chkCleanTemp.FlatStyle = 'Flat'; $script:chkCleanTemp.Checked = $true
$script:chkCleanProfiles = New-Object System.Windows.Forms.CheckBox
$script:chkCleanProfiles.Text = "Delete stale user profiles (older than threshold)"
$script:chkCleanProfiles.Location = New-Object System.Drawing.Point(10, 74); $script:chkCleanProfiles.Size = New-Object System.Drawing.Size(540, 22)
$script:chkCleanProfiles.ForeColor = $c.Warning; $script:chkCleanProfiles.FlatStyle = 'Flat'; $script:chkCleanProfiles.Checked = $false
$lblCleanDays = New-Lbl -Text "Profile age threshold:" -X 40 -Y 104 -W 140 -Font $fn.LabelB -Fg $c.TextSec
$script:nudCleanDays = New-Object System.Windows.Forms.NumericUpDown
$script:nudCleanDays.Location = New-Object System.Drawing.Point(180, 102); $script:nudCleanDays.Size = New-Object System.Drawing.Size(70, 24)
$script:nudCleanDays.Minimum = 7; $script:nudCleanDays.Maximum = 730; $script:nudCleanDays.Value = 60
$script:nudCleanDays.BackColor = $c.Input; $script:nudCleanDays.ForeColor = $c.White
$lblCleanDaysHint = New-Lbl -Text "days (default 60)" -X 256 -Y 106 -W 140 -Font $fn.Small -Fg $c.Dim
$script:chkCleanDryRun = New-Object System.Windows.Forms.CheckBox
$script:chkCleanDryRun.Text = "DRY RUN (report only, no deletions)"
$script:chkCleanDryRun.Location = New-Object System.Drawing.Point(10, 132); $script:chkCleanDryRun.Size = New-Object System.Drawing.Size(320, 22)
$script:chkCleanDryRun.ForeColor = $c.Success; $script:chkCleanDryRun.FlatStyle = 'Flat'; $script:chkCleanDryRun.Checked = $true
$lblCleanSafety = New-Lbl -Text "System/service accounts, default profiles, and loaded profiles are always excluded." -X 10 -Y 158 -W 580 -Font $fn.Small -Fg $c.Dim
$script:btnCleanRun = New-Btn -Text "Run Cleanup" -X 10 -Y 186 -W 160 -H 32 -Bg $c.Success -Font $fn.BtnBig
$script:btnCleanStop = New-Btn -Text "Stop" -X 178 -Y 186 -W 80 -H 32 -Bg $c.Danger; $script:btnCleanStop.Enabled = $false
$script:lblCleanStatus = New-Lbl -Text "Configure and click Run Cleanup." -X 266 -Y 194 -W 330 -Font $fn.Small -Fg $c.Dim
$grpCleanCfg.Controls.AddRange(@($lblCleanDesc, $script:chkCleanTemp, $script:chkCleanProfiles, $lblCleanDays, $script:nudCleanDays, $lblCleanDaysHint, $script:chkCleanDryRun, $lblCleanSafety, $script:btnCleanRun, $script:btnCleanStop, $script:lblCleanStatus))

## === TOP-RIGHT: TARGETS PANEL ===
$grpCleanTargets = New-Grp -Text "CLEANUP TARGETS" -X 612 -Y 6 -W 494 -H 240 -Fg $c.Cyan; $grpCleanTargets.Anchor = 'Top,Left,Right'
$lblCleanTgtHint = New-Lbl -Text "Defaults to the main target list. Override here if you want a different subset." -X 10 -Y 22 -W 480 -Font $fn.Small -Fg $c.Dim
$script:lbxCleanTargets = New-Object System.Windows.Forms.ListBox
$script:lbxCleanTargets.Location = New-Object System.Drawing.Point(10, 42); $script:lbxCleanTargets.Size = New-Object System.Drawing.Size(474, 110)
$script:lbxCleanTargets.BackColor = $c.Input; $script:lbxCleanTargets.ForeColor = $c.Cyan; $script:lbxCleanTargets.Font = $fn.Console; $script:lbxCleanTargets.SelectionMode = 'MultiExtended'
$script:txtCleanPaste = New-Tb -X 10 -Y 158 -W 300 -H 24; $script:txtCleanPaste.Font = $fn.Console
$btnCleanAdd = New-Btn -Text "Add" -X 316 -Y 158 -W 54 -H 24 -Bg $c.Success; $btnCleanAdd.Font = $fn.Small
$btnCleanImport = New-Btn -Text "Import" -X 374 -Y 158 -W 54 -H 24 -Bg $c.PanelLight; $btnCleanImport.Font = $fn.Small
$btnCleanSync = New-Btn -Text "Sync" -X 432 -Y 158 -W 54 -H 24 -Bg $c.Accent; $btnCleanSync.Font = $fn.Small
$btnCleanRemove = New-Btn -Text "Remove Selected" -X 10 -Y 188 -W 130 -H 22 -Bg $c.Warning; $btnCleanRemove.Font = $fn.Small
$btnCleanClear = New-Btn -Text "Clear All" -X 146 -Y 188 -W 80 -H 22 -Bg $c.Danger; $btnCleanClear.Font = $fn.Small
$script:lblCleanTgtCount = New-Lbl -Text "0 target(s)" -X 232 -Y 192 -W 250 -Font $fn.SmallB -Fg $c.Dim

$UpdateCleanTgtCount = { $n = $script:lbxCleanTargets.Items.Count; $script:lblCleanTgtCount.Text = "$n cleanup target(s)"; $script:lblCleanTgtCount.ForeColor = if ($n -gt 0) { $c.Success } else { $c.Dim } }
$btnCleanAdd.Add_Click({ $names = Parse-Hosts $script:txtCleanPaste.Text; foreach ($n in $names) { if ($script:lbxCleanTargets.Items -notcontains $n) { [void]$script:lbxCleanTargets.Items.Add($n) } }; $script:txtCleanPaste.Clear(); & $UpdateCleanTgtCount })
$btnCleanImport.Add_Click({ $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter = "Text/CSV|*.txt;*.csv|All|*.*"; if ($ofd.ShowDialog() -eq 'OK') { $lines = Get-Content $ofd.FileName -EA Stop | ForEach-Object { ($_ -split "[,;]")[0].Trim() } | Where-Object { $_ -ne "" }; foreach ($n in $lines) { if ($script:lbxCleanTargets.Items -notcontains $n) { [void]$script:lbxCleanTargets.Items.Add($n) } }; & $UpdateCleanTgtCount } })
$btnCleanSync.Add_Click({ $script:lbxCleanTargets.Items.Clear(); foreach ($h in $global:ComputerList) { [void]$script:lbxCleanTargets.Items.Add($h) }; & $UpdateCleanTgtCount; CleanLog "Synced $($global:ComputerList.Count) target(s) from main list" 'OK' })
$btnCleanRemove.Add_Click({ $sel = @($script:lbxCleanTargets.SelectedItems); foreach ($i in $sel) { $script:lbxCleanTargets.Items.Remove($i) }; & $UpdateCleanTgtCount })
$btnCleanClear.Add_Click({ $script:lbxCleanTargets.Items.Clear(); & $UpdateCleanTgtCount })
$tabCleanup.Add_Enter({ if ($script:lbxCleanTargets.Items.Count -eq 0 -and $global:ComputerList.Count -gt 0) { foreach ($h in $global:ComputerList) { [void]$script:lbxCleanTargets.Items.Add($h) }; & $UpdateCleanTgtCount } })

$grpCleanTargets.Controls.AddRange(@($lblCleanTgtHint, $script:lbxCleanTargets, $script:txtCleanPaste, $btnCleanAdd, $btnCleanImport, $btnCleanSync, $btnCleanRemove, $btnCleanClear, $script:lblCleanTgtCount))

## === BOTTOM-LEFT: RESULTS GRID ===
$lblCleanGridTitle = New-Lbl -Text "RESULTS" -X 10 -Y 254 -W 200 -Font $fn.LabelB -Fg $c.Gold
$script:dgvClean = New-Object System.Windows.Forms.DataGridView
$script:dgvClean.Location = New-Object System.Drawing.Point(6, 272); $script:dgvClean.Size = New-Object System.Drawing.Size(600, 180)
$script:dgvClean.Anchor = 'Top,Left,Bottom'; $script:dgvClean.ReadOnly = $true; Style-Grid $script:dgvClean
$script:dgvClean.AutoSizeColumnsMode = 'None'; $script:dgvClean.ScrollBars = 'Both'
foreach ($col in @(@{N='Host';H='Host';W=140},@{N='TempMB';H='Temp MB';W=75},@{N='TempFiles';H='Files';W=55},@{N='ProfilesFound';H='Prof Found';W=75},@{N='ProfilesRemoved';H='Removed';W=70},@{N='Skipped';H='Skip';W=50},@{N='Status';H='Status';W=110}) ) { $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvClean.Columns.Add($cc) }

## === BOTTOM-RIGHT: LIVE EXECUTION PANEL ===
## Shows the running script actions in real time -- what path is being cleaned,
## what profile is being evaluated, what was deleted, per-host progress.
$lblCleanExecTitle = New-Lbl -Text "LIVE EXECUTION (what the script is doing right now)" -X 616 -Y 254 -W 450 -Font $fn.LabelB -Fg $c.Cyan; $lblCleanExecTitle.Anchor = 'Top,Right'
$script:rtbCleanExec = New-Object System.Windows.Forms.RichTextBox
$script:rtbCleanExec.Location = New-Object System.Drawing.Point(612, 272); $script:rtbCleanExec.Size = New-Object System.Drawing.Size(494, 180)
$script:rtbCleanExec.Anchor = 'Top,Right,Bottom'; $script:rtbCleanExec.BackColor = $c.OutputBg; $script:rtbCleanExec.ForeColor = $c.Console
## v6.1.7: switched BorderStyle None -> FixedSingle. Without a border and
## with BackColor=OutputBg (near-black) on a near-black tab, the panel was
## indistinguishable from the surrounding empty area -- operators reported
## "there is no Live Execution box" because they literally could not see it.
$script:rtbCleanExec.Font = $fn.Console; $script:rtbCleanExec.ReadOnly = $true; $script:rtbCleanExec.BorderStyle = 'FixedSingle'; $script:rtbCleanExec.WordWrap = $false

function CleanExec($msg, $lvl = 'INFO') {
    if ($null -eq $script:rtbCleanExec) { return }
    $ts = (Get-Date).ToString("HH:mm:ss.fff"); $line = "[$ts] $msg`r`n"
    try {
        if (-not $script:rtbCleanExec.IsHandleCreated) { $script:rtbCleanExec.CreateControl() }
        $start = $script:rtbCleanExec.TextLength
        $script:rtbCleanExec.AppendText($line)
        $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; 'ACTION' { $c.Cyan }; 'DELETE' { $c.Purple }; default { $c.Console } }
        $script:rtbCleanExec.Select($start, $line.Length); $script:rtbCleanExec.SelectionColor = $clr
        $script:rtbCleanExec.SelectionLength = 0; $script:rtbCleanExec.ScrollToCaret()
        ## Auto-trim to keep memory reasonable during long cleanups
        if ($script:rtbCleanExec.Lines.Count -gt 2000) {
            $keep = $script:rtbCleanExec.Lines | Select-Object -Last 1500
            $script:rtbCleanExec.Clear(); $script:rtbCleanExec.AppendText(($keep -join "`r`n"))
        }
    } catch {}
    [System.Windows.Forms.Application]::DoEvents()
}

## === LEGACY SUMMARY LOG (below grid, full width) ===
$lblCleanLogTitle = New-Lbl -Text "SUMMARY LOG" -X 10 -Y 458 -W 200 -Font $fn.LabelB -Fg $c.Gold; $lblCleanLogTitle.Anchor = 'Left,Bottom'
$script:rtbCleanLog = New-Object System.Windows.Forms.TextBox
$script:rtbCleanLog.Location = New-Object System.Drawing.Point(6, 478); $script:rtbCleanLog.Size = New-Object System.Drawing.Size(1100, 174)
$script:rtbCleanLog.Anchor = 'Left,Right,Bottom'; $script:rtbCleanLog.BackColor = $c.OutputBg; $script:rtbCleanLog.ForeColor = $c.Console
## v6.1.7: also gave the summary log a FixedSingle border for the same
## reason as rtbCleanExec above. The duplicate config line below was dead
## weight from a copy-paste merge; kept one copy.
$script:rtbCleanLog.Font = $fn.Console; $script:rtbCleanLog.ReadOnly = $true; $script:rtbCleanLog.Multiline = $true; $script:rtbCleanLog.ScrollBars = 'Vertical'; $script:rtbCleanLog.BorderStyle = 'FixedSingle'; $script:rtbCleanLog.WordWrap = $false
function CleanLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbCleanLog) { try { if (-not $script:rtbCleanLog.IsHandleCreated) { $script:rtbCleanLog.CreateControl() }; $script:rtbCleanLog.Text += $line; $script:rtbCleanLog.SelectionStart = $script:rtbCleanLog.TextLength; $script:rtbCleanLog.ScrollToCaret() } catch {} }
    Log "[Cleanup] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents()
}

## Cleanup scriptblock -- runs on each remote target
$global:CleanBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth, [bool]$DoTemp, [bool]$DoProfiles, [int]$DaysThreshold, [bool]$DryRun, $EventQueue)
    $r = @{ Host=$Computer; TempMB=0; TempFiles=0; ProfilesFound=0; ProfilesRemoved=0; Skipped=0; Status='Failed'; Detail=''; ProfileNames=@() }
    $Emit = { param($lvl, $msg); if ($null -ne $EventQueue) { [void]$EventQueue.Enqueue(@{ Host=$Computer; Level=$lvl; Msg=$msg; Time=(Get-Date) }) } }
    & $Emit 'INFO' "[$Computer] Starting cleanup (Temp=$DoTemp, Profiles=$DoProfiles, Dry=$DryRun)"
    ## v47 AFNET: TCP reachability instead of ICMP (blocked by Defender GPO).
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { & $Emit 'ERR' "[$Computer] Unreachable -- WinRM/SMB closed"; $r.Detail = 'Offline'; return $r }
    $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sess = $null
    try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop; & $Emit 'OK' "[$Computer] PSSession established" }
    catch { & $Emit 'ERR' "[$Computer] Session failed: $($_.Exception.Message)"; $r.Detail = "Session: $($_.Exception.Message)"; return $r }
    try {
        if ($DoTemp) {
            & $Emit 'ACTION' "[$Computer] Phase: Temp file cleanup starting"
            ## v6.1.7: Events are collected in a local array inside the
            ## remote scriptblock and returned with the result. The previous
            ## pattern passed the ConcurrentQueue through -ArgumentList,
            ## but PSSession remoting serializes the queue to a deserialized
            ## PSCustomObject -- Enqueue() calls on it silently failed, so
            ## every per-path / per-profile diagnostic line was being lost.
            ## The local worker now re-emits each returned event via $Emit,
            ## which writes to the real in-process queue the UI timer reads.
            $tempResult = Invoke-Command -Session $sess -ArgumentList $DryRun, $Computer -EA Stop -ScriptBlock {
                param($dry, $thisHost)
                $ev = New-Object System.Collections.Generic.List[hashtable]
                $add = { param($lvl, $msg) [void]$ev.Add(@{ Level=$lvl; Msg=$msg }) }
                $totalBytes = 0; $totalFiles = 0
                $tempPaths = @('C:\Windows\Temp','C:\Temp','C:\Windows\Prefetch')
                $userProfiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
                foreach ($up in $userProfiles) {
                    $tempPaths += (Join-Path $up.FullName 'AppData\Local\Temp')
                    $tempPaths += (Join-Path $up.FullName 'AppData\Local\Microsoft\Windows\INetCache')
                }
                foreach ($tp in $tempPaths) {
                    if (-not (Test-Path -LiteralPath $tp -EA SilentlyContinue)) { & $add 'INFO' "[$thisHost]   Skip (not present): $tp"; continue }
                    & $add 'ACTION' "[$thisHost]   Scanning: $tp"
                    $items = Get-ChildItem -LiteralPath $tp -Recurse -Force -File -EA SilentlyContinue
                    $pathFiles = 0; $pathBytes = 0
                    foreach ($it in $items) {
                        $totalBytes += $it.Length; $totalFiles++; $pathFiles++; $pathBytes += $it.Length
                        if (-not $dry) { try { Remove-Item -LiteralPath $it.FullName -Force -EA Stop } catch {} }
                    }
                    $pathMB = [Math]::Round($pathBytes / 1MB, 1)
                    if ($pathFiles -gt 0) {
                        $verb = if ($dry) { 'Would delete' } else { 'Deleted' }
                        & $add 'DELETE' "[$thisHost]     $verb $pathFiles file(s), $pathMB MB from $(Split-Path $tp -Leaf)"
                    }
                }
                return @{ Bytes=$totalBytes; Files=$totalFiles; Events=$ev.ToArray() }
            }
            foreach ($e in @($tempResult.Events)) { & $Emit $e.Level $e.Msg }
            $r.TempMB = [Math]::Round(($tempResult.Bytes / 1MB), 1); $r.TempFiles = $tempResult.Files
            & $Emit 'OK' "[$Computer] Temp complete: $($r.TempMB) MB / $($r.TempFiles) files"
        }
        if ($DoProfiles) {
            & $Emit 'ACTION' "[$Computer] Phase: Profile scan (threshold $DaysThreshold days)"
            $profResult = Invoke-Command -Session $sess -ArgumentList $DaysThreshold, $DryRun, $Computer -EA Stop -ScriptBlock {
                param($days, $dry, $thisHost)
                $ev = New-Object System.Collections.Generic.List[hashtable]
                $add = { param($lvl, $msg) [void]$ev.Add(@{ Level=$lvl; Msg=$msg }) }
                $cutoff = (Get-Date).AddDays(-$days)
                $found = 0; $removed = 0; $skipped = 0; $names = @()

                ## Exclude list inherited from SrA Tennesen Garrett's AFNET
                ## script: Public / Administrator / USAF_Admin + the
                ## operator's current session account in base and ".adw"
                ## admin forms. $env:USERNAME inside the PSSession is the
                ## credential we connected with (often <edipi>.adw); strip
                ## ".adw" to also protect the matching regular account.
                $curName  = $env:USERNAME
                $baseName = $curName -replace '\.adw$',''
                $adwName  = "$baseName.adw"
                $excluded = @('Public','Administrator','USAF_Admin',$curName,$baseName,$adwName) | Sort-Object -Unique

                ## Get-WmiObject (not Get-CimInstance) so the returned
                ## object's native .Delete() method is available -- matches
                ## the reference script and works on PS 5.1. Loaded
                ## profiles are kept in the candidate set; we detect
                ## "Loaded" later and skip the actual delete with a
                ## "reboot to unload" warning rather than hiding them.
                $profiles = Get-WmiObject Win32_UserProfile -Filter "LocalPath like 'C:\\Users\\%'" -EA SilentlyContinue | Where-Object {
                    -not $_.Special -and
                    (Split-Path -Parent $_.LocalPath) -eq "$env:SystemDrive\Users" -and
                    (Split-Path -Leaf   $_.LocalPath) -notin $excluded
                }
                & $add 'INFO' "[$thisHost]   Found $(@($profiles).Count) candidate profile(s) (excluded: $($excluded -join ', '))"
                foreach ($p in $profiles) {
                    $profPath = $p.LocalPath; if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
                    $profName = Split-Path $profPath -Leaf
                    $folder = Get-Item -LiteralPath $profPath -Force -EA SilentlyContinue
                    if (-not $folder) { & $add 'WARN' "[$thisHost]     Skip (folder missing): $profName"; $skipped++; continue }

                    ## v6.1.7: age classification uses the OLDEST of three
                    ## signals. Rationale: on live AFNET hosts every
                    ## "recent activity" signal gets bumped by SOMETHING
                    ## -- folder mtime by Defender/ESS/Search/GPO/OneDrive;
                    ## NTUSER.DAT by GPO evaluating user context or any
                    ## Reg.exe Load/Unload cycle; only LastUseTime is
                    ## strictly logon-scoped, and even it can get stuck.
                    ## If ANY signal says "hasn't been touched in a long
                    ## time," trust that -- a profile being actively used
                    ## bumps ALL three. The safety net: if a profile is
                    ## currently Loaded (real user session), we detect
                    ## that flag below and skip the delete regardless.
                    ## Signals gathered:
                    ##   1) NTUSER.DAT LastWriteTime (registry hive)
                    ##   2) Win32_UserProfile.LastUseTime (WMI)
                    ##   3) folder LastWriteTime (noisiest)
                    $sigs = @()
                    $ntuserPath = Join-Path $profPath 'NTUSER.DAT'
                    $ntuser = Get-Item -LiteralPath $ntuserPath -Force -EA SilentlyContinue
                    if ($ntuser -and $ntuser.LastWriteTime -gt [datetime]'2000-01-01') {
                        $sigs += [PSCustomObject]@{ Src='NTUSER.DAT'; Time=$ntuser.LastWriteTime }
                    }
                    if ($p.LastUseTime) {
                        try {
                            $t = [System.Management.ManagementDateTimeConverter]::ToDateTime($p.LastUseTime)
                            if ($t -gt [datetime]'2000-01-01') {
                                $sigs += [PSCustomObject]@{ Src='LastUseTime'; Time=$t }
                            }
                        } catch {}
                    }
                    if ($folder.LastWriteTime -gt [datetime]'2000-01-01') {
                        $sigs += [PSCustomObject]@{ Src='folder-mtime'; Time=$folder.LastWriteTime }
                    }

                    if ($sigs.Count -eq 0) {
                        & $add 'WARN' "[$thisHost]     Skip (no usable timestamps): $profName"
                        $skipped++
                        continue
                    }

                    $oldest = $sigs | Sort-Object Time | Select-Object -First 1
                    $newest = $sigs | Sort-Object Time -Descending | Select-Object -First 1
                    $lastUse = $oldest.Time; $ageSrc = $oldest.Src
                    $ageDays = [int]((Get-Date) - $lastUse).TotalDays

                    ## Per-profile signal spread line for ops visibility.
                    $spread = ($sigs | ForEach-Object { "$($_.Src)=$($_.Time.ToString('yyyy-MM-dd'))" }) -join ' / '
                    & $add 'INFO' "[$thisHost]     $profName signals: $spread (oldest=$ageSrc, ${ageDays}d)"

                    if ($lastUse -ge $cutoff) {
                        & $add 'INFO' "[$thisHost]     Keep: $profName (${ageDays}d old, under ${days}d threshold)"
                        continue
                    }

                    if ($p.Loaded) {
                        & $add 'WARN' "[$thisHost]     Stale but LOADED: $profName (${ageDays}d) -- reboot host to unload, then re-run"
                        $skipped++
                        continue
                    }

                    $found++
                    $names += "$profName (${ageDays}d, src=$ageSrc)"
                    & $add 'ACTION' "[$thisHost]     Stale: $profName (${ageDays}d, oldest signal=$ageSrc)"
                    if (-not $dry) {
                        ## Three-tier delete: WMI .Delete() is what the
                        ## reference script uses, but on Win10/11 it
                        ## frequently throws an empty-message exception
                        ## even with elevated WinRM. Fall back to
                        ## Remove-CimInstance, and finally to a manual
                        ## ProfileList SID-key + folder removal.
                        $deleted = $false
                        $tries = New-Object System.Collections.Generic.List[string]
                        $sid   = [string]$p.SID

                        try {
                            $p.Delete()
                            $deleted = $true
                            $tries.Add('WMI=ok') | Out-Null
                        } catch {
                            $msg = $_.Exception.Message
                            if ([string]::IsNullOrWhiteSpace($msg)) { $msg = '(empty)' }
                            $tries.Add("WMI=fail:$msg") | Out-Null
                        }

                        if (-not $deleted) {
                            try {
                                $cim = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -EA Stop
                                if ($cim) {
                                    Remove-CimInstance -InputObject $cim -EA Stop
                                    $deleted = $true
                                    $tries.Add('CIM=ok') | Out-Null
                                } else {
                                    $tries.Add('CIM=fail:no-instance') | Out-Null
                                }
                            } catch {
                                $tries.Add("CIM=fail:$($_.Exception.Message)") | Out-Null
                            }
                        }

                        if (-not $deleted) {
                            ## v6.4.1: hardened manual tier. Two failure modes
                            ## the simple Remove-Item path can't handle:
                            ##   (a) MAX_PATH (260-char) — Office vNext license
                            ##       entitlement files under AppData\Local\
                            ##       Microsoft\Office\Licenses use base64 UTF-16
                            ##       names that can blow past 260 chars when
                            ##       prefixed with the profile path. Remove-Item
                            ##       walks in, can't enumerate the deeper file,
                            ##       and aborts.
                            ##   (b) ACL — at least one file has an ACL the
                            ##       .adw account can't traverse without first
                            ##       taking ownership.
                            ## Order: takeown + icacls -> Remove-Item ->
                            ## cmd `rd /s /q` -> robocopy /MIR (handles long
                            ## paths natively) -> SID key removal. Each step
                            ## is best-effort; the first one that empties the
                            ## folder wins, and the SID key removal is always
                            ## attempted regardless so half-deleted profiles
                            ## still detach from the ProfileList.
                            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                            $folderGone = (-not (Test-Path -LiteralPath $profPath))
                            $manualErr  = ''

                            ## Step A: take ownership + grant Administrators
                            ## full control recursively. Both tools are silent
                            ## on success and ignore non-existent paths, so
                            ## we don't gate on their exit codes.
                            if (-not $folderGone) {
                                try { & cmd /c "takeown /F `"$profPath`" /A /R /D Y" 2>&1 | Out-Null } catch {}
                                try { & cmd /c "icacls `"$profPath`" /grant *S-1-5-32-544:(F) /T /C /Q" 2>&1 | Out-Null } catch {}
                            }

                            ## Step B: try Remove-Item first (fast path).
                            if (-not $folderGone) {
                                try {
                                    Remove-Item -LiteralPath $profPath -Recurse -Force -EA Stop
                                    $folderGone = $true
                                } catch { $manualErr = $_.Exception.Message }
                            }

                            ## Step C: cmd `rd /s /q` — slightly more tolerant
                            ## of in-use handles than Remove-Item.
                            if (-not $folderGone -and (Test-Path -LiteralPath $profPath)) {
                                try {
                                    & cmd /c "rd /s /q `"$profPath`"" 2>&1 | Out-Null
                                    if (-not (Test-Path -LiteralPath $profPath)) { $folderGone = $true }
                                } catch {}
                            }

                            ## Step D: robocopy /MIR an empty dir over the
                            ## profile. robocopy walks long paths natively
                            ## (no MAX_PATH limit) and is the canonical fix
                            ## for the Office EXCatalog entitlement-file mess.
                            if (-not $folderGone -and (Test-Path -LiteralPath $profPath)) {
                                try {
                                    $emptyDir = Join-Path $env:TEMP ("wpt-empty-{0:N}" -f [guid]::NewGuid())
                                    New-Item -Path $emptyDir -ItemType Directory -Force -EA Stop | Out-Null
                                    & robocopy $emptyDir $profPath /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP 2>&1 | Out-Null
                                    Remove-Item -LiteralPath $emptyDir -Force -Recurse -EA SilentlyContinue
                                    Remove-Item -LiteralPath $profPath -Force -Recurse -EA SilentlyContinue
                                    if (-not (Test-Path -LiteralPath $profPath)) { $folderGone = $true }
                                } catch { $manualErr = "robocopy: $($_.Exception.Message)" }
                            }

                            ## Step E: ProfileList SID key — always attempted.
                            ## A profile is "gone" from Windows' POV when this
                            ## key is removed even if the folder is partially
                            ## intact, so logon won't reuse it.
                            $keyGone = $true
                            try {
                                if ($sid -and (Test-Path -LiteralPath $regKey)) {
                                    Remove-Item -LiteralPath $regKey -Recurse -Force -EA Stop
                                }
                            } catch { $keyGone = $false; $manualErr = "regkey: $($_.Exception.Message)" }

                            if ($folderGone -and $keyGone) {
                                $deleted = $true
                                $tries.Add('Manual=ok') | Out-Null
                            } elseif ($keyGone -and -not $folderGone) {
                                ## SID key gone, folder partially remains.
                                ## Counts as success — the profile won't be
                                ## reused; the leftover bytes are inert.
                                $deleted = $true
                                $tries.Add('Manual=partial(key-only)') | Out-Null
                            } else {
                                $detail = if ($manualErr) { "Manual=fail:$manualErr" } else { 'Manual=fail:folder remained' }
                                $tries.Add($detail) | Out-Null
                            }
                        }

                        if ($deleted) {
                            $removed++
                            & $add 'DELETE' "[$thisHost]       DELETED profile: $profName  ($(($tries -join ' ; ')))"
                        } else {
                            $skipped++
                            & $add 'ERR' "[$thisHost]       Delete failed: $profName  ($(($tries -join ' ; ')))"
                        }
                    } else {
                        & $add 'DELETE' "[$thisHost]       Would delete (dry run): $profName"
                    }
                }
                return @{ Found=$found; Removed=$removed; Skipped=$skipped; Names=$names; Events=$ev.ToArray() }
            }
            foreach ($e in @($profResult.Events)) { & $Emit $e.Level $e.Msg }
            $r.ProfilesFound = $profResult.Found; $r.ProfilesRemoved = $profResult.Removed
            $r.Skipped = $profResult.Skipped; $r.ProfileNames = @($profResult.Names)
            & $Emit 'OK' "[$Computer] Profile phase complete: $($r.ProfilesFound) stale, $($r.ProfilesRemoved) removed, $($r.Skipped) skipped"
        }
        $r.Status = if ($DryRun) { 'Dry Run OK' } else { 'Success' }
        $r.Detail = "Temp: $($r.TempMB)MB / $($r.TempFiles) files | Profiles found: $($r.ProfilesFound), removed: $($r.ProfilesRemoved)"
        & $Emit 'OK' "[$Computer] DONE -- $($r.Detail)"
    } catch { $r.Detail = $_.Exception.Message; & $Emit 'ERR' "[$Computer] ERROR: $($r.Detail)" }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

$script:btnCleanRun.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    $cleanupTargets = @($script:lbxCleanTargets.Items | ForEach-Object { $_.ToString() })
    if ($cleanupTargets.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No cleanup targets. Add hosts in the Cleanup Targets panel, or click Sync to copy from the main Targets list.","No Targets"); return }
    if (-not $script:chkCleanTemp.Checked -and -not $script:chkCleanProfiles.Checked) { [System.Windows.Forms.MessageBox]::Show("Select at least one cleanup operation.","Nothing Selected"); return }
    $doTemp = $script:chkCleanTemp.Checked; $doProfiles = $script:chkCleanProfiles.Checked
    $days = [int]$script:nudCleanDays.Value; $dry = $script:chkCleanDryRun.Checked
    $ops = @(); if ($doTemp) { $ops += "Temp files" }; if ($doProfiles) { $ops += "Profiles older than $days days" }
    $modeStr = if ($dry) { "DRY RUN" } else { "LIVE -- deletions will occur" }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Run cleanup on $($cleanupTargets.Count) workstation(s)?`n`nOperations: $($ops -join ', ')`nMode: $modeStr","Confirm Cleanup",4,48)
    if ($confirm -ne 'Yes') { return }
    if (-not $dry -and $doProfiles) {
        $confirm2 = [System.Windows.Forms.MessageBox]::Show("LIVE MODE -- profiles will be PERMANENTLY DELETED.`n`nAre you absolutely sure?","Final Confirmation",4,16)
        if ($confirm2 -ne 'Yes') { return }
    }
    $script:btnCleanRun.Enabled = $false; $script:btnCleanStop.Enabled = $true
    $script:dgvClean.Rows.Clear(); $script:rtbCleanExec.Clear()
    $dimClr = [System.Drawing.Color]::FromArgb(90,90,130)
    foreach ($comp in $cleanupTargets) { $idx = $script:dgvClean.Rows.Add($comp, '--', '--', '--', '--', '--', 'Queued'); foreach ($ci in 0..6) { $script:dgvClean.Rows[$idx].Cells[$ci].Style.ForeColor = $dimClr } }
    $script:lblCleanStatus.Text = "Running: 0 / $($cleanupTargets.Count)"; $script:lblCleanStatus.ForeColor = $c.Warning
    CleanLog "========================================"
    CleanLog "Cleanup started on $($cleanupTargets.Count) workstation(s) [$modeStr]"
    CleanLog "Temp: $doTemp | Profiles: $doProfiles (threshold $days days)"
    CleanLog "========================================"
    CleanExec "=== Cleanup session started: $modeStr ===" 'ACTION'
    CleanExec "Operations: $($ops -join ', ')" 'ACTION'
    CleanExec "Target count: $($cleanupTargets.Count)" 'ACTION'
    ## Create a thread-safe queue for live events from runspace threads
    $script:CleanEventQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[hashtable]
    Initialize-RunspacePool; $script:CleanJobs = @{}
    foreach ($comp in $cleanupTargets) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:CleanBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument('Negotiate').AddArgument($doTemp).AddArgument($doProfiles).AddArgument($days).AddArgument($dry).AddArgument($script:CleanEventQueue)
        $script:CleanJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() }
    }
    $script:CleanTotal = $cleanupTargets.Count
    $script:CleanTimer = New-Object System.Windows.Forms.Timer; $script:CleanTimer.Interval = 300; $script:CleanTickBusy = $false
    $script:CleanTimer.Add_Tick({
        if ($script:CleanTickBusy) { return }
        $script:CleanTickBusy = $true
        try {
        ## Drain live event queue first (this is what streams script actions into the Live panel)
        $evt = $null; $drained = 0
        while ($drained -lt 50 -and $script:CleanEventQueue.TryDequeue([ref]$evt)) {
            CleanExec $evt.Msg $evt.Level
            $drained++
        }
        ## Then collect completed jobs
        foreach ($key in @($script:CleanJobs.Keys)) {
            $job = $script:CleanJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            $res = $null
            try { $raw = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose(); if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [hashtable]) { $res = @($raw)[0] } else { $res = $raw } }
            catch { $res = @{ Host=$key; Status='Error'; Detail=$_.Exception.Message } }
            $script:CleanJobs.Remove($key)
            if ($null -eq $res) { continue }
            foreach ($row in $script:dgvClean.Rows) {
                if ($row.Cells[0].Value -eq $res.Host) {
                    $row.Cells[1].Value = if ($res.TempMB) { "$($res.TempMB)" } else { '--' }
                    $row.Cells[2].Value = if ($res.TempFiles) { "$($res.TempFiles)" } else { '--' }
                    $row.Cells[3].Value = if ($null -ne $res.ProfilesFound) { "$($res.ProfilesFound)" } else { '--' }
                    $row.Cells[4].Value = if ($null -ne $res.ProfilesRemoved) { "$($res.ProfilesRemoved)" } else { '--' }
                    $row.Cells[5].Value = if ($null -ne $res.Skipped) { "$($res.Skipped)" } else { '--' }
                    $row.Cells[6].Value = $res.Status
                    $clr = if ($res.Status -match 'Success|Dry Run') { $c.Success } else { $c.Danger }
                    foreach ($ci in 0..6) { $row.Cells[$ci].Style.ForeColor = $clr }
                    break
                }
            }
            CleanLog "$($res.Host) : $($res.Status) | $($res.Detail)" $(if ($res.Status -match 'Success|Dry') { 'OK' } else { 'ERR' })
            if ($res.ProfileNames -and $res.ProfileNames.Count -gt 0) { foreach ($pn in $res.ProfileNames) { CleanLog "    Profile: $pn" } }
            Write-AuditLog -Action "Cleanup" -Target $res.Host -Result $res.Status -Detail $res.Detail
        }
        $done = $script:CleanTotal - $script:CleanJobs.Count
        $script:lblCleanStatus.Text = "Running: $done / $($script:CleanTotal)"
        if ($script:CleanJobs.Count -eq 0) {
            ## Final drain pass to catch any trailing events
            while ($script:CleanEventQueue.TryDequeue([ref]$evt)) { CleanExec $evt.Msg $evt.Level }
            if ($null -ne $script:CleanTimer) { $script:CleanTimer.Stop(); $script:CleanTimer.Dispose(); $script:CleanTimer = $null }
            $script:btnCleanRun.Enabled = $true; $script:btnCleanStop.Enabled = $false
            $script:lblCleanStatus.Text = "Cleanup complete: $($script:CleanTotal) workstation(s)"
            $script:lblCleanStatus.ForeColor = $c.Success
            CleanLog "========================================"
            CleanLog "Cleanup complete"
            CleanLog "========================================"
            CleanExec "=== Cleanup session finished ===" 'OK'
        }
        } finally { $script:CleanTickBusy = $false }
    })
    $script:CleanTimer.Start()
})
$script:btnCleanStop.Add_Click({
    if ($null -eq $script:CleanJobs -or $script:CleanJobs.Count -eq 0) { return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Stop cleanup? In-flight remote operations will be cancelled.`n`nNote: Operations already executing on remote hosts may complete anyway.","Confirm Stop",4,48)
    if ($confirm -ne 'Yes') { return }
    CleanExec "=== STOP REQUESTED -- cancelling $($script:CleanJobs.Count) in-flight job(s) ===" 'WARN'
    foreach ($key in @($script:CleanJobs.Keys)) {
        try { $script:CleanJobs[$key].PS.Stop(); $script:CleanJobs[$key].PS.Dispose() } catch {}
        $script:CleanJobs.Remove($key)
    }
    if ($null -ne $script:CleanTimer) { try { $script:CleanTimer.Stop(); $script:CleanTimer.Dispose() } catch {}; $script:CleanTimer = $null }
    $script:btnCleanRun.Enabled = $true; $script:btnCleanStop.Enabled = $false
    $script:lblCleanStatus.Text = "Stopped by operator"; $script:lblCleanStatus.ForeColor = $c.Warning
    CleanLog "Cleanup stopped by operator" 'WARN'
})
$tabCleanup.Controls.AddRange(@($grpCleanCfg, $grpCleanTargets, $lblCleanGridTitle, $script:dgvClean, $lblCleanExecTitle, $script:rtbCleanExec, $lblCleanLogTitle, $script:rtbCleanLog))
#endregion

###############################################################################
###      REG KEY FIXES (BHI Remediation, CVE-2022-0001)  v6.3.0             ###
###############################################################################
## Generic registry-value remediation framework. Add a new entry to
## $global:RegKeyFixCatalog and the rest of the tab is automatic - the
## scan/apply/verify/dashboard logic reads everything from the catalog.
##
## Status semantics (dashboard column):
##   Vulnerable             - any expected value is missing or zero
##   Patched                - all values match expected (kernel will pick
##                            them up at next reboot; BHI mitigation reads
##                            these registry keys at boot only)
##   Drifted                - values present but != expected (something
##                            else wrote here - investigate)
##   Unreachable            - WinRM did not answer; skipped
##
## Exact-equality against expected values rather than a bit-mask check
## (the latter was decoupled from the apply value and always reported
## "vulnerable" even right after a successful apply).
#region === REG KEY FIXES SCRIPTBLOCKS (v6.3.0 - Ninkxz/RegKeyFixes-BHI port) ===
$global:RegKeyFixCatalog = [ordered]@{
    'BHI' = @{
        DisplayName = 'BHI Remediation (CVE-2022-0001)'
        CVE         = 'CVE-2022-0001'
        RegPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
        Values      = [ordered]@{
            ## v6.5.20 BUG FIX: was Expected=8264 (0x2048), which does NOT
            ## contain the BHI mitigation bit (0x800000). Because the apply
            ## block does a flat overwrite, the old value (a) never cleared
            ## Tenable plugin 302873 and (b) would have STRIPPED the BHI bit
            ## from any host that already had 0x800000 set. The 28 May 2026
            ## fleet scan proved (a): 43 hosts sitting at exactly 0x2048
            ## were still flagged for CVE-2022-0001.
            ## Switched to OrBits mode -- set bit 0x800000 while PRESERVING
            ## the existing Spectre/Meltdown bits already in the value:
            ##   0x48     -> 0x800048   (Recommended Settings 3, HT enabled)
            ##   0x2048   -> 0x802048   (Recommended Settings 2, HT disabled)
            ##   0x800000 -> 0x800000   (already compliant; OR is a no-op)
            ## Mask stays 3 (matches all three of the plugin's Recommended
            ## Settings scenarios).
            'FeatureSettingsOverride'     = @{ OrBits = 0x00800000; Type = 'DWord' }
            'FeatureSettingsOverrideMask' = @{ Expected = 3;        Type = 'DWord' }
        }
        Description = 'Sets the Branch History Injection mitigation bit (0x800000) in FeatureSettingsOverride, OR-ed into the existing value so Spectre/Meltdown mitigations are preserved (e.g. 0x48->0x800048, 0x2048->0x802048). Mask=3. Reboot required for the kernel to pick up the change. (v6.5.20 corrected the old flat 0x2048 write that never cleared plugin 302873.)'
    }
    'Edge_ImportSearchEngine' = @{
        ## v6.5.20: DISA Microsoft Edge STIG EDGE-00-000022 /
        ## SV-235739r960963_rule. Tenable plugin 1004575 with the
        ## reference token "noCCE" -- the .audit file for the Edge
        ## STIG ships without a CCE field on this check, so Tenable
        ## just emits noCCE. The 28 May 2026 scan flagged 1489
        ## hosts fleet-wide for the same single control because the
        ## GPO 'Allow importing of search engine settings = Disabled'
        ## was never deployed (or the MSEdge ADMX in the Central
        ## Store is too old to write the value). One DWord; takes
        ## effect at next Edge launch, no reboot.
        DisplayName = 'Edge: Disable Importing Search Engine Settings (STIG EDGE-00-000022)'
        CVE         = 'STIG EDGE-00-000022'
        RegPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Values      = [ordered]@{
            'ImportSearchEngine' = @{ Expected = 0; Type = 'DWord' }
        }
        Description = 'Sets HKLM:\SOFTWARE\Policies\Microsoft\Edge\ImportSearchEngine = 0 (REG_DWORD) -- equivalent to GPO "Allow importing of search engine settings = Disabled". Clears DISA Edge STIG EDGE-00-000022 / Tenable noCCE finding. No reboot; takes effect at next Edge launch.'
    }
}

## Per-host scan scriptblock. Returns: @{ Host; Reachable; CPU; LastBoot;
## RegValues; Status; Error }. Runspace pool worker; no globals visible.
$global:RegKeyScanBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth, [string]$RegPath, [object[]]$Defs)
    $r = @{ Host=$Computer; Reachable=$false; CPU=''; LastBoot=$null; RegValues=@{}; Status='Unreachable'; Error='' }
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Error = 'Offline'; return $r }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $remote = Invoke-Command -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -ArgumentList $RegPath, $Defs -EA Stop -ScriptBlock {
            param($p, $defs)
            $out = @{ RegValues=@{}; CPU=''; LastBoot=$null }
            try {
                $out.CPU = (Get-CimInstance Win32_Processor -EA SilentlyContinue | Select-Object -First 1).Name
                $out.LastBoot = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).LastBootUpTime
            } catch {}
            foreach ($d in $defs) {
                $val = $null
                try { $val = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}
                $out.RegValues[$d.Name] = $val
            }
            return $out
        }
        $r.Reachable = $true
        $r.CPU       = [string]$remote.CPU
        $r.LastBoot  = $remote.LastBoot
        $r.RegValues = @{}
        foreach ($k in $remote.RegValues.Keys) { $r.RegValues[$k] = $remote.RegValues[$k] }
        $allMatch = $true; $anyMissing = $false; $anyDrift = $false
        foreach ($d in $Defs) {
            $cur = $r.RegValues[$d.Name]
            if ($null -ne $d.OrBits) {
                ## v6.5.20 OR-mode: compliant only if every required bit is
                ## already set. Missing value = not compliant; value present
                ## but missing a bit = drift (the apply will OR it in).
                $bits = [int]$d.OrBits
                if ($null -eq $cur) { $anyMissing = $true; $allMatch = $false }
                elseif (([int]$cur -band $bits) -ne $bits) { $anyDrift = $true; $allMatch = $false }
            } else {
                if ($null -eq $cur) { $anyMissing = $true; $allMatch = $false }
                elseif ([int]$cur -ne [int]$d.Expected) { $anyDrift = $true; $allMatch = $false }
            }
        }
        if ($allMatch)        { $r.Status = 'Patched' }
        elseif ($anyMissing)  { $r.Status = 'Vulnerable' }
        elseif ($anyDrift)    { $r.Status = 'Drifted' }
        else                  { $r.Status = 'Vulnerable' }
    } catch {
        $r.Error  = $_.Exception.Message
        $r.Status = 'Error'
    }
    return $r
}

## Per-host apply scriptblock. Writes expected values, reads them back,
## reports Success only if every readback matches.
$global:RegKeyApplyBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth, [string]$RegPath, [object[]]$Defs)
    $r = @{ Host=$Computer; Success=$false; PostValues=@{}; Error='' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $post = Invoke-Command -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -ArgumentList $RegPath, $Defs -EA Stop -ScriptBlock {
            param($p, $defs)
            if (-not (Test-Path $p)) { New-Item -Path $p -Force -EA Stop | Out-Null }
            foreach ($d in $defs) {
                $type = if ($d.Type) { $d.Type } else { 'DWord' }
                if ($null -ne $d.OrBits) {
                    ## v6.5.20 OR-mode: read current, bitwise-OR the required
                    ## bits, write back. Preserves any bits already set (e.g.
                    ## the Spectre/Meltdown bits in FeatureSettingsOverride)
                    ## instead of clobbering them with a flat Expected value.
                    $cur = $null
                    try { $cur = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}
                    $base = if ($null -ne $cur) { [int]$cur } else { 0 }
                    $newVal = $base -bor [int]$d.OrBits
                    Set-ItemProperty -Path $p -Name $d.Name -Value $newVal -Type $type -Force -EA Stop
                } else {
                    Set-ItemProperty -Path $p -Name $d.Name -Value $d.Expected -Type $type -Force -EA Stop
                }
            }
            $out = @{}
            foreach ($d in $defs) {
                $val = $null
                try { $val = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}
                $out[$d.Name] = $val
            }
            return $out
        }
        $r.PostValues = @{}
        foreach ($k in $post.Keys) { $r.PostValues[$k] = $post[$k] }
        $allMatch = $true
        foreach ($d in $Defs) {
            $cur = $r.PostValues[$d.Name]
            if ($null -ne $d.OrBits) {
                $bits = [int]$d.OrBits
                if ($null -eq $cur -or ([int]$cur -band $bits) -ne $bits) { $allMatch = $false; break }
            } else {
                if ($null -eq $cur -or [int]$cur -ne [int]$d.Expected) { $allMatch = $false; break }
            }
        }
        $r.Success = $allMatch
        if (-not $r.Success) { $r.Error = 'Post-write readback did not match expected values' }
    } catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}

## Combined notify-then-schedule-reboot scriptblock. Both run on the
## target in a single Invoke-Command so we don't spawn two separate
## jobs per host. Notify uses the same scheduled-task-as-logged-in-user
## pattern as the Remote Message tab (the only delivery path that works
## on hardened AFNET workstations -- msg.exe silently drops).
$global:RegKeyNotifyAndRebootBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth, [int]$DelaySeconds, [string]$Title, [string]$Body, [string]$Comment)
    $r = @{ Host=$Computer; NotifySent=$false; RebootScheduled=$false; ScheduledFor=$null; Error='' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $remote = Invoke-Command -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -ArgumentList $DelaySeconds, $Title, $Body, $Comment -EA Stop -ScriptBlock {
            param($d, $t, $b, $cmt)
            $o = @{ NotifySent=$false; RebootScheduled=$false; NotifyError=''; RebootError='' }
            ## Notify FIRST. If the notify path throws after a successful
            ## shutdown.exe, the user gets a silent reboot -- we want them
            ## warned even if the schedule call later fails.
            try {
                $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
                if (-not [string]::IsNullOrWhiteSpace($loggedIn)) {
                    New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                    $vbsName = "WPT_RegKeyMsg_$(Get-Random).vbs"; $vbsPath = "C:\Temp\$vbsName"
                    $vbsContent = 'Set oShell = CreateObject("Wscript.Shell")' + "`r`n" + 'oShell.Popup "' + ($b -replace '"','""') + '", 0, "' + ($t -replace '"','""') + '", 64' + "`r`n"
                    [System.IO.File]::WriteAllText($vbsPath, $vbsContent)
                    $taskName = "WPT_RegKeyMsg_$(Get-Random)"
                    $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
                    $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
                    $task = New-ScheduledTask -Action $action -Principal $principal
                    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -EA Stop | Out-Null
                    Start-ScheduledTask -TaskName $taskName -EA Stop
                    Start-Sleep -Seconds 3
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue
                    Start-Job -ScriptBlock { param($p); Start-Sleep -Seconds 120; Remove-Item $p -Force -EA SilentlyContinue } -ArgumentList $vbsPath | Out-Null
                    $o.NotifySent = $true
                }
            } catch { $o.NotifyError = $_.Exception.Message }
            try {
                & shutdown.exe /r /t $d /c $cmt /f
                if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1190) { throw "shutdown.exe exit $LASTEXITCODE" }
                $o.RebootScheduled = $true
            } catch { $o.RebootError = $_.Exception.Message }
            return $o
        }
        $r.NotifySent      = $remote.NotifySent
        $r.RebootScheduled = $remote.RebootScheduled
        if ($r.RebootScheduled) { $r.ScheduledFor = (Get-Date).AddSeconds($DelaySeconds) }
        $errs = @()
        if ($remote.RebootError) { $errs += "reboot: $($remote.RebootError)" }
        if ($remote.NotifyError) { $errs += "notify: $($remote.NotifyError)" }
        if ($errs.Count -gt 0) { $r.Error = ($errs -join '; ') }
    } catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}
#endregion

#region === TAB: REG KEY FIXES (v6.3.0 - Ninkxz/RegKeyFixes-BHI port) ===
$tabRegKey = New-Object System.Windows.Forms.TabPage; $tabRegKey.BackColor = $c.BG

## --- Top toolbar: fix selector + actions ---
$pnlRkBar = New-Object System.Windows.Forms.Panel
$pnlRkBar.Location = New-Object System.Drawing.Point(6, 6); $pnlRkBar.Size = New-Object System.Drawing.Size(1100, 40)
$pnlRkBar.BackColor = $c.Panel; $pnlRkBar.Anchor = 'Top,Left,Right'

$lblRkFix = New-Lbl -Text "Fix:" -X 10 -Y 12 -W 30
$script:ddlRkFix = New-Object System.Windows.Forms.ComboBox
$script:ddlRkFix.Location = New-Object System.Drawing.Point(40, 8); $script:ddlRkFix.Size = New-Object System.Drawing.Size(280, 24)
$script:ddlRkFix.BackColor = $c.Input; $script:ddlRkFix.ForeColor = $c.Cyan; $script:ddlRkFix.DropDownStyle = 'DropDownList'
foreach ($k in $global:RegKeyFixCatalog.Keys) { [void]$script:ddlRkFix.Items.Add($global:RegKeyFixCatalog[$k].DisplayName) }
if ($script:ddlRkFix.Items.Count -gt 0) { $script:ddlRkFix.SelectedIndex = 0 }
$script:btnRkScan   = New-Btn -Text "Scan All"          -X 326 -Y 6 -W 90  -H 28 -Bg $c.Success -Font $fn.BtnBig
$script:btnRkSelVul = New-Btn -Text "Select Vulnerable" -X 422 -Y 6 -W 130 -H 28 -Bg $c.PanelLight; $script:btnRkSelVul.Font = $fn.SmallB
$script:btnRkApply  = New-Btn -Text "Apply Selected"    -X 558 -Y 6 -W 130 -H 28 -Bg $c.Warning -Font $fn.BtnBig
$script:btnRkVerify = New-Btn -Text "Verify Selected"   -X 694 -Y 6 -W 130 -H 28 -Bg $c.PanelLight; $script:btnRkVerify.Font = $fn.SmallB
$script:btnRkExport = New-Btn -Text "Export CSV"        -X 830 -Y 6 -W 100 -H 28 -Bg $c.Accent
$pnlRkBar.Controls.AddRange(@($lblRkFix, $script:ddlRkFix, $script:btnRkScan, $script:btnRkSelVul, $script:btnRkApply, $script:btnRkVerify, $script:btnRkExport))

## --- Description + reboot option row ---
$pnlRkOpt = New-Object System.Windows.Forms.Panel
$pnlRkOpt.Location = New-Object System.Drawing.Point(6, 50); $pnlRkOpt.Size = New-Object System.Drawing.Size(1100, 30)
$pnlRkOpt.BackColor = [System.Drawing.Color]::FromArgb(16,16,30); $pnlRkOpt.Anchor = 'Top,Left,Right'
$script:lblRkDesc = New-Lbl -Text "" -X 10 -Y 6 -W 740 -Font $fn.Small -Fg $c.Dim
$script:chkRkReboot = New-Object System.Windows.Forms.CheckBox
$script:chkRkReboot.Text = "Auto-reboot 1 hour after apply (notify user)"
$script:chkRkReboot.Location = New-Object System.Drawing.Point(760, 4); $script:chkRkReboot.Size = New-Object System.Drawing.Size(330, 22)
$script:chkRkReboot.ForeColor = $c.Warning; $script:chkRkReboot.BackColor = [System.Drawing.Color]::FromArgb(16,16,30)
$script:chkRkReboot.Checked = $false
$pnlRkOpt.Controls.AddRange(@($script:lblRkDesc, $script:chkRkReboot))

$script:lblRkProg = New-Lbl -Text "Load targets on Targets tab, then Scan All." -X 6 -Y 86 -W 1100 -Font $fn.Small -Fg $c.Dim
$script:lblRkProg.Anchor = 'Top,Left,Right'

## --- Grid ---
$script:dgvRk = New-Object System.Windows.Forms.DataGridView
$script:dgvRk.Location = New-Object System.Drawing.Point(6, 110); $script:dgvRk.Size = New-Object System.Drawing.Size(1100, 380)
$script:dgvRk.Anchor = 'Top,Left,Right,Bottom'; $script:dgvRk.ReadOnly = $false
Style-Grid $script:dgvRk
$script:dgvRk.AutoSizeColumnsMode = 'None'; $script:dgvRk.ScrollBars = 'Both'
$colChkRk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colChkRk.Name = 'Sel'; $colChkRk.HeaderText = ''; $colChkRk.Width = 35
$colChkRk.TrueValue = $true; $colChkRk.FalseValue = $false
[void]$script:dgvRk.Columns.Add($colChkRk)
foreach ($col in @(@{N='Host';H='Host';W=160},@{N='Reachable';H='Up';W=55},@{N='CPU';H='CPU';W=240},@{N='Status';H='Status';W=110},@{N='Override';H='Override';W=90},@{N='Mask';H='Mask';W=60},@{N='LastBoot';H='Last Boot';W=110},@{N='LastAction';H='Last Action';W=200})) {
    $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; $cc.ReadOnly = $true
    [void]$script:dgvRk.Columns.Add($cc)
}
$script:dgvRk.Add_CurrentCellDirtyStateChanged({ if ($script:dgvRk.IsCurrentCellDirty) { $script:dgvRk.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })

## --- Log panel ---
$lblRkLogTitle = New-Lbl -Text "REG KEY FIXES LOG" -X 6 -Y 500 -W 200 -Font $fn.LabelB -Fg $c.Gold
$lblRkLogTitle.Anchor = 'Left,Bottom'
$script:rtbRkLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbRkLog.Location = New-Object System.Drawing.Point(6, 522); $script:rtbRkLog.Size = New-Object System.Drawing.Size(1100, 130)
$script:rtbRkLog.Anchor = 'Left,Right,Bottom'; $script:rtbRkLog.BackColor = $c.OutputBg
$script:rtbRkLog.ForeColor = $c.Console; $script:rtbRkLog.Font = $fn.Console
$script:rtbRkLog.ReadOnly = $true; $script:rtbRkLog.BorderStyle = 'None'

function RkLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbRkLog) {
        try {
            if (-not $script:rtbRkLog.IsHandleCreated) { $script:rtbRkLog.CreateControl() }
            $start = $script:rtbRkLog.TextLength
            $script:rtbRkLog.AppendText($line)
            $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
            $script:rtbRkLog.Select($start, $line.Length); $script:rtbRkLog.SelectionColor = $clr
            $script:rtbRkLog.SelectionLength = 0; $script:rtbRkLog.ScrollToCaret()
        } catch { try { $script:rtbRkLog.AppendText($line) } catch {} }
    }
    Log "[RegKey] $msg" $lvl
    [System.Windows.Forms.Application]::DoEvents()
}

## --- Helpers ---
$getActiveFixRk = {
    $sel = $script:ddlRkFix.SelectedItem
    foreach ($k in $global:RegKeyFixCatalog.Keys) {
        if ($global:RegKeyFixCatalog[$k].DisplayName -eq $sel) { return $global:RegKeyFixCatalog[$k] }
    }
    return $null
}.GetNewClosure()

$getDefsArrayRk = {
    param($fix)
    $arr = @()
    foreach ($n in $fix.Values.Keys) {
        ## v6.5.20: carry OrBits through to the scan/apply scriptblocks so
        ## a value def can opt into bitwise-OR mode (read current, OR the
        ## bits, write back) instead of the default flat-overwrite Expected
        ## mode. Used by the BHI fix so applying it preserves the existing
        ## Spectre/Meltdown bits in FeatureSettingsOverride.
        $arr += @{ Name=$n; Expected=$fix.Values[$n].Expected; Type=$fix.Values[$n].Type; OrBits=$fix.Values[$n].OrBits }
    }
    return ,$arr
}

$updateRkDesc = {
    $fix = & $getActiveFixRk
    if ($fix) { $script:lblRkDesc.Text = "$($fix.CVE) - $($fix.Description)" }
    else      { $script:lblRkDesc.Text = '' }
}.GetNewClosure()
$script:ddlRkFix.Add_SelectedIndexChanged({ & $updateRkDesc }.GetNewClosure())
& $updateRkDesc

$seedGridRk = {
    $script:dgvRk.Rows.Clear()
    foreach ($comp in $global:ComputerList) {
        $idx = $script:dgvRk.Rows.Add()
        $row = $script:dgvRk.Rows[$idx]
        $row.Cells['Sel'].Value        = $false
        $row.Cells['Host'].Value       = $comp
        $row.Cells['Reachable'].Value  = ''
        $row.Cells['CPU'].Value        = ''
        $row.Cells['Status'].Value     = 'Pending'
        $row.Cells['Override'].Value   = ''
        $row.Cells['Mask'].Value       = ''
        $row.Cells['LastBoot'].Value   = ''
        $row.Cells['LastAction'].Value = ''
    }
}.GetNewClosure()

$findRowRk = {
    param($hostname)
    foreach ($row in $script:dgvRk.Rows) {
        if ([string]$row.Cells['Host'].Value -eq [string]$hostname) { return $row }
    }
    return $null
}.GetNewClosure()

$paintScanRk = {
    param($res, $fix)
    $row = & $findRowRk $res.Host
    if (-not $row) { return }
    if (-not $res.Reachable) {
        $row.Cells['Reachable'].Value = 'No'; $row.Cells['Reachable'].Style.ForeColor = $c.Danger
        $row.Cells['Status'].Value = 'Unreachable'; $row.Cells['Status'].Style.ForeColor = $c.Danger
        $row.Cells['LastAction'].Value = $res.Error
        return
    }
    $row.Cells['Reachable'].Value = 'Yes'; $row.Cells['Reachable'].Style.ForeColor = $c.Success
    $row.Cells['CPU'].Value = $res.CPU
    $vNames = @($fix.Values.Keys)
    if ($vNames.Count -ge 1) { $row.Cells['Override'].Value = $res.RegValues[$vNames[0]] }
    if ($vNames.Count -ge 2) { $row.Cells['Mask'].Value     = $res.RegValues[$vNames[1]] }
    if ($res.LastBoot) {
        try { $row.Cells['LastBoot'].Value = ([datetime]$res.LastBoot).ToString('MM-dd HH:mm') }
        catch { $row.Cells['LastBoot'].Value = [string]$res.LastBoot }
    }
    switch ($res.Status) {
        'Patched'    { $row.Cells['Status'].Value = 'Patched';    $row.Cells['Status'].Style.ForeColor = $c.Success }
        'Vulnerable' { $row.Cells['Status'].Value = 'Vulnerable'; $row.Cells['Status'].Style.ForeColor = $c.Danger  }
        'Drifted'    { $row.Cells['Status'].Value = 'Drifted';    $row.Cells['Status'].Style.ForeColor = $c.Warning }
        default      { $row.Cells['Status'].Value = $res.Status;  $row.Cells['Status'].Style.ForeColor = $c.Dim     }
    }
}.GetNewClosure()

$disableRkBtns = {
    $script:btnRkScan.Enabled = $false; $script:btnRkApply.Enabled = $false
    $script:btnRkVerify.Enabled = $false; $script:btnRkSelVul.Enabled = $false
    $script:ddlRkFix.Enabled = $false
}.GetNewClosure()
$enableRkBtns = {
    $script:btnRkScan.Enabled = $true; $script:btnRkApply.Enabled = $true
    $script:btnRkVerify.Enabled = $true; $script:btnRkSelVul.Enabled = $true
    $script:ddlRkFix.Enabled = $true
}.GetNewClosure()

## --- Scan / Verify (same scriptblock; just different button + log tag) ---
$runScanRk = {
    param([string[]]$hostsToScan, [string]$logTag)
    $fix = & $getActiveFixRk
    if (-not $fix) { return }
    if (-not $global:Credentials) {
        [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials") | Out-Null; return
    }
    if ($hostsToScan.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing to scan.","Nothing to do") | Out-Null; return
    }
    & $disableRkBtns
    Initialize-RunspacePool
    $defs = & $getDefsArrayRk $fix
    $script:RkScanFix = $fix; $script:RkScanLogTag = $logTag
    $script:RkScanJobs = @{}
    foreach ($comp in $hostsToScan) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:RegKeyScanBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($global:AuthMethod).AddArgument($fix.RegPath).AddArgument($defs)
        $script:RkScanJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() }
    }
    $script:RkScanTotal = $script:RkScanJobs.Count
    $script:lblRkProg.Text = "$logTag : 0 / $($script:RkScanTotal)"
    $script:lblRkProg.ForeColor = $c.Warning
    RkLog "=== $logTag ($($fix.DisplayName)) on $($script:RkScanTotal) host(s) ==="
    $script:RkScanTimer = New-Object System.Windows.Forms.Timer
    $script:RkScanTimer.Interval = 600
    $script:RkScanTickBusy = $false
    $script:RkScanTimer.Add_Tick({
        if ($script:RkScanTickBusy) { return }
        $script:RkScanTickBusy = $true
        try {
        foreach ($key in @($script:RkScanJobs.Keys)) {
            $job = $script:RkScanJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Reachable=$false; Error=$_.ToString(); Status='Error' } }
            $script:RkScanJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            & $paintScanRk $res $script:RkScanFix
            if ($res.Error) { RkLog "  $($res.Host): $($res.Error)" 'ERR' }
            else            { RkLog "  $($res.Host): $($res.Status)" }
        }
        $done = $script:RkScanTotal - $script:RkScanJobs.Count
        $script:lblRkProg.Text = "$($script:RkScanLogTag) : $done / $($script:RkScanTotal)"
        if ($script:RkScanJobs.Count -eq 0) {
            if ($null -ne $script:RkScanTimer) { $script:RkScanTimer.Stop(); $script:RkScanTimer.Dispose(); $script:RkScanTimer = $null }
            & $enableRkBtns
            $script:lblRkProg.Text = "$($script:RkScanLogTag) complete: $($script:RkScanTotal) host(s)"
            $script:lblRkProg.ForeColor = $c.Success
            RkLog "=== $($script:RkScanLogTag) complete ===" 'OK'
        }
        } finally { $script:RkScanTickBusy = $false }
    })
    $script:RkScanTimer.Start()
}.GetNewClosure()

$script:btnRkScan.Add_Click({
    & $seedGridRk
    & $runScanRk @($global:ComputerList) 'Scanning'
}.GetNewClosure())

$script:btnRkSelVul.Add_Click({
    $count = 0
    foreach ($row in $script:dgvRk.Rows) {
        $st = [string]$row.Cells['Status'].Value
        $isVul = ($st -eq 'Vulnerable' -or $st -eq 'Drifted')
        $row.Cells['Sel'].Value = $isVul
        if ($isVul) { $count++ }
    }
    RkLog "Selected $count vulnerable/drifted host(s)"
})

$script:btnRkVerify.Add_Click({
    $hosts = @()
    foreach ($row in $script:dgvRk.Rows) {
        if ($row.Cells['Sel'].Value -eq $true) { $hosts += [string]$row.Cells['Host'].Value }
    }
    if ($hosts.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Tick the rows you want to verify.","Nothing selected") | Out-Null
        return
    }
    & $runScanRk $hosts 'Verifying'
}.GetNewClosure())

## --- Apply (with optional auto-reboot chain) ---
$script:btnRkApply.Add_Click({
    $fix = & $getActiveFixRk
    if (-not $fix) { return }
    if (-not $global:Credentials) {
        [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials") | Out-Null; return
    }
    $hosts = @()
    foreach ($row in $script:dgvRk.Rows) {
        if ($row.Cells['Sel'].Value -eq $true) { $hosts += [string]$row.Cells['Host'].Value }
    }
    if ($hosts.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Tick the rows you want to fix.","Nothing selected") | Out-Null
        return
    }
    $rebootMsg = if ($script:chkRkReboot.Checked) { "`n`nAUTO-REBOOT IS ON: each host will pop a notice and reboot 1 hour after apply." } else { '' }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Apply $($fix.DisplayName) to $($hosts.Count) host(s)?$rebootMsg","Confirm Apply",4,48)
    if ($confirm -ne 'Yes') { return }

    & $disableRkBtns
    Initialize-RunspacePool
    foreach ($h in $hosts) {
        $row = & $findRowRk $h
        if ($row) { $row.Cells['LastAction'].Value = 'Applying...'; $row.Cells['LastAction'].Style.ForeColor = $c.Warning }
    }
    RkLog "=== Apply $($fix.DisplayName) on $($hosts.Count) host(s); auto-reboot=$($script:chkRkReboot.Checked) ==="
    Write-AuditLog -Action "RegKeyApply" -Result "Started" -Detail "$($fix.CVE) on $($hosts.Count) targets"
    $defs = & $getDefsArrayRk $fix
    $script:RkApplyJobs = @{}
    $script:RkApplyOk = 0; $script:RkApplyFail = 0
    $script:RkApplyFix = $fix
    $script:RkApplyDoReboot = $script:chkRkReboot.Checked
    $script:RkPostJobs = @{}
    foreach ($comp in $hosts) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:RegKeyApplyBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($global:AuthMethod).AddArgument($fix.RegPath).AddArgument($defs)
        $script:RkApplyJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() }
    }
    $script:RkApplyTotal = $script:RkApplyJobs.Count
    $script:lblRkProg.Text = "Applying: 0 / $($script:RkApplyTotal)"; $script:lblRkProg.ForeColor = $c.Warning
    $script:RkApplyTimer = New-Object System.Windows.Forms.Timer
    $script:RkApplyTimer.Interval = 600
    $script:RkApplyTickBusy = $false
    $script:RkApplyTimer.Add_Tick({
        if ($script:RkApplyTickBusy) { return }
        $script:RkApplyTickBusy = $true
        try {
        ## Drain Apply jobs
        foreach ($key in @($script:RkApplyJobs.Keys)) {
            $job = $script:RkApplyJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Success=$false; Error=$_.ToString() } }
            $script:RkApplyJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = & $findRowRk $res.Host
            if ($res.Success) {
                $script:RkApplyOk++
                if ($row) {
                    $row.Cells['LastAction'].Value = 'Applied (pending boot)'
                    $row.Cells['LastAction'].Style.ForeColor = $c.Success
                    $row.Cells['Status'].Value = 'Patched'
                    $row.Cells['Status'].Style.ForeColor = $c.Success
                    $vNames = @($script:RkApplyFix.Values.Keys)
                    if ($vNames.Count -ge 1) { $row.Cells['Override'].Value = $res.PostValues[$vNames[0]] }
                    if ($vNames.Count -ge 2) { $row.Cells['Mask'].Value     = $res.PostValues[$vNames[1]] }
                }
                RkLog "  $($res.Host): applied OK" 'OK'
                Track-Action -Action 'RegKeyApply' -Target $res.Host -Result 'OK' -Detail $script:RkApplyFix.CVE
                if ($script:RkApplyDoReboot) {
                    $rebootAt = (Get-Date).AddHours(1).ToString('HH:mm')
                    $body = "Your device will reboot at approximately $rebootAt to apply a security mitigation ($($script:RkApplyFix.CVE)). Please save your work."
                    $title = 'Scheduled Reboot Notice'
                    $cmt = "WPT: $($script:RkApplyFix.CVE) reboot scheduled. Save your work."
                    try {
                        $ps2 = [PowerShell]::Create(); $ps2.RunspacePool = $script:RSPool
                        [void]$ps2.AddScript($global:RegKeyNotifyAndRebootBlock).AddArgument($res.Host).AddArgument($global:Credentials).AddArgument($global:AuthMethod).AddArgument(3600).AddArgument($title).AddArgument($body).AddArgument($cmt)
                        $script:RkPostJobs["rb-$($res.Host)"] = @{ PS=$ps2; Handle=$ps2.BeginInvoke() }
                    } catch { RkLog "  $($res.Host): could not schedule reboot job - $($_.Exception.Message)" 'ERR' }
                }
            } else {
                $script:RkApplyFail++
                if ($row) {
                    $row.Cells['LastAction'].Value = "Apply failed: $($res.Error)"
                    $row.Cells['LastAction'].Style.ForeColor = $c.Danger
                }
                RkLog "  $($res.Host): apply FAILED - $($res.Error)" 'ERR'
                Track-Action -Action 'RegKeyApply' -Target $res.Host -Result 'Fail' -Detail $res.Error
            }
        }
        ## Drain post-apply jobs (combined notify + scheduled reboot)
        foreach ($key in @($script:RkPostJobs.Keys)) {
            $job = $script:RkPostJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key.Substring(3); RebootScheduled=$false; NotifySent=$false; Error=$_.ToString() } }
            $script:RkPostJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = & $findRowRk $res.Host
            if ($res.RebootScheduled) {
                if ($row) {
                    $row.Cells['LastAction'].Value = "Reboot @ $($res.ScheduledFor.ToString('HH:mm'))"
                    $row.Cells['LastAction'].Style.ForeColor = $c.Warning
                }
                $sentTxt = if ($res.NotifySent) { 'notified' } else { 'NOT notified' }
                RkLog "  $($res.Host): reboot scheduled for $($res.ScheduledFor.ToString('HH:mm')) ($sentTxt)" 'OK'
            } else {
                RkLog "  $($res.Host): reboot/notify FAILED - $($res.Error)" 'ERR'
            }
        }
        $applyDone = $script:RkApplyTotal - $script:RkApplyJobs.Count
        $postLeft  = $script:RkPostJobs.Count
        $tail = if ($postLeft -gt 0) { " (post: $postLeft)" } else { '' }
        $script:lblRkProg.Text = "Applying: $applyDone / $($script:RkApplyTotal)$tail"
        if ($script:RkApplyJobs.Count -eq 0 -and $script:RkPostJobs.Count -eq 0) {
            if ($null -ne $script:RkApplyTimer) { $script:RkApplyTimer.Stop(); $script:RkApplyTimer.Dispose(); $script:RkApplyTimer = $null }
            & $enableRkBtns
            $summary = "Apply complete: $($script:RkApplyOk) ok, $($script:RkApplyFail) failed"
            $script:lblRkProg.Text = $summary
            $script:lblRkProg.ForeColor = if ($script:RkApplyFail -eq 0) { $c.Success } else { $c.Warning }
            RkLog "=== $summary ===" 'OK'
        }
        } finally { $script:RkApplyTickBusy = $false }
    })
    $script:RkApplyTimer.Start()
}.GetNewClosure())

$script:btnRkExport.Add_Click({
    if ($script:dgvRk.Rows.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV|*.csv'
    $sfd.FileName = "WPT_RegKeyFixes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq 'OK') {
        $rows = foreach ($row in $script:dgvRk.Rows) {
            [pscustomobject]@{
                Host       = $row.Cells['Host'].Value
                Reachable  = $row.Cells['Reachable'].Value
                CPU        = $row.Cells['CPU'].Value
                Status     = $row.Cells['Status'].Value
                Override   = $row.Cells['Override'].Value
                Mask       = $row.Cells['Mask'].Value
                LastBoot   = $row.Cells['LastBoot'].Value
                LastAction = $row.Cells['LastAction'].Value
            }
        }
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation
        RkLog "Exported $($script:dgvRk.Rows.Count) row(s) to $($sfd.FileName)" 'OK'
    }
})

$tabRegKey.Add_Enter({
    ## Re-seed the grid if the targets list size changed since last visit.
    if ($script:dgvRk.Rows.Count -ne $global:ComputerList.Count) { & $seedGridRk }
}.GetNewClosure())
$tabRegKey.Controls.AddRange(@($pnlRkBar, $pnlRkOpt, $script:lblRkProg, $script:dgvRk, $lblRkLogTitle, $script:rtbRkLog))
#endregion

###############################################################################
###                          TAB 4: ACTIVITY LOG                            ###
###############################################################################
## Read-only live log mirror. Every Log "..." call anywhere in the tool
## appends a timestamped line here, color-coded by level (OK=green,
## WARN=amber, ERR=red, default=console green). The same content also
## goes to the on-disk audit log ($global:AuditLogPath). Useful for
## verifying what happened end-to-end without stitching together per-
## tab sub-logs.
#region === TAB 4: ACTIVITY LOG ===
$tabLog = New-Object System.Windows.Forms.TabPage; $tabLog.BackColor = $c.BG
$lblLogTitle = New-Lbl -Text "LOGS" -X 10 -Y 8 -W 200 -Font $fn.LabelB -Fg $c.Gold
$script:rtbLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbLog.Location = New-Object System.Drawing.Point(6, 30); $script:rtbLog.Size = New-Object System.Drawing.Size(1100, 620); $script:rtbLog.Anchor = 'Top,Left,Right,Bottom'
$script:rtbLog.BackColor = $c.OutputBg; $script:rtbLog.ForeColor = $c.Console; $script:rtbLog.Font = $fn.Console; $script:rtbLog.ReadOnly = $true; $script:rtbLog.BorderStyle = 'FixedSingle'
## v6.1.8: explicit ForcedVertical scrollbar (RichTextBox default is Both,
## but the default only shows scrollbars when needed -- combined with the
## anchor-offset bug that made this control physically 2700px wide, the
## scrollbar was being positioned beyond the visible tab edge. Forcing it
## gives a belt-and-suspenders guarantee alongside the Shown anchor fix.
$script:rtbLog.ScrollBars = 'ForcedVertical'; $script:rtbLog.WordWrap = $true
$tabLog.Controls.AddRange(@($lblLogTitle, $script:rtbLog))
#endregion

###############################################################################
###                        TAB 5: SCCM APP MANAGER                          ###
###############################################################################
## Per-host MECM CCM_Application query + action driver. Pick a
## workstation (dropdown populated from $global:ComputerList); Query
## Apps pulls the full CCM_Application inventory with InstallState /
## EvalState / ApplicabilityState / Version / Progress, color-coded by
## state. Quick filter: Chrome / Edge / M365 / Teams / Tanium.
## Per-row actions: Install / Uninstall / Reinstall / Repair - each
## runs the corresponding CCM_Application method via Invoke-CimMethod.
## Reinstall = Uninstall + 10s wait + Install.
#region === TAB 5: SCCM APP MANAGER ===
$tabAppMgr = New-Object System.Windows.Forms.TabPage; $tabAppMgr.BackColor = $c.BG
$pnlAmBar = New-Object System.Windows.Forms.Panel; $pnlAmBar.Location = New-Object System.Drawing.Point(6,6); $pnlAmBar.Size = New-Object System.Drawing.Size(1100,42); $pnlAmBar.BackColor = $c.Panel; $pnlAmBar.Anchor = 'Top,Left,Right'
$lblAmHost = New-Lbl -Text "Workstation:" -X 10 -Y 12 -W 85
$script:ddlAmHost = New-Object System.Windows.Forms.ComboBox; $script:ddlAmHost.Location = New-Object System.Drawing.Point(100,8); $script:ddlAmHost.Size = New-Object System.Drawing.Size(500,24); $script:ddlAmHost.BackColor = $c.Input; $script:ddlAmHost.ForeColor = $c.Cyan; $script:ddlAmHost.DropDownStyle = 'DropDownList'
$btnAmQuery = New-Btn -Text "Query Apps" -X 610 -Y 6 -W 120 -H 28 -Bg $c.Accent -Font $fn.BtnBig
$script:lblAmHostSt = New-Lbl -Text "Select a workstation and click Query Apps" -X 740 -Y 12 -W 540 -Font $fn.Small -Fg $c.Dim
$pnlAmBar.Controls.AddRange(@($lblAmHost, $script:ddlAmHost, $btnAmQuery, $script:lblAmHostSt))
$script:lblAmCount = New-Lbl -Text "" -X 350 -Y 54 -W 500 -Font $fn.SmallB -Fg $c.Dim
$lblAmFilter = New-Lbl -Text "Quick Filter:" -X 10 -Y 54 -W 85 -Font $fn.LabelB -Fg $c.Gold
$script:ddlAmFilter = New-Object System.Windows.Forms.ComboBox; $script:ddlAmFilter.Location = New-Object System.Drawing.Point(100, 50); $script:ddlAmFilter.Size = New-Object System.Drawing.Size(240, 24); $script:ddlAmFilter.BackColor = $c.Input; $script:ddlAmFilter.ForeColor = $c.White; $script:ddlAmFilter.DropDownStyle = 'DropDownList'; $script:ddlAmFilter.Font = $fn.Label
[void]$script:ddlAmFilter.Items.AddRange(@("All Applications","Chrome","Edge","Microsoft 365","Microsoft Teams","Tanium")); $script:ddlAmFilter.SelectedIndex = 0
$script:AllAppsCache = @()
function Populate-AppGrid { param([string]$FilterKey = "All Applications")
    $script:dgvApps.Rows.Clear(); $appsToShow = $script:AllAppsCache
    if ($FilterKey -ne "All Applications" -and -not [string]::IsNullOrWhiteSpace($FilterKey)) { $appsToShow = @($script:AllAppsCache | Where-Object { $_.Name -like "*$FilterKey*" }) }
    $installed = 0; $notInstalled = 0
    foreach ($app in $appsToShow) { $idx = $script:dgvApps.Rows.Add(); $row = $script:dgvApps.Rows[$idx]
        $row.Cells['Name'].Value = $app.Name; $row.Cells['InstallState'].Value = $app.InstallState; $row.Cells['Applicable'].Value = $app.ApplicabilityState; $row.Cells['Version'].Value = $app.SoftwareVersion; $row.Cells['Result'].Value = "--"
        $row.Tag = @{ Id=$app.Id; Revision=$app.Revision; IsMachineTarget=$app.IsMachineTarget }
        $evalText = $script:EvalMap[[int]$app.EvaluationState]; if ([string]::IsNullOrWhiteSpace($evalText)) { $evalText = "Unknown ($($app.EvaluationState))" }
        $row.Cells['EvalState'].Value = $evalText; $row.Cells['Pct'].Value = "$($app.PercentComplete)%"
        $evalClr = Get-EvalColor -state ([int]$app.EvaluationState); $row.Cells['EvalState'].Style.ForeColor = $evalClr; $row.Cells['Pct'].Style.ForeColor = $evalClr
        if ($app.InstallState -eq 'Installed') { $row.Cells['InstallState'].Style.ForeColor = $c.Success; $installed++ } elseif ($app.InstallState -eq 'NotInstalled') { $row.Cells['InstallState'].Style.ForeColor = $c.Warning; $notInstalled++ } else { $row.Cells['InstallState'].Style.ForeColor = $c.Cyan }
    }
    $total = $script:AllAppsCache.Count; $showing = $appsToShow.Count
    if ($FilterKey -eq "All Applications") { $script:lblAmCount.Text = "$installed installed, $notInstalled not installed, $total total" } else { $script:lblAmCount.Text = "Showing $showing of $total (filter: $FilterKey)" }
}
$script:ddlAmFilter.Add_SelectedIndexChanged({ if ($script:AllAppsCache.Count -eq 0) { return }; Populate-AppGrid -FilterKey $script:ddlAmFilter.SelectedItem.ToString() })
$script:dgvApps = New-Object System.Windows.Forms.DataGridView; $script:dgvApps.Location = New-Object System.Drawing.Point(6, 74); $script:dgvApps.Size = New-Object System.Drawing.Size(1100, 340)
$script:dgvApps.Anchor = 'Top,Left,Right'; $script:dgvApps.ReadOnly = $true; Style-Grid $script:dgvApps; $script:dgvApps.AutoSizeColumnsMode = 'None'; $script:dgvApps.ScrollBars = 'Both'
foreach ($col in @(@{N='Name';H='Application';W=260},@{N='InstallState';H='State';W=85},@{N='Applicable';H='Appl';W=75},@{N='EvalState';H='Eval';W=130},@{N='Pct';H='%';W=45},@{N='Version';H='Ver';W=80},@{N='Result';H='Result';W=140})) { $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvApps.Columns.Add($cc) }
$pnlAmActions = New-Object System.Windows.Forms.Panel; $pnlAmActions.Location = New-Object System.Drawing.Point(6,420); $pnlAmActions.Size = New-Object System.Drawing.Size(1100,38); $pnlAmActions.Anchor = 'Top,Left,Right'; $pnlAmActions.BackColor = $c.Panel
$btnAmInstall2 = New-Btn -Text "Install" -X 6 -Y 4 -W 100 -H 28 -Bg $c.Success; $btnAmUninstall2 = New-Btn -Text "Uninstall" -X 114 -Y 4 -W 100 -H 28 -Bg $c.Danger
$btnAmReinstall2 = New-Btn -Text "Reinstall" -X 222 -Y 4 -W 100 -H 28 -Bg $c.Warning; $btnAmRepair2 = New-Btn -Text "Repair" -X 330 -Y 4 -W 90 -H 28 -Bg $c.Purple
$btnAmQueryFull = New-Btn -Text "Full Query" -X 560 -Y 4 -W 110 -H 28 -Bg $c.Accent; $btnAmRefreshSt = New-Btn -Text "Refresh Status" -X 678 -Y 4 -W 125 -H 28 -Bg $c.Cyan
$pnlAmActions.Controls.AddRange(@($btnAmInstall2, $btnAmUninstall2, $btnAmReinstall2, $btnAmRepair2, $btnAmQueryFull, $btnAmRefreshSt))
$lblAmLogTitle = New-Lbl -Text "APP MANAGER LOG" -X 10 -Y 462 -W 200 -Font $fn.LabelB -Fg $c.Gold
$script:rtbAmLog = New-Object System.Windows.Forms.RichTextBox; $script:rtbAmLog.Location = New-Object System.Drawing.Point(6, 480); $script:rtbAmLog.Size = New-Object System.Drawing.Size(1100, 130)
$script:rtbAmLog.Anchor = 'Left,Right,Bottom'; $script:rtbAmLog.BackColor = $c.OutputBg; $script:rtbAmLog.ForeColor = $c.Console; $script:rtbAmLog.Font = $fn.Console; $script:rtbAmLog.ReadOnly = $true; $script:rtbAmLog.BorderStyle = 'None'; $script:rtbAmLog.WordWrap = $false; $script:rtbAmLog.ScrollBars = 'Vertical'
function AmLog($msg, $lvl = 'INFO') { $ts = (Get-Date).ToString("HH:mm:ss"); $line = "[$ts] $msg`r`n"; if ($null -ne $script:rtbAmLog) { try { if (-not $script:rtbAmLog.IsHandleCreated) { $script:rtbAmLog.CreateControl() }; $script:rtbAmLog.AppendText($line) } catch {} }; Log "[AppMgr] $msg" $lvl; [System.Windows.Forms.Application]::DoEvents() }
$script:EvalMap = @{0='None';1='Available';2='Submitted';3='Detecting';4='PreDownload';5='Downloading';6='Wait Install';7='Installing';8='Pend Soft Reboot';9='Pend Hard Reboot';10='Wait Reboot';11='Verifying';12='Install Complete';13='Error';14='Wait Window';15='Wait Logon';16='Wait Logoff';17='Wait Reconnect';18='Pend User Logoff';19='Pend Logoff';20='Pend Update';21='Wait Retry';22='Wait Presentation Off';23='Wait Orchestration';24='Download Failed';25='PreDownload Failed';26='Download OK';27='Post-Enforce Eval';28='Wait Network'}
function Get-EvalColor([int]$state) { switch ($state) { { $_ -in 12,1 } { return $c.Success }; { $_ -in 13,24,25 } { return $c.Danger }; { $_ -in 5,6,7,11 } { return $c.Cyan }; { $_ -in 8,9,10 } { return $c.Warning }; default { return $c.Dim } } }
function Query-HostApps {
    $target = $script:ddlAmHost.SelectedItem; if ([string]::IsNullOrWhiteSpace($target)) { AmLog "No workstation selected." 'WARN'; return }
    if (-not $global:Credentials) { AmLog "No credentials set." 'WARN'; return }; $auth = "Negotiate"
    $script:dgvApps.Rows.Clear(); $script:AllAppsCache = @(); $script:lblAmHostSt.Text = "Querying $target..."; $script:lblAmHostSt.ForeColor = $c.Cyan; [System.Windows.Forms.Application]::DoEvents()
    AmLog "Querying MECM applications on $target..."
    try { $sess = New-PSSession -ComputerName $target -Credential $global:Credentials -Authentication $auth -SessionOption $global:WSManOpt -EA Stop
        try { $apps = Invoke-Command -Session $sess -EA Stop -ScriptBlock { @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop | Select-Object Name, InstallState, ApplicabilityState, EvaluationState, PercentComplete, Id, Revision, IsMachineTarget, SoftwareVersion) }
            $script:AllAppsCache = @($apps | Sort-Object Name); $script:ddlAmFilter.SelectedIndex = 0; Populate-AppGrid -FilterKey "All Applications"
            $script:lblAmHostSt.Text = "$($script:AllAppsCache.Count) app(s) on $target"; $script:lblAmHostSt.ForeColor = $c.Success
            AmLog "Found $($script:AllAppsCache.Count) app(s) on $target" 'OK'
        } finally { Remove-PSSession $sess -EA SilentlyContinue }
    } catch { $script:lblAmHostSt.Text = "Query failed: $($_.Exception.Message)"; $script:lblAmHostSt.ForeColor = $c.Danger; AmLog "Could not query ${target}: $($_.Exception.Message)" 'ERR' }
}
function Refresh-AppStatus {
    $target = $script:ddlAmHost.SelectedItem; if ([string]::IsNullOrWhiteSpace($target) -or $script:AllAppsCache.Count -eq 0 -or -not $global:Credentials) { return }; $auth = "Negotiate"
    $script:lblAmHostSt.Text = "Refreshing $target..."; $script:lblAmHostSt.ForeColor = $c.Cyan; [System.Windows.Forms.Application]::DoEvents()
    try { $sess = New-PSSession -ComputerName $target -Credential $global:Credentials -Authentication $auth -SessionOption $global:WSManOpt -EA Stop
        try { $freshApps = Invoke-Command -Session $sess -EA Stop -ScriptBlock { @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop | Select-Object Name, InstallState, ApplicabilityState, EvaluationState, PercentComplete, Id, Revision, IsMachineTarget, SoftwareVersion) }
            $script:AllAppsCache = @($freshApps | Sort-Object Name); $currentFilter = $script:ddlAmFilter.SelectedItem.ToString(); Populate-AppGrid -FilterKey $currentFilter
            $script:lblAmHostSt.Text = "Refreshed"; $script:lblAmHostSt.ForeColor = $c.Success; AmLog "Refreshed app status on $target" 'OK'
        } finally { Remove-PSSession $sess -EA SilentlyContinue }
    } catch { $script:lblAmHostSt.Text = "Refresh failed"; $script:lblAmHostSt.ForeColor = $c.Danger; AmLog "Could not refresh ${target}: $($_.Exception.Message)" 'ERR' }
}
function Invoke-AppAction { param([string]$Action)
    $target = $script:ddlAmHost.SelectedItem; if ([string]::IsNullOrWhiteSpace($target) -or -not $global:Credentials) { return }
    if ($script:dgvApps.SelectedRows.Count -eq 0) { AmLog "No apps selected." 'WARN'; return }; $auth = "Negotiate"
    $selectedApps = @(); foreach ($row in $script:dgvApps.SelectedRows) { if ($null -ne $row.Tag) { $selectedApps += @{ Name=$row.Cells['Name'].Value; Row=$row; Meta=$row.Tag } } }
    if ($selectedApps.Count -eq 0) { return }; $appNames = ($selectedApps | ForEach-Object { $_.Name }) -join "`n  "
    $confirm = [System.Windows.Forms.MessageBox]::Show("$Action $($selectedApps.Count) app(s) on ${target}?`n`n  $appNames","Confirm $Action",4,48); if ($confirm -ne 'Yes') { return }
    AmLog "========================================"; AmLog "$Action -- $($selectedApps.Count) app(s) on $target"
    try { $sess = New-PSSession -ComputerName $target -Credential $global:Credentials -Authentication $auth -SessionOption $global:WSManOpt -EA Stop
        try { foreach ($app in $selectedApps) { $app.Row.Cells['Result'].Value = "Running..."; $app.Row.Cells['Result'].Style.ForeColor = $c.Warning; [System.Windows.Forms.Application]::DoEvents()
            $appId = $app.Meta.Id; $appRev = $app.Meta.Revision; $appMachine = $app.Meta.IsMachineTarget
            if ($Action -eq 'Reinstall') {
                AmLog "  $($app.Name) : Uninstalling..."; $app.Row.Cells['Result'].Value = "Uninstalling..."; [System.Windows.Forms.Application]::DoEvents()
                try { Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine -EA Stop -ScriptBlock { param($id,$rev,$machine); $p = @{EnforcePreference=[UINT32]0;Id=$id;IsMachineTarget=[System.Convert]::ToBoolean($machine);IsRebootIfNeeded=$false;Priority='High';Revision=$rev}; Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Uninstall -Arguments $p -EA Stop | Out-Null }; AmLog "  $($app.Name) : Uninstall sent, waiting 10s..." 'OK'; Start-Sleep -Seconds 10 } catch { AmLog "  $($app.Name) : Uninstall error: $($_.Exception.Message)" 'ERR' }
                AmLog "  $($app.Name) : Installing..."; $app.Row.Cells['Result'].Value = "Installing..."; [System.Windows.Forms.Application]::DoEvents()
                try { Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine -EA Stop -ScriptBlock { param($id,$rev,$machine); $p = @{EnforcePreference=[UINT32]0;Id=$id;IsMachineTarget=[System.Convert]::ToBoolean($machine);IsRebootIfNeeded=$false;Priority='High';Revision=$rev}; Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Install -Arguments $p -EA Stop | Out-Null }
                    $app.Row.Cells['Result'].Value = "Reinstall sent"; $app.Row.Cells['Result'].Style.ForeColor = $c.Success; AmLog "  $($app.Name) : Reinstall sent" 'OK'
                } catch { $app.Row.Cells['Result'].Value = "Install failed"; $app.Row.Cells['Result'].Style.ForeColor = $c.Danger; AmLog "  $($app.Name) : Install error: $($_.Exception.Message)" 'ERR' }
            } else {
                try { Invoke-Command -Session $sess -ArgumentList $appId, $appRev, $appMachine, $Action -EA Stop -ScriptBlock { param($id,$rev,$machine,$method); $p = @{EnforcePreference=[UINT32]0;Id=$id;IsMachineTarget=[System.Convert]::ToBoolean($machine);IsRebootIfNeeded=$false;Priority='High';Revision=$rev}; Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName $method -Arguments $p -EA Stop | Out-Null }
                    $app.Row.Cells['Result'].Value = "$Action sent"; $app.Row.Cells['Result'].Style.ForeColor = $c.Success; AmLog "  $($app.Name) : $Action sent" 'OK'
                } catch { $app.Row.Cells['Result'].Value = "$Action failed"; $app.Row.Cells['Result'].Style.ForeColor = $c.Danger; AmLog "  $($app.Name) : $Action error: $($_.Exception.Message)" 'ERR' }
            }
            Track-Action -Action $Action -Target $target -Result $app.Row.Cells['Result'].Value -Detail $app.Name
            if (($Action -eq 'Uninstall' -or $Action -eq 'Reinstall') -and $app.Name -like '*Tanium*') {
                AmLog "Tanium detected -- cleaning registry on $target..."
                try { Invoke-Command -Session $sess -EA Stop -ScriptBlock { $regPath = 'HKLM:\SOFTWARE\WOW6432Node\Tanium'; if (Test-Path $regPath) { Remove-Item -Path $regPath -Recurse -Force -EA Stop; return 'Deleted' } else { return 'NotFound' } } | ForEach-Object { if ($_ -eq 'Deleted') { AmLog "Registry key removed on $target" 'OK' } else { AmLog "Registry key not found (already clean)" 'OK' } } } catch { AmLog "Registry cleanup FAILED: $($_.Exception.Message)" 'ERR' }
            }
        } } finally { Remove-PSSession $sess -EA SilentlyContinue }
    } catch { AmLog "Could not connect to ${target}: $($_.Exception.Message)" 'ERR' }
    AmLog "========================================"; AmLog "$Action complete on $target" 'OK'; AmLog "========================================"
}
$btnAmQuery.Add_Click({ Query-HostApps }); $btnAmQueryFull.Add_Click({ Query-HostApps }); $btnAmRefreshSt.Add_Click({ Refresh-AppStatus })
$btnAmInstall2.Add_Click({ Invoke-AppAction -Action "Install" }); $btnAmUninstall2.Add_Click({ Invoke-AppAction -Action "Uninstall" })
$btnAmReinstall2.Add_Click({ Invoke-AppAction -Action "Reinstall" }); $btnAmRepair2.Add_Click({ Invoke-AppAction -Action "Repair" })
$tabAppMgr.Add_Enter({ $script:ddlAmHost.Items.Clear(); foreach ($comp in $global:ComputerList) { [void]$script:ddlAmHost.Items.Add($comp) }; if ($script:ddlAmHost.Items.Count -gt 0 -and $script:ddlAmHost.SelectedIndex -lt 0) { $script:ddlAmHost.SelectedIndex = 0 } })
$tabAppMgr.Controls.AddRange(@($pnlAmBar, $lblAmFilter, $script:ddlAmFilter, $script:lblAmCount, $script:dgvApps, $pnlAmActions, $lblAmLogTitle, $script:rtbAmLog))
#endregion

###############################################################################
###                        TAB 6: REPORTS & STATS                           ###
###############################################################################
## Session dashboard. Three sections:
##   SESSION STATISTICS - seven live stat cards driven by $global:Stats
##     counters (Scanned / Updates / Installed / Uninstalled /
##     Reinstalled / Repaired / Reboots). Cards update whenever
##     Track-Action fires.
##   ACTION HISTORY - $global:ActionHistory grid (Time / Action /
##     Target / Result / Detail), color-coded by Action type. Export
##     CSV writes the full history; Export Summary writes a totals-
##     only roll-up row.
##   REPORT FILES - file browser over .\Logs\ sorted newest-first.
##     Double-click to open. Open Folder button shells to Explorer.
#region === TAB 6: REPORTS & STATS ===
$tabReports = New-Object System.Windows.Forms.TabPage; $tabReports.BackColor = $c.BG
$grpStats = New-Grp -Text "SESSION STATISTICS" -X 6 -Y 6 -W 1100 -H 120 -Fg $c.Gold; $grpStats.Anchor = 'Top,Left,Right'
$statDefs = @(@{T='Scanned';K='Scanned';X=10;Clr=$c.Accent},@{T='Updates';K='Updated';X=142;Clr=$c.Cyan},@{T='Installed';K='Installed';X=274;Clr=$c.Success},@{T='Uninstalled';K='Uninstalled';X=406;Clr=$c.Danger},@{T='Reinstalled';K='Reinstalled';X=538;Clr=$c.Warning},@{T='Repaired';K='Repaired';X=670;Clr=$c.Purple},@{T='Reboots';K='Reboots';X=802;Clr=$c.Danger})
foreach ($sd in $statDefs) { $cardPnl = New-Object System.Windows.Forms.Panel; $cardPnl.Location = New-Object System.Drawing.Point($sd.X, 24); $cardPnl.Size = New-Object System.Drawing.Size(122, 80); $cardPnl.BackColor = $c.PanelLight
    $cardTitle = New-Object System.Windows.Forms.Label; $cardTitle.Text = $sd.T; $cardTitle.ForeColor = $c.Dim; $cardTitle.Font = $fn.Small; $cardTitle.AutoSize = $true; $cardTitle.Location = New-Object System.Drawing.Point(8, 6)
    $cardVal = New-Object System.Windows.Forms.Label; $cardVal.Text = "0"; $cardVal.ForeColor = $sd.Clr; $cardVal.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold); $cardVal.AutoSize = $true; $cardVal.Location = New-Object System.Drawing.Point(8, 26)
    $cardPnl.Controls.AddRange(@($cardTitle, $cardVal)); $grpStats.Controls.Add($cardPnl)
    switch ($sd.K) { 'Scanned' { $script:lblStatScanned = $cardVal }; 'Updated' { $script:lblStatUpdated = $cardVal }; 'Installed' { $script:lblStatInstalled = $cardVal }; 'Uninstalled' { $script:lblStatUninstalled = $cardVal }; 'Reinstalled' { $script:lblStatReinstalled = $cardVal }; 'Repaired' { $script:lblStatRepaired = $cardVal }; 'Reboots' { $script:lblStatReboots = $cardVal } }
}
$lblRptUser = New-Lbl -Text "Operator: $env:USERNAME" -X 18 -Y 132 -W 300 -Font $fn.SmallB -Fg $c.Cyan
$lblRptTime = New-Lbl -Text "Session: $(Get-Date -Format 'g')" -X 320 -Y 132 -W 300 -Font $fn.Small -Fg $c.Dim
$lblRptLog = New-Lbl -Text "Audit: $($global:AuditLogPath)" -X 620 -Y 132 -W 450 -Font $fn.Small -Fg $c.Dim
$grpHistory = New-Grp -Text "ACTION HISTORY" -X 6 -Y 152 -W 1100 -H 340 -Fg $c.Cyan; $grpHistory.Anchor = 'Top,Left,Right'
$script:dgvHistory = New-Object System.Windows.Forms.DataGridView; $script:dgvHistory.Location = New-Object System.Drawing.Point(8, 24); $script:dgvHistory.Size = New-Object System.Drawing.Size(1080, 270)
$script:dgvHistory.Anchor = 'Top,Left,Right'; $script:dgvHistory.ReadOnly = $true; Style-Grid $script:dgvHistory; $script:dgvHistory.AutoSizeColumnsMode = 'None'; $script:dgvHistory.ScrollBars = 'Both'
foreach ($col in @(@{N='Time';H='Time';W=70},@{N='Action';H='Action';W=90},@{N='Target';H='Target';W=180},@{N='Result';H='Result';W=110},@{N='Detail';H='Detail';W=280})) { $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvHistory.Columns.Add($cc) }
$script:lblHistCount = New-Lbl -Text "0 action(s) recorded" -X 10 -Y 300 -W 200 -Font $fn.Small -Fg $c.Dim
$btnRefreshHist = New-Btn -Text "Refresh" -X 220 -Y 296 -W 90 -H 26 -Bg $c.Accent; $btnRefreshHist.Font = $fn.Small
$btnExportCSV = New-Btn -Text "Export to CSV" -X 318 -Y 296 -W 120 -H 26 -Bg $c.Success; $btnExportCSV.Font = $fn.Small
$btnExportSummary = New-Btn -Text "Export Summary" -X 446 -Y 296 -W 130 -H 26 -Bg $c.Cyan; $btnExportSummary.Font = $fn.Small
$btnClearHist = New-Btn -Text "Clear" -X 584 -Y 296 -W 70 -H 26 -Bg $c.PanelLight; $btnClearHist.Font = $fn.Small
function Refresh-HistoryGrid {
    $script:dgvHistory.Rows.Clear()
    foreach ($entry in $global:ActionHistory) { $idx = $script:dgvHistory.Rows.Add($entry.Time, $entry.Action, $entry.Target, $entry.Result, $entry.Detail); $row = $script:dgvHistory.Rows[$idx]
        $actClr = switch ($entry.Action) { 'Scan' { $c.Accent }; 'PatchUpdate' { $c.Cyan }; 'PatchApp' { $c.Success }; 'Install' { $c.Success }; 'Uninstall' { $c.Danger }; 'Reinstall' { $c.Warning }; 'Repair' { $c.Purple }; 'Reboot' { $c.Danger }; default { $c.Dim } }
        $row.Cells['Action'].Style.ForeColor = $actClr
        $resClr = if ($entry.Result -match 'Success|OK|triggered|sent') { $c.Success } elseif ($entry.Result -match 'Fail|Error') { $c.Danger } else { $c.Dim }; $row.Cells['Result'].Style.ForeColor = $resClr
    }; $script:lblHistCount.Text = "$($global:ActionHistory.Count) action(s) recorded"; Update-StatLabels
}
$btnRefreshHist.Add_Click({ Refresh-HistoryGrid })
$btnClearHist.Add_Click({ if ($global:ActionHistory.Count -eq 0) { return }; $confirm = [System.Windows.Forms.MessageBox]::Show("Clear all action history?","Confirm",4,48); if ($confirm -eq 'Yes') { $global:ActionHistory.Clear(); $global:Stats = @{Scanned=0;Updated=0;AppsInstalled=0;AppsUninstalled=0;AppsReinstalled=0;AppsRepaired=0;Reboots=0}; Refresh-HistoryGrid } })
$btnExportCSV.Add_Click({ if ($global:ActionHistory.Count -eq 0) { return }; $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_ActionHistory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; if ($sfd.ShowDialog() -eq 'OK') { $global:ActionHistory | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8 } })
$btnExportSummary.Add_Click({ $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; if ($sfd.ShowDialog() -eq 'OK') {
    @([PSCustomObject]@{Metric='Scanned';Count=$global:Stats.Scanned},[PSCustomObject]@{Metric='Updates';Count=$global:Stats.Updated},[PSCustomObject]@{Metric='Installed';Count=$global:Stats.AppsInstalled},[PSCustomObject]@{Metric='Uninstalled';Count=$global:Stats.AppsUninstalled},[PSCustomObject]@{Metric='Reinstalled';Count=$global:Stats.AppsReinstalled},[PSCustomObject]@{Metric='Repaired';Count=$global:Stats.AppsRepaired},[PSCustomObject]@{Metric='Reboots';Count=$global:Stats.Reboots},[PSCustomObject]@{Metric='Total Actions';Count=$global:ActionHistory.Count},[PSCustomObject]@{Metric='Operator';Count=$env:USERNAME},[PSCustomObject]@{Metric='Session Date';Count=(Get-Date -Format 'yyyy-MM-dd HH:mm')}) | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8 } })
$grpHistory.Controls.AddRange(@($script:dgvHistory, $script:lblHistCount, $btnRefreshHist, $btnExportCSV, $btnExportSummary, $btnClearHist))
$grpFiles = New-Grp -Text "REPORT FILES" -X 6 -Y 498 -W 1100 -H 155 -Fg $c.Success; $grpFiles.Anchor = 'Top,Left,Right'
$script:dgvFiles = New-Object System.Windows.Forms.DataGridView; $script:dgvFiles.Location = New-Object System.Drawing.Point(8, 24); $script:dgvFiles.Size = New-Object System.Drawing.Size(960, 90)
$script:dgvFiles.Anchor = 'Top,Left,Right'; $script:dgvFiles.ReadOnly = $true; Style-Grid $script:dgvFiles; $script:dgvFiles.AutoSizeColumnsMode = 'None'; $script:dgvFiles.ScrollBars = 'Both'
foreach ($col in @(@{N='File';H='File Name';W=380},@{N='Size';H='Size';W=80},@{N='Modified';H='Modified';W=120},@{N='Type';H='Type';W=60})) { $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W; [void]$script:dgvFiles.Columns.Add($cc) }
$script:dgvFiles.Add_CellDoubleClick({ param($s,$e); if ($e.RowIndex -ge 0) { $path = $script:dgvFiles.Rows[$e.RowIndex].Tag; if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path)) { Invoke-Item $path } } })
$btnRefreshFiles = New-Btn -Text "Refresh" -X 978 -Y 24 -W 100 -H 26 -Bg $c.Accent; $btnRefreshFiles.Font = $fn.Small
$btnOpenFolder = New-Btn -Text "Open Folder" -X 978 -Y 56 -W 100 -H 26 -Bg $c.PanelLight; $btnOpenFolder.Font = $fn.Small
$script:lblFileCount = New-Lbl -Text "" -X 10 -Y 120 -W 300 -Font $fn.Small -Fg $c.Dim
function Refresh-ReportFiles {
    $script:dgvFiles.Rows.Clear()
    ## v6.4.0: prefer the per-operator UserLogDir (matches ACAS Nemesis
    ## layout — that's where the session .log + WPT_TouchedHosts CSV live).
    ## Fall back to flat LogDir for older sessions or subfolder-create failure.
    $reportDir = if ($global:UserLogDir -and (Test-Path -LiteralPath $global:UserLogDir)) { $global:UserLogDir } else { $global:LogDir }
    if (-not (Test-Path -LiteralPath $reportDir)) { $script:lblFileCount.Text = "Log folder not found"; return }
    $files = Get-ChildItem -Path $reportDir -File -EA SilentlyContinue | Sort-Object LastWriteTime -Descending
    foreach ($f in $files) { $sizeKB = [Math]::Round($f.Length / 1KB, 1); $idx = $script:dgvFiles.Rows.Add($f.Name, "$sizeKB KB", $f.LastWriteTime.ToString("MM/dd HH:mm"), $f.Extension.TrimStart('.').ToUpper()); $script:dgvFiles.Rows[$idx].Tag = $f.FullName
        $clr = switch ($f.Extension.ToLower()) { '.csv' { $c.Success }; '.log' { $c.Cyan }; '.txt' { $c.Warning }; default { $c.Dim } }; foreach ($ci in 0..3) { $script:dgvFiles.Rows[$idx].Cells[$ci].Style.ForeColor = $clr }
    }; $script:lblFileCount.Text = "$($files.Count) file(s) in log folder"
}
$btnRefreshFiles.Add_Click({ Refresh-ReportFiles }); $btnOpenFolder.Add_Click({ $openDir = if ($global:UserLogDir -and (Test-Path -LiteralPath $global:UserLogDir)) { $global:UserLogDir } else { $global:LogDir }; if (Test-Path -LiteralPath $openDir) { Invoke-Item $openDir } })
$grpFiles.Controls.AddRange(@($script:dgvFiles, $btnRefreshFiles, $btnOpenFolder, $script:lblFileCount))
$tabReports.Add_Enter({ Refresh-HistoryGrid; Refresh-ReportFiles })
$tabReports.Controls.AddRange(@($grpStats, $lblRptUser, $lblRptTime, $lblRptLog, $grpHistory, $grpFiles))
#endregion

## v6.1.0: TAB: ABOUT & CHANGELOG removed. Content is now accessed via the
## "About" and "Change Log" buttons on the Start tab (Show-WptAboutDialog
## and Show-WptChangeLogDialog popups backed by $script:WPT_AboutText and
## $script:WPT_ChangeLogText defined in the STATIC INFO TEXT region above).

###############################################################################
###                    TAB: HEAL  (v47.1 Phase 3 - new)                     ###
###############################################################################
## One-click remediation for stuck workstations -- the "5% coverage"
## capability for hosts Tanium/ARAD can't reach because their agents
## are wedged. 10-column grid: Host / MECM / SWCenter / WMI / WU /
## Reboot / Last Check-In / Overall / Detail. Action buttons feed the
## Heal scriptblocks (region up top):
##   Health Scan All   -> $global:HealthScanBlock       (every row)
##   Restart CcmExec   -> $global:RestartCcmExecBlock   (selected)
##   Repair WMI        -> $global:WmiRepairBlock        (selected)
##   Reset WU          -> $global:WuResetBlock          (selected)
##   Trigger Check-In  -> $global:TriggerCheckInBlock   (selected)
##   gpupdate /force   -> $global:GpUpdateBlock         (selected)
## Live log below. Every action writes a Track-Action row.
#region === TAB: HEAL (v47.1 Phase 3 - new, additive) ===
## One-click remediation for workstations whose MECM/WMI/WU is stuck.
## Runs Get-Wpt*Block scriptblocks (above) via Legacy's RunspacePool.
## Reads from $global:ComputerList / $global:Credentials. Writes to
## Legacy's Log + Write-AuditLog. Does NOT touch any Legacy tab or helper.

$tabHeal = New-Object System.Windows.Forms.TabPage
$tabHeal.BackColor = $c.BG

## v6.5.11: Pre-size the TabPage to match the TabControl's design size
## BEFORE adding any anchored children. Without this, $tabHeal stays at
## WinForms' default 200x100 while children are added, and Top,Right
## anchors capture a large negative right-offset against that tiny
## parent. Once $tabHeal docks into $tc and grows to ~1030 wide, those
## offsets push the grid + log group several hundred pixels past the
## visible right edge. (Same root cause as the v6.5.9 close-button
## anchor fix.)
$tabHeal.Size = New-Object System.Drawing.Size($tc.Width, $tc.Height)

## --- Header
## v6.5.11: explicit -H 28 -- New-Lbl defaults to H=18, which clips
## the top of the letters when -Font $fn.Title (13pt bold mono).
$lblHealTitle = New-Lbl -Text "Heal: One-Click Workstation Remediation" -X 14 -Y 10 -W 900 -H 28 -Font $fn.Title -Fg $c.Gold
$lblHealSub   = New-Lbl -Text "Fixes for targets whose MECM / WMI / WU agents are broken. Runs against the shared target list." -X 16 -Y 42 -W 1000 -Font $fn.Sub -Fg $c.Dim

## --- Results grid
## v6.5.11: width trimmed from 1170 to fit within tabHeal design width
## (1030) with 14px margins. Top,Left,Right anchor still grows it with
## the form on resize.
$script:dgvHeal = New-Object System.Windows.Forms.DataGridView
$script:dgvHeal.Location = New-Object System.Drawing.Point(14, 74)
$script:dgvHeal.Size     = New-Object System.Drawing.Size(1002, 380)
$script:dgvHeal.Anchor   = 'Top,Left,Right'
Style-Grid $script:dgvHeal
$healChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$healChk.Name = 'chkSel'; $healChk.HeaderText = ''; $healChk.Width = 30
$script:dgvHeal.Columns.Add($healChk) | Out-Null
$script:dgvHeal.Columns.Add('Host','Host') | Out-Null
$script:dgvHeal.Columns.Add('MECM','MECM') | Out-Null
$script:dgvHeal.Columns.Add('SWCenter','SW Center') | Out-Null
$script:dgvHeal.Columns.Add('WMI','WMI') | Out-Null
$script:dgvHeal.Columns.Add('WU','WU') | Out-Null
$script:dgvHeal.Columns.Add('Reboot','Reboot') | Out-Null
$script:dgvHeal.Columns.Add('LastCheckIn','Last Check-In') | Out-Null
$script:dgvHeal.Columns.Add('Overall','Overall') | Out-Null
$script:dgvHeal.Columns.Add('Detail','Detail') | Out-Null

## --- Button bar
$script:btnHealScan        = New-Btn -Text "Health Scan All"    -X 14  -Y 470 -W 150 -H 32 -Bg $c.Accent
$script:btnHealRestartCcm  = New-Btn -Text "Restart CcmExec"    -X 172 -Y 470 -W 150 -H 32 -Bg $c.Success
$script:btnHealRepairWmi   = New-Btn -Text "Repair WMI"         -X 330 -Y 470 -W 130 -H 32 -Bg $c.Warning
$script:btnHealResetWu     = New-Btn -Text "Reset WU"           -X 468 -Y 470 -W 110 -H 32 -Bg $c.Warning
$script:btnHealTrigger     = New-Btn -Text "Trigger Check-In"   -X 586 -Y 470 -W 150 -H 32 -Bg $c.Cyan
$script:btnHealGpUpdate    = New-Btn -Text "gpupdate /force"    -X 744 -Y 470 -W 140 -H 32 -Bg $c.Cyan
## v6.5.11: lblHealProg trimmed (280 -> 200) and anchored Top,Right so
## it sits at the right edge regardless of form size. AutoEllipsis on so
## long completion messages truncate gracefully instead of clipping.
$script:lblHealProg        = New-Lbl -Text "Idle"                -X 828 -Y 476 -W 200 -Font $fn.LabelB -Fg $c.Dim
$script:lblHealProg.Anchor       = 'Top,Right'
$script:lblHealProg.AutoEllipsis = $true
$script:lblHealProg.TextAlign    = 'MiddleRight'

## --- Output log
## v6.5.11: width trimmed from 1170 to fit within tabHeal design width.
## Top,Left,Right,Bottom anchor still stretches the log to fill the
## remaining vertical space on resize.
$grpHealLog = New-Grp -Text "HEAL LOG" -X 14 -Y 512 -W 1002 -H 230 -Fg $c.Cyan
$grpHealLog.Anchor = 'Top,Left,Right,Bottom'
$script:rtbHealLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbHealLog.Location    = New-Object System.Drawing.Point(10, 22)
$script:rtbHealLog.Size        = New-Object System.Drawing.Size(982, 200)
$script:rtbHealLog.Anchor      = 'Top,Left,Right,Bottom'
$script:rtbHealLog.BackColor   = $c.OutputBg
$script:rtbHealLog.ForeColor   = $c.Console
$script:rtbHealLog.Font        = $fn.Console
$script:rtbHealLog.ReadOnly    = $true
$script:rtbHealLog.BorderStyle = 'None'
$script:rtbHealLog.WordWrap    = $false
$script:rtbHealLog.ScrollBars  = 'Vertical'
$grpHealLog.Controls.Add($script:rtbHealLog)

## Tab-local log helper (same shape as MsgLog / KBLog / etc).
function HealLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbHealLog) {
        try {
            if (-not $script:rtbHealLog.IsHandleCreated) { $script:rtbHealLog.CreateControl() }
            $start = $script:rtbHealLog.TextLength
            $script:rtbHealLog.AppendText($line)
            $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
            $script:rtbHealLog.Select($start, $line.Length)
            $script:rtbHealLog.SelectionColor = $clr
            $script:rtbHealLog.SelectionLength = 0
            $script:rtbHealLog.ScrollToCaret()
        } catch { try { $script:rtbHealLog.AppendText($line) } catch {} }
    }
    Log "[Heal] $msg" $lvl
    [System.Windows.Forms.Application]::DoEvents()
}

## --- Health Scan (all targets, parallel via RunspacePool)
$script:btnHealScan.Add_Click({
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $script:btnHealScan.Enabled = $false
    $script:dgvHeal.Rows.Clear()
    $dimClr = [System.Drawing.Color]::FromArgb(90,90,130)
    foreach ($comp in $global:ComputerList) {
        $idx = $script:dgvHeal.Rows.Add()
        $row = $script:dgvHeal.Rows[$idx]
        $row.Cells[0].Value = $false
        $row.Cells[1].Value = $comp
        foreach ($ci in 2..9) { $row.Cells[$ci].Value = "Scanning..."; $row.Cells[$ci].Style.ForeColor = $dimClr }
    }
    HealLog "=== Health Scan started: $($global:ComputerList.Count) workstation(s) ===" 'OK'
    Write-AuditLog -Action "HealthScan" -Result "Started" -Detail "$($global:ComputerList.Count) targets"
    $script:lblHealProg.Text = "Scanning 0 / $($global:ComputerList.Count)"
    $script:lblHealProg.ForeColor = $c.Warning
    Initialize-RunspacePool
    $script:HealScanJobs = @{}
    $runId = [guid]::NewGuid().ToString('N').Substring(0,12)
    foreach ($comp in $global:ComputerList) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:HealthScanBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument('Negotiate').AddArgument($runId)
        $script:HealScanJobs[$comp] = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $script:HealScanTotal = $global:ComputerList.Count
    $script:HealScanTimer = New-Object System.Windows.Forms.Timer
    $script:HealScanTimer.Interval = 500
    $script:HealScanTimer.Add_Tick({
        foreach ($key in @($script:HealScanJobs.Keys)) {
            $job = $script:HealScanJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Overall='Broken'; Error=$_.ToString() } }
            $script:HealScanJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null
            foreach ($r in $script:dgvHeal.Rows) { if ($r.Cells[1].Value -eq $res.Host) { $row = $r; break } }
            if ($null -eq $row) { continue }
            if ($res.Overall -eq 'Offline') {
                foreach ($ci in 2..9) { $row.Cells[$ci].Value = "--"; $row.Cells[$ci].Style.ForeColor = $c.Danger }
                $row.Cells[8].Value = "Offline"
                HealLog "$($res.Host): offline" 'WARN'
                continue
            }
            $row.Cells[2].Value = $res.MecmState
            $row.Cells[2].Style.ForeColor = switch ($res.MecmState) { 'Running' { $c.Success } 'Stopped' { $c.Warning } 'Missing' { $c.Danger } default { $c.Dim } }
            $row.Cells[3].Value = $res.SwCenter
            $row.Cells[3].Style.ForeColor = switch ($res.SwCenter) { 'Healthy' { $c.Success } 'NotRunning' { $c.Warning } 'Broken' { $c.Danger } 'Missing' { $c.Danger } default { $c.Dim } }
            $row.Cells[4].Value = $res.WmiState
            $row.Cells[4].Style.ForeColor = if ($res.WmiState -eq 'OK') { $c.Success } else { $c.Danger }
            $row.Cells[5].Value = $res.WuState
            $row.Cells[5].Style.ForeColor = switch ($res.WuState) { 'OK' { $c.Success } 'Disabled' { $c.Danger } 'Broken' { $c.Danger } default { $c.Dim } }
            $row.Cells[6].Value = if ($res.RebootState -eq 'Pending') { "Pending $($res.RebootAge)" } else { 'None' }
            $row.Cells[6].Style.ForeColor = if ($res.RebootState -eq 'Pending') { $c.Warning } else { $c.Success }
            $row.Cells[7].Value = [string]$res.LastCheckIn
            $row.Cells[7].Style.ForeColor = $c.White
            $row.Cells[8].Value = $res.Overall
            $row.Cells[8].Style.ForeColor = switch ($res.Overall) { 'Healthy' { $c.Success } 'Degraded' { $c.Warning } 'Broken' { $c.Danger } default { $c.Dim } }
            $row.Cells[9].Value = [string]$res.Error
            $row.Cells[9].Style.ForeColor = $c.Dim
            $row.Tag = $res
            HealLog "$($res.Host): $($res.Overall) (MECM=$($res.MecmState), WMI=$($res.WmiState), WU=$($res.WuState))"
            Track-Action -Action 'HealthScan' -Target $res.Host -Result $res.Overall
        }
        $done = $script:HealScanTotal - $script:HealScanJobs.Count
        $script:lblHealProg.Text = "Scanning $done / $script:HealScanTotal"
        if ($script:HealScanJobs.Count -eq 0) {
            $script:HealScanTimer.Stop(); $script:HealScanTimer.Dispose()
            $script:btnHealScan.Enabled = $true
            $script:lblHealProg.Text = "Scan complete: $script:HealScanTotal workstation(s)"
            $script:lblHealProg.ForeColor = $c.Success
            HealLog "=== Health Scan complete ===" 'OK'
        }
    })
    $script:HealScanTimer.Start()
})

## --- Generic run-block-against-selected-rows helper. Used by all five
## remediation buttons. $BlockVar names the $global:*Block scriptblock; the
## button labels above identify the action.
$script:InvokeHealAction = {
    param([string]$ActionLabel, [scriptblock]$ActionBlock, $Btn)
    $selected = @()
    foreach ($row in $script:dgvHeal.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No workstations selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("$ActionLabel on $($selected.Count) workstation(s)?","Confirm $ActionLabel",4,48)
    if ($confirm -ne 'Yes') { return }
    $Btn.Enabled = $false
    foreach ($srv in $selected) {
        foreach ($row in $script:dgvHeal.Rows) { if ($row.Cells[1].Value -eq $srv) { $row.Cells[9].Value = "$ActionLabel..."; $row.Cells[9].Style.ForeColor = $c.Warning; break } }
    }
    HealLog "=== $ActionLabel on $($selected.Count) workstation(s) ===" 'OK'
    Write-AuditLog -Action $ActionLabel -Result "Started" -Detail "$($selected.Count) targets"
    Initialize-RunspacePool
    $jobs = @{}
    $runId = [guid]::NewGuid().ToString('N').Substring(0,12)
    foreach ($comp in $selected) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($ActionBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument('Negotiate').AddArgument($runId)
        $jobs[$comp] = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $total = $selected.Count
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 600
    $timer.Tag = @{ Jobs = $jobs; Total = $total; Btn = $Btn; Action = $ActionLabel }
    $timer.Add_Tick({
        param($s, $e)
        $state = $s.Tag
        foreach ($key in @($state.Jobs.Keys)) {
            $job = $state.Jobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Success=$false; Detail=$_.ToString() } }
            $state.Jobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            foreach ($row in $script:dgvHeal.Rows) {
                if ($row.Cells[1].Value -eq $res.Host) {
                    if ($res.Success) {
                        $row.Cells[9].Value = "OK: $($res.Detail)"
                        $row.Cells[9].Style.ForeColor = $c.Success
                    } else {
                        $row.Cells[9].Value = "FAIL: $($res.Detail)"
                        $row.Cells[9].Style.ForeColor = $c.Danger
                    }
                    break
                }
            }
            HealLog "$($res.Host): $(if ($res.Success) { 'OK' } else { 'FAIL' }) - $($res.Detail)" $(if ($res.Success) { 'OK' } else { 'ERR' })
            Track-Action -Action $state.Action -Target $res.Host -Result $(if ($res.Success) { 'OK' } else { 'Fail' }) -Detail $res.Detail
        }
        $done = $state.Total - $state.Jobs.Count
        $script:lblHealProg.Text = "$($state.Action): $done / $($state.Total)"
        if ($state.Jobs.Count -eq 0) {
            $s.Stop(); $s.Dispose()
            $state.Btn.Enabled = $true
            $script:lblHealProg.Text = "$($state.Action) complete"
            $script:lblHealProg.ForeColor = $c.Success
            HealLog "=== $($state.Action) complete ===" 'OK'
        }
    })
    $timer.Start()
}

$script:btnHealRestartCcm.Add_Click({ & $script:InvokeHealAction 'RestartCcmExec'  $global:RestartCcmExecBlock $script:btnHealRestartCcm })
$script:btnHealRepairWmi.Add_Click({  & $script:InvokeHealAction 'WmiRepair'       $global:WmiRepairBlock      $script:btnHealRepairWmi })
$script:btnHealResetWu.Add_Click({    & $script:InvokeHealAction 'WuReset'         $global:WuResetBlock        $script:btnHealResetWu })
$script:btnHealTrigger.Add_Click({    & $script:InvokeHealAction 'TriggerCheckIn'  $global:TriggerCheckInBlock $script:btnHealTrigger })
$script:btnHealGpUpdate.Add_Click({   & $script:InvokeHealAction 'GpUpdate'        $global:GpUpdateBlock       $script:btnHealGpUpdate })

$tabHeal.Controls.AddRange(@($lblHealTitle, $lblHealSub, $script:dgvHeal, $script:btnHealScan, $script:btnHealRestartCcm, $script:btnHealRepairWmi, $script:btnHealResetWu, $script:btnHealTrigger, $script:btnHealGpUpdate, $script:lblHealProg, $grpHealLog))
#endregion

###############################################################################
###                 TAB: WINRM SETUP  (v47.1 Phase 3 - new)                 ###
###############################################################################
## Bootstraps WinRM on hosts that can't answer on 5985 (WinRM disabled,
## firewall blocked, service broken). Uses $global:WinRMBootstrapBlock
## which connects over DCOM (port 135) as the side channel. Grid:
## Host / WinRM 5985 Pre / Result / WinRM 5985 Post / Steps.
## Workflow:
##   1. Load Targets       - pull from $global:ComputerList.
##   2. Pre-Probe Selected - TCP 5985 probe (no creds needed) to see
##                           who actually needs bootstrapping.
##   3. Bootstrap Selected - parallel DCOM bootstrap + post-probe
##                           confirmation.
## The DCOM path requires local-admin creds + RPC dynamic range open.
#region === TAB: WINRM SETUP (v47.1 Phase 3 - new, additive) ===
## Remotely enable WinRM on hosts where it's disabled. Uses the DCOM
## side-channel via $global:WinRMBootstrapBlock. Works against targets
## whose WinRM isn't listening yet (the "fix what Tanium can't" tab).

$tabWinRM = New-Object System.Windows.Forms.TabPage
$tabWinRM.BackColor = $c.BG

## v6.5.12: Same anchor pre-sizing fix as the Heal tab in v6.5.11 --
## $tabWinRM must have its true geometry before anchored children are
## added, otherwise Top,Right offsets capture against the default
## 200x100 and the grid + log group land off the right edge once
## $tabWinRM docks into $tc.
$tabWinRM.Size = New-Object System.Drawing.Size($tc.Width, $tc.Height)

## v6.5.12: explicit -H 28 to keep the 13pt Cascadia Mono Title font
## from clipping at the top.
$lblWinRMTitle = New-Lbl -Text "WinRM Setup: Bootstrap WinRM via DCOM" -X 14 -Y 10 -W 900 -H 28 -Font $fn.Title -Fg $c.Gold
$lblWinRMSub   = New-Lbl -Text "Enables WinRM on hosts that can't be reached on TCP 5985. Runs against the shared target list. Requires DCOM/RPC (port 135) + local-admin creds." -X 16 -Y 42 -W 1000 -Font $fn.Sub -Fg $c.Dim

## v6.5.12: width trimmed from 1170 to fit within tabWinRM design width.
$script:dgvWinRM = New-Object System.Windows.Forms.DataGridView
$script:dgvWinRM.Location = New-Object System.Drawing.Point(14, 74)
$script:dgvWinRM.Size     = New-Object System.Drawing.Size(1002, 380)
$script:dgvWinRM.Anchor   = 'Top,Left,Right'
Style-Grid $script:dgvWinRM
$winrmChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$winrmChk.Name = 'chkSel'; $winrmChk.HeaderText = ''; $winrmChk.Width = 30
$script:dgvWinRM.Columns.Add($winrmChk) | Out-Null
$script:dgvWinRM.Columns.Add('Host','Host') | Out-Null
$script:dgvWinRM.Columns.Add('PreProbe','WinRM 5985 Pre') | Out-Null
$script:dgvWinRM.Columns.Add('Result','Result') | Out-Null
$script:dgvWinRM.Columns.Add('PostProbe','WinRM 5985 Post') | Out-Null
$script:dgvWinRM.Columns.Add('Steps','Steps') | Out-Null

$script:btnWinRMLoad    = New-Btn -Text "Load Targets"        -X 14  -Y 470 -W 130 -H 32 -Bg $c.Cyan
$script:btnWinRMProbe   = New-Btn -Text "Pre-Probe Selected"  -X 152 -Y 470 -W 150 -H 32 -Bg $c.Accent
$script:btnWinRMBoot    = New-Btn -Text "Bootstrap Selected"  -X 310 -Y 470 -W 160 -H 32 -Bg $c.Success
$script:btnWinRMSelAll  = New-Btn -Text "Select All"          -X 478 -Y 470 -W 100 -H 32 -Bg $c.PanelLight
$script:btnWinRMSelNone = New-Btn -Text "Deselect All"        -X 586 -Y 470 -W 110 -H 32 -Bg $c.PanelLight
## v6.5.12: lblWinRMProg trimmed (460 -> 200) and anchored Top,Right so
## it sits at the right edge regardless of form size. AutoEllipsis on so
## long completion messages truncate gracefully.
$script:lblWinRMProg    = New-Lbl -Text "Idle" -X 828 -Y 476 -W 200 -Font $fn.LabelB -Fg $c.Dim
$script:lblWinRMProg.Anchor       = 'Top,Right'
$script:lblWinRMProg.AutoEllipsis = $true
$script:lblWinRMProg.TextAlign    = 'MiddleRight'

## v6.5.12: width trimmed from 1170 to fit within tabWinRM design width.
$grpWinRMLog = New-Grp -Text "WINRM BOOTSTRAP LOG" -X 14 -Y 512 -W 1002 -H 230 -Fg $c.Cyan
$grpWinRMLog.Anchor = 'Top,Left,Right,Bottom'
$script:rtbWinRMLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbWinRMLog.Location    = New-Object System.Drawing.Point(10, 22)
$script:rtbWinRMLog.Size        = New-Object System.Drawing.Size(982, 200)
$script:rtbWinRMLog.Anchor      = 'Top,Left,Right,Bottom'
$script:rtbWinRMLog.BackColor   = $c.OutputBg
$script:rtbWinRMLog.ForeColor   = $c.Console
$script:rtbWinRMLog.Font        = $fn.Console
$script:rtbWinRMLog.ReadOnly    = $true
$script:rtbWinRMLog.BorderStyle = 'None'
$script:rtbWinRMLog.WordWrap    = $false
$script:rtbWinRMLog.ScrollBars  = 'Vertical'
$grpWinRMLog.Controls.Add($script:rtbWinRMLog)

function WinRMLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbWinRMLog) {
        try {
            if (-not $script:rtbWinRMLog.IsHandleCreated) { $script:rtbWinRMLog.CreateControl() }
            $start = $script:rtbWinRMLog.TextLength
            $script:rtbWinRMLog.AppendText($line)
            $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
            $script:rtbWinRMLog.Select($start, $line.Length); $script:rtbWinRMLog.SelectionColor = $clr; $script:rtbWinRMLog.SelectionLength = 0
            $script:rtbWinRMLog.ScrollToCaret()
        } catch { try { $script:rtbWinRMLog.AppendText($line) } catch {} }
    }
    Log "[WinRM] $msg" $lvl
    [System.Windows.Forms.Application]::DoEvents()
}

## Populate grid from shared target list.
$script:btnWinRMLoad.Add_Click({
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $script:dgvWinRM.Rows.Clear()
    foreach ($comp in $global:ComputerList) {
        $idx = $script:dgvWinRM.Rows.Add()
        $row = $script:dgvWinRM.Rows[$idx]
        $row.Cells[0].Value = $false
        $row.Cells[1].Value = $comp
        $row.Cells[2].Value = '--'
        $row.Cells[3].Value = ''
        $row.Cells[4].Value = '--'
        $row.Cells[5].Value = ''
    }
    WinRMLog "Loaded $($global:ComputerList.Count) target(s) from shared list"
})

$script:btnWinRMSelAll.Add_Click({ foreach ($r in $script:dgvWinRM.Rows) { $r.Cells[0].Value = $true } })
$script:btnWinRMSelNone.Add_Click({ foreach ($r in $script:dgvWinRM.Rows) { $r.Cells[0].Value = $false } })

## Pre-probe: TCP 5985 test (no creds needed). Quick way to see which
## targets actually need bootstrapping before firing DCOM against them.
$script:btnWinRMProbe.Add_Click({
    $selected = @(); foreach ($row in $script:dgvWinRM.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No hosts selected.","Nothing Selected"); return }
    $script:btnWinRMProbe.Enabled = $false
    WinRMLog "=== Pre-probing WinRM 5985 on $($selected.Count) host(s) ===" 'OK'
    foreach ($srv in $selected) {
        $up = $false
        $tcp = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($srv, 5985, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tcp.Connected) { $up = $true }
        } catch {} finally { if ($tcp) { try { $tcp.Close() } catch {} } }
        foreach ($row in $script:dgvWinRM.Rows) {
            if ($row.Cells[1].Value -eq $srv) {
                $row.Cells[2].Value = if ($up) { 'Open' } else { 'Closed' }
                $row.Cells[2].Style.ForeColor = if ($up) { $c.Success } else { $c.Warning }
                break
            }
        }
        WinRMLog "$srv : 5985 $(if ($up) { 'Open' } else { 'Closed' })"
        [System.Windows.Forms.Application]::DoEvents()
    }
    WinRMLog "=== Pre-probe complete ===" 'OK'
    $script:btnWinRMProbe.Enabled = $true
})

## Bootstrap: fire $global:WinRMBootstrapBlock against selected hosts in
## parallel via Legacy's RunspacePool.
$script:btnWinRMBoot.Add_Click({
    $selected = @(); foreach ($row in $script:dgvWinRM.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No hosts selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Bootstrap WinRM on $($selected.Count) host(s)? DCOM (port 135) must be reachable.","Confirm Bootstrap",4,48)
    if ($confirm -ne 'Yes') { return }
    $script:btnWinRMBoot.Enabled = $false
    foreach ($srv in $selected) {
        foreach ($row in $script:dgvWinRM.Rows) {
            if ($row.Cells[1].Value -eq $srv) { $row.Cells[3].Value = 'Bootstrapping...'; $row.Cells[3].Style.ForeColor = $c.Warning; break }
        }
    }
    WinRMLog "=== Bootstrap started on $($selected.Count) host(s) ===" 'OK'
    Write-AuditLog -Action "WinRMBootstrap" -Result "Started" -Detail "$($selected.Count) targets"
    Initialize-RunspacePool
    $script:WinRMJobs = @{}
    foreach ($comp in $selected) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:WinRMBootstrapBlock).AddArgument($comp).AddArgument($global:Credentials)
        $script:WinRMJobs[$comp] = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $script:WinRMTotal = $selected.Count
    $script:WinRMTimer = New-Object System.Windows.Forms.Timer
    $script:WinRMTimer.Interval = 700
    $script:WinRMTimer.Add_Tick({
        foreach ($key in @($script:WinRMJobs.Keys)) {
            $job = $script:WinRMJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Success=$false; Error=$_.ToString(); Steps=@(); PostProbeOk=$false } }
            $script:WinRMJobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            foreach ($row in $script:dgvWinRM.Rows) {
                if ($row.Cells[1].Value -eq $res.Host) {
                    if ($res.Success) {
                        $row.Cells[3].Value = 'OK'; $row.Cells[3].Style.ForeColor = $c.Success
                    } else {
                        $row.Cells[3].Value = if ($res.Error) { "FAIL: $($res.Error)" } else { 'FAIL' }
                        $row.Cells[3].Style.ForeColor = $c.Danger
                    }
                    $row.Cells[4].Value = if ($res.PostProbeOk) { 'Open' } else { 'Closed' }
                    $row.Cells[4].Style.ForeColor = if ($res.PostProbeOk) { $c.Success } else { $c.Warning }
                    $row.Cells[5].Value = ($res.Steps -join ' | ')
                    break
                }
            }
            foreach ($step in $res.Steps) { WinRMLog "$($res.Host): $step" }
            WinRMLog "$($res.Host): bootstrap $(if ($res.Success) { 'OK' } else { 'FAIL' })" $(if ($res.Success) { 'OK' } else { 'ERR' })
            Track-Action -Action 'WinRMBootstrap' -Target $res.Host -Result $(if ($res.Success) { 'OK' } else { 'Fail' }) -Detail ($res.Steps -join '; ')
        }
        $done = $script:WinRMTotal - $script:WinRMJobs.Count
        $script:lblWinRMProg.Text = "Bootstrapping $done / $script:WinRMTotal"
        if ($script:WinRMJobs.Count -eq 0) {
            $script:WinRMTimer.Stop(); $script:WinRMTimer.Dispose()
            $script:btnWinRMBoot.Enabled = $true
            $script:lblWinRMProg.Text = "Bootstrap complete"
            $script:lblWinRMProg.ForeColor = $c.Success
            WinRMLog "=== Bootstrap complete ===" 'OK'
        }
    })
    $script:WinRMTimer.Start()
})

$tabWinRM.Controls.AddRange(@($lblWinRMTitle, $lblWinRMSub, $script:dgvWinRM, $script:btnWinRMLoad, $script:btnWinRMProbe, $script:btnWinRMBoot, $script:btnWinRMSelAll, $script:btnWinRMSelNone, $script:lblWinRMProg, $grpWinRMLog))
#endregion

###############################################################################
###                      APP UPDATER PROFILE REGISTRY                       ###
###############################################################################
## $global:AppUpdateProfiles hashtable - the data the App Updater v2 tab
## reads. Five entries, each with Desc / Script / Verify fields:
##   * Microsoft 365 - Force Update     (OfficeC2RClient + force close)
##   * Microsoft 365 - Update (User Visible)
##   * Windows Defender - Update Definitions  (Update-MpSignature)
##   * Google Chrome - Update           (GoogleUpdate.exe /ua)
##   * Microsoft Edge - Update          (MicrosoftEdgeUpdate.exe /ua)
## Script runs remotely to apply the update. Verify queries the current
## version + last-updated timestamp + a staleness verdict so the operator
## can confirm the push actually took. Registry is read-only at runtime.
## Helpers: Get-WptAppUpdateProfiles, Get-WptAppUpdateProfile -Name <n>,
## Get-WptAppUpdateProfileNames.
#region === APP UPDATER PROFILE REGISTRY (v47.1 Phase 3 - modular-ported) ===
## Ported from modular WPT v2.4.0 Tools\WPT\Integrations\AppUpdateProfiles.ps1.
## Central registry of 5 named app-update profiles. Each profile has a Script
## (run remotely) and a Verify (query current version + last-updated). The
## "App Updater v2" tab below consumes this registry. Legacy's existing
## "App Updater" tab is untouched and continues to work with its inline
## profiles.
$global:AppUpdateProfiles = @{
    'Microsoft 365 - Force Update' = @{
        Desc   = 'OfficeC2RClient.exe /update user -- silent, force close apps'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user','/displaylevel=false','/forceappshutdown=true' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version='n/a'; LastUpdated='n/a'; Verified=$null; Detail='Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version=$ver; LastUpdated=$modStr; Verified=$verified; Detail="Scenario=$($p.LastScenario)" }
        }
    }
    'Microsoft 365 - Update (User Visible)' = @{
        Desc   = 'OfficeC2RClient.exe /update user -- shows progress to user'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version='n/a'; LastUpdated='n/a'; Verified=$null; Detail='Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version=$ver; LastUpdated=$modStr; Verified=$verified; Detail="Scenario=$($p.LastScenario)" }
        }
    }
    'Windows Defender - Update Definitions' = @{
        Desc   = 'Update-MpSignature -- pulls latest Defender definitions'
        Script = {
            try {
                Update-MpSignature -ErrorAction Stop
                $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
                $ver = if ($def) { $def.AntivirusSignatureVersion } else { 'unknown' }
                return "OK (Defender definitions updated to $ver)"
            } catch { return "FAIL: $($_.Exception.Message)" }
        }
        Verify = {
            try {
                $def = Get-MpComputerStatus -ErrorAction Stop
                $ver = "$($def.AntivirusSignatureVersion)"
                $last = $def.AntivirusSignatureLastUpdated
                $lastStr = if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
                $verified = if ($last) { ((Get-Date) - $last).TotalHours -lt 24 } else { $false }
                return @{ Version=$ver; LastUpdated=$lastStr; Verified=$verified; Detail="Engine=$($def.AMEngineVersion)" }
            } catch { return @{ Version='error'; LastUpdated='n/a'; Verified=$false; Detail=$_.Exception.Message } }
        }
    }
    'Google Chrome - Update' = @{
        Desc   = 'GoogleUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'
            if (-not (Test-Path $exe)) { $exe = 'C:\Program Files\Google\Update\GoogleUpdate.exe' }
            if (-not (Test-Path $exe)) { return 'FAIL: GoogleUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Chrome update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $guid = '{8A69D345-D564-463c-AFF1-A69D9E530F96}'
            $paths = @("HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\$guid","HKLM:\SOFTWARE\Google\Update\Clients\$guid")
            $ver = 'not installed'; $mod = $null
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $pp = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    if ($pp.pv) { $ver = "$($pp.pv)" }
                    $key = Get-Item -Path $p -ErrorAction SilentlyContinue
                    if ($key) { $mod = $key.LastWriteTime }
                    break
                }
            }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 14 } else { $null }
            return @{ Version=$ver; LastUpdated=$modStr; Verified=$verified; Detail='' }
        }
    }
    'Microsoft Edge - Update' = @{
        Desc   = 'MicrosoftEdgeUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
            if (-not (Test-Path $exe)) { return 'FAIL: MicrosoftEdgeUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Edge update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $guid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
            $paths = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid","HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid")
            $ver = 'not installed'; $mod = $null
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $pp = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    if ($pp.pv) { $ver = "$($pp.pv)" }
                    $key = Get-Item -Path $p -ErrorAction SilentlyContinue
                    if ($key) { $mod = $key.LastWriteTime }
                    break
                }
            }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 14 } else { $null }
            return @{ Version=$ver; LastUpdated=$modStr; Verified=$verified; Detail='' }
        }
    }
    'Apache Log4j - Replace Vulnerable Jars' = @{
        ## v6.4.2: Port of Log4J_Plugin_282519 v2.ps1.
        ## v6.5.2: source share path is now operator-overrideable. The
        ## Apply handler reads the textbox in the App Updater tab and
        ## substitutes the value into a copy of this scriptblock at
        ## runtime. The literal below is the embedded fallback if the
        ## global default + textbox are both empty -- the canonical
        ## default is $global:Log4jDefaultSource (auto-detected from
        ## the WPT script location: <JANET-root>\Packages\Log4j\
        ## NewFiles\).
        ## v6.5.18: Script + Verify rewritten to RECURSE under each
        ## target lib root. Previous versions only enumerated the top
        ## level, which left the Backup_<ts>\ subdirs they themselves
        ## created accumulating stale jars (2.17.2 / 2.25.3) that
        ## Tenable kept flagging via plugins 306549 / 306550.
        ##
        ## New per-jar dispositions (computed from filename + path):
        ##   - filename == log4j-(api|core)-2.25.4.jar   -> SKIP (already current)
        ##   - path contains \Backup_*\                  -> DELETE in place
        ##                                                  (no back-of-a-backup;
        ##                                                   the live copy in the
        ##                                                   parent is the source
        ##                                                   of truth)
        ##   - else (top-level live jar that isn't 2.25.4) -> BACKUP + REPLACE
        ##                                                    using a new
        ##                                                    Backup_<ts>\ in
        ##                                                    the lib root
        ## The bundled service is only stopped if at least one live jar
        ## needs replacing -- pure archive-folder cleanups don't need a
        ## service bounce.
        Desc   = 'Replace log4j-api/core jars with 2.25.4 across HID + Adobe lib paths (recursive: live jars get back-up-then-replace, Backup_* subdir jars get deleted in place). Source path is operator-overrideable in the box below.'
        Script = {
            $sourceShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles'
            $newApi      = 'log4j-api-2.25.4.jar'
            $newCore     = 'log4j-core-2.25.4.jar'
            $targets     = @(
                @{ Path='C:\Program Files\HID Global\Credential Management Client\lib'; Service='HIDCredentialManagementClient' }
                @{ Path='C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'; Service='AdobeExperienceManagerFormsDesigner' }
            )

            ## Verify the source share is reachable from this host before
            ## we touch any service. If the share is gated by an ACL the
            ## machine account can't read, this returns FAIL early without
            ## leaving a service stopped.
            $srcApi  = Join-Path $sourceShare $newApi
            $srcCore = Join-Path $sourceShare $newCore
            if (-not (Test-Path -LiteralPath $srcApi))  { return "FAIL: source jar missing on share: $srcApi" }
            if (-not (Test-Path -LiteralPath $srcCore)) { return "FAIL: source jar missing on share: $srcCore" }

            $liveReplaced    = 0
            $archiveDeleted  = 0
            $skippedRoots    = 0
            $skippedCurrent  = 0
            $errors          = New-Object System.Collections.Generic.List[string]

            foreach ($t in $targets) {
                $libPath = $t.Path
                if (-not (Test-Path -LiteralPath $libPath)) { $skippedRoots++; continue }

                ## v6.5.18: RECURSIVE enumeration. -Filter is FS-driver fast.
                ## Wrap in try/catch for ACL surprises under recursed dirs.
                try {
                    $allJars = @(Get-ChildItem -LiteralPath $libPath -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                } catch { $allJars = @() }

                ## Only care about api + core jars for the swap action --
                ## the source share only ships those two. Other components
                ## (1.2-api, jul, to-slf4j) get left alone here; the Log4j
                ## Finder tab will still surface them if present.
                $relevant = @($allJars | Where-Object {
                    $_.Name -match '^log4j-(api|core)-' -and $_.Name -like '*.jar'
                })
                if ($relevant.Count -eq 0) { $skippedRoots++; continue }

                ## Partition: already-current (filename exactly 2.25.4),
                ## archive (path contains \Backup_*\), live (everything
                ## else -- expected to be the lib root top level but a
                ## recursed match in a non-Backup_ subdir falls here too).
                $current = @($relevant | Where-Object { $_.Name -eq $newApi -or $_.Name -eq $newCore })
                $stale   = @($relevant | Where-Object { $_.Name -ne $newApi -and $_.Name -ne $newCore })
                $skippedCurrent += $current.Count

                $archiveStale = @($stale | Where-Object { $_.FullName -like '*\Backup_*\*' })
                $liveStale    = @($stale | Where-Object { $_.FullName -notlike '*\Backup_*\*' })

                ## Service bounce only if there are live jars to replace.
                $wasRunning = $false
                if ($liveStale.Count -gt 0) {
                    $svc = Get-Service -Name $t.Service -ErrorAction SilentlyContinue
                    $wasRunning = ($svc -and $svc.Status -eq 'Running')
                    if ($wasRunning) {
                        try { Stop-Service -Name $t.Service -Force -ErrorAction Stop }
                        catch { $errors.Add("$($t.Service) stop failed: $($_.Exception.Message)") | Out-Null }
                    }
                }

                try {
                    ## --- Live jars: back up + replace at lib root ---
                    if ($liveStale.Count -gt 0) {
                        $backupDir = Join-Path $libPath ("Backup_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                        New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null

                        foreach ($f in $liveStale) {
                            try {
                                Copy-Item -LiteralPath $f.FullName -Destination $backupDir -Force -ErrorAction Stop
                                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                            } catch { $errors.Add("$($f.FullName) backup/remove failed: $($_.Exception.Message)") | Out-Null }
                        }
                        ## Drop the fresh 2.25.4 jars at the lib root.
                        ## Only do this if the lib root previously had api+core
                        ## stale jars OR no api/core present at all -- skipping
                        ## here when the user's install has core but no api
                        ## (or vice versa) keeps us from creating a half-pair.
                        $rootApi  = Join-Path $libPath $newApi
                        $rootCore = Join-Path $libPath $newCore
                        try { Copy-Item -LiteralPath $srcApi  -Destination $rootApi  -Force -ErrorAction Stop }
                        catch { $errors.Add("$rootApi copy failed: $($_.Exception.Message)") | Out-Null }
                        try { Copy-Item -LiteralPath $srcCore -Destination $rootCore -Force -ErrorAction Stop }
                        catch { $errors.Add("$rootCore copy failed: $($_.Exception.Message)") | Out-Null }

                        $liveReplaced++
                    }

                    ## --- Archive jars: delete in place ---
                    ## No back-of-a-backup. The live copy in the parent
                    ## lib root is the source of truth; these are stale
                    ## artifacts from earlier swap runs.
                    foreach ($f in $archiveStale) {
                        try {
                            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                            $archiveDeleted++
                        } catch { $errors.Add("$($f.FullName) delete failed: $($_.Exception.Message)") | Out-Null }
                    }
                } catch {
                    $errors.Add("$libPath swap failed: $($_.Exception.Message)") | Out-Null
                } finally {
                    if ($wasRunning) {
                        try { Start-Service -Name $t.Service -ErrorAction Stop }
                        catch { $errors.Add("$($t.Service) restart failed: $($_.Exception.Message)") | Out-Null }
                    }
                }
            }

            $summary = "live=$liveReplaced archive=$archiveDeleted current=$skippedCurrent rootsSkipped=$skippedRoots"
            if ($errors.Count -gt 0) {
                return "FAIL ($summary; errors: " + ($errors -join '; ') + ')'
            }
            if ($liveReplaced -eq 0 -and $archiveDeleted -eq 0) {
                return "OK (nothing to do; $summary)"
            }
            return "OK ($summary)"
        }
        Verify = {
            $targets = @(
                'C:\Program Files\HID Global\Credential Management Client\lib'
                'C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'
            )
            $found    = New-Object System.Collections.Generic.List[string]
            $vulns    = New-Object System.Collections.Generic.List[string]
            $newest   = $null

            foreach ($p in $targets) {
                if (-not (Test-Path -LiteralPath $p)) { continue }
                ## v6.5.18: RECURSIVE -- the Backup_<ts>\ subdirs the
                ## Script side creates are what Tenable hits via plugin
                ## 306549 / 306550. Non-recursive Get-ChildItem hid them.
                $jars = @(Get-ChildItem -LiteralPath $p -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                foreach ($j in $jars) {
                    $found.Add("$($j.Name)") | Out-Null
                    ## Only api+core in the 2.25.4-exactly pattern are
                    ## considered "patched" -- match the Tenable plugin
                    ## bar the App Updater is already chasing.
                    if ($j.Name -notmatch '^log4j-(api|core)-2\.25\.4\.jar$') {
                        ## Include the full path so the operator can
                        ## see "ah it's in Backup_20260506_..." instead
                        ## of a bare filename that doesn't disambiguate
                        ## live vs archive.
                        $vulns.Add("$($j.FullName)") | Out-Null
                    }
                    if ($null -eq $newest -or $j.LastWriteTime -gt $newest) { $newest = $j.LastWriteTime }
                }
            }

            if ($found.Count -eq 0) {
                return @{ Version='none'; LastUpdated='n/a'; Verified=$true; Detail='No log4j jars in target paths' }
            }

            $verStr  = ($found | Sort-Object -Unique) -join ', '
            $modStr  = if ($newest) { $newest.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = ($vulns.Count -eq 0)
            $detail  = if ($vulns.Count -gt 0) { "STILL-VULNERABLE ($($vulns.Count)): " + (($vulns | Sort-Object -Unique) -join '; ') } else { 'All jars at 2.25.4 (recursive scan)' }
            return @{ Version=$verStr; LastUpdated=$modStr; Verified=$verified; Detail=$detail }
        }
    }
    'Windows Unquoted Service Path - Remediate' = @{
        ## v6.5.20: Tenable plugin 63155 (~322 hosts). Walks every
        ## service under HKLM\SYSTEM\CurrentControlSet\Services and
        ## quotes any ImagePath whose executable portion contains
        ## a space but isn't already quoted. Preserves the original
        ## value-kind (REG_SZ vs REG_EXPAND_SZ) so %SystemRoot%-
        ## style entries keep expanding. Pre-edit value is stashed
        ## at HKLM:\SOFTWARE\JANET\WPT\UnquotedSvcPath\<svc>\Original
        ## ImagePath so a human can roll back without git history.
        ## No reboot, but the fixed services need a restart (or
        ## next boot) before the new ImagePath is honored.
        Desc   = 'Find services whose ImagePath has spaces and no surrounding quotes, then rewrite with quotes around the exe (args preserved). Backs up original value to HKLM:\SOFTWARE\JANET\WPT\UnquotedSvcPath. Clears Tenable plugin 63155.'
        Script = {
            $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            $backupRoot = 'HKLM:\SOFTWARE\JANET\WPT\UnquotedSvcPath'
            if (-not (Test-Path $svcRoot)) { return 'FAIL: services hive not found' }
            try {
                if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -Force -EA Stop | Out-Null }
            } catch { return "FAIL: cannot create backup root: $($_.Exception.Message)" }

            $fixed   = New-Object System.Collections.Generic.List[string]
            $skipped = 0
            $errors  = New-Object System.Collections.Generic.List[string]

            ## Match the exe boundary: lazy up to the first .exe (case-
            ## insensitive), optionally followed by whitespace + args.
            ## We do NOT touch entries that don't end in .exe (svchost
            ## -k Foo, kernel drivers with .sys, etc.) -- those don't
            ## trigger the unquoted-path EoP and editing them is risky.
            $exeRe = [regex]'(?i)^(.+?\.exe)(\s.*)?$'

            foreach ($svc in Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue) {
                $svcName = $svc.PSChildName
                $img = $null
                try { $img = (Get-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath -EA Stop).ImagePath }
                catch { continue }   ## no ImagePath -> not a service exe (or driver-only)
                if ([string]::IsNullOrWhiteSpace($img)) { continue }

                $trim = $img.TrimStart()
                if ($trim.StartsWith('"')) { $skipped++; continue }   ## already quoted

                $m = $exeRe.Match($trim)
                if (-not $m.Success) { $skipped++; continue }
                $exePart  = $m.Groups[1].Value
                $argsPart = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { '' }
                if ($exePart -notmatch ' ') { $skipped++; continue }  ## no space in exe -> not vulnerable

                $newImg = '"' + $exePart + '"' + $argsPart
                if ($newImg -eq $img) { $skipped++; continue }

                ## Preserve REG_SZ vs REG_EXPAND_SZ so %ProgramFiles%-
                ## style ImagePaths keep expanding at service start.
                $kind = $null
                try { $kind = (Get-Item -LiteralPath $svc.PSPath).GetValueKind('ImagePath') } catch {}
                $type = if ($kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) { 'ExpandString' } else { 'String' }

                try {
                    $bk = Join-Path $backupRoot $svcName
                    if (-not (Test-Path $bk)) { New-Item -Path $bk -Force -EA Stop | Out-Null }
                    Set-ItemProperty -LiteralPath $bk -Name 'OriginalImagePath' -Value $img    -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $bk -Name 'FixedTimestamp'    -Value (Get-Date -Format 's') -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $bk -Name 'OriginalKind'      -Value "$kind" -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath   -Value $newImg -Type $type   -Force -EA Stop
                    $fixed.Add($svcName) | Out-Null
                } catch {
                    $errors.Add("${svcName}: $($_.Exception.Message)") | Out-Null
                }
            }

            $summary = "fixed=$($fixed.Count) skipped=$skipped errors=$($errors.Count)"
            if ($errors.Count -gt 0) { return "PARTIAL ($summary; first error: $($errors[0]))" }
            if ($fixed.Count -eq 0)  { return "OK (nothing to fix; $summary)" }
            return "OK ($summary; fixed: $((($fixed | Sort-Object) -join ', ')))"
        }
        Verify = {
            $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            $backupRoot = 'HKLM:\SOFTWARE\JANET\WPT\UnquotedSvcPath'
            $exeRe      = [regex]'(?i)^(.+?\.exe)(\s.*)?$'
            $remaining  = New-Object System.Collections.Generic.List[string]

            foreach ($svc in Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue) {
                $img = $null
                try { $img = (Get-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath -EA Stop).ImagePath }
                catch { continue }
                if ([string]::IsNullOrWhiteSpace($img)) { continue }
                $trim = $img.TrimStart()
                if ($trim.StartsWith('"')) { continue }
                $m = $exeRe.Match($trim)
                if (-not $m.Success) { continue }
                if ($m.Groups[1].Value -notmatch ' ') { continue }
                $remaining.Add($svc.PSChildName) | Out-Null
            }

            $lastFix = 'n/a'
            if (Test-Path $backupRoot) {
                $newest = Get-ChildItem -LiteralPath $backupRoot -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($newest) { $lastFix = $newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            }

            return @{
                Version     = "Unquoted remaining: $($remaining.Count)"
                LastUpdated = $lastFix
                Verified    = ($remaining.Count -eq 0)
                Detail      = if ($remaining.Count -eq 0) { 'All service ImagePath values are quoted or have no spaces in the exe portion.' } else { 'Still unquoted: ' + (($remaining | Sort-Object) -join ', ') }
            }
        }
    }
    'MSXML 4.0 - Uninstall' = @{
        ## v6.5.20: Tenable plugin 62758 (~26 hosts). MSXML 4.0 SP3
        ## reached Microsoft end-of-support in 2014; any version
        ## still installed is the vulnerability. Discovery is by
        ## DisplayName ('MSXML 4.0*') across the standard Uninstall
        ## hives, not a hardcoded GUID list -- the GUID varies per
        ## locale + KB level, and a DisplayName scan catches both
        ## the Parser and the SP packages without missing a build.
        ## Pair with the v6.5.19 Sw Mgr detection that already
        ## reports MSXML across all four places it can hide.
        Desc   = 'MsiExec /x of any "MSXML 4.0*" product found in the Uninstall registry (HKLM 64-bit + WOW6432Node). Silent. Clears Tenable plugin 62758. No reboot expected.'
        Script = {
            $hives = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )
            $found = New-Object System.Collections.Generic.List[object]
            foreach ($hive in $hives) {
                if (-not (Test-Path $hive)) { continue }
                foreach ($k in Get-ChildItem -LiteralPath $hive -EA SilentlyContinue) {
                    $p = $null
                    try { $p = Get-ItemProperty -LiteralPath $k.PSPath -EA Stop } catch { continue }
                    if ($p.DisplayName -like 'MSXML 4.0*') {
                        $found.Add([pscustomobject]@{
                            Name = "$($p.DisplayName)"
                            Ver  = "$($p.DisplayVersion)"
                            GUID = "$($k.PSChildName)"
                        }) | Out-Null
                    }
                }
            }
            if ($found.Count -eq 0) { return 'OK (no MSXML 4.0 products installed)' }

            $removed = New-Object System.Collections.Generic.List[string]
            $errors  = New-Object System.Collections.Generic.List[string]
            foreach ($f in $found) {
                if ($f.GUID -notmatch '^\{[0-9A-Fa-f-]+\}$') {
                    $errors.Add("$($f.Name): unsupported product key '$($f.GUID)' (not a GUID, skipping)") | Out-Null
                    continue
                }
                try {
                    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x', $f.GUID, '/qn', '/norestart') -Wait -PassThru -NoNewWindow -EA Stop
                    ## Exit codes: 0 = success, 1605 = product not currently installed
                    ## (already removed by a parallel run), 3010 = success but reboot
                    ## suggested (we won't trigger it from here).
                    if ($proc.ExitCode -in 0,1605,3010) {
                        $removed.Add("$($f.Name) [$($f.GUID)] (exit $($proc.ExitCode))") | Out-Null
                    } else {
                        $errors.Add("$($f.Name) [$($f.GUID)]: msiexec exit $($proc.ExitCode)") | Out-Null
                    }
                } catch { $errors.Add("$($f.Name): $($_.Exception.Message)") | Out-Null }
            }

            $summary = "removed=$($removed.Count) errors=$($errors.Count)"
            if ($errors.Count -gt 0) { return "PARTIAL ($summary; first error: $($errors[0]))" }
            return "OK ($summary; $($removed -join '; '))"
        }
        Verify = {
            $hives = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )
            $names = New-Object System.Collections.Generic.List[string]
            foreach ($hive in $hives) {
                if (-not (Test-Path $hive)) { continue }
                foreach ($k in Get-ChildItem -LiteralPath $hive -EA SilentlyContinue) {
                    $p = $null
                    try { $p = Get-ItemProperty -LiteralPath $k.PSPath -EA Stop } catch { continue }
                    if ($p.DisplayName -like 'MSXML 4.0*') {
                        $names.Add("$($p.DisplayName) $($p.DisplayVersion)") | Out-Null
                    }
                }
            }
            return @{
                Version     = if ($names.Count -gt 0) { ($names | Sort-Object -Unique) -join '; ' } else { 'none' }
                LastUpdated = 'n/a'
                Verified    = ($names.Count -eq 0)
                Detail      = if ($names.Count -eq 0) { 'No MSXML 4.0 products in Uninstall registry' } else { "$($names.Count) MSXML 4.0 entries still installed" }
            }
        }
    }
    'Office VBA Project Access - Disable (AccessVBOM)' = @{
        ## v6.5.20: Tenable plugin 123461 (~17 hosts). "Trust access to the
        ## VBA project object model" enabled (AccessVBOM=1) lets macro code
        ## reach into the VBA project itself -- a macro self-propagation
        ## vector. The secure Office default is 0 (absent or 0); something
        ## (an add-in installer, a power user, a stray preference) set it to
        ## 1 per-user. Tenable reads it out of the LOADED user hives, so we
        ## walk HKEY_USERS the same way: every real user SID (S-1-5-21-*,
        ## skipping the *_Classes companion hives), Office 14.0/15.0/16.0,
        ## the common VBA apps, flipping AccessVBOM 1 -> 0 where present.
        ##
        ## SCOPE NOTE: loaded hives only -- identical to what the scanner
        ## sees. Users not logged on at run time have unloaded hives and
        ## won't be touched; re-run after they log on (or pair with a
        ## logon GPO) to catch them. We deliberately do NOT reg-load
        ## unloaded NTUSER.DAT files -- that's lock-prone and risks
        ## leaving orphaned loaded hives on a remote box.
        ##
        ## SAFETY: setting 0 does NOT disable macros; it only blocks code
        ## from programmatically modifying the VBA project object model.
        ## 0 is the Office default. Pre-edit values stashed at
        ## HKLM:\SOFTWARE\JANET\WPT\OfficeVBOM\<SID>\<ver-app> for rollback.
        ## No reboot; takes effect at next Office launch. Run Verify first
        ## as a dry run -- it lists exactly which SID/app pairs are hot.
        Desc   = 'Set AccessVBOM=0 (disable trust access to the VBA project object model) for Word/Excel/PowerPoint/Outlook/Access/Publisher across all loaded user hives where it is currently 1. Office secure default; macros still run. Backs up originals to HKLM:\SOFTWARE\JANET\WPT\OfficeVBOM. Clears Tenable plugin 123461. No reboot. (Run Verify first for a dry-run list.)'
        Script = {
            $apps       = @('Word','Excel','PowerPoint','Outlook','Access','Publisher')
            $vers       = @('16.0','15.0','14.0')
            $backupRoot = 'HKLM:\SOFTWARE\JANET\WPT\OfficeVBOM'
            try { if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -Force -EA Stop | Out-Null } }
            catch { return "FAIL: cannot create backup root: $($_.Exception.Message)" }

            $fixed  = New-Object System.Collections.Generic.List[string]
            $errors = New-Object System.Collections.Generic.List[string]

            ## Real interactive user hives only -- S-1-5-21-* excludes the
            ## SYSTEM/LOCAL SERVICE/NETWORK SERVICE well-known SIDs, and the
            ## *_Classes filter drops the per-user COM companion hives.
            $userHives = @(Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue | Where-Object {
                $_.PSChildName -like 'S-1-5-21-*' -and $_.PSChildName -notlike '*_Classes'
            })

            foreach ($hive in $userHives) {
                $sid = $hive.PSChildName
                foreach ($v in $vers) {
                    foreach ($app in $apps) {
                        $secPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\$v\$app\Security"
                        if (-not (Test-Path $secPath)) { continue }
                        $cur = $null
                        try { $cur = (Get-ItemProperty -LiteralPath $secPath -Name AccessVBOM -EA Stop).AccessVBOM }
                        catch { continue }   ## value absent = secure default, nothing to do
                        if ($null -eq $cur -or [int]$cur -ne 1) { continue }
                        try {
                            $bk = Join-Path $backupRoot "$sid\$v-$app"
                            if (-not (Test-Path $bk)) { New-Item -Path $bk -Force -EA Stop | Out-Null }
                            Set-ItemProperty -LiteralPath $bk -Name 'OriginalAccessVBOM' -Value 1 -Type DWord -Force -EA Stop
                            Set-ItemProperty -LiteralPath $bk -Name 'FixedTimestamp'     -Value (Get-Date -Format 's') -Type String -Force -EA Stop
                            Set-ItemProperty -LiteralPath $secPath -Name AccessVBOM -Value 0 -Type DWord -Force -EA Stop
                            $fixed.Add("$sid : $v\$app") | Out-Null
                        } catch {
                            $errors.Add("$sid $v\$app : $($_.Exception.Message)") | Out-Null
                        }
                    }
                }
            }

            $summary = "fixed=$($fixed.Count) hivesScanned=$($userHives.Count) errors=$($errors.Count)"
            if ($errors.Count -gt 0) { return "PARTIAL ($summary; first error: $($errors[0]))" }
            if ($fixed.Count -eq 0)  { return "OK (nothing to fix; $summary)" }
            return "OK ($summary)"
        }
        Verify = {
            $apps = @('Word','Excel','PowerPoint','Outlook','Access','Publisher')
            $vers = @('16.0','15.0','14.0')
            $hot  = New-Object System.Collections.Generic.List[string]
            $userHives = @(Get-ChildItem 'Registry::HKEY_USERS' -EA SilentlyContinue | Where-Object {
                $_.PSChildName -like 'S-1-5-21-*' -and $_.PSChildName -notlike '*_Classes'
            })
            foreach ($hive in $userHives) {
                $sid = $hive.PSChildName
                foreach ($v in $vers) {
                    foreach ($app in $apps) {
                        $secPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Office\$v\$app\Security"
                        if (-not (Test-Path $secPath)) { continue }
                        $cur = $null
                        try { $cur = (Get-ItemProperty -LiteralPath $secPath -Name AccessVBOM -EA Stop).AccessVBOM }
                        catch { continue }
                        if ($null -ne $cur -and [int]$cur -eq 1) { $hot.Add("$sid : $v\$app") | Out-Null }
                    }
                }
            }
            return @{
                Version     = if ($hot.Count -gt 0) { "AccessVBOM=1 in $($hot.Count) hive/app" } else { 'none' }
                LastUpdated = 'n/a'
                Verified    = ($hot.Count -eq 0)
                Detail      = if ($hot.Count -eq 0) { "No loaded hive has AccessVBOM=1 (scanned $($userHives.Count) user hive(s))" } else { 'Still enabled: ' + (($hot | Sort-Object) -join '; ') }
            }
        }
    }

    'Oracle Java - Software Center' = @{
        ## Added 2026-06-02. Oracle Java SE downloads are SSO-gated, so
        ## the practical push path is the MECM Software Center catalog.
        ## Operator publishes a Java app in SC, then this profile
        ## triggers CCM_Application Install on the matching catalog
        ## entry. Pattern matches *Java* / *Oracle JRE* with conservative
        ## excludes (Helper / Auto Update / Update Scheduler / Web Start);
        ## refine the excludes if SC has multiple Java packages that
        ## both still match the *Java* pattern.
        Desc = 'CCM_Application Install via SCCM client SDK. Triggers the Software Center Java package install -- use when Oracle Java SE CPU vulnerabilities are flagged and a Java app is published in SC.'
        Script = {
            try {
                $ns = 'ROOT\ccm\ClientSDK'
                if (-not (Get-CimClass -Namespace $ns -ClassName CCM_Application -ErrorAction SilentlyContinue)) {
                    return 'FAIL: SCCM client (CCM_Application) not present on this host'
                }
                $apps = @(Get-CimInstance -Namespace $ns -ClassName CCM_Application -ErrorAction Stop)
                if ($apps.Count -eq 0) {
                    return 'FAIL: No CCM_Application objects on this host (SCCM client present but empty)'
                }
                $patterns = @('*Java*','*Oracle JRE*')
                $excludes = @('*Helper*','*Auto Update*','*Update Scheduler*','*Web Start*')
                $candidates = @($apps | Where-Object {
                    $n = "$($_.LocalizedDisplayName) $($_.Name)"
                    $m = $false
                    foreach ($p in $patterns) { if ($n -like $p) { $m = $true; break } }
                    if (-not $m) { return $false }
                    foreach ($x in $excludes) { if ($n -like $x) { return $false } }
                    return $true
                })
                if ($candidates.Count -eq 0) {
                    return 'SKIP: No matching Java app in Software Center catalog'
                }
                $best = $candidates | Sort-Object `
                    @{Expression={ if ($_.ApplicabilityState -eq 'Applicable') { 0 } else { 1 } }; Descending=$false}, `
                    @{Expression={ [bool]$_.IsMachineTarget }; Descending=$true}, `
                    @{Expression={ if ($_.InstallState -eq 'Installed') { 0 } else { 1 } }; Descending=$false} |
                    Select-Object -First 1
                if ($best.ApplicabilityState -ne 'Applicable') {
                    return "SKIP: '$($best.LocalizedDisplayName)' not Applicable (state=$($best.ApplicabilityState))"
                }
                $param = @{
                    EnforcePreference = [UINT32]0
                    Id                = "$($best.Id)"
                    IsMachineTarget   = [System.Convert]::ToBoolean($best.IsMachineTarget)
                    IsRebootIfNeeded  = $false
                    Priority          = 'High'
                    Revision          = "$($best.Revision)"
                }
                Invoke-CimMethod -Namespace 'root/ccm/clientSDK' -ClassName CCM_Application `
                    -MethodName Install -Arguments $param -ErrorAction Stop | Out-Null
                return "OK (Software Center Install triggered: $($best.LocalizedDisplayName) v$($best.SoftwareVersion))"
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
        }
        Verify = {
            ## Read CurrentVersion from the JavaSoft registry, then the
            ## installed build number from jvm.dll's ProductVersion --
            ## that matches the version string Tenable's CPU plugins
            ## enumerate (eg. 8.0.4410.10 -> "8.0.441 build 10").
            $paths = @(
                'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment'
                'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
                'HKLM:\SOFTWARE\JavaSoft\JRE'
                'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\JRE'
            )
            $ver = 'not installed'; $mod = $null; $javaHome = ''
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $pp = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    $cur = if ($pp -and $pp.CurrentVersion) { "$($pp.CurrentVersion)" } else { '' }
                    if (-not $cur) { continue }
                    $sub = Join-Path $p $cur
                    if (Test-Path $sub) {
                        $spp = Get-ItemProperty -Path $sub -ErrorAction SilentlyContinue
                        if ($spp -and $spp.JavaHome) { $javaHome = "$($spp.JavaHome)" }
                        $skey = Get-Item -Path $sub -ErrorAction SilentlyContinue
                        if ($skey) { $mod = $skey.LastWriteTime }
                    }
                    $ver = $cur
                    if ($javaHome) {
                        $jvm = Join-Path $javaHome 'bin\server\jvm.dll'
                        if (-not (Test-Path -LiteralPath $jvm)) { $jvm = Join-Path $javaHome 'bin\client\jvm.dll' }
                        if (Test-Path -LiteralPath $jvm) {
                            try {
                                $fi = (Get-Item -LiteralPath $jvm -ErrorAction Stop).VersionInfo
                                if ($fi.ProductVersion) { $ver = "$($fi.ProductVersion)" }
                                elseif ($fi.FileVersion) { $ver = "$($fi.FileVersion)" }
                            } catch {}
                        }
                    }
                    break
                }
            }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 30 } else { $null }
            $detailStr = if ($javaHome) { "home: $javaHome" } else { 'via Software Center' }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = $detailStr }
        }
    }
}

function Get-WptAppUpdateProfiles { return $global:AppUpdateProfiles }
function Get-WptAppUpdateProfile { param([Parameter(Mandatory)][string]$Name); if ($global:AppUpdateProfiles.ContainsKey($Name)) { return $global:AppUpdateProfiles[$Name] }; return $null }
function Get-WptAppUpdateProfileNames { return @($global:AppUpdateProfiles.Keys | Sort-Object) }
#endregion

###############################################################################
###                          TAB: APP UPDATER  (unified)                    ###
###############################################################################
## Single App Updater tab — replaced both the original inline-profile
## App Updater and the v2 "Profile Registry + Verification" tab in
## v6.5.0. Uses the $global:AppUpdateProfiles registry above. 7-column
## grid: Host / Current Version / Last Updated / Verified? / Action
## Status / Detail. Operator picks a profile from the combo, picks
## hosts from the grid, then:
##   Verify Selected   - runs the profile's Verify scriptblock and
##                       fills in version/last-updated/verified columns.
##   Apply to Selected - runs the profile's Script scriptblock in
##                       parallel via RSPool and paints OK/FAIL per row.
##
## Capabilities ported in v6.5.0 from the now-removed Legacy tab:
##   * Custom Command pseudo-profile + textbox — pick "Custom Command"
##     and the textbox accepts a free-form PowerShell command that is
##     wrapped in a scriptblock at apply time. Verify is unavailable
##     for Custom Command (no canonical state to query).
##   * TCP reachability probe (5985 -> 445, 1.5s each) before every
##     Invoke-Command — same pattern WPT uses elsewhere; matches
##     AFNET's Defender-blocked-ICMP environment.
##   * -SessionOption $global:WSManOpt on every Invoke-Command —
##     bounds the WinRM operation/open/cancel/idle timeouts so an
##     unreachable host doesn't hang for the default ~3 minutes.
##   * Per-host audit fan-out — Write-AuditLog -Action 'AppUpdate'
##     -Target <host> on every completion (was only an aggregate
##     'AppUpdate2 / Started' row in v2). Feeds the Nemesis-style
##     TouchedHosts CSV from v6.4.0.
##   * Auto-refresh on tab enter — populates targets from the shared
##     ComputerList so the operator doesn't have to remember to click
##     Load Targets after a session restart.
#region === TAB: APP UPDATER (unified, v6.5.0) ===

$tabAppUpd2 = New-Object System.Windows.Forms.TabPage
$tabAppUpd2.BackColor = $c.BG
## v6.4.3 / v6.5.13: pre-size the tab page so anchor offsets calibrate
## against a realistic runtime size. Default TabPage size is 200x100 --
## at that size, any child with a 'Bottom' anchor captures a negative
## distance from the parent's bottom edge, which lands the control
## off-screen at runtime. The Verify Selected / Apply to Selected /
## Load Targets button row + log group below were all hitting this.
## v6.5.13: switched from a hard-coded (1170, 660) to $tc.Size so the
## tab matches the TabControl's actual design size (1034, 676) at the
## form's default ClientSize. The previous 1170 caused $grpAU2Prof and
## $lblAU2Sub (no Right anchor) to overflow past the right edge once
## the tab docked into a 1030-wide $tc.
$tabAppUpd2.Size = New-Object System.Drawing.Size($tc.Width, $tc.Height)

## v6.5.13: explicit -H 28 (Title font is 13pt bold mono, default 18 clips).
$lblAU2Title = New-Lbl -Text "App Updater" -X 14 -Y 10 -W 900 -H 28 -Font $fn.Title -Fg $c.Gold
$lblAU2Sub   = New-Lbl -Text "Pre-defined update profiles + free-form Custom Command. Each profile carries a Script (apply) and a Verify (query current version). Uses the shared target list." -X 16 -Y 42 -W 1000 -Font $fn.Sub -Fg $c.Dim

## v6.5.0: PROFILE group taller (90 -> 122) to accommodate the
## Custom Command textbox row that appears below the description.
## v6.5.13: width trimmed 1170 -> 1002 + Top,Left,Right anchor so the
## group stretches with the form instead of clipping at design width.
$grpAU2Prof = New-Grp -Text "PROFILE" -X 14 -Y 74 -W 1002 -H 122 -Fg $c.Accent
$grpAU2Prof.Anchor = 'Top,Left,Right'
$lblAU2ProfLbl = New-Lbl -Text "Profile:" -X 12 -Y 24 -W 60 -Font $fn.LabelB -Fg $c.White
$script:comboAU2 = New-Object System.Windows.Forms.ComboBox
$script:comboAU2.Location      = New-Object System.Drawing.Point(76, 22)
$script:comboAU2.Size          = New-Object System.Drawing.Size(380, 24)
$script:comboAU2.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$script:comboAU2.BackColor     = $c.Input; $script:comboAU2.ForeColor = $c.White; $script:comboAU2.Font = $fn.Label
foreach ($n in (Get-WptAppUpdateProfileNames)) { [void]$script:comboAU2.Items.Add($n) }
## v6.5.0: synthetic "Custom Command" entry — not in the registry,
## handled inline at apply time. Verify is unavailable for it.
[void]$script:comboAU2.Items.Add('Custom Command')
if ($script:comboAU2.Items.Count -gt 0) { $script:comboAU2.SelectedIndex = 0 }
$script:lblAU2Desc = New-Lbl -Text '' -X 12 -Y 56 -W 982 -Font $fn.Small -Fg $c.Dim
$script:lblAU2Desc.Anchor = 'Top,Left,Right'

## Dual-purpose row (Y=86) — repurposed in v6.5.2 to also serve the
## Log4j profile's source-share override.
##   Custom Command profile: textbox holds the operator's PowerShell
##                           command, label reads "Command:".
##   Log4j profile:          textbox holds the source path for the
##                           replacement jars, label reads "Jar
##                           source:". Pre-filled with
##                           $global:Log4jDefaultSource on selection
##                           so the operator can see + edit the path.
##   Other profiles:         textbox disabled and cleared.
$lblAU2CmdLbl = New-Lbl -Text "Command:" -X 12 -Y 90 -W 80 -Font $fn.LabelB -Fg $c.TextSec
$script:txtAU2Custom = New-Tb -X 94 -Y 86 -W 902 -H 24
$script:txtAU2Custom.Font      = $fn.Console
$script:txtAU2Custom.ForeColor = $c.Cyan
$script:txtAU2Custom.Enabled   = $false
$script:txtAU2Custom.Anchor    = 'Top,Left,Right'

$script:comboAU2.Add_SelectedIndexChanged({
    $sel = [string]$script:comboAU2.SelectedItem
    if ($sel -eq 'Custom Command') {
        $script:txtAU2Custom.Enabled = $true
        $script:txtAU2Custom.Clear()
        $lblAU2CmdLbl.Text          = 'Command:'
        $script:lblAU2Desc.Text     = 'Free-form PowerShell. Runs on each selected target via Invoke-Command. Verify is unavailable for Custom Command.'
    } elseif ($sel -eq 'Apache Log4j - Replace Vulnerable Jars') {
        $script:txtAU2Custom.Enabled = $true
        $script:txtAU2Custom.Text    = [string]$global:Log4jDefaultSource
        $lblAU2CmdLbl.Text           = 'Jar source:'
        $prof = Get-WptAppUpdateProfile -Name $sel
        if ($prof) { $script:lblAU2Desc.Text = [string]$prof.Desc }
    } else {
        $script:txtAU2Custom.Enabled = $false
        $script:txtAU2Custom.Clear()
        $lblAU2CmdLbl.Text          = 'Command:'
        $prof = Get-WptAppUpdateProfile -Name $sel
        if ($prof) { $script:lblAU2Desc.Text = [string]$prof.Desc }
    }
})
if ($script:comboAU2.SelectedItem) {
    $sel0 = [string]$script:comboAU2.SelectedItem
    if ($sel0 -eq 'Apache Log4j - Replace Vulnerable Jars') {
        $script:txtAU2Custom.Enabled = $true
        $script:txtAU2Custom.Text    = [string]$global:Log4jDefaultSource
        $lblAU2CmdLbl.Text           = 'Jar source:'
        $p0 = Get-WptAppUpdateProfile -Name $sel0
        if ($p0) { $script:lblAU2Desc.Text = [string]$p0.Desc }
    } elseif ($sel0 -ne 'Custom Command') {
        $p0 = Get-WptAppUpdateProfile -Name $sel0
        if ($p0) { $script:lblAU2Desc.Text = [string]$p0.Desc }
    }
}
$grpAU2Prof.Controls.AddRange(@($lblAU2ProfLbl, $script:comboAU2, $script:lblAU2Desc, $lblAU2CmdLbl, $script:txtAU2Custom))

$script:dgvAU2 = New-Object System.Windows.Forms.DataGridView
## v6.5.0: Y=206 (was 174). PROFILE group above grew from H=90 to
## H=122 to fit the Custom Command row, so the grid starts 32px
## lower. Initial height 224 (was 256) keeps the captured
## bottom-distance the same — grid still fills the gap to the
## bottom-anchored buttons row.
$script:dgvAU2.Location = New-Object System.Drawing.Point(14, 206)
$script:dgvAU2.Size     = New-Object System.Drawing.Size(1002, 224)
## v6.4.3: anchor all four edges so the grid grows vertically with
## the form. Bottom anchor + the pre-sized tab page above means the
## button row and log group below stay aligned regardless of form
## size.
$script:dgvAU2.Anchor   = 'Top,Left,Right,Bottom'
Style-Grid $script:dgvAU2
$au2Chk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$au2Chk.Name = 'chkSel'; $au2Chk.HeaderText = ''; $au2Chk.Width = 30
$script:dgvAU2.Columns.Add($au2Chk) | Out-Null
$script:dgvAU2.Columns.Add('Host','Host') | Out-Null
$script:dgvAU2.Columns.Add('Version','Current Version') | Out-Null
$script:dgvAU2.Columns.Add('LastUpdated','Last Updated') | Out-Null
$script:dgvAU2.Columns.Add('Verified','Verified?') | Out-Null
$script:dgvAU2.Columns.Add('Status','Action Status') | Out-Null
$script:dgvAU2.Columns.Add('Detail','Detail') | Out-Null

## v6.4.3: button row Y=440 (was 490). All buttons + the progress
## label are anchored Bottom,Left so they stay glued to the bottom of
## the tab page when the form resizes — the previous layout had no
## anchor, so they sat at a fixed offset from the top and slid out
## of view when the tab page shrunk vertically. lblAU2Prog also gets
## a Right anchor so it stretches to fill the row.
## v6.5.5: added Cancel button between Apply and Select All. Stops
## the in-flight Apply runspaces + Verify foreach loop and re-enables
## Apply. Disabled by default; Apply / Verify handlers flip it on
## while a run is in progress and back off when complete.
$script:btnAU2Load   = New-Btn -Text "Load Targets"      -X 14  -Y 440 -W 130 -H 32 -Bg $c.Cyan
$script:btnAU2Verify = New-Btn -Text "Verify Selected"   -X 152 -Y 440 -W 150 -H 32 -Bg $c.Accent
$script:btnAU2Apply  = New-Btn -Text "Apply to Selected" -X 310 -Y 440 -W 160 -H 32 -Bg $c.Success
$script:btnAU2Cancel = New-Btn -Text "Cancel"            -X 478 -Y 440 -W 100 -H 32 -Bg $c.Danger
$script:btnAU2Cancel.Enabled = $false
$script:btnAU2All    = New-Btn -Text "Select All"        -X 586 -Y 440 -W 100 -H 32 -Bg $c.PanelLight
$script:btnAU2None   = New-Btn -Text "Deselect All"      -X 694 -Y 440 -W 110 -H 32 -Bg $c.PanelLight
$script:lblAU2Prog   = New-Lbl -Text "Idle" -X 816 -Y 446 -W 200 -Font $fn.LabelB -Fg $c.Dim
$script:lblAU2Prog.AutoEllipsis = $true
$script:lblAU2Prog.TextAlign    = 'MiddleLeft'
$script:btnAU2Load.Anchor   = 'Bottom,Left'
$script:btnAU2Verify.Anchor = 'Bottom,Left'
$script:btnAU2Apply.Anchor  = 'Bottom,Left'
$script:btnAU2Cancel.Anchor = 'Bottom,Left'
$script:btnAU2All.Anchor    = 'Bottom,Left'
$script:btnAU2None.Anchor   = 'Bottom,Left'
$script:lblAU2Prog.Anchor   = 'Bottom,Left,Right'

## v6.4.3: log group anchored Bottom,Left,Right (was Top,Left,Right,
## Bottom). With Top+Bottom anchored against a 100-tall default
## TabPage, the captured offsets stretched the group to ~780 tall at
## runtime, eating the buttons row above. Bottom-only anchor with a
## fixed height keeps it glued to the form bottom; the grid above
## absorbs the variable space.
$grpAU2Log = New-Grp -Text "APP UPDATER v2 LOG" -X 14 -Y 480 -W 1002 -H 174 -Fg $c.Cyan
$grpAU2Log.Anchor = 'Bottom,Left,Right'
$script:rtbAU2Log = New-Object System.Windows.Forms.RichTextBox
$script:rtbAU2Log.Location    = New-Object System.Drawing.Point(10, 22)
$script:rtbAU2Log.Size        = New-Object System.Drawing.Size(982, 144)
$script:rtbAU2Log.Anchor      = 'Top,Left,Right,Bottom'
$script:rtbAU2Log.BackColor   = $c.OutputBg
$script:rtbAU2Log.ForeColor   = $c.Console
$script:rtbAU2Log.Font        = $fn.Console
$script:rtbAU2Log.ReadOnly    = $true
## v6.5.1: BorderStyle FixedSingle (was None). With None against the
## near-black OutputBg the scroll bar rendered with matching color
## and was effectively invisible. Same fix the Cleanup tab made in
## v6.1.7 for rtbCleanExec / rtbCleanLog.
$script:rtbAU2Log.BorderStyle = 'FixedSingle'
$script:rtbAU2Log.WordWrap    = $false
## v6.5.1: ScrollBars 'Both' (was 'Vertical'). WordWrap is off so
## long lines run past the viewport edge — without a horizontal bar
## the operator couldn't see anything past column ~1100. Vertical
## still appears when content overflows.
$script:rtbAU2Log.ScrollBars  = 'Both'
$grpAU2Log.Controls.Add($script:rtbAU2Log)

## v6.5.1: tail-following auto-scroll. Capture whether the operator
## is parked near the end BEFORE we append. If yes, ScrollToCaret
## after to keep them following live output. If no (they scrolled
## up to read older entries), restore their scroll position so the
## new line doesn't yank the view back to the bottom mid-read.
## Win32 GETSCROLLINFO is the only reliable way to read the actual
## scroll thumb position on a RichTextBox; SelectionStart drifts
## with caret-only operations and isn't a stable proxy for view.
if (-not ('Wpt.RichScrollPInvoke' -as [type])) {
    Add-Type -Namespace 'Wpt' -Name 'RichScrollPInvoke' -MemberDefinition @'
        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SCROLLINFO {
            public uint cbSize;
            public uint fMask;
            public int  nMin;
            public int  nMax;
            public uint nPage;
            public int  nPos;
            public int  nTrackPos;
        }
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool GetScrollInfo(System.IntPtr hwnd, int fnBar, ref SCROLLINFO lpsi);
'@
}

function AU2Log($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbAU2Log) {
        try {
            if (-not $script:rtbAU2Log.IsHandleCreated) { $script:rtbAU2Log.CreateControl() }

            ## Was the operator at the tail before this append?
            $atTail = $true
            try {
                $si = New-Object 'Wpt.RichScrollPInvoke+SCROLLINFO'
                $si.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]'Wpt.RichScrollPInvoke+SCROLLINFO')
                ## SIF_ALL = 0x17 (range + page + pos + trackpos), SB_VERT = 1
                $si.fMask = 0x17
                if ([Wpt.RichScrollPInvoke]::GetScrollInfo($script:rtbAU2Log.Handle, 1, [ref]$si)) {
                    $bottom = $si.nPos + [int]$si.nPage
                    ## At-tail tolerance: within 3 line-heights of the bottom.
                    $atTail = ($bottom -ge ($si.nMax - 3))
                }
            } catch { $atTail = $true }

            $start = $script:rtbAU2Log.TextLength
            $script:rtbAU2Log.AppendText($line)
            $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
            $script:rtbAU2Log.Select($start, $line.Length); $script:rtbAU2Log.SelectionColor = $clr; $script:rtbAU2Log.SelectionLength = 0
            if ($atTail) { $script:rtbAU2Log.ScrollToCaret() }
        } catch { try { $script:rtbAU2Log.AppendText($line) } catch {} }
    }
    Log "[AppUpd2] $msg" $lvl
    [System.Windows.Forms.Application]::DoEvents()
}

$script:btnAU2Load.Add_Click({
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    $script:dgvAU2.Rows.Clear()
    foreach ($comp in $global:ComputerList) {
        $idx = $script:dgvAU2.Rows.Add()
        $row = $script:dgvAU2.Rows[$idx]
        $row.Cells[0].Value = $false
        $row.Cells[1].Value = $comp
        $row.Cells[2].Value = '--'
        $row.Cells[3].Value = '--'
        $row.Cells[4].Value = '--'
        $row.Cells[5].Value = ''
        $row.Cells[6].Value = ''
    }
    AU2Log "Loaded $($global:ComputerList.Count) target(s) from shared list"
})

$script:btnAU2All.Add_Click({ foreach ($r in $script:dgvAU2.Rows) { $r.Cells[0].Value = $true } })
$script:btnAU2None.Add_Click({ foreach ($r in $script:dgvAU2.Rows) { $r.Cells[0].Value = $false } })

## v6.5.5: cancel handler.
##   * Apply path  : stops every PowerShell instance in $script:AU2Jobs,
##                   stops + disposes the drain timer, marks unfinished
##                   rows as Cancelled, re-enables Apply.
##   * Verify path : sets $script:AU2VerifyCancelled which the Verify
##                   foreach checks at the top of every iteration. Mid-
##                   Invoke-Command calls cannot be interrupted, but
##                   DoEvents inside the loop pumps this click event so
##                   the next iteration sees the flag and breaks.
## Confirm dialog before stopping — accidental clicks on Cancel mid-run
## would otherwise leave half-finished swaps with no easy way to know
## which hosts got which version.
$script:btnAU2Cancel.Add_Click({
    $haveJobs   = ($null -ne $script:AU2Jobs   -and $script:AU2Jobs.Count -gt 0)
    $haveVerify = $script:btnAU2Verify -and -not $script:btnAU2Verify.Enabled
    if (-not $haveJobs -and -not $haveVerify) { return }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Stop the in-progress App Updater run?`r`n`r`nIn-flight remote operations may complete on the target anyway, but no further results will be processed and any not-yet-dispatched hosts will be skipped.",
        "Confirm Cancel", 4, 48)
    if ($confirm -ne 'Yes') { return }

    $cancelled = 0
    if ($haveJobs) {
        foreach ($key in @($script:AU2Jobs.Keys)) {
            $job = $script:AU2Jobs[$key]
            try { $job.PS.Stop() }    catch {}
            try { $job.PS.Dispose() } catch {}
            $cancelled++
        }
        $script:AU2Jobs = @{}

        if ($script:AU2Timer) {
            try { $script:AU2Timer.Stop()    } catch {}
            try { $script:AU2Timer.Dispose() } catch {}
            $script:AU2Timer = $null
        }
    }

    ## Verify-loop kill switch (read at the top of each foreach iteration
    ## inside btnAU2Verify.Add_Click).
    $script:AU2VerifyCancelled = $true

    ## Mark any row still showing an in-progress status. Don't touch
    ## rows that already have a final status (OK / FAIL / Verified /
    ## Unreachable) — those are real results from completed jobs.
    foreach ($row in $script:dgvAU2.Rows) {
        $st = [string]$row.Cells[5].Value
        if ($st -in @('Applying...', 'Verifying...', 'Probing...')) {
            $row.Cells[5].Value = 'Cancelled'
            $row.Cells[5].Style.ForeColor = $c.Warning
        }
    }

    AU2Log "=== Cancelled by operator ($cancelled job(s) stopped) ===" 'WARN'
    Write-AuditLog -Action "AppUpdate" -Result "Cancelled" -Detail "stopped=$cancelled"

    $script:lblAU2Prog.Text      = "Cancelled ($cancelled job(s) stopped)"
    $script:lblAU2Prog.ForeColor = $c.Warning
    $script:btnAU2Apply.Enabled  = $true
    $script:btnAU2Verify.Enabled = $true
    $script:btnAU2Cancel.Enabled = $false
})

## v6.5.0: TCP reachability probe (5985 -> 445, 1.5s each). Same
## probe pattern WPT uses elsewhere; matches AFNET's blocked-ICMP
## reality. Returns $true if either WinRM or SMB answers within
## 1.5s. Used as a precheck before Invoke-Command on every Verify
## and Apply call so an unreachable host fails fast instead of
## hanging on the WSMan timeout.
function global:Test-AU2Reachable {
    param([Parameter(Mandatory)] [string] $Computer)
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                return $true
            }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}

## Runs the profile's Verify block on selected hosts via Invoke-Command.
$script:btnAU2Verify.Add_Click({
    $selected = @(); foreach ($row in $script:dgvAU2.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No hosts selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    if (-not $script:comboAU2.SelectedItem) { [System.Windows.Forms.MessageBox]::Show("Pick a profile first.","No Profile"); return }
    $profName = [string]$script:comboAU2.SelectedItem
    if ($profName -eq 'Custom Command') {
        [System.Windows.Forms.MessageBox]::Show("Verify is not available for Custom Command — there is no canonical state to query.","No Verify")
        return
    }
    $prof = Get-WptAppUpdateProfile -Name $profName
    if (-not $prof -or -not $prof.Verify) { [System.Windows.Forms.MessageBox]::Show("Profile has no Verify scriptblock.","No Verify"); return }
    $script:btnAU2Verify.Enabled       = $false
    $script:btnAU2Apply.Enabled        = $false
    $script:btnAU2Cancel.Enabled       = $true
    $script:AU2VerifyCancelled         = $false
    AU2Log "=== Verify ($profName) on $($selected.Count) host(s) ===" 'OK'
    Write-AuditLog -Action "AppUpdate" -Result "VerifyStart" -Detail "Profile=$profName Targets=$($selected.Count)"
    foreach ($srv in $selected) {
        ## v6.5.5: cancel kill-switch — break out of the foreach if
        ## the operator clicked Cancel since the last DoEvents pump.
        if ($script:AU2VerifyCancelled) {
            AU2Log "=== Verify cancelled by operator ===" 'WARN'
            break
        }
        $row = $null; foreach ($r in $script:dgvAU2.Rows) { if ($r.Cells[1].Value -eq $srv) { $row = $r; break } }
        if ($null -eq $row) { continue }
        $row.Cells[5].Value = 'Probing...'; $row.Cells[5].Style.ForeColor = $c.Warning
        [System.Windows.Forms.Application]::DoEvents()

        ## v6.5.0: TCP probe before invoking. Saves ~3 minutes per
        ## unreachable host that would otherwise stall on WSMan
        ## timeout — frequent on AFNET workstations off-domain.
        if (-not (Test-AU2Reachable -Computer $srv)) {
            $row.Cells[5].Value = 'Unreachable (TCP 5985/445)'
            $row.Cells[5].Style.ForeColor = $c.Danger
            AU2Log "$srv : unreachable (TCP 5985/445)" 'ERR'
            Write-AuditLog -Action "AppUpdate" -Target $srv -Result "Failed" -Detail "Verify ${profName}: unreachable"
            continue
        }

        $row.Cells[5].Value = 'Verifying...'
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $res = Invoke-Command -ComputerName $srv -Credential $global:Credentials -Authentication Negotiate -SessionOption $global:WSManOpt -ScriptBlock $prof.Verify -ErrorAction Stop
            $row.Cells[2].Value = [string]$res.Version
            $row.Cells[3].Value = [string]$res.LastUpdated
            $row.Cells[4].Value = if ($null -eq $res.Verified) { 'n/a' } elseif ($res.Verified) { 'Yes' } else { 'No' }
            $row.Cells[4].Style.ForeColor = if ($res.Verified -eq $true) { $c.Success } elseif ($res.Verified -eq $false) { $c.Danger } else { $c.Dim }
            $row.Cells[5].Value = 'Verified'
            $row.Cells[5].Style.ForeColor = $c.Success
            $row.Cells[6].Value = [string]$res.Detail
            AU2Log "$srv : $($res.Version) (updated $($res.LastUpdated))"
            ## v6.5.0: per-host audit row so the TouchedHosts CSV
            ## fan-out (Write-AuditLog hook from v6.4.0) captures
            ## every Verify completion, not just the aggregate
            ## Started event.
            Write-AuditLog -Action "AppUpdate" -Target $srv -Result "Verified" -Detail "Profile=$profName Version=$($res.Version) LastUpdated=$($res.LastUpdated)"
        } catch {
            $row.Cells[5].Value = "FAIL: $($_.Exception.Message)"
            $row.Cells[5].Style.ForeColor = $c.Danger
            AU2Log "$srv : verify failed - $($_.Exception.Message)" 'ERR'
            Write-AuditLog -Action "AppUpdate" -Target $srv -Result "Failed" -Detail "Verify ${profName}: $($_.Exception.Message)"
        }
    }
    if (-not $script:AU2VerifyCancelled) { AU2Log "=== Verify complete ===" 'OK' }
    $script:btnAU2Verify.Enabled = $true
    $script:btnAU2Apply.Enabled  = $true
    $script:btnAU2Cancel.Enabled = $false
})

## Fires the profile's Script block on selected hosts in parallel via RunspacePool.
$script:btnAU2Apply.Add_Click({
    $selected = @(); foreach ($row in $script:dgvAU2.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No hosts selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    if (-not $script:comboAU2.SelectedItem) { [System.Windows.Forms.MessageBox]::Show("Pick a profile first.","No Profile"); return }
    $profName = [string]$script:comboAU2.SelectedItem

    ## v6.5.0: Custom Command path. v6.5.2 adds Log4j source-share
    ## override. Build the apply scriptblock based on profile:
    ##   Custom Command -> textbox text wrapped in [ScriptBlock]
    ##   Log4j           -> registry script with $sourceShare swapped
    ##                      for the textbox's path
    ##   other           -> registry script as-is
    $applyScript = $null
    if ($profName -eq 'Custom Command') {
        $cmd = ([string]$script:txtAU2Custom.Text).Trim()
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            [System.Windows.Forms.MessageBox]::Show("Enter a custom command in the Command box.","No Command")
            return
        }
        try {
            $applyScript = [ScriptBlock]::Create($cmd)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Custom command failed to parse:`r`n$($_.Exception.Message)","Parse Error",0,16)
            return
        }
    } elseif ($profName -eq 'Apache Log4j - Replace Vulnerable Jars') {
        $prof = Get-WptAppUpdateProfile -Name $profName
        if (-not $prof -or -not $prof.Script) { [System.Windows.Forms.MessageBox]::Show("Profile has no Script scriptblock.","No Script"); return }
        $opPath = ([string]$script:txtAU2Custom.Text).Trim()
        if ([string]::IsNullOrWhiteSpace($opPath)) { $opPath = [string]$global:Log4jDefaultSource }
        if ([string]::IsNullOrWhiteSpace($opPath)) {
            [System.Windows.Forms.MessageBox]::Show("Log4j source path is empty. Set the Jar source: textbox to a folder containing log4j-api-2.25.4.jar + log4j-core-2.25.4.jar.","No Source Path")
            return
        }
        ## v6.5.3: controller-side pre-check. If the jars aren't
        ## where the operator says they are FROM THIS WORKSTATION,
        ## fail fast with a clear message instead of dispatching N
        ## runspaces that all fail the same way. The wrapper's stage
        ## push picks them up from this same path on the controller,
        ## so this check is authoritative.
        $localApi  = Join-Path $opPath 'log4j-api-2.25.4.jar'
        $localCore = Join-Path $opPath 'log4j-core-2.25.4.jar'
        if (-not (Test-Path -LiteralPath $localApi)) {
            [System.Windows.Forms.MessageBox]::Show("Source jar not found:`r`n$localApi`r`n`r`nThis path is checked from THIS workstation. Make sure the jars exist at the path in the Jar source: box on this machine — they'll be pushed to each remote target over the WinRM session at apply time.","Source Jar Missing",0,16)
            return
        }
        if (-not (Test-Path -LiteralPath $localCore)) {
            [System.Windows.Forms.MessageBox]::Show("Source jar not found:`r`n$localCore`r`n`r`nThis path is checked from THIS workstation. Make sure the jars exist at the path in the Jar source: box on this machine — they'll be pushed to each remote target over the WinRM session at apply time.","Source Jar Missing",0,16)
            return
        }
        ## Substitution skipped here on purpose — the wrapper does
        ## the substitution AFTER staging the jars to a remote-local
        ## temp dir, so the script ends up reading from the staged
        ## path on the target instead of trying to UNC-traverse to
        ## a path the remote may not be able to reach.
        $applyScript = $prof.Script
        AU2Log "Log4j source: $opPath (controller-side; will stage to each remote target)" 'OK'
    } else {
        $prof = Get-WptAppUpdateProfile -Name $profName
        if (-not $prof -or -not $prof.Script) { [System.Windows.Forms.MessageBox]::Show("Profile has no Script scriptblock.","No Script"); return }
        $applyScript = $prof.Script
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show("Apply '$profName' to $($selected.Count) host(s)?","Confirm Apply",4,48)
    if ($confirm -ne 'Yes') { return }
    $script:btnAU2Apply.Enabled  = $false
    $script:btnAU2Verify.Enabled = $false
    $script:btnAU2Cancel.Enabled = $true
    foreach ($srv in $selected) {
        foreach ($row in $script:dgvAU2.Rows) { if ($row.Cells[1].Value -eq $srv) { $row.Cells[5].Value = 'Applying...'; $row.Cells[5].Style.ForeColor = $c.Warning; break } }
    }
    AU2Log "=== Apply ($profName) on $($selected.Count) host(s) ===" 'OK'
    Write-AuditLog -Action "AppUpdate" -Result "Started" -Detail "Profile=$profName Targets=$($selected.Count)"
    Initialize-RunspacePool
    $script:AU2Jobs = @{}
    ## v6.5.3: wrapper switched from Invoke-Command -ComputerName
    ## (one-shot) to New-PSSession + Invoke-Command -Session so the
    ## Log4j staging path (Copy-Item -ToSession) has a persistent
    ## session to push jars over. Staging only fires for the Log4j
    ## profile; all other profiles just run the Inner scriptblock
    ## once over the same session and ignore the staging args.
    ## The remote-side stage dir is C:\Windows\Temp\janet-log4j-
    ## stage-<guid> and gets cleaned up in the wrapper's finally
    ## block whether the swap succeeds or fails.
    $wrapperSb = {
        param([string]$Computer, [pscredential]$Credential, [string]$AuthMethod, [scriptblock]$Inner, [string]$ProfileName, [string]$Log4jSrcPath)
        $r = @{ Host=$Computer; Success=$false; Detail=''; StartTime=(Get-Date) }
        $reachable = $false
        foreach ($port in 5985, 445) {
            $tc = $null
            try {
                $tc  = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
            } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
            if ($reachable) { break }
        }
        if (-not $reachable) {
            $r.Detail = 'Unreachable (TCP 5985/445)'
            $r.EndTime = Get-Date
            return $r
        }
        $opt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $sess = $null
        $remoteStageDir = $null
        try {
            $sess = New-PSSession -ComputerName $Computer -Credential $Credential -Authentication $AuthMethod -SessionOption $opt -ErrorAction Stop

            ## v6.5.3: Log4j stage push. Verify jars exist on the
            ## controller, mkdir on the remote, push via session,
            ## substitute the remote stage dir into the script's
            ## $sourceShare literal so the swap reads from there.
            $effectiveInner = $Inner
            if ($ProfileName -eq 'Apache Log4j - Replace Vulnerable Jars') {
                if ([string]::IsNullOrWhiteSpace($Log4jSrcPath)) {
                    $r.Detail = 'FAIL: Log4j source path not set'
                    $r.EndTime = Get-Date
                    return $r
                }
                $localApi  = Join-Path $Log4jSrcPath 'log4j-api-2.25.4.jar'
                $localCore = Join-Path $Log4jSrcPath 'log4j-core-2.25.4.jar'
                if (-not (Test-Path -LiteralPath $localApi)) {
                    $r.Detail = "FAIL: source jar missing on controller: $localApi"
                    $r.EndTime = Get-Date
                    return $r
                }
                if (-not (Test-Path -LiteralPath $localCore)) {
                    $r.Detail = "FAIL: source jar missing on controller: $localCore"
                    $r.EndTime = Get-Date
                    return $r
                }
                $stageGuid      = [guid]::NewGuid().ToString('N').Substring(0,8)
                $remoteStageDir = "C:\Windows\Temp\janet-log4j-stage-$stageGuid"
                Invoke-Command -Session $sess -ScriptBlock {
                    param($d)
                    New-Item -Path $d -ItemType Directory -Force -ErrorAction Stop | Out-Null
                } -ArgumentList $remoteStageDir -ErrorAction Stop
                Copy-Item -Path $localApi  -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop
                Copy-Item -Path $localCore -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop

                $innerText  = $Inner.ToString()
                $escPath    = $remoteStageDir.Replace("'", "''")
                $innerText  = [regex]::Replace($innerText, "(?<=\`$sourceShare\s*=\s*')[^']*", $escPath)
                $effectiveInner = [scriptblock]::Create($innerText)
            }

            $res = Invoke-Command -Session $sess -ScriptBlock $effectiveInner -ErrorAction Stop
            $r.Detail = [string]$res
            $r.Success = ($r.Detail -like 'OK*')
        } catch {
            $r.Detail = $_.Exception.Message
        } finally {
            if ($remoteStageDir -and $sess) {
                try {
                    Invoke-Command -Session $sess -ScriptBlock {
                        param($d)
                        Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
                    } -ArgumentList $remoteStageDir -ErrorAction SilentlyContinue
                } catch {}
            }
            if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
        }
        $r.EndTime = Get-Date
        return $r
    }
    ## v6.5.3: pass profile name + Log4j source path to the wrapper.
    ## $log4jOpPath comes from the textbox via the Apply branch above
    ## — empty string when the profile isn't Log4j (wrapper ignores).
    $log4jOpPath = ''
    if ($profName -eq 'Apache Log4j - Replace Vulnerable Jars') {
        $tmp = ([string]$script:txtAU2Custom.Text).Trim()
        $log4jOpPath = if ([string]::IsNullOrWhiteSpace($tmp)) { [string]$global:Log4jDefaultSource } else { $tmp }
    }
    foreach ($comp in $selected) {
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($wrapperSb).AddArgument($comp).AddArgument($global:Credentials).AddArgument('Negotiate').AddArgument($applyScript).AddArgument($profName).AddArgument($log4jOpPath)
        $script:AU2Jobs[$comp] = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    $script:AU2Total = $selected.Count
    $script:AU2Timer = New-Object System.Windows.Forms.Timer
    $script:AU2Timer.Interval = 700
    $script:AU2Timer.Add_Tick({
        foreach ($key in @($script:AU2Jobs.Keys)) {
            $job = $script:AU2Jobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
            catch { $res = @{ Host=$key; Success=$false; Detail=$_.ToString() } }
            $script:AU2Jobs.Remove($key)
            if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            foreach ($row in $script:dgvAU2.Rows) {
                if ($row.Cells[1].Value -eq $res.Host) {
                    if ($res.Success) {
                        $row.Cells[5].Value = 'OK'; $row.Cells[5].Style.ForeColor = $c.Success
                    } else {
                        $row.Cells[5].Value = 'FAIL'; $row.Cells[5].Style.ForeColor = $c.Danger
                    }
                    $row.Cells[6].Value = [string]$res.Detail
                    break
                }
            }
            AU2Log "$($res.Host): $($res.Detail)" $(if ($res.Success) { 'OK' } else { 'ERR' })
            ## v6.5.0: Action 'AppUpdate' (was 'AppUpdate2'). Per-host
            ## audit fan-out via Write-AuditLog so the Nemesis-style
            ## TouchedHosts CSV captures every completion (not just
            ## the aggregate Started row), and Track-Action keeps the
            ## existing usage-summary rollup happy.
            Track-Action -Action 'AppUpdate' -Target $res.Host -Result $(if ($res.Success) { 'OK' } else { 'Fail' }) -Detail $res.Detail
            Write-AuditLog -Action "AppUpdate" -Target $res.Host -Result $(if ($res.Success) { 'OK' } else { 'Failed' }) -Detail $res.Detail
        }
        $done = $script:AU2Total - $script:AU2Jobs.Count
        $script:lblAU2Prog.Text = "Applying $done / $script:AU2Total"
        if ($script:AU2Jobs.Count -eq 0) {
            $script:AU2Timer.Stop(); $script:AU2Timer.Dispose(); $script:AU2Timer = $null
            $script:btnAU2Apply.Enabled  = $true
            $script:btnAU2Verify.Enabled = $true
            $script:btnAU2Cancel.Enabled = $false
            $script:lblAU2Prog.Text      = "Apply complete"
            $script:lblAU2Prog.ForeColor = $c.Success
            AU2Log "=== Apply complete ===" 'OK'
        }
    })
    $script:AU2Timer.Start()
})

$tabAppUpd2.Controls.AddRange(@($lblAU2Title, $lblAU2Sub, $grpAU2Prof, $script:dgvAU2, $script:btnAU2Load, $script:btnAU2Verify, $script:btnAU2Apply, $script:btnAU2Cancel, $script:btnAU2All, $script:btnAU2None, $script:lblAU2Prog, $grpAU2Log))

## v6.5.0: auto-refresh on tab enter — populate the grid from the
## shared ComputerList if it's empty. Mirrors the Cleanup tab's
## Add_Enter pattern so the operator doesn't have to remember to
## click Load Targets after a session restart.
$tabAppUpd2.Add_Enter({
    if ($script:dgvAU2.Rows.Count -eq 0 -and $global:ComputerList.Count -gt 0) {
        foreach ($comp in $global:ComputerList) {
            $idx = $script:dgvAU2.Rows.Add()
            $row = $script:dgvAU2.Rows[$idx]
            $row.Cells[0].Value = $false
            $row.Cells[1].Value = $comp
            $row.Cells[2].Value = '--'
            $row.Cells[3].Value = '--'
            $row.Cells[4].Value = '--'
            $row.Cells[5].Value = ''
            $row.Cells[6].Value = ''
        }
    }
})
#endregion

###############################################################################
###                       CLOSING FLOW + USAGE CSV                          ###
###############################################################################
## Infrastructure powering the "on form close, write one aggregated
## session row to the shared CSV" feature. Key pieces:
##   Get-WptState              - accessor that returns $script:WPT for
##                               modular-style call sites.
##   $global:WptUsage          - session runtime state (SessionStartTime,
##                               SessionRunId, OperatorFullName, CsvPath).
##   Get-WptOperatorFullName   - ADSI DirectorySearcher lookup of the
##                               current user's AD displayName. Cached.
##                               Returns '' off-domain.
##   Resolve-WptUsageCsvPath   - figures out where WPT-UsageV2-<YYYY-MM>.csv
##                               lives (config share first, then local
##                               Logs folder, then temp).
##   Get-WptUsageSummary       - aggregates $global:ActionHistory into
##                               Count / Ok / Fail per action family
##                               (Scan / Patch / Reboot / KBInstall /
##                               AppUpdate / Cleanup / Heal / Message /
##                               AcasRemediation).
##   Publish-WptUsageCsvRow    - writes the v2 header (30 cols) if the
##                               monthly file doesn't exist, then appends
##                               ONE row with Timestamp / User /
##                               SessionStart / Duration / RunId / Notes
##                               + the aggregated counts. Notes are
##                               whatever the operator typed in the
##                               closing notes dialog.
##   Publish-WptUsageJournal   - thin compat alias used by the inlined
##                               modular Invoke-WptClosingFlow.
##   Write-WptAudit            - forwards modular-style -Action/-Target/
##                               -Result/-Detail calls to Legacy's
##                               Write-AuditLog.
## The Add_FormClosing handler that calls this flow is inside FORM
## CLEANUP & SHOW (bottom of the file).
#region === CLOSING FLOW + USAGE CSV (v47.1 Phase 3 - modular-ported) ===
## Wires the modular closing-notes dialog (inlined in Task 1.7) into a NEW
## $f.Add_FormClosing handler that runs ALONGSIDE Legacy's existing cleanup
## handler. On close: show dialog, capture notes, write a single aggregated
## row to the shared WPT-UsageV2-YYYY-MM.csv. Counts come from Legacy's
## $global:ActionHistory (no separate journal needed). Legacy's cleanup
## handler (timers/jobs/pool dispose) is NOT modified.

## Shim for modular Get-WptState so inlined Dialog.Closing functions resolve.
function Get-WptState { return $script:WPT }

$global:WptUsage = @{
    SessionStartTime = (Get-Date)
    SessionRunId     = "$((Get-Date).ToString('yyyyMMdd-HHmmss'))-$('{0:x4}' -f (Get-Random -Minimum 0 -Maximum 65536))"
    OperatorFullName = $null
    CsvPath          = $null
}

function Get-WptOperatorFullName {
    <#
    .SYNOPSIS
        AD displayName lookup for the current $env:USERNAME via ADSI (no module needed).
        Returns '' on any failure; caller falls back to bare EDIPI.
    #>
    [CmdletBinding()]
    param()
    if ($global:WptUsage.OperatorFullName -ne $null) { return $global:WptUsage.OperatorFullName }
    $edipi = $env:USERNAME
    $full = ''
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter     = "(&(objectCategory=user)(sAMAccountName=$edipi))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $searcher.SizeLimit  = 1
        $searcher.ClientTimeout = [System.TimeSpan]::FromSeconds(3)
        $res = $searcher.FindOne()
        if ($res -and $res.Properties['displayname']) { $full = [string]$res.Properties['displayname'][0] }
    } catch { $full = '' }
    $global:WptUsage.OperatorFullName = $full
    return $full
}

function Resolve-WptUsageCsvPath {
    <#
    .SYNOPSIS
        Monthly CSV path: WPT-UsageV2-YYYY-MM.csv. Prefers a configured share
        (WPT.config.json: usageCsvShare or logShare), falls back to the local
        Logs folder. Returns the resolved path (directory is created if missing).
    #>
    [CmdletBinding()]
    param()
    if ($global:WptUsage.CsvPath) { return $global:WptUsage.CsvPath }
    $month = (Get-Date).ToString('yyyy-MM')
    $file = "WPT-UsageV2-$month.csv"
    $candidates = New-Object System.Collections.ArrayList
    try {
        $cfgPath = Join-Path (Split-Path -Parent $PSCommandPath) 'WPT.config.json'
        if (Test-Path $cfgPath) {
            $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
            foreach ($prop in 'usageCsvShare','logShare','auditShare') {
                if ($cfg.PSObject.Properties.Name -contains $prop -and $cfg.$prop) {
                    [void]$candidates.Add([string]$cfg.$prop)
                }
            }
        }
    } catch {}
    if ($global:LogDir) { [void]$candidates.Add([string]$global:LogDir) }
    [void]$candidates.Add([System.IO.Path]::GetTempPath())
    foreach ($dir in $candidates) {
        try {
            if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            $p = Join-Path $dir $file
            $test = Join-Path $dir ".wpt_write_test_$(Get-Random)"
            Set-Content -Path $test -Value 'x' -ErrorAction Stop
            Remove-Item -Path $test -Force -ErrorAction SilentlyContinue
            $global:WptUsage.CsvPath = $p
            return $p
        } catch { continue }
    }
    return $null
}

function Get-WptUsageSummary {
    <#
    .SYNOPSIS
        Aggregates $global:ActionHistory into Count/Ok/Fail per action family
        matching the modular v2 schema. Returns a hashtable.
    #>
    [CmdletBinding()]
    param()
    $map = @{
        'Scan'           = 'Scan'
        'PatchUpdate'    = 'Patch';     'PatchApp' = 'Patch';    'Patch' = 'Patch'
        'Reboot'         = 'Reboot'
        'KBInstall'      = 'KBInstall'
        'AppUpdate'      = 'AppUpdate'; 'AppUpdate2' = 'AppUpdate'
        'Cleanup'        = 'Cleanup'
        'HealthScan'     = 'Heal';      'Heal' = 'Heal';         'RestartCcmExec' = 'Heal'
        'WmiRepair'      = 'Heal';      'WuReset' = 'Heal';      'TriggerCheckIn' = 'Heal'
        'GpUpdate'       = 'Heal';      'WinRMBootstrap' = 'Heal'
        'RemoteMessage'  = 'Message';   'Message' = 'Message'
        'AcasRemediation'= 'AcasRemediation'
    }
    $sum = @{}
    foreach ($fam in 'Scan','Patch','Reboot','KBInstall','AppUpdate','Cleanup','Heal','Message','AcasRemediation') {
        $sum["$($fam)Count"] = 0; $sum["$($fam)Ok"] = 0; $sum["$($fam)Fail"] = 0
    }
    foreach ($entry in $global:ActionHistory) {
        $fam = $map[[string]$entry.Action]
        if (-not $fam) { continue }
        $sum["$($fam)Count"]++
        $result = [string]$entry.Result
        if ($result -match '(?i)^(OK|Scanned|Sent|Triggered|Success|Healthy|Degraded)') { $sum["$($fam)Ok"]++ }
        else { $sum["$($fam)Fail"]++ }
    }
    return $sum
}

function Publish-WptUsageCsvRow {
    <#
    .SYNOPSIS
        Appends one row to WPT-UsageV2-YYYY-MM.csv with this session's
        aggregated metrics + operator notes. Creates the file with v2 header
        if it doesn't exist yet.
    #>
    [CmdletBinding()]
    param([string]$Notes = '')
    $path = Resolve-WptUsageCsvPath
    if (-not $path) {
        Log "Usage CSV: no writable path; row not written" 'WARN'
        return $null
    }
    $edipi = $env:USERNAME
    $full  = Get-WptOperatorFullName
    $userLabel = if ($full) { "$edipi - $full" } else { $edipi }
    $start = $global:WptUsage.SessionStartTime
    $durSec = [int]((Get-Date) - $start).TotalSeconds
    $sum = Get-WptUsageSummary
    $columns = @(
        'Timestamp','User','SessionStart','SessionDurationSec','RunId','Notes'
        'ScanCount','ScanOk','ScanFail'
        'PatchCount','PatchOk','PatchFail'
        'RebootCount','RebootOk','RebootFail'
        'KBInstallCount','KBInstallOk','KBInstallFail'
        'AppUpdateCount','AppUpdateOk','AppUpdateFail'
        'CleanupCount','CleanupOk','CleanupFail'
        'HealCount','HealOk','HealFail'
        'MessageCount','MessageOk','MessageFail'
        'AcasRemediationCount','AcasRemediationOk','AcasRemediationFail'
    )
    $esc = { param($v) $s = [string]$v; if ($s -match '[",\r\n]') { '"' + ($s -replace '"','""') + '"' } else { $s } }
    $row = [ordered]@{
        Timestamp          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        User               = $userLabel
        SessionStart       = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        SessionDurationSec = $durSec
        RunId              = $global:WptUsage.SessionRunId
        Notes              = $Notes
    }
    foreach ($k in $sum.Keys) { $row[$k] = $sum[$k] }
    $values = foreach ($col in $columns) { & $esc $row[$col] }
    $line = $values -join ','
    try {
        if (-not (Test-Path $path)) {
            Set-Content -Path $path -Value ($columns -join ',') -Encoding UTF8 -ErrorAction Stop
        }
        Add-Content -Path $path -Value $line -Encoding UTF8 -ErrorAction Stop
        Log "Usage CSV row written: $path" 'OK'
        Write-AuditLog -Action 'UsageFlush' -Target $path -Result 'OK' -Detail "Notes=$(if ($Notes) { 'yes' } else { 'no' }) Duration=${durSec}s"
        return @{ Path = $path; Flushed = 1 }
    } catch {
        Log "Usage CSV write failed: $($_.Exception.Message)" 'ERR'
        Write-AuditLog -Action 'UsageFlush' -Target $path -Result 'Failed' -Detail $_.Exception.Message
        return $null
    }
}

## Drop-in that satisfies the previously-inlined Invoke-WptClosingFlow's
## call to Publish-WptUsageJournal. The inlined flow uses the return shape
## @{ Flushed = N; Path = ... }; Publish-WptUsageCsvRow matches that shape.
function Publish-WptUsageJournal {
    [CmdletBinding()]
    param([string]$Notes = '', [switch]$Force)
    return Publish-WptUsageCsvRow -Notes $Notes
}

function Write-WptAudit {
    ## Shim: routes modular-style calls to Legacy's Write-AuditLog. Modular
    ## passes -Action / -Target / -Result / -Detail; Legacy has the same
    ## parameter names, so this is a straight forward.
    [CmdletBinding()]
    param([string]$Action, [string]$Target = '', [string]$Result = '', [string]$Detail = '')
    try { Write-AuditLog -Action $Action -Target $Target -Result $Result -Detail $Detail } catch {}
}

###############################################################################
###                 TAB: USAGE LOG  (v47.1 Phase 3 - new)                   ###
###############################################################################
## Read-only observability for the closing-flow infrastructure above:
##   SESSION INFO group - operator (EDIPI + AD display name), session
##     start, running duration, CSV target path, audit log path.
##   ACTION COUNTS grid - live aggregation of $global:ActionHistory
##     (same shape Publish-WptUsageCsvRow emits). Refresh button
##     re-reads everything.
##   Publish Now button - fires the closing-notes dialog + CSV write
##     on demand (not just at form close), handy for partway-through-
##     shift check-ins.
##   Open CSV Folder button - shells Explorer to the CSV directory.
#region === TAB: USAGE LOG (v47.1 Phase 3 - new, additive) ===
## Observability for the closing flow: shows operator, session start/runtime,
## per-action counts, target CSV path, and a "Publish Now" button that
## fires Show-WptClosingNotesDialog + Publish-WptUsageCsvRow without waiting
## for form close. Handy for partway-through-shift check-ins.

$tabUsage = New-Object System.Windows.Forms.TabPage
$tabUsage.BackColor = $c.BG

## v6.5.13: Pre-size the tab page so anchored children calibrate
## against the TabControl's real geometry (1034x676 at design
## ClientSize 1280x740) instead of WinForms' default 200x100.
$tabUsage.Size = New-Object System.Drawing.Size($tc.Width, $tc.Height)

## v6.5.13: explicit -H 28 (Title font is 13pt bold mono, default 18 clips).
$lblUsageTitle = New-Lbl -Text "Usage Log: Session Observability + Manual Publish" -X 14 -Y 10 -W 900 -H 28 -Font $fn.Title -Fg $c.Gold
$lblUsageSub   = New-Lbl -Text "On form close, a single aggregated row is written to WPT-UsageV2-<year-month>.csv with action counts and your closing notes. Publish Now triggers the same flow on demand." -X 16 -Y 42 -W 1000 -Font $fn.Sub -Fg $c.Dim

## v6.5.13: SESSION INFO trimmed 720 -> 560 to make room for ACTION
## COUNTS to fit on the right within the 1030-wide design tab. Internal
## label widths trimmed 680 -> 520 to match.
$grpUsageSession = New-Grp -Text "SESSION INFO" -X 14 -Y 82 -W 560 -H 180 -Fg $c.Cyan
$script:lblUsageOperator = New-Lbl -Text "Operator: (loading)" -X 12 -Y 24 -W 520 -Font $fn.Label -Fg $c.White
$script:lblUsageRunId    = New-Lbl -Text "Run ID: $($global:WptUsage.SessionRunId)" -X 12 -Y 48 -W 520 -Font $fn.Small -Fg $c.Dim
$script:lblUsageStart    = New-Lbl -Text "Session start: $($global:WptUsage.SessionStartTime.ToString('g'))" -X 12 -Y 68 -W 520 -Font $fn.Small -Fg $c.Dim
$script:lblUsageDuration = New-Lbl -Text "Duration: --" -X 12 -Y 88 -W 520 -Font $fn.Small -Fg $c.Dim
$script:lblUsageCsv      = New-Lbl -Text "CSV target: (resolving)" -X 12 -Y 108 -W 520 -Font $fn.Small -Fg $c.Dim
$script:lblUsageAudit    = New-Lbl -Text "Audit log: $($global:AuditLogPath)" -X 12 -Y 128 -W 520 -Font $fn.Small -Fg $c.Dim
$grpUsageSession.Controls.AddRange(@($script:lblUsageOperator, $script:lblUsageRunId, $script:lblUsageStart, $script:lblUsageDuration, $script:lblUsageCsv, $script:lblUsageAudit))

## v6.5.13: ACTION COUNTS moved 750 -> 584 (right of trimmed SESSION
## INFO group with 10px gap) and anchored Top,Right so it sits at the
## right edge regardless of form size. Width 434 -> 432 for a clean
## 14px right margin at design width.
$grpUsageCounts = New-Grp -Text "ACTION COUNTS (Count / OK / Fail)" -X 584 -Y 82 -W 432 -H 280 -Fg $c.Success
$grpUsageCounts.Anchor = 'Top,Right'
$script:dgvUsage = New-Object System.Windows.Forms.DataGridView
$script:dgvUsage.Location = New-Object System.Drawing.Point(10, 22)
$script:dgvUsage.Size     = New-Object System.Drawing.Size(412, 250)
Style-Grid $script:dgvUsage
$script:dgvUsage.Columns.Add('Action','Action') | Out-Null
$script:dgvUsage.Columns.Add('Count','Count') | Out-Null
$script:dgvUsage.Columns.Add('Ok','OK') | Out-Null
$script:dgvUsage.Columns.Add('Fail','Fail') | Out-Null
$grpUsageCounts.Controls.Add($script:dgvUsage)

$script:btnUsageRefresh = New-Btn -Text "Refresh" -X 14  -Y 280 -W 120 -H 30 -Bg $c.Accent
$script:btnUsagePublish = New-Btn -Text "Publish Now..." -X 142 -Y 280 -W 160 -H 30 -Bg $c.Success
$script:btnUsageOpenCsv = New-Btn -Text "Open CSV Folder" -X 310 -Y 280 -W 160 -H 30 -Bg $c.Cyan

## v6.5.13: USAGE LOG width trimmed 720 -> 1002 (full width below the
## SESSION INFO + ACTION COUNTS row) and anchored Top,Left,Right,Bottom
## so it stretches with the form. Previously Top,Left,Bottom meant the
## log stayed 720 wide while the rest of the tab grew on a maximized
## window, leaving wide empty space on the right.
$grpUsageLog = New-Grp -Text "USAGE LOG" -X 14 -Y 376 -W 1002 -H 270 -Fg $c.Cyan
$grpUsageLog.Anchor = 'Top,Left,Right,Bottom'
$script:rtbUsageLog = New-Object System.Windows.Forms.RichTextBox
$script:rtbUsageLog.Location    = New-Object System.Drawing.Point(10, 22)
$script:rtbUsageLog.Size        = New-Object System.Drawing.Size(982, 240)
$script:rtbUsageLog.Anchor      = 'Top,Left,Right,Bottom'
$script:rtbUsageLog.BackColor   = $c.OutputBg
$script:rtbUsageLog.ForeColor   = $c.Console
$script:rtbUsageLog.Font        = $fn.Console
$script:rtbUsageLog.ReadOnly    = $true
$script:rtbUsageLog.BorderStyle = 'None'
$script:rtbUsageLog.WordWrap    = $false
$script:rtbUsageLog.ScrollBars  = 'Vertical'
$grpUsageLog.Controls.Add($script:rtbUsageLog)

function UsageLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbUsageLog) {
        try {
            if (-not $script:rtbUsageLog.IsHandleCreated) { $script:rtbUsageLog.CreateControl() }
            $start = $script:rtbUsageLog.TextLength
            $script:rtbUsageLog.AppendText($line)
            $clr = switch ($lvl) { 'OK' { $c.Success }; 'WARN' { $c.Warning }; 'ERR' { $c.Danger }; default { $c.Console } }
            $script:rtbUsageLog.Select($start, $line.Length); $script:rtbUsageLog.SelectionColor = $clr; $script:rtbUsageLog.SelectionLength = 0
            $script:rtbUsageLog.ScrollToCaret()
        } catch { try { $script:rtbUsageLog.AppendText($line) } catch {} }
    }
    [System.Windows.Forms.Application]::DoEvents()
}

$script:RefreshUsageTab = {
    ## Operator label (kick AD lookup once if not cached)
    $edipi = $env:USERNAME
    $full  = Get-WptOperatorFullName
    $label = if ($full) { "Operator: $edipi - $full" } else { "Operator: $edipi" }
    $script:lblUsageOperator.Text = $label
    ## Duration
    $dur = (Get-Date) - $global:WptUsage.SessionStartTime
    $script:lblUsageDuration.Text = "Duration: $([int]$dur.TotalMinutes)m $(($dur.Seconds).ToString('00'))s"
    ## CSV target
    $csv = Resolve-WptUsageCsvPath
    $script:lblUsageCsv.Text = if ($csv) { "CSV target: $csv" } else { "CSV target: (no writable path)" }
    ## Counts
    $sum = Get-WptUsageSummary
    $script:dgvUsage.Rows.Clear()
    foreach ($fam in 'Scan','Patch','Reboot','KBInstall','AppUpdate','Cleanup','Heal','Message','AcasRemediation') {
        $script:dgvUsage.Rows.Add($fam, $sum["$($fam)Count"], $sum["$($fam)Ok"], $sum["$($fam)Fail"]) | Out-Null
    }
}

$script:btnUsageRefresh.Add_Click({ & $script:RefreshUsageTab; UsageLog "Usage tab refreshed" })
$script:btnUsagePublish.Add_Click({
    UsageLog "Opening closing notes dialog..."
    try {
        $outcome = Show-WptClosingNotesDialog
        if ($outcome.Choice -eq 'Cancel') { UsageLog "Publish cancelled by operator" 'WARN'; return }
        $notes = if ($outcome.Choice -eq 'Force') { '' } else { [string]$outcome.Notes }
        $res = Publish-WptUsageCsvRow -Notes $notes
        if ($res) {
            UsageLog "Published row to $($res.Path)" 'OK'
            & $script:RefreshUsageTab
        } else {
            UsageLog "Publish failed - see activity log" 'ERR'
        }
    } catch { UsageLog "Publish error: $($_.Exception.Message)" 'ERR' }
})
$script:btnUsageOpenCsv.Add_Click({
    $csv = Resolve-WptUsageCsvPath
    if (-not $csv) { UsageLog "No CSV path" 'WARN'; return }
    $dir = Split-Path -Parent $csv
    if (Test-Path $dir) { Start-Process explorer.exe -ArgumentList $dir }
})

## Refresh on tab selection via $tc.Add_SelectedIndexChanged hook added later
## by the sidebar nav. For initial population, do one refresh now.
& $script:RefreshUsageTab

$tabUsage.Controls.AddRange(@($lblUsageTitle, $lblUsageSub, $grpUsageSession, $grpUsageCounts, $script:btnUsageRefresh, $script:btnUsagePublish, $script:btnUsageOpenCsv, $grpUsageLog))
#endregion

## Additive FormClosing handler: fires alongside Legacy's existing cleanup
## handler (Legacy's is untouched). WinForms runs event handlers in
## registration order; this one registers AFTER Legacy's, so cleanup runs
## first, then closing notes / CSV publish.
## NOTE: This handler is wired at the bottom of FORM CLEANUP & SHOW region
## -- see the Add_FormClosing line added by Task 3.6 there.
#endregion

###############################################################################
###                       LOG4J FINDER SCRIPTBLOCK (v6.5.17)                 ###
###############################################################################
## $global:L4JFinderBlock - runs once per target via the RunspacePool. Pure
## discovery: enumerates all log4j-*.jar files under common Java install
## roots (no JNDI class probe, no SHA-256 hashing). Per-jar payload is
## kept small (Path / Component / Version / LastWriteTime / SizeKB) so
## the per-host result hashtable stays light even on hosts with dozens
## of jars under bundled JREs.
##
## Search roots: C:\Program Files, C:\Program Files (x86), C:\ProgramData,
## C:\Users, plus C:\Java / C:\jdk* / C:\jre* / C:\opt / C:\apps if
## present. Misses non-standard installs on other drives -- that's the
## "common dirs first (fast)" tradeoff vs. a full fixed-drive scan.
#region === LOG4J FINDER SCRIPTBLOCK (v6.5.17) ===
$global:L4JFinderBlock = {
    param([string]$Computer, [pscredential]$Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; ScanOK=$false; Jars=@(); Error="" }

    ## v47 AFNET reachability: TCP probe (WinRM 5985 / SMB 445) instead of
    ## ICMP, matching every other fan-out scriptblock in this tool.
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Error = "Offline"; return $r }
    $r.Online = $true

    ## OperationTimeout bumped to 300000 (5m) because recursive
    ## Get-ChildItem under C:\Users can be slow on hosts with many
    ## profiles; per-host it should still finish in well under a minute
    ## but a stuck profile (offline cache, redirected folder hang)
    ## shouldn't kill the whole batch.
    $wsOpt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sess = $null
    try { $sess = New-PSSession -ComputerName $Computer -Credential $Cred -Authentication $Auth -SessionOption $wsOpt -EA Stop }
    catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }

    try {
        $remote = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $roots = @(
                'C:\Program Files'
                'C:\Program Files (x86)'
                'C:\ProgramData'
                'C:\Users'
                'C:\Java'
                'C:\opt'
                'C:\apps'
            )
            ## Add C:\jdk* / C:\jre* if present (catches hand-installed
            ## Oracle / OpenJDK roots that don't land under Program Files).
            $roots += @(Get-ChildItem -Path 'C:\' -Directory -Filter 'jdk*' -EA SilentlyContinue | ForEach-Object { $_.FullName })
            $roots += @(Get-ChildItem -Path 'C:\' -Directory -Filter 'jre*' -EA SilentlyContinue | ForEach-Object { $_.FullName })

            $jars = New-Object System.Collections.Generic.List[object]
            foreach ($root in $roots) {
                if (-not (Test-Path -LiteralPath $root)) { continue }
                ## -Filter is much faster than -Include because it's
                ## evaluated by the FS driver, not in PowerShell. Still
                ## wrap in try/catch -- ACL denials inside C:\Users are
                ## the common failure mode and shouldn't abort the scan.
                try {
                    $found = Get-ChildItem -LiteralPath $root -Filter 'log4j-*.jar' -Recurse -File -Force -EA SilentlyContinue
                } catch { continue }
                foreach ($f in $found) {
                    $name = $f.Name
                    $component = ''
                    $version   = ''
                    ## Match log4j-<component>-<version>.jar where
                    ## component can be api / core / 1.2-api / to-slf4j /
                    ## jul / etc. and version is M.m.p with optional
                    ## suffix (-beta9, .2, etc.).
                    if ($name -match '^log4j-([A-Za-z0-9\.\-]+?)-(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*)\.jar$') {
                        $component = $Matches[1]
                        $version   = $Matches[2]
                    } elseif ($name -match '^log4j-(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*)\.jar$') {
                        ## Legacy log4j 1.x bare name (e.g. log4j-1.2.17.jar)
                        $component = 'legacy'
                        $version   = $Matches[1]
                    } else {
                        $component = 'unknown'
                        $version   = ''
                    }
                    $jars.Add(@{
                        Path          = $f.FullName
                        Component     = $component
                        Version       = $version
                        LastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                        SizeKB        = [int][Math]::Ceiling($f.Length / 1KB)
                    }) | Out-Null
                }
            }
            return ,$jars.ToArray()
        }
        $r.Jars   = @($remote)
        $r.ScanOK = $true
    } catch {
        $r.Error = $_.Exception.Message
    } finally { Remove-PSSession $sess -EA SilentlyContinue }

    return $r
}

## Version classifier (advisory only). Filename version is parseable but
## isn't a deterministic safety check -- the canonical Log4Shell test is
## whether org/apache/logging/log4j/core/lookup/JndiLookup.class is still
## inside the jar. We don't open the jar here, so this is a heuristic.
##
## v6.5.18 - Bar raised from "2.17+ = patched" to "2.25.4 exactly = patched"
## to match Tenable plugins 306549/306550 (the floor the existing
## 'Apache Log4j - Replace Vulnerable Jars' App Updater profile was
## already chasing per its inline comment). v6.5.17 was greenlighting
## 2.17.x and 2.25.3 jars that Tenable was still flagging on real
## scans, leading operators to think the host was clean when it wasn't.
##
## Rules:
##   - exactly 2.25.4   -> Patched
##   - anything else with a parseable version -> Vulnerable
##   - unparseable      -> Unknown (flag for review)
function global:Get-Log4jVulnState {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return 'Unknown' }
    if ($Version -eq '2.25.4') { return 'Patched' }
    if ($Version -match '^\d+\.\d+') { return 'Vulnerable' }
    return 'Unknown'
}
#endregion

###############################################################################
###                       LOG4J FINDER DRILL-DOWN DIALOG                    ###
###############################################################################
function Show-Log4jHostDetails {
    param([hashtable]$Result)
    if (-not $Result) {
        [System.Windows.Forms.MessageBox]::Show("This row has no scan data yet. Run Scan first, then double-click a scanned row.","No Scan Data",0,64)
        return
    }
    $h = [string]$Result.Host
    $jars = @($Result.Jars)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Log4j Finder - $h"
    $dlg.ClientSize = New-Object System.Drawing.Size(900, 520)
    $dlg.BackColor = $c.BG; $dlg.ForeColor = $c.White; $dlg.Font = $fn.Label
    $dlg.StartPosition = 'CenterScreen'; $dlg.FormBorderStyle = 'Sizable'
    $dlg.MinimumSize = New-Object System.Drawing.Size(700, 360)

    $lblHost = New-Lbl -Text $h -X 10 -Y 8 -W 700 -H 28 -Font $fn.Title -Fg $c.Cyan
    $online  = if ($Result.Online) { 'Online' } else { 'Offline' }
    $onlineFg = if ($Result.Online) { $c.Success } else { $c.Danger }
    $lblOnline = New-Lbl -Text $online -X 720 -Y 14 -W 160 -H 22 -Font $fn.LabelB -Fg $onlineFg

    $vulnCount = @($jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Vulnerable' }).Count
    $unkCount  = @($jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Unknown' }).Count
    $sumText = "$($jars.Count) jar(s)  |  $vulnCount vulnerable  |  $unkCount unknown"
    $sumFg   = if ($vulnCount -gt 0) { $c.Danger } elseif ($jars.Count -gt 0) { $c.Warning } else { $c.Success }
    $lblSum = New-Lbl -Text $sumText -X 10 -Y 38 -W 880 -H 20 -Font $fn.LabelB -Fg $sumFg

    if (-not [string]::IsNullOrWhiteSpace($Result.Error)) {
        $lblErr = New-Lbl -Text "Scan error: $($Result.Error)" -X 10 -Y 60 -W 880 -H 18 -Font $fn.Small -Fg $c.Danger
        $dlg.Controls.Add($lblErr)
    }

    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Location = New-Object System.Drawing.Point(10, 84)
    $dgv.Size     = New-Object System.Drawing.Size(880, 380)
    $dgv.Anchor   = 'Top,Left,Right,Bottom'
    $dgv.ReadOnly = $true; $dgv.RowHeadersVisible = $false; $dgv.AllowUserToAddRows = $false
    Style-Grid $dgv
    $dgv.AutoSizeColumnsMode = 'None'
    foreach ($col in @(
        @{N='Component';H='Component';W=110},
        @{N='Version';  H='Version';  W=90 },
        @{N='Vuln';     H='Vuln?';    W=90 },
        @{N='Path';     H='Path';     W=460},
        @{N='Modified'; H='Modified'; W=120}
    )) {
        $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W
        [void]$dgv.Columns.Add($cc)
    }
    foreach ($j in ($jars | Sort-Object { (Get-Log4jVulnState $_.Version) }, Path)) {
        $idx = $dgv.Rows.Add()
        $row = $dgv.Rows[$idx]
        $row.Cells['Component'].Value = $j.Component
        $row.Cells['Version'].Value   = $j.Version
        $vuln = Get-Log4jVulnState $j.Version
        $row.Cells['Vuln'].Value      = $vuln
        $row.Cells['Path'].Value      = $j.Path
        $row.Cells['Modified'].Value  = $j.LastWriteTime
        $vFg = switch ($vuln) {
            'Vulnerable' { $c.Danger }
            'Patched'    { $c.Success }
            default      { $c.Warning }
        }
        $row.Cells['Vuln'].Style.ForeColor = $vFg
    }
    if ($jars.Count -eq 0) {
        $idx = $dgv.Rows.Add()
        $dgv.Rows[$idx].Cells['Component'].Value = '(no log4j jars found)'
        $dgv.Rows[$idx].DefaultCellStyle.ForeColor = $c.Dim
    }

    $btnCp = New-Btn -Text "Copy to Clipboard" -X 10  -Y 478 -W 160 -H 30 -Bg $c.PanelLight
    $btnEx = New-Btn -Text "Export CSV"        -X 178 -Y 478 -W 120 -H 30 -Bg $c.Accent
    $btnCl = New-Btn -Text "Close"             -X 780 -Y 478 -W 110 -H 30 -Bg $c.Danger
    $btnCp.Anchor = 'Bottom,Left'; $btnEx.Anchor = 'Bottom,Left'; $btnCl.Anchor = 'Bottom,Right'

    $btnCp.Add_Click({
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Host: $h  ($online)")
        [void]$sb.AppendLine("Scan time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("Summary: $sumText")
        if (-not [string]::IsNullOrWhiteSpace($Result.Error)) { [void]$sb.AppendLine("Error: $($Result.Error)") }
        [void]$sb.AppendLine("")
        foreach ($j in $jars) {
            $v = Get-Log4jVulnState $j.Version
            [void]$sb.AppendLine("$v`t$($j.Component)`t$($j.Version)`t$($j.Path)`t$($j.LastWriteTime)")
        }
        try { [System.Windows.Forms.Clipboard]::SetText($sb.ToString()) } catch {}
    }.GetNewClosure())

    $btnEx.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_Log4j_${h}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        if ($sfd.ShowDialog() -eq 'OK') {
            $rows = @()
            foreach ($j in $jars) {
                $rows += [PSCustomObject]@{
                    Host          = $h
                    Component     = $j.Component
                    Version       = $j.Version
                    Vuln          = (Get-Log4jVulnState $j.Version)
                    Path          = $j.Path
                    LastWriteTime = $j.LastWriteTime
                    SizeKB        = $j.SizeKB
                }
            }
            if ($rows.Count -eq 0) { $rows += [PSCustomObject]@{ Host=$h; Component=''; Version=''; Vuln='None'; Path='(no jars)'; LastWriteTime=''; SizeKB=0 } }
            $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        }
    }.GetNewClosure())

    $btnCl.Add_Click({ $dlg.Close() })

    $dlg.Controls.AddRange(@($lblHost, $lblOnline, $lblSum, $dgv, $btnCp, $btnEx, $btnCl))
    $dlg.ShowDialog() | Out-Null
    $dlg.Dispose()
}

###############################################################################
###                         TAB: LOG4J FINDER (v6.5.17)                     ###
###############################################################################
## New dedicated tab. Pattern follows KB Scanner: header bar, filter strip,
## roll-up grid (one row per host), bottom log textbox. Per-host drill-down
## via Show-Log4jHostDetails. RunspacePool fan-out mirrors $global:ScanBlock.
#region === TAB: LOG4J FINDER (v6.5.17) ===
$tabL4J = New-Object System.Windows.Forms.TabPage; $tabL4J.BackColor = $c.BG

$pnlL4JBar = New-Object System.Windows.Forms.Panel
$pnlL4JBar.Location = New-Object System.Drawing.Point(6, 6)
$pnlL4JBar.Size = New-Object System.Drawing.Size(1100, 42)
$pnlL4JBar.BackColor = $c.Panel; $pnlL4JBar.Anchor = 'Top,Left,Right'

$script:btnL4JScan   = New-Btn -Text "Find Log4j Jars" -X 6   -Y 6 -W 160 -H 30 -Bg $c.Accent -Font $fn.BtnBig
$script:btnL4JCancel = New-Btn -Text "Cancel"          -X 174 -Y 6 -W 90  -H 30 -Bg $c.Danger; $script:btnL4JCancel.Enabled = $false
$script:btnL4JExport = New-Btn -Text "Export CSV"      -X 272 -Y 6 -W 110 -H 30 -Bg $c.Success; $script:btnL4JExport.Enabled = $false
$script:lblL4JTargetCount = New-Lbl -Text "Targets: 0" -X 396 -Y 12 -W 110 -Font $fn.SmallB -Fg $c.Dim
$script:lblL4JProg        = New-Lbl -Text "Load targets on Targets tab, then click Find Log4j Jars." -X 514 -Y 12 -W 580 -Font $fn.Small -Fg $c.Dim

$pnlL4JBar.Controls.AddRange(@($script:btnL4JScan, $script:btnL4JCancel, $script:btnL4JExport, $script:lblL4JTargetCount, $script:lblL4JProg))

$pnlL4JFilter = New-Object System.Windows.Forms.Panel
$pnlL4JFilter.Location = New-Object System.Drawing.Point(6, 52)
$pnlL4JFilter.Size = New-Object System.Drawing.Size(1100, 32)
$pnlL4JFilter.BackColor = [System.Drawing.Color]::FromArgb(16,16,30); $pnlL4JFilter.Anchor = 'Top,Left,Right'
$lblL4JFilter = New-Lbl -Text "Filter:" -X 6 -Y 7 -W 45 -Font $fn.LabelB -Fg $c.TextSec
$script:txtL4JFilter = New-Tb -X 52 -Y 4 -W 250 -H 24; $script:txtL4JFilter.Font = $fn.Console
$lblL4JFilterHint = New-Lbl -Text "Type to filter by host or jar path" -X 310 -Y 7 -W 280 -Font $fn.Small -Fg $c.Dim
$script:chkL4JOnlyVuln = New-Object System.Windows.Forms.CheckBox
$script:chkL4JOnlyVuln.Text = "Only show hosts with vulnerable jars"
$script:chkL4JOnlyVuln.Location = New-Object System.Drawing.Point(600, 6); $script:chkL4JOnlyVuln.Size = New-Object System.Drawing.Size(280, 22)
$script:chkL4JOnlyVuln.ForeColor = $c.Warning; $script:chkL4JOnlyVuln.FlatStyle = 'Flat'
$script:lblL4JCount = New-Lbl -Text "" -X 890 -Y 7 -W 200 -Font $fn.SmallB -Fg $c.Dim
$pnlL4JFilter.Controls.AddRange(@($lblL4JFilter, $script:txtL4JFilter, $lblL4JFilterHint, $script:chkL4JOnlyVuln, $script:lblL4JCount))

$script:dgvL4J = New-Object System.Windows.Forms.DataGridView
$script:dgvL4J.Location = New-Object System.Drawing.Point(6, 88)
$script:dgvL4J.Size     = New-Object System.Drawing.Size(1100, 420)
$script:dgvL4J.Anchor   = 'Top,Left,Right,Bottom'
$script:dgvL4J.ReadOnly = $true
Style-Grid $script:dgvL4J
$script:dgvL4J.AutoSizeColumnsMode = 'None'
foreach ($col in @(
    @{N='Host';   H='Host';        W=180},
    @{N='Status'; H='Status';      W=110},
    @{N='Jars';   H='Jar Count';   W=80 },
    @{N='Vuln';   H='Vulnerable?'; W=120},
    @{N='Notes';  H='Notes';       W=580}
)) {
    $cc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cc.Name = $col.N; $cc.HeaderText = $col.H; $cc.Width = $col.W
    [void]$script:dgvL4J.Columns.Add($cc)
}

$lblL4JLogTitle = New-Lbl -Text "LOG4J FINDER LOG" -X 10 -Y 514 -W 200 -Font $fn.LabelB -Fg $c.Gold
$lblL4JLogTitle.Anchor = 'Left,Bottom'
$script:rtbL4JLog = New-Object System.Windows.Forms.TextBox
$script:rtbL4JLog.Location = New-Object System.Drawing.Point(6, 532)
$script:rtbL4JLog.Size     = New-Object System.Drawing.Size(1100, 120)
$script:rtbL4JLog.Anchor   = 'Left,Right,Bottom'
$script:rtbL4JLog.BackColor = $c.OutputBg; $script:rtbL4JLog.ForeColor = $c.Console; $script:rtbL4JLog.Font = $fn.Console
$script:rtbL4JLog.ReadOnly = $true; $script:rtbL4JLog.Multiline = $true; $script:rtbL4JLog.ScrollBars = 'Vertical'
$script:rtbL4JLog.BorderStyle = 'None'; $script:rtbL4JLog.WordWrap = $false

function L4JLog($msg, $lvl = 'INFO') {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "[$ts] $msg`r`n"
    if ($null -ne $script:rtbL4JLog) {
        try {
            if (-not $script:rtbL4JLog.IsHandleCreated) { $script:rtbL4JLog.CreateControl() }
            $script:rtbL4JLog.Text += $line
            $script:rtbL4JLog.SelectionStart = $script:rtbL4JLog.TextLength
            $script:rtbL4JLog.ScrollToCaret()
        } catch {}
    }
    Log "[Log4j] $msg" $lvl
    [System.Windows.Forms.Application]::DoEvents()
}

## Per-host result cache. Key = hostname, Value = the result hashtable
## returned by $global:L4JFinderBlock. Used for grid repopulation on
## filter changes and for the drill-down dialog.
$script:L4JResults = @{}

function Populate-L4JGrid {
    $script:dgvL4J.Rows.Clear()
    $filter = $script:txtL4JFilter.Text.Trim()
    $onlyVuln = [bool]$script:chkL4JOnlyVuln.Checked

    $rows = @()
    foreach ($k in ($script:L4JResults.Keys | Sort-Object)) {
        $res = $script:L4JResults[$k]
        $jars = @($res.Jars)
        $vulnList = @($jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Vulnerable' })
        $unkList  = @($jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Unknown' })

        if (-not $res.Online) {
            $status = 'Offline'; $vulnTxt = '-'; $notes = if ($res.Error) { $res.Error } else { 'No TCP 5985/445' }
        } elseif (-not $res.ScanOK) {
            $status = 'Scan Error'; $vulnTxt = '-'; $notes = if ($res.Error) { $res.Error } else { 'Remote scan failed' }
        } elseif ($jars.Count -eq 0) {
            $status = 'Clean'; $vulnTxt = 'None'; $notes = 'No log4j jars in scanned roots'
        } elseif ($vulnList.Count -gt 0) {
            $status = 'Found'; $vulnTxt = "$($vulnList.Count) vuln"
            $sample = ($vulnList | Select-Object -First 2 | ForEach-Object { "$($_.Component) $($_.Version)" }) -join ', '
            $notes = "VULN: $sample"
            if ($vulnList.Count -gt 2) { $notes += " (+$($vulnList.Count - 2) more)" }
        } elseif ($unkList.Count -gt 0) {
            $status = 'Found'; $vulnTxt = "$($unkList.Count) unknown"; $notes = "$($jars.Count) jar(s); $($unkList.Count) unparseable"
        } else {
            $status = 'Found'; $vulnTxt = 'No (patched)'; $notes = "$($jars.Count) jar(s), all 2.17+"
        }

        $haystack = "$k $notes"
        if (-not [string]::IsNullOrWhiteSpace($filter) -and $haystack -notlike "*$filter*") { continue }
        if ($onlyVuln -and $vulnList.Count -eq 0) { continue }

        $rows += [PSCustomObject]@{
            Host    = $k
            Status  = $status
            Jars    = $jars.Count
            VulnTxt = $vulnTxt
            Notes   = $notes
            VulnFg  = if ($vulnList.Count -gt 0) { $c.Danger } elseif ($unkList.Count -gt 0) { $c.Warning } elseif (-not $res.Online -or -not $res.ScanOK) { $c.Dim } elseif ($jars.Count -gt 0) { $c.Success } else { $c.Dim }
            StatusFg = switch ($status) {
                'Offline'    { $c.Dim }
                'Scan Error' { $c.Danger }
                'Clean'      { $c.Success }
                'Found'      { if ($vulnList.Count -gt 0) { $c.Danger } else { $c.Warning } }
                default      { $c.TextSec }
            }
        }
    }

    foreach ($r in $rows) {
        $idx = $script:dgvL4J.Rows.Add()
        $row = $script:dgvL4J.Rows[$idx]
        $row.Cells['Host'].Value   = $r.Host
        $row.Cells['Status'].Value = $r.Status
        $row.Cells['Jars'].Value   = $r.Jars
        $row.Cells['Vuln'].Value   = $r.VulnTxt
        $row.Cells['Notes'].Value  = $r.Notes
        $row.Cells['Status'].Style.ForeColor = $r.StatusFg
        $row.Cells['Vuln'].Style.ForeColor   = $r.VulnFg
    }

    $script:lblL4JCount.Text = "Showing $($rows.Count) of $($script:L4JResults.Count)"
    $script:lblL4JCount.ForeColor = $c.Cyan
}

$script:txtL4JFilter.Add_TextChanged({ Populate-L4JGrid })
$script:chkL4JOnlyVuln.Add_CheckedChanged({ Populate-L4JGrid })

$script:dgvL4J.Add_CellDoubleClick({
    param($src, $e)
    if ($e.RowIndex -lt 0) { return }
    $host2 = [string]$script:dgvL4J.Rows[$e.RowIndex].Cells['Host'].Value
    if ($script:L4JResults.ContainsKey($host2)) {
        Show-Log4jHostDetails -Result $script:L4JResults[$host2]
    }
})

$script:btnL4JScan.Add_Click({
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials on Start tab first.","No Credentials"); return }
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }

    $script:btnL4JScan.Enabled = $false; $script:btnL4JExport.Enabled = $false; $script:btnL4JCancel.Enabled = $true
    $script:L4JResults = @{}
    $script:dgvL4J.Rows.Clear()
    $script:lblL4JProg.Text = "Scanning $($global:ComputerList.Count) workstation(s) for log4j-*.jar..."
    $script:lblL4JProg.ForeColor = $c.Warning

    L4JLog "========================================"
    L4JLog "Log4j Finder started on $($global:ComputerList.Count) workstation(s)"
    L4JLog "========================================"

    Initialize-RunspacePool
    $script:L4JJobs = @{}
    foreach ($comp in $global:ComputerList) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:RSPool
        [void]$ps.AddScript($global:L4JFinderBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument("Negotiate")
        $script:L4JJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() }
    }
    $script:L4JTotal = $script:L4JJobs.Count
    $script:L4JTimer = New-Object System.Windows.Forms.Timer
    $script:L4JTimer.Interval = 500
    $script:L4JTimer.Add_Tick({
        $newResults = $false
        foreach ($key in @($script:L4JJobs.Keys)) {
            $job = $script:L4JJobs[$key]
            if (-not $job.Handle.IsCompleted) { continue }
            $res = $null
            try {
                $raw = $job.PS.EndInvoke($job.Handle)
                $job.PS.Dispose()
                if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [hashtable])) {
                    $res = @($raw) | Select-Object -First 1
                } else { $res = $raw }
            } catch {
                L4JLog "$key : EndInvoke error - $($_.Exception.Message)" 'ERR'
                $script:L4JJobs.Remove($key); continue
            }
            $script:L4JJobs.Remove($key)
            if ($null -eq $res) { continue }
            $hostName = if ($res -is [hashtable]) { $res['Host'] } else { $res.Host }
            $online   = if ($res -is [hashtable]) { [bool]$res['Online'] } else { [bool]$res.Online }
            $scanOK   = if ($res -is [hashtable]) { [bool]$res['ScanOK'] } else { [bool]$res.ScanOK }
            $jars     = if ($res -is [hashtable]) { @($res['Jars']) } else { @($res.Jars) }
            $err      = if ($res -is [hashtable]) { [string]$res['Error'] } else { [string]$res.Error }

            ## Normalize back into a hashtable so the cache and drill-down
            ## dialog always see the same shape regardless of runspace
            ## marshaling quirks.
            $normalized = @{
                Host = $hostName; Online = $online; ScanOK = $scanOK; Jars = $jars; Error = $err
            }
            $script:L4JResults[$hostName] = $normalized

            if (-not $online) {
                L4JLog "$hostName : OFFLINE" 'ERR'
            } elseif (-not $scanOK) {
                L4JLog "$hostName : SCAN ERROR - $err" 'ERR'
            } else {
                $vulnCount = @($jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Vulnerable' }).Count
                if ($jars.Count -eq 0) {
                    L4JLog "$hostName : clean (no log4j jars)" 'OK'
                } elseif ($vulnCount -gt 0) {
                    L4JLog "$hostName : $($jars.Count) jar(s), $vulnCount VULNERABLE" 'ERR'
                } else {
                    L4JLog "$hostName : $($jars.Count) jar(s), none flagged" 'OK'
                }
            }
            $newResults = $true
        }

        $done = $script:L4JTotal - $script:L4JJobs.Count
        $script:lblL4JProg.Text = "Scanning: $done / $($script:L4JTotal)"
        if ($newResults) { Populate-L4JGrid }

        if ($script:L4JJobs.Count -eq 0) {
            $script:L4JTimer.Stop(); $script:L4JTimer.Dispose(); $script:L4JTimer = $null
            $script:btnL4JScan.Enabled = $true; $script:btnL4JCancel.Enabled = $false
            $script:btnL4JExport.Enabled = ($script:L4JResults.Count -gt 0)
            $hostsWithJars = @($script:L4JResults.Values | Where-Object { @($_.Jars).Count -gt 0 }).Count
            $hostsVuln     = @($script:L4JResults.Values | Where-Object {
                @($_.Jars | Where-Object { (Get-Log4jVulnState $_.Version) -eq 'Vulnerable' }).Count -gt 0
            }).Count
            $script:lblL4JProg.Text = "Complete: $($script:L4JTotal) host(s)  |  $hostsWithJars with jars  |  $hostsVuln vulnerable"
            $script:lblL4JProg.ForeColor = if ($hostsVuln -gt 0) { $c.Danger } elseif ($hostsWithJars -gt 0) { $c.Warning } else { $c.Success }
            L4JLog "========================================"
            L4JLog "Log4j Finder complete: $($script:L4JTotal) host(s), $hostsWithJars with jars, $hostsVuln vulnerable"
            L4JLog "========================================"
            Write-AuditLog -Action "Log4jFinder" -Result "Complete" -Detail "Hosts=$($script:L4JTotal) WithJars=$hostsWithJars Vuln=$hostsVuln"
        }
    })
    $script:L4JTimer.Start()
})

$script:btnL4JCancel.Add_Click({
    if ($null -eq $script:L4JJobs -or $script:L4JJobs.Count -eq 0) { return }
    foreach ($key in @($script:L4JJobs.Keys)) {
        try { $script:L4JJobs[$key].PS.Stop() } catch {}
        try { $script:L4JJobs[$key].PS.Dispose() } catch {}
        $script:L4JJobs.Remove($key)
    }
    if ($null -ne $script:L4JTimer) { try { $script:L4JTimer.Stop(); $script:L4JTimer.Dispose() } catch {}; $script:L4JTimer = $null }
    $script:btnL4JScan.Enabled = $true; $script:btnL4JCancel.Enabled = $false
    $script:btnL4JExport.Enabled = ($script:L4JResults.Count -gt 0)
    $script:lblL4JProg.Text = "Cancelled by operator"
    $script:lblL4JProg.ForeColor = $c.Warning
    L4JLog "Cancelled by operator" 'WARN'
})

$script:btnL4JExport.Add_Click({
    if ($script:L4JResults.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_Log4jFinder_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq 'OK') {
        $rows = @()
        foreach ($k in ($script:L4JResults.Keys | Sort-Object)) {
            $res = $script:L4JResults[$k]
            $jars = @($res.Jars)
            if ($jars.Count -eq 0) {
                $rows += [PSCustomObject]@{
                    Host=$k; Online=$res.Online; ScanOK=$res.ScanOK; Error=$res.Error
                    Component=''; Version=''; Vuln=''; Path=''; LastWriteTime=''; SizeKB=0
                }
            } else {
                foreach ($j in $jars) {
                    $rows += [PSCustomObject]@{
                        Host=$k; Online=$res.Online; ScanOK=$res.ScanOK; Error=$res.Error
                        Component=$j.Component; Version=$j.Version
                        Vuln=(Get-Log4jVulnState $j.Version)
                        Path=$j.Path; LastWriteTime=$j.LastWriteTime; SizeKB=$j.SizeKB
                    }
                }
            }
        }
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        L4JLog "Exported $($rows.Count) row(s) to $($sfd.FileName)" 'OK'
    }
})

$tabL4J.Add_Enter({
    $cnt = $global:ComputerList.Count
    $script:lblL4JTargetCount.Text = "Targets: $cnt"
    $script:lblL4JTargetCount.ForeColor = if ($cnt -gt 0) { $c.Success } else { $c.Warning }
})

$tabL4J.Controls.AddRange(@($pnlL4JBar, $pnlL4JFilter, $script:dgvL4J, $lblL4JLogTitle, $script:rtbL4JLog))
#endregion

###############################################################################
###                             ASSEMBLE TABS                               ###
###############################################################################
## Single call to $tc.Controls.AddRange that places every tab page in
## its display order. This is the ONE place to edit tab ordering --
## sidebar nav display order is driven by the $navSpec array in the
## SIDEBAR NAVIGATION region, and the two should stay consistent.
#region === ASSEMBLE TABS ===
## v6.5.0: $tabUpdater removed (Legacy App Updater retired); $tabAppUpd2
## is now the single App Updater tab.
## v6.5.17: $tabL4J inserted between $tabRegKey and $tabRemMsg.
$tc.Controls.AddRange(@($script:tabStartAbout, $tabTargets, $tabBulk, $tabSoftware, $tabAppMgr, $tabKB, $tabAppUpd2, $tabCleanup, $tabRegKey, $tabL4J, $tabRemMsg, $tabRebootMsg, $tabReports, $tabHeal, $tabWinRM, $tabUsage, $tabLog))
#endregion

###############################################################################
###                       WIRE NAV CARDS TO TABS                            ###
###############################################################################
## Legacy-era plumbing. The Start tab's center "NAVIGATE TO SECTION"
## card column was removed in v47.1; $script:NavCards is now an empty
## ArrayList so this loop iterates zero items and stays harmless.
## Kept as a safety shim so any dormant reference that still accesses
## $script:NavCards doesn't null-ref.
#region === WIRE NAV CARDS TO TABS ===
$navTabTargets2 = @($tabTargets, $tabBulk, $tabSoftware, $tabAppMgr, $tabKB, $tabAppUpd2, $tabCleanup, $tabRegKey, $tabL4J, $tabRemMsg, $tabRebootMsg, $tabReports, $tabLog)
for ($i = 0; $i -lt $script:NavCards.Count -and $i -lt $navTabTargets2.Count; $i++) { $script:NavCards[$i].Tag = $navTabTargets2[$i] }
#endregion

###############################################################################
###                  SIDEBAR NAVIGATION WITH SESSION GATING                 ###
###############################################################################
## Builds the left sidebar: brand block (J.A.N.E.T. wordmark + subtitle
## + version), hairline separator, scrollable nav host with one
## New-WptNavItem per $navSpec entry, and a bottom user block (user,
## status, host). The $navSpec array maps Key / Label / Icon / Tab /
## AlwaysOpen for every sidebar entry -- add or remove entries here to
## change sidebar content. Session gating is enforced in two places:
##   - The per-item click handler checks $global:SessionStarted + the
##     item's AlwaysOpen flag (Start is the only AlwaysOpen=true tab).
##   - $tc.Add_SelectedIndexChanged re-asserts the same rule so any
##     programmatic SelectedTab change (keyboard, mouse wheel, etc.)
##     also respects gating.
## The default WinForms gray scrollbar is hidden via user32!ShowScrollBar
## (SB_BOTH, false) wired on HandleCreated + Layout so MouseWheel
## scrolling works but the bar doesn't visibly appear. Drag-to-scroll
## is the tradeoff.
#region === SIDEBAR NAVIGATION WITH SESSION GATING ===
## Modular-style sidebar: J.A.N.E.T. wordmark + "Workstation Patching tool"
## subtitle + version, a hairline separator, then numbered + iconed nav items
## built via New-WptNavItem (inlined from modular Controls.ps1 in Task 1.5b).
## Session-gating preserved from Legacy: only Start / How To Use / About are
## reachable until $global:SessionStarted is set.

$_theme = $script:WPT.UI.Theme
$_fonts = $script:WPT.UI.Fonts
$_icons = $script:WPT.UI.Icons

$pnlSide = New-Object System.Windows.Forms.Panel
$pnlSide.Location  = New-Object System.Drawing.Point(0, 32)
$pnlSide.Size      = New-Object System.Drawing.Size($script:SideW, ($f.ClientSize.Height - 64))
$pnlSide.Anchor    = 'Top,Left,Bottom'
$pnlSide.BackColor = $_theme.Sidebar

## Right-edge 1px divider
$pnlSideEdge = New-Object System.Windows.Forms.Panel
$pnlSideEdge.Dock = 'Right'; $pnlSideEdge.Width = 1; $pnlSideEdge.BackColor = $_theme.Border
$pnlSide.Controls.Add($pnlSideEdge)

## ---- Brand block ----
$brand = New-Object System.Windows.Forms.Panel
$brand.Location  = New-Object System.Drawing.Point(0, 20)
$brand.Size      = New-Object System.Drawing.Size($script:SideW, 100)
$brand.BackColor = $_theme.Sidebar

$lblBrandMark = New-WptLabel -Text 'J.A.N.E.T.' `
    -X 22 -Y 14 -W ($script:SideW - 32) -H 28 -Font $_fonts.DisplayLg -Fg $_theme.Accent1

$lblBrandSub = New-WptLabel -Text 'Workstation Patching tool' `
    -X 22 -Y 48 -W ($script:SideW - 32) -H 16 -Font $_fonts.Caption -Fg $_theme.TextSecondary

$lblBrandVer = New-WptLabel -Text "v$JanetWptVersion" `
    -X 22 -Y 68 -W ($script:SideW - 32) -H 16 -Font $_fonts.MonoTiny -Fg $_theme.TextFaint

$brand.Controls.AddRange(@($lblBrandMark, $lblBrandSub, $lblBrandVer))

## Hairline divider below brand
$brandSep = New-WptSeparator -X 20 -Y 128 -W ($script:SideW - 40) -Color $_theme.Border

## ---- Nav host (scrollable if the 15 items overflow) ----
$navHost = New-Object System.Windows.Forms.Panel
$navHost.Location   = New-Object System.Drawing.Point(0, 140)
$navHost.Size       = New-Object System.Drawing.Size($script:SideW, ($pnlSide.Size.Height - 140 - 96))
$navHost.BackColor  = $_theme.Sidebar
$navHost.Anchor     = 'Top,Left,Bottom,Right'
## v5.1.2: Re-enabled AutoScroll (v5.1.1's disable + shrink wasn't enough -
## 19 items * 32px still overflows on shorter window heights). MouseWheel
## scrolls; the default gray scrollbar is hidden via ShowScrollBar P/Invoke
## wired on HandleCreated + Layout so it never repaints visibly. Drag-to-
## scroll is lost as a tradeoff; wheel + keyboard work.
$navHost.AutoScroll = $true
if (-not ('WptScrollbar.Api' -as [type])) {
    Add-Type -Namespace 'WptScrollbar' -Name 'Api' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool ShowScrollBar(System.IntPtr hWnd, int wBar, bool bShow);
'@ -ErrorAction SilentlyContinue
}
$hideNavScrollbar = {
    try {
        if ($navHost -and $navHost.IsHandleCreated -and $navHost.Handle -ne [System.IntPtr]::Zero) {
            ## SB_BOTH = 3. Hiding both axes -- the H scrollbar never shows
            ## anyway (items are fixed-width), but hiding it defensively costs
            ## nothing and prevents a regression if navHost ever widens.
            [void][WptScrollbar.Api]::ShowScrollBar($navHost.Handle, 3, $false)
        }
    } catch {}
}.GetNewClosure()
$navHost.Add_HandleCreated($hideNavScrollbar)
$navHost.Add_Layout($hideNavScrollbar)

## Nav spec - order must match Legacy's tab order (ASSEMBLE TABS region).
## AlwaysOpen = always reachable even before session starts.
$navSpec = @(
    @{ Key='Start';      Label='Start';             Icon=$_icons.Settings; Tab=$script:tabStartAbout; AlwaysOpen=$true  }
    @{ Key='Targets';    Label='Targets';           Icon=$_icons.Target;   Tab=$tabTargets;           AlwaysOpen=$false }
    @{ Key='BulkScan';   Label='Bulk Scan & Patch'; Icon=$_icons.Search;   Tab=$tabBulk;              AlwaysOpen=$false }
    @{ Key='SwMgr';      Label='Software Manager';  Icon=$_icons.Package;  Tab=$tabSoftware;          AlwaysOpen=$false }
    @{ Key='SccmAppMgr'; Label='SCCM App Manager';  Icon=$_icons.AppIcon;  Tab=$tabAppMgr;            AlwaysOpen=$false }
    @{ Key='KBScanner';  Label='KB Scanner';        Icon=$_icons.Keyboard; Tab=$tabKB;                AlwaysOpen=$false }
    @{ Key='AppUpdater'; Label='App Updater';       Icon=$_icons.Sync;     Tab=$tabAppUpd2;           AlwaysOpen=$false }
    @{ Key='Cleanup';    Label='Cleanup';           Icon=$_icons.Broom;    Tab=$tabCleanup;           AlwaysOpen=$false }
    @{ Key='RegKey';     Label='Reg Key Fixes';     Icon=$_icons.Shield;   Tab=$tabRegKey;            AlwaysOpen=$false }
    @{ Key='Log4j';      Label='Log4j Finder';      Icon=$_icons.Warning;  Tab=$tabL4J;               AlwaysOpen=$false }
    @{ Key='RemoteMsg';  Label='Remote Message';    Icon=$_icons.Mail;     Tab=$tabRemMsg;            AlwaysOpen=$false }
    @{ Key='RebootMsg';  Label='Reboot Countdown';  Icon=$_icons.Power;    Tab=$tabRebootMsg;         AlwaysOpen=$false }
    @{ Key='Reports';    Label='Reports';           Icon=$_icons.Chart;    Tab=$tabReports;           AlwaysOpen=$false }
    @{ Key='Heal';       Label='Heal';              Icon=$_icons.Shield;   Tab=$tabHeal;              AlwaysOpen=$false }
    @{ Key='WinRMSetup'; Label='WinRM Setup';       Icon=$_icons.Radio;    Tab=$tabWinRM;             AlwaysOpen=$false }
    @{ Key='Usage';      Label='Usage';             Icon=$_icons.Chart;    Tab=$tabUsage;             AlwaysOpen=$false }
    @{ Key='Logs';       Label='Logs';              Icon=$_icons.Document; Tab=$tabLog;               AlwaysOpen=$false }
)

$script:SideItems = @()
$_y = 4
for ($i = 0; $i -lt $navSpec.Count; $i++) {
    $spec = $navSpec[$i]
    $ni = New-WptNavItem -Key $spec.Key -Label $spec.Label -Icon $spec.Icon -Index ($i + 1) -Y $_y -W ($script:SideW - 1) -H 32
    ## Store tab reference + gating flag in the same Tag hashtable the factory
    ## created, so the click handler can reach them without extra closures.
    $ni.Tag['TabRef']     = $spec.Tab
    $ni.Tag['AlwaysOpen'] = $spec.AlwaysOpen
    $navHost.Controls.Add($ni)
    $script:SideItems += $ni

    ## Click handler: walks up to the nav-item panel (clicks on sub-labels
    ## bubble with $sender = the sub-label, not the Panel), then does Legacy's
    ## session-gating check, then switches the tab. Tab's SelectedIndexChanged
    ## handler will drive Set-WptNavItemActive via $UpdateSidebar.
    $clickHandler = {
        param($src, $e)
        $p = $src
        while ($p -and -not ($p.Tag -is [hashtable] -and $p.Tag.ContainsKey('Key'))) { $p = $p.Parent }
        if (-not $p) { return }
        $target     = $p.Tag['TabRef']
        $alwaysOpen = [bool]$p.Tag['AlwaysOpen']
        if (-not $global:SessionStarted -and -not $alwaysOpen) {
            [System.Windows.Forms.MessageBox]::Show("Complete the setup and click START SESSION before navigating to other sections.","Session Not Started",0,48)
            $tc.SelectedTab = $script:tabStartAbout
            return
        }
        $tc.SelectedTab = $target
    }
    $ni.Add_Click($clickHandler)
    foreach ($child in $ni.Controls) { $child.Add_Click($clickHandler) }

    $_y += 32
}

## ---- User / session block pinned to bottom of the sidebar ----
$userBlock = New-Object System.Windows.Forms.Panel
$userBlock.Location  = New-Object System.Drawing.Point(0, ($pnlSide.Size.Height - 140))
$userBlock.Size      = New-Object System.Drawing.Size($script:SideW, 140)
$userBlock.BackColor = $_theme.Sidebar
$userBlock.Anchor    = 'Bottom,Left,Right'

$userSep = New-WptSeparator -X 20 -Y 0 -W ($script:SideW - 40) -Color $_theme.Border
$userBlock.Controls.Add($userSep)

$lblOpName  = New-WptLabel -Text "User: $env:USERNAME" `
    -X 22 -Y 16 -W ($script:SideW - 32) -H 16 -Font $_fonts.MonoSm -Fg $_theme.TextPrimary

$lblOpState = New-WptLabel -Text 'Status: idle' `
    -X 22 -Y 40 -W ($script:SideW - 32) -H 16 -Font $_fonts.MonoSm -Fg $_theme.TextMuted

$lblOpHost = New-WptLabel -Text "Host: $env:COMPUTERNAME" `
    -X 22 -Y 64 -W ($script:SideW - 32) -H 16 -Font $_fonts.MonoTiny -Fg $_theme.TextFaint

## v6.5.8: $btnCloseTool relocated to the top-right of the form's TOP
## STRIP (see TOP STRIP region above). Removed from the sidebar
## userBlock to free vertical space and improve discoverability.
$userBlock.Controls.AddRange(@($lblOpName, $lblOpState, $lblOpHost))

$pnlSide.Controls.AddRange(@($brand, $brandSep, $navHost, $userBlock))

## Activate the nav item whose TabRef matches the currently-selected tab.
## Driven by $tc.Add_SelectedIndexChanged below so keyboard navigation and
## Legacy's sidebar-card clicks both keep the sidebar visual in sync.
$UpdateSidebar = {
    $cur = $tc.SelectedTab
    foreach ($ni in $script:SideItems) {
        $ni.Tag['IsActive'] = ($ni.Tag['TabRef'] -eq $cur)
        & $ni.Tag['Refresh'] $ni
    }
}

$tc.Add_SelectedIndexChanged({
    if (-not $global:SessionStarted -and $tc.SelectedTab -ne $script:tabStartAbout) {
        $tc.SelectedTab = $script:tabStartAbout
        return
    }
    & $UpdateSidebar
})
#endregion

###############################################################################
###                BULK SCAN / PATCH / REBOOT EVENT HANDLERS                ###
###############################################################################
## The click handlers for the Bulk Scan & Patch tab's five action
## buttons. Each handler:
##   1. Validates ($global:ComputerList not empty, $global:Credentials
##      set where applicable).
##   2. Resets grid rows to a "Scanning..." / "Patching..." / etc.
##      placeholder state with dim coloring.
##   3. Initialize-RunspacePool, then dispatches the appropriate
##      scriptblock per host and stashes the job handle in a
##      $script:*Jobs hashtable.
##   4. Starts a WinForms Timer polling every 300-700 ms:
##      - Drains completed jobs, EndInvoke + Dispose the PowerShell
##        instances, paints the resulting hashtable into the grid row
##        for that host.
##      - Updates the progress label.
##      - When $Jobs.Count hits 0, stops+disposes the timer, re-enables
##        the button, sets completion state on the label.
##   5. Track-Action is called per host for every row update.
## Handlers: btnScanAll, btnPatchSel, btnRebootSel, btnPingSweep,
## btnExport.
#region === BULK SCAN/PATCH/REBOOT EVENT HANDLERS ===
$script:btnScanAll.Add_Click({
    if ($global:ComputerList.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No targets loaded.","No Targets"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $auth = "Negotiate"; $script:btnScanAll.Enabled = $false; $script:dgvBulk.Rows.Clear()
    $dimClr = [System.Drawing.Color]::FromArgb(90,90,130)
    foreach ($comp in $global:ComputerList) { $idx = $script:dgvBulk.Rows.Add(); $row = $script:dgvBulk.Rows[$idx]; $row.Cells[0].Value = $false; $row.Cells[1].Value = $comp; foreach ($ci in 2..9) { $row.Cells[$ci].Value = "Scanning..."; $row.Cells[$ci].Style.ForeColor = $dimClr } }
    $script:lblBulkProg.Text = "Scanning: 0 / $($global:ComputerList.Count)"; $script:lblBulkProg.ForeColor = $c.Warning
    Log "=== Bulk scan started: $($global:ComputerList.Count) workstation(s) ==="; Write-AuditLog -Action "BulkScan" -Result "Started" -Detail "$($global:ComputerList.Count) targets"
    Initialize-RunspacePool; $script:ScanJobs = @{}
    foreach ($comp in $global:ComputerList) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($global:ScanBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($auth); $script:ScanJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:ScanTotal = $global:ComputerList.Count; $script:ScanTimer = New-Object System.Windows.Forms.Timer; $script:ScanTimer.Interval = 500
    $script:ScanTimer.Add_Tick({
        $clrOK = $c.Success; $clrWn = $c.Warning; $clrEr = $c.Danger; $clrDm = [System.Drawing.Color]::FromArgb(90,90,130)
        foreach ($key in @($script:ScanJobs.Keys)) { $job = $script:ScanJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() } catch { $res = @{ Host=$key; Online=$false } }
            $script:ScanJobs.Remove($key); if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null; foreach ($r in $script:dgvBulk.Rows) { if ($r.Cells[1].Value -eq $res.Host) { $row = $r; break } }; if ($null -eq $row) { continue }
            if (-not $res.Online) { $row.Cells[2].Value = "Offline"; $row.Cells[2].Style.ForeColor = $clrEr; foreach ($ci in 3..9) { $row.Cells[$ci].Value = "--"; $row.Cells[$ci].Style.ForeColor = $clrDm }; $row.Cells[7].Value = "Offline"; $row.Tag = $res; continue }
            $row.Cells[2].Value = "Online"; $row.Cells[2].Style.ForeColor = $clrOK
            if ($res.DriveOK) { $row.Cells[3].Value = "$($res.DriveFree)GB ($($res.DrivePct)%)"; $row.Cells[3].Style.ForeColor = if ($res.DrivePct -gt 20) { $clrOK } else { $clrWn } } else { $row.Cells[3].Value = "Error"; $row.Cells[3].Style.ForeColor = $clrEr }
            if ($res.RebootOK) { if ($res.RebootPending) { $row.Cells[4].Value = "YES"; $row.Cells[4].Style.ForeColor = $clrWn } else { $row.Cells[4].Value = "No"; $row.Cells[4].Style.ForeColor = $clrOK } } else { $row.Cells[4].Value = "Error"; $row.Cells[4].Style.ForeColor = $clrEr }
            $uCnt = $res.UpdateNames.Count; if ($res.UpdatesOK) { if ($uCnt -gt 0) { $row.Cells[5].Value = "$uCnt update(s)"; $row.Cells[5].Style.ForeColor = $clrWn } else { $row.Cells[5].Value = "Current"; $row.Cells[5].Style.ForeColor = $clrOK } } else { $row.Cells[5].Value = "Error"; $row.Cells[5].Style.ForeColor = $clrEr }
            $aCnt = $res.AppNames.Count; if ($res.AppsOK) { if ($aCnt -gt 0) { $row.Cells[6].Value = "$aCnt app(s)"; $row.Cells[6].Style.ForeColor = $clrWn } else { $row.Cells[6].Value = "Current"; $row.Cells[6].Style.ForeColor = $clrOK } } else { $row.Cells[6].Value = "Error"; $row.Cells[6].Style.ForeColor = $clrEr }
            ## v6.2.6: paint WU column from direct Windows Update Agent scan
            $wCnt = @($res.WuNames).Count; if ($res.WuOK) { if ($wCnt -gt 0) { $row.Cells[9].Value = "$wCnt update(s)"; $row.Cells[9].Style.ForeColor = $clrWn } else { $row.Cells[9].Value = "Current"; $row.Cells[9].Style.ForeColor = $clrOK } } else { $row.Cells[9].Value = "Error"; $row.Cells[9].Style.ForeColor = $clrEr }
            $row.Cells[7].Value = "Scanned"; $row.Cells[7].Style.ForeColor = $clrOK; $row.Cells[8].Value = "--"; $row.Cells[8].Style.ForeColor = $clrDm; $row.Tag = $res
            Track-Action -Action 'Scan' -Target $res.Host -Result 'Scanned' -Detail "MECM:$($res.UpdateNames.Count) WU:$wCnt App:$($res.AppNames.Count)"
        }
        $done = $script:ScanTotal - $script:ScanJobs.Count; $script:lblBulkProg.Text = "Scanning: $done / $script:ScanTotal"
        if ($script:ScanJobs.Count -eq 0) { $script:ScanTimer.Stop(); $script:ScanTimer.Dispose(); $script:btnScanAll.Enabled = $true; $script:lblBulkProg.Text = "Scan complete: $script:ScanTotal workstation(s)"; $script:lblBulkProg.ForeColor = $c.Success; Log "=== Bulk scan complete ===" }
    }); $script:ScanTimer.Start()
})
$script:btnPatchSel.Add_Click({
    $selected = @(); foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No workstations selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("Patch $($selected.Count) workstation(s)?`n`nReboot will be suppressed.", "Confirm Patch", 4, 48); if ($confirm -ne 'Yes') { return }
    $auth = "Negotiate"; $script:btnPatchSel.Enabled = $false; $script:btnScanAll.Enabled = $false
    foreach ($srv in $selected) { foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[1].Value -eq $srv) { $row.Cells[8].Value = "Patching..."; $row.Cells[8].Style.ForeColor = $c.Warning; break } } }
    Log "=== Patching $($selected.Count) workstation(s) ==="; $script:PatchJobs = @{}
    foreach ($comp in $selected) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($global:PatchBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($auth); $script:PatchJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:PatchTotal = $selected.Count; $script:PatchTimer = New-Object System.Windows.Forms.Timer; $script:PatchTimer.Interval = 600
    $script:PatchTimer.Add_Tick({
        foreach ($key in @($script:PatchJobs.Keys)) { $job = $script:PatchJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() } catch { $res = @{ Host=$key; Reachable=$false; Error=$_.ToString(); UpdatesTriggered=0; AppsTriggered=0 } }
            $script:PatchJobs.Remove($key); if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null; foreach ($r in $script:dgvBulk.Rows) { if ($r.Cells[1].Value -eq $res.Host) { $row = $r; break } }; if ($null -eq $row) { continue }
            if ($res.Error) { $row.Cells[8].Value = "Error: $($res.Error)"; $row.Cells[8].Style.ForeColor = $c.Danger }
            elseif ($res.UpdatesTriggered -eq 0 -and $res.AppsTriggered -eq 0) { $row.Cells[8].Value = "Nothing to patch"; $row.Cells[8].Style.ForeColor = $c.Success }
            else { $parts = @(); if ($res.UpdatesTriggered -gt 0) { $parts += "$($res.UpdatesTriggered) upd" }; if ($res.AppsTriggered -gt 0) { $parts += "$($res.AppsTriggered) app" }; $row.Cells[8].Value = "Triggered: $($parts -join ', ')"; $row.Cells[8].Style.ForeColor = $c.Success }
            if ($res.UpdatesTriggered -gt 0) { for ($ui = 0; $ui -lt $res.UpdatesTriggered; $ui++) { Track-Action -Action 'PatchUpdate' -Target $res.Host -Result 'Triggered' } }
            if ($res.AppsTriggered -gt 0) { for ($ai = 0; $ai -lt $res.AppsTriggered; $ai++) { Track-Action -Action 'PatchApp' -Target $res.Host -Result 'Triggered' } }
        }
        $done = $script:PatchTotal - $script:PatchJobs.Count; $script:lblBulkProg.Text = "Patching: $done / $script:PatchTotal"
        if ($script:PatchJobs.Count -eq 0) { $script:PatchTimer.Stop(); $script:PatchTimer.Dispose(); $script:btnPatchSel.Enabled = $true; $script:btnScanAll.Enabled = $true; $script:lblBulkProg.Text = "Patch complete"; $script:lblBulkProg.ForeColor = $c.Success; Log "=== Patch complete ===" }
    }); $script:PatchTimer.Start()
})
$script:btnRebootSel.Add_Click({
    $selected = @(); foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[0].Value -eq $true) { $selected += $row.Cells[1].Value } }
    if ($selected.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("No workstations selected.","Nothing Selected"); return }
    if (-not $global:Credentials) { [System.Windows.Forms.MessageBox]::Show("Set credentials first.","No Credentials"); return }
    $confirm = [System.Windows.Forms.MessageBox]::Show("REBOOT $($selected.Count) workstation(s)?`n`nThis is immediate and forced.", "Confirm Reboot", 4, 16); if ($confirm -ne 'Yes') { return }
    $auth = "Negotiate"; Log "=== Rebooting $($selected.Count) workstation(s) ==="; $script:RebootJobs = @{}
    foreach ($comp in $selected) { foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[1].Value -eq $comp) { $row.Cells[8].Value = "Rebooting..."; $row.Cells[8].Style.ForeColor = $c.Warning; break } }
        $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($global:RebootBlock).AddArgument($comp).AddArgument($global:Credentials).AddArgument($auth); $script:RebootJobs[$comp] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:RebootTotal = $selected.Count; $script:RebootTimer = New-Object System.Windows.Forms.Timer; $script:RebootTimer.Interval = 500
    $script:RebootTimer.Add_Tick({
        foreach ($key in @($script:RebootJobs.Keys)) { $job = $script:RebootJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() } catch { $res = @{ Host=$key; Success=$false; Message=$_.ToString() } }
            $script:RebootJobs.Remove($key); if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            $row = $null; foreach ($r in $script:dgvBulk.Rows) { if ($r.Cells[1].Value -eq $res.Host) { $row = $r; break } }
            if ($row) { if ($res.Success) { $row.Cells[8].Value = "Reboot sent"; $row.Cells[8].Style.ForeColor = $c.Success; Track-Action -Action 'Reboot' -Target $res.Host -Result 'Sent' } else { $row.Cells[8].Value = "Reboot failed"; $row.Cells[8].Style.ForeColor = $c.Danger } }
        }
        if ($script:RebootJobs.Count -eq 0) { $script:RebootTimer.Stop(); $script:RebootTimer.Dispose(); $script:lblBulkProg.Text = "Reboot complete"; $script:lblBulkProg.ForeColor = $c.Success
            $rebooted = @(); foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[8].Value -eq 'Reboot sent') { $rebooted += $row.Cells[1].Value } }
            if ($rebooted.Count -gt 0) { $mon = [System.Windows.Forms.MessageBox]::Show("Monitor $($rebooted.Count) workstation(s) until they come back online?","Monitor Reboots?",4,32); if ($mon -eq 'Yes') { Show-RebootMonitor -ServerList $rebooted } } }
    }); $script:RebootTimer.Start()
})
$script:btnPingSweep.Add_Click({
    if ($script:dgvBulk.Rows.Count -eq 0) { return }; $script:btnPingSweep.Enabled = $false; $dimClr = [System.Drawing.Color]::FromArgb(90,90,130)
    foreach ($row in $script:dgvBulk.Rows) { $row.Cells[2].Value = "Pinging..."; $row.Cells[2].Style.ForeColor = $dimClr }
    ## v47 AFNET: TCP reachability (WinRM/SMB) instead of ICMP.
    $script:PingJobs = @{}; $sbPing = {
        param($s)
        $up = $false
        foreach ($port in 5985,445) {
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($s, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $up = $true }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }
            if ($up) { break }
        }
        @{ Host=$s; Up=$up }
    }
    $hosts = @(); foreach ($row in $script:dgvBulk.Rows) { $hosts += $row.Cells[1].Value }
    foreach ($h in $hosts) { $ps = [PowerShell]::Create(); $ps.RunspacePool = $script:RSPool; [void]$ps.AddScript($sbPing).AddArgument($h); $script:PingJobs[$h] = @{ PS=$ps; Handle=$ps.BeginInvoke() } }
    $script:PingTimer = New-Object System.Windows.Forms.Timer; $script:PingTimer.Interval = 300
    $script:PingTimer.Add_Tick({
        foreach ($key in @($script:PingJobs.Keys)) { $job = $script:PingJobs[$key]; if (-not $job.Handle.IsCompleted) { continue }
            try { $res = $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() } catch { $res = @{ Host=$key; Up=$false } }
            $script:PingJobs.Remove($key); if ($res -is [System.Collections.IEnumerable] -and $res -isnot [hashtable]) { $res = @($res)[0] }
            foreach ($row in $script:dgvBulk.Rows) { if ($row.Cells[1].Value -eq $res.Host) { if ($res.Up) { $row.Cells[2].Value = "Online"; $row.Cells[2].Style.ForeColor = $c.Success } else { $row.Cells[2].Value = "Offline"; $row.Cells[2].Style.ForeColor = $c.Danger }; break } }
        }; if ($script:PingJobs.Count -eq 0) { $script:PingTimer.Stop(); $script:PingTimer.Dispose(); $script:btnPingSweep.Enabled = $true }
    }); $script:PingTimer.Start()
})
$btnExport.Add_Click({ if ($script:dgvBulk.Rows.Count -eq 0) { return }; $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter = "CSV|*.csv"; $sfd.FileName = "WPT_BulkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq 'OK') { $rows = foreach ($row in $script:dgvBulk.Rows) { [PSCustomObject]@{ Host=$row.Cells[1].Value; Online=$row.Cells[2].Value; Drive=$row.Cells[3].Value; Reboot=$row.Cells[4].Value; MECM=$row.Cells[5].Value; WU=$row.Cells[9].Value; Apps=$row.Cells[6].Value; Scan=$row.Cells[7].Value; Patch=$row.Cells[8].Value } }; $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation } })
#endregion

## v6.0.0: PACKAGE DEPLOY EVENT HANDLER removed with the tab.

###############################################################################
###                         FORM CLEANUP & SHOW                             ###
###############################################################################
## The final lifecycle region. Runs in this order:
##   1. $f.Add_FormClosing (Legacy) - disposes all timers and stops all
##      in-flight PowerShell jobs in every $script:*Jobs hashtable,
##      then closes + disposes $script:RSPool.
##   2. $f.Add_FormClosing (v47.1 Phase 3) - ADDITIVE second handler
##      that runs after Legacy's. Only fires if $global:SessionStarted,
##      pops Show-WptClosingNotesDialog, and on Submit / Force writes
##      one aggregated row via Publish-WptUsageCsvRow. Wrapped in
##      try/catch so an error never blocks closure.
##   3. Initialize-RunspacePool  - pre-warm so the first operation
##      doesn't pay the pool-init cost.
##   4. $f.Controls.AddRange(@($pnlSide, $tc)) - sidebar + tab control
##      into the form (top strip and status strip were already docked
##      earlier).
##   5. $UpdateSidebar scriptblock invoked once to mark the initial
##      active nav item.
##   6. JANET CREDENTIAL INHERIT block (v5.1.0) - reads
##      $env:JANET_CRED_FILE if present, Import-Clixml, populates
##      $global:Credentials + updates Start tab labels.
##   7. $f.Add_Shown startup logs.
##   8. [void]$f.ShowDialog() - blocks until form is closed.
##   9. Write-AuditLog SessionEnd + $f.Dispose(). End of script.
#region === FORM CLEANUP & SHOW ===
Set-JanetAllowClose $false
$f.Add_FormClosing({
    param($sender, $e)

    ## X-block: only the Close Tool button is allowed to actually close
    ## the form. Any other origin (X chrome button, Alt-F4, right-click
    ## title-bar Close) hits the FormClosing pipeline and gets cancelled
    ## here. WindowsShutDown is excepted — let the OS shut down cleanly
    ## instead of forcing the operator through the nag-prompt loop.
    if (-not (Get-JanetAllowClose) -and $e.CloseReason -ne [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        $e.Cancel = $true
        return
    }

    foreach ($tmr in @($script:ScanTimer, $script:PatchTimer, $script:RebootTimer, $script:PingTimer, $script:RbTimer, $script:KBTimer, $script:KBInstallTimer, $script:CleanTimer, $script:RkScanTimer, $script:RkApplyTimer)) { if ($null -ne $tmr) { try { $tmr.Stop(); $tmr.Dispose() } catch {} } }
    foreach ($jobs in @($script:ScanJobs, $script:PatchJobs, $script:RebootJobs, $script:PingJobs, $script:CleanJobs, $script:RkScanJobs, $script:RkApplyJobs, $script:RkPostJobs, $script:installJobs, $script:kbJobs)) { if ($null -ne $jobs) { foreach ($j in $jobs.Values) { try { $j.PS.Stop(); $j.PS.Dispose() } catch {} } } }
    if ($null -ne $script:RSPool) { try { $script:RSPool.Close(); $script:RSPool.Dispose() } catch {} }
})
## v6.5.10: Notes outcome is now captured in the Close Tool click
## handler (so 'Return to Tool' can actually return before any cleanup
## runs). This handler picks the stashed $script:WptCloseOutcome up and
## fans it out to the audit log (always) + WPT CSV + JANET session
## close (only when a session was started). Wrapped in try/catch so an
## error here can never block form closure.
$f.Add_FormClosing({
    try {
        $outcome = $script:WptCloseOutcome
        if (-not $outcome) {
            ## Form closed without going through the Close Tool button
            ## (e.g., WindowsShutDown). Nothing operator-authored to log.
            return
        }
        $choice = [string]$outcome.Choice
        $notes  = [string]$outcome.Notes

        ## ALWAYS write the operator's notes to the audit log file so
        ## the closing context lands in $global:AuditLogPath even when
        ## the operator never clicked START SESSION (e.g., they opened
        ## the tool, looked at credentials, decided to back out, and
        ## want to leave a note for the next session).
        if ($choice -eq 'Submit') {
            try { Write-AuditLog -Action 'ClosingNotes' -Target 'N/A' -Result 'Submitted' -Detail $notes } catch {}
            try { Log "Closing notes recorded." 'OK' } catch {}
        } elseif ($choice -eq 'Force') {
            try { Write-AuditLog -Action 'ClosingNotes' -Target 'N/A' -Result 'ForceClose' -Detail '' } catch {}
        }

        ## Session-rollup writes only run when a session was actually
        ## started -- the WPT CSV and JANET session-close rows are
        ## meaningless for a boot-then-close with no work done.
        if ($global:SessionStarted) {
            if ($choice -eq 'Force') { Publish-WptUsageCsvRow -Notes '' | Out-Null }
            else                     { Publish-WptUsageCsvRow -Notes $notes | Out-Null }

            ## JANET centralized session close (v6.2.1 fix): ALWAYS writes
            ## the rollup row when a session was started. Notes carry
            ## through only when the operator explicitly Submitted; Force
            ## leaves notes empty. Stop-JanetSession nullifies
            ## $script:JanetSession, so any later re-entry becomes a
            ## no-op.
            try {
                $janetNotes = if ($choice -eq 'Submit') { $notes } else { '' }
                Stop-JanetSession -ClosingNotes $janetNotes
            } catch {
                try { Log "JANET Stop-JanetSession failed: $($_.Exception.Message)" 'WARN' } catch {}
            }
        }
    } catch {
        try { Log "Closing flow error: $($_.Exception.Message)" 'ERR' } catch {}
    }
})
Initialize-RunspacePool
$f.Controls.AddRange(@($pnlSide, $tc))
& $UpdateSidebar

## v5.1.0: Inherit shared credentials from J.A.N.E.T.ps1 launcher.
## JANET exports the PSCredential to %LOCALAPPDATA%\JANET\Session\janet_cred.xml
## via Export-Clixml (DPAPI-encrypted, current-user-only) and passes the path
## and username down to child tools via env vars. If both are present and the
## file round-trips cleanly, pre-populate $global:Credentials and update the
## Start tab UI so the operator only has to ack + click START SESSION.
## Falls through silently when launched directly (no env vars) -- the manual
## "Set Credentials" flow on Start tab continues to work unchanged.
if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $inheritedCred = Import-Clixml -LiteralPath $env:JANET_CRED_FILE -ErrorAction Stop
        if ($inheritedCred -is [System.Management.Automation.PSCredential]) {
            $global:Credentials = $inheritedCred
            if ($script:lblCredStatus) {
                $script:lblCredStatus.Text      = "$($inheritedCred.UserName)  (inherited from J.A.N.E.T.)"
                $script:lblCredStatus.ForeColor = $c.Success
            }
            if ($script:btnSetCredStart) {
                $script:btnSetCredStart.Text = "Override Credentials"
            }
            if ($script:lblSICred) {
                $script:lblSICred.Text      = "Credentials: $($inheritedCred.UserName) (from J.A.N.E.T.)"
                $script:lblSICred.ForeColor = $c.Success
            }
            Log "Credentials inherited from J.A.N.E.T. launcher: $($inheritedCred.UserName)" 'OK'
            Write-AuditLog -Action "CredentialInherit" -Result "OK" -Detail "User=$($inheritedCred.UserName) Source=JANET_CRED_FILE"
        } else {
            Log "JANET_CRED_FILE present but did not deserialize to a PSCredential" 'WARN'
        }
    } catch {
        Log "Failed to import inherited credentials from JANET_CRED_FILE: $($_.Exception.Message)" 'WARN'
    }
}

## v6.1.9: The v6.1.8 Anchor-toggle fix was insufficient. Setting
## Anchor = None then back to the intended value forces WinForms to
## recapture offsets, but it recaptures against the control's CURRENT
## Bounds, which were already wrong from the initial broken layout --
## so the bad geometry persisted. The Live Execution panel was still
## invisible (X pushed off-screen).
## New approach: bypass the anchor system entirely for the Cleanup tab
## and lay out its controls manually in a callback wired to both
## Form.Shown (initial render) and Form.Resize (window resize). The
## anchor-toggle walk is kept for other tabs that don't need per-pixel
## layout, so the Logs-tab scrollbar / other-tab Right-anchored bugs
## still get the belt-and-suspenders fix.
## Promote the Cleanup tab controls to script scope so the layout callback
## below can find them no matter how PS resolves event-handler scope.
$script:tabCleanup        = $tabCleanup
$script:grpCleanCfg       = $grpCleanCfg
$script:grpCleanTargets   = $grpCleanTargets
$script:lblCleanGridTitle = $lblCleanGridTitle
$script:lblCleanExecTitle = $lblCleanExecTitle
$script:lblCleanLogTitle  = $lblCleanLogTitle
$SetCleanupLayout = {
    $tab = $script:tabCleanup
    if ($null -eq $tab -or -not $tab.IsHandleCreated) { return }
    $w = $tab.ClientSize.Width
    $h = $tab.ClientSize.Height
    if ($w -le 200 -or $h -le 200) { return }
    $leftW  = 600
    $gap    = 6
    $topH   = 240
    $sumH   = 180
    $rightX = $leftW + $gap + 6
    $rightW = $w - $rightX - $gap
    $midY   = $topH + 26
    $midH   = $h - $midY - $sumH - 26
    $sumY   = $h - $sumH + 4
    if ($script:grpCleanCfg)       { $script:grpCleanCfg.SetBounds(6, 6, $leftW, $topH) }
    if ($script:grpCleanTargets)   { $script:grpCleanTargets.SetBounds($rightX, 6, $rightW, $topH) }
    if ($script:lblCleanGridTitle) { $script:lblCleanGridTitle.SetBounds(10, $topH + 8, 200, 18) }
    if ($script:dgvClean)          { $script:dgvClean.SetBounds(6, $midY, $leftW, $midH) }
    if ($script:lblCleanExecTitle) { $script:lblCleanExecTitle.SetBounds($rightX + 4, $topH + 8, $rightW - 8, 18) }
    if ($script:rtbCleanExec)      { $script:rtbCleanExec.SetBounds($rightX, $midY, $rightW, $midH) }
    if ($script:lblCleanLogTitle)  { $script:lblCleanLogTitle.SetBounds(10, $sumY - 20, 200, 18) }
    if ($script:rtbCleanLog)       { $script:rtbCleanLog.SetBounds(6, $sumY, $w - 12, $sumH - 12) }
}
$script:SetCleanupLayout = $SetCleanupLayout
$f.Add_Shown({
    ## First: anchor-toggle walk for every other tab with Right/Bottom
    ## anchors (Logs tab rtbLog in particular -- its scrollbar needs
    ## this to be clickable). The toggle works for controls whose
    ## design-time bounds happen to fit the default 200x100 TabPage.
    $stack = New-Object System.Collections.Generic.Stack[System.Windows.Forms.Control]
    $stack.Push($f)
    while ($stack.Count -gt 0) {
        $parent = $stack.Pop()
        foreach ($ctrl in $parent.Controls) {
            if ($ctrl.Controls.Count -gt 0) { $stack.Push($ctrl) }
            $a = $ctrl.Anchor
            if ($a -ne [System.Windows.Forms.AnchorStyles]::None -and
                ((([int]$a -band [int][System.Windows.Forms.AnchorStyles]::Right) -ne 0) -or
                 (([int]$a -band [int][System.Windows.Forms.AnchorStyles]::Bottom) -ne 0))) {
                $ctrl.Anchor = [System.Windows.Forms.AnchorStyles]::None
                $ctrl.Anchor = $a
            }
        }
    }
    ## Then: explicit manual layout for the Cleanup tab. Controls there
    ## have Right/Bottom anchors set at design-time against a 200x100
    ## default TabPage, so the offsets are broken beyond anchor-toggle
    ## repair. SetBounds puts them exactly where they belong based on
    ## the tab's actual current ClientSize.
    & $script:SetCleanupLayout
})
$f.Add_Resize({ if ($script:SetCleanupLayout) { & $script:SetCleanupLayout } })
$f.Add_Shown({ $f.Activate(); Log "J.A.N.E.T. Workstation Patching Tool v$JanetWptVersion initialized." 'OK'; Log "Session gating active -- complete setup on Start tab."; Log "Audit log: $($global:AuditLogPath)"; Log "Click 'Start' in the sidebar to begin." })
[void]$f.ShowDialog()
Write-AuditLog -Action "SessionEnd" -Result "Closed"
$f.Dispose()
#endregion