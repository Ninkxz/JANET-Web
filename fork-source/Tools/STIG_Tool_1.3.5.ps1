# STIG_Tool_1.3.5.ps1
# J.A.N.E.T. STIG Tool — PowerStig-backed DSC compliance
# Part of the Joint Administration and Network Execution Toolkit.
#
# SUITE INTEGRATION:
# This tool is a full member of the J.A.N.E.T. suite. It lives at
# J.A.N.E.T\Tools\STIG_Tool_<version>.ps1, launched either via the launcher
# (click the "STIG Tool" card in JANET.ps1) or directly.
#
# v1.3.5 - 2026-06-06 - Fix: Export-ScanToCklb (STIG Viewer 3 / CKLB JSON)
#     called Get-PowerStigRuleCatalog / Get-DisaStigIdentity WITHOUT
#     -TechnologyVersion / -OsVersion, so every non-2022 Windows Server host
#     resolved to the Server 2022 benchmark identity + rule catalog and the
#     .cklb would not merge in STIG Viewer / eMASS. Now mirrors Export-ScanToCkl
#     and passes the scanned OsVersion. Also corrected the stale
#     $global:ToolVersion (was v1.3.3) baked into export provenance strings.
#
# v1.3.4 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
#   *_usage*.csv so schema-rotation sister files (created when the legacy
#   file is persistently locked) are drained on next launch instead of
#   stranded.
#
# v1.3.3 - 2026-05-09 - CKLB Import: whole-feature review fixes.
#   * C-A: JANET centralized-logging events now route correctly. The
#     v1.3.0 Write-CklbAuditEvent wrapper called a non-existent
#     Write-JanetMetric — events were silent no-ops. Per-host CklbApply
#     events now go through Write-JanetAction (the existing per-host
#     fleet-rollup function); session-level events (CklbImport,
#     AnswerFileWrite, CklbResidualExport) go through Write-Audit.
#   * C-B: Set-FindingClassification gates 'PowerStigFixable' on a
#     Windows-tech allow-list. Real PowerStig has Adobe / Chrome /
#     Office / etc. StigData folders that the v1.3.0 classifier
#     happily tagged PS-fixable, but New-StigDscConfigFile rejects
#     anything outside Windows{Client|Server|Firewall|Defender}. Apply
#     would have errored on every non-Windows row. Now those classify
#     as Residual / Justifiable.
#   * I-B: Apply path now clears PendingAction on the host-not-in-
#     Targets branch so those rows reappear in the residual worklist
#     instead of silently leaking.
#   * I-C: Apply Fixes button shows a clear "Install PowerStig from
#     About tab" message when PowerStig isn't installed, instead of
#     silently reducing every finding to Residual.
#   * M-A: Show-StigMarkAnswerDialog renames $matches to $libMatches
#     to avoid shadowing PowerShell's automatic regex variable.
#   * M-C: Findings-summary label 'Already NF' renamed to 'Already
#     final (NF/NA)' since AlreadyClosed covers both.
#   * Pester +2 (non-Windows-tech classification, host-not-in-Targets
#     PendingAction rollback). Total now 47/47.
#   * Patch bump.
#
# v1.3.2 - 2026-05-09 - CKLB Import polish: DRY apply, sortable-grid bug
#   carry-over, rule-map disk cache, multi-STIG test coverage.
#   * Apply-tab UI handler now uses Invoke-StigPipelineForHost (introduced
#     in v1.3.1) instead of an inlined compile -> apply sequence — both
#     call sites finally share one path.
#   * Review tab grid columns set to NotSortable. Same latent bug the
#     v1.3.0 final reviewer caught on the CKLB Import grid: clicking a
#     column header silently desyncs the row index from the backing
#     data, leading to wrong-row mutations on Apply / skip-list.
#   * PowerStigRuleMap.json on-disk cache. Walking the StigData tree on
#     every first-import was multi-second on real PowerStig installs.
#     Cached by PowerStig module version; cache miss rebuilds.
#   * Pester: multi-STIG CKLB fixture + import test (real Evaluate-STIG
#     output for a multi-tech host produces multiple CKLBs; the parser
#     handles them but the coverage gap is now closed).
#   * Patch bump.
#
# v1.3.1 - 2026-05-09 - CKLB Import: surgical Apply via PowerStig wired.
#   The v1.3.0 stub for Invoke-StigApplyFromCklb is replaced by a real
#   implementation. New top-level helper Invoke-StigPipelineForHost
#   encapsulates the per-host compile -> Test -> Apply pipeline so the
#   Apply-tab UI handler and the CKLB Import handler share one path.
#   The CKLB Import tab's Apply Fixes button is now functional.
#
# v1.3.0 - 2026-05-08 - Evaluate-STIG CKLB import + AnswerFile authoring.
#   Adds a new "CKLB Import" tab that consumes Evaluate-STIG .cklb output,
#   classifies findings as PowerStig-fixable / Justifiable / Residual,
#   drives PowerStig DSC remediation against the fixable subset, authors
#   Evaluate-STIG AnswerFile XML (per Template_AnswerFile.xml schema) for
#   the rest, and emits an XLSX residual worklist.
#   Spec: docs/superpowers/specs/2026-05-08-stig-tool-cklb-import-design.md
#
# v1.2.20 - 2026-05-08 - JANET centralized-logging schema cleanup
#   (single SessionEnd rollup row; Snapshot rows retired) and the
#   WPT-themed Closing Notes prompt rolled across the suite.
#
# v1.2.19 - 2026-04-25 - Mid-scan freeze diagnostics + LCM state clear:
#   * Operator reported scan completed iteration 1/3 (~33%) on a work
#     host then froze. Without per-step log lines we can't tell if the
#     freeze was inside compile, Test-DscConfiguration, or somewhere
#     between. Most-likely cause: the LCM stayed in Busy/Pending state
#     after iteration 1's Test-DscConfiguration, and iteration 2's
#     test waited indefinitely for LCM to become Idle. (CERBERUS at
#     home didn't show this — likely because no WinRM service meant
#     the LCM transport was different.)
#   * Added Stop-DscConfiguration -Force between iterations in Local
#     mode. No-op when the LCM is Idle, clears Busy/Pending when not.
#   * Added per-step scan-log lines with elapsed-time stamps so the
#     next freeze pinpoints itself: "Generating DSC config", "Config
#     file: <path>", "MOF compiled in Xs", "Calling
#     Test-DscConfiguration (this may pause if LCM is busy)",
#     "Test-DscConfiguration finished in Xs — N records", and a
#     "Clearing LCM state before next iteration" line on every
#     iteration after the first.
#   * Extra DoEvents() calls between phases to keep the WinForms
#     message loop ticking even when DSC is slow.
#
# v1.2.18 - 2026-04-24 - PS 5.1 parser fix: inline `if` expression as positional arg:
#   * Scan-completion logging line had:
#       Write-StigScanLog ($statusParts -join '; ') (if (...) {'WARN'} else {'DONE'})
#     PS 5.1's parser doesn't accept `if` as an expression in a
#     positional-argument context — it tries to resolve `if` as a
#     cmdlet name, fails with "The term 'if' is not recognized as the
#     name of a cmdlet, function, script file, or operable program."
#     The handler aborted before any scan started running. (Hadn't been
#     hit before because v1.2.16's Local-mode WinRM/MOF-name failures
#     ended the scan loop before this line ran.)
#   * Fixed: assign the if-expression to a $logTag local first, then
#     pass $logTag positionally. Same code, parses cleanly.
#
# v1.2.17 - 2026-04-24 - Local DSC needs localhost.mof, not <hostname>.mof:
#   * v1.2.16's DCOM CimSession trick shifted the error from "winrm
#     quickconfig" to "computer-specific MOF file for computer localhost
#     does not exist in the current directory". The CimSession's
#     ComputerName defaulted to "localhost", so DSC looked for
#     localhost.mof — but we'd compiled CERBERUS.mof.
#   * Test-DscConfiguration / Start-DscConfiguration use the in-process
#     LCM API for localhost (no WinRM needed) IF the MOF folder contains
#     a file named localhost.mof. Dropped the DCOM CimSession entirely.
#     Local mode now copies the named MOF (e.g. CERBERUS.mof) to
#     localhost.mof in the same folder before calling Test/Start. The
#     original named MOF stays in place so Apply / Verify and any
#     downstream consumer that wants the host-identified MOF still has it.
#   * Same fix applied to Invoke-StigApply.
#
# v1.2.16 - 2026-04-24 - Local mode uses DCOM CimSession (no WinRM dep):
#   * After v1.2.15 fixed the path-doubling, the next layer of the
#     onion: Test-DscConfiguration in Local mode was still routing
#     through a WinRM-backed CimSession to talk to the local LCM. On
#     workstations where the WinRM service hasn't been configured
#     (most AFNET clients), every rule fails with "The client cannot
#     connect to the destination... run winrm quickconfig" — which
#     defeats the entire promise of Local mode.
#   * Invoke-StigEvaluation + Invoke-StigApply now build an explicit
#     DCOM CimSession when -Mode Local and pass it via -CimSession.
#     DCOM is always available on a Windows host, so Local scans /
#     applies work out of the box without enabling WinRM. Remote mode
#     unchanged — still WinRM / Negotiate as before.
#   * Compliance Summary CAT II / CAT III / Weighted % MinimumWidths
#     bumped so headers stop wrapping to two lines on common form
#     widths.
#
# v1.2.15 - 2026-04-24 - Invoke-StigCompile output leak (fixes "not a valid directory"):
#   * The scan log surfaced the bug nicely: every successful compile
#     showed "MOF compiled: E:\...CERBERUS.mof E:\...CERBERUS.mof" — the
#     same path repeated. Cause: `. $ConfigFile` (dot-source) inside
#     Invoke-StigCompile leaked the Configuration block's pipeline
#     output (the generated MOF FileInfo) into the function's output
#     collection alongside the explicit `return $mof.FullName`. The
#     function returned an ARRAY of two paths, the caller's $mofPath
#     became that array, and Split-Path -Parent emitted two parent
#     paths that bound back to [string]$MofFolder as a single
#     space-joined string. Test-DscConfiguration then reported
#     "<MOFdir> <MOFdir> is not a valid directory." — visible in the
#     scan log on every host as 1-rule eval errors with Pass/Fail/CAT
#     all 0. Fix: pipe `. $ConfigFile | Out-Null` so dot-source output
#     is discarded and only the explicit return value escapes.
#   * Compliance Summary grid: MOF column FillWeight 18->30 + Min 140
#     ->260 so the full path is visible (or near-visible). Other
#     columns rebalanced to share remaining width.
#
# v1.2.14 - 2026-04-24 - Targets-grid Select column + Scan Log panel:
#   * Targets grid Select column is now exactly checkbox-sized (30 px,
#     AutoSizeMode=None, non-resizable). The grid's other columns reclaim
#     all the space the wider checkbox column was eating, so OS / STIG
#     Applies / Error get more horizontal room. Error column FillWeight
#     bumped 16->24 + MinimumWidth 120->220 so the operator can read TCP
#     probe / WinRM error text without scrolling horizontally.
#   * Scan tab now has a Scan Log textbox docked Bottom inside the
#     Compliance Summary card (200 px tall). Compile + evaluate progress
#     and per-host eval errors append to it in real time with a
#     [HH:mm:ss] [TAG] prefix. TextBox is read-only but supports normal
#     text selection + Ctrl+C; right-click context menu adds Copy /
#     Select All / Copy All / Clear. Operators can highlight a stack
#     trace and paste it into a ticket without dumping the console.
#   * Helper: function global:Write-StigScanLog -Message X -Tag (INFO|
#     STEP|OK|WARN|ERR|DONE). Wired into the Start Scan handler around
#     each compile step, evaluation step, and completion summary.
#
# v1.2.13 - 2026-04-24 - AddRange Z-order fix (Dock=Fill must be added first):
#   * v1.2.12 switched to Dock-based layouts but the AddRange order was
#     wrong: grpHosts (Left) was added before grpDiscovered (Fill). In
#     WinForms, docking processes the Controls collection in REVERSE
#     Z-order (highest index docks first). With Fill added LAST it
#     docked first and claimed the entire parent area, then Dock=Left
#     grpHosts was placed on top of it covering the first columns of
#     the grid. Operators saw "Add Hosts" panel sitting over the left
#     half of the Discovered Targets grid, hiding the Host / Online
#     columns. Same on Scan / Review / Apply / Verify tabs.
#   * Reversed every AddRange so Dock=Fill is added FIRST (becomes
#     lowest-index, docks LAST, gets leftover space):
#       Targets : @($grpDiscovered, $grpHosts)
#       Scan    : @($grpScanGrid, $grpScanHosts, $grpScanCtl)
#       Review  : @($grpRevGrid, $grpRevCtl)
#       Apply   : @($grpApplyLog, $grpApplyCtl, $pnlDanger)
#       Verify  : @($grpVerGrid, $grpVerCtl)
#
# v1.2.12 - 2026-04-24 - Anchor -> Dock: tab layouts grow with the form:
#   * v1.2.11's Anchor=Top+Left+Right+Bottom on the right-pane groups
#     didn't actually grow the panels on a maximized window. Anchor
#     distances are captured at add-time, but the parent TabPages
#     hadn't been sized yet (TabControl Dock=Fill sizing happens after
#     the form's first Show), so the captured "distance from bottom"
#     was nonsensically large and the panels never expanded vertically.
#     Operators saw a one-row Discovered Targets grid sitting at the
#     top of a mostly-empty pane on a wide screen.
#   * Switched to Dock-based layouts for every tab. WinForms computes
#     dock positions on every layout pass, so they react correctly to
#     the actual current parent size:
#       - Targets : grpHosts Dock=Left (W=520) / grpDiscovered Dock=Fill
#       - Scan    : grpScanCtl Dock=Top  (H=150) /
#                   grpScanHosts Dock=Left (W=380) /
#                   grpScanGrid Dock=Fill
#       - Review  : grpRevCtl Dock=Top   (H=80)  / grpRevGrid Dock=Fill
#       - Apply   : pnlDanger Dock=Top   (H=36)  /
#                   grpApplyCtl Dock=Top (H=220) / grpApplyLog Dock=Fill
#       - Verify  : grpVerCtl Dock=Top   (H=90)  / grpVerGrid Dock=Fill
#     Each TabPage gets Padding=15 so docked children sit off the edges.
#     Inner DataGridViews are Dock=Fill within their group with the
#     group's Padding=15 providing the inset margin. No more anchor math.
#
# v1.2.11 - 2026-04-24 - Layout pass: maximize + grid anchors + column widths:
#   * Form launches Maximized. ClientSize bumped 1360x800 -> 1600x900,
#     MinimumSize bumped 1200x720 -> 1366x800. STIG rule titles + grid
#     columns get the horizontal space they need without the operator
#     dragging the window every session.
#   * Grid + groupbox anchors added on the Targets / Scan / Review /
#     Apply / Verify tabs. Previously the right-pane groups (Discovered
#     Targets, Compliance Summary, Per-Rule Results, Apply Log, Diff
#     Results) were Top+Left only — they didn't grow when the form was
#     widened, so columns stayed cramped even on a maximized window.
#     All five panels + their grids now Anchor=Top+Left+Right+Bottom.
#   * Grid column MinimumWidth set on every column across all five grids
#     so headers like "Online", "WinRM", "Last Scan", "STIG Applies",
#     "CAT I Fail", "CAT II Fail", "Weighted %", "MOF" no longer clip
#     to "Onli" / "WinF" / "Last Sca" / "Weighte..." even when the
#     window is dragged narrow. FillWeights also bumped for content
#     columns (OS, Tech, Title) so they get the extra space when
#     available.
#   * Grids set ScrollBars=Both as a safety net so rows that overflow
#     the visible width on a small window still scroll horizontally.
#
# v1.2.10 - 2026-04-24 - Wholesale $script: -> $global: + Close Tool relocated:
#   * Scan tab still threw closure-isolation null-ref errors against
#     $script:StigVersionPins, $script:SkipLists, $script:EvalRoot, and
#     other workspace-state variables. Same root cause as v1.2.7-v1.2.9
#     (PS 5.1 .GetNewClosure() handlers each capture their own snapshot
#     of $script: scope, so writes from one closure don't propagate to
#     reads from another).
#   * Bulk-converted EVERY $script: reference in the file (711 sites) to
#     $global: scope. All bootstrap state (workspace paths, runspace
#     pool, audit log, prereq status, supported tech, palette colors,
#     fonts, UI control refs, scan/skip/metadata caches, etc.) now lives
#     in process scope so every closure agrees on the value. The prior
#     incremental conversions (Targets, JanetAllowClose, ExecutionMode,
#     RemoteCred, ApplyInProgress) are subsumed here.
#   * Close Tool button moved from the bottom-left sidebar to the
#     top-right content strip, immediately left of the live heartbeat
#     indicator. Always visible without scrolling the sidebar. Operator
#     info (User / Mode / Creds / Host) stays in the sidebar bottom.
#     pnlUser height reduced 160 -> 110 to match the trimmed content.
#
# v1.2.9 - 2026-04-24 - Close Tool button visibility + X-block removal:
#   * Close Tool button has been INVISIBLE since the close-button feature
#     shipped. Root cause: $pnlUser used Anchor=Bottom + Location calculated
#     from $pnlSidebar.ClientSize.Height, but at form-build time the sidebar
#     was not yet sized (Dock=Left sizing happens after add). Default
#     ClientSize.Height was ~100, making $pnlUser.Top resolve to -60 — the
#     panel was positioned ABOVE the visible sidebar. The Bottom anchor
#     never recovered cleanly because navHost (Anchor=Top+Bottom) was
#     expanding past it. Switched $pnlUser to Dock=Bottom (Height=160) and
#     added a sidebar Resize handler that explicitly sets navHost.Height
#     so the two never overlap. Operator block + Close Tool button now
#     render at the bottom of the sidebar as designed.
#   * X-block removed. The X chrome button, Alt-F4, and right-click Close
#     menu all close the form normally now. The Apply-in-progress
#     confirmation is the only remaining guard. Get-/Set-JanetAllowClose
#     are still defined for backward-compatibility but no longer gate
#     anything — clicking Close Tool just calls $AppForm.Close() like
#     before but no FormClosing veto comes from the AllowClose flag.
#   * $global:ApplyInProgress also converted to $global: (set in Apply
#     click handler closure, read in FormClosing closure — same isolation
#     pattern as v1.2.7 / v1.2.8).
#
# v1.2.8 - 2026-04-24 - ExecutionMode/RemoteCred moved to $global: scope:
#   * Local-mode scan against the operator's own machine reported "TCP 445
#     (SMB) is open but WinRM (5985) is not" even though Local mode is
#     supposed to bypass WinRM entirely. Same closure-isolation pattern as
#     v1.2.7: rbLocal.Add_CheckedChanged wrote $global:ExecutionMode = 'Local'
#     into one closure's snapshot of script scope, but the Test Reachability
#     click handler's closure read $global:ExecutionMode as $null, fell into
#     the REMOTE branch, and ran the WinRM/SMB TCP probe instead of the local
#     CIM/DCOM path.
#   * Converted $global:ExecutionMode and $global:RemoteCred (the credential
#     written by "Set Credentials" — same broken-write pattern) to $global:
#     scope. Now mode-switch and credential changes propagate to every
#     handler. The "Set Credentials" button, Test Reachability, scan, apply,
#     and verify handlers all read consistently.
#
# v1.2.7 - 2026-04-24 - $global: scope migration (closure-visibility fixes):
#   * Targets-state visibility: v1.2.6 fixed the "bare hashtable" symptom
#     but operators still saw "No targets to probe" on Test Reachability
#     immediately after a successful Add (audit log: total=2, but next
#     handler reads count=0). Root cause: PS 5.1 .GetNewClosure() handlers
#     each capture their own view of $global: scope; one closure's
#     $global:Targets = ... write does NOT propagate to other closures'
#     $global:Targets reads. Documented in the user's "PS 5.1 closures
#     need global:-scoped helpers" memory note.
#     Renamed every $global:Targets reference to $global:Targets (45 sites
#     across the file: bootstrap init, Save-/Load-StigTargets, the four
#     closure click handlers on the Targets tab, $SyncGrid, scan/review/
#     apply tab readers, Update-StigScanHostPicker). All closures now
#     share one process-scope binding.
#   * Close Tool / X-close: same root cause. Get-/Set-JanetAllowClose
#     are global functions that internally read/wrote $global:JanetAllowClose.
#     The Close Tool button (one closure) called Set to true, but the
#     FormClosing handler (a different closure) read $global:JanetAllowClose
#     as $null/false and refused the close. Switched both helpers to
#     $global:JanetAllowClose. The X button, Alt-F4, and Close Tool button
#     all unblock the form correctly now.
#   * Patch bump.
#
# v1.2.6 - 2026-04-24 - $global:Targets closure-mutation fix (partial):
#   * Inside .GetNewClosure() click handlers, "$global:Targets += @{...}"
#     could resolve $global:Targets as $null. PS 5.1 then collapses
#     "$null + @{...}" to the bare hashtable, so $global:Targets ended up
#     as a single hashtable (Count=9 — the key count) instead of an array
#     of one hashtable. Symptom: status said "Added 1 host(s)", but the
#     grid stayed empty and Test Reachability reported "Add hosts to the
#     list first" because $global:Targets.Count was misread.
#   * Both += sites (+ Add to list, Test Reachability auto-add) now build
#     into a local with @($global:Targets) cast first, then write back
#     with $global:Targets = @($local). Array semantics are guaranteed
#     even if the closure read returns null.
#
# v1.2.5 - 2026-04-24 - Targets-tab closure-binding fix:
#   * $SyncGrid / $RefreshPre / $LoadReviewEntry were defined without
#     .GetNewClosure(). Worked synchronously during tab build, but every
#     post-build invocation from a click handler crashed with
#     "$gridTargets.Rows.Clear() — null-valued expression" because the
#     captured locals (DataGridView, labels, etc.) were unreachable once
#     the build function had returned. All three now close over their
#     scope correctly.
#
# v1.2.4 - 2026-05-06 - Second-pass review hardening:
#   * Atomic JSON write extended to Export-ScanToCklb and per-host
#     evaluation.json so a kill mid-write can't truncate either.
#   * Apply-in-progress UI guard: FormClosing refuses to close while a
#     real Apply loop is running unless the operator explicitly confirms;
#     status bar shows elapsed time on completion; apply handler now
#     wraps in try/catch/finally so an unhandled exception can't leave
#     the button disabled and the in-progress flag stuck.
#   * Audit log: per-row monotonic sequence number + a BoundaryStart
#     row at session launch that records the previous file's last seq.
#     A gap between sessions is evidence of tampering.
#   * Restore-point failures tracked in a separate dict (was conflated
#     with success-suppression in v1.2.3); failure list surfaces at the
#     end of the apply log.
#   * Stale-MOF removal failures in Invoke-StigCompile now throw instead
#     of silently swallowing — prevents apply against the wrong (older)
#     MOF when a previous DSC apply still holds a lock.
#   * DNS resolves in CKL/CKLB exporters bounded to 1s via runspace.
#   * Removed dead Test-TargetReachability legacy function.
#   * MessageBox -eq/-ne compares the DialogResult enum.
#
# v1.2.3 - 2026-05-06 - Full STIG-grade security + reliability review.
#   * Critical: New-StigDscConfigFile validates ComputerName / Technology /
#     OsVersion / OsRole / StigVersion / SkipRule against allow-lists before
#     interpolating into the generated .ps1 — closes a config-injection RCE
#     where a spoofed Win32_OperatingSystem.Caption from a hostile target
#     could break out of the single-quoted strings.
#   * Hostname allow-list validation in + Add to list.
#   * Atomic file writes (write-tmp -> File.Replace) for Targets.json /
#     SkipLists / RuleMetadata — no more truncated persistence on crash.
#   * Invoke-StigBoundedRemote helper with bounded New-PSSessionOption
#     (180s op / 15s open / Negotiate) used in LCM probe, restore-point
#     creation, and reboot detection. Replaces unbounded Invoke-Command
#     calls that previously froze the UI for ~3 min per half-broken host.
#   * Apply confirm-token reset moved to immediately-after-pass so a
#     declined LCM warning can't bypass the typed gate on the next click.
#   * Probe runspace results now read .HadErrors / .Streams.Error so
#     script-block crashes surface with a real error instead of a silent
#     "(no OS, no role)" row.
#   * Audit log buffers + replays on share-offline blip; counter exposed
#     to operator. Tri-state scan-complete status text. Reboot-detection
#     failures are treated as needs-reboot instead of silently dropped.
#   * v1.2.2 ordering bug fixed: $global:LastInstallResult set BEFORE
#     Add_Shown wires its closure (otherwise StrictMode 3 null-deref on
#     first form render).
#   * Stale help/workflow strings updated for the v1.2.2 "+ Add to list"
#     workflow.
#
# v1.2.2 - 2026-05-06 - Targets tab usability overhaul. Hosts can now be
#   added without first running a reachability probe (+ Add to list button),
#   the list persists across launches in Workspace\Targets.json, and Test
#   Reachability uses a TCP 5985/445 probe (ported from WPT) instead of
#   ICMP — AFNET firewalls block ICMP, which made Online=no for hosts that
#   were actually reachable. New "Remove selected" button. Scan-tab host
#   picker auto-refreshes whenever the targets list changes.
#
# v1.2.1 - 2026-04-25 - Added JANET centralized logging. Per-host ApplySTIG rows
#   (Success / Failure / Skipped, with pre-apply non-compliant count as ItemCount)
#   go to \\dm-tn-01\sh-usafe-automation$\JANET\Logs\STIG\<YYYY-MM>_detail.csv;
#   rollup row per session goes to <YYYY-MM>_usage.csv at the log root.
#   JANET closing-notes dialog captures ASI+notes on form close.
#   Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
#
# v1.1.0 inlines the suite-shared UI kit (Tools\UI\Theme.ps1 + Controls.ps1
# + Dialog.Info.ps1) verbatim so the script is now self-contained in the
# same shape as WorkstationPatchingTool_6.1.10.ps1 — no runtime dot-sourcing
# of the UI kit, copy this .ps1 anywhere and it runs. Re-inline the UI kit
# below if the shared files are edited.
#
# When launched from inside the J.A.N.E.T. suite folder layout, workspace
# artifacts live at <J.A.N.E.T root>\STIG_Workspace\ — a suite-level
# folder alongside JANET's own Logs\ and Images\. This keeps Tools\ clean
# and matches WPT's "WPT.config.json at the suite root" convention.
# When launched standalone (script moved elsewhere), workspace falls back
# to <script dir>\Workspace, then %LOCALAPPDATA%\STIG_Tool\Workspace.
# The About tab shows which path is active.
#
# WORKFLOW (matches PowerStig docs):
#   1. Evaluate the system   -> Test-DscConfiguration against compiled MOF
#   2. Review the checklist  -> per-rule grid populated from PowerStig StigData
#   3. Adjust (skip-list)    -> uncheck rules to exclude from apply
#   4. Apply                 -> Start-DscConfiguration (Checkpoint-Computer first on workstations)
#   5. Rescan & Verify       -> diff vs prior scan: Resolved / Still Failing / Regression
#   6. Export                -> XLSX report via ImportExcel, or per-host CKL
#
# v1.0 scope: Windows 10/11 Client + Server 2019/2022 + Firewall + Defender.
# Local and remote (WinRM) execution both supported.

#region ------------------------ BOOTSTRAP --------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v1.2.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\STIG\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetSTIGVersion = '1.3.5'

# === BEGIN JANET LOGGING BLOCK (paste from here) ===
$JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

$global:JanetSession   = $null
$global:JanetNetworkOk = $false

## Closure-safe getter — closures created with .GetNewClosure() under StrictMode 3
## cannot reliably resolve $global:Foo. Helpers used from inside closures must
## be declared at global scope so they are always visible.
function global:Get-JanetSession { return $global:JanetSession }

## X-block flag. Initialized $false in the form builder; set $true only by
## the Close Tool button handler. The FormClosing handler cancels any close
## that arrives without the flag set (X, Alt-F4, right-click-close), except
## WindowsShutDown which is allowed through so the OS doesn't nag-prompt the
## operator. Removes the per-host snapshot churn from the rollup CSV by
## guaranteeing every session ends through Stop-JanetSession.
## Allow-close gate: the FormClosing handler refuses any close that didn't
## come through the Close Tool button. Stored in $global: so writes from one
## closure (Close Tool button) are visible to reads from another closure
## (FormClosing handler). $global: would be sandboxed per-closure in PS 5.1
## .GetNewClosure() handlers and the Close Tool button would never unblock
## the X / Alt-F4 path.
function global:Get-JanetAllowClose { return [bool]$global:JanetAllowClose }
function global:Set-JanetAllowClose { param($Value) $global:JanetAllowClose = [bool]$Value }

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
    if ($null -eq $global:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\{0}\{1}" -f $global:JanetSession.Tool, $userFolder)
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
    if ($null -eq $global:JanetSession) { return $null }
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

    if ($global:JanetNetworkOk -eq $false -and $null -ne $global:JanetSession) {
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

    if ($null -ne $global:JanetSession) { $global:JanetNetworkOk = $false }
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
    $global:JanetSession   = Initialize-JanetSession -Tool $Tool -Version $Version -Operator $Operator -ASI $ASI
    $global:JanetNetworkOk = Test-JanetNetwork

    if ($global:JanetNetworkOk -and -not $SkipReplay) {
        try { Invoke-JanetReplay } catch {
            Write-Host ("NOTE: JANET replay skipped: $_") -ForegroundColor Yellow
        }
    }
}

## Header strings for the two CSV families. Pinned here so every tool
## emits the exact same column order. Detail header has 10 columns; usage
## header has 10 columns. ConvertTo-JanetCsvLine uses the same comma-strip
## rules the data rows use, so the header line round-trips cleanly.
$global:JanetDetailHeader = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
$global:JanetUsageHeader  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

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
    ## rows don't pollute the legacy file. Reuses the rotation timestamp in
    ## the suffix so concurrent writers in the same second land in the same
    ## sister file (deterministic per-second naming).
    $dir    = Split-Path -Parent $Path
    $base   = [IO.Path]::GetFileNameWithoutExtension($Path)
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

    if ($null -eq $global:JanetSession) {
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
    $beforeCount = $global:JanetSession.Hosts.Count
    [void]$global:JanetSession.Hosts.Add($Target)
    $afterCount  = $global:JanetSession.Hosts.Count
    $newHost = ($afterCount -gt $beforeCount)

    if ($Result -eq 'Failure') {
        $global:JanetSession.Failures++
    }
    if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') {
        ## Failed patches don't count as "vuln patched" — only successful or
        ## skipped (where skip means already-patched, still effectively applied).
        $global:JanetSession.VulnsPatched += [int]$ItemCount
    }

    ## Per-user detail CSV — Nemesis-style folder layout:
    ##   Logs/<Tool>/<user> - <COMPUTER>_<user>/<YYYY-MM>_detail.csv
    $userFolder = Get-JanetUserFolderName
    $netDir   = Join-Path (Join-Path $JanetLogRoot $global:JanetSession.Tool) $userFolder
    $localDir = Get-JanetLocalDir
    $fileName = Get-JanetMonthFile -Detail
    $netFile   = Join-Path $netDir   $fileName
    $localFile = Join-Path $localDir $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $global:JanetDetailHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $global:JanetSession.SessionId,
        $global:JanetSession.Operator,
        $global:JanetSession.ASI,
        $global:JanetSession.Tool,
        $global:JanetSession.Version,
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
    if ($null -eq $global:JanetSession) { return }
    $duration    = (Get-Date) - $global:JanetSession.StartTime
    $durationMin = [Math]::Round($duration.TotalMinutes, 1)

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $global:JanetSession.SessionId,
        $global:JanetSession.Operator,
        $global:JanetSession.ASI,
        $global:JanetSession.Tool,
        $global:JanetSession.Version,
        'SessionEnd',
        $global:JanetSession.Hosts.Count,
        $global:JanetSession.VulnsPatched,
        $global:JanetSession.Failures,
        $durationMin,
        $ClosingNotes
    )

    $fileName  = Get-JanetMonthFile
    $netFile   = Join-Path $JanetLogRoot              $fileName
    $localFile = Join-Path (Get-JanetLocalRollupDir)  $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $global:JanetUsageHeader
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

    if ($null -eq $global:JanetSession) {
        Write-Host "WARNING: Stop-JanetSession called with no active session; ignored." -ForegroundColor Yellow
        return
    }

    if ($ShowDialog) {
        $dialogResult = Show-JanetClosingNotesForm
        if ($null -ne $dialogResult.ASI -and $dialogResult.ASI -ne '') {
            $global:JanetSession.ASI = $dialogResult.ASI
        }
        if ($null -ne $dialogResult.Notes) {
            $ClosingNotes = $dialogResult.Notes
        }
    }

    ## SessionEnd row — the only rollup row this tool writes. Schema
    ## matches $global:JanetUsageHeader (12 cols incl. SessionId + RowType).
    ## Exactly one row per session, written from Stop-JanetSession. The dashboard
    ## parser still groups by SessionId to absorb legacy v1.8.x logs that emitted
    ## intermediate Snapshot rows; new sessions never produce them.
    Write-JanetRollupSnapshot -ClosingNotes $ClosingNotes

    $global:JanetSession   = $null
    $global:JanetNetworkOk = $false
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

    if ($null -eq $global:JanetSession) { return }
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
        $detailNet = Join-Path (Join-Path $JanetLogRoot $global:JanetSession.Tool) $userFolder
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


$global:ToolVersion     = 'v1.3.5'
$global:ToolName        = 'J.A.N.E.T. STIG Tool'
$global:ToolSubtitle    = 'Joint Administration and Network Execution Toolkit'

# --- Resolve script root (portable across launch methods) ----------------
# Order of preference:
#   1. $PSScriptRoot            (set when run via .ps1 file, ISE, VS Code, -File)
#   2. $MyInvocation.MyCommand.Path (set when dot-sourced from a path)
#   3. Current working directory (last-ditch; only happens if code is pasted
#      into an interactive console, which is not a supported launch path)
$global:ScriptRoot = $null
if ($PSScriptRoot) {
    $global:ScriptRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $global:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $global:ScriptRoot = (Get-Location).Path
}

# --- Detect whether we're embedded inside a J.A.N.E.T. suite layout -----
# Convention: J.A.N.E.T\JANET.ps1 at the suite root, with tools under
# J.A.N.E.T\Tools\. If the script's parent folder is "Tools" AND the
# grandparent contains a JANET.ps1, we're embedded — use the suite root
# for workspace so multiple tools can share a common data area and Tools\
# stays clean. Otherwise fall back to the standalone layout.
function Test-JanetEmbedded {
    param([string]$ScriptRoot)
    try {
        $parent = Split-Path -Leaf $ScriptRoot
        if ($parent -ne 'Tools') { return $null }
        $suiteRoot = Split-Path -Parent $ScriptRoot
        if (-not $suiteRoot) { return $null }
        $janetScript = Join-Path $suiteRoot 'JANET.ps1'
        if (Test-Path $janetScript) { return $suiteRoot }
        return $null
    } catch {
        return $null
    }
}
$global:JanetSuiteRoot = Test-JanetEmbedded -ScriptRoot $global:ScriptRoot
$global:IsJanetMember  = [bool]$global:JanetSuiteRoot

# --- Pick a workspace location that we can actually write to -------------
# Preference chain:
#   1. <J.A.N.E.T root>\STIG_Workspace      (when embedded — suite-level)
#   2. <script folder>\Workspace            (standalone — next to .ps1)
#   3. %LOCALAPPDATA%\STIG_Tool\Workspace   (last-resort fallback)
function Resolve-WorkspaceRoot {
    param([string[]]$Candidates)
    foreach ($c in @($Candidates | Where-Object { $_ })) {
        try {
            if (-not (Test-Path $c)) {
                New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null
            }
            # Probe writability
            $probe = Join-Path $c ".write_probe_$([guid]::NewGuid().ToString('N'))"
            Set-Content -Path $probe -Value 'ok' -ErrorAction Stop
            Remove-Item $probe -Force -ErrorAction SilentlyContinue
            return $c
        } catch {
            continue
        }
    }
    throw "Could not find a writable workspace location. Tried: $($Candidates -join '; ')"
}

if ($global:IsJanetMember) {
    # Suite-level: keep Tools\ clean, share a root-level workspace
    $global:WorkspaceRootPreferred = Join-Path $global:JanetSuiteRoot 'STIG_Workspace'
} else {
    $global:WorkspaceRootPreferred = Join-Path $global:ScriptRoot 'Workspace'
}
$global:WorkspaceRoot       = Resolve-WorkspaceRoot -Candidates @(
    $global:WorkspaceRootPreferred,
    (Join-Path $env:LOCALAPPDATA 'STIG_Tool\Workspace')
)
$global:WorkspaceIsFallback = ($global:WorkspaceRoot -ne $global:WorkspaceRootPreferred)

$global:ConfigsDir      = Join-Path $global:WorkspaceRoot 'Configs'
$global:MofRoot         = Join-Path $global:WorkspaceRoot 'MOF'
$global:EvalRoot        = Join-Path $global:WorkspaceRoot 'Evaluations'
$global:ChecklistRoot   = Join-Path $global:WorkspaceRoot 'Checklists'
$global:ReportRoot      = Join-Path $global:WorkspaceRoot 'Reports'
$global:SkipListRoot    = Join-Path $global:WorkspaceRoot 'SkipLists'
$global:LogRoot         = Join-Path $global:WorkspaceRoot 'Logs'
$global:AuditLogPath    = Join-Path $global:LogRoot 'audit.log'

# --- Inlined UI kit (self-contained) --------------------------------------
# Verbatim copy of Tools\UI\Theme.ps1 + Controls.ps1 + Dialog.Info.ps1 as of
# 2026-04-23, making this script self-contained in the same shape as WPT
# 6.1.10. If you edit the shared UI files under Tools\UI\ later, re-inline
# the updated bodies below to keep palette/factories in sync across the
# suite. The $global:WPT shim below is the namespace that the inlined
# theme + control factories write into.
if (-not $global:WPT) {
    $global:WPT = @{
        ModuleRoot = $global:ScriptRoot
        ToolsRoot  = Split-Path $global:ScriptRoot -Parent
        UI = @{
            Form     = $null
            Theme    = $null
            Fonts    = $null
            Icons    = $null
            Controls = @{}
            TabPages = @{}
            NavItems = @{}
        }
    }
}

## --- From Tools\UI\Theme.ps1 ---

<#
.SYNOPSIS
    Purple + Gold on Black theme - matches the JANET.ps1 launcher palette
    exactly, plus an auto-contrast button fix so dark buttons on dark
    panels are readable.

.DESCRIPTION
    RGB triples are copied verbatim from JANET.ps1's `$c*` color variables
    so the WPT window looks like part of the same suite. The ONLY behavioral
    change versus the launcher is that New-WptButton now picks a contrasting
    foreground automatically - bright Bg gets dark text (TextOnAccent),
    dark Bg gets near-white text (TextPrimary). That's what fixes the
    previously-unreadable "Select All / Deselect / Select With Updates /
    Export CSV" buttons (dark text on PanelLight dark-grey bg).
#>

function Initialize-WptTheme {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing      -ErrorAction SilentlyContinue

    ## HIGH-DPI AWARENESS must be set before ANY window is created in the
    ## process, otherwise Windows bitmap-scales the whole app on 125%/150%
    ## displays -> text (especially inside Flat-style buttons) looks blurry.
    ## Must come before EnableVisualStyles.
    Set-WptDpiAware

    ## EnableVisualStyles + SetCompatibleTextRenderingDefault must both be
    ## called BEFORE any IWin32Window exists in the process. If the user
    ## relaunches the tool in the same PowerShell session (or has already
    ## done anything that creates a window - Get-Credential, a prior Show-
    ## WptMainForm, etc.), these calls throw. They're cosmetic/rendering
    ## hints, not critical correctness. Swallow both so relaunches work.
    try { [System.Windows.Forms.Application]::EnableVisualStyles() }           catch {}
    try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

    $c = { param($r,$g,$b) [System.Drawing.Color]::FromArgb($r, $g, $b) }

    ## ============================================================
    ## Purple + Gold on Black palette. Primary accent is PURPLE
    ## (#8C64DC), secondary accent is GOLD (#DAB452). Surfaces are
    ## near-black with a faint violet lean. Text hierarchy uses
    ## lavender-tinted whites. Status colors are semantic (green /
    ## red / amber / blue).
    ## ============================================================
    $global:WPT.UI.Theme = [pscustomobject]@{
        ## ============ Surfaces (black with faint violet lean) ============
        Background      = & $c   8   8  12   ## near-black
        Sidebar         = & $c   6   6  10   ## deeper for sidebar
        TitleBar        = & $c   6   6  10
        StatusBar       = & $c   7   7  11
        Surface         = & $c  16  16  22   ## card base / row base
        SurfaceAlt      = & $c  22  22  30   ## row alternate
        SurfaceHover    = & $c  30  28  40   ## row hover
        SurfaceActive   = & $c  40  36  54   ## row active

        ## ============ Borders (violet-tinted) ============
        Border          = & $c  38  34  52
        BorderStrong    = & $c  52  46  72
        BorderAccent    = & $c 140 100 220   ## purple - active nav accent bar

        ## ============ Primary accent - PURPLE #8C64DC ============
        Accent1         = & $c 140 100 220   ## #8C64DC - purple
        Accent1Hover    = & $c 164 128 240   ## brighter for hover
        Accent1Muted    = & $c  96  68 156   ## darker, for disabled / subtle
        Accent1Glow     = & $c  28  20  48   ## dark bg wash

        ## ============ Secondary accent - GOLD #DAB452 ============
        Accent2         = & $c 218 180  82   ## #DAB452 - gold
        Accent2Hover    = & $c 238 200 110

        ## ============ Semantic status ============
        Success         = & $c  92 198 120
        SuccessHover    = & $c 120 220 148
        Warning         = & $c 230 180  70
        WarningHover    = & $c 248 200 100
        Danger          = & $c 224  80  90
        DangerHover     = & $c 244 110 118
        Info            = & $c  88 180 210

        ## ============ Text hierarchy (lavender-tinted whites) ============
        TextPrimary     = & $c 240 240 245
        TextSecondary   = & $c 170 168 180
        TextMuted       = & $c 110 106 125
        TextFaint       = & $c  60  56  74
        TextDisabled    = & $c  60  56  74
        TextOnAccent    = & $c 255 255 255   ## white, used on purple buttons

        ## ============ Data grid ============
        GridBgPrimary   = & $c  16  16  22
        GridBgAlt       = & $c  22  22  30
        GridHeader      = & $c  10  10  16
        GridSelection   = & $c  28  20  48   ## purple glow on selected row
        GridLine        = & $c  38  34  52

        ## ============ Console / log ============
        ConsoleBg       = & $c   6   6  10
        ConsoleFg       = & $c 164 128 240   ## purple phosphor
        ConsoleMuted    = & $c  96  68 156

        ## ============ Accent stripe (purple + black) ============
        StripeYellow    = & $c 140 100 220   ## purple stripe color
        StripeBlack     = & $c   8   8  12

        ## ============ Backward-compatible aliases ============
        ## Tab code uses these names.
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
        Accent          = & $c 140 100 220   ## purple
        Gold            = & $c 218 180  82   ## gold (DGV headers, count labels)
        Console         = & $c 218 180  82   ## gold
        Cyan            = & $c  88 180 210
        Purple          = & $c 218 180  82   ## gold (used by Ping Sweep)
        SidebarBg       = & $c   6   6  10
    }

    ## ============ Typography ============
    ## Display / titles / data use Cascadia Mono (shipped with Windows 10+)
    ## Body copy uses Segoe UI Variable Display on Win11, falls back to Segoe UI
    ## Icons use Segoe MDL2 Assets (safe fallback from Segoe Fluent Icons)
    $mono = 'Cascadia Mono'
    $body = 'Segoe UI Variable Display'    ## auto-falls-back to Segoe UI
    $bodyAlt = 'Segoe UI'

    $global:WPT.UI.Fonts = [pscustomobject]@{
        ## Display scale (monospace)
        DisplayLg   = New-Object System.Drawing.Font($mono, 18, [System.Drawing.FontStyle]::Bold)
        DisplayMd   = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
        DisplaySm   = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)

        ## Section headers / small caps feeling via mono
        Eyebrow     = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
        EyebrowDim  = New-Object System.Drawing.Font($mono,  8, [System.Drawing.FontStyle]::Regular)

        ## Body copy (proportional)
        H1          = New-Object System.Drawing.Font($body, 18, [System.Drawing.FontStyle]::Bold)
        H2          = New-Object System.Drawing.Font($body, 14, [System.Drawing.FontStyle]::Bold)
        H3          = New-Object System.Drawing.Font($body, 11, [System.Drawing.FontStyle]::Bold)
        Body        = New-Object System.Drawing.Font($body, 10)
        BodyStrong  = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
        Caption     = New-Object System.Drawing.Font($body,  9)
        CaptionB    = New-Object System.Drawing.Font($body,  9, [System.Drawing.FontStyle]::Bold)
        Tiny        = New-Object System.Drawing.Font($body,  8)

        ## Data display (monospace - always)
        Mono        = New-Object System.Drawing.Font($mono, 10)
        MonoSm      = New-Object System.Drawing.Font($mono,  9)
        MonoTiny    = New-Object System.Drawing.Font($mono,  8)

        ## Icons
        Icon        = New-Object System.Drawing.Font('Segoe MDL2 Assets', 14)
        IconLarge   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 22)
        IconSmall   = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)

        ## v48a aliases - point at the new fonts
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

    ## Icon glyph registry (Segoe MDL2 Assets)
    $global:WPT.UI.Icons = [pscustomobject]@{
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

## ============ High-DPI awareness ============

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

## ============ Windows 11 DWM chrome helper (unchanged from v48.1) ============

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

## --- From Tools\UI\Controls.ps1 ---

<#
.SYNOPSIS
    WinForms control factory helpers for the Tactical Operations aesthetic.

.DESCRIPTION
    All helpers here paint their own visuals via GDI+ Paint handlers.
    That's how we get non-rectangular things like corner brackets, diagonal
    warning stripes, and pulsing indicators in WinForms without resorting
    to WPF.

    Modern tactical helpers (v48.2):
      * New-WptCard           - corner-bracket "brief box" (NOT a full border)
      * New-WptNavItem        - numbered tactical nav item with accent bar
      * New-WptPulseIndicator - animated blinking status dot (Forms.Timer)
      * New-WptStripeButton   - primary button with diagonal caution stripe
      * New-WptPrimaryButton  - flat amber CTA
      * New-WptGhostButton    - outline button
      * New-WptHeading        - bracketed section header [ 01 / TITLE ]
      * New-WptBadge          - small uppercase tag
      * New-WptSeparator      - faded 1px horizontal rule
      * New-WptIconLabel      - Segoe MDL2 Assets glyph label
      * Legacy helpers unchanged in signature - they inherit the new palette
        through the Theme aliases.
#>

## ============================================================
## Reflection helper - set protected members
## ============================================================

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

## ============================================================
## Legacy helpers (keep signatures, upgrade visuals via theme)
## ============================================================

function New-WptButton {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
        $Bg = $null, $Fg = $null, $Font = $null
    )
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Location    = New-Object System.Drawing.Point($X, $Y)
    $n.Size        = New-Object System.Drawing.Size($W, $H)
    $n.Minimum     = $Min
    $n.Maximum     = $Max
    $n.Value       = $Value
    $n.BackColor   = $theme.Input
    $n.ForeColor   = $theme.TextPrimary
    $n.BorderStyle = 'FixedSingle'
    $n.Font        = $global:WPT.UI.Fonts.Mono
    return $n
}

function New-WptListBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 300, [int]$H = 200
    )
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $tp = New-Object System.Windows.Forms.Panel
    $tp.Tag       = $Text
    $tp.BackColor = $theme.Background
    $tp.Dock      = 'Fill'
    $tp.Visible   = $false
    $tp.Padding   = New-Object System.Windows.Forms.Padding(0)
    return $tp
}

## ============================================================
## Modern helpers (v48.2 tactical)
## ============================================================

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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts
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
        this generically via the $global:WPT.UI.Controls cleanup loop).

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
    $theme = $global:WPT.UI.Theme
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
    $theme = $global:WPT.UI.Theme
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
    $theme = $global:WPT.UI.Theme
    $fonts = $global:WPT.UI.Fonts

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
    $theme = $global:WPT.UI.Theme
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
    $theme = $global:WPT.UI.Theme
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

## --- Get-WptState helper (required by the Dialog.Info.ps1 factory below) ---
## WPT's own copy defines this as part of its state-module block; in STIG_Tool
## we just need the minimal form that returns the script-scope $global:WPT
## hashtable so Show-WptInfoDialog can read the theme + fonts.
function Get-WptState { return $global:WPT }

## --- From Tools\UI\Dialog.Info.ps1 ---

<#
.SYNOPSIS
    Popup dialogs for Change Log + How to Use reference material.

.DESCRIPTION
    Borrowed from SIM_Tool's pattern: reference text lives in popup dialogs
    instead of permanent tabs, since operators look at it occasionally (not
    every session). Keeps the main tab surface focused on operational work.

    Both dialogs share Show-WptInfoDialog (the factory) - they just pass
    different text bodies. Text lives in $global: variables at the bottom of
    this file so it's easy to edit + doesn't bloat the dialog functions.

    Triggered from the Start tab's "Change Log" and "How to Use" buttons.
#>

function Show-WptInfoDialog {
    <#
    .SYNOPSIS
        Shared read-only popup: title bar + scrollable RichTextBox + Close.

    .DESCRIPTION
        Keeps the theme consistent with the rest of WPT. The RTB is read-only
        and word-wrapped. Close returns control to the main form.
    #>
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

## NOTE: the companion Show-WptChangeLogDialog / Show-WptHowToUseDialog helpers
## from the original Dialog.Info.ps1 are intentionally NOT inlined here -- they
## reference WPT-specific $global:WPT_ChangeLogText / $global:WPT_HowToUseText
## constants. STIG_Tool has its own Show-StigChangeLogDialog + Show-StigHowToUseDialog
## (defined later in this file) that call Show-WptInfoDialog with STIG-specific
## text bodies.

Set-WptDpiAware
Initialize-WptTheme

# --- Palette (aliased to the shared theme) --------------------------------
# Historical names $global:clrXxx keep working so every tab's existing code
# that reads the palette doesn't need rewriting. Each alias points at the
# same Color object the shared UI kit uses, so STIG and WPT now render
# the same RGB values pixel-for-pixel.
# Defined HERE at script load, outside BuildAppForm, so they're guaranteed
# non-null in any event handler — even after modal unwind (Get-Credential).
$__theme = $global:WPT.UI.Theme
$global:clrBG           = $__theme.Background
$global:clrPanel        = $__theme.Surface
$global:clrInputBG      = $__theme.Input
$global:clrBtnBG        = $__theme.Surface
$global:clrCyan         = $__theme.Accent1        # shared purple accent #8C64DC
$global:clrGreen        = $__theme.Success
$global:clrOrange       = $__theme.Warning
$global:clrRed          = $__theme.Danger
$global:clrPurple       = $__theme.Accent1        # alias — STIG workflow mapping uses this
$global:clrWhite        = $__theme.TextPrimary
$global:clrDim          = $__theme.TextSecondary
$global:clrAccentHov    = $__theme.Accent1Hover
$global:clrAccentDim    = $__theme.Accent1Muted
$global:clrAccentGlow   = $__theme.Accent1Glow
$global:clrRowAlt       = $__theme.SurfaceAlt
$global:clrRowHover     = $__theme.SurfaceHover
$global:clrBorder       = $__theme.Border
$global:clrHeaderBg     = $__theme.TitleBar
$global:clrSidebar      = $__theme.Sidebar
$global:clrTextDark     = $__theme.TextFaint
$global:clrTextOnAmber  = [System.Drawing.Color]::FromArgb( 12,   9,   3)   # dark foreground for bright button backgrounds
$global:clrConsole      = $__theme.ConsoleFg
# Semantic workflow colors — distinct from the 6 primary accents so the
# About / Help workflow steps each have their own visual identity.
$global:clrInfo         = $__theme.Info
$global:clrTeal         = [System.Drawing.Color]::FromArgb( 82, 196, 166)   # #52C4A6 verify/analyze teal
$global:clrGold         = $__theme.Accent2        # shared gold #DAB452
$global:clrMuted        = [System.Drawing.Color]::FromArgb(181, 122,  21)   # #B57A15 muted amber (archival/export)
Remove-Variable __theme -ErrorAction SilentlyContinue

# STIG technologies supported. Each entry maps a PowerStig DSC resource to
# the host roles it applies to. Get-TechnologiesForRole returns the entries
# matching a discovered host's ProductType role.
$global:SupportedTechnologies = @(
    @{ Key='WindowsClient';   Display='Windows 10/11 Client';      DscResource='WindowsClient';   OsVersionDefault='10';   Roles=@('Workstation') },
    @{ Key='WindowsServer';   Display='Windows Server 2019/2022';  DscResource='WindowsServer';   OsVersionDefault='2019'; Roles=@('MemberServer','DomainController') },
    @{ Key='WindowsFirewall'; Display='Windows Firewall';          DscResource='WindowsFirewall'; OsVersionDefault=$null;  Roles=@('Workstation','MemberServer','DomainController') },
    @{ Key='WindowsDefender'; Display='Windows Defender';          DscResource='WindowsDefender'; OsVersionDefault=$null;  Roles=@('Workstation','MemberServer','DomainController') }
)

# State buckets populated at runtime
$global:Targets         = @()   # list of hashtables: Host, OS, Role, Online, WinRM, Technologies
$global:LastScan        = $null # hashtable of ScanId -> per-host results (for Verify diff)
$global:CurrentScan     = $null
$global:RuleCatalogCache= @{}   # key: "Tech|Version" -> RuleList array from PowerStig
$global:SkipLists       = @{}   # key: Technology -> array of VulnIDs excluded
# Per-rule metadata keyed by "Technology|VulnID" — operator-added fields
# that flow into CKL/CKLB export: NA justification (required by DISA for
# Not_Applicable status), finding-details commentary, analyst comments,
# severity override text, and severity override justification.
$global:RuleMetadata    = @{}   # key: "Tech|VulnID" -> hashtable
$global:PrereqStatus    = $null
$global:Operator        = $env:USERNAME
$global:RemoteCred      = $null
$global:ExecutionMode   = 'Local'  # 'Local' or 'Remote'
$global:RSPool          = $null
$global:RunningJobs     = @()
$global:ApplyInProgress = $false   # set true while the Apply tab loop is running; FormClosing refuses to close while true

#endregion

#region ------------------------ WORKSPACE / PREREQS ---------------------
function Initialize-Workspace {
    foreach ($d in @($global:WorkspaceRoot, $global:ConfigsDir, $global:MofRoot, $global:EvalRoot,
                     $global:ChecklistRoot, $global:ReportRoot, $global:SkipListRoot, $global:LogRoot)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    if (-not (Test-Path $global:AuditLogPath)) {
        "Timestamp`tSeq`tOperator`tEvent`tDetails" | Set-Content -Path $global:AuditLogPath -Encoding UTF8
    } else {
        # Read the last seq from the existing file so a startup BoundaryStart
        # row records "previous tail = N". Reviewers comparing previous
        # session's last seq to this session's first seq can spot deletion.
        $priorTail = '?'
        try {
            $tail = Get-Content -Path $global:AuditLogPath -Tail 1 -ErrorAction SilentlyContinue
            if ($tail) {
                $cols = ($tail -split "`t")
                if ($cols.Count -ge 2 -and $cols[1] -match '^\d+$') { $priorTail = $cols[1] }
            }
        } catch {}
        # Stash for first Write-Audit call; emitted by Start-StigTool.
        $global:AuditPriorTail = $priorTail
    }
}

$global:AuditWriteFailedCount = 0
$global:AuditFallbackBuffer   = [System.Collections.ArrayList]::new()
# Per-process monotonic sequence number prepended to every audit row.
# Combined with the BoundaryStart row written on each launch (which records
# the previous file's last sequence), this lets a reviewer detect whether
# any rows were deleted from the file: a gap in the sequence number is
# evidence of tampering. Cheap form of audit-integrity per DISA expectations
# without requiring HMAC infrastructure.
$global:AuditSeq = 0

function Write-Audit {
    param([string]$Event, [string]$Details)
    $global:AuditSeq++
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "$ts`t$($global:AuditSeq)`t$($global:Operator)`t$Event`t$Details"
    try {
        Add-Content -Path $global:AuditLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        # If we previously couldn't write but now can, replay the buffer.
        if ($global:AuditFallbackBuffer.Count -gt 0) {
            try {
                foreach ($buffered in $global:AuditFallbackBuffer) {
                    Add-Content -Path $global:AuditLogPath -Value $buffered -Encoding UTF8 -ErrorAction Stop
                }
                $global:AuditFallbackBuffer.Clear()
            } catch {}
        }
    } catch {
        # Buffer the entry for later replay and bump the failure counter.
        # DISA audit-integrity controls require either tamper-evident logging
        # or guaranteed delivery — buffering + replay is the cheapest way to
        # not lose audit rows when the workspace share blips offline.
        $global:AuditWriteFailedCount++
        try { [void]$global:AuditFallbackBuffer.Add($line) } catch {}
    }
}

# Gate for actions that need credentials. Local mode always passes.
# Remote mode requires $global:RemoteCred to be set. Returns $true if OK,
# or displays a blocking error dialog and returns $false.
function Test-StigCredsReady {
    param([string]$ActionName = 'this action')
    if ($global:ExecutionMode -eq 'Local') { return $true }
    if ($global:RemoteCred) { return $true }
    [System.Windows.Forms.MessageBox]::Show(
        "Remote mode requires credentials. Open the About tab and click 'Set Credentials' before running $ActionName.",
        'Credentials required',
        'OK',
        'Warning'
    ) | Out-Null
    return $false
}

# Copyable error dialog. MessageBox.Show's text isn't selectable — operators
# can't paste error details into a ticket or search. This builds a modal
# dialog with a read-only multiline TextBox (selectable) plus a one-click
# "Copy All" button that puts the full message on the clipboard.
# Called from scan/apply/verify/credential handlers whenever an error has
# useful details worth preserving.
function Show-StigCopyableError {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Error','Warning','Info')][string]$Severity = 'Error'
    )
    $accent = switch ($Severity) {
        'Error'   { $global:clrRed }
        'Warning' { $global:clrOrange }
        'Info'    { $global:clrCyan }
    }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = $Title
    $dlg.Size            = New-Object System.Drawing.Size(680, 420)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(500, 260)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $global:clrPanel
    $dlg.ForeColor       = $global:clrWhite
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.MinimizeBox     = $false
    $dlg.MaximizeBox     = $true
    $dlg.ShowInTaskbar   = $false
    try { $dlg.Font = $global:DefaultFont } catch {}

    # Colored header strip with the severity label
    $pnlHeader = New-Object System.Windows.Forms.Panel
    $pnlHeader.Dock      = 'Top'
    $pnlHeader.Height    = 42
    $pnlHeader.BackColor = $global:clrHeaderBg
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = "  $($Severity.ToUpper())   $Title"
    $lblTitle.ForeColor = $accent
    $lblTitle.Dock      = 'Fill'
    $lblTitle.TextAlign = 'MiddleLeft'
    try { $lblTitle.Font = New-Object System.Drawing.Font('Cascadia Mono', 11, [System.Drawing.FontStyle]::Bold) } catch {}
    $pnlHeader.Controls.Add($lblTitle)
    $pnlAccent = New-Object System.Windows.Forms.Panel
    $pnlAccent.Dock = 'Bottom'; $pnlAccent.Height = 2; $pnlAccent.BackColor = $accent
    $pnlHeader.Controls.Add($pnlAccent)

    # Bottom button row (panel first so Dock=Fill message area fills correctly)
    $pnlButtons = New-Object System.Windows.Forms.Panel
    $pnlButtons.Dock      = 'Bottom'
    $pnlButtons.Height    = 52
    $pnlButtons.BackColor = $global:clrPanel

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text      = 'Copy All'
    $btnCopy.Size      = New-Object System.Drawing.Size(120, 32)
    $btnCopy.Location  = New-Object System.Drawing.Point(14, 10)
    $btnCopy.BackColor = $global:clrCyan
    $btnCopy.ForeColor = $global:clrTextOnAmber
    $btnCopy.FlatStyle = 'Flat'
    $btnCopy.FlatAppearance.BorderSize = 0
    try { $btnCopy.Font = New-Object System.Drawing.Font('Cascadia Mono', 9, [System.Drawing.FontStyle]::Bold) } catch {}
    $btnCopy.Cursor = [System.Windows.Forms.Cursors]::Hand
    # Closure captures $Message so Copy All always has the right text
    $btnCopy.Add_Click({
        try {
            [System.Windows.Forms.Clipboard]::SetText($Message)
            $btnCopy.Text = 'Copied'
        } catch {
            $btnCopy.Text = 'Copy failed'
        }
    }.GetNewClosure())

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text      = 'Close'
    $btnClose.Size      = New-Object System.Drawing.Size(100, 32)
    $btnClose.Location  = New-Object System.Drawing.Point(540, 10)
    $btnClose.Anchor    = 'Top,Right'
    $btnClose.BackColor = $global:clrBtnBG
    $btnClose.ForeColor = $global:clrWhite
    $btnClose.FlatStyle = 'Flat'
    $btnClose.FlatAppearance.BorderColor = $global:clrBorder
    $btnClose.FlatAppearance.BorderSize  = 1
    try { $btnClose.Font = New-Object System.Drawing.Font('Cascadia Mono', 9, [System.Drawing.FontStyle]::Bold) } catch {}
    $btnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $pnlButtons.Controls.AddRange(@($btnCopy, $btnClose))
    # Keep Close button right-anchored on resize
    $pnlButtons.Add_Resize({
        $btnClose.Location = New-Object System.Drawing.Point(($pnlButtons.ClientSize.Width - 114), 10)
    })

    # Selectable, scrollable message body
    $txtMsg = New-Object System.Windows.Forms.TextBox
    $txtMsg.Multiline   = $true
    $txtMsg.ReadOnly    = $true
    $txtMsg.ScrollBars  = 'Both'
    $txtMsg.WordWrap    = $true
    $txtMsg.BackColor   = $global:clrInputBG
    $txtMsg.ForeColor   = $global:clrWhite
    $txtMsg.BorderStyle = 'FixedSingle'
    try { $txtMsg.Font = New-Object System.Drawing.Font('Cascadia Mono', 9) } catch {}
    $txtMsg.Text        = $Message
    $txtMsg.Dock        = 'Fill'

    $dlg.Controls.Add($txtMsg)
    $dlg.Controls.Add($pnlButtons)
    $dlg.Controls.Add($pnlHeader)

    $dlg.AcceptButton = $btnClose
    $dlg.CancelButton = $btnClose
    [void]$dlg.ShowDialog()
    try { $dlg.Dispose() } catch {}
}

# Modal multi-line text input with OK/Cancel. Returns the entered text,
# or $null if the user cancelled. Used for NA justification capture,
# severity override justification, operator finding details, etc.
# Styled to match Show-StigCopyableError (tactical amber accent header).
function Read-StigMultilineInput {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Initial = '',
        [int]$MinLength = 0
    )
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = $Title
    $dlg.Size            = New-Object System.Drawing.Size(620, 340)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(480, 240)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $global:clrPanel
    $dlg.ForeColor       = $global:clrWhite
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.MinimizeBox     = $false
    $dlg.ShowInTaskbar   = $false
    try { $dlg.Font = $global:DefaultFont } catch {}

    $pnlHeader = New-Object System.Windows.Forms.Panel
    $pnlHeader.Dock      = 'Top'
    $pnlHeader.Height    = 42
    $pnlHeader.BackColor = $global:clrHeaderBg
    $lblT = New-Object System.Windows.Forms.Label
    $lblT.Text      = "  $Title"
    $lblT.ForeColor = $global:clrCyan
    $lblT.Dock      = 'Fill'
    $lblT.TextAlign = 'MiddleLeft'
    try { $lblT.Font = New-Object System.Drawing.Font('Cascadia Mono', 11, [System.Drawing.FontStyle]::Bold) } catch {}
    $pnlHeader.Controls.Add($lblT)
    $pnlAccent = New-Object System.Windows.Forms.Panel
    $pnlAccent.Dock = 'Bottom'; $pnlAccent.Height = 2; $pnlAccent.BackColor = $global:clrCyan
    $pnlHeader.Controls.Add($pnlAccent)

    $lblPrompt = New-Object System.Windows.Forms.Label
    $lblPrompt.Text      = $Prompt
    $lblPrompt.Dock      = 'Top'
    $lblPrompt.Height    = 48
    $lblPrompt.ForeColor = $global:clrDim
    $lblPrompt.BackColor = $global:clrPanel
    $lblPrompt.Padding   = New-Object System.Windows.Forms.Padding(12, 8, 12, 0)
    try { $lblPrompt.Font = New-Object System.Drawing.Font('Segoe UI', 9) } catch {}

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Multiline   = $true
    $txt.ScrollBars  = 'Vertical'
    $txt.WordWrap    = $true
    $txt.BackColor   = $global:clrInputBG
    $txt.ForeColor   = $global:clrWhite
    $txt.BorderStyle = 'FixedSingle'
    $txt.Text        = $Initial
    $txt.Dock        = 'Fill'
    try { $txt.Font = New-Object System.Drawing.Font('Segoe UI', 10) } catch {}

    $pnlButtons = New-Object System.Windows.Forms.Panel
    $pnlButtons.Dock      = 'Bottom'
    $pnlButtons.Height    = 52
    $pnlButtons.BackColor = $global:clrPanel

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text      = 'OK'
    $btnOk.Size      = New-Object System.Drawing.Size(100, 32)
    $btnOk.Location  = New-Object System.Drawing.Point(14, 10)
    $btnOk.BackColor = $global:clrCyan
    $btnOk.ForeColor = $global:clrTextOnAmber
    $btnOk.FlatStyle = 'Flat'
    $btnOk.FlatAppearance.BorderSize = 0
    try { $btnOk.Font = New-Object System.Drawing.Font('Cascadia Mono', 9, [System.Drawing.FontStyle]::Bold) } catch {}
    $btnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text      = 'Cancel'
    $btnCancel.Size      = New-Object System.Drawing.Size(100, 32)
    $btnCancel.Location  = New-Object System.Drawing.Point(480, 10)
    $btnCancel.Anchor    = 'Top,Right'
    $btnCancel.BackColor = $global:clrBtnBG
    $btnCancel.ForeColor = $global:clrWhite
    $btnCancel.FlatStyle = 'Flat'
    $btnCancel.FlatAppearance.BorderColor = $global:clrBorder
    $btnCancel.FlatAppearance.BorderSize  = 1
    try { $btnCancel.Font = New-Object System.Drawing.Font('Cascadia Mono', 9, [System.Drawing.FontStyle]::Bold) } catch {}
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $pnlButtons.Add_Resize({ $btnCancel.Location = New-Object System.Drawing.Point(($pnlButtons.ClientSize.Width - 114), 10) })
    $pnlButtons.Controls.AddRange(@($btnOk, $btnCancel))

    # Dock order: Fill last
    $dlg.Controls.Add($txt)
    $dlg.Controls.Add($lblPrompt)
    $dlg.Controls.Add($pnlHeader)
    $dlg.Controls.Add($pnlButtons)

    $dlg.AcceptButton = $btnOk
    $dlg.CancelButton = $btnCancel

    $result = $dlg.ShowDialog()
    $value  = $txt.Text
    try { $dlg.Dispose() } catch {}
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($MinLength -gt 0 -and $value.Trim().Length -lt $MinLength) { return $null }
    return $value
}

function Test-Prerequisites {
    $result = [ordered]@{
        IsAdmin             = $false
        PSVersionOk         = $false
        PSVersion           = $PSVersionTable.PSVersion.ToString()
        PowerStigInstalled  = $false
        PowerStigVersion    = $null
        DscInstalled        = $false
        ImportExcelInstalled= $false
        WinRmConfigured     = $false
        Warnings            = @()
    }
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        $result.IsAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    $result.PSVersionOk = ($PSVersionTable.PSVersion.Major -ge 5)
    $ps = Get-Module -ListAvailable -Name PowerStig -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($ps) { $result.PowerStigInstalled = $true; $result.PowerStigVersion = $ps.Version.ToString() }
    $dsc = Get-Module -ListAvailable -Name PSDesiredStateConfiguration -ErrorAction SilentlyContinue
    if ($dsc) { $result.DscInstalled = $true }
    $xl = Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue
    if ($xl) { $result.ImportExcelInstalled = $true }
    try {
        $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $result.WinRmConfigured = $true }
    } catch {}
    if (-not $result.IsAdmin)             { $result.Warnings += 'Not running elevated — scan works, Apply/Verify will fail.' }
    if (-not $result.PSVersionOk)         { $result.Warnings += 'PowerShell 5.1+ required for DSC.' }
    if (-not $result.PowerStigInstalled)  { $result.Warnings += 'PowerStig missing — click "Install Missing Modules" or run Install-Module PowerStig -Scope AllUsers' }
    if (-not $result.DscInstalled)        { $result.Warnings += 'PSDesiredStateConfiguration missing.' }
    if (-not $result.ImportExcelInstalled){ $result.Warnings += 'ImportExcel missing — XLSX export disabled. Install-Module ImportExcel -Scope AllUsers' }
    if (-not $result.WinRmConfigured)     { $result.Warnings += 'WinRM not running — remote mode disabled.' }
    $global:PrereqStatus = $result
    return $result
}

# Mandatory module installer. Called at startup BEFORE BuildAppForm.
# Installs PowerStig (required) and ImportExcel (required for XLSX export).
# Handles every PS 5.1 PSGallery gotcha:
#   1. TLS 1.2 enablement (PS 5.1 defaults to TLS 1.0/1.1 which PSGallery rejects)
#   2. NuGet provider bootstrapping (first-ever Install-Module prompts otherwise)
#   3. PSGallery trust (otherwise Install-Module blocks on a Y/N prompt)
#   4. Admin vs per-user scope (falls back to CurrentUser if AllUsers fails)
#   5. Offline / no-network graceful degradation (catches the WebException
#      and returns a structured error so the caller can show a clear UI
#      instead of a silent failure or scary red console spew)
#
# Returns a hashtable:
#   @{ Success=$bool; Installed=@('PowerStig'); Skipped=@(...); Errors=@(...); Message='...' }
function Install-StigToolModules {
    param(
        [switch]$Force,          # force reinstall even if already present
        [switch]$Quiet           # suppress console Write-Host (used by GUI-only callers)
    )
    $result = @{
        Success   = $true
        Installed = @()
        Skipped   = @()
        Errors    = @()
        Message   = ''
    }
    $log = {
        param($msg)
        if (-not $Quiet) { Write-Host $msg }
    }

    # --- Step 1: TLS 1.2 ---
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        & $log '  TLS 1.2 enabled for this session'
    } catch {
        $result.Errors += "TLS 1.2 enable failed: $($_.Exception.Message)"
    }

    # Pick install scope: AllUsers if admin, else CurrentUser
    $isAdmin = $false
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = [Security.Principal.WindowsPrincipal]::new($wi)
        $isAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    $installScope = if ($isAdmin) { 'AllUsers' } else { 'CurrentUser' }
    & $log "  Install scope: $installScope"

    # --- Step 2: NuGet provider (PSGallery won't work without it) ---
    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
            & $log '  Installing NuGet provider...'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope $installScope -Force -ErrorAction Stop | Out-Null
            & $log '  NuGet provider installed'
        }
    } catch {
        $result.Errors += "NuGet provider install failed: $($_.Exception.Message)"
    }

    # --- Step 3: Trust PSGallery so Install-Module doesn't prompt ---
    try {
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            & $log '  PSGallery marked as Trusted'
        }
    } catch {
        $result.Errors += "PSGallery trust failed: $($_.Exception.Message)"
    }

    # --- Step 4: Install the actual modules ---
    $wanted = @(
        @{ Name = 'PowerStig';    Required = $true  },
        @{ Name = 'ImportExcel';  Required = $false } # XLSX export is nice-to-have, not fatal
    )
    foreach ($mod in $wanted) {
        $name = $mod.Name
        $already = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($already -and -not $Force) {
            & $log "  $name : already installed ($($already.Version))"
            $result.Skipped += $name
            continue
        }
        try {
            & $log "  Installing $name (scope=$installScope)..."
            # Silence progress bar (blocks in some hosts) and force (no prompt)
            $oldPref = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                Install-Module -Name $name -Scope $installScope -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
            } finally {
                $ProgressPreference = $oldPref
            }
            $result.Installed += $name
            & $log "  $name installed OK"
        } catch {
            $msg = "$name install failed: $($_.Exception.Message)"
            $result.Errors += $msg
            & $log "  $msg"
            if ($mod.Required) { $result.Success = $false }
        }
    }

    # --- Build status message for the UI ---
    if ($result.Installed.Count -gt 0) {
        $result.Message = "Installed: $($result.Installed -join ', ')"
    }
    if ($result.Skipped.Count -gt 0) {
        if ($result.Message) { $result.Message += " | " }
        $result.Message += "Already present: $($result.Skipped -join ', ')"
    }
    if ($result.Errors.Count -gt 0) {
        if ($result.Message) { $result.Message += " | " }
        $result.Message += "Errors: $($result.Errors.Count)"
    }
    if (-not $result.Message) { $result.Message = 'No action taken' }

    try { Write-Audit -Event 'ModuleInstall' -Details $result.Message } catch {}
    return $result
}
#endregion

#region ------------------------ RUNSPACE POOL ----------------------------
function Initialize-RunspacePool {
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $global:RSPool = [runspacefactory]::CreateRunspacePool(1, 12, $iss, $Host)
    $global:RSPool.ApartmentState = 'MTA'
    $global:RSPool.Open()
}

function Close-RunspacePool {
    if ($global:RSPool) {
        try { $global:RSPool.Close() } catch {}
        try { $global:RSPool.Dispose() } catch {}
        $global:RSPool = $null
    }
}

function Invoke-ParallelJob {
    param(
        [ScriptBlock]$ScriptBlock,
        [object[]]$Arguments
    )
    # Re-open the pool if it was closed by a prior CleanUp/FormClose cycle.
    # Without this, any post-close invocation throws "pool is closed" from
    # BeginInvoke with no useful diagnostic for the operator.
    $needsInit = $true
    if ($global:RSPool) {
        try {
            if ($global:RSPool.RunspacePoolStateInfo.State -eq [System.Management.Automation.Runspaces.RunspacePoolState]::Opened) {
                $needsInit = $false
            }
        } catch {}
    }
    if ($needsInit) { Initialize-RunspacePool }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $global:RSPool
    [void]$ps.AddScript($ScriptBlock)
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{ PS = $ps; Handle = $handle }
}
#endregion

#region ------------------------ TECHNOLOGY HELPERS ------------------------
# Return the SupportedTechnologies entries whose Roles list contains $Role.
function Get-TechnologiesForRole {
    param([string]$Role)
    if (-not $Role) { return @() }
    return @($global:SupportedTechnologies | Where-Object { $_.Roles -contains $Role })
}

# Determine the correct OsVersion string for a given technology + OS caption.
# WindowsClient always returns '10'. WindowsServer parses the year from the
# OS caption string (e.g. "Microsoft Windows Server 2022 Datacenter" -> "2022").
# Firewall/Defender don't need OsVersion (return $null).
function Get-OsVersionForTech {
    param([string]$Technology, [string]$OSCaption, [string]$Role)
    switch ($Technology) {
        'WindowsClient' { return '10' }
        'WindowsServer' {
            if ($OSCaption -match '2022') { return '2022' }
            if ($OSCaption -match '2019') { return '2019' }
            if ($OSCaption -match '2016') { return '2016' }
            return '2019'  # default
        }
        default { return $null }
    }
}

# Determine the OsRole parameter for WindowsServer DSC resource.
# Returns 'MS' for MemberServer, 'DC' for DomainController.
function Get-OsRoleForTech {
    param([string]$Technology, [string]$Role)
    if ($Technology -ne 'WindowsServer') { return $null }
    switch ($Role) {
        'DomainController' { return 'DC' }
        default            { return 'MS' }
    }
}
#endregion

#region ------------------------ POWERSTIG ENGINE -------------------------
# Translate PowerStig's lowercase severity -> DISA CAT I/II/III labels.
# DISA audit tooling (eMASS, STIG Viewer filters, ACAS) categorizes by
# CAT level; keeping raw "high/medium/low" breaks those filters.
function Convert-SeverityToCat {
    param([string]$Severity)
    switch -Regex ($Severity) {
        '^(CAT\s*I{1,3})$'   { return $Severity.ToUpper() }   # already CAT
        '^high$'             { return 'CAT I' }
        '^medium$'           { return 'CAT II' }
        '^low$'              { return 'CAT III' }
        default              { return 'CAT II' }              # conservative fallback
    }
}

# Map internal technology key -> DISA canonical stigid + fallback title.
# STIG Viewer uses stigid to match CKL imports against XCCDF benchmarks.
# Custom/wrong stigid means the CKL won't merge with official DISA
# deliveries. These IDs match DISA's published XCCDF benchmark filenames.
function Get-DisaStigIdentity {
    param([string]$Technology, [string]$OsVersion)
    switch ($Technology) {
        'WindowsClient'   { return @{ StigId = 'Windows_10_STIG';           Title = 'Microsoft Windows 10 Security Technical Implementation Guide' } }
        'WindowsServer'   {
            # stigid must match the XCCDF benchmark filename DISA publishes per OS
            # version — wrong year here and STIG Viewer refuses to merge.
            $v = if ($OsVersion) { $OsVersion } else { '2022' }
            switch ($v) {
                '2016'  { return @{ StigId = 'Windows_Server_2016_STIG'; Title = 'Microsoft Windows Server 2016 Security Technical Implementation Guide' } }
                '2019'  { return @{ StigId = 'Windows_Server_2019_STIG'; Title = 'Microsoft Windows Server 2019 Security Technical Implementation Guide' } }
                default { return @{ StigId = 'Windows_Server_2022_STIG'; Title = 'Microsoft Windows Server 2022 Security Technical Implementation Guide' } }
            }
        }
        'WindowsFirewall' { return @{ StigId = 'Windows_Firewall_STIG';     Title = 'Microsoft Windows Firewall with Advanced Security Security Technical Implementation Guide' } }
        'WindowsDefender' { return @{ StigId = 'Windows_Defender_Antivirus_STIG'; Title = 'Microsoft Windows Defender Antivirus Security Technical Implementation Guide' } }
        default           { return @{ StigId = $Technology;                 Title = $Technology } }
    }
}

# Return installed PowerStig versions available for a given technology.
# Used by the Scan tab's STIG version dropdown for pinned reproducibility.
function Get-StigVersionList {
    param([string]$Technology, [string]$TechnologyVersion = '10')
    if (-not $global:PrereqStatus -or -not $global:PrereqStatus.PowerStigInstalled) { return @() }
    try {
        # Get-StigList in PowerStig 4.x returns objects with .Technology .TechnologyVersion .Version
        $list = Get-StigList -ErrorAction SilentlyContinue | Where-Object {
            $_.Technology -eq $Technology -and
            ($_.TechnologyVersion -eq $TechnologyVersion -or -not $TechnologyVersion)
        }
        return @($list | ForEach-Object { $_.Version } | Sort-Object -Unique -Descending)
    } catch {
        return @()
    }
}

# Get the rule catalog for a given STIG technology from PowerStig.
# Returns an array of hashtables: VulnID, RuleID, Severity (raw), Cat (CAT I/II/III),
# Title, Description, FixText, CheckContent, Ccis[], DscResource, plus stig-level
# metadata accessible via the first rule's .StigInfo hashtable for downstream
# CKL/CKLB export.
function Get-PowerStigRuleCatalog {
    param([string]$Technology, [string]$TechnologyVersion = '10', [string]$StigVersion)
    $cacheKey = "$Technology|$TechnologyVersion|$StigVersion"
    if ($global:RuleCatalogCache.ContainsKey($cacheKey)) { return $global:RuleCatalogCache[$cacheKey] }

    if (-not $global:PrereqStatus.PowerStigInstalled) { return @() }

    $rules = @()
    $disaId = Get-DisaStigIdentity -Technology $Technology -OsVersion $TechnologyVersion
    $stigInfo = @{
        StigId      = $disaId.StigId
        Title       = $disaId.Title
        Version     = ''
        ReleaseInfo = ''
    }
    try {
        # PowerStig 4.x API — Get-Stig returns a [Stig] object with RuleList
        $argsHt = @{ Technology = $Technology; TechnologyVersion = $TechnologyVersion }
        if ($StigVersion) { $argsHt.StigVersion = $StigVersion }
        $stig = Get-Stig @argsHt -ErrorAction Stop

        # Capture stig-level metadata for CKL export
        if ($stig) {
            if ($stig.PSObject.Properties['StigVersion']) { $stigInfo.Version = [string]$stig.StigVersion }
            if ($stig.PSObject.Properties['Title'])       { $stigInfo.Title = [string]$stig.Title }
            if ($stig.PSObject.Properties['ReleaseDate']) { $stigInfo.ReleaseInfo = "Release: $($stig.StigVersion) Benchmark Date: $($stig.ReleaseDate)" }
            elseif ($stig.PSObject.Properties['Release']) { $stigInfo.ReleaseInfo = [string]$stig.Release }
        }

        if ($stig -and $stig.RuleList) {
            foreach ($r in $stig.RuleList) {
                # CCI refs — PowerStig exposes these on several property names
                # depending on version. Capture all plausible shapes.
                $ccis = @()
                foreach ($prop in 'cci','ccis','CCI','CCIs') {
                    if ($r.PSObject.Properties[$prop]) {
                        $v = $r.$prop
                        if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                            $ccis += @($v | ForEach-Object { [string]$_ })
                        } else {
                            $ccis += [string]$v
                        }
                    }
                }
                $ccis = @($ccis | Where-Object { $_ -and $_ -match 'CCI-' } | Select-Object -Unique)

                $rawSev = if ($r.PSObject.Properties['severity']) { $r.severity } else { 'medium' }
                $rules += [ordered]@{
                    VulnID      = $r.Id
                    RuleID      = if ($r.PSObject.Properties['RuleID'])      { $r.RuleID }      else { $r.Id }
                    Severity    = $rawSev
                    Cat         = Convert-SeverityToCat -Severity $rawSev
                    Title       = if ($r.PSObject.Properties['title'])       { $r.title }       else { '' }
                    Description = if ($r.PSObject.Properties['description']) { $r.description } else { '' }
                    FixText     = if ($r.PSObject.Properties['fixText'])     { $r.fixText }     else { '' }
                    CheckContent= if ($r.PSObject.Properties['checkContent']){ $r.checkContent }else { '' }
                    Ccis        = $ccis
                    DscResource = if ($r.PSObject.Properties['dscresource']) { $r.dscresource } else { '' }
                    StigInfo    = $stigInfo
                }
            }
        }
    } catch {
        Write-Audit -Event 'RuleCatalogError' -Details "Tech=$Technology err=$($_.Exception.Message)"
    }
    $global:RuleCatalogCache[$cacheKey] = $rules
    return $rules
}

# Write a DSC configuration .ps1 for the given host + technology + skip-list.
# Handles all four technology types: WindowsClient (needs OsVersion),
# WindowsServer (needs OsVersion + OsRole), WindowsFirewall and
# WindowsDefender (need neither).
function New-StigDscConfigFile {
    param(
        [string]$ComputerName,
        [string]$Technology = 'WindowsClient',
        [string]$OsVersion,
        [string]$OsRole,
        [string]$StigVersion,
        [string[]]$SkipRule = @()
    )
    # INPUT ALLOW-LISTS (added in v1.2.3). The output of this function is a
    # generated .ps1 that gets dot-sourced into the operator's elevated
    # session by Invoke-StigCompile. Any value interpolated into the
    # single-quoted strings below MUST be validated here — otherwise a
    # spoofed Win32_OperatingSystem.Caption from a hostile target (which
    # flows into $OsVersion via Get-OsVersionForTech), or a tampered
    # Targets.json / SkipList.json, becomes RCE on the operator's box.
    if ($ComputerName -and $ComputerName -notmatch '^[A-Za-z0-9._-]{1,253}$') {
        throw "New-StigDscConfigFile: invalid ComputerName '$ComputerName' (must match RFC-1123 hostname charset)"
    }
    if ($Technology -notmatch '^Windows(Client|Server|Firewall|Defender)$') {
        throw "New-StigDscConfigFile: invalid Technology '$Technology'"
    }
    if ($OsVersion -and $OsVersion -notmatch '^[A-Za-z0-9._-]{1,32}$') {
        throw "New-StigDscConfigFile: invalid OsVersion '$OsVersion'"
    }
    if ($OsRole -and $OsRole -notmatch '^(MS|DC)$') {
        throw "New-StigDscConfigFile: invalid OsRole '$OsRole'"
    }
    if ($StigVersion -and $StigVersion -notmatch '^[A-Za-z0-9._-]{1,32}$') {
        throw "New-StigDscConfigFile: invalid StigVersion '$StigVersion'"
    }
    foreach ($r in @($SkipRule)) {
        # PowerStig SkipRule entries are DISA Vuln IDs. The official format
        # is V-<digits>; we also accept the SV-<digits>r<digits>_rule form
        # used in some XCCDF deliveries. Reject anything else.
        if ($r -and $r -notmatch '^(V-\d{1,8}|SV-\d{1,8}r\d{1,4}_rule)$') {
            throw "New-StigDscConfigFile: invalid SkipRule entry '$r' (expected V-#### or SV-####r##_rule)"
        }
    }

    $safe = ($ComputerName -replace '[^A-Za-z0-9_\-]','_')
    $cfgName = "Stig_${Technology}_$safe"
    $cfgFile = Join-Path $global:ConfigsDir "$cfgName.ps1"
    $skipBlock = ''
    if ($SkipRule.Count -gt 0) {
        $quoted = ($SkipRule | ForEach-Object { "'$_'" }) -join ','
        $skipBlock = "            SkipRule = @($quoted)"
    }
    # Only include parameters that the specific DSC resource accepts
    $osVerLine  = if ($OsVersion)   { "            OsVersion = '$OsVersion'" }   else { '' }
    $osRoleLine = if ($OsRole)      { "            OsRole    = '$OsRole'" }      else { '' }
    $stigVerLine= if ($StigVersion) { "            StigVersion = '$StigVersion'" } else { '' }

    $content = @"
Configuration $cfgName {
    param([string[]]`$NodeName = '$ComputerName')
    Import-DscResource -ModuleName PowerStig
    Node `$NodeName {
        $Technology BaselineSettings {
$osVerLine
$osRoleLine
$stigVerLine
$skipBlock
        }
    }
}
$cfgName -OutputPath '$(Join-Path $global:MofRoot $safe)'
"@
    Set-Content -Path $cfgFile -Value $content -Encoding UTF8
    return [pscustomobject]@{
        ConfigFile = $cfgFile
        ConfigName = $cfgName
        MofFolder  = Join-Path $global:MofRoot $safe
    }
}

# Compile a DSC config into a MOF.
# Runs the generated .ps1 (which invokes the Configuration). Returns MOF path or throws.
function Invoke-StigCompile {
    param([string]$ConfigFile, [string]$ComputerName)
    if (-not (Test-Path $ConfigFile)) { throw "Config file not found: $ConfigFile" }
    $safe = ($ComputerName -replace '[^A-Za-z0-9_\-]','_')
    $mofDir = Join-Path $global:MofRoot $safe
    if (-not (Test-Path $mofDir)) { New-Item -ItemType Directory -Path $mofDir -Force | Out-Null }
    # Clear stale MOFs from prior compiles before dot-sourcing. Without this,
    # LastWriteTime-based selection can pick up a leftover MOF from a previous
    # tech/skip-list run if two compiles land in the same second on the Apply
    # recompile path.
    $staleMofs = @(Get-ChildItem -Path $mofDir -Filter '*.mof' -ErrorAction SilentlyContinue)
    $staleRemoveFails = @()
    foreach ($sm in $staleMofs) {
        try { Remove-Item -Path $sm.FullName -Force -ErrorAction Stop } catch {
            $staleRemoveFails += "$($sm.Name) ($($_.Exception.Message))"
        }
    }
    if ($staleRemoveFails.Count -gt 0) {
        # If we couldn't clear stale MOFs, the Sort-Object LastWriteTime
        # below could pick up the wrong one and the apply would silently
        # use the stale skip-list. Refuse to compile rather than hide the
        # ambiguity.
        Write-Audit -Event 'StaleMofRemoveFail' -Details "dir=$mofDir failed=$($staleRemoveFails -join ',')"
        throw "Could not clear $($staleRemoveFails.Count) stale MOF(s) in $mofDir before recompile: $($staleRemoveFails -join '; '). Most likely a prior DSC apply is still holding a lock; wait for Get-DscConfigurationStatus to settle and retry."
    }
    # Dot-source the config and compile.
    # v1.2.15: pipe dot-source output to Out-Null. The Configuration block
    # emits the generated MOF FileInfo to the pipeline; without suppression
    # it leaks into this function's output collection alongside the explicit
    # `return $mof.FullName`, so the caller receives an array of TWO path
    # strings. That array silently coerces back to a doubled string when
    # bound to [string]$MofFolder downstream, and Test-DscConfiguration
    # reports "<path> <path> is not a valid directory."
    . $ConfigFile | Out-Null
    $mof = Get-ChildItem -Path $mofDir -Filter '*.mof' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $mof) { throw "No MOF produced in $mofDir" }
    return $mof.FullName
}

# Parse a DSC ResourceId like '[Registry]V-220706' back to its VulnID.
function Get-VulnIdFromResourceId {
    param([string]$ResourceId)
    if ($ResourceId -match 'V-\d+') { return $Matches[0] }
    return $null
}

# Run Test-DscConfiguration (local or remote) and return per-rule records.
# Returns array of hashtables: VulnID, InDesiredState (bool), ResourceId, Error
#
# v1.2.17: Peeling another layer of the local-DSC onion. Iteration log:
#
#   v1.2.15: Test-DscConfiguration -Path <dir> with CERBERUS.mof in <dir>.
#            DSC's default name lookup is "<localhost>.mof" — not found in
#            <dir>. DSC internally tries WinRM to reach the named host,
#            fails with "client cannot connect... winrm quickconfig".
#   v1.2.16: Added a DCOM CimSession to bypass WinRM. Now DSC sees
#            CimSession.ComputerName = "localhost" and explicitly looks
#            for localhost.mof in <dir>. Our file is CERBERUS.mof — error
#            "computer-specific MOF file for computer localhost does not
#            exist in the current directory."
#   v1.2.17: Drop the DCOM CimSession (Test-DscConfiguration uses the
#            in-process LCM API for localhost — no WinRM needed). Instead,
#            ensure a localhost.mof file exists in the MOF folder by
#            copying the named MOF to localhost.mof in Local mode. The
#            named MOF stays in place so Apply / Verify and any other
#            downstream consumer that wants the host-identified MOF still
#            has it.
function Invoke-StigEvaluation {
    param(
        [string]$MofFolder,
        [string]$ComputerName,
        [string]$Mode = 'Local',          # Local or Remote
        [System.Management.Automation.PSCredential]$Credential
    )
    $records = @()
    try {
        $params = @{ Path = $MofFolder; ErrorAction = 'Stop' }
        if ($Mode -eq 'Remote') {
            $params.ComputerName = $ComputerName
            if ($Credential) { $params.Credential = $Credential }
        } else {
            # Local: DSC LCM looks for localhost.mof in the folder. Our
            # compile generates <ComputerName>.mof, so duplicate it as
            # localhost.mof if one isn't already there.
            $localhostMof = Join-Path $MofFolder 'localhost.mof'
            if (-not (Test-Path $localhostMof)) {
                $existingMof = Get-ChildItem -Path $MofFolder -Filter '*.mof' -ErrorAction SilentlyContinue |
                               Where-Object { $_.Name -ne 'localhost.mof' } |
                               Sort-Object LastWriteTime -Descending |
                               Select-Object -First 1
                if ($existingMof) {
                    Copy-Item -Path $existingMof.FullName -Destination $localhostMof -Force -ErrorAction Stop
                }
            }
        }
        $res = Test-DscConfiguration @params
        if (-not $res) {
            # Test-DscConfiguration can return nothing while the LCM is in
            # a transient state (Pending / Busy). Treat as an evaluate error
            # so the operator sees an actionable message instead of a crash.
            $records += [ordered]@{ VulnID = $null; ResourceId = $null; InDesiredState = $false; Error = 'Test-DscConfiguration returned no result (LCM may be Pending, Busy, or Rebooting).' }
            return $records
        }
        $inState  = @()
        $outState = @()
        if ($res.PSObject.Properties['ResourcesInDesiredState']   ) { $inState  = @($res.ResourcesInDesiredState)    }
        if ($res.PSObject.Properties['ResourcesNotInDesiredState']) { $outState = @($res.ResourcesNotInDesiredState) }
        foreach ($r in $inState) {
            $records += [ordered]@{
                VulnID = (Get-VulnIdFromResourceId -ResourceId $r.ResourceId)
                ResourceId = $r.ResourceId
                InDesiredState = $true
                Error = $null
            }
        }
        foreach ($r in $outState) {
            $records += [ordered]@{
                VulnID = (Get-VulnIdFromResourceId -ResourceId $r.ResourceId)
                ResourceId = $r.ResourceId
                InDesiredState = $false
                Error = $null
            }
        }
    } catch {
        $records += [ordered]@{ VulnID = $null; ResourceId = $null; InDesiredState = $false; Error = $_.Exception.Message }
    }
    return $records
}

# Run Start-DscConfiguration
# v1.2.17: same localhost.mof fix as Invoke-StigEvaluation. Local
# Start-DscConfiguration looks for localhost.mof in the folder, our
# compile produces <ComputerName>.mof, so duplicate it. No DCOM
# CimSession needed — the in-process LCM works without WinRM when
# the right MOF name is present.
function Invoke-StigApply {
    param(
        [string]$MofFolder,
        [string]$ComputerName,
        [string]$Mode = 'Local',
        [System.Management.Automation.PSCredential]$Credential,
        [int]$TimeoutSec = 1800
    )
    try {
        # ErrorAction=Continue so per-resource non-terminating errors accumulate
        # in $errs instead of aborting on the first failure. Start-DscConfiguration
        # typically emits one non-terminating error per resource that failed
        # to remediate, and a terminating error only for infra-level problems.
        $errs = @()
        $params = @{ Path = $MofFolder; Wait = $true; Force = $true; Verbose = $true; ErrorAction = 'Continue'; ErrorVariable = 'errs' }
        if ($Mode -eq 'Remote') {
            $params.ComputerName = $ComputerName
            if ($Credential) { $params.Credential = $Credential }
        } else {
            $localhostMof = Join-Path $MofFolder 'localhost.mof'
            if (-not (Test-Path $localhostMof)) {
                $existingMof = Get-ChildItem -Path $MofFolder -Filter '*.mof' -ErrorAction SilentlyContinue |
                               Where-Object { $_.Name -ne 'localhost.mof' } |
                               Sort-Object LastWriteTime -Descending |
                               Select-Object -First 1
                if ($existingMof) {
                    Copy-Item -Path $existingMof.FullName -Destination $localhostMof -Force -ErrorAction Stop
                }
            }
        }
        Start-DscConfiguration @params 4>&1 | Out-Null
        if ($errs -and $errs.Count -gt 0) {
            $msgs = ($errs | ForEach-Object { [string]$_ }) -join '; '
            return [pscustomobject]@{ Success = $false; Error = $msgs }
        }
        return [pscustomobject]@{ Success = $true; Error = $null }
    } catch {
        return [pscustomobject]@{ Success = $false; Error = $_.Exception.Message }
    }
}

# Bounded remote-execution helper (added in v1.2.3). Funnels every
# remote PSRemoting call in the apply / verify / reboot / LCM paths
# through a single New-PSSession with bounded timeouts and Negotiate
# auth. Without this, an unbounded Invoke-Command -ComputerName against
# a half-broken target hangs the UI thread for the WSMan default of
# ~3 minutes per call. Pattern ported from the J.A.N.E.T. WPT.
function Invoke-StigBoundedRemote {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$OperationTimeoutMs = 180000,
        [int]$OpenTimeoutMs      = 15000
    )
    $sopt = New-PSSessionOption -OperationTimeout $OperationTimeoutMs -OpenTimeout $OpenTimeoutMs -CancelTimeout 5000 -IdleTimeout 60000
    $sp = @{
        ComputerName    = $ComputerName
        ErrorAction     = 'Stop'
        Authentication  = 'Negotiate'
        SessionOption   = $sopt
    }
    if ($Credential) { $sp.Credential = $Credential }
    $sess = $null
    try {
        $sess = New-PSSession @sp
        $cp = @{ Session = $sess; ScriptBlock = $ScriptBlock; ErrorAction = 'Stop' }
        if ($ArgumentList) { $cp.ArgumentList = $ArgumentList }
        return Invoke-Command @cp
    } finally {
        if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
    }
}

# Probe the DSC Local Configuration Manager state for a target. Returns a
# hashtable with Health (OK/Warn/Fail), State (LCMState from DSC), and
# Message. DSC applies silently fail or hang when the LCM is Busy or
# PendingConfiguration — better to detect up-front and tell the operator
# how to fix it (Remove-DscConfigurationDocument -Stage Current,Pending,Previous).
function Test-StigDscLcmHealth {
    param(
        [string]$ComputerName,
        [string]$Mode = 'Local',
        [System.Management.Automation.PSCredential]$Credential
    )
    $res = @{ Health = 'OK'; State = 'Unknown'; Message = ''; RefreshMode = ''; Raw = $null }
    try {
        if ($Mode -eq 'Local') {
            $lcm = Get-DscLocalConfigurationManager -ErrorAction Stop
        } else {
            # Bounded session so a half-broken target doesn't hang the UI.
            $lcm = Invoke-StigBoundedRemote -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Get-DscLocalConfigurationManager
            }
        }
        $res.Raw = $lcm
        $res.State       = [string]$lcm.LCMState
        $res.RefreshMode = [string]$lcm.RefreshMode
        switch ($res.State) {
            'Idle'                  { $res.Health = 'OK';   $res.Message = 'LCM is Idle and ready.' }
            'Busy'                  { $res.Health = 'Warn'; $res.Message = 'LCM is Busy — another configuration is currently executing. Wait and retry.' }
            'PendingConfiguration'  { $res.Health = 'Warn'; $res.Message = 'LCM has a pending configuration. Clear via: Remove-DscConfigurationDocument -Stage Pending' }
            'PendingReboot'         { $res.Health = 'Warn'; $res.Message = 'LCM is awaiting a reboot. Restart the target before applying again.' }
            default                 { $res.Health = 'Warn'; $res.Message = "LCM state '$($res.State)' — may be non-Idle. Apply may behave unexpectedly." }
        }
        # Pull / ApplyAndAutoCorrect modes reapply configuration on a schedule
        # and can fight a manual apply. Warn about that too.
        $cfgMode = [string]$lcm.ConfigurationMode
        if ($res.RefreshMode -eq 'Pull' -or $cfgMode -eq 'ApplyAndAutoCorrect') {
            $res.Health = 'Warn'
            $res.Message += "  NOTE: LCM RefreshMode=$($res.RefreshMode), ConfigurationMode=$cfgMode — a pull server or auto-correct loop may revert your manual apply."
        }
    } catch {
        $res.Health  = 'Fail'
        $res.Message = "Could not query DSC LCM: $($_.Exception.Message)"
    }
    return $res
}

# Per-host compile -> (Test or Apply) pipeline. Factored out of the
# Apply-tab UI handler in v1.3.1 so the CKLB Import tab can drive it
# from Invoke-StigApplyFromCklb.
#
# Returns: pscustomobject with Success/Error/MofPath/RecordCount.
#   - For DryRun=$true: RecordCount = count of would-be-remediated rules.
#   - For DryRun=$false: RecordCount = $null; Success/Error reflect the apply result.
function Invoke-StigPipelineForHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $Technology,
        [string] $OsCaption = '',
        [string] $Role      = '',
        [string[]] $SkipRule = @(),
        [ValidateSet('Local','Remote')] [string] $Mode = 'Local',
        [System.Management.Automation.PSCredential] $Credential,
        [bool] $DryRun = $false,
        # v1.3.2: -CompileOnly returns immediately after Invoke-StigCompile
        # without running Test-DscConfiguration or Start-DscConfiguration.
        # The caller gets MofPath back and can drive Test/Apply themselves —
        # used by the Apply-tab handler which needs to interleave a
        # pre-apply Invoke-StigEvaluation call (for the JANET VulnsRemediated
        # metric) between compile and apply against the same MOF.
        [switch] $CompileOnly
    )
    $osVer  = Get-OsVersionForTech -Technology $Technology -OSCaption $OsCaption -Role $Role
    $osRole = Get-OsRoleForTech   -Technology $Technology -Role $Role

    try {
        $cfg = New-StigDscConfigFile -ComputerName $ComputerName -Technology $Technology -OsVersion $osVer -OsRole $osRole -SkipRule $SkipRule
    } catch {
        return [pscustomobject]@{
            Success     = $false
            Error       = "config-gen failed: $($_.Exception.Message)"
            MofPath     = $null
            RecordCount = $null
        }
    }

    try {
        $mof = Invoke-StigCompile -ConfigFile $cfg.ConfigFile -ComputerName $ComputerName
    } catch {
        return [pscustomobject]@{
            Success     = $false
            Error       = "compile failed: $($_.Exception.Message)"
            MofPath     = $null
            RecordCount = $null
        }
    }

    $mofFolder = Split-Path $mof -Parent

    if ($CompileOnly) {
        return [pscustomobject]@{
            Success     = $true
            Error       = $null
            MofPath     = $mof
            RecordCount = $null
        }
    }

    if ($DryRun) {
        try {
            $records = Invoke-StigEvaluation -MofFolder $mofFolder -ComputerName $ComputerName -Mode $Mode -Credential $Credential
            $would = @($records | Where-Object { $_.InDesiredState -eq $false -and -not $_.Error }).Count
            return [pscustomobject]@{
                Success     = $true
                Error       = $null
                MofPath     = $mof
                RecordCount = $would
            }
        } catch {
            return [pscustomobject]@{
                Success     = $false
                Error       = "evaluation failed: $($_.Exception.Message)"
                MofPath     = $mof
                RecordCount = $null
            }
        }
    }

    $res = Invoke-StigApply -MofFolder $mofFolder -ComputerName $ComputerName -Mode $Mode -Credential $Credential
    return [pscustomobject]@{
        Success     = [bool]$res.Success
        Error       = $res.Error
        MofPath     = $mof
        RecordCount = $null
    }
}
#endregion

#region ------------------------ TARGET DISCOVERY -------------------------
# v1.2.4: removed legacy Test-TargetReachability function. The Targets-tab
# Test Reachability button uses the inline TCP 5985/445 probe defined
# in BuildAppForm; this helper was unused dead code that still relied on
# ICMP Test-Connection and unbounded Invoke-Command.
#endregion

#region ------------------------ XLSX EXPORT ------------------------------
function Export-ScanToXlsx {
    param(
        [hashtable]$ScanData,      # ScanId, Timestamp, Mode, Operator, Hosts (array of host result hashtables)
        [string]$OutputPath
    )
    if (-not $global:PrereqStatus.ImportExcelInstalled) {
        throw 'ImportExcel module not installed — cannot export XLSX.'
    }
    Import-Module ImportExcel -ErrorAction Stop

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

    # Summary sheet
    $summary = @()
    foreach ($h in $ScanData.Hosts) {
        $total = $h.Records.Count
        $pass  = @($h.Records | Where-Object { $_.InDesiredState -eq $true }).Count
        $fail  = @($h.Records | Where-Object { $_.InDesiredState -eq $false -and -not $_.Error }).Count
        $err   = @($h.Records | Where-Object { $_.Error }).Count
        $pct   = if ($total -gt 0) { [math]::Round(($pass / $total) * 100, 1) } else { 0 }
        $summary += [pscustomobject]@{
            Host        = $h.Host
            Technology  = $h.Technology
            Total       = $total
            Pass        = $pass
            Fail        = $fail
            Errors      = $err
            CompliancePct = $pct
            ScannedAt   = $h.ScannedAt
        }
    }
    $summary | Export-Excel -Path $OutputPath -WorksheetName 'Summary' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2

    # PerRule sheet — catalog joined to results
    $perRule = @()
    foreach ($h in $ScanData.Hosts) {
        $catalog = Get-PowerStigRuleCatalog -Technology $h.Technology
        $catalogMap = @{}
        foreach ($c in $catalog) { $catalogMap[$c.VulnID] = $c }
        foreach ($r in $h.Records) {
            $meta = $catalogMap[$r.VulnID]
            $perRule += [pscustomobject]@{
                Host      = $h.Host
                VulnID    = $r.VulnID
                Severity  = if ($meta) { $meta.Severity } else { '' }
                Title     = if ($meta) { $meta.Title }    else { '' }
                Status    = if ($r.Error) { 'Error' } elseif ($r.InDesiredState) { 'Pass' } else { 'Fail' }
                ResourceId= $r.ResourceId
                Error     = $r.Error
            }
        }
    }
    $perRule | Export-Excel -Path $OutputPath -WorksheetName 'PerRule' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2 -Append

    # Skipped sheet
    $skipped = @()
    foreach ($tech in $global:SkipLists.Keys) {
        foreach ($v in $global:SkipLists[$tech]) {
            $skipped += [pscustomobject]@{ Technology = $tech; VulnID = $v }
        }
    }
    if ($skipped.Count -gt 0) {
        $skipped | Export-Excel -Path $OutputPath -WorksheetName 'Skipped' -AutoSize -BoldTopRow -TableStyle Medium2 -Append
    }

    # Audit tail (last 200 lines)
    if (Test-Path $global:AuditLogPath) {
        $auditRows = @()
        Get-Content $global:AuditLogPath -Tail 200 | ForEach-Object {
            $parts = $_ -split "`t"
            if ($parts.Count -ge 4) {
                $auditRows += [pscustomobject]@{
                    Timestamp = $parts[0]; Operator = $parts[1]; Event = $parts[2]; Details = $parts[3]
                }
            }
        }
        if ($auditRows.Count -gt 0) {
            $auditRows | Export-Excel -Path $OutputPath -WorksheetName 'AuditTrail' -AutoSize -BoldTopRow -TableStyle Medium2 -Append
        }
    }

    return $OutputPath
}

# Export a per-host CKL (STIG Viewer XML checklist) from scan results.
# CKL format: CHECKLIST > STIGS > iSTIG > VULN entries per rule, each with
# STATUS (NotAFinding / Open / Not_Reviewed / Not_Applicable), FINDING_DETAILS,
# COMMENTS. Auditors import these directly into STIG Viewer or eMASS.
function Export-ScanToCkl {
    param(
        [hashtable]$HostResult,   # single entry from CurrentScan.Hosts: Host, Technology, Records, StigVersion
        [string]$OutputPath
    )
    $tech = $HostResult.Technology
    $osVer = [string]$HostResult.OsVersion
    $catalog = Get-PowerStigRuleCatalog -Technology $tech -TechnologyVersion $osVer -StigVersion $HostResult.StigVersion
    $catalogMap = @{}
    foreach ($c in $catalog) { $catalogMap[$c.VulnID] = $c }

    # DISA canonical STIG identity — what STIG Viewer uses to match the
    # CKL to its XCCDF benchmark. Wrong stigid = no merge with official DISA releases.
    $disaIdent = Get-DisaStigIdentity -Technology $tech -OsVersion $osVer
    $stigInfoMeta = if ($catalog.Count -gt 0 -and $catalog[0].StigInfo) { $catalog[0].StigInfo } else { @{ StigId = $disaIdent.StigId; Title = $disaIdent.Title; Version = ''; ReleaseInfo = '' } }

    # XML 1.0 strips most control chars; STIG Viewer's parser is strict about
    # them. PowerStig CheckContent/FixText occasionally contains NUL / form
    # feed from DISA's source XCCDF. Sanitize before every InnerText assignment.
    $sanitize = {
        param([string]$Text)
        if (-not $Text) { return '' }
        return ($Text -replace '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]','')
    }

    # Try to resolve host IP/MAC/FQDN from the scan-time target record.
    # Bounded — default resolver timeout is ~5s per failure, which would
    # freeze the export on every unresolvable host.
    $target = $global:Targets | Where-Object { $_.Host -eq $HostResult.Host } | Select-Object -First 1
    $hostIp = ''
    $hostFqdn = ''
    if ($target -and $HostResult.Host) {
        $dns = Resolve-StigHostBounded -ComputerName $HostResult.Host -TimeoutMs 1000
        $hostIp   = [string]$dns.Ip
        $hostFqdn = [string]$dns.Fqdn
        if (-not $hostIp -and -not $hostFqdn) {
            Write-Audit -Event 'DnsLookupTimeout' -Details "host=$($HostResult.Host) timeoutMs=1000"
        }
    }

    $xml = [System.Xml.XmlDocument]::new()
    [void]$xml.AppendChild($xml.CreateXmlDeclaration('1.0', 'UTF-8', $null))
    $root = $xml.CreateElement('CHECKLIST')
    [void]$xml.AppendChild($root)

    # ASSET node
    $asset = $xml.CreateElement('ASSET')
    foreach ($kv in @(
        @('ROLE','None'),
        @('ASSET_TYPE','Computing'),
        @('HOST_NAME', [string]$HostResult.Host),
        @('HOST_IP',   [string]$hostIp),
        @('HOST_MAC',  ''),
        @('HOST_FQDN', [string]$hostFqdn),
        @('TECH_AREA',''),
        @('TARGET_KEY',''),
        @('WEB_OR_DATABASE','false'),
        @('WEB_DB_SITE',''),
        @('WEB_DB_INSTANCE','')
    )) {
        $el = $xml.CreateElement($kv[0])
        $el.InnerText = $kv[1]
        [void]$asset.AppendChild($el)
    }
    [void]$root.AppendChild($asset)

    # STIGS > iSTIG
    $stigs = $xml.CreateElement('STIGS')
    $istig = $xml.CreateElement('iSTIG')

    # STIG_INFO header — now uses proper DISA stigid, version, releaseinfo,
    # UUID so STIG Viewer / eMASS accepts the CKL and can merge it with
    # the matching XCCDF benchmark.
    $ckUuid = [guid]::NewGuid().ToString()
    $stigInfo = $xml.CreateElement('STIG_INFO')
    foreach ($si in @(
        @('version',      $(if ($stigInfoMeta.Version) { $stigInfoMeta.Version } else { '1' })),
        @('classification','UNCLASSIFIED'),
        @('customname',   ''),
        @('stigid',       $stigInfoMeta.StigId),
        @('description',  "PowerStig-driven compliance scan. Source: J.A.N.E.T. STIG Tool $global:ToolVersion"),
        @('filename',     "$($stigInfoMeta.StigId).xml"),
        @('releaseinfo',  $stigInfoMeta.ReleaseInfo),
        @('title',        $stigInfoMeta.Title),
        @('uuid',         $ckUuid),
        @('notice',       'terms-of-use'),
        @('source',       'STIG.DOD.MIL')
    )) {
        $siData = $xml.CreateElement('SI_DATA')
        $sidName = $xml.CreateElement('SID_NAME'); $sidName.InnerText = $si[0]
        $sidData = $xml.CreateElement('SID_DATA'); $sidData.InnerText = & $sanitize ([string]$si[1])
        [void]$siData.AppendChild($sidName)
        [void]$siData.AppendChild($sidData)
        [void]$stigInfo.AppendChild($siData)
    }
    [void]$istig.AppendChild($stigInfo)

    # VULN entries per rule
    foreach ($rec in $HostResult.Records) {
        if (-not $rec.VulnID) { continue }
        $meta = $catalogMap[$rec.VulnID]
        $rmd  = Get-RuleMetadata -Technology $tech -VulnID $rec.VulnID
        $vuln = $xml.CreateElement('VULN')

        # CAT-level severity (lowercase form = DISA CKL convention: 'high'/'medium'/'low')
        # STIG Viewer still wants lowercase here, but the display labels in
        # the Review grid + XLSX now say CAT I/II/III for operators.
        $sevLower = if ($meta) {
            switch ($meta.Cat) {
                'CAT I'   { 'high' }
                'CAT II'  { 'medium' }
                'CAT III' { 'low' }
                default   { 'medium' }
            }
        } else { 'medium' }

        # CCI refs → emit multiple STIG_DATA rows if the rule has multiple CCIs
        $ccis = if ($meta -and $meta.Ccis) { @($meta.Ccis) } else { @() }
        $cciFirst = if ($ccis.Count -gt 0) { $ccis[0] } else { '' }

        # STIG_DATA fields (base set — CCI rows added below in a loop)
        foreach ($sd in @(
            @('Vuln_Num',          $rec.VulnID),
            @('Severity',          $sevLower),
            @('Group_Title',       $(if($meta){$meta.Title}else{''})),
            @('Rule_ID',           $(if($meta){$meta.RuleID}else{$rec.VulnID})),
            @('Rule_Ver',          $(if($meta -and $meta.PSObject.Properties['RuleVer']){$meta.RuleVer}else{''})),
            @('Rule_Title',        $(if($meta){$meta.Title}else{''})),
            @('Vuln_Discuss',      $(if($meta){$meta.Description}else{''})),
            @('IA_Controls',       ''),
            @('Check_Content',     $(if($meta){$meta.CheckContent}else{''})),
            @('Fix_Text',          $(if($meta){$meta.FixText}else{''})),
            @('False_Positives',   ''),
            @('False_Negatives',   ''),
            @('Documentable',      'false'),
            @('Mitigations',       ''),
            @('Potential_Impact',  ''),
            @('Third_Party_Tools', ''),
            @('Mitigation_Control',''),
            @('Responsibility',    ''),
            @('Security_Override_Guidance',''),
            @('Check_Content_Ref', 'DPMS Target'),
            @('Weight',            '10.0'),
            @('Class',             'Unclass'),
            @('STIGRef',           "$($stigInfoMeta.Title) :: $($stigInfoMeta.Version) $($stigInfoMeta.ReleaseInfo)"),
            @('TargetKey',         ''),
            @('STIG_UUID',         $ckUuid),
            @('LEGACY_ID',         '')
        )) {
            $stigData = $xml.CreateElement('STIG_DATA')
            $vdName = $xml.CreateElement('VULN_ATTRIBUTE'); $vdName.InnerText = $sd[0]
            $vdData = $xml.CreateElement('ATTRIBUTE_DATA'); $vdData.InnerText = & $sanitize ([string]$sd[1])
            [void]$stigData.AppendChild($vdName)
            [void]$stigData.AppendChild($vdData)
            [void]$vuln.AppendChild($stigData)
        }
        # CCI refs — one STIG_DATA row per CCI (STIG Viewer supports multiple)
        foreach ($cci in $ccis) {
            $stigData = $xml.CreateElement('STIG_DATA')
            $vdName = $xml.CreateElement('VULN_ATTRIBUTE'); $vdName.InnerText = 'CCI_REF'
            $vdData = $xml.CreateElement('ATTRIBUTE_DATA'); $vdData.InnerText = [string]$cci
            [void]$stigData.AppendChild($vdName)
            [void]$stigData.AppendChild($vdData)
            [void]$vuln.AppendChild($stigData)
        }
        if ($ccis.Count -eq 0) {
            $stigData = $xml.CreateElement('STIG_DATA')
            $vdName = $xml.CreateElement('VULN_ATTRIBUTE'); $vdName.InnerText = 'CCI_REF'
            $vdData = $xml.CreateElement('ATTRIBUTE_DATA'); $vdData.InnerText = ''
            [void]$stigData.AppendChild($vdName)
            [void]$stigData.AppendChild($vdData)
            [void]$vuln.AppendChild($stigData)
        }

        # STATUS: Open/NotAFinding/Not_Reviewed/Not_Applicable
        # Not_Applicable is used for rules the operator excluded via skip-list
        # AND provided a justification for. Without justification we fall back
        # to whatever the scan returned (Open/NotAFinding/Not_Reviewed).
        $skipList = @()
        if ($global:SkipLists.ContainsKey($tech)) { $skipList = @($global:SkipLists[$tech]) }
        $isSkipped = $skipList -contains $rec.VulnID

        $statusEl = $xml.CreateElement('STATUS')
        if ($isSkipped -and $rmd.NAJustification) {
            $statusEl.InnerText = 'Not_Applicable'
        } elseif ($rec.Error) {
            $statusEl.InnerText = 'Not_Reviewed'
        } elseif ($rec.InDesiredState) {
            $statusEl.InnerText = 'NotAFinding'
        } else {
            $statusEl.InnerText = 'Open'
        }
        [void]$vuln.AppendChild($statusEl)

        # FINDING_DETAILS: operator text wins if present; else auto-generated
        $fd = $xml.CreateElement('FINDING_DETAILS')
        $fdText = if ($rmd.FindingDetails) {
            $rmd.FindingDetails
        } elseif ($rec.Error) {
            "Scan error: $($rec.Error)"
        } elseif ($rec.InDesiredState) {
            "In desired state per Test-DscConfiguration. Resource: $($rec.ResourceId)"
        } else {
            "Not in desired state per Test-DscConfiguration. Resource: $($rec.ResourceId)"
        }
        $fd.InnerText = & $sanitize $fdText
        [void]$vuln.AppendChild($fd)

        # COMMENTS: for NA status we MUST include the justification (DISA requirement).
        # For other statuses, include operator comments if any, plus scan provenance.
        $cm = $xml.CreateElement('COMMENTS')
        $cmText = if ($isSkipped -and $rmd.NAJustification) {
            "[NA JUSTIFICATION] $($rmd.NAJustification)`r`n`r`nScanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        } elseif ($rmd.Comments) {
            "$($rmd.Comments)`r`n`r`nScanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        } else {
            "Scanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        }
        $cm.InnerText = & $sanitize $cmText
        [void]$vuln.AppendChild($cm)

        # DISA rule: SEVERITY_OVERRIDE is only valid when paired with a
        # non-empty SEVERITY_JUSTIFICATION. Emit the override only when both
        # sides are present; otherwise emit empty strings to pass STIG Viewer.
        $overrideToken = ''
        $overrideJust  = [string]$rmd.SeverityJustification
        if ($rmd.SeverityOverride) {
            $tok = switch ($rmd.SeverityOverride) {
                'CAT I'   { 'high' }
                'CAT II'  { 'medium' }
                'CAT III' { 'low' }
                default   { '' }
            }
            if ($tok -and $overrideJust) {
                $overrideToken = $tok
            } else {
                $overrideJust = ''
            }
        } else {
            $overrideJust = ''
        }
        $sv = $xml.CreateElement('SEVERITY_OVERRIDE')
        $sv.InnerText = $overrideToken
        [void]$vuln.AppendChild($sv)

        $sj = $xml.CreateElement('SEVERITY_JUSTIFICATION')
        $sj.InnerText = & $sanitize $overrideJust
        [void]$vuln.AppendChild($sj)

        [void]$istig.AppendChild($vuln)
    }

    [void]$stigs.AppendChild($istig)
    [void]$root.AppendChild($stigs)

    $xml.Save($OutputPath)
    return $OutputPath
}

# Export a per-host checklist in STIG Viewer 3's CKLB format (JSON).
# DISA released STIG Viewer 3 in 2023; CKLB is the forward-going format
# replacing CKL (XML). Modern eMASS imports accept both.
# Schema reference: stig.defense.gov (STIG Viewer 3 User Guide)
function Export-ScanToCklb {
    param(
        [hashtable]$HostResult,
        [string]$OutputPath
    )
    $tech = $HostResult.Technology
    $osVer = [string]$HostResult.OsVersion
    $catalog = Get-PowerStigRuleCatalog -Technology $tech -TechnologyVersion $osVer -StigVersion $HostResult.StigVersion
    $catalogMap = @{}
    foreach ($c in $catalog) { $catalogMap[$c.VulnID] = $c }
    $disaIdent = Get-DisaStigIdentity -Technology $tech -OsVersion $osVer
    $stigInfoMeta = if ($catalog.Count -gt 0 -and $catalog[0].StigInfo) { $catalog[0].StigInfo } else { @{ StigId = $disaIdent.StigId; Title = $disaIdent.Title; Version = ''; ReleaseInfo = '' } }

    $skipList = @()
    if ($global:SkipLists.ContainsKey($tech)) { $skipList = @($global:SkipLists[$tech]) }

    $ckUuid = [guid]::NewGuid().ToString()

    $rules = @()
    foreach ($rec in $HostResult.Records) {
        if (-not $rec.VulnID) { continue }
        $meta = $catalogMap[$rec.VulnID]
        $rmd  = Get-RuleMetadata -Technology $tech -VulnID $rec.VulnID
        $isSkipped = $skipList -contains $rec.VulnID

        $catLower = if ($meta) {
            switch ($meta.Cat) {
                'CAT I'   { 'high' }
                'CAT II'  { 'medium' }
                'CAT III' { 'low' }
                default   { 'medium' }
            }
        } else { 'medium' }
        $statusCklb = if ($isSkipped -and $rmd.NAJustification) {
            'not_applicable'
        } elseif ($rec.Error) {
            'not_reviewed'
        } elseif ($rec.InDesiredState) {
            'not_a_finding'
        } else {
            'open'
        }

        $findingDetails = if ($rmd.FindingDetails) {
            $rmd.FindingDetails
        } elseif ($rec.Error) {
            "Scan error: $($rec.Error)"
        } elseif ($rec.InDesiredState) {
            "In desired state per Test-DscConfiguration. Resource: $($rec.ResourceId)"
        } else {
            "Not in desired state per Test-DscConfiguration. Resource: $($rec.ResourceId)"
        }
        $comments = if ($isSkipped -and $rmd.NAJustification) {
            "[NA JUSTIFICATION] $($rmd.NAJustification)`n`nScanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        } elseif ($rmd.Comments) {
            "$($rmd.Comments)`n`nScanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        } else {
            "Scanned by J.A.N.E.T. STIG Tool $global:ToolVersion on $($HostResult.ScannedAt)"
        }

        $overrideSev = if ($rmd.SeverityOverride) {
            switch ($rmd.SeverityOverride) {
                'CAT I'   { 'high' }
                'CAT II'  { 'medium' }
                'CAT III' { 'low' }
                default   { '' }
            }
        } else { '' }

        # Build CCI array outside the hashtable literal. Computing it inline
        # via @(if (...) { $meta.Ccis } else { @() }) can produce nested
        # arrays under PS 5.1 and breaks eMASS's JSON validator.
        $cciArr = @()
        if ($meta -and $meta.Ccis) { $cciArr = @([string[]]$meta.Ccis) }

        # eMASS expects the override to pair with a justification; suppress
        # both sides when the justification is missing.
        $overrideJust = [string]$rmd.SeverityJustification
        $overridesObj = @{}
        if ($overrideSev -and $overrideJust) {
            $overridesObj = @{ severity = @{ newSeverity = $overrideSev; reason = 'Operator override'; justification = $overrideJust } }
        }

        $rules += [ordered]@{
            uuid                 = [guid]::NewGuid().ToString()
            stig_uuid            = $ckUuid
            target_key           = $null
            stig_ref             = $null
            group_id             = $(if($meta){$meta.VulnID}else{$rec.VulnID})
            rule_id              = $(if($meta){$meta.RuleID}else{$rec.VulnID})
            rule_id_src          = $(if($meta){$meta.RuleID}else{$rec.VulnID})
            weight               = '10.0'
            classification       = 'UNCLASSIFIED'
            severity             = $catLower
            rule_version         = $(if($meta -and $meta.PSObject.Properties['RuleVer']){$meta.RuleVer}else{''})
            group_title          = $(if($meta){$meta.Title}else{''})
            rule_title           = $(if($meta){$meta.Title}else{''})
            fix_text             = $(if($meta){$meta.FixText}else{''})
            false_positives      = ''
            false_negatives      = ''
            discussion           = $(if($meta){$meta.Description}else{''})
            check_content        = $(if($meta){$meta.CheckContent}else{''})
            documentable         = $false
            mitigations          = ''
            potential_impacts    = ''
            third_party_tools    = ''
            mitigation_control   = ''
            responsibility       = ''
            security_override_guidance = ''
            ia_controls          = ''
            check_content_ref    = @{ href = ''; name = 'DPMS Target' }
            legacy_ids           = @()
            ccis                 = $cciArr
            group_tree           = @()
            createdAt            = (Get-Date).ToString('o')
            updatedAt            = (Get-Date).ToString('o')
            STIGUuid             = $ckUuid
            status               = $statusCklb
            overrides            = $overridesObj
            comments             = $comments
            finding_details      = $findingDetails
        }
    }

    # Resolve host IP + FQDN — bounded to avoid the OS resolver default
    # 5s freeze per unresolvable host on a multi-host export.
    $hostIp = ''
    $hostFqdn = ''
    if ($HostResult.Host) {
        $dns = Resolve-StigHostBounded -ComputerName $HostResult.Host -TimeoutMs 1000
        $hostIp   = [string]$dns.Ip
        $hostFqdn = [string]$dns.Fqdn
        if (-not $hostIp -and -not $hostFqdn) {
            Write-Audit -Event 'DnsLookupTimeout' -Details "host=$($HostResult.Host) timeoutMs=1000"
        }
    }

    $cklb = [ordered]@{
        title              = $stigInfoMeta.Title
        id                 = $ckUuid
        stigs              = @(
            [ordered]@{
                stig_name            = $stigInfoMeta.Title
                display_name         = $stigInfoMeta.Title
                stig_id              = $stigInfoMeta.StigId
                release_info         = $stigInfoMeta.ReleaseInfo
                version              = [string]$stigInfoMeta.Version
                uuid                 = $ckUuid
                reference_identifier = $stigInfoMeta.StigId
                size                 = $rules.Count
                rules                = $rules
            }
        )
        active             = $false
        mode               = 1
        has_path           = $true
        target_data        = [ordered]@{
            target_type         = 'Computing'
            host_name           = [string]$HostResult.Host
            ip_address          = $hostIp
            mac_address         = ''
            fqdn                = $hostFqdn
            comments            = ''
            role                = 'None'
            is_web_database     = $false
            technology_area     = ''
            web_db_site         = ''
            web_db_instance     = ''
            classification      = 'UNCLASSIFIED'
        }
        cklb_version       = '1.0'
    }
    # Atomic write — CKLBs are consumed by STIG Viewer / eMASS imports and
    # a half-written file silently breaks the import.
    $res = Set-StigJsonAtomic -Path $OutputPath -InputObject $cklb -Depth 10
    if (-not $res.Ok) { throw "CKLB write failed: $($res.Error)" }
    return $OutputPath
}

# Export a DoD RMF-style POA&M workbook for findings that are Open / Not
# Applicable. Columns follow the eMASS POA&M import template: one row
# per finding with CCI mapping, severity, weakness description, mitigation,
# milestones, scheduled completion.
function Export-ScanToPoam {
    param(
        [hashtable]$ScanData,
        [string]$OutputPath
    )
    if (-not $global:PrereqStatus.ImportExcelInstalled) {
        throw 'ImportExcel module not installed — cannot export POA&M XLSX.'
    }
    Import-Module ImportExcel -ErrorAction Stop

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
    $rows = @()
    foreach ($hr in $ScanData.Hosts) {
        $catalog = Get-PowerStigRuleCatalog -Technology $hr.Technology -TechnologyVersion ([string]$hr.OsVersion) -StigVersion $hr.StigVersion
        $catMap = @{}
        foreach ($c in $catalog) { $catMap[$c.VulnID] = $c }
        $skipList = @()
        if ($global:SkipLists.ContainsKey($hr.Technology)) { $skipList = @($global:SkipLists[$hr.Technology]) }
        # eMASS expects POA&M finding IDs unique per host/asset — counter
        # resets inside the host loop so each asset's rows number from 1.
        $counter = 1
        foreach ($r in $hr.Records) {
            if (-not $r.VulnID) { continue }
            # Only write rows for findings that need remediation — skip Pass
            if ($r.InDesiredState) { continue }
            $meta = $catMap[$r.VulnID]
            $rmd  = Get-RuleMetadata -Technology $hr.Technology -VulnID $r.VulnID
            $isSkipped = $skipList -contains $r.VulnID

            $status = if ($isSkipped -and $rmd.NAJustification) {
                'Risk Accepted'
            } elseif ($r.Error) {
                'Not Reviewed'
            } else {
                'Ongoing'
            }
            $cat = if ($meta) { $meta.Cat } else { 'CAT II' }
            $metaTitle = if ($meta) { [string]$meta.Title } else { '(rule metadata unavailable)' }
            $metaDesc  = if ($meta) { [string]$meta.Description } else { '' }
            $metaFix   = if ($meta) { [string]$meta.FixText } else { '' }
            $cciList   = if ($meta -and $meta.Ccis) { (@($meta.Ccis) -join '; ') } else { '' }
            $rows += [pscustomobject][ordered]@{
                'Control Vulnerability Description' = "$($hr.Host): $metaTitle"
                'Security Control Number (NIST 800-53)' = ''
                'CCI'                               = $cciList
                'Office/Org'                        = $global:Operator
                'Security Checks'                   = $r.VulnID
                'Resources Required'                = ''
                'Scheduled Completion Date'         = ''
                'Milestones with Completion Dates'  = ''
                'Milestone Changes'                 = ''
                'Source Identifying Control Vulnerability' = "$($hr.Technology) STIG (J.A.N.E.T. STIG Tool scan)"
                'Status'                            = $status
                'Comments'                          = if ($rmd.Comments) { $rmd.Comments } elseif ($isSkipped) { $rmd.NAJustification } else { "Detected via Test-DscConfiguration on $($hr.ScannedAt)" }
                'Raw Severity'                      = $cat
                'Mitigations'                       = ''
                'Severity'                          = $cat
                'Relevance of Threat'               = ''
                'Threat Description'                = $metaDesc
                'Likelihood'                        = ''
                'Impact'                            = ''
                'Impact Description'                = ''
                'Residual Risk Level'               = ''
                'Recommendations'                   = $metaFix
                'Resulting Residual Risk after Proposed Mitigations' = ''
                'Finding Details'                   = if ($rmd.FindingDetails) { $rmd.FindingDetails } else { "Not in desired state. Resource: $($r.ResourceId)" }
                'Host'                              = $hr.Host
                'Finding Number'                    = $counter
            }
            $counter++
        }
    }
    if ($rows.Count -eq 0) { $rows = @([pscustomobject]@{ Note = 'No findings requiring POA&M (everything passed or all findings have NA justifications).' }) }
    $rows | Export-Excel -Path $OutputPath -WorksheetName 'POAM' -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2
    return $OutputPath
}
#endregion

#region ------------------------ SKIP-LIST PERSIST ------------------------
function Export-StigSkipList {
    param([string]$Technology)
    $path = Join-Path $global:SkipListRoot "$Technology.json"
    $data = @{
        Technology = $Technology
        SavedAt    = (Get-Date).ToString('o')
        SavedBy    = $global:Operator
        Rules      = @($global:SkipLists[$Technology])
    }
    $res = Set-StigJsonAtomic -Path $path -InputObject $data -Depth 4
    if (-not $res.Ok) {
        Write-Audit -Event 'SkipListSaveFailed' -Details "tech=$Technology err=$($res.Error)"
        throw "Skip-list save failed for $Technology : $($res.Error)"
    }
    Write-Audit -Event 'SkipListSaved' -Details "tech=$Technology count=$($data.Rules.Count)"
    return $path
}

function Import-StigSkipList {
    param([string]$Technology)
    $path = Join-Path $global:SkipListRoot "$Technology.json"
    if (-not (Test-Path $path)) { return @() }
    try {
        $j = Get-Content $path -Raw | ConvertFrom-Json
        $global:SkipLists[$Technology] = @($j.Rules)
        return $global:SkipLists[$Technology]
    } catch {
        return @()
    }
}

# Per-rule metadata persistence (NA justification, finding details,
# analyst comments, severity override). Separate file per technology,
# saved alongside the skip-list. Required by DISA for valid CKL exports.
function Export-StigRuleMetadata {
    param([string]$Technology)
    $path = Join-Path $global:SkipListRoot "${Technology}_metadata.json"
    $rows = @()
    foreach ($k in $global:RuleMetadata.Keys) {
        if ($k -like "${Technology}|*") {
            $vid = ($k -split '\|', 2)[1]
            $m   = $global:RuleMetadata[$k]
            $rows += [ordered]@{
                VulnID                = $vid
                NAJustification       = $m.NAJustification
                FindingDetails        = $m.FindingDetails
                Comments              = $m.Comments
                SeverityOverride      = $m.SeverityOverride
                SeverityJustification = $m.SeverityJustification
            }
        }
    }
    $data = @{
        Technology = $Technology
        SavedAt    = (Get-Date).ToString('o')
        SavedBy    = $global:Operator
        Rules      = $rows
    }
    $res = Set-StigJsonAtomic -Path $path -InputObject $data -Depth 5
    if (-not $res.Ok) {
        Write-Audit -Event 'RuleMetadataSaveFailed' -Details "tech=$Technology err=$($res.Error)"
        throw "Rule metadata save failed for $Technology : $($res.Error)"
    }
    Write-Audit -Event 'RuleMetadataSaved' -Details "tech=$Technology count=$($rows.Count)"
    return $path
}

function Import-StigRuleMetadata {
    param([string]$Technology)
    $path = Join-Path $global:SkipListRoot "${Technology}_metadata.json"
    if (-not (Test-Path $path)) { return 0 }
    $loaded = 0
    try {
        $j = Get-Content $path -Raw | ConvertFrom-Json
        foreach ($row in @($j.Rules)) {
            if (-not $row.VulnID) { continue }
            $key = "$Technology|$($row.VulnID)"
            $global:RuleMetadata[$key] = @{
                NAJustification       = [string]$row.NAJustification
                FindingDetails        = [string]$row.FindingDetails
                Comments              = [string]$row.Comments
                SeverityOverride      = [string]$row.SeverityOverride
                SeverityJustification = [string]$row.SeverityJustification
            }
            $loaded++
        }
    } catch {}
    return $loaded
}

# Small helper for fetching/creating a metadata entry on demand.
function Get-RuleMetadata {
    param([string]$Technology, [string]$VulnID)
    $key = "$Technology|$VulnID"
    if (-not $global:RuleMetadata.ContainsKey($key)) {
        $global:RuleMetadata[$key] = @{
            NAJustification       = ''
            FindingDetails        = ''
            Comments              = ''
            SeverityOverride      = ''
            SeverityJustification = ''
        }
    }
    return $global:RuleMetadata[$key]
}

# Atomic file write helper (added in v1.2.3). All persistence helpers in
# this script (Targets.json, SkipLists/*.json, *_metadata.json) write JSON
# that the next launch reads back at startup. A non-atomic Set-Content
# leaves a half-written file if the process is killed mid-write or two
# instances race — which silently truncates the operator's persisted
# fleet / skip-lists. Pattern: write to a sibling .tmp.<guid>, then
# replace. NTFS File.Replace is atomic; first-write fallback uses a
# rename. Errors are returned (not thrown) so callers can decide whether
# to surface a UI warning or just keep the in-memory copy.
function Set-StigJsonAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$InputObject,
        [int]$Depth = 5
    )
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {
            return @{ Ok = $false; Error = "Could not create $dir : $($_.Exception.Message)" }
        }
    }
    $tmp = "$Path.tmp.$([guid]::NewGuid().ToString('N'))"
    try {
        $json = $InputObject | ConvertTo-Json -Depth $Depth
        Set-Content -Path $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
        if (Test-Path $Path) {
            # File.Replace requires the target to exist. NTFS atomic.
            # [NullString]::Value (not $null) for the backupFileName param —
            # PS 5.1 binds bare $null to string parameters as empty string,
            # which fails File.Replace with "path not of a legal form".
            [System.IO.File]::Replace($tmp, $Path, [NullString]::Value)
        } else {
            Move-Item -Path $tmp -Destination $Path -Force -ErrorAction Stop
        }
        return @{ Ok = $true; Error = $null }
    } catch {
        # Best-effort cleanup of the temp on failure
        if (Test-Path $tmp) { try { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue } catch {} }
        return @{ Ok = $false; Error = $_.Exception.Message }
    }
}

# Persist the discovered/added Targets list to a JSON file in the workspace
# so the operator doesn't have to re-paste hostnames every launch. Saved
# fields are deliberately scalar (no SecureString creds, no live PSObject
# refs) so the file can be hand-edited or version-controlled.
function Save-StigTargets {
    if (-not $global:WorkspaceRoot) { return }
    $path = Join-Path $global:WorkspaceRoot 'Targets.json'
    $rows = @()
    foreach ($t in $global:Targets) {
        if (-not $t -or -not $t.Host) { continue }
        $rows += [ordered]@{
            Host         = [string]$t.Host
            Online       = [bool]$t.Online
            WinRM        = [bool]$t.WinRM
            OS           = [string]$t.OS
            Role         = [string]$t.Role
            Technologies = @($t.Technologies)
            Error        = [string]$t.Error
            LastScan     = [string]$t.LastScan
            ProbedAt     = [string]$t.ProbedAt
        }
    }
    $data = [ordered]@{
        SavedAt = (Get-Date).ToString('o')
        SavedBy = $global:Operator
        Targets = $rows
    }
    [void](Set-StigJsonAtomic -Path $path -InputObject $data -Depth 5)
}

function Load-StigTargets {
    if (-not $global:WorkspaceRoot) { return @() }
    $path = Join-Path $global:WorkspaceRoot 'Targets.json'
    if (-not (Test-Path $path)) { return @() }
    try {
        $j = Get-Content $path -Raw | ConvertFrom-Json
        $loaded = @()
        foreach ($row in @($j.Targets)) {
            if (-not $row.Host) { continue }
            $loaded += @{
                Host         = [string]$row.Host
                Online       = [bool]$row.Online
                WinRM        = [bool]$row.WinRM
                OS           = [string]$row.OS
                Role         = [string]$row.Role
                Technologies = @($row.Technologies)
                Error        = [string]$row.Error
                LastScan     = [string]$row.LastScan
                ProbedAt     = [string]$row.ProbedAt
            }
        }
        $global:Targets = $loaded
        return $loaded
    } catch {
        return @()
    }
}

# Bounded DNS lookup helper (added in v1.2.4). [System.Net.Dns]::GetHostEntry
# blocks the calling thread for the OS resolver default (~5s) per failure,
# which freezes the UI thread during CKL/CKLB export when any host's name
# fails to resolve. Wraps the resolve in a runspace and waits up to
# $TimeoutMs; returns empty strings on timeout. Use only in UI-thread paths
# where blocking is unacceptable.
function Resolve-StigHostBounded {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$TimeoutMs = 1000
    )
    $result = @{ Ip = ''; Fqdn = '' }
    $ps = $null
    try {
        $ps = [powershell]::Create()
        if ($global:RSPool) { $ps.RunspacePool = $global:RSPool }
        [void]$ps.AddScript({
            param($h)
            $r = @{ Ip = ''; Fqdn = '' }
            try {
                $addr = [System.Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                if ($addr) { $r.Ip = $addr.ToString() }
                $entry = [System.Net.Dns]::GetHostEntry($h)
                if ($entry) { $r.Fqdn = $entry.HostName }
            } catch {}
            return $r
        }).AddArgument($ComputerName)
        $handle = $ps.BeginInvoke()
        if ($handle.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $r = $ps.EndInvoke($handle)
            if ($r -and $r.Count -gt 0) { $result = $r[0] }
        } else {
            try { $ps.Stop() } catch {}
        }
    } catch {
    } finally {
        if ($ps) { try { $ps.Dispose() } catch {} }
    }
    return $result
}

# Fast TCP-port reachability probe. Replaces ICMP ping for AFNET, where
# ICMP is frequently blocked at the host firewall but WinRM (5985) and
# SMB (445) are open. Returns $true if EITHER port answers within the
# timeout. Pattern ported from the J.A.N.E.T. Workstation Patching Tool.
function Test-StigTcpReachable {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int[]]$Ports     = @(5985, 445),
        [int]$TimeoutMs   = 1500
    )
    foreach ($port in $Ports) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($ComputerName, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                try { $client.EndConnect($iar) } catch { continue }
                if ($client.Connected) {
                    try { $client.Close() } catch {}
                    return @{ Reachable = $true; Port = $port }
                }
            }
        } catch {
            # try next port
        } finally {
            if ($client) { try { $client.Close() } catch {} }
        }
    }
    return @{ Reachable = $false; Port = $null }
}
#endregion

#region ------------------------ CKLB IMPORT ------------------------------
# v1.3.0 - Evaluate-STIG CKLB import + AnswerFile authoring.
# All helpers in this region are pure logic (no UI, no global state writes
# except via $global:CklbImport which the form initializes before use).
# Spec: docs/superpowers/specs/2026-05-08-stig-tool-cklb-import-design.md

# ---- Import-EvaluateStigCklb ---------------------------------------------
# Parse one Evaluate-STIG .cklb file into a flat array of finding records.
# Validates the cklb_version key is present (rejects alien JSON).
# Returns: array of [pscustomobject] with fields per spec data model.
function Import-EvaluateStigCklb {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CKLB file not found: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try {
        $obj = $raw | ConvertFrom-Json
    } catch {
        throw "CKLB parse failed ($Path): $($_.Exception.Message)"
    }
    if (-not $obj.cklb_version) {
        throw "Not a CKLB file (no cklb_version key): $Path"
    }
    if (-not $obj.target_data -or -not $obj.stigs) {
        throw "CKLB missing required keys (target_data, stigs): $Path"
    }
    $assetHost = [string]$obj.target_data.host_name
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($stig in $obj.stigs) {
        $shortName = [string]$stig.stig_id
        $stigVersion = "V$($stig.version)R$([regex]::Match($stig.release_info,'Release:\s*(\d+)').Groups[1].Value)"
        foreach ($rule in $stig.rules) {
            $rec = [pscustomobject]@{
                SourceFile     = (Resolve-Path -LiteralPath $Path).Path
                AssetHost      = $assetHost
                StigShortName  = $shortName
                StigVersion    = $stigVersion
                VulnId         = [string]$rule.group_id
                RuleId         = [string]$rule.rule_id
                Severity       = [string]$rule.severity
                Status         = [string]$rule.status
                CheckText      = [string]$rule.check_content
                FixText        = [string]$rule.fix_text
                FindingDetails = [string]$rule.finding_details
                Comments       = [string]$rule.comments
                Class           = $null
                PowerStigHint   = $null
                PendingAction   = $null
                PendingJustId   = $null
                PendingHostname = $null
            }
            [void]$findings.Add($rec)
        }
    }
    # Emit each finding individually so consumers piping through Where-Object
    # iterate per-record (a leading unary-comma here would deliver the whole
    # array as a single pipeline item, breaking $_-based filtering downstream).
    return $findings.ToArray()
}


# ---- Justification Library -----------------------------------------------
# Persistent JSON store of saved justifications. Each entry has a label,
# status (NF/NA), comment text, and optional scope (StigShortNames / VulnIds).
# Empty scope arrays mean "any" — the entry is offered as a generic option.
function New-StigJustificationEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Label,
        [Parameter(Mandatory)] [ValidateSet('NF','NA')] [string] $Status,
        [Parameter(Mandatory)] [string]   $Comment,
        [string[]] $StigShortNames = @(),
        [string[]] $VulnIds        = @()
    )
    $now = (Get-Date).ToUniversalTime().ToString('o')
    return [pscustomobject]@{
        Id             = [Guid]::NewGuid().ToString()
        Label          = $Label
        Status         = $Status
        Comment        = $Comment
        AppliesTo      = [pscustomobject]@{
                            StigShortNames = @($StigShortNames)
                            VulnIds        = @($VulnIds)
                         }
        CreatedAt      = $now
        LastUsedAt     = $now
        TimesUsed      = 0
    }
}

function Get-StigJustificationLibrary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Entries = @() }
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{ Entries = @() }
    }
    $obj = $raw | ConvertFrom-Json
    if (-not $obj.Entries) {
        $obj | Add-Member -NotePropertyName Entries -NotePropertyValue @() -Force
    }
    # ConvertFrom-Json returns single-element arrays as scalars in PS 5.1.
    # Normalize Entries to always be an array.
    $obj.Entries = @($obj.Entries)
    return $obj
}

function Save-StigJustificationLibrary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Library,
        [Parameter(Mandatory)] [string] $Path
    )
    $res = Set-StigJsonAtomic -Path $Path -InputObject $Library -Depth 8
    if (-not $res.Ok) { throw "JustificationLibrary save failed: $($res.Error)" }
}

function Find-StigJustification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Library,
        [Parameter(Mandatory)] [string] $StigShortName,
        [Parameter(Mandatory)] [string] $VulnId
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Library.Entries)) {
        $matchesStig = ($e.AppliesTo.StigShortNames.Count -eq 0) -or ($e.AppliesTo.StigShortNames -contains $StigShortName)
        $matchesVuln = ($e.AppliesTo.VulnIds.Count -eq 0)        -or ($e.AppliesTo.VulnIds        -contains $VulnId)
        if ($matchesStig -and $matchesVuln) { [void]$out.Add($e) }
    }
    return ,$out.ToArray()
}


# ---- PowerStig rule-map ---------------------------------------------------
# Walk the StigData XCCDF XML tree under PowerStig and build a flat
# VulnId -> (PowerStigStig, PowerStigVersion, RuleType) map. The folder
# layout under PowerStig is StigData\<StigName>\U_*-xccdf.xml, and each
# Rule element lives under a <RuleType> tag (RegistryRule, AuditPolicyRule,
# UserRightRule, etc.) -- we capture the parent-element local name as the
# rule type.
function Build-PowerStigRuleMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StigDataRoot,
        [Parameter(Mandatory)] [string] $PowerStigVersion
    )
    $byVuln = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    if (-not (Test-Path -LiteralPath $StigDataRoot -PathType Container)) {
        # Treat missing root as empty map rather than throwing -- the caller
        # decides whether that's fatal.
        return [pscustomobject]@{
            PowerStigVersion = $PowerStigVersion
            BuiltAt          = (Get-Date).ToUniversalTime().ToString('o')
            ByVulnId         = [pscustomobject]@{}
        }
    }
    $xmlFiles = Get-ChildItem -LiteralPath $StigDataRoot -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue
    foreach ($f in $xmlFiles) {
        try {
            [xml]$doc = Get-Content -LiteralPath $f.FullName -Raw
        } catch {
            continue
        }
        if (-not $doc.DISASTIG) { continue }
        $stigName = Split-Path -Path (Split-Path -Path $f.FullName -Parent) -Leaf
        $version  = [string]$doc.DISASTIG.fullversion
        foreach ($child in $doc.DISASTIG.ChildNodes) {
            if ($child.NodeType -ne 'Element') { continue }
            $ruleType = $child.LocalName
            foreach ($rule in @($child.Rule)) {
                if (-not $rule -or -not $rule.id) { continue }
                $vid = [string]$rule.id
                $rec = [pscustomobject]@{
                    PowerStigStig    = $stigName
                    PowerStigVersion = $version
                    RuleType         = $ruleType
                }
                $byVuln[$vid] = $rec
            }
        }
    }
    # Convert dictionary to PSCustomObject for clean JSON serialization.
    $byVulnObj = New-Object pscustomobject
    foreach ($k in $byVuln.Keys) {
        $byVulnObj | Add-Member -NotePropertyName $k -NotePropertyValue $byVuln[$k] -Force
    }
    return [pscustomobject]@{
        PowerStigVersion = $PowerStigVersion
        BuiltAt          = (Get-Date).ToUniversalTime().ToString('o')
        ByVulnId         = $byVulnObj
    }
}

# ---- Get-PowerStigRuleMap (cached wrapper) -------------------------------
# v1.3.2: walking the StigData XCCDF tree on every first-import was
# multi-second on real PowerStig installs (a few hundred files times
# [xml] parse cost). Cache the map to JSON keyed by the installed
# PowerStig module version. Cache hit short-circuits the walk; cache
# miss (file absent OR version mismatch) rebuilds and persists.
#
# CachePath is required so the function stays testable without coupling
# to $global:WorkspaceRoot. UI lazy-load passes the workspace path.
function Get-PowerStigRuleMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StigDataRoot,
        [Parameter(Mandatory)] [string] $PowerStigVersion,
        [Parameter(Mandatory)] [string] $CachePath
    )
    if (Test-Path -LiteralPath $CachePath -PathType Leaf) {
        try {
            $raw = Get-Content -LiteralPath $CachePath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $cached = $raw | ConvertFrom-Json
                if ($cached.PowerStigVersion -eq $PowerStigVersion -and $cached.ByVulnId) {
                    return $cached
                }
            }
        } catch {
            # Cache file corrupt or unreadable — fall through and rebuild.
        }
    }
    $map = Build-PowerStigRuleMap -StigDataRoot $StigDataRoot -PowerStigVersion $PowerStigVersion
    # Best-effort persist. A write failure (read-only workspace, share
    # offline) does not block the caller — they still got the freshly-
    # built map back. Set-StigJsonAtomic returns @{Ok;Error}; we ignore.
    try {
        $null = Set-StigJsonAtomic -Path $CachePath -InputObject $map -Depth 6
    } catch {}
    return $map
}

# ---- Test-IsCklbApplyableTech ---------------------------------------------
# v1.3.3: PowerStig has StigData folders for Adobe / Chrome / Office /
# DotNetFramework / IISServer / SqlServer / etc. — none of which our
# Apply path supports today (New-StigDscConfigFile validates Technology
# against ^Windows(Client|Server|Firewall|Defender)$). Findings under
# those folders should NOT classify as PowerStigFixable; they fall
# through to Justifiable / Residual where the AnswerFile flow handles
# them.
function Test-IsCklbApplyableTech {
    [CmdletBinding()] [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $TechnologyName)
    return ($TechnologyName -match '^Windows(Client|Server|Firewall|Defender)$')
}

# ---- Set-FindingClassification --------------------------------------------
# Mutates $Finding in place to set Class / PowerStigHint / PendingJustId.
# Class values: PowerStigFixable | Justifiable | Residual | AlreadyClosed
function Set-FindingClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)] $RuleMap,
        [Parameter(Mandatory)] $Library
    )
    # CKLB schema reports status in CKLB-flavor strings; match case-insensitively.
    $closed = @('not_a_finding','not_applicable')
    if ($closed -contains $Finding.Status.ToLowerInvariant()) {
        $Finding.Class = 'AlreadyClosed'
        return
    }
    # PowerStig hit?
    $hit = $RuleMap.ByVulnId.PSObject.Properties[$Finding.VulnId]
    if ($hit) {
        $stigName = [string]$hit.Value.PowerStigStig
        if (Test-IsCklbApplyableTech -TechnologyName $stigName) {
            $Finding.Class         = 'PowerStigFixable'
            $Finding.PowerStigHint = $stigName
            return
        }
        # Non-applyable tech (Adobe / Chrome / Office etc.) — fall through
        # to Library / Residual classification so the AnswerFile flow
        # handles it instead of failing at apply time. PowerStigHint is
        # still populated as a useful diagnostic ("we know which PS folder
        # owns this rule, we just can't drive it via DSC today").
        $Finding.PowerStigHint = $stigName
    }
    # Library hit?
    # Use $libMatches, not $matches — $matches is PowerShell's automatic
    # variable populated by -match/-notmatch. Shadowing it here would
    # silently collide with any future regex check added to this function.
    $libMatches = Find-StigJustification -Library $Library -StigShortName $Finding.StigShortName -VulnId $Finding.VulnId
    if ($libMatches.Count -ge 1) {
        $Finding.Class = 'Justifiable'
        if ($libMatches.Count -eq 1) {
            $Finding.PendingJustId = $libMatches[0].Id
        }
        return
    }
    $Finding.Class = 'Residual'
}


# ---- Import-EvaluateStigAnswerFile ---------------------------------------
# Read an Evaluate-STIG AnswerFile XML into a lightweight model. We only
# capture the fields we'll re-emit on merge: STIG ShortName + a flat list
# of Vuln blocks with their AnswerKey/Answer attributes and validation
# fragments. Validation code (script bodies) is preserved verbatim — we
# don't try to interpret it; we just round-trip it on merge.
function Import-EvaluateStigAnswerFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path
    )
    $model = [pscustomobject]@{
        StigShortName = $null
        Vulns         = @()
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $model
    }
    [xml]$doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if (-not $doc.STIGComments) { return $model }
    $model.StigShortName = [string]$doc.STIGComments.Name
    $vulns = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($doc.STIGComments.Vuln)) {
        $ak = $v.AnswerKey | Select-Object -First 1
        $an = $ak.Answer    | Select-Object -First 1
        $vulns.Add([pscustomobject]@{
            VulnId            = [string]$v.ID
            AnswerKeyName     = [string]$ak.Name
            Index             = [string]$an.Index
            ExpectedStatus    = [string]$an.ExpectedStatus
            Hostname          = [string]$an.Hostname
            ValidationCode    = [string]$an.ValidationCode
            ValidTrueStatus   = [string]$an.ValidTrueStatus
            ValidTrueComment  = [string]$an.ValidTrueComment
            ValidFalseStatus  = [string]$an.ValidFalseStatus
            ValidFalseComment = [string]$an.ValidFalseComment
        }) | Out-Null
    }
    $model.Vulns = ,$vulns.ToArray()
    return $model
}


# ---- Export-EvaluateStigAnswerFile ---------------------------------------
# Write/merge an Evaluate-STIG AnswerFile. Each input entry is a record
# with: VulnId, ExpectedStatus (in EvalSTIG flavor: O/NR/NA/NF), Hostname,
# Status (NF or NA), Comment. We always emit the simple validation-empty
# pattern (ValidationCode blank => $true => ValidTrueStatus applies).
# Merge policy:
#   * Existing Vuln IDs we're not authoring -> preserved verbatim.
#   * Existing Vuln IDs we ARE authoring with same ExpectedStatus -> replaced.
#   * Existing Vuln IDs we ARE authoring with different ExpectedStatus
#     -> throws 'AnswerFileConflict' (caller handles in UI).
function Export-EvaluateStigAnswerFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StigShortName,
        [Parameter(Mandatory)] [array]  $Entries,
        [Parameter(Mandatory)] [string] $Path
    )
    # Read existing (if any). Empty model on first write.
    $existing = Import-EvaluateStigAnswerFile -Path $Path

    # Conflict scan up-front so partial-write is impossible.
    foreach ($e in $Entries) {
        $clash = $existing.Vulns | Where-Object { $_.VulnId -eq $e.VulnId -and $_.ExpectedStatus -ne $e.ExpectedStatus }
        if ($clash) {
            throw "AnswerFileConflict: $($e.VulnId) - existing ExpectedStatus '$($clash.ExpectedStatus)' vs new '$($e.ExpectedStatus)'."
        }
    }

    # Build merged Vuln list.
    $newVulnIds = @($Entries | ForEach-Object { $_.VulnId })
    $kept       = @($existing.Vulns | Where-Object { $newVulnIds -notcontains $_.VulnId })
    $authored   = foreach ($e in $Entries) {
        [pscustomobject]@{
            VulnId            = $e.VulnId
            AnswerKeyName     = 'DEFAULT'
            Index             = '1'
            ExpectedStatus    = $e.ExpectedStatus
            Hostname          = [string]$e.Hostname
            ValidationCode    = ''
            ValidTrueStatus   = $e.Status
            ValidTrueComment  = $e.Comment
            ValidFalseStatus  = ''
            ValidFalseComment = ''
        }
    }
    $merged = @($kept + $authored)

    # Build XML. Use [xml] builder rather than string concat to avoid
    # encoding/escaping bugs with comments containing < > & quotes.
    $xml = New-Object System.Xml.XmlDocument
    [void]$xml.AppendChild($xml.CreateXmlDeclaration('1.0','utf-8',$null))
    $rootNode = $xml.CreateElement('STIGComments')
    $rootNode.SetAttribute('Name', $StigShortName)
    [void]$xml.AppendChild($rootNode)
    foreach ($v in $merged) {
        $vNode = $xml.CreateElement('Vuln')
        $vNode.SetAttribute('ID', $v.VulnId)
        $akNode = $xml.CreateElement('AnswerKey')
        $akNode.SetAttribute('Name', $v.AnswerKeyName)
        $aNode = $xml.CreateElement('Answer')
        $aNode.SetAttribute('Index',          $v.Index)
        $aNode.SetAttribute('ExpectedStatus', $v.ExpectedStatus)
        $aNode.SetAttribute('Hostname',       [string]$v.Hostname)
        $aNode.SetAttribute('Instance', '')
        $aNode.SetAttribute('Database', '')
        $aNode.SetAttribute('Site',     '')
        $aNode.SetAttribute('ResultHash','')
        foreach ($pair in @(
            @{Name='ValidationCode';    Text=$v.ValidationCode},
            @{Name='ValidTrueStatus';   Text=$v.ValidTrueStatus},
            @{Name='ValidTrueComment';  Text=$v.ValidTrueComment},
            @{Name='ValidFalseStatus';  Text=$v.ValidFalseStatus},
            @{Name='ValidFalseComment'; Text=$v.ValidFalseComment}
        )) {
            $child = $xml.CreateElement($pair.Name)
            $child.InnerText = [string]$pair.Text
            [void]$aNode.AppendChild($child)
        }
        [void]$akNode.AppendChild($aNode)
        [void]$vNode.AppendChild($akNode)
        [void]$rootNode.AppendChild($vNode)
    }

    # Atomic write - write to .tmp, replace.
    $dir  = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $tmp  = "$Path.tmp"
    $sw   = New-Object System.IO.StreamWriter($tmp, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $xml.Save($sw)
    } finally {
        $sw.Dispose()
    }
    if (Test-Path -LiteralPath $Path) {
        # PS 5.1 binds plain $null to a string parameter as empty string,
        # which File.Replace rejects as "not of a legal form" - use the
        # typed null sentinel to skip the backup.
        [System.IO.File]::Replace($tmp, $Path, [NullString]::Value)
    } else {
        Move-Item -LiteralPath $tmp -Destination $Path
    }
}


# ---- PowerStig SkipRule inversion ----------------------------------------
# PowerStig DSC configs accept a -SkipRule list. To apply ONLY the rules
# our CKLB flagged Open + PowerStig-fixable, we tell PowerStig to skip
# every OTHER rule. ConvertTo-PowerStigSkipRuleList is the inversion.
function ConvertTo-PowerStigSkipRuleList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $StigVulnIds,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $MatchedVulnIds
    )
    $matchedSet = @{}
    foreach ($id in $MatchedVulnIds) { $matchedSet[$id] = $true }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($id in $StigVulnIds) {
        if (-not $matchedSet.ContainsKey($id)) { [void]$out.Add($id) }
    }
    return ,$out.ToArray()
}

# Below this matched-fraction threshold we use surgical SkipRule inversion;
# at or above we fall back to a full apply because the SkipRule list would
# be longer than the apply list and the surgical approach loses its point.
function Test-FullApplyThreshold {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int] $StigVulnCount,
        [Parameter(Mandatory)] [int] $MatchedCount
    )
    if ($StigVulnCount -le 0) { return $false }
    return ([double]$MatchedCount / [double]$StigVulnCount) -ge 0.8
}

# ---- Invoke-StigApplyFromCklb --------------------------------------------
# Integration glue between classified findings and the existing Apply
# pipeline. Wired to the real pipeline in v1.3.1 via the new top-level
# helper Invoke-StigPipelineForHost (POWERSTIG ENGINE region), which
# factors the per-host New-StigDscConfigFile -> Invoke-StigCompile ->
# (Invoke-StigEvaluation | Invoke-StigApply) sequence out of the
# Apply-tab UI handler.
#
# Per-host inputs: AssetHost + PowerStigHint pair from the Findings
# group; OS caption + Role looked up in $global:Targets; SkipRule list
# computed from ConvertTo-PowerStigSkipRuleList (or empty when
# Test-FullApplyThreshold says the matched fraction is high enough that
# a full apply is cheaper than a long inverted skip list).
function Invoke-StigApplyFromCklb {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array] $Findings,
        [Parameter(Mandatory)] [ValidateSet('Local','Remote')] [string] $Mode,
        [Parameter(Mandatory)] $RuleMap,
        [System.Management.Automation.PSCredential] $Credential
    )
    $applyTargets = @($Findings | Where-Object { $_.Class -eq 'PowerStigFixable' -and $_.PendingAction -eq 'Apply' })
    if ($applyTargets.Count -eq 0) {
        if (Get-Command Write-StigScanLog -ErrorAction SilentlyContinue) {
            Write-StigScanLog 'CklbApply: nothing to apply.' 'INFO'
        }
        return @()
    }

    $groups  = $applyTargets | Group-Object AssetHost, PowerStigHint
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($g in $groups) {
        $assetHost = $g.Group[0].AssetHost
        $stigName  = $g.Group[0].PowerStigHint

        # Look up host in the Targets list to get OS caption + Role.
        # Without these, OsVersion/OsRole detection won't work and the
        # generated DSC config will be wrong.
        $target = @($global:Targets | Where-Object { $_.Host -eq $assetHost }) | Select-Object -First 1
        if (-not $target) {
            $msg = "host '$assetHost' is not in the Targets list. Add it via the Targets tab (and run Test Reachability so the OS detect populates) before applying CKLB-driven fixes."
            if (Get-Command Write-StigScanLog -ErrorAction SilentlyContinue) {
                Write-StigScanLog "CklbApply: $msg" 'ERR'
            }
            $results.Add([pscustomobject]@{
                AssetHost    = $assetHost
                Stig         = $stigName
                MatchedCount = $g.Count
                Mode         = 'skipped'
                Result       = $null
                Error        = $msg
            }) | Out-Null
            # v1.3.3 I-B: roll back PendingAction so these rows reappear
            # in the residual worklist instead of silently leaking out
            # (Export-CklbResidualWorklist excludes PowerStigFixable rows
            # with non-null PendingAction).
            foreach ($f in $g.Group) {
                if ($f.PendingAction -eq 'Apply') { $f.PendingAction = $null }
            }
            continue
        }

        # Compute the surgical SkipRule list (every VulnId in the STIG
        # that's NOT in our matched-Open set) OR fall back to a full
        # apply when the matched fraction crosses the threshold.
        $matched   = @($g.Group | ForEach-Object VulnId | Sort-Object -Unique)
        $allInStig = @($RuleMap.ByVulnId.PSObject.Properties |
                          Where-Object { $_.Value.PowerStigStig -eq $stigName } |
                          ForEach-Object Name)
        $useFull   = Test-FullApplyThreshold -StigVulnCount $allInStig.Count -MatchedCount $matched.Count
        $skipRules = if ($useFull) { @() } else { ConvertTo-PowerStigSkipRuleList -StigVulnIds $allInStig -MatchedVulnIds $matched }

        if (Get-Command Write-StigScanLog -ErrorAction SilentlyContinue) {
            Write-StigScanLog ("CklbApply: host={0} stig={1} matched={2}/{3} mode={4}" -f $assetHost, $stigName, $matched.Count, $allInStig.Count, $(if($useFull){'full'}else{'surgical'})) 'STEP'
        }

        $modeStr = if ($useFull) { 'full' } else { 'surgical' }
        try {
            $r = Invoke-StigPipelineForHost `
                    -ComputerName $assetHost `
                    -Technology   $stigName `
                    -OsCaption    ([string]$target.OS) `
                    -Role         ([string]$target.Role) `
                    -SkipRule     $skipRules `
                    -Mode         $Mode `
                    -Credential   $Credential `
                    -DryRun       $false

            $results.Add([pscustomobject]@{
                AssetHost    = $assetHost
                Stig         = $stigName
                MatchedCount = $matched.Count
                Mode         = $modeStr
                Result       = $r
                Error        = $r.Error
            }) | Out-Null

            if ($r.Success) {
                foreach ($f in $g.Group) { $f.PendingAction = 'Applied' }
                if (Get-Command Write-JanetAction -ErrorAction SilentlyContinue) {
                    try {
                        Write-JanetAction -Action 'VulnPatched' -Target $assetHost -Result 'Success' -ItemCount $matched.Count -Detail "tech=$stigName cklb-driven mode=$modeStr"
                    } catch {}
                }
            }
            else {
                # On failure, leave PendingAction='Apply' so the operator sees
                # the rows didn't go through and can retry / look at the log.
                if (Get-Command Write-JanetAction -ErrorAction SilentlyContinue) {
                    try {
                        Write-JanetAction -Action 'VulnPatched' -Target $assetHost -Result 'Failure' -ItemCount $matched.Count -Detail "tech=$stigName cklb-driven mode=$modeStr err=$($r.Error)"
                    } catch {}
                }
            }
        } catch {
            if (Get-Command Write-StigScanLog -ErrorAction SilentlyContinue) {
                Write-StigScanLog "CklbApply pipeline-throw: $assetHost / $stigName : $($_.Exception.Message)" 'ERR'
            }
            $results.Add([pscustomobject]@{
                AssetHost    = $assetHost
                Stig         = $stigName
                MatchedCount = $matched.Count
                Mode         = $modeStr
                Result       = $null
                Error        = $_.Exception.Message
            }) | Out-Null
            if (Get-Command Write-JanetAction -ErrorAction SilentlyContinue) {
                try {
                    Write-JanetAction -Action 'VulnPatched' -Target $assetHost -Result 'Failure' -ItemCount $matched.Count -Detail "tech=$stigName cklb-driven mode=$modeStr err=$($_.Exception.Message)"
                } catch {}
            }
            # v1.3.3 I-B: pipeline threw before producing a result —
            # roll back PendingAction so these rows reappear in the
            # residual worklist. (The success-but-failed branch above
            # intentionally leaves PendingAction='Apply' per the
            # v1.3.0-final-review C-2 behavior, where the operator DOES
            # know about the failure and the stamped state is
            # informative.)
            foreach ($f in $g.Group) {
                if ($f.PendingAction -eq 'Apply') { $f.PendingAction = $null }
            }
        }
    }

    return ,$results.ToArray()
}

# ---- Export-CklbResidualWorklist -----------------------------------------
# XLSX export of findings still needing manual attention. "Residual" =
# findings the tool did not fix (PowerStig couldn't) and did not justify
# (no library entry, no operator action). Sheet 'Residual' with one row
# per finding sorted by Severity desc, then Host, then VulnId.
function Export-CklbResidualWorklist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array]  $Findings,
        [Parameter(Mandatory)] [string] $Path
    )
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        throw 'ImportExcel module not installed - cannot export residual worklist.'
    }
    Import-Module ImportExcel -ErrorAction Stop

    $sevRank = @{ 'high'=0; 'medium'=1; 'low'=2 }
    $rows = $Findings |
        Where-Object { $_.Class -eq 'Residual' -or ($_.Class -eq 'Justifiable' -and -not $_.PendingAction) -or ($_.Class -eq 'PowerStigFixable' -and -not $_.PendingAction) } |
        Sort-Object @{Expression={ $sevRank[$_.Severity] }}, AssetHost, VulnId |
        ForEach-Object {
            [pscustomobject]@{
                Host       = $_.AssetHost
                STIG       = $_.StigShortName
                VulnId     = $_.VulnId
                RuleId     = $_.RuleId
                Severity   = $_.Severity
                Class      = $_.Class
                Status     = $_.Status
                Check      = $_.CheckText
                Fix        = $_.FixText
                Observed   = $_.FindingDetails
            }
        }

    if ($rows.Count -eq 0) {
        # Still write an empty sheet so downstream tooling can rely on the file existing.
        $rows = ,([pscustomobject]@{ Host=''; STIG=''; VulnId=''; RuleId=''; Severity=''; Class='(no residual findings)'; Status=''; Check=''; Fix=''; Observed='' })
    }

    $rows | Export-Excel -Path $Path -WorksheetName 'Residual' -AutoSize -FreezeTopRow -BoldTopRow -ClearSheet
}

# ---- Write-CklbAuditEvent ------------------------------------------------
# Routes the four CKLB-import event types to the right log surface.
#
# v1.3.3: the v1.3.0 implementation called Write-JanetMetric which does
# not exist in this tool — every event was a silent no-op. Now:
#   * CklbApply -> Write-JanetAction (per-host VulnPatched fleet-rollup)
#                  via the per-host call in Invoke-StigApplyFromCklb;
#                  this wrapper just tees a session-level note.
#   * CklbImport / AnswerFileWrite / CklbResidualExport -> Write-Audit
#                  (session-level audit log, the right home for non-
#                  per-host operator actions).
# Always tees to Write-StigScanLog for live observability.
function Write-CklbAuditEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('CklbImport','CklbApply','AnswerFileWrite','CklbResidualExport')] [string] $Event,
        [Parameter(Mandatory)] [ValidateSet('Success','Failure','Skipped')]                                  [string] $Status,
        [int]    $ItemCount = 0,
        [string] $Details   = ''
    )
    if (Get-Command Write-Audit -ErrorAction SilentlyContinue) {
        try {
            $detailsLine = "$Event $Status n=$ItemCount $Details"
            Write-Audit -Event $Event -Details $detailsLine
        } catch {
            # Best-effort: a logging failure never blocks the operator.
        }
    }
    if (Get-Command Write-StigScanLog -ErrorAction SilentlyContinue) {
        Write-StigScanLog ("$Event $Status (n=$ItemCount) $Details") 'INFO'
    }
}

# ---- Show-StigMarkAnswerDialog -------------------------------------------
# Modal dialog for marking selected findings NF/NA against the
# JustificationLibrary. Returns a hashtable result; Cancelled=$true if the
# operator cancels or leaves the comment empty.
#
# Top-level function — does NOT use the Start-StigTool-local theme
# helpers ($StyleBtn etc.) because those are scoped inside Start-StigTool's
# closure. Themes are applied directly via the $global:clr* palette.
function Show-StigMarkAnswerDialog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array] $Findings,    # selection (>=1)
        [Parameter(Mandatory)] $Library
    )
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $first   = $Findings[0]
    # Use $libMatches, not $matches — $matches is PowerShell's automatic
    # variable populated by -match/-notmatch. Same shadowing fix the
    # v1.3.0-final-review applied to Set-FindingClassification.
    $libMatches = Find-StigJustification -Library $Library -StigShortName $first.StigShortName -VulnId $first.VulnId

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = ("Mark NF/NA — {0} finding(s) selected" -f $Findings.Count)
    $dlg.Size = New-Object System.Drawing.Size(600, 470)
    $dlg.StartPosition    = 'CenterParent'
    $dlg.FormBorderStyle  = 'FixedDialog'
    $dlg.MaximizeBox      = $false
    $dlg.MinimizeBox      = $false
    $dlg.BackColor        = $global:clrBG
    $dlg.ForeColor        = $global:clrWhite
    $dlg.Font             = (New-Object System.Drawing.Font('Segoe UI', 9))

    $lblPick      = New-Object System.Windows.Forms.Label
    $lblPick.Text = 'Pick saved justification (or write a new one):'
    $lblPick.SetBounds(15, 12, 540, 18)
    $lblPick.ForeColor = $global:clrDim

    $cmbPick = New-Object System.Windows.Forms.ComboBox
    $cmbPick.DropDownStyle = 'DropDownList'
    $cmbPick.SetBounds(15, 32, 540, 24)
    [void]$cmbPick.Items.Add('-- new justification --')
    foreach ($e in $libMatches) { [void]$cmbPick.Items.Add(("[{0}] {1}" -f $e.Status, $e.Label)) }
    $cmbPick.SelectedIndex = 0

    $rbNF = New-Object System.Windows.Forms.RadioButton
    $rbNF.Text = 'Not a Finding (NF)'
    $rbNF.SetBounds(15, 70, 220, 22)
    $rbNF.Checked = $true
    $rbNF.ForeColor = $global:clrWhite

    $rbNA = New-Object System.Windows.Forms.RadioButton
    $rbNA.Text = 'Not Applicable (NA)'
    $rbNA.SetBounds(245, 70, 220, 22)
    $rbNA.ForeColor = $global:clrWhite

    $lblComment      = New-Object System.Windows.Forms.Label
    $lblComment.Text = 'Justification text (required):'
    $lblComment.SetBounds(15, 100, 540, 18)
    $lblComment.ForeColor = $global:clrDim

    $txtComment = New-Object System.Windows.Forms.TextBox
    $txtComment.Multiline  = $true
    $txtComment.SetBounds(15, 120, 540, 110)
    $txtComment.ScrollBars = 'Vertical'
    $txtComment.BackColor  = $global:clrInputBG
    $txtComment.ForeColor  = $global:clrWhite

    $chkPerHost      = New-Object System.Windows.Forms.CheckBox
    $chkPerHost.Text = ("Scope to this host only ({0})" -f $first.AssetHost)
    $chkPerHost.SetBounds(15, 240, 540, 22)
    $chkPerHost.ForeColor = $global:clrWhite

    $chkSave      = New-Object System.Windows.Forms.CheckBox
    $chkSave.Text = 'Save to Justification Library for reuse'
    $chkSave.SetBounds(15, 268, 360, 22)
    $chkSave.ForeColor = $global:clrWhite

    $lblLabel      = New-Object System.Windows.Forms.Label
    $lblLabel.Text = 'Library label:'
    $lblLabel.SetBounds(15, 296, 100, 22)
    $lblLabel.ForeColor = $global:clrDim

    $txtLabel = New-Object System.Windows.Forms.TextBox
    $txtLabel.SetBounds(120, 294, 435, 22)
    $txtLabel.BackColor  = $global:clrInputBG
    $txtLabel.ForeColor  = $global:clrWhite

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text         = 'OK'
    $btnOK.SetBounds(370, 380, 90, 30)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnOK.BackColor    = $global:clrPurple
    $btnOK.ForeColor    = $global:clrWhite
    $btnOK.FlatStyle    = 'Flat'

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text         = 'Cancel'
    $btnCancel.SetBounds(465, 380, 90, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $btnCancel.BackColor    = $global:clrOrange
    $btnCancel.ForeColor    = $global:clrWhite
    $btnCancel.FlatStyle    = 'Flat'

    # Picking an existing entry populates the fields.
    $cmbPick.Add_SelectedIndexChanged({
        if ($cmbPick.SelectedIndex -le 0) { return }
        $sel = $libMatches[$cmbPick.SelectedIndex - 1]
        $txtComment.Text = $sel.Comment
        if ($sel.Status -eq 'NA') { $rbNA.Checked = $true } else { $rbNF.Checked = $true }
        $chkSave.Checked = $false
    }.GetNewClosure())

    $dlg.Controls.AddRange(@(
        $lblPick, $cmbPick, $rbNF, $rbNA,
        $lblComment, $txtComment,
        $chkPerHost, $chkSave, $lblLabel, $txtLabel,
        $btnOK, $btnCancel
    ))
    $dlg.AcceptButton = $btnOK
    $dlg.CancelButton = $btnCancel

    $r = $dlg.ShowDialog()
    if ($r -ne [System.Windows.Forms.DialogResult]::OK) {
        return @{ Cancelled = $true }
    }
    if ([string]::IsNullOrWhiteSpace($txtComment.Text)) {
        [System.Windows.Forms.MessageBox]::Show('Justification text is required.','Missing comment','OK','Warning') | Out-Null
        return @{ Cancelled = $true }
    }
    # I-3 fix: previously a SaveAsNew checkbox + empty Label would silently
    # no-op (the caller's $r.SaveAsNew && $r.Label guard fell through), so
    # operators believed they had saved a reusable justification when they
    # hadn't. Reject empty labels at dialog dismissal instead.
    if ($chkSave.Checked -and [string]::IsNullOrWhiteSpace($txtLabel.Text)) {
        [System.Windows.Forms.MessageBox]::Show('Library label is required when "Save to Justification Library" is checked.','Missing label','OK','Warning') | Out-Null
        return @{ Cancelled = $true }
    }
    return @{
        Cancelled = $false
        Status    = $(if ($rbNA.Checked) { 'NA' } else { 'NF' })
        Comment   = $txtComment.Text.Trim()
        Hostname  = $(if ($chkPerHost.Checked) { $first.AssetHost } else { '' })
        SaveAsNew = $chkSave.Checked
        Label     = $txtLabel.Text.Trim()
        PickedId  = $(if ($cmbPick.SelectedIndex -gt 0) { $libMatches[$cmbPick.SelectedIndex - 1].Id } else { $null })
    }
}

# ---- Update-StigFindingClassifications -----------------------------------
# Re-runs Set-FindingClassification across all current findings. Called
# after a Library update or after the operator marks rows so the grid
# reflects new state without re-importing the CKLBs.
function Update-StigFindingClassifications {
    [CmdletBinding()] param()
    if (-not $global:CklbImport -or -not $global:CklbImport.Findings) { return }
    foreach ($f in $global:CklbImport.Findings) {
        # Preserve PendingAction/PendingJustId across re-classification.
        $prevAction = $f.PendingAction
        $prevJust   = $f.PendingJustId
        $f.Class = $null; $f.PowerStigHint = $null; $f.PendingJustId = $null
        Set-FindingClassification -Finding $f -RuleMap $global:CklbImport.PowerStigRuleMap -Library $global:CklbImport.JustificationLib
        if ($prevAction) { $f.PendingAction = $prevAction }
        if ($prevJust -and -not $f.PendingJustId) { $f.PendingJustId = $prevJust }
    }
}

#endregion ----------------------- CKLB IMPORT -----------------------------

#region ------------------------ GUI: THEME + SHELL -----------------------
function BuildAppForm {
    # Palette is defined at SCRIPT LOAD (top of file) so $global:clrXxx vars
    # are guaranteed non-null in any event handler, regardless of execution
    # context transitions (Get-Credential modal, runspace join, etc.).
    # See the palette block near the top of this file.

    # Resolve the first available font family from a comma-separated list,
    # fallback to Microsoft Sans Serif if none are installed. System.Drawing.Font's
    # constructor treats commas as part of the family name (no built-in fallback),
    # so we have to pick manually against InstalledFontCollection.
    if (-not $global:InstalledFontNames) {
        try {
            $ifc = New-Object System.Drawing.Text.InstalledFontCollection
            $global:InstalledFontNames = @($ifc.Families | ForEach-Object { $_.Name })
        } catch {
            $global:InstalledFontNames = @()
        }
    }
    $MkFont = {
        param([string]$FamilyCsv, [double]$Size, [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular)
        $fam = 'Microsoft Sans Serif'
        foreach ($candidate in ($FamilyCsv -split ',\s*')) {
            if ($global:InstalledFontNames -contains $candidate) { $fam = $candidate; break }
        }
        New-Object System.Drawing.Font($fam, $Size, $Style)
    }

    # Fonts — Cascadia Mono for display, titles, nav, buttons,
    # group headers, data rows. Segoe UI (Variable Display on Win11) for body
    # copy. Same variable names as before so tab code works unchanged.
    $global:DefaultFont  = & $MkFont 'Segoe UI Variable Display, Segoe UI' 9.5
    $fontSmall           = & $MkFont 'Segoe UI Variable Display, Segoe UI' 9
    $fontSmallBold       = & $MkFont 'Cascadia Mono, Consolas' 8 Bold
    $fontMono            = & $MkFont 'Cascadia Mono, Consolas' 10
    $fontBigBtn          = & $MkFont 'Cascadia Mono, Consolas' 10 Bold
    $fontGroupHeader     = & $MkFont 'Cascadia Mono, Consolas' 9 Bold
    $fontDanger          = & $MkFont 'Cascadia Mono, Consolas' 12 Bold
    $fontTitle           = & $MkFont 'Cascadia Mono, Consolas' 18 Bold
    $fontSubtitle        = & $MkFont 'Segoe UI Variable Display, Segoe UI' 9 Italic
    $fontNav             = & $MkFont 'Cascadia Mono, Consolas' 9 Bold
    $fontEyebrow         = & $MkFont 'Cascadia Mono, Consolas' 8 Bold

    $tooltip = New-Object System.Windows.Forms.ToolTip
    $tooltip.BackColor    = [System.Drawing.Color]::FromArgb(30, 30, 45)
    $tooltip.ForeColor    = [System.Drawing.Color]::White
    $tooltip.AutoPopDelay = 10000
    $tooltip.InitialDelay = 400

    # Flat button: colored background, no border, hover lighter.
    # $bg is the button's identity color. Text color is chosen for contrast --
    # bright backgrounds get near-black text, dark backgrounds get
    # warm white. Font is Cascadia Mono Bold.
    $StyleBtn = {
        param($btn, $bg, $tip = '')
        $btn.BackColor = $bg
        # Bright backgrounds (gold, green, caution) need dark text for legibility.
        # Use perceptual brightness: R*299 + G*587 + B*114 > ~128000 = bright
        $brightness = ($bg.R * 299) + ($bg.G * 587) + ($bg.B * 114)
        $btn.ForeColor = if ($brightness -gt 128000) { $global:clrTextOnAmber } else { $global:clrWhite }
        $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $btn.FlatAppearance.BorderSize = 0
        # Hover: lighten by 28 (matches WPT's New-WptButton hover delta)
        $rh = [Math]::Min(255, [int]$bg.R + 28)
        $gh = [Math]::Min(255, [int]$bg.G + 28)
        $bh = [Math]::Min(255, [int]$bg.B + 28)
        $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($rh, $gh, $bh)
        # Press: darken by 20 (distinct from hover — gives tactile "push" feel)
        $rd = [Math]::Max(0, [int]$bg.R - 20)
        $gd = [Math]::Max(0, [int]$bg.G - 20)
        $bd = [Math]::Max(0, [int]$bg.B - 20)
        $btn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb($rd, $gd, $bd)
        $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btn.Font   = $fontGroupHeader
        $btn.UseVisualStyleBackColor = $false
        if ($tip) { $tooltip.SetToolTip($btn, $tip) }
    }
    # JANET-style flat card: GroupBox with subtle clrBorder border line,
    # and a separately-rendered title label in the accent color that overlaps
    # the top border. Keeps GroupBox layout (children still start at y~18)
    # but looks like a modern flat card instead of a thick-bordered 3D box.
    $MakeGB = {
        param($txt, $x, $y, $w, $h, $col = $global:clrCyan)
        $gb = New-Object System.Windows.Forms.GroupBox
        $gb.Text     = ''   # suppress GroupBox's own title — we overlay our own
        $gb.Location = New-Object System.Drawing.Point($x, $y)
        $gb.Size     = New-Object System.Drawing.Size($w, $h)
        $gb.ForeColor= $global:clrBorder   # subtle 1px border line
        $gb.BackColor= $global:clrPanel
        $gb.Font     = $fontGroupHeader
        # Accent-colored title label that covers the border behind it
        $titleLbl = New-Object System.Windows.Forms.Label
        $titleLbl.Text      = "  $txt  "
        $titleLbl.Font      = $fontGroupHeader
        $titleLbl.ForeColor = $col
        $titleLbl.BackColor = $global:clrPanel   # matches GB bg to punch through border
        $titleLbl.AutoSize  = $true
        $titleLbl.Location  = New-Object System.Drawing.Point(8, 0)
        $gb.Controls.Add($titleLbl)
        return $gb
    }
    $MakeLbl = {
        param($txt, $x, $y, $w = 160, $col = $global:clrDim)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $txt; $l.ForeColor = $col; $l.Font = $fontSmall
        $l.AutoSize = $false
        $l.Size = New-Object System.Drawing.Size($w, 18)
        $l.Location = New-Object System.Drawing.Point($x, $y)
        return $l
    }
    $MakeVal = {
        param($x, $y, $w = 450, $col = $global:clrWhite)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = ''; $l.ForeColor = $col; $l.Font = $fontSmall
        $l.AutoSize = $false
        $l.Size = New-Object System.Drawing.Size($w, 18)
        $l.Location = New-Object System.Drawing.Point($x, $y)
        return $l
    }
    # DataGridView theming. Matches WPT's grid treatment: dark
    # background, purple-on-near-black column headers in Cascadia Mono Bold,
    # purple selection highlight with dark text, horizontal cell borders
    # only (no vertical separators — easier on the eyes for dense data).
    $StyleGrid = {
        param($g)
        $g.BackgroundColor                   = $global:clrPanel
        $g.GridColor                         = $global:clrBorder
        $g.BorderStyle                       = 'None'
        $g.CellBorderStyle                   = 'SingleHorizontal'
        $g.EnableHeadersVisualStyles         = $false
        $g.RowHeadersVisible                 = $false
        $g.AllowUserToAddRows                = $false
        $g.AllowUserToDeleteRows             = $false
        $g.AllowUserToResizeRows             = $false
        $g.SelectionMode                     = 'FullRowSelect'
        $g.AutoSizeColumnsMode               = 'Fill'
        $g.ColumnHeadersHeight               = 30
        $g.ColumnHeadersHeightSizeMode       = 'DisableResizing'
        $g.RowTemplate.Height                = 26
        # Column headers: deepest-black bg, purple Cascadia Mono text
        $g.ColumnHeadersDefaultCellStyle.BackColor  = $global:clrHeaderBg
        $g.ColumnHeadersDefaultCellStyle.ForeColor  = $global:clrCyan     # purple accent
        $g.ColumnHeadersDefaultCellStyle.Font       = $fontGroupHeader    # Cascadia Mono Bold
        $g.ColumnHeadersDefaultCellStyle.Alignment  = 'MiddleLeft'
        # Default row: dark bg, warm-white text, Segoe UI body
        $g.DefaultCellStyle.BackColor                = $global:clrPanel
        $g.DefaultCellStyle.ForeColor                = $global:clrWhite
        $g.DefaultCellStyle.SelectionBackColor       = $global:clrCyan    # purple selection
        $g.DefaultCellStyle.SelectionForeColor       = $global:clrTextOnAmber  # dark on accent
        $g.DefaultCellStyle.Font                     = $fontSmall
        # Alternating row: very subtle lift
        $g.AlternatingRowsDefaultCellStyle.BackColor = $global:clrRowAlt
        $g.AlternatingRowsDefaultCellStyle.ForeColor = $global:clrWhite
        $g.AlternatingRowsDefaultCellStyle.SelectionBackColor = $global:clrCyan
        $g.AlternatingRowsDefaultCellStyle.SelectionForeColor = $global:clrTextOnAmber
    }

    # CKLB Import state container — populated by the CKLB Import tab's
    # + Add CKLB... handler. Justification library and PowerStig rule map
    # are loaded lazily on first Add (cheap per-launch cost amortized over
    # the session — most operators only import once).
    $global:CklbImport = [ordered]@{
        SourceFiles      = @()
        Findings         = @()
        JustificationLib = $null   # loaded lazily on first Add-CKLB
        PowerStigRuleMap = $null   # built lazily on first Add-CKLB
        JustLibPath      = $null   # set after first load
    }

    # -------- BASE FORM --------
    # v1.2.11: bumped ClientSize 1360x800 -> 1600x900 and launches
    # Maximized so STIG rule titles + grid columns get the horizontal
    # space they need without operator window-juggling. MinimumSize
    # 1366x800 = the smallest practical AFNET laptop screen; below that
    # the grids start clipping headers. AutoScaleMode=Dpi pairs with
    # Set-WptDpiAware (already called at script load) so WinForms
    # relays against the monitor's real DPI instead of being
    # bitmap-stretched at 125%/150% scaling.
    $AppForm = New-Object System.Windows.Forms.Form
    $AppForm.ClientSize         = New-Object System.Drawing.Size(1600, 900)
    $AppForm.MinimumSize        = New-Object System.Drawing.Size(1366, 800)
    $AppForm.WindowState        = [System.Windows.Forms.FormWindowState]::Maximized
    $AppForm.Text               = "J.A.N.E.T. STIG Tool $global:ToolVersion"
    $AppForm.BackColor          = $global:clrBG
    $AppForm.ForeColor          = $global:clrWhite
    $AppForm.Font               = $global:DefaultFont
    $AppForm.StartPosition      = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $AppForm.FormBorderStyle    = [System.Windows.Forms.FormBorderStyle]::Sizable
    $AppForm.MaximizeBox        = $true
    $AppForm.AutoScaleMode      = [System.Windows.Forms.AutoScaleMode]::Dpi
    $AppForm.AutoScaleDimensions= New-Object System.Drawing.SizeF(96.0, 96.0)
    Enable-WptDoubleBuffer -Control $AppForm

    $global:WPT.UI.Form = $AppForm

    # X-block removed in v1.2.9: the X chrome button, Alt-F4, and the
    # Close Tool button all close the form normally now. The only remaining
    # guard is the Apply-in-progress confirmation — closing during a real
    # DSC apply still prompts before letting LCM enter PendingConfiguration.
    # Set-/Get-JanetAllowClose are kept as no-op stubs so the Close Tool
    # button click still compiles. The intent of "single-egress" was to
    # prevent accidental closes; in practice it just made the tool feel
    # broken when the Close Tool button itself was invisible (v1.2.8 fix
    # made the button render correctly, but operators still want X to work).
    $AppForm.Add_FormClosing({
        param($sender, $e)

        if ($global:ApplyInProgress) {
            $resp = [System.Windows.Forms.MessageBox]::Show(
                "An Apply is currently running. Closing now will leave DSC in a half-applied state on any in-flight host (LCM PendingConfiguration). Close anyway?",
                'Apply in progress',
                'YesNo','Warning'
            )
            if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) {
                $e.Cancel = $true
                return
            }
            try { Write-Audit -Event 'ToolCloseDuringApply' -Details "operator=$($global:Operator)" } catch {}
        }
        try { Write-Audit -Event 'ToolClose' -Details "operator=$($global:Operator)" } catch {}
        try { CleanUp } catch {}
    }.GetNewClosure())

    # Win11 dark immersive title bar (DWM). Silently no-ops on older builds.
    $AppForm.Add_HandleCreated({ try { Set-WptDarkTitleBar -Form $AppForm } catch {} }.GetNewClosure())
    $AppForm.Add_Load({ try { Set-WptDarkTitleBar -Form $AppForm } catch {} }.GetNewClosure())

    # ==================== STATUS BAR (bottom, Dock) ====================
    # Matches WPT: scanline overlay + heartbeat + Session / Targets / Log labels.
    $pnlStatus = New-Object System.Windows.Forms.Panel
    $pnlStatus.Dock      = [System.Windows.Forms.DockStyle]::Bottom
    $pnlStatus.Height    = 32
    $pnlStatus.BackColor = $global:WPT.UI.Theme.StatusBar

    $pnlStatusEdge = New-Object System.Windows.Forms.Panel
    $pnlStatusEdge.Dock      = [System.Windows.Forms.DockStyle]::Top
    $pnlStatusEdge.Height    = 1
    $pnlStatusEdge.BackColor = $global:clrBorder
    $pnlStatus.Controls.Add($pnlStatusEdge)

    New-WptScanlineOverlay -Panel $pnlStatus

    # Heartbeat at the far left — freeze detector.
    $statusHeartbeat = New-WptPulseIndicator -X 10 -Y 12 -Size 8 -State 'Active'
    $global:WPT.UI.Controls['heartbeatStatus'] = $statusHeartbeat

    $lblStatusSession = New-WptLabel -Text "  SESSION: $env:USERNAME@$env:COMPUTERNAME" `
        -X 22 -Y 8 -W 300 -H 18 -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:WPT.UI.Theme.TextMuted
    $lblStatusSession.BackColor = [System.Drawing.Color]::Transparent

    # Status-bar mode indicator. Duplicates the sidebar credential/mode chip so
    # the current execution mode is visible regardless of scroll position.
    $lblStatusMode = New-WptLabel -Text 'MODE: LOCAL' -X 332 -Y 8 -W 180 -H 18 `
        -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:clrGreen
    $lblStatusMode.Name = 'lblStatusMode'
    $lblStatusMode.BackColor = [System.Drawing.Color]::Transparent
    $global:lblStatusModeRef = $lblStatusMode

    $lblStatusLog = New-WptLabel -Text "LOG: $($global:AuditLogPath)  " `
        -X 520 -Y 8 -W 800 -H 18 -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:clrTextDark
    $lblStatusLog.BackColor = [System.Drawing.Color]::Transparent
    $lblStatusLog.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $lblStatusLog.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $pnlStatus.Add_Resize({
        $lblStatusLog.Location = New-Object System.Drawing.Point(520, 8)
        $lblStatusLog.Size     = New-Object System.Drawing.Size(($pnlStatus.Width - 540), 18)
    }.GetNewClosure())
    $pnlStatus.Controls.AddRange(@($statusHeartbeat, $lblStatusSession, $lblStatusMode, $lblStatusLog))

    # ==================== SIDEBAR (left, Dock) ====================
    $pnlSidebar = New-Object System.Windows.Forms.Panel
    $pnlSidebar.Dock      = [System.Windows.Forms.DockStyle]::Left
    $pnlSidebar.Width     = 252
    $pnlSidebar.BackColor = $global:clrSidebar

    # Right edge divider
    $sidebarEdge = New-Object System.Windows.Forms.Panel
    $sidebarEdge.Dock      = [System.Windows.Forms.DockStyle]::Right
    $sidebarEdge.Width     = 1
    $sidebarEdge.BackColor = $global:clrBorder
    $pnlSidebar.Controls.Add($sidebarEdge)

    # ---- Brand block ----
    $pnlBrand = New-Object System.Windows.Forms.Panel
    $pnlBrand.Location  = New-Object System.Drawing.Point(0, 20)
    $pnlBrand.Size      = New-Object System.Drawing.Size(252, 100)
    $pnlBrand.BackColor = $global:clrSidebar

    $lblBrandMark = New-WptLabel -Text 'J.A.N.E.T.' -X 22 -Y 14 -W 220 -H 28 `
        -Font $global:WPT.UI.Fonts.DisplayLg -Fg $global:clrPurple
    $lblBrandSub  = New-WptLabel -Text 'STIG Tool' -X 22 -Y 48 -W 220 -H 16 `
        -Font $global:WPT.UI.Fonts.Caption -Fg $global:clrDim
    $lblBrandVer  = New-WptLabel -Text $global:ToolVersion -X 22 -Y 68 -W 220 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoTiny -Fg $global:clrTextDark

    # Blinking heartbeat next to the wordmark — if it stops, the UI thread
    # is frozen. Replaces the old custom-Paint pulse dot.
    $brandHeartbeat = New-WptPulseIndicator -X 200 -Y 22 -Size 10 -State 'Active'
    $global:WPT.UI.Controls['heartbeatBrand'] = $brandHeartbeat
    # Legacy compatibility: CleanUp still disposes $global:pulseTimerRef. Point
    # it at the brand heartbeat's timer so the shutdown path keeps working.
    if ($brandHeartbeat.Tag -and $brandHeartbeat.Tag.Timer) {
        $global:pulseTimerRef = $brandHeartbeat.Tag.Timer
    }
    $global:pnlPulseRef = $brandHeartbeat

    $pnlBrand.Controls.AddRange(@($lblBrandMark, $lblBrandSub, $lblBrandVer, $brandHeartbeat))

    $brandSep = New-WptSeparator -X 20 -Y 128 -W 212 -Color $global:clrBorder

    # ---- Nav host ----
    # AutoScroll so the 9 nav items remain reachable on small screens.
    $navHost = New-Object System.Windows.Forms.Panel
    $navHost.Location   = New-Object System.Drawing.Point(0, 140)
    $navHost.Size       = New-Object System.Drawing.Size(252, 500)
    $navHost.BackColor  = $global:clrSidebar
    $navHost.Anchor     = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $navHost.AutoScroll = $true
    $global:NavHost = $navHost

    # ---- User / operator block pinned to bottom ----
    # v1.2.10: Close Tool button moved to the top-right content strip
    # (next to the "live" indicator), so this block now only carries
    # operator info (User / Mode / Creds / Host). Height trimmed
    # accordingly.
    $pnlUser = New-Object System.Windows.Forms.Panel
    $pnlUser.Dock      = [System.Windows.Forms.DockStyle]::Bottom
    $pnlUser.Height    = 110
    $pnlUser.BackColor = $global:clrSidebar

    $userSep = New-WptSeparator -X 20 -Y 0 -W 212 -Color $global:clrBorder
    $pnlUser.Controls.Add($userSep)

    $lblOpName = New-WptLabel -Text "User: $env:USERNAME" -X 22 -Y 12 -W 212 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:clrWhite

    # Mode chip in the sidebar — same object the About-tab radios write to.
    $lblMode = New-WptLabel -Text 'Mode: Local' -X 22 -Y 34 -W 212 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:clrGreen
    $lblMode.Name = 'lblMode'
    $global:lblModeRef = $lblMode

    # Credential chip — text toggles between "not set" / actual UserName.
    $lblCredHdr = New-WptLabel -Text 'Creds: n/a (Local)' -X 22 -Y 54 -W 212 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoSm -Fg $global:clrDim
    $lblCredHdr.Name = 'lblCredHdr'
    $global:lblCredHdr = $lblCredHdr

    $lblOpHost = New-WptLabel -Text "Host: $env:COMPUTERNAME" -X 22 -Y 80 -W 212 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoTiny -Fg $global:clrTextDark

    # btnCloseTool is created later in the content top-strip block (line ~4592)
    # so it sits next to the live heartbeat indicator. Operator info stays here.
    $pnlUser.Controls.AddRange(@($lblOpName, $lblMode, $lblCredHdr, $lblOpHost))

    $pnlSidebar.Controls.AddRange(@($pnlBrand, $brandSep, $navHost, $pnlUser))

    # Keep navHost from running into pnlUser (or off the bottom of the
    # sidebar) on resize. navHost has Anchor=Top+Left+Bottom which CAN
    # do this in theory, but the at-add anchor distance was calculated
    # before the sidebar was sized, so the anchor math was off and the
    # bottom of navHost ended up well past pnlUser. Explicit Resize
    # handler is more reliable than trusting WinForms anchor.
    $pnlSidebar.Add_Resize({
        if ($navHost -and -not $navHost.IsDisposed -and
            $pnlUser -and -not $pnlUser.IsDisposed) {
            $availH = $pnlSidebar.ClientSize.Height - $navHost.Top - $pnlUser.Height
            if ($availH -lt 50) { $availH = 50 }
            $navHost.Height = $availH
        }
    }.GetNewClosure())

    # ==================== CONTENT HOST (center, Fill) ====================
    $pnlContentHost = New-Object System.Windows.Forms.Panel
    $pnlContentHost.Dock      = [System.Windows.Forms.DockStyle]::Fill
    $pnlContentHost.BackColor = $global:clrBG
    Enable-WptDoubleBuffer -Control $pnlContentHost

    # Thin top strip with right-anchored content heartbeat (third freeze detector).
    $pnlContentTop = New-Object System.Windows.Forms.Panel
    $pnlContentTop.Dock      = [System.Windows.Forms.DockStyle]::Top
    $pnlContentTop.Height    = 36
    $pnlContentTop.BackColor = $global:clrBG

    $contentHeartbeat = New-WptPulseIndicator -X 940 -Y 14 -Size 10 -State 'Active'
    $contentHeartbeat.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $global:WPT.UI.Controls['heartbeatContent'] = $contentHeartbeat
    $lblHeartbeat = New-WptLabel -Text 'live' -X 958 -Y 12 -W 48 -H 16 `
        -Font $global:WPT.UI.Fonts.MonoTiny -Fg $global:clrTextDark
    $lblHeartbeat.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right

    # v1.2.10: Close Tool button moved here from the sidebar bottom. Sits
    # immediately to the LEFT of the heartbeat dot + "live" label so it
    # is always visible and reachable.
    $btnCloseTool = New-WptButton -Text 'Close Tool' -X 850 -Y 6 -W 90 -H 24 -Bg $global:clrRed
    $btnCloseTool.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCloseTool.Add_Click({
        Set-JanetAllowClose $true
        $AppForm.Close()
    }.GetNewClosure())

    $pnlContentTop.Controls.AddRange(@($btnCloseTool, $contentHeartbeat, $lblHeartbeat))
    $pnlContentTop.Add_Resize({
        $w = $pnlContentTop.ClientSize.Width
        $contentHeartbeat.Location = New-Object System.Drawing.Point(($w - 74), 14)
        $lblHeartbeat.Location     = New-Object System.Drawing.Point(($w - 56), 12)
        $btnCloseTool.Location     = New-Object System.Drawing.Point(($w - 180), 6)
    }.GetNewClosure())

    # Accent rule (2px) + hairline (1px) — same as WPT's divider pair.
    $pnlAccentRule = New-Object System.Windows.Forms.Panel
    $pnlAccentRule.Dock      = [System.Windows.Forms.DockStyle]::Top
    $pnlAccentRule.Height    = 2
    $pnlAccentRule.BackColor = $global:clrAccentDim

    $pnlDivider = New-Object System.Windows.Forms.Panel
    $pnlDivider.Dock      = [System.Windows.Forms.DockStyle]::Top
    $pnlDivider.Height    = 1
    $pnlDivider.BackColor = $global:clrBorder

    # ---- TabControl now docks Fill inside the content host. Tab strip stays
    # hidden (ItemSize 0,1 + Fixed); sidebar nav items drive SelectedTab. ----
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock       = [System.Windows.Forms.DockStyle]::Fill
    $tabControl.Appearance = [System.Windows.Forms.TabAppearance]::FlatButtons
    $tabControl.BackColor  = $global:clrBG
    $tabControl.ForeColor  = $global:clrBG
    $tabControl.ItemSize   = New-Object System.Drawing.Size(0, 1)
    $tabControl.SizeMode   = [System.Windows.Forms.TabSizeMode]::Fixed
    $tabControl.Padding    = New-Object System.Drawing.Point(0, 0)
    Enable-WptDoubleBuffer -Control $tabControl

    # Assembly order — TabControl must dock-fill LAST so the Top strips sit above it.
    $pnlContentHost.Controls.Add($tabControl)
    $pnlContentHost.Controls.Add($pnlDivider)
    $pnlContentHost.Controls.Add($pnlAccentRule)
    $pnlContentHost.Controls.Add($pnlContentTop)

#endregion

#region ------------------------ TAB: START ------------------------------
    # Hero landing tab — mirrors WPT's Start pattern. Shows the tool's
    # current session state at a glance and offers quick pop-outs for
    # Change Log + How to Use. Detailed configuration still lives on the
    # About tab (credentials, operator name, prereq install buttons).
    $tabStart = New-Object System.Windows.Forms.TabPage
    $tabStart.Text      = '  Start  '
    $tabStart.BackColor = $global:clrBG
    $tabStart.ForeColor = $global:clrWhite

    $theme = $global:WPT.UI.Theme
    $wFonts = $global:WPT.UI.Fonts
    $wIcons = $global:WPT.UI.Icons

    # Session Activation card — the wide hero at the top of the tab.
    $cardAct = New-WptCard -Header 'Session Activation' -X 20 -Y 20 -W 1060 -H 220 -Fg $theme.Accent1 -Padding 24
    $cardAct.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    $iconShield = New-WptIconLabel -Glyph $wIcons.Shield -X 28 -Y 68 -W 56 -H 56 -Font $wFonts.IconLarge -Fg $theme.Accent1

    $lblOpHead   = New-WptLabel -Text 'OPERATOR' -X 104 -Y 70 -W 120 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $lblOpStart  = New-WptLabel -Text $global:Operator -X 232 -Y 70 -W 360 -H 18 -Font $wFonts.MonoSm -Fg $theme.TextSecondary
    $global:lblOpStartRef = $lblOpStart

    $lblModeHead = New-WptLabel -Text 'MODE' -X 104 -Y 94 -W 120 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $lblModeStart= New-WptLabel -Text 'Local' -X 232 -Y 94 -W 360 -H 18 -Font $wFonts.MonoSm -Fg $theme.Success
    $global:lblModeStartRef = $lblModeStart

    $lblCredHead = New-WptLabel -Text 'CREDENTIALS' -X 104 -Y 118 -W 120 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $lblCredStart= New-WptLabel -Text 'not set' -X 232 -Y 118 -W 360 -H 18 -Font $wFonts.MonoSm -Fg $theme.TextMuted
    $global:lblCredStartRef = $lblCredStart

    $lblPreHead  = New-WptLabel -Text 'PREREQS' -X 104 -Y 142 -W 120 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $lblPreStart = New-WptLabel -Text 'unknown — open About to check' -X 232 -Y 142 -W 360 -H 18 -Font $wFonts.MonoSm -Fg $theme.TextMuted
    $global:lblPreStartRef = $lblPreStart

    $lblWsHead   = New-WptLabel -Text 'WORKSPACE' -X 104 -Y 166 -W 120 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $lblWsStart  = New-WptLabel -Text $global:WorkspaceRoot -X 232 -Y 166 -W 600 -H 18 -Font $wFonts.MonoTiny -Fg $theme.TextFaint
    $lblWsStart.AutoEllipsis = $true

    # Vertical divider between status column and the CTA column.
    $startRule = New-Object System.Windows.Forms.Panel
    $startRule.Location  = New-Object System.Drawing.Point(700, 60)
    $startRule.Size      = New-Object System.Drawing.Size(1, 140)
    $startRule.BackColor = $theme.Border

    $lblCtaHead = New-WptLabel -Text 'READY TO START?' -X 740 -Y 68 -W 280 -H 18 -Font $wFonts.Eyebrow -Fg $theme.TextMuted
    $btnGoTargets = New-WptPrimaryButton -Text 'Go to Targets' -X 740 -Y 96 -W 280 -H 54 -Font $wFonts.DisplayMd
    $btnGoTargets.Add_Click({
        # Switch to the Targets tab via the named nav helper.
        Invoke-StigSetActiveTab -TabKey 'Targets'
    }.GetNewClosure())
    $lblCtaSub = New-WptLabel -Text 'Configure creds + prereqs on the About tab first' -X 740 -Y 160 -W 280 -H 18 -Font $wFonts.Caption -Fg $theme.TextFaint
    $lblCtaSub.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

    $cardAct.Controls.AddRange(@(
        $iconShield,
        $lblOpHead,   $lblOpStart,
        $lblModeHead, $lblModeStart,
        $lblCredHead, $lblCredStart,
        $lblPreHead,  $lblPreStart,
        $lblWsHead,   $lblWsStart,
        $startRule,
        $lblCtaHead, $btnGoTargets, $lblCtaSub
    ))
    $tabStart.Controls.Add($cardAct)

    # Tip strip — tells the operator where real configuration lives.
    $tipStart = New-Object System.Windows.Forms.Panel
    $tipStart.Location  = New-Object System.Drawing.Point(20, 260)
    $tipStart.Size      = New-Object System.Drawing.Size(1060, 52)
    $tipStart.BackColor = $theme.SurfaceAlt
    $tipStart.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    $tipStartBar = New-Object System.Windows.Forms.Panel
    $tipStartBar.Dock      = [System.Windows.Forms.DockStyle]::Left
    $tipStartBar.Width     = 3
    $tipStartBar.BackColor = $theme.Accent1
    $tipStart.Controls.Add($tipStartBar)

    $tipStartIcon = New-WptIconLabel -Glyph $wIcons.Info -X 18 -Y 14 -W 26 -H 26 -Font $wFonts.Icon -Fg $theme.Accent1
    $tipStartHead = New-WptLabel -Text 'TIP' -X 52 -Y 8 -W 40 -H 16 -Font $wFonts.Eyebrow -Fg $theme.Accent1
    $tipStartBody = New-WptLabel -Text 'First run: click the About tab to set your operator name, pick Local or Remote mode, load credentials (Remote only), and install PowerStig + ImportExcel. Then come back to Targets.' `
        -X 52 -Y 26 -W 980 -H 20 -Font $wFonts.Caption -Fg $theme.TextSecondary
    $tipStartBody.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $tipStart.Controls.AddRange(@($tipStartIcon, $tipStartHead, $tipStartBody))
    $tabStart.Controls.Add($tipStart)

    # Change Log + How to Use ghost buttons (matches WPT Start tab).
    $btnChangeLog = New-WptGhostButton -Text 'Change Log' -X 780 -Y 330 -W 140 -H 32 -Fg $theme.TextSecondary -Font $wFonts.Btn
    $btnHowToUse  = New-WptGhostButton -Text 'How to Use' -X 930 -Y 330 -W 150 -H 32 -Fg $theme.Accent1       -Font $wFonts.Btn
    $btnChangeLog.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnHowToUse.Anchor  = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnChangeLog.Add_Click({ Show-StigChangeLogDialog }.GetNewClosure())
    $btnHowToUse.Add_Click({ Show-StigHowToUseDialog }.GetNewClosure())
    $tabStart.Controls.AddRange(@($btnChangeLog, $btnHowToUse))

    # Refresh callback wired via a NAMED function at script scope — not a
    # $global: scriptblock — because closures over $global:<name> scriptblocks
    # resolve to $null in WinForms event handlers after modal unwind.
    # Named functions live in the session command table and always resolve.
    $tabStart.Add_VisibleChanged({ if ($tabStart.Visible) { Update-StigStartCard } }.GetNewClosure())
    $tabStart.Add_Enter({ Update-StigStartCard }.GetNewClosure())

#endregion

#region ------------------------ TAB: ABOUT / SETUP ----------------------
    $tabAbout = New-Object System.Windows.Forms.TabPage
    $tabAbout.Text = '  About / Setup  '
    $tabAbout.BackColor = $global:clrBG; $tabAbout.ForeColor = $global:clrWhite

    $grpOp = & $MakeGB 'Operator & Workspace' 15 15 520 95
    $lOp = & $MakeLbl 'Operator:' 15 30 80
    $tOp = New-Object System.Windows.Forms.TextBox
    $tOp.Text = $global:Operator
    $tOp.BackColor = $global:clrInputBG; $tOp.ForeColor = $global:clrWhite
    $tOp.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $tOp.Location = New-Object System.Drawing.Point(100, 28)
    $tOp.Size = New-Object System.Drawing.Size(200, 22)
    $tOp.Add_TextChanged({ $global:Operator = $tOp.Text.Trim() }.GetNewClosure())

    $lblWs = & $MakeLbl 'Workspace:' 15 58 80
    $wsColor = if ($global:WorkspaceIsFallback) { $global:clrOrange } else { $global:clrCyan }
    $lblWsVal = & $MakeVal 100 58 400 $wsColor
    $lblWsVal.Text = $global:WorkspaceRoot
    if ($global:WorkspaceIsFallback) {
        $tooltip.SetToolTip($lblWsVal, "Script folder was not writable; falling back to %LOCALAPPDATA%. Preferred: $($global:WorkspaceRootPreferred)")
    }
    $grpOp.Controls.AddRange(@($lOp, $tOp, $lblWs, $lblWsVal))

    $grpMode = & $MakeGB 'Execution Mode & Credentials' 15 120 520 140
    $rbLocal = New-Object System.Windows.Forms.RadioButton
    $rbLocal.Text = 'Local — run against THIS machine'
    $rbLocal.ForeColor = $global:clrWhite
    $rbLocal.AutoSize = $true
    $rbLocal.Location = New-Object System.Drawing.Point(20, 28)
    $rbLocal.Checked = $true

    $rbRemote = New-Object System.Windows.Forms.RadioButton
    $rbRemote.Text = 'Remote — PSRemoting (WinRM) to targets'
    $rbRemote.ForeColor = $global:clrWhite
    $rbRemote.AutoSize = $true
    $rbRemote.Location = New-Object System.Drawing.Point(20, 53)

    $btnCred = New-Object System.Windows.Forms.Button
    $btnCred.Text = 'Set Credentials'
    $btnCred.Size = New-Object System.Drawing.Size(160, 30)
    $btnCred.Location = New-Object System.Drawing.Point(20, 88)
    & $StyleBtn $btnCred $global:clrCyan 'Prompt for credentials used for remote WinRM and Invoke-Command'
    # Button is always enabled so operators can pre-stage creds even while in
    # Local mode (they may plan to flip to Remote later). Creds are only
    # ENFORCED when an action runs in Remote mode (via Test-StigCredsReady).

    $lblCredStatus = New-Object System.Windows.Forms.Label
    $lblCredStatus.Text      = 'No credentials set (only required for Remote mode)'
    $lblCredStatus.ForeColor = $global:clrDim
    $lblCredStatus.Font      = $fontSmall
    $lblCredStatus.AutoSize  = $false
    $lblCredStatus.Size      = New-Object System.Drawing.Size(310, 30)
    $lblCredStatus.Location  = New-Object System.Drawing.Point(190, 88)
    $lblCredStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

    # Expose to event handlers via closures
    $global:btnCredRef = $btnCred
    $global:lblCredStatusRef = $lblCredStatus
    $global:rbLocalRef  = $rbLocal
    $global:rbRemoteRef = $rbRemote
    $global:lblModeRef  = $lblMode

    $btnCred.Add_Click({
        # Phase 1: acquire credentials. Keep this SMALL and isolated — if
        # Get-Credential fails or is cancelled, we don't want the UI update
        # phase to run on garbage data.
        $cred = $null
        try {
            $cred = Get-Credential -Message 'Remote credentials for STIG operations'
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Credential prompt failed: $($_.Exception.Message)",
                'Credential error',
                'OK',
                'Warning'
            ) | Out-Null
            return
        }
        if (-not $cred -or -not $cred.UserName) { return }   # user cancelled

        # Phase 2: commit to state + paint UI. Each control ref is null-checked
        # individually so one missing label can't blow up the whole update.
        $global:RemoteCred = $cred
        try { Write-Audit -Event 'CredentialSet' -Details "user=$($cred.UserName)" } catch {}

        if ($global:btnCredRef -and $global:btnCredRef -is [System.Windows.Forms.Button]) {
            $global:btnCredRef.Text = 'Re-enter Credentials'
        }
        if ($global:lblCredStatusRef -and $global:lblCredStatusRef -is [System.Windows.Forms.Label]) {
            $global:lblCredStatusRef.Text      = "Signed in as $($cred.UserName)"
            $global:lblCredStatusRef.ForeColor = $global:clrGreen
        }
        if ($global:lblCredHdr -and $global:lblCredHdr -is [System.Windows.Forms.Label]) {
            $global:lblCredHdr.Text      = "Creds: $($cred.UserName)"
            $global:lblCredHdr.ForeColor = $global:clrGreen
        }
    }.GetNewClosure())

    $rbLocal.Add_CheckedChanged({
        if ($global:rbLocalRef.Checked) {
            $global:ExecutionMode = 'Local'
            $global:lblModeRef.Text = 'Mode: Local'
            $global:lblModeRef.ForeColor = $global:clrGreen
            if ($global:lblCredHdr) {
                $global:lblCredHdr.Text = 'Creds: n/a (Local)'
                $global:lblCredHdr.ForeColor = $global:clrDim
            }
            if ($global:lblStatusModeRef) {
                $global:lblStatusModeRef.Text = 'MODE: LOCAL'
                $global:lblStatusModeRef.ForeColor = $global:clrGreen
            }
        }
    }.GetNewClosure())
    $rbRemote.Add_CheckedChanged({
        if ($global:rbRemoteRef.Checked) {
            if (-not $global:PrereqStatus.WinRmConfigured) {
                [System.Windows.Forms.MessageBox]::Show('WinRM service is not running on this machine. Cannot use Remote mode.', 'Remote unavailable','OK','Warning') | Out-Null
                $global:rbLocalRef.Checked = $true
                return
            }
            $global:ExecutionMode = 'Remote'
            $global:lblModeRef.Text = 'Mode: Remote'
            $global:lblModeRef.ForeColor = $global:clrOrange
            # When switching INTO Remote mode, clear the Targets hostname
            # field if it still contains the local machine name we pre-
            # populated at startup. Operators entering remote hostnames
            # shouldn't have to manually delete $env:COMPUTERNAME first.
            # Only clear if the box contains exactly the local name (so we
            # don't clobber names the operator already typed).
            if ($global:txtHostsRef -and $global:txtHostsRef.Text.Trim() -eq $env:COMPUTERNAME) {
                $global:txtHostsRef.Text = ''
            }
            # Repaint credential chip based on whether creds are already set
            if ($global:lblCredHdr) {
                if ($global:RemoteCred) {
                    $global:lblCredHdr.Text = "Creds: $($global:RemoteCred.UserName)"
                    $global:lblCredHdr.ForeColor = $global:clrGreen
                } else {
                    $global:lblCredHdr.Text = 'Creds: NOT SET'
                    $global:lblCredHdr.ForeColor = $global:clrRed
                }
            }
            if ($global:lblStatusModeRef) {
                $global:lblStatusModeRef.Text = 'MODE: REMOTE (WinRM)'
                $global:lblStatusModeRef.ForeColor = $global:clrOrange
            }
        }
    }.GetNewClosure())
    $grpMode.Controls.AddRange(@($rbLocal, $rbRemote, $btnCred, $lblCredStatus))

    $grpPre = & $MakeGB 'Prerequisite Status' 555 15 640 375
    $txtPre = New-Object System.Windows.Forms.TextBox
    $txtPre.Multiline = $true; $txtPre.ReadOnly = $true
    $txtPre.ScrollBars = 'Vertical'; $txtPre.Font = $fontMono
    $txtPre.BackColor = $global:clrInputBG; $txtPre.ForeColor = $global:clrWhite
    $txtPre.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtPre.Location = New-Object System.Drawing.Point(15, 30)
    $txtPre.Size = New-Object System.Drawing.Size(610, 260)

    $btnReCheck = New-Object System.Windows.Forms.Button
    $btnReCheck.Text = 'Re-check Prerequisites'
    $btnReCheck.Size = New-Object System.Drawing.Size(180, 26)
    $btnReCheck.Location = New-Object System.Drawing.Point(15, 300)
    & $StyleBtn $btnReCheck $global:clrCyan 'Re-run the prereq check after installing modules'

    $btnInstallMods = New-Object System.Windows.Forms.Button
    $btnInstallMods.Text = 'Install Missing Modules'
    $btnInstallMods.Size = New-Object System.Drawing.Size(180, 26)
    $btnInstallMods.Location = New-Object System.Drawing.Point(205, 300)
    & $StyleBtn $btnInstallMods $global:clrOrange 'Install PowerStig + ImportExcel from PSGallery (requires internet)'
    # Add_Click wired AFTER $RefreshPre is defined so the closure captures it correctly

    $btnOpenWs = New-Object System.Windows.Forms.Button
    $btnOpenWs.Text = 'Open Workspace Folder'
    $btnOpenWs.Size = New-Object System.Drawing.Size(180, 26)
    $btnOpenWs.Location = New-Object System.Drawing.Point(395, 300)
    & $StyleBtn $btnOpenWs $global:clrGreen 'Open Workspace in Explorer'
    $btnOpenWs.Add_Click({ Start-Process explorer.exe $global:WorkspaceRoot }.GetNewClosure())

    $btnOpenAudit = New-Object System.Windows.Forms.Button
    $btnOpenAudit.Text = 'Open Audit Log'
    $btnOpenAudit.Size = New-Object System.Drawing.Size(180, 26)
    $btnOpenAudit.Location = New-Object System.Drawing.Point(15, 332)
    & $StyleBtn $btnOpenAudit $global:clrPurple 'Open audit.log in notepad'
    $btnOpenAudit.Add_Click({ if (Test-Path $global:AuditLogPath) { Start-Process notepad.exe $global:AuditLogPath } }.GetNewClosure())

    # $RefreshPre is defined BEFORE any click handler that references it
    # via .GetNewClosure(). Previously the offline-import handler was wired
    # above the definition, so the closure captured $null and the prereq
    # panel silently never refreshed after an offline install.
    $RefreshPre = {
        $p = Test-Prerequisites
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("PowerShell version      : $($p.PSVersion)  [$(if($p.PSVersionOk){'OK'}else{'FAIL'})]")
        [void]$sb.AppendLine("Elevated (Administrator): $(if($p.IsAdmin){'YES'}else{'NO  — Apply will fail'})")
        [void]$sb.AppendLine("PowerStig module        : $(if($p.PowerStigInstalled){"$($p.PowerStigVersion)"}else{'MISSING'})")
        [void]$sb.AppendLine("PSDesiredStateConfig    : $(if($p.DscInstalled){'OK'}else{'MISSING'})")
        [void]$sb.AppendLine("ImportExcel module      : $(if($p.ImportExcelInstalled){'OK'}else{'MISSING — XLSX export disabled'})")
        [void]$sb.AppendLine("WinRM service           : $(if($p.WinRmConfigured){'Running — Remote mode available'}else{'Stopped — Remote mode disabled'})")
        [void]$sb.AppendLine('')
        if ($p.Warnings.Count -gt 0) {
            [void]$sb.AppendLine('Warnings:')
            foreach ($w in $p.Warnings) { [void]$sb.AppendLine("  - $w") }
        } else {
            [void]$sb.AppendLine('All prerequisites satisfied.')
        }
        [void]$sb.AppendLine('')
        if ($global:IsJanetMember) {
            [void]$sb.AppendLine("Mode          : J.A.N.E.T. suite member")
            [void]$sb.AppendLine("Suite root    : $($global:JanetSuiteRoot)")
        } else {
            [void]$sb.AppendLine("Mode          : standalone")
        }
        [void]$sb.AppendLine("Script folder : $($global:ScriptRoot)")
        [void]$sb.AppendLine("Workspace     : $($global:WorkspaceRoot)")
        if ($global:WorkspaceIsFallback) {
            [void]$sb.AppendLine("                ^ Fallback: preferred path was not writable.")
            [void]$sb.AppendLine("                  Preferred was: $($global:WorkspaceRootPreferred)")
        }
        [void]$sb.AppendLine("Audit log     : $($global:AuditLogPath)")
        $txtPre.Text = $sb.ToString()
    }.GetNewClosure()
    $btnReCheck.Add_Click($RefreshPre)

    # Offline module import — for air-gapped AFNET hosts that can't reach
    # PSGallery. Operator points at a folder containing PowerStig/ImportExcel
    # module subfolders and we copy them into the user's PSModulePath.
    $btnImportOffline = New-Object System.Windows.Forms.Button
    $btnImportOffline.Text = 'Import Modules (Offline)...'
    $btnImportOffline.Size = New-Object System.Drawing.Size(180, 26)
    $btnImportOffline.Location = New-Object System.Drawing.Point(205, 332)
    & $StyleBtn $btnImportOffline $global:clrCyan 'Copy PowerStig / ImportExcel from a local folder (air-gapped install path)'
    $btnImportOffline.Add_Click({
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Select a folder containing PowerStig\ and/or ImportExcel\ module subfolders (DISA-side offline export)'
        if ($fbd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $src = $fbd.SelectedPath
        # Target: first writable path on PSModulePath (usually Documents\WindowsPowerShell\Modules)
        $targets = @(
            (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules')
        )
        try {
            $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { $isAdmin = $false }
        if ($isAdmin) { $targets += (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') }
        $dest = $targets[0]
        if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force -ErrorAction SilentlyContinue | Out-Null }

        $report = [System.Collections.ArrayList]::new()
        foreach ($modName in @('PowerStig','ImportExcel')) {
            $srcModRoot = Join-Path $src $modName
            if (-not (Test-Path $srcModRoot)) {
                [void]$report.Add("  [$modName] skipped — folder not found at: $srcModRoot")
                continue
            }
            try {
                $destModRoot = Join-Path $dest $modName
                Copy-Item -Path $srcModRoot -Destination $dest -Recurse -Force -ErrorAction Stop
                [void]$report.Add("  [$modName] copied to: $destModRoot")
            } catch {
                [void]$report.Add("  [$modName] COPY FAILED: $($_.Exception.Message)")
            }
        }
        $reportText = @"
Offline module import complete.

Source: $src
Target: $dest

$($report -join "`r`n")

Click "Re-check Prerequisites" to refresh the prereq panel.
"@
        Show-StigCopyableError -Severity 'Info' -Title 'Offline Import Report' -Message $reportText
        if ($RefreshPre) { & $RefreshPre }
    }.GetNewClosure())

    # Install button click: runs Install-StigToolModules and refreshes the prereq panel
    $btnInstallMods.Add_Click({
        $btnInstallMods.Enabled = $false
        $btnInstallMods.Text = 'Installing...'
        [System.Windows.Forms.Application]::DoEvents()
        $r = Install-StigToolModules -Force
        $btnInstallMods.Text = 'Install Missing Modules'
        $btnInstallMods.Enabled = $true
        $msg = "$($r.Message)`n`n"
        if ($r.Errors.Count -gt 0) { $msg += "Errors:`n" + ($r.Errors -join "`n") }
        [System.Windows.Forms.MessageBox]::Show(
            $msg,
            $(if($r.Success){'Install complete'}else{'Install had errors'}),
            'OK',
            $(if($r.Success){'Information'}else{'Warning'})
        ) | Out-Null
        & $RefreshPre
    }.GetNewClosure())

    $grpPre.Controls.AddRange(@($txtPre, $btnReCheck, $btnInstallMods, $btnOpenWs, $btnOpenAudit, $btnImportOffline))

    $grpWorkflow = & $MakeGB 'Workflow' 15 260 520 395 $global:clrPurple
    # Each step gets a DISTINCT color so the sequence is visually readable.
    # Semantics:
    #   blue (info)   = preparation / setup
    #   green (go)    = discovery / active scanning
    #   purple (pick) = decision point / per-rule curation
    #   red (danger)  = state-changing action
    #   yellow (chk)  = verification / checking
    #   muted amber   = export / archival
    $aboutSteps = @(
        @{ Num='1'; Name='About / Setup';    Color=$global:clrInfo;   Desc='Confirm operator, prereqs, Local or Remote mode.' },
        @{ Num='2'; Name='Targets';          Color=$global:clrGreen;  Desc='Type/paste hosts, click + Add to list, then Test Reachability.' },
        @{ Num='3'; Name='Scan (Evaluate)';  Color=$global:clrGreen;  Desc='Compile MOF, run Test-DscConfiguration per host.' },
        @{ Num='4'; Name='Checklist Review'; Color=$global:clrPurple; Desc='Per-rule grid. Uncheck rules to exclude from Apply.' },
        @{ Num='5'; Name='Apply (Remediate)';Color=$global:clrRed;    Desc='Restore point + typed APPLY confirm. DRY RUN available.' },
        @{ Num='6'; Name='Verify';           Color=$global:clrOrange; Desc='Rescan and diff: Resolved / Still Failing / Regression.' },
        @{ Num='7'; Name='Reports';          Color=$global:clrMuted;  Desc='Export XLSX: Summary / PerRule / Skipped / Audit.' }
    )
    $flowY = 28
    foreach ($s in $aboutSteps) {
        $fp = New-Object System.Windows.Forms.Panel
        $fp.Size      = New-Object System.Drawing.Size(490, 46)
        $fp.Location  = New-Object System.Drawing.Point(15, $flowY)
        $fp.BackColor = $global:clrInputBG
        $fbar = New-Object System.Windows.Forms.Panel
        $fbar.Size = New-Object System.Drawing.Size(3, 46); $fbar.Location = New-Object System.Drawing.Point(0,0); $fbar.BackColor = $s.Color
        $fp.Controls.Add($fbar)
        $fnum = New-Object System.Windows.Forms.Label
        $fnum.Text=$s.Num; $fnum.Font=New-Object System.Drawing.Font('Segoe UI',16,[System.Drawing.FontStyle]::Bold)
        $fnum.ForeColor=$s.Color; $fnum.BackColor=[System.Drawing.Color]::Transparent
        $fnum.AutoSize=$false; $fnum.Size=New-Object System.Drawing.Size(30,36); $fnum.Location=New-Object System.Drawing.Point(10,5)
        $fnum.TextAlign=[System.Drawing.ContentAlignment]::MiddleCenter
        $fp.Controls.Add($fnum)
        $fname = New-Object System.Windows.Forms.Label
        $fname.Text=$s.Name; $fname.Font=$fontGroupHeader; $fname.ForeColor=$global:clrWhite
        $fname.BackColor=[System.Drawing.Color]::Transparent; $fname.AutoSize=$false
        $fname.Size=New-Object System.Drawing.Size(340,18); $fname.Location=New-Object System.Drawing.Point(48,4)
        $fname.TextAlign=[System.Drawing.ContentAlignment]::MiddleLeft
        $fp.Controls.Add($fname)
        $fdesc = New-Object System.Windows.Forms.Label
        $fdesc.Text=$s.Desc; $fdesc.Font=$fontSmall; $fdesc.ForeColor=$global:clrDim
        $fdesc.BackColor=[System.Drawing.Color]::Transparent; $fdesc.AutoSize=$false
        $fdesc.Size=New-Object System.Drawing.Size(430,18); $fdesc.Location=New-Object System.Drawing.Point(48,24)
        $fdesc.TextAlign=[System.Drawing.ContentAlignment]::MiddleLeft
        $fp.Controls.Add($fdesc)
        $grpWorkflow.Controls.Add($fp)
        $flowY += 50
    }

    $tabAbout.Controls.AddRange(@($grpOp, $grpMode, $grpPre, $grpWorkflow))

#endregion

#region ------------------------ TAB: TARGETS ----------------------------
    $tabTargets = New-Object System.Windows.Forms.TabPage
    $tabTargets.Text = '  Targets  '
    $tabTargets.BackColor = $global:clrBG; $tabTargets.ForeColor = $global:clrWhite
    # v1.2.12: 15px padding on the tab page so docked children sit off
    # the edges. Using Padding here (instead of explicit X=15 on each
    # child) lets grpHosts/grpDiscovered Dock with proper insets.
    $tabTargets.Padding = New-Object System.Windows.Forms.Padding(15)

    $grpHosts = & $MakeGB 'Add Hosts' 15 15 520 580
    # v1.2.12: Dock=Left + fixed Width (520). Children inside use their
    # original X/Y coordinates — group's internal coordinate system
    # doesn't change when Dock takes effect.
    $grpHosts.Dock  = [System.Windows.Forms.DockStyle]::Left
    $grpHosts.Width = 520
    # Friendly intro line so first-time operators see what this pane does
    # without having to read tooltips. Larger font + accent color.
    $lblHowTo = New-Object System.Windows.Forms.Label
    $lblHowTo.Text      = 'Type or paste host names (one per line), then click + Add to list.'
    $lblHowTo.ForeColor = $global:clrWhite
    $lblHowTo.Font      = $fontSmall
    $lblHowTo.AutoSize  = $false
    $lblHowTo.Size      = New-Object System.Drawing.Size(490, 18)
    $lblHowTo.Location  = New-Object System.Drawing.Point(15, 26)

    $lblPaste = & $MakeLbl 'Hosts (one per line):' 15 50 240
    $txtHosts = New-Object System.Windows.Forms.TextBox
    $txtHosts.Multiline = $true; $txtHosts.ScrollBars = 'Vertical'; $txtHosts.Font = $fontMono
    $txtHosts.BackColor = $global:clrInputBG; $txtHosts.ForeColor = $global:clrWhite
    $txtHosts.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtHosts.Location = New-Object System.Drawing.Point(15, 70)
    $txtHosts.Size = New-Object System.Drawing.Size(490, 200)
    # Pre-populate with the local machine ONLY in Local mode — in Remote
    # mode the operator is typing actual target names, so we clear it out.
    # The rbRemote handler on the About tab blanks this when switched.
    if ($global:ExecutionMode -eq 'Local') {
        $txtHosts.Text = $env:COMPUTERNAME
    }
    $global:txtHostsRef = $txtHosts   # exposed for rbRemote handler

    # PRIMARY ACTION: + Add to list. Adds typed hosts to the grid AND
    # $global:Targets immediately, without waiting for a reachability probe.
    # This was the #1 friction point in v1.2.1 — operators expected an
    # explicit "add" step, not "paste + run probe to even SEE the host".
    $btnAddTargets = New-Object System.Windows.Forms.Button
    $btnAddTargets.Text     = '+ Add to list'
    $btnAddTargets.Size     = New-Object System.Drawing.Size(160, 32)
    $btnAddTargets.Font     = $fontBigBtn
    $btnAddTargets.Location = New-Object System.Drawing.Point(15, 285)
    & $StyleBtn $btnAddTargets $global:clrPurple 'Add the typed hosts to the Discovered Targets list (no probe)'

    $btnAddThis = New-Object System.Windows.Forms.Button
    $btnAddThis.Text = 'Add this machine'
    $btnAddThis.Size = New-Object System.Drawing.Size(160, 32)
    $btnAddThis.Location = New-Object System.Drawing.Point(185, 285)
    $btnAddThis.Font     = $fontBigBtn
    & $StyleBtn $btnAddThis $global:clrCyan 'Append this computer name to the input box and add to list'
    $btnAddThis.Add_Click({
        if ($txtHosts.Text -notmatch [regex]::Escape($env:COMPUTERNAME)) {
            if ($txtHosts.Text) { $txtHosts.AppendText([Environment]::NewLine) }
            $txtHosts.AppendText($env:COMPUTERNAME)
        }
        $btnAddTargets.PerformClick()
    }.GetNewClosure())

    $btnLoadFile = New-Object System.Windows.Forms.Button
    $btnLoadFile.Text = 'Load from file...'
    $btnLoadFile.Size = New-Object System.Drawing.Size(160, 28)
    $btnLoadFile.Location = New-Object System.Drawing.Point(355, 287)
    & $StyleBtn $btnLoadFile $global:clrGreen 'Load a .txt file of hosts (one per line) into the input box'
    $btnLoadFile.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
        if ($ofd.ShowDialog() -eq 'OK') {
            $txtHosts.Text = [string]::Join([Environment]::NewLine, (Get-Content $ofd.FileName))
        }
    }.GetNewClosure())

    $btnClearHosts = New-Object System.Windows.Forms.Button
    $btnClearHosts.Text = 'Clear input'
    $btnClearHosts.Size = New-Object System.Drawing.Size(160, 26)
    $btnClearHosts.Location = New-Object System.Drawing.Point(15, 325)
    & $StyleBtn $btnClearHosts $global:clrBtnBG 'Empty the host input box (does NOT remove anything from the grid)'
    $btnClearHosts.Add_Click({ $txtHosts.Text = '' }.GetNewClosure())

    # Helper hint: explain that adding ≠ probing. Operators in v1.2.1 thought
    # rows had to be probed-green to count as "added"; now they are decoupled.
    $lblAddHint = New-Object System.Windows.Forms.Label
    $lblAddHint.Text      = "+ Add saves the host name. Test Reachability (right pane) probes\nWinRM/OS so the right STIGs are auto-selected. You can do either order."
    $lblAddHint.ForeColor = $global:clrDim
    $lblAddHint.Font      = $fontSmall
    $lblAddHint.AutoSize  = $false
    $lblAddHint.Size      = New-Object System.Drawing.Size(490, 32)
    $lblAddHint.Location  = New-Object System.Drawing.Point(15, 360)

    # Persistence indicator — shows when Targets.json is loaded/saved so the
    # operator can see at a glance that their list survives across launches.
    $lblPersist = New-Object System.Windows.Forms.Label
    $lblPersist.Text      = 'Targets persist across sessions in Workspace\Targets.json.'
    $lblPersist.ForeColor = $global:clrCyan
    $lblPersist.Font      = $fontSmall
    $lblPersist.AutoSize  = $false
    $lblPersist.Size      = New-Object System.Drawing.Size(490, 16)
    $lblPersist.Location  = New-Object System.Drawing.Point(15, 408)

    $btnTestReach = New-Object System.Windows.Forms.Button
    $btnTestReach.Text = 'Test Reachability'
    $btnTestReach.Size = New-Object System.Drawing.Size(220, 38)
    $btnTestReach.Font = $fontBigBtn
    $btnTestReach.Location = New-Object System.Drawing.Point(15, 440)
    & $StyleBtn $btnTestReach $global:clrOrange 'TCP 5985/445 probe + WinRM + OS detect across all listed targets'

    $btnRemoveSelected = New-Object System.Windows.Forms.Button
    $btnRemoveSelected.Text = 'Remove selected'
    $btnRemoveSelected.Size = New-Object System.Drawing.Size(160, 30)
    $btnRemoveSelected.Location = New-Object System.Drawing.Point(245, 444)
    & $StyleBtn $btnRemoveSelected $global:clrRed 'Remove the rows whose Select checkbox is ticked from the grid'

    $lblReachStatus = & $MakeLbl '' 15 488 490 $global:clrCyan
    $grpHosts.Controls.AddRange(@($lblHowTo, $lblPaste, $txtHosts, $btnAddTargets, $btnAddThis, $btnLoadFile, $btnClearHosts, $lblAddHint, $lblPersist, $btnTestReach, $btnRemoveSelected, $lblReachStatus))

    # v1.2.12: Discovered Targets fills all remaining space to the right
    # of the Add Hosts column. Dock=Fill on the group + Dock=Fill on the
    # grid (with Padding margin) so the layout is computed by WinForms
    # and doesn't depend on Anchor distances captured at add-time
    # against a still-unsized TabPage.
    $grpDiscovered = & $MakeGB 'Discovered Targets' 555 15 640 580
    $grpDiscovered.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpDiscovered.Padding = New-Object System.Windows.Forms.Padding(15)
    $gridTargets = New-Object System.Windows.Forms.DataGridView
    $gridTargets.Dock = [System.Windows.Forms.DockStyle]::Fill
    $gridTargets.MultiSelect = $true
    $gridTargets.ScrollBars  = [System.Windows.Forms.ScrollBars]::Both
    & $StyleGrid $gridTargets

    # v1.2.14: checkbox column is fixed-width — just enough for the box
    # itself. AutoSizeMode=None opts out of the grid's Fill layout so
    # this column stays at exactly 30px regardless of grid width, and
    # the remaining columns share the rest via FillWeight.
    $colSelect = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colSelect.HeaderText   = ''
    $colSelect.Name         = 'Select'
    $colSelect.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::None
    $colSelect.Width        = 30
    $colSelect.MinimumWidth = 30
    $colSelect.Resizable    = [System.Windows.Forms.DataGridViewTriState]::False
    $colSelect.ReadOnly     = $false
    [void]$gridTargets.Columns.Add($colSelect)
    # v1.2.11: bumped FillWeights + MinimumWidths so headers like
    # "Online" / "WinRM" / "Last Scan" / "STIG Applies" no longer clip
    # to "Onli" / "WinF" / "Last Sca" on a 1366x768 laptop screen.
    # MinimumWidth wins over FillWeight when the grid is narrow, so a
    # cramped form still shows full headers.
    # v1.2.14: bumped Error FillWeight 16->24 + MinimumWidth 120->220 so
    # operators can read TCP probe / WinRM error text without scrolling
    # horizontally. Other columns rebalanced so OS / STIG Applies still
    # fit on a 1366-wide display when the grid is split with Add Hosts.
    foreach ($colDef in @(
        @{ N='Host';     H='Host';         W=11; M=100 },
        @{ N='Online';   H='Online';       W=7;  M=64  },
        @{ N='WinRM';    H='WinRM';        W=7;  M=64  },
        @{ N='OS';       H='OS';           W=18; M=170 },
        @{ N='Role';     H='Role';         W=9;  M=88  },
        @{ N='Tech';     H='STIG Applies'; W=22; M=190 },
        @{ N='LastScan'; H='Last Scan';    W=10; M=84  },
        @{ N='Error';    H='Error';        W=24; M=220 }
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name = $colDef.N; $c.HeaderText = $colDef.H
        $c.FillWeight = $colDef.W; $c.MinimumWidth = $colDef.M
        $c.ReadOnly = $true
        [void]$gridTargets.Columns.Add($c)
    }

    # Error cells are often long (WSManFault XML, PowerShell errors) — the
    # cell renders truncated with "..." but double-click opens the full
    # message in a copyable dialog so the operator can paste it for
    # diagnosis. Tooltip also shows the full text on hover.
    $gridTargets.Add_CellMouseEnter({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
        $col = $gridTargets.Columns[$e.ColumnIndex]
        if ($col.Name -eq 'Error' -or $col.Name -eq 'Tech' -or $col.Name -eq 'OS') {
            $val = [string]$gridTargets.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
            $cell = $gridTargets.Rows[$e.RowIndex].Cells[$e.ColumnIndex]
            $cell.ToolTipText = if ($val) { $val } else { '' }
        }
    }.GetNewClosure())
    $gridTargets.Add_CellDoubleClick({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
        $col = $gridTargets.Columns[$e.ColumnIndex]
        # Only open the dialog for the Error / Tech / OS columns (the ones
        # likely to be truncated). Double-click on Select toggles the box.
        if ($col.Name -notin 'Error','Tech','OS') { return }
        $hostName = [string]$gridTargets.Rows[$e.RowIndex].Cells['Host'].Value
        $val      = [string]$gridTargets.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
        if (-not $val) { return }
        Show-StigCopyableError -Severity 'Info' -Title "$hostName - $($col.HeaderText)" -Message $val
    }.GetNewClosure())

    # Commit the checkbox toggle IMMEDIATELY on click. Without this, WinForms
    # holds the edit in "dirty" state until the user leaves the cell, and the
    # Select column's value reads stale when Start Scan iterates the grid.
    $gridTargets.Add_CurrentCellDirtyStateChanged({
        if ($gridTargets.IsCurrentCellDirty -and $gridTargets.CurrentCell -is [System.Windows.Forms.DataGridViewCheckBoxCell]) {
            $gridTargets.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    }.GetNewClosure())

    $grpDiscovered.Controls.Add($gridTargets)

    # GRID-SYNC HELPER: re-render the grid from $global:Targets and persist.
    # Called after every add / remove / probe. Defined as a closure so the
    # Add / Remove / Test handlers below can reuse it without re-walking the
    # tab-build tree to find $gridTargets / $lblReachStatus.
    $SyncGrid = {
        $gridTargets.Rows.Clear()
        if (-not $global:Targets -or $global:Targets.Count -eq 0) {
            return
        }
        foreach ($t in $global:Targets) {
            $techDisplay =
                if ($t.Technologies -and $t.Technologies.Count -gt 0) {
                    $names = foreach ($k in $t.Technologies) {
                        $tech = $global:SupportedTechnologies | Where-Object Key -EQ $k | Select-Object -First 1
                        if ($tech) { $tech.Display } else { $k }
                    }
                    $names -join ', '
                } elseif ($t.Role -and $t.Role -ne 'Unknown') {
                    '(no STIGs for this role)'
                } else {
                    '(probe to detect role)'
                }
            $online = if ($t.ProbedAt) { if ($t.Online) { 'YES' } else { 'no' } } else { '?' }
            $winrm  = if ($t.ProbedAt) { if ($t.WinRM)  { 'YES' } else { 'no' } } else { '?' }
            [void]$gridTargets.Rows.Add(
                $true, $t.Host, $online, $winrm,
                $(if ($t.OS) { $t.OS } else { '' }),
                $(if ($t.Role) { $t.Role } else { '' }),
                $techDisplay,
                $(if ($t.LastScan) { $t.LastScan } else { 'never' }),
                $(if ($t.Error) { $t.Error } else { '' })
            )
        }
        try { Save-StigTargets } catch {}
        try { Update-StigScanHostPicker } catch {}
    }.GetNewClosure()
    # Render any rows that were loaded from Targets.json on startup so the
    # operator sees their persisted fleet immediately, without having to
    # click Test Reachability first.
    & $SyncGrid

    # + Add to list — adds typed hosts straight into the grid + $global:Targets
    # without probing. Lets the operator build the list incrementally and
    # decouples "i want this host tracked" from "i can reach it right now".
    $btnAddTargets.Add_Click({
        $hosts = @($txtHosts.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (-not $hosts) {
            Show-StigCopyableError -Severity 'Warning' -Title 'No hosts entered' -Message 'Type or paste one or more host names (one per line) into the box above before clicking + Add to list.'
            return
        }
        # HOSTNAME ALLOW-LIST (added in v1.2.3). Operator-typed hostnames
        # flow into New-StigDscConfigFile (.ps1 generation), Invoke-Command
        # ComputerName, and Join-Path target paths. Reject anything outside
        # the RFC-1123 hostname charset before it reaches any of those.
        # PS 5.1 closure-scope quirk: inside a .GetNewClosure() handler,
        # `$global:Targets += @{...}` can resolve $global:Targets as $null
        # (closure capture mismatch), and `$null + @{...}` collapses to the
        # bare hashtable. Result: $global:Targets becomes a single hashtable
        # whose .Count returns 9 (key count), not the array we wanted.
        # Fix: build the new array in a local first, then write the assembled
        # array back to $global:Targets in one shot. The @($global:Targets)
        # cast guarantees array semantics even if the read returns null.
        $local = @($global:Targets)
        $existing = @{}
        foreach ($t in $local) { if ($t.Host) { $existing[$t.Host.ToLower()] = $true } }
        $added = 0; $dupes = 0; $bad = @()
        foreach ($h in $hosts) {
            if ($h -notmatch '^[A-Za-z0-9._-]{1,253}$') { $bad += $h; continue }
            if ($existing.ContainsKey($h.ToLower())) { $dupes++; continue }
            $local += ,@{
                Host         = $h
                Online       = $false
                WinRM        = $false
                OS           = ''
                Role         = ''
                Technologies = @()
                Error        = ''
                LastScan     = 'never'
                ProbedAt     = ''
            }
            $existing[$h.ToLower()] = $true
            $added++
        }
        $global:Targets = @($local)
        if ($bad.Count -gt 0) {
            Show-StigCopyableError -Severity 'Warning' -Title 'Invalid host name(s) skipped' -Message @"
The following entries were rejected because they do not match a valid
RFC-1123 hostname (letters, digits, dots, dashes, underscores; 1-253
chars). Most likely cause: stray quote, slash, or whitespace pasted
in from a spreadsheet.

Rejected:
$(($bad | ForEach-Object { "  $_" }) -join "`n")
"@
        }
        $txtHosts.Text = ''
        & $SyncGrid
        $msg = "Added $added host(s)."
        if ($dupes -gt 0) { $msg += " Skipped $dupes duplicate(s)." }
        if ($bad.Count -gt 0) { $msg += " Rejected $($bad.Count) invalid name(s)." }
        $msg += '  Click Test Reachability to probe role/OS.'
        $lblReachStatus.Text = $msg
        Write-Audit -Event 'TargetsAdded' -Details "added=$added dupes=$dupes total=$($global:Targets.Count)"
    }.GetNewClosure())

    # Remove selected — drops the rows whose Select checkbox is ticked from
    # both the grid and $global:Targets. Confirm dialog because there is no
    # undo (the persisted Targets.json is overwritten by the Save below).
    $btnRemoveSelected.Add_Click({
        $toRemove = @()
        for ($i = 0; $i -lt $gridTargets.Rows.Count; $i++) {
            $val = $gridTargets.Rows[$i].Cells['Select'].Value
            if ($val -eq $true) {
                $toRemove += [string]$gridTargets.Rows[$i].Cells['Host'].Value
            }
        }
        if (-not $toRemove) {
            Show-StigCopyableError -Severity 'Warning' -Title 'Nothing selected' -Message 'Tick the Select checkbox on one or more rows in the grid before clicking Remove selected.'
            return
        }
        $confirm = [System.Windows.Forms.MessageBox]::Show("Remove $($toRemove.Count) target(s) from the list?`n`n$($toRemove -join "`n")", 'Remove targets', 'YesNo', 'Question')
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $global:Targets = @($global:Targets | Where-Object { $toRemove -notcontains $_.Host })
        & $SyncGrid
        $lblReachStatus.Text = "Removed $($toRemove.Count) target(s)."
        Write-Audit -Event 'TargetsRemoved' -Details "count=$($toRemove.Count) hosts=$($toRemove -join ',')"
    }.GetNewClosure())

    $btnTestReach.Add_Click({
        try {
            # Auto-add anything still sitting in the input box so operators
            # who paste + click Test Reachability (the v1.2.1 muscle memory)
            # don't lose those hosts.
            $newHosts = @($txtHosts.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($newHosts.Count -gt 0) { $btnAddTargets.PerformClick() }

            if (-not $global:Targets -or $global:Targets.Count -eq 0) {
                Show-StigCopyableError -Severity 'Warning' -Title 'No targets to probe' -Message 'Add hosts to the list first using "+ Add to list" (or paste names and click Test Reachability — they will be added automatically).'
                return
            }

            # LOCAL MODE GUARD: In Local mode we scan only this machine. If
            # the list contains anything else, reject upfront so we don't
            # silently report local OS info for remote hostnames.
            if ($global:ExecutionMode -eq 'Local') {
                $localRefs = @($env:COMPUTERNAME, "$env:COMPUTERNAME.$env:USERDNSDOMAIN", 'localhost', '127.0.0.1', '::1', '.')
                $nonLocal  = @($global:Targets | Where-Object { $_.Host -notin $localRefs })
                if ($nonLocal.Count -gt 0) {
                    $msg = @"
Local mode scans only the machine this tool is running on:
  $env:COMPUTERNAME

The following target(s) are NOT this machine:
$(($nonLocal | ForEach-Object { "  $($_.Host)" }) -join "`n")

Choose one:

  1. Scan THIS machine only
     - Tick those rows in the grid and click Remove selected
     - Make sure $env:COMPUTERNAME is in the list (use Add this machine)
     - Click Test Reachability again

  2. Scan the typed host(s) over the network
     - Go to About tab -> switch mode to Remote (PSRemoting / WinRM)
     - Click "Set Credentials" and enter an account with admin rights
       on the target(s)
     - Return here and click Test Reachability

Local mode was selected on the About tab. No reachability test was
performed.
"@
                    Show-StigCopyableError -Severity 'Warning' -Title 'Local mode scans THIS machine only' -Message $msg
                    return
                }
            }

            $hostsToProbe = @($global:Targets | ForEach-Object { $_.Host })
            $lblReachStatus.Text = "Probing $($hostsToProbe.Count) host(s)..."
            $btnTestReach.Enabled = $false
            [System.Windows.Forms.Application]::DoEvents()

            # TCP-port reachability probe ported from the J.A.N.E.T.
            # Workstation Patching Tool. ICMP (Test-Connection) is blocked on
            # most AFNET workstation firewalls; WinRM (5985) and SMB (445)
            # are usually open. Falling through to TCP makes "Online" mean
            # "I can talk to the management plane" instead of "ping replied".
            $sb = {
                param($h, $cred, $mode)
                try {
                    $o = [ordered]@{ Host=$h; Online=$false; WinRM=$false; OS=$null; Role=$null; Error=$null }
                    if ($mode -eq 'Local') {
                        # Local mode uses CIM/DCOM (then WMI) directly — no
                        # WinRM dependency for THIS machine's OS info.
                        $cimSession = $null
                        try {
                            $opt = New-CimSessionOption -Protocol Dcom
                            $cimSession = New-CimSession -SessionOption $opt -ErrorAction Stop
                            $ci = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop
                            $o.Online = $true; $o.WinRM = $true; $o.OS = $ci.Caption
                            switch ([int]$ci.ProductType) {
                                1 {$o.Role='Workstation'}
                                2 {$o.Role='DomainController'}
                                3 {$o.Role='MemberServer'}
                                default {$o.Role='Unknown'}
                            }
                        } catch {
                            try {
                                $wmi = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                                $o.Online = $true; $o.WinRM = $true; $o.OS = $wmi.Caption
                                switch ([int]$wmi.ProductType) {
                                    1 {$o.Role='Workstation'}
                                    2 {$o.Role='DomainController'}
                                    3 {$o.Role='MemberServer'}
                                    default {$o.Role='Unknown'}
                                }
                            } catch {
                                $o.Error = "Local OS detection failed (CIM/DCOM and WMI both errored): $($_.Exception.Message)"
                            }
                        } finally {
                            if ($cimSession) { try { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue } catch {} }
                        }
                    } else {
                        # REMOTE: TCP probe to 5985 then 445 (1.5s each).
                        $reachable = $false; $reachPort = $null
                        foreach ($port in @(5985, 445)) {
                            $client = $null
                            try {
                                $client = New-Object System.Net.Sockets.TcpClient
                                $iar = $client.BeginConnect($h, $port, $null, $null)
                                if ($iar.AsyncWaitHandle.WaitOne(1500, $false)) {
                                    try { $client.EndConnect($iar) } catch { continue }
                                    if ($client.Connected) {
                                        $reachable = $true; $reachPort = $port; break
                                    }
                                }
                            } catch {} finally {
                                if ($client) { try { $client.Close() } catch {} }
                            }
                        }
                        $o.Online = $reachable
                        if ($reachable -and $reachPort -eq 5985) {
                            # WinRM is responding — pull OS info via a bounded PSSession
                            # using Negotiate so Kerberos preferred, NTLM fallback works.
                            $sess = $null
                            try {
                                $sopt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
                                $sp = @{ ComputerName = $h; ErrorAction = 'Stop'; Authentication = 'Negotiate'; SessionOption = $sopt }
                                if ($cred) { $sp.Credential = $cred }
                                $sess = New-PSSession @sp
                                $o.WinRM = $true
                                $ci = Invoke-Command -Session $sess -ScriptBlock { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, ProductType }
                                if ($ci) {
                                    $o.OS = $ci.Caption
                                    switch ([int]$ci.ProductType) {
                                        1 {$o.Role='Workstation'}
                                        2 {$o.Role='DomainController'}
                                        3 {$o.Role='MemberServer'}
                                        default {$o.Role='Unknown'}
                                    }
                                }
                            } catch {
                                $o.Error = "WinRM open but session/CIM failed: $($_.Exception.Message)"
                            } finally {
                                if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
                            }
                        } elseif ($reachable -and $reachPort -eq 445) {
                            $o.Error = 'TCP 445 (SMB) is open but WinRM (5985) is not — cannot run STIG scans without WinRM. Run "Repair WinRM" via Group Policy or winrm quickconfig on the target.'
                        } else {
                            $o.Error = 'TCP 5985 (WinRM) and 445 (SMB) both timed out (1.5s each). Host is offline, blocked by firewall, or DNS does not resolve.'
                        }
                    }
                    return $o
                } catch {
                    return [ordered]@{ Host=$h; Online=$false; WinRM=$false; OS=$null; Role=$null; Error=$_.Exception.Message }
                }
            }

            $jobs = @()
            foreach ($h in $hostsToProbe) {
                $jobs += [pscustomobject]@{ Host = $h; Job = (Invoke-ParallelJob -ScriptBlock $sb -Arguments @($h, $global:RemoteCred, $global:ExecutionMode)) }
            }

            # Update each existing target hashtable in-place so unprobed rows
            # (and any row metadata we don't want to clobber) are preserved.
            $byHost = @{}
            foreach ($t in $global:Targets) { $byHost[$t.Host] = $t }
            $okCount = 0
            foreach ($j in $jobs) {
                $o = $null
                $jobErr = $null
                try {
                    $r = $j.Job.PS.EndInvoke($j.Job.Handle)
                    # Surface PowerShell error-stream messages from the runspace
                    # — without this, a script-block that threw would set $r to
                    # empty and the host would silently appear "offline,
                    # no-error", obscuring real probe-code crashes.
                    if ($j.Job.PS.HadErrors -and $j.Job.PS.Streams.Error.Count -gt 0) {
                        $jobErr = ($j.Job.PS.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
                    }
                    if ($r -and $r.Count -gt 0) {
                        $o = $r[0]
                    } else {
                        $o = [ordered]@{
                            Host = $j.Host; Online = $false; WinRM = $false
                            OS = $null; Role = $null
                            Error = $(if ($jobErr) { "Probe runspace error: $jobErr" } else { 'Probe returned no result' })
                        }
                    }
                    if ($jobErr -and -not $o.Error) { $o.Error = "Probe runspace error: $jobErr" }
                    $techs = @(Get-TechnologiesForRole -Role $o.Role)
                    $techKeys = @($techs | ForEach-Object { $_.Key })
                    $lastScanText = 'never'
                    try {
                        $evalHostDir = Join-Path $global:EvalRoot $o.Host
                        if (Test-Path $evalHostDir) {
                            $latest = Get-ChildItem -Path $evalHostDir -Recurse -Filter 'evaluation.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                            if ($latest) {
                                $age = (Get-Date) - $latest.LastWriteTime
                                $days = [int]$age.TotalDays
                                if ($days -ge 90)    { $lastScanText = "OVERDUE (${days}d)" }
                                elseif ($days -gt 0) { $lastScanText = "${days}d ago" }
                                elseif ($age.TotalHours -ge 1) { $lastScanText = "$([int]$age.TotalHours)h ago" }
                                else                 { $lastScanText = "$([int]$age.TotalMinutes)m ago" }
                            }
                        }
                    } catch {}
                    $existing = $byHost[$o.Host]
                    if ($existing) {
                        $existing.Online       = [bool]$o.Online
                        $existing.WinRM        = [bool]$o.WinRM
                        $existing.OS           = [string]$o.OS
                        $existing.Role         = [string]$o.Role
                        $existing.Technologies = $techKeys
                        $existing.Error        = [string]$o.Error
                        $existing.LastScan     = $lastScanText
                        $existing.ProbedAt     = (Get-Date).ToString('o')
                    } else {
                        # Same closure-scope quirk as the Add-to-list handler:
                        # build via a local, write back as @(array). Avoids the
                        # "$global:Targets becomes a bare hashtable" failure.
                        $local = @($global:Targets)
                        $local += ,@{
                            Host = $o.Host; Online = [bool]$o.Online; WinRM = [bool]$o.WinRM
                            OS = [string]$o.OS; Role = [string]$o.Role
                            Technologies = $techKeys; Error = [string]$o.Error
                            LastScan = $lastScanText; ProbedAt = (Get-Date).ToString('o')
                        }
                        $global:Targets = @($local)
                    }
                    if ($o.WinRM) { $okCount++ }
                } catch {
                    # EndInvoke itself threw (e.g. runspace torn down between
                    # BeginInvoke and EndInvoke). Record on the existing row
                    # so the operator sees a useful error instead of "(no
                    # OS, no role, no message)" silence.
                    $existing = $byHost[$j.Host]
                    if ($existing) {
                        $existing.Error    = "EndInvoke failed: $($_.Exception.Message)"
                        $existing.Online   = $false
                        $existing.WinRM    = $false
                        $existing.ProbedAt = (Get-Date).ToString('o')
                    }
                } finally {
                    try { $j.Job.PS.Dispose() } catch {}
                }
            }
            & $SyncGrid
            $btnTestReach.Enabled = $true
            $unreachable = $jobs.Count - $okCount
            $lblReachStatus.Text = "Probed $($jobs.Count) host(s) — $okCount OK, $unreachable unreachable. Hop to the Scan tab to evaluate."
            Write-Audit -Event 'TargetsDiscovered' -Details "count=$($global:Targets.Count) reachable=$okCount unreachable=$unreachable"
        } catch {
            $btnTestReach.Enabled = $true
            # Unexpected error at the handler level — surface it copyably so
            # the operator can paste it into a ticket or search it.
            Show-StigCopyableError -Title 'Test Reachability error' -Message @"
An unexpected error occurred while running Test Reachability.

Error:
$($_.Exception.Message)

Type:
$($_.Exception.GetType().FullName)

ScriptStackTrace:
$($_.ScriptStackTrace)

InvocationInfo:
Line $($_.InvocationInfo.ScriptLineNumber) of $($_.InvocationInfo.ScriptName)
$($_.InvocationInfo.Line)
"@
        }
    }.GetNewClosure())

    # v1.2.13: Dock-Fill control must be added FIRST so it docks LAST.
    # WinForms processes Dock in reverse Z-order; if Fill is added last
    # it docks first and claims everything, hiding sibling Dock=Left
    # controls behind it. Add order: Fill then Left.
    $tabTargets.Controls.AddRange(@($grpDiscovered, $grpHosts))
#endregion

#region ------------------------ TAB: SCAN -------------------------------
    $tabScan = New-Object System.Windows.Forms.TabPage
    $tabScan.Text = '  Scan (Evaluate)  '
    $tabScan.BackColor = $global:clrBG; $tabScan.ForeColor = $global:clrWhite
    # v1.2.12: Padding so docked children don't sit flush with the tab edge.
    $tabScan.Padding = New-Object System.Windows.Forms.Padding(15)

    # SCAN CONTROLS card — Start button, status, progress bar
    $grpScanCtl = & $MakeGB 'Scan Controls' 15 15 1180 150
    # v1.2.12: Dock=Top with fixed height; Hosts/Summary panels below
    # split horizontally via Dock=Left + Dock=Fill so they grow with
    # the form regardless of when the TabPage gets sized.
    $grpScanCtl.Dock   = [System.Windows.Forms.DockStyle]::Top
    $grpScanCtl.Height = 150
    # Row 1 (y=25): info label spanning the card
    $lblScanInfo = New-Object System.Windows.Forms.Label
    $lblScanInfo.Text = 'Technologies auto-selected per host role. Pin a specific DISA STIG version below to lock reproducibility across scans.'
    $lblScanInfo.ForeColor = $global:clrWhite; $lblScanInfo.Font = $fontSmall
    $lblScanInfo.AutoSize = $true
    $lblScanInfo.Location = New-Object System.Drawing.Point(15, 25)

    # Row 2 (y=46): Start Scan button on the left, STIG version pickers right
    $btnScanStart = New-Object System.Windows.Forms.Button
    $btnScanStart.Text = 'Start Scan'
    $btnScanStart.Size = New-Object System.Drawing.Size(200, 58)
    $btnScanStart.Font = $fontBigBtn
    $btnScanStart.Location = New-Object System.Drawing.Point(15, 46)
    & $StyleBtn $btnScanStart $global:clrGreen 'Compile MOF and run Test-DscConfiguration on selected targets'

    # STIG version pinning dropdowns — one per supported technology.
    # Populating from Get-StigVersionList (queries Get-StigList). If the
    # user picks an explicit version, the scan compiles against THAT version
    # instead of PowerStig's latest. Required for audit reproducibility
    # (quarterly scans must pin to the DISA release in effect at audit time).
    $global:StigVersionPins = @{}
    $stigVerX = 230
    $stigVerY = 46
    $stigVerW = 220
    foreach ($tech in $global:SupportedTechnologies) {
        $lblVer = New-Object System.Windows.Forms.Label
        $lblVer.Text      = $tech.Display
        $lblVer.ForeColor = $global:clrDim
        $lblVer.Font      = $fontSmall
        $lblVer.AutoSize  = $false
        $lblVer.Size      = New-Object System.Drawing.Size($stigVerW, 14)
        $lblVer.Location  = New-Object System.Drawing.Point($stigVerX, $stigVerY)

        $cboVer = New-Object System.Windows.Forms.ComboBox
        $cboVer.DropDownStyle = 'DropDownList'
        $cboVer.BackColor = $global:clrInputBG
        $cboVer.ForeColor = $global:clrWhite
        $cboVer.Font      = $fontMono
        $cboVer.Location  = New-Object System.Drawing.Point($stigVerX, ($stigVerY + 16))
        $cboVer.Size      = New-Object System.Drawing.Size($stigVerW, 22)
        [void]$cboVer.Items.Add('(latest installed)')
        foreach ($v in (Get-StigVersionList -Technology $tech.Key)) {
            [void]$cboVer.Items.Add($v)
        }
        $cboVer.SelectedIndex = 0
        $cboVer.Tag = $tech.Key
        $cboVer.Add_SelectedIndexChanged({
            $k = $this.Tag
            $v = $this.SelectedItem
            if ($v -eq '(latest installed)' -or -not $v) {
                $global:StigVersionPins.Remove($k) | Out-Null
            } else {
                $global:StigVersionPins[$k] = [string]$v
            }
        }.GetNewClosure())
        $grpScanCtl.Controls.AddRange(@($lblVer, $cboVer))
        $stigVerX += ($stigVerW + 8)
    }

    # Status label fills the left half of the row.
    # Row 3 (y=112): status text + progress bar below Start Scan and dropdowns
    $lblScanStatus = & $MakeLbl '' 15 120 720 $global:clrCyan
    $lblScanStatus.Font = $fontMono

    # Custom progress bar: hand-drawn on a Panel instead of using a
    # native ProgressBar (which ignores BackColor/ForeColor under Visual
    # Styles and renders as a jarring white rectangle against the dark bg).
    # In its empty state, the panel blends into the card background.
    # As the scan advances, a filled purple bar grows from left to right
    # with the percentage in Cascadia Mono centered on top.
    #
    # State held on the panel itself: .Tag = @{ Value=0; Maximum=1 }
    # Rendering via Paint handler reads .Tag and draws the bar each repaint.
    $pnlProgress = New-Object System.Windows.Forms.Panel
    $pnlProgress.Location  = New-Object System.Drawing.Point(740, 116)
    $pnlProgress.Size      = New-Object System.Drawing.Size(420, 22)
    $pnlProgress.BackColor = $global:clrInputBG      # blends with the card in empty state
    $pnlProgress.Tag       = @{ Value = 0; Maximum = 1 }
    # Paint handler uses LITERAL Color values — NOT $global: references.
    # Event handler closures can't reliably resolve $global: vars in all
    # rendering contexts (Paint fires from the Win32 message pump which
    # runs in a scope where $global: lookups return null). Hardcoding the
    # RGB values here makes this handler self-contained and bulletproof.
    $pnlProgress.Add_Paint({
        param($sender, $e)
        $g   = $e.Graphics
        $tag = $sender.Tag
        if (-not $tag) { return }
        $max = [Math]::Max(1, [int]$tag.Maximum)
        $val = [int]$tag.Value
        $pct = [Math]::Max(0.0, [Math]::Min(1.0, $val / $max))
        $w   = $sender.ClientSize.Width
        $h   = $sender.ClientSize.Height

        # Thin border — literal clrBorder (#22252D)
        $borderPen = New-Object System.Drawing.Pen(([System.Drawing.Color]::FromArgb(34, 37, 45)), 1)
        $g.DrawRectangle($borderPen, 0, 0, ($w - 1), ($h - 1))
        $borderPen.Dispose()

        # Purple fill -- literal clrCyan (#8478E0)
        if ($pct -gt 0.0) {
            $fillW = [int]([Math]::Max(2, [Math]::Floor(($w - 2) * $pct)))
            $brushFill = New-Object System.Drawing.SolidBrush(([System.Drawing.Color]::FromArgb(132, 120, 224)))
            $g.FillRectangle($brushFill, 1, 1, $fillW, ($h - 2))
            $brushFill.Dispose()
        }

        # Percentage text
        $pctText = "{0}%" -f [int]([Math]::Round($pct * 100))
        try { $pctFont = New-Object System.Drawing.Font('Cascadia Mono', 8, [System.Drawing.FontStyle]::Bold) }
        catch { $pctFont = New-Object System.Drawing.Font('Consolas', 8, [System.Drawing.FontStyle]::Bold) }
        # Dark on accent when >40% filled; dim gray (#A0A5AE) when empty
        $textColor = if ($pct -gt 0.4) {
            [System.Drawing.Color]::FromArgb(12, 9, 3)
        } else {
            [System.Drawing.Color]::FromArgb(160, 165, 174)
        }
        $brushText = New-Object System.Drawing.SolidBrush($textColor)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment     = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
        $rect = New-Object System.Drawing.RectangleF(0, 0, $w, $h)
        $g.DrawString($pctText, $pctFont, $brushText, $rect, $sf)
        $brushText.Dispose()
        $pctFont.Dispose()
        $sf.Dispose()
    }.GetNewClosure())
    $global:prgScanRef = $pnlProgress

    $grpScanCtl.Controls.AddRange(@($lblScanInfo, $btnScanStart, $lblScanStatus, $pnlProgress))

    # HOST PICKER card — CheckedListBox of hosts discovered on the Targets tab
    # with Select All / Select None / Refresh From Targets buttons. This gives
    # operators a visible confirmation of what they're about to scan WITHOUT
    # needing to flip back to the Targets tab. Re-populates on tab entry.
    $grpScanHosts = & $MakeGB 'Hosts to Scan' 15 175 380 430
    # v1.2.12: Dock=Left with fixed Width, Compliance Summary fills rest.
    $grpScanHosts.Dock  = [System.Windows.Forms.DockStyle]::Left
    $grpScanHosts.Width = 380
    $lblHostPickHelp = New-Object System.Windows.Forms.Label
    $lblHostPickHelp.Text      = 'Check one or more hosts. Refresh pulls the latest from the Targets tab.'
    $lblHostPickHelp.ForeColor = $global:clrDim
    $lblHostPickHelp.Font      = $fontSmall
    $lblHostPickHelp.AutoSize  = $false
    $lblHostPickHelp.Size      = New-Object System.Drawing.Size(350, 30)
    $lblHostPickHelp.Location  = New-Object System.Drawing.Point(15, 28)
    $grpScanHosts.Controls.Add($lblHostPickHelp)

    $clbScanHosts = New-Object System.Windows.Forms.CheckedListBox
    $clbScanHosts.Location        = New-Object System.Drawing.Point(15, 62)
    $clbScanHosts.Size            = New-Object System.Drawing.Size(350, 290)
    $clbScanHosts.BackColor       = $global:clrInputBG
    $clbScanHosts.ForeColor       = $global:clrWhite
    $clbScanHosts.Font            = $fontMono
    $clbScanHosts.BorderStyle     = 'FixedSingle'
    $clbScanHosts.CheckOnClick    = $true
    $clbScanHosts.IntegralHeight  = $false
    # Exposed at script scope so Update-StigScanHostPicker (defined at
    # script level below) can refresh it from any event handler scope.
    $global:clbScanHostsRef = $clbScanHosts
    $grpScanHosts.Controls.Add($clbScanHosts)

    $btnScanRefresh = New-Object System.Windows.Forms.Button
    $btnScanRefresh.Text = 'Refresh'
    $btnScanRefresh.Size = New-Object System.Drawing.Size(110, 28)
    $btnScanRefresh.Location = New-Object System.Drawing.Point(15, 364)
    & $StyleBtn $btnScanRefresh $global:clrCyan 'Re-pull host list from the Targets tab'

    $btnScanAll = New-Object System.Windows.Forms.Button
    $btnScanAll.Text = 'Check All'
    $btnScanAll.Size = New-Object System.Drawing.Size(110, 28)
    $btnScanAll.Location = New-Object System.Drawing.Point(135, 364)
    & $StyleBtn $btnScanAll $global:clrBtnBG ''

    $btnScanNone = New-Object System.Windows.Forms.Button
    $btnScanNone.Text = 'Uncheck All'
    $btnScanNone.Size = New-Object System.Drawing.Size(110, 28)
    $btnScanNone.Location = New-Object System.Drawing.Point(255, 364)
    & $StyleBtn $btnScanNone $global:clrBtnBG ''

    # Populate the host picker by calling the real named function
    # Update-StigScanHostPicker (defined near the bottom of this file).
    # Using a NAMED FUNCTION instead of a $global: scriptblock because
    # scriptblock-variable references are not reliably resolvable from
    # inside event handler closures — same issue that previously bit
    # $global:SetActiveTab. Named functions live in the command table
    # and are always findable by name. See line ~2620 for the definition.

    # Wire the Refresh / Check All / Uncheck All buttons
    $btnScanRefresh.Add_Click({ Update-StigScanHostPicker }.GetNewClosure())
    $btnScanAll.Add_Click({
        for ($i = 0; $i -lt $clbScanHosts.Items.Count; $i++) {
            # Only re-check rows that correspond to hosts with applicable STIGs.
            # Rows labelled "(no applicable STIGs)" stay unchecked — can't scan those.
            $text = [string]$clbScanHosts.Items[$i]
            if ($text -notmatch 'no applicable STIGs' -and $text -notmatch 'no hosts discovered') {
                $clbScanHosts.SetItemChecked($i, $true)
            }
        }
    }.GetNewClosure())
    $btnScanNone.Add_Click({
        for ($i = 0; $i -lt $clbScanHosts.Items.Count; $i++) {
            $clbScanHosts.SetItemChecked($i, $false)
        }
    }.GetNewClosure())

    # Auto-refresh the picker every time the Scan tab becomes visible so
    # it always reflects the latest Test-Reachability result from Targets.
    $tabScan.Add_Enter({ Update-StigScanHostPicker }.GetNewClosure())

    $grpScanHosts.Controls.AddRange(@($btnScanRefresh, $btnScanAll, $btnScanNone))

    # COMPLIANCE SUMMARY card shifts right next to the host picker
    # v1.2.12: Dock=Fill — takes remaining space after Scan Controls
    # (Top) and Hosts to Scan (Left) have docked. No anchor math.
    # v1.2.14: a Scan Log textbox is docked Bottom inside this group so
    # operators can see what compile / Test-DscConfiguration is doing
    # in real time, copy errors out of it, etc. The compliance grid
    # still Docks Fill above the log.
    $grpScanGrid = & $MakeGB 'Compliance Summary' 405 175 790 430
    $grpScanGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpScanGrid.Padding = New-Object System.Windows.Forms.Padding(15)

    # Scan Log — selectable, copyable, mono. WinForms TextBox already
    # supports highlight + Ctrl+C / right-click Copy by default.
    $txtScanLog = New-Object System.Windows.Forms.TextBox
    $txtScanLog.Multiline   = $true
    $txtScanLog.ReadOnly    = $true
    $txtScanLog.ScrollBars  = [System.Windows.Forms.ScrollBars]::Vertical
    $txtScanLog.Font        = $fontMono
    $txtScanLog.BackColor   = $global:clrInputBG
    $txtScanLog.ForeColor   = $global:clrWhite
    $txtScanLog.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtScanLog.WordWrap    = $false
    $txtScanLog.Dock        = [System.Windows.Forms.DockStyle]::Bottom
    $txtScanLog.Height      = 200
    $txtScanLog.HideSelection = $false   # keep highlight visible when focus moves
    # Right-click context menu for Copy / Select All — TextBox auto-
    # provides one but we override so the items are unambiguous.
    $cmsScanLog = New-Object System.Windows.Forms.ContextMenuStrip
    $miCopy = $cmsScanLog.Items.Add('Copy')
    $miCopy.Add_Click({
        if (-not [string]::IsNullOrEmpty($txtScanLog.SelectedText)) {
            [System.Windows.Forms.Clipboard]::SetText($txtScanLog.SelectedText)
        }
    }.GetNewClosure())
    $miSelAll = $cmsScanLog.Items.Add('Select All')
    $miSelAll.Add_Click({ $txtScanLog.SelectAll() }.GetNewClosure())
    $miCopyAll = $cmsScanLog.Items.Add('Copy All')
    $miCopyAll.Add_Click({
        if ($txtScanLog.Text) { [System.Windows.Forms.Clipboard]::SetText($txtScanLog.Text) }
    }.GetNewClosure())
    $cmsScanLog.Items.Add('-') | Out-Null
    $miClear = $cmsScanLog.Items.Add('Clear')
    $miClear.Add_Click({ $txtScanLog.Clear() }.GetNewClosure())
    $txtScanLog.ContextMenuStrip = $cmsScanLog
    $global:txtScanLogRef = $txtScanLog

    # Append-to-log helper. Pass -Tag for color-prefix coding (not yet
    # styled — TextBox can't do per-line color, but the tag prefix lets
    # an operator grep the log later, and a future RichTextBox swap can
    # honor the tags). Auto-scrolls to the bottom and updates the UI
    # so messages appear immediately during long-running runs.
    function global:Write-StigScanLog {
        param([string]$Message, [string]$Tag = 'INFO')
        if (-not $global:txtScanLogRef -or $global:txtScanLogRef.IsDisposed) { return }
        $ts   = (Get-Date).ToString('HH:mm:ss')
        $line = "[$ts] [$Tag] $Message`r`n"
        try {
            $global:txtScanLogRef.AppendText($line)
            $global:txtScanLogRef.SelectionStart  = $global:txtScanLogRef.Text.Length
            $global:txtScanLogRef.ScrollToCaret()
            [System.Windows.Forms.Application]::DoEvents()
        } catch {}
    }

    $gridScan = New-Object System.Windows.Forms.DataGridView
    $gridScan.Dock = [System.Windows.Forms.DockStyle]::Fill
    $gridScan.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    & $StyleGrid $gridScan
    # v1.2.11: bumped FillWeights + MinimumWidths so the wrapped two-line
    # headers ("CAT I Fail", "Weighted %") and the truncated MOF column
    # all fit on a maximized window. Header for "CAT I Fail" needs ~80px
    # in Cascadia Mono Bold, "Weighted %" ~92px, "MOF" path ~140px.
    # v1.2.16: bumped CAT II / CAT III MinimumWidth so headers don't wrap.
    # Cascadia Mono Bold renders "CAT II Fail" / "CAT III Fail" at ~110-118
    # px, so MinimumWidth needs to clear that mark.
    foreach ($cd in @(
        @{N='Host';     H='Host';         W=10; M=100},
        @{N='Tech';     H='Technology';   W=14; M=150},
        @{N='Total';    H='Total';        W=5;  M=58 },
        @{N='Pass';     H='Pass';         W=5;  M=54 },
        @{N='Fail';     H='Fail';         W=5;  M=54 },
        @{N='CatI';     H='CAT I Fail';   W=8;  M=104},
        @{N='CatII';    H='CAT II Fail';  W=8;  M=114},
        @{N='CatIII';   H='CAT III Fail'; W=9;  M=124},
        @{N='Errors';   H='Err';          W=4;  M=46 },
        @{N='Pct';      H='%';            W=4;  M=46 },
        @{N='WPct';     H='Weighted %';   W=8;  M=104},
        @{N='Scanned';  H='Scanned';      W=8;  M=86 },
        @{N='MOF';      H='MOF';          W=30; M=260}
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=$cd.N; $c.HeaderText=$cd.H
        $c.FillWeight=$cd.W; $c.MinimumWidth=$cd.M
        $c.ReadOnly=$true
        [void]$gridScan.Columns.Add($c)
    }
    # Double-click a Scan grid row to drill down into the Review tab for that host.
    # Reads the Host column, switches to Review, populates the dropdown, and
    # selects the clicked host — saving a manual tab-click + dropdown-pick.
    $gridScan.Add_CellDoubleClick({
        param($sender, $e)
        if ($e.RowIndex -lt 0) { return }
        $hostName = $gridScan.Rows[$e.RowIndex].Cells['Host'].Value
        if (-not $hostName) { return }
        # Resolve the tech key from the display text in the grid row
        $techDisplay = $gridScan.Rows[$e.RowIndex].Cells['Tech'].Value
        $techDef = $global:SupportedTechnologies | Where-Object { $_.Display -eq $techDisplay } | Select-Object -First 1
        $techKey = if ($techDef) { $techDef.Key } else { $techDisplay }
        $comboKey = "$hostName | $techKey"
        # Populate the Review dropdown from current scan data
        $cboReviewHost.Items.Clear()
        if ($global:CurrentScan -and $global:CurrentScan.Hosts) {
            foreach ($hr in $global:CurrentScan.Hosts) { [void]$cboReviewHost.Items.Add("$($hr.Host) | $($hr.Technology)") }
        }
        # Select the double-clicked host+tech combo
        $idx = $cboReviewHost.Items.IndexOf($comboKey)
        if ($idx -ge 0) { $cboReviewHost.SelectedIndex = $idx }
        Invoke-StigSetActiveTab -TabRef $tabReview
    }.GetNewClosure())
    # v1.2.14: gridScan added FIRST (lowest Z) so its Dock=Fill claims
    # leftover space; txtScanLog added LAST so Dock=Bottom claims its
    # 200px first. Same reverse-Z-order docking rule from v1.2.13.
    $grpScanGrid.Controls.Add($gridScan)
    $grpScanGrid.Controls.Add($txtScanLog)
    Write-StigScanLog 'Scan log ready. Click Start Scan to begin. Errors and progress updates appear here.' 'INFO'

    $btnScanStart.Add_Click({
        # Safety net: if PrereqStatus was never populated (null), refresh it
        # before the PowerStig check — otherwise we'd spuriously report "no
        # module" just because the status hasn't been initialized yet.
        if (-not $global:PrereqStatus) {
            try { Test-Prerequisites | Out-Null } catch {}
        }
        # Direct re-check right now (don't trust cached status — the operator
        # may have installed PowerStig between form open and clicking Scan).
        $ps = Get-Module -ListAvailable -Name PowerStig -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $ps) {
            Show-StigCopyableError -Title 'PowerStig not detected' -Message @"
PowerStig module was not detected via Get-Module -ListAvailable.

Fix options:
  1. Click "Install Missing Modules" on the About tab (needs PSGallery reachability)
  2. Run: Install-Module PowerStig -Scope CurrentUser -Force
  3. Copy a PowerStig folder into:
     $($env:USERPROFILE)\Documents\WindowsPowerShell\Modules\
  OR: $($env:ProgramFiles)\WindowsPowerShell\Modules\

Then click "Re-check Prerequisites" on the About tab.

PSModulePath:
$($env:PSModulePath -replace ';', "`n")
"@
            return
        }
        # Keep the cached status in sync
        if ($global:PrereqStatus) {
            $global:PrereqStatus.PowerStigInstalled = $true
            $global:PrereqStatus.PowerStigVersion   = $ps.Version.ToString()
        }
        if (-not (Test-StigCredsReady -ActionName 'a scan')) { return }

        # Walk the Targets grid and figure out WHY each host did/didn't qualify.
        # Three fail cases we want to distinguish so the operator sees a real
        # diagnostic instead of a generic "no targets":
        #   (a) grid is empty         -> no hosts loaded / Test Reach not run
        #   (b) grid has rows but no row's "Include" checkbox is ticked
        #   (c) checked rows all got skipped because no applicable STIGs were
        #       detected for their role (usually = reachability/role detect
        #       failed, so Technologies is empty)
        # Read checked items from the Scan-tab host picker (CheckedListBox),
        # not the Targets grid. Each list item's text starts with the
        # hostname; we parse that out and look up the full target record.
        $totalTargets    = $global:Targets.Count
        $checkedItems    = 0
        $skippedDetails  = [System.Collections.ArrayList]::new()
        $selectedTargets = @()
        for ($i = 0; $i -lt $clbScanHosts.Items.Count; $i++) {
            if (-not $clbScanHosts.GetItemChecked($i)) { continue }
            $checkedItems++
            $text = [string]$clbScanHosts.Items[$i]
            # Parse hostname: everything before the first "  [" separator
            $idx = $text.IndexOf('  [')
            $hostName = if ($idx -gt 0) { $text.Substring(0, $idx).Trim() } else { $text.Trim() }
            $target = $global:Targets | Where-Object { $_.Host -eq $hostName } | Select-Object -First 1
            if ($target -and $target.Technologies -and $target.Technologies.Count -gt 0) {
                $selectedTargets += $target
            } else {
                $roleDisplay = if ($target -and $target.Role) { $target.Role } else { '<unknown>' }
                $osDisplay   = if ($target -and $target.OS)   { $target.OS }   else { '<unknown>' }
                $reachErr    = if ($target -and $target.Error){ $target.Error }else { '' }
                $line = "  $hostName : Role='$roleDisplay', OS='$osDisplay'"
                if ($reachErr) { $line += ", ReachErr='$reachErr'" }
                [void]$skippedDetails.Add($line)
            }
        }

        if ($totalTargets -eq 0) {
            Show-StigCopyableError -Severity 'Warning' -Title 'No targets in the list' -Message @"
The host picker above is empty because no hosts are in your Targets list.

Fix:
  1. Go to the Targets tab
  2. Type or paste host names (one per line) and click "+ Add to list"
     (or click "Add this machine" to add yourself)
  3. (Optional) Click "Test Reachability" so OS/role/STIG selection
     auto-populate before you scan
  4. Return to the Scan tab (the host picker auto-refreshes on tab enter)
  5. Tick the hosts you want to scan and click Start Scan

Targets persist across launches in Workspace\Targets.json, so you only
have to do this once per fleet.
"@
            return
        }
        if ($checkedItems -eq 0) {
            Show-StigCopyableError -Severity 'Warning' -Title 'No hosts checked' -Message @"
The host picker has $totalTargets discovered host(s) but none are
currently checked.

Fix: tick one or more hosts in the "Hosts to Scan" list on the left,
then click Start Scan again. Use "Check All" to select all eligible
hosts at once.
"@
            return
        }
        if ($selectedTargets.Count -eq 0) {
            $hostList = $skippedDetails -join "`n"
            Show-StigCopyableError -Severity 'Warning' -Title 'No applicable STIGs for the checked hosts' -Message @"
Checked $checkedItems host(s), but none have applicable STIGs.

This usually means Test Reachability couldn't determine the host's OS
role, so no STIG technology (WindowsClient / WindowsServer / Firewall /
Defender) was assigned. Common causes:
  - Host was offline when Test Reachability ran (re-run the test)
  - WinRM is blocked on the remote host (Local mode bypasses this)
  - Current account lacks remote query permissions on the target
  - Host is a non-Windows machine (no PowerStig STIGs apply)

Per-host diagnostic:
$hostList

Fix: go to the Targets tab and click Test Reachability again. If the
Role column still shows blank or 'Unknown', that host is not scannable
from this machine in the current configuration.
"@
            return
        }
        $gridScan.Rows.Clear()
        $btnScanStart.Enabled = $false
        $scanId = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $global:CurrentScan = @{
            ScanId    = $scanId
            Timestamp = (Get-Date).ToString('o')
            Mode      = $global:ExecutionMode
            Operator  = $global:Operator
            Hosts     = @()
        }
        # Count total host+tech combos for progress
        $totalJobs = 0
        foreach ($t in $selectedTargets) { $totalJobs += $t.Technologies.Count }
        $jobIdx = 0
        if ($global:prgScanRef) {
            $global:prgScanRef.Tag = @{ Value = 0; Maximum = [Math]::Max(1, $totalJobs) }
            $global:prgScanRef.Invalidate()
        }
        Write-Audit -Event 'ScanStart' -Details "scanId=$scanId hosts=$($selectedTargets.Host -join ',') mode=$($global:ExecutionMode)"
        Write-StigScanLog "================================================================" 'INFO'
        Write-StigScanLog "Scan started — scanId=$scanId mode=$($global:ExecutionMode) hosts=$($selectedTargets.Count) jobs=$totalJobs" 'INFO'
        Write-StigScanLog "  Targets: $($selectedTargets.Host -join ', ')" 'INFO'
        Write-StigScanLog "================================================================" 'INFO'

        # Tri-state result counters for the final status line. v1.2.2 just
        # said "Scan complete" even if every host failed compile — operators
        # took that as success and were surprised when Apply/Verify produced
        # nothing.
        $okJobs = 0; $compileFails = 0; $evalErrors = 0

        foreach ($target in $selectedTargets) {
            $h = $target.Host
            foreach ($techKey in $target.Technologies) {
                $jobIdx++
                if ($global:prgScanRef) {
                    $max = [int]$global:prgScanRef.Tag.Maximum
                    $global:prgScanRef.Tag = @{ Value = [Math]::Min($jobIdx, $max); Maximum = $max }
                    $global:prgScanRef.Invalidate()
                }
                $techDef = $global:SupportedTechnologies | Where-Object { $_.Key -eq $techKey } | Select-Object -First 1
                $techDisplay = if ($techDef) { $techDef.Display } else { $techKey }
                $osVer  = Get-OsVersionForTech -Technology $techKey -OSCaption $target.OS -Role $target.Role
                $osRole = Get-OsRoleForTech   -Technology $techKey -Role $target.Role
                # Pinned STIG version from the Scan Controls dropdowns (blank = latest)
                $pinnedVer = $null
                if ($global:StigVersionPins.ContainsKey($techKey)) { $pinnedVer = $global:StigVersionPins[$techKey] }
                $statusMsg = "[$jobIdx/$totalJobs] $h — $techDisplay$(if($pinnedVer){" v$pinnedVer"}) — compiling MOF..."
                $lblScanStatus.Text = $statusMsg
                Write-StigScanLog $statusMsg 'STEP'
                [System.Windows.Forms.Application]::DoEvents()

                # v1.2.19: between iterations, ask the LCM to drop any
                # in-flight configuration from the previous Test-Dsc call.
                # On work hosts (CERBERUS at home didn't show this) the
                # LCM stayed Busy after iteration 1's evaluation and
                # iteration 2 hung indefinitely on Test-DscConfiguration.
                # Stop-DscConfiguration -Force is a no-op when the LCM is
                # already Idle, and clears Busy/Pending when it isn't.
                if ($jobIdx -gt 1 -and $global:ExecutionMode -eq 'Local') {
                    Write-StigScanLog "  Clearing LCM state before next iteration..." 'STEP'
                    [System.Windows.Forms.Application]::DoEvents()
                    try {
                        Stop-DscConfiguration -Force -ErrorAction SilentlyContinue 4>&1 5>&1 | Out-Null
                    } catch {
                        Write-StigScanLog "  Stop-DscConfiguration warning: $($_.Exception.Message)" 'WARN'
                    }
                    [System.Windows.Forms.Application]::DoEvents()
                }

                $skip = @()
                if ($global:SkipLists.ContainsKey($techKey)) { $skip = @($global:SkipLists[$techKey]) }
                Write-StigScanLog "  Generating DSC config..." 'STEP'
                [System.Windows.Forms.Application]::DoEvents()
                $cfg = New-StigDscConfigFile -ComputerName $h -Technology $techKey -OsVersion $osVer -OsRole $osRole -StigVersion $pinnedVer -SkipRule $skip
                Write-StigScanLog "  Config file: $($cfg.ConfigFile)" 'STEP'
                $mofPath = $null
                $compileStart = Get-Date
                try {
                    $mofPath = Invoke-StigCompile -ConfigFile $cfg.ConfigFile -ComputerName $h
                    $compileSec = [math]::Round(((Get-Date) - $compileStart).TotalSeconds, 1)
                    Write-StigScanLog "  MOF compiled in ${compileSec}s: $mofPath" 'OK'
                } catch {
                    [void]$gridScan.Rows.Add($h, $techDisplay, 0, 0, 0, 0, 0, 0, 1, '0.0', '0.0', (Get-Date).ToString('HH:mm:ss'), "compile error: $($_.Exception.Message)")
                    $global:CurrentScan.Hosts += @{ Host=$h; Technology=$techKey; OsVersion=$osVer; StigVersion=$pinnedVer; Records=@(@{VulnID=$null;ResourceId=$null;InDesiredState=$false;Error=$_.Exception.Message}); ScannedAt=(Get-Date).ToString('o'); MOFPath=$null }
                    Write-StigScanLog "  COMPILE FAILED ($h / $techKey): $($_.Exception.Message)" 'ERR'
                    $compileFails++
                    continue
                }
                [System.Windows.Forms.Application]::DoEvents()
                $statusMsg = "[$jobIdx/$totalJobs] $h — $techDisplay$(if($pinnedVer){" v$pinnedVer"}) — evaluating..."
                $lblScanStatus.Text = $statusMsg
                Write-StigScanLog $statusMsg 'STEP'
                Write-StigScanLog "  Calling Test-DscConfiguration (this may pause if LCM is busy)..." 'STEP'
                [System.Windows.Forms.Application]::DoEvents()
                $evalStart = Get-Date
                $records = Invoke-StigEvaluation -MofFolder (Split-Path $mofPath -Parent) -ComputerName $h -Mode $global:ExecutionMode -Credential $global:RemoteCred
                $evalSec = [math]::Round(((Get-Date) - $evalStart).TotalSeconds, 1)
                Write-StigScanLog "  Test-DscConfiguration finished in ${evalSec}s — $((($records | Measure-Object).Count)) records" 'OK'
                [System.Windows.Forms.Application]::DoEvents()

                # CAT breakdown — we need the rule catalog to look up each
                # failing rule's CAT level. Build a VulnID->Cat map once.
                $catalog = Get-PowerStigRuleCatalog -Technology $techKey -TechnologyVersion $osVer -StigVersion $pinnedVer
                $catMap  = @{}
                foreach ($cr in $catalog) { $catMap[$cr.VulnID] = $cr.Cat }

                $total_r  = @($records).Count
                $pass_r   = @($records | Where-Object { $_.InDesiredState -eq $true }).Count
                $err_r    = @($records | Where-Object { $_.Error }).Count
                $cat1_r = 0; $cat2_r = 0; $cat3_r = 0
                foreach ($r in $records) {
                    if ($r.Error -or $r.InDesiredState) { continue }
                    $c = $catMap[$r.VulnID]
                    switch ($c) {
                        'CAT I'   { $cat1_r++ }
                        'CAT II'  { $cat2_r++ }
                        'CAT III' { $cat3_r++ }
                    }
                }
                $fail_r = $cat1_r + $cat2_r + $cat3_r
                # Simple compliance %: pass / total
                $pct = if ($total_r -gt 0) { [math]::Round(($pass_r / $total_r) * 100, 1) } else { 0 }
                # CAT-weighted compliance: weight CAT I 10x, CAT II 3x, CAT III 1x.
                # This matches how DISA audit scoring actually prioritizes —
                # a box with 5 CAT I failures scores much worse than one with
                # 5 CAT III failures even though simple % is the same.
                $weightedTotal = ($cat1_r * 10) + ($cat2_r * 3) + ($cat3_r * 1)
                $maxWeighted   = ($total_r * 10)   # worst case: every rule is CAT I fail
                $wpct = if ($maxWeighted -gt 0) { [math]::Round((1 - ($weightedTotal / $maxWeighted)) * 100, 1) } else { 0 }
                $rowIdx = $gridScan.Rows.Add($h, $techDisplay, $total_r, $pass_r, $fail_r, $cat1_r, $cat2_r, $cat3_r, $err_r, "$pct", "$wpct", (Get-Date).ToString('HH:mm:ss'), $mofPath)
                # Highlight rows with CAT I findings in red so they pop
                if ($cat1_r -gt 0) {
                    $gridScan.Rows[$rowIdx].DefaultCellStyle.ForeColor = $global:clrRed
                }
                $global:CurrentScan.Hosts += @{
                    Host=$h; Technology=$techKey; OsVersion=$osVer; StigVersion=$pinnedVer
                    Records=$records; ScannedAt=(Get-Date).ToString('o'); MOFPath=$mofPath
                    CatCounts=@{ CatI=$cat1_r; CatII=$cat2_r; CatIII=$cat3_r; Pass=$pass_r; Error=$err_r; Total=$total_r; Pct=$pct; WeightedPct=$wpct }
                }
                # Persist eval
                $evalDir = Join-Path $global:EvalRoot "$h\$techKey"
                if (-not (Test-Path $evalDir)) { New-Item -ItemType Directory -Path $evalDir -Force | Out-Null }
                $stamp = Join-Path $evalDir $scanId
                if (-not (Test-Path $stamp)) { New-Item -ItemType Directory -Path $stamp -Force | Out-Null }
                # Atomic write so a kill mid-write doesn't truncate evaluation.json
                # — Verify reads it back to compute the next "Last Scan" age chip.
                [void](Set-StigJsonAtomic -Path (Join-Path $stamp 'evaluation.json') -InputObject $records -Depth 4)
                if ($err_r -gt 0) {
                    $evalErrors++
                    Write-StigScanLog "  EVAL ERRORS ($h / $techKey): $err_r rule(s) failed to evaluate. Pass=$pass_r Fail=$fail_r CAT-I=$cat1_r CAT-II=$cat2_r CAT-III=$cat3_r" 'ERR'
                    foreach ($r in $records) {
                        if ($r.Error) {
                            Write-StigScanLog ("    " + ($r.VulnID, $r.ResourceId, $r.Error -join ' | ')) 'ERR'
                        }
                    }
                } else {
                    $okJobs++
                    Write-StigScanLog "  OK ($h / $techKey): Total=$total_r Pass=$pass_r Fail=$fail_r (CAT-I=$cat1_r, CAT-II=$cat2_r, CAT-III=$cat3_r). Pct=$pct% Weighted=$wpct%" 'OK'
                }
            }
        }
        $statusParts = @("Scan finished — $okJobs OK")
        if ($evalErrors  -gt 0) { $statusParts += "$evalErrors with eval errors" }
        if ($compileFails -gt 0) { $statusParts += "$compileFails compile fail(s)" }
        $statusParts += "($totalJobs scan(s) across $($selectedTargets.Count) host(s))"
        $lblScanStatus.Text = ($statusParts -join '; ')
        # PS 5.1 won't parse an `if` expression inline as a positional arg
        # ("if : The term 'if' is not recognized" — parser thinks it's a
        # cmdlet). Assign to a temp first.
        $logTag = if (($evalErrors + $compileFails) -gt 0) { 'WARN' } else { 'DONE' }
        Write-StigScanLog ($statusParts -join '; ') $logTag
        if ($global:prgScanRef) {
            $max = [int]$global:prgScanRef.Tag.Maximum
            $global:prgScanRef.Tag = @{ Value = $max; Maximum = $max }
            $global:prgScanRef.Invalidate()
        }
        $btnScanStart.Enabled = $true
        Write-Audit -Event 'ScanComplete' -Details "scanId=$scanId"
        $global:LastScan = $global:CurrentScan
    }.GetNewClosure())

    # v1.2.13: Fill first, then Left, then Top — reverse-Z-order docking.
    $tabScan.Controls.AddRange(@($grpScanGrid, $grpScanHosts, $grpScanCtl))
#endregion

#region ------------------------ TAB: CHECKLIST REVIEW -------------------
    $tabReview = New-Object System.Windows.Forms.TabPage
    $tabReview.Text = '  Checklist Review  '
    $tabReview.BackColor = $global:clrBG; $tabReview.ForeColor = $global:clrWhite
    $tabReview.Padding = New-Object System.Windows.Forms.Padding(15)

    $grpRevCtl = & $MakeGB 'Host / Technology' 15 15 1180 80
    # v1.2.12: Dock=Top fixed-height; grid below is Dock=Fill.
    $grpRevCtl.Dock   = [System.Windows.Forms.DockStyle]::Top
    $grpRevCtl.Height = 80
    $lblHostPick = & $MakeLbl 'Scan entry:' 15 32 70
    $cboReviewHost = New-Object System.Windows.Forms.ComboBox
    $cboReviewHost.DropDownStyle = 'DropDownList'
    $cboReviewHost.BackColor = $global:clrInputBG; $cboReviewHost.ForeColor = $global:clrWhite
    $cboReviewHost.Location = New-Object System.Drawing.Point(90, 30)
    $cboReviewHost.Size = New-Object System.Drawing.Size(380, 22)
    # Track the currently selected technology key for skip-list operations
    $global:ReviewSelectedTech = $null

    $lblSkipInfo = & $MakeLbl '' 490 32 300 $global:clrOrange

    $btnSaveSkip = New-Object System.Windows.Forms.Button
    $btnSaveSkip.Text = 'Save Skip-List'
    $btnSaveSkip.Size = New-Object System.Drawing.Size(140, 26)
    $btnSaveSkip.Location = New-Object System.Drawing.Point(900, 28)
    $btnSaveSkip.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    & $StyleBtn $btnSaveSkip $global:clrGreen 'Persist excluded rules so Apply and future scans honor them'

    $btnLoadSkip = New-Object System.Windows.Forms.Button
    $btnLoadSkip.Text = 'Load Skip-List'
    $btnLoadSkip.Size = New-Object System.Drawing.Size(140, 26)
    $btnLoadSkip.Location = New-Object System.Drawing.Point(1045, 28)
    $btnLoadSkip.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    & $StyleBtn $btnLoadSkip $global:clrCyan 'Load skip-list from disk and re-apply to grid'

    $grpRevCtl.Controls.AddRange(@($lblHostPick, $cboReviewHost, $lblSkipInfo, $btnSaveSkip, $btnLoadSkip))

    $grpRevGrid = & $MakeGB 'Per-Rule Results' 15 105 1180 500
    $grpRevGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpRevGrid.Padding = New-Object System.Windows.Forms.Padding(15)
    $gridRev = New-Object System.Windows.Forms.DataGridView
    $gridRev.Dock = [System.Windows.Forms.DockStyle]::Fill
    $gridRev.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    & $StyleGrid $gridRev

    $colInclude = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colInclude.HeaderText = 'Apply?'; $colInclude.Name = 'Include'; $colInclude.FillWeight = 7
    $colInclude.ReadOnly = $false
    [void]$gridRev.Columns.Add($colInclude)
    # Read-only informational columns (VulnID / Cat / Status / Title / Resource)
    # v1.2.11: MinimumWidths added so headers stay readable on narrow forms.
    foreach ($cd in @(
        @{N='VulnID';     H='VulnID';   W=9;  M=80 },
        @{N='Cat';        H='CAT';      W=5;  M=50 },
        @{N='Status';     H='Status';   W=7;  M=64 },
        @{N='Title';      H='Title';    W=32; M=240},
        @{N='ResourceId'; H='Resource'; W=14; M=110}
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=$cd.N; $c.HeaderText=$cd.H
        $c.FillWeight=$cd.W; $c.MinimumWidth=$cd.M
        $c.ReadOnly=$true
        [void]$gridRev.Columns.Add($c)
    }
    # EDITABLE columns for DISA audit metadata — these flow into CKL/CKLB
    # export. Operators fill these in during review BEFORE running Apply
    # or exporting a checklist.
    foreach ($cd in @(
        @{N='NAJustification'; H='NA Justification'; W=16; M=140},
        @{N='FindingDetails';  H='Finding Details';  W=16; M=140},
        @{N='Comments';        H='Comments';         W=14; M=110},
        @{N='SevOverride';     H='Sev Override';     W=8;  M=92 }
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=$cd.N; $c.HeaderText=$cd.H
        $c.FillWeight=$cd.W; $c.MinimumWidth=$cd.M
        $c.ReadOnly=$false
        [void]$gridRev.Columns.Add($c)
    }
    # v1.3.2: disable column header sorting. The Review-grid row index
    # aligns 1-to-1 with the loaded scan record set (see $LoadReviewEntry
    # below) and the SkipList save path reads $gridRev.Rows[i].Cells[...]
    # by visual index. Without this, an operator who clicks any column
    # header sorts the visual rows but not the backing data — every
    # subsequent skip-list checkbox toggle then mutates the wrong rule.
    # Same latent bug the v1.3.0 final reviewer caught on the CKLB Import
    # grid; carrying the fix here as well.
    foreach ($col in $gridRev.Columns) {
        $col.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    }
    $grpRevGrid.Controls.Add($gridRev)

    # LoadReviewEntry: parses "HOST | TECH" from dropdown, loads the scan
    # result for that host+tech combo, joins the PowerStig rule catalog,
    # and populates the review grid with per-rule pass/fail/skip status.
    $LoadReviewEntry = {
        param($comboText)
        $gridRev.Rows.Clear()
        $global:ReviewSelectedTech = $null
        if (-not $global:CurrentScan -or -not $comboText) { return }
        # Parse "HOST | TECHKEY" back into parts
        $parts = $comboText -split '\s*\|\s*', 2
        if ($parts.Count -lt 2) { return }
        $selHost = $parts[0]; $selTech = $parts[1]
        $global:ReviewSelectedTech = $selTech
        $hostResult = $global:CurrentScan.Hosts | Where-Object { $_.Host -eq $selHost -and $_.Technology -eq $selTech } | Select-Object -First 1
        if (-not $hostResult) { return }
        $catalog = Get-PowerStigRuleCatalog -Technology $selTech
        $catalogMap = @{}
        foreach ($c in $catalog) { $catalogMap[$c.VulnID] = $c }
        $skip = @()
        if ($global:SkipLists.ContainsKey($selTech)) { $skip = @($global:SkipLists[$selTech]) }
        # Suspend events while bulk-populating so CellValueChanged doesn't
        # fire for every column assignment — commits happen when user edits.
        $global:SuspendRuleEvents = $true
        foreach ($r in $hostResult.Records) {
            if (-not $r.VulnID) { continue }
            $meta = $catalogMap[$r.VulnID]
            $cat  = if ($meta -and $meta.Cat) { $meta.Cat } else { '' }
            $status = if ($r.Error) { 'Error' } elseif ($r.InDesiredState) { 'Pass' } else { 'Fail' }
            $include = ($skip -notcontains $r.VulnID)
            # Hydrate saved metadata (NA justification / comments / etc.)
            $rmd = Get-RuleMetadata -Technology $selTech -VulnID $r.VulnID
            $rowIdx = $gridRev.Rows.Add(
                $include,
                $r.VulnID,
                $cat,
                $status,
                $(if($meta){$meta.Title}else{''}),
                $r.ResourceId,
                $rmd.NAJustification,
                $rmd.FindingDetails,
                $rmd.Comments,
                $rmd.SeverityOverride
            )
            $row = $gridRev.Rows[$rowIdx]
            switch ($status) {
                'Pass'  { $row.DefaultCellStyle.ForeColor = $global:clrGreen }
                'Fail'  { $row.DefaultCellStyle.ForeColor = $global:clrRed }
                'Error' { $row.DefaultCellStyle.ForeColor = $global:clrOrange }
            }
            # CAT I failures get extra-bold styling so they don't hide in the
            # sea of CAT II findings. DISA requires priority attention on
            # CAT I (IAVM 24-72hr remediation windows).
            if ($cat -eq 'CAT I' -and $status -eq 'Fail') {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(64, 20, 22)   # dark red tint
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255, 120, 120) # brighter red
            }
        }
        $global:SuspendRuleEvents = $false
        $lblSkipInfo.Text = "[$selTech] $($gridRev.Rows.Count) rules. Skip-list: $($skip.Count) excluded."
    }.GetNewClosure()

    $tabReview.Add_Enter({
        $cboReviewHost.Items.Clear()
        if ($global:CurrentScan -and $global:CurrentScan.Hosts) {
            foreach ($hr in $global:CurrentScan.Hosts) {
                [void]$cboReviewHost.Items.Add("$($hr.Host) | $($hr.Technology)")
            }
            if ($cboReviewHost.Items.Count -gt 0) { $cboReviewHost.SelectedIndex = 0 }
        }
    }.GetNewClosure())
    $cboReviewHost.Add_SelectedIndexChanged({ & $LoadReviewEntry $cboReviewHost.SelectedItem }.GetNewClosure())

    $gridRev.Add_CellValueChanged({
        param($sender, $e)
        if ($e.ColumnIndex -lt 0 -or $e.RowIndex -lt 0) { return }
        if ($global:SuspendRuleEvents) { return }
        $tech = $global:ReviewSelectedTech
        if (-not $tech) { return }
        $colName = $gridRev.Columns[$e.ColumnIndex].Name
        $vid     = [string]$gridRev.Rows[$e.RowIndex].Cells['VulnID'].Value
        if (-not $vid) { return }
        $rmd     = Get-RuleMetadata -Technology $tech -VulnID $vid

        if ($colName -eq 'Include') {
            $inc = [bool]$gridRev.Rows[$e.RowIndex].Cells['Include'].Value
            if (-not $global:SkipLists.ContainsKey($tech)) { $global:SkipLists[$tech] = @() }
            $current = [System.Collections.Generic.List[string]]::new()
            $global:SkipLists[$tech] | ForEach-Object { if ($_) { $current.Add([string]$_) } }
            if ($inc) {
                # Re-including: drop from skip-list, clear NA justification
                if ($current.Contains([string]$vid)) { [void]$current.Remove([string]$vid) }
                $rmd.NAJustification = ''
                $gridRev.Rows[$e.RowIndex].Cells['NAJustification'].Value = ''
            } else {
                # Excluding: add to skip-list AND prompt for NA justification.
                # DISA requires all Not_Applicable rules to carry a written
                # justification — emitted in the CKL COMMENTS field.
                if (-not $current.Contains([string]$vid)) { $current.Add([string]$vid) }
                $existing = $rmd.NAJustification
                $prompt   = "VulnID $vid will be excluded from Apply and marked Not_Applicable on export.`r`n`r`nDISA audit practice requires a written justification for every NA rule (this appears in the CKL COMMENTS field). Provide a brief reason below:"
                $just = Read-StigMultilineInput -Title "NA Justification for $vid" -Prompt $prompt -Initial $existing -MinLength 1
                if ($just -eq $null) {
                    # User cancelled — revert the uncheck
                    $global:SuspendRuleEvents = $true
                    $gridRev.Rows[$e.RowIndex].Cells['Include'].Value = $true
                    $global:SuspendRuleEvents = $false
                    if ($current.Contains([string]$vid)) { [void]$current.Remove([string]$vid) }
                } else {
                    $rmd.NAJustification = $just
                    $gridRev.Rows[$e.RowIndex].Cells['NAJustification'].Value = $just
                }
            }
            $global:SkipLists[$tech] = $current.ToArray()
            $lblSkipInfo.Text = "[$tech] Skip-list: $($global:SkipLists[$tech].Count) entries (unsaved)."
            return
        }

        # Editable text columns — mirror into $global:RuleMetadata
        $val = [string]$gridRev.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
        switch ($colName) {
            'NAJustification' { $rmd.NAJustification = $val }
            'FindingDetails'  { $rmd.FindingDetails  = $val }
            'Comments'        { $rmd.Comments        = $val }
            'SevOverride'     {
                # Severity Override cell: empty | 'CAT I' | 'CAT II' | 'CAT III'.
                # When set, prompt for justification (DISA requires it).
                $up = $val.Trim().ToUpper()
                if ($up -and $up -notin @('CAT I','CAT II','CAT III')) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Severity Override must be empty or one of: CAT I, CAT II, CAT III",
                        'Invalid severity override',
                        'OK','Warning') | Out-Null
                    $global:SuspendRuleEvents = $true
                    $gridRev.Rows[$e.RowIndex].Cells['SevOverride'].Value = $rmd.SeverityOverride
                    $global:SuspendRuleEvents = $false
                    return
                }
                $rmd.SeverityOverride = $up
                if ($up) {
                    $just = Read-StigMultilineInput -Title "Severity Override justification for $vid" -Prompt "Override severity to $up. Enter justification (appears in CKL SEVERITY_JUSTIFICATION):" -Initial $rmd.SeverityJustification -MinLength 1
                    if ($just) { $rmd.SeverityJustification = $just }
                } else {
                    $rmd.SeverityJustification = ''
                }
            }
        }
        $lblSkipInfo.Text = "[$tech] Metadata edited (unsaved). Click Save Skip-List to persist."
    }.GetNewClosure())
    $gridRev.Add_CurrentCellDirtyStateChanged({
        if ($gridRev.IsCurrentCellDirty) { $gridRev.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
    }.GetNewClosure())

    $btnSaveSkip.Add_Click({
        $tech = $global:ReviewSelectedTech
        if (-not $tech) { [System.Windows.Forms.MessageBox]::Show('Select a scan entry first.','No tech','OK','Warning') | Out-Null; return }
        $p  = Export-StigSkipList     -Technology $tech
        $pm = Export-StigRuleMetadata -Technology $tech
        $lblSkipInfo.Text = "[$tech] Saved skip-list + metadata."
    }.GetNewClosure())
    $btnLoadSkip.Add_Click({
        $tech = $global:ReviewSelectedTech
        if (-not $tech) { [System.Windows.Forms.MessageBox]::Show('Select a scan entry first.','No tech','OK','Warning') | Out-Null; return }
        $r  = Import-StigSkipList     -Technology $tech
        $rm = Import-StigRuleMetadata -Technology $tech
        $lblSkipInfo.Text = "[$tech] Loaded skip-list ($($r.Count)) + metadata ($rm rules)."
        if ($cboReviewHost.SelectedItem) { & $LoadReviewEntry $cboReviewHost.SelectedItem }
    }.GetNewClosure())

    # v1.2.13: Fill first, then Top — reverse-Z-order docking.
    $tabReview.Controls.AddRange(@($grpRevGrid, $grpRevCtl))
#endregion

#region ------------------------ TAB: APPLY ------------------------------
    $tabApply = New-Object System.Windows.Forms.TabPage
    $tabApply.Text = '  Apply (Remediate)  '
    $tabApply.BackColor = $global:clrBG; $tabApply.ForeColor = $global:clrWhite
    $tabApply.Padding = New-Object System.Windows.Forms.Padding(15)

    # v1.2.12: Dock-based layout — Danger banner Top, Apply Controls Top
    # below it (fixed height), Apply Log Fill takes the rest. No anchor
    # math against an unsized TabPage.
    $pnlDanger = New-Object System.Windows.Forms.Panel
    $pnlDanger.Dock = [System.Windows.Forms.DockStyle]::Top
    $pnlDanger.Height = 36
    $pnlDanger.BackColor = [System.Drawing.Color]::FromArgb(80, 20, 20)
    $lblDanger = New-Object System.Windows.Forms.Label
    $lblDanger.Text = '  DANGER: This tab makes real changes. Restore points, confirmation, and audit logging are enforced.'
    $lblDanger.ForeColor = $global:clrWhite; $lblDanger.Font = $fontDanger
    $lblDanger.Dock = 'Fill'; $lblDanger.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $pnlDanger.Controls.Add($lblDanger)

    $grpApplyCtl = & $MakeGB 'Apply Controls' 15 60 1180 220 $global:clrRed
    $grpApplyCtl.Dock   = [System.Windows.Forms.DockStyle]::Top
    $grpApplyCtl.Height = 220
    $lblApplyInfo = New-Object System.Windows.Forms.Label
    $lblApplyInfo.ForeColor = $global:clrWhite; $lblApplyInfo.Font = $fontSmall
    $lblApplyInfo.AutoSize = $false
    $lblApplyInfo.Size = New-Object System.Drawing.Size(1150, 60)
    $lblApplyInfo.Location = New-Object System.Drawing.Point(15, 25)
    $lblApplyInfo.Text = 'Applies the LAST SCAN''s compiled MOF for each selected host, honoring the current skip-list. Run Scan first if anything has changed.'

    $chkRestore = New-Object System.Windows.Forms.CheckBox
    $chkRestore.Text = 'Create System Restore point before apply (workstations only)'
    $chkRestore.ForeColor = $global:clrWhite
    $chkRestore.Checked = $true
    $chkRestore.AutoSize = $true
    $chkRestore.Location = New-Object System.Drawing.Point(15, 88)

    $chkDryRun = New-Object System.Windows.Forms.CheckBox
    $chkDryRun.Text = 'DRY RUN (Test-DscConfiguration preview — does not change state)'
    $chkDryRun.ForeColor = $global:clrOrange
    $chkDryRun.AutoSize = $true
    $chkDryRun.Location = New-Object System.Drawing.Point(15, 113)

    $lblConfirm = & $MakeLbl 'Type APPLY to confirm:' 15 148 180 $global:clrOrange
    $txtConfirm = New-Object System.Windows.Forms.TextBox
    $txtConfirm.BackColor = $global:clrInputBG; $txtConfirm.ForeColor = $global:clrWhite
    $txtConfirm.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtConfirm.Location = New-Object System.Drawing.Point(200, 145)
    $txtConfirm.Size = New-Object System.Drawing.Size(120, 22)

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = 'Start Apply'
    $btnApply.Size = New-Object System.Drawing.Size(200, 36)
    $btnApply.Font = $fontBigBtn
    $btnApply.Location = New-Object System.Drawing.Point(15, 175)
    & $StyleBtn $btnApply $global:clrRed 'Apply the compiled MOF(s) — requires typed confirmation'

    $lblApplyStatus = & $MakeLbl '' 230 185 900 $global:clrCyan
    $grpApplyCtl.Controls.AddRange(@($lblApplyInfo, $chkRestore, $chkDryRun, $lblConfirm, $txtConfirm, $btnApply, $lblApplyStatus))

    $grpApplyLog = & $MakeGB 'Apply Log' 15 290 1180 315
    $grpApplyLog.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpApplyLog.Padding = New-Object System.Windows.Forms.Padding(15)
    $txtApplyLog = New-Object System.Windows.Forms.TextBox
    $txtApplyLog.Multiline = $true; $txtApplyLog.ReadOnly = $true
    $txtApplyLog.ScrollBars = 'Vertical'; $txtApplyLog.Font = $fontMono
    $txtApplyLog.BackColor = $global:clrInputBG; $txtApplyLog.ForeColor = $global:clrWhite
    $txtApplyLog.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtApplyLog.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpApplyLog.Controls.Add($txtApplyLog)

    $btnApply.Add_Click({
        if (-not $global:CurrentScan) {
            [System.Windows.Forms.MessageBox]::Show('No scan data. Run Scan tab first.', 'No scan','OK','Warning') | Out-Null
            return
        }
        if (-not $global:PrereqStatus.IsAdmin) {
            [System.Windows.Forms.MessageBox]::Show('Apply requires elevation. Re-launch the tool as Administrator.','Not elevated','OK','Error') | Out-Null
            return
        }
        if (-not (Test-StigCredsReady -ActionName 'an apply')) { return }
        if ($txtConfirm.Text -ne 'APPLY') {
            [System.Windows.Forms.MessageBox]::Show('Type APPLY in the confirmation box first.','Confirmation missing','OK','Warning') | Out-Null
            return
        }
        # Reset the typed token IMMEDIATELY after it passes — so any path
        # that bails after this point (LCM warning declined, MessageBox
        # cancelled, exception during compile) requires the operator to
        # re-type "APPLY" for the next attempt. v1.2.2 only reset on the
        # success path, so a declined LCM warning let the next click skip
        # straight past the typed-confirmation gate.
        $txtConfirm.Text = ''

        # DSC LCM pre-flight: probe each unique target once before the real
        # apply loop. If LCM is Busy / PendingConfiguration / PendingReboot
        # on any host, surface the details copyably so the operator can fix
        # it (usually: Remove-DscConfigurationDocument -Stage Pending) instead
        # of watching Start-DscConfiguration fail opaquely.
        if (-not $chkDryRun.Checked) {
            $uniqueHosts = @($global:CurrentScan.Hosts | Select-Object -ExpandProperty Host -Unique)
            $lcmReport   = [System.Collections.ArrayList]::new()
            $lcmBlocking = $false
            foreach ($uh in $uniqueHosts) {
                $lcm = Test-StigDscLcmHealth -ComputerName $uh -Mode $global:ExecutionMode -Credential $global:RemoteCred
                [void]$lcmReport.Add("  $uh : $($lcm.Health) / LCMState=$($lcm.State)`r`n    $($lcm.Message)")
                if ($lcm.Health -ne 'OK') { $lcmBlocking = $true }
            }
            if ($lcmBlocking) {
                $msgBody = @"
One or more targets have a DSC Local Configuration Manager state that
may interfere with Start-DscConfiguration.

Per-host report:
$($lcmReport -join "`r`n")

Common fixes (run on the target as admin):

  # Clear any pending/previous documents
  Remove-DscConfigurationDocument -Stage Pending,Previous,Current

  # If LCM is truly Busy, wait for current apply to finish (minutes)
  Get-DscConfigurationStatus

You can continue anyway by clicking YES, or cancel and resolve first.
"@
                Show-StigCopyableError -Severity 'Warning' -Title 'DSC LCM pre-check has warnings' -Message $msgBody
                $cont = [System.Windows.Forms.MessageBox]::Show(
                    'Continue with Apply despite LCM warnings?',
                    'Override LCM warning',
                    'YesNo','Warning'
                )
                if ($cont -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            }
        }

        $isDry = $chkDryRun.Checked
        $msg = if ($isDry) {
            'DRY RUN will run Test-DscConfiguration against the current MOFs and log what WOULD change. No changes will be made.'
        } else {
            "REAL APPLY will run Start-DscConfiguration on $($global:CurrentScan.Hosts.Count) host(s). This makes REAL CHANGES. Continue?"
        }
        $r = [System.Windows.Forms.MessageBox]::Show($msg, $(if($isDry){'Confirm DRY RUN'}else{'CONFIRM APPLY'}), 'YesNo', $(if($isDry){'Question'}else{'Warning'}))
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $btnApply.Enabled = $false
        # Mark Apply in progress so FormClosing can refuse to silently
        # tear down a half-applied DSC operation (LCM left in
        # PendingConfiguration is hard to recover from).
        $global:ApplyInProgress = (-not $isDry)
        $applyStartTicks = [Environment]::TickCount
        try {
        $txtApplyLog.Clear()
        $txtApplyLog.AppendText("=== Apply started $((Get-Date).ToString('o')) ===`r`n")
        $txtApplyLog.AppendText("Mode : $($global:ExecutionMode)`r`n")
        $txtApplyLog.AppendText("DryRun: $isDry`r`n")
        $txtApplyLog.AppendText("Operator: $($global:Operator)`r`n")
        $txtApplyLog.AppendText("Hosts: $($global:CurrentScan.Hosts.Host -join ', ')`r`n")
        if (-not $isDry) {
            $txtApplyLog.AppendText("`r`nNOTE: Each Start-DscConfiguration call can take 5-30 minutes per host on a fresh STIG apply. The UI will appear unresponsive between status updates — DO NOT close the tool. Watch the elapsed-time counter in the status bar.`r`n")
        }
        $txtApplyLog.AppendText("`r`n")
        Write-Audit -Event $(if($isDry){'DryRunStart'}else{'ApplyStart'}) -Details "hosts=$($global:CurrentScan.Hosts.Host -join ',')"

        # Track which hosts have already had a restore point successfully
        # created vs failed. v1.2.3 conflated them — failure marked
        # $restoreCreated=$true to suppress retries within the same apply,
        # but that meant the operator never saw a retry prompt the second
        # time they hit Apply on the same host either.
        $restoreCreated = @{}
        $restoreFailed  = @{}
        foreach ($hr in $global:CurrentScan.Hosts) {
            $h = $hr.Host
            $tech = $hr.Technology
            $target = $global:Targets | Where-Object { $_.Host -eq $h } | Select-Object -First 1
            # Null-safe technology lookup. Under StrictMode 3 the previous
            # `... | Select -First 1).Display` chain throws when no match is
            # found (e.g. metadata referring to a removed technology key).
            $techDef = $global:SupportedTechnologies | Where-Object { $_.Key -eq $tech } | Select-Object -First 1
            $techDisplay = if ($techDef) { $techDef.Display } else { $tech }
            $lblApplyStatus.Text = "$h — $techDisplay — preparing..."
            [System.Windows.Forms.Application]::DoEvents()

            # Restore point: once per host, not per technology. If a previous
            # tech in this loop already failed restore-point on this host, do
            # NOT silently retry — log that we're proceeding without one and
            # keep going. (Failures usually mean System Restore is disabled,
            # which is a per-host config and won't change between techs.)
            if (-not $isDry -and $chkRestore.Checked -and -not $restoreCreated.ContainsKey($h) -and -not $restoreFailed.ContainsKey($h)) {
                $txtApplyLog.AppendText("[$h] Creating restore point...`r`n")
                try {
                    if ($global:ExecutionMode -eq 'Local' -and ($h -eq $env:COMPUTERNAME)) {
                        Checkpoint-Computer -Description "STIG_Tool apply $((Get-Date).ToString('yyyyMMdd-HHmm'))" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
                    } else {
                        # Bounded session — Checkpoint-Computer can hang for 60-120s
                        # on a host with VSS disabled or Volume Shadow Copy backlog.
                        Invoke-StigBoundedRemote -ComputerName $h -Credential $global:RemoteCred `
                            -ArgumentList @("STIG_Tool apply $((Get-Date).ToString('yyyyMMdd-HHmm'))") `
                            -OperationTimeoutMs 120000 `
                            -ScriptBlock { param($d) Checkpoint-Computer -Description $d -RestorePointType 'MODIFY_SETTINGS' }
                    }
                    $txtApplyLog.AppendText("[$h] Restore point created.`r`n")
                    $restoreCreated[$h] = $true
                } catch {
                    $txtApplyLog.AppendText("[$h] Restore point FAILED (continuing without one for this host): $($_.Exception.Message)`r`n")
                    $restoreFailed[$h] = $_.Exception.Message
                    Write-Audit -Event 'RestorePointFailed' -Details "host=$h err=$($_.Exception.Message)"
                }
            }

            # Re-compile with current skip-list for this technology.
            # v1.3.2: routed through Invoke-StigPipelineForHost -CompileOnly
            # so the CKLB Import tab and this tab share one compile path.
            # We still drive Test/Apply manually below because this handler
            # needs the pre-apply Invoke-StigEvaluation (for the JANET
            # VulnsRemediated metric) interleaved between compile and apply
            # against the same MOF.
            $skip = @()
            if ($global:SkipLists.ContainsKey($tech)) { $skip = @($global:SkipLists[$tech]) }
            $compileResult = Invoke-StigPipelineForHost `
                -ComputerName $h `
                -Technology   $tech `
                -OsCaption    $(if($target){[string]$target.OS}else{''}) `
                -Role         $(if($target){[string]$target.Role}else{''}) `
                -SkipRule     $skip `
                -Mode         $global:ExecutionMode `
                -Credential   $global:RemoteCred `
                -CompileOnly
            if (-not $compileResult.Success) {
                $txtApplyLog.AppendText("[$h | $techDisplay] COMPILE FAIL: $($compileResult.Error)`r`n")
                continue
            }
            $mof = $compileResult.MofPath

            $lblApplyStatus.Text = "$h — $techDisplay — $(if($isDry){'evaluating (DRY)'}else{'applying'})..."
            [System.Windows.Forms.Application]::DoEvents()

            if ($isDry) {
                $records = Invoke-StigEvaluation -MofFolder (Split-Path $mof -Parent) -ComputerName $h -Mode $global:ExecutionMode -Credential $global:RemoteCred
                $willFix = @($records | Where-Object { $_.InDesiredState -eq $false -and -not $_.Error }).Count
                $txtApplyLog.AppendText("[$h | $techDisplay] DRY RUN: would remediate $willFix rule(s) (excluded $($skip.Count))`r`n")

                ## JANET centralized logging (added in v1.2.1). Dry-run = Skipped row.
                if ($null -ne $global:JanetSession) {
                    try { Write-JanetAction -Action 'VulnPatched' -Target $h -Result 'Skipped' -ItemCount $willFix -Detail "tech=$tech dry-run" } catch {}
                }
            } else {
                ## JANET: pre-apply non-compliant count for VulnsRemediated metric.
                $preFix = 0
                if ($null -ne $global:JanetSession) {
                    try {
                        $preRecords = Invoke-StigEvaluation -MofFolder (Split-Path $mof -Parent) -ComputerName $h -Mode $global:ExecutionMode -Credential $global:RemoteCred
                        $preFix = @($preRecords | Where-Object { $_.InDesiredState -eq $false -and -not $_.Error }).Count
                    } catch { $preFix = 0 }
                }

                $res = Invoke-StigApply -MofFolder (Split-Path $mof -Parent) -ComputerName $h -Mode $global:ExecutionMode -Credential $global:RemoteCred
                if ($res.Success) {
                    $txtApplyLog.AppendText("[$h | $techDisplay] APPLY OK`r`n")
                    Write-Audit -Event 'ApplyHost' -Details "host=$h tech=$tech result=ok skip=$($skip.Count)"

                    ## JANET centralized logging (added in v1.2.1). Per-host ApplySTIG success row.
                    if ($null -ne $global:JanetSession) {
                        try { Write-JanetAction -Action 'VulnPatched' -Target $h -Result 'Success' -ItemCount $preFix -Detail "tech=$tech" } catch {}
                    }
                } else {
                    $txtApplyLog.AppendText("[$h | $techDisplay] APPLY FAIL: $($res.Error)`r`n")
                    Write-Audit -Event 'ApplyHost' -Details "host=$h tech=$tech result=fail err=$($res.Error)"

                    ## JANET centralized logging (added in v1.2.1). Per-host ApplySTIG failure row.
                    if ($null -ne $global:JanetSession) {
                        try { Write-JanetAction -Action 'VulnPatched' -Target $h -Result 'Failure' -Detail "tech=$tech err=$($res.Error)" } catch {}
                    }
                }
            }
        }
        $txtApplyLog.AppendText("`r`n=== Apply finished $((Get-Date).ToString('o')) ===`r`n")
        # Surface any per-host restore-point failures so the operator sees
        # the list at the bottom of the log instead of having to scroll.
        if ($restoreFailed.Count -gt 0) {
            $txtApplyLog.AppendText("`r`nWARNING: $($restoreFailed.Count) host(s) had restore-point failures. The DSC apply still ran on those hosts but there is NO restore point to roll back to:`r`n")
            foreach ($k in $restoreFailed.Keys) {
                $txtApplyLog.AppendText("  $k : $($restoreFailed[$k])`r`n")
            }
        }
        Write-Audit -Event $(if($isDry){'DryRunComplete'}else{'ApplyComplete'}) -Details "restoreFails=$($restoreFailed.Count)"

        # Reboot-required detection — many STIG remediations (credential
        # guard, UAC registry keys, security options) don't take effect
        # until reboot. Check each unique host for the standard Windows
        # reboot-pending signals. If any are flagged, offer the operator
        # a choice to reboot now, schedule, or defer.
        if (-not $isDry) {
            $rebootHosts = @()
            $rebootDetectFailed = @()
            foreach ($uh in @($global:CurrentScan.Hosts | Select-Object -ExpandProperty Host -Unique)) {
                try {
                    $sbCheck = {
                        $r = $false
                        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r = $true }
                        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r = $true }
                        try {
                            $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
                            if ($val -and $val.PendingFileRenameOperations) { $r = $true }
                        } catch {}
                        return $r
                    }
                    if ($global:ExecutionMode -eq 'Local' -and ($uh -eq $env:COMPUTERNAME -or $uh -eq 'localhost' -or $uh -eq '.')) {
                        $needsReboot = & $sbCheck
                    } else {
                        # Bounded session — never let a half-broken target hang the
                        # apply loop on the WSMan default 3-min timeout.
                        $needsReboot = Invoke-StigBoundedRemote -ComputerName $uh -Credential $global:RemoteCred -ScriptBlock $sbCheck -OperationTimeoutMs 30000
                    }
                    if ($needsReboot) { $rebootHosts += $uh }
                } catch {
                    # Don't silently swallow — operator needs to know that
                    # reboot detection failed (the apply DID make changes,
                    # the host probably DOES need a reboot, but we couldn't
                    # confirm). Add to a separate bucket so the prompt can
                    # be shown anyway with a "(detection failed)" tag.
                    $rebootDetectFailed += $uh
                    Write-Audit -Event 'RebootDetectFail' -Details "host=$uh err=$($_.Exception.Message)"
                }
            }
            if ($rebootDetectFailed.Count -gt 0) {
                $txtApplyLog.AppendText("`r`n[WARN] Reboot detection failed on $($rebootDetectFailed.Count) host(s) (treating as reboot-pending):`r`n  $($rebootDetectFailed -join "`r`n  ")`r`n")
                # Treat detection-failed as needs-reboot so operator gets the
                # prompt instead of false-clean status.
                $rebootHosts += $rebootDetectFailed
            }
            if ($rebootHosts.Count -gt 0) {
                $txtApplyLog.AppendText("`r`n=== REBOOT REQUIRED on $($rebootHosts.Count) host(s) ===`r`n$($rebootHosts -join "`r`n")`r`n")
                $msg = "These host(s) have pending reboots after the apply:`r`n`r`n$(($rebootHosts | ForEach-Object { "  $_" }) -join "`r`n")`r`n`r`nRebooting is typically required for STIG remediations covering Credential Guard, UAC policy, Secure Boot, and other kernel-level settings to take effect. Verify will show these rules as 'Still Failing' until reboot.`r`n`r`nYes  = reboot the local machine in 60 seconds (remote hosts unaffected)`r`nNo   = defer reboot (note: Verify will be inaccurate until rebooted)"
                $r = [System.Windows.Forms.MessageBox]::Show($msg, 'Reboot required after Apply', 'YesNo', 'Warning')
                if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
                    try {
                        shutdown.exe /r /t 60 /c "J.A.N.E.T. STIG Tool: post-apply reboot in 60 seconds. Save your work."
                        $lblApplyStatus.Text = 'Reboot scheduled (60s). Cancel with: shutdown /a'
                        Write-Audit -Event 'RebootScheduled' -Details "hosts=$($rebootHosts -join ',')"
                    } catch {
                        Show-StigCopyableError -Title 'Reboot schedule failed' -Message $_.Exception.Message
                    }
                }
            }
        }

            $elapsedSec = [int](([Environment]::TickCount - $applyStartTicks) / 1000)
            $elapsedTxt = if ($elapsedSec -ge 60) { "$([int]($elapsedSec/60))m $($elapsedSec % 60)s" } else { "$($elapsedSec)s" }
            if (-not $isDry) {
                $lblApplyStatus.Text = "Apply finished in $elapsedTxt. Go to Verify tab to rescan and diff."
            } else {
                $lblApplyStatus.Text = "Dry run finished in $elapsedTxt. Flip the DRY RUN checkbox off to run for real."
            }
        } catch {
            # Surface any unhandled error from the apply loop to the operator
            # (and audit). Without this catch the closure would silently exit
            # while $global:ApplyInProgress stays $true and btnApply stays
            # disabled, locking the operator out of retrying.
            $errMsg = $_.Exception.Message
            $txtApplyLog.AppendText("`r`n[FATAL] Apply handler aborted: $errMsg`r`n$($_.ScriptStackTrace)`r`n")
            Write-Audit -Event 'ApplyHandlerCrash' -Details "err=$errMsg"
            Show-StigCopyableError -Title 'Apply handler crashed' -Message @"
The apply handler hit an unhandled exception. The DSC apply may have
partially run on some hosts before this crash — review the log and the
target's Get-DscConfigurationStatus before retrying.

Error:
$errMsg

ScriptStackTrace:
$($_.ScriptStackTrace)
"@
        } finally {
            $btnApply.Enabled = $true
            $global:ApplyInProgress = $false
        }
    }.GetNewClosure())

    # v1.2.13: Fill first, then the two Top stripes (grpApplyCtl below
    # pnlDanger because it's added last — last-Top-added sits inside the
    # earlier Top, so we want pnlDanger LAST so it claims the very top).
    $tabApply.Controls.AddRange(@($grpApplyLog, $grpApplyCtl, $pnlDanger))
#endregion

#region ------------------------ TAB: VERIFY -----------------------------
    $tabVerify = New-Object System.Windows.Forms.TabPage
    $tabVerify.Text = '  Verify  '
    $tabVerify.BackColor = $global:clrBG; $tabVerify.ForeColor = $global:clrWhite
    $tabVerify.Padding = New-Object System.Windows.Forms.Padding(15)

    $grpVerCtl = & $MakeGB 'Post-Apply Verification' 15 15 1180 90
    $grpVerCtl.Dock   = [System.Windows.Forms.DockStyle]::Top
    $grpVerCtl.Height = 90
    $lblVerInfo = New-Object System.Windows.Forms.Label
    $lblVerInfo.Text = 'Rescans all hosts in the current scan and diffs vs the saved pre-apply results. Resolved rules are green, still-failing red, regressions orange.'
    $lblVerInfo.ForeColor = $global:clrWhite; $lblVerInfo.Font = $fontSmall
    $lblVerInfo.AutoSize = $false
    $lblVerInfo.Size = New-Object System.Drawing.Size(1150, 30)
    $lblVerInfo.Location = New-Object System.Drawing.Point(15, 22)

    $btnVerify = New-Object System.Windows.Forms.Button
    $btnVerify.Text = 'Rescan and Diff'
    $btnVerify.Size = New-Object System.Drawing.Size(200, 32)
    $btnVerify.Font = $fontBigBtn
    $btnVerify.Location = New-Object System.Drawing.Point(15, 50)
    & $StyleBtn $btnVerify $global:clrOrange 'Re-run Test-DscConfiguration and diff against LastScan'

    $lblVerStatus = & $MakeLbl '' 230 60 900 $global:clrCyan
    $grpVerCtl.Controls.AddRange(@($lblVerInfo, $btnVerify, $lblVerStatus))

    $grpVerGrid = & $MakeGB 'Diff Results' 15 115 1180 490
    $grpVerGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $grpVerGrid.Padding = New-Object System.Windows.Forms.Padding(15)
    $gridVer = New-Object System.Windows.Forms.DataGridView
    $gridVer.Dock = [System.Windows.Forms.DockStyle]::Fill
    $gridVer.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    & $StyleGrid $gridVer
    foreach ($cd in @(
        @{N='Host';    H='Host';       W=12; M=100},
        @{N='Tech';    H='Technology'; W=14; M=140},
        @{N='VulnID';  H='VulnID';     W=10; M=80 },
        @{N='Before';  H='Before';     W=8;  M=70 },
        @{N='After';   H='After';      W=8;  M=70 },
        @{N='Outcome'; H='Outcome';    W=12; M=110},
        @{N='Title';   H='Title';      W=40; M=260}
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name=$cd.N; $c.HeaderText=$cd.H
        $c.FillWeight=$cd.W; $c.MinimumWidth=$cd.M
        $c.ReadOnly=$true
        [void]$gridVer.Columns.Add($c)
    }
    $grpVerGrid.Controls.Add($gridVer)

    $btnVerify.Add_Click({
        if (-not $global:LastScan) {
            [System.Windows.Forms.MessageBox]::Show('No prior scan to diff against.','No baseline','OK','Warning') | Out-Null
            return
        }
        if (-not (Test-StigCredsReady -ActionName 'verification')) { return }
        $gridVer.Rows.Clear()
        $btnVerify.Enabled = $false

        $totalEntries = $global:LastScan.Hosts.Count
        $idx = 0
        $resolved=0; $stillFail=0; $regressed=0
        foreach ($hr in $global:LastScan.Hosts) {
            $idx++
            $h = $hr.Host
            $tech = $hr.Technology
            # Null-safe technology lookup (StrictMode 3 — see Apply tab note).
            $techDef = $global:SupportedTechnologies | Where-Object { $_.Key -eq $tech } | Select-Object -First 1
            $techDisplay = if ($techDef) { $techDef.Display } else { $tech }
            # Load rule catalog for THIS technology
            $catalog = Get-PowerStigRuleCatalog -Technology $tech
            $catMap = @{}
            foreach ($c in $catalog) { $catMap[$c.VulnID] = $c }
            $lblVerStatus.Text = "[$idx/$totalEntries] $h — $techDisplay..."
            [System.Windows.Forms.Application]::DoEvents()
            $mofFolder = if ($hr.MOFPath) { Split-Path $hr.MOFPath -Parent } else { $null }
            if (-not $mofFolder -or -not (Test-Path $mofFolder)) {
                $txt = "[$h] MOF missing — cannot rescan"
                $lblVerStatus.Text = $txt
                continue
            }
            $new = Invoke-StigEvaluation -MofFolder $mofFolder -ComputerName $h -Mode $global:ExecutionMode -Credential $global:RemoteCred
            $oldMap = @{}
            foreach ($r in $hr.Records) { if ($r.VulnID) { $oldMap[$r.VulnID] = $r } }
            foreach ($r in $new) {
                if (-not $r.VulnID) { continue }
                $before = if ($oldMap.ContainsKey($r.VulnID)) { if ($oldMap[$r.VulnID].InDesiredState) {'Pass'} else {'Fail'} } else { '?' }
                $after  = if ($r.InDesiredState) { 'Pass' } else { 'Fail' }
                $outcome = ''
                $color = $global:clrWhite
                if ($before -eq 'Fail' -and $after -eq 'Pass') { $outcome='Resolved';      $color=$global:clrGreen;  $resolved++ }
                elseif ($before -eq 'Pass' -and $after -eq 'Fail') { $outcome='Regression'; $color=$global:clrOrange; $regressed++ }
                elseif ($before -eq 'Fail' -and $after -eq 'Fail') { $outcome='Still Failing'; $color=$global:clrRed; $stillFail++ }
                else { $outcome='Unchanged Pass'; $color=$global:clrDim }
                $meta = $catMap[$r.VulnID]
                $rowIdx = $gridVer.Rows.Add($h, $techDisplay, $r.VulnID, $before, $after, $outcome, $(if($meta){$meta.Title}else{''}))
                $gridVer.Rows[$rowIdx].DefaultCellStyle.ForeColor = $color
            }
        }
        $lblVerStatus.Text = "Diff complete: $resolved resolved, $stillFail still failing, $regressed regression(s)."
        Write-Audit -Event 'Verify' -Details "resolved=$resolved stillFail=$stillFail regressed=$regressed"
        $btnVerify.Enabled = $true
    }.GetNewClosure())

    # v1.2.13: Fill first, then Top — reverse-Z-order docking.
    $tabVerify.Controls.AddRange(@($grpVerGrid, $grpVerCtl))
#endregion

#region ------------------------ TAB: CKLB IMPORT ------------------------
    # v1.3.0 — Import Evaluate-STIG CKLB findings, classify each finding into
    # PowerStigFixable / Justifiable / Residual / AlreadyClosed, and present
    # a worklist that operators can drive into PowerStig apply, AnswerFile
    # writes, and residual XLSX exports. Tasks 13/15 wire the action buttons.
    $tabCklbImport = New-Object System.Windows.Forms.TabPage
    $tabCklbImport.Text = '  CKLB Import  '
    $tabCklbImport.BackColor = $global:clrBG; $tabCklbImport.ForeColor = $global:clrWhite
    $tabCklbImport.Padding = New-Object System.Windows.Forms.Padding(15)

    # ---- Sources panel (left): Add button + ListBox + summary counts ----
    $grpCklbSrc = & $MakeGB 'CKLB Sources' 15 15 280 555 $global:clrPurple

    $btnAddCklb = New-Object System.Windows.Forms.Button
    $btnAddCklb.Text = '+ Add CKLB...'
    $btnAddCklb.Size = New-Object System.Drawing.Size(250, 32)
    $btnAddCklb.Font = $fontBigBtn
    $btnAddCklb.Location = New-Object System.Drawing.Point(15, 30)
    & $StyleBtn $btnAddCklb $global:clrPurple 'Pick one or more Evaluate-STIG .cklb files; classify findings against PowerStig + Justification Library'

    $lblSrcHeader = & $MakeLbl 'Imported files:' 15 75 250
    $lstSources = New-Object System.Windows.Forms.ListBox
    $lstSources.Location = New-Object System.Drawing.Point(15, 96)
    $lstSources.Size = New-Object System.Drawing.Size(250, 220)
    $lstSources.BackColor = $global:clrInputBG; $lstSources.ForeColor = $global:clrWhite
    $lstSources.Font = $fontSmall
    $lstSources.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $lstSources.IntegralHeight = $false

    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.Text = "Summary:`n  PS-fix               : 0`n  Justify              : 0`n  Residual             : 0`n  Already final (NF/NA): 0"
    $lblSummary.ForeColor = $global:clrWhite
    $lblSummary.Font = $fontMono
    $lblSummary.AutoSize = $false
    $lblSummary.Location = New-Object System.Drawing.Point(15, 326)
    $lblSummary.Size = New-Object System.Drawing.Size(250, 110)

    $grpCklbSrc.Controls.AddRange(@($btnAddCklb, $lblSrcHeader, $lstSources, $lblSummary))

    # ---- Findings grid (top-right): one row per finding ----
    $grpCklbGrid = & $MakeGB 'Findings' 305 15 890 360 $global:clrCyan
    $grdFindings = New-Object System.Windows.Forms.DataGridView
    $grdFindings.Location = New-Object System.Drawing.Point(15, 28)
    $grdFindings.Size = New-Object System.Drawing.Size(860, 320)
    $grdFindings.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor `
                          [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $grdFindings.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    & $StyleGrid $grdFindings
    foreach ($cd in @(
        @{N='Sev';     H='Sev';     W=5;  M=50 },
        @{N='Host';    H='Host';    W=12; M=110},
        @{N='STIG';    H='STIG';    W=18; M=160},
        @{N='VulnId';  H='VulnId';  W=10; M=80 },
        @{N='Status';  H='Status';  W=10; M=80 },
        @{N='Class';   H='Class';   W=14; M=130},
        @{N='Action';  H='Action';  W=14; M=120}
    )) {
        $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $c.Name = $cd.N; $c.HeaderText = $cd.H
        $c.FillWeight = $cd.W; $c.MinimumWidth = $cd.M
        $c.ReadOnly = $true
        [void]$grdFindings.Columns.Add($c)
    }
    # C-1 fix: row indices must stay aligned with $global:CklbImport.Findings.
    # User-driven sort would reorder visual rows without sorting the backing
    # array, causing every SelectedRows[0].Index access to read/mutate the
    # wrong record (Detail pane, Mark NF/NA, Apply, AnswerFile export).
    foreach ($col in $grdFindings.Columns) {
        $col.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    }
    $grpCklbGrid.Controls.Add($grdFindings)

    # ---- Detail panel (mid-right): selected finding's check / fix / observed text ----
    $grpCklbDetail = & $MakeGB 'Detail' 305 380 890 190 $global:clrCyan
    $txtDetail = New-Object System.Windows.Forms.TextBox
    $txtDetail.Multiline = $true; $txtDetail.ReadOnly = $true
    $txtDetail.ScrollBars = 'Vertical'; $txtDetail.Font = $fontMono
    $txtDetail.BackColor = $global:clrInputBG; $txtDetail.ForeColor = $global:clrWhite
    $txtDetail.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $txtDetail.Location = New-Object System.Drawing.Point(15, 28)
    $txtDetail.Size = New-Object System.Drawing.Size(860, 150)
    $txtDetail.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor `
                        [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $grpCklbDetail.Controls.Add($txtDetail)

    # ---- Action bar (bottom-full): four CKLB import action buttons ----
    $grpCklbActions = & $MakeGB 'Actions' 15 580 1180 60 $global:clrOrange

    $btnApplyFixes = New-Object System.Windows.Forms.Button
    $btnApplyFixes.Text = 'Apply Fixes'
    $btnApplyFixes.Size = New-Object System.Drawing.Size(180, 28)
    $btnApplyFixes.Location = New-Object System.Drawing.Point(15, 22)
    & $StyleBtn $btnApplyFixes $global:clrGreen 'Run PowerStig DSC apply for findings classed PowerStigFixable'

    $btnMarkAnswer = New-Object System.Windows.Forms.Button
    $btnMarkAnswer.Text = 'Mark NF/NA...'
    $btnMarkAnswer.Size = New-Object System.Drawing.Size(180, 28)
    $btnMarkAnswer.Location = New-Object System.Drawing.Point(205, 22)
    & $StyleBtn $btnMarkAnswer $global:clrCyan 'Open the justification dialog for the selected finding'

    $btnExportAF = New-Object System.Windows.Forms.Button
    $btnExportAF.Text = 'Export AnswerFiles'
    $btnExportAF.Size = New-Object System.Drawing.Size(180, 28)
    $btnExportAF.Location = New-Object System.Drawing.Point(395, 22)
    & $StyleBtn $btnExportAF $global:clrPurple 'Write Evaluate-STIG AnswerFile XML for justified findings'

    $btnExportResid = New-Object System.Windows.Forms.Button
    $btnExportResid.Text = 'Export Worklist'
    $btnExportResid.Size = New-Object System.Drawing.Size(180, 28)
    $btnExportResid.Location = New-Object System.Drawing.Point(585, 22)
    & $StyleBtn $btnExportResid $global:clrOrange 'Export residual findings as XLSX worklist'

    $grpCklbActions.Controls.AddRange(@($btnApplyFixes, $btnMarkAnswer, $btnExportAF, $btnExportResid))

    # ---- + Add CKLB... handler: pick files, build rule map + library lazily,
    # parse + classify each finding, append to global state, refresh grid + summary.
    $btnAddCklb.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Multiselect = $true
        $ofd.Filter = 'STIG Viewer 3 Checklist (*.cklb)|*.cklb'
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

        # Library and rule map are session-scoped — load once, reuse for all
        # subsequent imports. Building the rule map walks every XCCDF in the
        # PowerStig StigData root, so it's not free.
        # I-4 fix: switch to WaitCursor during the multi-second lazy build so
        # the form doesn't appear frozen to field operators on slow boxes.
        # Using [Cursor]::Current keeps this robust to form-variable naming.
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            if (-not $global:CklbImport.JustificationLib) {
                $libPath = Join-Path $global:WorkspaceRoot 'JustificationLibrary.json'
                $global:CklbImport.JustLibPath = $libPath
                try {
                    $global:CklbImport.JustificationLib = Get-StigJustificationLibrary -Path $libPath
                } catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to load justification library:`n$($_.Exception.Message)",
                        'Justification library error','OK','Error') | Out-Null
                    return
                }
            }
            if (-not $global:CklbImport.PowerStigRuleMap) {
                $stigDataRoot = $null
                $psModule = Get-Module -ListAvailable -Name PowerStig | Sort-Object Version -Descending | Select-Object -First 1
                if ($psModule) {
                    $stigDataRoot = Join-Path (Split-Path $psModule.Path -Parent) 'StigData'
                }
                $psVersion = if ($psModule) { [string]$psModule.Version } else { 'unknown' }
                $cachePath = Join-Path $global:WorkspaceRoot 'PowerStigRuleMap.json'
                try {
                    # v1.3.2: routes through Get-PowerStigRuleMap so the
                    # multi-second StigData walk is paid once per PowerStig
                    # version, not on every first-import.
                    $global:CklbImport.PowerStigRuleMap = Get-PowerStigRuleMap -StigDataRoot ([string]$stigDataRoot) -PowerStigVersion $psVersion -CachePath $cachePath
                } catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to build PowerStig rule map:`n$($_.Exception.Message)",
                        'PowerStig rule map error','OK','Error') | Out-Null
                    return
                }
            }
        } finally {
            [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
        }

        $totalAdded = 0
        foreach ($file in $ofd.FileNames) {
            try {
                $f = Import-EvaluateStigCklb -Path $file
                foreach ($rec in $f) {
                    Set-FindingClassification -Finding $rec -RuleMap $global:CklbImport.PowerStigRuleMap -Library $global:CklbImport.JustificationLib
                }
                $global:CklbImport.SourceFiles += $file
                $global:CklbImport.Findings    += $f
                [void]$lstSources.Items.Add(("{0}  ({1} rules)" -f (Split-Path -Leaf $file), $f.Count))
                $totalAdded += $f.Count
            } catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'CKLB import error', 'OK', 'Error') | Out-Null
                Write-CklbAuditEvent -Event CklbImport -Status Failure -ItemCount 0 -Details ("file={0} err={1}" -f (Split-Path -Leaf $file), $_.Exception.Message)
            }
        }

        # Refresh grid + summary counters from the FULL findings collection
        # (rebuild rather than append-only so re-classifications would surface
        # if a future code path mutates existing rows).
        $grdFindings.Rows.Clear()
        foreach ($r in $global:CklbImport.Findings) {
            [void]$grdFindings.Rows.Add($r.Severity, $r.AssetHost, $r.StigShortName, $r.VulnId, $r.Status, $r.Class, $r.PendingAction)
        }
        $byClass = @{}
        foreach ($r in $global:CklbImport.Findings) {
            $k = if ($r.Class) { [string]$r.Class } else { '<unset>' }
            if (-not $byClass.ContainsKey($k)) { $byClass[$k] = 0 }
            $byClass[$k]++
        }
        $lblSummary.Text = ("Summary:`n  PS-fix               : {0}`n  Justify              : {1}`n  Residual             : {2}`n  Already final (NF/NA): {3}" -f `
            [int]$byClass['PowerStigFixable'], [int]$byClass['Justifiable'], [int]$byClass['Residual'], [int]$byClass['AlreadyClosed'])

        Write-CklbAuditEvent -Event CklbImport -Status Success -ItemCount $totalAdded -Details ("files={0}" -f $ofd.FileNames.Count)
    }.GetNewClosure())

    # ---- Selection-change: refresh detail textbox with the selected finding's
    # check / fix / observed text. The grid is read-only and FullRowSelect, so
    # SelectedRows[0].Index lines up 1-to-1 with $global:CklbImport.Findings.
    $grdFindings.Add_SelectionChanged({
        if ($grdFindings.SelectedRows.Count -lt 1) { $txtDetail.Text = ''; return }
        $rowIdx = $grdFindings.SelectedRows[0].Index
        if ($rowIdx -lt 0 -or $rowIdx -ge $global:CklbImport.Findings.Count) { return }
        $r = $global:CklbImport.Findings[$rowIdx]
        if (-not $r) { return }
        $txtDetail.Text = @"
$($r.VulnId)   $($r.StigShortName)   Severity: $($r.Severity)   Class: $($r.Class)
Status (CKLB): $($r.Status)
PendingAction: $($r.PendingAction)
PowerStigHint: $($r.PowerStigHint)

Check:
$($r.CheckText)

Fix:
$($r.FixText)

Evaluate-STIG observed:
$($r.FindingDetails)
"@
    }.GetNewClosure())

    # ---- Action handlers: Mark NF/NA dialog, PowerStig Apply (stubbed v1.3.1),
    # Evaluate-STIG AnswerFile export, residual worklist XLSX export.
    $btnMarkAnswer.Add_Click({
        if ($grdFindings.SelectedRows.Count -lt 1) {
            [System.Windows.Forms.MessageBox]::Show('Select one or more findings first.','No selection','OK','Information') | Out-Null
            return
        }
        $sel = @()
        foreach ($row in $grdFindings.SelectedRows) {
            $sel += $global:CklbImport.Findings[$row.Index]
        }
        $sel = @($sel | Where-Object { $_.Class -ne 'AlreadyClosed' })
        if ($sel.Count -lt 1) {
            [System.Windows.Forms.MessageBox]::Show('Selected rows are all already closed.','Nothing to mark','OK','Information') | Out-Null
            return
        }
        $r = Show-StigMarkAnswerDialog -Findings $sel -Library $global:CklbImport.JustificationLib
        if ($r.Cancelled) { return }

        if ($r.SaveAsNew -and $r.Label) {
            $stigShortNames = @($sel | ForEach-Object StigShortName | Sort-Object -Unique)
            $entry = New-StigJustificationEntry -Label $r.Label -Status $r.Status -Comment $r.Comment -StigShortNames $stigShortNames -VulnIds @()
            $global:CklbImport.JustificationLib.Entries = @($global:CklbImport.JustificationLib.Entries) + $entry
            Save-StigJustificationLibrary -Library $global:CklbImport.JustificationLib -Path $global:CklbImport.JustLibPath
            $r.PickedId = $entry.Id
        }

        # I-2 fix: when the operator picks an existing library entry (rather
        # than creating a new one), bump TimesUsed + LastUsedAt and persist.
        # Spec 308-311: dropdown ordering depends on these counters.
        if (-not $r.SaveAsNew -and $r.PickedId) {
            $hit = $global:CklbImport.JustificationLib.Entries | Where-Object { $_.Id -eq $r.PickedId } | Select-Object -First 1
            if ($hit) {
                $hit.TimesUsed  = [int]$hit.TimesUsed + 1
                $hit.LastUsedAt = (Get-Date).ToUniversalTime().ToString('o')
                Save-StigJustificationLibrary -Library $global:CklbImport.JustificationLib -Path $global:CklbImport.JustLibPath
            }
        }

        foreach ($f in $sel) {
            $f.PendingAction   = ('Answer' + $r.Status)   # AnswerNF | AnswerNA
            $f.PendingJustId   = $r.PickedId
            $f.Comments        = $r.Comment
            # C-2 fix: persist per-host scoping so AnswerFile export knows
            # which Hostname attribute to write on the <Answer> element.
            $f.PendingHostname = [string]$r.Hostname
        }
        Update-StigFindingClassifications

        for ($i = 0; $i -lt $grdFindings.Rows.Count; $i++) {
            $f = $global:CklbImport.Findings[$i]
            $grdFindings.Rows[$i].Cells['Class'].Value  = $f.Class
            $grdFindings.Rows[$i].Cells['Action'].Value = $f.PendingAction
        }
    }.GetNewClosure())

    $btnApplyFixes.Add_Click({
        # v1.3.3 I-C — explicit PowerStig-presence guard. Without this,
        # PowerStig missing -> empty rule map -> all findings classified
        # Residual -> candidate count zero -> "Nothing to apply" message
        # that doesn't tell the operator the actual reason.
        $psModuleAvailable = [bool](Get-Module -ListAvailable -Name PowerStig | Select-Object -First 1)
        if (-not $psModuleAvailable) {
            [System.Windows.Forms.MessageBox]::Show(
                "PowerStig is not installed.`n`nAFNET / air-gapped: install PowerStig from the About tab (Install Modules Offline). With internet: Install-Module PowerStig -Scope AllUsers from an elevated PowerShell.`n`nUntil then, use Mark NF/NA + Export AnswerFiles for documentation-only remediation.",
                'PowerStig not installed','OK','Warning') | Out-Null
            return
        }
        $candidates = @($global:CklbImport.Findings | Where-Object { $_.Class -eq 'PowerStigFixable' })
        if (-not $candidates -or $candidates.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No PowerStig-fixable findings to apply.','Nothing to apply','OK','Information') | Out-Null
            return
        }
        $hostCount = (@($candidates | ForEach-Object AssetHost | Sort-Object -Unique)).Count
        $msg = ("About to apply PowerStig DSC remediation against {0} matched rule(s) across {1} host(s). Existing typed-confirm + restore-point gates apply per host. Continue?" -f
                $candidates.Count, $hostCount)
        $resp = [System.Windows.Forms.MessageBox]::Show($msg,'Confirm Apply','YesNo','Question')
        if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        foreach ($c in $candidates) { $c.PendingAction = 'Apply' }
        $mode = if ($global:ExecutionMode) { $global:ExecutionMode } elseif ($global:CurrentScan -and $global:CurrentScan.Mode) { $global:CurrentScan.Mode } else { 'Local' }
        try {
            $results = Invoke-StigApplyFromCklb -Findings $global:CklbImport.Findings -Mode $mode -RuleMap $global:CklbImport.PowerStigRuleMap -Credential $global:RemoteCred
            $okCount  = (@($results | Where-Object { -not $_.Error })).Count
            $errCount = (@($results | Where-Object {     $_.Error })).Count
            Write-CklbAuditEvent -Event CklbApply -Status $(if ($errCount){'Failure'}else{'Success'}) -ItemCount $candidates.Count -Details ("ok=$okCount err=$errCount")
            [System.Windows.Forms.MessageBox]::Show(("Apply complete. OK: $okCount  Errors: $errCount"),'Apply','OK','Information') | Out-Null
        } catch {
            Write-CklbAuditEvent -Event CklbApply -Status Failure -ItemCount $candidates.Count -Details $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Apply error','OK','Error') | Out-Null
            # I-1 fix: roll back the speculative PendingAction='Apply' stamps
            # so candidate rows remain in the residual worklist (the worklist
            # exporter excludes PowerStigFixable rows with non-null PendingAction).
            foreach ($c in $candidates) {
                if ($c.PendingAction -eq 'Apply') { $c.PendingAction = $null }
            }
        }

        for ($i = 0; $i -lt $grdFindings.Rows.Count; $i++) {
            $grdFindings.Rows[$i].Cells['Action'].Value = $global:CklbImport.Findings[$i].PendingAction
        }
    }.GetNewClosure())

    $btnExportAF.Add_Click({
        $authored = @($global:CklbImport.Findings | Where-Object { $_.PendingAction -in @('AnswerNF','AnswerNA') })
        if (-not $authored -or $authored.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No findings have a pending answer set. Use Mark NF/NA first.','Nothing to export','OK','Information') | Out-Null
            return
        }
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Choose folder for Evaluate-STIG AnswerFiles (recommended: <Evaluate-STIG>\AnswerFiles)'
        if ($fbd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $outDir = $fbd.SelectedPath

        $evalStatus = @{ 'open'='O'; 'not_reviewed'='NR'; 'not_a_finding'='NF'; 'not_applicable'='NA' }

        $byStig = $authored | Group-Object StigShortName
        $writeCount = 0; $errCount = 0
        foreach ($g in $byStig) {
            $entries = foreach ($f in $g.Group) {
                [pscustomobject]@{
                    VulnId         = $f.VulnId
                    ExpectedStatus = $evalStatus[$f.Status.ToLowerInvariant()]
                    # C-2 fix: honour per-host scope from Mark NF/NA dialog.
                    # When unchecked, PendingHostname stays '' (applies to all
                    # hosts running this STIG); when checked it carries the
                    # finding's AssetHost forward to the AnswerFile XML.
                    Hostname       = [string]$f.PendingHostname
                    Status         = $(if ($f.PendingAction -eq 'AnswerNA') { 'NA' } else { 'NF' })
                    Comment        = $f.Comments
                }
            }
            $outFile = Join-Path $outDir ("{0}.xml" -f $g.Name)
            try {
                Export-EvaluateStigAnswerFile -StigShortName $g.Name -Entries $entries -Path $outFile
                $writeCount++
            } catch {
                $errCount++
                if ($_.Exception.Message -match 'AnswerFileConflict') {
                    [System.Windows.Forms.MessageBox]::Show(("$($_.Exception.Message)`n`nResolve in STIG Viewer 3 or remove the conflicting answer manually."),'Conflict',[System.Windows.Forms.MessageBoxButtons]::OK,'Warning') | Out-Null
                } else {
                    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,"AnswerFile error: $($g.Name)",'OK','Error') | Out-Null
                }
            }
        }
        Write-CklbAuditEvent -Event AnswerFileWrite -Status $(if ($errCount){'Failure'}else{'Success'}) -ItemCount $authored.Count -Details ("files=$writeCount errors=$errCount dir=$outDir")
        if ($writeCount -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(("Wrote $writeCount AnswerFile(s) to:`n$outDir"),'AnswerFiles exported','OK','Information') | Out-Null
        }
    }.GetNewClosure())

    $btnExportResid.Add_Click({
        if (-not $global:CklbImport.Findings -or $global:CklbImport.Findings.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No findings imported yet.','Nothing to export','OK','Information') | Out-Null
            return
        }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter   = 'Excel Workbook (*.xlsx)|*.xlsx'
        $sfd.FileName = ("STIG_Residual_{0}.xlsx" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            Export-CklbResidualWorklist -Findings $global:CklbImport.Findings -Path $sfd.FileName
            $residualCount = (@($global:CklbImport.Findings | Where-Object { $_.Class -eq 'Residual' })).Count
            Write-CklbAuditEvent -Event CklbResidualExport -Status Success -ItemCount $residualCount -Details ("path={0}" -f $sfd.FileName)
            [System.Windows.Forms.MessageBox]::Show(("Wrote residual worklist:`n{0}" -f $sfd.FileName),'Worklist exported','OK','Information') | Out-Null
        } catch {
            Write-CklbAuditEvent -Event CklbResidualExport -Status Failure -ItemCount 0 -Details $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Worklist error','OK','Error') | Out-Null
        }
    }.GetNewClosure())

    $tabCklbImport.Controls.AddRange(@($grpCklbSrc, $grpCklbGrid, $grpCklbDetail, $grpCklbActions))
#endregion

#region ------------------------ TAB: REPORTS ----------------------------
    $tabReports = New-Object System.Windows.Forms.TabPage
    $tabReports.Text = '  Reports  '
    $tabReports.BackColor = $global:clrBG; $tabReports.ForeColor = $global:clrWhite

    $grpRep = & $MakeGB 'Export Current Scan' 15 15 1180 200
    $lblRepInfo = New-Object System.Windows.Forms.Label
    $lblRepInfo.Text = "Per-host DISA-compliant exports. CKL = STIG Viewer v2 XML. CKLB = STIG Viewer 3 JSON. POA&M = eMASS import template. XLSX = rollup dashboard."
    $lblRepInfo.ForeColor = $global:clrWhite; $lblRepInfo.Font = $fontSmall
    $lblRepInfo.AutoSize = $true
    $lblRepInfo.Location = New-Object System.Drawing.Point(15, 30)

    $btnExportXlsx = New-Object System.Windows.Forms.Button
    $btnExportXlsx.Text = 'Export XLSX...'
    $btnExportXlsx.Size = New-Object System.Drawing.Size(180, 36)
    $btnExportXlsx.Font = $fontBigBtn
    $btnExportXlsx.Location = New-Object System.Drawing.Point(15, 60)
    & $StyleBtn $btnExportXlsx $global:clrGreen 'Export scan rollup XLSX (Summary / PerRule / Skipped / AuditTrail)'

    $btnExportCkl = New-Object System.Windows.Forms.Button
    $btnExportCkl.Text = 'Export CKL (v2)...'
    $btnExportCkl.Size = New-Object System.Drawing.Size(180, 36)
    $btnExportCkl.Font = $fontBigBtn
    $btnExportCkl.Location = New-Object System.Drawing.Point(205, 60)
    & $StyleBtn $btnExportCkl $global:clrPurple 'Export per-host STIG Viewer v2 checklist (.ckl) files'

    $btnExportCklb = New-Object System.Windows.Forms.Button
    $btnExportCklb.Text = 'Export CKLB (v3)...'
    $btnExportCklb.Size = New-Object System.Drawing.Size(180, 36)
    $btnExportCklb.Font = $fontBigBtn
    $btnExportCklb.Location = New-Object System.Drawing.Point(395, 60)
    & $StyleBtn $btnExportCklb $global:clrPurple 'Export per-host STIG Viewer v3 checklist (.cklb) JSON files'

    $btnExportPoam = New-Object System.Windows.Forms.Button
    $btnExportPoam.Text = 'Export POA&M...'
    $btnExportPoam.Size = New-Object System.Drawing.Size(180, 36)
    $btnExportPoam.Font = $fontBigBtn
    $btnExportPoam.Location = New-Object System.Drawing.Point(585, 60)
    & $StyleBtn $btnExportPoam $global:clrOrange 'Export DoD RMF POA&M worksheet (XLSX) for open + risk-accepted findings'

    $btnOpenReports = New-Object System.Windows.Forms.Button
    $btnOpenReports.Text = 'Open Reports Folder'
    $btnOpenReports.Size = New-Object System.Drawing.Size(180, 36)
    $btnOpenReports.Font = $fontBigBtn
    $btnOpenReports.Location = New-Object System.Drawing.Point(775, 60)
    & $StyleBtn $btnOpenReports $global:clrCyan 'Open the reports folder in Explorer'
    $btnOpenReports.Add_Click({ Start-Process explorer.exe $global:ReportRoot }.GetNewClosure())

    $lblRepStatus = & $MakeLbl '' 15 110 1150 $global:clrCyan
    $grpRep.Controls.AddRange(@($lblRepInfo, $btnExportXlsx, $btnExportCkl, $btnExportCklb, $btnExportPoam, $btnOpenReports, $lblRepStatus))

    $btnExportXlsx.Add_Click({
        if (-not $global:CurrentScan) {
            [System.Windows.Forms.MessageBox]::Show('No scan to export. Run Scan first.','No scan','OK','Warning') | Out-Null
            return
        }
        if (-not $global:PrereqStatus.ImportExcelInstalled) {
            [System.Windows.Forms.MessageBox]::Show('ImportExcel module is not installed. Install it and re-check prereqs.','No ImportExcel','OK','Error') | Out-Null
            return
        }
        $default = Join-Path $global:ReportRoot ("STIG_Scan_{0}.xlsx" -f $global:CurrentScan.ScanId)
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = 'Excel (*.xlsx)|*.xlsx'
        $sfd.InitialDirectory = $global:ReportRoot
        $sfd.FileName = Split-Path $default -Leaf
        if ($sfd.ShowDialog() -ne 'OK') { return }
        try {
            $out = Export-ScanToXlsx -ScanData $global:CurrentScan -OutputPath $sfd.FileName
            $lblRepStatus.Text = "Exported: $out"
            Write-Audit -Event 'Export' -Details "path=$out"
        } catch {
            $lblRepStatus.Text = "Export FAILED: $($_.Exception.Message)"
        }
    }.GetNewClosure())

    $btnExportCkl.Add_Click({
        if (-not $global:CurrentScan) {
            [System.Windows.Forms.MessageBox]::Show('No scan to export. Run Scan first.','No scan','OK','Warning') | Out-Null
            return
        }
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Choose folder for CKL files (one per host per technology)'
        $fbd.SelectedPath = $global:ChecklistRoot
        if ($fbd.ShowDialog() -ne 'OK') { return }
        $outDir = $fbd.SelectedPath
        $count = 0
        foreach ($hr in $global:CurrentScan.Hosts) {
            $safe = ($hr.Host -replace '[^A-Za-z0-9_\-]','_')
            $fname = "${safe}_$($hr.Technology)_$($global:CurrentScan.ScanId).ckl"
            $outPath = Join-Path $outDir $fname
            try {
                [void](Export-ScanToCkl -HostResult $hr -OutputPath $outPath)
                $count++
            } catch {
                $lblRepStatus.Text = "CKL error ($($hr.Host)/$($hr.Technology)): $($_.Exception.Message)"
            }
        }
        $lblRepStatus.Text = "Exported $count CKL file(s) to $outDir"
        Write-Audit -Event 'ExportCKL' -Details "count=$count dir=$outDir"
    }.GetNewClosure())

    $btnExportCklb.Add_Click({
        if (-not $global:CurrentScan) {
            [System.Windows.Forms.MessageBox]::Show('No scan to export. Run Scan first.','No scan','OK','Warning') | Out-Null
            return
        }
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Choose folder for CKLB (STIG Viewer 3) files (one per host per technology)'
        $fbd.SelectedPath = $global:ChecklistRoot
        if ($fbd.ShowDialog() -ne 'OK') { return }
        $outDir = $fbd.SelectedPath
        $count = 0
        foreach ($hr in $global:CurrentScan.Hosts) {
            $safe = ($hr.Host -replace '[^A-Za-z0-9_\-]','_')
            $fname = "${safe}_$($hr.Technology)_$($global:CurrentScan.ScanId).cklb"
            $outPath = Join-Path $outDir $fname
            try {
                [void](Export-ScanToCklb -HostResult $hr -OutputPath $outPath)
                $count++
            } catch {
                $lblRepStatus.Text = "CKLB error ($($hr.Host)/$($hr.Technology)): $($_.Exception.Message)"
            }
        }
        $lblRepStatus.Text = "Exported $count CKLB file(s) to $outDir"
        Write-Audit -Event 'ExportCKLB' -Details "count=$count dir=$outDir"
    }.GetNewClosure())

    $btnExportPoam.Add_Click({
        if (-not $global:CurrentScan) {
            [System.Windows.Forms.MessageBox]::Show('No scan to export. Run Scan first.','No scan','OK','Warning') | Out-Null
            return
        }
        if (-not $global:PrereqStatus.ImportExcelInstalled) {
            [System.Windows.Forms.MessageBox]::Show('ImportExcel module is not installed. Install it and re-check prereqs.','No ImportExcel','OK','Error') | Out-Null
            return
        }
        $default = Join-Path $global:ReportRoot ("STIG_POAM_{0}.xlsx" -f $global:CurrentScan.ScanId)
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = 'Excel (*.xlsx)|*.xlsx'
        $sfd.InitialDirectory = $global:ReportRoot
        $sfd.FileName = Split-Path $default -Leaf
        if ($sfd.ShowDialog() -ne 'OK') { return }
        try {
            $out = Export-ScanToPoam -ScanData $global:CurrentScan -OutputPath $sfd.FileName
            $lblRepStatus.Text = "POA&M exported: $out"
            Write-Audit -Event 'ExportPOAM' -Details "path=$out"
        } catch {
            $lblRepStatus.Text = "POA&M export FAILED: $($_.Exception.Message)"
        }
    }.GetNewClosure())

    $tabReports.Controls.Add($grpRep)
#endregion

#region ------------------------ TAB: HELP -------------------------------
    $tabHelp = New-Object System.Windows.Forms.TabPage
    $tabHelp.Text = '  Help  '
    $tabHelp.BackColor = $global:clrBG; $tabHelp.ForeColor = $global:clrWhite

    # -------- Workflow card (left column, full height): 7 step sub-panels --------
    $grpHelpFlow = & $MakeGB 'Workflow' 15 15 590 640 $global:clrPurple
    $fontStepNum   = New-Object System.Drawing.Font('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
    $fontStepName  = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
    $fontStepDesc  = New-Object System.Drawing.Font('Segoe UI', 8.5)

    # Same phase-color mapping as the About tab workflow — each step gets a
    # distinct semantic color. See $aboutSteps near line 1648 for rationale.
    $stepDefs = @(
        @{ Num='1'; Name='About / Setup';   Color=$global:clrInfo;   Desc="Confirm operator, verify prerequisites, pick Local or Remote.`r`nSet credentials first if using Remote mode." },
        @{ Num='2'; Name='Targets';         Color=$global:clrGreen;  Desc="Type/paste hosts and click ``+ Add to list`` (or ``Add this`r`nmachine``). Test Reachability runs a TCP 5985/445 probe and detects OS/role." },
        @{ Num='3'; Name='Scan (Evaluate)'; Color=$global:clrGreen;  Desc="Compiles a MOF per host using PowerStig's WindowsClient DSC,`r`nthen runs Test-DscConfiguration and stores evaluation.json." },
        @{ Num='4'; Name='Checklist Review';Color=$global:clrPurple; Desc="Per-rule grid joined to the PowerStig rule catalog.`r`nUncheck rules to exclude from Apply. Save skip-list persists it." },
        @{ Num='5'; Name='Apply (Remediate)';Color=$global:clrRed;   Desc="Creates restore point (workstations), recompiles MOF with`r`nskip-list, requires typing APPLY. DRY RUN preview available." },
        @{ Num='6'; Name='Verify';          Color=$global:clrOrange; Desc="Rescans each host and diffs vs baseline.`r`nGreen = Resolved, Red = Still Failing, Orange = Regression." },
        @{ Num='7'; Name='Reports';         Color=$global:clrMuted;  Desc="Export XLSX via ImportExcel: Summary / PerRule /`r`nSkipped / AuditTrail sheets." }
    )

    $stepY = 30
    $stepH = 80
    foreach ($step in $stepDefs) {
        $card = New-Object System.Windows.Forms.Panel
        $card.Size      = New-Object System.Drawing.Size(560, $stepH)
        $card.Location  = New-Object System.Drawing.Point(15, $stepY)
        $card.BackColor = $global:clrInputBG

        # 3px left accent bar in the step's color (JANET tool-card style)
        $bar = New-Object System.Windows.Forms.Panel
        $bar.Size      = New-Object System.Drawing.Size(3, $stepH)
        $bar.Location  = New-Object System.Drawing.Point(0, 0)
        $bar.BackColor = $step.Color
        $card.Controls.Add($bar)

        # Big colored step number
        $lblNum = New-Object System.Windows.Forms.Label
        $lblNum.Text      = $step.Num
        $lblNum.Font      = $fontStepNum
        $lblNum.ForeColor = $step.Color
        $lblNum.BackColor = [System.Drawing.Color]::Transparent
        $lblNum.AutoSize  = $false
        $lblNum.Size      = New-Object System.Drawing.Size(45, 50)
        $lblNum.Location  = New-Object System.Drawing.Point(12, 14)
        $lblNum.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $card.Controls.Add($lblNum)

        # Step name (white semibold)
        $lblName = New-Object System.Windows.Forms.Label
        $lblName.Text      = $step.Name
        $lblName.Font      = $fontStepName
        $lblName.ForeColor = $global:clrWhite
        $lblName.BackColor = [System.Drawing.Color]::Transparent
        $lblName.AutoSize  = $false
        $lblName.Size      = New-Object System.Drawing.Size(480, 22)
        $lblName.Location  = New-Object System.Drawing.Point(65, 10)
        $lblName.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $card.Controls.Add($lblName)

        # Description (dim, two lines)
        $lblDesc = New-Object System.Windows.Forms.Label
        $lblDesc.Text      = $step.Desc
        $lblDesc.Font      = $fontStepDesc
        $lblDesc.ForeColor = $global:clrDim
        $lblDesc.BackColor = [System.Drawing.Color]::Transparent
        $lblDesc.AutoSize  = $false
        $lblDesc.Size      = New-Object System.Drawing.Size(485, 40)
        $lblDesc.Location  = New-Object System.Drawing.Point(65, 32)
        $lblDesc.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
        $card.Controls.Add($lblDesc)

        $grpHelpFlow.Controls.Add($card)
        $stepY += ($stepH + 6)
    }

    # -------- Prerequisites card (right column top) --------
    $grpHelpPre = & $MakeGB 'Prerequisites' 615 15 590 200 $global:clrGreen
    $preItems = @(
        @{ Name='Windows PowerShell 5.1';        Detail='Ships with Windows 10/11 — AFNET target.' },
        @{ Name='PowerStig module';              Detail='Auto-installed at startup from PSGallery' },
        @{ Name='PSDesiredStateConfiguration';   Detail='Ships with Windows — no install needed.' },
        @{ Name='ImportExcel module';            Detail='Auto-installed at startup (required for XLSX export)' },
        @{ Name='Administrator elevation';       Detail='Required for Apply and Verify tabs.' },
        @{ Name='WinRM service';                 Detail='Required only for Remote mode.' }
    )
    $preY = 28
    foreach ($item in $preItems) {
        # Bullet dot in accent color
        $bullet = New-Object System.Windows.Forms.Label
        $bullet.Text      = [char]0x25CF   # ●
        $bullet.Font      = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $bullet.ForeColor = $global:clrCyan
        $bullet.BackColor = [System.Drawing.Color]::Transparent
        $bullet.AutoSize  = $false
        $bullet.Size      = New-Object System.Drawing.Size(18, 22)
        $bullet.Location  = New-Object System.Drawing.Point(15, $preY)
        $bullet.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $grpHelpPre.Controls.Add($bullet)

        $lblItemName = New-Object System.Windows.Forms.Label
        $lblItemName.Text      = $item.Name
        $lblItemName.Font      = $fontSmallBold
        $lblItemName.ForeColor = $global:clrWhite
        $lblItemName.BackColor = [System.Drawing.Color]::Transparent
        $lblItemName.AutoSize  = $false
        $lblItemName.Size      = New-Object System.Drawing.Size(220, 22)
        $lblItemName.Location  = New-Object System.Drawing.Point(38, $preY)
        $lblItemName.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $grpHelpPre.Controls.Add($lblItemName)

        $lblItemDetail = New-Object System.Windows.Forms.Label
        $lblItemDetail.Text      = $item.Detail
        $lblItemDetail.Font      = $fontSmall
        $lblItemDetail.ForeColor = $global:clrDim
        $lblItemDetail.BackColor = [System.Drawing.Color]::Transparent
        $lblItemDetail.AutoSize  = $false
        $lblItemDetail.Size      = New-Object System.Drawing.Size(310, 22)
        $lblItemDetail.Location  = New-Object System.Drawing.Point(260, $preY)
        $lblItemDetail.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $grpHelpPre.Controls.Add($lblItemDetail)

        $preY += 26
    }

    # -------- Launch & Workspace card (right column middle) --------
    $grpHelpLaunch = & $MakeGB 'Launch & Workspace' 615 225 590 200 $global:clrCyan

    $lblLaunchA = New-Object System.Windows.Forms.Label
    $lblLaunchA.Text      = "Right-click STIG_Tool.ps1 -> ``Run with PowerShell``"
    $lblLaunchA.Font      = $fontSmallBold
    $lblLaunchA.ForeColor = $global:clrWhite
    $lblLaunchA.AutoSize  = $false
    $lblLaunchA.Size      = New-Object System.Drawing.Size(560, 20)
    $lblLaunchA.Location  = New-Object System.Drawing.Point(15, 30)
    $grpHelpLaunch.Controls.Add($lblLaunchA)

    $lblLaunchB = New-Object System.Windows.Forms.Label
    $lblLaunchB.Text      = 'Use `Run as Administrator` for Apply and Verify.'
    $lblLaunchB.Font      = $fontSmall
    $lblLaunchB.ForeColor = $global:clrDim
    $lblLaunchB.AutoSize  = $false
    $lblLaunchB.Size      = New-Object System.Drawing.Size(560, 18)
    $lblLaunchB.Location  = New-Object System.Drawing.Point(15, 50)
    $grpHelpLaunch.Controls.Add($lblLaunchB)

    $lblLaunchC = New-Object System.Windows.Forms.Label
    $lblLaunchC.Text      = 'Or from an elevated PowerShell prompt:'
    $lblLaunchC.Font      = $fontSmall
    $lblLaunchC.ForeColor = $global:clrDim
    $lblLaunchC.AutoSize  = $false
    $lblLaunchC.Size      = New-Object System.Drawing.Size(560, 18)
    $lblLaunchC.Location  = New-Object System.Drawing.Point(15, 72)
    $grpHelpLaunch.Controls.Add($lblLaunchC)

    $lblLaunchD = New-Object System.Windows.Forms.Label
    $lblLaunchD.Text      = 'powershell -ExecutionPolicy Bypass -File .\STIG_Tool.ps1'
    $lblLaunchD.Font      = $fontMono
    $lblLaunchD.ForeColor = $global:clrCyan
    $lblLaunchD.BackColor = $global:clrInputBG
    $lblLaunchD.AutoSize  = $false
    $lblLaunchD.Size      = New-Object System.Drawing.Size(560, 22)
    $lblLaunchD.Location  = New-Object System.Drawing.Point(15, 92)
    $lblLaunchD.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $lblLaunchD.Padding   = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
    $grpHelpLaunch.Controls.Add($lblLaunchD)

    $lblWsTitle = New-Object System.Windows.Forms.Label
    $lblWsTitle.Text      = 'Workspace layout (auto-created beside STIG_Tool.ps1):'
    $lblWsTitle.Font      = $fontSmallBold
    $lblWsTitle.ForeColor = $global:clrWhite
    $lblWsTitle.AutoSize  = $false
    $lblWsTitle.Size      = New-Object System.Drawing.Size(560, 18)
    $lblWsTitle.Location  = New-Object System.Drawing.Point(15, 122)
    $grpHelpLaunch.Controls.Add($lblWsTitle)

    $lblWsBody = New-Object System.Windows.Forms.Label
    $lblWsBody.Text      = 'Configs  /  MOF  /  Evaluations  /  Checklists  /  Reports  /  SkipLists  /  Logs'
    $lblWsBody.Font      = $fontSmall
    $lblWsBody.ForeColor = $global:clrDim
    $lblWsBody.AutoSize  = $false
    $lblWsBody.Size      = New-Object System.Drawing.Size(560, 18)
    $lblWsBody.Location  = New-Object System.Drawing.Point(15, 142)
    $grpHelpLaunch.Controls.Add($lblWsBody)

    $lblWsFallback = New-Object System.Windows.Forms.Label
    $lblWsFallback.Text      = 'Falls back to %LOCALAPPDATA%\STIG_Tool\Workspace if script folder is read-only.'
    $lblWsFallback.Font      = $fontSmall
    $lblWsFallback.ForeColor = $global:clrDim
    $lblWsFallback.AutoSize  = $false
    $lblWsFallback.Size      = New-Object System.Drawing.Size(560, 18)
    $lblWsFallback.Location  = New-Object System.Drawing.Point(15, 160)
    $grpHelpLaunch.Controls.Add($lblWsFallback)

    # -------- Known Caveats card (right column bottom) --------
    $grpHelpCav = & $MakeGB 'Known Caveats' 615 435 590 220 $global:clrOrange
    $caveats = @(
        'Restore points only work on Workstation SKUs — skipped automatically on servers.',
        'PowerStig rule metadata (Title/Severity) requires the module to be installed on this box.',
        'Remote Test-DscConfiguration requires PowerStig on the TARGET machine too.',
        'Canceling mid-scan: runspaces close on next launch; in-flight MOFs are safe to discard.',
        'Audit log lives at Workspace\Logs\audit.log — TSV format, opens cleanly in Excel.'
    )
    $cavY = 30
    foreach ($line in $caveats) {
        $bull = New-Object System.Windows.Forms.Label
        $bull.Text      = [char]0x25B8   # ▸
        $bull.Font      = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $bull.ForeColor = $global:clrOrange
        $bull.BackColor = [System.Drawing.Color]::Transparent
        $bull.AutoSize  = $false
        $bull.Size      = New-Object System.Drawing.Size(18, 32)
        $bull.Location  = New-Object System.Drawing.Point(15, $cavY)
        $bull.TextAlign = [System.Drawing.ContentAlignment]::TopCenter
        $grpHelpCav.Controls.Add($bull)

        $cav = New-Object System.Windows.Forms.Label
        $cav.Text      = $line
        $cav.Font      = $fontSmall
        $cav.ForeColor = $global:clrDim
        $cav.BackColor = [System.Drawing.Color]::Transparent
        $cav.AutoSize  = $false
        $cav.Size      = New-Object System.Drawing.Size(540, 32)
        $cav.Location  = New-Object System.Drawing.Point(38, $cavY)
        $cav.TextAlign = [System.Drawing.ContentAlignment]::TopLeft
        $grpHelpCav.Controls.Add($cav)

        $cavY += 36
    }

    $tabHelp.Controls.AddRange(@($grpHelpFlow, $grpHelpPre, $grpHelpLaunch, $grpHelpCav))
#endregion

#region ------------------------ SIDEBAR NAV + ASSEMBLY ------------------
    # Tab registry — Start is index 0 so the tool lands there on launch.
    # Icons are Segoe MDL2 Assets glyphs looked up from the shared UI kit.
    $tabPages = @(
        @{ Key='Start';    Tab=$tabStart;    Label='Start';    Icon=$wIcons.Settings; Accent=$global:clrCyan   },
        @{ Key='Targets';  Tab=$tabTargets;  Label='Targets';  Icon=$wIcons.Target;   Accent=$global:clrGreen  },
        @{ Key='Scan';     Tab=$tabScan;     Label='Scan';     Icon=$wIcons.Search;   Accent=$global:clrGreen  },
        @{ Key='Review';   Tab=$tabReview;   Label='Review';   Icon=$wIcons.Check;    Accent=$global:clrCyan   },
        @{ Key='Apply';    Tab=$tabApply;    Label='Apply';    Icon=$wIcons.Shield;   Accent=$global:clrRed    },
        @{ Key='Verify';   Tab=$tabVerify;   Label='Verify';   Icon=$wIcons.Sync;     Accent=$global:clrOrange },
        @{ Key='CklbImport'; Tab=$tabCklbImport; Label='CKLB Import'; Icon=$wIcons.Upload; Accent=$global:clrPurple },
        @{ Key='Reports';  Tab=$tabReports;  Label='Reports';  Icon=$wIcons.Chart;    Accent=$global:clrPurple },
        @{ Key='Help';     Tab=$tabHelp;     Label='Help';     Icon=$wIcons.Document; Accent=$global:clrCyan   },
        @{ Key='About';    Tab=$tabAbout;    Label='About';    Icon=$wIcons.Info;     Accent=$global:clrCyan   }
    )
    foreach ($tp in $tabPages) { [void]$tabControl.TabPages.Add($tp.Tab) }

    # Build sidebar nav items via the shared New-WptNavItem factory. Each
    # item exposes its own state machine; Set-WptNavItemActive handles the
    # active / inactive visuals uniformly.
    $global:NavButtons = @{}
    $global:TabControl = $tabControl
    $global:TabPages   = $tabPages

    $navY  = 4
    $navH  = 42
    $navIdx = 0
    foreach ($tp in $tabPages) {
        $navIdx++
        $ni = New-WptNavItem -Key $tp.Key -Label $tp.Label -Icon $tp.Icon -Index $navIdx -Y $navY -W 252 -H $navH
        $ni.Tag['TabRef'] = $tp.Tab
        $navHost.Controls.Add($ni)
        $global:NavButtons[$tp.Key] = @{ NavItem = $ni; Tab = $tp.Tab; Accent = $tp.Accent; Key = $tp.Key }
        $global:WPT.UI.NavItems[$tp.Key] = $ni
        $navY += $navH
    }

    # Wire click handlers — each nav item and its inner controls (bar, number,
    # icon, label) need the same handler. The factory already routes
    # mouse-enter/leave; we add the click behaviour here because the tab
    # association is STIG-specific.
    foreach ($key in $global:NavButtons.Keys) {
        $entry = $global:NavButtons[$key]
        $captureKey = $key
        $handler = {
            Invoke-StigSetActiveTab -TabKey $captureKey
        }.GetNewClosure()
        $entry.NavItem.Add_Click($handler)
        foreach ($child in $entry.NavItem.Controls) { $child.Add_Click($handler) }
    }

    # Repaint nav when TabControl changes (keeps state in sync if code
    # programmatically switches tabs without going through a nav click).
    $tabControl.Add_SelectedIndexChanged({
        if ($global:TabControl -and $global:TabControl.SelectedTab) {
            $selected = $global:TabControl.SelectedTab
            foreach ($entry in $global:NavButtons.Values) {
                if ($entry.Tab -eq $selected) {
                    Set-WptNavItemActive -SidebarPanel $global:NavHost -Key $entry.Key
                    break
                }
            }
        }
    }.GetNewClosure())

    # Docking order matters: Bottom + Left first, then Fill last. The status
    # bar and sidebar consume their edges; the content host takes the rest.
    $AppForm.Controls.Add($pnlContentHost)
    $AppForm.Controls.Add($pnlSidebar)
    $AppForm.Controls.Add($pnlStatus)

    # Refresh prereqs on first show
    & $RefreshPre

    # Load persisted skip-lists for all supported technologies
    foreach ($tech in $global:SupportedTechnologies) {
        [void](Import-StigSkipList     -Technology $tech.Key)
        [void](Import-StigRuleMetadata -Technology $tech.Key)
    }

    # Paint the initial active nav item. Pass 'Start' explicitly because at
    # this point the form hasn't shown, so $tabControl.SelectedTab may be
    # null — the nav + tab state needs to be primed manually.
    Invoke-StigSetActiveTab -TabKey 'Start'

    # Comma-wrap guarantees a single-object pipeline output.
    # Without this, any accidental bare expression elsewhere in BuildAppForm
    # would turn the caller's $form into a multi-element array.
    ,$AppForm
}
#endregion

#region ------------------------ CLEANUP + ENTRY -------------------------
function CleanUp {
    # Stop and dispose the pulsing-dot timer. Without this the Timer keeps
    # ticking until GC, holding closures over $pnlPulse alive and leaking the
    # header panel chain.
    try {
        if ($global:pulseTimerRef) {
            $global:pulseTimerRef.Stop()
            $global:pulseTimerRef.Dispose()
            $global:pulseTimerRef = $null
        }
    } catch {}
    # Release the logo's GDI+ bitmap (and its backing MemoryStream) if set,
    # so the source image file isn't held locked after the process exits.
    try {
        if ($global:LogoImageRef) {
            $global:LogoImageRef.Dispose()
            $global:LogoImageRef = $null
        }
    } catch {}
    # Dispose any in-flight probe-job PowerShell instances before tearing
    # down the runspace pool. Without this, BeginInvoke handles whose
    # corresponding EndInvoke never ran (probe still in flight at form
    # close) leak the PowerShell instance and the runspace.
    try {
        if ($global:RunningJobs) {
            foreach ($job in $global:RunningJobs) {
                if ($job -and $job.PS) {
                    try { $job.PS.Stop() } catch {}
                    try { $job.PS.Dispose() } catch {}
                }
            }
            $global:RunningJobs = @()
        }
    } catch {}
    # Flush any buffered audit lines if the share is reachable now.
    try {
        if ($global:AuditFallbackBuffer.Count -gt 0 -and (Test-Path $global:AuditLogPath)) {
            foreach ($line in $global:AuditFallbackBuffer) {
                Add-Content -Path $global:AuditLogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            $global:AuditFallbackBuffer.Clear()
        }
    } catch {}
    Close-RunspacePool
}

# Refresh the Scan-tab host picker (CheckedListBox). Reads $global:Targets
# (populated by Test Reachability on the Targets tab) and rebuilds the list
# so the Scan tab shows a live view of discovered hosts + their applicable
# STIGs. Hosts with no STIGs are listed but disabled.
#
# Must be a NAMED function (not a $global:ScriptBlock variable) because
# event handler closures can't reliably resolve scriptblock vars from
# script scope across modal/runspace context transitions. Same pattern
# as Invoke-StigSetActiveTab below.
function Update-StigScanHostPicker {
    $clb = $global:clbScanHostsRef
    if (-not $clb) { return }
    $clb.Items.Clear()
    if (-not $global:Targets -or $global:Targets.Count -eq 0) {
        [void]$clb.Items.Add('  (no hosts in list - go to Targets tab and click "+ Add to list")', $false)
        return
    }
    foreach ($target in $global:Targets) {
        if ($target.Technologies -and $target.Technologies.Count -gt 0) {
            $label = "$($target.Host)  [$($target.Role)]  ->  $($target.Technologies -join ', ')"
            # Default eligible hosts to checked so one click of Start Scan
            # does the common-case "scan everything discovered" action.
            [void]$clb.Items.Add($label, $true)
        } else {
            $role = if ($target.Role) { $target.Role } else { 'unknown' }
            $label = "$($target.Host)  [$role]  ->  (no applicable STIGs - skipped)"
            [void]$clb.Items.Add($label, $false)
        }
    }
}

# Named function for switching the active tab and repainting the sidebar
# nav. Lives at script scope so closures from any context can reach it by
# name. Accepts either -TabKey (a string key registered in $global:NavButtons,
# such as 'Start' / 'About' / 'Targets') or -TabRef (an actual TabPage object).
function Invoke-StigSetActiveTab {
    param(
        [string]$TabKey,
        $TabRef
    )
    if (-not $global:NavButtons) { return }

    # Resolve -TabRef from -TabKey when both weren't passed.
    if ($TabKey) {
        $entry = $global:NavButtons[$TabKey]
        if ($entry) { $TabRef = $entry.Tab }
    }
    if (-not $TabRef) {
        if ($global:TabControl -and $global:TabControl.SelectedTab) {
            $TabRef = $global:TabControl.SelectedTab
        } else {
            $firstKey = @($global:NavButtons.Keys)[0]
            if ($firstKey) { $TabRef = $global:NavButtons[$firstKey].Tab }
        }
    }
    if (-not $TabRef) { return }

    # Find the matching nav key so we can drive Set-WptNavItemActive.
    $matchKey = $null
    foreach ($k in $global:NavButtons.Keys) {
        if ($global:NavButtons[$k].Tab -eq $TabRef) { $matchKey = $k; break }
    }
    if ($matchKey -and $global:NavHost) {
        Set-WptNavItemActive -SidebarPanel $global:NavHost -Key $matchKey
    }
    if ($global:TabControl -and $global:TabControl.SelectedTab -ne $TabRef) {
        $global:TabControl.SelectedTab = $TabRef
    }
}

$global:StigChangeLogText = @'
v1.3.3 - CKLB Import: whole-feature review fixes
  * JANET centralized-logging events now route correctly (the
    v1.3.0 wrapper called a non-existent function and was silent).
  * Set-FindingClassification gates PowerStigFixable on a Windows-
    tech allow-list — Adobe / Chrome / Office rules now classify
    Residual instead of failing at apply time.
  * Apply path clears PendingAction on host-not-in-Targets so those
    rows reappear in the residual worklist.
  * Apply Fixes button explains itself when PowerStig isn't
    installed instead of silently reducing every finding to Residual.
  * Patch bump.

v1.3.2 - CKLB Import polish: DRY apply, grid-sort fix, rule-map cache
  * Apply-tab UI handler now calls Invoke-StigPipelineForHost (the
    helper introduced in v1.3.1) instead of an inlined compile -> apply
    sequence. Both apply call sites now share one path.
  * Review tab grid columns set to SortMode=NotSortable. Same latent
    bug the v1.3.0 final reviewer caught on the CKLB Import grid:
    clicking a column header desyncs the row index from the backing
    array, leading to wrong-row mutations on Apply / skip-list edits.
  * PowerStigRuleMap.json cached to disk under STIG_Workspace, keyed
    by installed PowerStig module version. First import on a real
    PowerStig install was multi-second; subsequent imports are now
    near-instant unless the PowerStig version changed.
  * Pester: multi-STIG CKLB fixture covers the case where Evaluate-STIG
    output for a multi-tech host produces a single CKLB with several
    <stigs> blocks. Parser already handles it; coverage gap closed.
  * Patch bump.

v1.3.1 - CKLB Import: surgical Apply via PowerStig wired
  * Invoke-StigApplyFromCklb is no longer a stub — it now drives the
    real compile -> Test -> Apply pipeline, scoped via SkipRule
    inversion to only the rules the imported CKLB flagged Open.
  * New top-level helper Invoke-StigPipelineForHost factors the
    per-host compile-and-apply sequence out of the Apply-tab UI scope
    so it's reusable from the CKLB Import tab.
  * Apply Fixes button now does what its label says.
  * Patch bump.

v1.3.0 - Evaluate-STIG CKLB import + AnswerFile authoring
  * New "CKLB Import" tab consumes Evaluate-STIG .cklb output.
  * Classifies findings as PowerStig-fixable / Justifiable / Residual.
  * Drives PowerStig DSC remediation against the fixable subset, scoped
    via SkipRule inversion to only the CKLB-flagged rules.
  * Authors Evaluate-STIG AnswerFile XML (per Template_AnswerFile.xml
    schema) for findings PowerStig can't fix.
  * Persistent Justification Library at STIG_Workspace\JustificationLibrary.json
    so saved NF/NA reasons reuse across scans and hosts.
  * Emits XLSX residual worklist for findings still needing manual attention.
  * JANET centralized logging: new event types CklbImport, CklbApply,
    AnswerFileWrite, CklbResidualExport.
  * Minor bump.

v1.2.20 - Mid-scan freeze diagnostics + LCM state clear
  * Operator reported scan reached 33% (1 of 3 iterations) on a work
    host then froze. Most-likely cause: LCM stayed Busy/Pending after
    iteration 1's Test-DscConfiguration, and iteration 2 waited
    indefinitely for LCM to become Idle. (CERBERUS at home didn't
    show this — likely because no WinRM service meant the LCM
    transport differed.)
  * Added Stop-DscConfiguration -Force between iterations in Local
    mode. No-op when LCM is Idle, clears Busy/Pending when not.
  * Added per-step scan-log lines with elapsed-time stamps so the
    next freeze pinpoints itself:
      "Generating DSC config"
      "Config file: <path>"
      "MOF compiled in Xs"
      "Calling Test-DscConfiguration (this may pause if LCM is busy)"
      "Test-DscConfiguration finished in Xs — N records"
      "Clearing LCM state before next iteration"  (after iter 1+)
  * Extra DoEvents() between phases so the UI stays responsive even
    when DSC is slow.
  * Patch bump.

v1.2.18 - PS 5.1 parser fix: inline `if` expression as positional arg
  * Scan-completion log line had:
      Write-StigScanLog ($statusParts -join '; ') (if (...) {'W'} else {'D'})
    PS 5.1's parser doesn't accept `if` as an expression in a
    positional-argument context. It tries to resolve `if` as a
    cmdlet, fails with "The term 'if' is not recognized..." — the
    handler aborted before the scan loop even started running.
    (Hadn't been hit before because v1.2.16's Local-mode WinRM /
    MOF-name failures ended the scan loop before this line ran.)
  * Fixed: assign the if-expression to a $logTag local first, then
    pass $logTag positionally.
  * Patch bump.

v1.2.17 - Local DSC needs localhost.mof, not <hostname>.mof
  * v1.2.16's DCOM CimSession trick shifted the error from "winrm
    quickconfig" to "computer-specific MOF file for computer localhost
    does not exist in the current directory". The DCOM CimSession's
    ComputerName defaulted to "localhost", so DSC looked for
    localhost.mof — but we'd compiled CERBERUS.mof.
  * Test-DscConfiguration / Start-DscConfiguration use the in-process
    LCM API for localhost (no WinRM needed) IF the MOF folder contains
    a file named localhost.mof. Dropped the DCOM CimSession entirely.
    Local mode now copies the named MOF (e.g. CERBERUS.mof) to
    localhost.mof in the same folder before calling Test/Start. The
    original named MOF stays in place for downstream consumers.
  * Same fix applied to Invoke-StigApply so Apply will work too.
  * Patch bump.

v1.2.16 - Local mode uses DCOM CimSession (no WinRM dep)
  * After v1.2.15 fixed the path-doubling, the next layer surfaced:
    Test-DscConfiguration in Local mode was still routing through a
    WinRM-backed CimSession to talk to the local LCM. On AFNET
    workstations where WinRM isn't configured, every rule failed with
    "The client cannot connect to the destination... winrm
    quickconfig" — which defeats the entire promise of Local mode.
  * Invoke-StigEvaluation + Invoke-StigApply now build an explicit
    DCOM CimSession when -Mode Local and pass it via -CimSession.
    DCOM is always available on a Windows host, so Local scans /
    applies work out of the box without enabling WinRM. Remote mode
    unchanged — still WinRM / Negotiate as before.
  * Compliance Summary grid: CAT II / CAT III / Weighted %
    MinimumWidth bumped so headers stop wrapping to two lines on
    common form widths.
  * Patch bump.

v1.2.15 - Invoke-StigCompile output leak (fixes "not a valid directory")
  * Scan log surfaced the bug: every successful compile showed
    "MOF compiled: E:\...CERBERUS.mof E:\...CERBERUS.mof" — same path
    twice. `. $ConfigFile` (dot-source) inside Invoke-StigCompile
    leaked the Configuration block's MOF FileInfo to the function's
    output collection alongside `return $mof.FullName`. Function
    returned a 2-element array, Split-Path -Parent emitted two parent
    paths, [string]$MofFolder coerced to "<dir> <dir>", and Test-
    DscConfiguration complained "<dir> <dir> is not a valid directory."
    (1-rule eval error per host, Pass/Fail/CAT all 0).
    Fix: `. $ConfigFile | Out-Null` so only the explicit return is
    visible to the caller.
  * Compliance Summary MOF column widened 18/140 -> 30/260 so the
    full path is visible (or near-visible) and the column header
    isn't clipped on narrow forms. Other columns rebalanced.
  * Patch bump.

v1.2.14 - Targets-grid Select column + Scan Log panel
  * Targets grid Select column is now exactly checkbox-sized (30 px,
    AutoSizeMode=None, non-resizable). The other columns reclaim the
    space, so OS / STIG Applies / Error get more horizontal room.
    Error column FillWeight bumped 16->24 + MinimumWidth 120->220 so
    operators can read TCP probe / WinRM error text without scrolling.
  * Scan tab gained a Scan Log textbox docked Bottom inside the
    Compliance Summary card (200 px tall). Compile + evaluate progress
    and per-host eval errors append to it in real time with a
    [HH:mm:ss] [TAG] prefix (INFO, STEP, OK, WARN, ERR, DONE). The
    log is read-only TextBox so normal text selection + Ctrl+C work;
    right-click also offers Copy / Select All / Copy All / Clear.
  * Patch bump.

v1.2.13 - AddRange Z-order fix: Dock=Fill must be added first
  * v1.2.12 switched to Dock layouts but the AddRange order had
    Dock=Left/Top siblings BEFORE the Dock=Fill control. WinForms
    processes Dock in reverse Z-order (highest index docks first), so
    the LAST-added Fill control docked first and claimed the entire
    parent area, then Dock=Left grpHosts was painted ON TOP of it,
    covering the first columns (Host / Online) of the Discovered
    Targets grid. Operators saw the Add Hosts panel sitting over the
    left half of the grid.
  * Reversed every AddRange so Fill is added FIRST and docks LAST:
      Targets : (grpDiscovered, grpHosts)
      Scan    : (grpScanGrid, grpScanHosts, grpScanCtl)
      Review  : (grpRevGrid, grpRevCtl)
      Apply   : (grpApplyLog, grpApplyCtl, pnlDanger)
      Verify  : (grpVerGrid, grpVerCtl)
  * Patch bump.

v1.2.12 - Anchor -> Dock: tab layouts grow with the form
  * v1.2.11 added Anchor=Top+Left+Right+Bottom on the right-pane groups
    but they didn't grow on a maximized window. Anchor distances are
    captured at add-time, but the parent TabPages hadn't been sized
    yet (TabControl Dock=Fill sizing happens after Form.Show). Captured
    "distance from bottom" was nonsensically large and the panels never
    expanded — operators saw a one-row Discovered Targets sitting in
    the top of a mostly-empty pane on a wide screen.
  * Switched every tab to Dock-based layout (recomputed on every
    layout pass, no captured distances):
      Targets : grpHosts Left(520) / grpDiscovered Fill
      Scan    : grpScanCtl Top(150) / grpScanHosts Left(380) /
                grpScanGrid Fill
      Review  : grpRevCtl  Top(80)  / grpRevGrid Fill
      Apply   : pnlDanger  Top(36)  / grpApplyCtl Top(220) /
                grpApplyLog Fill
      Verify  : grpVerCtl  Top(90)  / grpVerGrid Fill
    TabPages get Padding=15 so docked children sit off the edges.
    Inner grids/textboxes Dock=Fill within their group with the
    group's Padding=15 as inset.
  * Patch bump.

v1.2.11 - Layout pass: maximize + grid anchors + column widths
  * Form launches Maximized; ClientSize 1600x900, MinimumSize 1366x800.
  * Grid + groupbox anchors added on Targets / Scan / Review / Apply /
    Verify tabs. The right-pane groups (Discovered Targets, Compliance
    Summary, Per-Rule Results, Apply Log, Diff Results) were Top+Left
    only — they didn't grow when the form was widened. Now all five
    Anchor=Top+Left+Right+Bottom.
  * Grid column MinimumWidth set on every column so "Online", "WinRM",
    "Last Scan", "STIG Applies", "CAT I Fail", "CAT II Fail", "Weighted
    %", "MOF", and other clipped headers stay readable on narrow
    windows. FillWeights bumped for content columns (OS, Tech, Title).
  * Grids ScrollBars=Both as safety net for narrow windows.

v1.2.10 - Wholesale $script: -> $global: + Close Tool relocated
  * Scan tab still threw closure-isolation null-refs against
    $script:StigVersionPins, $script:SkipLists, $script:EvalRoot, and
    workspace path variables. Same root cause as v1.2.7-v1.2.9: PS 5.1
    .GetNewClosure() handlers each capture their own snapshot of
    $script: scope, so writes from one closure don't propagate to reads
    from another.
  * Bulk-converted EVERY $script: reference in the file (711 sites) to
    $global: scope. The prior incremental conversions (Targets,
    JanetAllowClose, ExecutionMode, RemoteCred, ApplyInProgress) are
    subsumed here. All bootstrap state (workspace paths, runspace pool,
    audit log, prereq status, supported tech, palette colors, fonts, UI
    control refs, scan/skip/metadata caches, etc.) now lives in process
    scope so every closure agrees on the value.
  * Close Tool button moved from the bottom-left sidebar to the
    top-right content strip, immediately left of the live heartbeat
    indicator. Always visible without scrolling the sidebar. Operator
    info (User / Mode / Creds / Host) stays in the sidebar bottom.
    pnlUser height trimmed 160 -> 110 to match.
  * Patch bump.

v1.2.9 - Close Tool button visibility + X-block removal
  * Close Tool button + operator info block were invisible since the
    feature shipped. $pnlUser used Anchor=Bottom + a Location calculated
    from $pnlSidebar.ClientSize.Height at form-build time — but at that
    moment the sidebar (Dock=Left) had not been sized yet, so
    ClientSize.Height returned the WinForms default (~100). $pnlUser.Top
    resolved to -60, putting the whole block above the visible sidebar.
    Anchor=Bottom did not recover cleanly because navHost expanded into
    the same space.
  * Switched $pnlUser to Dock=Bottom (Height=160) and added a sidebar
    Resize handler that explicitly sets navHost.Height to the available
    space above $pnlUser. Operator info + Close Tool button now render
    at the bottom of the sidebar as designed.
  * X-block removed. X chrome button, Alt-F4, and right-click Close all
    close the form normally now. The only remaining guard is the
    Apply-in-progress confirmation. Get-/Set-JanetAllowClose stubs are
    kept for backward-compat but no longer veto anything.
  * $global:ApplyInProgress (set in Apply click handler, read in
    FormClosing) converted to $global: — same closure-isolation pattern
    as v1.2.7 / v1.2.8 fixes.
  * Patch bump.

v1.2.8 - ExecutionMode/RemoteCred moved to $global: scope
  * Local-mode scan against the operator's own machine reported "TCP 445
    (SMB) is open but WinRM (5985) is not" even though Local mode bypasses
    WinRM. Same closure-isolation pattern as v1.2.7: the rbLocal radio
    handler wrote $global:ExecutionMode = 'Local' into one closure's
    snapshot of script scope, but Test Reachability's click handler read
    $global:ExecutionMode as $null, fell into the REMOTE TCP-probe branch,
    and reported "WinRM not open" against the local machine.
  * $global:ExecutionMode and $global:RemoteCred (credential written by
    "Set Credentials" — same write-from-closure pattern) converted to
    $global: scope. Mode switch + credential change now propagate to every
    handler: Set Credentials, Test Reachability, scan, apply, verify.
  * Patch bump.

v1.2.7 - $global: scope migration (closure-visibility fixes)
  Two closely-related closure-visibility bugs fixed:

  1. Targets-tab "ghost host" / Test Reachability false-empty
     v1.2.6 fixed the "bare hashtable" symptom but operators still saw
     "No targets to probe" on Test Reachability right after a successful
     Add. Audit log on the same sequence said total=2, but the very next
     handler read $global:Targets.Count and got 0.
     Root cause: PS 5.1 .GetNewClosure() handlers each capture their own
     snapshot of $global: scope. A write of $global:Targets from inside
     one click handler does not propagate to a sibling click handler's
     read of $global:Targets.
     Fix: rename every $global:Targets reference (45 sites) to
     $global:Targets so all closures share one process-scope binding.

  2. X-close / Close Tool button never unblocked the form
     The X / Alt-F4 / title-bar Close were intentionally cancelled by
     FormClosing unless Get-JanetAllowClose returned $true; the Close
     Tool button was supposed to call Set-JanetAllowClose $true and then
     close. Both helpers are global functions but stored their value in
     $global:JanetAllowClose, which was sandboxed per-closure for the
     same reason as #1. Set wrote one snapshot, Get read another, and
     the form refused every close. Both helpers now use
     $global:JanetAllowClose.

  * Patch bump.

v1.2.6 - $global:Targets closure-mutation fix (partial)
  * Inside .GetNewClosure() click handlers, "$global:Targets += @{...}"
    could resolve $global:Targets as $null. PS 5.1 collapsed the
    "$null + @{...}" expression to the bare hashtable, so $global:Targets
    ended up as a single hashtable (Count=9, matching the field count)
    instead of an array of one hashtable.
    Symptoms operators reported:
      - "Added 1 host(s)" status confirmed the click ran
      - Discovered Targets grid stayed empty
      - Test Reachability said "Add hosts to the list first" even
        though the audit log showed total=9
  * Both += sites (+ Add to list and Test Reachability auto-add) now
    assemble into a local first, with explicit @() cast:
        $local = @($global:Targets)
        $local += ,@{...}
        $global:Targets = @($local)
    The cast forces array semantics no matter what the closure read of
    $global:Targets returns, and the comma-prefix on the new entry
    keeps + from unwrapping the hashtable's keys.
  * Patch bump.

v1.2.5 - Targets-tab closure-binding fix
  * Three helper scriptblocks ($SyncGrid, $RefreshPre, $LoadReviewEntry)
    were defined as plain { ... } instead of { ... }.GetNewClosure(). They
    rendered fine on first invocation (called synchronously while their
    tab-build function was still on the stack), but the first time any
    button click handler tried to call them after build returned, every
    captured local was null:
        "$gridTargets.Rows.Clear() — null-valued expression"
    Click reports from operators that triggered this:
      - "Add this machine" (Targets tab)  -> $SyncGrid via PerformClick
      - "+ Add to list"   (Targets tab)   -> $SyncGrid
      - "Remove selected" (Targets tab)   -> $SyncGrid
      - "Test Reachability" finalizer     -> $SyncGrid
      - "Re-check Prerequisites"          -> $RefreshPre
      - "Install Missing Modules" / Offline import -> $RefreshPre
      - Review-tab host picker change     -> $LoadReviewEntry
    All three definitions now end with .GetNewClosure() so the captured
    variables ($gridTargets, $txtPre, $gridRev, $lblSkipInfo, etc.) stay
    reachable after the build function unwinds. PATCH bump.

v1.2.4 - Second-pass review hardening
  * Atomic JSON writes extended to Export-ScanToCklb and per-host
    evaluation.json — STIG Viewer / eMASS imports can no longer read
    a half-written file after a kill mid-write.
  * Apply-in-progress UI guard: FormClosing refuses to close during a
    real Apply (operator confirms first); status bar reports total
    elapsed time on completion; apply handler wrapped in try/catch/
    finally so an unhandled mid-loop exception always re-enables the
    button and clears the in-progress flag.
  * Audit log per-row monotonic sequence number, header now Timestamp /
    Seq / Operator / Event / Details. New BoundaryStart row at every
    launch that records the previous file's last seq. Reviewers can
    detect deletion as a gap in the sequence between sessions.
  * Restore-point failures tracked in $restoreFailed (separate from
    $restoreCreated). End-of-apply log surfaces the failed-host list
    so operators see which hosts ran without a rollback option.
  * Invoke-StigCompile: stale-MOF removal failures THROW instead of
    swallowing. Was masking the case where a still-running DSC apply
    held a MOF lock and the next compile silently used the old MOF.
  * CKL/CKLB exporters: DNS resolution bounded to 1s via runspace.
    A 50-host export with 5 unresolvable names no longer freezes the
    UI for 25 seconds.
  * Removed dead Test-TargetReachability legacy function (still used
    ICMP + unbounded Invoke-Command). The live probe path is the
    inline TCP 5985/445 probe in the Targets-tab handler.
  * MessageBox -eq/-ne now compares [DialogResult]::Yes throughout
    instead of the stringly-typed 'Yes'.

v1.2.3 - Full STIG-grade security + reliability review
  * CRITICAL fix: New-StigDscConfigFile now allow-list-validates every
    interpolated value (ComputerName, Technology, OsVersion, OsRole,
    StigVersion, SkipRule entries) before writing the generated .ps1
    that Invoke-StigCompile dot-sources. Closes a config-injection RCE
    path where a spoofed Win32_OperatingSystem.Caption from a hostile
    target could escape single-quoted interpolation and execute arbitrary
    code in the operator's elevated session.
  * Hostname allow-list (RFC-1123 charset, 1-253 chars) on + Add to list.
  * Atomic file writes for Targets.json, SkipLists/*.json, and
    *_metadata.json. Set-StigJsonAtomic writes to a sibling .tmp.<guid>
    then [IO.File]::Replace — kill -9 mid-write no longer truncates the
    persisted fleet or the NA-justification metadata that DISA CKL
    exports require.
  * Invoke-StigBoundedRemote helper centralizes every remote PSSession
    call (LCM probe, restore-point creation, reboot detection) on a
    bounded New-PSSessionOption (180s op / 15s open / 5s cancel /
    Negotiate auth). v1.2.2 only used the bounded pattern in the
    Targets-tab probe; apply/verify still used unbounded
    Invoke-Command -ComputerName which froze the UI for ~3 minutes
    per half-broken host.
  * Apply tab: typed-APPLY token resets IMMEDIATELY after passing the
    check, not after the apply loop completes. v1.2.2 left the token
    intact when a declined LCM warning bailed out — meaning the next
    click bypassed the typed-confirmation gate.
  * Probe runspace results now check .HadErrors and .Streams.Error so
    a crashing probe script-block surfaces a real diagnostic instead
    of silent (Online=no, no error message) rows that masked bugs.
  * Reboot-detection failures during apply are now treated as
    "needs-reboot" with a (detection failed) annotation, preventing
    operators from running Verify against a not-yet-rebooted host and
    seeing false "Still Failing" results.
  * Audit log buffers entries when the workspace share is unreachable
    and replays them on the next successful write. Failure counter
    exposed via $global:AuditWriteFailedCount.
  * Tri-state scan-complete status: distinguishes OK / eval-error /
    compile-fail counts instead of always saying "Scan complete".
  * v1.2.2 ordering bug fixed: $global:LastInstallResult is set before
    the Add_Shown closure that references it. StrictMode 3 was
    null-deref-throwing on first form render.
  * Stale workflow strings ("Paste hosts, Test Reachability...") on the
    Start tab and Help tab updated to reflect v1.2.2's + Add to list
    workflow.

v1.2.2 - Targets tab usability overhaul
  * + Add to list button: type/paste hosts and add them to the grid
    immediately, without first running a reachability probe. Previous
    workflow forced "paste -> Test Reachability or hosts vanish" — now
    Add and Probe are decoupled, in either order.
  * Targets persist across launches in Workspace\Targets.json. Open the
    tool tomorrow, your fleet is still there.
  * Remove selected button: tick rows, click remove. Previously the only
    way to clear a row was to run Test Reachability with a different
    paste-list (which wiped everything).
  * Test Reachability now uses a TCP 5985 / 445 probe (1.5s each) instead
    of ICMP. AFNET workstation firewalls block ICMP almost universally,
    so Test-Connection was returning Online=no for hosts that were
    actually reachable on WinRM. Pattern ported from the J.A.N.E.T.
    Workstation Patching Tool.
  * Remote-mode probe now opens a bounded New-PSSession (180s op /
    15s open / Negotiate auth) instead of unbounded Invoke-Command —
    fixes the "session hangs forever on a half-broken host" failure
    mode that bit the older flow.
  * Scan-tab host picker auto-refreshes whenever the targets list
    changes (add / remove / probe), not just on tab switch.
  * Empty-state messages on both Targets and Scan tabs spell out the
    new workflow so first-time operators see the call-to-action.

v1.2.1 - JANET centralized logging
  * Per-host ApplySTIG rows (Success / Failure / Skipped, with
    pre-apply non-compliant count as ItemCount) go to the AFNET
    log share at \\dm-tn-01\sh-usafe-automation$\JANET\Logs\STIG\.
  * JANET closing-notes dialog captures ASI + notes on form close.

v1.1.0 - Self-contained single-file + shared UI kit + Start tab
  * Single-file distribution. The UI kit (Theme + Controls + Dialog.Info)
    is now inlined verbatim into this script so STIG_Tool.ps1 ships as one
    self-contained .ps1 in the same shape as WorkstationPatchingTool_6.1.10.
    No more runtime dependency on Tools\UI\*.ps1 -- copy this file anywhere
    and it runs. Source of truth for the kit still lives at Tools\UI\; if
    those files are edited, re-inline the bodies below the "## --- From
    Tools\UI\..." banners in this file to keep the palette and factories
    in sync across the suite.
  * Palette, fonts, and control factories match WPT exactly (purple
    #8C64DC accent, gold #DAB452, olive #5CC678 success). Renders pixel-
    for-pixel identical to WPT 6.1.10.
  * Left sidebar nav replaces the horizontal toolbar - 01 Start, 02 About,
    03 Targets, 04 Scan, 05 Review, 06 Apply, 07 Verify, 08 Reports, 09 Help.
  * Form sized to 1360x800 (min 1200x720) to match WPT.
  * DPI awareness + dark immersive title bar via DWM.
  * New Start tab with session summary, big "Go to Targets" CTA, and
    Change Log / How to Use pop-out buttons.
  * Status bar redesigned - scanline overlay, heartbeat pulse, session +
    mode + log trail.
  * Filename renamed to STIG_Tool_1.1.0.ps1 to match the suite's versioned-
    filename convention (e.g. WorkstationPatchingTool_6.1.10.ps1).

v1.0.0 - Initial release
  * PowerStig 4.x integration for Windows 10/11, Server 2019/2022,
    Windows Firewall, Windows Defender.
  * Local and Remote (WinRM) execution modes with credential management.
  * Target discovery with reachability probe and role detection.
  * MOF compile -> Test-DscConfiguration evaluation -> per-rule grid review.
  * Checklist Review tab - per-rule skip-list, NA justifications,
    severity overrides, finding details and comments.
  * Apply tab with restore-point checkpoint and typed APPLY confirmation.
  * Verify tab diffs pre/post scans: Resolved / Still Failing / Regression.
  * Reports tab exports XLSX, CKL (STIG Viewer), CKLB (STIG Viewer 3),
    and POA&M workbook (eMASS).
  * Audit log at workspace\Logs\audit.log captures every operation.
  * Embedded in the J.A.N.E.T. suite launcher with shared workspace.
'@

$global:StigHowToUseText = @'
QUICK START

  1. Start tab (you are here after launch)
     * Glance at the session summary - operator, mode, credentials, prereqs.
     * First run? Click About to set your operator name and install
       PowerStig + ImportExcel if missing.
     * Click "Go to Targets" when the prereq line reads green.

  2. About tab
     * Set OPERATOR name (used in audit log and CKL exports).
     * Pick MODE:
         Local  - scan THIS machine (no creds needed)
         Remote - scan other machines via WinRM (need a-account creds)
     * Click "Set Credentials" if Remote.
     * Check PREREQUISITES: PowerStig + ImportExcel + DSC + WinRM.
     * Use "Install Missing Modules" on an online box, or
       "Import Modules (Offline)..." on an air-gapped AFNET host.

  3. Targets tab
     * Paste hostnames (one per line, comma, or space separated).
     * Click "Test Reachability" to probe each host - ping + WinRM + OS/role.
     * Tick hosts to include in the scan.

  4. Scan (Evaluate) tab
     * Pick STIG versions per technology (blank = latest PowerStig).
     * Click "Start Scan". Each host+tech combo runs Test-DscConfiguration.
     * Grid shows compliance %, CAT I/II/III breakdown, per-host timing.
     * MOF paths are recorded so the Apply tab can recompile with skip-lists.

  5. Checklist Review tab
     * Pick a scan entry from the dropdown.
     * Edit per-rule metadata: NA Justification, Finding Details, Comments,
       Severity Override / Justification.
     * Untick rules you want EXCLUDED from Apply (skip-list).
     * Save/Load skip-list + metadata to disk for reuse.

  6. Apply (Remediate) tab
     * Review danger banner. DRY RUN is ON by default - untick to apply.
     * Optional: tick Restore Point to create one before applying.
     * Type APPLY in the confirmation box.
     * Click Apply. DSC re-compiles with the current skip-list and runs
       Start-DscConfiguration per host.
     * If reboot required, you get a prompt to schedule one.

  7. Verify tab
     * Click "Rescan and Diff". Runs Test-DscConfiguration again per host
       and diffs the result against the pre-Apply scan.
     * Outcomes: Resolved (green), Still Failing (red), Regression (orange).

  8. Reports tab
     * Export XLSX (Summary + PerRule + Skipped + AuditTrail sheets).
     * Per-host CKL for STIG Viewer 2.x legacy imports.
     * Per-host CKLB for STIG Viewer 3 / eMASS.
     * POA&M workbook with eMASS import columns.

  9. Help tab
     * Glossary, workflow diagram, and caveats.


WORKSPACE LAYOUT

  J.A.N.E.T\STIG_Workspace\
    Configs\       DSC Configuration .ps1 files (per host/tech)
    MOF\           Compiled MOFs (per host)
    Evaluations\   Saved Test-DscConfiguration results (JSON)
    Checklists\    Exported CKL / CKLB artifacts
    Reports\       Exported XLSX / POA&M
    SkipLists\     Saved per-technology skip-lists and rule metadata
    Logs\audit.log Master audit trail (tab-delimited)


TROUBLESHOOTING

  * "PowerStig MISSING" on the About tab: click "Install Missing Modules"
    (online) or "Import Modules (Offline)..." (air-gapped).
  * "Test-DscConfiguration returned no result": LCM is in a transient
    state (Pending / Busy / Rebooting). Wait or reboot and retry.
  * STIG Viewer refuses the CKL: check the OS version match. Server 2019
    uses Windows_Server_2019_STIG; 2022 uses Windows_Server_2022_STIG.
  * eMASS rejects the CKLB: the tool now emits a flat ccis array. If
    an older CKLB is still around, re-export it.
  * LCM RefreshMode=Pull warning: a pull server will revert your manual
    apply. Coordinate with the domain admin before continuing.


CLOSING THE TOOL

  * Native window X close. CleanUp flushes the runspace pool, disposes
    timers, releases the logo handle, and writes a final audit event.
'@

# Repaint the Start tab's session-summary card. Named function (not a
# $global: scriptblock) so event-handler closures can reach it reliably
# across modal/runspace context transitions — see CLAUDE.md's "recurring
# bug pattern" note. Reads live state from $global:Operator, $global:ExecutionMode,
# $global:RemoteCred, and $global:PrereqStatus.
function Update-StigStartCard {
    $theme = $global:WPT.UI.Theme
    if (-not $theme) { return }
    $s = $global:lblOpStartRef;   if ($s) { $s.Text = [string]$global:Operator }
    $m = $global:lblModeStartRef; if ($m) {
        $m.Text      = if ($global:ExecutionMode -eq 'Remote') { 'Remote' } else { 'Local' }
        $m.ForeColor = if ($global:ExecutionMode -eq 'Remote') { $theme.Accent1 } else { $theme.Success }
    }
    $c = $global:lblCredStartRef; if ($c) {
        if ($global:RemoteCred) {
            $c.Text      = [string]$global:RemoteCred.UserName
            $c.ForeColor = $theme.Success
        } elseif ($global:ExecutionMode -eq 'Remote') {
            $c.Text      = 'REQUIRED - not set'
            $c.ForeColor = $theme.Danger
        } else {
            $c.Text      = 'not set (only required for Remote)'
            $c.ForeColor = $theme.TextMuted
        }
    }
    $p = $global:lblPreStartRef;  if ($p -and $global:PrereqStatus) {
        $missing = @()
        if (-not $global:PrereqStatus.PowerStigInstalled)   { $missing += 'PowerStig' }
        if (-not $global:PrereqStatus.ImportExcelInstalled) { $missing += 'ImportExcel' }
        if ($missing.Count -eq 0) {
            $p.Text      = 'all modules installed'
            $p.ForeColor = $theme.Success
        } else {
            $p.Text      = "missing: $($missing -join ', ') - install on About tab"
            $p.ForeColor = $theme.Warning
        }
    }
}

function Show-StigChangeLogDialog {
    Show-WptInfoDialog -Title 'J.A.N.E.T. STIG Tool - Change Log' -BodyText $global:StigChangeLogText
}

function Show-StigHowToUseDialog {
    Show-WptInfoDialog -Title 'J.A.N.E.T. STIG Tool - How to Use' -BodyText $global:StigHowToUseText
}

function Start-StigTool {
    Initialize-Workspace
    Initialize-RunspacePool
    # Restore persisted targets (added in v1.2.2) so operators don't have to
    # re-paste the same fleet every launch. Silent if no Targets.json yet.
    try { [void](Load-StigTargets) } catch {}
    # First audit row of the session is a BoundaryStart that records the
    # prior file's last seq number. Combined with per-row seq, this gives
    # a tamper-evident audit trail without HMAC infrastructure.
    $priorTail = if ($global:AuditPriorTail) { $global:AuditPriorTail } else { 'new-file' }
    Write-Audit -Event 'BoundaryStart' -Details "priorSeq=$priorTail version=$global:ToolVersion"
    Write-Audit -Event 'ToolStart' -Details "version=$global:ToolVersion root=$global:ScriptRoot"

    # MANDATORY module install — runs BEFORE the GUI comes up so that the
    # Prereq Status panel reflects the post-install state. On an online box
    # this adds a few seconds to startup the first time and is instant after.
    # On an offline box (AFNET air-gapped) it fails gracefully and the tool
    # still launches — the About tab will show PowerStig MISSING with the
    # manual install command so the operator knows what to do.
    Write-Host ''
    Write-Host '=== J.A.N.E.T. STIG Tool: Installing required modules ==='
    $installResult = Install-StigToolModules
    if (-not $installResult.Success) {
        Write-Host ''
        Write-Host 'Module install had errors (see above). The tool will still launch.'
        Write-Host 'On an air-gapped machine, copy PowerStig and ImportExcel to:'
        Write-Host "  $($env:ProgramFiles)\WindowsPowerShell\Modules\"
        Write-Host '(one subfolder per module, containing the module files)'
        Write-Host ''
    }
    Write-Host '=== Module check complete. Launching GUI... ==='
    Write-Host ''

    # Now re-check prereqs so the GUI reflects post-install state
    Test-Prerequisites | Out-Null

    # Defensive: BuildAppForm is large and any bare expression inside it
    # (e.g. a stray .Focus() or .Add() call without [void]) would leak
    # extra values into the output stream. Pick the Form out of whatever
    # came back so we never hand ShowDialog a Boolean or an array.
    $rawOutput = @(BuildAppForm)
    $form = $rawOutput | Where-Object { $_ -is [System.Windows.Forms.Form] } | Select-Object -First 1
    if (-not $form) {
        $leaks = ($rawOutput | ForEach-Object { "$($_.GetType().FullName)" }) -join ', '
        throw "BuildAppForm did not return a Form object. Pipeline contained: [$leaks]"
    }
    # Set BEFORE Add_Shown wires its closure — the closure derefs
    # $global:LastInstallResult when the form first renders, which is
    # before this function continues past ShowDialog. v1.2.2 had this
    # assignment after Add_Shown, which threw a null-deref under
    # StrictMode 3 the first time the form was shown.
    $global:LastInstallResult = $installResult
    # If install had errors, pop a warning dialog after the GUI renders so
    # the operator sees it (console text is often hidden when run via the
    # Windows shell "Run with PowerShell" context).
    if ($installResult.Errors.Count -gt 0) {
        $form.Add_Shown({
            [System.Windows.Forms.MessageBox]::Show(
                "Module install reported $($global:LastInstallResult.Errors.Count) error(s):`n`n$($global:LastInstallResult.Errors -join ""`n"")`n`nThe tool will run in degraded mode. Use the 'Install Missing Modules' button on the About tab to retry after fixing network/permissions.",
                'Module install incomplete',
                'OK',
                'Warning'
            ) | Out-Null
        }.GetNewClosure())
    }

    ## JANET centralized session (added in v1.2.1). Metric tool: per-host ApplySTIG
    ## rows emitted from the apply loop; rollup row written on form close with -ShowDialog.
    try { Start-JanetSession -Tool 'STIG' -Version $JanetSTIGVersion } catch {}

    [void]$form.ShowDialog()

    try { Stop-JanetSession -ShowDialog } catch {}
}

if (-not $env:STIG_TOOL_TEST_MODE) {
    Start-StigTool
}
#endregion