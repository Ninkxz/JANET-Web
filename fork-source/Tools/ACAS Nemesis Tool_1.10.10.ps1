###############################################################################
###  J.A.N.E.T. ACAS Nemesis Tool
###  Joint Administration and Network Execution Toolkit
###############################################################################
###
###  Author:   Braxton Thompson | 48CS/SCOO
###  Date:     May 2026
###  Version:  1.10.10
###
###  Purpose:  Import ACAS / Nessus CSV exports, surface vulnerabilities per
###            host, and drive targeted remediation via per-vulnerability
###            Updater cards (Microsoft 365, Chrome, Edge, Defender) + a
###            MECM (CIM) / UsoClient KB Installer. Every run is logged to
###            the AFNET shared log share as CSV alongside a per-operator
###            session transcript. Closing the tool prompts for operator
###            notes, appended to the daily Runs CSV.
###
###  Runtime:  PowerShell 5.1 ONLY. No PS 7+ syntax.
###  Logs:     \\dm-tn-01\sh-usafe-automation$\JANET\Logs\ACAS_Nemesis
###            (unified under the JANET share as of v1.3.1)
###
###############################################################################
###
###  CHANGELOG
###  ---------
###  v1.10.10 - 2026-06-06 - Code-review fix: Start-NemRebootRun treated
###            shutdown.exe exit 1190 (ERROR_SHUTDOWN_IS_SCHEDULED) as a
###            failure, so a host that already had a reboot pending was logged
###            red and counted as Failed even though it will reboot. 1190 is now
###            accepted as success (matches RemoteRestartScheduler and the
###            suite-wide contract). No second reboot path exists in this tool.
###
###  v1.10.9 - 2026-06-06 - Two reliability fixes.
###            (1) The JRE version-detection helper assigned to $home, a
###                read-only PowerShell automatic variable, so it threw on
###                every run. Renamed the local to $javaHome.
###            (2) Cancel during a Reboot or Reboot-Verify run left rebTimer /
###                rebVerifyTimer (and kbTimer) ticking after $s.Jobs was
###                wiped, null-dereferencing _counters on the next tick. The
###                Cancel handler and FormClosing now tear down every drain
###                timer, not just updTimer/preflightTimer.
###
###  v1.10.8 - 2026-05-28 - Three hardening / unsupported-software
###          remediations ported from WPT 6.5.20, onboarded as
###          Script-type AppUpdateProfiles + keyword rules in
###          Get-NemProfileMatchTable. Sourced from the 28 May
###          fleet scan.
###            (1) 'Edge STIG - Disable Search Engine Import' --
###                writes HKLM:\SOFTWARE\Policies\Microsoft\Edge
###                \ImportSearchEngine = 0 (DWord). DISA Edge STIG
###                EDGE-00-000022 / SV-235739r960963_rule, the
###                Tenable "noCCE" finding (~1489 hosts). No reboot.
###                Keyword rule uses 'EDGE-00-000022' + 'Importing
###                of search engine settings' and is placed ABOVE
###                the generic 'Edge' rule so first-match-wins
###                routes the STIG finding here instead of to the
###                Edge-Update browser profile.
###            (2) 'Windows Unquoted Service Path - Remediate' --
###                quotes service ImagePath values with spaces in
###                the exe and no surrounding quotes; backs up the
###                original to HKLM:\SOFTWARE\JANET\Nemesis\Unquoted
###                SvcPath. Tenable plugin 63155 (~322 hosts).
###            (3) 'MSXML 4.0 - Uninstall' -- MsiExec /x of any
###                "MSXML 4.0*" Uninstall-registry product. Tenable
###                plugin 62758 (~26 hosts).
###          All three Scripts are self-contained (built-in cmdlets
###          + literals only) so they survive the Start-NemVulnRun
###          .ToString() rehydration. Java + .NET Core EoL were
###          deferred (Java SSO-gated; .NET pulled from WPT for now).
###
###  v1.10.7 - 2026-05-27 - Log4j updater rewritten to RECURSE under
###          each target lib root and handle Backup_<ts>\ subdirs
###          the previous versions left accumulating. Same fix that
###          shipped in WPT 6.5.18, ported with Nemesis's existing
###          remote-staging shape preserved:
###            - `$sourceShare = '...'` stays as the first single-
###              quoted assignment so Resolve-NemProfileScriptText's
###              regex substitution (and the per-target stage-dir
###              substitution in the bulk pool scriptblock) still
###              swap it correctly at dispatch.
###            - $newApi / $newCore literals unchanged so the
###              controller-side stage push at line ~5820 still
###              matches what the remote Script reads.
###            - $targets shape unchanged.
###          New per-jar dispositions (computed from filename + path):
###            * filename == log4j-(api|core)-2.25.4.jar
###                -> SKIP (idempotent re-runs)
###            * other version, path contains \Backup_*\
###                -> DELETE in place (no back-of-a-backup)
###            * other version, top-level live
###                -> BACKUP + REPLACE (stop service, copy to fresh
###                   Backup_<ts>\, drop 2.25.4 jars)
###          Service bounce only fires when at least one live jar
###          needs replacing -- pure archive cleanups don't touch
###          the bundled service.
###          Verify scriptblock also recurses now and surfaces full
###          paths in the STILL-VULNERABLE detail string, so the
###          Updater card's post-run "bumped: X -> Y" line correctly
###          reflects backup-folder cleanup that 1.10.6 and earlier
###          hid behind a non-recursive Get-ChildItem.
###          Driven by a real Tenable scan on msekl-9pl6cf3 that
###          flagged 2.17.2 / 2.25.3 jars inside Backup_20260506_*
###          dirs left over from prior runs (plugins 306549 / 306550).
###
###  v1.10.6 - 2026-05-21 - CLOSE-HANG FIX (1.10.5 regression). The
###          off-thread log writer fixed the freeze but introduced a
###          new one: "Close Tool ... still not closing the program."
###
###          Mechanism (the writer-runspace teardown in 1.10.5's
###          Stop-NemLogWriter, called from FormClosing):
###            1. A standalone Runspace runs its pipeline on a
###               dedicated FOREGROUND thread (verified on PS 5.1:
###               IsBackground = $false). A foreground thread keeps
###               powershell.exe — and the launcher waiting on it —
###               alive after the form window closes.
###            2. 1.10.5 disposed that runspace (PowerShell.Dispose /
###               Runspace.Close/Dispose) from inside FormClosing. If
###               the writer thread is wedged in an uninterruptible
###               native call — exactly what a hung AFNET share write
###               is — PowerShell.Stop() cannot abort it and the
###               Dispose/Close blocks the close. (A healthy share
###               never wedges, which is why an isolated repro on
###               local files does NOT hang for either version — the
###               failure needs a genuinely hung share, the operator's
###               actual environment all through this episode.)
###
###          Fix (both addressed):
###            * The writer scriptblock sets
###              [Threading.Thread]::CurrentThread.IsBackground = $true
###              as its first statement. A background thread is
###              abandoned the instant the UI thread exits, so the
###              process ALWAYS terminates.
###            * ThreadOptions=ReuseThread dropped — default options,
###              one long-lived pipeline, no parked reuse-thread.
###            * Stop-NemLogWriter no longer disposes the runspace /
###              PowerShell object. It only sets the stop flag and
###              waits (bounded, 5s) for the queue to flush, then
###              returns — nothing in it can block FormClosing. The OS
###              reclaims the background thread + runspace on process
###              exit; Stop-NemLogWriter only ever runs during
###              shutdown, so skipping dispose costs nothing. Isolated
###              WinForms close repro verified clean (exits ~2s).
###
###  v1.10.5 - 2026-05-21 - UI FREEZE FIX (round 4 — off-thread logging).
###          1.10.4's per-tick drain cap paced a SLOW share, but the
###          operator then hit a HUNG one: "runs one then everything
###          just freezes." One completion logged, then a single
###          synchronous share write blocked the UI thread and never
###          returned. A cap can't help that — even one blocking write
###          on the UI thread is one too many. Add-JanetCsvRow alone
###          could spend ~15s in Start-Sleep retries on the caller.
###
###          Root fix: ALL log/CSV file I/O moved off the UI thread.
###          A single dedicated background runspace (Initialize-NemLogWriter)
###          owns every share write. The UI thread calls Add-NemLogWrite,
###          which only enqueues a fully-resolved write request to a
###          ConcurrentQueue and returns instantly — zero I/O on the UI
###          thread. If the share hangs, the writer thread blocks and the
###          queue grows; the window stays fully responsive. Worst case
###          on a dead share is delayed/dropped log lines, never a frozen
###          tool.
###
###          Routed through the background writer:
###            * Write-NemAudit          — per-session .log
###            * Write-NemTouchedHostCsv — operator TouchedHosts CSV
###            * Add-JanetCsvRow         — JANET detail + usage CSVs
###              (Write-JanetAction / Write-JanetRollupSnapshot)
###            * Write-NemRunCsvLine     — daily ACAS-Nemesis-Runs CSV
###          The writer creates directories, writes the CSV header on
###          first touch, applies a bounded retry, and falls back to the
###          local workspace copy — all on its own thread.
###
###          Stop-NemLogWriter drains the queue (bounded 8s wait) and
###          disposes the runspace from the form-close path, so a clean
###          exit still flushes every queued line to the share. A dead
###          share cannot hang the close — the wait is bounded.
###
###          Tradeoffs (deliberate, low-impact):
###            * Inline CSV schema-rotation is dropped from the hot path
###              (Add-JanetCsvHeader / the Runs-CSV .pre-schema-change
###              archive). Both schemas have been stable for many
###              versions and live share files already carry the current
###              header; the writer still writes a header to any
###              brand-new file.
###            * On a hard process kill, lines still in the queue are
###              lost. Normal Close Tool / X exits flush via
###              Stop-NemLogWriter.
###
###  v1.10.4 - 2026-05-21 - UI FREEZE FIX (round 3 — the real one).
###          With 1.10.3's host-visible errors in place, the operator
###          caught the actual freeze: window title "(Not Responding)"
###          during RUN ALL on the first card (Apache Log4j, 15 hosts),
###          PS console showing VulnRun.Target ... FAIL: unreachable
###          (TCP 5985/445).
###
###          Root cause — the drain timer, NOT card rendering (1.10.2
###          already fixed that). Each drain Tick processed EVERY
###          completed job in one pass. Per completion it does ~3
###          synchronous writes to the AFNET log share
###          (\\dm-tn-01\...\JANET\Logs): Write-NemAudit appends the
###          .log line AND fans out a TouchedHosts CSV row, then
###          Write-JanetAction appends the centralized-logging CSV row.
###          The runspace pool is 8 wide, so a 15-host card finishes in
###          ~2 waves of 8 + 7 completions. Unreachable hosts all time
###          out together at the ~6s TCP probe, so a whole wave lands in
###          ONE Tick — 8 completions x 3 share writes = 24 back-to-back
###          SMB round-trips on the UI thread. On a sluggish AFNET share
###          that is well past the ~5s Windows "Not Responding"
###          threshold. The 1.10.3 PS-console echo confirmed it: exactly
###          one [ERR] line printed, then the thread buried itself in
###          the rest of the wave.
###
###          Fix: bound the drain Tick. New $script:NemDrainTickCap
###          (default 3) + Get-NemDrainCap accessor. All SIX drain-timer
###          Tick handlers (Start-NemVulnRun, Start-NemRebootRun,
###          Start-NemRebootVerify, Start-NemServicesPreflight,
###          Start-NemBulkRunAll, Start-NemKbRun) now process at most
###          $cap completed jobs per tick and `break` once the cap is
###          hit. The drain timer fires every 250ms, so the message
###          pump runs between ticks and the window stays responsive —
###          a 15-host wave drains over ~5 ticks instead of freezing
###          solid. No logging semantics change: every job is still
###          drained, audited, and JANET-logged; the work is just paced
###          across ticks. The post-loop outstanding-count check keeps
###          the timer alive until $s.Jobs is genuinely empty, so no
###          completion is ever dropped.
###
###          NOTE (next step if still hitchy): the writes are still
###          synchronous, so a genuinely HUNG share (vs. merely slow)
###          could still stall one tick. If that shows up, the proper
###          fix is moving Write-NemAudit / Write-JanetAction onto a
###          background writer runspace + queue. Deferred — the cap is
###          the low-risk fix and the audit trail is compliance-
###          critical, so the logging core was left untouched here.
###
###  v1.10.3 - 2026-05-19 - VISIBLE ERRORS. The launching PowerShell
###          window had been showing as completely blank, even when
###          something in the tool was clearly going wrong, because
###          every catch-handler in the script funnels errors to
###          Write-NemAudit (which only writes to the per-session
###          transcript file) — nothing was ever printed to the host.
###          Behaviour-only change, no UI or run-flow rewiring.
###            * Write-NemAudit now echoes Failed entries to the host
###              in red via Write-Host. Every existing catch-handler
###              already calls
###                Write-NemAudit -Result 'Failed' -Detail $_.Exception.Message
###              so this single addition makes every silently-swallowed
###              error visible in real time.
###            * Script-level trap{} after the param() block catches
###              anything that escapes the per-handler catches (eg.
###              an Add_Click / Add_Tick scriptblock that lacks its
###              own try/catch) and prints it to the host. The trap
###              uses `continue` so a single bad event handler can't
###              tear down the WinForms UI thread.
###            * Host writes are wrapped — running under -NonInteractive
###              or with a redirected host won't break audit logging.
###
###  v1.10.2 - 2026-05-19 - UI FREEZE FIX (round 2). 1.10.1 deferred the
###          Update-NemVulnCards / Update-NemNonUpdatableCards call by
###          one Timer tick, which fixed the tab-paint perception (the
###          tab chrome appeared immediately) but did NOT break up the
###          card construction itself — once the deferred tick fired,
###          the function ran to completion synchronously, locking the
###          UI thread for the full build duration. On a 9k-finding
###          import that's hundreds of card Panels (each ~7 child
###          controls + event hooks) which can run 5-30s on the UI
###          thread — long enough for Windows to draw its "not
###          responding" white-form-with-blue-spinner overlay on top
###          of the tool. Operator report after 1.10.1: still freezing.
###
###          Fix: chunked card rendering. Both Update-NemVulnCards and
###          Update-NemNonUpdatableCards now build cards N per
###          single-shot Timer tick (default batch = 10) so the
###          WinForms message pump runs between batches. Cards visibly
###          fill in from the top down instead of the host locking up
###          while everything is built at once. The Updater tab queue
###          is a flat list of card entries; the Not Updatable queue
###          interleaves section headers ('UNPATCHABLE' /
###          'UNCLASSIFIED') with their cards so the visual ordering
###          is preserved.
###
###          Builder state ({Queue, All, BatchSz}) and the Timer live
###          on $state.UI.Controls so Refresh / Selection-change /
###          another VisibleChanged tick can dispose the prior in-flight
###          builder before queueing a fresh pass — no risk of cards
###          from a stale pass appearing alongside the new ones.
###          Summary tile refresh (Update-NemUpdaterSummary /
###          Update-NemNotUpdatableSummary) is fired on the FINAL tick
###          so totals reflect the fully-built card list.
###
###  v1.10.1 - 2026-05-19 - UI FREEZE FIX. The 1.10.0 UI refresh introduced
###          three new synchronous-on-UI-thread costs that combined into
###          a white-screen + spinner stall after large ACAS imports
###          (operator reported on a 9,514-finding CSV). Behaviour-neutral
###          patch — no card layout, schema, or run-flow changes.
###          1) Update-NemUpdaterSummary used to call Get-NemVulnCardEntries
###             again after Update-NemVulnCards already had. With 9k+
###             findings the classify/group/sort pass ran twice per
###             refresh. Now Update-NemVulnCards computes the entry list
###             once and forwards it via -Entries; Update-NemUpdaterSummary
###             takes an optional -Entries param and only re-computes when
###             called standalone. Same pattern for Update-NemNonUpdatableCards
###             / Update-NemNotUpdatableSummary.
###          2) New-NemVulnCard / New-NemRebootCard / New-NemNonUpdatableCard
###             each created 2-3 fresh System.Windows.Forms.ToolTip
###             objects per card. Each tooltip allocates a native Win32
###             HWND — hundreds of cards meant hundreds of HWNDs in one
###             synchronous burst. The cards-host panel now owns a single
###             shared ToolTip (Get-NemSharedToolTip) and cards call
###             SetToolTip on it. Same tooltip behaviour, one HWND total.
###          3) The Updater + Not Updatable VisibleChanged handlers ran
###             Update-NemVulnCards (+ for Updater, the auto-popout Form
###             construction) inline before the tab had a chance to paint.
###             Now the rebuild + auto-popout are queued via a 1-tick
###             System.Windows.Forms.Timer so the WinForms message pump
###             shows the tab first, then builds cards. The visible
###             artefact ("white form + spinning blue circle") goes away —
###             the tab may still take a moment to fill on huge imports,
###             but the chrome paints immediately and the host stays
###             responsive.
###
###  v1.10.0 - 2026-05-12 - UI REFRESH. Cosmetic-only release aligning
###          the tool's chrome with the Reports Tool aesthetic so the
###          whole suite reads as one application. NO changes to update
###          behavior, session logging, audit/CSV writers, nav wiring,
###          or any tab handler — visual only.
###
###          DASHBOARD (Updater + Not Updatable + Targets):
###            * NEW global:New-NemDashTile primitive — Reports / Weekly
###              Export-style hero-number tile (eyebrow + 22pt mono-bold
###              number + caption + 3px coloured top accent). Returns a
###              hashtable so callers can update labels without rebuilding.
###            * Updater: 6-tile strip (Total / Patchable / Not Patchable
###              / Critical / High / Med+Low) — refreshes on every
###              Update-NemVulnCards call via Update-NemUpdaterSummary.
###            * Not Updatable: 4-tile strip (Total Not Patchable /
###              Critical / High / Hosts Affected) refreshed via
###              Update-NemNotUpdatableSummary.
###            * Targets tab rebuilt as a Data Import hub with a 4-tile
###              strip (Targets Loaded / Findings / Unique Hosts /
###              Last Import). State tracks LastImportFile + Time + Count.
###
###          CARDS (compact "block" rebuild):
###            * Per-vuln cards rebuilt as discrete blocks for easier
###              scanning while scrolling, then compacted in pass 4:
###                - 4px TOP accent strip in severity colour (replaces
###                  the 6px left bar; matches the dashboard tile look).
###                - Two content rows: title row (Title + [SEVERITY] +
###                  [ROLLUP/EXPERIMENTAL] badge) + profile row
###                  (Profile dropdown OR label + host count on the
###                  right). Right column: Run + Verify stacked.
###                - Profile dropdown preserved as the "how it's updated"
###                  picker (combo for multi-profile vulns, label for
###                  single, "no profile mapped" hint for empty).
###                - CVE list + affected-host preview moved to TOOLTIPS
###                  on the title + host-count labels — same info, no
###                  chrome cost.
###                - Card heights: Patchable 96, Reboot 110, Unpatchable
###                  116, NotUpdatable 92. Cards-host BG = $theme.Background
###                  so each Surface-coloured card reads as a raised block.
###              Affects New-NemVulnCard, New-NemRebootCard, and
###              New-NemNonUpdatableCard.
###
###          UPDATER LOG (auto-popout):
###            * Pop logic extracted into the new global helper
###              Show-NemUpdaterLogPopOut.
###            * On first Updater-tab VisibleChanged, the log auto-pops
###              into its own floating window (one-shot per launch).
###              Embedded log section removed from the tab layout — the
###              bottom 260px now belongs to cards.
###            * Pop-out window anchors at the bottom-right of the
###              working area so it doesn't cover the main window.
###            * The RTB lives in a hidden $rtbWrap orphan Panel between
###              pops — every existing $rtb.AppendText() call site keeps
###              working unchanged.
###
###          CHROME (Show-NemMainForm):
###            * Full-width 64px top bar with gold "J.A.N.E.T. ACAS
###              Nemesis Tool" wordmark + subtitle + 2px gold accent
###              stripe. Close Tool button moved into the top bar's
###              top-right.
###            * Sidebar slimmed 252 -> 210px. Brand block removed (now
###              duplicated by the top bar); nav items start at the top.
###            * Action button palette normalized on Updater + Not
###              Updatable: ghost (PanelLight + Accent1 fg) for Refresh
###              / Pre-Flight / Pop Out, gold (Accent2) for Run All +
###              Bulk Run, Danger for Cancel only.
###            * Removed decorative chrome that didn't carry signal:
###              scanline overlay on the status bar, 16x16 grid-paper
###              background on the tab host, and the four pulse
###              indicators (heartbeatStatus / heartbeatBrand /
###              heartbeatContent / sidebarPulse). sidebarPulse key
###              preserved as a static coloured dot.
###
###  v1.9.5 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
###          *_usage*.csv so schema-rotation sister files (created when
###          the legacy file is persistently locked) are drained on next
###          launch instead of stranded.
###
###  v1.9.4 - 2026-05-08 - JANET centralized-logging schema cleanup
###          (single SessionEnd rollup row; Snapshot rows retired)
###          and the WPT-themed Closing Notes prompt rolled across
###          the suite.
###
###  v1.9.3 - 2026-05-07 - Bug-hunt sweep (post-review).
###          Code-reviewer found two surviving instances of the
###          same closure-scope bug class fixed in 1.9.2 (direct
###          ``$script:`` access from inside `.GetNewClosure()` under
###          PS 5.1 + StrictMode 3 silently resolves to ``$null``)
###          plus five smaller items. All addressed in this round.
###
###          BLOCKERS (silent-fail bugs):
###            * SessionEnd terminator (FormClosing closure, line
###              ~11680) — was reading ``$script:Nemesis.Config.LogFile/.LogDir``
###              from inside the FormClosing closure body. Wrapped
###              in try/catch{} so the symptom was symptom-free:
###              terminator silently skipped, lead reading the
###              share later sees a session log with no closing
###              line. Fixed by routing through the closure-local
###              ``$sDlg`` (already resolved by ``Get-NemState`` at
###              the top of the closure).
###            * btnStart "logs unavailable" MessageBox — was
###              interpolating ``$script:NemLogShare`` from inside
###              the click closure, getting an empty string on
###              closure-resolution miss. Fixed by adding
###              ``function global:Get-NemLogShare`` (matches the
###              existing ``Get-NemAllowClose`` pattern) and routing
###              the message through it.
###
###          SHOULD-FIX (latent / UX):
###            * ``Write-NemAudit`` fan-out filter dropped the dead
###              ``*.Preflight`` arm. No callsite ever used a bare
###              ``.Preflight`` suffix; keeping the arm was a future-
###              bug magnet (a contributor adding ``-Action 'X.Preflight'``
###              later would have got unexpected fan-out semantics).
###              Filter is now ``$Action -like '*.Target'`` only.
###            * FormClosing in-flight gate latch moved earlier —
###              ``Set-NemClosingInFlight $true`` now happens BEFORE
###              ``Show-NemClosingNotesDialog``, not after. WinForms
###              modal dialogs don't normally reenter, but any
###              future code path that pumps the message loop
###              during the dialog (DoEvents, async toolkit,
###              third-party hook) would re-enter and double-prompt.
###              Cancel-Close path now explicitly clears the flag
###              so the operator can try again.
###            * Closing-notes dialog ``ControlBox = $false``. The
###              dialog defaults ``Cancelled = $true``, so a stray
###              title-bar X click silently aborted the close —
###              operator could think they had submitted logs when
###              in fact the dialog was dismissed. Force them
###              through one of the three explicit buttons.
###            * Documented the IsPackage Cancel-during-Copy stage-
###              dir leak risk. PowerShell.Stop() does NOT guarantee
###              the runspace's `finally` runs, so a Cancel
###              mid-Copy-Item-ToSession can leave
###              ``C:\Windows\Temp\janet-pkg-<guid>`` orphans on
###              targets. Accepted (narrow window, OS-cleanup path,
###              inert dirs). If it becomes a real complaint, add a
###              controller-side stage-tracker file + session-start
###              sweep.
###            * Added scriptblock-author warning above the
###              IsPackage Verify rehydration sites: every IsPackage
###              Verify body MUST be self-contained — no $using:,
###              $script:, $global:, no closure-captured locals. We
###              rehydrate it via ``[scriptblock]::Create()`` on the
###              remote, which means anything that's not built-in
###              cmdlets / types / inline literals will silently
###              throw inside the swallow-catch.
###
###          What looks solid (reviewer's positive notes — left as-is):
###            * Invoke-NemCloseFlow (1.9.2) clears the flag on
###              every failure path; both buttons use it cleanly.
###            * IsPackage early-returns are bulletproof — the
###              ``$prof.Script.ToString()`` calls below are
###              unreachable for package profiles.
###            * AddArgument / param order matches across both
###              pool scriptblocks.
###            * ``Write-NemTouchedHostCsv`` swallows comprehensively;
###              never throws.
###            * FormClosing CloseReason filter correctly only
###              blocks UserClosing.
###            * Drain-timer Tick handlers all use ``Get-NemState``
###              and never reach for ``$script:`` directly.
###            * ``Write-NemRunSummary`` member fan-out preserves
###              per-CVE Scope correctly.
###
###  v1.9.2 - 2026-05-07 - Hotfix: Close Tool buttons actually fire Form.Close().
###          Operator report on 1.9.1: "Close Tool button still does
###          not work, but X works and shows the popup I want."
###
###          Root cause: both Close Tool button click handlers
###          (sidebar + new top-right) did:
###              `$btn.Add_Click({
###                  Set-NemAllowClose `$true
###                  `$script:Nemesis.UI.Form.Close()
###              }.GetNewClosure())
###          Per the standing project rule, direct ``$script:`` access
###          from inside .GetNewClosure() under PS 5.1 + StrictMode 3
###          is unreliable — ``$script:Nemesis`` silently resolves to
###          ``$null`` on some launch paths so Form.Close() never
###          fires. Set-NemAllowClose IS a global function so the flag
###          DOES land. Result: button click sets ``NemAllowClose=`$true``
###          but does NOT close the form. Next time the operator clicks
###          X, the X-block sees the leftover flag, lets the close
###          through, and the closing-notes popup fires. Hence the
###          symptom: button "doesn't work", X "works."
###
###          Fix: new global:Invoke-NemCloseFlow helper that:
###            1. Set-NemAllowClose `$true
###            2. Resolves the form via Get-NemState (works from
###               closure context where direct `$script: access does
###               not).
###            3. Calls `$form.Close().
###            4. On any failure (Close throws, form not resolvable),
###               clears NemAllowClose and writes a CloseFlow.Failed
###               audit row so a stale flag can't slip a subsequent
###               X click through the X-block.
###
###          Both button click handlers now contain only:
###              `$btn.Add_Click({ Invoke-NemCloseFlow }.GetNewClosure())
###          Zero ``$script:`` access in either closure.
###
###  v1.9.1 - 2026-05-07 - Top-right Close Tool button + X-block restore.
###          New prominent "Close Tool" button at the top-right of the
###          content header bar (anchored Top,Right; tracks viewport
###          resize). Pairs with the existing sidebar "Close Tool"
###          button — both routes set NemAllowClose=`$true and call
###          `$form.Close(), funneling through the same closing-notes
###          flow.
###
###          X-block restored. The title-bar X / Alt-F4 /
###          right-click-title-Close paths are now inert: FormClosing
###          cancels CloseReason=UserClosing unless NemAllowClose has
###          been set by an explicit Close Tool button click. Other
###          CloseReasons (Console, TaskManager, WindowsShutdown,
###          ApplicationExitCall) pass through so OS-driven shutdown
###          still works. v1.8.12 had removed this block because the
###          sidebar button alone was hard to find at certain DPI
###          combos — the new top-right button removes that concern.
###
###          Closing-notes dialog reworked to make "submit all logs"
###          explicit:
###            * Title: "ACAS Nemesis - Submit Logs + Close Tool"
###            * Body lists every artifact that gets flushed on submit
###              (today's Runs CSV + per-session .log + TouchedHosts
###              CSV + JANET centralized rollup) so the operator and
###              the lead reading the share later can see exactly
###              what was delivered.
###            * Buttons: "Submit Logs + Close" (primary) / "Submit
###              (skip notes)" / "Cancel Close".
###            * Dialog grew 410h -> 470h to fit the new artifacts list.
###
###          New SessionEnd audit terminator written to the per-session
###          .log right after Stop-JanetSession, with run/success/fail
###          counters + the artifact paths in the Detail field. Gives
###          the lead a clean closing line when reading the .log later
###          ("this session completed and submitted everything").
###
###          New audit action: CloseAttempt.Blocked — written when the
###          operator clicks the title-bar X / hits Alt-F4 / picks
###          system-menu Close. Lets a lead see in the .log if an
###          operator was confused about how to exit.
###
###  v1.9.0 - 2026-05-07 - Tenable Nessus Agent profile (PSADT package deploy).
###          ACAS plugin "Tenable Nessus Agent" / "Nessus Agent" findings
###          now route to a new updater profile that pushes the operator-
###          staged PSADT package at:
###            Tools\Packages\NIPR_Tenable Nessus Agent_11.1.3\
###          to the target via Copy-Item -ToSession over the existing
###          PSSession, then runs Deploy-Application.ps1 with
###          -DeployMode NonInteractive. PSADT exit codes are parsed
###          (0/1641/3010 = Success, 60012 = Deferred, else Failed).
###          Engine mirrors WPT 6.5.x's RemotePackageInstaller path.
###
###          Plumbing
###            * NEW Get-NemPackageSourcePath - resolves and validates
###              `$PSScriptRoot\Packages\<folder>\Deploy-Application.ps1
###              before dispatch. Returns `$null when missing — caller
###              fails fast with a clear message rather than hanging
###              on remote.
###            * NEW IsPackage / PackageFolder fields on profile entries.
###              Profile.Script is `$null for IsPackage profiles — the
###              deploy engine lives in the pool scriptblock instead.
###            * Start-NemVulnRun: pre-resolves `$pkgSrcOverride before
###              entering the pool, passes via new AddArgument slot.
###              Pool scriptblock gained `$PkgSrcIn param + IsPackage
###              branch (validates package, creates remote stage dir,
###              Copy-Item -ToSession, runs Deploy-Application.ps1,
###              parses exit codes, post-Verify, cleanup).
###            * Start-NemBulkRunAll: same param + branch, with a
###              per-profile package-path map (`$pkgSrcByProfile)
###              built operator-side so heterogeneous bulk batches
###              with multiple IsPackage profiles all work.
###            * Invoke-NemUpdateRun: returns FAIL with a clear message
###              for IsPackage profiles (this helper has no package
###              dispatch path — programmatic callers should use
###              Start-NemVulnRun instead).
###            * Backbone tab notes: new entry under
###              Get-NemUpdaterMechanismsText so the per-profile
###              reference renders Mechanism / When to use / Verify
###              for the Nessus profile.
###
###          Profile entries
###            * NEW 'Tenable Nessus Agent - Package Deploy'
###                IsPackage     = `$true
###                PackageFolder = 'NIPR_Tenable Nessus Agent_11.1.3'
###                Script        = `$null
###                Verify        = HKLM:\SOFTWARE\Tenable\Tenable
###                                Nessus Agent registry probe with
###                                Uninstall-key DisplayVersion fallback
###            * Match-table: Keywords=@('Tenable Nessus Agent',
###              'Nessus Agent','Tenable Nessus') -> the new profile.
###
###          When the package folder is absent (operator's J.A.N.E.T.
###          copy doesn't have Tools\Packages\NIPR_Tenable Nessus
###          Agent_11.1.3\), the per-host result is "FAIL: Package
###          source not resolved on controller" — no remote work,
###          no half-run state.
###
###  v1.8.12 - 2026-05-06 - Restore working X / Alt-F4 close.
###          Operator report: "no close button — clicking X doesn't
###          work nor do I see it." Root cause: the FormClosing handler
###          had an X-block that cancelled any close not initiated by
###          the bottom-sidebar "Close Tool" button. At certain DPI
###          / window-size combos the Close Tool button drifted out
###          of view, leaving the operator with no way out (X / Alt-F4
###          / right-click-title-Close were all silently rejected).
###          The block was originally defense against the closing-notes
###          dialog or ACAS Runs CSV write throwing and skipping the
###          JANET rollup row, but v1.3.2 already separated the
###          dialog + CSV-write try/catch from the Stop-JanetSession
###          call so the rollup writes unconditionally on actual close.
###          Removed the block. X / Alt-F4 / right-click Close all now
###          flow through FormClosing normally: closing-notes dialog
###          appears, Cancel keeps the form open ($e.Cancel = $true),
###          OK writes the SessionNotes row + JANET rollup + closes.
###          The "Close Tool" sidebar button is preserved as a
###          secondary exit (Set-NemAllowClose call is now harmless,
###          since the gate is gone).
###
###  v1.8.11 - 2026-05-06 - Sister-CSV spam fix in JANET logging.
###          Operator hit "WARNING: JANET schema rotation failed; routing
###          rows to sister CSV: ...2026-05_usage.r<unix>.csv" once per
###          audit row when the share's legacy 2026-05_usage.csv was
###          locked by a peer process. The redirect path was generating
###          a fresh <base>.r<stamp>.csv per call (stamp is the current
###          Unix second), so each row produced a NEW sister file —
###          dozens of empty-or-near-empty sisters piling up in the
###          share's Logs folder.
###          Fix: before creating a sister, scan
###          <Logs>\<base>.r*.csv for one whose first line matches the
###          current header. If found, reuse it silently. Only mint +
###          warn when none exists. Net effect: at most ONE sister CSV
###          per (operator, schema) pair instead of one per call, and
###          the warning fires once instead of every audit write.
###          Same fix applied to WPT 6.5.7.
###
###  v1.8.10 - 2026-05-06 - Apache Log4j profile: 2.25.3 -> 2.25.4.
###          Updated all Log4j references in the
###          'Apache Log4j - Replace Vulnerable Jars' profile from
###          2.25.3 to 2.25.4: $newApi / $newCore constants, profile
###          Desc, Verify regex, Verify Detail string, and the
###          comment block above the profile.
###          The 2.25.4 release adds fixes for plugins 306549
###          (XmlLayout invalid output, CVE-2026-34480) and 306550
###          (SSL hostname verification bypass, CVE-2026-34477) on
###          top of 282519 (MitM, CVE-2025-68161). All three plugins
###          now clear via the profile's Verify path — previously
###          306549/306550 ran the swap successfully but Verify
###          flagged them STILL-VULNERABLE because 2.25.3 < 2.25.4.
###          Operators must drop log4j-api-2.25.4.jar +
###          log4j-core-2.25.4.jar at the source path (default
###          <JANET-root>\Tools\Packages\Log4j\NewFiles\) before
###          running. Stale 2.25.3 jars at the share will produce a
###          "FAIL: source jar missing on share" up front, no
###          half-stopped services.
###
###  v1.8.9 - 2026-05-06 - Hostname normalization at ACAS import.
###          Operator report: Tenable CSVs ship hostnames in three
###          forms — `DOMAIN\HOST` in NetBIOS, `host.fqdn.tld` in DNS,
###          IPv4 in IP. The DNS form is preferred downstream, so the
###          FQDN was driving every WinRM connect, audit row, log
###          line, and card host list. Two problems with that:
###            (1) Noisy UI — every host in the Targets tab and on
###                Updater cards read "msekl-2701dz.area52.afnoapps
###                .usaf.mil" instead of just "msekl-2701dz".
###            (2) Correlated with Negotiate auth failures on hosts
###                whose AD SPN registration didn't match the FQDN.
###                The v1.8.3 NetBIOS retry was already silently
###                stripping the suffix on auth failure — this just
###                does it consistently up front.
###          New global helper Get-NemShortHost normalizes any of the
###          three forms to the bare short name:
###            "DOMAIN\HOST"        -> "HOST"
###            "host.fqdn.tld"      -> "host"
###            "10.0.0.5"           -> "10.0.0.5"  (IPv4 untouched)
###          Applied at Import-WptAcasCsv to both the DnsName and
###          NetBios columns. IpAddress passes through unchanged.
###          Test-NemIsServer keeps catching `^msek-` server prefixes
###          (msek-as-03v / msek-fs-01v / etc.) because they're still
###          intact post-strip. Existing v1.8.3 NetBIOS retry path is
###          unchanged — already a no-op when the input is short.
###
###  v1.8.8 - 2026-05-06 - UI freeze fix + Pop Out Log button.
###          Operator hit a hard UI freeze during a Log4j run — the
###          window stopped responding and there was no way to scroll
###          the cards or see what was running. Two fixes:
###
###          1. Removed all serial preflight loops on the UI thread.
###             v1.8.4's TCP probe runs at 3s/port — for N unreachable
###             hosts that's up to 6s × N seconds of frozen UI before
###             ANY work dispatches. Stripped at all four sites:
###             Start-NemVulnRun, Start-NemBulkRunAll, Start-NemRebootRun,
###             KB Installer. Each runspace scriptblock already has the
###             same TCP probe inline, so unreachable hosts now fail in
###             parallel via the pool with the same FAIL message
###             ("FAIL - unreachable (TCP 5985/445)") flowing through
###             the drain timer instead of upfront.
###
###          2. New "Pop Out Log" button on the Updater tab header.
###             Reparents the embedded RichTextBox into a separate
###             floating Form (1100x700, resizable, min 640x360). All
###             existing $rtb.AppendText() call sites keep working
###             unchanged because the RTB control reference is stable
###             — only its parent changes. On window close, the RTB
###             reparents back into the embedded panel. State is held
###             at $s.UI.Controls['updPopOutForm'] so re-clicking the
###             button just activates the existing window instead of
###             opening a duplicate.
###
###  v1.8.7 - 2026-05-06 - Log4j default path: Tools\Packages, not
###          root\Packages. The fleet convention is
###          <JANET-root>\Tools\Packages\Log4j\NewFiles\ — Packages\
###          is a sibling of ACAS Nemesis Tool_*.ps1 inside the
###          Tools folder, NOT one level up next to Tools\. v1.8.5
###          mistakenly used Split-Path -Parent before joining,
###          which walked up out of Tools\. Now joins directly onto
###          $scriptDir.
###
###  v1.8.6 - 2026-05-06 - Log4j: stage jars over the session.
###          v1.8.5's path-override approach interpreted the textbox
###          as a remote-side path: the swap script ran on the target
###          and called Test-Path against it. That works only when
###          the remote can reach the path itself — fails when:
###            * Operator's textbox is a local controller path (e.g.
###              C:\Users\<edipi>\Documents\Code\J.A.N.E.T\Packages\
###              Log4j\NewFiles) — remote target's local C: doesn't
###              have those files at that path.
###            * Path is a UNC the controller can read but the remote
###              can't (double-hop credential delegation: Negotiate-
###              auth WinRM sessions don't pass creds beyond the
###              first hop, so the remote can't authenticate to the
###              share even though the operator can).
###          Fix: textbox is now interpreted as a CONTROLLER-side
###          path. Both runspace dispatch sites (Start-NemVulnRun +
###          Start-NemBulkRunAll) now:
###            1. Pre-check the jars exist at $Log4jSrcIn locally on
###               the controller before opening the session.
###            2. Open session, mkdir C:\Windows\Temp\janet-log4j-
###               stage-<guid>\ on the remote.
###            3. Copy-Item -ToSession push the two jars over the
###               authenticated session — no second-hop auth, no
###               remote-side share dependency.
###            4. Substitute the remote stage dir as $sourceShare in
###               the profile script before rehydration.
###            5. finally: remove the remote stage dir best-effort.
###          Result: works whether JANET runs from local disk, a
###          UNC share, or a mapped drive — the operator just points
###          the textbox at where the jars live on THEIR machine.
###
###  v1.8.5 - 2026-05-06 - Operator-overrideable Log4j source path
###          (port of WPT 6.5.2). Default no longer hardcoded to
###          \\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\
###          NewFiles — now auto-resolves to <JANET-root>\Packages\
###          Log4j\NewFiles based on $scriptDir, so the path follows
###          wherever JANET is installed. New $global:NemLog4jDefault
###          Source exposes that resolved path.
###          Updater tab gains a "Log4j source:" label + textbox in
###          the header (height 136 -> 168) pre-filled with the
###          default. Operator can edit before clicking Run on any
###          Apache Log4j card. The active value is read by
###          Get-NemLog4jSourcePath (textbox > default fallback) and
###          fed into both runspace dispatch sites (Start-NemVulnRun
###          + Start-NemBulkRunAll) as $Log4jSrcIn. The runspace
###          inlines a regex substitution against the embedded
###          $sourceShare literal in profile.Script.ToString() before
###          rehydrating with [scriptblock]::Create(), so the remote
###          sees the operator's path instead of the registry default.
###          Single-target Invoke-NemRemote path also updated via the
###          new Resolve-NemProfileScriptText helper.
###          Verify path needs no override — it only reads the target
###          paths, doesn't touch the source share.
###
###  v1.8.4 - 2026-05-06 - Bumped TCP probe per-port timeout 1.5s -> 3s.
###          A WPT-vs-Nemesis side-by-side on the same host set showed
###          slow-but-reachable AFNET hosts being false-negatived at
###          1.5s while WPT (no pre-probe, long WSMan OpenTimeout)
###          eventually got through. 3s per port keeps the worst-case
###          dead-host wait bounded at 6s (5985 then 445) while catching
###          slow responders Nemesis was previously writing off.
###          Applied to Test-NemTcpReachable param default + all five
###          inlined runspace probe blocks (VulnRun, BulkRunAll,
###          RebootVerify, KB Installer MECM, KB Installer UsoClient).
###
###  v1.8.3 - 2026-05-06 - NetBIOS auth fallback + server-prefix filter.
###          Two fixes driven by an actual Run-All log on AFNET:
###
###          1. NetBIOS retry on Negotiate auth failures.
###             Hosts whose Kerberos handshake fails with WSMan
###             0x80090322 (SEC_E_WRONG_PRINCIPAL) or "Negotiate
###             authentication" / "Access is denied" now get a
###             one-shot retry using the NetBIOS short name (everything
###             before the first '.' in the FQDN). NetBIOS forces NTLM,
###             which has different SPN requirements than Kerberos and
###             usually clears the case where AD SPN registration or
###             DNS reverse lookup is broken on the target. Applied to
###             all five PSSession open sites: Start-NemVulnRun,
###             Start-NemBulkRunAll, Start-NemRebootVerify, KB Installer
###             MECM, KB Installer UsoClient. Failure messages now read
###             "FAIL: Session - <orig> (NetBIOS retry [name] also
###             failed: <reason>)" so the operator can tell which leg
###             of the retry actually failed.
###
###          2. Server-prefix filter on ACAS import.
###             New global helper Test-NemIsServer flags any hostname
###             matching ^msek- (literal hyphen, distinct from msekl- /
###             msekt- / msekw- workstations). The Targets-tab
###             "Import ACAS" handler now drops both server-tagged
###             rows (from AcasFindings) and server-tagged hostnames
###             (from the unique-host accumulator) at the source.
###             Skipped counts surface in the ImportACAS audit detail
###             as "servers_skipped=<hosts>/<rows>" so the operator can
###             confirm the filter fired. Server patching belongs in a
###             separate change window with separate approval — this
###             tool only drives end-user endpoint remediation.
###
###  v1.8.2 - 2026-05-05 - Apache Log4j updater profile (WPT 6.4.2 port).
###          Log4j moved from "Unpatchable" classification to a real
###          updater profile. Lift-and-shift port of WPT 6.4.2's
###          'Apache Log4j - Replace Vulnerable Jars' which is itself a
###          port of Log4J_Plugin_282519 v2.ps1. Source jars (2.25.3) at
###          \\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles.
###          Targets HID Global Credential Management Client + Adobe
###          Experience Manager Forms Designer lib paths. Stops bundled
###          service, backs up old jars to Backup_<ts>\, swaps,
###          restarts service in finally{} so a failed swap can't leave
###          a half-stopped service. Verify enumerates log4j-*.jar in
###          both targets and flags non-2.25.3 names as STILL-VULNERABLE.
###          Card grouping: every "Apache Log4j" plugin (282519 MitM,
###          306549 XmlLayout, 306550 SSL Hostname, etc.) rolls up to
###          one card per the operator request. Plugins requiring
###          2.25.4+ will need the share jars + profile constants
###          bumped — Verify already flags them as STILL-VULNERABLE so
###          the rollup card surfaces the gap clearly.
###
###  v1.8.1 - 2026-05-04 - Renamed the new tab "How To" -> "Backbone".
###          Side-nav position 08 unchanged. Renames:
###            * nav Key 'HowTo' -> 'Backbone'; Label same.
###            * function Add-NemHowToTab -> Add-NemBackboneTab
###            * state-dict key 'howToRtb' -> 'backboneRtb'
###            * tab title label 'How To' -> 'Backbone'
###            * subtitle text rephrased to lead with "mechanism backbone"
###          Pre-existing Start-tab "How To Use" dialog button is
###          unaffected — that's a separate UI element with its own
###          backing function (Get-NemHowToUseText) which still feeds
###          both the dialog and the Backbone tab body.
###
###  v1.8.0 - 2026-05-04 - New "How To" tab below Logs.
###          Position 08 in the side nav. Scrollable RichTextBox view
###          of the full narrative reference. Two sections:
###            1. PER-PROFILE MECHANISM REFERENCE - auto-generated
###               from $script:WptAppUpdateProfiles. For each profile
###               (Microsoft 365 - Force Update / -SYSTEM task /
###               -User Visible / -Software Center, Google Chrome -
###               Update / -Software Center, Microsoft Edge -
###               Update / -Software Center, Windows Defender -
###               Update Definitions, Microsoft Store - Update Apps)
###               prints Summary + Mechanism + When-to-use + Verify.
###               New profiles added to the registry surface here on
###               next tab visit without a code change to the tab.
###            2. OPERATOR WORKFLOW WALKTHROUGH - the existing
###               Get-NemHowToUseText (Quick Start, KB Installer
###               method breakdown, troubleshooting, required access).
###               The Start-tab "How To Use" dialog button continues
###               to show ONLY the workflow walkthrough — the tab is
###               the richer single-source reference.
###          Tab toolbar: Refresh Content (rebuilds from live registry)
###          and Copy to Clipboard. Tab content also auto-refreshes
###          on VisibleChanged so a profile added mid-session shows
###          up next time the operator opens the tab.
###          New helpers: Get-NemUpdaterMechanismsText,
###          Get-NemOverviewText. Add-NemHowToTab as the tab builder.
###          Hand-written mechanism notes table in
###          Get-NemUpdaterMechanismsText needs an entry per profile
###          for full detail; profiles missing from the table still
###          render their Desc + a stub note pointing at the source.
###
###  v1.7.0 - 2026-05-04 - Per-operator TouchedHosts CSV.
###          Use case: tool is going out to smaller / unknown teams and
###          a lead needs to know "which machines did operator X touch
###          this month" without grepping through daily session .log
###          files. Adds an operator-attributable structured CSV that
###          captures every per-host event the tool already audits.
###
###          Captures every operator action that reaches a remote box:
###            * VulnRun.Target / VulnRun.Preflight
###            * VulnVerify.Target / VulnVerify.Preflight
###            * Reboot.Target / Reboot.Preflight
###            * Reboot.Verify.Target / Reboot.Verify.Preflight
###            * Preflight.Services.Target
###            * BulkRun.Target / BulkRun.Preflight
###            * BulkVerify.Target / BulkVerify.Preflight
###            * KbInstall.Target
###          Aggregate events (.Start / .End / .Cancel / .StepFail)
###          skip the fan-out — they're not per-host.
###
###          New file:
###            \\dm-tn-01\sh-usafe-automation`$\JANET\Logs\ACAS_Nemesis\
###              <edipi> - <DisplayName>\
###                TouchedHosts_<YYYY-MM>.csv
###          Schema:
###            Timestamp,Operator,Edipi,SessionId,SourceHost,Action,
###            TargetHost,Result,Detail
###          Monthly rotation matches the JANET shared CSVs. Header is
###          written on first append of the month. Falls back to local
###          workspace if the share is unreachable, identical to the
###          existing Open-NemAuditLog resilience pattern.
###
###          Implementation: Write-NemAudit gained an inline fan-out at
###          the bottom that detects the per-host action suffix and
###          calls a new global Write-NemTouchedHostCsv helper. Zero
###          call-site changes — every existing audit call that writes
###          a host name as Target now also writes a CSV row, for free.
###
###  v1.6.2 - 2026-05-04 - Side-nav reorder.
###          Vulnerabilities moved from position 03 to position 06,
###          directly above Logs. New nav order:
###            01 Start
###            02 Targets
###            03 Updater
###            04 Not Updatable
###            05 KB Installer
###            06 Vulnerabilities
###            07 Logs
###          Rationale: the Updater workflow (Targets -> Updater) is the
###          primary path; the raw findings grid is a secondary lookup
###          view that pairs naturally with Logs. Pairs well with the
###          1.6.1 on-demand Load Findings change — operators no longer
###          accidentally click into the heavy tab on the way from
###          Targets to Updater. Pure presentation change; tab keys,
###          tab-builder calls, and audit actions unchanged.
###
###  v1.6.1 - 2026-05-04 - Vulnerabilities tab on-demand load (crash fix).
###          The Vulnerabilities tab was hanging the WinForms host when
###          activated against a 400+ row CSV. Root cause: the
###          VisibleChanged handler called the grid populator on every
###          tab switch, which clears + re-adds rows one-at-a-time.
###          DataGridView.Rows.Add() in a tight loop with auto-fill
###          columns + cell-style work + StrictMode reentrancy is a
###          known crash mode at that volume.
###          Fix:
###            * Removed the VisibleChanged auto-load handler.
###            * Tab now opens with the grid hidden under a centered
###              "Load Findings" overlay (Accent1 button + hint label).
###              Operator clicks once to populate.
###            * After load, a new "Reload Findings" toolbar button
###              picks up fresh imports without re-hiding the grid.
###            * Both load paths emit audit rows (VulnsLoad /
###              VulnsReload) with the resulting row count.
###            * Populator now writes into a hidden grid (overlay
###              covers the empty grid during the load) so paint
###              storms during Rows.Add() can't kill the host.
###
###  v1.6.0 - 2026-05-04 - Software Center updater profiles for Chrome / Edge / M365.
###          Three new entries in $script:WptAppUpdateProfiles:
###            * Google Chrome - Software Center
###            * Microsoft Edge - Software Center
###            * Microsoft 365 - Software Center
###          Each finds the matching CCM_Application via the SCCM client
###          SDK (ROOT\ccm\ClientSDK), filters by name + ApplicabilityState
###          + IsMachineTarget, picks the best candidate, and triggers
###          Install via Invoke-CimMethod. Same engine WPT 6.3.0 uses in
###          its bulk-patch / SCCM App Manager paths, lifted into the
###          named-profile registry so per-card dropdowns can choose
###          EXE-direct vs Software Center per Run.
###
###          Get-NemProfileMatchTable updated:
###            * Office / M365 keyword match: 3 -> 4 profiles in the
###              dropdown (added Software Center as the 4th alternative
###              after the 3 OfficeC2RClient.exe variants).
###            * Chrome keyword match: 1 -> 2 profiles (EXE-direct
###              default, Software Center alt).
###            * Edge keyword match: 1 -> 2 profiles (EXE-direct
###              default, Software Center alt).
###            * Defender unchanged.
###
###          Edge cases the Software Center scriptblocks handle gracefully
###          (return informative status, never throw):
###            * SCCM client absent  -> 'FAIL: SCCM client not present'
###            * No matching app     -> 'SKIP: No matching <product>...'
###            * App not Applicable  -> 'SKIP: ... not Applicable'
###            * Install throws      -> 'FAIL: <err>'
###          The Edge name-match excludes the noise variants (Edge Update,
###          WebView2, Helper, Beta/Dev/Canary) since those ship as
###          separate CCM_Application entries on most images. The M365
###          name-match excludes per-app sidecars (Skype, Teams, OneDrive,
###          Visio, Project, Language Pack, Proofing, etc.).
###
###          Verify scriptblocks reuse the EXE-direct profile's registry
###          version-probe — install location is mechanism-agnostic.
###
###          Card UX impact: Chrome and Edge ROLLUP cards now render the
###          same per-card profile dropdown M365 already had; the default
###          selection stays the EXE-direct profile (most reliable on
###          AFNET workstations where the SCCM client may lag). The
###          ROLLUP card grouping is unchanged — sort-joined profile
###          signature still buckets all Chrome vulns into one card,
###          all Edge vulns into another. GroupKey strings change for
###          Chrome / Edge groups (one-time discontinuity in the new
###          column added in 1.5.0; no data loss).
###
###  v1.5.0 - 2026-05-04 - Updater card grouping by profile.
###          Same-profile vulns roll up into one consolidated card.
###          A typical weekly scan (e.g. ESS Future Target List Lakenheath
###          2026-05-04) collapses ~92 per-vuln cards across Chrome (18) /
###          Office C2R (72) / Defender (2) into 3 ROLLUP cards. Bulk Run
###          dispatch count drops proportionally, host-union dedupes any
###          overlap so each host gets the updater pushed once.
###
###          Card UX:
###          * NEW Get-NemVulnCardEntries (after Get-NemVulnGroups): wraps
###            the per-vuln list and rolls up by sorted-joined profile-name
###            signature. Singletons stay ungrouped. Reboot / Unpatchable /
###            NotUpdatable categories never group.
###          * NEW IsGroup branch in New-NemVulnCard: ROLLUP xN badge in
###            Accent2, hover-tooltip on the badge + title row listing
###            member Plugin Names (truncated at 25 + "...+M more").
###          * Update-NemVulnCards switched to Get-NemVulnCardEntries.
###            Reboot cards still use New-NemRebootCard; everything else
###            (Patchable / Experimental, grouped or not) flows through
###            New-NemVulnCard which already handles the synthetic shape.
###
###          Run / Verify pipeline:
###          * Start-NemVulnRun gained -GroupKey + -GroupMembers params
###            (default empty). Per-vuln cards leave them empty and
###            behavior is byte-identical to 1.4.x. Group cards thread
###            them in. Both stash into $s.Jobs._counters so the drain
###            timer's final tick can pass them to Write-NemRunSummary.
###          * The dispatch / pool / cancel / scriptblock / Verify path
###            is untouched — the synthetic vuln walks the same code as
###            a real one. Host union happens upstream in
###            Get-NemVulnCardEntries.
###
###          Audit fan-out:
###          * Write-NemRunSummary gained -GroupKey + -GroupMembers. When
###            GroupMembers is non-empty, writes one Runs CSV row per
###            member vuln (sharing Timestamp/Profile/Mode/Hosts*/RunBatch
###            counters) instead of one synthetic-display-name row.
###            JanetDashboard / per-CVE reporting stay accurate.
###          * Write-NemRunCsvLine schema bumped: trailing GroupKey and
###            GroupSize columns. The existing schema-migration block
###            (line 4945-area, archives the old daily file as
###            .pre-schema-change.csv when column count changes)
###            handles the upgrade in-place — no manual migration needed.
###          * Bulk Run summary tagged GroupKey='<bulk>' for visibility.
###            Bulk does NOT fan out per-member (heterogeneous batch by
###            design) — use the per-card Run for member-level rollup.
###
###  v1.4.1 - 2026-05-04 - Hotfix on top of 1.4.0.
###          * Add-NemVulnCard: $card.Tag assignment was placed BEFORE
###            $btnVerify was created (introduced in 1.4.0 alongside the
###            VerifyButton field added for Start-NemBulkRunAll). Under
###            Set-StrictMode -Version 3.0 this threw "the variable
###            '$btnVerify' cannot be retrieved because it has not been
###            set" on every Refresh Cards / Bulk Run click on the
###            Updater tab. Reordered so $btnVerify is created first,
###            $card.Tag is assigned second.
###          * Bumped $JanetACAS_NemesisVersion from 1.3.4 -> 1.4.1.
###            The 1.4.0 file was renamed without bumping this
###            constant, so the title bar / audit log header / Start
###            tab version label all displayed v1.3.4 while the
###            filename and JANET centralized CSV reported 1.4.0.
###            Both now agree on 1.4.1.
###
###  v1.4.0 - 2026-05-04 - WPT-ported reliability + bulk parallel runs.
###          Most updates were failing on AFNET because of two compounding
###          issues: (1) ICMP-based reachability was producing false
###          negatives on hosts that block ping but accept WinRM, and (2)
###          every remote call used `Invoke-Command -ComputerName` with
###          the default ~3min OpenTimeout and no auth scheme override,
###          so a single dead host could stall the runspace pool. Both
###          patterns were fixed in WPT 6.2.6+ ("v47 AFNET" changes); this
###          release ports them across.
###
###          Reliability changes (mirror WPT):
###          * NEW Test-NemTcpReachable - TCP probe on 5985 (WinRM) then
###            445 (SMB), 1.5s per port. Replaces Test-Connection ICMP
###            ping at every preflight site (Start-NemVulnRun,
###            Start-NemRebootRun, Start-NemRebootVerify, KB Installer).
###          * NEW New-NemSessionOption - bounded PSSessionOption with
###            OpenTimeout=15s, OperationTimeout=180s, IdleTimeout=60s.
###            Mirrors WPT 6.2.6 line 3954.
###          * NEW Invoke-NemRemote - one-shot helper for non-runspace
###            callers. TCP probe + bounded PSSession + Negotiate auth.
###          * Start-NemVulnRun scriptblock: replaced one-shot
###            `Invoke-Command -ComputerName` with inlined TCP probe +
###            New-PSSession (Negotiate auth, bounded timeouts), reused
###            for both Verify-only and full Update paths.
###          * Start-NemRebootVerify scriptblock: 10-minute reachability
###            poll switched from ICMP to TCP. Post-reach, opens a
###            bounded PSSession instead of one-shot Invoke-Command, so
###            machines with WinRM still warming up after reboot don't
###            get a 3-minute hang.
###          * KB Installer (MECM CIM): unified the MECM trigger and the
###            MSU fallback under ONE bounded PSSession, halving the
###            per-host WinRM handshake cost. Both phases reuse the same
###            session.
###          * KB Installer (UsoClient): switched to bounded PSSession.
###          * Invoke-NemUpdateRun (external single-target helper): now
###            delegates to Invoke-NemRemote so ad-hoc callers also get
###            the reachability preflight + bounded timeouts.
###
###          Bulk parallel runs (NEW):
###          * NEW Start-NemBulkRunAll + "Bulk Run (Parallel)" button on
###            the Updater tab header. Walks every patchable card,
###            collects (host, profile) tuples (honors the per-card
###            profile dropdown), and submits ALL jobs into the runspace
###            pool simultaneously. Single drain timer aggregates results
###            with [VulnDisplay] prefixes so the operator can see which
###            update on which host succeeded/failed.
###          * Distinct from existing Run All Updates (sequential card
###            walk). The two buttons share the cancel handler, the
###            single-run lock, and the audit trail. Reboot cards are
###            skipped (those need the explicit warning dialog).
###          * New audit prefixes: BulkRun.Start / BulkRun.Target /
###            BulkRun.End and BulkVerify.* mirror the per-card prefixes.
###            Per-host JANET centralized logging (VulnPatched) fires for
###            every job, same as per-card runs.
###          * Card Tag now exposes Vuln + ProfileCombo + VerifyButton
###            (line ~5711) so the bulk runner can build its dispatch
###            list without going through the per-card click handler.
###
###  v1.3.4 - 2026-04-29 - JANET detail CSV improvements:
###          * Per-host RemediatePlugin row's Detail column now includes the
###            vulnerability display name and the mode (Update / Verify), so
###            the file reads cleanly in Excel without cross-referencing the
###            ACAS Runs CSV. Format: "vuln=<name> profile=<profile> mode=<mode>".
###          * Canonical block re-stamped to add CSV header rows on first
###            write and a more robust AD displayName lookup.
###
###  v1.3.3 - withdrawn pre-release (no shipped build).
###
###  v1.3.2 - 2026-04-27 - Bug fix: Stop-JanetSession could be skipped if the
###          closing-notes dialog or the ACAS-specific Runs CSV write threw.
###          Restructured the FormClosing handler so the JANET rollup row
###          ALWAYS lands when the form is actually closing — only skipped
###          on the explicit Cancelled path (which keeps the form open via
###          $e.Cancel). Same class of bug as WPT 6.2.1 had; this is the
###          ACAS-flavored fix.
###
###  v1.3.1 - 2026-04-26 - Unified the ACAS-specific Runs CSV onto the JANET share.
###          $script:NemLogShare moved from
###            \\msek-fs-01v\Apps\10. Patching\#_Remote Patching Scripts\#_Logs
###          to
###            \\dm-tn-01\sh-usafe-automation$\JANET\Logs\ACAS_Nemesis
###          The ACAS Runs CSV (per-run rich schema: HostsTotal/Success/Failed/
###          Duration) and the JANET detail CSV (per-action rows) now live in
###          the same folder — different file naming, no collision:
###            ACAS-Nemesis-Runs_YYYY-MM-DD.csv  (this tool's per-run history)
###            YYYY-MM_detail.csv                (JANET centralized per-action)
###          One share for the whole suite.
###
###  v1.3.0 - 2026-04-25 - Added JANET centralized logging. Per-host RemediatePlugin
###          rows go to \\dm-tn-01\sh-usafe-automation$\JANET\Logs\ACAS_Nemesis\<YYYY-MM>_detail.csv;
###          rollup row per session goes to <YYYY-MM>_usage.csv at the log root.
###          Reuses ACAS's existing closing-notes dialog (no double-prompt) and
###          mirrors its notes into the JANET rollup row. Spec:
###          docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
###
###  v1.2.1 - Finding classification + Reboot card + Experimental profile.
###
###           Get-NemVulnGroups now tags every group with a Category field
###           (Patchable / Experimental / Reboot / Unpatchable / NotUpdatable).
###           Priority: Unpatchable > Reboot > Experimental > Patchable >
###           NotUpdatable. Classification is pattern-matched on PluginName.
###
###           New Microsoft Store - Update Apps profile (MDM CIM method).
###           Tagged Experimental; routes to the Updater tab with amber
###           styling. Verify block reports Microsoft.WindowsApp version.
###
###           New Start-NemRebootRun: dispatches shutdown.exe /m \\HOST /r /t
###           300 locally for each reboot-group host. Pre-flight ping, drain-
###           timer pattern mirrors Start-NemVulnRun. Audit: Reboot.*.
###
###           New Start-NemRebootVerify: per-host runspace ping loop (15s
###           poll, 10min timeout) then Invoke-Command checks RebootPending
###           registry key + returns CurrentBuildNumber.UBR.
###
###           New New-NemRebootCard: amber accent bar, two-button layout
###           (Reboot Now / Verify Post-Reboot), editable warning-message
###           TextBox. Registered in updVulnCards for master run-lock.
###
###           New-NemVulnCard updated: Experimental category gets amber
###           accent, EXPERIMENTAL badge, orange Run button, and prefixed
###           profile description.
###
###           Update-NemVulnCards now routes by Category; Reboot cards use
###           New-NemRebootCard. Cards ordered: Patchable, Experimental,
###           Reboot (by CatRank sort in Get-NemVulnGroups).
###
###           Update-NemNonUpdatableCards now shows Unpatchable and
###           NotUpdatable with separate section headers. New-NemNonUpdatableCard
###           shows context-aware remediation notes per plugin family (Log4j /
###           Oracle / CPU microcode) + a Copy Plan button that writes
###           hosts + CVEs + Solution text to the Windows clipboard.
###
###  v1.2.0 - Ship-time hardening + critical bug fix.
###
###           CRITICAL: fixed a WinRM scriptblock-serialization bug that
###           made every Office / Chrome / Edge / Defender Updater card
###           fail with "The term '$c2r = ...' is not recognized as the
###           name of a cmdlet". Scriptblocks passed through
###           -ArgumentList do not survive WinRM serialization — they
###           arrive remotely as plain strings. Fix: pass scriptblock
###           source text explicitly and rehydrate with
###           [scriptblock]::Create() on the remote side.
###
###           Share-access resilience: the tool now starts + logs
###           locally when the shared log path is unreachable or ACL-
###           denied. Resolve-NemLogDir replaces Test-Path with an
###           actual sentinel-file write probe (Test-Path returns true
###           even on read-only shares). Open-NemAuditLog never
###           throws — it tries the configured LogDir, then the local
###           workspace, then silently gives up (session still starts).
###           Session-start shows a soft info/warning popup explaining
###           the fallback. Write-NemRunCsvLine also fails over to
###           local mid-session if the share drops, and flips
###           Config.LogDir so every subsequent row goes local without
###           re-hitting the dead share.
###
###           Start tab share line now reflects the LIVE Config.LogDir
###           (not the stale startup-time resolution), so mid-session
###           failover is visible without a relaunch.
###
###  v1.1.0 - Per-vulnerability Updater refactor. Targets tab is now ACAS-
###           only (no paste). New Vulnerabilities tab owns the findings
###           grid. Updater tab split: cards with matched profiles on the
###           Updater tab, non-updatable findings on the new Not Updatable
###           tab. Each updatable card picks its own profile via dropdown
###           when multiple variants exist (e.g., M365 Force vs User-
###           Visible). Added per-card Verify button that runs only the
###           Verify scriptblock to re-check versions post-update.
###
###           KB Installer gained a Method dropdown: MECM (CIM targeted)
###           using the SIM_Tool pattern (CCM_SoftwareUpdatesManager.
###           InstallUpdates over WinRM-CIM) as the default, UsoClient
###           Trigger as the alternate. Added optional MSU path + Browse
###           for WPT-style wusa.exe fallback on KBs MECM didn't match,
###           and a Suppress Auto-Reboot checkbox that flips the AU
###           registry keys pre-install and passes /norestart to wusa.
###           Fixed a pre-existing bug where UsoClient ran locally
###           instead of on the target.
###
###           All remote Invoke-Command / PSSession calls now forward the
###           operator-set PSCredential from the Start tab (falls back to
###           ambient Kerberos when no credential is stored).
###
###           Added shared daily Runs CSV telemetry to the log share,
###           closing-notes dialog on shutdown, and SIM-style AD
###           displayName + EDIPI operator identity (per-user subfolder
###           under the log share for transcripts). CSV writer auto-
###           detects schema changes and archives older-schema files with
###           a .pre-schema-change.csv suffix so today's new rows start
###           in a clean file.
###
###           Section headers reboxed, added Change Log + How To Use
###           buttons on the Start tab.
###
###  v1.0.4 - Smart Dispatch (Auto) mode for Updater: match findings to
###           profiles and run only what each host needs.
###
###  v1.0.3 - KB Installer v1 (UsoClient StartInstall trigger).
###
###  v1.0.2 - Pre-flight reachability ping; runspace pool drain timer
###           hardening.
###
###  v1.0.1 - Cancel button + timer/job disposal cleanup.
###
###  v1.0.0 - Initial release. Updater tab with Office / Chrome / Edge /
###           Defender profiles + Custom Command. Panel shell ported from
###           WPT, ACAS CSV parser ported from WPT AcasImport.
###
###############################################################################

[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

## v1.10.3: script-level trap. Anything that escapes a per-handler
## catch (or fires outside one — eg. a UI event-thread error in a
## scriptblock added via Add_Click / Add_Tick that lacks its own
## try/catch) lands here and gets printed to the host so the operator
## sees what blew up in the launching PowerShell window. The trap
## must `continue` rather than break — otherwise the WinForms UI
## thread exits on first unhandled error and the tool crashes.
trap {
    try {
        $exMsg = $_.Exception.Message
        $exType = $_.Exception.GetType().FullName
        $where = ''
        if ($_.InvocationInfo) {
            $li = $_.InvocationInfo.ScriptLineNumber
            $col = $_.InvocationInfo.OffsetInLine
            $ln = ($_.InvocationInfo.Line -as [string])
            if ($ln) { $ln = $ln.Trim() }
            $where = " at line ${li}:${col}  $ln"
        }
        Write-Host "[ERR] $exType - $exMsg$where" -ForegroundColor Red
    } catch {}
    continue
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v1.3.0. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\ACAS_Nemesis\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetACAS_NemesisVersion = '1.10.10'

# === BEGIN JANET LOGGING BLOCK (paste from here) ===
$JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

$script:JanetSession   = $null
$script:JanetNetworkOk = $false

## Closure-safe getter — closures created with .GetNewClosure() under StrictMode 3
## cannot reliably resolve $script:Foo. Helpers used from inside closures must
## be declared at global scope so they are always visible.
function global:Get-JanetSession { return $script:JanetSession }

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
    ## v1.10.5: thin enqueue wrapper. Previously this ran up to 6 retries
    ## with exponential Start-Sleep (~15s worst case) on the calling
    ## thread — a UI-thread freeze when the share misbehaved. The
    ## background writer now owns the network append, the local fallback,
    ## and header-on-create. $Header is written only when the target file
    ## is missing/empty. $MaxRetries / $InitialDelayMs are kept on the
    ## signature for call-site compatibility but are no longer used here
    ## (the writer applies its own bounded retry off-thread).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$Line,
        [string]$Header      = '',
        [int]$MaxRetries     = 6,
        [int]$InitialDelayMs = 250
    )
    Add-NemLogWrite -NetworkPath $NetworkPath -LocalPath $LocalPath -Line $Line -Header $Header
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
    ## v1.8.11 fix: reuse an existing sister whose first line already matches
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

    ## v1.10.5: header ensure folded into the async write. The background
    ## writer writes $script:JanetDetailHeader on first touch of the file;
    ## the old synchronous Add-JanetCsvHeader (Test-Path + mkdir + header
    ## write + schema rotation, all on the calling thread) is bypassed.
    ## Schema-mismatch rotation (legacy-rename) is no longer done inline —
    ## the JANET CSV schema has been stable since v1.3.4 and existing
    ## share files already carry the current header.
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
    Add-JanetCsvRow -NetworkPath $netFile -LocalPath $localFile -Line $line -Header $script:JanetDetailHeader

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

    ## v1.10.5: async write; writer handles header-on-create (see
    ## Write-JanetAction note).
    Add-JanetCsvRow -NetworkPath $netFile -LocalPath $localFile -Line $line -Header $script:JanetUsageHeader
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


## Resolve ToolsRoot with three-way fallback so ISE, dot-source, and shortcut
## launches all agree on where the workspace goes.
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
             elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
             else { (Get-Location).Path }

###########################
## TOP-OF-FILE CONSTANTS ##
###########################
## Change these in one place if the share moves or pool sizing changes.
$script:NemLogShare          = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs\ACAS_Nemesis'
$script:NemPoolMinThreads    = 1
$script:NemPoolMaxThreads    = 8
$script:NemOperationTimeoutS = 600    # per-target Invoke-Command timeout, seconds
$script:NemDrainIntervalMs   = 250    # UI log-drain timer cadence
$script:NemDrainTickCap      = 3      # v1.10.4: max job completions processed per drain tick

###############
## WORKSPACE ##
###############
$workspaceRoot = Join-Path $scriptDir 'ACASNemesis'
$localLogDir   = Join-Path $workspaceRoot 'Logs'
$csvDir        = Join-Path $workspaceRoot 'CSVImports'
foreach ($d in @($workspaceRoot, $localLogDir, $csvDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -Path $d -ItemType Directory -Force | Out-Null
    }
}

## v1.8.7: default Log4j replacement-jar source path — sits inside
## the Tools folder next to Nemesis itself, NOT one level up. The
## fleet convention is <JANET-root>\Tools\Packages\Log4j\NewFiles\,
## with Packages\ as a sibling of ACAS Nemesis Tool_*.ps1 inside
## Tools\. (v1.8.5 mistakenly went up one level.) Operator can
## override per-run via the "Log4j source:" textbox on the Updater
## tab. Matches WPT 6.5.4's same-named convention so a fleet that
## uses one path uses the same path in both tools. v1.8.6 staging
## interprets this as a CONTROLLER-side path and pushes the jars
## per-target over the WinRM session.
$global:NemLog4jDefaultSource = Join-Path $scriptDir 'Packages\Log4j\NewFiles'

######################################################
## $script:Nemesis state (populated in later tasks) ##
######################################################
$script:Nemesis = [ordered]@{
    ToolsRoot       = $scriptDir
    WorkspaceRoot   = $workspaceRoot
    LocalLogDir     = $localLogDir
    CsvDir          = $csvDir
    Config          = [pscustomobject]@{
        ToolVersion = $JanetACAS_NemesisVersion
        LogDir      = $null
        LogFile     = $null
        acasImport  = [pscustomobject]@{
            columnMappingProfiles = [pscustomobject]@{
                ACAS_Default = [pscustomobject]@{
                    dnsName    = 'DNS Name'
                    netbios    = 'NetBIOS Name'
                    ip         = 'IP Address'
                    pluginId   = 'Plugin'
                    pluginName = 'Plugin Name'
                    severity   = 'Severity'
                    cvssV3     = 'CVSS v3.0 Base Score'
                    cve        = 'CVE'
                    solution   = 'Steps to Remediate'
                    firstSeen  = 'First Discovered'
                    lastSeen   = 'Last Observed'
                }
            }
            activeProfile = 'ACAS_Default'
        }
    }
    Session         = @{
        Started     = $false
        Id          = $null
        StartedAt   = $null
        User        = $env:USERNAME
        Edipi       = $env:USERNAME   # replaced at entry point by Resolve-NemOperatorIdentity
        DisplayName = $env:USERNAME   # replaced at entry point
        FolderName  = $env:USERNAME   # "<edipi> - <DisplayName>" — replaced at entry point
    }
    Credentials     = $null
    Targets         = [System.Collections.ArrayList]::new()
    AcasFindings    = [System.Collections.ArrayList]::new()
    ## v1.10.0: lightweight import history for the Targets tab
    ## dashboard tile strip. Updated by the Import ACAS click handler;
    ## consumed by Refresh-NemTargetsTab.
    LastImportFile  = ''
    LastImportTime  = $null
    LastImportCount = 0
    Jobs            = @{}
    Pool            = $null
    UI              = @{ Theme = $null; Fonts = $null; Icons = $null; Form = $null; Controls = @{}; NavItems = @{} }
    LogQueue        = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
}

## Global scope is required — closures created inside tab-builder functions
## cannot resolve script-scope functions when the script is launched via
## `& '.\script.ps1'` from powershell.exe -Command. Global scope is always
## visible. See WPT pattern.
function global:Get-NemState { return $script:Nemesis }
function global:Get-NemPoolMin { return $script:NemPoolMinThreads }
function global:Get-NemPoolMax { return $script:NemPoolMaxThreads }
function global:Get-NemDrainInterval { return $script:NemDrainIntervalMs }
function global:Get-NemDrainCap { return $script:NemDrainTickCap }

#####################################################################
## BACKGROUND LOG WRITER (v1.10.5)                                 ##
#####################################################################
## Every AFNET-share file append (the per-session .log, the JANET
## detail/usage CSVs, the TouchedHosts CSV, the daily Runs CSV) used
## to run SYNCHRONOUSLY on the UI thread — most of them inside the
## drain timer Tick. A slow share merely lagged; a HUNG share froze
## the whole window solid (operator hit this through 1.10.1-1.10.4:
## "runs one then everything just freezes" — the first completion's
## log write blocked and never returned). Add-JanetCsvRow alone could
## burn ~15s of Start-Sleep retries on the calling thread.
##
## Fix: one dedicated background runspace owns ALL share I/O. The UI
## thread calls Add-NemLogWrite, which does nothing but enqueue a
## fully-resolved write request (pure string work) and return
## instantly. If the share hangs, the writer thread blocks and the
## queue grows — the UI stays completely responsive. Worst case on a
## dead share is delayed/dropped log lines, never a frozen tool.
$script:NemLogQueue       = $null    # ConcurrentQueue[hashtable]
$script:NemLogWriter      = $null    # @{ Runspace; PowerShell; Async; Stop }
$script:NemLogWriterTried = $false   # one-shot init guard

function global:Initialize-NemLogWriter {
    if ($script:NemLogWriter -or $script:NemLogWriterTried) { return }
    $script:NemLogWriterTried = $true
    try {
        $q    = New-Object 'System.Collections.Concurrent.ConcurrentQueue[hashtable]'
        $stop = [hashtable]::Synchronized(@{ Value = $false })

        $rs = [runspacefactory]::CreateRunspace()
        ## v1.10.6: do NOT set ThreadOptions=ReuseThread. A ReuseThread
        ## runspace parks its dedicated thread for reuse, and disposing it
        ## from inside the WinForms FormClosing handler hung the close
        ## (operator: "Close Tool ... still not closing the program").
        ## Default options + the IsBackground flip below + a flag-only
        ## Stop-NemLogWriter = a close path that cannot hang.
        $rs.Open()
        $rs.SessionStateProxy.SetVariable('NemQ',    $q)
        $rs.SessionStateProxy.SetVariable('NemStop', $stop)

        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript({
            ## v1.10.6: mark this writer thread as a BACKGROUND thread.
            ## A standalone Runspace runs its pipeline on a dedicated
            ## FOREGROUND thread (verified: IsBackground = $false), which
            ## keeps powershell.exe alive after the form closes. Flipping
            ## it to background means the OS abandons it the instant the
            ## UI thread exits, so the process always terminates — even
            ## if Stop-NemLogWriter never runs.
            try { [System.Threading.Thread]::CurrentThread.IsBackground = $true } catch {}

            ## Self-contained — a fresh runspace cannot see the script's
            ## functions, so the append routine is inlined here. Each job
            ## is @{ NetworkPath; LocalPath; Line; Header }. Header is
            ## written only when the target file is missing or empty.
            $writeOne = {
                param($job)
                $net    = [string]$job['NetworkPath']
                $local  = [string]$job['LocalPath']
                $line   = [string]$job['Line']
                $header = if ($job.ContainsKey('Header')) { [string]$job['Header'] } else { '' }

                $appendTo = {
                    param($path, $hdr, $ln)
                    $dir = Split-Path -Parent $path
                    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                        [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
                    }
                    if ($hdr) {
                        $needHdr = $true
                        if (Test-Path -LiteralPath $path) {
                            try { if (Get-Content -LiteralPath $path -TotalCount 1 -ErrorAction Stop) { $needHdr = $false } } catch {}
                        }
                        if ($needHdr) { Add-Content -LiteralPath $path -Value $hdr -Encoding UTF8 -ErrorAction Stop }
                    }
                    Add-Content -LiteralPath $path -Value $ln -Encoding UTF8 -ErrorAction Stop
                }

                $netOk = $false
                if ($net) {
                    for ($a = 1; $a -le 3; $a++) {
                        try { & $appendTo $net $header $line; $netOk = $true; break }
                        catch { Start-Sleep -Milliseconds (250 * $a) }
                    }
                }
                if (-not $netOk -and $local) {
                    try { & $appendTo $local $header $line } catch {}
                }
            }

            while ($true) {
                $job = $null
                if ($NemQ.TryDequeue([ref]$job)) {
                    if ($job) { try { & $writeOne $job } catch {} }
                } elseif ($NemStop['Value']) {
                    break
                } else {
                    Start-Sleep -Milliseconds 40
                }
            }
        })
        $async = $ps.BeginInvoke()

        $script:NemLogQueue  = $q
        $script:NemLogWriter = @{ Runspace = $rs; PowerShell = $ps; Async = $async; Stop = $stop }
    } catch {
        $script:NemLogQueue  = $null
        $script:NemLogWriter = $null
        try { Write-Host "[WARN] background log writer unavailable, falling back to synchronous writes: $($_.Exception.Message)" -ForegroundColor Yellow } catch {}
    }
}

function global:Add-NemLogWrite {
    <#
        Enqueue one file append for the background writer. NetworkPath is
        the primary target; LocalPath (optional) is the fallback the
        writer uses if the network append fails. Header (optional) is
        written only when the target file does not yet exist / is empty.
        Returns instantly — no I/O on the calling thread. Falls back to a
        synchronous best-effort write only if the writer runspace could
        not be created.
    #>
    [CmdletBinding()]
    param(
        [string] $NetworkPath = '',
        [string] $LocalPath   = '',
        [Parameter(Mandatory)] [string] $Line,
        [string] $Header      = ''
    )
    if (-not $script:NemLogWriter -and -not $script:NemLogWriterTried) { Initialize-NemLogWriter }
    if ($script:NemLogQueue) {
        $script:NemLogQueue.Enqueue(@{
            NetworkPath = $NetworkPath
            LocalPath   = $LocalPath
            Line        = $Line
            Header      = $Header
        })
        return
    }
    ## Writer infra unavailable — synchronous best-effort so logs are not
    ## lost outright. This path only runs if the runspace failed to start.
    try {
        if ($NetworkPath) {
            $d = Split-Path -Parent $NetworkPath
            if ($d -and -not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop) }
            if ($Header -and -not (Test-Path -LiteralPath $NetworkPath)) {
                Add-Content -LiteralPath $NetworkPath -Value $Header -Encoding UTF8 -ErrorAction Stop
            }
            Add-Content -LiteralPath $NetworkPath -Value $Line -Encoding UTF8 -ErrorAction Stop
            return
        }
    } catch {}
    if ($LocalPath) {
        try {
            $d2 = Split-Path -Parent $LocalPath
            if ($d2 -and -not (Test-Path -LiteralPath $d2)) { [void](New-Item -ItemType Directory -Path $d2 -Force -ErrorAction SilentlyContinue) }
            if ($Header -and -not (Test-Path -LiteralPath $LocalPath)) {
                Add-Content -LiteralPath $LocalPath -Value $Header -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            Add-Content -LiteralPath $LocalPath -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
    }
}

function global:Stop-NemLogWriter {
    <#
        Signal the background writer to stop and give the queue a bounded
        chance to flush. Called only from the form-close path (process
        shutdown). Idempotent.

        Deliberately does NOT dispose the runspace / PowerShell object:
        that teardown — particularly Runspace.Dispose() — could block the
        WinForms FormClosing handler and leave the window open ("Close
        Tool ... still not closing"). The writer runs on a BACKGROUND
        thread, so the OS reclaims it (and the runspace) the instant the
        process exits. Since this function only ever runs as part of
        shutdown, skipping the explicit dispose costs nothing.

        Worst case is bounded by $DrainTimeoutMs — the close can never
        hang on it, even against a dead share.
    #>
    [CmdletBinding()]
    param([int]$DrainTimeoutMs = 5000)
    if (-not $script:NemLogWriter) { return }
    $w = $script:NemLogWriter
    $q = $script:NemLogQueue
    ## Clear the handles up front: any late Add-NemLogWrite falls through
    ## to synchronous best-effort, and a re-entrant / safety-net call
    ## no-ops immediately.
    $script:NemLogWriter = $null
    $script:NemLogQueue  = $null

    ## Signal stop, then let the queue drain (bounded). The writer keeps
    ## dequeuing regardless of the flag, so everything already queued is
    ## still flushed; the flag just makes the loop exit once empty.
    try { $w.Stop['Value'] = $true } catch {}
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($q -and $q.Count -gt 0 -and $sw.ElapsedMilliseconds -lt $DrainTimeoutMs) {
            Start-Sleep -Milliseconds 50
        }
    } catch {}
}

## v1.10.1: Shared ToolTip singleton. The card builders were creating
## 2-3 fresh System.Windows.Forms.ToolTip per card; on a 9k-finding
## import that's hundreds of new Win32 tooltip HWNDs allocated in one
## synchronous burst (a major source of the UI freeze that 1.10.1 fixes).
## A single ToolTip can host any number of (control -> text) bindings
## via SetToolTip — same behaviour, one HWND.
function global:Get-NemSharedToolTip {
    $s = Get-NemState
    if (-not $s.UI.Controls.ContainsKey('sharedToolTip') -or -not $s.UI.Controls['sharedToolTip']) {
        $tt = New-Object System.Windows.Forms.ToolTip
        $tt.AutoPopDelay = 30000
        $tt.InitialDelay = 200
        $tt.ReshowDelay  = 200
        $tt.ShowAlways   = $true
        $s.UI.Controls['sharedToolTip'] = $tt
    }
    return $s.UI.Controls['sharedToolTip']
}

#####################################################################
## WPT-PORTED RELIABILITY HELPERS (v1.4.0)                         ##
## Mirror the patterns from WorkstationPatchingTool 6.2.6+ that    ##
## made bulk patching reliable on AFNET: TCP reachability probes   ##
## (5985/445) instead of ICMP, bounded PSSession options to keep   ##
## hung connects from blocking the runspace pool, Negotiate auth   ##
## so NTLM/Kerberos fall through correctly. Used by both the       ##
## outer dispatch (Start-NemVulnRun preflight, KB preflight) AND   ##
## inlined into runspace scriptblocks where global functions are   ##
## not visible.                                                    ##
#####################################################################

#####################################################################
## SERVER-EXCLUSION FILTER (v1.8.3)                                ##
## On AFNET, hostnames split by a 1-char prefix:                   ##
##   msek-<id>      = SERVER  (msek-as-03v, msek-fs-01v, ...)      ##
##   msekl-<id>     = laptop / workstation                         ##
##   msekt-<id>     = workstation                                  ##
##   msekw-<id>     = workstation                                  ##
## Servers are excluded from import — operator only patches end-   ##
## user endpoints from this tool. Server patching is handled       ##
## elsewhere (different change windows, different approval).      ##
#####################################################################
function global:Get-NemShortHost {
    <#
    .SYNOPSIS
        Normalize an ACAS-emitted hostname to the short (NetBIOS-style)
        name. Strips DOMAIN\ prefix and any DNS suffix from the first
        '.' onwards.
    .DESCRIPTION
        Tenable / ACAS CSV exports give us hostnames in three forms:
            "AREA52.AFNOAPPS.USAF.MIL\MSEKL-2701DZ"  (NetBIOS w/ domain)
            "msekl-2701dz.area52.afnoapps.usaf.mil" (DNS FQDN)
            "131.51.140.46"                          (IP)
        The first two surface in our Targets list and Updater cards as
        is, which is noisy and (per operator report v1.8.9) also tends
        to drive Kerberos failures on workstations whose AD SPN
        registration doesn't match the CSV's FQDN. Standardizing every
        host to its short name "msekl-2701dz" before the tool ever sees
        it lets WinRM Negotiate fall through to NTLM cleanly.

        Behavior:
          * "DOMAIN\HOST"          -> "HOST"
          * "host.fqdn.tld"        -> "host"
          * "10.0.0.5"             -> "10.0.0.5" (IPv4 untouched)
          * "host"                 -> "host"
          * empty / null           -> empty string
    #>
    [CmdletBinding()]
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim()
    ## Strip DOMAIN\ prefix.
    if ($n -match '\\') { $n = ($n -split '\\')[-1] }
    ## Leave IPv4 literals untouched — splitting on '.' would mangle them.
    if ($n -match '^\d+(\.\d+){3}$') { return $n }
    ## FQDN -> short. Take the first label only.
    if ($n -match '\.') { $n = ($n -split '\.', 2)[0] }
    return $n
}

function global:Test-NemIsServer {
    <#
    .SYNOPSIS
        Return $true when the supplied hostname matches a known server
        naming convention. Currently: anything starting with "msek-"
        (note: literal hyphen immediately after "msek", which is
        distinct from "msekl-" / "msekt-" / "msekw-" workstations).
    .DESCRIPTION
        Used at ACAS CSV import time to drop server findings before
        they ever land in AcasFindings or the Targets list. Pattern is
        deliberately specific to avoid false-positive workstation skips.
        Add additional patterns here when other server prefixes are
        identified.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $h = $HostName.Trim()
    ## Strip DOMAIN\ prefix from NetBIOS-style values.
    if ($h -match '\\') { $h = ($h -split '\\')[-1] }
    return ($h -match '^msek-')
}

function global:Test-NemTcpReachable {
    <#
    .SYNOPSIS
        TCP reachability probe — tries WinRM (5985) then SMB (445).
        Returns $true if either responds inside the per-port timeout.
    .DESCRIPTION
        ICMP is widely blocked on AFNET endpoints, so Test-Connection
        produces false negatives on hosts that are perfectly reachable
        for WinRM. WPT v47 switched to a TCP probe for the same reason
        (WPT 6.2.6 line 3936). This is the lift-and-shift of that probe.
    .PARAMETER Computer
        DNS name, NetBIOS name, or IP of the target.
    .PARAMETER TimeoutMs
        Per-port connect timeout. v1.8.4 bumped 1500 -> 3000 after a
        WPT-vs-Nemesis side-by-side showed slow-but-reachable AFNET
        hosts being false-negatived at 1.5s while WPT (no pre-probe,
        long WSMan OpenTimeout) eventually got through. 3s/port keeps
        the worst-case "definitely-dead host" wait at 6s while catching
        slower responders.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Computer,
        [int] $TimeoutMs = 3000
    )
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) {
                return $true
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}

function global:New-NemSessionOption {
    <#
    .SYNOPSIS
        Bounded PSSessionOption mirroring WPT 6.2.6 line 3954.
    .DESCRIPTION
        OpenTimeout 15s prevents the default ~3min hang on dead hosts.
        OperationTimeout 180s tolerates slow WUA scans / vendor updaters.
        IdleTimeout 60s cleans up the remote runspace if the local end
        crashes. CancelTimeout 5s lets Stop-NemRun() actually stop.
    #>
    return New-PSSessionOption `
        -OperationTimeout 180000 `
        -OpenTimeout      15000  `
        -CancelTimeout    5000   `
        -IdleTimeout      60000
}

function global:Invoke-NemRemote {
    <#
    .SYNOPSIS
        Open a bounded PSSession, run a scriptblock, tear down. Returns
        whatever the scriptblock returns. Catches all exceptions and
        returns a "FAIL: <reason>" string so callers never see a throw.
    .DESCRIPTION
        Used by outer-context callers (not runspace scriptblocks — those
        runspaces don't see this function). For runspace contexts the
        same pattern is inlined; see Start-NemVulnRun scriptblock.
        Performs TCP preflight first so we don't burn the WinRM
        OpenTimeout on a target that's offline.
    .PARAMETER Target
        Computer name, FQDN, or IP.
    .PARAMETER ScriptBlock
        The scriptblock to run on the remote.
    .PARAMETER ArgumentList
        Forwarded to Invoke-Command -ArgumentList.
    .PARAMETER Credential
        Optional PSCredential. When $null, ambient Kerberos is used.
    .PARAMETER Authentication
        WinRM auth scheme. Default 'Negotiate' — falls through Kerberos
        first then NTLM, matching WPT and SIM behavior.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]      $Target,
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [object[]]                           $ArgumentList,
        [System.Management.Automation.PSCredential] $Credential,
        [string] $Authentication = 'Negotiate'
    )
    if (-not (Test-NemTcpReachable -Computer $Target)) {
        return "FAIL: unreachable (TCP 5985/445)"
    }
    $sessArgs = @{
        ComputerName   = $Target
        SessionOption  = (New-NemSessionOption)
        Authentication = $Authentication
        ErrorAction    = 'Stop'
    }
    if ($Credential) { $sessArgs['Credential'] = $Credential }
    $sess = $null
    try {
        $sess = New-PSSession @sessArgs
    } catch {
        return "FAIL: Session - $($_.Exception.Message)"
    }
    try {
        $icArgs = @{ Session = $sess; ScriptBlock = $ScriptBlock; ErrorAction = 'Stop' }
        if ($ArgumentList) { $icArgs['ArgumentList'] = $ArgumentList }
        $out = Invoke-Command @icArgs
        if ($null -eq $out) { return 'OK (no output)' }
        return $out
    } catch {
        return "FAIL: $($_.Exception.Message)"
    } finally {
        if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
    }
}

## Closure-safe getters/setters for script-scope state read or written from
## inside .GetNewClosure() bodies. StrictMode 3 cannot reliably resolve
## $script:Foo through a captured closure; routing through a global function
## sidesteps the lookup mismatch.
function global:Get-NemInheritedJanet  { return $script:NemInheritedJanet }
function global:Get-NemResolvedLog     { return $script:NemResolvedLog }
function global:Get-NemClosingInFlight { return $script:NemClosingInFlight }
function global:Set-NemClosingInFlight { param($Value) $script:NemClosingInFlight = [bool]$Value }

## X-block flag. Initialized $false in the form builder; set $true only by
## the Close Tool button handler. The FormClosing handler cancels any close
## that arrives without the flag set (X, Alt-F4, right-click-close), except
## WindowsShutDown which is allowed through so the OS doesn't nag-prompt the
## operator. Removes the per-host snapshot churn from the rollup CSV by
## guaranteeing every session ends through Stop-JanetSession.
function global:Get-NemAllowClose { return $script:NemAllowClose }
function global:Set-NemAllowClose { param($Value) $script:NemAllowClose = [bool]$Value }

## v1.9.3: closure-safe getter for the JANET log share UNC. Top-level
## script constants like `$script:NemLogShare` cannot be read directly
## from inside `.GetNewClosure()` bodies under PS 5.1 + StrictMode 3
## (silently resolves to `$null` on some launch paths). The btnStart
## "logs unavailable" MessageBox was hitting that — it tried to print
## the share path and got an empty string. Same fix pattern as
## `Get-NemAllowClose`.
function global:Get-NemLogShare { return $script:NemLogShare }

function global:Invoke-NemCloseFlow {
    <#
    .SYNOPSIS
        Trigger the tool's close flow from any UI source.
    .DESCRIPTION
        v1.9.2 fix: both Close Tool buttons (top-right + sidebar) need to
        call Form.Close() to start the FormClosing handler that runs the
        submit-logs dialog. The earlier pattern was inline in the click
        handler closures:
            `$btn.Add_Click({
                Set-NemAllowClose `$true
                `$script:Nemesis.UI.Form.Close()
            }.GetNewClosure())
        Per the standing project rule, direct ``$script:`` access from
        inside .GetNewClosure() under StrictMode 3 is unreliable in PS
        5.1 — the resolution silently returns ``$null`` on some launch
        paths, so Form.Close() never fires. The flag DOES land (because
        Set-NemAllowClose is a global function), so the next time the
        operator clicks X the X-block sees the leftover flag and lets
        the close through with the popup. That's exactly the symptom
        the operator reported in 1.9.1: "Close Tool button doesn't
        work, but X works and shows the popup."
        Routing both buttons through this global helper sidesteps the
        closure-scope problem — Get-NemState resolves correctly from
        any context, and the helper is itself a global function so
        button-click closures only reference its name (no ``$script:``
        access from inside the closure).
    #>
    [CmdletBinding()]
    param()

    Set-NemAllowClose $true
    $s = Get-NemState
    if ($s -and $s.UI -and $s.UI.Form) {
        try { $s.UI.Form.Close() } catch {
            ## If Close() throws (rare — only seen during reentrancy),
            ## clear the flag so a subsequent X click doesn't slip
            ## through the X-block on stale state.
            Set-NemAllowClose $false
            try { Write-NemAudit -Action 'CloseFlow' -Result 'Failed' -Detail $_.Exception.Message } catch {}
        }
    } else {
        ## State not resolvable — clear the flag so X-block stays
        ## intact, then surface the failure to the operator log.
        Set-NemAllowClose $false
        try { Write-NemAudit -Action 'CloseFlow' -Result 'Failed' -Detail 'Form not resolvable from Get-NemState' } catch {}
    }
}

function global:Get-NemSelectedFindings {
    <#
    .SYNOPSIS
        Returns the findings that are currently checked (Select=true) in the
        Targets tab findings grid.  Falls back to ALL AcasFindings when the
        grid does not yet exist (e.g. before the UI is built), so callers are
        always safe to use this instead of $script:Nemesis.AcasFindings directly.
    #>
    [CmdletBinding()]
    param()

    $s = $script:Nemesis
    $grid = $s.UI.Controls['vulnsFindingsGrid']

    ## Grid not built yet (or no findings loaded) — return everything
    if (-not $grid -or $grid.Rows.Count -eq 0) {
        return $s.AcasFindings
    }

    $result = [System.Collections.ArrayList]::new()
    for ($ri = 0; $ri -lt $grid.Rows.Count; $ri++) {
        $chk = $grid.Rows[$ri].Cells['ColFSelect']
        if ($chk -and [bool]$chk.Value) {
            ## The Tag on the row holds the original finding object
            $orig = $grid.Rows[$ri].Tag
            if ($orig) { [void]$result.Add($orig) }
        }
    }
    return $result
}

function global:Get-NemProfileMatchTable {
    ## Shared keyword→profile rules used by the Updater card builder.
    ## Profiles is an array — first entry is the default choice, additional
    ## entries surface as a per-card dropdown so the operator can pick the
    ## variant to push (e.g., Force vs. User-Visible for Office).
    ## Add rows here when new AppUpdateProfiles are onboarded.
    return @(
        ## v1.10.8: hardening / unsupported-software remediations ported
        ## from WPT 6.5.20. These sit ABOVE the generic browser rules on
        ## purpose -- the Edge STIG finding's PluginName contains
        ## "EDGE-00-000022" and "MS_Edge_STIG", which would otherwise trip
        ## the generic 'Edge' keyword below and route to Edge-Update. The
        ## match loop is first-rule-wins, so the specific STIG rule must
        ## precede the generic one. MSXML + Unquoted Service Path don't
        ## collide with anything but are grouped here for clarity.
        @{ Keywords=@('EDGE-00-000022','Importing of search engine settings'); Profiles=@('Edge STIG - Disable Search Engine Import') }
        @{ Keywords=@('Unquoted Service Path');                                Profiles=@('Windows Unquoted Service Path - Remediate') }
        @{ Keywords=@('MSXML','XML Parser','XML Core Services');               Profiles=@('MSXML 4.0 - Uninstall') }
        ## v1.6.0: appended Software Center variants for Office / Chrome / Edge.
        ## Each card exposes its full Profiles array via the per-card dropdown
        ## (1.5.0 grouping logic groups vulns by the sorted-joined signature, so
        ## adding a profile shifts the GroupKey but does not change which vulns
        ## roll up together — Chrome stays one ROLLUP card, just with a 2-entry
        ## dropdown instead of a fixed single-profile label).
        @{ Keywords=@('Office','Microsoft 365','Excel','Word','PowerPoint','Outlook'); Profiles=@('Microsoft 365 - Force Update','Microsoft 365 - Force Update (SYSTEM task)','Microsoft 365 - Update (User Visible)','Microsoft 365 - Software Center') }
        @{ Keywords=@('Google Chrome','Chrome');                                       Profiles=@('Google Chrome - Update','Google Chrome - Software Center') }
        @{ Keywords=@('Microsoft Edge','Edge');                                        Profiles=@('Microsoft Edge - Update','Microsoft Edge - Software Center') }
        @{ Keywords=@('Windows Defender','Defender','Endpoint Protection');            Profiles=@('Windows Defender - Update Definitions') }
        ## v1.8.2: every "Apache Log4j" plugin variant (MitM 282519,
        ## XmlLayout 306549, SSL Hostname 306550, etc.) maps to the same
        ## profile. Get-NemVulnGroups groups by sorted-joined Profiles
        ## signature, so all Log4j plugins roll up onto ONE card —
        ## matching the operator's "group them all together" request.
        @{ Keywords=@('Apache Log4j','Log4j');                                         Profiles=@('Apache Log4j - Replace Vulnerable Jars') }
        ## v1.9.0: Tenable Nessus Agent vulnerabilities. Plugin names
        ## are typically "Tenable Nessus Agent < X.Y.Z" or "Nessus Agent
        ## RCE". Routes to the PSADT package-deploy profile which copies
        ## Tools\Packages\NIPR_Tenable Nessus Agent_X.Y.Z\ to the target
        ## and runs Deploy-Application.ps1.
        @{ Keywords=@('Tenable Nessus Agent','Nessus Agent','Tenable Nessus');         Profiles=@('Tenable Nessus Agent - Package Deploy') }
        ## Added 2026-06-02: Oracle Java SE CPU vulnerabilities (the
        ## quarterly "Oracle Java SE Multiple Vulnerabilities ... CPU"
        ## plugin family — 9 plugin variants covering 2024-2026 CPUs,
        ## ~719 findings on the operator's most recent ACAS export).
        ## Oracle's direct download is SSO-gated, so the practical push
        ## is via MECM Software Center; operators with a Java app
        ## published to SC can now route Oracle Java CPUs to the
        ## Updater tab instead of the Not Updatable tab.
        @{ Keywords=@('Oracle Java','Oracle JRE','Java SE Multiple Vulnerabilities'); Profiles=@('Oracle Java - Software Center') }
    )
}

function global:Get-NemVulnGroups {
    <#
    .SYNOPSIS
        Group operator-selected ACAS findings by plugin name and resolve each
        group's matched App Update profile + affected host set.

    .DESCRIPTION
        Card-based Updater uses this to build one card per vulnerability.
        Each group is pushed ONLY to its own host list — no all-hosts
        fallback. Groups with no profile match are still returned so the UI
        can surface coverage gaps (card Run is disabled for those).

        Each output object now includes a Category field:
          'Unpatchable'  — manual remediation required (Log4j, Oracle, CPU vuln)
          'Reboot'       — Windows Update Reboot Required finding
          'Experimental' — MS Store / Defender Definition findings needing test-first
          'Patchable'    — has matched ProfileNames, standard automated run
          'NotUpdatable' — no profile match, unclassified
        Priority: Unpatchable > Reboot > Experimental > Patchable > NotUpdatable.
    #>
    [CmdletBinding()]
    param()

    $findings = @(Get-NemSelectedFindings)
    if ($findings.Count -eq 0) { return @() }

    $matchTable = Get-NemProfileMatchTable
    $sevRank = @{ 'critical' = 5; 'high' = 4; 'medium' = 3; 'low' = 2; 'info' = 1 }

    ## Classification helper — returns category string + optionally overrides ProfileNames.
    ## Returns a hashtable: @{ Category = '...'; ProfileOverride = $null -or @(...) }
    $classifyPlugin = {
        param([string]$PluginName)

        ## --- Unpatchable patterns (first match wins over everything) ---
        ## v1.8.2: 'Log4j' removed — now mapped to the
        ## 'Apache Log4j - Replace Vulnerable Jars' profile via
        ## Get-NemProfileMatchTable (HID + Adobe lib path swap, ported
        ## from WPT 6.4.2). Plugin variants (282519 MitM, 306549
        ## XmlLayout, 306550 SSL Hostname) all roll up to one card.
        $unpatchPatterns = @('Oracle Database','Speculative Execution','Intel BHI','Spectre','Meltdown','ZombieLoad')
        foreach ($pat in $unpatchPatterns) {
            if ($PluginName.IndexOf($pat, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return @{ Category = 'Unpatchable'; ProfileOverride = $null }
            }
        }

        ## --- Reboot patterns ---
        $isRebootExplicit = ($PluginName.IndexOf('Windows Update Reboot Required', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $isRebootGeneric  = (($PluginName.IndexOf('Reboot',    [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -and
                             ($PluginName.IndexOf('Required',  [System.StringComparison]::OrdinalIgnoreCase) -ge 0))
        if ($isRebootExplicit -or $isRebootGeneric) {
            return @{ Category = 'Reboot'; ProfileOverride = $null }
        }

        ## --- Experimental patterns ---
        $hasWindowsApp = ($PluginName.IndexOf('Windows App', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasRce        = ($PluginName.IndexOf('RCE',         [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasCve        = ($PluginName.IndexOf('CVE-',        [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        if ($hasWindowsApp -and ($hasRce -or $hasCve)) {
            return @{ Category = 'Experimental'; ProfileOverride = @('Microsoft Store - Update Apps') }
        }

        $hasDefender = ($PluginName.IndexOf('Defender', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasCheck    = ($PluginName.IndexOf('Check',    [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasSigDef   = ($PluginName.IndexOf('Signature Definition', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        if ($hasDefender -and ($hasCheck -or $hasSigDef)) {
            return @{ Category = 'Experimental'; ProfileOverride = $null }
        }

        ## Caller resolves Patchable vs NotUpdatable based on ProfileNames count.
        return @{ Category = $null; ProfileOverride = $null }
    }

    $groups = [ordered]@{}

    foreach ($row in $findings) {
        $plugin = if ($row.PSObject.Properties['PluginName'] -and $row.PluginName) { [string]$row.PluginName } else { '' }
        if ([string]::IsNullOrWhiteSpace($plugin)) { continue }

        $key = $plugin.ToLowerInvariant()

        if (-not $groups.Contains($key)) {
            ## Classify the plugin before the keyword-match loop so Experimental
            ## patterns can override ProfileNames before the table lookup runs.
            $classResult = & $classifyPlugin $plugin
            $forcedCategory  = $classResult.Category
            $profileOverride = $classResult.ProfileOverride

            ## First time we see this plugin — resolve its matched profile(s).
            $matchedList = @()
            if ($profileOverride -ne $null) {
                ## Experimental pattern supplied a forced profile list.
                $matchedList = @($profileOverride)
            } elseif ($forcedCategory -ne 'Unpatchable' -and $forcedCategory -ne 'Reboot') {
                ## Standard keyword-match only for non-classified plugins.
                foreach ($rule in $matchTable) {
                    foreach ($kw in $rule.Keywords) {
                        if ($plugin.IndexOf($kw, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $matchedList = @($rule.Profiles); break
                        }
                    }
                    if ($matchedList.Count -gt 0) { break }
                }
            }

            ## Resolve final Category.
            $finalCategory = $forcedCategory
            if (-not $finalCategory) {
                if ($matchedList.Count -gt 0) { $finalCategory = 'Patchable' }
                else                          { $finalCategory = 'NotUpdatable' }
            }

            $groups[$key] = [pscustomobject]@{
                PluginKey    = $key
                DisplayName  = $plugin
                Severity     = ''
                Category     = $finalCategory
                ProfileNames = $matchedList
                Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Cves         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                _sevRank     = 0
            }
        }
        $g = $groups[$key]

        ## Resolve host: DNS > NetBIOS (DOMAIN\ stripped) > IP
        $h = $null
        if ($row.PSObject.Properties['DnsName'] -and $row.DnsName) {
            $h = [string]$row.DnsName
        } elseif ($row.PSObject.Properties['NetBios'] -and $row.NetBios) {
            $nb = [string]$row.NetBios
            if ($nb -match '\\') { $nb = ($nb -split '\\')[-1] }
            $h = $nb
        } elseif ($row.PSObject.Properties['IpAddress'] -and $row.IpAddress) {
            $h = [string]$row.IpAddress
        }
        if ($h) { [void]$g.Hosts.Add($h) }

        ## Track highest severity seen in this group.
        $sev = if ($row.PSObject.Properties['Severity'] -and $row.Severity) { [string]$row.Severity } else { '' }
        $rank = 0
        if ($sev) {
            $sk = $sev.ToLowerInvariant()
            if ($sevRank.ContainsKey($sk)) { $rank = $sevRank[$sk] }
        }
        if ($rank -gt $g._sevRank) {
            $g._sevRank = $rank
            $g.Severity = $sev
        }

        ## Collect CVEs.
        if ($row.PSObject.Properties['Cve'] -and $row.Cve) {
            foreach ($c in ([string]$row.Cve -split '[,;\s]+')) {
                if ($c) { [void]$g.Cves.Add($c.Trim()) }
            }
        }
    }

    ## Flatten + sort: category bucket first (Patchable < Experimental < Reboot < rest),
    ## then severity desc, then host count desc, then name asc.
    $catOrder = @{ 'Patchable' = 0; 'Experimental' = 1; 'Reboot' = 2; 'Unpatchable' = 3; 'NotUpdatable' = 4 }
    $flat = @()
    foreach ($key in $groups.Keys) {
        $g = $groups[$key]
        $catRank = 99
        if ($catOrder.ContainsKey($g.Category)) { $catRank = $catOrder[$g.Category] }
        $flat += [pscustomobject]@{
            PluginKey    = $g.PluginKey
            DisplayName  = $g.DisplayName
            Severity     = $g.Severity
            Category     = $g.Category
            SevRank      = $g._sevRank
            CatRank      = $catRank
            ProfileNames = @($g.ProfileNames)
            Hosts        = @(@($g.Hosts) | Sort-Object)
            HostCount    = $g.Hosts.Count
            Cves         = @(@($g.Cves) | Sort-Object)
        }
    }
    return @($flat | Sort-Object -Property `
        @{Expression = 'CatRank';     Descending = $false}, `
        @{Expression = 'SevRank';     Descending = $true}, `
        @{Expression = 'HostCount';   Descending = $true}, `
        @{Expression = 'DisplayName'; Descending = $false})
}

function global:Get-NemVulnGroupingKey {
    <#
    .SYNOPSIS
        Compute the rollup-grouping signature for a vuln group object.
    .DESCRIPTION
        Two vulns share a card if they would route to the exact same set
        of updater profiles. The signature is the sorted, joined profile
        names — preserves multi-profile cases (Office) without crossing
        into single-profile families (Chrome).
        Returns $null for vulns that should NEVER be grouped (Reboot,
        Unpatchable, NotUpdatable, no-profile). Those render as their own
        individual cards.
    #>
    param($Vuln)
    if (-not $Vuln) { return $null }
    if ($Vuln.PSObject.Properties['Category']) {
        $cat = [string]$Vuln.Category
        if ($cat -eq 'Reboot' -or $cat -eq 'Unpatchable' -or $cat -eq 'NotUpdatable') {
            return $null
        }
    }
    $names = @($Vuln.ProfileNames)
    if ($names.Count -eq 0) { return $null }
    return (($names | Sort-Object) -join '||')
}

function global:Get-NemVulnCardEntries {
    <#
    .SYNOPSIS
        Take Get-NemVulnGroups output and roll up cards that share an
        updater-profile signature into single synthetic group entries.
    .DESCRIPTION
        Each "group" entry is a synthetic Vuln pscustomobject with the
        same shape as a real vuln plus three extra fields:
          IsGroup       = $true
          GroupKey      = profile signature (sorted-joined names)
          GroupMembers  = array of original real vuln objects
        The synthetic vuln is what the card renderer + Run/Verify
        dispatch use. Audit fan-out happens at Write-NemRunSummary by
        unrolling GroupMembers into N CSV rows.
        Returns the same array shape Update-NemVulnCards already
        consumes — group entries and ungrouped real vulns intermixed,
        sorted by the same CatRank/SevRank ordering.
    #>
    [CmdletBinding()]
    param()

    $all = @(Get-NemVulnGroups)
    if ($all.Count -eq 0) { return @() }

    $sevRank = @{ 'critical' = 5; 'high' = 4; 'medium' = 3; 'low' = 2; 'info' = 1 }
    $catOrder = @{ 'Patchable' = 0; 'Experimental' = 1; 'Reboot' = 2; 'Unpatchable' = 3; 'NotUpdatable' = 4 }

    ## Bucket: each profile-signature -> array of member vulns.
    ## Vulns with no signature (Reboot/Unpatchable/etc.) pass through.
    $buckets   = [ordered]@{}
    $passThru  = [System.Collections.ArrayList]::new()
    foreach ($v in $all) {
        $key = Get-NemVulnGroupingKey -Vuln $v
        if (-not $key) {
            [void]$passThru.Add($v)
            continue
        }
        if (-not $buckets.Contains($key)) {
            $buckets[$key] = [System.Collections.ArrayList]::new()
        }
        [void]$buckets[$key].Add($v)
    }

    ## Build synthetic group vulns. A bucket of size 1 stays ungrouped —
    ## no point rolling up a single vuln (loses Plugin Name in the card
    ## header for zero gain).
    $entries = [System.Collections.ArrayList]::new()
    foreach ($v in $passThru) { [void]$entries.Add($v) }

    foreach ($key in $buckets.Keys) {
        $members = @($buckets[$key])
        if ($members.Count -le 1) {
            foreach ($v in $members) { [void]$entries.Add($v) }
            continue
        }

        ## Roll up display name from the shared profile family.
        $profileNames = @($members[0].ProfileNames)
        $primaryProfile = $profileNames[0]
        ## Strip the trailing " - Update" / " - Force Update" / etc. for
        ## a clean header. If nothing strips, keep the full profile name.
        $family = $primaryProfile -replace '\s*-\s*(Update.*|Force Update.*)$',''
        if (-not $family) { $family = $primaryProfile }

        ## Severity = worst across members. Get-NemVulnGroups flattens
        ## the internal _sevRank to SevRank in its output, so read that.
        $maxSevRank = 0
        $maxSevText = ''
        foreach ($m in $members) {
            $r = 0
            if ($m.PSObject.Properties['SevRank']) { $r = [int]$m.SevRank }
            if ($r -gt $maxSevRank) {
                $maxSevRank = $r
                $maxSevText = [string]$m.Severity
            }
        }

        ## Host union across all members.
        $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $members) {
            foreach ($h in @($m.Hosts)) {
                if ($h) { [void]$hostSet.Add([string]$h) }
            }
        }

        ## CVE union (deduped) for hover/tooltip use.
        $cveSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $members) {
            foreach ($c in @($m.Cves)) {
                if ($c) { [void]$cveSet.Add([string]$c) }
            }
        }

        ## Category = take the worst (lowest CatRank wins per the existing
        ## priority). All members in a group should share Category since
        ## Reboot/Unpatchable bail out of grouping above, but be defensive.
        $catRank = 99
        $cat     = 'Patchable'
        foreach ($m in $members) {
            $mc = if ($m.PSObject.Properties['Category']) { [string]$m.Category } else { '' }
            $mr = 99
            if ($catOrder.ContainsKey($mc)) { $mr = $catOrder[$mc] }
            if ($mr -lt $catRank) {
                $catRank = $mr
                $cat     = $mc
            }
        }

        $synthetic = [pscustomobject]@{
            PluginKey    = "__group__::$key"
            DisplayName  = "$family  -  $($members.Count) vulns"
            Severity     = $maxSevText
            Category     = $cat
            SevRank      = $maxSevRank
            CatRank      = $catRank
            ProfileNames = @($profileNames)
            Hosts        = @(@($hostSet) | Sort-Object)
            HostCount    = $hostSet.Count
            Cves         = @(@($cveSet) | Sort-Object)
            IsGroup      = $true
            GroupKey     = $key
            GroupMembers = $members
        }
        [void]$entries.Add($synthetic)
    }

    ## Same sort order Get-NemVulnGroups uses, so display ordering is
    ## stable whether the operator's view is grouped or not.
    return @($entries | Sort-Object -Property `
        @{Expression = { if ($_.PSObject.Properties['CatRank']) { $_.CatRank } else { 99 } }; Descending = $false}, `
        @{Expression = { if ($_.PSObject.Properties['SevRank']) { $_.SevRank } else { 0  } }; Descending = $true}, `
        @{Expression = 'HostCount';   Descending = $true}, `
        @{Expression = 'DisplayName'; Descending = $false})
}

function Import-NemJanetCredential {
    <#
        Pull the launcher-shared credential from J.A.N.E.T. if available.
        JANET.ps1 exports a PSCredential via Export-Clixml and sets the
        JANET_CRED_FILE env var on the child process. We Import-Clixml it
        into $script:Nemesis.Credentials so the operator doesn't have to
        re-enter them here.
        Returns $true if creds were inherited, $false otherwise.
    #>
    [CmdletBinding()]
    param()
    $path = $env:JANET_CRED_FILE
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $cred = Import-Clixml -LiteralPath $path
        if ($cred -is [System.Management.Automation.PSCredential]) {
            $script:Nemesis['Credentials'] = $cred
            return $true
        }
    } catch {
        ## fall through to $false
    }
    return $false
}

###########
## THEME ##
###########
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
    $script:Nemesis.UI.Theme = [pscustomobject]@{
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

    $script:Nemesis.UI.Fonts = [pscustomobject]@{
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
    $script:Nemesis.UI.Icons = [pscustomobject]@{
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

##############
## CONTROLS ##
##############
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Location    = New-Object System.Drawing.Point($X, $Y)
    $n.Size        = New-Object System.Drawing.Size($W, $H)
    $n.Minimum     = $Min
    $n.Maximum     = $Max
    $n.Value       = $Value
    $n.BackColor   = $theme.Input
    $n.ForeColor   = $theme.TextPrimary
    $n.BorderStyle = 'FixedSingle'
    $n.Font        = $script:Nemesis.UI.Fonts.Mono
    return $n
}

function New-WptListBox {
    [CmdletBinding()]
    param(
        [int]$X = 0, [int]$Y = 0, [int]$W = 300, [int]$H = 200
    )
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
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
        this generically via the $script:Nemesis.UI.Controls cleanup loop).

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
    $theme = $script:Nemesis.UI.Theme
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
    $theme = $script:Nemesis.UI.Theme
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
    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts

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
    $theme = $script:Nemesis.UI.Theme
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
    $theme = $script:Nemesis.UI.Theme
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

#####################
## ACAS CSV IMPORT ##
#####################
<#
.SYNOPSIS
    ACAS/Tenable CSV import with configurable column mapping.

.DESCRIPTION
    Minimal Phase 1 stub that replaces the legacy regex-based CSV reader with a
    proper Import-Csv + column-mapping approach. Phase 2 adds the vulnerability
    triage grid, patch predictor, and compliance export on top of this.

    The column mapping comes from $Config.acasImport.columnMappingProfiles.
    The user picks an active profile (default: ACAS_Default). If the CSV has
    additional columns, they're preserved in the Extras hashtable.

    Two public functions:
      * Import-WptAcasCsv         - read the CSV, return normalized rows
      * Get-WptAcasTargetHosts    - extract unique target hostnames (DNS > NetBIOS > IP)
#>

function Import-WptAcasCsv {
    <#
    .SYNOPSIS
        Parse an ACAS/Tenable/Nessus CSV using the active column mapping profile.

    .PARAMETER Path
        CSV file on disk.

    .PARAMETER ProfileName
        Optional override; defaults to Config.acasImport.activeProfile.

    .OUTPUTS
        Array of PSCustomObject rows with fields:
            DnsName, NetBios, IpAddress, PluginId, PluginName, Severity,
            CvssV3, Cve, Solution, FirstSeen, LastSeen, RawRow
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ProfileName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "ACAS import: file not found: $Path"
    }

    $cfg = $script:Nemesis.Config.acasImport
    if (-not $ProfileName) { $ProfileName = $cfg.activeProfile }
    $map = $cfg.columnMappingProfiles.$ProfileName
    if (-not $map) {
        throw "ACAS import: column mapping profile '$ProfileName' not found in config."
    }

    $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop
    if (-not $rows -or $rows.Count -eq 0) {
        return @()
    }

    ## Helper to safely pull a column by its mapped name. Missing columns become empty strings.
    $getCol = {
        param($row, $colName)
        if (-not $colName) { return '' }
        $p = $row.PSObject.Properties[$colName]
        if ($p) { return [string]$p.Value }
        return ''
    }

    ## v1.8.9: ACAS CSVs ship hostnames in three forms — `DOMAIN\HOST`
    ## in the NetBIOS column, `host.fqdn.tld` in the DNS column, IPv4
    ## in the IP column. The DNS form is preferred downstream
    ## (Get-NemVulnGroups picks DnsName first), so the FQDN ends up
    ## driving every WinRM connect, audit row, log line, and card host
    ## list. Operator report: that produces noisy UI ("...area52
    ## .afnoapps.usaf.mil" everywhere) and correlates with Negotiate
    ## auth failures on hosts whose AD SPN registration doesn't match
    ## the FQDN. Normalize at import time so the rest of the tool
    ## never sees the long forms.
    $out = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($r in $rows) {
        $out.Add([pscustomobject]@{
            DnsName    = Get-NemShortHost ((& $getCol $r $map.dnsName).Trim())
            NetBios    = Get-NemShortHost ((& $getCol $r $map.netbios).Trim())
            IpAddress  = (& $getCol $r $map.ip).Trim()
            PluginId   = (& $getCol $r $map.pluginId).Trim()
            PluginName = (& $getCol $r $map.pluginName).Trim()
            Severity   = (& $getCol $r $map.severity).Trim()
            CvssV3     = (& $getCol $r $map.cvssV3).Trim()
            Cve        = (& $getCol $r $map.cve).Trim()
            Solution   = (& $getCol $r $map.solution).Trim()
            FirstSeen  = (& $getCol $r $map.firstSeen).Trim()
            LastSeen   = (& $getCol $r $map.lastSeen).Trim()
            RawRow     = $r
        })
    }
    return $out.ToArray()
}

function Get-WptAcasTargetHosts {
    <#
    .SYNOPSIS
        Extract unique target hostnames from parsed ACAS rows.

    .DESCRIPTION
        Picks DNS Name first (best), NetBIOS second, IP address third (worst).
        Deduplicates. Drops rows with no identifiable target.

        Used by the Targets tab's "Import ACAS CSV" button.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Rows)

    $set = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        $pick = $null
        if     ($r.DnsName)   { $pick = $r.DnsName }
        elseif ($r.NetBios)   { $pick = $r.NetBios }
        elseif ($r.IpAddress) { $pick = $r.IpAddress }
        if ($pick) { [void]$set.Add($pick) }
    }
    ## Return the hostnames as a plain array. The original `,@($set)`
    ## double-wrapped multi-element results: PS unrolled the outer array
    ## once, delivering the INNER array as a single pipeline item, so the
    ## caller's @() collected 1 element whose value was the whole list.
    ## `[string[]]$hosts` then stringified that inner array into one
    ## space-joined blob -> "1 target(s) loaded" shown space-separated.
    ## Plain `@($set)` emits each hostname as its own item; caller's @()
    ## handles 0/1/N correctly.
    return @($set)
}

function Get-WptAcasFindingsForHost {
    <#
    .SYNOPSIS
        Return the ACAS rows that apply to a single hostname.

    .DESCRIPTION
        Used by App Updater (and any future tab) to cross-reference the
        imported ACAS findings against a specific target. Matches
        case-insensitively on DnsName, NetBios, or IpAddress. To bridge
        FQDN-vs-short-name mismatches (operator TXT lists are typically
        short; ACAS CSV rows are typically FQDN), a second pass compares
        the short forms (everything before the first '.').

        Returns @() when rows are null/empty or hostname is blank, never
        $null -- so `.Count` is always safe on the result.

    .PARAMETER HostName
        Target workstation name as the operator knows it.

    .PARAMETER Rows
        Array of rows previously returned by Import-WptAcasCsv. Typically
        $script:Nemesis.AcasFindings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$HostName,
        [object[]]$Rows
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return @() }
    if ([string]::IsNullOrWhiteSpace($HostName)) { return @() }

    $h      = $HostName.Trim()
    $hShort = $h.Split('.')[0]

    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        ## Import-WptAcasCsv always sets these as [string] via .Trim(), so
        ## they exist on every row (StrictMode=3 safe). They may be empty.
        $dns = if ($r.DnsName)   { $r.DnsName }   else { '' }
        $nb  = if ($r.NetBios)   { $r.NetBios }   else { '' }
        $ip  = if ($r.IpAddress) { $r.IpAddress } else { '' }

        $match = $false
        if     ($dns -and ($dns -ieq $h))  { $match = $true }
        elseif ($nb  -and ($nb  -ieq $h))  { $match = $true }
        elseif ($ip  -and ($ip  -ieq $h))  { $match = $true }
        else {
            ## FQDN-vs-short fallback. '.Split(".")[0]' on a bare short
            ## name returns the name unchanged, so this also covers
            ## short-vs-short matches where the exact test above missed
            ## due to trailing whitespace already stripped at import.
            $dnsShort = if ($dns) { $dns.Split('.')[0] } else { '' }
            $nbShort  = if ($nb)  { $nb.Split('.')[0]  } else { '' }
            if     ($dnsShort -and ($dnsShort -ieq $hShort)) { $match = $true }
            elseif ($nbShort  -and ($nbShort  -ieq $hShort)) { $match = $true }
        }
        if ($match) { [void]$list.Add($r) }
    }
    return $list.ToArray()
}

#########################
## APP UPDATE PROFILES ##
#########################
<#
.SYNOPSIS
    App Updater profile registry - shared between the App Updater tab and
    the ACAS Remediation tab.

.DESCRIPTION
    Each profile carries:
      * Desc   - human-readable one-liner shown near the profile dropdown
      * Script - scriptblock run remotely on each target via Invoke-Command
      * Verify - optional scriptblock that queries current version +
                 last-updated timestamp (returns hashtable with Version,
                 LastUpdated, Verified, Detail). Null for profiles where
                 verification is not meaningful.

    The profiles used to live inline inside Add-WptAppUpdaterTab. Moving
    them here lets the ACAS Remediation tab run the same profile against
    a host subset without duplicating scriptblocks.

    Note: "Custom Command" in the App Updater combo is NOT in this
    registry -- it's a free-form textbox handled separately by the tab.
    Only profiles with a fixed Script live here (currently five).

    Consumers:
      * Get-WptAppUpdateProfiles       - full hashtable (read-only use only)
      * Get-WptAppUpdateProfile -Name  - single profile, $null if unknown
      * Get-WptAppUpdateProfileNames   - string[] of names for combo boxes
#>

## Module-scoped registry. Populated at dot-source time; never mutated at
## runtime (consumers treat it as read-only).
$script:WptAppUpdateProfiles = @{
    'Microsoft 365 - Force Update' = @{
        Desc = 'OfficeC2RClient.exe /update user -- silent, force close apps'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user','/displaylevel=false','/forceappshutdown=true' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version = 'n/a'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = "Scenario=$($p.LastScenario)" }
        }
    }
    'Microsoft 365 - Update (User Visible)' = @{
        Desc = 'OfficeC2RClient.exe /update user -- shows progress to user'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version = 'n/a'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = "Scenario=$($p.LastScenario)" }
        }
    }
    'Microsoft 365 - Force Update (SYSTEM task)' = @{
        Desc = 'Scheduled task runs OfficeC2RClient.exe as SYSTEM with /forceappshutdown=true. Fallback when operator-context runs fail (open sessions, Kerberos, delegation).'
        Script = {
            $exe = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $exe)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $arguments = '/update user /displaylevel=false /forceappshutdown=true'
            $taskName  = 'AcasNemesis_OfficeC2R_Update'

            try {
                ## Clean up any stale task from a prior run.
                $stale = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($stale) {
                    try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                }

                $action  = New-ScheduledTaskAction -Execute $exe -Argument $arguments
                ## Trigger far future - we will Start-ScheduledTask manually below.
                $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(10))
                [void](Register-ScheduledTask -Action $action -Trigger $trigger `
                    -TaskName $taskName -User 'System' -RunLevel Highest -ErrorAction Stop)

                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

                ## Poll up to 10 min for task to finish (State returns to Ready).
                $deadline = (Get-Date).AddMinutes(10)
                $elapsed  = 0
                $stillRunning = $true
                while ((Get-Date) -lt $deadline) {
                    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if (-not $t) { $stillRunning = $false; break }
                    if ($t.State -eq 'Ready') { $stillRunning = $false; break }
                    Start-Sleep -Seconds 5
                    $elapsed += 5
                }

                ## Clean up regardless of outcome.
                try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch {}

                if ($stillRunning) {
                    return "FAIL: SYSTEM task still running after 600s (unregistered)"
                }
                return "OK (SYSTEM task completed in ${elapsed}s)"
            } catch {
                ## Best-effort cleanup on error.
                try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                return "FAIL: $($_.Exception.Message)"
            }
        }
        Verify = {
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version = 'n/a'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = "Scenario=$($p.LastScenario); SYSTEM-task variant" }
        }
    }
    'Windows Defender - Update Definitions' = @{
        Desc = 'Update-MpSignature -- pulls latest Defender definitions'
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
                ## Defender signatures ship every few hours; anything > 24h stale is suspect.
                $verified = if ($last) { ((Get-Date) - $last).TotalHours -lt 24 } else { $false }
                return @{ Version = $ver; LastUpdated = $lastStr; Verified = $verified; Detail = "Engine=$($def.AMEngineVersion)" }
            } catch {
                return @{ Version = 'error'; LastUpdated = 'n/a'; Verified = $false; Detail = $_.Exception.Message }
            }
        }
    }
    'Google Chrome - Update' = @{
        Desc = 'GoogleUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'
            if (-not (Test-Path $exe)) { $exe = 'C:\Program Files\Google\Update\GoogleUpdate.exe' }
            if (-not (Test-Path $exe)) { return 'FAIL: GoogleUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Chrome update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            ## Chrome version lives under the BrowserReplacement GUID. Check
            ## both 32- and 64-bit registry views for servers / x64 images.
            $guid = '{8A69D345-D564-463c-AFF1-A69D9E530F96}'
            $paths = @(
                "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\$guid"
                "HKLM:\SOFTWARE\Google\Update\Clients\$guid"
            )
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
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = '' }
        }
    }
    'Microsoft Edge - Update' = @{
        Desc = 'MicrosoftEdgeUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
            if (-not (Test-Path $exe)) { return 'FAIL: MicrosoftEdgeUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Edge update triggered, exit $($proc.ExitCode))"
        }
        Verify = {
            $guid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
            $paths = @(
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid"
                "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid"
            )
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
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = '' }
        }
    }
    'Microsoft Store - Update Apps' = @{
        Desc = 'Trigger a Microsoft Store update scan (EXPERIMENTAL). Covers Windows App (Remote Desktop) and other MS-Store apps.'
        Script = {
            try {
                $obj = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
                                       -ClassName  'MDM_EnterpriseModernAppManagement_AppManagement01' `
                                       -ErrorAction Stop
                if (-not $obj) { return 'FAIL: MDM AppManagement CIM class not available' }
                [void]($obj | Invoke-CimMethod -MethodName 'UpdateScanMethod' -ErrorAction Stop)
                return 'OK (Store UpdateScanMethod triggered)'
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
        }
        Verify = {
            ## Look up the installed Windows App package (Microsoft.Windows.WindowsApp)
            ## and report its version. This is the specific target of the RCE finding.
            try {
                $pkg = Get-AppxPackage -AllUsers -Name 'Microsoft.WindowsApp*' -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                if (-not $pkg) {
                    return @{ Version = 'not installed'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Microsoft.WindowsApp package not found' }
                }
                $ver = "$($pkg.Version)"
                $inst = Get-Item -Path $pkg.InstallLocation -ErrorAction SilentlyContinue
                $mod = if ($inst) { $inst.LastWriteTime } else { $null }
                $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
                ## Experimental: >14d staleness isn't a hard fail — just a hint.
                $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 14 } else { $null }
                return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = 'EXPERIMENTAL' }
            } catch {
                return @{ Version = 'error'; LastUpdated = 'n/a'; Verified = $false; Detail = $_.Exception.Message }
            }
        }
    }

    ## ---------------------------------------------------------------------
    ## Software Center variants (v1.6.0). Trigger an Install on the matching
    ## CCM_Application object via the SCCM client SDK. Same engine WPT uses
    ## in its bulk-patch / SCCM App Manager paths, lifted here as named
    ## update profiles so each per-vuln (or rolled-up) Updater card can pick
    ## EXE-direct vs Software Center via its profile dropdown.
    ##
    ## Behavior on edge cases:
    ##   - SCCM client absent -> returns 'FAIL: SCCM client not present'
    ##   - No matching app in catalog -> returns 'SKIP: No matching app...'
    ##   - Matching app is NotApplicable -> returns 'SKIP: ... not Applicable'
    ##   - Install method throws -> returns 'FAIL: <err>'
    ## SKIP rows are surfaced in the per-host log but DO NOT count as
    ## failures (the operator chose Software Center as a deliberate
    ## alternative; missing catalog entry is informational, not a defect).
    ##
    ## Verify: reuse the EXE-direct profile's Verify scriptblock — the
    ## install location / registry version is mechanism-agnostic. (We
    ## inline a copy here rather than referencing the other profile's
    ## scriptblock by name; remote sessions don't share the registry.)
    ## ---------------------------------------------------------------------

    'Google Chrome - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Use when GoogleUpdate.exe is broken / absent or you want to honor the Software Center deployment ring.'
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
                $patterns = @('*Google Chrome*')
                $excludes = @('*Update*','*Helper*','*Sync*')
                $candidates = @($apps | Where-Object {
                    $n = "$($_.LocalizedDisplayName) $($_.Name)"
                    $m = $false
                    foreach ($p in $patterns) { if ($n -like $p) { $m = $true; break } }
                    if (-not $m) { return $false }
                    foreach ($x in $excludes) { if ($n -like $x) { return $false } }
                    return $true
                })
                if ($candidates.Count -eq 0) {
                    return 'SKIP: No matching Chrome app in Software Center catalog'
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
            $guid = '{8A69D345-D564-463c-AFF1-A69D9E530F96}'
            $paths = @(
                "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\$guid"
                "HKLM:\SOFTWARE\Google\Update\Clients\$guid"
            )
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
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = 'via Software Center' }
        }
    }

    'Microsoft Edge - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Use when MicrosoftEdgeUpdate.exe is broken / absent or you want to honor the Software Center deployment ring.'
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
                ## Edge name-match is the noisy one — Microsoft Edge ships alongside
                ## Microsoft Edge Update, Microsoft Edge WebView2 Runtime, and
                ## Microsoft Edge Helper. Match permissively, then exclude the noise.
                $patterns = @('*Microsoft Edge*')
                $excludes = @('*Update*','*WebView*','*Helper*','*Beta*','*Dev*','*Canary*')
                $candidates = @($apps | Where-Object {
                    $n = "$($_.LocalizedDisplayName) $($_.Name)"
                    $m = $false
                    foreach ($p in $patterns) { if ($n -like $p) { $m = $true; break } }
                    if (-not $m) { return $false }
                    foreach ($x in $excludes) { if ($n -like $x) { return $false } }
                    return $true
                })
                if ($candidates.Count -eq 0) {
                    return 'SKIP: No matching Edge app in Software Center catalog'
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
            $guid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
            $paths = @(
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid"
                "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid"
            )
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
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = 'via Software Center' }
        }
    }

    'Microsoft 365 - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Targets the M365 Apps / Office 365 ProPlus catalog entry. Use when OfficeC2RClient.exe is wedged or you want SCCM-controlled rollout.'
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
                ## Office is heavily fragmented in CCM catalogs — accept any of
                ## the common naming variants, exclude the per-app noise.
                $patterns = @('*Microsoft 365 Apps*','*Office 365 ProPlus*','*Microsoft 365*','*Office 365*','*Microsoft Office Pro*','*M365 Apps*')
                $excludes = @('*Skype*','*Teams*','*OneDrive*','*OneNote*','*Visio*','*Project*','*Language Pack*','*Proofing*','*Web Apps*','*Remove*','*Uninstall*')
                $candidates = @($apps | Where-Object {
                    $n = "$($_.LocalizedDisplayName) $($_.Name)"
                    $m = $false
                    foreach ($p in $patterns) { if ($n -like $p) { $m = $true; break } }
                    if (-not $m) { return $false }
                    foreach ($x in $excludes) { if ($n -like $x) { return $false } }
                    return $true
                })
                if ($candidates.Count -eq 0) {
                    return 'SKIP: No matching Office / M365 app in Software Center catalog'
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
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version = 'n/a'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = "Scenario=$($p.LastScenario); via Software Center" }
        }
    }

    'Apache Log4j - Replace Vulnerable Jars' = @{
        ## v1.8.2: Lift-and-shift port of WPT 6.4.2's Apache Log4j profile
        ## (which is itself a port of Log4J_Plugin_282519 v2.ps1). Source
        ## share holds the replacement jars (log4j-api-2.25.4.jar +
        ## log4j-core-2.25.4.jar) -- drop point lives next to the JANET
        ## Logs share. Targets the two paths the original script targets
        ## (HID Global Credential Management Client + Adobe Experience
        ## Manager Forms Designer).
        ##
        ## Plugin coverage (as of v1.8.10, jars bumped to 2.25.4):
        ##   282519 - MitM, fixed in 2.25.3+ : CLEARS
        ##   306549 - XmlLayout, fixed in 2.25.4+ : CLEARS
        ##   306550 - SSL Hostname, fixed in 2.25.4+ : CLEARS
        ## Grouped under one card per the operator request: the
        ## Get-NemProfileMatchTable rule maps every "Apache Log4j"
        ## plugin to this profile so the rollup card covers them all.
        ## When a future Log4j CVE drops, bump the constants below +
        ## the Verify regex to the new fixed version and re-stage the
        ## jars at the share.
        ##
        ## v1.10.7: Script + Verify rewritten to RECURSE under each
        ## target lib root. Previous versions only enumerated the top
        ## level, leaving the Backup_<ts>\ subdirs they themselves
        ## created accumulating stale jars (2.17.2 / 2.25.3) that
        ## Tenable kept flagging via plugins 306549 / 306550. The
        ## `$sourceShare = '...'` literal MUST stay as the first
        ## single-quoted assignment in this scriptblock -- both
        ## Resolve-NemProfileScriptText (single-target dispatch) and
        ## the Start-NemBulkRunAll pool scriptblock (bulk dispatch)
        ## substitute it via regex at run time to point at the
        ## operator-staged dir; if the assignment shape changes the
        ## substitution silently no-ops and the remote Script tries
        ## to reach the embedded UNC literal directly (double-hop).
        ##
        ## New per-jar dispositions:
        ##   - filename == log4j-(api|core)-2.25.4.jar   -> SKIP (already current)
        ##   - path contains \Backup_*\                  -> DELETE in place
        ##                                                  (no back-of-a-backup)
        ##   - else (top-level live jar that isn't 2.25.4) -> BACKUP + REPLACE
        ##                                                    using a fresh
        ##                                                    Backup_<ts>\ in
        ##                                                    the lib root
        ## The bundled service is only stopped when at least one live
        ## jar needs replacing -- pure archive cleanups don't bounce
        ## the service.
        Desc   = 'Replace log4j-api/core jars with 2.25.4 across HID + Adobe lib paths (recursive: live jars get back-up-then-replace, Backup_* subdir jars get deleted in place). Stops/starts bundled service when live jars need swapping.'
        Script = {
            $sourceShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles'
            $newApi      = 'log4j-api-2.25.4.jar'
            $newCore     = 'log4j-core-2.25.4.jar'
            $targets     = @(
                @{ Path='C:\Program Files\HID Global\Credential Management Client\lib'; Service='HIDCredentialManagementClient' }
                @{ Path='C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'; Service='AdobeExperienceManagerFormsDesigner' }
            )

            ## Verify the source jars are reachable BEFORE touching any
            ## service. The dispatcher substitutes $sourceShare with
            ## either an operator-staged dir or (in bulk mode) a per-host
            ## remote stage dir like C:\Windows\Temp\janet-log4j-stage-*.
            ## Either way, Test-Path here is the last gate before we
            ## stop anything.
            $srcApi  = Join-Path $sourceShare $newApi
            $srcCore = Join-Path $sourceShare $newCore
            if (-not (Test-Path -LiteralPath $srcApi))  { return "FAIL: source jar missing: $srcApi" }
            if (-not (Test-Path -LiteralPath $srcCore)) { return "FAIL: source jar missing: $srcCore" }

            $liveReplaced    = 0
            $archiveDeleted  = 0
            $skippedRoots    = 0
            $skippedCurrent  = 0
            $errors          = New-Object System.Collections.Generic.List[string]

            foreach ($t in $targets) {
                $libPath = $t.Path
                if (-not (Test-Path -LiteralPath $libPath)) { $skippedRoots++; continue }

                ## v1.10.7: RECURSIVE enumeration. -Filter is FS-driver fast.
                ## Wrap in try/catch for ACL surprises under recursed dirs.
                try {
                    $allJars = @(Get-ChildItem -LiteralPath $libPath -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                } catch { $allJars = @() }

                ## Only care about api + core jars for the swap action --
                ## the source stage only ships those two. Other components
                ## (1.2-api, jul, to-slf4j) get left alone here.
                $relevant = @($allJars | Where-Object {
                    $_.Name -match '^log4j-(api|core)-' -and $_.Name -like '*.jar'
                })
                if ($relevant.Count -eq 0) { $skippedRoots++; continue }

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

                        $rootApi  = Join-Path $libPath $newApi
                        $rootCore = Join-Path $libPath $newCore
                        try { Copy-Item -LiteralPath $srcApi  -Destination $rootApi  -Force -ErrorAction Stop }
                        catch { $errors.Add("$rootApi copy failed: $($_.Exception.Message)") | Out-Null }
                        try { Copy-Item -LiteralPath $srcCore -Destination $rootCore -Force -ErrorAction Stop }
                        catch { $errors.Add("$rootCore copy failed: $($_.Exception.Message)") | Out-Null }

                        $liveReplaced++
                    }

                    ## --- Archive jars: delete in place ---
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
                ## v1.10.7: RECURSIVE -- the Backup_<ts>\ subdirs the
                ## Script side creates are what Tenable hits via plugin
                ## 306549 / 306550. Non-recursive Get-ChildItem hid them.
                $jars = @(Get-ChildItem -LiteralPath $p -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                foreach ($j in $jars) {
                    $found.Add("$($j.Name)") | Out-Null
                    ## Only api+core in the 2.25.4-exactly pattern are
                    ## considered "patched" -- match the Tenable plugin
                    ## bar the updater is chasing.
                    if ($j.Name -notmatch '^log4j-(api|core)-2\.25\.4\.jar$') {
                        ## Include the full path so the Updater card's
                        ## post-run detail string disambiguates live vs
                        ## archive (Backup_*) jars instead of a bare
                        ## filename that doesn't say where it lives.
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

    'Tenable Nessus Agent - Package Deploy' = @{
        ## v1.9.0: PSADT-style package install. The pool scriptblock detects
        ## IsPackage=$true and takes the package-deploy branch:
        ##   1. Validates Tools\Packages\<PackageFolder>\Deploy-Application.ps1
        ##      exists on the controller side BEFORE dispatching.
        ##   2. After PSSession opens, creates a remote stage dir at
        ##      C:\Windows\Temp\janet-pkg-<guid>\ on the target.
        ##   3. Copies the entire package folder via Copy-Item -ToSession.
        ##   4. Invokes Deploy-Application.ps1 -DeployMode NonInteractive
        ##      on the target.
        ##   5. Parses PSADT exit codes (0/1641/3010 = Success, 60012 =
        ##      User Deferred, anything else = Failed).
        ##   6. Runs the Verify scriptblock in the same session for
        ##      post-install version reporting.
        ##   7. Cleans up the remote stage dir.
        ## Script field is intentionally $null — the engine lives in the
        ## pool scriptblock branch, not here.
        Desc = 'PSADT package install via Copy-Item -ToSession + remote Deploy-Application.ps1. Mirrors the WPT RemotePackageInstaller engine. Targets Tenable Nessus Agent vulnerabilities. Reads from Tools\Packages\NIPR_Tenable Nessus Agent_11.1.3 next to the script.'
        IsPackage     = $true
        PackageFolder = 'NIPR_Tenable Nessus Agent_11.1.3'
        Script        = $null
        Verify = {
            ## Tenable Nessus Agent registers under HKLM:\SOFTWARE\Tenable\
            ## with a Version / nessus_agent_ver value. We also fall back
            ## to the Uninstall key (DisplayVersion) since some installer
            ## flavors don't write the Tenable key consistently.
            $tenPaths = @(
                'HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\WOW6432Node\Tenable\Tenable Nessus Agent\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\WOW6432Node\Tenable\Tenable Nessus Agent'
            )
            $ver = 'not installed'
            $mod = $null
            foreach ($p in $tenPaths) {
                if (Test-Path -LiteralPath $p) {
                    $pp = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
                    if ($pp -and $pp.PSObject.Properties['nessus_agent_ver'] -and $pp.nessus_agent_ver) {
                        $ver = "$($pp.nessus_agent_ver)"
                    } elseif ($pp -and $pp.PSObject.Properties['Version'] -and $pp.Version) {
                        $ver = "$($pp.Version)"
                    }
                    $key = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                    if ($key) { $mod = $key.LastWriteTime }
                    if ($ver -ne 'not installed') { break }
                }
            }
            if ($ver -eq 'not installed') {
                $uninstRoots = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                )
                foreach ($u in $uninstRoots) {
                    if (-not (Test-Path -LiteralPath $u)) { continue }
                    try {
                        $hit = Get-ChildItem -LiteralPath $u -ErrorAction SilentlyContinue |
                            Where-Object {
                                $dn = $_.GetValue('DisplayName')
                                $dn -and ($dn -like '*Nessus Agent*' -or $dn -like '*Tenable*Agent*')
                            } |
                            Select-Object -First 1
                        if ($hit) {
                            $dv = $hit.GetValue('DisplayVersion')
                            if ($dv) { $ver = [string]$dv }
                            $instDate = $hit.GetValue('InstallDate')
                            if ($instDate -and -not $mod) {
                                ## InstallDate is yyyymmdd format
                                try { $mod = [datetime]::ParseExact("$instDate", 'yyyyMMdd', $null) } catch {}
                            }
                            break
                        }
                    } catch {}
                }
            }

            $modStr = if ($mod -is [datetime]) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($ver -ne 'not installed') { $true } else { $false }
            $detail = if ($ver -eq 'not installed') { 'Nessus Agent not detected via registry' } else { 'via Tenable registry / Uninstall key' }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = $detail }
        }
    }
    'Edge STIG - Disable Search Engine Import' = @{
        ## v1.10.8 (ported from WPT 6.5.20): DISA Microsoft Edge STIG
        ## EDGE-00-000022 / SV-235739r960963_rule. Tenable surfaces this
        ## with the reference token "noCCE" -- the Edge STIG .audit ships
        ## without a CCE on this check. Equivalent to GPO "Allow importing
        ## of search engine settings = Disabled". One DWord; effective at
        ## next Edge launch, no reboot. Self-contained for the
        ## Start-NemVulnRun .ToString() rehydration.
        Desc   = 'Set HKLM:\SOFTWARE\Policies\Microsoft\Edge\ImportSearchEngine = 0 (DWord). Clears DISA Edge STIG EDGE-00-000022 / the Tenable noCCE finding. No reboot; effective at next Edge launch.'
        Script = {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            try {
                if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force -EA Stop | Out-Null }
                New-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -Value 0 -PropertyType DWord -Force -EA Stop | Out-Null
                $now = (Get-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -EA Stop).ImportSearchEngine
                if ([int]$now -eq 0) { return 'OK (ImportSearchEngine=0 set)' }
                return "FAIL: readback was $now after write"
            } catch { return "FAIL: $($_.Exception.Message)" }
        }
        Verify = {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            $val = $null
            try { $val = (Get-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -EA Stop).ImportSearchEngine } catch {}
            $mod = $null
            try { if (Test-Path -LiteralPath $key) { $mod = (Get-Item -LiteralPath $key -EA SilentlyContinue).LastWriteTime } } catch {}
            $modStr = if ($mod -is [datetime]) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $isOk   = ($null -ne $val -and [int]$val -eq 0)
            return @{
                Version     = if ($null -eq $val) { 'not set' } else { "ImportSearchEngine=$val" }
                LastUpdated = $modStr
                Verified    = $isOk
                Detail      = if ($isOk) { 'STIG EDGE-00-000022 satisfied (import disabled)' } else { 'Value missing or non-zero -- STIG not satisfied' }
            }
        }
    }
    'Windows Unquoted Service Path - Remediate' = @{
        ## v1.10.8 (ported from WPT 6.5.20): Tenable plugin 63155
        ## (~322 hosts). Walks every service under HKLM\SYSTEM\Current
        ## ControlSet\Services and quotes any ImagePath whose executable
        ## portion contains a space but isn't already quoted. Preserves
        ## the original value-kind (REG_SZ vs REG_EXPAND_SZ) so
        ## %SystemRoot%-style entries keep expanding. Pre-edit value is
        ## stashed at HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath\<svc>
        ## \OriginalImagePath as a rollback breadcrumb. No reboot, but the
        ## fixed services need a restart (or next boot) before the new
        ## ImagePath is honored. Self-contained for .ToString() rehydration.
        Desc   = 'Find services whose ImagePath has spaces and no surrounding quotes, then rewrite with quotes around the exe (args preserved). Backs up original value to HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath. Clears Tenable plugin 63155.'
        Script = {
            $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            $backupRoot = 'HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath'
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
            $backupRoot = 'HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath'
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
        ## v1.10.8 (ported from WPT 6.5.20): Tenable plugin 62758
        ## (~26 hosts). MSXML 4.0 SP3 reached Microsoft end-of-support in
        ## 2014; any version still installed is the vulnerability.
        ## Discovery is by DisplayName ('MSXML 4.0*') across the standard
        ## Uninstall hives, not a hardcoded GUID list -- the GUID varies
        ## per locale + KB level, and a DisplayName scan catches both the
        ## Parser and the SP packages without missing a build.
        ## Self-contained for .ToString() rehydration.
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

    'Oracle Java - Software Center' = @{
        ## Added 2026-06-02. Oracle Java SE downloads are SSO-gated, so
        ## the practical push path is the MECM Software Center catalog.
        ## Operator publishes a Java app in SC, then this profile
        ## triggers CCM_Application Install on the matching catalog
        ## entry. Pattern matches *Java* / *Oracle JRE* with conservative
        ## excludes (Helper / Auto Update / Update Scheduler / Web Start);
        ## refine the excludes if SC has multiple Java packages that
        ## both still match the *Java* pattern.
        Desc = 'CCM_Application Install via SCCM client SDK. Triggers the Software Center Java package install — use when Oracle Java SE CPU vulnerabilities are flagged and a Java app is published in SC.'
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

function Get-WptAppUpdateProfiles {
    <#
    .SYNOPSIS
        Return the full App Updater profile hashtable. Read-only use only.
    #>
    [CmdletBinding()]
    param()
    return $script:WptAppUpdateProfiles
}

function Get-WptAppUpdateProfile {
    <#
    .SYNOPSIS
        Return one profile by name, or $null if the name is not registered.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    if ($script:WptAppUpdateProfiles.ContainsKey($Name)) {
        return $script:WptAppUpdateProfiles[$Name]
    }
    return $null
}

function Get-WptAppUpdateProfileNames {
    <#
    .SYNOPSIS
        Ordered list of profile names suitable for a ComboBox Items source.
    #>
    [CmdletBinding()]
    param()
    return @($script:WptAppUpdateProfiles.Keys | Sort-Object)
}

function global:Get-NemLog4jSourcePath {
    <#
    .SYNOPSIS
        Resolve the active Log4j replacement-jar source path. Operator
        override (Updater tab textbox) wins; otherwise the auto-resolved
        $global:NemLog4jDefaultSource. Matches WPT 6.5.2's pattern.
    #>
    [CmdletBinding()]
    param()
    $ovr = $null
    try {
        $s = Get-NemState
        if ($s -and $s.UI -and $s.UI.Controls.ContainsKey('updTxtLog4jSrc')) {
            $tb = $s.UI.Controls['updTxtLog4jSrc']
            if ($tb -and $tb.Text) { $ovr = ([string]$tb.Text).Trim() }
        }
    } catch {}
    if (-not [string]::IsNullOrWhiteSpace($ovr)) { return $ovr }
    return [string]$global:NemLog4jDefaultSource
}

function global:Get-NemPackageSourcePath {
    <#
    .SYNOPSIS
        Resolve the operator-side absolute path to a PSADT package folder
        for an IsPackage updater profile.
    .DESCRIPTION
        Packages live under $PSScriptRoot\Packages\<FolderName>\ next to
        the Nemesis script. Validates the folder exists and contains a
        Deploy-Application.ps1 (PSADT entry point). Returns $null if
        either check fails — caller is expected to surface a "package
        missing" FAIL up the per-host result chain so the operator
        sees it instead of a silent no-op.
    .PARAMETER FolderName
        Name of the package folder under Tools\Packages\ (e.g.
        'NIPR_Tenable Nessus Agent_11.1.3'). Hardcoded in the matching
        profile entry.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $FolderName)

    $root = Join-Path $PSScriptRoot 'Packages'
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    $full = Join-Path $root $FolderName
    if (-not (Test-Path -LiteralPath $full)) { return $null }
    ## Confirm the PSADT entry point is present so we don't dispatch
    ## copies that will fail post-WinRM with a less obvious error.
    $deploy = Get-ChildItem -LiteralPath $full -Filter 'Deploy-Application.ps1' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $deploy) { return $null }
    return $full
}

function global:Resolve-NemProfileScriptText {
    <#
    .SYNOPSIS
        Return a profile's Script as plain text, with profile-specific
        operator overrides applied. Today only the Apache Log4j profile
        has an override (the source-share path). Used by every site
        that ships profile.Script across to a remote — Invoke-NemRemote
        for bulk run + the Start-NemVulnRun / VulnVerify combined
        scriptblocks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ProfileName,
        [Parameter(Mandatory)] [scriptblock] $Script
    )
    $text = $Script.ToString()
    if ($ProfileName -eq 'Apache Log4j - Replace Vulnerable Jars') {
        $opPath = Get-NemLog4jSourcePath
        if (-not [string]::IsNullOrWhiteSpace($opPath)) {
            $escPath = $opPath.Replace("'", "''")
            ## Same regex pattern WPT 6.5.2 uses: lookbehind for
            ## "$sourceShare\s*=\s*'", capture everything up to the
            ## next single quote, replace.
            $text = [regex]::Replace($text, "(?<=\`$sourceShare\s*=\s*')[^']*", $escPath)
        }
    }
    return $text
}

function Invoke-NemUpdateRun {
    <#
    .SYNOPSIS
        Run a named App Update profile against a remote target via Invoke-Command.
    .DESCRIPTION
        Wraps the profile scriptblock inside an Invoke-Command call with a
        per-target timeout. Returns a single string: OK* for success, FAIL*
        for any failure mode. Exceptions are caught and serialized as FAIL:
        so the caller never has to handle them.
    .PARAMETER Target
        Computer name (DNS FQDN, NetBIOS, or IP).
    .PARAMETER ProfileName
        Name of a profile from Get-WptAppUpdateProfileNames, OR the literal
        string 'Custom Command' when CustomCommand is supplied.
    .PARAMETER ForceClose
        Pass-through flag - meaningful for M365 profiles only.
    .PARAMETER SuppressReboot
        Pass-through flag - reserved for profiles that care.
    .PARAMETER CustomCommand
        Scriptblock text. Used only when ProfileName = 'Custom Command'.
    .PARAMETER TimeoutSec
        Per-target Invoke-Command timeout, defaults to the module constant.
    #>
    param(
        [Parameter(Mandatory)] [string]   $Target,
        [Parameter(Mandatory)] [string]   $ProfileName,
        [bool]   $ForceClose     = $false,
        [bool]   $SuppressReboot = $false,
        [string] $CustomCommand  = '',
        [int]    $TimeoutSec     = $script:NemOperationTimeoutS
    )
    try {
        if ($ProfileName -eq 'Custom Command') {
            if ([string]::IsNullOrWhiteSpace($CustomCommand)) {
                return 'FAIL: Custom Command selected but command text is empty.'
            }
            $sb = [scriptblock]::Create($CustomCommand)
        } else {
            $profile = Get-WptAppUpdateProfile -Name $ProfileName
            if (-not $profile) {
                return "FAIL: Unknown profile '$ProfileName'."
            }
            ## v1.9.0: IsPackage profiles can't run through this helper —
            ## the deploy engine lives in the Start-NemVulnRun pool
            ## scriptblock (needs the operator-side $PSScriptRoot\Packages\
            ## tree + Copy-Item -ToSession). Programmatic single-target
            ## callers should drive Start-NemVulnRun directly.
            $isPkg = $false
            try {
                if ($profile -is [hashtable] -and $profile.ContainsKey('IsPackage')) { $isPkg = [bool]$profile['IsPackage'] }
                elseif ($profile.PSObject -and $profile.PSObject.Properties['IsPackage']) { $isPkg = [bool]$profile.IsPackage }
            } catch {}
            if ($isPkg) {
                return "FAIL: '$ProfileName' is a package-deploy profile. Use the Updater card Run button (Start-NemVulnRun) — Invoke-NemUpdateRun cannot dispatch package deploys."
            }
            ## v1.8.5: route through Resolve-NemProfileScriptText so the
            ## Apache Log4j source path is the operator's override (or
            ## the auto-detected $global:NemLog4jDefaultSource) instead
            ## of the embedded literal in the registry. Other profiles
            ## round-trip unchanged.
            $sb = [scriptblock]::Create((Resolve-NemProfileScriptText -ProfileName $ProfileName -Script $profile.Script))
        }

        ## v1.4.0 (WPT-ported): bounded PSSession via Invoke-NemRemote
        ## helper instead of `Invoke-Command -ComputerName` one-shot.
        ## Picks up TCP reachability preflight, OpenTimeout/OperationTimeout
        ## bounds, and Negotiate auth automatically. Caller's $TimeoutSec
        ## is folded into the helper's session option.
        $cred = $null
        try { $cred = (Get-NemState).Credentials } catch {}

        $result = Invoke-NemRemote -Target $Target -ScriptBlock $sb -Credential $cred

        if ($null -eq $result) { return 'OK (no output)' }
        return [string]$result
    } catch {
        return "FAIL: $($_.Exception.Message)"
    }
}

###################################
## PER-VULNERABILITY UPDATER RUN ##
###################################
## Card-based Updater — one card per vulnerability, each Run pushes a single
## profile to ONLY that vulnerability's affected hosts. No all-hosts path.
function global:Start-NemVulnRun {
    <#
    .SYNOPSIS
        Run a single App Update profile against the exact host set affected
        by one vulnerability.  Called from each Updater card's Run button.

    .DESCRIPTION
        Serialises with the shared drain timer and Jobs table: only one vuln
        run at a time.  Reachability pre-flight drops unreachable hosts from
        dispatch but counts them as failures.  Results stream into the
        shared Updater log pane with the vuln name in the header banner.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $VulnKey,
        [Parameter(Mandatory)] [string]   $VulnDisplay,
        [Parameter(Mandatory)] [string]   $ProfileName,
        [Parameter(Mandatory)] [string[]] $HostList,
        ## VerifyOnly: skip the update scriptblock and only probe the remote
        ## version via the profile's Verify block. Used by each card's
        ## "Verify" button so the operator can re-check after the async
        ## Chrome/Edge/Office update has had time to complete.
        [switch] $VerifyOnly,
        ## v1.5.0: rollup-card context. When GroupMembers is non-empty the
        ## drain-timer's final tick passes both into Write-NemRunSummary so
        ## one Run on a rolled-up card writes N CSV rows (one per member
        ## vuln) instead of one synthetic-display-name row. Per-vuln cards
        ## leave both empty and behave exactly as before.
        [string]   $GroupKey     = '',
        [object[]] $GroupMembers = @()
    )

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls

    $rtb    = $ctrl['updRtbLog']
    $lbl    = $ctrl['updLblStatus']
    $cancel = $ctrl['updBtnCancel']

    $modeLabel    = if ($VerifyOnly) { 'Verify' } else { 'Update' }
    $auditPrefix  = if ($VerifyOnly) { 'VulnVerify' } else { 'VulnRun' }
    $statusVerb   = if ($VerifyOnly) { 'Checking' } else { 'Running' }

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Only one card operation at a time — Update and Verify share the drain
    ## timer + Jobs table, so a Verify blocks a concurrent Run and vice versa.
    $outstanding = 0
    foreach ($k in $s.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
    if ($outstanding -gt 0 -or $s.UI.Controls.ContainsKey('updTimer')) {
        [System.Windows.Forms.MessageBox]::Show(
            'A vulnerability run is already in progress. Use Cancel, or wait for it to finish.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $targets = @($HostList | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
    if ($targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No affected hosts resolved for '$VulnDisplay'.",
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Lock every card's Run + Verify buttons for the duration.
    Set-NemVulnCardRunEnabled -Enabled $false
    $cancel.Enabled = $true
    $lbl.Text      = "$statusVerb '$ProfileName' for [$VulnDisplay] on $($targets.Count) host(s)..."
    $lbl.ForeColor = $theme.Warning

    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("Vuln:    $VulnDisplay`r`n")
    $rtb.AppendText("Profile: $ProfileName  |  Mode: $modeLabel  |  Hosts: $($targets.Count)`r`n")
    $rtb.AppendText("========================================`r`n")
    Write-NemAudit -Action "$auditPrefix.Start" -Target $VulnDisplay -Result 'OK' `
        -Detail "profile=$ProfileName hosts=$($targets.Count)"

    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success      = 0
        Failed       = 0
        Total        = $targets.Count
        VulnDisplay  = $VulnDisplay
        ProfileName  = $ProfileName
        AuditPrefix  = $auditPrefix
        ModeLabel    = $modeLabel
        StartedAt    = Get-Date
        ## v1.5.0: rollup-card audit fan-out context.
        GroupKey     = $GroupKey
        GroupMembers = $GroupMembers
    }

    ## v1.8.8: removed serial preflight loop. The 3s/port TCP probe
    ## times out on the UI thread for unreachable hosts, freezing the
    ## window for up to 6s × N hosts before any dispatch happens. Each
    ## runspace scriptblock already has an inline TCP probe that runs
    ## in parallel via the pool — letting it handle reachability lifts
    ## the freeze entirely. Unreachable hosts still get
    ## "FAIL - unreachable (TCP 5985/445)" logged through the drain
    ## timer, just async instead of upfront.

    $profilesTable    = Get-WptAppUpdateProfiles
    $cred             = $s.Credentials   # operator-set credential (may be $null → ambient Kerberos)
    ## v1.8.5: resolve the operator's Log4j source-share override on
    ## the controller side. Passed into each runspace so the inline
    ## script-text substitution can swap the embedded $sourceShare
    ## literal before the remote rehydrates the scriptblock. Empty
    ## string when the operator hasn't picked the Log4j profile or
    ## hasn't entered an override — the runspace skips the swap in
    ## that case and the embedded literal stands.
    $log4jSrcOverride = Get-NemLog4jSourcePath

    ## v1.9.0: resolve the operator-side package source path for
    ## IsPackage profiles BEFORE entering the runspace pool. Each
    ## runspace receives the absolute path via AddArgument and uses
    ## Copy-Item -ToSession to push the package to a remote stage dir
    ## inside the existing PSSession. Empty string for non-package
    ## profiles — the package-deploy branch in the scriptblock skips
    ## itself when the path is empty.
    $pkgSrcOverride = ''
    if ($profilesTable.ContainsKey($ProfileName)) {
        $profSel = $profilesTable[$ProfileName]
        $isPkg = $false
        if ($profSel -is [hashtable] -and $profSel.ContainsKey('IsPackage')) {
            $isPkg = [bool]$profSel['IsPackage']
        } elseif ($profSel.PSObject -and $profSel.PSObject.Properties['IsPackage']) {
            $isPkg = [bool]$profSel.IsPackage
        }
        if ($isPkg) {
            $folder = $null
            if ($profSel -is [hashtable] -and $profSel.ContainsKey('PackageFolder')) {
                $folder = [string]$profSel['PackageFolder']
            } elseif ($profSel.PSObject -and $profSel.PSObject.Properties['PackageFolder']) {
                $folder = [string]$profSel.PackageFolder
            }
            if ($folder) {
                $resolved = Get-NemPackageSourcePath -FolderName $folder
                if ($resolved) { $pkgSrcOverride = $resolved }
            }
        }
    }

    foreach ($t in $targets) {
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        [void]$ps.AddScript({
            param($TargetIn, $ProfileIn, $UpdateProfilesTable, $VerifyOnlyIn, $CredIn, $Log4jSrcIn, $PkgSrcIn)
            $prof = $UpdateProfilesTable[$ProfileIn]
            if (-not $prof) { return "FAIL: Unknown profile '$ProfileIn'." }

            ## v1.9.0: package-profile guard. IsPackage=$true profiles use
            ## the controller-staged Tools\Packages\<folder>\ tree which
            ## the operator-side resolver hands in via $PkgSrcIn. If that
            ## resolver returned empty (folder missing, Deploy-Application.ps1
            ## absent), bail BEFORE we touch the network — the missing
            ## package is the operator's problem to fix, not the target's.
            $isPkgProfile = $false
            try {
                if ($prof -is [hashtable] -and $prof.ContainsKey('IsPackage')) { $isPkgProfile = [bool]$prof['IsPackage'] }
                elseif ($prof.PSObject -and $prof.PSObject.Properties['IsPackage']) { $isPkgProfile = [bool]$prof.IsPackage }
            } catch {}
            if ($isPkgProfile -and -not $VerifyOnlyIn) {
                if ([string]::IsNullOrWhiteSpace($PkgSrcIn)) {
                    return "FAIL: Package source not resolved on controller (Tools\Packages\<folder>\Deploy-Application.ps1 missing?)"
                }
                if (-not (Test-Path -LiteralPath $PkgSrcIn)) {
                    return "FAIL: Package source not found on controller: $PkgSrcIn"
                }
            }

            ## v1.4.0 (WPT-ported): inline TCP reachability + bounded
            ## PSSession. Replaces the prior `Invoke-Command -ComputerName`
            ## one-shot which used the default ~3min OpenTimeout and no
            ## auth scheme override. Negotiate falls through Kerberos
            ## then NTLM, matching WPT/SIM. The runspace cannot see
            ## global:Test-NemTcpReachable / New-NemSessionOption, so the
            ## probe + option construction are inlined here.
            $reachable = $false
            foreach ($port in 5985, 445) {
                $tc = $null
                try {
                    $tc  = New-Object System.Net.Sockets.TcpClient
                    $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
                } catch {}
                finally { if ($tc) { try { $tc.Close() } catch {} } }
                if ($reachable) { break }
            }
            if (-not $reachable) { return "FAIL: unreachable (TCP 5985/445)" }

            $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
            $sessArgs = @{
                ComputerName   = $TargetIn
                SessionOption  = $wsOpt
                Authentication = 'Negotiate'
                ErrorAction    = 'Stop'
            }
            if ($CredIn) { $sessArgs['Credential'] = $CredIn }
            $sess = $null
            try { $sess = New-PSSession @sessArgs }
            catch {
                $sessErr = $_.Exception.Message
                ## v1.8.3: NetBIOS fallback on Negotiate auth failures.
                ## 0x80090322 = SEC_E_WRONG_PRINCIPAL (broken SPN / DNS-name
                ## mismatch — Kerberos can't form a ticket). "Access is denied"
                ## from a Negotiate handshake also fits this bucket. Retrying
                ## with the NetBIOS short name (everything before first '.')
                ## forces NTLM, which has different SPN requirements and
                ## usually works when Kerberos doesn't. Only retry when we
                ## actually have an FQDN to strip.
                if ($TargetIn -match '\.' -and (
                        $sessErr -match '0x80090322' -or
                        $sessErr -match 'Negotiate authentication' -or
                        $sessErr -match 'Access is denied'
                    )) {
                    $nbName = ($TargetIn -split '\.')[0]
                    $sessArgs2 = @{} + $sessArgs
                    $sessArgs2['ComputerName'] = $nbName
                    try {
                        $sess = New-PSSession @sessArgs2
                    } catch {
                        return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
                    }
                } else {
                    return "FAIL: Session - $sessErr"
                }
            }

            try {
                if ($VerifyOnlyIn) {
                    ## Verify-only: just probe the remote version. Used when the
                    ## operator clicks the card's Verify button to re-check after
                    ## the vendor updater has had time to finish asynchronously.
                    if (-not $prof.Verify) { return 'SKIP: profile has no Verify block' }
                    try {
                        $out = Invoke-Command -Session $sess -ScriptBlock $prof.Verify -ErrorAction Stop
                        if ($out -is [hashtable]) {
                            $ver  = if ($out.Version)     { [string]$out.Version }     else { 'unknown' }
                            $last = if ($out.LastUpdated) { [string]$out.LastUpdated } else { 'n/a' }
                            $ver2 = $out.Verified
                            $flag = if ($ver2 -eq $true) { 'fresh' } elseif ($null -eq $ver2) { 'n/a' } else { 'stale' }
                            $detail = if ($out.Detail) { " ($([string]$out.Detail))" } else { '' }
                            return "v=$ver last=$last [$flag]$detail"
                        }
                        if ($null -eq $out) { return 'OK (no output)' }
                        return [string]$out
                    } catch {
                        return "FAIL: $($_.Exception.Message)"
                    }
                }

                ## v1.9.0: PSADT package-deploy branch. Profiles flagged
                ## IsPackage=$true (e.g. Tenable Nessus Agent) skip the
                ## scriptblock-text rehydration path — they have no
                ## Script. Instead:
                ##   1. Create a per-host stage dir on target
                ##   2. Copy the controller-side package folder via
                ##      Copy-Item -ToSession (uses the open PSSession)
                ##   3. Find Deploy-Application.ps1 in the staged dir
                ##   4. Invoke -DeployMode NonInteractive
                ##   5. Parse PSADT exit codes (0/1641/3010 = success,
                ##      60012 = user-deferred, anything else = failed)
                ##   6. Run the profile Verify post-install for version
                ##      reporting (best-effort — failure here doesn't
                ##      flip the run result)
                ##   7. Cleanup remote stage dir in finally
                ##
                ## v1.9.3: KNOWN LEAK on Cancel during Copy-Item -ToSession.
                ## PowerShell.Stop() (the Cancel path) does NOT guarantee
                ## the runspace's `finally` block runs — it can do a hard
                ## abort before reaching the cleanup. Worst case: orphan
                ## C:\Windows\Temp\janet-pkg-<guid> dirs on targets where
                ## the operator cancelled mid-copy. Accepted risk:
                ## (a) Cancel mid-copy is a narrow window (the copy
                ## itself is fast), (b) C:\Windows\Temp is the OS-cleanup
                ## path so dirs eventually age out, (c) the dirs are
                ## inert (no running service / scheduled task). If this
                ## becomes a real complaint, add a controller-side
                ## stage-tracker file (CSV of in-flight target+dir
                ## tuples) and a session-start sweep that PSSessions
                ## into each tracked target and removes orphans.
                $remotePkgStage = $null
                if ($isPkgProfile) {
                    $stageGuid       = [guid]::NewGuid().ToString('N').Substring(0,8)
                    $remotePkgStage  = "C:\Windows\Temp\janet-pkg-$stageGuid"
                    try {
                        Invoke-Command -Session $sess -ScriptBlock {
                            param($d)
                            New-Item -Path $d -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        } -ArgumentList $remotePkgStage -ErrorAction Stop

                        ## Push every file/folder under $PkgSrcIn into the
                        ## stage dir. Trailing \* matches Copy-Item's
                        ## "contents of folder, not folder itself" idiom.
                        Copy-Item -Path (Join-Path $PkgSrcIn '*') -Destination $remotePkgStage `
                            -Recurse -ToSession $sess -Force -ErrorAction Stop
                    } catch {
                        return "FAIL: package stage push failed: $($_.Exception.Message)"
                    }

                    try {
                        $deployRes = Invoke-Command -Session $sess -ArgumentList $remotePkgStage -ScriptBlock {
                            param($stageDir)
                            $out = [pscustomobject]@{
                                Status='FAIL'; ExitCode=$null; Reason=''; Output=''
                            }
                            try {
                                Get-ChildItem -Path $stageDir -Filter *.ps1 -Recurse -EA SilentlyContinue | Unblock-File
                                $deploy = Get-ChildItem -Path $stageDir -Filter 'Deploy-Application.ps1' -Recurse -File -EA SilentlyContinue | Select-Object -First 1
                                if (-not $deploy) {
                                    $out.Reason = 'Deploy-Application.ps1 not found in staged package post-copy'
                                    return $out
                                }
                                Set-Location $deploy.DirectoryName
                                $global:LASTEXITCODE = 0
                                $output   = & $deploy.FullName -DeployMode NonInteractive 2>&1
                                $exitCode = $LASTEXITCODE
                                $outStr   = ($output | Out-String).TrimEnd()
                                $out.ExitCode = $exitCode
                                $out.Output   = $outStr

                                ## PSADT exit-code conventions (matches
                                ## RemotePackageInstaller v2.4.3):
                                ##   0 / 1641 / 3010 = Success
                                ##   60012           = Deferred (user clicked Defer)
                                ##   anything else   = Failed
                                $successExits = @(0, 1641, 3010)
                                $softFail = $outStr -match '(?im)^\s*(ERROR|FAILED|FAILURE)\b'
                                if ($successExits -contains $exitCode) {
                                    if ($softFail) {
                                        $out.Status = 'FAIL'
                                        $out.Reason = "Exit $exitCode but output contained ERROR/FAILED tokens"
                                    } else {
                                        $out.Status = 'OK'
                                        $out.Reason = switch ($exitCode) {
                                            3010 { 'Success (reboot required)' }
                                            1641 { 'Success (reboot initiated)' }
                                            default { 'Success' }
                                        }
                                    }
                                } elseif ($exitCode -eq 60012) {
                                    $out.Status = 'SKIP'
                                    $out.Reason = 'User deferred install (PSADT 60012)'
                                } else {
                                    $out.Status = 'FAIL'
                                    $out.Reason = "Non-zero exit code: $exitCode"
                                }
                                return $out
                            } catch {
                                $out.Reason = "Terminating error: $($_.Exception.Message)"
                                return $out
                            }
                        } -ErrorAction Stop
                    } catch {
                        return "FAIL: deploy invoke failed: $($_.Exception.Message)"
                    } finally {
                        ## Best-effort cleanup of the remote stage dir.
                        try {
                            Invoke-Command -Session $sess -ScriptBlock {
                                param($d) Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
                            } -ArgumentList $remotePkgStage -ErrorAction SilentlyContinue
                        } catch {}
                    }

                    ## Best-effort post-install Verify (same session).
                    ## v1.9.3: SCRIPTBLOCK-AUTHOR WARNING — every IsPackage
                    ## profile's Verify scriptblock MUST be self-contained.
                    ## We rehydrate it on the remote via
                    ## [scriptblock]::Create() from the .ToString() text,
                    ## which means any closure-captured outer variable
                    ## (controller-side path, operator-set flag, helper
                    ## function defined locally in the profile registry)
                    ## will NOT be visible on the remote side and the
                    ## scriptblock will throw NullReference / "command not
                    ## recognized" silently inside the catch below. Verify
                    ## bodies should reference only:
                    ##   - Built-in cmdlets (Test-Path, Get-ItemProperty,
                    ##     Get-ChildItem, Get-AppxPackage, Update-MpSignature,
                    ##     etc.)
                    ##   - Built-in types and methods
                    ##   - String / int literals defined inline in the
                    ##     scriptblock body
                    ## Never reference $using:, $script:, $global:, or
                    ## locals captured at scriptblock-definition time.
                    $postVerSummary = ''
                    if ($prof.Verify) {
                        try {
                            $verifyText = [string]$prof.Verify.ToString()
                            $postRaw = Invoke-Command -Session $sess -ScriptBlock {
                                param($vt)
                                try { return & ([scriptblock]::Create($vt)) } catch { return $null }
                            } -ArgumentList $verifyText -ErrorAction SilentlyContinue
                            if ($postRaw -is [hashtable]) {
                                $pv = if ($postRaw.Version) { [string]$postRaw.Version } else { 'unknown' }
                                $postVerSummary = " | post-verify v=$pv"
                            }
                        } catch {}
                    }

                    $tag = switch ($deployRes.Status) {
                        'OK'   { 'OK' }
                        'SKIP' { 'SKIP' }
                        default { 'FAIL' }
                    }
                    $exitDisp = if ($null -ne $deployRes.ExitCode) { $deployRes.ExitCode } else { 'n/a' }
                    return "$tag (exit=$exitDisp; $($deployRes.Reason))$postVerSummary"
                }

                ## Full update: verify-before, update, verify-after in ONE remote
                ## session so we only pay the WinRM handshake once per target.
                ##
                ## Scriptblocks do NOT round-trip through -ArgumentList across
                ## WinRM — they arrive on the remote side as plain strings, so
                ## `& $updateSb` would try to invoke the source text as a command
                ## name (classic "The term '$c2r = ...' is not recognized" bug).
                ## We pass the source text explicitly and rehydrate with
                ## [scriptblock]::Create() on the remote side.
                $updateText = [string]$prof.Script.ToString()
                ## v1.8.6: Apache Log4j now stages jars to the remote
                ## via Copy-Item -ToSession over the existing session,
                ## then runs the swap from a remote-local stage dir.
                ## Eliminates the double-hop / remote-side UNC reach
                ## problem v1.8.5 hit — operator's $Log4jSrcIn is now
                ## interpreted as a CONTROLLER-side path (local disk
                ## or UNC the controller can read) instead of a path
                ## the remote has to reach itself.
                $remoteStageDir = $null
                if ($ProfileIn -eq 'Apache Log4j - Replace Vulnerable Jars') {
                    if ([string]::IsNullOrWhiteSpace($Log4jSrcIn)) {
                        return "FAIL: Log4j source path not set (textbox empty + no default)"
                    }
                    $localApi  = Join-Path $Log4jSrcIn 'log4j-api-2.25.4.jar'
                    $localCore = Join-Path $Log4jSrcIn 'log4j-core-2.25.4.jar'
                    if (-not (Test-Path -LiteralPath $localApi)) {
                        return "FAIL: source jar missing on controller: $localApi"
                    }
                    if (-not (Test-Path -LiteralPath $localCore)) {
                        return "FAIL: source jar missing on controller: $localCore"
                    }
                    $stageGuid      = [guid]::NewGuid().ToString('N').Substring(0,8)
                    $remoteStageDir = "C:\Windows\Temp\janet-log4j-stage-$stageGuid"
                    try {
                        Invoke-Command -Session $sess -ScriptBlock {
                            param($d)
                            New-Item -Path $d -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        } -ArgumentList $remoteStageDir -ErrorAction Stop
                        Copy-Item -Path $localApi  -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop
                        Copy-Item -Path $localCore -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop
                    } catch {
                        return "FAIL: stage push failed: $($_.Exception.Message)"
                    }
                    ## Substitute the remote-local stage dir into the
                    ## profile script so the swap reads from there
                    ## instead of the registry's hardcoded UNC.
                    $escPath    = $remoteStageDir.Replace("'", "''")
                    $updateText = [regex]::Replace($updateText, "(?<=\`$sourceShare\s*=\s*')[^']*", $escPath)
                }
                $verifyText = if ($prof.Verify) { [string]$prof.Verify.ToString() } else { '' }
                $combined = {
                    param($updateTxt, $verifyTxt)
                    $pre = $null
                    if ($verifyTxt) {
                        try { $pre = & ([scriptblock]::Create($verifyTxt)) } catch { $pre = $null }
                    }

                    $updateOut = & ([scriptblock]::Create($updateTxt))
                    $updateStr = if ($null -eq $updateOut) { 'OK (no output)' } else { [string]$updateOut }

                    $post = $null
                    if ($verifyTxt) {
                        try { $post = & ([scriptblock]::Create($verifyTxt)) } catch { $post = $null }
                    }

                    return @{ Update = $updateStr; Pre = $pre; Post = $post }
                }
                try {
                    $result = Invoke-Command -Session $sess -ScriptBlock $combined `
                                             -ArgumentList $updateText, $verifyText `
                                             -ErrorAction Stop
                    $updateStr = [string]$result.Update
                    $preV  = if ($result.Pre  -is [hashtable] -and $result.Pre.Version)  { [string]$result.Pre.Version }  else { 'n/a' }
                    $postV = if ($result.Post -is [hashtable] -and $result.Post.Version) { [string]$result.Post.Version } else { 'n/a' }
                    if ($preV -eq 'n/a' -and $postV -eq 'n/a') { return $updateStr }
                    $diff = if ($preV -eq $postV) { 'unchanged (async update may be in progress)' } else { "bumped: $preV -> $postV" }
                    return "$updateStr | $diff"
                } catch {
                    return "FAIL: $($_.Exception.Message)"
                }
            } finally {
                ## v1.8.6: clean up the per-host Log4j stage dir on
                ## the remote, regardless of whether the swap
                ## succeeded. Best-effort — leaving an inert
                ## C:\Windows\Temp\janet-log4j-stage-* if the cleanup
                ## fails is not a correctness issue.
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
        })
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($ProfileName)
        [void]$ps.AddArgument($profilesTable)
        [void]$ps.AddArgument([bool]$VerifyOnly)
        [void]$ps.AddArgument($cred)
        ## v1.8.5: Log4j source-share override (empty string for
        ## non-Log4j profiles — runspace ignores it).
        [void]$ps.AddArgument([string]$log4jSrcOverride)
        ## v1.9.0: package source path for IsPackage profiles
        ## (empty string for non-package profiles — runspace ignores).
        [void]$ps.AddArgument([string]$pkgSrcOverride)

        $async = $ps.BeginInvoke()
        $s.Jobs[$id] = @{ PS = $ps; Async = $async; Target = $t }
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = Get-NemDrainInterval
    $timer.Add_Tick({
        $s2     = Get-NemState
        $rtb2   = $s2.UI.Controls['updRtbLog']
        $lbl2   = $s2.UI.Controls['updLblStatus']
        $cancel2= $s2.UI.Controls['updBtnCancel']
        $theme2 = $s2.UI.Theme

        $counters = $s2.Jobs['_counters']
        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("$($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = 'OK'
                if ($resultStr -like 'FAIL*') { $auditResult = 'Failed' }
                Write-NemAudit -Action "$($counters['AuditPrefix']).Target" -Target $job.Target -Result $auditResult `
                    -Detail "profile=$($counters['ProfileName']) mode=$($counters['ModeLabel']) result=$resultStr"

                ## JANET centralized logging (v1.3.4: two-bucket model).
                ## Every plugin remediation is a VulnPatched. Detail carries
                ## vuln name + profile + mode for traceability.
                if ($null -ne (Get-JanetSession)) {
                    $janetResult = if ($auditResult -eq 'OK') { 'Success' } else { 'Failure' }
                    $itemCount = if ($auditResult -eq 'OK') { 1 } else { 0 }
                    $vulnDisplay = [string]$counters['VulnDisplay']
                    $profileName = [string]$counters['ProfileName']
                    $modeLabel   = [string]$counters['ModeLabel']
                    $janetDetail = "vuln=$vulnDisplay profile=$profileName mode=$modeLabel"
                    try { Write-JanetAction -Action 'VulnPatched' -Target $job.Target -Result $janetResult -ItemCount $itemCount -Detail $janetDetail } catch {}
                }

                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        $outstanding2 = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding2++ } }
        if ($outstanding2 -eq 0) {
            $this.Stop()
            $this.Dispose()
            $s2.UI.Controls.Remove('updTimer') | Out-Null

            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("Complete [$($counters['VulnDisplay'])] $($counters['ModeLabel']): $($counters['Success']) succeeded, $($counters['Failed']) failed`r`n")
            $rtb2.AppendText("========================================`r`n")
            Write-NemAudit -Action "$($counters['AuditPrefix']).End" -Target $counters['VulnDisplay'] -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed'])"

            ## Append one row to the daily Runs CSV on the log share.
            ## v1.5.0: rolled-up cards stash GroupKey + GroupMembers in
            ## counters; Write-NemRunSummary fans out one CSV row per
            ## member when those are populated, otherwise writes one row
            ## with the original Scope (per-vuln behavior unchanged).
            try {
                $grpKey  = ''
                $grpMems = @()
                if ($counters.ContainsKey('GroupKey'))     { $grpKey  = [string]$counters['GroupKey'] }
                if ($counters.ContainsKey('GroupMembers')) { $grpMems = @($counters['GroupMembers']) }
                Write-NemRunSummary -Action $counters['AuditPrefix'] `
                    -Scope       $counters['VulnDisplay'] `
                    -Profile     $counters['ProfileName'] `
                    -Mode        $counters['ModeLabel'] `
                    -HostsTotal  ([int]$counters['Total']) `
                    -Success     ([int]$counters['Success']) `
                    -Failed      ([int]$counters['Failed']) `
                    -StartedAt   $counters['StartedAt'] `
                    -GroupKey    $grpKey `
                    -GroupMembers $grpMems
            } catch {
                Write-NemAudit -Action 'RunsCsv.Failed' -Target $counters['VulnDisplay'] -Result 'Failed' `
                    -Detail $_.Exception.Message
            }

            Set-NemVulnCardRunEnabled -Enabled $true
            $cancel2.Enabled = $false
            $lbl2.Text = "$($counters['Success']) succeeded, $($counters['Failed']) failed"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $timer.Start()
    $s.UI.Controls['updTimer'] = $timer
}

function global:Set-NemVulnCardRunEnabled {
    <#
        Toggle every card's Run button enabled/disabled.  Called when a run
        starts/ends/cancels.  Cards that had no matched profile stay disabled
        regardless of the request, so the "no profile" visual state is
        preserved.
    #>
    param([bool]$Enabled)
    $s = Get-NemState
    $cards = $s.UI.Controls['updVulnCards']
    if (-not $cards) { return }
    foreach ($c in $cards) {
        $hasProf = ($c.Vuln.ProfileNames -and @($c.Vuln.ProfileNames).Count -gt 0)
        $effective = $Enabled -and $hasProf
        $c.Run.Enabled = $effective
        if ($c.ContainsKey('Verify') -and $c.Verify) { $c.Verify.Enabled = $effective }
    }
}

function global:Start-NemRebootRun {
    <#
    .SYNOPSIS
        Dispatch a remote reboot (5-minute warning) to all hosts in a Reboot
        vuln group.  shutdown.exe runs LOCALLY with /m \\TARGET so no WinRM
        session is needed for the dispatch itself.  Mirrors the drain-timer
        pattern of Start-NemVulnRun.
    .PARAMETER VulnDisplay
        Display name of the plugin (logged in audit).
    .PARAMETER HostList
        Array of target computer names.
    .PARAMETER WarningText
        Message displayed on the remote workstation's shutdown dialog.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $VulnDisplay,
        [Parameter(Mandatory)] [string[]] $HostList,
        [string] $WarningText = 'This workstation will reboot in 5 minutes for required security updates. Save your work now.'
    )

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls

    $rtb    = $ctrl['updRtbLog']
    $lbl    = $ctrl['updLblStatus']
    $cancel = $ctrl['updBtnCancel']

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $outstanding = 0
    foreach ($k in $s.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
    if ($outstanding -gt 0 -or $s.UI.Controls.ContainsKey('rebTimer') -or $s.UI.Controls.ContainsKey('updTimer')) {
        [System.Windows.Forms.MessageBox]::Show(
            'A run is already in progress. Cancel or wait for it to finish.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $targets = @($HostList | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
    if ($targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No hosts in reboot group for '$VulnDisplay'.",
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    Set-NemVulnCardRunEnabled -Enabled $false
    $cancel.Enabled = $true
    $lbl.Text      = "Scheduling reboot on $($targets.Count) host(s) for [$VulnDisplay]..."
    $lbl.ForeColor = $theme.Warning

    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("REBOOT  : $VulnDisplay`r`n")
    $rtb.AppendText("Warning : $WarningText`r`n")
    $rtb.AppendText("Hosts   : $($targets.Count)`r`n")
    $rtb.AppendText("========================================`r`n")
    Write-NemAudit -Action 'Reboot.Start' -Target $VulnDisplay -Result 'OK' `
        -Detail "hosts=$($targets.Count) warning=$WarningText"

    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success     = 0
        Failed      = 0
        Total       = $targets.Count
        VulnDisplay = $VulnDisplay
        StartedAt   = Get-Date
    }

    ## v1.8.8: serial preflight removed (see Start-NemVulnRun). The
    ## all-unreachable bailout is gone with it — the drain timer will
    ## report unreachables as they complete, then complete-and-reset
    ## via its own end-of-run path when all jobs drain.

    $warnCopy = $WarningText  ## capture for closure

    foreach ($t in $targets) {
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        [void]$ps.AddScript({
            param($Target, $WarnMsg)
            $shutdown = "$env:WinDir\System32\shutdown.exe"
            $shutArgs = @('/m', "\\$Target", '/r', '/t', '300', '/c', $WarnMsg)
            try {
                $proc = Start-Process -FilePath $shutdown -ArgumentList $shutArgs -Wait -PassThru -NoNewWindow
                if ($proc.ExitCode -eq 0) { return 'OK (reboot scheduled, 300s warning)' }
                elseif ($proc.ExitCode -eq 1190) { return 'OK (already scheduled, rc=1190)' }
                else { return "FAIL: shutdown.exe exit code $($proc.ExitCode)" }
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
        })
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($warnCopy)

        $async = $ps.BeginInvoke()
        $s.Jobs[$id] = @{ PS = $ps; Async = $async; Target = $t }
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = Get-NemDrainInterval
    $timer.Add_Tick({
        $s2      = Get-NemState
        $rtb2    = $s2.UI.Controls['updRtbLog']
        $lbl2    = $s2.UI.Controls['updLblStatus']
        $cancel2 = $s2.UI.Controls['updBtnCancel']
        $theme2  = $s2.UI.Theme
        $counters = $s2.Jobs['_counters']

        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("$($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = if ($resultStr -like 'FAIL*') { 'Failed' } else { 'OK' }
                Write-NemAudit -Action 'Reboot.Target' -Target $job.Target -Result $auditResult `
                    -Detail "result=$resultStr"
                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        $outstanding2 = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding2++ } }
        if ($outstanding2 -eq 0) {
            $this.Stop()
            $this.Dispose()
            $s2.UI.Controls.Remove('rebTimer') | Out-Null

            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("Reboot Complete [$($counters['VulnDisplay'])]: $($counters['Success']) scheduled, $($counters['Failed']) failed`r`n")
            $rtb2.AppendText("========================================`r`n")
            Write-NemAudit -Action 'Reboot.End' -Target $counters['VulnDisplay'] -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed'])"

            Set-NemVulnCardRunEnabled -Enabled $true
            $cancel2.Enabled = $false
            $lbl2.Text = "$($counters['Success']) reboots scheduled, $($counters['Failed']) failed"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $timer.Start()
    $s.UI.Controls['rebTimer'] = $timer
}

function global:Start-NemRebootVerify {
    <#
    .SYNOPSIS
        For each host in the supplied list: ping until reachable (up to 10min),
        then check via Invoke-Command whether the reboot-pending key is cleared
        and return the current OS build number.
    .PARAMETER VulnDisplay
        Display name of the plugin (logged in audit).
    .PARAMETER HostList
        Array of target computer names to verify post-reboot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $VulnDisplay,
        [Parameter(Mandatory)] [string[]] $HostList
    )

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls

    $rtb    = $ctrl['updRtbLog']
    $lbl    = $ctrl['updLblStatus']
    $cancel = $ctrl['updBtnCancel']

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $outstanding = 0
    foreach ($k in $s.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
    if ($outstanding -gt 0 -or $s.UI.Controls.ContainsKey('rebVerifyTimer') -or $s.UI.Controls.ContainsKey('updTimer') -or $s.UI.Controls.ContainsKey('rebTimer')) {
        [System.Windows.Forms.MessageBox]::Show(
            'A run is already in progress. Cancel or wait for it to finish.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $targets = @($HostList | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
    if ($targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No hosts supplied for reboot verify of '$VulnDisplay'.",
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    Set-NemVulnCardRunEnabled -Enabled $false
    $cancel.Enabled = $true
    $lbl.Text      = "Verifying post-reboot state on $($targets.Count) host(s)..."
    $lbl.ForeColor = $theme.Warning

    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("REBOOT VERIFY: $VulnDisplay`r`n")
    $rtb.AppendText("Hosts         : $($targets.Count)`r`n")
    $rtb.AppendText("========================================`r`n")
    Write-NemAudit -Action 'Reboot.Verify.Start' -Target $VulnDisplay -Result 'OK' `
        -Detail "hosts=$($targets.Count)"

    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success     = 0
        Failed      = 0
        Total       = $targets.Count
        VulnDisplay = $VulnDisplay
        StartedAt   = Get-Date
    }

    $cred = $s.Credentials

    foreach ($t in $targets) {
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        [void]$ps.AddScript({
            param($TargetIn, $CredIn)

            ## v1.4.0 (WPT-ported): TCP probe loop instead of ICMP.
            ## Up to 10 minutes, poll every 15 seconds. ICMP is often
            ## blocked on AFNET, which made the verifier report stale
            ## machines as "still rebooting" indefinitely.
            $deadline = (Get-Date).AddMinutes(10)
            $reachable = $false
            while ((Get-Date) -lt $deadline) {
                foreach ($port in 5985, 445) {
                    $tc = $null
                    try {
                        $tc  = New-Object System.Net.Sockets.TcpClient
                        $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
                    } catch {}
                    finally { if ($tc) { try { $tc.Close() } catch {} } }
                    if ($reachable) { break }
                }
                if ($reachable) { break }
                Start-Sleep -Seconds 15
            }

            if (-not $reachable) {
                return "FAIL: UNREACHABLE after 10min wait (TCP 5985/445 - still rebooting or offline)"
            }

            ## Connected — open a bounded PSSession and check reboot-pending
            ## key + build number. Bounded timeouts prevent the hung-WinRM
            ## scenario where a machine answers TCP but the WSMan service
            ## itself isn't fully up yet (common ~30s post-boot).
            $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
            $sessArgs = @{
                ComputerName   = $TargetIn
                SessionOption  = $wsOpt
                Authentication = 'Negotiate'
                ErrorAction    = 'Stop'
            }
            if ($CredIn) { $sessArgs['Credential'] = $CredIn }
            $sess = $null
            try { $sess = New-PSSession @sessArgs }
            catch {
                $sessErr = $_.Exception.Message
                ## v1.8.3: NetBIOS fallback on Negotiate auth failures.
                ## 0x80090322 = SEC_E_WRONG_PRINCIPAL (broken SPN / DNS-name
                ## mismatch — Kerberos can't form a ticket). "Access is denied"
                ## from a Negotiate handshake also fits this bucket. Retrying
                ## with the NetBIOS short name (everything before first '.')
                ## forces NTLM, which has different SPN requirements and
                ## usually works when Kerberos doesn't. Only retry when we
                ## actually have an FQDN to strip.
                if ($TargetIn -match '\.' -and (
                        $sessErr -match '0x80090322' -or
                        $sessErr -match 'Negotiate authentication' -or
                        $sessErr -match 'Access is denied'
                    )) {
                    $nbName = ($TargetIn -split '\.')[0]
                    $sessArgs2 = @{} + $sessArgs
                    $sessArgs2['ComputerName'] = $nbName
                    try {
                        $sess = New-PSSession @sessArgs2
                    } catch {
                        return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
                    }
                } else {
                    return "FAIL: Session - $sessErr"
                }
            }

            try {
                $result = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
                    $pendingPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                    $stillPending = Test-Path -Path $pendingPath

                    $ntKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                    $ntProps = Get-ItemProperty -Path $ntKey -ErrorAction SilentlyContinue
                    $build = if ($ntProps -and $ntProps.CurrentBuildNumber) { [string]$ntProps.CurrentBuildNumber } else { 'unknown' }
                    $ubr   = if ($ntProps -and $ntProps.UBR)               { [string]$ntProps.UBR }               else { '0' }

                    return @{ StillPending = $stillPending; Build = $build; UBR = $ubr }
                }

                if ($result.StillPending) {
                    return "FAIL: still pending reboot (Build=$($result.Build).$($result.UBR))"
                }
                return "OK (Build=$($result.Build).$($result.UBR), RebootPending=false)"
            } catch {
                return "FAIL: $($_.Exception.Message)"
            } finally {
                if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
            }
        })
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($cred)

        $async = $ps.BeginInvoke()
        $s.Jobs[$id] = @{ PS = $ps; Async = $async; Target = $t }
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = Get-NemDrainInterval
    $timer.Add_Tick({
        $s2      = Get-NemState
        $rtb2    = $s2.UI.Controls['updRtbLog']
        $lbl2    = $s2.UI.Controls['updLblStatus']
        $cancel2 = $s2.UI.Controls['updBtnCancel']
        $theme2  = $s2.UI.Theme
        $counters = $s2.Jobs['_counters']

        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("$($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = if ($resultStr -like 'FAIL*') { 'Failed' } else { 'OK' }
                Write-NemAudit -Action 'Reboot.Verify.Target' -Target $job.Target -Result $auditResult `
                    -Detail "result=$resultStr"
                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        $outstanding2 = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding2++ } }
        if ($outstanding2 -eq 0) {
            $this.Stop()
            $this.Dispose()
            $s2.UI.Controls.Remove('rebVerifyTimer') | Out-Null

            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("Reboot Verify Complete [$($counters['VulnDisplay'])]: $($counters['Success']) OK, $($counters['Failed']) failed`r`n")
            $rtb2.AppendText("========================================`r`n")
            Write-NemAudit -Action 'Reboot.Verify.End' -Target $counters['VulnDisplay'] -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed'])"

            Set-NemVulnCardRunEnabled -Enabled $true
            $cancel2.Enabled = $false
            $lbl2.Text = "$($counters['Success']) OK, $($counters['Failed']) failed (Reboot Verify)"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $timer.Start()
    $s.UI.Controls['rebVerifyTimer'] = $timer
}

function global:Start-NemServicesPreflight {
    <#
    .SYNOPSIS
        Ensure winrm, Winmgmt, and RemoteRegistry are Running + Automatic on
        every target in $s.Targets. Narrow ACAS-only pre-flight — not a
        general heal tab. Dispatches via the shared runspace pool; drains via
        a 250 ms WinForms timer keyed 'preflightTimer'.
    #>
    [CmdletBinding()]
    param()

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls
    $rtb   = $ctrl['updRtbLog']
    $lbl   = $ctrl['updLblStatus']

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Guard: another run (vuln / reboot / preflight) already active.
    $outstanding = 0
    foreach ($k in $s.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
    if ($outstanding -gt 0 -or
        $ctrl.ContainsKey('updTimer') -or
        $ctrl.ContainsKey('rebTimer') -or
        $ctrl.ContainsKey('rebVerifyTimer') -or
        $ctrl.ContainsKey('preflightTimer')) {
        [System.Windows.Forms.MessageBox]::Show(
            'A run is already in progress. Cancel or wait for it to finish.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $targets = @($s.Targets | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
    $N = $targets.Count
    if ($N -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'No targets. Import an ACAS CSV on the Targets tab first.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Pre-flight will start + set to Automatic the winrm, Winmgmt, and RemoteRegistry services on $N target(s). Continue?",
        'ACAS Nemesis - Pre-Flight Services', 'YesNo', 'Question')
    if ($ans -ne 'Yes') { return }

    Set-NemVulnCardRunEnabled -Enabled $false
    $ctrl['updBtnPreflight'].Enabled = $false
    $ctrl['updBtnRunAll'].Enabled    = $false
    $ctrl['updBtnCancel'].Enabled    = $true
    $lbl.Text      = "Pre-flight services: $N target(s)..."
    $lbl.ForeColor = $theme.Warning

    $rtb.SelectionColor = $theme.Accent1
    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("PRE-FLIGHT SERVICES: $N target(s)`r`n")
    $rtb.AppendText("========================================`r`n")
    $rtb.SelectionColor = $rtb.ForeColor

    Write-NemAudit -Action 'Preflight.Services.Start' -Result 'OK' -Detail "targets=$N"

    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success   = 0
        Failed    = 0
        Total     = $N
        StartedAt = Get-Date
    }

    foreach ($t in $targets) {
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        [void]$ps.AddScript({
            param($Target)
            $names   = @('winrm', 'Winmgmt', 'RemoteRegistry')
            $changes = @()
            $errors  = @()
            foreach ($n in $names) {
                try {
                    $svc = Get-Service -ComputerName $Target -Name $n -ErrorAction Stop
                    $needStart = $svc.Status   -ne 'Running'
                    $needAuto  = $svc.StartType -ne 'Automatic'
                    if ($needStart -or $needAuto) {
                        [void](Set-Service -ComputerName $Target -Name $n `
                            -StartupType Automatic -Status Running -PassThru -ErrorAction Stop)
                        $changes += $n
                    }
                } catch {
                    $errors += "$n ($($_.Exception.Message))"
                }
            }
            if ($errors.Count  -gt 0) { return 'FAIL: ' + ($errors  -join '; ') }
            if ($changes.Count -gt 0) { return 'OK (fixed: ' + ($changes -join ', ') + ')' }
            return 'OK (all three already Running + Automatic)'
        })
        [void]$ps.AddArgument($t)

        $async = $ps.BeginInvoke()
        $s.Jobs[$id] = @{ PS = $ps; Async = $async; Target = $t }
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 250
    $timer.Add_Tick({
        $s2      = Get-NemState
        $rtb2    = $s2.UI.Controls['updRtbLog']
        $lbl2    = $s2.UI.Controls['updLblStatus']
        $theme2  = $s2.UI.Theme
        $ctrl2   = $s2.UI.Controls
        $counters = $s2.Jobs['_counters']

        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("$($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = if ($resultStr -like 'FAIL*') { 'Failed' } else { 'OK' }
                Write-NemAudit -Action 'Preflight.Services.Target' -Target $job.Target `
                    -Result $auditResult -Detail "result=$resultStr"

                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        $outstanding2 = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding2++ } }
        if ($outstanding2 -eq 0) {
            $this.Stop()
            $this.Dispose()
            $ctrl2.Remove('preflightTimer') | Out-Null

            $rtb2.SelectionColor = $theme2.Accent1
            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("PRE-FLIGHT COMPLETE: $($counters['Success']) OK, $($counters['Failed']) failed`r`n")
            $rtb2.AppendText("========================================`r`n")
            $rtb2.SelectionColor = $rtb2.ForeColor

            Write-NemAudit -Action 'Preflight.Services.End' -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed'])"

            Set-NemVulnCardRunEnabled -Enabled $true
            $ctrl2['updBtnPreflight'].Enabled = $true
            $ctrl2['updBtnRunAll'].Enabled    = $true
            $ctrl2['updBtnCancel'].Enabled    = $false
            $lbl2.Text = "Pre-flight: $($counters['Success']) OK, $($counters['Failed']) failed"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $timer.Start()
    $s.UI.Controls['preflightTimer'] = $timer
}

function global:Start-NemRunAll {
    <#
    .SYNOPSIS
        Sequentially invoke every card's Run action on the Updater tab.
    .DESCRIPTION
        Builds a queue of all card Panels in $s.UI.Controls['updCardsHost'].
        Each card's Run button is located by its Tag (see card builders);
        Run All clicks them one at a time, waiting for $s.Jobs to drain
        before moving to the next card. Reboot cards: only the "Reboot Now"
        button is triggered — Verify Post-Reboot stays manual.
    #>
    [CmdletBinding()]
    param()

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls
    $rtb   = $ctrl['updRtbLog']
    $lbl   = $ctrl['updLblStatus']
    $btnRunAll  = $ctrl['updBtnRunAll']
    $btnCancel  = $ctrl['updBtnCancel']
    $host2      = $ctrl['updCardsHost']

    if (-not $host2) {
        [System.Windows.Forms.MessageBox]::Show('No cards host.','ACAS Nemesis','OK','Error') | Out-Null
        return
    }

    ## Build queue — each entry has a reference to the card and its primary Run button.
    ## Card builders register the primary Run button on $card.Tag.RunButton (Patchable/Experimental)
    ## or $card.Tag.RebootButton (Reboot cards). Skip any panel that doesn't expose one.
    $queue = [System.Collections.ArrayList]::new()
    foreach ($c in @($host2.Controls)) {
        if ($c -isnot [System.Windows.Forms.Panel]) { continue }
        if (-not $c.Tag) { continue }
        $btn = $null
        if ($c.Tag.PSObject.Properties['RunButton']    -and $c.Tag.RunButton)    { $btn = $c.Tag.RunButton }
        elseif ($c.Tag.PSObject.Properties['RebootButton'] -and $c.Tag.RebootButton) { $btn = $c.Tag.RebootButton }
        if ($btn) { [void]$queue.Add(@{ Card = $c; Button = $btn }) }
    }

    if ($queue.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'No runnable cards. Import an ACAS CSV and select findings first.',
            'ACAS Nemesis','OK','Warning') | Out-Null
        return
    }

    ## Confirm
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Run All will sequentially execute $($queue.Count) card action(s) on the Updater tab. Continue?",
        'ACAS Nemesis - Confirm Run All', 'YesNo', 'Question')
    if ($ans -ne 'Yes') { return }

    $rtb.SelectionColor = $theme.Accent1
    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("RUN ALL: sequencing $($queue.Count) cards`r`n")
    $rtb.AppendText("========================================`r`n")
    $rtb.SelectionColor = $rtb.ForeColor

    Write-NemAudit -Action 'RunAll.Start' -Result 'OK' -Detail "queueSize=$($queue.Count)"

    ## Stash queue on state so the orchestrator timer can read it.
    $s['RunAllQueue']     = $queue
    $s['RunAllTotal']     = $queue.Count
    $s['RunAllDoneCount'] = 0
    $btnRunAll.Enabled = $false
    $btnCancel.Enabled = $true
    $lbl.Text = "Run All: 0 of $($queue.Count) completed, starting..."
    $lbl.ForeColor = $theme.Warning

    ## Kick off card 1 immediately.
    $first = $queue[0]
    [void]$queue.RemoveAt(0)
    try { $first.Button.PerformClick() }
    catch {
        Write-NemAudit -Action 'RunAll.StepFail' -Result 'Failed' -Detail $_.Exception.Message
    }

    ## Orchestrator timer — polls every 500ms. When $s.Jobs is empty AND the
    ## drain timers have cleared, dequeue next card and click it.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    $timer.Add_Tick({
        $s2 = Get-NemState
        $q  = $s2['RunAllQueue']
        $t2 = $s2.UI.Theme

        ## Cancel detection: if someone set RunAllCancelled flag, stop.
        if ($s2['RunAllCancelled']) {
            $this.Stop(); $this.Dispose()
            $s2.UI.Controls.Remove('runAllTimer') | Out-Null
            $s2.Remove('RunAllQueue')        | Out-Null
            $s2.Remove('RunAllCancelled')    | Out-Null
            $s2.UI.Controls['updBtnRunAll'].Enabled = $true
            $rtb2 = $s2.UI.Controls['updRtbLog']
            $rtb2.SelectionColor = $t2.Warning
            $rtb2.AppendText("RUN ALL: cancelled`r`n")
            $rtb2.SelectionColor = $rtb2.ForeColor
            Write-NemAudit -Action 'RunAll.End' -Result 'Cancelled' `
                -Detail "done=$($s2['RunAllDoneCount']) of $($s2['RunAllTotal'])"
            $s2.UI.Controls['updLblStatus'].Text = "Run All cancelled ($($s2['RunAllDoneCount']) of $($s2['RunAllTotal']) completed)"
            return
        }

        ## Still work in flight? Any job keys other than the _counters bucket?
        $stillRunning = $false
        foreach ($k in @($s2.Jobs.Keys)) { if ($k -ne '_counters') { $stillRunning = $true; break } }
        if ($stillRunning) { return }

        ## Also wait for the per-card drain timer to have stopped itself.
        if ($s2.UI.Controls.ContainsKey('updTimer'))       { return }
        if ($s2.UI.Controls.ContainsKey('rebTimer'))       { return }
        if ($s2.UI.Controls.ContainsKey('rebVerifyTimer')) { return }

        ## Previous card finished. Record it.
        $s2['RunAllDoneCount'] = [int]$s2['RunAllDoneCount'] + 1

        if ($q -and $q.Count -gt 0) {
            ## Dequeue next and click it
            $next = $q[0]
            [void]$q.RemoveAt(0)
            $s2.UI.Controls['updLblStatus'].Text =
                "Run All: $($s2['RunAllDoneCount']) of $($s2['RunAllTotal']) completed, starting next..."
            $s2.UI.Controls['updLblStatus'].ForeColor = $t2.Warning
            try { $next.Button.PerformClick() }
            catch {
                $rtb2 = $s2.UI.Controls['updRtbLog']
                $rtb2.SelectionColor = $t2.Danger
                $rtb2.AppendText("RUN ALL: step dispatch failed - $($_.Exception.Message)`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor
                Write-NemAudit -Action 'RunAll.StepFail' -Result 'Failed' -Detail $_.Exception.Message
            }
        } else {
            ## Queue empty — done.
            $this.Stop(); $this.Dispose()
            $s2.UI.Controls.Remove('runAllTimer') | Out-Null
            $s2.Remove('RunAllQueue') | Out-Null
            $rtb2 = $s2.UI.Controls['updRtbLog']
            $rtb2.SelectionColor = $t2.Success
            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("RUN ALL: complete ($($s2['RunAllDoneCount']) cards)`r`n")
            $rtb2.AppendText("========================================`r`n")
            $rtb2.SelectionColor = $rtb2.ForeColor
            Write-NemAudit -Action 'RunAll.End' -Result 'OK' `
                -Detail "done=$($s2['RunAllDoneCount']) of $($s2['RunAllTotal'])"
            $s2.UI.Controls['updLblStatus'].Text = "Run All complete ($($s2['RunAllDoneCount']) cards)"
            $s2.UI.Controls['updLblStatus'].ForeColor = $t2.Success
            $s2.UI.Controls['updBtnRunAll'].Enabled = $true
            $s2.UI.Controls['updBtnCancel'].Enabled = $false
        }
    }.GetNewClosure())
    $timer.Start()
    $s.UI.Controls['runAllTimer'] = $timer
}

function global:Start-NemBulkRunAll {
    <#
    .SYNOPSIS
        Dispatch every patchable card's (host, profile) tuples into the
        runspace pool IN PARALLEL. Mirrors WPT's bulk-scan/bulk-patch
        engine: one job per (target, profile), all submitted up-front,
        single drain timer aggregates results across the whole batch.
    .DESCRIPTION
        Functional difference from Start-NemRunAll: that runs cards
        sequentially (one card's host fan-out completes before the next
        starts). This runs ALL cards' hosts concurrently — limited only
        by the runspace pool max ($script:NemPoolMaxThreads). Reboot
        cards are skipped — those need the explicit warning dialog.

        Single-run lock shares with Start-NemVulnRun: only one
        bulk-or-card run at a time. The same Cancel button stops it.

        Per job, the scriptblock matches Start-NemVulnRun (TCP probe +
        bounded PSSession + Negotiate auth + remote scriptblock
        rehydration), but each job carries its own (VulnDisplay,
        ProfileName) context so the drain timer can label log lines and
        audit rows correctly across the heterogeneous batch.
    .PARAMETER VerifyOnly
        Run only each profile's Verify scriptblock instead of the full
        update + verify cycle. Useful for "did all my prior updates
        finish?" sweeps.
    #>
    [CmdletBinding()]
    param([switch]$VerifyOnly)

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls

    $rtb       = $ctrl['updRtbLog']
    $lbl       = $ctrl['updLblStatus']
    $cancel    = $ctrl['updBtnCancel']
    $cardsHost = $ctrl['updCardsHost']

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $cardsHost) {
        [System.Windows.Forms.MessageBox]::Show('No cards host.','ACAS Nemesis','OK','Error') | Out-Null
        return
    }

    ## Single-run lock — bulk shares the same slot as per-card runs.
    $outstanding = 0
    foreach ($k in $s.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
    if ($outstanding -gt 0 -or $ctrl.ContainsKey('updTimer')) {
        [System.Windows.Forms.MessageBox]::Show(
            'A vulnerability run is already in progress. Use Cancel, or wait for it to finish.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Walk every card panel, build the flat job list. One entry per
    ## (host, profile) tuple. Skip reboot cards and cards with no profile.
    $jobsToDispatch = [System.Collections.ArrayList]::new()
    $cardCount      = 0
    $hostUnion      = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in @($cardsHost.Controls)) {
        if ($c -isnot [System.Windows.Forms.Panel]) { continue }
        if (-not $c.Tag) { continue }
        ## Reboot cards expose RebootButton not RunButton — skip.
        if ($c.Tag.PSObject.Properties['RebootButton'] -and $c.Tag.RebootButton) { continue }
        if (-not $c.Tag.PSObject.Properties['Vuln']) { continue }
        $vuln = $c.Tag.Vuln
        if (-not $vuln) { continue }
        $names = @($vuln.ProfileNames)
        if ($names.Count -eq 0) { continue }

        ## Honor the per-card dropdown selection if present.
        $profileName = $names[0]
        if ($c.Tag.PSObject.Properties['ProfileCombo'] -and $c.Tag.ProfileCombo -and $c.Tag.ProfileCombo.SelectedItem) {
            $profileName = [string]$c.Tag.ProfileCombo.SelectedItem
        }

        $hosts = @($vuln.Hosts | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
        if ($hosts.Count -eq 0) { continue }

        $cardCount++
        foreach ($t in $hosts) {
            [void]$hostUnion.Add($t)
            [void]$jobsToDispatch.Add(@{
                Target      = $t
                ProfileName = $profileName
                VulnKey     = [string]$vuln.PluginKey
                VulnDisplay = [string]$vuln.DisplayName
            })
        }
    }

    if ($jobsToDispatch.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'No bulk-runnable cards. Import an ACAS CSV and select findings first.',
            'ACAS Nemesis','OK','Warning') | Out-Null
        return
    }

    $modeLabel   = if ($VerifyOnly) { 'Verify' } else { 'Update' }
    $auditPrefix = if ($VerifyOnly) { 'BulkVerify' } else { 'BulkRun' }
    $hostCount   = $hostUnion.Count

    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Bulk $modeLabel will dispatch $($jobsToDispatch.Count) job(s) across $cardCount card(s) and $hostCount unique host(s) IN PARALLEL.`r`n`r`nPool max threads: $(Get-NemPoolMax). Continue?",
        "ACAS Nemesis - Confirm Bulk $modeLabel", 'YesNo', 'Question')
    if ($ans -ne 'Yes') { return }

    Set-NemVulnCardRunEnabled -Enabled $false
    if ($ctrl.ContainsKey('updBtnRunAll'))  { $ctrl['updBtnRunAll'].Enabled  = $false }
    if ($ctrl.ContainsKey('updBtnBulkRun')) { $ctrl['updBtnBulkRun'].Enabled = $false }
    $cancel.Enabled = $true
    $lbl.Text       = "$modeLabel BULK: $($jobsToDispatch.Count) job(s) across $cardCount card(s), $hostCount host(s)..."
    $lbl.ForeColor  = $theme.Warning

    $rtb.SelectionColor = $theme.Accent1
    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("BULK $($modeLabel.ToUpper()): $cardCount card(s), $hostCount host(s), $($jobsToDispatch.Count) job(s)`r`n")
    $rtb.AppendText("Pool max threads: $(Get-NemPoolMax)`r`n")
    $rtb.AppendText("========================================`r`n")
    $rtb.SelectionColor = $rtb.ForeColor

    Write-NemAudit -Action "$auditPrefix.Start" -Result 'OK' `
        -Detail "cards=$cardCount hosts=$hostCount jobs=$($jobsToDispatch.Count) mode=$modeLabel"

    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success     = 0
        Failed      = 0
        Total       = $jobsToDispatch.Count
        CardCount   = $cardCount
        HostCount   = $hostCount
        ModeLabel   = $modeLabel
        AuditPrefix = $auditPrefix
        StartedAt   = Get-Date
        IsBulk      = $true
        VulnDisplay = "Bulk ($cardCount cards / $hostCount hosts)"
    }

    ## v1.8.8: serial preflight removed (see Start-NemVulnRun). For
    ## bulk runs the cost is even worse — N cards × M hosts probed
    ## sequentially on the UI thread. Inline runspace probes handle
    ## reachability in parallel via the pool.

    $profilesTable    = Get-WptAppUpdateProfiles
    $cred             = $s.Credentials
    ## v1.8.5: Log4j source-share override resolved on the controller
    ## side, fed to each runspace below. Same pattern as
    ## Start-NemVulnRun.
    $log4jSrcOverride = Get-NemLog4jSourcePath

    ## v1.9.0: pre-resolve package paths for every IsPackage profile in
    ## $profilesTable so the per-job loop below can hand each runspace
    ## the right value via AddArgument. Bulk runs are heterogeneous —
    ## different jobs may target different IsPackage profiles, so the
    ## map is profile-keyed.
    $pkgSrcByProfile = @{}
    foreach ($pn in @($profilesTable.Keys)) {
        $pe = $profilesTable[$pn]
        $isPkg = $false
        try {
            if ($pe -is [hashtable] -and $pe.ContainsKey('IsPackage')) { $isPkg = [bool]$pe['IsPackage'] }
            elseif ($pe.PSObject -and $pe.PSObject.Properties['IsPackage']) { $isPkg = [bool]$pe.IsPackage }
        } catch {}
        if (-not $isPkg) { continue }
        $folder = $null
        if ($pe -is [hashtable] -and $pe.ContainsKey('PackageFolder')) { $folder = [string]$pe['PackageFolder'] }
        elseif ($pe.PSObject -and $pe.PSObject.Properties['PackageFolder']) { $folder = [string]$pe.PackageFolder }
        if ($folder) {
            $resolved = Get-NemPackageSourcePath -FolderName $folder
            if ($resolved) { $pkgSrcByProfile[$pn] = $resolved }
        }
    }

    ## Submit every job up-front. Pool throttles concurrency.
    foreach ($j in $jobsToDispatch) {
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        ## Per-job package source override. Empty string when this job's
        ## profile is not an IsPackage profile or its package folder
        ## did not resolve operator-side.
        $pkgSrcForJob = ''
        if ($pkgSrcByProfile.ContainsKey([string]$j.ProfileName)) {
            $pkgSrcForJob = [string]$pkgSrcByProfile[[string]$j.ProfileName]
        }

        ## Same scriptblock body as Start-NemVulnRun. Kept inline here
        ## (rather than DRY-ed into a shared script var) because runspaces
        ## don't share script-scope reliably and the duplication is cheap.
        [void]$ps.AddScript({
            param($TargetIn, $ProfileIn, $UpdateProfilesTable, $VerifyOnlyIn, $CredIn, $Log4jSrcIn, $PkgSrcIn)
            $prof = $UpdateProfilesTable[$ProfileIn]
            if (-not $prof) { return "FAIL: Unknown profile '$ProfileIn'." }

            ## v1.9.0: package-profile guard (mirror Start-NemVulnRun).
            $isPkgProfile = $false
            try {
                if ($prof -is [hashtable] -and $prof.ContainsKey('IsPackage')) { $isPkgProfile = [bool]$prof['IsPackage'] }
                elseif ($prof.PSObject -and $prof.PSObject.Properties['IsPackage']) { $isPkgProfile = [bool]$prof.IsPackage }
            } catch {}
            if ($isPkgProfile -and -not $VerifyOnlyIn) {
                if ([string]::IsNullOrWhiteSpace($PkgSrcIn)) {
                    return "FAIL: Package source not resolved on controller (Tools\Packages\<folder>\Deploy-Application.ps1 missing?)"
                }
                if (-not (Test-Path -LiteralPath $PkgSrcIn)) {
                    return "FAIL: Package source not found on controller: $PkgSrcIn"
                }
            }

            $reachable = $false
            foreach ($port in 5985, 445) {
                $tc = $null
                try {
                    $tc  = New-Object System.Net.Sockets.TcpClient
                    $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
                } catch {}
                finally { if ($tc) { try { $tc.Close() } catch {} } }
                if ($reachable) { break }
            }
            if (-not $reachable) { return "FAIL: unreachable (TCP 5985/445)" }

            $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
            $sessArgs = @{
                ComputerName   = $TargetIn
                SessionOption  = $wsOpt
                Authentication = 'Negotiate'
                ErrorAction    = 'Stop'
            }
            if ($CredIn) { $sessArgs['Credential'] = $CredIn }
            $sess = $null
            try { $sess = New-PSSession @sessArgs }
            catch {
                $sessErr = $_.Exception.Message
                ## v1.8.3: NetBIOS fallback on Negotiate auth failures.
                ## 0x80090322 = SEC_E_WRONG_PRINCIPAL (broken SPN / DNS-name
                ## mismatch — Kerberos can't form a ticket). "Access is denied"
                ## from a Negotiate handshake also fits this bucket. Retrying
                ## with the NetBIOS short name (everything before first '.')
                ## forces NTLM, which has different SPN requirements and
                ## usually works when Kerberos doesn't. Only retry when we
                ## actually have an FQDN to strip.
                if ($TargetIn -match '\.' -and (
                        $sessErr -match '0x80090322' -or
                        $sessErr -match 'Negotiate authentication' -or
                        $sessErr -match 'Access is denied'
                    )) {
                    $nbName = ($TargetIn -split '\.')[0]
                    $sessArgs2 = @{} + $sessArgs
                    $sessArgs2['ComputerName'] = $nbName
                    try {
                        $sess = New-PSSession @sessArgs2
                    } catch {
                        return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
                    }
                } else {
                    return "FAIL: Session - $sessErr"
                }
            }

            try {
                if ($VerifyOnlyIn) {
                    if (-not $prof.Verify) { return 'SKIP: profile has no Verify block' }
                    try {
                        $out = Invoke-Command -Session $sess -ScriptBlock $prof.Verify -ErrorAction Stop
                        if ($out -is [hashtable]) {
                            $ver  = if ($out.Version)     { [string]$out.Version }     else { 'unknown' }
                            $last = if ($out.LastUpdated) { [string]$out.LastUpdated } else { 'n/a' }
                            $ver2 = $out.Verified
                            $flag = if ($ver2 -eq $true) { 'fresh' } elseif ($null -eq $ver2) { 'n/a' } else { 'stale' }
                            $detail = if ($out.Detail) { " ($([string]$out.Detail))" } else { '' }
                            return "v=$ver last=$last [$flag]$detail"
                        }
                        if ($null -eq $out) { return 'OK (no output)' }
                        return [string]$out
                    } catch {
                        return "FAIL: $($_.Exception.Message)"
                    }
                }

                ## v1.9.0: PSADT package-deploy branch (mirror of
                ## Start-NemVulnRun). Triggered when the matched profile
                ## is IsPackage. Copies the controller-staged Tools\Packages\<folder>\
                ## tree to a per-host stage dir on the target via
                ## Copy-Item -ToSession, runs Deploy-Application.ps1
                ## with -DeployMode NonInteractive, parses PSADT exit
                ## codes (0/1641/3010 = success, 60012 = deferred,
                ## else fail), best-effort post-Verify, cleanup.
                $remotePkgStage = $null
                if ($isPkgProfile) {
                    $stageGuid       = [guid]::NewGuid().ToString('N').Substring(0,8)
                    $remotePkgStage  = "C:\Windows\Temp\janet-pkg-$stageGuid"
                    try {
                        Invoke-Command -Session $sess -ScriptBlock {
                            param($d)
                            New-Item -Path $d -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        } -ArgumentList $remotePkgStage -ErrorAction Stop

                        Copy-Item -Path (Join-Path $PkgSrcIn '*') -Destination $remotePkgStage `
                            -Recurse -ToSession $sess -Force -ErrorAction Stop
                    } catch {
                        return "FAIL: package stage push failed: $($_.Exception.Message)"
                    }

                    try {
                        $deployRes = Invoke-Command -Session $sess -ArgumentList $remotePkgStage -ScriptBlock {
                            param($stageDir)
                            $out = [pscustomobject]@{
                                Status='FAIL'; ExitCode=$null; Reason=''; Output=''
                            }
                            try {
                                Get-ChildItem -Path $stageDir -Filter *.ps1 -Recurse -EA SilentlyContinue | Unblock-File
                                $deploy = Get-ChildItem -Path $stageDir -Filter 'Deploy-Application.ps1' -Recurse -File -EA SilentlyContinue | Select-Object -First 1
                                if (-not $deploy) {
                                    $out.Reason = 'Deploy-Application.ps1 not found in staged package post-copy'
                                    return $out
                                }
                                Set-Location $deploy.DirectoryName
                                $global:LASTEXITCODE = 0
                                $output   = & $deploy.FullName -DeployMode NonInteractive 2>&1
                                $exitCode = $LASTEXITCODE
                                $outStr   = ($output | Out-String).TrimEnd()
                                $out.ExitCode = $exitCode
                                $out.Output   = $outStr

                                $successExits = @(0, 1641, 3010)
                                $softFail = $outStr -match '(?im)^\s*(ERROR|FAILED|FAILURE)\b'
                                if ($successExits -contains $exitCode) {
                                    if ($softFail) {
                                        $out.Status = 'FAIL'
                                        $out.Reason = "Exit $exitCode but output contained ERROR/FAILED tokens"
                                    } else {
                                        $out.Status = 'OK'
                                        $out.Reason = switch ($exitCode) {
                                            3010 { 'Success (reboot required)' }
                                            1641 { 'Success (reboot initiated)' }
                                            default { 'Success' }
                                        }
                                    }
                                } elseif ($exitCode -eq 60012) {
                                    $out.Status = 'SKIP'
                                    $out.Reason = 'User deferred install (PSADT 60012)'
                                } else {
                                    $out.Status = 'FAIL'
                                    $out.Reason = "Non-zero exit code: $exitCode"
                                }
                                return $out
                            } catch {
                                $out.Reason = "Terminating error: $($_.Exception.Message)"
                                return $out
                            }
                        } -ErrorAction Stop
                    } catch {
                        return "FAIL: deploy invoke failed: $($_.Exception.Message)"
                    } finally {
                        try {
                            Invoke-Command -Session $sess -ScriptBlock {
                                param($d) Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
                            } -ArgumentList $remotePkgStage -ErrorAction SilentlyContinue
                        } catch {}
                    }

                    $postVerSummary = ''
                    if ($prof.Verify) {
                        try {
                            $verifyText = [string]$prof.Verify.ToString()
                            $postRaw = Invoke-Command -Session $sess -ScriptBlock {
                                param($vt)
                                try { return & ([scriptblock]::Create($vt)) } catch { return $null }
                            } -ArgumentList $verifyText -ErrorAction SilentlyContinue
                            if ($postRaw -is [hashtable]) {
                                $pv = if ($postRaw.Version) { [string]$postRaw.Version } else { 'unknown' }
                                $postVerSummary = " | post-verify v=$pv"
                            }
                        } catch {}
                    }

                    $tag = switch ($deployRes.Status) {
                        'OK'   { 'OK' }
                        'SKIP' { 'SKIP' }
                        default { 'FAIL' }
                    }
                    $exitDisp = if ($null -ne $deployRes.ExitCode) { $deployRes.ExitCode } else { 'n/a' }
                    return "$tag (exit=$exitDisp; $($deployRes.Reason))$postVerSummary"
                }

                $updateText = [string]$prof.Script.ToString()
                ## v1.8.6: Apache Log4j stage-via-session in the bulk
                ## path. Same logic as Start-NemVulnRun.
                $remoteStageDir = $null
                if ($ProfileIn -eq 'Apache Log4j - Replace Vulnerable Jars') {
                    if ([string]::IsNullOrWhiteSpace($Log4jSrcIn)) {
                        return "FAIL: Log4j source path not set (textbox empty + no default)"
                    }
                    $localApi  = Join-Path $Log4jSrcIn 'log4j-api-2.25.4.jar'
                    $localCore = Join-Path $Log4jSrcIn 'log4j-core-2.25.4.jar'
                    if (-not (Test-Path -LiteralPath $localApi)) {
                        return "FAIL: source jar missing on controller: $localApi"
                    }
                    if (-not (Test-Path -LiteralPath $localCore)) {
                        return "FAIL: source jar missing on controller: $localCore"
                    }
                    $stageGuid      = [guid]::NewGuid().ToString('N').Substring(0,8)
                    $remoteStageDir = "C:\Windows\Temp\janet-log4j-stage-$stageGuid"
                    try {
                        Invoke-Command -Session $sess -ScriptBlock {
                            param($d)
                            New-Item -Path $d -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        } -ArgumentList $remoteStageDir -ErrorAction Stop
                        Copy-Item -Path $localApi  -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop
                        Copy-Item -Path $localCore -Destination $remoteStageDir -ToSession $sess -Force -ErrorAction Stop
                    } catch {
                        return "FAIL: stage push failed: $($_.Exception.Message)"
                    }
                    $escPath    = $remoteStageDir.Replace("'", "''")
                    $updateText = [regex]::Replace($updateText, "(?<=\`$sourceShare\s*=\s*')[^']*", $escPath)
                }
                $verifyText = if ($prof.Verify) { [string]$prof.Verify.ToString() } else { '' }
                $combined = {
                    param($updateTxt, $verifyTxt)
                    $pre = $null
                    if ($verifyTxt) {
                        try { $pre = & ([scriptblock]::Create($verifyTxt)) } catch { $pre = $null }
                    }
                    $updateOut = & ([scriptblock]::Create($updateTxt))
                    $updateStr = if ($null -eq $updateOut) { 'OK (no output)' } else { [string]$updateOut }
                    $post = $null
                    if ($verifyTxt) {
                        try { $post = & ([scriptblock]::Create($verifyTxt)) } catch { $post = $null }
                    }
                    return @{ Update = $updateStr; Pre = $pre; Post = $post }
                }
                try {
                    $result = Invoke-Command -Session $sess -ScriptBlock $combined `
                                             -ArgumentList $updateText, $verifyText `
                                             -ErrorAction Stop
                    $updateStr = [string]$result.Update
                    $preV  = if ($result.Pre  -is [hashtable] -and $result.Pre.Version)  { [string]$result.Pre.Version }  else { 'n/a' }
                    $postV = if ($result.Post -is [hashtable] -and $result.Post.Version) { [string]$result.Post.Version } else { 'n/a' }
                    if ($preV -eq 'n/a' -and $postV -eq 'n/a') { return $updateStr }
                    $diff = if ($preV -eq $postV) { 'unchanged (async update may be in progress)' } else { "bumped: $preV -> $postV" }
                    return "$updateStr | $diff"
                } catch {
                    return "FAIL: $($_.Exception.Message)"
                }
            } finally {
                ## v1.8.6: Log4j stage cleanup on the remote.
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
        })
        [void]$ps.AddArgument($j.Target)
        [void]$ps.AddArgument($j.ProfileName)
        [void]$ps.AddArgument($profilesTable)
        [void]$ps.AddArgument([bool]$VerifyOnly)
        [void]$ps.AddArgument($cred)
        ## v1.8.5: Log4j source-share override.
        [void]$ps.AddArgument([string]$log4jSrcOverride)
        ## v1.9.0: per-job package source path (empty for non-IsPackage
        ## jobs — the runspace ignores it).
        [void]$ps.AddArgument([string]$pkgSrcForJob)

        $async = $ps.BeginInvoke()
        ## Per-job context preserved here so the drain timer can label
        ## log lines and audit rows with the right vuln/profile origin.
        $s.Jobs[$id] = @{
            PS          = $ps
            Async       = $async
            Target      = $j.Target
            VulnDisplay = $j.VulnDisplay
            VulnKey     = $j.VulnKey
            ProfileName = $j.ProfileName
        }
    }

    ## Drain timer (mirrors Start-NemVulnRun's drain). Aggregates per-job
    ## results, prefixed with [VulnDisplay] so the operator can see which
    ## update on which host succeeded/failed.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = Get-NemDrainInterval
    $timer.Add_Tick({
        $s2     = Get-NemState
        $rtb2   = $s2.UI.Controls['updRtbLog']
        $lbl2   = $s2.UI.Controls['updLblStatus']
        $cancel2= $s2.UI.Controls['updBtnCancel']
        $theme2 = $s2.UI.Theme

        $counters = $s2.Jobs['_counters']
        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("[$($job.VulnDisplay)] $($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = if ($resultStr -like 'FAIL*') { 'Failed' } else { 'OK' }
                Write-NemAudit -Action "$($counters['AuditPrefix']).Target" -Target $job.Target -Result $auditResult `
                    -Detail "vuln=$($job.VulnDisplay) profile=$($job.ProfileName) mode=$($counters['ModeLabel']) result=$resultStr"

                if ($null -ne (Get-JanetSession)) {
                    $janetResult = if ($auditResult -eq 'OK') { 'Success' } else { 'Failure' }
                    $itemCount   = if ($auditResult -eq 'OK') { 1 } else { 0 }
                    $janetDetail = "vuln=$($job.VulnDisplay) profile=$($job.ProfileName) mode=$($counters['ModeLabel'])"
                    try { Write-JanetAction -Action 'VulnPatched' -Target $job.Target -Result $janetResult -ItemCount $itemCount -Detail $janetDetail } catch {}
                }

                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        ## Update progress label periodically.
        $totalDone  = [int]$counters['Success'] + [int]$counters['Failed']
        $lbl2.Text  = "$($counters['ModeLabel']) BULK: $totalDone of $($counters['Total']) ($($counters['Success']) ok, $($counters['Failed']) failed)"

        $outstanding2 = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding2++ } }
        if ($outstanding2 -eq 0) {
            $this.Stop()
            $this.Dispose()
            $s2.UI.Controls.Remove('updTimer') | Out-Null

            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("BULK $($counters['ModeLabel'].ToString().ToUpper()) complete: $($counters['Success']) succeeded, $($counters['Failed']) failed across $($counters['CardCount']) card(s) and $($counters['HostCount']) host(s)`r`n")
            $rtb2.AppendText("========================================`r`n")
            Write-NemAudit -Action "$($counters['AuditPrefix']).End" -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed']) cards=$($counters['CardCount']) hosts=$($counters['HostCount'])"

            try {
                ## v1.5.0: tag the bulk-summary row with GroupKey='<bulk>'
                ## and GroupSize=CardCount so a CSV reader can tell at a
                ## glance this is a batch summary (not a per-vuln Run).
                ## Per-card-in-the-batch Run rows are NOT fanned out from
                ## the bulk path — bulk is an aggregate by design. Use the
                ## per-card Run button if per-vuln rollup is needed.
                Write-NemRunSummary -Action $counters['AuditPrefix'] `
                    -Scope       $counters['VulnDisplay'] `
                    -Profile     '<bulk>' `
                    -Mode        $counters['ModeLabel'] `
                    -HostsTotal  ([int]$counters['Total']) `
                    -Success     ([int]$counters['Success']) `
                    -Failed      ([int]$counters['Failed']) `
                    -StartedAt   $counters['StartedAt'] `
                    -GroupKey    '<bulk>' `
                    -GroupMembers @()
            } catch {
                Write-NemAudit -Action 'RunsCsv.Failed' -Target $counters['VulnDisplay'] -Result 'Failed' `
                    -Detail $_.Exception.Message
            }

            Set-NemVulnCardRunEnabled -Enabled $true
            if ($s2.UI.Controls.ContainsKey('updBtnRunAll'))  { $s2.UI.Controls['updBtnRunAll'].Enabled  = $true }
            if ($s2.UI.Controls.ContainsKey('updBtnBulkRun')) { $s2.UI.Controls['updBtnBulkRun'].Enabled = $true }
            $cancel2.Enabled = $false
            $lbl2.Text = "Bulk $($counters['ModeLabel']) complete: $($counters['Success']) succeeded, $($counters['Failed']) failed"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $timer.Start()
    $s.UI.Controls['updTimer'] = $timer
}

#############
## LOGGING ##
#############
function Resolve-NemOperatorIdentity {
    <#
    .SYNOPSIS
        Resolve the operator's AD display name + EDIPI. Matches the SIM_Tool
        v6.6 pattern so logs line up across tools.

    .DESCRIPTION
        Fallback chain (SIM parity):
          1. AD displayName via [adsi]"LDAP://$(whoami /fqdn)" — primary
          2. Win32_ComputerSystem.UserName — WMI fallback
          3. $env:USERNAME — last resort
        EDIPI follows AFNET convention: it IS the raw $env:USERNAME (SSO
        maps EDIPI to USERNAME on domain-joined workstations). The folder
        name combines both in SIM's format: "<edipi> - <DisplayName>".
        Returns a PSObject with Edipi / DisplayName / FolderName.
    #>
    [CmdletBinding()]
    param()

    $displayName = $null

    ## Primary — AD displayName via LDAP bind on the signed-in user's FQDN.
    try {
        $fqdn = (& whoami /fqdn 2>$null) | Select-Object -First 1
        if ($fqdn) {
            $adObj = [adsi]"LDAP://$fqdn"
            if ($adObj -and $adObj.displayName -and $adObj.displayName.Value) {
                $displayName = [string]$adObj.displayName.Value
            } elseif ($adObj -and $adObj.displayName) {
                $displayName = [string]$adObj.displayName
            }
        }
    } catch {
        ## fall through to WMI fallback
    }

    ## Secondary — WMI's idea of the logged-on user.
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if ($cs.UserName) { $displayName = [string]$cs.UserName }
        } catch {}
    }

    ## Tertiary — env var (always present).
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        $displayName = $env:USERNAME
    }

    ## AFNET convention: $env:USERNAME IS the EDIPI on domain-joined boxes.
    $edipi = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()

    ## Per-operator folder, path-safe.
    $folderName = ("$edipi - $displayName" -replace '[\\/:*?"<>|]', '_').Trim()

    return [pscustomobject]@{
        Edipi       = $edipi
        DisplayName = $displayName
        FolderName  = $folderName
    }
}

function Resolve-NemLogDir {
    <#
        Resolution order:
          1. Primary share at $script:NemLogShare — WRITE-probed, not just
             reachability. Test-Path returns $true when the share is listable
             even if ACLs block writes, so we drop a sentinel file to confirm
             the operator actually has rw access.
          2. Local fallback at $script:Nemesis.LocalLogDir.
        The active path is written to $script:Nemesis.Config.LogDir.
        Returns a hashtable: @{ Path = '<path>'; IsFallback = $true/$false; Warning = '<msg-or-null>' }
    #>
    [CmdletBinding()]
    param()

    $share = $script:NemLogShare
    ## Pre-declare $probeErr so StrictMode=3 can read it even when neither
    ## catch block fires (e.g. when Test-Path returns $false without throwing).
    $probeErr = $null
    try {
        if ($share -and (Test-Path -LiteralPath $share -ErrorAction Stop)) {
            ## Write-probe: create, write, delete a tiny sentinel. Any ACL
            ## denial or network hiccup drops us to the local fallback.
            $sentinel = Join-Path $share (".acas-nemesis-write-test-{0:N}.tmp" -f [guid]::NewGuid())
            try {
                'ok' | Out-File -LiteralPath $sentinel -Encoding ASCII -ErrorAction Stop
                Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue

                ## Sweep orphans left by prior sessions whose Remove-Item
                ## lost the race against AV / process kill / sync agent.
                ## 1-hour grace window is generous: even the slowest write
                ## probe finishes in <5s, and a sentinel older than an hour
                ## is unambiguously orphaned (the operator who created it
                ## has long since started writing real session logs).
                try {
                    Get-ChildItem -LiteralPath $share -Filter '.acas-nemesis-write-test-*.tmp' -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
                        ForEach-Object {
                            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
                        }
                } catch {}

                $script:Nemesis.Config.LogDir = $share
                return @{ Path = $share; IsFallback = $false; Warning = $null }
            } catch {
                ## Share visible but not writable — note it and fall through.
                $probeErr = $_.Exception.Message
            }
        }
    } catch {
        ## Share unreachable — fall through.
        $probeErr = $_.Exception.Message
    }

    $script:Nemesis.Config.LogDir = $script:Nemesis.LocalLogDir
    $reason = if ($probeErr) { "write-probe failed: $probeErr" } else { 'share unreachable' }
    return @{
        Path       = $script:Nemesis.LocalLogDir
        IsFallback = $true
        Warning    = "Log share unavailable ($reason). Session logs + CSV telemetry will be saved locally only at '$($script:Nemesis.LocalLogDir)'."
    }
}

function global:Open-NemAuditLog {
    <#
        Stamps a session id + timestamp, creates the audit log file, returns
        the full path (or $null if no writable location). Called once at
        Start Session.

        Per-operator subfolder matches SIM_Tool: '<edipi> - <DisplayName>'
        under the root log dir. Aggregate CSVs stay at the root so a single
        fleet-wide aggregate exists.

        NEVER THROWS. Tries the resolved LogDir first, then the local
        workspace dir. If both fail, sets LogFile=$null — session still
        starts, audit rows just get dropped rather than blocking operation.
        This keeps the tool usable on locked-down workstations where the
        share ACL rejects the operator mid-session.
    #>
    [CmdletBinding()]
    param()

    $script:Nemesis.Session['Id']        = [guid]::NewGuid().ToString('N').Substring(0,8)
    $script:Nemesis.Session['StartedAt'] = Get-Date
    $startedAt = $script:Nemesis.Session['StartedAt']
    $ts = $startedAt.ToString('yyyy-MM-dd_HH-mm-ss')

    $folderName = [string]$script:Nemesis.Session['FolderName']
    if ([string]::IsNullOrWhiteSpace($folderName)) { $folderName = $env:USERNAME }

    $displayName = [string]$script:Nemesis.Session['DisplayName']
    $edipi       = [string]$script:Nemesis.Session['Edipi']
    $fileName    = "ACASNemesis_${env:USERNAME}_${ts}.log"

    ## Try the resolved LogDir first, then the local workspace as last
    ## resort. Whichever works becomes the new Config.LogDir so every
    ## subsequent audit/CSV write targets the same location.
    $candidates = @(
        $script:Nemesis.Config.LogDir,
        $script:Nemesis.LocalLogDir
    ) | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($root in $candidates) {
        try {
            if (-not (Test-Path -LiteralPath $root)) {
                New-Item -Path $root -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            $userDir = Join-Path $root $folderName
            if (-not (Test-Path -LiteralPath $userDir)) {
                try { New-Item -Path $userDir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
                catch { $userDir = $root }   # flat dir if subfolder create fails
            }
            $path = Join-Path $userDir $fileName

            "=== ACAS Nemesis Tool v$($script:Nemesis.Config.ToolVersion) ===" | Out-File -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
            "Session $($script:Nemesis.Session['Id']) started $($startedAt.ToString('yyyy-MM-dd HH:mm:ss'))" |
                Out-File -LiteralPath $path -Append -Encoding UTF8 -ErrorAction Stop
            "Operator: $displayName  (EDIPI: $edipi)  on $($env:COMPUTERNAME)" |
                Out-File -LiteralPath $path -Append -Encoding UTF8 -ErrorAction Stop

            ## Point the active LogDir at the root that actually worked.
            $script:Nemesis.Config.LogDir  = $root
            $script:Nemesis.Config.LogFile = $path
            return $path
        } catch {
            ## Try the next candidate silently; final failure falls through.
            continue
        }
    }

    ## All candidates failed — keep session alive with no transcript file.
    $script:Nemesis.Config.LogFile = $null
    return $null
}

function global:Write-NemTouchedHostCsv {
    <#
    .SYNOPSIS
        Append one structured row to the per-operator TouchedHosts CSV.
    .DESCRIPTION
        Companion to the per-session free-text .log. Captures one row per
        (timestamp, operator, session, action, target host, result) so a
        lead can answer "which machines did operator X touch this month"
        with a single CSV pivot — no grep across daily session logs.

        Path: <LogDir>\<edipi> - <DisplayName>\TouchedHosts_<YYYY-MM>.csv
        File rotates monthly (date-stamped) so it never grows unbounded.
        Header line is written on first append of the month. Schema-
        change discontinuities are accepted as-is (operator can rename
        the old file if a future schema change actually breaks parsers).

        NEVER THROWS. All failures swallowed — the per-session .log and
        the daily Runs CSV are the authoritative records; this is an
        operator-attribution convenience layer.

        Auto-invoked by Write-NemAudit when the Action looks per-host
        (.Target or .Preflight suffix). Callers don't normally invoke
        this directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [string] $TargetHost,
        [string] $Result = '',
        [string] $Detail = ''
    )

    ## Bail if the per-operator log dir hasn't been resolved yet (e.g.
    ## audit fires before Open-NemAuditLog finishes during early init).
    $cfgFile = $script:Nemesis.Config.LogFile
    if ([string]::IsNullOrWhiteSpace($cfgFile)) { return }

    ## TouchedHosts file lives in the same per-operator subfolder as the
    ## session .log file. Derive the folder from the .log path so we
    ## stay in sync with whatever Open-NemAuditLog picked (share or
    ## local fallback).
    $userDir = $null
    try { $userDir = Split-Path -Parent $cfgFile } catch { return }
    if ([string]::IsNullOrWhiteSpace($userDir)) { return }

    $month   = (Get-Date).ToString('yyyy-MM')
    $csvPath = Join-Path $userDir "TouchedHosts_$month.csv"

    $session = $script:Nemesis.Session
    $sid     = if ($session.ContainsKey('Id') -and $session['Id']) { [string]$session['Id'] } else { '-' }
    $opRaw   = if ($session.ContainsKey('DisplayName') -and $session['DisplayName']) {
        [string]$session['DisplayName']
    } else { $env:USERNAME }
    $edipi   = if ($session.ContainsKey('Edipi') -and $session['Edipi']) {
        [string]$session['Edipi']
    } else { $env:USERNAME }

    ## Reuse Get-NemCsvEscape (defined later in the script under SHARED
    ## CSV TELEMETRY) but if we've been called early-init before that
    ## function exists, fall back to inline escape.
    $esc = if (Get-Command Get-NemCsvEscape -ErrorAction SilentlyContinue) {
        ${function:Get-NemCsvEscape}
    } else {
        { param($v) if ($null -eq $v) { '' } else { ([string]$v) -replace '[\r\n]+', ' ' -replace ',', ';' } }
    }

    $line = @(
        (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'),
        (& $esc $opRaw),
        $edipi,
        $sid,
        $env:COMPUTERNAME,
        (& $esc $Action),
        (& $esc $TargetHost),
        (& $esc $Result),
        (& $esc $Detail)
    ) -join ','

    $header = 'Timestamp,Operator,Edipi,SessionId,SourceHost,Action,TargetHost,Result,Detail'

    ## v1.10.5: enqueue to the background writer. The writer creates the
    ## directory and writes the header on first touch of the month, then
    ## appends the row — all off the UI thread.
    Add-NemLogWrite -NetworkPath $csvPath -Line $line -Header $header
}

function global:Write-NemAudit {
    <#
        Write one audit line. Safe from any thread / catch block.
        Format: [yyyy-MM-dd HH:mm:ss] [USER: x] [ACTION: y] [TARGET: z] [RESULT: w] [DETAIL: ...]

        v1.7.0: when the Action is a per-host event (.Target or
        .Preflight suffix), ALSO appends a structured row to the
        per-operator TouchedHosts_<YYYY-MM>.csv via
        Write-NemTouchedHostCsv. The .log stays the narrative
        transcript; the CSV is the operator-attributable host
        manifest a lead can pivot on without grepping.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [string] $Target = 'N/A',
        [string] $Result = '',
        [string] $Detail = ''
    )
    if (-not $script:Nemesis.Config.LogFile) { return }
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "[$ts] [USER: $env:USERNAME] [ACTION: $Action] [TARGET: $Target] [RESULT: $Result]"
    if ($Detail) { $entry += " [DETAIL: $Detail]" }
    ## v1.10.5: enqueue to the background writer instead of a synchronous
    ## Out-File. The drain timer calls this per completed host — a hung
    ## share on a synchronous append froze the UI thread mid-run.
    Add-NemLogWrite -NetworkPath $script:Nemesis.Config.LogFile -Line $entry

    ## v1.10.3: echo Failed audit entries to the launching PowerShell
    ## console window in red so the operator can see *what* went wrong
    ## without grepping the per-session transcript. Every existing
    ## catch-handler in the tool already does
    ##     Write-NemAudit -Result 'Failed' -Detail $_.Exception.Message
    ## so this single line makes every silently-swallowed error visible
    ## in real time. Host writes are wrapped — a missing/redirected host
    ## (eg. running under -NonInteractive) won't break audit logging.
    if ($Result -eq 'Failed') {
        try { Write-Host "[ERR] $entry" -ForegroundColor Red } catch {}
    }

    ## v1.7.0: per-host fan-out. The `.Target` suffix is the convention
    ## every per-host audit call already uses (VulnRun.Target,
    ## Reboot.Target, Reboot.Verify.Target, BulkRun.Target,
    ## KbInstall.Target, Preflight.Services.Target). Aggregate calls
    ## (.Start / .End / .Cancel / .StepFail) skip the fan-out.
    ## v1.9.3: dropped the `*.Preflight` arm of the filter — no audit
    ## callsite ever uses a bare `.Preflight` suffix (the per-host
    ## preflight calls all end in `.Target` or are folded into a
    ## `.Preflight.Target`-style nested name). Keeping the arm was a
    ## future-bug magnet: a contributor adding `-Action 'X.Preflight'`
    ## later would get unexpected fan-out semantics. Drop now, document
    ## the convention here.
    ## Defensive: only fan out when Target looks like a hostname
    ## (non-empty, not the placeholder, not aggregate).
    if ($Target -and $Target -ne 'N/A' -and $Action -like '*.Target') {
        try { Write-NemTouchedHostCsv -Action $Action -TargetHost $Target -Result $Result -Detail $Detail } catch {}
    }
}

##########################
## SHARED CSV TELEMETRY ##
##########################
## SIM-style aggregate logging. Daily-rotated CSV on the log share tracks
## every Run/Verify/KB Install plus a closing SessionNotes row with
## operator-supplied notes. See Show-NemClosingNotesDialog for the UI that
## feeds the Notes column.

function Get-NemCsvEscape {
    ## Minimal CSV sanitizer: strip CR/LF, replace literal commas with
    ## semicolons. Matches SIM's pattern (no RFC-4180 quoting).
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '[\r\n]+', ' ' -replace ',', ';'
}

function global:Write-NemRunCsvLine {
    <#
        Append one line to the daily Runs CSV on the log share.
        Writes a header row only when creating the file for the first time.
        Retries up to 3x on share contention (200ms * attempt backoff).

        v1.5.0 schema: added GroupKey and GroupSize trailing columns for
        rolled-up Updater cards. Per-vuln cards write GroupKey='' and
        GroupSize=1; rolled-up cards fan out N rows (one per member vuln)
        sharing the same Timestamp + RunBatchId, with GroupKey set to the
        profile-signature and GroupSize set to N. The existing
        schema-migration block (column-count change archives the old file
        as .pre-schema-change.csv) handles the upgrade from 1.4.x in-place.
    #>
    [CmdletBinding()]
    param(
        [string] $RowType      = 'Run',        # 'Run' | 'SessionNotes'
        [string] $Action       = '',           # 'VulnRun' | 'VulnVerify' | 'KbInstall' | 'SessionEnd'
        [string] $Scope        = '',           # vuln display name, 'KB bulk', or ''
        [string] $Profile      = '',           # profile name or KB method
        [string] $Mode         = '',           # 'Update' | 'Verify' | 'MECM (CIM targeted)' | 'UsoClient Trigger'
        [int]    $HostsTotal   = 0,
        [int]    $Success      = 0,
        [int]    $Failed       = 0,
        [int]    $DurationSec  = 0,
        [string] $Notes        = '',
        [string] $GroupKey     = '',           # v1.5.0: profile signature for rolled-up cards, empty otherwise
        [int]    $GroupSize    = 1             # v1.5.0: member-vuln count for rolled-up cards, 1 otherwise
    )

    $s       = $script:Nemesis
    $dir     = $s.Config.LogDir
    if (-not $dir) {
        try { $resolved = Resolve-NemLogDir; $dir = $resolved.Path } catch { return $false }
    }
    if (-not $dir) { return $false }

    $fileName = 'ACAS-Nemesis-Runs_' + (Get-Date -Format 'yyyy-MM-dd') + '.csv'
    $path     = Join-Path $dir $fileName

    $header = 'Timestamp,User,Edipi,SessionId,Host,RowType,Action,Scope,Profile,Mode,HostsTotal,Success,Failed,DurationSec,Notes,GroupKey,GroupSize'
    $ts     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    ## User column = AD display name (SIM-style, commas stripped for CSV safety).
    $userRaw = if ($s.Session.ContainsKey('DisplayName') -and $s.Session['DisplayName']) {
        [string]$s.Session['DisplayName']
    } else { $env:USERNAME }
    $user  = Get-NemCsvEscape $userRaw
    $edipi = if ($s.Session.ContainsKey('Edipi') -and $s.Session['Edipi']) {
        [string]$s.Session['Edipi']
    } else { $env:USERNAME }
    $hostN = $env:COMPUTERNAME
    $sid   = if ($s.Session.Id) { $s.Session.Id } else { '-' }

    $line = @(
        $ts, $user, $edipi, $sid, $hostN, $RowType, $Action,
        (Get-NemCsvEscape $Scope),
        (Get-NemCsvEscape $Profile),
        (Get-NemCsvEscape $Mode),
        $HostsTotal, $Success, $Failed, $DurationSec,
        (Get-NemCsvEscape $Notes),
        (Get-NemCsvEscape $GroupKey),       # v1.5.0
        $GroupSize                          # v1.5.0
    ) -join ','

    ## v1.10.5: enqueue to the background writer. The daily Runs CSV is
    ## written once per run (drain timer's final tick) and once per
    ## session-close — a hung share on the old synchronous path (3
    ## retries + local failover, all inline) stalled the UI thread at
    ## run-end. The writer creates the file with $header on first touch
    ## and falls back to the local workspace copy if the share append
    ## fails. The old inline schema-migration archive (.pre-schema-
    ## change.csv) is dropped: the Runs CSV schema has been stable since
    ## v1.5.0 and that one-time 1.4->1.5 migration already ran.
    $localPath = ''
    try {
        if ($s.LocalLogDir) { $localPath = Join-Path $s.LocalLogDir $fileName }
    } catch {}
    Add-NemLogWrite -NetworkPath $path -LocalPath $localPath -Line $line -Header $header
    return $true
}

function Write-NemRunSummary {
    <#
        Called from each drain timer's final tick. Appends one RowType=Run
        row to the daily Runs CSV, and bumps per-session counters used by
        the closing dialog summary + SessionNotes row.

        v1.5.0: when -GroupMembers is non-empty (rolled-up Updater card),
        writes one CSV row per member vuln instead of a single
        synthetic-display-name row. Every fanned-out row shares the same
        Timestamp + Profile + Mode + HostsTotal/Success/Failed counters,
        and carries the same GroupKey and GroupSize=N tags so downstream
        consumers (JanetDashboard) can reconstruct the rollup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [string] $Scope      = '',
        [string] $Profile    = '',
        [string] $Mode       = '',
        [int]    $HostsTotal = 0,
        [int]    $Success    = 0,
        [int]    $Failed     = 0,
        [datetime] $StartedAt = (Get-Date),
        [string]   $GroupKey     = '',
        [object[]] $GroupMembers = @()
    )

    $duration = [int]((Get-Date) - $StartedAt).TotalSeconds

    if ($GroupMembers -and @($GroupMembers).Count -gt 0) {
        ## Rolled-up card: one CSV row per member vuln, sharing the
        ## per-host run counters (each member is logically "fixed" by the
        ## same per-host updater push).
        $members = @($GroupMembers)
        $size    = $members.Count
        foreach ($m in $members) {
            $memberScope = if ($m -and $m.PSObject.Properties['DisplayName']) { [string]$m.DisplayName } else { $Scope }
            Write-NemRunCsvLine -RowType 'Run' -Action $Action `
                -Scope $memberScope -Profile $Profile -Mode $Mode `
                -HostsTotal $HostsTotal -Success $Success -Failed $Failed `
                -DurationSec $duration `
                -GroupKey $GroupKey -GroupSize $size | Out-Null
        }
    } else {
        Write-NemRunCsvLine -RowType 'Run' -Action $Action -Scope $Scope -Profile $Profile -Mode $Mode `
            -HostsTotal $HostsTotal -Success $Success -Failed $Failed -DurationSec $duration `
            -GroupKey $GroupKey -GroupSize 1 | Out-Null
    }

    ## Per-session counters — used by the closing notes dialog.
    $session = $script:Nemesis.Session
    if (-not $session.ContainsKey('RunCount')) {
        $session['RunCount'] = 0
        $session['Success']  = 0
        $session['Failed']   = 0
    }
    $session['RunCount'] = [int]$session['RunCount'] + 1
    $session['Success']  = [int]$session['Success']  + $Success
    $session['Failed']   = [int]$session['Failed']   + $Failed
}

function global:Show-NemClosingNotesDialog {
    <#
        Modal "session notes" prompt, displayed from FormClosing. Matches
        SIM's ClosingNotes pattern: Submit writes a SessionNotes row,
        Skip writes a SessionNotes row with empty Notes, Cancel aborts
        the close.
        Returns a hashtable: @{ Cancelled=$bool; Notes=$string }
    #>
    [CmdletBinding()]
    param()

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $fonts = $s.UI.Fonts

    $runs = if ($s.Session.ContainsKey('RunCount'))    { [int]$s.Session['RunCount'] }    else { 0 }
    $succ = if ($s.Session.ContainsKey('Success'))     { [int]$s.Session['Success']  }    else { 0 }
    $fail = if ($s.Session.ContainsKey('Failed'))      { [int]$s.Session['Failed']   }    else { 0 }
    $opName  = if ($s.Session.ContainsKey('DisplayName')) { [string]$s.Session['DisplayName'] } else { $env:USERNAME }
    $opEdipi = if ($s.Session.ContainsKey('Edipi'))       { [string]$s.Session['Edipi'] }       else { $env:USERNAME }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = 'ACAS Nemesis - Submit Logs + Close Tool'
    $dlg.ClientSize      = New-Object System.Drawing.Size(620, 470)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MinimizeBox     = $false
    $dlg.MaximizeBox     = $false
    ## v1.9.3: drop the dialog's title-bar X. The dialog defaults
    ## `Cancelled = $true`, so a stray title-bar X click silently
    ## aborted the close — operator could think they had submitted
    ## logs when in fact the dialog was dismissed. Force the
    ## operator through one of the three explicit buttons (Submit
    ## Logs + Close / Submit (skip notes) / Cancel Close).
    $dlg.ControlBox      = $false
    $dlg.BackColor       = $theme.Background
    $dlg.ForeColor       = $theme.TextPrimary
    $dlg.Font            = $fonts.Body
    Set-WptDarkTitleBar -Form $dlg

    $lblOperator = New-WptLabel -Text ("Operator:  $opName   (EDIPI: $opEdipi)") `
        -X 16 -Y 14 -W 580 -H 22 -Font $fonts.Body -Fg $theme.Accent1

    $lblSummary = New-WptLabel -Text ("Session summary: {0} run(s), {1} target success(es), {2} failure(s)" -f $runs, $succ, $fail) `
        -X 16 -Y 40 -W 580 -H 22 -Font $fonts.Body -Fg $theme.Accent2

    $lblPath = New-WptLabel -Text ("Log share: " + ([string]$s.Config.LogDir)) `
        -X 16 -Y 64 -W 580 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted

    ## v1.9.1: explicit list of every artifact that gets flushed on submit.
    ## Operator (and lead reading the share later) can see exactly what
    ## "submit all logs" delivers without having to chase the code.
    $lblWhatSubmits = New-WptLabel `
        -Text "Submitting will flush these artifacts to the share:" `
        -X 16 -Y 88 -W 580 -H 18 -Font $fonts.Body -Fg $theme.TextSecondary

    $bullet = "  - ACAS-Nemesis-Runs_<today>.csv  (this session's Run rows + the SessionNotes row below)`r`n" +
              "  - <edipi> - <operator>\ACASNemesis_<user>_<ts>.log  (per-session transcript, every audit line)`r`n" +
              "  - <edipi> - <operator>\TouchedHosts_<YYYY-MM>.csv   (one row per host this session touched)`r`n" +
              "  - JANET <YYYY-MM>_detail.csv + _usage.csv           (centralized rollup, per-action + per-session)"
    $lblBullets = New-WptLabel -Text $bullet `
        -X 16 -Y 108 -W 588 -H 76 -Font $fonts.MonoTiny -Fg $theme.TextMuted

    $lblPrompt = New-WptLabel -Text 'Operator notes (optional) — appended to today''s ACAS-Nemesis-Runs CSV:' `
        -X 16 -Y 188 -W 580 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location      = New-Object System.Drawing.Point(16, 212)
    $txt.Size          = New-Object System.Drawing.Size(588, 200)
    $txt.Multiline     = $true
    $txt.ScrollBars    = 'Vertical'
    $txt.BackColor     = $theme.Input
    $txt.ForeColor     = $theme.TextPrimary
    $txt.Font          = $fonts.Body
    $txt.AcceptsReturn = $true

    $btnSubmit = New-WptButton -Text 'Submit Logs + Close' -X 16  -Y 422 -W 180 -H 38 `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body
    $btnSkip   = New-WptButton -Text 'Submit (skip notes)' -X 204 -Y 422 -W 180 -H 38 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body
    $btnCancel = New-WptButton -Text 'Cancel Close'        -X 424 -Y 422 -W 180 -H 38 `
        -Bg $theme.Danger -Fg $theme.TextOnAccent -Font $fonts.Body

    ## Use a local hashtable captured by each button's closure. Hashtables
    ## are reference types, so mutations inside the click handlers survive
    ## past ShowDialog. Avoids $script: scope — which can resolve to $null
    ## under the ISE + StrictMode v3 combo — and the "Cannot index into a
    ## null array" error that followed.
    $result = [ordered]@{ Cancelled = $true; Notes = '' }

    $btnSubmit.Add_Click({
        $result['Cancelled'] = $false
        $result['Notes']     = [string]$txt.Text
        $dlg.Close()
    }.GetNewClosure())
    $btnSkip.Add_Click({
        $result['Cancelled'] = $false
        $result['Notes']     = ''
        $dlg.Close()
    }.GetNewClosure())
    $btnCancel.Add_Click({
        $result['Cancelled'] = $true
        $dlg.Close()
    }.GetNewClosure())

    $dlg.Controls.AddRange(@($lblOperator, $lblSummary, $lblPath, $lblWhatSubmits, $lblBullets, $lblPrompt, $txt, $btnSubmit, $btnSkip, $btnCancel))
    $dlg.AcceptButton = $btnSubmit

    $parent = if ($s.UI.Form) { $s.UI.Form } else { $null }
    if ($parent) { [void]$dlg.ShowDialog($parent) } else { [void]$dlg.ShowDialog() }

    return $result
}

##################
## TAB BUILDERS ##
##################
function Add-NemStartTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = $script:Nemesis
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text 'Start Session' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Set credentials and acknowledge before starting the session.' `
        -X 20 -Y 50 -W 900 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== ACTIVATION CARD (status + Start button) ==========
    $actCard = New-Object System.Windows.Forms.Panel
    $actCard.Location  = New-Object System.Drawing.Point(20, 86)
    $actCard.Size      = New-Object System.Drawing.Size(1100, 200)
    $actCard.BackColor = $theme.Surface
    $actCard.BorderStyle = 'FixedSingle'
    $actCard.Anchor    = 'Top,Left,Right'

    ## -- Left column: 4 status lines --
    $lblCredHead = New-WptLabel -Text 'CREDENTIALS' -X 24 -Y 20  -W 120 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblCredVal  = New-WptLabel -Text 'not set'     -X 160 -Y 20 -W 400 -H 18 -Font $fonts.MonoSm -Fg $theme.Danger
    $state.UI.Controls['startCredLine'] = $lblCredVal

    $lblAckHead = New-WptLabel -Text 'ACKNOWLEDGE' -X 24 -Y 48  -W 120 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblAckVal  = New-WptLabel -Text 'pending'     -X 160 -Y 48 -W 400 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $state.UI.Controls['startAckLine'] = $lblAckVal

    $lblOpHead = New-WptLabel -Text 'USER' -X 24 -Y 76 -W 120 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblOpVal  = New-WptLabel -Text "$env:USERNAME @ $env:COMPUTERNAME" `
        -X 160 -Y 76 -W 400 -H 18 -Font $fonts.MonoSm -Fg $theme.TextSecondary

    $lblLogHead = New-WptLabel -Text 'LOG FILE' -X 24 -Y 104 -W 120 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblLogVal  = New-WptLabel -Text '(pending session start)' -X 160 -Y 104 -W 440 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextFaint
    $lblLogVal.AutoEllipsis = $true
    $state.UI.Controls['startLogLine'] = $lblLogVal

    $lblShareHead = New-WptLabel -Text 'SHARE LOG' -X 24 -Y 128 -W 120 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblShareVal  = New-WptLabel -Text '' -X 160 -Y 128 -W 440 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextFaint
    $lblShareVal.AutoEllipsis = $true
    $state.UI.Controls['startShareLine'] = $lblShareVal

    ## -- Vertical divider --
    $divider = New-Object System.Windows.Forms.Panel
    $divider.Location  = New-Object System.Drawing.Point(620, 20)
    $divider.Size      = New-Object System.Drawing.Size(1, 160)
    $divider.BackColor = $theme.Border

    ## -- Right column: Start button + gate hint --
    $lblReadyHead = New-WptLabel -Text 'READY TO START?' `
        -X 660 -Y 20 -W 300 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted

    $btnStart = New-WptButton -Text 'Start Session' `
        -X 660 -Y 48 -W 380 -H 56 `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.DisplayLg
    $btnStart.Enabled = $false
    $state.UI.Controls['btnStartSession'] = $btnStart

    $lblReadySub = New-WptLabel `
        -Text 'Set credentials and acknowledge to enable' `
        -X 660 -Y 112 -W 380 -H 18 -Font $fonts.Caption -Fg $theme.TextFaint
    $lblReadySub.TextAlign = 'MiddleCenter'
    $state.UI.Controls['startReadySub'] = $lblReadySub

    $lblGateHint = New-WptLabel -Text '' `
        -X 660 -Y 132 -W 380 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextMuted
    $lblGateHint.TextAlign = 'MiddleCenter'
    $state.UI.Controls['startGateHint'] = $lblGateHint

    $actCard.Controls.AddRange(@(
        $lblCredHead, $lblCredVal,
        $lblAckHead,  $lblAckVal,
        $lblOpHead,   $lblOpVal,
        $lblLogHead,  $lblLogVal,
        $lblShareHead, $lblShareVal,
        $divider,
        $lblReadyHead, $btnStart, $lblReadySub, $lblGateHint
    ))

    ## ========== CREDENTIALS CARD ==========
    $credCard = New-Object System.Windows.Forms.Panel
    $credCard.Location    = New-Object System.Drawing.Point(20, 300)
    $credCard.Size        = New-Object System.Drawing.Size(540, 170)
    $credCard.BackColor   = $theme.Surface
    $credCard.BorderStyle = 'FixedSingle'

    $lblCredCardHead = New-WptLabel -Text 'CREDENTIALS' `
        -X 20 -Y 14 -W 400 -H 18 -Font $fonts.MonoTiny -Fg $theme.Accent1

    $lblCredCardBlurb = New-WptLabel `
        -Text 'Admin account used for every Invoke-Command remote operation. Prompts for username and password.' `
        -X 20 -Y 38 -W 500 -H 40 -Font $fonts.Caption -Fg $theme.TextSecondary

    $btnSetCred = New-WptButton -Text 'Set Credentials' `
        -X 20 -Y 100 -W 200 -H 36 `
        -Bg $theme.Accent1 -Fg $theme.Background -Font $fonts.Body

    $lblCredStatus = New-WptLabel -Text 'not set' `
        -X 236 -Y 108 -W 280 -H 22 -Font $fonts.MonoSm -Fg $theme.Danger
    $state.UI.Controls['startCredStatus'] = $lblCredStatus

    $credCard.Controls.AddRange(@($lblCredCardHead, $lblCredCardBlurb, $btnSetCred, $lblCredStatus))

    ## ========== ACKNOWLEDGE CARD ==========
    $ackCard = New-Object System.Windows.Forms.Panel
    $ackCard.Location    = New-Object System.Drawing.Point(580, 300)
    $ackCard.Size        = New-Object System.Drawing.Size(540, 170)
    $ackCard.BackColor   = $theme.Surface
    $ackCard.BorderStyle = 'FixedSingle'
    $ackCard.Anchor      = 'Top,Left,Right'

    $lblAckCardHead = New-WptLabel -Text 'ACKNOWLEDGMENT' `
        -X 20 -Y 14 -W 400 -H 18 -Font $fonts.MonoTiny -Fg $theme.Accent1

    $lblAckCardBlurb = New-WptLabel `
        -Text 'You are responsible for every remote action this tool takes against AFNET workstations. All activity is audit-logged.' `
        -X 20 -Y 38 -W 500 -H 56 -Font $fonts.Caption -Fg $theme.TextSecondary

    $chkAck = New-WptCheckBox `
        -Text 'I acknowledge responsibility for remote operations' `
        -X 20 -Y 108 -W 500 -H 28
    $state.UI.Controls['startAckCheck'] = $chkAck

    $ackCard.Controls.AddRange(@($lblAckCardHead, $lblAckCardBlurb, $chkAck))

    ## ========== EVENT WIRING ==========

    $refreshStatus = {
        $s  = Get-NemState
        $t  = $s.UI.Theme
        $cs = $s.UI.Controls

        ## Cred line (main + card status)
        if ($s.Credentials) {
            $userText = $s.Credentials.UserName
            if (Get-NemInheritedJanet) { $userText += '  (inherited from J.A.N.E.T.)' }
            $cs['startCredLine'].Text       = $userText
            $cs['startCredLine'].ForeColor  = $t.Success
            $cs['startCredStatus'].Text     = $userText
            $cs['startCredStatus'].ForeColor = $t.Success
        } else {
            $cs['startCredLine'].Text       = 'not set'
            $cs['startCredLine'].ForeColor  = $t.Danger
            $cs['startCredStatus'].Text     = 'not set'
            $cs['startCredStatus'].ForeColor = $t.Danger
        }

        ## Ack line
        if ($cs['startAckCheck'].Checked) {
            $cs['startAckLine'].Text      = 'acknowledged'
            $cs['startAckLine'].ForeColor = $t.Success
        } else {
            $cs['startAckLine'].Text      = 'pending'
            $cs['startAckLine'].ForeColor = $t.TextMuted
        }

        ## Log line
        if ($s.Config.LogFile) {
            $cs['startLogLine'].Text      = $s.Config.LogFile
            $cs['startLogLine'].ForeColor = $t.TextSecondary
        } else {
            $cs['startLogLine'].Text      = '(pending session start)'
            $cs['startLogLine'].ForeColor = $t.TextFaint
        }

        ## Share line — prefer the LIVE LogDir (which may have failed over
        ## to local mid-session) and fall back to the startup-time resolution
        ## cached in $script:NemResolvedLog (read via the closure-safe getter).
        $liveDir = [string]$s.Config.LogDir
        $isFallback = ($liveDir -eq [string]$s.LocalLogDir)
        if ($liveDir) {
            if ($isFallback) {
                $cs['startShareLine'].Text      = "local only: $liveDir"
                $cs['startShareLine'].ForeColor = $t.Warning
            } else {
                $cs['startShareLine'].Text      = "$liveDir  [reachable]"
                $cs['startShareLine'].ForeColor = $t.Success
            }
        } else {
            $resolved = Get-NemResolvedLog
            if ($resolved) {
                $cs['startShareLine'].Text      = $resolved.Path
                $cs['startShareLine'].ForeColor = if ($resolved.IsFallback) { $t.Warning } else { $t.Success }
            }
        }

        ## Gate + button
        $hasCred = [bool]$s.Credentials
        $hasAck  = [bool]$cs['startAckCheck'].Checked
        $canStart = ($hasCred -and $hasAck)
        $cs['btnStartSession'].Enabled = $canStart -and (-not $s.Session['Started'])

        $credMark = '-'
        if ($hasCred) { $credMark = '+' }
        $ackMark = '-'
        if ($hasAck)  { $ackMark = '+' }
        $cs['startGateHint'].Text = "[$credMark] credentials   [$ackMark] acknowledge"

        if ($s.Session['Started']) {
            $cs['startReadySub'].Text      = 'Session active'
            $cs['startReadySub'].ForeColor = $t.Success
        } elseif ($canStart) {
            $cs['startReadySub'].Text      = 'Ready to start'
            $cs['startReadySub'].ForeColor = $t.Success
        } else {
            $cs['startReadySub'].Text      = 'Set credentials and acknowledge to enable'
            $cs['startReadySub'].ForeColor = $t.TextFaint
        }
    }.GetNewClosure()

    $btnSetCred.Add_Click({
        $s = Get-NemState
        try {
            $cred = Get-Credential -Message 'Enter admin credentials for remote workstation operations'
            if ($cred) {
                $s['Credentials'] = $cred
                Write-NemAudit -Action 'CredentialSet' -Result 'OK' -Detail $cred.UserName
                & $refreshStatus
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to capture credentials: $($_.Exception.Message)",
                'ACAS Nemesis', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $chkAck.Add_CheckedChanged({ & $refreshStatus }.GetNewClosure())

    $btnStart.Add_Click({
        $s = Get-NemState
        try {
            if ($s.Session['Started']) { return }
            if (-not $s.Credentials) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Set credentials first.',
                    'ACAS Nemesis', 'OK', 'Warning') | Out-Null
                return
            }
            if (-not $s.UI.Controls['startAckCheck'].Checked) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Check the acknowledgment box before starting.',
                    'ACAS Nemesis', 'OK', 'Warning') | Out-Null
                return
            }

            $s.Session['Started'] = $true

            ## JANET centralized session (added in v1.3.0). Metric tool: per-host
            ## RemediatePlugin rows emitted by the runspace drain timer; rollup row
            ## written on FormClosing (reuses ACAS's existing closing-notes dialog).
            try { Start-JanetSession -Tool 'ACAS_Nemesis' -Version $JanetACAS_NemesisVersion } catch {}

            ## Open the audit log — never throws. $logPath is $null only
            ## when every candidate location (share + local) failed to
            ## write; in that case we keep the session alive but warn the
            ## operator that no transcript will be persisted.
            $logPath = Open-NemAuditLog
            if (-not $logPath) {
                ## v1.9.3: read share path through global getter so the
                ## closure-resolution failure-mode of direct `$script:`
                ## access doesn't blank out the path in this MessageBox.
                $shareForMsg = Get-NemLogShare
                [System.Windows.Forms.MessageBox]::Show(
                    "No writable log location found. The session will start, but the transcript + Runs CSV will NOT be persisted.`r`n`r`nTried:`r`n  - $shareForMsg`r`n  - $($s.LocalLogDir)",
                    'ACAS Nemesis - Logs unavailable', 'OK', 'Warning') | Out-Null
            } elseif ([string]$s.Config.LogDir -eq [string]$s.LocalLogDir) {
                [System.Windows.Forms.MessageBox]::Show(
                    "The shared log path could not be written (share unreachable or ACL denied). Session started; logs will be saved locally only at:`r`n`r`n$($s.LocalLogDir)",
                    'ACAS Nemesis - Local logs only', 'OK', 'Information') | Out-Null
            }

            Write-NemAudit -Action 'SessionStart' -Result 'OK' `
                -Detail "User=$($s.Credentials.UserName) LogDir=$($s.Config.LogDir)"

            $s['Pool'] = [runspacefactory]::CreateRunspacePool((Get-NemPoolMin), (Get-NemPoolMax))
            $s['Pool'].Open()

            $s.UI.Controls['btnStartSession'].Text    = 'Session Active'
            $s.UI.Controls['btnStartSession'].Enabled = $false
            & $refreshStatus
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to start session: $($_.Exception.Message)",
                'ACAS Nemesis - Session start failure', 'OK', 'Error') | Out-Null
            Write-NemAudit -Action 'SessionStart' -Result 'Failed' -Detail $_.Exception.Message
            $s.Session['Started'] = $false
        }
    }.GetNewClosure())

    ####################
    ## INFO BUTTONS ##
    ####################
    ## Change Log + How To Use popups, WPT-style. Always visible, no
    ## session gate — useful BEFORE the operator starts a session so new
    ## users can read the guide first.
    $btnChangeLog = New-WptButton -Text 'Change Log' `
        -X 20 -Y 494 -W 540 -H 40 -Bg $theme.PanelLight -Fg $theme.Accent1 -Font $fonts.Body
    $btnChangeLog.FlatAppearance.BorderSize  = 1
    $btnChangeLog.FlatAppearance.BorderColor = $theme.Accent1
    $btnChangeLog.Add_Click({
        try {
            Show-NemInfoDialog -Title 'ACAS Nemesis Tool - Change Log' -BodyText (Get-NemChangeLogText)
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Change Log dialog failed: $($_.Exception.Message)",
                'ACAS Nemesis', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $btnHowTo = New-WptButton -Text 'How To Use' `
        -X 580 -Y 494 -W 540 -H 40 -Bg $theme.PanelLight -Fg $theme.Accent2 -Font $fonts.Body
    $btnHowTo.FlatAppearance.BorderSize  = 1
    $btnHowTo.FlatAppearance.BorderColor = $theme.Accent2
    $btnHowTo.Add_Click({
        try {
            Show-NemInfoDialog -Title 'ACAS Nemesis Tool - How To Use' -BodyText (Get-NemHowToUseText)
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "How To Use dialog failed: $($_.Exception.Message)",
                'ACAS Nemesis', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $TabPanel.Controls.AddRange(@($lblTitle, $lblSub, $actCard, $credCard, $ackCard, $btnChangeLog, $btnHowTo))

    ## Initial paint of status lines.
    & $refreshStatus
}

function Add-NemTargetsTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text 'Data Import' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Import ACAS / Nessus CSV exports to populate targets and findings. Duplicates ignored (case-insensitive).' `
        -X 20 -Y 50 -W 1000 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== DATA-STATE TILE STRIP ==========
    ## v1.10.0: matches the Updater / Not Updatable dashboard
    ## strips so the whole suite reads with one visual language.
    $tgtTileSpecs = @(
        @{ Key='Targets';  Eyebrow='Targets Loaded';   Accent=$theme.Accent1 }
        @{ Key='Findings'; Eyebrow='ACAS Findings';    Accent=$theme.Accent2 }
        @{ Key='Hosts';    Eyebrow='Unique Hosts';     Accent=$theme.Success }
        @{ Key='Import';   Eyebrow='Last Import';      Accent=$theme.Info }
    )
    $tgtTileW = 220; $tgtTileH = 96; $tgtTileGap = 16; $tgtTileX = 20; $tgtTileY = 76
    $tgtTileMap = @{}
    $tgtTileControls = @()
    for ($ti = 0; $ti -lt $tgtTileSpecs.Count; $ti++) {
        $spec = $tgtTileSpecs[$ti]
        $tx = $tgtTileX + ($ti * ($tgtTileW + $tgtTileGap))
        $tile = New-NemDashTile -Eyebrow $spec.Eyebrow -Hero '0' -Sub '-' `
            -X $tx -Y $tgtTileY -W $tgtTileW -H $tgtTileH -AccentColor $spec.Accent
    $tgtTileMap[$spec.Key] = $tile
        $tgtTileControls += $tile.Panel
    }
    $state.UI.Controls['targetsTiles'] = $tgtTileMap

    ## ========== ACTION ROW ==========
    ## Hero Import button + smaller management buttons.
    $btnImportAcas = New-WptButton -Text 'Import ACAS CSV' -X 20 -Y 192 -W 260 -H 44 `
        -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.BtnBig
    $btnClear = New-WptButton -Text 'Clear All' -X 296 -Y 198 -W 140 -H 32 `
        -Bg $theme.PanelLight -Fg $theme.Danger -Font $fonts.Body
    $btnRemove = New-WptButton -Text 'Remove Selected' -X 444 -Y 198 -W 180 -H 32 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body

    ## ========== TARGETS LIST ==========
    $lblCount = New-WptLabel -Text 'Targets list' -X 20 -Y 256 -W 300 -H 20 `
        -Font $fonts.EyebrowDim -Fg $theme.TextMuted
    $state.UI.Controls['targetsCount'] = $lblCount

    $lbx = New-Object System.Windows.Forms.ListBox
    $lbx.Dock            = 'Fill'
    $lbx.BorderStyle     = 'FixedSingle'
    $lbx.BackColor       = $theme.Input
    $lbx.ForeColor       = $theme.TextPrimary
    $lbx.Font            = $fonts.MonoSm
    $lbx.IntegralHeight  = $false
    $lbx.SelectionMode   = 'MultiExtended'
    $state.UI.Controls['targetsList'] = $lbx

    ## ========== HELPERS ==========

    $refreshTargets = {
        $s2 = Get-NemState
        $lb = $s2.UI.Controls['targetsList']
        $lb.BeginUpdate()
        $lb.Items.Clear()
        foreach ($t in $s2.Targets) { [void]$lb.Items.Add($t) }
        $lb.EndUpdate()

        ## Top "Targets list" eyebrow shows the count inline.
        $s2.UI.Controls['targetsCount'].Text = ("TARGETS LIST  ({0:N0})" -f $s2.Targets.Count)
        $s2.UI.Controls['statusTargets'].Text = "Targets: $($s2.Targets.Count)"

        ## v1.10.0: data-state tile strip refresh.
        $tiles = $s2.UI.Controls['targetsTiles']
        if ($tiles) {
            $uniqueHosts = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($row in $s2.AcasFindings) {
                $rh = $null
                if ($row.PSObject.Properties['DnsName'] -and $row.DnsName) { $rh = [string]$row.DnsName }
                elseif ($row.PSObject.Properties['NetBios'] -and $row.NetBios) { $rh = [string]$row.NetBios }
                elseif ($row.PSObject.Properties['IpAddress'] -and $row.IpAddress) { $rh = [string]$row.IpAddress }
                if ($rh) { [void]$uniqueHosts.Add($rh) }
            }
            $tiles['Targets'].Hero.Text  = ('{0:N0}' -f $s2.Targets.Count)
            $tiles['Targets'].Sub.Text   = if ($s2.Targets.Count -gt 0) { 'in-scope hostnames' } else { 'import a CSV to start' }
            $tiles['Findings'].Hero.Text = ('{0:N0}' -f $s2.AcasFindings.Count)
            $tiles['Findings'].Sub.Text  = if ($s2.AcasFindings.Count -gt 0) { 'plugin rows' } else { '-' }
            $tiles['Hosts'].Hero.Text    = ('{0:N0}' -f $uniqueHosts.Count)
            $tiles['Hosts'].Sub.Text     = if ($uniqueHosts.Count -gt 0) { 'found in scan(s)' } else { '-' }
            if ($s2.LastImportFile) {
                $leaf = Split-Path -Leaf ([string]$s2.LastImportFile)
                $tiles['Import'].Hero.Text = if ($leaf.Length -gt 22) { $leaf.Substring(0,19) + '...' } else { $leaf }
                $tiles['Import'].Hero.Font = New-Object System.Drawing.Font('Cascadia Mono', 11, [System.Drawing.FontStyle]::Bold)
                if ($s2.LastImportTime) {
                    $tiles['Import'].Sub.Text = ([datetime]$s2.LastImportTime).ToString('yyyy-MM-dd HH:mm')
                } else {
                    $tiles['Import'].Sub.Text = '-'
                }
            } else {
                $tiles['Import'].Hero.Text = '-'
                $tiles['Import'].Sub.Text  = 'no CSV imported yet'
            }
        }
    }.GetNewClosure()

    $addHostname = {
        param([string]$hostname)
        if ([string]::IsNullOrWhiteSpace($hostname)) { return $false }
        $h = $hostname.Trim()
        $s2 = Get-NemState
        foreach ($existing in $s2.Targets) {
            if ($existing -ieq $h) { return $false }
        }
        [void]$s2.Targets.Add($h)
        return $true
    }.GetNewClosure()

    ## ========== EVENT HANDLERS ==========

    $btnImportAcas.Add_Click({
        $s = Get-NemState
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Filter      = 'ACAS CSV (*.csv)|*.csv|All files (*.*)|*.*'
        $ofd.Title       = 'Select ACAS / Nessus CSV export'
        $ofd.Multiselect = $true
        if ($ofd.ShowDialog() -ne 'OK') { return }

        $totalRows = 0; $totalAdded = 0
        foreach ($csvPath in $ofd.FileNames) {
            try {
                $rows = Import-WptAcasCsv -Path $csvPath
                $hosts = Get-WptAcasTargetHosts -Rows $rows
                $rowCount = @($rows).Count
                $totalRows += $rowCount

                ## Archive a copy for the audit trail
                $dest = Join-Path $s.CsvDir ((Get-Date -Format 'yyyy-MM-dd_HH-mm-ss_') + (Split-Path -Leaf $csvPath))
                Copy-Item -LiteralPath $csvPath -Destination $dest -Force -ErrorAction SilentlyContinue

                ## Accumulate rows into AcasFindings for the Vulnerabilities tab + KB Installer.
                ## v1.8.3: server-prefix filter — drop msek-* (server) findings
                ## at the source so they never appear on cards / counts / runs.
                ## Workstations (msekl-/msekt-/msekw-) are kept as-is.
                $skippedServerRows = 0
                foreach ($row in $rows) {
                    $rh = $null
                    if     ($row.PSObject.Properties['DnsName']   -and $row.DnsName)   { $rh = [string]$row.DnsName }
                    elseif ($row.PSObject.Properties['NetBios']   -and $row.NetBios)   { $rh = [string]$row.NetBios }
                    elseif ($row.PSObject.Properties['IpAddress'] -and $row.IpAddress) { $rh = [string]$row.IpAddress }
                    if ($rh -and (Test-NemIsServer -HostName $rh)) {
                        $skippedServerRows++
                        continue
                    }
                    [void]$s.AcasFindings.Add($row)
                }

                $added = 0
                $skippedServerHosts = 0
                foreach ($h in $hosts) {
                    if (Test-NemIsServer -HostName $h) {
                        $skippedServerHosts++
                        continue
                    }
                    if (& $addHostname $h) { $added++ }
                }
                $totalAdded += $added
                $serverDetail = if ($skippedServerRows -gt 0 -or $skippedServerHosts -gt 0) {
                    "; servers_skipped=$skippedServerHosts hosts/$skippedServerRows rows"
                } else { '' }
                Write-NemAudit -Action 'ImportACAS' -Target (Split-Path -Leaf $csvPath) -Result 'OK' `
                    -Detail "+$added of $($hosts.Count) unique from $rowCount rows; findings=$($s.AcasFindings.Count)$serverDetail"

                ## v1.10.0: stash for the Last Import dashboard tile.
                $s['LastImportFile']  = (Split-Path -Leaf $csvPath)
                $s['LastImportTime']  = Get-Date
                $s['LastImportCount'] = $rowCount
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to parse '$(Split-Path -Leaf $csvPath)':`r`n$($_.Exception.Message)",
                    'ACAS Import Error', 'OK', 'Error') | Out-Null
                Write-NemAudit -Action 'ImportACAS' -Target (Split-Path -Leaf $csvPath) -Result 'Failed' -Detail $_.Exception.Message
            }
        }
        & $refreshTargets
    }.GetNewClosure())

    $btnClear.Add_Click({
        $s = Get-NemState
        if (@($s.Targets).Count -eq 0 -and @($s.AcasFindings).Count -eq 0) { return }
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Clear all $($s.Targets.Count) targets and $($s.AcasFindings.Count) findings?",
            'ACAS Nemesis', 'YesNo', 'Question')
        if ($ans -eq 'Yes') {
            $s.Targets.Clear()
            $s.AcasFindings.Clear()
            & $refreshTargets
            Write-NemAudit -Action 'TargetsClear' -Result 'OK' -Detail 'targets+findings cleared'
        }
    }.GetNewClosure())

    $btnRemove.Add_Click({
        $s = Get-NemState
        $lb = $s.UI.Controls['targetsList']
        $sel = @($lb.SelectedItems) | ForEach-Object { [string]$_ }
        if ($sel.Count -eq 0) { return }
        foreach ($item in $sel) { [void]$s.Targets.Remove($item) }
        & $refreshTargets
        Write-NemAudit -Action 'TargetsRemove' -Result 'OK' -Detail "-$($sel.Count)"
    }.GetNewClosure())

    ## ========== ASSEMBLE ==========
    ## v1.10.0: header carries the tile strip + the hero
    ## Import button + smaller management buttons. List goes in the
    ## body Fill area — no separate footer needed since the Remove
    ## button lives in the header action row now.
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 248
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@($lblTitle, $lblSub, $btnImportAcas, $btnClear, $btnRemove))
    foreach ($tilePanel in $tgtTileControls) { $header.Controls.Add($tilePanel) }

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock      = 'Fill'
    $body.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)
    $body.BackColor = [System.Drawing.Color]::Transparent

    $countWrap = New-Object System.Windows.Forms.Panel
    $countWrap.Dock      = 'Top'
    $countWrap.Height    = 28
    $countWrap.BackColor = [System.Drawing.Color]::Transparent
    $lblCount.Location   = New-Object System.Drawing.Point(0, 4)
    $countWrap.Controls.Add($lblCount)

    $body.Controls.Add($lbx)        # Dock=Fill — must be added FIRST so Dock=Top siblings stack above it
    $body.Controls.Add($countWrap)  # Dock=Top

    $TabPanel.Controls.Add($body)    # Dock=Fill — added first so it fills what's left after header
    $TabPanel.Controls.Add($header)  # Dock=Top

    ## Initial paint of the dashboard tiles so empty state reads cleanly.
    & $refreshTargets
}

function Add-NemVulnerabilitiesTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text 'Vulnerabilities' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Review ACAS / Nessus findings. Check rows to include them in Updater and KB Installer runs.' `
        -X 20 -Y 50 -W 1000 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== FINDINGS GRID TOOLBAR ==========
    $btnFSelAll = New-WptButton -Text 'Select All' `
        -X 20 -Y 96 -W 110 -H 30 -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.Body
    $btnFDeselAll = New-WptButton -Text 'Deselect All' `
        -X 138 -Y 96 -W 110 -H 30 -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body
    $btnFSelCritHigh = New-WptButton -Text 'Select Critical/High Only' `
        -X 256 -Y 96 -W 200 -H 30 -Bg $theme.Warning -Fg $theme.Background -Font $fonts.Body

    ## v1.6.1: explicit Reload button — populates the grid from the latest
    ## $script:Nemesis.AcasFindings without leaving the tab. Used after a
    ## fresh import on the Targets tab.
    $btnFReload = New-WptButton -Text 'Reload Findings' `
        -X 466 -Y 96 -W 140 -H 30 -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body

    $lblFCount = New-WptLabel -Text 'Not loaded yet — click Load Findings to populate the grid.' `
        -X 616 -Y 104 -W 480 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $state.UI.Controls['vulnsFindingsCount'] = $lblFCount

    $lblFNote = New-WptLabel `
        -Text 'Note: deselected rows are excluded from Updater (Smart Dispatch) and KB Installer runs. Target list is independent.' `
        -X 20 -Y 132 -W 1100 -H 18 -Font $fonts.MonoTiny -Fg $theme.TextFaint

    ## ========== FINDINGS GRID (DataGridView) ==========
    $dgvF = New-Object System.Windows.Forms.DataGridView
    $dgvF.Dock                 = 'Fill'
    $dgvF.AutoGenerateColumns  = $false
    $dgvF.AllowUserToAddRows   = $false
    $dgvF.RowHeadersVisible    = $false
    $dgvF.SelectionMode        = 'FullRowSelect'
    $dgvF.BackgroundColor      = $theme.Input
    $dgvF.ForeColor            = $theme.TextPrimary
    $dgvF.GridColor            = $theme.Border
    $dgvF.Font                 = $fonts.MonoSm
    $dgvF.BorderStyle          = 'None'
    $dgvF.ColumnHeadersBorderStyle = 'Single'
    $dgvF.EnableHeadersVisualStyles = $false
    $dgvF.DefaultCellStyle.BackColor = $theme.Input
    $dgvF.DefaultCellStyle.ForeColor = $theme.TextPrimary
    $dgvF.DefaultCellStyle.SelectionBackColor = $theme.SurfaceActive
    $dgvF.DefaultCellStyle.SelectionForeColor = $theme.TextPrimary
    $dgvF.AlternatingRowsDefaultCellStyle.BackColor = $theme.SurfaceAlt
    $dgvF.ColumnHeadersDefaultCellStyle.BackColor   = $theme.Sidebar
    $dgvF.ColumnHeadersDefaultCellStyle.ForeColor   = $theme.Accent1
    $dgvF.ColumnHeadersDefaultCellStyle.Font        = $fonts.MonoSm
    $dgvF.ColumnHeadersHeight     = 26
    $dgvF.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $dgvF.RowTemplate.Height     = 22

    ## Col: Select (checkbox)
    $colFSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colFSel.Name          = 'ColFSelect'
    $colFSel.HeaderText    = 'Select'
    $colFSel.Width         = 50
    $colFSel.AutoSizeMode  = 'None'
    $colFSel.TrueValue     = $true
    $colFSel.FalseValue    = $false
    $colFSel.IndeterminateValue = $false
    [void]$dgvF.Columns.Add($colFSel)

    ## Col: Host
    $colFHost = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colFHost.Name         = 'ColFHost'
    $colFHost.HeaderText   = 'Host'
    $colFHost.Width        = 260
    $colFHost.AutoSizeMode = 'None'
    $colFHost.ReadOnly     = $true
    [void]$dgvF.Columns.Add($colFHost)

    ## Col: Severity
    $colFSev = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colFSev.Name          = 'ColFSeverity'
    $colFSev.HeaderText    = 'Severity'
    $colFSev.Width         = 80
    $colFSev.AutoSizeMode  = 'None'
    $colFSev.ReadOnly      = $true
    [void]$dgvF.Columns.Add($colFSev)

    ## Col: Plugin (fill)
    $colFPlugin = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colFPlugin.Name         = 'ColFPlugin'
    $colFPlugin.HeaderText   = 'Plugin'
    $colFPlugin.AutoSizeMode = 'Fill'
    $colFPlugin.ReadOnly     = $true
    [void]$dgvF.Columns.Add($colFPlugin)

    ## Col: CVE (fill)
    $colFCve = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colFCve.Name          = 'ColFCve'
    $colFCve.HeaderText    = 'CVE'
    $colFCve.AutoSizeMode  = 'Fill'
    $colFCve.ReadOnly      = $true
    [void]$dgvF.Columns.Add($colFCve)

    ## Col: Solution (fill, wraps)
    $colFSol = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colFSol.Name          = 'ColFSolution'
    $colFSol.HeaderText    = 'Solution'
    $colFSol.AutoSizeMode  = 'Fill'
    $colFSol.ReadOnly      = $true
    $colFSol.DefaultCellStyle.WrapMode = 'True'
    [void]$dgvF.Columns.Add($colFSol)

    $state.UI.Controls['vulnsFindingsGrid'] = $dgvF

    ## ========== FINDINGS GRID HELPERS ==========

    $updateFindingsCount = {
        $s2   = Get-NemState
        $g    = $s2.UI.Controls['vulnsFindingsGrid']
        $lbl  = $s2.UI.Controls['vulnsFindingsCount']
        if (-not $g -or -not $lbl) { return }
        $total = $g.Rows.Count
        $sel   = 0
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $cell = $g.Rows[$ri].Cells['ColFSelect']
            if ($cell -and [bool]$cell.Value) { $sel++ }
        }
        $lbl.Text = "$total findings loaded ($sel selected)"
    }.GetNewClosure()

    $refreshFindingsGrid = {
        $s2     = Get-NemState
        $g      = $s2.UI.Controls['vulnsFindingsGrid']
        if (-not $g) { return }

        ## Snapshot existing checkbox state keyed by "Host|PluginName|Cve"
        $prevState = @{}
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $cell = $g.Rows[$ri].Cells['ColFSelect']
            $orig = $g.Rows[$ri].Tag
            if ($orig -and $cell) {
                $dns  = if ($orig.DnsName)   { [string]$orig.DnsName }   else { '' }
                $nb   = if ($orig.NetBios)   { [string]$orig.NetBios }   else { '' }
                $ip   = if ($orig.IpAddress) { [string]$orig.IpAddress } else { '' }
                if ($nb -match '\\') { $nb = $nb -replace '^[^\\]+\\', '' }
                $hostKey = if ($dns) { $dns } elseif ($nb) { $nb } else { $ip }
                $key = "$hostKey|$($orig.PluginName)|$($orig.Cve)"
                $prevState[$key.ToLower()] = [bool]$cell.Value
            }
        }

        $g.SuspendLayout()
        $g.Rows.Clear()

        foreach ($row in $s2.AcasFindings) {
            ## Resolve host display value (DNS > NetBIOS stripped > IP)
            $dns  = if ($row.DnsName)   { [string]$row.DnsName }   else { '' }
            $nb   = if ($row.NetBios)   { [string]$row.NetBios }   else { '' }
            $ip   = if ($row.IpAddress) { [string]$row.IpAddress } else { '' }
            if ($nb -match '\\') { $nb = $nb -replace '^[^\\]+\\', '' }
            $hostVal = if ($dns) { $dns } elseif ($nb) { $nb } else { $ip }

            $plugin = if ($row.PluginName) { [string]$row.PluginName } else { '' }
            $sev    = if ($row.Severity)   { [string]$row.Severity }   else { '' }
            $cve    = if ($row.Cve)        { [string]$row.Cve }        else { '' }
            $sol    = if ($row.Solution)   { [string]$row.Solution }   else { '' }

            ## Determine checked state: restore from snapshot, default $true (selected)
            $key     = "$hostVal|$plugin|$cve".ToLower()
            $checked = if ($prevState.ContainsKey($key)) { $prevState[$key] } else { $true }

            $rowIdx = $g.Rows.Add()
            $g.Rows[$rowIdx].Cells['ColFSelect'].Value   = $checked
            $g.Rows[$rowIdx].Cells['ColFHost'].Value     = $hostVal
            $g.Rows[$rowIdx].Cells['ColFSeverity'].Value = $sev
            $g.Rows[$rowIdx].Cells['ColFPlugin'].Value   = $plugin
            $g.Rows[$rowIdx].Cells['ColFCve'].Value      = $cve
            $g.Rows[$rowIdx].Cells['ColFSolution'].Value = $sol
            $g.Rows[$rowIdx].Tag                         = $row
        }

        $g.ResumeLayout()
        & $updateFindingsCount
    }.GetNewClosure()

    ## ========== FINDINGS GRID EVENT HANDLERS ==========

    $dgvF.Add_CurrentCellDirtyStateChanged({
        param($sender, $e)
        if ($sender.IsCurrentCellDirty) {
            $sender.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    }.GetNewClosure())

    $dgvF.Add_CellValueChanged({
        param($sender, $e)
        if ($e.ColumnIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq 'ColFSelect') {
            & $updateFindingsCount
        }
    }.GetNewClosure())

    $btnFSelAll.Add_Click({
        $s2 = Get-NemState
        $g  = $s2.UI.Controls['vulnsFindingsGrid']
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $g.Rows[$ri].Cells['ColFSelect'].Value = $true
        }
        & $updateFindingsCount
    }.GetNewClosure())

    $btnFDeselAll.Add_Click({
        $s2 = Get-NemState
        $g  = $s2.UI.Controls['vulnsFindingsGrid']
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $g.Rows[$ri].Cells['ColFSelect'].Value = $false
        }
        & $updateFindingsCount
    }.GetNewClosure())

    $btnFSelCritHigh.Add_Click({
        $s2  = Get-NemState
        $g   = $s2.UI.Controls['vulnsFindingsGrid']
        $hi  = @('Critical', 'High')
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $sev = [string]$g.Rows[$ri].Cells['ColFSeverity'].Value
            $g.Rows[$ri].Cells['ColFSelect'].Value = ($hi -icontains $sev)
        }
        & $updateFindingsCount
    }.GetNewClosure())

    ## ========== LOAD-OVERLAY (v1.6.1) ==========
    ## v1.6.1: removed the VisibleChanged auto-load handler. Re-populating
    ## a 400+ row DataGridView via Rows.Add() in a tight loop on every tab
    ## activation was crashing the host (paint storm + reentrancy). The
    ## tab now opens with an empty grid hidden under a centered "Load
    ## Findings" overlay; the operator clicks once to populate. After
    ## first load the toolbar's "Reload Findings" button covers re-imports
    ## without re-hiding the grid.
    $loadOverlay = New-Object System.Windows.Forms.Panel
    $loadOverlay.Dock      = 'Fill'
    $loadOverlay.BackColor = $theme.Background
    $state.UI.Controls['vulnsLoadOverlay'] = $loadOverlay

    ## Centered Load button — recalculate position on resize so it stays in
    ## the middle of whatever viewport the operator drags the window to.
    $btnLoadFindings = New-WptButton -Text 'Load Findings' `
        -X 0 -Y 0 -W 280 -H 60 `
        -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.DisplayMd
    $btnLoadFindings.Anchor = [System.Windows.Forms.AnchorStyles]::None

    $lblLoadHint = New-Object System.Windows.Forms.Label
    $lblLoadHint.AutoSize  = $false
    $lblLoadHint.Width     = 720
    $lblLoadHint.Height    = 60
    $lblLoadHint.Text      = "Loading large vulnerability lists is deferred until you click — auto-loading 400+ rows on tab activation can crash the WinForms host. Click the button above whenever you've imported a new ACAS CSV on the Targets tab."
    $lblLoadHint.Font      = $fonts.MonoSm
    $lblLoadHint.ForeColor = $theme.TextMuted
    $lblLoadHint.BackColor = [System.Drawing.Color]::Transparent
    $lblLoadHint.TextAlign = 'TopCenter'
    $lblLoadHint.Anchor    = [System.Windows.Forms.AnchorStyles]::None

    $loadOverlay.Controls.AddRange(@($btnLoadFindings, $lblLoadHint))

    ## Re-center the button + hint whenever the overlay is resized.
    $centerLoadOverlay = {
        $ov = $state.UI.Controls['vulnsLoadOverlay']
        if (-not $ov) { return }
        $cw = $ov.ClientSize.Width
        $ch = $ov.ClientSize.Height
        if ($cw -le 0 -or $ch -le 0) { return }
        $btn  = $null
        $hint = $null
        foreach ($c in $ov.Controls) {
            if ($c -is [System.Windows.Forms.Button]) { $btn = $c }
            elseif ($c -is [System.Windows.Forms.Label]) { $hint = $c }
        }
        if ($btn) {
            $btn.Left = [int](($cw - $btn.Width) / 2)
            $btn.Top  = [int](($ch - $btn.Height - 80) / 2)
        }
        if ($hint -and $btn) {
            $hint.Left = [int](($cw - $hint.Width) / 2)
            $hint.Top  = $btn.Bottom + 16
        }
    }.GetNewClosure()

    $loadOverlay.Add_Resize({ & $centerLoadOverlay }.GetNewClosure())

    ## ========== LOAD-OVERLAY EVENT ==========
    $btnLoadFindings.Add_Click({
        $s2 = Get-NemState
        $g  = $s2.UI.Controls['vulnsFindingsGrid']
        $ov = $s2.UI.Controls['vulnsLoadOverlay']
        try {
            ## Populate first, then swap visibility — gives the long-running
            ## Rows.Add() loop a fully-hidden grid to write into (no paint
            ## storms while it runs).
            & $refreshFindingsGrid
            if ($g)  { $g.Visible  = $true }
            if ($ov) { $ov.Visible = $false }
            Write-NemAudit -Action 'VulnsLoad' -Target 'on-demand' -Result 'OK' `
                -Detail "rows=$($g.Rows.Count)"
        } catch {
            try {
                Write-NemAudit -Action 'VulnsLoad' -Target 'on-demand' -Result 'Failed' `
                    -Detail $_.Exception.Message
            } catch {}
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to load findings: $($_.Exception.Message)",
                'ACAS Nemesis - Load error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $btnFReload.Add_Click({
        ## Reload re-runs the populator without touching overlay visibility —
        ## the grid is already shown (post-first-load), the operator just
        ## wants to pick up a fresh import.
        try {
            & $refreshFindingsGrid
            $s2 = Get-NemState
            $g  = $s2.UI.Controls['vulnsFindingsGrid']
            Write-NemAudit -Action 'VulnsReload' -Target 'toolbar' -Result 'OK' `
                -Detail "rows=$($g.Rows.Count)"
        } catch {
            try {
                Write-NemAudit -Action 'VulnsReload' -Target 'toolbar' -Result 'Failed' `
                    -Detail $_.Exception.Message
            } catch {}
            [System.Windows.Forms.MessageBox]::Show(
                "Reload failed: $($_.Exception.Message)",
                'ACAS Nemesis - Reload error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    ## Grid starts hidden — overlay covers the body until the operator
    ## explicitly loads. After load, the grid stays visible across tab
    ## switches (no re-hide on VisibleChanged).
    $dgvF.Visible = $false

    ## ========== ASSEMBLE (Dock-based: header / fill) ==========
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 156
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@(
        $lblTitle, $lblSub,
        $btnFSelAll, $btnFDeselAll, $btnFSelCritHigh, $btnFReload,
        $lblFCount, $lblFNote
    ))

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock      = 'Fill'
    $body.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)
    $body.BackColor = [System.Drawing.Color]::Transparent
    ## Order matters for Dock=Fill z-order: last added paints on top.
    ## Grid first (so it's the bottom layer), overlay last (paints over
    ## the empty grid until the operator clicks Load).
    $body.Controls.Add($dgvF)         # Dock=Fill — bottom layer
    $body.Controls.Add($loadOverlay)  # Dock=Fill — paints on top until load

    $TabPanel.Controls.Add($body)    # Dock=Fill — added first
    $TabPanel.Controls.Add($header)  # Dock=Top

    ## Trigger an initial center so the button is positioned correctly
    ## the first time the tab becomes visible.
    & $centerLoadOverlay
}

function global:Update-NemVulnCards {
    <#
        Rebuild the Updater card list from the currently selected ACAS
        findings.  Routing by Category:
          Unpatchable / NotUpdatable  -> Not Updatable tab (skip here)
          Reboot                      -> New-NemRebootCard
          Experimental                -> New-NemVulnCard (with Experimental styling)
          Patchable                   -> New-NemVulnCard (standard)
        Cards rendered in order: Patchable, then Experimental, then Reboot
        (already guaranteed by the CatRank sort in Get-NemVulnGroups).
        Called on VisibleChanged + Refresh.
    #>
    $s     = Get-NemState
    $host2 = $s.UI.Controls['updCardsHost']
    if (-not $host2) { return }

    ## v1.10.2: cancel any prior in-flight chunked builder so a fresh
    ## Refresh / Selection-change re-render doesn't race with cards from
    ## the previous pass appearing alongside the new ones.
    if ($s.UI.Controls.ContainsKey('updCardsBuilder') -and $s.UI.Controls['updCardsBuilder']) {
        $prior = $s.UI.Controls['updCardsBuilder']
        try { $prior.Stop()    } catch {}
        try { $prior.Dispose() } catch {}
        $s.UI.Controls.Remove('updCardsBuilder')      | Out-Null
    }
    if ($s.UI.Controls.ContainsKey('updCardsBuilderState')) {
        $s.UI.Controls.Remove('updCardsBuilderState') | Out-Null
    }

    $host2.SuspendLayout()
    foreach ($c in @($host2.Controls)) {
        $host2.Controls.Remove($c)
        try { $c.Dispose() } catch {}
    }
    $s.UI.Controls['updVulnCards'] = [System.Collections.ArrayList]::new()
    $host2.ResumeLayout()

    ## v1.5.0: Get-NemVulnCardEntries wraps Get-NemVulnGroups and rolls up
    ## same-profile vulns into synthetic group entries. The card builder
    ## (New-NemVulnCard) handles both shapes — IsGroup flag triggers the
    ## ROLLUP badge + member tooltip.
    $all = @(Get-NemVulnCardEntries)
    ## Updater tab shows Patchable, Experimental, and Reboot categories.
    $updCategories = @('Patchable', 'Experimental', 'Reboot')
    $groups = @($all | Where-Object {
        $cat = ''
        if ($_.PSObject.Properties['Category'] -and $_.Category) { $cat = $_.Category }
        $updCategories -contains $cat
    })

    if ($groups.Count -eq 0) {
        $hintCount = @($all | Where-Object {
            $cat = ''
            if ($_.PSObject.Properties['Category'] -and $_.Category) { $cat = $_.Category }
            ($cat -eq 'Unpatchable') -or ($cat -eq 'NotUpdatable') -or ($cat -eq '')
        }).Count
        $msg = if ($hintCount -gt 0) {
            "No updatable vulnerabilities. $hintCount finding(s) require manual remediation — see the Not Updatable tab."
        } else {
            'No vulnerabilities to display. Import an ACAS CSV on the Targets tab, then check rows on the Vulnerabilities tab.'
        }
        $empty = New-Object System.Windows.Forms.Label
        $empty.AutoSize  = $false
        $empty.Width     = [Math]::Max(400, $host2.ClientSize.Width - 24)
        $empty.Height    = 80
        $empty.Text      = $msg
        $empty.Font      = $s.UI.Fonts.Body
        $empty.ForeColor = $s.UI.Theme.TextMuted
        $empty.BackColor = [System.Drawing.Color]::Transparent
        $empty.TextAlign = 'MiddleCenter'
        $empty.Margin    = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
        $host2.Controls.Add($empty)
        try { Update-NemUpdaterSummary -Entries $all } catch {
            Write-NemAudit -Action 'UpdaterSummary.Refresh' -Result 'Failed' -Detail $_.Exception.Message
        }
        return
    }

    ## v1.10.2: chunked card build. Building hundreds of WinForms Panels
    ## (each with ~7 child controls + event hooks) in one synchronous
    ## foreach can run 5-30s on a 9k-finding import — long enough for
    ## Windows to draw the unresponsive "white form + spinner" overlay
    ## over the tool. The list is rendered N at a time off a 1-tick
    ## System.Windows.Forms.Timer so the WinForms message pump runs
    ## between batches; cards visibly fill in instead of the host
    ## locking up. The builder + queue stash live on $s.UI.Controls so
    ## Cancel/Refresh can dispose them.
    $builderState = @{
        Queue   = [System.Collections.ArrayList]@($groups)
        All     = $all
        BatchSz = 10
    }
    $s.UI.Controls['updCardsBuilderState'] = $builderState

    $builder = New-Object System.Windows.Forms.Timer
    $builder.Interval = 1
    $builder.Add_Tick({
        param($sender, $e)
        $s2 = Get-NemState
        $h2 = $s2.UI.Controls['updCardsHost']
        $st = $s2.UI.Controls['updCardsBuilderState']
        if (-not $h2 -or -not $st) {
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            $s2.UI.Controls.Remove('updCardsBuilder')      | Out-Null
            $s2.UI.Controls.Remove('updCardsBuilderState') | Out-Null
            return
        }
        $q  = $st.Queue
        $bs = [int]$st.BatchSz

        $h2.SuspendLayout()
        for ($i = 0; ($i -lt $bs) -and ($q.Count -gt 0); $i++) {
            $g = $q[0]; [void]$q.RemoveAt(0)
            $cat = ''
            if ($g.PSObject.Properties['Category'] -and $g.Category) { $cat = $g.Category }
            $card = $null
            try {
                if ($cat -eq 'Reboot') { $card = New-NemRebootCard -Vuln $g }
                else                   { $card = New-NemVulnCard   -Vuln $g }
            } catch {
                Write-NemAudit -Action 'VulnCards.BuildCard' -Result 'Failed' -Detail $_.Exception.Message
                continue
            }
            if ($card) { $h2.Controls.Add($card) }
        }
        ## Width sync runs every tick — newly added cards pick up the
        ## current host viewport width. Cheap (just Width = N on Panels).
        $targetW = [Math]::Max(400, $h2.ClientSize.Width - 20)
        foreach ($ctrl in $h2.Controls) {
            if ($ctrl -is [System.Windows.Forms.Panel]) { $ctrl.Width = $targetW }
        }
        $h2.ResumeLayout()

        if ($q.Count -eq 0) {
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            $s2.UI.Controls.Remove('updCardsBuilder')      | Out-Null
            $s2.UI.Controls.Remove('updCardsBuilderState') | Out-Null
            try { Update-NemUpdaterSummary -Entries $st.All } catch {
                Write-NemAudit -Action 'UpdaterSummary.Refresh' -Result 'Failed' -Detail $_.Exception.Message
            }
        }
    })
    $s.UI.Controls['updCardsBuilder'] = $builder
    $builder.Start()
}

function global:Update-NemNonUpdatableCards {
    <#
        Rebuild the Not Updatable card list.  Mirror layout of the Updater
        tab but cards are info-only — no profile dropdown, no Run button.
        Driven by the same Get-NemVulnGroups feed.
    #>
    $s     = Get-NemState
    $host2 = $s.UI.Controls['nupCardsHost']
    if (-not $host2) { return }

    ## v1.10.2: cancel any in-flight chunked builder. Same pattern as
    ## Update-NemVulnCards on the Updater tab.
    if ($s.UI.Controls.ContainsKey('nupCardsBuilder') -and $s.UI.Controls['nupCardsBuilder']) {
        $prior = $s.UI.Controls['nupCardsBuilder']
        try { $prior.Stop()    } catch {}
        try { $prior.Dispose() } catch {}
        $s.UI.Controls.Remove('nupCardsBuilder')      | Out-Null
    }
    if ($s.UI.Controls.ContainsKey('nupCardsBuilderState')) {
        $s.UI.Controls.Remove('nupCardsBuilderState') | Out-Null
    }

    $host2.SuspendLayout()
    foreach ($c in @($host2.Controls)) {
        $host2.Controls.Remove($c)
        try { $c.Dispose() } catch {}
    }
    $host2.ResumeLayout()

    ## v1.10.1: this tab works off Get-NemVulnGroups (not the grouped
    ## Card Entries feed). Compute once and reuse for the summary tile
    ## refresh below — saves the second classify/sort pass.
    $all = @(Get-NemVulnGroups)
    ## Not Updatable tab shows Unpatchable + NotUpdatable categories.
    $nupCategories = @('Unpatchable', 'NotUpdatable')
    $groups = @($all | Where-Object {
        $cat = ''
        if ($_.PSObject.Properties['Category'] -and $_.Category) { $cat = $_.Category }
        $nupCategories -contains $cat
    })

    if ($groups.Count -eq 0) {
        $empty = New-Object System.Windows.Forms.Label
        $empty.AutoSize  = $false
        $empty.Width     = [Math]::Max(400, $host2.ClientSize.Width - 24)
        $empty.Height    = 80
        $empty.Text      = 'All selected vulnerabilities have a matching update profile. Nothing to show here.'
        $empty.Font      = $s.UI.Fonts.Body
        $empty.ForeColor = $s.UI.Theme.TextMuted
        $empty.BackColor = [System.Drawing.Color]::Transparent
        $empty.TextAlign = 'MiddleCenter'
        $empty.Margin    = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
        $host2.Controls.Add($empty)
        try { Update-NemNotUpdatableSummary -Groups $all } catch {
            Write-NemAudit -Action 'NotUpdatableSummary.Refresh' -Result 'Failed' -Detail $_.Exception.Message
        }
        return
    }

    ## v1.10.2: chunked card build (same rationale as Update-NemVulnCards).
    ## Section headers are kept in-stream as 'Header' entries so the queue
    ## reads top-to-bottom and the Tick handler emits whichever next.
    $unpatchable  = @($groups | Where-Object { $_.Category -eq 'Unpatchable' })
    $notUpdatable = @($groups | Where-Object { $_.Category -eq 'NotUpdatable' })

    $queue = [System.Collections.ArrayList]::new()
    if ($unpatchable.Count -gt 0) {
        [void]$queue.Add(@{ Kind = 'Header'; Text = 'UNPATCHABLE — manual remediation required'; IsDanger = $true })
        foreach ($g in $unpatchable) { [void]$queue.Add(@{ Kind = 'Card'; Vuln = $g }) }
    }
    if ($notUpdatable.Count -gt 0) {
        [void]$queue.Add(@{ Kind = 'Header'; Text = 'UNCLASSIFIED — no profile mapped'; IsDanger = $false })
        foreach ($g in $notUpdatable) { [void]$queue.Add(@{ Kind = 'Card'; Vuln = $g }) }
    }

    $s.UI.Controls['nupCardsBuilderState'] = @{
        Queue   = $queue
        All     = $all
        BatchSz = 10
    }

    $builder = New-Object System.Windows.Forms.Timer
    $builder.Interval = 1
    $builder.Add_Tick({
        param($sender, $e)
        $s2 = Get-NemState
        $h2 = $s2.UI.Controls['nupCardsHost']
        $st = $s2.UI.Controls['nupCardsBuilderState']
        if (-not $h2 -or -not $st) {
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            $s2.UI.Controls.Remove('nupCardsBuilder')      | Out-Null
            $s2.UI.Controls.Remove('nupCardsBuilderState') | Out-Null
            return
        }
        $q  = $st.Queue
        $bs = [int]$st.BatchSz

        $h2.SuspendLayout()
        for ($i = 0; ($i -lt $bs) -and ($q.Count -gt 0); $i++) {
            $item = $q[0]; [void]$q.RemoveAt(0)
            try {
                if ($item.Kind -eq 'Header') {
                    $fg = if ($item.IsDanger) { $s2.UI.Theme.Danger } else { $s2.UI.Theme.TextMuted }
                    $hdr = New-WptLabel -Text $item.Text -X 0 -Y 0 -W 900 -H 22 -Font $s2.UI.Fonts.MonoSm -Fg $fg
                    $topPad = if ($item.IsDanger) { 8 } else { 12 }
                    $hdr.Margin = New-Object System.Windows.Forms.Padding(0, $topPad, 0, 4)
                    $h2.Controls.Add($hdr)
                } else {
                    $card = New-NemNonUpdatableCard -Vuln $item.Vuln
                    if ($card) { $h2.Controls.Add($card) }
                }
            } catch {
                Write-NemAudit -Action 'NonUpdatableCards.BuildItem' -Result 'Failed' -Detail $_.Exception.Message
            }
        }
        $targetW = [Math]::Max(400, $h2.ClientSize.Width - 20)
        foreach ($ctrl in $h2.Controls) {
            if ($ctrl -is [System.Windows.Forms.Panel]) { $ctrl.Width = $targetW }
            elseif ($ctrl -is [System.Windows.Forms.Label]) { $ctrl.Width = $targetW }
        }
        $h2.ResumeLayout()

        if ($q.Count -eq 0) {
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            $s2.UI.Controls.Remove('nupCardsBuilder')      | Out-Null
            $s2.UI.Controls.Remove('nupCardsBuilderState') | Out-Null
            try { Update-NemNotUpdatableSummary -Groups $st.All } catch {
                Write-NemAudit -Action 'NotUpdatableSummary.Refresh' -Result 'Failed' -Detail $_.Exception.Message
            }
        }
    })
    $s.UI.Controls['nupCardsBuilder'] = $builder
    $builder.Start()
}

function global:Update-NemNotUpdatableSummary {
    <#
        Walk Get-NemVulnGroups for entries in the Unpatchable / NotUpdatable
        categories and update the 4-tile strip on the Not Updatable tab.
        v1.10.1: optional -Groups param lets Update-NemNonUpdatableCards
        forward its Get-NemVulnGroups output so the grouping pass only
        runs once.
    #>
    param($Groups)
    $s = Get-NemState
    $tiles = $s.UI.Controls['nupSummaryTiles']
    if (-not $tiles) { return }

    $all = if ($PSBoundParameters.ContainsKey('Groups') -and $null -ne $Groups) {
        @($Groups)
    } else {
        @(Get-NemVulnGroups)
    }
    $notPatch = @($all | Where-Object {
        $cat = ''; if ($_.PSObject.Properties['Category'] -and $_.Category) { $cat = $_.Category }
        $cat -in @('Unpatchable','NotUpdatable')
    })

    $sevCount = { param($entries, $sev)
        @($entries | Where-Object {
            $s2 = ''; if ($_.Severity) { $s2 = $_.Severity.ToLowerInvariant() }
            $s2 -eq $sev
        }).Count
    }
    $crit = & $sevCount $notPatch 'critical'
    $high = & $sevCount $notPatch 'high'

    $allHosts = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $notPatch) {
        if ($e.PSObject.Properties['Hosts'] -and $e.Hosts) {
            foreach ($h in $e.Hosts) { [void]$allHosts.Add([string]$h) }
        }
    }
    $hostCount = $allHosts.Count

    $fmt = { param($n) ('{0:N0}' -f [int]$n) }

    $tiles['Total'].Hero.Text    = & $fmt $notPatch.Count
    $tiles['Total'].Sub.Text     = if ($notPatch.Count -gt 0) { 'requires manual work' } else { 'nothing here' }

    $tiles['Critical'].Hero.Text = & $fmt $crit
    $tiles['Critical'].Sub.Text  = if ($crit -gt 0) { 'plan a manual fix' } else { 'none' }

    $tiles['High'].Hero.Text     = & $fmt $high
    $tiles['High'].Sub.Text      = if ($high -gt 0) { 'high severity' } else { 'none' }

    $tiles['Hosts'].Hero.Text    = & $fmt $hostCount
    $tiles['Hosts'].Sub.Text     = if ($hostCount -gt 0) { 'unique affected' } else { '-' }
}

function global:New-NemNonUpdatableCard {
    <#
        Info-only card for Unpatchable / NotUpdatable vulnerabilities.
        Unpatchable cards show a context-specific remediation note
        and a "Copy Plan" button (copies hosts + CVEs + Solution to clipboard).
        NotUpdatable cards show the standard "no profile mapped" hint.
    #>
    param($Vuln)

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $fonts = $s.UI.Fonts

    $sevLower = ''
    if ($Vuln.Severity) { $sevLower = $Vuln.Severity.ToLowerInvariant() }
    $sevColor = switch ($sevLower) {
        'critical' { $theme.Danger }
        'high'     { $theme.Warning }
        'medium'   { $theme.Accent2 }
        'low'      { $theme.TextMuted }
        'info'     { $theme.Info }
        default    { $theme.Border }
    }

    $isUnpatchable = ($Vuln.PSObject.Properties['Category'] -and $Vuln.Category -eq 'Unpatchable')

    ## Determine the remediation note text based on PluginName for Unpatchable cards.
    $noteText = ''
    if ($isUnpatchable) {
        $pn = $Vuln.DisplayName
        if ($pn.IndexOf('Log4j', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $noteText = 'Log4j — redistribute/patch the bundled library. Not a Windows Update or Office C2R fix.'
        } elseif ($pn.IndexOf('Oracle Database', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $noteText = 'Oracle Database — requires DBA action / CPU patch download from support.oracle.com.'
        } elseif (($pn.IndexOf('Speculative Execution', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($pn.IndexOf('Intel BHI', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($pn.IndexOf('Spectre', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($pn.IndexOf('Meltdown', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                  ($pn.IndexOf('ZombieLoad', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            $noteText = 'CPU microcode / registry mitigation — typically applied via GPO or OEM BIOS update.'
        } else {
            $noteText = 'Manual remediation required. Consult vendor advisory for patch or workaround steps.'
        }
    } else {
        $noteText = 'No matched update profile. Add one to Get-NemProfileMatchTable + $script:WptAppUpdateProfiles to enable remediation.'
    }

    ## v1.10.0: compact card. CVE list goes to tooltip on title;
    ## Solution preview folds into the note row for Unpatchable cards.
    ##   Unpatchable: 116px tall (3 content rows: title+sev / note / solution)
    ##   NotUpdatable: 92px tall (2 content rows: title+sev / note)
    $cardH = if ($isUnpatchable) { 116 } else { 92 }

    $card = New-Object System.Windows.Forms.Panel
    $card.Width       = 1000
    $card.Height      = $cardH
    $card.BackColor   = $theme.Surface
    $card.BorderStyle = 'FixedSingle'
    $card.Margin      = New-Object System.Windows.Forms.Padding(0, 0, 0, 14)

    ## Danger accent strip for Unpatchable, severity colour otherwise.
    $accentColor = if ($isUnpatchable) { $theme.Danger } else { $sevColor }
    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock      = 'Top'
    $accent.Height    = 4
    $accent.BackColor = $accentColor
    $card.Controls.Add($accent)

    ## Row 1: severity badge + title.
    $sevText  = if ($Vuln.Severity) { $Vuln.Severity.ToUpperInvariant() } else { 'UNKNOWN' }
    $sevBadge = New-WptLabel -Text "[$sevText]" `
        -X 18 -Y 14 -W 96 -H 18 -Font $fonts.MonoSm -Fg $sevColor

    $lblName = New-WptLabel -Text $Vuln.DisplayName `
        -X 116 -Y 14 -W 660 -H 18 -Font $fonts.BodyStrong -Fg $theme.TextPrimary
    $lblName.AutoEllipsis = $true

    ## Host count on the right (no Run button column to fight with for non-Unpatchable).
    $hostsPrev = ''
    if ($Vuln.Hosts -and @($Vuln.Hosts).Count -gt 0) {
        $firstHosts = @($Vuln.Hosts) | Select-Object -First 12
        $hostsPrev  = "Affected hosts ($($Vuln.HostCount)):`r`n  " + ($firstHosts -join "`r`n  ")
        if (@($Vuln.Hosts).Count -gt 12) { $hostsPrev += "`r`n  ...+$(@($Vuln.Hosts).Count - 12) more" }
    }
    $hostText = ('{0:N0} host(s)' -f [int]$Vuln.HostCount)
    $hostsX = if ($isUnpatchable) { 608 } else { 800 }
    $hostsW = if ($isUnpatchable) { 170 } else { 184 }
    $lblHosts = New-WptLabel -Text $hostText `
        -X $hostsX -Y 14 -W $hostsW -H 18 -Font $fonts.MonoSm -Fg $theme.TextSecondary
    $lblHosts.TextAlign = 'MiddleRight'

    ## CVE list + member list -> tooltip on the title.
    $titleTipParts = @()
    if ($Vuln.Cves -and @($Vuln.Cves).Count -gt 0) {
        $titleTipParts += ('CVE: ' + ((@($Vuln.Cves)) -join ', '))
    }
    ## v1.10.1: was 2 fresh ToolTip allocations per card; now reuses the
    ## session-wide singleton.
    if ($titleTipParts.Count -gt 0) {
        try { (Get-NemSharedToolTip).SetToolTip($lblName, ($titleTipParts -join "`r`n`r`n")) } catch {}
    }
    if ($hostsPrev) {
        try { (Get-NemSharedToolTip).SetToolTip($lblHosts, $hostsPrev) } catch {}
    }

    ## Row 2: remediation note.
    $noteFg = if ($isUnpatchable) { $theme.Danger } else { $theme.TextFaint }
    $lblNote = New-WptLabel -Text $noteText `
        -X 18 -Y 44 -W 780 -H 18 -Font $fonts.MonoSm -Fg $noteFg
    $lblNote.AutoEllipsis = $true

    $controlList = @($lblName, $sevBadge, $lblNote, $lblHosts)

    if ($isUnpatchable) {
        ## Solution text (collapsed into a single truncated line — full text goes to clipboard).
        $solText = ''
        if ($Vuln.PSObject.Properties['Solution'] -and $Vuln.Solution) {
            $solText = [string]$Vuln.Solution
        }
        $solPreview = if ($solText.Length -gt 160) { $solText.Substring(0, 157) + '...' } else { $solText }
        $lblSol = New-WptLabel -Text "Steps: $solPreview" `
            -X 18 -Y 70 -W 780 -H 36 -Font $fonts.MonoTiny -Fg $theme.TextFaint

        ## Copy Plan button.
        $btnCopy = New-WptButton -Text 'Copy Plan' -X 810 -Y 14 -W 170 -H 32 `
            -Bg $theme.Danger -Fg $theme.TextOnAccent -Font $fonts.Body
        $btnCopy.Anchor = 'Top,Right'

        $btnCopy.Add_Click({
            $hostList   = @($Vuln.Hosts) -join "`r`n"
            $cveList    = (@($Vuln.Cves) -join ', ')
            $solFull    = ''
            if ($Vuln.PSObject.Properties['Solution'] -and $Vuln.Solution) { $solFull = [string]$Vuln.Solution }
            $plan = "UNPATCHABLE FINDING: $($Vuln.DisplayName)`r`n"
            $plan += "Severity  : $($Vuln.Severity)`r`n"
            $plan += "CVEs      : $cveList`r`n"
            $plan += "Hosts ($($Vuln.HostCount)):`r`n$hostList`r`n"
            $plan += "Steps to Remediate:`r`n$solFull"
            try {
                [System.Windows.Forms.Clipboard]::SetText($plan)
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Clipboard write failed: $($_.Exception.Message)",
                    'ACAS Nemesis', 'OK', 'Warning') | Out-Null
            }
        }.GetNewClosure())

        $controlList += $lblSol
        $controlList += $btnCopy
    }

    $card.Controls.AddRange($controlList)
    return $card
}

function global:New-NemVulnCard {
    <#
        Build one vuln card.  Card renders:
          - plugin name (title row)
          - severity badge + CVEs
          - matched profile (or 'No profile mapped')
          - affected host count + first few hostnames
          - Run button (disabled when no profile matched)
        Card is registered in $state.UI.Controls['updVulnCards'] so the
        master run-lock can toggle its Run button with the others.
    #>
    param($Vuln)

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $fonts = $s.UI.Fonts

    $sevLower = ''
    if ($Vuln.Severity) { $sevLower = $Vuln.Severity.ToLowerInvariant() }
    $sevColor = switch ($sevLower) {
        'critical' { $theme.Danger }
        'high'     { $theme.Warning }
        'medium'   { $theme.Accent2 }
        'low'      { $theme.TextMuted }
        'info'     { $theme.Info }
        default    { $theme.Border }
    }

    ## Experimental-category flag — affects accent colour, label, and Run button.
    $isExperimental = ($Vuln.PSObject.Properties['Category'] -and $Vuln.Category -eq 'Experimental')

    ## v1.5.0: Group-rollup flag. A synthetic vuln from Get-NemVulnCardEntries
    ## has IsGroup=$true and GroupMembers populated. The card renders the same
    ## as a per-vuln card but with a ROLLUP badge + a tooltip listing members,
    ## and the Run/Verify clicks pass GroupKey/GroupMembers into Start-NemVulnRun
    ## so the audit fan-out writes one CSV row per member vuln.
    $isGroup = ($Vuln.PSObject.Properties['IsGroup'] -and $Vuln.IsGroup)

    ## v1.10.0: compact card. Two content rows + top accent.
    ## Density is much higher now (96px vs 156px in pass 3) so more cards
    ## fit on screen at once. CVE list + affected-host preview move to
    ## TOOLTIPS on the title + host-count labels — still one hover away,
    ## but they don't take chrome space.
    ##
    ##  Row 1 (y=12):  Title (BodyStrong)  [SEVERITY]  [ROLLUP/EXPERIMENTAL]
    ##  Row 2 (y=40):  Profile combo or label             N,NNN hosts
    ##  Right column:  Run button (y=14, h=34)
    ##                 Verify (y=54, h=28)
    $card = New-Object System.Windows.Forms.Panel
    $card.Width       = 1000
    $card.Height      = 96
    $card.BackColor   = $theme.Surface
    $card.BorderStyle = 'FixedSingle'
    $card.Margin      = New-Object System.Windows.Forms.Padding(0, 0, 0, 14)

    ## Amber accent bar for Experimental, severity colour otherwise.
    $accentColor = if ($isExperimental) { $theme.Warning } else { $sevColor }
    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock      = 'Top'
    $accent.Height    = 4
    $accent.BackColor = $accentColor
    $card.Controls.Add($accent)

    ## ----- Row 1: title + severity badge + optional EXP/ROLLUP badge -----
    $sevText = if ($Vuln.Severity) { $Vuln.Severity.ToUpperInvariant() } else { 'UNKNOWN' }
    $sevBadge = New-WptLabel -Text "[$sevText]" `
        -X 18 -Y 14 -W 96 -H 18 -Font $fonts.MonoSm -Fg $sevColor

    ## ROLLUP / EXPERIMENTAL badge sits right of the severity tag.
    $lblExpBadge = $null
    if ($isExperimental) {
        $lblExpBadge = New-WptLabel -Text '[EXPERIMENTAL]' `
            -X 116 -Y 14 -W 130 -H 18 -Font $fonts.MonoSm -Fg $theme.Warning
    } elseif ($isGroup) {
        $memberCount = @($Vuln.GroupMembers).Count
        $lblExpBadge = New-WptLabel -Text "[ROLLUP x$memberCount]" `
            -X 116 -Y 14 -W 130 -H 18 -Font $fonts.MonoSm -Fg $theme.Accent2
    }
    $nameX = if ($lblExpBadge) { 250 } else { 116 }
    $nameW = 540   # leaves ~250px gutter before the Run button column at X=792
    $lblName = New-WptLabel -Text $Vuln.DisplayName `
        -X $nameX -Y 14 -W $nameW -H 18 -Font $fonts.BodyStrong -Fg $theme.TextPrimary
    $lblName.AutoEllipsis = $true

    ## Tooltip on the title carries the CVE list + (for groups) member list.
    $titleTipParts = @()
    if ($Vuln.Cves -and @($Vuln.Cves).Count -gt 0) {
        $cveAll = @($Vuln.Cves) -join ', '
        $titleTipParts += "CVE: $cveAll"
    }
    if ($isGroup) {
        $members = @($Vuln.GroupMembers)
        $shown   = @($members | Select-Object -First 25)
        $memberList = "Rolled-up vulns ($($members.Count)):`r`n" + ((@($shown | ForEach-Object { ' - ' + $_.DisplayName })) -join "`r`n")
        if ($members.Count -gt $shown.Count) {
            $memberList += "`r`n   ...+$($members.Count - $shown.Count) more"
        }
        $titleTipParts += $memberList
    }
    ## v1.10.1: shared singleton tooltip — was 1 fresh ToolTip per card.
    if ($titleTipParts.Count -gt 0) {
        try {
            $tt = Get-NemSharedToolTip
            $tipText = $titleTipParts -join "`r`n`r`n"
            $tt.SetToolTip($lblName, $tipText)
            if ($lblExpBadge) { $tt.SetToolTip($lblExpBadge, $tipText) }
        } catch {}
    }

    ## ----- Row 2: profile dropdown (or label) + host count -----
    $profileNames = @($Vuln.ProfileNames)
    $cboProfile = $null
    $lblProfCaption = $null
    if ($profileNames.Count -gt 1) {
        $lblProfCaption = New-WptLabel -Text 'Profile:' `
            -X 18 -Y 44 -W 60 -H 22 -Font $fonts.MonoSm -Fg $theme.Accent2
        $cboProfile = New-WptComboBox -X 80 -Y 42 -W 440 -H 24 -Items $profileNames
        $cboProfile.SelectedIndex = 0
    } elseif ($profileNames.Count -eq 1) {
        $profDescText = if ($isExperimental) {
            "EXPERIMENTAL - verify on a test host first. Profile: $($profileNames[0])"
        } else {
            "Profile: $($profileNames[0])"
        }
        $profDescFg = if ($isExperimental) { $theme.Warning } else { $theme.Accent2 }
        $lblProfCaption = New-WptLabel -Text $profDescText `
            -X 18 -Y 44 -W 580 -H 18 -Font $fonts.MonoSm -Fg $profDescFg
        $lblProfCaption.AutoEllipsis = $true
    } else {
        $lblProfCaption = New-WptLabel -Text 'No profile mapped - nothing to run.' `
            -X 18 -Y 44 -W 580 -H 18 -Font $fonts.MonoSm -Fg $theme.TextFaint
    }

    ## Host count label — keep visible, push affected-host preview to tooltip.
    $hostsPrev = ''
    if ($Vuln.Hosts -and @($Vuln.Hosts).Count -gt 0) {
        $firstHosts = @($Vuln.Hosts) | Select-Object -First 12
        $hostsPrev = "Affected hosts ($($Vuln.HostCount)):`r`n  " + ($firstHosts -join "`r`n  ")
        if (@($Vuln.Hosts).Count -gt 12) { $hostsPrev += "`r`n  ...+$(@($Vuln.Hosts).Count - 12) more" }
    }
    $hostText = ('{0:N0} host(s)' -f [int]$Vuln.HostCount)
    $lblHosts = New-WptLabel -Text $hostText `
        -X 608 -Y 44 -W 170 -H 18 -Font $fonts.MonoSm -Fg $theme.TextSecondary
    $lblHosts.TextAlign = 'MiddleRight'
    if ($hostsPrev) {
        try { (Get-NemSharedToolTip).SetToolTip($lblHosts, $hostsPrev) } catch {}
    }

    ## ----- Right column: Run + Verify buttons -----
    $hasProfile = $profileNames.Count -gt 0
    $btnRunTxt = if ($hasProfile) { "Run on $($Vuln.HostCount) host(s)" } else { 'No profile' }
    $btnRunBg  = if (-not $hasProfile) { $theme.PanelLight } elseif ($isExperimental) { $theme.Warning } else { $theme.Accent2 }
    $btnRunFg  = if ($hasProfile) { $theme.Background } else { $theme.TextFaint }
    $btnRun = New-WptButton -Text $btnRunTxt -X 792 -Y 14 -W 196 -H 32 `
        -Bg $btnRunBg -Fg $btnRunFg -Font $fonts.Body
    $btnRun.Enabled = $hasProfile
    $btnRun.Anchor  = 'Top,Right'
    $btnVerifyBg = $theme.PanelLight
    $btnVerifyFg = if ($hasProfile) { $theme.TextPrimary } else { $theme.TextFaint }
    $btnVerify = New-WptButton -Text 'Verify' -X 792 -Y 52 -W 196 -H 26 `
        -Bg $btnVerifyBg -Fg $btnVerifyFg -Font $fonts.Body
    $btnVerify.Enabled = $hasProfile
    $btnVerify.Anchor  = 'Top,Right'

    ## Expose primary Run button for Start-NemRunAll orchestrator.
    ## v1.4.0: also expose Vuln + ProfileCombo + VerifyButton so
    ## Start-NemBulkRunAll can build a parallel dispatch list without
    ## going through PerformClick.
    ## v1.4.1: $card.Tag MUST be assigned AFTER $btnVerify is created —
    ## StrictMode 3 throws on the use-before-define otherwise (this
    ## fired on every Refresh Cards click in 1.4.0).
    $card.Tag = [pscustomobject]@{
        RunButton    = $btnRun
        VerifyButton = $btnVerify
        Vuln         = $Vuln
        ProfileCombo = $cboProfile
    }

    ## Shared profile-picker: read card dropdown selection (if present) or
    ## fall back to the single profile. Both Run and Verify use this.
    $pickProfile = {
        $names = @($Vuln.ProfileNames)
        if ($names.Count -eq 0) { return $null }
        if ($cboProfile -and $cboProfile.SelectedItem) {
            return [string]$cboProfile.SelectedItem
        }
        return $names[0]
    }.GetNewClosure()

    ## v1.5.0: thread group context for the audit fan-out. For ungrouped
    ## per-vuln cards both params are empty/null and Start-NemVulnRun
    ## behaves exactly as before.
    $groupKeyForRun = if ($isGroup -and $Vuln.PSObject.Properties['GroupKey']) { [string]$Vuln.GroupKey } else { '' }
    $groupMembersForRun = if ($isGroup -and $Vuln.PSObject.Properties['GroupMembers']) { @($Vuln.GroupMembers) } else { @() }

    $btnRun.Add_Click({
        $chosen = & $pickProfile
        if (-not $chosen) { return }
        try {
            Start-NemVulnRun -VulnKey $Vuln.PluginKey `
                             -VulnDisplay $Vuln.DisplayName `
                             -ProfileName $chosen `
                             -HostList @($Vuln.Hosts) `
                             -GroupKey $groupKeyForRun `
                             -GroupMembers $groupMembersForRun
        } catch {
            Write-NemAudit -Action 'VulnRun' -Target $Vuln.DisplayName -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Run failed: $($_.Exception.Message)",
                'ACAS Nemesis - Run error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $btnVerify.Add_Click({
        $chosen = & $pickProfile
        if (-not $chosen) { return }
        try {
            Start-NemVulnRun -VulnKey $Vuln.PluginKey `
                             -VulnDisplay $Vuln.DisplayName `
                             -ProfileName $chosen `
                             -HostList @($Vuln.Hosts) `
                             -VerifyOnly `
                             -GroupKey $groupKeyForRun `
                             -GroupMembers $groupMembersForRun
        } catch {
            Write-NemAudit -Action 'VulnVerify' -Target $Vuln.DisplayName -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Verify failed: $($_.Exception.Message)",
                'ACAS Nemesis - Verify error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    ## v1.10.0: $lblCve removed (folded into the title tooltip).
    $controls = @($lblName, $sevBadge, $lblProfCaption, $lblHosts, $btnRun, $btnVerify)
    if ($lblExpBadge) { $controls += $lblExpBadge }
    if ($cboProfile)  { $controls += $cboProfile }
    $card.Controls.AddRange($controls)

    ## Register for the master run-lock (both buttons move together).
    $cards = $s.UI.Controls['updVulnCards']
    if (-not $cards) {
        $cards = [System.Collections.ArrayList]::new()
        $s.UI.Controls['updVulnCards'] = $cards
    }
    [void]$cards.Add(@{ Card = $card; Run = $btnRun; Verify = $btnVerify; Vuln = $Vuln })

    return $card
}

function global:New-NemRebootCard {
    <#
        Card for a 'Reboot' category vuln (e.g. Windows Update Reboot Required).
        Amber accent bar. Two buttons: Reboot Now and Verify Post-Reboot.
        Small editable TextBox for the warning message.
        Registers itself in updVulnCards so the master run-lock covers it.
    #>
    param($Vuln)

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $fonts = $s.UI.Fonts

    ## v1.10.0: compact reboot card (3 rows of content because
    ## the warning textbox is unique to this kind of card).
    ##   Row 1 (y=12): Title  [SEV]  [REBOOT REQUIRED]
    ##   Row 2 (y=40): Warning text input + caption + host count
    ##   Right column: Reboot Now (y=12, h=34) / Verify Post-Reboot (y=50, h=28)
    $card = New-Object System.Windows.Forms.Panel
    $card.Width       = 1000
    $card.Height      = 110
    $card.BackColor   = $theme.Surface
    $card.BorderStyle = 'FixedSingle'
    $card.Margin      = New-Object System.Windows.Forms.Padding(0, 0, 0, 14)

    ## Amber accent strip across the top.
    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock      = 'Top'
    $accent.Height    = 4
    $accent.BackColor = $theme.Warning
    $card.Controls.Add($accent)

    ## Severity tag.
    $sevText = if ($Vuln.Severity) { $Vuln.Severity.ToUpperInvariant() } else { 'UNKNOWN' }
    $sevLower = if ($Vuln.Severity) { $Vuln.Severity.ToLowerInvariant() } else { '' }
    $sevColor = switch ($sevLower) {
        'critical' { $theme.Danger }
        'high'     { $theme.Warning }
        'medium'   { $theme.Accent2 }
        'low'      { $theme.TextMuted }
        'info'     { $theme.Info }
        default    { $theme.Border }
    }
    $lblSev = New-WptLabel -Text "[$sevText]" `
        -X 18 -Y 14 -W 96 -H 18 -Font $fonts.MonoSm -Fg $sevColor

    $lblBadge = New-WptLabel -Text '[REBOOT REQUIRED]' `
        -X 116 -Y 14 -W 150 -H 18 -Font $fonts.MonoSm -Fg $theme.Warning

    $lblName = New-WptLabel -Text $Vuln.DisplayName `
        -X 270 -Y 14 -W 510 -H 18 -Font $fonts.BodyStrong -Fg $theme.TextPrimary
    $lblName.AutoEllipsis = $true

    ## Row 2: warning text input + host count
    $lblWarnCaption = New-WptLabel -Text 'Warning:' `
        -X 18 -Y 44 -W 70 -H 22 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $txtWarn = New-Object System.Windows.Forms.TextBox
    $txtWarn.Location    = New-Object System.Drawing.Point(90, 42)
    $txtWarn.Size        = New-Object System.Drawing.Size(530, 24)
    $txtWarn.Font        = $fonts.MonoTiny
    $txtWarn.BackColor   = $theme.Input
    $txtWarn.ForeColor   = $theme.TextPrimary
    $txtWarn.BorderStyle = 'FixedSingle'
    $txtWarn.Text        = 'This workstation will reboot in 5 minutes for required security updates. Save your work now.'

    ## Affected hosts preview -> tooltip on the host-count label.
    $hostsPrev = ''
    if ($Vuln.Hosts -and @($Vuln.Hosts).Count -gt 0) {
        $firstHosts = @($Vuln.Hosts) | Select-Object -First 12
        $hostsPrev = "Affected hosts ($($Vuln.HostCount)):`r`n  " + ($firstHosts -join "`r`n  ")
        if (@($Vuln.Hosts).Count -gt 12) { $hostsPrev += "`r`n  ...+$(@($Vuln.Hosts).Count - 12) more" }
    }
    $hostText = ('{0:N0} host(s)' -f [int]$Vuln.HostCount)
    $lblHosts = New-WptLabel -Text $hostText `
        -X 630 -Y 44 -W 148 -H 22 -Font $fonts.MonoSm -Fg $theme.TextSecondary
    $lblHosts.TextAlign = 'MiddleRight'
    ## v1.10.1: shared singleton tooltip — see Get-NemSharedToolTip.
    if ($hostsPrev) {
        try { (Get-NemSharedToolTip).SetToolTip($lblHosts, $hostsPrev) } catch {}
    }

    ## Two action buttons, right-aligned.
    $btnReboot = New-WptButton -Text "Reboot Now ($($Vuln.HostCount) host(s))" `
        -X 792 -Y 14 -W 196 -H 32 `
        -Bg $theme.Warning -Fg $theme.Background -Font $fonts.Body
    $btnReboot.Anchor = 'Top,Right'
    ## Expose primary Reboot button for Start-NemRunAll orchestrator.
    ## Verify Post-Reboot is intentionally NOT exposed — Run All skips it.
    $card.Tag = [pscustomobject]@{ RebootButton = $btnReboot }

    $btnVerify = New-WptButton -Text 'Verify Post-Reboot' `
        -X 792 -Y 52 -W 196 -H 28 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body
    $btnVerify.Anchor = 'Top,Right'

    $btnReboot.Add_Click({
        $warnMsg = $txtWarn.Text
        if ([string]::IsNullOrWhiteSpace($warnMsg)) {
            $warnMsg = 'This workstation will reboot in 5 minutes for required security updates. Save your work now.'
        }
        try {
            Start-NemRebootRun -VulnDisplay $Vuln.DisplayName `
                               -HostList @($Vuln.Hosts) `
                               -WarningText $warnMsg
        } catch {
            Write-NemAudit -Action 'Reboot.Start' -Target $Vuln.DisplayName -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Reboot dispatch failed: $($_.Exception.Message)",
                'ACAS Nemesis - Reboot error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $btnVerify.Add_Click({
        try {
            Start-NemRebootVerify -VulnDisplay $Vuln.DisplayName `
                                  -HostList @($Vuln.Hosts)
        } catch {
            Write-NemAudit -Action 'Reboot.Verify.Start' -Target $Vuln.DisplayName -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Reboot verify failed: $($_.Exception.Message)",
                'ACAS Nemesis - Verify error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $card.Controls.AddRange(@($lblName, $lblBadge, $lblSev, $lblHosts, $lblWarnCaption, $txtWarn, $btnReboot, $btnVerify))

    ## Register in the master run-lock list.
    $cards = $s.UI.Controls['updVulnCards']
    if (-not $cards) {
        $cards = [System.Collections.ArrayList]::new()
        $s.UI.Controls['updVulnCards'] = $cards
    }
    [void]$cards.Add(@{ Card = $card; Run = $btnReboot; Verify = $btnVerify; Vuln = $Vuln })

    return $card
}

function global:New-NemDashTile {
    <#
        Dashboard tile in the Reports / Weekly Export style:
          +-------------------------------+
          | EYEBROW (uppercase mono 9pt)  |
          | 1,247   (24pt mono bold)      |
          | sub-line (caption 9pt)        |
          +-------------------------------+
        4px coloured top accent strip. Background = Surface, border = Border.

        Returns a hashtable @{ Panel; HeroLabel; SubLabel } so the caller can
        update Hero / Sub text later without recreating the tile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Eyebrow,
        [string]$Hero = '-',
        [string]$Sub  = '',
        [int]$X = 0, [int]$Y = 0, [int]$W = 180, [int]$H = 96,
        [System.Drawing.Color]$AccentColor
    )
    $t = $script:Nemesis.UI.Theme
    $f = $script:Nemesis.UI.Fonts
    if (-not $AccentColor) { $AccentColor = $t.Accent1 }

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location    = New-Object System.Drawing.Point($X, $Y)
    $panel.Size        = New-Object System.Drawing.Size($W, $H)
    $panel.BackColor   = $t.Surface
    $panel.BorderStyle = 'FixedSingle'

    $accent = New-Object System.Windows.Forms.Panel
    $accent.Dock = 'Top'; $accent.Height = 3; $accent.BackColor = $AccentColor
    $panel.Controls.Add($accent)

    $lblEyebrow = New-Object System.Windows.Forms.Label
    $lblEyebrow.Text      = $Eyebrow.ToUpperInvariant()
    $lblEyebrow.Location  = New-Object System.Drawing.Point(12, 10)
    $lblEyebrow.Size      = New-Object System.Drawing.Size(($W - 24), 16)
    $lblEyebrow.Font      = $f.EyebrowDim
    $lblEyebrow.ForeColor = $t.TextMuted
    $lblEyebrow.BackColor = [System.Drawing.Color]::Transparent
    $panel.Controls.Add($lblEyebrow)

    $lblHero = New-Object System.Windows.Forms.Label
    $lblHero.Text      = $Hero
    $lblHero.Location  = New-Object System.Drawing.Point(12, 26)
    $lblHero.Size      = New-Object System.Drawing.Size(($W - 24), 38)
    $lblHero.Font      = New-Object System.Drawing.Font('Cascadia Mono', 22, [System.Drawing.FontStyle]::Bold)
    $lblHero.ForeColor = $AccentColor
    $lblHero.BackColor = [System.Drawing.Color]::Transparent
    $lblHero.TextAlign = 'MiddleLeft'
    $panel.Controls.Add($lblHero)

    $lblSub = New-Object System.Windows.Forms.Label
    $lblSub.Text      = $Sub
    $lblSub.Location  = New-Object System.Drawing.Point(12, 66)
    $lblSub.Size      = New-Object System.Drawing.Size(($W - 24), 22)
    $lblSub.Font      = $f.Caption
    $lblSub.ForeColor = $t.TextSecondary
    $lblSub.BackColor = [System.Drawing.Color]::Transparent
    $panel.Controls.Add($lblSub)

    return @{ Panel = $panel; Hero = $lblHero; Sub = $lblSub; Eyebrow = $lblEyebrow; Accent = $accent }
}

function global:Update-NemUpdaterSummary {
    <#
        Walk Get-NemVulnCardEntries (the same source the Updater cards use),
        compute totals + breakdowns, push them into the summary-strip tiles.
        No-op if the strip isn't built yet (i.e. tab hasn't been constructed).
        v1.10.1: optional -Entries param lets Update-NemVulnCards forward
        its already-computed list so the classify/group/sort pass only runs
        once per refresh. Standalone callers (none today) still get the
        full lookup when -Entries is omitted.
    #>
    param($Entries)
    $s = Get-NemState
    $tiles = $s.UI.Controls['updSummaryTiles']
    if (-not $tiles) { return }

    $entries = if ($PSBoundParameters.ContainsKey('Entries') -and $null -ne $Entries) {
        @($Entries)
    } else {
        @(Get-NemVulnCardEntries)
    }
    $patchable    = @($entries | Where-Object { $_.PSObject.Properties['Category'] -and ($_.Category -in @('Patchable','Experimental','Reboot')) })
    $notPatchable = @($entries | Where-Object { $_.PSObject.Properties['Category'] -and ($_.Category -in @('Unpatchable','NotUpdatable')) })

    $sevCount = { param($entries, $sev)
        @($entries | Where-Object {
            $s2 = ''; if ($_.Severity) { $s2 = $_.Severity.ToLowerInvariant() }
            $s2 -eq $sev
        }).Count
    }
    $crit = & $sevCount $entries 'critical'
    $high = & $sevCount $entries 'high'
    $med  = & $sevCount $entries 'medium'
    $low  = & $sevCount $entries 'low'

    $allHosts = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $entries) {
        if ($e.PSObject.Properties['Hosts'] -and $e.Hosts) {
            foreach ($h in $e.Hosts) { [void]$allHosts.Add([string]$h) }
        }
    }
    $hostCount = $allHosts.Count

    $fmt = { param($n) ('{0:N0}' -f [int]$n) }

    $tiles['Total'].Hero.Text     = & $fmt $entries.Count
    $tiles['Total'].Sub.Text      = "across $($hostCount) host(s)"

    $tiles['Patchable'].Hero.Text = & $fmt $patchable.Count
    $tiles['Patchable'].Sub.Text  = if ($entries.Count -gt 0) {
        "{0:P0} of total" -f ($patchable.Count / [Math]::Max(1, $entries.Count))
    } else { '-' }

    $tiles['NotPatch'].Hero.Text  = & $fmt $notPatchable.Count
    $tiles['NotPatch'].Sub.Text   = if ($notPatchable.Count -gt 0) { 'see Not Updatable tab' } else { '-' }

    $tiles['Critical'].Hero.Text  = & $fmt $crit
    $tiles['Critical'].Sub.Text   = if ($crit -gt 0) { 'patch first' } else { 'none' }

    $tiles['High'].Hero.Text      = & $fmt $high
    $tiles['High'].Sub.Text       = if ($high -gt 0) { 'high severity' } else { 'none' }

    $tiles['MedLow'].Hero.Text    = & $fmt ($med + $low)
    $tiles['MedLow'].Sub.Text     = "$med med  $low low"
}

function global:Show-NemUpdaterLogPopOut {
    <#
        Pop the Updater Log RichTextBox out into a separate floating window.
        Reparents the single RTB instance — no duplication — so existing
        $rtb.AppendText() call sites keep working unchanged while the
        window is popped. On close, the RTB returns to the hidden $rtbWrap
        Panel so it survives between pops.

        Idempotent: a second call while already popped just brings the
        existing window forward.

        Extracted from the Pop Out Log button click handler in v1.10.0
        pass 4 so the Updater tab can auto-fire it on first VisibleChanged
        (freeing the bottom 260px for cards).
    #>
    $s = Get-NemState
    $theme2 = $s.UI.Theme
    $rtb2   = $s.UI.Controls['updRtbLog']
    $wrap2  = $s.UI.Controls['updRtbWrap']
    if (-not $rtb2 -or -not $wrap2) { return }

    ## Already popped? Just bring forward.
    if ($s.UI.Controls.ContainsKey('updPopOutForm') -and $s.UI.Controls['updPopOutForm']) {
        try {
            $s.UI.Controls['updPopOutForm'].WindowState = 'Normal'
            $s.UI.Controls['updPopOutForm'].Show()
            $s.UI.Controls['updPopOutForm'].Activate()
        } catch {}
        return
    }

    $popForm = New-Object System.Windows.Forms.Form
    $popForm.Text          = 'ACAS Nemesis - Updater Log'
    $popForm.Size          = New-Object System.Drawing.Size(1100, 600)
    $popForm.StartPosition = 'Manual'
    ## Drop it near the bottom-right of the working area so it doesn't
    ## cover the main window. Operator can drag it anywhere from there.
    try {
        $screenArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $popForm.Location = New-Object System.Drawing.Point(
            ($screenArea.Right - 1120),
            ($screenArea.Bottom - 640)
        )
    } catch {
        $popForm.StartPosition = 'CenterScreen'
    }
    $popForm.BackColor   = $theme2.Background
    $popForm.ForeColor   = $theme2.TextPrimary
    $popForm.ShowIcon    = $false
    $popForm.MinimumSize = New-Object System.Drawing.Size(640, 320)

    $popPanel = New-Object System.Windows.Forms.Panel
    $popPanel.Dock      = 'Fill'
    $popPanel.BackColor = [System.Drawing.Color]::Transparent
    $popPanel.Padding   = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
    $popForm.Controls.Add($popPanel)

    ## Reparent the RTB control into the pop-out form's panel.
    $wrap2.Controls.Remove($rtb2)
    $rtb2.Dock = 'Fill'
    $popPanel.Controls.Add($rtb2)

    $popForm.Add_FormClosing({
        ## Reparent the RTB back into the hidden wrap so it survives between
        ## pops — every AppendText call site keeps working even when no
        ## window is visible.
        param($sender, $e)
        try {
            $s2 = Get-NemState
            $rtb3 = $s2.UI.Controls['updRtbLog']
            $wrap3 = $s2.UI.Controls['updRtbWrap']
            if ($rtb3 -and $wrap3 -and $rtb3.Parent) {
                $rtb3.Parent.Controls.Remove($rtb3)
                $rtb3.Dock = 'Fill'
                $wrap3.Controls.Add($rtb3)
            }
            $s2.UI.Controls.Remove('updPopOutForm') | Out-Null
        } catch {}
    }.GetNewClosure())

    $s.UI.Controls['updPopOutForm'] = $popForm
    try { Set-WptDarkTitleBar -Form $popForm } catch {}
    $popForm.Show()
}

function Add-NemUpdaterTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== HEADER ==========
    ## v1.10.0: header reorganized into three rows:
    ##   y= 16 : Title + Sub
    ##   y= 56 : SUMMARY STRIP (6 hero tiles, total + patchable + not / sev)
    ##   y=164 : Action button row + status
    ##   y=210 : Log4j source override row
    $lblTitle = New-WptLabel -Text 'Updater' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'One card per vulnerability. Each Run pushes ONLY to the hosts that vuln affects — no all-hosts dispatch.' `
        -X 20 -Y 50 -W 1100 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ----- SUMMARY STRIP (Reports / Weekly Export style hero tiles) -----
    ## 6 tiles wide. Total / Patchable / NotPatch on the left (overview),
    ## Critical / High / Med+Low on the right (severity breakdown).
    $tileSpecs = @(
        @{ Key='Total';     Eyebrow='Total Vulns';   Accent=$theme.Accent1 }
        @{ Key='Patchable'; Eyebrow='Patchable';     Accent=$theme.Success }
        @{ Key='NotPatch';  Eyebrow='Not Patchable'; Accent=$theme.TextMuted }
        @{ Key='Critical';  Eyebrow='Critical';      Accent=$theme.Danger }
        @{ Key='High';      Eyebrow='High';          Accent=$theme.Warning }
        @{ Key='MedLow';    Eyebrow='Med + Low';     Accent=$theme.Info }
    )
    $tileW = 184; $tileH = 96; $tileGap = 12; $tileX = 20; $tileY = 76
    $tileMap = @{}
    $tileControls = @()
    for ($ti = 0; $ti -lt $tileSpecs.Count; $ti++) {
        $spec = $tileSpecs[$ti]
        $tx = $tileX + ($ti * ($tileW + $tileGap))
        $tile = New-NemDashTile -Eyebrow $spec.Eyebrow -Hero '-' -Sub '-' `
            -X $tx -Y $tileY -W $tileW -H $tileH -AccentColor $spec.Accent
        $tileMap[$spec.Key] = $tile
        $tileControls += $tile.Panel
    }
    $state.UI.Controls['updSummaryTiles'] = $tileMap

    ## ----- ACTION BUTTON ROW (normalized palette) -----
    ## Ghost (PanelLight bg + Accent1 fg) for non-destructive setup actions:
    ##   Refresh Cards, Pre-Flight Services, Pop Out Log
    ## Gold (Accent2) for the loud run actions:
    ##   Run All (Sequential), Bulk Run (Parallel)
    ## Danger only for Cancel.
    $btnY = 184
    $btnH = 34
    $ghostBg = $theme.PanelLight
    $ghostFg = $theme.Accent1Hover
    $btnRefresh = New-WptButton -Text 'Refresh Cards' -X 20 -Y $btnY -W 140 -H $btnH `
        -Bg $ghostBg -Fg $ghostFg -Font $fonts.Body
    $btnPreflight = New-WptButton -Text 'Pre-Flight Services' -X 168 -Y $btnY -W 168 -H $btnH `
        -Bg $ghostBg -Fg $ghostFg -Font $fonts.Body
    $state.UI.Controls['updBtnPreflight'] = $btnPreflight
    $btnRunAll  = New-WptButton -Text 'Run All (Sequential)' -X 344 -Y $btnY -W 180 -H $btnH `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body
    $state.UI.Controls['updBtnRunAll'] = $btnRunAll
    ## v1.4.0: Bulk Run = parallel dispatch of every patchable card's
    ## (host, profile) tuples through the runspace pool. Distinct from
    ## Run All (sequential card-by-card). See Start-NemBulkRunAll.
    $btnBulkRun = New-WptButton -Text 'Bulk Run (Parallel)' -X 532 -Y $btnY -W 180 -H $btnH `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body
    $state.UI.Controls['updBtnBulkRun'] = $btnBulkRun
    $btnCancel  = New-WptButton -Text 'Cancel Run' -X 720 -Y $btnY -W 124 -H $btnH `
        -Bg $theme.Danger -Fg $theme.TextOnAccent -Font $fonts.Body
    $btnCancel.Enabled = $false
    $state.UI.Controls['updBtnCancel'] = $btnCancel
    ## v1.8.8: Pop Out Log button. Reparents the embedded RichTextBox
    ## into a separate floating Form so the operator can keep the run
    ## visible while scrolling the cards / switching tabs in the main
    ## window. Single RTB control, just moved between parents — every
    ## existing AppendText call site keeps working unchanged.
    $btnPopOut  = New-WptButton -Text 'Pop Out Log' -X 852 -Y $btnY -W 124 -H $btnH `
        -Bg $ghostBg -Fg $ghostFg -Font $fonts.Body
    $state.UI.Controls['updBtnPopOut'] = $btnPopOut

    $lblStatus = New-WptLabel -Text 'Idle' -X 988 -Y ($btnY + 8) -W 400 -H 20 `
        -Font $fonts.Body -Fg $theme.TextMuted
    $state.UI.Controls['updLblStatus'] = $lblStatus

    ## v1.8.5: Log4j source-share override row.
    $lblLog4jSrc = New-WptLabel -Text 'Log4j source:' -X 20 -Y 230 -W 110 -H 20 `
        -Font $fonts.Body -Fg $theme.TextSecondary
    $txtLog4jSrc = New-Object System.Windows.Forms.TextBox
    $txtLog4jSrc.Location  = New-Object System.Drawing.Point(132, 226)
    $txtLog4jSrc.Size      = New-Object System.Drawing.Size(680, 24)
    $txtLog4jSrc.Font      = $fonts.Console
    $txtLog4jSrc.BackColor = $theme.Input
    $txtLog4jSrc.ForeColor = $theme.TextPrimary
    $txtLog4jSrc.Text      = [string]$global:NemLog4jDefaultSource
    $state.UI.Controls['updTxtLog4jSrc'] = $txtLog4jSrc
    $lblLog4jHint = New-WptLabel `
        -Text 'Used only by the Apache Log4j profile. Drop log4j-api-2.25.4.jar + log4j-core-2.25.4.jar at this path.' `
        -X 820 -Y 230 -W 500 -H 20 -Font $fonts.Body -Fg $theme.TextMuted

    ## ========== CARDS HOST (scrollable flow) ==========
    $cardsHost = New-Object System.Windows.Forms.FlowLayoutPanel
    $cardsHost.FlowDirection = 'TopDown'
    $cardsHost.WrapContents  = $false
    $cardsHost.AutoScroll    = $true
    $cardsHost.Dock          = 'Fill'
    ## v1.10.0: host BG = Background (near-black) so the Surface
    ## cards inside read as raised blocks rather than blending in.
    $cardsHost.BackColor     = $theme.Background
    $cardsHost.Padding       = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
    $state.UI.Controls['updCardsHost'] = $cardsHost

    ## Keep cards sized to the host width on resize.
    $cardsHost.Add_Resize({
        $h = Get-NemState
        $ch = $h.UI.Controls['updCardsHost']
        if (-not $ch) { return }
        $w = [Math]::Max(400, $ch.ClientSize.Width - 20)
        foreach ($ctrl in $ch.Controls) {
            if ($ctrl -is [System.Windows.Forms.Panel]) { $ctrl.Width = $w }
            elseif ($ctrl -is [System.Windows.Forms.Label]) { $ctrl.Width = $w }
        }
    }.GetNewClosure())

    ## ========== LOG PANE ==========
    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Dock        = 'Fill'
    $rtbLog.ReadOnly    = $true
    $rtbLog.WordWrap    = $false
    $rtbLog.ScrollBars  = 'Vertical'
    $rtbLog.Font        = $fonts.Console
    $rtbLog.BackColor   = $theme.StatusBar
    $rtbLog.ForeColor   = $theme.TextPrimary
    $rtbLog.BorderStyle = 'FixedSingle'
    $state.UI.Controls['updRtbLog'] = $rtbLog

    $lblLog = New-WptLabel -Text 'UPDATER LOG' -X 0 -Y 0 -W 200 -H 20 -Font $fonts.Body -Fg $theme.Accent2

    ## ========== HANDLERS ==========
    $btnRefresh.Add_Click({ Update-NemVulnCards }.GetNewClosure())

    $btnPreflight.Add_Click({
        try { Start-NemServicesPreflight }
        catch {
            Write-NemAudit -Action 'Preflight.Services' -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Pre-flight failed: $($_.Exception.Message)",
                'ACAS Nemesis','OK','Error') | Out-Null
        }
    }.GetNewClosure())

    $btnRunAll.Add_Click({
        try { Start-NemRunAll }
        catch {
            Write-NemAudit -Action 'RunAll' -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Run All failed: $($_.Exception.Message)",
                'ACAS Nemesis','OK','Error') | Out-Null
        }
    }.GetNewClosure())

    $btnBulkRun.Add_Click({
        try { Start-NemBulkRunAll }
        catch {
            Write-NemAudit -Action 'BulkRun' -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "Bulk Run failed: $($_.Exception.Message)",
                'ACAS Nemesis','OK','Error') | Out-Null
        }
    }.GetNewClosure())

    ## v1.10.0: Pop Out logic extracted into Show-NemUpdaterLogPopOut
    ## so the button click handler AND the first-VisibleChanged auto-popper
    ## share one code path. See above the Add-NemUpdaterTab function.
    $btnPopOut.Add_Click({
        try { Show-NemUpdaterLogPopOut } catch {
            Write-NemAudit -Action 'LogPopOut' -Result 'Failed' -Detail $_.Exception.Message
        }
    }.GetNewClosure())

    $btnCancel.Add_Click({
        $s = Get-NemState
        $rtb2 = $s.UI.Controls['updRtbLog']
        $lbl2 = $s.UI.Controls['updLblStatus']
        $theme2 = $s.UI.Theme

        ## Pre-flight services timer — stop and dispose if active.
        if ($s.UI.Controls.ContainsKey('preflightTimer')) {
            $tim = $s.UI.Controls['preflightTimer']
            try { $tim.Stop()    } catch {}
            try { $tim.Dispose() } catch {}
            $s.UI.Controls.Remove('preflightTimer') | Out-Null
        }

        ## Run All orchestrator — flag it to stop on next tick.
        ## $script:Nemesis is `[ordered]@{}` (OrderedDictionary), which
        ## exposes `.Contains()` rather than `.ContainsKey()` — calling
        ## ContainsKey on the top-level state throws. The nested
        ## `$s.UI.Controls` is a regular Hashtable so its ContainsKey
        ## calls below are fine. Only the top-level $s lookup needs this.
        if ($s.Contains('RunAllQueue')) {
            $s['RunAllCancelled'] = $true
        }

        $cancelCount = 0
        foreach ($key in @($s.Jobs.Keys)) {
            if ($key -eq '_counters') { continue }
            $job = $s.Jobs[$key]
            try { $job.PS.Stop()    } catch {}
            try { $job.PS.Dispose() } catch {}
            $cancelCount++
        }
        $s['Jobs'] = @{}

        ## All drain timers share this Cancel button. Reboot, Reboot-Verify and
        ## KB runs register their own timer keys; if we don't stop them here they
        ## keep ticking after $s.Jobs is wiped above and null-deref the (now gone)
        ## _counters on their next tick. Tear every drain timer down.
        foreach ($timerKey in @('updTimer','rebTimer','rebVerifyTimer','kbTimer')) {
            if ($s.UI.Controls.ContainsKey($timerKey)) {
                $tim = $s.UI.Controls[$timerKey]
                try { $tim.Stop()    } catch {}
                try { $tim.Dispose() } catch {}
                $s.UI.Controls.Remove($timerKey) | Out-Null
            }
        }

        $rtb2.SelectionColor = $theme2.Warning
        $rtb2.AppendText("========================================`r`n")
        $rtb2.AppendText("CANCELLED by operator ($cancelCount job(s) stopped)`r`n")
        $rtb2.AppendText("========================================`r`n")
        $rtb2.SelectionColor = $rtb2.ForeColor
        Write-NemAudit -Action 'VulnRun.Cancel' -Result 'OK' -Detail "jobs_stopped=$cancelCount"

        Set-NemVulnCardRunEnabled -Enabled $true
        $s.UI.Controls['updBtnCancel'].Enabled = $false
        if ($s.UI.Controls.ContainsKey('updBtnRunAll'))  { $s.UI.Controls['updBtnRunAll'].Enabled  = $true }
        if ($s.UI.Controls.ContainsKey('updBtnBulkRun')) { $s.UI.Controls['updBtnBulkRun'].Enabled = $true }
        $lbl2.Text      = 'Cancelled'
        $lbl2.ForeColor = $theme2.Warning
    }.GetNewClosure())

    ## v1.10.0: on first VisibleChanged, auto-pop the Updater Log
    ## into its own floating window — operator gets a dedicated log surface
    ## AND the full vertical space on the Updater tab goes to cards.
    ## A flag in $state.UI.Controls keeps it a one-shot per launch (otherwise
    ## every tab switch would re-pop).
    ## v1.10.1: rebuild + auto-popout deferred to the next message-pump
    ## tick via a single-shot Timer. Doing the work inline in VisibleChanged
    ## blocks the pump before the tab paints — on a 9k-finding import the
    ## tab showed up as a blank white surface with a spinning busy cursor
    ## for as long as the rebuild took. Yielding first lets the tab chrome
    ## render immediately while the cards build in a second tick.
    $TabPanel.Add_VisibleChanged({
        if (-not $TabPanel.Visible) { return }
        $deferTimer = New-Object System.Windows.Forms.Timer
        $deferTimer.Interval = 1
        $deferTimer.Add_Tick({
            param($sender, $e)
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            try { Update-NemVulnCards } catch {
                Write-NemAudit -Action 'VulnCards.DeferRebuild' -Result 'Failed' -Detail $_.Exception.Message
            }
            $s2 = Get-NemState
            if (-not $s2.UI.Controls.ContainsKey('updLogAutoPopped') -or -not $s2.UI.Controls['updLogAutoPopped']) {
                try {
                    Show-NemUpdaterLogPopOut
                    $s2.UI.Controls['updLogAutoPopped'] = $true
                } catch {
                    Write-NemAudit -Action 'LogPopOut.Auto' -Result 'Failed' -Detail $_.Exception.Message
                }
            }
        })
        $deferTimer.Start()
    }.GetNewClosure())

    ## ========== ASSEMBLE (Dock: header / cards (fill)) ==========
    ## v1.10.0: log section removed from this tab's layout.
    ## The RTB lives in $rtbWrap (orphan Panel — never added to the
    ## visible tree). Show-NemUpdaterLogPopOut reparents it into a
    ## floating window on demand; close reparents it back to $rtbWrap.
    ## Cards now have the full vertical space below the header.
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 260
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@($lblTitle, $lblSub, $btnRefresh, $btnPreflight, $btnRunAll, $btnBulkRun, $btnCancel, $btnPopOut, $lblStatus, $lblLog4jSrc, $txtLog4jSrc, $lblLog4jHint))
    foreach ($tilePanel in $tileControls) { $header.Controls.Add($tilePanel) }

    ## Hidden home for the RTB when not popped out. Never parented to the
    ## visible tree — Show-NemUpdaterLogPopOut reparents the RTB out of
    ## here on first call; FormClosing on the pop-out reparents it back.
    $rtbWrap = New-Object System.Windows.Forms.Panel
    $rtbWrap.Visible   = $false
    $rtbWrap.Controls.Add($rtbLog)
    $state.UI.Controls['updRtbWrap'] = $rtbWrap
    ## $lblLog is no longer surfaced in the embedded layout — it would
    ## only be visible if we re-added the log section. Kept as an
    ## allocated control (no-op) so other code that referenced it (if any)
    ## won't NPE.

    $cardsWrap = New-Object System.Windows.Forms.Panel
    $cardsWrap.Dock      = 'Fill'
    $cardsWrap.BackColor = [System.Drawing.Color]::Transparent
    $cardsWrap.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 8)
    $cardsWrap.Controls.Add($cardsHost)

    $TabPanel.Controls.Add($cardsWrap)   # Dock=Fill — must be added first
    $TabPanel.Controls.Add($header)      # Dock=Top
}

function Add-NemNotUpdatableTab {
    <#
        Info-only sibling of the Updater tab. Shows vulnerabilities that
        have no matched profile — same card layout, minus the Run button,
        dropdown, and log pane.  Lets the operator see what ACAS flagged
        that this tool cannot remediate.
    #>
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    $lblTitle = New-WptLabel -Text 'Not Updatable' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Vulnerabilities with no matched update profile. Add rules to Get-NemProfileMatchTable (and a profile to $script:WptAppUpdateProfiles) to move one here onto the Updater tab.' `
        -X 20 -Y 50 -W 1100 -H 36 -Font $fonts.Body -Fg $theme.TextSecondary

    ## v1.10.0: hero-tile summary strip matching the Updater tab. 4 tiles:
    ##   Total Not Patchable | Critical | High | Unique Hosts Affected
    $nupTileSpecs = @(
        @{ Key='Total';    Eyebrow='Total Not Patchable'; Accent=$theme.TextMuted }
        @{ Key='Critical'; Eyebrow='Critical';            Accent=$theme.Danger }
        @{ Key='High';     Eyebrow='High';                Accent=$theme.Warning }
        @{ Key='Hosts';    Eyebrow='Hosts Affected';      Accent=$theme.Accent1 }
    )
    $nupTileW = 220; $nupTileH = 96; $nupTileGap = 16; $nupTileX = 20; $nupTileY = 92
    $nupTileMap = @{}
    $nupTileControls = @()
    for ($ti = 0; $ti -lt $nupTileSpecs.Count; $ti++) {
        $spec = $nupTileSpecs[$ti]
        $tx = $nupTileX + ($ti * ($nupTileW + $nupTileGap))
        $tile = New-NemDashTile -Eyebrow $spec.Eyebrow -Hero '-' -Sub '-' `
            -X $tx -Y $nupTileY -W $nupTileW -H $nupTileH -AccentColor $spec.Accent
        $nupTileMap[$spec.Key] = $tile
        $nupTileControls += $tile.Panel
    }
    $state.UI.Controls['nupSummaryTiles'] = $nupTileMap

    $btnRefresh = New-WptButton -Text 'Refresh Cards' -X 20 -Y 204 -W 160 -H 34 `
        -Bg $theme.PanelLight -Fg $theme.Accent1Hover -Font $fonts.Body

    ## ========== CARDS HOST ==========
    $cardsHost = New-Object System.Windows.Forms.FlowLayoutPanel
    $cardsHost.FlowDirection = 'TopDown'
    $cardsHost.WrapContents  = $false
    $cardsHost.AutoScroll    = $true
    $cardsHost.Dock          = 'Fill'
    ## v1.10.0: host BG = Background (near-black) so the Surface
    ## cards inside read as raised blocks rather than blending in.
    $cardsHost.BackColor     = $theme.Background
    $cardsHost.Padding       = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
    $state.UI.Controls['nupCardsHost'] = $cardsHost

    $cardsHost.Add_Resize({
        $h = Get-NemState
        $ch = $h.UI.Controls['nupCardsHost']
        if (-not $ch) { return }
        $w = [Math]::Max(400, $ch.ClientSize.Width - 20)
        foreach ($ctrl in $ch.Controls) {
            if ($ctrl -is [System.Windows.Forms.Panel]) { $ctrl.Width = $w }
            elseif ($ctrl -is [System.Windows.Forms.Label]) { $ctrl.Width = $w }
        }
    }.GetNewClosure())

    $btnRefresh.Add_Click({ Update-NemNonUpdatableCards }.GetNewClosure())

    ## v1.10.1: defer rebuild to the next message-pump tick so the tab
    ## paints first. See identical pattern on the Updater tab above.
    $TabPanel.Add_VisibleChanged({
        if (-not $TabPanel.Visible) { return }
        $deferTimer = New-Object System.Windows.Forms.Timer
        $deferTimer.Interval = 1
        $deferTimer.Add_Tick({
            param($sender, $e)
            try { $sender.Stop()    } catch {}
            try { $sender.Dispose() } catch {}
            try { Update-NemNonUpdatableCards } catch {
                Write-NemAudit -Action 'NonUpdatableCards.DeferRebuild' -Result 'Failed' -Detail $_.Exception.Message
            }
        })
        $deferTimer.Start()
    }.GetNewClosure())

    ## ========== ASSEMBLE ==========
    ## v1.10.0: header height 140 -> 252 to fit the summary tile strip.
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 252
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@($lblTitle, $lblSub, $btnRefresh))
    foreach ($tilePanel in $nupTileControls) { $header.Controls.Add($tilePanel) }

    $cardsWrap = New-Object System.Windows.Forms.Panel
    $cardsWrap.Dock      = 'Fill'
    $cardsWrap.BackColor = [System.Drawing.Color]::Transparent
    $cardsWrap.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)
    $cardsWrap.Controls.Add($cardsHost)

    $TabPanel.Controls.Add($cardsWrap)
    $TabPanel.Controls.Add($header)
}

##################
## KB INSTALLER ##
##################
function global:Get-NemKbParsedFindings {
    <#
    .SYNOPSIS
        Returns a deduped list of @{ Host; Kb; Severity; Plugin; Cve; Solution }
        objects built by scanning $script:Nemesis.AcasFindings for rows whose
        Solution text contains a KB number.

    .DESCRIPTION
        Recognises:
          KB<num>                 (e.g. KB5034441)
          Security Update <num>   (e.g. Security Update 5034441)
          Apply Security Update <num>
        Normalises all matches to uppercase KB<num>.
        Dedup key is "$Host|$Kb" (case-insensitive).
        Host priority: DnsName > NetBIOS (DOMAIN\ stripped) > IpAddress.
    #>
    [CmdletBinding()]
    param()

    ## Use only the operator-selected findings from the Targets tab grid.
    ## Falls back to all AcasFindings if the grid is not yet built.
    $findings = Get-NemSelectedFindings
    if (-not $findings -or $findings.Count -eq 0) { return @() }

    ## Patterns that yield a KB number:
    ##   KB<6-8 digits>              (explicit KB prefix)
    ##   Security Update <6-8 digits>
    ##   Apply Security Update <6-8 digits>
    $kbPattern      = [regex]'(?i)\bKB\s*(\d{6,8})\b'
    $secUpdPattern  = [regex]'(?i)(?:Apply\s+)?Security\s+Update\s+(\d{6,8})\b'

    $seen   = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $result = [System.Collections.ArrayList]::new()

    foreach ($row in $findings) {
        $sol = if ($row.Solution) { [string]$row.Solution } else { '' }
        if ([string]::IsNullOrWhiteSpace($sol)) { continue }

        ## Collect all KB numbers from this row's solution text
        $kbNums = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $kbPattern.Matches($sol))     { [void]$kbNums.Add("KB$($m.Groups[1].Value)") }
        foreach ($m in $secUpdPattern.Matches($sol)) { [void]$kbNums.Add("KB$($m.Groups[1].Value)") }
        if ($kbNums.Count -eq 0) { continue }

        ## Resolve host (DNS > NetBIOS stripped of DOMAIN\ > IP)
        $dns  = if ($row.DnsName)   { [string]$row.DnsName }   else { '' }
        $nb   = if ($row.NetBios)   { [string]$row.NetBios }   else { '' }
        $ip   = if ($row.IpAddress) { [string]$row.IpAddress } else { '' }
        ## Strip DOMAIN\ prefix from NetBIOS if present
        if ($nb -match '\\') { $nb = $nb -replace '^[^\\]+\\', '' }

        $hostVal = ''
        if     ($dns) { $hostVal = $dns }
        elseif ($nb)  { $hostVal = $nb  }
        elseif ($ip)  { $hostVal = $ip  }
        if ([string]::IsNullOrWhiteSpace($hostVal)) { continue }

        foreach ($kb in $kbNums) {
            $dedup = "$hostVal|$kb"
            if ($seen.Add($dedup)) {
                [void]$result.Add(@{
                    Host     = $hostVal
                    Kb       = $kb.ToUpperInvariant()
                    Severity = if ($row.Severity)   { [string]$row.Severity }   else { '' }
                    Plugin   = if ($row.PluginName) { [string]$row.PluginName } else { '' }
                    Cve      = if ($row.Cve)        { [string]$row.Cve }        else { '' }
                    Solution = $sol
                })
            }
        }
    }
    return $result.ToArray()
}

function global:Start-NemKbInstallerRun {
    <#
    .SYNOPSIS
        Read checked rows from kbGrid, group by host, dispatch one runspace
        job per host via the pool, drain with a WinForms timer.

    .DESCRIPTION
        Follows the same pool + drain-timer pattern used by Start-NemVulnRun,
        but with its own control keys (kbGrid, kbBtnRun, kbBtnCancel,
        kbLblStatus, kbRtbLog, kbTimer) so Updater and KB Installer can run
        independently.

        v1.1.0: method is driven by the kbDdlMethod dropdown — either
        MECM (CIM targeted) via CCM_SoftwareUpdatesManager.InstallUpdates,
        or UsoClient Trigger as a fallback nudge to the target's WUA.
    #>
    [CmdletBinding()]
    param()

    $s     = Get-NemState
    $theme = $s.UI.Theme
    $ctrl  = $s.UI.Controls

    $rtb = $ctrl['kbRtbLog']
    $btn = $ctrl['kbBtnRun']
    $lbl = $ctrl['kbLblStatus']

    if (-not $s.Session['Started']) {
        Show-NemSessionGateDialog
        return
    }
    if (-not $s.Pool) {
        [System.Windows.Forms.MessageBox]::Show(
            'Runspace pool is not open. Start the session again.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Collect checked rows from the DataGridView
    $dgv = $ctrl['kbGrid']
    $checkedRows = @()
    for ($ri = 0; $ri -lt $dgv.Rows.Count; $ri++) {
        $cell = $dgv.Rows[$ri].Cells['ColSelect']
        if ($cell -and [bool]$cell.Value) {
            $checkedRows += @{
                Host     = [string]$dgv.Rows[$ri].Cells['ColHost'].Value
                Kb       = [string]$dgv.Rows[$ri].Cells['ColKb'].Value
                Severity = [string]$dgv.Rows[$ri].Cells['ColSeverity'].Value
            }
        }
    }

    if ($checkedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'No rows checked. Use the checkboxes to select KB entries to install.',
            'ACAS Nemesis', 'OK', 'Warning') | Out-Null
        return
    }

    ## Group checked rows by host
    $byHost = @{}
    foreach ($row in $checkedRows) {
        $h = $row.Host
        if (-not $byHost.ContainsKey($h)) { $byHost[$h] = [System.Collections.ArrayList]::new() }
        [void]$byHost[$h].Add($row.Kb)
    }
    $targets = @($byHost.Keys)

    ## Resolve selected install method (defaults to MECM on first paint).
    $method = if ($ctrl.ContainsKey('kbDdlMethod') -and $ctrl['kbDdlMethod'].SelectedItem) {
        [string]$ctrl['kbDdlMethod'].SelectedItem
    } else {
        'MECM (CIM targeted)'
    }

    ## Lock UI
    $btn.Enabled = $false
    $ctrl['kbBtnCancel'].Enabled = $true
    $lbl.Text      = "KB Install [$method] running on $($targets.Count) host(s), $($checkedRows.Count) KB(s)..."
    $lbl.ForeColor = $theme.Warning

    ## Log header
    $rtb.AppendText("========================================`r`n")
    $rtb.AppendText("Method:  $method`r`n")
    $rtb.AppendText("Hosts:   $($targets.Count)  |  KB entries: $($checkedRows.Count)`r`n")
    $rtb.AppendText("========================================`r`n")
    Write-NemAudit -Action 'KbInstall.Start' -Result 'OK' `
        -Detail "method=$method hosts=$($targets.Count) kb_entries=$($checkedRows.Count)"

    ## Reset jobs
    $s['Jobs'] = @{}
    $s.Jobs['_counters'] = @{
        Success   = 0
        Failed    = 0
        Total     = $targets.Count
        Method    = $method
        StartedAt = Get-Date
    }

    ## v1.8.8: serial preflight removed (see Start-NemVulnRun). The
    ## inline TCP probe in each runspace scriptblock handles
    ## reachability without blocking the UI.

    ## Capture per-run options once so every dispatched runspace sees the
    ## same credential, MSU path, and reboot-suppression intent.
    $cred           = $s.Credentials   # PSCredential or $null (→ ambient Kerberos)
    $msuPath        = if ($ctrl.ContainsKey('kbTxtMsuPath'))       { [string]$ctrl['kbTxtMsuPath'].Text.Trim() } else { '' }
    $suppressReboot = if ($ctrl.ContainsKey('kbChkSuppressReboot')) { [bool]$ctrl['kbChkSuppressReboot'].Checked } else { $false }

    ## Dispatch - one job per host with its KB list; scriptblock branches on method.
    foreach ($t in $targets) {
        $kbList = @($byHost[$t])
        $id = [guid]::NewGuid().ToString('N')
        $ps = [powershell]::Create()
        $ps.RunspacePool = $s.Pool

        if ($method -eq 'MECM (CIM targeted)') {
            ## SIM pattern + WPT MSU fallback:
            ##   1. CIM query MECM's CCM_SoftwareUpdate catalog
            ##   2. CCM_SoftwareUpdatesManager.InstallUpdates on matched subset
            ##   3. For KBs MECM didn't match, fall back to wusa.exe with the
            ##      operator-provided MSU path (copied over a PSSession)
            ##   4. Optional: flip AU registry keys pre-install to suppress reboot
            [void]$ps.AddScript({
                param($TargetIn, $KbsIn, $CredIn, $MsuPathIn, $SuppressRebootIn)

                ## v1.4.0 (WPT-ported): TCP probe + ONE bounded PSSession
                ## shared across the MECM CIM trigger and the MSU fallback.
                ## Previously: one transient `Invoke-Command -ComputerName`
                ## (no timeout cap) for MECM, then a SEPARATE New-PSSession
                ## (also no timeout cap) for MSU. Now: single Negotiate
                ## session with bounded OpenTimeout/OperationTimeout that
                ## both phases reuse, halving the WinRM handshake cost
                ## and preventing 3-minute hangs on flaky targets.
                $reachable = $false
                foreach ($port in 5985, 445) {
                    $tc = $null
                    try {
                        $tc  = New-Object System.Net.Sockets.TcpClient
                        $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
                    } catch {}
                    finally { if ($tc) { try { $tc.Close() } catch {} } }
                    if ($reachable) { break }
                }
                if (-not $reachable) { return "FAIL: unreachable (TCP 5985/445)" }

                $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
                $sessArgs = @{
                    ComputerName   = $TargetIn
                    SessionOption  = $wsOpt
                    Authentication = 'Negotiate'
                    ErrorAction    = 'Stop'
                }
                if ($CredIn) { $sessArgs['Credential'] = $CredIn }
                $sess = $null
                try { $sess = New-PSSession @sessArgs }
                catch {
                    $sessErr = $_.Exception.Message
                    ## v1.8.3: NetBIOS fallback on Negotiate auth failures.
                    ## See VulnRun scriptblock for the full rationale.
                    if ($TargetIn -match '\.' -and (
                            $sessErr -match '0x80090322' -or
                            $sessErr -match 'Negotiate authentication' -or
                            $sessErr -match 'Access is denied'
                        )) {
                        $nbName = ($TargetIn -split '\.')[0]
                        $sessArgs2 = @{} + $sessArgs
                        $sessArgs2['ComputerName'] = $nbName
                        try {
                            $sess = New-PSSession @sessArgs2
                        } catch {
                            return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
                        }
                    } else {
                        return "FAIL: Session - $sessErr"
                    }
                }

                try {
                    $remoteSb = {
                        param($kbsArr, $suppressReboot)
                        $report = @{ Matched = @(); Triggered = 0; TotalPending = 0; Errors = @() }

                        if ($suppressReboot) {
                            try {
                                $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                                if (-not (Test-Path $auKey)) {
                                    New-Item -Path $auKey -Force -ErrorAction Stop | Out-Null
                                }
                                Set-ItemProperty -Path $auKey -Name 'NoAutoRebootWithLoggedOnUsers'   -Value 1 -Type DWord -Force -ErrorAction Stop
                                Set-ItemProperty -Path $auKey -Name 'AlwaysAutoRebootAtScheduledTime' -Value 0 -Type DWord -Force -ErrorAction Stop
                            } catch {
                                $report.Errors += "reboot-prep: $($_.Exception.Message)"
                            }
                        }

                        try {
                            $pending = @(Get-CimInstance -Namespace 'ROOT\ccm\ClientSDK' `
                                -ClassName CCM_SoftwareUpdate -Filter 'ComplianceState = 0' -ErrorAction Stop)
                        } catch {
                            $report.Errors += "MECM query failed: $($_.Exception.Message)"
                            return $report
                        }
                        $report.TotalPending = $pending.Count
                        if ($pending.Count -eq 0) { return $report }

                        $matchedUpdates = [System.Collections.ArrayList]::new()
                        foreach ($kb in $kbsArr) {
                            $num = $kb -replace '^KB',''
                            $m = @($pending | Where-Object { $_.ArticleID -eq $num -or $_.Name -like "*$kb*" })
                            if ($m.Count -gt 0) {
                                $report.Matched += $kb
                                foreach ($u in $m) { [void]$matchedUpdates.Add($u) }
                            }
                        }
                        if ($matchedUpdates.Count -eq 0) { return $report }
                        try {
                            Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' `
                                -ClassName CCM_SoftwareUpdatesManager -MethodName InstallUpdates `
                                -Arguments @{ CCMUpdates = [ciminstance[]]$matchedUpdates } -ErrorAction Stop | Out-Null
                            $report.Triggered = $matchedUpdates.Count
                        } catch {
                            $report.Errors += "InstallUpdates failed: $($_.Exception.Message)"
                        }
                        return $report
                    }

                    $mecmResult = $null
                    try {
                        $mecmResult = Invoke-Command -Session $sess -ScriptBlock $remoteSb `
                                                     -ArgumentList (,$KbsIn), [bool]$SuppressRebootIn `
                                                     -ErrorAction Stop
                    } catch {
                        return "FAIL: $($_.Exception.Message)"
                    }
                    if ($mecmResult -isnot [hashtable]) { return 'FAIL: unexpected remote payload' }

                    ## MSU fallback for KBs MECM did not match (WPT pattern).
                    ## Reuses the same PSSession opened above.
                    $matched   = @($mecmResult.Matched)
                    $unmatched = @($KbsIn | Where-Object { $matched -notcontains $_ })
                    $msu = @{ Installed = 0; AlreadyInstalled = 0; Skipped = 0; Errors = @() }

                    if ($unmatched.Count -gt 0 -and $MsuPathIn -and (Test-Path -LiteralPath $MsuPathIn)) {
                        try {
                            Invoke-Command -Session $sess -ScriptBlock {
                                if (-not (Test-Path 'C:\Temp')) {
                                    New-Item -Path 'C:\Temp' -ItemType Directory -Force -ErrorAction Stop | Out-Null
                                }
                            } -ErrorAction Stop | Out-Null

                            $msuName   = Split-Path $MsuPathIn -Leaf
                            $remoteMsu = "C:\Temp\$msuName"
                            Copy-Item -LiteralPath $MsuPathIn -Destination $remoteMsu -ToSession $sess -Force -ErrorAction Stop

                            $wusaArgs = "`"$remoteMsu`" /quiet"
                            if ($SuppressRebootIn) { $wusaArgs += ' /norestart' }

                            $exit = Invoke-Command -Session $sess -ScriptBlock {
                                param($a)
                                try {
                                    $p = Start-Process wusa.exe -ArgumentList $a -Wait -PassThru -NoNewWindow -ErrorAction Stop
                                    return [int]$p.ExitCode
                                } catch {
                                    return -1
                                }
                            } -ArgumentList $wusaArgs -ErrorAction Stop

                            switch ([int]$exit) {
                                0        { $msu.Installed++ }
                                3010     { $msu.Installed++ }         # success, reboot required
                                2359302  { $msu.AlreadyInstalled++ }  # already installed
                                -1       { $msu.Errors += 'wusa launch failed' }
                                default  { $msu.Errors += "wusa exit=$exit" }
                            }

                            try {
                                Invoke-Command -Session $sess -ScriptBlock {
                                    param($f); Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                                } -ArgumentList $remoteMsu -ErrorAction SilentlyContinue
                            } catch {}
                        } catch {
                            $msu.Errors += "MSU: $($_.Exception.Message)"
                        }
                    } elseif ($unmatched.Count -gt 0) {
                        $msu.Skipped = $unmatched.Count
                    }

                    ## Summary
                    $matchedCount = @($mecmResult.Matched).Count
                    $allErrors    = @($mecmResult.Errors) + @($msu.Errors)
                    $parts = @("MECM matched=$matchedCount/$($KbsIn.Count) triggered=$($mecmResult.Triggered) (pool=$($mecmResult.TotalPending))")
                    if ($MsuPathIn) {
                        $parts += "MSU installed=$($msu.Installed) already=$($msu.AlreadyInstalled) skipped=$($msu.Skipped)"
                    }
                    $summary = $parts -join ' | '

                    if (@($allErrors).Count -gt 0) {
                        return "FAIL: $summary | " + ($allErrors -join '; ')
                    }
                    if ($matchedCount -eq 0 -and $msu.Installed -eq 0 -and $msu.AlreadyInstalled -eq 0) {
                        return "OK: no MECM catalog match for $($KbsIn -join ',') (MSU fallback " + $(if ($MsuPathIn) { 'produced nothing' } else { 'not configured' }) + ')'
                    }
                    return "OK: $summary"
                } finally {
                    if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
                }
            })
        } else {
            ## UsoClient Trigger — poke the target's Windows Update Agent.
            ## Credential is forwarded if the operator set one; otherwise
            ## ambient Kerberos. Suppress-reboot flips AU registry keys
            ## pre-install (same pattern as the MECM branch).
            [void]$ps.AddScript({
                param($TargetIn, $KbsIn, $CredIn, $SuppressRebootIn)

                ## v1.4.0 (WPT-ported): TCP probe + bounded PSSession.
                $reachable = $false
                foreach ($port in 5985, 445) {
                    $tc = $null
                    try {
                        $tc  = New-Object System.Net.Sockets.TcpClient
                        $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
                    } catch {}
                    finally { if ($tc) { try { $tc.Close() } catch {} } }
                    if ($reachable) { break }
                }
                if (-not $reachable) { return "FAIL: unreachable (TCP 5985/445)" }

                $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
                $sessArgs = @{
                    ComputerName   = $TargetIn
                    SessionOption  = $wsOpt
                    Authentication = 'Negotiate'
                    ErrorAction    = 'Stop'
                }
                if ($CredIn) { $sessArgs['Credential'] = $CredIn }
                $sess = $null
                try { $sess = New-PSSession @sessArgs }
                catch {
                    $sessErr = $_.Exception.Message
                    ## v1.8.3: NetBIOS fallback on Negotiate auth failures.
                    ## See VulnRun scriptblock for the full rationale.
                    if ($TargetIn -match '\.' -and (
                            $sessErr -match '0x80090322' -or
                            $sessErr -match 'Negotiate authentication' -or
                            $sessErr -match 'Access is denied'
                        )) {
                        $nbName = ($TargetIn -split '\.')[0]
                        $sessArgs2 = @{} + $sessArgs
                        $sessArgs2['ComputerName'] = $nbName
                        try {
                            $sess = New-PSSession @sessArgs2
                        } catch {
                            return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
                        }
                    } else {
                        return "FAIL: Session - $sessErr"
                    }
                }

                try {
                    $r = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
                        param($suppress)
                        if ($suppress) {
                            try {
                                $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                                if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force -ErrorAction Stop | Out-Null }
                                Set-ItemProperty -Path $auKey -Name 'NoAutoRebootWithLoggedOnUsers'   -Value 1 -Type DWord -Force -ErrorAction Stop
                                Set-ItemProperty -Path $auKey -Name 'AlwaysAutoRebootAtScheduledTime' -Value 0 -Type DWord -Force -ErrorAction Stop
                            } catch { return "FAIL: reboot-prep - $($_.Exception.Message)" }
                        }
                        try {
                            Start-Process -FilePath "$env:WinDir\System32\UsoClient.exe" `
                                          -ArgumentList 'StartInstall' `
                                          -WindowStyle Hidden -Wait -ErrorAction Stop
                            return 'OK'
                        } catch {
                            return "FAIL: UsoClient - $($_.Exception.Message)"
                        }
                    } -ArgumentList ([bool]$SuppressRebootIn)
                    if ([string]$r -like 'FAIL*') { return [string]$r }
                    return "OK (UsoClient StartInstall triggered; requested KBs informational: $($KbsIn -join ','))"
                } catch {
                    return "FAIL: $($_.Exception.Message)"
                } finally {
                    if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
                }
            })
        }

        ## Common arguments for both branches
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($kbList)
        [void]$ps.AddArgument($cred)
        if ($method -eq 'MECM (CIM targeted)') {
            [void]$ps.AddArgument($msuPath)
            [void]$ps.AddArgument($suppressReboot)
        } else {
            [void]$ps.AddArgument($suppressReboot)
        }

        $async = $ps.BeginInvoke()
        $s.Jobs[$id] = @{ PS = $ps; Async = $async; Target = $t; Kbs = $kbList }
    }

    ## Drain timer - uses 'kbTimer' key to avoid collision with updTimer
    $kbTimer = New-Object System.Windows.Forms.Timer
    $kbTimer.Interval = Get-NemDrainInterval
    $kbTimer.Add_Tick({
        $s2     = Get-NemState
        $rtb2   = $s2.UI.Controls['kbRtbLog']
        $btn2   = $s2.UI.Controls['kbBtnRun']
        $lbl2   = $s2.UI.Controls['kbLblStatus']
        $theme2 = $s2.UI.Theme

        $counters = $s2.Jobs['_counters']
        $done = @()
        ## v1.10.4: cap completions processed per drain tick. When a batch
        ## of remote jobs finishes together (eg. 15 unreachable hosts all
        ## timing out at the same ~6s TCP probe), processing every one in a
        ## single Tick meant ~3 synchronous AFNET-share log writes each,
        ## back to back, on the UI thread — long enough to freeze the
        ## window ("Not Responding"). Get-NemDrainCap bounds the per-tick
        ## work; the message pump runs between ticks and remaining
        ## completed jobs are picked up on the next one. Job state is never
        ## lost — the outstanding-count check below keeps the timer alive
        ## until the dictionary is truly empty.
        $drainCap  = Get-NemDrainCap
        $drainDone = 0
        foreach ($id in @($s2.Jobs.Keys)) {
            if ($id -eq '_counters') { continue }
            if ($drainDone -ge $drainCap) { break }
            $job = $s2.Jobs[$id]
            if ($job.Async.IsCompleted) {
                $resultStr = ''
                try {
                    $out = $job.PS.EndInvoke($job.Async)
                    if ($out -and @($out).Count -gt 0) { $resultStr = [string]$out[0] }
                    else { $resultStr = 'OK (no output)' }
                } catch {
                    $resultStr = "FAIL: $($_.Exception.Message)"
                }
                try { $job.PS.Dispose() } catch {}

                if ($resultStr -like 'FAIL*') {
                    $counters['Failed'] = [int]$counters['Failed'] + 1
                    $rtb2.SelectionColor = $theme2.Danger
                } else {
                    $counters['Success'] = [int]$counters['Success'] + 1
                    $rtb2.SelectionColor = $theme2.Success
                }
                $rtb2.AppendText("$($job.Target) : $resultStr`r`n")
                $rtb2.SelectionColor = $rtb2.ForeColor

                $auditResult = 'OK'
                if ($resultStr -like 'FAIL*') { $auditResult = 'Failed' }
                Write-NemAudit -Action 'KbInstall.Target' -Target $job.Target `
                    -Result $auditResult `
                    -Detail "kbs=$($job.Kbs -join ',') result=$resultStr"

                $done += $id
                $drainDone++
            }
        }
        foreach ($id in $done) { [void]$s2.Jobs.Remove($id) }

        ## Done condition
        $outstanding = 0
        foreach ($k in $s2.Jobs.Keys) { if ($k -ne '_counters') { $outstanding++ } }
        if ($outstanding -eq 0) {
            $this.Stop()
            $this.Dispose()
            $s2.UI.Controls.Remove('kbTimer') | Out-Null

            $rtb2.AppendText("========================================`r`n")
            $rtb2.AppendText("Complete: $($counters['Success']) succeeded, $($counters['Failed']) failed`r`n")
            $rtb2.AppendText("========================================`r`n")
            Write-NemAudit -Action 'KbInstall.End' -Result 'OK' `
                -Detail "success=$($counters['Success']) failed=$($counters['Failed'])"

            ## Append one row to the daily Runs CSV on the log share.
            try {
                Write-NemRunSummary -Action 'KbInstall' `
                    -Scope      'KB bulk' `
                    -Profile    ([string]$counters['Method']) `
                    -Mode       ([string]$counters['Method']) `
                    -HostsTotal ([int]$counters['Total']) `
                    -Success    ([int]$counters['Success']) `
                    -Failed     ([int]$counters['Failed']) `
                    -StartedAt  $counters['StartedAt']
            } catch {
                Write-NemAudit -Action 'RunsCsv.Failed' -Target 'KbInstall' -Result 'Failed' `
                    -Detail $_.Exception.Message
            }

            $btn2.Enabled = $true
            $s2.UI.Controls['kbBtnCancel'].Enabled = $false
            $lbl2.Text = "$($counters['Success']) succeeded, $($counters['Failed']) failed"
            if ([int]$counters['Failed'] -eq 0) { $lbl2.ForeColor = $theme2.Success }
            else { $lbl2.ForeColor = $theme2.Warning }
        }
    }.GetNewClosure())

    $kbTimer.Start()
    $s.UI.Controls['kbTimer'] = $kbTimer
}

function Add-NemKBInstallerTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text ([char]0x26A1 + ' KB Installer') -X 20 -Y 16 -W 700 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Install specific Windows KB rollups on hosts that need them. KB numbers are parsed from the imported ACAS CSV ''Steps to Remediate'' column.' `
        -X 20 -Y 50 -W 1100 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== ACTION BAR ==========
    $btnRescan = New-WptButton -Text 'Rescan Findings' -X 20 -Y 86 -W 160 -H 30 `
        -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.Body

    $btnSelAll = New-WptButton -Text 'Select All' -X 192 -Y 86 -W 110 -H 30 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body

    $btnDeselAll = New-WptButton -Text 'Deselect All' -X 314 -Y 86 -W 120 -H 30 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body

    $btnSelCritHigh = New-WptButton -Text 'Select Critical/High' -X 446 -Y 86 -W 180 -H 30 `
        -Bg $theme.Warning -Fg $theme.Background -Font $fonts.Body

    ## Install-method dropdown — MECM (CIM targeted) default, UsoClient Trigger alternate.
    $lblMethod = New-WptLabel -Text 'Method:' -X 650 -Y 92 -W 70 -H 22 `
        -Font $fonts.Body -Fg $theme.TextSecondary
    $ddlMethod = New-WptComboBox -X 724 -Y 86 -W 300 -H 28 -Items @(
        'MECM (CIM targeted)'
        'UsoClient Trigger'
    )
    $ddlMethod.SelectedIndex = 0
    $state.UI.Controls['kbDdlMethod'] = $ddlMethod

    ## Second config row — MSU file (MECM fallback) + Suppress-reboot.
    $lblMsu = New-WptLabel -Text 'MSU file (MECM only):' `
        -X 20 -Y 128 -W 160 -H 22 -Font $fonts.Body -Fg $theme.TextSecondary

    $txtMsuPath = New-WptTextBox -X 186 -Y 124 -W 550 -H 26
    $state.UI.Controls['kbTxtMsuPath'] = $txtMsuPath

    $btnBrowseMsu = New-WptButton -Text 'Browse...' -X 744 -Y 122 -W 90 -H 30 `
        -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body

    $chkSuppressReboot = New-WptCheckBox -Text 'Suppress auto-reboot' `
        -X 852 -Y 124 -W 240 -H 26 -Fg $theme.Warning
    $state.UI.Controls['kbChkSuppressReboot'] = $chkSuppressReboot

    $lblCount = New-WptLabel -Text '0 findings parsed (0 selected)' `
        -X 20 -Y 162 -W 700 -H 20 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $state.UI.Controls['kbLblCount'] = $lblCount

    ## Toggle MSU + Browse enable state based on method selection.
    $toggleMsuEnabled = {
        $s2 = Get-NemState
        $method2 = [string]$s2.UI.Controls['kbDdlMethod'].SelectedItem
        $isMecm = ($method2 -eq 'MECM (CIM targeted)')
        $s2.UI.Controls['kbTxtMsuPath'].Enabled = $isMecm
        foreach ($c in @($btnBrowseMsu, $lblMsu)) {
            if ($c) { $c.Enabled = $isMecm }
        }
    }.GetNewClosure()
    $ddlMethod.Add_SelectedIndexChanged({ & $toggleMsuEnabled }.GetNewClosure())
    & $toggleMsuEnabled   # initial state

    $btnBrowseMsu.Add_Click({
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Filter = 'Microsoft Update (*.msu)|*.msu|All files (*.*)|*.*'
        $ofd.Title  = 'Select MSU file'
        if ($ofd.ShowDialog() -eq 'OK') {
            (Get-NemState).UI.Controls['kbTxtMsuPath'].Text = $ofd.FileName
        }
    }.GetNewClosure())

    ## ========== DATA GRID ==========
    ## Dock=Fill inside a padded body panel — avoids the anchor-timing bug
    ## (margins computed against still-resolving parent Dock=Fill chain).
    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Dock                   = 'Fill'
    $dgv.BackgroundColor        = $theme.Input
    $dgv.ForeColor              = $theme.TextPrimary
    $dgv.GridColor              = $theme.Border
    $dgv.AutoGenerateColumns    = $false
    $dgv.AllowUserToAddRows     = $false
    $dgv.RowHeadersVisible      = $false
    $dgv.SelectionMode          = 'FullRowSelect'
    $dgv.BorderStyle            = 'None'
    $dgv.CellBorderStyle        = 'SingleHorizontal'
    $dgv.DefaultCellStyle.BackColor    = $theme.Input
    $dgv.DefaultCellStyle.ForeColor    = $theme.TextPrimary
    $dgv.DefaultCellStyle.SelectionBackColor = $theme.SurfaceActive
    $dgv.DefaultCellStyle.SelectionForeColor = $theme.TextPrimary
    $dgv.AlternatingRowsDefaultCellStyle.BackColor = $theme.SurfaceAlt
    $dgv.ColumnHeadersDefaultCellStyle.BackColor   = $theme.Sidebar
    $dgv.ColumnHeadersDefaultCellStyle.ForeColor   = $theme.Accent1
    $dgv.ColumnHeadersDefaultCellStyle.Font        = $fonts.MonoSm
    $dgv.ColumnHeadersHeight    = 28
    $dgv.RowTemplate.Height     = 22
    $dgv.Font                   = $fonts.MonoSm
    Enable-WptDoubleBuffer -Control $dgv
    $state.UI.Controls['kbGrid'] = $dgv

    ## Define columns
    $colSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colSel.Name           = 'ColSelect'
    $colSel.HeaderText     = ''
    $colSel.Width          = 50
    $colSel.AutoSizeMode   = 'None'
    $colSel.FillWeight     = 1
    $colSel.FalseValue     = $false
    $colSel.TrueValue      = $true
    $colSel.IndeterminateValue = $false

    $colHost = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colHost.Name           = 'ColHost'
    $colHost.HeaderText     = 'Host'
    $colHost.Width          = 260
    $colHost.AutoSizeMode   = 'None'
    $colHost.ReadOnly       = $true

    $colKb = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colKb.Name             = 'ColKb'
    $colKb.HeaderText       = 'KB'
    $colKb.Width            = 100
    $colKb.AutoSizeMode     = 'None'
    $colKb.ReadOnly         = $true

    $colSeverity = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colSeverity.Name       = 'ColSeverity'
    $colSeverity.HeaderText = 'Severity'
    $colSeverity.Width      = 90
    $colSeverity.AutoSizeMode = 'None'
    $colSeverity.ReadOnly   = $true

    $colPlugin = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colPlugin.Name         = 'ColPlugin'
    $colPlugin.HeaderText   = 'Plugin Name'
    $colPlugin.AutoSizeMode = 'Fill'
    $colPlugin.ReadOnly     = $true

    $colCve = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colCve.Name            = 'ColCve'
    $colCve.HeaderText      = 'CVE'
    $colCve.AutoSizeMode    = 'Fill'
    $colCve.ReadOnly        = $true

    [void]$dgv.Columns.AddRange($colSel, $colHost, $colKb, $colSeverity, $colPlugin, $colCve)

    ## ========== RUN CONTROLS (positioned inside footer row below) ==========
    $btnRun = New-WptButton -Text 'Run Install' -X 0 -Y 4 -W 200 -H 44 `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.DisplayLg
    $btnRun.Enabled = $false
    $state.UI.Controls['kbBtnRun'] = $btnRun

    $btnCancel = New-WptButton -Text 'Cancel' -X 214 -Y 4 -W 140 -H 44 `
        -Bg $theme.Danger -Fg $theme.TextOnAccent -Font $fonts.DisplayLg
    $btnCancel.Enabled = $false
    $state.UI.Controls['kbBtnCancel'] = $btnCancel

    $lblStatus = New-WptLabel -Text 'Idle' -X 370 -Y 14 -W 720 -H 24 `
        -Font $fonts.Body -Fg $theme.TextMuted
    $state.UI.Controls['kbLblStatus'] = $lblStatus

    ## ========== LOG ==========
    $lblLog = New-WptLabel -Text 'KB INSTALLER LOG' -X 0 -Y 0 -W 220 -H 20 `
        -Font $fonts.Body -Fg $theme.Accent2

    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Dock        = 'Fill'
    $rtbLog.ReadOnly    = $true
    $rtbLog.WordWrap    = $false
    $rtbLog.ScrollBars  = 'Vertical'
    $rtbLog.Font        = $fonts.Console
    $rtbLog.BackColor   = $theme.StatusBar
    $rtbLog.ForeColor   = $theme.TextPrimary
    $rtbLog.BorderStyle = 'FixedSingle'
    $state.UI.Controls['kbRtbLog'] = $rtbLog

    ## ========== HELPERS ==========
    $updateCountLabel = {
        $s2  = Get-NemState
        $g   = $s2.UI.Controls['kbGrid']
        $lc  = $s2.UI.Controls['kbLblCount']
        $total    = $g.Rows.Count
        $selected = 0
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $cell = $g.Rows[$ri].Cells['ColSelect']
            if ($cell -and [bool]$cell.Value) { $selected++ }
        }
        $lc.Text = "$total findings parsed ($selected selected)"
        $s2.UI.Controls['kbBtnRun'].Enabled = ($selected -gt 0)
    }.GetNewClosure()

    $populateGrid = {
        $s2  = Get-NemState
        $g   = $s2.UI.Controls['kbGrid']
        $g.Rows.Clear()
        $items = Get-NemKbParsedFindings
        foreach ($item in $items) {
            $rowIdx = $g.Rows.Add()
            $g.Rows[$rowIdx].Cells['ColSelect'].Value   = $false
            $g.Rows[$rowIdx].Cells['ColHost'].Value     = $item.Host
            $g.Rows[$rowIdx].Cells['ColKb'].Value       = $item.Kb
            $g.Rows[$rowIdx].Cells['ColSeverity'].Value = $item.Severity
            $g.Rows[$rowIdx].Cells['ColPlugin'].Value   = $item.Plugin
            $g.Rows[$rowIdx].Cells['ColCve'].Value      = $item.Cve
        }
        & $updateCountLabel
    }.GetNewClosure()

    ## ========== HANDLERS ==========
    $btnRescan.Add_Click({
        & $populateGrid
    }.GetNewClosure())

    $btnSelAll.Add_Click({
        $s2 = Get-NemState
        $g  = $s2.UI.Controls['kbGrid']
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $g.Rows[$ri].Cells['ColSelect'].Value = $true
        }
        & $updateCountLabel
    }.GetNewClosure())

    $btnDeselAll.Add_Click({
        $s2 = Get-NemState
        $g  = $s2.UI.Controls['kbGrid']
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $g.Rows[$ri].Cells['ColSelect'].Value = $false
        }
        & $updateCountLabel
    }.GetNewClosure())

    $btnSelCritHigh.Add_Click({
        $s2   = Get-NemState
        $g    = $s2.UI.Controls['kbGrid']
        $high = @('Critical', 'High')
        for ($ri = 0; $ri -lt $g.Rows.Count; $ri++) {
            $sev = [string]$g.Rows[$ri].Cells['ColSeverity'].Value
            $g.Rows[$ri].Cells['ColSelect'].Value = ($high -icontains $sev)
        }
        & $updateCountLabel
    }.GetNewClosure())

    $dgv.Add_CellValueChanged({
        param($sender, $e)
        if ($e.ColumnIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq 'ColSelect') {
            & $updateCountLabel
        }
    }.GetNewClosure())

    ## Checkbox cells commit on click in DataGridView — need CurrentCellDirtyStateChanged
    $dgv.Add_CurrentCellDirtyStateChanged({
        param($sender, $e)
        if ($sender.IsCurrentCellDirty) {
            $sender.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    }.GetNewClosure())

    $btnRun.Add_Click({
        try {
            Start-NemKbInstallerRun
        } catch {
            Write-NemAudit -Action 'KbInstall' -Result 'Failed' -Detail $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show(
                "KB Install run failed: $($_.Exception.Message)",
                'ACAS Nemesis - Run error', 'OK', 'Error') | Out-Null
        }
    }.GetNewClosure())

    $btnCancel.Add_Click({
        $s2    = Get-NemState
        $rtb2  = $s2.UI.Controls['kbRtbLog']
        $btn2  = $s2.UI.Controls['kbBtnRun']
        $lbl2  = $s2.UI.Controls['kbLblStatus']
        $thm2  = $s2.UI.Theme

        $cancelCount = 0
        foreach ($key in @($s2.Jobs.Keys)) {
            if ($key -eq '_counters') { continue }
            $job = $s2.Jobs[$key]
            try { $job.PS.Stop()    } catch {}
            try { $job.PS.Dispose() } catch {}
            $cancelCount++
        }
        $s2['Jobs'] = @{}

        $tim = $s2.UI.Controls['kbTimer']
        if ($tim) {
            try { $tim.Stop()    } catch {}
            try { $tim.Dispose() } catch {}
            $s2.UI.Controls.Remove('kbTimer') | Out-Null
        }

        $rtb2.SelectionColor = $thm2.Warning
        $rtb2.AppendText("========================================`r`n")
        $rtb2.AppendText("CANCELLED by operator ($cancelCount job(s) stopped)`r`n")
        $rtb2.AppendText("========================================`r`n")
        $rtb2.SelectionColor = $rtb2.ForeColor
        Write-NemAudit -Action 'KbInstall.Cancel' -Result 'OK' `
            -Detail "jobs_stopped=$cancelCount"

        $s2.UI.Controls['kbBtnCancel'].Enabled = $false
        $btn2.Enabled  = $true
        $lbl2.Text     = 'Cancelled'
        $lbl2.ForeColor = $thm2.Warning
    }.GetNewClosure())

    ## Auto-rescan when tab becomes visible
    $TabPanel.Add_VisibleChanged({
        if ($TabPanel.Visible) { & $populateGrid }
    }.GetNewClosure())

    ## ========== ASSEMBLE (Dock: header / footer / fill) ==========
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 194
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@(
        $lblTitle, $lblSub,
        $btnRescan, $btnSelAll, $btnDeselAll, $btnSelCritHigh,
        $lblMethod, $ddlMethod,
        $lblMsu, $txtMsuPath, $btnBrowseMsu, $chkSuppressReboot,
        $lblCount
    ))

    ## Footer: log label + log textbox + run/cancel/status row.
    $footer = New-Object System.Windows.Forms.Panel
    $footer.Dock      = 'Bottom'
    $footer.Height    = 300
    $footer.BackColor = [System.Drawing.Color]::Transparent
    $footer.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)

    $runRow = New-Object System.Windows.Forms.Panel
    $runRow.Dock      = 'Top'
    $runRow.Height    = 54
    $runRow.BackColor = [System.Drawing.Color]::Transparent
    $runRow.Controls.AddRange(@($btnRun, $btnCancel, $lblStatus))

    $logLabelRow = New-Object System.Windows.Forms.Panel
    $logLabelRow.Dock      = 'Top'
    $logLabelRow.Height    = 22
    $logLabelRow.BackColor = [System.Drawing.Color]::Transparent
    $logLabelRow.Controls.Add($lblLog)

    $logHost = New-Object System.Windows.Forms.Panel
    $logHost.Dock      = 'Fill'
    $logHost.BackColor = [System.Drawing.Color]::Transparent
    $logHost.Controls.Add($rtbLog)

    ## Fill first so the docked rows claim their space above it.
    $footer.Controls.Add($logHost)
    $footer.Controls.Add($logLabelRow)
    $footer.Controls.Add($runRow)

    ## Body: the DataGridView, padded.
    $body = New-Object System.Windows.Forms.Panel
    $body.Dock      = 'Fill'
    $body.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 8)
    $body.BackColor = [System.Drawing.Color]::Transparent
    $body.Controls.Add($dgv)

    $TabPanel.Controls.Add($body)    # Dock=Fill — added first
    $TabPanel.Controls.Add($footer)  # Dock=Bottom
    $TabPanel.Controls.Add($header)  # Dock=Top
}

function Add-NemBackboneTab {
    <#
        v1.8.0: dedicated reference tab. Shows per-updater-profile
        mechanism notes (auto-generated from the live profile registry)
        followed by the existing workflow walkthrough. Operators can
        scroll, copy text, and Ctrl+F find without leaving the app.

        Content built fresh each time the tab becomes visible — picks up
        any profiles added to $script:WptAppUpdateProfiles after launch
        (rare but cheap to refresh).

        v1.8.1: renamed from Add-NemHowToTab to Add-NemBackboneTab.
        Tab label "How To" -> "Backbone". State key 'howToRtb' ->
        'backboneRtb'. Nav key 'HowTo' -> 'Backbone'. The Start-tab
        "How To Use" dialog button is unaffected.
    #>
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text 'Backbone' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'The mechanism backbone of every updater profile (what each one actually pushes to your hosts), plus the full operator workflow. Always reflects the live profile registry — newly-added profiles appear here automatically.' `
        -X 20 -Y 50 -W 1100 -H 36 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== HEADER (toolbar) ==========
    $btnRefresh = New-WptButton -Text 'Refresh Content' `
        -X 20 -Y 96 -W 160 -H 30 -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body
    $btnCopy = New-WptButton -Text 'Copy to Clipboard' `
        -X 188 -Y 96 -W 160 -H 30 -Bg $theme.PanelLight -Fg $theme.TextPrimary -Font $fonts.Body

    ## ========== CONTENT (RichTextBox, scrollable, monospace) ==========
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock           = 'Fill'
    $rtb.ReadOnly       = $true
    $rtb.WordWrap       = $true
    $rtb.BorderStyle    = 'None'
    $rtb.Font           = $fonts.MonoSm
    $rtb.BackColor      = $theme.Input
    $rtb.ForeColor      = $theme.TextPrimary
    $rtb.DetectUrls     = $false
    $rtb.ScrollBars     = 'Vertical'
    $state.UI.Controls['backboneRtb'] = $rtb

    $populate = {
        $r = $state.UI.Controls['backboneRtb']
        if (-not $r) { return }
        try {
            $r.Text = Get-NemOverviewText
        } catch {
            $r.Text = "Failed to build overview content: $($_.Exception.Message)"
        }
        $r.SelectionStart = 0
        $r.ScrollToCaret()
    }.GetNewClosure()

    $btnRefresh.Add_Click({ & $populate }.GetNewClosure())

    $btnCopy.Add_Click({
        try {
            $r = $state.UI.Controls['backboneRtb']
            if ($r -and $r.Text) {
                [System.Windows.Forms.Clipboard]::SetText($r.Text)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Clipboard write failed: $($_.Exception.Message)",
                'ACAS Nemesis - Copy', 'OK', 'Warning') | Out-Null
        }
    }.GetNewClosure())

    ## Build content once on tab construction; rebuild whenever the tab
    ## becomes visible so newly-added profiles are picked up.
    & $populate
    $TabPanel.Add_VisibleChanged({
        if ($TabPanel.Visible) { & $populate }
    }.GetNewClosure())

    ## ========== ASSEMBLE ==========
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 138
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@($lblTitle, $lblSub, $btnRefresh, $btnCopy))

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock      = 'Fill'
    $body.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)
    $body.BackColor = [System.Drawing.Color]::Transparent
    $body.Controls.Add($rtb)   # Dock=Fill

    $TabPanel.Controls.Add($body)    # Dock=Fill — added first
    $TabPanel.Controls.Add($header)  # Dock=Top
}

function Add-NemLogsTab {
    param([System.Windows.Forms.Panel]$TabPanel)

    $state = Get-NemState
    $theme = $state.UI.Theme
    $fonts = $state.UI.Fonts

    ## ========== TITLE ==========
    $lblTitle = New-WptLabel -Text 'Logs' -X 20 -Y 16 -W 600 -H 32 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $lblSub = New-WptLabel `
        -Text 'Session audit log (last 500 lines). Refresh pulls the latest tail.' `
        -X 20 -Y 50 -W 900 -H 20 -Font $fonts.Body -Fg $theme.TextSecondary

    ## ========== PATH LABEL ==========
    $lblPath = New-WptLabel -Text 'Audit log: (not started)' -X 20 -Y 86 -W 1100 -H 20 `
        -Font $fonts.MonoSm -Fg $theme.TextMuted
    $state.UI.Controls['logsLblPath'] = $lblPath

    ## ========== ACTION BUTTONS ==========
    $btnRefresh = New-WptButton -Text 'Refresh' -X 20 -Y 116 -W 120 -H 30 `
        -Bg $theme.Accent2 -Fg $theme.Background -Font $fonts.Body

    $btnOpen = New-WptButton -Text 'Open Log Folder' -X 148 -Y 116 -W 160 -H 30 `
        -Bg $theme.Accent1 -Fg $theme.Background -Font $fonts.Body

    ## ========== LOG TEXTBOX ==========
    ## Dock=Fill inside a padded body panel — avoids anchor-timing stretch.
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Dock        = 'Fill'
    $tb.Multiline   = $true
    $tb.ReadOnly    = $true
    $tb.ScrollBars  = 'Vertical'
    $tb.Font        = $fonts.Console
    $tb.BackColor   = $theme.StatusBar
    $tb.ForeColor   = $theme.TextPrimary
    $tb.WordWrap    = $false
    $tb.BorderStyle = 'FixedSingle'
    $state.UI.Controls['logsTextbox'] = $tb

    ## ========== HANDLERS ==========
    $refreshTail = {
        $s = Get-NemState
        $tbRef   = $s.UI.Controls['logsTextbox']
        $pathRef = $s.UI.Controls['logsLblPath']

        $logPath = $s.Config.LogFile
        if (-not $logPath -or -not (Test-Path -LiteralPath $logPath)) {
            $tbRef.Text    = '(no audit log yet - start a session)'
            $pathRef.Text  = 'Audit log: (not started)'
            return
        }
        $pathRef.Text = "Audit log: $logPath"
        try {
            $lines = Get-Content -LiteralPath $logPath -Tail 500 -ErrorAction Stop
            if ($null -eq $lines) { $tbRef.Text = '' }
            else { $tbRef.Lines = @($lines) }
            $tbRef.SelectionStart = $tbRef.TextLength
            $tbRef.ScrollToCaret()
        } catch {
            $tbRef.Text = "Failed to read log: $($_.Exception.Message)"
        }
    }.GetNewClosure()

    $btnRefresh.Add_Click({
        & $refreshTail
    }.GetNewClosure())

    $btnOpen.Add_Click({
        $s = Get-NemState
        $dir = $s.Config.LogDir
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            Invoke-Item -LiteralPath $dir
        }
    }.GetNewClosure())

    ## Auto-refresh when the tab becomes visible.
    $TabPanel.Add_VisibleChanged({
        if ($TabPanel.Visible) { & $refreshTail }
    }.GetNewClosure())

    ## ========== ASSEMBLE ==========
    ## ========== ASSEMBLE (Dock: header / fill) ==========
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock      = 'Top'
    $header.Height    = 154
    $header.BackColor = [System.Drawing.Color]::Transparent
    $header.Controls.AddRange(@($lblTitle, $lblSub, $lblPath, $btnRefresh, $btnOpen))

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock      = 'Fill'
    $body.Padding   = New-Object System.Windows.Forms.Padding(20, 0, 20, 16)
    $body.BackColor = [System.Drawing.Color]::Transparent
    $body.Controls.Add($tb)

    $TabPanel.Controls.Add($body)    # Dock=Fill — added first
    $TabPanel.Controls.Add($header)  # Dock=Top
}

###################
## STATIC INFO TEXT ##
###################
## Backing text for the Start-tab "Change Log" and "How To Use" popups.
## Kept at script scope so the dialog can read them without parameter
## plumbing. Edit these here when a new release ships.

function global:Get-NemChangeLogText { return @"
v1.9.4 - 2026-05-07 - Bug-hunt sweep (post-review).

         Code-reviewer found two more silent-fail bugs in the same
         closure-scope class fixed in 1.9.2, plus five smaller items.
         All addressed.

         Silent-fail fixes:
           * SessionEnd terminator now writes correctly. Previous
             versions had a ``$script:Nemesis.Config.LogFile``
             reference inside the FormClosing closure; on
             closure-resolution miss the whole try/catch swallowed
             a NullReference and the per-session .log got no
             closing line. Lead reading the share later saw an
             unclear session ending.
           * btnStart "logs unavailable" MessageBox now shows the
             actual share path. New ``Get-NemLogShare`` global getter.

         UX / latent fixes:
           * Closing-notes dialog drops its title-bar X — operators
             who clicked it were silently cancelling the close.
             Three explicit buttons remain.
           * Closing-in-flight gate latched earlier (before the
             modal dialog) so any future message-loop pumping
             can't re-enter the handler.
           * Dropped the dead ``*.Preflight`` arm of the
             TouchedHosts CSV fan-out filter (no callsite used it).
           * Comment block above each IsPackage Verify
             rehydration warning that the scriptblock body must
             be self-contained (no `$using:, `$script:, `$global:,
             no captured locals — we ``[scriptblock]::Create()``
             it on the remote).
           * Documented (but not yet fixed) the IsPackage
             Cancel-during-Copy stage-dir leak risk. Narrow
             window, OS-cleanup path, accepted.

v1.9.2 - 2026-05-07 - Hotfix: Close Tool buttons actually close the tool.

         Root cause of the 1.9.1 "Close Tool button doesn't work, but
         X works" symptom: both button click handlers were calling
         `$script:Nemesis.UI.Form.Close() directly from inside their
         click closures. PS 5.1 + StrictMode 3 + .GetNewClosure() do
         not resolve `$script: variables reliably from closure
         context. The Set-NemAllowClose flag landed (it's a global
         function) but Form.Close() silently failed, so the form
         stayed open with NemAllowClose=`$true left over. Next X
         click slipped through the X-block on the stale flag and
         showed the popup.

         New helper: global:Invoke-NemCloseFlow. Both Close Tool
         buttons call it; zero `$script: access from either click
         closure. The X-block now actually engages on title-bar X /
         Alt-F4 / right-click-title-Close.

v1.9.1 - 2026-05-07 - Close Tool button (top-right) + X-block + log-submit dialog.

         Three changes to the close flow:
           1. New "Close Tool" button at the top-right of the content
              header (alongside the live indicator). Pairs with the
              existing sidebar twin — both go through the same
              closing-notes / submit-logs flow.
           2. The title-bar X / Alt-F4 / right-click-title-Close are
              now inert. Only the explicit Close Tool buttons can
              actually exit the tool. OS-driven shutdown
              (TaskManager, Windows shutdown) still passes through.
           3. Closing-notes dialog now lists every artifact that
              gets submitted on close: today's Runs CSV, the
              per-session .log, the TouchedHosts CSV, and the JANET
              centralized rollup. Buttons renamed: "Submit Logs +
              Close" / "Submit (skip notes)" / "Cancel Close".
              Operator notes are still optional; Skip writes a
              SessionNotes row with empty notes so the close still
              gets logged.

         A new SessionEnd terminator line lands in the per-session
         .log at the very end of the close flow, listing the run
         counters and artifact paths so a lead reading the .log
         later sees a clean "session completed + submitted" marker.

v1.9.0 - 2026-05-07 - Tenable Nessus Agent profile (PSADT package deploy).

         New updater profile + match-table row for ACAS findings tagged
         "Tenable Nessus Agent" / "Nessus Agent" / "Tenable Nessus".
         Click Run on the rolled-up Nessus card and the tool:

           1. Validates Tools\Packages\NIPR_Tenable Nessus Agent_11.1.3\
              has Deploy-Application.ps1 on the operator side.
           2. Per-host: opens the same bounded PSSession the other
              profiles use, creates C:\Windows\Temp\janet-pkg-<guid>\
              on the target.
           3. Copies the entire package folder via Copy-Item -ToSession
              (uses the live PSSession — no separate C`$ admin-share
              mount, no second auth round-trip).
           4. Runs Deploy-Application.ps1 -DeployMode NonInteractive
              and parses PSADT exit codes:
                0 / 1641 / 3010 = Success
                60012           = Deferred (user clicked Defer in dialog)
                anything else   = Failed
           5. Best-effort post-install Verify in the same session
              (HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent registry,
              with Uninstall-key DisplayVersion fallback).
           6. Cleans up the remote stage dir whether deploy succeeded
              or not.

         Engine mirrors WPT's RemotePackageInstaller. The Verify-only
         (Verify button) path runs the registry probe directly, no
         deploy attempted.

         If the operator's J.A.N.E.T. copy doesn't have the package
         folder, the per-host result is "FAIL: Package source not
         resolved on controller" — no remote work, no half-run state.
         Drop NIPR_Tenable Nessus Agent_11.1.3\ into Tools\Packages\
         and re-run.

         Bulk Run honors the new profile too — heterogeneous batches
         with multiple IsPackage profiles work via a per-profile
         package-path map built operator-side before dispatch.

v1.8.12 - 2026-05-06 - Restore working X / Alt-F4 close.

         Operator report: "no close button — clicking X doesn't work
         nor do I see it." The FormClosing handler had an X-block
         that cancelled every close not initiated by the bottom
         sidebar "Close Tool" button. At certain DPI/window-size
         combos that button drifted out of view, leaving the operator
         stuck. The block was leftover defense from before v1.3.2
         restructured the closing-notes flow so the JANET rollup
         writes unconditionally on real close. Removed. X / Alt-F4 /
         right-click Close all flow through FormClosing now: notes
         dialog appears, Cancel keeps the form open, OK saves notes +
         writes the JANET rollup + closes. The Close Tool sidebar
         button stays as a secondary exit.

v1.8.11 - 2026-05-06 - Sister-CSV spam fix in JANET logging.

         Operator hit "WARNING: JANET schema rotation failed; routing
         rows to sister CSV: ...2026-05_usage.r<unix>.csv" once per
         audit row whenever the share's legacy CSV was locked. The
         redirect path was minting a fresh sister file per call (timestamp
         changes by the second), so dozens of near-empty sister CSVs piled
         up. Fix: scan for an existing matching sister and reuse silently;
         only create + warn when none exists.

v1.8.10 - 2026-05-06 - Apache Log4j profile: 2.25.3 -> 2.25.4.

         Updated `$newApi / `$newCore + Verify regex + Detail string in
         the 'Apache Log4j - Replace Vulnerable Jars' profile to use
         log4j-api-2.25.4.jar and log4j-core-2.25.4.jar.

         2.25.4 fixes plugins 306549 (XmlLayout, CVE-2026-34480) and
         306550 (SSL hostname bypass, CVE-2026-34477) on top of 282519
         (MitM, CVE-2025-68161). All three plugins now clear via
         Verify — previously 306549/306550 ran the swap fine but
         Verify said STILL-VULNERABLE because 2.25.3 < 2.25.4.

         Operators: stage log4j-api-2.25.4.jar + log4j-core-2.25.4.jar
         at the source share / Tools\Packages\Log4j\NewFiles\ before
         running.

v1.8.9 - 2026-05-06 - Hostname normalization at ACAS import.

         Tenable CSVs ship hosts in three forms — DOMAIN\HOST,
         host.fqdn.tld, IPv4. The DNS form was driving every WinRM
         connect, log line, and card. Two problems:
           1. Noisy UI — every host read "msekl-2701dz.area52
              .afnoapps.usaf.mil" instead of "msekl-2701dz".
           2. Correlated with Negotiate auth failures on hosts whose
              AD SPN registration didn't match the FQDN.

         New global helper Get-NemShortHost normalizes to short:
           "DOMAIN\HOST"     -> "HOST"
           "host.fqdn.tld"   -> "host"
           "10.0.0.5"        -> "10.0.0.5" (IPv4 untouched)
         Applied at import to DnsName and NetBios.

v1.8.8 - 2026-05-06 - UI freeze fix + Pop Out Log.

         Operator hit a hard freeze during a Log4j run — main window
         locked, couldn't scroll cards. Two fixes:

         1. Removed all serial preflight loops on the UI thread. The
            v1.8.4 TCP probe runs at 3s/port — N unreachable hosts =
            up to 6s × N seconds of frozen UI before anything
            dispatches. Each runspace scriptblock already has the same
            probe inline, so unreachable hosts now fail in parallel
            via the pool. Same FAIL message, just async through the
            drain timer instead of upfront.

         2. NEW "Pop Out Log" button on the Updater tab header. Lifts
            the embedded RichTextBox into a separate floating window
            (1100x700, resizable). Operator can scroll cards / switch
            tabs while watching the run. Single RTB instance — moved
            between parents, not duplicated — so every existing log
            write still works. Closing the window reparents the RTB
            back into the tab.

v1.8.4 - 2026-05-06 - TCP probe per-port timeout 1.5s -> 3s.

         Side-by-side run on the same fleet showed slow-but-reachable
         AFNET hosts being false-negatived at 1.5s/port while WPT (no
         pre-probe, long WSMan OpenTimeout) eventually got through.
         Bumped to 3s/port — worst-case dead-host wait still bounded
         at 6s, but slower responders now make it past preflight.
         Applied to Test-NemTcpReachable + all five inlined runspace
         probes (VulnRun, BulkRunAll, RebootVerify, KB MECM, KB Uso).

v1.8.3 - 2026-05-06 - NetBIOS auth fallback + server-prefix filter.

         Two fixes from an actual Run-All log:

         1. NetBIOS retry on Negotiate auth failures. Hosts whose
            Kerberos handshake fails with WSMan 0x80090322
            (SEC_E_WRONG_PRINCIPAL), "Negotiate authentication", or
            "Access is denied" get a one-shot retry using the NetBIOS
            short name. NetBIOS forces NTLM — different SPN
            requirements than Kerberos, usually clears the case where
            target SPN registration / DNS reverse lookup is broken.
            Applied to VulnRun, BulkRunAll, RebootVerify, and both KB
            Installer scriptblocks (5 PSSession open sites total).

         2. Server-prefix filter on ACAS import. New global helper
            ``Test-NemIsServer`` flags any hostname matching ^msek- (note:
            hyphen immediately after "msek", distinct from msekl- /
            msekt- / msekw- workstations). The Targets-tab "Import
            ACAS" handler now drops both server-tagged rows (from
            ``AcasFindings``) and server-tagged hostnames (from the
            unique-host list). Skipped counts appear in the ImportACAS
            audit detail as ``servers_skipped=<hosts>/<rows>``. Server
            patching belongs in a different change window — this tool
            only drives end-user endpoint remediation.

v1.8.2 - 2026-05-05 - Apache Log4j updater profile (WPT 6.4.2 port).

         Log4j was previously classified as "Unpatchable" (manual
         remediation only). Now it has a real updater profile that
         ports the WPT 6.4.2 jar-swap logic — same logic as the
         standalone Log4J_Plugin_282519 v2.ps1 script but driven
         from the Updater tab card flow.

         Profile: 'Apache Log4j - Replace Vulnerable Jars'.
           Source share: \\dm-tn-01\sh-usafe-automation`$\JANET\Packages\Log4j\NewFiles
           Drops in: log4j-api-2.25.4.jar + log4j-core-2.25.4.jar
           Targets:  C:\Program Files\HID Global\Credential Management Client\lib
                     C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs
           Per path: stop bundled service, backup old jars to
                     Backup_<ts>\, swap, restart service. Service
                     restart runs in finally{} so we never leave a
                     half-stopped service even if the swap fails.
           Verify:   enumerates log4j-*.jar in both target paths and
                     reports STILL-VULNERABLE for any non-2.25.3 names.

         Card grouping: every plugin name containing "Apache Log4j"
         (or just "Log4j") matches this profile, so plugins 282519
         (MitM), 306549 (XmlLayout), 306550 (SSL Hostname) all roll up
         onto ONE card. Plugins requiring 2.25.4+ run the same swap
         but Verify will flag them STILL-VULNERABLE — bump the share
         jars + the profile constants when 2.25.4 is staged.

         Also: 'Log4j' removed from the Unpatchable pattern list.

v1.8.1 - 2026-05-04 - Renamed tab "How To" -> "Backbone".

         Same content, same nav position (08, below Logs), better
         name. The Start-tab "How To Use" dialog button is a
         separate UI element and is unchanged.

v1.8.0 - 2026-05-04 - New "How To" tab below Logs.

         Position 08 in the side nav. Scrollable, copyable, Ctrl+F
         findable. Two sections:
           1. Per-profile mechanism reference. Auto-generated from
              the live updater-profile registry. Each profile gets:
              Summary, Mechanism (what it actually invokes on the
              host), When to use it, and where Verify looks.
           2. The full operator workflow walkthrough — same content
              the Start-tab "How To Use" dialog has been showing.

         The Start-tab "How To Use" dialog still works and still
         shows the workflow walkthrough only. The new tab is the
         richer single-source reference; the dialog stays for
         backward-compat with operators who already use it.

         New profiles added to `$script:WptAppUpdateProfiles surface
         in the tab automatically on next visit (Refresh Content
         button forces a rebuild). Hand-written mechanism notes
         for each profile live in Get-NemUpdaterMechanismsText —
         add an entry there when you onboard a new profile so it
         shows full detail instead of the stub note.

v1.7.0 - 2026-05-04 - Per-operator TouchedHosts CSV.

         Every audit event that touches a remote box (Run target,
         Verify target, Preflight unreachable, Reboot target, Bulk
         target, KB install target) now also writes a structured row
         to a per-operator monthly CSV:

           \\dm-tn-01\sh-usafe-automation`$\JANET\Logs\ACAS_Nemesis\
             <edipi> - <DisplayName>\
               TouchedHosts_<YYYY-MM>.csv

         Schema: Timestamp, Operator, Edipi, SessionId, SourceHost,
                 Action, TargetHost, Result, Detail.

         A lead overseeing multiple teams can pivot this CSV to
         answer "which hosts did operator X touch this month, what
         action, and did it succeed" in one Excel pass — no grep
         across daily session .log files. The session .log stays as
         the narrative transcript for incident reconstruction.

         No call-site changes — Write-NemAudit auto-detects per-host
         actions (.Target / .Preflight suffix) and fans out. Falls
         back to local workspace if share is unreachable, same as
         the existing audit log path.

v1.6.2 - 2026-05-04 - Side-nav reorder.

         Vulnerabilities moved from position 03 to position 06 — sits
         directly above Logs now. The Targets -> Updater workflow is
         the primary path; the raw findings grid is a secondary lookup
         next to Logs. Pairs well with 1.6.1 (on-demand Load Findings)
         since operators no longer accidentally click into the heavy
         tab on the way from Targets to Updater.

v1.6.1 - 2026-05-04 - Vulnerabilities tab on-demand load (crash fix).

         The Vulnerabilities tab was crashing the WinForms host every
         time you clicked it against a 400+ row CSV — populating the
         DataGridView row-by-row on tab activation triggered a paint
         storm + reentrancy that took the whole app down.

         Fix: tab now opens with an empty grid hidden under a centered
         "Load Findings" overlay button. Click once to populate. A new
         "Reload Findings" button in the toolbar picks up fresh imports
         after the initial load without re-hiding the grid. The grid
         population now happens inside a hidden control so the same
         400+ row write cannot trigger the original crash.

v1.6.0 - 2026-05-04 - Software Center updater profiles.

         Three new entries in the updater-profile registry, one each
         for Chrome / Edge / Microsoft 365. Each finds the matching
         CCM_Application via the SCCM client SDK and triggers Install —
         the same engine WPT uses in its bulk-patch path, lifted into
         a named profile so each per-card dropdown can pick EXE-direct
         vs Software Center per Run.

         What you'll see:
         * Chrome and Edge cards now show a 2-entry profile dropdown
           (default = EXE-direct, alt = Software Center). Same as M365
           already had — M365 dropdown grew from 3 -> 4 entries.
         * If the SCCM client is missing or has no matching catalog
           entry, the per-host log shows 'FAIL' or 'SKIP' with a clear
           reason — no silent failures.
         * Edge name-match excludes the noise variants (Edge Update,
           WebView2, Helper, Beta/Dev/Canary). M365 name-match excludes
           per-app sidecars (Skype, Teams, OneDrive, Visio, etc.).

         When to pick Software Center over EXE-direct:
         * The product's own updater (GoogleUpdate.exe / EdgeUpdate.exe
           / OfficeC2RClient.exe) is wedged or absent on the host image.
         * You want SCCM to honor the deployment ring instead of
           forcing the latest available version immediately.

v1.5.0 - 2026-05-04 - Updater card grouping by profile.

         Same-profile vulns now collapse into a single ROLLUP card. A
         typical weekly scan with 18 Chrome / 72 Office / 2 Defender
         per-vuln cards becomes 3 ROLLUP cards. Bulk Run dispatch
         count drops proportionally; host-union dedupes overlap so each
         host gets the updater pushed once per group.

         What you'll see:
         * ROLLUP xN badge (Accent2 colour) in the card title row when
           N vulns share an updater profile. Hover the badge or the
           title to see the member Plugin Names.
         * Reboot / Unpatchable / NotUpdatable cards never group — they
           still render one card per vuln.
         * Per-vuln cards still appear for any vuln whose profile-set
           is unique (singletons don't roll up).

         Audit / Runs CSV:
         * One ROLLUP card Run still writes one CSV row per member vuln
           (per-CVE reporting unchanged) — Scope is the member Plugin
           Name, with new GroupKey / GroupSize columns flagging the
           rollup.
         * GroupKey / GroupSize are NEW trailing columns on the daily
           Runs CSV. The first day's CSV after upgrade gets archived as
           ".pre-schema-change.csv" so the new-schema rows start clean.
         * Bulk Run still writes one batch-summary row, tagged
           GroupKey='<bulk>'. Use the per-card Run for member-level
           per-vuln rollup.

v1.4.1 - 2026-05-04 - Hotfix on top of 1.4.0.

         * Add-NemVulnCard: ``$card.Tag`` was assigned BEFORE ``$btnVerify``
           was created (introduced in 1.4.0 alongside the VerifyButton
           field added for Start-NemBulkRunAll). Under StrictMode 3 this
           threw "the variable '`$btnVerify' cannot be retrieved because
           it has not been set" on every Refresh Cards / Bulk Run click
           on the Updater tab. Reordered: ``$btnVerify`` is created first,
           ``$card.Tag`` is assigned second.
         * Bumped ``$JanetACAS_NemesisVersion`` 1.3.4 -> 1.4.1. The 1.4.0
           file rename did not bump this constant, so the title bar /
           audit log / Start-tab version label all displayed v1.3.4
           while filename + JANET centralized CSV reported 1.4.0.
           All version strings now agree on 1.4.1.

v1.4.0 - 2026-05-04 - WPT-ported reliability + bulk parallel runs.

         Most updates were failing on AFNET because of two compounding
         issues: (1) ICMP-based reachability was producing false negatives
         on hosts that block ping but accept WinRM, and (2) every remote
         call used `Invoke-Command -ComputerName` with the default ~3min
         OpenTimeout and no auth scheme override, so a single dead host
         could stall the runspace pool. WPT 6.2.6 fixed both — this
         release ports the same patterns across.

         Reliability changes (mirror WPT):
         * NEW Test-NemTcpReachable - TCP probe on 5985 (WinRM) then 445
           (SMB), 1.5s per port. Replaces Test-Connection ICMP at every
           preflight site.
         * NEW New-NemSessionOption - bounded PSSessionOption
           (OpenTimeout 15s / OperationTimeout 180s / IdleTimeout 60s).
         * NEW Invoke-NemRemote - one-shot helper for non-runspace
           callers: TCP probe + bounded PSSession + Negotiate auth.
         * Start-NemVulnRun: scriptblock now opens a bounded PSSession
           (Negotiate auth) per target instead of a one-shot
           Invoke-Command. Verify-only and full Update share the same
           session.
         * Start-NemRebootVerify: 10-minute reachability poll switched
           from ICMP to TCP. Bounded PSSession on the post-reboot probe
           prevents the 3-minute hang on machines whose WSMan service
           hasn't fully started yet.
         * KB Installer (MECM): unified MECM trigger + MSU fallback
           under ONE bounded PSSession, halving the WinRM handshake.
         * KB Installer (UsoClient): bounded PSSession.
         * Invoke-NemUpdateRun delegates to Invoke-NemRemote.

         Bulk parallel runs (NEW):
         * NEW Start-NemBulkRunAll + "Bulk Run (Parallel)" button on
           the Updater tab header. Walks every patchable card, collects
           (host, profile) tuples (honors per-card profile dropdown),
           and submits ALL jobs into the runspace pool simultaneously.
         * Distinct from existing Run All Updates (sequential card
           walk). Both buttons share the same Cancel handler and
           single-run lock. Reboot cards are excluded from bulk dispatch
           (those need the explicit warning dialog).
         * Drain timer aggregates results with [VulnDisplay] prefixes,
           audit prefixes BulkRun.* / BulkVerify.*. JANET centralized
           VulnPatched logging fires per-host as in per-card runs.

v1.2.0 - Ship-time hardening + critical bug fix.

         CRITICAL: fixed a WinRM scriptblock-serialization bug that
         made every Office / Chrome / Edge / Defender Updater card
         fail with "The term '`$c2r = ...' is not recognized as the
         name of a cmdlet". Scriptblocks passed through -ArgumentList
         don't survive WinRM serialization — they arrive remotely as
         plain strings. Fix: pass scriptblock source text explicitly
         and rehydrate via [scriptblock]::Create() on the remote side.

         Share-access resilience: the tool now starts + logs locally
         when the shared log path is unreachable or ACL-denied.
         Resolve-NemLogDir replaces Test-Path with an actual
         sentinel-file write probe. Open-NemAuditLog never throws —
         it tries the configured LogDir, then the local workspace,
         then silently gives up (session still starts). A soft
         popup at session-start explains fallback state.
         Write-NemRunCsvLine also fails over to local mid-session
         if the share drops and flips Config.LogDir so subsequent
         rows go local without re-hitting the dead share.

         Start tab share line now reflects the LIVE Config.LogDir
         (not the stale startup-time resolution), so mid-session
         failover is visible without a relaunch.

v1.1.0 - Per-vulnerability Updater refactor. Targets tab is now ACAS-only
         (no paste). New Vulnerabilities tab owns the findings grid.
         Updater tab split in two: cards with matched profiles stay on
         Updater, non-updatable findings move to the new Not Updatable
         tab. Each updatable card picks its own profile via dropdown when
         multiple variants exist (M365 Force vs M365 User-Visible).
         Added a per-card Verify button that runs only the profile's
         Verify scriptblock to re-check remote versions after Chrome /
         Edge / Office async updates land.

         KB Installer gained an install-method dropdown:
           - MECM (CIM targeted) [default] — SIM_Tool pattern, per-host
             CCM_SoftwareUpdate match + CCM_SoftwareUpdatesManager
             InstallUpdates, over WinRM-CIM (no DCOM).
           - UsoClient Trigger — fallback nudge for non-MECM targets.
         Also added an optional MSU file path + Browse button — KBs
         that MECM's catalog does not have fall back to wusa.exe on the
         target (copied over a PSSession), with exit codes 0 / 3010 /
         2359302 mapped to Installed / Installed-reboot / Already.
         New "Suppress auto-reboot" checkbox flips the Windows Update
         AU registry keys on each target before the install fires, and
         appends /norestart to wusa when the MSU path is used.
         Fixed a pre-existing bug where UsoClient Trigger ran locally
         on the operator's workstation instead of the target host.

         Credentials: every remote Invoke-Command and PSSession in the
         Updater + KB Installer now forwards the operator-set
         PSCredential from the Start tab. Falls back to ambient
         Kerberos when no credential has been stored, so admin shells
         keep working without having to set credentials.

         Telemetry: every Run, Verify, and KB Install appends one row to
         a daily CSV on the log share:
           \\msek-fs-01v\Apps\10. Patching\#_Remote Patching Scripts\
               #_Logs\ACAS-Nemesis-Runs_YYYY-MM-DD.csv
         Closing the tool now prompts for operator notes; submit or
         skip appends a SessionNotes row with per-session counters.
         Operator identity matches SIM_Tool: AD displayName + EDIPI,
         per-operator transcript subfolder "<edipi> - <DisplayName>".
         CSV writer auto-detects schema changes — if an older-schema
         file exists for today, it's archived with a
         .pre-schema-change.csv suffix and a fresh file is started.

         Cosmetics: section headers reboxed. Start tab gained Change
         Log + How To Use buttons.

v1.0.4 - Smart Dispatch (Auto) mode for Updater: match findings to
         profiles and run only what each host needs.

v1.0.3 - KB Installer v1 (UsoClient StartInstall trigger).

v1.0.2 - Pre-flight reachability ping; runspace pool drain timer
         hardening.

v1.0.1 - Cancel button + timer / job disposal cleanup.

v1.0.0 - Initial release. Updater tab with Office / Chrome / Edge /
         Defender profiles + Custom Command. Panel shell ported from
         WPT, ACAS CSV parser ported from WPT AcasImport.
"@
}

function global:Get-NemUpdaterMechanismsText {
    <#
    .SYNOPSIS
        Per-profile mechanism narrative for the How To tab.
    .DESCRIPTION
        For each entry in $script:WptAppUpdateProfiles, prints:
          * Name + Desc (one-liner from the registry)
          * What the Script scriptblock actually invokes (hand-written
            mechanism note, kept in sync below when profiles change)
          * Where the Verify scriptblock looks for the version
          * When to pick this profile vs the alternative(s)
        Auto-walks the registry so newly-added profiles surface in the
        tab. Profiles not in the hand-written notes table fall back to
        their Desc plus a generic "see source for mechanism" line.
    #>
    [CmdletBinding()]
    param()

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('PER-PROFILE MECHANISM REFERENCE')
    [void]$sb.AppendLine('===============================')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Each Updater card has a profile dropdown. This section explains what')
    [void]$sb.AppendLine('every profile actually does on the target host, where the Verify button')
    [void]$sb.AppendLine('looks for confirmation, and which one to pick when you have a choice.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Defaults: the EXE-direct profile (GoogleUpdate / EdgeUpdate /')
    [void]$sb.AppendLine('OfficeC2RClient) is selected by default everywhere it exists. Software')
    [void]$sb.AppendLine('Center is the alternative — pick it when the EXE-direct path is')
    [void]$sb.AppendLine('broken / absent on the host image, or when you want SCCM to honor the')
    [void]$sb.AppendLine('deployment ring instead of forcing the latest available version.')
    [void]$sb.AppendLine('')

    ## Hand-written mechanism + when-to-pick notes per profile name. New
    ## profiles added to the registry without an entry here still print
    ## their Desc — the missing-notes fallback marks them so we know to
    ## fill in the mechanism details.
    $notes = @{
        'Microsoft 365 - Force Update' = @{
            Mechanism = "OfficeC2RClient.exe /update user /displaylevel=false /forceappshutdown=true. Open Office apps close mid-edit. Update runs silently."
            WhenToUse = "Off-hours / known-empty-user-session pushes. Fast, no user prompt."
            Verify    = "Reads HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration VersionToReport. Verified=true if the registry key was modified within the last 7 days."
        }
        'Microsoft 365 - Update (User Visible)' = @{
            Mechanism = "OfficeC2RClient.exe /update user — same exe but no /displaylevel override and no /forceappshutdown. User sees the C2R progress dialog."
            WhenToUse = "When you want the user to see the update happen, or you can't risk closing their open Office apps mid-edit."
            Verify    = "Same registry probe as Force Update."
        }
        'Microsoft 365 - Force Update (SYSTEM task)' = @{
            Mechanism = "Registers a temporary scheduled task that runs OfficeC2RClient.exe as SYSTEM with /forceappshutdown=true. Polls task State up to 10 minutes. Cleans up the task regardless of outcome."
            WhenToUse = "Fallback when operator-context runs fail — typically open user sessions causing Kerberos delegation issues. SYSTEM context bypasses user delegation."
            Verify    = "Same registry probe as Force Update. Detail field also notes 'SYSTEM-task variant'."
        }
        'Microsoft 365 - Software Center' = @{
            Mechanism = "Queries the target's CCM_Application catalog (ROOT\ccm\ClientSDK), filters to *Microsoft 365 Apps* / *Office 365 ProPlus* / *Microsoft Office Pro* / *M365 Apps* (excluding Skype/Teams/OneDrive/Visio/Project/Language Pack/Proofing/etc), picks the most-applicable + machine-targeted candidate, calls CCM_Application.Install via Invoke-CimMethod."
            WhenToUse = "When OfficeC2RClient.exe is wedged or absent on the host image, or when you want SCCM to honor the deployment ring."
            Verify    = "Same Office C2R registry probe — install location is mechanism-agnostic. Detail field marks 'via Software Center'."
        }
        'Google Chrome - Update' = @{
            Mechanism = "GoogleUpdate.exe /ua /installsource scheduler from C:\Program Files (x86)\Google\Update\ (or Program Files\Google\Update\). Update runs in the background asynchronously."
            WhenToUse = "Default for Chrome. Most reliable on AFNET workstations with the standard Chrome image."
            Verify    = "Reads HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-...} pv value. Verified=true if registry was modified within the last 14 days. Async update may not show a version bump on the first Verify — wait a few minutes and re-check."
        }
        'Google Chrome - Software Center' = @{
            Mechanism = "Queries CCM_Application for *Google Chrome* (excluding *Update*/*Helper*/*Sync*), picks the most-applicable + machine-targeted candidate, calls CCM_Application.Install."
            WhenToUse = "When GoogleUpdate.exe is missing or broken (some imaged variants strip it), or when you want SCCM-controlled rollout."
            Verify    = "Same Chrome registry probe. Detail field marks 'via Software Center'."
        }
        'Microsoft Edge - Update' = @{
            Mechanism = "MicrosoftEdgeUpdate.exe /ua /installsource scheduler from C:\Program Files (x86)\Microsoft\EdgeUpdate\. Update runs in the background asynchronously."
            WhenToUse = "Default for Edge. Most reliable on standard Edge installs."
            Verify    = "Reads HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-...} pv value. Verified=true if registry was modified within the last 14 days."
        }
        'Microsoft Edge - Software Center' = @{
            Mechanism = "Queries CCM_Application for *Microsoft Edge* (excluding *Update*/*WebView*/*Helper*/*Beta*/*Dev*/*Canary*), picks the most-applicable + machine-targeted candidate, calls CCM_Application.Install."
            WhenToUse = "When MicrosoftEdgeUpdate.exe is missing or broken, or when you want SCCM-controlled rollout."
            Verify    = "Same Edge registry probe. Detail field marks 'via Software Center'."
        }
        'Windows Defender - Update Definitions' = @{
            Mechanism = "Update-MpSignature cmdlet remotely. Defender pulls latest signatures from whatever source it's configured for (WSUS / MECM / Microsoft Update fallback)."
            WhenToUse = "Always — there's no alternative profile. Quick, deterministic."
            Verify    = "Get-MpComputerStatus AntivirusSignatureVersion + AntivirusSignatureLastUpdated. Verified=true if updated within the last 24 hours."
        }
        'Microsoft Store - Update Apps' = @{
            Mechanism = "Calls MDM_EnterpriseModernAppManagement_AppManagement01.UpdateScanMethod via CIM. Triggers a Microsoft Store update scan on the target."
            WhenToUse = "EXPERIMENTAL. Specifically targets the Windows App (Remote Desktop) and other MS-Store apps. Verify on a test host before pushing fleet-wide."
            Verify    = "Get-AppxPackage -Name 'Microsoft.WindowsApp*'. Reports the installed package version + InstallLocation last-modified date."
        }
        'Tenable Nessus Agent - Package Deploy' = @{
            Mechanism = "PSADT package-deploy. Operator-side: resolves Tools\Packages\NIPR_Tenable Nessus Agent_11.1.3\, validates Deploy-Application.ps1 exists. Per-host: opens PSSession, creates C:\Windows\Temp\janet-pkg-<guid>\ on the target, copies the entire package folder via Copy-Item -ToSession (uses the live PSSession — no separate C`$ admin-share mount), unblocks the .ps1 files, runs Deploy-Application.ps1 -DeployMode NonInteractive. Parses PSADT exit codes: 0/1641/3010 = Success (3010 = reboot required, 1641 = reboot initiated), 60012 = User Deferred (returns SKIP), anything else = FAIL. Cleans up the remote stage dir whether the deploy succeeded or not."
            WhenToUse = "Default for any 'Tenable Nessus Agent < X.Y.Z' / 'Nessus Agent RCE' style ACAS finding. Only profile in the Nessus Agent dropdown — no SCCM alternative wired today (the package is the source of truth)."
            Verify    = "Reads HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent (Version / nessus_agent_ver), falls back to the Uninstall key DisplayVersion when the Tenable key is absent. Verified=true if any version was discovered; Detail records which source matched."
        }
    }

    $profileNames = @($script:WptAppUpdateProfiles.Keys | Sort-Object)
    foreach ($name in $profileNames) {
        $prof = $script:WptAppUpdateProfiles[$name]
        $desc = if ($prof.PSObject.Properties['Desc'] -or $prof.ContainsKey('Desc')) { [string]$prof.Desc } else { '' }
        if ([string]::IsNullOrWhiteSpace($desc)) { $desc = '(no description in registry)' }

        [void]$sb.AppendLine($name)
        [void]$sb.AppendLine(('-' * $name.Length))
        [void]$sb.AppendLine("  Summary    : $desc")

        if ($notes.ContainsKey($name)) {
            $n = $notes[$name]
            [void]$sb.AppendLine("  Mechanism  : $($n.Mechanism)")
            [void]$sb.AppendLine("  When to use: $($n.WhenToUse)")
            [void]$sb.AppendLine("  Verify     : $($n.Verify)")
        } else {
            [void]$sb.AppendLine("  Mechanism  : (no detailed notes — see scriptblock in `$script:WptAppUpdateProfiles)")
            [void]$sb.AppendLine("  Verify     : (see scriptblock in `$script:WptAppUpdateProfiles)")
        }
        [void]$sb.AppendLine('')
    }

    return $sb.ToString().TrimEnd()
}

function global:Get-NemOverviewText {
    <#
    .SYNOPSIS
        Combined narrative for the How To tab.
    .DESCRIPTION
        Concatenates the per-profile mechanism reference (built fresh each
        call from the live $script:WptAppUpdateProfiles registry) with the
        existing operator-workflow walkthrough (Get-NemHowToUseText). The
        Start-tab "How To Use" dialog button continues to show only the
        workflow walkthrough — the tab is the richer, single-source
        reference.
    #>
    [CmdletBinding()]
    param()

    $mech = ''
    try { $mech = Get-NemUpdaterMechanismsText } catch { $mech = '(mechanism reference unavailable)' }
    $how = ''
    try { $how = Get-NemHowToUseText } catch { $how = '(workflow walkthrough unavailable)' }

    $sep = "`r`n`r`n" + ('=' * 72) + "`r`n`r`n"
    return $mech + $sep + $how
}

function global:Get-NemHowToUseText { return @"
QUICK START
-----------
1. START tab
   - Set credentials (or inherit from J.A.N.E.T. launcher).
   - Check the "I acknowledge responsibility" box.
   - Click "Start Session". This assigns a Session ID, opens the
     transcript .log in the per-operator subfolder on the log share,
     and unlocks the other tabs.

2. TARGETS tab
   - Click "Import ACAS" and select the CSV export from ACAS / Nessus.
     Multi-select is supported. Hosts parse from DNS / NetBIOS / IP in
     that priority.
   - The target list fills automatically. Findings are also loaded
     behind the scenes for the Vulnerabilities tab.
   - "Clear All" wipes both targets and findings.

3. VULNERABILITIES tab
   - One row per (host, plugin, CVE) triple. Check / uncheck rows to
     include or exclude them from Updater and KB Installer runs.
   - "Select All" / "Deselect All" / "Select Critical/High Only" act
     on the whole grid.
   - Deselected rows are filtered out of Updater card groupings and
     KB Installer parsing — this is your pre-dispatch gate.

4. UPDATER tab
   - Shows one card per vulnerability that maps to a known update
     profile (Microsoft 365, Chrome, Edge, Defender).
   - Profile dropdown appears when multiple variants exist (e.g.,
     M365 Force vs M365 User-Visible).
   - "Run on N host(s)" triggers the profile's update script against
     ONLY that vulnerability's affected hosts. There is NO all-hosts
     button by design.
   - "Verify" re-runs the profile's verify scriptblock (no update).
     Useful after Chrome / Edge / Office async updates have had time
     to complete — click Verify to confirm the version bumped.
   - Only one run at a time. Use Cancel Run to abort.

5. NOT UPDATABLE tab
   - Vulnerabilities with no matching profile. Info-only — no Run
     button. Expand the card list to see coverage gaps. Add a profile
     to Get-NemProfileMatchTable + $script:WptAppUpdateProfiles in the
     script to promote one to the Updater tab.

6. KB INSTALLER tab
   - Parses KB numbers from the Solution text of the selected ACAS
     findings (Vulnerabilities tab checkboxes still gate what you
     see here).
   - Use "Select Critical/High" for fast triage, then pick a Method
     below and click Run Install.

   WHAT EACH METHOD ACTUALLY DOES
   ------------------------------
   The tool never downloads anything from Microsoft. It either
   triggers MECM to install content MECM already has, or nudges
   Windows Update on the target, or pushes an MSU file you
   pre-downloaded yourself. Pick the method that matches your target
   environment.

   (A) "MECM (CIM targeted)" [default]
       1. Connects to the target over WinRM.
       2. Queries the target's own MECM client cache:
            Get-CimInstance ROOT\ccm\ClientSDK CCM_SoftwareUpdate
            -Filter 'ComplianceState = 0'
          This returns every update MECM has already deployed to
          that machine — same list the user would see in Software
          Center, already cached locally or on the MECM DP.
       3. Filters that list by the KB numbers from ACAS.
       4. Calls CCM_SoftwareUpdatesManager.InstallUpdates to tell
          the MECM client to install JUST those matched updates,
          right now.
       What you get: the same content Software Center would install
       if a user clicked Install, but driven remotely, in bulk,
       for only the KBs ACAS flagged. No new download, no bypass
       of MECM approval — if MECM hasn't deployed the KB to that
       machine, this method does nothing for that KB (logged as
       "no MECM catalog match") and moves on to the MSU fallback
       if one is configured.

   (B) "UsoClient Trigger" (non-MECM fallback)
       1. Connects to the target over WinRM.
       2. Runs UsoClient.exe StartInstall remotely.
       3. That kicks the target's Windows Update Agent, which
          installs whatever is pending from whatever source it is
          configured for (MECM / WSUS / Microsoft Update).
       Caveat: this is NOT KB-targeted. It installs everything
       pending for that machine. Use it only when the target isn't
       MECM-managed, or when you truly want "run whatever WU has
       queued."

   (C) MSU fallback (optional, MECM method only)
       Fills in the gap when ACAS flags a KB but MECM hasn't
       deployed it to that target.
       1. You download the .msu from catalog.update.microsoft.com
          to your own workstation.
       2. Point the "MSU file" textbox at it (or click Browse).
       3. For every KB that MECM didn't match on a given host, the
          tool:
            - opens a PSSession to the target
            - copies the MSU to C:\Temp on the target
            - runs wusa.exe "<path>" /quiet [/norestart]
            - parses the exit code:
                0 / 3010   = installed (3010 needs reboot)
                2359302    = already installed
                other      = failure
            - deletes the MSU and closes the session
       What you get: a direct install using the MSU you supplied.
       Bypasses MECM / WSUS entirely. Use when you cannot wait for
       MECM to deploy the KB.

   "Suppress auto-reboot" checkbox
       Applies to both methods. Flips the target's Windows Update
       AU registry keys (NoAutoRebootWithLoggedOnUsers=1,
       AlwaysAutoRebootAtScheduledTime=0) BEFORE the install runs,
       and appends /norestart to wusa.exe for the MSU path.

   ONE-SENTENCE VERSION
   --------------------
   "Read ACAS → find hosts that need KB X → tell each host's MECM
   client to install that specific KB now → fall back to a pre-
   downloaded MSU for hosts MECM doesn't have it for → log success
   / fail per host to the daily CSV."

7. LOGS tab
   - Shows the session transcript path and the log share path.
   - The share holds a per-operator subfolder named
     "<EDIPI> - <DisplayName>" with each session's .log file inside.
   - Daily CSV "ACAS-Nemesis-Runs_YYYY-MM-DD.csv" lives at the share
     root — one row per run, one SessionNotes row per close.

CLOSING THE TOOL
----------------
- When you close the main window, a notes dialog appears with the
  session summary (runs / successes / failures) and a free-text box.
  - "Submit + Close" appends your notes to today's Runs CSV.
  - "Skip (no notes)" still logs the session row with blank notes.
  - "Cancel Close" keeps the tool open.

TROUBLESHOOTING
---------------
- "Runspace pool is not open" — restart the session from the Start
  tab; pool is created on Start Session.
- "0 of N KB(s) matched MECM catalog" — the KB isn't in an MECM
  deployment for that host. Use UsoClient Trigger or a real MECM
  console.
- "All unreachable" — check WinRM (TCP 5985) on the target and your
  ambient credential.
- Log share unreachable — falls back to the local workspace at
  ACASNemesis\Logs next to the script.

REQUIRED ACCESS
---------------
- Admin rights on every target for remote Invoke-Command.
- WinRM (TCP 5985) reachable.
- Read+Write on the log share for CSV telemetry (tool still works
  without it; writes fall back to local and flag the failure).
"@
}

function global:Show-NemInfoDialog {
    <#
        Modal, themed, scrollable popup for long-form static text
        (Change Log / How To Use). Mirrors WPT's Show-WptInfoDialog
        pattern so both tools feel the same.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $BodyText
    )
    $s     = Get-NemState
    $theme = $s.UI.Theme
    $fonts = $s.UI.Fonts

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = $Title
    $dlg.ClientSize      = New-Object System.Drawing.Size(820, 620)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(640, 480)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.MaximizeBox     = $true
    $dlg.BackColor       = $theme.Background
    $dlg.ForeColor       = $theme.TextPrimary
    $dlg.Font            = $fonts.Body
    Set-WptDarkTitleBar -Form $dlg

    $lblHead = New-WptLabel -Text $Title -X 20 -Y 14 -W 780 -H 28 `
        -Font $fonts.DisplayLg -Fg $theme.Accent1

    $divider = New-Object System.Windows.Forms.Panel
    $divider.Location  = New-Object System.Drawing.Point(20, 46)
    $divider.Size      = New-Object System.Drawing.Size(780, 1)
    $divider.BackColor = $theme.Border
    $divider.Anchor    = 'Top,Left,Right'

    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location    = New-Object System.Drawing.Point(20, 56)
    $rtb.Size        = New-Object System.Drawing.Size(780, 510)
    $rtb.Anchor      = 'Top,Left,Right,Bottom'
    $rtb.BackColor   = $theme.Surface
    $rtb.ForeColor   = $theme.TextPrimary
    $rtb.Font        = $fonts.Mono
    $rtb.ReadOnly    = $true
    $rtb.ScrollBars  = 'Vertical'
    $rtb.WordWrap    = $true
    $rtb.BorderStyle = 'FixedSingle'
    $rtb.Text        = $BodyText

    $btnClose = New-WptButton -Text 'Close' -X 680 -Y 578 -W 120 -H 32 `
        -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.Body
    $btnClose.Anchor = 'Bottom,Right'
    $btnClose.Add_Click({ $dlg.Close() })

    $dlg.Controls.AddRange(@($lblHead, $divider, $rtb, $btnClose))
    $dlg.AcceptButton = $btnClose
    $dlg.CancelButton = $btnClose

    $parent = if ($s.UI.Form) { $s.UI.Form } else { $null }
    if ($parent) { [void]$dlg.ShowDialog($parent) } else { [void]$dlg.ShowDialog() }
}

###############
## MAIN FORM ##
###############
function global:Show-NemSessionGateDialog {
    [System.Windows.Forms.MessageBox]::Show(
        "Session not started.`r`n`r`nOpen the Start tab and click Start Session before using the other tabs.",
        'ACAS Nemesis Tool',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
}

function Show-NemMainForm {
    [CmdletBinding()]
    param()

    $theme = $script:Nemesis.UI.Theme
    $fonts = $script:Nemesis.UI.Fonts
    $cfg   = $script:Nemesis.Config

    ## ===== FORM =====
    $form = New-Object System.Windows.Forms.Form
    $form.Text               = "ACAS Nemesis Tool  v$($cfg.ToolVersion)"
    $form.ClientSize         = New-Object System.Drawing.Size(1440, 850)
    $form.MinimumSize        = New-Object System.Drawing.Size(1280, 760)
    $form.AutoScaleMode      = [System.Windows.Forms.AutoScaleMode]::Dpi
    $form.AutoScaleDimensions= New-Object System.Drawing.SizeF(96.0, 96.0)
    $form.StartPosition      = 'CenterScreen'
    $form.BackColor          = $theme.Background
    $form.ForeColor          = $theme.TextPrimary
    $form.Font               = $fonts.Body
    $form.FormBorderStyle    = 'Sizable'
    $form.MaximizeBox        = $true
    Enable-WptDoubleBuffer -Control $form

    $script:Nemesis.UI.Form = $form
    $form.Add_HandleCreated({ Set-WptDarkTitleBar -Form $form })
    $form.Add_Load({         Set-WptDarkTitleBar -Form $form })

    ## ===== STATUS STRIP (bottom) =====
    $statusBar = New-Object System.Windows.Forms.Panel
    $statusBar.Dock      = 'Bottom'
    $statusBar.Height    = 32
    $statusBar.BackColor = $theme.StatusBar

    $statusTopEdge = New-Object System.Windows.Forms.Panel
    $statusTopEdge.Dock = 'Top'; $statusTopEdge.Height = 1; $statusTopEdge.BackColor = $theme.Border
    $statusBar.Controls.Add($statusTopEdge)
    ## v1.10.0: scanline overlay + heartbeat pulse removed — purely decorative,
    ## never carried session signal. Cleaner read on the status row.

    $lblStatusSession = New-WptLabel -Text 'Session: idle' -X 14 -Y 8 -W 240 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $lblStatusSession.BackColor = [System.Drawing.Color]::Transparent
    $script:Nemesis.UI.Controls['statusSession'] = $lblStatusSession

    $lblStatusTargets = New-WptLabel -Text 'Targets: 0' -X 264 -Y 8 -W 180 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $lblStatusTargets.BackColor = [System.Drawing.Color]::Transparent
    $script:Nemesis.UI.Controls['statusTargets'] = $lblStatusTargets

    $lblStatusLog = New-WptLabel -Text '' -X 462 -Y 8 -W 800 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
    $lblStatusLog.BackColor = [System.Drawing.Color]::Transparent
    $lblStatusLog.TextAlign = 'MiddleRight'
    $lblStatusLog.Anchor    = 'Top,Left,Right'
    $script:Nemesis.UI.Controls['statusLog'] = $lblStatusLog

    $statusBar.Add_Resize({
        $lblStatusLog.Location = New-Object System.Drawing.Point(462, 8)
        $lblStatusLog.Size     = New-Object System.Drawing.Size(($statusBar.Width - 478), 18)
    }.GetNewClosure())
    $statusBar.Controls.AddRange(@($lblStatusSession, $lblStatusTargets, $lblStatusLog))

    ## ===== SIDEBAR =====
    ## v1.10.0: sidebar slimmed 252 -> 210px to match Reports' density.
    ## Brand block removed (J.A.N.E.T. wordmark + subtitle + version + pulse)
    ## — the new full-width top bar owns title chrome, no need to duplicate
    ## it inside the sidebar. Nav items start at top with a small breathing
    ## gap. Bottom user block stays (User / Status / Host) but the pulse
    ## indicator is gone — a plain colored dot stays for status legibility.
    $sidebar = New-Object System.Windows.Forms.Panel
    $sidebar.Dock = 'Left'; $sidebar.Width = 210; $sidebar.BackColor = $theme.Sidebar

    $sidebarEdge = New-Object System.Windows.Forms.Panel
    $sidebarEdge.Dock = 'Right'; $sidebarEdge.Width = 1; $sidebarEdge.BackColor = $theme.Border
    $sidebar.Controls.Add($sidebarEdge)

    ## Nav host (items added in Task 8)
    $navHost = New-Object System.Windows.Forms.Panel
    $navHost.Location  = New-Object System.Drawing.Point(0, 12)
    $navHost.Size      = New-Object System.Drawing.Size(209, 600)
    $navHost.BackColor = $theme.Sidebar
    $navHost.Anchor    = 'Top,Left,Bottom'
    $navHost.AutoScroll = $true
    $script:Nemesis.UI.Controls['navHost'] = $navHost

    ## User/session block. v1.9.4: sidebar Close Tool removed (was a
    ## duplicate of the top-right $btnTopClose in $contentTop) — single
    ## egress matches the WPT pattern. Height drops back to 92 since the
    ## button no longer occupies the bottom of the block.
    $userBlock = New-Object System.Windows.Forms.Panel
    $userBlock.Location = New-Object System.Drawing.Point(0, ($sidebar.ClientSize.Height - 92))
    $userBlock.Size     = New-Object System.Drawing.Size(209, 92)
    $userBlock.BackColor= $theme.Sidebar
    $userBlock.Anchor   = 'Bottom,Left,Right'
    $userBlock.Controls.Add((New-WptSeparator -X 16 -Y 0 -W 178 -Color $theme.Border))

    $lblOpName  = New-WptLabel -Text "User: $env:USERNAME"      -X 16 -Y 16 -W 180 -H 16 -Font $fonts.MonoSm   -Fg $theme.TextPrimary
    $lblOpTag   = New-WptLabel -Text 'Status:'                  -X 16 -Y 40 -W 54  -H 16 -Font $fonts.MonoSm   -Fg $theme.TextMuted
    ## v1.10.0: pulse indicator replaced with a static colored dot for
    ## a quieter sidebar. State labels still update via sidebarSessionLbl.
    $sideDot = New-Object System.Windows.Forms.Label
    $sideDot.Text      = [string]([char]0x25CF)
    $sideDot.Location  = New-Object System.Drawing.Point(72, 38)
    $sideDot.Size      = New-Object System.Drawing.Size(12, 18)
    $sideDot.Font      = $fonts.MonoSm
    $sideDot.ForeColor = $theme.TextMuted
    $sideDot.BackColor = [System.Drawing.Color]::Transparent
    $script:Nemesis.UI.Controls['sidebarPulse'] = $sideDot
    $lblOpState = New-WptLabel -Text 'idle'                     -X 86 -Y 40 -W 120 -H 16 -Font $fonts.MonoSm   -Fg $theme.TextMuted
    $script:Nemesis.UI.Controls['sidebarSessionLbl'] = $lblOpState
    $lblOpHost  = New-WptLabel -Text "Host: $env:COMPUTERNAME"  -X 16 -Y 64 -W 180 -H 16 -Font $fonts.MonoTiny -Fg $theme.TextFaint

    $userBlock.Controls.AddRange(@($lblOpName, $lblOpTag, $sideDot, $lblOpState, $lblOpHost))
    $sidebar.Controls.AddRange(@($navHost, $userBlock))

    ## ===== TOP BAR (full-width, matches Reports Tool chrome) =====
    ## v1.10.0: full-width 64px title bar with gold "J.A.N.E.T." mark +
    ## subtitle + a bottom 2px gold accent stripe. Replaces the in-sidebar
    ## brand block and the old $contentTop strip (which held a "live"
    ## heartbeat label and the Close Tool). Single visual identity for the
    ## tool, same chrome the Reports Tool uses.
    $topBar = New-Object System.Windows.Forms.Panel
    $topBar.Dock = 'Top'; $topBar.Height = 64; $topBar.BackColor = $theme.TitleBar

    $lblTopTitle = New-Object System.Windows.Forms.Label
    $lblTopTitle.Text      = 'J.A.N.E.T. ACAS Nemesis Tool'
    $lblTopTitle.Location  = New-Object System.Drawing.Point(20, 8)
    $lblTopTitle.AutoSize  = $true
    $lblTopTitle.Font      = $fonts.Title
    $lblTopTitle.ForeColor = $theme.Gold
    $lblTopTitle.BackColor = [System.Drawing.Color]::Transparent
    $topBar.Controls.Add($lblTopTitle)

    $lblTopSubtitle = New-Object System.Windows.Forms.Label
    $lblTopSubtitle.Text      = "Joint Administration and Network Execution Toolkit  -  v$($cfg.ToolVersion)"
    $lblTopSubtitle.Location  = New-Object System.Drawing.Point(20, 38)
    $lblTopSubtitle.AutoSize  = $true
    $lblTopSubtitle.Font      = $fonts.Body
    $lblTopSubtitle.ForeColor = $theme.TextSecondary
    $lblTopSubtitle.BackColor = [System.Drawing.Color]::Transparent
    $topBar.Controls.Add($lblTopSubtitle)

    ## v1.9.1 -> v1.10.0: prominent top-right "Close Tool" button.
    ## Single sanctioned form egress (FormClosing blocks the title-bar X /
    ## Alt-F4 unless NemAllowClose is latched). Same Invoke-NemCloseFlow
    ## click path as before — just lives in the new top bar instead of the
    ## now-removed $contentTop strip.
    $btnTopClose = New-WptButton -Text 'Close Tool' -X 0 -Y 18 -W 120 -H 28 `
        -Bg $theme.Danger -Fg $theme.TextOnAccent -Font $fonts.MonoSm
    $btnTopClose.Anchor = 'Top,Right'
    $btnTopClose.Add_Click({
        ## v1.9.2: closure-scope fix — route through global:Invoke-NemCloseFlow.
        Invoke-NemCloseFlow
    }.GetNewClosure())
    $script:Nemesis.UI.Controls['btnTopClose'] = $btnTopClose
    $topBar.Controls.Add($btnTopClose)

    $topBar.Add_Resize({
        $btnTopClose.Location = New-Object System.Drawing.Point(($topBar.ClientSize.Width - 140), 18)
    }.GetNewClosure())
    $btnTopClose.Location = New-Object System.Drawing.Point(($topBar.ClientSize.Width - 140), 18)

    ## Gold accent stripe at the bottom edge of the top bar.
    $topBarAccent = New-Object System.Windows.Forms.Panel
    $topBarAccent.Dock = 'Bottom'; $topBarAccent.Height = 2; $topBarAccent.BackColor = $theme.Gold
    $topBar.Controls.Add($topBarAccent)

    ## ===== CONTENT HOST =====
    $contentHost = New-Object System.Windows.Forms.Panel
    $contentHost.Dock = 'Fill'; $contentHost.BackColor = $theme.Background
    Enable-WptDoubleBuffer -Control $contentHost

    $tabHost = New-Object System.Windows.Forms.Panel
    $tabHost.Dock = 'Fill'; $tabHost.BackColor = $theme.Background
    Enable-WptDoubleBuffer -Control $tabHost
    ## v1.10.0: grid-paper Paint overlay removed for a plain background
    ## that matches the Reports Tool. Tabs themselves still own their
    ## decoration if any.

    $tc = New-Object System.Windows.Forms.Panel
    $tc.Dock = 'Fill'; $tc.BackColor = $theme.Background
    Enable-WptDoubleBuffer -Control $tc
    $tc.Font = $fonts.Body
    $tabHost.Controls.Add($tc)
    $script:Nemesis.UI.Controls['tabControl'] = $tc

    $contentHost.Controls.Add($tabHost)

    ## ===== ASSEMBLE =====
    ## Dock layout iterates controls in REVERSE z-order — the LAST-added
    ## docked sibling is laid out FIRST and claims its edge from the full
    ## client rect. So to get topBar + statusBar full-width across the top
    ## and bottom (with sidebar fitting BETWEEN them rather than over them,
    ## matching the Reports Tool layout), $topBar / $statusBar are added
    ## AFTER $sidebar. $contentHost (Fill) is added first → processed last
    ## → gets the inner rectangle that's left.
    $form.Controls.Add($contentHost)
    $form.Controls.Add($sidebar)
    $form.Controls.Add($topBar)
    $form.Controls.Add($statusBar)

    ## ===== NAV ITEMS =====
    ## v1.6.2: Vulnerabilities moved from position 03 to 06 — sits directly
    ## above Logs. The Updater workflow (Targets -> Updater) is the
    ## primary path; the raw findings grid is a secondary lookup view
    ## next to Logs. Also makes the on-demand Load Findings flow less
    ## surprising — operators won't accidentally click into the heavy
    ## tab on the way from Targets to Updater.
    $navSpec = @(
        @{ Key='Start';           Label='Start';           Icon=[char]0x2699 }   # gear
        @{ Key='Targets';         Label='Targets';         Icon=[char]0x25CE }   # bullseye
        @{ Key='Updater';         Label='Updater';         Icon=[char]0x21BB }   # update glyph
        @{ Key='NotUpdatable';    Label='Not Updatable';   Icon=[char]0x2717 }   # ballot X
        @{ Key='KBInstaller';     Label='KB Installer';    Icon=[char]0x26A1 }   # lightning / KB
        @{ Key='Vulnerabilities'; Label='Vulnerabilities'; Icon=[char]0x26A0 }   # warning triangle
        @{ Key='Logs';            Label='Logs';            Icon=[char]0x2630 }   # three-line menu
        @{ Key='Backbone';        Label='Backbone';        Icon=[char]0x2139 }   # info source (v1.8.0; renamed from "How To" in v1.8.1)
    )

    ## v1.10.0: nav-item width follows the slimmed sidebar (210 - 1 edge).
    $y = 4
    for ($i = 0; $i -lt $navSpec.Count; $i++) {
        $spec = $navSpec[$i]
        $ni = New-WptNavItem -Key $spec.Key -Label $spec.Label -Icon $spec.Icon -Index ($i + 1) -Y $y -W 209 -H 42
        $navHost.Controls.Add($ni)
        $script:Nemesis.UI.NavItems[$spec.Key] = $ni
        $y += 42
    }

    ## ===== TAB PANELS =====
    ## One Dock=Fill, Visible=$false child per nav item. Populated in
    ## Tasks 9-12. Panels are kept in $script:Nemesis.UI.Controls["tab.$Key"]
    ## so the tab-builder functions can find them by key.
    foreach ($spec in $navSpec) {
        $p = New-Object System.Windows.Forms.Panel
        $p.Dock = 'Fill'
        $p.BackColor = [System.Drawing.Color]::Transparent
        $p.Visible = $false
        $tc.Controls.Add($p)
        $script:Nemesis.UI.Controls["tab.$($spec.Key)"] = $p
    }

    Add-NemStartTab -TabPanel $script:Nemesis.UI.Controls['tab.Start']
    Add-NemTargetsTab -TabPanel $script:Nemesis.UI.Controls['tab.Targets']
    Add-NemVulnerabilitiesTab -TabPanel $script:Nemesis.UI.Controls['tab.Vulnerabilities']
    Add-NemUpdaterTab -TabPanel $script:Nemesis.UI.Controls['tab.Updater']
    Add-NemNotUpdatableTab -TabPanel $script:Nemesis.UI.Controls['tab.NotUpdatable']
    Add-NemKBInstallerTab -TabPanel $script:Nemesis.UI.Controls['tab.KBInstaller']
    Add-NemLogsTab -TabPanel $script:Nemesis.UI.Controls['tab.Logs']
    Add-NemBackboneTab -TabPanel $script:Nemesis.UI.Controls['tab.Backbone']

    ## ===== NAV WIRING =====
    $activate = {
        param($key)
        foreach ($spec in $navSpec) {
            $panel = $script:Nemesis.UI.Controls["tab.$($spec.Key)"]
            if ($panel) { $panel.Visible = ($spec.Key -eq $key) }
        }
        Set-WptNavItemActive -SidebarPanel $navHost -Key $key
    }

    foreach ($spec in $navSpec) {
        $key = $spec.Key
        $ni  = $script:Nemesis.UI.NavItems[$key]

        $handler = {
            param($sender, $e)
            try {
                $s = Get-NemState
                if ($key -ne 'Start' -and -not $s.Session['Started']) {
                    Show-NemSessionGateDialog
                    return
                }
                & $activate $key
            } catch {
                Write-NemAudit -Action 'NavClick' -Target $key -Result 'Failed' -Detail $_.Exception.Message
            }
        }.GetNewClosure()

        $ni.Add_Click($handler)
        foreach ($c in $ni.Controls) { $c.Add_Click($handler) }
    }

    & $activate 'Start'

    ## ===== CLEAN SHUTDOWN =====
    Set-NemClosingInFlight $false
    Set-NemAllowClose      $false
    $form.Add_FormClosing({
        param($sender, $e)
        if (Get-NemClosingInFlight) { return }

        ## v1.9.1: X-block restored at operator request. With the new
        ## prominent top-right "Close Tool" button (plus the existing
        ## sidebar twin), operators always have a findable exit at every
        ## DPI / window-size combo — so we can re-block the title-bar X /
        ## Alt-F4 / right-click-title-Close paths without leaving anyone
        ## stuck (which was the v1.8.12 regression that prompted removing
        ## this block).
        ##
        ## CloseReason filter: only block UserClosing. Console / TaskManager
        ## / WindowsShutdown / ApplicationExitCall reasons pass through so
        ## OS-driven shutdown still tears the form down cleanly.
        ## NemAllowClose: set $true by the top-right + sidebar Close Tool
        ## button click handlers BEFORE calling $form.Close(). Any other
        ## UserClosing source (X / Alt-F4 / system menu) leaves the flag
        ## $false and gets cancelled here.
        if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing -and -not (Get-NemAllowClose)) {
            $e.Cancel = $true
            try {
                Write-NemAudit -Action 'CloseAttempt.Blocked' -Result 'OK' `
                    -Detail "CloseReason=$($e.CloseReason); use the Close Tool button (top-right or sidebar)"
            } catch {}
            return
        }

        ## v1.9.3: latch the closing-in-flight gate BEFORE running the
        ## modal dialog rather than after. WinForms modal dialogs do
        ## not normally re-enter FormClosing, but any future code path
        ## that pumps the message loop during the dialog
        ## (Application.DoEvents, async toolkit, third-party hook,
        ## etc.) would re-enter and double-prompt. Set the flag now so
        ## the early `return` at the top of the handler short-circuits
        ## any reentry.
        Set-NemClosingInFlight $true

        ## Closing notes prompt — only meaningful once a session is started
        ## (LogDir known, SessionId assigned). Cancel aborts the close.
        ## StrictMode v3 requires hashtable indexer syntax (['Key']) rather
        ## than dot access.
        $sDlg = Get-NemState
        if ($sDlg.Session -and $sDlg.Session['Started']) {
            ## v1.3.2: structured so Stop-JanetSession ALWAYS runs when the form
            ## actually closes. Previously it was nested inside the try block
            ## that wrapped the dialog AND the ACAS-specific CSV write — so a
            ## throw from either path skipped the JANET rollup. Now: dialog +
            ## ACAS write are guarded; cancelled state is captured separately;
            ## the JANET stop runs after the gate.
            $cancelled = $false
            $notes     = ''
            try {
                $dlgResult = Show-NemClosingNotesDialog
                $cancelled = [bool]$dlgResult['Cancelled']
                if (-not $cancelled) {
                    $notes       = [string]$dlgResult['Notes']
                    $sessSuccess = if ($sDlg.Session.ContainsKey('Success')) { [int]$sDlg.Session['Success'] } else { 0 }
                    $sessFailed  = if ($sDlg.Session.ContainsKey('Failed'))  { [int]$sDlg.Session['Failed']  } else { 0 }
                    Write-NemRunCsvLine -RowType 'SessionNotes' -Action 'SessionEnd' `
                        -Scope      '' `
                        -Profile    '' `
                        -Mode       '' `
                        -HostsTotal 0 `
                        -Success    $sessSuccess `
                        -Failed     $sessFailed `
                        -Notes      $notes | Out-Null
                }
            } catch {
                Write-NemAudit -Action 'ClosingNotes' -Result 'Failed' -Detail $_.Exception.Message
                ## Dialog or ACAS-write failed. Form will still close (no
                ## $e.Cancel set), so we MUST still write the JANET rollup
                ## with whatever notes we managed to capture (default empty).
            }

            if ($cancelled) {
                $e.Cancel = $true
                ## v1.9.3: clear the closing-in-flight gate on Cancel.
                ## We latched it $true above (before the dialog) so a
                ## reentry during the modal couldn't double-prompt.
                ## Now that the operator picked "Cancel Close", the
                ## form stays open and a future close attempt has to
                ## go through the handler from the top — leaving the
                ## flag $true would short-circuit that.
                Set-NemClosingInFlight $false
                return    ## form stays open, session continues
            }

            ## JANET rollup — always writes when the form is actually closing.
            try { Stop-JanetSession -ClosingNotes $notes } catch {
                Write-NemAudit -Action 'JanetStop' -Result 'Failed' -Detail $_.Exception.Message
            }

            ## v1.9.1: explicit SessionEnd terminator so the per-session
            ## .log on the share has a clear closing line — useful for a
            ## lead reading the .log later to confirm "this session
            ## completed cleanly + all artifacts submitted." Lists the
            ## artifacts written this session for traceability.
            ## v1.9.3: read state through `$sDlg` (which `Get-NemState`
            ## already resolved at the top of the closure) instead of
            ## reaching for `$script:Nemesis.Config.*` from inside the
            ## closure body — direct `$script:` access from inside
            ## `.GetNewClosure()` under PS 5.1 + StrictMode 3 is
            ## unreliable (silently resolves to `$null` on some launch
            ## paths). The whole block is in a try/catch{} swallow so
            ## the failure was symptom-free: terminator silently
            ## skipped, lead reading the share later sees a session
            ## with no closing line. Same bug class we fixed in
            ## `Invoke-NemCloseFlow` for v1.9.2 — this was a survivor.
            try {
                $logPath = if ($sDlg -and $sDlg.Config -and $sDlg.Config.LogFile) { [string]$sDlg.Config.LogFile } else { '<no log>' }
                $logDir  = if ($sDlg -and $sDlg.Config -and $sDlg.Config.LogDir)  { [string]$sDlg.Config.LogDir }  else { '<no dir>' }
                $rc      = if ($sDlg.Session.ContainsKey('RunCount')) { [int]$sDlg.Session['RunCount'] } else { 0 }
                $sx      = if ($sDlg.Session.ContainsKey('Success'))  { [int]$sDlg.Session['Success']  } else { 0 }
                $fx      = if ($sDlg.Session.ContainsKey('Failed'))   { [int]$sDlg.Session['Failed']   } else { 0 }
                Write-NemAudit -Action 'SessionEnd' -Result 'OK' `
                    -Detail "runs=$rc success=$sx failed=$fx; logs flushed to $logDir; transcript=$logPath"
            } catch {}
        }

        ## v1.9.3: in-flight gate is now latched earlier (before the
        ## modal dialog at line ~11598) and cleared explicitly on
        ## Cancel. The duplicate set that used to live here was
        ## redundant — removed.

        $s = Get-NemState

        ## Stop the drainer timers if runs are in progress
        try {
            if ($s.UI.Controls.ContainsKey('updTimer')) {
                $t = $s.UI.Controls['updTimer']
                if ($t) {
                    try { $t.Stop() } catch {}
                    try { $t.Dispose() } catch {}
                }
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.Timer' -Result 'Failed' -Detail $_.Exception.Message
        }
        try {
            if ($s.UI.Controls.ContainsKey('kbTimer')) {
                $t = $s.UI.Controls['kbTimer']
                if ($t) {
                    try { $t.Stop() } catch {}
                    try { $t.Dispose() } catch {}
                }
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.KbTimer' -Result 'Failed' -Detail $_.Exception.Message
        }
        try {
            if ($s.UI.Controls.ContainsKey('runAllTimer')) {
                $t = $s.UI.Controls['runAllTimer']
                if ($t) {
                    try { $t.Stop() } catch {}
                    try { $t.Dispose() } catch {}
                }
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.RunAllTimer' -Result 'Failed' -Detail $_.Exception.Message
        }
        try {
            if ($s.UI.Controls.ContainsKey('preflightTimer')) {
                $t = $s.UI.Controls['preflightTimer']
                if ($t) {
                    try { $t.Stop() } catch {}
                    try { $t.Dispose() } catch {}
                }
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.PreflightTimer' -Result 'Failed' -Detail $_.Exception.Message
        }
        try {
            foreach ($rebKey in @('rebTimer','rebVerifyTimer')) {
                if ($s.UI.Controls.ContainsKey($rebKey)) {
                    $t = $s.UI.Controls[$rebKey]
                    if ($t) {
                        try { $t.Stop() } catch {}
                        try { $t.Dispose() } catch {}
                    }
                }
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.RebootTimer' -Result 'Failed' -Detail $_.Exception.Message
        }

        ## Cancel in-flight PS jobs + dispose
        try {
            foreach ($id in @($s.Jobs.Keys)) {
                if ($id -eq '_counters') { continue }
                $job = $s.Jobs[$id]
                if ($job -and $job.PS) {
                    try { $job.PS.Stop() } catch {}
                    try { $job.PS.Dispose() } catch {}
                }
            }
            $s['Jobs'] = @{}
        } catch {
            Write-NemAudit -Action 'Shutdown.Jobs' -Result 'Failed' -Detail $_.Exception.Message
        }

        ## Dispose runspace pool
        try {
            if ($s.Pool) {
                try { $s.Pool.Close() } catch {}
                try { $s.Pool.Dispose() } catch {}
                $s['Pool'] = $null
            }
        } catch {
            Write-NemAudit -Action 'Shutdown.Pool' -Result 'Failed' -Detail $_.Exception.Message
        }

        Write-NemAudit -Action 'FormClose' -Result 'OK'

        ## v1.10.5: drain + shut down the background log writer LAST, so
        ## every queued line (including the FormClose audit just above and
        ## the SessionEnd terminator) gets flushed to the share before the
        ## process exits. Bounded wait inside Stop-NemLogWriter — a dead
        ## share can't hang the close.
        try { Stop-NemLogWriter } catch {}
    }.GetNewClosure())

    Write-NemAudit -Action 'FormShow' -Result 'OK'
    [void]$form.ShowDialog()
}

#################
## Entry point ##
#################
Set-WptDpiAware
Initialize-WptTheme
$script:NemOperator        = Resolve-NemOperatorIdentity
$script:Nemesis.Session['Edipi']       = $script:NemOperator.Edipi
$script:Nemesis.Session['DisplayName'] = $script:NemOperator.DisplayName
$script:Nemesis.Session['FolderName']  = $script:NemOperator.FolderName
$script:NemResolvedLog     = Resolve-NemLogDir
$script:NemInheritedJanet  = Import-NemJanetCredential

Show-NemMainForm

## v1.10.5: safety-net flush. The FormClosing handler already calls
## Stop-NemLogWriter; this idempotent second call covers any exit path
## that bypasses it (Stop-NemLogWriter no-ops when already shut down).
try { Stop-NemLogWriter } catch {}