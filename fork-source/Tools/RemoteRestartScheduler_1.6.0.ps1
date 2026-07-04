<#
.NAME
    J.A.N.E.T. Remote Restart Scheduler
.SYNOPSIS
    Joint Administration and Network Execution Toolkit - Mass Scheduled Restart
.DESCRIPTION
    WinForms tool for staggering Windows restarts across a fleet of remote
    machines. Each target gets a Windows shutdown countdown popup N minutes
    before its scheduled restart time. Default profile: 4000 machines, 60
    minute restart window starting 02:00 AM, 15 minute pre-restart warning.

    Mechanism: shutdown.exe /m \\HOST /r /t <lead-seconds> /c "<message>" /f
    is dispatched per machine at (RestartAt - LeadMinutes). Windows handles
    the visible 15-minute countdown popup AND the actual reboot - the tool
    only needs to fire each command on time.

    Stagger math (defaults):
        Restart window:  02:00 - 03:00
        Dispatch window: 01:45 - 02:45  (each command fires 15 min before)
        Cadence:         ~1 dispatch / 0.9 sec for 4000 machines

    UI: 3 tabs - Targets, Schedule, Run/Results. WPT purple + gold theme,
    DWM dark titlebar, JANET centralized logging, closing-notes egress.
.AUTHOR
    THOMPSON, BRAXTON - 48 CS / SCOO
.VERSION
    1.6.0
.CHANGELOG
    v1.6.0 - 2026-06-11 - STABLE RELEASE. Promotes 1.6.0-beta (below) to the
             stable line after same-day field testing on the dispatcher
             server, replacing 1.5.2. Contents: server-hosted operation
             (run the tool ON the server, service-account scheduled task
             fires the wave), the two field fixes (delayed-start
             PerformClick no-op; reboot-monitor GetNewClosure scope trap -
             both also ported to 1.5.2), and the reboot-monitor
             plain-language wording pass.
    v1.6.0-beta - 2026-06-11 - SERVER-HOSTED OPERATION (BETA). Functionally
             identical to 1.5.1 - this build is the reviewed/blessed copy for
             running the tool ON A DISPATCHER SERVER itself (copy to e.g.
             C:\JANET\Tools\ on the server, RDP in, run it there exactly like
             on a desktop, and use "Schedule as Windows Task..." with the
             service account). Review confirmed the 1.5.1 mechanism already
             supports this end-to-end: the task registers on the machine the
             tool runs on, runs as the service account whether logged on or
             not, job/log data is workspace-anchored next to the tool (NOT
             under the operator's profile), and the auto run self-deletes its
             task at drain. Requirements on the server: service account is
             password-based with 'Log on as a batch job' there + remote
             restart rights on targets; operator can create scheduled tasks.
           - Reboot-monitor wording pass (field feedback, 2026-06-11): the
             terse states confused operators - "Dispatched" in the Run grid
             next to "Online (no reboot seen)" in the monitor read as a
             contradiction when the host was simply still counting down. The
             'Up' state now reads the live plan row and says WHY the machine
             is still online ("Restart sent - waiting for it to go down
             (countdown on machine)", "User clicked Decline - will NOT
             restart this run", "Restart command FAILED", "restart not sent
             to it yet"), reboots read "RESTARTED - went down and came back",
             WinRM verdicts read "RESTARTED - confirmed by boot time (...)" /
             "Did NOT restart - confirmed (last boot ...)", and the summary
             bar + final tally + CSV Verify column use the same plain
             language.
           - FIX (field, 2026-06-11): in-app "Begin at the scheduled time"
             countdown reached 0:00 and the wave never started. Arming the
             countdown disables the Start button; at fire time the tick
             called $btnStart.PerformClick(), but PerformClick() on a
             DISABLED button is a silent no-op (ButtonBase requires
             CanSelect = visible + enabled - verified on PS 5.1/WinForms).
             The timer stopped, the label froze at "(in 00:00:00)" and
             nothing dispatched. Fire path now re-enables the button before
             clicking. (1.5.1 STABLE has the same latent bug - the in-app
             delayed start has likely never successfully fired there; port
             with the monitor fix when promoting.)
           - FIX (field, 2026-06-11): reboot-verification monitor spammed
             "Invoke-RebootMonitorTick is not recognized" every tick when the
             tool was launched via the call operator - & 'script.ps1', which
             is what right-click "Run with PowerShell" does. The monitor
             dialog's timer/button/close handlers were .GetNewClosure()
             closures; GetNewClosure rebinds a scriptblock to a dynamic
             module whose command lookup sees only its module + GLOBAL scope.
             Under & the script's functions live in a private script scope
             (invisible to the module), so the tick, verify pass,
             Log-Activity and the CSV-export helpers were all
             CommandNotFoundException - the monitor never advanced past
             "Checking...", Verify/Stop/Export were dead, and closing the
             dialog leaked the timer + runspace pool. Launches via
             -File were immune (-File runs the script dot-sourced into the
             session's global scope), which is why the scheduled-task auto
             run never hit it. Repro + fix verified both ways on PS 5.1.
             (1.5.1 STABLE has the same latent bug - port this fix when
             promoting.) Handlers are now plain scriptblocks (stay bound to
             the script's session state, so functions resolve under ANY
             launch style) and the per-dialog monitor context rides in on
             each sender control's .Tag ($this.Tag) instead of a closure
             capture. Affects only the 1.5.1-line monitor dialog; the
             dispatch engine itself was never impacted.
           - FIX: the ISE/dot-source fallback for the tool's own path still
             pointed at the old RemoteRestartScheduler_1.5.0-beta3.ps1
             filename; now derived from the current version constant.
    v1.5.1 - 2026-06-10 - STABLE RELEASE. Promotes the 1.5.0 beta line
             (scheduled-task arming, rolling/go-fast mode, fast defaults - see
             beta entries below) to the stable line, replacing 1.4.3, plus the
             reboot-verification overhaul. Field run reported
             ~800 of ~900 dispatched hosts "Online (no reboot seen)" when most
             had in fact rebooted - the ping monitor can only credit a reboot it
             personally watched go down and come back, and it didn't open until
             the dispatch queue drained, after rolling / catch-up / late-consent
             hosts (60s grace floor) had already cycled. Five fixes:
           - WinRM boot-time verification (NEW). When the ping phase ends (all
             back, or timeout) the monitor asks every still-ambiguous host
             (Online-no-reboot / Came-online) for
             Win32_OperatingSystem.LastBootUpTime over the same WinRM channel
             the dispatch used, and compares it to when that host's shutdown
             command actually landed (new per-row DispatchedAt; falls back to
             RestartAt for replayed rows). Verdicts render as "Rebooted -
             verified (boot HH:mm:ss)" / "NOT rebooted - verified" and are
             definitive regardless of when the monitor opened. New
             "Verify (WinRM)" button runs the same pass on demand mid-watch
             (pinging continues; a later witnessed down-cycle clears a stale
             NOT-rebooted verdict). BootTime + Verify columns added to the
             monitor's CSV export.
           - The monitor now auto-opens at dispatch START (manual non-dry runs,
             right after the pre-flight gate) instead of at queue drain, so the
             down->up windows actually happen while it's watching. The
             drain-time auto-open remains as a fallback / reopen.
           - Hosts already down when monitoring began and answering later are no
             longer lumped into "Online (no reboot seen)": new 'CameBack' state
             ("Came online (down at start)", gold) which the WinRM pass then
             settles. The old EverDown promotion on the Unreachable->up path was
             dead code (nothing ever set EverDown entering Unreachable).
           - Watch timeout now derives from the schedule: (latest RestartAt -
             now) + the configured allowance (default 30 min), capped at 24 h -
             previously a flat 30 min that could expire before the wave was due,
             stamping the whole fleet "no reboot seen".
           - Monitor grid columns set NotSortable: a header-click sort reordered
             the rows while repaints still addressed fixed row indexes, painting
             host states onto the wrong rows.
    v1.5.0-beta4 - 2026-06-08 - CONVERGENCE BUILD: superset of the stable 1.4.3
             line + the beta scheduled-task line, plus a new rolling "go-fast"
             mode. This is intended to be the single line going forward.
           - Rolling / go-fast mode (NEW toggle, default OFF). When ON, prompts
             go out immediately and each host reboots ~<rolling grace>s after IT
             approves - rolling down the line - instead of every approved host
             converging on one shared restart clock time. Fixes the "set 2am but
             a box isn't even prompted till 3am, and approvers still wait for
             2am" problem: in rolling mode there is no shared reboot time, each
             machine goes as soon as it says yes. New "Restart grace after
             approve (sec)" control (default 60). Timeout/no-user still proceed;
             Decline still skips. OFF = the existing converge-at-scheduled-time
             behavior (kept as a toggle).
           - In-app delayed start (NEW). "Begin at the scheduled time" checkbox:
             leave the tool open + logged in and it auto-begins the wave itself
             at the Schedule-tab time (countdown on the Start button); Cancel
             aborts the wait. Complements the unattended Windows-Task path - now
             BOTH attended-timer and unattended-task auto-start exist.
           - Rolling settings persist into the scheduled-task job JSON and replay
             at fire time, so the unattended 2am task runs rolling too.
           - Ported from stable 1.4.3: live Elapsed timer + ETA (projected finish
             from done/elapsed, freezes "Completed in HH:MM:SS") and the Split
             targets -> N balanced CSVs button (round-robin, for fanning a wave
             across N dispatcher boxes). Concurrency ceiling 128 -> 256.
           - $script:TerminalStatuses centralizes the done/drain status set.
           - Production-hardening pass (independent code review + isolated logic
             tests of split/duration/ETA):
             * FIX (blocker): the in-app StartWaitTimer is now stopped+disposed
               on form close, and the FormClosing guard offers to cancel a
               pending scheduled start - previously closing mid-countdown could
               fire PerformClick() on a disposed form (crash / headless arm).
             * FIX: X / Alt-F4 while a scheduled start counts down now prompts
               instead of being silently refused.
             * FIX: converge-mode consent prompts open ConsentPromptSeconds
               before the dispatch window, matching the scheduled task's early
               fire, so an unattended converge run prompts at once instead of
               idling for the prompt window first.
             * The scheduled-start countdown re-reads the time picker each tick,
               so the operator can adjust the start time mid-countdown.
    v1.5.0-beta3 - 2026-06-06 - "Fastest possible" defaults for full-fleet waves.
             Tuned the out-of-box dispatch for 2600+ hosts after a field run
             took ~3 h wall-clock (mostly dead-host WinRM timeouts + the
             consent floor), not the dispatch itself.
           - Skip servers (NEW, ON by default). Server-named hosts must not ride
             a workstation reboot wave (own maintenance windows / dependencies),
             so any host matching the server name pattern (default
             ^MSEK-[A-Za-z]{2,4}- : MSEK-AS-/-BS-/-CM-/-DB-/-FS-/-WXA-, but NOT
             the MSEKL-/MSEKW- workstations) is marked Skipped-Server up front
             and never pinged or contacted. New Schedule-tab checkbox plus an
             editable regex box so other environments can tune the convention;
             a bad regex fails open (skip-servers off that run, nobody dropped).
           - Pre-flight ping gate (NEW, ON by default). Before the WinRM
             fan-out, every planned host is pinged in parallel (same
             System.Net.NetworkInformation.Ping pool the reboot monitor uses,
             cap 64, fixed per-host timeout). Non-responders are marked
             Unreachable up front and NEVER get a WinRM call - so a wall of
             offline boxes no longer burns OpenTimeout (15 s) each inside a
             dispatch slot, and they don't pad the reboot-monitor tail either.
             New Schedule-tab checkbox "Skip unreachable (pre-flight ping)" so
             ICMP-blocked subnets can turn it off. Skipped on dry runs.
           - Concurrency default 32 -> 96. WinRM fan-out is I/O-bound (slots
             sit blocked on the network), so a higher default pushes the whole
             prompt/dispatch wave out far faster from one operator box. Cap
             stays 128; operators can still dial it down.
           - Consent reboots now CONVERGE on the shared restart time instead of
             each host starting its own grace countdown when its prompt clears.
             A Consent-Approved host is dispatched with /t = (RestartAt - now)
             floored at the Accept grace, so every approved machine reboots
             together at the scheduled time (matches burst-mode semantics) -
             "send to all, then wait for the one countdown" rather than a
             rolling per-host stagger. Consent stays ON by default.
           - Consent poll interval 12 s -> 20 s: with the whole fleet Awaiting-
             Consent at once, fewer poll round-trips means more slots free for
             launching the remaining prompts. The PromptDeadline backstop is
             unchanged, so proceed-on-timeout behavior is identical.
           - Review fixes (multi-agent code review, same set applied to 1.4.2):
             * Abort (button + Send-RemoteAbortFanOut) now includes
               'Already-Scheduled' (rc=1190) hosts - previously the emergency
               cancel skipped exactly the hosts guaranteed to reboot.
             * Pre-flight ping gate no longer overwrites a row the operator
               Cancelled mid-sweep (DoEvents) back to Unreachable / double-counts.
             * 'Cancelled' added to the auto-stop terminal set; re-arm now
               revives Cancelled rows to Pending so they actually re-dispatch.
             * Cancel recomputes Pending/Awaiting so the stats bar + close-guard
               stop reporting cancelled hosts as still pending.
             * Skipped-Server hosts now counted in a new 'Skipped' stat bucket
               (+ completion summary) so the buckets reconcile to Total.
             * Tick timer is stopped once the wave drains (manual completion,
               Cancel, and abort-only runs) instead of firing all session.
             * Consent 'AgentError' result now surfaced as a distinct
               Agent-Failed outcome instead of silently riding the No-Response
               backstop into an unconsented restart.
    v1.5.0-beta2 - 2026-06-06 - Bug-hunt fixes on the beta.
           - Schedule-as-Task audit row was silently dropped: Write-JanetAction
             was called with -Action 'ScheduleTask', which fails the shared
             logging block's ValidateSet (TouchHost|VulnPatched), so the call
             threw and the surrounding try/catch swallowed it. Now logs
             'TouchHost' with the schedule specifics in -Detail.
           - Inherited from 1.4.x and fixed here too: the "Computed plan"
             $first/$last range and the empty $script:LeadSeconds in the
             per-host shutdown audit Detail.
    v1.5.0-beta - 2026-06-05 - Schedule-as-Windows-Task (BETA). Lets the
             operator ARM a reboot wave before leaving work and have a one-shot
             Windows Scheduled Task fire the whole dispatch automatically at the
             chosen time (e.g. 02:00) - no need to physically come in and click
             Start Dispatch.
           - New Schedule-tab button "Schedule as Windows Task...". It snapshots
             the current targets + schedule + consent settings into a job JSON
             under JanetLocal\Remote_Restart\<user>\Jobs\ and registers a one-shot
             Task Scheduler job (schtasks /Create /XML, "run whether logged on or
             not", highest privileges) that re-launches THIS script with
             -AutoDispatch -JobFile <job>.
           - SERVICE-ACCOUNT credential model: the operator enters a service
             account (DOMAIN\svc, username pre-filled from last time, password
             never persisted by us); the task RUNS AS that account and the 2 AM
             dispatch authenticates WinRM with the service account's OWN Kerberos.
             Nothing is written to any share - Windows holds the task password in
             its LSA secret store. The service account needs remote-restart rights
             on the targets. (No DPAPI cred file: that only decrypts for the same
             user+machine that wrote it, so a shared file would fail unattended.)
           - The end-user Accept/Decline consent prompt is UNCHANGED and still
             happens on each target at fire time, so users can still say no - the
             whole consent subsystem runs exactly as it does for a manual click.
             A declined host is skipped just like today.
           - New -AutoDispatch / -JobFile parameters. In auto mode the tool loads
             the job, replays it into the controls, auto-arms the dispatch, then
             self-deletes its own scheduled task and closes when the wave drains
             (no closing-notes dialog, no reboot-monitor pop-up). The operator
             still gets an "OK to schedule?" confirmation up front, and can pick
             No there OR leave "Require user consent" on so each user is still
             asked at 2 AM.
           - Task start time = RestartTime - lead (- prompt window when consent
             is on) so the wave lands near the chosen restart time.
           - BETA CAVEATS: the service account must be a normal password-based
             account (a CAC/smartcard identity cannot run an unattended task) and
             needs 'Log on as a batch job' on the operator box plus remote-restart
             rights on the targets; gMSA would remove the password step entirely
             (future). WinForms runs in a non-interactive window station under the
             task; the dispatcher pumps fine but nothing renders on the (logged-
             off) console - expected.
           - Targets + Exception boxes set MaxLength=0 (no cap). The WinForms
             default 32,767-char limit was silently truncating large pastes
             before a full fleet fit; 3000+ hosts now paste in full.
           - Original v1.4.0 left untouched; this is a parallel beta build.
    v1.4.0 - 2026-06-05 - User Consent Prompt. Optional (default ON) gate that
             asks the logged-on user to Accept or Decline the restart BEFORE
             the machine reboots, shown on THEIR interactive desktop.
           - Why a scheduled task: the dispatch runs over WinRM in session 0
             (non-interactive), where a WinForms dialog is invisible to the
             user. So the dispatcher stages a tiny self-contained consent
             agent on the target and registers a ONE-SHOT scheduled task that
             runs it AS THE INTERACTIVE USER (schtasks /IT, no stored creds),
             which is the only reliable way to put a dialog on their screen.
           - STIG-safe: the agent only COLLECTS the choice (Accept/Decline)
             and writes a small result JSON locally; it never calls shutdown
             itself (locked-down users often lack the "Shut down the system"
             right). The dispatcher reads the result back over the SAME WinRM
             channel - point-to-point, no central share, scales to the whole
             fleet the same way dispatch fan-out already does.
           - Two-phase, non-blocking flow folded into the dispatch tick:
             Pending -> (ConsentLaunch) -> Awaiting-Consent -> (ConsentPoll)
             -> Consent-Approved -> normal restart. Each WinRM call is short
             (launch / poll), so throughput stays high across 2000+ hosts.
           - Policy: no response within the prompt window (default 5 min) OR
             no user logged on -> restart proceeds. Decline -> host is SKIPPED
             this run and marked Declined (operator re-arms to retry). Accept
             -> normal restart with a save-your-work grace (default 60 s).
           - New Schedule-tab controls: "Require user consent" checkbox plus
             Prompt window (min) and Accept grace (sec). Dry runs never prompt.
           - New plan statuses surfaced live in the Run grid + stats bar:
             Awaiting-Consent (cyan) and Declined (yellow). Result column
             records who accepted/declined and why a host proceeded.
    v1.3.0 - 2026-05-30 - Reboot Verification Monitor. New pop-out window
             that confirms which machines actually came back from the
             restart, by ping, in real time.
           - Show-RebootMonitorDialog: a modeless window (owns its own
             frame, stays open alongside the tool) that pings every
             successfully-dispatched host on a repeating interval until
             each one is confirmed back online or a timeout is hit.
           - Reboot is proven by a DOWN-then-UP transition, not a single
             "is it up" check. A host that merely stayed reachable the
             whole time is reported "Online (no reboot seen)" in yellow,
             because we never observed it drop - it may not have rebooted,
             or the reboot was faster than the ping interval. Confirmed
             down->up hosts read "Rebooted - online" in green.
           - Per-host state machine: Pending -> Up -> Down -> Rebooted,
             with Unreachable (never answered) and Down-not-returned
             (offline) terminal states. Live summary counts + per-host
             Went-down / Came-back timestamps in a color-coded grid.
           - Parallel pinging via a dedicated runspace pool (cap 64) using
             System.Net.NetworkInformation.Ping with a fixed per-host
             timeout, so the UI never blocks and dead hosts don't stall
             the wave on PS 5.1 (Test-Connection has no per-ping timeout
             on 5.1). Waves are serialized: a new wave starts only after
             the prior one fully drains AND the interval has elapsed.
           - Auto-opens when a real (non-dry-run) dispatch finishes with at
             least one host Sent; also launchable any time from the new
             "Verify Reboots" button on the Run / Results tab. Export the
             monitor results to CSV. One JANET activity-log summary line on
             completion; no per-ping log spam.
           - Run / Results button row re-spaced to fit the new button.
    v1.2.0 - 2026-05-19 - Simultaneous mass-reboot model. The v1.0/v1.1
             "stagger across a restart window" design did not match real
             operator intent - field test on a 13-host plan with a 2-min
             window produced ~5-min host-to-host spacing instead of all-
             at-once, because the underlying Build-Plan distributed
             RestartAt evenly across WindowMinutes. Replaced with single-
             time model:
           - Removed "Window length (minutes)" field from the Schedule
             tab.
           - Renamed "Restart window start" -> "Restart time (all
             machines)".
           - Build-Plan now takes a single $RestartTime parameter. Every
             row gets identical DispatchAt = RestartTime - LeadMinutes
             and identical RestartAt = RestartTime. No per-host stagger.
           - Plan-summary label rewrote: "N machines | ALL restart at
             HH:MM | Dispatch begins HH:MM | N-min warning per host".
           - Burst dispatch (default) fan-outs every shutdown command in
             parallel via the RunspacePool, /t = (RestartTime - Now) for
             every host - so all hosts receive their countdown popup
             near-simultaneously and restart together at RestartTime.
             With 32 threads, 4000 machines dispatch in ~2 minutes.
           - SmartCard (CAC) credentials: dispatch can now run without
             explicit -Credential, using the operator's current CAC-
             bound Kerberos ticket. Refresh-CredStatus shows "current
             Windows session (CAC)" in cyan when no cred is captured.
           - shutdown.exe is invoked via ProcessStartInfo in the remote
             scriptblock instead of '& shutdown.exe', which sidesteps
             PS 5.1's native-command-stderr-as-ErrorRecord behavior that
             was making Invoke-Command throw and corrupting exit codes.
           - Exit code 1190 (ERROR_SHUTDOWN_IS_SCHEDULED) treated as
             success - target already has a pending restart, which is
             the end state we want. Counts toward Sent, log line reads
             "ALREADY <host>", row colored yellow.
    v1.1.1 - 2026-05-15 - Credential capture reverted to WPT-verbatim
             after field test: v1.1.0's MSA-token rejection / DOMAIN\username
             prefill / no-prefix warning was blocking valid admin tokens
             that worked fine in WPT.
           - Set Credentials handler stripped to the WPT 6.5.16 line 6140
             and ACAS Nemesis 1.10.0 line 7858 pattern verbatim: just
             Get-Credential -Message, store whatever the dialog returns,
             no second-guessing.
           - Import-RrsJanetCredential matches: launcher-inherited cred
             accepted as-is, only the PSCredential type check remains.
           - $script:CredInheritedFromJanet flag + UI hooks (added in the
             prior round) are kept: status label suffixes "(inherited
             from J.A.N.E.T.)" and the Set Credentials button text flips
             to "Override Credentials" when the cred came from the
             launcher. Manual Set or Clear resets the flag.
           - Get-ShutdownErrorHint stays detail-aware: pattern matchers
             for 0x80090351, TrustedHosts, access denied, logon failure,
             unresolvable hostnames return targeted fixes. Entries for
             -3 (remote scriptblock threw) / -4 (Invoke-Command failed)
             still present. Purely diagnostic, never blocks a credential.
           - Cred file I/O switched to -LiteralPath on Import-Clixml +
             Export-Clixml to match WPT/Nemesis convention.
    v1.1.0 - 2026-05-15 - Aligned credentialed dispatch to WPT 6.5.16's
             proven pattern after a field report that credentialed restart
             was reporting failure even when shutdown was actually scheduled.
           - Microsoft Account session token guard: Set Credentials now
             pre-fills DOMAIN\username (from $env:USERDOMAIN\USERNAME when
             domain-joined) and REJECTS any @@-prefixed token captured back
             from the prompt with a MessageBox explaining the cause and
             the fix. Same MSA-token failure mode WPT 6.2.2 documented;
             without the guard the credential dialog silently returns
             '@@BZCFBcC52CAa485vTfJS5T0yyoGI' style blobs that AD cannot
             authenticate, producing 0x80090351 on every target.
           - Startup inheritance from $env:JANET_CRED_FILE also rejects
             MSA tokens (warn-only log line + cred not loaded), so a
             stale MSA cred saved by a prior session doesn't sit quietly
             in $global:Credentials and fail every dispatch.
           - Launcher-inheritance UI now matches WPT 6.5.16 (line 11013)
             and ACAS Nemesis 1.10.0 (Import-NemJanetCredential, line
             2545) verbatim: Import-RrsJanetCredential factored into a
             named function; $script:CredInheritedFromJanet flag tracks
             inheritance source; status label appends "(inherited from
             J.A.N.E.T.)" suffix when applicable; Set Credentials button
             text flips to "Override Credentials" so the operator knows
             a click will REPLACE the launcher cred. Manual Set or Clear
             both reset the flag.
           - Cred file persistence switched to -LiteralPath on both
             Import-Clixml and Export-Clixml to match WPT/Nemesis.
           - Get-ShutdownErrorHint became detail-aware. Pattern matchers
             for 0x80090351, TrustedHosts, access denied, logon failure,
             and unresolvable hostnames surface targeted fixes instead
             of the generic 'net helpmsg <code>' fallback. New hints
             added for the tool's own -3 (remote scriptblock threw) and
             -4 (Invoke-Command failed to reach target) codes.
           - Set Credentials prompt switched from $host.UI.PromptForCredential
             (which silently returned $null on some hosts) to Get-Credential
             -Message, matching WPT verbatim.
           - PSSession dispatch now uses Invoke-Command -ComputerName direct
             (not New-PSSession + Invoke-Command -Session), with
             -Authentication Negotiate + $global:WSManOpt profile cribbed
             from WPT line 2846 (Open=15s, Op=30s, Cancel=5s, Idle=60s).
           - Removed '2>&1' from remote shutdown.exe call. In PS 5.1 the
             redirect wraps stderr as ErrorRecord and sets $? to $false
             even on exit code 0 - the root cause of the false-failure
             reports. Now mirrors WPT's RegKeyNotifyAndRebootBlock exactly.
           - Inner remote scriptblock returns @{ ExitCode; Output; Error }
             so Invoke-Command-itself failures are distinguishable from
             target-side shutdown failures.
           - $global:Cred renamed to $global:Credentials to match WPT and
             keep JANET launcher inheritance consistent across tools.
           - Header redesigned: top-left Close Tool button + top-right
             Set Credentials / Clear pair with live status label.
           - Targets tab rebuilt with Dock-based layout: docked-right
             button rail (210 px), SplitContainer for Targets / Exceptions
             columns (user-resizable, 60/40 default), and a separate stats
             bar below the header so labels never clip into the title.
           - Test Single Host dialog on the Targets tab: enter one
             hostname, fire one shutdown, see exit code + output + a
             plain-English hint mapping common shutdown.exe error codes.
           - Concurrency cap raised 32 -> 128 (default 8 -> 32).
    v1.0.0 - 2026-05-14 - Initial release.
           - Targets paste/CSV import with case-insensitive dedup.
           - Exception List (never-restart) column with separate CSV import
             and Clear + cross-session persistence to
             JanetLocal\Remote_Restart\<user>\exceptions.txt; targets pasted
             that also appear in the exception list are silently filtered
             out and the drop count is surfaced on the count label.
           - Schedule planner with editable restart start / window / lead,
             warning message with {LEAD} token, Compute Schedule preview
             grid + Save Plan CSV.
           - Two dispatch modes:
              * Burst (default, recommended): every shutdown command is
                fan-out submitted to the RunspacePool ASAP with a per-host
                /t = (RestartAt - Now).TotalSeconds clamped at a 60-second
                floor. The restart stagger is preserved by Windows' own
                countdown timer on each host. 4000 machines dispatch in
                ~1-2 min instead of ~60 min, and the dispatcher can be
                closed once the queue drains.
              * Time-gated: legacy mode - one command per second-aligned
                tick, fired exactly LeadMinutes before each restart for
                a flat 15-min warning per host. Dispatcher must stay
                running for the full window.
           - RunspacePool dispatch (1-128 threads, default 32), Dry-Run
             mode, live counters, Cancel Pending, Abort Already-Dispatched
             (shutdown /a fan-out), Results CSV export.
           - JANET logging block cloned from RemoteMessageTool 1.3.3
             verbatim; per-host TouchHost rows; one SessionEnd row on close
             via closing-notes dialog.
#>

## v1.5.0-beta - Scheduled-task auto-dispatch parameters.
##   -AutoDispatch : run headlessly - load -JobFile, auto-arm the dispatch, then
##                   self-close when the wave drains. Set ONLY by the one-shot
##                   Windows Scheduled Task this tool registers; never by hand.
##   -JobFile      : path to the saved job JSON (targets + schedule + consent
##                   settings + optional credential) the auto run replays.
## param() MUST be the first executable statement, so it sits ahead of the STA
## guard below. Both args are forwarded through the STA self-relaunch.
param(
    [switch]$AutoDispatch,
    [string]$JobFile
)

## STA self-relaunch guard. Windows Forms requires Single-Threaded Apartment
## (STA). Windows PowerShell 5.1 (powershell.exe) defaults to STA, but pwsh.exe
## (PS 7+), some Task Scheduler invocations, ConEmu/Terminal profiles, and
## certain "Run with PowerShell" shell verbs default to MTA. In MTA, any Form
## constructor throws and the host process exits silently before the operator
## can see the error - exact symptom: "doesn't launch from PowerShell but
## works when pasted into ISE" (ISE is always STA).
## If we wake up in MTA, respawn ourselves in a fresh Windows PowerShell 5.1
## process with -STA and exit this one.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $self = $MyInvocation.MyCommand.Path
    if (-not $self) { $self = $PSCommandPath }
    if ($self) {
        $psExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $psExe)) { $psExe = 'powershell.exe' }
        $relArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$self`"")
        ## Forward the v1.5.0-beta auto-dispatch args so an MTA respawn still
        ## fires the scheduled wave instead of dropping into the manual GUI.
        if ($AutoDispatch) { $relArgs += '-AutoDispatch' }
        if ($JobFile)      { $relArgs += @('-JobFile', "`"$JobFile`"") }
        Start-Process -FilePath $psExe -ArgumentList $relArgs
        exit
    }
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -AssemblyName System.IO.Compression -EA SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
[System.Windows.Forms.Application]::EnableVisualStyles()

## $PSScriptRoot fallback. The spliced JANET logging block's Get-JanetLocalDir
## references $PSScriptRoot directly, which is empty under some launch paths
## (ISE paste, dot-source from a runspace, etc.) and produces the
## "Cannot bind argument to parameter 'Path' because it is an empty string"
## errors out of Split-Path / Join-Path / Test-Path. Populate it from
## $MyInvocation or PWD before any code that depends on it runs.
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $candidate = $null
    try { if ($MyInvocation.MyCommand.Path) { $candidate = Split-Path -Parent $MyInvocation.MyCommand.Path } } catch {}
    if (-not $candidate) { $candidate = (Get-Location).Path }
    if ($candidate) { Set-Variable -Name PSScriptRoot -Scope Script -Value $candidate -Force }
}

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Spliced verbatim from RemoteMessageTool 1.3.3. Self-contained. Single
## source of truth is $JanetLogRoot. Falls back to JanetLocal\ when share
## is unreachable; replays orphan rows on next launch.
$JanetRemoteRestartVersion = '1.6.0'

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
    ## Workspace-anchored fallback under the tool's parent dir (the JANET root,
    ## peer to Logs/ and Tools/). Never %USERPROFILE% / %PROGRAMDATA% /
    ## %LOCALAPPDATA% — keeps tool data next to the launcher so portable /
    ## kiosk installs stay self-contained.
    ## PATCHED for RemoteRestartScheduler: $PSScriptRoot inside this function
    ## is empty under some launch paths (ISE paste, etc.) which produces
    ## empty-string Split-Path errors. Use $global:ScriptDir which the tool's
    ## RESOLVE SCRIPT DIR region sets up with proper fallbacks.
    if ($null -eq $script:JanetSession) { return $null }
    $base = if ($global:ScriptDir) { $global:ScriptDir } else { $PSScriptRoot }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $root = Split-Path -Parent $base
    if ([string]::IsNullOrWhiteSpace($root)) { $root = $base }
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\{0}\{1}" -f $script:JanetSession.Tool, $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Get-JanetLocalRollupDir {
    ## Local fallback for the fleet rollup. PATCHED same as Get-JanetLocalDir.
    if ($null -eq $script:JanetSession) { return $null }
    $base = if ($global:ScriptDir) { $global:ScriptDir } else { $PSScriptRoot }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $root = Split-Path -Parent $base
    if ([string]::IsNullOrWhiteSpace($root)) { $root = $base }
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


#region === RESOLVE SCRIPT DIR ===
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }

## v1.5.0-beta - remember our own full path so the scheduled-task action can
## re-launch THIS exact script with -AutoDispatch. $PSCommandPath is populated
## when run via -File (both the launcher path and the scheduled task path);
## fall back to ScriptDir + this file's name for ISE/dot-source launches.
$global:RrsScriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($global:RrsScriptPath)) {
    try { $global:RrsScriptPath = $MyInvocation.MyCommand.Path } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:RrsScriptPath)) {
    $global:RrsScriptPath = Join-Path $global:ScriptDir ("RemoteRestartScheduler_{0}.ps1" -f $JanetRemoteRestartVersion)
}
#endregion

#region === PER-TOOL LOGGING ===
$parentDir = Split-Path -Parent $global:ScriptDir
$global:LogDir = $null
foreach ($candidate in @((Join-Path $parentDir "Logs"), (Join-Path $global:ScriptDir "Logs"), $global:ScriptDir)) {
    try {
        if (-not (Test-Path $candidate)) { New-Item -Path $candidate -ItemType Directory -Force -EA Stop | Out-Null }
        $testFile = Join-Path $candidate ".janet_write_test"
        Set-Content -Path $testFile -Value "test" -EA Stop; Remove-Item $testFile -Force -EA SilentlyContinue
        $global:LogDir = $candidate; break
    } catch { continue }
}
if (-not $global:LogDir) { $global:LogDir = $global:ScriptDir }

$global:LogFile = Join-Path $global:LogDir ("RRSched_{0}_{1}.log" -f $env:USERNAME, (Get-Date -Format "yyyy-MM-dd_HH-mm-ss"))
function Write-RLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    try { Add-Content -Path $global:LogFile -Value "[$ts] [$Level] $Message" -EA SilentlyContinue } catch {}
}
Write-RLog "=== J.A.N.E.T. Remote Restart Scheduler v$JanetRemoteRestartVersion starting ==="
Write-RLog "ScriptDir: $($global:ScriptDir) | User: $env:USERNAME | PS: $($PSVersionTable.PSVersion)"
#endregion

#region === COLORS / FONTS (Purple + Gold on Black - mirrors JANET.ps1) ===
$colors = @{
    Background    = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    Sidebar       = [System.Drawing.Color]::FromArgb(  7,   7,  11)
    TopBar        = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Panel         = [System.Drawing.Color]::FromArgb( 16,  16,  22)
    PanelLight    = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    Input         = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    InputBorder   = [System.Drawing.Color]::FromArgb( 52,  46,  72)
    OutputBg      = [System.Drawing.Color]::FromArgb(  6,   6,  10)
    Border        = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    TextPrimary   = [System.Drawing.Color]::FromArgb(240, 240, 245)
    TextSecondary = [System.Drawing.Color]::FromArgb(170, 168, 180)
    TextDim       = [System.Drawing.Color]::FromArgb(110, 106, 125)
    Accent        = [System.Drawing.Color]::FromArgb(140, 100, 220)
    AccentHover   = [System.Drawing.Color]::FromArgb(164, 128, 240)
    AccentDim     = [System.Drawing.Color]::FromArgb( 96,  68, 156)
    Success       = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    SuccessDim    = [System.Drawing.Color]::FromArgb( 50, 120,  65)
    Warning       = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Danger        = [System.Drawing.Color]::FromArgb(224,  80,  90)
    Orange        = [System.Drawing.Color]::FromArgb(230, 180,  70)
    Cyan          = [System.Drawing.Color]::FromArgb( 88, 180, 210)
    Console       = [System.Drawing.Color]::FromArgb(164, 128, 240)
    Gold          = [System.Drawing.Color]::FromArgb(218, 180,  82)
    GoldDim       = [System.Drawing.Color]::FromArgb(155, 125,  52)
    Purple        = [System.Drawing.Color]::FromArgb(140, 100, 220)
}

$fonts = @{
    JTitle    = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    JSub      = New-Object System.Drawing.Font("Segoe UI", 9,  [System.Drawing.FontStyle]::Italic)
    Section   = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
    Label     = New-Object System.Drawing.Font("Segoe UI", 9.5)
    LabelBold = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5)
    Button    = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
    Small     = New-Object System.Drawing.Font("Segoe UI", 8.5)
    SmallBold = New-Object System.Drawing.Font("Segoe UI Semibold", 8.5)
    Tiny      = New-Object System.Drawing.Font("Segoe UI Semibold", 7.5)
    Console   = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 9)
    ConsoleSm = New-Object System.Drawing.Font("Cascadia Mono,Consolas", 8.5)
    Stat      = New-Object System.Drawing.Font("Segoe UI Semibold", 14)
}
#endregion

#region === GLOBAL STATE ===
## WSManOpt: aligned with WorkstationPatchingTool's proven WinRM profile
## (Open=15s, Op=30s, Cancel=5s, Idle=60s). Same values used here so credential
## behavior on AFNET workstations matches what WPT already validates.
$global:WSManOpt   = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
$global:Credentials       = $null
$script:CredInheritedFromJanet = $false   # set $true by Import-RrsJanetCredential when the launcher cred was picked up; cleared by manual Set / Clear

function Import-RrsJanetCredential {
    <#
        Pull the launcher-shared credential from J.A.N.E.T. if available.
        Mirrors WPT 6.5.16 line 11013 and ACAS Nemesis 1.10.0 line 2545
        (Import-NemJanetCredential) verbatim - import whatever the launcher
        saved, no second-guessing. JANET.ps1 sets $env:JANET_CRED_FILE on
        the child process after Export-Clixml-ing the launcher-prompted
        cred. Returns $true if a usable cred was inherited, $false otherwise.
    #>
    [CmdletBinding()] param()
    $path = $env:JANET_CRED_FILE
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $cred = Import-Clixml -LiteralPath $path -ErrorAction Stop
        if ($cred -isnot [System.Management.Automation.PSCredential]) {
            Write-RLog "JANET_CRED_FILE did not deserialize to a PSCredential" "WARN"
            return $false
        }
        $global:Credentials = $cred
        Write-RLog "Credentials inherited from J.A.N.E.T. launcher: $($cred.UserName)" "INFO"
        return $true
    } catch {
        Write-RLog "Failed to import inherited credentials: $($_.Exception.Message)" "WARN"
        return $false
    }
}

$script:CredInheritedFromJanet = [bool](Import-RrsJanetCredential)

$global:RunspacePool       = $null
$global:ActiveJobs         = @{}                       # key=Host => @{ PS=...; Async=...; SubmittedAt=...; Row=...; Action/Phase='Dispatch'|'Abort'|'ConsentLaunch'|'ConsentPoll' }
$script:Targets            = New-Object System.Collections.ArrayList   # unique hostnames AFTER exclusion filter
$script:Exceptions         = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:LastExclusionCount = 0                         # how many were dropped by the exception list on the last Apply
$script:Plan               = New-Object System.Collections.ArrayList   # PSCustomObject rows: Host / DispatchAt / RestartAt / Status / Note / Dispatched / Result
$script:PlanByHost         = @{}                       # case-insensitive map host => row
$script:Stats              = [ordered]@{ Pending=0; InFlight=0; Sent=0; Failed=0; Aborted=0; Total=0; Awaiting=0; Declined=0; Skipped=0 }
$script:DispatchActive     = $false
$script:CancelRequested    = $false
$script:DispatchScriptBlock = $null
$script:TickTimer          = $null
$script:MaxConcurrency     = 8
$script:RebootMon          = $null   # active Reboot Verification Monitor context (one at a time); $null when closed
$script:RebootMonPrompted  = $false  # one-shot guard so dispatch-complete auto-opens the monitor only once per run

## --- Progress timer / ETA (ported from stable v1.4.3) ---
$script:DispatchStartTime  = $null   # wall-clock when the current wave's Start ran; drives Elapsed + ETA
$script:DispatchEndTime    = $null   # frozen when the wave drains, so Elapsed shows the final total
## Single source of truth for "this host is finished" - used by both the
## auto-stop drain check and the progress/ETA "Done" count so they can't drift.
$script:TerminalStatuses   = @('Dispatched','Already-Scheduled','Failed','Aborted','Abort Failed','Declined','Unreachable','Skipped-Server','Cancelled')

## --- Rolling / go-fast mode (v1.5.0-beta4) ---
## When ON: prompts go out immediately and each approved host reboots after just
## RollingGraceSeconds (no convergence on a shared RestartAt) - the wave rolls
## down the line. Captured at arm time so a mid-run toggle can't change policy.
$script:RollingMode         = $false
$script:RollingGraceSeconds = 60

## --- In-app delayed start (v1.5.0-beta4) ---
## "Begin at the scheduled time": hold the wave until dtpStart, then auto-start.
## Distinct from the unattended Windows-Task path (that fires with nobody here).
$script:StartWaiting        = $false  # currently counting down to a scheduled start
$script:StartWaitTarget     = $null   # the datetime to begin at
$script:StartWaitSatisfied  = $false  # set when the countdown elapses so the re-entered Start proceeds
$script:StartWaitTimer      = $null

## --- User Consent Prompt (v1.4.0) ---
## Captured from the GUI at arm time so toggling controls mid-run is harmless.
$script:ConsentRequired         = $false   # set true on Start when chkConsent ticked AND not a dry run
$script:ConsentPromptSeconds    = 300      # how long the Accept/Decline dialog stays up before timeout->restart
$script:ConsentGraceSeconds     = 60       # save-your-work countdown after Accept (and the /t for forced restarts)
$script:ConsentPollInterval     = 20       # seconds between result-file polls (v1.5.0-beta3: 12->20, fewer round-trips when the whole fleet is Awaiting-Consent at once; PromptDeadline backstop unchanged)
$script:ConsentAgentTemplate     = $null   # here-string body of the interactive consent agent (.ps1 staged on target)
$script:ConsentLaunchScriptBlock = $null   # runspace job: stage agent + register/run the interactive task
$script:ConsentPollScriptBlock   = $null   # runspace job: read (and on terminal result, clean up) the result file

## --- Server skip (v1.5.0-beta3) ---
## Hosts whose name matches this pattern are SERVERS and are skipped by default
## (they have their own maintenance windows / dependencies and must not ride a
## workstation reboot wave). Naming convention on this fleet: servers are
## MSEK-<role>-<n> (MSEK-AS-01V, MSEK-DB-01V, MSEK-FS-05P, MSEK-WXA-101P, ...)
## i.e. a dash right after "MSEK"; workstations are MSEKL-... / MSEKW-... with a
## letter glued to MSEK and no dash. The "Skip servers" checkbox exposes an
## editable copy of this regex so the convention can be tuned per environment.
$script:ServerNamePattern = '^MSEK-[A-Za-z]{2,4}-'

## --- Scheduled-task auto-dispatch (v1.5.0-beta) ---
## $AutoDispatch / $JobFile come from the param() block at the top of the script
## (set ONLY by the one-shot Windows Scheduled Task this tool registers).
$script:AutoMode     = [bool]$AutoDispatch  # true => load the job, auto-arm, self-close when drained
$script:AutoJobFile  = $JobFile             # path to the job JSON to replay
$script:AutoTaskName = $null                # the scheduled task to self-delete once the wave drains
#endregion

#region === EXCEPTION LIST PERSISTENCE ===
## Exceptions persist across sessions to the same per-user JanetLocal folder
## the logging block uses (Get-JanetLocalDir returns <repo>\JanetLocal\Remote_Restart\<user>).
## Load is deferred until after Start-JanetSession because Get-JanetLocalDir
## depends on $script:JanetSession being populated.
function Get-ExceptionPath {
    if ($null -eq $script:JanetSession) { return $null }
    $dir = Get-JanetLocalDir
    if (-not $dir) { return $null }
    return (Join-Path $dir 'exceptions.txt')
}

function Save-ExceptionsToDisk {
    param([string[]]$Hosts)
    $path = Get-ExceptionPath
    if (-not $path) { return }
    try {
        $sorted = @($Hosts | Sort-Object -Unique)
        Set-Content -LiteralPath $path -Value $sorted -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-RLog "Save-ExceptionsToDisk failed: $($_.Exception.Message)" "WARN"
    }
}

function Load-ExceptionsFromDisk {
    $path = Get-ExceptionPath
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
    try { return @(Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) }) }
    catch { Write-RLog "Load-ExceptionsFromDisk failed: $($_.Exception.Message)" "WARN"; return @() }
}

function ConvertTo-HostList {
    ## Returns a de-duped list with no side effects. Used by both targets and
    ## exception parsing so they share quirks: case-insensitive dedup, leading
    ## \\ stripped, comma / space / tab / newline / semicolon all valid separators.
    param([string]$Text)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.ArrayList
    if (-not $Text) { return ,$list }
    foreach ($raw in ($Text -split "[\r\n,;\t ]+")) {
        $h = $raw.Trim().Trim('\','/').TrimStart('\\')
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        if ($set.Add($h)) { [void]$list.Add($h) }
    }
    return ,$list
}
#endregion

#region === HELPERS ===
function New-StyledButton {
    param([string]$Text, [System.Drawing.Point]$Location, [System.Drawing.Size]$Size,
          [System.Drawing.Color]$BgColor, $FgColor = $null,
          [System.Drawing.Font]$Font = $fonts.Button)
    if (-not $FgColor) {
        $lum = (0.299 * $BgColor.R + 0.587 * $BgColor.G + 0.114 * $BgColor.B) / 255.0
        if ($lum -gt 0.55) { $FgColor = [System.Drawing.Color]::Black } else { $FgColor = [System.Drawing.Color]::White }
    }
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text; $btn.Location = $Location; $btn.Size = $Size
    $btn.BackColor = $BgColor; $btn.ForeColor = $FgColor
    $btn.FlatStyle = 'Flat'; $btn.FlatAppearance.BorderSize = 0
    $btn.Font = $Font; $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $r = [Math]::Min(255, $BgColor.R + 30); $g = [Math]::Min(255, $BgColor.G + 30); $b = [Math]::Min(255, $BgColor.B + 30)
    $btn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb($r, $g, $b)
    return $btn
}

function New-OutputBox {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location = $Location; $rtb.Size = $Size; $rtb.ReadOnly = $true
    $rtb.BackColor = $colors.OutputBg; $rtb.ForeColor = $colors.Console
    $rtb.Font = $fonts.Console; $rtb.BorderStyle = 'None'
    $cm = New-Object System.Windows.Forms.ContextMenuStrip
    $cm.BackColor = $colors.Panel; $cm.ForeColor = $colors.TextPrimary; $cm.Font = $fonts.Label
    $cmClear = $cm.Items.Add("Clear"); $cmClear.ForeColor = $colors.Warning
    $cmClear.Add_Click({ $rtb.Clear() }.GetNewClosure())
    $cmCopy = $cm.Items.Add("Copy All"); $cmCopy.ForeColor = $colors.Accent
    $cmCopy.Add_Click({ if ($rtb.Text) { [System.Windows.Forms.Clipboard]::SetText($rtb.Text) } }.GetNewClosure())
    $rtb.ContextMenuStrip = $cm
    return $rtb
}

function Set-DarkTitleBar {
    param($Form)
    try {
        if (-not ('RRSched.Dwm' -as [type])) {
            Add-Type -Namespace 'RRSched' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction Stop
        }
    } catch {}
    $Form.Add_HandleCreated({
        try {
            $hwnd = $Form.Handle
            if ($hwnd -ne [System.IntPtr]::Zero) {
                $on = 1
                [RRSched.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) | Out-Null
                [RRSched.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4) | Out-Null
            }
        } catch {}
    }.GetNewClosure())
}

function Log-Activity {
    param([string]$Message, [System.Drawing.Color]$Color = $colors.Console)
    if (-not $oLog) { Write-RLog $Message; return }
    $ts = (Get-Date).ToString("HH:mm:ss")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.SelectionColor = $colors.TextDim
    $oLog.AppendText("[$ts] ")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.SelectionColor = $Color
    $oLog.AppendText("$Message`r`n")
    $oLog.SelectionStart = $oLog.TextLength
    $oLog.ScrollToCaret()
    Write-RLog $Message
}

function Format-Hms { param([datetime]$dt) return $dt.ToString('yyyy-MM-dd HH:mm:ss') }
function Format-Duration {
    ## TimeSpan -> compact HH:MM:SS (days fold into hours, so 26h not 1d 2h).
    param([TimeSpan]$ts)
    if ($null -eq $ts) { return '--:--:--' }
    if ($ts.TotalSeconds -lt 0) { $ts = [TimeSpan]::Zero }
    return ('{0:00}:{1:00}:{2:00}' -f [int][Math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds)
}
#endregion

#region === TARGET / SCHEDULE COMPUTATION ===
function Load-TargetsFromCsv {
    param([string]$Path)
    $list = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Path)) { return ,$list }
    try {
        $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop
        $colName = $null
        if ($rows.Count -gt 0) {
            foreach ($candidate in @('ComputerName','Computer','Hostname','Host','Name','Machine','NetBIOS','DNSName','DNS')) {
                if ($rows[0].PSObject.Properties.Name -contains $candidate) { $colName = $candidate; break }
            }
        }
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if ($colName) {
            foreach ($r in $rows) {
                $h = ("$($r.$colName)").Trim().Trim('\','/').TrimStart('\\')
                if ($h -and $set.Add($h)) { [void]$list.Add($h) }
            }
        } else {
            ## Fallback: no recognizable column header. Treat as one host per line.
            $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
            foreach ($ln in $lines) {
                foreach ($tok in ($ln -split '[,;\t]')) {
                    $h = $tok.Trim().Trim('"').Trim('\','/').TrimStart('\\')
                    if ($h -and $set.Add($h)) { [void]$list.Add($h) }
                }
            }
        }
    } catch {
        Write-RLog "CSV import failed: $($_.Exception.Message)" "WARN"
    }
    return ,$list
}

function Build-Plan {
    ## Simultaneous-restart model (v1.2.0+). Every machine gets identical
    ## DispatchAt and RestartAt - no per-host stagger. All hosts in the
    ## plan restart at the same instant.
    ##   RestartAt  = $RestartTime (user-configured)
    ##   DispatchAt = RestartAt - LeadMinutes
    ## The dispatcher fires every shutdown command in parallel (RunspacePool
    ## concurrency) so all hosts receive their countdown popup at roughly
    ## the same moment and restart together.
    param(
        [datetime]$RestartTime,
        [int]$LeadMinutes
    )
    $script:Plan.Clear()
    $script:PlanByHost = @{}

    ## Defensive re-filter: $script:Targets is already filtered by Apply-Targets,
    ## but if the user edited the exception textbox after Apply (without re-Applying)
    ## we still want the plan to honor the latest exception state. Cheap to do here.
    $effective = @($script:Targets | Where-Object { -not $script:Exceptions.Contains($_) })
    $n = $effective.Count
    if ($n -le 0) { return }

    ## Sort targets alphabetically for predictable plan output. Operators reading
    ## the printed plan want hostnames in a stable order, not insertion order.
    $sorted = @($effective | Sort-Object { $_.ToString() })

    $dispatchAt = $RestartTime.AddMinutes(-1 * $LeadMinutes)
    foreach ($h in $sorted) {
        $row = [PSCustomObject]@{
            Host       = $h
            DispatchAt = $dispatchAt
            RestartAt  = $RestartTime
            Status     = 'Pending'
            Note       = ''
            Dispatched = $false
            ## v1.5.1: stamped when the shutdown command lands on the host.
            ## The reboot monitor's WinRM verify compares LastBootUpTime to this.
            DispatchedAt = $null
            Result     = ''
            ## Consent flow (v1.4.0) - unused unless "Require user consent" is on.
            ConsentToken    = ''
            ConsentState    = ''       # Accepted | Declined | Timeout | No-User | No-Response | Prompt-Failed
            PromptDeadline  = $null    # wall-clock backstop: force restart after this even if no result lands
            NextPollAt      = $null    # next time this Awaiting-Consent host should be polled
        }
        [void]$script:Plan.Add($row)
        $script:PlanByHost[$h] = $row
    }
}

function Save-PlanCsv {
    param([string]$Path)
    if ($script:Plan.Count -eq 0) { throw "No plan to save." }
    $rows = @()
    foreach ($r in $script:Plan) {
        $rows += [PSCustomObject]@{
            Host       = $r.Host
            DispatchAt = (Format-Hms $r.DispatchAt)
            RestartAt  = (Format-Hms $r.RestartAt)
            Status     = $r.Status
            Consent    = $r.ConsentState
            Note       = $r.Note
            Result     = $r.Result
        }
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}
#endregion

#region === DISPATCH ENGINE ===
function Init-RunspacePool {
    if ($global:RunspacePool -and $global:RunspacePool.RunspacePoolStateInfo.State -eq 'Opened') { return }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $max = [Math]::Max(1, [int]$script:MaxConcurrency)
    $global:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $max, $iss, $Host)
    $global:RunspacePool.Open()
    Write-RLog "RunspacePool opened (1-$max threads)"
}

## Per-host dispatch. Always uses Invoke-Command -ComputerName + WinRM Negotiate
## auth (matches WPT's RegKeyNotifyAndRebootBlock pattern). When $cred is $null,
## Invoke-Command uses the current Windows session's auth context - which on an
## AFNET admin's CAC-logged-in box IS the SmartCard-bound Kerberos ticket. So
## the "no creds set" path is the no-typing CAC path: just dispatch as you.
##
## Inside the remote scriptblock, shutdown.exe /r /t $sec /c $msg /f runs
## LOCALLY on the target (no /m needed; we're already in a session there).
##
## NO '2>&1' on shutdown.exe (PS 5.1 wraps stderr in ErrorRecord and
## corrupts $LASTEXITCODE - WPT v6.2.4 documented this).
$script:DispatchScriptBlock = {
    param($hostname, $action, $leadSeconds, $message, $dryRun, $cred)
    $r = @{ Host = $hostname; Action = $action; Success = $false; ExitCode = $null; Detail = $null; CompletedAt = (Get-Date); Transport = 'PSSession' }
    try {
        if ($dryRun) {
            $r.Success  = $true
            $r.ExitCode = 0
            $authNote   = if ($null -ne $cred) { "as $($cred.UserName)" } else { 'current Windows session (CAC)' }
            if ($action -eq 'Abort') {
                $r.Detail = "DRYRUN ($authNote): Invoke-Command $hostname { shutdown /a }"
            } else {
                $r.Detail = "DRYRUN ($authNote): Invoke-Command $hostname { shutdown /r /t $leadSeconds /c <msg> /f }"
            }
            return $r
        }

        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ArgumentList   = @($action, $leadSeconds, $message)
            ErrorAction    = 'Stop'
            ScriptBlock    = {
                param($act, $sec, $msg)
                ## Use Start-Process / ProcessStartInfo to capture stdout +
                ## stderr + exit code WITHOUT touching the PowerShell error
                ## stream. PS 5.1's native-command stderr handling wraps
                ## stderr in ErrorRecord objects, which Invoke-Command then
                ## reports as remote errors and corrupts the exit code.
                ## Going through ProcessStartInfo bypasses all of that.
                $o = @{ ExitCode = $null; Output = ''; Error = '' }
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName               = 'shutdown.exe'
                    $psi.UseShellExecute        = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError  = $true
                    $psi.CreateNoWindow         = $true
                    if ($act -eq 'Abort') {
                        $psi.Arguments = '/a'
                    } else {
                        ## Quote the message so spaces survive
                        $msgArg = '"' + ($msg -replace '"','\"') + '"'
                        $psi.Arguments = "/r /t $sec /c $msgArg /f"
                    }
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $stdout = $p.StandardOutput.ReadToEnd()
                    $stderr = $p.StandardError.ReadToEnd()
                    if (-not $p.WaitForExit(30000)) {
                        try { $p.Kill() } catch {}
                        $o.ExitCode = -1
                        $o.Output   = 'shutdown.exe timed out after 30s'
                    } else {
                        $o.ExitCode = $p.ExitCode
                        $o.Output   = (($stdout + $stderr) | Out-String).Trim()
                    }
                } catch {
                    $o.Error = $_.Exception.Message
                }
                return $o
            }
        }
        ## -Credential is OPTIONAL. With it, dispatch authenticates as that
        ## principal. Without it, the current session's auth (your CAC-bound
        ## Kerberos ticket) is used - no typing, no PIN re-prompt.
        if ($null -ne $cred) { $icArgs['Credential'] = $cred }

        $remote = Invoke-Command @icArgs
        if ($remote.Error) {
            $r.ExitCode = -3
            $r.Detail   = "remote: $($remote.Error)"
        } else {
            $r.ExitCode = [int]$remote.ExitCode
            $r.Detail   = if ($remote.Output) { $remote.Output.Substring(0, [Math]::Min(500, $remote.Output.Length)) } else { '' }
            ## Treat 1190 (ERROR_SHUTDOWN_IS_SCHEDULED) as success - it means
            ## the target already has a pending shutdown which is exactly the
            ## end state we want. Common when a Test Single Host or earlier
            ## dispatch already scheduled this host.
            $r.Success  = (($r.ExitCode -eq 0) -or ($r.ExitCode -eq 1190))
        }
    } catch {
        $r.ExitCode = -4
        $r.Detail   = "Invoke-Command failed: $($_.Exception.Message)"
    }
    return $r
}

#region === USER CONSENT SUBSYSTEM (v1.4.0) ===
## Puts an Accept / Decline dialog on the logged-on user's screen before a
## restart. WinRM lands in session 0 (non-interactive) where a dialog is
## invisible, so we stage a tiny self-contained agent on the target and run
## it AS THE INTERACTIVE USER via a one-shot scheduled task (schtasks /IT).
## The agent only records the choice to a local result file; the DISPATCHER
## reads it back over WinRM and performs the actual restart with its own
## admin rights. No shared storage, no end-user network access required.

## The interactive consent agent. Staged on the target as agent_<token>.ps1
## and launched in the user's session. Single-quoted here-string: every $ is
## literal (it's the agent's own code); only __TOKEN__ is substituted per host.
$script:ConsentAgentTemplate = @'
# === JANET Consent Agent === runs in the interactive user's session ===
$ErrorActionPreference = 'Stop'
$token      = '__TOKEN__'
$dir        = Join-Path $env:ProgramData 'JANET\Consent'
$cfgPath    = Join-Path $dir ("cfg_$token.json")
$resultPath = Join-Path $dir ("result_$token.json")

function Write-ConsentResult([string]$decision) {
    $o = [ordered]@{
        Token     = $token
        Decision  = $decision
        User      = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        DecidedAt = (Get-Date).ToString('o')
    }
    try { ($o | ConvertTo-Json -Compress) | Out-File -FilePath $resultPath -Encoding UTF8 -Force } catch {}
}

try { $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json }
catch { Write-ConsentResult 'AgentError'; return }

$promptSecs = [int]$cfg.PromptSeconds
$message    = [string]$cfg.Message

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text            = 'System Restart Required'
$form.Size            = New-Object System.Drawing.Size(580, 360)
$form.StartPosition   = 'CenterScreen'
$form.TopMost         = $true
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox     = $false
$form.MinimizeBox     = $false
$form.ShowInTaskbar   = $true
$form.BackColor       = [System.Drawing.Color]::FromArgb(28, 24, 38)
$form.ForeColor       = [System.Drawing.Color]::White

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = 'Scheduled System Restart'
$lblTitle.Font      = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::Gold
$lblTitle.Location  = New-Object System.Drawing.Point(24, 18)
$lblTitle.Size      = New-Object System.Drawing.Size(520, 32)
$form.Controls.Add($lblTitle)

$lblMsg = New-Object System.Windows.Forms.Label
$lblMsg.Text      = $message
$lblMsg.Font      = New-Object System.Drawing.Font('Segoe UI', 11)
$lblMsg.Location  = New-Object System.Drawing.Point(24, 60)
$lblMsg.Size      = New-Object System.Drawing.Size(525, 120)
$form.Controls.Add($lblMsg)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Font      = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Italic)
$lblCount.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
$lblCount.Location  = New-Object System.Drawing.Point(24, 188)
$lblCount.Size      = New-Object System.Drawing.Size(525, 44)
$form.Controls.Add($lblCount)

$btnAccept = New-Object System.Windows.Forms.Button
$btnAccept.Text      = 'Restart now'
$btnAccept.Size      = New-Object System.Drawing.Size(220, 44)
$btnAccept.Location  = New-Object System.Drawing.Point(24, 250)
$btnAccept.FlatStyle = 'Flat'
$btnAccept.BackColor = [System.Drawing.Color]::FromArgb(46, 122, 60)
$btnAccept.ForeColor = [System.Drawing.Color]::White
$btnAccept.Font      = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnAccept)

$btnDecline = New-Object System.Windows.Forms.Button
$btnDecline.Text      = 'Not now'
$btnDecline.Size      = New-Object System.Drawing.Size(220, 44)
$btnDecline.Location  = New-Object System.Drawing.Point(305, 250)
$btnDecline.FlatStyle = 'Flat'
$btnDecline.BackColor = [System.Drawing.Color]::FromArgb(90, 70, 40)
$btnDecline.ForeColor = [System.Drawing.Color]::White
$btnDecline.Font      = New-Object System.Drawing.Font('Segoe UI', 11)
$form.Controls.Add($btnDecline)

$script:decision = $null
$btnAccept.Add_Click({ $script:decision = 'Accepted'; $form.Close() })
$btnDecline.Add_Click({ $script:decision = 'Declined'; $form.Close() })

$deadline = (Get-Date).AddSeconds($promptSecs)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $rem = [int][Math]::Ceiling((($deadline) - (Get-Date)).TotalSeconds)
    if ($rem -le 0) { $script:decision = 'Timeout'; $timer.Stop(); $form.Close(); return }
    $mm = [int]($rem / 60); $ss = $rem % 60
    $lblCount.Text = ("If you do not choose, this computer will restart automatically in {0}:{1:00}." -f $mm, $ss)
})
$timer.Start()
$form.Add_FormClosing({ $timer.Stop() })
[void]$form.ShowDialog()
if (-not $script:decision) { $script:decision = 'Timeout' }
Write-ConsentResult $script:decision

# Best-effort self-clean. The dispatcher also cleans up over WinRM, so a
# failure here (e.g. a limited user can't delete an admin-created task) is fine.
try { schtasks.exe /Delete /TN ('JANET\Consent_' + $token) /F 2>$null | Out-Null } catch {}
try { Remove-Item -LiteralPath $cfgPath -Force -ErrorAction SilentlyContinue } catch {}
try {
    $self = $MyInvocation.MyCommand.Path
    if ($self) { Start-Sleep -Milliseconds 300; Remove-Item -LiteralPath $self -Force -ErrorAction SilentlyContinue }
} catch {}
'@

## Runspace job: detect the interactive user, stage the agent + config on the
## target, and register/run a one-shot interactive scheduled task. Returns a
## shaped status: Prompt-Launched | No-User | Launch-Failed.
$script:ConsentLaunchScriptBlock = {
    param($hostname, $cred, $token, $agentScript, $cfgJson)
    $r = @{ Host = $hostname; Phase = 'ConsentLaunch'; Status = 'Launch-Failed'; User = $null; Detail = ''; CompletedAt = (Get-Date) }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 60000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ArgumentList   = @($token, $agentScript, $cfgJson)
            ScriptBlock    = {
                param($tok, $agent, $cfg)
                $res = @{ Status = 'Launch-Failed'; User = $null; Detail = '' }
                try {
                    $dir = Join-Path $env:ProgramData 'JANET\Consent'
                    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                    ## Open this one folder so a standard/STIG interactive user can
                    ## write its result file. Scoped grant, not a blanket loosen.
                    ## *>$null on every native exe below: PS 5.1 wraps native
                    ## stderr as ErrorRecords which, under the outer
                    ## Invoke-Command -ErrorAction Stop, would throw even on
                    ## success. Redirect all streams and read $LASTEXITCODE.
                    try { & icacls.exe $dir /grant '*S-1-5-11:(OI)(CI)M' /T /C /Q *>$null } catch {}

                    ## Who is on the console? UserName covers the primary interactive
                    ## user; explorer.exe owner is the RDP/secondary fallback.
                    $user = $null
                    try { $user = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
                    if (-not $user) {
                        try {
                            $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
                            if ($ex) {
                                $own = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction Stop
                                if ($own.User) { $user = ("{0}\{1}" -f $own.Domain, $own.User) }
                            }
                        } catch {}
                    }
                    if (-not $user) { $res.Status = 'No-User'; return $res }
                    $res.User = $user

                    $agentPath  = Join-Path $dir ("agent_$tok.ps1")
                    $cfgPath    = Join-Path $dir ("cfg_$tok.json")
                    $resultPath = Join-Path $dir ("result_$tok.json")
                    $enc = New-Object System.Text.UTF8Encoding($false)
                    [System.IO.File]::WriteAllText($agentPath, $agent, $enc)
                    [System.IO.File]::WriteAllText($cfgPath,   $cfg,   $enc)
                    if (Test-Path $resultPath) { Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue }

                    $taskName = 'JANET\Consent_' + $tok
                    $tr = 'powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $agentPath + '"'
                    & schtasks.exe /Delete /TN $taskName /F *>$null
                    ## /ST is a required field even though we /Run immediately; park it
                    ## an hour out so it never auto-fires on its own.
                    $st = (Get-Date).AddHours(1).ToString('HH:mm')
                    & schtasks.exe /Create /TN $taskName /TR $tr /SC ONCE /ST $st /RU $user /IT /RL LIMITED /F *>$null
                    $rcCreate = $LASTEXITCODE
                    if ($rcCreate -ne 0) { $res.Detail = "schtasks /Create rc=$rcCreate (user=$user)"; return $res }
                    & schtasks.exe /Run /TN $taskName *>$null
                    $rcRun = $LASTEXITCODE
                    if ($rcRun -ne 0) { $res.Detail = "schtasks /Run rc=$rcRun"; return $res }
                    $res.Status = 'Prompt-Launched'
                } catch {
                    $res.Detail = $_.Exception.Message
                }
                return $res
            }
        }
        if ($null -ne $cred) { $icArgs['Credential'] = $cred }
        $remote = Invoke-Command @icArgs
        $r.Status = [string]$remote.Status
        $r.User   = [string]$remote.User
        $r.Detail = [string]$remote.Detail
    } catch {
        $r.Status = 'Launch-Failed'
        $r.Detail = "Invoke-Command failed: $($_.Exception.Message)"
    }
    return $r
}

## Runspace job: read the result file back over WinRM. When a terminal result
## is present, also clean up the task + staged files (we have admin rights on
## the target; the limited-user agent may not be able to). Returns Found flag
## plus the Decision the user (or timeout) produced.
$script:ConsentPollScriptBlock = {
    param($hostname, $cred, $token)
    $r = @{ Host = $hostname; Phase = 'ConsentPoll'; Found = $false; Decision = $null; User = $null; Detail = ''; CompletedAt = (Get-Date) }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ArgumentList   = @($token)
            ScriptBlock    = {
                param($tok)
                $o = @{ Found = $false; Decision = $null; User = $null }
                try {
                    $dir        = Join-Path $env:ProgramData 'JANET\Consent'
                    $resultPath = Join-Path $dir ("result_$tok.json")
                    if (Test-Path $resultPath) {
                        $j = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json
                        $o.Found    = $true
                        $o.Decision = [string]$j.Decision
                        $o.User     = [string]$j.User
                        ## Terminal: tidy up so we don't leave 2000 files/tasks behind.
                        ## *>$null: keep native stderr from tripping -ErrorAction Stop.
                        try { & schtasks.exe /Delete /TN ('JANET\Consent_' + $tok) /F *>$null } catch {}
                        foreach ($f in @("agent_$tok.ps1", "cfg_$tok.json", "result_$tok.json")) {
                            try { Remove-Item -LiteralPath (Join-Path $dir $f) -Force -ErrorAction SilentlyContinue } catch {}
                        }
                    }
                } catch {}
                return $o
            }
        }
        if ($null -ne $cred) { $icArgs['Credential'] = $cred }
        $remote = Invoke-Command @icArgs
        $r.Found    = [bool]$remote.Found
        $r.Decision = [string]$remote.Decision
        $r.User     = [string]$remote.User
    } catch {
        $r.Detail = "poll failed: $($_.Exception.Message)"
    }
    return $r
}

function Submit-ConsentJob {
    ## Mirror of Submit-DispatchJob for the consent phases. Tags the job with a
    ## Phase so Reap-CompletedJobs routes the result correctly.
    param(
        [Parameter(Mandatory)] [string]$Hostname,
        [Parameter(Mandatory)] [ValidateSet('ConsentLaunch','ConsentPoll')] [string]$Phase,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object[]]$Arguments = @(),
        $Row,
        $Credential = $null
    )
    Init-RunspacePool
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $global:RunspacePool
    [void]$ps.AddScript($ScriptBlock)
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $async = $ps.BeginInvoke()
    $global:ActiveJobs[$Hostname] = @{
        PS          = $ps
        Async       = $async
        SubmittedAt = (Get-Date)
        Row         = $Row
        Action      = $Phase
        Phase       = $Phase
    }
    $script:Stats.InFlight = $global:ActiveJobs.Count
}
#endregion

function Submit-DispatchJob {
    param(
        [Parameter(Mandatory)] [string]$Hostname,
        [Parameter(Mandatory)] [ValidateSet('Dispatch','Abort')] [string]$Action,
        [int]$LeadSeconds = 900,
        [string]$Message  = '',
        [bool]$DryRun     = $false,
        $Row,
        $Credential = $null
    )
    Init-RunspacePool
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $global:RunspacePool
    [void]$ps.AddScript($script:DispatchScriptBlock)
    [void]$ps.AddArgument($Hostname)
    [void]$ps.AddArgument($Action)
    [void]$ps.AddArgument($LeadSeconds)
    [void]$ps.AddArgument($Message)
    [void]$ps.AddArgument($DryRun)
    [void]$ps.AddArgument($Credential)
    $async = $ps.BeginInvoke()
    $global:ActiveJobs[$Hostname] = @{
        PS          = $ps
        Async       = $async
        SubmittedAt = (Get-Date)
        Row         = $Row
        Action      = $Action
        Phase       = $Action
        LeadSeconds = $LeadSeconds
    }
    $script:Stats.InFlight = $global:ActiveJobs.Count
}

function Reap-CompletedJobs {
    if ($global:ActiveJobs.Count -eq 0) { return 0 }
    $reaped = 0
    $doneKeys = @()
    foreach ($k in @($global:ActiveJobs.Keys)) {
        $j = $global:ActiveJobs[$k]
        if ($j.Async.IsCompleted) { $doneKeys += $k }
    }
    foreach ($k in $doneKeys) {
        $j = $global:ActiveJobs[$k]
        $result = $null
        try { $result = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $result = $null }
        try { $j.PS.Dispose() } catch {}
        $global:ActiveJobs.Remove($k)
        $reaped++

        $row = $j.Row

        ## --- Consent phases (v1.4.0). These set the row's next Status; the
        ## actual restart is submitted from Tick-Dispatch when a row reaches
        ## 'Consent-Approved', reusing the proven dispatch path. ---
        if ($j.Phase -eq 'ConsentLaunch') {
            $status = if ($null -ne $result) { [string]$result.Status } else { 'Launch-Failed' }
            switch ($status) {
                'Prompt-Launched' {
                    if ($row) {
                        $row.Status         = 'Awaiting-Consent'
                        $row.PromptDeadline = (Get-Date).AddSeconds([int]$script:ConsentPromptSeconds + 20)
                        $row.NextPollAt     = (Get-Date).AddSeconds(8)
                        $row.Result         = "Prompt shown to $($result.User)"
                    }
                    Log-Activity ("PROMPT    {0}  asked {1}" -f $k, $result.User) $colors.Cyan
                }
                'No-User' {
                    ## Nobody to ask - policy: restart proceeds.
                    if ($row) { $row.Status = 'Consent-Approved'; $row.ConsentState = 'No-User'; $row.Result = 'No user logged on - restarting' }
                    $script:Stats.Awaiting = [Math]::Max(0, $script:Stats.Awaiting - 1)
                    Log-Activity ("NO-USER   {0}  no one logged on - proceeding" -f $k) $colors.Warning
                }
                default {
                    ## Couldn't show a prompt (WinRM/schtasks issue). Closest policy
                    ## match is the no-user outcome: proceed, but flag it loudly.
                    $d = if ($null -ne $result) { [string]$result.Detail } else { 'no result' }
                    if ($row) { $row.Status = 'Consent-Approved'; $row.ConsentState = 'Prompt-Failed'; $row.Result = "Prompt launch failed - restarting anyway ($d)" }
                    $script:Stats.Awaiting = [Math]::Max(0, $script:Stats.Awaiting - 1)
                    Log-Activity ("PRMT-FAIL {0}  {1} - proceeding" -f $k, $d) $colors.Danger
                }
            }
            continue
        }
        if ($j.Phase -eq 'ConsentPoll') {
            $found    = ($null -ne $result) -and ([bool]$result.Found)
            $decision = if ($found) { [string]$result.Decision } else { '' }
            if ($found -and $decision -eq 'Declined') {
                if ($row) { $row.Status = 'Declined'; $row.ConsentState = 'Declined'; $row.Result = "Declined by $($result.User)" }
                $script:Stats.Awaiting  = [Math]::Max(0, $script:Stats.Awaiting - 1)
                $script:Stats.Declined++
                Log-Activity ("DECLINED  {0}  by {1} - skipped this run" -f $k, $result.User) $colors.Warning
            }
            elseif ($found -and ($decision -eq 'Accepted' -or $decision -eq 'Timeout')) {
                $how = if ($decision -eq 'Accepted') { "Accepted by $($result.User)" } else { 'No response (timeout) - proceeding' }
                if ($row) { $row.Status = 'Consent-Approved'; $row.ConsentState = $decision; $row.Result = $how }
                $script:Stats.Awaiting = [Math]::Max(0, $script:Stats.Awaiting - 1)
                $tag = if ($decision -eq 'Accepted') { 'ACCEPTED' } else { 'TIMEOUT ' }
                Log-Activity ("$tag  {0}  {1}" -f $k, $how) $colors.Success
            }
            elseif ($found) {
                ## v1.5.0-beta3 review-fix: a result file WAS written but with an
                ## unexpected decision (e.g. 'AgentError' - the on-target agent
                ## couldn't read its own config). The poller already deleted the
                ## file, so we can't keep waiting (it would silently fall through
                ## to the No-Response backstop and reboot unconsented). Surface it
                ## distinctly and proceed, mirroring the ConsentLaunch Prompt-Failed
                ## policy.
                if ($row) { $row.Status = 'Consent-Approved'; $row.ConsentState = 'Agent-Failed'; $row.Result = "Consent agent error ($decision) - proceeding" }
                $script:Stats.Awaiting = [Math]::Max(0, $script:Stats.Awaiting - 1)
                Log-Activity ("AGENT-ERR {0}  consent agent error ({1}) - proceeding" -f $k, $decision) $colors.Danger
            }
            else {
                ## No result yet. Either keep waiting, or - if the agent never
                ## wrote one (user logged off mid-prompt) - hit the wall-clock
                ## backstop and proceed.
                if ($row -and $row.PromptDeadline -and ((Get-Date) -ge $row.PromptDeadline)) {
                    $row.Status = 'Consent-Approved'; $row.ConsentState = 'No-Response'; $row.Result = 'No response within window - proceeding'
                    $script:Stats.Awaiting = [Math]::Max(0, $script:Stats.Awaiting - 1)
                    Log-Activity ("NO-RESP   {0}  window elapsed - proceeding" -f $k) $colors.Warning
                } elseif ($row) {
                    $row.Status     = 'Awaiting-Consent'
                    $row.NextPollAt = (Get-Date).AddSeconds([int]$script:ConsentPollInterval)
                }
            }
            continue
        }

        if ($null -ne $result) {
            if ($j.Action -eq 'Abort') {
                if ($result.Success) {
                    if ($row) { $row.Status = 'Aborted'; $row.Result = "Aborted (rc=$($result.ExitCode))" }
                    $script:Stats.Aborted++
                    Log-Activity ("ABORT OK   {0}" -f $k) $colors.Warning
                } else {
                    $detail = if ($result.Detail) { " - $($result.Detail)" } else { '' }
                    if ($row) { $row.Status = 'Abort Failed'; $row.Result = "rc=$($result.ExitCode)$detail" }
                    Log-Activity ("ABORT FAIL {0}  rc={1}{2}" -f $k, $result.ExitCode, $detail) $colors.Danger
                }
            } else {
                if ($result.Success) {
                    ## 1190 = ALREADY-SCHEDULED: target already had a pending
                    ## shutdown when we got there. Counts as success but the
                    ## log line says so explicitly.
                    $isAlready = ($result.ExitCode -eq 1190)
                    $statusText = if ($isAlready) { 'Already-Scheduled' } else { 'Dispatched' }
                    $resultText = if ($isAlready) { "Already scheduled (rc=1190)" } else { "OK (rc=$($result.ExitCode))" }
                    $logTag     = if ($isAlready) { 'ALREADY' } else { 'SENT   ' }
                    if ($row) { $row.Status = $statusText; $row.Result = $resultText; $row.DispatchedAt = Get-Date }
                    $script:Stats.Sent++
                    try { Write-JanetAction -Action 'TouchHost' -Target $k -Result 'Success' -Detail "shutdown /r /t $($j.LeadSeconds) rc=$($result.ExitCode)" } catch {}
                    $logColor = if ($isAlready) { $colors.Warning } else { $colors.Success }
                    Log-Activity ("$logTag    {0}  restart {1}" -f $k, (Format-Hms $row.RestartAt)) $logColor
                } else {
                    $detail = if ($result.Detail) { " - $($result.Detail)" } else { '' }
                    if ($row) { $row.Status = 'Failed'; $row.Result = "rc=$($result.ExitCode)$detail" }
                    $script:Stats.Failed++
                    try { Write-JanetAction -Action 'TouchHost' -Target $k -Result 'Failure' -Detail ("rc={0}{1}" -f $result.ExitCode, $detail) } catch {}
                    Log-Activity ("FAIL      {0}  rc={1}{2}" -f $k, $result.ExitCode, $detail) $colors.Danger
                }
            }
        } else {
            if ($row) { $row.Status = 'Failed'; $row.Result = 'No result returned' }
            $script:Stats.Failed++
            Log-Activity ("FAIL      {0}  (no result)" -f $k) $colors.Danger
        }
    }
    $script:Stats.InFlight = $global:ActiveJobs.Count
    return $reaped
}

function Send-RemoteAbortFanOut {
    ## Issues `shutdown /m \\HOST /a` to every machine in the plan that's
    ## been Dispatched but not yet Aborted. Bypasses the time-gated tick
    ## loop - all are submitted immediately into the pool.
    ## v1.5.0-beta3 review-fix: 'Already-Scheduled' (rc=1190) hosts DO have a
    ## pending reboot and must be abortable too - filtering only 'Dispatched'
    ## left exactly the guaranteed-to-reboot hosts un-cancellable.
    $abortable = @('Dispatched','Already-Scheduled')
    $count = 0
    foreach ($row in $script:Plan) {
        if ($abortable -contains $row.Status) {
            Submit-DispatchJob -Hostname $row.Host -Action 'Abort' -Row $row -Credential $global:Credentials
            $count++
        }
    }
    return $count
}

function Invoke-ShutdownDirect {
    ## Synchronous, single-host shutdown via Invoke-Command + WinRM Negotiate.
    ## Same pattern as the production dispatch scriptblock. When $Credential
    ## is $null, the current Windows session's auth (your CAC-bound Kerberos
    ## ticket) is used.
    param(
        [Parameter(Mandatory)] [string]$Hostname,
        [Parameter(Mandatory)] [ValidateSet('Dispatch','Abort')] [string]$Action,
        [int]$LeadSeconds = 60,
        [string]$Message  = 'TEST: this machine will restart shortly.',
        $Credential       = $null
    )
    $r = @{ Host = $Hostname; Action = $Action; Success = $false; ExitCode = $null; Stdout = ''; Stderr = ''; Detail = ''; Transport = 'PSSession' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $Hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ArgumentList   = @($Action, $LeadSeconds, $Message)
            ErrorAction    = 'Stop'
            ScriptBlock    = {
                param($act, $sec, $msg)
                ## ProcessStartInfo capture to bypass PS 5.1's native-command
                ## stderr handling. See production dispatch scriptblock for
                ## the full rationale.
                $o = @{ ExitCode = $null; Output = ''; Error = '' }
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName               = 'shutdown.exe'
                    $psi.UseShellExecute        = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError  = $true
                    $psi.CreateNoWindow         = $true
                    if ($act -eq 'Abort') {
                        $psi.Arguments = '/a'
                    } else {
                        $msgArg = '"' + ($msg -replace '"','\"') + '"'
                        $psi.Arguments = "/r /t $sec /c $msgArg /f"
                    }
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $stdout = $p.StandardOutput.ReadToEnd()
                    $stderr = $p.StandardError.ReadToEnd()
                    if (-not $p.WaitForExit(30000)) {
                        try { $p.Kill() } catch {}
                        $o.ExitCode = -1
                        $o.Output   = 'shutdown.exe timed out after 30s'
                    } else {
                        $o.ExitCode = $p.ExitCode
                        $o.Output   = (($stdout + $stderr) | Out-String).Trim()
                    }
                } catch {
                    $o.Error = $_.Exception.Message
                }
                return $o
            }
        }
        if ($null -ne $Credential) { $icArgs['Credential'] = $Credential }

        $remote = Invoke-Command @icArgs
        if ($remote.Error) {
            $r.ExitCode = -3
            $r.Stdout   = "remote: $($remote.Error)"
        } else {
            $r.ExitCode = [int]$remote.ExitCode
            $r.Stdout   = [string]$remote.Output
            ## 1190 = ERROR_SHUTDOWN_IS_SCHEDULED. Target already has a
            ## pending shutdown - the end state we want, so call it success.
            $r.Success  = (($r.ExitCode -eq 0) -or ($r.ExitCode -eq 1190))
        }
        $credNote   = if ($null -ne $Credential) { "-Credential $($Credential.UserName) " } else { '' }
        $r.Detail   = "Invoke-Command -ComputerName $Hostname $credNote-Authentication Negotiate -SessionOption <WSManOpt> { shutdown ... }"
    } catch {
        $r.ExitCode = -4
        $r.Stdout   = "Invoke-Command failed: $($_.Exception.Message)"
    }
    return $r
}

function Get-ShutdownErrorHint {
    ## Map common shutdown.exe Win32 error codes AND Invoke-Command / WinRM
    ## error strings to human hints. The pattern matchers run FIRST so a
    ## detailed WinRM error (e.g. 0x80090351) surfaces a targeted hint
    ## instead of the generic 'unknown code -4' fallback.
    param([int]$Code, [string]$Detail = '')
    if ($Detail) {
        if ($Detail -match '0x80090351|SEC_E_NO_AUTHENTICATING_AUTHORITY|no\s+authenticating\s+authority|unknown\s+security\s+error') {
            return 'WinRM auth: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY. The dispatcher could not contact an authentication authority that can validate the credential against the target. Common causes: target outside the dispatcher''s Kerberos realm / domain trust, target name needs to be added to WinRM TrustedHosts (for cross-domain or workgroup targets), or the SPN for the target is not registered in AD. Try clicking Clear (to fall back to the current CAC session) and re-running.'
        }
        if ($Detail -match 'TrustedHosts') {
            return 'Target not in the dispatcher''s WinRM TrustedHosts. Run as admin: Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<hostname-or-FQDN-or-*>" -Concatenate -Force. Workgroup / cross-forest targets always need this.'
        }
        if ($Detail -match 'The WinRM client cannot process the request') {
            return 'WinRM client config rejected the request. Inspect: winrm get winrm/config/client. May need Enable-PSRemoting or a TrustedHosts entry.'
        }
        if ($Detail -match 'destination\s+unreachable|cannot\s+find\s+the\s+computer|could\s+not\s+be\s+resolved|not\s+be\s+found') {
            return 'Target name not resolvable / not pingable. Check DNS, that the target is online, and that you''re on a network with line-of-sight to it.'
        }
        if ($Detail -match 'access\s+(is\s+)?denied|0x80070005|ERROR_ACCESS_DENIED') {
            return 'Access denied. The credential does not have local-admin rights on the target, OR User Account Control is filtering the token. Verify the account is in BUILTIN\Administrators on the target.'
        }
        if ($Detail -match 'logon\s+failure|0x8009030E|wrong\s+user\s+name\s+or\s+password|0xC000006D') {
            return 'Logon failure - bad credential. Click Clear to fall back to the current CAC session, or click Set Credentials to capture a different identity.'
        }
    }
    switch ($Code) {
        0     { return 'OK - target accepted the restart command.' }
        5     { return 'ERROR_ACCESS_DENIED - your account is not local admin on this target.' }
        53    { return 'ERROR_BAD_NETPATH - host offline, DNS lookup failed, or SMB blocked.' }
        1314  { return 'ERROR_PRIVILEGE_NOT_HELD - your account lacks SeRemoteShutdownPrivilege on the target.' }
        1722  { return 'RPC_S_SERVER_UNAVAILABLE - RPC blocked (firewall TCP 135 / dynamic ports) or target''s RPC service is down.' }
        1727  { return 'RPC_S_NO_MORE_ENDPOINTS - Remote Registry / RPC endpoint mapper not serving requests.' }
        1115  { return 'ERROR_SHUTDOWN_IN_PROGRESS - target already has a pending shutdown. Use Abort first.' }
        1116  { return 'ERROR_NO_SHUTDOWN_IN_PROGRESS - no scheduled shutdown to abort on this target.' }
        1190  { return 'ALREADY SCHEDULED - target already has a pending restart from a prior dispatch (or another tool). Treated as success: the target IS going to restart. Use Abort if you want to cancel and reschedule.' }
        -1    { return 'Tool-side timeout - shutdown.exe took > 60 seconds and was killed.' }
        -2    { return 'Tool-side exception while spawning shutdown.exe (see Detail).' }
        -3    { return 'Remote scriptblock threw - target reached but shutdown.exe failed (see Detail).' }
        -4    { return 'Invoke-Command failed to complete. Common causes: WinRM not enabled on target (Enable-PSRemoting), TCP 5985 blocked, target in a Kerberos realm the dispatcher can''t reach, target name not in TrustedHosts (for cross-domain/workgroup), or hostname not resolvable.' }
        default { return "Unknown shutdown.exe return code $Code - look it up: net helpmsg $Code" }
    }
}

function Show-RrsCredentialDialog {
    ## Custom credential capture that bypasses Get-Credential entirely.
    ## Plain TextBox for username + masked TextBox for password. No Windows
    ## credential picker, no MSA-account substitution, no pre-filled fields.
    ## Whatever the operator types in the username box is what gets stored.
    ##
    ## Returns [PSCredential] on OK, $null on Cancel.
    param([string]$DefaultUserName = '')

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text          = 'Set Credentials - J.A.N.E.T. Remote Restart Scheduler'
    $dlg.Size          = New-Object System.Drawing.Size(520, 280)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor     = $colors.Background
    $dlg.ForeColor     = $colors.TextPrimary
    $dlg.Font          = $fonts.Label
    $dlg.MaximizeBox   = $false
    $dlg.MinimizeBox   = $false
    $dlg.FormBorderStyle = 'FixedDialog'
    Set-DarkTitleBar -Form $dlg

    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text       = 'Enter admin credentials'
    $lblHdr.Location   = New-Object System.Drawing.Point(16, 12)
    $lblHdr.AutoSize   = $true
    $lblHdr.Font       = $fonts.Section
    $lblHdr.ForeColor  = $colors.Gold
    $dlg.Controls.Add($lblHdr)

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text       = "Type your username as DOMAIN\\username (e.g. AFNET\\admin-user).`r`nWhatever you type is what gets used - no Windows substitution."
    $lblHint.Location   = New-Object System.Drawing.Point(16, 40)
    $lblHint.Size       = New-Object System.Drawing.Size(480, 36)
    $lblHint.Font       = $fonts.Small
    $lblHint.ForeColor  = $colors.TextSecondary
    $dlg.Controls.Add($lblHint)

    # Username
    $lblU = New-Object System.Windows.Forms.Label
    $lblU.Text     = 'Username'
    $lblU.Location = New-Object System.Drawing.Point(16, 90)
    $lblU.Size     = New-Object System.Drawing.Size(96, 22)
    $lblU.Font     = $fonts.LabelBold
    $lblU.ForeColor = $colors.TextSecondary
    $dlg.Controls.Add($lblU)

    $tbU = New-Object System.Windows.Forms.TextBox
    $tbU.Location    = New-Object System.Drawing.Point(120, 88)
    $tbU.Size        = New-Object System.Drawing.Size(370, 24)
    $tbU.Font        = $fonts.Console
    $tbU.BackColor   = $colors.Input
    $tbU.ForeColor   = $colors.TextPrimary
    $tbU.BorderStyle = 'FixedSingle'
    $tbU.Text        = $DefaultUserName
    $dlg.Controls.Add($tbU)

    # Password
    $lblP = New-Object System.Windows.Forms.Label
    $lblP.Text     = 'Password'
    $lblP.Location = New-Object System.Drawing.Point(16, 124)
    $lblP.Size     = New-Object System.Drawing.Size(96, 22)
    $lblP.Font     = $fonts.LabelBold
    $lblP.ForeColor = $colors.TextSecondary
    $dlg.Controls.Add($lblP)

    $tbP = New-Object System.Windows.Forms.TextBox
    $tbP.Location    = New-Object System.Drawing.Point(120, 122)
    $tbP.Size        = New-Object System.Drawing.Size(370, 24)
    $tbP.Font        = $fonts.Console
    $tbP.BackColor   = $colors.Input
    $tbP.ForeColor   = $colors.TextPrimary
    $tbP.BorderStyle = 'FixedSingle'
    $tbP.UseSystemPasswordChar = $true
    $dlg.Controls.Add($tbP)

    # Buttons
    $btnOK = New-StyledButton 'OK'     (New-Object System.Drawing.Point(280, 180)) (New-Object System.Drawing.Size(100, 36)) $colors.Success
    $btnOK.DialogResult = 'OK'
    $dlg.Controls.Add($btnOK)

    $btnCancel = New-StyledButton 'Cancel' (New-Object System.Drawing.Point(390, 180)) (New-Object System.Drawing.Size(100, 36)) $colors.PanelLight
    $btnCancel.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnCancel)

    $dlg.AcceptButton = $btnOK
    $dlg.CancelButton = $btnCancel

    ## Focus the username field on open so the operator immediately types into it.
    $dlg.Add_Shown({ $tbU.Focus() | Out-Null })

    $cred = $null
    if ($dlg.ShowDialog() -eq 'OK') {
        $u = $tbU.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($u)) {
            [System.Windows.Forms.MessageBox]::Show('Username cannot be empty.', 'Set Credentials', 'OK', 'Warning') | Out-Null
        } else {
            $secure = New-Object System.Security.SecureString
            foreach ($ch in $tbP.Text.ToCharArray()) { $secure.AppendChar($ch) }
            $secure.MakeReadOnly()
            $cred = New-Object System.Management.Automation.PSCredential ($u, $secure)
        }
    }
    $dlg.Dispose()
    return $cred
}

function Show-TestRestartDialog {
    ## Small modal dialog: enter ONE hostname, fire a single shutdown.exe,
    ## show the exact exit code + stdout + stderr + a plain-English hint.
    ## Use this BEFORE the 4000-machine run to confirm the operator has the
    ## right permissions and the network path to a known-good test target.
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text          = 'Test single host - J.A.N.E.T. Remote Restart Scheduler'
    $dlg.Size          = New-Object System.Drawing.Size(640, 600)
    $dlg.MinimumSize   = New-Object System.Drawing.Size(560, 540)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor     = $colors.Background
    $dlg.ForeColor     = $colors.TextPrimary
    $dlg.Font          = $fonts.Label
    $dlg.MaximizeBox   = $false
    $dlg.MinimizeBox   = $false
    Set-DarkTitleBar -Form $dlg

    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text       = 'Single-host pre-flight check'
    $lblHdr.Location   = New-Object System.Drawing.Point(16, 12)
    $lblHdr.AutoSize   = $true
    $lblHdr.Font       = $fonts.Section
    $lblHdr.ForeColor  = $colors.Gold
    $dlg.Controls.Add($lblHdr)

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text       = "Fires one shutdown.exe /m \\HOST /r /t SECONDS /c <msg> /f against the host you enter below. Verify that:`r`n  1. Exit code 0 returns,`r`n  2. The Windows shutdown countdown popup appears on the target,`r`n  3. The machine actually reboots (or use Cancel to abort)."
    $lblHint.Location   = New-Object System.Drawing.Point(16, 40)
    $lblHint.Size       = New-Object System.Drawing.Size(600, 78)
    $lblHint.Font       = $fonts.Small
    $lblHint.ForeColor  = $colors.TextSecondary
    $dlg.Controls.Add($lblHint)

    # Hostname
    $lblH = New-Object System.Windows.Forms.Label
    $lblH.Text       = 'Hostname'
    $lblH.Location   = New-Object System.Drawing.Point(16, 132)
    $lblH.Size       = New-Object System.Drawing.Size(120, 22)
    $lblH.Font       = $fonts.LabelBold
    $lblH.ForeColor  = $colors.TextSecondary
    $dlg.Controls.Add($lblH)

    $tbH = New-Object System.Windows.Forms.TextBox
    $tbH.Location    = New-Object System.Drawing.Point(140, 130)
    $tbH.Size        = New-Object System.Drawing.Size(280, 24)
    $tbH.Font        = $fonts.Console
    $tbH.BackColor   = $colors.Input
    $tbH.ForeColor   = $colors.TextPrimary
    $tbH.BorderStyle = 'FixedSingle'
    if ($script:Targets.Count -gt 0) { $tbH.Text = $script:Targets[0] }
    $dlg.Controls.Add($tbH)

    # /t seconds
    $lblT = New-Object System.Windows.Forms.Label
    $lblT.Text       = 'Countdown (/t seconds)'
    $lblT.Location   = New-Object System.Drawing.Point(16, 168)
    $lblT.Size       = New-Object System.Drawing.Size(120, 22)
    $lblT.Font       = $fonts.LabelBold
    $lblT.ForeColor  = $colors.TextSecondary
    $dlg.Controls.Add($lblT)

    $numT = New-Object System.Windows.Forms.NumericUpDown
    $numT.Location = New-Object System.Drawing.Point(140, 166)
    $numT.Size     = New-Object System.Drawing.Size(100, 24)
    $numT.Minimum  = 30
    $numT.Maximum  = 3600
    $numT.Value    = 60
    $numT.Font     = $fonts.Label
    $dlg.Controls.Add($numT)

    $lblTHint = New-Object System.Windows.Forms.Label
    $lblTHint.Text       = '60s default = quick popup, fast verify. Bump to 600+ if you want time to validate before reboot.'
    $lblTHint.Location   = New-Object System.Drawing.Point(250, 170)
    $lblTHint.Size       = New-Object System.Drawing.Size(360, 18)
    $lblTHint.Font       = $fonts.Small
    $lblTHint.ForeColor  = $colors.TextDim
    $dlg.Controls.Add($lblTHint)

    # Buttons
    $btnFire = New-StyledButton 'Fire test restart' (New-Object System.Drawing.Point(16, 206)) (New-Object System.Drawing.Size(180, 36)) $colors.Danger
    $dlg.Controls.Add($btnFire)
    $btnAbort = New-StyledButton 'Abort scheduled restart' (New-Object System.Drawing.Point(204, 206)) (New-Object System.Drawing.Size(200, 36)) $colors.Warning
    $dlg.Controls.Add($btnAbort)
    $btnClose = New-StyledButton 'Close' (New-Object System.Drawing.Point(508, 206)) (New-Object System.Drawing.Size(100, 36)) $colors.PanelLight
    $btnClose.Anchor = 'Top,Right'
    $dlg.Controls.Add($btnClose)

    # Output
    $tbOut = New-Object System.Windows.Forms.TextBox
    $tbOut.Location    = New-Object System.Drawing.Point(16, 254)
    $tbOut.Size        = New-Object System.Drawing.Size(592, 296)
    $tbOut.Anchor      = 'Top,Bottom,Left,Right'
    $tbOut.Multiline   = $true
    $tbOut.ReadOnly    = $true
    $tbOut.ScrollBars  = 'Vertical'
    $tbOut.Font        = $fonts.Console
    $tbOut.BackColor   = $colors.OutputBg
    $tbOut.ForeColor   = $colors.Console
    $tbOut.BorderStyle = 'FixedSingle'
    $dlg.Controls.Add($tbOut)

    $appendOut = {
        param([string]$Line)
        $tbOut.AppendText($Line + "`r`n")
        $tbOut.SelectionStart = $tbOut.TextLength
        $tbOut.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }

    $runTest = {
        param([string]$Action)
        $h = $tbH.Text.Trim().Trim('\','/').TrimStart('\\')
        if ([string]::IsNullOrWhiteSpace($h)) {
            & $appendOut 'ERROR: enter a hostname first.'
            return
        }
        $t = [int]$numT.Value
        $btnFire.Enabled  = $false
        $btnAbort.Enabled = $false
        try {
            & $appendOut ("[{0}]  Action: {1}   Target: {2}   /t: {3}s" -f (Get-Date -Format 'HH:mm:ss'), $Action, $h, $t)
            $authNote = if ($null -ne $global:Credentials) { "as $($global:Credentials.UserName) via PSSession (WinRM)" } else { 'as current user via RPC' }
            & $appendOut ("       auth:    $authNote")
            $msg = "TEST: J.A.N.E.T. Remote Restart Scheduler pre-flight check. This machine will restart in approximately $([Math]::Round($t/60.0,1)) minute(s)."
            if ($null -ne $global:Credentials) {
                & $appendOut ("       running: Invoke-Command -ComputerName $h -Credential $($global:Credentials.UserName) -Authentication Negotiate -SessionOption <WSManOpt>")
                & $appendOut ("                                -ScriptBlock { shutdown " + $(if ($Action -eq 'Abort') { '/a' } else { "/r /t $t /c <msg> /f" }) + " }")
            } else {
                & $appendOut ("       running: shutdown.exe /m \\$h " + $(if ($Action -eq 'Abort') { '/a' } else { "/r /t $t /c <msg> /f" }))
            }
            [System.Windows.Forms.Application]::DoEvents()
            $r = Invoke-ShutdownDirect -Hostname $h -Action $Action -LeadSeconds $t -Message $msg -Credential $global:Credentials
            & $appendOut ("       exit code: {0}" -f $r.ExitCode)
            if ($r.Stdout) { & $appendOut ('       stdout: ' + ($r.Stdout.Trim())) }
            if ($r.Stderr) { & $appendOut ('       stderr: ' + ($r.Stderr.Trim())) }
            ## Detail string concatenates stdout + stderr so pattern matchers
            ## in Get-ShutdownErrorHint can detect WinRM-specific errors that
            ## come back from Invoke-Command (e.g. 0x80090351 / TrustedHosts).
            $detailStr = (@($r.Stdout, $r.Stderr) -join ' ').Trim()
            & $appendOut ('       hint:   ' + (Get-ShutdownErrorHint -Code $r.ExitCode -Detail $detailStr))
            if ($r.Success -and $Action -eq 'Dispatch') {
                & $appendOut ''
                & $appendOut ("SUCCESS - {0} has accepted the restart command." -f $h)
                & $appendOut ("Now verify on the target box:")
                & $appendOut ("  1. A Windows shutdown countdown popup should appear within seconds.")
                & $appendOut ("  2. The machine will restart in {0}s unless you press Abort scheduled restart above." -f $t)
            } elseif ($r.Success -and $Action -eq 'Abort') {
                & $appendOut ''
                & $appendOut ("SUCCESS - pending restart on {0} has been cancelled." -f $h)
            } else {
                & $appendOut ''
                & $appendOut ("FAILED - see hint above. Fix the underlying issue, then try again.")
            }
            & $appendOut ''
        } finally {
            $btnFire.Enabled  = $true
            $btnAbort.Enabled = $true
        }
    }

    $btnFire.Add_Click({  & $runTest 'Dispatch' })
    $btnAbort.Add_Click({ & $runTest 'Abort' })
    $btnClose.Add_Click({ $dlg.Close() })

    [void]$dlg.ShowDialog()
    $dlg.Dispose()
}
#endregion

#region === SCHEDULED-TASK AUTO-DISPATCH (v1.5.0-beta) ===
## Beta capability: arm a reboot wave now, have a one-shot Windows Scheduled Task
## on THIS operator box fire the whole dispatch at the chosen time. The operator
## doesn't have to be present at 02:00 - but the per-user Accept/Decline consent
## prompt still runs on each target at fire time, so users can still refuse.
##
## Flow: GUI "Schedule as Windows Task..." -> snapshot job JSON (+ export cred)
## -> register schtasks /XML (run whether logged on or not) that re-launches
## this script with -AutoDispatch -JobFile <job>. At fire time the auto run
## replays the job into the controls, clicks Start Dispatch, then self-deletes
## its task and closes when the wave drains.

function Get-RrsJobDir {
    ## Per-user Jobs folder under the same JanetLocal tree the exception list uses.
    $dir = Get-JanetLocalDir
    if (-not $dir) {
        $base = if ($global:ScriptDir) { $global:ScriptDir } else { (Get-Location).Path }
        $dir  = Join-Path (Split-Path -Parent $base) ('JanetLocal\Remote_Restart\{0}' -f $env:USERNAME)
    }
    $jobs = Join-Path $dir 'Jobs'
    if (-not (Test-Path -LiteralPath $jobs)) {
        try { New-Item -ItemType Directory -Path $jobs -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $jobs
}

function New-RrsJobObject {
    ## Serializable snapshot of the current GUI settings + applied targets. The
    ## auto run rebuilds the plan from this at fire time (targets are NOT re-queried
    ## from AD - this tool works off an explicit applied list).
    param([datetime]$RestartTime, [int]$LeadMinutes)
    return [ordered]@{
        Schema        = 'rrs-job/1'
        Version       = $JanetRemoteRestartVersion
        CreatedBy     = $env:USERNAME
        CreatedOn     = (Format-Hms (Get-Date))
        RestartTime   = $RestartTime.ToString('yyyy-MM-dd HH:mm:ss')
        LeadMinutes   = [int]$LeadMinutes
        Concurrency   = [int]$numConc.Value
        Burst         = [bool]$chkBurst.Checked
        DryRun        = [bool]$chkDryRun.Checked
        ConsentReq    = [bool]$chkConsent.Checked
        PromptMinutes = [int]$numPromptWin.Value
        GraceSeconds  = [int]$numAcceptGrace.Value
        Preflight     = [bool]$chkPreflight.Checked   # v1.5.0-beta3: pre-flight ping gate
        SkipServers   = [bool]$chkSkipServers.Checked # v1.5.0-beta3: skip server-named hosts
        ServerPattern = [string]$tbServerPat.Text
        Rolling       = [bool]$chkRolling.Checked      # v1.5.0-beta4: rolling/go-fast mode
        RollingGrace  = [int]$numRollingGrace.Value    # v1.5.0-beta4: per-host reboot grace in rolling mode

        Message       = [string]$tbMessage.Text
        Targets       = @($script:Targets)
        Exceptions    = @($script:Exceptions)
        CredFile      = ''     # unused in the service-account model (task runs AS the account)
        RunAsUser     = ''     # the service account the task runs as (informational)
        TaskName      = ''
    }
}

function Save-RrsJob {
    param($Job, [string]$Path)
    ($Job | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Import-RrsJob {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Job file not found: $Path" }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function ConvertTo-RrsUncPath {
    ## Mapped drive letters (e.g. X:) are per-logon-session - the service account
    ## that runs the task does NOT inherit them, so a task action pointing at
    ## "X:\..." fails with "file not found". Resolve a mapped NETWORK drive to its
    ## UNC root (\\server\share\...) so the task uses a path the service account
    ## can actually reach. Local drives and already-UNC paths pass through.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($Path -like '\\*') { return $Path }
    if ($Path -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $matches[1]; $rest = $matches[2]
        try {
            $psd = Get-PSDrive -Name $drive -ErrorAction Stop
            if ($psd.DisplayRoot -and ($psd.DisplayRoot -like '\\*')) {
                return (Join-Path $psd.DisplayRoot $rest)
            }
        } catch {}
    }
    return $Path
}

function ConvertTo-RrsXmlText {
    ## Minimal XML text escaping for element/attribute values.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&apos;')
}

function New-RrsTaskXml {
    ## Build a Task Scheduler 1.2 XML definition. ISO-8601 boundaries are
    ## locale-independent (unlike schtasks /SD /ST), LogonType=Password means
    ## "run whether logged on or not", HighestAvailable elevates for schtasks
    ## on the targets. StartWhenAvailable lets a missed 02:00 still fire if the
    ## operator box was asleep; the auto run self-deletes the task afterward.
    param(
        [string]$UserId,
        [datetime]$StartAt,
        [string]$ScriptPath,
        [string]$JobPath,
        [string]$Description
    )
    $startB = $StartAt.ToString('yyyy-MM-ddTHH:mm:ss')
    $endB   = $StartAt.AddHours(12).ToString('yyyy-MM-ddTHH:mm:ss')
    $argLine = '-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}" -AutoDispatch -JobFile "{1}"' -f $ScriptPath, $JobPath
    $argEsc  = ConvertTo-RrsXmlText $argLine
    $userEsc = ConvertTo-RrsXmlText $UserId
    $descEsc = ConvertTo-RrsXmlText $Description
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$descEsc</Description>
    <Author>J.A.N.E.T. Remote Restart Scheduler $JanetRemoteRestartVersion</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$startB</StartBoundary>
      <EndBoundary>$endB</EndBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$userEsc</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>5</Priority>
    <DeleteExpiredTaskAfter>PT1H</DeleteExpiredTaskAfter>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$argEsc</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

function Register-RrsScheduledTask {
    ## Write the XML to a temp UTF-16 file and register via schtasks /Create /XML.
    ## /RU + /RP supply the password the LogonType=Password principal needs.
    ## Returns @{ Rc; Output }. Trusts $LASTEXITCODE (not $?), so the PS 5.1
    ## native-stderr-as-ErrorRecord quirk on the 2>&1 capture is harmless here.
    param([string]$TaskName, [string]$Xml, [string]$UserId, [System.Security.SecureString]$Password)
    $tmpXml = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('rrs_task_{0}.xml' -f ([guid]::NewGuid().ToString('N'))))
    [System.IO.File]::WriteAllText($tmpXml, $Xml, [System.Text.Encoding]::Unicode)
    $plain = $null
    $bstr  = [IntPtr]::Zero
    try {
        $bstr  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $out = & schtasks.exe /Create /TN $TaskName /XML $tmpXml /RU $UserId /RP $plain /F 2>&1
        $rc  = $LASTEXITCODE
        return @{ Rc = $rc; Output = ($out -join "`r`n") }
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plain = $null
        try { Remove-Item -LiteralPath $tmpXml -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function Get-RrsServiceAccountFile {
    ## Tiny per-user config that remembers ONLY the service account username
    ## (never the password) so scheduling pre-fills it next time.
    $dir = Get-JanetLocalDir
    if (-not $dir) { return $null }
    return (Join-Path $dir 'svc_account.txt')
}

function Get-RememberedServiceAccount {
    $p = Get-RrsServiceAccountFile
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return '' }
    try { return ([string](Get-Content -LiteralPath $p -Raw)).Trim() } catch { return '' }
}

function Save-RememberedServiceAccount {
    param([string]$UserName)
    $p = Get-RrsServiceAccountFile
    if (-not $p) { return }
    try { Set-Content -LiteralPath $p -Value $UserName.Trim() -Encoding UTF8 -ErrorAction Stop } catch {}
}

function Show-RrsServiceAccountDialog {
    ## Collect the SERVICE ACCOUNT the scheduled task will RUN AS. The task runs
    ## as this identity "whether logged on or not", and the 2 AM dispatch uses
    ## ITS Kerberos for WinRM - so this account must have remote-restart rights
    ## on the targets. The password is passed straight to schtasks /RP to register
    ## the task (Windows then holds it in the task's LSA secret) and is never
    ## written to a share by us. Returns [PSCredential] or $null.
    param([string]$DefaultUserName = '')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text          = 'Service account for the scheduled task'
    $dlg.Size          = New-Object System.Drawing.Size(560, 300)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor     = $colors.Background
    $dlg.ForeColor     = $colors.TextPrimary
    $dlg.Font          = $fonts.Label
    $dlg.MaximizeBox   = $false
    $dlg.MinimizeBox   = $false
    $dlg.FormBorderStyle = 'FixedDialog'
    Set-DarkTitleBar -Form $dlg

    $lblHdr = New-Object System.Windows.Forms.Label
    $lblHdr.Text      = 'Run the task as a service account'
    $lblHdr.Location  = New-Object System.Drawing.Point(16, 12)
    $lblHdr.AutoSize  = $true
    $lblHdr.Font      = $fonts.Section
    $lblHdr.ForeColor = $colors.Gold
    $dlg.Controls.Add($lblHdr)

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Text      = "Enter the service account as DOMAIN\svc-account. The task runs as this`r`naccount at the scheduled time and dispatches over WinRM using its Kerberos -`r`nso it needs remote-restart rights on the targets. The password registers the`r`ntask once (held by Windows in the task) and is never saved to a share by us."
    $lblHint.Location  = New-Object System.Drawing.Point(16, 40)
    $lblHint.Size      = New-Object System.Drawing.Size(520, 70)
    $lblHint.Font      = $fonts.Small
    $lblHint.ForeColor = $colors.TextSecondary
    $dlg.Controls.Add($lblHint)

    $lblU = New-Object System.Windows.Forms.Label
    $lblU.Text      = 'Service acct'
    $lblU.Location  = New-Object System.Drawing.Point(16, 122)
    $lblU.Size      = New-Object System.Drawing.Size(96, 22)
    $lblU.Font      = $fonts.LabelBold
    $lblU.ForeColor = $colors.TextSecondary
    $dlg.Controls.Add($lblU)

    $tbU = New-Object System.Windows.Forms.TextBox
    $tbU.Location    = New-Object System.Drawing.Point(120, 120)
    $tbU.Size        = New-Object System.Drawing.Size(400, 24)
    $tbU.Font        = $fonts.Console
    $tbU.BackColor   = $colors.Input
    $tbU.ForeColor   = $colors.TextPrimary
    $tbU.BorderStyle = 'FixedSingle'
    $tbU.Text        = $DefaultUserName
    $dlg.Controls.Add($tbU)

    $lblP = New-Object System.Windows.Forms.Label
    $lblP.Text      = 'Password'
    $lblP.Location  = New-Object System.Drawing.Point(16, 158)
    $lblP.Size      = New-Object System.Drawing.Size(96, 22)
    $lblP.Font      = $fonts.LabelBold
    $lblP.ForeColor = $colors.TextSecondary
    $dlg.Controls.Add($lblP)

    $tbP = New-Object System.Windows.Forms.TextBox
    $tbP.Location    = New-Object System.Drawing.Point(120, 156)
    $tbP.Size        = New-Object System.Drawing.Size(400, 24)
    $tbP.Font        = $fonts.Console
    $tbP.BackColor   = $colors.Input
    $tbP.ForeColor   = $colors.TextPrimary
    $tbP.BorderStyle = 'FixedSingle'
    $tbP.UseSystemPasswordChar = $true
    $dlg.Controls.Add($tbP)

    $btnOK = New-StyledButton 'Schedule' (New-Object System.Drawing.Point(320, 210)) (New-Object System.Drawing.Size(100, 36)) $colors.Success
    $btnOK.DialogResult = 'OK'
    $dlg.Controls.Add($btnOK)
    $btnCancel = New-StyledButton 'Cancel' (New-Object System.Drawing.Point(430, 210)) (New-Object System.Drawing.Size(100, 36)) $colors.PanelLight
    $btnCancel.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnCancel)
    $dlg.AcceptButton = $btnOK
    $dlg.CancelButton = $btnCancel
    ## Focus password if the username is pre-filled, else the username field.
    $dlg.Add_Shown({ if ([string]::IsNullOrWhiteSpace($tbU.Text)) { $tbU.Focus() | Out-Null } else { $tbP.Focus() | Out-Null } })

    $cred = $null
    if ($dlg.ShowDialog() -eq 'OK') {
        $u = $tbU.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($u)) {
            [System.Windows.Forms.MessageBox]::Show('Service account cannot be empty.','Schedule as Task','OK','Warning') | Out-Null
        } elseif ([string]::IsNullOrEmpty($tbP.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Password cannot be empty for a run-whether-logged-on task.','Schedule as Task','OK','Warning') | Out-Null
        } else {
            $secure = New-Object System.Security.SecureString
            foreach ($ch in $tbP.Text.ToCharArray()) { $secure.AppendChar($ch) }
            $secure.MakeReadOnly()
            $cred = New-Object System.Management.Automation.PSCredential ($u, $secure)
        }
    }
    $dlg.Dispose()
    return $cred
}

function Invoke-RrsScheduleAsTask {
    ## Handler body for the "Schedule as Windows Task..." button. Service-account
    ## model: the task RUNS AS a service account and dispatches over WinRM with
    ## that account's own Kerberos - so nothing is exported to any share. The
    ## operator still confirms (and can pick No); the per-user Accept/Decline
    ## consent prompt still fires on each target at run time.
    Apply-Targets
    if ($script:Targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No targets applied. Paste hostnames on the Targets tab and click Apply first.','Schedule as Task','OK','Warning') | Out-Null
        return
    }

    $rt        = [datetime]$dtpStart.Value
    $lead      = [int]$numLead.Value
    $consentOn = ([bool]$chkConsent.Checked) -and (-not [bool]$chkDryRun.Checked)
    $consentLead = if ($consentOn) { [int]$numPromptWin.Value } else { 0 }
    $rollingOn = [bool]$chkRolling.Checked
    ## Converge mode: fire early (RestartTime - lead - prompt) so reboots land AT
    ## RestartTime. Rolling mode: the chosen time is when the WAVE BEGINS (prompts
    ## start rolling), not a convergence reboot time - so fire AT that time.
    $startAt = if ($rollingOn) { $rt } else { $rt.AddMinutes(-1 * ($lead + $consentLead)) }
    $now     = Get-Date
    if ($startAt -le $now.AddMinutes(1)) {
        $when = if ($rollingOn) { "begin at {0} (rolling)" -f (Format-Hms $rt) } else { "start at {0} (restart {1} minus {2}-min lead{3})" -f (Format-Hms $startAt), (Format-Hms $rt), $lead, $(if ($consentOn) { " minus $consentLead-min prompt window" } else { '' }) }
        $msg = "The task would have to $when, which is in the past or under a minute away.`r`n`r`nPick a later time on the Schedule tab."
        [System.Windows.Forms.MessageBox]::Show($msg,'Schedule as Task','OK','Warning') | Out-Null
        return
    }

    ## Collect the service account the task will run as (username pre-filled from
    ## last time; password never persisted by us).
    $svcCred = Show-RrsServiceAccountDialog -DefaultUserName (Get-RememberedServiceAccount)
    if (-not $svcCred) { Log-Activity 'Schedule-as-task cancelled (no service account).' $colors.TextSecondary; return }
    $userId = $svcCred.UserName
    if ($userId -like '@@*') {
        [System.Windows.Forms.MessageBox]::Show("'$userId' looks like a CAC/smartcard identity, which cannot run an unattended task. Use a normal password-based service account (DOMAIN\svc).",'Schedule as Task','OK','Warning') | Out-Null
        return
    }

    ## Resolve mapped drives (X:) to UNC so the service-account session can reach
    ## the script + job. Build these now so the confirm dialog can warn about
    ## share access / approved-path policy before anything is registered.
    $token    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $jobDir   = Get-RrsJobDir
    $jobPath  = Join-Path $jobDir ("job_{0}.json" -f $token)
    $taskName = "JANET\RemoteRestart_$token"
    $scriptForTask = ConvertTo-RrsUncPath $global:RrsScriptPath
    $jobForTask    = ConvertTo-RrsUncPath $jobPath

    ## Path sanity. The biggest foot-gun is scheduling from the DEV/lab share:
    ## an IP-literal UNC (e.g. \\192.168.1.2\Code) won't exist on the work network,
    ## so the task would silently never find the script. Catch that loudly; then
    ## the softer notes for a generic share or an unresolvable mapped drive.
    $pathNote = ''
    if ($scriptForTask -match '^\\\\(\d{1,3}\.){3}\d{1,3}\\') {
        $pathNote = "`r`n  *** PATH STOP:  the tool is on $scriptForTask - that IP-based path looks like your DEV/lab share.`r`n                  At WORK that address won't exist and the task will never find the script.`r`n                  Copy the tool to a LOCAL path on the work box (e.g. C:\JANET\Tools) and run`r`n                  Schedule as Task FROM there. Schedule on the machine the task will run on. ***"
    } elseif ($scriptForTask -like '\\*' -or $jobForTask -like '\\*') {
        $pathNote = "`r`n  Path note:      script/job are on a network share - $userId must have READ access to it,`r`n                  and your AppLocker / PowerShell policy must allow running scripts from there.`r`n                  (At work, copying the tool to a local approved path is usually safer.)"
    } elseif ($scriptForTask -match '^[A-Za-z]:[\\/]' -and (Get-PSDrive -Name $scriptForTask.Substring(0,1) -ErrorAction SilentlyContinue).DisplayRoot) {
        $pathNote = "`r`n  Path WARNING:   the tool is on mapped drive '$($scriptForTask.Substring(0,2))', which the service account will NOT see.`r`n                  Could not resolve it to a UNC path - the task will likely fail. Run the tool from a UNC or local path."
    }

    $confirm = @"
Register a one-shot Windows Scheduled Task to run this restart wave automatically?

  Targets:        $($script:Targets.Count) machine(s)
  $(if ($rollingOn) { "Wave begins:    $(Format-Hms $rt)  (ROLLING - each host reboots ~$([int]$numRollingGrace.Value)s after it approves; no shared reboot time)" } else { "Restart time:   $(Format-Hms $rt)" })
  Task fires at:  $(Format-Hms $startAt)
  Mode:           rolling=$rollingOn  burst=$([bool]$chkBurst.Checked)  dry-run=$([bool]$chkDryRun.Checked)
  User consent:   $(if ($consentOn) { "ON - each user is still asked Accept/Decline at fire time and can decline" } else { 'OFF' })
  Runs as:        $userId  (service account, whether logged on or not)
  WinRM auth:     this service account's Kerberos - it needs remote-restart rights on the targets
  Script:         $scriptForTask$pathNote

No credential is written to any share. You can close the tool / log off after this;
the task fires on its own. Proceed?
"@
    if ([System.Windows.Forms.MessageBox]::Show($confirm,'Schedule as Windows Task','YesNo','Question') -ne 'Yes') {
        Log-Activity 'Schedule-as-task cancelled by operator.' $colors.TextSecondary
        return
    }

    ## $token / $jobDir / $jobPath / $taskName / $scriptForTask / $jobForTask
    ## were computed above (before the confirm) so the path note could be shown.
    $job = New-RrsJobObject -RestartTime $rt -LeadMinutes $lead
    $job.TaskName  = $taskName
    $job.RunAsUser = $userId
    ## CredFile stays empty: the task runs AS the service account, so the auto
    ## run dispatches with the process (service account) Kerberos - no file.

    try { Save-RrsJob -Job $job -Path $jobPath }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to save job file: $($_.Exception.Message)",'Schedule as Task','OK','Error') | Out-Null
        return
    }

    ## Reference the script + job by their UNC/local form (not a mapped drive),
    ## so the service-account session can actually find them.
    $desc = "JANET Remote Restart - one-shot auto-dispatch of $($script:Targets.Count) host(s), restart $(Format-Hms $rt), runs as $userId. Self-deletes after running."
    $xml  = New-RrsTaskXml -UserId $userId -StartAt $startAt -ScriptPath $scriptForTask -JobPath $jobForTask -Description $desc

    $res = Register-RrsScheduledTask -TaskName $taskName -Xml $xml -UserId $userId -Password $svcCred.Password
    if ($res.Rc -eq 0) {
        Save-RememberedServiceAccount -UserName $userId
        Log-Activity ("Scheduled task '{0}' registered - fires {1}, restart {2}, {3} host(s), runs as {4}." -f $taskName, (Format-Hms $startAt), (Format-Hms $rt), $script:Targets.Count, $userId) $colors.Success
        try { Write-JanetAction -Action 'TouchHost' -Target $taskName -Result 'Success' -Detail ("scheduled-task fire={0} restart={1} hosts={2} consent={3} runas={4}" -f (Format-Hms $startAt), (Format-Hms $rt), $script:Targets.Count, $consentOn, $userId) } catch {}
        [System.Windows.Forms.MessageBox]::Show(
            ("Scheduled.`r`n`r`nTask: {0}`r`nFires: {1}`r`nRestart: {2}`r`nHosts: {3}`r`nRuns as: {4}`r`n`r`nYou can close the tool and log off. Users will still get the Accept/Decline prompt at fire time." -f $taskName, (Format-Hms $startAt), (Format-Hms $rt), $script:Targets.Count, $userId),
            'Schedule as Windows Task', 'OK', 'Information') | Out-Null
    } else {
        Write-RLog "schtasks /Create failed rc=$($res.Rc): $($res.Output)" 'ERROR'
        Log-Activity ("Scheduled task registration FAILED (rc={0}). {1}" -f $res.Rc, $res.Output) $colors.Danger
        ## Clean up the orphaned job so a failed attempt leaves nothing behind.
        try { Remove-Item -LiteralPath $jobPath -Force -ErrorAction SilentlyContinue } catch {}
        [System.Windows.Forms.MessageBox]::Show(
            ("Failed to register the scheduled task (rc={0}).`r`n`r`n{1}`r`n`r`nCommon causes: wrong password, the service account lacks 'Log on as a batch job' on this machine, or you lack permission to create tasks." -f $res.Rc, $res.Output),
            'Schedule as Windows Task', 'OK', 'Error') | Out-Null
    }
}

function Start-RrsAutoDispatch {
    ## Fired from the form's Shown event when launched with -AutoDispatch. Loads
    ## the job, replays it into the controls, and clicks Start Dispatch. The wave
    ## then runs through the exact same engine (including the per-user consent
    ## prompt) a manual click uses. Tick-Dispatch self-closes us when it drains.
    if (-not $script:AutoMode) { return }
    if ([string]::IsNullOrWhiteSpace($script:AutoJobFile)) {
        Write-RLog 'AUTO MODE: no -JobFile supplied; nothing to dispatch.' 'ERROR'
        Set-JanetAllowClose $true; try { $f.Close() } catch {}; return
    }
    try {
        Log-Activity ("AUTO MODE: loading job {0}" -f $script:AutoJobFile) $colors.Gold
        $job = Import-RrsJob -Path $script:AutoJobFile
        $script:AutoTaskName = [string]$job.TaskName

        ## Credential model. Service-account jobs carry NO CredFile: the task runs
        ## AS the service account, so we dispatch with the process's own identity
        ## (null cred => Invoke-Command uses current-session Kerberos). A CredFile
        ## (legacy / explicit-cred path) is honored if present and decryptable.
        $cf = [string]$job.CredFile
        if ($cf -and (Test-Path -LiteralPath $cf)) {
            try { $global:Credentials = Import-Clixml -LiteralPath $cf; try { Refresh-CredStatus } catch {} ; Write-RLog "AUTO MODE: cred loaded ($($global:Credentials.UserName))" }
            catch { Write-RLog "AUTO MODE: cred import failed: $($_.Exception.Message)" 'WARN' }
        } else {
            $global:Credentials = $null
            try { Refresh-CredStatus } catch {}
            Write-RLog ("AUTO MODE: dispatching as task identity ({0}\{1}); run-as={2}" -f $env:USERDOMAIN, $env:USERNAME, ([string]$job.RunAsUser))
        }

        ## Replay settings into the controls so the existing Start handler + engine
        ## read them exactly as if an operator had set them.
        $tbExceptions.Text = ((@($job.Exceptions)) -join "`r`n")
        $tbTargets.Text    = ((@($job.Targets))    -join "`r`n")
        Apply-Targets
        $numLead.Value        = [Math]::Min($numLead.Maximum,        [Math]::Max($numLead.Minimum,        [int]$job.LeadMinutes))
        $numConc.Value        = [Math]::Min($numConc.Maximum,        [Math]::Max($numConc.Minimum,        [int]$job.Concurrency))
        $chkBurst.Checked     = [bool]$job.Burst
        $chkDryRun.Checked    = [bool]$job.DryRun
        $chkConsent.Checked   = [bool]$job.ConsentReq
        $numPromptWin.Value   = [Math]::Min($numPromptWin.Maximum,   [Math]::Max($numPromptWin.Minimum,   [int]$job.PromptMinutes))
        $numAcceptGrace.Value = [Math]::Min($numAcceptGrace.Maximum, [Math]::Max($numAcceptGrace.Minimum, [int]$job.GraceSeconds))
        ## v1.5.0-beta3: pre-flight gate defaults ON for jobs saved before it existed.
        if ($job.PSObject.Properties['Preflight']) { $chkPreflight.Checked = [bool]$job.Preflight } else { $chkPreflight.Checked = $true }
        ## v1.5.0-beta3: skip-servers defaults ON; keep saved pattern if present.
        if ($job.PSObject.Properties['SkipServers']) { $chkSkipServers.Checked = [bool]$job.SkipServers } else { $chkSkipServers.Checked = $true }
        if ($job.PSObject.Properties['ServerPattern'] -and -not [string]::IsNullOrWhiteSpace([string]$job.ServerPattern)) { $tbServerPat.Text = [string]$job.ServerPattern }
        ## v1.5.0-beta4: rolling/go-fast mode. Defaults OFF for jobs saved before it existed.
        if ($job.PSObject.Properties['Rolling']) { $chkRolling.Checked = [bool]$job.Rolling } else { $chkRolling.Checked = $false }
        if ($job.PSObject.Properties['RollingGrace']) { $numRollingGrace.Value = [Math]::Min($numRollingGrace.Maximum, [Math]::Max($numRollingGrace.Minimum, [int]$job.RollingGrace)) }
        ## The unattended task IS the timer - never re-arm the in-app wait in auto mode.
        $chkBeginAtTime.Checked = $false
        $tbMessage.Text       = [string]$job.Message

        $rt = [datetime]::Parse([string]$job.RestartTime)
        $dtpStart.Value = $rt

        Build-Plan -RestartTime $rt -LeadMinutes ([int]$numLead.Value)
        Render-PlanGrids
        $script:Stats.Total    = $script:Plan.Count
        $script:Stats.Pending  = $script:Plan.Count
        $script:Stats.InFlight = 0; $script:Stats.Sent = 0; $script:Stats.Failed = 0
        $script:Stats.Aborted  = 0; $script:Stats.Awaiting = 0; $script:Stats.Declined = 0; $script:Stats.Skipped = 0
        Refresh-StatsLabels

        if ($script:Plan.Count -eq 0) {
            Log-Activity 'AUTO MODE: 0 targets after exclusions - nothing to do.' $colors.Warning
            try { if ($script:AutoTaskName) { & schtasks.exe /Delete /TN $script:AutoTaskName /F *>$null } } catch {}
            Set-JanetAllowClose $true; try { $f.Close() } catch {}
            return
        }

        Log-Activity ("AUTO MODE: {0} target(s), restart {1}, consent {2}, dry-run {3}" -f $script:Plan.Count, (Format-Hms $rt), $chkConsent.Checked, $chkDryRun.Checked) $colors.Gold
        $btnStart.PerformClick()
    } catch {
        Write-RLog "AUTO MODE failed: $($_.Exception.Message)" 'ERROR'
        Log-Activity ("AUTO MODE error: {0}" -f $_.Exception.Message) $colors.Danger
        Set-JanetAllowClose $true; try { $f.Close() } catch {}
    }
}
#endregion

#region === REBOOT VERIFICATION MONITOR ===
## Pop-out window that confirms which dispatched machines actually came back
## from the restart, by ping, in real time.
##
## Why ping a DOWN->UP transition instead of a single "is it up" check:
## a machine that simply stayed reachable the whole time proves nothing - it
## may never have rebooted, or the reboot was faster than one ping interval.
## A confirmed reboot is "we saw it drop, then we saw it answer again". The
## state machine below encodes exactly that, and is honest about the cases it
## cannot positively confirm (Online-no-reboot, No-contact, still-Down).
##
## All of these helpers are PLAIN script-scope functions (NOT global:). Script
## functions resolve $colors / $oLog through their script parent scope, which
## global: functions would NOT see (same trap the logging block documents for
## $script:JanetSession). v1.6.0-beta: the monitor dialog's handlers pass the
## monitor context in via the sender control's .Tag ($this.Tag) as PLAIN
## scriptblocks - NOT .GetNewClosure() closures. GetNewClosure() rebinds a
## scriptblock to a dynamic module that resolves commands from module+global
## scope only, so under a call-operator launch (& 'script.ps1' / right-click
## Run with PowerShell) these script-scope helpers were
## CommandNotFoundException inside the handlers. -File launches dot-source
## into the global scope and never hit it.

function Update-RebootHostState {
    ## Advance one host's reboot state from a single ping result.
    ##   Pending      - no usable ping yet
    ##   Up           - reachable, but we have NOT seen it drop (no reboot proven)
    ##   Down         - was reachable, now not (reboot in progress / offline)
    ##   Rebooted     - saw Down then Up again => confirmed reboot, online now
    ##   Unreachable  - never answered since monitoring began
    ##   CameBack     - was down at monitor start (Unreachable), then answered.
    ##                  Almost certainly a reboot completing, but the drop itself
    ##                  predates the monitor - the WinRM verify pass settles it.
    ##                  (v1.5.1: previously this fell into 'Up' = "no
    ##                  reboot seen" because the EverDown promotion on the
    ##                  Unreachable->up path could never fire - nothing set
    ##                  EverDown when entering Unreachable.)
    param($Mon, [bool]$Up, [datetime]$At)
    $Mon.LastPing   = $At
    $Mon.LastResult = if ($Up) { 'reply' } else { 'timeout' }
    if ($Up) {
        $Mon.EverUp = $true
        switch ($Mon.State) {
            'Down'        { $Mon.State = 'Rebooted'; if (-not $Mon.UpAt) { $Mon.UpAt = $At } }
            'Pending'     { $Mon.State = 'Up' }
            'Unreachable' { $Mon.State = 'CameBack'; if (-not $Mon.UpAt) { $Mon.UpAt = $At } }
            default       { }   # 'Up' stays Up; 'Rebooted'/'CameBack' stay put
        }
    } else {
        switch ($Mon.State) {
            'Up'       { $Mon.State = 'Down'; $Mon.DownAt = $At; $Mon.EverDown = $true }
            'Pending'  { $Mon.State = 'Unreachable' }
            'Rebooted' { $Mon.State = 'Down'; $Mon.DownAt = $At; $Mon.EverDown = $true }   # returned, then dropped again
            'CameBack' { $Mon.State = 'Down'; $Mon.DownAt = $At; $Mon.EverDown = $true }   # now we HAVE seen a drop
            default    { }   # 'Down' stays Down; 'Unreachable' stays Unreachable
        }
        ## A witnessed drop supersedes an earlier point-in-time "NOT rebooted"
        ## WinRM verdict (operator clicked Verify before the host's turn came).
        if ($Mon.EverDown -and $Mon.VerifyState -eq 'NoReboot') { $Mon.VerifyState = ''; $Mon.BootTime = $null }
    }
}

function Get-RebootStateDisplay {
    ## Map a host state to (display text, row color). Referenced $colors is the
    ## script-scope palette - visible because this is a script (not global) fn.
    ## v1.5.1: a WinRM boot-time verdict trumps the ping-only inference.
    ## v1.6.0-beta: plain-language wording pass. Operators read "Dispatched" in
    ## the Run grid next to "Online (no reboot seen)" here as a contradiction,
    ## when the host was simply still counting down. The 'Up' state now uses
    ## the live plan row (RowRef) to say WHY the machine is still online.
    param($Mon)
    if ($Mon.VerifyState -eq 'Confirmed' -and $Mon.BootTime) {
        return @{ Text = ('RESTARTED - confirmed by boot time ({0})' -f $Mon.BootTime.ToString('HH:mm:ss')); Color = $colors.Success }
    }
    if ($Mon.VerifyState -eq 'NoReboot' -and $Mon.BootTime) {
        return @{ Text = ('Did NOT restart - confirmed (last boot {0})' -f $Mon.BootTime.ToString('MM-dd HH:mm')); Color = $colors.Danger }
    }
    if ($Mon.VerifyState -eq 'Info' -and $Mon.BootTime) {
        return @{ Text = ('Online (last boot {0} - no restart sent to compare)' -f $Mon.BootTime.ToString('MM-dd HH:mm')); Color = $colors.Warning }
    }
    $suffix = if ($Mon.VerifyState -eq 'Error') { ' - boot-time check failed' } else { '' }
    if ($Mon.State -eq 'Up') {
        ## Still online and never seen to drop. Explain why, from the plan row.
        $rs = if ($Mon.RowRef -and $Mon.RowRef.PSObject.Properties['Status']) { [string]$Mon.RowRef.Status } else { '' }
        switch ($rs) {
            'Dispatched'        { return @{ Text = ('Restart sent - waiting for it to go down (countdown on machine)' + $suffix); Color = $colors.Warning } }
            'Already-Scheduled' { return @{ Text = ('Restart already pending on machine - waiting for it to go down' + $suffix);  Color = $colors.Warning } }
            'Declined'          { return @{ Text = ('User clicked Decline - will NOT restart this run' + $suffix);                Color = $colors.Warning } }
            'Failed'            { return @{ Text = ('Restart command FAILED - machine will not restart' + $suffix);               Color = $colors.Danger } }
            'Cancelled'         { return @{ Text = ('Cancelled by operator - no restart sent' + $suffix);                         Color = $colors.TextSecondary } }
            default             { return @{ Text = ('Online - restart not sent to it yet' + $suffix);                             Color = $colors.Warning } }
        }
    }
    switch ($Mon.State) {
        'Rebooted'    { return @{ Text = ('RESTARTED - went down and came back' + $suffix);                          Color = $colors.Success } }
        'CameBack'    { return @{ Text = ('Back online (was down when watch began - likely restarted)' + $suffix);   Color = $colors.Gold } }
        'Down'        { return @{ Text = ('Offline - restarting now, waiting for it to come back' + $suffix);        Color = $colors.Cyan } }
        'Unreachable' { return @{ Text = ('No reply to any ping (off or unreachable)' + $suffix);                    Color = $colors.Danger } }
        default       { return @{ Text = 'Checking...';                                                              Color = $colors.TextSecondary } }
    }
}

function Update-RebootMonitorGrid {
    ## Repaint only the rows whose display key changed since last tick. With a
    ## few thousand hosts a blind full repaint every second is visibly janky;
    ## the per-row $Mon.Rendered guard keeps churn proportional to real changes.
    param($ctx)
    $g = $ctx.Grid
    $g.SuspendLayout()
    foreach ($m in $ctx.Mons) {
        $disp = Get-RebootStateDisplay -Mon $m
        $dStr = if ($m.DownAt)   { $m.DownAt.ToString('HH:mm:ss') }   else { '' }
        $uStr = if ($m.UpAt)     { $m.UpAt.ToString('HH:mm:ss') }     else { '' }
        $lStr = if ($m.LastPing) { $m.LastPing.ToString('HH:mm:ss') } else { '' }
        $key  = '{0}|{1}|{2}|{3}' -f $disp.Text, $dStr, $uStr, $lStr
        if ($m.Rendered -ne $key) {
            $m.Rendered = $key
            $row = $g.Rows[$m.RowIndex]
            $row.Cells['State'].Value           = $disp.Text
            $row.Cells['State'].Style.ForeColor = $disp.Color
            $row.Cells['Down'].Value            = $dStr
            $row.Cells['Up'].Value              = $uStr
            $row.Cells['Last'].Value            = $lStr
        }
    }
    $g.ResumeLayout()
}

function Start-RebootVerifyPass {
    ## v1.5.1 - WinRM LastBootUpTime pass. Ping down->up can only credit a
    ## reboot the monitor personally witnessed; anything that cycled before the
    ## monitor opened reads "Online (no reboot seen)". This asks each still-
    ## ambiguous host (Up / CameBack) for its actual boot time over the same
    ## WinRM channel the dispatch used and lets the reaper compare it to when
    ## that host's shutdown command landed. Returns the number of hosts queried.
    ## Does NOT stop the ping waves - callers decide (final pass sets
    ## $ctx.FinishAfterVerify; the manual button leaves monitoring running).
    param($ctx)
    if ($ctx.VJobs.Count -gt 0) { return 0 }   # a pass is already in flight
    $cands = @($ctx.Mons | Where-Object { ($_.State -eq 'Up' -or $_.State -eq 'CameBack') -and $_.VerifyState -ne 'Confirmed' -and $_.VerifyState -ne 'NoReboot' })
    foreach ($m in $cands) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $ctx.Pool
        [void]$ps.AddScript($ctx.VerifySB)
        [void]$ps.AddArgument($m.Host)
        [void]$ps.AddArgument($global:Credentials)
        $async = $ps.BeginInvoke()
        $ctx.VJobs[$m.Host] = @{ PS = $ps; Async = $async }
    }
    return $cands.Count
}

function Complete-RebootMonitor {
    ## Final tally + shutdown of the monitor's timer/buttons. Counts are
    ## recomputed here so WinRM verdicts that landed this tick are included.
    param($ctx, [TimeSpan]$elapsed)
    $ctx.Done = $true
    try { $ctx.Timer.Stop() } catch {}
    $cReb = 0; $cBack = 0; $cUp = 0; $cDown = 0; $cNo = 0; $vCon = 0; $vNo = 0; $vErr = 0
    foreach ($m in $ctx.Mons) {
        switch ($m.State) {
            'Rebooted'    { $cReb++ }
            'CameBack'    { $cBack++ }
            'Up'          { $cUp++ }
            'Down'        { $cDown++ }
            'Unreachable' { $cNo++ }
        }
        switch ($m.VerifyState) {
            'Confirmed' { $vCon++ }
            'NoReboot'  { $vNo++ }
            'Error'     { $vErr++ }
        }
    }
    $unconfirmed = [Math]::Max(0, ($cUp + $cBack) - $vNo)
    $parts = New-Object System.Collections.ArrayList
    [void]$parts.Add(('{0}/{1} restarted' -f $cReb, $ctx.Mons.Count))
    if ($vCon -gt 0)        { [void]$parts.Add(('{0} of those confirmed by boot time' -f $vCon)) }
    if ($vNo -gt 0)         { [void]$parts.Add(('{0} confirmed NOT restarted' -f $vNo)) }
    if ($unconfirmed -gt 0) { [void]$parts.Add(('{0} still online, restart unconfirmed' -f $unconfirmed)) }
    if ($cDown -gt 0)       { [void]$parts.Add(('{0} still down' -f $cDown)) }
    if ($cNo -gt 0)         { [void]$parts.Add(('{0} never answered' -f $cNo)) }
    if ($vErr -gt 0)        { [void]$parts.Add(('{0} boot-time check failed' -f $vErr)) }
    $line = ($parts.ToArray() -join ', ')
    $ctx.LblStatus.Text  = ('DONE - {0}. Elapsed {1:hh\:mm\:ss}.' -f $line, $elapsed)
    $ctx.BtnStop.Text    = 'Stopped'
    $ctx.BtnStop.Enabled = $false
    try { $ctx.BtnVerify.Enabled = $false } catch {}
    Log-Activity ('Reboot monitor finished: ' + $line) $colors.Gold
}

function Invoke-RebootMonitorTick {
    ## One monitor heartbeat (Forms.Timer, ~1 Hz):
    ##   1. Reap finished pings + finished WinRM verifies, advance host states.
    ##   2. If the prior wave fully drained AND the interval elapsed, fan out a
    ##      fresh ping wave for every host not yet confirmed Rebooted.
    ##   3. Repaint grid + summary, update elapsed/in-flight status.
    ##   4. When every host is Rebooted/CameBack, or the timeout is hit, run the
    ##      final WinRM boot-time pass over the ambiguous hosts, then finish.
    param($ctx)
    if ($null -eq $ctx) { return }

    ## 1. Reap completed pings.
    if ($ctx.Jobs.Count -gt 0) {
        $done = @()
        foreach ($k in @($ctx.Jobs.Keys)) {
            if ($ctx.Jobs[$k].Async.IsCompleted) { $done += $k }
        }
        foreach ($k in $done) {
            $j = $ctx.Jobs[$k]
            $res = $null
            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = $null }
            try { $j.PS.Dispose() } catch {}
            $ctx.Jobs.Remove($k)
            if ($res) {
                $m = $ctx.MonByHost[[string]$res.Host]   # PS hashtable keys are case-insensitive
                if ($m) { Update-RebootHostState -Mon $m -Up ([bool]$res.Up) -At $res.At }
            }
        }
    }

    ## 1b. Reap completed WinRM boot-time verifies (v1.5.1).
    if ($ctx.VJobs.Count -gt 0) {
        $vdone = @()
        foreach ($k in @($ctx.VJobs.Keys)) {
            if ($ctx.VJobs[$k].Async.IsCompleted) { $vdone += $k }
        }
        foreach ($k in $vdone) {
            $j = $ctx.VJobs[$k]
            $res = $null
            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = $null }
            try { $j.PS.Dispose() } catch {}
            $ctx.VJobs.Remove($k)
            $m = $ctx.MonByHost[[string]$k]
            if (-not $m) { continue }
            if ($res -and [bool]$res.Ok -and $res.BootTime) {
                $m.BootTime = [datetime]$res.BootTime
                ## Baseline = when THIS host's shutdown command landed. Falls back
                ## to RestartAt (replayed/imported rows). Boot time is target-local
                ## clock; domain time sync keeps the comparison honest.
                $baseline = $null
                if ($m.RowRef -and $m.RowRef.PSObject.Properties['DispatchedAt'] -and $m.RowRef.DispatchedAt) { $baseline = [datetime]$m.RowRef.DispatchedAt }
                if (-not $baseline -and $m.RestartAt) { $baseline = [datetime]$m.RestartAt }
                if ($baseline) {
                    if ($m.BootTime -gt $baseline) {
                        $m.VerifyState = 'Confirmed'
                        $m.State = 'Rebooted'
                        if (-not $m.UpAt) { $m.UpAt = $m.BootTime }
                    } else {
                        $m.VerifyState = 'NoReboot'
                    }
                } else {
                    $m.VerifyState = 'Info'   # bare-hostname spot check: report boot time, no verdict
                }
            } else {
                $m.VerifyState  = 'Error'
                $m.VerifyDetail = if ($res) { [string]$res.Err } else { 'no result' }
            }
        }
    }

    $now     = Get-Date
    $elapsed = $now - $ctx.StartTime
    $intervalSec = 15
    try { $intervalSec = [int]$ctx.NumInterval.Value } catch {}
    if ($intervalSec -lt 3) { $intervalSec = 3 }

    ## 2. Start a new wave once the previous one has fully drained. Suppressed
    ##    once the final verify pass is running - the ping phase is over.
    if (-not $ctx.Done -and -not $ctx.FinishAfterVerify -and $ctx.Jobs.Count -eq 0) {
        $due = ($null -eq $ctx.LastWaveAt) -or (($now - $ctx.LastWaveAt).TotalSeconds -ge $intervalSec)
        if ($due) {
            $ctx.LastWaveAt = $now
            foreach ($m in $ctx.Mons) {
                if ($m.State -eq 'Rebooted') { continue }   # confirmed up - stop pinging it
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $ctx.Pool
                [void]$ps.AddScript($ctx.PingSB)
                [void]$ps.AddArgument($m.Host)
                [void]$ps.AddArgument($ctx.TimeoutMs)
                $async = $ps.BeginInvoke()
                $ctx.Jobs[$m.Host] = @{ PS = $ps; Async = $async }
            }
        }
    }

    ## 3. Repaint + tally.
    Update-RebootMonitorGrid -ctx $ctx
    $cReb = 0; $cBack = 0; $cUp = 0; $cDown = 0; $cNo = 0; $cChk = 0
    foreach ($m in $ctx.Mons) {
        switch ($m.State) {
            'Rebooted'    { $cReb++ }
            'CameBack'    { $cBack++ }
            'Up'          { $cUp++ }
            'Down'        { $cDown++ }
            'Unreachable' { $cNo++ }
            default       { $cChk++ }
        }
    }
    $ctx.LblSummary.Text = ('Total {0}   |   Restarted {1}   |   Came back {2}   |   Still online {3}   |   Down now {4}   |   No contact {5}   |   Checking {6}' -f
        $ctx.Mons.Count, $cReb, $cBack, $cUp, $cDown, $cNo, $cChk)

    ## 4. Completion. Ping phase ends when every host is Rebooted or CameBack
    ##    (nothing left for ping to prove), or on timeout. Then the WinRM
    ##    boot-time pass settles the ambiguous rows, and the monitor finishes
    ##    once those verifies drain.
    if ($ctx.Done) { return }
    $remaining = @($ctx.Mons | Where-Object { $_.State -ne 'Rebooted' -and $_.State -ne 'CameBack' })
    $allBack   = ($remaining.Count -eq 0)
    $timedOut  = ($elapsed.TotalMinutes -ge [double]$ctx.TimeoutMin)

    if (-not $ctx.FinishAfterVerify -and ($allBack -or $timedOut)) {
        $ctx.FinishAfterVerify = $true
        $why = if ($allBack) { 'all hosts answered' } else { ('{0}-minute timeout reached' -f $ctx.TimeoutMin) }
        $n = Start-RebootVerifyPass -ctx $ctx
        if ($n -gt 0) {
            Log-Activity ('Reboot monitor: ping phase done ({0}) - WinRM boot-time check on {1} unconfirmed host(s)...' -f $why, $n) $colors.Cyan
        }
    }

    if ($ctx.FinishAfterVerify -and $ctx.VJobs.Count -eq 0) {
        Complete-RebootMonitor -ctx $ctx -elapsed $elapsed
    } elseif ($ctx.FinishAfterVerify) {
        $ctx.LblStatus.Text = ('Verifying boot times via WinRM... {0} in-flight  |  elapsed {1:hh\:mm\:ss}' -f $ctx.VJobs.Count, $elapsed)
    } else {
        $vNote = if ($ctx.VJobs.Count -gt 0) { ('  |  WinRM verifies {0}' -f $ctx.VJobs.Count) } else { '' }
        $ctx.LblStatus.Text = ('Monitoring... elapsed {0:hh\:mm\:ss}  |  next wave every {1}s  |  in-flight pings {2}  |  timeout {3} min{4}' -f
            $elapsed, $intervalSec, $ctx.Jobs.Count, $ctx.TimeoutMin, $vNote)
    }
}

function Show-RebootMonitorDialog {
    ## Build + show the modeless monitor window. $Rows may be plan rows
    ## (objects with .Host / .RestartAt) or bare hostname strings.
    param(
        [Parameter(Mandatory)] $Rows,
        [int]$PingIntervalSec = 15,
        [int]$TimeoutMin      = 30
    )

    ## Only one monitor at a time - re-focus an open one instead of stacking.
    if ($script:RebootMon -and $script:RebootMon.Form -and -not $script:RebootMon.Form.IsDisposed) {
        try { $script:RebootMon.Form.Activate(); $script:RebootMon.Form.BringToFront() } catch {}
        return
    }

    ## Build per-host monitor records (case-insensitive de-dup).
    $mons      = New-Object System.Collections.ArrayList
    $monByHost = @{}                                  # case-insensitive by default
    $seen      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Rows)) {
        $h = if ($r -is [string]) { $r } else { [string]$r.Host }
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        if (-not $seen.Add($h)) { continue }
        $ra = $null
        if ($r -isnot [string] -and $r.PSObject.Properties['RestartAt']) { $ra = $r.RestartAt }
        $rec = [PSCustomObject]@{
            Host = $h; RestartAt = $ra; State = 'Pending'
            EverUp = $false; EverDown = $false
            DownAt = $null; UpAt = $null; LastPing = $null; LastResult = ''
            RowIndex = $mons.Count; Rendered = ''
            ## v1.5.1 - WinRM boot-time verification. RowRef keeps the live
            ## plan row so DispatchedAt (stamped when the shutdown lands, possibly
            ## AFTER this dialog opens) is read fresh at verify time.
            RowRef = $(if ($r -is [string]) { $null } else { $r })
            BootTime = $null; VerifyState = ''; VerifyDetail = ''
        }
        [void]$mons.Add($rec)
        $monByHost[$h] = $rec
    }
    if ($mons.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No dispatched hosts to verify yet.', 'Reboot Monitor', 'OK', 'Information') | Out-Null
        return
    }

    ## v1.5.1 - honor the schedule. The watch window must cover the latest
    ## planned restart plus the allowance, or a wave due further out than the
    ## flat timeout got stamped "no reboot seen" before anything was even due.
    $maxRa = $null
    foreach ($m in $mons) { if ($m.RestartAt -and ($null -eq $maxRa -or $m.RestartAt -gt $maxRa)) { $maxRa = $m.RestartAt } }
    if ($maxRa) {
        $untilMin = [int][Math]::Ceiling((([datetime]$maxRa) - (Get-Date)).TotalMinutes)
        if ($untilMin -gt 0) { $TimeoutMin = [Math]::Min(1440, $untilMin + $TimeoutMin) }
    }

    ## Ping worker - System.Net.NetworkInformation.Ping with a fixed per-host
    ## timeout. Test-Connection on PS 5.1 has no per-ping timeout, so a wall of
    ## dead hosts would stall the wave for seconds each; Ping.Send(host, ms)
    ## bounds every probe. DNS / unreachable both surface as "not up".
    $pingSB = {
        param($hostname, $timeoutMs)
        $up = $false
        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            $reply = $p.Send($hostname, $timeoutMs)
            if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $up = $true }
        } catch { $up = $false }
        [PSCustomObject]@{ Host = $hostname; Up = $up; At = (Get-Date) }
    }

    ## v1.5.1 - WinRM boot-time worker. Same transport + timeouts as the
    ## dispatch scriptblock (Negotiate, bounded open/operation), so any host we
    ## could send shutdown.exe to, we can also ask for its LastBootUpTime.
    $verifySB = {
        param($hostname, $cred)
        $r = @{ Host = $hostname; Ok = $false; BootTime = $null; Err = '' }
        try {
            $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
            $icArgs = @{
                ComputerName   = $hostname
                Authentication = 'Negotiate'
                SessionOption  = $wsOpt
                ErrorAction    = 'Stop'
                ScriptBlock    = { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
            }
            if ($null -ne $cred) { $icArgs['Credential'] = $cred }
            $bt = Invoke-Command @icArgs
            if ($bt) { $r.Ok = $true; $r.BootTime = [datetime]$bt }
        } catch { $r.Err = $_.Exception.Message }
        return $r
    }

    ## Dedicated ping pool (kept separate from the dispatch pool).
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pmax = [Math]::Min(64, [Math]::Max(4, $mons.Count))
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
    $pool.Open()

    $CW = 1100; $CH = 620   # v1.5.1: widened for the Verify (WinRM) button

    $form = New-Object System.Windows.Forms.Form
    $form.Text          = 'Reboot Verification Monitor'
    $form.ClientSize    = New-Object System.Drawing.Size($CW, $CH)
    $form.MinimumSize   = New-Object System.Drawing.Size(720, 420)
    $form.StartPosition = 'CenterParent'
    $form.BackColor     = $colors.Background
    $form.ForeColor     = $colors.TextPrimary
    $form.Font          = $fonts.Label
    Set-DarkTitleBar -Form $form

    $lblTitleM = New-Object System.Windows.Forms.Label
    $lblTitleM.Text      = 'Reboot Verification Monitor'
    $lblTitleM.Location  = New-Object System.Drawing.Point(14, 8)
    $lblTitleM.AutoSize  = $true
    $lblTitleM.Font      = $fonts.JTitle
    $lblTitleM.ForeColor = $colors.Gold
    $form.Controls.Add($lblTitleM)

    $lblSubM = New-Object System.Windows.Forms.Label
    $lblSubM.Text      = ('Pinging {0} host(s) until each confirms a reboot (down then back up) or the timeout is reached; unconfirmed hosts then get a WinRM boot-time check.' -f $mons.Count)
    $lblSubM.Location  = New-Object System.Drawing.Point(16, 40)
    $lblSubM.AutoSize  = $true
    $lblSubM.Font      = $fonts.Small
    $lblSubM.ForeColor = $colors.TextSecondary
    $form.Controls.Add($lblSubM)

    $lblSummaryM = New-Object System.Windows.Forms.Label
    $lblSummaryM.Location  = New-Object System.Drawing.Point(16, 62)
    $lblSummaryM.Size      = New-Object System.Drawing.Size(($CW - 32), 22)
    $lblSummaryM.Anchor    = 'Top,Left,Right'
    $lblSummaryM.Font      = $fonts.LabelBold
    $lblSummaryM.ForeColor = $colors.TextPrimary
    $lblSummaryM.Text      = ('Total {0}   |   Rebooted 0   |   Came-online 0   |   Online no-reboot 0   |   Offline/down 0   |   No contact 0   |   Checking {0}' -f $mons.Count)
    $form.Controls.Add($lblSummaryM)

    ## --- Right-cluster controls (anchored Top,Right) ---
    $lblIntCap = New-Object System.Windows.Forms.Label
    $lblIntCap.Text      = 'Ping every (s):'
    $lblIntCap.Location  = New-Object System.Drawing.Point(372, 16)
    $lblIntCap.Size      = New-Object System.Drawing.Size(92, 18)
    $lblIntCap.Anchor    = 'Top,Right'
    $lblIntCap.Font      = $fonts.Small
    $lblIntCap.ForeColor = $colors.TextSecondary
    $lblIntCap.TextAlign = 'MiddleRight'
    $form.Controls.Add($lblIntCap)

    $numIntervalM = New-Object System.Windows.Forms.NumericUpDown
    $numIntervalM.Location  = New-Object System.Drawing.Point(468, 14)
    $numIntervalM.Size      = New-Object System.Drawing.Size(54, 24)
    $numIntervalM.Anchor    = 'Top,Right'
    $numIntervalM.Minimum   = 3
    $numIntervalM.Maximum   = 300
    $numIntervalM.Value     = [Math]::Max(3, [Math]::Min(300, $PingIntervalSec))
    $numIntervalM.BackColor = $colors.Input
    $numIntervalM.ForeColor = $colors.TextPrimary
    $numIntervalM.BorderStyle = 'FixedSingle'
    $form.Controls.Add($numIntervalM)

    $btnRecheckM = New-StyledButton 'Ping now'       (New-Object System.Drawing.Point(530, 12)) (New-Object System.Drawing.Size(96, 32))  $colors.Accent
    $btnVerifyM  = New-StyledButton 'Verify (WinRM)' (New-Object System.Drawing.Point(632, 12)) (New-Object System.Drawing.Size(116, 32)) $colors.Gold
    $btnExportM  = New-StyledButton 'Export CSV...'  (New-Object System.Drawing.Point(754, 12)) (New-Object System.Drawing.Size(120, 32)) $colors.PanelLight
    $btnStopM    = New-StyledButton 'Stop'           (New-Object System.Drawing.Point(880, 12)) (New-Object System.Drawing.Size(96, 32))  $colors.Warning
    $btnCloseM   = New-StyledButton 'Close'          (New-Object System.Drawing.Point(982, 12)) (New-Object System.Drawing.Size(96, 32))  $colors.PanelLight
    foreach ($b in @($btnRecheckM, $btnVerifyM, $btnExportM, $btnStopM, $btnCloseM)) { $b.Anchor = 'Top,Right'; $form.Controls.Add($b) }

    ## --- Grid ---
    $gridM = New-Object System.Windows.Forms.DataGridView
    $gridM.Location = New-Object System.Drawing.Point(8, 96)
    $gridM.Size     = New-Object System.Drawing.Size(($CW - 16), ($CH - 96 - 34))
    $gridM.Anchor   = 'Top,Bottom,Left,Right'
    $gridM.BackgroundColor       = $colors.Panel
    $gridM.GridColor             = $colors.Border
    $gridM.BorderStyle           = 'FixedSingle'
    $gridM.RowHeadersVisible     = $false
    $gridM.AllowUserToAddRows    = $false
    $gridM.AllowUserToDeleteRows = $false
    $gridM.AllowUserToResizeRows = $false
    $gridM.ReadOnly              = $true
    $gridM.SelectionMode         = 'FullRowSelect'
    $gridM.MultiSelect           = $false
    $gridM.AutoSizeColumnsMode   = 'Fill'
    $gridM.Font                  = $fonts.ConsoleSm
    $gridM.DefaultCellStyle.BackColor          = $colors.Panel
    $gridM.DefaultCellStyle.ForeColor          = $colors.TextPrimary
    $gridM.DefaultCellStyle.SelectionBackColor = $colors.Accent
    $gridM.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $gridM.AlternatingRowsDefaultCellStyle.BackColor = $colors.PanelLight
    $gridM.ColumnHeadersDefaultCellStyle.BackColor   = $colors.Sidebar
    $gridM.ColumnHeadersDefaultCellStyle.ForeColor   = $colors.Gold
    $gridM.ColumnHeadersDefaultCellStyle.Font        = $fonts.SmallBold
    $gridM.EnableHeadersVisualStyles = $false
    [void]$gridM.Columns.Add('Host','Host')
    [void]$gridM.Columns.Add('State','State')
    [void]$gridM.Columns.Add('Down','Went down')
    [void]$gridM.Columns.Add('Up','Came back')
    [void]$gridM.Columns.Add('Last','Last ping')
    ## v1.6.0-beta: State got wider (plain-language wording pass) at the
    ## expense of the three timestamp columns, which only hold HH:mm:ss.
    $gridM.Columns['Host'].FillWeight  = 24
    $gridM.Columns['State'].FillWeight = 43
    $gridM.Columns['Down'].FillWeight  = 11
    $gridM.Columns['Up'].FillWeight    = 11
    $gridM.Columns['Last'].FillWeight  = 11
    ## v1.5.1: repaints address rows by the fixed RowIndex captured at
    ## build time - a header-click sort would reorder the rows and paint host
    ## states onto the wrong lines. Sorting is disabled outright.
    foreach ($c in $gridM.Columns) { $c.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable }
    $form.Controls.Add($gridM)

    ## Seed rows once; the tick repaints cells in place.
    $gridM.SuspendLayout()
    foreach ($m in $mons) {
        [void]$gridM.Rows.Add(@($m.Host, 'Checking...', '', '', ''))
    }
    $gridM.ResumeLayout()

    $lblStatusM = New-Object System.Windows.Forms.Label
    $lblStatusM.Location  = New-Object System.Drawing.Point(16, ($CH - 26))
    $lblStatusM.Size      = New-Object System.Drawing.Size(($CW - 32), 20)
    $lblStatusM.Anchor    = 'Bottom,Left,Right'
    $lblStatusM.Font      = $fonts.Small
    $lblStatusM.ForeColor = $colors.TextSecondary
    $lblStatusM.Text      = 'Starting...'
    $form.Controls.Add($lblStatusM)

    ## Monitor context - handed to each handler via the sender's .Tag ($this.Tag).
    ## v1.6.0-beta FIX: these handlers used { ... $ctx ... }.GetNewClosure(), but
    ## GetNewClosure() rebinds the scriptblock to a fresh dynamic module that
    ## resolves commands from its module + GLOBAL scope only. Launched via the
    ## call operator (& 'script.ps1' - what right-click "Run with PowerShell"
    ## does) the tool's functions live in a private script scope the module
    ## cannot see, so Invoke-RebootMonitorTick et al. spammed
    ## CommandNotFoundException every tick. (-File launches were immune: -File
    ## dot-sources into the global scope.) Plain scriptblocks stay bound to
    ## the script's session state (functions resolve under any launch style);
    ## per-dialog state rides in on the control's Tag instead of a closure.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $ctx = @{
        Mons        = $mons
        MonByHost   = $monByHost
        Pool        = $pool
        PingSB      = $pingSB
        Jobs        = @{}
        Form        = $form
        Grid        = $gridM
        Timer       = $timer
        StartTime   = (Get-Date)
        LastWaveAt  = $null
        TimeoutMin  = $TimeoutMin
        TimeoutMs   = 1500
        Done        = $false
        LblSummary  = $lblSummaryM
        LblStatus   = $lblStatusM
        BtnStop     = $btnStopM
        NumInterval = $numIntervalM
        ## v1.5.1 - WinRM boot-time verification.
        VerifySB          = $verifySB
        VJobs             = @{}
        FinishAfterVerify = $false   # set when the ping phase ends; monitor finishes once VJobs drain
        BtnVerify         = $btnVerifyM
    }
    $script:RebootMon = $ctx

    ## Hand each handler its context via the sender's Tag (see note above).
    $timer.Tag      = $ctx
    $btnRecheckM.Tag = $ctx
    $btnVerifyM.Tag  = $ctx
    $btnStopM.Tag    = $ctx
    $btnExportM.Tag  = $ctx
    $btnCloseM.Tag   = $ctx
    $form.Tag        = $ctx

    $timer.Add_Tick({ Invoke-RebootMonitorTick -ctx $this.Tag })

    $btnRecheckM.Add_Click({
        $ctx = $this.Tag
        if (-not $ctx.Done -and -not $ctx.FinishAfterVerify) { $ctx.LastWaveAt = $null }   # force the next tick to fan out immediately
    })

    ## v1.5.1 - on-demand WinRM boot-time pass. Monitoring keeps running;
    ## verdicts fold into the grid as they land, and a host whose verdict was
    ## "NOT rebooted" that later drops gets its stale verdict cleared by the
    ## ping state machine.
    $btnVerifyM.Add_Click({
        $ctx = $this.Tag
        if ($ctx.Done) { return }
        $n = Start-RebootVerifyPass -ctx $ctx
        if ($n -gt 0) {
            $ctx.LblStatus.Text = ('Verifying boot times via WinRM on {0} host(s)...' -f $n)
            Log-Activity ('Reboot monitor: manual WinRM boot-time check on {0} host(s).' -f $n) $colors.Cyan
        } else {
            $ctx.LblStatus.Text = 'Nothing to verify - no unconfirmed online hosts (or a verify pass is already running).'
        }
    })

    $btnStopM.Add_Click({
        $ctx = $this.Tag
        if ($ctx.Done) { return }
        $ctx.Done = $true
        try { $ctx.Timer.Stop() } catch {}
        $ctx.LblStatus.Text = 'Stopped by operator.'
        $ctx.BtnStop.Text = 'Stopped'
        $ctx.BtnStop.Enabled = $false
        Log-Activity 'Reboot monitor stopped by operator.' $colors.Warning
    })

    $btnExportM.Add_Click({
        $ctx = $this.Tag
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter   = 'CSV|*.csv'
        $dlg.FileName  = 'RebootVerify_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        if ($dlg.ShowDialog() -eq 'OK') {
            try {
                $out = foreach ($m in $ctx.Mons) {
                    $disp = Get-RebootStateDisplay -Mon $m
                    [PSCustomObject]@{
                        Host      = $m.Host
                        State     = $disp.Text
                        RestartAt = if ($m.RestartAt) { Format-Hms $m.RestartAt } else { '' }
                        WentDown  = if ($m.DownAt)    { Format-Hms $m.DownAt }    else { '' }
                        CameBack  = if ($m.UpAt)      { Format-Hms $m.UpAt }      else { '' }
                        LastPing  = if ($m.LastPing)  { Format-Hms $m.LastPing }  else { '' }
                        LastReply = $m.LastResult
                        ## v1.5.1 - WinRM boot-time verdict.
                        BootTime  = if ($m.BootTime)  { $m.BootTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                        Verify    = $(switch ($m.VerifyState) {
                                        'Confirmed' { 'Restarted (confirmed by boot time)' }
                                        'NoReboot'  { 'Did NOT restart (confirmed by boot time)' }
                                        'Info'      { 'Boot time read (no restart sent to compare)' }
                                        'Error'     { 'Boot-time check failed: ' + $m.VerifyDetail }
                                        default     { '' }
                                    })
                    }
                }
                $out | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
                Log-Activity ('Reboot monitor results exported to {0}' -f $dlg.FileName) $colors.Cyan
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Export', 'OK', 'Error') | Out-Null
            }
        }
    })

    $btnCloseM.Add_Click({ $this.Tag.Form.Close() })

    $form.Add_FormClosed({
        $ctx = $this.Tag
        try { if ($ctx.Timer) { $ctx.Timer.Stop(); $ctx.Timer.Dispose() } } catch {}
        try { foreach ($j in $ctx.Jobs.Values)  { try { $j.PS.Stop() } catch {}; try { $j.PS.Dispose() } catch {} } } catch {}
        try { foreach ($j in $ctx.VJobs.Values) { try { $j.PS.Stop() } catch {}; try { $j.PS.Dispose() } catch {} } } catch {}
        try { if ($ctx.Pool) { $ctx.Pool.Close(); $ctx.Pool.Dispose() } } catch {}
        $script:RebootMon = $null
    })

    $timer.Start()
    Log-Activity ('Reboot verification monitor opened for {0} host(s).' -f $mons.Count) $colors.Cyan

    ## Modeless so the tool stays usable while the monitor runs. Owner = main
    ## form so it rides along on minimize and closes when the tool closes.
    if ($f -and -not $f.IsDisposed) { $form.Show($f) } else { $form.Show() }
}
#endregion


#region === FORM ===
$f = New-Object System.Windows.Forms.Form
$f.Text = "J.A.N.E.T. Remote Restart Scheduler v$JanetRemoteRestartVersion"
$f.Size = New-Object System.Drawing.Size(1400, 1000)
$f.MinimumSize = New-Object System.Drawing.Size(1280, 880)
$f.StartPosition = "CenterScreen"
$f.BackColor = $colors.Background
$f.ForeColor = $colors.TextPrimary
$f.Font = $fonts.Label
Set-DarkTitleBar -Form $f
#endregion

#region === HEADER ===
## Header is title + subtitle + a globally-visible Close Tool button at the
## top-left. The Close button is the only path that flips the JANET X-block
## flag so the FormClosing egress runs (closing-notes dialog + SessionEnd row).
## The X chrome button stays blocked by design (toolsuite convention).
$header = New-Object System.Windows.Forms.Panel
$header.Dock      = 'Top'
$header.Height    = 64
$header.BackColor = $colors.TopBar
$f.Controls.Add($header)

$btnHeaderClose = New-StyledButton 'Close Tool' (New-Object System.Drawing.Point(14, 14)) (New-Object System.Drawing.Size(112, 36)) $colors.Danger
$btnHeaderClose.Font = $fonts.Button
$header.Controls.Add($btnHeaderClose)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text       = "J.A.N.E.T. Remote Restart Scheduler"
$lblTitle.Location   = New-Object System.Drawing.Point(140, 8)
$lblTitle.AutoSize   = $true
$lblTitle.ForeColor  = $colors.Gold
$lblTitle.Font       = $fonts.JTitle
$lblTitle.BackColor  = [System.Drawing.Color]::Transparent
$header.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text         = "Staggered mass restart with pre-restart user warnings - Joint Administration and Network Execution Toolkit"
$lblSub.Location     = New-Object System.Drawing.Point(142, 40)
$lblSub.AutoSize     = $true
$lblSub.ForeColor    = $colors.TextSecondary
$lblSub.Font         = $fonts.JSub
$lblSub.BackColor    = [System.Drawing.Color]::Transparent
$header.Controls.Add($lblSub)

## --- Credentials strip (top-right of header) ---
## When credentials are set, dispatch routes through Invoke-Command -Credential
## (WinRM). When not set, falls back to shutdown.exe /m \\HOST using the
## operator's current token. Inherits $env:JANET_CRED_FILE from the launcher
## on startup if present.
$btnSetCred = New-StyledButton 'Set Credentials...' (New-Object System.Drawing.Point(0, 12)) (New-Object System.Drawing.Size(180, 32)) $colors.Accent
$btnSetCred.Anchor = 'Top,Right'
$header.Controls.Add($btnSetCred)

$btnClearCred = New-StyledButton 'Clear' (New-Object System.Drawing.Point(0, 12)) (New-Object System.Drawing.Size(60, 32)) $colors.PanelLight
$btnClearCred.Anchor = 'Top,Right'
$header.Controls.Add($btnClearCred)

$lblCredStatus = New-Object System.Windows.Forms.Label
$lblCredStatus.Text       = '(no credentials set - using current user)'
$lblCredStatus.Location   = New-Object System.Drawing.Point(0, 46)
$lblCredStatus.Size       = New-Object System.Drawing.Size(240, 16)
$lblCredStatus.Font       = $fonts.Small
$lblCredStatus.ForeColor  = $colors.TextDim
$lblCredStatus.TextAlign  = 'MiddleRight'
$lblCredStatus.BackColor  = [System.Drawing.Color]::Transparent
$lblCredStatus.Anchor     = 'Top,Right'
$header.Controls.Add($lblCredStatus)

## Position the cred controls relative to the header's right edge AFTER they're
## added (Anchor=Top,Right needs an initial Left to anchor from).
$header.Add_HandleCreated({
    try {
        $w = $header.ClientSize.Width
        $btnClearCred.Left  = $w - 14 - 60
        $btnSetCred.Left    = $btnClearCred.Left - 6 - 180
        $lblCredStatus.Left = $btnSetCred.Left
        $lblCredStatus.Width = ($btnClearCred.Left + 60) - $btnSetCred.Left
    } catch {}
}.GetNewClosure())

function Refresh-CredStatus {
    ## State -> label + button:
    ##   Inherited from JANET launcher -> green "user  (inherited from J.A.N.E.T.)"; button = "Override Credentials"
    ##   Manually set                  -> green "as: user"; button = "Set Credentials..."
    ##   None                          -> cyan "current Windows session (CAC)"; button = "Set Credentials..."
    ##
    ## The "None" state is FINE on AFNET admin boxes - Invoke-Command without
    ## -Credential uses the current CAC-bound Kerberos ticket. No typing,
    ## no PIN re-prompt, no captured cred to drift.
    if ($null -ne $global:Credentials) {
        if ($script:CredInheritedFromJanet) {
            $lblCredStatus.Text      = "$($global:Credentials.UserName)  (inherited from J.A.N.E.T.)"
            $btnSetCred.Text         = 'Override Credentials'
        } else {
            $lblCredStatus.Text      = "as: $($global:Credentials.UserName)"
            $btnSetCred.Text         = 'Set Credentials...'
        }
        $lblCredStatus.ForeColor = $colors.Success
    } else {
        $lblCredStatus.Text      = "current Windows session (CAC)"
        $lblCredStatus.ForeColor = $colors.Cyan
        $btnSetCred.Text         = 'Set Credentials...'
    }
}
#endregion

#region === STATS BAR (its own row, below header) ===
## Outer bar is docked top below the header. Stats labels live inside a
## fixed-width inner panel anchored Top,Right so the math is independent of
## any TabPage / form-resize quirks. Six stat cards, each 110 wide.
$statsBar = New-Object System.Windows.Forms.Panel
$statsBar.Dock      = 'Top'
$statsBar.Height    = 56
$statsBar.BackColor = $colors.Sidebar
$f.Controls.Add($statsBar)

$statsInnerWidth = (9 * 110)        # 990 px - 9 stat columns (Total..Skipped) on the 1280-min form
$statsInner = New-Object System.Windows.Forms.Panel
$statsInner.Size      = New-Object System.Drawing.Size($statsInnerWidth, 56)
$statsInner.BackColor = [System.Drawing.Color]::Transparent
$statsInner.Anchor    = 'Top,Right'
$statsInner.Location  = New-Object System.Drawing.Point(($statsBar.ClientSize.Width - $statsInnerWidth - 14), 0)
$statsBar.Controls.Add($statsInner)

function New-StatLabel {
    param([string]$Caption, [int]$X, [System.Drawing.Color]$ValueColor)
    $cap = New-Object System.Windows.Forms.Label
    $cap.Text = $Caption
    $cap.Location = New-Object System.Drawing.Point($X, 4)
    $cap.Size     = New-Object System.Drawing.Size(110, 14)
    $cap.ForeColor = $colors.TextDim
    $cap.Font      = $fonts.Tiny
    $cap.TextAlign = 'MiddleCenter'
    $cap.BackColor = [System.Drawing.Color]::Transparent
    $statsInner.Controls.Add($cap)

    $val = New-Object System.Windows.Forms.Label
    $val.Text = '0'
    $val.Location = New-Object System.Drawing.Point($X, 20)
    $val.Size     = New-Object System.Drawing.Size(110, 30)
    $val.ForeColor = $ValueColor
    $val.Font      = $fonts.Stat
    $val.TextAlign = 'MiddleCenter'
    $val.BackColor = [System.Drawing.Color]::Transparent
    $statsInner.Controls.Add($val)
    return $val
}
$lblStatTotal    = New-StatLabel 'Total'       0 $colors.TextPrimary
$lblStatPending  = New-StatLabel 'Pending'   110 $colors.TextPrimary
$lblStatAwaiting = New-StatLabel 'Awaiting'  220 $colors.Cyan
$lblStatInFlight = New-StatLabel 'In-Flight' 330 $colors.Cyan
$lblStatSent     = New-StatLabel 'Sent'      440 $colors.Success
$lblStatDeclined = New-StatLabel 'Declined'  550 $colors.Warning
$lblStatFailed   = New-StatLabel 'Failed'    660 $colors.Danger
$lblStatAborted  = New-StatLabel 'Aborted'   770 $colors.Warning
$lblStatSkipped  = New-StatLabel 'Skipped'   880 $colors.TextDim   # v1.5.0-beta3: server-skip gate count (keeps buckets summing to Total)

function Refresh-StatsLabels {
    $lblStatTotal.Text    = $script:Stats.Total
    $lblStatPending.Text  = $script:Stats.Pending
    $lblStatAwaiting.Text = $script:Stats.Awaiting
    $lblStatInFlight.Text = $script:Stats.InFlight
    $lblStatSent.Text     = $script:Stats.Sent
    $lblStatDeclined.Text = $script:Stats.Declined
    $lblStatFailed.Text   = $script:Stats.Failed
    $lblStatAborted.Text  = $script:Stats.Aborted
    $lblStatSkipped.Text  = $script:Stats.Skipped
}
#endregion

#region === TAB CONTROL ===
## Dock=Fill: occupies whatever's left after the Top-docked header + statsBar.
## WinForms processes docking in REVERSE z-order (highest z-index first claims
## its slot, lowest z-index gets what remains). So Fill must be at the LOWEST
## z-index. Adding $tabs last gives it the highest z-index, so we explicitly
## demote it to index 0.
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock     = 'Fill'
$tabs.Font     = $fonts.Section
$f.Controls.Add($tabs)
$f.Controls.SetChildIndex($tabs, 0)

$tabTargets  = New-Object System.Windows.Forms.TabPage; $tabTargets.Text  = '  Targets  ';  $tabTargets.BackColor  = $colors.Background
$tabSchedule = New-Object System.Windows.Forms.TabPage; $tabSchedule.Text = '  Schedule  '; $tabSchedule.BackColor = $colors.Background
$tabRun      = New-Object System.Windows.Forms.TabPage; $tabRun.Text      = '  Run / Results  '; $tabRun.BackColor      = $colors.Background
$tabs.TabPages.Add($tabTargets)
$tabs.TabPages.Add($tabSchedule)
$tabs.TabPages.Add($tabRun)
#endregion

#region === TARGETS TAB ===
## Layout (Dock-based, no fragile absolute positioning):
##   [ Right Rail Panel  Dock=Right Width=210 ]  buttons + counts
##   [ Center Panel      Dock=Fill           ]  two textbox columns 50/50

# --- RIGHT RAIL Panel ---
$tgtRight = New-Object System.Windows.Forms.Panel
$tgtRight.Dock      = 'Right'
$tgtRight.Width     = 210
$tgtRight.BackColor = $colors.Background
$tgtRight.Padding   = New-Object System.Windows.Forms.Padding(10, 8, 12, 8)
$tabTargets.Controls.Add($tgtRight)

$btnImportCsv    = New-StyledButton 'Import targets CSV...'   (New-Object System.Drawing.Point(10, 56))  (New-Object System.Drawing.Size(188, 32)) $colors.Accent
$btnClearTargets = New-StyledButton 'Clear targets'           (New-Object System.Drawing.Point(10, 92))  (New-Object System.Drawing.Size(188, 28)) $colors.PanelLight
$btnImportExc    = New-StyledButton 'Import exceptions CSV...' (New-Object System.Drawing.Point(10, 132)) (New-Object System.Drawing.Size(188, 32)) $colors.AccentDim
$btnClearExc     = New-StyledButton 'Clear exceptions'        (New-Object System.Drawing.Point(10, 168)) (New-Object System.Drawing.Size(188, 28)) $colors.PanelLight
$btnApplyTargets = New-StyledButton 'Apply'                   (New-Object System.Drawing.Point(10, 212)) (New-Object System.Drawing.Size(188, 40)) $colors.Success
$btnTestHost     = New-StyledButton 'Test single host...'     (New-Object System.Drawing.Point(10, 264)) (New-Object System.Drawing.Size(188, 36)) $colors.Gold
$btnSplitTargets = New-StyledButton 'Split targets -> N CSVs...' (New-Object System.Drawing.Point(10, 306)) (New-Object System.Drawing.Size(188, 32)) $colors.AccentDim

$lblTargetCount = New-Object System.Windows.Forms.Label
$lblTargetCount.Text = '0 unique target(s)'
$lblTargetCount.Location = New-Object System.Drawing.Point(10, 346)
$lblTargetCount.Size     = New-Object System.Drawing.Size(188, 22)
$lblTargetCount.Font     = $fonts.LabelBold
$lblTargetCount.ForeColor = $colors.Cyan

$lblExcCount = New-Object System.Windows.Forms.Label
$lblExcCount.Text = '0 in exception list'
$lblExcCount.Location = New-Object System.Drawing.Point(10, 370)
$lblExcCount.Size     = New-Object System.Drawing.Size(188, 22)
$lblExcCount.Font     = $fonts.LabelBold
$lblExcCount.ForeColor = $colors.Danger

$lblTargetsBox = New-Object System.Windows.Forms.Label
$lblTargetsBox.Text = "Apply here, then move to Schedule. Exception-listed hosts are filtered out. Test single host fires one shutdown.exe and shows the exit code. Split targets writes N balanced CSVs to run on N separate dispatcher boxes for ~Nx speed."
$lblTargetsBox.Location = New-Object System.Drawing.Point(10, 402)
$lblTargetsBox.Size     = New-Object System.Drawing.Size(188, 150)
$lblTargetsBox.Font     = $fonts.Small
$lblTargetsBox.ForeColor = $colors.TextSecondary

$tgtRight.Controls.AddRange(@($btnImportCsv, $btnClearTargets, $btnImportExc, $btnClearExc, $btnApplyTargets, $btnTestHost, $btnSplitTargets, $lblTargetCount, $lblExcCount, $lblTargetsBox))

# --- CENTER Panel (split: Targets column | Exceptions column) ---
$tgtCenter = New-Object System.Windows.Forms.Panel
$tgtCenter.Dock      = 'Fill'
$tgtCenter.BackColor = $colors.Background
$tgtCenter.Padding   = New-Object System.Windows.Forms.Padding(14, 12, 6, 8)
$tabTargets.Controls.Add($tgtCenter)
## Z-order: rail first claims its 210 px on the right, Fill takes the rest.
$tabTargets.Controls.SetChildIndex($tgtCenter, 0)

$splitter = New-Object System.Windows.Forms.SplitContainer
$splitter.Dock          = 'Fill'
$splitter.Orientation   = 'Vertical'
$splitter.BackColor     = $colors.Background
$splitter.Panel1.BackColor = $colors.Background
$splitter.Panel2.BackColor = $colors.Background
$splitter.SplitterWidth = 8
$tgtCenter.Controls.Add($splitter)
## Default split: 60% targets / 40% exceptions. SplitterDistance must be set
## AFTER the splitter is added to a parent or it throws on small widths.
$splitter.Add_HandleCreated({
    try {
        $w = $splitter.ClientSize.Width
        if ($w -gt 200) { $splitter.SplitterDistance = [int]($w * 0.6) }
    } catch {}
}.GetNewClosure())

# --- TARGETS column (in splitter.Panel1) ---
$lblTargets = New-Object System.Windows.Forms.Label
$lblTargets.Text = 'Target machines'
$lblTargets.Location = New-Object System.Drawing.Point(0, 0)
$lblTargets.AutoSize = $true
$lblTargets.Font     = $fonts.Section
$lblTargets.ForeColor = $colors.Gold
$splitter.Panel1.Controls.Add($lblTargets)

$lblTargetsHint = New-Object System.Windows.Forms.Label
$lblTargetsHint.Text = 'Paste hostnames (one per line, or comma/space/tab separated). Case-insensitive dedup.'
$lblTargetsHint.Location = New-Object System.Drawing.Point(0, 26)
$lblTargetsHint.AutoSize = $true
$lblTargetsHint.Font     = $fonts.Small
$lblTargetsHint.ForeColor = $colors.TextSecondary
$splitter.Panel1.Controls.Add($lblTargetsHint)

$tbTargets = New-Object System.Windows.Forms.TextBox
$tbTargets.Location  = New-Object System.Drawing.Point(0, 50)
$tbTargets.Size      = New-Object System.Drawing.Size(($splitter.Panel1.ClientSize.Width - 2), ($splitter.Panel1.ClientSize.Height - 56))
$tbTargets.Anchor    = 'Top,Bottom,Left,Right'
$tbTargets.Multiline  = $true
## MaxLength 0 = no character cap (bounded only by memory). The WinForms default
## of 32,767 silently truncates large pastes - at long AFNET FQDNs that can cut
## off well before a full fleet. 3000+ hosts now paste in full.
$tbTargets.MaxLength  = 0
$tbTargets.ScrollBars = 'Vertical'
$tbTargets.Font       = $fonts.Console
$tbTargets.BackColor  = $colors.Input
$tbTargets.ForeColor  = $colors.TextPrimary
$tbTargets.BorderStyle = 'FixedSingle'
$splitter.Panel1.Controls.Add($tbTargets)

# --- EXCEPTIONS column (in splitter.Panel2) ---
$lblExceptions = New-Object System.Windows.Forms.Label
$lblExceptions.Text = 'Exception list (never restart)'
$lblExceptions.Location = New-Object System.Drawing.Point(0, 0)
$lblExceptions.AutoSize = $true
$lblExceptions.Font     = $fonts.Section
$lblExceptions.ForeColor = $colors.Danger
$splitter.Panel2.Controls.Add($lblExceptions)

$lblExceptionsHint = New-Object System.Windows.Forms.Label
$lblExceptionsHint.Text = 'Filtered out of any plan. Persists between launches.'
$lblExceptionsHint.Location = New-Object System.Drawing.Point(0, 26)
$lblExceptionsHint.AutoSize = $true
$lblExceptionsHint.Font     = $fonts.Small
$lblExceptionsHint.ForeColor = $colors.TextSecondary
$splitter.Panel2.Controls.Add($lblExceptionsHint)

$tbExceptions = New-Object System.Windows.Forms.TextBox
$tbExceptions.Location  = New-Object System.Drawing.Point(0, 50)
$tbExceptions.Size      = New-Object System.Drawing.Size(($splitter.Panel2.ClientSize.Width - 2), ($splitter.Panel2.ClientSize.Height - 56))
$tbExceptions.Anchor    = 'Top,Bottom,Left,Right'
$tbExceptions.Multiline  = $true
$tbExceptions.MaxLength  = 0   # no cap (see Targets box) - large exception lists paste in full
$tbExceptions.ScrollBars = 'Vertical'
$tbExceptions.Font       = $fonts.Console
$tbExceptions.BackColor  = $colors.Input
$tbExceptions.ForeColor  = $colors.Danger
$tbExceptions.BorderStyle = 'FixedSingle'
$splitter.Panel2.Controls.Add($tbExceptions)
#endregion

#region === SCHEDULE TAB ===
$lblSched = New-Object System.Windows.Forms.Label
$lblSched.Text = 'Restart schedule'
$lblSched.Location = New-Object System.Drawing.Point(20, 15)
$lblSched.Size     = New-Object System.Drawing.Size(400, 22)
$lblSched.Font     = $fonts.Section
$lblSched.ForeColor = $colors.Gold
$tabSchedule.Controls.Add($lblSched)

## Default start = next 02:00 (today if before 2 AM, otherwise tomorrow).
$now = Get-Date
$defaultStart = (Get-Date -Hour 2 -Minute 0 -Second 0 -Millisecond 0)
if ($defaultStart -le $now) { $defaultStart = $defaultStart.AddDays(1) }

$rowY = 60
function Add-FieldLabel {
    param([string]$Text, [int]$Y)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point(20, $Y)
    $l.Size     = New-Object System.Drawing.Size(220, 22)
    $l.Font     = $fonts.LabelBold
    $l.ForeColor = $colors.TextSecondary
    $tabSchedule.Controls.Add($l)
}

Add-FieldLabel 'Restart time (all machines)' $rowY
$dtpStart = New-Object System.Windows.Forms.DateTimePicker
$dtpStart.Location = New-Object System.Drawing.Point(250, $rowY)
$dtpStart.Size     = New-Object System.Drawing.Size(260, 24)
$dtpStart.Font     = $fonts.Label
$dtpStart.Format   = 'Custom'
$dtpStart.CustomFormat = 'yyyy-MM-dd  HH:mm'
$dtpStart.ShowUpDown = $true
$dtpStart.Value      = $defaultStart
$tabSchedule.Controls.Add($dtpStart)

$rowY += 36
Add-FieldLabel 'Pre-restart warning (minutes)' $rowY
$numLead = New-Object System.Windows.Forms.NumericUpDown
$numLead.Location = New-Object System.Drawing.Point(250, $rowY)
$numLead.Size     = New-Object System.Drawing.Size(120, 24)
$numLead.Minimum  = 1
$numLead.Maximum  = 60
$numLead.Value    = 15
$numLead.Font     = $fonts.Label
$tabSchedule.Controls.Add($numLead)

$rowY += 36
Add-FieldLabel 'Dispatch concurrency (threads)' $rowY
$numConc = New-Object System.Windows.Forms.NumericUpDown
$numConc.Location = New-Object System.Drawing.Point(250, $rowY)
$numConc.Size     = New-Object System.Drawing.Size(120, 24)
$numConc.Minimum  = 1
$numConc.Maximum  = 256  # v1.5.0-beta4: 128->256 headroom (dead-host timeouts, not threads, were the bottleneck - ping gate handles that)
$numConc.Value    = 96   # v1.5.0-beta3: 32->96. WinRM fan-out is I/O-bound, so a higher default pushes the prompt/dispatch wave out far faster on a full-fleet run.
$numConc.Font     = $fonts.Label
$tabSchedule.Controls.Add($numConc)

$rowY += 36
$chkBurst = New-Object System.Windows.Forms.CheckBox
$chkBurst.Text = 'Burst mode: dispatch all commands ASAP (per-host /t = time until that host''s restart)'
$chkBurst.Location = New-Object System.Drawing.Point(20, $rowY)
$chkBurst.Size     = New-Object System.Drawing.Size(900, 22)
$chkBurst.Font     = $fonts.LabelBold
$chkBurst.ForeColor = $colors.Gold
$chkBurst.Checked   = $true
$tabSchedule.Controls.Add($chkBurst)

$rowY += 22
$lblBurstHint = New-Object System.Windows.Forms.Label
$lblBurstHint.Text = '   - ON  (recommended): all shutdown commands fire in batches as fast as the threads can run; each host gets its own Windows countdown so the per-host restart stagger is preserved. Operator can leave once dispatch finishes.'
$lblBurstHint.Location = New-Object System.Drawing.Point(20, $rowY)
$lblBurstHint.Size     = New-Object System.Drawing.Size(1280, 18)
$lblBurstHint.Font     = $fonts.Small
$lblBurstHint.ForeColor = $colors.TextSecondary
$tabSchedule.Controls.Add($lblBurstHint)

$rowY += 18
$lblBurstHint2 = New-Object System.Windows.Forms.Label
$lblBurstHint2.Text = '   - OFF (time-gated): one command per dispatch tick, fired exactly LeadMinutes before each restart - exact 15-minute warning per host but the dispatcher must stay running for the full window.'
$lblBurstHint2.Location = New-Object System.Drawing.Point(20, $rowY)
$lblBurstHint2.Size     = New-Object System.Drawing.Size(1280, 18)
$lblBurstHint2.Font     = $fonts.Small
$lblBurstHint2.ForeColor = $colors.TextDim
$tabSchedule.Controls.Add($lblBurstHint2)

$rowY += 26
$chkDryRun = New-Object System.Windows.Forms.CheckBox
$chkDryRun.Text = 'Dry run (log commands only, do not contact hosts)'
$chkDryRun.Location = New-Object System.Drawing.Point(20, $rowY)
$chkDryRun.Size     = New-Object System.Drawing.Size(500, 22)
$chkDryRun.Font     = $fonts.Label
$chkDryRun.ForeColor = $colors.Warning
$tabSchedule.Controls.Add($chkDryRun)

## v1.5.0-beta3 - pre-flight reachability gate (default ON). Shares the dry-run
## row; ICMP-only so it can be unticked for subnets that block ping.
$chkPreflight = New-Object System.Windows.Forms.CheckBox
$chkPreflight.Text = 'Skip unreachable (pre-flight ping before WinRM)'
$chkPreflight.Location = New-Object System.Drawing.Point(540, $rowY)
$chkPreflight.Size     = New-Object System.Drawing.Size(620, 22)
$chkPreflight.Font     = $fonts.Label
$chkPreflight.ForeColor = $colors.Cyan
$chkPreflight.Checked   = $true
$tabSchedule.Controls.Add($chkPreflight)

## v1.5.0-beta3 - server skip (default ON). Server-named hosts must not ride a
## workstation reboot wave; matched rows are marked Skipped-Server up front and
## never pinged or contacted. The pattern is editable for other environments.
$rowY += 28
$chkSkipServers = New-Object System.Windows.Forms.CheckBox
$chkSkipServers.Text = 'Skip servers - do not reboot hosts whose name matches:'
$chkSkipServers.Location = New-Object System.Drawing.Point(20, $rowY)
$chkSkipServers.Size     = New-Object System.Drawing.Size(430, 22)
$chkSkipServers.Font     = $fonts.LabelBold
$chkSkipServers.ForeColor = $colors.Gold
$chkSkipServers.Checked   = $true
$tabSchedule.Controls.Add($chkSkipServers)

$tbServerPat = New-Object System.Windows.Forms.TextBox
$tbServerPat.Location = New-Object System.Drawing.Point(455, ($rowY - 1))
$tbServerPat.Size     = New-Object System.Drawing.Size(330, 24)
$tbServerPat.Font      = $fonts.Console
$tbServerPat.BackColor = $colors.Input
$tbServerPat.ForeColor = $colors.TextPrimary
$tbServerPat.BorderStyle = 'FixedSingle'
$tbServerPat.Text      = $script:ServerNamePattern
$tabSchedule.Controls.Add($tbServerPat)

$lblSkipSrvHint = New-Object System.Windows.Forms.Label
$lblSkipSrvHint.Text = '(regex; default matches MSEK-AS-/-DB-/-FS-/-WXA- servers - workstations MSEKL-/MSEKW- are kept)'
$lblSkipSrvHint.Location = New-Object System.Drawing.Point(795, ($rowY + 2))
$lblSkipSrvHint.Size     = New-Object System.Drawing.Size(545, 18)
$lblSkipSrvHint.Font     = $fonts.Small
$lblSkipSrvHint.ForeColor = $colors.TextDim
$tabSchedule.Controls.Add($lblSkipSrvHint)

## --- User Consent (v1.4.0) ---
$rowY += 32
$chkConsent = New-Object System.Windows.Forms.CheckBox
$chkConsent.Text = 'Require user consent: prompt the logged-on user (Accept / Decline) before restarting'
$chkConsent.Location = New-Object System.Drawing.Point(20, $rowY)
$chkConsent.Size     = New-Object System.Drawing.Size(900, 22)
$chkConsent.Font     = $fonts.LabelBold
$chkConsent.ForeColor = $colors.Gold
$chkConsent.Checked   = $true
$tabSchedule.Controls.Add($chkConsent)

$rowY += 28
$lblPromptWin = New-Object System.Windows.Forms.Label
$lblPromptWin.Text = 'Prompt window (min):'
$lblPromptWin.Location = New-Object System.Drawing.Point(40, ($rowY + 2))
$lblPromptWin.Size     = New-Object System.Drawing.Size(150, 22)
$lblPromptWin.Font     = $fonts.Label
$lblPromptWin.ForeColor = $colors.TextSecondary
$tabSchedule.Controls.Add($lblPromptWin)

$numPromptWin = New-Object System.Windows.Forms.NumericUpDown
$numPromptWin.Location = New-Object System.Drawing.Point(195, $rowY)
$numPromptWin.Size     = New-Object System.Drawing.Size(70, 24)
$numPromptWin.Minimum  = 1
$numPromptWin.Maximum  = 60
$numPromptWin.Value    = 5
$numPromptWin.Font     = $fonts.Label
$tabSchedule.Controls.Add($numPromptWin)

$lblAcceptGrace = New-Object System.Windows.Forms.Label
$lblAcceptGrace.Text = 'Accept grace (sec):'
$lblAcceptGrace.Location = New-Object System.Drawing.Point(300, ($rowY + 2))
$lblAcceptGrace.Size     = New-Object System.Drawing.Size(135, 22)
$lblAcceptGrace.Font     = $fonts.Label
$lblAcceptGrace.ForeColor = $colors.TextSecondary
$tabSchedule.Controls.Add($lblAcceptGrace)

$numAcceptGrace = New-Object System.Windows.Forms.NumericUpDown
$numAcceptGrace.Location = New-Object System.Drawing.Point(440, $rowY)
$numAcceptGrace.Size     = New-Object System.Drawing.Size(85, 24)
$numAcceptGrace.Minimum  = 10
$numAcceptGrace.Maximum  = 3600
$numAcceptGrace.Increment = 10
$numAcceptGrace.Value    = 60
$numAcceptGrace.Font     = $fonts.Label
$tabSchedule.Controls.Add($numAcceptGrace)

$rowY += 28
$lblConsentHint = New-Object System.Windows.Forms.Label
$lblConsentHint.Text = '   - ON: a one-time scheduled task shows an Accept/Decline dialog in the user''s session. No response within the window OR no user logged on -> restart proceeds. Decline -> host is skipped this run. Ignored on dry runs.'
$lblConsentHint.Location = New-Object System.Drawing.Point(20, $rowY)
$lblConsentHint.Size     = New-Object System.Drawing.Size(1280, 32)
$lblConsentHint.Font     = $fonts.Small
$lblConsentHint.ForeColor = $colors.TextDim
$tabSchedule.Controls.Add($lblConsentHint)

## --- Rolling / go-fast mode (v1.5.0-beta4) ---
$rowY += 34
$chkRolling = New-Object System.Windows.Forms.CheckBox
$chkRolling.Text = 'Rolling / go-fast: restart each host as soon as it approves (do NOT wait for the scheduled time)'
$chkRolling.Location = New-Object System.Drawing.Point(20, $rowY)
$chkRolling.Size     = New-Object System.Drawing.Size(950, 22)
$chkRolling.Font     = $fonts.LabelBold
$chkRolling.ForeColor = $colors.Cyan
$chkRolling.Checked   = $false
$tabSchedule.Controls.Add($chkRolling)

$rowY += 28
$lblRollGrace = New-Object System.Windows.Forms.Label
$lblRollGrace.Text = 'Restart grace after approve (sec):'
$lblRollGrace.Location = New-Object System.Drawing.Point(40, ($rowY + 2))
$lblRollGrace.Size     = New-Object System.Drawing.Size(220, 22)
$lblRollGrace.Font     = $fonts.Label
$lblRollGrace.ForeColor = $colors.TextSecondary
$tabSchedule.Controls.Add($lblRollGrace)

$numRollingGrace = New-Object System.Windows.Forms.NumericUpDown
$numRollingGrace.Location = New-Object System.Drawing.Point(265, $rowY)
$numRollingGrace.Size     = New-Object System.Drawing.Size(85, 24)
$numRollingGrace.Minimum  = 10
$numRollingGrace.Maximum  = 3600
$numRollingGrace.Increment = 10
$numRollingGrace.Value    = 60
$numRollingGrace.Font     = $fonts.Label
$tabSchedule.Controls.Add($numRollingGrace)

$rowY += 28
$lblRollHint = New-Object System.Windows.Forms.Label
$lblRollHint.Text = '   - ON: prompts go out immediately; each box reboots ~grace seconds after IT approves, rolling down the line. The scheduled time is NOT a reboot time. OFF: all approved hosts converge and reboot together at the scheduled time.'
$lblRollHint.Location = New-Object System.Drawing.Point(20, $rowY)
$lblRollHint.Size     = New-Object System.Drawing.Size(1280, 32)
$lblRollHint.Font     = $fonts.Small
$lblRollHint.ForeColor = $colors.TextDim
$tabSchedule.Controls.Add($lblRollHint)

## --- In-app delayed start (v1.5.0-beta4) ---
$rowY += 36
$chkBeginAtTime = New-Object System.Windows.Forms.CheckBox
$chkBeginAtTime.Text = 'Begin at the scheduled time (leave this tool open; it auto-starts the wave at the time above)'
$chkBeginAtTime.Location = New-Object System.Drawing.Point(20, $rowY)
$chkBeginAtTime.Size     = New-Object System.Drawing.Size(950, 22)
$chkBeginAtTime.Font     = $fonts.Label
$chkBeginAtTime.ForeColor = $colors.TextSecondary
$chkBeginAtTime.Checked   = $false
$tabSchedule.Controls.Add($chkBeginAtTime)

$rowY += 36
Add-FieldLabel 'Warning message ({LEAD} -> minutes)' $rowY
$tbMessage = New-Object System.Windows.Forms.TextBox
$tbMessage.Location = New-Object System.Drawing.Point(250, $rowY)
$tbMessage.Size     = New-Object System.Drawing.Size(900, 90)
$tbMessage.Multiline = $true
$tbMessage.Font      = $fonts.Console
$tbMessage.BackColor = $colors.Input
$tbMessage.ForeColor = $colors.TextPrimary
$tbMessage.BorderStyle = 'FixedSingle'
$tbMessage.Text       = 'Mandatory system maintenance. This computer will restart in {LEAD} minutes. Please save your work and close all applications now.'
$tabSchedule.Controls.Add($tbMessage)

$rowY += 110
$btnCompute = New-StyledButton 'Compute Schedule' (New-Object System.Drawing.Point(250, $rowY)) (New-Object System.Drawing.Size(200, 38)) $colors.Accent
$tabSchedule.Controls.Add($btnCompute)

$btnSavePlan = New-StyledButton 'Save Plan CSV...' (New-Object System.Drawing.Point(460, $rowY)) (New-Object System.Drawing.Size(180, 38)) $colors.PanelLight
$tabSchedule.Controls.Add($btnSavePlan)

## v1.5.0-beta - arm a one-shot Windows Scheduled Task that fires this whole
## dispatch automatically at the chosen time (no operator present needed).
$btnSchedTask = New-StyledButton 'Schedule as Windows Task...' (New-Object System.Drawing.Point(650, $rowY)) (New-Object System.Drawing.Size(260, 38)) $colors.Gold
$tabSchedule.Controls.Add($btnSchedTask)

$rowY += 50
$lblPlanSummary = New-Object System.Windows.Forms.Label
$lblPlanSummary.Text = '(No plan computed)'
$lblPlanSummary.Location = New-Object System.Drawing.Point(20, $rowY)
$lblPlanSummary.Size     = New-Object System.Drawing.Size(1280, 22)
$lblPlanSummary.Font     = $fonts.LabelBold
$lblPlanSummary.ForeColor = $colors.Gold
$tabSchedule.Controls.Add($lblPlanSummary)

$rowY += 28
$gridPlan = New-Object System.Windows.Forms.DataGridView
$gridPlan.Location = New-Object System.Drawing.Point(20, $rowY)
$gridPlan.Size     = New-Object System.Drawing.Size(1320, 480)
$gridPlan.Anchor   = 'Top,Bottom,Left,Right'
$gridPlan.BackgroundColor = $colors.Panel
$gridPlan.GridColor       = $colors.Border
$gridPlan.BorderStyle     = 'FixedSingle'
$gridPlan.RowHeadersVisible = $false
$gridPlan.AllowUserToAddRows = $false
$gridPlan.AllowUserToDeleteRows = $false
$gridPlan.AllowUserToResizeRows = $false
$gridPlan.ReadOnly       = $true
$gridPlan.SelectionMode  = 'FullRowSelect'
$gridPlan.MultiSelect    = $false
$gridPlan.AutoSizeColumnsMode = 'Fill'
$gridPlan.Font           = $fonts.ConsoleSm
$gridPlan.DefaultCellStyle.BackColor          = $colors.Panel
$gridPlan.DefaultCellStyle.ForeColor          = $colors.TextPrimary
$gridPlan.DefaultCellStyle.SelectionBackColor = $colors.Accent
$gridPlan.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
$gridPlan.AlternatingRowsDefaultCellStyle.BackColor = $colors.PanelLight
$gridPlan.ColumnHeadersDefaultCellStyle.BackColor = $colors.Sidebar
$gridPlan.ColumnHeadersDefaultCellStyle.ForeColor = $colors.Gold
$gridPlan.ColumnHeadersDefaultCellStyle.Font      = $fonts.SmallBold
$gridPlan.EnableHeadersVisualStyles = $false
[void]$gridPlan.Columns.Add('Host','Host')
[void]$gridPlan.Columns.Add('DispatchAt','Dispatch at')
[void]$gridPlan.Columns.Add('RestartAt','Restart at')
[void]$gridPlan.Columns.Add('Status','Status')
[void]$gridPlan.Columns.Add('Result','Result')
$tabSchedule.Controls.Add($gridPlan)
#endregion

#region === RUN / RESULTS TAB ===
## Toolbar is a FlowLayoutPanel of AUTO-SIZING buttons so labels never clip and
## the row reflows (wraps) instead of running off-screen at higher display
## scaling / DPI - fixed pixel widths were truncating the button text. The grid
## fills the remaining space and the activity log docks to the bottom, so the
## whole tab adapts to any window size.
$panelRunTop = New-Object System.Windows.Forms.FlowLayoutPanel
$panelRunTop.Dock          = 'Top'
$panelRunTop.AutoSize      = $true
$panelRunTop.AutoSizeMode  = 'GrowAndShrink'
$panelRunTop.WrapContents  = $true
$panelRunTop.FlowDirection = 'LeftToRight'
$panelRunTop.BackColor     = $colors.Background
$panelRunTop.Padding       = New-Object System.Windows.Forms.Padding(14, 10, 14, 8)

function Set-ToolbarButton {
    ## Make a New-StyledButton flow-friendly: size to its text (+ padding) so the
    ## label can never be clipped, with a uniform 38px-tall minimum.
    param($Button)
    $Button.AutoSize     = $true
    $Button.AutoSizeMode = 'GrowAndShrink'
    $Button.Margin       = New-Object System.Windows.Forms.Padding(4, 4, 4, 4)
    $Button.Padding      = New-Object System.Windows.Forms.Padding(12, 6, 12, 6)
    $Button.MinimumSize  = New-Object System.Drawing.Size(0, 38)
    return $Button
}

$ph = New-Object System.Drawing.Point(0, 0)
$sz = New-Object System.Drawing.Size(10, 38)
$btnStart  = Set-ToolbarButton (New-StyledButton 'Start Dispatch'           $ph $sz $colors.Success)
$btnCancel = Set-ToolbarButton (New-StyledButton 'Cancel Pending'           $ph $sz $colors.Warning)
$btnCancel.Enabled = $false
$btnAbort  = Set-ToolbarButton (New-StyledButton 'Abort Already-Dispatched' $ph $sz $colors.Danger)
$btnAbort.Enabled = $false
## Reboot Verification Monitor launcher. Always enabled - it resolves the
## dispatched-host set itself and explains if there's nothing to verify yet.
$btnVerify = Set-ToolbarButton (New-StyledButton 'Verify Reboots'           $ph $sz $colors.Cyan)
$btnExport = Set-ToolbarButton (New-StyledButton 'Export Results CSV...'    $ph $sz $colors.PanelLight)
## Close Tool button (egress) - only path that sets the X-block flag to allow close.
$btnCloseTool = Set-ToolbarButton (New-StyledButton 'Close Tool'            $ph $sz $colors.PanelLight)

## Now / Next status as one flow item (two stacked lines).
$runInfoPanel = New-Object System.Windows.Forms.Panel
$runInfoPanel.Size      = New-Object System.Drawing.Size(300, 46)
$runInfoPanel.Margin    = New-Object System.Windows.Forms.Padding(20, 2, 4, 2)
$runInfoPanel.BackColor = [System.Drawing.Color]::Transparent

$lblNow = New-Object System.Windows.Forms.Label
$lblNow.Location = New-Object System.Drawing.Point(0, 2)
$lblNow.Size     = New-Object System.Drawing.Size(300, 22)
$lblNow.Font     = $fonts.LabelBold
$lblNow.ForeColor = $colors.Gold
$runInfoPanel.Controls.Add($lblNow)

$lblNext = New-Object System.Windows.Forms.Label
$lblNext.Location = New-Object System.Drawing.Point(0, 24)
$lblNext.Size     = New-Object System.Drawing.Size(300, 20)
$lblNext.Font     = $fonts.Small
$lblNext.ForeColor = $colors.TextSecondary
$runInfoPanel.Controls.Add($lblNext)

## Progress: live Elapsed timer (top) + ETA / projected finish (bottom).
$runProgPanel = New-Object System.Windows.Forms.Panel
$runProgPanel.Size      = New-Object System.Drawing.Size(380, 46)
$runProgPanel.Margin    = New-Object System.Windows.Forms.Padding(16, 2, 4, 2)
$runProgPanel.BackColor = [System.Drawing.Color]::Transparent

$lblElapsed = New-Object System.Windows.Forms.Label
$lblElapsed.Location = New-Object System.Drawing.Point(0, 2)
$lblElapsed.Size     = New-Object System.Drawing.Size(380, 22)
$lblElapsed.Font     = $fonts.LabelBold
$lblElapsed.ForeColor = $colors.Cyan
$lblElapsed.Text     = 'Elapsed --:--:--   |   Done 0/0'
$runProgPanel.Controls.Add($lblElapsed)

$lblEta = New-Object System.Windows.Forms.Label
$lblEta.Location = New-Object System.Drawing.Point(0, 24)
$lblEta.Size     = New-Object System.Drawing.Size(380, 20)
$lblEta.Font     = $fonts.Small
$lblEta.ForeColor = $colors.TextSecondary
$lblEta.Text     = 'ETA --:--:--   |   finish ~--:--'
$runProgPanel.Controls.Add($lblEta)

$panelRunTop.Controls.AddRange(@($btnStart, $btnCancel, $btnAbort, $btnVerify, $btnExport, $runInfoPanel, $runProgPanel, $btnCloseTool))

$gridRun = New-Object System.Windows.Forms.DataGridView
$gridRun.Dock = 'Fill'
$gridRun.BackgroundColor = $colors.Panel
$gridRun.GridColor       = $colors.Border
$gridRun.BorderStyle     = 'FixedSingle'
$gridRun.RowHeadersVisible = $false
$gridRun.AllowUserToAddRows = $false
$gridRun.AllowUserToDeleteRows = $false
$gridRun.AllowUserToResizeRows = $false
$gridRun.ReadOnly       = $true
$gridRun.SelectionMode  = 'FullRowSelect'
$gridRun.MultiSelect    = $false
$gridRun.AutoSizeColumnsMode = 'Fill'
$gridRun.Font           = $fonts.ConsoleSm
$gridRun.DefaultCellStyle.BackColor          = $colors.Panel
$gridRun.DefaultCellStyle.ForeColor          = $colors.TextPrimary
$gridRun.DefaultCellStyle.SelectionBackColor = $colors.Accent
$gridRun.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
$gridRun.AlternatingRowsDefaultCellStyle.BackColor = $colors.PanelLight
$gridRun.ColumnHeadersDefaultCellStyle.BackColor = $colors.Sidebar
$gridRun.ColumnHeadersDefaultCellStyle.ForeColor = $colors.Gold
$gridRun.ColumnHeadersDefaultCellStyle.Font      = $fonts.SmallBold
$gridRun.EnableHeadersVisualStyles = $false
[void]$gridRun.Columns.Add('Host','Host')
[void]$gridRun.Columns.Add('DispatchAt','Dispatch at')
[void]$gridRun.Columns.Add('RestartAt','Restart at')
[void]$gridRun.Columns.Add('Status','Status')
[void]$gridRun.Columns.Add('Result','Result')

$oLog = New-OutputBox (New-Object System.Drawing.Point(0, 0)) (New-Object System.Drawing.Size(10, 240))
$oLog.Dock   = 'Bottom'
$oLog.Height = 240

## Docking z-order: add the Fill control first (sent to the back), then the
## Bottom log, then the Top toolbar last so it claims the top edge cleanly.
$tabRun.Controls.Add($gridRun)
$tabRun.Controls.Add($oLog)
$tabRun.Controls.Add($panelRunTop)
#endregion

#region === EVENT HANDLERS ===

function Apply-Targets {
    ## 1. Parse exceptions textbox -> $script:Exceptions (persist to disk).
    $excList = ConvertTo-HostList -Text $tbExceptions.Text
    $script:Exceptions.Clear()
    foreach ($e in $excList) { [void]$script:Exceptions.Add($e) }
    Save-ExceptionsToDisk -Hosts @($script:Exceptions)

    ## 2. Parse targets textbox, filter out anything in the exception set.
    $rawTargets = ConvertTo-HostList -Text $tbTargets.Text
    $kept       = New-Object System.Collections.ArrayList
    $dropped    = 0
    foreach ($h in $rawTargets) {
        if ($script:Exceptions.Contains($h)) { $dropped++ }
        else                                  { [void]$kept.Add($h) }
    }
    $script:Targets.Clear()
    foreach ($h in $kept) { [void]$script:Targets.Add($h) }
    $script:LastExclusionCount = $dropped

    if ($dropped -gt 0) {
        $lblTargetCount.Text = "$($script:Targets.Count) target(s)  ({0} excluded)" -f $dropped
    } else {
        $lblTargetCount.Text = "$($script:Targets.Count) unique target(s)"
    }
    $lblExcCount.Text = "$($script:Exceptions.Count) in exception list"
    $script:Stats.Total = $script:Targets.Count
    Refresh-StatsLabels
    if ($dropped -gt 0) {
        Log-Activity ("Applied {0} target(s); {1} filtered by exception list ({2} entries)" -f $script:Targets.Count, $dropped, $script:Exceptions.Count) $colors.Cyan
    } else {
        Log-Activity ("Applied {0} target(s) (exception list: {1})" -f $script:Targets.Count, $script:Exceptions.Count) $colors.Cyan
    }
}

$btnApplyTargets.Add_Click({ Apply-Targets })

function Show-SplitCountDialog {
    ## Tiny modal: how many balanced lists to split into. Returns [int] or $null.
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = 'Split targets'
    $dlg.Size            = New-Object System.Drawing.Size(360, 170)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false; $dlg.MinimizeBox = $false
    $dlg.BackColor       = $colors.Background
    $dlg.ForeColor       = $colors.TextPrimary

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text     = 'Number of balanced lists (one per dispatcher box):'
    $lbl.Location = New-Object System.Drawing.Point(16, 16)
    $lbl.Size     = New-Object System.Drawing.Size(320, 22)
    $lbl.Font     = $fonts.Label
    $dlg.Controls.Add($lbl)

    $num = New-Object System.Windows.Forms.NumericUpDown
    $num.Location = New-Object System.Drawing.Point(16, 44)
    $num.Size     = New-Object System.Drawing.Size(80, 24)
    $num.Minimum  = 2; $num.Maximum = 20; $num.Value = 4
    $num.Font     = $fonts.Label
    $dlg.Controls.Add($num)

    $ok = New-StyledButton 'Split' (New-Object System.Drawing.Point(150, 88)) (New-Object System.Drawing.Size(90, 32)) $colors.Success
    $cancel = New-StyledButton 'Cancel' (New-Object System.Drawing.Point(246, 88)) (New-Object System.Drawing.Size(90, 32)) $colors.PanelLight
    $ok.Add_Click({ $dlg.Tag = [int]$num.Value; $dlg.DialogResult = 'OK'; $dlg.Close() })
    $cancel.Add_Click({ $dlg.DialogResult = 'Cancel'; $dlg.Close() })
    $dlg.Controls.AddRange(@($ok, $cancel))
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel

    if ($dlg.ShowDialog() -eq 'OK') { return [int]$dlg.Tag }
    return $null
}

function Split-TargetsToCsv {
    ## Round-robin the applied (exception-filtered) targets into N balanced,
    ## interleaved Host-column CSVs. Each file re-imports via "Import targets CSV".
    param([int]$N, [string]$Dir)
    $effective = @($script:Targets | Where-Object { -not $script:Exceptions.Contains($_) } | Sort-Object { $_.ToString() })
    $total = $effective.Count
    if ($total -eq 0) { throw 'No applied targets to split. Apply targets first.' }
    if ($N -lt 2)     { throw 'Split count must be 2 or more.' }
    if ($N -gt $total){ throw "Cannot split $total host(s) into $N lists." }

    $buckets = @{}
    for ($i = 0; $i -lt $N; $i++) { $buckets[$i] = New-Object System.Collections.ArrayList }
    for ($i = 0; $i -lt $total; $i++) { [void]$buckets[$i % $N].Add($effective[$i]) }

    $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $written = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $N; $i++) {
        $path = Join-Path $Dir ("RestartTargets_{0}_part{1}of{2}.csv" -f $stamp, ($i + 1), $N)
        $rows = @($buckets[$i] | ForEach-Object { [PSCustomObject]@{ Host = $_ } })
        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        [void]$written.Add([PSCustomObject]@{ Path = $path; Count = $buckets[$i].Count })
    }
    return $written
}

$btnSplitTargets.Add_Click({
    if ($script:Targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Apply targets on the Targets tab first.', 'Split targets', 'OK', 'Warning') | Out-Null
        return
    }
    $n = Show-SplitCountDialog
    if (-not $n) { return }
    $fb = New-Object System.Windows.Forms.FolderBrowserDialog
    $fb.Description = "Choose a folder for the $n split CSV(s)"
    if ($fb.ShowDialog() -ne 'OK') { return }
    try {
        $res   = Split-TargetsToCsv -N $n -Dir $fb.SelectedPath
        $sum   = ($res | Measure-Object -Property Count -Sum).Sum
        $lines = ($res | ForEach-Object { "  {0}  ({1} hosts)" -f (Split-Path $_.Path -Leaf), $_.Count }) -join "`r`n"
        Log-Activity ("Split {0} targets into {1} balanced CSV(s) -> {2}" -f $sum, $n, $fb.SelectedPath) $colors.Cyan
        [System.Windows.Forms.MessageBox]::Show(
            ("Wrote {0} balanced list(s) ({1} hosts total):`r`n`r`n{2}`r`n`r`nRun each part on a SEPARATE dispatcher box (Import targets CSV) for ~{0}x throughput." -f $n, $sum, $lines),
            'Split targets', 'OK', 'Information') | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Split targets', 'OK', 'Warning') | Out-Null
    }
})

$btnClearTargets.Add_Click({
    $tbTargets.Clear()
    $script:Targets.Clear()
    $script:LastExclusionCount = 0
    $lblTargetCount.Text = "0 unique target(s)"
    $script:Stats.Total = 0
    Refresh-StatsLabels
})

$btnImportCsv.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "CSV|*.csv|Text|*.txt|All|*.*"
    if ($dlg.ShowDialog() -eq 'OK') {
        $list = Load-TargetsFromCsv -Path $dlg.FileName
        if ($list.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No hostnames found in $($dlg.FileName).","Import CSV",'OK','Warning') | Out-Null
            return
        }
        $tbTargets.Text = ($list -join "`r`n")
        Apply-Targets
        Log-Activity ("Imported {0} target(s) from {1}" -f $list.Count, [System.IO.Path]::GetFileName($dlg.FileName)) $colors.Cyan
    }
})

$btnImportExc.Add_Click({
    ## Append to existing exceptions (don't blow them away). Operators typically
    ## have a long-standing exclusion list and want to ADD a new batch, not
    ## replace. Use Clear exceptions if a wholesale reset is wanted.
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "CSV|*.csv|Text|*.txt|All|*.*"
    if ($dlg.ShowDialog() -eq 'OK') {
        $list = Load-TargetsFromCsv -Path $dlg.FileName
        if ($list.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No hostnames found in $($dlg.FileName).","Import exceptions",'OK','Warning') | Out-Null
            return
        }
        $existing = ConvertTo-HostList -Text $tbExceptions.Text
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $merged = New-Object System.Collections.ArrayList
        foreach ($h in $existing) { if ($set.Add($h)) { [void]$merged.Add($h) } }
        $addedNew = 0
        foreach ($h in $list)     { if ($set.Add($h)) { [void]$merged.Add($h); $addedNew++ } }
        $tbExceptions.Text = ($merged -join "`r`n")
        Apply-Targets
        Log-Activity ("Imported {0} exception(s) from {1}; {2} new" -f $list.Count, [System.IO.Path]::GetFileName($dlg.FileName), $addedNew) $colors.Cyan
    }
})

$btnTestHost.Add_Click({
    Show-TestRestartDialog
})

$btnClearExc.Add_Click({
    $msg = "Clear the persisted exception list ({0} entries)? This deletes exceptions.txt on disk." -f $script:Exceptions.Count
    if ([System.Windows.Forms.MessageBox]::Show($msg,"Clear exceptions",'YesNo','Warning') -ne 'Yes') { return }
    $tbExceptions.Clear()
    $script:Exceptions.Clear()
    Save-ExceptionsToDisk -Hosts @()      # writes an empty file (acts as "explicitly empty" marker)
    $lblExcCount.Text = "0 in exception list"
    Log-Activity "Exception list cleared." $colors.Warning
})

function Render-PlanGrids {
    foreach ($g in @($gridPlan, $gridRun)) {
        $g.SuspendLayout()
        $g.Rows.Clear()
        foreach ($r in $script:Plan) {
            [void]$g.Rows.Add(@(
                $r.Host,
                (Format-Hms $r.DispatchAt),
                (Format-Hms $r.RestartAt),
                $r.Status,
                $r.Result
            ))
        }
        $g.ResumeLayout()
    }
}

function Tint-RunRows {
    ## Color rows by Status. Called from Refresh-Run after stats updates.
    for ($i = 0; $i -lt $gridRun.Rows.Count -and $i -lt $script:Plan.Count; $i++) {
        $status = $script:Plan[$i].Status
        $color = switch ($status) {
            'Dispatched'        { $colors.Success }
            'Already-Scheduled' { $colors.Warning }
            'Failed'            { $colors.Danger }
            'Aborted'           { $colors.Warning }
            'Abort Failed'      { $colors.Danger }
            'In-Flight'         { $colors.Cyan }
            'Consent-Launching' { $colors.Cyan }
            'Awaiting-Consent'  { $colors.Cyan }
            'Consent-Polling'   { $colors.Cyan }
            'Consent-Approved'  { $colors.Gold }
            'Declined'          { $colors.Warning }
            'Unreachable'       { $colors.Danger }
            'Skipped-Server'    { $colors.TextDim }
            default             { $colors.TextPrimary }
        }
        $gridRun.Rows[$i].Cells['Status'].Style.ForeColor = $color
        $gridRun.Rows[$i].Cells['Result'].Value = $script:Plan[$i].Result
        $gridRun.Rows[$i].Cells['Status'].Value = $status
    }
}

$btnCompute.Add_Click({
    if ($script:Targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Apply targets on the Targets tab first.","No targets",'OK','Warning') | Out-Null
        return
    }
    $restartTime = [datetime]$dtpStart.Value
    $lead        = [int]$numLead.Value

    Build-Plan -RestartTime $restartTime -LeadMinutes $lead

    $row0 = $script:Plan[0]
    $lblPlanSummary.Text = (
        "{0} machines  |  ALL restart at {1}  |  Dispatch begins {2}  |  {3}-min warning per host" -f
        $script:Plan.Count,
        (Format-Hms $row0.RestartAt),
        (Format-Hms $row0.DispatchAt),
        $lead
    )
    Render-PlanGrids
    $script:Stats.Total   = $script:Plan.Count
    $script:Stats.Pending = $script:Plan.Count
    $script:Stats.InFlight = 0
    $script:Stats.Sent = 0
    $script:Stats.Failed = 0
    $script:Stats.Aborted = 0
    $script:Stats.Awaiting = 0
    $script:Stats.Declined = 0
    $script:Stats.Skipped = 0
    Refresh-StatsLabels
    Log-Activity ("Computed plan: {0} machines, dispatch {1} - {2}" -f $script:Plan.Count, (Format-Hms $script:Plan[0].DispatchAt), (Format-Hms $script:Plan[-1].DispatchAt)) $colors.Gold
})

$btnSchedTask.Add_Click({ Invoke-RrsScheduleAsTask })

$btnSavePlan.Add_Click({
    if ($script:Plan.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Compute the plan first.","No plan",'OK','Warning') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = "CSV|*.csv"
    $dlg.FileName = "RestartPlan_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            Save-PlanCsv -Path $dlg.FileName
            Log-Activity ("Plan saved to {0}" -f $dlg.FileName) $colors.Cyan
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Save failed: $($_.Exception.Message)","Save plan",'OK','Error') | Out-Null
        }
    }
})

$btnExport.Add_Click({
    if ($script:Plan.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing to export.","Export",'OK','Warning') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = "CSV|*.csv"
    $dlg.FileName = "RestartResults_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    if ($dlg.ShowDialog() -eq 'OK') {
        try {
            Save-PlanCsv -Path $dlg.FileName
            Log-Activity ("Results exported to {0}" -f $dlg.FileName) $colors.Cyan
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)","Export",'OK','Error') | Out-Null
        }
    }
})

$btnVerify.Add_Click({
    ## Verify the hosts that actually accepted a restart command. Falls back to
    ## the full applied target list if nothing's been dispatched yet (so the
    ## operator can spot-check connectivity), with a heads-up that without a
    ## dispatch a "reboot" can't be confirmed - only current online/offline.
    $dispatched = @($script:Plan | Where-Object { $_.Status -eq 'Dispatched' -or $_.Status -eq 'Already-Scheduled' })
    if ($dispatched.Count -gt 0) {
        Show-RebootMonitorDialog -Rows $dispatched
        return
    }
    if ($script:Targets.Count -gt 0) {
        $msg = "No machines have been dispatched yet, so a reboot can't be confirmed (we never saw them go down).`r`n`r`nPing the {0} applied target(s) anyway to show current online/offline status?" -f $script:Targets.Count
        if ([System.Windows.Forms.MessageBox]::Show($msg, 'Verify Reboots', 'YesNo', 'Question') -eq 'Yes') {
            Show-RebootMonitorDialog -Rows @($script:Targets)
        }
        return
    }
    [System.Windows.Forms.MessageBox]::Show('No dispatched hosts and no applied targets to verify. Apply targets and start a dispatch first.', 'Verify Reboots', 'OK', 'Information') | Out-Null
})

## Resolve {LEAD} token in the warning message at dispatch time. shutdown.exe
## /c has a 512-char limit on Win10+; truncate proactively to 511.
function Get-EffectiveMessage {
    param([int]$LeadMinutes)
    $m = $tbMessage.Text -replace '\{LEAD\}', "$LeadMinutes"
    if ($m.Length -gt 511) { $m = $m.Substring(0, 511) }
    return $m
}

## v1.5.0-beta3 - pre-flight ping worker. Same bounded-timeout Ping.Send the
## reboot monitor uses (Test-Connection has no per-ping timeout on PS 5.1, so a
## wall of dead hosts would stall). DNS-fail / unreachable both surface as down.
$script:PreflightPingSB = {
    param($hostname, $timeoutMs)
    $up = $false
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $reply = $p.Send($hostname, $timeoutMs)
        if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $up = $true }
    } catch { $up = $false }
    [PSCustomObject]@{ Host = $hostname; Up = $up }
}

function Invoke-PreflightPingGate {
    ## Ping every still-Pending plan row in parallel and mark non-responders
    ## 'Unreachable' so the WinRM fan-out never spends a slot (and a 15 s
    ## OpenTimeout) on an offline box - the single biggest time sink on a
    ## full-fleet run. Runs synchronously from the Start handler with DoEvents
    ## pumping so the UI stays live. ICMP-only: a host that blocks ping but
    ## answers WinRM WOULD be skipped, which is why the caller gates this behind
    ## the (default-on) "Skip unreachable" checkbox. Returns hosts gated out.
    param([int]$TimeoutMs = 1000)

    $targets = @($script:Plan | Where-Object { $_.Status -eq 'Pending' })
    if ($targets.Count -eq 0) { return 0 }

    Log-Activity ("PRE-FLIGHT  pinging {0} host(s) before WinRM..." -f $targets.Count) $colors.Cyan

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pmax = [Math]::Min(64, [Math]::Max(4, $targets.Count))
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
    $pool.Open()

    $jobs      = @{}
    $reachable = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($row in $targets) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($script:PreflightPingSB)
            [void]$ps.AddArgument($row.Host)
            [void]$ps.AddArgument($TimeoutMs)
            $jobs[$row.Host] = @{ PS = $ps; Async = $ps.BeginInvoke() }
        }
        $total = $jobs.Count
        while ($jobs.Count -gt 0) {
            $done = @()
            foreach ($k in @($jobs.Keys)) { if ($jobs[$k].Async.IsCompleted) { $done += $k } }
            foreach ($k in $done) {
                $j = $jobs[$k]; $res = $null
                try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = $null }
                try { $j.PS.Dispose() } catch {}
                $jobs.Remove($k)
                if ($res -and [bool]$res.Up) { [void]$reachable.Add([string]$res.Host) }
            }
            $lblNext.Text = "Pre-flight ping: {0}/{1} answered  |  {2} in-flight..." -f $reachable.Count, $total, $jobs.Count
            [System.Windows.Forms.Application]::DoEvents()
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 60 }
        }
    } finally {
        try { $pool.Close() } catch {}
        try { $pool.Dispose() } catch {}
    }

    $gated = 0
    foreach ($row in $targets) {
        ## v1.5.0-beta3 review-fix: the ping loop above pumps DoEvents, so the
        ## operator may have hit Cancel mid-sweep, moving these rows out of
        ## Pending (to Cancelled). Never overwrite a row that already left Pending
        ## or we'd reclassify Cancelled hosts as Unreachable and double-count Stats.
        if ($row.Status -ne 'Pending') { continue }
        if (-not $reachable.Contains([string]$row.Host)) {
            $row.Status     = 'Unreachable'
            $row.Result     = 'Unreachable (no ping reply) - skipped, no WinRM attempted'
            $row.Dispatched = $false
            $script:Stats.Pending = [Math]::Max(0, $script:Stats.Pending - 1)
            $script:Stats.Failed++
            $gated++
        }
    }
    if ($gated -gt 0) {
        Log-Activity ("PRE-FLIGHT  {0} unreachable gated out; {1} reachable -> WinRM" -f $gated, ($targets.Count - $gated)) $colors.Warning
    } else {
        Log-Activity ("PRE-FLIGHT  all {0} host(s) answered ping" -f $targets.Count) $colors.Success
    }
    Tint-RunRows; Refresh-StatsLabels
    return $gated
}

function Apply-ServerSkipGate {
    ## v1.5.0-beta3 - mark server-named hosts 'Skipped-Server' so they never get
    ## pinged or contacted. Pure name match (instant, no network), so it runs
    ## BEFORE the ping gate. $Pattern is the operator-editable regex from the
    ## Schedule tab; a bad regex is caught and the gate is skipped (fail-open,
    ## so a typo never silently drops the whole fleet). Returns hosts gated out.
    param([string]$Pattern)

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return 0 }
    ## Validate the regex once up front; bail (keep everyone) if it won't compile.
    try { $null = [regex]::new($Pattern) }
    catch {
        Log-Activity ("SKIP-SVR  invalid server pattern '{0}' - skip-servers disabled this run ({1})" -f $Pattern, $_.Exception.Message) $colors.Danger
        return 0
    }

    $targets = @($script:Plan | Where-Object { $_.Status -eq 'Pending' })
    $gated = 0
    foreach ($row in $targets) {
        if ([string]$row.Host -match $Pattern) {
            $row.Status     = 'Skipped-Server'
            $row.Result     = 'Server-named host - skipped (not part of workstation reboot wave)'
            $row.Dispatched = $false
            $script:Stats.Pending = [Math]::Max(0, $script:Stats.Pending - 1)
            $script:Stats.Skipped++
            $gated++
        }
    }
    if ($gated -gt 0) {
        Log-Activity ("SKIP-SVR  {0} server-named host(s) excluded from this wave (pattern {1})" -f $gated, $Pattern) $colors.Warning
    }
    Tint-RunRows; Refresh-StatsLabels
    return $gated
}

function Update-ProgressLabels {
    ## Live Elapsed timer + ETA for the whole wave (ported from stable v1.4.3).
    ## "Done" = any host at a terminal status; rate = done/elapsed projected over
    ## what's left. Honest about early uncertainty; freezes on completion.
    if ($null -eq $script:DispatchStartTime) {
        $lblElapsed.Text = 'Elapsed --:--:--   |   Done 0/0'
        $lblEta.Text     = 'ETA --:--:--   |   finish ~--:--'
        return
    }
    $now      = Get-Date
    $endRef   = if ($script:DispatchEndTime) { $script:DispatchEndTime } else { $now }
    $elapsed  = $endRef - $script:DispatchStartTime
    $elapsedS = [Math]::Max(0.0, $elapsed.TotalSeconds)

    $total = [int]$script:Stats.Total
    if ($total -le 0) { $total = $script:Plan.Count }
    $done  = @($script:Plan | Where-Object { $script:TerminalStatuses -contains $_.Status }).Count
    $pct   = if ($total -gt 0) { [int][Math]::Round(100.0 * $done / $total) } else { 0 }

    if ($script:DispatchEndTime) {
        $lblElapsed.Text = "Completed in {0}   |   Done {1}/{2} (100%)" -f (Format-Duration $elapsed), $done, $total
        $lblEta.Text     = "Finished at {0}" -f $script:DispatchEndTime.ToString('HH:mm:ss')
        return
    }

    $lblElapsed.Text = "Elapsed {0}   |   Done {1}/{2} ({3}%)" -f (Format-Duration $elapsed), $done, $total, $pct

    if ($done -ge 3 -and $elapsedS -ge 5 -and $done -lt $total) {
        $rate      = $done / $elapsedS
        $remaining = $total - $done
        $etaSec    = if ($rate -gt 0) { $remaining / $rate } else { 0 }
        $etaTs     = [TimeSpan]::FromSeconds([Math]::Min($etaSec, 86400 * 7))
        $finish    = $now.AddSeconds($etaSec)
        $lblEta.Text = "ETA {0}   |   finish ~{1}" -f (Format-Duration $etaTs), $finish.ToString('HH:mm:ss')
    } elseif ($done -ge $total -and $total -gt 0) {
        $lblEta.Text = 'ETA 00:00:00   |   finishing...'
    } else {
        $lblEta.Text = "ETA --:--:--   |   calculating ({0}/{1})..." -f $done, $total
    }
}

function Tick-Dispatch {
    ## Called once per second by the form timer.
    ##   1. Reap completed jobs
    ##   2. If active, submit pending rows up to the concurrency cap.
    ##      Burst mode    -> submit ANY pending row, /t = (RestartAt - Now).
    ##      Time-gated    -> submit only rows whose DispatchAt <= Now, /t = LeadMinutes * 60.
    ##   3. Update Now / next-dispatch labels.
    Reap-CompletedJobs | Out-Null

    $now = Get-Date
    $lblNow.Text = "Now: " + (Format-Hms $now)

    if ($script:DispatchActive -and -not $script:CancelRequested) {
        $maxInFlight = [Math]::Max(1, [int]$numConc.Value)
        $lead        = [int]$numLead.Value
        $msg         = Get-EffectiveMessage -LeadMinutes $lead
        $dryRun      = [bool]$chkDryRun.Checked
        $burst       = [bool]$chkBurst.Checked

        $consent = $script:ConsentRequired   # captured at arm time; already false on dry runs
        $rollNow = $script:RollingMode       # rolling: restart each host on approval, no shared-time convergence

        foreach ($row in $script:Plan) {
            if ($global:ActiveJobs.Count -ge $maxInFlight) { break }
            ## A host is processed by exactly one job at a time. While it's in
            ## ActiveJobs (In-Flight / Consent-Launching / Consent-Polling) skip it.
            if ($global:ActiveJobs.ContainsKey($row.Host)) { continue }

            if (-not $consent) {
                ## --- Original direct-dispatch path (consent off / dry run) ---
                if ($row.Dispatched -or $row.Status -ne 'Pending') { continue }

                ## Per-host /t. In burst mode the value is computed at submit time
                ## as "seconds remaining until this host's RestartAt", clamped to a
                ## 60-second floor. That floor matters when an operator hits Start
                ## past the schedule's first RestartAt: the host gets a 1-minute
                ## warning instead of restarting before shutdown.exe can dispatch.
                $thisLeadSec = $null
                if ($rollNow) {
                    ## Rolling: reboot ASAP (just the grace), no convergence on RestartAt.
                    $thisLeadSec = [int]$script:RollingGraceSeconds
                } elseif ($burst) {
                    $rem = ($row.RestartAt - $now).TotalSeconds
                    if ($rem -lt 60) { $thisLeadSec = 60 } else { $thisLeadSec = [int][Math]::Round($rem) }
                } else {
                    if ($row.DispatchAt -gt $now) { continue }     # not yet
                    $thisLeadSec = $lead * 60
                }

                $row.Dispatched = $true
                $row.Status     = 'In-Flight'
                $script:Stats.Pending = [Math]::Max(0, $script:Stats.Pending - 1)
                Submit-DispatchJob -Hostname $row.Host -Action 'Dispatch' -LeadSeconds $thisLeadSec -Message $msg -DryRun $dryRun -Row $row -Credential $global:Credentials
                continue
            }

            ## --- Consent path: Pending -> launch prompt -> poll -> approve -> restart ---
            switch ($row.Status) {
                'Pending' {
                    ## Time-gate: a non-burst, non-rolling run holds prompts until
                    ## the dispatch window. But consent needs its prompt window to
                    ## resolve BEFORE the lead countdown, so when consent is ON we
                    ## open prompts ConsentPromptSeconds early - which also matches
                    ## the scheduled task's early fire (RestartAt - lead - prompt),
                    ## so an auto run prompts immediately instead of idling first.
                    ## Rolling mode prompts immediately (that's the whole point).
                    $gateAt = $row.DispatchAt
                    if ($script:ConsentRequired) { $gateAt = $row.DispatchAt.AddSeconds(-1 * [int]$script:ConsentPromptSeconds) }
                    if (-not $burst -and -not $rollNow -and $gateAt -gt $now) { break }
                    $tok = ("{0}_{1}_{2}" -f $row.Host, (Get-Date -Format 'yyyyMMddHHmmss'), ([guid]::NewGuid().ToString('N').Substring(0,6)))
                    $tok = ($tok -replace '[^A-Za-z0-9_]', '')
                    $row.ConsentToken = $tok
                    $cfgObj  = [ordered]@{ Token = $tok; Message = $msg; PromptSeconds = [int]$script:ConsentPromptSeconds; GraceSeconds = [int]$script:ConsentGraceSeconds }
                    $cfgJson = $cfgObj | ConvertTo-Json -Compress
                    $agentScript = ($script:ConsentAgentTemplate -replace '__TOKEN__', $tok)
                    $row.Status = 'Consent-Launching'
                    $script:Stats.Pending  = [Math]::Max(0, $script:Stats.Pending - 1)
                    $script:Stats.Awaiting++
                    Submit-ConsentJob -Hostname $row.Host -Phase 'ConsentLaunch' -ScriptBlock $script:ConsentLaunchScriptBlock -Arguments @($row.Host, $global:Credentials, $tok, $agentScript, $cfgJson) -Row $row -Credential $global:Credentials
                }
                'Awaiting-Consent' {
                    if ((-not $row.NextPollAt) -or ($now -ge $row.NextPollAt)) {
                        $row.Status = 'Consent-Polling'
                        Submit-ConsentJob -Hostname $row.Host -Phase 'ConsentPoll' -ScriptBlock $script:ConsentPollScriptBlock -Arguments @($row.Host, $global:Credentials, $row.ConsentToken) -Row $row -Credential $global:Credentials
                    }
                }
                'Consent-Approved' {
                    ## User accepted (or timed out / no user) - fire the real restart.
                    ## v1.5.0-beta3: converge on the shared restart time instead of
                    ## starting a fresh per-host grace countdown when this host's
                    ## prompt cleared. /t = seconds remaining until RestartAt,
                    ## floored at the Accept grace so an approver always gets at
                    ## least that much warning. Result: every approved machine
                    ## reboots together at RestartAt (matches burst semantics)
                    ## rather than rolling one-by-one as consents resolve. In a
                    ## time-gated (non-burst) run RestartAt is still honored the
                    ## same way; the grace floor covers a late-resolving consent.
                    if ($rollNow) {
                        ## Rolling: this host reboots ~grace seconds after IT approved,
                        ## independent of any shared clock - the wave keeps moving.
                        $leadSec = [int]$script:RollingGraceSeconds
                    } else {
                        $remSec  = [int][Math]::Round(($row.RestartAt - $now).TotalSeconds)
                        $leadSec = [Math]::Max([int]$script:ConsentGraceSeconds, $remSec)
                    }
                    $row.Dispatched = $true
                    $row.Status     = 'In-Flight'
                    Submit-DispatchJob -Hostname $row.Host -Action 'Dispatch' -LeadSeconds $leadSec -Message $msg -DryRun $false -Row $row -Credential $global:Credentials
                }
            }
        }
    }

    ## "Next pending" label - in burst mode there is no waiting, so report
    ## remaining queue size instead of a future DispatchAt time.
    $burstNow = [bool]$chkBurst.Checked
    $pending  = @($script:Plan | Where-Object { -not $_.Dispatched -and $_.Status -eq 'Pending' })
    if ($pending.Count -gt 0) {
        if ($burstNow) {
            $lblNext.Text = "Queue: {0} pending  |  in-flight {1}  |  burst mode" -f $pending.Count, $global:ActiveJobs.Count
        } else {
            $delta = $pending[0].DispatchAt - $now
            $deltaStr = if ($delta.TotalSeconds -lt 0) { 'now (catching up)' } else { ('in {0:c}' -f $delta).Split('.')[0] }
            $lblNext.Text = "Next: {0} at {1}  ({2})" -f $pending[0].Host, (Format-Hms $pending[0].DispatchAt), $deltaStr
        }
    } else {
        $awaiting = @($script:Plan | Where-Object { $_.Status -eq 'Awaiting-Consent' -or $_.Status -eq 'Consent-Launching' -or $_.Status -eq 'Consent-Polling' }).Count
        if ($awaiting -gt 0) {
            $lblNext.Text = "Awaiting user consent: {0} host(s)  |  in-flight {1}" -f $awaiting, $global:ActiveJobs.Count
        } else {
            $lblNext.Text = if ($global:ActiveJobs.Count -gt 0) { "Draining {0} in-flight job(s)..." -f $global:ActiveJobs.Count } else { 'No pending dispatches.' }
        }
    }

    Tint-RunRows
    Refresh-StatsLabels
    Update-ProgressLabels

    ## Auto-stop when the queue is fully drained. A row counts as "remaining"
    ## until it reaches a terminal status - this now includes the consent
    ## states (Awaiting-Consent etc.), which sit outside ActiveJobs between
    ## polls and would otherwise trip a premature stop.
    if ($script:DispatchActive -and $global:ActiveJobs.Count -eq 0) {
        $terminal  = $script:TerminalStatuses
        $remaining = @($script:Plan | Where-Object { $terminal -notcontains $_.Status }).Count
        if ($remaining -eq 0) {
            $script:DispatchActive = $false
            if ($null -ne $script:DispatchStartTime -and $null -eq $script:DispatchEndTime) { $script:DispatchEndTime = Get-Date }
            $btnStart.Enabled  = $true; $btnStart.Text = 'Start Dispatch'
            $btnCancel.Enabled = $false
            $btnAbort.Enabled  = ($script:Stats.Sent -gt 0)
            $elapsedNote = if ($script:DispatchStartTime) { " in " + (Format-Duration ($script:DispatchEndTime - $script:DispatchStartTime)) } else { '' }
            Log-Activity ("Dispatch complete{5}. Sent={0} Declined={1} Failed={2} Aborted={3} Skipped={4}" -f $script:Stats.Sent, $script:Stats.Declined, $script:Stats.Failed, $script:Stats.Aborted, $script:Stats.Skipped, $elapsedNote) $colors.Gold
            Update-ProgressLabels

            ## Auto-open the Reboot Verification Monitor once per run, for real
            ## (non-dry-run) dispatches that actually sent a restart. Dry runs
            ## never reboot anything, so there's nothing to verify. Skipped in
            ## auto/scheduled mode - no operator is watching the box.
            if (-not $script:RebootMonPrompted -and -not $script:AutoMode) {
                $script:RebootMonPrompted = $true
                $dispatchedRows = @($script:Plan | Where-Object { $_.Status -eq 'Dispatched' -or $_.Status -eq 'Already-Scheduled' })
                if ($dispatchedRows.Count -gt 0 -and -not [bool]$chkDryRun.Checked) {
                    try { Show-RebootMonitorDialog -Rows $dispatchedRows }
                    catch { Write-RLog "Reboot monitor failed to auto-open: $($_.Exception.Message)" 'WARN' }
                }
            }

            ## v1.5.0-beta - scheduled/auto run: self-delete the one-shot task and
            ## close so the unattended process doesn't linger. The closing-notes
            ## dialog is suppressed for auto mode in the FormClosing handler.
            if ($script:AutoMode) {
                try { if ($script:AutoTaskName) { & schtasks.exe /Delete /TN $script:AutoTaskName /F *>$null } } catch {}
                Write-RLog "AUTO MODE: wave drained, self-deleting task '$script:AutoTaskName' and closing."
                Set-JanetAllowClose $true
                try { $script:TickTimer.Stop() } catch {}
                try { $f.BeginInvoke([Action]{ $f.Close() }) | Out-Null } catch { try { $f.Close() } catch {} }
            }
        }
    }

    ## v1.5.0-beta3 review-fix: once nothing is active and no jobs remain, stop the
    ## tick timer so it doesn't keep firing Tick-Dispatch for the rest of the
    ## session. Covers a drained manual run (auto-stop set DispatchActive=$false
    ## above), a Cancel (handler clears DispatchActive; we wait out in-flight here),
    ## and an abort-only run (which never sets DispatchActive). Dispose is left to
    ## FormClosing, which owns the timer's lifetime - a later Start re-uses it.
    if (-not $script:DispatchActive -and $global:ActiveJobs.Count -eq 0) {
        try { if ($script:TickTimer) { $script:TickTimer.Stop() } } catch {}
    }
}

$btnStart.Add_Click({
    if ($script:DispatchActive) { return }
    if ($script:StartWaiting) { return }   # already counting down to a scheduled start; ignore re-click

    ## In-app delayed start (v1.5.0-beta4): if "Begin at the scheduled time" is
    ## ticked and that time is still in the future, hold here and auto-fire Start
    ## when it arrives. Skipped in auto/scheduled-task mode (the task itself is
    ## the timer) and once the countdown has already elapsed this run.
    if ([bool]$chkBeginAtTime.Checked -and -not $script:StartWaitSatisfied -and -not $script:AutoMode) {
        $target = [datetime]$dtpStart.Value
        if ((Get-Date) -lt $target) {
            $script:StartWaitTarget   = $target
            $script:StartWaiting      = $true
            $script:CancelRequested   = $false
            $btnStart.Enabled  = $false
            $btnCancel.Enabled = $true
            if (-not $script:StartWaitTimer) {
                $script:StartWaitTimer = New-Object System.Windows.Forms.Timer
                $script:StartWaitTimer.Interval = 1000
                $script:StartWaitTimer.Add_Tick({
                    if ($script:CancelRequested) { try { $script:StartWaitTimer.Stop() } catch {}; $script:StartWaiting = $false; return }
                    ## Re-read the picker each tick so the operator can push the
                    ## scheduled start earlier/later mid-countdown and it takes effect.
                    $script:StartWaitTarget = [datetime]$dtpStart.Value
                    $left = $script:StartWaitTarget - (Get-Date)
                    if ($left.TotalSeconds -le 0) {
                        try { $script:StartWaitTimer.Stop() } catch {}
                        $script:StartWaiting     = $false
                        $script:StartWaitSatisfied = $true
                        $btnStart.Text = 'Start Dispatch'
                        ## v1.6.0-beta FIX: the button was disabled when the
                        ## countdown armed, and PerformClick() on a DISABLED
                        ## button is a silent no-op (ButtonBase requires
                        ## CanSelect) - so the countdown hit 0:00 and nothing
                        ## fired. Re-enable before clicking.
                        $btnStart.Enabled = $true
                        $btnStart.PerformClick()
                    } else {
                        $btnStart.Text = 'Starts in ' + (Format-Duration $left)
                        $lblNext.Text  = "Scheduled start: {0}  (in {1})" -f (Format-Hms $script:StartWaitTarget), (Format-Duration $left)
                    }
                })
            }
            $script:StartWaitTimer.Start()
            Log-Activity ("Scheduled start armed: wave auto-begins at {0}. (Cancel to abort.)" -f (Format-Hms $target)) $colors.Gold
            return
        }
    }
    $script:StartWaitSatisfied = $false   # consumed / not needed; reset for any future run

    ## Auto-compute schedule if none exists. Uses the current Schedule tab
    ## settings + the currently-applied Targets. This removes the
    ## "Compute Schedule first" popup ceremony - operators can paste
    ## targets on the Targets tab and click Start Dispatch directly.
    if ($script:Plan.Count -eq 0) {
        if ($script:Targets.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No targets applied. Paste hostnames on the Targets tab and click Apply.","No targets",'OK','Warning') | Out-Null
            return
        }
        $restartTime = [datetime]$dtpStart.Value
        $lead        = [int]$numLead.Value
        Build-Plan -RestartTime $restartTime -LeadMinutes $lead
        Render-PlanGrids
        $script:Stats.Total    = $script:Plan.Count
        $script:Stats.Pending  = $script:Plan.Count
        $script:Stats.InFlight = 0
        $script:Stats.Sent     = 0
        $script:Stats.Failed   = 0
        $script:Stats.Aborted  = 0
        $script:Stats.Awaiting = 0
        $script:Stats.Declined = 0
        $script:Stats.Skipped  = 0
        Refresh-StatsLabels
        Log-Activity ("Auto-computed plan: {0} machines, ALL restart at {1}" -f $script:Plan.Count, (Format-Hms $script:Plan[0].RestartAt)) $colors.Gold
    }

    ## v1.5.0-beta3 review-fix: on a re-arm (Start clicked again with an existing
    ## plan), revive rows the operator Cancelled in a prior pass back to Pending so
    ## they re-dispatch. Without this the leftover Cancelled rows (now treated as
    ## terminal by auto-stop) would make the re-armed wave complete instantly with
    ## no work done on them. No-op on a freshly-built plan. Already-actioned rows
    ## (Dispatched/Failed/Skipped-Server/Unreachable) are intentionally left alone.
    $revived = 0
    foreach ($r in $script:Plan) {
        if ($r.Status -eq 'Cancelled') { $r.Status = 'Pending'; $r.Dispatched = $false; $r.Result = ''; $revived++ }
    }
    if ($revived -gt 0) {
        $script:Stats.Pending = @($script:Plan | Where-Object { $_.Status -eq 'Pending' }).Count
        Refresh-StatsLabels; Tint-RunRows
        Log-Activity ("Re-arm: revived {0} previously-cancelled host(s) to Pending." -f $revived) $colors.Cyan
    }

    $burst = [bool]$chkBurst.Checked

    ## Capture consent settings ONCE at arm time so toggling the controls
    ## mid-run can't change the in-flight policy. Dry runs never prompt.
    $script:ConsentRequired      = ([bool]$chkConsent.Checked) -and (-not [bool]$chkDryRun.Checked)
    $script:ConsentPromptSeconds = [int]$numPromptWin.Value * 60
    $script:ConsentGraceSeconds  = [int]$numAcceptGrace.Value

    ## Rolling / go-fast settings, captured once at arm time.
    $script:RollingMode         = [bool]$chkRolling.Checked
    $script:RollingGraceSeconds = [int]$numRollingGrace.Value

    $script:MaxConcurrency = [int]$numConc.Value
    Init-RunspacePool
    $script:DispatchActive  = $true
    $script:CancelRequested = $false
    $script:RebootMonPrompted = $false   # re-arm the auto-open for this run
    ## Start the Elapsed/ETA clock (includes the pre-flight ping phase). Re-arm of
    ## a partly-done plan keeps the original start; a fresh/completed run resets it.
    if ($null -eq $script:DispatchStartTime -or $script:DispatchEndTime) { $script:DispatchStartTime = Get-Date }
    $script:DispatchEndTime = $null
    $btnStart.Enabled  = $false; $btnStart.Text = 'Dispatching...'
    $btnCancel.Enabled = $true
    $btnAbort.Enabled  = $true

    ## v1.5.0-beta3 - server skip. Pure name match, instant, runs first so we
    ## don't even ping a host we're going to skip. Applies on dry runs too (it
    ## changes WHICH hosts the wave targets, which a dry run should reflect).
    if ([bool]$chkSkipServers.Checked) {
        try { Apply-ServerSkipGate -Pattern ([string]$tbServerPat.Text) | Out-Null }
        catch { Write-RLog "Server-skip gate failed (continuing without it): $($_.Exception.Message)" 'WARN' }
    }

    ## v1.5.0-beta3 - pre-flight reachability gate. Ping the whole plan in
    ## parallel and drop non-responders to 'Unreachable' BEFORE the WinRM
    ## fan-out, so offline boxes never burn a dispatch slot on a 15 s connect
    ## timeout (and never pad the reboot-monitor tail). ICMP-only; skipped on
    ## dry runs and when the operator unticks "Skip unreachable". Runs with
    ## DoEvents pumping, so a mid-sweep Cancel still takes effect.
    if ([bool]$chkPreflight.Checked -and -not [bool]$chkDryRun.Checked) {
        try { Invoke-PreflightPingGate | Out-Null }
        catch { Write-RLog "Pre-flight ping gate failed (continuing without it): $($_.Exception.Message)" 'WARN' }
    }

    ## v1.5.1 - open the reboot monitor at dispatch START, not queue drain.
    ## A ping monitor can only credit a down->up cycle it personally witnesses;
    ## by drain-time, rolling / catch-up / late-consent hosts (60s grace floor)
    ## have already rebooted and were reported "Online (no reboot seen)". The
    ## drain-time auto-open below remains as a fallback / reopen. Modeless, so
    ## the Run tab stays fully usable. Skipped on dry runs (nothing will reboot)
    ## and in auto/scheduled mode (no operator is watching).
    if (-not $script:AutoMode -and -not [bool]$chkDryRun.Checked) {
        $watchRows = @($script:Plan | Where-Object { $_.Status -eq 'Pending' })
        if ($watchRows.Count -gt 0) {
            try { Show-RebootMonitorDialog -Rows $watchRows }
            catch { Write-RLog "Reboot monitor failed to open at dispatch start: $($_.Exception.Message)" 'WARN' }
        }
    }

    $authNote = if ($null -ne $global:Credentials) { "PSSession as $($global:Credentials.UserName)" } else { 'RPC as current user' }
    $consentNote = if ($script:ConsentRequired) { "consent ON ({0}-min prompt, {1}s grace)" -f [int]$numPromptWin.Value, $script:ConsentGraceSeconds } else { 'consent OFF' }
    Log-Activity ("Dispatch armed. {0} machines, concurrency {1}, burst {2}, dry-run {3}, {4}, transport {5}" -f $script:Plan.Count, $script:MaxConcurrency, $burst, $chkDryRun.Checked, $consentNote, $authNote) $colors.Gold

    if (-not $script:TickTimer) {
        $script:TickTimer = New-Object System.Windows.Forms.Timer
        $script:TickTimer.Add_Tick({ Tick-Dispatch })
    }
    ## Burst mode wants tight loops to feed the pool; time-gated mode only
    ## needs 1Hz to honor 1-second granularity on DispatchAt comparisons.
    $script:TickTimer.Interval = if ($burst -or $script:RollingMode) { 250 } else { 1000 }
    $script:TickTimer.Start()
})

$btnCancel.Add_Click({
    ## Cancel a pending scheduled-start countdown (wave hasn't begun yet).
    if ($script:StartWaiting) {
        $script:CancelRequested = $true
        try { if ($script:StartWaitTimer) { $script:StartWaitTimer.Stop() } } catch {}
        $script:StartWaiting = $false
        $btnStart.Enabled  = $true; $btnStart.Text = 'Start Dispatch'
        $btnCancel.Enabled = $false
        $lblNext.Text = 'Scheduled start cancelled.'
        Log-Activity 'Scheduled start cancelled before the wave began.' $colors.Warning
        return
    }
    if (-not $script:DispatchActive) { return }
    $script:CancelRequested = $true
    $script:DispatchActive  = $false
    $btnCancel.Enabled = $false
    $btnStart.Enabled  = $true; $btnStart.Text = 'Start Dispatch'
    ## Mark all not-yet-restarted rows as Cancelled. Includes consent limbo
    ## states (a prompt may still be on a user's screen, but we stop polling
    ## and won't restart - the agent's own timeout just goes unheeded).
    $cancellable = @('Pending','Awaiting-Consent','Consent-Approved')
    foreach ($r in $script:Plan) {
        if (-not $r.Dispatched -and ($cancellable -contains $r.Status)) {
            $r.Status = 'Cancelled'
            $r.Result = 'Cancelled before restart'
        }
    }
    ## v1.5.0-beta3 review-fix: recompute the live counters from the plan so the
    ## stats bar and the close-guard dialog don't keep reporting cancelled hosts
    ## as still Pending / Awaiting.
    $script:Stats.Pending  = @($script:Plan | Where-Object { $_.Status -eq 'Pending' }).Count
    $script:Stats.Awaiting = @($script:Plan | Where-Object { @('Awaiting-Consent','Consent-Launching','Consent-Polling') -contains $_.Status }).Count
    Refresh-StatsLabels; Tint-RunRows
    Log-Activity "Pending dispatches cancelled. Already-dispatched commands are still running on targets." $colors.Warning
})

$btnAbort.Add_Click({
    ## v1.5.0-beta3 review-fix: include 'Already-Scheduled' (rc=1190) - those hosts
    ## have a pending reboot and must be abortable. @() keeps .Count safe on a 0/1 result.
    $dispatched = @($script:Plan | Where-Object { @('Dispatched','Already-Scheduled') -contains $_.Status }).Count
    if ($dispatched -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nothing to abort - no machines have been successfully dispatched yet.","Abort",'OK','Information') | Out-Null
        return
    }
    $msg = "Send `shutdown /a` to {0} machines that have already accepted a restart command?`r`n`r`nThis cancels any pending restart on those hosts. Machines that have already restarted are not affected." -f $dispatched
    if ([System.Windows.Forms.MessageBox]::Show($msg,"Confirm remote abort",'YesNo','Warning') -ne 'Yes') { return }

    Init-RunspacePool
    $sent = Send-RemoteAbortFanOut
    Log-Activity ("Submitted {0} remote-abort command(s)." -f $sent) $colors.Warning

    ## Make sure the tick timer is running to reap the abort jobs even if
    ## the main dispatch was already complete.
    if (-not $script:TickTimer) {
        $script:TickTimer = New-Object System.Windows.Forms.Timer
        $script:TickTimer.Interval = 1000
        $script:TickTimer.Add_Tick({ Tick-Dispatch })
    }
    if (-not $script:TickTimer.Enabled) { $script:TickTimer.Start() }
})

$closeToolHandler = {
    Set-JanetAllowClose $true
    $f.Close()
}
$btnCloseTool.Add_Click($closeToolHandler)
$btnHeaderClose.Add_Click($closeToolHandler)

$btnSetCred.Add_Click({
    ## WPT 6.5.16 line 6140 + ACAS Nemesis 1.10.0 line 7858 pattern verbatim.
    ## Get-Credential -Message pops the standard Windows credential dialog,
    ## which on AFNET workstations offers "More choices > Smart Card" so the
    ## operator can pick their CAC cert. The resulting PSCredential's
    ## UserName is the @@-prefixed cert identifier - that's the correct
    ## AFNET admin principal, not an MSA token. (The capture path is
    ## NOT what was failing earlier; my prior diagnosis was wrong.)
    try {
        $cred = Get-Credential -Message 'Enter admin credentials for remote workstation operations'
        if ($cred) {
            $global:Credentials            = $cred
            $script:CredInheritedFromJanet = $false
            Refresh-CredStatus
            Log-Activity ("Credentials set: $($cred.UserName)") $colors.Success
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to capture credentials: $($_.Exception.Message)",
            'Remote Restart Scheduler', 'OK', 'Error') | Out-Null
    }
})

$btnClearCred.Add_Click({
    ## Wipes BOTH the in-memory cred AND the on-disk launcher cred file.
    ## The disk-delete is intentional - without it, a stale MSA token saved
    ## by an older launcher / tool version keeps getting inherited on every
    ## launch and the operator has no way to recover short of manually
    ## deleting %LOCALAPPDATA%\JANET\Session\janet_cred.xml.
    if ($null -ne $global:Credentials) {
        $oldUser = $global:Credentials.UserName
        $global:Credentials            = $null
        $script:CredInheritedFromJanet = $false
        Refresh-CredStatus
        Log-Activity ("Credentials cleared from memory (was: $oldUser).") $colors.Warning
    }
    if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
        try {
            Remove-Item -LiteralPath $env:JANET_CRED_FILE -Force -ErrorAction Stop
            Write-RLog "Removed launcher cred file $env:JANET_CRED_FILE"
            Log-Activity ("Deleted launcher cred file: $env:JANET_CRED_FILE") $colors.Warning
        } catch {
            Write-RLog "Could not remove cred file: $($_.Exception.Message)" "WARN"
            Log-Activity ("Could not delete cred file: $($_.Exception.Message)") $colors.Danger
        }
    }
})
#endregion

#region === STARTUP / SHUTDOWN ===
Log-Activity "Remote Restart Scheduler ready" $colors.Gold
Log-Activity ("Defaults: Window=60min  Lead=15min  Start={0}" -f (Format-Hms $defaultStart)) $colors.TextSecondary
Log-Activity "Workflow: Targets -> Schedule -> Compute -> Start Dispatch" $colors.TextSecondary

Set-JanetAllowClose $false
$f.Add_FormClosing({
    param($sender, $e)
    if (-not (Get-JanetAllowClose) -and $e.CloseReason -ne [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        ## Guard against accidental close while a dispatch is mid-flight.
        if ($script:DispatchActive -or $global:ActiveJobs.Count -gt 0) {
            $msg = "A dispatch is in progress (in-flight: {0}, pending: {1}). Use Cancel Pending first, then Close Tool. Force close anyway?" -f $global:ActiveJobs.Count, $script:Stats.Pending
            if ([System.Windows.Forms.MessageBox]::Show($msg,"Dispatch active",'YesNo','Warning') -ne 'Yes') {
                $e.Cancel = $true
                return
            }
        } elseif ($script:StartWaiting) {
            ## A scheduled start is counting down (wave hasn't begun). X/Alt-F4
            ## would otherwise be silently refused; offer to cancel + close. The
            ## StartWaitTimer is torn down below regardless of which path closes.
            $msg = "A scheduled start is counting down (begins {0}). Cancel it and close the tool?" -f (Format-Hms $script:StartWaitTarget)
            if ([System.Windows.Forms.MessageBox]::Show($msg,"Scheduled start pending",'YesNo','Warning') -ne 'Yes') {
                $e.Cancel = $true
                return
            }
        } else {
            $e.Cancel = $true
            return
        }
    }

    Write-RLog "Form closing"
    ## Stop the in-app delayed-start timer FIRST and unconditionally - otherwise a
    ## close while it's counting down (incl. the Close Tool button, which bypasses
    ## the guard above) leaves it firing PerformClick() on a disposed form, which
    ## could crash or even arm a wave with no UI present.
    try { if ($script:StartWaitTimer) { $script:StartWaitTimer.Stop(); $script:StartWaitTimer.Dispose() } } catch {}
    $script:StartWaiting = $false
    try { if ($script:TickTimer) { $script:TickTimer.Stop(); $script:TickTimer.Dispose() } } catch {}
    try {
        foreach ($j in $global:ActiveJobs.Values) { try { $j.PS.Stop() } catch {}; try { $j.PS.Dispose() } catch {} }
        if ($global:RunspacePool) { $global:RunspacePool.Close(); $global:RunspacePool.Dispose() }
    } catch {}
    ## Auto/scheduled mode has no operator at the keyboard - close the session
    ## without the interactive closing-notes dialog. Manual runs keep it.
    try {
        if ($script:AutoMode) { Stop-JanetSession }
        else                  { Stop-JanetSession -ShowDialog }
    } catch { Write-RLog "JANET Stop-JanetSession failed: $($_.Exception.Message)" }
    Write-RLog "=== Session ended ==="
})

try { Start-JanetSession -Tool 'Remote_Restart' -Version $JanetRemoteRestartVersion } catch { Write-RLog "JANET Start-JanetSession failed: $($_.Exception.Message)" }

## Reflect any launcher-inherited credential in the header status label.
try { Refresh-CredStatus } catch {}

## Load persisted exception list now that the session (and therefore Get-JanetLocalDir) is wired up.
try {
    $persisted = Load-ExceptionsFromDisk
    if ($persisted -and $persisted.Count -gt 0) {
        $tbExceptions.Text = ($persisted -join "`r`n")
        foreach ($h in $persisted) { [void]$script:Exceptions.Add($h) }
        $lblExcCount.Text = "$($script:Exceptions.Count) in exception list"
        Log-Activity ("Loaded {0} persisted exception(s)" -f $persisted.Count) $colors.TextSecondary
    }
} catch { Write-RLog "Exception list load failed: $($_.Exception.Message)" "WARN" }

## v1.5.0-beta - when launched by the one-shot scheduled task (-AutoDispatch),
## replay the job and auto-arm the wave once the form is up and pumping messages.
## Manual launches just show the GUI as before.
if ($script:AutoMode) {
    $f.Add_Shown({ Start-RrsAutoDispatch })
}

[void]$f.ShowDialog()
#endregion
