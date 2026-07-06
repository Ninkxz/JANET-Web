# =============================================================================
#  JanetWeb.wpt.psm1  -  Workstation Patching tool engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\WorkstationPatchingTool_6.5.22.ps1 (engine reused, the
#  WinForms layer dropped). Fans out MECM/WMI/WinRM remote-ops across many
#  workstations in parallel via a RunspacePool, with per-host streaming.
#
#  The remote scriptblocks below are lifted faithfully from the original tool's
#  $global:ScanBlock / $global:PatchBlock / $global:RebootBlock / the six Heal
#  blocks / $global:WinRMBootstrapBlock / $global:CleanBlock /
#  $global:RegKeyScanBlock / $global:RegKeyApplyBlock / $global:L4JFinderBlock,
#  plus the KB / Software / Remote-Message / App-Update handlers.
#
#  Contract (identical to JanetWeb.message.psm1):
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'wpt'
        name     = 'Workstation Patching'
        category = 'Patching'
        version  = '6.5.32'
        summary  = 'MECM-driven bulk scan/patch, KB management, software uninstall, Software Center available-deployments picker, health diagnostics + healers (incl. CCM client repair), single-host info + event-log triage, maintenance lock/unlock (banner + optional logon hard-lock), AD OU target import, reboot, disk + ccmcache cleanup, per-profile user-app cleanup, STIG reg-key fixes, app updates (incl. Trellix/McAfee) and Log4j scanning across many workstations in parallel (WinRM/DCOM).'
        actions  = @(
            @{
                id='bulk-scan'; label='Bulk Scan'; kind='stream-table'; destructive=$false
                description='Parallel scan of each target: online (TCP 5985/445), logged-on user, C: disk space, reboot-pending, MECM/WUA/app pending counts.'
                columns=@('Host','LoggedOnUser','Online','OsName','OsBuild','DriveSize','DriveFree','DriveFreePercent','RebootPending','LastBootTime','MECMUpdateCount','WindowsUpdateCount','AppCount','Error')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 },
                    @{ name='saveSnapshot'; label='Save snapshot for trending'; type='bool'; required=$false; default=$false }
                )
            },
            @{
                id='trend'; label='Compliance Trend'; kind='stream-table'; destructive=$false
                description='Read-only fleet compliance trend from saved Bulk Scan snapshots (JanetLocal\snapshots, newest 60). One row per snapshot (newest first): total hosts, online, hosts with any pending update channel, and reboot-pending count. Hosts pending in 3+ consecutive snapshots are streamed to the activity log as "stuck". Reads local files only - no hosts are touched.'
                columns=@('ScanStamp','TotalHosts','Online','HostsPending','RebootPending','PendingUpdates','File')
                inputs=@()
            },
            @{
                id='bulk-patch'; label='Patch Selected'; kind='stream-table'; destructive=$true
                description='Trigger MECM software updates and pending app installs on the checked/targeted hosts. Patch posture (mode): "noninvasive" (default) suppresses reboots so patching runs while users work; "forced" sets reboot-if-needed on app installs (customer-affecting) for quarantined / no-user hosts. Tip: on the Bulk Scan grid, "Select With Updates" checks the hosts that need work, or "Patch All Needing" selects + patches them in one click.'
                columns=@('Host','Reachable','UpdatesTriggered','AppsTriggered','Error')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='mode'; label='Patch posture'; type='select'; options=@('noninvasive','forced'); default='noninvasive'; required=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='reboot'; label='Reboot Selected'; kind='stream-table'; destructive=$true
                description='Force an immediate reboot on each target (Restart-Computer -Force).'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='reboot-schedule'; label='Arm Reboot Countdown'; kind='stream-table'; destructive=$true
                confirm='Arm a scheduled reboot on the target(s)? Each host gets a shutdown /r /t timer (and, if a user is logged on and a message is supplied, a warning popup). Use Cancel Countdown to call it off before it fires. Proceed?'
                description='Schedule a delayed reboot on each target (shutdown /r /t), re-arming cleanly over any existing timer, and optionally pop a warning to the logged-on user. Pair with Cancel Countdown (reboot-abort) and Send Warning Now (remote-message).'
                columns=@('Host','Success','RebootAt','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='seconds'; label='Delay before reboot (seconds)'; type='int'; required=$true; default=900 },
                    @{ name='message'; label='Warning popup body (blank = no popup)'; type='string'; required=$false; default='' },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='reboot-abort'; label='Cancel Reboot Countdown'; kind='stream-table'; destructive=$true
                description='Abort a pending scheduled reboot on each target (shutdown /a). Hosts with no pending shutdown report "nothing to cancel".'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='ping-sweep'; label='Ping Sweep'; kind='stream-table'; destructive=$false
                description='TCP reachability test (ports 5985/445) across the target list.'
                columns=@('Host','Reachable')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            },
            @{
                id='winrm-bootstrap'; label='Repair WinRM'; kind='stream-table'; destructive=$true
                description='Bootstrap WinRM over DCOM on offline hosts: set service Automatic, start it, run winrm quickconfig, re-probe 5985.'
                columns=@('Host','Success','PostProbeOk','Steps')
                inputs=@(
                    @{ name='targets'; label='Offline hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='health-scan'; label='Health Scan'; kind='stream-table'; destructive=$false
                description='Deep diagnostics: MECM state, WMI/WU health, reboot-pending age, last check-in, overall verdict.'
                columns=@('Host','MecmState','ClientVersion','SwCenter','WmiHealth','WuState','RebootPending','RebootAge','LastCheckIn','OverallHealth')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='healer-restart-ccm'; label='Restart MECM Client'; kind='stream-table'; destructive=$true
                description='Stop and start the CcmExec service on each target.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='healer-wmi-repair'; label='Repair WMI'; kind='stream-table'; destructive=$true
                description='Run winmgmt /salvagerepository on each target.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='healer-wu-reset'; label='Reset Windows Update'; kind='stream-table'; destructive=$true
                description='Stop wuauserv/cryptsvc/bits/msiserver, rename SoftwareDistribution + catroot2, restart services.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='healer-trigger-checkin'; label='Trigger MECM Check-In'; kind='stream-table'; destructive=$false
                description='Trigger MachinePolicy + Software Updates Scan MECM cycles.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='healer-gpupdate'; label='Group Policy Update'; kind='stream-table'; destructive=$true
                description='Run gpupdate.exe /force /wait:60 on each target.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='healer-ccm-repair'; label='Repair MECM Client'; kind='stream-table'; destructive=$true
                confirm='Trigger a full ConfigMgr client repair (SMS_Client.RepairClient -> ccmsetup.exe) on the target(s)? The client reinstalls in the background (5-20 min/host). Proceed?'
                description='Trigger SMS_Client.RepairClient() on each target (full ccmsetup-based client repair), briefly confirm ccmsetup.exe started, and report the last ccmsetup.log return code. The repair itself runs 5-20 min in the background; re-check with Health Scan afterward.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='software-scan'; label='Software Scan'; kind='table'; destructive=$false
                description='Single-host registry scan: Win32 apps (HKLM/HKU Uninstall) + Store apps. Returns the uninstall string so Software Uninstall can act on a row.'
                columns=@('Name','Version','Publisher','InstallDate','Install Type','Size')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true },
                    @{ name='filter'; label='Name/Publisher filter (optional)'; type='text'; required=$false }
                )
            },
            @{
                id='scan-detail'; label='Scan Detail (1 host)'; kind='table'; destructive=$false
                description='Single-host drill-down: list the NAMED pending items per channel - MECM updates, direct Windows Update titles, and pending Software Center apps (the names behind the bulk-scan counts).'
                columns=@('Host','Channel','Name')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true }
                )
            },
            @{
                id='host-info'; label='Host Info (1 host)'; kind='table'; destructive=$false
                description='Single-host snapshot: model, BIOS version, serial, MAC/IP, OS build/DisplayVersion, uptime, RAM, C: free, logged-on + recent users, pending reboot - one Property/Value row each. First-step triage card.'
                columns=@('Property','Value')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true }
                )
            },
            @{
                id='eventlog-scan'; label='Event Log Errors (1 host)'; kind='table'; destructive=$false
                description='Pull recent Error+Critical entries (last N hours) from the Application/System/Security logs of one host (Schannel noise filtered). Read-only diagnostics.'
                columns=@('Log','TimeCreated','EventId','Provider','Message')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true },
                    @{ name='application'; label='Application log'; type='bool'; required=$false; default=$true },
                    @{ name='system'; label='System log'; type='bool'; required=$false; default=$true },
                    @{ name='security'; label='Security log'; type='bool'; required=$false; default=$false },
                    @{ name='hours'; label='Look back (hours)'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='ad-computers'; label='AD Computers (OU import)'; kind='table'; destructive=$false
                description='Query Active Directory for computer objects (name + OU + OS + enabled) to drive the Targets OU-import picker. Read-only LDAP (no RSAT); honors the Set-Credentials identity.'
                columns=@('Name','OU','OS','Enabled')
                inputs=@(
                    @{ name='workstationsonly'; label='Workstations only (exclude servers)'; type='bool'; required=$false; default=$true },
                    @{ name='filter'; label='Name/OS filter (optional)'; type='text'; required=$false }
                )
            },
            @{
                id='software-uninstall'; label='Software Uninstall'; kind='stream-table'; destructive=$true
                description='Uninstall apps on one host by display name or uninstall GUID. Auto-detects type: MSI (msiexec /x /qn /norestart), EXE (quiet/silent uninstall string), or Store app (Remove-AppxPackage -AllUsers). Run a Software Scan first to get exact names.'
                columns=@('Host','App','Install Type','Result','Detail')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true },
                    @{ name='apps'; label='Apps to uninstall (one display name or {GUID} per line)'; type='textarea'; required=$true }
                )
            },
            @{
                id='app-list'; label='Software Center Apps (1 host)'; kind='table'; destructive=$false
                description='List the CCM_Application catalog on one host (Software Center): name, install/eval state, applicability, version, and the Id/Revision needed to drive an App Action.'
                columns=@('Host','Name','InstallState','Applicable','EvalState','Version','Id','Revision','IsMachineTarget')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true }
                )
            },
            @{
                id='app-action'; label='Software Center App Action'; kind='stream-table'; destructive=$true
                description='Install / Uninstall / Reinstall / Repair Software Center apps (CCM_Application) via the client SDK, across one or many hosts. Easiest path: open Software Center Apps, query a host, check the app(s) and use the Install/Uninstall/Reinstall/Repair buttons - that fills App Id(s) and host here. Revision and machine/user targeting are auto-resolved from each host''s live catalog, and a non-applicable app is reported (not falsely "triggered"). Reinstall = Uninstall, wait, Install. One result row per host x app.'
                columns=@('Host','App','Method','Result','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='appids'; label='CCM_Application Id(s) - one per line (from Software Center Apps)'; type='textarea'; required=$false },
                    @{ name='appid'; label='...or a single CCM_Application Id'; type='text'; required=$false },
                    @{ name='method'; label='Method'; type='select'; required=$false; default='Install'; options=@('Install','Uninstall','Reinstall','Repair') },
                    @{ name='revision'; label='Revision (optional - auto-resolved from the host if blank)'; type='text'; required=$false },
                    @{ name='ismachinetarget'; label='Machine-targeted (auto-detected from catalog; fallback only)'; type='bool'; required=$false; default=$true },
                    @{ name='threads'; label='Parallel operations'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='sccm-available'; label='Available Deployments (1 host)'; kind='table'; destructive=$false
                description='Unified read-only list of everything MECM has AVAILABLE for one host - applicable Software Center apps not yet installed + pending software updates - so you see what the client still needs in one place (auto-skips already-installed in the picker).'
                columns=@('Type','Name','State','Version','Id','Revision')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true }
                )
            },
            @{
                id='sccm-install-available'; label='Install Available (deploy)'; kind='stream-table'; destructive=$true
                confirm='Trigger install of the selected MECM deployment(s) on this host? Apps install via the Software Center client, updates via the Software Updates agent. Proceed?'
                description='Install the checked available deployments on one host: Software Center apps via CCM_Application.Install, software updates via CCM_SoftwareUpdatesManager.InstallUpdates. Driven by the "Install Checked" button on Available Deployments. One result row per item.'
                columns=@('Host','Type','Name','Result','Detail')
                inputs=@(
                    @{ name='host'; label='Host'; type='hostpick'; required=$true },
                    @{ name='items'; label='Items (Type|Id|Revision|Name per line; filled by the picker)'; type='textarea'; required=$true }
                )
            },
            @{
                id='unsupported-scan'; label='Unsupported Software Scan'; kind='stream-table'; destructive=$false
                description='Bulk: cross-reference each host''s installed software against the ACAS/Tenable unsupported & SEoL product catalog (MSXML, old Office/M365, SQL/Oracle, .NET Core/ASP.NET SEoL, Firefox, Log4j 1.x, Flash, Java...). Returns ONLY the host x product matches that need action, each tagged with a remediation Action (Uninstall / Update / Review). Check rows and use the "Uninstall Matched" grid button to remove the Uninstall-tagged ones (Review/Update are skipped).'
                columns=@('Host','Product','InstalledName','Version','Category','Action','Notes')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='unsupported-uninstall'; label='Uninstall Matched (unsupported)'; kind='stream-table'; destructive=$true
                description='Uninstall the checked unsupported/SEoL products with their native uninstaller (NOT MECM), grouped per host. Driven by the "Uninstall Matched" button on the Unsupported Software Scan grid, which fills the host/app pairs below; Review/Update rows are skipped. One result row per host x product.'
                columns=@('Host','App','Install Type','Result','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='pairs'; label='Host + TAB + AppName pairs (one per line; filled by the scan grid)'; type='textarea'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='kb-scan'; label='KB Scan'; kind='stream-table'; destructive=$false
                description='Parallel Get-HotFix scan. Blank Target KB = list all hotfixes; set a KB to get a per-host Present/Missing verdict + fleet compliance %.'
                columns=@('Host','HotFixID','Description','InstalledOn','InstalledBy')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='kb'; label='Target KB (optional, e.g. KB5062552 - blank lists all hotfixes)'; type='text'; required=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='kb-trigger-mecm'; label='Trigger MECM Cycles'; kind='stream-table'; destructive=$false
                description='Trigger SW Updates Scan / Deploy / MachinePolicy MECM discovery cycles.'
                columns=@('Host','Status')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='kb-push-download'; label='KB Push & Download'; kind='stream-table'; destructive=$false
                description='Per host: query pending MECM updates (CCM_SoftwareUpdate ComplianceState=0); if any exist, trigger the download (schedule 108) + SW update deployment (114) cycles to push them to DOWNLOAD state.'
                columns=@('Host','PendingCount','Status')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='kb-install'; label='Install KBs'; kind='stream-table'; destructive=$true
                confirm='Push the listed KB(s) to the target workstation(s)? MECM is tried first; the optional .msu is the fallback. Proceed?'
                description='Install specific KBs: MECM first (match each KB in CCM_SoftwareUpdate by ArticleID/Name, then CCM_SoftwareUpdatesManager.InstallUpdates); for any KB not deployed in MECM, fall back to an uploaded .msu copied to each host and run via wusa. The one .msu serves as the fallback for the listed KB(s).'
                columns=@('Host','MECMFound','MECMInstalled','MSUInstalled','Skipped','Result','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='kbs'; label='Target KBs (comma/space separated, e.g. KB5060999 KB5062552)'; type='text'; required=$true },
                    @{ name='msu'; label='MSU fallback file (optional)'; type='file'; filter='Windows Update (*.msu)|*.msu|All files (*.*)|*.*'; required=$false },
                    @{ name='noreboot'; label='Suppress auto-reboot after install'; type='bool'; required=$false; default=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='verify-patch'; label='Verify Patch'; kind='stream-table'; destructive=$false
                description='Read-only post-patch verification (SCCM/MECM only): poll CCM_SoftwareUpdate (root\ccm\ClientSDK) on each host, map EvaluationState to text, and report whether each update reached InstallComplete. Optionally filter to specific KBs/update names. No-ops gracefully on hosts without an SCCM client.'
                columns=@('Host','Update','State','Status')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='kbFilter'; label='KB / update filter (comma-separated substrings; blank = all)'; type='text'; required=$false },
                    @{ name='maxPolls'; label='Max polls per host'; type='int'; required=$false; default=6 },
                    @{ name='intervalSeconds'; label='Seconds between polls'; type='int'; required=$false; default=30 },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='remote-message'; label='Remote Message'; kind='stream-table'; destructive=$true
                confirm='Send this popup message to the logged-on user on the selected target(s)?'
                description='Deliver a titled popup to the logged-on user on each target via scheduled-task/VBS.'
                columns=@('Host','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='title'; label='Title'; type='text'; required=$true; default='A message from the 48th Communications Squadron' },
                    @{ name='body'; label='Message'; type='textarea'; required=$true },
                    @{ name='timeout'; label='Dismiss after (sec, 0=never)'; type='int'; required=$false; default=300 },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='cleanup-disk'; label='Disk Cleanup'; kind='stream-table'; destructive=$true
                confirm='Run Disk Cleanup on the selected target(s)? With "Dry run" UNCHECKED this PERMANENTLY deletes temp files, the MECM cache (ccmcache), and/or stale user profiles and cannot be undone. Proceed?'
                description='Temp-file cleanup, MECM cache (ccmcache) purge, and/or stale user-profile removal (by age). Dry-run supported. CcmCache reports the cache size found (MB); a live run best-effort deletes it.'
                columns=@('Host','TempMB','TempFiles','CacheMB','ProfilesFound','ProfilesRemoved','Skipped','FreedMB','FreeAfterGB','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='operation'; label='Operation'; type='select'; required=$true; default='TempFiles'; options=@('TempFiles','OldProfiles','CcmCache','Both') },
                    @{ name='days'; label='Profile age threshold (days)'; type='int'; required=$false; default=60 },
                    @{ name='dryrun'; label='Dry run (enumerate, do not delete)'; type='bool'; required=$false; default=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='clean-user-apps'; label='Clean User Apps'; kind='stream-table'; destructive=$true
                confirm='Remove user-installed app BINARIES (Chrome/Firefox/Zoom/Teams/Webex) from EVERY user profile on the target(s)? User data (bookmarks/history/profiles) is preserved. With "Dry run" UNCHECKED this permanently deletes the binaries and cannot be undone. Proceed?'
                description='Per-profile cleanup of user-installed app binaries: kills the app, then deletes its per-user program folder while preserving user data. Targets orphaned per-user Chrome/Firefox/Zoom/Teams/Webex (common outdated ACAS findings). Dry-run supported. Does NOT touch user data and does NOT mount NTUSER.DAT hives.'
                columns=@('Host','Removed','FreedMB','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='chrome'; label='Chrome (per-user)'; type='bool'; required=$false; default=$true },
                    @{ name='firefox'; label='Firefox (per-user)'; type='bool'; required=$false; default=$true },
                    @{ name='zoom'; label='Zoom'; type='bool'; required=$false; default=$false },
                    @{ name='teams'; label='Teams (classic)'; type='bool'; required=$false; default=$false },
                    @{ name='webex'; label='Webex'; type='bool'; required=$false; default=$false },
                    @{ name='dryrun'; label='Dry run (enumerate, do not delete)'; type='bool'; required=$false; default=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            },
            @{
                id='maintenance-lock'; label='Maintenance Lock'; kind='stream-table'; destructive=$true
                confirm='Put the selected workstation(s) into MAINTENANCE? This sets a logon banner on each host. If "Hard lock" is checked it ALSO restricts interactive logon to local Administrators (standard users cannot sign in) until you run Maintenance Unlock. Proceed?'
                description='Set a maintenance logon banner (legalnotice) on each target, and optionally HARD-LOCK interactive logon to Administrators only (secedit SeInteractiveLogonRight). The original logon right is backed up per host for a clean Unlock; local Admins are never locked out.'
                columns=@('Host','Success','Mode','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='caption'; label='Banner caption'; type='text'; required=$false; default='System Maintenance' },
                    @{ name='message'; label='Banner message'; type='textarea'; required=$false; default='This workstation is undergoing scheduled maintenance by the 48th Communications Squadron. Please do not log in until maintenance is complete.' },
                    @{ name='hardlock'; label='Hard lock (block standard-user logon)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='maintenance-unlock'; label='Maintenance Unlock'; kind='stream-table'; destructive=$true
                confirm='Take the selected workstation(s) OUT of maintenance? Clears the logon banner and restores normal interactive logon (from the per-host backup). Proceed?'
                description='Clear the maintenance logon banner and restore interactive logon rights from the per-host backup taken at lock time (falls back to the Windows default of Administrators + Users + Backup Operators if no backup is found). Safe to run on hosts that were only banner-locked.'
                columns=@('Host','Success','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='registry-key-scan'; label='Registry Key Scan'; kind='stream-table'; destructive=$false
                description='Scan a STIG/CVE fix from the built-in catalog: read current values, compare against expected.'
                columns=@('Host','RegPath','CurrentValue','ExpectedValue','Compliant','Status')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='cvekey'; label='Fix'; type='select'; required=$true; default='BHI'; options=@('BHI','Edge_ImportSearchEngine') },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=24 }
                )
            },
            @{
                id='registry-key-apply'; label='Registry Key Apply'; kind='stream-table'; destructive=$true
                confirm='Apply the selected STIG/CVE fix to the target(s)? If "Notify user + reboot 1 hour after a successful apply" is checked, every successfully-patched host will be FORCE-rebooted (shutdown /r /f) ~1 hour later. Proceed?'
                description='Apply a STIG/CVE fix from the built-in catalog: write values, read back, report compliance. Optionally notify the logged-on user and schedule a reboot 1 hour after a successful apply.'
                columns=@('Host','RegPath','NewValue','Reboot','Status')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='cvekey'; label='Fix'; type='select'; required=$true; default='BHI'; options=@('BHI','Edge_ImportSearchEngine') },
                    @{ name='rebootafter'; label='Notify user + reboot 1 hour after a successful apply'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='app-update-verify'; label='App Update Verify'; kind='stream-table'; destructive=$false
                description='Verify the installed version/last-updated of an app-update profile (read-only).'
                columns=@('Host','Version','LastUpdated','Verified','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='profile'; label='Profile'; type='select'; required=$true; default='Microsoft 365 - Force Update'; options=@('Microsoft 365 - Force Update','Windows Defender - Update Definitions','Trellix / McAfee - Update Definitions','Google Chrome - Update','Microsoft Edge - Update','Microsoft 365 - Update (User Visible)','Oracle Java - Software Center','Windows Unquoted Service Path - Remediate','MSXML 4.0 - Uninstall','Apache Log4j - Replace Vulnerable Jars','Office VBA Project Access - Disable (AccessVBOM)') },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='app-update-apply'; label='App Update Apply'; kind='stream-table'; destructive=$true
                description='Run an app-update profile (or custom command) remotely on each target.'
                columns=@('Host','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='profile'; label='Profile'; type='select'; required=$true; default='Microsoft 365 - Force Update'; options=@('Microsoft 365 - Force Update','Windows Defender - Update Definitions','Trellix / McAfee - Update Definitions','Google Chrome - Update','Microsoft Edge - Update','Microsoft 365 - Update (User Visible)','Oracle Java - Software Center','Windows Unquoted Service Path - Remediate','MSXML 4.0 - Uninstall','Apache Log4j - Replace Vulnerable Jars','Office VBA Project Access - Disable (AccessVBOM)','Custom Command') },
                    @{ name='customcommand'; label='Custom command (only for Custom Command)'; type='textarea'; required=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='log4j-scanner'; label='Log4j Scanner'; kind='stream-table'; destructive=$false
                description='Search Program Files / ProgramData / Users / Java roots for log4j-*.jar; classify versions.'
                columns=@('Host','JARPath','Filename','VulnerableVersion')
                inputs=@(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            }
        )
    }
}

# -----------------------------------------------------------------------------
#  Helpers
# -----------------------------------------------------------------------------

function ConvertTo-JanetHostList {
    # Split a pasted blob into clean, unique, upper-cased hostnames.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim()
        # Accept only a bare host/IPv4 token; a pasted UNC fragment / URL / junk is
        # dropped here so it never reaches New-PSSession / Invoke-Command.
        if ($h -and ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
    }
    return $out.ToArray()
}

function Get-WptThreadCount {
    param([hashtable]$Params, [int]$Default)
    $threads = $Default
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    return [Math]::Max(1, [Math]::Min(64, $threads))
}

# -----------------------------------------------------------------------------
#  Fleet compliance snapshots + trending (feature #6)
#  A Bulk Scan can persist ONE CSV per run to JanetLocal\snapshots; the read-only
#  'trend' action aggregates the newest 60 into a per-snapshot compliance series
#  and flags hosts stuck with pending work across consecutive snapshots. The
#  snapshot folder ships with the take-to-work mirror (like KevCatalog / c2c-baseline).
# -----------------------------------------------------------------------------
function Get-WptSnapshotDir { Join-Path $PSScriptRoot '..\JanetLocal\snapshots' }

# Coerce a param value to bool (checkbox may cross as $true/$false or a string).
function ConvertTo-WptBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ("$Value" -match '^(?i:true|1|yes|on)$')
}

# Persist the bulk-scan result rows as one snapshot CSV. Best-effort: any failure
# only WARNS via -Send and never throws, so a save problem cannot fail the scan.
function Save-WptBulkSnapshot {
    param($Rows, [scriptblock]$Send, [string]$Stamp)
    try {
        # One Get-Date drives BOTH the filename stamp and the ScanStamp column so they
        # cannot straddle a second boundary.
        $now = Get-Date
        if ([string]::IsNullOrWhiteSpace($Stamp)) { $Stamp = $now.ToString('yyyyMMdd-HHmmss') }
        $dir = Get-WptSnapshotDir
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        $scanStamp = $now.ToString('yyyy-MM-dd HH:mm:ss')
        $objs = New-Object System.Collections.ArrayList
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            $get = { param($k) if ($r -is [hashtable]) { $r[$k] } else { $r.$k } }
            [void]$objs.Add([pscustomobject]@{
                Host               = [string](& $get 'Host')
                Online             = [bool](& $get 'Online')
                OS                 = [string](& $get 'OsName')
                Build              = [string](& $get 'OsBuild')
                MECMUpdateCount    = [string](& $get 'MECMUpdateCount')
                WindowsUpdateCount = [string](& $get 'WindowsUpdateCount')
                AppUpdateCount     = [string](& $get 'AppCount')
                RebootPending      = [string](& $get 'RebootPending')
                LastBootTime       = [string](& $get 'LastBootTime')
                ScanStamp          = $scanStamp
            })
        }
        if ($objs.Count -eq 0) {
            if ($Send) { & $Send @{ type='log'; level='warn'; text='Snapshot not saved: no scan rows to persist.' } }
            return
        }
        $csv  = @($objs | ConvertTo-Csv -NoTypeInformation)
        $path = Join-Path $dir ("wpt-bulkscan_$Stamp.csv")
        # A second-granular stamp can collide (back-to-back scans / two operator
        # sessions); disambiguate rather than silently overwriting an earlier point.
        if (Test-Path -LiteralPath $path) {
            $n = 2
            do { $path = Join-Path $dir ("wpt-bulkscan_${Stamp}_$n.csv"); $n++ } while (Test-Path -LiteralPath $path)
        }
        $enc  = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($path, (($csv -join "`r`n") + "`r`n"), $enc)
        if ($Send) { & $Send @{ type='log'; level='ok'; text="Saved fleet snapshot ($($objs.Count) host(s)) to JanetLocal\snapshots\$([System.IO.Path]::GetFileName($path)) for trending." } }
    } catch {
        if ($Send) { & $Send @{ type='log'; level='warn'; text="Snapshot NOT saved (scan unaffected): $($_.Exception.Message)" } }
    }
}

# Read the newest $Max snapshot CSVs and aggregate a per-snapshot compliance
# series (newest first) plus the per-host current streak of consecutive snapshots
# with pending work. A missing folder / corrupt file yields an empty (valid) view.
function Get-WptTrendData {
    param([int]$Max = 60)
    $dir = Get-WptSnapshotDir
    $result = @{ Snapshots = @(); Stuck = @(); Dir = $dir; Found = 0 }
    if (-not (Test-Path -LiteralPath $dir)) { return $result }
    # Filename stamp is yyyyMMdd-HHmmss so a lexical descending sort = newest first.
    $files = @(Get-ChildItem -LiteralPath $dir -Filter 'wpt-bulkscan_*.csv' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    $result.Found = $files.Count
    if ($Max -gt 0 -and $files.Count -gt $Max) { $files = @($files[0..($Max - 1)]) }
    $snaps = New-Object System.Collections.ArrayList
    foreach ($f in $files) {
        $rows = $null
        try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
        $total = 0; $online = 0; $pending = 0; $reboot = 0; $pendUpd = 0; $errors = 0; $stamp = ''
        $pendSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $rows) {
            $total++
            if ([string]::IsNullOrWhiteSpace($stamp)) { $stamp = [string]$r.ScanStamp }
            $isOnline = (([string]$r.Online) -match '^(?i:true|1|yes)$')
            if ($isOnline) { $online++ }
            $m = 0; $mOk = [int]::TryParse([string]$r.MECMUpdateCount,    [ref]$m)
            $w = 0; $wOk = [int]::TryParse([string]$r.WindowsUpdateCount, [ref]$w)
            $a = 0; $aOk = [int]::TryParse([string]$r.AppUpdateCount,     [ref]$a)
            $sum = $m + $w + $a
            $pendUpd += $sum
            $hn = ([string]$r.Host).Trim()
            # An ONLINE host whose channel value did not parse (the literal 'Error' the
            # scan grid writes on a failed query) is UNKNOWN, not compliant: count it as
            # an error and keep it PENDING so a broken-WMI/CCM blip does not silently fold
            # the host into the compliant side or reset its stuck-host streak.
            $hasErr = ($isOnline -and -not ($mOk -and $wOk -and $aOk))
            if ($hasErr) { $errors++ }
            if ($hn -and ($sum -gt 0 -or $hasErr)) { $pending++; [void]$pendSet.Add($hn) }
            if (([string]$r.RebootPending) -match '^(?i:true|1|yes)$') { $reboot++ }
        }
        if ([string]::IsNullOrWhiteSpace($stamp)) { $stamp = ($f.BaseName -replace '^wpt-bulkscan_', '') }
        [void]$snaps.Add(@{ Stamp = $stamp; File = $f.Name; Total = $total; Online = $online; HostsPending = $pending; RebootPending = $reboot; PendingUpdates = $pendUpd; Errors = $errors; PendSet = $pendSet })
    }
    $result.Snapshots = @($snaps)   # already newest-first
    # Per-host streak: walk newest -> older, count consecutive snapshots the host is
    # pending in; a snapshot where it is absent (or not pending) breaks the streak.
    $everPending = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $snaps) { foreach ($h in $s.PendSet) { [void]$everPending.Add($h) } }
    $stuck = New-Object System.Collections.ArrayList
    foreach ($h in $everPending) {
        $streak = 0
        foreach ($s in $snaps) { if ($s.PendSet.Contains($h)) { $streak++ } else { break } }
        if ($streak -ge 3) { [void]$stuck.Add(@{ Host = $h; Streak = $streak }) }
    }
    $result.Stuck = @($stuck | Sort-Object @{ Expression = { [int]$_['Streak'] }; Descending = $true }, @{ Expression = { [string]$_['Host'] } })
    return $result
}

# Unsupported / SEoL product catalog, ported from the desktop UnsupportedProductRemediator
# (X:\J.A.N.E.T\JanetLocal\UnsupportedProductCatalog.json -- THE SOURCE OF TRUTH; when that
# JSON changes (new SEoL products) re-sync this list + note it in docs\HANDOFF.md). Each
# profile maps an unsupported/SEoL product family to a registry DisplayName regex (broadened
# here vs the desktop's ACAS-plugin-name regexes, since we match the live registry
# DisplayName) + an optional VersionMaxExclusive cutoff + the remediation Action:
#   Uninstall - intent: remove with the native uninstaller (reuses WptSoftwareUninstallBlock)
#   Update    - flip to current instead of removing (e.g. M365 force-update)
#   Review    - needs human sign-off (DBA approval / manual jar removal) - NOT auto-removed
# SAFETY (see Get-WptUnsupportedAction): an 'Uninstall' profile is only AUTO-uninstallable
# when the match PROVES the install is unsupported -- a VersionMaxExclusive the install is
# below, OR Proven=$true (the regex itself pins an EOL-by-definition / old-version product,
# e.g. Flash, perpetual Office years). A bare family-name match (.NET, Firefox, Java with no
# version proof) is DOWNGRADED to Review at scan time so a supported in-market build is never
# auto-removed without human sign-off (the desktop relies on the ACAS plugin that flagged the
# host for this; the live scan has no such per-host signal yet -> ACAS-CSV gate is a TODO).
# Embedded (not file-loaded) so JANET Web stays self-contained for the take-to-work mirror.
function Get-WptUnsupportedCatalog {
    @(
        @{ Label='MSXML 3/4 (XML Core Services)';      DisplayNameRegex='^(Microsoft (XML Parser|Core Services|XML 4)|MSXML )'; VersionMaxExclusive='5.0'; Category='UnsupportedSoftware'; Action='Uninstall'; Proven=$false; Notes='MSXML 3/4 EOL (version-gated < 5.0; MSXML 6 left alone) - uninstall, no successor on the AFNET image.' }
        @{ Label='Microsoft 365 (unsupported channel)';DisplayNameRegex='^Microsoft 365 Apps';                          VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Update';    Proven=$false; Notes='Channel mismatch - M365 force-update flips to a supported channel.' }
        @{ Label='Microsoft Office (perpetual, unsupported)'; DisplayNameRegex='^Microsoft Office (2003|2007|2010|2013|2016)'; VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Uninstall'; Proven=$true; Notes='Pre-M365 perpetual Office (regex pins the EOL year) - uninstall, then deploy M365 separately.' }
        @{ Label='Microsoft SQL Server (unsupported)'; DisplayNameRegex='^Microsoft SQL Server (2005|2008|2012|2014)';   VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Review';    Proven=$false; Notes='DBA approval required before uninstall - flagged for review.' }
        @{ Label='Mozilla (unsupported)';              DisplayNameRegex='^Mozilla (Firefox|Thunderbird|SeaMonkey)';      VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Uninstall'; Proven=$false; Notes='Mozilla family - name-only match has supported in-market builds; surfaced as Review pending ACAS confirmation.' }
        @{ Label='Oracle Database (unsupported)';      DisplayNameRegex='^Oracle Database';                              VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Review';    Proven=$false; Notes='DBA approval required before uninstall - flagged for review.' }
        @{ Label='.NET Core / Runtime (SEoL)';         DisplayNameRegex='^Microsoft \.NET (Core|Runtime)';               VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Uninstall'; Proven=$false; Notes='.NET runtime family - supported .NET 8/9 also match; surfaced as Review pending ACAS confirmation.' }
        @{ Label='.NET Core SDK (SEoL)';               DisplayNameRegex='^Microsoft \.NET (Core SDK|SDK)';               VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Uninstall'; Proven=$false; Notes='.NET SDK family - supported SDKs also match; surfaced as Review pending ACAS confirmation.' }
        @{ Label='ASP.NET Core (SEoL)';                DisplayNameRegex='^Microsoft ASP\.NET Core';                      VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Uninstall'; Proven=$false; Notes='ASP.NET Core family - supported 8.x also match; surfaced as Review pending ACAS confirmation.' }
        @{ Label='Mozilla Firefox (SEoL)';             DisplayNameRegex='^Mozilla Firefox';                              VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Uninstall'; Proven=$false; Notes='Firefox family - current Firefox also matches; surfaced as Review pending ACAS confirmation (AFNET image installs ESR separately).' }
        @{ Label='Apache Log4j 1.x (SEoL)';            DisplayNameRegex='log4j-1\.';                                     VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Review';    Proven=$false; Notes='Log4j 1.x - usually a JAR on disk, not an MSI. Surface for manual jar removal (Log4j Finder).' }
        @{ Label='Adobe Flash / Shockwave (SEoL)';     DisplayNameRegex='^Adobe (Flash|Shockwave) Player';               VersionMaxExclusive=$null; Category='SEoLSoftware';        Action='Uninstall'; Proven=$true; Notes='Flash/Shockwave EOL by definition (no supported version) - always uninstall.' }
        @{ Label='Java SE / JRE / JDK (unsupported)';  DisplayNameRegex='^(Java|JRE|JDK)[ (]';                           VersionMaxExclusive=$null; Category='UnsupportedSoftware'; Action='Uninstall'; Proven=$false; Notes='Java family (matches "Java 8...", "Java(TM)...") - supported builds also match; surfaced as Review pending ACAS confirmation.' }
    )
}

# Private helper: parse both version strings and compare. Returns $true if $Ver is
# provably below $Max, $false if at-or-above, $null if either string won't parse.
# Callers decide how to treat the unparseable case ($null is falsy in PS conditionals).
function Test-WptVersionBelow {
    param([string]$Ver, [string]$Max)
    $vObj = $null; $maxObj = $null
    $clean = ($Ver -replace '[^0-9\.]', '').Trim('.')
    if (-not ([version]::TryParse($clean, [ref]$vObj) -and [version]::TryParse($Max, [ref]$maxObj))) { return $null }
    return ($vObj -lt $maxObj)
}

# Does an installed app match an unsupported-catalog profile? Name must match the
# DisplayName regex; if the profile sets a VersionMaxExclusive, the install counts as
# unsupported only when its version is BELOW that cutoff (so e.g. MSXML 6 is left alone
# while MSXML 4 is flagged). A version that won't parse is included (can't prove it's
# supported) so it still surfaces (Get-WptUnsupportedAction then tags it Review).
function Test-WptUnsupportedMatch {
    param([string]$AppName, [string]$AppVersion, $Prof)
    if ([string]::IsNullOrWhiteSpace($AppName)) { return $false }
    if ($AppName -notmatch $Prof.DisplayNameRegex) { return $false }
    $vmax = [string]$Prof.VersionMaxExclusive
    if ([string]::IsNullOrWhiteSpace($vmax)) { return $true }
    $cmp = Test-WptVersionBelow $AppVersion $vmax
    return ($null -eq $cmp -or $cmp)   # parse-unprovable -> include; below -> include; at/above -> exclude
}

# The SAFE effective remediation action for a matched profile + installed version.
# 'Update'/'Review' pass through unchanged (they never auto-remove). An 'Uninstall' profile
# only stays 'Uninstall' when the match PROVES the install is unsupported: Proven=$true (the
# regex pins an EOL/old-version product) OR a VersionMaxExclusive the install is provably
# below. Otherwise (a bare family-name match, or an unparseable version on a gated profile)
# it is DOWNGRADED to 'Review' so a supported in-market build (.NET 8, current Firefox, ...)
# is never one-click auto-uninstalled without human sign-off. (When the ACAS-CSV per-host
# gate is added, a confirmed finding can promote a Review match back to Uninstall.)
function Get-WptUnsupportedAction {
    param($Prof, [string]$AppVersion)
    $act = [string]$Prof.Action
    if ($act -ne 'Uninstall') { return $act }
    if ($Prof.Proven) { return 'Uninstall' }
    $vmax = [string]$Prof.VersionMaxExclusive
    if (-not [string]::IsNullOrWhiteSpace($vmax)) {
        if (Test-WptVersionBelow $AppVersion $vmax) { return 'Uninstall' }
    }
    return 'Review'
}

# The fixed registry-fix catalog, lifted from $global:RegKeyFixCatalog
# (WorkstationPatchingTool_6.5.22.ps1:8327). Each entry is flattened into a
# plain array of value-definition hashtables so the scriptblocks can iterate.
function Get-WptRegKeyCatalog {
    [ordered]@{
        'BHI' = @{
            DisplayName = 'BHI Remediation (CVE-2022-0001)'
            RegPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Defs        = @(
                @{ Name='FeatureSettingsOverride';     OrBits=0x00800000; Expected=$null; Type='DWord' },
                @{ Name='FeatureSettingsOverrideMask'; OrBits=$null;      Expected=3;     Type='DWord' }
            )
        }
        'Edge_ImportSearchEngine' = @{
            DisplayName = 'Edge: Disable Importing Search Engine Settings (STIG EDGE-00-000022)'
            RegPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            Defs        = @(
                @{ Name='ImportSearchEngine'; OrBits=$null; Expected=0; Type='DWord' }
            )
        }
    }
}

# Shared Verify scriptblock for both M365 C2R profiles (Force Update and User Visible).
# Reads the same ClickToRun registry key; no variables differ between the two profiles.
# Self-contained: runs remotely via Invoke-Command with no closed-over controller vars.
$script:M365C2RVerify = {
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

# Factory: stamps out a self-contained remote Verify scriptblock for browser updater
# clients (Chrome / Edge) with the two registry paths baked as string literals.
# Both profiles share identical logic; only the WoW64 and native path differ.
function New-WptUpdateClientVerify {
    param([string]$P1, [string]$P2)
    $body = @'
$ver = 'not installed'; $mod = $null
foreach ($p in @('__P1__','__P2__')) {
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
'@
    [scriptblock]::Create($body.Replace('__P1__', $P1).Replace('__P2__', $P2))
}

# The app-update profile registry, lifted from $global:AppUpdateProfiles
# (WorkstationPatchingTool_6.5.22.ps1:9685). Each profile carries a remote
# Script (apply) and Verify scriptblock that run inside Invoke-Command on the
# target. All 10 desktop profiles are present; unknown profile names fall
# through to a clear "unknown profile" result.
function Get-WptAppUpdateProfiles {
    @{
        'Microsoft 365 - Force Update' = @{
            Script = {
                $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
                if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
                $proc = Start-Process -FilePath $c2r -ArgumentList '/update user','/displaylevel=false','/forceappshutdown=true' -Wait -PassThru -NoNewWindow
                return "OK (Office update triggered, exit $($proc.ExitCode))"
            }
            Verify = $script:M365C2RVerify
        }
        'Windows Defender - Update Definitions' = @{
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
        'Trellix / McAfee - Update Definitions' = @{
            # Force a Trellix/McAfee endpoint security update: ePO agent sync (cmdagent)
            # + AMCore/DAT content update (amcfg). Mirrors the desktop PIRS "Trellix
            # Update". Runs ON the host inside Invoke-Command, so local exe paths apply.
            Script = {
                $msgs = New-Object System.Collections.Generic.List[string]
                $cmd = $null
                foreach ($p in @(
                    'C:\Program Files\McAfee\Agent\cmdagent.exe',
                    'C:\Program Files\Trellix\Agent\cmdagent.exe',
                    'C:\Program Files (x86)\McAfee\Common Framework\cmdagent.exe')) {
                    if (Test-Path $p) { $cmd = $p; break }
                }
                if ($cmd) {
                    # /p collect+send props, /e enforce policies, /c check-in for new policies (ePO sync)
                    try { & $cmd /p /e /c 2>&1 | Out-Null; [void]$msgs.Add('ePO sync sent (cmdagent /p /e /c)') }
                    catch { [void]$msgs.Add("cmdagent error: $($_.Exception.Message)") }
                } else { [void]$msgs.Add('cmdagent.exe not found (McAfee/Trellix Agent)') }
                $amcfg = @(
                    'C:\Program Files\McAfee\Endpoint Security\Threat Prevention\amcfg.exe',
                    'C:\Program Files (x86)\McAfee\Endpoint Security\Threat Prevention\amcfg.exe',
                    'C:\Program Files\Trellix\Endpoint Security\Threat Prevention\amcfg.exe') |
                    Where-Object { Test-Path $_ } | Select-Object -First 1
                if ($amcfg) {
                    try { & $amcfg /update 2>&1 | Out-Null; [void]$msgs.Add('DAT/AMCore update triggered (amcfg /update)') }
                    catch { [void]$msgs.Add("amcfg error: $($_.Exception.Message)") }
                } else { [void]$msgs.Add('amcfg.exe not found (Endpoint Security may not be installed)') }
                if (($msgs -join ' ') -match 'sent|triggered') { return "OK ($($msgs -join '; '))" }
                return "FAIL: $($msgs -join '; ')"
            }
            Verify = {
                # Best-effort, read-only: report the installed AMCore/DAT content version +
                # date from the Trellix/McAfee registry; never throws (returns 'unknown' if
                # the layout differs). Verified = content less than 7 days old.
                $ver = 'not installed'; $when = 'n/a'; $src = ''
                $keys = @(
                    'HKLM:\SOFTWARE\McAfee\AVSolution\DS\DS',
                    'HKLM:\SOFTWARE\Wow6432Node\McAfee\AVSolution\DS\DS',
                    'HKLM:\SOFTWARE\McAfee\AVSolution\DS',
                    'HKLM:\SOFTWARE\Wow6432Node\McAfee\AVSolution\DS'
                )
                foreach ($k in $keys) {
                    if (Test-Path $k) {
                        $pp = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                        if ($pp) {
                            if ($pp.szContentCreationDate) { $when = [string]$pp.szContentCreationDate }
                            if ($null -ne $pp.dwContentMajorVersion) { $ver = "$($pp.dwContentMajorVersion).$($pp.dwContentMinorVersion)" }
                            $src = $k; break
                        }
                    }
                }
                if (-not $src) {
                    $svc = Get-Service -Name 'masvc','macmnsvc','mfemms','McAfeeFramework' -ErrorAction SilentlyContinue
                    if ($svc) { $ver = 'installed (DAT version unreadable)'; $src = 'service' }
                }
                $verified = $null
                if ($when -ne 'n/a') {
                    $dt = New-Object DateTime
                    if ([datetime]::TryParse($when, [ref]$dt)) { $verified = ((Get-Date) - $dt).TotalDays -lt 7 }
                }
                return @{ Version=$ver; LastUpdated=$when; Verified=$verified; Detail=$(if ($src) { "src: $src" } else { 'Trellix/McAfee not detected' }) }
            }
        }
        'Google Chrome - Update' = @{
            Script = {
                $exe = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'
                if (-not (Test-Path $exe)) { $exe = 'C:\Program Files\Google\Update\GoogleUpdate.exe' }
                if (-not (Test-Path $exe)) { return 'FAIL: GoogleUpdate.exe not found' }
                $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
                return "OK (Chrome update triggered, exit $($proc.ExitCode))"
            }
            Verify = New-WptUpdateClientVerify `
                'HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463c-AFF1-A69D9E530F96}' `
                'HKLM:\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463c-AFF1-A69D9E530F96}'
        }
        'Microsoft Edge - Update' = @{
            Script = {
                $exe = 'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
                if (-not (Test-Path $exe)) { return 'FAIL: MicrosoftEdgeUpdate.exe not found' }
                $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
                return "OK (Edge update triggered, exit $($proc.ExitCode))"
            }
            Verify = New-WptUpdateClientVerify `
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' `
                'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
        }
        'Microsoft 365 - Update (User Visible)' = @{
            Script = {
                $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
                if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
                $proc = Start-Process -FilePath $c2r -ArgumentList '/update user' -Wait -PassThru -NoNewWindow
                return "OK (Office update triggered, exit $($proc.ExitCode))"
            }
            Verify = $script:M365C2RVerify
        }
        'Oracle Java - Software Center' = @{
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
        'Windows Unquoted Service Path - Remediate' = @{
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
                $exeRe = [regex]'(?i)^(.+?\.exe)(\s.*)?$'

                foreach ($svc in Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue) {
                    $svcName = $svc.PSChildName
                    $img = $null
                    try { $img = (Get-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath -EA Stop).ImagePath }
                    catch { continue }
                    if ([string]::IsNullOrWhiteSpace($img)) { continue }

                    $trim = $img.TrimStart()
                    if ($trim.StartsWith('"')) { $skipped++; continue }

                    $m = $exeRe.Match($trim)
                    if (-not $m.Success) { $skipped++; continue }
                    $exePart  = $m.Groups[1].Value
                    $argsPart = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { '' }
                    if ($exePart -notmatch ' ') { $skipped++; continue }

                    $newImg = '"' + $exePart + '"' + $argsPart
                    if ($newImg -eq $img) { $skipped++; continue }

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
        'Apache Log4j - Replace Vulnerable Jars' = @{
            # Requires controller-side staged jars; the JANET Web web host has no
            # staging substitution, so auto-patch treats this as a coverage gap
            # (NeedsStaging). Carried for manifest completeness / manual single runs.
            NeedsStaging = $true
            Script = {
                $sourceShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles'
                $newApi      = 'log4j-api-2.25.4.jar'
                $newCore     = 'log4j-core-2.25.4.jar'
                $targets     = @(
                    @{ Path='C:\Program Files\HID Global\Credential Management Client\lib'; Service='HIDCredentialManagementClient' }
                    @{ Path='C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'; Service='AdobeExperienceManagerFormsDesigner' }
                )
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
                    try {
                        $allJars = @(Get-ChildItem -LiteralPath $libPath -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                    } catch { $allJars = @() }

                    $relevant = @($allJars | Where-Object {
                        $_.Name -match '^log4j-(api|core)-' -and $_.Name -like '*.jar'
                    })
                    if ($relevant.Count -eq 0) { $skippedRoots++; continue }

                    $current = @($relevant | Where-Object { $_.Name -eq $newApi -or $_.Name -eq $newCore })
                    $stale   = @($relevant | Where-Object { $_.Name -ne $newApi -and $_.Name -ne $newCore })
                    $skippedCurrent += $current.Count

                    $archiveStale = @($stale | Where-Object { $_.FullName -like '*\Backup_*\*' })
                    $liveStale    = @($stale | Where-Object { $_.FullName -notlike '*\Backup_*\*' })

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
                    $jars = @(Get-ChildItem -LiteralPath $p -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                    foreach ($j in $jars) {
                        $found.Add("$($j.Name)") | Out-Null
                        if ($j.Name -notmatch '^log4j-(api|core)-2\.25\.4\.jar$') {
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

        # ---------------------------------------------------------------------
        # BETA profiles - EXPERIMENTAL, AFNET-unproven. Surfaced ONLY in the WPT
        # "Beta" tab, never in the proven App Updater dropdown. All use local
        # mechanisms (registry / Windows Firewall / the app's own updater); no
        # internet, no new software. Efficacy is the operator's AFNET validation.
        # ---------------------------------------------------------------------
        '[BETA] Adobe Acrobat/Reader - Update' = @{
            Script = {
                param($Method, $Arg)
                if ("$Method" -eq 'sc') {
                    try {
                        $appName = "$Arg".Trim()
                        if ($appName) {
                            $app = @(Get-CimInstance -Namespace 'ROOT\ccm\ClientSDK' -ClassName CCM_Application -ErrorAction Stop | Where-Object { $_.Name -like ('*' + $appName + '*') }) | Select-Object -First 1
                            if (-not $app) { return ("SKIP: no Software Center application matching '" + $appName + "'") }
                            Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName CCM_Application -MethodName Install -Arguments @{ Id=[string]$app.Id; Revision=[string]$app.Revision; IsMachineTarget=[bool]$app.IsMachineTarget; EnforcePreference=[uint32]0; Priority='High'; IsRebootIfNeeded=$false } -ErrorAction Stop | Out-Null
                            return ("OK (Software Center install triggered for '" + $app.Name + "')")
                        }
                        $cycles = @('{00000000-0000-0000-0000-000000000121}','{00000000-0000-0000-0000-000000000108}','{00000000-0000-0000-0000-000000000113}','{00000000-0000-0000-0000-000000000114}')
                        $ok = 0
                        foreach ($c in $cycles) { try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID = $c } -ErrorAction Stop | Out-Null; $ok++ } catch {} }
                        if ($ok -gt 0) { return ("OK (MECM triggered " + $ok + " cycle(s): app-deployment + software-update scan/deploy; deployed Adobe updates install on next cycle)") }
                        return 'FAIL: could not trigger MECM cycles (is the ConfigMgr client present?)'
                    } catch { return ('FAIL: ' + $_.Exception.Message) }
                }
                $did = @()
                try {
                    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like '*Adobe*Update*' } | ForEach-Object {
                        try { Start-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop; $did += ('task:' + $_.TaskName.Trim()) } catch {}
                    }
                } catch {}
                if ($did.Count -eq 0) {
                    $arms = @()
                    if ($env:CommonProgramFiles) { $arms += (Join-Path $env:CommonProgramFiles 'Adobe\ARM\1.0\AdobeARM.exe') }
                    $cpfx = (Get-Item 'Env:CommonProgramFiles(x86)' -ErrorAction SilentlyContinue).Value
                    if ($cpfx) { $arms += (Join-Path $cpfx 'Adobe\ARM\1.0\AdobeARM.exe') }
                    foreach ($arm in $arms) {
                        if (Test-Path $arm) { try { Start-Process -FilePath $arm -ArgumentList '/PRODUCT:Acrobat','/MODE:3' -WindowStyle Hidden -ErrorAction Stop; $did += 'AdobeARM'; break } catch {} }
                    }
                }
                if ($did.Count -gt 0) { return ('OK (Adobe direct update triggered: ' + ($did -join ', ') + '; applies on next check if a source is reachable)') }
                return 'SKIP: no Adobe updater found (no Adobe*Update task, no AdobeARM.exe)'
            }
            Verify = {
                $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                $a = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Adobe Acrobat|Adobe.*Reader|Acrobat Reader' } | Sort-Object DisplayVersion -Descending | Select-Object -First 1
                if ($a) { return @{ Version = "$($a.DisplayVersion)"; LastUpdated = 'n/a'; Verified = $null; Detail = "$($a.DisplayName) - informational only (no compliance target; compare version to your patch baseline)" } }
                return @{ Version = 'not installed'; LastUpdated = 'n/a'; Verified = $null; Detail = 'no Adobe Acrobat/Reader found' }
            }
        }
        '[BETA] SMB Signing - Require' = @{
            Script = {
                try {
                    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
                    $wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                    Set-ItemProperty -Path $srv -Name RequireSecuritySignature -Value 1 -Type DWord -ErrorAction Stop
                    Set-ItemProperty -Path $srv -Name EnableSecuritySignature  -Value 1 -Type DWord -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $wks -Name RequireSecuritySignature -Value 1 -Type DWord -ErrorAction Stop
                    Set-ItemProperty -Path $wks -Name EnableSecuritySignature  -Value 1 -Type DWord -ErrorAction SilentlyContinue
                    return 'OK (SMB signing required on server + workstation; effective after service restart/reboot)'
                } catch { return ('FAIL: ' + $_.Exception.Message) }
            }
            Verify = {
                $s = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature
                $w = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature
                return @{ Version = "server=$s workstation=$w"; LastUpdated = 'n/a'; Verified = ([int]$s -eq 1 -and [int]$w -eq 1); Detail = 'RequireSecuritySignature' }
            }
        }
        '[BETA] RDP - Require NLA' = @{
            Script = {
                try {
                    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                    if (-not (Test-Path $p)) { return 'SKIP: RDP-Tcp station not present' }
                    Set-ItemProperty -Path $p -Name UserAuthentication -Value 1 -Type DWord -ErrorAction Stop
                    return 'OK (RDP NLA required; UserAuthentication=1)'
                } catch { return ('FAIL: ' + $_.Exception.Message) }
            }
            Verify = {
                $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
                return @{ Version = "UserAuthentication=$v"; LastUpdated = 'n/a'; Verified = ([int]$v -eq 1); Detail = '' }
            }
        }
        '[BETA] ICMP Timestamp - Block (firewall)' = @{
            Script = {
                try {
                    $name = 'JANET-Block-ICMP-Timestamp'
                    Get-NetFirewallRule -DisplayName "$name*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                    New-NetFirewallRule -DisplayName $name       -Direction Inbound  -Protocol ICMPv4 -IcmpType 13 -Action Block -ErrorAction Stop | Out-Null
                    New-NetFirewallRule -DisplayName "$name-Out" -Direction Outbound -Protocol ICMPv4 -IcmpType 13 -Action Block -ErrorAction Stop | Out-Null
                    return 'OK (ICMP timestamp type 13 blocked inbound + outbound)'
                } catch { return ('FAIL: ' + $_.Exception.Message) }
            }
            Verify = {
                $r = @(Get-NetFirewallRule -DisplayName 'JANET-Block-ICMP-Timestamp*' -ErrorAction SilentlyContinue)
                return @{ Version = $(if ($r.Count -gt 0) { "$($r.Count) rule(s) present" } else { 'absent' }); LastUpdated = 'n/a'; Verified = ($r.Count -ge 1); Detail = '' }
            }
        }
    }
}

# -----------------------------------------------------------------------------
#  Per-host worker scriptblocks (lifted from the original $global:* blocks)
#  Each takes ($Computer, $Cred, $Auth, ...) and returns a flat result hashtable.
#  When no credential is supplied, the harness passes $null for $Cred and the
#  string 'Default' for $Auth; the blocks splat -Credential/-Authentication
#  conditionally so the caller's Kerberos identity is used.
# -----------------------------------------------------------------------------

# --- Bulk Scan (ScanBlock:5144) ---
$script:WptScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    # Per-channel OK flags (desktop 5146-5149): a channel query that fails must
    # be distinguishable from a genuine zero, or broken hosts read as patched.
    $r = @{ Host=$Computer; Online=$false; DnsMismatch=$false; OsName=''; OsBuild=''; DriveOK=$false; DriveFree=0; DriveSize=0; DrivePct=0
            RebootOK=$false; RebootPending=$false; LastBoot=''; LoggedOnUser=''; UpdatesOK=$false; UpdateCount=0
            WuOK=$false; WuCount=0; AppsOK=$false; AppCount=0
            UpdateNames=@(); WuNames=@(); AppNames=@(); Error='' }
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
    if (-not $reachable) { return $r }
    $r.Online = $true
    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        # Single consolidated probe (perf): gather COMPUTERNAME (for the DNS-mismatch
        # guard), disk, reboot+logged-on user, MECM updates, Windows Update, and CCM
        # apps in ONE Invoke-Command round-trip (was six). Each channel keeps its own
        # try/catch + OK flag so a failed query stays distinguishable from a genuine
        # zero, exactly as before. Mirrors WptHealthScanBlock's single-probe pattern.
        $probe = $null
        try {
            $probe = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                $o = @{ RemoteName=$env:COMPUTERNAME; OsName=''; OsBuild=''
                        DriveOK=$false; DriveSize=0; DriveFree=0; DrivePct=0
                        RebootOK=$false; RebootPending=$false; LastBoot=''; LoggedOnUser=''
                        UpdatesOK=$false; UpdateNames=@(); WuOK=$false; WuNames=@(); AppsOK=$false; AppNames=@() }
                try {
                    # OS name + full build. Caption (not registry ProductName, which still
                    # reads "Windows 10" on Win11); build.UBR + feature version (24H2) come
                    # from the registry since Win32_OperatingSystem.Version omits the UBR.
                    $o.OsName = ([string](Get-CimInstance Win32_OperatingSystem -EA Stop).Caption) -replace '^Microsoft\s+', ''
                    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA Stop
                    $bld = [string]$cv.CurrentBuildNumber
                    $full = if ("$($cv.UBR)") { "$bld.$($cv.UBR)" } else { $bld }
                    $disp = [string]$cv.DisplayVersion; if (-not $disp) { $disp = [string]$cv.ReleaseId }
                    $o.OsBuild = if ($disp) { "$disp ($full)" } else { $full }
                } catch {}
                try {
                    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA Stop
                    $sizeGB = [Math]::Truncate($d.Size/1GB); $freeGB = [Math]::Truncate($d.FreeSpace/1GB)
                    $o.DriveSize = $sizeGB; $o.DriveFree = $freeGB
                    $o.DrivePct = if ($sizeGB -gt 0) { [Math]::Truncate($freeGB / $sizeGB * 100) } else { 0 }
                    $o.DriveOK = $true
                } catch {}
                try {
                    $os = Get-CimInstance Win32_OperatingSystem -EA Stop
                    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                    $wuau = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                    $sccm = $false
                    try {
                        $ccm = Invoke-WmiMethod -Namespace ROOT\ccm\ClientSDK -Class CCM_ClientUtilities -Name DetermineIfRebootPending -EA Stop
                        $sccm = $ccm.IsHardRebootPending -or $ccm.RebootPending
                    } catch {}
                    # Logged-on (interactive console) user; blank when nobody is signed in.
                    $usr = ''; try { $usr = [string](Get-CimInstance Win32_ComputerSystem -EA Stop).UserName } catch {}
                    $o.RebootPending = ($cbs -or $wuau -or $sccm); $o.LastBoot = $os.LastBootUpTime.ToString('g'); $o.LoggedOnUser = $usr; $o.RebootOK = $true
                } catch {}
                try {
                    $upd = @(Get-CimInstance -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace root/CCM/ClientSDK -EA Stop |
                        Where-Object { $_.InstallState -ne 'Installed' -and $_.ApplicabilityState -ne 'NotApplicable' } |
                        Select-Object -ExpandProperty Name)
                    $o.UpdateNames = @($upd); $o.UpdatesOK = $true
                } catch {}
                try {
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $searcher = $session.CreateUpdateSearcher()
                    $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
                    $titles = @()
                    foreach ($u in $found.Updates) { $titles += [string]$u.Title }
                    $o.WuNames = @($titles); $o.WuOK = $true
                } catch { $o.WuNames = @(); $o.WuOK = $false }
                try {
                    $apps = @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop |
                        Where-Object {
                            $_.InstallState -eq 'Installed' -and
                            $_.ApplicabilityState -eq 'Applicable' -and
                            $_.IsPreflightOnly -eq $false -and
                            $_.EvaluationState -ne 0 -and
                            $_.EvaluationState -ne 1 -and
                            $_.EvaluationState -ne 12
                        } | Select-Object -ExpandProperty Name)
                    $o.AppNames = @($apps); $o.AppsOK = $true
                } catch {}
                return $o
            }
        } catch { $r.Error = "Scan: $($_.Exception.Message)"; return $r }
        # DNS-mismatch guard (soft-warn): if the box that answered isn't the one we
        # dialed (stale DNS / reused IP), flag it and stop - the gathered reads would
        # describe the WRONG machine, so discard them. Session-based name compare
        # (AFNET reverse-DNS zones are unreliable, so never trust a PTR lookup here).
        $actualName = [string]$probe.RemoteName
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.DnsMismatch = $true
            $r.Error = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - skipped (would report the wrong machine)"
            return $r
        }
        $r.OsName = [string]$probe.OsName; $r.OsBuild = [string]$probe.OsBuild
        $r.DriveSize = $probe.DriveSize; $r.DriveFree = $probe.DriveFree; $r.DrivePct = $probe.DrivePct; $r.DriveOK = [bool]$probe.DriveOK
        $r.RebootPending = [bool]$probe.RebootPending; $r.LastBoot = [string]$probe.LastBoot; $r.LoggedOnUser = [string]$probe.LoggedOnUser; $r.RebootOK = [bool]$probe.RebootOK
        $r.UpdateNames = @($probe.UpdateNames); $r.UpdateCount = @($probe.UpdateNames).Count; $r.UpdatesOK = [bool]$probe.UpdatesOK
        $r.WuNames = @($probe.WuNames); $r.WuCount = @($probe.WuNames).Count; $r.WuOK = [bool]$probe.WuOK
        $r.AppNames = @($probe.AppNames); $r.AppCount = @($probe.AppNames).Count; $r.AppsOK = [bool]$probe.AppsOK
    } finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# --- Bulk Patch (PatchBlock:5270) ---
# $Mode picks the patch posture:
#   'noninvasive' (default) - trigger installs but SUPPRESS reboots (IsRebootIfNeeded
#      $false), so patching runs while people work; reboot is deferred to a window.
#   'forced'                - IsRebootIfNeeded $true: the client reboots the box when an
#      app install requires it. Customer-affecting; for quarantined/no-user hosts.
$script:WptPatchBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$Mode = 'noninvasive')
    $r = @{ Host=$Computer; Reachable=$false; UpdatesTriggered=0; AppsTriggered=0; Mode=$Mode; Error='' }
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
    $r.Reachable = $true
    $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        # DNS-mismatch guard (HARD ABORT): never trigger installs on a box that
        # isn't the one we dialed. Session-based name compare (no PTR on AFNET).
        $actualName = try { Invoke-Command -Session $sess -EA Stop -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Error = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no patch triggered"
            return $r  # the finally below removes the session
        }
        # Only count a host as triggered when the client-SDK method actually accepted
        # the request (ReturnValue 0/null). InstallUpdates / CCM_Application.Install can
        # reject WITHOUT throwing (not applicable, wrong target, agent busy); the old
        # code discarded the result and reported false success (audit#4).
        $upResult = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $updates = Get-WmiObject -Namespace "ROOT\ccm\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop
            if (-not $updates) { return @{ Count = 0; Rejected = 0 } }
            $rv = $null
            try { $rv = (Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$updates) -Namespace ROOT\ccm\ClientSDK).ReturnValue } catch { $rv = -1 }
            if ($null -ne $rv -and [int]$rv -ne 0) { return @{ Count = 0; Rejected = @($updates).Count; ReturnValue = [int]$rv } }
            return @{ Count = @($updates).Count; Rejected = 0 }
        }
        $r.UpdatesTriggered = [int]$upResult.Count
        if ($upResult.Rejected -gt 0) { $r.Error = "Update trigger rejected by client (ReturnValue=$($upResult.ReturnValue)); $($upResult.Rejected) update(s) NOT installed" }

        $appResult = Invoke-Command -Session $sess -EA Stop -ArgumentList $Mode -ScriptBlock {
            param([string]$mode)
            # Forced mode lets the client reboot the box when an app install needs it;
            # non-invasive suppresses it so work isn't interrupted (reboot deferred).
            $rebootIfNeeded = ($mode -eq 'forced')
            $count = 0; $rejected = 0
            $apps = Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop |
                Where-Object {
                    $_.InstallState -eq 'Installed' -and $_.ApplicabilityState -eq 'Applicable' -and
                    $_.IsPreflightOnly -eq $false -and $_.EvaluationState -ne 0 -and
                    $_.EvaluationState -ne 1 -and $_.EvaluationState -ne 12
                }
            foreach ($app in $apps) {
                try {
                    $param = @{
                        EnforcePreference=[UINT32]0; Id="$($app.Id)"
                        IsMachineTarget=[System.Convert]::ToBoolean($app.IsMachineTarget)
                        IsRebootIfNeeded=$rebootIfNeeded; Priority='High'; Revision="$($app.Revision)"
                    }
                    $rv = (Invoke-CimMethod -Namespace root/ccm/clientSDK -ClassName CCM_Application -MethodName Install -Arguments $param).ReturnValue
                    if ($null -eq $rv -or [int]$rv -eq 0) { $count++ } else { $rejected++ }
                } catch { $rejected++ }
            }
            return @{ Count = $count; Rejected = $rejected }
        }
        $r.AppsTriggered = [int]$appResult.Count
        if ($appResult.Rejected -gt 0) {
            $appErr = "$($appResult.Rejected) app install(s) rejected/failed at the client (not counted as triggered)"
            $r.Error = if ($r.Error) { "$($r.Error); $appErr" } else { $appErr }
        }
    } catch { $r.Error = $_.Exception.Message }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# --- Reboot (RebootBlock:5346) ---
$script:WptRebootBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    try {
        # DNS-mismatch guard (HARD ABORT on a CONFIRMED mismatch): verify the box
        # that answers is the one we dialed before rebooting (stale DNS / reused IP
        # could reboot the WRONG machine). One quick WinRM round-trip. If the verify
        # can't run (empty), proceed as before so we don't regress reboots where the
        # WMI path works but WinRM doesn't. Never trust a PTR lookup on AFNET.
        $icSplat = @{ ComputerName=$Computer; ErrorAction='Stop' }
        if ($Cred) { $icSplat['Credential']=$Cred; if ($Auth) { $icSplat['Authentication']=$Auth } }
        $actualName = try { Invoke-Command @icSplat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Detail = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no reboot sent"
            return $r
        }
        $splat = @{ ComputerName=$Computer; Force=$true; ErrorAction='Stop' }
        if ($Cred) { $splat['Credential']=$Cred }
        Restart-Computer @splat
        $r.Success = $true; $r.Detail = 'Reboot command sent'
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Scheduled reboot countdown (shutdown /r /t + optional logged-on-user popup) ---
# Lifts the proven notify + shutdown chain from registry-key-apply (desktop chkRkReboot,
# 8490-8543): pop a warning via a scheduled-task VBS popup running as the logged-on user,
# then arm shutdown /r /t. Re-arms cleanly by aborting any existing pending shutdown first.
$script:WptRebootScheduleBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [int]$DelaySeconds, [string]$Message)
    $r = @{ Host=$Computer; Success=$false; RebootAt=''; Detail='' }
    try {
        if ($DelaySeconds -lt 0) { $DelaySeconds = 0 }
        $splat = @{ ComputerName=$Computer; ErrorAction='Stop' }
        if ($Cred) { $splat['Credential']=$Cred }
        if ($Auth) { $splat['Authentication']=$Auth }
        $cmt = 'WPT: scheduled reboot. Save your work.'
        $res = Invoke-Command @splat -ArgumentList $DelaySeconds, $Message, $cmt, (($Computer -split '\.')[0]) -ScriptBlock {
            param($d, $b, $cmt, $expected)
            # DNS-mismatch guard (HARD ABORT): this block runs ON the box that answered,
            # so $env:COMPUTERNAME is the real machine. Abort before arming shutdown if
            # it isn't the host we dialed (stale DNS / reused IP).
            if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                return "DNS_MISMATCH: dialed '$expected' but this machine is '$($env:COMPUTERNAME)'"
            }
            $notifyErr = ''
            if (-not [string]::IsNullOrWhiteSpace($b)) {
                try {
                    $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
                    if (-not [string]::IsNullOrWhiteSpace($loggedIn)) {
                        New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                        $tag = [guid]::NewGuid().ToString('N'); $vbsPath = "C:\Temp\WPT_RebMsg_$tag.vbs"
                        # Harden the popup body (audit#22, same fold as WptMessageBlock): strip
                        # control chars, cap length, double quotes (drop all if an odd run
                        # survives), and fold CR/LF into a VBS concat so a multi-line warning
                        # can't produce an unterminated literal that silently suppresses the popup.
                        $bRaw = ([string]$b) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                        if ($bRaw.Length -gt 1000) { $bRaw = $bRaw.Substring(0, 1000) }
                        $bDbl = $bRaw -replace '"','""'
                        if (($bDbl -replace '""','').Contains('"')) { $bDbl = $bRaw -replace '"','' }
                        $bEsc = $bDbl -replace "\r?\n", '" & vbCrLf & "'
                        ('Set o=CreateObject("Wscript.Shell")' + "`r`n" + 'o.Popup "' + $bEsc + '", 0, "Scheduled Reboot Notice", 48') | Out-File $vbsPath -Encoding ASCII -Force
                        $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$vbsPath`""
                        $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
                        Register-ScheduledTask -TaskName "WPT_RebMsg_$tag" -InputObject (New-ScheduledTask -Action $action -Principal $principal) -Force -EA Stop | Out-Null
                        Start-ScheduledTask -TaskName "WPT_RebMsg_$tag" -EA Stop; Start-Sleep -Seconds 3
                        Unregister-ScheduledTask -TaskName "WPT_RebMsg_$tag" -Confirm:$false -EA SilentlyContinue
                    }
                } catch { $notifyErr = $_.Exception.Message }
            }
            # re-arm cleanly: abort any existing pending shutdown, then schedule a fresh one.
            & shutdown.exe /a 2>&1 | Out-Null
            $sdOut = (& shutdown.exe /r /t $d /c $cmt /f 2>&1)
            $sdCode = $LASTEXITCODE
            if ($sdCode -ne 0) { "SHUTDOWN_FAIL: exit $sdCode $sdOut" }
            elseif ($notifyErr) { "NOTIFY_FAIL: $notifyErr" }
            else { 'OK' }
        }
        $res = [string]$res
        if ($res -like 'DNS_MISMATCH*') {
            $r.Detail = "DNS mismatch - ABORTED, no reboot scheduled ($($res -replace '^DNS_MISMATCH:\s*',''))"
        } elseif ($res -like 'SHUTDOWN_FAIL*') {
            $r.Detail = "shutdown command failed ($($res -replace '^SHUTDOWN_FAIL:\s*',''))"
        } else {
            $r.Success = $true
            $r.RebootAt = (Get-Date).AddSeconds($DelaySeconds).ToString('HH:mm:ss')
            $r.Detail = if ($res -like 'NOTIFY_FAIL*') { "scheduled for ~$($r.RebootAt); user-notify failed: $($res -replace '^NOTIFY_FAIL:\s*','')" } else { "reboot scheduled for ~$($r.RebootAt)" }
        }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Cancel a pending scheduled reboot (shutdown /a) ---
# Exit 1116 = ERROR_NO_SHUTDOWN_IN_PROGRESS -> "nothing to cancel" (still a success).
$script:WptRebootAbortBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    try {
        $splat = @{ ComputerName=$Computer; ErrorAction='Stop' }
        if ($Cred) { $splat['Credential']=$Cred }
        if ($Auth) { $splat['Authentication']=$Auth }
        $res = [string](Invoke-Command @splat -ScriptBlock {
            $aOut = (& shutdown.exe /a 2>&1)
            $code = $LASTEXITCODE
            if ($code -eq 0) { 'CANCELLED' } elseif ($code -eq 1116) { 'NONE' } else { "FAIL:$code $aOut" }
        })
        if ($res -eq 'CANCELLED') { $r.Success = $true; $r.Detail = 'pending reboot cancelled' }
        elseif ($res -eq 'NONE') { $r.Success = $true; $r.Detail = 'nothing to cancel (no pending reboot)' }
        else { $r.Detail = "shutdown /a failed ($($res -replace '^FAIL:\s*',''))" }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Ping Sweep (inline TcpClient.BeginConnect:12360) ---
$script:WptPingBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $reachable = $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    return @{ Host=$Computer; Reachable=$reachable }
}

# --- WinRM Bootstrap over DCOM (WinRMBootstrapBlock:5663) ---
$script:WptWinRMBootstrapBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Steps=(New-Object System.Collections.ArrayList); Success=$false; Error=''; PostProbeOk=$false }
    $addStep = { param($s) [void]$r.Steps.Add($s) }
    $opt = New-CimSessionOption -Protocol DCOM
    $cim = $null; $lastErr = $null
    for ($attempt = 1; $attempt -le 2 -and -not $cim; $attempt++) {
        try {
            $csplat = @{ ComputerName=$Computer; SessionOption=$opt; OperationTimeoutSec=30; ErrorAction='Stop' }
            if ($Cred) { $csplat['Credential']=$Cred }
            $cim = New-CimSession @csplat
        } catch { $lastErr = $_.Exception.Message; if ($attempt -lt 2) { Start-Sleep -Seconds 2 } }
    }
    if (-not $cim) {
        $r.Error = "DCOM connect failed (2 attempts): $lastErr"; & $addStep $r.Error
        $r.Steps = @($r.Steps); return $r
    }
    & $addStep "DCOM CIM session opened"
    try {
        $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        if (-not $svc) { $r.Error = "WinRM service not found on host (unusual)"; & $addStep $r.Error; return $r }
        & $addStep "WinRM service found - StartMode=$($svc.StartMode), State=$($svc.State)"
        if ($svc.StartMode -ne 'Auto') {
            try {
                $chg = Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName ChangeStartMode -Arguments @{ StartMode='Automatic' } -ErrorAction Stop
                if ($chg.ReturnValue -eq 0) { & $addStep "StartMode set to Automatic" } else { & $addStep "ChangeStartMode returned code $($chg.ReturnValue)" }
            } catch { & $addStep "ChangeStartMode failed: $($_.Exception.Message)" }
        }
        if ($svc.State -ne 'Running') {
            try {
                $start = Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName StartService -ErrorAction Stop
                if ($start.ReturnValue -eq 0) { & $addStep "WinRM service start requested" } else { & $addStep "StartService returned code $($start.ReturnValue)" }
                Start-Sleep -Seconds 2
            } catch { & $addStep "StartService failed: $($_.Exception.Message)" }
        } else { & $addStep "Service already running - skipping start" }
        $logPath = 'C:\Windows\Temp\wpt_winrm_bootstrap.log'
        $cmd = "cmd.exe /c winrm quickconfig -force -quiet -skipNetworkProfileCheck >""$logPath"" 2>&1"
        try {
            $proc = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine=$cmd } -ErrorAction Stop
            if ($proc.ReturnValue -eq 0) { & $addStep "winrm quickconfig queued (PID $($proc.ProcessId))"; Start-Sleep -Seconds 3 }
            else { & $addStep "Win32_Process.Create returned code $($proc.ReturnValue)" }
        } catch { & $addStep "quickconfig failed: $($_.Exception.Message)" }
        $deadline = (Get-Date).AddSeconds(30); $probeAttempts = 0
        do {
            $probeAttempts++
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected) { $r.PostProbeOk = $true }
            } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
            if (-not $r.PostProbeOk -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        } while (-not $r.PostProbeOk -and (Get-Date) -lt $deadline)
        if ($r.PostProbeOk) { & $addStep "Post-probe: WinRM 5985 reachable (attempt $probeAttempts)" }
        else { & $addStep "Post-probe: WinRM 5985 still not reachable after $probeAttempts probe(s) over 30s" }
        $r.Success = $r.PostProbeOk
    } catch {
        $r.Error = $_.Exception.Message; & $addStep "Bootstrap error: $($r.Error)"
    } finally {
        if ($cim) { try { Remove-CimSession $cim -ErrorAction SilentlyContinue } catch {} }
        $r.Steps = @($r.Steps)
    }
    return $r
}

# --- Health Scan (HealthScanBlock:5392) ---
$script:WptHealthScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; MecmState='Unknown'; ClientVer=''; SwCenter='Missing'
            WmiState='Unknown'; WuState='Unknown'; RebootState='Unknown'; RebootAge=''
            LastCheckIn=''; Overall='Unknown'; Error='' }
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $reachable = $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Overall='Offline'; $r.Error='Unreachable'; return $r }
    $r.Online = $true
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error="Session: $($_.Exception.Message)"; $r.Overall='Broken'; return $r }
    try {
        $probe = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
            $o = @{ MecmInstalled=$false; MecmRunning=$false; ClientVer=''; SwCenterExe=''
                    WmiOK=$false; WuSvcStartup=''; TrustedInstallerOK=$false
                    RebootPending=$false; PendingDays=0; LastPolicyReq='' }
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM') {
                $o.MecmInstalled = $true
                try { $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\CCM' -Name ClientVersion -ErrorAction Stop).ClientVersion; $o.ClientVer = [string]$v } catch {}
                try { $svc = Get-Service CcmExec -ErrorAction Stop; $o.MecmRunning = ($svc.Status -eq 'Running') } catch {}
                foreach ($p in @('C:\Windows\CCM\SCClient.exe','C:\Windows\CCM\ClientUX\SCClient.exe')) { if (Test-Path $p) { $o.SwCenterExe=$p; break } }
            }
            try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; if ($cs) { $o.WmiOK=$true } } catch {}
            try { $svcWu = Get-Service wuauserv -ErrorAction Stop; $o.WuSvcStartup=[string]$svcWu.StartType } catch {}
            try { $svcTi = Get-Service TrustedInstaller -ErrorAction Stop; $o.TrustedInstallerOK=[bool]$svcTi } catch {}
            $reasons = New-Object System.Collections.ArrayList; $oldestMark = $null
            try { $cbs = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop; [void]$reasons.Add('CBS'); if (-not $oldestMark -or $cbs.LastWriteTime -lt $oldestMark) { $oldestMark = $cbs.LastWriteTime } } catch {}
            try { $wu = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop; [void]$reasons.Add('WU'); if (-not $oldestMark -or $wu.LastWriteTime -lt $oldestMark) { $oldestMark = $wu.LastWriteTime } } catch {}
            try { $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop; if ($pfro.PendingFileRenameOperations) { [void]$reasons.Add('PFRO') } } catch {}
            try { $ccm = Invoke-WmiMethod -Namespace 'ROOT\ccm\ClientSDK' -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Stop; if ($ccm.IsHardRebootPending -or $ccm.RebootPending) { [void]$reasons.Add('SCCM') } } catch {}
            if ($reasons.Count -gt 0) { $o.RebootPending=$true; if ($oldestMark) { $o.PendingDays=[int]((Get-Date)-$oldestMark).TotalDays } }
            try { $lph = Get-CimInstance -Namespace 'root\ccm' -ClassName CCM_Client -ErrorAction Stop; if ($lph -and $lph.LastHinvChangeTime) { $o.LastPolicyReq = $lph.LastHinvChangeTime.ToString('yyyy-MM-dd HH:mm') } } catch {}
            if ([string]::IsNullOrWhiteSpace($o.LastPolicyReq)) { try { $sched = Get-ChildItem 'C:\Windows\CCM\Logs\ClientIDManagerStartup.log' -ErrorAction Stop; $o.LastPolicyReq = $sched.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } catch {} }
            return $o
        }
        if (-not $probe.MecmInstalled) { $r.MecmState='Missing' } elseif (-not $probe.MecmRunning) { $r.MecmState='Stopped' } else { $r.MecmState='Running' }
        $r.ClientVer = [string]$probe.ClientVer
        if (-not $probe.MecmInstalled) { $r.SwCenter='Missing' } elseif ([string]::IsNullOrWhiteSpace($probe.SwCenterExe)) { $r.SwCenter='Broken' } elseif (-not $probe.MecmRunning) { $r.SwCenter='NotRunning' } else { $r.SwCenter='Healthy' }
        $r.WmiState = if ($probe.WmiOK) { 'OK' } else { 'Broken' }
        if ($probe.WuSvcStartup -eq 'Disabled') { $r.WuState='Disabled' } elseif (-not $probe.TrustedInstallerOK) { $r.WuState='Broken' } elseif ($probe.WuSvcStartup) { $r.WuState='OK' }
        if ($probe.RebootPending) { $r.RebootState='Pending'; $r.RebootAge = if ([int]$probe.PendingDays -gt 0) { "$($probe.PendingDays)d" } else { '<1d' } } else { $r.RebootState='None' }
        $r.LastCheckIn = [string]$probe.LastPolicyReq
        if ($r.MecmState -eq 'Missing' -or $r.WmiState -eq 'Broken') { $r.Overall='Broken' }
        elseif ($r.MecmState -eq 'Stopped' -or $r.WuState -eq 'Disabled' -or $r.WuState -eq 'Broken' -or $r.SwCenter -eq 'Broken' -or ([int]$probe.PendingDays -gt 14)) { $r.Overall='Degraded' }
        else { $r.Overall='Healthy' }
    } catch { $r.Error=$_.Exception.Message; $r.Overall='Broken' }
    finally { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    return $r
}

# --- Healer: Restart CcmExec (RestartCcmExecBlock:5492) ---
$script:WptRestartCcmBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        Invoke-Command @splat -ScriptBlock {
            $svc = Get-Service CcmExec -ErrorAction Stop
            if ($svc.Status -eq 'Running') { Stop-Service CcmExec -Force -ErrorAction Stop }
            Start-Sleep -Seconds 2
            Start-Service CcmExec -ErrorAction Stop
            $svc2 = Get-Service CcmExec -ErrorAction Stop
            if ($svc2.Status -ne 'Running') { throw "CcmExec did not reach Running state (status=$($svc2.Status))" }
        }
        $r.Success = $true; $r.Detail = 'CcmExec restarted'
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Healer: CCM client repair (SMS_Client.RepairClient + ccmsetup.log return code) ---
$script:WptCcmRepairBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    # ccmsetup.exe return-code -> plain-language remediation table (PIRS parity
    # 6534-6577). Keys are upper-cased decimal OR hex strings so both 7/1603 and
    # 0x8007045D-style codes resolve. Used to enrich the reported Detail.
    $ccmCodeMap = @{
        '0'          = 'Completed successfully'
        '2'          = 'System cannot find the file specified (WMI Repair needed)'
        '5'          = 'Access denied (Check Admin Group)'
        '7'          = 'Reboot Required'
        '8'          = 'Setup Already Running'
        '9'          = 'Prerequisite evaluation failure'
        '10'         = 'Setup manifest hash validation failure'
        '52'         = 'Duplicate name exists on network (DNS/IP)'
        '53'         = 'Unable to locate network path (Check Firewall/Browser)'
        '58'         = 'The specified server cannot perform the requested operation'
        '64'         = 'The specified network name is no longer available'
        '67'         = 'Network name cannot be found (Check DNS)'
        '86'         = 'Incorrect network configuration'
        '112'        = 'Not enough disk space'
        '1003'       = 'Cannot complete this function'
        '1053'       = 'Service did not respond to start/control request'
        '1068'       = 'Dependency service or group failed to start'
        '1130'       = 'Not enough server storage is available'
        '1203'       = 'Network path typed incorrectly or unavailable'
        '1208'       = 'An extended error has occurred'
        '1305'       = 'The revision level is unknown'
        '1396'       = 'Login Failure: Target account incorrect (Check NBTSTAT)'
        '1450'       = 'Insufficient system resources'
        '1603'       = 'CCMExec could not be stopped (Reboot required)'
        '1618'       = 'Another MSI install in progress (Stop MSI processes)'
        '1789'       = 'Trust relationship with primary domain failed'
        '12002'      = 'Failed to send HTTP Request (Check firewall ports)'
        '8007045D'   = 'MSI: Unable to create WMI namespace CCM (Rebuild WMI)'
        '800706BA'   = 'WMI: Unable to connect to remote machine WMI'
        '80041001'   = 'MSI: Unable to create WMI namespace CCM (WMI Repair needed)'
        '8004103B'   = 'WMI: Unable to create WMI Namespace (Rebuild WMI)'
        '80070070'   = 'Setup failed due to unexpected circumstances (Rebuild WMI)'
        '87D0029E'   = 'WMI: CCMSetup Failed'
        '2147023174' = 'RPC server is unavailable (Check Firewall/AV)'
        '2147024891' = 'Access is denied'
        '2147749889' = 'WMI: Generic failure'
        '2147749890' = 'WMI: Not found (WMI Repair needed)'
        '2147749904' = 'WMI: Invalid class'
        '2147749908' = 'WMI: Initialization failure'
        '2147942405' = 'Access is Denied (Missing Firewall rules / AV)'
        '2147944122' = 'RPC server is unavailable (DCOM misconfigured)'
        '2148007941' = 'Server Execution Failed'
    }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 150000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
            if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM')) {
                return [pscustomobject]@{ Triggered=$false; Detail='MECM client not installed (HKLM\SOFTWARE\Microsoft\CCM missing)'; Running=$false; LogResult='' }
            }
            $triggered = $false; $tdetail = ''
            # SMS_Client.RepairClient() kicks off a full ccmsetup-based client repair.
            try {
                Invoke-WmiMethod -Namespace 'root\ccm' -Class SMS_Client -Name RepairClient -ErrorAction Stop | Out-Null
                $triggered = $true
            } catch {
                try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName RepairClient -ErrorAction Stop | Out-Null; $triggered = $true }
                catch { $tdetail = "RepairClient failed: $($_.Exception.Message)" }
            }
            # Bounded confirm (~60s): the repair runs 5-20 min, so we only confirm ccmsetup.exe started.
            $running = $false
            if ($triggered) {
                for ($i = 0; $i -lt 12; $i++) {
                    try { if (Get-Process -Name ccmsetup -ErrorAction SilentlyContinue) { $running = $true; break } } catch {}
                    Start-Sleep -Seconds 5
                }
            }
            # Most recent ccmsetup.log return code, if a prior install left one.
            # Capture hex OR decimal codes (PIRS parity 6611) so the local map can
            # resolve both 7/1603 and 0x8007045D-style failures.
            $logResult = ''; $retCode = ''
            $logPath = 'C:\Windows\ccmsetup\Logs\ccmsetup.log'
            if (Test-Path $logPath) {
                try {
                    $tail = Get-Content -LiteralPath $logPath -Tail 200 -ErrorAction Stop
                    $hit = $tail | Select-String -Pattern 'CcmSetup is exiting with return code ([-0-9A-Fa-fxX]+)' | Select-Object -Last 1
                    if ($hit) { $retCode = [string]$hit.Matches[0].Groups[1].Value; $logResult = "last ccmsetup return code $retCode" }
                } catch {}
            }
            return [pscustomobject]@{ Triggered=$triggered; Detail=$tdetail; Running=$running; LogResult=$logResult; ReturnCode=$retCode }
        }
        if ($out.Triggered) {
            $r.Success = $true
            $bits = New-Object System.Collections.Generic.List[string]
            [void]$bits.Add('RepairClient invoked')
            if ($out.Running) { [void]$bits.Add('ccmsetup.exe running (repair in progress, 5-20 min)') }
            else { [void]$bits.Add('ccmsetup.exe not yet seen (may start shortly)') }
            if ($out.LogResult) {
                # Append the plain-language meaning of the ccmsetup return code.
                $rc = ([string]$out.ReturnCode).Trim()
                $meaning = ''
                if ($rc) {
                    $key = $rc.ToUpper() -replace '^0X',''
                    if ($ccmCodeMap.ContainsKey($key)) { $meaning = $ccmCodeMap[$key] }
                    elseif ($ccmCodeMap.ContainsKey($rc)) { $meaning = $ccmCodeMap[$rc] }
                    else { $meaning = 'unmapped return code' }
                }
                if ($meaning) { [void]$bits.Add("$([string]$out.LogResult) ($meaning)") }
                else { [void]$bits.Add([string]$out.LogResult) }
            }
            $r.Detail = ($bits -join '; ')
        } else {
            $r.Detail = if ($out.Detail) { [string]$out.Detail } else { 'RepairClient not triggered' }
        }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Verify Patch (read-only; SCCM/MECM only; PIRS parity 2083-2106) ---
#  Poll CCM_SoftwareUpdate (root\ccm\ClientSDK) on the target up to $MaxPolls times
#  every $IntervalSeconds, mapping EvaluationState to text, until every (optionally
#  KB-filtered) update is terminal (InstallComplete/Error) or the poll budget is
#  spent. Returns one record per tracked update. No-ops gracefully (NoSccm) when the
#  root\ccm namespace is absent. AFNET-safe: TCP reachability + WinRM session; CIM
#  runs ON the target inside Invoke-Command.
$script:WptVerifyPatchBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$KbFilterCsv, [int]$MaxPolls, [int]$IntervalSeconds)
    $r = @{ Host=$Computer; Updates=@(); Error=''; NoSccm=$false }
    if ($MaxPolls -lt 1) { $MaxPolls = 1 }
    if ($IntervalSeconds -lt 1) { $IntervalSeconds = 1 }
    # TCP reachability (bare worker runspace -> inline, never ICMP).
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
    $wsOpt = New-PSSessionOption -OperationTimeout 120000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        $filters = @($KbFilterCsv -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $last = @{}; $completed = $false
        for ($poll = 1; $poll -le $MaxPolls; $poll++) {
            $snap = Invoke-Command -Session $sess -ArgumentList (,$filters) -EA Stop -ScriptBlock {
                param($flt)
                $map = @{0='None';1='Available';2='Submitted';3='Detecting';4='PreDownload';5='Downloading';6='WaitInstall';7='Installing';8='PendingSoftReboot';9='PendingHardReboot';10='WaitReboot';11='Verifying';12='InstallComplete';13='Error'}
                try {
                    $ups = @(Get-CimInstance -Namespace root\ccm\ClientSDK -ClassName CCM_SoftwareUpdate -EA Stop)
                } catch {
                    return @{ NoSccm=$true; Items=@() }
                }
                $res = New-Object System.Collections.ArrayList
                foreach ($u in $ups) {
                    $nm  = [string]$u.Name
                    $art = [string]$u.ArticleID
                    if (@($flt).Count -gt 0) {
                        $hit = $false
                        foreach ($f in @($flt)) {
                            if (($nm -and ($nm -match [regex]::Escape($f))) -or ($art -and (("KB$art" -match [regex]::Escape($f)) -or ($art -match [regex]::Escape($f))))) { $hit = $true; break }
                        }
                        if (-not $hit) { continue }
                    }
                    $es = [int]$u.EvaluationState
                    $stateTxt = if ($map.ContainsKey($es)) { $map[$es] } else { "State $es" }
                    [void]$res.Add(@{ Name=$nm; ArticleID=$art; Eval=$es; State=$stateTxt })
                }
                return @{ NoSccm=$false; Items=$res.ToArray() }
            }
            if ($snap.NoSccm) { $r.NoSccm = $true; break }   # graceful no-op (Error stays '' so it audits Success/itemCount 0)
            $items = @($snap.Items)
            $allDone = $true; $cur = @{}
            foreach ($it in $items) {
                $es = [int]$it.Eval
                if     ($es -eq 12) { $status = 'Installed' }
                elseif ($es -eq 13) { $status = 'Error' }
                elseif ($es -eq 7)  { $status = 'Installing' }
                else                { $status = 'Pending' }
                $cur[[string]$it.Name] = @{ State=[string]$it.State; Status=$status; Eval=$es }
                if (-not ($es -eq 12 -or $es -eq 13)) { $allDone = $false }
            }
            $last = $cur
            if ($items.Count -eq 0 -or $allDone) { $completed = $true; break }
            if ($poll -lt $MaxPolls) { Start-Sleep -Seconds $IntervalSeconds }
        }
        # Build the final per-update record set. If the poll budget ran out before
        # everything went terminal, non-terminal items report 'Timeout'.
        $finalRows = New-Object System.Collections.ArrayList
        foreach ($k in $last.Keys) {
            $st = [string]$last[$k].Status
            if (-not $completed -and ($st -eq 'Pending' -or $st -eq 'Installing')) { $st = 'Timeout' }
            [void]$finalRows.Add(@{ Update=[string]$k; State=[string]$last[$k].State; Status=$st })
        }
        $r.Updates = $finalRows.ToArray()
    } catch { $r.Error = $_.Exception.Message }
    finally { if ($sess) { Remove-PSSession $sess -EA SilentlyContinue } }
    return $r
}

# --- Healer: WMI repair (WmiRepairBlock:5510) ---
$script:WptWmiRepairBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
            $result = & winmgmt /salvagerepository 2>&1 | Out-String
            [pscustomobject]@{ Output=$result; Exit=$LASTEXITCODE }
        }
        if ($null -eq $out.Exit) { $r.Detail = "winmgmt did not run. Output: $($out.Output.Trim())" }
        elseif ($out.Exit -eq 0) { $r.Success = $true; $r.Detail = "exit=0; $($out.Output.Trim())" }
        else { $r.Detail = "exit=$($out.Exit); $($out.Output.Trim())" }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Healer: WU reset (WuResetBlock:5535) ---
$script:WptWuResetBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
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
                    Start-Service $svc -ErrorAction Stop; [void]$completed.Add("started $svc")
                    if ($svc -eq 'wuauserv') { $wuRestarted = $true }
                } catch {
                    [void]$failed.Add("start-$svc failed: $($_.Exception.Message)")
                    if ($svc -in 'wuauserv','cryptsvc') { $criticalFailed = $true }
                }
            }
            return [pscustomobject]@{ Completed=@($completed.ToArray()); Failed=@($failed.ToArray()); CriticalFailed=[bool]$criticalFailed; WuRestarted=[bool]$wuRestarted }
        }
        $r.Success = ($out.WuRestarted -and -not $out.CriticalFailed)
        $r.Detail = if ($r.Success) { "WU reset OK. Steps: $((@($out.Completed)) -join ' | ')" } else { "WU reset degraded. Failed: $((@($out.Failed)) -join ' | ')" }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Healer: Trigger check-in (TriggerCheckInBlock:5577) ---
$script:WptTriggerCheckInBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
            $schedules = @{ '{00000000-0000-0000-0000-000000000022}'='MachinePolicy'; '{00000000-0000-0000-0000-000000000113}'='SWUpdatesScan' }
            $ok = New-Object System.Collections.ArrayList; $bad = New-Object System.Collections.ArrayList
            foreach ($g in $schedules.Keys) {
                try { Invoke-WmiMethod -Namespace 'root\ccm' -Class SMS_Client -Name TriggerSchedule -ArgumentList $g -ErrorAction Stop | Out-Null; [void]$ok.Add($schedules[$g]) }
                catch { [void]$bad.Add("$($schedules[$g]): $($_.Exception.Message)") }
            }
            return [pscustomobject]@{ Succeeded=@($ok); Failed=@($bad) }
        }
        if (@($out.Succeeded).Count -gt 0) {
            $r.Success = $true; $r.Detail = "Triggered: $(@($out.Succeeded) -join ', ')"
            if (@($out.Failed).Count -gt 0) { $r.Detail += " (partial: $(@($out.Failed) -join '; '))" }
        } else { $r.Detail = "No schedules triggered: $(@($out.Failed) -join '; ')" }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Healer: gpupdate (GpUpdateBlock:5612) ---
$script:WptGpUpdateBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 30000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
            $text = & gpupdate.exe /force /wait:60 2>&1 | Out-String
            [pscustomobject]@{ Output=$text; Exit=$LASTEXITCODE }
        }
        $summary = (($out.Output -split "`r?`n") | Where-Object { $_ -match '(updated|error|failed|successfully)' } | Select-Object -First 3) -join ' | '
        if ($null -eq $out.Exit) { $r.Detail = "gpupdate did not run. Output: $($summary.Trim())" }
        elseif ($out.Exit -eq 0) { $r.Success = $true; $r.Detail = "gpupdate exit=0; $($summary.Trim())" }
        else { $r.Detail = "gpupdate exit=$($out.Exit); $($summary.Trim())" }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- KB Scan (kbBlock:7684) ---
$script:WptKbScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; KBs=@(); Error='' }
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
    $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $sess = New-PSSession @splat
        try {
            $kbs = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                Get-HotFix -EA SilentlyContinue | ForEach-Object {
                    @{ HotFixID=$_.HotFixID; Description=$_.Description; InstalledOn=if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}else{''}; InstalledBy=$_.InstalledBy }
                }
            }
            $r.KBs = @($kbs)
        } finally { Remove-PSSession $sess -EA SilentlyContinue }
    } catch { $r.Error = $_.Exception.Message }
    return $r
}

# --- KB Install (MECM-first + MSU fallback; mirrors desktop installBlock 7593-7636) ---
$script:WptKbInstallBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string[]]$KBs, [string]$MsuPath, [bool]$NoReboot)
    $r = @{ Host=$Computer; MECMFound=0; MECMInstalled=0; MSUInstalled=0; Skipped=0; Errors=@(); Details=@() }
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc=$null
        try { $tc=New-Object System.Net.Sockets.TcpClient; $iar=$tc.BeginConnect($Computer,$port,$null,$null); if ($iar.AsyncWaitHandle.WaitOne(1500,$false) -and $tc.Connected) { $reachable=$true } } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { $r.Errors += 'Offline'; return $r }
    $wsOpt = New-PSSessionOption -OperationTimeout 1800000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null; try { $sess = New-PSSession @splat } catch { $r.Errors += "Session failed: $($_.Exception.Message)"; return $r }
    try {
        # DNS-mismatch guard (HARD ABORT): never install KBs on a box that isn't the
        # one we dialed (stale DNS / reused IP). Session-based name compare (no PTR).
        $actualName = try { Invoke-Command -Session $sess -EA Stop -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Errors += "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no KB installed"
            return $r  # the finally below removes the session
        }
        # MECM first: match each requested KB in CCM_SoftwareUpdate (not-compliant) by
        # ArticleID/Name, then InstallUpdates the matched set.
        $mecm = Invoke-Command -Session $sess -ArgumentList (,$KBs) -EA Stop -ScriptBlock {
            param([string[]]$targetKBs)
            $found=@(); $allUpdates=@()
            try { $allUpdates = @(Get-WmiObject -Namespace 'ROOT\ccm\ClientSDK' -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop) } catch { return @{ Found=@(); Triggered=0; Error="MECM query failed: $($_.Exception.Message)" } }
            foreach ($kb in $targetKBs) { if (@($allUpdates | Where-Object { $_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','') }).Count -gt 0) { $found += $kb } }
            if ($found.Count -gt 0) {
                $toInstall = @($allUpdates | Where-Object { $dom=$false; foreach ($kb in $found) { if ($_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','')) { $dom=$true; break } }; $dom })
                if ($toInstall.Count -gt 0) { try { Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$toInstall) -Namespace 'ROOT\ccm\ClientSDK' -EA Stop | Out-Null; return @{ Found=$found; Triggered=$toInstall.Count; Error='' } } catch { return @{ Found=$found; Triggered=0; Error="Install trigger failed: $($_.Exception.Message)" } } }
            }
            return @{ Found=$found; Triggered=0; Error='' }
        }
        if (@($mecm.Found).Count -gt 0) { $r.MECMFound = @($mecm.Found).Count; if ($mecm.Triggered -gt 0) { $r.MECMInstalled = $mecm.Triggered; $r.Details += "MECM: triggered $($mecm.Triggered) update(s)" } }
        if ($mecm.Error) { $r.Errors += $mecm.Error }
        $handled = @(); if ($mecm.Found) { $handled = @($mecm.Found) }
        $remaining = @($KBs | Where-Object { $handled -notcontains $_ })
        if ($remaining.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($MsuPath)) {
            if (-not (Test-Path -LiteralPath $MsuPath)) { $r.Errors += "MSU file not found: $MsuPath" }
            else {
                Invoke-Command -Session $sess -EA Stop -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -Force -EA Stop | Out-Null } }
                $msuName = Split-Path $MsuPath -Leaf
                try {
                    Copy-Item -LiteralPath $MsuPath -Destination "C:\Temp\$msuName" -ToSession $sess -Force -EA Stop
                    $wusaArgs = "C:\Temp\$msuName /quiet"; if ($NoReboot) { $wusaArgs += ' /norestart' }
                    $exit = Invoke-Command -Session $sess -ArgumentList $wusaArgs -EA Stop -ScriptBlock { param($a) (Start-Process -FilePath 'wusa.exe' -ArgumentList $a -Wait -PassThru -NoNewWindow -EA Stop).ExitCode }
                    if ($exit -eq 0 -or $exit -eq 3010) { $r.MSUInstalled++; $r.Details += "MSU $($msuName): installed (exit $exit)" }
                    elseif ($exit -eq 2359302) { $r.Skipped++; $r.Details += "MSU $($msuName): already installed" }
                    else { $r.Errors += "MSU $msuName exit $exit" }
                    Invoke-Command -Session $sess -ArgumentList $msuName -EA SilentlyContinue -ScriptBlock { param($n) Remove-Item "C:\Temp\$n" -Force -EA SilentlyContinue }
                } catch { $r.Errors += "MSU copy/install: $($_.Exception.Message)" }
            }
        } elseif ($remaining.Count -gt 0) { foreach ($kb in $remaining) { $r.Skipped++; $r.Details += "$kb not in MECM, no MSU path -- skipped" } }
    } finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# --- KB Trigger MECM cycles (btnKBTrigger:7517) ---
$script:WptKbTriggerBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Status=''; Success=$false }
    $opt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        Invoke-Command @splat -ScriptBlock {
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000113}" -EA SilentlyContinue | Out-Null
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000114}" -EA SilentlyContinue | Out-Null
            Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000021}" -EA SilentlyContinue | Out-Null
        }
        $r.Success = $true; $r.Status = 'MECM cycles triggered'
    } catch { $r.Status = "FAILED - $($_.Exception.Message)" }
    return $r
}

# --- KB Push & Download (btnKBPushDownload:7534) ---
$script:WptKbPushDownloadBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; PendingCount=0; Status=''; Success=$false }
    $opt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $result = Invoke-Command @splat -ScriptBlock {
            $pending = @(Get-WmiObject -Namespace "ROOT\ccm\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop)
            if ($pending.Count -eq 0) { return @{ Count=0; Error='' } }
            try {
                Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000108}" -EA SilentlyContinue | Out-Null
                Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000114}" -EA SilentlyContinue | Out-Null
                return @{ Count=$pending.Count; Error='' }
            } catch { return @{ Count=$pending.Count; Error=$_.Exception.Message } }
        }
        $cnt = if ($result -is [hashtable]) { [int]$result['Count'] } else { [int]$result.Count }
        $err = if ($result -is [hashtable]) { [string]$result['Error'] } else { [string]$result.Error }
        $r.PendingCount = $cnt
        if ($cnt -eq 0) { $r.Success = $true; $r.Status = 'No pending updates (fully current)' }
        elseif ([string]::IsNullOrWhiteSpace($err)) { $r.Success = $true; $r.Status = "$cnt pending update(s) - download triggered" }
        else { $r.Status = "$cnt pending but trigger failed: $err" }
    } catch { $r.Status = "FAILED - $($_.Exception.Message)" }
    return $r
}

# --- Remote Message (btnMsgSend:7255 scheduled-task/VBS path) ---
$script:WptMessageBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$Title, [string]$Body, [int]$Timeout)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $result = Invoke-Command @splat -ArgumentList $Title, $Body, $Timeout -ScriptBlock {
            param($t, $b, $to)
            try {
                $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
                if ([string]::IsNullOrWhiteSpace($loggedIn)) { return "FAIL: No user logged in" }
                New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                $vbsPath = "C:\Temp\WPT_Msg_$(Get-Random).vbs"; $timeoutVal = if ($to -gt 0) { $to } else { 0 }
                # Escape quotes AND fold newlines into VBS concatenation - a raw CR/LF
                # inside a VBS "..." literal is a syntax error (multi-line bodies failed).
                # Harden the fold so a stray control byte, a huge paste, or a trailing
                # backslash+quote edge case can't break the single Popup statement:
                #  1) strip control chars (body keeps the CR/LF we deliberately fold),
                #  2) cap length (Title 200 / Body 1000),
                #  3) double every quote, then ASSERT no lone quote survived (an odd quote
                #     run would close the literal early) - if one did, strip quotes outright.
                $bRaw = ([string]$b) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                $tRaw = ([string]$t) -replace "[\x00-\x09\x0B-\x1F]", ' '
                if ($bRaw.Length -gt 1000) { $bRaw = $bRaw.Substring(0, 1000) }
                if ($tRaw.Length -gt 200)  { $tRaw = $tRaw.Substring(0, 200) }
                $bDbl = $bRaw -replace '"','""'
                $tDbl = $tRaw -replace '"','""'
                # After doubling, every " must be part of a "" pair. If removing all pairs
                # leaves a stray ", the escaping didn't hold (e.g. odd quote run) -> drop all
                # quotes so the literal stays closed. Assert on the pre-fold strings; the
                # newline fold below intentionally adds its own (correct) literal quotes.
                if (($bDbl -replace '""','').Contains('"')) { $bDbl = $bRaw -replace '"','' }
                if (($tDbl -replace '""','').Contains('"')) { $tDbl = $tRaw -replace '"','' }
                $bEsc = $bDbl -replace "\r?\n", '" & vbCrLf & "'
                $tEsc = $tDbl -replace "\r?\n", ' '
                $vbsContent = 'Set oShell = CreateObject("Wscript.Shell")' + "`r`n" + 'oShell.Popup "' + $bEsc + '", ' + $timeoutVal + ', "' + $tEsc + '", 64' + "`r`n"
                [System.IO.File]::WriteAllText($vbsPath, $vbsContent)
                $taskName = "WPT_Message_$(Get-Random)"
                $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
                $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
                $task = New-ScheduledTask -Action $action -Principal $principal
                Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -EA Stop | Out-Null
                Start-ScheduledTask -TaskName $taskName -EA Stop; Start-Sleep -Seconds 3
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue
                Start-Job -ScriptBlock { param($p); Start-Sleep -Seconds 120; Remove-Item $p -Force -EA SilentlyContinue } -ArgumentList $vbsPath | Out-Null
                return "OK (scheduled task as $loggedIn)"
            } catch {
                # Best-effort cleanup on the FAILURE path too, mirroring the success cleanup:
                # a throw after the .vbs is written / the task is registered would otherwise
                # orphan the temp script and the scheduled task on the host. Guard each (they
                # may be unset if the throw happened earlier) and swallow secondary errors.
                if ($taskName) { try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -EA SilentlyContinue } catch {} }
                if ($vbsPath -and (Test-Path -LiteralPath $vbsPath)) { try { Remove-Item -LiteralPath $vbsPath -Force -EA SilentlyContinue } catch {} }
                return "FAIL: $($_.Exception.Message)"
            }
        }
        if ("$result" -like 'OK*') { $r.Success = $true; $r.Detail = "$result" } else { $r.Detail = "$result" }
    } catch { $r.Detail = "WinRM error: $($_.Exception.Message)" }
    return $r
}

# --- Disk Cleanup (CleanBlock:7881) ---
$script:WptCleanBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$DoTemp, [bool]$DoProfiles, [int]$DaysThreshold, [bool]$DryRun, [bool]$DoCache)
    $r = @{ Host=$Computer; TempMB=0; TempFiles=0; CacheMB=0; ProfilesFound=0; ProfilesRemoved=0; Skipped=0; ProfileNames=@(); FreeBeforeGB=$null; FreeAfterGB=$null; FreedMB=0; Events=@(); Status='Failed'; Detail='' }
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
    if (-not $reachable) { $r.Detail = 'Offline'; return $r }
    $wsOpt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Detail = "Session: $($_.Exception.Message)"; return $r }
    try {
        # C: free-space snapshot (before) over the same WinRM session, so the row can
        # report a real before/after delta. CIM runs ON the target inside the session.
        try {
            $fb = Invoke-Command -Session $sess -EA Stop -ScriptBlock { $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA Stop; [Math]::Round($d.FreeSpace/1GB,2) }
            $r.FreeBeforeGB = [double]$fb
        } catch {}
        if ($DoTemp) {
            $r.Events = @($r.Events) + @(@{ Level='ACTION'; Msg="[$Computer] Phase: Temp file cleanup starting" })
            $tempResult = Invoke-Command -Session $sess -ArgumentList $DryRun, $Computer -EA Stop -ScriptBlock {
                param($dry, $thisHost)
                # Per-path diagnostics buffered here and replayed by the dispatcher
                # (desktop CleanBlock event-queue parity) so the operator sees what
                # the temp sweep is doing per host, dry-run or live.
                $ev  = New-Object System.Collections.Generic.List[hashtable]
                $add = { param($lvl, $msg) [void]$ev.Add(@{ Level=$lvl; Msg=$msg }) }
                $totalBytes = 0; $totalFiles = 0
                $tempPaths = @('C:\Windows\Temp','C:\Temp','C:\Windows\Prefetch','C:\Windows\SoftwareDistribution\Download')
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
            $r.Events = @($r.Events) + @($tempResult.Events)
            $r.TempMB = [Math]::Round(($tempResult.Bytes / 1MB), 1); $r.TempFiles = $tempResult.Files
            $r.Events = @($r.Events) + @(@{ Level='OK'; Msg="[$Computer] Temp complete: $($r.TempMB) MB / $($r.TempFiles) files" })
        }
        if ($DoCache) {
            $r.Events = @($r.Events) + @(@{ Level='ACTION'; Msg="[$Computer] Phase: MECM cache (ccmcache) cleanup" })
            $cacheResult = Invoke-Command -Session $sess -ArgumentList $DryRun, $Computer -EA Stop -ScriptBlock {
                param($dry, $thisHost)
                $ev  = New-Object System.Collections.Generic.List[hashtable]
                $add = { param($lvl, $msg) [void]$ev.Add(@{ Level=$lvl; Msg=$msg }) }
                $cachePath = 'C:\Windows\ccmcache'
                if (-not (Test-Path -LiteralPath $cachePath)) {
                    & $add 'INFO' "[$thisHost]   ccmcache not present (MECM client may not be installed)"
                    return @{ Bytes=0; Files=0; Events=$ev.ToArray() }
                }
                $files = Get-ChildItem -LiteralPath $cachePath -Recurse -Force -File -EA SilentlyContinue
                $bytes = 0; foreach ($f in $files) { $bytes += $f.Length }
                $mb = [Math]::Round($bytes / 1MB, 1)
                & $add 'ACTION' "[$thisHost]   ccmcache holds $mb MB in $(@($files).Count) file(s)"
                if (-not $dry) {
                    foreach ($it in (Get-ChildItem -LiteralPath $cachePath -Force -EA SilentlyContinue)) {
                        try { Remove-Item -LiteralPath $it.FullName -Recurse -Force -EA Stop } catch {}
                    }
                    & $add 'DELETE' "[$thisHost]     Deleted ccmcache contents ($mb MB)"
                } else {
                    & $add 'DELETE' "[$thisHost]     Would delete ccmcache contents ($mb MB)"
                }
                return @{ Bytes=$bytes; Files=@($files).Count; Events=$ev.ToArray() }
            }
            $r.Events = @($r.Events) + @($cacheResult.Events)
            $r.CacheMB = [Math]::Round(($cacheResult.Bytes / 1MB), 1)
            $r.Events = @($r.Events) + @(@{ Level='OK'; Msg="[$Computer] ccmcache complete: $($r.CacheMB) MB" })
        }
        if ($DoProfiles) {
            $r.Events = @($r.Events) + @(@{ Level='ACTION'; Msg="[$Computer] Phase: Profile scan (threshold $DaysThreshold days)" })
            $profResult = Invoke-Command -Session $sess -ArgumentList $DaysThreshold, $DryRun, $Computer -EA Stop -ScriptBlock {
                param($days, $dry, $thisHost)
                # Per-profile events are buffered here and replayed as log events by
                # the dispatcher - dry-run review must show WHICH profiles will be
                # destroyed (desktop CleanBlock event-queue parity).
                $ev  = New-Object System.Collections.Generic.List[hashtable]
                $add = { param($lvl, $msg) [void]$ev.Add(@{ Level=$lvl; Msg=$msg }) }
                $cutoff = (Get-Date).AddDays(-$days)
                $found = 0; $removed = 0; $skipped = 0; $names = @()
                $curName  = $env:USERNAME
                $baseName = $curName -replace '\.adw$',''
                $adwName  = "$baseName.adw"
                $excluded = @('Public','Administrator','USAF_Admin',$curName,$baseName,$adwName) | Sort-Object -Unique
                $profiles = Get-WmiObject Win32_UserProfile -Filter "LocalPath like 'C:\\Users\\%'" -EA SilentlyContinue | Where-Object {
                    -not $_.Special -and (Split-Path -Parent $_.LocalPath) -eq "$env:SystemDrive\Users" -and (Split-Path -Leaf $_.LocalPath) -notin $excluded
                }
                & $add 'INFO' "[$thisHost]   Found $(@($profiles).Count) candidate profile(s) (excluded: $($excluded -join ', '))"
                foreach ($p in $profiles) {
                    $profPath = $p.LocalPath; if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
                    $profName = Split-Path $profPath -Leaf
                    $folder = Get-Item -LiteralPath $profPath -Force -EA SilentlyContinue
                    if (-not $folder) { & $add 'WARN' "[$thisHost]     Skip (folder missing): $profName"; $skipped++; continue }
                    $sigs = @()
                    $ntuser = Get-Item -LiteralPath (Join-Path $profPath 'NTUSER.DAT') -Force -EA SilentlyContinue
                    if ($ntuser -and $ntuser.LastWriteTime -gt [datetime]'2000-01-01') { $sigs += [pscustomobject]@{ Src='NTUSER.DAT'; Time=$ntuser.LastWriteTime } }
                    if ($p.LastUseTime) { try { $t = [System.Management.ManagementDateTimeConverter]::ToDateTime($p.LastUseTime); if ($t -gt [datetime]'2000-01-01') { $sigs += [pscustomobject]@{ Src='LastUseTime'; Time=$t } } } catch {} }
                    if ($folder.LastWriteTime -gt [datetime]'2000-01-01') { $sigs += [pscustomobject]@{ Src='folder-mtime'; Time=$folder.LastWriteTime } }
                    if ($sigs.Count -eq 0) { & $add 'WARN' "[$thisHost]     Skip (no usable timestamps): $profName"; $skipped++; continue }
                    # Age = the OLDEST of the three signals (ascending sort, -First 1).
                    # Faithful to the desktop reference (WorkstationPatchingTool_6.5.22.ps1:8024).
                    # On live AFNET hosts SOMETHING (Defender/ESS/Search/GPO/OneDrive) bumps at
                    # least one signal recently, so trusting the NEWEST signal made every stale
                    # profile read "recent" -> "finds 0 profiles". A genuinely active profile
                    # bumps ALL three, so the oldest stays recent too; the $p.Loaded check below
                    # is the safety net against deleting a profile that still has a live session.
                    $oldest = ($sigs | Sort-Object Time | Select-Object -First 1)
                    $lastUse = $oldest.Time; $ageSrc = $oldest.Src
                    $ageDays = [int]((Get-Date) - $lastUse).TotalDays
                    $spread = ($sigs | ForEach-Object { "$($_.Src)=$($_.Time.ToString('yyyy-MM-dd'))" }) -join ' / '
                    & $add 'INFO' "[$thisHost]     $profName signals: $spread (oldest=$ageSrc, ${ageDays}d)"
                    if ($lastUse -ge $cutoff) { & $add 'INFO' "[$thisHost]     Keep: $profName (${ageDays}d old, under ${days}d threshold)"; continue }
                    if ($p.Loaded) { $skipped++; & $add 'WARN' "[$thisHost]     Stale but LOADED: $profName (${ageDays}d) -- reboot host to unload, then re-run"; continue }
                    $found++
                    $names += "$profName (${ageDays}d, src=$ageSrc)"
                    & $add 'ACTION' "[$thisHost]     Stale: $profName (${ageDays}d, oldest signal=$ageSrc)"
                    if (-not $dry) {
                        $deleted = $false
                        $tries = New-Object System.Collections.Generic.List[string]
                        $sid = [string]$p.SID
                        try { $p.Delete(); $deleted = $true; $tries.Add('WMI=ok') | Out-Null }
                        catch { $msg = $_.Exception.Message; if ([string]::IsNullOrWhiteSpace($msg)) { $msg = '(empty)' }; $tries.Add("WMI=fail:$msg") | Out-Null }
                        if (-not $deleted) {
                            try {
                                $cim = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -EA Stop
                                if ($cim) { Remove-CimInstance -InputObject $cim -EA Stop; $deleted = $true; $tries.Add('CIM=ok') | Out-Null }
                                else { $tries.Add('CIM=fail:no-instance') | Out-Null }
                            } catch { $tries.Add("CIM=fail:$($_.Exception.Message)") | Out-Null }
                        }
                        if (-not $deleted) {
                            # v6.4.1 hardened manual tier (desktop 8047-8171). Handles the
                            # two failure modes the simple Remove-Item path can't: MAX_PATH
                            # blowouts (Office vNext license files) and ACLs the .adw
                            # account can't traverse. Order: takeown + icacls grant ->
                            # Remove-Item -> cmd rd /s /q -> robocopy /MIR from an empty
                            # dir (walks long paths natively) -> ProfileList SID key, which
                            # is ALWAYS attempted - key-only removal still detaches the
                            # profile from Windows, so it counts as deleted.
                            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                            $folderGone = (-not (Test-Path -LiteralPath $profPath))
                            $manualErr  = ''
                            if (-not $folderGone) {
                                try { & cmd /c "takeown /F `"$profPath`" /A /R /D Y" 2>&1 | Out-Null } catch {}
                                try { & cmd /c "icacls `"$profPath`" /grant *S-1-5-32-544:(F) /T /C /Q" 2>&1 | Out-Null } catch {}
                            }
                            if (-not $folderGone) {
                                try { Remove-Item -LiteralPath $profPath -Recurse -Force -EA Stop; $folderGone = $true }
                                catch { $manualErr = $_.Exception.Message }
                            }
                            if (-not $folderGone -and (Test-Path -LiteralPath $profPath)) {
                                try {
                                    & cmd /c "rd /s /q `"$profPath`"" 2>&1 | Out-Null
                                    if (-not (Test-Path -LiteralPath $profPath)) { $folderGone = $true }
                                } catch {}
                            }
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
                            $keyGone = $true
                            try {
                                if ($sid -and (Test-Path -LiteralPath $regKey)) { Remove-Item -LiteralPath $regKey -Recurse -Force -EA Stop }
                            } catch { $keyGone = $false; $manualErr = "regkey: $($_.Exception.Message)" }
                            if ($folderGone -and $keyGone) { $deleted = $true; $tries.Add('Manual=ok') | Out-Null }
                            elseif ($keyGone -and -not $folderGone) { $deleted = $true; $tries.Add('Manual=partial(key-only)') | Out-Null }
                            else { $tries.Add($(if ($manualErr) { "Manual=fail:$manualErr" } else { 'Manual=fail:folder remained' })) | Out-Null }
                        }
                        if ($deleted) { $removed++; & $add 'DELETE' "[$thisHost]       DELETED profile: $profName ($(($tries -join ' ; ')))" }
                        else { $skipped++; & $add 'ERR' "[$thisHost]       Delete failed: $profName ($(($tries -join ' ; ')))" }
                    } else {
                        & $add 'DELETE' "[$thisHost]       Would delete (dry run): $profName (${ageDays}d, src=$ageSrc)"
                    }
                }
                return @{ Found=$found; Removed=$removed; Skipped=$skipped; Names=$names; Events=$ev.ToArray() }
            }
            $r.ProfilesFound = $profResult.Found; $r.ProfilesRemoved = $profResult.Removed; $r.Skipped = $profResult.Skipped
            $r.ProfileNames = @($profResult.Names); $r.Events = @($r.Events) + @($profResult.Events)
            $r.Events = @($r.Events) + @(@{ Level='OK'; Msg="[$Computer] Profile phase complete: $($r.ProfilesFound) stale, $($r.ProfilesRemoved) removed, $($r.Skipped) skipped" })
        }
        # C: free-space snapshot (after) + freed delta over the same session.
        try {
            $fa = Invoke-Command -Session $sess -EA Stop -ScriptBlock { $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA Stop; [Math]::Round($d.FreeSpace/1GB,2) }
            $r.FreeAfterGB = [double]$fa
        } catch {}
        if ($null -ne $r.FreeBeforeGB -and $null -ne $r.FreeAfterGB) {
            # only report a delta when BOTH snapshots were captured; a failed 'before'
            # would otherwise make 'after' read as the entire free space "freed".
            $r.FreedMB = [Math]::Round((($r.FreeAfterGB - $r.FreeBeforeGB) * 1024), 1)
            if ($r.FreedMB -lt 0) { $r.FreedMB = 0 }   # dry-run / concurrent-write noise -> floor at 0
            $r.Events = @($r.Events) + @(@{ Level='OK'; Msg="[$Computer] Freed $($r.FreedMB) MB; C: free $($r.FreeBeforeGB) -> $($r.FreeAfterGB) GB" })
        }
        $r.Status = if ($DryRun) { 'Dry Run OK' } else { 'Success' }
        $r.Detail = "Temp: $($r.TempMB)MB / $($r.TempFiles) files | Cache: $($r.CacheMB)MB | Profiles found: $($r.ProfilesFound), removed: $($r.ProfilesRemoved), skipped: $($r.Skipped) | Freed: $($r.FreedMB)MB (C: free $($r.FreeBeforeGB) -> $($r.FreeAfterGB) GB)"
        if (@($r.ProfileNames).Count -gt 0) { $r.Detail += " | Profiles: $((@($r.ProfileNames)) -join ', ')" }
        $r.Events = @($r.Events) + @(@{ Level='OK'; Msg="[$Computer] DONE -- $($r.Detail)" })
    } catch { $r.Detail = $_.Exception.Message }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# --- Registry Key Scan (RegKeyScanBlock:8375) ---
$script:WptRegScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$RegPath, [object[]]$Defs)
    $r = @{ Host=$Computer; Reachable=$false; RegValues=@{}; Status='Unreachable'; Error='' }
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
        $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
        if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
        $remote = Invoke-Command @splat -ArgumentList $RegPath, $Defs -ScriptBlock {
            param($p, $defs)
            $out = @{}
            foreach ($d in $defs) { $val = $null; try { $val = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}; $out[$d.Name] = $val }
            return $out
        }
        $r.Reachable = $true
        $r.RegValues = @{}
        foreach ($k in $remote.Keys) { $r.RegValues[$k] = $remote[$k] }
        $allMatch = $true; $anyMissing = $false; $anyDrift = $false
        foreach ($d in $Defs) {
            $cur = $r.RegValues[$d.Name]
            if ($null -ne $d.OrBits) {
                # [int64] (not [int]) so a DWORD/QWORD value above int32 range doesn't overflow/throw;
                # results are identical for the small in-range catalog values.
                $bits = [int64]$d.OrBits
                if ($null -eq $cur) { $anyMissing = $true; $allMatch = $false }
                elseif (([int64]$cur -band $bits) -ne $bits) { $anyDrift = $true; $allMatch = $false }
            } else {
                if ($null -eq $cur) { $anyMissing = $true; $allMatch = $false }
                elseif ([int64]$cur -ne [int64]$d.Expected) { $anyDrift = $true; $allMatch = $false }
            }
        }
        if ($allMatch) { $r.Status = 'Patched' } elseif ($anyMissing) { $r.Status = 'Vulnerable' } elseif ($anyDrift) { $r.Status = 'Drifted' } else { $r.Status = 'Vulnerable' }
    } catch { $r.Error = $_.Exception.Message; $r.Status = 'Error' }
    return $r
}

# --- Registry Key Apply (RegKeyApplyBlock:8438) ---
$script:WptRegApplyBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$RegPath, [object[]]$Defs, [bool]$DoReboot, [string]$Cve)
    $r = @{ Host=$Computer; Reachable=$false; Success=$false; PostValues=@{}; RebootScheduled=$false; Error='' }
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
        $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
        if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
        # DNS-mismatch guard (HARD ABORT): never write registry keys on a box that
        # isn't the one we dialed. One quick WinRM round-trip; name compare (no PTR).
        $actualName = try { Invoke-Command @splat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Reachable = $true
            $r.Error = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no registry change"
            return $r
        }
        $post = Invoke-Command @splat -ArgumentList $RegPath, $Defs -ScriptBlock {
            param($p, $defs)
            if (-not (Test-Path $p)) { New-Item -Path $p -Force -EA Stop | Out-Null }
            foreach ($d in $defs) {
                $type = if ($d.Type) { $d.Type } else { 'DWord' }
                if ($null -ne $d.OrBits) {
                    # Read the existing value as [int64] (not [int]) so a current value with the high
                    # bit set (>int32 range) doesn't overflow/throw before the OR; for in-range values
                    # the OR result and the DWORD/QWORD written are identical.
                    $cur = $null; try { $cur = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}
                    $base = if ($null -ne $cur) { [int64]$cur } else { [int64]0 }
                    Set-ItemProperty -Path $p -Name $d.Name -Value ($base -bor [int64]$d.OrBits) -Type $type -Force -EA Stop
                } else {
                    Set-ItemProperty -Path $p -Name $d.Name -Value $d.Expected -Type $type -Force -EA Stop
                }
            }
            $out = @{}
            foreach ($d in $defs) { $val = $null; try { $val = (Get-ItemProperty -Path $p -Name $d.Name -EA Stop).$($d.Name) } catch {}; $out[$d.Name] = $val }
            return $out
        }
        $r.Reachable = $true
        $r.PostValues = @{}
        foreach ($k in $post.Keys) { $r.PostValues[$k] = $post[$k] }
        $allMatch = $true
        foreach ($d in $Defs) {
            $cur = $r.PostValues[$d.Name]
            # [int64] (not [int]) so a value above int32 range doesn't overflow/throw on readback compare.
            if ($null -ne $d.OrBits) { $bits = [int64]$d.OrBits; if ($null -eq $cur -or ([int64]$cur -band $bits) -ne $bits) { $allMatch = $false; break } }
            else { if ($null -eq $cur -or [int64]$cur -ne [int64]$d.Expected) { $allMatch = $false; break } }
        }
        $r.Success = $allMatch
        if (-not $r.Success) { $r.Error = 'Post-write readback did not match expected values' }
        # Optional: notify the logged-on user and schedule a 1-hour reboot on a
        # successful apply (desktop chkRkReboot chain, 8490-8543; OFF by default).
        if ($r.Success -and $DoReboot) {
            try {
                $rebootAt = (Get-Date).AddHours(1).ToString('HH:mm')
                $body = "Your device will reboot at approximately $rebootAt to apply a security mitigation$(if($Cve){" ($Cve)"}). Please save your work."
                $cmt  = "WPT: $(if($Cve){"$Cve "})reboot scheduled. Save your work."
                $notify = Invoke-Command @splat -ArgumentList 3600, 'Scheduled Reboot Notice', $body, $cmt -ScriptBlock {
                    param($d, $t, $b, $cmt)
                    $notifyErr = ''
                    try {
                        $loggedIn = (Get-CimInstance Win32_ComputerSystem -EA Stop).UserName
                        if (-not [string]::IsNullOrWhiteSpace($loggedIn)) {
                            New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                            $tag = [guid]::NewGuid().ToString('N'); $vbsPath = "C:\Temp\WPT_RkMsg_$tag.vbs"
                            # Harden body + title (audit#22, same fold as WptMessageBlock).
                            $bRaw = ([string]$b) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                            $tRaw = ([string]$t) -replace "[\x00-\x09\x0B-\x1F]", ' '
                            if ($bRaw.Length -gt 1000) { $bRaw = $bRaw.Substring(0, 1000) }
                            if ($tRaw.Length -gt 200)  { $tRaw = $tRaw.Substring(0, 200) }
                            $bDbl = $bRaw -replace '"','""'; $tDbl = $tRaw -replace '"','""'
                            if (($bDbl -replace '""','').Contains('"')) { $bDbl = $bRaw -replace '"','' }
                            if (($tDbl -replace '""','').Contains('"')) { $tDbl = $tRaw -replace '"','' }
                            $bEsc = $bDbl -replace "\r?\n", '" & vbCrLf & "'
                            ('Set o=CreateObject("Wscript.Shell")' + "`r`n" + 'o.Popup "' + $bEsc + '", 0, "' + $tDbl + '", 64') | Out-File $vbsPath -Encoding ASCII -Force
                            $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "`"$vbsPath`""
                            $principal = New-ScheduledTaskPrincipal -UserId $loggedIn -LogonType Interactive -RunLevel Limited
                            Register-ScheduledTask -TaskName "WPT_RkMsg_$tag" -InputObject (New-ScheduledTask -Action $action -Principal $principal) -Force -EA Stop | Out-Null
                            Start-ScheduledTask -TaskName "WPT_RkMsg_$tag" -EA Stop; Start-Sleep -Seconds 3
                            Unregister-ScheduledTask -TaskName "WPT_RkMsg_$tag" -Confirm:$false -EA SilentlyContinue
                        }
                    } catch { $notifyErr = $_.Exception.Message }
                    # re-arm cleanly: abort any existing pending shutdown, then schedule a fresh one.
                    & shutdown.exe /a 2>&1 | Out-Null
                    $sdOut = (& shutdown.exe /r /t $d /c $cmt /f 2>&1)
                    $sdCode = $LASTEXITCODE
                    if ($sdCode -ne 0) { "SHUTDOWN_FAIL: exit $sdCode $sdOut" }
                    elseif ($notifyErr) { "NOTIFY_FAIL: $notifyErr" }
                    else { 'OK' }
                }
                $notify = [string]$notify
                if ($notify -like 'SHUTDOWN_FAIL*') {
                    # reg write already applied; only the reboot re-arm failed (e.g. shutdown 1190) - report it distinctly.
                    $r.RebootScheduled = $false
                    $r.Error = (@($r.Error, "reboot schedule FAILED: $($notify -replace '^SHUTDOWN_FAIL:\s*','')") | Where-Object { $_ }) -join '; '
                } else {
                    $r.RebootScheduled = $true
                    if ($notify -like 'NOTIFY_FAIL*') { $r.Error = (@($r.Error, "reboot scheduled but user-notify failed: $($notify -replace '^NOTIFY_FAIL:\s*','')") | Where-Object { $_ }) -join '; ' }
                }
            } catch { $r.Error = (@($r.Error, "reboot schedule failed: $($_.Exception.Message)") | Where-Object { $_ }) -join '; ' }
        }
    } catch { $r.Error = $_.Exception.Message }
    return $r
}

# --- App Update Verify / Apply (btnAU2Verify:10760 / btnAU2Apply:10832) ---
$script:WptAppUpdateBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [scriptblock]$Remote, [string]$Method, [string]$Arg, [bool]$IsVerify)
    $r = @{ Host=$Computer; Reachable=$false; Version=''; LastUpdated=''; Verified=$null; Status=''; Detail='' }
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
    if (-not $reachable) { $r.Status = 'Unreachable (TCP 5985/445)'; $r.Detail = 'Offline'; return $r }
    $r.Reachable = $true
    $opt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        # DNS-mismatch guard (HARD ABORT on a confirmed mismatch): a verify on the
        # wrong box returns wrong data; an apply changes the wrong box. One quick
        # WinRM round-trip; name compare (no PTR on AFNET). If the probe can't run
        # (empty), proceed as before so we don't regress reachable hosts.
        $actualName = try { Invoke-Command @splat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Status = 'DNS Mismatch'; $r.Detail = "dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no action taken"
            return $r
        }
        $res = Invoke-Command @splat -ScriptBlock $Remote -ArgumentList $Method, $Arg
        if ($IsVerify) {
            $r.Version = [string]$res.Version; $r.LastUpdated = [string]$res.LastUpdated
            $r.Verified = $res.Verified; $r.Detail = [string]$res.Detail
            $r.Status = 'Verified'
        } else {
            $r.Detail = [string]$res
            $r.Status = if ("$res" -like 'OK*') { 'OK' } elseif ("$res" -like 'SKIP*') { 'Skipped' } elseif ("$res" -like 'PARTIAL*') { 'Partial' } else { 'Failed' }
        }
    } catch { $r.Status = 'Failed'; $r.Detail = $_.Exception.Message }
    return $r
}

# Controller-side TCP reachability probe for the single-host blocks (which run
# in-process in the worker runspace) so an offline target fast-fails instead of
# waiting out New-PSSession's 15s open-timeout. (Pool-runspace fan-out workers
# carry their own inline probe since they can't see module functions.)
function Test-WptHostReachable {
    param([string]$Computer)
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { return $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}

# Cancel-aware wrapper for the single-host blocks (software-scan / scan-detail /
# software-uninstall / app-list), modeled on Invoke-JanetOnDhcpCancelable: run
# the block on a [powershell] handle in a 1-slot pool, poll the operator-cancel
# flag ~150ms, BeginStop on cancel/timeout. The handle is NULLED after BeginStop
# (Dispose right after BeginStop empirically blocks ~11s); the pool Close/Dispose
# in the finally reclaims the stopping child. The single-host blocks call
# Test-WptHostReachable, which the bare worker runspace can't see, so its
# definition is injected into the InitialSessionState.
function Invoke-WptSingleHostCancelable {
    param(
        [scriptblock]$Work,
        [object[]]$Arguments = @(),
        [scriptblock]$CancelCheck,
        [int]$TimeoutSeconds = 1800   # wall-clock backstop; the remote op timeouts are tighter
    )
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $fn  = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry('Test-WptHostReachable', ${function:Test-WptHostReachable}.ToString())
    $iss.Commands.Add($fn)
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 1, $iss, $Host)
    $pool.Open()
    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript($Work)
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $async = $ps.BeginInvoke()
    $cancelled = $false; $timedOut = $false
    $deadline = (Get-Date).AddSeconds([Math]::Max(30, $TimeoutSeconds))
    try {
        while (-not $async.IsCompleted) {
            if     ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true }
            elseif ((Get-Date) -gt $deadline)           { $timedOut  = $true }
            if ($cancelled -or $timedOut) {
                try { [void]$ps.BeginStop($null, $null) } catch {}
                $ps = $null
                break
            }
            Start-Sleep -Milliseconds 150
        }
        if ($cancelled -or $timedOut) {
            return @{ Cancelled=$cancelled; TimedOut=$timedOut; Result=$null; Error=$null }
        }
        $out = $null; $err = $null
        try { $out = $ps.EndInvoke($async) } catch {
            # EndInvoke wraps the worker's throw; unwrap so audits carry the
            # same clean message the old inline '& $block' calls produced.
            $err = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        }
        return @{ Cancelled=$false; TimedOut=$false; Result=$out; Error=$err }
    } finally {
        if ($ps) { try { $ps.Dispose() } catch {} }
        try { $pool.Close(); $pool.Dispose() } catch {}
    }
}

# EndInvoke output can be either the enumerated items or one collection object
# (the single-host blocks that return comma-wrapped arrays produce the latter);
# normalize to a flat item array so the call sites see the same shape the old
# inline '& $block' calls did. Dictionaries/strings are payloads, not wrappers.
function Expand-WptSingleHostResult {
    param($Result)
    $items = @($Result)
    if ($items.Count -eq 1 -and $items[0] -is [System.Collections.IEnumerable] -and
        $items[0] -isnot [string] -and $items[0] -isnot [System.Collections.IDictionary]) {
        return @($items[0])
    }
    return $items
}

# --- Clean User Apps (per-profile user-installed binary removal; PIRS parity) ---
# Removes user-installed app BINARIES (the program folder) from every user profile,
# preserving user data (bookmarks/history/profiles are NOT in the delete list). Kills
# the app first so files unlock. Conservative: only known binary dirs are touched, so
# a wrong path finds nothing rather than deleting user data. Does NOT mount NTUSER.DAT
# hives (too risky to do unattended).
$script:WptCleanUserAppsBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$AppsCsv, [bool]$DryRun)
    $r = @{ Host=$Computer; AppsRemoved=0; Bytes=0; FreedMB=0; Events=@(); Status='Failed'; Detail='' }
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
    if (-not $reachable) { $r.Detail = 'Offline'; return $r }
    $wsOpt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Detail = "Session: $($_.Exception.Message)"; return $r }
    try {
        $res = Invoke-Command -Session $sess -ArgumentList $AppsCsv, $DryRun, $Computer -EA Stop -ScriptBlock {
            param($appsCsv, $dry, $thisHost)
            $ev = New-Object System.Collections.Generic.List[hashtable]
            $add = { param($l, $m) [void]$ev.Add(@{ Level=$l; Msg=$m }) }
            $sel = @($appsCsv -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
            # Per-app: processes to kill + BINARY dirs to remove (relative to each profile root).
            # User-data dirs are deliberately NOT listed, so they are never deleted.
            $catalog = @{
                chrome  = @{ Procs=@('chrome','GoogleUpdate'); Dirs=@('AppData\Local\Google\Chrome\Application') }
                firefox = @{ Procs=@('firefox'); Dirs=@('AppData\Local\Mozilla Firefox') }
                zoom    = @{ Procs=@('Zoom'); Dirs=@('AppData\Roaming\Zoom\bin') }
                teams   = @{ Procs=@('Teams','msteams'); Dirs=@('AppData\Local\Microsoft\Teams\current') }
                webex   = @{ Procs=@('CiscoCollabHost','webexhost','atmgr','ptoneclk'); Dirs=@('AppData\Local\CiscoSpark','AppData\Local\WebEx','AppData\Local\Programs\Cisco Spark') }
            }
            $excl = @('Public','Default','Default User','All Users')
            $profiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin $excl }
            $totalBytes = 0; $removed = 0; $found = 0
            foreach ($app in $sel) {
                if (-not $catalog.ContainsKey($app)) { & $add 'WARN' "[$thisHost] Unknown app '$app' - skipped"; continue }
                $c = $catalog[$app]
                if (-not $dry) {
                    foreach ($pn in $c.Procs) { try { Get-Process -Name $pn -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue } catch {} }
                }
                foreach ($prof in $profiles) {
                    foreach ($rel in $c.Dirs) {
                        $path = Join-Path $prof.FullName $rel
                        if (-not (Test-Path -LiteralPath $path)) { continue }
                        $bytes = 0
                        try { foreach ($f in (Get-ChildItem -LiteralPath $path -Recurse -Force -File -EA SilentlyContinue)) { $bytes += $f.Length } } catch {}
                        $mb = [Math]::Round($bytes / 1MB, 1)
                        $totalBytes += $bytes; $found++
                        if ($dry) {
                            & $add 'DELETE' "[$thisHost]   Would remove $app for $($prof.Name): $rel ($mb MB)"
                        } else {
                            try { Remove-Item -LiteralPath $path -Recurse -Force -EA Stop; $removed++; & $add 'DELETE' "[$thisHost]   Removed $app for $($prof.Name): $rel ($mb MB)" }
                            catch { & $add 'ERR' "[$thisHost]   Failed $app for $($prof.Name): $($_.Exception.Message)" }
                        }
                    }
                }
            }
            return @{ Bytes=$totalBytes; Removed=$removed; Found=$found; Events=$ev.ToArray() }
        }
        $r.Bytes = $res.Bytes; $r.FreedMB = [Math]::Round($res.Bytes / 1MB, 1)
        $r.AppsRemoved = if ($DryRun) { [int]$res.Found } else { [int]$res.Removed }
        $r.Events = @($res.Events)
        $r.Status = if ($DryRun) { 'Dry Run OK' } else { 'Success' }
        $r.Detail = if ($DryRun) { "$([int]$res.Found) binary path(s) would be removed, $($r.FreedMB) MB" } else { "$([int]$res.Removed) binary path(s) removed, $($r.FreedMB) MB" }
    } catch { $r.Detail = $_.Exception.Message }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# --- Maintenance Lock (logon banner + optional hard-lock via secedit) ---
# Mirrors the desktop PIRS Lockout: sets the legalnotice banner, and (hard lock)
# restricts SeInteractiveLogonRight to local Administrators so standard users
# can't sign in during a patch window. The ORIGINAL right is backed up under
# HKLM\SOFTWARE\JANET\Lockout so Unlock restores exactly what was there. Admins
# are always retained (they ARE the granted group), so this can't lock you out.
$script:WptMaintLockBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$Caption, [string]$Message, [bool]$HardLock)
    $r = @{ Host=$Computer; Success=$false; Mode=''; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        # DNS-mismatch guard (HARD ABORT): a maintenance hard-lock restricts interactive
        # logon on the box that answers; verify it's the one we dialed before touching it
        # (stale DNS / reused IP could lock out the WRONG machine). One quick WinRM probe,
        # copied from WptRebootBlock (~1665) / WptPatchBlock (~1606). An IPv4-literal target
        # has no shortname to compare -> skip. Empty probe -> proceed (don't regress).
        if ($Computer -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            $targetShort = ($Computer -split '\.')[0]
            $probeSplat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
            if ($Cred) { $probeSplat['Credential']=$Cred; $probeSplat['Authentication']=$Auth }
            $actualName = try { Invoke-Command @probeSplat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
            if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
                $r.Mode = 'Failed'
                $r.Detail = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no maintenance lock applied"
                return $r
            }
        }
        $out = Invoke-Command @splat -ArgumentList $Caption, $Message, $HardLock -ScriptBlock {
            param($caption, $message, $hardlock)
            $res = @{ Banner=$false; HardLock=$false; Err='' }
            $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            try {
                if (-not (Test-Path $sysPol)) { New-Item -Path $sysPol -Force -EA Stop | Out-Null }
                Set-ItemProperty -Path $sysPol -Name legalnoticecaption -Value $caption -Force -EA Stop
                Set-ItemProperty -Path $sysPol -Name legalnoticetext -Value $message -Force -EA Stop
                $res.Banner = $true
            } catch { $res.Err = "banner: $($_.Exception.Message)" }
            if ($hardlock) {
                try {
                    $tmp = Join-Path $env:windir 'Temp'
                    $exp = Join-Path $tmp 'janet_sec_export.inf'
                    $cfg = Join-Path $tmp 'janet_sec_lock.inf'
                    $db  = Join-Path $tmp 'janet_sec_lock.sdb'
                    Remove-Item $exp, $cfg, $db -Force -EA SilentlyContinue
                    & secedit /export /areas USER_RIGHTS /cfg "$exp" /quiet 2>&1 | Out-Null
                    $orig = ''
                    if (Test-Path $exp) {
                        $line = (Get-Content $exp -EA SilentlyContinue | Where-Object { $_ -match '^\s*SeInteractiveLogonRight\s*=' } | Select-Object -First 1)
                        if ($line) { $orig = ($line -split '=', 2)[1].Trim() }
                    }
                    $bkKey = 'HKLM:\SOFTWARE\JANET\Lockout'
                    if (-not (Test-Path $bkKey)) { New-Item -Path $bkKey -Force -EA Stop | Out-Null }
                    # Don't clobber a prior backup if Lock is run twice (keep the TRUE original).
                    $existing = (Get-ItemProperty -Path $bkKey -Name OrigSeInteractiveLogonRight -EA SilentlyContinue).OrigSeInteractiveLogonRight
                    if ([string]::IsNullOrEmpty($existing)) { Set-ItemProperty -Path $bkKey -Name OrigSeInteractiveLogonRight -Value $orig -Force }
                    Set-ItemProperty -Path $bkKey -Name LockedAt -Value (Get-Date -Format 's') -Force
                    $infText = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544
'@
                    Set-Content -Path $cfg -Value $infText -Encoding Unicode -Force
                    & secedit /configure /db "$db" /cfg "$cfg" /areas USER_RIGHTS /quiet 2>&1 | Out-Null
                    $cfgRc = $LASTEXITCODE
                    # VERIFY (fail-closed): secedit's exit code is no longer discarded, and
                    # we RE-READ the effective SeInteractiveLogonRight and confirm it is the
                    # intended locked state (Administrators only). HardLock is reported ONLY
                    # when BOTH hold; otherwise a no-op secedit would falsely read "LOCKED".
                    $vrf = Join-Path $tmp 'janet_sec_verify.inf'
                    Remove-Item $vrf -Force -EA SilentlyContinue
                    & secedit /export /areas USER_RIGHTS /cfg "$vrf" /quiet 2>&1 | Out-Null
                    $eff = ''
                    if (Test-Path $vrf) {
                        $vline = (Get-Content $vrf -EA SilentlyContinue | Where-Object { $_ -match '^\s*SeInteractiveLogonRight\s*=' } | Select-Object -First 1)
                        if ($vline) { $eff = ($vline -split '=', 2)[1].Trim() }
                    }
                    $normEff  = (($eff -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ','
                    $normWant = 'S-1-5-32-544' # normalized (leading '*' stripped below)
                    $normEff  = ($normEff -replace '\*','')
                    Remove-Item $exp, $cfg, $db, $vrf -Force -EA SilentlyContinue
                    if ($cfgRc -eq 0 -and $normEff -eq $normWant) {
                        $res.HardLock = $true
                    } else {
                        $res.HardLock = $false
                        $res.Err = ("$($res.Err) | hardlock NOT verified (secedit exit=$cfgRc; effective SeInteractiveLogonRight='$eff'; users may NOT be locked)").Trim(' |')
                    }
                } catch { $res.Err = ("$($res.Err) | hardlock: $($_.Exception.Message)").Trim(' |') }
            }
            return $res
        }
        # Success reflects the PRIMARY intent: when a hard-lock was requested, a
        # successful lock IS success (even if the banner write failed) - so the host
        # never reads "Success=false" while actually being locked.
        $bannerOk = [bool]$out.Banner
        if ($HardLock) {
            $r.Success = [bool]$out.HardLock
            if ($out.HardLock) {
                $r.Mode = 'Hard lock'
                $r.Detail = if ($bannerOk) { 'Banner set; interactive logon restricted to Administrators' } else { 'HOST LOCKED (logon restricted to Administrators) - WARNING: banner write failed' }
            } else {
                $r.Mode = 'Failed'; $r.Detail = "Hard-lock NOT verified (host may NOT be locked): $($out.Err)"
            }
        } else {
            $r.Success = $bannerOk
            $r.Mode = if ($bannerOk) { 'Banner' } else { 'Failed' }
            $r.Detail = if ($bannerOk) { 'Maintenance banner set (logon not blocked)' } else { "banner failed: $($out.Err)" }
        }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Maintenance Unlock (clear banner + restore logon right from backup) ---
$script:WptMaintUnlockBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Success=$false; Detail='' }
    $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        $out = Invoke-Command @splat -ScriptBlock {
            $res = @{ Banner=$false; Restored=$false; Source=''; Err='' }
            $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            try {
                Set-ItemProperty -Path $sysPol -Name legalnoticecaption -Value '' -Force -EA SilentlyContinue
                Set-ItemProperty -Path $sysPol -Name legalnoticetext -Value '' -Force -EA SilentlyContinue
                $res.Banner = $true
            } catch { $res.Err = "banner: $($_.Exception.Message)" }
            $bkKey = 'HKLM:\SOFTWARE\JANET\Lockout'
            $orig = ''
            $lockedAt = ''
            if (Test-Path $bkKey) {
                $orig = (Get-ItemProperty -Path $bkKey -Name OrigSeInteractiveLogonRight -EA SilentlyContinue).OrigSeInteractiveLogonRight
                $lockedAt = (Get-ItemProperty -Path $bkKey -Name LockedAt -EA SilentlyContinue).LockedAt
            }
            # Only rewrite logon rights if we have evidence WE hard-locked this host
            # (a LockedAt marker or a saved original). Otherwise leave rights untouched
            # (it was a banner-only lock - don't gratuitously rewrite security policy).
            if ($lockedAt -or -not [string]::IsNullOrWhiteSpace($orig)) {
                if ([string]::IsNullOrWhiteSpace($orig)) { $orig = '*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551'; $res.Source = 'default' } else { $res.Source = 'backup' }
                try {
                    $tmp = Join-Path $env:windir 'Temp'
                    $cfg = Join-Path $tmp 'janet_sec_unlock.inf'
                    $db  = Join-Path $tmp 'janet_sec_unlock.sdb'
                    Remove-Item $cfg, $db -Force -EA SilentlyContinue
                    $infText = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeInteractiveLogonRight = $orig
"@
                    Set-Content -Path $cfg -Value $infText -Encoding Unicode -Force
                    & secedit /configure /db "$db" /cfg "$cfg" /areas USER_RIGHTS /quiet 2>&1 | Out-Null
                    $cfgRc = $LASTEXITCODE
                    # VERIFY (fail-closed): a failed unlock must NOT read "restored" while
                    # standard users stay locked out. Check secedit's exit code AND re-read
                    # the effective SeInteractiveLogonRight, confirming it now matches the
                    # intended restored state ($orig). Only then report Restored, and only
                    # then clear the backup markers (so a failed restore can be retried).
                    $vrf = Join-Path $tmp 'janet_sec_unlock_verify.inf'
                    Remove-Item $vrf -Force -EA SilentlyContinue
                    & secedit /export /areas USER_RIGHTS /cfg "$vrf" /quiet 2>&1 | Out-Null
                    $eff = ''
                    if (Test-Path $vrf) {
                        $vline = (Get-Content $vrf -EA SilentlyContinue | Where-Object { $_ -match '^\s*SeInteractiveLogonRight\s*=' } | Select-Object -First 1)
                        if ($vline) { $eff = ($vline -split '=', 2)[1].Trim() }
                    }
                    $normEff  = ((($eff  -split ',') | ForEach-Object { ($_ -replace '\*','').Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                    $normWant = ((($orig -split ',') | ForEach-Object { ($_ -replace '\*','').Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                    Remove-Item $cfg, $db, $vrf -Force -EA SilentlyContinue
                    if ($cfgRc -eq 0 -and $normEff -eq $normWant) {
                        Remove-ItemProperty -Path $bkKey -Name OrigSeInteractiveLogonRight -EA SilentlyContinue
                        Remove-ItemProperty -Path $bkKey -Name LockedAt -EA SilentlyContinue
                        $res.Restored = $true
                    } else {
                        $res.Restored = $false
                        $res.Err = ("$($res.Err) | restore NOT verified -- users may still be locked out (secedit exit=$cfgRc; effective SeInteractiveLogonRight='$eff')").Trim(' |')
                    }
                } catch { $res.Err = ("$($res.Err) | restore: $($_.Exception.Message)").Trim(' |') }
            } else {
                $res.Restored = $true; $res.Source = 'banner-only'
            }
            return $res
        }
        $r.Success = ([bool]$out.Banner -and [bool]$out.Restored)
        $bits = New-Object System.Collections.Generic.List[string]
        if ($out.Banner) { [void]$bits.Add('banner cleared') }
        if ($out.Restored) {
            if ($out.Source -eq 'banner-only') { [void]$bits.Add('no hard-lock backup (banner-only)') }
            elseif ($out.Source -eq 'default') { [void]$bits.Add('logon restored to Windows default (no backup found)') }
            else { [void]$bits.Add('logon restored from backup') }
        }
        if ($out.Err) { [void]$bits.Add("warn: $($out.Err)") }
        $r.Detail = ($bits -join '; ')
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Available Deployments (single-host unified MECM available list) ---
$script:WptSccmAvailableBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    $opt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $rows = Invoke-Command @splat -ScriptBlock {
        $out = New-Object System.Collections.ArrayList
        if (-not (Get-CimClass -Namespace ROOT\ccm\ClientSDK -ClassName CCM_Application -EA SilentlyContinue)) {
            return ,@(@{ Type='(info)'; Name='MECM client SDK not present on this host (ROOT\ccm\ClientSDK missing)'; State=''; Version=''; Id=''; Revision='' })
        }
        try {
            foreach ($a in @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop)) {
                if ($a.ApplicabilityState -ne 'Applicable') { continue }
                [void]$out.Add(@{ Type='App'; Name=[string]$a.Name; State=[string]$a.InstallState; Version=[string]$a.SoftwareVersion; Id=[string]$a.Id; Revision=[string]$a.Revision })
            }
        } catch {}
        try {
            foreach ($u in @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_SoftwareUpdate -EA Stop)) {
                if ([int]$u.ComplianceState -ne 0) { continue }   # 0 = required/missing (pending)
                [void]$out.Add(@{ Type='Update'; Name=[string]$u.Name; State='Pending'; Version=[string]$u.ArticleID; Id=[string]$u.UpdateID; Revision='' })
            }
        } catch {}
        return ,@($out.ToArray())
    }
    return ,@($rows)
}

# --- Install Available (single-host deploy: apps + updates routed by type) ---
$script:WptSccmInstallBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$ItemsText)
    if (-not (Test-WptHostReachable $Computer)) { return ,@(@{ Type=''; Name=$Computer; Result='Failed'; Detail='unreachable (TCP 5985/445)' }) }
    $opt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        # DNS-mismatch guard (HARD ABORT): never deploy to a box that isn't the one
        # we dialed. Name compare (no PTR on AFNET); if the probe can't run, proceed.
        $actualName = try { Invoke-Command @splat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            return ,@(@{ Type=''; Name=$Computer; Result='Failed'; Detail="DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no action taken" })
        }
        $res = Invoke-Command @splat -ArgumentList $ItemsText -ScriptBlock {
            param($itemsText)
            $items = @()
            foreach ($ln in ($itemsText -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                $p = $ln -split '\|', 4
                $items += [pscustomobject]@{ Type=$p[0].Trim(); Id=$(if ($p.Count -gt 1) { $p[1].Trim() } else { '' }); Revision=$(if ($p.Count -gt 2) { $p[2].Trim() } else { '' }); Name=$(if ($p.Count -gt 3) { $p[3] } else { $p[1] }) }
            }
            $out = New-Object System.Collections.ArrayList
            foreach ($it in ($items | Where-Object { $_.Type -eq 'App' })) {
                try {
                    $app = @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop | Where-Object { $_.Id -eq $it.Id }) | Select-Object -First 1
                    if (-not $app) { [void]$out.Add(@{ Type='App'; Name=$it.Name; Result='Skipped'; Detail='not in catalog' }); continue }
                    if ($app.ApplicabilityState -ne 'Applicable') { [void]$out.Add(@{ Type='App'; Name=$it.Name; Result='Skipped'; Detail="not applicable ($($app.ApplicabilityState))" }); continue }
                    $iargs = @{ EnforcePreference=[uint32]0; Id="$($app.Id)"; IsMachineTarget=[System.Convert]::ToBoolean($app.IsMachineTarget); IsRebootIfNeeded=$false; Priority='High'; Revision="$($app.Revision)" }
                    Invoke-CimMethod -Namespace ROOT\ccm\ClientSDK -ClassName CCM_Application -MethodName Install -Arguments $iargs -EA Stop | Out-Null
                    [void]$out.Add(@{ Type='App'; Name=$it.Name; Result='Triggered'; Detail="Install (v$($app.SoftwareVersion))" })
                } catch { [void]$out.Add(@{ Type='App'; Name=$it.Name; Result='Failed'; Detail=$_.Exception.Message }) }
            }
            $upIds = @(($items | Where-Object { $_.Type -eq 'Update' }) | ForEach-Object { $_.Id })
            if ($upIds.Count -gt 0) {
                try {
                    $allUp = @(Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_SoftwareUpdate -EA Stop | Where-Object { $upIds -contains $_.UpdateID })
                    if ($allUp.Count -gt 0) {
                        Invoke-CimMethod -Namespace ROOT\ccm\ClientSDK -ClassName CCM_SoftwareUpdatesManager -MethodName InstallUpdates -Arguments @{ CCMUpdates=[ciminstance[]]$allUp } -EA Stop | Out-Null
                        foreach ($u in $allUp) { [void]$out.Add(@{ Type='Update'; Name=[string]$u.Name; Result='Triggered'; Detail='InstallUpdates' }) }
                    } else { [void]$out.Add(@{ Type='Update'; Name="$($upIds.Count) update(s)"; Result='Skipped'; Detail='none matched in CCM_SoftwareUpdate' }) }
                } catch { [void]$out.Add(@{ Type='Update'; Name="$($upIds.Count) update(s)"; Result='Failed'; Detail=$_.Exception.Message }) }
            }
            if ($out.Count -eq 0) { [void]$out.Add(@{ Type=''; Name='(nothing)'; Result='Skipped'; Detail='no valid items parsed' }) }
            return ,@($out.ToArray())
        }
        return ,@($res)
    } catch { return ,@(@{ Type=''; Name=$Computer; Result='Failed'; Detail="Session: $($_.Exception.Message)" }) }
}

# --- Host Info (single-host snapshot; PIRS "Get Info" parity, over WinRM) ---
$script:WptHostInfoBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    $opt = New-PSSessionOption -OperationTimeout 120000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $info = Invoke-Command @splat -ScriptBlock {
        $cs   = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
        $os   = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA SilentlyContinue
        $dv = ''
        try { $dv = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA Stop).DisplayVersion } catch {}
        $ips = @(); $macs = @()
        foreach ($n in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -EA SilentlyContinue)) {
            foreach ($ip in @($n.IPAddress)) { if ($ip -and $ip -notmatch ':') { $ips += $ip } }   # IPv4 only
            if ($n.MACAddress) { $macs += $n.MACAddress }
        }
        $recent = ''
        try {
            $excl = @('Public','Default','Default User','All Users')
            $ups = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin $excl } | Sort-Object LastWriteTime -Descending | Select-Object -First 3
            if ($ups) { $recent = (($ups | ForEach-Object { $_.Name }) -join ', ') }
        } catch {}
        $cbs  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wuau = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $sccm = $false
        try { $ccm = Invoke-WmiMethod -Namespace ROOT\ccm\ClientSDK -Class CCM_ClientUtilities -Name DetermineIfRebootPending -EA Stop; $sccm = ($ccm.IsHardRebootPending -or $ccm.RebootPending) } catch {}
        $up = ''
        if ($os -and $os.LastBootUpTime) {
            $span = (Get-Date) - $os.LastBootUpTime
            $up = "$([int]$span.TotalDays)d $($span.Hours)h $($span.Minutes)m (since $($os.LastBootUpTime.ToString('g')))"
            # Heuristic flag (PIRS parity 1919-1921): uptime > 5 days -> nudge a reboot.
            if ($span.TotalDays -gt 5) { $up += ' (REBOOT RECOMMENDED)' }
        }
        $ramStr = ''
        if ($os -and $os.TotalVisibleMemorySize) {
            $totGB = [Math]::Round($os.TotalVisibleMemorySize/1MB,1); $freeGB = [Math]::Round($os.FreePhysicalMemory/1MB,1)
            $usedPct = if ($os.TotalVisibleMemorySize -gt 0) { [Math]::Round((($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100) } else { 0 }
            $ramStr = "$usedPct% used ($freeGB GB free / $totGB GB)"
        }
        $diskStr = ''
        if ($disk -and $disk.Size) {
            $diskStr = "$([Math]::Round($disk.FreeSpace/1GB,1)) GB free / $([Math]::Round($disk.Size/1GB,1)) GB"
            # Heuristic flag (PIRS parity 1887-1890): C: free < 30 GB -> LOW SPACE.
            if (($disk.FreeSpace/1GB) -lt 30) { $diskStr += ' (LOW SPACE)' }
        }
        # --- Session state via quser (PIRS parity 1847-1874), run ON the target. ---
        # Translate the console/logged-on user's quser line into an Active /
        # Disconnected / Idle <n>m [- AWAY] label. Tolerates mm, hh:mm and d+hh:mm
        # idle formats plus empty / "No User exists" output.
        $sessionState = ''
        try {
            $loginShort = ''
            if ($cs -and $cs.UserName) { $loginShort = (([string]$cs.UserName) -split '\\')[-1] }
            $qu = @(& quser.exe 2>&1 | ForEach-Object { [string]$_ })
            if ($qu.Count -gt 0 -and (($qu -join ' ') -notmatch 'No User exists')) {
                $chosen = $null; $fallback = $null
                foreach ($line in $qu) {
                    if ($line -match '^\s*USERNAME') { continue }
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    if (-not $fallback) { $fallback = $line }
                    $tok = ((($line -replace '^\s*>','').Trim()) -split '\s+')[0]
                    if ($line -match '^\s*>') { $chosen = $line; break }
                    if ($loginShort -and $tok -and ($tok -eq $loginShort)) { $chosen = $line }
                }
                if (-not $chosen) { $chosen = $fallback }
                if ($chosen) {
                    $toMin = {
                        param($s)
                        $v = ([string]$s).Trim()
                        if ($v -eq '' -or $v -eq '.' -or $v -match '(?i)none') { return 0 }
                        if ($v -match '^\d+$') { return [int]$v }
                        if ($v -match '^(\d+)\+(\d+):(\d+)$') { return (([int]$matches[1])*1440 + ([int]$matches[2])*60 + [int]$matches[3]) }
                        if ($v -match '^(\d+):(\d+)$') { return (([int]$matches[1])*60 + [int]$matches[2]) }
                        return 0
                    }
                    if ($chosen -match '(?i)\bDisc\b') {
                        $sessionState = 'Disconnected'
                    } else {
                        $idleRaw = ''
                        if ($chosen -match '(?i)\bActive\b\s+([\d\.\+:]+|none)') { $idleRaw = $matches[1] }
                        $idleMin = & $toMin $idleRaw
                        if ($idleMin -le 0) { $sessionState = 'Active' }
                        elseif ($idleMin -ge 15) { $sessionState = "Idle ${idleMin}m - AWAY" }
                        else { $sessionState = "Idle ${idleMin}m" }
                    }
                }
            }
        } catch {}
        [pscustomobject]@{
            ComputerName  = $env:COMPUTERNAME
            Model         = if ($cs) { "$($cs.Manufacturer) $($cs.Model)".Trim() } else { '' }
            Serial        = if ($bios) { [string]$bios.SerialNumber } else { '' }
            BIOS          = if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { '' }
            OS            = if ($os) { ("$($os.Caption)" + $(if ($dv) { " (Version $dv)" } else { '' }) + " build $($os.BuildNumber)") } else { '' }
            Uptime        = $up
            RAM           = $ramStr
            CDrive        = $diskStr
            IPv4          = ($ips -join ', ')
            MAC           = ($macs -join ', ')
            LoggedOnUser  = if ($cs -and $cs.UserName) { [string]$cs.UserName } else { '' }
            SessionState  = $sessionState
            RecentUsers   = $recent
            RebootPending = ($cbs -or $wuau -or $sccm)
        }
    }
    $kv = [ordered]@{
        'Computer name'    = $info.ComputerName
        'Model'            = $info.Model
        'Serial number'    = $info.Serial
        'BIOS version'     = $info.BIOS
        'Operating system' = $info.OS
        'Uptime'           = $info.Uptime
        'RAM usage'        = $info.RAM
        'C: free'          = $info.CDrive
        'IPv4 address(es)' = $info.IPv4
        'MAC address(es)'  = $info.MAC
        'Logged-on user'   = $(if ($info.LoggedOnUser) { if ($info.SessionState) { "$($info.LoggedOnUser) ($($info.SessionState))" } else { [string]$info.LoggedOnUser } } else { '(none)' })
        'Recent users'     = $info.RecentUsers
        'Pending reboot'   = $(if ($info.RebootPending) { 'YES' } else { 'No' })
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($k in $kv.Keys) { [void]$rows.Add(@{ Property=$k; Value=[string]$kv[$k] }) }
    return ,@($rows.ToArray())
}

# --- Event Log error scan (single-host; PIRS error-log parity, over WinRM) ---
$script:WptEventLogBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$LogsCsv, [int]$Hours)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    if ($Hours -le 0) { $Hours = 12 }
    $opt = New-PSSessionOption -OperationTimeout 120000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $rows = Invoke-Command @splat -ArgumentList $LogsCsv, $Hours -ScriptBlock {
        param($logsCsv, $hours)
        $logs = @($logsCsv -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($logs.Count -eq 0) { $logs = @('Application','System') }
        $start = (Get-Date).AddHours(-[Math]::Abs($hours))
        $out = New-Object System.Collections.ArrayList
        foreach ($ln in $logs) {
            try {
                $evts = Get-WinEvent -FilterHashtable @{ LogName=$ln; Level=1,2; StartTime=$start } -ErrorAction Stop |
                        Where-Object { $_.ProviderName -ne 'Schannel' } | Select-Object -First 15
                if ($evts) {
                    foreach ($e in $evts) {
                        $msg = ''
                        if ($e.Message) { $msg = ($e.Message -split "`r?`n")[0] }
                        [void]$out.Add(@{ Log=$ln; TimeCreated=$(if ($e.TimeCreated) { $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }); EventId=[string]$e.Id; Provider=[string]$e.ProviderName; Message=$msg })
                    }
                } else {
                    [void]$out.Add(@{ Log=$ln; TimeCreated=''; EventId=''; Provider=''; Message="(no Error/Critical events in the last $hours h)" })
                }
            } catch {
                $em = $_.Exception.Message
                if ($em -match 'No events were found') { [void]$out.Add(@{ Log=$ln; TimeCreated=''; EventId=''; Provider=''; Message="(no Error/Critical events in the last $hours h)" }) }
                else { [void]$out.Add(@{ Log=$ln; TimeCreated=''; EventId=''; Provider='ERROR'; Message="query failed: $em" }) }
            }
        }
        return ,@($out.ToArray())
    }
    return ,@($rows)
}

# --- Software Scan (single-host; Populate-SwGrid remote block:6921) ---
$script:WptSoftwareScanBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    $opt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    return Invoke-Command @splat -ScriptBlock {
        $allApps = @()
        $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
        foreach ($rp in $regPaths) {
            Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } | ForEach-Object {
                $type = if ($_.UninstallString -match 'msiexec') { 'MSI' } else { 'EXE' }
                $sizeKB = if ($_.EstimatedSize) { "$([Math]::Round($_.EstimatedSize / 1024, 1)) MB" } else { '' }
                $allApps += @{ Name=$_.DisplayName; Version=$_.DisplayVersion; Publisher=$_.Publisher; InstallDate=$_.InstallDate; Type=$type; Size=$sizeKB; UninstallString=[string]$_.UninstallString; PSChildName=[string]$_.PSChildName }
            }
        }
        # try/catch: a missing Appx module throws CommandNotFoundException, which
        # -EA SilentlyContinue cannot suppress - degrade to Win32/MSI-only instead of
        # failing the whole scan.
        try {
            Get-AppxPackage -AllUsers -EA SilentlyContinue | ForEach-Object {
                $allApps += @{ Name=$_.Name; Version=$_.Version; Publisher=$_.Publisher; InstallDate=''; Type='Store'; Size=''; UninstallString=''; PSChildName='' }
            }
        } catch {}
        # MSXML KB-package detection (desktop 6935-6968). MSXML 4 SP3 servicing
        # hotfixes live under HKLM:\SOFTWARE\Microsoft\Updates\*MSXML*\KB* and never
        # appear in the regular Uninstall hive; surface them as Type='KB' with the KB
        # number stuffed into the Name so the uninstall worker can wusa /uninstall it.
        try {
            $msxmlParents = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Updates' -EA SilentlyContinue | Where-Object {
                $_.PSChildName -like '*MSXML*' -or $_.PSChildName -like '*XML Core Services*' -or $_.PSChildName -like '*XML Parser*' })
            foreach ($parent in $msxmlParents) {
                Get-ChildItem -LiteralPath $parent.PSPath -EA SilentlyContinue | Where-Object { $_.PSChildName -like 'KB*' } | ForEach-Object {
                    $kbProp = Get-ItemProperty -LiteralPath $_.PSPath -EA SilentlyContinue
                    $kbName = if ($kbProp.PackageName) { "$([string]$kbProp.PackageName) ($($_.PSChildName))" } else { "$($parent.PSChildName) ($($_.PSChildName))" }
                    $allApps += @{ Name=$kbName; Version=''; Publisher='Microsoft Corporation'; InstallDate=$(if($kbProp.InstalledDate){[string]$kbProp.InstalledDate}else{''}); Type='KB'; Size=''; UninstallString=$_.PSChildName; PSChildName=$_.PSChildName }
                }
            }
        } catch {}
        # Orphan MSXML DLL detection (desktop 6970-7006). Tenable 62758 scans the
        # filesystem, so msxml*.dll left by partial removals get flagged with no
        # Add/Remove entry. msxml6*.dll is OS-bundled -> Type='DLL (OS-protected)'
        # so the operator SEES it but the uninstall worker refuses to touch it.
        foreach ($dir in @('C:\Windows\System32','C:\Windows\SysWOW64')) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            try { $msxmlDlls = @(Get-ChildItem -LiteralPath $dir -Filter 'msxml*.dll' -File -Force -EA SilentlyContinue) } catch { continue }
            foreach ($d in $msxmlDlls) {
                $dllType = if ($d.Name -match '^msxml6[a-z]?\.dll$') { 'DLL (OS-protected)' } else { 'DLL' }
                $ver = ''; try { $ver = [string]$d.VersionInfo.FileVersion } catch {}
                $bitness = if ($dir -like '*SysWOW64*') { '32-bit' } else { '64-bit' }
                $allApps += @{ Name="$($d.Name) [$bitness] - $($d.FullName)"; Version=$ver; Publisher='Microsoft Corporation'; InstallDate=$d.LastWriteTime.ToString('yyyy-MM-dd'); Type=$dllType; Size="$([Math]::Round($d.Length / 1KB, 0)) KB"; UninstallString=$d.FullName; PSChildName=$d.Name }
            }
        }
        return $allApps
    }
}

# --- Software Uninstall (generic dispatch, mirrors WPT 7178-7185) -------------
#  Single host, list of display names or {MSI GUID}s. Re-enumerates installed
#  products on the remote box and uninstalls each match by type:
#    MSI   -> msiexec /x {GUID} /qn /norestart   (exit 0 or 3010 = OK)
#    EXE   -> QuietUninstallString, else UninstallString head + silent switches
#    Store -> Get-AppxPackage -AllUsers | Remove-AppxPackage -AllUsers
#  Tanium leaves a stale WOW6432Node key behind; clean it on success.
$script:WptSoftwareUninstallBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string[]]$AppNames)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    $opt = New-PSSessionOption -OperationTimeout 600000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    # DNS-mismatch guard (HARD ABORT): never uninstall on a box that isn't the one
    # we dialed. Name compare (no PTR on AFNET); if the probe can't run, proceed.
    $actualName = try { Invoke-Command @splat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
    $targetShort = ($Computer -split '\.')[0]
    if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
        return ,@(@{ App=$Computer; Type=''; Result='Failed'; Detail="DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no action taken" })
    }
    return Invoke-Command @splat -ArgumentList (,$AppNames) -ScriptBlock {
        param([string[]]$Names)
        $results = New-Object System.Collections.ArrayList
        $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
        $installed = @()
        foreach ($rp in $regPaths) {
            Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } | ForEach-Object {
                $installed += [pscustomobject]@{ Name=[string]$_.DisplayName; UninstallString=[string]$_.UninstallString; QuietUninstallString=[string]$_.QuietUninstallString; PSChildName=[string]$_.PSChildName }
            }
        }
        foreach ($raw in $Names) {
            $name = ([string]$raw).Trim()
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $type = ''; $result = 'Failed'; $detail = ''
            try {
                # --- Special-case handlers (mirror desktop 7061-7177). The web worker
                #     only receives names, so each branch re-detects from the scan-
                #     formatted display name (the scan embeds the KB number / DLL path).
                #     They run BEFORE the generic MSI/EXE/Store path. ---
                # OS-protected MSXML 6 DLL: refuse (SFC restores it; deleting bricks COM).
                if ($name -match '(?i)\bmsxml6[a-z0-9]?\.dll\b') {
                    [void]$results.Add(@{ App=$name; Type='DLL (OS-protected)'; Result='Skipped'; Detail="$name is an OS-bundled Windows component (SFC restores it; removing it breaks XML/COM apps). For Tenable 62758 against OS-bundled MSXML 6, upgrade Windows -- do not remove the DLL." }); continue
                }
                # Orphan MSXML DLL: scan name is "<file> [<bitness>] - <fullpath>".
                if ($name -match '(?i)^(msxml[0-9a-z]*\.dll)\s*\[[^\]]*\]\s*-\s*(.+)$') {
                    $type = 'DLL'; $dllPath = $Matches[2].Trim()
                    if ([string]::IsNullOrWhiteSpace($dllPath) -or -not (Test-Path -LiteralPath $dllPath)) {
                        [void]$results.Add(@{ App=$name; Type=$type; Result='Failed'; Detail="DLL path not present ($dllPath)" }); continue
                    }
                    $steps = @()
                    foreach ($s in @('MSExchangeTransport','W3SVC','wuauserv','BITS','wmiApSrv')) { $svc = Get-Service -Name $s -EA SilentlyContinue; if ($svc -and $svc.Status -eq 'Running') { try { Stop-Service -Name $s -Force -EA SilentlyContinue; $steps += "stopped $s" } catch {} } }
                    $regsvr = if ($dllPath -like '*\SysWOW64\*') { 'C:\Windows\SysWOW64\regsvr32.exe' } else { 'C:\Windows\System32\regsvr32.exe' }
                    try { $rp = Start-Process -FilePath $regsvr -ArgumentList "/u /s `"$dllPath`"" -Wait -PassThru -WindowStyle Hidden -EA SilentlyContinue; $steps += "regsvr32 /u exit=$($rp.ExitCode)" } catch { $steps += 'regsvr32 threw' }
                    try { $to = Start-Process -FilePath 'takeown.exe' -ArgumentList "/f `"$dllPath`"" -Wait -PassThru -WindowStyle Hidden -EA SilentlyContinue; $steps += "takeown exit=$($to.ExitCode)"; $ic = Start-Process -FilePath 'icacls.exe' -ArgumentList "`"$dllPath`" /grant Administrators:F /C" -Wait -PassThru -WindowStyle Hidden -EA SilentlyContinue; $steps += "icacls exit=$($ic.ExitCode)" } catch { $steps += 'ACL adjust threw' }
                    try { Remove-Item -LiteralPath $dllPath -Force -EA Stop; $result='Removed'; $detail="DLL removed: $dllPath | $($steps -join ' | ')" }
                    catch { $detail = "DLL delete blocked: $($_.Exception.Message) | $($steps -join ' | ')" }
                    [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail }); continue
                }
                # MSXML servicing KB: scan name carries "(KBxxxx)".
                if ($name -match '(?i)(MSXML|XML Core Services|XML Parser)' -and $name -match 'KB(\d{4,})') {
                    $type = 'KB'; $kb = $Matches[1]
                    $proc = Start-Process -FilePath 'wusa.exe' -ArgumentList "/uninstall /kb:$kb /quiet /norestart" -Wait -PassThru -WindowStyle Hidden
                    switch ($proc.ExitCode) {
                        0       { $result='Removed'; $detail="wusa /uninstall /kb:$kb succeeded" }
                        3010    { $result='Removed'; $detail="wusa /uninstall /kb:$kb succeeded (reboot required)" }
                        2359303 { $result='Removed'; $detail="KB$kb was not actually installed -- nothing to remove" }
                        default { $detail="wusa /uninstall /kb:$kb exit $($proc.ExitCode)" }
                    }
                    [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail }); continue
                }
                # Microsoft 365 / Office: built-in removal (the desktop's site-specific
                # package-share precopy is dropped; setup.exe /configure -> C2R -> the
                # registered uninstall string cover it).
                if ($name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                    $type = 'EXE'; $steps = @(); $done = $false; $c2rPath = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun'
                    $setupExe = Join-Path $c2rPath 'setup.exe'
                    if (Test-Path $setupExe) {
                        try {
                            New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                            $xmlPath = 'C:\Temp\OfficeRemoveAll.xml'
                            '<Configuration><Remove All="TRUE"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' | Out-File $xmlPath -Encoding ASCII -Force
                            $p = Start-Process $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -PassThru -WindowStyle Hidden
                            Remove-Item $xmlPath -Force -EA SilentlyContinue; $steps += "setup.exe /configure exit $($p.ExitCode)"
                            if ($p.ExitCode -eq 0) { $result='Removed'; $detail="Office removed via setup.exe /configure | $($steps -join ' | ')"; $done=$true }
                        } catch { $steps += "setup.exe threw: $($_.Exception.Message)" }
                    }
                    if (-not $done) {
                        $c2rExe = Join-Path $c2rPath 'OfficeClickToRun.exe'
                        if (Test-Path $c2rExe) {
                            $c2rReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -EA SilentlyContinue
                            $prodIds = @(); if ($c2rReg.ProductReleaseIds) { $prodIds = @($c2rReg.ProductReleaseIds -split ',') }; if ($prodIds.Count -eq 0) { $prodIds = @('O365ProPlusRetail') }
                            $culture = if ($c2rReg.ClientCulture) { $c2rReg.ClientCulture } else { 'en-us' }
                            foreach ($prodId in $prodIds) {
                                $removeStr = "${prodId}.16_${culture}_x-none"
                                $p = Start-Process $c2rExe -ArgumentList "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=$removeStr DisplayLevel=False" -Wait -PassThru -WindowStyle Hidden
                                $steps += "C2R $removeStr exit $($p.ExitCode)"
                                if ($p.ExitCode -eq 0) { $result='Removed'; $detail="Office removed via C2R ($removeStr) | $($steps -join ' | ')"; $done=$true; break }
                            }
                        }
                    }
                    if (-not $done) {
                        $m365 = $installed | Where-Object { $_.Name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus' } | Select-Object -First 1
                        if ($m365 -and -not [string]::IsNullOrWhiteSpace($m365.UninstallString)) {
                            $p = Start-Process cmd.exe -ArgumentList '/c', $m365.UninstallString -Wait -PassThru -WindowStyle Hidden; $steps += "uninstall string exit $($p.ExitCode)"
                            if ($p.ExitCode -eq 0) { $result='Removed'; $detail="Office removed via uninstall string | $($steps -join ' | ')"; $done=$true }
                        }
                    }
                    if (-not $done) { $detail = "Office: all methods attempted | $($steps -join ' | ')" }
                    [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail }); continue
                }
                # Adobe Acrobat: drop RunAsPPL (restore in finally), kill Adobe svcs/procs,
                # msiexec /x each Adobe GUID from both Uninstall hives.
                if ($name -match 'Adobe Acrobat') {
                    $type = 'MSI'; $steps = @(); $removed = $false; $pplRestore = $false; $pplVal = $null; $pplRestoreFailed = $false
                    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                    try {
                        try { $pv = Get-ItemProperty $lsaKey -Name 'RunAsPPL' -EA SilentlyContinue; if ($null -ne $pv -and $null -ne $pv.RunAsPPL) { $pplVal=$pv.RunAsPPL; Remove-ItemProperty -Path $lsaKey -Name 'RunAsPPL' -Force -EA Stop; $pplRestore=$true; $steps += "RunAsPPL removed (was $pplVal)" } } catch {}
                        try { foreach ($svc in @('AdobeARMservice','AdobeUpdateService','AGSService')) { $s=Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Stop-Service $svc -Force -EA SilentlyContinue } }; foreach ($pn in @('Acrobat','AcroCEF','AcroRd32','AdobeARM','AdobeCollabSync','armsvc')) { Get-Process $pn -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }; $steps += 'Adobe procs killed' } catch {}
                        $adobeGuids = @()
                        foreach ($rp in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
                            Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Adobe Acrobat' } | ForEach-Object { if ($_.UninstallString -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }; if ($_.PSChildName -match '^\{') { $adobeGuids += $_.PSChildName } }
                        }
                        $adobeGuids = @($adobeGuids | Select-Object -Unique)
                        foreach ($guid in $adobeGuids) { $p = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -WindowStyle Hidden; if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { $removed=$true } }
                        $steps += "$($adobeGuids.Count) GUID(s)"
                    } finally {
                        if ($pplRestore) { try { New-ItemProperty -Path $lsaKey -Name 'RunAsPPL' -Value $pplVal -PropertyType DWord -Force -EA Stop | Out-Null; $steps += "RunAsPPL restored to $pplVal" } catch { $pplRestoreFailed = $true; $steps += 'WARNING: RunAsPPL restore FAILED' } }
                    }
                    if ($removed) { $result='Removed'; $detail="Adobe removed via MSI | $($steps -join ' | ')" } else { $detail="Adobe: all methods attempted | $($steps -join ' | ')" }
                    # A failed RunAsPPL restore left LSASS protection OFF - that must read
                    # as a FAILURE in the grid/audit, never a clean 'Removed'.
                    if ($pplRestoreFailed) { $result = 'Failed'; $detail = "CRITICAL: RunAsPPL (LSASS protection) NOT restored on this host - re-enable it. $detail" }
                    [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail }); continue
                }
                # Direct {GUID} entry -> straight MSI removal.
                if ($name -match '^\{[0-9A-Fa-f\-]+\}$') {
                    $type = 'MSI'
                    $p = Start-Process msiexec.exe -ArgumentList "/x $name /qn /norestart" -Wait -PassThru -WindowStyle Hidden
                    if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { $result = 'Removed'; $detail = "msiexec /x $name (exit $($p.ExitCode))" }
                    else { $detail = "msiexec exit $($p.ExitCode)" }
                    [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail }); continue
                }
                $match = $installed | Where-Object { $_.Name -like "*$name*" } | Select-Object -First 1
                $appx  = Get-AppxPackage -AllUsers -Name "*$name*" -EA SilentlyContinue
                if (-not $match -and $appx) {
                    $type = 'Store'
                    $appx | Remove-AppxPackage -AllUsers -EA Stop
                    $result = 'Removed'; $detail = "Removed Appx package(s): $(@($appx).Count)"
                } elseif ($match) {
                    $unStr = $match.UninstallString
                    if ($unStr -match 'msiexec') {
                        $type = 'MSI'
                        $guid = $unStr -replace '.*(\{[^\}]+\}).*','$1'
                        if ($guid -match '^\{[0-9A-Fa-f\-]+\}$') {
                            $p = Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -WindowStyle Hidden
                            if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { $result = 'Removed'; $detail = "$($match.Name): msiexec /x $guid (exit $($p.ExitCode))" }
                            else { $detail = "msiexec exit $($p.ExitCode)" }
                        } else { $detail = "Could not parse MSI product code from: $unStr" }
                    } else {
                        $type = 'EXE'
                        # Capture the uninstaller's real exit code (cmd /c returns the last
                        # command's code); only 0/3010 = success. The old `cmd /c ... | Out-Null`
                        # discarded the code and reported 'Removed' even when it failed.
                        $quiet = $match.QuietUninstallString
                        if (-not [string]::IsNullOrWhiteSpace($quiet)) {
                            $pe = Start-Process cmd.exe -ArgumentList '/c', $quiet -Wait -PassThru -WindowStyle Hidden
                            if ($pe.ExitCode -eq 0 -or $pe.ExitCode -eq 3010) { $result = 'Removed'; $detail = "$($match.Name): QuietUninstallString (exit $($pe.ExitCode))" }
                            else { $detail = "$($match.Name): QuietUninstall exit $($pe.ExitCode)" }
                        } elseif (-not [string]::IsNullOrWhiteSpace($unStr)) {
                            # Parse the exe without splitting on '/' or '--' (those truncate any
                            # uninstall path that legitimately contains them). A quoted path takes
                            # the text between the first quote pair; otherwise reuse the same
                            # exe regex the unquoted-service-path healer uses.
                            $unTrim = $unStr.Trim()
                            if ($unTrim.StartsWith('"')) {
                                $close = $unTrim.IndexOf('"', 1)
                                $exe = if ($close -gt 0) { $unTrim.Substring(1, $close - 1) } else { $unTrim.Trim('"') }
                            } else {
                                $em = [regex]::Match($unTrim, '(?i)^(.+?\.exe)(.*)$')
                                $exe = if ($em.Success) { $em.Groups[1].Value } else { $unTrim }
                            }
                            $pe = Start-Process cmd.exe -ArgumentList '/c', "`"$exe`" /S /silent /quiet /uninstall /norestart" -Wait -PassThru -WindowStyle Hidden
                            if ($pe.ExitCode -eq 0 -or $pe.ExitCode -eq 3010) { $result = 'Removed'; $detail = "$($match.Name): EXE silent $exe (exit $($pe.ExitCode))" }
                            else { $detail = "$($match.Name): EXE silent exit $($pe.ExitCode)" }
                        } else { $detail = "No UninstallString for $($match.Name)" }
                    }
                    # Tanium leaves a stale key behind; only clean it on a genuine removal.
                    if ($result -eq 'Removed' -and $match.Name -like '*Tanium*') {
                        Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Tanium' -Recurse -Force -EA SilentlyContinue
                    }
                } else {
                    $result = 'NotFound'; $detail = "No installed product matched '$name'"
                }
            } catch { $detail = $_.Exception.Message }
            [void]$results.Add(@{ App=$name; Type=$type; Result=$result; Detail=$detail })
        }
        return ,$results.ToArray()
    }
}

# --- Software Center App List (CCM_Application, mirrors WPT 6018-6029) ---------
$script:WptAppListBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    if (-not (Test-WptHostReachable $Computer)) { throw 'unreachable (TCP 5985/445)' }
    $opt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    return Invoke-Command @splat -ScriptBlock {
        # Full App Manager EvaluationState map (desktop $script:EvalMap, 9036).
        $evalMap = @{0='None';1='Available';2='Submitted';3='Detecting';4='PreDownload';5='Downloading';6='Wait Install';7='Installing';8='Pend Soft Reboot';9='Pend Hard Reboot';10='Wait Reboot';11='Verifying';12='Install Complete';13='Error';14='Wait Window';15='Wait Logon';16='Wait Logoff';17='Wait Reconnect';18='Pend User Logoff';19='Pend Logoff';20='Pend Update';21='Wait Retry';22='Wait Presentation Off';23='Wait Orchestration';24='Download Failed';25='PreDownload Failed';26='Download OK';27='Post-Enforce Eval';28='Wait Network'}
        $apps = Get-CimInstance -Namespace ROOT\ccm\ClientSDK -Class CCM_Application -EA Stop | Select-Object Name,InstallState,ApplicabilityState,EvaluationState,PercentComplete,Id,Revision,IsMachineTarget,SoftwareVersion
        $out = New-Object System.Collections.ArrayList
        foreach ($a in @($apps)) {
            $es = [int]$a.EvaluationState
            $esName = if ($evalMap.ContainsKey($es)) { $evalMap[$es] } else { "State $es" }
            [void]$out.Add(@{
                Name=[string]$a.Name; InstallState=[string]$a.InstallState; Applicable=[string]$a.ApplicabilityState
                EvalState=$esName; PercentComplete=[string]$a.PercentComplete; Version=[string]$a.SoftwareVersion; Id=[string]$a.Id; Revision=[string]$a.Revision
                IsMachineTarget=[string]$a.IsMachineTarget })
        }
        return ,$out.ToArray()
    }
}

# --- Software Center App Action (CCM_Application SDK, mirrors WPT 9078-9086) ---
#  Install / Uninstall / Reinstall / Repair a deployed app by Id+Revision.
#  Reinstall = Uninstall, wait 10s, Install. Tanium cleanup on Uninstall/Reinstall.
$script:WptAppActionBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$AppId, [string]$Revision, $IsMachineTarget, [string]$Method, [string]$AppName)
    $r = @{ Host=$Computer; App=$AppName; Method=$Method; Result='Failed'; Detail='' }
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
    if (-not $reachable) { $r.Detail = 'Offline'; return $r }
    $opt = New-PSSessionOption -OperationTimeout 1800000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    try {
        # DNS-mismatch guard (HARD ABORT): never fire a CCM app action on a box that
        # isn't the one we dialed (audit#2 - every sibling destructive block has this).
        # Name compare (no PTR on AFNET); if the probe can't run, proceed.
        $actualName = try { Invoke-Command @splat -ScriptBlock { $env:COMPUTERNAME } } catch { '' }
        $targetShort = ($Computer -split '\.')[0]
        if ($actualName -and ($actualName.Trim().ToUpper() -ne $targetShort.ToUpper())) {
            $r.Detail = "DNS mismatch: dialed '$targetShort' but remote is '$($actualName.Trim())' - ABORTED, no action taken"
            return $r
        }
        $remote = Invoke-Command @splat -ArgumentList $AppId,$Revision,$IsMachineTarget,$Method,$AppName -ScriptBlock {
            param([string]$Id, [string]$Rev, $Machine, [string]$Mthd, [string]$Nm)
            # Resolve the app from the host's LIVE Software Center catalog so the SDK is
            # driven with values that actually match the deployment. A wrong target
            # (machine vs user), a stale/blank Revision, or a non-applicable app makes
            # CCM_Application.Install return WITHOUT throwing, yet Software Center on the
            # box declines to run it ("Software Center cannot run the update") -- the old
            # code reported a false 'Triggered'. Desktop parity: the WinForms tool carries
            # Id/Revision/IsMachineTarget from the queried row, so they always match.
            $evalMap = @{0='None';1='Available';2='Submitted';3='Detecting';4='PreDownload';5='Downloading';6='Wait Install';7='Installing';8='Pend Soft Reboot';9='Pend Hard Reboot';10='Wait Reboot';11='Verifying';12='Install Complete';13='Error';14='Wait Window';15='Wait Logon';16='Wait Logoff';17='Wait Reconnect';18='Pend User Logoff';19='Pend Logoff';20='Pend Update';21='Wait Retry';22='Wait Presentation Off';23='Wait Orchestration';24='Download Failed';25='PreDownload Failed';26='Download OK';27='Post-Enforce Eval';28='Wait Network'}
            $evalName = { param($a) if ($null -eq $a) { return 'unknown' }; $e=[int]$a.EvaluationState; if ($evalMap.ContainsKey($e)) { $evalMap[$e] } else { "State $e" } }
            try { $null = Get-CimClass -Namespace 'ROOT\ccm\ClientSDK' -ClassName CCM_Application -ErrorAction Stop }
            catch { return @{ OK=$false; Detail='SCCM client (CCM_Application) not present on this host' } }
            $cat = $null
            try { $cat = @(Get-CimInstance -Namespace 'ROOT\ccm\ClientSDK' -Class CCM_Application -ErrorAction Stop) }
            catch { return @{ OK=$false; Detail="Software Center catalog query failed: $($_.Exception.Message)" } }
            if (-not $cat -or $cat.Count -eq 0) { return @{ OK=$false; Detail='No CCM_Application objects on this host (SCCM client present but catalog empty)' } }
            $cands = @($cat | Where-Object { [string]$_.Id -eq $Id })
            if ($cands.Count -eq 0) { return @{ OK=$false; Detail="App Id not found in this host's Software Center catalog ($($cat.Count) app(s) present)" } }
            $app = $null
            if ($Rev) { $app = $cands | Where-Object { [string]$_.Revision -eq $Rev } | Select-Object -First 1 }
            if (-not $app) { $app = $cands | Sort-Object { try { [int]$_.Revision } catch { 0 } } -Descending | Select-Object -First 1 }
            $effRev     = [string]$app.Revision
            $effMachine = if ($null -ne $app.IsMachineTarget) { [bool]$app.IsMachineTarget } else { [System.Convert]::ToBoolean($Machine) }
            $applic     = [string]$app.ApplicabilityState
            $instState  = [string]$app.InstallState
            $tgt        = if ($effMachine) { 'machine' } else { 'user' }
            # Install/Repair/Reinstall need an applicable app; Uninstall does not.
            if (($Mthd -eq 'Install' -or $Mthd -eq 'Repair' -or $Mthd -eq 'Reinstall') -and $applic -and $applic -ne 'Applicable') {
                return @{ OK=$false; Name=[string]$app.Name; Detail="Skipped: not applicable to this host (Applicability=$applic, Install=$instState, Eval=$(& $evalName $app)). Software Center will not run it." }
            }
            $invoke = {
                param([string]$M)
                Invoke-CimMethod -Namespace 'root/ccm/clientSDK' -ClassName CCM_Application -MethodName $M -Arguments @{
                    EnforcePreference=[UINT32]0; Id=$Id; IsMachineTarget=$effMachine; IsRebootIfNeeded=$false; Priority='High'; Revision=$effRev
                } -ErrorAction Stop
            }
            try {
                $rv = $null
                if ($Mthd -eq 'Reinstall') {
                    [void](& $invoke 'Uninstall'); Start-Sleep -Seconds 10; $res = & $invoke 'Install'; if ($res) { $rv = $res.ReturnValue }
                } else {
                    $res = & $invoke $Mthd; if ($res) { $rv = $res.ReturnValue }
                }
                if (($Mthd -eq 'Uninstall' -or $Mthd -eq 'Reinstall') -and $Nm -like '*Tanium*') {
                    Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Tanium' -Recurse -Force -EA SilentlyContinue
                }
                # Re-read post-invoke state so the grid shows real progress, not a guess.
                $post = $null
                try { $post = @(Get-CimInstance -Namespace 'ROOT\ccm\ClientSDK' -Class CCM_Application -ErrorAction Stop | Where-Object { [string]$_.Id -eq $Id -and [string]$_.Revision -eq $effRev }) | Select-Object -First 1 } catch {}
                $postEval = & $evalName $post
                $rvText = if ($null -ne $rv) { "rv=$rv" } else { 'rv=n/a' }
                if ($null -ne $rv -and [int]$rv -ne 0) {
                    return @{ OK=$false; Name=[string]$app.Name; Detail="$Mthd returned $rvText (target=$tgt, rev=$effRev). Eval now: $postEval" }
                }
                return @{ OK=$true; Name=[string]$app.Name; Detail="$Mthd triggered ($rvText, target=$tgt, rev=$effRev). Eval now: $postEval" }
            } catch { return @{ OK=$false; Name=[string]$app.Name; Detail="$Mthd failed: $($_.Exception.Message)" } }
        }
        if ($remote -and $remote.OK) { $r.Result = 'Triggered'; $r.Detail = [string]$remote.Detail }
        else { $r.Detail = if ($remote) { [string]$remote.Detail } else { 'no result' } }
        if ($remote -and $remote.Name) { $r.App = [string]$remote.Name }
    } catch { $r.Detail = $_.Exception.Message }
    return $r
}

# --- Log4j Finder (L4JFinderBlock:11481) ---
$script:WptLog4jBlock = {
    param([string]$Computer, $Cred, [string]$Auth)
    $r = @{ Host=$Computer; Online=$false; ScanOK=$false; Jars=@(); Error='' }
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
    $r.Online = $true
    $wsOpt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Error = "Session: $($_.Exception.Message)"; return $r }
    try {
        $remote = Invoke-Command -Session $sess -EA Stop -ScriptBlock {
            $roots = @('C:\Program Files','C:\Program Files (x86)','C:\ProgramData','C:\Users','C:\Java','C:\opt','C:\apps')
            $roots += @(Get-ChildItem -Path 'C:\' -Directory -Filter 'jdk*' -EA SilentlyContinue | ForEach-Object { $_.FullName })
            $roots += @(Get-ChildItem -Path 'C:\' -Directory -Filter 'jre*' -EA SilentlyContinue | ForEach-Object { $_.FullName })
            $jars = New-Object System.Collections.Generic.List[object]
            foreach ($root in $roots) {
                if (-not (Test-Path -LiteralPath $root)) { continue }
                try { $found = Get-ChildItem -LiteralPath $root -Filter 'log4j-*.jar' -Recurse -File -Force -EA SilentlyContinue } catch { continue }
                foreach ($f in $found) {
                    $name = $f.Name; $component = ''; $version = ''
                    if ($name -match '^log4j-([A-Za-z0-9\.\-]+?)-(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*)\.jar$') { $component = $Matches[1]; $version = $Matches[2] }
                    elseif ($name -match '^log4j-(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*)\.jar$') { $component = 'legacy'; $version = $Matches[1] }
                    else { $component = 'unknown'; $version = '' }
                    $jars.Add(@{ Path=$f.FullName; Filename=$name; Component=$component; Version=$version }) | Out-Null
                }
            }
            return ,$jars.ToArray()
        }
        $r.Jars = @($remote); $r.ScanOK = $true
    } catch { $r.Error = $_.Exception.Message }
    finally { Remove-PSSession $sess -EA SilentlyContinue }
    return $r
}

# Log4j version classifier (Get-Log4jVulnState:11592). 2.25.4 exactly = patched.
function Get-WptLog4jVulnState {
    param([string]$Version)
    if ([string]::IsNullOrWhiteSpace($Version)) { return 'Unknown' }
    if ($Version -eq '2.25.4') { return 'Patched' }
    if ($Version -match '^\d+\.\d+') { return 'Vulnerable' }
    return 'Unknown'
}

# -----------------------------------------------------------------------------
#  Shared multi-host fan-out harvester. Mirrors the RunspacePool pattern in
#  JanetWeb.message.psm1: one [powershell] per host added to a pool, a harvest
#  loop polling IsCompleted, EndInvoke, build a row, stream row+audit+progress.
#  $Work is the worker scriptblock; $ArgFactory builds the argument array for a
#  host; $RowOf maps a worker result to a grid row; $OkOf decides success;
#  $AuditDetail produces a short audit detail; $AuditAction is the fixed
#  ValidateSet action ('TouchHost' for reads, 'VulnPatched' for state-changes).
# -----------------------------------------------------------------------------
function Invoke-WptFanOut {
    param(
        [string[]]$Targets, [int]$Threads, [scriptblock]$Work, [scriptblock]$ArgFactory,
        [scriptblock]$RowOf, [scriptblock]$OkOf, [scriptblock]$AuditDetail,
        [scriptblock]$LogOf,   # optional: returns @{level;text} per host -> emits a per-host activity-log line (opt-in; other actions stay quiet)
        [string]$AuditAction, [scriptblock]$Send, [string]$ActionId,
        [scriptblock]$CancelCheck,   # returns $true when the operator pressed Cancel
        [int]$DeadlineSeconds = 3600, # wall-clock backstop so wedged hosts can't hang the batch forever
        [int]$PerHostTimeoutSeconds = 0 # per-host limit; >0 abandons ONLY a host overrunning its OWN run clock (0 = off). Mirrors Invoke-AcasFanOut. Leave 0 for long actions (patch/reboot/install); set it for read-only scans where a long run means a WMI/CIM hang.
    )
    # Default to the dispatcher's cancel bridge so every fan-out honors Cancel
    # without each call site passing it (one action per worker runspace -> safe).
    if (-not $CancelCheck) { $CancelCheck = $script:WptCancelCheck }
    & $Send @{ type='status'; text="Starting '$ActionId' on $($Targets.Count) host(s) with $Threads thread(s)..." }
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $Targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($Work)
        foreach ($a in (& $ArgFactory $h)) { [void]$ps.AddArgument($a) }
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }
    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0
    $deadline = (Get-Date).AddSeconds([Math]::Max(60, $DeadlineSeconds))
    $cancelled = $false; $timedOut = $false
    try {
        while ($done -lt $jobs.Count) {
            foreach ($j in $jobs) {
                # Stamp real execution start (NotStarted->Running) so the per-host
                # clock doesn't penalize hosts still queued behind the thread cap.
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    # Surface a worker-runspace failure as an explicit log event too: for actions
                    # whose columns don't include an 'Error' field the message would otherwise be
                    # swallowed into $res.Error and never shown. Additive only -- $res/flow unchanged.
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; Error="worker error: $($_.Exception.Message)" }; & $Send @{ type='log'; level='warn'; text="$($j.Host) : worker error: $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Error='no result' } }
                    $ok = [bool](& $OkOf $res)
                    if ($ok) { $okCount++ } else { $failCount++ }
                    $row = & $RowOf $res
                    [void]$rows.Add($row)
                    & $Send (@{ type='row' } + $row)
                    & $Send @{ type='audit'; action=$AuditAction; target=$res.Host; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$(if($ok){1}else{0}); detail=([string](& $AuditDetail $res)) }
                    # opt-in per-host activity-log line, so a clean run leaves evidence in
                    # the log (e.g. a "No change" patch shows "HOST: 0 updates, 0 apps").
                    if ($LogOf) { $lg = & $LogOf $res; if ($lg) { & $Send (@{ type='log' } + $lg) } }
                    $done++
                    & $Send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon ONLY a host that overran its own run clock
            # so one wedged WMI/CIM call can't pin a thread for the whole batch
            # deadline. Opt-in via -PerHostTimeoutSeconds; mirrors Invoke-AcasFanOut.
            if ($PerHostTimeoutSeconds -gt 0 -and $done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $PerHostTimeoutSeconds) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}
                        $j.PS = $null
                        $rowT = & $RowOf @{ Host=$j.Host; Error="per-host timeout (${PerHostTimeoutSeconds}s) - possible WMI/CIM hang" }
                        [void]$rows.Add($rowT); & $Send (@{ type='row' } + $rowT)
                        & $Send @{ type='audit'; action=$AuditAction; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${PerHostTimeoutSeconds}s)" }
                        & $Send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${PerHostTimeoutSeconds}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                        $failCount++; $done++
                        & $Send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                # Honor the server cancel contract: POST /job/<id>/cancel sets the
                # injected job's Cancel flag; stop in-flight WinRM children so a stood-
                # down bulk patch/reboot stops dispatching to the remaining hosts.
                if     ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true }
                elseif ((Get-Date) -gt $deadline)           { $timedOut  = $true }
                if ($cancelled -or $timedOut) {
                    $reason = if ($cancelled) { 'cancelled by operator' } else { "timed out after $([int]$DeadlineSeconds)s" }
                    $abandoned = 0
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            # BeginStop then NULL the handle - Dispose right after BeginStop
                            # empirically blocks ~11s per host; the pool Close/Dispose in the
                            # finally reclaims the stopping children after the abandon
                            # rows/audits below have been emitted.
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $rowR = & $RowOf @{ Host=$j.Host; Error=$reason }
                            [void]$rows.Add($rowR); & $Send (@{ type='row' } + $rowR)
                            & $Send @{ type='audit'; action=$AuditAction; target=$j.Host; result='Failure'; itemCount=0; detail=$reason }
                            $failCount++; $done++; $abandoned++
                        }
                    }
                    & $Send @{ type='log'; level='warn'; text="Run $reason; $abandoned host(s) abandoned mid-flight (in-flight WinRM calls are being stopped)." }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }
    & $Send @{ type='status'; text="Done. $okCount ok, $failCount failed of $($jobs.Count)." }
    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; failed=$failCount; cancelled=$cancelled; timedOut=$timedOut } }
}

# -----------------------------------------------------------------------------
#  Invoke-JanetToolAction - dispatcher
# -----------------------------------------------------------------------------
function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge: the server injects the synchronized job as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running fan-out break and BeginStop in-flight WinRM children. Stored in a
    # script-scoped var so every Invoke-WptFanOut picks it up by default.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $script:WptCancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Negotiate when a credential is supplied; otherwise omit auth (Kerberos).
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }

    # ---- Single-host: Host Info snapshot ----
    if ($ActionId -eq 'host-info') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Querying $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        $call = Invoke-WptSingleHostCancelable -Work $script:WptHostInfoBlock -Arguments @($hostName, $Credential, $auth) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : host info abandoned ($reason)." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            $ok = $true
            foreach ($a in (Expand-WptSingleHostResult $call.Result)) {
                $g = { param($k) if ($a -is [hashtable]) { [string]$a[$k] } else { [string]$a.$k } }
                $row = @{ _rk="$hostName|$(& $g 'Property')"; Host=$hostName; Property=(& $g 'Property'); Value=(& $g 'Value') }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            $detail = "$($rows.Count) field(s)"
            & $send @{ type='status'; text="$hostName : info retrieved" }
        } else {
            $detail = "Query failed: $($call.Error)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Single-host: Event Log error scan ----
    if ($ActionId -eq 'eventlog-scan') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        $logs = New-Object System.Collections.ArrayList
        if (-not $Params.ContainsKey('application') -or [bool]$Params['application']) { [void]$logs.Add('Application') }
        if (-not $Params.ContainsKey('system') -or [bool]$Params['system']) { [void]$logs.Add('System') }
        if ($Params.ContainsKey('security') -and [bool]$Params['security']) { [void]$logs.Add('Security') }
        if ($logs.Count -eq 0) { [void]$logs.Add('Application'); [void]$logs.Add('System') }
        $hours = 12; $hp = 0; if ($Params.ContainsKey('hours') -and [int]::TryParse([string]$Params['hours'], [ref]$hp) -and $hp -gt 0) { $hours = $hp }
        & $send @{ type='status'; text="Reading $((@($logs)) -join '/') errors (last $hours h) on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        $call = Invoke-WptSingleHostCancelable -Work $script:WptEventLogBlock -Arguments @($hostName, $Credential, $auth, ((@($logs)) -join ','), $hours) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : event-log scan abandoned ($reason)." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            $ok = $true; $i = 0
            foreach ($a in (Expand-WptSingleHostResult $call.Result)) {
                $g = { param($k) if ($a -is [hashtable]) { [string]$a[$k] } else { [string]$a.$k } }
                $i++
                $row = @{ _rk="$hostName|$i"; Host=$hostName; Log=(& $g 'Log'); TimeCreated=(& $g 'TimeCreated'); EventId=(& $g 'EventId'); Provider=(& $g 'Provider'); Message=(& $g 'Message') }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            $detail = "$($rows.Count) event row(s)"
            & $send @{ type='status'; text="$hostName : $detail" }
        } else {
            $detail = "Event-log scan failed: $($call.Error)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Single-host: Available Deployments (unified MECM available list) ----
    if ($ActionId -eq 'sccm-available') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Querying available MECM deployments on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        $call = Invoke-WptSingleHostCancelable -Work $script:WptSccmAvailableBlock -Arguments @($hostName, $Credential, $auth) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : available-deployments query abandoned ($reason)." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            $ok = $true
            foreach ($a in (Expand-WptSingleHostResult $call.Result)) {
                $g = { param($k) if ($a -is [hashtable]) { [string]$a[$k] } else { [string]$a.$k } }
                $row = @{ _rk="$hostName|$(& $g 'Type')|$(& $g 'Id')|$(& $g 'Name')"; Host=$hostName; Type=(& $g 'Type'); Name=(& $g 'Name'); State=(& $g 'State'); Version=(& $g 'Version'); Id=(& $g 'Id'); Revision=(& $g 'Revision') }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            $detail = "$($rows.Count) available item(s)"
            & $send @{ type='status'; text="$hostName : $detail" }
        } else {
            $detail = "Query failed: $($call.Error)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Single-host: Install Available (deploy apps + updates) ----
    if ($ActionId -eq 'sccm-install-available') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        $itemsText = [string]$Params['items']
        if ([string]::IsNullOrWhiteSpace($itemsText)) {
            & $send @{ type='log'; level='warn'; text='No deployment items selected.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Installing selected deployment(s) on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $okCount = 0; $failCount = 0
        $call = Invoke-WptSingleHostCancelable -Work $script:WptSccmInstallBlock -Arguments @($hostName, $Credential, $auth, $itemsText) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : install abandoned ($reason); installs already dispatched on the host may proceed." }
            & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            foreach ($u in (Expand-WptSingleHostResult $call.Result)) {
                $g = { param($k) if ($u -is [hashtable]) { [string]$u[$k] } else { [string]$u.$k } }
                $rst = (& $g 'Result')
                $isOk = ($rst -eq 'Triggered')
                if ($isOk) { $okCount++ } elseif ($rst -eq 'Failed') { $failCount++ }
                $row = @{ Host=$hostName; Type=(& $g 'Type'); Name=(& $g 'Name'); Result=$rst; Detail=(& $g 'Detail') }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result=$(if($isOk){'Success'}else{'Failure'}); itemCount=$(if($isOk){1}else{0}); detail="$($row.Type) $($row.Name): $rst - $($row.Detail)" }
            }
        } else {
            & $send @{ type='log'; level='err'; text="$hostName : $($call.Error)" }
            & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result='Failure'; itemCount=0; detail=$call.Error }
        }
        & $send @{ type='status'; text="$hostName : $okCount triggered, $failCount failed." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$okCount; failed=$failCount } }
    }

    # ---- Active Directory computer query (drives the Targets OU-import picker) ----
    if ($ActionId -eq 'ad-computers') {
        $wsOnly = $true; if ($Params.ContainsKey('workstationsonly') -and $null -ne $Params['workstationsonly']) { $wsOnly = [bool]$Params['workstationsonly'] }
        $filter = ([string]$Params['filter']).Trim()
        & $send @{ type='status'; text='Querying Active Directory for computer objects...' }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        try {
            $rootDse = if ($Credential) { New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE', $Credential.UserName, $Credential.GetNetworkCredential().Password) } else { New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE') }
            $nc = [string]$rootDse.Properties['defaultNamingContext'][0]
            if ([string]::IsNullOrWhiteSpace($nc)) { throw 'cannot read defaultNamingContext (not domain-joined or no DC reachable)' }
            $basePath = "LDAP://$nc"
            $de = if ($Credential) { New-Object System.DirectoryServices.DirectoryEntry($basePath, $Credential.UserName, $Credential.GetNetworkCredential().Password) } else { New-Object System.DirectoryServices.DirectoryEntry($basePath) }
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
            $searcher.Filter = '(objectCategory=computer)'
            $searcher.PageSize = 1000
            $searcher.SizeLimit = 0
            foreach ($p in 'name','distinguishedName','operatingSystem','userAccountControl') { [void]$searcher.PropertiesToLoad.Add($p) }
            $ress = $searcher.FindAll()
            foreach ($res in $ress) {
                $pr = $res.Properties
                $name = if ($pr['name'].Count) { [string]$pr['name'][0] } else { '' }
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $dn  = if ($pr['distinguishedname'].Count) { [string]$pr['distinguishedname'][0] } else { '' }
                $os  = if ($pr['operatingsystem'].Count) { [string]$pr['operatingsystem'][0] } else { '' }
                $uac = if ($pr['useraccountcontrol'].Count) { [int]$pr['useraccountcontrol'][0] } else { 0 }
                $enabled = (($uac -band 2) -eq 0)
                if ($wsOnly -and ($os -match 'Server')) { continue }
                if ($filter -and -not ("$name $os" -like "*$filter*")) { continue }
                $ou = ($dn -replace '^CN=[^,]+,', '')
                $row = @{ _rk=$dn; Name=$name.ToUpperInvariant(); OU=$ou; OS=$os; Enabled=$enabled }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            $ress.Dispose(); $searcher.Dispose(); $de.Dispose(); $rootDse.Dispose()
            $ok = $true; $detail = "$($rows.Count) computer(s)"
            & $send @{ type='status'; text="AD query complete: $detail" }
        } catch {
            $detail = "AD query failed: $($_.Exception.Message)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target='(ActiveDirectory)'; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Single-host: Software Scan ----
    if ($ActionId -eq 'software-scan') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        $filter = [string]$Params['filter']
        & $send @{ type='status'; text="Scanning software on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        $call = Invoke-WptSingleHostCancelable -Work $script:WptSoftwareScanBlock -Arguments @($hostName, $Credential, $auth) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : software scan abandoned ($reason); the in-flight remote query was stopped but may complete on the host." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            $apps = Expand-WptSingleHostResult $call.Result
            $ok = $true
            foreach ($a in @($apps)) {
                $name = if ($a -is [hashtable]) { [string]$a['Name'] } else { [string]$a.Name }
                $pub  = if ($a -is [hashtable]) { [string]$a['Publisher'] } else { [string]$a.Publisher }
                $ver  = if ($a -is [hashtable]) { [string]$a['Version'] } else { [string]$a.Version }
                if (-not [string]::IsNullOrWhiteSpace($filter)) {
                    if (-not ($name -like "*$filter*" -or $pub -like "*$filter*" -or $ver -like "*$filter*")) { continue }
                }
                $child = if ($a -is [hashtable]) { [string]$a['PSChildName'] } else { [string]$a.PSChildName }
                $row = @{
                    # unique per-app key (MSI GUID / registry subkey / KB / DLL path) so
                    # two apps with the same display name don't collapse to one grid row.
                    _rk="$hostName|$name|$ver|$child"
                    Host=$hostName; Name=$name; Version=$ver; Publisher=$pub
                    InstallDate=$(if ($a -is [hashtable]) { [string]$a['InstallDate'] } else { [string]$a.InstallDate })
                    # key must NOT be 'Type' (collides with the event's 'type' when merged)
                    'Install Type'=$(if ($a -is [hashtable]) { [string]$a['Type'] } else { [string]$a.Type })
                    Size=$(if ($a -is [hashtable]) { [string]$a['Size'] } else { [string]$a.Size })
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
            }
            $detail = "$($rows.Count) application(s)"
            & $send @{ type='status'; text="$hostName : $detail" }
        } else {
            $detail = "Scan failed: $($call.Error)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Single-host: Scan Detail (named MECM/WU/App items, not just counts) ----
    if ($ActionId -eq 'scan-detail') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Scanning pending items on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $call = Invoke-WptSingleHostCancelable -Work $script:WptScanBlock -Arguments @($hostName, $Credential, $auth) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : scan detail abandoned ($reason); the in-flight remote query was stopped but may complete on the host." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        $r = if ($call.Error) { @{ Host=$hostName; Online=$false; Error=$call.Error } } else { @($call.Result) | Select-Object -First 1 }
        if ($null -eq $r) { $r = @{ Host=$hostName; Online=$false; Error='no result' } }
        if (-not $r.Online) {
            $d = if ($r.Error) { $r.Error } else { 'offline' }
            & $send @{ type='log'; level='warn'; text="$hostName : $d" }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail=$d }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1 } }
        }
        $emitItems = {
            param($channel, $names)
            foreach ($n in @($names)) {
                if ([string]::IsNullOrWhiteSpace([string]$n)) { continue }
                $row = @{ _rk="$hostName|$channel|$n"; Host=$hostName; Channel=$channel; Name=[string]$n }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
        }
        & $emitItems 'MECM'         $r.UpdateNames
        & $emitItems 'WindowsUpdate' $r.WuNames
        & $emitItems 'App'          $r.AppNames
        # A channel whose query failed must not read as "0 pending" - surface it
        # and audit Failure so a broken CCM/WMI/WUA host can't pass as patched.
        $chFail = @()
        if (-not $r.UpdatesOK) { $chFail += 'MECM' }
        if (-not $r.WuOK)      { $chFail += 'WindowsUpdate' }
        if (-not $r.AppsOK)    { $chFail += 'App' }
        $detail = "MECM=$(if($r.UpdatesOK){$r.UpdateCount}else{'Error'}) WU=$(if($r.WuOK){$r.WuCount}else{'Error'}) Apps=$(if($r.AppsOK){$r.AppCount}else{'Error'})"
        $allOk = ($chFail.Count -eq 0)
        if (-not $allOk) {
            & $send @{ type='log'; level='warn'; text="$hostName : channel query failed: $($chFail -join ', ') - items missing from those channels are NOT confirmed absent.$(if ($r.Error) { " Root error: $($r.Error)" })" }
            $detail += " | channel failures: $($chFail -join ', ')"
        }
        & $send @{ type='status'; text="$hostName : $($rows.Count) pending item(s) - $detail" }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($allOk){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($allOk){$rows.Count}else{0}); failed=$(if($allOk){0}else{1}) } }
    }

    # ---- Single-host: Software Uninstall (destructive) ----
    if ($ActionId -eq 'software-uninstall') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        $appNames = @(([string]$Params['apps']) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        if ($appNames.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='At least one app name or {GUID} is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Uninstalling $($appNames.Count) item(s) on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $okCount = 0; $failCount = 0
        # DESTRUCTIVE single-host op (the remote operation timeout is 10 minutes):
        # run on a cancelable handle so the operator can stand it down mid-flight.
        $call = Invoke-WptSingleHostCancelable -Work $script:WptSoftwareUninstallBlock -Arguments @($hostName, $Credential, $auth, $appNames) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : software uninstall abandoned ($reason); uninstalls already dispatched on the host may have proceeded." }
            & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason - remote uninstall may have proceeded" }
            return @{ rows=@(); summary=@{ total=$appNames.Count; ok=0; failed=$appNames.Count; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            foreach ($u in (Expand-WptSingleHostResult $call.Result)) {
                $app = if ($u -is [hashtable]) { [string]$u['App'] } else { [string]$u.App }
                $typ = if ($u -is [hashtable]) { [string]$u['Type'] } else { [string]$u.Type }
                $rst = if ($u -is [hashtable]) { [string]$u['Result'] } else { [string]$u.Result }
                $det = if ($u -is [hashtable]) { [string]$u['Detail'] } else { [string]$u.Detail }
                $isOk = ($rst -eq 'Removed')
                if ($isOk) { $okCount++ } else { $failCount++ }
                $row = @{ Host=$hostName; App=$app; 'Install Type'=$typ; Result=$rst; Detail=$det }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result=$(if($isOk){'Success'}else{'Failure'}); itemCount=$(if($isOk){1}else{0}); detail="$app : $rst - $det" }
            }
        } else {
            & $send @{ type='log'; level='err'; text="$hostName : $($call.Error)" }
            & $send @{ type='audit'; action='VulnPatched'; target=$hostName; result='Failure'; itemCount=0; detail=$call.Error }
        }
        & $send @{ type='status'; text="$hostName : $okCount removed, $failCount failed of $($appNames.Count)." }
        return @{ rows=@($rows); summary=@{ total=$appNames.Count; ok=$okCount; failed=$failCount } }
    }

    # ---- Single-host: Software Center App List ----
    if ($ActionId -eq 'app-list') {
        $hostName = ([string]$Params['host']).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            & $send @{ type='log'; level='warn'; text='Host is required.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        & $send @{ type='status'; text="Listing Software Center apps on $hostName..." }
        $rows = New-Object System.Collections.ArrayList
        $ok = $false; $detail = ''
        $call = Invoke-WptSingleHostCancelable -Work $script:WptAppListBlock -Arguments @($hostName, $Credential, $auth) -CancelCheck $script:WptCancelCheck
        if ($call.Cancelled -or $call.TimedOut) {
            $reason = if ($call.Cancelled) { 'cancelled by operator' } else { 'timed out' }
            & $send @{ type='log'; level='warn'; text="$hostName : app list abandoned ($reason); the in-flight remote query was stopped but may complete on the host." }
            & $send @{ type='audit'; action='TouchHost'; target=$hostName; result='Failure'; itemCount=0; detail="abandoned: $reason" }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; cancelled=[bool]$call.Cancelled; timedOut=[bool]$call.TimedOut } }
        }
        if (-not $call.Error) {
            $apps = Expand-WptSingleHostResult $call.Result
            $ok = $true
            foreach ($a in @($apps)) {
                $g = { param($k) if ($a -is [hashtable]) { [string]$a[$k] } else { [string]$a.$k } }
                $row = @{
                    Host=$hostName; Name=(& $g 'Name'); InstallState=(& $g 'InstallState'); Applicable=(& $g 'Applicable')
                    EvalState=(& $g 'EvalState'); Version=(& $g 'Version'); Id=(& $g 'Id'); Revision=(& $g 'Revision')
                    IsMachineTarget=(& $g 'IsMachineTarget')
                    # popup-only key (not in the manifest columns): in-flight progress
                    PercentComplete=(& $g 'PercentComplete')
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
            }
            $detail = "$($rows.Count) application(s)"
            & $send @{ type='status'; text="$hostName : $detail" }
        } else {
            $detail = "Query failed: $($call.Error)"
            & $send @{ type='log'; level='err'; text=$detail }
        }
        & $send @{ type='audit'; action='TouchHost'; target=$hostName; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$rows.Count; detail=$detail }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$(if($ok){$rows.Count}else{0}); failed=$(if($ok){0}else{1}) } }
    }

    # ---- Fleet compliance trend (read-only; reads local snapshot CSVs, no targets) ----
    if ($ActionId -eq 'trend') {
        & $send @{ type='status'; text='Reading fleet snapshots for trend...' }
        $trend = Get-WptTrendData -Max 60
        $snaps = @($trend.Snapshots)
        if ($snaps.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="No snapshots found in JanetLocal\snapshots. Run a Bulk Scan with 'Save snapshot for trending' checked to start building history." }
            & $send @{ type='status'; text='No snapshots yet.' }
            return @{ rows=@(); summary=@{ snapshots=0; kept=0; found=0; latestPending=0; latestReboot=0; latestTotal=0; stuck=0; maxPending=0 } }
        }
        $rows = New-Object System.Collections.ArrayList
        $idx = 0
        foreach ($s in $snaps) {
            $idx++
            $row = @{ _rk=("$idx|$($s.File)"); ScanStamp=[string]$s.Stamp; File=[string]$s.File; TotalHosts=[int]$s.Total; Online=[int]$s.Online; HostsPending=[int]$s.HostsPending; RebootPending=[int]$s.RebootPending; PendingUpdates=[int]$s.PendingUpdates; Errors=[int]$s.Errors }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        $latest = $snaps[0]
        $stuck  = @($trend.Stuck)
        $maxPending = 0
        foreach ($s in $snaps) { if ([int]$s.HostsPending -gt $maxPending) { $maxPending = [int]$s.HostsPending } }
        # Stream the stuck-host list to the activity log (read-only; no audit rows).
        if ($stuck.Count -gt 0) {
            & $send @{ type='log'; level='banner'; text="STUCK HOSTS - pending work in >= 3 consecutive snapshots ($($stuck.Count)):" }
            foreach ($h in $stuck) { & $send @{ type='log'; level='warn'; text=("  {0} - pending in {1} consecutive snapshot(s)" -f [string]$h.Host, [int]$h.Streak) } }
        } else {
            & $send @{ type='log'; level='ok'; text='No stuck hosts (none pending across 3+ consecutive snapshots).' }
        }
        & $send @{ type='log'; level='info'; text="Trend: $($snaps.Count) snapshot(s) kept (of $($trend.Found) on disk). Latest ($([string]$latest.Stamp)): $([int]$latest.HostsPending) host(s) with pending work, $([int]$latest.RebootPending) reboot-pending, of $([int]$latest.Total) scanned." }
        & $send @{ type='status'; text="Done. $($snaps.Count) snapshot(s); latest pending $([int]$latest.HostsPending); stuck $($stuck.Count)." }
        return @{ rows=@($rows); summary=@{ snapshots=$snaps.Count; kept=$snaps.Count; found=$trend.Found; latestPending=[int]$latest.HostsPending; latestReboot=[int]$latest.RebootPending; latestTotal=[int]$latest.Total; stuck=$stuck.Count; maxPending=$maxPending } }
    }

    # ---- All other actions are multi-host fan-outs ----
    $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    switch ($ActionId) {
        'ping-sweep' {
            $threads = Get-WptThreadCount $Params 32
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptPingBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $null, 'Default') } `
                -OkOf { param($r) [bool]$r.Reachable } `
                -AuditDetail { param($r) if ($r.Reachable) { 'reachable' } else { 'no TCP reply on 5985/445' } } `
                -RowOf { param($r) @{ Host=$r.Host; Reachable=[bool]$r.Reachable } }
        }
        'bulk-scan' {
            $threads = Get-WptThreadCount $Params 24
            $saveSnap = ConvertTo-WptBool $Params['saveSnapshot']
            $scanResult = Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send -PerHostTimeoutSeconds 300 `
                -Work $script:WptScanBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Online } `
                -AuditDetail { param($r) if ($r.Online) { "MECM=$(if($r.UpdatesOK){$r.UpdateCount}else{'Error'}) WU=$(if($r.WuOK){$r.WuCount}else{'Error'}) Apps=$(if($r.AppsOK){$r.AppCount}else{'Error'})" } elseif ($r.Error) { $r.Error } else { 'offline' } } `
                -RowOf { param($r)
                    # Desktop parity (12301-12306): a channel whose query failed renders
                    # the literal 'Error' instead of a silent 0, and the failures also
                    # aggregate into the Error column so 0-with-failure is unmistakable.
                    # Offline rows keep their plain defaults (Online=false says it all).
                    $cell = { param($ok, $val) if (-not $r.Online) { $val } elseif ($ok) { $val } else { 'Error' } }
                    $err = [string]$r.Error
                    if ($r.Online) {
                        $chFail = @()
                        if (-not $r.DriveOK)   { $chFail += 'Drive' }
                        if (-not $r.RebootOK)  { $chFail += 'Reboot' }
                        if (-not $r.UpdatesOK) { $chFail += 'MECM' }
                        if (-not $r.WuOK)      { $chFail += 'WU' }
                        if (-not $r.AppsOK)    { $chFail += 'Apps' }
                        if ($chFail.Count -gt 0) {
                            $chMsg = "channel query failed: $($chFail -join ', ')"
                            $err = if ($err) { "$err | $chMsg" } else { $chMsg }
                        }
                    }
                    @{
                    Host=$r.Host; LoggedOnUser=[string]$r.LoggedOnUser; Online=[bool]$r.Online; OsName=[string]$r.OsName; OsBuild=[string]$r.OsBuild; DriveSize=(& $cell $r.DriveOK ([int]$r.DriveSize)); DriveFree=(& $cell $r.DriveOK ([int]$r.DriveFree))
                    DriveFreePercent=(& $cell $r.DriveOK ([int]$r.DrivePct)); RebootPending=(& $cell $r.RebootOK ([bool]$r.RebootPending)); LastBootTime=[string]$r.LastBoot
                    MECMUpdateCount=(& $cell $r.UpdatesOK ([int]$r.UpdateCount)); WindowsUpdateCount=(& $cell $r.WuOK ([int]$r.WuCount)); AppCount=(& $cell $r.AppsOK ([int]$r.AppCount))
                    MECMUpdates=([string]::Join('; ', @($r.UpdateNames))); WindowsUpdates=([string]::Join('; ', @($r.WuNames))); PendingApps=([string]::Join('; ', @($r.AppNames)))
                    Error=$err } }
            # Optional trend snapshot: persist one CSV per run AFTER the scan finishes.
            # Best-effort - Save-WptBulkSnapshot only warns on failure, never fails the scan.
            # A cancelled / timed-out run's rows are partial (abandoned hosts read offline
            # with zero counts), so saving them would permanently pollute the trend series
            # with a false compliance dip - skip the save with a warn instead.
            if ($saveSnap) {
                if ($scanResult.summary.cancelled -or $scanResult.summary.timedOut) {
                    & $send @{ type='log'; level='warn'; text='Snapshot NOT saved: run was cancelled/timed out - a partial scan would pollute the compliance trend.' }
                } else {
                    Save-WptBulkSnapshot -Rows $scanResult.rows -Send $send
                }
            }
            return $scanResult
        }
        'bulk-patch' {
            $threads = Get-WptThreadCount $Params 16
            # Patch posture: non-invasive (default, reboots suppressed) vs forced
            # (reboot-if-needed, customer-affecting - for quarantined hosts).
            $patchMode = ([string]$Params['mode']).ToLower(); if ($patchMode -ne 'forced') { $patchMode = 'noninvasive' }
            & $send @{ type='log'; level=$(if ($patchMode -eq 'forced') { 'warn' } else { 'info' }); text="Patch posture: $(if ($patchMode -eq 'forced') { 'FORCED (reboot-if-needed - customer-affecting)' } else { 'non-invasive (reboots suppressed)' })." }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptPatchBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $patchMode) } `
                -OkOf { param($r) [bool]$r.Reachable -and [string]::IsNullOrEmpty([string]$r.Error) } `
                -AuditDetail { param($r) if ($r.Error) { $r.Error } else { "mode=$($r.Mode) updates=$($r.UpdatesTriggered) apps=$($r.AppsTriggered)" } } `
                -LogOf { param($r)
                    if ($r.Error) { @{ level='warn'; text="$($r.Host): $($r.Error)" } }
                    elseif (-not $r.Reachable) { @{ level='warn'; text="$($r.Host): unreachable - nothing triggered." } }
                    else {
                        $u = [int]$r.UpdatesTriggered; $a = [int]$r.AppsTriggered
                        if ($u -eq 0 -and $a -eq 0) { @{ level='info'; text="$($r.Host): 0 updates, 0 apps - nothing to trigger." } }
                        else { @{ level='ok'; text="$($r.Host): triggered $u update(s), $a app(s)." } }
                    }
                } `
                -RowOf { param($r) @{ Host=$r.Host; Reachable=[bool]$r.Reachable; UpdatesTriggered=[int]$r.UpdatesTriggered; AppsTriggered=[int]$r.AppsTriggered; Error=[string]$r.Error } }
        }
        'reboot' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRebootBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } `
                -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'reboot-schedule' {
            $threads = Get-WptThreadCount $Params 16
            $seconds = 900; if ($Params['seconds']) { [int]::TryParse([string]$Params['seconds'], [ref]$seconds) | Out-Null }
            if ($seconds -lt 0) { $seconds = 0 }
            $msg = [string]$Params['message']
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRebootScheduleBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $seconds, $msg) } `
                -OkOf { param($r) [bool]$r.Success } `
                -AuditDetail { param($r) if ($r.Success) { "reboot scheduled +$seconds s" } else { $r.Detail } } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; RebootAt=[string]$r.RebootAt; Detail=[string]$r.Detail } }
        }
        'reboot-abort' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRebootAbortBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } `
                -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'winrm-bootstrap' {
            $threads = Get-WptThreadCount $Params 12
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptWinRMBootstrapBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } `
                -AuditDetail { param($r) if ($r.Error) { $r.Error } else { "PostProbeOk=$($r.PostProbeOk)" } } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; PostProbeOk=[bool]$r.PostProbeOk; Steps=(@($r.Steps) -join ' | ') } }
        }
        'health-scan' {
            $threads = Get-WptThreadCount $Params 24
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send -PerHostTimeoutSeconds 300 `
                -Work $script:WptHealthScanBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) ($r.Overall -ne 'Offline' -and $r.Overall -ne 'Broken' -and [string]::IsNullOrEmpty([string]$r.Error)) } `
                -AuditDetail { param($r) "Overall=$($r.Overall) MECM=$($r.MecmState) WU=$($r.WuState)" } `
                -RowOf { param($r) @{
                    Host=$r.Host; MecmState=[string]$r.MecmState; ClientVersion=[string]$r.ClientVer; SwCenter=[string]$r.SwCenter; WmiHealth=[string]$r.WmiState
                    WuState=[string]$r.WuState; RebootPending=[string]$r.RebootState; RebootAge=[string]$r.RebootAge
                    LastCheckIn=[string]$r.LastCheckIn; OverallHealth=[string]$r.Overall } }
        }
        'healer-restart-ccm' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRestartCcmBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'healer-wmi-repair' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptWmiRepairBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'healer-wu-reset' {
            $threads = Get-WptThreadCount $Params 12
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptWuResetBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'healer-trigger-checkin' {
            $threads = Get-WptThreadCount $Params 24
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptTriggerCheckInBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'healer-gpupdate' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptGpUpdateBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'healer-ccm-repair' {
            $threads = Get-WptThreadCount $Params 12
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send -PerHostTimeoutSeconds 200 `
                -Work $script:WptCcmRepairBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'app-action' {
            $threads = Get-WptThreadCount $Params 12
            $method = ([string]$Params['method']).Trim(); if ([string]::IsNullOrWhiteSpace($method)) { $method = 'Install' }
            $validMethods = @('Install','Uninstall','Reinstall','Repair')
            if ($validMethods -notcontains $method) {
                & $send @{ type='log'; level='warn'; text="Method '$method' invalid. Use one of: $($validMethods -join ', ')." }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
            # Accept ONE app ('appid') or MANY ('appids', one per line) so the SCCM App
            # Manager grid can act on every checked app in a single run. Revision +
            # machine/user targeting are resolved per-host from the live catalog inside
            # WptAppActionBlock, so only the Id is required.
            $idsRaw = New-Object System.Collections.ArrayList
            if ($Params.ContainsKey('appids') -and $Params['appids']) { foreach ($x in ([string]$Params['appids'] -split "[`r`n,;]+")) { [void]$idsRaw.Add($x) } }
            if ($Params.ContainsKey('appid')  -and $Params['appid'])  { [void]$idsRaw.Add([string]$Params['appid']) }
            $appIds = @($idsRaw | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
            if ($appIds.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='At least one CCM_Application Id is required (get it from Software Center Apps).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $revision = ([string]$Params['revision']).Trim()
            $isMachine = $true
            if ($Params.ContainsKey('ismachinetarget') -and $null -ne $Params['ismachinetarget']) { $isMachine = [bool]$Params['ismachinetarget'] }
            # One operation per (host x app); emit a row per operation. Bespoke harvest
            # because the shared fan-out is one-row-per-host (mirrors kb-scan's expansion).
            $units = New-Object System.Collections.ArrayList
            foreach ($h in $targets) { foreach ($id in $appIds) { [void]$units.Add(@{ Host=$h; Id=$id }) } }
            & $send @{ type='status'; text="$method on $($appIds.Count) app(s) across $($targets.Count) host(s) = $($units.Count) operation(s) with $threads thread(s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($u in $units) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptAppActionBlock).AddArgument($u.Host).AddArgument($Credential).AddArgument($auth).AddArgument($u.Id).AddArgument($revision).AddArgument($isMachine).AddArgument($method).AddArgument($u.Id)
                [void]$jobs.Add([pscustomobject]@{ Host=$u.Host; Id=$u.Id; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0
            $deadline = (Get-Date).AddSeconds(3600); $cancelled = $false; $timedOut = $false
            $perHostTimeout = 300   # per-host watchdog: abandon a single (host x app) trigger wedged on a WMI/CIM call so it can't pin a worker thread for the whole batch
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; App=$j.Id; Method=$method; Result='Failed'; Detail="worker error: $($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($null -eq $res) { $res = @{ Host=$j.Host; App=$j.Id; Method=$method; Result='Failed'; Detail='no result' } }
                            $ok = ($res.Result -eq 'Triggered')
                            if ($ok) { $okCount++ } else { $failCount++ }
                            $row = @{ Host=[string]$res.Host; App=[string]$res.App; Method=[string]$res.Method; Result=[string]$res.Result; Detail=[string]$res.Detail }
                            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                            & $send @{ type='audit'; action='VulnPatched'; target=$res.Host; result=$(if($ok){'Success'}else{'Failure'}); itemCount=$(if($ok){1}else{0}); detail="$($res.Method) $($res.App): $($res.Detail)" }
                            $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($perHostTimeout -gt 0 -and $done -lt $jobs.Count) {
                        $nowPh = Get-Date
                        foreach ($j in $jobs) {
                            if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                                try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                                $detPh = "per-host timeout (${perHostTimeout}s) - possible WMI/CIM hang"
                                $row = @{ Host=$j.Host; App=$j.Id; Method=$method; Result='Failed'; Detail=$detPh }
                                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail=$detPh }
                                & $send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${perHostTimeout}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                                $failCount++; $done++
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        if     ($script:WptCancelCheck -and (& $script:WptCancelCheck)) { $cancelled = $true }
                        elseif ((Get-Date) -gt $deadline) { $timedOut = $true }
                        if ($cancelled -or $timedOut) {
                            $reason = if ($cancelled) { 'cancelled by operator' } else { 'timed out' }
                            foreach ($j in $jobs) {
                                if ($j.PS) {
                                    try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                                    $row = @{ Host=$j.Host; App=$j.Id; Method=$method; Result='Failed'; Detail=$reason }
                                    [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                    & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail=$reason }
                                    $failCount++; $done++
                                }
                            }
                            & $send @{ type='log'; level='warn'; text="Run $reason; remaining operations abandoned." }
                            break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            & $send @{ type='status'; text="Done. $okCount ok, $failCount failed of $($jobs.Count)." }
            return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount; cancelled=$cancelled; timedOut=$timedOut } }
        }
        'unsupported-scan' {
            # Bulk software scan + local cross-reference against the unsupported/SEoL
            # catalog. Bespoke harvest (one job per host runs WptSoftwareScanBlock; the
            # match is computed server-side) so it can emit MANY rows per host (one per
            # matched product) - the shared fan-out is one-row-per-host.
            $threads = Get-WptThreadCount $Params 12
            $catalog = Get-WptUnsupportedCatalog
            & $send @{ type='status'; text="Scanning $($targets.Count) host(s) for unsupported/SEoL software with $threads thread(s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $targets) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptSoftwareScanBlock).AddArgument($h).AddArgument($Credential).AddArgument($auth)
                [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $hostsOk = 0; $hostsFail = 0; $matchCount = 0
            $deadline = (Get-Date).AddSeconds(3600); $cancelled = $false; $timedOut = $false
            $perHostTimeout = 300   # per-host watchdog: abandon a single host wedged on the HKLM/HKU uninstall enumeration so it can't pin a worker thread for the whole batch
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null; $err = $null
                            try { $res = $j.PS.EndInvoke($j.Async) } catch { $err = "worker error: $($_.Exception.Message)" }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($err) {
                                $hostsFail++
                                & $send @{ type='log'; level='err'; text="$($j.Host) : $err" }
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$err }
                            } else {
                                $apps = Expand-WptSingleHostResult $res
                                $hostMatches = 0
                                foreach ($a in @($apps)) {
                                    $name = if ($a -is [hashtable]) { [string]$a['Name'] } else { [string]$a.Name }
                                    $ver  = if ($a -is [hashtable]) { [string]$a['Version'] } else { [string]$a.Version }
                                    if ([string]::IsNullOrWhiteSpace($name)) { continue }
                                    foreach ($prof in $catalog) {
                                        if (Test-WptUnsupportedMatch -AppName $name -AppVersion $ver -Prof $prof) {
                                            # SAFE effective action: a bare family-name match is Review, not auto-Uninstall.
                                            $effAction = Get-WptUnsupportedAction -Prof $prof -AppVersion $ver
                                            $row = @{
                                                _rk="$($j.Host)|$name|$ver"
                                                Host=$j.Host; Product=$prof.Label; InstalledName=$name; Version=$ver
                                                Category=$prof.Category; Action=$effAction; Notes=$prof.Notes
                                            }
                                            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                            $matchCount++; $hostMatches++
                                            break   # one row per app (first matching profile)
                                        }
                                    }
                                }
                                $hostsOk++
                                & $send @{ type='log'; level=$(if($hostMatches -gt 0){'warn'}else{'ok'}); text="$($j.Host): $hostMatches unsupported/SEoL product(s) found." }
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Success'; itemCount=$hostMatches; detail="$hostMatches unsupported match(es)" }
                            }
                            $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($perHostTimeout -gt 0 -and $done -lt $jobs.Count) {
                        $nowPh = Get-Date
                        foreach ($j in $jobs) {
                            if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                                try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null
                                $hostsFail++; $done++
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${perHostTimeout}s)" }
                                & $send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${perHostTimeout}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        if     ($script:WptCancelCheck -and (& $script:WptCancelCheck)) { $cancelled = $true }
                        elseif ((Get-Date) -gt $deadline) { $timedOut = $true }
                        if ($cancelled -or $timedOut) {
                            $reason = if ($cancelled) { 'cancelled by operator' } else { 'timed out' }
                            foreach ($j in $jobs) { if ($j.PS) { try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null; $hostsFail++; $done++; & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail="abandoned: $reason" } } }
                            & $send @{ type='log'; level='warn'; text="Run $reason; remaining hosts abandoned." }
                            break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            & $send @{ type='status'; text="Done. $matchCount unsupported match(es) across $hostsOk scanned host(s); $hostsFail failed." }
            return @{ rows=@($rows); summary=@{ matches=$matchCount; hostsScanned=$hostsOk; hostsFailed=$hostsFail; cancelled=$cancelled; timedOut=$timedOut } }
        }
        'unsupported-uninstall' {
            # Uninstall the checked unsupported products, grouped per host. 'pairs' is a
            # newline list of "HOST<TAB>AppName" filled by the scan grid's Uninstall
            # Matched button. One job per host runs WptSoftwareUninstallBlock with that
            # host's app names; one result row per (host x product).
            $threads = Get-WptThreadCount $Params 12
            $byHost = @{}
            foreach ($line in (([string]$Params['pairs']) -split "`r?`n")) {
                if ($line -notmatch "`t") { continue }
                $parts = $line -split "`t", 2
                $h = $parts[0].Trim().ToUpperInvariant(); $n = $parts[1].Trim()
                if ([string]::IsNullOrWhiteSpace($h) -or [string]::IsNullOrWhiteSpace($n)) { continue }
                if (-not $byHost.ContainsKey($h)) { $byHost[$h] = New-Object System.Collections.ArrayList }
                if (-not $byHost[$h].Contains($n)) { [void]$byHost[$h].Add($n) }
            }
            $hostList = @($byHost.Keys)
            if ($hostList.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No host/app pairs to uninstall (check Uninstall-tagged rows on the Unsupported Software Scan grid first).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $totalUnits = [int](($byHost.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum)
            & $send @{ type='status'; text="Uninstalling $totalUnits unsupported product(s) across $($hostList.Count) host(s) with $threads thread(s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $hostList) {
                $names = @($byHost[$h])
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptSoftwareUninstallBlock).AddArgument($h).AddArgument($Credential).AddArgument($auth).AddArgument($names)
                [void]$jobs.Add([pscustomobject]@{ Host=$h; Names=$names; PS=$ps; Async=$ps.BeginInvoke() })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0
            $deadline = (Get-Date).AddSeconds(3600); $cancelled = $false; $timedOut = $false
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null; $err = $null
                            try { $res = $j.PS.EndInvoke($j.Async) } catch { $err = "worker error: $($_.Exception.Message)" }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($err) {
                                foreach ($n in $j.Names) {
                                    $row = @{ _rk="$($j.Host)|$n"; Host=$j.Host; App=$n; 'Install Type'=''; Result='Failed'; Detail=$err }
                                    [void]$rows.Add($row); & $send (@{ type='row' } + $row); $failCount++
                                }
                                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail=$err }
                            } else {
                                foreach ($u in (Expand-WptSingleHostResult $res)) {
                                    $app = if ($u -is [hashtable]) { [string]$u['App'] } else { [string]$u.App }
                                    $typ = if ($u -is [hashtable]) { [string]$u['Type'] } else { [string]$u.Type }
                                    $rst = if ($u -is [hashtable]) { [string]$u['Result'] } else { [string]$u.Result }
                                    $det = if ($u -is [hashtable]) { [string]$u['Detail'] } else { [string]$u.Detail }
                                    $isOk = ($rst -eq 'Removed')
                                    if ($isOk) { $okCount++ } else { $failCount++ }
                                    $row = @{ _rk="$($j.Host)|$app"; Host=$j.Host; App=$app; 'Install Type'=$typ; Result=$rst; Detail=$det }
                                    [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                    & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result=$(if($isOk){'Success'}else{'Failure'}); itemCount=$(if($isOk){1}else{0}); detail="$app : $rst - $det" }
                                }
                            }
                            $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        if     ($script:WptCancelCheck -and (& $script:WptCancelCheck)) { $cancelled = $true }
                        elseif ((Get-Date) -gt $deadline) { $timedOut = $true }
                        if ($cancelled -or $timedOut) {
                            $reason = if ($cancelled) { 'cancelled by operator' } else { 'timed out' }
                            foreach ($j in $jobs) {
                                if ($j.PS) {
                                    try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null
                                    foreach ($n in $j.Names) {
                                        $row = @{ _rk="$($j.Host)|$n"; Host=$j.Host; App=$n; 'Install Type'=''; Result='Failed'; Detail=$reason }
                                        [void]$rows.Add($row); & $send (@{ type='row' } + $row); $failCount++
                                    }
                                    & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail="abandoned: $reason - already-dispatched removals may proceed" }
                                }
                            }
                            & $send @{ type='log'; level='warn'; text="Run $reason; remaining uninstalls abandoned (already-dispatched removals may proceed on the host)." }
                            break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            & $send @{ type='status'; text="Done. $okCount removed, $failCount failed of $totalUnits." }
            return @{ rows=@($rows); summary=@{ total=$totalUnits; ok=$okCount; failed=$failCount; cancelled=$cancelled; timedOut=$timedOut } }
        }
        'kb-install' {
            $threads = Get-WptThreadCount $Params 16
            $kbList = @(([string]$Params['kbs']) -split '[,\s;]+' | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ } | ForEach-Object { if ($_ -notmatch '^KB') { "KB$_" } else { $_ } } | Select-Object -Unique)
            if ($kbList.Count -eq 0) { & $send @{ type='log'; level='warn'; text='Enter one or more KB numbers to install.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $msuPath = ([string]$Params['msu']).Trim()
            $noReboot = $true; if ($Params.ContainsKey('noreboot') -and $null -ne $Params['noreboot']) { $noReboot = [bool]$Params['noreboot'] }
            & $send @{ type='status'; text="Installing $($kbList.Count) KB(s) on $($targets.Count) host(s)$(if($msuPath){' (MSU fallback armed)'} )..." }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptKbInstallBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $kbList, $msuPath, $noReboot) } `
                -OkOf { param($r) (@($r.Errors).Count -eq 0) } `
                -AuditDetail { param($r) "MECM=$($r.MECMInstalled) MSU=$($r.MSUInstalled) Skip=$($r.Skipped) Err=$(@($r.Errors).Count)" } `
                -RowOf { param($r) @{ Host=$r.Host; MECMFound=[int]$r.MECMFound; MECMInstalled=[int]$r.MECMInstalled; MSUInstalled=[int]$r.MSUInstalled; Skipped=[int]$r.Skipped; Result=$(if(@($r.Errors).Count -gt 0){'Errors'}elseif(($r.MECMInstalled + $r.MSUInstalled) -gt 0){'Installed'}else{'No change'}); Detail=$((@($r.Details) + @(@($r.Errors) | ForEach-Object { "ERR: $_" })) -join ' | ') } }
        }
        'kb-scan' {
            # KB scan returns one row PER hotfix per host. The fan-out harvester
            # streams one row per host, so expand the KB list into rows here by
            # streaming directly and counting hosts as the unit of success.
            $threads = Get-WptThreadCount $Params 24
            # Optional targeted-KB verdict: blank = full hotfix dump (original behavior);
            # set = one Present/Missing row per host + a fleet compliance %.
            $kbTarget = ''
            if ($Params['kb']) {
                $kbTarget = ([string]$Params['kb']).Trim().ToUpper()
                if ($kbTarget -and $kbTarget -notmatch '^KB') { $kbTarget = 'KB' + ($kbTarget -replace '[^0-9]','') }
            }
            $kbPresent = 0; $kbMissing = 0
            & $send @{ type='status'; text="Starting 'kb-scan'$(if($kbTarget){" for $kbTarget"}) on $($targets.Count) host(s) with $threads thread(s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $targets) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptKbScanBlock).AddArgument($h).AddArgument($Credential).AddArgument($auth)
                [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0
            $deadline = (Get-Date).AddSeconds(900)   # wall-clock backstop so a wedged host can't hang the job forever
            $perHostTimeout = 300   # per-host watchdog: abandon a single host wedged on a WMI/CIM call so it can't pin a worker thread for the whole batch
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; KBs=@(); Error="worker error: $($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($null -eq $res) { $res = @{ Host=$j.Host; KBs=@(); Error='no result' } }
                            $kbArr = @($res.KBs); $hostOk = [string]::IsNullOrWhiteSpace([string]$res.Error)
                            if ($hostOk) { $okCount++ } else { $failCount++ }
                            if ($hostOk -and $kbTarget) {
                                # Targeted verdict: one row per host, Present/Missing for the KB.
                                $hit = $null
                                foreach ($kb in $kbArr) {
                                    $kbID = if ($kb -is [hashtable]) { [string]$kb['HotFixID'] } else { [string]$kb.HotFixID }
                                    if ($kbID -and ($kbID.Trim().ToUpper() -eq $kbTarget)) { $hit = $kb; break }
                                }
                                if ($hit) {
                                    $kbOn = if ($hit -is [hashtable]) { [string]$hit['InstalledOn'] } else { [string]$hit.InstalledOn }
                                    $kbBy = if ($hit -is [hashtable]) { [string]$hit['InstalledBy'] } else { [string]$hit.InstalledBy }
                                    $row = @{ _rk="$($res.Host)|$kbTarget"; Host=$res.Host; HotFixID=$kbTarget; Description='Present'; InstalledOn=$kbOn; InstalledBy=$kbBy }
                                    $kbPresent++
                                } else {
                                    $row = @{ _rk="$($res.Host)|$kbTarget"; Host=$res.Host; HotFixID=$kbTarget; Description='Missing'; InstalledOn=''; InstalledBy='' }
                                    $kbMissing++
                                }
                                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                            } elseif ($hostOk) {
                                foreach ($kb in $kbArr) {
                                    $kbID  = if ($kb -is [hashtable]) { [string]$kb['HotFixID'] } else { [string]$kb.HotFixID }
                                    $kbDes = if ($kb -is [hashtable]) { [string]$kb['Description'] } else { [string]$kb.Description }
                                    $kbOn  = if ($kb -is [hashtable]) { [string]$kb['InstalledOn'] } else { [string]$kb.InstalledOn }
                                    $kbBy  = if ($kb -is [hashtable]) { [string]$kb['InstalledBy'] } else { [string]$kb.InstalledBy }
                                    $row = @{ _rk="$($res.Host)|$kbID"; Host=$res.Host; HotFixID=$kbID; Description=$kbDes; InstalledOn=$kbOn; InstalledBy=$kbBy }
                                    [void]$rows.Add($row)
                                    & $send (@{ type='row' } + $row)
                                }
                            } else {
                                & $send @{ type='log'; level='err'; text="$($res.Host) : $($res.Error)" }
                            }
                            & $send @{ type='audit'; action='TouchHost'; target=$res.Host; result=$(if($hostOk){'Success'}else{'Failure'}); itemCount=$kbArr.Count; detail=$(if($hostOk){"$($kbArr.Count) KB(s)"}else{[string]$res.Error}) }
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($perHostTimeout -gt 0 -and $done -lt $jobs.Count) {
                        $nowPh = Get-Date
                        foreach ($j in $jobs) {
                            if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                                try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null
                                $failCount++; $done++
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${perHostTimeout}s)" }
                                & $send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${perHostTimeout}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        $cancel = ($script:WptCancelCheck -and (& $script:WptCancelCheck))
                        $expired = ((Get-Date) -gt $deadline)
                        if ($cancel -or $expired) {
                            $reason = if ($cancel) { 'cancelled by operator' } else { 'timed out (deadline)' }
                            # BeginStop + null only (no Dispose - it blocks ~11s/host); the pool teardown in the finally reclaims the children.
                            foreach ($j in $jobs) { if ($j.PS) { try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null; $failCount++; $done++; & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$reason } } }
                            & $send @{ type='log'; level='warn'; text="kb-scan $reason; remaining host(s) abandoned (in-flight calls stopped)." }; break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            if ($kbTarget) {
                $reach = $kbPresent + $kbMissing
                $pct  = if ($targets.Count -gt 0) { [math]::Round(($kbPresent / $targets.Count) * 100, 1) } else { 0 }
                $pctM = if ($reach -gt 0) { [math]::Round(($kbPresent / $reach) * 100, 1) } else { 0 }
                & $send @{ type='log'; level='ok'; text="$kbTarget presence - Fleet: $pct% ($kbPresent/$($targets.Count)) | Measured: $pctM% ($kbPresent/$reach reachable). Missing: $kbMissing, unreachable: $failCount." }
                & $send @{ type='status'; text="Done. $kbTarget present on $kbPresent, missing on $kbMissing, $failCount unreachable of $($targets.Count)." }
                return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount; kbTarget=$kbTarget; present=$kbPresent; missing=$kbMissing; fleetPct=$pct; measuredPct=$pctM } }
            }
            & $send @{ type='status'; text="Done. $okCount host(s) scanned, $failCount failed; $($rows.Count) KB row(s)." }
            return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount; kbRows=$rows.Count } }
        }
        'kb-trigger-mecm' {
            $threads = Get-WptThreadCount $Params 24
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptKbTriggerBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Status } `
                -RowOf { param($r) @{ Host=$r.Host; Status=[string]$r.Status } }
        }
        'kb-push-download' {
            $threads = Get-WptThreadCount $Params 24
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptKbPushDownloadBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Status } `
                -RowOf { param($r) @{ Host=$r.Host; PendingCount=[int]$r.PendingCount; Status=[string]$r.Status } }
        }
        'verify-patch' {
            # Read-only SCCM verification: one row PER host+update. The fan-out
            # harvester streams one row per host, so (like kb-scan) expand the
            # per-update records here, streaming directly and counting hosts as
            # the unit of success.
            $threads = Get-WptThreadCount $Params 12
            $kbFilter = ''
            if ($Params.ContainsKey('kbFilter') -and $Params['kbFilter']) { $kbFilter = ([string]$Params['kbFilter']).Trim() }
            $maxPolls = 6
            if ($Params.ContainsKey('maxPolls') -and -not [string]::IsNullOrWhiteSpace([string]$Params['maxPolls'])) { [int]::TryParse([string]$Params['maxPolls'], [ref]$maxPolls) | Out-Null }
            if ($maxPolls -lt 1) { $maxPolls = 1 }
            if ($maxPolls -gt 60) { $maxPolls = 60 }   # ceiling: guard a typo from sleeping for hours
            $interval = 30
            if ($Params.ContainsKey('intervalSeconds') -and -not [string]::IsNullOrWhiteSpace([string]$Params['intervalSeconds'])) { [int]::TryParse([string]$Params['intervalSeconds'], [ref]$interval) | Out-Null }
            if ($interval -lt 1) { $interval = 1 }
            if ($interval -gt 600) { $interval = 600 }   # ceiling: max 10 min between polls
            & $send @{ type='status'; text="Starting 'verify-patch' on $($targets.Count) host(s) with $threads thread(s) (up to $maxPolls poll(s) every ${interval}s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $targets) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptVerifyPatchBlock).AddArgument($h).AddArgument($Credential).AddArgument($auth).AddArgument($kbFilter).AddArgument($maxPolls).AddArgument($interval)
                [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke() })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0; $updRows = 0
            $deadline = (Get-Date).AddSeconds(($maxPolls * $interval) + 600)   # wall-clock backstop > the longest host poll budget
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; Updates=@(); Error="worker error: $($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($null -eq $res) { $res = @{ Host=$j.Host; Updates=@(); Error='no result' } }
                            $hostOk = [string]::IsNullOrWhiteSpace([string]$res.Error)
                            if ($hostOk) { $okCount++ } else { $failCount++ }
                            $ups = @($res.Updates)
                            if ($hostOk -and $ups.Count -gt 0) {
                                foreach ($u in $ups) {
                                    $un  = if ($u -is [hashtable]) { [string]$u['Update'] } else { [string]$u.Update }
                                    $ust = if ($u -is [hashtable]) { [string]$u['State'] }  else { [string]$u.State }
                                    $uss = if ($u -is [hashtable]) { [string]$u['Status'] } else { [string]$u.Status }
                                    $row = @{ _rk="$($res.Host)|$un"; Host=$res.Host; Update=$un; State=$ust; Status=$uss }
                                    [void]$rows.Add($row); & $send (@{ type='row' } + $row); $updRows++
                                }
                            } elseif ($hostOk) {
                                $msg = if ($res.NoSccm) { 'no SCCM client (root\ccm absent)' } else { 'no matching updates' }
                                & $send @{ type='log'; level='info'; text="$($res.Host) : $msg" }
                            } else {
                                & $send @{ type='log'; level='err'; text="$($res.Host) : $($res.Error)" }
                            }
                            $aDetail = if ($hostOk) { if ($res.NoSccm) { 'no SCCM client' } else { "$($ups.Count) update(s)" } } else { [string]$res.Error }
                            & $send @{ type='audit'; action='TouchHost'; target=$res.Host; result=$(if($hostOk){'Success'}else{'Failure'}); itemCount=$ups.Count; detail=$aDetail }
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        $cancel = ($script:WptCancelCheck -and (& $script:WptCancelCheck))
                        $expired = ((Get-Date) -gt $deadline)
                        if ($cancel -or $expired) {
                            $reason = if ($cancel) { 'cancelled by operator' } else { 'timed out (deadline)' }
                            foreach ($j in $jobs) { if ($j.PS) { try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null; $failCount++; $done++; & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$reason } } }
                            & $send @{ type='log'; level='warn'; text="verify-patch $reason; remaining host(s) abandoned (in-flight calls stopped)." }; break
                        }
                        Start-Sleep -Milliseconds 200
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            & $send @{ type='status'; text="Done. $okCount host(s) verified, $failCount failed; $updRows update row(s)." }
            return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount; updateRows=$updRows } }
        }
        'remote-message' {
            $threads = Get-WptThreadCount $Params 16
            $title = [string]$Params['title']; $body = [string]$Params['body']
            if ([string]::IsNullOrWhiteSpace($title) -or [string]::IsNullOrWhiteSpace($body)) {
                & $send @{ type='log'; level='warn'; text='Title and message are both required.' }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
            $timeout = 300; if ($Params['timeout']) { [int]::TryParse([string]$Params['timeout'], [ref]$timeout) | Out-Null }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptMessageBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $title, $body, $timeout) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Status=$(if($r.Success){'Delivered'}else{'Failed'}); Detail=[string]$r.Detail } }
        }
        'cleanup-disk' {
            $threads = Get-WptThreadCount $Params 12
            $op = ([string]$Params['operation']).Trim()
            $doTemp = ($op -match 'Temp' -or $op -match 'Both' -or [string]::IsNullOrWhiteSpace($op))
            $doProf = ($op -match 'Profile' -or $op -match 'Old' -or $op -match 'Both')
            $doCache = ($op -match 'Cache')
            if (-not $doTemp -and -not $doProf -and -not $doCache) { $doTemp = $true }
            $days = 60; $daysParsed = 0; if ($Params.ContainsKey('days') -and -not [string]::IsNullOrWhiteSpace([string]$Params['days']) -and [int]::TryParse([string]$Params['days'], [ref]$daysParsed)) { $days = $daysParsed }
            $dry = $true
            if ($Params.ContainsKey('dryrun') -and $null -ne $Params['dryrun']) { $dry = [bool]$Params['dryrun'] }
            $auditAct = if ($dry) { 'TouchHost' } else { 'VulnPatched' }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptCleanBlock -AuditAction $auditAct `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $doTemp, $doProf, $days, $dry, $doCache) } `
                -OkOf { param($r) ($r.Status -eq 'Success' -or $r.Status -eq 'Dry Run OK') } `
                -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r)
                    # Replay the per-profile events the remote block buffered, so the
                    # operator sees WHICH profiles would be / were deleted per host.
                    # ($null = ... : RowOf output is captured as the row, so the send
                    # calls must not leak anything into the pipeline.)
                    if ($r.Events) {
                        foreach ($e in @($r.Events)) {
                            # Map remote-block levels to the UI's log classes. ok/warn/err have
                            # distinct colors (janet.css); INFO/ACTION fall through to default.
                            $lvl = switch ([string]$e.Level) {
                                'ERR'    { 'err' }
                                'WARN'   { 'warn' }
                                'OK'     { 'ok' }
                                'DELETE' { 'ok' }
                                default  { 'info' }
                            }
                            $null = (& $send @{ type='log'; level=$lvl; text=[string]$e.Msg })
                        }
                    }
                    @{ Host=$r.Host; TempMB=[double]$r.TempMB; TempFiles=[int]$r.TempFiles; CacheMB=[double]$r.CacheMB; ProfilesFound=[int]$r.ProfilesFound; ProfilesRemoved=[int]$r.ProfilesRemoved; Skipped=[int]$r.Skipped; FreedMB=[double]$r.FreedMB; FreeAfterGB=[double]$r.FreeAfterGB; Status=[string]$r.Status; Detail=[string]$r.Detail } }
        }
        'clean-user-apps' {
            $threads = Get-WptThreadCount $Params 12
            $apps = New-Object System.Collections.ArrayList
            foreach ($a in 'chrome','firefox','zoom','teams','webex') { if ($Params.ContainsKey($a) -and [bool]$Params[$a]) { [void]$apps.Add($a) } }
            if ($apps.Count -eq 0) { & $send @{ type='log'; level='warn'; text='Select at least one app to clean.' }; return @{ rows=@(); summary=@{ total=$targets.Count } } }
            $appsCsv = (@($apps)) -join ','
            $dry = $true; if ($Params.ContainsKey('dryrun') -and $null -ne $Params['dryrun']) { $dry = [bool]$Params['dryrun'] }
            $auditAct = if ($dry) { 'TouchHost' } else { 'VulnPatched' }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send -PerHostTimeoutSeconds 300 `
                -Work $script:WptCleanUserAppsBlock -AuditAction $auditAct `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $appsCsv, $dry) } `
                -OkOf { param($r) ($r.Status -eq 'Success' -or $r.Status -eq 'Dry Run OK') } `
                -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r)
                    if ($r.Events) {
                        foreach ($e in @($r.Events)) {
                            $lvl = switch ([string]$e.Level) { 'ERR' { 'err' } 'WARN' { 'warn' } 'DELETE' { 'ok' } default { 'info' } }
                            $null = (& $send @{ type='log'; level=$lvl; text=[string]$e.Msg })
                        }
                    }
                    @{ Host=$r.Host; Removed=[int]$r.AppsRemoved; FreedMB=[double]$r.FreedMB; Status=[string]$r.Status; Detail=[string]$r.Detail } }
        }
        'maintenance-lock' {
            $threads = Get-WptThreadCount $Params 16
            $caption = [string]$Params['caption']; if ([string]::IsNullOrWhiteSpace($caption)) { $caption = 'System Maintenance' }
            $message = [string]$Params['message']; if ([string]::IsNullOrWhiteSpace($message)) { $message = 'This workstation is undergoing scheduled maintenance. Please do not log in until maintenance is complete.' }
            $hardlock = $false; if ($Params.ContainsKey('hardlock') -and $null -ne $Params['hardlock']) { $hardlock = [bool]$Params['hardlock'] }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptMaintLockBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $caption, $message, $hardlock) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) "$($r.Mode): $($r.Detail)" } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Mode=[string]$r.Mode; Detail=[string]$r.Detail } }
        }
        'maintenance-unlock' {
            $threads = Get-WptThreadCount $Params 16
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptMaintUnlockBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth) } `
                -OkOf { param($r) [bool]$r.Success } -AuditDetail { param($r) $r.Detail } `
                -RowOf { param($r) @{ Host=$r.Host; Success=[bool]$r.Success; Detail=[string]$r.Detail } }
        }
        'registry-key-scan' {
            $threads = Get-WptThreadCount $Params 24
            $catalog = Get-WptRegKeyCatalog
            $key = ([string]$Params['cvekey']).Trim()
            if (-not $catalog.Contains($key)) {
                & $send @{ type='log'; level='warn'; text="Unknown catalog key '$key'. Valid: $((@($catalog.Keys)) -join ', ')" }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
            $entry = $catalog[$key]; $regPath = $entry.RegPath; $defs = $entry.Defs
            $expectedStr = (($defs | ForEach-Object { if ($null -ne $_.OrBits) { "$($_.Name)|0x$('{0:X}' -f [int]$_.OrBits)" } else { "$($_.Name)=$($_.Expected)" } }) -join '; ')
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRegScanBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $regPath, $defs) } `
                -OkOf { param($r) ($r.Reachable -and $r.Status -ne 'Error') } `
                -AuditDetail { param($r) if ($r.Error) { $r.Error } else { $r.Status } } `
                -RowOf { param($r)
                    $curStr = if ($r.RegValues -and $r.RegValues.Count -gt 0) { (($r.RegValues.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ') } else { '' }
                    @{ Host=$r.Host; RegPath=$regPath; CurrentValue=$curStr; ExpectedValue=$expectedStr; Compliant=$(if($r.Status -eq 'Patched'){'Yes'}elseif($r.Reachable){'No'}else{'?'}); Status=[string]$r.Status } }
        }
        'registry-key-apply' {
            $threads = Get-WptThreadCount $Params 16
            $catalog = Get-WptRegKeyCatalog
            $key = ([string]$Params['cvekey']).Trim()
            if (-not $catalog.Contains($key)) {
                & $send @{ type='log'; level='warn'; text="Unknown catalog key '$key'. Valid: $((@($catalog.Keys)) -join ', ')" }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
            $entry = $catalog[$key]; $regPath = $entry.RegPath; $defs = $entry.Defs
            $cveLabel = [string]$entry.DisplayName
            $rebootAfter = $false; if ($Params.ContainsKey('rebootafter') -and $null -ne $Params['rebootafter']) { $rebootAfter = [bool]$Params['rebootafter'] }
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptRegApplyBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $regPath, $defs, $rebootAfter, $cveLabel) } `
                -OkOf { param($r) [bool]$r.Success } `
                -AuditDetail { param($r) if ($r.Error) { $r.Error } elseif ($r.RebootScheduled) { 'applied; reboot scheduled (1h)' } else { 'applied' } } `
                -RowOf { param($r)
                    $newStr = if ($r.PostValues -and $r.PostValues.Count -gt 0) { (($r.PostValues.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ') } else { '' }
                    @{ Host=$r.Host; RegPath=$regPath; NewValue=$newStr; Reboot=$(if($r.RebootScheduled){'Scheduled (1h)'}elseif($rebootAfter -and $r.Success){'Schedule failed'}else{'No'}); Status=$(if($r.Success){'Applied'}elseif($r.Reachable){"Failed: $($r.Error)"}else{'Offline'}) } }
        }
        'app-update-verify' {
            $threads = Get-WptThreadCount $Params 16
            $profName = ([string]$Params['profile']).Trim()
            $profiles = Get-WptAppUpdateProfiles
            if (-not $profiles.ContainsKey($profName) -or -not $profiles[$profName].Verify) {
                & $send @{ type='log'; level='warn'; text="Profile '$profName' has no Verify. Known: $((@($profiles.Keys)) -join ', ')" }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
            $remote = $profiles[$profName].Verify
            $method = [string]$Params['method']; $arg = [string]$Params['arg']
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptAppUpdateBlock -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $remote, $method, $arg, $true) } `
                -OkOf { param($r) ($r.Reachable -and $r.Status -eq 'Verified') } `
                -AuditDetail { param($r) "Version=$($r.Version) LastUpdated=$($r.LastUpdated)" } `
                -RowOf { param($r) @{ Host=$r.Host; Version=[string]$r.Version; LastUpdated=[string]$r.LastUpdated; Verified=$(if($null -eq $r.Verified){'n/a'}elseif($r.Verified){'Yes'}else{'No'}); Detail=[string]$r.Detail } }
        }
        'app-update-apply' {
            $threads = Get-WptThreadCount $Params 16
            $profName = ([string]$Params['profile']).Trim()
            $remote = $null
            $cmdAuditTag = ''   # appended to each host's audit Detail for Custom Command forensics
            if ($profName -eq 'Custom Command') {
                $cmd = ([string]$Params['customcommand']).Trim()
                if ([string]::IsNullOrWhiteSpace($cmd)) {
                    & $send @{ type='log'; level='warn'; text='Custom Command profile requires a customcommand.' }
                    return @{ rows=@(); summary=@{ total=$targets.Count } }
                }
                try { $remote = [scriptblock]::Create($cmd) } catch {
                    & $send @{ type='log'; level='err'; text="Custom command failed to parse: $($_.Exception.Message)" }
                    return @{ rows=@(); summary=@{ total=$targets.Count } }
                }
                # Forensic record: arbitrary operator text is about to fan out to a remote
                # scriptblock. Audit the command body (truncated) once up front, and stamp a
                # short hash + preview into every per-host audit Detail so post-hoc review can
                # reconstruct exactly what ran. Audit only - does not block the run.
                $cmdFlat = ($cmd -replace '\s+', ' ').Trim()
                $cmdHash = try {
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    $hb  = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($cmd))
                    $sha.Dispose()
                    (-join ($hb[0..5] | ForEach-Object { $_.ToString('x2') }))
                } catch { 'nohash' }
                $cmdPreview = if ($cmdFlat.Length -gt 200) { $cmdFlat.Substring(0, 200) + '...' } else { $cmdFlat }
                $cmdAuditTag = " | cmd sha256:$cmdHash `"$cmdPreview`""
                $cmdLogText = if ($cmdFlat.Length -gt 500) { $cmdFlat.Substring(0, 500) + '... (truncated)' } else { $cmdFlat }
                & $send @{ type='log'; level='warn'; text="Custom Command (sha256:$cmdHash) fanning out to $($targets.Count) host(s): $cmdLogText" }
                & $send @{ type='audit'; action='VulnPatched'; target='(custom command)'; result='Skipped'; itemCount=0; detail="Custom Command queued for $($targets.Count) host(s) (pre-run forensic record; per-host audits carry the real result); sha256:$cmdHash; body: $cmdLogText" }
            } else {
                $profiles = Get-WptAppUpdateProfiles
                if (-not $profiles.ContainsKey($profName) -or -not $profiles[$profName].Script) {
                    & $send @{ type='log'; level='warn'; text="Profile '$profName' has no Script. Known: $((@($profiles.Keys)) -join ', '), Custom Command" }
                    return @{ rows=@(); summary=@{ total=$targets.Count } }
                }
                # NeedsStaging profiles (e.g. Log4j) hard-code a controller-side UNC the
                # remote host would reach back to itself - a Kerberos double-hop that
                # silently fails or uses un-staged jars. WPT has no -ToSession staging
                # path; refuse and point at the ACAS Auto-Patch flow, which stages the
                # jars into each session correctly.
                if ($profiles[$profName].NeedsStaging) {
                    & $send @{ type='log'; level='err'; text="Profile '$profName' needs controller-side staging (the remote host can't reach the jar share directly - double-hop). Run it from ACAS Nemesis -> Remediation (Log4j), which stages the 2.25.4 jars into each session." }
                    return @{ rows=@(); summary=@{ total=$targets.Count; failed=$targets.Count } }
                }
                $remote = $profiles[$profName].Script
            }
            $method = [string]$Params['method']; $arg = [string]$Params['arg']
            return Invoke-WptFanOut -Targets $targets -Threads $threads -ActionId $ActionId -Send $send `
                -Work $script:WptAppUpdateBlock -AuditAction 'VulnPatched' `
                -ArgFactory { param($h) ,@($h, $Credential, $auth, $remote, $method, $arg, $false) } `
                -OkOf { param($r) ($r.Status -eq 'OK') } `
                -AuditDetail ({ param($r) "$($r.Detail)$cmdAuditTag" }.GetNewClosure()) `
                -RowOf { param($r) @{ Host=$r.Host; Status=[string]$r.Status; Detail=[string]$r.Detail } }
        }
        'log4j-scanner' {
            # One row per discovered jar; success counted per host.
            $threads = Get-WptThreadCount $Params 12
            & $send @{ type='status'; text="Starting 'log4j-scanner' on $($targets.Count) host(s) with $threads thread(s)..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
            $pool.Open()
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $targets) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($script:WptLog4jBlock).AddArgument($h).AddArgument($Credential).AddArgument($auth)
                [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
            }
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0; $vulnTotal = 0
            $deadline = (Get-Date).AddSeconds(1800)   # log4j recursive scan is slower; 30-min backstop per job
            $perHostTimeout = 300   # per-host watchdog: abandon a single host wedged on the Program Files/Users/Java jar tree walk so it can't pin a worker thread for the whole batch
            try {
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; ScanOK=$false; Jars=@(); Error="worker error: $($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}; $j.PS = $null
                            if ($null -eq $res) { $res = @{ Host=$j.Host; ScanOK=$false; Jars=@(); Error='no result' } }
                            $hostOk = [bool]$res.ScanOK
                            if ($hostOk) { $okCount++ } else { $failCount++ }
                            $jars = @($res.Jars); $hostVuln = 0
                            foreach ($jar in $jars) {
                                $path = if ($jar -is [hashtable]) { [string]$jar['Path'] } else { [string]$jar.Path }
                                $fn   = if ($jar -is [hashtable]) { [string]$jar['Filename'] } else { [string]$jar.Filename }
                                $ver  = if ($jar -is [hashtable]) { [string]$jar['Version'] } else { [string]$jar.Version }
                                $state = Get-WptLog4jVulnState $ver
                                if ($state -eq 'Vulnerable') { $hostVuln++; $vulnTotal++ }
                                $row = @{ _rk="$($res.Host)|$path"; Host=$res.Host; JARPath=$path; Filename=$fn; VulnerableVersion=$(if($state -eq 'Patched'){"$ver (patched)"}elseif($state -eq 'Unknown'){"$ver (unknown)"}else{$ver}) }
                                [void]$rows.Add($row)
                                & $send (@{ type='row' } + $row)
                            }
                            if (-not $hostOk -and $res.Error) { & $send @{ type='log'; level='err'; text="$($res.Host) : $($res.Error)" } }
                            & $send @{ type='audit'; action='TouchHost'; target=$res.Host; result=$(if($hostOk){'Success'}else{'Failure'}); itemCount=$jars.Count; detail=$(if($hostOk){"$($jars.Count) jar(s), $hostVuln vulnerable"}else{[string]$res.Error}) }
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($perHostTimeout -gt 0 -and $done -lt $jobs.Count) {
                        $nowPh = Get-Date
                        foreach ($j in $jobs) {
                            if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                                try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null
                                $failCount++; $done++
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${perHostTimeout}s)" }
                                & $send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${perHostTimeout}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                    }
                    if ($done -lt $jobs.Count) {
                        $cancel = ($script:WptCancelCheck -and (& $script:WptCancelCheck))
                        $expired = ((Get-Date) -gt $deadline)
                        if ($cancel -or $expired) {
                            $reason = if ($cancel) { 'cancelled by operator' } else { 'timed out (deadline)' }
                            # BeginStop + null only (no Dispose - it blocks ~11s/host); the pool teardown in the finally reclaims the children.
                            foreach ($j in $jobs) { if ($j.PS) { try { [void]$j.PS.BeginStop($null,$null) } catch {}; $j.PS=$null; $failCount++; $done++; & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$reason } } }
                            & $send @{ type='log'; level='warn'; text="log4j-scanner $reason; remaining host(s) abandoned (in-flight calls stopped)." }; break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally { try { $pool.Close(); $pool.Dispose() } catch {} }
            & $send @{ type='status'; text="Done. $okCount host(s) scanned, $failCount failed; $($rows.Count) jar(s), $vulnTotal vulnerable." }
            return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount; jars=$rows.Count; vulnerable=$vulnTotal } }
        }
        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
