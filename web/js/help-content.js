/* ============================================================================
   help-content.js  ->  window.JANETWEB_HELP
   Per-tool / per-tab "How to use" copy, shown in the noteworthy purple .j-howto
   box atop every tool by shell.js. Brief by design - one or two sentences:
   what to do, how to patch, and the read-only / DESTRUCTIVE flag.

   Shape (matches how shell.js + TabHost read it):
     - Single-flow tools  -> a plain string (shown as-is).
     - Multi-tab tools    -> { _overview, <tabId>: '...' }. openTool shows
       _overview; TabHost calls Janet.howtoTab(toolId, tabId) on each tab
       switch to swap in that tab's blurb (falls back to _overview).
     Tab ids must match the TabHost tab ids in the matching view.

   Distilled from JANET ONE's web/js/help-content.js + the desktop tools'
   How-To text (both referenced, NOT modified). <b> marks the key safety word.
   Data only - no logic. Add a tab = add a key under its tool.
   ========================================================================== */
(function () {
  'use strict';
  window.JANETWEB_HELP = {

    /* ---- multi-tab tools (per-tab guidance, swapped by TabHost) ---------- */

    wpt: {
      _overview: 'The Workstation Patching Tool scans, patches, and repairs Windows hosts in parallel. Some tabs are <b>Read-only</b> (triage); others are <b>Destructive</b> (install / uninstall / reboot). Load <b>Targets</b> first.',
      targets: 'Set Credentials and load <b>Targets</b> - the shared host list every tab uses. Paste hostnames, Import TXT / CSV, or <b>Import from AD (OU)</b> - query Active Directory and add computers by OU, unchecking OUs to exclude (remembered per browser). <b>Read-only</b>; nothing is touched until you act on another tab.',
      bulk: '<b>Read-only</b> parallel scan: online status, logged-on user, C: free %, reboot-pending, and MECM / Windows Update / app pending counts. Select hosts with updates, then <b>Patch Selected</b>, <b>Reboot Selected</b>, or <b>Repair WinRM</b> below the grid. <b>Destructive</b> once you patch.',
      software: 'Single-host software inventory (MSI / EXE / Store) with filter, plus <b>Scan Detail</b> for named pending items. Check apps and <b>Uninstall Checked</b> via the native uninstaller. <b>Read-only</b> to scan; <b>Destructive</b> on uninstall.',
      sccm: 'Query one host\'s MECM Software Center catalog, check app(s), then <b>Install</b> / <b>Uninstall</b> / <b>Reinstall</b> / <b>Repair</b> across all targets. <b>Destructive</b> - scan one host before pushing to the fleet.',
      available: 'One host, everything MECM has <b>available</b> in one list - applicable Software Center apps + pending updates (already-installed auto-unchecked). Check what to push, then <b>Install Checked</b> (apps via Software Center, updates via the Software Updates agent). <b>Destructive</b> on install.',
      kb: '<b>Read-only</b> Get-HotFix inventory (one row per host x KB). Leave <b>Target KB</b> blank to list all hotfixes, or enter one KB for a per-host <b>Present/Missing</b> verdict + fleet compliance % ("did the cumulative land everywhere?"). <b>Trigger MECM Cycles</b> and <b>Push & Download</b> to refresh update state, or <b>Install KBs</b> by number (MECM-first, .msu fallback). <b>Destructive</b> on install.',
      appupd: 'Pick an app-update profile (Office, Defender, <b>Trellix / McAfee</b>, Chrome (Software Center or direct Google Update), Edge, Java, Log4j...), <b>VERIFY</b> (read-only) installed versions across the fleet, then <b>APPLY</b> to remediate - or run a Custom Command. <b>Destructive</b> on apply.',
      beta: '<b>Experimental, AFNET-unproven</b> fixes. Pick a beta profile (Adobe, SMB Signing, RDP NLA, ICMP block), read <b>How to</b>, <b>VERIFY</b> (read-only), test one host, then <b>APPLY</b>. <b>Destructive</b>.',
      cleanup: '<b>Destructive</b> temp-file cleanup, MECM cache (<b>ccmcache</b>) purge, and / or stale-profile removal by age. <b>DRY RUN defaults ON</b> (enumerate only). Preview, then uncheck to permanently delete.',
      cleanapps: '<b>Destructive</b> per-profile removal of user-installed app <b>binaries</b> (Chrome / Firefox / Zoom / Teams / Webex) - kills the app, deletes its per-user program folder, <b>preserves user data</b>. Targets orphaned per-user installs that show as outdated ACAS findings. <b>DRY RUN defaults ON</b>.',
      regkey: 'Pick a STIG / CVE registry fix from the catalog (e.g. BHI, Edge search-engine import): read current values and compare to expected. <b>Read-only</b> on scan; <b>APPLY FIX</b> writes then reads back. <b>Destructive</b> on apply.',
      unsupported: '<b>Read-only</b> cross-reference of each host\'s software against the ACAS unsupported / SEoL catalog - returns host x product matches to Uninstall / Update / Review. Check rows, then <b>Uninstall Matched</b>. <b>Destructive</b> on uninstall.',
      log4j: '<b>Read-only</b> recursive search for log4j-*.jar across Program Files, ProgramData, Users, and Java roots. Classifies each as Patched / Vulnerable / Unknown, one row per jar per host. Changes nothing.',
      health: '<b>Read-only</b> deep diagnostics: MECM client, Software Center, WMI, Windows Update, reboot-pending age, last check-in, overall verdict. Then run one-click healers (Restart MECM, <b>Repair MECM Client</b>, Repair WMI, Reset WU...). <b>Destructive</b> on heal.',
      hostinfo: '<b>Read-only</b> single-host snapshot: model, BIOS, serial, MAC / IP, OS build, uptime, RAM, C: free, logged-on + recent users, pending reboot. First-step triage; changes nothing.',
      eventlog: '<b>Read-only</b> single-host event-log triage: recent Error + Critical entries (last N hours) from Application / System / Security (Schannel noise filtered). Changes nothing.',
      winrm: 'Bootstrap WinRM over DCOM on offline hosts: set the service Automatic, start it, run quickconfig, re-probe 5985. <b>Read-only</b> probe; <b>Destructive</b> config change. Needs an admin session.',
      reboot: 'Schedule a delayed reboot (shutdown /r /t) with warning popups every N minutes - or warnings-only with no reboot. Cancel any time before it fires; the monitor pings hosts back online afterward. <b>Destructive</b>.',
      maint: 'Put hosts into a maintenance window: set a logon banner, and optionally <b>HARD-LOCK</b> interactive logon to local Administrators only (standard users can\'t sign in). <b>UNLOCK</b> restores normal logon from a per-host backup. Admins are never locked out. <b>Destructive</b>; needs an admin session.',
      message: 'Deliver a titled popup to logged-on users via scheduled task / VBS; auto-dismisses after N seconds (0 = never). <b>Read-only</b> to the system - it only shows a box.',
      reports: 'Live session stats (scanned, updated, installed, uninstalled, repaired, reboots) and an <b>ACTION HISTORY</b> grid fed by every run on every tab. <b>Read-only</b>; export to CSV or a text summary.',
      usage: '<b>Read-only</b> live usage metrics (runs, hosts touched, action counts, per-category tallies, log root) - mirrors the row published to the central JANET telemetry share on tool close.',
      logs: '<b>Read-only</b> global activity log. Every WPT run on every tab streams here - a pure audit trail of this session, no writes to hosts.'
    },

    acas: {
      _overview: 'ACAS Nemesis vulnerability remediation. <b>Destructive</b> patching (app updates, reboots, KB installs) needs ADW credentials and confirmation; analysis and catalog views are <b>Read-only</b>.',
      import: 'Drop an ACAS / Nessus CSV to parse findings by host. <b>Read-only</b> import - shows affected hosts, total findings, and servers skipped.',
      updater: 'The main workflow: <b>Analyze</b> the CSV into one card per vulnerability, then <b>Patch Selected</b>, <b>Verify Selected</b>, or <b>Run All</b> across affected hosts. <b>Destructive</b> - set credentials and test one host first.',
      kb: 'Parse and install Windows KB rollups from the CSV. Check host x KB rows, pick MECM or UsoClient, add an optional .msu fallback, then <b>Install</b>. <b>Destructive</b> - confirm the KBs and hosts first.',
      vulns: '<b>Read-only</b> per-finding drill-down. Pick a remediation card from the <b>Updater</b> tab to see the raw findings (Host / Severity / Plugin / CVE / Solution) behind it.',
      backbone: '<b>Read-only</b> reference catalog of every App Update remediation profile: name, kind, mechanism, and whether it runs automatically from this host or needs staging.'
    },

    reports: {
      _overview: '<b>Read-only</b> reporting workspace for ACAS findings, trending, and remediation tracking. Load a scan, triage, cross-reference patches, and export briefs / CSVs. Never touches hosts.',
      start: 'Landing page and session guide. Start here: parse a scan in <b>ACAS Import</b>, review <b>Dashboard</b> and <b>Remediation Plan</b>, then export briefs and metrics. State persists across tabs.',
      acas: '<b>Read-only</b> import and triage. Parse a .nessus / CSV scan into findings, mark Patched / NOT OUR PATCH / Open, export a findings CSV, or save / load session state as JSON.',
      remediation: '<b>Read-only</b> planning grid. Groups findings by app bucket (Chrome / Edge / Office / Defender / KB / Other) with affected hosts, target versions, and Critical / High counts to drive priority.',
      compare: '<b>Read-only</b> patch validation. Load a baseline (before) and a comparison scan (after); diff on Hostname|PluginID for REMEDIATED / STILL OPEN / NEW, then fold remediated findings into your working set.',
      weekly: '<b>Read-only</b> metrics roll-up. Parse an ACAS_Calculations CSV into per-week, per-enclave (NIPR / SIPR) metrics, then render an HTML brief or export CSV.',
      dirty30: '<b>Read-only</b> critical-host triage. Paste a Tenable Dirty 30 list, parse + AD lookup, optionally probe last-logged-on users, then render an HTML report or export CSV.',
      cora: '<b>Read-only</b> commander brief. Analyzes loaded findings into headline metrics (open findings, unique hosts, VPH, severity breakdown) plus an HTML brief for leadership.',
      future: '<b>Read-only</b> target discovery. Parallel DNS-resolve + ping of future target hostnames, returning IP, Online / Offline / DNS Failed, and latency; export the results as CSV.',
      dashboard: '<b>Read-only</b> per-host summary. Tallies severity and Patched / Open / NOT OUR PATCH counts, plus patch rate per host across the loaded findings.'
    },

    restart: {
      _overview: 'Coordinated fleet restart scheduler. Set targets and config, then <b>Dispatch</b> a <b>Destructive</b> reboot; use <b>Verify</b> to confirm hosts went down and came back.',
      targets: 'Configure <b>Targets</b> (and exceptions that never reboot), restart mode (Burst / Time-gated / Rolling), time, message, consent prompt, pre-flight gates, and concurrency. Run a read-only <b>Ping All</b> and test a single host to prove WinRM + credential first.',
      dispatch: 'Fan out <b>shutdown /r</b> to every target - <b>Destructive</b>; the arming dialog confirms host count and consequence. Watch the live grid; <b>Abort Already-Dispatched</b> (shutdown /a) stands hosts down before they reboot.',
      verify: '<b>Read-only</b> reboot monitor: after the scheduled time passes it pings each target on an interval and confirms a down-then-up transition, timestamping when each host dropped and returned.'
    },

    upr: {
      _overview: 'Upload an Unsupported &amp; SEoL (Tenable / ACAS) report, scan affected hosts against the removal catalog, then uninstall proven-EOL products. <b>Destructive</b>, uninstall-only; dry run by default.',
      findings: 'Load a Tenable / ACAS Unsupported &amp; SEoL report (PDF or CSV) and review the flagged products. Click a finding row, then switch to <b>Uninstall</b> to scan and remove it. <b>Read-only</b> here.',
      uninstall: 'Click <b>Scan Hosts</b> to match installed software against the catalog - only PROVEN-EOL rows pre-check. <b>Plan-only defaults ON</b>; review, then uncheck to uninstall the checked products across your hosts. <b>Destructive</b>.',
      os: '<b>Read-only</b> list of unsupported operating systems from the report, one row per host. Export and hand to whoever runs OS rebuilds - UPR does not change the OS.',
      history: '<b>Read-only</b> audit trail of every uninstall outcome (OK / WARN / FAIL / Skipped) from dry runs and live uninstalls - last 200 rows this session.'
    },

    /* ---- single-flow tools (one box each) -------------------------------- */

    pkginstall: 'Stage a <b>PSADT package</b> (with Deploy-Application.ps1) or an <b>MSI bundle</b>, set Credentials (ADW cert), load <b>Targets</b>, pick the package, then <b>Deploy</b> - it copies to each host\'s C:\\Temp and installs silently. <b>Destructive</b>; test on one host first.',

    winupgrade: 'Pick an operation - <b>Pin</b> (hold at a feature version) / <b>Unpin</b> (remove the hold) / <b>Install CAB</b> (upgrade via DISM) - load <b>Targets</b>, tick <b>Dry-run</b> to preview, then <b>Run</b>. <b>Destructive</b>; Unpin before pushing a CAB past a pin.',

    message: 'Type a Title + Message, set the dismissal timeout (default 5 min, 0 = until clicked), load <b>Targets</b>, then <b>Send</b> a popup to every logged-on user. <b>Read-only</b> to the system; <b>Ping</b> first to see who is online.',

    adsearch: 'Pick a <b>search mode</b> (Users / Computers / Groups / Org Boxes / Email / Manager / Bulk / Base Export / Last PC), fill the fields, and run. <b>Read-only</b> Active Directory queries - changes nothing; double-click a result for detail.',

    dhcp: '<b>Connect</b> to a DHCP server, <b>Load</b> an option\'s values from a scope to preview, then <b>Apply</b> (one scope) or <b>Bulk</b> append / prepend / remove across many. <b>Set is a whole-option atomic replace - read first.</b> Changes the server.',

    secureboot: 'Load <b>Targets</b> (max 50), optionally set a BIOS password and parallel jobs, tick <b>Dry Run</b> to verify reachability + OEM detection, then uncheck and <b>Enable Secure Boot</b> via a SYSTEM scheduled task. <b>Destructive</b> (UEFI firmware); a brick-safety precheck guards unbootable configs.',
    biosfirmware: 'Load <b>Targets</b> and <b>Scan BIOS Firmware</b> - a <b>read-only</b> WinRM scan that reads each host BIOS version + model and scores it <b>Current</b> / <b>Outdated</b> / <b>Unknown</b> against the per-model baseline. <b>List Baselines</b> shows the targets in effect and whether they came from <b>JanetLocal\\BiosFirmwareCatalog.json</b> (editable) or the built-in default. No firmware is written.',
    beta: {
      _overview: '<b>Beta Lab</b> - staging ground for experimental, <b>read-only</b> fleet features. None are active right now; new sections appear here as they bake, then graduate into their own tool. (App Versions + Software Inventory moved into Workstation Patching; logged-on user / last boot / pending-reboot into the WPT Bulk Scan grid.)'
    }
  };

  /* ----- full per-tab guides (JANETWEB_GUIDE) -> the "How to" modal -------
     {what, steps[], patch, notes[], flag} per tab + tool overview. Generated
     from JANET ONE help + the views; brief box copy is JANETWEB_HELP above. */
  window.JANETWEB_GUIDE = {
  "wpt": {
    "overview": {
      "what": "The Workstation Patching Tool (WPT) is the centerpiece of JANET Web\u2014a single-window fleet patch and remediation utility for Windows sysadmins. It scans, patches, uninstalls, repairs, and reboots hosts in parallel across a shared target list, with tabs for bulk operations (Bulk Scan & Patch), granular app/software management (Software Manager, Software Center, Unsupported Software), security updates (KB Scanner, Log4j Finder), app deployment (App Updater, Beta), disk/registry fixes (Cleanup, Reg Key Fixes), diagnostics and healing (Health & Healers), WinRM bootstrap, reboot scheduling, messaging, and telemetry reporting.",
      "steps": [
        "Set Credentials (top-right, ADW account) to start an admin session for destructive operations; read-only scans do not require credentials.",
        "Build the shared target host list on the Targets tab: paste hostnames (line/comma/space separated), or import a TXT/CSV, or use the ACAS CSV importer.",
        "Navigate to an operational tab (Bulk Scan & Patch, Software Manager, KB Scanner, Health & Healers, etc.).",
        "On most tabs: optionally adjust Parallel hosts (default 16\u201324), configure scan/patch parameters, then click the primary button (SCAN ALL, Patch Selected, VERIFY, etc.).",
        "Monitor the Results Grid for per-host output in real-time; the Activity Log shows phase status and errors.",
        "For destructive actions, a second confirmation dialog (title + preflight + confirm word) appears before execution.",
        "After runs, check the Reports and Usage tabs for session-wide statistics and action history."
      ],
      "patch": "WPT is a control hub that orchestrates actions across the fleet. Most destructive operations (bulk-patch, software uninstall, reboot, registry apply, app-update-apply, cleanup with dry-run OFF, healers) use the same three mechanisms: (1) PowerShell runspace pools fan the action over N hosts in parallel, (2) each host streams back rows as it finishes, (3) results are color-coded in the grid (green=OK, orange=warn, red=fail). For example, a bulk-patch row succeeds when Reachable=true and rows report UpdatesTriggered + AppsTriggered counts; a reboot row succeeds when Success=true. Read-only tabs (Bulk Scan, KB Scan, Health Scan, Software Scan, etc.) change nothing; they enumerate/probe and feed their output into grid rows and the shared activity log. Verify that each affected host shows a successful status (OK, Patched, Installed, Armed, Applied, Repaired, etc.) in the Status/Result column. Export the grid as CSV for audit/hand-off, and check the central audit log if configured (depends on deployment).",
      "notes": [
        "Admin session (Set Credentials, top-right) is REQUIRED for all destructive operations (patch, uninstall, reboot, apply, repair, cleanup with dry-run OFF). Read-only scans use your Kerberos identity unless credentials are set.",
        "All destructive actions require a second confirmation (Arm, Proceed, Patch, Delete, Apply, Reboot, Uninstall, etc.) to prevent accidents.",
        "Offline/unreachable hosts are flagged in Bulk Scan (Online=false) and skipped by most actions. Use Ping Sweep or Repair WinRM to diagnose connectivity.",
        "Dry-run defaults to ON for Disk Cleanup (preview only, no deletion); untick it to apply destructive changes.",
        "Sessions are ephemeral: session stats, action history, and the global activity log live in-browser only and are cleared on page reload. Central audit logs (if configured) are written to a server share."
      ],
      "flag": "destructive"
    },
    "tabs": {
      "targets": {
        "what": "<b>Build and manage the shared target host list</b> that is used by every operational tab (mirroring the desktop's global $global:ComputerList). Supports paste-in entry, TXT/CSV import, and ACAS CSV auto-detection of hostname columns.",
        "steps": [
          "Paste hostnames into the large text box (line, comma, or space separated).",
          "Or click 'Import TXT' and select a .txt/.csv/.tsv file from your local machine.",
          "Or click 'Import ACAS CSV...' and open a Tenable/ACAS vulnerability export; the tool auto-detects the hostname column (NetBIOS, DNS, Host, Hostname, or IP preference order) and imports matching rows.",
          "The list is case-insensitively de-duplicated live as you paste.",
          "Switch to any other tab\u2014the same list appears in the TARGET WORKSTATIONS card on the left, updated in real-time.",
          "Edit the list on any tab; changes sync back to the Targets tab and to all other open tabs."
        ],
        "patch": "No patch mechanism; this tab is data-only. The host list is consumed by every operational tab (Bulk Scan & Patch, Software Manager, KB Scanner, App Updater, Health & Healers, Reboot Countdown, etc.). Changes made here immediately propagate to every other tab's shared target card.",
        "notes": [
          "The list is shared and persistent within the session but not saved across page reloads.",
          "ACAS import: paste the entire CSV (it parses headers client-side) or drop the file. The tool extracts hosts and appends them to the current list (no duplicates).",
          "Manual entry accepts a mix of short names, FQDN, and IPv4 addresses. They are normalized (FQDN\u2192short name, unless it is an IP)."
        ],
        "flag": "read-only"
      },
      "bulk": {
        "what": "<b>Parallel fleet scan and patch centerpiece:</b> SCAN ALL probes every target for online status, logged-on user, C: free space, reboot-pending, and counts of pending MECM updates, Windows Updates, and Software Center apps. Then select hosts with pending work and run Patch Selected (triggers updates) or Reboot Selected (forced reboot) on just the checked rows. Also includes Ping Sweep and Repair WinRM buttons.",
        "steps": [
          "Add hosts on Targets tab, set credentials if needed.",
          "Optionally adjust 'Parallel hosts' (default 24) in the settings card.",
          "Click 'SCAN ALL'. Each host streams a row as it finishes: Online status, logged-on user, C: free space + % free, reboot-pending flag, MECM/WU/app counts, and any error.",
          "Read the scan results. Check 'Select With Updates' button to auto-select all rows that have pending updates, reboot-pending, or offline status.",
          "Check the rows you want to patch, then click 'Patch Selected' (triggers MECM + app installs, reboot suppressed).",
          "Or check rows and click 'Reboot Selected' for immediate forced reboot (after confirmation).",
          "Optionally click 'Ping Sweep' (TCP 5985/445 check) or 'Repair WinRM' (for offline hosts) as follow-on fixes.",
          "Export the scan grid to CSV using the 'Export CSV' button for audit/hand-off."
        ],
        "patch": "<b>Bulk Scan</b> (read-only): probes 5985/445 TCP, reads online/drive/counts over WinRM into per-host rows. Success row shows Online=true, DriveFree with % free and size (green if >20%, orange if lower, red if error), RebootPending (YES or No), and MECM/WU/APP update counts. <b>Bulk Patch</b> (destructive): triggers MECM CCM_SoftwareUpdate + CCM_Application installs on checked hosts. Success row shows Reachable=true, UpdatesTriggered count, AppsTriggered count. Reboot is suppressed (IsRebootIfNeeded=false); machines may end up reboot-pending. <b>Reboot Selected</b> (destructive): issues Restart-Computer -Force. Success row shows Success=true, Detail='Reboot command sent'. <b>Ping Sweep</b> (read-only): TCP port test. Success row shows Reachable=true/false. <b>Repair WinRM</b> (destructive): connects over DCOM, sets WinRM service Automatic, runs winrm quickconfig, re-probes 5985. Success row shows Success=true, PostProbeOk=true (5985 now answers).",
        "notes": [
          "Bulk Scan is read-only (no changes to targets) and is the starting point to triage which hosts need work.",
          "Select With Updates is a client-side filter (no re-scan); it checks rows where MECMUpdateCount>0 OR WindowsUpdateCount>0 OR AppCount>0 OR RebootPending=true, or Online=false.",
          "Patch Selected suppresses reboot (set IsRebootIfNeeded=false); the install may still leave a host with reboot-pending. Follow up with a Reboot Selected if needed.",
          "Offline (Online=false) hosts from Bulk Scan can be fed to Repair WinRM to restore connectivity (requires SMB/DCOM reachability).",
          "Double-click any scan row to see a host details popup (C: free, installed KB names, named MECM/WU/app titles behind the counts)."
        ],
        "flag": "destructive"
      },
      "software": {
        "what": "<b>Single-host registry software scan and uninstall.</b> Query one target's installed software (Win32 registry HKLM/WOW6432Node/HKCU + Appx Store apps), then uninstall checked apps by name or MSI GUID with their native uninstallers. Includes a Scan Detail panel to show named MECM/WU/Software Center pending items behind the bulk-scan counts.",
        "steps": [
          "Type or select a single Host from the dropdown (or type a hostname not in the list).",
          "Optionally type a Name/Publisher filter substring to narrow the software list.",
          "Click 'Software Scan'. The INSTALLED SOFTWARE grid populates with Name, Version, Publisher, Install Date, Install Type (MSI/EXE/Store), and Size.",
          "Note the exact Name and Install Type for anything you plan to remove.",
          "Alternatively, click 'Scan Detail' to list named pending items (MECM updates, Windows Updates, Software Center apps) on that one host\u2014the names behind Bulk Scan's counts.",
          "Check the software rows you want to remove, then click 'Uninstall Checked'. The tool auto-detects Install Type (MSI \u2192 msiexec /x /qn, EXE \u2192 silent string, Store \u2192 Remove-AppxPackage) and removes it.",
          "Use the Quick filter dropdown (Chrome, Edge, Teams, Adobe, Java, etc.) for client-side filtering (no re-scan)."
        ],
        "patch": "<b>Software Scan</b> (read-only): reads target's registry Uninstall keys (HKLM 64-bit, WOW6432Node, HKCU) and Appx packages, returns Name/Version/Publisher/InstallDate/Type/Size per installed app. <b>Scan Detail</b> (read-only): lists named items per Channel (MECM = CCM_SoftwareUpdate, WindowsUpdate = title from COM searcher, App = CCM_Application display name). <b>Software Uninstall</b> (destructive): matches checked app names (loose substring, or exact MSI GUID in {braces}) against registry, auto-detects type, runs msiexec /x /qn /norestart for MSI, native uninstall string for EXE, Remove-AppxPackage for Store. Success row shows Result (Removed/NotFound/Failed), Detail (exit code or error). On successful removal of '*Tanium*' products, also deletes HKLM:\\SOFTWARE\\WOW6432Node\\Tanium.",
        "notes": [
          "Software Scan / Scan Detail are single-host only (the Host field, not the shared Targets list).",
          "Install Type from Scan drives how Uninstall removes it; loose name matching can match more than intended\u2014prefer exact names from Scan or use the MSI {GUID}.",
          "Result code 3010 in Detail = uninstall succeeded but host needs reboot.",
          "Tanium cleanup: on uninstall of '*Tanium*' name, a known leftover key is also removed from WOW6432Node."
        ],
        "flag": "destructive"
      },
      "sccm": {
        "what": "<b>Single-host query and multi-host action on Software Center apps.</b> Query one host's CCM_Application catalog, check specific app(s), then Install/Uninstall/Reinstall/Repair them across the shared target list (or just the query host). Includes quick-filter by app name (Chrome, Edge, Teams, Microsoft 365, Tanium).",
        "steps": [
          "Type a single Host name in the 'Query host' field.",
          "Click 'Query Apps'. The CATALOG grid fills with app Name, InstallState, Applicable, EvalState, Version, Id, and IsMachineTarget.",
          "Check the app(s) you want to act on.",
          "Use the Quick filter dropdown for Chrome, Edge, Microsoft Teams, Microsoft 365, or Tanium (client-side, no re-query).",
          "Set the action: Install, Uninstall, Reinstall, or Repair.",
          "Optionally check 'Run on ALL targets' to apply the action across the entire shared target list; unchecked = only the query host.",
          "Click Install / Uninstall / Reinstall / Repair. A confirmation popup shows the app count and target count. Confirm, and the action runs.",
          "Monitor the Activity Log for per-host status (Installed/Uninstalled/Repaired with Detail)."
        ],
        "patch": "<b>Query Apps</b> (read-only): reads query host's ROOT\\ccm\\ClientSDK CCM_Application catalog over WinRM. Returns Id, Revision, Name, InstallState (Installed/NotInstalled/Error), Applicable (Yes/No), EvalState, Version, IsMachineTarget (true/false). <b>App Action</b> (destructive): runs Install/Uninstall/Reinstall/Repair of checked app(s) via the MECM client SDK on all targets (or the query host). Requires app Id + Revision + IsMachineTarget flag. Success row shows Result (Triggered/Installed/Uninstalled/Repaired/Failed), Detail (error or outcome). Reinstall = Uninstall, wait 10s, Install. On Uninstall/Reinstall of '*Tanium*', also deletes HKLM:\\SOFTWARE\\WOW6432Node\\Tanium on the target.",
        "notes": [
          "Query must match the target environment's catalog; a wrong Id silently does nothing.",
          "IsMachineTarget must match the deployment's targeting for the action to apply.",
          "Reboot is suppressed; apps may leave the host reboot-pending.",
          "Result 'Triggered' = action kicked off, not finished. Completion happens asynchronously on the client.",
          "Tanium cleanup: on Uninstall/Reinstall of any '*Tanium*' app, a known leftover registry key is removed from WOW6432Node."
        ],
        "flag": "destructive"
      },
      "kb": {
        "what": "<b>Inventory, trigger cycles, download, and install KBs.</b> Scan all targets for installed hotfixes (Get-HotFix), then use toolbar buttons to trigger MECM update cycles, push & download pending updates, or install specific KBs by number with optional .msu fallback.",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Click 'SCAN INSTALLED KBs'. Each host expands into one row per installed hotfix (HotFixID, Description, InstalledOn, InstalledBy).",
          "Optionally click 'Trigger MECM Cycles' to kick Software Updates Scan / Deploy / MachinePolicy cycles on all targets.",
          "Or click 'Push & Download' to query pending MECM updates and trigger Download (108) + Deployment (114) cycles\u2014updates are pulled to DOWNLOAD state but not installed.",
          "To install specific KBs: enter KB numbers (KB5060999 KB5062552) in the 'KBs' field, optionally check 'No auto-reboot' (default ON), and optionally upload a .msu file as a fallback.",
          "Click 'Install KBs' and confirm. The tool attempts MECM install first; if MECM doesn't have it, falls back to the .msu.",
          "Click 'Export CSV' to download the hotfix inventory."
        ],
        "patch": "<b>KB Scan</b> (read-only): runs Get-HotFix on each target, emits one row per hotfix with Host / HotFixID / Description / InstalledOn / InstalledBy. <b>Trigger MECM Cycles</b> (non-destructive trigger): runs schedules 0113 (SW Updates Scan), 0114 (SW Updates Deployment), 0021 (Machine Policy Eval) on each target. Result row shows Status 'MECM cycles triggered' on success. <b>Push & Download</b> (non-destructive): counts pending MECM updates per host and triggers Download (108) + Deployment (114) cycles to pull them to DOWNLOAD state. Result row shows PendingCount, Status. <b>Install KBs</b> (destructive): attempts install of listed KBs via MECM first; any not found in MECM are installed via .msu file (if provided). No auto-reboot unless the .msu exit code is 3010 (reboot required) and 'No auto-reboot' is unchecked. Result row shows Success/Failed.",
        "notes": [
          "Get-HotFix only lists known CBS/servicing-stack hotfixes; some cumulative updates may not appear as distinct KB rows.",
          "Trigger MECM Cycles can cause the Software Updates Deployment cycle (0114) to START installing already-deployed updates; it nudges MECM to do its scheduled work.",
          "Push & Download moves updates to DOWNLOAD state; they are not installed or rebooted. Install them through your normal MECM deployment / maintenance window.",
          ".msu fallback: small files can be uploaded directly (1 GB cap); for large packages, prefer the path field pointing at a network share the operator's box can read.",
          "No auto-reboot defaults to ON; uncheckto allow post-KB reboot if the installer reports 3010."
        ],
        "flag": "destructive"
      },
      "appupd": {
        "what": "<b>Verify and apply app-update profiles (Office, Defender, Chrome via Software Center or direct Google Update, Edge, Java, MSXML 4.0, etc.) or custom commands.</b> VERIFY (read-only) checks installed version and last-updated date of a profile; APPLY runs the profile (or a custom PowerShell) remotely to update/remediate.",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Choose a Profile from the dropdown (Microsoft 365 - Force Update, Windows Defender, Chrome, Edge, Java, MSXML 4.0 Uninstall, Office VBA AccessVBOM Disable, etc.).",
          "Optionally adjust 'Parallel hosts' (default 16).",
          "Click 'VERIFY PROFILE'. Each host streams a row showing Version, LastUpdated, Verified (Yes/No), and Detail (engine version, path, or error).",
          "Check hosts that failed verify or are out of date.",
          "Choose an Apply profile from the same dropdown, or select 'Custom Command' and paste PowerShell.",
          "Click 'APPLY (ALL TARGETS)' to apply across all targets, or check rows and click 'Apply to Selected' for a subset.",
          "Confirm the danger dialog. The action runs and each host streams its result (Updated/Failed/Partial/Skipped with Detail)."
        ],
        "patch": "<b>Verify</b> (read-only): queries the target's registry/file/service state per profile (e.g. Office C2R config key, Defender service state, Chrome update GUID, Java installation folder). Returns Version, LastUpdated, Verified (Yes/No/n/a), Detail. Verified uses per-product recency window (Defender <24h, Office <7d, browsers <14d, Java <30d). <b>Apply</b> (destructive): runs the profile on each target. Profiles are product-specific: Office \u2192 triggers C2R update agent, Defender \u2192 downloads/applies definitions, Chrome \u2192 Software Center install (MECM-cycle fallback) or a verified direct Google Update trigger, Edge \u2192 runs its Update exe, Java \u2192 triggers Software Center install, MSXML 4.0 \u2192 msiexec /x, Office VBA AccessVBOM \u2192 edits HKEY_USERS hives (logged-on users only), Unquoted Service Path \u2192 rewrites HKLM ImagePath and backs original to HKLM:\\SOFTWARE\\JANET\\Nemesis\\UnquotedSvcPath, Log4j \u2192 replaces vulnerable .jars (requires staged 2.25.4 jars). Result row shows OK/Skipped/Partial/Failed with Detail.",
        "notes": [
          "Profile names must match exactly; unknown profile names return the list of valid ones.",
          "Custom Command runs arbitrary PowerShell as-is on every target\u2014review it carefully; there is no sandbox or dry-run.",
          "Office/Chrome/Edge updaters run asynchronously on the target; 'Version After' often shows 'unchanged' immediately after Apply\u2014re-run Verify later to confirm the bump.",
          "Office VBA AccessVBOM only edits currently logged-on user hives; re-run after other users log on to update their hives.",
          "Log4j requires operator-staged replacement jars (log4j-api-2.25.4.jar, log4j-core-2.25.4.jar) on a share; the action fails if jars are missing.",
          "Reboots are NOT issued by Apply profiles; some changes (SMB Signing, RDP NLA, registry edits) take effect after service restart or reboot."
        ],
        "flag": "destructive"
      },
      "beta": {
        "what": "<b>Experimental, AFNET-unproven app-update profiles for fixes not yet in the proven App Updater tab.</b> Includes Adobe Acrobat/Reader, SMB Signing, RDP NLA, ICMP Timestamp block, and others. Each fix offers multiple methods (Software Center vs direct registry/firewall/updater). VERIFY is read-only; APPLY is destructive and requires an extra 'experimental' confirmation.",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Choose a Beta fix from the dropdown (Adobe Acrobat, SMB Signing, RDP NLA, ICMP Timestamp, etc.).",
          "Select the Method (e.g. Software Center vs Direct for Adobe; Direct for others).",
          "If the method requires an input (e.g. Adobe Software Center app name), fill it or leave blank to trigger all deployed Adobe updates.",
          "Click 'How to' to read AFNET-specific instructions for the selected fix.",
          "Click 'VERIFY (READ-ONLY)' to check the current state on all targets (Version, Compliant Yes/No).",
          "Check rows that are non-compliant, or check all to apply.",
          "Click 'APPLY (ALL TARGETS)' or 'Apply to Selected' and confirm the danger dialog (which emphasizes 'experimental / unproven on AFNET').",
          "Monitor results in the Activity Log and grid."
        ],
        "patch": "<b>Verify</b> (read-only): reads the target's current state for the selected fix (e.g. Adobe version from registry, SMB Signing RequireSecuritySignature value, RDP NLA UserAuthentication, ICMP Timestamp firewall rule). Returns Version / CurrentState, Verified (Yes/No/info), Detail. Info = informational only, no pass/fail check. <b>Apply</b> (destructive): runs the selected method (Software Center trigger, registry write, firewall rule addition, or direct updater). Result row shows OK/Skipped/Partial/Failed. Some fixes take effect after service restart or reboot (SMB Signing, RDP NLA).",
        "notes": [
          "Beta fixes are experimental and unproven on AFNET\u2014test on a single host first before rolling out.",
          "Adobe Software Center method requires the patched app deployed in MECM first; the fix only triggers MECM cycles so the deployed update installs. Direct method runs Adobe's own updater on each host (requires AUSST or internet access).",
          "SMB Signing / RDP NLA / ICMP Timestamp are registry/firewall-direct changes; they apply immediately to new connections but may require service restart or reboot for full effect.",
          "How to button shows AFNET-specific guidance per fix\u2014read before apply.",
          "Reboot is NOT issued; schedule one separately if the fix requires it for full compliance."
        ],
        "flag": "destructive"
      },
      "cleanup": {
        "what": "<b>Disk cleanup: delete temp files and/or remove stale user profiles.</b> Supports dry-run (enumerate only, safe, ON by default) and live mode (actually delete, OFF by default). Settings: Operation (TempFiles/OldProfiles/Both), Profile age threshold (days), Dry run toggle.",
        "steps": [
          "Add hosts on Targets, set credentials for live mode.",
          "Choose Operation: 'Temp files' (C:\\\\Windows\\\\Temp, C:\\\\Temp, Prefetch, per-user AppData\\\\Local\\\\Temp/INetCache), 'Old profiles' (C:\\\\Users folders older than threshold), or 'Both'.",
          "If using OldProfiles/Both, set 'Profile age (days)' threshold (default 60).",
          "Leave 'Dry run' ON (checked, default). Click 'RUN CLEANUP' to enumerate what would be deleted.",
          "Read the grid: TempMB / TempFiles (counts), ProfilesFound (how many profiles match age), ProfilesRemoved (only non-zero in live mode), Status 'Dry Run OK'.",
          "Review the Detail column; if the sizes/counts look right, uncheck 'Dry run' and run again for real deletion.",
          "After live cleanup, Status shows 'Success' and ProfilesRemoved shows count (non-zero if profiles were removed)."
        ],
        "patch": "<b>Dry Run mode (ON by default, safe):</b> enumerates temp files and old profiles per host without deleting. Status row shows 'Dry Run OK', TempMB and counts are reported for preview. <b>Live mode (Dry Run OFF, destructive):</b> PERMANENTLY deletes temp files under C:\\\\Windows\\\\Temp, C:\\\\Temp, Prefetch, and per-user AppData\\\\Local\\\\Temp/INetCache. Removes user profile folders from C:\\\\Users if idle >threshold days. Status row shows 'Success', ProfilesRemoved shows count. Guard: skips loaded/in-use profiles, special profiles (Public/Administrator/USAF_Admin), and operator's own account (USERNAME, its base, and <base>.adw). Age is judged from NTUSER.DAT last write or Win32_UserProfile LastLogon.",
        "notes": [
          "Dry Run defaults ON for safety; preview first, then uncheck to delete.",
          "Profile removal skips: currently loaded profiles, special system profiles, and the operator's own account and variants.",
          "Temp file deletion includes per-user caches (AppData\\\\Local\\\\Temp, INetCache) and system temp folders.",
          "Always run Dry Run first to preview counts and sizes. PERMANENT deletion on live mode; there is no undo.",
          "Set Credentials (ADW cert) if your identity can't delete files/profiles remotely."
        ],
        "flag": "destructive"
      },
      "regkey": {
        "what": "<b>Scan and apply fixed STIG/CVE registry remedies from a built-in catalog.</b> Catalog keys: BHI (memory-management CVE mitigation), Edge_ImportSearchEngine (Edge policy). Scan reads current vs expected values; Apply writes the fix and reads back to confirm.",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Choose a Fix from the dropdown (BHI, Edge_ImportSearchEngine).",
          "Click 'SCAN FIX'. Each host streams a row showing RegPath, CurrentValue, ExpectedValue, and Compliant (Yes/No).",
          "Read the results. Non-compliant rows need Apply.",
          "Optionally check 'Notify user + reboot 1 hour after success' if the fix requires a reboot for full effect (BHI does).",
          "Click 'APPLY FIX' and confirm. Each host streams Status (Applied/Failed) and NewValue (what was written).",
          "Re-run Scan to confirm Compliant=Yes on all targets."
        ],
        "patch": "<b>Scan</b> (read-only): reads registry values per fix. BHI reads HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Memory Management (FeatureSettingsOverride bit 0x800000, FeatureSettingsOverrideMask). Edge_ImportSearchEngine reads HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Edge (ImportSearchEngine=0). Returns CurrentValue, ExpectedValue, Compliant (Yes/No). Status: Patched/Vulnerable/Drifted. <b>Apply</b> (destructive): writes expected values to registry, creating the key if missing. BHI ORs bit 0x800000 into FeatureSettingsOverride, sets FeatureSettingsOverrideMask=3. Edge_ImportSearchEngine sets ImportSearchEngine=0. Result row shows Status (Applied/Failed), NewValue. Optional post-apply action: if 'Notify + reboot 1 hour' is checked, each successfully-patched host receives a user notification and schedules a forced reboot ~1 hour later.",
        "notes": [
          "Only two cataloged keys are supported: BHI, Edge_ImportSearchEngine. Any other Catalog key value is rejected.",
          "BHI is a CVE memory-management mitigation; it takes full effect only after reboot or service restart. Check 'Notify + reboot 1h' to schedule auto-reboot after successful apply.",
          "Edge_ImportSearchEngine applies immediately to new sessions.",
          "No automatic backup of prior values; there is no undo beyond reverting the registry change manually.",
          "Set Credentials (ADW cert) if your identity can't write HKLM remotely."
        ],
        "flag": "destructive"
      },
      "unsupported": {
        "what": "<b>Scan for unsupported and end-of-life (SEoL) software by cross-referencing installed apps against the ACAS/Tenable catalog.</b> Returns only matches that need action (Uninstall/Update/Review). Check Uninstall-tagged rows, then click 'Uninstall Matched' to remove them with their native uninstallers.",
        "steps": [
          "Add hosts on Targets.",
          "Click 'SCAN UNSUPPORTED'. Each host's installed software is cross-referenced against the ACAS catalog.",
          "The grid shows matching unsupported/SEoL products: Product, InstalledName, Version, Category, and Action (Uninstall/Update/Review).",
          "Click 'Select Uninstall rows' to auto-check only Uninstall-tagged items (Review/Update are skipped).",
          "Manually check rows you want to remove, or check 'Select Uninstall rows' first.",
          "Click 'Uninstall Matched'. A confirmation popup lists the products and affected hosts.",
          "Confirm, and each host uninstalls its checked products using their native uninstallers (MSI /x, EXE silent string, or per-product method).",
          "Monitor the Activity Log for per-host uninstall status."
        ],
        "patch": "<b>Scan</b> (read-only): reads target's installed software registry + Appx packages and cross-references against ACAS unsupported/SEoL catalog. Returns only matches. Product / InstalledName / Version / Category (Unsupported / SEoL / Degraded) / Action (Uninstall / Update / Review). <b>Uninstall Matched</b> (destructive): on each host, uninstalls checked Uninstall-tagged products using their native uninstallers (auto-detects type: MSI \u2192 msiexec /x /qn /norestart, EXE \u2192 silent string, Store \u2192 Remove-AppxPackage). Result row shows Result (Uninstalled/Failed/NotFound), Detail (exit code or error). On successful removal of '*Tanium*', also deletes HKLM:\\\\SOFTWARE\\\\WOW6432Node\\\\Tanium.",
        "notes": [
          "Scan is read-only; only Uninstall Matched makes changes.",
          "Select Uninstall rows toolbar button auto-checks only Action=Uninstall items; Review/Update are left unchecked (operator must decide manually).",
          "Uninstall pairs param: Host<TAB>AppName per line (automatically derived from checked rows).",
          "Tanium cleanup: on successful uninstall of any '*Tanium*' app, a known leftover registry key is also removed from WOW6432Node.",
          "Set Credentials (ADW cert) if needed for uninstall operations."
        ],
        "flag": "destructive"
      },
      "log4j": {
        "what": "<b>Scan for vulnerable log4j JAR files.</b> Recursively searches common roots (Program Files, ProgramData, Users, Java/JDK/JRE, C:\\\\opt, C:\\\\apps) for log4j-*.jar and classifies each by version: Patched (2.25.4 and later), Vulnerable (known CVE versions), or Unknown (unparseable).",
        "steps": [
          "Add hosts on Targets.",
          "Optionally adjust 'Parallel hosts' (default 12; this scan is disk-heavy).",
          "Click 'SCAN FOR LOG4J'. Each host recursively searches for log4j JAR files and streams one row per jar found.",
          "Read the VulnerableVersion column: green = Patched (2.25.4+), orange = Vulnerable (known CVE versions), red = Unknown (unparseable).",
          "Any row not marked '(patched)' needs remediation. Use the App Updater tab with profile 'Apache Log4j - Replace Vulnerable Jars' to replace vulnerable jars (requires staged replacement jars on a share).",
          "Export CSV for audit/hand-off."
        ],
        "patch": "<b>Scan</b> (read-only): recursively searches C:\\\\Program Files, Program Files (x86), ProgramData, Users, Java, JDK*/JRE*, C:\\\\opt, C:\\\\apps on each target for log4j-*.jar files. For each jar found, parses version and classifies as Patched (2.25.4+), Vulnerable (known CVE versions), Unknown (unparseable). Returns one row per jar with Host / JARPath / Filename / VulnerableVersion. No remediation is applied by this tab; use App Updater -> 'Apache Log4j - Replace Vulnerable Jars' to replace vulnerable jars (requires staged 2.25.4 jars on a share at \\\\\\\\dm-tn-01\\\\sh-usafe-automation$\\\\JANET\\\\Packages\\\\Log4j\\\\NewFiles).",
        "notes": [
          "Scan is read-only; no jars are replaced or deleted by this tab.",
          "Only the patched build 2.25.4 is marked '(patched)'; any other parseable version is Vulnerable; unparseable names show '(unknown)'.",
          "Recursive search across large Program Files trees can take several minutes per host\u2014keep thread count modest.",
          "Offline hosts return Error='Offline' and contribute no rows.",
          "Remediation (jar replacement) requires staged replacement jars and uses the App Updater tab."
        ],
        "flag": "read-only"
      },
      "health": {
        "what": "<b>Deep diagnostic of client health (MECM state, WMI, Windows Update, reboot-pending age, last check-in) and one-click healing buttons.</b> Scan returns a per-host overall verdict (Healthy/Degraded/Broken/Offline); then run Healers: Restart MECM Client, Repair WMI, Reset Windows Update, Trigger Check-In, gpupdate /force.",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Optionally adjust 'Parallel hosts' (default 24).",
          "Click 'HEALTH SCAN ALL'. Each host streams diagnostics: MecmState (OK/Stopped/Missing), ClientVersion, Software Center state, WMI health, Windows Update state, reboot-pending and its age, last MECM check-in, and OverallHealth verdict (Healthy/Degraded/Broken/Offline).",
          "Read OverallHealth per host. Broken = fix immediately (MECM Missing/Stopped, WMI Broken). Degraded = may need a healer (slow services, old reboot-pending).",
          "Click a healer button for hosts flagged Broken/Degraded: 'Restart MECM Client' (service restart), 'Repair WMI' (salvagerepository), 'Reset Windows Update' (clear cache, restart services), 'Trigger Check-In' (kick MECM cycles), or 'gpupdate /force' (re-apply policy).",
          "After healing, re-run Health Scan to confirm OverallHealth improved."
        ],
        "patch": "<b>Health Scan</b> (read-only): queries each target for MECM client state/version, Software Center accessibility, WMI status (winmgmt service + test query), Windows Update service state (wuauserv), reboot-pending flag and age, last MECM check-in timestamp. Overall verdict logic: Broken = MECM Missing OR WMI Broken; Degraded = MECM Stopped, WU Disabled/Broken, SW Center Broken, or reboot >14 days old; otherwise Healthy. Offline = not reachable on 5985/445. <b>Healers (destructive):</b> Restart MECM Client: stops/starts CcmExec service, verifies it reaches Running. Repair WMI: runs winmgmt /salvagerepository in-place repair. Reset Windows Update: stops wuauserv/cryptsvc/bits/msiserver, renames SoftwareDistribution and catroot2 folders to timestamped backups, restarts services. Trigger Check-In: runs MECM cycles 0022 (Machine Policy) and 0113 (SW Updates Scan). gpupdate /force: re-applies all Group Policy. All healers return Success true/false and Detail (outcome or error).",
        "notes": [
          "RebootAge shows how long a reboot has been pending (e.g. '5d', '<1d'); a long age is a strong signal to reboot.",
          "Overall verdict: Broken requires immediate action; Degraded may improve with a healer; Healthy = no action needed.",
          "Restart MECM Client briefly interrupts MECM agent; in-progress MECM work is cut off when CcmExec stops.",
          "Reset Windows Update renames backup folders but does NOT delete them; C: space is consumed by .wpt-bak-* folders (clean them up later if needed).",
          "Trigger Check-In is non-destructive (read-only trigger); others are minor config changes.",
          "Some policy changes only take effect at logon/reboot\u2014gpupdate may report 'reboot recommended'.",
          "Set Credentials (ADW cert) if your identity can't control services remotely."
        ],
        "flag": "destructive"
      },
      "winrm": {
        "what": "<b>Bootstrap WinRM on offline/unreachable hosts.</b> For hosts reachable on SMB (port 445) but not WinRM (port 5985): connects over DCOM, sets WinRM service to Automatic, starts it, runs winrm quickconfig, re-probes 5985 to confirm.",
        "steps": [
          "Get the list of offline/unreachable hosts first (e.g. unreachable=false rows from Ping Sweep or Online=false from Bulk Scan).",
          "Enter those hosts in Targets (labeled 'Offline hosts').",
          "Optionally adjust 'Parallel hosts' (default 12).",
          "Click 'REPAIR WINRM'. Each host streams: Success (OK/Failed), PostProbeOk (5985 reachable after repair), and Steps (details of what was done).",
          "Read PostProbeOk: true = WinRM 5985 is now reachable. False = repair attempted but WinRM still not answering.",
          "Once repaired, re-run your original WinRM action (Bulk Scan, Patch, etc.) on the now-online hosts."
        ],
        "patch": "<b>Repair WinRM</b> (destructive, changes service config): connects to target over DCOM (RPC), sets WinRM service (WinRM) to Automatic, starts the service, runs 'winrm quickconfig -force' to configure listeners/firewall, then re-probes TCP 5985 within ~30s. Success row shows Success (true/false), PostProbeOk (5985 now answers yes/no), Steps (full path of actions taken). Writes a bootstrap log to target at C:\\\\Windows\\\\Temp\\\\wpt_winrm_bootstrap.log for troubleshooting.",
        "notes": [
          "Repair WinRM requires DCOM (RPC) reachability even though WinRM is down\u2014needs SMB (445) and RPC (135+). If DCOM fails, the host reports 'DCOM connect failed'.",
          "Changes target's WinRM service start mode and firewall rules (via quickconfig -force). Only point this at hosts that should have WinRM.",
          "Success = post-probe on 5985 succeeded within ~30s. PostProbeOk=false = WinRM still isn't answering (may require reboot or manual investigation).",
          "Bootstrap log is left on target at C:\\\\Windows\\\\Temp\\\\wpt_winrm_bootstrap.log for troubleshooting why a failed bootstrap didn't work.",
          "Set Credentials (ADW cert) if your identity can't open DCOM sessions or manage services remotely."
        ],
        "flag": "destructive"
      },
      "reboot": {
        "what": "<b>Schedule a delayed reboot with warning popups, or warnings-only mode.</b> Includes a client-side countdown timer and post-reboot monitor (pings hosts back online and beeps on return, parity with desktop).",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Configure the countdown: Total time (1\u20131440 min, default 15), Warn every (1\u2013120 min, default 5).",
          "Choose Mode: 'Auto-reboot when timer reaches zero' (issues shutdown /r /t <seconds>) or 'Warnings only' (no scheduled reboot, just popups).",
          "Enter Warning title (default 'Scheduled reboot - 48th Communications Squadron') and Message body (default 'Your computer will restart soon...').",
          "Click 'Arm Countdown'. A preflight dialog confirms target count, credential set, and mode. Click 'Arm Reboot' (auto) or 'Start Warnings' (warnings-only).",
          "The countdown timer displays in the top-right (e.g. 'Reboot in 15:00'). The SCHEDULE/MONITOR grid tracks each host's Phase (Armed/Waiting/Offline/Back online/Cancelled).",
          "At timer=zero in auto mode, the grid shows 'Rebooting now...' and the post-reboot monitor starts pinging hosts back online.",
          "Click 'Cancel Countdown' anytime before timer fires to abort (issues shutdown /a on auto mode).",
          "Click 'Send Warning Now' to pop a one-off warning immediately (uses current countdown value if armed)."
        ],
        "patch": "<b>Arm Countdown (auto mode, destructive):</b> on each target, issues 'shutdown /r /t <seconds> /f /c <message>' where <seconds>=totalMin*60. Result row shows Phase (Armed/Failed), RebootAt (~estimated time), Detail. At timer=zero the phase becomes 'Rebooting now' and the client-side monitor pings hosts back online every 6s. <b>Cancel Countdown (auto mode only, destructive):</b> issues 'shutdown /a' on each target to abort the scheduled reboot. Result row shows Phase (Cancelled/Failed). <b>Warnings-only mode:</b> no reboot scheduled. Message popups are sent every N minutes. <b>Post-reboot monitor:</b> pings each target every 6 seconds; Phase changes from Armed/Waiting to Offline (down, rebooting), then Back online (up, returned). Beeps on each host's return (Console.Beep parity).",
        "notes": [
          "Arm Countdown requires a strong confirmation (mode-specific button like REBOOT for auto-reboot, or START WARNINGS for warnings).",
          "Auto-reboot: shutdown /r /t is immediate and forced (-Force); open files are lost without warning. No grace period or user can cancel.",
          "Warnings-only mode: no reboot is scheduled; warning popups appear every N minutes per the 'Warn every' setting.",
          "Post-reboot monitor: pings each host and updates Phase grid live. Beeps (browser audio) when hosts return. Polls every 6 seconds; high thread count can cause brief UI lag.",
          "Offline hosts that reboot: Phase becomes Offline (down, rebooting), then Back online when ping succeeds. Hosts already offline show 'Waiting' until they reboot.",
          "Cancel Countdown: works anytime before the timer fires (sends shutdown /a). After timer=zero, cancel is a no-op.",
          "Set Credentials (ADW cert) for all Reboot operations."
        ],
        "flag": "destructive"
      },
      "message": {
        "what": "<b>Pop a titled message to logged-on users on each target.</b> Implemented via temporary scheduled task + VBS popup script. Supports title, multi-line body, and auto-dismiss timeout (0 = stays until user clicks OK).",
        "steps": [
          "Add hosts on Targets, set credentials.",
          "Enter a Title (e.g. 'A message from the 48th Communications Squadron').",
          "Enter the Message body (multi-line supported).",
          "Set 'Dismiss after (sec)': seconds until popup auto-closes (0 = never, stays until user OK; default 300 = 5 min).",
          "Optionally adjust 'Parallel hosts' (default 16).",
          "Click 'SEND MESSAGE'. A confirmation popup shows title and target count.",
          "Confirm. The tool registers a scheduled task on each target to run a VBS popup as the currently logged-on user.",
          "Status row shows Status (Delivered/Failed), Detail (reason if failed, e.g. 'No user logged in').",
          "The VBS script and scheduled task are self-cleaned (script deleted ~120s after popup closes)."
        ],
        "patch": "<b>Send Message</b> (reads to system, shows popup, non-destructive data-wise): on each target, writes a temporary VBS script to C:\\\\Temp\\\\WPT_Msg_<random>.vbs and registers a scheduled task to run it as the currently logged-on user (or fails if no user is logged in). The VBS pops a message box with title + body + timeout. Result row shows Status (Delivered/Failed), Detail (outcome or error). Cleanup is automatic: VBS is deleted ~120s after popup closes; scheduled task is cleaned up after execution.",
        "notes": [
          "If no user is logged on, that host returns 'No user logged in' and no popup appears.",
          "Non-destructive to data/system; only changes are a self-cleaning temp file and scheduled task.",
          "Dismiss timeout: 0 = user must click OK; 300 = auto-closes after 5 min (default); any positive integer = seconds.",
          "Use this to warn users before a Reboot Countdown or maintenance window.",
          "Set Credentials (ADW cert) if your identity can't create scheduled tasks remotely."
        ],
        "flag": "read-only"
      },
      "reports": {
        "what": "<b>Session telemetry: live statistics, action history grid, and CSV/text exports.</b> Tracks cumulative counts (Scanned, Updates, Installed, Uninstalled, Repaired, Reboots) and full action history (Time / Action / Target / Result / Detail) fed live by every WPT run on every tab.",
        "steps": [
          "Navigate to the Reports tab anytime during a session.",
          "Read SESSION STATISTICS cards at the top: Scanned (host count), Updates (count triggered), Installed/Uninstalled/Repaired (app/KB count), Reboots (count issued).",
          "Scroll down to the ACTION HISTORY grid. Each row is one action result: Time, Action (scan name), Target (host), Result (status), Detail (outcome/error).",
          "Click 'Refresh' to re-render the grids (usually unnecessary\u2014they update live).",
          "Click 'Export CSV' to download the full action history as CSV (Time / Action / Target / Result / Detail).",
          "Click 'Export Summary' to download a TXT summary report (operator, session start time, run count, distinct host count, and cumulative statistics).",
          "Click 'Clear' to reset session stats and history (does NOT affect central audit logs on the share)."
        ],
        "patch": "Reports are read-only telemetry. Statistics and history are fed live by every WPT action on every tab via a session Telemetry object. Each action, when it completes, classifies its results (e.g. bulk-scan: scanned count per host; bulk-patch: updates+apps triggered; kb-install: installed=1 per success; uninstall: uninstalled=1 per success; reboot: reboots=1 per success; healer: repaired=1 per success) and pushes summary counts into Telemetry.stats(). Individual rows are logged to Telemetry.history() with (seq, time, action, target, result, detail). The Reports grid renders both live. CSV export downloads the history table. TXT export downloads operator, started-at, run count, distinct host count, and aggregated stats.",
        "notes": [
          "Statistics and history are session-scoped (cleared on page reload). Central audit logs (if configured) persist on a server share.",
          "Multi-row-per-host scans (scan-detail, kb-scan, software-scan, unsupported-scan, log4j) add scanned=1 once per distinct host (not per row).",
          "Clear button removes session telemetry but does NOT touch the central audit CSV on the share.",
          "Export Summary TXT is the local session summary; the central audit log (if configured) is a separate server-side record."
        ],
        "flag": "read-only"
      },
      "usage": {
        "what": "<b>Live session usage metrics:</b> operator name, session mode, run count, distinct host count, and cumulative action statistics. Mirrors the WPT usage CSV row published to the JANET telemetry share when the tool closes.",
        "steps": [
          "Navigate to the Usage tab anytime during a session.",
          "Read the USAGE METRICS grid: Operator, Session mode, Session started, Runs executed, Distinct hosts touched, Action history entry count.",
          "Below that: Scanned (host count), Updates triggered, Installed/Uninstalled/Reinstalled (app/KB count), Repaired (agent/component count), Reboots issued.",
          "Bottom row: Log root (configured audit path, if any).",
          "The metrics are live\u2014they update as you run actions across all tabs."
        ],
        "patch": "Usage is read-only telemetry. Metrics are computed live from the session Telemetry object: Operator (from ctx.session.state.user), Session started (first run time), Run count (Telemetry.metrics().runs), Hosts touched (distinct host set count), Stats (scanned, updates, installed, etc. from Telemetry.stats()), Log root (from ctx.session.state.logRoot). This mirrors the usage CSV row published to the central telemetry share at session close (if configured).",
        "notes": [
          "Usage metrics are session-scoped and cleared on page reload.",
          "Log root is the configured central audit log path (if any)\u2014this tab shows it for reference.",
          "The metrics displayed here match the usage CSV exported to the telemetry share on tool close."
        ],
        "flag": "read-only"
      },
      "logs": {
        "what": "<b>Global activity log: streaming output from every WPT run on every tab.</b> A single activity log dock shows all phases, log lines, errors, and status updates as they happen across all operational tabs.",
        "steps": [
          "Navigate to the Logs tab anytime. The GLOBAL ACTIVITY LOG is a scrolling activity log.",
          "As you run actions on any other tab (Bulk Scan, Patch, Uninstall, Health Scan, KB Install, etc.), their log lines stream into this log in real-time.",
          "Each log entry shows phase (phase name), accent level (accent/ok/warn/err/dim), and text.",
          "Phase entries are colored banners (e.g. 'Bulk Scan started (24 host(s))' in accent, 'Scan complete: 18 online, 2 offline, 7 need work' in banner).",
          "Error entries are red (err level).",
          "Warning entries are orange (warn level).",
          "Scroll up to review past actions. The log buffer holds up to 5000 entries (circular buffer)."
        ],
        "patch": "Logs are read-only streaming output. Every tab's activity log appends to the global Telemetry.logBuf() buffer (max 5000 entries, FIFO). The Logs tab renders all buffered entries. New log entries stream in real-time as actions run on any tab. The buffer is fed by every action via Telemetry.onLog() subscribers.",
        "notes": [
          "Logs are session-scoped and cleared on page reload.",
          "Entries are streamed in real-time; you can navigate other tabs and the log continues in the background.",
          "Circular buffer (5000 max) means old entries drop off as new ones arrive.",
          "Color coding: accent (phase starts, major events), ok (success), warn (warnings, retries), err (errors), dim (low-level detail).",
          "Use this tab to audit multi-tab sequences and verify no errors occurred across runs."
        ],
        "flag": "read-only"
      }
    }
  },
  "acas": {
    "overview": {
      "what": "ACAS Nemesis vulnerability remediation tool for JANET Web. Import Tenable/ACAS-Nessus CSV exports, auto-analyze findings into selectable remediation cards (one per vulnerability, grouped by category), then patch or verify across affected hosts in parallel. Includes KB installer, raw-finding drill-down, and a profile catalog reference.",
      "steps": [
        "Go to the IMPORT tab and click 'IMPORT ACAS CSV' to upload a Tenable/ACAS-Nessus export.",
        "Switch to the UPDATER tab and click 'Analyze / Refresh Cards' to turn the import into one card per vulnerability (grouped Patchable/Experimental/Reboot/Unpatchable/NotUpdatable).",
        "For each card, optionally review affected hosts (click the host count label) and pick a profile variant (if more than one).",
        "Check the cards you want to patch, then click 'Patch Selected' (requires Set Credentials / ADW cert) or 'Verify Selected' (dry-run, no credential needed).",
        "Monitor results in the PER-HOST RESULTS grid and Updater Log (right column and bottom drawer); per-host color shows OK/FAIL/SKIP.",
        "Use KB INSTALLER, VULNERABILITIES (finding drill-down), and BACKBONE (profile catalog) tabs as needed.",
        "Close out the run with End Session / Notes (audit trail)."
      ],
      "patch": "PATCH SELECTED runs run-vulnerability (per-card) or run-all-parallel (multi-card) over each card's explicit affected-host set, dispatching the chosen profile per card in parallel (default 20 threads). Each (Host, Profile) tuple in the results grid shows Result (OK/FAIL/SKIP), Version Before/After, and Detail. OK means the remediation succeeded (app updated, KB installed, service fixed, etc.); FAIL means an error (Detail explains). Verify Selected is identical but with verifyOnly=true (reads current state, changes nothing). Success row shows OK in the Result column and non-empty Version After if applicable. Verification: re-run Verify Selected later to confirm current state matches target version, or use Bulk Scan on Workstation Patching tab to confirm patch deployed fleet-wide.",
      "notes": [
        "Set Credentials (ADW cert) is REQUIRED for any patching or preflight action. Analyzing, importing, and finding drill-down are read-only and need no credential.",
        "Patching does NOT reboot machines. Office/Chrome/Edge updates may temporarily force-close open apps on targets; warn users if running live.",
        "Coverage gaps (Reboot-required, Unpatchable, Staged package installs, any vuln with no matched profile) are shown but never auto-patched. Handle reboots with the Reboot card, and staged packages via Workstation Patching.",
        "Offline or unreachable hosts are reported as FAIL or SKIP in the results. Run Pre-Flight Services first if WinRM is known to be down.",
        "All server I/O goes through the RunController (one per action/card). The CSV is uploaded to a temp server path; parsed findings and remediation plans live in memory (no persistent DB)."
      ],
      "flag": "destructive"
    },
    "tabs": {
      "import": {
        "what": "Upload and parse a Tenable / ACAS-Nessus CSV export. The tool de-duplicates hostnames (resolves DNS Name / NetBIOS Name / IP to short hostname), drops msek-* server findings, and tallies findings per host. Results feed the Updater tab.",
        "steps": [
          "Export the findings CSV from ACAS/Nessus to your Downloads folder. Ensure it includes the standard columns: DNS Name, NetBIOS Name, IP Address, Plugin, Plugin Name, Severity, CVE, and Steps to Remediate.",
          "Click 'IMPORT ACAS CSV' to browse for the file, or drag the CSV onto this tab.",
          "Monitor the upload progress; the 'PARSING' phase shows real-time per-host summary rows as the tool de-duplicates and tallies.",
          "Read the four hero tiles: TARGETS LOADED (affected hostnames), ACAS FINDINGS (total), UNIQUE HOSTS (de-duplicated), SERVERS SKIPPED (msek-* rows dropped).",
          "Review the PER-HOST IMPORT SUMMARY grid showing each host, findings count, max severity, plugin count, and servers skipped.",
          "Once import completes (status = 'Imported N host(s), M finding(s)'), proceed to the UPDATER tab and click 'Analyze / Refresh Cards'."
        ],
        "patch": "This tab changes nothing on any host. It uploads the CSV to a server temp path, parses it, and populates the Import grid in-app. The ACAS FINDINGS and UNIQUE HOSTS counts feed the Updater tab's hero stats and the Card builder. Success = the import status shows 'Imported' and the grid fills; verification is visual inspection of the counts matching your source CSV.",
        "notes": [
          "The CSV must match the ACAS standard template (the nine named columns). If hostnames do not resolve or findings = 0, check the column headers in your source file.",
          "Msek-* (Microsoft-owned security) server findings are automatically filtered out per the workflow (use Workstation Patching for Windows server updates).",
          "Hostname resolution prefers DNS Name, falls back to NetBIOS Name, then IP. If a row has none of those it is skipped.",
          "Re-importing replaces the prior CSV; to combine multiple enclave exports, append them yourself before importing (not currently supported in-tool)."
        ],
        "flag": "read-only"
      },
      "updater": {
        "what": "The signature ACAS surface: one card per rolled-up vulnerability, grouped by remediation category (Patchable / Experimental / Reboot / Unpatchable / Not Updatable). Check the cards you want, pick a profile variant, then Patch / Verify in parallel over affected hosts. Live results stream into the PER-HOST RESULTS grid and hero stats recompute in real-time.",
        "steps": [
          "After importing (IMPORT tab), click 'Analyze / Refresh Cards' to parse the CSV and build one card per matched remediation profile. Cards appear grouped by category.",
          "Optional: click the host-count label on a card to review the exact affected hosts for that vulnerability; uncheck individual hosts if you want to exclude them from a per-card patch run.",
          "Optional: if a card shows multiple profile options (e.g. Office: EXE vs Software Center), use the per-card selector to pick the variant you prefer.",
          "Check the cards you want to patch. Unpatchable and Not Updatable cards show a 'Copy Plan' button instead (no patch available); Reboot-category cards show a 'Reboot Now' and 'Verify' button pair.",
          "For a dry-run: check the cards and click 'Verify Selected' (no credential needed, changes nothing).",
          "Once the verify looks right: Set Credentials (ADW cert, top-right), check the cards again, and click 'Patch Selected' to apply the profile to every affected host in parallel.",
          "Monitor results in the PER-HOST RESULTS grid (Host / Profile / Result / Version Before / Version After / Detail) and the Updater Log (right column, pop-out available). Status 'Complete' shows final ok/failed counts."
        ],
        "patch": "Patch Selected runs run-all-parallel internally: each checked card dispatches run-vulnerability (or schedule-reboot for Reboot cards) against its explicit affected-host set; profile selections and host excludes are honored per card. Results stream into the PER-HOST RESULTS grid keyed by (Host, Profile), showing Result: OK = succeeded (version bumped), FAIL = error (Detail shows why), SKIP = not applicable. Affected-host list is re-derived server-side and de-duplicated so the same (profile, host) is never run twice. Hero stats (PATCHABLE / PATCHED / FAILED) recompute per row and show the live tally. Success = OK result + matching Version After column (if applicable). Verification: re-run Verify Selected on the same card(s) later; Version After should match the target or show 'unchanged' if the update is still pending (async updaters like Office).",
        "notes": [
          "Set Credentials (ADW cert) is REQUIRED for any Patch / Preflight / Reboot action. Analyze, Verify, and other read-only runs do not need credentials.",
          "Patching does not reboot machines. Machines may be left reboot-pending after updates; run Reboot on the Reboot-category cards or trigger a separate reboot workflow.",
          "Office/Chrome/Edge updates are asynchronous - 'Version After' may show 'unchanged' immediately even on success. Re-verify later or trigger a check-in cycle to confirm.",
          "Pre-Flight Services can be run before a large patch wave to ensure WinRM / Winmgmt / RemoteRegistry are Running + Automatic on all affected hosts.",
          "Coverage gaps (Reboot-required, no matched profile, staged package installs) are never auto-included. Handle them separately via the Reboot cards or Workstation Patching tool."
        ],
        "flag": "destructive"
      },
      "kb": {
        "what": "Windows KB remediation installer. Parses KB references from the imported ACAS CSV, presents a selectable grid of Host x KB pairs, and installs selected KBs via MECM (CIM targeted) or UsoClient Trigger, with an optional .msu fallback.",
        "steps": [
          "Import an ACAS CSV on the IMPORT tab first.",
          "Click 'Rescan Findings' to parse KB references from the CSV into the KB FINDINGS grid (Host / KB / Severity / Plugin / CVE).",
          "Use 'Select All', 'Deselect All', or 'Select Critical/High' to pick which Host x KB pairs to install.",
          "Choose a Method: 'MECM (CIM targeted)' (default) or 'UsoClient Trigger'.",
          "Optional: click 'MSU fallback' to upload a .msu file (used only if a KB is not found in MECM on a target).",
          "Optional: un-tick 'Suppress auto-reboot' if you want machines to auto-reboot after successful KB install (default is suppressed).",
          "Set Credentials (ADW cert, top-right) - required for any install action.",
          "Click 'Install KBs'. Confirm the dialog showing count of KBs and hosts. Results stream into the INSTALL RESULTS grid (Host / KBs / MECM count / MSU count / Result / Detail)."
        ],
        "patch": "Install KBs groups the checked (Host, KB) pairs by Host and runs kb-install internally: for each host, it invokes either MECM InstallUpdates (if method=MECM, matches KB in CCM_SoftwareUpdate and queues them) or UsoClient.exe /StartInteractiveDownload (if method=UsoClient Trigger, triggers a scan and install). The .msu path is passed as a fallback - if MECM does not find/install a KB, the host attempts msiexec /i /qn on the .msu. Each result row shows Host, KBs (comma-separated list installed), MECM (count matched in MECM), MSU (count installed via fallback), Result (OK/FAIL/SKIP), and Detail. Success = OK result + MECM + MSU counts > 0 (at least one via either method). Suppress auto-reboot suppresses the automatic /t 10 reboot issued after successful install; if un-ticked, machines reboot ~10s after completion.",
        "notes": [
          "MECM method requires the KBs to be deployed in MECM CCM_SoftwareUpdate on the targets; if a KB is missing from MECM, the .msu fallback is attempted (or it is Skipped if no fallback provided).",
          "UsoClient Trigger is simpler (does not require MECM) but relies on Windows Update service and may take longer to complete.",
          "Set Credentials (ADW cert) is REQUIRED - must be an admin account with permissions to run installs remotely.",
          "Suppress auto-reboot = noreboot flag set. Machines may end up reboot-pending after install; schedule a separate reboot or leave auto-reboot enabled.",
          "Offline or unreachable hosts skip with Error='Offline'. Pre-Flight Services can verify WinRM is up first."
        ],
        "flag": "destructive"
      },
      "vulns": {
        "what": "Read-only finding drill-down. Lists the raw findings (Host / Severity / Plugin / CVE / Solution) behind each remediation card. Use this to see the exact vulnerabilities grouped under a single card before patching.",
        "steps": [
          "On the UPDATER tab, run 'Analyze / Refresh Cards' to populate the remediation cards.",
          "Switch to the VULNERABILITIES tab.",
          "Click the 'Remediation card' dropdown (shows 'Plugin [N host(s)]' for each card).",
          "Select a card from the list.",
          "Click 'Load Findings' to fetch and display the raw findings that make up that card.",
          "Read the grid: Host, Severity (color-coded), Plugin (vuln name), CVE, and Solution. One row per finding.",
          "Sort/filter the grid as needed to review hosts, severities, or solutions."
        ],
        "patch": "This tab changes nothing. It calls group-findings internally (reads the CSV server-side, groups by the selected card key) and populates the grid in-app. Success = grid fills with findings rows (Host / Severity / Plugin / CVE / Solution); count shown in status. Verification: the findings grid matches what the remediation card groups together for patching.",
        "notes": [
          "The dropdown is automatically repopulated each time you run Analyze / Refresh Cards on the UPDATER tab.",
          "This is a read-only view; it does not let you exclude individual findings from a card patch (the card granularity is the gate). To run a card on a subset of hosts, use the per-card 'host count' label on the UPDATER tab to review and uncheck hosts.",
          "If Analyze has not been run yet, the dropdown shows '(analyze first)' and Load Findings is disabled."
        ],
        "flag": "read-only"
      },
      "backbone": {
        "what": "Reference catalog: every App Update remediation profile, its mechanism (DISM / installer / update client / service restart / registry write / uninstall), and whether it auto-runs from the JANET Web web host (yes) or needs controller-side staging (no). Use this to understand the remediation profiles matched to your cards.",
        "steps": [
          "Click 'Load / Refresh Catalog' to fetch the current list of available profiles from the ACAS engine.",
          "Read the grid: Profile (name), Kind (category), Auto-Runnable (yes/no), and Mechanism (how it works).",
          "Sort by Auto-Runnable or Kind to find profiles of interest.",
          "Use this catalog as a reference when reviewing UPDATER cards - if a card's profile is 'no' on Auto-Runnable, it needs staged files or external setup and may be skipped on an auto-patch run."
        ],
        "patch": "This tab changes nothing. It calls list-profiles internally (reads the available remediation profiles from the engine) and populates the grid in-app. Success = grid fills with Profile / Kind / Auto-Runnable / Mechanism rows. Verification: cross-check a profile from an UPDATER card against the catalog to confirm its mechanism and auto-run status.",
        "notes": [
          "Auto-Runnable = yes means the profile can be triggered directly from JANET Web without additional staging. No means it needs controller-side package files or external manual setup (e.g. Log4j jars, staged .msu files).",
          "The Mechanism column explains the technical approach (DISM /Add-Package, msiexec /x /qn, PowerShell update cmdlet, etc.) - use it to understand what each profile does before patching.",
          "This catalog is rebuilt each time you click 'Load / Refresh Catalog', so changes in the engine (new profiles, retired profiles) are reflected immediately."
        ],
        "flag": "read-only"
      }
    }
  },
  "reports": {
    "overview": {
      "what": "JANET Web Reports Tool - a <b>stateful, persistent reporting workspace</b> for ACAS/Nessus scan analysis, cross-reference, and vulnerability briefing. Each action builds on the previous one in the same session (parse -> triage -> dashboard -> CORA -> remediation plan), eliminating the need to re-upload data.",
      "steps": [
        "Open the Reports tool (toolId 'reports').",
        "Choose a tab from the left rail: Start for guidance, ACAS Import to load findings, Remediation Plan to view app-by-app patch strategy, Patch Cross-Ref to compare before/after scans, Weekly Export to analyze metrics, Dirty 30 Triage to assess riskiest hosts, CORA Vulns for a commander brief, Future Target IPs to resolve hostnames, or Dashboard for a per-host summary.",
        "Most tabs are read-only analysis and reporting (HTML / CSV / JSON exports); no credentials are required.",
        "The Activity Log (lower left, persistent across tab switches) tracks all actions and shows detailed diagnostics.",
        "Use Download buttons to save HTML/CSV artifacts to your local machine."
      ],
      "patch": "The Reports tool is entirely read-only\u2014it changes nothing on targets or the network. It reads scan files, performs local analysis, and exports briefing documents (HTML, CSV, JSON). The output feeds to leadership briefs, executive dashboards, or downstream patches run via other tools.",
      "notes": [
        "This is a stateful tool: once you parse an ACAS file in ACAS Import, the same findings set is used by CORA, Remediation Plan, and Dashboard until you reload.",
        "No credentials (Set Credentials) are required; all work happens on the server as analysis and synthesis.",
        "The session is lost on server restart\u2014use ACAS Save Report (JSON) to preserve triage work across restarts."
      ],
      "flag": "read-only"
    },
    "tabs": {
      "start": {
        "what": "Landing page and orientation guide. Shows the workflow loop (parse ACAS -> triage -> review dashboard/remediation -> compare scans -> export briefs) and reminds admins that reporting is read-only and stateful.",
        "steps": [
          "Click the Start tab.",
          "Read the workflow outline to understand the typical loop.",
          "Note: Reporting is read-only - no credentials needed. Probes (Dirty 30 last-user, IP resolve) run under the server identity."
        ],
        "patch": "Read-only orientation; changes nothing. Click through to the tab that matches your task (ACAS Import to start a scan, Dashboard to see a summary, etc.).",
        "notes": [
          "This is the welcome/help tab.",
          "Refer back to it when unsure of the next step in the workflow."
        ],
        "flag": "read-only"
      },
      "acas": {
        "what": "<b>ACAS Scan Import and Triage</b>. Upload a .nessus / CSV / TSV ACAS export, review the parsed findings in a grid, then mark them Patched / NOT OUR PATCH / Open (undo). This is the core data-intake step; all other tabs (CORA, Remediation, Dashboard, Compare) read from the findings you load and triage here.",
        "steps": [
          "Click Import ACAS (.nessus / .csv / .tsv) and select a scan file.",
          "Optionally check 'Append to existing findings' to add to current data instead of replacing it.",
          "Review the grid: Hostname, PluginID, VulnName (plugin name), Severity, CVE, Category (auto-assigned: Chrome / Edge / Office / Defender / KB / Other / NOT OUR PATCH).",
          "Optional: use Severity + free-text filters to narrow the view (FILTER row below the grid).",
          "To mark findings: check one or more rows, choose 'Patched by', 'Patched date' (both optional), then click Mark Selected: Patched / Mark Selected: NOT OUR PATCH / Undo Selected (-> Open).",
          "To export: pick a View (Full / Open / NOT OUR PATCH / Patched), click Build CSV, then Download CSV.",
          "To save your triage work: click Save Report (JSON) and download the file; after a server restart, use Load Saved Report (JSON) to pick it up."
        ],
        "patch": "Read-only import and analysis. This tab loads findings into the session; it does not change targets or write configuration. The parsed findings feed the Remediation Plan, CORA, Dashboard, and Compare tabs. Use Download CSV to export a snapshot of your findings + triage state.",
        "notes": [
          "Append is OFF by default, so re-uploading a file replaces all loaded findings. Turn it ON to merge multiple scans in one session.",
          "Findings marked 'NOT OUR PATCH' are excluded from CORA briefs and the Remediation Plan by design.",
          "Triage marks (Patched by, Patched date) are session-only\u2014use Save Report (JSON) to preserve them across restarts."
        ],
        "flag": "read-only"
      },
      "remediation": {
        "what": "<b>Remediation Plan</b>. Turns the loaded ACAS findings into an actionable per-app remediation roadmap: fixed buckets (Chrome, Edge, Office, Defender, KB, Other) showing host counts, target versions, and critical/high breakdowns. Dynamic 'Other' rows appear for common 3rd-party vulns hitting 10+ hosts.",
        "steps": [
          "Load findings first (ACAS Import tab).",
          "Optionally enter 'Network size' (total devices on network) to calculate a '% of fleet' figure; leave 0 to hide it.",
          "Click Refresh Plan to build the grid from current findings.",
          "Read each row: App (Chrome / Edge / Office / Defender / KB / Other: <vuln>), TargetCount (hosts needing this fix), TargetVersion (latest version seen in solutions), CriticalCount, HighCount.",
          "To track which apps have been pushed: fill 'App bucket or group' (e.g. 'Chrome' or 'Other: Apache Log4j'), set Status (Pushed / Skipped / Pending), click Mark.",
          "Re-run Refresh Plan after marking to see the updated grid (Pushed/Skipped rows drop out)."
        ],
        "patch": "Read-only analysis plan. The grid is derived from the loaded findings and is rebuilt each refresh; it does not patch or change any host. Use this list to prioritize and scope patching through other JANET tools (Workstation Patching) or your deployment infrastructure.",
        "notes": [
          "NOT OUR PATCH findings are excluded entirely (no bucket).",
          "TargetVersion is inferred from plugin solution text\u2014verify against the vendor's actual release before pushing.",
          "Mark status (Pushed/Skipped/Pending) is session-only and resets on reload; it helps you track progress but does not persist."
        ],
        "flag": "read-only"
      },
      "compare": {
        "what": "<b>Patch Cross-Reference (Scan Compare)</b>. Load a BEFORE (baseline) and AFTER (comparison) ACAS scan, diff them on Hostname|PluginID, and label results as REMEDIATED (in baseline, gone in comparison), STILL OPEN (in both), or NEW (in comparison). Use this to record and cross-check patching progress.",
        "steps": [
          "Click Load Baseline (BEFORE) and pick the pre-patching ACAS scan file; confirm the Findings/Hosts counts.",
          "Click Load Comparison (AFTER) and pick the post-patching scan file; confirm its Findings/Hosts.",
          "Optionally set filters: Delta (All / REMEDIATED / STILL OPEN / NEW), host substring, Severity (All / Critical / High / etc.).",
          "Click Compare Scans to build the delta grid (Hostname / PluginID / VulnName / Severity / Delta).",
          "Read Delta per row: REMEDIATED (green) = fixed, STILL OPEN (amber) = not fixed yet, NEW (red) = appeared in the after scan.",
          "To mark the REMEDIATED findings as Patched in your loaded findings set: click Apply Remediated -> Findings (auto-marks matching keys Patched in the current ACAS findings).",
          "To clear and start a fresh compare: click Clear Compare State."
        ],
        "patch": "Read-only comparison and analysis. The compare diffs two scan files and reports the delta; it does not change targets. Apply Remediated -> Findings mutates only the in-session findings state (marks matching keys as Patched), not the remote hosts.",
        "notes": [
          "Load both a baseline and a comparison scan first, or there is nothing to compare.",
          "The baseline and comparison live in separate session stores and do NOT touch the main findings set (ACAS Import).",
          "Comparison is case-insensitive on Hostname|PluginID; the filters only change which rows are shown (the full delta is retained internally)."
        ],
        "flag": "read-only"
      },
      "weekly": {
        "what": "<b>Weekly Export</b>. Parse the monthly ACAS_Calculations spreadsheet (CSV export) into per-week, per-enclave (NIPR/SIPR) metrics (total vulns, AR %, MAJCOM VPH, category/PMO breakdowns), then render an HTML weekly brief or export per-week CSVs.",
        "steps": [
          "Save the monthly ACAS_Calculations workbook to CSV (keep the layout intact; don't rearrange columns).",
          "Click Load ACAS_Calculations CSV and pick the exported CSV file.",
          "Review the grid: one row per parsed week block (Week, Enclave, TotalVulns, AR_Percent, MAJCOM_VPH).",
          "To generate an HTML brief: optionally set 'Enclave' (NIPR / SIPR / blank for all), click Render HTML Brief, then click Open brief to view it in a new window.",
          "To export CSV(s): optionally set 'Week' (DateRange substring; blank = first week), check 'All weeks' to export one CSV per week, set 'Enclave' if needed, click Export CSV, then Download CSV.",
          "Check the 'All weeks' checkbox to write one CSV per non-empty week (per-week files are named with dates and written inline)."
        ],
        "patch": "Read-only synthesis and export. This tab parses metrics from the workbook and generates briefs/exports; it does not touch targets. The output (HTML/CSV) is for briefing and records.",
        "notes": [
          "The parser expects the actual ACAS_Calculations layout (NIPR in columns A-L, SIPR in O-Z per week block). A different CSV layout will parse to zero weeks.",
          "Weeks flagged 'Stale' during parse carry a warning badge (possible carryover from prior month)\u2014verify before publishing.",
          "VPH and AR % are recomputed from raw totals, so they may differ slightly from a single cell in the source sheet."
        ],
        "flag": "read-only"
      },
      "dirty30": {
        "what": "<b>Dirty 30 Triage</b>. Paste or load a Tenable Dirty 30 list (PDF text, CSV, or hostname-per-line), parse + cross-reference Active Directory, optionally probe each host's last interactive user over WMI, then render an HTML report or export a 14-column CSV.",
        "steps": [
          "In the 'Load File (PDF/CSV/TXT)' button: optionally upload a Dirty 30 PDF/CSV/TXT (it reads the text into the input box below); or paste the text manually (Dirty 30 PDF copy-paste, CSV, or one hostname per line).",
          "Optionally set 'Source label' (e.g. 'Dirty 30 - June NIPR') to label the data source in reports.",
          "Click Parse + AD Lookup to parse the hostnames and run a batched LDAP lookup; review the grid (Hostname, Score, Vulns, LastLogon, Squadron, OUChain, Status).",
          "Status shows: Active (AD logon within 90 days), Stale (no logon >90 days), Not Found (no AD object).",
          "Optional: click + Probe Last User to read the last interactive user (LastLoggedOnUser registry value) from each host over WMI; set Timeout and Parallel hosts as needed.",
          "To render an HTML report: click Render HTML to generate a dark-themed, filterable interactive report; click Open report to view it.",
          "To export: click Export CSV to download a 14-column CSV (Hostname, IP, Score, C/H/M/L counts, LastLogon, LastUser, Squadron, OU, Status, Notes columns)."
        ],
        "patch": "Read-only AD lookup and host probing. The parse queries Active Directory (no changes made); the probe reads a single registry value per host over WMI (read-only). Output is briefing documents (HTML/CSV) for leadership triage.",
        "notes": [
          "Status = Stale means no AD logon in >90 days (the host object still exists but isn't being used).",
          "Last-user probe requires local admin or WMI read rights on targets; unreachable hosts show '- offline -' or '- denied -'.",
          "Probing is parallel (default 16 hosts at once); higher counts are faster but heavier on the network.",
          "PDF text extraction is best-effort; messy/wrapped PDF columns may occasionally mis-parse. A clean CSV or one-host-per-line is most reliable."
        ],
        "flag": "read-only"
      },
      "cora": {
        "what": "<b>CORA Vulnerabilities</b>. Analyzes the loaded ACAS findings and generates a commander brief: headline metrics (open findings, unique hosts, VPH, severity breakdown, % of fleet) and a formatted HTML brief with top-15 vulnerability cards and category tables.",
        "steps": [
          "Load findings first (ACAS Import tab).",
          "Optionally enter 'Network size' (total devices on network) to compute '% of fleet' for each top vuln; leave 0 to hide it.",
          "Click Build Summary to compute metrics (Open Findings, Unique Hosts, VPH, Critical/High/Medium/Low/Info counts, Network %).",
          "Review the grid (Metric / Value).",
          "Click Open HTML Brief (or Render HTML in JANET Web v1.x) to generate the full commander brief inline\u2014headline tiles, severity/category tables, and top-15 vuln cards (each with host count, plugin, category, and solution).",
          "Click the Open brief button on the result to view it in a new window (sandboxed), or Download HTML to save it as a file."
        ],
        "patch": "Read-only synthesis and briefing. The CORA analysis reads the in-session findings and generates a formatted brief; it does not change targets. Output (HTML) is for leadership review and record-keeping.",
        "notes": [
          "Patched and NOT OUR PATCH findings are deliberately excluded so the brief reflects only open, actionable vulnerabilities.",
          "The 'Total devices on network' value is shared with Remediation Plan and other tabs for the session.",
          "If no findings are loaded, you'll get a 'No open actionable findings' card\u2014parse an ACAS file first."
        ],
        "flag": "read-only"
      },
      "future": {
        "what": "<b>Future Target IPs</b>. Parallel DNS resolve + ICMP ping of a list of target hostnames (e.g., AQC pre-target list, planned deployments). Reports IP address, Online/Offline/DNS Failed status, and round-trip latency per host. Includes copy and export helpers.",
        "steps": [
          "In the left column, enter target hostnames: type one per line, paste a CSV, or use Import CSV to load a file.",
          "Optionally adjust 'Threads' (parallel resolvers, 1-32; default 32) and 'Timeout ms' (1500 default).",
          "Click Resolve IPs to run DNS resolve + ping in parallel.",
          "Review the grid (Host, IP, Status, LatencyMs): Status shows Online (ping OK), Offline (resolved but no ping), or DNS Failed (no record).",
          "Use Copy All IPs / Copy Online IPs to copy IP lists to the clipboard (e.g., to paste into a share list).",
          "Use Copy Host,IP CSV to copy a simple hostname,IP format.",
          "Click Export CSV to download the full table (Host, IP, Status, LatencyMs) as a file."
        ],
        "patch": "Read-only reachability and DNS check. DNS resolve + ICMP ping only; no changes made to targets. Output is a status grid and exportable CSV for planning.",
        "notes": [
          "Status = Offline means the hostname resolved (DNS OK) but the ICMP echo timed out (host unreachable or blocking ICMP).",
          "Status = DNS Failed means no A record found for the hostname.",
          "Runs up to 32 parallel resolvers; lower the count if your network or the admin box is under heavy load."
        ],
        "flag": "read-only"
      },
      "dashboard": {
        "what": "<b>Dashboard - Per-Host Summary</b>. Displays aggregated vulnerability metrics (Total Vulns, Critical, High, Patched, Open, NOT OURS, Patch Rate) and a per-host breakdown grid (Host, severities, counts, patch rate). Patch rate (Patched of Patched+Open) is color-coded: green >=90%, amber >=50%, red below.",
        "steps": [
          "Load findings first (ACAS Import tab).",
          "Click Refresh Dashboard to compute the per-host summary from current findings.",
          "Review the aggregate metric cards at the top (TOTAL VULNS, CRITICAL, HIGH, PATCHED, OPEN, NOT OURS, PATCH RATE) and the progress bar (Patch Rate %).",
          "Review the grid below: Host, TotalVulns, Crit, High, Med, Low, Info (per-severity counts), Patched (marked), Open (actionable), NotOurs (third-party), PatchRate (%).",
          "Click any row to pop out a detail view, or export via the grid's Export CSV button."
        ],
        "patch": "Read-only summary and analysis. The dashboard recomputes from the in-session findings each refresh; it does not change targets. Output is a visual summary for monitoring patch progress.",
        "notes": [
          "PatchRate = (Patched) / (Patched + Open); it shows N/A when a host has no actionable findings.",
          "Patch rate color: green >=90% (on track), amber >=50% (some progress), red below (needs work).",
          "This tab feeds from the same findings set as ACAS Import, CORA, and Remediation; triage marks in one tab immediately affect the others."
        ],
        "flag": "read-only"
      }
    }
  },
  "restart": {
    "overview": {
      "what": "A multi-step coordinated fleet-reboot tool that sends synchronized restart commands to many Windows machines at once, optionally requires user consent, and then monitors which ones actually rebooted. Dispatch is destructive; Verify is read-only.",
      "steps": [
        "Set up targets on the Targets / Config tab: enter hostnames, paste exceptions (never-restart), and configure restart mode (Burst / Time-gated / Rolling).",
        "Set restart time (HH:mm or ISO 8601) for when the machines should reboot (ignored in rolling mode).",
        "Configure optional gates: skip unreachable hosts (pre-flight ping) and skip server-named hosts via regex.",
        "Optionally enable user consent prompts so logged-on users must accept the restart in a popup window.",
        "Click 'Continue to Dispatch / Monitor' to move to the Dispatch tab.",
        "Review the arming dialog that restates the host count and consequence, then click Dispatch Restart (or Dry Run first).",
        "After dispatch completes, move to the Verify tab to monitor which hosts went down and came back online."
      ],
      "patch": "Patch mechanism: the tool sends WinRM commands (shutdown /r /t <countdown>) to each target to schedule a restart. Success = host receives the command and a restart timer begins. Verify watches for a DOWN-then-UP transition on each host, confirming the reboot actually happened. Export CSV results for audit records.",
      "notes": [
        "DESTRUCTIVE: Dispatch Restart reboots live machines. Always test against a small set first with Dry Run enabled.",
        "Requires Set Credentials (ADW cert) to run \u2014 admin sessions are necessary because reboots change machine state.",
        "Burst mode (default) converges all approved hosts to reboot at the shared Restart time. Rolling mode reboots each host ~grace seconds after user approval, no shared time.",
        "User consent is optional (checkbox). If enabled, each logged-on user sees a popup; no answer defaults to proceed (reboot anyway); explicit 'Decline' skips that host.",
        "Abort Already-Dispatched is the emergency cancel button \u2014 it sends shutdown /a to hosts that received a restart command but haven't rebooted yet."
      ],
      "flag": "destructive"
    },
    "tabs": {
      "targets": {
        "what": "<b>Configure targets and restart mode</b>. Paste hostnames (one per line, or import CSV/TXT), define exception hosts that must never restart, set the restart time and mode (Burst / Time-gated / Rolling), and tune optional gates like pre-flight ping and server-skip regex.",
        "steps": [
          "Paste hostnames into TARGET MACHINES (one per line, space/comma/tab separated, or click Import targets CSV). Case-insensitive dedup.",
          "Paste any hosts that must NEVER restart into EXCEPTION LIST (or click Import CSV). These are filtered out before dispatch, even if they appear in Targets.",
          "Under RESTART CONFIGURATION, select a Mode: Burst converge (every host reboots at the shared time), Time-gated (lead minutes before each host fires), or Rolling / go-fast (reboot each host ~grace seconds after user approval, no shared time).",
          "Set Restart time (HH:mm like '02:00' rolls to tomorrow if that time passed today, or ISO 8601 like '2026-06-09T02:00'). Ignored in rolling mode.",
          "For Time-gated mode, set Lead minutes (default 15). For Rolling mode, set Rolling grace (seconds, default 60).",
          "Under PRE-FLIGHT GATES, tick 'Skip unreachable' to ping all hosts first and skip dead ones (saves 15s timeouts per offline box).",
          "Optionally tick 'Skip servers matching regex' and adjust the pattern to filter out server-named hosts from the wave.",
          "Under USER CONSENT, optionally tick 'Require user consent prompt' to show each logged-on user an Accept/Decline popup. If unchecked, restart proceeds without user input.",
          "Optionally edit the Countdown message (the {LEAD} token expands to lead minutes).",
          "Under SINGLE-HOST TEST, enter a hostname and click 'Test single host...' to fire one real restart at one machine for WinRM/credential validation. Returns exit code + error hint.",
          "Review Parallel hosts (default 96, max 256) for concurrency.",
          "Click 'Continue to Dispatch / Monitor  ->' to move to the Dispatch tab."
        ],
        "patch": "No patch applied on the Targets tab \u2014 it is configuration and read-only to the targets themselves. Clicking Ping All checks reachability and logs results, but changes nothing on hosts. The exception list is saved in browser localStorage for session persistence.",
        "notes": [
          "Exceptions are case-insensitive and matched as substrings in the hostname.",
          "Restart time in HH:mm format (e.g., '02:00') that has already passed today rolls to tomorrow automatically.",
          "Single-host test is synchronous and returns immediately with an exit code; a success (rc=0 or 1190 = already scheduled) means the test host WILL reboot unless you abort it.",
          "Ping All uses ICMP; hosts blocking ICMP will show Offline even if WinRM works \u2014 for those, tick 'Attempt even if offline' on the real dispatch.",
          "Parallel hosts setting only applies to the real dispatch run, not to Ping All on the Targets tab."
        ],
        "flag": "read-only"
      },
      "dispatch": {
        "what": "<b>Arm and launch the coordinated restart wave</b>. Shows a live results grid streaming per-host dispatch status (Pending / Consent / In-Flight / Sent / Declined / Failed / etc.), a nine-cell stats bar, and an activity log. The START DISPATCH button is guarded by an arming dialog that confirms host count and consequence before any WinRM is issued.",
        "steps": [
          "Review the Targets / Config tab results: target count, mode, restart time, consent setting.",
          "On the Dispatch / Monitor tab, review the workflow hint in the log. Set Credentials (ADW cert) if not already set \u2014 a coordinated reboot is destructive and needs an admin session.",
          "Click START DISPATCH. An arming dialog appears restating the host count, mode, restart time, and consequence (LIVE \u2014 machines WILL restart). For dry runs, it reads 'DRY RUN \u2014 safe, no machines contacted'.",
          "Review the preflight checks (host count, credential, dry-run vs live). For a live run, you may need to type the confirmation word 'RESTART'.",
          "Click 'Dispatch Restart' (or 'Run Dry' for dry-run). The dispatch begins and streams rows into the results grid.",
          "Watch the DISPATCH RESULTS grid as each host reports a status: Sent (dispatched), Declined (user said no, consent mode only), Failed (WinRM error or code), Unreachable (pre-flight ping gate), or Skipped-Server (regex match). The nine-cell STAT BAR updates live.",
          "If you enabled 'Begin at the scheduled time' (delayed-start arming), the START DISPATCH button shows a live countdown ('Starts in HH:MM:SS'). Click CANCEL DISPATCH to stand it down before it fires.",
          "Once dispatch completes, the log shows a summary: N sent, N declined, N failed, N skipped-server. If 'Auto-open the Reboot Verification Monitor' is checked and at least one host was dispatched on a real (non-dry-run), the tool auto-switches to the Verify tab.",
          "To cancel pending restarts on any host that already received a restart command, click 'Abort Already-Dispatched' and confirm the abort dialog."
        ],
        "patch": "Patch mechanism: each dispatched host receives a WinRM call to 'shutdown /r /t <countdown>' (in burst/time-gated modes) or 'shutdown /r' (rolling mode). The restart timer countdown is calculated so all burst-mode hosts fire at the shared Restart time. Status 'Dispatched' = the command was accepted (rc=0); 'Already-Scheduled' = the host already had a pending restart (rc=1190, also success). The host will reboot when its timer fires. To verify the reboot actually happened, run the Verify Reboots action (Verify tab). To cancel before the reboot fires, run Abort Already-Dispatched against any host with status Dispatched or Already-Scheduled.",
        "notes": [
          "DESTRUCTIVE: on a real (non-dry-run) dispatch, every reachable, approved host will reboot. Always dry-run against a small set first.",
          "Dry run logs what would be done and contacts no hosts. Review the output, then uncheck 'Dry run' and run for real.",
          "Arming dialog requires confirmation (including the word 'RESTART' for live runs) to prevent accidental mass reboots.",
          "Delayed-start (Begin at the scheduled time) holds a countdown and auto-fires at zero. Cancel any time before it fires by clicking CANCEL DISPATCH.",
          "User consent mode adds latency (default 5-min prompt window, 60-sec accept grace) and per-host round-trips. Declined hosts are skipped this run.",
          "Export Results CSV button saves a CSV of all dispatch rows for audit records (Host, Status, RestartAt, ConsentState, Result)."
        ],
        "flag": "destructive"
      },
      "verify": {
        "what": "<b>Monitor and confirm reboots</b>. Pings each target on a repeating interval to detect a DOWN-then-UP reboot transition. Read-only \u2014 it never touches or restarts any host. Rows show State (Rebooted / Online / Offline / No contact), Went-Down and Came-Back timestamps, confirming which machines actually completed a reboot.",
        "steps": [
          "If auto-opened after dispatch, the monitor uses the hosts that were dispatched. Otherwise, the Targets list is used by default.",
          "Set 'Ping every (s)' (default 15) \u2014 how often each host is pinged.",
          "Set 'Timeout (s)' (default 1800 = 30 min) \u2014 how long to monitor before giving up on hosts that haven't confirmed.",
          "Set 'Parallel pings' (default 32, max 64) \u2014 how many hosts are pinged at once.",
          "Click START REBOOT MONITOR. The monitor begins and streams rows into the REBOOT VERIFICATION grid.",
          "Read the State column: 'Rebooted - online' (green, confirmed \u2014 went down then came back up); 'Online (no reboot seen)' (yellow, stayed reachable the whole time \u2014 may not have rebooted, or rebooted faster than your ping interval); 'Offline (down, waiting)' (blue, currently down); 'No contact' (red, never answered).",
          "The Went-Down and Came-Back columns show timestamps of the down and up transitions.",
          "The monitor stops automatically when every host shows 'Rebooted' or when the Timeout is reached. You can click STOP MONITOR any time to end early.",
          "Click 'Export CSV...' to save a CSV of all rows (Host, State, Went-Down, Came-Back, Result) for audit records."
        ],
        "patch": "No patch applied \u2014 this is read-only monitoring. The monitor only pings (ICMP) and does not touch or change any host. It confirms a reboot happened by watching for a host to drop offline and come back online. Results are streamed to the grid and optionally exported to CSV for record-keeping.",
        "notes": [
          "Read-only: ICMP ping only, no WinRM, no credential needed.",
          "A reboot is proven by a DOWN-then-UP transition (Rebooted state). A host that never dropped shows 'Online (no reboot seen)' \u2014 that is expected if the reboot completed faster than your ping interval. If you keep missing fast reboots, lower the 'Ping every' interval.",
          "Start the monitor AFTER the restart time has passed, so machines have had a chance to reboot. Starting too early shows everything Online.",
          "Useless on ICMP-blocked subnets \u2014 every host would read 'No contact'. For those, use another method to confirm reboots (e.g., re-run Bulk Scan from WPT to see uptime / last boot time).",
          "Shorten the Timeout or click STOP MONITOR early if you have confirmed all critical hosts \u2014 no need to wait for slow/offline machines."
        ],
        "flag": "read-only"
      }
    }
  },
  "upr": {
    "overview": {
      "what": "Unsupported Product Remediator (UPR) removes proven end-of-life software from Windows fleets. Upload a Tenable ACAS/Nessus Unsupported & SEoL report, scan hosts to match against the catalog, then uninstall the checked proven-EOL products across many hosts at once.",
      "steps": [
        "Click Load PDF / CSV to upload a Tenable/ACAS Unsupported & SEoL report (.pdf or .csv).",
        "Review the findings on the Import & Findings tab.",
        "Select a finding and open the Uninstall tab.",
        "Click Scan Hosts to enumerate software on each affected host and match the catalog.",
        "Review the scan results. Proven-EOL (Uninstall) rows are pre-checked automatically.",
        "Verify Plan-only (dry run) is checked (default ON), click Uninstall Selected to preview, then uncheck Plan-only for a real uninstall.",
        "Monitor the Activity log for per-host progress and outcomes."
      ],
      "patch": "The tool is two-stage: (1) Scan hosts gathers installed software and matches against the unsupported/SEoL catalog via the report-scan engine. Only rows with Decision='Uninstall' (proven EOL) are removable and pre-checked. (2) Uninstall hosts execute the real uninstall on checked rows via report-uninstall engine using silent uninstall strings (msiexec /x /qn for MSI, EXE quiet flag, or Remove-AppxPackage for Store apps). Plan-only (dry run) is ON by default \u2014 the first run enumerates without removing. Success = each row shows Result='OK' or 'OK (Reboot Required)'. Review / Tanium / unreachable rows are never removable, even if checked. Verify by re-running Bulk Scan on affected hosts and confirming the product counts drop.",
      "notes": [
        "DESTRUCTIVE with Plan-only OFF: this uninstalls software. Always test with Plan-only ON first. Dry run is the default.",
        "Requires admin session (ADW credential + responsibility ack) for a live uninstall. Dry run needs no admin session.",
        "Scan and Uninstall lock the global controls (Report load, Host class, Threads, Plan-only) while running; you cannot change them mid-flight.",
        "The catalog (JanetLocal\\UnsupportedProductCatalog.json) is reloaded on every scan. Click Reload Catalog to refresh it from disk.",
        "History tab records the last 200 uninstall outcomes from this session (in-memory only, not persisted across tool close).",
        "OS Findings tab is read-only \u2014 export and hand those hosts to your OS rebuild team separately."
      ],
      "flag": "destructive"
    },
    "tabs": {
      "findings": {
        "what": "<b>Parse-only</b> catalog of findings from the uploaded report. Each row is one vulnerability (plugin), showing which hosts are affected, category, and the catalog's decision for that product (Uninstall / Review / OS-only, etc.).",
        "steps": [
          "Upload a Tenable/ACAS report using Load PDF / CSV at the top.",
          "Review the populated grid: Plugin / Category / Plugin Name / Severity / Hosts count / Catalog Match.",
          "Use the Search box to filter by Plugin number, Plugin Name, or Category.",
          "Click a finding row to select it (highlighted in the grid). The selection carries to the Uninstall tab.",
          "Click View findings to inspect the per-host breakdown (Host / Severity / Plugin / CVE / Solution)."
        ],
        "patch": "This tab is read-only and changes nothing on hosts. It parses and displays the findings from the report. The decision (Uninstall / Review / OS-only) comes from the built-in catalog match. Selected findings are used by the Uninstall tab to scope the scan operation \u2014 selection is informational; the scan actually processes ALL actionable findings in the report, not just the selected one.",
        "notes": [
          "Update-class findings (e.g., M365 channel) are hidden by default \u2014 use the App Updater tool for those.",
          "The Host class filter (top global control) clips this tab to a specific class (e.g., 'Workstations' = MSEKL/MSEKW only).",
          "No credential or admin session needed to view findings."
        ],
        "flag": "read-only"
      },
      "uninstall": {
        "what": "<b>Scan + Uninstall core tab</b>. Scan opens a session per affected host, enumerates installed software, and matches the catalog to find proven-EOL products. Only PROVEN-EOL (Uninstall) rows auto-check and are removable; Review / Tanium / unreachable rows are locked from removal.",
        "steps": [
          "Load a report and select a finding on the Import & Findings tab first.",
          "Click Scan Hosts. The tool opens a session per affected host and enumerates installed software, then matches the catalog.",
          "Monitor the Activity log for progress. The grid populates one row per (host \u00d7 matched install) keyed by a unique _rk.",
          "When Scan completes, review the Decision column: Uninstall (proven) = green, Review = cyan, Tanium = amber, Unreachable/No match = dim.",
          "Proven-EOL rows are pre-checked automatically. Uncheck any rows you do NOT want to remove.",
          "Verify Plan-only (dry run) is ON in the global strip (default). Click Uninstall Selected to preview the plan.",
          "Review the Result column. When satisfied with the plan, uncheck Plan-only and click Uninstall Selected again for a real uninstall.",
          "After uninstall, review Results (OK / WARN / FAIL) and export the grid to CSV if needed."
        ],
        "patch": "Scan (report-scan engine): Open per-host sessions and enumerate software from the registry Uninstall keys + Microsoft Store apps. Match each against the catalog. Return Decision (Uninstall / Review / Skipped (Tanium) / Unreachable / Error / No match). On completion, pre-check only the Uninstall (proven) rows \u2014 these are the only ones that can be removed. Uninstall (report-uninstall engine) with Plan-only ON: re-scan and show what WOULD be uninstalled (nothing is actually removed). With Plan-only OFF: execute silent uninstall on each checked proven row using the stored uninstall string (msiexec /x /qn for MSI, EXE quiet flag, Store via Remove-AppxPackage). Success = Result column shows 'OK' (exit 0) or 'OK (Reboot Required)' (exit 3010). The engine automatically gates Review / Tanium / unreachable rows \u2014 they report Decision properly but are never actually removed, even if manually checked. Verify by re-running a Bulk Scan on the affected hosts and confirming software counts dropped for confirmed products.",
        "notes": [
          "Plan-only (dry run) is ON by default and is strongly recommended for the first pass to preview what will be removed.",
          "DESTRUCTIVE with Plan-only OFF: actually removes software. Admin session (ADW credential + ack) is required for live uninstall; Plan-only does not need it.",
          "Multi-row-per-host: a single host can have many matched products (one row per product). Threads control parallel host sessions; Results stream as each host finishes.",
          "The Scan/Uninstall buttons are disabled while a run is in flight. Cancel button stops in-flight host jobs (already-triggered uninstalls keep running on those machines).",
          "Export Results saves the grid to an Excel file (UPR_Candidates_<timestamp>.xlsx) for external review or auditing."
        ],
        "flag": "destructive"
      },
      "os": {
        "what": "<b>Read-only</b> unsupported operating-system findings extracted from the report. One row per affected host showing Plugin / Finding / Severity / IP / NetBIOS / DNS / OS CPE / MAC. Out of scope for UPR \u2014 hand this list to your OS rebuild team.",
        "steps": [
          "Load a report at the top. The OS Findings tab auto-populates when the report is ingested.",
          "Review the grid. One row per unique host with an unsupported OS finding.",
          "Click Refresh to re-parse the loaded report.",
          "Click Export CSV to download the list as an Excel file (UPR_OS_Findings_<timestamp>.xlsx).",
          "Click Copy to Clipboard to copy the grid as tab-separated text (for pasting into a ticket or email).",
          "Hand the exported list to your OS rebuild / infrastructure team for scheduling OS migration."
        ],
        "patch": "This tab is read-only and changes nothing on hosts. It extracts and displays OS-level findings (e.g., 'Windows 7 no longer supported') from the report. OS remediation is a separate project (rebuild / upgrade) outside UPR scope. Export the list and route it to the appropriate team.",
        "notes": [
          "These are informational only \u2014 UPR does not attempt to upgrade operating systems.",
          "The Host class filter (global control) clips this tab to the selected class (e.g., 'Workstations' only).",
          "No credential needed to view OS findings."
        ],
        "flag": "read-only"
      },
      "history": {
        "what": "<b>Session history</b> of all uninstall outcomes from this session (last 200 rows). One row per finished uninstall operation, showing When / Host / Action / Item / Result. In-memory only \u2014 not persisted after you close the tool.",
        "steps": [
          "Run one or more Scan + Uninstall operations (Plan-only or live).",
          "Each uninstall outcome (OK / WARN / FAIL / Skipped) is recorded in the History tab as it completes.",
          "Review the grid to see the per-host uninstall results from this session.",
          "Click Export CSV to save the history as an Excel file (UPR_History_<timestamp>.xlsx) for your audit trail.",
          "Click Clear Grid to erase the session history (be careful \u2014 this clears in-memory rows only; no undo)."
        ],
        "patch": "This tab is read-only and logs only. It records the outcomes of Uninstall operations that completed in this session. Each row captures the timestamp, host, action (Uninstall or Uninstall (DryRun)), product name/version, and the result (OK / WARN / FAIL / Skipped / etc.). Export to CSV for your change-control / audit-trail documentation. History is cleared when you close the tool (not persisted to disk).",
        "notes": [
          "History is in-session only \u2014 if you close the tool, history is lost. Export to CSV before closing if you need a permanent record.",
          "Last 200 rows kept automatically; older entries are discarded when the limit is exceeded.",
          "Action 'Uninstall (DryRun)' = Plan-only was ON. Action 'Uninstall' = Plan-only was OFF (real removal)."
        ],
        "flag": "read-only"
      }
    }
  },
  "pkginstall": {
    "overview": {
      "what": "<b>Remote Package Installer</b> deploys software across a fleet in parallel: either a PSADT package (runs Deploy-Application.ps1 folder) or an MSI bundle (runs msiexec /i on checked .msi files). Targets stream through Queued \u2192 Probing \u2192 Copying \u2192 Deploying \u2192 Success/Failed/Deferred, with a live results grid and execution log.",
      "steps": [
        "Enter target hostnames in the TARGET WORKSTATIONS card (one per line, comma or newline separated). Use Import TXT to load from a file.",
        "Choose PSADT Package (gold button, default) or MSI Bundle (ghost button toggle).",
        "Pick a package from the dropdown, or type a custom UNC/local path in 'Custom package path (optional)'. Optionally set a display name for audit.",
        "If MSI Bundle mode: check the .msi files to install (Check All / Uncheck All), and set msiexec arguments (default: /qn /norestart).",
        "Set Parallel Hosts (default 8, range 1-32) for concurrent deployments.",
        "Click DEPLOY. Confirm the prompt: package name, target count, deployment mode.",
        "Watch the results grid and activity log as hosts progress. Successful rows show green (Success), failed rows show red (Failed/Rejected), pending rows show yellow (Deferred).",
        "Export Results (CSV) when done, or Retry Failed to reload failed hosts for another run."
      ],
      "patch": "Mechanism: PSADT mode runs Deploy-Application.ps1 (folder structure); MSI mode runs msiexec /i <msi> <args> /L*v on each checked .msi. Success = exit code 0 (or 3010 for MSI reboot-needed). Failed/Rejected rows indicate install failure; Deferred means the package was unavailable or preconditions failed. Verify: spot-check a target machine (Control Panel > Programs, or Get-Package on PowerShell) to confirm the app name, version, or install date. Export the results grid for audit.",
      "notes": [
        "PSADT and MSI modes are mutually exclusive (toggle via the PSADT Package / MSI Bundle buttons).",
        "Custom package path overrides the dropdown when non-empty \u2014 it can be a local path readable by JANET Web, or a UNC share.",
        "Retry Failed reloads failed/rejected hosts and clears the current grid; run Deploy again.",
        "Admin session (Set Credentials) is required for installation.",
        "Deferred does not mean failure \u2014 it means the operation was skipped per policy/precondition; review the Detail column."
      ],
      "flag": "destructive"
    }
  },
  "winupgrade": {
    "overview": {
      "what": "<b>Windows Upgrade Tool</b> performs one of three operations: <b>Pin</b> (hold a feature version via WU policy), <b>Unpin</b> (remove the policy hold), or <b>Install CAB</b> (push a feature-update .cab/.msu via DISM and optionally reboot). Results stream as Queued \u2192 Pinning/Unpinning/DISM/Rebooting \u2192 DONE/FAILED/DRY-RUN/Skipped. The left column holds scenario/operation/computer config; the right shows a per-host results grid.",
      "steps": [
        "Enter computer names in the COMPUTERS card (one per line; Import TXT supported). Up to 50 hosts per run.",
        "Choose a SCENARIO from the dropdown (24H2 upgrade, 25H2 update, Manual) or leave it Manual to hand-pick an operation.",
        "If Manual: pick an OPERATION radio \u2014 Pin (hold at a feature version), Unpin (remove the hold), or Install CAB (push a feature update).",
        "If Pin: set Product (e.g. 'Windows 11') and Version (e.g. '24H2').",
        "If Install CAB: type a file path (\\\\share\\KB5054156.cab) or click Browse / drag a .cab/.msu to upload. Tick 'Reboot target ~10s after' if you want an automatic reboot after DISM succeeds (pre-ticked for scenarios).",
        "Tick Dry-run to preview (no changes; reports 'Would...' instead). Untick for real run.",
        "Tick 'Attempt even if offline' to skip the ICMP ping pre-check and proceed even if the host doesn't respond to ping (but WinRM is up).",
        "Set Max concurrent (default 16; lower for Install CAB, which is heavy).",
        "Click Test Ping first (optional; tests reachability), or RUN for the actual operation.",
        "Review the RESULTS grid: Ping latency, Status (DONE / FAILED / DRY-RUN / Skipped / Offline), and Detail per host. Export CSV when done."
      ],
      "patch": "Mechanism varies per operation: Pin writes HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate values (TargetReleaseVersion=1 DWORD, ProductVersion, TargetReleaseVersionInfo) to hold the PC at a feature version \u2014 WU will offer quality fixes but not a newer feature build, until Unpin removes those values. Unpin deletes the three Target Release Version values (or the key if nothing else is in it). Install CAB copies the .cab to C:\\Temp on each target, runs dism.exe /Online /Add-Package /PackagePath:C:\\Temp\\<file> /Quiet /NoRestart, optionally issues shutdown /r /t 10 after success. Success = Pin/Unpin report DONE or DRY-RUN (dry shows what would change); Install CAB = DISM exit 0 or 3010 (3010 = reboot pending). Verify: winver on the target shows the expected build/version; wmic os get version on an offline check shows the build number.",
      "notes": [
        "Pin and Unpin change policy only \u2014 they do not push/install anything. Pin sets a ceiling; WU/MECM must still deliver and install the update.",
        "Install CAB is destructive: it changes the OS build directly via DISM and optionally reboots. It IGNORES a Pin \u2014 if the fleet is pinned to 24H2, Unpin FIRST before installing 25H2 CAB.",
        "Reboot is issued as 'shutdown /r /t 10' only after a successful DISM install; it is skipped on Dry-run or Cancel.",
        "Dry-run is always safe (no writes, no reboots); untick to commit.",
        "Admin session (Set Credentials) is required for any real operation (destructive guard). Dry-run is allowed without credential.",
        "Upload cap is 1 GB for Browse/drag; larger packages should be dropped on a share and typed in the path field.",
        "Offline hosts return Status 'Offline' unless 'Attempt even if offline' is ticked, then they proceed."
      ],
      "flag": "destructive"
    }
  },
  "message": {
    "overview": {
      "what": "<b>Remote Message</b> broadcasts a titled popup message to every interactive session on each target host. Implemented via msg.exe (or VBS/scheduled task fallback on older Windows). Rows show per-host Ping latency, Status (Delivered / Failed / Offline), and the number of sessions reached. Results can be exported per status (Sent XLSX, Failed XLSX, All XLSX).",
      "steps": [
        "Enter target hostnames in TARGET MACHINES (one per line; Import TXT / CSV / TSV supported).",
        "Type a Title (or accept the default 'Message from the 48 Communications Squadron').",
        "Type the Message body in the textarea. Character count is shown live.",
        "Under DISPLAY OPTIONS, set Auto-dismiss timeout (5-3600 seconds, default 60). Unchecked = message auto-closes after this timeout; checked 'Require user to click OK' = popup stays until the user dismisses it.",
        "Tick 'Send in parallel' (default ON) to broadcast to many hosts at once, or untick for serial (slower).",
        "Click 'Test Ping' (optional) to check which hosts are online (changes nothing).",
        "Click SEND MESSAGE TO TARGETS. Confirm the popup: target count, title, mode, first few hosts.",
        "Watch the RESULTS grid: Ping status, Delivered count, Sessions count, and Mode per host. Activity log shows per-host 'Delivered to N session(s)' or error.",
        "Export Results (Sent / Failed / All XLSX) when done."
      ],
      "patch": "Mechanism: calls msg.exe /server:<hostname> /TIME:<timeout> '<title>' '<message>' (or VBS/task fallback on older Windows) which creates a popup in every user session on the target. Success = rows show Delivered=Yes, Sessions > 0 (at least one logged-on user). Failed rows show Undelivered=Yes with Detail explaining the failure (no user logged in, host unreachable, etc.). The popup is not logged anywhere \u2014 it is live only. Verify: confirm the popup appeared on the target when you sent it (visual confirmation is the only verification).",
      "notes": [
        "Requires at least one interactive user logged on each target; if no user is logged in, that host returns 'No user logged in'.",
        "The tool reads ctx.session.state.credSet (universal Set Credentials) but message delivery does not require special privileges \u2014 it uses RPC/WinRM which usually works under the operator's own identity.",
        "Parallel mode is faster for large fleets; serial is safer if WinRM is slow or unreliable.",
        "Title and message are both shown; both are limited by Windows messaging buffer size (~1000 chars per message).",
        "Not destructive \u2014 it only displays a popup and changes nothing on the target."
      ],
      "flag": "read-only"
    }
  },
  "adsearch": {
    "overview": {
      "what": "<b>AD Search Tool</b> is a read-only Active Directory lookup using 9 modes: Users (first/last/EDIPI), Computers, Groups, Org Boxes, By Email, By Manager, Bulk Computers, Base Users Export, and Last PC (logon scan of DC Security logs). The MODE bar at the top swaps input fields; the left RESULTS grid shows column headers specific to each mode; the right EXTENDED INFO console shows summaries and per-row detail on double-click.",
      "steps": [
        "Click one of the 9 MODE buttons at the top (USERS, COMPUTERS, GROUPS, ORG BOXES, BY EMAIL, BY MANAGER, BULK COMPUTERS, BASE USERS EXPORT, or BY LAST PC).",
        "The input fields below swap to match the mode. Fill in the required / optional search criteria (e.g. First Name, Last Name for Users; Computer Name for Computers).",
        "Criteria are matched as prefix wildcards and ANDed together; leaving all fields blank returns everything (caution on large queries).",
        "Click SEARCH (or press Enter in a text field) to execute. The grid populates with results; a progress bar shows completion.",
        "Double-click a row to open EXTENDED INFO with full detail (labelled attribute block) and an OBJECT DETAIL popup.",
        "Use Save (CSV) to export the current results. Use Clear to reset inputs, grid, and console.",
        "About button shows the tool overview."
      ],
      "patch": "All modes are read-only \u2014 they query AD with ADSI/ADSISearcher, they do not change anything. Mechanism per mode: Users / Computers / Groups / Org Boxes / By Email / By Manager query samAccountName, displayName, mail, manager attributes via LDAP filter matching. Bulk Computers batches machine names (50 at a time) and classifies as Active (logon <90d), Stale (>90d), or Not Found. Base Users Export finds OU children matching *Users* or *Administrative*, then enumerates user objects below and flags by sAMAccountName suffix (.adw/.adm/etc.). Last PC scans every reachable DC's Security event log (4624/4768/4769/4776) for the user's logon events \u2014 no changes made. Verify: query result shows an attribute value you expect to see (e.g. DisplayName, Email); double-click to see the full object.",
      "notes": [
        "Read-only (RSAT-free; uses ADSI/ADSISearcher built into Windows). No Set Credentials / ADW cert needed \u2014 runs under your current Windows logged-on identity.",
        "Last PC mode is the slowest \u2014 it touches every reachable DC and scans up to 2000 security log entries per DC. Larger 'Days Back' = longer scan.",
        "Prefix wildcard matching: 'Smith' matches Smith, Smithers, etc. At least one criterion is recommended to avoid huge result sets.",
        "Manager role is inferred from the sAMAccountName suffix (.adw/.adm/etc.) or '(ADM)' in the display name \u2014 it is not authoritative.",
        "Bulk Computers handles de-duplication and splits input on commas, semicolons, spaces, tabs, and newlines.",
        "Double-click any row to view extended info; single-click navigates the grid."
      ],
      "flag": "read-only"
    }
  },
  "dhcp": {
    "overview": {
      "what": "<b>DHCP Scope Options</b> edits IP option values (006 DNS, 003 Router, 042 NTP, 044 WINS, 045 NetBIOS NBDD, or custom ID) per DHCP scope in an ordered list. Two workflows: single-scope edit (pick scope, load option, reorder/add/remove IPs, Apply), and bulk operations (check scopes, Append/Prepend/Remove IPs across all checked). A 3-column layout shows Scopes (left), Scope Option editor (middle), and Activity Log (full-width dock). The tool connects to a DHCP server first.",
      "steps": [
        "Type the DHCP server hostname/FQDN in the DHCP SERVER field (top strip).",
        "Click Connect. The tool probes TCP 5985 (WinRM) and lists all scopes on that server in the left SCOPES card.",
        "For single-scope edit: click a scope row to select it. The middle card shows the scope subnet/name/state.",
        "Set the Option dropdown (006 DNS, 003 Router, etc.) or choose 'Other' and type a custom ID (1-254).",
        "Click Load Values to fetch the current option values for that scope. They appear in the IP ADDRESS LIST as an ordered list.",
        "Reorder IPs using Up/Down/Top/Bottom buttons (select an IP by clicking it in the list).",
        "Add new IPs: type an IP in the 'Add' field, click Add (inserts after selection) or Add to Bottom. Remove: select an IP and click Remove.",
        "Tick 'Remove option' to delete the option entirely (requires an empty IP list).",
        "Review the diff in the confirm dialog ('ADD', 'REMOVE', or 'REORDER ONLY'), then click APPLY.",
        "For bulk operations: check scopes in the left SCOPES card (All/None/Active/Invert buttons), paste IPs in BULK APPLY footer (IPs, one per line), choose Append/Prepend/Remove, and click the action button."
      ],
      "patch": "Mechanism: single-scope Set is an atomic replace \u2014 the tool reads the current option values, you edit the list, then writes the new list back via ctx.run('apply', ...) which calls the DHCP API on the server to update DHCPOptionValue for that scope+option ID. Bulk Append/Prepend/Remove targets multiple scopes in one operation \u2014 each checked scope receives the same IP list operation. Success = rows show 'changed' or 'no change'; 'removed' if the option was deleted; Error if write failed. Diff shows what was added/removed before Apply. After Apply, revert with Revert button (restores working list to original). Verify: on the DHCP server console (DHCP.msc) or via PowerShell Get-DhcpServerv4OptionValue -ScopeId <scope> -OptionId <id> to confirm the new IPs are there in the right order.",
      "notes": [
        "Connect first \u2014 all other operations require a successful server connection.",
        "Set is a whole-option replace \u2014 you are replacing the entire list, not merging. Load Values first to see what's there.",
        "Bulk Append/Prepend/Remove operates on every checked scope with the same IP list \u2014 each scope gets the same new IPs at the top/bottom or has them removed from wherever they appear.",
        "Admin session (Set Credentials) is required for Connect and Apply/Bulk operations. Load is read-only.",
        "Dry-run is available (tick checkbox) to preview changes without writing.",
        "Order matters for DNS/NTP/WINS \u2014 the DHCP client tries them in order. Reorder carefully.",
        "The tool handles full-line IPv4 validation; malformed IPs are rejected before Apply."
      ],
      "flag": "destructive"
    }
  },
  "secureboot": {
    "overview": {
      "what": "<b>Secure Boot Enabler</b> enables UEFI Secure Boot on up to 50 targets via OEM WMI DCOM (the SMBus firmware interface under SYSTEM context via a scheduled task). A left TARGET MACHINES card lists hosts (max 50); a right column holds Settings (BIOS password, parallel jobs, Dry-run), an Action bar, and a RESULTS grid showing per-host Status (Success / Skipped / Error / DryRun), Manufacturer, Before/After secure-boot state, and reachability.",
      "steps": [
        "Enter hostnames in TARGET MACHINES (one per line; Import TXT supported; max 50).",
        "Type the BIOS admin password in the SETTINGS card (or leave blank if the BIOS has no password \u2014 the tool will ask for confirmation).",
        "Set Parallel jobs (1-10, default 5) for concurrent machines.",
        "Tick Dry Run to probe reachability and manufacturer detection only (no firmware write).",
        "Click Set Credentials (top-right) to set your ADW cert (admin session required for real enable; Dry-run works without).",
        "Click ENABLE SECURE BOOT. Confirm the prompt: number of targets, any password note, credential used.",
        "Watch the RESULTS grid: Status (Success / Skipped / Error / Timeout / DryRun), Manufacturer detected, Before/After Secure Boot state (Enabled / Disabled / Unknown), and any Error/Notes.",
        "Export CSV when done for audit."
      ],
      "patch": "Mechanism: the tool calls Win32_SystemSecuritySettings WMI (DCOM) on each target with the provided BIOS password, running in SYSTEM context via a scheduled task. Secure Boot is enabled via the firmware interface if it is not already enabled. Success = Status 'Success' and Before != After (was Disabled, now Enabled). Skipped = already enabled (Before = After = Enabled) or not applicable (non-UEFI). Error = BIOS password wrong, DCOM unreachable, WMI error, or firmware not responding. DryRun = connectivity + manufacturer detected, no write. Verify: reboot the target and press F2/F10/Del during boot to enter BIOS/firmware menu; confirm Secure Boot shows Enabled. Or run 'Get-SecureBootUEFI' on Windows 11+ (requires admin).",
      "notes": [
        "This is a firmware change (destructive) \u2014 targets are rebooted ONLY if the firmware write succeeds AND the tool detects a successful change (not automatic; manual reboot may be needed for full effect).",
        "BIOS password is required if the BIOS is password-protected; blank password works only if the BIOS has no password set (tool will ask for confirmation).",
        "Max 50 hosts per run (safety guard for firmware operations).",
        "Manufacturer detection is automatic (reads SMBIOS/DMI); the tool knows Dell, HP/Lenovo/Supermicro and can attempt generic WMI, but older/unknown OEMs may fail with 'Unsupported manufacturer'.",
        "Admin session (Set Credentials) is REQUIRED for real enable; Dry-run does not require credential.",
        "Dry-run is safe (reachability + manufacturer detection only; no firmware write).",
        "DCOM must be working (TCP 135/445); some firewalls block it. If all targets fail with 'timeout' or 'DCOM connect failed', check firewall rules."
      ],
      "flag": "destructive"
    }
  }
};
})();
