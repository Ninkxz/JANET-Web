# =============================================================================
#  JanetWeb.reports.psm1  -  Reports tool engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\ReportsTool_2.14.5.ps1 (engine reused, WinForms layer
#  dropped). Provides ACAS vulnerability import/parse, Dirty 30 AD cross-
#  reference + parallel WMI last-user probe, weekly enclave metric parsing,
#  CORA commander-brief summarization, remediation planning, and self-
#  contained HTML / CSV report generation. All read-only; no operator
#  credential is required (LDAP ADSI binds with the calling thread identity;
#  WMI probes use the same identity).
#
#  v2.15.2 (audit 2026-07-25, fable re-audit follow-up): squadron-rollup records
#  every unreadable log-share path in an error bag and returns readErrors/readFailed
#  (a denied directory silently contributed ZERO rows, so "could not read" rendered
#  as "no activity"); its usage pass globs '<month>_usage*.csv' so header-rotation
#  sister files (<base>.r<unix>.csv) are no longer invisible; acas-ping-hosts records
#  a 'cancelled' sentinel on the cancel sweep so a previously-confirmed-offline host
#  cannot stay in the Offline export while the grid shows '?'; sla-aging / command-
#  brief skip Patched on the exact literal like host-summary does (was -match).
#
#  v2.15.1 (audit 2026-07-24): acas-host-summary classifies each finding into
#  exactly ONE bucket (Patched / NOT OUR PATCH / Open) so a Patched+NOT-OUR-PATCH
#  finding can no longer drive Open negative or overstate PatchRate; acas-ping-hosts
#  records never-probed hosts as Timeout (truthy sentinel) instead of confirmed
#  offline; weekly-export-csv's single-week write gets the TCP-445 pre-gate its
#  siblings already have; iavm-board splits a multi-bulletin IAVA cell before
#  grouping so a finding counts under EVERY bulletin it maps to.
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'reports'
        name     = 'Reports'
        category = 'Reporting'
        version  = '2.15.2'
        summary  = 'ACAS vulnerability import with CISA KEV auto-flag (known-exploited CVEs highlighted at parse), scan-to-scan comparison (REMEDIATED / STILL OPEN / NEW + apply), findings triage (Patched / NOT OUR PATCH / Undo), per-host dashboard summary, Dirty 30 AD triage, weekly enclave metrics, CORA commander briefs, remediation planning with push tracking, and parallel target IP resolve. Self-contained HTML/CSV output.'
        # parse/build actions cache findings in $script: state that later render/export
        # actions read - so this tool MUST run in one persistent runspace (the server
        # otherwise re-imports the module per action and the parsed state is lost).
        statefulRunspace = $true
        actions  = @(
            @{
                id          = 'dirty30-parse-lookup'
                label       = 'Dirty 30 AD Lookup'
                description  = 'Parse Tenable Dirty 30 input (PDF text, CSV, or hostname list) and run a batched LDAP lookup. Returns a hostname grid with score, vulns, squadron, OU/location, last AD logon, and stale/active status.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Hostname','Score','Vulns','LastLogon','Squadron','OUChain','Status')
                inputs       = @(
                    @{ name='InputText';   label='Dirty 30 input (paste PDF text, CSV, or one host per line)'; type='textarea'; required=$true },
                    @{ name='SourceLabel'; label='Source label';                                              type='text';     required=$false }
                )
            },
            @{
                id          = 'dirty30-probe-lastuser'
                label       = 'Dirty 30 Probe Last User'
                description  = 'Parallel WMI StdRegProv probe of each host LastLoggedOnUser registry value. Fans out across many hosts at once.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','LastUser')
                inputs       = @(
                    @{ name='Hostnames';     label='Hostnames (one per line; blank = use last lookup)'; type='hostlist'; required=$false },
                    @{ name='TimeoutSec';    label='Per-host timeout (sec)';   type='int'; required=$false; default=8 },
                    @{ name='MaxConcurrent'; label='Parallel hosts';           type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'dirty30-render-html'
                label       = 'Dirty 30 Render HTML'
                description  = 'Generate a self-contained HTML triage report (dark theme, summary tiles, squadron chips, status-colored grid) from the most recent lookup + probe.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','Hosts','Bytes')
                inputs       = @(
                    @{ name='SourceLabel'; label='Source label override'; type='text'; required=$false },
                    @{ name='colorblind'; label='Colorblind-safe palette'; type='select'; required=$false; default='None'; options=@('None','Protanopia','Deuteranopia','Tritanopia') },
                    @{ name='OutputPath'; label='Output HTML path (blank = return inline)'; type='savefile'; filter='HTML files (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*'; required=$false }
                )
            },
            @{
                id          = 'dirty30-export-csv'
                label       = 'Dirty 30 Export CSV'
                description  = 'Export merged Dirty 30 + AD + probe data to a 14-column CSV.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','Hosts','Bytes')
                inputs       = @(
                    @{ name='OutputPath'; label='Output CSV path (blank = return inline)'; type='savefile'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false }
                )
            },
            @{
                id          = 'acas-parse-file'
                label       = 'ACAS Parse File'
                description  = 'Parse a .nessus XML or CSV/TSV ACAS export into findings (hostname, plugin, vuln name, severity, CVE, category). Each finding is cross-checked against the CISA KEV catalog (JanetLocal\KevCatalog.txt) and flagged InKEV when its CVE is known-exploited, and tagged with its IAVA id from the IAVM map (JanetLocal\IavmMap.csv) when the CVE is mapped. Replaces the current findings set used by CORA / Remediation.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Hostname','PluginID','VulnName','Severity','CVE','IAVA','Category','InKEV')
                inputs       = @(
                    @{ name='FilePath'; label='ACAS file path (.nessus / .csv / .tsv)'; type='file'; filter='ACAS files (*.nessus;*.csv;*.tsv)|*.nessus;*.csv;*.tsv|All files (*.*)|*.*'; required=$true },
                    @{ name='Append';   label='Append to existing findings';            type='bool'; required=$false; default=$false }
                )
            },
            @{
                id          = 'iavm-add-map'
                label       = 'Add IAVM Mapping'
                description  = 'Append (or update) a CVE -> IAVA/bulletin mapping in JanetLocal\IavmMap.csv (validated, de-duped, atomic write). The map ships in take-to-work and auto-tags freshly parsed ACAS findings + KEV cross-refs with their IAVA id. Mirrors the KEV tool Add to KEV persistence.'
                kind         = 'table'
                destructive  = $false
                columns      = @('CVE','IAVA','Title','Status')
                inputs       = @(
                    @{ name='cve';   label='CVE (CVE-YYYY-NNNN)';                     type='text'; required=$true },
                    @{ name='iava';  label='IAVA / bulletin id (e.g. 2024-A-0100)';   type='text'; required=$true },
                    @{ name='title'; label='Title / description (optional)';          type='text'; required=$false }
                )
            },
            @{
                id          = 'acas-weekly-parse'
                label       = 'Weekly Export Parse'
                description  = 'Parse an ACAS_Calculations CSV export into per-week, per-enclave (NIPR/SIPR) metrics: total vulns, AR %, MAJCOM VPH, category counts.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Week','Enclave','TotalVulns','AR_Percent','MAJCOM_VPH')
                inputs       = @(
                    @{ name='FilePath'; label='ACAS_Calculations CSV path'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'weekly-render-html'
                label       = 'Weekly Render HTML'
                description  = 'Generate an HTML weekly brief from the most recently parsed weekly metrics (month summary strip + per-week cards, metric tiles per enclave).'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','Weeks','Bytes')
                inputs       = @(
                    @{ name='Enclave'; label='Enclave (NIPR / SIPR / blank=all)'; type='text'; required=$false },
                    @{ name='colorblind'; label='Colorblind-safe palette'; type='select'; required=$false; default='None'; options=@('None','Protanopia','Deuteranopia','Tritanopia') },
                    @{ name='OutputPath'; label='Output HTML path (blank = return inline)'; type='savefile'; filter='HTML files (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*'; required=$false }
                )
            },
            @{
                id          = 'weekly-export-csv'
                label       = 'Weekly Export CSV'
                description  = 'Export the most recently parsed weekly metrics to CSV (raw scans + category roll-up + PMO owner breakdown + totals). Blank Week = first parsed week-block; AllWeeks writes one CSV per non-empty week. The desktop XLSX export is not ported - CSV only.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','Weeks','Bytes')
                inputs       = @(
                    @{ name='Enclave';    label='Enclave (NIPR / SIPR / blank=first)'; type='text'; required=$false },
                    @{ name='Week';       label='Week (DateRange of a parsed week; blank = first)'; type='text'; required=$false },
                    @{ name='AllWeeks';   label='Export all non-empty weeks (one CSV per week)'; type='bool'; required=$false; default=$false },
                    @{ name='OutputPath'; label='Output CSV path (blank = return inline; with AllWeeks the per-week files land in its folder)'; type='savefile'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false }
                )
            },
            @{
                id          = 'cora-build-summary'
                label       = 'CORA Build Summary'
                description  = 'Analyze current open + actionable ACAS findings: total vulns, severity breakdown, top 15 vulns by host count, category breakdown, VPH, and network %.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Metric','Value')
                inputs       = @(
                    @{ name='NetworkDeviceCount'; label='Total devices on network (for % of fleet; 0 = hide)'; type='int'; required=$false; default=0 }
                )
            },
            @{
                id          = 'cora-render-html'
                label       = 'CORA Render HTML'
                description  = 'Generate a commander-brief HTML report from the current findings: headline tiles, top-15 vuln cards, severity / category breakdown.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','UniqueHosts','Bytes')
                inputs       = @(
                    @{ name='NetworkDeviceCount'; label='Total devices on network (for % of fleet; 0 = hide)'; type='int'; required=$false; default=0 },
                    @{ name='colorblind'; label='Colorblind-safe palette'; type='select'; required=$false; default='None'; options=@('None','Protanopia','Deuteranopia','Tritanopia') },
                    @{ name='OutputPath'; label='Output HTML path (blank = return inline)'; type='savefile'; filter='HTML files (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*'; required=$false }
                )
            },
            @{
                id          = 'remediation-refresh'
                label       = 'Remediation Refresh'
                description  = 'Build a remediation plan from current ACAS findings: fixed app buckets (Chrome, Edge, Office, Defender, KB, Other) with target version, host count, severity, and KEV (known-exploited) host count; dynamic cards for common Other vulns affecting >= 10 hosts.'
                kind         = 'table'
                destructive  = $false
                columns      = @('App','TargetCount','TargetVersion','CriticalCount','HighCount','KevCount')
                inputs       = @(
                    @{ name='NetworkDeviceCount'; label='Total devices on network (for % of fleet; 0 = hide)'; type='int'; required=$false; default=0 }
                )
            },
            @{
                id          = 'acas-load-baseline'
                label       = 'ACAS Load Baseline'
                description  = 'Parse a BASELINE scan (taken BEFORE patching) into a separate session store for scan-to-scan comparison. Does not touch the current findings set; replaces any previously loaded baseline.'
                kind         = 'table'
                destructive  = $false
                columns      = @('File','Findings','Hosts')
                inputs       = @(
                    @{ name='file'; label='Baseline ACAS file path (.nessus / .csv / .tsv)'; type='file'; filter='ACAS files (*.nessus;*.csv;*.tsv)|*.nessus;*.csv;*.tsv|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'acas-load-comparison'
                label       = 'ACAS Load Comparison'
                description  = 'Parse a COMPARISON scan (taken AFTER patching) into a separate session store for scan-to-scan comparison. Does not touch the current findings set; replaces any previously loaded comparison.'
                kind         = 'table'
                destructive  = $false
                columns      = @('File','Findings','Hosts')
                inputs       = @(
                    @{ name='file'; label='Comparison ACAS file path (.nessus / .csv / .tsv)'; type='file'; filter='ACAS files (*.nessus;*.csv;*.tsv)|*.nessus;*.csv;*.tsv|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'acas-run-compare'
                label       = 'ACAS Scan Compare'
                description  = 'Compare the loaded baseline (BEFORE) against the loaded comparison scan (AFTER, from ACAS Load Comparison) on the Hostname|PluginID key: REMEDIATED (baseline only), STILL OPEN (both), NEW (comparison only). Filters affect the rows shown; the full delta is kept for ACAS Apply Remediated.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Hostname','PluginID','VulnName','Severity','Delta')
                inputs       = @(
                    @{ name='deltaFilter';    label='Delta filter';    type='select'; options=@('All','REMEDIATED','STILL OPEN','NEW'); default='All'; required=$false },
                    @{ name='hostFilter';     label='Host filter (substring, blank = all)'; type='text'; required=$false },
                    @{ name='severityFilter'; label='Severity filter'; type='select'; options=@('All','Critical','High','Medium','Low','Info'); default='All'; required=$false }
                )
            },
            @{
                id          = 'scan-closure-proof'
                label       = 'ACAS Prove Closure'
                description  = 'Prove the wave worked: run the baseline-vs-comparison compare, then join every REMEDIATED and STILL OPEN row against the audit trail JANET already writes (per-tool TouchedHosts + detail CSVs on the log share, local-spool fallback) between the two scan dates. Adds TouchedByJanet / Tool / Operator / TouchDate and states causation - N closed on hosts JANET touched (wave worked), M closed on untouched hosts (something else), K still-open on touched hosts (patch did not take = next-day worklist). Read-only.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Hostname','PluginID','Severity','Delta','TouchedByJanet','Tool','Operator','TouchDate')
                inputs       = @(
                    @{ name='baselineDate';   label='Baseline scan date (YYYY-MM-DD; blank = 90 days before comparison)'; type='text'; required=$false },
                    @{ name='comparisonDate'; label='Comparison scan date (YYYY-MM-DD; blank = today)'; type='text'; required=$false },
                    @{ name='hostFilter';     label='Host filter (substring, blank = all)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'acas-apply-remediated'
                label       = 'ACAS Apply Remediated'
                description  = 'Mark every currently loaded finding (ACAS Parse File) whose Hostname|PluginID was classified REMEDIATED by the last ACAS Scan Compare as Status=Patched (PatchedBy=Scan Comparison). Mutates session state only - re-parse the file to undo.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Metric','Value')
                inputs       = @()
            },
            @{
                id          = 'acas-clear-state'
                label       = 'ACAS Clear Compare State'
                description  = 'Clear the loaded baseline scan, comparison scan, and the last compare result (frees session memory). Does NOT touch the current findings loaded by ACAS Parse File.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Store','Cleared')
                inputs       = @()
            },
            @{
                id          = 'acas-mark-status'
                label       = 'ACAS Mark Status'
                description  = 'Triage loaded findings by Hostname|PluginID key: mark Patched (records by/date), NOT OUR PATCH (recategorizes), or Open (undo - recomputes the category and clears patch info). CORA / remediation actions then exclude Patched and NOT OUR PATCH findings.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Hostname','PluginID','NewStatus','Outcome')
                inputs       = @(
                    @{ name='keys';        label='Finding keys (one Hostname|PluginID per line)'; type='textarea'; required=$true },
                    @{ name='newStatus';   label='New status'; type='select'; options=@('Patched','NOT OUR PATCH','Open'); default='Patched'; required=$false },
                    @{ name='patchedBy';   label='Patched by (used when Patched; blank = you)'; type='text'; required=$false; default="$(Get-ReportsCleanUser)" },
                    @{ name='patchedDate'; label='Patched date (blank = today)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'remediation-mark-pushed'
                label       = 'Remediation Mark Pushed'
                description  = 'Record push status for a Remediation Refresh row: app bucket (Chrome / Edge / Office / Defender / KB / Other) or an Other-vuln group ("Plugin <id>", a bare plugin ID, or the "Other: <vuln name>" label). Pushed/Skipped rows drop out of the next Remediation Refresh; Pending resets them.'
                kind         = 'table'
                destructive  = $false
                columns      = @('App','NewStatus','RowsChanged')
                inputs       = @(
                    @{ name='app';    label='App bucket or group (as shown by Remediation Refresh)'; type='text'; required=$true },
                    @{ name='status'; label='Status'; type='select'; options=@('Pushed','Skipped','Pending'); default='Pushed'; required=$false }
                )
            },
            @{
                id          = 'acas-host-summary'
                label       = 'ACAS Host Summary'
                description  = 'Per-host dashboard over the loaded findings: severity breakdown, KEV (known-exploited) count, Patched / Open / NOT OUR PATCH tallies, and patch rate (Patched of Patched+Open; N/A when a host has no actionable findings).'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','TotalVulns','Crit','High','Med','Low','Info','Kev','Patched','Open','NotOurs','PatchRate')
                inputs       = @()
            },
            @{
                id          = 'sla-aging'
                label       = 'SLA / Finding Aging'
                description  = 'Remediation SLA dashboard: joins the loaded OPEN findings + their firstSeen date (backfilled from the persisted JanetLocal\sla-ledger.json so the aging clock survives a fresh re-parse) + the editable JanetLocal\sla-baseline.json remediation windows (days-to-remediate per severity; KEV overrides). Each finding gets ageDays, dueIn (days to deadline), and a bucket: ON-TRACK / DUE-SOON (<=25% of the window or <=3 days left) / OVERDUE / NEW-UNTRACKED (no firstSeen, not yet in the ledger). Read-only; CSV-exportable for POA&M.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','Plugin','VulnName','Severity','KEV','IAVA','FirstSeen','AgeDays','DueIn','Bucket')
                inputs       = @()
            },
            @{
                id          = 'export-poam'
                label       = 'Export eMASS POA&M (CSV)'
                description  = 'Export the loaded OPEN findings as an RMF/eMASS POA&M workbook (CSV, one row per open finding) using the eMASS POA&M import-template columns. Severity maps to a DISA CAT level, the Scheduled Completion Date is derived from the SLA window + firstSeen (KEV overrides), Recommendations carries the scanner Steps-to-Remediate, and KEV/IAVM are noted in Comments. Read-only; download and hand to the ISSM/ISSO. No new dependencies (CSV, not XLSX).'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','Finding','Severity','CAT','Status','ScheduledCompletion','KEV')
                inputs       = @()
            },
            @{
                id          = 'acas-ping-hosts'
                label       = 'ACAS Ping Hosts'
                description  = 'Ping every distinct host in the loaded findings in parallel and record an online/offline map, so the import grid can be filtered to just the hosts reachable right now (and the offline ones exported for follow-up).'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Online')
                inputs       = @(
                    @{ name='threads';   label='Parallel pingers (1-32)'; type='int'; required=$false; default=32 },
                    @{ name='timeoutMs'; label='Ping timeout (ms)'; type='int'; required=$false; default=1500 }
                )
            },
            @{
                id          = 'acas-export-findings'
                label       = 'ACAS Export Findings (CSV)'
                description  = 'Export the loaded findings (with their triage Status / PatchedBy / PatchedDate) to a downloadable CSV. View picks which subset: Full (all), Open (still actionable), NOT OUR PATCH, or Patched.'
                kind         = 'table'
                destructive  = $false
                columns      = @('View','Findings','Bytes')
                inputs       = @(
                    @{ name='view'; label='View'; type='select'; options=@('Full (all findings)','Open (remaining)','NOT OUR PATCH','Patched','Offline (host down)'); default='Full (all findings)'; required=$false }
                )
            },
            @{
                id          = 'acas-save-report'
                label       = 'ACAS Save Report (JSON)'
                description  = 'Save all loaded findings and their triage state (Status / PatchedBy / PatchedDate / Category) to a downloadable JSON file, so the work survives a server restart. Reload it later with ACAS Load Report.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Findings','Bytes')
                inputs       = @()
            },
            @{
                id          = 'acas-load-report'
                label       = 'ACAS Load Report (JSON)'
                description  = 'Restore findings + triage state from a JSON file saved by ACAS Save Report. Replaces the currently loaded findings.'
                kind         = 'table'
                destructive  = $false
                columns      = @('File','Findings','Hosts')
                inputs       = @(
                    @{ name='file'; label='Saved report JSON file'; type='file'; filter='JSON files (*.json)|*.json|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'resolve-target-ips'
                label       = 'Resolve Target IPs'
                description  = 'Parallel DNS resolve + ping of future target hostnames (e.g. an AQC pre-target list): IP, Online / Offline / DNS Failed status, and latency per host.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','IP','Status','LatencyMs')
                inputs       = @(
                    @{ name='targets';   label='Target hostnames (one per line)'; type='hostlist'; required=$true },
                    @{ name='threads';   label='Parallel resolvers (1-32)'; type='int'; required=$false; default=32 },
                    @{ name='timeoutMs'; label='Ping timeout (ms)'; type='int'; required=$false; default=1500 }
                )
            },
            @{
                id          = 'squadron-rollup'
                label       = 'Squadron Rollup'
                description  = 'Read-only fleet-activity rollup from the central JANET log share: aggregates the monthly usage rollup (Logs\<YYYY-MM>_usage.csv) plus every per-tool detail CSV (Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv) into one row per operator - and one per squadron when AD can classify the touched hostnames (needs credentials; otherwise operator-level only). Columns: actions run, distinct hosts touched, TouchHost successes/failures, vulns patched, sessions, tool mix, last-active date. 445-gated; an unreachable share fails friendly. Detail parsing is capped for very large months (the cap is noted in the summary).'
                kind         = 'table'
                destructive  = $false
                columns      = @('Level','Name','Actions','Hosts','TouchOK','TouchFail','Vulns','Sessions','TopTools','LastActive')
                inputs       = @(
                    @{ name='monthsBack'; label='Months back (1 = current month)'; type='int'; required=$false; default=1 }
                )
            },
            @{
                id          = 'remediation-route'
                label       = 'Remediation Router'
                description  = 'Scan-to-patch correlation over the loaded findings: group every OPEN (not-yet-Patched) finding by its Categorize-Finding bucket and map each bucket to the concrete JANET remediation that clears it - acas Run Vulnerability Update (Chrome / Edge / Office / Defender / registry-hardening profiles), acas Install KBs (KB patches), or the Unsupported Product Remediator (upr) for EOL / not-our-patch products. Buckets with no safe one-click route fall to manual review. Rows: bucket, mapped tool, mapped action/profile, finding count, host count, affected hosts, sample plugins. Summary reports routable % vs manual. Read-only - the view can load a route''s hosts into the shared target list and hand off to the mapped tool.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Bucket','Tool','Action','Profile','FindingCount','HostCount','SamplePlugins')
                inputs       = @()
            },
            @{
                id          = 'remediation-plan'
                label       = 'Remediation Planner (per-host)'
                description  = 'Inverts the Remediation Router into a PER-HOST work queue: one row per affected host listing the distinct JANET remediations that host needs (patch X, update Y, remove Z), its open-finding count, severity mix, KEV count, and how many findings are routable vs need manual review. Read-only planning ONLY - it tells the operator exactly what to run where; every destructive step is then executed by the operator through the mapped tool''s existing admin-session + confirm-word + DNS/self guards. No host is touched here and no new execution path is created. Sort by KEV/severity to work the worst hosts first.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','Findings','Sev','KEV','Routable','Manual','Plan')
                inputs       = @()
            },
            @{
                id          = 'kb-needed'
                label       = 'KBs Needed (from scan)'
                description  = 'Extract the exact KB ids the loaded Tenable/ACAS findings say to install (from the plugin name + Solution text), so you can push precisely what the scan found instead of a broad profile. Rolls up by KB with supersedence in mind - one cumulative KB clears many hosts, so the KB affecting the most hosts leads (KEV-carrying KBs first). Per-KB rows show affected host count, worst severity, KEV, and sample plugins. The full KB list (copy into Patch Content to check staged-content coverage) and a per-host Host,KB list (feed WPT KB Installer) ship in the summary. Read-only.'
                kind         = 'table'
                destructive  = $false
                columns      = @('KB','Hosts','Severity','KEV','Findings','SamplePlugins')
                inputs       = @()
            },
            @{
                id          = 'thirdparty-catalog'
                label       = 'Third-Party Catalog (from scan)'
                description  = 'The flip side of KBs Needed: on a real Tenable scan only ~1% of findings name a KB - the other ~99% are third-party / version-upgrade vulns (Chrome, Firefox, Adobe, Java, 7-Zip, Notepad++, VLC, Wireshark, PuTTY, .NET, ...). This rolls those NON-KB findings up by PRODUCT so the biggest vuln-reduction levers stand out at a glance: distinct affected host count, worst severity, KEV, a representative fixed/target version, the mapped JANET remediation route (same Categorize-Finding + Remediation Router mapping the Planner uses, so routes stay consistent), and finding count. Ranked KEV-first, then most hosts, then worst severity. Read-only - it names the products to upgrade; execution runs through the mapped tools'' own gated engines. Pairs with KBs Needed to cover 100% of open findings.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Product','Hosts','Severity','KEV','FixedVersion','Route','Findings')
                inputs       = @()
            },
            @{
                id          = 'iavm-board'
                label       = 'IAVM Board (compliance rollup)'
                description  = 'DoD grades technical-vulnerability compliance by IAVA/IAVM bulletin, not by raw CVE. Each loaded finding is tagged with its IAVA id (from the shipped IavmMap CVE->bulletin map); this rolls the OPEN (not-yet-Patched) findings up BY BULLETIN so the operator sees compliance the way the inspector does: distinct affected hosts, worst severity, KEV, open finding count, a sample of the bulletin''s CVEs, and sample plugin ids. Ranked KEV-first, then most hosts, then worst severity. Findings that carry no IAVA are counted separately (not every plugin maps to a bulletin). The parsed scan carries no per-bulletin compliance/due date, so this is a pure counts/severity/KEV rollup (no overdue bucketing). Read-only.'
                kind         = 'table'
                destructive  = $false
                columns      = @('IAVA','Hosts','Severity','KEV','Findings','CVEs','Plugins')
                inputs       = @()
            },
            @{
                id          = 'posture-digest'
                label       = 'Posture Digest (nightly snapshot)'
                description  = 'Render the current vuln posture to a self-contained HTML + a CSV on disk, so it can be armed on the off-hours Scheduler (reports/posture-digest) to drop a fresh snapshot on an audit share every night - no email/infra needed. Reuses the same rollups as the Dashboard/CORA (severity + host totals), SLA / Finding Aging, KBs Needed, Third-Party Catalog, and IAVM Board. Read-only; writes only the two digest files to outDir (created if missing).'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','Path','Kind','Bytes')
                inputs       = @(
                    @{ name='outDir'; label='Output folder (blank = JanetLocal\digests; can be a UNC share)'; type='text'; required=$false },
                    @{ name='title';  label='Report title (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'burndown-snapshot'
                label       = 'Burndown: Snapshot Now'
                description  = 'Append one point to the persisted vuln-backlog trend (JanetLocal\trend\burndown.jsonl): total open findings + severity mix + KEV + host count, reusing the same Build-CoraSummary tallies posture-digest uses (not recomputed). Read-only against hosts - only appends one small local JSON line. Can be armed on the off-hours Scheduler (reports/burndown-snapshot) to capture a nightly point automatically, so the Burndown trend fills in with nobody at the keyboard.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Field','Value')
                inputs       = @(
                    @{ name='label'; label='Snapshot label (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'burndown'
                label       = 'Burndown Trend'
                description  = 'Read the persisted vuln-backlog trend (JanetLocal\trend\burndown.jsonl) and compute the trajectory: open-findings delta and % closed from the first snapshot to the latest, KEV closed, plus the raw snapshot series for the chart. "Are we winning?" at a glance. Read-only; take snapshots (Burndown: Snapshot Now, or arm it nightly on the Scheduler) to build the series over time.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Date','TotalOpen','Critical','High','KEV','Hosts')
                inputs       = @()
            },
            @{
                id          = 'campaign-create'
                label       = 'Create Remediation Campaign'
                description  = 'Snapshot the currently loaded OPEN findings into a persisted remediation campaign (JanetLocal\campaigns\<id>.json): the finding keys (Hostname|PluginID), the affected host set, the distinct mapped JANET remediations, and the severity/KEV mix. This ties finding -> fix -> (later) re-verify so a wave can be tracked to closure. READ-ONLY: creates the tracking record only; the actual remediation runs through the gated engines. Re-import the next scan and use the campaign to prove closure.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Field','Value')
                inputs       = @(
                    @{ name='name'; label='Campaign name'; type='text'; required=$false; default='' }
                )
            },
            @{
                id          = 'campaign-list'
                label       = 'Remediation Campaigns'
                description  = 'List every saved remediation campaign (JanetLocal\campaigns\*.json), newest first: name, when/who created, status, open-finding count at creation, KEV count, and affected host count. Read-only.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','Created','Status','OpenFindings','KEV','Hosts')
                inputs       = @()
            },
            @{
                id          = 'campaign-verify'
                label       = 'Verify Campaign (close the loop)'
                description  = 'Close the loop on a saved campaign: load a FRESH scan (ACAS Import), then verify against the campaign''s snapshotted finding keys - each key still OPEN in the new scan is STILL-OPEN, each key gone is REMEDIATED. Records the result back onto the campaign JSON (verify block + closedPct) and flips status to VERIFIED-CLOSED when every finding is remediated. Read-only against hosts; proves remediation without waiting for the weekly re-import to be eyeballed.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','Plugin','VulnName','Severity','KEV','State')
                inputs       = @(
                    @{ name='campaignId'; label='Campaign ID'; type='text'; required=$true; default='' }
                )
            },
            @{
                id          = 'command-brief'
                label       = 'Executive Command Brief'
                description  = 'One self-contained dark-theme HTML commander brief that rolls up the other reports: SLA aging buckets (ledger-backed, works at idle), open KEV (known-exploited) posture, the last Squadron Rollup this session, the newest WPT fleet-compliance snapshots trend (read straight from JanetLocal\snapshots - no wpt import), the Remediation Router routable-vs-manual split, and scan-closure numbers when a Patch Cross-Ref compare has run this session. Each section degrades to a "run X first" note when its source is empty. Build LAST after the sections it consumes.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Report','Sections','Bytes')
                inputs       = @(
                    @{ name='colorblind'; label='Colorblind-safe palette'; type='select'; required=$false; default='None'; options=@('None','Protanopia','Deuteranopia','Tritanopia') },
                    @{ name='OutputPath'; label='Output HTML path (blank = return inline)'; type='savefile'; filter='HTML files (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*'; required=$false }
                )
            }
        )
    }
}

# -----------------------------------------------------------------------------
# Module-scoped session state (replaces the original's $global:* / $script:*).
# Persists across Invoke calls within the same loaded module so a parse feeds
# the renderers / summarizers, exactly like the WinForms tool's tabs did.
# -----------------------------------------------------------------------------
$script:AcasFindings        = New-Object System.Collections.ArrayList
$script:Dirty30Hosts        = New-Object System.Collections.ArrayList
$script:Dirty30AdResults    = @{}
$script:Dirty30LastUserMap  = @{}
$script:Dirty30SourceLabel  = $null
$script:AcasCalcWeeks       = New-Object System.Collections.ArrayList
$script:AcasCalcSourceFile  = $null
$script:NetworkDeviceCount  = 0

# Scan-to-scan comparison state - three independent stores, exactly like the
# desktop Patch Cross-Ref tab ($global:BaselineScan / $global:ComparisonScan /
# $global:ComparisonResults, ReportsTool_2.14.5.ps1:2381-2383): Baseline = the
# BEFORE-patching scan, Comparison = a SEPARATE AFTER-patching scan, and the
# delta is applied to $script:AcasFindings (the import/triage set). Keeping the
# comparison scan separate from AcasFindings is what lets acas-apply-remediated
# mark the REMEDIATED (baseline-only) keys in the import set. ComparisonResults
# stays $null until a compare runs so apply can tell "never ran" from "zero deltas".
$script:BaselineFindings     = New-Object System.Collections.ArrayList
$script:ComparisonFindings   = New-Object System.Collections.ArrayList
$script:ComparisonResults    = $null

# Remediation plan state (session-only; resets on module reload, by design).
$script:RemediationStatus      = @{}
$script:OtherVulnPushed        = @{}
$script:OtherVulnGroupMinHosts = 10
# Host reachability map from acas-ping-hosts (hostname -> [bool] online); lets the
# import grid filter findings to reachable hosts + export the offline subset. (#10)
$script:AcasHostOnline         = @{}
# Last Squadron Rollup summary this session (set by 'squadron-rollup'); the
# Executive Command Brief reads it instead of re-running the heavy log-share parse.
# $null = not run this session (the brief shows a "run Squadron Rollup first" note).
$script:LastSquadronRollup     = $null

# Remediation Router mapping (scan-to-patch correlation, action 'remediation-route').
# Maps each Categorize-Finding bucket to the concrete JANET remediation that clears
# it. Source of the tool ids / action ids / profile names - keep in sync, do NOT
# import (each engine loads in its own runspace):
#   - acas: JanetWeb.acas.psm1 -> manifest action id 'run-vulnerability' (label
#     'Run Vulnerability Update'); profile strings are keys of
#     $script:AcasUpdateProfiles (Google Chrome - Update, Microsoft Edge - Update,
#     Microsoft 365 - Force Update, Windows Defender - Update Definitions, Windows
#     Unquoted Service Path - Remediate).
#   - wpt:  JanetWeb.wpt.psm1  -> manifest action id 'kb-install' (label 'Install
#     KBs'). KB routes go to WPT because WPT is the tool that reads the SHARED
#     target list (ctx.targets) the view's Send-to-tool handoff loads; acas/upr
#     scan their own imported host set, so the view hands them the hosts via the
#     clipboard instead (see reports.view.js sendRoute).
#   - upr:  JanetWeb.upr.psm1  -> tool id 'upr' (Unsupported Product Remediator),
#     for EOL / unsupported / not-our-patch products.
# Buckets with no safe one-click route (Other and anything unlisted) fall through
# to 'manual review' (Routable=$false) at the action. Tracked-exception buckets
# (IsException, empty ToolId) route to NOTHING but are labelled a POA&M exception,
# so coverage counts them apart from both routable and manual-review piles.
#
# ROUTE Profile CONVENTION: for an acas 'run-vulnerability' route Profile is the
# ACAS profile name; for a wpt 'registry-key-apply' route Profile carries the
# reg-key CATALOG KEY (becomes the 'cvekey' param at the handoff).
$script:RemediationRouteMap = @{
    'Chrome'        = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update';      Profile='Google Chrome - Update' }
    'Edge'          = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update';      Profile='Microsoft Edge - Update' }
    'Office'        = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update';      Profile='Microsoft 365 - Force Update' }
    'Defender'      = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update';      Profile='Windows Defender - Update Definitions' }
    # Apache / Log4j / Tomcat / Struts / httpd all bucket to 'Apache' - route them
    # to the ACAS Log4j jar-replace profile (the vast bulk of the pile is Log4j).
    # NOTE: that profile currently swaps only 2 hard-coded lib paths (HID + Adobe);
    # generalizing it is a SEPARATE follow-up - routing the bucket is still correct.
    'Apache'        = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update';      Profile='Apache Log4j - Replace Vulnerable Jars' }
    'KB Patch'      = @{ ToolId='wpt';  ActionId='kb-install';        Action='Install KBs';                   Profile='' }
    # Only genuine unquoted-service-path findings route to that profile (it mutates
    # service ImagePath registry values). The broad 'Registry Fix' bucket (SMB
    # signing, IE/GPO hardening, ...) has NO one-click route and falls through to
    # manual review - see the promotion in remediation-route.
    'Unquoted Service Path' = @{ ToolId='acas'; ActionId='run-vulnerability'; Action='Run Vulnerability Update'; Profile='Windows Unquoted Service Path - Remediate' }
    # Intel BHI / speculative-execution -> the WPT reg-key fix (FeatureSettingsOverride
    # bits). Profile carries the reg-catalog KEY 'BHI' -> becomes cvekey at the handoff.
    'Speculative Execution' = @{ ToolId='wpt'; ActionId='registry-key-apply'; Action='Apply Registry Fix'; Profile='BHI' }
    'NOT OUR PATCH' = @{ ToolId='upr';  ActionId='';                  Action='Unsupported Product Remediator'; Profile='' }
    # No local PowerShell fix (self-signed / untrusted certs, ~764 findings). Routes
    # to nothing but is a TRACKED exception (POA&M), not a "manual review" that
    # implies a fix exists. Empty ToolId + IsException keep it out of routable counts.
    'Exception (no local fix)' = @{ ToolId=''; ActionId=''; Action='Tracked exception - no local fix (POA&M)'; Profile=''; IsException=$true }
}

# A route is an ACTIONABLE one-click fix only when it names a tool. Tracked-exception
# entries (IsException + empty ToolId) are explicitly "no local fix" (POA&M) - counted
# apart from both routable and plain manual-review buckets. Central so every consumer
# (Router / Planner / Catalog / Campaign / Command Brief) reads the same rule.
function Test-JanetWebRouteActionable {
    param($Route)
    return [bool]($Route -and -not [string]::IsNullOrWhiteSpace([string]$Route.ToolId))
}

# audit 2026-07-23: ONE severity -> numeric rank map for every rollup that sorts or
# maxes by severity (kb-needed / thirdparty-catalog / iavm-board / export-poam) -
# previously re-declared inline per action. The two hot-loop switch forms in
# Build-RemediationPlan / Build-CoraSummary stay local (converting them is not a
# mechanical swap).
$script:SeverityRank = @{ 'Critical'=4; 'High'=3; 'Medium'=2; 'Low'=1; 'Info'=0 }

# audit 2026-07-23: the Router / Planner / Third-Party Catalog / Campaign /
# Command-Brief bucket classifier (Defender + unquoted-service-path promotion,
# else the finding's Category, blank -> Other) lived as five identical copies -
# one function so the bucketing can never drift between the views.
# Build-RemediationPlan's Defender-only split keeps its own variant by design
# (no unquoted-service-path promotion there).
function Get-ReportsRouteBucket {
    param($Finding)
    $vn = ($Finding.VulnName -as [string]).ToLower()
    if ($vn -match 'defender|microsoft security essentials|antimalware') { return 'Defender' }
    if ("$vn $(($Finding.Solution -as [string]).ToLower())" -match 'unquoted service path') { return 'Unquoted Service Path' }
    $bucket = [string]$Finding.Category
    if ([string]::IsNullOrWhiteSpace($bucket)) { return 'Other' }
    return $bucket
}

# Scan-name -> category/owner classifier. ORDER MATTERS - first match wins.
# Lifted verbatim from ReportsTool_2.14.5.ps1 ($global:AcasCategoryRules:2417).
$script:AcasCategoryRules = @(
    @{ Pattern = 'ONBoarding|Onboarding|ISE Server|Enterprise_ESXI|VDI |VDI\.|VDI_|Bad Host|Lakenheath-Non-Reportable|Differential Scan'; Category = 'Ignore'; Owner = $null }
    @{ Pattern = 'PMO WEATHER';                                              Category = 'PMO'; Owner = 'Weather' }
    @{ Pattern = 'PMO AFLCMC_ELX|Servers\.Linux-PMO-ELX';                    Category = 'PMO'; Owner = 'AFLCMC / ELX' }
    @{ Pattern = 'PMO AFLCMC_ACAS|Servers\.Linux-PMO ACAS';                  Category = 'PMO'; Owner = 'AFLCMC / ACAS' }
    @{ Pattern = '1stACOS';                                                  Category = 'PMO'; Owner = '1st ACOS' }
    @{ Pattern = 'PMO UE';                                                   Category = 'PMO'; Owner = 'AFAS' }
    @{ Pattern = 'UEs_Vuln|UE\.User Endpts';                                 Category = 'UEs'; Owner = $null }
    @{ Pattern = 'DCs Lakenheath|Server\.Windows|CES_Servers|48 CS Servers|ACAS SCANNERS|Servers\.Windows_Vuln'; Category = 'Servers'; Owner = $null }
    @{ Pattern = 'Infrastructure';                                           Category = 'Infrastructure'; Owner = $null }
    @{ Pattern = 'Printer';                                                  Category = 'Printers';       Owner = $null }
)

# =============================================================================
#  Region: shared helpers (no-UI ports of the original engine functions)
# =============================================================================


function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# Human-facing author label: drop the .csa admin suffix so report bylines and
# "Patched by" defaults read as the bare EDIPI (matches the cleaned Operator
# string from Get-JanetWebOperatorIdentity). Display only - never used for paths.
function Get-ReportsCleanUser {
    $u = ($env:USERNAME -replace '(?i)\.csa$', '').Trim()
    if ([string]::IsNullOrWhiteSpace($u)) { $u = [string]$env:USERNAME }
    return $u
}

# Shared report colour palette (the :root custom-property block) for all HTML
# report renderers - one source of truth instead of three near-duplicate blocks,
# plus optional colorblind-safe swaps of the success/danger pair. Default 'None'
# returns the standard JANET dark palette (byte-identical to the old Dirty 30
# block). Kept hidden-default - no SPA action param yet - so AFNET output is
# unchanged until a colorblind mode is explicitly wired to a manifest field.
function Get-JanetReportCSS {
    param([string]$ColorblindMode = '')
    # Caller usually omits the arg; fall back to the per-invocation mode set from
    # the action's 'colorblind' input. Any unrecognized value safely = standard.
    if ([string]::IsNullOrWhiteSpace($ColorblindMode)) {
        $ColorblindMode = if ($script:JanetReportColorblind) { [string]$script:JanetReportColorblind } else { 'None' }
    }
    $success = 'rgb(92,198,120)'; $danger = 'rgb(220,92,100)'; $warning = 'rgb(245,180,70)'
    switch ($ColorblindMode) {
        'Protanopia'   { $success = 'rgb(0,160,255)';  $danger = 'rgb(220,140,0)' }
        'Deuteranopia' { $success = 'rgb(0,160,255)';  $danger = 'rgb(220,140,0)' }
        'Tritanopia'   { $success = 'rgb(255,100,180)'; $danger = 'rgb(0,200,210)' }
    }
    return @"
  :root {
    --bg: rgb(8,8,12); --panel: rgb(18,18,26); --panel-light: rgb(30,28,40);
    --input: rgb(22,22,30); --border: rgb(38,34,52); --text: rgb(240,240,245);
    --text-dim: rgb(210,208,220); --text-faint: rgb(180,178,195);
    --accent: rgb(140,100,220); --success: $success; --warning: $warning;
    --danger: $danger; --cyan: rgb(80,200,220); --gold: rgb(238,196,88); --orange: rgb(232,140,70);
  }
"@
}

function Categorize-Finding {
    param([string]$VulnName, [string]$Solution, [string]$PluginID)
    $combined = "$VulnName $Solution".ToLower()
    if ($combined -match 'chrome|chromium|google chrome')          { return 'Chrome' }
    if ($combined -match 'edge|msedge|microsoft edge')            { return 'Edge' }
    if ($combined -match 'apache|log4j|tomcat|httpd|struts')      { return 'Apache' }
    if ($combined -match 'office|word|excel|outlook|powerpoint|visio|access|onenote|microsoft 365') { return 'Office' }
    if ($combined -match '\bkb\d{6,}\b|cumulative update|security update|servicing stack|\.net framework.*update') { return 'KB Patch' }
    # Speculative-execution / Intel BHI - the WPT reg-key 'BHI' fix (FeatureSettingsOverride).
    # ABOVE 'Registry Fix' so BHI (whose solution names a registry key) is not stolen by it.
    if ($combined -match 'bhi|branch history injection|cve-2022-0001|spectre|meltdown|speculative execution|featuresettingsoverride') { return 'Speculative Execution' }
    if ($combined -match 'registry|regedit|reg key|group policy|gpo|local policy') { return 'Registry Fix' }
    # Untrusted / self-signed certificates have no local PS fix - track as a POA&M
    # exception (ABOVE the NOT OUR PATCH / Other catch-alls) rather than imply a fix.
    if ($combined -match 'cert.*not.*trust|self-signed certificate|untrusted certificate') { return 'Exception (no local fix)' }
    if ($combined -match 'not a(n)?\s+(microsoft|windows)|third.party|vendor|contact.*vendor|no (patch|fix|update) available|eol|end.of.life|unsupported|adobe|java|firefox|vmware|cisco|oracle|apple') { return 'NOT OUR PATCH' }
    return 'Other'
}

# Third-party PRODUCT keyword list for the 'thirdparty-catalog' action. The
# existing Categorize-Finding + $script:RemediationRouteMap already name and route
# the routable buckets (Chrome/Edge/Office); this finer list only adds the PRODUCT
# names Categorize-Finding lumps into 'NOT OUR PATCH'/'Other' (Adobe, Java,
# Firefox, 7-Zip, Notepad++, VLC, ...). The catalog action derives its ROUTE from
# the same bucket mapping, so a product's route stays consistent with the Router /
# Planner. ORDER MATTERS - first match wins, most specific first.
$script:ThirdPartyProductRules = @(
    @{ Rx = 'mozilla firefox|firefox esr|\bfirefox\b';                     Name = 'Mozilla Firefox' }
    @{ Rx = 'mozilla thunderbird|\bthunderbird\b';                         Name = 'Mozilla Thunderbird' }
    @{ Rx = 'google chrome';                                               Name = 'Google Chrome' }
    @{ Rx = '\bchromium\b';                                                Name = 'Chromium' }
    @{ Rx = 'microsoft edge|\bmsedge\b';                                   Name = 'Microsoft Edge' }
    @{ Rx = 'adobe acrobat|acrobat reader|adobe reader';                   Name = 'Adobe Acrobat/Reader' }
    @{ Rx = 'adobe flash|flash player';                                    Name = 'Adobe Flash Player' }
    @{ Rx = 'adobe air';                                                   Name = 'Adobe AIR' }
    @{ Rx = 'adobe shockwave';                                             Name = 'Adobe Shockwave' }
    @{ Rx = '\badobe\b';                                                   Name = 'Adobe (other)' }
    @{ Rx = '\bopenjdk\b';                                                 Name = 'OpenJDK' }
    @{ Rx = 'oracle java|java runtime|java se|java\(tm\)|\bjre\b|\bjdk\b|\bjava\b'; Name = 'Oracle Java' }
    @{ Rx = '7-zip|\b7zip\b';                                              Name = '7-Zip' }
    @{ Rx = 'notepad\+\+';                                                 Name = 'Notepad++' }
    @{ Rx = 'vlc media player|\bvlc\b';                                    Name = 'VLC Media Player' }
    @{ Rx = '\bwireshark\b';                                               Name = 'Wireshark' }
    @{ Rx = '\bputty\b';                                                   Name = 'PuTTY' }
    @{ Rx = '\bfilezilla\b';                                               Name = 'FileZilla' }
    @{ Rx = '\bwinrar\b';                                                  Name = 'WinRAR' }
    @{ Rx = 'apache tomcat|\btomcat\b';                                    Name = 'Apache Tomcat' }
    @{ Rx = 'apache log4j|\blog4j\b';                                      Name = 'Apache Log4j' }
    @{ Rx = 'apache http|\bhttpd\b|apache server';                        Name = 'Apache HTTP Server' }
    @{ Rx = '\bopenssl\b';                                                 Name = 'OpenSSL' }
    @{ Rx = 'node\.js|\bnodejs\b';                                         Name = 'Node.js' }
    @{ Rx = '\bpython\b';                                                  Name = 'Python' }
    @{ Rx = '\.net core|\.net framework|microsoft \.net|\.net\b';         Name = 'Microsoft .NET' }
    @{ Rx = '\bvmware\b';                                                  Name = 'VMware' }
    @{ Rx = '\bzoom\b';                                                    Name = 'Zoom' }
    @{ Rx = 'microsoft onedrive|\bonedrive\b';                            Name = 'Microsoft OneDrive' }
    @{ Rx = 'microsoft teams|\bteams\b';                                   Name = 'Microsoft Teams' }
    @{ Rx = '\blibreoffice\b';                                             Name = 'LibreOffice' }
    @{ Rx = 'microsoft visual c\+\+|visual studio';                       Name = 'Microsoft Visual Studio/C++' }
    @{ Rx = 'microsoft office|microsoft 365|\boffice\b|\bword\b|\bexcel\b|\boutlook\b|powerpoint'; Name = 'Microsoft Office' }
    @{ Rx = 'git for windows';                                            Name = 'Git for Windows' }
)

# Return the third-party PRODUCT name a finding names (from VulnName + Solution
# text), or $null when no known product is recognized. First rule wins.
function Get-ReportsThirdPartyProduct {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = ([string]$Text).ToLower()
    foreach ($rule in $script:ThirdPartyProductRules) {
        if ($t -match $rule.Rx) { return $rule.Name }
    }
    return $null
}

function Parse-Severity {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Medium' }
    switch -Regex ($Value.Trim()) {
        '^4$|^critical'   { return 'Critical' }
        '^3$|^high'       { return 'High' }
        '^2$|^medium'     { return 'Medium' }
        '^1$|^low'        { return 'Low' }
        '^0$|^info|^none' { return 'Info' }
        default           { return $Value }
    }
}

# =============================================================================
#  KEV auto-flag  -  cross-reference every finding's CVE cell against the CISA
#  Known Exploited Vulnerabilities catalog that ships inside JANET
#  (JanetLocal\KevCatalog.txt). Private in-module copy of the reader semantics
#  used by JanetWeb.kev.psm1 (Read-KevCatalog) - deliberately NOT an import of
#  that module (each engine loads in its own runspace; keep reports self-
#  contained). The file is read ONCE per parse and the resulting HashSet is
#  threaded into every New-AcasFinding call so a finding whose CVE cell contains
#  a KEV CVE is flagged InKEV=$true (KevCves = the overlapping ids). A missing or
#  empty catalog is NOT a failure: findings simply parse with InKEV=$false and
#  the caller logs one warning line.
# -----------------------------------------------------------------------------
function Get-ReportsKevCatalogPath { Join-Path $PSScriptRoot '..\JanetLocal\KevCatalog.txt' }

# Read the KEV catalog fresh. Format-agnostic (newline / comma / semicolon / tab
# / space separated), de-duped case-insensitively, never throws. Returns a
# HashSet + count + source string. Mirrors JanetWeb.kev.psm1 Read-KevCatalog.
function Read-ReportsKevCatalog {
    $p   = Get-ReportsKevCatalogPath
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $source = ''
    if (Test-Path -LiteralPath $p) {
        try {
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if ($null -eq $raw) { $raw = '' }
            if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
            foreach ($tok in ($raw -split '[\r\n,;\t ]+')) {
                $c = ([string]$tok).Trim().ToUpper()
                if ($c -match '^CVE-\d{4}-\d{4,}$') { [void]$set.Add($c) }
            }
            $source = 'JanetLocal\KevCatalog.txt'
        } catch {
            $source = "read error: $($_.Exception.Message)"
        }
    } else {
        $source = '(missing - JanetLocal\KevCatalog.txt not found)'
    }
    return @{ Set = $set; Count = $set.Count; Source = $source; Path = $p }
}

# Extract EVERY CVE token from a finding's CVE cell and return the subset that is
# on the KEV catalog. @{ InKev = [bool]; KevCves = 'CVE-..., CVE-...' }. A null /
# empty catalog or CVE cell yields InKev=$false.
function Get-ReportsKevOverlap {
    param([string]$CveCell, $KevSet)
    $result = @{ InKev = $false; KevCves = '' }
    if ($null -eq $KevSet -or $KevSet.Count -eq 0) { return $result }
    if ([string]::IsNullOrWhiteSpace($CveCell)) { return $result }
    $hits = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($mm in [regex]::Matches([string]$CveCell, '(?i)CVE-\d{4}-\d{4,}')) {
        $c = $mm.Value.ToUpper()
        if (-not $seen.Add($c)) { continue }
        if ($KevSet.Contains($c)) { [void]$hits.Add($c) }
    }
    if ($hits.Count -gt 0) { $result.InKev = $true; $result.KevCves = ($hits -join ', ') }
    return $result
}

# =============================================================================
#  IAVM mapping  -  auto-tag every finding's CVE cell with its IAVA / bulletin id
#  from a small flat file that ships inside JANET (JanetLocal\IavmMap.csv, header
#  CVE,IAVA,Title). Same self-contained-reader pattern as the KEV auto-flag above
#  (private in-module copy of the reader semantics used by JanetWeb.kev.psm1 -
#  deliberately NOT an import; each engine loads in its own runspace). The file is
#  read ONCE per parse and the resulting map is threaded into every New-AcasFinding
#  call so a finding whose CVE cell contains a mapped CVE is stamped IAVA=<id>. A
#  missing / empty map is NOT a failure: findings parse with IAVA='' and the caller
#  logs one warning line. This is the ONLY reader (the writer is Write-ReportsIavmMap,
#  used by the iavm-add-map action).
# -----------------------------------------------------------------------------
function Get-ReportsIavmMapPath { Join-Path $PSScriptRoot '..\JanetLocal\IavmMap.csv' }

# Read the IAVM map fresh. CSV with header CVE,IAVA,Title; de-duped case-insensitively
# on CVE (first row wins); never throws. Returns @{ Map = dict CVE -> @{IAVA;Title};
# Count; Source; Path }. A missing / empty / corrupt file yields an empty (but valid) map.
function Read-ReportsIavmMap {
    $p   = Get-ReportsIavmMapPath
    $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $source = ''
    if (Test-Path -LiteralPath $p) {
        try {
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if ($null -eq $raw) { $raw = '' }
            if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                foreach ($r in @($raw | ConvertFrom-Csv -ErrorAction Stop)) {
                    if ($null -eq $r) { continue }
                    $cve = ''; if ($r.PSObject.Properties['CVE']) { $cve = ([string]$r.CVE).Trim().ToUpper() }
                    if ($cve -notmatch '^CVE-\d{4}-\d{4,}$') { continue }
                    $iava  = ''; if ($r.PSObject.Properties['IAVA'])  { $iava  = ([string]$r.IAVA).Trim() }
                    $title = ''; if ($r.PSObject.Properties['Title']) { $title = ([string]$r.Title).Trim() }
                    if (-not $map.ContainsKey($cve)) { $map[$cve] = @{ IAVA = $iava; Title = $title } }
                }
            }
            $source = 'JanetLocal\IavmMap.csv'
        } catch {
            $source = "read error: $($_.Exception.Message)"
        }
    } else {
        $source = '(missing - JanetLocal\IavmMap.csv not found)'
    }
    return @{ Map = $map; Count = $map.Count; Source = $source; Path = $p }
}

# Extract EVERY CVE token from a finding's CVE cell and return the distinct IAVA
# id(s) mapped by the IAVM map. @{ IAVA = '2024-A-0100, ...' }. A null / empty map
# or CVE cell yields IAVA=''.
function Get-ReportsIavmForCves {
    param([string]$CveCell, $IavmMap)
    $result = @{ IAVA = '' }
    if ($null -eq $IavmMap -or $IavmMap.Count -eq 0) { return $result }
    if ([string]::IsNullOrWhiteSpace($CveCell)) { return $result }
    $hits = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($mm in [regex]::Matches([string]$CveCell, '(?i)CVE-\d{4}-\d{4,}')) {
        $c = $mm.Value.ToUpper()
        if ($IavmMap.ContainsKey($c)) {
            $ia = [string]$IavmMap[$c].IAVA
            if (-not [string]::IsNullOrWhiteSpace($ia) -and $seen.Add($ia)) { [void]$hits.Add($ia) }
        }
    }
    if ($hits.Count -gt 0) { $result.IAVA = ($hits -join ', ') }
    return $result
}

# The ONLY writer of the IAVM map (used by iavm-add-map). Rewrites the whole file
# from the supplied CVE -> @{IAVA;Title} map (de-duped, CVE-sorted) via temp-file +
# atomic swap, exactly like JanetWeb.kev.psm1 Write-KevCatalog. UTF-8 no BOM, CVE,
# IAVA, Title CSV-quoted.
# ponytail: last-writer-wins on concurrent edits from two machines on the share -
# acceptable for a rarely-edited reference list, matching Write-KevCatalog.
function Write-ReportsIavmMap {
    param([System.Collections.IDictionary]$Map, [string]$Path)
    # loop14 (item 12): formula-injection guard (prefix ' when a cell begins = + - @ tab cr).
    # CVE is regex-validated (can't lead with a sigil) but Title/IAVA are free text.
    # audit 2026-07-23: the hand-rolled guard+quote scriptblock collapsed onto the
    # canonical ConvertTo-ReportsCsvCell (identical behavior, byte-for-byte output).
    $keys = @($Map.Keys | Sort-Object `
        @{ Expression = { [long]($_ -replace '^CVE-(\d+)-(\d+)$','$1') } }, `
        @{ Expression = { [long]($_ -replace '^CVE-(\d+)-(\d+)$','$2') } })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('CVE,IAVA,Title')
    foreach ($k in $keys) {
        $e = $Map[$k]
        [void]$sb.AppendLine((@((ConvertTo-ReportsCsvCell $k), (ConvertTo-ReportsCsvCell $e.IAVA), (ConvertTo-ReportsCsvCell $e.Title)) -join ','))
    }
    $content = $sb.ToString()
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = Join-Path $dir ("IavmMap.$PID.$([DateTime]::UtcNow.Ticks).tmp")
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tmp, $content, $enc)
    try {
        if (Test-Path -LiteralPath $Path) {
            try { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }
            catch { Move-Item -LiteralPath $tmp -Destination $Path -Force }   # DFS / odd-SMB fallback
        } else {
            Move-Item -LiteralPath $tmp -Destination $Path -Force
        }
    } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}

function New-AcasFinding {
    # loop40 P1: $IP is the per-row scan IP the parser reads (host-ip / IP Address column).
    # It is threaded here so the cross-domain collision guard can disambiguate two BARE
    # short names (e.g. two WEB01s on different IPs) that the FQDN-only signal is blind to.
    # It is a NEW discriminator field ONLY - $Hostname is unchanged (the fold still keys on
    # the name), so no closure verdict changes except a genuine >=2-distinct-IP collision.
    param([string]$Hostname,[string]$PluginID,[string]$VulnName,[string]$Severity,[string]$CVE,[string]$Category,[string]$Solution,$KevSet,$IavmMap,[string]$IP='')
    $status = if ($Category -eq 'NOT OUR PATCH') { 'NOT OUR PATCH' } else { 'Open' }
    $kev = Get-ReportsKevOverlap -CveCell $CVE -KevSet $KevSet
    $iavm = Get-ReportsIavmForCves -CveCell $CVE -IavmMap $IavmMap
    return [PSCustomObject]@{
        Hostname    = $Hostname
        IP          = $IP
        PluginID    = $PluginID
        VulnName    = $VulnName
        Severity    = $Severity
        CVE         = $CVE
        Category    = $Category
        Status      = $status
        Solution    = $Solution
        InKEV       = $kev.InKev
        KevCves     = $kev.KevCves
        IAVA        = $iavm.IAVA
        FirstSeen   = ''
        PatchedDate = ''
        PatchedBy   = ''
    }
}

# =============================================================================
#  Remediation SLA / finding-age baseline  -  editable JanetLocal\sla-baseline.json
#  giving the days-to-remediate window per severity (KEV overrides). Same safe-
#  default loader pattern as JanetWeb.c2c.psm1 Get-C2cBaseline: a missing / empty /
#  corrupt file silently falls back to the embedded defaults so an SLA run never
#  breaks. Read-only - the module never writes this file.
# -----------------------------------------------------------------------------
function Get-ReportsSlaDefaults {
    @{ kev = 7; critical = 21; high = 30; medium = 90; low = 180; note = 'days to remediate by severity; kev overrides' }
}

function Get-ReportsSlaBaselinePath { Join-Path $PSScriptRoot '..\JanetLocal\sla-baseline.json' }

# audit 2026-07-23 deferred pass (E2): SLA read memo for ONE posture-digest run.
# posture-digest re-invokes sla-aging (and siblings) as recursive Invoke-JanetToolAction
# calls, and every Get-ReportsSlaBaseline / Get-ReportsSlaLedger call is a fresh disk
# read+parse. The files cannot meaningfully change mid-snapshot, so posture-digest
# opens this script-scope memo (a hashtable) around its sub-action calls and clears it
# in a finally - it can NEVER leak into normal operation, where $null here means every
# call still reads fresh from disk. Consumers inside a digest run are read-only
# (nothing writes the baseline or ledger), so serving the same parsed object back is
# byte-identical to re-reading it.
$script:SlaDigestMemo = $null

# Read the editable JanetLocal SLA baseline fresh; returns @{ Config=@{...}; Source='...' }.
# Only positive integer overrides are adopted (a zero/negative/non-numeric window is
# ignored in favor of the default so a typo cannot make everything instantly overdue).
# Get-ReportsSlaBaseline is the memo-aware front door; the disk read body is unchanged.
function Get-ReportsSlaBaseline {
    if ($null -ne $script:SlaDigestMemo) {
        if (-not $script:SlaDigestMemo.ContainsKey('Baseline')) { $script:SlaDigestMemo['Baseline'] = Read-ReportsSlaBaselineFromDisk }
        return $script:SlaDigestMemo['Baseline']
    }
    Read-ReportsSlaBaselineFromDisk
}

function Read-ReportsSlaBaselineFromDisk {
    $cfg = Get-ReportsSlaDefaults
    try {
        $p = Get-ReportsSlaBaselinePath
        if (-not (Test-Path -LiteralPath $p)) { return @{ Config = $cfg; Source = 'embedded defaults (no JanetLocal\sla-baseline.json)' } }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($null -eq $raw) { $raw = '' }
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Config = $cfg; Source = 'embedded defaults (baseline file empty)' } }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj) { return @{ Config = $cfg; Source = 'embedded defaults (baseline parsed empty)' } }
        $has = { param($n) $null -ne $obj.PSObject.Properties[$n] }
        foreach ($k in @('kev','critical','high','medium','low')) {
            if ((& $has $k) -and $null -ne $obj.$k) {
                $n = 0
                if ([int]::TryParse([string]$obj.$k, [ref]$n) -and $n -gt 0) { $cfg[$k] = $n }
            }
        }
        if ((& $has 'note') -and -not [string]::IsNullOrWhiteSpace([string]$obj.note)) { $cfg.note = [string]$obj.note }
        return @{ Config = $cfg; Source = 'JanetLocal\sla-baseline.json (overlaid on defaults)' }
    } catch { return @{ Config = $cfg; Source = "embedded defaults (sla baseline read error: $($_.Exception.Message))" } }
}

# Days-to-remediate for a finding. KEV (known-exploited) overrides severity with the
# tightest window; otherwise map by ACAS severity (Info falls back to the Low window).
function Get-ReportsSlaDeadline {
    param($Config, [string]$Severity, [bool]$InKev)
    if ($InKev) { return [int]$Config.kev }
    switch ($Severity) {
        'Critical' { return [int]$Config.critical }
        'High'     { return [int]$Config.high }
        'Medium'   { return [int]$Config.medium }
        'Low'      { return [int]$Config.low }
        'Info'     { return [int]$Config.low }
        default    { return [int]$Config.medium }
    }
}

# loop21: SINGLE SOURCE OF TRUTH for the SLA aging boundary rule. Two operator-facing
# views compute these buckets - the SLA / Finding Aging dashboard (sla-aging) and the
# Executive Command Brief SLA section - and they MUST agree, or the same fleet reports
# two different overdue counts. Both used to hand-duplicate this arithmetic; now both
# call here. Given the remediation window (deadline, days) and the finding's age (days):
#   OVERDUE   - past the deadline (dueIn < 0)
#   DUE-SOON  - within the tighter of 25% of the window or 3 days left (dueIn <= soon)
#   ON-TRACK  - otherwise
# The deadline day itself (dueIn == 0) is DUE-SOON, not OVERDUE. A zero/absent deadline
# floors the window to 1 so the 25% math never divides into nonsense.
function Get-ReportsSlaBucket {
    param([int]$Deadline, [int]$Age)
    $dueIn  = $Deadline - $Age
    $window = if ($Deadline -gt 0) { $Deadline } else { 1 }
    $soon   = [Math]::Max(3, [int][Math]::Ceiling($window * 0.25))
    $bucket = if ($dueIn -lt 0) { 'OVERDUE' } elseif ($dueIn -le $soon) { 'DUE-SOON' } else { 'ON-TRACK' }
    return @{ DueIn = $dueIn; Bucket = $bucket; SoonThreshold = $soon; Window = $window }
}

# =============================================================================
#  SLA firstSeen ledger  -  JanetLocal\sla-ledger.json (RUNTIME STATE, gitignored)
#  Persists the SLA finding-age clock OUTSIDE the working report so it survives a
#  fresh scan import: the previous fix stamped firstSeen only inside a saved report
#  JSON, so re-parsing a raw ACAS export (the common weekly workflow) reset every
#  clock to today (audit P1). The ledger maps "Hostname|PluginID" ->
#  { firstSeen; severity; kev; lastSeen } and is the AUTHORITATIVE source for
#  backfilling firstSeen on freshly parsed findings. Loader tolerates a missing /
#  empty / corrupt file (empty map + warn) exactly like Get-ReportsSlaBaseline.
# -----------------------------------------------------------------------------
function Get-ReportsSlaLedgerPath { Join-Path $PSScriptRoot '..\JanetLocal\sla-ledger.json' }

# Read the ledger fresh. Returns @{ Map=@{ key -> @{firstSeen;severity;kev;lastSeen} }; Source='...'; Ok=$bool }.
# A read/parse error yields an empty map with Ok=$false so the caller can warn (never throws).
# Get-ReportsSlaLedger is the memo-aware front door (see $script:SlaDigestMemo above);
# the disk read body is unchanged. Update-ReportsSlaLedger (the only writer) never runs
# inside a digest, so a memoized map can never be served stale.
function Get-ReportsSlaLedger {
    if ($null -ne $script:SlaDigestMemo) {
        if (-not $script:SlaDigestMemo.ContainsKey('Ledger')) { $script:SlaDigestMemo['Ledger'] = Read-ReportsSlaLedgerFromDisk }
        return $script:SlaDigestMemo['Ledger']
    }
    Read-ReportsSlaLedgerFromDisk
}

function Read-ReportsSlaLedgerFromDisk {
    $map = @{}
    try {
        $p = Get-ReportsSlaLedgerPath
        if (-not (Test-Path -LiteralPath $p)) { return @{ Map = $map; Source = 'none (no JanetLocal\sla-ledger.json yet)'; Ok = $true } }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($null -eq $raw) { $raw = '' }
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Map = $map; Source = 'empty (ledger file blank)'; Ok = $true } }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj) { return @{ Map = $map; Source = 'empty (ledger parsed empty)'; Ok = $true } }
        foreach ($prop in $obj.PSObject.Properties) {
            $v = $prop.Value
            if ($null -eq $v) { continue }
            $fs  = if ($v.PSObject.Properties['firstSeen']) { [string]$v.firstSeen } else { '' }
            $ls  = if ($v.PSObject.Properties['lastSeen'])  { [string]$v.lastSeen }  else { '' }
            $sev = if ($v.PSObject.Properties['severity'])  { [string]$v.severity }  else { '' }
            $kev = $false; if ($v.PSObject.Properties['kev']) { $kev = [bool]$v.kev }
            $map[[string]$prop.Name] = @{ firstSeen = $fs; severity = $sev; kev = $kev; lastSeen = $ls }
        }
        return @{ Map = $map; Source = 'JanetLocal\sla-ledger.json'; Ok = $true }
    } catch { return @{ Map = $map; Source = "empty (ledger read error: $($_.Exception.Message))"; Ok = $false } }
}

# Persist the ledger map atomically (temp + move) as a UTF-8-with-BOM JSON object,
# keys sorted for a stable, diff-friendly file. Returns @{ Written=$bool; Path; Error }.
# Never throws - a write failure is reported, not fatal (the in-report-JSON firstSeen
# is the belt-and-suspenders fallback copy).
function Save-ReportsSlaLedger {
    param([hashtable]$Map)
    $res = @{ Written = $false; Path = ''; Error = '' }
    $tmp = $null
    try {
        $p = Get-ReportsSlaLedgerPath
        $dir = Split-Path -Parent $p
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        $ordered = [ordered]@{}
        foreach ($k in ($Map.Keys | Sort-Object)) {
            $v = $Map[$k]
            $ordered[[string]$k] = [ordered]@{ firstSeen = [string]$v.firstSeen; severity = [string]$v.severity; kev = [bool]$v.kev; lastSeen = [string]$v.lastSeen }
        }
        $json = if ($ordered.Count -eq 0) { '{}' } else { $ordered | ConvertTo-Json -Depth 5 }
        $tmp = "$p.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($true))
        Move-Item -LiteralPath $tmp -Destination $p -Force -ErrorAction Stop
        $res.Written = $true; $res.Path = $p
    } catch {
        $res.Error = $_.Exception.Message
        if ($tmp) { try { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } } catch {} }
    }
    return $res
}

# =============================================================================
#  Remediation campaigns  -  JanetLocal\campaigns\<id>.json
#  A persisted closed-loop object: a snapshot of a set of OPEN findings + their
#  affected host set + the mapped JANET remediations, so a wave can be tracked
#  finding -> fix -> (later) re-verify. Read-only creation from the loaded
#  findings; the actual remediation still runs through the gated engines.
# =============================================================================
function Get-ReportsCampaignDir { Join-Path $PSScriptRoot '..\JanetLocal\campaigns' }

# Extract distinct KB ids (KB######[#]) from Tenable free-text (VulnName + Solution).
# Same lenient token shape patchlib uses, so a KB pulled here matches staged content
# there. Returns a de-duped uppercase string array.
function Get-ReportsKbsFromText {
    param([string]$Text)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($m in [regex]::Matches([string]$Text, '(?i)(?<![A-Za-z0-9])KB\d{6,7}(?!\d)')) {
        $kb = $m.Value.ToUpper()
        if ($seen.Add($kb)) { [void]$out.Add($kb) }
    }
    # Return the elements (enumerated); the caller wraps with @() to get a flat array.
    return $out.ToArray()
}

# Read one campaign by id (PSCustomObject) or $null if absent/unreadable.
function Get-ReportsCampaignById {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    try {
        $p = Join-Path (Get-ReportsCampaignDir) ("$Id.json")
        if (-not (Test-Path -LiteralPath $p)) { return $null }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($raw -and $raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch { return $null }
}

# Persist one campaign object (hashtable OR PSCustomObject; atomic temp+move, UTF-8
# BOM). Uses $Campaign.id for the filename. Returns @{Written;Path;Error}.
function Save-ReportsCampaign {
    param($Campaign)
    $res = @{ Written = $false; Path = ''; Error = '' }
    $tmp = $null
    try {
        $dir = Get-ReportsCampaignDir
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        $p = Join-Path $dir ("$($Campaign.id).json")
        $json = $Campaign | ConvertTo-Json -Depth 6
        $tmp = "$p.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($true))
        Move-Item -LiteralPath $tmp -Destination $p -Force -ErrorAction Stop
        $res.Written = $true; $res.Path = $p
    } catch {
        $res.Error = $_.Exception.Message
        if ($tmp) { try { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } } catch {} }
    }
    return $res
}

# Read every saved campaign (newest first). Returns @{ Campaigns=@(...); Source; Ok }.
function Get-ReportsCampaigns {
    $out = New-Object System.Collections.ArrayList
    try {
        $dir = Get-ReportsCampaignDir
        if (-not (Test-Path -LiteralPath $dir)) { return @{ Campaigns = @(); Source = 'none (no JanetLocal\campaigns yet)'; Ok = $true } }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction Stop)) {
            try {
                $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                if ($raw -and $raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                if (-not [string]::IsNullOrWhiteSpace($raw)) { [void]$out.Add(($raw | ConvertFrom-Json -ErrorAction Stop)) }
            } catch {}
        }
        $sorted = @($out | Sort-Object -Property @{ Expression = { [string]$_.createdUtc }; Descending = $true })
        return @{ Campaigns = $sorted; Source = $dir; Ok = $true }
    } catch { return @{ Campaigns = @(); Source = "read error: $($_.Exception.Message)"; Ok = $false } }
}

# =============================================================================
#  Burndown trend  -  JanetLocal\trend\burndown.jsonl
#  A persisted vuln-backlog time series: one compact JSON object per line,
#  appended by 'burndown-snapshot' and read back by 'burndown' to show the
#  trajectory ("are we winning?"). Deliberately JSONL (append-only), unlike
#  the one-file-per-record campaign store above, because a time series is
#  naturally append-only and never needs a per-record rewrite. Read-only
#  against hosts; only ever appends to this one local file.
# =============================================================================

# $script:ReportsTrendDir is a testability seam ONLY (no SPA/manifest field
# sets it): Pester points it at a temp folder so tests never touch the real
# JanetLocal\trend store. Unset/blank (the normal path) -> the real default.
$script:ReportsTrendDir = $null
function Get-ReportsTrendDir {
    if (-not [string]::IsNullOrWhiteSpace($script:ReportsTrendDir)) { return $script:ReportsTrendDir }
    return (Join-Path $PSScriptRoot '..\JanetLocal\trend')
}
function Get-ReportsTrendPath { Join-Path (Get-ReportsTrendDir) 'burndown.jsonl' }

# Append one compact JSON record as a new line (dir/file created if missing).
# Plain UTF-8 (no BOM) so a BOM never lands mid-file on a line other than the
# first - Get-ReportsTrendRecords strips a leading BOM defensively anyway.
function Add-ReportsTrendRecord {
    param($Record)
    $res = @{ Written = $false; Error = '' }
    try {
        $dir = Get-ReportsTrendDir
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        $path = Get-ReportsTrendPath
        $line = ($Record | ConvertTo-Json -Depth 4 -Compress)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $sw = New-Object System.IO.StreamWriter($path, $true, $utf8NoBom)
        try { $sw.WriteLine($line) } finally { $sw.Dispose() }
        $res.Written = $true
    } catch { $res.Error = $_.Exception.Message }
    return $res
}

# Read every trend record ascending by tsUtc. Tolerates a missing/empty store
# and skips any corrupt line rather than throwing. Returns a flat array.
#
# Two snapshots taken seconds apart can share the same tsUtc string (the
# format is whole-seconds); Sort-Object is not guaranteed stable across ties,
# so an explicit file-order index is carried as the tie-breaker to keep
# same-second records in append (chronological) order instead of risking a
# sort-stability flip.
function Get-ReportsTrendRecords {
    $out = New-Object System.Collections.ArrayList
    try {
        $path = Get-ReportsTrendPath
        if (Test-Path -LiteralPath $path) {
            $i = 0
            foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction Stop)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $clean = $line
                if ($clean.Length -gt 0 -and [int]$clean[0] -eq 0xFEFF) { $clean = $clean.Substring(1) }
                try {
                    $rec = $clean | ConvertFrom-Json -ErrorAction Stop
                    Add-Member -InputObject $rec -NotePropertyName '_seq' -NotePropertyValue $i -Force
                    [void]$out.Add($rec)
                    $i++
                } catch {}
            }
        }
    } catch {}
    $sorted = @($out | Sort-Object -Property @{ Expression = { [string]$_.tsUtc } }, @{ Expression = { $_._seq } })
    foreach ($r in $sorted) { $r.PSObject.Properties.Remove('_seq') }
    return $sorted
}

# Upsert the ledger from the current in-session findings and persist it. For every
# finding key (Hostname|PluginID): absent -> add with firstSeen=today (a NEW clock
# starts); present -> refresh lastSeen + severity + kev but PRESERVE firstSeen (clock
# carried). A finding that carries its own FirstSeen (from a loaded report) but is not
# yet in the ledger seeds the ledger with that date (carried, not restarted). The
# authoritative firstSeen is stamped back onto the live finding so a same-session
# sla-aging sees the key as tracked without a reload. Returns
# @{ Carried; Started; Total; Written; Path; Error }.
function Update-ReportsSlaLedger {
    param([System.Collections.IEnumerable]$Findings)
    $todayIso = (Get-Date).ToString('yyyy-MM-dd')
    $led = Get-ReportsSlaLedger
    $map = $led.Map
    $carried = 0; $started = 0; $seen = 0
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $seen++
        # Normalize the host portion (FQDN/NetBIOS/case all fold to one stable key)
        # so the same physical host does not reset its firstSeen clock when a later
        # scan exports it in a different name format. Reads below use the same key.
        $key = "$(Get-ReportsAuditHostKey $f.Hostname)|$($f.PluginID)"
        $sev = [string]$f.Severity
        $kev = [bool]$f.InKEV
        $ownFs = if ($f.PSObject.Properties['FirstSeen']) { [string]$f.FirstSeen } else { '' }
        if ($map.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$map[$key].firstSeen)) {
            $fs = [string]$map[$key].firstSeen; $carried++          # ledger already tracks it - preserve
        } elseif (-not [string]::IsNullOrWhiteSpace($ownFs)) {
            $fs = $ownFs; $carried++                                 # seed ledger from the finding's own clock
        } else {
            $fs = $todayIso; $started++                              # brand-new key - start the clock today
        }
        $map[$key] = @{ firstSeen = $fs; severity = $sev; kev = $kev; lastSeen = $todayIso }
        if ($f.PSObject.Properties['FirstSeen']) { $f.FirstSeen = $fs }
        else { $f | Add-Member -NotePropertyName FirstSeen -NotePropertyValue $fs -Force }
    }
    # Prune keys not seen in a long time (audit#6): bounds the file AND lets a finding
    # that was genuinely remediated (dropped out of scan) start a fresh clock if it
    # re-appears later, instead of inheriting its old firstSeen and reading OVERDUE.
    # Retention = longest realistic SLA window + margin. Anything whose lastSeen is
    # older than this is considered closed-and-forgotten.
    # ponytail: fixed 365-day retention; make it a config value if SLA windows change.
    $pruned = 0
    $cutoff = (Get-Date).Date.AddDays(-365)
    foreach ($k in @($map.Keys)) {
        $ls = [string]$map[$k].lastSeen
        [datetime]$lsDate = [datetime]::MinValue
        if ([DateTime]::TryParse($ls, [ref]$lsDate)) {
            if ($lsDate.Date -lt $cutoff) { [void]$map.Remove($k); $pruned++ }
        }
    }
    $save = Save-ReportsSlaLedger -Map $map
    return @{ Carried = $carried; Started = $started; Total = $seen; Pruned = $pruned; Written = $save.Written; Path = $save.Path; Error = $save.Error }
}

function Read-CsvRowsSafe {
    # Quote-aware CSV/TSV reader. Returns @{ Header=@(lowercased); Rows=@(@(fields)) }.
    param([string]$FilePath)
    $result = @{ Header = @(); Rows = @() }
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch {
        return $result
    }
    $delimiter = ","
    $sr = $null
    try {
        $sr = New-Object System.IO.StreamReader($FilePath)
        $firstLine = $sr.ReadLine()
        while ($null -ne $firstLine -and [string]::IsNullOrWhiteSpace($firstLine)) { $firstLine = $sr.ReadLine() }
        if ($firstLine) {
            $tabCount   = ([regex]::Matches($firstLine, "`t")).Count
            $commaCount = ([regex]::Matches($firstLine, ',')).Count
            if ($tabCount -gt $commaCount) { $delimiter = "`t" }
        }
    } catch {
        return $result
    } finally {
        if ($sr) { $sr.Dispose() }
    }
    $parser = $null
    try {
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($FilePath)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(@($delimiter))
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        if (-not $parser.EndOfData) {
            $hdr = $parser.ReadFields()
            if ($hdr) { $result.Header = @($hdr | ForEach-Object { ($_ -as [string]).Trim().Trim('"').ToLower() }) }
        }
        $rowList = New-Object System.Collections.ArrayList
        while (-not $parser.EndOfData) {
            try {
                $fields = $parser.ReadFields()
                if ($fields -and $fields.Count -gt 0) { [void]$rowList.Add(@($fields | ForEach-Object { ($_ -as [string]) })) }
            } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
                continue
            }
        }
        $result.Rows = $rowList.ToArray()
    } catch {
    } finally {
        if ($parser) { $parser.Close(); $parser.Dispose() }
    }
    return $result
}

function Find-AcasColumn {
    param([string[]]$Header, [string[]]$Patterns)
    foreach ($p in $Patterns) {
        for ($i = 0; $i -lt $Header.Count; $i++) {
            if ($Header[$i] -match $p) { return $i }
        }
    }
    return -1
}

function Get-AcasColumnMap {
    param([string[]]$Header)
    # Separators in multi-word headers are matched with [\s._] so a space-, dot-,
    # or underscore-delimited export ('DNS Name' / 'dns.name' / 'dns_name') all map.
    $iHost = Find-AcasColumn -Header $Header -Patterns @('^dns[\s._]name$','^dns$')
    if ($iHost -lt 0) { $iHost = Find-AcasColumn -Header $Header -Patterns @('^host$','^hostname$','^host[\s._]name$','netbios','asset') }
    if ($iHost -lt 0) { $iHost = Find-AcasColumn -Header $Header -Patterns @('^ip[\s._]address$','^ip$','^ipv4$') }
    $iPlugin = Find-AcasColumn -Header $Header -Patterns @('^plugin$','^plugin[\s._]id$','^pluginid$','nessus[\s._]id')
    $iVuln   = Find-AcasColumn -Header $Header -Patterns @('plugin[\s._]name','^name$','^vuln','vulnerability','^title$','synopsis')
    $iSev    = Find-AcasColumn -Header $Header -Patterns @('^severity$','^risk[\s._]factor$','^risk$','^threat$','^sev$')
    $iSol    = Find-AcasColumn -Header $Header -Patterns @('steps[\s._]to[\s._]remediate','^solution$','^fix$','remediation','^patch$')
    $iCVE    = Find-AcasColumn -Header $Header -Patterns @('^cve$','^cve[\s._]id$')
    # Also record IP and NetBIOS columns so Parse-AcasFile can fall back per-row
    # when the primary host cell (usually DNS Name) is blank - common on AFNET
    # Nessus CSVs where DNS Name is empty but IP / NetBIOS Name are populated.
    $iNetbios = Find-AcasColumn -Header $Header -Patterns @('^netbios[\s._]name$','^netbios$','netbios')
    $iIp      = Find-AcasColumn -Header $Header -Patterns @('^ip[\s._]address$','^ip$','^ipv4$')
    return @{ Host = $iHost; Plugin = $iPlugin; Vuln = $iVuln; Sev = $iSev; Sol = $iSol; CVE = $iCVE; Netbios = $iNetbios; Ip = $iIp }
}

function Get-NessusCveList {
    param($ReportItem)
    $cveList = @()
    try {
        $nodes = $ReportItem.SelectNodes("cve")
        if ($nodes) {
            foreach ($cn in $nodes) {
                $v = $cn.InnerText.Trim()
                if ($v -and ($cveList -notcontains $v)) { $cveList += $v }
            }
        }
    } catch {}
    return ($cveList -join ', ')
}

function Read-XmlFileSafe {
    # Hardened XML load (DTD prohibited, no external resolver) to block XXE.
    param([string]$FilePath)
    $fs = $null; $reader = $null
    try {
        $fs = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver   = $null
        $settings.MaxCharactersFromEntities = 0
        $reader = [System.Xml.XmlReader]::Create($fs, $settings)
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
        return $doc
    } catch {
        return $null
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($fs)     { $fs.Dispose() }
    }
}

function Parse-AcasFile {
    # Unified parser returning fully-populated findings. Handles .nessus XML
    # and CSV/TSV with quoted multi-line fields via TextFieldParser.
    # Loads the KEV catalog ONCE up front and flags every finding whose CVE cell
    # overlaps it (InKEV/KevCves). A missing/empty catalog is not fatal: findings
    # parse with InKEV=$false and (if -Emit was supplied) one warning line is sent.
    param([string]$FilePath, [scriptblock]$Emit)
    $findings = New-Object System.Collections.ArrayList
    $kev = Read-ReportsKevCatalog
    if ($kev.Count -eq 0 -and $Emit) {
        & $Emit @{ type='log'; level='warn'; text="KEV catalog is empty/unreadable ($($kev.Source)) - findings will not be KEV-flagged. Restore JanetLocal\KevCatalog.txt (or add CVEs on the KEV tool) to enable auto-flag." }
    }
    # IAVM map (same ship-inside-JANET flat file pattern): tag each finding's CVE
    # with its IAVA id. A missing / empty map is not fatal - findings parse with IAVA=''.
    $iavm = Read-ReportsIavmMap
    if ($iavm.Count -eq 0 -and $Emit) {
        & $Emit @{ type='log'; level='warn'; text="IAVM map is empty/unreadable ($($iavm.Source)) - findings will not be IAVA-tagged. Restore JanetLocal\IavmMap.csv (or use Add IAVM Mapping) to enable it." }
    }

    if ($FilePath -match '\.nessus$') {
        $nessusXml = Read-XmlFileSafe -FilePath $FilePath
        if (-not $nessusXml) { return $findings }
        $reports = $nessusXml.SelectNodes("//Report")
        if (-not $reports -or $reports.Count -eq 0) { $reports = $nessusXml.SelectNodes("//NessusClientData_v2/Report") }
        if (-not $reports) { return $findings }
        foreach ($report in $reports) {
            $reportHosts = $report.SelectNodes("ReportHost"); if (-not $reportHosts) { continue }
            foreach ($rh in $reportHosts) {
                $hostname = $rh.GetAttribute("name")
                # loop40 P1: keep the host-ip even when a name string exists (it used to be
                # read only as a hostname fallback and then discarded). It is threaded onto
                # the finding as the IP discriminator for the collision guard.
                $hostIp = ''
                $hostProps = $rh.SelectNodes("HostProperties/tag")
                if ($hostProps) {
                    $hostFqdn = $null
                    foreach ($tag in $hostProps) {
                        $tn = $tag.GetAttribute("name")
                        if ($tn -eq "host-fqdn" -and $tag.InnerText.Trim()) { $hostFqdn = $tag.InnerText.Trim() }
                        elseif ($tn -eq "host-ip" -and $tag.InnerText.Trim()) { $hostIp = $tag.InnerText.Trim() }
                    }
                    if ($hostFqdn) { $hostname = $hostFqdn }
                    elseif ([string]::IsNullOrWhiteSpace($hostname) -and $hostIp) { $hostname = $hostIp }
                }
                if ([string]::IsNullOrWhiteSpace($hostname)) { continue }
                $items = $rh.SelectNodes("ReportItem"); if (-not $items) { continue }
                foreach ($item in $items) {
                    $pluginID = $item.GetAttribute("pluginID")
                    if ([string]::IsNullOrWhiteSpace($pluginID) -or $pluginID -eq "0") { continue }
                    $vulnName = $item.GetAttribute("pluginName")
                    if ([string]::IsNullOrWhiteSpace($vulnName)) {
                        $vn = $item.SelectSingleNode("plugin_name")
                        $vulnName = if ($vn) { $vn.InnerText.Trim() } else { "Unknown" }
                    }
                    $severity = "Medium"
                    $riskNode = $item.SelectSingleNode("risk_factor")
                    if ($riskNode -and $riskNode.InnerText.Trim()) { $severity = Parse-Severity $riskNode.InnerText.Trim() }
                    else { $sa = $item.GetAttribute("severity"); if ($sa) { $severity = Parse-Severity $sa } }
                    $solution = ""
                    $solNode = $item.SelectSingleNode("solution")
                    if ($solNode) { $solution = $solNode.InnerText.Trim() }
                    $cveVal = Get-NessusCveList -ReportItem $item
                    $category = Categorize-Finding -VulnName $vulnName -Solution $solution -PluginID $pluginID
                    [void]$findings.Add((New-AcasFinding -Hostname $hostname -PluginID $pluginID -VulnName $vulnName -Severity $severity -CVE $cveVal -Category $category -Solution $solution -KevSet $kev.Set -IavmMap $iavm.Map -IP $hostIp))
                }
            }
        }
        return $findings
    }

    # CSV/TSV path
    $data = Read-CsvRowsSafe -FilePath $FilePath
    if (-not $data.Header -or $data.Header.Count -eq 0) { return $findings }
    $cols = Get-AcasColumnMap -Header $data.Header
    if ($cols.Host -lt 0 -or $cols.Plugin -lt 0) {
        # loop19: the header parsed but the host and/or plugin column could not be
        # resolved - almost always a wrong export template (renamed/missing columns),
        # NOT an empty scan. Surface it LOUDLY instead of silently importing zero
        # findings (which reads to the operator as a clean fleet). Parity with the
        # acas ConvertFrom-AcasCsv wrong-template hint.
        if ($Emit) {
            $miss = @()
            if ($cols.Host   -lt 0) { $miss += 'a host column (DNS Name / Host / NetBIOS / IP Address)' }
            if ($cols.Plugin -lt 0) { $miss += 'a plugin column (Plugin / Plugin ID / Nessus ID)' }
            & $Emit @{ type='log'; level='warn'; text=("Parsed the CSV header but could not find " + ($miss -join ' and ') + " - no findings imported. Check the export matches the expected ACAS/Nessus CSV columns.") }
        }
        return $findings
    }
    foreach ($fields in $data.Rows) {
        if (-not $fields -or $fields.Count -le $cols.Plugin) { continue }
        $pluginID = ($fields[$cols.Plugin] -as [string]).Trim()
        if ([string]::IsNullOrWhiteSpace($pluginID)) { continue }
        $hostname = if ($fields.Count -gt $cols.Host) { ($fields[$cols.Host] -as [string]).Trim() } else { '' }
        # loop40 P1: read the IP column value up front and KEEP it as the finding's IP
        # discriminator, regardless of whether it also has to stand in as the hostname.
        # (Previously the IP was consulted only as a name fallback and then discarded.)
        $rowIp = if ($cols.Ip -ge 0 -and $fields.Count -gt $cols.Ip) { ($fields[$cols.Ip] -as [string]).Trim() } else { '' }
        # AFNET Nessus CSVs often leave DNS Name blank; fall back per-row to
        # NetBIOS then IP before discarding, so the row is only dropped when all
        # host identifiers are blank.
        if ([string]::IsNullOrWhiteSpace($hostname) -and $cols.Netbios -ge 0 -and $fields.Count -gt $cols.Netbios) {
            $hostname = ($fields[$cols.Netbios] -as [string]).Trim()
        }
        if ([string]::IsNullOrWhiteSpace($hostname) -and $rowIp) {
            $hostname = $rowIp
        }
        if ([string]::IsNullOrWhiteSpace($hostname)) { continue }
        $vulnName = if ($cols.Vuln -ge 0 -and $fields.Count -gt $cols.Vuln) { ($fields[$cols.Vuln] -as [string]).Trim() } else { "Unknown" }
        $severity = if ($cols.Sev  -ge 0 -and $fields.Count -gt $cols.Sev)  { Parse-Severity ($fields[$cols.Sev] -as [string]) } else { "Medium" }
        $solution = if ($cols.Sol  -ge 0 -and $fields.Count -gt $cols.Sol)  { ($fields[$cols.Sol] -as [string]).Trim() } else { "" }
        $cveVal   = if ($cols.CVE  -ge 0 -and $fields.Count -gt $cols.CVE)  { ($fields[$cols.CVE] -as [string]).Trim() } else { "" }
        $category = Categorize-Finding -VulnName $vulnName -Solution $solution -PluginID $pluginID
        [void]$findings.Add((New-AcasFinding -Hostname $hostname -PluginID $pluginID -VulnName $vulnName -Severity $severity -CVE $cveVal -Category $category -Solution $solution -KevSet $kev.Set -IavmMap $iavm.Map -IP $rowIp))
    }
    return $findings
}

function Compare-AcasScans {
    # Hostname|PluginID set delta between the baseline store (BEFORE) and the
    # comparison store (AFTER). Ported from ReportsTool_2.14.5.ps1:6298-6334
    # (btnRunCompare): REMEDIATED = baseline-only, STILL OPEN = in both,
    # NEW = comparison-only. Comparison side = $script:ComparisonFindings (a
    # separate AFTER-patching scan, NOT the import set). The host portion of every
    # key is run through Get-ReportsAuditHostKey (IPv4-whole, else pre-dot short name
    # upper-cased) so a host exported as HOST1 in one file and host1.dom in another
    # collapses to ONE key and cannot produce a phantom REMEDIATED+NEW pair.
    # OrdinalIgnoreCase alone only folds case (HOST1 vs host1) - it would NOT fold
    # HOST1 vs host1.dom - so normalization, not the comparer, is what pairs them.
    $results = New-Object System.Collections.ArrayList
    $cmp = [System.StringComparer]::OrdinalIgnoreCase

    # audit 2026-07-23: the hostname/IP gathering for the collision guard below is
    # folded into these two existing key-building passes (was two extra full passes
    # over both finding sets).
    $allHostnames = New-Object System.Collections.ArrayList
    $allIps       = New-Object System.Collections.ArrayList
    $baselineKeys   = New-Object 'System.Collections.Generic.HashSet[string]' $cmp
    $baselineLookup = New-Object 'System.Collections.Generic.Dictionary[string,object]' $cmp
    foreach ($f in $script:BaselineFindings) {
        $key = "$(Get-ReportsAuditHostKey $f.Hostname)|$($f.PluginID)"
        [void]$baselineKeys.Add($key)
        $baselineLookup[$key] = $f
        [void]$allHostnames.Add([string]$f.Hostname); [void]$allIps.Add([string]$f.IP)
    }
    $comparisonKeys   = New-Object 'System.Collections.Generic.HashSet[string]' $cmp
    $comparisonLookup = New-Object 'System.Collections.Generic.Dictionary[string,object]' $cmp
    foreach ($f in $script:ComparisonFindings) {
        $key = "$(Get-ReportsAuditHostKey $f.Hostname)|$($f.PluginID)"
        [void]$comparisonKeys.Add($key)
        $comparisonLookup[$key] = $f
        [void]$allHostnames.Add([string]$f.Hostname); [void]$allIps.Add([string]$f.IP)
    }

    # loop39 (ledger row 36): cross-domain short-name COLLISIONS across BOTH scans. The
    # fold above collapses any non-IP name to its short NetBIOS label, so two DISTINCT
    # FQDNs (web01.us.af.mil + web01.eu.af.mil) both become WEB01. A baseline-only key on
    # such a short name LOOKS remediated, but the comparison's WEB01 may be a DIFFERENT
    # physical box (the other domain), so we cannot confirm the baseline host was actually
    # patched. Those keys are classified AMBIGUOUS (a new bucket alongside REMEDIATED /
    # STILL OPEN / NEW), never a silent false-close. Reuses the PROVEN loop24 helper
    # Get-ReportsHostKeyCollisions (the same one campaign-verify uses); the fold itself is
    # UNCHANGED - only a genuine collision demotes a would-be REMEDIATED.
    # loop40 P1: the scan IP is now threaded through New-AcasFinding / Parse-AcasFile and
    # passed here (-IPs), so a collision is flagged on >=2 distinct FQDNs OR >=2 distinct IPs.
    # That closes the short-name-only residual: two BARE WEB01s on different IPs are now caught
    # (the FQDN-only signal was blind to them). RESIDUAL: a truly IP-LESS short-name-only export
    # (no IP column at all) remains genuinely undisambiguable and stays unflagged - re-scan by
    # FQDN or restore the IP to resolve it.
    # loop40 P1: thread the per-finding scan IP (parallel to the hostname) so the collision
    # guard also fires on two BARE short names on DIFFERENT IPs (the AFNET short-name-only norm
    # the FQDN-only signal missed). IP defaults to '' on legacy findings that carry no IP field.
    $collisions = Get-ReportsHostKeyCollisions -Hostnames @($allHostnames.ToArray()) -IPs @($allIps.ToArray())

    # REMEDIATED: in baseline but NOT in comparison (patched/fixed) - UNLESS the short host
    # key is a cross-domain collision, in which case the closure is AMBIGUOUS (see above).
    foreach ($key in $baselineKeys) {
        if (-not $comparisonKeys.Contains($key)) {
            $f = $baselineLookup[$key]
            $hk = Get-ReportsAuditHostKey $f.Hostname
            $delta = if ($collisions.Contains($hk)) { 'AMBIGUOUS' } else { 'REMEDIATED' }
            [void]$results.Add([PSCustomObject]@{ Hostname=$f.Hostname; IP=$f.IP; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta=$delta; Solution=$f.Solution })
        }
    }
    # STILL OPEN: in BOTH baseline AND comparison (not fixed)
    foreach ($key in $baselineKeys) {
        if ($comparisonKeys.Contains($key)) {
            $f = $comparisonLookup[$key]
            [void]$results.Add([PSCustomObject]@{ Hostname=$f.Hostname; IP=$f.IP; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta='STILL OPEN'; Solution=$f.Solution })
        }
    }
    # NEW: in comparison but NOT in baseline (new findings)
    foreach ($key in $comparisonKeys) {
        if (-not $baselineKeys.Contains($key)) {
            $f = $comparisonLookup[$key]
            [void]$results.Add([PSCustomObject]@{ Hostname=$f.Hostname; IP=$f.IP; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Delta='NEW'; Solution=$f.Solution })
        }
    }
    return $results
}

# ---- Wave closure proof: audit-trail causation join ----------------------
# Extends the scan compare (REMEDIATED / STILL OPEN) with a "prove it" join against
# the audit trail JANET already writes: for each closed / still-open row, did an
# operator touch that host through JANET between the two scans' dates? Models the
# hardened readers in JanetWeb.history.psm1 (share-gate + local-spool fallback +
# month enumeration + Timestamp window filter) with a private in-module copy so this
# engine stays self-contained in its own runspace (suite convention: no cross-import).

# The RUNTIME local spool the logging bridge writes to during a share outage. It is
# at the JANET root (peer to Logs\), NOT the in-repo JanetLocal the KEV catalog reads:
# New-JanetWebLogContext uses JanetRoot = Split-Path -Parent <JANET Web folder>, then
# <JanetRoot>\JanetLocal. $PSScriptRoot = <JANET Web>\modules. (Matches
# JanetWeb.history.psm1 Get-HistSpoolRoot.)
function Get-ReportsAuditSpoolRoot {
    $twoRoot   = Split-Path -Parent $PSScriptRoot
    $janetRoot = Split-Path -Parent $twoRoot
    return (Join-Path $janetRoot 'JanetLocal')
}

# Resolve which audit root to read: the central share when 445-reachable AND listable,
# else the local spool. Models JanetWeb.history.psm1 Resolve-HistRoot. Returns
# @{ Root; OnShare; Reason; Exists }.
function Resolve-ReportsAuditRoot {
    $share = Get-ReportsLogShareRoot
    $ok = $false
    try { $ok = ((Test-JanetUncReachable -Path $share) -and (Test-Path -LiteralPath $share -ErrorAction SilentlyContinue)) } catch { $ok = $false }
    if ($ok) { return @{ Root = $share; OnShare = $true; Reason = "central log share ($share)"; Exists = $true } }
    $spool  = Get-ReportsAuditSpoolRoot
    $exists = [bool](Test-Path -LiteralPath $spool -ErrorAction SilentlyContinue)
    return @{ Root = $spool; OnShare = $false; Reason = "log share unreachable - reading local spool only ($spool)"; Exists = $exists }
}

# yyyy-MM tokens covering [Start..End] inclusive, newest first, clamped to 24 so a
# bad window cannot walk years of files (mirrors Get-HistMonthTokens's clamp).
function Get-ReportsWindowMonths {
    param([datetime]$Start, [datetime]$End)
    if ($End -lt $Start) { $t = $Start; $Start = $End; $End = $t }
    $cur  = (Get-Date -Year $End.Year   -Month $End.Month   -Day 1)
    $stop = (Get-Date -Year $Start.Year -Month $Start.Month -Day 1)
    $list = New-Object System.Collections.ArrayList
    $guard = 0
    while ($cur -ge $stop -and $guard -lt 24) {
        [void]$list.Add($cur.ToString('yyyy-MM'))
        $cur = $cur.AddMonths(-1); $guard++
    }
    return @($list)
}

# Normalized key for matching an ACAS hostname against an audit TargetHost. IPv4 is
# kept whole; anything else collapses to the pre-dot short name upper-cased
# (FQDN-tolerant). Mirrors JanetWeb.history.psm1 Get-HistShortName but IP-safe - a
# bare IP must NOT collapse to its first octet.
function Get-ReportsAuditHostKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $v = ([string]$Value).Trim()
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return $v }
    return ((($v -split '\.')[0]).ToUpper())
}

# Detect cross-domain short-name COLLISIONS (ledger row 36): two physically-distinct hosts
# that fold to the SAME Get-ReportsAuditHostKey short key. The short fold is INTENDED for
# short-vs-FQDN of ONE host (web01 <-> web01.dom), but two DIFFERENT boxes sharing a short
# name make a closure/compare verdict under that shared key ambiguous. A short key is flagged
# when it is backed by EITHER:
#   (a) >=2 DISTINCT dot-bearing FQDNs (web01.us.af.mil + web01.eu.af.mil -> WEB01), OR
#   (b) >=2 DISTINCT non-empty scan IPs (loop40 P1) - the signal that catches two BARE
#       WEB01 exports (the AFNET short-name-only norm), where the FQDN signal is blind
#       because neither name has a dot. $IPs is the per-hostname scan IP (parallel array,
#       $IPs[$i] pairs with $Hostnames[$i]); the caller threads finding.IP through.
# Both signals are OrdinalIgnoreCase and PURELY ADDITIVE: they can only DEMOTE a would-be
# closure to AMBIGUOUS, never invent one and never touch the fold. A short + single FQDN,
# or a short+FQDN sharing ONE IP (one physical box, two name forms), is NOT a collision -
# that is the intended fold (this is what corrects the loop40 F2 over-fire). An IP-literal
# hostname is kept whole (never a short key) and never collides.
# RESIDUAL (documented, not a code gap): a truly IP-LESS short-name-only export (two bare
# WEB01s, no IP column at all) is genuinely UNDISAMBIGUABLE - both signals are blind, so it
# is NOT flagged, unchanged from loop39. Restore the IP / re-scan by FQDN to disambiguate.
function Get-ReportsHostKeyCollisions {
    param([string[]]$Hostnames, [string[]]$IPs)
    $byKeyFqdn = @{}   # short key -> set of distinct dot-bearing FQDNs seen under it
    $byKeyIp   = @{}   # short key -> set of distinct non-empty scan IPs seen under it
    for ($i = 0; $i -lt $Hostnames.Count; $i++) {
        $hn = ([string]$Hostnames[$i]).Trim()
        if (-not $hn) { continue }
        if ($hn -match '^\d{1,3}(\.\d{1,3}){3}$') { continue }      # IP-literal hostname - IP key, never a short key
        $key = Get-ReportsAuditHostKey $hn
        if ($hn -match '\.') {                                     # dot-bearing FQDN - contributes to signal (a)
            if (-not $byKeyFqdn.ContainsKey($key)) { $byKeyFqdn[$key] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase) }
            [void]$byKeyFqdn[$key].Add($hn)
        }
        $ip = if ($IPs -and $i -lt $IPs.Count) { ([string]$IPs[$i]).Trim() } else { '' }
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {                # a real, non-empty IPv4 - contributes to signal (b)
            if (-not $byKeyIp.ContainsKey($key)) { $byKeyIp[$key] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase) }
            [void]$byKeyIp[$key].Add($ip)
        }
    }
    $collisions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $byKeyFqdn.Keys) { if ($byKeyFqdn[$k].Count -ge 2) { [void]$collisions.Add($k) } }
    foreach ($k in $byKeyIp.Keys)   { if ($byKeyIp[$k].Count   -ge 2) { [void]$collisions.Add($k) } }
    return ,$collisions
}

# Scan Logs\<Tool>\<userFolder>\ TouchedHosts_<m>*.csv + <m>_detail*.csv across $Months
# under $Root, keeping the MOST RECENT in-window touch per interesting host key. Window
# = [Start..End] on the row Timestamp. Streams Import-Csv one file at a time (never a
# whole-tree slurp), excludes '*.legacy_*' rotations (stale schema), and caps at $Cap
# rows. Returns @{ Index = @{ hostKey -> @{ Tool; Operator; TouchDate; TouchDateDt;
# Count } }; Files; Rows; Capped }.
function Read-ReportsAuditTouchIndex {
    param(
        [string]$Root,
        [string[]]$Months,
        [hashtable]$WantHosts,
        [datetime]$Start,
        [datetime]$End,
        [int]$Cap = 300000
    )
    $index = @{}
    $files = 0; $rows = 0; $capped = $false
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        return @{ Index = $index; Files = 0; Rows = 0; Capped = $false }
    }
    if (-not $WantHosts -or $WantHosts.Count -eq 0) { return @{ Index = $index; Files = 0; Rows = 0; Capped = $false } }

    $toolDirs = @()
    try { $toolDirs = @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '_Rollup' }) } catch {}
    foreach ($td in $toolDirs) {
        if ($capped) { break }
        $toolName = $td.Name
        $opDirs = @()
        try { $opDirs = @(Get-ChildItem -LiteralPath $td.FullName -Directory -ErrorAction SilentlyContinue) } catch {}
        foreach ($od in $opDirs) {
            if ($capped) { break }
            foreach ($m in $Months) {
                if ($capped) { break }
                # (filter, host-column, use-row-Tool?) sets: TouchedHosts_<m>*.csv keys on
                # TargetHost + the folder tool name; <m>_detail*.csv keys on Target + its
                # own Tool column. Both exclude '*.legacy_*' rotations.
                $sets = @(
                    @{ Filter = ('TouchedHosts_' + $m + '*.csv'); Prop = 'TargetHost'; RowTool = $false },
                    @{ Filter = ($m + '_detail*.csv');            Prop = 'Target';     RowTool = $true }
                )
                foreach ($set in $sets) {
                    if ($capped) { break }
                    $csvFiles = @()
                    try { $csvFiles = @(Get-ChildItem -LiteralPath $od.FullName -Filter $set.Filter -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.legacy_*' }) } catch {}
                    foreach ($cf in $csvFiles) {
                        if ($capped) { break }
                        $files++
                        $data = @()
                        try { $data = @(Import-Csv -LiteralPath $cf.FullName -ErrorAction Stop) } catch { $data = @() }
                        foreach ($r in $data) {
                            if ($rows -ge $Cap) { $capped = $true; break }
                            $target = [string]$r.($set.Prop)
                            $hk = Get-ReportsAuditHostKey $target
                            if (-not $hk -or -not $WantHosts.ContainsKey($hk)) { continue }
                            $tsRaw = [string]$r.Timestamp
                            $tsD = [datetime]::MinValue
                            if (-not [datetime]::TryParse($tsRaw, [ref]$tsD)) { continue }
                            if ($tsD -lt $Start -or $tsD -gt $End) { continue }
                            $rows++
                            $rowTool = if ($set.RowTool -and -not [string]::IsNullOrWhiteSpace([string]$r.Tool)) { [string]$r.Tool } else { $toolName }
                            $op = [string]$r.Operator
                            $cur = $index[$hk]
                            if (-not $cur) {
                                $index[$hk] = @{ Tool = $rowTool; Operator = $op; TouchDate = $tsRaw; TouchDateDt = $tsD; Count = 1 }
                            } else {
                                $cur.Count++
                                if ($tsD -gt $cur.TouchDateDt) { $cur.Tool = $rowTool; $cur.Operator = $op; $cur.TouchDate = $tsRaw; $cur.TouchDateDt = $tsD }
                            }
                        }
                    }
                }
            }
        }
    }
    return @{ Index = $index; Files = $files; Rows = $rows; Capped = $capped }
}

# ---- Remediation plan helpers --------------------------------------------

function Get-RemediationApp {
    param([Parameter(Mandatory)][string]$Category)
    switch ($Category) {
        'Chrome'        { return 'Chrome' }
        'Edge'          { return 'Edge' }
        'Office'        { return 'Office' }
        'KB Patch'      { return 'KB' }
        'Registry Fix'  { return 'Other' }
        'Apache'        { return 'Other' }
        'NOT OUR PATCH' { return $null }
        default         { return 'Other' }
    }
}

function Convert-VersionForSort {
    param([string]$Ver)
    if ([string]::IsNullOrWhiteSpace($Ver)) { return [System.Version]::new(0,0,0,0) }
    $parts = $Ver.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    try { return [System.Version]::new([int]$parts[0], [int]$parts[1], [int]$parts[2], [int]$parts[3]) }
    catch { return [System.Version]::new(0,0,0,0) }
}

function Get-VersionsFromText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $verMatches = [regex]::Matches($Text, '\b\d+(?:\.\d+){2,3}\b')
    if ($verMatches.Count -eq 0) { return @() }
    $list = @($verMatches.Value | Select-Object -Unique)
    return @($list | Sort-Object -Property @{ Expression = { Convert-VersionForSort $_ } } -Descending)
}

function Build-RemediationPlan {
    # Single pass over $script:AcasFindings. Returns @{ Rows; Summary; OtherGroups }.
    $bucket = @{}
    $appTargets = @{}
    $otherByPlugin = @{}
    foreach ($f in $script:AcasFindings) {
        $vn = ($f.VulnName -as [string]).ToLower()
        $app = if ($vn -match 'defender|microsoft security essentials|antimalware') { 'Defender' } else { Get-RemediationApp -Category $f.Category }
        if (-not $app) { continue }
        # loop20: key the per-(host,app) bucket on the NORMALIZED audit host key
        # (IPv4-whole, else pre-dot short name upper) so one physical box exported
        # as WEB01 in one row and web01.dom in another folds to ONE plan row / ONE
        # summary host - completing the loop13 sweep that already normalized the
        # adjacent Other-group host count. The status setter (Invoke mark-remediation)
        # keys the SAME way, so the persisted status still lines up. Keep the raw
        # first-seen Hostname for display.
        $hk  = Get-ReportsAuditHostKey ([string]$f.Hostname)
        $key = "$hk|$app"
        if (-not $bucket.ContainsKey($key)) {
            $bucket[$key] = @{
                Hostname        = $f.Hostname
                App             = $app
                CurrentVersions = New-Object System.Collections.ArrayList
                TargetSeen      = New-Object System.Collections.ArrayList
                MaxSeverity     = 'Info'
                SeverityRank    = 0
                LastObserved    = ''
                PluginIDs       = New-Object System.Collections.ArrayList
                FindingCount    = 0
                HasKev          = $false
                Status          = 'Pending'
                By              = ''
                Date            = ''
                Notes           = ''
            }
        }
        $r = $bucket[$key]
        $r.FindingCount++
        if ($f.InKEV) { $r.HasKev = $true }
        if (-not $r.PluginIDs.Contains($f.PluginID)) { [void]$r.PluginIDs.Add($f.PluginID) }
        $sevRank = switch ($f.Severity) { 'Critical'{4} 'High'{3} 'Medium'{2} 'Low'{1} 'Info'{0} default{0} }
        if ($sevRank -gt $r.SeverityRank) { $r.SeverityRank = $sevRank; $r.MaxSeverity = $f.Severity }
        foreach ($v in (Get-VersionsFromText -Text $f.Solution)) {
            if (-not $r.TargetSeen.Contains($v)) { [void]$r.TargetSeen.Add($v) }
            if (-not $appTargets.ContainsKey($app)) { $appTargets[$app] = $v }
            elseif ((Convert-VersionForSort $v) -gt (Convert-VersionForSort $appTargets[$app])) { $appTargets[$app] = $v }
        }
        foreach ($v in (Get-VersionsFromText -Text $f.VulnName)) {
            if (-not $r.CurrentVersions.Contains($v)) { [void]$r.CurrentVersions.Add($v) }
        }
        if ($app -eq 'Other') {
            $pluginIdKey = ($f.PluginID -as [string])
            if ([string]::IsNullOrWhiteSpace($pluginIdKey)) { continue }
            if (-not $otherByPlugin.ContainsKey($pluginIdKey)) {
                $otherByPlugin[$pluginIdKey] = @{
                    PluginID     = $pluginIdKey
                    VulnName     = ($f.VulnName -as [string])
                    Hosts        = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                    KevHosts     = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                    MaxSeverity  = 'Info'
                    SeverityRank = 0
                    TargetSeen   = New-Object System.Collections.ArrayList
                    Solution     = ($f.Solution -as [string])
                    FindingCount = 0
                }
            }
            $g = $otherByPlugin[$pluginIdKey]
            # loop13: TargetCount / KevCount count DISTINCT hosts - key on the normalized audit
            # key so a short+FQDN pair of one host is not counted twice (agrees with CORA).
            $g_hk = Get-ReportsAuditHostKey ([string]$f.Hostname)
            if ($g_hk) { [void]$g.Hosts.Add($g_hk); if ($f.InKEV) { [void]$g.KevHosts.Add($g_hk) } }
            $g.FindingCount++
            if ($sevRank -gt $g.SeverityRank) { $g.SeverityRank = $sevRank; $g.MaxSeverity = $f.Severity }
            foreach ($v in (Get-VersionsFromText -Text $f.Solution)) {
                if (-not $g.TargetSeen.Contains($v)) { [void]$g.TargetSeen.Add($v) }
            }
        }
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($key in $bucket.Keys) {
        $r = $bucket[$key]
        if ($appTargets.ContainsKey($r.App)) { $r.TargetVersion = $appTargets[$r.App] }
        else { $r.TargetVersion = $null }
        if ($script:RemediationStatus.ContainsKey($key)) {
            $s = $script:RemediationStatus[$key]
            $r.Status = $s.Status; $r.By = $s.By; $r.Date = $s.Date; $r.Notes = $s.Notes
        }
        [void]$rows.Add($r)
    }
    $summary = @{ Chrome=0; Edge=0; Office=0; Defender=0; KB=0; Other=0 }
    $hostsBy = @{ Chrome=@{}; Edge=@{}; Office=@{}; Defender=@{}; KB=@{}; Other=@{} }
    foreach ($r in $rows) {
        if ($r.Status -eq 'Pushed' -or $r.Status -eq 'Skipped') { continue }
        # loop20: count DISTINCT hosts per app on the normalized key (rows are now
        # already one-per-(normalized-host,app), but normalize here too so the summary
        # can never double-count a short+FQDN pair).
        $rHk = Get-ReportsAuditHostKey ([string]$r.Hostname)
        if (-not $hostsBy[$r.App].ContainsKey($rHk)) {
            $hostsBy[$r.App][$rHk] = $true
            $summary[$r.App]++
        }
    }
    $otherGroups = New-Object System.Collections.ArrayList
    foreach ($pluginIdKey in $otherByPlugin.Keys) {
        if ($script:OtherVulnPushed.ContainsKey($pluginIdKey)) { continue }
        $g = $otherByPlugin[$pluginIdKey]
        if ($g.Hosts.Count -lt $script:OtherVulnGroupMinHosts) { continue }
        $tgt = $null
        if ($g.TargetSeen.Count -gt 0) {
            $tgt = ($g.TargetSeen | Sort-Object -Property @{ Expression = { Convert-VersionForSort $_ } } -Descending | Select-Object -First 1)
        }
        [void]$otherGroups.Add(@{
            PluginID      = $g.PluginID
            VulnName      = $g.VulnName
            HostCount     = $g.Hosts.Count
            KevHostCount  = $g.KevHosts.Count
            Hosts         = @($g.Hosts | Sort-Object)
            MaxSeverity   = $g.MaxSeverity
            SeverityRank  = $g.SeverityRank
            TargetVersion = $tgt
            Solution      = $g.Solution
            FindingCount  = $g.FindingCount
        })
    }
    $otherGroupsSorted = @($otherGroups | Sort-Object -Property @{ Expression = { -$_.SeverityRank } }, @{ Expression = { -$_.HostCount } })
    return @{
        Rows        = @($rows | Sort-Object -Property @{ Expression = { -$_.SeverityRank } }, App, Hostname)
        Summary     = $summary
        OtherGroups = $otherGroupsSorted
    }
}

# ---- Weekly export helpers (CSV matrix parse) ----------------------------

function Read-AcasCsvMatrix {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { return $null }   # audit 2026-07-23: -LiteralPath (lone offender; [ ] in a filename must not glob)
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop } catch {
        return $null
    }
    $matrix = New-Object System.Collections.ArrayList
    $parser = $null
    try {
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($FilePath)
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        while (-not $parser.EndOfData) {
            try { [void]$matrix.Add($parser.ReadFields()) }
            catch { [void]$matrix.Add(@()) }
        }
    } finally {
        if ($parser) { $parser.Dispose() }
    }
    return $matrix
}

function Get-AcasCellSafe {
    param($Row, [int]$Col)
    if ($null -eq $Row -or $Row.Length -le $Col) { return '' }
    $v = $Row[$Col]
    if ($null -eq $v) { return '' }
    return [string]$v
}

function ConvertTo-AcasInt {
    param($Value)
    if ($null -eq $Value) { return 0 }
    $s = ([string]$Value).Trim().Replace(',', '')
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq 'N/A' -or $s -eq 'Discovery') { return 0 }
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }
    return 0
}

function ConvertTo-AcasDouble {
    param($Value)
    if ($null -eq $Value) { return [double]::NaN }
    $s = ([string]$Value).Trim().Replace(',', '').Replace('%', '')
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq 'N/A' -or $s -eq 'Discovery') { return [double]::NaN }
    $d = 0.0
    if ([double]::TryParse($s, [ref]$d)) { return $d }
    return [double]::NaN
}

function Get-AcasScanCategory {
    param([string]$ScanName)
    foreach ($rule in $script:AcasCategoryRules) {
        if ($ScanName -match $rule.Pattern) {
            return @{ Category = $rule.Category; Owner = $rule.Owner }
        }
    }
    return @{ Category = 'Other'; Owner = $null }
}

function Parse-AcasScanRow {
    param([Parameter(Mandatory)]$Row, [int]$ColStart, [string]$Name)
    $cat = Get-AcasScanCategory -ScanName $Name
    if ($cat.Category -eq 'Ignore') { return $null }
    $good     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 1))
    $bad      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 2))
    $crit     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 3))
    $high     = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 4))
    $med      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 5))
    $low      = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 6))
    $totalIps = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 7))
    $limboIps = ConvertTo-AcasInt    (Get-AcasCellSafe $Row ($ColStart + 8))
    $vph      = ConvertTo-AcasDouble (Get-AcasCellSafe $Row ($ColStart + 9))
    $arPct    = ConvertTo-AcasDouble (Get-AcasCellSafe $Row ($ColStart + 10))
    $sumAll = $good + $bad + $crit + $high + $med + $low + $totalIps
    if ($sumAll -eq 0 -and [double]::IsNaN($vph)) { return $null }
    return [PSCustomObject]@{
        Name       = $Name
        Good       = $good
        Bad        = $bad
        Crit       = $crit
        High       = $high
        Med        = $med
        Low        = $low
        TotalVulns = $crit + $high + $med + $low
        TotalIps   = $totalIps
        LimboIps   = $limboIps
        Vph        = $vph
        ArPct      = $arPct
        Category   = $cat.Category
        Owner      = $cat.Owner
    }
}

function Get-AcasDateRange {
    param([string]$HeaderText)
    if ($HeaderText -match 'RAW SCAN DATA:\s*-?\s*(.+?)\s*$') {
        return $Matches[1].Trim().TrimEnd(',').Trim()
    }
    return $HeaderText
}

function Parse-AcasCalculationsWorkbook {
    param([string]$FilePath)
    $matrix = Read-AcasCsvMatrix -FilePath $FilePath
    if (-not $matrix -or $matrix.Count -eq 0) { return $null }

    $weeks = New-Object System.Collections.ArrayList
    $sides = @(
        @{ Enclave = 'NIPR'; ColStart = 0  }
        @{ Enclave = 'SIPR'; ColStart = 15 }
    )

    foreach ($side in $sides) {
        $headerRows = @()
        for ($i = 0; $i -lt $matrix.Count; $i++) {
            $cell = Get-AcasCellSafe $matrix[$i] $side.ColStart
            if ($cell -match '^RAW SCAN DATA:') { $headerRows += $i }
        }
        for ($h = 0; $h -lt $headerRows.Count; $h++) {
            $startRow = $headerRows[$h]
            $endRow   = if ($h + 1 -lt $headerRows.Count) { $headerRows[$h + 1] - 1 } else { $matrix.Count - 1 }
            $headerText = Get-AcasCellSafe $matrix[$startRow] $side.ColStart
            $week = [PSCustomObject]@{
                Enclave       = $side.Enclave
                HeaderText    = $headerText
                DateRange     = Get-AcasDateRange $headerText
                StartRow      = $startRow
                EndRow        = $endRow
                Scans         = (New-Object System.Collections.ArrayList)
                InHouseTotals = $null
                MajcomTotals  = $null
                Stale         = $false
                Warnings      = (New-Object System.Collections.ArrayList)
            }
            for ($r = $startRow + 1; $r -le $endRow; $r++) {
                $row = $matrix[$r]
                $name = (Get-AcasCellSafe $row $side.ColStart).Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                if ($name -eq 'BLANK') { continue }
                if ($name -match '^(SCAN NAMES|VULN SCAN)$') { continue }
                if ($name -in @('GOOD','BAD','BAD ','CRIT','HIGH','MED','LOW','WVI','RATE','30-D FILTER: CCRI')) { continue }
                if ($name -match '^EXEC\. SUMMARY') { continue }
                if ($name -match '^PMO ULI_GCCS') { continue }
                if ($name -match '^RAF Lakenheath In House TOTALS') {
                    $week.InHouseTotals = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                    continue
                }
                if ($name -match '^MAJCOM TOTALS') {
                    $week.MajcomTotals = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                    continue
                }
                if ($name -match '^AFNS ISN TOTALS') { continue }
                $scan = Parse-AcasScanRow -Row $row -ColStart $side.ColStart -Name $name
                if ($scan) { [void]$week.Scans.Add($scan) }
            }
            $ihEmpty = (-not $week.InHouseTotals) -or (
                $week.InHouseTotals.Good -eq 0 -and $week.InHouseTotals.Bad -eq 0 -and
                $week.InHouseTotals.TotalVulns -eq 0)
            $mjHas = $week.MajcomTotals -and (
                $week.MajcomTotals.Good -gt 0 -or $week.MajcomTotals.Bad -gt 0 -or
                $week.MajcomTotals.TotalVulns -gt 0)
            if ($ihEmpty -and $mjHas) {
                $week.Stale = $true
                [void]$week.Warnings.Add("In-House totals empty but MAJCOM row has data - possible carry-over from a previous month.")
            }
            [void]$weeks.Add($week)
        }
    }
    return $weeks
}

function Get-WeeklyCategoryMetrics {
    param([Parameter(Mandatory)]$Week)
    $byCat = @{}
    foreach ($scan in $Week.Scans) {
        $cat = $scan.Category
        if (-not $byCat.ContainsKey($cat)) {
            $byCat[$cat] = [PSCustomObject]@{
                Category   = $cat
                Good = 0; Bad = 0; Crit = 0; High = 0; Med = 0; Low = 0
                TotalVulns = 0; TotalIps = 0; LimboIps = 0
                VphNumerator = 0.0; VphHosts = 0; ScanCount = 0
            }
        }
        $b = $byCat[$cat]
        $b.Good += $scan.Good; $b.Bad += $scan.Bad
        $b.Crit += $scan.Crit; $b.High += $scan.High
        $b.Med  += $scan.Med;  $b.Low  += $scan.Low
        $b.TotalVulns += $scan.TotalVulns
        $b.TotalIps   += $scan.TotalIps
        $b.LimboIps   += $scan.LimboIps
        $b.ScanCount  += 1
        if (-not [double]::IsNaN($scan.Vph) -and $scan.TotalIps -gt 0) {
            $b.VphNumerator += $scan.Vph * $scan.TotalIps
            $b.VphHosts     += $scan.TotalIps
        }
    }
    foreach ($key in @($byCat.Keys)) {
        $b = $byCat[$key]
        $vph = if ($b.VphHosts -gt 0) { [Math]::Round($b.VphNumerator / $b.VphHosts, 2) } else { [double]::NaN }
        $ar  = if (($b.Good + $b.Bad) -gt 0) { [Math]::Round(($b.Good / ($b.Good + $b.Bad)) * 100, 2) } else { [double]::NaN }
        Add-Member -InputObject $b -NotePropertyName 'Vph'   -NotePropertyValue $vph -Force
        Add-Member -InputObject $b -NotePropertyName 'ArPct' -NotePropertyValue $ar  -Force
    }
    return $byCat
}

function Get-WeeklyPmoOwnerMetrics {
    param([Parameter(Mandatory)]$Week)
    $byOwner = @{}
    foreach ($scan in $Week.Scans) {
        if ($scan.Category -ne 'PMO') { continue }
        $owner = if ($scan.Owner) { $scan.Owner } else { 'PMO / Unknown' }
        if (-not $byOwner.ContainsKey($owner)) {
            $byOwner[$owner] = [PSCustomObject]@{
                Owner = $owner; Good = 0; Bad = 0
                TotalVulns = 0; TotalIps = 0
                VphNumerator = 0.0; VphHosts = 0; ScanCount = 0
                ScanNames = (New-Object System.Collections.ArrayList)
            }
        }
        $o = $byOwner[$owner]
        $o.Good += $scan.Good; $o.Bad += $scan.Bad
        $o.TotalVulns += $scan.TotalVulns
        $o.TotalIps   += $scan.TotalIps
        $o.ScanCount  += 1
        [void]$o.ScanNames.Add($scan.Name)
        if (-not [double]::IsNaN($scan.Vph) -and $scan.TotalIps -gt 0) {
            $o.VphNumerator += $scan.Vph * $scan.TotalIps
            $o.VphHosts     += $scan.TotalIps
        }
    }
    foreach ($key in @($byOwner.Keys)) {
        $o = $byOwner[$key]
        $vph = if ($o.VphHosts -gt 0) { [Math]::Round($o.VphNumerator / $o.VphHosts, 2) } else { [double]::NaN }
        Add-Member -InputObject $o -NotePropertyName 'Vph' -NotePropertyValue $vph -Force
    }
    return $byOwner
}

function Get-WeeklyArWithoutPmo {
    param([Parameter(Mandatory)]$Week)
    $good = 0; $bad = 0
    foreach ($scan in $Week.Scans) {
        if ($scan.Category -eq 'PMO') { continue }
        $good += $scan.Good; $bad += $scan.Bad
    }
    if (($good + $bad) -eq 0) { return [PSCustomObject]@{ Good = 0; Bad = 0; ArPct = [double]::NaN } }
    return [PSCustomObject]@{
        Good  = $good; Bad = $bad
        ArPct = [Math]::Round(($good / ($good + $bad)) * 100, 2)
    }
}

function Format-AcasNumber {
    param($Value, [string]$Format = 'N0')
    if ($null -eq $Value) { return 'N/A' }
    if ($Value -is [double] -and [double]::IsNaN($Value)) { return 'N/A' }
    return ([double]$Value).ToString($Format)
}

function Format-AcasPercent {
    param($Value)
    if ($null -eq $Value) { return 'N/A' }
    if ($Value -is [double] -and [double]::IsNaN($Value)) { return 'N/A' }
    return ([double]$Value).ToString('0.00') + '%'
}

function Export-AcasFindingsCsvText {
    # Full ACAS findings CSV body as a string. Columns verbatim from the desktop
    # "Export Full CSV" handler (ReportsTool_2.14.5.ps1:6735-6741).
    param($Findings)
    $lines = New-Object System.Collections.ArrayList
    # Neutralize spreadsheet formula injection on scanner-supplied free text via the
    # canonical ConvertTo-ReportsCsvCell (guard + RFC-4180 quote-when-needed).
    # audit 2026-07-23: the hand-rolled guard + quote-doubling collapsed onto the
    # helper; cells with no comma/quote/newline are no longer force-quoted - the
    # parsed CSV is unchanged.
    # audit loop7 P3: run EVERY cell through the guard - PatchedBy is operator-typed (EDIPI)
    # free text, the rest are scanner-supplied; a leading = + - @ would otherwise evaluate in Excel.
    [void]$lines.Add('"Host","PluginID","VulnName","Severity","IAVA","Category","Status","PatchedDate","PatchedBy","Solution"')
    foreach ($f in $Findings) {
        [void]$lines.Add((@(
            (ConvertTo-ReportsCsvCell $f.Hostname), (ConvertTo-ReportsCsvCell $f.PluginID),
            (ConvertTo-ReportsCsvCell $f.VulnName), (ConvertTo-ReportsCsvCell $f.Severity),
            (ConvertTo-ReportsCsvCell $f.IAVA),     (ConvertTo-ReportsCsvCell $f.Category),
            (ConvertTo-ReportsCsvCell $f.Status),   (ConvertTo-ReportsCsvCell $f.PatchedDate),
            (ConvertTo-ReportsCsvCell $f.PatchedBy),(ConvertTo-ReportsCsvCell $f.Solution)
        ) -join ','))
    }
    return (($lines -join "`r`n") + "`r`n")
}

function Export-WeeklyToCsvText {
    # Returns the single-week CSV body as a string (caller writes / streams).
    param([Parameter(Mandatory)]$Week)
    $lines = New-Object System.Collections.ArrayList
    # Neutralize spreadsheet formula injection on scanner/user-supplied free text
    # (scan Name / Category / Owner / ScanNames) via the canonical
    # ConvertTo-ReportsCsvCell (guard + RFC-4180 quote-when-needed).
    # audit 2026-07-23: the hand-rolled guard + quote-doubling collapsed onto the
    # helper (cells with no comma/quote/newline are no longer force-quoted - the
    # parsed CSV is unchanged), and the inline NaN->'N/A' number formatting now
    # goes through Format-AcasNumber / Format-AcasPercent (same output).
    [void]$lines.Add("# ACAS Weekly Export - $($Week.Enclave) - $($Week.DateRange)")
    [void]$lines.Add("# Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $(Get-ReportsCleanUser) on $env:COMPUTERNAME")
    if ($Week.Stale) {
        [void]$lines.Add("# WARNING: stale-data heuristic triggered - In-House totals empty but MAJCOM populated. Verify before publishing.")
    }
    [void]$lines.Add('')
    [void]$lines.Add('"SCAN","CATEGORY","OWNER","GOOD","BAD","CRIT","HIGH","MED","LOW","TOTAL VULNS","TOTAL IPS","LIMBO","VPH","AR %"')
    foreach ($s in $Week.Scans) {
        $nm  = ConvertTo-ReportsCsvCell $s.Name
        $cat = ConvertTo-ReportsCsvCell $s.Category
        $vphStr = Format-AcasNumber $s.Vph '0.00'
        $arStr  = Format-AcasPercent $s.ArPct
        $own = if ($s.Owner) { ConvertTo-ReportsCsvCell $s.Owner } else { '' }
        [void]$lines.Add("$nm,$cat,$own,$($s.Good),$($s.Bad),$($s.Crit),$($s.High),$($s.Med),$($s.Low),$($s.TotalVulns),$($s.TotalIps),$($s.LimboIps),$vphStr,$arStr")
    }
    [void]$lines.Add('')
    [void]$lines.Add('# === BY CATEGORY ===')
    [void]$lines.Add('"CATEGORY","SCANS","GOOD","BAD","TOTAL VULNS","TOTAL IPS","VPH (WTD)","AR %"')
    $cats = Get-WeeklyCategoryMetrics -Week $Week
    foreach ($k in ($cats.Keys | Sort-Object)) {
        $c = $cats[$k]
        $ccat = ConvertTo-ReportsCsvCell $c.Category
        $vphStr = Format-AcasNumber $c.Vph '0.00'
        $arStr  = Format-AcasPercent $c.ArPct
        [void]$lines.Add("$ccat,$($c.ScanCount),$($c.Good),$($c.Bad),$($c.TotalVulns),$($c.TotalIps),$vphStr,$arStr")
    }
    [void]$lines.Add('')
    [void]$lines.Add('# === PMO BREAKDOWN BY OWNER ===')
    [void]$lines.Add('"OWNER","SCANS","GOOD","BAD","TOTAL VULNS","TOTAL IPS","VPH (WTD)","SCAN NAMES"')
    $owners = Get-WeeklyPmoOwnerMetrics -Week $Week
    foreach ($k in ($owners.Keys | Sort-Object)) {
        $o = $owners[$k]
        $oown = ConvertTo-ReportsCsvCell $o.Owner
        $vphStr = Format-AcasNumber $o.Vph '0.00'
        $names  = ConvertTo-ReportsCsvCell ($o.ScanNames -join ' | ')
        [void]$lines.Add("$oown,$($o.ScanCount),$($o.Good),$($o.Bad),$($o.TotalVulns),$($o.TotalIps),$vphStr,$names")
    }
    [void]$lines.Add('')
    [void]$lines.Add('# === ROLLUP ROWS ===')
    [void]$lines.Add('"LABEL","GOOD","BAD","CRIT","HIGH","MED","LOW","TOTAL VULNS","TOTAL IPS","LIMBO","VPH","AR %"')
    foreach ($pair in @(
        @{ Label = 'RAF Lakenheath In House TOTALS'; Row = $Week.InHouseTotals }
        @{ Label = 'MAJCOM TOTALS';                   Row = $Week.MajcomTotals  }
    )) {
        $r = $pair.Row
        if (-not $r) { continue }
        $vphStr = Format-AcasNumber $r.Vph '0.00'
        $arStr  = Format-AcasPercent $r.ArPct
        [void]$lines.Add("$(ConvertTo-ReportsCsvCell $pair.Label),$($r.Good),$($r.Bad),$($r.Crit),$($r.High),$($r.Med),$($r.Low),$($r.TotalVulns),$($r.TotalIps),$($r.LimboIps),$vphStr,$arStr")
    }
    return ($lines -join "`r`n")
}

function Get-WeeklySafeFileName {
    # Compose an export filename that includes the enclave and a date stamp
    # so SIPR data never lands in a NIPR-labeled workbook. Ported from
    # ReportsTool_2.14.5.ps1:4158.
    param([Parameter(Mandatory)]$Week, [string]$Extension = 'csv')
    $range = ($Week.DateRange -replace '[^A-Za-z0-9_\- ]', '').Trim() -replace '\s+','_'
    if (-not $range) { $range = 'unknown' }
    # audit loop7 P3: sanitize Enclave too (a hard-coded 'NIPR'/'SIPR' today, but defensive if it
    # ever becomes data-derived) so no traversal/odd char can reach the Join-Path'd filename.
    $enc = ([string]$Week.Enclave -replace '[^A-Za-z0-9_\-]', ''); if (-not $enc) { $enc = 'ENC' }
    return "ACAS_Weekly_${range}_$enc.$Extension"
}

function Test-JanetUncReachable {
    # TCP-445 pre-gate for file writes against UNC paths so a dead share cannot
    # hang the worker mid-export. AFNET blocks ICMP, and 445 is the authoritative
    # signal for an SMB write anyway, so probe 445 directly. Non-UNC paths pass.
    param([string]$Path)
    if ($Path -notmatch '^\\\\([^\\]+)\\') { return $true }
    $uncHost = $Matches[1]
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($uncHost, 445, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(2000) -and $tcp.Connected) { return $true }
        return $false
    } catch {
        return $false
    } finally {
        if ($tcp) { try { $tcp.Close() } catch {} }
    }
}

# ---- CORA summary ---------------------------------------------------------

function Build-CoraSummary {
    # Single pass over open + actionable findings.
    $hosts    = @{}
    $sevCount = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    $sevHosts = @{ Critical=@{}; High=@{}; Medium=@{}; Low=@{}; Info=@{} }
    $catData  = @{}
    $byPlugin = @{}
    $considered = 0
    foreach ($f in $script:AcasFindings) {
        if ($f.Status -eq 'Patched') { continue }
        if ($f.Category -eq 'NOT OUR PATCH') { continue }
        $considered++
        # loop39 (ledger row 37): count unique hosts by the SAME normalized key the compare /
        # closure paths use (Get-ReportsAuditHostKey), so one physical box exported as WEB01 in
        # one file and web01.us.af.mil in another counts ONCE, not twice. The map value keeps a
        # representative display name per key (the raw hostname); only the KEY drives the count.
        $hk = Get-ReportsAuditHostKey $f.Hostname
        $hosts[$hk] = $f.Hostname
        $sev = $f.Severity
        if (-not $sevCount.ContainsKey($sev)) { $sevCount[$sev] = 0; $sevHosts[$sev] = @{} }
        $sevCount[$sev]++
        $sevHosts[$sev][$hk] = $f.Hostname
        $cat = if ([string]::IsNullOrWhiteSpace($f.Category)) { 'Other' } else { $f.Category }
        if (-not $catData.ContainsKey($cat)) { $catData[$cat] = @{ Count = 0; Hosts = @{} } }
        $catData[$cat].Count++
        $catData[$cat].Hosts[$hk] = $f.Hostname
        $pluginIdKey = ($f.PluginID -as [string])
        if ([string]::IsNullOrWhiteSpace($pluginIdKey)) { continue }
        $thisRank = switch ($f.Severity) { 'Critical'{4} 'High'{3} 'Medium'{2} 'Low'{1} 'Info'{0} default{0} }
        if (-not $byPlugin.ContainsKey($pluginIdKey)) {
            $byPlugin[$pluginIdKey] = @{
                PluginID     = $pluginIdKey
                VulnName     = ($f.VulnName -as [string])
                Severity     = $f.Severity
                SeverityRank = $thisRank
                Hosts        = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                Category     = $cat
                Solution     = ($f.Solution -as [string])
                FindingCount = 0
            }
        }
        $g = $byPlugin[$pluginIdKey]
        [void]$g.Hosts.Add($hk)
        $g.FindingCount++
        if ($thisRank -gt $g.SeverityRank) { $g.SeverityRank = $thisRank; $g.Severity = $f.Severity }
    }
    $uniqueHosts = $hosts.Count
    $vph = if ($uniqueHosts -gt 0) { [Math]::Round($considered / $uniqueHosts, 2) } else { 0.0 }
    $pluginList = New-Object System.Collections.ArrayList
    foreach ($k in $byPlugin.Keys) {
        $g = $byPlugin[$k]
        [void]$pluginList.Add([PSCustomObject]@{
            PluginID     = $g.PluginID
            VulnName     = $g.VulnName
            Severity     = $g.Severity
            SeverityRank = $g.SeverityRank
            HostCount    = $g.Hosts.Count
            FindingCount = $g.FindingCount
            Category     = $g.Category
            Solution     = $g.Solution
        })
    }
    $topVulns = @($pluginList |
        Sort-Object -Property @{ Expression = { -$_.HostCount } }, @{ Expression = { -$_.SeverityRank } }, VulnName |
        Select-Object -First 15)
    $netSize = $script:NetworkDeviceCount
    $netPct  = if ($netSize -gt 0 -and $uniqueHosts -gt 0) {
        [Math]::Round(($uniqueHosts / $netSize) * 100, 1)
    } else { [double]::NaN }
    return @{
        ConsideredFindings = $considered
        UniqueHosts        = $uniqueHosts
        Vph                = $vph
        SevCount           = $sevCount
        SevHosts           = @{
            Critical = $sevHosts['Critical'].Count
            High     = $sevHosts['High'].Count
            Medium   = $sevHosts['Medium'].Count
            Low      = $sevHosts['Low'].Count
            Info     = $sevHosts['Info'].Count
        }
        Categories         = $catData
        TopVulns           = $topVulns
        NetworkSize        = $netSize
        NetworkPct         = $netPct
        TotalLoaded        = $script:AcasFindings.Count
    }
}

# ---- Dirty 30 parse / lookup / probe -------------------------------------

# --- Dirty 30 severity corrector ------------------------------------------
# Tenable "Top Worst Hosts" renders the Crit/High/Med/Low breakdown as a
# stacked bar. When a segment is narrow, pdftotext glues its label onto the
# next ("2"+"19" -> "219") and drops zero-count segments, so a naive
# left-to-right read inflates Critical (the "hundreds of vulns" bug) or, when
# only two numbers survive, fails to parse. The Score column extracts cleanly
# and for this report satisfies  Score = 10*Crit + 10*High + 4*Med + 1*Low;
# Resolve-Dirty30Severities uses that invariant to recover the true split.

function Get-D30IntSplits {
    # Every way to cut a digit-string into >=1 positive-integer pieces (no
    # leading-zero pieces). Returns an ArrayList of int[].
    param([string]$Digits)
    $out = New-Object System.Collections.ArrayList
    $n = $Digits.Length
    if ($n -eq 0) { return ,$out }
    $gaps   = $n - 1
    $combos = [int][math]::Pow(2, $gaps)
    for ($mask = 0; $mask -lt $combos; $mask++) {
        $pieces = New-Object System.Collections.ArrayList
        $cur = [string]$Digits[0]
        for ($g = 0; $g -lt $gaps; $g++) {
            if ((($mask -shr $g) -band 1) -eq 1) { [void]$pieces.Add($cur); $cur = '' }
            $cur = $cur + $Digits[$g + 1]
        }
        [void]$pieces.Add($cur)
        $ok = $true
        foreach ($p in $pieces) {
            if ($p.Length -eq 0) { $ok = $false; break }
            if ($p.Length -gt 1 -and $p[0] -eq '0') { $ok = $false; break }
        }
        if ($ok) {
            $ints = New-Object System.Collections.ArrayList
            foreach ($p in $pieces) { [void]$ints.Add([int]$p) }
            [void]$out.Add($ints.ToArray())
        }
    }
    return ,$out
}

function Get-D30SlotCombos {
    # Choose $J severity-slot indices from {0=Crit,1=High,2=Med,3=Low} in
    # strictly increasing order (models Tenable omitting zero-count segments
    # while preserving severity order). Returns an ArrayList of int[].
    param([int]$J)
    $res = New-Object System.Collections.ArrayList
    for ($a = 0; $a -lt 4; $a++) {
        if ($J -eq 1) { [void]$res.Add(@($a)); continue }
        for ($b = $a + 1; $b -lt 4; $b++) {
            if ($J -eq 2) { [void]$res.Add(@($a, $b)); continue }
            for ($c = $b + 1; $c -lt 4; $c++) {
                if ($J -eq 3) { [void]$res.Add(@($a, $b, $c)); continue }
                for ($d = $c + 1; $d -lt 4; $d++) {
                    if ($J -eq 4) { [void]$res.Add(@($a, $b, $c, $d)) }
                }
            }
        }
    }
    return ,$res
}

function Resolve-Dirty30Severities {
    # Recover true Crit/High/Med/Low from a Tenable bar that pdftotext glued
    # ("2"+"19" -> "219") or zero-collapsed, using the clean Score column and
    # the report invariant  Score = 10*Crit + 10*High + 4*Med + 1*Low.
    # Returns @{ Crit; High; Med; Low; Confidence } where Confidence is:
    #   asis       - naive read already matched the Score (untouched)
    #   corrected  - exactly one score-consistent reading found
    #   ambiguous  - several score-consistent readings (Crit-vs-High share
    #                weight 10 so Score can't split them); best guess returned,
    #                caller should flag for manual verification
    #   unresolved - no score-consistent reading; naive read returned as-is
    param([int]$Score, [string[]]$BarTokens)

    $nv = @(0, 0, 0, 0)
    $cap = [math]::Min(4, $BarTokens.Count)
    for ($i = 0; $i -lt $cap; $i++) {
        $t = 0; [void][int]::TryParse(($BarTokens[$i] -replace '[^\d]', ''), [ref]$t); $nv[$i] = $t
    }
    $naive = [PSCustomObject]@{ Crit = $nv[0]; High = $nv[1]; Med = $nv[2]; Low = $nv[3]; Confidence = 'asis' }

    if ($Score -le 0) { return $naive }
    $naiveSum = $nv[0]*10 + $nv[1]*10 + $nv[2]*4 + $nv[3]
    if ($naiveSum -eq $Score -and $BarTokens.Count -le 4) { return $naive }

    $seqs = New-Object System.Collections.ArrayList
    [void]$seqs.Add(@())
    foreach ($tok in $BarTokens) {
        $digits = ($tok -replace '[^\d]', '')
        if (-not $digits) { continue }
        $splits = Get-D30IntSplits $digits
        $next = New-Object System.Collections.ArrayList
        foreach ($partial in $seqs) {
            foreach ($pieces in $splits) { [void]$next.Add( @($partial + $pieces) ) }
        }
        $seqs = $next
    }

    $matches = New-Object System.Collections.ArrayList
    foreach ($seq in $seqs) {
        $J = @($seq).Count
        if ($J -lt 1 -or $J -gt 4) { continue }
        foreach ($combo in (Get-D30SlotCombos $J)) {
            $slots = @(0, 0, 0, 0)
            for ($k = 0; $k -lt $J; $k++) { $slots[$combo[$k]] = $seq[$k] }
            $sum = $slots[0]*10 + $slots[1]*10 + $slots[2]*4 + $slots[3]
            if ($sum -eq $Score) {
                $nSplit   = $J - $BarTokens.Count
                $leadOmit = $combo[0]
                $cost = $nSplit*1000 + $leadOmit*100 + $slots[0]
                [void]$matches.Add([PSCustomObject]@{
                    C = $slots[0]; H = $slots[1]; M = $slots[2]; L = $slots[3]
                    Cost = $cost; Key = ('{0}/{1}/{2}/{3}' -f $slots[0],$slots[1],$slots[2],$slots[3])
                })
            }
        }
    }
    if ($matches.Count -eq 0) {
        return [PSCustomObject]@{ Crit = $nv[0]; High = $nv[1]; Med = $nv[2]; Low = $nv[3]; Confidence = 'unresolved' }
    }
    $distinct = $matches | Group-Object Key | ForEach-Object { $_.Group[0] }
    $best = $distinct | Sort-Object Cost | Select-Object -First 1
    $conf = if (@($distinct).Count -eq 1) { 'corrected' } else { 'ambiguous' }
    return [PSCustomObject]@{ Crit = $best.C; High = $best.H; Med = $best.M; Low = $best.L; Confidence = $conf }
}

function Parse-Dirty30Input {
    # Auto-detect input format and extract hostnames. Returns ArrayList of
    # PSCustomObject (Hostname, IP, Score, Crit, High, Med, Low, VulnConfidence).
    # Ported from ReportsTool_2.14.6.ps1:4615; bar parsing routes through
    # Resolve-Dirty30Severities to undo pdftotext digit-gluing.
    param([Parameter(Mandatory)][string]$Text)

    $hosts = New-Object System.Collections.ArrayList
    $seen  = @{}

    $firstLine = ($Text -split "`r?`n", 2)[0]
    $looksCsv  = ($firstLine -match ',') -and ($firstLine -match '(?i)host|netbios|dns|name|score|ip')
    if ($looksCsv) {
        try {
            $rows = $Text | ConvertFrom-Csv
            foreach ($row in $rows) {
                $hostname = ''; $ip = ''; $score = 0
                $crit = 0; $high = 0; $med = 0; $low = 0
                foreach ($p in $row.PSObject.Properties.Name) {
                    $v = "$($row.$p)".Trim()
                    if (-not $v) { continue }
                    if (-not $hostname -and $p -match '(?i)netbios') {
                        $hostname = (($v -split '\\')[-1]).Trim()
                    } elseif (-not $hostname -and $p -match '(?i)^(hostname|host|computer)$') {
                        $hostname = (($v -split '\\')[-1] -split '\.')[0].Trim()
                    } elseif (-not $hostname -and $p -match '(?i)^dns') {
                        $hostname = ($v -split '\.')[0].Trim()
                    } elseif ($p -match '(?i)^ip') {
                        $ip = $v
                    } elseif ($p -match '(?i)^score$') {
                        $n = 0; if ([int]::TryParse(($v -replace ',',''), [ref]$n)) { $score = $n }
                    } elseif ($p -match '(?i)^crit') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $crit = $n }
                    } elseif ($p -match '(?i)^high') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $high = $n }
                    } elseif ($p -match '(?i)^med') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $med = $n }
                    } elseif ($p -match '(?i)^low') {
                        $n = 0; if ([int]::TryParse($v, [ref]$n)) { $low = $n }
                    }
                }
                if ($hostname) {
                    $u = $hostname.ToUpper()
                    if (-not $seen.ContainsKey($u)) {
                        $seen[$u] = $true
                        [void]$hosts.Add([PSCustomObject]@{
                            Hostname = $u; IP = $ip; Score = $score
                            Crit = $crit; High = $high; Med = $med; Low = $low
                            VulnConfidence = 'asis'
                        })
                    }
                }
            }
        } catch {
        }
    }

    if ($hosts.Count -eq 0) {
        $domainPrefixes = @{
            'AREA52'     = $true; 'AFNOAPPS' = $true; 'USAF' = $true
            'AF'         = $true; 'MIL'       = $true; 'ELX'  = $true
            'LAKENHEATH' = $true; 'UNKNOWN'   = $true
        }

        $allLines = $Text -split "`r?`n"
        $ipPositions = @()
        for ($i = 0; $i -lt $allLines.Count; $i++) {
            if ($allLines[$i] -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b') {
                $ipPositions += $i
            }
        }

        $noiseRx = '(?i)^\s*(cpe:|ft:|>\s*Microsoft|>\s*Red Hat|Microsoft Windows|Windows\s+(?:11|10|Server|7|8)|Red Hat\s+Enterprise|Linux|enterprise(?:\s|$)|ise[~_]|ux:\d|x86_|x64-|2:\d|ARM\d|Server\s+20\d\d|IP Address|NetBIOS|DNS Name|OS CPE|UNCLASSIFIED|Top \d+ Worst|Score\s+Vulns|Dirty 30|Generated on|Tenable|Security Center|LAKENHEATH)\s*$|^\s*(Windows|Linux|ARM|ARM64|mil|Microsoft|Red Hat|enterprise)\s*$'

        # Relaxed: Score + at least one bar number (Crit); High/Med/Low
        # optional, so a 2-token tail like "190 316" (Tenable dropped the zero
        # Med/Low segments) still matches. Groups widened to {1,5} so a glued
        # token ("219","316") is captured whole, then un-glued against Score by
        # Resolve-Dirty30Severities below.
        $tailRx = [regex]'^\s*(?:((?=[A-Z0-9\-\.]*[A-Z])[A-Za-z0-9][A-Za-z0-9\-\.]{2,40})\s+)?([\d,]{1,7})\s+(\d{1,5})(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?\s*$'

        for ($bIdx = 0; $bIdx -lt $ipPositions.Count; $bIdx++) {
            $startLine = $ipPositions[$bIdx]
            $endLine   = if ($bIdx + 1 -lt $ipPositions.Count) { $ipPositions[$bIdx + 1] - 1 } else { $allLines.Count - 1 }
            $block     = $allLines[$startLine..$endLine]
            if ($block.Count -eq 0) { continue }

            $ip = ''
            if ($block[0] -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $ip = $Matches[1] }

            $score = 0; $crit = 0; $high = 0; $med = 0; $low = 0
            $vulnConfidence = 'asis'
            $tailIdx = -1
            $tailHostname = ''
            for ($i = $block.Count - 1; $i -ge 0; $i--) {
                $tm = $tailRx.Match($block[$i])
                if ($tm.Success) {
                    $n = 0
                    if ([int]::TryParse($tm.Groups[2].Value.Replace(',',''), [ref]$n)) { $score = $n }
                    # Collect the bar tokens (Crit/High/Med/Low) exactly as
                    # pdftotext emitted them - possibly glued or zero-collapsed -
                    # and let Resolve-Dirty30Severities reconcile them with Score.
                    $barTokens = New-Object System.Collections.ArrayList
                    foreach ($gi in 3, 4, 5, 6) { if ($tm.Groups[$gi].Success -and $tm.Groups[$gi].Value) { [void]$barTokens.Add($tm.Groups[$gi].Value) } }
                    $sev = Resolve-Dirty30Severities -Score $score -BarTokens ($barTokens.ToArray())
                    $crit = $sev.Crit; $high = $sev.High; $med = $sev.Med; $low = $sev.Low; $vulnConfidence = $sev.Confidence
                    if ($tm.Groups[1].Success) {
                        $tailHostname = $tm.Groups[1].Value
                        if ($tailHostname -match '\.') { $tailHostname = ($tailHostname -split '\.')[0] }
                        $tailHostname = $tailHostname.ToUpper()
                        if ($domainPrefixes.ContainsKey($tailHostname)) { $tailHostname = '' }
                    }
                    $tailIdx = $i
                    break
                }
            }

            $hostZone = New-Object System.Text.StringBuilder
            $upper = if ($tailIdx -ge 0) { $tailIdx - 1 } else { $block.Count - 1 }
            for ($i = 0; $i -le $upper; $i++) {
                $line = $block[$i]
                if ($i -eq 0) {
                    $line = $line -replace '^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*', ''
                }
                $trimmed = $line.Trim()
                if (-not $trimmed) { continue }
                if ($trimmed -match $noiseRx) { continue }
                [void]$hostZone.Append($trimmed)
            }
            $zoneText = $hostZone.ToString()

            $hostname = ''
            $nbMatches = [regex]::Matches($zoneText, '\\([A-Z0-9][A-Z0-9\-]{2,40})')
            if ($nbMatches.Count -gt 0) {
                $best = ''
                foreach ($m in $nbMatches) {
                    $cand = $m.Groups[1].Value
                    if ($cand -match '[A-Z]' -and $cand.Length -gt $best.Length) { $best = $cand }
                }
                $hostname = $best.ToUpper()
            }
            if (-not $hostname) {
                $dnsMatch = [regex]::Match($zoneText, '(?i)([a-z][a-z0-9\-]{2,40})\.[a-z][a-z0-9\-]*\.(?:afnoapps|usaf|af|mil|elx)')
                if ($dnsMatch.Success) { $hostname = $dnsMatch.Groups[1].Value.ToUpper() }
            }
            if (-not $hostname -and $tailHostname) { $hostname = $tailHostname }

            if (-not $hostname) { continue }
            if ($domainPrefixes.ContainsKey($hostname)) { continue }
            if ($hostname -notmatch '[A-Z]') { continue }
            if ($seen.ContainsKey($hostname)) { continue }

            $seen[$hostname] = $true
            [void]$hosts.Add([PSCustomObject]@{
                Hostname = $hostname; IP = $ip; Score = $score
                Crit = $crit; High = $high; Med = $med; Low = $low
                VulnConfidence = $vulnConfidence
            })
        }

        if ($hosts.Count -gt 0) { return $hosts }

        $Text = $Text -replace '\\[ \t]*\r?\n[ \t]*', '\'
        $Text = $Text -replace '(\.)[ \t]*\r?\n[ \t]*([a-z0-9])', '$1$2'

        $netbiosLineRx = [regex]'(?i)\\\s*([A-Z][A-Z0-9\-]{2,31})\b'
        $dnsLineRx     = [regex]'(?i)\b([a-z][a-z0-9\-]{2,31})\.[a-z][a-z0-9\-]*\.(?:afnoapps|usaf|af|mil|elx)\b'
        $tailRx2       = [regex]'^\s*(?:([A-Z][A-Z0-9\-]{2,31}|[a-z][a-z0-9\-]{2,31}(?:\.[a-z0-9\-\.]+)?)\s+)?([\d,]{1,7})\s+(\d{1,5})(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?(?:\s+(\d{1,5}))?\s*$'

        $lines = $Text -split "`r?`n"
        $pendingName = $null
        $pendingIP   = $null

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line.Trim() -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $pendingIP = $line.Trim()
                continue
            }
            $tail = $tailRx2.Match($line)
            if ($tail.Success) {
                $name = $pendingName
                if ($tail.Groups[1].Success) {
                    $tailName = $tail.Groups[1].Value
                    if ($tailName -match '\.') { $tailName = ($tailName -split '\.')[0] }
                    $tailName = $tailName.Trim().ToUpper()
                    if ($tailName -and -not $domainPrefixes.ContainsKey($tailName)) { $name = $tailName }
                }
                if ($name -and -not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    $score = 0; $null = [int]::TryParse($tail.Groups[2].Value.Replace(',',''), [ref]$score)
                    $barTokens = New-Object System.Collections.ArrayList
                    foreach ($gi in 3, 4, 5, 6) { if ($tail.Groups[$gi].Success -and $tail.Groups[$gi].Value) { [void]$barTokens.Add($tail.Groups[$gi].Value) } }
                    $sev = Resolve-Dirty30Severities -Score $score -BarTokens ($barTokens.ToArray())
                    [void]$hosts.Add([PSCustomObject]@{
                        Hostname = $name; IP = $pendingIP; Score = $score
                        Crit = $sev.Crit; High = $sev.High; Med = $sev.Med; Low = $sev.Low
                        VulnConfidence = $sev.Confidence
                    })
                }
                $pendingName = $null
                $pendingIP   = $null
                continue
            }
            $nb = $netbiosLineRx.Match($line)
            if ($nb.Success) {
                $candidate = $nb.Groups[1].Value.Trim().ToUpper()
                if (-not $domainPrefixes.ContainsKey($candidate)) { $pendingName = $candidate }
                continue
            }
            if (-not $pendingName) {
                $dn = $dnsLineRx.Match($line)
                if ($dn.Success) {
                    $candidate = $dn.Groups[1].Value.Trim().ToUpper()
                    if (-not $domainPrefixes.ContainsKey($candidate)) { $pendingName = $candidate }
                }
            }
        }

        if ($hosts.Count -eq 0) {
            foreach ($m in $netbiosLineRx.Matches($Text)) {
                $name = $m.Groups[1].Value.Trim().ToUpper()
                if ($domainPrefixes.ContainsKey($name)) { continue }
                if (-not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    [void]$hosts.Add([PSCustomObject]@{ Hostname = $name; IP = ''; Score = 0; Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis' })
                }
            }
            foreach ($m in $dnsLineRx.Matches($Text)) {
                $name = $m.Groups[1].Value.Trim().ToUpper()
                if ($domainPrefixes.ContainsKey($name)) { continue }
                if (-not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    [void]$hosts.Add([PSCustomObject]@{ Hostname = $name; IP = ''; Score = 0; Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis' })
                }
            }
            if ($hosts.Count -eq 0) {
                foreach ($line in ($Text -split "`r?`n")) {
                    $t = $line.Trim()
                    if ($t -match '^[A-Za-z][A-Za-z0-9\-]{2,31}$') {
                        $name = $t.ToUpper()
                        if (-not $seen.ContainsKey($name)) {
                            $seen[$name] = $true
                            [void]$hosts.Add([PSCustomObject]@{ Hostname = $name; IP = ''; Score = 0; Crit = 0; High = 0; Med = 0; Low = 0; VulnConfidence = 'asis' })
                        }
                    }
                }
            }
        }
    }

    return $hosts
}

function Get-Dirty30AdInfo {
    # Batched LDAP lookup. Returns hashtable indexed by uppercase hostname.
    # Ported from ReportsTool_2.14.5.ps1:4984 (ADSI empty-string bind).
    # CancelCheck (optional) is polled between 50-name batches and between
    # per-host fallback iterations; on cancel an abandon audit goes out via
    # Send and unqueried names stay absent from the result (not 'Not Found').
    param(
        [Parameter(Mandatory)][string[]]$Hostnames,
        [scriptblock]$CancelCheck,
        [scriptblock]$Send
    )

    $results = @{}
    $now = Get-Date
    $staleThreshold = $now.AddDays(-90)

    try {
        $root     = [ADSI]''
        $searcher = [ADSISEARCHER]$root
        $searcher.PageSize = 15000
    } catch {
        return $results
    }

    $clean = @($Hostnames | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ } | Select-Object -Unique)
    $foundSet = @{}

    $buildResult = {
        param($entry, $staleThreshold)
        $name = "$($entry.Properties['name'][0])".ToUpper()
        $dn   = "$($entry.Properties['distinguishedname'][0])"
        $os   = if ($entry.Properties['operatingsystem'].Count -gt 0) { "$($entry.Properties['operatingsystem'][0])" } else { '' }

        $ouPath  = ($dn -split ',', 2)[1]
        $ouParts = $ouPath -split ','
        $ouNames = @()
        foreach ($part in $ouParts) {
            if ($part -match '^OU=(.+)$') { $ouNames += $Matches[1] }
        }
        $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { '(Root)' }
        $ouSquadron = $parentOU
        $generic = @('Workstations','Computers','Servers','Desktops','Laptops','Devices','Resources','Members')
        if ($ouNames.Count -ge 2 -and $generic -contains $parentOU) {
            $ouSquadron = $ouNames[1]
        }
        $reversed = @($ouNames); [array]::Reverse($reversed)
        $ouChain = if ($reversed.Count -gt 0) { $reversed -join ' > ' } else { '(Root)' }

        $locRaw = ''
        if ($entry.Properties['location'].Count -gt 0) { $locRaw = "$($entry.Properties['location'][0])" }
        $orgFromLoc = ''
        if ($locRaw -and $locRaw -match 'ORGANIZATION:\s*([^;]+)') {
            $orgFromLoc = $Matches[1].Trim()
        }
        $squadron = if ($orgFromLoc) { $orgFromLoc } else { $ouSquadron }

        if (-not $orgFromLoc -and $entry.Properties['department'].Count -gt 0) {
            $dep = "$($entry.Properties['department'][0])".Trim()
            if ($dep) { $squadron = $dep }
        }

        $lastLogon = 'Never'; $isStale = $true
        try {
            if ($entry.Properties['lastlogontimestamp'].Count -gt 0) {
                $tsVal = $entry.Properties['lastlogontimestamp'][0]
                if ($tsVal -gt 0) {
                    $lld = [DateTime]::FromFileTime([Int64]$tsVal)
                    $lastLogon = $lld.ToString('yyyy-MM-dd HH:mm')
                    if ($lld -ge $staleThreshold) { $isStale = $false }
                }
            }
        } catch {}

        return @{
            Key = $name
            Row = [PSCustomObject]@{
                Hostname     = $name
                DN           = $dn
                OS           = $os
                Squadron     = $squadron
                ParentOU     = $parentOU
                OUChain      = $ouChain
                LocationInfo = $locRaw
                LastLogon    = $lastLogon
                IsStale      = $isStale
                Status       = if ($isStale) { 'Stale' } else { 'Active' }
                LastUser     = ''
            }
        }
    }

    $batchSize = 50
    $cancelled = $false
    $processed = @{}   # names whose LDAP query actually ran (batch or fallback)
    for ($i = 0; $i -lt $clean.Count; $i += $batchSize) {
        if ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true; break }
        $batch = $clean[$i..[Math]::Min(($i + $batchSize - 1), ($clean.Count - 1))]
        $filterParts = ''
        foreach ($name in $batch) {
            $esc = $name -replace '\\','\5c' -replace '\*','\2a' -replace '\(','\28' -replace '\)','\29' -replace '/','\2f' -replace [char]0,'\00'
            $filterParts += "(name=$esc)"
        }
        $searcher.Filter = if ($batch.Count -eq 1) {
            "(&(objectCategory=Computer)$filterParts)"
        } else {
            "(&(objectCategory=Computer)(|$filterParts))"
        }
        try {
            $adResults = $searcher.FindAll()
            foreach ($entry in $adResults) {
                $built = & $buildResult $entry $staleThreshold
                $results[$built.Key] = $built.Row
                $foundSet[$built.Key] = $true
            }
            foreach ($name in $batch) { $processed[$name] = $true }
        } catch {
            foreach ($name in $batch) {
                if ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true; break }
                $searcher.Filter = "(&(objectCategory=Computer)(name=$(($name -replace '\\','\5c' -replace '\*','\2a' -replace '\(','\28' -replace '\)','\29' -replace [char]0,'\00'))))"
                try {
                    $fb = $searcher.FindAll()
                    foreach ($entry in $fb) {
                        $built = & $buildResult $entry $staleThreshold
                        $results[$built.Key] = $built.Row
                        $foundSet[$built.Key] = $true
                    }
                } catch {
                }
                $processed[$name] = $true
            }
            if ($cancelled) { break }
        }
    }

    if ($cancelled) {
        $unresolved = 0
        foreach ($name in $clean) { if (-not $processed.ContainsKey($name)) { $unresolved++ } }
        if ($Send) {
            & $Send @{ type='audit'; action='TouchHost'; target="Dirty30 LDAP lookup ($($clean.Count) names)"; result='Failure'; itemCount=0; detail="cancelled by operator; $unresolved of $($clean.Count) name(s) left unresolved" }
            & $Send @{ type='log'; level='warn'; text="LDAP lookup cancelled by operator; $unresolved name(s) left unresolved." }
        }
    }

    foreach ($name in $clean) {
        # Only names whose query actually ran can be declared Not Found; a
        # cancelled run leaves the rest absent so they read Unknown upstream.
        if ($processed.ContainsKey($name) -and -not $foundSet.ContainsKey($name)) {
            $results[$name] = [PSCustomObject]@{
                Hostname  = $name; DN = ''; OS = ''; LocationInfo = ''
                Squadron  = 'UNKNOWN'; ParentOU = 'N/A'
                OUChain   = 'no matching computer object'
                LastLogon = '-'; IsStale = $false
                Status    = 'Not Found'; LastUser = '-'
            }
        }
    }
    return $results
}

# Per-host worker for the parallel last-logged-on-user probe. Lifted from
# Get-Dirty30LastLoggedOnUser:5150 (the inner scriptblock). The harvest loop
# in Invoke-JanetToolAction adds one of these per host to the RunspacePool.
$script:Dirty30LastUserWorker = {
    param($Target,$TimeoutSec,$Cred)
    $subKey  = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
    $regPath = "HKLM:\$subKey"
    $valName = 'LastLoggedOnUser'

    # Reachability gate (TCP-only, AFNET-safe): reachable if a TCP probe to WinRM
    # HTTP (5985), WinRM HTTPS (5986), or SMB (445) connects. Never ICMP - AFNET
    # blocks it, and the user can only be read over WinRM / CIM-WSMan, so an
    # ICMP-only host yields nothing anyway. Short per-port timeout (700-1500 ms) so
    # a filtered host fails fast. $useSsl tracks whether ONLY 5986 answered, so the
    # WinRM/CIM calls below auto-switch to -UseSSL (5985 stays preferred when both
    # are open).
    $reachable = $false; $useSsl = $false
    $tcpTimeout = [Math]::Max(700, [Math]::Min(1500, [int]$TimeoutSec * 1000))
    foreach ($port in 5985, 5986, 445) {
        $tcp = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($Target, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($tcpTimeout) -and $tcp.Connected) { $reachable = $true; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally {
            if ($tcp) { try { $tcp.Close() } catch {} }
        }
        if ($reachable) { break }
    }
    if (-not $reachable) { return @{ Host = $Target; User = '- offline -' } }

    # Preferred path: WinRM / Invoke-Command with the operator credential when one
    # was supplied (falls back to the calling identity when not). -UseSSL only when
    # the host answered ONLY on 5986 (self-signed WinRM HTTPS is common on AFNET, so
    # skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    try {
        $icmArgs = @{
            ComputerName = $Target
            ScriptBlock  = { param($kp,$vn) try { (Get-ItemProperty -Path $kp -Name $vn -ErrorAction Stop).$vn } catch { '' } }
            ArgumentList = @($regPath, $valName)
            ErrorAction  = 'Stop'
        }
        if ($Cred) { $icmArgs['Credential'] = $Cred }
        if ($useSsl) { $icmArgs['UseSSL'] = $true; $icmArgs['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck }
        $val = Invoke-Command @icmArgs
        if ($val -and -not [string]::IsNullOrWhiteSpace([string]$val)) {
            return @{ Host = $Target; User = [string]$val }
        }
        # WinRM responded but the value was empty/missing.
        return @{ Host = $Target; User = '- no value -' }
    } catch {}

    # Fall back to CIM-over-WSMan (StdRegProv) with the same credential. RPC/DCOM
    # is commonly filtered on AFNET; WinRM-over-WSMan is the supported transport.
    # Same -UseSsl auto-switch as the Invoke-Command path above.
    $cim = $null
    try {
        # -UseSsl and -Protocol live in MUTUALLY EXCLUSIVE New-CimSessionOption parameter sets
        # (combining them throws "Unable to resolve the parameter set name"), so BRANCH: -UseSsl
        # already implies WSMan (skip CA/CN for self-signed 5986); else the explicit WSMan set.
        $sopt = if ($useSsl) { New-CimSessionOption -UseSsl -SkipCACheck -SkipCNCheck } else { New-CimSessionOption -Protocol Wsman }
        $csParams = @{ ComputerName = $Target; SessionOption = $sopt; OperationTimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
        if ($Cred) { $csParams['Credential'] = $Cred }
        $cim = New-CimSession @csParams
        $HKLM = [uint32]2147483650
        $cimArgs = @{ hDefKey = $HKLM; sSubKeyName = $subKey; sValueName = $valName }
        $r = Invoke-CimMethod -CimSession $cim -Namespace 'root\default' -ClassName 'StdRegProv' -MethodName 'GetStringValue' -Arguments $cimArgs -ErrorAction Stop
        if ($r.ReturnValue -eq 0 -and $r.sValue) { return @{ Host = $Target; User = [string]$r.sValue } }
        return @{ Host = $Target; User = '- no value -' }
    } catch {
        $m = $_.Exception.Message
        if ($m -match 'RPC|unavailable|not found|denied|0x8|WinRM|WS-?Man|cannot connect') { return @{ Host = $Target; User = '- offline -' } }
        return @{ Host = $Target; User = '- error -' }
    } finally {
        if ($cim) { try { Remove-CimSession $cim -ErrorAction SilentlyContinue } catch {} }
    }
}

# Per-host worker for the parallel target-IP resolve (DNS + ping). Lifted from
# Invoke-AsyncIpResolve:6810-6827 (the inner scriptblock). The resolve-target-ips
# harvest loop adds one of these per host to its RunspacePool.
$script:TargetIpResolveWorker = {
    param($Target, $TimeoutMs)
    $r = @{ Host = $Target; IP = ''; Online = $false; Latency = -1; ResolveOk = $false }
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Target) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($addrs) { $r.IP = $addrs.IPAddressToString; $r.ResolveOk = $true }
    } catch {}
    # ICMP leg: records round-trip latency when it replies.
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Target, $TimeoutMs)
        if ($reply -and $reply.Status -eq 'Success') {
            $r.Online = $true
            $r.Latency = [int]$reply.RoundtripTime
            if ($reply.Address) { $r.IP = $reply.Address.IPAddressToString; $r.ResolveOk = $true }
        }
    } catch {}
    # Reachability UNION (AFNET-safe): a host that blocks ICMP is still reachable
    # if a TCP probe to WinRM (5985) or SMB (445) connects. This only ever ADDS to
    # the ICMP result (never regresses) and never depends on ICMP. Short per-port
    # timeout (700-1500 ms) so a filtered port cannot stall the worker.
    if (-not $r.Online) {
        $tcpTimeout = [Math]::Max(700, [Math]::Min(1500, [int]$TimeoutMs))
        foreach ($port in 5985, 5986, 445) {   # WinRM HTTP, WinRM HTTPS, then SMB - reachability union only (no session)
            $tcp = $null
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($Target, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne($tcpTimeout) -and $tcp.Connected) { $r.Online = $true }
            } catch {} finally {
                if ($tcp) { try { $tcp.Close() } catch {} }
            }
            if ($r.Online) { break }
        }
    }
    return $r
}

# ---- Dirty 30 HTML / CSV render ------------------------------------------

function Render-Dirty30Html {
    # Build a single self-contained HTML string from the current Dirty 30
    # session state. Ported from ReportsTool_2.14.5.ps1:5245.
    $totalParsed = $script:Dirty30Hosts.Count
    $activeCount = 0; $staleCount = 0; $notFoundCount = 0
    $sqCounts = @{}
    foreach ($h in $script:Dirty30Hosts) {
        $ad = $script:Dirty30AdResults[$h.Hostname]
        if (-not $ad) { continue }
        switch ($ad.Status) {
            'Active'    { $activeCount++ }
            'Stale'     { $staleCount++ }
            'Not Found' { $notFoundCount++ }
        }
        if ($ad.Status -ne 'Not Found') {
            if (-not $sqCounts.ContainsKey($ad.Squadron)) { $sqCounts[$ad.Squadron] = 0 }
            $sqCounts[$ad.Squadron]++
        }
    }
    $foundCount = $totalParsed - $notFoundCount

    $topName = '-'; $topCount = 0
    foreach ($k in $sqCounts.Keys) { if ($sqCounts[$k] -gt $topCount) { $topName = $k; $topCount = $sqCounts[$k] } }
    $topSub = if ($foundCount -gt 0 -and $topCount -gt 0) {
        $pct = [Math]::Round(($topCount / $foundCount) * 100, 1)
        "$topCount of $foundCount found ($pct%)"
    } else { '' }

    $chipsHtml = New-Object System.Text.StringBuilder
    if ($sqCounts.Count -gt 0) {
        $sorted = $sqCounts.GetEnumerator() | Sort-Object Value -Descending
        foreach ($kv in $sorted) {
            $pct = if ($foundCount -gt 0) { [Math]::Round(($kv.Value / $foundCount) * 100, 1) } else { 0 }
            $name = ConvertTo-HtmlEscaped $kv.Key
            [void]$chipsHtml.Append("<div class=`"squad-chip`"><span class=`"name`">$name</span><span class=`"count`">$($kv.Value)</span><span class=`"frac`">$pct%</span></div>`n")
        }
    }
    if ($notFoundCount -gt 0) {
        [void]$chipsHtml.Append("<div class=`"squad-chip`" style=`"opacity: 0.6; border-color: var(--danger);`"><span class=`"name`" style=`"color: var(--danger);`">UNKNOWN</span><span class=`"count`">$notFoundCount</span><span class=`"frac`">Not Found</span></div>`n")
    }

    $rowsHtml = New-Object System.Text.StringBuilder
    foreach ($h in $script:Dirty30Hosts) {
        $ad = $script:Dirty30AdResults[$h.Hostname]
        $vulnStr = if ($h.Score -gt 0 -or $h.Crit -gt 0 -or $h.High -gt 0) {
            "<span class=`"c`">$($h.Crit)</span> / <span class=`"h`">$($h.High)</span> / <span class=`"m`">$($h.Med)</span> / <span class=`"l`">$($h.Low)</span>"
        } else { '-' }
        # Tenable glued the Crit/High segments and Score can't split them (both
        # weigh 10); flag the best-guess split so the operator verifies it.
        if ($h.PSObject.Properties['VulnConfidence'] -and $h.VulnConfidence -eq 'ambiguous') {
            $vulnStr += '<sup title="Critical-vs-High split inferred from the Score (Tenable bar glued the segments) - verify against the PDF bar colors." style="color:#e8a23d;cursor:help;font-weight:700;">*</sup>'
        }
        $scoreStr = if ($h.Score -gt 0) { $h.Score.ToString('N0') } else { '-' }
        $lastAd = if ($ad) { ConvertTo-HtmlEscaped $ad.LastLogon } else { '' }
        $lastUserRaw = if ($script:Dirty30LastUserMap.ContainsKey($h.Hostname)) { $script:Dirty30LastUserMap[$h.Hostname] } elseif ($ad) { $ad.LastUser } else { '' }
        $lastUserEsc = ConvertTo-HtmlEscaped $lastUserRaw
        $lastUserClass = if ($lastUserRaw -match '^-' -or [string]::IsNullOrWhiteSpace($lastUserRaw)) { 'lastuser unknown' } else { 'lastuser' }
        $sq = if ($ad) { ConvertTo-HtmlEscaped $ad.Squadron } else { '' }
        $locValue = if ($ad -and $ad.PSObject.Properties['LocationInfo'] -and $ad.LocationInfo) { $ad.LocationInfo } elseif ($ad) { $ad.OUChain } else { '' }
        $ou = ConvertTo-HtmlEscaped $locValue
        $st = if ($ad) { $ad.Status } else { 'Unknown' }
        $badgeClass = switch ($st) {
            'Active'    { 'active' }
            'Stale'     { 'stale' }
            'Not Found' { 'notfound' }
            default     { 'active' }
        }
        $lastAdClass = if ($st -eq 'Stale') { 'lastad stale' } else { 'lastad' }
        $sqClass = if ($st -eq 'Not Found') { 'squad nf' } else { 'squad' }
        $rowOpacity = if ($st -eq 'Not Found') { 'style="opacity: 0.78;"' } else { '' }
        $hostname = ConvertTo-HtmlEscaped $h.Hostname

        [void]$rowsHtml.Append(@"
<tr $rowOpacity>
  <td class="host">$hostname</td>
  <td class="score">$scoreStr</td>
  <td class="vulns">$vulnStr</td>
  <td class="$lastAdClass">$lastAd</td>
  <td class="$lastUserClass">$lastUserEsc</td>
  <td class="$sqClass">$sq</td>
  <td class="ou">$ou</td>
  <td class="status"><span class="badge $badgeClass">$st</span></td>
</tr>
"@)
    }
    if ($totalParsed -eq 0) {
        [void]$rowsHtml.Append('<tr><td colspan="8" style="text-align:center; padding:20px; color: var(--text-faint); font-style: italic;">No hosts loaded.</td></tr>')
    }

    $sourceLabel = ConvertTo-HtmlEscaped ($script:Dirty30SourceLabel)
    if (-not $sourceLabel) { $sourceLabel = '(no source loaded)' }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $operator = ConvertTo-HtmlEscaped (Get-ReportsCleanUser)
    $machine  = ConvertTo-HtmlEscaped $env:COMPUTERNAME

    $chipsBlock = $chipsHtml.ToString()
    $rowsBlock  = $rowsHtml.ToString()

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET - Dirty 30 Triage - $generated</title>
<style>
$(Get-JanetReportCSS)
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 60px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 20px; font-weight: 600; color: var(--gold); }
  .topbar .subtitle { color: var(--text-dim); font-size: 13px; }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .topbar .meta .gen { color: var(--cyan); }
  .content { padding: 20px 28px; max-width: 1600px; margin: 0 auto; }
  .page-title { font-size: 26px; color: var(--gold); font-weight: 600; margin: 0 0 4px 0; }
  .page-subtitle { color: var(--text-dim); font-size: 13px; margin: 0 0 14px 0; }
  .source { background: var(--panel); border: 1px solid var(--border); padding: 11px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 18px; font-family: Consolas, monospace; }
  .source .file { color: var(--cyan); font-weight: 600; }
  .summary-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 18px; }
  .summary-tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .summary-tile.green { border-top-color: var(--success); }
  .summary-tile.gold { border-top-color: var(--gold); }
  .summary-tile.danger { border-top-color: var(--danger); }
  .summary-tile.warning { border-top-color: var(--warning); }
  .summary-tile .lbl { font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .summary-tile .val { font-size: 40px; font-weight: 800; color: var(--text); margin-top: 8px; line-height: 1.1; }
  .summary-tile.green .val { color: var(--success); }
  .summary-tile.warning .val { color: var(--warning); }
  .summary-tile.danger .val { color: var(--danger); }
  .summary-tile.gold .val { color: var(--gold); font-size: 28px; }
  .summary-tile .sub { font-size: 13px; color: var(--text-dim); margin-top: 6px; }
  .squadron-strip { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--gold); padding: 14px 16px; margin-bottom: 18px; border-radius: 3px; }
  .squadron-strip h3 { margin: 0 0 10px 0; font-size: 13px; color: var(--gold); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
  .squadron-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .squad-chip { background: var(--input); border: 1px solid var(--border); padding: 8px 14px; border-radius: 2px; font-size: 13px; }
  .squad-chip .name { color: var(--gold); font-weight: 700; margin-right: 8px; }
  .squad-chip .count { color: var(--text); font-weight: 700; font-size: 15px; }
  .squad-chip .frac { color: var(--text-dim); font-size: 12px; margin-left: 6px; }
  table.grid { width: 100%; border-collapse: collapse; background: var(--panel); font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); font-weight: 700; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; padding: 10px 12px; text-align: left; border-bottom: 2px solid var(--border); position: sticky; top: 0; z-index: 2; }
  table.grid td { padding: 12px 14px; border-bottom: 1px solid var(--border); color: var(--text); vertical-align: middle; }
  table.grid tr:hover td { background: rgba(140,100,220,0.06); }
  td.host { font-family: Consolas, monospace; color: var(--cyan); font-weight: 700; font-size: 22px; letter-spacing: 0.3px; }
  td.score { font-weight: 800; color: var(--gold); font-size: 15px; }
  td.vulns { font-family: Consolas, monospace; font-size: 13px; }
  td.vulns .c { color: var(--danger); font-weight: 700; }
  td.vulns .h { color: var(--orange); font-weight: 700; }
  td.vulns .m { color: var(--warning); }
  td.vulns .l { color: var(--cyan); }
  td.squad { color: var(--gold); font-weight: 700; font-size: 13.5px; }
  td.squad.nf { color: var(--danger); }
  td.lastad { font-family: Consolas, monospace; font-size: 12.5px; }
  td.lastad.stale { color: var(--warning); }
  td.lastuser { font-family: Consolas, monospace; color: var(--accent); font-size: 12.5px; font-weight: 600; }
  td.lastuser.unknown { color: var(--text-dim); font-style: italic; }
  td.ou { font-size: 12px; color: var(--text-dim); font-family: Consolas, monospace; max-width: 320px; word-wrap: break-word; }
  td.status .badge { padding: 3px 10px; border-radius: 10px; font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; }
  td.status .badge.active   { background: rgba(92,198,120,0.18); color: var(--success); }
  td.status .badge.stale    { background: rgba(245,180,70,0.18); color: var(--warning); }
  td.status .badge.notfound { background: rgba(220,92,100,0.18); color: var(--danger); }
  .filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; padding: 10px 14px; background: var(--panel); border: 1px solid var(--border); border-radius: 3px; }
  .filter-bar .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-right: 6px; font-weight: 600; }
  .pill-btn { background: var(--input); color: var(--text-dim); border: 1px solid var(--border); padding: 6px 14px; border-radius: 12px; cursor: pointer; font-size: 12.5px; font-family: inherit; font-weight: 600; }
  .pill-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
  .pill-btn.warning.active { background: var(--warning); border-color: var(--warning); color: black; }
  .pill-btn.danger.active { background: var(--danger); border-color: var(--danger); color: white; }
  .filter-bar .search { margin-left: auto; }
  .filter-bar input.search { background: var(--input); color: var(--text); border: 1px solid var(--border); padding: 7px 12px; border-radius: 2px; font-size: 13px; width: 260px; font-family: inherit; }
  .footer { margin-top: 18px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="topbar">
  <div>
    <div class="title">J.A.N.E.T - Dirty 30 Triage</div>
    <div class="subtitle">Joint Administration and Network Execution Toolkit - ReportsTool 2.14.5</div>
  </div>
  <div class="grow"></div>
  <div class="meta">
    <div>Generated <span class="gen">$generated</span></div>
    <div>by $operator on $machine</div>
  </div>
</div>
<div class="content">
  <h1 class="page-title">DIRTY 30 TRIAGE</h1>
  <p class="page-subtitle">
    Top vulnerable hosts cross-referenced with Active Directory - squadron, last AD logon, stale detection (&gt; 90 days), and (where probed) the last interactive user.
  </p>
  <div class="source">Source: <span class="file">$sourceLabel</span></div>
  <div class="summary-strip">
    <div class="summary-tile">
      <div class="lbl">Hosts Parsed</div>
      <div class="val">$totalParsed</div>
      <div class="sub">from source</div>
    </div>
    <div class="summary-tile green">
      <div class="lbl">AD: Active</div>
      <div class="val">$activeCount</div>
      <div class="sub">logon &lt;= 90 days</div>
    </div>
    <div class="summary-tile warning">
      <div class="lbl">AD: Stale</div>
      <div class="val">$staleCount</div>
      <div class="sub">no logon &gt; 90 days</div>
    </div>
    <div class="summary-tile danger">
      <div class="lbl">AD: Not Found</div>
      <div class="val">$notFoundCount</div>
      <div class="sub">no matching computer object</div>
    </div>
    <div class="summary-tile gold">
      <div class="lbl">Top Squadron</div>
      <div class="val">$(ConvertTo-HtmlEscaped $topName)</div>
      <div class="sub">$(ConvertTo-HtmlEscaped $topSub)</div>
    </div>
  </div>
  <div class="squadron-strip">
    <h3>Hosts by Squadron / OU</h3>
    <div class="squadron-row">
$chipsBlock
    </div>
  </div>
  <div class="filter-bar">
    <span class="lbl">View</span>
    <button class="pill-btn active" data-filter="all">All ($totalParsed)</button>
    <button class="pill-btn warning" data-filter="stale">Stale ($staleCount)</button>
    <button class="pill-btn danger" data-filter="notfound">Not Found ($notFoundCount)</button>
    <div class="search"><input class="search" id="searchBox" type="text" placeholder="Filter by hostname / squadron / OU..." /></div>
  </div>
  <table class="grid" id="hostGrid">
    <thead>
      <tr>
        <th>Hostname</th>
        <th style="width:60px;">Score</th>
        <th style="width:130px;">Vulns (C/H/M/L)</th>
        <th style="width:120px;">Last AD Logon</th>
        <th style="width:160px;">Last User</th>
        <th style="width:90px;">Squadron</th>
        <th>OU / Location</th>
        <th style="width:90px;">Status</th>
      </tr>
    </thead>
    <tbody id="hostBody">
$rowsBlock
    </tbody>
  </table>
  <div class="footer">
    Self-contained snapshot. To refresh, re-run the AD lookup in JANET Web Reports and re-export.
  </div>
</div>
<script>
  var rows = Array.prototype.slice.call(document.querySelectorAll('#hostBody tr'));
  var currentFilter = 'all';
  var pills = document.querySelectorAll('.pill-btn');
  pills.forEach(function (p) {
    p.addEventListener('click', function () {
      pills.forEach(function (x) { x.classList.remove('active'); });
      p.classList.add('active');
      currentFilter = p.getAttribute('data-filter');
      applyFilters();
    });
  });
  document.getElementById('searchBox').addEventListener('input', applyFilters);
  function applyFilters() {
    var q = document.getElementById('searchBox').value.toLowerCase().trim();
    rows.forEach(function (r) {
      var badge = r.querySelector('.badge');
      var status = badge ? badge.textContent.toLowerCase() : '';
      var passFilter = true;
      if (currentFilter === 'stale')    { passFilter = status === 'stale'; }
      if (currentFilter === 'notfound') { passFilter = status === 'not found'; }
      var passSearch = true;
      if (q) { passSearch = r.textContent.toLowerCase().indexOf(q) !== -1; }
      r.style.display = (passFilter && passSearch) ? '' : 'none';
    });
  }
</script>
</body>
</html>
"@
    return $html
}

function Export-Dirty30CsvText {
    # CSV export string of the merged Dirty 30 + AD + probe data.
    $lines = New-Object System.Collections.ArrayList
    # Neutralize spreadsheet formula injection via the canonical
    # ConvertTo-ReportsCsvCell (guard + RFC-4180 quote-when-needed).
    # audit 2026-07-23: the hand-rolled guard + per-cell quote-doubling collapsed
    # onto the helper. Strict improvement: Squadron / Status / Last AD Logon
    # previously skipped the quote-doubling entirely, so an embedded " could
    # corrupt the row; the helper doubles quotes on every cell. Cells with no
    # comma/quote/newline are no longer force-quoted - the parsed CSV is unchanged.
    [void]$lines.Add("# Dirty 30 Triage - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $(Get-ReportsCleanUser) on $env:COMPUTERNAME")
    if ($script:Dirty30SourceLabel) { [void]$lines.Add("# Source: $($script:Dirty30SourceLabel)") }
    [void]$lines.Add('')
    [void]$lines.Add('"Hostname","IP","Score","Crit","High","Med","Low","Last AD Logon","Last User","Squadron","Location Info","OU Chain","Status","Notes"')
    foreach ($d30h in $script:Dirty30Hosts) {
        $ad = $script:Dirty30AdResults[$d30h.Hostname]
        $lastUser = if ($script:Dirty30LastUserMap.ContainsKey($d30h.Hostname)) { $script:Dirty30LastUserMap[$d30h.Hostname] } elseif ($ad) { $ad.LastUser } else { '' }
        $lastUser = ConvertTo-ReportsCsvCell $lastUser
        $sq = ConvertTo-ReportsCsvCell $(if ($ad) { $ad.Squadron } else { '?' })
        $ou = ConvertTo-ReportsCsvCell $(if ($ad) { $ad.OUChain } else { '' })
        $loc = ConvertTo-ReportsCsvCell $(if ($ad -and $ad.PSObject.Properties['LocationInfo']) { $ad.LocationInfo } else { '' })
        $st = ConvertTo-ReportsCsvCell $(if ($ad) { $ad.Status } else { 'Unknown' })
        $ll = ConvertTo-ReportsCsvCell $(if ($ad) { $ad.LastLogon } else { '' })
        $hn = ConvertTo-ReportsCsvCell $d30h.Hostname
        $ip = ConvertTo-ReportsCsvCell $d30h.IP
        [void]$lines.Add("$hn,$ip,$($d30h.Score),$($d30h.Crit),$($d30h.High),$($d30h.Med),$($d30h.Low),$ll,$lastUser,$sq,$loc,$ou,$st,")
    }
    return ($lines -join "`r`n")
}

# ---- Weekly + CORA HTML render (structured brief) ------------------------

function Render-WeeklyExportHtml {
    # Build a self-contained HTML weekly brief from the parsed weeks. The
    # original WinForms renderer (ReportsTool_2.14.5.ps1:4167) produced an
    # enclave-toggled, multi-card layout with SVG charts; this reproduces the
    # data faithfully in a clean projector-ready brief (per-week cards, metric
    # tiles, MAJCOM + category + PMO owner roll-ups). See limitations.
    param([string]$EnclaveFilter)

    $weeks = @($script:AcasCalcWeeks | Where-Object {
        [string]::IsNullOrWhiteSpace($EnclaveFilter) -or $_.Enclave -eq $EnclaveFilter
    })
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $src = ConvertTo-HtmlEscaped ($script:AcasCalcSourceFile)
    if (-not $src) { $src = '(no workbook parsed)' }

    $cards = New-Object System.Text.StringBuilder
    # Group by enclave (parse order: NIPR then SIPR) so each enclave gets its
    # month-summary strip ahead of its week cards (desktop 4181-4214).
    $enclaveOrder = New-Object System.Collections.ArrayList
    foreach ($w in $weeks) { if (-not $enclaveOrder.Contains($w.Enclave)) { [void]$enclaveOrder.Add($w.Enclave) } }
    foreach ($enc in $enclaveOrder) {
        $encWeeks = @($weeks | Where-Object { $_.Enclave -eq $enc })

        # Month summary aggregates. The month AR % values are recomputed from
        # the SUMMED Good/Bad across the weeks - never an average of the
        # weekly percentages (desktop 4181-4206).
        $monthGood = 0; $monthBad = 0; $monthVulns = 0
        $monthCrit = 0; $monthHigh = 0; $monthMed = 0; $monthLow = 0
        $monthMajVulns = 0; $bestMajAr = [double]::NaN
        $woGood = 0; $woBad = 0
        foreach ($w in $encWeeks) {
            if ($w.InHouseTotals) {
                $monthGood  += $w.InHouseTotals.Good
                $monthBad   += $w.InHouseTotals.Bad
                $monthVulns += $w.InHouseTotals.TotalVulns
                $monthCrit  += $w.InHouseTotals.Crit; $monthHigh += $w.InHouseTotals.High
                $monthMed   += $w.InHouseTotals.Med;  $monthLow  += $w.InHouseTotals.Low
            }
            if ($w.MajcomTotals) {
                $monthMajVulns += $w.MajcomTotals.TotalVulns
                if (-not [double]::IsNaN($w.MajcomTotals.ArPct)) {
                    if ([double]::IsNaN($bestMajAr) -or $w.MajcomTotals.ArPct -gt $bestMajAr) {
                        $bestMajAr = $w.MajcomTotals.ArPct
                    }
                }
            }
            $wo = Get-WeeklyArWithoutPmo -Week $w
            $woGood += $wo.Good; $woBad += $wo.Bad
        }
        $monthAr = if (($monthGood + $monthBad) -gt 0) { [Math]::Round(($monthGood / ($monthGood + $monthBad)) * 100, 2) } else { [double]::NaN }
        $woAr    = if (($woGood + $woBad) -gt 0)       { [Math]::Round(($woGood / ($woGood + $woBad)) * 100, 2) } else { [double]::NaN }

        [void]$cards.Append("<div class=`"month-strip`">`n")
        [void]$cards.Append("  <div class=`"month-tile`"><div class=`"label`">$enc Total Vulns (Month)</div><div class=`"value`">$(Format-AcasNumber $monthVulns)</div><div class=`"sub`">CRIT $monthCrit &middot; HIGH $monthHigh &middot; MED $monthMed &middot; LOW $monthLow</div></div>`n")
        [void]$cards.Append("  <div class=`"month-tile green`"><div class=`"label`">AR % w/ PMO (Month)</div><div class=`"value`">$(Format-AcasPercent $monthAr)</div><div class=`"sub`">G $(Format-AcasNumber $monthGood) &middot; B $(Format-AcasNumber $monthBad)</div></div>`n")
        [void]$cards.Append("  <div class=`"month-tile cyan`"><div class=`"label`">AR % w/o PMO (Month)</div><div class=`"value`">$(Format-AcasPercent $woAr)</div><div class=`"sub`">G $(Format-AcasNumber $woGood) &middot; B $(Format-AcasNumber $woBad)</div></div>`n")
        [void]$cards.Append("  <div class=`"month-tile gold`"><div class=`"label`">MAJCOM Total Vulns</div><div class=`"value`">$(Format-AcasNumber $monthMajVulns)</div><div class=`"sub`">Best week AR: $(Format-AcasPercent $bestMajAr)</div></div>`n")
        [void]$cards.Append("</div>`n")

        foreach ($w in $encWeeks) {
        $arNoPmo = Get-WeeklyArWithoutPmo -Week $w
        $cats    = Get-WeeklyCategoryMetrics -Week $w
        $owners  = Get-WeeklyPmoOwnerMetrics -Week $w
        $mj = $w.MajcomTotals
        $ih = $w.InHouseTotals
        $staleBadge = if ($w.Stale) { "<span class=`"stale`">STALE DATA - verify before publishing</span>" } else { '' }

        $mjVulns = if ($mj) { Format-AcasNumber $mj.TotalVulns } else { 'N/A' }
        $mjVph   = if ($mj) { Format-AcasNumber $mj.Vph 'N2' } else { 'N/A' }
        $mjAr    = if ($mj) { Format-AcasPercent $mj.ArPct } else { 'N/A' }
        $ihVulns = if ($ih) { Format-AcasNumber $ih.TotalVulns } else { 'N/A' }
        # In-House VPH (Base) tile - operator request, desktop v2.14.2 (4259).
        $ihVph   = if ($ih) { Format-AcasNumber $ih.Vph '0.00' } else { 'N/A' }
        $ihAr    = if ($ih) { Format-AcasPercent $ih.ArPct } else { 'N/A' }
        $arNoPmoStr = Format-AcasPercent $arNoPmo.ArPct

        $catRows = New-Object System.Text.StringBuilder
        foreach ($k in ($cats.Keys | Sort-Object)) {
            $c = $cats[$k]
            [void]$catRows.Append("<tr><td>$(ConvertTo-HtmlEscaped $c.Category)</td><td>$($c.ScanCount)</td><td>$(Format-AcasNumber $c.TotalVulns)</td><td>$(Format-AcasNumber $c.TotalIps)</td><td>$(Format-AcasNumber $c.Vph 'N2')</td><td>$(Format-AcasPercent $c.ArPct)</td></tr>`n")
        }
        $ownerRows = New-Object System.Text.StringBuilder
        foreach ($k in ($owners.Keys | Sort-Object)) {
            $o = $owners[$k]
            [void]$ownerRows.Append("<tr><td>$(ConvertTo-HtmlEscaped $o.Owner)</td><td>$($o.ScanCount)</td><td>$(Format-AcasNumber $o.TotalVulns)</td><td>$(Format-AcasNumber $o.TotalIps)</td><td>$(Format-AcasNumber $o.Vph 'N2')</td></tr>`n")
        }

        [void]$cards.Append(@"
<div class="card">
  <div class="card-head">
    <span class="enclave $($w.Enclave)">$($w.Enclave)</span>
    <span class="range">$(ConvertTo-HtmlEscaped $w.DateRange)</span>
    $staleBadge
  </div>
  <div class="tiles">
    <div class="tile"><div class="lbl">MAJCOM Vulns</div><div class="val">$mjVulns</div></div>
    <div class="tile"><div class="lbl">MAJCOM VPH</div><div class="val">$mjVph</div></div>
    <div class="tile"><div class="lbl">In-House VPH (Base)</div><div class="val">$ihVph</div></div>
    <div class="tile"><div class="lbl">MAJCOM AR %</div><div class="val">$mjAr</div></div>
    <div class="tile"><div class="lbl">In-House Vulns</div><div class="val">$ihVulns</div></div>
    <div class="tile"><div class="lbl">In-House AR %</div><div class="val">$ihAr</div></div>
    <div class="tile"><div class="lbl">AR w/o PMO</div><div class="val">$arNoPmoStr</div></div>
  </div>
  <h4>By Category</h4>
  <table class="grid"><thead><tr><th>Category</th><th>Scans</th><th>Total Vulns</th><th>Total IPs</th><th>VPH (wtd)</th><th>AR %</th></tr></thead><tbody>
$($catRows.ToString())
  </tbody></table>
  <h4>PMO Breakdown by Owner</h4>
  <table class="grid"><thead><tr><th>Owner</th><th>Scans</th><th>Total Vulns</th><th>Total IPs</th><th>VPH (wtd)</th></tr></thead><tbody>
$($ownerRows.ToString())
  </tbody></table>
</div>
"@)
        }
    }
    if ($weeks.Count -eq 0) {
        [void]$cards.Append('<div class="card"><div class="card-head"><span class="range">No weeks parsed. Run Weekly Export Parse first.</span></div></div>')
    }

    $cardsBlock = $cards.ToString()
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET - ACAS Weekly Export - $generated</title>
<style>
$(Get-JanetReportCSS)
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 56px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 19px; font-weight: 600; color: var(--gold); }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .content { padding: 18px 28px; max-width: 1500px; margin: 0 auto; }
  .source { background: var(--panel); border: 1px solid var(--border); padding: 10px 14px; border-radius: 3px; font-size: 13px; color: var(--text-dim); margin-bottom: 16px; font-family: Consolas, monospace; }
  .month-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
  .month-tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .month-tile.green { border-top-color: var(--success); }
  .month-tile.cyan { border-top-color: var(--cyan); }
  .month-tile.gold { border-top-color: var(--gold); }
  .month-tile .label { font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .month-tile .value { font-size: 40px; font-weight: 800; color: var(--text); margin-top: 8px; line-height: 1.1; }
  .month-tile .sub { font-size: 13px; color: var(--text-dim); margin-top: 6px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--gold); padding: 16px 18px; margin-bottom: 18px; border-radius: 3px; }
  .card-head { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .card-head .enclave { font-weight: 800; padding: 3px 10px; border-radius: 3px; font-size: 13px; }
  .card-head .enclave.NIPR { background: rgba(80,200,220,0.18); color: var(--cyan); }
  .card-head .enclave.SIPR { background: rgba(220,92,100,0.18); color: var(--danger); }
  .card-head .range { color: var(--text); font-weight: 700; font-size: 15px; }
  .card-head .stale { margin-left: auto; color: var(--warning); font-weight: 700; font-size: 12px; }
  .tiles { display: grid; grid-template-columns: repeat(7, 1fr); gap: 10px; margin-bottom: 14px; }
  .tile { background: var(--panel-light); border: 1px solid var(--border); padding: 12px; border-radius: 3px; }
  .tile .lbl { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .tile .val { font-size: 26px; font-weight: 800; color: var(--gold); margin-top: 6px; }
  h4 { color: var(--cyan); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin: 14px 0 6px 0; }
  table.grid { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); font-size: 12px; text-transform: uppercase; }
  table.grid td { padding: 7px 10px; border-bottom: 1px solid var(--border); }
  .footer { margin-top: 16px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="topbar">
  <div class="title">J.A.N.E.T - ACAS Weekly Export</div>
  <div class="grow"></div>
  <div class="meta">Generated $generated by $(ConvertTo-HtmlEscaped (Get-ReportsCleanUser))</div>
</div>
<div class="content">
  <div class="source">Source: $src</div>
$cardsBlock
  <div class="footer">Self-contained ACAS weekly brief. VPH is host-count-weighted; AR % recomputed from raw GOOD/BAD sums.</div>
</div>
</body>
</html>
"@
    return $html
}

function Render-CoraVulnHtml {
    # Self-contained commander-brief HTML from a CORA summary. Faithful to the
    # data shape of ReportsTool_2.14.5.ps1:8369 (headline tiles, severity +
    # category breakdown, top-15 vuln cards). The original's inline-SVG donut/
    # bar charts are rendered as data tables/bars here (see limitations).
    param([Parameter(Mandatory)]$Summary)

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $netPctStr = if ($Summary.NetworkPct -is [double] -and -not [double]::IsNaN($Summary.NetworkPct)) { "$($Summary.NetworkPct)% of $($Summary.NetworkSize) devices" } else { 'network size not set' }

    $sevRows = New-Object System.Text.StringBuilder
    foreach ($s in @('Critical','High','Medium','Low','Info')) {
        $cnt = if ($Summary.SevCount.ContainsKey($s)) { $Summary.SevCount[$s] } else { 0 }
        $hostCnt = if ($Summary.SevHosts.ContainsKey($s)) { $Summary.SevHosts[$s] } else { 0 }
        [void]$sevRows.Append("<tr class=`"sev-$($s.ToLower())`"><td>$s</td><td>$cnt</td><td>$hostCnt</td></tr>`n")
    }

    $catRows = New-Object System.Text.StringBuilder
    $catSorted = @($Summary.Categories.GetEnumerator() | Sort-Object { -$_.Value.Count })
    foreach ($kv in $catSorted) {
        $name = ConvertTo-HtmlEscaped $kv.Key
        [void]$catRows.Append("<tr><td>$name</td><td>$($kv.Value.Count)</td><td>$($kv.Value.Hosts.Count)</td></tr>`n")
    }

    $vulnCards = New-Object System.Text.StringBuilder
    foreach ($v in $Summary.TopVulns) {
        $sevClass = "sev-$(($v.Severity -as [string]).ToLower())"
        $name = ConvertTo-HtmlEscaped $v.VulnName
        $sol  = ConvertTo-HtmlEscaped $v.Solution
        $ofNet = if ($Summary.NetworkSize -gt 0) { ' &middot; ' + ([Math]::Round(($v.HostCount / [double]$Summary.NetworkSize) * 100, 1)).ToString('0.0') + '% of net' } else { '' }
        [void]$vulnCards.Append(@"
<div class="vuln-card $sevClass">
  <div class="vc-head"><span class="badge">$(ConvertTo-HtmlEscaped $v.Severity)</span><span class="hosts">$($v.HostCount) hosts$ofNet</span></div>
  <div class="vc-name">$name</div>
  <div class="vc-meta">Plugin $(ConvertTo-HtmlEscaped $v.PluginID) - $(ConvertTo-HtmlEscaped $v.Category) - $($v.FindingCount) findings</div>
  <div class="vc-sol">$sol</div>
</div>
"@)
    }
    if ($Summary.TopVulns.Count -eq 0) {
        [void]$vulnCards.Append('<div class="vuln-card"><div class="vc-name">No open actionable findings loaded.</div></div>')
    }

    $sevBlock = $sevRows.ToString()
    $catBlock = $catRows.ToString()
    $vulnBlock = $vulnCards.ToString()
    # VPH tile: fixed 0.00 formatting, N/A when there are no hosts (orig:8380).
    $vphStr = if ($Summary.UniqueHosts -gt 0) { $Summary.Vph.ToString('0.00') } else { 'N/A' }
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET - CORA Commander Brief - $generated</title>
<style>
$(Get-JanetReportCSS)
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 56px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 19px; font-weight: 600; color: var(--gold); }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .content { padding: 18px 28px; max-width: 1500px; margin: 0 auto; }
  .summary-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
  .tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .tile .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .tile .val { font-size: 38px; font-weight: 800; color: var(--gold); margin-top: 6px; }
  .tile .sub { font-size: 12px; color: var(--text-dim); margin-top: 4px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px; }
  .panel { background: var(--panel); border: 1px solid var(--border); padding: 14px 16px; border-radius: 3px; }
  .panel h3 { color: var(--cyan); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 10px 0; }
  table.grid { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); font-size: 12px; text-transform: uppercase; }
  table.grid td { padding: 7px 10px; border-bottom: 1px solid var(--border); }
  tr.sev-critical td:first-child { color: var(--danger); font-weight: 700; }
  tr.sev-high td:first-child { color: var(--orange); font-weight: 700; }
  tr.sev-medium td:first-child { color: var(--warning); }
  tr.sev-low td:first-child { color: var(--cyan); }
  .vuln-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .vuln-card { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--accent); padding: 12px 14px; border-radius: 3px; }
  .vuln-card.sev-critical { border-left-color: var(--danger); }
  .vuln-card.sev-high { border-left-color: var(--orange); }
  .vuln-card.sev-medium { border-left-color: var(--warning); }
  .vc-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .vc-head .badge { font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--gold); }
  .vc-head .hosts { font-size: 18px; font-weight: 800; color: var(--cyan); }
  .vc-name { font-weight: 700; font-size: 13.5px; margin-bottom: 4px; }
  .vc-meta { font-size: 11.5px; color: var(--text-dim); margin-bottom: 6px; font-family: Consolas, monospace; }
  .vc-sol { font-size: 12px; color: var(--text-dim); max-height: 60px; overflow: hidden; }
  .footer { margin-top: 16px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="topbar">
  <div class="title">J.A.N.E.T - CORA Commander Brief</div>
  <div class="grow"></div>
  <div class="meta">Generated $generated by $(ConvertTo-HtmlEscaped (Get-ReportsCleanUser))</div>
</div>
<div class="content">
  <div class="summary-strip">
    <div class="tile"><div class="lbl">Open Findings</div><div class="val">$($Summary.ConsideredFindings)</div><div class="sub">of $($Summary.TotalLoaded) loaded</div></div>
    <div class="tile"><div class="lbl">Unique Hosts</div><div class="val">$($Summary.UniqueHosts)</div><div class="sub">$netPctStr</div></div>
    <div class="tile"><div class="lbl">Vulns / Host</div><div class="val">$vphStr</div><div class="sub">VPH</div></div>
    <div class="tile"><div class="lbl">Critical + High</div><div class="val">$([int]$Summary.SevCount['Critical'] + [int]$Summary.SevCount['High'])</div><div class="sub">priority findings</div></div>
  </div>
  <div class="two-col">
    <div class="panel">
      <h3>Severity Breakdown</h3>
      <table class="grid"><thead><tr><th>Severity</th><th>Findings</th><th>Hosts</th></tr></thead><tbody>
$sevBlock
      </tbody></table>
    </div>
    <div class="panel">
      <h3>Category Breakdown</h3>
      <table class="grid"><thead><tr><th>Category</th><th>Findings</th><th>Hosts</th></tr></thead><tbody>
$catBlock
      </tbody></table>
    </div>
  </div>
  <div class="panel">
    <h3>Top 15 Vulnerabilities by Host Count</h3>
    <div class="vuln-grid">
$vulnBlock
    </div>
  </div>
  <div class="footer">Commander brief - current open + actionable findings (excludes Patched and NOT OUR PATCH).</div>
</div>
</body>
</html>
"@
    return $html
}

# =============================================================================
#  Executive Command Brief renderer (feature) - one self-contained HTML page that
#  rolls up every other reports view into a single commander-facing brief. Takes
#  the pre-computed $Brief bag the 'command-brief' action assembles (each section
#  already carries HasData + a "run X first" Note when its source was empty). Same
#  renderer pattern + shared CSS as Render-CoraVulnHtml - no charts, plain
#  tables/tiles/chips, ASCII-only body.
# -----------------------------------------------------------------------------
function Render-CommandBriefHtml {
    param([Parameter(Mandatory)]$Brief)

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $sla = $Brief.Sla; $kev = $Brief.Kev; $sq = $Brief.Squadron
    $trend = $Brief.Trend; $route = $Brief.Route; $close = $Brief.Closure
    $noteHtml = { param($t) "<div class=`"nodata`">$(ConvertTo-HtmlEscaped ([string]$t))</div>" }

    # ---- headline tiles (N/A when the underlying section has no data) --------
    $tSla   = if ($sla.HasData)   { [string]$sla.Overdue } else { 'N/A' }
    $tKev   = if ($kev.HasData)   { [string]$kev.OpenKev } else { 'N/A' }
    $tRoute = if ($route.HasData) { "$($route.RoutablePct)%" } else { 'N/A' }
    $tComp  = if ($trend.HasData -and $trend.Points.Count -gt 0) { [string]$trend.Points[0].Pending } else { 'N/A' }

    # ---- (a) SLA -------------------------------------------------------------
    $slaBlock = if ($sla.HasData) {
        $slaRows = New-Object System.Text.StringBuilder
        foreach ($r in $sla.TopOverdue) {
            $sevClass = "sev-$(($r.Severity -as [string]).ToLower())"
            [void]$slaRows.Append("<tr class=`"$sevClass`"><td>$(ConvertTo-HtmlEscaped $r.Host)</td><td>$(ConvertTo-HtmlEscaped $r.Plugin)</td><td>$(ConvertTo-HtmlEscaped $r.VulnName)</td><td>$(ConvertTo-HtmlEscaped $r.Severity)</td><td class=`"num`">$($r.DueIn)</td></tr>`n")
        }
        if ($sla.TopOverdue.Count -eq 0) { [void]$slaRows.Append('<tr><td colspan="5" class="dim">No overdue findings - every open finding is inside its SLA window.</td></tr>') }
        @"
<div class="chips">
  <span class="chip bad">$($sla.Overdue) overdue</span>
  <span class="chip warn">$($sla.DueSoon) due-soon</span>
  <span class="chip ok">$($sla.OnTrack) on-track</span>
  <span class="chip info">$($sla.Untracked) untracked</span>
  <span class="chip dim">$($sla.Total) in scope</span>
</div>
<table class="grid"><thead><tr><th>Host</th><th>Plugin</th><th>Vuln</th><th>Sev</th><th>Due In (d)</th></tr></thead><tbody>
$($slaRows.ToString())</tbody></table>
<div class="src">Baseline: $(ConvertTo-HtmlEscaped $sla.Baseline)</div>
"@
    } else { & $noteHtml $sla.Note }

    # ---- (b) KEV posture -----------------------------------------------------
    $kevBlock = if ($kev.HasData) {
        if ([int]$kev.OpenKev -eq 0) {
            '<div class="good">No open known-exploited (KEV) findings - good posture.</div>'
        } else {
            $kevRows = New-Object System.Text.StringBuilder
            foreach ($r in $kev.Items) {
                [void]$kevRows.Append("<tr><td>$(ConvertTo-HtmlEscaped $r.Host)</td><td>$(ConvertTo-HtmlEscaped $r.Plugin)</td><td>$(ConvertTo-HtmlEscaped $r.VulnName)</td><td class=`"mono`">$(ConvertTo-HtmlEscaped $r.CVE)</td></tr>`n")
            }
            $more = if ($kev.Truncated) { "<div class=`"src`">Showing first $($kev.Items.Count) of $($kev.OpenKev) - export the full list from ACAS Export Findings.</div>" } else { '' }
            @"
<div class="chips">
  <span class="chip bad">$($kev.OpenKev) open KEV finding(s)</span>
  <span class="chip warn">$($kev.Hosts) host(s) affected</span>
</div>
<table class="grid"><thead><tr><th>Host</th><th>Plugin</th><th>Vuln</th><th>KEV CVE(s)</th></tr></thead><tbody>
$($kevRows.ToString())</tbody></table>
$more
"@
        }
    } else { & $noteHtml $kev.Note }

    # ---- (c) Squadron rollup -------------------------------------------------
    $sqBlock = if ($sq.HasData) {
        $sqRows = New-Object System.Text.StringBuilder
        foreach ($r in $sq.Rows) {
            $lvlCls = if ([string]$r.Level -eq 'Squadron') { ' class="lvl-sq"' } else { '' }
            [void]$sqRows.Append("<tr$lvlCls><td>$(ConvertTo-HtmlEscaped $r.Level)</td><td>$(ConvertTo-HtmlEscaped $r.Name)</td><td class=`"num`">$($r.Actions)</td><td class=`"num`">$($r.Hosts)</td><td class=`"num`">$($r.Vulns)</td><td class=`"mono`">$(ConvertTo-HtmlEscaped $r.LastActive)</td></tr>`n")
        }
        @"
<div class="chips">
  <span class="chip info">$($sq.Operators) operator(s)</span>
  <span class="chip ok">$($sq.Hosts) host(s) touched</span>
  <span class="chip ok">$($sq.Vulns) vuln(s) patched</span>
  <span class="chip bad">$($sq.FailPct)% fleet failure</span>
</div>
<table class="grid"><thead><tr><th>Level</th><th>Operator / Squadron</th><th>Actions</th><th>Hosts</th><th>Vulns</th><th>Last Active</th></tr></thead><tbody>
$($sqRows.ToString())</tbody></table>
<div class="src">Window: $(ConvertTo-HtmlEscaped $sq.Months)$(if (-not $sq.SquadronResolved) { ' - operator-level only (no AD squadron classification)' } else { '' })$(if ($sq.ReadFailed) { " - INCOMPLETE: $([int]$sq.ReadErrors) log-share path(s) could not be read, so absent operators/hosts are UNKNOWN, not idle (audit 2026-07-25)" } else { '' })</div>
"@
    } else { & $noteHtml $sq.Note }

    # ---- (d) Fleet compliance trend -----------------------------------------
    $trendBlock = if ($trend.HasData) {
        $tRows = New-Object System.Text.StringBuilder
        foreach ($p in $trend.Points) {
            [void]$tRows.Append("<tr><td class=`"mono`">$(ConvertTo-HtmlEscaped $p.Stamp)</td><td class=`"num`">$($p.Total)</td><td class=`"num`">$($p.Online)</td><td class=`"num`">$($p.Pending)</td><td class=`"num`">$($p.Reboot)</td></tr>`n")
        }
        @"
<table class="grid"><thead><tr><th>Snapshot</th><th>Hosts</th><th>Online</th><th>Pending</th><th>Reboot-Pending</th></tr></thead><tbody>
$($tRows.ToString())</tbody></table>
<div class="src">Newest $($trend.Points.Count) WPT Bulk Scan snapshot(s), newest first.</div>
"@
    } else { & $noteHtml $trend.Note }

    # ---- (e) Remediation routing --------------------------------------------
    $routeBlock = if ($route.HasData) {
        $rRows = New-Object System.Text.StringBuilder
        foreach ($r in $route.Rows) {
            $rowCls = if ($r.Routable) { '' } else { ' class="manual"' }
            [void]$rRows.Append("<tr$rowCls><td>$(ConvertTo-HtmlEscaped $r.Bucket)</td><td>$(ConvertTo-HtmlEscaped $r.Tool)</td><td>$(ConvertTo-HtmlEscaped $r.Action)</td><td class=`"num`">$($r.FindingCount)</td><td class=`"num`">$($r.HostCount)</td></tr>`n")
        }
        @"
<div class="chips">
  <span class="chip ok">$($route.RoutablePct)% routable</span>
  <span class="chip ok">$($route.RoutableFindings) one-click finding(s)</span>
  <span class="chip warn">$($route.ManualFindings) need manual review</span>
  <span class="chip dim">$($route.OpenFindings) open</span>
</div>
<table class="grid"><thead><tr><th>Bucket</th><th>Tool</th><th>Route</th><th>Findings</th><th>Hosts</th></tr></thead><tbody>
$($rRows.ToString())</tbody></table>
"@
    } else { & $noteHtml $route.Note }

    # ---- (f) Scan closure ----------------------------------------------------
    $closeBlock = if ($close.HasData) {
        @"
<div class="chips">
  <span class="chip ok">$($close.Remediated) remediated</span>
  <span class="chip warn">$($close.StillOpen) still open</span>
  <span class="chip bad">$($close.New) new</span>
  <span class="chip warn">$($close.Ambiguous) ambiguous</span>
  <span class="chip info">$($close.ClosurePct)% closure rate</span>
</div>
<div class="src">Closure rate = remediated of (remediated + still-open) from the last Patch Cross-Ref compare this session. AMBIGUOUS findings (a short name shared by distinct hosts/IPs - re-scan by FQDN) are UNCONFIRMED and excluded from the rate, shown separately.</div>
"@
    } else { & $noteHtml $close.Note }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>JANET - Executive Command Brief - $generated</title>
<style>
$(Get-JanetReportCSS)
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 56px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 19px; font-weight: 600; color: var(--gold); }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .content { padding: 18px 28px; max-width: 1500px; margin: 0 auto; }
  .summary-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
  .tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .tile .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .tile .val { font-size: 38px; font-weight: 800; color: var(--gold); margin-top: 6px; }
  .tile .sub { font-size: 12px; color: var(--text-dim); margin-top: 4px; }
  .panel { background: var(--panel); border: 1px solid var(--border); padding: 14px 16px; border-radius: 3px; margin-bottom: 16px; }
  .panel h3 { color: var(--cyan); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 10px 0; }
  table.grid { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); font-size: 12px; text-transform: uppercase; }
  table.grid td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.mono, .mono { font-family: Consolas, monospace; font-size: 12px; }
  td.dim, .dim { color: var(--text-dim); }
  tr.sev-critical td:nth-child(4) { color: var(--danger); font-weight: 700; }
  tr.sev-high td:nth-child(4) { color: var(--orange); font-weight: 700; }
  tr.sev-medium td:nth-child(4) { color: var(--warning); }
  tr.sev-low td:nth-child(4) { color: var(--cyan); }
  tr.lvl-sq td:first-child { color: var(--cyan); font-weight: 700; }
  tr.manual td { color: var(--text-dim); }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
  .chip { font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 3px; border: 1px solid var(--border); background: var(--panel-light); }
  .chip.bad { color: var(--danger); border-color: var(--danger); }
  .chip.warn { color: var(--warning); border-color: var(--warning); }
  .chip.ok { color: var(--success); border-color: var(--success); }
  .chip.info { color: var(--cyan); border-color: var(--cyan); }
  .chip.dim { color: var(--text-dim); }
  .nodata { color: var(--warning); font-size: 13px; padding: 10px 12px; border: 1px dashed var(--border); border-radius: 3px; background: var(--input); }
  .good { color: var(--success); font-size: 13px; font-weight: 600; padding: 6px 0; }
  .src { color: var(--text-faint); font-size: 11.5px; margin-top: 8px; }
  .footer { margin-top: 6px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="topbar">
  <div class="title">J.A.N.E.T - Executive Command Brief</div>
  <div class="grow"></div>
  <div class="meta">Generated $generated by $(ConvertTo-HtmlEscaped (Get-ReportsCleanUser))</div>
</div>
<div class="content">
  <div class="summary-strip">
    <div class="tile"><div class="lbl">SLA Overdue</div><div class="val">$tSla</div><div class="sub">findings past deadline</div></div>
    <div class="tile"><div class="lbl">Open KEV</div><div class="val">$tKev</div><div class="sub">known-exploited findings</div></div>
    <div class="tile"><div class="lbl">One-Click Routable</div><div class="val">$tRoute</div><div class="sub">of open findings</div></div>
    <div class="tile"><div class="lbl">Latest Pending</div><div class="val">$tComp</div><div class="sub">hosts in newest snapshot</div></div>
  </div>
  <div class="panel"><h3>(a) Remediation SLA / Finding Aging</h3>$slaBlock</div>
  <div class="panel"><h3>(b) KEV Posture (known-exploited)</h3>$kevBlock</div>
  <div class="panel"><h3>(c) Squadron Rollup</h3>$sqBlock</div>
  <div class="panel"><h3>(d) Fleet Compliance Trend</h3>$trendBlock</div>
  <div class="panel"><h3>(e) Remediation Routing</h3>$routeBlock</div>
  <div class="panel"><h3>(f) Scan Closure</h3>$closeBlock</div>
  <div class="footer">Executive command brief - each section reads live session state / local files; empty sections show what to run first.</div>
</div>
</body>
</html>
"@
    return $html
}

# =============================================================================
#  Posture Digest ('posture-digest' action)  -  self-contained HTML + CSV
#  snapshot for the off-hours Scheduler. Deliberately does NOT re-derive any
#  aggregation: the action branch below calls Build-CoraSummary (severity /
#  host / VPH - same function cora-build-summary / cora-render-html use) and
#  re-invokes the sla-aging / kb-needed / thirdparty-catalog / iavm-board
#  actions themselves (their row/status/log chatter swallowed by a no-op
#  Emit), then hands the resulting rollups to these two renderers.
# -----------------------------------------------------------------------------
function Render-PostureDigestHtml {
    param([Parameter(Mandatory)]$Digest)

    $generated = $Digest.GeneratedLocal
    $sc  = $Digest.SevCount
    $sla = $Digest.Sla

    $tile = { param($label, $val, $cls) "<div class=`"tile`"><div class=`"lbl`">$label</div><div class=`"val $cls`">$val</div></div>" }
    $sevStrip = @(
        (& $tile 'Critical' ([int]$sc.Critical) 'sev-crit'),
        (& $tile 'High'     ([int]$sc.High)     'sev-high'),
        (& $tile 'Medium'   ([int]$sc.Medium)   'sev-med'),
        (& $tile 'Low'      ([int]$sc.Low)      'sev-low'),
        (& $tile 'KEV'      ([int]$Digest.KevTotal) 'sev-kev')
    ) -join "`n"

    $slaChips = if ($sla -and $null -ne $sla.total) {
        @"
<div class="chips">
  <span class="chip bad">$($sla.overdue) overdue</span>
  <span class="chip warn">$($sla.dueSoon) due-soon</span>
  <span class="chip ok">$($sla.onTrack) on-track</span>
  <span class="chip info">$($sla.untracked) untracked</span>
  <span class="chip dim">$($sla.hosts) host(s) in scope; $($sla.hostsOverdue) w/ an overdue finding</span>
</div>
<div class="src">Baseline: $(ConvertTo-HtmlEscaped ([string]$sla.baseline))</div>
"@
    } else { '<div class="nodata">No SLA data (nothing loaded).</div>' }

    $kevRows = New-Object System.Text.StringBuilder
    foreach ($k in $Digest.TopKevHosts) {
        [void]$kevRows.Append("<tr><td>$(ConvertTo-HtmlEscaped $k.Host)</td><td class=`"num`">$($k.KevFindings)</td></tr>`n")
    }
    if ($Digest.TopKevHosts.Count -eq 0) { [void]$kevRows.Append('<tr><td colspan="2" class="dim">No open KEV (known-exploited) findings.</td></tr>') }

    $prodRows = New-Object System.Text.StringBuilder
    foreach ($p in $Digest.TopProducts) {
        $cls = if ($p.KEV) { ' class="kev"' } else { '' }
        [void]$prodRows.Append("<tr$cls><td>$(ConvertTo-HtmlEscaped $p.Product)</td><td class=`"num`">$($p.Hosts)</td><td>$(ConvertTo-HtmlEscaped $p.Severity)</td><td>$(ConvertTo-HtmlEscaped $p.KEV)</td><td>$(ConvertTo-HtmlEscaped $p.FixedVersion)</td><td>$(ConvertTo-HtmlEscaped $p.Route)</td><td class=`"num`">$($p.Findings)</td></tr>`n")
    }
    if ($Digest.TopProducts.Count -eq 0) { [void]$prodRows.Append('<tr><td colspan="7" class="dim">No third-party catalog data.</td></tr>') }

    $kbRows = New-Object System.Text.StringBuilder
    foreach ($k in $Digest.TopKb) {
        $cls = if ($k.KEV) { ' class="kev"' } else { '' }
        [void]$kbRows.Append("<tr$cls><td>$(ConvertTo-HtmlEscaped $k.KB)</td><td class=`"num`">$($k.Hosts)</td><td>$(ConvertTo-HtmlEscaped $k.Severity)</td><td>$(ConvertTo-HtmlEscaped $k.KEV)</td><td class=`"num`">$($k.Findings)</td><td class=`"mono`">$(ConvertTo-HtmlEscaped $k.SamplePlugins)</td></tr>`n")
    }
    if ($Digest.TopKb.Count -eq 0) { [void]$kbRows.Append('<tr><td colspan="6" class="dim">No KB-named findings in the loaded scan.</td></tr>') }

    $iavmRows = New-Object System.Text.StringBuilder
    foreach ($i in $Digest.TopIavm) {
        $cls = if ($i.KEV) { ' class="kev"' } else { '' }
        [void]$iavmRows.Append("<tr$cls><td>$(ConvertTo-HtmlEscaped $i.IAVA)</td><td class=`"num`">$($i.Hosts)</td><td>$(ConvertTo-HtmlEscaped $i.Severity)</td><td>$(ConvertTo-HtmlEscaped $i.KEV)</td><td class=`"num`">$($i.Findings)</td><td class=`"mono`">$(ConvertTo-HtmlEscaped $i.CVEs)</td></tr>`n")
    }
    if ($Digest.TopIavm.Count -eq 0) { [void]$iavmRows.Append('<tr><td colspan="6" class="dim">No findings carry an IAVA/IAVM bulletin mapping.</td></tr>') }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>$(ConvertTo-HtmlEscaped $Digest.Title) - $generated</title>
<style>
$(Get-JanetReportCSS)
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", system-ui, sans-serif; font-size: 14px; }
  .topbar { height: 56px; background: linear-gradient(180deg, rgb(20,18,30), rgb(12,10,18)); border-bottom: 2px solid var(--gold); display: flex; align-items: center; padding: 0 20px; }
  .topbar .title { font-size: 19px; font-weight: 600; color: var(--gold); }
  .topbar .grow { flex: 1; }
  .topbar .meta { color: var(--text-dim); font-size: 12px; text-align: right; }
  .content { padding: 18px 28px; max-width: 1500px; margin: 0 auto; }
  .summary-strip { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 18px; }
  .panel .summary-strip { grid-template-columns: repeat(5, 1fr); margin-bottom: 0; }
  .tile { background: var(--panel); border: 1px solid var(--border); border-top: 3px solid var(--accent); padding: 16px 18px; }
  .tile .lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
  .tile .val { font-size: 34px; font-weight: 800; color: var(--gold); margin-top: 6px; }
  .tile .val.sev-crit { color: var(--danger); } .tile .val.sev-high { color: var(--orange); }
  .tile .val.sev-med  { color: var(--warning); } .tile .val.sev-low  { color: var(--cyan); }
  .tile .val.sev-kev  { color: var(--danger); }
  .tile .sub { font-size: 12px; color: var(--text-dim); margin-top: 4px; }
  .panel { background: var(--panel); border: 1px solid var(--border); padding: 14px 16px; border-radius: 3px; margin-bottom: 16px; }
  .panel h3 { color: var(--cyan); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin: 0 0 10px 0; }
  table.grid { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.grid th { background: var(--panel-light); color: var(--gold); text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); font-size: 12px; text-transform: uppercase; }
  table.grid td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.mono, .mono { font-family: Consolas, monospace; font-size: 12px; }
  td.dim, .dim { color: var(--text-dim); }
  tr.kev td:first-child { color: var(--danger); font-weight: 700; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
  .chip { font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 3px; border: 1px solid var(--border); background: var(--panel-light); }
  .chip.bad { color: var(--danger); border-color: var(--danger); }
  .chip.warn { color: var(--warning); border-color: var(--warning); }
  .chip.ok { color: var(--success); border-color: var(--success); }
  .chip.info { color: var(--cyan); border-color: var(--cyan); }
  .chip.dim { color: var(--text-dim); }
  .nodata { color: var(--warning); font-size: 13px; padding: 10px 12px; border: 1px dashed var(--border); border-radius: 3px; background: var(--input); }
  .src { color: var(--text-faint); font-size: 11.5px; margin-top: 8px; }
  .footer { margin-top: 6px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="topbar">
  <div class="title">J.A.N.E.T - $(ConvertTo-HtmlEscaped $Digest.Title)</div>
  <div class="grow"></div>
  <div class="meta">Generated $generated (UTC $($Digest.GeneratedUtc)) by $(ConvertTo-HtmlEscaped (Get-ReportsCleanUser))</div>
</div>
<div class="content">
  <div class="summary-strip">
    <div class="tile"><div class="lbl">Findings Loaded</div><div class="val">$($Digest.TotalLoaded)</div><div class="sub">raw scan rows</div></div>
    <div class="tile"><div class="lbl">Open Findings</div><div class="val">$($Digest.OpenFindings)</div><div class="sub">not Patched / not NOT OUR PATCH</div></div>
    <div class="tile"><div class="lbl">Hosts Affected</div><div class="val">$($Digest.UniqueHosts)</div><div class="sub">$($Digest.Vph) vulns/host (VPH)</div></div>
  </div>
  <div class="panel"><h3>Severity Breakdown</h3><div class="summary-strip">$sevStrip</div></div>
  <div class="panel"><h3>SLA / Finding Aging Posture</h3>$slaChips</div>
  <div class="panel"><h3>Top KEV Exposure (by host)</h3>
    <table class="grid"><thead><tr><th>Host</th><th>Open KEV Findings</th></tr></thead><tbody>
$($kevRows.ToString())</tbody></table>
  </div>
  <div class="panel"><h3>Top Third-Party Products</h3>
    <table class="grid"><thead><tr><th>Product</th><th>Hosts</th><th>Severity</th><th>KEV</th><th>Fixed Version</th><th>Route</th><th>Findings</th></tr></thead><tbody>
$($prodRows.ToString())</tbody></table>
  </div>
  <div class="panel"><h3>Top KBs Needed</h3>
    <table class="grid"><thead><tr><th>KB</th><th>Hosts</th><th>Severity</th><th>KEV</th><th>Findings</th><th>Sample Plugins</th></tr></thead><tbody>
$($kbRows.ToString())</tbody></table>
  </div>
  <div class="panel"><h3>IAVA / IAVM Bulletins</h3>
    <table class="grid"><thead><tr><th>IAVA</th><th>Hosts</th><th>Severity</th><th>KEV</th><th>Findings</th><th>CVEs</th></tr></thead><tbody>
$($iavmRows.ToString())</tbody></table>
  </div>
  <div class="footer">Posture digest - a nightly snapshot. Arm on the off-hours Scheduler (Reports / Posture Digest) to drop a fresh copy in this folder every night.</div>
</div>
</body>
</html>
"@
    return $html
}

# Flat CSV companion to the HTML digest: Section,Metric,Value,Detail rows (one
# section per metric group, then one row per top-list item). Every cell goes
# through the shared ConvertTo-ReportsCsvCell (RFC-4180 quoting + the same
# formula-injection guard the other exporters use).
function Build-PostureDigestCsv {
    param([Parameter(Mandatory)]$Digest)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('Section,Metric,Value,Detail')
    $add = {
        param($section, $metric, $value, $detail)
        [void]$sb.AppendLine((@(
            (ConvertTo-ReportsCsvCell $section), (ConvertTo-ReportsCsvCell $metric),
            (ConvertTo-ReportsCsvCell $value), (ConvertTo-ReportsCsvCell $detail)
        ) -join ','))
    }
    & $add 'Header' 'Title' $Digest.Title ''
    & $add 'Header' 'GeneratedLocal' $Digest.GeneratedLocal ''
    & $add 'Header' 'GeneratedUtc' $Digest.GeneratedUtc ''
    & $add 'Header' 'FindingsLoaded' $Digest.TotalLoaded ''
    & $add 'Header' 'OpenFindings' $Digest.OpenFindings ''
    & $add 'Header' 'UniqueHosts' $Digest.UniqueHosts ''
    & $add 'Header' 'VulnsPerHost' $Digest.Vph ''
    $sc = $Digest.SevCount
    & $add 'Severity' 'Critical' ([int]$sc.Critical) ''
    & $add 'Severity' 'High' ([int]$sc.High) ''
    & $add 'Severity' 'Medium' ([int]$sc.Medium) ''
    & $add 'Severity' 'Low' ([int]$sc.Low) ''
    & $add 'Severity' 'Info' ([int]$sc.Info) ''
    & $add 'KEV' 'OpenKevFindings' $Digest.KevTotal ''
    & $add 'KEV' 'HostsWithKev' $Digest.KevHostsCount ''
    $sla = $Digest.Sla
    if ($sla -and $null -ne $sla.total) {
        & $add 'SLA' 'Overdue' $sla.overdue ''
        & $add 'SLA' 'DueSoon' $sla.dueSoon ''
        & $add 'SLA' 'OnTrack' $sla.onTrack ''
        & $add 'SLA' 'Untracked' $sla.untracked ''
        & $add 'SLA' 'HostsOverdue' $sla.hostsOverdue ''
        & $add 'SLA' 'Baseline' '' $sla.baseline
    }
    foreach ($k in $Digest.TopKevHosts) { & $add 'TopKevHost' $k.Host $k.KevFindings '' }
    foreach ($p in $Digest.TopProducts) { & $add 'TopProduct' $p.Product $p.Hosts "Sev=$($p.Severity); KEV=$($p.KEV); Fixed=$($p.FixedVersion); Route=$($p.Route); Findings=$($p.Findings)" }
    foreach ($k in $Digest.TopKb)       { & $add 'TopKB' $k.KB $k.Hosts "Sev=$($k.Severity); KEV=$($k.KEV); Findings=$($k.Findings); Plugins=$($k.SamplePlugins)" }
    foreach ($i in $Digest.TopIavm)     { & $add 'TopIAVA' $i.IAVA $i.Hosts "Sev=$($i.Severity); KEV=$($i.KEV); Findings=$($i.Findings); CVEs=$($i.CVEs)" }
    return $sb.ToString().TrimEnd()
}

# =============================================================================
#  Region: helper used by both the probe action and any inline ping needs
# =============================================================================

function ConvertTo-JanetHostList {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim()
        # Accept only a bare host/IPv4 token; drop UNC/URL/junk before any remote call.
        if ($h -and ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
    }
    return $out.ToArray()
}

# =============================================================================
#  The contract entrypoint
# =============================================================================

function Set-JanetNetworkDeviceCount {
    param($Params)
    if ($Params['NetworkDeviceCount']) {
        $n = 0; if ([int]::TryParse([string]$Params['NetworkDeviceCount'], [ref]$n) -and $n -ge 0) { $script:NetworkDeviceCount = $n }
    }
}

# =============================================================================
#  Squadron-level rollup helpers  -  read-only aggregation of the central JANET
#  log share (same path conventions as server\JanetWeb.Logging.ps1, which we do
#  NOT edit): the fleet usage rollup Logs\<YYYY-MM>_usage.csv (one SessionEnd row
#  per tool + an aggregate JANET-WEB row per session - JANET-TWO on historical
#  rows - all operators/instances) and
#  the per-tool detail CSVs Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv. The
#  share is 445-gated up front (reusing Test-JanetUncReachable) so a dead share
#  fails friendly instead of hanging. Nothing here writes to the share.
# -----------------------------------------------------------------------------

# The production log share root the desktop + JANET Web tools log to (byte-for-byte
# the same literal as $script:JanetWebShareRoot in JanetWeb.Logging.ps1). Kept as a
# helper so this module stays self-contained (each engine loads in its own runspace).
function Get-ReportsLogShareRoot { return '\\dm-tn-01\sh-usafe-automation$\JANET\Logs' }

# The list of yyyy-MM month tokens to scan, newest first. MonthsBack=1 -> current
# month only; clamped to 1..24 so a typo cannot walk years of files.
function Get-ReportsRollupMonths {
    param([int]$MonthsBack = 1)
    if ($MonthsBack -lt 1)  { $MonthsBack = 1 }
    if ($MonthsBack -gt 24) { $MonthsBack = 24 }
    $now = Get-Date
    $list = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $MonthsBack; $i++) { [void]$list.Add($now.AddMonths(-$i).ToString('yyyy-MM')) }
    return $list
}

# One fresh per-operator accumulator. Hosts/Sessions are case-insensitive sets so a
# host or session id seen in two files counts once; Tools is a name->action-count map.
function New-ReportsRollupOp {
    param([string]$Name)
    return @{
        Name       = $Name
        Actions    = 0
        TouchOK    = 0
        TouchFail  = 0
        Vulns      = 0
        Hosts      = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
        Tools      = @{}
        Sessions   = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
        LastActive = ''
    }
}

# CSV cell quoter for the rollup export (RFC-4180: quote only when needed). The
# rollup's own values are simple, but TopTools can carry commas.
function ConvertTo-ReportsCsvCell {
    param([string]$Value)
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    # Formula-injection guard (audit#23): AD-derived Name/OU and log tool names can
    # begin with = + - @; prefix a single quote so they are not evaluated in Excel.
    if ($s.Length -gt 0 -and ('=','+','-','@',"`t","`r") -contains $s[0]) { $s = "'" + $s }
    if ($s -match '[",\r\n]') { return '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel contract: the server injects a synchronized hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running fan-out break and stop its in-flight workers instead of probing
    # every remaining host. No __job (e.g. direct calls) -> cancelCheck is $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Per-invocation report palette (the render actions' optional 'colorblind' input);
    # Get-JanetReportCSS reads this when called with no explicit mode. Default None.
    $script:JanetReportColorblind = if ($Params -and $Params['colorblind']) { [string]$Params['colorblind'] } else { 'None' }

    switch ($ActionId) {

        # -------------------------------------------------------------------
        'dirty30-parse-lookup' {
            $inputText = [string]$Params['InputText']
            $sourceLabel = [string]$Params['SourceLabel']
            if ([string]::IsNullOrWhiteSpace($inputText)) {
                & $send @{ type='log'; level='warn'; text='No Dirty 30 input provided.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Parsing Dirty 30 input...' }
            $parsed = Parse-Dirty30Input -Text $inputText
            $script:Dirty30Hosts = $parsed
            $script:Dirty30SourceLabel = if ($sourceLabel) { $sourceLabel } else { "pasted input ($($parsed.Count) hosts)" }
            $script:Dirty30LastUserMap = @{}
            & $send @{ type='status'; text="Parsed $($parsed.Count) host(s). Running batched LDAP lookup..." }

            $names = @($parsed | ForEach-Object { $_.Hostname })
            $ad = @{}
            try {
                $ad = Get-Dirty30AdInfo -Hostnames $names -CancelCheck $cancelCheck -Send $send
            } catch {
                & $send @{ type='log'; level='err'; text="LDAP lookup failed: $($_.Exception.Message)" }
            }
            $script:Dirty30AdResults = $ad

            $rows = New-Object System.Collections.ArrayList
            $okCount = 0; $failCount = 0
            $i = 0
            foreach ($h in $parsed) {
                $i++
                $a = $ad[$h.Hostname]
                $vulns = "$($h.Crit)/$($h.High)/$($h.Med)/$($h.Low)"
                $status = if ($a) { $a.Status } else { 'Unknown' }
                if ($status -eq 'Not Found' -or $status -eq 'Unknown') { $failCount++ } else { $okCount++ }
                $row = @{
                    Host     = $h.Hostname
                    Hostname = $h.Hostname
                    Score    = $h.Score
                    Vulns    = $vulns
                    LastLogon = if ($a) { $a.LastLogon } else { '' }
                    Squadron = if ($a) { $a.Squadron } else { '' }
                    OUChain  = if ($a) { $a.OUChain } else { '' }
                    Status   = $status
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='progress'; done=$i; total=$parsed.Count }
            }
            & $send @{ type='audit'; action='TouchHost'; target="Dirty30 ($($parsed.Count) hosts)"; result=$(if ($ad.Count -gt 0) { 'Success' } else { 'Failure' }); itemCount=$parsed.Count; detail="LDAP lookup: $okCount resolved, $failCount not found/unknown" }
            if (& $cancelCheck) {
                & $send @{ type='status'; text="Cancelled. $($parsed.Count) host(s) parsed; $okCount resolved in AD before cancel (rest Unknown)." }
            } else {
                & $send @{ type='status'; text="Done. $($parsed.Count) host(s) parsed; $okCount resolved in AD." }
            }
            return @{ rows=@(); summary=@{ total=$parsed.Count; ok=$okCount; failed=$failCount } }
        }

        # -------------------------------------------------------------------
        'dirty30-probe-lastuser' {
            $rawHosts = [string]$Params['Hostnames']
            $targets = ConvertTo-JanetHostList $rawHosts
            if ($targets.Count -eq 0) {
                # fall back to the last parsed Dirty 30 host set
                $targets = @($script:Dirty30Hosts | ForEach-Object { $_.Hostname })
            }
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No hosts to probe (paste hosts or run a Dirty 30 lookup first).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $timeoutSec = 8; if ($Params['TimeoutSec']) { [int]::TryParse([string]$Params['TimeoutSec'], [ref]$timeoutSec) | Out-Null }
            $threads = 16; if ($Params['MaxConcurrent']) { [int]::TryParse([string]$Params['MaxConcurrent'], [ref]$threads) | Out-Null }
            $threads = [Math]::Max(1, [Math]::Min(64, $threads))

            & $send @{ type='status'; text="Probing LastLoggedOnUser on $($targets.Count) host(s) with $threads thread(s)..." }

            # ponytail: resolve-target-ips deliberately mirrors this pool/stall/cancel/deadline
            # machinery rather than sharing a callback fanout - the per-outcome rows/counters/audit
            # and the LastUser map differ, and indirection here would hide the cancel/deadline
            # contract behind a closure on a remote-exec path. Two boring loops beat one clever helper.
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = $null
            $jobs = New-Object System.Collections.ArrayList
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $okCount = 0; $failCount = 0
            # Per-job stall-guard margin so a host that accepts TCP but never
            # replies (Async.IsCompleted stays false) can't busy-wait forever.
            # The worker's WMI Timeout should fire first; this is the floor.
            $jobTimeout = [TimeSpan]::FromSeconds($timeoutSec + 5)
            # Pool create/Open and the submit loop live inside this try so a
            # throw mid-submit still runs the finally that tears the pool down.
            try {
                $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
                $pool.Open()
                foreach ($t in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                    [void]$ps.AddScript($script:Dirty30LastUserWorker)
                    [void]$ps.AddArgument($t)
                    [void]$ps.AddArgument($timeoutSec)
                    [void]$ps.AddArgument($Credential)
                    # Async/Started stay $null until a slot frees: the per-job
                    # stall-guard must time RUNNING jobs only, never queued ones.
                    [void]$jobs.Add([pscustomobject]@{ Host=$t; PS=$ps; Async=$null; Started=$null })
                }
                # Overall deadline scaled by wave count so queued jobs on big
                # fleets are not reaped before they ever get a pool slot.
                $waves = [Math]::Ceiling($jobs.Count / [double]$threads)
                $deadline = (Get-Date).AddSeconds($jobTimeout.TotalSeconds * $waves + 10)
                $running = 0

                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($running -ge $threads) { break }
                        if ($j.PS -and -not $j.Async) {
                            $j.Async = $j.PS.BeginInvoke()
                            $j.Started = Get-Date
                            $running++
                        }
                    }
                    foreach ($j in $jobs) {
                        if ($j.PS -and $j.Async -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; User="- error - $($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}
                            $j.PS = $null
                            $running--
                            $userVal = if ($res) { [string]$res.User } else { '- no result -' }
                            $ok = ($userVal -notmatch '^-')
                            if ($ok) { $okCount++ } else { $failCount++ }
                            $script:Dirty30LastUserMap[$j.Host.ToUpper()] = $userVal
                            $row = @{ Host=$j.Host; LastUser=$userVal }
                            [void]$rows.Add($row)
                            & $send (@{ type='row' } + $row)
                            & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result=$(if ($ok) { 'Success' } else { 'Failure' }); itemCount=$(if ($ok) { 1 } else { 0 }); detail=$userVal }
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                        elseif ($j.PS -and $j.Async -and (((Get-Date) - $j.Started) -gt $jobTimeout)) {
                            # Stalled RUNNING job: exceeded its budget. Reap it.
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $running--
                            $userVal = '- timeout -'
                            $failCount++
                            $script:Dirty30LastUserMap[$j.Host.ToUpper()] = $userVal
                            $row = @{ Host=$j.Host; LastUser=$userVal }
                            [void]$rows.Add($row)
                            & $send (@{ type='row' } + $row)
                            & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$userVal }
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    # Operator cancel: stop every still-running job, record it, and break.
                    if ($done -lt $jobs.Count -and (& $cancelCheck)) {
                        $unprobed = $jobs.Count - $done
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                # Started jobs get BeginStop; queued ones were never
                                # invoked, so an immediate Dispose is safe and instant.
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} }
                                else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null
                                $userVal = '- cancelled -'
                                $failCount++
                                $script:Dirty30LastUserMap[$j.Host.ToUpper()] = $userVal
                                $row = @{ Host=$j.Host; LastUser=$userVal }
                                [void]$rows.Add($row)
                                & $send (@{ type='row' } + $row)
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail='cancelled by operator' }
                                $done++
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text="Cancelled by operator; $unprobed host(s) left unprobed." }
                        break
                    }
                    # Overall deadline guard: a stuck handle never trips IsCompleted
                    # and BeginStop may not unblock the runspace; bail out cleanly.
                    if ($done -lt $jobs.Count -and (Get-Date) -gt $deadline) {
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} }
                                else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null
                                $userVal = '- timeout -'
                                $failCount++
                                $script:Dirty30LastUserMap[$j.Host.ToUpper()] = $userVal
                                $row = @{ Host=$j.Host; LastUser=$userVal }
                                [void]$rows.Add($row)
                                & $send (@{ type='row' } + $row)
                                & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$userVal }
                                $done++
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text='Probe deadline exceeded; remaining host(s) marked timeout.' }
                        break
                    }
                    if ($done -lt $jobs.Count) { Start-Sleep -Milliseconds 120 }
                }
            } finally {
                # Best-effort: dispose any handles still live (only the abnormal
                # path leaves $j.PS non-null; the normal loop nulls each one), then
                # tear the pool down. $pool may be $null if create/Open threw.
                foreach ($j in $jobs) { if ($j.PS) { try { $j.PS.Dispose() } catch {} } }
                if ($pool) { try { $pool.Close(); $pool.Dispose() } catch {} }
            }
            & $send @{ type='status'; text="Done. $okCount resolved, $failCount unresolved of $($jobs.Count)." }
            return @{ rows=@($rows); summary=@{ total=$jobs.Count; ok=$okCount; failed=$failCount } }
        }

        # -------------------------------------------------------------------
        'dirty30-render-html' {
            if ($Params['SourceLabel']) { $script:Dirty30SourceLabel = [string]$Params['SourceLabel'] }
            if ($script:Dirty30Hosts.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No Dirty 30 hosts loaded. Run a lookup first.' }
            }
            & $send @{ type='status'; text='Rendering Dirty 30 HTML report...' }
            $html = Render-Dirty30Html
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($html)
            $outPath = [string]$Params['OutputPath']
            $written = ''; $writeErr = $null
            if ($outPath) {
                # audit 2026-07-23: TCP-445 pre-gate (same idiom as weekly-render-html) so a
                # dead UNC share fails fast instead of hanging the serialized reports runspace.
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $html, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=$script:Dirty30Hosts.Count; detail="Dirty 30 HTML report written ($bytes bytes, $($script:Dirty30Hosts.Count) host(s))" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="HTML report write failed: $writeErr" } }
            }
            $row = @{ Report='Dirty 30 Triage'; Hosts=$script:Dirty30Hosts.Count; Bytes=$bytes; Html=$html; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; Hosts=$row.Hosts; Bytes=$row.Bytes })
            & $send @{ type='status'; text="Rendered HTML ($bytes bytes)." }
            return @{ rows=@($row); summary=@{ total=1; hosts=$script:Dirty30Hosts.Count; bytes=$bytes; html=$html } }
        }

        # -------------------------------------------------------------------
        'dirty30-export-csv' {
            if ($script:Dirty30Hosts.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No Dirty 30 hosts loaded. Run a lookup first.' }
            }
            & $send @{ type='status'; text='Exporting Dirty 30 CSV...' }
            $csv = Export-Dirty30CsvText
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($csv)
            $outPath = [string]$Params['OutputPath']
            $written = ''; $writeErr = $null
            if ($outPath) {
                # audit 2026-07-23: TCP-445 pre-gate (same idiom as weekly-render-html) so a
                # dead UNC share fails fast instead of hanging the serialized reports runspace.
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $csv, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=$script:Dirty30Hosts.Count; detail="Dirty 30 CSV written ($bytes bytes, $($script:Dirty30Hosts.Count) host(s))" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="CSV write failed: $writeErr" } }
            }
            $row = @{ Report='Dirty 30 CSV'; Hosts=$script:Dirty30Hosts.Count; Bytes=$bytes; Csv=$csv; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; Hosts=$row.Hosts; Bytes=$row.Bytes })
            & $send @{ type='status'; text="Exported CSV ($bytes bytes)." }
            return @{ rows=@($row); summary=@{ total=1; hosts=$script:Dirty30Hosts.Count; bytes=$bytes; csv=$csv } }
        }

        # -------------------------------------------------------------------
        'acas-parse-file' {
            $filePath = [string]$Params['FilePath']
            $append = $false; if ($Params['Append']) { $append = [bool]$Params['Append'] }
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -LiteralPath $filePath)) {
                & $send @{ type='log'; level='err'; text="File not found: $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='file not found' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Parsing ACAS file: $filePath" }
            $findings = Parse-AcasFile -FilePath $filePath -Emit $send
            if (-not $append) {
                $script:AcasFindings = New-Object System.Collections.ArrayList
                $script:ComparisonResults = $null   # the import set changed; the last compare's delta no longer applies to it
                $script:AcasHostOnline = @{}         # offline map must not outlive the findings it describes (#10)
            }
            # De-dup on Hostname|PluginID exactly like the desktop import (orig
            # btnImportAcas:6131-6150): a plugin on multiple open ports of one host -
            # or a re-import of the same file - must NOT inflate the open-vuln total.
            $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $script:AcasFindings) { [void]$seenKeys.Add("$($e.Hostname)|$($e.PluginID)") }
            $added = New-Object System.Collections.ArrayList
            $dupes = 0
            foreach ($f in $findings) {
                if ($seenKeys.Add("$($f.Hostname)|$($f.PluginID)")) { [void]$script:AcasFindings.Add($f); [void]$added.Add($f) }
                else { $dupes++ }
            }

            $rows = New-Object System.Collections.ArrayList
            $i = 0; $kevCount = 0
            foreach ($f in $added) {
                $i++
                if ($f.InKEV) { $kevCount++ }
                $row = @{
                    Host=$f.Hostname; Hostname=$f.Hostname; PluginID=$f.PluginID
                    VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category
                    Status=$f.Status; Solution=$f.Solution; InKEV=$f.InKEV; KevCves=$f.KevCves; IAVA=$f.IAVA
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                if (($i % 200) -eq 0) { & $send @{ type='progress'; done=$i; total=$added.Count } }
            }
            & $send @{ type='progress'; done=$added.Count; total=$added.Count }
            # SLA firstSeen ledger (audit P1 permanent fix): upsert every currently loaded
            # finding so the aging clock survives THIS re-parse - keys already in the ledger
            # keep their original firstSeen (carried), brand-new keys start today. The ledger
            # stamps the authoritative firstSeen back onto the live findings so sla-aging sees
            # them as tracked with zero operator discipline (no Save step required).
            $led = Update-ReportsSlaLedger -Findings $script:AcasFindings
            & $send @{ type='log'; level='info'; text="SLA ledger: $($led.Carried) clock(s) carried, $($led.Started) newly started (of $($led.Total) loaded finding(s))." }
            if (-not $led.Written) { & $send @{ type='log'; level='warn'; text="SLA ledger not saved (firstSeen persisted only inside a saved report this run): $($led.Error)" } }
            $dupeNote = if ($dupes -gt 0) { " ($dupes duplicate Host|Plugin row(s) skipped)" } else { '' }
            if ($kevCount -gt 0) { & $send @{ type='log'; level='banner'; text="$kevCount of $($added.Count) added finding(s) are on the CISA KEV list (known-exploited - prioritize)." } }
            # added>0 -> real work (Success). Nothing added but rows were parsed and
            # all were duplicates of the loaded set (e.g. a re-import) -> Skipped, not
            # a failure. Nothing parsed at all (unreadable / no findings) -> Failure.
            $result = if ($added.Count -gt 0) { 'Success' } elseif ($dupes -gt 0) { 'Skipped' } else { 'Failure' }
            $kevNote = if ($kevCount -gt 0) { ", $kevCount KEV" } else { '' }
            & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $filePath); result=$result; itemCount=$added.Count; detail="$($added.Count) findings added$kevNote$dupeNote (total loaded: $($script:AcasFindings.Count))" }
            & $send @{ type='status'; text="Added $($added.Count) finding(s)$kevNote$dupeNote. Total loaded: $($script:AcasFindings.Count)." }
            return @{ rows=@(); summary=@{ total=$added.Count; loaded=$script:AcasFindings.Count; kev=$kevCount; duplicatesSkipped=$dupes } }
        }

        # -------------------------------------------------------------------
        'iavm-add-map' {
            # Append/update one CVE -> IAVA/Title mapping in JanetLocal\IavmMap.csv.
            # Mirrors the KEV tool's add-kev persistence: validate, de-dup, atomic
            # write of the whole file. Lenient - a bad CVE / blank IAVA is a friendly
            # error, never a throw. Read-only w.r.t. loaded findings (no re-parse).
            $cve   = ([string]$Params['cve']).Trim().ToUpper()
            $iava  = ([string]$Params['iava']).Trim()
            $title = ([string]$Params['title']).Trim()
            if ($cve -notmatch '^CVE-\d{4}-\d{4,}$') {
                & $send @{ type='log'; level='err'; text="Invalid CVE format: '$cve'. Expected CVE-YYYY-NNNN." }
                return @{ rows=@(); summary=@{ added=0; updated=0; invalid=1 } }
            }
            if ([string]::IsNullOrWhiteSpace($iava)) {
                & $send @{ type='log'; level='err'; text='IAVA / bulletin id is required.' }
                return @{ rows=@(); summary=@{ added=0; updated=0; invalid=1 } }
            }
            $im = Read-ReportsIavmMap
            # Copy the existing map into a plain (case-insensitive) hashtable to mutate.
            $map = @{}
            foreach ($k in $im.Map.Keys) { $map[$k] = @{ IAVA = [string]$im.Map[$k].IAVA; Title = [string]$im.Map[$k].Title } }
            $existed = $map.ContainsKey($cve)
            $status = if ($existed) { 'Updated' } else { 'Added' }
            $map[$cve] = @{ IAVA = $iava; Title = $title }
            try {
                Write-ReportsIavmMap -Map $map -Path $im.Path
            } catch {
                & $send @{ type='error'; text="Save FAILED - IAVM map NOT changed: $($_.Exception.Message)" }
                return @{ rows=@(); summary=@{ added=0; updated=0; invalid=0; saveError=$true } }
            }
            $row = @{ _rk=$cve; CVE=$cve; IAVA=$iava; Title=$title; Status=$status }
            & $send (@{ type='row' } + $row)
            & $send @{ type='log'; level='ok'; text="$status $cve -> $iava in JanetLocal\IavmMap.csv (now $($map.Count) mapping(s))." }
            & $send @{ type='status'; text="$status $cve -> $iava. IAVM map now $($map.Count) mapping(s)." }
            return @{ rows=@($row); summary=@{ added=$(if ($existed) { 0 } else { 1 }); updated=$(if ($existed) { 1 } else { 0 }); invalid=0; total=$map.Count } }
        }

        # -------------------------------------------------------------------
        'acas-weekly-parse' {
            $filePath = [string]$Params['FilePath']
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -LiteralPath $filePath)) {
                & $send @{ type='log'; level='err'; text="File not found: $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='file not found' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Parsing ACAS_Calculations workbook: $filePath" }
            $weeks = Parse-AcasCalculationsWorkbook -FilePath $filePath
            if (-not $weeks) { $weeks = New-Object System.Collections.ArrayList }
            $script:AcasCalcWeeks = $weeks
            $script:AcasCalcSourceFile = $filePath

            $rows = New-Object System.Collections.ArrayList
            $i = 0
            foreach ($w in $weeks) {
                $i++
                $mj = $w.MajcomTotals
                $totalVulns = if ($mj) { $mj.TotalVulns } else { 0 }
                $arPct = if ($mj -and -not [double]::IsNaN($mj.ArPct)) { $mj.ArPct } else { '' }
                $vph = if ($mj -and -not [double]::IsNaN($mj.Vph)) { $mj.Vph } else { '' }
                $row = @{
                    Host="$($w.Enclave) $($w.DateRange)"
                    Week=$w.DateRange; Enclave=$w.Enclave
                    TotalVulns=$totalVulns; AR_Percent=$arPct; MAJCOM_VPH=$vph
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='progress'; done=$i; total=$weeks.Count }
            }
            $result = if ($weeks.Count -gt 0) { 'Success' } else { 'Failure' }
            & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $filePath); result=$result; itemCount=$weeks.Count; detail="$($weeks.Count) week-block(s) parsed" }
            & $send @{ type='status'; text="Parsed $($weeks.Count) week-block(s)." }
            return @{ rows=@($rows); summary=@{ total=$weeks.Count } }
        }

        # -------------------------------------------------------------------
        'weekly-render-html' {
            $enclave = [string]$Params['Enclave']
            if ($script:AcasCalcWeeks.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No weekly data parsed. Run Weekly Export Parse first.' }
            }
            & $send @{ type='status'; text='Rendering weekly HTML brief...' }
            $html = Render-WeeklyExportHtml -EnclaveFilter $enclave
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($html)
            $outPath = [string]$Params['OutputPath']
            $written = ''; $writeErr = $null
            if ($outPath) {
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $html, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=$script:AcasCalcWeeks.Count; detail="Weekly HTML brief written ($bytes bytes, $($script:AcasCalcWeeks.Count) week-block(s))" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="weekly HTML write failed: $writeErr" } }
            }
            $row = @{ Report='ACAS Weekly Export'; Weeks=$script:AcasCalcWeeks.Count; Bytes=$bytes; Html=$html; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; Weeks=$row.Weeks; Bytes=$row.Bytes })
            & $send @{ type='status'; text="Rendered weekly HTML ($bytes bytes)." }
            return @{ rows=@($row); summary=@{ total=1; weeks=$script:AcasCalcWeeks.Count; bytes=$bytes; html=$html } }
        }

        # -------------------------------------------------------------------
        'weekly-export-csv' {
            $enclave = [string]$Params['Enclave']
            $weekSel = ([string]$Params['Week']).Trim()
            $allWeeks = $false; if ($Params['AllWeeks']) { $allWeeks = [bool]$Params['AllWeeks'] }
            if ($script:AcasCalcWeeks.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No weekly data parsed. Run Weekly Export Parse first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $candidates = @($script:AcasCalcWeeks | Where-Object {
                [string]::IsNullOrWhiteSpace($enclave) -or $_.Enclave -eq $enclave
            })
            if ($candidates.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text="No weeks match enclave '$enclave'." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $outPath = [string]$Params['OutputPath']

            if ($allWeeks) {
                # One CSV per non-empty week, safe per-week filenames (desktop
                # btnExportAllCsv:7561-7581 - weeks with no scan rows skipped).
                $exportable = @($candidates | Where-Object { $_.Scans.Count -gt 0 })
                if ($exportable.Count -eq 0) {
                    & $send @{ type='log'; level='warn'; text='No non-empty weeks to export.' }
                    return @{ rows=@(); summary=@{ total=0 } }
                }
                $outDir = ''
                if ($outPath) {
                    if (-not (Test-JanetUncReachable -Path $outPath)) {
                        & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                    } else {
                        if (Test-Path -LiteralPath $outPath -PathType Container) { $outDir = $outPath }
                        else { $outDir = Split-Path -Parent $outPath }
                        if ([string]::IsNullOrWhiteSpace($outDir)) {
                            $outDir = ''
                            & $send @{ type='log'; level='warn'; text='OutputPath has no folder component; per-week CSVs returned inline only.' }
                        }
                    }
                }
                $rows = New-Object System.Collections.ArrayList
                $writtenCount = 0; $i = 0
                foreach ($w in $exportable) {
                    $i++
                    $csv = Export-WeeklyToCsvText -Week $w
                    $bytes = [System.Text.Encoding]::UTF8.GetByteCount($csv)
                    $written = ''; $writeErr = $null
                    if ($outDir) {
                        $file = Join-Path $outDir (Get-WeeklySafeFileName -Week $w)
                        try { [System.IO.File]::WriteAllText($file, $csv, [System.Text.UTF8Encoding]::new($true)); $written = $file; $writtenCount++ } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed for $($w.Enclave) $($w.DateRange): $writeErr" } }
                        if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $file); result='Success'; itemCount=1; detail="Weekly CSV written for $($w.Enclave) $($w.DateRange) ($bytes bytes)" } }
                        else { & $send @{ type='audit'; action='TouchHost'; target=$file; result='Failure'; itemCount=0; detail="weekly CSV write failed for $($w.Enclave) $($w.DateRange): $writeErr" } }
                    }
                    $row = @{ Report="Weekly CSV ($($w.Enclave) $($w.DateRange))"; Weeks=1; Bytes=$bytes; Csv=$csv; Path=$written }
                    [void]$rows.Add($row)
                    & $send (@{ type='row' } + @{ Report=$row.Report; Weeks=$row.Weeks; Bytes=$row.Bytes })
                    & $send @{ type='progress'; done=$i; total=$exportable.Count }
                }
                $skippedEmpty = $candidates.Count - $exportable.Count
                $emptyNote = if ($skippedEmpty -gt 0) { " $skippedEmpty empty week(s) skipped." } else { '' }
                if ($outDir) {
                    & $send @{ type='status'; text="Exported $writtenCount of $($exportable.Count) week CSV(s) to $outDir.$emptyNote" }
                } else {
                    & $send @{ type='status'; text="Rendered $($exportable.Count) week CSV(s) inline (no usable OutputPath).$emptyNote" }
                }
                return @{ rows=@($rows); summary=@{ total=$exportable.Count; written=$writtenCount; skippedEmpty=$skippedEmpty } }
            }

            $week = $null
            if ($weekSel) {
                $week = @($candidates | Where-Object { $_.DateRange -eq $weekSel }) | Select-Object -First 1
                if (-not $week) {
                    # forgiving fallback: case-insensitive substring of the label
                    $week = @($candidates | Where-Object { $_.DateRange -and $_.DateRange.IndexOf($weekSel, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }) | Select-Object -First 1
                }
                if (-not $week) {
                    $avail = (@($candidates | ForEach-Object { "$($_.Enclave) '$($_.DateRange)'" }) -join '; ')
                    & $send @{ type='log'; level='warn'; text="No parsed week matches '$weekSel'. Available: $avail" }
                    return @{ rows=@(); summary=@{ total=0 } }
                }
            } else {
                $week = $candidates[0]
            }
            & $send @{ type='status'; text="Exporting weekly CSV for $($week.Enclave) $($week.DateRange)..." }
            $csv = Export-WeeklyToCsvText -Week $week
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($csv)
            $written = ''; $writeErr = $null
            if ($outPath) {
                # audit 2026-07-24: TCP-445 pre-gate, same idiom as the AllWeeks branch above
                # and cora-render-html. This single-week write was the LAST operator-supplied
                # output write in the module with no gate, so a dead UNC path blocked the
                # whole serialized reports runspace on the SMB timeout instead of failing fast.
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $csv, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=1; detail="Weekly CSV written for $($week.Enclave) $($week.DateRange) ($bytes bytes)" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="weekly CSV write failed: $writeErr" } }
            }
            $row = @{ Report="Weekly CSV ($($week.Enclave) $($week.DateRange))"; Weeks=1; Bytes=$bytes; Csv=$csv; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; Weeks=$row.Weeks; Bytes=$row.Bytes })
            $others = $candidates.Count - 1
            $otherNote = if ($others -gt 0) { " $others other parsed week(s) available - set Week or AllWeeks to export them." } else { '' }
            & $send @{ type='status'; text="Exported weekly CSV for $($week.Enclave) $($week.DateRange) ($bytes bytes).$otherNote" }
            return @{ rows=@($row); summary=@{ total=1; bytes=$bytes; csv=$csv } }
        }

        # -------------------------------------------------------------------
        'cora-build-summary' {
            Set-JanetNetworkDeviceCount -Params $Params
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
            }
            & $send @{ type='status'; text='Building CORA summary...' }
            $summary = Build-CoraSummary
            $rows = New-Object System.Collections.ArrayList
            $add = { param($metric,$value) $r=@{ Metric=$metric; Value=$value }; [void]$rows.Add($r); & $send (@{ type='row' } + $r) }
            & $add 'Open Findings' $summary.ConsideredFindings
            & $add 'Total Loaded' $summary.TotalLoaded
            & $add 'Unique Hosts' $summary.UniqueHosts
            & $add 'Vulns Per Host (VPH)' $summary.Vph
            & $add 'Critical' $summary.SevCount['Critical']
            & $add 'High' $summary.SevCount['High']
            & $add 'Medium' $summary.SevCount['Medium']
            & $add 'Low' $summary.SevCount['Low']
            & $add 'Info' $summary.SevCount['Info']
            $netPctStr = if ($summary.NetworkPct -is [double] -and -not [double]::IsNaN($summary.NetworkPct)) { "$($summary.NetworkPct)%" } else { 'n/a' }
            & $add 'Network %' $netPctStr
            & $add 'Top Vulns (count)' $summary.TopVulns.Count
            & $send @{ type='status'; text="CORA summary: $($summary.ConsideredFindings) open findings across $($summary.UniqueHosts) hosts." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; cora=$summary } }
        }

        # -------------------------------------------------------------------
        'cora-render-html' {
            Set-JanetNetworkDeviceCount -Params $Params
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
            }
            & $send @{ type='status'; text='Building CORA summary + rendering commander brief...' }
            $summary = Build-CoraSummary
            $html = Render-CoraVulnHtml -Summary $summary
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($html)
            $outPath = [string]$Params['OutputPath']
            $written = ''; $writeErr = $null
            if ($outPath) {
                # audit 2026-07-23: TCP-445 pre-gate (same idiom as weekly-render-html) so a
                # dead UNC share fails fast instead of hanging the serialized reports runspace.
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $html, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=$summary.UniqueHosts; detail="CORA commander brief written ($bytes bytes, $($summary.UniqueHosts) host(s))" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="CORA HTML write failed: $writeErr" } }
            }
            $row = @{ Report='CORA Commander Brief'; UniqueHosts=$summary.UniqueHosts; Bytes=$bytes; Html=$html; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; UniqueHosts=$row.UniqueHosts; Bytes=$row.Bytes })
            & $send @{ type='status'; text="Rendered CORA HTML ($bytes bytes)." }
            return @{ rows=@($row); summary=@{ total=1; uniqueHosts=$summary.UniqueHosts; bytes=$bytes; html=$html } }
        }

        # -------------------------------------------------------------------
        'remediation-refresh' {
            Set-JanetNetworkDeviceCount -Params $Params
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
            }
            & $send @{ type='status'; text='Building remediation plan...' }
            $plan = Build-RemediationPlan

            # Per-app aggregate (TargetCount = unique hosts behind, severity counts,
            # KevHosts = distinct hosts with a KEV/known-exploited finding in the bucket).
            $appAgg = @{}
            foreach ($r in $plan.Rows) {
                if ($r.Status -eq 'Pushed' -or $r.Status -eq 'Skipped') { continue }
                if (-not $appAgg.ContainsKey($r.App)) {
                    $appAgg[$r.App] = @{ App=$r.App; Hosts=(New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)); KevHosts=(New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)); Crit=0; High=0; Target=$r.TargetVersion }
                }
                $a = $appAgg[$r.App]
                # loop14 (item 11): TargetCount / KevCount / the affected-host list count
                # DISTINCT hosts - key on the normalized audit key so a short+FQDN pair of one
                # host is one host (agrees with CORA + the loop-13 headline fixes). The list is
                # then shown as normalized keys, consistent with CORA's presentation.
                $r_hk = Get-ReportsAuditHostKey ([string]$r.Hostname)
                if ($r_hk) { [void]$a.Hosts.Add($r_hk); if ($r.HasKev) { [void]$a.KevHosts.Add($r_hk) } }
                if ($r.MaxSeverity -eq 'Critical') { $a.Crit++ }
                elseif ($r.MaxSeverity -eq 'High') { $a.High++ }
                if (-not $a.Target -and $r.TargetVersion) { $a.Target = $r.TargetVersion }
            }

            $rows = New-Object System.Collections.ArrayList
            $kevBuckets = 0
            $order = @('Chrome','Edge','Office','Defender','KB','Other')
            foreach ($app in $order) {
                if (-not $appAgg.ContainsKey($app)) { continue }
                $a = $appAgg[$app]
                if ($a.KevHosts.Count -gt 0) { $kevBuckets++ }
                $row = @{
                    Host=$app; App=$app
                    TargetCount=$a.Hosts.Count
                    TargetVersion=$(if ($a.Target) { $a.Target } else { '(latest)' })
                    CriticalCount=$a.Crit
                    HighCount=$a.High
                    KevCount=$a.KevHosts.Count
                    Hosts=(@($a.Hosts | Sort-Object) -join "`n")   # affected host list for view Copy/Export (#9)
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
            }
            # Dynamic Other-vuln group cards (>= 10 hosts).
            foreach ($g in $plan.OtherGroups) {
                if ($g.KevHostCount -gt 0) { $kevBuckets++ }
                $row = @{
                    Host="Plugin $($g.PluginID)"
                    App="Other: $($g.VulnName)"
                    TargetCount=$g.HostCount
                    TargetVersion=$(if ($g.TargetVersion) { $g.TargetVersion } else { '-' })
                    CriticalCount=$(if ($g.MaxSeverity -eq 'Critical') { $g.HostCount } else { 0 })
                    HighCount=$(if ($g.MaxSeverity -eq 'High') { $g.HostCount } else { 0 })
                    KevCount=$g.KevHostCount
                    Hosts=(@($g.Hosts) -join "`n")   # affected host list for view Copy/Export (#9)
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
            }
            $kevNote = if ($kevBuckets -gt 0) { " ($kevBuckets with KEV)" } else { '' }
            & $send @{ type='status'; text="Remediation plan: $($rows.Count) bucket(s)/group(s)$kevNote." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; appSummary=$plan.Summary; otherGroups=$plan.OtherGroups.Count; kevBuckets=$kevBuckets } }
        }

        # -------------------------------------------------------------------
        # Remediation Router (feature #8): correlate the loaded OPEN findings to the
        # concrete JANET tool/action/profile that clears each Categorize-Finding
        # bucket (mapping table: $script:RemediationRouteMap). Read-only - no remote
        # calls, no audit rows (session START/END is logged server-side).
        'remediation-route' {
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Correlating open findings to JANET remediation routes...' }

            # Group every OPEN (not-yet-Patched, incl. NOT OUR PATCH -> upr) finding by
            # its Categorize-Finding bucket - promoting Defender out of Other by vuln
            # name, exactly like Build-RemediationPlan (Defender split, line ~895).
            $buckets = @{}
            $totalOpen = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $totalOpen++
                # Promote genuine unquoted-service-path findings (by vuln name/solution)
                # into their own routable bucket - the broad 'Registry Fix' category is
                # otherwise NOT safe to run the ImagePath-mutating profile against, so it
                # falls through to manual review (no route map entry).
                # audit 2026-07-23: classifier extracted to Get-ReportsRouteBucket (was
                # copy-pasted across five actions).
                $bucket = Get-ReportsRouteBucket $f
                if (-not $buckets.ContainsKey($bucket)) {
                    $buckets[$bucket] = @{
                        Bucket       = $bucket
                        FindingCount = 0
                        Hosts        = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                        HostKeys     = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                        Plugins      = New-Object System.Collections.ArrayList
                        PluginSeen   = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                    }
                }
                $b = $buckets[$bucket]
                $b.FindingCount++
                # audit 2026-07-23: HostCount counts DISTINCT hosts on the normalized audit
                # key (short+FQDN of one host = one, like the sibling rollups); the raw-name
                # Hosts set stays as-is for the display list + Send-to-tool handoff.
                if (-not [string]::IsNullOrWhiteSpace([string]$f.Hostname)) {
                    [void]$b.Hosts.Add([string]$f.Hostname)
                    [void]$b.HostKeys.Add((Get-ReportsAuditHostKey ([string]$f.Hostname)))
                }
                $plgId = [string]$f.PluginID
                if (-not [string]::IsNullOrWhiteSpace($plgId) -and $b.PluginSeen.Add($plgId)) { [void]$b.Plugins.Add($plgId) }
            }

            # Attach the route (or $null = manual review) and sort: routable buckets
            # first, then by finding count (desc), then bucket name.
            $agg = New-Object System.Collections.ArrayList
            foreach ($key in $buckets.Keys) {
                $route = if ($script:RemediationRouteMap.ContainsKey($key)) { $script:RemediationRouteMap[$key] } else { $null }
                [void]$agg.Add(@{ B=$buckets[$key]; Route=$route })
            }
            $sorted = @($agg | Sort-Object -Property `
                @{ Expression = { if ($_.Route) { 0 } else { 1 } } }, `
                @{ Expression = { -$_.B.FindingCount } }, `
                @{ Expression = { $_.B.Bucket } })

            $rows = New-Object System.Collections.ArrayList
            $routableFindings = 0
            $routableBuckets  = 0
            $exceptionFindings = 0
            $exceptionBuckets  = 0
            $hostCap   = 40   # capped host display; full list ships in Hosts for the view handoff
            $pluginCap = 8
            foreach ($item in $sorted) {
                $b = $item.B; $route = $item.Route
                $hostList = @($b.Hosts | Sort-Object)
                $hostsDisplay = if ($hostList.Count -gt $hostCap) {
                    (@($hostList | Select-Object -First $hostCap) -join ', ') + " ... (+$($hostList.Count - $hostCap) more)"
                } else { ($hostList -join ', ') }
                $sampleP = @($b.Plugins | Select-Object -First $pluginCap)
                $sampleStr = if ($b.Plugins.Count -gt $pluginCap) { ($sampleP -join ', ') + " ... (+$($b.Plugins.Count - $pluginCap))" } else { ($sampleP -join ', ') }
                $isAct = Test-JanetWebRouteActionable $route
                $isExc = [bool]($route -and $route.IsException)
                if ($isAct)      { $routableFindings  += $b.FindingCount; $routableBuckets++ }
                elseif ($isExc)  { $exceptionFindings += $b.FindingCount; $exceptionBuckets++ }
                $row = @{
                    Host          = $b.Bucket
                    Bucket        = $b.Bucket
                    Tool          = $(if ($isAct) { $route.ToolId } else { '-' })
                    ToolId        = $(if ($isAct) { $route.ToolId } else { '' })
                    Action        = $(if ($route) { $route.Action } else { 'Manual review' })
                    ActionId      = $(if ($isAct) { $route.ActionId } else { '' })
                    Profile       = $(if ($isAct -and $route.Profile) { $route.Profile } else { '-' })
                    FindingCount  = $b.FindingCount
                    HostCount     = $b.HostKeys.Count        # audit 2026-07-23: distinct normalized hosts (see above)
                    Hosts         = ($hostList -join "`n")   # full list for the view's Send-to-tool handoff
                    HostsDisplay  = $hostsDisplay
                    SamplePlugins = $sampleStr
                    Routable      = [bool]$isAct
                    IsException   = [bool]$isExc
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
            }

            $routablePct = if ($totalOpen -gt 0) { [math]::Round(($routableFindings / $totalOpen) * 100, 1) } else { 0 }
            $manualFindings = $totalOpen - $routableFindings - $exceptionFindings
            $excNote = if ($exceptionFindings -gt 0) { " $exceptionFindings finding(s) are tracked exceptions (no local fix / POA&M)." } else { '' }
            & $send @{ type='status'; text="Router: $($rows.Count) bucket(s), $routableBuckets routable ($routablePct% of $totalOpen open finding(s)); $manualFindings finding(s) need manual review.$excNote" }
            return @{ rows=@($rows); summary=@{
                total=$rows.Count; openFindings=$totalOpen
                routableBuckets=$routableBuckets; routableFindings=$routableFindings
                exceptionBuckets=$exceptionBuckets; exceptionFindings=$exceptionFindings
                manualFindings=$manualFindings; routablePct=$routablePct
            } }
        }

        # -------------------------------------------------------------------
        'remediation-plan' {
            # PER-HOST remediation work queue. Same bucketing as remediation-route,
            # but grouped by HOST so an operator sees exactly what to run on each box.
            # READ-ONLY: emits the plan only; execution happens in the mapped tools
            # under their own admin-session + confirm + DNS/self guards (no new path).
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Building per-host remediation work queue...' }
            # audit 2026-07-23: the unused local $sevRank copy is gone (severity here is
            # tallied by the switch below); the shared map lives at $script:SeverityRank.
            $hosts = @{}   # normalized host key -> aggregate
            $totalOpen = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $hn = [string]$f.Hostname
                if ([string]::IsNullOrWhiteSpace($hn)) { continue }
                $totalOpen++
                # audit 2026-07-23: classifier extracted to Get-ReportsRouteBucket (was
                # copy-pasted across five actions).
                $bucket = Get-ReportsRouteBucket $f
                # audit 2026-07-23: ONE work-queue row per physical host - key on the
                # normalized audit key (short+FQDN of one host fold to one, like the
                # sibling rollups); Host keeps the first-seen raw name for display.
                $hk = Get-ReportsAuditHostKey $hn
                if (-not $hosts.ContainsKey($hk)) {
                    $hosts[$hk] = @{
                        Host=$hn; Findings=0; Crit=0; High=0; Med=0; Low=0; Kev=0
                        Routable=0; Manual=0; Exception=0
                        Routes = New-Object System.Collections.ArrayList        # ordered distinct route labels
                        RouteSeen = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                        ManualBuckets = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                        ExceptionBuckets = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                    }
                }
                $h = $hosts[$hk]
                $h.Findings++
                switch ([string]$f.Severity) { 'Critical' { $h.Crit++ } 'High' { $h.High++ } 'Medium' { $h.Med++ } 'Low' { $h.Low++ } }
                if ([bool]$f.InKEV) { $h.Kev++ }
                $route = if ($script:RemediationRouteMap.ContainsKey($bucket)) { $script:RemediationRouteMap[$bucket] } else { $null }
                if (Test-JanetWebRouteActionable $route) {
                    $h.Routable++
                    $label = if ($route.Profile) { "$($route.ToolId): $($route.Profile)" } else { "$($route.ToolId): $($route.Action)" }
                    if ($h.RouteSeen.Add($label)) { [void]$h.Routes.Add($label) }
                } elseif ($route -and $route.IsException) {
                    $h.Exception++
                    [void]$h.ExceptionBuckets.Add($bucket)
                } else {
                    $h.Manual++
                    [void]$h.ManualBuckets.Add($bucket)
                }
            }

            # Worst hosts first: KEV desc, then Critical desc, then total findings desc.
            $ordered = @($hosts.Values | Sort-Object -Property `
                @{ Expression = { $_.Kev }; Descending = $true }, `
                @{ Expression = { $_.Crit }; Descending = $true }, `
                @{ Expression = { $_.Findings }; Descending = $true }, `
                @{ Expression = { $_.Host } })

            $rows = New-Object System.Collections.ArrayList
            $hostsWithRoutes = 0; $idx = 0
            foreach ($h in $ordered) {
                $idx++
                if ($h.Routable -gt 0) { $hostsWithRoutes++ }
                $planParts = @($h.Routes)
                if ($h.ManualBuckets.Count -gt 0) { $planParts += "manual: " + ((@($h.ManualBuckets | Sort-Object)) -join ', ') }
                if ($h.ExceptionBuckets.Count -gt 0) { $planParts += "exception (no local fix): " + ((@($h.ExceptionBuckets | Sort-Object)) -join ', ') }
                $sevStr = "$($h.Crit)/$($h.High)/$($h.Med)/$($h.Low)"
                $row = @{
                    _rk       = $h.Host
                    Host      = $h.Host
                    Findings  = $h.Findings
                    Sev       = $sevStr
                    KEV       = $h.Kev
                    Routable  = $h.Routable
                    Manual    = $h.Manual
                    Exception = $h.Exception
                    Plan      = ($planParts -join ' · ')
                }
                [void]$rows.Add($row)
                if ($idx -le 800) { & $send (@{ type='row' } + $row) }
                if (($idx % 200) -eq 0) { & $send @{ type='progress'; done=$idx; total=$ordered.Count } }
            }
            & $send @{ type='progress'; done=$ordered.Count; total=$ordered.Count }
            if ($ordered.Count -gt 800) { & $send @{ type='log'; level='info'; text="Showing first 800 of $($ordered.Count) hosts in the grid." } }
            & $send @{ type='status'; text="Remediation plan: $($ordered.Count) host(s), $hostsWithRoutes with a one-click route, over $totalOpen open finding(s)." }
            return @{ rows=@($rows); summary=@{ total=$ordered.Count; hostsWithRoutes=$hostsWithRoutes; openFindings=$totalOpen } }
        }

        # -------------------------------------------------------------------
        'kb-needed' {
            # Extract the exact KBs the loaded findings name, roll up by KB
            # (supersedence: one cumulative clears many hosts), and produce a per-host
            # Host,KB list for the WPT KB Installer + a copy list for Patch Content.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Extracting KB ids from the loaded findings...' }
            $sevRank = $script:SeverityRank   # audit 2026-07-23: shared module-scope map
            $kbMap = @{}                 # KB -> aggregate
            $perHost = @{}               # host -> HashSet of KBs (for the WPT handoff)
            $openFindings = 0; $withKb = 0; $noKb = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $openFindings++
                $kbs = @(Get-ReportsKbsFromText ("$($f.VulnName) $($f.Solution)"))
                if ($kbs.Count -eq 0) { $noKb++; continue }
                $withKb++
                # loop13: per-KB host count + the per-host KB set both count DISTINCT hosts -
                # key on the normalized audit key so short+FQDN of one host folds to one.
                $hn = Get-ReportsAuditHostKey ([string]$f.Hostname)
                $sev = [string]$f.Severity
                $isKev = [bool]$f.InKEV
                foreach ($kb in $kbs) {
                    if (-not $kbMap.ContainsKey($kb)) {
                        $entry = @{ KB = $kb; Findings = 0; MaxSev = 0; SevName = ''; Kev = $false }
                        $entry.Hosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        $entry.Plugins = New-Object System.Collections.ArrayList
                        $entry.PluginSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        $kbMap[$kb] = $entry
                    }
                    $k = $kbMap[$kb]
                    $k.Findings = [int]$k.Findings + 1
                    if ($hn) { [void]$k.Hosts.Add($hn) }
                    if ($isKev) { $k.Kev = $true }
                    $rank = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 0 }
                    if ($rank -gt $k.MaxSev) { $k.MaxSev = $rank; $k.SevName = $sev }
                    $plg = [string]$f.PluginID
                    if ($plg -and $k.PluginSeen.Add($plg)) { [void]$k.Plugins.Add($plg) }
                    if ($hn) {
                        if (-not $perHost.ContainsKey($hn)) {
                            $perHost[$hn] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        }
                        [void]$perHost[$hn].Add($kb)
                    }
                }
            }
            # Rank: KEV first, then most hosts (supersedence payoff), then worst severity.
            $ordered = @($kbMap.Values | Sort-Object -Property `
                @{ Expression = { [bool]$_.Kev }; Descending = $true }, `
                @{ Expression = { $_.Hosts.Count }; Descending = $true }, `
                @{ Expression = { $_.MaxSev }; Descending = $true }, `
                @{ Expression = { $_.KB } })
            $rows = New-Object System.Collections.ArrayList
            foreach ($k in $ordered) {
                $sampleP = @($k.Plugins | Select-Object -First 6)
                $sampleStr = if ($k.Plugins.Count -gt 6) { ($sampleP -join ', ') + " (+$($k.Plugins.Count - 6))" } else { ($sampleP -join ', ') }
                $row = @{
                    _rk=$k.KB; KB=$k.KB; Hosts=$k.Hosts.Count
                    Severity=$(if ($k.SevName) { $k.SevName } else { 'n/a' })
                    KEV=$(if ($k.Kev) { 'KEV' } else { '' })
                    Findings=$k.Findings; SamplePlugins=$sampleStr
                }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            # Handoff artifacts: unique KB list (Patch Content) + per-host Host,KB CSV (WPT).
            $kbList = (@($ordered | ForEach-Object { $_.KB }) -join "`n")
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('Host,KB')
            foreach ($hn in (@($perHost.Keys) | Sort-Object)) {
                foreach ($kb in (@($perHost[$hn]) | Sort-Object)) { [void]$sb.AppendLine("$(ConvertTo-ReportsCsvCell $hn),$(ConvertTo-ReportsCsvCell $kb)") }
            }
            $kevKbs = @($ordered | Where-Object { $_.Kev }).Count
            & $send @{ type='status'; text="KBs needed: $($ordered.Count) distinct KB(s) ($kevKbs KEV) across $($perHost.Count) host(s); $withKb finding(s) name a KB, $noKb have no KB in the scan text (use the Remediation Planner for those)." }
            return @{ rows=@($rows); summary=@{
                total=$ordered.Count; kevKbs=$kevKbs; hosts=$perHost.Count
                openFindings=$openFindings; findingsWithKb=$withKb; findingsNoKb=$noKb
                kbList=$kbList; perHostCsv=$sb.ToString().TrimEnd()
            } }
        }

        # -------------------------------------------------------------------
        'thirdparty-catalog' {
            # The ~99% of findings that do NOT name a KB are third-party /
            # version-upgrade product vulns (Chrome, Firefox, Adobe, Java, 7-Zip,
            # ...). kb-needed covers the KB ones; this rolls the REST up by PRODUCT so
            # the operator sees the biggest vuln-reduction levers. The Route column
            # reuses the SAME Categorize-Finding + $script:RemediationRouteMap mapping
            # the Router / Planner use, so a product's route stays consistent with
            # them. READ-ONLY: no remote calls, names products only.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Cataloging third-party (non-KB) products from the loaded findings...' }
            $sevRank = $script:SeverityRank   # audit 2026-07-23: shared module-scope map
            $prodMap = @{}                 # product -> aggregate
            $allHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $thirdPartyFindings = 0; $unclassified = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $text = "$($f.VulnName) $($f.Solution)"
                # KB findings belong to kb-needed - skip anything that names a KB.
                if (@(Get-ReportsKbsFromText $text).Count -gt 0) { continue }
                $thirdPartyFindings++
                $product = Get-ReportsThirdPartyProduct $text
                if ([string]::IsNullOrWhiteSpace($product)) { $unclassified++; continue }
                # Route via the SAME bucket mapping the Router / Planner use (Defender
                # + unquoted-service-path promotion, else the finding's Category).
                # audit 2026-07-23: classifier extracted to Get-ReportsRouteBucket (was
                # copy-pasted across five actions).
                $bucket = Get-ReportsRouteBucket $f
                $route = if ($script:RemediationRouteMap.ContainsKey($bucket)) { $script:RemediationRouteMap[$bucket] } else { $null }
                $hn = [string]$f.Hostname
                $sev = [string]$f.Severity
                $isKev = [bool]$f.InKEV
                if (-not $prodMap.ContainsKey($product)) {
                    $entry = @{ Product = $product; Findings = 0; MaxSev = 0; SevName = ''; Kev = $false; MaxVer = $null; MaxVerText = '' }
                    $entry.Hosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    $entry.HostKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    $entry.RouteCounts = @{}      # route label -> finding count (route = plurality)
                    $entry.RouteObjs   = @{}      # route label -> structured route ($null for manual/none)
                    $prodMap[$product] = $entry
                }
                $p = $prodMap[$product]
                $p.Findings = [int]$p.Findings + 1
                # audit 2026-07-23: host COUNTS key on the normalized audit key (short+FQDN
                # of one host = one, like the sibling rollups); the raw-name Hosts set stays
                # for the HostsList handoff below.
                if ($hn) {
                    [void]$p.Hosts.Add($hn)
                    [void]$p.HostKeys.Add((Get-ReportsAuditHostKey $hn))
                    [void]$allHosts.Add((Get-ReportsAuditHostKey $hn))
                }
                if ($isKev) { $p.Kev = $true }
                $rank = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 0 }
                if ($rank -gt $p.MaxSev) { $p.MaxSev = $rank; $p.SevName = $sev }
                # Tally the route per finding; the product's Route is the plurality
                # route (so a handful of mis-bucketed findings can't hijack the row -
                # the bulk of a product's findings decides its route).
                $routeAct = Test-JanetWebRouteActionable $route
                $label = if ($routeAct) { if ($route.Profile) { "$($route.ToolId): $($route.Profile)" } else { "$($route.ToolId): $($route.Action)" } } else { 'manual / none' }
                if (-not $p.RouteCounts.ContainsKey($label)) { $p.RouteCounts[$label] = 0 }
                $p.RouteCounts[$label] = [int]$p.RouteCounts[$label] + 1
                # Keep the STRUCTURED route (tool/action/profile) beside its label so the
                # plurality winner below can surface concrete ids for the handoff - taken
                # from the SAME $script:RemediationRouteMap the Router/Planner resolve, so
                # the catalog can never drift from a parallel map.
                if (-not $p.RouteObjs.ContainsKey($label)) { $p.RouteObjs[$label] = $(if ($routeAct) { $route } else { $null }) }
                # Representative FIXED/target version: the highest version token in the
                # finding text (Tenable "Upgrade to X" lines put the target as highest).
                $vers = @(Get-VersionsFromText $text)
                if ($vers.Count -gt 0) {
                    $cand = [string]$vers[0]
                    $candV = Convert-VersionForSort $cand
                    if ($null -eq $p.MaxVer -or $candV -gt $p.MaxVer) { $p.MaxVer = $candV; $p.MaxVerText = $cand }
                }
            }
            # Rank: KEV first, then most hosts, then worst severity (supersedence-style).
            $ordered = @($prodMap.Values | Sort-Object -Property `
                @{ Expression = { [bool]$_.Kev }; Descending = $true }, `
                @{ Expression = { $_.HostKeys.Count }; Descending = $true }, `
                @{ Expression = { $_.MaxSev }; Descending = $true }, `
                @{ Expression = { $_.Product } })
            $rows = New-Object System.Collections.ArrayList
            $kevProducts = 0; $routable = 0; $manual = 0
            foreach ($p in $ordered) {
                if ($p.Kev) { $kevProducts++ }
                # Plurality route: most-common route across the product's findings; on a
                # tie a real route beats 'manual / none'.
                $bestLabel = 'manual / none'; $bestCount = -1
                foreach ($lk in $p.RouteCounts.Keys) {
                    $c = [int]$p.RouteCounts[$lk]
                    if ($c -gt $bestCount -or ($c -eq $bestCount -and $bestLabel -eq 'manual / none' -and $lk -ne 'manual / none')) {
                        $bestCount = $c; $bestLabel = $lk
                    }
                }
                $isRoutable = ($bestLabel -ne 'manual / none')
                if ($isRoutable) { $routable++ } else { $manual++ }
                # Structured route for the winning label + the FULL affected host list, so
                # the view's "Remediate Selected" handoff can prefill targets and open the
                # mapped tool without a second round-trip. HostsList is a newline string
                # (mirrors the remediation-route row's Hosts) - the count stays in Hosts.
                $bestRoute = if ($p.RouteObjs.ContainsKey($bestLabel)) { $p.RouteObjs[$bestLabel] } else { $null }
                $hostList  = @($p.Hosts | Sort-Object)
                $row = @{
                    _rk=$p.Product; Product=$p.Product; Hosts=$p.HostKeys.Count   # audit 2026-07-23: distinct normalized hosts
                    Severity=$(if ($p.SevName) { $p.SevName } else { 'n/a' })
                    KEV=$(if ($p.Kev) { 'KEV' } else { '' })
                    FixedVersion=$(if ($p.MaxVerText) { $p.MaxVerText } else { '-' })
                    Route=$bestLabel
                    Findings=$p.Findings
                    # Non-column handoff fields (read per-row by reports.view.js):
                    Routable=[bool]$bestRoute
                    RouteTool=$(if ($bestRoute) { [string]$bestRoute.ToolId } else { '' })
                    RouteActionId=$(if ($bestRoute) { [string]$bestRoute.ActionId } else { '' })
                    RouteAction=$(if ($bestRoute) { [string]$bestRoute.Action } else { '' })
                    RouteProfile=$(if ($bestRoute -and $bestRoute.Profile) { [string]$bestRoute.Profile } else { '' })
                    HostsList=($hostList -join "`n")
                }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            & $send @{ type='status'; text="Third-party catalog: $($ordered.Count) product(s) ($kevProducts KEV) across $($allHosts.Count) host(s); $routable routable via a JANET tool, $manual manual/none. $thirdPartyFindings non-KB finding(s) total ($unclassified not tied to a known product - the KB ones are in KBs Needed)." }
            return @{ rows=@($rows); summary=@{
                total=$ordered.Count; kevProducts=$kevProducts; hosts=$allHosts.Count
                routable=$routable; manual=$manual; thirdPartyFindings=$thirdPartyFindings
                unclassified=$unclassified
            } }
        }

        # -------------------------------------------------------------------
        'iavm-board' {
            # DoD compliance rollup BY IAVA/IAVM bulletin (the unit the inspector
            # grades), not by raw CVE. Each finding is IAVA-tagged at parse time from
            # the shipped CVE->bulletin map; this groups the OPEN (not Patched) findings
            # by that bulletin id and rolls up hosts / worst severity / KEV / open count
            # / a CVE + plugin sample. Findings with a blank IAVA are NOT grouped - they
            # are counted separately (many plugins map to no bulletin). The parsed scan
            # carries NO per-bulletin compliance/due date (finding fields are Hostname,
            # PluginID, VulnName, Severity, CVE, Category, Status, Solution, InKEV,
            # KevCves, IAVA, FirstSeen, PatchedDate, PatchedBy - FirstSeen is a JANET
            # ledger clock, not a bulletin due date), so this stays a pure counts rollup
            # with no overdue bucketing. READ-ONLY: no remote calls, no writes.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text='Rolling the loaded findings up by IAVA/IAVM bulletin...' }
            $sevRank = $script:SeverityRank   # audit 2026-07-23: shared module-scope map
            $iavaMap = @{}                 # IAVA -> aggregate
            $allHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $findingsWithIava = 0; $findingsNoIava = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $iavaRaw = ([string]$f.IAVA).Trim()
                if ([string]::IsNullOrWhiteSpace($iavaRaw)) { $findingsNoIava++; continue }
                # audit 2026-07-24 (BUG): the IAVA cell is MULTI-VALUE - Get-ReportsIavmTags
                # joins every bulletin a finding's CVEs map to with ', ' (:883). Grouping on
                # the raw cell therefore minted a PHANTOM compound bucket named e.g.
                # "2021-A-0573, 2022-A-0221", and the finding was counted under NEITHER real
                # bulletin - exactly the rows an inspector grades. Split first so the finding
                # contributes to BOTH. findingsWithIava still counts FINDINGS (not bulletin
                # memberships) so the with/no-IAVA pair still sums to the open set.
                $iavas = @($iavaRaw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($iavas.Count -eq 0) { $findingsNoIava++; continue }
                $findingsWithIava++
                # audit 2026-07-23: host tallies (count-only here - no display list) key on
                # the normalized audit key so short+FQDN of one host counts once, agreeing
                # with the sibling rollups.
                $hn = Get-ReportsAuditHostKey ([string]$f.Hostname)
                $sev = [string]$f.Severity
                $isKev = [bool]$f.InKEV
                $rank = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 0 }
                if ($hn) { [void]$allHosts.Add($hn) }
                foreach ($iava in $iavas) {
                    if (-not $iavaMap.ContainsKey($iava)) {
                        $entry = @{ IAVA = $iava; Findings = 0; MaxSev = 0; SevName = ''; Kev = $false }
                        $entry.Hosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        $entry.Cves = New-Object System.Collections.ArrayList
                        $entry.CveSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        $entry.Plugins = New-Object System.Collections.ArrayList
                        $entry.PluginSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                        $iavaMap[$iava] = $entry
                    }
                    $e = $iavaMap[$iava]
                    $e.Findings = [int]$e.Findings + 1
                    if ($hn) { [void]$e.Hosts.Add($hn) }
                    if ($isKev) { $e.Kev = $true }
                    if ($rank -gt $e.MaxSev) { $e.MaxSev = $rank; $e.SevName = $sev }
                    foreach ($mm in [regex]::Matches([string]$f.CVE, '(?i)CVE-\d{4}-\d{4,}')) {
                        $cve = $mm.Value.ToUpper()
                        if ($e.CveSeen.Add($cve)) { [void]$e.Cves.Add($cve) }
                    }
                    $plg = [string]$f.PluginID
                    if ($plg -and $e.PluginSeen.Add($plg)) { [void]$e.Plugins.Add($plg) }
                }
            }
            # Rank: KEV first, then most hosts, then worst severity (same order as kb-needed).
            $ordered = @($iavaMap.Values | Sort-Object -Property `
                @{ Expression = { [bool]$_.Kev }; Descending = $true }, `
                @{ Expression = { $_.Hosts.Count }; Descending = $true }, `
                @{ Expression = { $_.MaxSev }; Descending = $true }, `
                @{ Expression = { $_.IAVA } })
            $rows = New-Object System.Collections.ArrayList
            foreach ($e in $ordered) {
                $sampleC = @($e.Cves | Select-Object -First 4)
                $cveStr = if ($e.Cves.Count -gt 4) { ($sampleC -join ', ') + " (+$($e.Cves.Count - 4))" } else { ($sampleC -join ', ') }
                $sampleP = @($e.Plugins | Select-Object -First 6)
                $plgStr = if ($e.Plugins.Count -gt 6) { ($sampleP -join ', ') + " (+$($e.Plugins.Count - 6))" } else { ($sampleP -join ', ') }
                $row = @{
                    _rk=$e.IAVA; IAVA=$e.IAVA; Hosts=$e.Hosts.Count
                    Severity=$(if ($e.SevName) { $e.SevName } else { 'n/a' })
                    KEV=$(if ($e.Kev) { 'KEV' } else { '' })
                    Findings=$e.Findings; CVEs=$cveStr; Plugins=$plgStr
                }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            $kevIavas = @($ordered | Where-Object { $_.Kev }).Count
            & $send @{ type='status'; text="IAVM board: $($ordered.Count) IAVA bulletin(s) ($kevIavas KEV) across $($allHosts.Count) host(s); $findingsWithIava open finding(s) map to a bulletin, $findingsNoIava carry no IAVA (no CVE->bulletin match - restore/extend JanetLocal\IavmMap.csv to raise coverage)." }
            return @{ rows=@($rows); summary=@{
                total=$ordered.Count; kevIavas=$kevIavas; hosts=$allHosts.Count
                findingsWithIava=$findingsWithIava; findingsNoIava=$findingsNoIava
            } }
        }

        # -------------------------------------------------------------------
        'campaign-create' {
            # Snapshot the loaded OPEN findings into a persisted campaign. READ-ONLY.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $name = ([string]$Params['name']).Trim()
            if ([string]::IsNullOrWhiteSpace($name)) { $name = "Campaign $((Get-Date).ToString('yyyy-MM-dd HHmm'))" }
            $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $hosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $routes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $crit=0;$high=0;$med=0;$low=0;$kev=0;$open=0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched') { continue }
                $open++
                $hn = [string]$f.Hostname
                if ($hn) { [void]$hosts.Add($hn) }
                # Normalized key (FQDN/NetBIOS/case fold to one) so verify can pair the
                # snapshot against a later scan that names the host differently.
                [void]$keys.Add("$(Get-ReportsAuditHostKey $hn)|$($f.PluginID)")
                switch ([string]$f.Severity) { 'Critical' { $crit++ } 'High' { $high++ } 'Medium' { $med++ } 'Low' { $low++ } }
                if ([bool]$f.InKEV) { $kev++ }
                $bucket = Get-ReportsRouteBucket $f   # audit 2026-07-23: extracted classifier (was copy-pasted across five actions)
                $r = if ($script:RemediationRouteMap.ContainsKey($bucket)) { $script:RemediationRouteMap[$bucket] } else { $null }
                if (Test-JanetWebRouteActionable $r) {
                    [void]$routes.Add($(if ($r.Profile) { "$($r.ToolId): $($r.Profile)" } else { "$($r.ToolId): $($r.Action)" }))
                }
            }
            $id = [guid]::NewGuid().ToString('N')
            $campaign = @{
                id = $id; name = $name
                createdUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                createdBy = (Get-ReportsCleanUser)
                status = 'open'
                openFindings = $open; kev = $kev
                severity = @{ critical=$crit; high=$high; medium=$med; low=$low }
                hosts = @($hosts | Sort-Object)
                routes = @($routes | Sort-Object)
                findingKeys = @($keys)
            }
            $save = Save-ReportsCampaign -Campaign $campaign
            if (-not $save.Written) {
                & $send @{ type='error'; text="Campaign NOT saved: $($save.Error)" }
                return @{ rows=@(); summary=@{ total=0; saveError=$true } }
            }
            $rows = New-Object System.Collections.ArrayList
            foreach ($kv in @(
                @{ Field='Name'; Value=$name }, @{ Field='Campaign ID'; Value=$id },
                @{ Field='Open findings'; Value=[string]$open }, @{ Field='KEV findings'; Value=[string]$kev },
                @{ Field='Severity (C/H/M/L)'; Value="$crit/$high/$med/$low" },
                @{ Field='Affected hosts'; Value=[string]$hosts.Count },
                @{ Field='Mapped remediations'; Value=(@($routes | Sort-Object) -join ' · ') },
                @{ Field='Saved to'; Value=$save.Path }
            )) { [void]$rows.Add($kv); & $send (@{ type='row' } + $kv) }
            & $send @{ type='audit'; action='TouchHost'; target="Create campaign '$name'"; result='Success'; itemCount=$open; detail="$open open finding(s), $($hosts.Count) host(s), $kev KEV; id=$id" }
            & $send @{ type='status'; text="Campaign '$name' saved: $open open finding(s) over $($hosts.Count) host(s), $kev KEV. Re-import the next scan to prove closure." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; id=$id; openFindings=$open; kev=$kev; hosts=$hosts.Count } }
        }

        # -------------------------------------------------------------------
        'campaign-list' {
            $c = Get-ReportsCampaigns
            if (-not $c.Ok) { & $send @{ type='log'; level='warn'; text="Campaign store unreadable ($($c.Source))." } }
            $rows = New-Object System.Collections.ArrayList
            foreach ($cam in $c.Campaigns) {
                $created = ''
                try { $d=[datetime]::MinValue; if ([datetime]::TryParse([string]$cam.createdUtc, [ref]$d)) { $created = $d.ToLocalTime().ToString('yyyy-MM-dd HH:mm') } } catch {}
                $hostCount = 0; if ($cam.PSObject.Properties['hosts'] -and $cam.hosts) { $hostCount = @($cam.hosts).Count }
                $row = @{
                    _rk=[string]$cam.id
                    Name=[string]$cam.name; Created=$created; Status=[string]$cam.status
                    OpenFindings=[string]$cam.openFindings; KEV=[string]$cam.kev; Hosts=[string]$hostCount
                }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            & $send @{ type='status'; text="$($rows.Count) saved campaign(s) - source: $($c.Source)." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; source=$c.Source } }
        }

        # -------------------------------------------------------------------
        'campaign-verify' {
            # Close the loop: diff a saved campaign's snapshotted finding keys against
            # the CURRENTLY loaded (fresh) scan. A key still open now = STILL-OPEN; a
            # key gone = REMEDIATED. Persist the verdict; flip to VERIFIED-CLOSED when
            # all remediated. READ-ONLY (no host contact).
            $cid = ([string]$Params['campaignId']).Trim()
            $cam = Get-ReportsCampaignById -Id $cid
            if ($null -eq $cam) {
                & $send @{ type='error'; text="Campaign '$cid' not found in JanetLocal\campaigns." }
                return @{ rows=@(); summary=@{ total=0; notFound=$true } }
            }
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No fresh scan loaded. Import the NEW scan (ACAS Import) before verifying.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            # Classify every fresh-scan finding by NORMALIZED key (host FQDN/NetBIOS/case
            # fold to one - matches campaign-create's stored keys):
            #   openNow      = present AND still an open finding  -> STILL-OPEN
            #   attestedNow  = present BUT manually flagged Patched / NOT OUR PATCH
            # A manual 'Patched' flag is set by acas-mark-status with ZERO verification,
            # so it is NOT evidence the vuln is gone. Only physical ABSENCE from the
            # fresh scan (key in neither set) counts as scan-confirmed REMEDIATED. This
            # stops a campaign whose keys were all hand-flagged from auto-closing.
            $openNow     = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $attestedNow = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            # loop21 P1: host KEYS actually present in the fresh scan. A campaign host missing
            # here was NOT SCANNED this pass - its keys must NOT be scored as remediated (a
            # host offline during the scan window, or a scoped export, would else FALSE-CLOSE).
            $hostsPresent = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $freshHostnames = New-Object System.Collections.ArrayList
            $freshIps       = New-Object System.Collections.ArrayList   # loop40 P1: IP discriminator, parallel to $freshHostnames
            $detail = @{}
            foreach ($f in $script:AcasFindings) {
                $hk = Get-ReportsAuditHostKey $f.Hostname
                $k = "$hk|$($f.PluginID)"
                [void]$hostsPresent.Add($hk)
                [void]$freshHostnames.Add([string]$f.Hostname)
                [void]$freshIps.Add([string]$f.IP)
                $isFlagged = ($f.Status -eq 'Patched' -or $f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH')
                if ($isFlagged) { [void]$attestedNow.Add($k) } else { [void]$openNow.Add($k) }
                if (-not $detail.ContainsKey($k)) { $detail[$k] = $f }
            }
            $campKeys = @($cam.findingKeys)
            # loop24 (ledger row 36): short keys backed by >=2 DISTINCT FQDNs in the fresh scan
            # are cross-domain collisions (web01.us + web01.eu -> WEB01). A "remediated" verdict on
            # such a key is untrustworthy (which physical host was fixed?), so the classify loop
            # below marks them AMBIGUOUS (never remediated, never auto-close). Warn if any campaign
            # key rides a collided short name.
            $collisions   = Get-ReportsHostKeyCollisions -Hostnames @($freshHostnames.ToArray()) -IPs @($freshIps.ToArray())
            $campHostKeys = @($campKeys | ForEach-Object { (($_ -split '\|', 2)[0]) })
            $activeCollisions = @($collisions | Where-Object { $campHostKeys -contains $_ })
            if ($activeCollisions.Count -gt 0) {
                & $send @{ type='log'; level='warn'; text="Ambiguous host key(s) - a short name is shared by multiple DISTINCT hosts in this scan (re-scan by FQDN to resolve): $($activeCollisions -join ', '). Their campaign findings are scored AMBIGUOUS, not remediated." }
            }
            $rows = New-Object System.Collections.ArrayList
            $remediated = 0; $stillOpen = 0; $attested = 0; $notScanned = 0; $ambiguous = 0; $idx = 0
            foreach ($k in $campKeys) {
                $idx++
                $ks = [string]$k
                $parts = ($ks -split '\|', 2)
                $f = if ($detail.ContainsKey($ks)) { $detail[$ks] } else { $null }
                if ($openNow.Contains($ks)) {
                    $stillOpen++
                    $state = 'STILL-OPEN'
                } elseif ($attestedNow.Contains($ks)) {
                    # Present but hand-flagged: attested, NOT scan-confirmed closed.
                    $attested++
                    $state = 'MANUAL-ATTESTED'
                } elseif (-not $hostsPresent.Contains($parts[0])) {
                    # loop21 P1: the host is ABSENT from the fresh scan (offline during the scan
                    # window, or a scoped export) - we CANNOT confirm the vuln is gone. Never
                    # score it remediated and never let it auto-close the campaign; surface a
                    # visible NOT-SCANNED row so the operator re-scans that host.
                    $notScanned++
                    $state = 'NOT-SCANNED'
                } elseif ($collisions.Contains($parts[0])) {
                    # loop24 (ledger row 36): this short key is backed by >=2 distinct FQDNs in the
                    # fresh scan (cross-domain collision). A host with this short name IS present, so
                    # the key looks remediated - but we cannot confirm WHICH physical host was fixed.
                    # Never score it remediated and never let it close the campaign; surface an
                    # AMBIGUOUS row so the operator re-scans by FQDN / resolves it.
                    $ambiguous++
                    $state = 'AMBIGUOUS'
                } else {
                    $remediated++
                    continue   # absent AND the host WAS scanned (unambiguously) = scan-confirmed remediated
                }
                $row = @{
                    _rk=$ks
                    Host=$(if ($f) { [string]$f.Hostname } else { $parts[0] })
                    Plugin=$(if ($f) { [string]$f.PluginID } else { $(if ($parts.Count -gt 1) { $parts[1] } else { '' }) })
                    VulnName=$(if ($f) { [string]$f.VulnName } else { '' })
                    Severity=$(if ($f) { [string]$f.Severity } else { '' })
                    KEV=$(if ($f -and [bool]$f.InKEV) { 'KEV' } else { '' })
                    State=$state
                }
                [void]$rows.Add($row)
                if ($rows.Count -le 800) { & $send (@{ type='row' } + $row) }
            }
            $totalKeys = @($campKeys).Count
            # Closed % = SCAN-CONFIRMED remediation only (manual attestations excluded).
            $closedPct = if ($totalKeys -gt 0) { [math]::Round(($remediated / $totalKeys) * 100, 1) } else { 0 }
            # verified-closed requires EVERY key SCAN-CONFIRMED remediated - no still-open, no
            # merely-attested, no NOT-SCANNED key (loop21 P1: an unscanned host is unconfirmed), and
            # no AMBIGUOUS key (loop24: a cross-domain short-name collision can't confirm which host
            # was fixed). A campaign with any of those stays in-progress, never a false closure.
            $allClosed = ($stillOpen -eq 0 -and $attested -eq 0 -and $notScanned -eq 0 -and $ambiguous -eq 0 -and $totalKeys -gt 0)
            $newStatus = if ($allClosed) { 'verified-closed' } elseif ($remediated -gt 0 -or $attested -gt 0) { 'in-progress' } else { 'open' }

            # Persist the verdict back onto the campaign object.
            $verify = @{ verifiedUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); verifiedBy=(Get-ReportsCleanUser); remediated=$remediated; scanConfirmed=$remediated; attested=$attested; stillOpen=$stillOpen; notScanned=$notScanned; ambiguous=$ambiguous; total=$totalKeys; closedPct=$closedPct }
            if ($cam.PSObject.Properties['verify']) { $cam.verify = $verify } else { $cam | Add-Member -NotePropertyName verify -NotePropertyValue $verify -Force }
            if ($cam.PSObject.Properties['status']) { $cam.status = $newStatus } else { $cam | Add-Member -NotePropertyName status -NotePropertyValue $newStatus -Force }
            $save = Save-ReportsCampaign -Campaign $cam
            if (-not $save.Written) { & $send @{ type='log'; level='warn'; text="Verify computed but the campaign file could not be updated: $($save.Error)" } }

            $attNote = if ($attested -gt 0) { " ($attested manually attested, NOT scan-confirmed)" } else { '' }
            $nsNote  = if ($notScanned -gt 0) { " ($notScanned NOT scanned this pass - re-scan those hosts to confirm)" } else { '' }
            $ambNote = if ($ambiguous -gt 0) { " ($ambiguous AMBIGUOUS - short name shared by distinct hosts; re-scan by FQDN)" } else { '' }
            & $send @{ type='audit'; action='TouchHost'; target="Verify campaign '$($cam.name)'"; result='Success'; itemCount=$totalKeys; detail="$remediated scan-confirmed, $stillOpen still-open, $attested attested, $notScanned not-scanned, $ambiguous ambiguous of $totalKeys ($closedPct% closed); status=$newStatus" }
            & $send @{ type='status'; text="Campaign '$($cam.name)': $remediated scan-confirmed remediated, $stillOpen still-open of $totalKeys - $closedPct% closed$attNote$nsNote$ambNote. Status: $newStatus$(if ($allClosed) { ' 🎉' } else { '' })." }
            return @{ rows=@($rows); summary=@{ total=$stillOpen; remediated=$remediated; scanConfirmed=$remediated; attested=$attested; stillOpen=$stillOpen; notScanned=$notScanned; ambiguous=$ambiguous; totalKeys=$totalKeys; closedPct=$closedPct; status=$newStatus; name=[string]$cam.name } }
        }

        # -------------------------------------------------------------------
        'acas-load-baseline' {
            $filePath = [string]$Params['file']
            # UNC pre-gate: a dead \\share path would otherwise stall this serialized
            # stateful runspace on the SMB timeout, blocking every other reports action.
            if ($filePath -and -not (Test-JanetUncReachable -Path $filePath)) {
                & $send @{ type='log'; level='err'; text="UNC path is unreachable (share host not responding): $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='baseline UNC path unreachable' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -LiteralPath $filePath)) {
                & $send @{ type='log'; level='err'; text="File not found: $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='baseline file not found' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Parsing baseline scan: $filePath" }
            # Replace-not-append, like desktop btnLoadBaseline (6260-6272).
            $parsed = Parse-AcasFile -FilePath $filePath -Emit $send
            $script:BaselineFindings = New-Object System.Collections.ArrayList
            foreach ($f in $parsed) { [void]$script:BaselineFindings.Add($f) }
            $script:ComparisonResults = $null   # a new baseline invalidates the last compare
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($f in $script:BaselineFindings) { [void]$hostSet.Add($f.Hostname) }
            $leaf = Split-Path -Leaf $filePath
            $row = @{ File=$leaf; Findings=$script:BaselineFindings.Count; Hosts=$hostSet.Count }
            & $send (@{ type='row' } + $row)
            $result = if ($script:BaselineFindings.Count -gt 0) { 'Success' } else { 'Failure' }
            & $send @{ type='audit'; action='TouchHost'; target=$leaf; result=$result; itemCount=$script:BaselineFindings.Count; detail="baseline loaded: $($script:BaselineFindings.Count) finding(s) across $($hostSet.Count) host(s)" }
            & $send @{ type='status'; text="Baseline loaded: $($script:BaselineFindings.Count) finding(s) across $($hostSet.Count) host(s)." }
            return @{ rows=@($row); summary=@{ total=$script:BaselineFindings.Count; hosts=$hostSet.Count; file=$leaf } }
        }

        # -------------------------------------------------------------------
        'acas-load-comparison' {
            $filePath = [string]$Params['file']
            # UNC pre-gate (see acas-load-baseline).
            if ($filePath -and -not (Test-JanetUncReachable -Path $filePath)) {
                & $send @{ type='log'; level='err'; text="UNC path is unreachable (share host not responding): $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='comparison UNC path unreachable' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -LiteralPath $filePath)) {
                & $send @{ type='log'; level='err'; text="File not found: $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='comparison file not found' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Parsing comparison scan: $filePath" }
            # Replace-not-append, like desktop btnLoadComparison (6275-6287).
            $parsed = Parse-AcasFile -FilePath $filePath -Emit $send
            $script:ComparisonFindings = New-Object System.Collections.ArrayList
            foreach ($f in $parsed) { [void]$script:ComparisonFindings.Add($f) }
            $script:ComparisonResults = $null   # a new comparison scan invalidates the last compare
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($f in $script:ComparisonFindings) { [void]$hostSet.Add($f.Hostname) }
            $leaf = Split-Path -Leaf $filePath
            $row = @{ File=$leaf; Findings=$script:ComparisonFindings.Count; Hosts=$hostSet.Count }
            & $send (@{ type='row' } + $row)
            $result = if ($script:ComparisonFindings.Count -gt 0) { 'Success' } else { 'Failure' }
            & $send @{ type='audit'; action='TouchHost'; target=$leaf; result=$result; itemCount=$script:ComparisonFindings.Count; detail="comparison loaded: $($script:ComparisonFindings.Count) finding(s) across $($hostSet.Count) host(s)" }
            & $send @{ type='status'; text="Comparison loaded: $($script:ComparisonFindings.Count) finding(s) across $($hostSet.Count) host(s)." }
            return @{ rows=@($row); summary=@{ total=$script:ComparisonFindings.Count; hosts=$hostSet.Count; file=$leaf } }
        }

        # -------------------------------------------------------------------
        'acas-clear-state' {
            # Desktop btnClearXref (6353-6360): wipe the cross-ref stores; leave the
            # import/triage set ($script:AcasFindings) alone.
            $bN = $script:BaselineFindings.Count
            $cN = $script:ComparisonFindings.Count
            $hadResults = ($null -ne $script:ComparisonResults)
            $script:BaselineFindings = New-Object System.Collections.ArrayList
            $script:ComparisonFindings = New-Object System.Collections.ArrayList
            $script:ComparisonResults = $null
            $rows = New-Object System.Collections.ArrayList
            $add = { param($store,$cleared) $r=@{ Store=$store; Cleared=$cleared }; [void]$rows.Add($r); & $send (@{ type='row' } + $r) }
            & $add 'Baseline findings' $bN
            & $add 'Comparison findings' $cN
            & $add 'Last compare result' $(if ($hadResults) { 'yes' } else { 'none' })
            & $send @{ type='audit'; action='TouchHost'; target='ACAS clear compare state'; result='Success'; itemCount=($bN + $cN); detail="cleared baseline ($bN), comparison ($cN), last compare result" }
            & $send @{ type='status'; text="Cleared compare state (baseline $bN, comparison $cN). Loaded findings untouched." }
            return @{ rows=@($rows); summary=@{ baseline=$bN; comparison=$cN } }
        }

        # -------------------------------------------------------------------
        'acas-run-compare' {
            if ($script:BaselineFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No baseline loaded. Run ACAS Load Baseline first (the scan from BEFORE patching).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if ($script:ComparisonFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No comparison scan loaded. Run ACAS Load Comparison first (the scan from AFTER patching).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Comparing scans: $($script:BaselineFindings.Count) baseline vs $($script:ComparisonFindings.Count) comparison finding(s)..." }
            $results = Compare-AcasScans
            $script:ComparisonResults = $results

            $remediated = 0; $stillOpen = 0; $newCount = 0; $ambiguous = 0
            foreach ($r in $results) {
                switch ($r.Delta) {
                    'REMEDIATED' { $remediated++ }
                    'STILL OPEN' { $stillOpen++ }
                    'NEW'        { $newCount++ }
                    'AMBIGUOUS'  { $ambiguous++ }
                }
            }

            $deltaFilter = ([string]$Params['deltaFilter']).Trim()
            $hostFilter  = ([string]$Params['hostFilter']).Trim()
            $sevFilter   = ([string]$Params['severityFilter']).Trim()
            $rows = New-Object System.Collections.ArrayList
            $i = 0
            foreach ($r in $results) {
                if ($deltaFilter -and $deltaFilter -ne 'All' -and $r.Delta -ne $deltaFilter) { continue }
                if ($sevFilter -and $sevFilter -ne 'All' -and $r.Severity -ne $sevFilter) { continue }
                if ($hostFilter -and ([string]$r.Hostname).IndexOf($hostFilter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                $i++
                $row = @{
                    Host=$r.Hostname; Hostname=$r.Hostname; PluginID=$r.PluginID
                    VulnName=$r.VulnName; Severity=$r.Severity; Delta=$r.Delta
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                if (($i % 500) -eq 0) { & $send @{ type='progress'; done=$i; total=$results.Count } }
            }
            & $send @{ type='progress'; done=$results.Count; total=$results.Count }
            $filterNote = if ($rows.Count -ne $results.Count) { " ($($rows.Count) of $($results.Count) shown after filters)" } else { '' }
            # loop39 (ledger row 36): AMBIGUOUS = a would-be REMEDIATED key whose short host
            # name is shared by >=2 distinct FQDNs across the two scans - NOT auto-closed.
            $ambNote = if ($ambiguous -gt 0) { " ($ambiguous ambiguous - short name shared by distinct hosts; re-scan by FQDN)" } else { '' }
            & $send @{ type='audit'; action='TouchHost'; target="Scan compare ($($script:BaselineFindings.Count) baseline vs $($script:ComparisonFindings.Count) comparison)"; result='Success'; itemCount=$results.Count; detail="$remediated remediated, $stillOpen still open, $newCount new, $ambiguous ambiguous" }
            & $send @{ type='status'; text="Comparison complete: $remediated remediated, $stillOpen still open, $newCount new.$ambNote$filterNote" }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; remediated=$remediated; stillOpen=$stillOpen; newFindings=$newCount; ambiguous=$ambiguous; deltaTotal=$results.Count } }
        }

        # -------------------------------------------------------------------
        'scan-closure-proof' {
            # Prove the wave: compare, then join REMEDIATED / STILL OPEN rows against
            # the audit trail between the two scan dates to state causation. READ-ONLY
            # (the audit TouchHost row below records that the operator RAN the proof, not
            # a host touch - consistent with the other read-only reports actions).
            if ($script:BaselineFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No baseline loaded. Run ACAS Load Baseline first (the scan from BEFORE patching).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if ($script:ComparisonFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No comparison scan loaded. Run ACAS Load Comparison first (the scan from AFTER patching).' }
                return @{ rows=@(); summary=@{ total=0 } }
            }

            # Window = [baseline scan date .. comparison scan date]. Blank comparison =
            # today; blank baseline = 90 days before it (a sane default wave length). End
            # is pushed to end-of-day so a same-day touch on the comparison date counts.
            $endD = Get-Date
            $cmpRaw = ([string]$Params['comparisonDate']).Trim()
            if ($cmpRaw) { $tmp=[datetime]::MinValue; if ([datetime]::TryParse($cmpRaw, [ref]$tmp)) { $endD = $tmp } else { & $send @{ type='log'; level='warn'; text="Could not parse comparison date '$cmpRaw' - using today." } } }
            $endD = $endD.Date.AddDays(1).AddSeconds(-1)
            $startD = $endD.Date.AddDays(-90)
            $baseRaw = ([string]$Params['baselineDate']).Trim()
            if ($baseRaw) { $tmp=[datetime]::MinValue; if ([datetime]::TryParse($baseRaw, [ref]$tmp)) { $startD = $tmp.Date } else { & $send @{ type='log'; level='warn'; text="Could not parse baseline date '$baseRaw' - using 90 days before comparison." } } }
            if ($startD -gt $endD) {
                & $send @{ type='log'; level='err'; text='Baseline date is after the comparison date - swap them.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }

            $hostFilter = ([string]$Params['hostFilter']).Trim()
            & $send @{ type='status'; text="Comparing scans, then proving closure against the audit trail ($($startD.ToString('yyyy-MM-dd')) .. $($endD.ToString('yyyy-MM-dd')))..." }
            $results = Compare-AcasScans
            $script:ComparisonResults = $results

            # loop40 F4: AMBIGUOUS rows (collided short name - a would-be REMEDIATED whose short
            # host key is shared by distinct hosts/IPs) are NOT audit-joined below (they were never
            # confirmed closed), so surface their count so the proof output can't imply everything
            # closed while an unconfirmed finding is hidden.
            $ambiguousCount = @($results | Where-Object { [string]$_.Delta -eq 'AMBIGUOUS' }).Count
            if ($ambiguousCount -gt 0) { & $send @{ type='log'; level='warn'; text="$ambiguousCount finding(s) AMBIGUOUS (short name shared by distinct hosts/IPs) - excluded from the closure proof (neither confirmed closed nor open); re-scan by FQDN to resolve." } }

            # Only REMEDIATED + STILL OPEN rows get the audit join (NEW findings were
            # absent before, so there is nothing to attribute).
            $subject = @($results | Where-Object { $_.Delta -eq 'REMEDIATED' -or $_.Delta -eq 'STILL OPEN' })
            if ($subject.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No REMEDIATED or STILL OPEN rows in the compare - nothing to prove.' }
                & $send @{ type='status'; text='Nothing to prove (no closed or still-open findings).' }
                return @{ rows=@(); summary=@{ total=0; subjects=0; closedTouched=0; closedUntouched=0; openTouched=0; openUntouched=0; ambiguous=$ambiguousCount; worklist=@(); worklistCount=0 } }
            }

            # Distinct host keys we care about (drives the reader's WantHosts filter so it
            # only keeps touches for hosts in this compare).
            $want = @{}
            foreach ($r in $subject) { $hk = Get-ReportsAuditHostKey ([string]$r.Hostname); if ($hk) { $want[$hk] = $true } }

            $loc = Resolve-ReportsAuditRoot
            & $send @{ type='log'; level=($(if ($loc.OnShare) { 'info' } else { 'warn' })); text="Audit source: $($loc.Reason)." }
            $months = Get-ReportsWindowMonths -Start $startD -End $endD
            & $send @{ type='status'; text="Reading audit trail for $($want.Count) host(s) over $($months.Count) month(s)..." }
            $idxRes = Read-ReportsAuditTouchIndex -Root $loc.Root -Months $months -WantHosts $want -Start $startD -End $endD
            $index = $idxRes.Index
            if ($idxRes.Capped) { & $send @{ type='log'; level='warn'; text="Audit read cap hit ($($idxRes.Rows) rows) - some touches were not read; causation counts may undercount. Narrow the date window." } }

            $closedTouched=0; $closedUntouched=0; $openTouched=0; $openUntouched=0
            $worklist = New-Object System.Collections.ArrayList
            $rows = New-Object System.Collections.ArrayList
            $i = 0
            foreach ($r in $subject) {
                if ($hostFilter -and ([string]$r.Hostname).IndexOf($hostFilter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                $hk = Get-ReportsAuditHostKey ([string]$r.Hostname)
                $touch = if ($hk) { $index[$hk] } else { $null }
                $touched = [bool]$touch
                $tool = ''; $operator = ''; $touchDate = ''
                if ($touched) { $tool=[string]$touch.Tool; $operator=[string]$touch.Operator; $touchDate=[string]$touch.TouchDate }
                if ($r.Delta -eq 'REMEDIATED') {
                    if ($touched) { $closedTouched++ } else { $closedUntouched++ }
                } else {
                    if ($touched) { $openTouched++ } else { $openUntouched++ }
                }
                $i++
                $row = @{
                    Host=$r.Hostname; Hostname=$r.Hostname; PluginID=$r.PluginID
                    VulnName=$r.VulnName; Severity=$r.Severity; Delta=$r.Delta
                    TouchedByJanet=$(if ($touched) { 'YES' } else { 'no' })
                    Tool=$tool; Operator=$operator; TouchDate=$touchDate
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                if ($r.Delta -eq 'STILL OPEN' -and $touched) {
                    [void]$worklist.Add(@{ Hostname=$r.Hostname; PluginID=$r.PluginID; VulnName=$r.VulnName; Severity=$r.Severity; Tool=$tool; Operator=$operator; TouchDate=$touchDate })
                }
                if (($i % 500) -eq 0) { & $send @{ type='progress'; done=$i; total=$subject.Count } }
            }
            & $send @{ type='progress'; done=$subject.Count; total=$subject.Count }

            # The next-day worklist as its own list: STILL OPEN on a host JANET touched =
            # the patch did not take, so surface each row for the operator to re-run.
            foreach ($w in $worklist) {
                & $send @{ type='log'; level='warn'; text="WORKLIST (patch did not take): $($w.Hostname) plugin $($w.PluginID) [$($w.Severity)] - last touched by $($w.Tool)/$($w.Operator) on $($w.TouchDate)" }
            }

            $waveNote = "$closedTouched closed on hosts JANET touched (wave worked), $closedUntouched closed on untouched hosts (closed by something else), $openTouched still-open on touched hosts (patch did not take - next-day worklist)."
            & $send @{ type='audit'; action='TouchHost'; target="Wave closure proof ($($subject.Count) subject row(s))"; result='Success'; itemCount=$closedTouched; detail=$waveNote }
            & $send @{ type='status'; text="Closure proof: $waveNote" }

            return @{ rows=@($rows); summary=@{
                total=$rows.Count; subjects=$subject.Count
                closedTouched=$closedTouched; closedUntouched=$closedUntouched
                openTouched=$openTouched; openUntouched=$openUntouched
                ambiguous=$ambiguousCount
                onShare=$loc.OnShare; source=$loc.Reason
                windowStart=$startD.ToString('yyyy-MM-dd'); windowEnd=$endD.ToString('yyyy-MM-dd')
                auditRows=$idxRes.Rows; auditFiles=$idxRes.Files; capped=$idxRes.Capped
                worklist=@($worklist); worklistCount=$worklist.Count
            } }
        }

        # -------------------------------------------------------------------
        'acas-apply-remediated' {
            # Desktop btnApplyRemediated (6361-6385): match the last compare's
            # REMEDIATED keys against the loaded findings and flip them Patched.
            if ($null -eq $script:ComparisonResults) {
                & $send @{ type='log'; level='err'; text='No comparison results. Run ACAS Scan Compare first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $remediated = @($script:ComparisonResults | Where-Object { $_.Delta -eq 'REMEDIATED' })
            if ($remediated.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No remediated findings to apply - the last comparison classified nothing as REMEDIATED.' }
                return @{ rows=@(); summary=@{ total=0; remediated=0; marked=0 } }
            }
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Applying $($remediated.Count) remediated finding(s) to the loaded set..." }
            # Host portion normalized via Get-ReportsAuditHostKey so a REMEDIATED key
            # from a baseline exported as HOST1 still matches the import set's host1.dom
            # (baseline and import set can be different file formats); consistent with
            # the compare keys that produced these results.
            $remLookup = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($r in $remediated) { [void]$remLookup.Add("$(Get-ReportsAuditHostKey $r.Hostname)|$($r.PluginID)") }
            # loop39 (ledger row 36): this is the ONLY site that writes finding.Status='Patched',
            # and it builds its OWN keys - so it needs its OWN cross-domain collision guard (the
            # compare's demotion alone does not protect a stale/reused ComparisonResults set). A
            # finding whose short host key is shared by >=2 DISTINCT FQDNs in the loaded/compared
            # set is SKIPPED (left open, surfaced) rather than flipped to Patched - we cannot
            # confirm WHICH physical box a WEB01 remediation belongs to. Reuses the proven loop24
            # helper; the fold is unchanged. loop40 P1: the scan IP is now threaded through (-IPs),
            # so two BARE WEB01s on different IPs (the short-name-only norm) are also caught, not
            # just the FQDN case. RESIDUAL: a truly IP-less short-name-only set stays undisambiguable.
            # loop40 P1: thread the scan IP (parallel array) so two BARE WEB01s on different IPs
            # in the loaded set are detected as a collision and the flip is skipped.
            $applyHostnames = New-Object System.Collections.ArrayList
            $applyIps       = New-Object System.Collections.ArrayList
            foreach ($finding in $script:AcasFindings) { [void]$applyHostnames.Add([string]$finding.Hostname); [void]$applyIps.Add([string]$finding.IP) }
            foreach ($r in $remediated)                { [void]$applyHostnames.Add([string]$r.Hostname); [void]$applyIps.Add([string]$r.IP) }
            $applyCollisions = Get-ReportsHostKeyCollisions -Hostnames @($applyHostnames.ToArray()) -IPs @($applyIps.ToArray())
            $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm')
            $matchCount = 0; $skippedAmbiguous = 0
            foreach ($finding in $script:AcasFindings) {
                $hk  = Get-ReportsAuditHostKey $finding.Hostname
                $key = "$hk|$($finding.PluginID)"
                if ($remLookup.Contains($key) -and $finding.Status -ne 'Patched') {
                    if ($applyCollisions.Contains($hk)) {
                        # Collided short name - do NOT flip to Patched; leave the vuln open and surfaced.
                        $skippedAmbiguous++
                        continue
                    }
                    $finding.Status      = 'Patched'
                    $finding.PatchedDate = $stamp
                    $finding.PatchedBy   = 'Scan Comparison'
                    $matchCount++
                }
            }
            $rows = New-Object System.Collections.ArrayList
            $add = { param($metric,$value) $r=@{ Metric=$metric; Value=$value }; [void]$rows.Add($r); & $send (@{ type='row' } + $r) }
            & $add 'Remediated in comparison' $remediated.Count
            & $add 'Marked Patched now' $matchCount
            & $add 'Skipped (ambiguous host key)' $skippedAmbiguous
            & $add 'Already Patched / no match' ($remediated.Count - $matchCount - $skippedAmbiguous)
            # Success only when at least one loaded finding was actually flipped to
            # Patched; if nothing matched (or all were already Patched) no work was
            # done -> Skipped with itemCount=0.
            $applyResult = if ($matchCount -gt 0) { 'Success' } else { 'Skipped' }
            $skipNote = if ($skippedAmbiguous -gt 0) { " ($skippedAmbiguous skipped as ambiguous - short name shared by distinct hosts; re-scan by FQDN)" } else { '' }
            & $send @{ type='audit'; action='TouchHost'; target="Apply remediated ($($remediated.Count) keys)"; result=$applyResult; itemCount=$matchCount; detail="$matchCount finding(s) marked Patched (PatchedBy=Scan Comparison) of $($remediated.Count) remediated, $skippedAmbiguous skipped as ambiguous" }
            & $send @{ type='status'; text="$matchCount finding(s) marked Patched ($($remediated.Count) remediated in comparison).$skipNote" }
            return @{ rows=@($rows); summary=@{ total=$matchCount; remediated=$remediated.Count; marked=$matchCount; skippedAmbiguous=$skippedAmbiguous } }
        }

        # -------------------------------------------------------------------
        'acas-mark-status' {
            # Findings triage: same key shape as the import dedup. Ports the
            # desktop btnMarkPatched / btnMarkNotOurs / btnUndoStatus handlers
            # (5974-6046) with Get-AcasFindingIndex (2727) for the lookup.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $newStatus = ([string]$Params['newStatus']).Trim()
            if (-not $newStatus) { $newStatus = 'Patched' }
            $statusCanon = @(@('Patched','NOT OUR PATCH','Open') | Where-Object { $_ -ieq $newStatus }) | Select-Object -First 1
            if (-not $statusCanon) {
                & $send @{ type='log'; level='err'; text="Invalid status '$newStatus'. Use Patched, NOT OUR PATCH, or Open." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $keys = @()
            foreach ($line in (([string]$Params['keys']) -split "`r?`n")) {
                $k = $line.Trim()
                if ($k) { $keys += $k }
            }
            if ($keys.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No keys provided. Paste one Hostname|PluginID per line.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $patchedBy = ([string]$Params['patchedBy']).Trim()
            if (-not $patchedBy) { $patchedBy = Get-ReportsCleanUser }
            $patchedDate = ([string]$Params['patchedDate']).Trim()
            if (-not $patchedDate) { $patchedDate = (Get-Date).ToString('yyyy-MM-dd HH:mm') }

            # Hostname|PluginID -> finding index (hashtable keys are already
            # case-insensitive, matching the import dedup's OrdinalIgnoreCase).
            $idx = @{}
            foreach ($f in $script:AcasFindings) { $idx["$($f.Hostname)|$($f.PluginID)"] = $f }

            & $send @{ type='status'; text="Marking $($keys.Count) key(s) as ${statusCanon}..." }
            $rows = New-Object System.Collections.ArrayList
            $matched = 0; $changed = 0
            $missed = New-Object System.Collections.ArrayList
            $i = 0
            foreach ($rawKey in $keys) {
                $i++
                $parts = $rawKey -split '\|', 2
                $kHost = $parts[0].Trim()
                $kPlugin = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
                # Normalize 'HOST | 1234' -> 'HOST|1234' so pasted keys with
                # spaces around the pipe still match the index.
                $key = if ($kPlugin) { "$kHost|$kPlugin" } else { $rawKey }
                if (-not $idx.ContainsKey($key)) {
                    [void]$missed.Add($key)
                    $row = @{ Host=$kHost; Hostname=$kHost; PluginID=$kPlugin; NewStatus=''; Outcome='no match' }
                    [void]$rows.Add($row)
                    & $send (@{ type='row' } + $row)
                    & $send @{ type='progress'; done=$i; total=$keys.Count }
                    continue
                }
                $f = $idx[$key]
                $matched++
                $before = "$($f.Status)|$($f.Category)|$($f.PatchedBy)|$($f.PatchedDate)"
                switch ($statusCanon) {
                    'Patched' {
                        $f.Status = 'Patched'; $f.PatchedDate = $patchedDate; $f.PatchedBy = $patchedBy
                    }
                    'NOT OUR PATCH' {
                        $f.Category = 'NOT OUR PATCH'; $f.Status = 'NOT OUR PATCH'
                    }
                    'Open' {
                        # Undo: re-run the classifier to restore the computed class.
                        $f.Category = Categorize-Finding -VulnName $f.VulnName -Solution $f.Solution -PluginID $f.PluginID
                        $f.Status = if ($f.Category -eq 'NOT OUR PATCH') { 'NOT OUR PATCH' } else { 'Open' }
                        $f.PatchedDate = ''; $f.PatchedBy = ''
                    }
                }
                $after = "$($f.Status)|$($f.Category)|$($f.PatchedBy)|$($f.PatchedDate)"
                $outcome = if ($after -ne $before) { $changed++; 'updated' } else { 'unchanged' }
                $row = @{ Host=$f.Hostname; Hostname=$f.Hostname; PluginID=$f.PluginID; NewStatus=$f.Status; Status=$f.Status; Category=$f.Category; Outcome=$outcome }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='progress'; done=$i; total=$keys.Count }
            }
            if ($missed.Count -gt 0) {
                $preview = (@($missed | Select-Object -First 5) -join '; ')
                $more = if ($missed.Count -gt 5) { " (+$($missed.Count - 5) more)" } else { '' }
                & $send @{ type='log'; level='warn'; text="$($missed.Count) key(s) matched no loaded finding: $preview$more" }
            }
            & $send @{ type='audit'; action='TouchHost'; target="ACAS mark status ($statusCanon)"; result=$(if ($matched -gt 0) { 'Success' } else { 'Failure' }); itemCount=$changed; detail="$matched matched, $changed changed, $($missed.Count) unmatched of $($keys.Count) key(s)" }
            & $send @{ type='status'; text="Done. $matched matched, $changed changed, $($missed.Count) unmatched of $($keys.Count) key(s)." }
            return @{ rows=@(); summary=@{ total=$keys.Count; matched=$matched; changed=$changed; unmatched=$missed.Count } }
        }

        # -------------------------------------------------------------------
        'remediation-mark-pushed' {
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $app = ([string]$Params['app']).Trim()
            if (-not $app) {
                & $send @{ type='log'; level='err'; text='No app/group name provided.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $statusSel = ([string]$Params['status']).Trim()
            if (-not $statusSel) { $statusSel = 'Pushed' }
            $statusCanon = @(@('Pushed','Skipped','Pending') | Where-Object { $_ -ieq $statusSel }) | Select-Object -First 1
            if (-not $statusCanon) {
                & $send @{ type='log'; level='err'; text="Invalid status '$statusSel'. Use Pushed, Skipped, or Pending." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $by = Get-ReportsCleanUser
            $date = (Get-Date).ToString('yyyy-MM-dd HH:mm')
            $fixedApps = @('Chrome','Edge','Office','Defender','KB','Other')
            $appCanon = @($fixedApps | Where-Object { $_ -ieq $app }) | Select-Object -First 1

            if ($appCanon) {
                # Fixed app bucket: flip Status on every (host, app) plan row -
                # desktop Mark-RemediationStatus (3245-3273). Pending clears the
                # override so the rows re-enter the plan totals.
                $plan = Build-RemediationPlan
                # NB: wrap the whole if in @(): a statement block enumerates its
                # output, so a single matching row would otherwise come back as a
                # bare hashtable and .Count would report its KEY count.
                $planRows = @(
                    if ($statusCanon -eq 'Pending') {
                        $plan.Rows | Where-Object { $_.App -eq $appCanon }
                    } else {
                        $plan.Rows | Where-Object { $_.App -eq $appCanon -and $_.Status -ne 'Pushed' -and $_.Status -ne 'Skipped' }
                    }
                )
                if ($planRows.Count -eq 0) {
                    & $send @{ type='log'; level='warn'; text="No $appCanon row(s) to mark $statusCanon." }
                    return @{ rows=@(); summary=@{ total=0; app=$appCanon; status=$statusCanon } }
                }
                foreach ($r in $planRows) {
                    # loop20: build the status key the SAME normalized way Build-RemediationPlan
                    # keys its bucket ($hk|$app), so a status marked here is found by the reader
                    # even when the plan row's display Hostname is an FQDN.
                    $key = "$(Get-ReportsAuditHostKey ([string]$r.Hostname))|$($r.App)"
                    if ($statusCanon -eq 'Pending') { $script:RemediationStatus.Remove($key) }
                    else { $script:RemediationStatus[$key] = @{ Status=$statusCanon; By=$by; Date=$date; Notes='' } }
                }
                $row = @{ App=$appCanon; NewStatus=$statusCanon; RowsChanged=$planRows.Count }
                & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='TouchHost'; target="Remediation plan: $appCanon"; result='Success'; itemCount=$planRows.Count; detail="$($planRows.Count) (host, app) row(s) marked $statusCanon by $by" }
                & $send @{ type='status'; text="Marked $($planRows.Count) $appCanon target(s) as $statusCanon." }
                return @{ rows=@($row); summary=@{ total=$planRows.Count; app=$appCanon; status=$statusCanon } }
            }

            # Other-vuln group card: accept 'Plugin <id>', a bare plugin ID, or
            # the 'Other: <vuln name>' label shown by Remediation Refresh.
            $pluginId = $null
            if ($app -match '^[Pp]lugin\s+(\S+)$') { $pluginId = $Matches[1] }
            elseif ($app -match '^\d+$') { $pluginId = $app }
            else {
                $name = $app
                if ($app -match '^[Oo]ther:\s*(.+)$') { $name = $Matches[1].Trim() }
                $plan = Build-RemediationPlan
                $grp = @($plan.OtherGroups | Where-Object { ([string]$_.VulnName) -ieq $name }) | Select-Object -First 1
                if ($grp) { $pluginId = [string]$grp.PluginID }
            }
            if (-not $pluginId) {
                & $send @{ type='log'; level='err'; text="'$app' is not a fixed app bucket and matches no visible Other-vuln group. Use Chrome/Edge/Office/Defender/KB/Other, 'Plugin <id>', a bare plugin ID, or the exact 'Other: <vuln name>' label (already-pushed groups must be reset by plugin ID)." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $groupChanged = 0
            if ($statusCanon -eq 'Pending') {
                if ($script:OtherVulnPushed.ContainsKey($pluginId)) {
                    $script:OtherVulnPushed.Remove($pluginId)
                    $groupChanged = 1
                    & $send @{ type='status'; text="Plugin $pluginId reset to Pending - its card returns on the next Remediation Refresh." }
                } else {
                    & $send @{ type='log'; level='warn'; text="Plugin $pluginId was not marked - nothing to reset." }
                }
            } else {
                # Desktop Mark-OtherVulnPushed (3177-3188). Build-RemediationPlan
                # hides the card on key PRESENCE, so Skipped suppresses too.
                $script:OtherVulnPushed[$pluginId] = @{ Status=$statusCanon; By=$by; Date=$date; Notes='' }
                $groupChanged = 1
                & $send @{ type='status'; text="Plugin $pluginId marked $statusCanon - card hidden until reset or the next import." }
            }
            $row = @{ App="Plugin $pluginId"; NewStatus=$statusCanon; RowsChanged=$groupChanged }
            & $send (@{ type='row' } + $row)
            & $send @{ type='audit'; action='TouchHost'; target="Remediation plan: plugin $pluginId"; result=$(if ($groupChanged -gt 0) { 'Success' } else { 'Failure' }); itemCount=$groupChanged; detail="Other-vuln group marked $statusCanon by $by" }
            return @{ rows=@($row); summary=@{ total=$groupChanged; plugin=$pluginId; status=$statusCanon } }
        }

        # -------------------------------------------------------------------
        'acas-host-summary' {
            # Per-host dashboard tallies over the loaded findings - the exact
            # single-pass walk of desktop Refresh-Dashboard (3443-3463) plus the
            # grid math at 3494-3499. PatchRate denominator = Patched + Open (the
            # actionable set); N/A when a host has no actionable findings.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Building per-host summary over $($script:AcasFindings.Count) finding(s)..." }
            $perHost = @{}
            foreach ($f in $script:AcasFindings) {
                # audit 2026-07-23 (BUG): tally on the normalized audit key like every
                # sibling rollup (CORA / sla-aging) - keying on the RAW hostname split a
                # short+FQDN pair of ONE host into two rows and halved its PatchRate.
                # Rows display the normalized key, matching sla-aging / CORA.
                $h = Get-ReportsAuditHostKey ([string]$f.Hostname)
                if (-not $perHost.ContainsKey($h)) {
                    $perHost[$h] = @{ Total=0; Critical=0; High=0; Medium=0; Low=0; Info=0; Patched=0; NotOurs=0; Open=0; Kev=0 }
                }
                $t = $perHost[$h]
                $t.Total++
                switch ($f.Severity) {
                    'Critical' { $t.Critical++ }
                    'High'     { $t.High++ }
                    'Medium'   { $t.Medium++ }
                    'Low'      { $t.Low++ }
                    'Info'     { $t.Info++ }
                }
                # audit 2026-07-24 (BUG): these two tests were separate `if`s and are NOT
                # mutually exclusive - acas-apply-remediated (:5937) flips a finding to
                # Patched WITHOUT inspecting Category, so one finding could be Patched AND
                # NOT OUR PATCH and tally in BOTH buckets. The arithmetic below assumed the
                # buckets partition the set, so Total-Patched-NotOurs went NEGATIVE and the
                # PatchRate denominator was understated (rate overstated). Classify into
                # exactly ONE bucket, Patched winning over NOT OUR PATCH - the same
                # precedence sla-aging uses when it skips (:6250-6254), and Open matches the
                # Open export view (:6437), which excludes a finding that is either. The
                # NOT-OUR-PATCH test also checks Status now, like both siblings (acas-mark-
                # status writes the triage verdict to Status, not Category).
                if ($f.Status -eq 'Patched') { $t.Patched++ }
                elseif ($f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH') { $t.NotOurs++ }
                else { $t.Open++ }
                if ($f.InKEV) { $t.Kev++ }
            }
            $rows = New-Object System.Collections.ArrayList
            $i = 0; $kevHosts = 0
            foreach ($h in ($perHost.Keys | Sort-Object)) {
                $i++
                $t = $perHost[$h]
                if ($t.Kev -gt 0) { $kevHosts++ }
                # audit 2026-07-24: both figures now come FROM the counters instead of being
                # subtracted out of Total, so neither can drift when the buckets overlap.
                $hOpen = $t.Open
                $act = $t.Patched + $t.Open    # actionable denominator (excludes NOT OUR PATCH)
                $pr = if ($act -gt 0) { "$([Math]::Round(($t.Patched / $act) * 100, 0))%" } else { 'N/A' }
                $row = @{
                    Host=$h; TotalVulns=$t.Total
                    Crit=$t.Critical; High=$t.High; Med=$t.Medium; Low=$t.Low; Info=$t.Info
                    Kev=$t.Kev
                    Patched=$t.Patched; Open=$hOpen; NotOurs=$t.NotOurs; PatchRate=$pr
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                if (($i % 100) -eq 0) { & $send @{ type='progress'; done=$i; total=$perHost.Count } }
            }
            & $send @{ type='progress'; done=$perHost.Count; total=$perHost.Count }
            $kevNote = if ($kevHosts -gt 0) { " ($kevHosts with KEV)" } else { '' }
            & $send @{ type='status'; text="Host summary: $($perHost.Count) host(s)$kevNote over $($script:AcasFindings.Count) finding(s)." }
            return @{ rows=@(); summary=@{ total=$perHost.Count; findings=$script:AcasFindings.Count; kevHosts=$kevHosts } }
        }

        # -------------------------------------------------------------------
        'sla-aging' {
            # Remediation SLA / finding-age dashboard. Joins each OPEN (not Patched)
            # finding's saved firstSeen date against the editable per-severity
            # remediation windows (JanetLocal\sla-baseline.json; KEV overrides) and
            # buckets it ON-TRACK / DUE-SOON / OVERDUE. Findings that were never saved
            # (no firstSeen) bucket NEW-UNTRACKED - the operator must save the report
            # to start the clock. READ-ONLY: no audit rows (session START/END is logged
            # server-side); the module never writes the findings or the baseline.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $sla = Get-ReportsSlaBaseline
            $cfg = $sla.Config
            & $send @{ type='status'; text="Computing remediation SLA aging over $($script:AcasFindings.Count) finding(s)... (baseline: $($sla.Source))" }
            & $send @{ type='log'; level='info'; text="SLA windows (days): KEV=$($cfg.kev) Critical=$($cfg.critical) High=$($cfg.high) Medium=$($cfg.medium) Low=$($cfg.low). Source: $($sla.Source)." }
            # Backfill firstSeen from the persisted ledger so the aging clock survives a
            # fresh re-parse with zero operator discipline (audit P1 fix): a finding whose
            # live FirstSeen is blank but whose Hostname|PluginID key is in the ledger
            # adopts the ledger's firstSeen instead of falling into NEW-UNTRACKED.
            $ledger = Get-ReportsSlaLedger
            $ledMap = $ledger.Map
            if (-not $ledger.Ok) { & $send @{ type='log'; level='warn'; text="SLA ledger unreadable ($($ledger.Source)) - findings with no in-report firstSeen will show NEW-UNTRACKED." } }
            $cLedgerCarried = 0

            $today = (Get-Date).Date
            # Neutralize spreadsheet formula injection (audit#5): scanner free-text
            # (VulnName/IAVA/CVE) goes through the canonical ConvertTo-ReportsCsvCell.
            # audit 2026-07-23: the hand-rolled guard+quote scriptblock collapsed onto
            # the helper (identical behavior, byte-for-byte output).
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('Host,Plugin,VulnName,Severity,KEV,IAVA,CVE,FirstSeen,AgeDays,DueInDays,Deadline,Bucket')

            $rows = New-Object System.Collections.ArrayList
            $cOverdue = 0; $cDueSoon = 0; $cOnTrack = 0; $cUntracked = 0; $cPatchedSkipped = 0; $cNotOursSkipped = 0
            $perHost = @{}
            $i = 0; $total = $script:AcasFindings.Count
            foreach ($f in $script:AcasFindings) {
                $i++
                if (($i % 200) -eq 0) { & $send @{ type='progress'; done=$i; total=$total } }
                # audit 2026-07-25 (fable re-audit follow-up): -eq, not -match. host-summary
                # partitions on the exact literal (:6220) while this skipped on a SUBSTRING,
                # so an externally-produced save file carrying e.g. 'Unpatched' bucketed as
                # actionable-Open there and silently vanished from the SLA board here.
                if ($f.Status -eq 'Patched') { $cPatchedSkipped++; continue }   # Patched = remediated, out of scope
                # NOT OUR PATCH = vendor/EOL findings the shop triaged as not theirs;
                # keep them out of the actionable OVERDUE set (matches the Open export
                # view and the CORA / remediation actionable-set convention).
                if ($f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH') { $cNotOursSkipped++; continue }
                $hn = [string]$f.Hostname
                $inKev = [bool]$f.InKEV
                $fsRaw = if ($f.PSObject.Properties['FirstSeen']) { [string]$f.FirstSeen } else { '' }
                if ([string]::IsNullOrWhiteSpace($fsRaw)) {
                    $lk = "$(Get-ReportsAuditHostKey $hn)|$($f.PluginID)"
                    if ($ledMap.ContainsKey($lk) -and -not [string]::IsNullOrWhiteSpace([string]$ledMap[$lk].firstSeen)) {
                        $fsRaw = [string]$ledMap[$lk].firstSeen; $cLedgerCarried++
                        # stamp the carried date back so the live object is tracked without a reload
                        if ($f.PSObject.Properties['FirstSeen']) { $f.FirstSeen = $fsRaw } else { $f | Add-Member -NotePropertyName FirstSeen -NotePropertyValue $fsRaw -Force }
                    }
                }
                $fsDisplay = ''; $age = ''; $dueIn = ''; $deadline = ''; $bucket = ''
                $fsDate = [datetime]::MinValue
                $parsed = $false
                if (-not [string]::IsNullOrWhiteSpace($fsRaw)) { $parsed = [datetime]::TryParse($fsRaw, [ref]$fsDate) }
                if (-not $parsed) {
                    $bucket = 'NEW-UNTRACKED'; $cUntracked++
                } else {
                    $fsDisplay = $fsDate.ToString('yyyy-MM-dd')
                    $age = [int][Math]::Floor(($today - $fsDate.Date).TotalDays)
                    if ($age -lt 0) { $age = 0 }
                    $deadline = Get-ReportsSlaDeadline -Config $cfg -Severity ([string]$f.Severity) -InKev $inKev
                    $slaB = Get-ReportsSlaBucket -Deadline ([int]$deadline) -Age ([int]$age)   # loop21: shared boundary rule
                    $dueIn = $slaB.DueIn
                    $bucket = $slaB.Bucket
                    if ($bucket -eq 'OVERDUE') { $cOverdue++ }
                    elseif ($bucket -eq 'DUE-SOON') { $cDueSoon++ }
                    else { $cOnTrack++ }
                }

                # loop13: tally per-host by the normalized audit key so a short+FQDN pair of
                # the SAME host is one row (agrees with CORA UniqueHosts + the SLA ledger key
                # already used at the top of this loop). Display the normalized key, like CORA.
                $hk = Get-ReportsAuditHostKey $hn
                if (-not $perHost.ContainsKey($hk)) { $perHost[$hk] = @{ Host=$hk; Overdue=0; DueSoon=0; OnTrack=0; Untracked=0 } }
                switch ($bucket) {
                    'OVERDUE'       { $perHost[$hk].Overdue++ }
                    'DUE-SOON'      { $perHost[$hk].DueSoon++ }
                    'ON-TRACK'      { $perHost[$hk].OnTrack++ }
                    'NEW-UNTRACKED' { $perHost[$hk].Untracked++ }
                }

                $iava = [string]$f.IAVA
                $row = @{
                    Host=$hn; Plugin=[string]$f.PluginID; VulnName=[string]$f.VulnName; Severity=[string]$f.Severity
                    KEV=$(if ($inKev) { 'KEV' } else { '' }); InKEV=$inKev; KevCves=[string]$f.KevCves; IAVA=$iava; CVE=[string]$f.CVE
                    FirstSeen=$fsDisplay; AgeDays=$age; DueIn=$dueIn; Deadline=$deadline; Bucket=$bucket
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                [void]$sb.AppendLine((@(
                    (ConvertTo-ReportsCsvCell $hn), (ConvertTo-ReportsCsvCell $f.PluginID), (ConvertTo-ReportsCsvCell $f.VulnName), (ConvertTo-ReportsCsvCell $f.Severity),
                    (ConvertTo-ReportsCsvCell $(if ($inKev) { 'KEV' } else { '' })), (ConvertTo-ReportsCsvCell $iava), (ConvertTo-ReportsCsvCell $f.CVE), (ConvertTo-ReportsCsvCell $fsDisplay),
                    (ConvertTo-ReportsCsvCell $age), (ConvertTo-ReportsCsvCell $dueIn), (ConvertTo-ReportsCsvCell $deadline), (ConvertTo-ReportsCsvCell $bucket)
                ) -join ','))
            }
            & $send @{ type='progress'; done=$total; total=$total }

            $hostsOverdue = @($perHost.Values | Where-Object { $_.Overdue -gt 0 }).Count
            $perHostRows = @($perHost.Values | Sort-Object -Property @{ Expression = { $_.Overdue }; Descending = $true }, @{ Expression = { $_.DueSoon }; Descending = $true }, @{ Expression = { $_.Host } } | ForEach-Object {
                [ordered]@{ Host=$_.Host; Overdue=$_.Overdue; DueSoon=$_.DueSoon; OnTrack=$_.OnTrack; Untracked=$_.Untracked }
            })
            $inScope = $cOverdue + $cDueSoon + $cOnTrack + $cUntracked
            if ($cLedgerCarried -gt 0) { & $send @{ type='log'; level='info'; text="SLA ledger: carried firstSeen from JanetLocal\sla-ledger.json for $cLedgerCarried finding(s) - the clock survived the last re-parse." } }
            $hint = if ($cUntracked -gt 0) { "$cUntracked finding(s) have no firstSeen (not in the ledger yet) - Save the report (ACAS Import tab) to stamp today and start their SLA clock." } else { '' }
            & $send @{ type='status'; text="SLA aging: $cOverdue overdue, $cDueSoon due-soon, $cOnTrack on-track, $cUntracked untracked over $($perHost.Count) host(s)." }
            if ($hint) { & $send @{ type='log'; level='warn'; text=$hint } }

            return @{ rows=@(); summary=@{
                total=$inScope; overdue=$cOverdue; dueSoon=$cDueSoon; onTrack=$cOnTrack; untracked=$cUntracked
                patchedSkipped=$cPatchedSkipped; notOursSkipped=$cNotOursSkipped; hosts=$perHost.Count; hostsOverdue=$hostsOverdue
                baseline=$sla.Source; ledgerCarried=$cLedgerCarried; hint=$hint; perHost=$perHostRows; csv=$sb.ToString().TrimEnd()
            } }
        }

        # -------------------------------------------------------------------
        'export-poam' {
            # RMF/eMASS POA&M export (ported from the fork STIG desktop tool's
            # Export-ScanToPoam, but CSV not XLSX - no ImportExcel dependency - and
            # driven by the loaded ACAS findings). One row per OPEN finding, eMASS
            # POA&M import-template columns. Scheduled Completion = firstSeen + SLA
            # window (KEV overrides); severity -> DISA CAT. READ-ONLY.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse or load a report first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $sla = Get-ReportsSlaBaseline; $cfg = $sla.Config
            $ledger = Get-ReportsSlaLedger; $ledMap = $ledger.Map
            $today = (Get-Date).Date
            # DISA CAT mapping from ACAS severity (Critical=CAT I, High=CAT II, Med/Low=CAT III).
            $catOf = { param($sev) switch ([string]$sev) { 'Critical' { 'CAT I' } 'High' { 'CAT II' } 'Medium' { 'CAT III' } 'Low' { 'CAT III' } 'Info' { 'CAT III' } default { 'CAT III' } } }
            # Formula-injection-guarded CSV cells via the canonical ConvertTo-ReportsCsvCell
            # (audit 2026-07-23: the hand-rolled audit#5-pattern scriptblock collapsed onto
            # the helper - identical behavior, byte-for-byte output).
            $cols = @(
                'Control Vulnerability Description','Security Control Number (NIST 800-53)','CCI','Office/Org',
                'Security Checks','Resources Required','Scheduled Completion Date','Milestones with Completion Dates',
                'Milestone Changes','Source Identifying Control Vulnerability','Status','Comments','Raw Severity',
                'Mitigations','Severity','Relevance of Threat','Threat Description','Likelihood','Impact',
                'Impact Description','Residual Risk Level','Recommendations',
                'Resulting Residual Risk after Proposed Mitigations','Finding Details','Host','Finding Number'
            )
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine((($cols | ForEach-Object { ConvertTo-ReportsCsvCell $_ }) -join ','))

            $operator = ''   # Office/Org - left blank for the ISSM/ISSO to fill on submission
            $rows = New-Object System.Collections.ArrayList
            $perHostCounter = @{}
            $nOpen = 0; $nKev = 0; $nOverdue = 0
            # Open findings only, worst-severity first, then KEV, then host.
            $sevRank = $script:SeverityRank   # audit 2026-07-23: shared module-scope map
            $open = @($script:AcasFindings | Where-Object { $_.Status -ne 'Patched' -and $_.Status -ne 'NOT OUR PATCH' -and $_.Category -ne 'NOT OUR PATCH' })
            $open = @($open | Sort-Object -Property `
                @{ Expression = { if ($sevRank.ContainsKey([string]$_.Severity)) { $sevRank[[string]$_.Severity] } else { 0 } }; Descending = $true }, `
                @{ Expression = { [bool]$_.InKEV }; Descending = $true }, `
                @{ Expression = { [string]$_.Hostname } })
            foreach ($f in $open) {
                $nOpen++
                $hn = [string]$f.Hostname
                # loop14 (item 11): the per-host "Finding N" sequence keys on the normalized
                # audit key so two name forms of one host share one sequence; the POA&M row's
                # Host column below keeps the RAW name (it identifies the specific finding).
                $hnKey = Get-ReportsAuditHostKey $hn
                if (-not $perHostCounter.ContainsKey($hnKey)) { $perHostCounter[$hnKey] = 0 }
                $perHostCounter[$hnKey]++
                $isKev = [bool]$f.InKEV; if ($isKev) { $nKev++ }
                $cat = & $catOf $f.Severity
                # firstSeen: live, else ledger-backfilled.
                $fs = [string]$f.FirstSeen
                if ([string]::IsNullOrWhiteSpace($fs)) {
                    $key = "$(Get-ReportsAuditHostKey $hn)|$($f.PluginID)"
                    if ($ledMap.ContainsKey($key)) { $fs = [string]$ledMap[$key].firstSeen }
                }
                $schedDate = ''
                if (-not [string]::IsNullOrWhiteSpace($fs)) {
                    $d = [DateTime]::MinValue
                    if ([DateTime]::TryParse($fs, [ref]$d)) {
                        $win = [int](Get-ReportsSlaDeadline -Config $cfg -Severity ([string]$f.Severity) -InKev $isKev)
                        $deadline = $d.Date.AddDays($win)
                        $schedDate = $deadline.ToString('yyyy-MM-dd')
                        if ($deadline -lt $today) { $nOverdue++ }
                    }
                }
                $iava = [string]$f.IAVA
                $kevNote = if ($isKev) { 'CISA KEV known-exploited (expedited remediation).' } else { '' }
                $iavaNote = if ($iava) { "IAVM: $iava." } else { '' }
                $comments = (@($kevNote, $iavaNote) | Where-Object { $_ }) -join ' '
                $vulnDesc = "$hn`: $([string]$f.VulnName)"
                # CCI: left blank (the IAVA is NOT a CCI - it is surfaced in Comments).
                # Raw Severity: the real Tenable/ACAS severity; Severity (mapped) = DISA CAT.
                $cellVals = @(
                    $vulnDesc, '', '', $operator,
                    [string]$f.PluginID, '', $schedDate, '',
                    '', 'ACAS/Tenable scan (J.A.N.E.T.)', 'Ongoing', $comments, [string]$f.Severity,
                    '', $cat, '', [string]$f.VulnName, '', '',
                    '', '', [string]$f.Solution,
                    '', ("CVE(s): " + [string]$f.CVE), $hn, [string]$perHostCounter[$hnKey]
                )
                [void]$sb.AppendLine((($cellVals | ForEach-Object { ConvertTo-ReportsCsvCell $_ }) -join ','))
                if ($nOpen -le 500) {
                    $row = @{ Host=$hn; Finding=[string]$f.VulnName; Severity=[string]$f.Severity; CAT=$cat; Status='Ongoing'; ScheduledCompletion=$schedDate; KEV=$(if ($isKev) { 'KEV' } else { '' }) }
                    [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                }
            }
            if ($nOpen -gt 500) { & $send @{ type='log'; level='info'; text="Showing first 500 of $nOpen POA&M rows in the grid; the downloaded CSV contains all $nOpen." } }
            $csv = $sb.ToString().TrimEnd()
            & $send @{ type='status'; text="POA&M built: $nOpen open finding(s), $nKev KEV, $nOverdue past scheduled completion. Use Download CSV." }
            & $send @{ type='audit'; action='TouchHost'; target='Export eMASS POA&M (CSV)'; result='Success'; itemCount=$nOpen; detail="$nOpen POA&M row(s) exported ($nKev KEV, $nOverdue overdue)" }
            return @{ rows=@($rows); summary=@{ total=$nOpen; kev=$nKev; overdue=$nOverdue; baseline=$sla.Source; csv=$csv } }
        }

        # -------------------------------------------------------------------
        'acas-export-findings' {
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $view = ([string]$Params['view']).Trim()
            if (-not $view) { $view = 'Full (all findings)' }
            # @(...) around the whole switch: a switch unrolls a single-item branch
            # result to a scalar, which would make $sel.Count empty - force an array.
            $sel = @( switch -Wildcard ($view) {
                'Open*'          { $script:AcasFindings | Where-Object { $_.Status -ne 'Patched' -and $_.Status -ne 'NOT OUR PATCH' -and $_.Category -ne 'NOT OUR PATCH' }; break }
                'NOT OUR PATCH*' { $script:AcasFindings | Where-Object { $_.Status -eq 'NOT OUR PATCH' -or $_.Category -eq 'NOT OUR PATCH' }; break }
                'Patched*'       { $script:AcasFindings | Where-Object { $_.Status -eq 'Patched' }; break }
                'Offline*'       {
                    if ($script:AcasHostOnline.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No ping data yet - run Ping Hosts on the Import tab first; nothing to export as Offline.' } }
                    # -eq $false: CONFIRMED offline only. An 'unresolved' sentinel (DNS
                    # name did not resolve) is NOT a confirmed-offline host and is excluded.
                    $script:AcasFindings | Where-Object { $script:AcasHostOnline.ContainsKey([string]$_.Hostname) -and ($script:AcasHostOnline[[string]$_.Hostname] -eq $false) }; break
                }
                default          { $script:AcasFindings }
            } )
            & $send @{ type='status'; text="Exporting $($sel.Count) finding(s) [$view] to CSV..." }
            $csv = Export-AcasFindingsCsvText -Findings $sel
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($csv)
            $row = @{ View=$view; Findings=$sel.Count; Bytes=$bytes }
            & $send (@{ type='row' } + $row)
            & $send @{ type='audit'; action='TouchHost'; target="ACAS export findings [$view]"; result='Success'; itemCount=$sel.Count; detail="$($sel.Count) finding(s) exported to CSV ($bytes bytes)" }
            & $send @{ type='status'; text="Exported $($sel.Count) finding(s) [$view] - use Download CSV." }
            return @{ rows=@($row); summary=@{ total=$sel.Count; view=$view; bytes=$bytes; csv=$csv } }
        }

        # -------------------------------------------------------------------
        'acas-save-report' {
            # Desktop "Save Report to JSON" (6720-6732): findings + triage state.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Serializing $($script:AcasFindings.Count) finding(s) to JSON..." }
            # SLA firstSeen ledger: upsert JanetLocal\sla-ledger.json first so the aging
            # clock is authoritative and persisted OUTSIDE the report (survives a later
            # re-parse of a raw export). This stamps firstSeen back onto every live finding,
            # so the belt-and-suspenders in-report copy below just reads it (newlyStamped=0).
            $led = Update-ReportsSlaLedger -Findings $script:AcasFindings
            & $send @{ type='log'; level='info'; text="SLA ledger: $($led.Carried) clock(s) carried, $($led.Started) newly started (of $($led.Total) finding(s))." }
            if (-not $led.Written) { & $send @{ type='log'; level='warn'; text="SLA ledger not saved (firstSeen still persisted in this report JSON): $($led.Error)" } }
            # SLA finding-age clock: stamp firstSeen (ISO date) the FIRST time a
            # Hostname|PluginID key is saved; preserve any existing firstSeen on
            # re-save. The stamp is written back onto the live session object too so
            # a subsequent sla-aging run sees the key as tracked without a reload.
            $todayIso = (Get-Date).ToString('yyyy-MM-dd')
            $newlyStamped = 0
            $export = [ordered]@{
                ExportDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                ExportedBy = Get-ReportsCleanUser
                Findings   = @($script:AcasFindings | ForEach-Object {
                    $fs = if (-not [string]::IsNullOrWhiteSpace([string]$_.FirstSeen)) { [string]$_.FirstSeen } else { $newlyStamped++; $todayIso }
                    if ($_.PSObject.Properties['FirstSeen']) { $_.FirstSeen = $fs } else { $_ | Add-Member -NotePropertyName FirstSeen -NotePropertyValue $fs -Force }
                    [ordered]@{
                        Hostname=$_.Hostname; IP=$_.IP; PluginID=$_.PluginID; VulnName=$_.VulnName; Severity=$_.Severity
                        CVE=$_.CVE; Category=$_.Category; Status=$_.Status; Solution=$_.Solution
                        InKEV=$_.InKEV; KevCves=$_.KevCves; IAVA=$_.IAVA
                        FirstSeen=$fs
                        PatchedDate=$_.PatchedDate; PatchedBy=$_.PatchedBy
                    }
                })
            }
            if ($newlyStamped -gt 0) { & $send @{ type='log'; level='info'; text="Stamped firstSeen on $newlyStamped new finding(s) - the SLA aging clock is now running for them." } }
            $json = $export | ConvertTo-Json -Depth 5
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($json)
            $row = @{ Findings=$script:AcasFindings.Count; Bytes=$bytes }
            & $send (@{ type='row' } + $row)
            & $send @{ type='audit'; action='TouchHost'; target='ACAS save report (JSON)'; result='Success'; itemCount=$script:AcasFindings.Count; detail="$($script:AcasFindings.Count) finding(s) saved to JSON ($bytes bytes)" }
            & $send @{ type='status'; text="Saved $($script:AcasFindings.Count) finding(s) to JSON - use Download JSON." }
            return @{ rows=@($row); summary=@{ total=$script:AcasFindings.Count; bytes=$bytes; json=$json } }
        }

        # -------------------------------------------------------------------
        'acas-load-report' {
            # Desktop btnLoadJson (6171-6196): replace findings from a saved report.
            $filePath = [string]$Params['file']
            if ($filePath -and -not (Test-JanetUncReachable -Path $filePath)) {
                & $send @{ type='log'; level='err'; text="UNC path is unreachable (share host not responding): $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='report UNC path unreachable' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -LiteralPath $filePath)) {
                & $send @{ type='log'; level='err'; text="File not found: $filePath" }
                & $send @{ type='audit'; action='TouchHost'; target=$filePath; result='Failure'; itemCount=0; detail='report file not found' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Loading saved report: $filePath" }
            $obj = $null
            try { $obj = Get-Content -LiteralPath $filePath -Raw -Encoding UTF8 | ConvertFrom-Json }
            catch {
                & $send @{ type='log'; level='err'; text="Not valid JSON: $($_.Exception.Message)" }
                & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $filePath); result='Failure'; itemCount=0; detail='invalid JSON' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if (-not $obj -or -not $obj.Findings) {
                & $send @{ type='log'; level='err'; text="No 'Findings' in this file - not an ACAS Save Report JSON." }
                & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $filePath); result='Failure'; itemCount=0; detail='no Findings array' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            # Re-flag KEV from the CURRENT catalog rather than trusting the saved
            # value: the catalog may have grown since the report was saved, and
            # reports saved before KEV auto-flag existed carry no InKEV field.
            $kev = Read-ReportsKevCatalog
            if ($kev.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text="KEV catalog is empty/unreadable ($($kev.Source)) - loaded findings will not be KEV-flagged." }
            }
            # Re-tag IAVA from the CURRENT map too (same rationale as re-flagging KEV):
            # the map may have grown since the report was saved, and reports saved
            # before IAVM mapping existed carry no IAVA field.
            $iavm = Read-ReportsIavmMap
            if ($iavm.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text="IAVM map is empty/unreadable ($($iavm.Source)) - loaded findings will not be IAVA-tagged." }
            }
            $script:AcasFindings = New-Object System.Collections.ArrayList
            foreach ($item in $obj.Findings) {
                $ov = Get-ReportsKevOverlap -CveCell ([string]$item.CVE) -KevSet $kev.Set
                $iv = Get-ReportsIavmForCves -CveCell ([string]$item.CVE) -IavmMap $iavm.Map
                # firstSeen carries the SLA age clock across reloads; reports saved
                # before this feature carry no FirstSeen, so default to '' (untracked).
                $fsVal = if ($item.PSObject.Properties['FirstSeen']) { [string]$item.FirstSeen } else { '' }
                # loop40 P1: IP discriminator; reports saved before this field default to '' (untracked).
                $ipVal = if ($item.PSObject.Properties['IP']) { [string]$item.IP } else { '' }
                [void]$script:AcasFindings.Add([PSCustomObject]@{
                    Hostname=$item.Hostname; IP=$ipVal; PluginID=$item.PluginID; VulnName=$item.VulnName; Severity=$item.Severity
                    CVE=$item.CVE; Category=$item.Category; Status=$item.Status; Solution=$item.Solution
                    InKEV=$ov.InKev; KevCves=$ov.KevCves; IAVA=$iv.IAVA
                    FirstSeen=$fsVal
                    PatchedDate=$item.PatchedDate; PatchedBy=$item.PatchedBy
                })
            }
            $script:ComparisonResults = $null   # the import set was replaced
            $script:AcasHostOnline = @{}        # offline map must not outlive the findings it describes (#10)
            $leaf = Split-Path -Leaf $filePath
            # Stream each loaded finding as a row (same shape as acas-parse-file) so the
            # findings grid REPAINTS on load - the desktop btnLoadJson refreshes the grid.
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $rows = New-Object System.Collections.ArrayList
            $i = 0; $total = $script:AcasFindings.Count
            foreach ($f in $script:AcasFindings) {
                [void]$hostSet.Add($f.Hostname)
                $i++
                $row = @{ Host=$f.Hostname; Hostname=$f.Hostname; PluginID=$f.PluginID; VulnName=$f.VulnName; Severity=$f.Severity; CVE=$f.CVE; Category=$f.Category; Status=$f.Status; Solution=$f.Solution; InKEV=$f.InKEV; KevCves=$f.KevCves; IAVA=$f.IAVA }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                if (($i % 200) -eq 0) { & $send @{ type='progress'; done=$i; total=$total } }
            }
            & $send @{ type='progress'; done=$total; total=$total }
            $result = if ($script:AcasFindings.Count -gt 0) { 'Success' } else { 'Failure' }
            & $send @{ type='audit'; action='TouchHost'; target=$leaf; result=$result; itemCount=$script:AcasFindings.Count; detail="report loaded: $($script:AcasFindings.Count) finding(s) across $($hostSet.Count) host(s)" }
            & $send @{ type='status'; text="Loaded $($script:AcasFindings.Count) finding(s) across $($hostSet.Count) host(s) from $leaf." }
            return @{ rows=@($rows); summary=@{ total=$script:AcasFindings.Count; loaded=$script:AcasFindings.Count; hosts=$hostSet.Count; file=$leaf } }
        }

        # -------------------------------------------------------------------
        'resolve-target-ips' {
            # Parallel DNS + ping resolve (desktop Invoke-AsyncIpResolve:6798).
            # Harvest loop mirrors dirty30-probe-lastuser: staged BeginInvoke so
            # the per-job stall guard times RUNNING jobs only, full cancel
            # contract (BeginStop + null the handle, per-host cancelled rows),
            # pool Close/Dispose in finally.
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='err'; text='No target hostnames provided.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            # Only adopt a parsed value on success - [int]::TryParse zeroes its ref on
            # failure, which would turn a non-numeric value into 1 thread / 100 ms
            # instead of the intended default.
            $threads = 32; if ($Params['threads']) { $tmpT = 0; if ([int]::TryParse([string]$Params['threads'], [ref]$tmpT)) { $threads = $tmpT } }
            $threads = [Math]::Max(1, [Math]::Min(32, $threads))
            $timeoutMs = 1500; if ($Params['timeoutMs']) { $tmpO = 0; if ([int]::TryParse([string]$Params['timeoutMs'], [ref]$tmpO)) { $timeoutMs = $tmpO } }
            $timeoutMs = [Math]::Max(100, [Math]::Min(60000, $timeoutMs))

            & $send @{ type='status'; text="Resolving $($targets.Count) host(s) with $threads thread(s), $timeoutMs ms ping timeout..." }

            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = $null
            $jobs = New-Object System.Collections.ArrayList
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $online = 0; $offline = 0; $dnsFailed = 0; $timedOut = 0; $cancelledCount = 0
            # Per-job stall-guard budget: ping timeout plus generous DNS slack
            # (GetHostAddresses can block ~15s on a dead resolver).
            $jobTimeout = [TimeSpan]::FromMilliseconds($timeoutMs + 20000)
            try {
                $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
                $pool.Open()
                foreach ($t in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                    [void]$ps.AddScript($script:TargetIpResolveWorker)
                    [void]$ps.AddArgument($t)
                    [void]$ps.AddArgument($timeoutMs)
                    [void]$jobs.Add([pscustomobject]@{ Host=$t; PS=$ps; Async=$null; Started=$null })
                }
                $waves = [Math]::Ceiling($jobs.Count / [double]$threads)
                $deadline = (Get-Date).AddSeconds($jobTimeout.TotalSeconds * $waves + 10)
                $running = 0

                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($running -ge $threads) { break }
                        if ($j.PS -and -not $j.Async) {
                            $j.Async = $j.PS.BeginInvoke()
                            $j.Started = Get-Date
                            $running++
                        }
                    }
                    foreach ($j in $jobs) {
                        if ($j.PS -and $j.Async -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = $null }
                            try { $j.PS.Dispose() } catch {}
                            $j.PS = $null
                            $running--
                            $statusText = 'DNS Failed'; $ipVal = ''; $latVal = ''
                            if ($res) {
                                $ipVal = [string]$res.IP
                                if ($res.Online) {
                                    $statusText = 'Online'
                                    if ([int]$res.Latency -ge 0) { $latVal = [int]$res.Latency }
                                } elseif ($res.ResolveOk) {
                                    $statusText = 'Offline'
                                }
                            }
                            switch ($statusText) {
                                'Online'  { $online++ }
                                'Offline' { $offline++ }
                                default   { $dnsFailed++ }
                            }
                            $row = @{ Host=$j.Host; IP=$ipVal; Status=$statusText; LatencyMs=$latVal }
                            [void]$rows.Add($row)
                            & $send (@{ type='row' } + $row)
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                        elseif ($j.PS -and $j.Async -and (((Get-Date) - $j.Started) -gt $jobTimeout)) {
                            # Stalled RUNNING job: exceeded its budget. Reap it.
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $running--
                            $timedOut++
                            $row = @{ Host=$j.Host; IP=''; Status='Timeout'; LatencyMs='' }
                            [void]$rows.Add($row)
                            & $send (@{ type='row' } + $row)
                            $done++
                            & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    # Operator cancel: stop every still-running job, record it, break.
                    if ($done -lt $jobs.Count -and (& $cancelCheck)) {
                        $unresolved = $jobs.Count - $done
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} }
                                else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null
                                $cancelledCount++
                                $row = @{ Host=$j.Host; IP=''; Status='Cancelled'; LatencyMs='' }
                                [void]$rows.Add($row)
                                & $send (@{ type='row' } + $row)
                                $done++
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text="Cancelled by operator; $unresolved host(s) left unresolved." }
                        break
                    }
                    # Overall deadline guard: bail out cleanly on stuck handles.
                    if ($done -lt $jobs.Count -and (Get-Date) -gt $deadline) {
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} }
                                else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null
                                $timedOut++
                                $row = @{ Host=$j.Host; IP=''; Status='Timeout'; LatencyMs='' }
                                [void]$rows.Add($row)
                                & $send (@{ type='row' } + $row)
                                $done++
                                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text='Resolve deadline exceeded; remaining host(s) marked Timeout.' }
                        break
                    }
                    if ($done -lt $jobs.Count) { Start-Sleep -Milliseconds 120 }
                }
            } finally {
                foreach ($j in $jobs) { if ($j.PS) { try { $j.PS.Dispose() } catch {} } }
                if ($pool) { try { $pool.Close(); $pool.Dispose() } catch {} }
            }
            $auditResult = if ($cancelledCount -gt 0) { 'Failure' } else { 'Success' }
            & $send @{ type='audit'; action='TouchHost'; target="Resolve Target IPs ($($jobs.Count) hosts)"; result=$auditResult; itemCount=($online + $offline); detail="online $online, offline $offline, dns-failed $dnsFailed, timeout $timedOut, cancelled $cancelledCount" }
            & $send @{ type='status'; text="Done. Online $online, offline $offline, DNS failed $dnsFailed, timeout $timedOut, cancelled $cancelledCount of $($jobs.Count)." }
            return @{ rows=@(); summary=@{ total=$jobs.Count; online=$online; offline=$offline; dnsFailed=$dnsFailed; timedOut=$timedOut; cancelled=$cancelledCount } }
        }

        # -------------------------------------------------------------------
        'acas-ping-hosts' {
            # Ping every DISTINCT host in the loaded findings, in parallel, and cache
            # an online/offline map ($script:AcasHostOnline) the import grid filters on
            # + the Offline export reads. Reuses the resolve-target-ips runspace pattern
            # (TargetIpResolveWorker, staged BeginInvoke, stall guard, cancel contract)
            # but ping-only and host-set-from-findings. (#10)
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse an ACAS file first.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($f in $script:AcasFindings) { if ($f.Hostname) { [void]$hostSet.Add([string]$f.Hostname) } }
            $targets = @($hostSet)
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No host names on the loaded findings to ping.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $threads = 32; if ($Params['threads']) { $tmpT = 0; if ([int]::TryParse([string]$Params['threads'], [ref]$tmpT)) { $threads = $tmpT } }
            $threads = [Math]::Max(1, [Math]::Min(32, $threads))
            $timeoutMs = 1500; if ($Params['timeoutMs']) { $tmpO = 0; if ([int]::TryParse([string]$Params['timeoutMs'], [ref]$tmpO)) { $timeoutMs = $tmpO } }
            $timeoutMs = [Math]::Max(100, [Math]::Min(60000, $timeoutMs))

            & $send @{ type='status'; text="Pinging $($targets.Count) distinct host(s) with $threads thread(s), $timeoutMs ms timeout..." }
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pool = $null
            $jobs = New-Object System.Collections.ArrayList
            $rows = New-Object System.Collections.ArrayList
            $done = 0; $online = 0; $offline = 0; $unresolved = 0; $timedOut = 0; $cancelledCount = 0
            $jobTimeout = [TimeSpan]::FromMilliseconds($timeoutMs + 20000)
            try {
                $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
                $pool.Open()
                foreach ($t in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                    [void]$ps.AddScript($script:TargetIpResolveWorker)
                    [void]$ps.AddArgument($t)
                    [void]$ps.AddArgument($timeoutMs)
                    [void]$jobs.Add([pscustomobject]@{ Host=$t; PS=$ps; Async=$null; Started=$null })
                }
                $waves = [Math]::Ceiling($jobs.Count / [double]$threads)
                $deadline = (Get-Date).AddSeconds($jobTimeout.TotalSeconds * $waves + 10)
                $running = 0
                while ($done -lt $jobs.Count) {
                    foreach ($j in $jobs) {
                        if ($running -ge $threads) { break }
                        if ($j.PS -and -not $j.Async) { $j.Async = $j.PS.BeginInvoke(); $j.Started = Get-Date; $running++ }
                    }
                    foreach ($j in $jobs) {
                        if ($j.PS -and $j.Async -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = $null }
                            try { $j.PS.Dispose() } catch {}
                            $j.PS = $null; $running--
                            # Tri-state: a NAME that would not resolve (ResolveOk=false) is
                            # NOT the same as a resolved-but-powered-off host. Store the
                            # confirmed-offline hosts as $false, unresolved as 'unresolved'
                            # (truthy sentinel) so the Offline export (== $false) skips them.
                            # audit 2026-07-24: a NEVER-PROBED host (stall reaper / deadline
                            # sweep below) is a third non-confirmed case - 'timeout'.
                            if ($res -and $res.Online) {
                                $online++; $script:AcasHostOnline[[string]$j.Host] = $true; $pStatus = 'Online'
                            } elseif ($res -and $res.ResolveOk) {
                                $offline++; $script:AcasHostOnline[[string]$j.Host] = $false; $pStatus = 'Offline'
                            } else {
                                $unresolved++; $script:AcasHostOnline[[string]$j.Host] = 'unresolved'; $pStatus = 'Unresolved'
                            }
                            $row = @{ Host=$j.Host; Online=$pStatus }
                            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                            $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                        elseif ($j.PS -and $j.Async -and (((Get-Date) - $j.Started) -gt $jobTimeout)) {
                            # Stalled RUNNING job: reaped before it answered. audit 2026-07-24
                            # (BUG): this recorded $false = CONFIRMED offline, so a host we
                            # NEVER got a probe result for landed in the "Offline (host down)"
                            # export. Honour the tri-state contract above - a 'timeout' sentinel
                            # is truthy, so the Offline export (== $false) skips it - and tally
                            # it separately, mirroring resolve-target-ips (:6672).
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null; $running--
                            $script:AcasHostOnline[[string]$j.Host] = 'timeout'
                            $row = @{ Host=$j.Host; Online='Timeout' }
                            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                            $timedOut++; $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                        }
                    }
                    if ($done -lt $jobs.Count -and (& $cancelCheck)) {
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} } else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null; $cancelledCount++
                                # audit 2026-07-25 (fable re-audit follow-up): the cancel sweep
                                # emitted '?' to the grid but left the server-side map holding
                                # whatever a PREVIOUS ping wrote, so a host confirmed $false last
                                # run stayed in the "Offline (host down)" export (:6487) while the
                                # grid showed '?' - the same grid-vs-CSV disagreement the tri-state
                                # closed for Unresolved/Timeout. 'cancelled' is truthy, so the
                                # ==$false export skips it: cancelled is NOT confirmed-offline.
                                $script:AcasHostOnline[[string]$j.Host] = 'cancelled'
                                $row = @{ Host=$j.Host; Online='?' }
                                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining hosts not pinged.' }
                        break
                    }
                    if ($done -lt $jobs.Count -and (Get-Date) -gt $deadline) {
                        foreach ($j in $jobs) {
                            if ($j.PS) {
                                if ($j.Async) { try { [void]$j.PS.BeginStop($null, $null) } catch {} } else { try { $j.PS.Dispose() } catch {} }
                                $j.PS = $null
                                # audit 2026-07-24: same never-probed case as the stall reaper -
                                # the deadline sweep must NOT claim these hosts are down.
                                $script:AcasHostOnline[[string]$j.Host] = 'timeout'
                                $row = @{ Host=$j.Host; Online='Timeout' }
                                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                                $timedOut++; $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                            }
                        }
                        & $send @{ type='log'; level='warn'; text='Ping deadline exceeded; remaining host(s) marked Timeout (never probed - NOT counted as offline).' }
                        break
                    }
                    if ($done -lt $jobs.Count) { Start-Sleep -Milliseconds 120 }
                }
            } finally {
                foreach ($j in $jobs) { if ($j.PS) { try { $j.PS.Dispose() } catch {} } }
                if ($pool) { try { $pool.Close(); $pool.Dispose() } catch {} }
            }
            & $send @{ type='audit'; action='TouchHost'; target="ACAS ping hosts ($($jobs.Count))"; result=$(if ($cancelledCount -gt 0) { 'Failure' } else { 'Success' }); itemCount=$online; detail="online $online, offline $offline, unresolved $unresolved, timeout $timedOut, cancelled $cancelledCount" }
            & $send @{ type='status'; text="Ping done. Online $online, offline $offline$(if ($unresolved) { ", unresolved $unresolved" })$(if ($timedOut) { ", timeout $timedOut" })$(if ($cancelledCount) { ", cancelled $cancelledCount" }) of $($jobs.Count)." }
            return @{ rows=@(); summary=@{ total=$jobs.Count; online=$online; offline=$offline; unresolved=$unresolved; timedOut=$timedOut; cancelled=$cancelledCount } }
        }

        # -------------------------------------------------------------------
        'squadron-rollup' {
            # Read-only fleet rollup over the central log share. NO audit rows are
            # emitted (this action is read-only; SessionEnd usage logging is the
            # server's job) - just status/log/row events for the UI.
            $monthsBack = 1
            if ($Params -and $Params.ContainsKey('monthsBack')) {
                $mb = 0
                if ([int]::TryParse([string]$Params['monthsBack'], [ref]$mb) -and $mb -gt 0) { $monthsBack = $mb }
            }
            if ($monthsBack -gt 24) { $monthsBack = 24 }
            $months = @(Get-ReportsRollupMonths -MonthsBack $monthsBack)
            $root   = Get-ReportsLogShareRoot

            & $send @{ type='status'; text="Squadron rollup: probing log share (SMB/445) $root ..." }
            # 445-gate the share (reuse the module's TCP-445 pre-gate), then confirm the
            # root is actually listable. An unreachable share -> friendly failure summary.
            $shareOk = $false
            try { $shareOk = ((Test-JanetUncReachable -Path $root) -and (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) } catch { $shareOk = $false }
            if (-not $shareOk) {
                & $send @{ type='log'; level='err'; text="Log share unreachable - SMB/445 to the log server did not answer (or the root is not listable): $root. The rollup needs the central JANET log share; try again on-network." }
                & $send @{ type='status'; text='Log share unreachable - no rollup produced.' }
                $script:LastSquadronRollup = @{ shareOk=$false; months=($months -join ', ') }
                return @{ rows=@(); summary=@{
                    total=0; shareOk=$false; months=($months -join ', ')
                    operators=0; hosts=0; vulns=0; failPct=0
                    message="Log share unreachable: $root"
                } }
            }

            $maxRows    = 400000     # detail-row parse cap across every tool/month (perf guard)
            $rowsParsed = 0
            $capped     = $false
            $ops        = @{}        # operator string -> New-ReportsRollupOp accumulator
            $hostTally  = @{}        # HOST(UPPER)     -> @{Actions;TouchOK;TouchFail;Vulns;LastActive} for the squadron fold
            $filesRead  = 0

            # audit 2026-07-25 (fable re-audit follow-up): every walk below used to be
            # `-ErrorAction SilentlyContinue` inside a BARE `catch {}`, so a denied or
            # vanished directory contributed ZERO rows and said nothing - "could not read
            # the share" rendered as "nobody did any work". Record each failing path here
            # and carry readErrors/readFailed out in the summary, the same error-bag
            # contract JanetWeb.history.psm1 adopted, so neither the grid nor the Command
            # Brief can present a confident empty rollup over a tree we never walked.
            # (Keys are Errors/Messages, NOT 'Count' - a hashtable's real .Count property
            # would shadow that key.)
            $readBag = @{ Errors = 0; Messages = (New-Object System.Collections.ArrayList) }
            $addReadErr = {
                param([string]$Path, $Err)
                $readBag.Errors++
                if ($readBag.Messages.Count -lt 25) {
                    $m = if ($Err) { [string]$Err.Exception.Message } else { 'not readable' }
                    [void]$readBag.Messages.Add(("{0} ({1})" -f $Path, $m))
                }
            }

            # ---- Pass A: the monthly usage rollup at the share root -------------------
            # SessionEnd + aggregate rows (Tool=JANET-WEB, or the TWO-era JANET-TWO on
            # historical rows): seeds operators (incl. those
            # whose sessions did only read-only work, so they never wrote a detail row)
            # and their session ids + last-active. One small file per month.
            foreach ($m in $months) {
                if (& $cancelCheck) { break }
                # audit 2026-07-25 (fable re-audit follow-up): glob '<m>_usage*.csv', not the
                # exact name. When the live rollup is locked, Invoke-JanetWebHeaderEnsure
                # redirects rows to a sister '<base>.r<unix>.csv' (server\JanetWeb.Logging.ps1
                # :423), so an exact-name read made whole live web sessions invisible to this
                # pass. history.psm1 already globs this way; '*.legacy_*' rotations stay
                # excluded (stale schema - the replay path skips them the same way).
                $usageFiles = @()
                try {
                    $usageFiles = @(Get-ChildItem -LiteralPath $root -Filter ($m + '_usage*.csv') -File -ErrorAction Stop |
                        Where-Object { $_.Name -notlike '*.legacy_*' })
                } catch {
                    & $send @{ type='log'; level='warn'; text="Could not list the usage rollup for ${m}: $($_.Exception.Message)" }
                    & $addReadErr $root $_
                }
                foreach ($uf in $usageFiles) {
                if (& $cancelCheck) { break }
                $usagePath = $uf.FullName
                & $send @{ type='status'; text="Reading usage rollup $($uf.Name) ..." }
                try {
                    Import-Csv -LiteralPath $usagePath -ErrorAction Stop | ForEach-Object {
                        # audit 2026-07-24 (S4): accept Snapshot as well as SessionEnd. Snapshot
                        # rows are the LIVE cumulative rollup, so a still-running or killed
                        # session used to be invisible here. The aggregate-row filter below is
                        # what scopes this pass to JANET Web (desktop tools share the per-tool
                        # names but never write 'JANET-WEB'), and Write-JanetWebUsageSnapshot now
                        # emits that aggregate row too. $op.Sessions is a HashSet, so the ~5-min
                        # cumulative re-emission adds each SessionId exactly once.
                        $rowType = [string]$_.RowType
                        if ($rowType -ne 'SessionEnd' -and $rowType -ne 'Snapshot') { return }
                        if ('JANET-WEB','JANET-TWO' -notcontains [string]$_.Tool) { return }
                        $opName = [string]$_.Operator
                        if ([string]::IsNullOrWhiteSpace($opName)) { return }
                        $op = $ops[$opName]
                        if (-not $op) { $op = New-ReportsRollupOp -Name $opName; $ops[$opName] = $op }
                        $sid = [string]$_.SessionId
                        if ($sid) { [void]$op.Sessions.Add($sid) }
                        $ts = [string]$_.Timestamp
                        if ($ts -and ([string]::Compare($ts, $op.LastActive) -gt 0)) { $op.LastActive = $ts }
                    }
                    $filesRead++
                } catch {
                    & $send @{ type='log'; level='warn'; text="Skipped unreadable usage rollup $($uf.Name): $($_.Exception.Message)" }
                    & $addReadErr $usagePath $_
                }
                }
            }

            # ---- Pass B: per-tool detail CSVs (the per-action truth) ------------------
            # Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv. Streamed via Import-Csv |
            # ForEach so only one row is in memory at a time; capped at $maxRows.
            # audit 2026-07-25 (fable re-audit follow-up): -ErrorAction Stop + a RECORDING
            # catch on all three walks (see $addReadErr above) - a denied tool/user folder
            # must not read as an idle one.
            $toolDirs = @()
            try { $toolDirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop) }
            catch { & $send @{ type='log'; level='warn'; text="Could not list the log share root ${root}: $($_.Exception.Message)" }; & $addReadErr $root $_ }
            foreach ($td in $toolDirs) {
                if ($capped -or (& $cancelCheck)) { break }
                $toolName = $td.Name
                $userDirs = @()
                try { $userDirs = @(Get-ChildItem -LiteralPath $td.FullName -Directory -ErrorAction Stop) }
                catch { & $send @{ type='log'; level='warn'; text="Could not list operator folders under ${toolName}: $($_.Exception.Message)" }; & $addReadErr $td.FullName $_ }
                foreach ($ud in $userDirs) {
                    if ($capped -or (& $cancelCheck)) { break }
                    $userFolder = $ud.Name
                    foreach ($m in $months) {
                        if ($capped -or (& $cancelCheck)) { break }
                        # Read the live <m>_detail.csv AND any sister '<base>.r<unix>.csv'
                        # the logging writer redirected rows to when the live file was
                        # locked (Invoke-JanetWebHeaderEnsure). Exclude '*.legacy_*'
                        # rotations - stale schema (matches the replay convention).
                        $detailFiles = @()
                        try {
                            $detailFiles = @(Get-ChildItem -LiteralPath $ud.FullName -Filter ($m + '_detail*.csv') -File -ErrorAction Stop |
                                Where-Object { $_.Name -notlike '*.legacy_*' })
                        } catch {
                            & $send @{ type='log'; level='warn'; text="Could not list ${toolName}/${userFolder} for ${m}: $($_.Exception.Message)" }
                            & $addReadErr $ud.FullName $_
                        }
                        foreach ($df in $detailFiles) {
                            if ($capped -or (& $cancelCheck)) { break }
                            $detailPath = $df.FullName
                            & $send @{ type='status'; text="Reading $toolName / $userFolder / $($df.Name) ..." }
                            try {
                                Import-Csv -LiteralPath $detailPath -ErrorAction Stop | ForEach-Object {
                                    # Honor cap/cancel MID-file: a throw tears down the
                                    # pipeline so Import-Csv stops reading the rest of a
                                    # huge CSV over SMB (a plain return keeps streaming it).
                                    if ($rowsParsed -ge $maxRows) { $capped = $true; throw 'JANET_ROLLUP_STOP' }
                                    if ((($rowsParsed % 1000) -eq 0) -and (& $cancelCheck)) { throw 'JANET_ROLLUP_STOP' }
                                    $rowsParsed++

                                $opName = [string]$_.Operator
                                if ([string]::IsNullOrWhiteSpace($opName)) { $opName = $userFolder }
                                $rowTool = [string]$_.Tool
                                if ([string]::IsNullOrWhiteSpace($rowTool)) { $rowTool = $toolName }
                                $action = [string]$_.Action
                                $result = [string]$_.Result
                                $target = ([string]$_.Target).Trim()
                                $sid    = [string]$_.SessionId
                                $ts     = [string]$_.Timestamp
                                $ic = 0; [void][int]::TryParse([string]$_.ItemCount, [ref]$ic)

                                $op = $ops[$opName]
                                if (-not $op) { $op = New-ReportsRollupOp -Name $opName; $ops[$opName] = $op }
                                $op.Actions++
                                $op.Tools[$rowTool] = ([int]$op.Tools[$rowTool]) + 1
                                if ($sid) { [void]$op.Sessions.Add($sid) }
                                if ($ts -and ([string]::Compare($ts, $op.LastActive) -gt 0)) { $op.LastActive = $ts }
                                if ($action -eq 'TouchHost') {
                                    if ($result -eq 'Success')     { $op.TouchOK++ }
                                    elseif ($result -eq 'Failure') { $op.TouchFail++ }
                                }
                                if ($action -eq 'VulnPatched' -and $result -ne 'Failure') { $op.Vulns += $ic }

                                # Real machine targets only for the distinct-host count and
                                # the per-host squadron fold. Beyond the desktop sentinels,
                                # this module writes descriptive TouchHost targets (report/
                                # scan file names, 'ACAS save report (JSON)', 'Remediation
                                # plan: plugin NNN', 'ACAS export findings [view]') that must
                                # NOT count as hosts: require a hostname-shaped token (no
                                # spaces/brackets/colons/parens) on a TouchHost/VulnPatched row.
                                $isRealHost = ($action -eq 'TouchHost' -or $action -eq 'VulnPatched') -and
                                              $target -and $target -ne 'N/A' -and $target -ne '(custom command)' -and
                                              ($target -match '^[A-Za-z0-9][A-Za-z0-9.\-]{0,62}$')
                                if ($isRealHost) {
                                    [void]$op.Hosts.Add($target)
                                    $hu = $target.ToUpper()
                                    $ht = $hostTally[$hu]
                                    if (-not $ht) { $ht = @{ Actions=0; TouchOK=0; TouchFail=0; Vulns=0; LastActive='' }; $hostTally[$hu] = $ht }
                                    $ht.Actions++
                                    if ($action -eq 'TouchHost') {
                                        if ($result -eq 'Success')     { $ht.TouchOK++ }
                                        elseif ($result -eq 'Failure') { $ht.TouchFail++ }
                                    }
                                    if ($action -eq 'VulnPatched' -and $result -ne 'Failure') { $ht.Vulns += $ic }
                                    if ($ts -and ([string]::Compare($ts, $ht.LastActive) -gt 0)) { $ht.LastActive = $ts }
                                }
                            }
                                $filesRead++
                            } catch {
                                # The JANET_ROLLUP_STOP sentinel is our own mid-file cap/
                                # cancel break, not a read error - do not log it as unreadable.
                                if ([string]$_.Exception.Message -ne 'JANET_ROLLUP_STOP') {
                                    & $send @{ type='log'; level='warn'; text="Skipped unreadable detail ${toolName}/${userFolder}/$($df.Name): $($_.Exception.Message)" }
                                    & $addReadErr $detailPath $_    # audit 2026-07-25: count it, not just log it
                                }
                            }
                            if ($capped) {
                                & $send @{ type='log'; level='warn'; text="Detail parse cap reached ($maxRows rows) - remaining detail files were not read. Reduce the month count for a complete pass." }
                                break
                            }
                            if (& $cancelCheck) { break }
                        }
                        if ($capped) { break }
                    }
                }
            }

            # ---- Squadron classification (optional; needs AD + a credential) ----------
            # Reuses the module's Get-Dirty30AdInfo OU/location -> squadron classifier.
            # It binds AD with the calling thread identity; we only attempt it when the
            # operator has set credentials (per the read-only cred contract). No credential
            # OR no AD hit -> degrade to operator-level only and say so in the summary.
            $squadronResolved = $false
            $squadronNote = 'Operator-level only - set credentials to enable AD squadron classification.'
            $sq = @{}
            $hostCap = 750
            if ($Credential -and $hostTally.Count -gt 0 -and -not (& $cancelCheck)) {
                $distinctHosts = @($hostTally.Keys)
                $hostNote = ''
                if ($distinctHosts.Count -gt $hostCap) {
                    $distinctHosts = @($distinctHosts[0..($hostCap - 1)])
                    $hostNote = " (AD lookup capped at $hostCap of $($hostTally.Count) hosts)"
                }
                & $send @{ type='status'; text="Classifying $($distinctHosts.Count) host(s) by squadron via AD..." }
                $adMap = @{}
                try { $adMap = Get-Dirty30AdInfo -Hostnames $distinctHosts -CancelCheck $cancelCheck -Send $null }
                catch {
                    & $send @{ type='log'; level='warn'; text="AD squadron lookup failed ($($_.Exception.Message)) - falling back to operator-level only." }
                    $adMap = @{}
                }
                if ($adMap.Count -gt 0) {
                    foreach ($hu in $hostTally.Keys) {
                        $ht = $hostTally[$hu]
                        $ad = $adMap[$hu]
                        $sqName = if ($ad -and -not [string]::IsNullOrWhiteSpace([string]$ad.Squadron)) { [string]$ad.Squadron } else { 'UNKNOWN' }
                        $bucket = $sq[$sqName]
                        if (-not $bucket) {
                            $bucket = @{ Name=$sqName; Actions=0; TouchOK=0; TouchFail=0; Vulns=0; LastActive=''
                                         Hosts=(New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)) }
                            $sq[$sqName] = $bucket
                        }
                        $bucket.Actions   += [int]$ht.Actions
                        $bucket.TouchOK   += [int]$ht.TouchOK
                        $bucket.TouchFail += [int]$ht.TouchFail
                        $bucket.Vulns     += [int]$ht.Vulns
                        [void]$bucket.Hosts.Add($hu)
                        if ($ht.LastActive -and ([string]::Compare([string]$ht.LastActive, $bucket.LastActive) -gt 0)) { $bucket.LastActive = $ht.LastActive }
                    }
                    $squadronResolved = $true
                    $squadronNote = "AD squadron classification on$hostNote."
                }
            } elseif (-not $Credential) {
                $squadronNote = 'Operator-level only - no credentials set, so hostnames were not classified to squadrons in AD.'
            }

            # ---- Build + emit rows (squadrons first, then operators) ------------------
            $rows = New-Object System.Collections.ArrayList
            $csv  = New-Object System.Text.StringBuilder
            [void]$csv.AppendLine('Level,Name,Actions,Hosts,TouchOK,TouchFail,Vulns,Sessions,TopTools,LastActive')
            $addCsv = {
                param($r)
                $cells = @($r.Level,$r.Name,$r.Actions,$r.Hosts,$r.TouchOK,$r.TouchFail,$r.Vulns,$r.Sessions,$r.TopTools,$r.LastActive)
                [void]$csv.AppendLine((($cells | ForEach-Object { ConvertTo-ReportsCsvCell ([string]$_) }) -join ','))
            }

            if ($squadronResolved) {
                foreach ($e in ($sq.GetEnumerator() | Sort-Object { [int]$_.Value.Actions } -Descending)) {
                    $b = $e.Value
                    $row = @{
                        Level='Squadron'; Name=$b.Name; Actions=$b.Actions; Hosts=$b.Hosts.Count
                        TouchOK=$b.TouchOK; TouchFail=$b.TouchFail; Vulns=$b.Vulns; Sessions=''
                        TopTools=''; LastActive=$b.LastActive
                    }
                    [void]$rows.Add($row); & $send (@{ type='row' } + $row); & $addCsv $row
                }
            }

            foreach ($e in ($ops.GetEnumerator() | Sort-Object { [int]$_.Value.Actions } -Descending)) {
                $o = $e.Value
                $topTools = ''
                if ($o.Tools.Count -gt 0) {
                    $topTools = (($o.Tools.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 |
                                 ForEach-Object { "$($_.Key)($($_.Value))" }) -join ', ')
                }
                $row = @{
                    Level='Operator'; Name=$o.Name; Actions=$o.Actions; Hosts=$o.Hosts.Count
                    TouchOK=$o.TouchOK; TouchFail=$o.TouchFail; Vulns=$o.Vulns; Sessions=$o.Sessions.Count
                    TopTools=$topTools; LastActive=$o.LastActive
                }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row); & $addCsv $row
            }

            # ---- Fleet stat-card totals ----------------------------------------------
            $totVulns=0; $totOK=0; $totFail=0; $totActions=0
            foreach ($k in $ops.Keys) {
                $o = $ops[$k]
                $totVulns   += [int]$o.Vulns
                $totOK      += [int]$o.TouchOK
                $totFail    += [int]$o.TouchFail
                $totActions += [int]$o.Actions
            }
            $denom = $totOK + $totFail
            $failPct = if ($denom -gt 0) { [math]::Round(($totFail / $denom) * 100, 1) } else { 0 }

            # audit 2026-07-25 (fable re-audit follow-up): surface the read failures as an
            # operator-visible error BEFORE the totals land, and mark the whole rollup
            # incomplete - a zero/short rollup over a tree we could not walk is UNKNOWN,
            # not "no activity". readFailed rides out in the summary + the Command Brief
            # cache so no downstream renderer can present it as a confident result.
            $readErrors = [int]$readBag.Errors
            $readFailed = ($readErrors -gt 0)
            $errNote = ''
            if ($readFailed) {
                $errNote = " READ ERRORS - INCOMPLETE ($readErrors path(s) unreadable)."
                & $send @{ type='error'; text="Rollup INCOMPLETE - $readErrors log-share path(s) could not be read (first: $($readBag.Messages[0])). Operators, hosts and squadrons missing from this rollup may simply be unreadable, NOT inactive - this is no proof of no activity until the share reads clean." }
            }
            $capNote = if ($capped) { " Detail parsing was capped at $maxRows rows - lower the month count for a complete pass." } else { '' }
            & $send @{ type='status'; text="Rollup: $($ops.Count) operator(s), $($hostTally.Count) distinct host(s), $totVulns vuln(s) patched, $failPct% fleet failure over $($months -join ', ').$capNote$errNote" }

            # Cache a compact summary for the Executive Command Brief (feature) so the
            # brief can render a squadron section without re-reading the whole log share.
            $script:LastSquadronRollup = @{
                shareOk=$true; months=($months -join ', '); operators=$ops.Count; hosts=$hostTally.Count
                vulns=$totVulns; failPct=$failPct; squadronResolved=$squadronResolved; rows=@($rows)
                readErrors=$readErrors; readFailed=$readFailed   # audit 2026-07-25: the brief must not quote an incomplete rollup as fact
            }

            return @{ rows=@($rows); summary=@{
                total=$rows.Count; shareOk=$true; months=($months -join ', ')
                operators=$ops.Count; hosts=$hostTally.Count; vulns=$totVulns; actions=$totActions
                touchOk=$totOK; touchFail=$totFail; failPct=$failPct
                squadronResolved=$squadronResolved; squadronNote=$squadronNote; squadrons=$sq.Count
                capped=$capped; rowsParsed=$rowsParsed; maxRows=$maxRows; filesRead=$filesRead
                # audit 2026-07-25 (fable re-audit follow-up): "could not look" != "nothing there".
                readErrors=$readErrors; readFailed=$readFailed; readErrorPaths=@($readBag.Messages)
                csv=$csv.ToString().TrimEnd()
            } }
        }

        # -------------------------------------------------------------------
        # Executive Command Brief (feature): roll the other reports up into one
        # self-contained HTML page. Each section reads its OWN source (loaded
        # findings + SLA ledger/baseline, the session's last Squadron Rollup, the
        # newest local WPT snapshots, the session's last scan compare) and degrades
        # to a "run X first" note when that source is empty. Read-only.
        'command-brief' {
            & $send @{ type='status'; text='Assembling executive command brief (SLA + KEV + squadron + trend + routing + closure)...' }
            $openFilter = { param($f) $f.Status -ne 'Patched' -and $f.Status -ne 'NOT OUR PATCH' -and $f.Category -ne 'NOT OUR PATCH' }

            # ---- (a) SLA buckets (ledger-backed; mirrors the sla-aging logic) ----
            $slaSec = @{ HasData=$false; Note='No ACAS findings loaded - run ACAS Parse File (or Load Report) on the ACAS Import tab first.' }
            if ($script:AcasFindings.Count -gt 0) {
                $sla = Get-ReportsSlaBaseline; $cfg = $sla.Config
                $ledger = Get-ReportsSlaLedger; $ledMap = $ledger.Map
                $today = (Get-Date).Date
                $cOverdue=0; $cDueSoon=0; $cOnTrack=0; $cUntracked=0
                $overdueList = New-Object System.Collections.ArrayList
                foreach ($f in $script:AcasFindings) {
                    # audit 2026-07-25 (fable re-audit follow-up): exact literal, mirroring the
                    # sla-aging skip this section reproduces (:6293) and host-summary (:6220).
                    if ($f.Status -eq 'Patched') { continue }
                    if ($f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH') { continue }
                    $inKev = [bool]$f.InKEV
                    $fsRaw = if ($f.PSObject.Properties['FirstSeen']) { [string]$f.FirstSeen } else { '' }
                    if ([string]::IsNullOrWhiteSpace($fsRaw)) {
                        $lk = "$(Get-ReportsAuditHostKey $f.Hostname)|$($f.PluginID)"
                        if ($ledMap.ContainsKey($lk) -and -not [string]::IsNullOrWhiteSpace([string]$ledMap[$lk].firstSeen)) { $fsRaw = [string]$ledMap[$lk].firstSeen }
                    }
                    $fsDate = [datetime]::MinValue; $parsed = $false
                    if (-not [string]::IsNullOrWhiteSpace($fsRaw)) { $parsed = [datetime]::TryParse($fsRaw, [ref]$fsDate) }
                    if (-not $parsed) { $cUntracked++; continue }
                    $age = [int][Math]::Floor(($today - $fsDate.Date).TotalDays); if ($age -lt 0) { $age = 0 }
                    $deadline = Get-ReportsSlaDeadline -Config $cfg -Severity ([string]$f.Severity) -InKev $inKev
                    $slaB = Get-ReportsSlaBucket -Deadline ([int]$deadline) -Age ([int]$age)   # loop21: shared boundary rule
                    $dueIn = $slaB.DueIn
                    if ($slaB.Bucket -eq 'OVERDUE') { $cOverdue++; [void]$overdueList.Add(@{ Host=[string]$f.Hostname; Plugin=[string]$f.PluginID; VulnName=[string]$f.VulnName; Severity=[string]$f.Severity; DueIn=$dueIn }) }
                    elseif ($slaB.Bucket -eq 'DUE-SOON') { $cDueSoon++ }
                    else { $cOnTrack++ }
                }
                $topOverdue = @($overdueList | Sort-Object @{ Expression = { [int]$_.DueIn } } | Select-Object -First 12)
                $slaSec = @{ HasData=$true; Overdue=$cOverdue; DueSoon=$cDueSoon; OnTrack=$cOnTrack; Untracked=$cUntracked
                             Total=($cOverdue+$cDueSoon+$cOnTrack+$cUntracked); Baseline=$sla.Source; TopOverdue=$topOverdue }
            }

            # ---- (b) KEV posture (open + actionable, known-exploited) ----
            $kevSec = @{ HasData=$false; Note='No ACAS findings loaded - run ACAS Parse File first.' }
            if ($script:AcasFindings.Count -gt 0) {
                $kevItems = New-Object System.Collections.ArrayList
                $kevHosts = New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($f in $script:AcasFindings) {
                    if (-not (& $openFilter $f)) { continue }
                    if (-not [bool]$f.InKEV) { continue }
                    # loop13: count DISTINCT KEV hosts by the normalized audit key (short+FQDN
                    # of one host fold to one) so "Hosts=" agrees with CORA. The per-finding
                    # kevItems row below keeps the RAW hostname (it names the specific finding).
                    $hk = Get-ReportsAuditHostKey ([string]$f.Hostname)
                    if (-not [string]::IsNullOrWhiteSpace($hk)) { [void]$kevHosts.Add($hk) }
                    $cve = if (-not [string]::IsNullOrWhiteSpace([string]$f.KevCves)) { [string]$f.KevCves } else { [string]$f.CVE }
                    [void]$kevItems.Add(@{ Host=[string]$f.Hostname; Plugin=[string]$f.PluginID; VulnName=[string]$f.VulnName; CVE=$cve })
                }
                $kevTop = @($kevItems | Select-Object -First 25)
                $kevSec = @{ HasData=$true; OpenKev=$kevItems.Count; Hosts=$kevHosts.Count; Items=$kevTop; Truncated=($kevItems.Count -gt $kevTop.Count) }
            }

            # ---- (c) Squadron rollup (the session's last run; heavy read is its own action) ----
            $sqSec = @{ HasData=$false; Note='No squadron rollup this session - open Squadron Rollup and Run Rollup first.' }
            if ($script:LastSquadronRollup) {
                $lr = $script:LastSquadronRollup
                if ($lr.shareOk -eq $false) {
                    $sqSec = @{ HasData=$false; Note="Last squadron rollup could not reach the log share ($($lr.months)) - re-run Squadron Rollup on-network." }
                } else {
                    # audit 2026-07-25 (fable re-audit follow-up): carry the rollup's read-failure
                    # state into the brief so a partial rollup is not quoted as fleet fact.
                    $sqSec = @{ HasData=$true; Months=$lr.months; Operators=$lr.operators; Hosts=$lr.hosts; Vulns=$lr.vulns
                                FailPct=$lr.failPct; SquadronResolved=$lr.squadronResolved; Rows=@($lr.rows | Select-Object -First 15)
                                ReadFailed=[bool]$lr.readFailed; ReadErrors=[int]$lr.readErrors }
                }
            }

            # ---- (d) Fleet compliance trend (small private read of the newest WPT snapshot CSVs; NO wpt import) ----
            $trendSec = @{ HasData=$false; Note='No fleet snapshots yet - run a WPT Bulk Scan with "Save snapshot for trending" checked.' }
            $snapDir = Join-Path $PSScriptRoot '..\JanetLocal\snapshots'
            if (Test-Path -LiteralPath $snapDir) {
                $snapFiles = @(Get-ChildItem -LiteralPath $snapDir -Filter 'wpt-bulkscan_*.csv' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 6)
                if ($snapFiles.Count -gt 0) {
                    $points = New-Object System.Collections.ArrayList
                    foreach ($sf in $snapFiles) {
                        $srows = $null; try { $srows = @(Import-Csv -LiteralPath $sf.FullName -ErrorAction Stop) } catch { continue }
                        $total=0; $online=0; $pending=0; $reboot=0; $stamp=''
                        foreach ($r in $srows) {
                            $total++
                            if ([string]::IsNullOrWhiteSpace($stamp)) { $stamp = [string]$r.ScanStamp }
                            $isOnline = (([string]$r.Online) -match '^(?i:true|1|yes)$'); if ($isOnline) { $online++ }
                            $m=0; $mOk=[int]::TryParse([string]$r.MECMUpdateCount, [ref]$m)
                            $w=0; $wOk=[int]::TryParse([string]$r.WindowsUpdateCount, [ref]$w)
                            $a=0; $aOk=[int]::TryParse([string]$r.AppUpdateCount, [ref]$a)
                            $sum = $m + $w + $a
                            $hasErr = ($isOnline -and -not ($mOk -and $wOk -and $aOk))
                            if ((($sum -gt 0) -or $hasErr) -and -not [string]::IsNullOrWhiteSpace([string]$r.Host)) { $pending++ }
                            if (([string]$r.RebootPending) -match '^(?i:true|1|yes)$') { $reboot++ }
                        }
                        if ([string]::IsNullOrWhiteSpace($stamp)) { $stamp = ($sf.BaseName -replace '^wpt-bulkscan_', '') }
                        [void]$points.Add(@{ Stamp=$stamp; Total=$total; Online=$online; Pending=$pending; Reboot=$reboot })
                    }
                    if ($points.Count -gt 0) { $trendSec = @{ HasData=$true; Points=@($points) } }
                }
            }

            # ---- (e) Remediation routing split (mirrors remediation-route bucketing) ----
            $routeSec = @{ HasData=$false; Note='No ACAS findings loaded - run ACAS Parse File first.' }
            if ($script:AcasFindings.Count -gt 0) {
                $rbuckets = @{}; $totalOpen = 0
                foreach ($f in $script:AcasFindings) {
                    if ($f.Status -eq 'Patched') { continue }
                    $totalOpen++
                    # audit 2026-07-23: classifier extracted to Get-ReportsRouteBucket (was
                    # copy-pasted across five actions); the count-only Hosts set keys on the
                    # normalized audit key so short+FQDN of one host counts once, agreeing
                    # with the KEV section above and the sibling rollups.
                    $bucket = Get-ReportsRouteBucket $f
                    if (-not $rbuckets.ContainsKey($bucket)) { $rbuckets[$bucket] = @{ Bucket=$bucket; FindingCount=0; Hosts=(New-Object 'System.Collections.Generic.HashSet[string]'([System.StringComparer]::OrdinalIgnoreCase)) } }
                    $b = $rbuckets[$bucket]; $b.FindingCount++
                    $bhk = Get-ReportsAuditHostKey ([string]$f.Hostname)
                    if (-not [string]::IsNullOrWhiteSpace($bhk)) { [void]$b.Hosts.Add($bhk) }
                }
                $agg = New-Object System.Collections.ArrayList
                foreach ($key in $rbuckets.Keys) {
                    $rt = if ($script:RemediationRouteMap.ContainsKey($key)) { $script:RemediationRouteMap[$key] } else { $null }
                    [void]$agg.Add(@{ B=$rbuckets[$key]; Route=$rt })
                }
                $rsorted = @($agg | Sort-Object -Property `
                    @{ Expression = { if ($_.Route) { 0 } else { 1 } } }, `
                    @{ Expression = { -$_.B.FindingCount } }, `
                    @{ Expression = { $_.B.Bucket } })
                $rrows = New-Object System.Collections.ArrayList; $routableF = 0; $routableB = 0; $exceptionF = 0
                foreach ($item in $rsorted) {
                    $b = $item.B; $rt = $item.Route
                    $rtAct = Test-JanetWebRouteActionable $rt
                    if ($rtAct) { $routableF += $b.FindingCount; $routableB++ }
                    elseif ($rt -and $rt.IsException) { $exceptionF += $b.FindingCount }
                    [void]$rrows.Add(@{ Bucket=$b.Bucket; Tool=$(if ($rtAct) { $rt.ToolId } else { '-' }); Action=$(if ($rt) { $rt.Action } else { 'Manual review' })
                                       FindingCount=$b.FindingCount; HostCount=$b.Hosts.Count; Routable=[bool]$rtAct })
                }
                $routablePct = if ($totalOpen -gt 0) { [math]::Round(($routableF / $totalOpen) * 100, 1) } else { 0 }
                $routeSec = @{ HasData=$true; OpenFindings=$totalOpen; RoutableFindings=$routableF; ManualFindings=($totalOpen - $routableF - $exceptionF)
                               ExceptionFindings=$exceptionF; RoutablePct=$routablePct; RoutableBuckets=$routableB; Rows=@($rrows) }
            }

            # ---- (f) Scan closure (only if a compare/closure ran this session) ----
            $closeSec = @{ HasData=$false; Note='No scan comparison this session - run Patch Cross-Ref (Scan Compare or Prove Closure) first.' }
            if ($null -ne $script:ComparisonResults) {
                $rem=0; $still=0; $new=0; $amb=0
                foreach ($r in $script:ComparisonResults) {
                    switch ([string]$r.Delta) {
                        'REMEDIATED' { $rem++ }
                        'STILL OPEN' { $still++ }
                        'NEW'        { $new++ }
                        'AMBIGUOUS'  { $amb++ }
                    }
                }
                # loop40 F4: AMBIGUOUS is surfaced as its own count so a brief can never read
                # "100% closed" while an unconfirmed (collided short-name) finding is hidden. The
                # closure-rate FORMULA is unchanged (remediated of remediated+still-open) - ambiguous
                # keys are neither confirmed-closed nor confirmed-open, so they stay out of the ratio
                # but are now reported alongside it.
                $closurePct = if (($rem + $still) -gt 0) { [math]::Round(($rem / ($rem + $still)) * 100, 1) } else { 0 }
                $closeSec = @{ HasData=$true; Remediated=$rem; StillOpen=$still; New=$new; Ambiguous=$amb; Total=($rem+$still+$new+$amb); ClosurePct=$closurePct }
            }

            $brief = @{ Generated=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Sla=$slaSec; Kev=$kevSec; Squadron=$sqSec; Trend=$trendSec; Route=$routeSec; Closure=$closeSec }
            $html = Render-CommandBriefHtml -Brief $brief
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount($html)
            $sectionsWithData = @(@($slaSec.HasData, $kevSec.HasData, $sqSec.HasData, $trendSec.HasData, $routeSec.HasData, $closeSec.HasData) | Where-Object { $_ }).Count

            $outPath = [string]$Params['OutputPath']
            $written = ''; $writeErr = $null
            if ($outPath) {
                # audit 2026-07-23: TCP-445 pre-gate (same idiom as weekly-render-html) so a
                # dead UNC share fails fast instead of hanging the serialized reports runspace.
                if (Test-JanetUncReachable -Path $outPath) {
                    try { [System.IO.File]::WriteAllText($outPath, $html, [System.Text.UTF8Encoding]::new($true)); $written = $outPath } catch { $writeErr = $_.Exception.Message; & $send @{ type='log'; level='err'; text="Write failed: $writeErr" } }
                } else {
                    $writeErr = 'output share unreachable (ping/TCP-445 failed)'
                    & $send @{ type='log'; level='err'; text="Output share unreachable (ping/TCP-445 failed): $outPath" }
                }
                if ($written) { & $send @{ type='audit'; action='TouchHost'; target=(Split-Path -Leaf $outPath); result='Success'; itemCount=$sectionsWithData; detail="Executive command brief written ($bytes bytes, $sectionsWithData/6 sections populated)" } }
                else { & $send @{ type='audit'; action='TouchHost'; target=$outPath; result='Failure'; itemCount=0; detail="Command brief write failed: $writeErr" } }
            }
            $row = @{ Report='Executive Command Brief'; Sections="$sectionsWithData/6"; Bytes=$bytes; Html=$html; Path=$written }
            & $send (@{ type='row' } + @{ Report=$row.Report; Sections=$row.Sections; Bytes=$row.Bytes })
            & $send @{ type='status'; text="Command brief rendered ($bytes bytes; $sectionsWithData/6 sections populated)." }
            return @{ rows=@($row); summary=@{ total=1; sections=$sectionsWithData; bytes=$bytes; html=$html } }
        }

        # -------------------------------------------------------------------
        'posture-digest' {
            # Self-contained nightly snapshot for the off-hours Scheduler
            # (reports/posture-digest): renders a self-contained HTML + a
            # tidy CSV to outDir (can be a UNC audit share) so a fresh posture
            # snapshot lands on disk every night with no email/infra needed.
            # REUSE, not reinvention: Build-CoraSummary gives the severity /
            # host / VPH headline (same function cora-build-summary and
            # cora-render-html call); sla-aging / kb-needed / thirdparty-catalog
            # / iavm-board are re-invoked as actions (their row/status/log
            # chatter is swallowed by a no-op Emit) so their rollups are never
            # re-derived here - only the KEV-by-host tally below is new, and
            # it is a ~10-line loop using the same openFilter semantics
            # command-brief's KEV section already uses.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first - nothing to snapshot.' }
                return @{ rows=@(); summary=@{ ok=$false } }
            }
            & $send @{ type='status'; text='Building posture digest (severity / SLA / KBs / third-party / IAVM rollups)...' }

            $outDir = ([string]$Params['outDir']).Trim()
            if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = Join-Path $PSScriptRoot '..\JanetLocal\digests' }
            $title = ([string]$Params['title']).Trim()
            if ([string]::IsNullOrWhiteSpace($title)) { $title = 'Posture Digest' }

            # audit 2026-07-23: TCP-445 pre-gate (same idiom as weekly-render-html) BEFORE
            # the Test-Path/mkdir below - outDir can be a UNC audit share, and a dead share
            # would otherwise hang the serialized reports runspace mid-snapshot.
            if (-not (Test-JanetUncReachable -Path $outDir)) {
                & $send @{ type='error'; text="Output share unreachable (ping/TCP-445 failed): $outDir" }
                return @{ rows=@(); summary=@{ ok=$false; error='output share unreachable (ping/TCP-445 failed)' } }
            }

            try {
                if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null }
            } catch {
                & $send @{ type='error'; text="Could not create/access output folder '$outDir': $($_.Exception.Message)" }
                return @{ rows=@(); summary=@{ ok=$false; error=$_.Exception.Message } }
            }

            $cora = Build-CoraSummary
            $noop = { param($e) }
            # audit 2026-07-23 deferred pass (E2): open the SLA read memo for the span of
            # the recursive sub-action calls, so the SLA baseline + ledger are read+parsed
            # from disk AT MOST ONCE per digest run no matter how many sub-actions consult
            # them (sla-aging is the reader today; any future sibling joins the same single
            # read). try/finally so the memo can never leak past this digest - outside it,
            # every Get-ReportsSlaBaseline/Get-ReportsSlaLedger call reads fresh as before.
            # NOTE (E2b, deliberate): the four sub-actions each keep their own pass over
            # $script:AcasFindings - their filters/aggregations differ (kb-needed and
            # thirdparty-catalog even re-run Get-ReportsKbsFromText over the same text,
            # from opposite sides of the KB/non-KB split), and no existing helper exposes
            # that intermediate to share without restructuring the recursive-action design,
            # so those per-action passes stay as-is.
            $script:SlaDigestMemo = @{}
            try {
                $slaResult  = Invoke-JanetToolAction -ActionId 'sla-aging'          -Params @{} -Credential $Credential -Emit $noop
                $kbResult   = Invoke-JanetToolAction -ActionId 'kb-needed'          -Params @{} -Credential $Credential -Emit $noop
                $tpResult   = Invoke-JanetToolAction -ActionId 'thirdparty-catalog' -Params @{} -Credential $Credential -Emit $noop
                $iavmResult = Invoke-JanetToolAction -ActionId 'iavm-board'         -Params @{} -Credential $Credential -Emit $noop
            } finally {
                $script:SlaDigestMemo = $null
            }

            # KEV posture, grouped per host (open + actionable, same filter as
            # command-brief's KEV section) for the "top exposure" list.
            $kevHostMap = @{}
            $kevTotal = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched' -or $f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH') { continue }
                if (-not [bool]$f.InKEV) { continue }
                $kevTotal++
                # loop13: key the host tally on the normalized audit key (IPv4-whole, else
                # short-name upper) so WEB01 and web01.dom fold to ONE host - agreeing with
                # CORA's UniqueHosts (Build-CoraSummary uses the same key). Keying on the raw
                # hostname double-counted a host that appeared as both short + FQDN, making
                # KevHostsCount contradict UniqueHosts within this same digest.
                $hn = Get-ReportsAuditHostKey ([string]$f.Hostname)
                if ([string]::IsNullOrWhiteSpace($hn)) { continue }
                if (-not $kevHostMap.ContainsKey($hn)) { $kevHostMap[$hn] = 0 }
                $kevHostMap[$hn] = [int]$kevHostMap[$hn] + 1
            }
            $topKevHosts = @($kevHostMap.Keys | Sort-Object -Property @{ Expression = { -$kevHostMap[$_] } }, @{ Expression = { $_ } } |
                Select-Object -First 10 | ForEach-Object { @{ Host = $_; KevFindings = $kevHostMap[$_] } })

            $digest = @{
                Title          = $title
                GeneratedLocal = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                TotalLoaded    = $script:AcasFindings.Count
                OpenFindings   = $cora.ConsideredFindings
                UniqueHosts    = $cora.UniqueHosts
                Vph            = $cora.Vph
                SevCount       = $cora.SevCount
                KevTotal       = $kevTotal
                KevHostsCount  = $kevHostMap.Count
                Sla            = $slaResult.summary
                TopKevHosts    = $topKevHosts
                TopProducts    = @($tpResult.rows | Select-Object -First 10)
                TopKb          = @($kbResult.rows | Select-Object -First 10)
                TopIavm        = @($iavmResult.rows | Select-Object -First 10)
            }

            $html = Render-PostureDigestHtml -Digest $digest
            $csv  = Build-PostureDigestCsv -Digest $digest

            $stamp    = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
            $htmlName = "PostureDigest_$stamp.html"
            $csvName  = "PostureDigest_$stamp.csv"
            $htmlPath = Join-Path $outDir $htmlName
            $csvPath  = Join-Path $outDir $csvName

            $rows = New-Object System.Collections.ArrayList
            $ok = $true; $writeErr = $null
            try {
                [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($true))
                $htmlBytes = [System.Text.Encoding]::UTF8.GetByteCount($html)
                [void]$rows.Add(@{ Name=$htmlName; Path=$htmlPath; Kind='HTML'; Bytes=$htmlBytes })
                & $send (@{ type='row' } + @{ Name=$htmlName; Path=$htmlPath; Kind='HTML'; Bytes=$htmlBytes })
            } catch {
                $ok = $false; $writeErr = $_.Exception.Message
                & $send @{ type='error'; text="Failed to write HTML digest: $writeErr" }
            }
            if ($ok) {
                try {
                    [System.IO.File]::WriteAllText($csvPath, $csv, [System.Text.UTF8Encoding]::new($true))
                    $csvBytes = [System.Text.Encoding]::UTF8.GetByteCount($csv)
                    [void]$rows.Add(@{ Name=$csvName; Path=$csvPath; Kind='CSV'; Bytes=$csvBytes })
                    & $send (@{ type='row' } + @{ Name=$csvName; Path=$csvPath; Kind='CSV'; Bytes=$csvBytes })
                } catch {
                    $ok = $false; $writeErr = $_.Exception.Message
                    & $send @{ type='error'; text="Failed to write CSV digest: $writeErr" }
                }
            }

            if ($ok) {
                & $send @{ type='audit'; action='TouchHost'; target=$outDir; result='Success'; itemCount=2; detail="Posture digest written: $htmlName + $csvName ($($digest.OpenFindings) open findings, $($digest.UniqueHosts) hosts, $kevTotal KEV)" }
                & $send @{ type='status'; text="Posture digest written: $htmlPath" }
            } else {
                & $send @{ type='audit'; action='TouchHost'; target=$outDir; result='Failure'; itemCount=0; detail="Posture digest write failed: $writeErr" }
            }

            return @{ rows=@($rows); summary=@{
                ok = $ok
                htmlPath = $(if ($ok) { $htmlPath } else { '' }); csvPath = $(if ($ok) { $csvPath } else { '' })
                totalFindings = $digest.OpenFindings; loadedFindings = $digest.TotalLoaded; hosts = $digest.UniqueHosts
                kev = $kevTotal
                overdue = $(if ($slaResult.summary.overdue) { $slaResult.summary.overdue } else { 0 })
                dueSoon = $(if ($slaResult.summary.dueSoon) { $slaResult.summary.dueSoon } else { 0 })
                generatedUtc = $digest.GeneratedUtc
                error = $writeErr
            } }
        }

        # -------------------------------------------------------------------
        'burndown-snapshot' {
            # Append one point to the persisted vuln-backlog trend. REUSE, not
            # reinvention: Build-CoraSummary gives the same severity/host tallies
            # posture-digest uses; the only new work here is the KEV tally (same
            # open-filter semantics as command-brief/posture-digest's KEV section)
            # and the append itself. Read-only against hosts.
            if ($script:AcasFindings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No ACAS findings loaded. Parse or load a report first - nothing to snapshot.' }
                return @{ rows=@(); summary=@{ ok=$false } }
            }
            & $send @{ type='status'; text='Snapshotting current vuln posture for the burndown trend...' }

            $cora = Build-CoraSummary
            $kevCount = 0
            foreach ($f in $script:AcasFindings) {
                if ($f.Status -eq 'Patched' -or $f.Status -eq 'NOT OUR PATCH' -or $f.Category -eq 'NOT OUR PATCH') { continue }
                if ([bool]$f.InKEV) { $kevCount++ }
            }
            $label = ([string]$Params['label']).Trim()
            $record = [ordered]@{
                tsUtc     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                totalOpen = [int]$cora.ConsideredFindings
                critical  = [int]$cora.SevCount['Critical']
                high      = [int]$cora.SevCount['High']
                medium    = [int]$cora.SevCount['Medium']
                low       = [int]$cora.SevCount['Low']
                kev       = $kevCount
                hosts     = [int]$cora.UniqueHosts
            }
            if (-not [string]::IsNullOrWhiteSpace($label)) { $record['label'] = $label }

            $save = Add-ReportsTrendRecord -Record $record
            if (-not $save.Written) {
                & $send @{ type='error'; text="Burndown snapshot NOT saved: $($save.Error)" }
                return @{ rows=@(); summary=@{ ok=$false; error=$save.Error } }
            }
            $count = @(Get-ReportsTrendRecords).Count

            $rows = New-Object System.Collections.ArrayList
            foreach ($kv in @(
                @{ Field='Timestamp (UTC)'; Value=[string]$record.tsUtc },
                @{ Field='Total open'; Value=[string]$record.totalOpen },
                @{ Field='Severity (C/H/M/L)'; Value="$($record.critical)/$($record.high)/$($record.medium)/$($record.low)" },
                @{ Field='KEV'; Value=[string]$record.kev },
                @{ Field='Hosts'; Value=[string]$record.hosts },
                @{ Field='Snapshots on file'; Value=[string]$count }
            )) { [void]$rows.Add($kv); & $send (@{ type='row' } + $kv) }

            & $send @{ type='audit'; action='TouchHost'; target='Burndown snapshot'; result='Success'; itemCount=1; detail="open=$($record.totalOpen) kev=$($record.kev) hosts=$($record.hosts); $count snapshot(s) on file" }
            & $send @{ type='status'; text="Burndown snapshot recorded: $($record.totalOpen) open, $($record.kev) KEV, $($record.hosts) hosts. $count snapshot(s) on file." }
            return @{ rows=@($rows); summary=@{ ok=$true; record=$record; count=$count } }
        }

        # -------------------------------------------------------------------
        'burndown' {
            # Read the persisted trend series + compute the trajectory. Read-only.
            $records = @(Get-ReportsTrendRecords)
            if ($records.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No burndown snapshots yet. Use Snapshot Now (or arm reports/burndown-snapshot on the Scheduler) to start the trend.' }
                return @{ rows=@(); summary=@{ points=0; firstOpen=0; lastOpen=0; deltaOpen=0; pctClosed=0; firstKev=0; lastKev=0; kevClosed=0; series=@(); note='No snapshots recorded yet.' } }
            }
            & $send @{ type='status'; text="Building burndown trend over $($records.Count) snapshot(s)..." }

            $rows = New-Object System.Collections.ArrayList
            $series = New-Object System.Collections.ArrayList
            foreach ($r in $records) {
                $dateStr = [string]$r.tsUtc
                try { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$r.tsUtc, [ref]$d)) { $dateStr = $d.ToLocalTime().ToString('yyyy-MM-dd HH:mm') } } catch {}
                $row = @{
                    _rk       = [string]$r.tsUtc
                    Date      = $dateStr
                    TotalOpen = [int]$r.totalOpen
                    Critical  = [int]$r.critical
                    High      = [int]$r.high
                    KEV       = [int]$r.kev
                    Hosts     = [int]$r.hosts
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                [void]$series.Add(@{ ts=[string]$r.tsUtc; totalOpen=[int]$r.totalOpen; kev=[int]$r.kev })
            }

            $first = $records[0]; $last = $records[$records.Count - 1]
            $firstOpen = [int]$first.totalOpen; $lastOpen = [int]$last.totalOpen
            $deltaOpen = $lastOpen - $firstOpen
            $pctClosed = if ($firstOpen -gt 0) { [math]::Round((($firstOpen - $lastOpen) / $firstOpen) * 100, 1) } else { 0 }
            $firstKev = [int]$first.kev; $lastKev = [int]$last.kev
            $kevClosed = $firstKev - $lastKev

            $summary = @{
                points     = $records.Count
                firstOpen  = $firstOpen; lastOpen = $lastOpen; deltaOpen = $deltaOpen
                pctClosed  = $pctClosed
                firstKev   = $firstKev; lastKev = $lastKev; kevClosed = $kevClosed
                series     = $series.ToArray()
            }
            & $send @{ type='status'; text="Burndown: $($summary.points) snapshot(s), open $firstOpen -> $lastOpen (delta $deltaOpen, $pctClosed% closed)." }
            return @{ rows=@($rows); summary=$summary }
        }

        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
