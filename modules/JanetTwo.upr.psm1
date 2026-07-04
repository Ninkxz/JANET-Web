# =============================================================================
#  JanetTwo.upr.psm1  -  Unsupported Product Remediator engine for J.A.N.E.T. TWO
#  (Re-forked for JANET TWO from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\UnsupportedProductRemediator_1.1.0.ps1 (WinForms layer
#  dropped). Consumes a Tenable / ACAS "Unsupported / SEoL Product Summary"
#  report (PDF or CSV) and, host-by-host, scans the live registry for the
#  installs the report flagged and (optionally) removes the proven-EOL ones.
#
#  Self-contained: the catalog, parsers, proven-only gate, registry-scan
#  worker, and per-product uninstall handlers are all embedded here. The
#  RunspacePool harvest harness (Invoke-UprFanOut) is re-implemented locally --
#  modules load in isolation so WPT helpers are NOT callable.
#
#  Contract (identical to JanetTwo.wpt.psm1 / JanetTwo.message.psm1):
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
#
#  PROVEN-ONLY GATING (desktop v1.1.0): a scanned install is one-click
#  uninstallable only when the catalog PROVES it EOL -- Proven=true (the regex
#  pins an EOL-by-definition product) OR the installed version parses below
#  VersionMaxExclusive. Otherwise the row is surfaced as 'Review' and never
#  auto-removed. Tanium is always skipped.
# =============================================================================

# -----------------------------------------------------------------------------
#  Manifest
# -----------------------------------------------------------------------------
function Get-JanetToolManifest {
    @{
        id       = 'upr'
        name     = 'Unsupported Product Remediator'
        category = 'Remediation'
        version  = '1.2.1'
        summary  = 'Two ways to remediate, both host-by-host over WinRM: (1) consume a Tenable / ACAS Unsupported & SEoL report (PDF or CSV) and bulk-uninstall the proven-EOL findings; (2) Targeted Removal -- paste a machine list + a software list, scan, and uninstall the checked matches. Handlers: M365 SaRA, Adobe Acrobat w/ RunAsPPL guard, generic MSI/EXE/Store. Security agents (Tanium, Trellix, Defender, CrowdStrike, ...) are always skipped.'
        actions  = @(
            @{
                id='report-findings'; label='Report Findings'; kind='table'; destructive=$false
                description='Parse the Tenable/ACAS report ONLY (no host scanning) and list each unsupported/SEoL finding with its catalog decision: uninstall candidates, OS findings (out of scope), review-only matches, or no catalog match. Update-class findings (e.g. M365 channel mismatch) are hidden -- remediate those with the WPT App Updater.'
                columns=@('Plugin','Category','PluginName','Severity','Hosts','Decision')
                inputs=@(
                    @{ name='report'; label='Tenable report (CSV or PDF)'; type='file'; filter='Tenable report (*.csv;*.pdf)|*.csv;*.pdf|All files (*.*)|*.*'; required=$true },
                    @{ name='hostclass'; label='Host class'; type='select'; required=$false; default='All'; options=@('All','Workstations (MSEKL/MSEKW)','Non-Workstations (servers / other)') },
                    @{ name='search'; label='Search (Plugin / Plugin Name / Category)'; type='string'; required=$false }
                )
            },
            @{
                id='report-scan'; label='Scan Hosts'; kind='stream-table'; destructive=$false
                description='Parse the report, collect the unique set of hosts across all ACTIONABLE findings (non-OS, non-update-class), then open ONE session per host, enumerate installed software once, and match every applicable catalog profile. Reports each matched install with its remediation decision (Uninstall / Review / Skipped (Tanium)). NOTHING is uninstalled.'
                columns=@('Host','Plugin','Product','Version','Decision','Detail')
                inputs=@(
                    @{ name='report'; label='Tenable report (CSV or PDF)'; type='file'; filter='Tenable report (*.csv;*.pdf)|*.csv;*.pdf|All files (*.*)|*.*'; required=$true },
                    @{ name='hostclass'; label='Host class'; type='select'; required=$false; default='All'; options=@('All','Workstations (MSEKL/MSEKW)','Non-Workstations (servers / other)') },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='report-uninstall'; label='Uninstall Matched'; kind='stream-table'; destructive=$true
                confirm='Uninstall the PROVEN-EOL products flagged by this report from the affected hosts? With "Dry run" UNCHECKED this permanently removes software. Review/Tanium matches are never removed. Proceed?'
                description='Same host-centric scan as Scan Hosts, but for each candidate whose decision is Uninstall (proven EOL) and is NOT Tanium, run the per-product uninstall handler (M365 SaRA, Adobe Acrobat w/ RunAsPPL guard, generic MSI/EXE/Store). Review and Tanium matches are reported but never removed. Dry run plans only.'
                columns=@('Host','Plugin','Product','Version','Decision','Result')
                inputs=@(
                    @{ name='report'; label='Tenable report (CSV or PDF)'; type='file'; filter='Tenable report (*.csv;*.pdf)|*.csv;*.pdf|All files (*.*)|*.*'; required=$true },
                    @{ name='hostclass'; label='Host class'; type='select'; required=$false; default='All'; options=@('All','Workstations (MSEKL/MSEKW)','Non-Workstations (servers / other)') },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 },
                    @{ name='dryrun'; label='Dry run (enumerate, do not uninstall)'; type='bool'; required=$false; default=$true }
                )
            },
            @{
                id='os-findings'; label='OS Findings'; kind='table'; destructive=$false
                description='Parse the report ONLY (no scanning) and list every OS-level unsupported finding (unsupported Windows / Server, VMware ESXi, EOL Unix / macOS / RHEL / SUSE) broken out ONE ROW PER AFFECTED HOST with its network identifiers (IP / NetBIOS / DNS / OS CPE / MAC). OS findings are out of scope for uninstall -- hand the exported list to whoever runs OS rebuilds.'
                columns=@('Plugin','PluginName','Severity','IP','NetBIOS','DNS','OS CPE','MAC')
                inputs=@(
                    @{ name='report'; label='Tenable report (CSV or PDF)'; type='file'; filter='Tenable report (*.csv;*.pdf)|*.csv;*.pdf|All files (*.*)|*.*'; required=$true },
                    @{ name='hostclass'; label='Host class'; type='select'; required=$false; default='All'; options=@('All','Workstations (MSEKL/MSEKW)','Non-Workstations (servers / other)') }
                )
            }
            @{
                id='manual-scan'; label='Targeted Scan'; kind='stream-table'; destructive=$false
                description='Operator-driven (no report): paste a host list and a software list. Open ONE session per host, enumerate installed software once, and report every install whose DisplayName matches a pasted name (case-insensitive contains; * wildcard). NOTHING is uninstalled. Security agents (Tanium, Trellix, Defender, CrowdStrike, ...) always surface as protected and are never removable.'
                columns=@('Host','Product','Publisher','Type','Version','Decision','Detail')
                inputs=@(
                    @{ name='hosts'; label='Machines (one per line)'; type='text'; required=$true },
                    @{ name='software'; label='Software to find (one per line; * wildcard)'; type='text'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id='manual-uninstall'; label='Targeted Uninstall'; kind='stream-table'; destructive=$true
                confirm='Uninstall the SELECTED software from the listed hosts? With "Dry run" UNCHECKED this permanently removes software. Security agents are never removed. Proceed?'
                description='Same operator-driven scan, then uninstall ONLY the rows you checked (host+product). Dry run plans only. Security agents (Tanium, Trellix, Defender, CrowdStrike, ...) are always skipped.'
                columns=@('Host','Product','Publisher','Type','Version','Decision','Result')
                inputs=@(
                    @{ name='hosts'; label='Machines (one per line)'; type='text'; required=$true },
                    @{ name='software'; label='Software to find (one per line; * wildcard)'; type='text'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 },
                    @{ name='dryrun'; label='Dry run (enumerate, do not uninstall)'; type='bool'; required=$false; default=$true }
                )
            }
            @{
                id='reload-catalog'; label='Reload Catalog'; kind='table'; destructive=$false
                description='Reload the unsupported/SEoL product catalog. An operator-edited JanetLocal\UnsupportedProductCatalog.json (next to the tool) overrides the embedded default; this reports which source loaded and its profile/OS-pattern counts. The catalog is also re-read automatically on every scan.'
                columns=@('Source','Profiles','OS Plugin Patterns')
                inputs=@()
            }
        )
    }
}

# -----------------------------------------------------------------------------
#  Catalog (embedded from X:\J.A.N.E.T\JanetLocal\UnsupportedProductCatalog.json)
#  PRESERVE PROFILE ORDER: the perpetual-Office uninstall profile MUST precede
#  the M365-channel update profile (a PDF count-table row-merge can glue both
#  Office plugin names into one finding, and Get-CatalogProfileForFinding returns
#  the FIRST match; matching the uninstall profile first keeps the perpetual-
#  Office uninstall visible instead of being hidden as update-class).
# -----------------------------------------------------------------------------
function Get-UprCatalogPath { Join-Path $PSScriptRoot '..\JanetLocal\UnsupportedProductCatalog.json' }

function Get-UprCatalogFromFile {
    # Operator-editable override: <JANET TWO root>\JanetLocal\UnsupportedProductCatalog.json
    # (mirrors the desktop tool's editable catalog). Returns $null on any problem so
    # the caller falls back to the embedded default - a bad/partial JSON never breaks a scan.
    try {
        $p = Get-UprCatalogPath
        if (-not (Test-Path -LiteralPath $p)) { return $null }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj -or -not $obj.Profiles -or @($obj.Profiles).Count -eq 0) { return $null }
        if (-not ($obj.PSObject.Properties.Name -contains 'OperatingSystemPluginNames')) {
            $obj | Add-Member -NotePropertyName OperatingSystemPluginNames -NotePropertyValue @() -Force
        }
        return $obj
    } catch { return $null }
}

function Get-UprCatalog {
    # Read fresh each call: an operator-edited JanetLocal JSON wins, else the embedded
    # default. Reading per-call means editing the JSON + re-scanning (or Reload Catalog)
    # picks up the change - parity with the desktop editable-catalog + Reload button.
    $ext = Get-UprCatalogFromFile
    if ($ext) { return $ext }
    return (Get-UprCatalogDefault)
}

function Get-UprCatalogDefault {
    [PSCustomObject]@{
        Profiles = @(
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Microsoft XML Parser \(MSXML\)';                       DisplayNameRegex='^Microsoft (XML Parser|Core Services|XML 4)';  VersionMaxExclusive='5.0';  Updater=$null;             Proven=$false; Category='UnsupportedSoftware'; Notes='MSXML 3/4 EOL - proven by version gate (< 5.0; MSXML 6 is left alone). Uninstall, no successor on the AFNET image.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Microsoft Office Unsupported Version Detection';        DisplayNameRegex='^Microsoft Office (2003|2007|2010|2013|2016)'; VersionMaxExclusive=$null;  Updater=$null;             Proven=$true;  Category='UnsupportedSoftware'; Notes='Pre-M365 perpetual Office - proven EOL (the regex pins the EOL year). Uninstall, then deploy M365 separately. ORDER NOTE: must precede the Channel profile below.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Microsoft Office Unsupported Channel Version Detection';DisplayNameRegex='^Microsoft 365 Apps';                          VersionMaxExclusive=$null;  Updater='M365_ForceUpdate'; Proven=$false; Category='UnsupportedSoftware'; Notes='Channel mismatch - update-class (M365 force-update). Hidden from the uninstall-only tool; remediate with the WPT App Updater.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Microsoft SQL Server Unsupported Version Detection';    DisplayNameRegex='^Microsoft SQL Server (2005|2008|2012|2014)';   VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='UnsupportedSoftware'; Notes='DBA approval required before uninstall - surfaced as Review (not one-click).' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Mozilla Foundation Unsupported Application Detection';  DisplayNameRegex='^Mozilla (Firefox|Thunderbird|SeaMonkey)';      VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='UnsupportedSoftware'; Notes='Mozilla app - name-only match also hits supported in-market builds; surfaced as Review pending version/ACAS confirmation.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Oracle Database Unsupported Version Detection';         DisplayNameRegex='^Oracle Database';                              VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='UnsupportedSoftware'; Notes='DBA approval required before uninstall - surfaced as Review (not one-click).' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Microsoft \.NET Core SEoL';                             DisplayNameRegex='^Microsoft \.NET (Core|Runtime)';               VersionMaxExclusive='8.0';  Updater=$null;             Proven=$false; Category='SEoLSoftware';        Notes='SEoL .NET Core / runtime - proven by version gate (< 8.0). Supported .NET 8/9 are never auto-removed; redeploy supported .NET out-of-band.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='\.NET Core SDK SEoL';                                   DisplayNameRegex='^Microsoft \.NET (Core SDK|SDK)';               VersionMaxExclusive='8.0';  Updater=$null;             Proven=$false; Category='SEoLSoftware';        Notes='SEoL .NET Core SDK - proven by version gate (< 8.0). Supported 8.x/9.x SDKs are left alone.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='ASP\.NET Core SEoL';                                    DisplayNameRegex='^Microsoft ASP\.NET Core';                      VersionMaxExclusive='8.0';  Updater=$null;             Proven=$false; Category='SEoLSoftware';        Notes='SEoL ASP.NET Core - proven by version gate (< 8.0). Supported 8.x is left alone.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Mozilla Firefox SEoL';                                  DisplayNameRegex='^Mozilla Firefox';                              VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='SEoLSoftware';        Notes='SEoL Firefox - current Firefox also matches the name; surfaced as Review pending ACAS confirmation (AFNET image installs ESR separately).' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Apache Log4j SEoL';                                     DisplayNameRegex='log4j-1\.';                                     VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='SEoLSoftware';        Notes='Log4j 1.x - usually a JAR on disk, not an MSI. Registry uninstall path rarely applies; surfaced as Review for manual jar removal (Log4j Finder).' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Adobe (Flash|Shockwave) Player SEoL';                   DisplayNameRegex='^Adobe (Flash|Shockwave) Player';               VersionMaxExclusive=$null;  Updater=$null;             Proven=$true;  Category='SEoLSoftware';        Notes='Flash/Shockwave EOL by definition (no supported version) - proven, always uninstall.' }
            [PSCustomObject]@{ Plugin='*'; PluginNameMatch='Java SE (Unsupported|SEoL)';                            DisplayNameRegex='^(Java|Java SE|JRE|JDK) ';                      VersionMaxExclusive=$null;  Updater=$null;             Proven=$false; Category='UnsupportedSoftware'; Notes='Oracle JRE/JDK - name-only match also hits supported builds; surfaced as Review pending version/ACAS confirmation.' }
        )
        OperatingSystemPluginNames = @(
            'Unsupported Windows OS',
            'Microsoft Windows Server.*Unsupported',
            'Microsoft Windows.*Unsupported',
            'VMware ESX(\s|i)',
            'Unsupported Unix Operating System',
            'Apple macOS.*Unsupported',
            'Red Hat Enterprise Linux.*Unsupported',
            'SUSE Linux.*Unsupported'
        )
    }
}

# -----------------------------------------------------------------------------
#  Parsed-report cache (Wave-3 perf). The expensive step is pdftotext + the
#  regex table parse; cache the resulting finding set keyed by report identity
#  (file full path + LastWriteTimeUtc + size, OR an MD5 of pasted text) AND a
#  catalog signature -- so editing + reloading the catalog re-parses (catalog
#  reload semantics preserved). Bounded LRU so memory can't grow unbounded.
#  NOTE: 'upr' is non-stateful (fresh runspace + module re-import per action),
#  so this pays off only within a persistent runspace; it is always correct +
#  harmless otherwise, and the catalog is re-read per call regardless.
# -----------------------------------------------------------------------------
$script:UprFindingCache     = @{}
$script:UprFindingCacheKeys = New-Object System.Collections.ArrayList   # LRU order, oldest first
$script:UprFindingCacheMax  = 4

function Get-UprCatalogSignature {
    param($Catalog)
    if ($null -eq $Catalog) { return '0' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in @($Catalog.Profiles)) {
        [void]$sb.Append([string]$p.PluginNameMatch);     [void]$sb.Append('~')
        [void]$sb.Append([string]$p.DisplayNameRegex);    [void]$sb.Append('~')
        [void]$sb.Append([string]$p.VersionMaxExclusive); [void]$sb.Append('~')
        [void]$sb.Append([string]$p.Proven);              [void]$sb.Append('~')
        [void]$sb.Append([string]$p.Updater);             [void]$sb.Append('|')
    }
    foreach ($o in @($Catalog.OperatingSystemPluginNames)) { [void]$sb.Append([string]$o); [void]$sb.Append('|') }
    return ([string]($sb.ToString().GetHashCode()))
}

function Get-UprReportCacheKey {
    param([string]$ReportPath, [string]$ReportText, $Catalog)
    $sig = Get-UprCatalogSignature $Catalog
    if (-not [string]::IsNullOrWhiteSpace($ReportText)) {
        try {
            $sha   = [System.Security.Cryptography.SHA256]::Create()
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($ReportText)
            $hash  = [BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', ''
            $sha.Dispose()
            return "text:$hash|cat:$sig"
        } catch { return $null }
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        try {
            $fi = Get-Item -LiteralPath $ReportPath -ErrorAction Stop
            return "file:$($fi.FullName)|mt:$($fi.LastWriteTimeUtc.Ticks)|sz:$($fi.Length)|cat:$sig"
        } catch { return $null }
    }
    return $null
}

function Get-UprCachedFindings {
    param([string]$Key)
    if ($Key -and $script:UprFindingCache.ContainsKey($Key)) { return $script:UprFindingCache[$Key] }
    return $null
}

function Set-UprCachedFindings {
    param([string]$Key, $Findings)
    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    if (-not $script:UprFindingCache.ContainsKey($Key)) { [void]$script:UprFindingCacheKeys.Add($Key) }
    $script:UprFindingCache[$Key] = $Findings
    while ($script:UprFindingCacheKeys.Count -gt $script:UprFindingCacheMax) {
        $evict = [string]$script:UprFindingCacheKeys[0]
        $script:UprFindingCacheKeys.RemoveAt(0)
        if ($script:UprFindingCache.ContainsKey($evict)) { [void]$script:UprFindingCache.Remove($evict) }
    }
}

# -----------------------------------------------------------------------------
#  pdftotext.exe resolution -- portable candidate-list walk, then PATH.
#  Lifted from the desktop tool. $null when nothing resolves.
# -----------------------------------------------------------------------------
function Get-UprPdfTextExe {
    foreach ($candidate in @(
        'C:\Program Files\Git\mingw64\bin\pdftotext.exe',
        'C:\Program Files (x86)\Git\mingw64\bin\pdftotext.exe',
        "$env:LOCALAPPDATA\Programs\Git\mingw64\bin\pdftotext.exe",
        'C:\Tools\pdftotext.exe'
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue)) {
            return $candidate
        }
    }
    $cmd = Get-Command pdftotext.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# -----------------------------------------------------------------------------
#  Helpers
# -----------------------------------------------------------------------------

function Get-UprUsefulText {
    # Trim report text at the first trailing non-actionable section anchor so
    # both structured and relaxed parsers stop before the "Top 20 Exploitable"
    # tables. Extracted from the duplicate open-coded block in both parsers.
    param([string]$Raw)
    $stopAnchors = @(
        'Top 20 Exploitable Vulnerabilities',
        'Top 20 Exploitable Hosts',
        'Exploitable Framework Breakdown',
        'Exploits by Platform'
    )
    $stopIdx = $Raw.Length
    foreach ($s in $stopAnchors) {
        $i = $Raw.IndexOf($s)
        if ($i -ge 0 -and $i -lt $stopIdx) { $stopIdx = $i }
    }
    return $Raw.Substring(0, $stopIdx)
}

function Get-UprSections {
    # The three report sections both parsers iterate over. Extracted from the
    # duplicate literal array in Parse-ReportText and Parse-ReportTextRelaxed.
    @(
        @{ Name='OS';                   CountAnchor='Unsupported / Security End of Life (SEoL) Operating Systems Count'; HostsAnchor='Unsupported / Security End of Life (SEoL) Operating Systems Affected Hosts'; Category='OS' }
        @{ Name='UnsupportedSoftware';  CountAnchor='Unsupported Software Count';                                       HostsAnchor='Unsupported Software Affected Hosts';                                      Category='UnsupportedSoftware' }
        @{ Name='SEoLSoftware';         CountAnchor='Security End of Life (SEoL) Software Count';                       HostsAnchor='Security End of Life (SEoL) Software Affected Hosts';                      Category='SEoLSoftware' }
    )
}

function Get-UprThreadCount {
    param([hashtable]$Params, [int]$Default)
    $threads = $Default
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    return [Math]::Max(1, [Math]::Min(64, $threads))
}

# Host-class. Workstations on this network use the MSEKL (laptop) or MSEKW
# (desktop) NetBIOS prefix; everything else (servers, generic VMs, ...) is Other.
function Get-UprHostClass {
    param($HostObj)
    if ($null -eq $HostObj) { return 'Other' }
    foreach ($name in @($HostObj.NetBIOSName, $HostObj.DNSName)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $bare = ($name -split '\.')[0]
        if ($bare -match '^(?i:MSEK[LW])') { return 'Workstation' }
    }
    return 'Other'
}

# Does the host-class filter admit this host object?
function Test-UprHostClassMatch {
    param($HostObj, [string]$HostClass)
    switch ($HostClass) {
        'Workstations (MSEKL/MSEKW)'         { return ((Get-UprHostClass $HostObj) -eq 'Workstation') }
        'Non-Workstations (servers / other)' { return ((Get-UprHostClass $HostObj) -eq 'Other') }
        default                              { return $true }
    }
}

# A connect-target token is usable only if it's an IPv4 literal or a hostname/FQDN
# whose FIRST label is a plausible machine name -- NOT a bare domain fragment. The
# Tenable PDF's jagged affected-host table wraps "DOMAIN\HOST" and FQDNs across lines,
# so it can yield domain-only strings (e.g. "S.USAF.MIL", "AREA52.AFNOAPPS.USAF.MIL")
# that are NOT hosts. Reject those so the scan never wastes a WinRM attempt on a domain.
function Test-UprValidTarget {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $t = $Target.Trim()
    if ($t -match '[\\/\s]') { return $false }                  # backslash/slash/space = not a clean host token
    if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { return $true }   # IPv4 literal
    $first = ($t -split '\.')[0]
    if ($first.Length -lt 2) { return $false }                  # single-letter fragment ("S")
    if ($first -match '(^-|-$)') { return $false }              # truncated NetBIOS wrap ("MSEKL-") - a label can't start/end with a hyphen
    if ($first -match '^(?i:USAF|MIL|COM|NET|ORG|GOV|EDU|AF|ELX|AFNOAPP|AFNOAPPS|AREA\d+|LAKENHEATH|UNKNOWN)$') { return $false }  # bare domain/org token
    return $true
}

# The connect-target for a host: first VALID of DNS > NetBIOS > IP. Validation-gated
# so a garbage DNS fragment from the jagged PDF falls through to a clean NetBIOS short
# name (e.g. MSEKL-XXXXX) or the IP. Returns $null when nothing usable -> host skipped.
function Get-UprConnectTarget {
    param($HostObj)
    if ($null -eq $HostObj) { return $null }
    foreach ($cand in @($HostObj.DNSName, $HostObj.NetBIOSName, $HostObj.IPAddress)) {
        if ([string]::IsNullOrWhiteSpace($cand)) { continue }
        $t = ([string]$cand).Trim()
        if (Test-UprValidTarget $t) { return $t }
    }
    return $null
}

# -----------------------------------------------------------------------------
#  Catalog matching + proven-only gate (lifted from the desktop tool)
# -----------------------------------------------------------------------------
function Get-UprProfileForFinding {
    param($Catalog, $Finding)
    if ($null -eq $Catalog -or $null -eq $Catalog.Profiles) { return $null }
    foreach ($p in $Catalog.Profiles) {
        $pluginOk = ($p.Plugin -eq '*' -or $p.Plugin -eq $Finding.Plugin)
        if (-not $pluginOk) { continue }
        try {
            if ($Finding.PluginName -match $p.PluginNameMatch) { return $p }
        } catch { continue }
    }
    return $null
}

function Test-IsOsFinding {
    param($Catalog, $PluginName)
    if ($null -eq $Catalog -or $null -eq $Catalog.OperatingSystemPluginNames) { return $false }
    foreach ($pat in $Catalog.OperatingSystemPluginNames) {
        try { if ($PluginName -match $pat) { return $true } } catch {}
    }
    return $false
}

# -----------------------------------------------------------------------------
#  Input parsers (lifted from the desktop tool; Log -> $Log closure that emits
#  a {type='log'} event via $send). Both accept $Catalog so Test-IsOsFinding /
#  the no-keyword catalog fallback can run without module globals.
# -----------------------------------------------------------------------------
function Import-UprFinding {
    param([string]$Path, $Catalog, [scriptblock]$Log)
    if (-not (Test-Path -LiteralPath $Path)) {
        & $Log "Input file does not exist: $Path" 'err'
        return @()
    }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        '.csv' { return @(Parse-CsvFinding -Path $Path -Catalog $Catalog -Log $Log) }
        '.pdf' { return @(Parse-PdfFinding -Path $Path -Catalog $Catalog -Log $Log) }
        default {
            & $Log "Unsupported input extension: $ext (use .csv or .pdf)" 'err'
            return @()
        }
    }
}

function Parse-CsvFinding {
    param([string]$Path, $Catalog, [scriptblock]$Log)
    $rows = $null
    try { $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop } catch {
        & $Log "CSV import failed: $($_.Exception.Message)" 'err'
        return @()
    }
    if ($null -eq $rows -or $rows.Count -eq 0) { return @() }

    $cols = @($rows[0].PSObject.Properties.Name)
    $havePluginOutput = ($cols -contains 'Plugin Output')

    $findings = @{}
    foreach ($row in $rows) {
        $pluginName = [string]$row.'Plugin Name'
        if ([string]::IsNullOrWhiteSpace($pluginName)) { continue }

        ## Filter to unsupported / SEoL detection plugins:
        $isUnsupported = ($pluginName -match '(?i)unsupported|SEoL|End[\- ]of[\- ]Life|EOL|out of support')
        if (-not $isUnsupported) {
            ## Also keep anything with a catalog match (some plugin names don't include the keyword)
            $tryMatch = $false
            foreach ($p in $Catalog.Profiles) {
                if ($pluginName -match $p.PluginNameMatch) { $tryMatch = $true; break }
            }
            if (-not $tryMatch) { continue }
        }

        $key = "$($row.Plugin)|$pluginName"
        if (-not $findings.ContainsKey($key)) {
            $cat = if (Test-IsOsFinding $Catalog $pluginName) { 'OS' } elseif ($pluginName -match '(?i)SEoL|End[\- ]of[\- ]Life|EOL') { 'SEoLSoftware' } else { 'UnsupportedSoftware' }
            $findings[$key] = [PSCustomObject]@{
                Plugin     = [string]$row.Plugin
                PluginName = $pluginName
                Category   = $cat
                Severity   = [string]$row.Severity
                Hosts      = New-Object System.Collections.ArrayList
            }
        }
        $f = $findings[$key]

        $matched = $null
        $matchedVer = $null
        $matchedPath = $null
        if ($havePluginOutput -and $row.'Plugin Output') {
            $po = [string]$row.'Plugin Output'
            $mPath  = [regex]::Match($po, '(?im)^\s*(?:Path|Installed location|Install Path)\s*:\s*(.+?)\s*$')
            $mVer   = [regex]::Match($po, '(?im)^\s*(?:Installed version|Version)\s*:\s*(.+?)\s*$')
            $mProd  = [regex]::Match($po, '(?im)^\s*(?:Product|Display Name|Name)\s*:\s*(.+?)\s*$')
            if ($mPath.Success)  { $matchedPath = $mPath.Groups[1].Value.Trim() }
            if ($mVer.Success)   { $matchedVer  = $mVer.Groups[1].Value.Trim() }
            if ($mProd.Success)  { $matched     = $mProd.Groups[1].Value.Trim() }
        }

        $h = [PSCustomObject]@{
            IPAddress          = [string]$row.'IP Address'
            NetBIOSName        = [string]$row.'NetBIOS Name'
            DNSName            = [string]$row.'DNS Name'
            OSCpe              = if ($cols -contains 'OS CPE') { [string]$row.'OS CPE' } else { '' }
            MAC                = if ($cols -contains 'MAC Address') { [string]$row.'MAC Address' } else { '' }
            MatchedDisplayName = $matched
            MatchedVersion     = $matchedVer
            MatchedPath        = $matchedPath
            CVE                = if ($cols -contains 'CVE') { [string]$row.CVE } else { '' }
        }
        [void]$f.Hosts.Add($h)
    }

    $findings.Values
}

function Parse-PdfFinding {
    param([string]$Path, $Catalog, [scriptblock]$Log)
    $pdfExe = Get-UprPdfTextExe
    if (-not $pdfExe -or -not (Test-Path -LiteralPath $pdfExe -ErrorAction SilentlyContinue)) {
        & $Log "pdftotext.exe not resolved. Install Git for Windows (any standard location), add pdftotext.exe to PATH, or drop it at C:\Tools\pdftotext.exe." 'err'
        return @()
    }
    $tmpTxt = [IO.Path]::Combine([IO.Path]::GetTempPath(), "upr_pdf_$([guid]::NewGuid().ToString('N')).txt")
    try {
        ## v1.1.0 fix: pass a single PRE-QUOTED argument string. PS 5.1
        ## Start-Process does NOT quote individual -ArgumentList array elements,
        ## so a report path containing spaces / parentheses got split into bad
        ## args and pdftotext returned exit 99 with no output. Quoting both paths
        ## in one string fixes it while keeping -NoNewWindow + the stderr capture.
        $argLine = '-layout "{0}" "{1}"' -f $Path, $tmpTxt
        $proc = Start-Process -FilePath $pdfExe -ArgumentList $argLine -Wait -PassThru -NoNewWindow -RedirectStandardError ($tmpTxt + '.err')
        if ($proc.ExitCode -ne 0) {
            & $Log "pdftotext returned exit $($proc.ExitCode)" 'err'
            return @()
        }
    } catch {
        & $Log "pdftotext invocation failed: $($_.Exception.Message)" 'err'
        return @()
    }
    if (-not (Test-Path -LiteralPath $tmpTxt)) { return @() }

    $allText = Get-Content -LiteralPath $tmpTxt -Raw
    try { Remove-Item -LiteralPath $tmpTxt -Force -EA SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath ($tmpTxt + '.err') -Force -EA SilentlyContinue } catch {}

    ## pdftotext -layout output and a PDF-viewer copy-paste are both jagged
    ## reading-order text with the same section anchors -- share one parser.
    return @(Parse-ReportText -Text $allText -Catalog $Catalog -Log $Log)
}

# -----------------------------------------------------------------------------
#  Parse-ReportText -- shared text-table parser. Consumes already-extracted
#  report text (pdftotext -layout OR a PDF-viewer copy-paste) and returns the
#  same finding objects the CSV/PDF parsers do. No external dependency, so the
#  paste-text path works on a box with no pdftotext.exe installed.
# -----------------------------------------------------------------------------
function Parse-ReportText {
    param([string]$Text, $Catalog, [scriptblock]$Log)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        if ($Log) { & $Log "No report text to parse." 'warn' }
        return @()
    }
    $allText = $Text

    ## Stop scanning before non-actionable trailing sections.
    $usefulText = Get-UprUsefulText $allText
    $sections   = @(Get-UprSections)

    $findings = @{}
    foreach ($sec in $sections) {
        $countIdx = $usefulText.IndexOf($sec.CountAnchor)
        if ($countIdx -lt 0) { continue }
        $hostsIdx = $usefulText.IndexOf($sec.HostsAnchor, $countIdx)
        if ($hostsIdx -lt 0) { continue }
        $sectionEnd = $usefulText.Length
        foreach ($s2 in $sections) {
            if ($s2.Name -eq $sec.Name) { continue }
            $j = $usefulText.IndexOf($s2.CountAnchor, $hostsIdx)
            if ($j -ge 0 -and $j -lt $sectionEnd) { $sectionEnd = $j }
        }

        $countBlock = $usefulText.Substring($countIdx, $hostsIdx - $countIdx)
        $hostsBlock = $usefulText.Substring($hostsIdx, $sectionEnd - $hostsIdx)

        $rxNoise   = '(Plugin\s+Plugin\s+Name|Plugin Output|UNCLASSIFIED|^Lakenheath|SEoL_Product_Summary|Exploits by Platform|^Affected Hosts$|MAC Address\b|^IP Address|^NetBIOS Name|^DNS Name|^OS CPE|^Last Observed|^Steps to Remediate|^Plugin\s*$|^Plugin\s+Name\s*$|^Severity\s*$|^Total\s*$|^Unsupported Software Count$|^Unsupported / Security End of Life \(SEoL\) Operating Systems Count$|^Security End of Life \(SEoL\) Software Count$)'
        $rxSevTail = '\s+(?<sev>Critical|High|Medium|Low|Info)\s+(?<tot>\d+)\s*$'
        $rxIp4     = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

        $pending = New-Object System.Collections.ArrayList
        foreach ($ln in (($countBlock -split "`r?`n"))) {
            $s = $ln.Trim()
            if ($s -eq '' -or $s -match $rxNoise) { continue }
            if ($s -match $rxIp4) { break }   ## host block has leaked in -- stop

            $tail = [regex]::Match($s, $rxSevTail)
            if (-not $tail.Success) {
                [void]$pending.Add($s)
                continue
            }

            $sev   = $tail.Groups['sev'].Value
            $head  = $s.Substring(0, $tail.Index).Trim()
            $block = ($pending + @($head)) -join ' '
            $pending.Clear()
            $block = ($block -replace '\s+', ' ').Trim()
            if ($block -eq '') { continue }

            $plugin = ''
            $idMatch = [regex]::Match($block, '(?<![\w])(\d{4,7})(?![\w])')
            if ($idMatch.Success) { $plugin = $idMatch.Groups[1].Value }
            $name = ($block -replace '(?<![\w])\d{4,7}(?![\w])', ' ').Trim()
            $name = ($name -replace '\s+', ' ').Trim()
            if ($name -match '(?i)Unsupported.*Unsupported$') { $name = $name -replace '\s+Unsupported$','' }
            $name = ($name -replace '^Unsupported\s+(?=Microsoft|Mozilla|Oracle|VMware|Apache|Adobe|Java|Sun|IBM|Cisco|Tenable|HP\b|Citrix|Symantec|Trend\b|McAfee)', '').Trim()
            if ($name.Length -lt 6) { continue }

            $key = "$plugin|$name"
            if (-not $findings.ContainsKey($key)) {
                $cat = $sec.Category
                if (Test-IsOsFinding $Catalog $name) { $cat = 'OS' }
                $findings[$key] = [PSCustomObject]@{
                    Plugin         = $plugin
                    PluginName     = $name
                    Category       = $cat
                    SourceSection  = $sec.Name
                    Severity       = $sev
                    HostAttribution= 'exact'
                    Hosts          = New-Object System.Collections.ArrayList
                }
            }
        }

        $rxIp = '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        $hostRows = New-Object System.Collections.ArrayList
        $currentHost = $null
        foreach ($ln in (($hostsBlock -split "`r?`n"))) {
            $line = $ln.TrimEnd()
            if ($line -match '^\s*$' -or $line -match 'UNCLASSIFIED|IP Address\s+NetBIOS|Plugin Name|Affected Hosts') { continue }
            if ($line -match $rxIp) {
                $ip = $Matches[1]
                if ($null -ne $currentHost) { [void]$hostRows.Add($currentHost) }
                $currentHost = [PSCustomObject]@{
                    IPAddress = $ip; NetBIOSName=''; DNSName=''; OSCpe=''; MAC=''
                    MatchedDisplayName=$null; MatchedVersion=$null; MatchedPath=$null; CVE=''
                }
                $rest = $line.Substring($line.IndexOf($ip) + $ip.Length).Trim()
                if ($rest) {
                    if ($rest -match '\\(\S+)')                    { $currentHost.NetBIOSName = $Matches[1] }
                    if ($rest -match '([\w\-]+\.[\w\.\-]+\.\w+)')  { $currentHost.DNSName     = $Matches[1] }
                    if ($rest -match 'cpe:\S+')                    { $currentHost.OSCpe       = $Matches[0] }
                    if ($rest -match '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})') { $currentHost.MAC = $Matches[1] }
                }
            } elseif ($null -ne $currentHost) {
                if ($line -match '\\(\S+)' -and -not $currentHost.NetBIOSName)             { $currentHost.NetBIOSName = $Matches[1] }
                if ($line -match '([\w\-]+\.[\w\.\-]+\.\w+)' -and -not $currentHost.DNSName) { $currentHost.DNSName     = $Matches[1] }
                if ($line -match 'cpe:\S+' -and -not $currentHost.OSCpe)                   { $currentHost.OSCpe       = $Matches[0] }
                if ($line -match '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})' -and -not $currentHost.MAC) { $currentHost.MAC = $Matches[1] }
            }
        }
        if ($null -ne $currentHost) { [void]$hostRows.Add($currentHost) }

        $sectionFindings = @($findings.Values | Where-Object { $_.SourceSection -eq $sec.Name })
        # HONEST CAVEAT: the text-table path has no per-plugin sub-header, so every host
        # in the section's hosts block is attached to every finding in the section. That is
        # exact ONLY when the section has a single finding. When a section carries multiple
        # plugins (e.g. Win10 EOL + Server 2012 EOL + ESXi in one OS section), the per-plugin
        # host lists are section-level approximations -- tag them and warn the operator.
        $sectionApprox = ($sectionFindings.Count -gt 1)
        if ($sectionApprox -and $Log) {
            & $Log "Section '$($sec.Name)' contains $($sectionFindings.Count) findings but the report text has no per-plugin host breakdown -- host lists for these findings are section-level approximations (every host in the section is attributed to each plugin). Confirm per-host membership with a scan or the source ACAS report." 'warn'
        }
        foreach ($f in $sectionFindings) {
            if ($sectionApprox) { $f.HostAttribution = 'section-approximate' }
            foreach ($h in $hostRows) {
                $clone = $h | Select-Object *
                [void]$f.Hosts.Add($clone)
            }
        }
    }

    $out = @($findings.Values)
    if ($out.Count -eq 0) {
        ## The row-aligned parse found nothing -- the text is almost certainly
        ## linearized from a PDF-VIEWER copy-paste (the Tenable table columns
        ## collapse into separate runs, so each finding line no longer ends with
        ## "Severity Total"). Fall back to the catalog-driven relaxed parse.
        return @(Parse-ReportTextRelaxed -Text $allText -Catalog $Catalog -Log $Log)
    }
    $out
}

# -----------------------------------------------------------------------------
#  Parse-ReportTextRelaxed -- fallback for LINEARIZED report text (a PDF-viewer
#  copy-paste, where the table columns collapse and row alignment is lost).
#  Catalog-driven: find each known plugin-name pattern in the per-section count
#  block, and attach every IP in that section's hosts block.
#  ponytail: IP-only hosts -- NetBIOS/DNS are unrecoverable once the viewer
#  linearizes the table, but the scan connects by IP, so the core workflow works.
#  Two consequences in this mode: findings with no catalog profile aren't
#  surfaced (the tool only acts on catalog matches anyway), and the host-class
#  filter can't tell workstation from server (no NetBIOS) -- run host-class 'All'.
# -----------------------------------------------------------------------------
function Parse-ReportTextRelaxed {
    param([string]$Text, $Catalog, [scriptblock]$Log)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $allText = $Text

    $usefulText = Get-UprUsefulText $allText
    $sections   = @(Get-UprSections)

    $findings = @{}
    foreach ($sec in $sections) {
        $countIdx = $usefulText.IndexOf($sec.CountAnchor); if ($countIdx -lt 0) { continue }
        $hostsIdx = $usefulText.IndexOf($sec.HostsAnchor, $countIdx); if ($hostsIdx -lt 0) { continue }
        $sectionEnd = $usefulText.Length
        foreach ($s2 in $sections) { if ($s2.Name -eq $sec.Name) { continue }; $j = $usefulText.IndexOf($s2.CountAnchor, $hostsIdx); if ($j -ge 0 -and $j -lt $sectionEnd) { $sectionEnd = $j } }
        $countBlock = $usefulText.Substring($countIdx, $hostsIdx - $countIdx)
        $hostsBlock = $usefulText.Substring($hostsIdx, $sectionEnd - $hostsIdx)

        # IP-only host rows for this section (NetBIOS/DNS unrecoverable here).
        $hostRows = New-Object System.Collections.ArrayList
        $seenIp = @{}
        foreach ($mm in [regex]::Matches($hostsBlock, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')) {
            $ip = $mm.Value
            if ($seenIp.ContainsKey($ip)) { continue }
            $seenIp[$ip] = $true
            [void]$hostRows.Add([PSCustomObject]@{ IPAddress=$ip; NetBIOSName=''; DNSName=''; OSCpe=''; MAC=''; MatchedDisplayName=$null; MatchedVersion=$null; MatchedPath=$null; CVE='' })
        }

        # Catalog-driven finding extraction: locate each known plugin-name pattern
        # in the (glued) count block. The matched substring becomes the PluginName,
        # which then re-matches the same profile downstream (Get-UprProfileForFinding).
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($p in $Catalog.Profiles)                    { foreach ($x in [regex]::Matches($countBlock, $p.PluginNameMatch)) { if ($x.Value) { $names.Add($x.Value) } } }
        foreach ($op in $Catalog.OperatingSystemPluginNames) { foreach ($x in [regex]::Matches($countBlock, $op))               { if ($x.Value) { $names.Add($x.Value) } } }

        foreach ($nm in $names) {
            $name = ($nm -replace '\s+',' ').Trim()
            if ($name.Length -lt 4) { continue }
            $key = "rx|$name"
            if ($findings.ContainsKey($key)) { continue }
            $catg = $sec.Category
            if (Test-IsOsFinding $Catalog $name) { $catg = 'OS' }
            $f = [PSCustomObject]@{ Plugin=''; PluginName=$name; Category=$catg; SourceSection=$sec.Name; Severity=''; Hosts=(New-Object System.Collections.ArrayList) }
            foreach ($h in $hostRows) { [void]$f.Hosts.Add(($h | Select-Object *)) }
            $findings[$key] = $f
        }
    }

    if ($Log -and $findings.Count -gt 0) {
        & $Log "Linearized report text (PDF-viewer paste): recovered $($findings.Count) catalog-matched finding(s) by name + host IPs. NetBIOS/DNS are blank in this mode -- the scan connects by IP; run host-class 'All'." 'info'
    }
    $findings.Values
}

# -----------------------------------------------------------------------------
#  Remote worker scriptblock.
#  One worker per host: TCP 5985 precheck, open ONE session, enumerate installed
#  software ONCE, match every applicable profile (regex + VersionMaxExclusive),
#  compute Decision via the proven gate, and (when $DoUninstall) run the per-
#  product uninstall handler for each Uninstall-decision candidate (skipped on
#  DryRun, Review, or Tanium). Returns a result hashtable. Wrapped end-to-end in
#  try/catch so one host's failure never aborts the pool. Profiles are passed as
#  live objects (RunspacePool is in-process; no serialization).
# -----------------------------------------------------------------------------
$UprWorkerBlock = {
    param($ConnectTarget, $Profiles, $Cred, $Auth, $DoUninstall, $DryRun, $RemoveSet)

    $r = @{
        Host       = $ConnectTarget
        Reachable  = $false
        Error      = $null
        Candidates = @()
    }

    try {
        ## --- Reachability precheck (TCP 5985, 3s) ---
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($ConnectTarget, 5985, $null, $null)
            $ok  = $iar.AsyncWaitHandle.WaitOne(3000, $false)
            if ($ok -and $tcp.Connected) { $tcp.EndConnect($iar); $tcp.Close(); $r.Reachable = $true }
            else { try { $tcp.Close() } catch {} }
        } catch { }

        if (-not $r.Reachable) { return $r }

        ## --- Open ONE session ---
        $opt = New-PSSessionOption -OperationTimeout 300000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
        $session = $null
        try {
            if ($Cred) {
                $session = New-PSSession -ComputerName $ConnectTarget -Credential $Cred -Authentication $Auth -SessionOption $opt -ErrorAction Stop
            } else {
                $session = New-PSSession -ComputerName $ConnectTarget -SessionOption $opt -ErrorAction Stop
            }
        } catch {
            $r.Error = "session open failed: $($_.Exception.Message)"
            return $r
        }

        try {
            ## --- Enumerate installed software ONCE ---
            $installed = $null
            try {
                $installed = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    $apps = @()
                    $regPaths = @(
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    )
                    foreach ($rp in $regPaths) {
                        Get-ItemProperty $rp -EA SilentlyContinue | Where-Object {
                            $_.DisplayName -and $_.DisplayName.Trim() -ne ''
                        } | ForEach-Object {
                            $type = if ($_.UninstallString -match 'msiexec') { 'MSI' } else { 'EXE' }
                            $apps += @{
                                Name            = "$($_.DisplayName)"
                                Version         = "$($_.DisplayVersion)"
                                Publisher       = "$($_.Publisher)"
                                Type            = $type
                                UninstallString = "$($_.UninstallString)"
                                QuietUninstall  = "$($_.QuietUninstallString)"
                                PSChildName     = "$($_.PSChildName)"
                            }
                        }
                    }
                    return $apps
                }
            } catch {
                $r.Error = "scan failed: $($_.Exception.Message)"
                return $r
            }

            $installed = @($installed)

            ## --- Match every applicable profile against the install set ---
            $candidates = @()
            ## Protected security agents are NEVER removable -- regardless of what was
            ## named (manual mode) or catalog-flagged. Tanium keeps its own decision
            ## string for back-compat; the rest map to 'Skipped (protected)'. Over-
            ## matching here only ever REFUSES a removal (the safe direction).
            $protectedAgentRx = '(?i)Trellix|\bARAD\b|McAfee|ePolicy|Endpoint Security|Microsoft Defender|Windows Defender|System Center Endpoint|CrowdStrike|SentinelOne|Sentinel Agent|Carbon Black|Cb Defense|CbDefense|Cb Protection|Bit9|Cortex XDR|Symantec Endpoint|Tanium'
            foreach ($prof in @($Profiles)) {
                $rx   = [string]$prof.DisplayNameRegex
                $vmax = [string]$prof.VersionMaxExclusive
                foreach ($app in $installed) {
                    $name = [string]$app.Name
                    if ([string]::IsNullOrWhiteSpace($name)) { continue }
                    if ($name -notmatch $rx) { continue }

                    ## VersionMaxExclusive scan gate: include only when the install is
                    ## BELOW the cutoff (so MSXML 6 / .NET 8 don't even surface here). A
                    ## version that won't parse is included (can't prove it's supported)
                    ## so it still surfaces -- the proven gate then tags it Review.
                    if (-not [string]::IsNullOrWhiteSpace($vmax)) {
                        $vObj = $null; $maxObj = $null
                        $clean = ([string]$app.Version -replace '[^0-9\.]', '').Trim('.')
                        $vOk = [version]::TryParse($clean, [ref]$vObj)
                        $mOk = [version]::TryParse($vmax,  [ref]$maxObj)
                        if ($vOk -and $mOk -and ($vObj -ge $maxObj)) { continue }
                    }

                    ## Decision via the proven-only gate (inlined; worker is isolated).
                    $decision = 'Review'
                    if ($name -like '*Tanium*') {
                        $decision = 'Skipped (Tanium)'
                    } elseif ($name -match $protectedAgentRx) {
                        $decision = 'Skipped (protected)'
                    } elseif ($prof.Proven -eq $true) {
                        $decision = 'Uninstall'
                    } elseif (-not [string]::IsNullOrWhiteSpace($vmax)) {
                        if ($vOk -and $mOk -and ($vObj -lt $maxObj)) { $decision = 'Uninstall' }
                    }

                    $candidates += @{
                        Plugin          = [string]$prof.PluginNameMatch
                        Label           = [string]$prof.Notes
                        Product         = $name
                        Version         = [string]$app.Version
                        Publisher       = [string]$app.Publisher
                        Type            = [string]$app.Type
                        UninstallString = [string]$app.UninstallString
                        QuietUninstall  = [string]$app.QuietUninstall
                        PSChildName     = [string]$app.PSChildName
                        Decision        = $decision
                        Result          = $null
                    }
                }
            }

            ## De-dup candidates by Product+Version (a host can appear under several
            ## findings that map to overlapping profiles).
            $seen = @{}
            $uniq = @()
            foreach ($cand in $candidates) {
                $k = "$($cand.Product)|$($cand.Version)|$($cand.PSChildName)"
                if ($seen.ContainsKey($k)) { continue }
                $seen[$k] = $true
                $uniq += $cand
            }
            $candidates = $uniq

            ## --- Uninstall pass (report-uninstall only) ---
            if ($DoUninstall) {
                foreach ($cand in $candidates) {
                    if ($cand.Decision -eq 'Skipped (Tanium)') { $cand.Result = 'Skipped (Tanium)'; continue }
                    if ($cand.Decision -eq 'Skipped (protected)') { $cand.Result = 'Skipped (protected)'; continue }
                    if ($cand.Decision -ne 'Uninstall')        { $cand.Result = 'Skipped (Review)'; continue }
                    ## Operator-selection gate: when a remove-set was supplied, act ONLY on
                    ## the candidates the operator checked (Target|Product|Version|PSChildName).
                    ## $null => remove every proven candidate (legacy). This only ever removes
                    ## LESS than before, never more.
                    if ($null -ne $RemoveSet) {
                        $candKey = "$ConnectTarget|$($cand.Product)|$($cand.Version)|$($cand.PSChildName)"
                        if (-not $RemoveSet.Contains($candKey)) { $cand.Result = 'Skipped (not selected)'; continue }
                    }
                    if ($DryRun)                               { $cand.Result = 'Skipped (DryRun)'; continue }

                    $appResult = $null
                    try {
                        $appResult = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $cand.Product, $cand.Type, $cand.UninstallString, $cand.QuietUninstall, $cand.PSChildName -ScriptBlock {
                            param($name, $type, $unStr, $quietStr, $childName)
                            try {
                                ## === Microsoft 365 handler (SaRA-style package script + setup.exe /configure) ===
                                if ($name -match 'Microsoft 365|Office.*365|O365|Office.*ProPlus') {
                                    $steps = @(); $c2rPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
                                    $localCmd = "C:\Temp\Uninstall-M365.cmd"
                                    if (Test-Path $localCmd -EA SilentlyContinue) {
                                        $proc = Start-Process cmd.exe -ArgumentList "/c `"$localCmd`"" -Wait -PassThru -NoNewWindow
                                        Get-ChildItem "C:\Temp\Uninstall-*.cmd" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
                                        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (M365 package script exit $($proc.ExitCode))" }
                                        $steps += "Package script non-zero exit -- trying built-in"
                                    }
                                    $setupExe = Join-Path $c2rPath "setup.exe"
                                    if (Test-Path $setupExe) {
                                        New-Item -Path C:\Temp -ItemType Directory -Force -EA SilentlyContinue | Out-Null
                                        $xmlPath = "C:\Temp\OfficeRemoveAll.xml"
                                        '<Configuration><Remove All="TRUE"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' | Out-File $xmlPath -Encoding ASCII -Force
                                        $proc = Start-Process $setupExe -ArgumentList "/configure `"$xmlPath`"" -Wait -PassThru -NoNewWindow
                                        Remove-Item $xmlPath -Force -EA SilentlyContinue
                                        if ($proc.ExitCode -eq 0) { return "OK (Office removed via setup.exe /configure)" }
                                        $steps += "setup.exe /configure exit $($proc.ExitCode)"
                                    }
                                    if (-not [string]::IsNullOrWhiteSpace($unStr)) {
                                        $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr`"" -Wait -PassThru -NoNewWindow
                                        if ($proc.ExitCode -eq 0) { return "OK (Office removed via uninstall string)" }
                                        $steps += "Uninstall string exit $($proc.ExitCode)"
                                    }
                                    return "FAIL (Office -- all methods attempted: $($steps -join ' | '))"
                                }
                                ## === Adobe Acrobat handler with RunAsPPL save/remove/restore guard ===
                                if ($name -match 'Adobe Acrobat') {
                                    $steps = @(); $removed = $false; $pplRestoreNeeded = $false; $pplOriginalValue = $null
                                    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                                    try {
                                        try {
                                            $pplVal = Get-ItemProperty $lsaKey -Name "RunAsPPL" -EA SilentlyContinue
                                            if ($null -ne $pplVal -and $null -ne $pplVal.RunAsPPL) {
                                                $pplOriginalValue = $pplVal.RunAsPPL
                                                Remove-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Force -EA Stop
                                                $pplRestoreNeeded = $true
                                                $steps += "RunAsPPL removed (was: $pplOriginalValue)"
                                            }
                                        } catch {}
                                        try {
                                            $adobeSvcs = @('AdobeARMservice','AdobeUpdateService','AGSService')
                                            foreach ($svc in $adobeSvcs) { $s = Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -eq 'Running') { Stop-Service $svc -Force -EA SilentlyContinue } }
                                            $adobeProcs = @('Acrobat','AcroCEF','AcroRd32','AdobeARM','AdobeCollabSync','armsvc')
                                            foreach ($p in $adobeProcs) { Get-Process $p -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue }
                                        } catch {}
                                        ## Scope removal to the SELECTED candidate ONLY (audit#3). 'Adobe
                                        ## Acrobat' is a substring of Reader DC, Acrobat Pro and their
                                        ## 32/64-bit siblings, so a family-wide DisplayName re-enumeration
                                        ## here removed products the operator never checked. The candidate's
                                        ## own registry key (PSChildName) / uninstall strings carry its GUID.
                                        $adobeGuids = @()
                                        if ($childName -match '^\{[^\}]+\}$') { $adobeGuids += $childName }
                                        foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                                            $item = Get-ItemProperty (Join-Path $hive $childName) -EA SilentlyContinue
                                            if ($item -and $item.UninstallString -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }
                                        }
                                        if ($unStr -match '(\{[^\}]+\})') { $adobeGuids += $Matches[1] }
                                        $adobeGuids = @($adobeGuids | Select-Object -Unique)
                                        if ($adobeGuids.Count -eq 0) { return "FAIL (Adobe -- no MSI GUID resolvable for the selected install '$name' [$childName]; nothing removed)" }
                                        foreach ($guid in $adobeGuids) {
                                            $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                                            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { $removed = $true }
                                        }
                                    } finally {
                                        if ($pplRestoreNeeded) {
                                            try { New-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value $pplOriginalValue -PropertyType DWord -Force -EA Stop | Out-Null }
                                            catch { $steps += "WARNING: RunAsPPL restore FAILED" }
                                        }
                                    }
                                    if ($removed) { return "OK (Adobe removed via MSI -- $($adobeGuids.Count) GUID(s))" }
                                    return "FAIL (Adobe -- $($steps -join ' | '))"
                                }
                                ## === Generic handlers ===
                                if ($type -eq 'Store') {
                                    Get-AppxPackage -AllUsers -Name "*$name*" -EA SilentlyContinue | Remove-AppxPackage -AllUsers -EA Stop
                                    return "OK (Store app removed)"
                                } elseif ($type -eq 'MSI') {
                                    $guid = $unStr -replace '.*(\{[^\}]+\}).*', '$1'
                                    if ($guid -match '^\{') {
                                        $proc = Start-Process msiexec -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru -NoNewWindow
                                        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { return "OK (MSI exit $($proc.ExitCode))" }
                                        else { return "WARN (MSI exit $($proc.ExitCode))" }
                                    } else { return "FAIL: Could not extract MSI GUID" }
                                } else {
                                    ## Exit-code gate (mirrors the MSI handler): treat ONLY 0/3010 as
                                    ## success. A null process (Start-Process failed) or any other exit
                                    ## code is a real failure -- never report OK unconditionally.
                                    if (-not [string]::IsNullOrWhiteSpace($quietStr)) {
                                        $proc = Start-Process cmd.exe -ArgumentList "/c `"$quietStr`"" -Wait -PassThru -NoNewWindow
                                        if ($null -ne $proc -and ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010)) { return "OK (QuietUninstall exit $($proc.ExitCode))" }
                                        else { return "FAIL (QuietUninstall exit $(if ($proc) { $proc.ExitCode } else { 'no process' }))" }
                                    } elseif (-not [string]::IsNullOrWhiteSpace($unStr)) {
                                        $exePath = ($unStr -split '/|--')[0].Trim('"').Trim()
                                        if (Test-Path $exePath) {
                                            $proc = Start-Process $exePath -ArgumentList "/S /silent /quiet /uninstall /norestart" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                            if ($null -ne $proc -and ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010)) { return "OK (EXE exit $($proc.ExitCode))" }
                                            else { return "FAIL (EXE exit $(if ($proc) { $proc.ExitCode } else { 'no process' }))" }
                                        } else {
                                            $proc = Start-Process cmd.exe -ArgumentList "/c `"$unStr /S /quiet /norestart`"" -Wait -PassThru -NoNewWindow -EA SilentlyContinue
                                            if ($null -ne $proc -and ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010)) { return "OK (CMD exit $($proc.ExitCode))" }
                                            else { return "FAIL (CMD exit $(if ($proc) { $proc.ExitCode } else { 'no process' }))" }
                                        }
                                    } else { return "FAIL: No uninstall string available" }
                                }
                            } catch { return "FAIL: $($_.Exception.Message)" }
                        }
                    } catch { $appResult = "FAIL: $($_.Exception.Message)" }
                    $cand.Result = [string]$appResult
                }
            }

            $r.Candidates = $candidates
        } finally {
            try { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } catch {}
        }
    } catch {
        $r.Error = "worker error: $($_.Exception.Message)"
    }

    return $r
}

# -----------------------------------------------------------------------------
#  Invoke-UprFanOut -- self-contained RunspacePool harvest loop (re-implemented
#  from the WPT Invoke-WptFanOut; WPT functions are NOT callable from here).
#  One worker per host. Each $HostJob is @{ Target=<connect target>; Profiles=
#  <profile object list>; HostObj=<the host record> }. For each completed worker
#  the EmitRows callback turns the result into grid rows + emits row/audit/log
#  events; the harness handles progress and the operator-cancel bridge.
# -----------------------------------------------------------------------------
function Invoke-UprFanOut {
    param(
        [object[]]$HostJobs,
        [int]$Threads,
        [scriptblock]$Work,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Auth,
        [bool]$DoUninstall,
        [bool]$DryRun,
        [scriptblock]$EmitRows,    # param($result, $hostJob) -> returns @{ rows=@(); ok=$bool; itemCount=$int; detail='' }
        [string]$AuditAction,
        [scriptblock]$Send,
        [string]$ActionId,
        [scriptblock]$CancelCheck,
        [int]$DeadlineSeconds = 3600,
        [int]$PerHostTimeoutSeconds = 0, # per-host limit; >0 abandons ONLY a host overrunning its OWN run clock (0 = off). Mirrors Invoke-AcasFanOut. Set it for the read-only scan; leave 0 for uninstall runs that legitimately run long.
        [bool]$EmitHostAudit = $true,    # $false suppresses the generic per-host audit emit; the uninstall path turns it off so the per-app VulnPatched records in EmitRows are the SOLE source (no double-counted itemCount). Scan keeps it on for the host-level TouchHost.
        $RemoveSet = $null               # report-uninstall only: HashSet of operator-checked "Target|Product|Version|PSChildName" keys. $null => remove every proven candidate (legacy). Passed live to each worker (in-process pool, no serialization).
    )

    & $Send @{ type='status'; text="Starting '$ActionId' on $($HostJobs.Count) host(s) with $Threads thread(s)..." }
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($hj in $HostJobs) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($Work)
        [void]$ps.AddArgument($hj.Target)
        [void]$ps.AddArgument($hj.Profiles)
        [void]$ps.AddArgument($Credential)
        [void]$ps.AddArgument($Auth)
        [void]$ps.AddArgument($DoUninstall)
        [void]$ps.AddArgument($DryRun)
        [void]$ps.AddArgument($RemoveSet)
        [void]$jobs.Add([pscustomobject]@{ Host=$hj.Target; HostJob=$hj; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
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
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch {
                        $res = @{ Host=$j.Host; Reachable=$false; Error="worker error: $($_.Exception.Message)"; Candidates=@() }
                        & $Send @{ type='log'; level='warn'; text="$($j.Host) : worker error: $($_.Exception.Message)" }
                    }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Reachable=$false; Error='no result'; Candidates=@() } }

                    $emit = & $EmitRows $res $j.HostJob
                    foreach ($row in @($emit.rows)) {
                        [void]$rows.Add($row)
                        & $Send (@{ type='row' } + $row)
                    }
                    $ok = [bool]$emit.ok
                    if ($ok) { $okCount++ } else { $failCount++ }
                    # Audit result/itemCount: honor an explicit honest result from the
                    # EmitRows callback (e.g. uninstall Success ONLY when >=1 removed)
                    # when present; otherwise fall back to the reach/scan ok flag.
                    $auditRes = if ($emit -is [hashtable] -and $emit.ContainsKey('auditResult') -and $emit['auditResult']) { [string]$emit['auditResult'] } else { if ($ok) { 'Success' } else { 'Failure' } }
                    $auditCnt = if ($emit -is [hashtable] -and $emit.ContainsKey('auditItems')) { [int]$emit['auditItems'] } else { [int]$emit.itemCount }
                    # Suppressed on the uninstall path ($EmitHostAudit=$false): the per-app
                    # VulnPatched records emitted in EmitRows are the sole audit source there,
                    # so we don't also write a host-level record (which double-counted itemCount).
                    if ($EmitHostAudit) { & $Send @{ type='audit'; action=$AuditAction; target=$res.Host; result=$auditRes; itemCount=$auditCnt; detail=([string]$emit.detail) } }
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
                        $rowT = @{ _rk="$($j.Host)|timeout"; Host=$j.Host; Plugin=''; Product=''; Version=''; Decision='Abandoned'; Detail="per-host timeout (${PerHostTimeoutSeconds}s) - possible WMI/CIM hang"; Result="per-host timeout (${PerHostTimeoutSeconds}s)" }
                        [void]$rows.Add($rowT); & $Send (@{ type='row' } + $rowT)
                        & $Send @{ type='audit'; action=$AuditAction; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${PerHostTimeoutSeconds}s)" }
                        & $Send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${PerHostTimeoutSeconds}s per-host timeout (in-flight WinRM/CIM call being stopped); the rest of the run continues." }
                        $failCount++; $done++
                        & $Send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if     ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true }
                elseif ((Get-Date) -gt $deadline)           { $timedOut  = $true }
                if ($cancelled -or $timedOut) {
                    $reason = if ($cancelled) { 'cancelled by operator' } else { "timed out after $([int]$DeadlineSeconds)s" }
                    $abandoned = 0
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $rowR = @{ _rk="$($j.Host)|abandoned"; Host=$j.Host; Plugin=''; Product=''; Version=''; Decision='Abandoned'; Detail=$reason; Result=$reason }
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
#  Build the host job map: de-dup hosts across all ACTIONABLE findings by the
#  connect-target (DNS > NetBIOS > IP, case-insensitive), filtered by host class,
#  and union the applicable profiles each host appears under.
#  Returns an array of @{ Target; Profiles=@(<profile objects>); HostObj }.
# -----------------------------------------------------------------------------
function Build-UprHostJobs {
    param($Findings, $Catalog, [string]$HostClass, [scriptblock]$Log, $TargetFilter = $null)

    # $TargetFilter (report-uninstall only): a HashSet of connect-targets the
    # operator actually checked. When supplied, only build jobs for those hosts so
    # the uninstall re-scan touches EXACTLY the selected machines (never more).
    # $null => no filter (Scan, and the legacy no-selection uninstall path).
    $byTarget = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $dropped  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($f in @($Findings)) {
        # Skip OS findings (out of scope) and update-class findings entirely.
        if ($f.Category -eq 'OS') { continue }
        if (Test-IsOsFinding $Catalog $f.PluginName) { continue }
        $prof = Get-UprProfileForFinding $Catalog $f
        if ($null -ne $prof -and -not [string]::IsNullOrWhiteSpace([string]$prof.Updater)) { continue }  # update-class hidden
        if ($null -eq $prof) { continue }  # no profile -> nothing the scan can match on this host

        foreach ($h in @($f.Hosts)) {
            if (-not (Test-UprHostClassMatch $h $HostClass)) { continue }
            $target = Get-UprConnectTarget $h
            if ([string]::IsNullOrWhiteSpace($target)) {
                # Host matched the class filter but has no usable connect target
                # (domain-fragment / blank from the jagged PDF). Count it once.
                [void]$dropped.Add("$($h.DNSName)|$($h.NetBIOSName)|$($h.IPAddress)")
                continue
            }

            # Operator-selection host filter: skip hosts the operator did not check.
            if ($null -ne $TargetFilter -and -not $TargetFilter.Contains($target)) { continue }

            if (-not $byTarget.ContainsKey($target)) {
                $byTarget[$target] = [PSCustomObject]@{
                    Target   = $target
                    HostObj  = $h
                    Profiles = (New-Object System.Collections.ArrayList)
                    ProfSeen = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
                }
            }
            $entry = $byTarget[$target]
            $pkey = [string]$prof.PluginNameMatch
            if ($entry.ProfSeen.Add($pkey)) { [void]$entry.Profiles.Add($prof) }
        }
    }

    if ($Log -and $dropped.Count -gt 0) {
        & $Log "$($dropped.Count) affected host(s) had no usable connect target (domain-fragment or blank in the report) and were skipped. CSV input gives clean IP/NetBIOS/DNS columns." 'warn'
    }

    $jobs = @()
    foreach ($entry in $byTarget.Values) {
        $jobs += [PSCustomObject]@{ Target=$entry.Target; Profiles=@($entry.Profiles.ToArray()); HostObj=$entry.HostObj }
    }
    return $jobs
}

# -----------------------------------------------------------------------------
#  New-UprEmitRows -- build the EmitRows callback for Invoke-UprFanOut. SHARED by
#  the report path (report-scan/report-uninstall) AND the manual path (manual-scan/
#  manual-uninstall): turns one worker result into grid rows + the per-app
#  VulnPatched audit (uninstall), honoring dry-run and the Uninstall/Tanium/
#  protected decisions. GetNewClosure captures the three params so it is self-
#  contained when handed to the fan-out. (Extracted verbatim from the old inline
#  report-mode closure -- behavior identical; manual mode reuses it unchanged.)
# -----------------------------------------------------------------------------
function New-UprEmitRows {
    param([bool]$DoUninstall, [bool]$DryRun, [scriptblock]$Send)
    return {
        param($res, $hj)
        $outRows = New-Object System.Collections.ArrayList
        $hostName = [string]$res.Host
        $uninstalledCount = 0
        $attempted = 0

        if (-not $res.Reachable) {
            $detailTxt = if ($res.Error) { [string]$res.Error } else { 'no TCP reply on 5985' }
            $row = @{ _rk="$hostName|unreachable"; Host=$hostName; Plugin=''; Product=''; Version=''; Decision='Unreachable'; Detail=$detailTxt }
            if ($DoUninstall) { $row.Remove('Detail'); $row['Result'] = $detailTxt }
            [void]$outRows.Add($row)
            return @{ rows=@($outRows); ok=$false; itemCount=0; detail=$detailTxt }
        }

        if ($res.Error) {
            $row = @{ _rk="$hostName|error"; Host=$hostName; Plugin=''; Product=''; Version=''; Decision='Error'; Detail=[string]$res.Error }
            if ($DoUninstall) { $row.Remove('Detail'); $row['Result'] = [string]$res.Error }
            [void]$outRows.Add($row)
            return @{ rows=@($outRows); ok=$false; itemCount=0; detail=[string]$res.Error }
        }

        $cands = @($res.Candidates)
        if ($cands.Count -eq 0) {
            $row = @{ _rk="$hostName|nomatch"; Host=$hostName; Plugin=''; Product=''; Version=''; Decision='No match'; Detail='No flagged install found in the registry.' }
            if ($DoUninstall) { $row.Remove('Detail'); $row['Result'] = 'No match' }
            [void]$outRows.Add($row)
            $nm = @{ rows=@($outRows); ok=$true; itemCount=0; detail='no match' }
            # Audit honesty: an uninstall pass that found nothing to remove patched
            # nothing -> Skipped (scan keeps the TouchHost 'host reached' semantic).
            if ($DoUninstall) { $nm['auditResult'] = 'Skipped'; $nm['auditItems'] = 0 }
            return $nm
        }

        $i = 0
        foreach ($cand in $cands) {
            $i++
            if ($DoUninstall) {
                $resultTxt = if ($cand.Result) { [string]$cand.Result } else { '' }
                # 'attempted' must exclude rows we deliberately skipped (e.g. not-selected),
                # so an all-skipped host audits Skipped, not a false Failure. In the legacy
                # no-selection path no proven row is ever 'Skipped*' in a live run, so this
                # is identical to before.
                if ($cand.Decision -eq 'Uninstall' -and (-not $DryRun) -and (-not ($resultTxt -like 'Skipped*'))) { $attempted++ }
                if ($cand.Decision -eq 'Uninstall' -and (-not $DryRun) -and ($resultTxt -like 'OK*')) { $uninstalledCount++ }
                $row = @{
                    _rk="$hostName|$($cand.Product)|$($cand.Version)|$i"
                    Host=$hostName; Plugin=[string]$cand.Plugin; Product=[string]$cand.Product
                    Version=[string]$cand.Version; Decision=[string]$cand.Decision; Result=$resultTxt
                    Publisher=[string]$cand.Publisher; Type=[string]$cand.Type; PSChildName=[string]$cand.PSChildName
                    Label=[string]$cand.Label; UninstallString=[string]$cand.UninstallString
                }
                # Per-app uninstall audit, matching the desktop twin's Write-AuditLog
                # "UnsupportedProductUninstall" call (OK*->Success, Skipped*->Skipped,
                # else->Failure) emitted once per host\app -- not just one per host.
                $candResult = if ($resultTxt -like 'OK*') { 'Success' } elseif ($resultTxt -like 'Skipped*') { 'Skipped' } else { 'Failure' }
                $candItems  = if ($candResult -eq 'Success') { 1 } else { 0 }
                & $Send @{ type='audit'; action='VulnPatched'; target="$hostName\$([string]$cand.Product)"; result=$candResult; itemCount=$candItems; detail=("UnsupportedProductUninstall: " + $resultTxt) }
            } else {
                $row = @{
                    _rk="$hostName|$($cand.Product)|$($cand.Version)|$i"
                    Host=$hostName; Plugin=[string]$cand.Plugin; Product=[string]$cand.Product
                    Version=[string]$cand.Version; Decision=[string]$cand.Decision; Detail=[string]$cand.Label
                    Publisher=[string]$cand.Publisher; Type=[string]$cand.Type; PSChildName=[string]$cand.PSChildName
                    Label=[string]$cand.Label; UninstallString=[string]$cand.UninstallString
                }
            }
            [void]$outRows.Add($row)
        }

        $detail = "$($cands.Count) candidate(s)"
        if ($DoUninstall) { $detail = "$($cands.Count) candidate(s); $uninstalledCount uninstalled" }
        $ret = @{ rows=@($outRows); ok=$true; itemCount=$uninstalledCount; detail=$detail }
        if ($DoUninstall) {
            # Audit honesty: VulnPatched Success ONLY when >=1 install was really
            # removed. Dry run / nothing-to-remove = Skipped; attempted-but-all-failed
            # = Failure. itemCount carries only truly-removed installs.
            $ret['auditItems'] = $uninstalledCount
            if ($DryRun)                     { $ret['auditResult'] = 'Skipped' }
            elseif ($uninstalledCount -ge 1) { $ret['auditResult'] = 'Success' }
            elseif ($attempted -ge 1)        { $ret['auditResult'] = 'Failure' }
            else                             { $ret['auditResult'] = 'Skipped' }
        }
        return $ret
    }.GetNewClosure()
}

# -----------------------------------------------------------------------------
#  Manual (operator-driven) mode helpers. Instead of a parsed ACAS report, the
#  operator pastes a host list + a software list. Each software line becomes a
#  synthetic profile (DisplayName contains-match, '*' wildcard) with Proven=$true
#  so every match is an Uninstall candidate -- the operator IS the authority. The
#  worker's protected-agent guard still refuses EDR / security agents.
# -----------------------------------------------------------------------------
function ConvertTo-UprManualRegex {
    # One pasted software line -> a case-insensitive substring DisplayName regex.
    # '*' is a wildcard (-> .*); every other regex metachar is escaped. Blank -> $null.
    param([string]$Line)
    $t = ([string]$Line).Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    # Reject a wildcard/metachar-only line (e.g. '*', '***'): with no literal character
    # it compiles to a match-everything regex and -- being Proven -- would make EVERY
    # installed app an uninstall candidate. Caller then surfaces 'No usable match rules'.
    if ([string]::IsNullOrWhiteSpace(($t -replace '\*', ''))) { return $null }
    $esc = [regex]::Escape($t)
    $esc = $esc -replace '\\\*', '.*'
    return ('(?i)' + $esc)
}

function Build-UprManualProfiles {
    # Pasted software names (newline-delimited) -> synthetic catalog profiles the
    # existing worker matches on. Proven=$true so every named match becomes an
    # Uninstall candidate. One profile per unique line.
    param([string]$SoftwareText, [scriptblock]$Log)
    $profiles = @()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in (($SoftwareText -split "`r?`n"))) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if (-not $seen.Add($t)) { continue }
        $rx = ConvertTo-UprManualRegex $t
        if ([string]::IsNullOrWhiteSpace($rx)) { continue }
        $profiles += [PSCustomObject]@{
            Plugin              = '*'
            PluginNameMatch     = $t
            DisplayNameRegex    = $rx
            VersionMaxExclusive = $null
            Updater             = $null
            Proven              = $true
            Category            = 'Manual'
            Notes               = ('Operator-named: ' + $t)
        }
    }
    if ($Log -and $profiles.Count -gt 0) { & $Log "Built $($profiles.Count) software match rule(s) from the pasted list." 'info' }
    return $profiles
}

function Build-UprManualHostJobs {
    # Operator-pasted host list -> host jobs, each carrying the FULL synthetic
    # profile set. De-dup by connect target (case-insensitive); take the first
    # whitespace/comma token per line (a raw paste may include extra columns);
    # validate with Test-UprValidTarget so obvious junk is dropped.
    param([string]$HostsText, $Profiles, [scriptblock]$Log)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $jobs = @()
    $dropped = 0
    foreach ($line in (($HostsText -split "`r?`n"))) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $t = (($t -split '[,\s]+')[0]).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if (-not (Test-UprValidTarget $t)) { $dropped++; continue }
        if (-not $seen.Add($t)) { continue }
        $jobs += [PSCustomObject]@{ Target=$t; Profiles=@($Profiles); HostObj=[PSCustomObject]@{ NetBIOSName=$t; DNSName=''; IPAddress='' } }
    }
    if ($Log -and $dropped -gt 0) { & $Log "$dropped pasted host token(s) were not valid host names/IPs and were skipped." 'warn' }
    return $jobs
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

    # Logging closure that emits a {type='log'} event (replaces the desktop Log fn).
    $log = { param($Msg, $Lvl = 'info') & $send @{ type='log'; level=$Lvl; text=[string]$Msg } }.GetNewClosure()

    # Operator-cancel bridge: the server injects the synchronized job as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running fan-out break and BeginStop in-flight WinRM children.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Negotiate when a credential is supplied; otherwise omit auth.
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }

    $catalog   = Get-UprCatalog
    $hostClass = if ($Params['hostclass']) { [string]$Params['hostclass'] } else { 'All' }

    # ---- Reload Catalog (no report needed): report which source loaded + counts ----
    if ($ActionId -eq 'reload-catalog') {
        $fromFile = Get-UprCatalogFromFile
        $src   = if ($fromFile) { 'JanetLocal\UnsupportedProductCatalog.json' } else { 'embedded default' }
        $profs = @($catalog.Profiles).Count
        $osn   = @($catalog.OperatingSystemPluginNames).Count
        $row = @{ Source=$src; Profiles=$profs; 'OS Plugin Patterns'=$osn }
        & $send (@{ type='row' } + $row)
        & $log "Catalog loaded from $src - $profs profile(s), $osn OS pattern(s)." 'ok'
        return @{ rows=@($row); summary=@{ total=$profs; source=$src } }
    }

    # =====================================================================
    #  manual-scan / manual-uninstall -- operator-driven (NO report).
    #  Paste a host list + a software list; synthesize match profiles and reuse
    #  the exact same per-host worker + fan-out + selection gate + audit as the
    #  report path. The catalog proven-gate is bypassed (the operator names the
    #  targets); the worker's protected-agent guard still refuses security agents.
    # =====================================================================
    if ($ActionId -eq 'manual-scan' -or $ActionId -eq 'manual-uninstall') {
        $softwareText = [string]$Params['software']
        $hostsText    = [string]$Params['hosts']
        if ([string]::IsNullOrWhiteSpace($softwareText)) { & $log 'Paste at least one software name to find.' 'warn'; return @{ rows=@(); summary=@{ total=0 } } }
        if ([string]::IsNullOrWhiteSpace($hostsText))    { & $log 'Paste at least one machine to scan.' 'warn';     return @{ rows=@(); summary=@{ total=0 } } }

        $manualProfiles = @(Build-UprManualProfiles -SoftwareText $softwareText -Log $log)
        if ($manualProfiles.Count -eq 0) { & $log 'No usable software match rules parsed from the list.' 'warn'; return @{ rows=@(); summary=@{ total=0 } } }

        $doUninstall = ($ActionId -eq 'manual-uninstall')
        $dryRun = $true
        if ($Params.ContainsKey('dryrun')) {
            $dv = $Params['dryrun']
            if ($dv -is [bool]) { $dryRun = $dv } else { $dryRun = -not (("$dv").Trim() -match '^(?i:false|0|no|off)$') }
        }
        $threads = Get-UprThreadCount $Params 16

        # Operator selection (uninstall only): same selecthosts/selectkeys contract
        # as report-uninstall. Per-row key is Host|Product|Version|PSChildName.
        $selectHosts = $null; $selectKeys = $null
        if ($doUninstall) {
            $rawHosts = [string]$Params['selecthosts']
            $rawKeys  = [string]$Params['selectkeys']
            if (-not [string]::IsNullOrWhiteSpace($rawHosts)) {
                $selectHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($hLine in ($rawHosts -split "`r?`n")) { $sv = ([string]$hLine).Trim(); if ($sv) { [void]$selectHosts.Add($sv) } }
            }
            if (-not [string]::IsNullOrWhiteSpace($rawKeys)) {
                $selectKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($kLine in ($rawKeys -split "`r?`n")) { $sv = ([string]$kLine).Trim(); if ($sv) { [void]$selectKeys.Add($sv) } }
            }
            if ($selectKeys -and $selectKeys.Count -gt 0) {
                $selHostCount = if ($selectHosts) { $selectHosts.Count } else { 0 }
                & $log "Honoring operator selection: $($selectKeys.Count) checked row(s) across $selHostCount host(s)." 'info'
            } else {
                if (-not $dryRun) {
                    $refuseMsg = 'Refused: no rows selected - check the software to uninstall (live uninstall requires an explicit selection).'
                    & $log $refuseMsg 'error'
                    & $send @{ type='status'; text=$refuseMsg }
                    return @{ rows=@(); summary=@{ total=0; error=$refuseMsg } }
                }
                & $log 'No row selection supplied -- dry-run will preview every match on all listed hosts.' 'warn'
            }
        }

        $manualJobs = @(Build-UprManualHostJobs -HostsText $hostsText -Profiles $manualProfiles -Log $log)
        # uninstall: restrict the re-scan to the selected hosts (never more).
        if ($doUninstall -and $null -ne $selectHosts) {
            $manualJobs = @($manualJobs | Where-Object { $selectHosts.Contains($_.Target) })
        }
        if ($manualJobs.Count -eq 0) { & $log 'No valid machines to scan after parsing the host list.' 'warn'; return @{ rows=@(); summary=@{ total=0 } } }

        $modeWord = if ($doUninstall) { 'uninstall' } else { 'scan' }
        & $log ("Targeted " + $modeWord + ": " + $manualJobs.Count + " host(s), " + $manualProfiles.Count + " software rule(s).") 'info'
        if ($doUninstall) {
            & $log ("Uninstall mode: dryRun=" + $dryRun + ". Protected security agents (Tanium/Trellix/Defender/CrowdStrike/...) are never removed.") $(if ($dryRun) { 'info' } else { 'warn' })
        }

        $removeSet = $null
        if ($doUninstall) { $removeSet = $selectKeys }

        $emitRows = New-UprEmitRows -DoUninstall $doUninstall -DryRun $dryRun -Send $send
        $auditAction = if ($doUninstall) { 'VulnPatched' } else { 'TouchHost' }
        $perHostTimeout = if ($doUninstall) { 0 } else { 300 }

        return Invoke-UprFanOut -HostJobs $manualJobs -Threads $threads -Work $UprWorkerBlock `
            -Credential $Credential -Auth $auth -DoUninstall $doUninstall -DryRun $dryRun `
            -EmitRows $emitRows -AuditAction $auditAction -Send $send -ActionId $ActionId -CancelCheck $cancelCheck -PerHostTimeoutSeconds $perHostTimeout `
            -EmitHostAudit (-not $doUninstall) -RemoveSet $removeSet
    }

    # ---- Resolve + parse the report: pasted text wins, else the uploaded file ----
    # 'reporttext' lets an operator paste the report (open PDF -> Ctrl+A -> Ctrl+C)
    # instead of uploading a file -- no pdftotext.exe needed on the server.
    $reportText = [string]$Params['reporttext']
    $reportPath = ''
    if ([string]::IsNullOrWhiteSpace($reportText)) {
        $reportPath = [string]$Params['report']
        if ([string]::IsNullOrWhiteSpace($reportPath) -or -not (Test-Path -LiteralPath $reportPath)) {
            & $log "Provide a report: upload a CSV/PDF, or paste the report text." 'warn'
            return @{ rows=@(); summary=@{ total=0 } }
        }
    }

    # Reuse the cached parse when the same report (file path+mtime+size, or pasted-
    # text hash) is re-submitted under the same catalog -- findings/OS/scan/uninstall
    # all re-enter here, so this avoids re-spawning pdftotext + re-running the parse.
    $cacheKey = Get-UprReportCacheKey -ReportPath $reportPath -ReportText $reportText -Catalog $catalog
    $findings = $null
    if ($cacheKey) { $findings = Get-UprCachedFindings $cacheKey }
    if ($null -ne $findings) {
        $findings = @($findings)
        & $log "Report unchanged - reusing cached parse ($($findings.Count) finding(s))." 'info'
    } else {
        if (-not [string]::IsNullOrWhiteSpace($reportText)) {
            & $log "Parsing pasted report text ($($reportText.Length) chars; no pdftotext needed)..." 'info'
            $findings = @(Parse-ReportText -Text $reportText -Catalog $catalog -Log $log)
        } else {
            & $log "Parsing $([IO.Path]::GetFileName($reportPath))..." 'info'
            $findings = @(Import-UprFinding -Path $reportPath -Catalog $catalog -Log $log)
        }
        if ($findings.Count -gt 0) {
            if ($cacheKey) { Set-UprCachedFindings $cacheKey $findings }
            & $log "Parsed $($findings.Count) finding(s)." 'ok'
        }
    }
    if ($findings.Count -eq 0) {
        & $log "No findings parsed from the report." 'warn'
        return @{ rows=@(); summary=@{ total=0 } }
    }

    # =====================================================================
    #  report-findings -- parse-only, one row per finding (no host scanning)
    # =====================================================================
    if ($ActionId -eq 'report-findings') {
        $rows = New-Object System.Collections.ArrayList
        $hiddenUpdate = 0
        $search = [string]$Params['search']
        $sorted = @($findings) | Sort-Object @{e='Category'}, @{e='Severity'; descending=$true}, @{e='PluginName'}
        foreach ($f in $sorted) {
            # Free-text search over Plugin / Plugin Name / Category (mirrors the desktop Findings search box).
            if (-not [string]::IsNullOrWhiteSpace($search)) {
                if ("$($f.Plugin) $($f.PluginName) $($f.Category)" -notlike "*$search*") { continue }
            }
            $isOs = ($f.Category -eq 'OS') -or (Test-IsOsFinding $catalog $f.PluginName)
            $prof = Get-UprProfileForFinding $catalog $f

            # Hide update-class findings (profile carries an Updater) -- count them.
            if (-not $isOs -and $null -ne $prof -and -not [string]::IsNullOrWhiteSpace([string]$prof.Updater)) {
                $hiddenUpdate++
                continue
            }

            # Host count respects the host-class filter.
            $hostCount = 0
            foreach ($h in @($f.Hosts)) { if (Test-UprHostClassMatch $h $hostClass) { $hostCount++ } }
            # When a host-class filter is active, hide findings whose entire host set fell outside.
            if ($hostClass -ne 'All' -and $hostCount -eq 0) { continue }

            $decision = if ($isOs) { 'OS (out of scope)' }
                        elseif ($null -ne $prof -and ($prof.Proven -eq $true -or -not [string]::IsNullOrWhiteSpace([string]$prof.VersionMaxExclusive))) { 'Uninstall (scan to confirm)' }
                        elseif ($null -ne $prof) { 'Review' }
                        else { 'No catalog match' }

            $row = @{
                _rk="$($f.Plugin)|$($f.PluginName)"
                Plugin     = [string]$f.Plugin
                Category   = [string]$f.Category
                PluginName = [string]$f.PluginName
                Severity   = [string]$f.Severity
                Hosts      = $hostCount
                Decision   = $decision
            }
            [void]$rows.Add($row)
            & $send (@{ type='row' } + $row)
            # Audit honesty: report-findings is a parse-only operation that contacts
            # NO host -- do not emit a TouchHost audit (nothing was touched). The
            # parsed findings are surfaced as table rows + a status summary only.
        }
        if ($hiddenUpdate -gt 0) {
            & $log "$hiddenUpdate update-class finding(s) hidden -- remediate with WPT App Updater." 'info'
        }
        & $send @{ type='status'; text="Done. $($rows.Count) finding(s) shown ($hiddenUpdate update-class hidden)." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count; hiddenUpdate=$hiddenUpdate } }
    }

    # =====================================================================
    #  os-findings -- parse-only, ONE ROW PER AFFECTED HOST of each OS finding
    #  (network identifiers for the rebuild team). Mirrors the desktop OS tab
    #  (Refresh-OsTab): never scanned, never uninstalled; respects host-class.
    # =====================================================================
    if ($ActionId -eq 'os-findings') {
        $rows = New-Object System.Collections.ArrayList
        $sorted = @($findings) | Sort-Object @{e='Severity'; descending=$true}, @{e='PluginName'}
        foreach ($f in $sorted) {
            if (-not (($f.Category -eq 'OS') -or (Test-IsOsFinding $catalog $f.PluginName))) { continue }
            $emitted = 0
            foreach ($h in @($f.Hosts)) {
                if (-not (Test-UprHostClassMatch $h $hostClass)) { continue }
                $row = @{
                    _rk        = "$($f.Plugin)|$($f.PluginName)|$($h.IPAddress)|$($h.NetBIOSName)|$($h.DNSName)"
                    Plugin     = [string]$f.Plugin
                    PluginName = [string]$f.PluginName
                    Severity   = [string]$f.Severity
                    IP         = [string]$h.IPAddress
                    NetBIOS    = [string]$h.NetBIOSName
                    DNS        = [string]$h.DNSName
                    'OS CPE'   = [string]$h.OSCpe
                    MAC        = [string]$h.MAC
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                $emitted++
            }
            # No per-finding audit: os-findings is a pure report parse that contacts
            # NO host, so a TouchHost audit here would be dishonest (matches report-findings).
        }
        if ($rows.Count -eq 0) {
            & $log "No OS-level findings in this report (after host-class filter '$hostClass')." 'info'
        }
        & $send @{ type='status'; text="Done. $($rows.Count) OS host row(s) across the report's OS findings." }
        return @{ rows=@($rows); summary=@{ total=$rows.Count } }
    }

    # =====================================================================
    #  report-scan / report-uninstall -- host-centric fan-out
    # =====================================================================
    $doUninstall = ($ActionId -eq 'report-uninstall')
    $dryRun = $true
    if ($Params.ContainsKey('dryrun')) {
        $dv = $Params['dryrun']
        if ($dv -is [bool]) { $dryRun = $dv } else { $dryRun = -not (("$dv").Trim() -match '^(?i:false|0|no|off)$') }
    }
    $threads = Get-UprThreadCount $Params 16

    # ---- Operator selection (report-uninstall only) --------------------------
    # The view sends the operator's CHECKED rows so the engine removes EXACTLY
    # those host+product pairs instead of re-scanning and removing every proven
    # candidate. Both params are newline-delimited; per-row key is
    # Host|Product|Version|PSChildName. Absent => legacy behavior (all proven).
    $selectHosts = $null
    $selectKeys  = $null
    if ($doUninstall) {
        $rawHosts = [string]$Params['selecthosts']
        $rawKeys  = [string]$Params['selectkeys']
        if (-not [string]::IsNullOrWhiteSpace($rawHosts)) {
            $selectHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($hLine in ($rawHosts -split "`r?`n")) { $t = ([string]$hLine).Trim(); if ($t) { [void]$selectHosts.Add($t) } }
        }
        if (-not [string]::IsNullOrWhiteSpace($rawKeys)) {
            $selectKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($kLine in ($rawKeys -split "`r?`n")) { $t = ([string]$kLine).Trim(); if ($t) { [void]$selectKeys.Add($t) } }
        }
        if ($selectKeys -and $selectKeys.Count -gt 0) {
            $selHostCount = if ($selectHosts) { $selectHosts.Count } else { 0 }
            & $log "Honoring operator selection: $($selectKeys.Count) checked row(s) across $selHostCount host(s) -- only those proven-EOL products are removed." 'info'
        } else {
            if (-not $dryRun) {
                # Live uninstall with NO operator selection: REFUSE. A non-UI or stale
                # client that omits the checked-row set must not silently trigger a
                # remove-all of every proven-EOL candidate. Dry-run may still preview-all.
                $refuseMsg = 'Refused: no rows selected - select the apps to uninstall (live uninstall requires an explicit selection).'
                & $log $refuseMsg 'error'
                & $send @{ type='status'; text=$refuseMsg }
                return @{ rows=@(); summary=@{ total=0; error=$refuseMsg } }
            }
            & $log "No row selection supplied -- dry-run will preview every proven-EOL candidate on all actionable hosts." 'warn'
        }
    }

    # Restrict the uninstall re-scan to the selected hosts (Scan is unaffected -> $null).
    $targetFilter = $null
    if ($doUninstall) { $targetFilter = $selectHosts }
    $removeSet = $null
    if ($doUninstall) { $removeSet = $selectKeys }

    $hostJobs = @(Build-UprHostJobs -Findings $findings -Catalog $catalog -HostClass $hostClass -Log $log -TargetFilter $targetFilter)
    if ($hostJobs.Count -eq 0) {
        & $log "No actionable hosts after applying the host-class filter ('$hostClass'). OS findings and update-class findings are excluded." 'warn'
        return @{ rows=@(); summary=@{ total=0 } }
    }
    & $log "Built $($hostJobs.Count) unique host target(s) across actionable findings." 'info'
    if ($doUninstall) {
        & $log "Uninstall mode: dryRun=$dryRun. Only proven-EOL (Uninstall) candidates are removed; Review/Tanium are skipped." $(if ($dryRun) { 'info' } else { 'warn' })
    }

    # EmitRows: turn one worker result into grid rows (shared with manual mode).
    # One row per matched candidate; unreachable -> 'Unreachable'; reachable w/ no
    # match -> 'No match'; worker/scan error -> a row carrying the error.
    $emitRows = New-UprEmitRows -DoUninstall $doUninstall -DryRun $dryRun -Send $send

    $auditAction = if ($doUninstall) { 'VulnPatched' } else { 'TouchHost' }
    # Per-host watchdog only on the read-only scan (a long run there = WMI/CIM hang);
    # an uninstall pass legitimately runs long, so leave it off (0) for that.
    $perHostTimeout = if ($doUninstall) { 0 } else { 300 }

    return Invoke-UprFanOut -HostJobs $hostJobs -Threads $threads -Work $UprWorkerBlock `
        -Credential $Credential -Auth $auth -DoUninstall $doUninstall -DryRun $dryRun `
        -EmitRows $emitRows -AuditAction $auditAction -Send $send -ActionId $ActionId -CancelCheck $cancelCheck -PerHostTimeoutSeconds $perHostTimeout `
        -EmitHostAudit (-not $doUninstall) -RemoveSet $removeSet
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
