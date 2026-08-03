# =============================================================================
#  Reports.RemediationPlanHostKey.Tests.ps1 - Pester 3.4 for the host-key
#  normalization sweep completion in Build-RemediationPlan (the operator-facing
#  Remediation Plan). loop13 normalized the adjacent "Other" per-plugin host
#  count (Get-ReportsAuditHostKey) but left the MAIN per-(host,app) bucket + the
#  per-app summary host count keyed on the RAW hostname - so one physical box
#  exported as WEB01 in one row and web01.dom in another produced TWO buckets and
#  the per-app summary counted it as TWO hosts. loop20 folds the bucket key, the
#  summary count, and the status-setter key on the normalized audit key so a
#  short+FQDN pair of one host collapses to ONE plan row and ONE host in the
#  summary (agreeing with CORA and the Other-group count beside it).
#
#  The FQDN variant is seeded FIRST on purpose: a raw short name (WEB01) already
#  equals its own normalized key, so only a first-seen FQDN row exercises the
#  fold (raw 'web01.corp.mil|Chrome' vs normalized 'WEB01|Chrome').
#
#  Drives the real Build-RemediationPlan over seeded $script:AcasFindings /
#  $script:RemediationStatus in module scope. No host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.RemediationPlanHostKey.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

function New-ChromeFinding([string]$HostName, [string]$PluginId) {
    [pscustomobject]@{
        Hostname = $HostName; PluginID = $PluginId; VulnName = 'Google Chrome Multiple Vulnerabilities'
        Severity = 'High'; Solution = 'Upgrade to Google Chrome 120'; Category = 'Chrome'
        CVE = ''; InKEV = $false; IP = ''
    }
}

# Build the seed set in TEST scope (the module-scope block can't see the test-scope
# helper), then pass the findings + status hashtable into Build-RemediationPlan.
function Invoke-Plan([System.Collections.ArrayList]$Findings, [hashtable]$Status) {
    & $script:Mod {
        param($f, $st)
        $script:AcasFindings = $f
        $script:RemediationStatus = $st
        Build-RemediationPlan
    } $Findings $Status
}
function New-FindingList([object[]]$Findings) {
    $l = New-Object System.Collections.ArrayList
    foreach ($f in $Findings) { [void]$l.Add($f) }
    return ,$l
}

Describe 'Build-RemediationPlan host-key fold - one physical host as short+FQDN counts once' {
    It 'a short+FQDN pair of one host collapses to ONE Chrome row and ONE host in the summary' {
        $findings = New-FindingList @(
            (New-ChromeFinding 'web01.corp.mil' '111'),   # FQDN first
            (New-ChromeFinding 'WEB01'          '222')    # short second
        )
        $plan = Invoke-Plan $findings @{}
        $plan.Summary.Chrome | Should Be 1
        @($plan.Rows | Where-Object { $_.App -eq 'Chrome' }).Count | Should Be 1
    }

    It 'two DISTINCT hosts still count as two (the fold does not over-merge)' {
        $findings = New-FindingList @(
            (New-ChromeFinding 'WEB01' '111'),
            (New-ChromeFinding 'APP02' '222')
        )
        $plan = Invoke-Plan $findings @{}
        $plan.Summary.Chrome | Should Be 2
    }

    It 'a status keyed on the normalized host key is read back onto the folded row' {
        # Seed status under the NORMALIZED key (WEB01|Chrome). The plan's first-seen
        # host is the FQDN row, so this only matches if the bucket/reader key is
        # normalized - proving the read side folds (and, by symmetry, the setter must
        # write the same normalized key).
        $findings = New-FindingList @(
            (New-ChromeFinding 'web01.corp.mil' '111'),
            (New-ChromeFinding 'WEB01'          '222')
        )
        $plan = Invoke-Plan $findings @{ 'WEB01|Chrome' = @{ Status='Pushed'; By='tester'; Date='2026-07-21 00:00'; Notes='' } }
        $chrome = @($plan.Rows | Where-Object { $_.App -eq 'Chrome' })
        @($chrome).Count | Should Be 1
        $chrome[0].Status | Should Be 'Pushed'
    }
}

Describe 'reports - manifest exact version pin (newest bump = loop 2026-08-03 P1: scan-compare NOT SCANNED bucket)' {
    It 'reports is at v2.16.0' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '2.16.0'
    }
}
