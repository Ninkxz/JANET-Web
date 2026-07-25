# =============================================================================
#  Upr.RelaxedAttribution.Tests.ps1 - Pester 3.4 for the relaxed (pasted-PDF)
#  parser's host attribution (audit 2026-07-24).
#
#  The relaxed parser is the LEAST exact ingestion mode: a PDF-viewer copy-paste
#  loses the per-plugin host breakdown, so it attaches EVERY IP in a section's
#  hosts block to EVERY catalog-matched finding in that section. It nevertheless
#  emitted finding objects with NO HostAttribution member, so report-findings /
#  os-findings read $null, labelled the rows ATTRIB='exact' and printed a bare
#  host count with no '~' marker - the least trustworthy input advertising the
#  highest confidence. These tests FAIL on that old behaviour.
#
#  Run:  Invoke-Pester -Path .\tests\Upr.RelaxedAttribution.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

# A PDF-viewer copy-paste: section anchors survive, the table columns do not.
$script:MultiText = @"
UNCLASSIFIED
Unsupported Software Count
Microsoft Office Unsupported Version Detection Critical 3
Adobe Flash Player SEoL High 2
Unsupported Software Affected Hosts
10.1.2.3 10.1.2.4 10.1.2.5
"@

# Same shape, but the section carries exactly ONE catalog-matched finding.
$script:SingleText = @"
UNCLASSIFIED
Unsupported Software Count
Adobe Flash Player SEoL High 2
Unsupported Software Affected Hosts
10.9.9.1 10.9.9.2
"@

function Get-RelaxedFindings([string]$Text) {
    @(& $script:Mod {
        param($t)
        $cat = Get-UprCatalogDefault
        Parse-ReportTextRelaxed -Text $t -Catalog $cat -Log $null
    } $Text)
}

# Mirror of the row-emit expressions in Invoke-JanetToolAction
# (report-findings Hosts/Exact, os-findings Exact).
function Get-HostsCell($Finding, [int]$HostCount) {
    if ([string]$Finding.HostAttribution -eq 'section-approximate') { "~$HostCount" } else { "$HostCount" }
}
function Get-ExactCell($Finding) {
    if ([string]$Finding.HostAttribution -eq 'section-approximate') { 'section-approx' } else { 'exact' }
}

Describe 'relaxed (pasted-PDF) parser tags its host attribution (audit 2026-07-24)' {

    It 'parses the linearized text into catalog-matched findings' {
        # NOTE: re-wrap with @() at every use site - Pester 3.4 unwraps a
        # single-element array returned from a helper function.
        $f = @(Get-RelaxedFindings $script:MultiText)
        (@($f).Count -ge 2) | Should Be $true
    }

    It 'sets HostAttribution on EVERY finding it emits (was absent -> read as exact)' {
        $f = @(Get-RelaxedFindings $script:MultiText)
        foreach ($x in @($f)) { [string]$x.HostAttribution | Should Be 'section-approximate' }
    }

    It 'tags a SINGLE-finding section too (this mode is approximate by construction)' {
        $f = @(Get-RelaxedFindings $script:SingleText)
        @($f).Count | Should Be 1
        [string]@($f)[0].HostAttribution | Should Be 'section-approximate'
    }

    It 'attaches every section IP to the finding (the reason it is approximate)' {
        $f = @(Get-RelaxedFindings $script:SingleText)
        @(@($f)[0].Hosts).Count | Should Be 2
    }

    It 'renders ATTRIB as section-approx, never exact' {
        $f = @(Get-RelaxedFindings $script:MultiText)
        foreach ($x in @($f)) { (Get-ExactCell $x) | Should Be 'section-approx' }
    }

    It 'marks the host count with the ~ upper-bound marker' {
        $f = @(Get-RelaxedFindings $script:MultiText)
        (Get-HostsCell @($f)[0] 3) | Should Be '~3'
    }
}
