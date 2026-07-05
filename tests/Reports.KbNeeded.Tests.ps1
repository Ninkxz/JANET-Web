# =============================================================================
#  Reports.KbNeeded.Tests.ps1 - Pester 3.4 tests for kb-needed: extract the exact
#  KB ids the loaded Tenable findings name (plugin + Solution text), roll up by
#  KB with supersedence ordering, and produce the per-host / copy lists.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'kb-needed: KB extraction + supersedence rollup' {

    It 'Get-ReportsKbsFromText pulls distinct KB ids from free text (and none when absent)' {
        $two = & $script:Mod { @(Get-ReportsKbsFromText 'Apply KB5040442 and cumulative KB5040437.') }
        $two.Count | Should Be 2
        ($two -contains 'KB5040442') | Should Be $true
        $none = & $script:Mod { @(Get-ReportsKbsFromText 'Upgrade Google Chrome to 148 or later.') }
        $none.Count | Should Be 0
    }

    $result = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='1'; VulnName='Win cumulative'; Severity='Critical'; CVE='CVE-1'; Category='KB Patch'; Status='Open';    Solution='Apply KB5040442.'; InKEV=$true;  KevCves='CVE-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Win cumulative'; Severity='High';     CVE='';      Category='KB Patch'; Status='Open';    Solution='Apply KB5040442 and KB5040437.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hC'; PluginID='3'; VulnName='Chrome';         Severity='High';     CVE='';      Category='Chrome';   Status='Open';    Solution='Upgrade to 148.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hD'; PluginID='4'; VulnName='Old fixed';      Severity='Low';      CVE='';      Category='KB Patch'; Status='Patched'; Solution='Apply KB5000000.'; InKEV=$false; KevCves=''; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'kb-needed' -Params @{} -Emit { param($e) }
    }

    It 'extracts the distinct KBs and counts findings with/without a KB (excludes Patched)' {
        [int]$result.summary.total          | Should Be 2   # KB5040442, KB5040437 (Patched KB excluded)
        [int]$result.summary.findingsWithKb | Should Be 2   # hA, hB
        [int]$result.summary.findingsNoKb   | Should Be 1   # hC (Chrome, no KB)
        [int]$result.summary.hosts          | Should Be 2   # hA, hB
    }

    It 'flags the KEV-carrying KB and orders it first (supersedence: KEV, then most hosts)' {
        [int]$result.summary.kevKbs | Should Be 1
        # First KB in the list is KB5040442 (KEV via hA, and on 2 hosts).
        (($result.summary.kbList -split "`n")[0]) | Should Be 'KB5040442'
        @($result.rows)[0].KEV | Should Be 'KEV'
        [int](@($result.rows)[0].Hosts) | Should Be 2
    }

    It 'emits a per-host Host,KB list (feed WPT KB Installer)' {
        $result.summary.perHostCsv | Should Match 'Host,KB'
        $result.summary.perHostCsv | Should Match 'hA,KB5040442'
    }
}
