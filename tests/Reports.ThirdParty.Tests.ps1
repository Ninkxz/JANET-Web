# =============================================================================
#  Reports.ThirdParty.Tests.ps1 - Pester 3.4 tests for thirdparty-catalog: roll
#  the NON-KB (third-party / version-upgrade) findings up by PRODUCT, excluding
#  the KB-naming and Patched findings, ranked KEV-first then most hosts. Routes
#  reuse the shared Categorize-Finding + RemediationRouteMap mapping.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'thirdparty-catalog: non-KB product rollup' {

    It 'Get-ReportsThirdPartyProduct names known products and returns null otherwise' {
        (& $script:Mod { Get-ReportsThirdPartyProduct 'Google Chrome < 148 Multiple Vulnerabilities' }) | Should Be 'Google Chrome'
        (& $script:Mod { Get-ReportsThirdPartyProduct 'Adobe Acrobat < 24.002' })                        | Should Be 'Adobe Acrobat/Reader'
        (& $script:Mod { Get-ReportsThirdPartyProduct 'Some unknown appliance firmware' })               | Should BeNullOrEmpty
    }

    $result = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='11'; VulnName='Google Chrome < 148 Multiple Vulnerabilities'; Severity='Critical'; CVE='CVE-1'; Category='Chrome';        Status='Open';    Solution='Upgrade to Google Chrome 148 or later.'; InKEV=$true;  KevCves='CVE-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hB'; PluginID='12'; VulnName='Google Chrome < 148 Multiple Vulnerabilities'; Severity='High';     CVE='';      Category='Chrome';        Status='Open';    Solution='Upgrade to Google Chrome 148 or later.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hC'; PluginID='13'; VulnName='Google Chrome < 148 Multiple Vulnerabilities'; Severity='Medium';   CVE='';      Category='Chrome';        Status='Open';    Solution='Upgrade to Google Chrome 148 or later.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hD'; PluginID='14'; VulnName='Adobe Acrobat < 24.002 Multiple Vulnerabilities'; Severity='High'; CVE='';      Category='NOT OUR PATCH'; Status='Open';    Solution='Upgrade to Adobe Acrobat 24.002.20933 or later.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hG'; PluginID='15'; VulnName='7-Zip < 24.00';                                Severity='Medium';   CVE='';      Category='Other';         Status='Open';    Solution='Upgrade to 7-Zip 24.00 or later.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hE'; PluginID='16'; VulnName='Windows cumulative update';                    Severity='Critical'; CVE='';      Category='KB Patch';      Status='Open';    Solution='Apply KB5040442.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hF'; PluginID='17'; VulnName='Google Chrome (old, fixed)';                   Severity='High';     CVE='';      Category='Chrome';        Status='Patched'; Solution='Upgrade to Google Chrome 148 or later.'; InKEV=$false; KevCves=''; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'thirdparty-catalog' -Params @{} -Emit { param($e) }
    }

    It 'rolls up distinct third-party products, excluding KB-only and Patched findings' {
        [int]$result.summary.total              | Should Be 3   # Chrome, Adobe, 7-Zip (KB-only + Patched excluded)
        [int]$result.summary.thirdPartyFindings | Should Be 5   # 3 Chrome + 1 Adobe + 1 7-Zip
    }

    It 'counts distinct affected hosts across the catalog' {
        [int]$result.summary.hosts | Should Be 5   # hA hB hC hD hG (hE=KB-only, hF=Patched excluded)
    }

    It 'flags KEV products and sorts the KEV product first (then most hosts)' {
        [int]$result.summary.kevProducts | Should Be 1
        @($result.rows)[0].Product      | Should Be 'Google Chrome'
        @($result.rows)[0].KEV          | Should Be 'KEV'
        [int](@($result.rows)[0].Hosts) | Should Be 3
    }

    It 'routes products via the shared Router mapping (Chrome->acas, Adobe->upr) and leaves unmapped products manual' {
        $chrome = @($result.rows | Where-Object { $_.Product -eq 'Google Chrome' })[0]
        $chrome.Route | Should Match 'acas'
        $adobe = @($result.rows | Where-Object { $_.Product -eq 'Adobe Acrobat/Reader' })[0]
        $adobe.Route | Should Match 'upr'
        $sevenzip = @($result.rows | Where-Object { $_.Product -eq '7-Zip' })[0]
        $sevenzip.Route | Should Match 'manual'
        [int]$result.summary.routable | Should Be 2   # Chrome (acas) + Adobe (upr)
        [int]$result.summary.manual   | Should Be 1   # 7-Zip (no route)
    }
}
