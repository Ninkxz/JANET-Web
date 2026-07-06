# =============================================================================
#  Reports.Routing.Tests.ps1 - Pester 3.4 tests for the Categorize-Finding
#  buckets + RemediationRouteMap routes wired this session:
#    - Apache / Log4j            -> acas run-vulnerability (Log4j jar-replace profile)
#    - Intel BHI / spec-exec     -> wpt registry-key-apply (reg-catalog key 'BHI')
#    - untrusted / self-signed   -> tracked exception (no local fix / POA&M)
#  Plus a Chrome regression guard. Asserts on RETURN VALUES only; no host contact.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'Categorize-Finding + RemediationRouteMap routing' {

    It 'routes an Apache Log4j finding to the ACAS Log4j jar-replace profile' {
        $r = & $script:Mod {
            $bucket = Categorize-Finding -VulnName 'Apache Log4j 2.x < 2.17.1 Remote Code Execution (Log4Shell)' -Solution 'Upgrade Apache Log4j to a supported version.' -PluginID '156103'
            $route  = $script:RemediationRouteMap[$bucket]
            [pscustomobject]@{ Bucket=$bucket; ToolId=$route.ToolId; ActionId=$route.ActionId; Profile=$route.Profile; Actionable=(Test-JanetWebRouteActionable $route) }
        }
        $r.Bucket     | Should Be 'Apache'
        $r.ToolId     | Should Be 'acas'
        $r.ActionId   | Should Be 'run-vulnerability'
        $r.Profile    | Should Be 'Apache Log4j - Replace Vulnerable Jars'
        $r.Actionable | Should Be $true
    }

    It 'the Log4j profile name exactly matches a defined ACAS update profile' {
        $exists = & (Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru) {
            [bool]($script:AcasUpdateProfiles.ContainsKey('Apache Log4j - Replace Vulnerable Jars'))
        }
        $exists | Should Be $true
    }

    It 'routes an Intel BHI (CVE-2022-0001) finding to the wpt BHI registry fix' {
        $r = & $script:Mod {
            $bucket = Categorize-Finding -VulnName 'Intel BHI (Branch History Injection) CVE-2022-0001' -Solution 'Apply the FeatureSettingsOverride registry mitigation.' -PluginID '000001'
            $route  = $script:RemediationRouteMap[$bucket]
            [pscustomobject]@{ Bucket=$bucket; ToolId=$route.ToolId; ActionId=$route.ActionId; Profile=$route.Profile; Actionable=(Test-JanetWebRouteActionable $route) }
        }
        $r.Bucket     | Should Be 'Speculative Execution'
        $r.ToolId     | Should Be 'wpt'
        $r.ActionId   | Should Be 'registry-key-apply'
        $r.Profile    | Should Be 'BHI'
        $r.Actionable | Should Be $true
    }

    It 'a wpt registry-key-apply route yields cvekey=BHI in the handoff params' {
        # Mirror the frontend handoff param build: for a registry-key-apply route the
        # route Profile becomes the cvekey param; acas routes keep Profile as profile.
        $cvekey = & $script:Mod {
            $route  = $script:RemediationRouteMap['Speculative Execution']
            if ($route.ActionId -eq 'registry-key-apply') { [string]$route.Profile } else { '' }
        }
        $cvekey | Should Be 'BHI'
    }

    It "the wpt reg-key catalog actually defines the 'BHI' key the route points at" {
        $hasBhi = & (Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru) {
            [bool]((Get-WptRegKeyCatalog).Contains('BHI'))
        }
        $hasBhi | Should Be $true
    }

    It 'buckets an untrusted / self-signed certificate finding as a tracked exception (no fix route)' {
        $r = & $script:Mod {
            $b1 = Categorize-Finding -VulnName 'SSL Certificate Cannot Be Trusted' -Solution 'Purchase or generate a proper SSL certificate for this service.' -PluginID '51192'
            $b2 = Categorize-Finding -VulnName 'SSL Self-Signed Certificate' -Solution 'Purchase or generate a proper SSL certificate.' -PluginID '57582'
            $route = $script:RemediationRouteMap[$b1]
            [pscustomobject]@{ B1=$b1; B2=$b2; IsException=$route.IsException; ToolId=$route.ToolId; Actionable=(Test-JanetWebRouteActionable $route); Action=$route.Action }
        }
        $r.B1          | Should Be 'Exception (no local fix)'
        $r.B2          | Should Be 'Exception (no local fix)'
        $r.IsException | Should Be $true
        $r.Actionable  | Should Be $false
        [string]::IsNullOrEmpty($r.ToolId) | Should Be $true
        $r.Action      | Should Match 'exception'
    }

    It 'regression: a Chrome finding still routes to the acas Chrome profile' {
        $r = & $script:Mod {
            $bucket = Categorize-Finding -VulnName 'Google Chrome < 148 Multiple Vulnerabilities' -Solution 'Upgrade to Google Chrome 148 or later.' -PluginID '200001'
            $route  = $script:RemediationRouteMap[$bucket]
            [pscustomobject]@{ Bucket=$bucket; ToolId=$route.ToolId; ActionId=$route.ActionId; Profile=$route.Profile }
        }
        $r.Bucket   | Should Be 'Chrome'
        $r.ToolId   | Should Be 'acas'
        $r.ActionId | Should Be 'run-vulnerability'
        $r.Profile  | Should Be 'Google Chrome - Update'
    }
}

Describe 'remediation-route surfaces routable / exception / manual counts' {
    $result = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='h1'; PluginID='1'; VulnName='Apache Log4j 2.x Log4Shell'; Severity='Critical'; CVE='CVE-2021-44228'; Category='Apache'; Status='Open'; Solution='Upgrade Log4j.'; InKEV=$true;  KevCves='CVE-2021-44228'; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='2'; VulnName='Intel BHI CVE-2022-0001'; Severity='High'; CVE='CVE-2022-0001'; Category='Speculative Execution'; Status='Open'; Solution='Registry mitigation.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h3'; PluginID='3'; VulnName='SSL Certificate Cannot Be Trusted'; Severity='Medium'; CVE=''; Category='Exception (no local fix)'; Status='Open'; Solution='Install a trusted cert.'; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h4'; PluginID='4'; VulnName='Some odd appliance thing'; Severity='Low'; CVE=''; Category='Other'; Status='Open'; Solution='n/a'; InKEV=$false; KevCves=''; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'remediation-route' -Params @{} -Emit { param($e) }
    }

    It 'counts Apache + BHI as routable, the cert as a tracked exception, and Other as manual' {
        [int]$result.summary.routableFindings  | Should Be 2
        [int]$result.summary.exceptionFindings | Should Be 1
        [int]$result.summary.manualFindings    | Should Be 1
    }

    It 'the Apache row carries the acas Log4j route and the BHI row the wpt reg-key route' {
        $apache = @($result.rows | Where-Object { $_.Bucket -eq 'Apache' })[0]
        $apache.Routable | Should Be $true
        $apache.ToolId   | Should Be 'acas'
        $apache.Profile  | Should Be 'Apache Log4j - Replace Vulnerable Jars'
        $bhi = @($result.rows | Where-Object { $_.Bucket -eq 'Speculative Execution' })[0]
        $bhi.Routable | Should Be $true
        $bhi.ToolId   | Should Be 'wpt'
        $bhi.ActionId | Should Be 'registry-key-apply'
        $bhi.Profile  | Should Be 'BHI'
    }

    It 'the exception row is NOT routable but is flagged an exception (not manual review)' {
        $exc = @($result.rows | Where-Object { $_.Bucket -eq 'Exception (no local fix)' })[0]
        $exc            | Should Not BeNullOrEmpty
        $exc.Routable   | Should Be $false
        $exc.IsException| Should Be $true
        $exc.Action     | Should Match 'exception'
    }
}
