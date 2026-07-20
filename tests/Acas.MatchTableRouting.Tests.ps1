# =============================================================================
#  Acas.MatchTableRouting.Tests.ps1 - Pester 3.4 for the acas remediation
#  ROUTING (Get-AcasVulnGroups over Get-AcasProfileMatchTable). The match table
#  turns an ACAS finding's plugin name into the remediation profile(s) the
#  auto-patch flow will run. A MIS-ROUTE is worse than a miscount - it sends the
#  WRONG fix (or a no-op) to a real vulnerability. The individual profiles are
#  tested elsewhere; the ROUTING itself (first-match-wins + the look-alike
#  EXCLUSIONS that stop a mis-route) was untested until now.
#
#  The exclusions are the safety-critical part: without them 'Microsoft Edge
#  WebView2' would route to the Edge browser updater, 'Symantec Endpoint
#  Protection' to the Windows Defender updater, 'Chrome Remote Desktop' to the
#  Chrome updater, and 'Access Database Engine' to the M365 updater - each a
#  wrong fix on a real finding. A future match-table edit (reorder, drop an
#  Exclude) that reintroduces a mis-route now fails here.
#
#  Read-only: synthetic findings (PluginName only) through the module-scope
#  router; no host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.MatchTableRouting.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-Route([string]$PluginName) {
    $g = & $m {
        param($pn)
        $f = @([pscustomobject]@{ PluginName = $pn; Hostname = 'H1'; Severity = 'High'; CVE = '' })
        @(Get-AcasVulnGroups -Findings $f)[0]
    } $PluginName
    if ($null -eq $g) { return @{ Category = '(none)'; Profiles = @() } }
    @{ Category = [string]$g.Category; Profiles = @($g.ProfileNames) }
}

Describe 'acas match-table routing - POSITIVE (real findings route to the right profile)' {
    It 'Google Chrome -> the Chrome updater profile' {
        $r = Get-Route 'Google Chrome (Multiple Remote Code Execution Vulnerabilities)'
        ($r.Profiles -contains 'Google Chrome - Update') | Should Be $true
    }
    It 'Microsoft Excel -> an M365 updater profile' {
        $r = Get-Route 'Microsoft Excel Products Multiple Vulnerabilities'
        ($r.Profiles -contains 'Microsoft 365 - Force Update') | Should Be $true
    }
    It 'Windows Unquoted Service Path -> the Unquoted remediation (specific rule wins over generic)' {
        $r = Get-Route 'Microsoft Windows Unquoted Service Path Enumeration'
        ($r.Profiles -contains 'Windows Unquoted Service Path - Remediate') | Should Be $true
    }
    It 'a plain Windows Defender vuln -> the Defender definitions profile' {
        $r = Get-Route 'Microsoft Windows Defender Elevation of Privilege Vulnerability'
        ($r.Profiles -contains 'Windows Defender - Update Definitions') | Should Be $true
    }
}

Describe 'acas match-table routing - EXCLUSIONS (look-alikes never mis-route to the wrong fix)' {
    It 'Microsoft Edge WebView2 does NOT route to the Edge browser updater' {
        $r = Get-Route 'Microsoft Edge WebView2 Runtime Multiple Vulnerabilities'
        ($r.Profiles -contains 'Microsoft Edge - Update') | Should Be $false
    }
    It 'Symantec Endpoint Protection does NOT route to Windows Defender' {
        $r = Get-Route 'Symantec Endpoint Protection Multiple Vulnerabilities'
        ($r.Profiles -contains 'Windows Defender - Update Definitions') | Should Be $false
    }
    It 'Google Chrome Remote Desktop does NOT route to the Chrome updater' {
        $r = Get-Route 'Google Chrome Remote Desktop Host Multiple Vulnerabilities'
        ($r.Profiles -contains 'Google Chrome - Update') | Should Be $false
    }
    It 'Microsoft Access Database Engine does NOT route to the M365 updater' {
        $r = Get-Route 'Microsoft Access Database Engine 2016 Multiple Vulnerabilities'
        (@($r.Profiles) | Where-Object { $_ -like 'Microsoft 365*' }).Count | Should Be 0
    }
    It 'LibreOffice does NOT route to the M365 updater' {
        $r = Get-Route 'LibreOffice < 7.6 Multiple Vulnerabilities'
        (@($r.Profiles) | Where-Object { $_ -like 'Microsoft 365*' }).Count | Should Be 0
    }
}

Describe 'acas match-table structure - the safety-critical exclusions are present' {
    $table = & $m { Get-AcasProfileMatchTable }
    It 'the Edge rule excludes WebView (and EdgeTransport/EdgeUpdate)' {
        $edge = @($table | Where-Object { $_.Keywords -contains 'Microsoft Edge' })[0]
        ($edge.Exclude -contains 'WebView') | Should Be $true
    }
    It 'the Defender rule excludes the third-party AV vendors' {
        $def = @($table | Where-Object { $_.Keywords -contains 'Windows Defender' })[0]
        ($def.Exclude -contains 'Symantec') | Should Be $true
        ($def.Exclude -contains 'CrowdStrike') | Should Be $true
    }
    It 'the Office rule excludes Access Database Engine + LibreOffice' {
        $off = @($table | Where-Object { $_.Keywords -contains 'Microsoft Office' })[0]
        ($off.Exclude -contains 'Access Database Engine') | Should Be $true
        ($off.Exclude -contains 'LibreOffice') | Should Be $true
    }
    It 'the Chrome rule excludes Remote Desktop' {
        $chr = @($table | Where-Object { $_.Keywords -contains 'Google Chrome' })[0]
        ($chr.Exclude -contains 'Remote Desktop') | Should Be $true
    }
}
