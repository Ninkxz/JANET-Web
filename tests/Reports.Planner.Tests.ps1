# =============================================================================
#  Reports.Planner.Tests.ps1 - Pester 3.4 tests for the per-host remediation
#  planner (remediation-plan action). Synthetic findings; asserts per-host
#  grouping, routable/manual split, KEV counting, worst-first ordering, and
#  that Patched findings are excluded. Read-only; no host contact.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'remediation-plan per-host work queue (Phase 3)' {

    $rows = & $script:Mod {
        $script:AcasFindings = @(
            # hostA: 1 Critical KEV Chrome (routable), 1 Apache (manual) + 1 Patched (excluded)
            [pscustomobject]@{ Hostname='hostA'; PluginID='1'; VulnName='Google Chrome flaw'; Severity='Critical'; CVE='CVE-2024-1'; Category='Chrome'; Status='Open'; Solution='Update Chrome'; InKEV=$true;  KevCves='CVE-2024-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hostA'; PluginID='2'; VulnName='Apache Struts';        Severity='High';     CVE='';          Category='Apache'; Status='Open'; Solution='';            InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hostA'; PluginID='3'; VulnName='Old thing';            Severity='Low';      CVE='';          Category='Chrome'; Status='Patched'; Solution='';         InKEV=$false; KevCves=''; IAVA='' }
            # hostB: 1 Medium Defender (routable), no KEV
            [pscustomobject]@{ Hostname='hostB'; PluginID='4'; VulnName='Windows Defender out of date'; Severity='Medium'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
        )
        $captured = New-Object System.Collections.ArrayList
        [void](Invoke-JanetToolAction -ActionId 'remediation-plan' -Params @{} -Emit { param($e) if ($e['type'] -eq 'row') { [void]$captured.Add($e) } })
        ,$captured
    }

    It 'emits one row per affected host (2 hosts)' {
        $rows.Count | Should Be 2
    }

    It 'orders worst-first: the KEV/Critical host leads' {
        $rows[0]['Host'] | Should Be 'hostA'
        [int]$rows[0]['KEV'] | Should Be 1
    }

    It 'excludes Patched findings from the open count' {
        # hostA has 3 findings but 1 is Patched -> 2 open.
        [int]($rows | Where-Object { $_['Host'] -eq 'hostA' } | ForEach-Object { $_['Findings'] }) | Should Be 2
    }

    It 'splits routable vs manual (hostA: Chrome routable, Apache manual)' {
        $a = $rows | Where-Object { $_['Host'] -eq 'hostA' }
        [int]$a['Routable'] | Should Be 1
        [int]$a['Manual']   | Should Be 1
        $a['Plan'] | Should Match 'acas: Google Chrome'
        $a['Plan'] | Should Match 'manual: Apache'
    }

    It 'promotes a Defender finding (by vuln name) to the routable Defender route' {
        $b = $rows | Where-Object { $_['Host'] -eq 'hostB' }
        [int]$b['Routable'] | Should Be 1
        $b['Plan'] | Should Match 'Windows Defender'
    }
}
