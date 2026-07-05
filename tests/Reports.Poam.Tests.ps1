# =============================================================================
#  Reports.Poam.Tests.ps1 - Pester 3.4 tests for the eMASS POA&M export
#  (export-poam action). Drives the action with synthetic in-session findings
#  and asserts the CSV shape, DISA CAT mapping, open-only filtering, and the
#  formula-injection guard. No file I/O, no host, no ImportExcel.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'export-poam eMASS POA&M CSV (audit Phase 3)' {

    $result = & $script:Mod {
        # Synthetic findings covering: Critical->CAT I, High->CAT II, Medium->CAT III,
        # a Patched finding (must be EXCLUDED), and a formula-injection VulnName.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hostA'; PluginID='1001'; VulnName='Critical thing'; Severity='Critical'; CVE='CVE-2024-0001'; Category='Vuln'; Status='Open'; Solution='Patch it'; InKEV=$false; KevCves=''; IAVA='2024-A-0001'; FirstSeen='' }
            [pscustomobject]@{ Hostname='hostB'; PluginID='1002'; VulnName='High thing'; Severity='High'; CVE='CVE-2024-0002'; Category='Vuln'; Status='Open'; Solution='Upgrade'; InKEV=$true; KevCves='CVE-2024-0002'; IAVA=''; FirstSeen='' }
            [pscustomobject]@{ Hostname='hostC'; PluginID='1003'; VulnName='Medium thing'; Severity='Medium'; CVE=''; Category='Vuln'; Status='Open'; Solution='Config'; InKEV=$false; KevCves=''; IAVA=''; FirstSeen='' }
            [pscustomobject]@{ Hostname='hostD'; PluginID='1004'; VulnName='Already fixed'; Severity='Critical'; CVE=''; Category='Vuln'; Status='Patched'; Solution=''; InKEV=$false; KevCves=''; IAVA=''; FirstSeen='' }
            [pscustomobject]@{ Hostname='hostE'; PluginID='1005'; VulnName='=cmd|calc'; Severity='Low'; CVE=''; Category='Vuln'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA=''; FirstSeen='' }
        )
        Invoke-JanetToolAction -ActionId 'export-poam' -Params @{} -Emit { param($e) }
    }
    $csv = $result.summary.csv
    # Parse the CSV back for structural assertions.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("poamtest_" + [guid]::NewGuid().ToString('N') + ".csv")
    [System.IO.File]::WriteAllText($tmp, $csv, (New-Object System.Text.UTF8Encoding($false)))
    $rows = @(Import-Csv $tmp)
    [System.IO.File]::Delete($tmp)

    It 'excludes Patched findings (4 open of 5 total)' {
        $result.summary.total | Should Be 4
        $rows.Count | Should Be 4
    }

    It 'emits the 26-column eMASS POA&M template' {
        ($rows[0].PSObject.Properties.Name).Count | Should Be 26
        $rows[0].PSObject.Properties.Name -contains 'Scheduled Completion Date' | Should Be $true
        $rows[0].PSObject.Properties.Name -contains 'CCI' | Should Be $true
    }

    It 'maps ACAS severity to DISA CAT (Critical=CAT I, High=CAT II, Med/Low=CAT III)' {
        ($rows | Where-Object { $_.Host -eq 'hostA' }).'Raw Severity' | Should Be 'CAT I'
        ($rows | Where-Object { $_.Host -eq 'hostB' }).'Raw Severity' | Should Be 'CAT II'
        ($rows | Where-Object { $_.Host -eq 'hostC' }).'Raw Severity' | Should Be 'CAT III'
        ($rows | Where-Object { $_.Host -eq 'hostE' }).'Raw Severity' | Should Be 'CAT III'
    }

    It 'counts KEV findings' {
        $result.summary.kev | Should Be 1
    }

    It 'carries the scanner Solution into Recommendations' {
        ($rows | Where-Object { $_.Host -eq 'hostA' }).Recommendations | Should Be 'Patch it'
    }

    It 'neutralizes a formula-injection VulnName in the CSV text' {
        # The raw CSV must not contain a bare cell starting with =cmd (guard prefixes ').
        ($csv -match "(^|,)=cmd") | Should Be $false
        ($csv -match "'=cmd\|calc" ) | Should Be $true
    }
}
