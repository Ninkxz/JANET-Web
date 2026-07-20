# =============================================================================
#  Reports.WrongTemplateHint.Tests.ps1 - Pester 3.4 for the reports CSV import
#  wrong-template hint (Parse-AcasFile). Parse-AcasFile resolves the host + plugin
#  columns from the CSV header via Get-AcasColumnMap; when a CSV's headers don't
#  match the expected ACAS/Nessus template (renamed/missing columns), the column
#  lookup returns -1 and the parser imports ZERO findings. Before the fix that
#  zero-import was SILENT - it read to the operator as a clean fleet. This pins
#  the loud warn hint (parity with acas ConvertFrom-AcasCsv) so a wrong-template
#  import surfaces "could not find a host/plugin column" instead of a false zero.
#
#  Drives the REAL Parse-AcasFile against temp CSV files; captures the -Emit log.
#  KEV/IAVM "empty catalog" warns are ignored - we assert only the wrong-template
#  line - so the test is independent of whether JanetLocal has those files.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.WrongTemplateHint.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

function New-TempCsv {
    param([string]$Content)
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("reports_wt_test_" + $PID + "_" + $script:CsvSeq + ".csv")
    $script:CsvSeq++
    [System.IO.File]::WriteAllText($p, $Content, (New-Object System.Text.UTF8Encoding($true)))  # UTF-8 BOM, like a real export
    return $p
}
$script:CsvSeq = 0

# Run Parse-AcasFile on a CSV string, returning @{ Findings; Logs } where Logs is
# the captured -Emit records. Cleans up the temp file.
function Invoke-ParseCsv {
    param([string]$Content)
    $script:CapLogs = New-Object System.Collections.ArrayList
    $emit = { param($msg) [void]$script:CapLogs.Add($msg) }
    $tmp = New-TempCsv $Content
    try {
        $f = & $script:Mod {
            param($path, $e)
            Parse-AcasFile -FilePath $path -Emit $e
        } $tmp $emit
        return @{ Findings = @($f); Logs = @($script:CapLogs) }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

Describe 'reports CSV import - wrong template fires a LOUD hint, not a silent zero-import' {
    It 'a header with no host/plugin column imports zero AND warns' {
        $res = Invoke-ParseCsv "Foo,Bar,Baz`r`n1,2,3`r`n4,5,6`r`n"
        @($res.Findings).Count | Should Be 0
        $warn = @($res.Logs) | Where-Object { $_.level -eq 'warn' -and $_.text -match 'could not find' }
        @($warn).Count | Should BeGreaterThan 0
    }
    It 'the hint names both the missing host and plugin columns' {
        $res = Invoke-ParseCsv "Foo,Bar,Baz`r`n1,2,3`r`n"
        $warn = @($res.Logs) | Where-Object { $_.text -match 'could not find' }
        @($warn)[0].text | Should Match 'host column'
        @($warn)[0].text | Should Match 'plugin column'
    }
    It 'a header missing ONLY the plugin column names just the plugin column' {
        # 'DNS Name' resolves the host; there is no plugin/nessus-id column.
        $res = Invoke-ParseCsv "DNS Name,Severity`r`nWKS-01,High`r`n"
        @($res.Findings).Count | Should Be 0
        $warn = @($res.Logs) | Where-Object { $_.text -match 'could not find' }
        @($warn).Count | Should BeGreaterThan 0
        @($warn)[0].text | Should Match 'plugin column'
        @($warn)[0].text | Should Not Match 'host column'
    }
}

Describe 'reports CSV import - a correct template parses findings and does NOT warn wrong-template' {
    It 'imports the finding and emits no wrong-template hint' {
        $res = Invoke-ParseCsv "DNS Name,Plugin,Plugin Name,Severity,CVE`r`nWKS-01,12345,Google Chrome RCE,High,CVE-2024-1`r`n"
        @($res.Findings).Count | Should BeGreaterThan 0
        $warn = @($res.Logs) | Where-Object { $_.text -match 'could not find' }
        @($warn).Count | Should Be 0
    }
}

Describe 'reports - manifest exact version pin (newest bump = loop-19 wrong-template hint)' {
    It 'reports is at v2.14.23' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '2.14.23'
    }
}
