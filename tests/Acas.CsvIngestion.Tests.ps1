# =============================================================================
#  Acas.CsvIngestion.Tests.ps1 - Pester 3.4 for the acas CSV IMPORT parser
#  (ConvertFrom-AcasCsv). This is the FRONT of the offline/CSV-fed pipeline for
#  the most-used remediation tool: an ACAS/Nessus export becomes the finding
#  rows every downstream number (routing, host counts, KEV, SLA) is built from.
#  A row mis-parsed here silently corrupts everything after it, so the parser's
#  robustness contract is worth pinning:
#    - -Encoding UTF8 decodes UTF-8 exports WITH a BOM (the common Nessus case)
#      without folding the BOM into the first column header (which would break
#      the host-column lookup and drop every finding).
#    - Import-Csv/ConvertFrom-Csv handle quoted fields with embedded commas.
#    - A MISSING/renamed column returns empty (no throw) - a finding with an
#      empty plugin name degrades to NotUpdatable (visible), never a crash.
#    - The host token is whitelist-validated BEFORE it can become a remote
#      target; a garbled cell is rejected, not forwarded.
#    - msek-* servers are skipped.
#    - When rows parse but NONE map to a host (wrong export template / renamed
#      host columns), a LOUD warn hint fires instead of silently importing zero.
#
#  Read-only: synthetic CSV through the module-scope parser; no host contact.
#  The one -Paths case writes a temp BOM file and removes it.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.CsvIngestion.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

# Drive the real parser in module scope. $Send captures the emitted log records
# into a fresh test-scope list per call so the wrong-template hint is assertable.
function Invoke-AcasIngest {
    param([string]$Csv, [string[]]$Paths)
    $script:CapturedLogs = New-Object System.Collections.ArrayList
    $send = { param($msg) [void]$script:CapturedLogs.Add($msg) }
    & $m {
        param($text, $paths, $s)
        ConvertFrom-AcasCsv -Text $text -Paths $paths -Send $s
    } $Csv $Paths $send
}

Describe 'acas CSV ingestion - well-formed rows map correctly' {
    $csv = @"
DNS Name,NetBIOS Name,IP Address,Plugin,Plugin Name,Severity,CVE,Steps to Remediate
WKS-01.corp.mil,WKS-01,10.0.0.5,12345,Google Chrome RCE,High,CVE-2024-1,Update Chrome
,,10.0.0.9,999,Some Finding,Medium,CVE-2024-2,Do the thing
"@
    $res = Invoke-AcasIngest $csv
    It 'parses both data rows' {
        $res.RowCount | Should Be 2
        @($res.Findings).Count | Should Be 2
    }
    It 'picks the DNS Name (short form) when present' {
        @($res.Findings | Where-Object { $_.Host -eq 'WKS-01' }).Count | Should Be 1
    }
    It 'falls back to the IP Address when DNS/NetBIOS are blank' {
        @($res.Findings | Where-Object { $_.Host -eq '10.0.0.9' }).Count | Should Be 1
    }
    It 'maps the plugin/severity/cve/solution columns onto the finding' {
        $f = @($res.Findings) | Where-Object { $_.Host -eq 'WKS-01' }
        $f.PluginId   | Should Be '12345'
        $f.PluginName | Should Be 'Google Chrome RCE'
        $f.Severity   | Should Be 'High'
        $f.Cve        | Should Be 'CVE-2024-1'
        $f.Solution   | Should Be 'Update Chrome'
    }
}

Describe 'acas CSV ingestion - host precedence DNS > NetBIOS > IP' {
    $csv = @"
DNS Name,NetBIOS Name,IP Address,Plugin Name,Severity
HOST-A,HOST-B,10.0.0.1,Finding X,Low
"@
    $res = Invoke-AcasIngest $csv
    It 'chooses the DNS Name over NetBIOS and IP' {
        @($res.Findings)[0].Host | Should Be 'HOST-A'
    }
}

Describe 'acas CSV ingestion - quoted field with an embedded comma survives' {
    # The CVE cell holds two comma-separated CVEs inside quotes - it must land as
    # ONE field on ONE row, not split the row or shift the columns.
    $csv = @"
DNS Name,Plugin Name,Severity,CVE
WKS-02,Multi-CVE Finding,High,"CVE-2024-10, CVE-2024-11"
"@
    $res = Invoke-AcasIngest $csv
    It 'keeps it a single row' {
        $res.RowCount | Should Be 1
        @($res.Findings).Count | Should Be 1
    }
    It 'keeps the embedded comma inside one CVE field' {
        @($res.Findings)[0].Cve | Should Be 'CVE-2024-10, CVE-2024-11'
    }
}

Describe 'acas CSV ingestion - a missing/renamed column is tolerated, not fatal' {
    # 'Plugin Name' header is absent (a slightly-off export template). The row
    # still has a host, so the finding is created with an EMPTY plugin name
    # (degrades to NotUpdatable downstream) rather than throwing or dropping.
    $csv = @"
DNS Name,Severity,CVE
WKS-03,High,CVE-2024-3
"@
    $res = Invoke-AcasIngest $csv
    It 'still produces the finding' {
        @($res.Findings).Count | Should Be 1
        @($res.Findings)[0].Host | Should Be 'WKS-03'
    }
    It 'leaves the missing plugin name empty (no throw)' {
        @($res.Findings)[0].PluginName | Should Be ''
    }
}

Describe 'acas CSV ingestion - msek-* servers are skipped' {
    $csv = @"
DNS Name,Plugin Name,Severity
msek-dc01,Server Finding,High
WKS-04,Client Finding,High
"@
    $res = Invoke-AcasIngest $csv
    It 'counts the server as skipped, not a finding' {
        $res.ServersSkipped | Should Be 1
        @($res.Findings | Where-Object { $_.Host -like 'msek-*' }).Count | Should Be 0
    }
    It 'still keeps the non-server finding' {
        @($res.Findings)[0].Host | Should Be 'WKS-04'
    }
}

Describe 'acas CSV ingestion - a garbled host token is rejected before it can be a target' {
    # 'bad host name' has embedded spaces - Test-AcasHostToken rejects it, so it
    # never becomes a finding (and thus never a remote target).
    $csv = @"
DNS Name,Plugin Name,Severity
bad host name,Junk Finding,High
"@
    $res = Invoke-AcasIngest $csv
    It 'drops the garbled row as no-host' {
        @($res.Findings).Count | Should Be 0
        $res.NoHostSkipped | Should Be 1
    }
}

Describe 'acas CSV ingestion - wrong template fires a LOUD hint, not a silent zero-import' {
    # Rows parse, but there is no DNS/NetBIOS/IP column at all - the classic
    # wrong-export-template case. Every row is no-host, so a warn must surface.
    $csv = @"
Plugin,Plugin Name,Severity
555,Orphan Finding,High
556,Another Orphan,Medium
"@
    $res = Invoke-AcasIngest $csv
    It 'imports zero findings (no host to attach to)' {
        @($res.Findings).Count | Should Be 0
        $res.NoHostSkipped | Should Be 2
    }
    It 'emits a warn hint that points at the column headers' {
        $warn = @($script:CapturedLogs) | Where-Object { $_.level -eq 'warn' -and $_.text -match 'column headers' }
        @($warn).Count | Should BeGreaterThan 0
    }
}

Describe 'acas CSV ingestion - a UTF-8 file WITH a BOM decodes without corrupting the first header' {
    # -Encoding UTF8 is the offline constraint: real ACAS exports are UTF-8 and
    # often carry a BOM. If the BOM folded into the first column name ('DNS Name'
    # -> BOM+'DNS Name') the host lookup would miss and every finding would drop.
    # This pins the -Paths import decode; a careless switch off -Encoding UTF8
    # (or to Get-Content default) fails here.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("acas_bom_ingest_test_" + $PID + ".csv")
    $content = "DNS Name,Plugin Name,Severity`r`nWKS-BOM,BOM Finding,High`r`n"
    [System.IO.File]::WriteAllText($tmp, $content, (New-Object System.Text.UTF8Encoding($true)))  # $true = emit BOM
    try {
        $res = Invoke-AcasIngest '' @($tmp)
        It 'parses the BOM file and attaches the finding to its host' {
            @($res.Findings).Count | Should Be 1
            @($res.Findings)[0].Host | Should Be 'WKS-BOM'
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}
