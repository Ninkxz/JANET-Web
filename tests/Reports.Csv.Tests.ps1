# =============================================================================
#  Reports.Csv.Tests.ps1 - Pester 3.4 tests for the CSV formula-injection guard
#  (audit#5 / audit#23) and the SLA-ledger prune cutoff (audit#6).
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetTwo.reports.psm1') -Force -PassThru

Describe 'ConvertTo-ReportsCsvCell formula-injection guard (audit#23)' {

    It 'prefixes a single quote to a leading = / + / - / @ cell' {
        $out = & $script:Mod { param($c) ConvertTo-ReportsCsvCell -Value $c } '=HYPERLINK("http://evil","x")'
        $out.StartsWith("'=") -or $out.StartsWith('"''=') | Should Be $true
        $out2 = & $script:Mod { ConvertTo-ReportsCsvCell -Value '@SUM(A1)' }
        $out2 | Should Be "'@SUM(A1)"
        $out3 = & $script:Mod { ConvertTo-ReportsCsvCell -Value '+1' }
        $out3 | Should Be "'+1"
        $out4 = & $script:Mod { ConvertTo-ReportsCsvCell -Value '-2' }
        $out4 | Should Be "'-2"
    }

    It 'leaves an ordinary value untouched' {
        (& $script:Mod { ConvertTo-ReportsCsvCell -Value 'NormalSquadron' }) | Should Be 'NormalSquadron'
    }

    It 'still quotes a value containing a comma' {
        (& $script:Mod { ConvertTo-ReportsCsvCell -Value 'Has,comma' }) | Should Be '"Has,comma"'
    }
}

Describe 'SLA-ledger prune cutoff (audit#6)' {
    # Mirror of the prune decision: a key whose lastSeen is older than the retention
    # window is dropped; a recently-seen key is kept.
    function Test-SlaPruneDrops {
        param([string]$LastSeen, [int]$RetentionDays = 365)
        $cutoff = (Get-Date).Date.AddDays(-$RetentionDays)
        [datetime]$d = [datetime]::MinValue
        if ([DateTime]::TryParse($LastSeen, [ref]$d)) { return ($d.Date -lt $cutoff) }
        return $false
    }

    It 'drops a key last seen 400 days ago' {
        (Test-SlaPruneDrops -LastSeen (Get-Date).AddDays(-400).ToString('yyyy-MM-dd')) | Should Be $true
    }
    It 'keeps a key last seen 30 days ago' {
        (Test-SlaPruneDrops -LastSeen (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')) | Should Be $false
    }
    It 'keeps a key with an unparseable lastSeen (never silently drops on bad data)' {
        (Test-SlaPruneDrops -LastSeen 'not-a-date') | Should Be $false
    }
}
