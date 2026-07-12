# =============================================================================
#  Csv.FormulaInjection.Tests.ps1 - Pester 3.4 tests for the CSV formula-injection
#  neutralizer added to the fleet-snapshot writer (wpt.psm1 Protect-WptCsvCell).
#  Mirrors reports.psm1's guard: a cell beginning with = + - @ TAB or CR gets a
#  single-quote prefix so Excel/Sheets renders it as literal text; benign and
#  blank values pass through unchanged.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

Describe 'Protect-WptCsvCell formula-injection neutralizer (Loop 6 parity)' {

    It 'prefixes a single quote to a leading-= formula payload' {
        (& $script:Mod { Protect-WptCsvCell -Value "=cmd|'/c calc'!A1" }) | Should Be "'=cmd|'/c calc'!A1"
    }
    It 'prefixes a single quote to a leading-+ cell' {
        (& $script:Mod { Protect-WptCsvCell -Value '+1' }) | Should Be "'+1"
    }
    It 'prefixes a single quote to a leading-- cell' {
        (& $script:Mod { Protect-WptCsvCell -Value '-1+1' }) | Should Be "'-1+1"
    }
    It 'prefixes a single quote to a leading-@ cell' {
        (& $script:Mod { Protect-WptCsvCell -Value '@SUM(A1)' }) | Should Be "'@SUM(A1)"
    }
    It 'prefixes a single quote to a leading TAB cell' {
        (& $script:Mod { Protect-WptCsvCell -Value "`tx" }) | Should Be "'`tx"
    }
    It 'prefixes a single quote to a leading CR cell' {
        (& $script:Mod { Protect-WptCsvCell -Value "`rx" }) | Should Be "'`rx"
    }

    It 'leaves a benign hostname unchanged' {
        (& $script:Mod { Protect-WptCsvCell -Value 'WIN-ABC' }) | Should Be 'WIN-ABC'
    }
    It 'leaves a benign OS caption unchanged' {
        (& $script:Mod { Protect-WptCsvCell -Value 'Microsoft Windows 11 Pro' }) | Should Be 'Microsoft Windows 11 Pro'
    }
    It 'leaves a benign build string unchanged' {
        (& $script:Mod { Protect-WptCsvCell -Value '10.0.26100' }) | Should Be '10.0.26100'
    }
    It 'leaves a blank value unchanged' {
        (& $script:Mod { Protect-WptCsvCell -Value '' }) | Should Be ''
    }
    It 'leaves a null value as empty (never throws)' {
        (& $script:Mod { Protect-WptCsvCell -Value $null }) | Should Be ''
    }

    It 'round-trips a snapshot object with the dangerous OS caption neutralized' {
        $neutralized = & $script:Mod { Protect-WptCsvCell -Value '=HYPERLINK("http://evil","x")' }
        $obj = [pscustomobject]@{ Host = 'WIN-ABC'; OS = $neutralized; Build = '10.0.26100' }
        $csv = @($obj | ConvertTo-Csv -NoTypeInformation)
        # Data row (index 1) must carry the apostrophe-neutralized formula, never a raw leading =.
        ($csv[1] -match "'=HYPERLINK") | Should Be $true
        ($csv[1] -match '"=HYPERLINK') | Should Be $false
    }
}
