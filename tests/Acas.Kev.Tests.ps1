# =============================================================================
#  Acas.Kev.Tests.ps1 - Pester 3.4 tests for the ACAS KEV-badging helpers
#  (Read-AcasKevSet / Test-AcasCvesInKev) that flag known-exploited groups at
#  the point of remediation.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetTwo.acas.psm1') -Force -PassThru

Describe 'ACAS KEV badging helpers' {

    It 'Read-AcasKevSet returns a case-insensitive HashSet (preserved on assignment)' {
        $isSet = & $script:Mod { $s = Read-AcasKevSet; $s -is [System.Collections.Generic.HashSet[string]] }
        $isSet | Should Be $true
    }

    It 'Test-AcasCvesInKev matches a CVE in the set (case-insensitive)' {
        $r = & $script:Mod {
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$set.Add('CVE-2021-44228')
            [pscustomobject]@{
                Hit   = (Test-AcasCvesInKev -CveCell 'CVE-2020-1, CVE-2021-44228' -KevSet $set)
                Lower = (Test-AcasCvesInKev -CveCell 'cve-2021-44228' -KevSet $set)
                Miss  = (Test-AcasCvesInKev -CveCell 'CVE-2019-9999' -KevSet $set)
                Empty = (Test-AcasCvesInKev -CveCell '' -KevSet $set)
            }
        }
        $r.Hit   | Should Be $true
        $r.Lower | Should Be $true
        $r.Miss  | Should Be $false
        $r.Empty | Should Be $false
    }

    It 'Test-AcasCvesInKev is false for an empty/null KEV set (no badging, no error)' {
        $r = & $script:Mod {
            $empty = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            Test-AcasCvesInKev -CveCell 'CVE-2021-44228' -KevSet $empty
        }
        $r | Should Be $false
    }
}
