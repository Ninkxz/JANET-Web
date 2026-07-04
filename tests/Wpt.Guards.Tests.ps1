# =============================================================================
#  Wpt.Guards.Tests.ps1 - Pester 3.4 tests for destructive-guard branches in
#  JanetTwo.wpt.psm1 (audit#2 / audit#30). Invoke-Command is shadowed inside
#  the module scope so NO real WinRM call ever leaves this box; the tests
#  drive the guard logic with a fake remote answer.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.Guards.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

Describe 'WptAppActionBlock DNS-mismatch hard-abort (audit#2)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetTwo.wpt.psm1') -Force -PassThru

    It 'aborts with no action when the answering box is not the dialed host' {
        $r = & $m {
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                return 'SOMEOTHERBOX'   # remote $env:COMPUTERNAME probe answer
            }
            try {
                & $script:WptAppActionBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' `
                    -AppId 'FAKE' -Revision '1' -IsMachineTarget $true -Method 'Uninstall' -AppName 'FakeApp'
            } finally { Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue }
        }
        $r.Result | Should Be 'Failed'
        $r.Detail | Should Match 'DNS mismatch'
        $r.Detail | Should Match 'ABORTED, no action taken'
    }

    It 'proceeds past the guard when the answering box matches the dialed host' {
        $r = & $m {
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                if (-not $ArgumentList) { return $env:COMPUTERNAME }          # probe: matches
                return @{ OK = $false; Detail = 'mock: CCM catalog not consulted' }  # main call: inert
            }
            try {
                & $script:WptAppActionBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' `
                    -AppId 'FAKE' -Revision '1' -IsMachineTarget $true -Method 'Uninstall' -AppName 'FakeApp'
            } finally { Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue }
        }
        $r.Detail | Should Not Match 'DNS mismatch'
        $r.Detail | Should Match 'mock: CCM catalog not consulted'
    }
}
