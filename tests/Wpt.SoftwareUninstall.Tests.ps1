# =============================================================================
#  Wpt.SoftwareUninstall.Tests.ps1 - Pester 3.4 tests for the v6.8.0
#  verify-and-clean uninstall pipeline in WptSoftwareUninstallBlock
#  (Remove App - GUI style: msiexec exit mapping incl. 1605 stale / 1618
#  retry, install-folder verification, orphaned-uninstall-key cleanup).
#  Invoke-Command / Test-WptHostReachable are shadowed inside the module
#  scope so the inner remote scriptblock runs LOCALLY - no WinRM leaves
#  this box. The only real process launched is msiexec /x against a GUID
#  that is guaranteed not installed (exit 1605, no system change).
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.SoftwareUninstall.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

Describe 'WptSoftwareUninstallBlock verify-and-clean pipeline (v6.8.0)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

    $runLocal = {
        param([string[]]$Apps)
        function script:Test-WptHostReachable { @{ Reachable = $true; UseSsl = $false } }
        # Get-AppxPackage -AllUsers throws when the test shell is not elevated
        # (a real remote session is always admin) - shadow it to 'nothing found'.
        function script:Get-AppxPackage { param($Name, [switch]$AllUsers, $EA) $null }
        function script:Invoke-Command {
            param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
            if (-not $ArgumentList) { return $env:COMPUTERNAME }   # DNS-mismatch probe
            & $ScriptBlock $ArgumentList[0]                        # run the remote block locally
        }
        try {
            & $script:WptSoftwareUninstallBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' -AppNames $Apps
        } finally {
            Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue
            Remove-Item function:script:Test-WptHostReachable -ErrorAction SilentlyContinue
            Remove-Item function:script:Get-AppxPackage -ErrorAction SilentlyContinue
        }
    }

    It 'reports NotFound for a name matching nothing installed (no uninstaller runs)' {
        $rows = @(& $m $runLocal @('ZZZ_Janet_Test_App_That_Does_Not_Exist_ZZZ'))
        $rows.Count | Should Be 1
        $rows[0].Result | Should Be 'NotFound'
    }

    It 'maps msiexec exit 1605 on a not-installed GUID to Removed / stale registry entry' {
        $rows = @(& $m $runLocal @('{DEADBEEF-0000-4000-8000-000000000000}'))
        $rows.Count | Should Be 1
        $rows[0].Type | Should Be 'MSI'
        $rows[0].Result | Should Be 'Removed'
        $rows[0].Detail | Should Match '1605'
        $rows[0].Detail | Should Match 'stale registry entry'
    }

    It 'passes a verbose msiexec log path and the retry/attention vocabulary in the module source' {
        $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
        $src | Should Match '/l\*v'
        $src | Should Match '1618.*retry later'
        $src | Should Match "files still present"
        $src | Should Match 'orphaned uninstall key cleaned'
    }
}
