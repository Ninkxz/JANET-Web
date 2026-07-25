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
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
# -----------------------------------------------------------------------------

Describe 'WptSoftwareUninstallBlock verify-and-clean pipeline (v6.8.0)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
    Add-ShimGuard $m

    $runLocal = {
        param([string[]]$Apps)
        $__shims = Save-ShimState @('Test-WptHostReachable','Get-AppxPackage','Invoke-Command')
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
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
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
