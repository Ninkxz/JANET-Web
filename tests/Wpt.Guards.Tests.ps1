# =============================================================================
#  Wpt.Guards.Tests.ps1 - Pester 3.4 tests for destructive-guard branches in
#  JanetWeb.wpt.psm1 (audit#2 / audit#30). Invoke-Command is shadowed inside
#  the module scope so NO real WinRM call ever leaves this box; the tests
#  drive the guard logic with a fake remote answer.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.Guards.Tests.ps1
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

Describe 'WptAppActionBlock DNS-mismatch hard-abort (audit#2)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
    Add-ShimGuard $m

    It 'aborts with no action when the answering box is not the dialed host' {
        $r = & $m {
            $__shims = Save-ShimState @('Invoke-Command')
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                return 'SOMEOTHERBOX'   # remote $env:COMPUTERNAME probe answer
            }
            try {
                & $script:WptAppActionBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' `
                    -AppId 'FAKE' -Revision '1' -IsMachineTarget $true -Method 'Uninstall' -AppName 'FakeApp'
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        }
        $r.Result | Should Be 'Failed'
        $r.Detail | Should Match 'DNS mismatch'
        $r.Detail | Should Match 'ABORTED, no action taken'
    }

    It 'proceeds past the guard when the answering box matches the dialed host' {
        $r = & $m {
            $__shims = Save-ShimState @('Invoke-Command')
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                if (-not $ArgumentList) { return $env:COMPUTERNAME }          # probe: matches
                return @{ OK = $false; Detail = 'mock: CCM catalog not consulted' }  # main call: inert
            }
            try {
                & $script:WptAppActionBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' `
                    -AppId 'FAKE' -Revision '1' -IsMachineTarget $true -Method 'Uninstall' -AppName 'FakeApp'
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        }
        $r.Detail | Should Not Match 'DNS mismatch'
        $r.Detail | Should Match 'mock: CCM catalog not consulted'
    }
}

Describe 'WptCcmRepairBlock wrong-box hard-abort (audit 2026-07-24)' {

    # RepairClient REINSTALLS the ConfigMgr client (a 5-20 min ccmsetup run) and the
    # result was reported under the DIALED name - a stale DNS / reused IP would rebuild
    # the WRONG machine's client and file the evidence against an innocent host. The
    # guard is folded into the block's single Invoke-Command, so the stub below RUNS the
    # real scriptblock locally (that is where $env:COMPUTERNAME is compared). Test-Path
    # is stubbed $false so the body stays inert even if the guard ever regresses.
    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
    Add-ShimGuard $m

    function Invoke-CcmRepairAgainst([string]$Dialed) {
        & $m {
            param($dialed)
            $__shims = Save-ShimState @('Invoke-Command','Test-Path')
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                return & $ScriptBlock @ArgumentList   # the "remote" box IS this box
            }
            function script:Test-Path { param($Path, $LiteralPath) $false }
            try { & $script:WptCcmRepairBlock -Computer $dialed -Cred $null -Auth 'Default' }
            finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        } $Dialed
    }

    It 'aborts with no repair when the answering box is not the dialed host' {
        $r = Invoke-CcmRepairAgainst 'SOMEOTHERBOX'
        [bool]$r.Success | Should Be $false
        $r.Detail | Should Match 'DNS mismatch'
        $r.Detail | Should Match 'ABORTED, no client repair triggered'
    }

    It 'proceeds past the guard when the answering box matches the dialed host' {
        $r = Invoke-CcmRepairAgainst $env:COMPUTERNAME
        $r.Detail | Should Not Match 'DNS mismatch'
        $r.Detail | Should Match 'MECM client not installed'
    }
}
