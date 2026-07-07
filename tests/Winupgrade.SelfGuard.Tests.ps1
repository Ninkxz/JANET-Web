# =============================================================================
#  Winupgrade.SelfGuard.Tests.ps1 - Pester 3.4 tests proving the dispatcher
#  self-reboot guard on JanetWeb.winupgrade.psm1 (audit FIX 1 / P1).
#
#  The InstallCab worker (remote reboot after DISM) and SetPageFile (reboot to
#  apply the page-file change) both issue an UNCONDITIONAL remote reboot when
#  $reboot is set. Without a self-filter, an OU/AD paste that includes the JANET
#  dispatcher's own name/IP would reboot the box running JANET mid-fan-out. This
#  proves Invoke-JanetToolAction DROPS a self-target from those reboot waves
#  BEFORE any dispatch, so the dispatcher is never rebooted.
#
#  Unit-scope only: the sole target is the loopback literal 127.0.0.1, which
#  Test-WinUpgradeHostIsSelf always classifies as self, so the guard removes it
#  and the function returns EARLY - no runspace pool is opened and NO host is
#  ever contacted. shutdown.exe / DISM are never reached.
#
#  Run:  Invoke-Pester -Path .\tests\Winupgrade.SelfGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

# Drive the REAL entry point in module scope, capturing every emitted event so we
# can assert the guard fired and that NO dispatch was started.
function Invoke-SelfGuard {
    param([string]$ActionId, [hashtable]$Params)
    $script:sgEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:sgEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:sgEvents) }
}

Describe 'Test-WinUpgradeHostIsSelf predicate (the filter uses this)' {
    It 'flags the loopback literal 127.0.0.1 as self' {
        (& $m { Test-WinUpgradeHostIsSelf '127.0.0.1' }) | Should Be $true
    }
    It 'does NOT flag an obviously-remote hostname' {
        (& $m { Test-WinUpgradeHostIsSelf 'WS-REMOTE-999' }) | Should Be $false
    }
}

Describe 'InstallCab self-guard drops the dispatcher host before dispatch' {
    $out = Invoke-SelfGuard -ActionId 'installcab' -Params @{ targets = '127.0.0.1'; reboot = $true }

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning naming the dropped host' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
    }
    It 'surfaces a Skipped grid row for the self-target' {
        $row = $out.Events | Where-Object { $_.type -eq 'row' -and $_.Status -eq 'Skipped' }
        $row | Should Not BeNullOrEmpty
        [string]$row.Host | Should Be '127.0.0.1'
    }
    It 'NEVER starts a dispatch (no Starting status = no runspace / no host contact)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' -and $_.text -match 'Starting' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'SetPageFile self-guard drops the dispatcher host before dispatch' {
    $out = Invoke-SelfGuard -ActionId 'setpagefile' -Params @{ targets = '127.0.0.1'; reboot = $true }

    It 'returns total=0 with selfSkipped=1 and no rows' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning and NEVER starts a dispatch' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
        $starting = $out.Events | Where-Object { $_.type -eq 'status' -and $_.text -match 'Starting' }
        $starting | Should BeNullOrEmpty
    }
}
