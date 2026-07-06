# =============================================================================
#  WinUpgrade.FleetStatus.Tests.ps1 - Pester 3.4 tests for the READ-ONLY
#  'fleet-status' action on JanetWeb.winupgrade.psm1.
#
#  Two layers, NO real WinRM ever leaves this box:
#   (1) the pure classifier Get-WinUpgradeFleetStatus is unit-tested directly for
#       every Win24H2Status branch + precedence.
#   (2) the end-to-end aggregation is exercised by swapping the module-scope
#       per-host worker ($script:WinUpgradeWorker) for a fake that returns canned
#       per-host scan signals. Invoke-JanetToolAction fans hosts out to a real
#       RunspacePool whose bare runspaces import nothing from THIS process, so a
#       function-shim would not reach them - swapping the module-scope worker
#       scriptblock (the Sysadmin.Sweeps.Tests idiom) does. The REAL, unmodified
#       classification + rollup code then runs against the synthetic data and we
#       assert the per-host Win24H2Status + the summary counts on the RETURN value.
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.FleetStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

Describe 'winupgrade manifest exposes a read-only fleet-status action' {
    It 'fleet-status is present, stream-table, destructive=false, with the board columns' {
        $mani = & $m { Get-JanetToolManifest }
        $act = $mani.actions | Where-Object { $_.id -eq 'fleet-status' }
        $act | Should Not BeNullOrEmpty
        $act.kind | Should Be 'stream-table'
        $act.destructive | Should Be $false
        ($act.columns -contains 'Win24H2Status') | Should Be $true
        ($act.columns -contains 'OsBuild')       | Should Be $true
        ($act.columns -contains 'Pinned')        | Should Be $true
    }
}

Describe 'Get-WinUpgradeFleetStatus classifier (pure)' {
    It 'build >= 26100 => Already 24H2+' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26100 -Online $true -Eligible $true }) | Should Be 'Already 24H2+'
    }
    It 'on 23H2 + eligible => Ready' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 22631 -Online $true -Eligible $true }) | Should Be 'Ready'
    }
    It 'on 23H2 + not eligible => Blocked: <reason>' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 22631 -Online $true -Eligible $false -BlockReason 'CPU unsupported; disk <64GB' }) | Should Be 'Blocked: CPU unsupported; disk <64GB'
    }
    It 'pending reboot (below 24H2) => Pending reboot, and Already 24H2+ still wins the build check' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 22631 -Online $true -Eligible $true -PendingReboot $true }) | Should Be 'Pending reboot'
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 26100 -Online $true -Eligible $true -PendingReboot $true }) | Should Be 'Already 24H2+'
    }
    It 'offline / error / unknown-build map to Offline / Error' {
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 22631 -Online $false }) | Should Be 'Offline'
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 0 -Online $true -ErrorText 'winrm failed' }) | Should Be 'Error'
        (& $m { Get-WinUpgradeFleetStatus -OsBuild 0 -Online $true }) | Should Be 'Error'
    }
}

Describe 'fleet-status end to end (shimmed worker - no real WinRM)' {

    # A synthetic per-host worker: keys off the host name to return canned scan
    # signals in the SAME shape the real worker's FleetStatus branch returns. It
    # declares only the leading positional params it needs; the remaining
    # AddArgument() values bind harmlessly to $args in the pool runspace.
    $fakeWorker = {
        param($Computer, $Op)
        $base = [ordered]@{
            Host=$Computer; Ping='TCP 5985'; Online=$true; OsBuild=22631; DisplayVersion='23H2';
            Eligible=$true; BlockReason=''; Pinned=$false; PinnedVersion=''; PendingReboot=$false;
            Error=''; Status='SCANNED'; Detail=''; Ok=$true; Report=''
        }
        switch ($Computer) {
            'HOST-26100'  { $base.OsBuild=26100; $base.DisplayVersion='24H2' }
            'HOST-READY'  { $base.OsBuild=22631; $base.DisplayVersion='23H2'; $base.Eligible=$true }
            'HOST-BLOCKED'{ $base.OsBuild=22631; $base.Eligible=$false; $base.BlockReason='CPU unsupported; disk <64GB' }
            'HOST-PENDING'{ $base.OsBuild=22631; $base.PendingReboot=$true; $base.Pinned=$true; $base.PinnedVersion='24H2' }
        }
        return $base
    }

    function Invoke-ShimmedFleet {
        param([scriptblock]$FakeWorker, [string]$Targets)
        return & $m {
            param($FakeWorker, $Targets)
            Set-Variable -Name __origWorker -Scope script -Value $script:WinUpgradeWorker
            $script:WinUpgradeWorker = $FakeWorker
            try {
                Invoke-JanetToolAction -ActionId 'fleet-status' -Params @{ targets = $Targets } -Emit { param($e) }
            } finally {
                $script:WinUpgradeWorker = $script:__origWorker
                Remove-Variable -Name __origWorker -Scope script -ErrorAction SilentlyContinue
            }
        } $FakeWorker $Targets
    }

    $result = Invoke-ShimmedFleet -FakeWorker $fakeWorker -Targets "HOST-26100`nHOST-READY`nHOST-BLOCKED`nHOST-PENDING"

    function Row([object]$res, [string]$hostName) { return @($res.rows | Where-Object { $_.Host -eq $hostName })[0] }

    It 'returns one row per target' {
        @($result.rows).Count | Should Be 4
    }
    It 'classifies each host Win24H2Status correctly' {
        (Row $result 'HOST-26100').Win24H2Status  | Should Be 'Already 24H2+'
        (Row $result 'HOST-READY').Win24H2Status  | Should Be 'Ready'
        (Row $result 'HOST-BLOCKED').Win24H2Status | Should Be 'Blocked: CPU unsupported; disk <64GB'
        (Row $result 'HOST-PENDING').Win24H2Status | Should Be 'Pending reboot'
    }
    It 'surfaces OsBuild + Pinned + PinnedVersion on the rows' {
        [int]((Row $result 'HOST-26100').OsBuild) | Should Be 26100
        (Row $result 'HOST-PENDING').Pinned | Should Be $true
        (Row $result 'HOST-PENDING').PinnedVersion | Should Be '24H2'
        (Row $result 'HOST-READY').Pinned | Should Be $false
    }
    It 'rolls the summary counts up' {
        $s = $result.summary
        [int]$s.total         | Should Be 4
        [int]$s.already24h2   | Should Be 1
        [int]$s.ready         | Should Be 1
        [int]$s.blocked       | Should Be 1
        [int]$s.pendingReboot | Should Be 1
        [int]$s.pinned        | Should Be 1
        [int]$s.on23h2OrOlder | Should Be 3
        [int]$s.online        | Should Be 4
    }
    It 'breaks the block reasons down' {
        [int]$result.summary.blockBreakdown['CPU unsupported'] | Should Be 1
        [int]$result.summary.blockBreakdown['disk <64GB']      | Should Be 1
    }
}
