# =============================================================================
#  Sysadmin.Sweeps.Tests.ps1 - Pester 3.4 tests for JanetWeb.sysadmin.psm1.
#
#  Two layers, NO real WinRM ever leaves this box:
#   (1) pure helpers (DaysLeft calc, reason-joining, admin-list formatting) are
#       unit-tested directly.
#   (2) the per-host worker ($script:SysadminSweepBlock) is driven with
#       Test-SysadminReachable / New-PSSession / Invoke-Command / Remove-PSSession
#       shadowed in the MODULE scope (the tests\Wpt.Guards.Tests.ps1 idiom), so
#       the worker's row-building runs against synthetic data and we assert the
#       emitted row shape.
#
#  Run:  Invoke-Pester -Path .\tests\Sysadmin.Sweeps.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.sysadmin.psm1') -Force -PassThru

Describe 'Sysadmin pure helpers' {

    It 'Get-SysadminDaysLeft floors whole days and returns negatives for expired' {
        $now = Get-Date '2026-01-01T00:00:00'
        (Get-SysadminDaysLeft -NotAfter $now.AddDays(90)  -Now $now) | Should Be 90
        (Get-SysadminDaysLeft -NotAfter $now.AddDays(-5)  -Now $now) | Should Be -5
        (Get-SysadminDaysLeft -NotAfter $now.AddDays(10).AddHours(12) -Now $now) | Should Be 10
    }

    It 'Join-SysadminReasons drops blanks/nulls and joins with a semicolon' {
        (Join-SysadminReasons -Reasons @('Windows Update', '', $null, 'CBS')) | Should Be 'Windows Update; CBS'
        (Join-SysadminReasons -Reasons @()) | Should Be ''
    }

    It 'Get-SysadminCleanMembers de-dups case-insensitively and drops blanks' {
        $c = @(Get-SysadminCleanMembers -Members @('CORP\alice', 'corp\alice', 'BUILTIN\Administrator', '  ', $null))
        $c.Count | Should Be 2
    }

    It 'Format-SysadminAdminList semicolon-joins the cleaned member list' {
        (Format-SysadminAdminList -Members @('CORP\alice', 'BUILTIN\Administrator', 'corp\alice')) | Should Be 'CORP\alice; BUILTIN\Administrator'
    }
}

Describe 'SysadminSweepBlock worker (shimmed - no real WinRM)' {

    # Install module-scope shims, run the worker, then always remove the shims.
    function Invoke-ShimmedSweep {
        param([string]$SweepId, [int]$Days, [scriptblock]$InvokeReturn, [bool]$Reachable = $true, [bool]$AttemptOffline = $false)
        return & $m {
            param($SweepId, $Days, $InvokeReturn, $Reachable, $AttemptOffline)
            Set-Variable -Name __ir -Scope script -Value $InvokeReturn
            Set-Variable -Name __reach -Scope script -Value $Reachable
            function script:Test-SysadminReachable { param($ComputerName, $Ports, $TimeoutMs) return [bool]$script:__reach }
            function script:New-PSSession { param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Invoke-Command { param($Session, $ScriptBlock, $ArgumentList, $ErrorAction) return (& $script:__ir) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            try {
                & $script:SysadminSweepBlock -Computer 'TESTHOST' -Cred $null -Auth 'Default' -AttemptOffline $AttemptOffline -SweepId $SweepId -Days $Days -ModulePath ''
            } finally {
                Remove-Item function:script:Test-SysadminReachable, function:script:New-PSSession, function:script:Invoke-Command, function:script:Remove-PSSession -ErrorAction SilentlyContinue
                Remove-Variable -Name __ir, __reach -Scope script -ErrorAction SilentlyContinue
            }
        } $SweepId $Days $InvokeReturn $Reachable $AttemptOffline
    }

    It 'localadmin-sweep emits one row with the formatted admin list and count' {
        $r = Invoke-ShimmedSweep -SweepId 'localadmin-sweep' -Days 90 -InvokeReturn { , @('BUILTIN\Administrator', 'CORP\alice') }
        $r.Online | Should Be $true
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].AdminCount | Should Be 2
        $r.Rows[0].Admins | Should Match 'Administrator'
        $r.Rows[0].Error | Should Be ''
    }

    It 'certexpiry-sweep emits one row per expiring/expired cert, excludes far-future, sorts expired first' {
        $now = Get-Date
        $r = Invoke-ShimmedSweep -SweepId 'certexpiry-sweep' -Days 90 -InvokeReturn {
            , @(
                [pscustomobject]@{ Subject = 'CN=soon';    Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(10);  Thumbprint = 'AAAA' },
                [pscustomobject]@{ Subject = 'CN=expired'; Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(-3);  Thumbprint = 'BBBB' },
                [pscustomobject]@{ Subject = 'CN=far';     Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(400); Thumbprint = 'CCCC' }
            )
        }
        @($r.Rows).Count | Should Be 2
        ([int]$r.Rows[0].DaysLeft) | Should BeLessThan 0     # expired sorts first
        $r.Rows[0].Subject | Should Match 'expired'
        $r.Rows[0].Expires | Should Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'certexpiry-sweep emits a single note row when nothing is expiring' {
        $r = Invoke-ShimmedSweep -SweepId 'certexpiry-sweep' -Days 90 -InvokeReturn { , @() }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].Subject | Should Match 'no certs expiring'
    }

    It 'rebootpending-sweep reports pending true with joined reasons' {
        $r = Invoke-ShimmedSweep -SweepId 'rebootpending-sweep' -Days 0 -InvokeReturn { , @('Component Based Servicing', 'Windows Update') }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].RebootPending | Should Be $true
        $r.Rows[0].Reasons | Should Match 'Windows Update'
    }

    It 'rebootpending-sweep reports pending false when no signal fired' {
        $r = Invoke-ShimmedSweep -SweepId 'rebootpending-sweep' -Days 0 -InvokeReturn { , @() }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].RebootPending | Should Be $false
        $r.Rows[0].Reasons | Should Be ''
    }

    It 'an offline host (not forced) emits one offline row and never opens a session' {
        $r = Invoke-ShimmedSweep -SweepId 'localadmin-sweep' -Days 90 -Reachable $false -AttemptOffline $false -InvokeReturn { , @('x') }
        $r.Online | Should Be $false
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].Error | Should Match 'Offline'
    }
}
