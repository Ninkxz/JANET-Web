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
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.sysadmin.psm1') -Force -PassThru
Add-ShimGuard $m

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
            $__shims = Save-ShimState @('Test-SysadminReachable','New-PSSession','Invoke-Command','Remove-PSSession')
            function script:Test-SysadminReachable { param($ComputerName, $Ports, $TimeoutMs, $UseSsl) if ($UseSsl -is [ref]) { $UseSsl.Value = $false }; return [bool]$script:__reach }
            function script:New-PSSession { param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Invoke-Command { param($Session, $ScriptBlock, $ArgumentList, $ErrorAction) return (& $script:__ir) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            try {
                & $script:SysadminSweepBlock -Computer 'TESTHOST' -Cred $null -Auth 'Default' -AttemptOffline $AttemptOffline -SweepId $SweepId -Days $Days -ModulePath ''
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
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

Describe 'The amber matcher reads the STATE, not the hostname (audit 2026-07-25 (fable re-audit follow-up))' {

    # The old matcher ran -cmatch over the WHOLE report line, hostname included, so a
    # CLEAN host NAMED 'WS-ERROR-01' was logged amber and an operator triaging by colour
    # would chase a box with nothing wrong with it.
    It 'a CLEAN host whose NAME contains a state word is logged info, not warn' {
        (Get-SysadminReportLevel -Report 'WS-ERROR-01 : no reboot pending')                | Should Be 'info'
        (Get-SysadminReportLevel -Report 'TIMEOUT-LAB-02 : no certs expiring within 90 day(s)') | Should Be 'info'
        (Get-SysadminReportLevel -Report 'OFFLINE-BAY-03 : 2 local admin(s) - CORP\alice; BUILTIN\Administrator') | Should Be 'info'
    }

    It 'a REAL finding still goes amber (no over-correction)' {
        (Get-SysadminReportLevel -Report 'WS01 : REBOOT PENDING - Windows Update')     | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : OFFLINE - no TCP on 5985/5986/445')   | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : SESSION ERROR - access denied')       | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : PROBE ERROR - rpc failed')            | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : WORKER ERROR - no result')            | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : TIMEOUT (150s) - possible remote read hang') | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : CANCELLED')                           | Should Be 'warn'
        (Get-SysadminReportLevel -Report "WS01 : DNS MISMATCH - dialed 'WS01', answered 'WS02' - skipped") | Should Be 'warn'
        (Get-SysadminReportLevel -Report 'WS01 : 3 cert(s) expiring within 90 day(s)') | Should Be 'warn'
    }

    It 'a local-admin MEMBER name containing a state word does not amber a clean row' {
        (Get-SysadminReportLevel -Report 'WS01 : 1 local admin(s) - CORP\ERROR-SVC') | Should Be 'info'
    }

    It 'an empty or unparsable report never throws' {
        (Get-SysadminReportLevel -Report '')   | Should Be 'info'
        (Get-SysadminReportLevel -Report $null) | Should Be 'info'
        (Get-SysadminReportLevel -Report 'REBOOT PENDING with no host prefix') | Should Be 'warn'
    }

    It 'END TO END: the emitted activity-log level for a clean ERROR-named host is info' {
        # Same fake-worker idiom as the tally regression below: the REAL
        # Invoke-JanetToolAction aggregation (and its log-level decision) runs.
        $fakeBlock = {
            param($Computer, $Cred, $Auth, $AttemptOffline, $SweepId, $Days, $ModulePath)
            return @{ Host = $Computer; Online = $true; Error = ''
                      Rows = @(@{ Host = $Computer; Online = $true; RebootPending = $false; Reasons = ''; Error = '' })
                      Report = "$Computer : no reboot pending" }
        }
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $null = & $m {
            param($fakeBlock, $em)
            Set-Variable -Name __origBlock -Scope script -Value $script:SysadminSweepBlock
            $script:SysadminSweepBlock = $fakeBlock
            try { Invoke-JanetToolAction -ActionId 'rebootpending-sweep' -Params @{ targets = 'WS-ERROR-01' } -Emit $em }
            finally {
                $script:SysadminSweepBlock = $script:__origBlock
                Remove-Variable -Name __origBlock -Scope script -ErrorAction SilentlyContinue
            }
        } $fakeBlock $emit

        $hostLines = @($evts | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'no reboot pending' })
        $hostLines.Count | Should Be 1
        [string]$hostLines[0].level | Should Be 'info'      # <-- was 'warn' before the fix
    }
}

Describe 'Invoke-JanetToolAction certexpiry-sweep (regression: expired-cert tally must not throw)' {

    # Invoke-JanetToolAction fans hosts out to a real RunspacePool (CreateDefault
    # InitialSessionState); each pool worker Import-Module's the .psm1 FRESH into
    # its own runspace, so shimming Test-SysadminReachable/New-PSSession/
    # Invoke-Command in THIS process's module instance (as Invoke-ShimmedSweep
    # does above) never reaches the pool worker - empirically confirmed while
    # building this test. Instead we swap the module-scope worker scriptblock
    # ($script:SysadminSweepBlock) itself for a fake that returns canned per-host
    # results directly (no module-function dependency, so it runs correctly in
    # any bare pool runspace). This exercises the REAL, unmodified
    # Invoke-JanetToolAction aggregation code - the exact code the certexpiry-sweep
    # expired/expiring tally (and the bug it had) lives in - end to end through the
    # action wrapper, not just the per-host block.
    It 'tallies expiredCerts/expiringCerts without throwing when a host reports an already-expired cert' {
        $fakeBlock = {
            param($Computer, $Cred, $Auth, $AttemptOffline, $SweepId, $Days, $ModulePath)
            if ($Computer -eq 'EXPIRED-HOST') {
                return @{ Host = $Computer; Online = $true; Error = ''; Rows = @(@{ Host = $Computer; Online = $true; Subject = 'CN=expired'; Issuer = 'CN=CA'; Expires = (Get-Date).AddDays(-3).ToString('yyyy-MM-dd'); DaysLeft = -3; Thumbprint = 'EEEE'; Error = '' }); Report = '' }
            } else {
                return @{ Host = $Computer; Online = $true; Error = ''; Rows = @(@{ Host = $Computer; Online = $true; Subject = 'CN=soon'; Issuer = 'CN=CA'; Expires = (Get-Date).AddDays(10).ToString('yyyy-MM-dd'); DaysLeft = 10; Thumbprint = 'FFFF'; Error = '' }); Report = '' }
            }
        }
        $r = & $m {
            param($fakeBlock)
            Set-Variable -Name __origBlock -Scope script -Value $script:SysadminSweepBlock
            $script:SysadminSweepBlock = $fakeBlock
            try {
                Invoke-JanetToolAction -ActionId 'certexpiry-sweep' -Params @{ targets = "EXPIRED-HOST`nSOON-HOST"; days = 90 } -Emit { param($e) }
            } finally {
                $script:SysadminSweepBlock = $script:__origBlock
                Remove-Variable -Name __origBlock -Scope script -ErrorAction SilentlyContinue
            }
        } $fakeBlock

        @($r.rows).Count | Should Be 2
        [int]$r.summary.expiredCerts | Should Be 1
        [int]$r.summary.expiringCerts | Should Be 2
    }
}
