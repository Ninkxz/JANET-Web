# =============================================================================
#  Sysadmin.Tests.ps1 - Pester 3.4 tests pinning the 2026-07-24 audit fixes in
#  JanetWeb.sysadmin.psm1. NO real WinRM ever leaves this box.
#
#  Companion to tests\Sysadmin.Sweeps.Tests.ps1: that suite shims Invoke-Command
#  to hand back the probe payload DIRECTLY (the legacy/bare-data unwrap path), so
#  it never exercised the remote wrapper - which is how the double-wrap defect
#  shipped green. Everything here goes through the REAL wrapper
#  (New-SysadminProbeBlock), executed locally against a synthetic payload.
#
#  Coverage:
#   (1) the wrapper wraps the payload EXACTLY once (text + round-trip shape).
#   (2) the worker's row build, driven through that wrapper: 3 admins report 3,
#       2 expiring certs emit 2 rows, and an empty reason list is NOT pending.
#   (3) Get-SysadminIntParam - days=0 survives, junk keeps the default.
#   (4) the activity-log level - a CLEAN host must not be logged amber.
#
#  Run:  Invoke-Pester -Path .\tests\Sysadmin.Tests.ps1
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

Describe 'New-SysadminProbeBlock wraps the payload exactly once (audit 2026-07-24)' {

    It 'does not array-wrap the payload a SECOND time in the generated text' {
        $sb = New-SysadminProbeBlock -Probe { return , @('A') }
        $sb.ToString() | Should Match '__SweepData = \(& \{'
        # The defective form was  __SweepData = @(& { ... })  - that @() is the bug:
        # every payload already returns its array as one object via  return ,@(...).
        ($sb.ToString() -like '*__SweepData = @(*') | Should Be $false
    }

    It 'passes a 3-element payload through as 3 elements (double-wrap gave 1)' {
        $out = & (New-SysadminProbeBlock -Probe { return , @('CORP\alice', 'CORP\bob', 'BUILTIN\Administrator') })
        @($out['__SweepData']).Count | Should Be 3
        ($out['__SweepData'][0] -is [array]) | Should Be $false
        $out['__SweepData'][0] | Should Be 'CORP\alice'
    }

    It 'keeps an EMPTY payload empty (double-wrap gave 1 element holding an empty array)' {
        $out = & (New-SysadminProbeBlock -Probe { return , @() })
        @($out['__SweepData']).Count | Should Be 0
    }

    It 'folds the answering box name in for the DNS-mismatch guard' {
        $out = & (New-SysadminProbeBlock -Probe { return , @() })
        $out['__SweepName'] | Should Be $env:COMPUTERNAME
    }

    It 'returns nothing when there is no probe to wrap' {
        (New-SysadminProbeBlock -Probe $null) | Should BeNullOrEmpty
    }
}

Describe 'SysadminSweepBlock row build THROUGH the real wrapper (audit 2026-07-24)' {

    # The Sysadmin.Sweeps.Tests shim idiom with two deliberate differences: the
    # host dialled is THIS box (so the DNS-mismatch guard sees a matching name),
    # and the Invoke-Command shim returns what a real remote would - the wrapper's
    # own output around a synthetic payload - so wrap, unwrap and row build all run.
    function Invoke-WrappedSweep {
        param([string]$SweepId, [int]$Days, [scriptblock]$Payload)
        return & $m {
            param($SweepId, $Days, $Payload)
            Set-Variable -Name __payload -Scope script -Value $Payload
            $__shims = Save-ShimState @('Test-SysadminReachable','New-PSSession','Invoke-Command','Remove-PSSession')
            function script:Test-SysadminReachable { param($ComputerName, $Ports, $TimeoutMs, $UseSsl) if ($UseSsl -is [ref]) { $UseSsl.Value = $false }; return $true }
            function script:New-PSSession { param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $UseSSL) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Invoke-Command { param($Session, $ScriptBlock, $ArgumentList, $ErrorAction) return (& (New-SysadminProbeBlock -Probe $script:__payload)) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            try {
                & $script:SysadminSweepBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' -AttemptOffline $false -SweepId $SweepId -Days $Days -ModulePath ''
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
                Remove-Variable -Name __payload -Scope script -ErrorAction SilentlyContinue
            }
        } $SweepId $Days $Payload
    }

    It 'localadmin-sweep counts all 3 admins (double-wrap always reported 1)' {
        $r = Invoke-WrappedSweep -SweepId 'localadmin-sweep' -Days 90 -Payload {
            return , @('BUILTIN\Administrator', 'CORP\alice', 'CORP\Domain Admins')
        }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].AdminCount | Should Be 3
        $r.Rows[0].Admins | Should Match 'CORP\\alice'
        $r.Rows[0].Error | Should Be ''
        $r.Report | Should Match '3 local admin'
    }

    It 'certexpiry-sweep emits a row per expiring cert (double-wrap reported a false CLEAN)' {
        $r = Invoke-WrappedSweep -SweepId 'certexpiry-sweep' -Days 90 -Payload {
            return , @(
                [pscustomobject]@{ Subject = 'CN=soon';    Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(10);  Thumbprint = 'AAAA' },
                [pscustomobject]@{ Subject = 'CN=expired'; Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(-3);  Thumbprint = 'BBBB' },
                [pscustomobject]@{ Subject = 'CN=far';     Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(400); Thumbprint = 'CCCC' }
            )
        }
        @($r.Rows).Count | Should Be 2
        $r.Rows[0].Subject | Should Match 'expired'          # expired sorts first
        ([int]$r.Rows[0].DaysLeft) | Should BeLessThan 0
        $r.Rows[0].Expires | Should Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'certexpiry-sweep with days=0 returns ONLY the already-expired cert' {
        $r = Invoke-WrappedSweep -SweepId 'certexpiry-sweep' -Days 0 -Payload {
            return , @(
                [pscustomobject]@{ Subject = 'CN=soon';    Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(10); Thumbprint = 'AAAA' },
                [pscustomobject]@{ Subject = 'CN=expired'; Issuer = 'CN=CA'; NotAfter = (Get-Date).AddDays(-3); Thumbprint = 'BBBB' }
            )
        }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].Subject | Should Match 'expired'
    }

    It 'rebootpending-sweep is NOT pending on an empty signal list (double-wrap was 100% false positive)' {
        $r = Invoke-WrappedSweep -SweepId 'rebootpending-sweep' -Days 90 -Payload { return , @() }
        @($r.Rows).Count | Should Be 1
        $r.Rows[0].RebootPending | Should Be $false
        $r.Rows[0].Reasons | Should Be ''
        $r.Report | Should Match 'no reboot pending'
    }

    It 'rebootpending-sweep still reports pending with the joined signal names' {
        $r = Invoke-WrappedSweep -SweepId 'rebootpending-sweep' -Days 90 -Payload {
            return , @('Component Based Servicing', 'Windows Update')
        }
        $r.Rows[0].RebootPending | Should Be $true
        $r.Rows[0].Reasons | Should Be 'Component Based Servicing; Windows Update'
    }
}

Describe 'Get-SysadminIntParam (audit 2026-07-24)' {

    It 'honours a literal 0 instead of silently falling back to the default' {
        (Get-SysadminIntParam -Value 0 -Default 90) | Should Be 0
        (Get-SysadminIntParam -Value '0' -Default 90) | Should Be 0
    }

    It 'keeps the default for absent/blank/junk input (junk must NOT become 0)' {
        (Get-SysadminIntParam -Value $null -Default 90) | Should Be 90
        (Get-SysadminIntParam -Value '' -Default 90) | Should Be 90
        (Get-SysadminIntParam -Value '   ' -Default 90) | Should Be 90
        (Get-SysadminIntParam -Value 'abc' -Default 90) | Should Be 90
        (Get-SysadminIntParam -Value '12x' -Default 16) | Should Be 16
    }

    It 'parses a good value, trimmed' {
        (Get-SysadminIntParam -Value ' 45 ' -Default 90) | Should Be 45
        (Get-SysadminIntParam -Value '-7' -Default 90) | Should Be -7
    }
}

Describe 'Activity-log level must not amber a CLEAN host (audit 2026-07-24)' {

    # Same swap-the-worker-scriptblock idiom as Sysadmin.Sweeps.Tests: the real
    # Invoke-JanetToolAction fans out to a real RunspacePool, so the fake worker
    # must not depend on any module function. We only care about the log events.
    function Invoke-LevelProbe {
        param([string]$ActionId, [scriptblock]$FakeBlock)
        $script:__evt = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$script:__evt.Add($e) }
        $null = & $m {
            param($FakeBlock, $emit, $ActionId)
            Set-Variable -Name __origBlock -Scope script -Value $script:SysadminSweepBlock
            $script:SysadminSweepBlock = $FakeBlock
            try {
                Invoke-JanetToolAction -ActionId $ActionId -Params @{ targets = "CLEAN-HOST`nDIRTY-HOST"; days = 90 } -Emit $emit
            } finally {
                $script:SysadminSweepBlock = $script:__origBlock
                Remove-Variable -Name __origBlock -Scope script -ErrorAction SilentlyContinue
            }
        } $FakeBlock $emit $ActionId
        return $script:__evt
    }

    It 'logs "no certs expiring within N day(s)" as info and a real finding as warn' {
        $evt = Invoke-LevelProbe -ActionId 'certexpiry-sweep' -FakeBlock {
            param($Computer, $Cred, $Auth, $AttemptOffline, $SweepId, $Days, $ModulePath)
            $rpt = if ($Computer -eq 'CLEAN-HOST') { "$Computer : no certs expiring within $Days day(s)" } else { "$Computer : 2 cert(s) expiring within $Days day(s)" }
            return @{ Host = $Computer; Online = $true; Error = ''; Report = $rpt; Rows = @(@{ Host = $Computer; Online = $true; Subject = 'x'; Issuer = ''; Expires = ''; DaysLeft = ''; Thumbprint = ''; Error = '' }) }
        }
        $clean = @($evt | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'CLEAN-HOST' })
        $dirty = @($evt | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'DIRTY-HOST' })
        $clean.Count | Should Be 1
        $clean[0].level | Should Be 'info'
        $dirty.Count | Should Be 1
        $dirty[0].level | Should Be 'warn'
    }

    It 'logs "no reboot pending" as info and REBOOT PENDING as warn' {
        $evt = Invoke-LevelProbe -ActionId 'rebootpending-sweep' -FakeBlock {
            param($Computer, $Cred, $Auth, $AttemptOffline, $SweepId, $Days, $ModulePath)
            $rpt = if ($Computer -eq 'CLEAN-HOST') { "$Computer : no reboot pending" } else { "$Computer : REBOOT PENDING - Windows Update" }
            return @{ Host = $Computer; Online = $true; Error = ''; Report = $rpt; Rows = @(@{ Host = $Computer; Online = $true; RebootPending = ($Computer -ne 'CLEAN-HOST'); Reasons = ''; Error = '' }) }
        }
        $clean = @($evt | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'CLEAN-HOST' })
        $dirty = @($evt | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'DIRTY-HOST' })
        $clean.Count | Should Be 1
        $clean[0].level | Should Be 'info'
        $dirty[0].level | Should Be 'warn'
    }
}
