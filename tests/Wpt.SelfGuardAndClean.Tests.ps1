# =============================================================================
#  Wpt.SelfGuardAndClean.Tests.ps1 - Pester 3.4 tests for two prior-review open
#  items fixed in JanetWeb.wpt.psm1:
#
#   (a) Reboot self-guard: 'reboot' / 'reboot-schedule' now run every target
#       through Remove-WptSelfTargets (mirrors JanetWeb.restart.psm1's
#       dispatch-restart self-guard) before ever touching WptRebootBlock /
#       WptRebootScheduleBlock, so the JANET dispatcher host itself can never
#       be rebooted mid-dispatch.
#   (b) IPv4 false-abort fix: the DNS-mismatch hard-abort guards used to run
#       ($Computer -split '.')[0] against an IPv4-literal target, which just
#       yields the first octet and could never match a real $env:COMPUTERNAME
#       - a guaranteed false abort. The guard is now skipped entirely for an
#       IPv4-literal target (kept active for hostname targets).
#
#  Invoke-Command / Restart-Computer are shadowed inside the module scope
#  (same technique as Wpt.Guards.Tests.ps1) so NO real WinRM/reboot call ever
#  leaves this box - unit scope only, no host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.SelfGuardAndClean.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

# Drive the REAL entry point in module scope, capturing every emitted event so
# we can assert the self-guard fired and no dispatch/reboot was ever started.
function Invoke-WptAction {
    param([string]$ActionId, [hashtable]$Params)
    $script:sgEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:sgEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:sgEvents) }
}

Describe 'Test-WptHostIsSelf predicate (the reboot self-guard uses this)' {
    It 'flags the loopback literal 127.0.0.1 as self' {
        (& $m { Test-WptHostIsSelf '127.0.0.1' }) | Should Be $true
    }
    It 'does NOT flag an obviously-remote hostname' {
        (& $m { Test-WptHostIsSelf 'WS-REMOTE-999' }) | Should Be $false
    }
}

Describe 'Reboot self-guard drops the dispatcher host before dispatch (FIX 3a)' {
    $out = Invoke-WptAction -ActionId 'reboot' -Params @{ targets = '127.0.0.1' }

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning naming the dropped host' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
    }
    It 'NEVER starts a fan-out (no status event = no runspace / no host contact)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'Reboot-schedule self-guard drops the dispatcher host before dispatch (FIX 3a)' {
    $out = Invoke-WptAction -ActionId 'reboot-schedule' -Params @{ targets = '127.0.0.1'; seconds = 300; message = 'test' }

    It 'returns total=0 with selfSkipped=1 and no rows' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning and never starts a fan-out' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'WptRebootBlock DNS-mismatch guard skips IPv4-literal targets (FIX 3b)' {

    It 'IPv4-literal target: DNS-mismatch probe is skipped entirely and the reboot path proceeds' {
        $r = & $m {
            $script:probeCalled = $false
            $script:restartCalled = $false
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                $script:probeCalled = $true
                return 'SOMEOTHERBOX'   # would read as a "mismatch" IF the guard evaluated it
            }
            function script:Restart-Computer {
                param($ComputerName, $Force, $ErrorAction, $Credential)
                $script:restartCalled = $true
            }
            try {
                $res = & $script:WptRebootBlock -Computer '198.51.100.5' -Cred $null -Auth 'Default'
                @{ Result = $res; ProbeCalled = $script:probeCalled; RestartCalled = $script:restartCalled }
            } finally {
                Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue
                Remove-Item function:script:Restart-Computer -ErrorAction SilentlyContinue
            }
        }
        $r.ProbeCalled          | Should Be $false   # IPv4 literal -> DNS-mismatch probe never runs
        $r.RestartCalled        | Should Be $true     # guard did not hard-abort; reboot path proceeded
        $r.Result.Detail        | Should Not Match 'DNS mismatch'
        [bool]$r.Result.Success | Should Be $true
    }

    It 'hostname target: DNS-mismatch guard still hard-aborts on a confirmed mismatch (guard stays active)' {
        $r = & $m {
            $script:restartCalled = $false
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                return 'SOMEOTHERBOX'   # a genuine mismatch for a hostname target
            }
            function script:Restart-Computer {
                param($ComputerName, $Force, $ErrorAction, $Credential)
                $script:restartCalled = $true
            }
            try {
                $res = & $script:WptRebootBlock -Computer 'WS-REMOTE-999' -Cred $null -Auth 'Default'
                @{ Result = $res; RestartCalled = $script:restartCalled }
            } finally {
                Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue
                Remove-Item function:script:Restart-Computer -ErrorAction SilentlyContinue
            }
        }
        $r.Result.Detail  | Should Match 'DNS mismatch'
        $r.Result.Detail  | Should Match 'ABORTED, no reboot sent'
        $r.RestartCalled  | Should Be $false   # hard-abort must prevent Restart-Computer
        [bool]$r.Result.Success | Should Be $false
    }
}
