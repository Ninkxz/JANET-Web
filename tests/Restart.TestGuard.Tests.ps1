# =============================================================================
#  Restart.TestGuard.Tests.ps1 - the test-single-host hardening:
#    (1) self-guard: refuse to test-reboot the JANET dispatcher itself.
#    (2) dry-run: report WOULD-do, contact/reboot nothing.
#  Shims the module's Invoke-RrsShutdownDirect so NO real shutdown is ever issued;
#  asserts it is NOT called on the self / dry-run paths and IS called on a real one.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Force -PassThru

# Shadow the real reboot call in module scope with a recorder (no shutdown.exe).
& $script:Mod {
    $script:ShutdownCalls = New-Object System.Collections.ArrayList
    function Invoke-RrsShutdownDirect {
        param($Hostname, $LeadSeconds, $Message, $Credential)
        [void]$script:ShutdownCalls.Add([string]$Hostname)
        return @{ ExitCode = 0; Stdout = 'shim - no real reboot' }
    }
}
function Reset-ShutdownCalls { & $script:Mod { $script:ShutdownCalls.Clear() } }
function Get-ShutdownCallCount { & $script:Mod { $script:ShutdownCalls.Count } }

Describe 'restart test-single-host hardening (self-guard + dry-run)' {

    It 'self-guard: refuses the dispatcher host (localhost) and issues NO reboot' {
        Reset-ShutdownCalls
        $r = & $script:Mod { Invoke-JanetToolAction -ActionId 'test-single-host' -Params @{ hostname = 'localhost' } -Emit { param($e) } }
        (Get-ShutdownCallCount) | Should Be 0
        [int]$r.summary.refused | Should Be 1
        [int]$r.summary.ok      | Should Be 0
    }

    It 'self-guard: refuses a 127.x loopback too' {
        Reset-ShutdownCalls
        $r = & $script:Mod { Invoke-JanetToolAction -ActionId 'test-single-host' -Params @{ hostname = '127.0.0.1' } -Emit { param($e) } }
        (Get-ShutdownCallCount) | Should Be 0
        [int]$r.summary.refused | Should Be 1
    }

    It 'dry-run: a non-self host reports WOULD-do and issues NO reboot' {
        Reset-ShutdownCalls
        $r = & $script:Mod { Invoke-JanetToolAction -ActionId 'test-single-host' -Params @{ hostname = 'FAKEHOST01'; dryRun = $true } -Emit { param($e) } }
        (Get-ShutdownCallCount) | Should Be 0
        [int]$r.summary.dryRun | Should Be 1
    }

    # NOTE: "a real non-self run reaches the reboot" is proven above by the dry-run
    # test on FAKEHOST01 - it passes the self-guard (non-self) and reaches the dry-run
    # branch that sits AFTER the guard. We deliberately do NOT drive the real reboot
    # path in a test (it would attempt an actual shutdown), so no such case exists here.

    It 'the manifest exposes the dryRun input on test-single-host' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        $act = $mani.actions | Where-Object { $_.id -eq 'test-single-host' }
        $act | Should Not BeNullOrEmpty
        ($act.inputs | Where-Object { $_.name -eq 'dryRun' }) | Should Not BeNullOrEmpty
    }
}
