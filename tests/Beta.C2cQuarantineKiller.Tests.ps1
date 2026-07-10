# =============================================================================
#  Beta.C2cQuarantineKiller.Tests.ps1 - Pester tests for the PURE helpers on
#  JanetWeb.beta.psm1 (C2C Quarantine Killer). These are the security-critical
#  bits the remote SYSTEM payload depends on:
#    - Test-BetaTaskName      : only safe task names reach the SYSTEM -Command
#    - Get-BetaKillerCommand  : the delete payload targets the TARGET task and can
#                               never delete the watchdog itself (self-deletion guard)
#    - Test-JanetBetaHostIsSelf: the JANET dispatcher is recognised as self
#  The pool worker MIRRORS Get-BetaKillerCommand inline (it runs in a bare runspace
#  and cannot call the module) - keep the two in sync.
#
#  Run:  Invoke-Pester -Path .\tests\Beta.C2cQuarantineKiller.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.beta.psm1') -Force -PassThru

Describe 'Test-BetaTaskName - only injection-safe task names pass' {
    It 'accepts the real target name' { Test-BetaTaskName 'C2C Quarantine' | Should Be $true }
    It 'accepts dots/underscores/hyphens' { Test-BetaTaskName 'C2C_Quarantine-Cycle.v2' | Should Be $true }
    It 'rejects empty / whitespace' {
        Test-BetaTaskName ''    | Should Be $false
        Test-BetaTaskName '   ' | Should Be $false
    }
    It 'rejects a single-quote breakout' { Test-BetaTaskName "a'; Remove-Item C:\ -Recurse" | Should Be $false }
    It 'rejects a semicolon command chain' { Test-BetaTaskName 'foo; calc' | Should Be $false }
    It 'rejects an ampersand' { Test-BetaTaskName 'foo & bar' | Should Be $false }
    It 'rejects a pipe' { Test-BetaTaskName 'foo | bar' | Should Be $false }
}

Describe 'Get-BetaKillerCommand - deletes the target, never the watchdog' {
    $killer = Get-BetaKillerTaskName
    $cmd = Get-BetaKillerCommand 'C2C Quarantine'
    It 'names the target task' { $cmd | Should Match "TaskName 'C2C Quarantine'" }
    It 'calls Unregister-ScheduledTask' { $cmd | Should Match 'Unregister-ScheduledTask' }
    It 'keeps $false literal (escaped, not expanded)' { $cmd | Should Match 'Confirm:\$false' }
    It 'does NOT reference the watchdog task name (no self-deletion)' {
        ($cmd -match [regex]::Escape($killer)) | Should Be $false
    }
}

Describe 'Test-JanetBetaHostIsSelf - dispatcher self-guard' {
    It 'flags localhost / 127.0.0.1 / this box as self' {
        Test-JanetBetaHostIsSelf 'localhost'  | Should Be $true
        Test-JanetBetaHostIsSelf '127.0.0.1'  | Should Be $true
        Test-JanetBetaHostIsSelf $env:COMPUTERNAME | Should Be $true
    }
    It 'does not flag an unrelated host' { Test-JanetBetaHostIsSelf 'ZZ-NOPE-9999' | Should Be $false }
    It 'treats a blank target as not-self' { Test-JanetBetaHostIsSelf '' | Should Be $false }
}

Describe 'Manifest - three actions, correct gates' {
    $man = Get-JanetToolManifest
    It 'exposes status/install/remove' {
        ($man.actions | ForEach-Object { $_.id }) -join ',' | Should Be 'status,install,remove'
    }
    It 'status is read-only; install/remove are destructive' {
        ($man.actions | Where-Object { $_.id -eq 'status' }).destructive  | Should Be $false
        ($man.actions | Where-Object { $_.id -eq 'install' }).destructive | Should Be $true
        ($man.actions | Where-Object { $_.id -eq 'remove' }).destructive  | Should Be $true
    }
    It 'status exposes a Watchdog run-health column' {
        @(($man.actions | Where-Object { $_.id -eq 'status' }).columns) -contains 'Watchdog' | Should Be $true
    }
    It 'reports version 0.7.0' { $man.version | Should Be '0.7.0' }
}

Describe 'Get-BetaWatchdogHealth - confirms the watchdog is RUNNING, not just installed' {
    It 'absent watchdog -> NOT INSTALLED' {
        (Get-BetaWatchdogHealth -Present $false).Word | Should Be 'NOT INSTALLED'
    }
    It 'present but Disabled -> DISABLED (will not run)' {
        (Get-BetaWatchdogHealth -Present $true -State 'Disabled' -LastRun '2026-07-09 14:00:00' -LastResult 0 -NextRun '2026-07-09 15:30:00').Word | Should Be 'DISABLED'
    }
    It 'present + enabled but never fired (empty LastRun) -> NEVER RAN' {
        (Get-BetaWatchdogHealth -Present $true -State 'Ready' -LastRun '' -LastResult 267011 -NextRun '2026-07-09 15:30:00').Word | Should Be 'NEVER RAN'
    }
    It 'the has-not-run result code 267011 -> NEVER RAN even if a LastRun sneaks through' {
        (Get-BetaWatchdogHealth -Present $true -State 'Ready' -LastRun '2026-07-09 14:00:00' -LastResult 267011 -NextRun '2026-07-09 15:30:00').Word | Should Be 'NEVER RAN'
    }
    It 'last run returned a non-zero failure code -> LAST FAILED' {
        $h = Get-BetaWatchdogHealth -Present $true -State 'Ready' -LastRun '2026-07-09 14:00:00' -LastResult 1 -NextRun '2026-07-09 15:30:00'
        $h.Word | Should Be 'LAST FAILED'
        $h.Detail | Should Match 'result 1'
    }
    It 'currently executing -> RUNNING' {
        (Get-BetaWatchdogHealth -Present $true -State 'Running' -LastRun '2026-07-09 14:00:00' -LastResult 267009 -NextRun '2026-07-09 15:30:00').Word | Should Be 'RUNNING'
    }
    It 'last run completed with result 0 -> HEALTHY, and the detail confirms last + next run' {
        $h = Get-BetaWatchdogHealth -Present $true -State 'Ready' -LastRun '2026-07-09 14:00:00' -LastResult 0 -NextRun '2026-07-09 15:30:00' -Interval 'PT90M'
        $h.Word | Should Be 'HEALTHY'
        $h.Detail | Should Match 'last ran 2026-07-09 14:00:00'
        $h.Detail | Should Match 'next run 2026-07-09 15:30:00'
    }
}
