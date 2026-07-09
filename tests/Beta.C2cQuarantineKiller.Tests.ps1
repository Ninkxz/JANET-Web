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
}
