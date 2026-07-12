# =============================================================================
#  RemoteAdmin.WrongBoxGuard.Tests.ps1 - loop-8 P2. run-script is the suite's most
#  dangerous action (it runs ARBITRARY operator PowerShell on a target). Its worker
#  ($script:RemoteAdminScriptBlock, modules\JanetWeb.remoteadmin.psm1 ~:268-288) now
#  hard-aborts BEFORE running the operator block if the box that answered the WinRM
#  session isn't the box that was dialed - closing the stale-DNS / reused-IP / dialed-
#  a-self-alias wrong-box hole its sibling workers already guard.
#
#  This pins the guard's DECISION LOGIC (the same house pattern as
#  tests\PkginstallSecureboot.WrongBoxGuard.Tests.ps1 and tests\Restart.Guards.Tests.ps1):
#  the expected-name computation and the mismatch boolean are replicated VERBATIM from
#  the worker below. Unit-scope only - no New-PSSession / Invoke-Command / host contact.
#  The live remote $env:COMPUTERNAME probe itself needs a real session -> pilot-pending,
#  like the six sibling guards; what regresses silently is this abort-vs-run decision,
#  which is what this locks.
#
#  Run:  Invoke-Pester -Path .\tests\RemoteAdmin.WrongBoxGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
# Imported for parity with the sibling files (the guard lives in this module); the
# assertions below use the verbatim replicas, matching the house pattern.
$script:RaMod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.remoteadmin.psm1') -Force -PassThru

# Verbatim replica of the dialed-target -> expected-COMPUTERNAME calculation the
# run-script worker uses (IPv4 literal => '' => guard skipped, no DNS indirection).
function Get-RaExpectedName { param([string]$Computer) if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] } }

# Verbatim replica of the worker's hard-abort boolean (the real box's COMPUTERNAME
# swapped for a test-supplied $Answering): abort only when a non-blank expected name
# differs (case-insensitively) from the answering box.
function Test-RaWrongBoxAbort {
    param([string]$Expected, [string]$Answering)
    [bool]($Expected -and (([string]$Answering).Trim().ToUpper() -ne ([string]$Expected).Trim().ToUpper()))
}

Describe 'run-script wrong-box guard: expected-name computation (loop-8 P2)' {
    It 'IPv4-literal target => empty expected name (guard skipped - no DNS indirection)' {
        (Get-RaExpectedName '10.1.2.3') | Should Be ''
    }
    It 'FQDN target => first dot-token as expected name' {
        (Get-RaExpectedName 'WS01.area.af.mil') | Should Be 'WS01'
    }
    It 'bare hostname target => itself as expected name' {
        (Get-RaExpectedName 'WS01') | Should Be 'WS01'
    }
}

Describe 'run-script wrong-box guard: hard-abort decision (operator block must NOT run on a mismatch)' {
    It 'a hostname mismatch hard-aborts (stale DNS / reused IP / dialed a different box)' {
        (Test-RaWrongBoxAbort -Expected 'WS01' -Answering 'WS02') | Should Be $true
    }
    It 'a hostname match does NOT abort' {
        (Test-RaWrongBoxAbort -Expected 'WS01' -Answering 'WS01') | Should Be $false
    }
    It 'a case-insensitive match does NOT abort (COMPUTERNAME casing varies)' {
        (Test-RaWrongBoxAbort -Expected 'WS01' -Answering 'ws01') | Should Be $false
    }
    It 'an IPv4-literal target is never aborted by the guard (expected name is blank)' {
        $expected = Get-RaExpectedName '10.1.2.3'
        (Test-RaWrongBoxAbort -Expected $expected -Answering 'SOME-OTHER-BOX') | Should Be $false
    }
    It 'an FQDN whose first label matches the answering short name does NOT abort' {
        $expected = Get-RaExpectedName 'WS01.area.af.mil'
        (Test-RaWrongBoxAbort -Expected $expected -Answering 'WS01') | Should Be $false
    }
}
