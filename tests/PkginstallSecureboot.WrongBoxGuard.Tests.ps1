# =============================================================================
#  PkginstallSecureboot.WrongBoxGuard.Tests.ps1 - P2-6a/P2-6b wrong-box guards.
#  pkginstall.psm1 and secureboot.psm1 dial a target by hostname and then act
#  (install / arm a firmware task) with no protection against stale-DNS/reused-IP
#  host confusion. Both engines now:
#    - compute an "expected name" that is '' for an IPv4-literal target (no DNS
#      indirection possible, so the guard is skipped) and the dialed shortname
#      otherwise;
#    - hard-abort (inside the remote block, comparing against the answering
#      box's own $env:COMPUTERNAME) on a mismatch.
#  secureboot.psm1 additionally drops the JANET dispatcher host itself from any
#  run (self-guard) so Secure Boot's pending-reboot can never take down JANET.
#  Unit-scope only: no New-PSSession/Invoke-Command/host contact anywhere below.
#  The expected-name and hard-abort expressions are replicated VERBATIM from the
#  modules (see modules\JanetWeb.pkginstall.psm1 ~line 168 and ~line 387/519,
#  modules\JanetWeb.secureboot.psm1 ~line 530/533) so this pins the contract -
#  mirrors the existing pattern in tests\Restart.Guards.Tests.ps1.
# =============================================================================
$script:Root   = Split-Path $PSScriptRoot -Parent
$script:PkgMod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Force -PassThru
$script:SbeMod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru

# Verbatim replica of the dialed-target -> expected-COMPUTERNAME calculation
# used by both engines (IPv4 literal => '' => guard skipped).
function Get-ExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }

# Verbatim replica of the hard-abort boolean both remote scriptblocks evaluate:
# "$expected -and ($env:COMPUTERNAME... -ne ([string]$expected)...)" with the
# real box's COMPUTERNAME swapped for a test-supplied $Answering value.
function Test-WrongBoxAbort {
    param([string]$Expected, [string]$Answering)
    [bool]($Expected -and ($Answering.Trim().ToUpper() -ne ([string]$Expected).Trim().ToUpper()))
}

Describe 'Wrong-box guard: expected-name computation (P2-6a/P2-6b, shared shape)' {
    It 'IPv4-literal target => empty expected name (guard skipped)' {
        (Get-ExpectedName '10.1.2.3') | Should Be ''
    }
    It 'FQDN target => first dot-token as expected name' {
        (Get-ExpectedName 'WS01.area.af.mil') | Should Be 'WS01'
    }
    It 'bare hostname target => itself as expected name' {
        (Get-ExpectedName 'WS01') | Should Be 'WS01'
    }
}

Describe 'Wrong-box guard: hard-abort decision' {
    It '(a) a hostname mismatch hard-aborts the host' {
        (Test-WrongBoxAbort -Expected 'WS01' -Answering 'WS02') | Should Be $true
    }
    It 'a hostname match (case-insensitive) does NOT abort' {
        (Test-WrongBoxAbort -Expected 'WS01' -Answering 'ws01') | Should Be $false
    }
    It '(b) an IPv4-literal target is NOT aborted by the guard (expected name is blank)' {
        $expected = Get-ExpectedName '10.1.2.3'
        (Test-WrongBoxAbort -Expected $expected -Answering 'SOME-OTHER-BOX') | Should Be $false
    }
}

Describe 'secureboot self-guard (P2-6b): Test-JanetSbeHostIsSelf' {
    It 'flags this host by COMPUTERNAME' {
        (& $script:SbeMod { param($n) Test-JanetSbeHostIsSelf $n } $env:COMPUTERNAME) | Should Be $true
    }
    It 'flags localhost and any 127.x loopback' {
        (& $script:SbeMod { Test-JanetSbeHostIsSelf 'localhost' }) | Should Be $true
        (& $script:SbeMod { Test-JanetSbeHostIsSelf '127.0.0.5' }) | Should Be $true
    }
    It 'does not flag an unrelated hostname' {
        (& $script:SbeMod { Test-JanetSbeHostIsSelf 'WS-NOT-ME-12345' }) | Should Be $false
    }
    It 'does not flag an empty token' {
        (& $script:SbeMod { Test-JanetSbeHostIsSelf '' }) | Should Be $false
    }
}

Describe '(c) secureboot drops a self-target from the run before any reboot-risking work' {
    It 'a run targeting only the JANET dispatcher host is skipped entirely (no rows, no worker dispatch)' {
        $r = & $script:SbeMod {
            Invoke-JanetToolAction -ActionId 'enable-secure-boot' `
                -Params @{ targets = $env:COMPUTERNAME; dry_run = $true } `
                -Emit { param($e) }
        }
        @($r.rows).Count      | Should Be 0
        [int]$r.summary.total | Should Be 0
        [int]$r.summary.selfSkipped | Should Be 1
    }
}
