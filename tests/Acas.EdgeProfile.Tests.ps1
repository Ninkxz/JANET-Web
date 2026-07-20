# =============================================================================
#  Acas.EdgeProfile.Tests.ps1 - Pester 3.4 tests for the ACAS 1.11.5 honest
#  'Microsoft Edge - Update' profile (roadmap item 1, loop 2).
#
#  Same defect + same treatment as the 1.11.4 Chrome port: the copied Script
#  ran MicrosoftEdgeUpdate.exe /ua and returned OK unconditionally. Now:
#  EdgeUpdate policy + service blocker pre-checks, exe-first trigger (UA task
#  fallback), before/after version poll, staged new_msedge.exe detection.
#  Unproven triggers return the acas-native UNCONFIRMED (never wpt's PENDING,
#  which $script:AcasOkOf would book green). Hard blockers FAIL and route to
#  the 'Microsoft Edge - Software Center' alternate.
#
#  Static-analysis scope only. No host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.EdgeProfile.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

$profiles = & $m { $script:AcasUpdateProfiles }
$name     = 'Microsoft Edge - Update'
$scName   = 'Microsoft Edge - Software Center'

Describe 'ACAS 1.11.5 - manifest loads at the bumped version' {
    $manifest = & $m { Get-JanetToolManifest }
    It 'manifest id is acas and version is 1.11.5' {
        [string]$manifest.id      | Should Be 'acas'
        [string]$manifest.version | Should Be '1.11.5'
    }
}

Describe 'ACAS 1.11.5 - honest Edge profile (registry shape)' {
    It 'still contains the Microsoft Edge - Update profile (name unchanged, match table intact)' {
        $profiles.ContainsKey($name) | Should Be $true
    }
    It 'still contains the Software Center alternate' {
        $profiles.ContainsKey($scName) | Should Be $true
    }
    It 'carries Script + Verify scriptblocks' {
        ($profiles[$name].Script -is [scriptblock]) | Should Be $true
        ($profiles[$name].Verify -is [scriptblock]) | Should Be $true
    }
    It 'Verify still reads the Edge Clients update GUID (New-AcasClientVerify)' {
        ("$($profiles[$name].Verify)" -match '56EB18F8-B008-4CBD-B6D2-8C97FE7E9062') | Should Be $true
    }
    It 'the match table still routes Microsoft Edge findings to Update then Software Center' {
        $rules = & $m { Get-AcasProfileMatchTable }
        $rule = @($rules | Where-Object { $_.Keywords -contains 'Microsoft Edge' })[0]
        @($rule.Profiles)[0] | Should Be $name
        @($rule.Profiles)[1] | Should Be $scName
    }
}

Describe 'ACAS 1.11.5 - honest Edge Script (static analysis)' {
    $net = "$($profiles[$name].Script)"
    It 'pre-checks the EdgeUpdate policy key before triggering anything' {
        ($net -match [regex]::Escape('Policies\Microsoft\EdgeUpdate')) | Should Be $true
    }
    It 'pre-checks the edgeupdate service state' {
        ($net -match "'edgeupdate'") | Should Be $true
    }
    It 'falls back to the MicrosoftEdgeUpdateTaskMachineUA scheduled task' {
        ($net -match 'MicrosoftEdgeUpdateTaskMachineUA') | Should Be $true
        ($net -match 'Start-ScheduledTask') | Should Be $true
    }
    It 'detects a staged update via new_msedge.exe' {
        ($net -match 'new_msedge\.exe') | Should Be $true
    }
    It 'polls the installed version before/after and reports movement' {
        ($net -match 'Edge updated') | Should Be $true
        ($net -match 'SKIP: Edge \(machine-level\) not installed') | Should Be $true
    }
    It 'does NOT contain the old unconditional "OK (Edge update triggered" string' {
        ($net -match [regex]::Escape('OK (Edge update triggered')) | Should Be $false
    }
    It 'unproven triggers return the acas-native UNCONFIRMED, never wpt''s PENDING' {
        ($net -match 'UNCONFIRMED') | Should Be $true
        ($net -match 'PENDING') | Should Be $false
    }
    It 'routes every hard blocker to the Software Center profile in its FAIL text' {
        ($net -match [regex]::Escape("use the 'Microsoft Edge - Software Center' profile")) | Should Be $true
    }
}

Describe 'ACAS 1.11.5 - AcasOkOf classifies every honest-Script state NOT-green except a proven bump' {
    $okOf = & $m { $script:AcasOkOf }
    It 'a policy-block FAIL is not green' {
        (& $okOf "FAIL: Edge auto-update blocked by policy (HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate) - use the 'Microsoft Edge - Software Center' profile") | Should Be $false
    }
    It 'a staged-update UNCONFIRMED is not green' {
        (& $okOf 'UNCONFIRMED: update staged as new_msedge.exe - applies when Edge is next relaunched (still v126.0.1 now)') | Should Be $false
    }
    It 'a proven version bump stays green' {
        (& $okOf 'OK (Edge updated 126.0.1 -> 127.0.2)') | Should Be $true
    }
}
