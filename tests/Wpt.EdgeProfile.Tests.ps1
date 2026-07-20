# =============================================================================
#  Wpt.EdgeProfile.Tests.ps1 - Pester 3.4 tests for the wpt 6.8.1 honest
#  'Microsoft Edge - Update' profile (roadmap item 1, loop 2).
#
#  The old Script ran MicrosoftEdgeUpdate.exe /ua and returned "OK (Edge update
#  triggered, exit N)" unconditionally - the same always-OK shape the Chrome
#  profiles lost in 6.5.33. Now: EdgeUpdate policy + service blocker pre-checks,
#  exe-first trigger (UA scheduled task fallback - Edge has no GoogleUpdater-
#  style migration), before/after version poll, staged new_msedge.exe
#  detection. Never a bare OK for an unverified trigger; unproven triggers
#  return PENDING* (wpt's classifier maps PENDING* to the amber Pending state).
#
#  Static-analysis scope only: profile table shape + script text + manifest
#  version. No host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.EdgeProfile.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

$profiles = & $m { Get-WptAppUpdateProfiles }
$name = 'Microsoft Edge - Update'

Describe 'WPT 6.8.2 - manifest loads at the bumped version' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is wpt and version is 6.8.2' {
        [string]$mani.id      | Should Be 'wpt'
        [string]$mani.version | Should Be '6.8.2'
    }
}

Describe 'WPT 6.8.2 - app-update audit books SKIP as Skipped, not Failure (loop-3 Opus P3-1)' {
    # A not-installed host (SKIP: from the honest Chrome/Edge Scripts) rendered
    # Skipped in the UI row but was booked as audit FAILURE - the AuditResultOf
    # map only special-cased Pending. Both non-attempt states now audit Skipped.
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'the AuditResultOf map sends both Pending and Skipped to the Skipped bucket' {
        $lit = '-eq ''Pending'' -or "$($r.Status)" -eq ''Skipped'') { ''Skipped'' }'
        ($moduleSrc.IndexOf($lit) -ge 0) | Should Be $true
    }
    It 'a genuine failure still books Failure (else-arm preserved)' {
        ($moduleSrc -match "else \{ 'Failure' \}") | Should Be $true
    }
}

Describe 'WPT 6.8.1 - honest Edge profile (registry shape)' {
    It 'still contains the Microsoft Edge - Update profile (name unchanged)' {
        $profiles.ContainsKey($name) | Should Be $true
    }
    It 'carries Script + Verify scriptblocks' {
        ($profiles[$name].Script -is [scriptblock]) | Should Be $true
        ($profiles[$name].Verify -is [scriptblock]) | Should Be $true
    }
    It 'Verify still reads the Edge Clients update GUID' {
        ("$($profiles[$name].Verify)" -match '56EB18F8-B008-4CBD-B6D2-8C97FE7E9062') | Should Be $true
    }
}

Describe 'WPT 6.8.1 - honest Edge Script (static analysis)' {
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
    It 'checks both Program Files updater exe locations' {
        ($net -match [regex]::Escape('C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe')) | Should Be $true
        ($net -match [regex]::Escape('C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe')) | Should Be $true
    }
    It 'detects a staged update via new_msedge.exe' {
        ($net -match 'new_msedge\.exe') | Should Be $true
    }
    It 'polls the installed version before/after and reports movement' {
        ($net -match 'Edge updated') | Should Be $true
        ($net -match 'PENDING') | Should Be $true
        ($net -match 'SKIP: Edge \(machine-level\) not installed') | Should Be $true
    }
    It 'does NOT contain the old unconditional "OK (Edge update triggered" string' {
        ($net -match [regex]::Escape('OK (Edge update triggered')) | Should Be $false
    }
    It 'routes every hard blocker to Software Center / MECM in its FAIL text' {
        ($net -match 'Software Center / MECM') | Should Be $true
    }
}
