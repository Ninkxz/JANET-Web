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
$msiName = 'Microsoft Edge - Update (Vendor MSI - Microsoft)'   # v6.10.0 vendor-direct push

Describe 'WPT - manifest loads at or above the Edge-port version' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is wpt and version is at least 6.8.2' {
        [string]$mani.id      | Should Be 'wpt'
        # Floor assert (wpt-suite precedent): the newest bump's own test file carries
        # the exact pin (loop 9: Wpt.SelfGuardApply pins 6.8.3); older files floor.
        ([version]$mani.version -ge [version]'6.8.2') | Should Be $true
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

Describe 'Vendor MSI (Microsoft direct push) profile - v6.10.0' {
    It 'the profile exists with Script + Verify scriptblocks' {
        $profiles.ContainsKey($msiName) | Should Be $true
        ($profiles[$msiName].Script -is [scriptblock]) | Should Be $true
        ($profiles[$msiName].Verify -is [scriptblock]) | Should Be $true
    }
    $msi = "$($profiles[$msiName].Script)"
    It 'queries the official Microsoft Edge enterprise update API' {
        ($msi -match [regex]::Escape('edgeupdates.microsoft.com/api/products')) | Should Be $true
        ($msi -match 'Invoke-RestMethod') | Should Be $true
    }
    It 'selects the newest Stable x64 MSI artifact' {
        ($msi -match "'Stable'") | Should Be $true
        ($msi -match "'x64'") | Should Be $true
        ($msi -match "ArtifactName") | Should Be $true
    }
    It 'force-installs via msiexec /i /qn from Microsoft''s CDN download' {
        ($msi -match 'Invoke-WebRequest') | Should Be $true
        ($msi -match 'msiexec') | Should Be $true
        ($msi -match '/qn') | Should Be $true
    }
    It 'verifies the vendor-published SHA256 before installing' {
        ($msi -match 'Get-FileHash') | Should Be $true
        ($msi -match 'SHA256 mismatch') | Should Be $true
    }
    It 'rejects a non-MSI (proxy page) via the OLE2 magic bytes' {
        ($msi -match '208,207,17,224') | Should Be $true
    }
    It 'SKIPs a host without Edge (upgrade-only intent) and Verify reads the Edge GUID' {
        ($msi -match 'SKIP: Edge \(machine-level\) not installed') | Should Be $true
        ("$($profiles[$msiName].Verify)" -match '56EB18F8-B008-4CBD-B6D2-8C97FE7E9062') | Should Be $true
    }
}
