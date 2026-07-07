# =============================================================================
#  Winupgrade.Diagnose24h2.Tests.ps1 - Pester 3.4 tests for the ENRICHED read-only
#  'diagnose' action on JanetWeb.winupgrade.psm1 (fleet-batch lessons: 23H2 -> 24H2,
#  8 boxes / 7 distinct root causes).
#
#  The diagnose scan runs ON the remote target in a bare pool runspace and cannot call
#  a module function, so its new decisions are MIRRORED inline; the DECIDABLE logic is
#  factored into pure, script-scope helpers (the same dual-tested pattern as
#  Get-WinUpgradeDrivePlan). These tests exercise ONLY those pure helpers + the static
#  manifest - no WinRM, no target contact, nothing is changed on any box:
#    - Get-WinUpgradeSetupErrSignatures : failure-signature table (exact prompt strings)
#    - Get-WinUpgradePauseClass         : expired (past) vs active (future) pause windows
#    - Get-WinUpgradeStagingClass       : (age, rollback-marker, process-running) staleness
#    - Test-WinUpgradeTrvHalfWritten    : half-written Target Release Version pin
#    - Test-WinUpgradeNonBootDriverClass: non-boot device-class membership (BootCritical FP)
#
#  Run:  Invoke-Pester -Path .\tests\Winupgrade.Diagnose24h2.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

Describe 'diagnose stays read-only and the registry description advertises the new coverage' {
    $mani = & $m { Get-JanetToolManifest }
    $act  = $mani.actions | Where-Object { $_.id -eq 'diagnose' }

    It 'diagnose is present, stream-table, destructive=false (changes NOTHING)' {
        $act | Should Not BeNullOrEmpty
        $act.kind | Should Be 'stream-table'
        $act.destructive | Should Be $false
    }
    It 'the description now mentions staging staleness, the signature table, BootCritical, SetupDiag + half-written pin' {
        [string]$act.description | Should Match 'STALE staging'
        [string]$act.description | Should Match '0x8007000E'
        [string]$act.description | Should Match 'BootCritical'
        [string]$act.description | Should Match 'SetupDiag'
        [string]$act.description | Should Match 'HALF-WRITTEN'
    }
}

Describe 'Get-WinUpgradeSetupErrSignatures - failure-signature table (exact prompt strings)' {
    It '0x000003F1 -> registry hive corrupt (REGISTRY_CORRUPT)' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'CSetupHost fatal 0x000003F1 during migrate' }
        @($r).Count | Should Be 1
        $r[0].Code    | Should Be 'REGISTRY_CORRUPT'
        $r[0].Message | Should Match 'registry hive corrupt'
        $r[0].Rec     | Should Match 'RestoreHealth'
    }
    It 'the "configuration registry database is corrupt" phrase also maps to REGISTRY_CORRUPT' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'The configuration registry database is corrupt.' }
        $r[0].Code | Should Be 'REGISTRY_CORRUPT'
    }
    It 'CBS_E_INVALID_PACKAGE -> component store broken (COMPONENT_STORE)' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'error CBS_E_INVALID_PACKAGE opening package' }
        $r[0].Code | Should Be 'COMPONENT_STORE'
    }
    It '"Failed to enumerate store capabilities" -> COMPONENT_STORE' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'Failed to enumerate store capabilities' }
        $r[0].Code | Should Be 'COMPONENT_STORE'
    }
    It 'FOD inventory + E_INVALIDARG (AND) -> COMPONENT_STORE only when BOTH present' {
        $both = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'FOD inventory failed with E_INVALIDARG' }
        @($both | Where-Object { $_.Code -eq 'COMPONENT_STORE' }).Count | Should Be 1
        $onlyOne = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'FOD inventory ran clean' }
        @($onlyOne).Count | Should Be 0
    }
    It '0x8007000E -> out of memory (OOM)' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'MEMORY 0x8007000E E_OUTOFMEMORY' }
        $r[0].Code | Should Be 'OOM'
        $r[0].Rec  | Should Match 'Set Page File'
    }
    It 'adammigrate.dll + 0x80070002 (AND) -> ADLDS_MIGRATE only when BOTH present' {
        $both = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'adammigrate.dll returned 0x80070002' }
        @($both | Where-Object { $_.Code -eq 'ADLDS_MIGRATE' }).Count | Should Be 1
        $onlyDll = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'adammigrate.dll loaded fine' }
        @($onlyDll | Where-Object { $_.Code -eq 'ADLDS_MIGRATE' }).Count | Should Be 0
    }
    It '0x800704C7 -> setup cancelled (SETUP_CANCELLED), cross-refs the pause check' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText 'operation cancelled 0x800704C7' }
        $r[0].Code | Should Be 'SETUP_CANCELLED'
        $r[0].Rec  | Should Match 'pause'
    }
    It 'a clean / empty log returns no signatures' {
        @(& $m { Get-WinUpgradeSetupErrSignatures -LogText 'setup completed successfully' }).Count | Should Be 0
        @(& $m { Get-WinUpgradeSetupErrSignatures -LogText '' }).Count | Should Be 0
    }
    It 'multiple distinct signatures in one log all surface' {
        $r = & $m { Get-WinUpgradeSetupErrSignatures -LogText '0x8007000E then later 0x800704C7' }
        $codes = @($r | ForEach-Object { $_.Code })
        ($codes -contains 'OOM')             | Should Be $true
        ($codes -contains 'SETUP_CANCELLED') | Should Be $true
    }
}

Describe 'Get-WinUpgradePauseClass - expired vs active pause windows' {
    $now = [datetime]'2026-07-07T12:00:00'
    It 'an End/Expiry time in the PAST -> Expired (lingering, clear it)' {
        (& $m { param($n) Get-WinUpgradePauseClass -ValueName 'PauseUpdatesExpiryTime' -Value '2026-01-01T00:00:00' -Now $n } $now) | Should Be 'Expired'
        (& $m { param($n) Get-WinUpgradePauseClass -ValueName 'PauseFeatureUpdatesEndTime' -Value '2025-06-01T00:00:00' -Now $n } $now) | Should Be 'Expired'
    }
    It 'an End/Expiry time in the FUTURE -> Active (a real block)' {
        (& $m { param($n) Get-WinUpgradePauseClass -ValueName 'PauseUpdatesExpiryTime' -Value '2099-01-01T00:00:00' -Now $n } $now) | Should Be 'Active'
    }
    It 'a Start-time value (no window end) -> Block (not classifiable past/future)' {
        (& $m { param($n) Get-WinUpgradePauseClass -ValueName 'PauseUpdatesStartTime' -Value '2099-01-01T00:00:00' -Now $n } $now) | Should Be 'Block'
    }
    It 'an unparseable End value -> Block' {
        (& $m { param($n) Get-WinUpgradePauseClass -ValueName 'PauseUpdatesExpiryTime' -Value 'not-a-date' -Now $n } $now) | Should Be 'Block'
    }
}

Describe 'Get-WinUpgradeStagingClass - (age, rollback-marker, process-running) staleness' {
    It 'a rollback marker -> Stale regardless of age (the 7-box field bug this prevents)' {
        (& $m { Get-WinUpgradeStagingClass -AgeHours 2  -RollbackMarker $true -SetupProcessRunning $false }) | Should Be 'Stale'
        (& $m { Get-WinUpgradeStagingClass -AgeHours 48 -RollbackMarker $true -SetupProcessRunning $false }) | Should Be 'Stale'
    }
    It 'a running setup process (no rollback) -> Active (genuinely mid-upgrade), even when old' {
        (& $m { Get-WinUpgradeStagingClass -AgeHours 2  -RollbackMarker $false -SetupProcessRunning $true }) | Should Be 'Active'
        (& $m { Get-WinUpgradeStagingClass -AgeHours 72 -RollbackMarker $false -SetupProcessRunning $true }) | Should Be 'Active'
    }
    It 'older than 24h with NO process and NO rollback -> Stale' {
        (& $m { Get-WinUpgradeStagingClass -AgeHours 25 -RollbackMarker $false -SetupProcessRunning $false }) | Should Be 'Stale'
    }
    It 'recent (<24h), no process, no rollback -> Recent (never "in progress")' {
        (& $m { Get-WinUpgradeStagingClass -AgeHours 2 -RollbackMarker $false -SetupProcessRunning $false }) | Should Be 'Recent'
    }
}

Describe 'Test-WinUpgradeTrvHalfWritten - half-written Target Release Version pin' {
    It 'TRV=1 but ProductVersion empty -> half-written (True)' {
        (& $m { Test-WinUpgradeTrvHalfWritten -TargetReleaseVersion 1 -ProductVersion '' -TargetReleaseVersionInfo '24H2' }) | Should Be $true
    }
    It 'TRV=1 but TargetReleaseVersionInfo empty -> half-written (True)' {
        (& $m { Test-WinUpgradeTrvHalfWritten -TargetReleaseVersion 1 -ProductVersion 'Windows 11' -TargetReleaseVersionInfo '' }) | Should Be $true
    }
    It 'TRV=1 with both set -> complete (False)' {
        (& $m { Test-WinUpgradeTrvHalfWritten -TargetReleaseVersion 1 -ProductVersion 'Windows 11' -TargetReleaseVersionInfo '24H2' }) | Should Be $false
    }
    It 'TRV not enabled (0) -> not a half-written pin (False)' {
        (& $m { Test-WinUpgradeTrvHalfWritten -TargetReleaseVersion 0 -ProductVersion '' -TargetReleaseVersionInfo '' }) | Should Be $false
    }
}

Describe 'Test-WinUpgradeNonBootDriverClass - non-boot device-class membership (BootCritical FP filter)' {
    It 'the known non-boot classes are members (case-insensitive)' {
        foreach ($c in 'HIDClass','Mouse','Keyboard','Media','Image','Printer','Camera','SoftwareDevice','Bluetooth') {
            (& $m { param($x) Test-WinUpgradeNonBootDriverClass -DriverClass $x } $c) | Should Be $true
        }
        (& $m { Test-WinUpgradeNonBootDriverClass -DriverClass 'hidclass' }) | Should Be $true
    }
    It 'a plausibly boot-relevant class is NOT a member' {
        foreach ($c in 'Net','DiskDrive','SCSIAdapter','System','Display') {
            (& $m { param($x) Test-WinUpgradeNonBootDriverClass -DriverClass $x } $c) | Should Be $false
        }
    }
    It 'an empty/missing class -> False (cannot claim false positive)' {
        (& $m { Test-WinUpgradeNonBootDriverClass -DriverClass '' }) | Should Be $false
    }
}
