# =============================================================================
#  WinUpgrade.StagingReboot.Tests.ps1 - Pester 3.4 for the upgrade-drive
#  reboot-when-staged staleness guard (loop36 / winupgrade deep-dive F2, item 27).
#  reboot-when-staged reboots a host the drive re-read as "staged" (a feature
#  update pending, awaiting reboot to complete). The re-read set Staged=true off a
#  BARE Test-Path of C:\$WINDOWS.~BT\Sources with NO staleness classification -
#  but a ROLLED-BACK 24H2 attempt leaves that tree behind while nothing is in
#  progress, so an un-staged host read staged and got rebooted (and came back on
#  23H2), weakening the "never reboot an un-staged host" invariant. The re-read
#  now CLASSIFIES the ~BT tree via Get-WinUpgradeStagingClass's rule (rollback
#  marker / age / setup process); only an Active/Recent staging counts as staged,
#  a Stale one does not.
#
#  The classifier decision is a pure tested helper; the local reboot gate
#  (Staged=false -> no reboot) is proven by WinUpgrade.Drive INVARIANT #4; this
#  file pins the classifier's REBOOT contract + that the re-read wires it in.
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.StagingReboot.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

function Get-Class([double]$AgeHours, [bool]$Rollback, [bool]$SetupRunning) {
    (& $script:Mod { param($a, $r, $s) Get-WinUpgradeStagingClass -AgeHours $a -RollbackMarker $r -SetupProcessRunning $s } $AgeHours $Rollback $SetupRunning)
}

Describe 'Get-WinUpgradeStagingClass - the reboot-when-staged contract' {
    It 'a rollback marker -> Stale (a rolled-back attempt is NOT reboot-worthy staging)' {
        Get-Class -AgeHours 1 -Rollback $true -SetupRunning $false | Should Be 'Stale'
    }
    It 'a running setup process -> Active (genuinely mid-upgrade, reboot-worthy)' {
        Get-Class -AgeHours 1 -Rollback $false -SetupRunning $true | Should Be 'Active'
    }
    It 'no process + older than 24h -> Stale (leftover tree, not reboot-worthy)' {
        Get-Class -AgeHours 48 -Rollback $false -SetupRunning $false | Should Be 'Stale'
    }
    It 'no process + recent -> Recent (may await reboot, reboot-worthy)' {
        Get-Class -AgeHours 2 -Rollback $false -SetupRunning $false | Should Be 'Recent'
    }
    It 'Stale is the ONLY class the drive must treat as un-staged (Active/Recent count)' {
        # the reboot gate treats staged = (class -ne 'Stale'); pin that Active/Recent are not Stale
        (Get-Class -AgeHours 1 -Rollback $false -SetupRunning $true) | Should Not Be 'Stale'
        (Get-Class -AgeHours 2 -Rollback $false -SetupRunning $false) | Should Not Be 'Stale'
    }
}

Describe 'upgrade-drive PHASE:STAGED re-read CLASSIFIES the ~BT tree (no bare Test-Path staged flag)' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw
    # isolate the PHASE:STAGED re-read scriptblock (up to the [pscustomobject]@{ Staged = ...} return)
    $block = ([regex]::Match($src, '(?s)PHASE:STAGED.*?\[pscustomobject\]@\{ Staged')).Value
    It 'the PHASE:STAGED re-read was isolated' {
        ($block.Length -gt 0) | Should Be $true
    }
    It 'it classifies the ~BT staging (references a rollback marker + Stale)' {
        ($block -match '(?i)rollback') | Should Be $true
        ($block -match "'Stale'") | Should Be $true
    }
}

Describe 'winupgrade - manifest version floor (staging-reboot guard shipped in 0.5.5; exact pin migrated to the newest bump)' {
    It 'winupgrade is at or past v0.5.5' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'0.5.5') | Should Be $true
    }
}
