# =============================================================================
#  WinUpgrade.Drive.Tests.ps1 - Pester 3.4 tests for the DESTRUCTIVE
#  'upgrade-drive' action on JanetWeb.winupgrade.psm1.
#
#  Proves the SAFETY invariants, NO real WinRM / no real reboot ever leaves box:
#   (1) the pure decision authority Get-WinUpgradeDrivePlan is unit-tested for
#       every skip/reboot branch + the DNS-guard abort. This is the single source
#       of truth the worker mirrors.
#   (2) the REAL per-host worker ($script:WinUpgradeWorker) is driven DIRECTLY in
#       module scope with Invoke-Command SHADOWED in the module (the
#       Sysadmin.Sweeps / Wpt.Guards idiom) - the shim feeds canned readiness /
#       pin / trigger / staged results and RECORDS (never executes) the reboot, so
#       the worker's real skip -> pin -> trigger -> re-read -> reboot wiring runs
#       against synthetic data. shutdown.exe is never called.
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.Drive.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

Describe 'winupgrade manifest exposes the destructive upgrade-drive action' {
    $mani = & $m { Get-JanetToolManifest }
    $act  = $mani.actions | Where-Object { $_.id -eq 'upgrade-drive' }

    It 'upgrade-drive is present, stream-table, destructive=true, with a confirm' {
        $act | Should Not BeNullOrEmpty
        $act.kind | Should Be 'stream-table'
        $act.destructive | Should Be $true
        [string]$act.confirm | Should Not BeNullOrEmpty
    }
    It 'carries the required inputs' {
        $names = @($act.inputs | ForEach-Object { $_.name })
        foreach ($n in 'targets','product','version','bypass','rebootWhenStaged','countdownSeconds','attemptOffline','dryRun','threads') {
            ($names -contains $n) | Should Be $true
        }
    }
    It 'exposes the drive row columns' {
        foreach ($c in 'Host','Online','OsBuild','DisplayVersion','WasPinned','TriggerResult','Staged','Rebooted','CountdownSec','Skipped','Error') {
            ($act.columns -contains $c) | Should Be $true
        }
    }
    It 'rebootWhenStaged defaults OFF' {
        $rw = $act.inputs | Where-Object { $_.name -eq 'rebootWhenStaged' }
        [bool]$rw.default | Should Be $false
    }
}

Describe 'Get-WinUpgradeDrivePlan pure decision authority' {
    It 'INVARIANT #2: build >= 26100 -> Skipped already 24H2+, no pin, no reboot' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 26100 -Eligible $true -RebootWhenStaged $true -Staged $true }
        $p.Skipped      | Should Be 'already 24H2+'
        $p.WouldPin     | Should Be $false
        $p.WouldTrigger | Should Be $false
        $p.ShouldReboot | Should Be $false
    }
    It 'INVARIANT #3: ineligible without bypass -> Skipped blocked, no reboot' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $false -BlockReason 'CPU unsupported; disk <64GB' -Bypass $false -RebootWhenStaged $true -Staged $true }
        $p.Skipped      | Should Be 'blocked (CPU unsupported; disk <64GB)'
        $p.WouldPin     | Should Be $false
        $p.ShouldReboot | Should Be $false
    }
    It 'ineligible WITH bypass -> not skipped, would pin+trigger' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $false -BlockReason 'CPU unsupported' -Bypass $true }
        $p.Skipped      | Should Be ''
        $p.WouldPin     | Should Be $true
        $p.WouldTrigger | Should Be $true
    }
    It 'INVARIANT #4: rebootWhenStaged but NOT staged -> ShouldReboot false (never reboot an un-staged host)' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $true -RebootWhenStaged $true -Staged $false }
        $p.WouldPin     | Should Be $true
        $p.ShouldReboot | Should Be $false
        $p.RebootAborted| Should Be $false
    }
    It 'INVARIANT #5a: rebootWhenStaged AND staged AND name matches -> ShouldReboot true with the countdown' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $true -RebootWhenStaged $true -Staged $true -CountdownSeconds 300 -ExpectedName 'WS-1' -LocalName 'WS-1' }
        $p.ShouldReboot | Should Be $true
        [int]$p.CountdownSec | Should Be 300
    }
    It 'INVARIANT #5b: staged+reboot but name MISMATCH -> reboot ABORTED (guard), ShouldReboot false' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $true -RebootWhenStaged $true -Staged $true -ExpectedName 'WS-1' -LocalName 'OTHER' }
        $p.ShouldReboot  | Should Be $false
        $p.RebootAborted | Should Be $true
        $p.RebootAbortReason | Should Match 'DNS mismatch'
    }
    It 'reboot NOT requested -> ShouldReboot false even when staged' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 22631 -Eligible $true -RebootWhenStaged $false -Staged $true }
        $p.ShouldReboot | Should Be $false
    }
}

Describe 'upgrade-drive worker end to end (shimmed Invoke-Command - no real WinRM / no real reboot)' {

    # Drive the REAL worker directly in module scope with Invoke-Command shadowed.
    # CpuPatterns/Cycles are passed as harmless scalars (only the shimmed read would
    # use them) to avoid PowerShell array-flattening in the positional arg list.
    function Invoke-DriveWorker {
        param(
            [string]$Computer, [int]$OsBuild = 22631, [string]$Report = '',
            [bool]$StagedAfter = $false, [bool]$Bypass = $false,
            [bool]$RebootWhenStaged = $false, [int]$Countdown = 300, [bool]$DryRun = $false
        )
        return & $m {
            param($Computer,$OsBuild,$Report,$StagedAfter,$Bypass,$RebootWhenStaged,$Countdown,$DryRun)
            Set-Variable -Name __ob    -Scope script -Value $OsBuild
            Set-Variable -Name __rep   -Scope script -Value $Report
            Set-Variable -Name __st    -Scope script -Value $StagedAfter
            Set-Variable -Name __calls -Scope script -Value (New-Object System.Collections.ArrayList)
            Set-Variable -Name __rbcd  -Scope script -Value $null
            function script:Invoke-Command {
                param($ComputerName,$ScriptBlock,$ArgumentList,$Authentication,$SessionOption,$ErrorAction,$Credential,$Session)
                $t = [string]$ScriptBlock
                if ($t -match 'SYSTEM INFO') {
                    [void]$script:__calls.Add('READ')
                    return [pscustomobject]@{ Report=$script:__rep; OsBuild=$script:__ob; DisplayVersion='23H2'; Pinned=$false; PinnedVersion=''; PendingReboot=$false }
                }
                if ($t -match 'PHASE:TRIGGER') { [void]$script:__calls.Add('TRIGGER'); return 'triggered: UsoClient StartScan, StartDownload, StartInstall' }
                if ($t -match 'PHASE:STAGED')  { [void]$script:__calls.Add('STAGED');  return ([pscustomobject]@{ Staged = [bool]$script:__st }) }
                if ($t -match 'PHASE:REBOOT')  { [void]$script:__calls.Add('REBOOT'); Set-Variable -Name __rbcd -Scope script -Value ([int]$ArgumentList[0]); return @{ ExitCode = 0; Error = '' } }
                if ($t -match 'doBypass')      { [void]$script:__calls.Add('PIN'); return 'ProductVersion=Windows 11; TargetReleaseVersionInfo=24H2' }
                return $null
            }
            try {
                $argl = @(
                    $Computer,'UpgradeDrive',$null,'Windows 11','24H2',
                    '','',$false,$false,$true,
                    $DryRun,$false,16384,$null,$null,
                    $false,$Bypass,$false,$true,
                    'x',4,64,'2.0','y',
                    $RebootWhenStaged,$Countdown,$script:WinUpgradePinBlock
                )
                $row = & $script:WinUpgradeWorker @argl
                return @{ Row = $row; Calls = @($script:__calls); RebootCd = $script:__rbcd }
            } finally {
                Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue
                Remove-Variable -Name __ob,__rep,__st,__calls,__rbcd -Scope script -ErrorAction SilentlyContinue
            }
        } $Computer $OsBuild $Report $StagedAfter $Bypass $RebootWhenStaged $Countdown $DryRun
    }

    It 'INVARIANT #2: a host already on 26100 -> Skipped, no PIN, no REBOOT' {
        $out = Invoke-DriveWorker -Computer 'WS-26100' -OsBuild 26100 -RebootWhenStaged $true -StagedAfter $true
        $out.Row.Status  | Should Be 'Skipped'
        $out.Row.Skipped | Should Be 'already 24H2+'
        ($out.Calls -contains 'PIN')    | Should Be $false
        ($out.Calls -contains 'REBOOT') | Should Be $false
        [bool]$out.Row.Rebooted | Should Be $false
    }

    It 'INVARIANT #3: an ineligible host WITHOUT bypass -> Skipped blocked, no PIN, no REBOOT' {
        $rep = "=== HARDWARE COMPATIBILITY ===`n[FAIL] CPU         : Bad CPU (not in supported list)`n[PASS] TPM         : v2.0`n[PASS] Disk        : 500 GB free"
        $out = Invoke-DriveWorker -Computer 'WS-BLOCKED' -OsBuild 22631 -Report $rep -Bypass $false -RebootWhenStaged $true -StagedAfter $true
        $out.Row.Status  | Should Be 'Skipped'
        $out.Row.Skipped | Should Match 'blocked'
        ($out.Calls -contains 'PIN')    | Should Be $false
        ($out.Calls -contains 'REBOOT') | Should Be $false
    }

    It 'INVARIANT #4: rebootWhenStaged=true but host NOT staged -> Rebooted=false, no REBOOT call' {
        $out = Invoke-DriveWorker -Computer 'WS-DRIVEN' -OsBuild 22631 -Report '[PASS] CPU`n[PASS] TPM`n[PASS] Disk' -RebootWhenStaged $true -StagedAfter $false
        ($out.Calls -contains 'PIN')     | Should Be $true    # eligible host IS pinned
        ($out.Calls -contains 'TRIGGER') | Should Be $true
        [bool]$out.Row.Staged   | Should Be $false
        [bool]$out.Row.Rebooted | Should Be $false
        ($out.Calls -contains 'REBOOT')  | Should Be $false
        $out.Row.Status | Should Be 'DRIVEN'
    }

    It 'INVARIANT #5: rebootWhenStaged=true AND host staged -> reboot path taken with the countdown' {
        $out = Invoke-DriveWorker -Computer 'WS-STAGED' -OsBuild 22631 -RebootWhenStaged $true -StagedAfter $true -Countdown 300
        ($out.Calls -contains 'PIN')     | Should Be $true
        ($out.Calls -contains 'REBOOT')  | Should Be $true
        [int]$out.RebootCd      | Should Be 300     # shutdown countdown asserted
        [bool]$out.Row.Rebooted | Should Be $true
        [int]$out.Row.CountdownSec | Should Be 300
        $out.Row.Status | Should Be 'REBOOTING'
    }

    It 'INVARIANT #6: dryRun=true -> nothing written / rebooted, reports WOULD-actions' {
        $out = Invoke-DriveWorker -Computer 'WS-DRY' -OsBuild 22631 -RebootWhenStaged $true -StagedAfter $true -DryRun $true
        ($out.Calls -contains 'READ')    | Should Be $true    # readiness read is safe/read-only
        ($out.Calls -contains 'PIN')     | Should Be $false
        ($out.Calls -contains 'TRIGGER') | Should Be $false
        ($out.Calls -contains 'REBOOT')  | Should Be $false
        $out.Row.Status | Should Be 'DRY-RUN'
        $out.Row.Detail | Should Match 'would pin'
        [bool]$out.Row.WasPinned | Should Be $false
    }

    It 'staged host but rebootWhenStaged OFF -> STAGED, not rebooted' {
        $out = Invoke-DriveWorker -Computer 'WS-STAGED2' -OsBuild 22631 -RebootWhenStaged $false -StagedAfter $true
        ($out.Calls -contains 'PIN')    | Should Be $true
        ($out.Calls -contains 'REBOOT') | Should Be $false
        [bool]$out.Row.Rebooted | Should Be $false
        $out.Row.Status | Should Be 'STAGED'
    }
}
