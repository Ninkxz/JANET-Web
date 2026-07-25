# =============================================================================
#  Winupgrade.OsAudit.Tests.ps1 - Pester 3.4 tests for the read-only 'os-audit'
#  action on JanetWeb.winupgrade.psm1 (the OS Version audit rule - NO partial state).
#
#  Coverage:
#   (1) manifest exposes os-audit as a read-only stream-table (destructive=$false)
#       with the documented 11 columns.
#   (2) the PURE decision authority Get-WinUpgradeOsAuditVerdict is unit-tested for
#       the full verdict matrix (the single source of truth the worker mirrors).
#   (3) the REAL per-host worker ($script:WinUpgradeWorker) is driven DIRECTLY in
#       module scope with Invoke-Command SHADOWED (the Drive / Sysadmin.Sweeps idiom)
#       to feed canned registry reads - proving the inline mirror + row shaping match
#       the pure helper. No real WinRM ever leaves the box.
#
#  Run:  Invoke-Pester -Path .\tests\Winupgrade.OsAudit.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
# -----------------------------------------------------------------------------
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru
Add-ShimGuard $m

Describe 'winupgrade manifest exposes the read-only os-audit action' {
    $mani = & $m { Get-JanetToolManifest }
    $act  = $mani.actions | Where-Object { $_.id -eq 'os-audit' }

    It 'os-audit is present, stream-table, destructive=false (read-only), no confirm' {
        $act | Should Not BeNullOrEmpty
        $act.kind | Should Be 'stream-table'
        $act.destructive | Should Be $false
        [string]$act.confirm | Should BeNullOrEmpty
    }
    It 'exposes the 11 audit row columns' {
        foreach ($c in 'Host','Online','Generation','ReleaseId','Edition','Gen11','Rel24H2','EntEdition','Verdict','Failed','Error') {
            ($act.columns -contains $c) | Should Be $true
        }
    }
    It 'the winupgrade manifest is version-bumped to 0.5.1 (or newer)' {
        [version]$mani.version -ge [version]'0.5.1' | Should Be $true
    }
}

Describe 'Get-WinUpgradeOsAuditVerdict - the three-check audit rule (no partial state)' {

    It 'Win11 26100 Enterprise => PASS (all three pass), empty Failed list' {
        $v = & $m { Get-WinUpgradeOsAuditVerdict -CurrentBuild 26100 -EditionID 'Enterprise' }
        $v.Gen11      | Should Be 'PASS'
        $v.Rel24H2    | Should Be 'PASS'
        $v.EntEdition | Should Be 'PASS'
        $v.Verdict    | Should Be 'PASS'
        [string]$v.Failed | Should Be ''
    }

    It 'Win11 26100 Pro => FAIL on EntEdition only' {
        $v = & $m { Get-WinUpgradeOsAuditVerdict -CurrentBuild 26100 -EditionID 'Professional' }
        $v.EntEdition | Should Be 'FAIL'
        $v.Verdict    | Should Be 'FAIL'
        $v.Failed     | Should Be 'EntEdition'
    }

    It 'Win11 22631 (23H2) Enterprise => FAIL on Rel24H2 only (Gen11 passes, edition passes)' {
        $v = & $m { Get-WinUpgradeOsAuditVerdict -CurrentBuild 22631 -EditionID 'Enterprise' }
        $v.Gen11      | Should Be 'PASS'
        $v.Rel24H2    | Should Be 'FAIL'
        $v.EntEdition | Should Be 'PASS'
        $v.Verdict    | Should Be 'FAIL'
        $v.Failed     | Should Be 'Rel24H2'
    }

    It 'Win10 19045 Enterprise => FAIL on Gen11 AND Rel24H2 (order preserved)' {
        $v = & $m { Get-WinUpgradeOsAuditVerdict -CurrentBuild 19045 -EditionID 'Enterprise' }
        $v.Gen11   | Should Be 'FAIL'
        $v.Rel24H2 | Should Be 'FAIL'
        $v.Verdict | Should Be 'FAIL'
        $v.Failed  | Should Be 'Gen11, Rel24H2'
    }

    It 'Enterprise multi-session 26100 (EnterpriseS variant) => FAIL EntEdition (only exact Enterprise passes)' {
        foreach ($ed in 'EnterpriseS','ServerRdsh','IoTEnterprise','Enterprise multi-session') {
            $v = & $m { param($e) Get-WinUpgradeOsAuditVerdict -CurrentBuild 26100 -EditionID $e } $ed
            $v.EntEdition | Should Be 'FAIL'
            $v.Verdict    | Should Be 'FAIL'
            $v.Failed     | Should Be 'EntEdition'
        }
    }

    It '25H2 (26200) Enterprise => PASS (newer than 24H2 still passes Rel24H2)' {
        $v = & $m { Get-WinUpgradeOsAuditVerdict -CurrentBuild 26200 -EditionID 'Enterprise' }
        $v.Verdict | Should Be 'PASS'
    }
}

Describe 'os-audit worker end to end (shimmed Invoke-Command - no real WinRM)' {

    # Drive the REAL worker directly with Invoke-Command shadowed to return a canned
    # CurrentVersion read. AttemptOffline is forced $true so the worker proceeds past
    # the (fake-host) reachability probe into the audit branch. CpuPatterns/Cycles are
    # harmless scalars (os-audit never uses them).
    function Invoke-OsAuditWorker {
        param([string]$Computer, [int]$Build, [string]$Edition, [string]$Display = '')
        return & $m {
            param($Computer, $Build, $Edition, $Display)
            Set-Variable -Name __b -Scope script -Value $Build
            Set-Variable -Name __e -Scope script -Value $Edition
            Set-Variable -Name __d -Scope script -Value $Display
            $__shims = Save-ShimState @('Invoke-Command')
            function script:Invoke-Command {
                param($ComputerName,$ScriptBlock,$ArgumentList,$Authentication,$SessionOption,$ErrorAction,$Credential,$Session,$Port,$UseSSL)
                $t = [string]$ScriptBlock
                if ($t -match 'CurrentBuild' -or $t -match 'EditionID') {
                    return [pscustomobject]@{
                        CurrentBuild   = $script:__b
                        UBR            = 100
                        DisplayVersion = $script:__d
                        ReleaseId      = ''
                        EditionID      = $script:__e
                        ProductName    = 'Windows 11 ' + $script:__e
                    }
                }
                return $null
            }
            try {
                $argl = @($Computer,'OsAudit',$null,'','','','',$false,$false,$true)
                $row = & $script:WinUpgradeWorker @argl
                return $row
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
                Remove-Variable -Name __b,__e,__d -Scope script -ErrorAction SilentlyContinue
            }
        } $Computer $Build $Edition $Display
    }

    It 'a Win11 26100 Enterprise host -> Verdict PASS, all checks PASS, Generation Windows 11' {
        $row = Invoke-OsAuditWorker -Computer 'WS-ENT' -Build 26100 -Edition 'Enterprise' -Display '24H2'
        $row.Verdict    | Should Be 'PASS'
        $row.Gen11      | Should Be 'PASS'
        $row.Rel24H2    | Should Be 'PASS'
        $row.EntEdition | Should Be 'PASS'
        $row.Generation | Should Be 'Windows 11'
        $row.ReleaseId  | Should Be '24H2'
        [bool]$row.Online | Should Be $true
    }

    It 'a Win11 26100 Pro host -> Verdict FAIL, Failed lists EntEdition' {
        $row = Invoke-OsAuditWorker -Computer 'WS-PRO' -Build 26100 -Edition 'Professional' -Display '24H2'
        $row.Verdict    | Should Be 'FAIL'
        $row.EntEdition | Should Be 'FAIL'
        $row.Failed     | Should Be 'EntEdition'
    }

    It 'a Win10 19045 Enterprise host -> Verdict FAIL, Failed lists Gen11 + Rel24H2, Generation Windows 10' {
        $row = Invoke-OsAuditWorker -Computer 'WS-W10' -Build 19045 -Edition 'Enterprise' -Display '22H2'
        $row.Verdict    | Should Be 'FAIL'
        $row.Failed     | Should Be 'Gen11, Rel24H2'
        $row.Generation | Should Be 'Windows 10'
    }
}
