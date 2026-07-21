# =============================================================================
#  Secureboot.Scan.Tests.ps1 - Pester 3.4 tests for the read-only fleet SCAN
#  added to JanetWeb.secureboot.psm1 in v1.6.0 (action 'scan-secure-boot').
#
#  All tests exercise the module contract WITHOUT any host contact:
#    * verdict derivation - Get-SbeScanVerdict is a pure function; the matrix
#      below pins on/off x UEFI/Legacy x GPT/MBR x supported/unsupported OEM.
#    * host-list parse    - ConvertTo-SecureBootHostList is reused by the scan
#      with NO 50-host cap (the cap lives only in the enable orchestrator).
#    * zero valid targets - the scan refuses (0 rows) before any WinRM fan-out.
#    * manifest contract  - scan-secure-boot is destructive=$false and the
#      existing enable-secure-boot action stays destructive=$true.
#  Internal (non-exported) functions are reached via  & $module { ... }  which
#  runs the block in module scope (same idiom as the self-guard test).
#
#  Run:  Invoke-Pester -Path .\tests\Secureboot.Scan.Tests.ps1
# =============================================================================
$script:Root   = Split-Path $PSScriptRoot -Parent
$script:SbeMod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru

# Collect the emitted 'row' events + return the action result (no host contact).
function Invoke-SbeScan {
    param([hashtable]$Params)
    $script:__rows = New-Object System.Collections.ArrayList
    $emit = { param($e) if ($e -and $e.type -eq 'row') { [void]$script:__rows.Add($e) } }
    $res = & $script:SbeMod {
        param($p, $cb)
        Invoke-JanetToolAction -ActionId 'scan-secure-boot' -Params $p -Emit $cb
    } $Params $emit
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows) }
}

# -----------------------------------------------------------------------------
Describe 'Secure Boot scan - verdict derivation matrix (Get-SbeScanVerdict)' {

    function Get-Verdict {
        param([string]$Sb, [string]$Fw, [string]$Disk, [string]$Mfr)
        & $script:SbeMod { param($a,$b,$c,$d) Get-SbeScanVerdict -SecureBoot $a -Firmware $b -Disk $c -Manufacturer $d } $Sb $Fw $Disk $Mfr
    }

    It 'Secure Boot ON -> ENABLED (regardless of the rest)' {
        (Get-Verdict 'On'  'UEFI'   'GPT' 'Dell')    | Should Be 'ENABLED'
        (Get-Verdict 'On'  'Legacy' 'MBR' 'Acme')    | Should Be 'ENABLED'
    }

    It 'OFF + UEFI + GPT + supported OEM (Dell/HP/Lenovo variants) -> READY TO ENABLE' {
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'Dell Inc.')        | Should Be 'READY TO ENABLE'
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'LENOVO')           | Should Be 'READY TO ENABLE'
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'HP')               | Should Be 'READY TO ENABLE'
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'Hewlett-Packard')  | Should Be 'READY TO ENABLE'
    }

    It 'OFF + UEFI + GPT + unsupported OEM -> OFF - UNSUPPORTED OEM' {
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'Microsoft Corporation') | Should Be 'OFF - UNSUPPORTED OEM'
        (Get-Verdict 'Off' 'UEFI' 'GPT' 'VMware, Inc.')          | Should Be 'OFF - UNSUPPORTED OEM'
    }

    It 'Legacy firmware OR MBR disk -> BLOCKED - LEGACY/MBR (never fed to the enabler)' {
        (Get-Verdict 'Off' 'Legacy' 'GPT' 'Dell') | Should Be 'BLOCKED - LEGACY/MBR'
        (Get-Verdict 'Off' 'UEFI'   'MBR' 'Dell') | Should Be 'BLOCKED - LEGACY/MBR'
        (Get-Verdict 'Off' 'Legacy' 'MBR' 'HP')   | Should Be 'BLOCKED - LEGACY/MBR'
    }

    It 'NotUEFI/Unsupported Secure Boot state -> BLOCKED - LEGACY/MBR' {
        (Get-Verdict 'NotUEFI/Unsupported' 'Unknown' 'Unknown' 'Dell') | Should Be 'BLOCKED - LEGACY/MBR'
    }

    It 'indeterminate Secure Boot state, or unconfirmable UEFI/GPT, -> CHECK ERROR (never called ready)' {
        (Get-Verdict 'Unknown' 'UEFI'    'GPT'     'Dell') | Should Be 'CHECK ERROR'
        (Get-Verdict 'Off'     'Unknown' 'GPT'     'Dell') | Should Be 'CHECK ERROR'
        (Get-Verdict 'Off'     'UEFI'    'Unknown' 'Dell') | Should Be 'CHECK ERROR'
    }
}

# -----------------------------------------------------------------------------
Describe 'Secure Boot scan - host-list parse reuse (no 50-host cap)' {

    It 'reuses ConvertTo-SecureBootHostList and parses a >50 host paste in full' {
        $big = (1..120 | ForEach-Object { "WS{0:D4}" -f $_ }) -join "`n"
        $n = & $script:SbeMod { param($b) (ConvertTo-SecureBootHostList $b).Count } $big
        $n | Should Be 120
    }

    It 'drops UNC/URL/leading-hyphen junk tokens' {
        $n = & $script:SbeMod { param($b) (ConvertTo-SecureBootHostList $b).Count } "\\evil\share`n../etc/passwd`n-badname`nhttp://x/y`nWS0001"
        $n | Should Be 1
    }
}

# -----------------------------------------------------------------------------
Describe 'Secure Boot scan - zero valid targets is refused before any fan-out' {

    It 'returns total=0 and no rows when every target is junk' {
        $out = Invoke-SbeScan -Params @{ targets = "\\evil\share`n../x`n-bad`nhttp://y" }
        [int]$out.Result.summary.total | Should Be 0
        @($out.Rows).Count | Should Be 0
    }

    It 'returns total=0 for an empty target string' {
        $out = Invoke-SbeScan -Params @{ targets = '' }
        [int]$out.Result.summary.total | Should Be 0
        @($out.Rows).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'Secure Boot scan - manifest contract' {

    $man = & $script:SbeMod { Get-JanetToolManifest }
    $scan   = @($man.actions | Where-Object { $_.id -eq 'scan-secure-boot' })[0]
    $enable = @($man.actions | Where-Object { $_.id -eq 'enable-secure-boot' })[0]

    It 'exposes scan-secure-boot as a read-only (destructive=$false) action' {
        $scan | Should Not BeNullOrEmpty
        [bool]$scan.destructive | Should Be $false
    }

    It 'scan advertises the specified columns and the scan inputs' {
        ($scan.columns -join ',') | Should Be 'Host,Ping,Verdict,SecureBoot,Firmware,Disk,Manufacturer,Model,Detail'
        @($scan.inputs | Where-Object { $_.name -eq 'targets' }).Count | Should Be 1
        @($scan.inputs | Where-Object { $_.name -eq 'threads' }).Count | Should Be 1
        @($scan.inputs | Where-Object { $_.name -eq 'attemptOffline' }).Count | Should Be 1
    }

    It 'leaves the enable-secure-boot action untouched at destructive=$true' {
        $enable | Should Not BeNullOrEmpty
        [bool]$enable.destructive | Should Be $true
    }

    It 'tool version is at least 1.6.0' {
        # Floor assert (wpt-suite precedent): the newest bump's own file
        # (the loop57 Describe below, v1.6.2) carries the exact pin; older files floor.
        ([version]$man.version -ge [version]'1.6.0') | Should Be $true
    }
}

# -----------------------------------------------------------------------------
# loop57 (P2): the enable worker polls a result JSON named from the hostname ALONE
# (SecureBoot_<host>.json) and pre-deletes a stale prior-run file best-effort. If that
# delete ever silently fails, the poll can replay an OLD SetResult=0 file as THIS run's
# Success. $taskName (SBE_<random>) is already per-run unique (it names $scriptFile);
# naming the result file with it too makes a cross-run filename collision impossible, so
# the poll can only ever read this run's own result. Static analysis (the worker is a
# module-less runspace scriptblock - not directly invokable without live SMB).
Describe 'secureboot 1.6.2 - enable result file is per-run unique (no stale-result replay)' {
    $man = & $script:SbeMod { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw

    It 'manifest version is at least 1.6.2 (floor; newest exact pin lives in ConfirmWord, loop58 v1.6.3)' {
        ([version][string]$man.version -ge [version]'1.6.2') | Should Be $true
    }
    It 'names the enable result JSON with the per-run-unique $taskName' {
        ($src -match '\$resultFile\s*=\s*"[^"]*\$\{taskName\}[^"]*\.json"') | Should Be $true
    }
    It 'no longer derives the result filename from the hostname alone' {
        ($src -match '\$resultFile\s*=\s*"SecureBoot_\$\{comp\}\.json"') | Should Be $false
    }
}
