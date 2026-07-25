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

# -----------------------------------------------------------------------------
# loop59 (item62): 'AlreadyPending' (host already staged pending-reboot; this run wrote
# nothing) resolved to 'Success', so a re-run booked a fresh VulnPatched/Success/itemCount=1
# audit and counted into "N enabled". It must resolve to 'Skipped'. Static analysis (the
# resolvedStatus mapping is inline in the module-less runspace worker scriptblock).
Describe 'secureboot 1.6.4 - AlreadyPending resolves to Skipped, not Success (no re-run audit inflation)' {
    $man = & $script:SbeMod { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw

    It 'manifest version is at least 1.6.4 (floor; newest exact pin = loop76 hint Describe, v1.6.5)' {
        ([version][string]$man.version -ge [version]'1.6.4') | Should Be $true
    }
    It 'the resolvedStatus chain maps SetResult AlreadyPending to Skipped' {
        ($src -match "elseif\s*\(\s*\`$result\.SetResult\s*-eq\s*'AlreadyPending'\s*\)\s*\{\s*'Skipped'\s*\}") | Should Be $true
    }
    It 'a non-Success (incl. Skipped) row books itemCount 0 - so a Skipped AlreadyPending is not a false patch' {
        ($src -match '\$itemCount\s*=\s*if\s*\(\s*\$isOk\s*\)\s*\{\s*1\s*\}\s*else\s*\{\s*0\s*\}') | Should Be $true
        ($src -match '\$isSkip\s*=\s*\(\s*\$status\s*-eq\s*''Skipped''\s*\)') | Should Be $true
    }
}

# loop76 (informative-failures theme): the secureboot ENABLE (destructive) harvest now, on a real
# enable failure (not ok/skip/unknown/dry-run), runs the raw error through Get-JanetTroubleshootHint
# and attaches the hint to a Hint row field + appends it to the err log (FIX:), raw error preserved.
# Static analysis (the harvest runs inside the fan-out over a real RunspacePool).
Describe 'secureboot - manifest version floor (loop76 enable-harvest hint in 1.6.5; exact pin migrated to newest bump)' {
    $man = & $script:SbeMod { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw

    It 'manifest version is at or past 1.6.5' {
        ([version][string]$man.version -ge [version]'1.6.5') | Should Be $true
    }
    It 'secureboot imports the shared troubleshoot engine' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1') | Should Be $true
    }
    It 'the enable harvest computes a hint only for a real failure and attaches it to the row' {
        # audit 2026-07-24: `-and (-not $isRefused)` joined the guard - a safety refusal is
        # not a failure, and its Error already names the exact precondition to fix.
        ($src -match '\$hint\s*=\s*if\s*\(\(-not \$isOk\)\s*-and\s*\(-not \$isSkip\)\s*-and\s*\(-not \$isUnknown\)\s*-and\s*\(-not \$isRefused\)\s*-and\s*\(-not \$isDryR\)\s*-and\s*\$res\.Error\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($src -match 'Error        = \[string\]\$res\.Error\s*\r?\n\s*Hint         = \[string\]\$hint') | Should Be $true
    }
    It 'the enable err log appends the FIX hint when one exists' {
        ($src -match "if \(\`$hint\) \{ ' \| FIX: ' \+ \`$hint \}") | Should Be $true
    }
}

# loop80 (informative-failures follow-up): the READ-ONLY scan harvest ($emitResult in Invoke-SbeScanAction)
# now, on a host-level CHECK ERROR (verdict = the host status, carrying the raw probe/session/DNS error in
# $detail), runs it through Get-JanetTroubleshootHint and attaches the hint to a Hint row field + an err log
# (FIX:), raw detail preserved. OFFLINE/DNS MISMATCH already carry a complete detail, so the hint is scoped
# to CHECK ERROR. Static analysis (the scan harvest runs inside the fan-out over a real RunspacePool).
Describe 'secureboot 1.6.6 - scan harvest attaches a troubleshooting hint to a CHECK ERROR host' {
    $man = & $script:SbeMod { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw

    It 'manifest version is at least 1.6.7 (floor; newest exact pin = audit 2026-07-25 BitLockerRefuse, v1.6.9)' {
        ([version][string]$man.version -ge [version]'1.6.7') | Should Be $true
    }
    It 'the scan harvest computes a hint only for a host-level CHECK ERROR and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\$verdict\s*-eq\s*''CHECK ERROR''\s*-and\s*\$hostStatus\s*-ne\s*''OK''\s*-and\s*\$detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($src -match 'Detail=\$detail;\s*Hint=\[string\]\$hint') | Should Be $true
    }
    It 'the scan err log carries the FIX hint when one exists (raw detail preserved)' {
        ($src -match "if \(\`$hint\) \{ &\s*\`$send @\{ type='log'; level='err'") | Should Be $true
        ($src -match 'FIX: \$hint')                                              | Should Be $true
    }
}
