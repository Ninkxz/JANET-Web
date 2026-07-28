# =============================================================================
#  Acas.ClientVerify.Tests.ps1 - Pester 3.4 for the honest Chrome/Edge updater
#  verify verdict (loop87). The Chrome/Edge app-update profiles decide "Verified"
#  from the Omaha/EdgeUpdate Clients\{GUID} registry key. The old rule used ONLY
#  that key's LastWriteTime freshness (< 14 days) - but Omaha/EdgeUpdate writes
#  Clients\{GUID} on every update CHECK, and a failed/no-op update leaves the OLD
#  pv, so a stale-but-recently-touched host read Verified=$true with an OLD, still-
#  vulnerable version (a false-clean; a verify-only run then lit the PATCHED tile).
#  This is the same class fixed for Office C2R in loop40. Now Verified is TRUE only
#  when the key is fresh AND the sibling ClientState\{GUID}\LastInstallerResult == 0
#  (the last install SUCCEEDED), $false when stale/failed, $null when no signal
#  (indeterminate - never over-claims).
#
#  Get-AcasClientVerified is the canonical verdict; New-AcasClientVerify's generated
#  remote scriptblock (and wpt's New-WptUpdateClientVerify) mirror it inline.
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.ClientVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-ClientVerdict {
    param([bool]$HasTs, [double]$Age, $Result)
    (& $script:Mod { param($h, $a, $r) Get-AcasClientVerified -HasTimestamp $h -AgeDays $a -LastInstallerResult $r } $HasTs $Age $Result)
}

Describe 'Get-AcasClientVerified - fresh + last-install-succeeded is the ONLY green' {
    It 'no timestamp -> $null (unknown)' {
        Get-ClientVerdict $false 0 0 | Should Be $null
    }
    It 'stale key (>= 14 days) -> $false, even if the last install succeeded' {
        Get-ClientVerdict $true 20 0 | Should Be $false
    }
    It 'fresh + LastInstallerResult 0 (success) -> $true' {
        Get-ClientVerdict $true 3 0 | Should Be $true
    }
    It 'fresh but the last install FAILED (non-zero result) -> $false (the false-clean fix)' {
        Get-ClientVerdict $true 3 1     | Should Be $false
        Get-ClientVerdict $true 3 1618  | Should Be $false
    }
    It 'fresh but NO ClientState install-result signal -> $null (never over-claims on mtime alone)' {
        Get-ClientVerdict $true 3 $null | Should Be $null
        Get-ClientVerdict $true 3 ''    | Should Be $null
    }
    It 'a string "0" registry value counts as success (REG_SZ tolerance)' {
        Get-ClientVerdict $true 3 '0' | Should Be $true
    }
}

Describe 'acas Chrome/Edge verify scriptblock - gates on the install result, not just mtime' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
    It 'the generated verify reads the sibling ClientState (LastCheckSuccess freshness + LastInstallerResult gate)' {
        ($moduleSrc -match "\`$csp = \`$p -replace '\\\\Clients\\\\', '\\ClientState\\'") | Should Be $true
        ($moduleSrc -match '\$cs\.LastCheckSuccess')                                      | Should Be $true
        ($moduleSrc -match '\$cs\.LastInstallerResult')                                   | Should Be $true
    }
    It 'the DEAD Get-Item .LastWriteTime read is GONE from New-AcasClientVerify (loop88: a RegistryKey has no LastWriteTime -> $mod was always null -> the verify was INERT)' {
        $fn = [regex]::Match($moduleSrc, '(?s)function New-AcasClientVerify.*?return \[scriptblock\]::Create').Value
        ($fn -match '\$mod = \$key\.LastWriteTime')                                                       | Should Be $false
        ($fn -match '\$verified = if \(\$mod\) \{ \(\(Get-Date\) - \$mod\)\.TotalDays -lt 14 \}')          | Should Be $false
    }
    It 'the fresh-AND-success gate is present (ge 14 -> false; else result -eq 0)' {
        ($moduleSrc -match '\(\(Get-Date\) - \$mod\)\.TotalDays -ge 14') | Should Be $true
        ($moduleSrc -match '\[bool\]\(\$lastResult -eq 0\)')            | Should Be $true
    }
}

# loop88 (P1, the test the loop-87 self-review said was missing): EXECUTE the generated probe against a REAL
# (sandbox HKCU) key. The loop-87 tests were static/canonical-only and never ran a probe, so they missed that
# $mod (from Get-Item .LastWriteTime, which does not exist on a RegistryKey) was ALWAYS $null -> Verified always
# $null / LastUpdated 'n/a'. This drives the acas AND wpt probes end-to-end.
Describe 'client verify probe EXECUTED against a real registry key (loop88 - catches the inert-verify class)' {
    $script:Base = 'HKCU:\Software\JanetWebTest_ClientVerify\Update'
    $script:Guid = '{9E8A0C1D-TEST}'
    $script:Wpt  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
    function Set-Sandbox { param([int64]$LcsAgeSec,$Lir,[bool]$WithClientState)
        Remove-Item 'HKCU:\Software\JanetWebTest_ClientVerify' -Recurse -Force -ErrorAction SilentlyContinue
        New-Item "$script:Base\Clients\$script:Guid" -Force | Out-Null
        New-ItemProperty "$script:Base\Clients\$script:Guid" -Name pv -Value '99.0.1' -PropertyType String -Force | Out-Null
        if ($WithClientState) {
            New-Item "$script:Base\ClientState\$script:Guid" -Force | Out-Null
            $lcs = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - $LcsAgeSec
            New-ItemProperty "$script:Base\ClientState\$script:Guid" -Name LastCheckSuccess -Value $lcs -PropertyType QWord -Force | Out-Null
            if ($null -ne $Lir) { New-ItemProperty "$script:Base\ClientState\$script:Guid" -Name LastInstallerResult -Value $Lir -PropertyType DWord -Force | Out-Null }
        }
    }
    function Get-AcasProbeResult { $sb = & $script:Mod { param($b,$g) New-AcasClientVerify -Guid $g -RootWow "$b\Clients" -Root "$b\Clients" } $script:Base $script:Guid; (& $sb) }
    function Get-WptProbeResult  { $sb = & $script:Wpt { param($b,$g) New-WptUpdateClientVerify -P1 "$b\Clients\$g" -P2 "$b\Clients\$g" } $script:Base $script:Guid; (& $sb) }

    It 'fresh check + last install SUCCEEDED -> Verified $true, LastUpdated is a REAL date (not n/a) - the inert bug is fixed' {
        Set-Sandbox -LcsAgeSec 3600 -Lir 0 -WithClientState $true
        $a = Get-AcasProbeResult
        $a.Verified   | Should Be $true
        $a.LastUpdated | Should Not Be 'n/a'
        $a.Version     | Should Be '99.0.1'
        (Get-WptProbeResult).Verified | Should Be $true
    }
    It 'fresh check + last install FAILED (LastInstallerResult != 0) -> Verified $false (the false-clean is now actually enforced)' {
        Set-Sandbox -LcsAgeSec 3600 -Lir 1 -WithClientState $true
        (Get-AcasProbeResult).Verified | Should Be $false
        (Get-WptProbeResult).Verified  | Should Be $false
    }
    It 'stale check (LastCheckSuccess > 14 days old) -> Verified $false' {
        Set-Sandbox -LcsAgeSec (20*86400) -Lir 0 -WithClientState $true
        (Get-AcasProbeResult).Verified | Should Be $false
    }
    It 'no ClientState key -> Verified $null (indeterminate, never a false-clean)' {
        Set-Sandbox -LcsAgeSec 3600 -Lir 0 -WithClientState $false
        (Get-AcasProbeResult).Verified | Should Be $null
    }
    It 'ClientState present but no LastInstallerResult -> Verified $null' {
        Set-Sandbox -LcsAgeSec 3600 -Lir $null -WithClientState $true
        (Get-AcasProbeResult).Verified | Should Be $null
        Remove-Item 'HKCU:\Software\JanetWebTest_ClientVerify' -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'acas - manifest version floor (exact pin migrated to the newest bump test)' {
    It 'acas manifest is at or past 1.11.21' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'1.11.21') | Should Be $true
    }
}

# audit 2026-07-28 (cross-fork drift slice): the MSXML 4.0 profile counted msiexec 1605
# as a removal. ERROR_UNKNOWN_PRODUCT means msiexec wrote NOTHING, and this profile
# never deletes the Uninstall key it enumerated - so the artifact Tenable 62758 reads
# survived, the host kept re-flagging, and the run still returned "removed=1 errors=0",
# which books a green row and a VulnPatched Success for a host nothing touched.
# Deliberately RECLASSIFIED rather than made to delete the key: this suite's own
# verify-and-clean rule (JanetWeb.wpt.psm1 $verifyClean, loop51/item45) permits removing
# an Uninstall key ONLY once the product's FILES are confirmed gone, and this profile
# carries no InstallLocation to establish that. 1605 also does not prove "not installed".
Describe 'acas 1.11.22 - MSXML 1605 is an honest error, not a phantom removal' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw

    It '1605 is no longer bucketed with the successes' {
        ($src -match '\$proc\.ExitCode -in 0,1605,3010') | Should Be $false
        ($src -match '\$proc\.ExitCode -in 0,3010')      | Should Be $true
    }
    It '1605 routes to $errors and says nothing was uninstalled' {
        ($src -match "elseif \(\`$proc\.ExitCode -eq 1605\)") | Should Be $true
        ($src -match 'MSI does not know this product \(1605\)') | Should Be $true
        ($src -match 'NOTHING was uninstalled')                 | Should Be $true
    }
    It 'the profile still does NOT delete the Uninstall key (the files-gone rule is respected)' {
        # guarding the deliberate choice: if someone later "completes" this fix by
        # pasting a key delete, they must also supply files-gone evidence first.
        $blk = [regex]::Match($src, "(?s)MSXML 4\.0.*?return `"OK \(\`$summary").Value
        ($blk -match 'Remove-Item') | Should Be $false
    }
    It 'acas manifest is exactly 1.11.22' {
        [string](& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '1.11.22'
    }
}
