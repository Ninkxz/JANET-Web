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
    It 'the generated verify reads the sibling ClientState + LastInstallerResult' {
        ($moduleSrc -match "\`$csp = \`$p -replace '\\\\Clients\\\\', '\\ClientState\\'") | Should Be $true
        ($moduleSrc -match '\$cs\.LastInstallerResult')                                   | Should Be $true
    }
    It 'the old mtime-only verdict is GONE from New-AcasClientVerify (the Store-app EXPERIMENTAL probe at ~:628 is a separate mtime-only case, out of scope - no Omaha ClientState analog)' {
        $fn = [regex]::Match($moduleSrc, '(?s)function New-AcasClientVerify.*?return \[scriptblock\]::Create').Value
        ($fn -match '\$verified = if \(\$mod\) \{ \(\(Get-Date\) - \$mod\)\.TotalDays -lt 14 \}') | Should Be $false
    }
    It 'the fresh-AND-success gate is present (ge 14 -> false; else result -eq 0)' {
        ($moduleSrc -match '\(\(Get-Date\) - \$mod\)\.TotalDays -ge 14') | Should Be $true
        ($moduleSrc -match '\[bool\]\(\$lastResult -eq 0\)')            | Should Be $true
    }
}

Describe 'acas 1.11.16 - manifest exact pin (newest bump = loop87 client-verify false-clean fix)' {
    It 'acas manifest is exactly 1.11.16' {
        [string](& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '1.11.16'
    }
}
