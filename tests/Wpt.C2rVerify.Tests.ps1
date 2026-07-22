# =============================================================================
#  Wpt.C2rVerify.Tests.ps1 - Pester 3.4 for the honest M365 Click-to-Run verify
#  verdict (loop24, roadmap item 15). The M365 "Force Update" / "User Visible"
#  profiles decide "Verified" from the ClickToRun\Configuration registry key.
#  The old rule used ONLY the key's LastWriteTime freshness (<7 days), but C2R
#  bumps that key on EVERY update attempt INCLUDING failures - so a failed Force
#  Update read Verified=$true with the OLD, still-vulnerable version (a false-
#  clean). Now Verified is TRUE only when the key is fresh AND the last update
#  scenario SUCCEEDED (LastScenarioResult), $null when unknown (never over-claims).
#
#  Get-WptC2rVerified is the canonical verdict; the M365C2RVerify scriptblock
#  mirrors it inline (it runs remotely via Invoke-Command, can't call a module fn).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Wpt.C2rVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

function Get-Verdict {
    param([bool]$HasTs, [double]$Age, [string]$Result)
    (& $script:Mod { param($h, $a, $r) Get-WptC2rVerified -HasTimestamp $h -AgeDays $a -ScenarioResult $r } $HasTs $Age $Result)
}

Describe 'Get-WptC2rVerified - fresh + succeeded is the ONLY green' {
    It 'no timestamp -> $null (unknown)' {
        Get-Verdict $false 0 'Success' | Should Be $null
    }
    It 'stale key (>= 7 days) -> $false, even if the scenario says Success' {
        Get-Verdict $true 10 'Success' | Should Be $false
    }
    It 'fresh + LastScenarioResult Success -> $true' {
        Get-Verdict $true 2 'Success' | Should Be $true
    }
    It 'fresh but the last scenario FAILED -> $false (the false-clean fix)' {
        Get-Verdict $true 2 'Failure' | Should Be $false
    }
    It 'fresh but the scenario result is unknown/blank -> $null (never over-claims)' {
        Get-Verdict $true 2 '' | Should Be $null
    }
    It 'SuccessRebootRequired still counts as success' {
        Get-Verdict $true 2 'SuccessRebootRequired' | Should Be $true
    }
    It 'the success match is case-insensitive' {
        Get-Verdict $true 2 'success' | Should Be $true
    }
}

Describe 'wpt M365 C2R verify scriptblock - gates on the scenario result, not just mtime' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'the M365 verify reads LastScenarioResult' {
        ($moduleSrc -match 'LastScenarioResult') | Should Be $true
    }
}

Describe 'wpt - manifest version floor (honest C2R verify shipped in 6.8.8; exact pin migrated to newest bump)' {
    It 'wpt is at or past v6.8.8' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.8') | Should Be $true
    }
}

# loop87: the Chrome/Edge updater verify (New-WptUpdateClientVerify) had the SAME mtime-only false-clean the
# C2R verify above once had - a fresh Clients\{GUID} key read Verified=$true even with an OLD version after a
# failed/no-op update. Now it also reads the sibling ClientState\{GUID}\LastInstallerResult (0 = last install
# SUCCEEDED) and is fresh-AND-succeeded, byte-identical to acas Get-AcasClientVerified (proven behaviorally in
# Acas.ClientVerify.Tests.ps1). Static assertion on the generated remote scriptblock body.
Describe 'wpt Chrome/Edge verify scriptblock - gates on the install result, not just mtime (loop87)' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'the generated verify reads the sibling ClientState (LastCheckSuccess freshness + LastInstallerResult gate)' {
        ($moduleSrc -match "\`$csp = \`$p -replace '\\\\Clients\\\\', '\\ClientState\\'") | Should Be $true
        ($moduleSrc -match '\$cs\.LastCheckSuccess')                                      | Should Be $true
        ($moduleSrc -match '\$cs\.LastInstallerResult')                                   | Should Be $true
    }
    It 'the DEAD Get-Item .LastWriteTime read is GONE from New-WptUpdateClientVerify (loop88 - it was always null -> inert)' {
        $fn = [regex]::Match($moduleSrc, '(?s)function New-WptUpdateClientVerify.*?\[scriptblock\]::Create').Value
        ($fn -match '\$mod = \$key\.LastWriteTime')                                                       | Should Be $false
        ($fn -match '\$verified = if \(\$mod\) \{ \(\(Get-Date\) - \$mod\)\.TotalDays -lt 14 \}')          | Should Be $false
    }
    It 'the fresh-AND-success gate is present' {
        ($moduleSrc -match '\(\(Get-Date\) - \$mod\)\.TotalDays -ge 14') | Should Be $true
        ($moduleSrc -match '\[bool\]\(\$lastResult -eq 0\)')            | Should Be $true
    }
    It 'wpt manifest is at or past 6.8.17 (client-verify real-timestamp fix; exact pin migrated to newest bump)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'6.8.17') | Should Be $true
    }
}
