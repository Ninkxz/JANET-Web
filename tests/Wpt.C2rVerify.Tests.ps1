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
