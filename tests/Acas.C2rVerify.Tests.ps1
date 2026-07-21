# =============================================================================
#  Acas.C2rVerify.Tests.ps1 - Pester 3.4 for the honest Office Click-to-Run verify
#  verdict (loop40, roadmap item35 Office-C2R slice; ported from wpt loop24/item15).
#  The 4 Office C2R app-update profiles decide "Verified" from the ClickToRun\
#  Configuration registry key. The old rule used ONLY the key's LastWriteTime
#  freshness (<7 days), but C2R bumps that key on EVERY update attempt INCLUDING
#  failures - so a failed Office update read Verified=$true with the OLD, still-
#  vulnerable version (a false-clean; a verify-only run then lit the PATCHED tile).
#  Now Verified is TRUE only when the key is fresh AND the last update scenario
#  SUCCEEDED (LastScenarioResult), $null when unknown (never over-claims).
#
#  Get-AcasC2rVerified is the canonical verdict; New-AcasOfficeC2RVerify's generated
#  remote scriptblock mirrors it inline (it runs over WinRM, can't call a module fn).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.C2rVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-Verdict {
    param([bool]$HasTs, [double]$Age, [string]$Result)
    (& $script:Mod { param($h, $a, $r) Get-AcasC2rVerified -HasTimestamp $h -AgeDays $a -ScenarioResult $r } $HasTs $Age $Result)
}

Describe 'Get-AcasC2rVerified - fresh + succeeded is the ONLY green' {
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

Describe 'acas Office C2R verify scriptblock - gates on the scenario result, not just mtime' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
    It 'the generated Office C2R verify reads LastScenarioResult' {
        ($moduleSrc -match 'LastScenarioResult') | Should Be $true
    }
    It 'the old mtime-only verdict (TotalDays -lt 7 as the whole test) is gone' {
        ($moduleSrc -match '\$verified = if \(\$mod\) \{ \(\(Get-Date\) - \$mod\)\.TotalDays -lt 7 \}') | Should Be $false
    }
}

Describe 'acas - manifest version floor (exact pin migrated to the newest bump: loop71 fan-out hint, v1.11.13)' {
    It 'acas is at least v1.11.12' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.12') | Should Be $true
    }
}
