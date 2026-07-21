# =============================================================================
#  Wpt.VerifyApp.Tests.ps1 - Pester 3.4 for the honest app-update-verify tally
#  (loop41, roadmap item41). The verify-app action runs a read-only Verify probe
#  per host; WptAppUpdateBlock sets Status='Verified' for ANY probe that returned
#  (regardless of the probe's Verified verdict). The OkOf keyed off that Status,
#  so a reachable host whose probe read Verified=No (stale, still on the vulnerable
#  version) or n/a (indeterminate) counted toward the "N verified" tally AND booked
#  a TouchHost Success audit - a false-clean: the verify tile/summary over-reported
#  a still-vulnerable host as verified. Now a verify row is OK only when the probe
#  CONFIRMED the host current (Verified=$true); a reachable-but-not-verified host is
#  audited Skipped (checked, not current - no action), unreachable/errored is Failure.
#
#  Get-WptVerifyOk is the pure ok predicate (mirrors acas Get-AcasVerifyRowStatus);
#  the verify-app handler's OkOf calls it and the AuditResultOf maps not-verified to
#  Skipped. Run:  Invoke-Pester -Path .\tests\Wpt.VerifyApp.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

function Get-Ok {
    param($Reachable, $Verified)
    (& $script:Mod { param($a,$b) Get-WptVerifyOk -Reachable $a -Verified $b } $Reachable $Verified)
}

Describe 'Get-WptVerifyOk - only a CONFIRMED-current host counts as verified' {
    It 'reachable + Verified $true -> ok' {
        Get-Ok $true $true | Should Be $true
    }
    It 'reachable but Verified $false (stale / still vulnerable) -> NOT ok (the false-clean fix)' {
        Get-Ok $true $false | Should Be $false
    }
    It 'reachable but Verified $null (indeterminate) -> NOT ok (never over-claims)' {
        Get-Ok $true $null | Should Be $false
    }
    It 'not reachable -> NOT ok, even if Verified somehow $true' {
        Get-Ok $false $true | Should Be $false
    }
}

Describe 'wpt verify-app handler - ok keys off the verdict, not "the probe ran"' {
    # Isolate the app-update-verify handler block (from its ActionId case to the next case).
    $blk = ([regex]::Match($script:Src, "(?s)'app-update-verify'\s*\{.*?'app-update-apply'")).Value
    It 'the verify-app handler block was isolated' {
        ($blk.Length -gt 0) | Should Be $true
    }
    It 'the OkOf calls Get-WptVerifyOk (not the old Status -eq Verified)' {
        ($blk -match 'Get-WptVerifyOk \$r\.Reachable \$r\.Verified') | Should Be $true
    }
    It 'the old Status-only ok predicate is gone from the verify-app OkOf' {
        ($blk -match "OkOf \{ param\(\`$r\) \(\`$r\.Reachable -and \`$r\.Status -eq 'Verified'\) \}") | Should Be $false
    }
    It 'a reachable-but-not-verified host audits Skipped, not Failure' {
        ($blk -match "elseif \(\`$r\.Reachable -and .*Status.*-eq 'Verified'\) \{ 'Skipped' \}") | Should Be $true
    }
}

Describe 'wpt - manifest version floor (honest verify tally shipped in 6.8.9; exact pin migrated to newest bump)' {
    It 'wpt is at or past v6.8.9' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.9') | Should Be $true
    }
}
