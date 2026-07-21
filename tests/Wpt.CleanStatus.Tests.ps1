# =============================================================================
#  Wpt.CleanStatus.Tests.ps1 - Pester 3.4 for the clean-user-apps host status
#  (Get-WptCleanStatus, loop50 / wpt deep-dive item44). A live Clean User Apps run
#  deletes app binaries (Chrome/Firefox/Zoom/Teams/Webex) from every user profile;
#  the worker counts $found paths that existed and $removed that were actually
#  deleted (a locked/running app throws -> ERR event, NOT counted removed). The row
#  Status was UNCONDITIONALLY 'Success' on a live run, so a host where every deletion
#  FAILED (e.g. Chrome running in all profiles -> found>0, removed=0) read Success,
#  lit the ok tile, and booked a VulnPatched Success audit while nothing was removed.
#  Now: nothing found or all removed -> Success; some removed -> Partial; found but
#  none removed -> Failed. The action's OkOf accepts only Success/Dry Run OK, and the
#  fan-out audits a non-ok host as Failure - so Partial/Failed drop out of the clean
#  bucket automatically.
#
#  Get-WptCleanStatus is the pure canonical status; the module-less worker mirrors it
#  inline. Run:  Invoke-Pester -Path .\tests\Wpt.CleanStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

function Get-Status {
    param([int]$Found, [int]$Removed, [bool]$DryRun)
    (& $script:Mod { param($f,$r,$d) Get-WptCleanStatus -Found $f -Removed $r -DryRun $d } $Found $Removed $DryRun)
}

Describe 'Get-WptCleanStatus - a live clean is Success only when it actually removed what it found (item44 fix)' {
    It 'found > 0 but removed 0 (every delete failed/locked) -> Failed, NOT Success (the false-clean)' {
        Get-Status -Found 5 -Removed 0 -DryRun $false | Should Be 'Failed'
    }
    It 'found > removed > 0 (some failed) -> Partial, not Success' {
        Get-Status -Found 5 -Removed 3 -DryRun $false | Should Be 'Partial'
    }
    It 'all found paths removed -> Success' {
        Get-Status -Found 5 -Removed 5 -DryRun $false | Should Be 'Success'
    }
    It 'nothing found to clean -> Success (no apps present is a legit clean state)' {
        Get-Status -Found 0 -Removed 0 -DryRun $false | Should Be 'Success'
    }
    It 'a dry run is always Dry Run OK (preview, no deletion)' {
        Get-Status -Found 5 -Removed 0 -DryRun $true | Should Be 'Dry Run OK'
    }
}

Describe 'wpt clean-user-apps - the honest statuses drop out of the ok/audit bucket' {
    It 'the action OkOf accepts only Success / Dry Run OK (Partial + Failed are not ok)' {
        ($script:Src -match "OkOf \{ param\(\`$r\) \(\`$r\.Status -eq 'Success' -or \`$r\.Status -eq 'Dry Run OK'\) \}") | Should Be $true
    }
    It 'the clean-user-apps worker gates Success on actual removals (removed >= found), not an unconditional Success' {
        # (the sibling disk-cleanup/maintenance worker keeps its own unconditional Success - different
        # semantics: a best-effort locked-profile skip is still a successful maintenance run.)
        ($script:Src -match "elseif \(\[int\]\`$res\.Removed -ge \[int\]\`$res\.Found\)\s*\{ 'Success' \}") | Should Be $true
    }
}

Describe 'wpt - manifest version floor (clean-user-apps honest status shipped in 6.8.12; exact pin migrated)' {
    It 'wpt is at or past v6.8.12' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.12') | Should Be $true
    }
}
