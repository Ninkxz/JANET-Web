# =============================================================================
#  Acas.ChromeProfile.Tests.ps1 - Pester 3.4 tests for the ACAS 1.11.4 honest
#  Chrome updater profile + the update-worker verdict passthrough.
#
#  Defect 1 (the "always-OK" chip, open since the wpt 6.5.33 split): acas's
#  copied 'Google Chrome - Update' profile still ran GoogleUpdate.exe /ua and
#  returned "OK (Chrome update triggered, exit N)" unconditionally - blind to
#  update policy blocks, disabled services, and the GoogleUpdater migration
#  (where GoogleUpdate.exe no longer exists). Ported the wpt honest Script:
#  blocker pre-checks, GoogleUpdaterTaskSystem*-first trigger, before/after
#  version poll, staged new_chrome.exe detection. Unproven triggers return the
#  acas-native UNCONFIRMED (never wpt's PENDING, which $script:AcasOkOf would
#  classify as a green OK).
#
#  Defect 2 (worker rewrap): $script:AcasUpdateWorker rewrapped ANY result
#  whose pre/post version probe came back unchanged as "UNCONFIRMED: version
#  unchanged after update (async update may still be in progress)" - including
#  hard FAILs from the profile Script (policy-block, updater missing). A
#  PERMANENT blocker rendered amber "maybe still in progress", for every
#  profile. Now FAIL*/SKIP*/UNCONFIRMED* Script results pass through
#  (markers appended) before the async rewrap; only OK-claiming Scripts still
#  need probe proof.
#
#  Static-analysis scope only: profile table shape + script text + worker text
#  + match-table routing + manifest version. No host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.ChromeProfile.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

$profiles = & $m { $script:AcasUpdateProfiles }
$name     = 'Google Chrome - Update'
$scName   = 'Google Chrome - Software Center'

Describe 'ACAS 1.11.4 - manifest loads at the bumped version' {
    $manifest = & $m { Get-JanetToolManifest }
    It 'manifest id is acas and version is at least 1.11.4' {
        [string]$manifest.id      | Should Be 'acas'
        # Floor assert (wpt-suite precedent 2026-07-16): the newest bump's own
        # test file carries the exact pin; older files assert a floor.
        ([version]$manifest.version -ge [version]'1.11.4') | Should Be $true
    }
}

Describe 'ACAS 1.11.4 - honest Chrome profile (registry shape)' {
    It 'still contains the Google Chrome - Update profile (name unchanged, match table intact)' {
        $profiles.ContainsKey($name) | Should Be $true
    }
    It 'still contains the Software Center alternate' {
        $profiles.ContainsKey($scName) | Should Be $true
    }
    It 'carries Script + Verify scriptblocks' {
        ($profiles[$name].Script -is [scriptblock]) | Should Be $true
        ($profiles[$name].Verify -is [scriptblock]) | Should Be $true
    }
    It 'Verify still reads the Chrome Clients update GUID (New-AcasClientVerify)' {
        ("$($profiles[$name].Verify)" -match '8A69D345-D564-463c-AFF1-A69D9E530F96') | Should Be $true
    }
    It 'the match table still routes Google Chrome findings to Update then Software Center' {
        $rules = & $m { Get-AcasProfileMatchTable }
        $rule = @($rules | Where-Object { $_.Keywords -contains 'Google Chrome' })[0]
        @($rule.Profiles)[0] | Should Be $name
        @($rule.Profiles)[1] | Should Be $scName
    }
}

Describe 'ACAS 1.11.4 - honest Chrome Script (static analysis)' {
    $net = "$($profiles[$name].Script)"
    It 'pre-checks the Google Update policy key before triggering anything' {
        ($net -match [regex]::Escape('Policies\Google\Update')) | Should Be $true
    }
    It 'pre-checks the legacy gupdate service state' {
        ($net -match 'gupdate') | Should Be $true
    }
    It 'prefers the modern GoogleUpdaterTaskSystem scheduled task' {
        ($net -match 'GoogleUpdaterTaskSystem') | Should Be $true
        ($net -match 'Start-ScheduledTask') | Should Be $true
    }
    It 'detects a staged update via new_chrome.exe' {
        ($net -match 'new_chrome\.exe') | Should Be $true
    }
    It 'polls the installed version before/after and reports movement' {
        ($net -match 'Chrome updated') | Should Be $true
        ($net -match 'SKIP: Chrome \(machine-level\) not installed') | Should Be $true
    }
    It 'does NOT contain the old unconditional "OK (Chrome update triggered" string' {
        ($net -match [regex]::Escape('OK (Chrome update triggered')) | Should Be $false
    }
    It 'unproven triggers return the acas-native UNCONFIRMED, never wpt''s PENDING' {
        ($net -match 'UNCONFIRMED') | Should Be $true
        ($net -match 'PENDING') | Should Be $false
    }
    It 'routes every hard blocker to the Software Center profile in its FAIL text' {
        ($net -match [regex]::Escape("use the 'Google Chrome - Software Center' profile")) | Should Be $true
    }
}

Describe 'ACAS 1.11.4 - AcasOkOf classifies every honest-Script state NOT-green except a proven bump' {
    $okOf = & $m { $script:AcasOkOf }
    It 'a policy-block FAIL is not green' {
        (& $okOf "FAIL: Chrome auto-update blocked by policy (HKLM\SOFTWARE\Policies\Google\Update) - use the 'Google Chrome - Software Center' profile") | Should Be $false
    }
    It 'a staged-update UNCONFIRMED is not green' {
        (& $okOf 'UNCONFIRMED: update staged as new_chrome.exe - applies when Chrome is next relaunched (still v138.0.1 now)') | Should Be $false
    }
    It 'a triggered-but-unmoved UNCONFIRMED is not green' {
        (& $okOf 'UNCONFIRMED: update triggered via legacy GoogleUpdate.exe /ua; version still 138.0.1 after 90s') | Should Be $false
    }
    It 'a proven version bump stays green' {
        (& $okOf 'OK (Chrome updated 138.0.1 -> 139.0.2)') | Should Be $true
    }
}

Describe 'ACAS 1.11.4 - update-worker verdict passthrough (Script self-classification is authoritative)' {
    $worker = & $m { "$script:AcasUpdateWorker" }
    It 'passes FAIL*/SKIP*/UNCONFIRMED* Script results through with markers appended' {
        ($worker -match "-like 'FAIL\*'") | Should Be $true
        ($worker -match "-like 'SKIP\*'") | Should Be $true
        ($worker -match "-like 'UNCONFIRMED\*'") | Should Be $true
    }
    It 'the passthrough sits BEFORE the async "version unchanged" rewrap' {
        $pass   = $worker.IndexOf("`$updateStr -like 'FAIL*'")
        $rewrap = $worker.IndexOf('version unchanged after update')
        ($pass -ge 0) | Should Be $true
        ($rewrap -ge 0) | Should Be $true
        ($pass -lt $rewrap) | Should Be $true
    }
    It 'the passthrough sits BEFORE the thrown-probe UNCONFIRMED wrap (a hard FAIL outranks a probe error)' {
        $pass  = $worker.IndexOf("`$updateStr -like 'FAIL*'")
        $probe = $worker.IndexOf('verify probe errored')
        ($probe -ge 0) | Should Be $true
        ($pass -lt $probe) | Should Be $true
    }
    It 'an OK-claiming Script still needs probe proof (the rewrap itself is preserved)' {
        ($worker -match 'version unchanged after update \(async update may still be in progress\)') | Should Be $true
    }
}
