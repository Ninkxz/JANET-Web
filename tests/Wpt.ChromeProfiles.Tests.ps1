# =============================================================================
#  Wpt.ChromeProfiles.Tests.ps1 - Pester 3.4 tests for the Chrome App Updater
#  profile split (wpt v6.5.33).
#
#  The old 'Google Chrome - Update' profile ran GoogleUpdate.exe /ua and
#  returned "OK (Chrome update triggered, exit N)" unconditionally - on AFNET
#  boxes with Google Update policy-blocked / service-disabled / migrated to
#  GoogleUpdater the operator saw OK and nothing updated. It is replaced by:
#
#   (a) 'Google Chrome - Update (Software Center)' - CCM_Application install
#       (Java-profile flow) with the Adobe-profile MECM-cycle fallback when
#       no Chrome app is in the catalog.
#   (b) 'Google Chrome - Update (Internet - Google Update)' - policy/service
#       blocker pre-checks, modern GoogleUpdaterTaskSystem* task or legacy
#       /ua trigger, before/after version poll + staged-update (new_chrome.exe)
#       detection. Never a bare OK for an unverified trigger.
#
#  Static-analysis scope only: profile table shape + script text + manifest and
#  view dropdown wiring. No host contact, nothing is executed remotely.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.ChromeProfiles.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

$profiles = & $m { Get-WptAppUpdateProfiles }
$scName   = 'Google Chrome - Update (Software Center)'
$netName  = 'Google Chrome - Update (Internet - Google Update)'
$msiName  = 'Google Chrome - Update (Vendor MSI - Google)'   # v6.10.0 vendor-direct push

Describe 'Chrome App Updater profile split (registry shape)' {
    It 'contains the Software Center profile' {
        $profiles.ContainsKey($scName) | Should Be $true
    }
    It 'contains the Internet (Google Update) profile' {
        $profiles.ContainsKey($netName) | Should Be $true
    }
    It 'no longer contains the old always-OK profile name exactly' {
        $profiles.ContainsKey('Google Chrome - Update') | Should Be $false
    }
    It 'both new profiles carry a Script scriptblock' {
        ($profiles[$scName].Script  -is [scriptblock]) | Should Be $true
        ($profiles[$netName].Script -is [scriptblock]) | Should Be $true
    }
    It 'both new profiles carry a Verify scriptblock' {
        ($profiles[$scName].Verify  -is [scriptblock]) | Should Be $true
        ($profiles[$netName].Verify -is [scriptblock]) | Should Be $true
    }
    It 'both Verify blocks read the Chrome Clients update GUID (New-WptUpdateClientVerify)' {
        foreach ($n in @($scName, $netName)) {
            ("$($profiles[$n].Verify)" -match '8A69D345-D564-463c-AFF1-A69D9E530F96') | Should Be $true
        }
    }
}

Describe 'Software Center profile script (static analysis)' {
    $sc = "$($profiles[$scName].Script)"
    It 'installs the deployed Chrome app via CCM_Application Invoke-CimMethod' {
        ($sc -match 'CCM_Application') | Should Be $true
        ($sc -match 'Invoke-CimMethod') | Should Be $true
    }
    It 'fails clearly when the SCCM client is absent' {
        ($sc -match 'SCCM client \(CCM_Application\) not present') | Should Be $true
    }
    It 'falls back to the 4 MECM cycles when no Chrome app is in the catalog' {
        ($sc -match 'TriggerSchedule') | Should Be $true
        foreach ($tail in @('121', '108', '113', '114')) {
            ($sc -match ('000000000' + $tail)) | Should Be $true
        }
        ($sc -match 'no Chrome app in Software Center catalog') | Should Be $true
    }
    It 'excludes Chrome Remote Desktop and side-channel builds from matching' {
        ($sc -match 'Remote Desktop') | Should Be $true
        ($sc -match 'Canary') | Should Be $true
    }
}

Describe 'Internet (Google Update) profile script (static analysis)' {
    $net = "$($profiles[$netName].Script)"
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
        ($net -match 'PENDING') | Should Be $true
        ($net -match 'SKIP: Chrome \(machine-level\) not installed') | Should Be $true
    }
    It 'does NOT contain the old unconditional "OK (Chrome update triggered" string' {
        ($net -match [regex]::Escape('OK (Chrome update triggered')) | Should Be $false
    }
    It 'routes every blocker to the Software Center profile in its FAIL text' {
        ($net -match 'use the Software Center profile') | Should Be $true
    }
}

Describe 'Vendor MSI (Google direct push) profile - v6.10.0' {
    It 'the profile exists with Script + Verify scriptblocks' {
        $profiles.ContainsKey($msiName) | Should Be $true
        ($profiles[$msiName].Script -is [scriptblock]) | Should Be $true
        ($profiles[$msiName].Verify -is [scriptblock]) | Should Be $true
    }
    $msi = "$($profiles[$msiName].Script)"
    It 'downloads the official Google Enterprise MSI vanity URL' {
        ($msi -match [regex]::Escape('dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi')) | Should Be $true
        ($msi -match 'Invoke-WebRequest') | Should Be $true
    }
    It 'force-installs via msiexec /i /qn (not just an updater nudge)' {
        ($msi -match 'msiexec') | Should Be $true
        ($msi -match '/qn') | Should Be $true
    }
    It 'forces TLS 1.2 for the vendor pull' {
        ($msi -match 'Tls12') | Should Be $true
    }
    It 'rejects a non-MSI (proxy/captive-portal page) via the OLE2 magic bytes' {
        ($msi -match '208,207,17,224') | Should Be $true
    }
    It 'treats 0/1641/3010 as install success and gates FAIL on other exit codes' {
        ($msi -match '1641') | Should Be $true
        ($msi -match '3010') | Should Be $true
        ($msi -match 'msiexec returned') | Should Be $true
    }
    It 'SKIPs a host without Chrome (upgrade-only intent) and Verify reads the Chrome GUID' {
        ($msi -match 'SKIP: Chrome \(machine-level\) not installed') | Should Be $true
        ("$($profiles[$msiName].Verify)" -match '8A69D345-D564-463c-AFF1-A69D9E530F96') | Should Be $true
    }
}

Describe 'Manifest + view dropdown wiring' {
    $mani = & $m { Get-JanetToolManifest }
    foreach ($aid in @('app-update-verify', 'app-update-apply')) {
        It "manifest $aid profile options list the SC/Internet/Vendor-MSI names and not the old one" {
            $act = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            $opts = @(@($act.inputs | Where-Object { $_.name -eq 'profile' })[0].options)
            ($opts -contains $scName)  | Should Be $true
            ($opts -contains $netName) | Should Be $true
            ($opts -contains $msiName) | Should Be $true
            ($opts -contains 'Google Chrome - Update') | Should Be $false
        }
    }
    It 'wpt.view.js PROFILES lists the SC/Internet/Vendor-MSI names and not the old exact name' {
        $view = Get-Content (Join-Path $script:Root 'web\js\views\wpt.view.js') -Raw
        $view.Contains("'" + $scName + "'")  | Should Be $true
        $view.Contains("'" + $netName + "'") | Should Be $true
        $view.Contains("'" + $msiName + "'") | Should Be $true
        $view.Contains("'Google Chrome - Update'") | Should Be $false
    }
}

Describe 'PENDING is its own pipeline state (classifier + audit, static analysis)' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'WptAppUpdateBlock classifier maps PENDING* results to a Pending status (not Failed)' {
        $blk = & $m { "$script:WptAppUpdateBlock" }
        ($blk -match "PENDING\*") | Should Be $true
        ($blk -match "'Pending'") | Should Be $true
    }
    It 'the app-update-apply dispatcher audits Pending AND Skipped rows as Skipped, never plain Failure' {
        # 6.8.2 (loop-3 Opus P3-1): Skipped joined Pending in the Skipped audit
        # bucket - a not-installed SKIP host used to book as audit Failure.
        ($moduleSrc -match 'AuditResultOf') | Should Be $true
        $lit = '-eq ''Pending'' -or "$($r.Status)" -eq ''Skipped'') { ''Skipped'' }'
        ($moduleSrc.IndexOf($lit) -ge 0) | Should Be $true
    }
    It 'Invoke-WptFanOut keeps the binary Success/Failure audit default when AuditResultOf is not supplied' {
        ($moduleSrc -match 'if \(\$AuditResultOf\)') | Should Be $true
        ($moduleSrc -match "else \{ if \(\`$ok\) \{ 'Success' \} else \{ 'Failure' \} \}") | Should Be $true
    }
    It 'the App Updater apply log handler renders Pending as warn (amber), not err or ok' {
        $view = Get-Content (Join-Path $script:Root 'web\js\views\wpt.view.js') -Raw
        ($view -match '/pending/i') | Should Be $true
    }
}
