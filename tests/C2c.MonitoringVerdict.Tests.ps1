# =============================================================================
#  C2c.MonitoringVerdict.Tests.ps1 - Pester 3.4 for the Monitoring pillar fix verdict
#  (Get-C2cMonitoringVerdict, loop45 / c2c deep-dive F5, item 52). The Monitoring
#  pillar is compliant ONLY when the Tanium SOFTWARE is installed (uninstall registry)
#  AND its client service is Running - the scan's Monitoring PASS criteria. The fixer
#  formerly booked FIXED / NOCHANGE (MONITORED) off the service alone, so a
#  Running-but-not-installed box (an orphaned service, or a host whose uninstall
#  registry couldn't be read) reported MONITORED / host FIXED / a VulnPatched Success
#  while the scan would still quarantine it - a false-clean, with the Detail literally
#  reading "Tanium not installed". Now a Running service with the software NOT detected
#  is NOT VERIFIED (host rollup -> not FIXED; audit -> not Success), never FIXED.
#
#  Get-C2cMonitoringVerdict is the pure canonical verdict; the module-less fix worker
#  mirrors it inline. Run:  Invoke-Pester -Path .\tests\C2c.MonitoringVerdict.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
$src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

function Get-Verdict {
    param([bool]$Installed, [bool]$RunNow, [int]$Changed)
    (& $cm { param($i,$r,$c) Get-C2cMonitoringVerdict -Installed $i -RunNow $r -ChangedCount $c } $Installed $RunNow $Changed)
}

Describe 'Get-C2cMonitoringVerdict - MONITORED needs Tanium INSTALLED and the service RUNNING' {
    It 'not running -> FAIL (whatever the install state)' {
        Get-Verdict -Installed $true  -RunNow $false -Changed 1 | Should Be 'FAIL'
        Get-Verdict -Installed $false -RunNow $false -Changed 0 | Should Be 'FAIL'
    }
    It 'running but software NOT installed -> NOT VERIFIED (the false-clean fix), even after a service heal' {
        Get-Verdict -Installed $false -RunNow $true -Changed 1 | Should Be 'NOT VERIFIED'
        Get-Verdict -Installed $false -RunNow $true -Changed 0 | Should Be 'NOT VERIFIED'
    }
    It 'installed + running + a service change -> FIXED' {
        Get-Verdict -Installed $true -RunNow $true -Changed 1 | Should Be 'FIXED'
    }
    It 'installed + already running, no change -> NOCHANGE' {
        Get-Verdict -Installed $true -RunNow $true -Changed 0 | Should Be 'NOCHANGE'
    }
}

Describe 'c2c Monitoring fix worker - the inline mirror gates FIXED/NOCHANGE on the Tanium-installed half' {
    It 'the worker verdict has the -not $ti.Installed -> NOT VERIFIED branch' {
        ($src -match "elseif \(-not \`$ti\.Installed\) \{[\s\S]*?'Monitoring' 'heal' 'NOT VERIFIED'") | Should Be $true
    }
}

Describe 'c2c - manifest exact version pin (newest bump = loop-45 Monitoring installed-half fail-close)' {
    It 'c2c is at v1.15.6' {
        $man = & $cm { Get-JanetToolManifest }
        [string]$man.version | Should Be '1.15.6'
    }
}
