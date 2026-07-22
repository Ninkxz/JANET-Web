# =============================================================================
#  Acas.KbInstallStatus.Tests.ps1 - Pester 3.4 for the honest acas kb-install
#  status (loop25). A Fable deep-dive of the acas remediation engine found the
#  kb-install worker reported an unverified MECM InstallUpdates trigger (and a
#  UsoClient fire-and-forget) as OK - which books a VulnPatched Success audit and
#  lights the PATCHED stat card - and let any confirmed install mask a real error
#  (partial-fail-as-OK). These are the acas siblings of the wpt kb-install issues
#  fixed in loops 22-23. Now: any error -> FAIL; a trigger/fire with no confirmed
#  install -> UNCONFIRMED (AcasOkOf renders it amber, out of the OK/patched tally);
#  a confirmed MSU exit-0 install -> OK; only skips -> SKIP.
#
#  Get-AcasKbInstallStatus is the canonical rule; the AcasKbInstallBlock worker
#  mirrors it inline (it runs in a module-less runspace, can't call a module fn).
#  The real worker's status is exercised end-to-end by FixVerify2 (Invoke-AcasKb).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.KbInstallStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-Status {
    param([int]$Err, [int]$Mecm, [int]$Msu, [int]$Skip, [bool]$Uso)
    (& $script:Mod { param($e, $m, $s, $k, $u) Get-AcasKbInstallStatus -ErrorCount $e -MecmTriggered $m -MsuInstalled $s -Skipped $k -UsoTriggered $u } $Err $Mecm $Msu $Skip $Uso)
}

Describe 'Get-AcasKbInstallStatus - a trigger is never "patched"' {
    It 'a MECM trigger with no confirmed install -> UNCONFIRMED (not OK)' {
        Get-Status -Err 0 -Mecm 2 -Msu 0 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
    It 'a UsoClient fire-and-forget -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $true | Should Be 'UNCONFIRMED'
    }
    It 'a confirmed MSU install (no trigger) -> OK' {
        Get-Status -Err 0 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'OK'
    }
    It 'a MECM trigger alongside an MSU install still errs toward verify -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 1 -Msu 1 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
}

Describe 'Get-AcasKbInstallStatus - an error never hides behind a partial install' {
    It 'any error -> FAIL, even with a confirmed MSU install (partial-fail no longer masks)' {
        Get-Status -Err 1 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
    It 'any error -> FAIL, even with a MECM trigger' {
        Get-Status -Err 1 -Mecm 1 -Msu 0 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
}

Describe 'Get-AcasKbInstallStatus - skips and no-ops' {
    It 'nothing installed, only skips -> SKIP' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 2 -Uso $false | Should Be 'SKIP'
    }
    It 'nothing happened at all -> SKIP (never a bare OK)' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $false | Should Be 'SKIP'
    }
}

Describe 'acas - manifest version floor (loop-25 honest kb-install status landed at 1.11.6)' {
    It 'acas version is >= 1.11.6 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.6') | Should Be $true
    }
}

# loop86: AcasKbInstallBlock is a DESTRUCTIVE worker (MECM InstallUpdates + wusa MSU + UsoClient install, and a
# reboot when NoReboot is off) that was the ONLY destructive acas fan-out MISSING the wrong-box (DNS-mismatch)
# guard its siblings carry (update worker ~:2004, reboot workers ~:2174/:2201). Stale DNS / a reused IP could
# install KBs on the WRONG machine. Now it verifies the answering box's $env:COMPUTERNAME == the dialed shortname
# before any install (IPv4-literal target skips the compare; empty probe proceeds). Same shape as the shared
# wrong-box guard in PkginstallSecureboot.WrongBoxGuard.Tests.ps1. Unit-scope: no host contact below.
$script:Src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
function Get-KbExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }
function Test-KbWrongBoxAbort { param([string]$Target,[string]$Answering) $e = Get-KbExpectedName $Target; [bool]($Target -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $Answering -and ($Answering.Trim().ToUpper() -ne $e.ToUpper())) }

Describe 'AcasKbInstallBlock wrong-box guard (loop86) - the destructive kb-install worker aborts on DNS mismatch' {
    It 'the guard is PRESENT in AcasKbInstallBlock before the install (COMPUTERNAME compare + hard-abort)' {
        # scope the assertion to the kb-install block body
        $blk = [regex]::Match($script:Src, '(?s)\$script:AcasKbInstallBlock\s*=\s*\{.*?\n\}').Value
        ($blk -match "\`$Computer -notmatch '\^\\d\{1,3\}\(\\\.\\d\{1,3\}\)\{3\}\$'")                 | Should Be $true
        ($blk -match '\$actualName\s*=\s*try \{ Invoke-Command -Session \$sess.*\$env:COMPUTERNAME')  | Should Be $true
        ($blk -match "DNS mismatch: dialed '\`$targetShort' but remote is.*ABORTED, no KBs installed") | Should Be $true
    }
    It 'the abort predicate: an FQDN whose box answers with a DIFFERENT name aborts' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' 'WS02' | Should Be $true
    }
    It 'the matching box (same shortname) does NOT abort' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' 'WS01' | Should Be $false
        Test-KbWrongBoxAbort 'WS01' 'ws01'             | Should Be $false   # case-insensitive
    }
    It 'an IPv4-literal target skips the compare (no shortname to match)' {
        (Get-KbExpectedName '10.1.2.3')            | Should Be ''
        Test-KbWrongBoxAbort '10.1.2.3' 'ANY-NAME' | Should Be $false
    }
    It 'an empty probe (COMPUTERNAME unreadable) proceeds - does not regress into a false abort' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' '' | Should Be $false
    }
    It 'acas manifest is at or past 1.11.15 (kb-install guard; exact pin migrated to the newest bump)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'1.11.15') | Should Be $true
    }
}
