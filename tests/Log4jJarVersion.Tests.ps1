# =============================================================================
#  Log4jJarVersion.Tests.ps1 - the Log4j replacement-jar version agrees across
#  every live file that hardcodes it.
#
#  WHY THIS EXISTS, AND WHY Acas.Log4j.Tests.ps1 IS NOT ENOUGH: bumping the
#  patched jar is a RECURRING chore, and the version is hardcoded in five files
#  here - it cannot be a shared constant, because the remediation blocks are
#  serialized to remote runspaces over WinRM and a module-scope variable would
#  arrive $null on the far side.
#
#  On the 2.25.4 -> 2.25.5 bump (2026-07-30) a literal find-and-replace swept 105
#  sites and MISSED 12, because those write the version REGEX-ESCAPED
#  (^log4j-(api|core)-2\.25\.4\.jar$) and the escaped form does not contain the
#  plain literal. The verification grep was blind in exactly the same way, so it
#  reported clean. The missed sites were the worst possible ones:
#    - the Verify regex in acas and wpt - the profile would copy the NEW jars in
#      and then report every successfully patched host STILL-VULNERABLE;
#    - the upload gate in acas.view.js - the UI would refuse the new jars, so the
#      operator could not stage the fix at all.
#  Acas.Log4j.Tests.ps1 pins the version as a literal, so it was swept alongside
#  the module and stayed green throughout. A test scoped to the sites you already
#  fixed cannot catch the sites you missed.
#
#  So this asserts AGREEMENT rather than a value - it stays true across every
#  future bump and fails the moment one site is left behind. Dots are unescaped
#  before matching so the escaped form is covered by the same sweep.
#
#  Run:  .\Run-Tests.ps1 -Area log4j    (or Invoke-Pester on this file)
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# Live files that hardcode the jar version. Acas.Log4j.Tests.ps1 is deliberately
# NOT here: it names old vulnerable versions (2.10.0, 2.17.0) as fixtures.
$script:Log4jFiles = @(
    'modules\JanetWeb.acas.psm1'
    'modules\JanetWeb.wpt.psm1'
    'server\JanetWeb.Server.ps1'
    'web\js\help-content.js'
    'web\js\views\acas.view.js'
)

function Get-Log4jJarVersions {
    param([string]$RelPath)
    $full = Join-Path $script:Root $RelPath
    if (-not (Test-Path -LiteralPath $full)) { return @() }
    $src = (Get-Content -LiteralPath $full -Raw) -replace '\\\.', '.'
    return @([regex]::Matches($src, 'log4j-(?:api|core)-(\d+(?:\.\d+)+)\.jar') |
             ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

Describe 'Log4j replacement jar version agrees everywhere' {

    It 'every file that names a log4j jar names the SAME version' {
        $all = @()
        foreach ($f in $script:Log4jFiles) { $all += Get-Log4jJarVersions $f }
        $distinct = @($all | Sort-Object -Unique)
        # Joined so a failure names the offending versions, not just a count.
        ($distinct -join ', ') | Should Not BeNullOrEmpty
        $distinct.Count | Should Be 1
    }

    It 'all five files still carry the literal (none silently lost it)' {
        foreach ($f in $script:Log4jFiles) {
            (Get-Log4jJarVersions $f).Count | Should Not Be 0
        }
    }

    It 'the Verify regex tests for the SAME version the profile copies in' {
        # The specific pairing that broke: $newApi/$newCore name what gets copied,
        # the escaped -notmatch decides what counts as still-vulnerable.
        foreach ($f in @('modules\JanetWeb.acas.psm1', 'modules\JanetWeb.wpt.psm1')) {
            $src = (Get-Content -LiteralPath (Join-Path $script:Root $f) -Raw)
            $copied = [regex]::Match($src, "\`$newCore\s*=\s*'log4j-core-(\d+(?:\.\d+)+)\.jar'").Groups[1].Value
            $verify = [regex]::Match($src, "\^log4j-\(api\|core\)-([\d\\.]+)\\\.jar\`$").Groups[1].Value -replace '\\', ''
            $copied | Should Not BeNullOrEmpty
            $verify | Should Not BeNullOrEmpty
            $verify | Should Be $copied
        }
    }

    # This file carries the EXACT pins for the 2026-07-30 bump, per the convention
    # that the newest bump pins exactly and older tests demote to a floor
    # (Acas.ClientVerify 1.11.22 and Wpt.C2rVerify 6.10.5 were demoted for it).
    # acas keeps the EXACT pin (1.11.23 is still the log4j bump). wpt's was demoted
    # to a floor on 2026-08-02 when 6.10.7 landed for an unrelated fix (healer-wu-reset)
    # - this file guards the jar sweep, not wpt's version, and an exact pin here would
    # make every future wpt bump fail a log4j test for no reason.
    It 'acas manifest is exactly 1.11.23 and wpt is at or past 6.10.6' {
        $acas = [regex]::Match((Get-Content -LiteralPath (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw), "version\s+=\s+'([0-9.]+)'").Groups[1].Value
        $wpt  = [regex]::Match((Get-Content -LiteralPath (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1')  -Raw), "version\s+=\s+'([0-9.]+)'").Groups[1].Value
        $acas | Should Be '1.11.23'
        ([version]$wpt -ge [version]'6.10.6') | Should Be $true
    }

    It 'the acas.view upload gate accepts the version the module copies in' {
        $modVer  = @(Get-Log4jJarVersions 'modules\JanetWeb.acas.psm1')[0]
        $viewVer = @(Get-Log4jJarVersions 'web\js\views\acas.view.js')
        $viewVer -contains $modVer | Should Be $true
        @($viewVer).Count | Should Be 1
    }
}
