# =============================================================================
#  Log4jJarVersion.Tests.ps1 - the Log4j patched-version FLOOR agrees across
#  every live file that carries it, and nothing pins a jar FILENAME any more.
#
#  WHY THIS EXISTS: bumping the patched jar is a RECURRING chore, and the value
#  is repeated in five files - it cannot be a single shared constant, because the
#  remediation blocks are serialized to remote runspaces over WinRM (and the
#  update worker runs in a bare pool runspace), where a module-scope variable
#  arrives $null.
#
#  On the 2.25.4 -> 2.25.5 bump (2026-07-30) a literal find-and-replace swept 105
#  sites and MISSED 12, because those write the version REGEX-ESCAPED
#  (^log4j-(api|core)-2\.25\.4\.jar$) and the escaped form does not contain the
#  plain literal. The verification grep was blind in exactly the same way.
#
#  2026-08-11 - the SAME defect surfaced from the other direction: the staging
#  share moved to 2.26.1 and every exact-match site REJECTED the newer jar (the
#  acas.view upload gate, the staged-source readiness probe, and Verify, which
#  would have called every patched host STILL-VULNERABLE). The pin is now a
#  FLOOR compared numerically, and the staged filename is DISCOVERED at runtime -
#  so a bump is a one-token change per site and a newer jar needs no change at all.
#
#  This asserts AGREEMENT rather than a value, so it stays true across every
#  future bump and fails the moment one site is left behind.
#
#  Run:  .\Run-Tests.ps1 -Area log4j    (or Invoke-Pester on this file)
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# Live files that carry the floor. Acas.Log4j*.Tests.ps1 are deliberately NOT here:
# they name concrete jar filenames (2.17.0, 2.10.0, the staged pair) as fixtures.
$script:Log4jFiles = @(
    'modules\JanetWeb.acas.psm1'
    'modules\JanetWeb.wpt.psm1'
    'server\JanetWeb.Server.ps1'
    'web\js\help-content.js'
    'web\js\views\acas.view.js'
)

function Get-L4jSrc { param([string]$Rel) Get-Content -LiteralPath (Join-Path $script:Root $Rel) -Raw }

# First in-block floor literal in a module - the value every other site must match.
function Get-L4jBlockFloor { param([string]$Rel)
    [regex]::Match((Get-L4jSrc $Rel), "\`$l4jFloor\s*=\s*'([\d.]+)'").Groups[1].Value
}

Describe 'Log4j patched-version floor agrees everywhere' {

    It 'all four in-block literals (acas + wpt, Script + Verify) carry the SAME floor' {
        $vals = @()
        foreach ($f in @('modules\JanetWeb.acas.psm1', 'modules\JanetWeb.wpt.psm1')) {
            $vals += @([regex]::Matches((Get-L4jSrc $f), "\`$l4jFloor\s*=\s*'([\d.]+)'") |
                       ForEach-Object { $_.Groups[1].Value })
        }
        # Two blocks per module. A Script/Verify pair that drifts is the exact failure
        # that made the last bump report patched hosts as STILL-VULNERABLE.
        $vals.Count | Should Be 4
        ($vals -join ', ') | Should Not BeNullOrEmpty
        (@($vals | Sort-Object -Unique)).Count | Should Be 1
    }

    It 'the acas module constant matches its in-block literals' {
        $const = [regex]::Match((Get-L4jSrc 'modules\JanetWeb.acas.psm1'), "\`$script:AcasLog4jFloor\s*=\s*'([\d.]+)'").Groups[1].Value
        $const | Should Not BeNullOrEmpty
        $const | Should Be (Get-L4jBlockFloor 'modules\JanetWeb.acas.psm1')
    }

    It 'the acas staging-FAIL text names the same floor' {
        # That message lives in $script:AcasUpdateWorker - a bare pool runspace with no
        # module scope, so it must hardcode the value rather than read the constant.
        $fail = [regex]::Match((Get-L4jSrc 'modules\JanetWeb.acas.psm1'),
                               'Log4j staging source not available \(drop log4j-api/core jars at or above ([\d.]+) ').Groups[1].Value
        $fail | Should Not BeNullOrEmpty
        $fail | Should Be (Get-L4jBlockFloor 'modules\JanetWeb.acas.psm1')
    }

    It 'the wpt scanner classifier (Get-WptLog4jVulnState) uses the same floor' {
        # The Log4j Scanner tab and the remediation must agree on what "Patched" means,
        # or the scan flags hosts the fix considers done.
        $fn = [regex]::Match((Get-L4jSrc 'modules\JanetWeb.wpt.psm1'), "(?s)function Get-WptLog4jVulnState \{.*?\n\}").Value
        $fn | Should Not BeNullOrEmpty
        [regex]::Match($fn, "\[version\]'([\d.]+)'").Groups[1].Value | Should Be (Get-L4jBlockFloor 'modules\JanetWeb.wpt.psm1')
    }

    It 'the acas.view upload gate accepts the floor the module enforces' {
        # The gate rejecting a jar the module would have accepted is what stranded the
        # operator: the fix could not be staged from the UI at all.
        $view = [regex]::Match((Get-L4jSrc 'web\js\views\acas.view.js'), "L4J_FLOOR\s*=\s*'([\d.]+)'").Groups[1].Value
        $view | Should Not BeNullOrEmpty
        $view | Should Be (Get-L4jBlockFloor 'modules\JanetWeb.acas.psm1')
    }

    It 'the operator-facing text (help + staging README) names the same floor' {
        $floor = Get-L4jBlockFloor 'modules\JanetWeb.acas.psm1'
        foreach ($f in @('web\js\help-content.js', 'server\JanetWeb.Server.ps1')) {
            ($f + ': ' + [bool]((Get-L4jSrc $f) -like ('*' + $floor + '*'))) | Should Be ($f + ': True')
        }
    }

    It 'no live file pins an exact replacement-jar FILENAME any more' {
        # Under the floor the staged filename is discovered at runtime, so there is
        # nothing left to sweep. A reintroduced literal (the shape that got half-swept
        # last time, and that rejected the 2.26.1 jars this time) fails here.
        # Dots are unescaped first so the regex-escaped form is caught by the same pass.
        foreach ($f in $script:Log4jFiles) {
            $hits = @([regex]::Matches(((Get-L4jSrc $f) -replace '\\\.', '.'), 'log4j-(?:api|core)-\d+(?:\.\d+)+\.jar') |
                      ForEach-Object { $_.Value } | Sort-Object -Unique)
            # Compared as a string so a failure names the file AND the offending literals.
            ($f + ' -> ' + ($hits -join ', ')) | Should Be ($f + ' -> ')
        }
    }
}

# EXACT pins for this bump, per the convention that the newest bump pins exactly and
# older tests demote to a floor (Platform.NoRegistryMtime's 1.11.26 / 6.10.10 exact pins
# were demoted for this one).
Describe 'manifest EXACT pins for the Log4j floor bump (acas 1.11.27, wpt 6.10.11)' {
    It 'acas is exactly 1.11.27' {
        [regex]::Match((Get-L4jSrc 'modules\JanetWeb.acas.psm1'), "version\s+=\s+'([0-9.]+)'").Groups[1].Value | Should Be '1.11.27'
    }
    # wpt DEMOTED to a floor on 2026-10-05 (6.10.12, App Updater Log4j staging); its
    # exact pin moved to Wpt.Log4jStaging.Tests.ps1. acas stays exact - not bumped since.
    It 'wpt is at or past 6.10.11' {
        ([version][regex]::Match((Get-L4jSrc 'modules\JanetWeb.wpt.psm1'), "version\s+=\s+'([0-9.]+)'").Groups[1].Value -ge [version]'6.10.11') | Should Be $true
    }
}
