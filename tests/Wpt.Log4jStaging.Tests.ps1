# =============================================================================
#  Wpt.Log4jStaging.Tests.ps1 - Pester 3.4 tests for the App Updater's Log4j
#  jar staging (wpt v6.10.12).
#
#  app-update-apply used to REFUSE the 'Apache Log4j - Replace Vulnerable Jars'
#  profile and point the operator at ACAS, because the profile Script reads a
#  UNC the target cannot reach (double-hop). It now resolves the jars host-side
#  and the worker copies them into each session, like the ACAS worker does.
#
#  The resolver is exercised for real against temp folders; the worker/dispatch
#  wiring is static-analysis only. No host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.Log4jStaging.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:WptPath = Join-Path $script:Root 'modules\JanetWeb.wpt.psm1'
$m = Import-Module $script:WptPath -Force -PassThru
$script:WptSrc = Get-Content -LiteralPath $script:WptPath -Raw

function New-L4jDir { param([string[]]$Names)
    $d = Join-Path $env:TEMP ('JwL4jStage_' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $d -Force)
    foreach ($n in $Names) { Set-Content -LiteralPath (Join-Path $d $n) -Value 'x' }
    return $d
}
function Resolve-L4j { param([string[]]$Dirs) & $m { param($c) Resolve-WptLog4jSource -Candidates $c } $Dirs }

Describe 'Resolve-WptLog4jSource (host-side jar source)' {
    $made = @()
    try {
        $floorPair = New-L4jDir @('log4j-api-2.26.1.jar', 'log4j-core-2.26.1.jar');  $made += $floorPair
        $newerPair = New-L4jDir @('log4j-api-2.30.0.jar', 'log4j-core-2.30.0.jar');  $made += $newerPair
        $oldPair   = New-L4jDir @('log4j-api-2.25.5.jar', 'log4j-core-2.25.5.jar');  $made += $oldPair
        $apiOnly   = New-L4jDir @('log4j-api-2.26.1.jar');                           $made += $apiOnly
        $mixed     = New-L4jDir @('log4j-api-2.26.1.jar', 'log4j-core-2.9.0.jar');   $made += $mixed
        $empty     = New-L4jDir @();                                                 $made += $empty

        It 'accepts an api+core pair exactly at the floor' {
            Resolve-L4j @($floorPair) | Should Be $floorPair
        }
        It 'accepts a pair NEWER than the floor (floor, not an exact pin)' {
            Resolve-L4j @($newerPair) | Should Be $newerPair
        }
        It 'refuses a pair below the floor' {
            Resolve-L4j @($oldPair) | Should Be ''
        }
        It 'refuses a folder holding only one of the two jars' {
            Resolve-L4j @($apiOnly) | Should Be ''
        }
        It 'refuses a pair whose core jar is below the floor (2.9.0 is not above 2.26.1)' {
            Resolve-L4j @($mixed) | Should Be ''
        }
        It 'skips a non-qualifying folder and falls through to the next candidate' {
            Resolve-L4j @($empty, $oldPair, $floorPair) | Should Be $floorPair
        }
        It 'returns empty for a folder that does not exist' {
            Resolve-L4j @((Join-Path $env:TEMP ('JwL4jMissing_' + [guid]::NewGuid().ToString('N')))) | Should Be ''
        }
    } finally {
        foreach ($d in $made) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'App Updater Log4j staging wiring' {
    $profiles = & $m { Get-WptAppUpdateProfiles }
    $l4j      = $profiles['Apache Log4j - Replace Vulnerable Jars']
    $blk      = & $m { "$script:WptAppUpdateBlock" }

    It 'the profile is still flagged NeedsStaging' {
        [bool]$l4j.NeedsStaging | Should Be $true
    }
    It 'the profile Script has exactly one single-quoted $sourceShare assignment for the worker to redirect' {
        @([regex]::Matches($l4j.Script.ToString(), "\`$sourceShare\s*=\s*'[^']*'")).Count | Should Be 1
    }
    It 'the worker redirect lands on the session-local temp, not the UNC' {
        $out = [regex]::Replace($l4j.Script.ToString(), "\`$sourceShare\s*=\s*'[^']*'", { param($x) "`$sourceShare = 'C:\Windows\Temp\JanetLog4j'" })
        $out | Should Match ([regex]::Escape("`$sourceShare = 'C:\Windows\Temp\JanetLog4j'"))
        $out | Should Not Match 'dm-tn-01'
    }
    It 'the worker copies the jars into the session and takes a StageSource argument' {
        $blk | Should Match '\[string\]\$StageSource'
        $blk | Should Match 'Copy-Item .*-ToSession \$sess'
        $blk | Should Match 'Remove-PSSession'
    }
    It 'the worker fails closed when the Script could not be redirected' {
        $blk | Should Match 'no \$sourceShare assignment to redirect'
    }
    It 'app-update-apply resolves the source and passes it to the worker' {
        $script:WptSrc | Should Match '\$stageSource = Resolve-WptLog4jSource'
        $script:WptSrc | Should Match '\$arg, \$false, \$stageSource\)'
    }
    It 'app-update-apply no longer redirects the operator to ACAS' {
        $script:WptSrc | Should Not Match 'Run it from ACAS Nemesis -> Remediation \(Log4j\)'
    }
}

# EXACT pin for this bump, per the convention that the newest bump pins exactly and
# older tests demote to a floor (Log4jJarVersion's 6.10.11 exact pin was demoted).
Describe 'manifest EXACT pin for the App Updater Log4j staging bump (wpt 6.10.12)' {
    It 'wpt is exactly 6.10.12' {
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '6.10.12'
    }
}
