# =============================================================================
#  Platform.NoTryParseZeroing.Tests.ps1 - no caller adopts a TryParse result it
#  did not check.
#
#  THE FAMILY: [int]::TryParse ZEROES its [ref] argument when the parse fails. So
#      $threads = 8
#      if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
#  does not "keep the default on bad input" - it silently REPLACES the default with
#  0, and the clamp that follows turns 0 into 1. The documented default never
#  applies, and nothing is said.
#
#  WHY IT MATTERS BEYOND PERFORMANCE: mostly this degrades a 200-host fan-out to a
#  single thread. But wpt's reboot-schedule used the same idiom for the countdown,
#  where 0 does not clamp to 1 - it clamps to nothing and arms `shutdown /r /t 0`,
#  an IMMEDIATE forced reboot instead of the 900-second default, with no warning for
#  anyone logged on.
#
#  WHY A SWEEP: this was found and fixed one module at a time across a single week -
#  remoteadmin, upr, c2c, certdeploy, then wpt - and each fix left the siblings
#  untouched, because each was written as "fix the module I am in". The correct
#  guarded idiom already existed in the codebase the whole time. So this asserts the
#  SHAPE across every module and expects ZERO.
#
#  Run: Invoke-Pester -Path .\tests\Platform.NoTryParseZeroing.Tests.ps1
# =============================================================================
$script:Root       = Split-Path $PSScriptRoot -Parent
$script:ModulesDir = Join-Path $script:Root 'modules'

# The defect shape: a TryParse whose result is discarded to Out-Null while its [ref]
# target is a live variable the code goes on to use.
$script:ZeroingRx = '\[ref\]\$\w+\)\s*\|\s*Out-Null'

Describe 'no module adopts an unchecked TryParse result' {

    It 'the sweep finds ZERO unguarded TryParse adoptions in modules\' {
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in (Get-ChildItem -LiteralPath $script:ModulesDir -Filter '*.psm1')) {
            $lines = Get-Content -LiteralPath $f.FullName
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*#') { continue }
                if ($lines[$i] -match $script:ZeroingRx) {
                    [void]$hits.Add("$($f.Name):$($i+1)  $($lines[$i].Trim())")
                }
            }
        }
        ($hits -join "`n") | Should BeNullOrEmpty
    }

    # Proves the sweep can fail - an over-tightened pattern would pass vacuously and
    # this family would keep reappearing exactly as it has.
    It 'the sweep detects the shape it is looking for (self-check)' {
        $sample = "    if (`$Params['threads']) { [int]::TryParse([string]`$Params['threads'], [ref]`$threads) | Out-Null }"
        ($sample -match $script:ZeroingRx) | Should Be $true
    }

    # The guarded idiom, which was already in the codebase before any of these fixes.
    It 'the guarded idiom is what replaced them' {
        $wpt = Get-Content (Join-Path $script:ModulesDir 'JanetWeb.wpt.psm1') -Raw
        ($wpt -match "if \(\[int\]::TryParse\(\[string\]\`$Params\['threads'\], \[ref\]\`$parsedThreads\)\) \{ \`$threads = \`$parsedThreads \}") | Should Be $true
    }
}

Describe 'the reboot countdown cannot become "reboot now" through a parse failure' {
    $wpt = Get-Content (Join-Path $script:ModulesDir 'JanetWeb.wpt.psm1') -Raw

    It 'a non-numeric delay keeps the documented default instead of zeroing' {
        ($wpt -match "if \(\[int\]::TryParse\(\[string\]\`$Params\['seconds'\], \[ref\]\`$parsedSeconds\)\) \{ \`$seconds = \`$parsedSeconds \}") | Should Be $true
    }
    It 'and it SAYS so rather than silently substituting' {
        ($wpt -match 'Ignoring non-numeric delay') | Should Be $true
    }
    # An explicit 0 is a legitimate operator choice ("reboot now"). What is refused is a
    # parse FAILURE silently becoming that. The clamp must therefore still exist.
    It 'an explicit 0 is still honoured (the fix did not overreach)' {
        ($wpt -match "if \(\`$seconds -lt 0\) \{ \`$seconds = 0 \}") | Should Be $true
    }
}

Describe 'documented exception' {
    # server\JanetWeb.Server.ps1:1660 parses a log-tail offset whose default IS 0, so
    # zeroing on a bad value changes nothing. Left as-is deliberately; asserted here so
    # it is a known exception rather than an oversight someone "fixes" later.
    It 'the server log-tail offset may zero, because 0 is its default' {
        $srv = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw
        ($srv -match "\`$since = 0; \[int\]::TryParse\(\[string\]\`$req\.QueryString\['since'\], \[ref\]\`$since\) \| Out-Null") | Should Be $true
    }
}
