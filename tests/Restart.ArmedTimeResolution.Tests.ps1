# =============================================================================
#  Restart.ArmedTimeResolution.Tests.ps1 - an armed wave reboots at the time it
#  was armed for, not 24 hours later.
#
#  THE DEFECT (loop 2026-08-03, P1): a bare 'HH:mm' restart time is AMBIGUOUS -
#  it means "the next 02:00" - and it was being resolved TWICE, at two different
#  moments:
#    1. at ARM time, by ConvertTo-JanetWebArmFireAt, to compute FireAt; and
#    2. AGAIN at FIRE time, by the engine (restart.psm1:1608), which re-parses the
#       same raw string, finds today's 02:00 is now seconds in the PAST, and rolls
#       it to TOMORROW.
#  Burst mode then computed /t = (tomorrow 02:00 - now) ~= 86400 and issued
#  'shutdown /r /t 86400' to every host. The grid read "Dispatched / OK (rc=0)"
#  and the FLEET REBOOTED THE NEXT NIGHT, unattended, a day after the consent
#  prompts. Time-gated was worse: each pool worker held in-runspace for ~24h.
#
#  The view pre-fills that field in bare HH:mm form (restart.view.js:277), so this
#  was the DEFAULT path for the delayed-start feature, not an exotic input.
#
#  THE FIX: resolve the ambiguous form ONCE, at arm time, and store the absolute
#  datetime. A restartTime that already carries a date is unambiguous and is left
#  exactly as supplied (an API caller may legitimately arm at X to reboot at Y).
#
#  Run:  Invoke-Pester -Path .\tests\Restart.ArmedTimeResolution.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

# The engine's day-roll, quoted EXACTLY as restart.psm1:1608 applies it. If that
# line ever changes shape, the source pin at the bottom of this file fails and
# sends the next reader here.
function Test-EngineWouldRoll {
    param([string]$Raw, [datetime]$AtFireTime)
    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($Raw, [ref]$parsed)) { return $false }
    return ($Raw -match '^\s*\d{1,2}:\d{2}' -and $parsed -lt $AtFireTime)
}

Describe 'the engine day-roll is exactly what made an armed wave 24h late' {

    # Establishes the defect is real before asserting the fix. At fire time the
    # armed moment has just passed, which is precisely when the roll triggers.
    It 'a bare HH:mm WOULD be rolled to tomorrow when re-parsed at its own fire time' {
        $armedFor = (Get-Date).Date.AddDays(1).AddHours(2)          # tomorrow 02:00
        $raw      = $armedFor.ToString('HH:mm')                      # '02:00'
        $fireTime = $armedFor.AddSeconds(2)                          # the tick fires ~2s late
        (Test-EngineWouldRoll -Raw $raw -AtFireTime $fireTime) | Should Be $true
    }
    It 'an ABSOLUTE datetime is immune to the roll (this is what the fix stores)' {
        $armedFor = (Get-Date).Date.AddDays(1).AddHours(2)
        $raw      = $armedFor.ToString('yyyy-MM-ddTHH:mm:ss')
        $fireTime = $armedFor.AddSeconds(2)
        (Test-EngineWouldRoll -Raw $raw -AtFireTime $fireTime) | Should Be $false
    }
}

Describe 'ConvertTo-JanetWebArmFireAt resolves every bare form to the NEXT occurrence' {
    $now = Get-Date -Year 2026 -Month 8 -Day 3 -Hour 22 -Minute 0 -Second 0 -Millisecond 0

    It 'a later time today stays today' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '23:30' -Now $now
        $d.Day | Should Be 3
        $d.Hour | Should Be 23
    }
    It 'an earlier time rolls to tomorrow' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '02:00' -Now $now
        $d.Day | Should Be 4
        $d.Hour | Should Be 2
    }
    # loop 2026-08-03: the engine's roll regex is UNANCHORED ('^\s*\d{1,2}:\d{2}'),
    # so it matches 'HH:mm:ss' too - but this resolver only handled 'HH:mm', leaving
    # the seconds form exposed to the same 24h roll. One resolver, one rule.
    It 'HH:mm:ss is handled too, with the seconds preserved' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '23:30:45' -Now $now
        $d.Day    | Should Be 3
        $d.Hour   | Should Be 23
        $d.Minute | Should Be 30
        $d.Second | Should Be 45
    }
    It 'HH:mm:ss earlier in the day also rolls to tomorrow' {
        $d = ConvertTo-JanetWebArmFireAt -Raw '02:00:30' -Now $now
        $d.Day | Should Be 4
    }
    It 'an out-of-range seconds value is refused, not silently wrapped' {
        (ConvertTo-JanetWebArmFireAt -Raw '02:00:99' -Now $now) | Should BeNullOrEmpty
    }
    It 'the existing contract is unchanged: ISO passes through, junk is refused' {
        (ConvertTo-JanetWebArmFireAt -Raw '2026-08-04T02:15:00' -Now $now).Hour | Should Be 2
        (ConvertTo-JanetWebArmFireAt -Raw 'tomorrow-ish' -Now $now) | Should BeNullOrEmpty
        (ConvertTo-JanetWebArmFireAt -Raw '99:99'        -Now $now) | Should BeNullOrEmpty
    }
}

Describe 'the resolved value survives a round trip through the engine parse' {

    # End to end on the two pure halves: what the arm route now stores must parse
    # back to the SAME instant the operator armed, and must not roll.
    It 'arm-time resolution + engine re-parse lands on the armed instant' {
        $now      = Get-Date -Year 2026 -Month 8 -Day 3 -Hour 22 -Minute 0 -Second 0 -Millisecond 0
        $resolved = ConvertTo-JanetWebArmFireAt -Raw '02:00' -Now $now      # -> 2026-08-04 02:00
        $stored   = ([datetime]$resolved).ToString('yyyy-MM-ddTHH:mm:ss')   # what the route writes back

        $reparsed = [datetime]::MinValue
        [datetime]::TryParse($stored, [ref]$reparsed) | Should Be $true
        $reparsed | Should Be $resolved
        # and at fire time (the armed instant, +2s tick slop) it must NOT roll
        (Test-EngineWouldRoll -Raw $stored -AtFireTime $resolved.AddSeconds(2)) | Should Be $false
    }
}

Describe 'the arm route resolves the ambiguous form and leaves dated ones alone' {
    $src = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw

    It 'the route rewrites a bare time-of-day restartTime to an absolute datetime' {
        ($src -match "if \(\`$rtRaw -match '\^\\d\{1,2\}:\\d\{2\}\(:\\d\{2\}\)\?\$'\)") | Should Be $true
        ($src -match "\`$armParams\['restartTime'\] = \(\[datetime\]\`$rtAbs\)\.ToString\('yyyy-MM-ddTHH:mm:ss'\)") | Should Be $true
    }
    It 'it reuses the ONE resolver rather than re-deriving the next-occurrence rule' {
        ($src -match "\`$rtAbs = ConvertTo-JanetWebArmFireAt -Raw \`$rtRaw") | Should Be $true
    }
    # Separate defect, same file: an unparseable/blank restart time REFUSES the whole
    # wave, but used to return a summary indistinguishable from a completed run, so the
    # banner read "Dispatch complete: 0 sent...". Reachable by design - the view allows a
    # blank time in rolling mode.
    It 'a refused wave is reported as REFUSED, not as a completed dispatch' {
        $eng = Get-Content (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Raw
        ($eng -match 'Dispatch REFUSED - \$why')                        | Should Be $true
        ($eng -match "rejected=\`$true; rejectReason=\`$why")            | Should Be $true
        $vw = Get-Content (Join-Path $script:Root 'web\js\views\restart.view.js') -Raw
        ($vw -match 'if \(sm\.rejected\)')                              | Should Be $true
        ($vw -match "banner\('Dispatch REFUSED - '")                    | Should Be $true
    }
    It 'the engine still has the day-roll (correct for a LIVE dispatch, which resolves once)' {
        # The roll is NOT a bug on the live path - the operator types 02:00 meaning the
        # next 02:00 and the engine is the only resolver in play. Removing it would break
        # live dispatch. This pin makes sure a future reader does not "fix" it there.
        $eng = Get-Content (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Raw
        ($eng -match "\`$restartTime = \`$restartTime\.AddDays\(1\)") | Should Be $true
    }
}
