# =============================================================================
#  Restart.ArmedDispatch.Tests.ps1 - Pester 3.4 tests pinning the CONTRACT
#  between the server-side armed restart and the restart engine / the UI
#  (audit 2026-07-25 convergence C1).
#
#  The point of this file is the word "EARLIER". Moving the delayed start out of
#  the browser is only safe if the typed-confirm gate did not dissolve on the
#  way: it now runs at ARM time, and it STILL runs at fire time because the arm
#  stores the operator's param set verbatim and replays it through the ordinary
#  dispatch path. These tests drive BOTH gates with the same param sets and
#  assert they agree, then pin the UI call sites that must not regress.
#
#  Run:  Invoke-Pester -Path .\tests\Restart.ArmedDispatch.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.restart.psm1') -Force -PassThru
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

# Run dispatch-restart with a param set and collect everything it emitted. The
# target is a deliberately non-existent host and every case below is refused at
# a gate BEFORE any WinRM/ping work, so nothing is ever contacted.
function Invoke-RrsDispatchProbe {
    param([hashtable]$Params)
    $events = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$events.Add($e) }.GetNewClosure()
    $res = & $script:Mod { param($p, $em) Invoke-JanetToolAction -ActionId 'dispatch-restart' -Params $p -Emit $em } $Params $emit
    @{ Result = $res; Events = @($events); Text = (@($events | ForEach-Object { [string]$_.text }) -join ' | ') }
}

$script:LiveNoWord = @{ targets = 'ARMTEST-NOSUCH-HOST-A'; restartTime = '23:59'; confirm = ''; dryRun = $false }
$script:LiveBadCase = @{ targets = 'ARMTEST-NOSUCH-HOST-A'; restartTime = '23:59'; confirm = 'restart'; dryRun = $false }

Describe 'The typed RESTART gate did not dissolve - it moved EARLIER' {

    # The fire-time gate, driven for real through the engine.
    It 'the ENGINE still refuses a live dispatch with no confirm word' {
        $p = Invoke-RrsDispatchProbe $script:LiveNoWord
        $p.Result.summary.rejected | Should Be $true
        $p.Result.summary.sent | Should Be 0
        @($p.Result.rows).Count | Should Be 0
        $p.Text | Should Match 'type RESTART'
    }
    It 'the ENGINE still refuses a live dispatch whose confirm word is the wrong case' {
        $p = Invoke-RrsDispatchProbe $script:LiveBadCase
        $p.Result.summary.rejected | Should Be $true
        @($p.Result.rows).Count | Should Be 0
    }

    # The arm-time gate, driven for real through the server helper, on the SAME
    # param sets. Same verdict = the gate moved, it did not disappear.
    It 'the ARM gate refuses exactly the same param set the engine refuses (no word)' {
        $a = Test-JanetWebArmRequest -Params $script:LiveNoWord -FireAtRaw '23:59' -Now (Get-Date '2026-07-25 10:00:00')
        $a.ok | Should Be $false
        $a.error | Should Match 'type RESTART'
    }
    It 'the ARM gate refuses exactly the same param set the engine refuses (wrong case)' {
        $a = Test-JanetWebArmRequest -Params $script:LiveBadCase -FireAtRaw '23:59' -Now (Get-Date '2026-07-25 10:00:00')
        $a.ok | Should Be $false
    }
    It 'an ACCEPTED arm carries the confirm word onward, so the engine gate passes at fire time too' {
        $good = @{ targets = 'ARMTEST-NOSUCH-HOST-A'; restartTime = '23:59'; confirm = 'RESTART'; dryRun = $false }
        $a = Test-JanetWebArmRequest -Params $good -FireAtRaw '23:59' -Now (Get-Date '2026-07-25 10:00:00')
        $a.ok | Should Be $true
        # the record the server stores is the operator's param set, unedited
        $arm = New-JanetWebArmedRestart -Params $good -FireAt $a.fireAt -SessionId 'S' -Operator 'tester'
        ([string]$arm.Params['confirm']) | Should Be 'RESTART'
        ([string]$arm.Params['targets']) | Should Be 'ARMTEST-NOSUCH-HOST-A'
    }
    It 'an arm never smuggles in the server-only __job cancel bridge' {
        $arm = New-JanetWebArmedRestart -Params @{ targets = 'WS-A'; confirm = 'RESTART' } -FireAt ((Get-Date).AddHours(1)) -SessionId 'S' -Operator 'tester'
        $arm.Params.ContainsKey('__job') | Should Be $false
    }
    It 'counts the armed hosts the way the engine parses them (case-insensitive dedup)' {
        $arm = New-JanetWebArmedRestart -Params @{ targets = "WS-A`nws-a, WS-B ;WS-C"; confirm = 'RESTART' } -FireAt ((Get-Date).AddHours(1)) -SessionId 'S' -Operator 'tester'
        $arm.HostCount | Should Be 3
        (& $script:Mod { param($t) (ConvertTo-JanetHostList $t).Count } "WS-A`nws-a, WS-B ;WS-C") | Should Be 3
    }
}

Describe 'The restart manifest is untouched by the arm work' {
    # arm-dispatch is a SERVER route, deliberately not a manifest action: nothing
    # in the tool registry may advertise an "arm" action, or the generic action
    # dispatcher would start treating it as one.
    It 'exposes no arm action in the manifest' {
        $ids = @(& $script:Mod { @((Get-JanetToolManifest).actions | ForEach-Object { $_.id }) })
        ($ids -match '(?i)arm') -join ',' | Should Be ''
    }
    It 'still marks dispatch-restart destructive' {
        $d = & $script:Mod { (@((Get-JanetToolManifest).actions | Where-Object { $_.id -eq 'dispatch-restart' }))[0].destructive }
        $d | Should Be $true
    }
}

Describe 'restart.view.js no longer owns the countdown' {
    $script:View = Get-Content -LiteralPath (Join-Path $script:Root 'web\js\views\restart.view.js') -Raw

    It 'hands the delayed start to the server (ctx.jobs.armRestart call site)' {
        $script:View | Should Match 'ctx\.jobs\.armRestart\('
    }
    It 'no longer launches a dispatch from a browser timer' {
        # the old bug: setInterval(tick,1000) whose tick called launchDispatch at zero.
        $timerBlocks = [regex]::Matches($script:View, 'setInterval\([\s\S]{0,900}?\}, 1000\)')
        $bad = @($timerBlocks | Where-Object { $_.Value -match 'launchDispatch' })
        $bad.Count | Should Be 0
    }
    It 'stands the wave down through the server, not by clearing a local timer' {
        $script:View | Should Match 'ctx\.jobs\.disarm\('
    }
    It 'reattaches to an already-running dispatch instead of re-posting it' {
        $script:View | Should Match "ctx\.adopt\('dispatch-restart'"
        # the ONLY ctx.run for the destructive action stays in launchDispatch
        ([regex]::Matches($script:View, "ctx\.run\('dispatch-restart'")).Count | Should Be 1
    }
    It 'still gates the dispatch with ctx.arm + the typed RESTART word (never ctx.confirm)' {
        $script:View | Should Match 'await ctx\.arm\('
        $script:View | Should Match "confirmWord: p\.dryRun \? null : 'RESTART'"
        $script:View | Should Match "if \(!p\.dryRun\) p\.confirm = 'RESTART';"
    }
    It 'the delayed-start checkbox now promises the wave survives the browser' {
        $m = [regex]::Match($script:View, 'var beginAtCb = ui\.checkbox\([\s\S]*?\}\);')
        $m.Success | Should Be $true
        $m.Value | Should Match 'close this browser tab'
        $m.Value | Should Not Match 'Leave the tool open'
    }
}

Describe 'shell.js reattach is status-only, never a resume' {
    $script:Shell = Get-Content -LiteralPath (Join-Path $script:Root 'web\js\shell.js') -Raw

    It 'exposes an attach path that only polls the existing job stream' {
        # isolate the attach() body and prove it contains no action POST at all
        $m = [regex]::Match($script:Shell, 'function attach\(toolId, actionId, jobId, opts\) \{[\s\S]*?\n    \}')
        $m.Success | Should Be $true
        $m.Value | Should Match "poll\(key, g\)"
        $m.Value | Should Not Match "api\('POST'"
        $m.Value | Should Not Match "'/tool/'"
    }
    It 'replays the adopted run from the start of the server-held event stream' {
        $m = [regex]::Match($script:Shell, 'function attach\(toolId, actionId, jobId, opts\) \{[\s\S]*?\n    \}')
        $m.Value | Should Match 'rs\.since = 0'
    }
    It 'classifies an unknown action as destructive (fail closed)' {
        $m = [regex]::Match($script:Shell, 'function actionIsDestructive\(toolId, actionId\) \{[\s\S]*?\n  \}')
        $m.Success | Should Be $true
        $m.Value | Should Match 'if \(!t \|\| !t\.actions\) return true;'
        $m.Value | Should Match 'if \(!a\) return true;'
    }
    It 'renders a shell-level armed bar with its own DISARM control' {
        $script:Shell | Should Match "dom\.armBar"
        $script:Shell | Should Match "'DISARM'"
        $script:Shell | Should Match 'JobsWatch\.disarm\(\)'
    }
    It 'offers Cancel beside every reattachable run' {
        $script:Shell | Should Match "'Cancel run'"
    }
}
