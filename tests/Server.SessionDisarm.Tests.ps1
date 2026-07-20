# =============================================================================
#  Server.SessionDisarm.Tests.ps1 - Pester 3.4 tests for the loop-1 P2 fix:
#  server-side admin-session DISARM.
#
#  Defect (Opus server-layer review, loop 1): $state.AckGiven was set $true by
#  POST /api/session/start and NEVER cleared for the life of the process.
#  POST /api/session/end recorded closing notes only - after "End Session" the
#  destructive gate ($state.AckGiven -and $state.Cred) stayed armed, so the
#  operator's "I locked it" signal was false. DELETE /api/cred dropped the
#  credential but not the ack, so a later re-POST /api/cred silently re-armed
#  the gate with NO fresh responsibility acknowledgment (ack was effectively a
#  one-time-per-process flag).
#
#  Fix: /api/session/end drops AckGiven AND Cred (responds disarmed=true);
#  DELETE /api/cred also drops AckGiven; shell.js mirrors both (disarm() +
#  clearCred clears the janetweb_ack/janetweb_session sessionStorage keys) so
#  the ADMIN strip goes cold; the acas End Session flow calls ctx.session.disarm().
#
#  The request loop cannot be dot-sourced (live HttpListener), so these are
#  anchored source assertions against the real handler text - they fail if the
#  disarm lines are removed or drift out of their handlers.
#
#  Run:  Invoke-Pester -Path .\tests\Server.SessionDisarm.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$srv   = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw
$shell = Get-Content (Join-Path $script:Root 'web\js\shell.js') -Raw
$acas  = Get-Content (Join-Path $script:Root 'web\js\views\acas.view.js') -Raw

Describe 'POST /api/session/end disarms server-side (ack + cred dropped)' {
    # Slice the session/end handler: from its route match to its writeJson response.
    $start = $srv.IndexOf("'/api/session/end'")
    $endIx = $srv.IndexOf('disarmed=$true', $start)
    It 'the handler exists and answers disarmed=$true' {
        ($start -ge 0) | Should Be $true
        ($endIx -gt $start) | Should Be $true
    }
    $block = $srv.Substring($start, $endIx - $start)
    It 'drops the responsibility ack inside the handler, before the response' {
        ($block -match [regex]::Escape('$state.AckGiven = $false')) | Should Be $true
    }
    It 'drops the credential inside the handler, before the response' {
        ($block -match [regex]::Escape('$state.Cred = $null')) | Should Be $true
    }
    It 'still writes the SessionNotes row BEFORE disarming (notes are not lost)' {
        $notesIx = $block.IndexOf('Write-JanetWebRun')
        $ackIx   = $block.IndexOf('$state.AckGiven = $false')
        ($notesIx -ge 0) | Should Be $true
        ($notesIx -lt $ackIx) | Should Be $true
    }
}

Describe 'DELETE /api/cred also drops the ack (re-set cred needs a fresh ack)' {
    It 'the DELETE arm clears Cred AND AckGiven' {
        ($srv -match "if \(\`$verb -eq 'DELETE'\) \{ \`$state\.Cred = \`$null; \`$state\.AckGiven = \`$false;") | Should Be $true
    }
    It 'session/start still requires an explicit ack=true body (arming path unchanged)' {
        ($srv -match [regex]::Escape("if (`$ack) { `$state.AckGiven = `$true }")) | Should Be $true
    }
}

Describe 'shell.js mirrors the disarm (ADMIN strip goes cold)' {
    It 'exposes disarm on the session API' {
        ($shell -match 'disarm:\s*disarmSession') | Should Be $true
    }
    It 'disarmSession clears ack/active/credSet and both sessionStorage keys' {
        $ix = $shell.IndexOf('function disarmSession()')
        ($ix -ge 0) | Should Be $true
        $blk = $shell.Substring($ix, 400)
        ($blk -match 'Session\.ack = false') | Should Be $true
        ($blk -match "removeItem\('janetweb_ack'\)") | Should Be $true
        ($blk -match "removeItem\('janetweb_session'\)") | Should Be $true
    }
    It 'clearCred drops the client ack mirror too' {
        $ix = $shell.IndexOf('async function clearCred()')
        ($ix -ge 0) | Should Be $true
        $blk = $shell.Substring($ix, 600)
        ($blk -match 'Session\.ack = false') | Should Be $true
        ($blk -match "removeItem\('janetweb_ack'\)") | Should Be $true
    }
}

Describe 'acas End Session flow mirrors the server disarm' {
    It 'calls ctx.session.disarm() after a successful /session/end' {
        ($acas -match [regex]::Escape('ctx.session.disarm()')) | Should Be $true
    }
    It 'tells the operator the session is disarmed in the activity log' {
        ($acas -match 'DISARMED') | Should Be $true
    }
}
