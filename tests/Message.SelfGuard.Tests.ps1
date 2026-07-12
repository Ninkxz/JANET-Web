# =============================================================================
#  Message.SelfGuard.Tests.ps1 - Pester 3.4 for the Remote Message 1.3.4
#  dispatcher self-guard (loop-7 audit gap). PURE / offline unit scope - no real
#  host, no WinRM, no msg.exe. We assert the destructive SEND action can NEVER
#  WinRM-loopback and pop msg.exe on the JANET box (the host running the
#  HttpListener) itself, while a real remote target is retained (no over-drop):
#
#   (a) Test-JanetMessageHostIsSelf: self short-name / 127.0.0.1 -> $true, a
#       far host -> $false (the acas FAR-HOST no-over-drop assertion);
#   (b) 'send' with a self-only target -> total=0, a Self-guard warn, and NO
#       'Dispatching N host(s)' fan-out is ever started (short-circuits first);
#   (c) 'send' with loopback-only (127.0.0.1) is likewise emptied;
#   (d) 'send' with self + FAR-HOST drops ONLY self and dispatches the 1 real
#       host (retention proof - no over-drop end to end);
#   (e) 'ping' (read-only) with a self-only target is NOT self-guarded (the drop
#       is gated to the destructive send action only - no warn, host retained).
#
#  Reuses the shim/dispatch idiom from tests\Acas.SelfGuard.Tests.ps1.
#
#  Run:  Invoke-Pester -Path .\tests\Message.SelfGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.message.psm1') -Force -PassThru

$Self = $env:COMPUTERNAME
$Body = @{ title = 'Test'; body = 'hello'; parallel = $false }   # minimal valid send params

Describe 'Message 1.3.4 - Test-JanetMessageHostIsSelf (identity, no over-drop)' {
    It 'flags this dispatcher shortname as self' {
        (& $mod { param($h) Test-JanetMessageHostIsSelf $h } $Self) | Should Be $true
    }
    It 'flags a 127.x loopback literal as self' {
        (& $mod { param($h) Test-JanetMessageHostIsSelf $h } '127.0.0.1') | Should Be $true
    }
    It 'does NOT flag a real far host as self (no over-drop)' {
        (& $mod { param($h) Test-JanetMessageHostIsSelf $h } 'FAR-HOST-1') | Should Be $false
    }
}

Describe 'Message 1.3.4 - send self-guard (never message the dispatcher)' {

    It 'a self-only send returns total=0 with a Self-guard warn and NO WinRM fan-out' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $prm = $Body.Clone(); $prm['targets'] = $Self
        $res = & $mod {
            param($aid, $p, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $p -Credential $null -Emit $em
        } 'send' $prm $emit

        [int]$res.summary.total | Should Be 0
        @($res.rows).Count      | Should Be 0
        # Self-guard warning fired...
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' -and $_.text -match 'dispatcher' })
        $warn.Count | Should BeGreaterThan 0
        # ...and the 'Dispatching N host(s)' status (which sits AFTER the guard) never fired,
        # so no WinRM session was ever opened to self.
        $started = @($evts | Where-Object { $_.type -eq 'status' -and $_.text -match 'Dispatching \d+ host' })
        $started.Count | Should Be 0
    }

    It 'a loopback-only send (127.0.0.1) is also emptied by the self-guard' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $prm = $Body.Clone(); $prm['targets'] = '127.0.0.1'
        $res = & $mod {
            param($aid, $p, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $p -Credential $null -Emit $em
        } 'send' $prm $emit

        [int]$res.summary.total | Should Be 0
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should BeGreaterThan 0
    }

    It 'a mixed send (self + FAR-HOST) drops ONLY self and dispatches the 1 real host' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        # requirePing skips the far host before WinRM so the run stays fast/offline; the
        # self-guard runs first and independently, so this still proves self is dropped and
        # the real host is RETAINED (it reaches the dispatch fan-out).
        $prm = $Body.Clone(); $prm['targets'] = "$Self`nFAR-HOST-1"; $prm['requirePing'] = $true
        $res = & $mod {
            param($aid, $p, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $p -Credential $null -Emit $em
        } 'send' $prm $emit

        # exactly one host survived the self-guard (the far host), self was dropped
        [int]$res.summary.total | Should Be 1
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' -and $_.text -match [regex]::Escape($Self) })
        $warn.Count | Should BeGreaterThan 0
        $started = @($evts | Where-Object { $_.type -eq 'status' -and $_.text -match 'Dispatching 1 host' })
        $started.Count | Should BeGreaterThan 0
    }
}

Describe 'Message 1.3.4 - ping stays self-inclusive (guard gated to send only)' {

    It 'a self-only ping is NOT self-guarded (no warn, host retained)' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $p, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $p -Credential $null -Emit $em
        } 'ping' @{ targets = $Self } $emit

        # read-only path keeps the dispatcher: it is dispatched (total=1) and NO self-guard warn.
        [int]$res.summary.total | Should Be 1
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should Be 0
    }
}
