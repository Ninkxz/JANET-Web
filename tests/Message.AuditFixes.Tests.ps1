# =============================================================================
#  Message.AuditFixes.Tests.ps1 - Pester 3.4 for the Remote Message 1.3.5
#  audit 2026-07-24 fix pass. PURE / offline unit scope: no WinRM session, no
#  msg.exe, no reachable host is ever contacted (the one end-to-end run below
#  targets an unresolvable name and is short-circuited by the operator's own
#  skip-if-not-pingable gate before any session is opened).
#
#   (1) [P2] wrong-box guard - the destructive send now proves, INSIDE the remote
#       block, that the box which answered is the box that was dialed, and aborts
#       before msg.exe if it is not (stale DNS / reused IP);
#   (2) [P2] the per-job watchdog clock starts when the worker STARTS, not at
#       enqueue - a host still queued behind a saturated pool can never be
#       declared timed-out before it has run;
#   (3) [P3] "nobody logged on" and operator-requested TCP-probe skips book as
#       Skipped, not Failure;
#   (4) [P3] watchdog-/cancel-abandoned hosts report 'Timed out' / 'Abandoned',
#       never the unmeasured network claim 'Unreachable';
#   (5) re-verification that the dispatcher self-guard identity set is intact.
#
#  Run:  Invoke-Pester -Path .\tests\Message.AuditFixes.Tests.ps1
# =============================================================================
$script:Root    = Split-Path $PSScriptRoot -Parent
$script:ModPath = Join-Path $script:Root 'modules\JanetWeb.message.psm1'
$mod = Import-Module $script:ModPath -Force -PassThru
$script:Src = Get-Content -LiteralPath $script:ModPath -Raw

# Verbatim replica of the dialed-target -> expected-COMPUTERNAME calculation the
# send worker performs (IPv4 literal => '' => guard skipped), matching the shared
# suite shape pinned in tests\PkginstallSecureboot.WrongBoxGuard.Tests.ps1.
function Get-ExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }
# Verbatim replica of the hard-abort boolean the remote block evaluates, with the
# answering box's real $env:COMPUTERNAME swapped for a test-supplied value.
function Test-WrongBoxAbort {
    param([string]$Expected, [string]$Answering)
    [bool]($Expected -and ($Answering.Trim().ToUpper() -ne ([string]$Expected).Trim().ToUpper()))
}

Describe '(1) Message 1.3.5 - the destructive send carries a wrong-box guard' {

    # The remote block cannot be executed here (it would pop msg.exe on this box), so
    # the guard's PRESENCE and ORDERING are pinned against the module text and its
    # DECISION is pinned behaviourally by the replica above.
    $blockMatch = [regex]::Match($script:Src,
        'Invoke-Command -Session \$session -ScriptBlock \{(?<b>.*?)\} -ArgumentList',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    It 'the remote send scriptblock is still shaped as expected (regex anchor holds)' {
        $blockMatch.Success | Should Be $true
    }

    It 'the remote block compares the answering box own $env:COMPUTERNAME (was absent)' {
        $blockMatch.Groups['b'].Value.Contains('$env:COMPUTERNAME') | Should Be $true
    }

    It 'the guard runs BEFORE any msg.exe call (hard abort, nothing is popped)' {
        $b = $blockMatch.Groups['b'].Value
        $guardIdx = $b.IndexOf('$env:COMPUTERNAME')
        $msgIdx   = $b.IndexOf('& msg.exe')          # the invocation, not the word in a comment
        $guardIdx | Should BeGreaterThan -1
        $msgIdx   | Should BeGreaterThan $guardIdx
    }

    It 'the dialed expected-name is actually passed into the remote block' {
        [bool]($script:Src -match '-ArgumentList \$title, \$body, \$timeoutSec, \$requireOK, \$expectedName') | Should Be $true
    }

    It 'a hostname mismatch hard-aborts (stale DNS / reused IP)' {
        (Test-WrongBoxAbort -Expected 'WS01' -Answering 'WS02') | Should Be $true
    }
    It 'a case-different match does NOT abort (no over-block)' {
        (Test-WrongBoxAbort -Expected 'WS01' -Answering 'ws01') | Should Be $false
    }
    It 'an FQDN target compares on its first dot-token' {
        (Get-ExpectedName 'WS01.area.af.mil') | Should Be 'WS01'
    }
    It 'an IPv4-literal target skips the compare (no DNS indirection to be fooled by)' {
        (Get-ExpectedName '10.1.2.3') | Should Be ''
        (Test-WrongBoxAbort -Expected (Get-ExpectedName '10.1.2.3') -Answering 'SOME-OTHER-BOX') | Should Be $false
    }
}

Describe '(2) Message 1.3.5 - the watchdog clock starts at RUN, not at enqueue' {

    It 'a host still QUEUED (no start stamp) can never expire, however long it has waited' {
        # The old code clocked from BeginInvoke, so this host - queued behind a
        # saturated pool for 10 minutes without ever running - was declared timed out.
        $r = & $mod { param($s, $n, $l) Test-JanetMessageJobExpired $s $n $l } `
                $null (Get-Date) 90
        $r | Should Be $false
    }

    It 'a RUNNING host past the limit does expire (the watchdog still works)' {
        $now = Get-Date
        $r = & $mod { param($s, $n, $l) Test-JanetMessageJobExpired $s $n $l } `
                $now.AddSeconds(-91) $now 90
        $r | Should Be $true
    }

    It 'a RUNNING host inside the limit does not expire' {
        $now = Get-Date
        $r = & $mod { param($s, $n, $l) Test-JanetMessageJobExpired $s $n $l } `
                $now.AddSeconds(-10) $now 90
        $r | Should Be $false
    }

    It 'the dispatcher no longer stamps an enqueue time on the job record' {
        # BeginInvoke only QUEUES when the pool is full, so an enqueue stamp is not a
        # runtime clock. The worker stamps $startMap the instant it begins instead.
        [bool]($script:Src -match 'Async=\$ps\.BeginInvoke\(\); StartTime=') | Should Be $false
        [bool]($script:Src -match '\$startMap\[\$hostname\] = Get-Date')     | Should Be $true
        [bool]($script:Src -match 'Test-JanetMessageJobExpired \$startMap\[\$j\.Host\]') | Should Be $true
    }
}

Describe '(3) Message 1.3.5 - a skip is booked Skipped, not Failure' {

    It 'nobody logged on -> Skipped (was Failure)' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false 'NoSessions') | Should Be 'Skipped'
    }
    It 'an operator-requested TCP-probe skip -> Skipped (was Failure)' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false 'Skipped') | Should Be 'Skipped'
    }
    It 'an unconfirmed delivery stays Skipped (unchanged)' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false 'Unknown') | Should Be 'Skipped'
    }
    It 'a confirmed delivery stays Success' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $true 'Delivered') | Should Be 'Success'
    }
    It 'a real delivery failure stays Failure (no over-forgiving)' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false 'Failed') | Should Be 'Failure'
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false '')       | Should Be 'Failure'
    }
    It 'a wrong-box abort is a Failure, never a skip' {
        (& $mod { param($s, $m) Get-JanetMessageSendVerdict $s $m } $false 'WrongBox') | Should Be 'Failure'
    }

    It 'the no-interactive-session branch returns the NoSessions status the verdict keys on' {
        [bool]($script:Src -match "Status = 'NoSessions'") | Should Be $true
    }

    It 'END TO END: a probe-skipped host audits Skipped and lands in summary.skipped, not failed' {
        # Unresolvable target: the TCP probe fails instantly (no DNS), requirePing bails
        # BEFORE New-PSSession, so nothing is contacted.
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $prm  = @{ targets = 'NO-SUCH-HOST-JANET-TEST'; title = 'T'; body = 'b'
                   parallel = $false; requirePing = $true }
        $res = & $mod {
            param($aid, $p, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $p -Credential $null -Emit $em
        } 'send' $prm $emit

        [int]$res.summary.total   | Should Be 1
        [int]$res.summary.skipped | Should Be 1   # <-- was failed=1 before the fix
        [int]$res.summary.failed  | Should Be 0
        [int]$res.summary.ok      | Should Be 0

        $audits = @($evts | Where-Object { $_.type -eq 'audit' })
        $audits.Count            | Should Be 1
        [string]$audits[0].result | Should Be 'Skipped'

        @($res.rows).Count             | Should Be 1
        [string]$res.rows[0].Status    | Should Be 'Skipped'
    }
}

Describe '(4) Message 1.3.5 - abandoned hosts are not called Unreachable' {

    It 'a watchdog-abandoned host reports Timed out' {
        (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $false 'TimedOut' $false) | Should Be 'Timed out'
    }
    It 'a cancel-abandoned host reports Abandoned' {
        (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $false 'Cancelled' $false) | Should Be 'Abandoned'
    }
    It 'neither abandoned status makes the unmeasured Unreachable claim' {
        foreach ($ms in 'TimedOut', 'Cancelled') {
            (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $false $ms $false) | Should Not Be 'Unreachable'
        }
    }
    It 'a host that WAS probed and stayed silent still reports Unreachable (no over-correction)' {
        (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $false '' $false) | Should Be 'Unreachable'
    }
    It 'a reached-but-undelivered host still reports Undelivered' {
        (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $false 'Failed' $true) | Should Be 'Undelivered'
    }
    It 'a delivered host still reports Delivered' {
        (& $mod { param($s, $m, $p) Get-JanetMessageRowStatus $s $m $p } $true 'Delivered' $true) | Should Be 'Delivered'
    }
    It 'the watchdog and cancel rows tag their disposition instead of defaulting to Unreachable' {
        [bool]($script:Src -match "MsgStatus='TimedOut'")  | Should Be $true
        [bool]($script:Src -match "MsgStatus='Cancelled'") | Should Be $true
    }
}

Describe '(6) Message 1.3.6 - the whole run has a ceiling, and unmeasured rows stay honest' {
    # audit 2026-07-25 (fable re-audit follow-up):
    #  (a) the per-job watchdog is blind to a host that never STARTED (no start stamp =
    #      no clock, by design - see (2) above), so the drain needed its own wall-clock
    #      ceiling or a stopped-but-never-settled runspace could hold the run open;
    #  (b) an EndInvoke failure is OUR error and claimed nothing about the target;
    #  (c) a cancelled PING host was booked Pingable=No for a probe that never ran.

    It 'the ceiling covers every WAVE the pool must run, plus one wave of slack' {
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 100 16 90) | Should Be 720
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 1 16 90)   | Should Be 180
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 32 16 90)  | Should Be 270
    }

    It 'the ceiling is always longer than one per-job window (a slow run is never cut short)' {
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 5 5 90) | Should BeGreaterThan 90
    }

    It 'degenerate inputs are clamped, never divided by zero' {
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 0 0 90) | Should Be 180
        (& $mod { param($t,$th,$p) Get-JanetMessageRunCeilingSeconds -Total $t -Threads $th -PerJobSeconds $p } 0 0 0)  | Should Be 2
    }

    It 'the drain loop actually arms the ceiling and reaps what is left' {
        [bool]($script:Src -match '\$runCeilingSeconds = Get-JanetMessageRunCeilingSeconds') | Should Be $true
        [bool]($script:Src -match '\(Get-Date\) -ge \$runDeadline')                          | Should Be $true
    }

    It 'a worker crash reports Worker error, not the unmeasured Unreachable claim' {
        (& $mod { param($s,$m,$p) Get-JanetMessageRowStatus $s $m $p } $false 'WorkerError' $false) | Should Be 'Worker error'
        (& $mod { param($s,$m,$p) Get-JanetMessageRowStatus $s $m $p } $false 'WorkerError' $false) | Should Not Be 'Unreachable'
    }

    It 'a worker crash is still a real Failure (not forgiven into a skip)' {
        (& $mod { param($s,$m) Get-JanetMessageSendVerdict $s $m } $false 'WorkerError') | Should Be 'Failure'
    }

    It 'the EndInvoke fallback row tags WorkerError and leaves reachability unmeasured' {
        [bool]($script:Src -match "Pingable=\`$null; Success=\`$false; Sessions=0; MsgStatus='WorkerError'") | Should Be $true
    }

    It 'the PING row projection renders a BLANK reachability cell when the probe never ran' {
        # BOTH row projections (ping and send) must carry the null-check now; the ping one
        # was a bare [bool] cast, which booked a never-probed host as an affirmative 'No'.
        $proj = @([regex]::Matches($script:Src, [regex]::Escape('Pingable=$(if ($null -eq $r.Pingable) { '''' } else { [bool]$r.Pingable })')))
        $proj.Count | Should Be 2
        [bool]($script:Src -match 'Pingable=\[bool\]\$r\.Pingable') | Should Be $false
    }
}

Describe '(5) Message 1.3.5 - dispatcher self-guard identity set still intact' {
    # Re-verification only (verified correct 2026-07-24, unchanged by this pass): the
    # unary-comma return is covered behaviourally by SelfGuard.CaseInsensitive.Tests.ps1;
    # here we pin the bound-NIC IPv4 enumeration, which stops a pasted IP-literal that
    # names this box (but is not registered in DNS under its name) from slipping through.
    It 'Get-JanetMessageLocalIdentity returns an intact HashSet (unary-comma form)' {
        $isSet = & $mod { (Get-JanetMessageLocalIdentity) -is [System.Collections.Generic.HashSet[string]] }
        $isSet | Should Be $true
    }
    It 'every locally-BOUND unicast IPv4 is in the identity set' {
        $bound = @()
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $bound += $ua.Address.IPAddressToString }
            }
        }
        $missing = @($bound | Where-Object { -not (& $mod { param($t) Test-JanetMessageHostIsSelf $t } $_) })
        $missing.Count | Should Be 0
    }
}
