# =============================================================================
#  Wpt.SelfGuardAndClean.Tests.ps1 - Pester 3.4 tests for two prior-review open
#  items fixed in JanetWeb.wpt.psm1:
#
#   (a) Reboot self-guard: 'reboot' / 'reboot-schedule' now run every target
#       through Remove-WptSelfTargets (mirrors JanetWeb.restart.psm1's
#       dispatch-restart self-guard) before ever touching WptRebootBlock /
#       WptRebootScheduleBlock, so the JANET dispatcher host itself can never
#       be rebooted mid-dispatch.
#   (b) IPv4 false-abort fix: the DNS-mismatch hard-abort guards used to run
#       ($Computer -split '.')[0] against an IPv4-literal target, which just
#       yields the first octet and could never match a real $env:COMPUTERNAME
#       - a guaranteed false abort. The guard is now skipped entirely for an
#       IPv4-literal target (kept active for hostname targets).
#
#  Invoke-Command / Restart-Computer are shadowed inside the module scope
#  (same technique as Wpt.Guards.Tests.ps1) so NO real WinRM/reboot call ever
#  leaves this box - unit scope only, no host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.SelfGuardAndClean.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
# -----------------------------------------------------------------------------
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
Add-ShimGuard $m

# Drive the REAL entry point in module scope, capturing every emitted event so
# we can assert the self-guard fired and no dispatch/reboot was ever started.
function Invoke-WptAction {
    param([string]$ActionId, [hashtable]$Params)
    $script:sgEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:sgEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:sgEvents) }
}

Describe 'Test-WptHostIsSelf predicate (the reboot self-guard uses this)' {
    It 'flags the loopback literal 127.0.0.1 as self' {
        (& $m { Test-WptHostIsSelf '127.0.0.1' }) | Should Be $true
    }
    It 'does NOT flag an obviously-remote hostname' {
        (& $m { Test-WptHostIsSelf 'WS-REMOTE-999' }) | Should Be $false
    }
}

Describe 'Reboot self-guard drops the dispatcher host before dispatch (FIX 3a)' {
    $out = Invoke-WptAction -ActionId 'reboot' -Params @{ targets = '127.0.0.1' }

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning naming the dropped host' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
    }
    It 'NEVER starts a fan-out (no status event = no runspace / no host contact)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'Reboot-schedule self-guard drops the dispatcher host before dispatch (FIX 3a)' {
    $out = Invoke-WptAction -ActionId 'reboot-schedule' -Params @{ targets = '127.0.0.1'; seconds = 300; message = 'test' }

    It 'returns total=0 with selfSkipped=1 and no rows' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning and never starts a fan-out' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

# -----------------------------------------------------------------------------
#  loop20: self-guard coverage extended to the three OTHER reboot-capable actions
#  (bulk-patch FORCED, kb-install reboot-ENABLED, registry-key-apply reboot-after).
#  Each now runs targets through Remove-WptSelfTargets BEFORE fan-out, exactly like
#  reboot/reboot-schedule above. A self-only target must drop to total=0 /
#  selfSkipped=1 with a Self-guard warn. Only the reboot-capable sub-mode is guarded
#  (non-invasive patch / noreboot KB / no-reboot-after apply are untouched).
# -----------------------------------------------------------------------------
Describe 'bulk-patch FORCED self-guard drops the dispatcher before dispatch (loop20 P1)' {
    $out = Invoke-WptAction -ActionId 'bulk-patch' -Params @{ targets = '127.0.0.1'; mode = 'forced' }
    It 'self-only forced patch -> total=0, selfSkipped=1, Self-guard warn' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        ($out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }) | Should Not BeNullOrEmpty
    }
}

Describe 'kb-install reboot-ENABLED self-guard drops the dispatcher (loop20 P2)' {
    $out = Invoke-WptAction -ActionId 'kb-install' -Params @{ targets = '127.0.0.1'; kbs = 'KB5001234'; noreboot = $false }
    It 'self-only reboot-enabled KB install -> total=0, selfSkipped=1, Self-guard warn' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        ($out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }) | Should Not BeNullOrEmpty
    }
}

Describe 'registry-key-apply reboot-after self-guard drops the dispatcher (loop20 P2)' {
    $key = & $m { @((Get-WptRegKeyCatalog).Keys)[0] }
    $out = Invoke-WptAction -ActionId 'registry-key-apply' -Params @{ targets = '127.0.0.1'; cvekey = $key; rebootafter = $true }
    It 'self-only reboot-after STIG apply -> total=0, selfSkipped=1, Self-guard warn' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        ($out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }) | Should Not BeNullOrEmpty
    }
}

Describe 'WptRebootBlock DNS-mismatch guard skips IPv4-literal targets (FIX 3b)' {

    It 'IPv4-literal target: DNS-mismatch probe is skipped entirely and the reboot path proceeds' {
        $r = & $m {
            $script:probeCalled = $false
            $script:restartCalled = $false
            $__shims = Save-ShimState @('Invoke-Command','Restart-Computer')
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                $script:probeCalled = $true
                return 'SOMEOTHERBOX'   # would read as a "mismatch" IF the guard evaluated it
            }
            function script:Restart-Computer {
                param($ComputerName, $Force, $ErrorAction, $Credential)
                $script:restartCalled = $true
            }
            try {
                $res = & $script:WptRebootBlock -Computer '198.51.100.5' -Cred $null -Auth 'Default'
                @{ Result = $res; ProbeCalled = $script:probeCalled; RestartCalled = $script:restartCalled }
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        }
        $r.ProbeCalled          | Should Be $false   # IPv4 literal -> DNS-mismatch probe never runs
        $r.RestartCalled        | Should Be $true     # guard did not hard-abort; reboot path proceeded
        $r.Result.Detail        | Should Not Match 'DNS mismatch'
        [bool]$r.Result.Success | Should Be $true
    }

    It 'hostname target: DNS-mismatch guard still hard-aborts on a confirmed mismatch (guard stays active)' {
        $r = & $m {
            $script:restartCalled = $false
            $__shims = Save-ShimState @('Invoke-Command','Restart-Computer')
            function script:Invoke-Command {
                param($ComputerName, $SessionOption, $ErrorAction, $Credential, $Authentication, $ArgumentList, [scriptblock]$ScriptBlock)
                return 'SOMEOTHERBOX'   # a genuine mismatch for a hostname target
            }
            function script:Restart-Computer {
                param($ComputerName, $Force, $ErrorAction, $Credential)
                $script:restartCalled = $true
            }
            try {
                $res = & $script:WptRebootBlock -Computer 'WS-REMOTE-999' -Cred $null -Auth 'Default'
                @{ Result = $res; RestartCalled = $script:restartCalled }
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        }
        $r.Result.Detail  | Should Match 'DNS mismatch'
        $r.Result.Detail  | Should Match 'ABORTED, no reboot sent'
        $r.RestartCalled  | Should Be $false   # hard-abort must prevent Restart-Computer
        [bool]$r.Result.Success | Should Be $false
    }
}

# loop90: WptCleanBlock (cleanup-disk - deletes temp files, caches, and stale user PROFILES) and
# WptCleanUserAppsBlock (deletes per-profile app binaries) are DESTRUCTIVE workers that were the two wpt
# destructive blocks MISSING the wrong-box (DNS-mismatch) guard every sibling carries. A stale DNS / reused IP
# could delete on the WRONG machine. Both verify the answering box's $env:COMPUTERNAME == the dialed
# shortname before any deletion (IPv4-literal skips; empty probe proceeds), mirroring WptPatchBlock.
# Audit 2026-07-23 deferred pass: the dedicated probe round-trip is FOLDED into each block's first working
# Invoke-Command (the WptRebootScheduleBlock pattern) - the remote scriptblock's FIRST statement does the
# name compare and returns a DnsMismatch marker; the controller hard-aborts with the SAME abort strings.
# The guard DECISION is tested via a verbatim replica + static presence assertions pinning the folded shape.
$script:WptSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
function Test-WptCleanWrongBoxAbort { param([string]$Computer,[string]$Answering)
    $skip = ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$')
    if ($skip) { return $false }
    $targetShort = ($Computer -split '\.')[0]
    [bool]($Answering -and ($Answering.Trim().ToUpper() -ne $targetShort.ToUpper()))
}

Describe 'WptCleanBlock + WptCleanUserAppsBlock wrong-box (DNS-mismatch) guard (loop90)' {
    It 'a hostname whose box answers a DIFFERENT name aborts' {
        Test-WptCleanWrongBoxAbort 'WS01.area.af.mil' 'WS02' | Should Be $true
    }
    It 'the matching box (same shortname, case-insensitive) does NOT abort' {
        Test-WptCleanWrongBoxAbort 'WS01.area.af.mil' 'WS01' | Should Be $false
        Test-WptCleanWrongBoxAbort 'WS01' 'ws01'             | Should Be $false
    }
    It 'an IPv4-literal target skips the compare (no shortname to match)' {
        Test-WptCleanWrongBoxAbort '10.1.2.3' 'ANY-NAME' | Should Be $false
    }
    It 'an empty probe (COMPUTERNAME unreadable) proceeds - no false abort' {
        Test-WptCleanWrongBoxAbort 'WS01.area.af.mil' '' | Should Be $false
    }
    It 'the guard is PRESENT in BOTH destructive clean blocks (folded first-statement COMPUTERNAME compare + hard-abort)' {
        # WptCleanBlock aborts with "nothing cleaned"; WptCleanUserAppsBlock with "nothing removed"
        # (the abort strings are UNCHANGED by the audit 2026-07-23 deferred-pass fold).
        ($script:WptSrc -match "DNS mismatch: dialed '\`$targetShort' but remote is.*ABORTED, nothing cleaned") | Should Be $true
        ($script:WptSrc -match "DNS mismatch: dialed '\`$targetShort' but remote is.*ABORTED, nothing removed") | Should Be $true
        # The standalone probe round-trip is GONE: each block folds the name check into its first
        # working Invoke-Command (first-statement-inside pattern). Extract each block's source up to
        # its abort string and pin the folded guard inside it: the remote-side compare + the
        # DnsMismatch marker return (IPv4-literal skips; unreadable name proceeds).
        $cleanBlk = [regex]::Match($script:WptSrc, "(?s)\`$script:WptCleanBlock = \{.*?ABORTED, nothing cleaned").Value
        $userBlk  = [regex]::Match($script:WptSrc, "(?s)\`$script:WptCleanUserAppsBlock = \{.*?ABORTED, nothing removed").Value
        $cleanBlk | Should Not BeNullOrEmpty
        $userBlk  | Should Not BeNullOrEmpty
        foreach ($blk in @($cleanBlk, $userBlk)) {
            ($blk -match [regex]::Escape('if (-not $isIPv4 -and $expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper()))')) | Should Be $true
            ($blk -match [regex]::Escape('return @{ DnsMismatch = $env:COMPUTERNAME }')) | Should Be $true
        }
        # and the old dedicated clean-block probe idiom must NOT come back (fold holds)
        ([regex]::Matches($script:WptSrc, "\`$actualName = try \{ Invoke-Command -Session \`$sess -EA Stop -ScriptBlock \{ \`$env:COMPUTERNAME \} \} catch \{ '' \}").Count) | Should Be 1
    }
    It 'wpt manifest is at or past 6.10.0 (exact pin migrated to the newest bump: audit 2026-07-24, 6.10.1)' {
        ([version][string](& $m { (Get-JanetToolManifest).version }) -ge [version]'6.10.0') | Should Be $true
    }
}

# -----------------------------------------------------------------------------
#  Audit 2026-07-23 deferred pass: the pool-runspace fan-out workers used to carry
#  INLINE copies of the TCP reachability probe (~14 blocks) and the wrong-box
#  DNS-name compare (~10 blocks) because bare worker runspaces can't see module
#  functions. Invoke-WptFanOut (and Invoke-WptSingleHostCancelable) now INJECT
#  Test-WptHostReachable + Test-WptRemoteNameMatch into the worker ISS instead.
#  These pins replace the old inline-idiom assertions with equal strictness:
#  the injection plumbing exists, the workers call the injected helpers, only the
#  canonical probe copy remains, and the per-block abort strings are unchanged.
# -----------------------------------------------------------------------------
Describe 'Unified fan-out ISS helper injection (audit 2026-07-23 deferred pass)' {
    It 'Invoke-WptFanOut takes -InjectFunctions and adds each as a SessionStateFunctionEntry' {
        ($script:WptSrc -match '\[string\[\]\]\$InjectFunctions') | Should Be $true
        ($script:WptSrc -match 'SessionStateFunctionEntry\(\[string\]\$fnName') | Should Be $true
    }
    It 'the ONLY TcpClient 5985/5986/445 sweep left is Test-WptHostReachable itself (inline copies removed)' {
        ([regex]::Matches($script:WptSrc, 'foreach \(\$port in 5985').Count) | Should Be 1
        # every worker block that used to carry the inline sweep now calls the injected probe
        ([regex]::Matches($script:WptSrc, '\$reach = Test-WptHostReachable \$Computer').Count -ge 24) | Should Be $true
    }
    It 'Test-WptRemoteNameMatch exists with the canonical semantics (IPv4-literal + empty probe proceed)' {
        (& $m { Test-WptRemoteNameMatch -Computer 'WS01.area.af.mil' -ActualName 'WS02' }) | Should Be $false
        (& $m { Test-WptRemoteNameMatch -Computer 'WS01.area.af.mil' -ActualName 'ws01' }) | Should Be $true
        (& $m { Test-WptRemoteNameMatch -Computer '10.1.2.3' -ActualName 'ANY-NAME' })     | Should Be $true
        (& $m { Test-WptRemoteNameMatch -Computer 'WS01' -ActualName '' })                 | Should Be $true
    }
    It 'the standalone-guard workers call the injected DNS-name-check helper; abort strings unchanged' {
        ([regex]::Matches($script:WptSrc, 'Test-WptRemoteNameMatch -Computer \$Computer -ActualName \$actualName').Count -ge 10) | Should Be $true
        ($script:WptSrc -match "ABORTED, no reboot sent")     | Should Be $true
        ($script:WptSrc -match "ABORTED, no KB installed")    | Should Be $true
        ($script:WptSrc -match "ABORTED, no registry change") | Should Be $true
        ($script:WptSrc -match "ABORTED, no action taken")    | Should Be $true
        ($script:WptSrc -match "ABORTED, no patch triggered") | Should Be $true
    }
}
