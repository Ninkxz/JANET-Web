# =============================================================================
#  RemoteAdmin.Tests.ps1 - Pester 3.4 tests for JanetWeb.remoteadmin.psm1.
#
#  NO real WinRM and NO Explorer ever launches:
#   (1) pure helpers (name validation, share path, sha256, target parse, output
#       truncation, self-guard) are unit-tested directly.
#   (2) open-cshare is driven through Invoke-JanetToolAction with
#       Start-RemoteAdminShare / Test-RemoteAdminReachable shadowed in MODULE
#       scope (the Sysadmin.Sweeps.Tests idiom), so no Explorer spawns.
#   (3) run-script's up-front guards (bad script, all-self targets) run in-process
#       (no fan-out), and the fan-out path is exercised by swapping the module
#       worker scriptblock ($script:RemoteAdminScriptBlock) for a canned fake -
#       the REAL Invoke-JanetToolAction aggregation + forensic audit run end to end.
#
#  Run:  Invoke-Pester -Path .\tests\RemoteAdmin.Tests.ps1
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
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.remoteadmin.psm1') -Force -PassThru
Add-ShimGuard $m

Describe 'Manifest' {
    $mani = & $m { Get-JanetToolManifest }
    It 'is the remoteadmin tool with both actions' {
        $mani.id | Should Be 'remoteadmin'
        $ids = @($mani.actions | ForEach-Object { $_.id })
        ($ids -contains 'open-cshare') | Should Be $true
        ($ids -contains 'run-script') | Should Be $true
    }
    It 'manifest version is 1.0.4' {
        [string]$mani.version | Should Be '1.0.4'
    }
    It 'open-cshare is non-destructive; run-script is destructive' {
        $open = @($mani.actions | Where-Object { $_.id -eq 'open-cshare' })[0]
        $run  = @($mani.actions | Where-Object { $_.id -eq 'run-script' })[0]
        [bool]$open.destructive | Should Be $false
        [bool]$run.destructive  | Should Be $true
    }
    It 'open-cshare takes a single computer text input (not a hostlist)' {
        $open = @($mani.actions | Where-Object { $_.id -eq 'open-cshare' })[0]
        $inp = @($open.inputs | Where-Object { $_.name -eq 'computer' })[0]
        $inp.type | Should Be 'text'
        [bool]$inp.required | Should Be $true
    }
    It 'run-script takes targets(hostlist) + script(textarea) required inputs' {
        $run = @($mani.actions | Where-Object { $_.id -eq 'run-script' })[0]
        $t = @($run.inputs | Where-Object { $_.name -eq 'targets' })[0]
        $s = @($run.inputs | Where-Object { $_.name -eq 'script' })[0]
        $t.type | Should Be 'hostlist'
        $s.type | Should Be 'textarea'
        [bool]$s.required | Should Be $true
    }
}

Describe 'Test-RemoteAdminComputerName' {
    It 'accepts a bare hostname and an IPv4 literal' {
        (Test-RemoteAdminComputerName -Name 'WS-0001')       | Should Be $true
        (Test-RemoteAdminComputerName -Name 'ws0001.corp.mil') | Should Be $true
        (Test-RemoteAdminComputerName -Name '10.1.2.3')      | Should Be $true
    }
    It 'rejects blank / whitespace' {
        (Test-RemoteAdminComputerName -Name '')     | Should Be $false
        (Test-RemoteAdminComputerName -Name '   ')  | Should Be $false
        (Test-RemoteAdminComputerName -Name $null)  | Should Be $false
    }
    It 'rejects spaces, quotes, backslashes, UNC, and injection punctuation' {
        (Test-RemoteAdminComputerName -Name 'WS 0001')        | Should Be $false
        (Test-RemoteAdminComputerName -Name '\\srv\c$')       | Should Be $false
        (Test-RemoteAdminComputerName -Name 'srv\c$')         | Should Be $false
        (Test-RemoteAdminComputerName -Name "ws'; rm -rf")    | Should Be $false
        (Test-RemoteAdminComputerName -Name 'ws&calc')        | Should Be $false
        (Test-RemoteAdminComputerName -Name 'ws/../etc')      | Should Be $false
        (Test-RemoteAdminComputerName -Name '"ws"')           | Should Be $false
    }
}

Describe 'Get-RemoteAdminSharePath' {
    It 'builds the C$ UNC path' {
        (Get-RemoteAdminSharePath -Computer 'WS-0001') | Should Be '\\WS-0001\C$'
        (Get-RemoteAdminSharePath -Computer '10.1.2.3') | Should Be '\\10.1.2.3\C$'
    }
}

Describe 'Get-RemoteAdminShortHash' {
    It 'is deterministic and 12 hex chars for the same input' {
        $a = Get-RemoteAdminShortHash -Text 'Get-Date'
        $b = Get-RemoteAdminShortHash -Text 'Get-Date'
        $a | Should Be $b
        ($a -match '^[0-9a-f]{12}$') | Should Be $true
    }
    It 'differs for different input' {
        (Get-RemoteAdminShortHash -Text 'Get-Date') | Should Not Be (Get-RemoteAdminShortHash -Text 'Get-Process')
    }
}

Describe 'Get-RemoteAdminTargets' {
    It 'keeps valid host/IPv4 tokens and drops UNC/junk/blank, de-dups' {
        $t = @(Get-RemoteAdminTargets -Raw "WS-1`nWS-2, WS-1`n\\srv\c$`nbad|name`n  `n10.0.0.5")
        ($t -contains 'WS-1')     | Should Be $true
        ($t -contains 'WS-2')     | Should Be $true
        ($t -contains '10.0.0.5') | Should Be $true
        ($t -contains '\\srv\c$') | Should Be $false
        ($t -contains 'bad|name') | Should Be $false
        $t.Count | Should Be 3
    }
    It 'de-dups CASE-INSENSITIVELY, order preserved, so an arbitrary block never runs twice on one host (loop23 P3)' {
        $t = @(Get-RemoteAdminTargets -Raw "host1`nHOST1`nHost1, WS-9")
        $t.Count | Should Be 2
        $t[0]    | Should Be 'host1'   # first occurrence kept; case-variants collapsed
        $t[1]    | Should Be 'WS-9'    # order preserved (not alphabetized)
    }
    # audit 2026-07-24 (P3): a '#' comment line used to tokenise into LIVE targets -
    # '# lab row' handed 'lab' and 'row' to an arbitrary remote script block.
    It 'strips a whole-line # comment instead of turning its words into targets' {
        $t = @(Get-RemoteAdminTargets -Raw "WS-0001`n# lab row`nWS-0003")
        ($t -contains 'lab') | Should Be $false
        ($t -contains 'row') | Should Be $false
        ($t -contains 'WS-0001') | Should Be $true
        ($t -contains 'WS-0003') | Should Be $true
        $t.Count | Should Be 2
    }
    It 'strips a trailing comment on a host line but keeps the host' {
        $t = @(Get-RemoteAdminTargets -Raw "WS-0001 # spare box, do not reboot")
        $t.Count | Should Be 1
        $t[0]    | Should Be 'WS-0001'
    }
}

Describe 'Get-RemoteAdminTruncatedOutput' {
    It 'returns short text unchanged' {
        (Get-RemoteAdminTruncatedOutput -Text 'hello' -Max 4000) | Should Be 'hello'
    }
    It 'caps long text and notes the truncation' {
        $long = ('x' * 5000)
        $out = Get-RemoteAdminTruncatedOutput -Text $long -Max 4000
        ($out.Length -lt 5000) | Should Be $true
        ($out -match 'output truncated at 4000 chars') | Should Be $true
    }
    It 'handles null' {
        (Get-RemoteAdminTruncatedOutput -Text $null -Max 10) | Should Be ''
    }
}

Describe 'Self-guard (Remove-RemoteAdminSelfTargets)' {
    # Seed a known dispatcher-identity set so the guard is deterministic on any box.
    & $m {
        $s = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in @('WS-SELF', 'ws-self.corp.mil', '127.0.0.1', 'localhost')) { [void]$s.Add($n) }
        $script:RemoteAdminLocalIdentity = $s
    }

    It 'flags dispatcher identity tokens (short/FQDN/loopback literal) as self' {
        (& $m { Test-RemoteAdminHostIsSelf 'WS-SELF' })         | Should Be $true
        (& $m { Test-RemoteAdminHostIsSelf 'ws-self.corp.mil' }) | Should Be $true
        (& $m { Test-RemoteAdminHostIsSelf '127.0.0.5' })       | Should Be $true
        (& $m { Test-RemoteAdminHostIsSelf 'WS-REMOTE' })       | Should Be $false
    }
    It 'drops self targets and keeps the rest' {
        $g = & $m { Remove-RemoteAdminSelfTargets -Targets @('WS-SELF', 'WS-REMOTE', '127.0.0.1') -Send $null }
        @($g.Targets) | Should Be @('WS-REMOTE')
        $g.SkippedCount | Should Be 2
    }

    # reset the cache so other describes recompute the real identity
    & $m { $script:RemoteAdminLocalIdentity = $null }
}

Describe 'Self-guard enumerates locally-bound NIC IPs, not just DNS' {
    # Force a real recompute (not the seeded set from the describe above).
    & $m { $script:RemoteAdminLocalIdentity = $null }
    $ident = & $m { Get-RemoteAdminLocalIdentity }

    # Independently enumerate THIS box's actually-bound IPv4s (the same source the
    # fix uses) so we can assert the identity set is a superset of them.
    $boundV4 = New-Object System.Collections.ArrayList
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$boundV4.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $boundV4 = @($boundV4 | Select-Object -Unique)

    It 'this box has at least one bound IPv4 (sanity for the assertion below)' {
        $boundV4.Count | Should BeGreaterThan 0
    }
    It 'the identity set contains every actually-bound local IPv4' {
        foreach ($ip in $boundV4) { $ident.Contains($ip) | Should Be $true }
    }
    It 'Test-RemoteAdminHostIsSelf flags a real bound local IPv4 as self' {
        foreach ($ip in $boundV4) { (& $m { param($x) Test-RemoteAdminHostIsSelf $x } $ip) | Should Be $true }
    }
    It 'flags a bound IP that DNS would NOT know (the multi-homed slip the fix closes)' {
        # Inject a synthetic bound address the box's hostname is never DNS-registered
        # for (TEST-NET-3, RFC 5737). With the DNS-only set it would slip the guard;
        # once the enumeration puts a bound IP in the set, the guard catches it.
        & $m {
            $s = Get-RemoteAdminLocalIdentity
            [void]$s.Add('203.0.113.199')
            $script:RemoteAdminLocalIdentity = $s
        }
        (& $m { Test-RemoteAdminHostIsSelf '203.0.113.199' }) | Should Be $true
    }

    & $m { $script:RemoteAdminLocalIdentity = $null }
}

Describe 'open-cshare via Invoke-JanetToolAction (Explorer + reachability shimmed)' {
    function Invoke-ShimmedOpen {
        param([string]$Computer, [bool]$Reachable = $true)
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        & $m {
            param($Reachable)
            Set-Variable -Name __reach -Scope script -Value $Reachable
            $script:TestLaunched = '__none__'
            # The shims and their teardown are in SEPARATE module blocks here, so the snapshot is
            # parked in module script scope rather than a block local.
            $script:__shims = Save-ShimState @('Test-RemoteAdminReachable','Start-RemoteAdminShare')
            function script:Test-RemoteAdminReachable { param($ComputerName, $Ports, $TimeoutMs) return [bool]$script:__reach }
            function script:Start-RemoteAdminShare { param($Computer) $script:TestLaunched = $Computer }
        } $Reachable
        $res = Invoke-JanetToolAction -ActionId 'open-cshare' -Params @{ computer = $Computer } -Credential $null -Emit $emit
        $launched = & $m { $script:TestLaunched }
        & $m {
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. Worse here than
            # elsewhere: BOTH names are REAL module functions, so the naive 'Remove-Item function:X'
            # would have deleted them outright. See Add-ShimGuard above.
            Restore-ShimState $script:__shims
            Remove-Variable -Name __shims, __reach -Scope script -ErrorAction SilentlyContinue
        }
        return @{ Result = $res; Events = @($events); Launched = $launched }
    }

    It 'launches Explorer for a valid, reachable host and audits the access' {
        $o = Invoke-ShimmedOpen -Computer 'WS-0001' -Reachable $true
        $o.Launched | Should Be 'WS-0001'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        $row.Status | Should Be 'Opened'
        $row.Path | Should Be '\\WS-0001\C$'
        $audit = @($o.Events | Where-Object { $_.type -eq 'audit' })[0]
        $audit.result | Should Be 'Success'
        ($audit.detail -match 'Opened admin share') | Should Be $true
    }
    It 'still launches when unreachable but notes the 445 miss' {
        $o = Invoke-ShimmedOpen -Computer 'WS-0002' -Reachable $false
        $o.Launched | Should Be 'WS-0002'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        ($row.Status -match 'unreachable on 445') | Should Be $true
    }
    It 'REJECTS an invalid name and never launches Explorer' {
        $o = Invoke-ShimmedOpen -Computer '\\srv\c$' -Reachable $true
        $o.Launched | Should Be '__none__'
        $row = @($o.Events | Where-Object { $_.type -eq 'row' })[0]
        $row.Status | Should Be 'Rejected'
        @($o.Events | Where-Object { $_.type -eq 'audit' }).Count | Should Be 0
    }
}

Describe 'run-script guards (in-process, no fan-out)' {
    function Invoke-Run {
        param([hashtable]$Params)
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        # Every run-script call must carry the typed barrier (audit 2026-07-24 S2); the
        # gate itself is asserted separately below.
        if (-not $Params.ContainsKey('confirm')) { $Params['confirm'] = 'RUN' }
        $res = Invoke-JanetToolAction -ActionId 'run-script' -Params $Params -Credential $null -Emit $emit
        return @{ Result = $res; Events = @($events) }
    }

    It 'REFUSES to run without the typed RUN confirm (server-side barrier)' {
        # Any word but the barrier word refuses BEFORE parse / target resolution / fan-out.
        # (Comparison is case-insensitive, the suite-wide confirm-gate idiom.)
        $r = Invoke-Run -Params @{ targets = 'WS-REMOTE'; script = 'Get-Date'; confirm = '' }
        @($r.Result.rows).Count | Should Be 0
        [bool]$r.Result.summary.rejected | Should Be $true
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'type RUN' }).Count | Should BeGreaterThan 0
    }
    It 'rejects an unparseable script and returns no rows' {
        $r = Invoke-Run -Params @{ targets = 'WS-REMOTE'; script = 'if (' }
        @($r.Result.rows).Count | Should Be 0
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and ($_.text -match 'failed to parse') }).Count | Should BeGreaterThan 0
    }
    It 'warns and returns no rows for a blank script' {
        $r = Invoke-Run -Params @{ targets = 'WS-REMOTE'; script = '   ' }
        @($r.Result.rows).Count | Should Be 0
    }
    It 'drops invalid target tokens (only valid names survive the strict parse)' {
        # all-invalid target set -> no targets -> empty (a fan-out would need WinRM)
        $r = Invoke-Run -Params @{ targets = '\\srv\c$'; script = 'Get-Date' }
        @($r.Result.rows).Count | Should Be 0
        ($r.Result.summary.total) | Should Be 0
    }
    It 'self-guards every target that is the dispatcher host' {
        & $m {
            $s = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$s.Add('WS-SELF')
            $script:RemoteAdminLocalIdentity = $s
        }
        $r = Invoke-Run -Params @{ targets = 'WS-SELF'; script = 'Get-Date' }
        & $m { $script:RemoteAdminLocalIdentity = $null }
        @($r.Result.rows).Count | Should Be 0
        $r.Result.summary.selfSkipped | Should Be 1
    }
}

Describe 'run-script fan-out + forensic audit (worker block faked)' {
    It 'streams a Success row and stamps the sha256 tag into the per-host audit' {
        $fake = {
            param($Computer, $Cred, $Auth, $ScriptText, $TimeoutSeconds, $MaxOutput, $ModulePath)
            return @{ Host = $Computer; Online = $true; Status = 'Success'; Output = "ran on $Computer"; Error = '' }
        }
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        $res = & $m {
            param($fake, $emit)
            $orig = $script:RemoteAdminScriptBlock
            $script:RemoteAdminScriptBlock = $fake
            try {
                Invoke-JanetToolAction -ActionId 'run-script' -Params @{ targets = 'WS-REMOTE'; script = 'Get-Date'; threads = 2; timeoutSeconds = 30; confirm = 'RUN' } -Credential $null -Emit $emit
            } finally { $script:RemoteAdminScriptBlock = $orig }
        } $fake $emit

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        $row.Host | Should Be 'WS-REMOTE'
        $row.Status | Should Be 'Success'

        # pre-run forensic audit record + per-host audit both carry the sha256
        # audit 2026-07-24 (P3): the pre-run record's target must be a sentinel BOTH audit
        # filter sites recognise ('N/A' / '(custom command)'). The old '(run-script)' was
        # unknown to them, so it wrote a phantom TouchedHosts row and inflated HostsTouched.
        $preAudit = @($events | Where-Object { $_.type -eq 'audit' -and $_.result -eq 'Skipped' -and $_.detail -match 'pre-run forensic record' })[0]
        [string]$preAudit.target | Should Not Be '(run-script)'
        (@('N/A', '(custom command)') -contains [string]$preAudit.target) | Should Be $true
        $preAudit.result | Should Be 'Skipped'
        ($preAudit.detail -match 'sha256:[0-9a-f]{12}') | Should Be $true
        $hostAudit = @($events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'WS-REMOTE' })[0]
        $hostAudit.result | Should Be 'Success'
        ($hostAudit.detail -match 'script sha256:[0-9a-f]{12}') | Should Be $true

        $res.summary.succeeded | Should Be 1
        $res.summary.scriptSha256 | Should Match '^[0-9a-f]{12}$'
    }

    # loop56 (C1): the worker returns its result as the LAST stream object. If the operator's script
    # leaks a stray object to the output stream before the return, the row must still be built from the
    # RETURN (-Last 1), not the stray (-First 1) - else Host/Status come from garbage.
    It 'builds the row from the returned result, not a stray leaked object (-Last 1)' {
        $fake = {
            param($Computer, $Cred, $Auth, $ScriptText, $TimeoutSeconds, $MaxOutput, $ModulePath)
            'STRAY-LEAK-OBJECT'   # a stray object emitted to the output stream BEFORE the return
            return @{ Host = $Computer; Online = $true; Status = 'Success'; Output = "ran on $Computer"; Error = '' }
        }
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        $res = & $m {
            param($fake, $emit)
            $orig = $script:RemoteAdminScriptBlock
            $script:RemoteAdminScriptBlock = $fake
            try {
                Invoke-JanetToolAction -ActionId 'run-script' -Params @{ targets = 'WS-REMOTE'; script = 'Get-Date'; threads = 2; timeoutSeconds = 30; confirm = 'RUN' } -Credential $null -Emit $emit
            } finally { $script:RemoteAdminScriptBlock = $orig }
        } $fake $emit

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        $row.Host   | Should Be 'WS-REMOTE'          # from the returned result, not the stray string
        $row.Status | Should Be 'Success'
        $row.Output | Should Be 'ran on WS-REMOTE'
        $res.summary.succeeded | Should Be 1
    }

    # loop70: a failed host carries an actionable troubleshooting hint (Get-JanetTroubleshootHint) in the
    # row Hint field, the persisted audit detail, and the err log - alongside (never replacing) the raw error.
    It 'a failed host gets a troubleshooting hint in the row, audit, and err log (raw error preserved)' {
        $fake = {
            param($Computer, $Cred, $Auth, $ScriptText, $TimeoutSeconds, $MaxOutput, $ModulePath)
            return @{ Host = $Computer; Online = $false; Status = 'Session error'; Output = ''; Error = 'Connecting to remote server WS-REMOTE failed: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY' }
        }
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        $null = & $m {
            param($fake, $emit)
            $orig = $script:RemoteAdminScriptBlock
            $script:RemoteAdminScriptBlock = $fake
            try {
                Invoke-JanetToolAction -ActionId 'run-script' -Params @{ targets = 'WS-REMOTE'; script = 'Get-Date'; threads = 2; timeoutSeconds = 30; confirm = 'RUN' } -Credential $null -Emit $emit
            } finally { $script:RemoteAdminScriptBlock = $orig }
        } $fake $emit

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Error | Should Match '0x80090351'          # raw error preserved
        [string]$row.Hint  | Should Match 'TrustedHosts|realm|CAC'  # actionable hint added
        $hostAudit = @($events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'WS-REMOTE' })[0]
        $hostAudit.result | Should Be 'Failure'
        ([string]$hostAudit.detail -match 'TROUBLESHOOT:') | Should Be $true
        $errLog = @($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'FIX:' })
        $errLog.Count | Should BeGreaterThan 0
    }
}

# audit 2026-07-24 (P2/P3): drive the REAL per-host worker ($script:RemoteAdminScriptBlock)
# with reachability, the session cmdlets and Invoke-Command shadowed in MODULE scope, so no
# WinRM is touched. The shimmed Invoke-Command answers the wrong-box probe first (matching
# the dialed name), then plays the caller's canned "remote" behaviour for the operator block.
Describe 'run-script worker: output honesty + receive cap (no WinRM)' {
    function Invoke-FakeWorker {
        param([scriptblock]$RemoteBehavior)
        return & $m {
            param($behavior)
            $script:TestRemoteBehavior = $behavior
            $script:TestSessOpt = $null
            $__shims = Save-ShimState @('Test-RemoteAdminReachable','New-PSSessionOption','New-PSSession','Remove-PSSession',
                'Invoke-Command')
            function script:Test-RemoteAdminReachable { param($ComputerName, $Ports, $TimeoutMs, $UseSsl) if ($UseSsl) { $UseSsl.Value = $false }; return $true }
            function script:New-PSSessionOption {
                param($OperationTimeout, $OpenTimeout, $CancelTimeout, $IdleTimeout, $MaximumReceivedDataSizePerCommand, $SkipCACheck, $SkipCNCheck)
                $script:TestSessOpt = @{ MaxPerCommand = $MaximumReceivedDataSizePerCommand; OperationTimeout = $OperationTimeout }
                return 'FAKE-OPT'
            }
            function script:New-PSSession { return 'FAKE-SESSION' }
            function script:Remove-PSSession { }
            function script:Invoke-Command {
                param($Session, $ScriptBlock)
                # the wrong-box guard probe asks for $env:COMPUTERNAME - answer with the dialed name
                if ("$ScriptBlock" -match 'COMPUTERNAME') { return 'WS-REMOTE' }
                & $script:TestRemoteBehavior
            }
            try {
                $res = & $script:RemoteAdminScriptBlock 'WS-REMOTE' $null 'Default' 'Get-Date' 30 4000 $null | Select-Object -Last 1
                return @{ Result = $res; SessOpt = $script:TestSessOpt }
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
                Remove-Variable -Name TestRemoteBehavior -Scope script -ErrorAction SilentlyContinue
            }
        } $RemoteBehavior
    }

    It 'PRESERVES the output a block printed before it threw (not just the error)' {
        $w = Invoke-FakeWorker -RemoteBehavior { 'line 1'; 'line 2'; throw 'boom from remote' }
        $w.Result.Status          | Should Be 'Failed'
        [string]$w.Result.Error   | Should Match 'boom from remote'
        [string]$w.Result.Output  | Should Match 'line 1'     # discarded entirely before the fix
        [string]$w.Result.Output  | Should Match 'line 2'
    }
    It 'fails the host on a remote error record but still keeps the captured output' {
        $w = Invoke-FakeWorker -RemoteBehavior { 'good line'; Write-Error 'partial fail' }
        $w.Result.Status          | Should Be 'Failed'
        [string]$w.Result.Error   | Should Match 'partial fail'
        [string]$w.Result.Output  | Should Match 'good line'
    }
    It 'still reports a clean run as Success with its output' {
        $w = Invoke-FakeWorker -RemoteBehavior { 'all good' }
        $w.Result.Status          | Should Be 'Success'
        [string]$w.Result.Output  | Should Match 'all good'
        [string]$w.Result.Error   | Should Be ''
    }
    It 'caps MaximumReceivedDataSizePerCommand on the session (no unbounded in-process buffering)' {
        $w = Invoke-FakeWorker -RemoteBehavior { 'x' }
        [int]$w.SessOpt.MaxPerCommand | Should BeGreaterThan 0
    }
}
