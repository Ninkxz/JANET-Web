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
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.remoteadmin.psm1') -Force -PassThru

Describe 'Manifest' {
    $mani = & $m { Get-JanetToolManifest }
    It 'is the remoteadmin tool with both actions' {
        $mani.id | Should Be 'remoteadmin'
        $ids = @($mani.actions | ForEach-Object { $_.id })
        ($ids -contains 'open-cshare') | Should Be $true
        ($ids -contains 'run-script') | Should Be $true
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

Describe 'open-cshare via Invoke-JanetToolAction (Explorer + reachability shimmed)' {
    function Invoke-ShimmedOpen {
        param([string]$Computer, [bool]$Reachable = $true)
        $events = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$events.Add($e) }
        & $m {
            param($Reachable)
            Set-Variable -Name __reach -Scope script -Value $Reachable
            $script:TestLaunched = '__none__'
            function script:Test-RemoteAdminReachable { param($ComputerName, $Ports, $TimeoutMs) return [bool]$script:__reach }
            function script:Start-RemoteAdminShare { param($Computer) $script:TestLaunched = $Computer }
        } $Reachable
        $res = Invoke-JanetToolAction -ActionId 'open-cshare' -Params @{ computer = $Computer } -Credential $null -Emit $emit
        $launched = & $m { $script:TestLaunched }
        & $m {
            Remove-Item function:script:Test-RemoteAdminReachable, function:script:Start-RemoteAdminShare -ErrorAction SilentlyContinue
            Remove-Variable -Name __reach -Scope script -ErrorAction SilentlyContinue
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
        $res = Invoke-JanetToolAction -ActionId 'run-script' -Params $Params -Credential $null -Emit $emit
        return @{ Result = $res; Events = @($events) }
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
                Invoke-JanetToolAction -ActionId 'run-script' -Params @{ targets = 'WS-REMOTE'; script = 'Get-Date'; threads = 2; timeoutSeconds = 30 } -Credential $null -Emit $emit
            } finally { $script:RemoteAdminScriptBlock = $orig }
        } $fake $emit

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        $row.Host | Should Be 'WS-REMOTE'
        $row.Status | Should Be 'Success'

        # pre-run forensic audit record + per-host audit both carry the sha256
        $preAudit = @($events | Where-Object { $_.type -eq 'audit' -and $_.target -eq '(run-script)' })[0]
        $preAudit.result | Should Be 'Skipped'
        ($preAudit.detail -match 'sha256:[0-9a-f]{12}') | Should Be $true
        $hostAudit = @($events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'WS-REMOTE' })[0]
        $hostAudit.result | Should Be 'Success'
        ($hostAudit.detail -match 'script sha256:[0-9a-f]{12}') | Should Be $true

        $res.summary.succeeded | Should Be 1
        $res.summary.scriptSha256 | Should Match '^[0-9a-f]{12}$'
    }
}
