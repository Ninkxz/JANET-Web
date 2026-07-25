# =============================================================================
#  Wpt.FanOutInjection.Tests.ps1 - Pester 3.4 for the audit 2026-07-24 P1 class:
#  a fan-out whose worker scriptblock calls a module helper the call site never
#  injected into the pool's InitialSessionState.
#
#  Why this file exists: bulk-scan passed -InjectFunctions 'Test-WptHostReachable'
#  while WptScanBlock also calls Test-WptRemoteNameMatch. A pool worker runs in a
#  BARE runspace with no module scope, so every online host threw CommandNotFound
#  at the wrong-box check - the guard was inert AND the host's real readings were
#  replaced by a 'worker error' row. 1640 text-assertion tests missed it because
#  the guard source was present and correct; only the WIRING was wrong. So the
#  tests here are behavioural: the invariant is derived from the real call graph
#  (AST), and the scan block is actually EXECUTED in a bare runspace carrying
#  nothing but the functions its call site injects.
#
#  No host contact: the session cmdlets are stubbed inside the worker runspace.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.FanOutInjection.Tests.ps1
# =============================================================================
$script:Root    = Split-Path $PSScriptRoot -Parent
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
$script:ModPath = Join-Path $script:Root 'modules\JanetWeb.wpt.psm1'
$script:Mod     = Import-Module $script:ModPath -Force -PassThru
Add-ShimGuard $script:Mod

# ---- AST: map every Invoke-WptFanOut call site -> (work block name, injected fns) ----
function Get-WptFanOutCallSites {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ModPath, [ref]$null, [ref]$null)
    $calls = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-WptFanOut' }, $true)
    $out = New-Object System.Collections.ArrayList
    foreach ($c in $calls) {
        $els = $c.CommandElements
        $work = ''; $inject = @()
        for ($i = 0; $i -lt $els.Count; $i++) {
            $p = $els[$i]
            if (-not ($p -is [System.Management.Automation.Language.CommandParameterAst])) { continue }
            # a parameter's value is either glued to it (-P:v) or the next element
            $val = if ($p.Argument) { $p.Argument } elseif ($i + 1 -lt $els.Count) { $els[$i + 1] } else { $null }
            if ($null -eq $val) { continue }
            if ($p.ParameterName -eq 'Work') { $work = $val.Extent.Text }
            if ($p.ParameterName -eq 'InjectFunctions') {
                $inject = @($val.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                            ForEach-Object { [string]$_.Value })
            }
        }
        [void]$out.Add(@{ Work = $work; Inject = @($inject); Line = $c.Extent.StartLineNumber })
    }
    return @($out)
}

# The module-helper commands a work scriptblock actually invokes (recursively, so a
# helper called from inside a nested scriptblock counts too).
function Get-WptHelperCallsIn {
    param([scriptblock]$Block)
    @($Block.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object { [string]$_.GetCommandName() } |
        Where-Object { $_ -like 'Test-Wpt*' } | Select-Object -Unique)
}

function Get-WptBlockByName {
    param([string]$Name)
    & $script:Mod { param($n) Get-Variable -Name $n -Scope Script -ValueOnly } $Name
}

# Run a worker scriptblock in a BARE runspace carrying ONLY the named functions -
# exactly what Invoke-WptFanOut builds for its pool. $Stubs replaces (or adds) a
# function body so no real session/TCP work happens.
function Invoke-WptWorkerInBareRunspace {
    param([scriptblock]$Block, [string[]]$Inject, [hashtable]$Stubs, [object[]]$WorkArgs)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $added = @()
    foreach ($fn in @($Inject)) {
        $body = if ($Stubs.ContainsKey($fn)) { $Stubs[$fn] } else { (& $script:Mod { param($n) (Get-Item "function:$n").ScriptBlock.ToString() } $fn) }
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $body)))
        $added += $fn
    }
    foreach ($k in @($Stubs.Keys)) {
        if ($added -notcontains $k) { $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($k, $Stubs[$k]))) }
    }
    $rs = [runspacefactory]::CreateRunspace($iss); $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript($Block.ToString())
    foreach ($a in @($WorkArgs)) { [void]$ps.AddArgument($a) }
    $res = $null; $err = ''
    try { $res = $ps.Invoke() } catch { $err = $_.Exception.Message }
    if (-not $err -and $ps.Streams.Error.Count -gt 0) { $err = [string]$ps.Streams.Error[0] }
    try { $ps.Dispose() } catch {}
    try { $rs.Close(); $rs.Dispose() } catch {}
    return @{ Result = @($res)[0]; Error = $err }
}

Describe 'wpt fan-out - every helper a worker calls is injected into the pool ISS (audit 2026-07-24)' {

    $sites = Get-WptFanOutCallSites

    It 'the module has fan-out call sites to check' {
        ($sites.Count -gt 0) | Should Be $true
    }

    It 'no call site passes a work block that calls an un-injected Test-Wpt* helper' {
        $bad = @()
        foreach ($s in $sites) {
            if ($s.Work -notmatch '^\$script:(\w+)$') { continue }   # only module-level $script: blocks are resolvable here
            $name = $Matches[1]
            $blk = Get-WptBlockByName $name
            if (-not $blk) { continue }
            foreach ($fn in (Get-WptHelperCallsIn $blk)) {
                if (@($s.Inject) -notcontains $fn) { $bad += "line $($s.Line): $name calls $fn but it is not in -InjectFunctions" }
            }
        }
        ($bad -join ' | ') | Should Be ''
    }
}

Describe 'wpt bulk-scan - the wrong-box guard actually RUNS inside a bare worker runspace' {

    # Reproduce the pool worker exactly: the scan block, plus ONLY the functions the
    # bulk-scan call site injects (Test-WptHostReachable swapped for a stub so no TCP
    # probe leaves the box), plus inert session cmdlets. The remote probe answers with
    # a DIFFERENT computer name -> the guard must fire and discard the readings.
    $site = @(Get-WptFanOutCallSites | Where-Object { $_.Work -eq '$script:WptScanBlock' })[0]
    $stubs = @{
        'Test-WptHostReachable' = 'param($Computer) @{ Reachable = $true; UseSsl = $false }'
        'New-PSSessionOption'   = 'param($OperationTimeout,$OpenTimeout,$CancelTimeout,$IdleTimeout,$SkipCACheck,$SkipCNCheck) "stub-option"'
        'New-PSSession'         = 'param($ComputerName,$SessionOption,$ErrorAction,$UseSSL,$Credential,$Authentication) "stub-session"'
        'Invoke-Command'        = '[CmdletBinding()] param($Session,$ScriptBlock,$ArgumentList,$ComputerName,$Credential,$Authentication,$SessionOption,[switch]$UseSSL) @{ RemoteName = "SOMEOTHERBOX" }'
        'Remove-PSSession'      = '[CmdletBinding()] param($Session)'
    }
    $out = Invoke-WptWorkerInBareRunspace -Block (Get-WptBlockByName 'WptScanBlock') -Inject $site.Inject -Stubs $stubs -WorkArgs @('WKS-DIALED', $null, 'Default')

    It 'the call site injects the name-match helper (else the worker cannot run the guard)' {
        (@($site.Inject) -contains 'Test-WptRemoteNameMatch') | Should Be $true
    }
    It 'the worker completes without a CommandNotFound (the guard is reachable in the runspace)' {
        [string]$out.Error | Should Be ''
    }
    It 'a mismatching remote name is flagged DnsMismatch and the readings are discarded' {
        [bool]$out.Result.DnsMismatch | Should Be $true
        [string]$out.Result.Error | Should Match 'DNS mismatch'
        [int]$out.Result.UpdateCount | Should Be 0
    }
}

Describe 'wpt fan-out - a run where every host failed cannot read as a completed run' {

    function Invoke-UnitFanOut {
        param([scriptblock]$Ok)
        & $script:Mod {
            param($okOf)
            $ev = New-Object System.Collections.ArrayList
            $send = { param($e) [void]$ev.Add($e) }
            $res = Invoke-WptFanOut -Targets @('UNIT-H1','UNIT-H2') -Threads 2 -ActionId 'unit-fanout' -Send $send `
                -Work { param($h) @{ Host=$h; Error='unit: forced failure' } } -AuditAction 'TouchHost' `
                -ArgFactory { param($h) ,@($h) } `
                -OkOf $okOf `
                -AuditDetail { param($r) 'unit' } `
                -RowOf { param($r) @{ Host=$r.Host; Error=[string]$r.Error } }
            return @{ Summary = $res.summary; Events = @($ev) }
        } $Ok
    }

    $allBad = Invoke-UnitFanOut { param($r) $false }
    $someOk = Invoke-UnitFanOut { param($r) ([string]$r.Host -eq 'UNIT-H1') }

    It 'flags allFailed when not one host succeeded' {
        [bool]$allBad.Summary.allFailed | Should Be $true
        [int]$allBad.Summary.ok         | Should Be 0
    }
    It 'warns the operator instead of leaving a quiet "0 ok" line' {
        $w = @($allBad.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and "$($_.text)" -match 'EVERY host failed' })
        $w.Count | Should Be 1
    }
    It 'does NOT flag allFailed when at least one host succeeded' {
        [bool]$someOk.Summary.allFailed | Should Be $false
        [int]$someOk.Summary.ok         | Should Be 1
    }
}

Describe 'wpt bulk-scan - an all-failed scan is never persisted into the compliance trend' {

    # Shadow the worker (every host errors) AND the snapshot writer (so nothing touches
    # JanetLocal\snapshots), then drive the REAL dispatcher with saveSnapshot on.
    $out = & $script:Mod {
        $script:__unitSaved = $false
        $orig = $script:WptScanBlock
        $script:WptScanBlock = { param($Computer, $Cred, $Auth) @{ Host=$Computer; Online=$false; DnsMismatch=$false; UpdateNames=@(); WuNames=@(); AppNames=@(); Error='unit: forced failure' } }
        $__shims = Save-ShimState @('Save-WptBulkSnapshot')
        function script:Save-WptBulkSnapshot { param($Rows, $Send) $script:__unitSaved = $true }
        try {
            $ev = New-Object System.Collections.ArrayList
            $emit = { param($e) [void]$ev.Add($e) }
            $res = Invoke-JanetToolAction -ActionId 'bulk-scan' -Params @{ targets='UNIT-HOST-A'; threads=1; saveSnapshot=$true } -Credential $null -Emit $emit
            return @{ Summary = $res.summary; Events = @($ev); Saved = [bool]$script:__unitSaved }
        } finally {
            $script:WptScanBlock = $orig
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
        }
    }

    It 'reports the run as all-failed' {
        [bool]$out.Summary.allFailed | Should Be $true
    }
    It 'refuses to save the snapshot' {
        $out.Saved | Should Be $false
    }
    It 'says why in the activity log' {
        $w = @($out.Events | Where-Object { $_.type -eq 'log' -and "$($_.text)" -match 'Snapshot NOT saved' })
        ($w.Count -ge 1) | Should Be $true
    }
}

Describe 'wpt - every manifest action is reachable from the view (audit 2026-07-24)' {

    # fix-java / spec-exec-scan / spec-exec-enable were declared, guarded, confirm-gated
    # and tested server-side, but NO operator could reach them: the view referenced none
    # of the three. They are now wired into the Vuln Fixes tab.
    It 'no action id is declared in the manifest yet absent from wpt.view.js' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        $viewSrc = Get-Content (Join-Path $script:Root 'web\js\views\wpt.view.js') -Raw
        $missing = @()
        foreach ($a in $mani.actions) { if (-not $viewSrc.Contains("'" + [string]$a.id + "'")) { $missing += [string]$a.id } }
        ($missing -join ', ') | Should Be ''
    }
}

Describe 'wpt - manifest version (newest bump holds the EXACT pin; older tests keep floors)' {
    It 'wpt manifest is exactly 6.10.2 (audit 2026-07-25 fable re-audit follow-up)' {
        [string](& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '6.10.2'
    }
}
