# =============================================================================
#  History.Tests.ps1 - Pester 3.4 tests for JanetWeb.history.psm1 (audit 2026-07-24)
#
#  The module is the READ side of JANET's audit trail. Its whole value is that an
#  empty answer means "nothing happened"; the audit found that every read failure
#  was swallowed (catch { $rows = @() } + bare catch {} on the directory walks), so
#  a denied ACL / dropped share / locked CSV produced the SAME empty answer. On the
#  staleness board that became a false "NEVER TOUCHED" - the loudest, most actionable
#  verdict on the board. Resolve-HistRoot's .Exists flag existed but no caller read it.
#
#  These tests pin the fixed behaviour:
#    P1  a failed read is COUNTED and surfaced, never silently rendered as zero rows,
#        and the staleness verdict refuses NEVER TOUCHED when the read failed.
#    P2  .Exists is wired into Invoke-JanetToolAction and surfaced to the operator.
#    P4  Read-HistUsageRows is capped like every other read in the module.
#
#  Everything runs against a throwaway temp tree; the REAL log share is never
#  touched (Resolve-HistRoot is overridden in module scope, then restored).
#
#  Run:  Invoke-Pester -Path .\tests\History.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.history.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ('histtest_' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

$script:Month = (Get-Date).ToString('yyyy-MM')

# Build Logs\<Tool>\<userFolder>\<yyyy-MM>_detail.csv with the real detail schema.
function New-HistTestTree {
    param([string]$Name, [string[]]$TargetHosts = @())
    $root = Join-Path $script:Tmp $Name
    $dir  = Join-Path $root 'WPT\test.operator'
    [void][System.IO.Directory]::CreateDirectory($dir)
    $csv = Join-Path $dir ($script:Month + '_detail.csv')
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail')
    foreach ($h in $TargetHosts) {
        [void]$lines.Add(('{0},s1,Test Operator,ASI,WPT,1.0.0,Patch,{1},Success,1,ok' -f ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $h)))
    }
    Set-Content -LiteralPath $csv -Value $lines -Encoding ASCII
    return @{ Root = $root; Csv = $csv }
}

# Hold a monthly CSV open with FileShare::None so Import-Csv genuinely fails - the
# closest faithful stand-in for the denied-ACL / share-dropped case the audit cites.
function Lock-HistFile {
    param([string]$Path)
    return [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
}

# -----------------------------------------------------------------------------
Describe 'Read-HistoryRows surfaces read failures instead of swallowing them (audit 2026-07-24 P1)' {

    It 'flags a root that does not exist as a read failure, not an empty audit trail' {
        $res = & $script:Mod { param($p) Read-HistoryRows -Root $p -Months @('2026-07') } (Join-Path $script:Tmp '__no_such_root__')
        $res.RootMissing | Should Be $true
        ([int]$res.Errors -ge 1) | Should Be $true
        @($res.Rows).Count | Should Be 0
    }

    It 'flags a blank root as a read failure' {
        $res = & $script:Mod { Read-HistoryRows -Root '' -Months @('2026-07') }
        $res.RootMissing | Should Be $true
        ([int]$res.Errors -ge 1) | Should Be $true
    }

    It 'reports ZERO errors and the real rows for a healthy readable tree' {
        $t = New-HistTestTree -Name 'healthy' -TargetHosts @('WS-0001')
        $res = & $script:Mod { param($p, $m) Read-HistoryRows -Root $p -Months @($m) } $t.Root $script:Month
        [int]$res.Errors | Should Be 0
        $res.RootMissing | Should Be $false
        @($res.Rows).Count | Should Be 1
        ([string]@($res.Rows)[0].Target) | Should Be 'WS-0001'
    }

    It 'counts an unreadable monthly CSV as a read error (the swallowed catch is gone)' {
        $t = New-HistTestTree -Name 'locked' -TargetHosts @('WS-0002')
        $fs = Lock-HistFile -Path $t.Csv
        try {
            $res = & $script:Mod { param($p, $m) Read-HistoryRows -Root $p -Months @($m) } $t.Root $script:Month
            @($res.Rows).Count | Should Be 0              # same empty row set as before...
            ([int]$res.Errors -ge 1) | Should Be $true    # ...but no longer indistinguishable from clean
            @($res.ErrorMessages).Count | Should Be 1
        } finally { $fs.Close(); $fs.Dispose() }
    }

    It 'names the failing path in ErrorMessages so the operator can fix the source' {
        $t = New-HistTestTree -Name 'locked2' -TargetHosts @('WS-0003')
        $fs = Lock-HistFile -Path $t.Csv
        try {
            $res = & $script:Mod { param($p, $m) Read-HistoryRows -Root $p -Months @($m) } $t.Root $script:Month
            ((@($res.ErrorMessages) -join ' ') -like ('*' + $script:Month + '_detail.csv*')) | Should Be $true
        } finally { $fs.Close(); $fs.Dispose() }
    }
}

# -----------------------------------------------------------------------------
Describe 'Read-HistUsageRows reports failures and is bounded (audit 2026-07-24 P1/P4)' {

    It 'flags a missing root as a read failure rather than returning an empty-but-successful list' {
        $res = & $script:Mod { param($p) Read-HistUsageRows -Root $p -Months @('2026-07') } (Join-Path $script:Tmp '__no_usage_root__')
        $res.RootMissing | Should Be $true
        ([int]$res.Errors -ge 1) | Should Be $true
        @($res.Rows).Count | Should Be 0
    }

    It 'reads usage rows with zero errors from a healthy root' {
        $ur = Join-Path $script:Tmp 'usage'
        [void][System.IO.Directory]::CreateDirectory($ur)
        $lines = @('Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes')
        1..5 | ForEach-Object { $lines += ('2026-07-01 00:00:0{0},s{0},Op,ASI,WPT,1.0.0,SessionEnd,3,0,0,5,' -f $_) }
        Set-Content -LiteralPath (Join-Path $ur ('2026-07_usage.csv')) -Value $lines -Encoding ASCII
        $res = & $script:Mod { param($p) Read-HistUsageRows -Root $p -Months @('2026-07') } $ur
        [int]$res.Errors | Should Be 0
        @($res.Rows).Count | Should Be 5
        $res.Capped | Should Be $false
    }

    It 'honours the read cap - the last unbounded read in the module is now bounded' {
        $ur = Join-Path $script:Tmp 'usage'
        $res = & $script:Mod { param($p) Read-HistUsageRows -Root $p -Months @('2026-07') -Cap 2 } $ur
        @($res.Rows).Count | Should Be 2
        $res.Capped | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'Resolve-HistRoot .Exists is wired into the callers (audit 2026-07-24 P2)' {

    # Resolve-HistRoot picks the REAL production share, so every action test below
    # overrides it in module scope (restored in the last It) - no live share touched.
    & $script:Mod { $script:__origResolveHistRoot = ${function:Resolve-HistRoot} }

    function Set-HistRootOverride {
        param([string]$Path, [bool]$Exists)
        & $script:Mod {
            param($p, $e)
            ${function:script:Resolve-HistRoot} = { @{ Root = $p; OnShare = $false; Reason = "test root ($p)"; Exists = $e } }.GetNewClosure()
        } $Path $Exists
    }

    function Invoke-StaleRun {
        param([string]$TargetHost = 'WS-9999')
        $evts = New-Object System.Collections.ArrayList
        $r = Invoke-JanetToolAction -ActionId 'stale-hosts' `
                -Params @{ targets = $TargetHost; thresholdDays = 30; lookbackMonths = 1 } `
                -Emit { param($e) [void]$evts.Add($e) }
        return @{ Result = $r; Events = @($evts) }
    }

    It 'computes Exists=$false for a spool root that is not there' {
        $x = & $script:Mod {
            ${function:script:Get-HistSpoolRoot} = { 'X:\__definitely_not_here__\JanetLocal' }
            $script:HistShareRoot = 'X:\__definitely_not_a_share__'
            (Resolve-HistRoot).Exists
        }
        $x | Should Be $false
        # put the module back the way we found it before the action tests run
        & $script:Mod { ${function:script:Resolve-HistRoot} = $script:__origResolveHistRoot }
    }

    It 'stale-hosts REFUSES "NEVER TOUCHED" when the source is unreadable (Exists=$false)' {
        Set-HistRootOverride -Path (Join-Path $script:Tmp '__unreadable__') -Exists $false
        $run = Invoke-StaleRun
        ([string]$run.Result.rows[0].Verdict) | Should Be 'UNKNOWN (read error)'
        [int]$run.Result.summary.never | Should Be 0
        [int]$run.Result.summary.unknown | Should Be 1
        $run.Result.summary.readFailed | Should Be $true
        $run.Result.summary.sourceReadable | Should Be $false
    }

    It 'emits an explicit error event when the source is unreadable (the flag is surfaced, not just computed)' {
        Set-HistRootOverride -Path (Join-Path $script:Tmp '__unreadable__') -Exists $false
        $run = Invoke-StaleRun
        (@($run.Events | Where-Object { $_.type -eq 'error' }).Count -ge 1) | Should Be $true
        ((@($run.Events | Where-Object { $_.type -eq 'error' } | ForEach-Object { [string]$_.text }) -join ' ') -like '*NOT READABLE*') | Should Be $true
    }

    It 'stale-hosts REFUSES "NEVER TOUCHED" when a monthly CSV cannot be read' {
        $t = New-HistTestTree -Name 'staleLocked' -TargetHosts @('WS-9999')
        $fs = Lock-HistFile -Path $t.Csv
        try {
            Set-HistRootOverride -Path $t.Root -Exists $true
            $run = Invoke-StaleRun
            ([string]$run.Result.rows[0].Verdict) | Should Be 'UNKNOWN (read error)'
            [int]$run.Result.summary.never | Should Be 0
            ([int]$run.Result.summary.readErrors -ge 1) | Should Be $true
        } finally { $fs.Close(); $fs.Dispose() }
    }

    It 'still reports NEVER TOUCHED on a healthy readable source (the fix is not a blanket UNKNOWN)' {
        $t = New-HistTestTree -Name 'staleClean' -TargetHosts @('WS-0001')
        Set-HistRootOverride -Path $t.Root -Exists $true
        $run = Invoke-StaleRun -TargetHost 'WS-9999'
        ([string]$run.Result.rows[0].Verdict) | Should Be 'NEVER TOUCHED'
        [int]$run.Result.summary.never | Should Be 1
        [int]$run.Result.summary.unknown | Should Be 0
        $run.Result.summary.readFailed | Should Be $false
        $run.Result.summary.sourceReadable | Should Be $true
    }

    It 'still reports FRESH for a host that really was touched' {
        $t = New-HistTestTree -Name 'staleFresh' -TargetHosts @('WS-0001')
        Set-HistRootOverride -Path $t.Root -Exists $true
        $run = Invoke-StaleRun -TargetHost 'WS-0001'
        ([string]$run.Result.rows[0].Verdict) | Should Be 'FRESH'
        [int]$run.Result.summary.fresh | Should Be 1
    }

    It 'host-timeline reports an unreadable source as UNKNOWN, not "no history"' {
        Set-HistRootOverride -Path (Join-Path $script:Tmp '__unreadable__') -Exists $false
        $evts = New-Object System.Collections.ArrayList
        $r = Invoke-JanetToolAction -ActionId 'host-timeline' `
                -Params @{ host = 'WS-9999'; months = 1 } `
                -Emit { param($e) [void]$evts.Add($e) }
        [int]$r.summary.total | Should Be 0
        $r.summary.readFailed | Should Be $true
        (@($evts | Where-Object { $_.type -eq 'error' }).Count -ge 1) | Should Be $true
    }

    It 'restores the real Resolve-HistRoot (no live share was ever read)' {
        & $script:Mod { ${function:script:Resolve-HistRoot} = $script:__origResolveHistRoot }
        (& $script:Mod { (Get-Command Resolve-HistRoot).Definition -like '*HistShareRoot*' }) | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'cleanup' {
    It 'removes its temp tree' {
        Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        (Test-Path -LiteralPath $script:Tmp) | Should Be $false
    }
}
