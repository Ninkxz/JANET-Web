# =============================================================================
#  History.RunOutcomes.Tests.ps1 - Pester 3.4 for the Run Outcomes Board
#  (capability audit 2026-07-25 #7, JanetWeb.history 1.2.0).
#
#  Write-JanetWebRun (server\JanetWeb.Logging.ps1:763-832) has written a 17-column
#  per-run card to Logs\<Tool>\ACAS-Nemesis-Runs_<YYYY-MM-DD>.csv since day one and
#  NOTHING in either repo ever read it. The board is that read side.
#
#  THE TRAP THIS FILE EXISTS TO PIN (:804-817): a rolled-up group card is written
#  as ONE ROW PER MEMBER, and every member row carries the SAME Timestamp,
#  SessionId, GroupKey AND THE SAME COUNTERS. Summing the rows raw multiplies
#  HostsTotal / Success / Failed by GroupSize - a 3-member card that patched 12
#  hosts with 10 successes would report 36 hosts and 30 successes, i.e. a board
#  that inflates the fleet's apparent throughput by a factor nobody can see.
#  'counts a 3-member rolled-up group card ONCE' below is the deliverable's proof.
#
#  Everything runs against a throwaway temp tree; the REAL log share is never
#  touched (Resolve-HistRoot is shadowed in MODULE scope and SAVED/RESTORED - the
#  naive 'Remove-Item function:script:X' form is INERT against a module-scope
#  function and its unqualified sibling DESTROYS the module's real one, see
#  tests\Patchlib.Tests.ps1).
#
#  Run:  Invoke-Pester -Path .\tests\History.RunOutcomes.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.history.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ('histruntest_' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

$script:RunHeader = 'Timestamp,User,Edipi,SessionId,Host,RowType,Action,Scope,Profile,Mode,HostsTotal,Success,Failed,DurationSec,Notes,GroupKey,GroupSize'

# One Runs-CSV row in the exact 17-column order Write-JanetWebRun emits.
function New-RunLine {
    param(
        [string]$Timestamp, [string]$User = 'Test Operator', [string]$SessionId = 'sess-1',
        [string]$RowType = 'Run', [string]$Action = 'Update', [string]$Scope = 'WS-0001',
        [string]$ProfileName = 'Chrome', [string]$Mode = 'Silent',
        [int]$HostsTotal = 1, [int]$Success = 1, [int]$Failed = 0, [int]$DurationSec = 10,
        [string]$Notes = '', [string]$GroupKey = '', [int]$GroupSize = 1
    )
    return ('{0},{1},1234567890,{2},SRC-01,{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14}' -f `
        $Timestamp, $User, $SessionId, $RowType, $Action, $Scope, $ProfileName, $Mode,
        $HostsTotal, $Success, $Failed, $DurationSec, $Notes, $GroupKey, $GroupSize)
}

# Build <root>\<Tool>\ACAS-Nemesis-Runs_<day>.csv from raw lines.
function New-RunTree {
    param([string]$Name, [string]$Tool = 'ACAS_Nemesis', [string]$Day = '', [string[]]$Lines = @())
    if (-not $Day) { $Day = (Get-Date).ToString('yyyy-MM-dd') }
    $root = Join-Path $script:Tmp $Name
    $dir  = Join-Path $root $Tool
    [void][System.IO.Directory]::CreateDirectory($dir)
    $csv = Join-Path $dir ('ACAS-Nemesis-Runs_' + $Day + '.csv')
    $all = New-Object System.Collections.ArrayList
    [void]$all.Add($script:RunHeader)
    foreach ($l in $Lines) { [void]$all.Add($l) }
    Set-Content -LiteralPath $csv -Value $all -Encoding ASCII
    return @{ Root = $root; Csv = $csv }
}

# --- module-scope shim of Resolve-HistRoot, SAVED so it can be RESTORED ---------
& $script:Mod { $script:__origResolveHistRoot = ${function:Resolve-HistRoot} }
function Set-RunRootOverride {
    param([string]$Path, [bool]$Exists = $true)
    & $script:Mod {
        param($p, $e)
        ${function:script:Resolve-HistRoot} = { @{ Root = $p; OnShare = $false; Reason = "test root ($p)"; Exists = $e } }.GetNewClosure()
    } $Path $Exists
}
function Restore-RunRoot {
    & $script:Mod { ${function:script:Resolve-HistRoot} = $script:__origResolveHistRoot }
}

function Invoke-RunOutcomes {
    param([int]$Days = 30)
    $evts = New-Object System.Collections.ArrayList
    $r = Invoke-JanetToolAction -ActionId 'run-outcomes' -Params @{ days = $Days } -Emit { param($e) [void]$evts.Add($e) }
    return @{ Result = $r; Events = @($evts) }
}

# -----------------------------------------------------------------------------
Describe 'Read-HistRunRows reads the per-run cards nothing has ever read' {

    It 'reads a healthy day-file with zero errors and the real 17-column values' {
        $t = New-RunTree -Name 'runs_ok' -Lines @(
            (New-RunLine -Timestamp ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 4 -Success 3 -Failed 1 -DurationSec 40)
        )
        $res = & $script:Mod { param($p) Read-HistRunRows -Root $p } $t.Root
        [int]$res.Errors | Should Be 0
        $res.RootMissing | Should Be $false
        @($res.Rows).Count | Should Be 1
        $row = @($res.Rows)[0]
        ([string]$row.Action) | Should Be 'Update'
        ([string]$row.Profile) | Should Be 'Chrome'
        ([string]$row.Mode) | Should Be 'Silent'
        ([int]$row.HostsTotal) | Should Be 4
        ([int]$row.Success) | Should Be 3
        ([int]$row.Failed) | Should Be 1
        ([int]$row.DurationSec) | Should Be 40
        ([string]$row.Operator) | Should Be 'Test Operator'
    }

    It 'flags a missing root as a read failure, not an empty run history' {
        $res = & $script:Mod { param($p) Read-HistRunRows -Root $p } (Join-Path $script:Tmp '__no_run_root__')
        $res.RootMissing | Should Be $true
        ([int]$res.Errors -ge 1) | Should Be $true
        @($res.Rows).Count | Should Be 0
    }

    It 'counts an unreadable day-file as a read error instead of swallowing it' {
        $t = New-RunTree -Name 'runs_locked' -Lines @((New-RunLine -Timestamp ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))
        $fs = [System.IO.File]::Open($t.Csv, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $res = & $script:Mod { param($p) Read-HistRunRows -Root $p } $t.Root
            @($res.Rows).Count | Should Be 0
            ([int]$res.Errors -ge 1) | Should Be $true
            ((@($res.ErrorMessages) -join ' ') -like '*ACAS-Nemesis-Runs_*') | Should Be $true
        } finally { $fs.Close(); $fs.Dispose() }
    }

    It 'skips a whole day-file outside the window without opening it' {
        $old = (Get-Date).AddDays(-100)
        $t = New-RunTree -Name 'runs_old' -Day $old.ToString('yyyy-MM-dd') -Lines @(
            (New-RunLine -Timestamp $old.ToString('yyyy-MM-dd HH:mm:ss'))
        )
        $res = & $script:Mod { param($p, $c) Read-HistRunRows -Root $p -MinDate $c } $t.Root ((Get-Date).AddDays(-30))
        [int]$res.Files | Should Be 0
        @($res.Rows).Count | Should Be 0
    }

    It 'honours the read cap' {
        $lines = @()
        1..5 | ForEach-Object { $lines += (New-RunLine -Timestamp ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -SessionId ("s$_")) }
        $t = New-RunTree -Name 'runs_cap' -Lines $lines
        $res = & $script:Mod { param($p) Read-HistRunRows -Root $p -Cap 2 } $t.Root
        @($res.Rows).Count | Should Be 2
        $res.Capped | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'Get-HistRunCardKey identifies rolled-up group-card members' {

    It 'returns a key for a group-card member row' {
        $k = & $script:Mod {
            Get-HistRunCardKey ([pscustomobject]@{ Timestamp='2026-07-25 10:00:00'; SessionId='s1'; GroupKey='grp-A'; Action='Update'; GroupSize=3 })
        }
        ([string]$k) | Should Match 'grp-A'
    }

    It 'gives the THREE member rows of one card the SAME key' {
        $keys = & $script:Mod {
            $r = 1..3 | ForEach-Object { [pscustomobject]@{ Timestamp='2026-07-25 10:00:00'; SessionId='s1'; GroupKey='grp-A'; Action='Update'; GroupSize=3 } }
            @($r | ForEach-Object { Get-HistRunCardKey $_ } | Select-Object -Unique)
        }
        @($keys).Count | Should Be 1
    }

    It 'returns NOTHING for a plain single-host run row - two real runs must never collapse' {
        $k = & $script:Mod {
            Get-HistRunCardKey ([pscustomobject]@{ Timestamp='2026-07-25 10:00:00'; SessionId='s1'; GroupKey=''; Action='Update'; GroupSize=1 })
        }
        ($null -eq $k) | Should Be $true
    }

    It 'still keys a group card whose GroupKey was left blank (GroupSize alone marks it)' {
        $k = & $script:Mod {
            Get-HistRunCardKey ([pscustomobject]@{ Timestamp='2026-07-25 10:00:00'; SessionId='s1'; GroupKey=''; Action='Update'; GroupSize=4 })
        }
        ($null -ne $k) | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'THE TRAP: the board counts a rolled-up group card ONCE (audit 2026-07-25 #7)' {

    # A 3-member rolled-up Updater card exactly as Write-JanetWebRun writes it:
    # one row PER MEMBER, all sharing Timestamp / SessionId / GroupKey AND the
    # SAME counters (HostsTotal 12, Success 10, Failed 2, DurationSec 60).
    $script:GroupStamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $script:GroupLines = @(
        (New-RunLine -Timestamp $script:GroupStamp -SessionId 'grp-sess' -Action 'Update' -Scope 'Google Chrome'   -ProfileName 'Browsers' -Mode 'Silent' -HostsTotal 12 -Success 10 -Failed 2 -DurationSec 60 -GroupKey 'card-7' -GroupSize 3),
        (New-RunLine -Timestamp $script:GroupStamp -SessionId 'grp-sess' -Action 'Update' -Scope 'Mozilla Firefox' -ProfileName 'Browsers' -Mode 'Silent' -HostsTotal 12 -Success 10 -Failed 2 -DurationSec 60 -GroupKey 'card-7' -GroupSize 3),
        (New-RunLine -Timestamp $script:GroupStamp -SessionId 'grp-sess' -Action 'Update' -Scope 'Adobe Reader'    -ProfileName 'Browsers' -Mode 'Silent' -HostsTotal 12 -Success 10 -Failed 2 -DurationSec 60 -GroupKey 'card-7' -GroupSize 3)
    )

    It 'Group-HistRunOutcomes collapses the 3 member rows into ONE run' {
        $t = New-RunTree -Name 'runs_group' -Lines $script:GroupLines
        $g = & $script:Mod { param($p) $r = Read-HistRunRows -Root $p; Group-HistRunOutcomes -Rows $r.Rows } $t.Root
        @($g.Groups).Count | Should Be 1
        [int]$g.Cards | Should Be 1
        [int]$g.Deduped | Should Be 2
        [int]@($g.Groups)[0].Runs | Should Be 1
    }

    It 'counts a 3-member rolled-up group card ONCE - counters are NOT multiplied by GroupSize' {
        $t = New-RunTree -Name 'runs_group2' -Lines $script:GroupLines
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        @($run.Result.rows).Count | Should Be 1
        $row = @($run.Result.rows)[0]
        [int]$row.Runs       | Should Be 1     # not 3
        [int]$row.HostsTotal | Should Be 12    # not 36
        [int]$row.Success    | Should Be 10    # not 30
        [int]$row.Failed     | Should Be 2     # not 6
        [int]$run.Result.summary.runs    | Should Be 1
        [int]$run.Result.summary.success | Should Be 10
        [int]$run.Result.summary.failed  | Should Be 2
        [int]$run.Result.summary.deduped | Should Be 2
    }

    It 'says out loud that member rows were de-duplicated (silent correctness is unauditable)' {
        $t = New-RunTree -Name 'runs_group3' -Lines $script:GroupLines
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        ((@($run.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join ' ') -like '*de-duplicated*') | Should Be $true
    }

    It 'still counts TWO independent single-host runs as TWO runs (the fix is not a blanket collapse)' {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $t = New-RunTree -Name 'runs_two' -Lines @(
            (New-RunLine -Timestamp $stamp -SessionId 'sameSess' -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 1 -Success 1 -Failed 0),
            (New-RunLine -Timestamp $stamp -SessionId 'sameSess' -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 1 -Success 1 -Failed 0)
        )
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        [int]@($run.Result.rows)[0].Runs    | Should Be 2
        [int]@($run.Result.rows)[0].Success | Should Be 2
        [int]$run.Result.summary.deduped    | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'run-outcomes aggregation and reporting' {

    It 'groups by (Action, Profile, Mode) and computes SuccessPct / AvgDurationSec / Operators' {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $t = New-RunTree -Name 'runs_agg' -Lines @(
            (New-RunLine -Timestamp $stamp -User 'Op A' -SessionId 'a1' -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 10 -Success 8 -Failed 2 -DurationSec 100),
            (New-RunLine -Timestamp $stamp -User 'Op B' -SessionId 'a2' -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 10 -Success 8 -Failed 2 -DurationSec 200),
            (New-RunLine -Timestamp $stamp -User 'Op A' -SessionId 'a3' -Action 'Remove' -ProfileName 'Java'   -Mode 'Forced' -HostsTotal 5  -Success 5 -Failed 0 -DurationSec 50)
        )
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        @($run.Result.rows).Count | Should Be 2
        $upd = @($run.Result.rows | Where-Object { $_.Action -eq 'Update' })[0]
        [int]$upd.Runs | Should Be 2
        [int]$upd.Success | Should Be 16
        [int]$upd.Failed | Should Be 4
        ([double]$upd.SuccessPct) | Should Be 80
        ([double]$upd.AvgDurationSec) | Should Be 150
        [int]$upd.Operators | Should Be 2
        ([string]$upd.Profile) | Should Be 'Chrome'
        ([string]$upd.Mode) | Should Be 'Silent'
    }

    It 'excludes the session-close SessionNotes roll-up so its whole-session counters do not double the board' {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $t = New-RunTree -Name 'runs_notes' -Lines @(
            (New-RunLine -Timestamp $stamp -Action 'Update' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 3 -Success 3 -Failed 0),
            (New-RunLine -Timestamp $stamp -RowType 'SessionNotes' -Action 'SessionEnd' -ProfileName 'Chrome' -Mode 'Silent' -HostsTotal 99 -Success 99 -Failed 9)
        )
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        [int]$run.Result.summary.runs    | Should Be 1
        [int]$run.Result.summary.success | Should Be 3
        [int]$run.Result.summary.failed  | Should Be 0
    }

    It 'renders a blank Action / Profile / Mode as (none) rather than an empty cell' {
        $t = New-RunTree -Name 'runs_blank' -Lines @(
            (New-RunLine -Timestamp ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) -Action '' -ProfileName '' -Mode '')
        )
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        ([string]@($run.Result.rows)[0].Action)  | Should Be '(none)'
        ([string]@($run.Result.rows)[0].Profile) | Should Be '(none)'
        ([string]@($run.Result.rows)[0].Mode)    | Should Be '(none)'
    }

    It 'reports an unreadable source as UNKNOWN, never as "no runs happened"' {
        Set-RunRootOverride -Path (Join-Path $script:Tmp '__no_such_run_root__') -Exists $false
        $run = Invoke-RunOutcomes -Days 30
        @($run.Result.rows).Count | Should Be 0
        $run.Result.summary.readFailed | Should Be $true
        $run.Result.summary.sourceReadable | Should Be $false
        (@($run.Events | Where-Object { $_.type -eq 'error' }).Count -ge 1) | Should Be $true
    }

    It 'is read-only: it emits no audit row and no destructive event' {
        $t = New-RunTree -Name 'runs_ro' -Lines @((New-RunLine -Timestamp ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))))
        Set-RunRootOverride -Path $t.Root -Exists $true
        $run = Invoke-RunOutcomes -Days 30
        @($run.Events | Where-Object { $_.type -eq 'audit' }).Count | Should Be 0
    }

    It 'declares run-outcomes in the manifest as a non-destructive action at version 1.2.1' {
        $m = Get-JanetToolManifest
        ([string]$m.version) | Should Be '1.2.1'
        $a = @($m.actions | Where-Object { $_.id -eq 'run-outcomes' })
        $a.Count | Should Be 1
        $a[0].destructive | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'cleanup' {
    It 'restores the real Resolve-HistRoot (no live share was ever read)' {
        Restore-RunRoot
        (& $script:Mod { (Get-Command Resolve-HistRoot).Definition -like '*HistShareRoot*' }) | Should Be $true
    }
    It 'removes its temp tree' {
        Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        (Test-Path -LiteralPath $script:Tmp) | Should Be $false
    }
}
