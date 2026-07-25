# =============================================================================
#  Logging.ReplayTail.Tests.ps1 - Pester 3.4 for Invoke-JanetWebReplay's
#  ".replayed" receipt, on the WHOLE-FILE (.log transcript) path.
#
#  WHY THIS EXISTS (audit 2026-07-25, fable re-audit follow-up): when the rename
#  that retires a spooled file is refused (peer handle / AV / ACL), the replay
#  drops a '<name>.replayed' receipt recording replayedLines=<n> so a later pass
#  ships only the TAIL. Two ways that can silently corrupt the audit trail of
#  record, and one test each:
#    1. the .log branch appends the file WHOLE (its 3-line session header is part
#       of the body), so its count must be a whole-file line count and the skip
#       must be over the whole file too. Get the basis wrong by 3 and every later
#       append is duplicated or dropped.
#    2. the receipt must not OUTLIVE its spool file. Spool paths are deterministic
#       (monthly CSVs, per-session .log), so the next local-only stretch recreates
#       the same path - a stale receipt makes the next pass skip that many
#       BRAND-NEW rows. That is silent loss, which is exactly what the receipt is
#       there to prevent.
#
#  Driven against the REAL source (dot-sourced JanetWeb.Logging.ps1). The rename
#  is blocked the way it is blocked in production: the file is held open with
#  FileShare 'Read', so the replay can still READ it but cannot rename it. Both
#  roots are local temp dirs - no share is touched.
#
#  Run:  Invoke-Pester -Path .\tests\Logging.ReplayTail.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

Describe 'Invoke-JanetWebReplay - receipt tail accounting' {

    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__rtRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwrtail_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:__rtRoot -Force | Out-Null

    # One isolated local+net pair per test, so a file left behind by one It can
    # never be re-enumerated by the next (the replay walks the whole spool tree).
    function New-ReplayEnv {
        param([string]$Name)
        $localRoot = Join-Path (Join-Path $script:__rtRoot $Name) 'JanetLocal'
        $netRoot   = Join-Path (Join-Path $script:__rtRoot $Name) 'share'
        $spoolDir  = Join-Path (Join-Path $localRoot 'WPT') 'tester - PC_tester'
        New-Item -ItemType Directory -Path $spoolDir, $netRoot -Force | Out-Null
        [pscustomobject]@{
            Ctx      = [pscustomobject]@{ JanetLocal = $localRoot; NetRoot = $netRoot; Lock = (New-Object object); OnShare = $true }
            SpoolDir = $spoolDir
            NetDir   = (Join-Path (Join-Path $netRoot 'WPT') 'tester - PC_tester')
        }
    }
    # Blocks Rename-Item (no FileShare.Delete) while leaving the file readable.
    function Open-Unrenamable { param([string]$Path) [System.IO.File]::Open($Path, 'Open', 'Read', 'Read') }
    function Get-ShareLines {
        param([string]$Dir, [string]$Name)
        $p = Join-Path $Dir $Name
        if (Test-Path -LiteralPath $p) { return @(Get-Content -LiteralPath $p) }
        return @()
    }
    # How many times does the WORST-represented / BEST-represented line appear?
    # Returns the max occurrence count across the expected lines (1 == exactly once each).
    function Get-MaxOccurrence {
        param([string[]]$Haystack, [string[]]$Expected)
        $max = 0
        foreach ($e in $Expected) {
            $n = @($Haystack | Where-Object { $_ -eq $e }).Count
            if ($n -gt $max) { $max = $n }
        }
        return $max
    }
    function Get-MinOccurrence {
        param([string[]]$Haystack, [string[]]$Expected)
        $min = [int]::MaxValue
        foreach ($e in $Expected) {
            $n = @($Haystack | Where-Object { $_ -eq $e }).Count
            if ($n -lt $min) { $min = $n }
        }
        if ($min -eq [int]::MaxValue) { return 0 }
        return $min
    }

    It 'replays a .log transcript tail exactly once when the rename stays blocked' {
        $e1 = New-ReplayEnv 'logtail'
        $log  = Join-Path $e1.SpoolDir 'WPT_tester_2026-07-25_09-00-00.log'
        # A real transcript: 3-line header block (part of the BODY on this path) + entries.
        $first = @(
            '=== WPT (JANET Web) v1.0.0 ===',
            'Session abcd1234 started 2026-07-25 09:00:00',
            'Operator: 1234567890 - Tester  (EDIPI: 1234567890)  on PC',
            '[2026-07-25 09:00:01] [USER: t] [ACTION: A1] [TARGET: PC-01] [RESULT: Success]',
            '[2026-07-25 09:00:02] [USER: t] [ACTION: A2] [TARGET: PC-02] [RESULT: Success]'
        )
        Set-Content -LiteralPath $log -Encoding UTF8 -Value $first

        # Pass 1 - rename refused, so a receipt has to carry the count forward.
        $fs = Open-Unrenamable $log
        try { Invoke-JanetWebReplay -Context $e1.Ctx -WarningAction SilentlyContinue } finally { $fs.Close() }
        Test-Path -LiteralPath ($log + '.replayed') | Should Be $true
        $after1 = Get-ShareLines $e1.NetDir 'WPT_tester_2026-07-25_09-00-00.log'
        (Get-MinOccurrence $after1 $first) | Should Be 1
        (Get-MaxOccurrence $after1 $first) | Should Be 1

        # The session keeps writing to the SAME spool file, then we replay again with
        # the rename still refused. Only the appended lines may go up.
        $more = @(
            '[2026-07-25 09:05:00] [USER: t] [ACTION: A3] [TARGET: PC-03] [RESULT: Success]',
            '[2026-07-25 09:05:01] [USER: t] [ACTION: A4] [TARGET: PC-04] [RESULT: Failure]'
        )
        Add-Content -LiteralPath $log -Encoding UTF8 -Value $more
        $fs = Open-Unrenamable $log
        try { Invoke-JanetWebReplay -Context $e1.Ctx -WarningAction SilentlyContinue } finally { $fs.Close() }

        $all   = @($first + $more)
        $after2 = Get-ShareLines $e1.NetDir 'WPT_tester_2026-07-25_09-00-00.log'
        $after2.Count | Should Be $all.Count
        (Get-MinOccurrence $after2 $all) | Should Be 1   # nothing dropped (a too-big skip)
        (Get-MaxOccurrence $after2 $all) | Should Be 1   # nothing doubled (a too-small skip)

        # And once the handle is gone the file retires without shipping anything twice.
        Invoke-JanetWebReplay -Context $e1.Ctx -WarningAction SilentlyContinue
        $after3 = Get-ShareLines $e1.NetDir 'WPT_tester_2026-07-25_09-00-00.log'
        $after3.Count | Should Be $all.Count
        (Get-MaxOccurrence $after3 $all) | Should Be 1
        Test-Path -LiteralPath $log | Should Be $false
    }

    It 'deletes the receipt when the rename finally succeeds, so a recreated spool file is not skipped' {
        # The receipt outliving its file was silent LOSS: the spool path is
        # deterministic, so the next outage refills it and a stale count skipped
        # that many brand-new rows.
        $e2 = New-ReplayEnv 'receiptlife'
        $hdr  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
        $csv  = Join-Path $e2.SpoolDir '2026-07_detail.csv'
        $old  = @('t,s,o,,WPT,1,TouchHost,PC-01,Success,1,d', 't,s,o,,WPT,1,TouchHost,PC-02,Success,1,d')
        Set-Content -LiteralPath $csv -Encoding UTF8 -Value (@($hdr) + $old)

        $fs = Open-Unrenamable $csv
        try { Invoke-JanetWebReplay -Context $e2.Ctx -WarningAction SilentlyContinue } finally { $fs.Close() }
        Test-Path -LiteralPath ($csv + '.replayed') | Should Be $true

        # Rename works now: the file retires AND its receipt must go with it.
        Invoke-JanetWebReplay -Context $e2.Ctx -WarningAction SilentlyContinue
        Test-Path -LiteralPath $csv               | Should Be $false
        Test-Path -LiteralPath ($csv + '.replayed') | Should Be $false

        # A later outage recreates the same monthly path with BRAND-NEW rows (three,
        # so a stale count of 2 could not be caught by the length sanity check).
        $new = @('t,s,o,,WPT,1,TouchHost,PC-07,Success,1,d',
                 't,s,o,,WPT,1,TouchHost,PC-08,Success,1,d',
                 't,s,o,,WPT,1,TouchHost,PC-09,Success,1,d')
        Set-Content -LiteralPath $csv -Encoding UTF8 -Value (@($hdr) + $new)
        Invoke-JanetWebReplay -Context $e2.Ctx -WarningAction SilentlyContinue

        $lines = Get-ShareLines $e2.NetDir '2026-07_detail.csv'
        $expect = @($old + $new)
        $lines.Count | Should Be ($expect.Count + 1)          # + the header
        (Get-MinOccurrence $lines $expect) | Should Be 1      # every row reached the share
        (Get-MaxOccurrence $lines $expect) | Should Be 1      # exactly once
    }

    Remove-Item -LiteralPath $script:__rtRoot -Recurse -Force -ErrorAction SilentlyContinue
}
