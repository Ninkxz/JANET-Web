# =============================================================================
#  Logging.UsageSnapshot.Tests.ps1 - Pester 3.4 for Write-JanetWebUsageSnapshot.
#
#  WHY THIS EXISTS: the SessionEnd usage rollup only lands on a CLEAN server stop,
#  so a JANET Web server left running for days wrote NO usage rows (dashboard
#  blind), and a killed console lost the rollup outright. The snapshot writer
#  emits CUMULATIVE per-tool rows (RowType='Snapshot') the dashboard's
#  per-(SessionId,Tool) dedupe keeps (latest wins; SessionEnd supersedes all).
#
#  Driven against the REAL source (dot-sourced JanetWeb.Logging.ps1) with a
#  share-down context so every row lands in a temp local spool. No live share.
#
#  Run:  Invoke-Pester -Path .\tests\Logging.UsageSnapshot.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

Describe 'Write-JanetWebUsageSnapshot - live usage rows without a server stop' {

    . (Join-Path $script:Root 'server\JanetWeb.Logging.ps1')

    $script:__tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('jwsnap_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:__tmpRoot -Force | Out-Null

    function New-SnapContext {
        # Mirrors New-JanetWebLogContext's shape; OnShare=$false -> local spool only.
        [pscustomobject]@{
            Lock           = (New-Object object)
            OnShare        = $false
            NetRoot        = 'C:\__janetweb_no_such_share__'
            JanetLocal     = $script:__tmpRoot
            Operator       = 'Test Operator'
            Edipi          = '0000000000'
            Asi            = ''
            SessionId      = 'snap-1'
            SourceHost     = 'TESTHOST'
            UserFolder     = 'tester - TESTHOST_tester'
            NemesisFolder  = 'tester - Test Operator'
            Version        = '1.0.0'
            Month          = (Get-Date).ToString('yyyy-MM')
            LogStamp       = 'stamp'
            StartedAt      = (Get-Date)
            Hosts          = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
            Vulns          = 0
            Failures       = 0
            RunCount       = 0
            RunSuccess     = 0
            RunFailed      = 0
            PerTool        = ([hashtable]::Synchronized(@{}))
            UsageDirty     = $false
            LastSnapshotAt = (Get-Date).AddHours(-1)
        }
    }
    function Get-UsageLines {
        $f = Join-Path (Join-Path (Join-Path $script:__tmpRoot '_Rollup') 'tester - TESTHOST_tester') ((Get-Date).ToString('yyyy-MM') + '_usage.csv')
        if (Test-Path -LiteralPath $f) { @(Get-Content -LiteralPath $f) } else { @() }
    }

    $ctx = New-SnapContext

    It 'is a NO-OP before any action was tallied (never writes an empty snapshot)' {
        Write-JanetWebUsageSnapshot -Context $ctx -MinIntervalSec 0
        @(Get-UsageLines).Count | Should Be 0
    }

    It 'after Write-JanetAction it writes one cumulative Snapshot row per tool' {
        Write-JanetAction -Context $ctx -Tool 'c2c' -Action 'VulnPatched' -Target 'HOSTA' -Result 'Success' -ItemCount 3
        Write-JanetAction -Context $ctx -Tool 'c2c' -Action 'VulnPatched' -Target 'HOSTB' -Result 'Failure'
        Write-JanetAction -Context $ctx -Tool 'wpt' -Action 'TouchHost'   -Target 'HOSTC' -Result 'Success'
        Write-JanetWebUsageSnapshot -Context $ctx -MinIntervalSec 0
        $rows = @(Get-UsageLines | Select-String -SimpleMatch 'Snapshot')
        # 2 per-tool rows + the aggregate JANET-WEB row (which mirrors the SessionEnd
        # rollup: readers that scope to JANET Web filter Tool='JANET-WEB', and the
        # per-tool rows carry DESKTOP tool names, so they cannot serve that scoping).
        $rows.Count | Should Be 3
        # c2c row: cumulative 2 hosts / 3 vulns / 1 failure
        $c2c = @($rows | Where-Object { $_ -match ',c2c,' })[0].ToString()
        $c2c | Should Match 'Snapshot,2,3,1'
        # wpt maps to the desktop WPT folder name
        @($rows | Where-Object { $_ -match ',WPT,' }).Count | Should Be 1
        # aggregate row: 3 distinct hosts across both tools, 3 vulns, 1 failure
        $agg = @($rows | Where-Object { $_ -match ',JANET-WEB,' })
        $agg.Count | Should Be 1
        $agg[0].ToString() | Should Match 'Snapshot,3,3,1'
    }

    It 'does NOT re-emit while nothing new was tallied (UsageDirty cleared)' {
        Write-JanetWebUsageSnapshot -Context $ctx -MinIntervalSec 0
        @(Get-UsageLines | Select-String -SimpleMatch 'Snapshot').Count | Should Be 3
    }

    It 'honours the minimum interval (fresh activity but too soon -> no row)' {
        Write-JanetAction -Context $ctx -Tool 'c2c' -Action 'TouchHost' -Target 'HOSTD' -Result 'Success'
        $ctx.LastSnapshotAt = Get-Date   # just snapped
        Write-JanetWebUsageSnapshot -Context $ctx -MinIntervalSec 300
        @(Get-UsageLines | Select-String -SimpleMatch 'Snapshot').Count | Should Be 3
    }

    It 're-emits UPDATED cumulative counts once the interval elapses' {
        $ctx.LastSnapshotAt = (Get-Date).AddHours(-1)
        Write-JanetWebUsageSnapshot -Context $ctx -MinIntervalSec 300
        $c2cRows = @(Get-UsageLines | Select-String -SimpleMatch 'Snapshot' | Where-Object { $_ -match ',c2c,' })
        $c2cRows.Count | Should Be 2
        # latest c2c snapshot now shows 3 hosts (HOSTA/HOSTB/HOSTD), still 3 vulns / 1 failure
        $c2cRows[-1].ToString() | Should Match 'Snapshot,3,3,1'
    }

    It 'SessionEnd rollup rows still land afterwards and outrank the snapshots' {
        Write-JanetWebRollup -Context $ctx -ClosingNotes 'done'
        $lines = @(Get-UsageLines)
        @($lines | Select-String -SimpleMatch 'SessionEnd' | Where-Object { $_ -match ',c2c,' }).Count | Should Be 1
        @($lines | Select-String -SimpleMatch 'SessionEnd' | Where-Object { $_ -match 'JANET-WEB' }).Count | Should Be 1
    }

    It 'the server accept loop calls the snapshot writer (wired, not just defined)' {
        (Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw) | Should Match 'Write-JanetWebUsageSnapshot -Context \$state\.LogCtx'
    }

    # cleanup
    Remove-Item -LiteralPath $script:__tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
