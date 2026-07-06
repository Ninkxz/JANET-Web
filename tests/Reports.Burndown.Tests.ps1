# =============================================================================
#  Reports.Burndown.Tests.ps1 - Pester 3.4 tests for the 'burndown-snapshot' /
#  'burndown' actions: a persisted vuln-backlog time series (JanetLocal\trend\
#  burndown.jsonl). REUSES Build-CoraSummary for the severity/host tallies
#  (same as posture-digest) - only the KEV tally + the append/read of the
#  trend store are new. Read-only over $script:AcasFindings; the only side
#  effect is appending to the trend store.
#
#  Testability seam: $script:ReportsTrendDir (module-scoped) overrides
#  Get-ReportsTrendDir so these tests point the store at a TEMP folder and
#  never touch the real JanetLocal\trend. Cleaned up at the end.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru
$script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetWeb_Burndown_Tests_" + [guid]::NewGuid().ToString('N'))

Describe 'burndown-snapshot: append one trend point (no findings loaded)' {

    $result = & $script:Mod {
        param($TrendDir)
        $script:ReportsTrendDir = $TrendDir
        $script:AcasFindings = New-Object System.Collections.ArrayList
        Invoke-JanetToolAction -ActionId 'burndown-snapshot' -Params @{} -Emit { param($e) }
    } $script:TempDir

    It 'returns ok=false when no findings are loaded' {
        $result.summary.ok | Should Be $false
    }
    It 'writes nothing to the trend store' {
        Test-Path -LiteralPath (Join-Path $script:TempDir 'burndown.jsonl') | Should Be $false
    }
}

Describe 'burndown-snapshot: append one trend point (findings loaded)' {

    $result = & $script:Mod {
        param($TrendDir)
        $script:ReportsTrendDir = $TrendDir
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='1'; VulnName='Google Chrome vuln'; Severity='Critical'; CVE='CVE-2024-1'; Category='Other'; Status='Open'; Solution='Upgrade Chrome.'; InKEV=$true;  KevCves='CVE-2024-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Firefox vuln';       Severity='High';     CVE='';           Category='Other'; Status='Open'; Solution='Upgrade Firefox.'; InKEV=$false; KevCves='';           IAVA='' }
            [pscustomobject]@{ Hostname='hC'; PluginID='3'; VulnName='Already fixed';      Severity='Critical'; CVE='';           Category='Other'; Status='Patched'; Solution='n/a';           InKEV=$true;  KevCves='';           IAVA='' }
        )
        $snap = Invoke-JanetToolAction -ActionId 'burndown-snapshot' -Params @{ label='unit-test' } -Emit { param($e) }
        $raw  = Get-Content -LiteralPath (Join-Path $TrendDir 'burndown.jsonl') -Raw
        [pscustomobject]@{ Snap = $snap; Raw = $raw }
    } $script:TempDir

    It 'returns ok=true with the computed record' {
        $result.Snap.summary.ok | Should Be $true
        [int]$result.Snap.summary.record.totalOpen | Should Be 2
        [int]$result.Snap.summary.record.critical  | Should Be 1
        [int]$result.Snap.summary.record.high      | Should Be 1
        [int]$result.Snap.summary.record.kev       | Should Be 1
        [int]$result.Snap.summary.record.hosts     | Should Be 2
        [int]$result.Snap.summary.count            | Should Be 1
    }
    It 'appends a real line to the trend store' {
        $result.Raw | Should Not BeNullOrEmpty
        $result.Raw | Should Match 'unit-test'
    }
}

Describe 'burndown: empty store reads back cleanly' {

    $emptyDir = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetWeb_Burndown_Empty_" + [guid]::NewGuid().ToString('N'))
    $result = & $script:Mod {
        param($TrendDir)
        $script:ReportsTrendDir = $TrendDir
        Invoke-JanetToolAction -ActionId 'burndown' -Params @{} -Emit { param($e) }
    } $emptyDir

    It 'returns an empty series with no throw' {
        [int]$result.summary.points | Should Be 0
        @($result.rows).Count | Should Be 0
        @($result.summary.series).Count | Should Be 0
    }
}

Describe 'burndown: reads back an appended series and computes deltas' {

    $trendDir = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetWeb_Burndown_Series_" + [guid]::NewGuid().ToString('N'))

    $result = & $script:Mod {
        param($TrendDir)
        $script:ReportsTrendDir = $TrendDir

        # Snapshot 1: 10 open, 4 KEV, 3 hosts.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='h1'; PluginID='1'; VulnName='a'; Severity='Critical'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$true;  KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='2'; VulnName='b'; Severity='High';     CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$true;  KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='3'; VulnName='c'; Severity='High';     CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$true;  KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='4'; VulnName='d'; Severity='Medium';   CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$true;  KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h3'; PluginID='5'; VulnName='e'; Severity='Medium';   CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h3'; PluginID='6'; VulnName='f'; Severity='Medium';   CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='7'; VulnName='g'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='8'; VulnName='h'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h3'; PluginID='9'; VulnName='i'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='10';VulnName='j'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'burndown-snapshot' -Params @{ label='point-1' } -Emit { param($e) } | Out-Null
        Start-Sleep -Milliseconds 20

        # Snapshot 2: backlog burned down to 5 open, 1 KEV, 2 hosts.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='h1'; PluginID='1'; VulnName='a'; Severity='Critical'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$true;  KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='2'; VulnName='b'; Severity='High';     CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='3'; VulnName='c'; Severity='Medium';   CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='4'; VulnName='d'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='5'; VulnName='e'; Severity='Low';      CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            # remainder patched -> not counted as open
            [pscustomobject]@{ Hostname='h3'; PluginID='6'; VulnName='f'; Severity='Medium';   CVE=''; Category='Other'; Status='Patched'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'burndown-snapshot' -Params @{ label='point-2' } -Emit { param($e) } | Out-Null

        Invoke-JanetToolAction -ActionId 'burndown' -Params @{} -Emit { param($e) }
    } $trendDir

    It 'reads back both points in ascending order' {
        [int]$result.summary.points | Should Be 2
        @($result.rows).Count | Should Be 2
        $result.rows[0].TotalOpen | Should Be 10
        $result.rows[1].TotalOpen | Should Be 5
    }
    It 'computes deltaOpen and pctClosed from first to last' {
        [int]$result.summary.firstOpen | Should Be 10
        [int]$result.summary.lastOpen  | Should Be 5
        [int]$result.summary.deltaOpen | Should Be -5
        [double]$result.summary.pctClosed | Should Be 50
    }
    It 'computes KEV deltas the same way' {
        [int]$result.summary.firstKev | Should Be 4
        [int]$result.summary.lastKev  | Should Be 1
        [int]$result.summary.kevClosed | Should Be 3
    }
    It 'carries a chart-ready series with the same point count' {
        @($result.summary.series).Count | Should Be 2
        $result.summary.series[0].totalOpen | Should Be 10
        $result.summary.series[1].totalOpen | Should Be 5
    }

    # cleanup: remove this Describe's temp trend dir
    It 'cleans up its temp trend dir' {
        if (Test-Path -LiteralPath $trendDir) { Remove-Item -LiteralPath $trendDir -Recurse -Force }
        Test-Path -LiteralPath $trendDir | Should Be $false
    }
}

# cleanup: remove the shared temp trend dir used by the first two Describes
if (Test-Path -LiteralPath $script:TempDir) { Remove-Item -LiteralPath $script:TempDir -Recurse -Force }
