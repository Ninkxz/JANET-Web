# =============================================================================
#  Reports.RollupReadFailure.Tests.ps1 - Pester 3.4 for the audit 2026-07-25
#  (fable re-audit follow-up) squadron-rollup read-failure fixes (reports v2.15.2).
#
#  BUG 1: every log-share walk in 'squadron-rollup' was `-ErrorAction SilentlyContinue`
#  inside a BARE `catch {}`. A DENIED or vanished directory therefore contributed
#  ZERO rows with no signal anywhere, so "the share could not be read" rendered as
#  "nobody did any work" - a confident empty fleet rollup over a tree the pass never
#  walked. The rollup now records each failing path, emits a type='error' event, and
#  returns readErrors / readFailed / readErrorPaths in the summary.
#
#  BUG 2: Pass A read the EXACT '<month>_usage.csv'. When the live file is locked the
#  logging writer redirects rows to a header-rotation sister '<base>.r<unix>.csv'
#  (server\JanetWeb.Logging.ps1), so live web sessions were invisible to this pass.
#  It now globs '<month>_usage*.csv' the way JanetWeb.history.psm1 does.
#
#  These are BEHAVIOURAL: a throwaway temp tree stands in for the log share (the
#  module's Get-ReportsLogShareRoot is redirected at it inside the module scope), and
#  one tool folder carries a real DENY ACE so its enumeration genuinely throws. The
#  real \\dm-tn-01 log share is never touched, and every temp artifact is removed.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.RollupReadFailure.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

$script:Month = (Get-Date).ToString('yyyy-MM')
$script:Me    = "$env:USERDOMAIN\$env:USERNAME"

# --- temp log-share builders -------------------------------------------------
function New-TestShare {
    # Logs\<Tool>\<userFolder>\<YYYY-MM>_detail.csv with a single TouchHost row.
    $r = Join-Path ([System.IO.Path]::GetTempPath()) ('janetrollup_' + [guid]::NewGuid().ToString('N'))
    $d = Join-Path $r 'acas\op.readable'
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $d ($script:Month + '_detail.csv')) -Encoding UTF8 -Value @(
        'Timestamp,Tool,Action,Target,Result,Operator,Detail,ItemCount,SessionId'
        "$($script:Month)-01 08:00:00,acas,TouchHost,GOODHOST01,Success,readable.op,seed,1,S-1"
    )
    return $r
}
function Add-DeniedToolDir {
    # A second tool folder the current user may NOT enumerate: Get-ChildItem on it
    # throws UnauthorizedAccessException, which is exactly the swallowed case.
    param([string]$ShareRoot)
    $denied = Join-Path $ShareRoot 'certdeploy'
    New-Item -ItemType Directory -Path (Join-Path $denied 'op.denied') -Force | Out-Null
    & icacls $denied /deny ($script:Me + ':(OI)(CI)(RX)') 2>&1 | Out-Null
    return $denied
}
function Remove-TestShare {
    param([string]$ShareRoot, [string]$DeniedDir)
    if ($DeniedDir -and (Test-Path -LiteralPath $DeniedDir)) { & icacls $DeniedDir /remove:d $script:Me 2>&1 | Out-Null }
    if ($ShareRoot -and (Test-Path -LiteralPath $ShareRoot)) { Remove-Item -LiteralPath $ShareRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
function Invoke-TestRollup {
    # Point the module at $ShareRoot (non-UNC, so the TCP-445 pre-gate passes) and run
    # the rollup with no credential (AD squadron classification stays off).
    param([string]$ShareRoot)
    & $script:Mod {
        param($root)
        Set-Item -Path function:script:Get-ReportsLogShareRoot -Value ([scriptblock]::Create("return '$root'"))
        $events = New-Object System.Collections.ArrayList
        $res = Invoke-JanetToolAction -ActionId 'squadron-rollup' -Params @{ monthsBack = 1 } -Emit { param($e) [void]$events.Add($e) }
        @{ Summary = $res.summary; Rows = @($res.rows); Events = @($events.ToArray()) }
    } $ShareRoot
}

Describe 'squadron-rollup: a DENIED directory is reported, not silently counted as no activity (audit 2026-07-25)' {

    $share = New-TestShare
    $denied = Add-DeniedToolDir -ShareRoot $share
    # Guard: if the deny ACE did not take (exotic ACL/policy), say so loudly rather
    # than passing a test that proved nothing.
    $denyBites = $false
    try { [void]@(Get-ChildItem -LiteralPath $denied -Directory -ErrorAction Stop) } catch { $denyBites = $true }
    $out = Invoke-TestRollup -ShareRoot $share
    Remove-TestShare -ShareRoot $share -DeniedDir $denied
    $s = $out.Summary

    It 'the DENY ACE actually blocks enumeration (guard - the rest proves nothing otherwise)' {
        $denyBites | Should Be $true
    }

    It 'reaches the share (this is a READ failure, not an unreachable-share failure)' {
        $s.shareOk | Should Be $true
    }

    It 'reports readFailed instead of a confident clean result' {
        [bool]$s.readFailed | Should Be $true
    }

    It 'counts the unreadable path(s) and names them' {
        ([int]$s.readErrors -ge 1) | Should Be $true
        (@($s.readErrorPaths).Count -ge 1) | Should Be $true
        (@($s.readErrorPaths) -join ' ') -like '*certdeploy*' | Should Be $true
    }

    It 'raises an operator-visible error event (a warn buried in the log is not enough)' {
        $errs = @($out.Events | Where-Object { $_.type -eq 'error' })
        ($errs.Count -ge 1) | Should Be $true
        ([string]$errs[0].text) -like '*INCOMPLETE*' | Should Be $true
    }

    It 'still returns what it COULD read (a read failure degrades the pass, never aborts it)' {
        @($out.Rows | Where-Object { $_.Name -eq 'readable.op' }).Count | Should Be 1
    }
}

Describe 'squadron-rollup: a clean share does NOT cry read-failure (no false alarm)' {

    $share = New-TestShare
    $out = Invoke-TestRollup -ShareRoot $share
    Remove-TestShare -ShareRoot $share
    $s = $out.Summary

    It 'readFailed is false and readErrors is 0' {
        [bool]$s.readFailed | Should Be $false
        [int]$s.readErrors  | Should Be 0
    }

    It 'emits no error event' {
        @($out.Events | Where-Object { $_.type -eq 'error' }).Count | Should Be 0
    }

    It 'rolls the readable operator up as before' {
        @($out.Rows | Where-Object { $_.Name -eq 'readable.op' }).Count | Should Be 1
    }
}

Describe 'squadron-rollup: the usage pass sees header-rotation sister files (audit 2026-07-25)' {

    # The live <month>_usage.csv is absent (locked/rotated); the writer put the rows in
    # <base>.r<unix>.csv. A '*.legacy_*' rotation alongside it must STAY excluded -
    # stale schema, same convention as the replay path and history.psm1.
    $share = New-TestShare
    Set-Content -LiteralPath (Join-Path $share ($script:Month + '_usage.r1770000000.csv')) -Encoding UTF8 -Value @(
        'Timestamp,SessionId,Operator,Tool,RowType,HostsTouched,VulnsPatched,Failures'
        "$($script:Month)-02 09:00:00,S-9,sister.op,JANET-WEB,SessionEnd,0,0,0"
    )
    Set-Content -LiteralPath (Join-Path $share ($script:Month + '_usage.legacy_1769000000.csv')) -Encoding UTF8 -Value @(
        'Timestamp,SessionId,Operator,Tool,RowType,HostsTouched,VulnsPatched,Failures'
        "$($script:Month)-03 09:00:00,S-8,legacy.op,JANET-WEB,SessionEnd,0,0,0"
    )
    $out = Invoke-TestRollup -ShareRoot $share
    Remove-TestShare -ShareRoot $share

    It 'the sister-file operator is in the rollup (was invisible to the exact-name read)' {
        @($out.Rows | Where-Object { $_.Name -eq 'sister.op' }).Count | Should Be 1
    }

    It 'the stale-schema *.legacy_* rotation is still skipped' {
        @($out.Rows | Where-Object { $_.Name -eq 'legacy.op' }).Count | Should Be 0
    }

    It 'reads clean - a sister file is normal operation, not a read error' {
        [bool]$out.Summary.readFailed | Should Be $false
    }
}
