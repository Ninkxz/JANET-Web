# =============================================================================
#  Reports.ClosureProofReadFailure.Tests.ps1 - an unreadable audit path is not
#  proof that JANET did nothing.
#
#  THE DEFECT (loop 2026-08-03, P2): Read-ReportsAuditTouchIndex swallowed every
#  read failure - `-ErrorAction SilentlyContinue` inside a bare `catch {}` on all
#  three directory walks, and `catch { $data = @() }` on the Import-Csv. A denied
#  operator folder or a locked TouchedHosts CSV contributed ZERO touches and said
#  nothing, so scan-closure-proof rendered CONFIDENT causation numbers over files
#  it never read:
#    - a host JANET really did patch reads "closed by something else", and
#    - a still-open finding on a touched host silently drops off the next-day
#      worklist (it is only added when a touch is found).
#
#  This is the same "denied path renders as no activity" defect that v2.15.2 fixed
#  in squadron-rollup with an error bag (:6993) - the sibling reader was simply
#  left on the old pattern. Third instance of that sweep failure this week.
#
#  These are BEHAVIOURAL: they build a real audit tree, make one file genuinely
#  unreadable with a deny ACE / exclusive lock, and assert the reader REPORTS it.
#  A source-regex pin would not prove the error actually escapes the function.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.ClosureProofReadFailure.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("rpt_proof_" + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

# <root>\<Tool>\<operator>\TouchedHosts_<yyyy-MM>.csv
function New-TouchTree {
    param([string]$Name, [datetime]$When, [string[]]$Hosts)
    $root = Join-Path $script:Tmp $Name
    $dir  = Join-Path $root 'WPT\test.operator'
    [void][System.IO.Directory]::CreateDirectory($dir)
    $m = $When.ToString('yyyy-MM')
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('Timestamp,TargetHost,Operator,Result')
    foreach ($h in $Hosts) {
        [void]$lines.Add(('{0},{1},test.operator,Success' -f $When.ToString('yyyy-MM-dd HH:mm:ss'), $h))
    }
    Set-Content -LiteralPath (Join-Path $dir ("TouchedHosts_$m.csv")) -Value $lines -Encoding ASCII
    return $root
}

function Invoke-Index {
    param([string]$Root, [datetime]$Start, [datetime]$End, [string[]]$Want)
    $w = @{}; foreach ($h in $Want) { $w[$h] = $true }
    $months = @($Start.ToString('yyyy-MM'), $End.ToString('yyyy-MM')) | Sort-Object -Unique
    & $script:Mod {
        param($r, $m, $wh, $s, $e)
        Read-ReportsAuditTouchIndex -Root $r -Months $m -WantHosts $wh -Start $s -End $e
    } $Root $months $w $Start $End
}

Describe 'Read-ReportsAuditTouchIndex - a clean tree reads clean' {
    $when = (Get-Date).AddDays(-2)
    $root = New-TouchTree -Name 'clean' -When $when -Hosts @('WS-TOUCHED')
    $res  = Invoke-Index -Root $root -Start $when.AddDays(-5) -End (Get-Date) -Want @('WS-TOUCHED')

    It 'finds the touch' {
        $res.Index.ContainsKey('WS-TOUCHED') | Should Be $true
    }
    It 'reports ZERO read errors when nothing is unreadable' {
        [int]$res.Errors | Should Be 0
        @($res.ErrorPaths).Count | Should Be 0
    }
}

Describe 'Read-ReportsAuditTouchIndex - a LOCKED csv is reported, not silently empty' {
    $when = (Get-Date).AddDays(-2)
    $root = New-TouchTree -Name 'locked' -When $when -Hosts @('WS-TOUCHED')
    $csv  = @(Get-ChildItem -LiteralPath (Join-Path $root 'WPT\test.operator') -Filter '*.csv')[0].FullName

    # Exclusive lock: Import-Csv cannot open it. This is the locked-log case, which is
    # ordinary on a live share (another JANET session mid-write).
    $fs = [System.IO.File]::Open($csv, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $res = Invoke-Index -Root $root -Start $when.AddDays(-5) -End (Get-Date) -Want @('WS-TOUCHED')

        It 'surfaces the unreadable file as a read error' {
            ([int]$res.Errors -ge 1) | Should Be $true
        }
        It 'names the offending path so the operator can go fix it' {
            (@($res.ErrorPaths) -join ' ') | Should Match 'TouchedHosts_'
        }
        It 'still returns an EMPTY index - the point is that emptiness is now EXPLAINED' {
            # Before the fix this same empty index came back with no signal at all, and
            # the caller reported the host as "closed by something else".
            $res.Index.ContainsKey('WS-TOUCHED') | Should Be $false
        }
    } finally { $fs.Close(); $fs.Dispose() }
}

Describe 'Read-ReportsAuditTouchIndex - a missing root is a read failure, not an empty trail' {
    It 'a non-existent root reports an error rather than a confident zero' {
        $res = Invoke-Index -Root (Join-Path $script:Tmp 'does-not-exist') -Start (Get-Date).AddDays(-5) -End (Get-Date) -Want @('WS-A')
        ([int]$res.Errors -ge 1) | Should Be $true
    }
    It 'an EMPTY root string stays a plain no-op (no source configured is not an error)' {
        $res = Invoke-Index -Root '' -Start (Get-Date).AddDays(-5) -End (Get-Date) -Want @('WS-A')
        [int]$res.Errors | Should Be 0
    }
}

Describe 'the reader carries the error-bag contract its siblings use' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Raw

    # Keys are Errors/Messages, never 'Count' - a hashtable's real .Count property
    # shadows that key, which is why squadron-rollup documented it at :6993.
    It 'the bag does not use a Count key that .Count would shadow' {
        $fn = [regex]::Match($src, '(?s)function Read-ReportsAuditTouchIndex.*?\n\}').Value
        ($fn -match '\$readBag = @\{ Errors = 0; Messages =') | Should Be $true
        ($fn -match '\$readBag\.Count')                        | Should Be $false
    }
    # COMMENT LINES ARE STRIPPED FIRST. Without that this failed on its first run
    # against the explanatory comment inside the function, which quotes the very
    # patterns it is asserting are gone ("inside a bare `catch {}`"). Matching prose
    # that documents a fix as though it were the defect is a false positive this repo
    # has produced more than once.
    It 'no swallow survives in the reader (no bare catch, no SilentlyContinue walk)' {
        $fn   = [regex]::Match($src, '(?s)function Read-ReportsAuditTouchIndex.*?\n\}').Value
        $code = (($fn -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        ($code -match 'catch \{\}')                 | Should Be $false
        ($code -match 'catch \{ \$data = @\(\) \}') | Should Be $false
        # every walk now escalates so the bag can see the failure
        (@([regex]::Matches($code, '& \$addReadErr')).Count -ge 4) | Should Be $true
    }
    It 'scan-closure-proof carries readFailed out so the brief cannot quote it as fact' {
        ($src -match 'readErrors=\$proofReadErrors; readFailed=\$proofReadFailed') | Should Be $true
        ($src -match "Closure proof INCOMPLETE")                                   | Should Be $true
    }
}
