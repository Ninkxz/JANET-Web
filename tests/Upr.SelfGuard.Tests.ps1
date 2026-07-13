# =============================================================================
#  Upr.SelfGuard.Tests.ps1 - Pester 3.4 for the UPR dispatcher self-guard
#  (loop22, ledger row 13). UPR's uninstall actions (report-uninstall /
#  manual-uninstall) PERMANENTLY remove software from each target over WinRM. The
#  DNS-mismatch guard stops acting on the WRONG remote host, but nothing stopped an
#  operator from listing the JANET dispatcher itself (correct DNS) - the uninstall
#  would then strip software from the box this HttpListener runs on. The self-guard
#  now drops self from the uninstall wave BEFORE fan-out; the read-only SCAN stays
#  self-inclusive.
#
#  The self-guard short-circuits (returns total=0) BEFORE Invoke-UprFanOut, so a
#  self-only uninstall makes NO host contact - unit scope only.
#
#  Run:  Invoke-Pester -Path .\tests\Upr.SelfGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

Describe 'upr Test-UprHostIsSelf predicate' {
    It 'flags the loopback literal as self' {
        (& $mod { Test-UprHostIsSelf '127.0.0.1' }) | Should Be $true
    }
    It 'flags this dispatcher shortname as self' {
        (& $mod { param($h) Test-UprHostIsSelf $h } $env:COMPUTERNAME) | Should Be $true
    }
    It 'does NOT flag an obviously-remote host (no over-drop)' {
        (& $mod { Test-UprHostIsSelf 'WS-REMOTE-999' }) | Should Be $false
    }
}

Describe 'upr uninstall self-guard drops the dispatcher before fan-out (loop22, ledger 13)' {
    function Invoke-Upr([string]$aid, [hashtable]$p) {
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $mod { param($a, $pp, $em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
        @{ Result = $res; Events = @($evs) }
    }

    It 'manual-uninstall self-only (dry-run) -> total=0 with a Self-guard warn, no fan-out' {
        $o = Invoke-Upr 'manual-uninstall' @{ hosts = '127.0.0.1'; software = 'SomeApp'; dryrun = $true }
        [int]$o.Result.summary.total | Should Be 0
        ($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }) | Should Not BeNullOrEmpty
    }
}
