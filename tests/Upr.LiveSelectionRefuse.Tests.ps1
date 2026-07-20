# =============================================================================
#  Upr.LiveSelectionRefuse.Tests.ps1 - Pester 3.4 for UPR's fail-closed
#  "live uninstall requires an explicit operator selection" gate (loop 5).
#
#  UPR permanently removes software over WinRM. The worker's per-candidate
#  selection gate treats a $null RemoveSet as "remove every proven candidate"
#  (legacy remove-all). The DISPATCHER must therefore never reach a LIVE
#  fan-out with no selection: a non-UI or stale client that omits the checked-
#  row set could otherwise trigger a fleet-wide remove-all of every proven-EOL
#  product. Both uninstall dispatchers (manual-uninstall JanetWeb.upr.psm1
#  ~1653; report-uninstall ~1878) REFUSE a live wave with no selection and
#  return BEFORE any host job is built or dialed - dry-run may still preview.
#
#  Before loop 5 only the self-guard drop had a behavioral test; this critical
#  fail-closed refusal had none. These tests drive the real dispatcher with no
#  credential; the refusal returns before Build-Upr*HostJobs, so NO host is
#  contacted (unit scope). The report path is fed a tiny in-memory CSV with one
#  "Unsupported" plugin row so findings.Count>0 and the refuse gate is reached.
#
#  Run:  Invoke-Pester -Path .\tests\Upr.LiveSelectionRefuse.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

function Invoke-Upr([string]$aid, [hashtable]$p) {
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $mod { param($a, $pp, $em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
    @{ Result = $res; Events = @($evs) }
}
function Has-RefuseLog($o) {
    @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'error' -and $_.text -match 'Refused' }).Count -gt 0
}

Describe 'manual-uninstall REFUSES a live wave with no operator selection' {
    $o = Invoke-Upr 'manual-uninstall' @{ hosts = 'WS-REMOTE-777'; software = 'SomeApp'; dryrun = $false }
    It 'returns total=0 (no fan-out)' {
        [int]$o.Result.summary.total | Should Be 0
    }
    It 'surfaces a Refused error on the summary' {
        [string]$o.Result.summary.error | Should Match 'Refused'
    }
    It 'logs the refusal at error level' {
        (Has-RefuseLog $o) | Should Be $true
    }
}

Describe 'manual-uninstall DRY-RUN does not refuse (preview allowed); self-guard still applies' {
    # dry-run + self-only host: the refuse gate is bypassed (dry-run previews),
    # then the self-guard drops the dispatcher -> total 0, WITHOUT a refusal.
    $o = Invoke-Upr 'manual-uninstall' @{ hosts = '127.0.0.1'; software = 'SomeApp'; dryrun = $true }
    It 'does NOT emit the live-selection refusal in dry-run' {
        (Has-RefuseLog $o) | Should Be $false
    }
    It 'still short-circuits to total=0 via the self-guard (no host contact)' {
        [int]$o.Result.summary.total | Should Be 0
        @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }).Count -gt 0 | Should Be $true
    }
}

Describe 'report-uninstall REFUSES a live wave with no operator selection' {
    # Minimal CSV: one row whose Plugin Name matches the unsupported regex, so
    # Parse-CsvFinding yields >=1 finding and the dispatcher reaches the refuse
    # gate. The refusal returns before Build-UprHostJobs -> no host dialed.
    $csv = Join-Path ([System.IO.Path]::GetTempPath()) ('upr_refuse_' + [guid]::NewGuid().ToString('N') + '.csv')
    @(
        'Plugin,Plugin Name,IP Address,NetBIOS Name,DNS Name,Severity'
        '99001,Microsoft Silverlight Unsupported Application,10.20.30.40,WS-REMOTE-777,,High'
    ) -join "`r`n" | Set-Content -LiteralPath $csv -Encoding UTF8

    $o = Invoke-Upr 'report-uninstall' @{ report = $csv; dryrun = $false; hostclass = 'all' }

    It 'parsed at least one finding (reached the refuse gate, not the empty-report exit)' {
        # A refusal on the summary proves findings.Count>0 AND the live gate fired;
        # an empty parse would instead return total=0 with no error.
        [string]$o.Result.summary.error | Should Match 'Refused'
    }
    It 'returns total=0 (no fan-out)' {
        [int]$o.Result.summary.total | Should Be 0
    }
    It 'logs the refusal at error level' {
        (Has-RefuseLog $o) | Should Be $true
    }

    It 'cleanup temp csv' {
        Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
        $true | Should Be $true
    }
}
