# =============================================================================
#  Acas.FanOutHint.Tests.ps1 - loop71 (informative-failures theme). Invoke-AcasFanOut
#  now runs a failed host's raw worker result through Get-JanetTroubleshootHint and
#  attaches the actionable hint to the row (Hint field) + an err log (FIX:), with the
#  raw result preserved. Drives the REAL fan-out with a synthetic failing $Work
#  (a runspace returns the canned FAIL string) - no host contact.
#  Run:  Invoke-Pester -Path .\tests\Acas.FanOutHint.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

Describe 'acas 1.11.13 - fan-out attaches a troubleshooting hint to a failed host' {
    It 'manifest version is at or past 1.11.13 (fan-out hint; exact pin migrated to the newest bump)' {
        ([version][string](& $m { Get-JanetToolManifest }).version -ge [version]'1.11.13') | Should Be $true
    }
    It 'a failed worker result -> Hint row field + err-log FIX line; raw result preserved' {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $null = & $m {
            param($snd)
            Invoke-AcasFanOut `
                -Jobs @([pscustomobject]@{ Host = 'WS-1'; Context = @{}; Args = @() }) `
                -Work { 'FAIL: Connecting to remote server WS-1 failed: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY' } `
                -Threads 1 `
                -RowOf { param($r, $h, $c) @{ Host = $h; Status = [string]$r } } `
                -OkOf { param($r) [bool]([string]$r -notmatch '^(FAIL|SKIP)') } `
                -AuditAction 'TouchHost' `
                -AuditDetailOf { param($r, $h, $c) [string]$r } `
                -Send $snd `
                -CancelCheck { $false }
        } $send

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status | Should Match '0x80090351'            # raw result preserved
        [string]$row.Hint   | Should Match 'TrustedHosts|realm|CAC' # actionable hint attached
        $errLog = @($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'FIX:' })
        $errLog.Count | Should BeGreaterThan 0
        # the per-host audit still fires as Failure (unchanged)
        $audit = @($events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'WS-1' })[0]
        [string]$audit.result | Should Be 'Failure'
    }
    It 'a successful worker result gets NO hint and NO extra err log (only failures)' {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $null = & $m {
            param($snd)
            Invoke-AcasFanOut `
                -Jobs @([pscustomobject]@{ Host = 'WS-2'; Context = @{}; Args = @() }) `
                -Work { 'OK (patched)' } `
                -Threads 1 `
                -RowOf { param($r, $h, $c) @{ Host = $h; Status = [string]$r } } `
                -OkOf { param($r) [bool]([string]$r -notmatch '^(FAIL|SKIP)') } `
                -AuditAction 'TouchHost' `
                -AuditDetailOf { param($r, $h, $c) [string]$r } `
                -Send $snd `
                -CancelCheck { $false }
        } $send

        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Hint | Should Be ''
        @($events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'FIX:' }).Count | Should Be 0
    }
}
