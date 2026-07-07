# =============================================================================
#  Server.SchedulePayload.Tests.ps1 - static-analysis Pester tests for the
#  off-hours scheduler's arm -> fire payload path (P2-2: an armed wave used to
#  fire with EMPTY params - no host list - because the frontend never sent a
#  'params' field on arm, so the poller fell back to a hard-coded '{}' body.
#  The engine then no-op'd / errored, yet the ledger read "fired ok").
#
#  These tests do NOT start a server and do NOT fire any wave. They AST-parse
#  Server.ps1 (must be error-free) and assert, via source-text checks, that:
#   - the arm route (POST /api/schedule) reads a 'params' field off the posted
#     body and persists it onto the stored schedule object, and
#   - the poller builds the fired request body FROM those stored params - the
#     literal '{}' body is only the guarded empty-params fallback, never an
#     unconditional/hard-coded body.
#   - a fired wave's ledger note distinguishes success/failure by HTTP status
#     (acceptance-vs-outcome), not just a bare "fired" string.
#
#  Run:  Invoke-Pester -Path .\tests\Server.SchedulePayload.Tests.ps1
# =============================================================================
$script:Root       = Split-Path $PSScriptRoot -Parent
$script:ServerPath = Join-Path $script:Root 'server\JanetWeb.Server.ps1'

Describe 'Scheduler arm/fire payload (P2-2 no-empty-params fix)' {

    $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw

    It 'Server.ps1 exists' {
        Test-Path -LiteralPath $script:ServerPath | Should Be $true
    }

    It 'Server.ps1 parses with zero AST errors' {
        $tokens = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$tokens, [ref]$errs)
        $errs.Count | Should Be 0
    }

    It 'the arm route (POST /api/schedule) reads a params field off the posted body' {
        $script:Src.Contains("sbody['params']") | Should Be $true
    }

    It 'the arm route persists the parsed params onto the stored schedule object' {
        $script:Src.Contains('$sParams = @{}') | Should Be $true
        $script:Src.Contains('params = $sParams') | Should Be $true
    }

    It 'the poller builds the fired request body FROM the stored params' {
        $script:Src.Contains('if ($o.params) { foreach ($pp in $o.params.PSObject.Properties)') | Should Be $true
    }

    It "the poller's '{}' body is only a guarded empty-params fallback, never unconditional" {
        # The pre-fix defect was an unconditional/hard-coded '{}' body. The fixed
        # line must gate it behind "$bodyObj.Count -gt 0 ... else { '{}' }" so an
        # armed wave with real params never gets flattened to an empty body.
        $script:Src.Contains("`$bodyJson = if (`$bodyObj.Count -gt 0) { `$bodyObj | ConvertTo-Json -Depth 6 -Compress } else { '{}' }") | Should Be $true
        # and there must be no OTHER assignment that hard-codes '{}' as $bodyJson
        # unconditionally (the pre-fix defect) - only the guarded form above.
        $script:Src.Contains('$bodyJson = ''{}''') | Should Be $false
    }

    It 'a fired wave records the actual HTTP status in the ledger note (acceptance-vs-outcome)' {
        $script:Src.Contains('fired ok (HTTP $code') | Should Be $true
        $script:Src.Contains('fire failed (HTTP $code)') | Should Be $true
        $script:Src.Contains("`$o.status = 'blocked'") | Should Be $true
        $script:Src.Contains("`$o.status = 'error'") | Should Be $true
    }

    It 'the frontend arm click sends a params snapshot (not an empty arm POST)' {
        $shellPath = Join-Path $script:Root 'web\js\shell.js'
        Test-Path -LiteralPath $shellPath | Should Be $true
        $shellSrc = Get-Content -LiteralPath $shellPath -Raw
        # the /schedule POST body must include a params field
        $shellSrc | Should Match "api\('POST', '/schedule',\s*\{[^}]*params:\s*armParams"
    }
}

Describe 'Scheduler arm gate + recurrence (P2 operating-model fixes)' {

    $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw

    # --- FIX (P2-a): arming ANY wave requires the admin session, not just destructive ---
    It 'the arm gate no longer keys on $sDestructive (any wave needs the admin session)' {
        # the old destructive-ONLY arm gate + its message must be gone...
        $script:Src.Contains("if (`$sDestructive -and -not (`$state.AckGiven -and `$null -ne `$state.Cred)) {") | Should Be $false
        $script:Src.Contains('Admin session required to arm a destructive wave') | Should Be $false
    }
    It 'the arm route gates any wave on the live admin session (ack + cred)' {
        $script:Src.Contains("if (-not (`$state.AckGiven -and `$null -ne `$state.Cred)) {") | Should Be $true
        $script:Src.Contains('Admin session required to arm a schedule') | Should Be $true
    }

    # --- FIX (P2-b): non-destructive waves are one-shot (no standing scan automation) ---
    It 'a non-destructive wave with recurrence != none is rejected (400)' {
        $script:Src.Contains("if (-not `$sDestructive -and `$rec -ne 'none') {") | Should Be $true
        $script:Src.Contains('non-destructive waves are one-shot') | Should Be $true
    }
    It 'destructive recurrence (daily/weekly) is still allowed to advance in the poller' {
        # unchanged fail-safe: a destructive recurrence re-arms only when it fires OK,
        # and the fire route still 403s without a live session.
        $script:Src.Contains("([string]`$o.recurrence) -eq 'daily' -or ([string]`$o.recurrence) -eq 'weekly'") | Should Be $true
    }
}

Describe 'API auth: query-string token scoped to the beacon-cancel route (P3 hardening)' {

    $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw

    It 'no longer accepts ?t= unconditionally on every /api/* route' {
        # the old unconditional fallback ("$tok = $req.QueryString['t']" for any empty
        # header) must be gone.
        $script:Src.Contains("if ([string]::IsNullOrEmpty(`$tok)) { `$tok = `$req.QueryString['t'] }") | Should Be $false
    }
    It 'accepts ?t= ONLY on POST /api/job/<id>/cancel (sendBeacon can''t set headers)' {
        $script:Src.Contains("if ([string]::IsNullOrEmpty(`$tok) -and `$verb -eq 'POST' -and `$path -match '^/api/job/[^/]+/cancel`$') { `$tok = `$req.QueryString['t'] }") | Should Be $true
    }
    It 'the constant-time header/token compare is preserved' {
        $script:Src.Contains('$d = 0; for ($ti = 0; $ti -lt $Token.Length; $ti++)') | Should Be $true
    }
}
