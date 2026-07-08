# =============================================================================
#  C2c.ImportAndFix.Tests.ps1 - Pester 3.4 tests for the C2C action side
#  (v1.4.0): the Tanium "C2C Compliance Status" CSV IMPORT parser (incl. the
#  runAllPlan) and the destructive PER-PILLAR fix guards (fix-monitoring /
#  fix-firewall / fix-antimalware / fix-pki, etc.).
#
#  All tests exercise the PUBLIC contract (Invoke-JanetToolAction) so no
#  internal helper is shimmed and NO WinRM call ever leaves this box:
#    * import   - local parse only (no remote).
#    * fix-*    - every negative case is refused BEFORE any host is dialed
#                 (confirm-word, PKI-without-sst, junk targets), and the
#                 self-guard case only supplies dispatcher-local targets so the
#                 run short-circuits with zero fan-out.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.ImportAndFix.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

$null = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force

# Collect the emitted 'row' events + return the action result.
function Invoke-C2cAction {
    param([string]$ActionId, [hashtable]$Params, $Cred = $null)
    $script:__rows = New-Object System.Collections.ArrayList
    $emit = { param($e) if ($e -and $e.type -eq 'row') { [void]$script:__rows.Add($e) } }
    $res = Invoke-JanetToolAction -ActionId $ActionId -Params $Params -Credential $Cred -Emit $emit
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows) }
}

function New-C2cTempCsv {
    param([string]$Content)
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_test_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $p -Value $Content -Encoding UTF8
    return $p
}

# -----------------------------------------------------------------------------
Describe 'C2C import - Tanium Compliance CSV parsing' {

    # HOSTA appears twice (worst row = Non-Compliant must win over Compliant).
    # HOSTA carries numbered rule variants + an Audit rule + an unknown rule.
    $csvBody = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
"Non-Compliant
Failed Rule 3 - Bitlocker
Failed Rule 2 - MDE Health
Audit Rule - PKI Trust Roots
Failed Rule 7 - Some Unknown Rule",,,HOSTA.area52.afnoapps.usaf.mil,1
Compliant,,,HOSTA.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Vulnerability Compliance",,,HOSTB.area52.afnoapps.usaf.mil,1
Compliant,,,HOSTC.area52.afnoapps.usaf.mil,1
"@
    $csv = New-C2cTempCsv $csvBody
    $out = Invoke-C2cAction -ActionId 'import' -Params @{ csvPath = $csv }
    $summary = $out.Result.summary
    $rows    = $out.Rows
    $hostA   = @($rows | Where-Object { $_.Host -eq 'HOSTA' })[0]
    $hostB   = @($rows | Where-Object { $_.Host -eq 'HOSTB' })[0]

    It 'de-duplicates by host and keeps the worst row (Non-Compliant over Compliant)' {
        @($rows | Where-Object { $_.Host -eq 'HOSTA' }).Count | Should Be 1
        $hostA.Compliance | Should Be 'Non-Compliant'
    }

    It 'resolves the FQDN to the short host name' {
        $hostA.Fqdn | Should Be 'HOSTA.area52.afnoapps.usaf.mil'
        $hostA.Host | Should Be 'HOSTA'
    }

    It 'maps NUMBERED rule variants to canonical pillars (Failed Rule 3 - Bitlocker -> Encryption; Failed Rule 2 - MDE Health -> AntiMalware)' {
        $hostA.Failed | Should Match 'Encryption'
        $hostA.Failed | Should Match 'AntiMalware'
    }

    It 'separates Failed rules from Audit rules (PKI Trust Roots Audit rule -> Audit column, not Failed)' {
        $hostA.Audit  | Should Match 'PkiRoots'
        $hostA.Failed | Should Not Match 'PkiRoots'
    }

    It 'surfaces an UNKNOWN rule name verbatim (never silently dropped)' {
        $hostA.Failed | Should Match 'Some Unknown Rule'
        $names = @($summary.pillars | ForEach-Object { $_.name })
        ($names -contains 'Some Unknown Rule') | Should Be $true
        $unk = @($summary.pillars | Where-Object { $_.name -eq 'Some Unknown Rule' })[0]
        $unk.routing | Should Be 'review manually'
    }

    It 'maps the Vulnerability Compliance rule to the Vuln pillar routed off-tool' {
        $hostB.Failed | Should Match 'Vuln'
        $vuln = @($summary.pillars | Where-Object { $_.name -eq 'Vuln' })[0]
        $vuln.routing | Should Match 'ACAS'
    }

    It 'tallies compliant / non-compliant correctly' {
        $summary.total        | Should Be 3
        $summary.nonCompliant | Should Be 2
        $summary.compliant    | Should Be 1
    }

    It 'returns per-pillar host lists so the view can load them into targets' {
        $enc = @($summary.pillars | Where-Object { $_.name -eq 'Encryption' })[0]
        @($enc.hosts) -contains 'HOSTA' | Should Be $true
        $enc.failedCount | Should Be 1
    }

    It 'emits a runAllPlan of each host + ONLY its endpoint-fixable failed pillars (verbatim for run-all)' {
        $plan = @($summary.runAllPlan)
        # HOSTA has fixable failed pillars (Encryption + AntiMalware); HOSTB fails only
        # Vuln (routes off-tool) so it is omitted; the unknown rule is not fixable either.
        $plan.Count | Should Be 1
        $pa = @($plan | Where-Object { $_.host -eq 'HOSTA' })[0]
        $pa | Should Not BeNullOrEmpty
        @($pa.pillars) -contains 'Encryption'  | Should Be $true
        @($pa.pillars) -contains 'AntiMalware' | Should Be $true
        @($pa.pillars) -contains 'Vuln'        | Should Be $false
        @($plan | Where-Object { $_.host -eq 'HOSTB' }).Count | Should Be 0
    }

    # Pester 3.4 runs the Describe body top-to-bottom, so this cleanup fires after
    # the It blocks above (which already parsed the fixture).
    Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar fix - confirm-word gate' {

    It 'REJECTS the run when the confirm word is not exactly FIX (nothing changed)' {
        $out = Invoke-C2cAction -ActionId 'fix-monitoring' -Params @{ targets = 'WS-0001'; confirm = 'nope' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }

    It 'REJECTS a lower-case "fix" (case-sensitive, exact word)' {
        $out = Invoke-C2cAction -ActionId 'fix-firewall' -Params @{ targets = 'WS-0001'; confirm = 'fix' }
        $out.Result.summary.rejected | Should Be $true
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar fix - self-guard drops the dispatcher host' {

    It 'drops local host targets with a SKIPPED row and never fans out' {
        # Only dispatcher-local targets -> after the self-guard drop there is nothing
        # to run, so the action short-circuits with zero WinRM fan-out.
        $out = Invoke-C2cAction -ActionId 'fix-antimalware' -Params @{
            targets = ("{0}`n127.0.0.1`nlocalhost" -f $env:COMPUTERNAME)
            confirm = 'FIX'
        }
        $skips = @($out.Rows | Where-Object { $_.Status -eq 'SKIPPED' })
        $skips.Count | Should Not Be 0
        ($skips[0].Detail) | Should Match 'self-guard'
        $out.Result.summary.selfSkipped | Should Not Be 0
        $out.Result.summary.total | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C fix-pki - PKI roots require a valid .sst' {

    It 'REFUSES fix-pki with no .sst attached (before any host is dialed)' {
        $out = Invoke-C2cAction -ActionId 'fix-pki' -Params @{ targets = 'WS-0001'; confirm = 'FIX' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }

    It 'REFUSES fix-pki when the .sst does not load as a certificate bundle' {
        $bogus = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_bogus_{0}.sst" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $bogus -Value 'this is not a certificate store' -Encoding UTF8
        try {
            $out = Invoke-C2cAction -ActionId 'fix-pki' -Params @{ targets = 'WS-0001'; confirm = 'FIX'; sstPath = $bogus }
            $out.Result.summary.rejected | Should Be $true
        } finally { Remove-Item -LiteralPath $bogus -Force -ErrorAction SilentlyContinue }
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar fix - target token regex rejects junk' {

    It 'refuses a run whose targets are all UNC/URL/leading-hyphen junk (0 valid, no fan-out)' {
        $out = Invoke-C2cAction -ActionId 'fix-monitoring' -Params @{
            targets = "\\evil\share`n../etc/passwd`n-badname`nhttp://x/y"
            confirm = 'FIX'
        }
        $out.Result.summary.total | Should Be 0
        @($out.Rows).Count | Should Be 0
    }

    It 'requires the exact confirm word even when targets are junk (confirm gate is first)' {
        $out = Invoke-C2cAction -ActionId 'fix-monitoring' -Params @{ targets = '\\evil\share'; confirm = 'no' }
        $out.Result.summary.rejected | Should Be $true
    }
}
