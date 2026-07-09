# =============================================================================
#  C2c.TaskordTiers.Tests.ps1 - Pester 3.4 tests for the v1.8.0 TASKORD 26-0822
#  realignment: the tiered verdict (only QUARANTINE pillars predict quarantine;
#  AUDIT + INFO are advisory; Monitoring -> NOT ATTESTING), the display-tag map,
#  the OSVersion audit check, and the import AUDIT-rule aggregation + run-all tagging.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.TaskordTiers.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# Build a check row the way the probe emits them.
function New-Chk { param($Name, $Status, $Detail = '') [pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail } }

Describe 'C2C v1.8.0 - pillar tier map (Get-C2cPillarTier)' {
    It 'the 5 TASKORD quarantine rules are Quarantine tier' {
        & $cm { foreach ($p in 'Firewall','AntiMalware','Patches','Encryption','Vuln') { (Get-C2cPillarTier $p) | Should Be 'Quarantine' } }
    }
    It 'PkiRoots and OSVersion are Audit tier' {
        & $cm { (Get-C2cPillarTier 'PkiRoots') | Should Be 'Audit'; (Get-C2cPillarTier 'OSVersion') | Should Be 'Audit' }
    }
    It 'AppWhitelist / Agents / COAMS are Info tier' {
        & $cm { foreach ($p in 'AppWhitelist','Agents','COAMS') { (Get-C2cPillarTier $p) | Should Be 'Info' } }
    }
    It 'Monitoring is the Attest tier' {
        & $cm { (Get-C2cPillarTier 'Monitoring') | Should Be 'Attest' }
    }
}

Describe 'C2C v1.8.0 - display tag (Get-C2cDisplayTag): audit/info fails never render as [FAIL]' {
    It 'an Audit-tier FAIL renders AUDIT' { & $cm { (Get-C2cDisplayTag 'PkiRoots' 'FAIL') | Should Be 'AUDIT' } }
    It 'an Info-tier ERROR renders INFO'  { & $cm { (Get-C2cDisplayTag 'AppWhitelist' 'ERROR') | Should Be 'INFO' } }
    It 'a Quarantine-tier FAIL stays FAIL' { & $cm { (Get-C2cDisplayTag 'Firewall' 'FAIL') | Should Be 'FAIL' } }
    It 'a PASS is never rewritten' { & $cm { (Get-C2cDisplayTag 'PkiRoots' 'PASS') | Should Be 'PASS' } }
}

Describe 'C2C v1.8.0 - tiered verdict (Get-C2cVerdict)' {
    # New-Chk is a test-scope function; build the arrays here and pass them into module scope.
    $verdict = { param($checks) & $cm { param($c) Get-C2cVerdict -Checks $c } $checks }

    It 'all quarantine pillars pass -> READY (audit/info/EXT are advisory)' {
        $v = & $verdict @(
            (New-Chk 'Firewall' 'PASS'), (New-Chk 'AntiMalware' 'PASS'), (New-Chk 'Patches' 'PASS'),
            (New-Chk 'Encryption' 'PASS'), (New-Chk 'Vuln' 'EXT'), (New-Chk 'Monitoring' 'PASS'))
        $v.Status | Should Be 'READY'
        $v.Ok | Should Be $true
        $v.Detail | Should Match 'all quarantine pillars pass'
        $v.Detail | Should Match 'AQC/Vuln not endpoint-verifiable'
    }
    It 'a quarantine-tier FAIL (Firewall) -> QUARANTINE RISK' {
        $v = & $verdict @((New-Chk 'Firewall' 'FAIL' 'off'), (New-Chk 'Monitoring' 'PASS'))
        $v.Status | Should Be 'QUARANTINE RISK'
        $v.Ok | Should Be $false
        $v.Detail | Should Match 'FAIL: Firewall'
    }
    It 'PkiRoots FAIL alone (audit) does NOT quarantine -> READY with an AUDIT note' {
        $v = & $verdict @(
            (New-Chk 'Firewall' 'PASS'), (New-Chk 'AntiMalware' 'PASS'), (New-Chk 'Patches' 'PASS'),
            (New-Chk 'Encryption' 'PASS'), (New-Chk 'Monitoring' 'PASS'), (New-Chk 'PkiRoots' 'FAIL' '2 missing'))
        $v.Status | Should Be 'READY'
        $v.Detail | Should Match 'AUDIT: PkiRoots'
        # and the report tags it [AUDIT], never [FAIL]
        $v.Report | Should Match '\[AUDIT\] PkiRoots'
        $v.Report | Should Not Match '\[FAIL\] PkiRoots'
    }
    It 'AppWhitelist / Agents FAIL (info) do NOT quarantine -> READY with an INFO note' {
        $v = & $verdict @(
            (New-Chk 'Firewall' 'PASS'), (New-Chk 'AntiMalware' 'PASS'), (New-Chk 'Patches' 'PASS'),
            (New-Chk 'Encryption' 'PASS'), (New-Chk 'Monitoring' 'PASS'),
            (New-Chk 'AppWhitelist' 'FAIL'), (New-Chk 'Agents' 'FAIL'))
        $v.Status | Should Be 'READY'
        $v.Detail | Should Match 'INFO: AppWhitelist, Agents'
    }
    It 'only Monitoring failing -> NOT ATTESTING (distinct from QUARANTINE RISK)' {
        $v = & $verdict @(
            (New-Chk 'Firewall' 'PASS'), (New-Chk 'AntiMalware' 'PASS'), (New-Chk 'Patches' 'PASS'),
            (New-Chk 'Encryption' 'PASS'), (New-Chk 'Monitoring' 'FAIL' 'Tanium not installed'))
        $v.Status | Should Be 'NOT ATTESTING'
        $v.Ok | Should Be $false
        $v.Detail | Should Match 'cannot be attested'
    }
    It 'a real quarantine FAIL outranks a Monitoring failure -> QUARANTINE RISK' {
        $v = & $verdict @((New-Chk 'Encryption' 'FAIL'), (New-Chk 'Monitoring' 'FAIL'))
        $v.Status | Should Be 'QUARANTINE RISK'
    }
    It 'a quarantine-tier ERROR (no FAIL) -> CHECK ERRORS' {
        $v = & $verdict @((New-Chk 'Patches' 'ERROR' 'CCM not queryable'), (New-Chk 'Monitoring' 'PASS'))
        $v.Status | Should Be 'CHECK ERRORS'
    }
    It 'an AUDIT/INFO ERROR never demotes a compliant host to CHECK ERRORS' {
        $v = & $verdict @(
            (New-Chk 'Firewall' 'PASS'), (New-Chk 'AntiMalware' 'PASS'), (New-Chk 'Patches' 'PASS'),
            (New-Chk 'Encryption' 'PASS'), (New-Chk 'Monitoring' 'PASS'),
            (New-Chk 'AppWhitelist' 'ERROR'), (New-Chk 'OSVersion' 'ERROR'))
        $v.Status | Should Be 'READY'
    }
}

Describe 'C2C v1.8.0 - the verdict helpers survive pool-runspace isolation (no module scope)' {
    # The scan probe runs in a RunspacePool built from CreateDefault() with NO module
    # functions. The verdict helpers MUST be reachable there via $script:C2cVerdictSrc
    # injection - a plain module function would be absent and produce a blank verdict.
    It 'Get-C2cVerdict is callable in a fresh default runspace after dot-sourcing the source string' {
        $src = & $cm { $script:C2cVerdictSrc }
        $src | Should Not BeNullOrEmpty
        $rs = [runspacefactory]::CreateRunspace([System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault())
        $rs.Open()
        try {
            $ps = [powershell]::Create(); $ps.Runspace = $rs
            $script = $src + "`n" + 'Get-C2cVerdict -Checks @([pscustomobject]@{Name="PkiRoots";Status="FAIL";Detail="x"},[pscustomobject]@{Name="Encryption";Status="FAIL";Detail="off"},[pscustomobject]@{Name="Monitoring";Status="PASS"})'
            [void]$ps.AddScript($script)
            $out = @($ps.Invoke())
            $ps.HadErrors | Should Be $false
            $out[0].Status | Should Be 'QUARANTINE RISK'       # Encryption (quarantine) fails; PkiRoots (audit) does not
            $out[0].Report | Should Match '\[AUDIT\] PkiRoots'  # audit fail tagged, never [FAIL]
        } finally { $rs.Close() }
    }
}

Describe 'C2C v1.8.0 - import aggregates AUDIT-rule findings + tags run-all audit fixes' {
    # A tiny Tanium-style CSV (header ends in "Compliance" so the parser finds it): one host
    # non-compliant on Encryption (Failed) + missing PKI (Audit), one compliant host failing
    # the PKI audit only.
    $csv = @"
Computer Name,Compliance
WS-1,"Non-Compliant
Failed Rule - Endpoint Data At Rest Encryption
Audit Rule - PKI Trust Roots"
WS-2,"Compliant
Audit Rule - PKI Trust Roots"
"@
    # Drive the import action via pasted CSV text; capture the returned summary.
    $res = & $cm {
        param($text)
        $emit = { param($msg) }
        Invoke-JanetToolAction -ActionId 'import' -Params @{ csvText = $text } -Credential $null -Emit $emit
    } $csv
    $summary = $res.summary

    It 'PkiRoots shows up as an AUDIT pillar (both hosts), not a failed pillar' {
        $aud = @($summary.auditPillars | Where-Object { $_.name -eq 'PkiRoots' })[0]
        $aud | Should Not BeNullOrEmpty
        $aud.failedCount | Should Be 2
        $aud.audit | Should Be $true
        # PkiRoots must NOT appear in the (quarantine) failed pillars list
        @($summary.pillars | Where-Object { $_.name -eq 'PkiRoots' }).Count | Should Be 0
    }
    It 'run-all includes both hosts with PkiRoots tagged as an audit fix' {
        $ws2 = @($summary.runAllPlan | Where-Object { $_.host -eq 'WS-2' })[0]
        $ws2 | Should Not BeNullOrEmpty                 # compliant host still targetable for the audit fix
        @($ws2.pillars) -contains 'PkiRoots' | Should Be $true
        @($ws2.auditPillars) -contains 'PkiRoots' | Should Be $true
    }
    It 'the Encryption failure on WS-1 is still a (quarantine) failed pillar' {
        @($summary.pillars | Where-Object { $_.name -eq 'Encryption' }).Count | Should Be 1
    }
}
