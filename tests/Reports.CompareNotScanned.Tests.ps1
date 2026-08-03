# =============================================================================
#  Reports.CompareNotScanned.Tests.ps1 - a host that never appeared in the
#  comparison scan is NOT remediated.
#
#  THE DEFECT (loop 2026-08-03, P1): Compare-AcasScans classified REMEDIATED as
#  "this baseline key is not in the comparison", with the only demotion being a
#  cross-domain short-name collision. Nothing checked whether the HOST ITSELF
#  appeared in the comparison scan at all. A box powered off during the
#  after-patch window - or dropped by a scoped export - therefore had EVERY one
#  of its baseline findings scored REMEDIATED.
#
#  Unlike the other consumers of this data, that path MUTATES: acas-apply-remediated
#  stamps Status='Patched' / PatchedBy='Scan Comparison' on every REMEDIATED key,
#  so the fleet reads clean on evidence that was never collected. That is the
#  worst outcome this codebase can produce.
#
#  WHY IT SURVIVED: campaign-verify already guards exactly this with a NOT-SCANNED
#  bucket ("loop21 P1 ... would else FALSE-CLOSE"). The guard was written once and
#  never swept to the sibling that writes - the recurring failure mode in this
#  repo. These tests are BEHAVIOURAL and drive the real Compare-AcasScans.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.CompareNotScanned.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

function New-F([string]$HostName, [string]$PluginId, [string]$Ip = '') {
    [pscustomobject]@{
        Hostname = $HostName; PluginID = $PluginId; VulnName = "Vuln $PluginId"
        Severity = 'High'; Solution = 'Patch it'; Category = 'Other'
        CVE = ''; InKEV = $false; IP = $Ip
    }
}

# Drive the real Compare-AcasScans over seeded module-scope scan sets.
function Invoke-Compare($Baseline, $Comparison) {
    & $script:Mod {
        param($b, $c)
        $script:BaselineFindings   = $b
        $script:ComparisonFindings = $c
        Compare-AcasScans
    } $Baseline $Comparison
}

Describe 'Compare-AcasScans - an absent host is NOT SCANNED, never REMEDIATED' {

    # HOST-A was re-scanned and is genuinely clean of plugin 1001.
    # HOST-B never appears in the comparison scan at all (powered off / out of scope).
    $baseline = @(
        (New-F 'HOST-A' '1001' '10.0.0.1'),
        (New-F 'HOST-A' '1002' '10.0.0.1'),
        (New-F 'HOST-B' '1001' '10.0.0.2')
    )
    $comparison = @(
        (New-F 'HOST-A' '1002' '10.0.0.1')   # A still has 1002; A's 1001 is gone
    )
    $res = @(Invoke-Compare $baseline $comparison)

    It "HOST-A's cleared finding is REMEDIATED (the tool still does its job)" {
        $r = @($res | Where-Object { $_.Hostname -eq 'HOST-A' -and $_.PluginID -eq '1001' })
        @($r).Count      | Should Be 1
        [string]$r[0].Delta | Should Be 'REMEDIATED'
    }
    It "HOST-A's surviving finding is STILL OPEN" {
        $r = @($res | Where-Object { $_.Hostname -eq 'HOST-A' -and $_.PluginID -eq '1002' })
        [string]$r[0].Delta | Should Be 'STILL OPEN'
    }
    It 'HOST-B (absent from the comparison entirely) is NOT SCANNED, not REMEDIATED' {
        $r = @($res | Where-Object { $_.Hostname -eq 'HOST-B' })
        @($r).Count         | Should Be 1
        [string]$r[0].Delta | Should Be 'NOT SCANNED'
    }
    It 'no absent host leaks into the REMEDIATED set that apply-remediated writes from' {
        # acas-apply-remediated filters on Delta -eq 'REMEDIATED' (psm1:5938), so this
        # is the exact set that would be stamped Status='Patched'.
        $rem = @($res | Where-Object { $_.Delta -eq 'REMEDIATED' })
        @($rem | Where-Object { $_.Hostname -eq 'HOST-B' }).Count | Should Be 0
        @($rem).Count | Should Be 1
    }
}

Describe 'Compare-AcasScans - the whole-fleet false-close case' {

    # The scenario that motivated this: the after-patch scan covers only a SUBSET of
    # the baseline fleet. Every finding on every uncovered host used to come back
    # REMEDIATED and could then be stamped Patched.
    $baseline = @(
        (New-F 'WS-1' '2001' '10.0.1.1'), (New-F 'WS-1' '2002' '10.0.1.1'),
        (New-F 'WS-2' '2001' '10.0.1.2'), (New-F 'WS-2' '2002' '10.0.1.2'),
        (New-F 'WS-3' '2001' '10.0.1.3'), (New-F 'WS-3' '2002' '10.0.1.3')
    )
    # Only WS-1 was actually re-scanned, and it is still dirty on 2001.
    $comparison = @( (New-F 'WS-1' '2001' '10.0.1.1') )
    $res = @(Invoke-Compare $baseline $comparison)

    It 'the four findings on the two unscanned hosts are all NOT SCANNED' {
        $ns = @($res | Where-Object { $_.Delta -eq 'NOT SCANNED' })
        @($ns).Count | Should Be 4
        (@($ns | Where-Object { $_.Hostname -eq 'WS-2' }).Count) | Should Be 2
        (@($ns | Where-Object { $_.Hostname -eq 'WS-3' }).Count) | Should Be 2
    }
    It 'only the genuinely re-scanned host can produce a REMEDIATED row' {
        $rem = @($res | Where-Object { $_.Delta -eq 'REMEDIATED' })
        @($rem).Count            | Should Be 1
        [string]$rem[0].Hostname | Should Be 'WS-1'
        [string]$rem[0].PluginID | Should Be '2002'
    }
    It 'nothing is silently dropped - every baseline finding is still accounted for' {
        # 6 baseline findings in, 6 rows out (1 REMEDIATED + 1 STILL OPEN + 4 NOT SCANNED).
        @($res).Count | Should Be 6
    }
}

Describe 'Compare-AcasScans - the existing buckets still work' {

    It 'a finding only in the comparison is NEW' {
        $res = @(Invoke-Compare @( (New-F 'HOST-C' '3001' '10.0.2.1') ) `
                                @( (New-F 'HOST-C' '3001' '10.0.2.1'), (New-F 'HOST-C' '3002' '10.0.2.1') ))
        $r = @($res | Where-Object { $_.PluginID -eq '3002' })
        [string]$r[0].Delta | Should Be 'NEW'
    }

    # The collision demotion (loop39/40) must still beat REMEDIATED for a host that IS
    # present. NOT SCANNED is checked first only because "we never saw the box" is the
    # more fundamental of the two unknowns.
    It 'a cross-domain short-name collision is still AMBIGUOUS, not REMEDIATED' {
        $baseline   = @( (New-F 'web01.us.af.mil' '4001' '10.0.3.1') )
        $comparison = @( (New-F 'web01.eu.af.mil' '4002' '10.0.3.9') )
        $res = @(Invoke-Compare $baseline $comparison)
        $r = @($res | Where-Object { $_.PluginID -eq '4001' })
        [string]$r[0].Delta | Should Be 'AMBIGUOUS'
    }
}
