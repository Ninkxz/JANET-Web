# =============================================================================
#  Reports.HostSummaryBuckets.Tests.ps1 - Pester 3.4 for the audit 2026-07-24
#  acas-host-summary bucket-partition fix (reports v2.15.1).
#
#  The dashboard tallied Patched and NOT-OUR-PATCH with two SEPARATE `if`s, which
#  are not mutually exclusive: acas-apply-remediated flips a finding to Patched
#  WITHOUT inspecting Category, so one finding could be counted in BOTH buckets.
#  The arithmetic beneath assumed the buckets partitioned the set
#  (Open = Total - Patched - NotOurs, denominator = Total - NotOurs), so Open went
#  NEGATIVE and PatchRate was overstated (200% on the seed below).
#
#  Each finding is now classified into exactly ONE bucket - Patched winning over
#  NOT OUR PATCH, the same precedence sla-aging uses when it skips - and Open /
#  the actionable denominator are read FROM the counters.
#
#  acas-host-summary returns rows=@() (its grid rows are streamed as 'row' events),
#  so these tests collect the emitted rows. Read-only over a seeded
#  $script:AcasFindings; no host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.HostSummaryBuckets.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'acas-host-summary: overlapping Patched + NOT OUR PATCH no longer double-counts (audit 2026-07-24)' {

    # H1: the concrete audit path. Two findings were triaged NOT OUR PATCH and then
    #     flipped to Patched by acas-apply-remediated (which never looks at Category),
    #     one is plain Open, one is a pure NOT-OUR-PATCH triage verdict on Status.
    #     Old math: Patched=2, NotOurs=3, Open=4-2-3=-1, denom=4-3=1 -> PatchRate 200%.
    # H2: no overlap at all, but the NOT-OUR-PATCH verdict lives on Status (where
    #     acas-mark-status writes it), which the old Category-only test missed.
    $rows = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='h1'; PluginID='1'; VulnName='Vendor EOL, then auto-closed'; Severity='High';     CVE='CVE-2024-1001'; Category='NOT OUR PATCH'; Status='Patched';       Solution='Vendor.';  InKEV=$false; KevCves=''; IAVA=''; PatchedBy='Scan Comparison' }
            [pscustomobject]@{ Hostname='h1'; PluginID='2'; VulnName='Vendor EOL, then auto-closed'; Severity='Medium';   CVE='CVE-2024-1002'; Category='NOT OUR PATCH'; Status='Patched';       Solution='Vendor.';  InKEV=$false; KevCves=''; IAVA=''; PatchedBy='Scan Comparison' }
            [pscustomobject]@{ Hostname='h1'; PluginID='3'; VulnName='Still open KB';                Severity='Critical'; CVE='CVE-2024-1003'; Category='KB Patch';      Status='Open';          Solution='Patch.';   InKEV=$false; KevCves=''; IAVA=''; PatchedBy='' }
            [pscustomobject]@{ Hostname='h1'; PluginID='4'; VulnName='Not ours';                     Severity='Low';      CVE='CVE-2024-1004'; Category='NOT OUR PATCH'; Status='NOT OUR PATCH'; Solution='Vendor.';  InKEV=$false; KevCves=''; IAVA=''; PatchedBy='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='5'; VulnName='Not ours (Status only)';       Severity='High';     CVE='CVE-2024-2001'; Category='KB Patch';      Status='NOT OUR PATCH'; Solution='Vendor.';  InKEV=$false; KevCves=''; IAVA=''; PatchedBy='' }
            [pscustomobject]@{ Hostname='h2'; PluginID='6'; VulnName='Still open KB';                Severity='Medium';   CVE='CVE-2024-2002'; Category='KB Patch';      Status='Open';          Solution='Patch.';   InKEV=$false; KevCves=''; IAVA=''; PatchedBy='' }
        )
        $collected = New-Object System.Collections.ArrayList
        [void](Invoke-JanetToolAction -ActionId 'acas-host-summary' -Params @{} -Emit { param($e) if ($e.type -eq 'row') { [void]$collected.Add($e) } })
        ,@($collected.ToArray())
    }
    $h1 = @($rows | Where-Object { $_.Host -eq 'H1' })[0]
    $h2 = @($rows | Where-Object { $_.Host -eq 'H2' })[0]

    It 'emits one row per normalized host' {
        @($rows).Count | Should Be 2
        ($h1 -ne $null) | Should Be $true
        ($h2 -ne $null) | Should Be $true
    }

    It 'Open is never NEGATIVE for a host with Patched + NOT-OUR-PATCH overlap (was -1)' {
        ([int]$h1.Open -ge 0) | Should Be $true
        [int]$h1.Open | Should Be 1        # only plugin 3 is actionable-open
    }

    It 'counts the overlapping finding ONCE - Patched wins, NotOurs does not re-count it' {
        [int]$h1.TotalVulns | Should Be 4
        [int]$h1.Patched    | Should Be 2  # plugins 1 + 2
        [int]$h1.NotOurs    | Should Be 1  # plugin 4 only (was 3 - it re-counted 1 + 2)
    }

    It 'the three buckets partition the host total (Patched + Open + NotOurs = Total)' {
        ([int]$h1.Patched + [int]$h1.Open + [int]$h1.NotOurs) | Should Be ([int]$h1.TotalVulns)
        ([int]$h2.Patched + [int]$h2.Open + [int]$h2.NotOurs) | Should Be ([int]$h2.TotalVulns)
    }

    It 'PatchRate uses the actionable denominator Patched + Open and cannot exceed 100% (was 200%)' {
        $h1.PatchRate | Should Be '67%'    # 2 patched of 3 actionable (2 + 1 open)
    }

    It 'a NOT-OUR-PATCH verdict on Status is bucketed too (the old test only read Category)' {
        [int]$h2.TotalVulns | Should Be 2
        [int]$h2.NotOurs    | Should Be 1  # plugin 5 - Status='NOT OUR PATCH', Category='KB Patch'
        [int]$h2.Open       | Should Be 1  # was 2
        [int]$h2.Patched    | Should Be 0
        $h2.PatchRate       | Should Be '0%'
    }
}

Describe 'acas-host-summary: the clean non-overlapping case is unchanged (regression guard)' {

    $clean = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='c1'; PluginID='1'; VulnName='Fixed';    Severity='High';     CVE='CVE-2024-3001'; Category='KB Patch';      Status='Patched'; Solution='Patch.'; InKEV=$false; KevCves=''; IAVA=''; PatchedBy='op' }
            [pscustomobject]@{ Hostname='c1'; PluginID='2'; VulnName='Open';     Severity='Critical'; CVE='CVE-2024-3002'; Category='KB Patch';      Status='Open';    Solution='Patch.'; InKEV=$true;  KevCves='CVE-2024-3002'; IAVA=''; PatchedBy='' }
            [pscustomobject]@{ Hostname='c1'; PluginID='3'; VulnName='Not ours'; Severity='Low';      CVE='CVE-2024-3003'; Category='NOT OUR PATCH'; Status='Open';    Solution='Vendor.'; InKEV=$false; KevCves=''; IAVA=''; PatchedBy='' }
        )
        $collected = New-Object System.Collections.ArrayList
        [void](Invoke-JanetToolAction -ActionId 'acas-host-summary' -Params @{} -Emit { param($e) if ($e.type -eq 'row') { [void]$collected.Add($e) } })
        ,@($collected.ToArray())
    }
    $c1 = @($clean | Where-Object { $_.Host -eq 'C1' })[0]

    It 'tallies 1 Patched / 1 Open / 1 NotOurs with a 50% rate, exactly as before the fix' {
        [int]$c1.TotalVulns | Should Be 3
        [int]$c1.Patched    | Should Be 1
        [int]$c1.Open       | Should Be 1
        [int]$c1.NotOurs    | Should Be 1
        $c1.PatchRate       | Should Be '50%'
    }

    It 'still flags the KEV finding on the host' {
        [int]$c1.Kev | Should Be 1
    }
}
