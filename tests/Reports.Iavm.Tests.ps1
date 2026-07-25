# =============================================================================
#  Reports.Iavm.Tests.ps1 - Pester 3.4 tests for iavm-board: DoD compliance
#  rollup BY IAVA/IAVM bulletin. Groups the OPEN (not Patched) findings by their
#  IAVA tag, counts blank-IAVA findings separately, and ranks KEV-first.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'iavm-board: compliance rollup by IAVA bulletin' {

    $result = & $script:Mod {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='1'; VulnName='Bulletin A vuln'; Severity='High';     CVE='CVE-2024-1111'; Category='KB Patch'; Status='Open';    Solution='Patch it.'; InKEV=$true;  KevCves='CVE-2024-1111'; IAVA='2024-A-0001' }
            [pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Bulletin A vuln'; Severity='Critical'; CVE='CVE-2024-2222'; Category='KB Patch'; Status='Open';    Solution='Patch it.'; InKEV=$false; KevCves='';            IAVA='2024-A-0001' }
            [pscustomobject]@{ Hostname='hC'; PluginID='3'; VulnName='Bulletin B vuln'; Severity='Medium';   CVE='CVE-2024-3333'; Category='Chrome';   Status='Open';    Solution='Upgrade.'; InKEV=$false; KevCves='';            IAVA='2024-B-0002' }
            [pscustomobject]@{ Hostname='hD'; PluginID='4'; VulnName='No bulletin';     Severity='Low';      CVE='';              Category='Info';     Status='Open';    Solution='n/a.';     InKEV=$false; KevCves='';            IAVA='' }
            [pscustomobject]@{ Hostname='hE'; PluginID='5'; VulnName='Already fixed';   Severity='Critical'; CVE='CVE-2024-9999'; Category='KB Patch'; Status='Patched'; Solution='Done.';    InKEV=$true;  KevCves='CVE-2024-9999'; IAVA='2024-A-0001' }
        )
        Invoke-JanetToolAction -ActionId 'iavm-board' -Params @{} -Emit { param($e) }
    }

    It 'groups OPEN findings by IAVA and counts distinct bulletins + hosts (Patched excluded)' {
        [int]$result.summary.total            | Should Be 2   # 2024-A-0001, 2024-B-0002 (Patched hE excluded)
        [int]$result.summary.hosts            | Should Be 3   # hA, hB, hC (hD has no IAVA, hE Patched)
        [int]$result.summary.findingsWithIava | Should Be 3   # hA, hB, hC
    }

    It 'counts blank-IAVA findings separately (not grouped)' {
        [int]$result.summary.findingsNoIava | Should Be 1   # hD only (hE Patched is not counted at all)
    }

    It 'excludes Patched findings from every tally' {
        # hE is Patched under 2024-A-0001; bulletin A must show only 2 hosts / 2 findings.
        $a = @($result.rows | Where-Object { $_.IAVA -eq '2024-A-0001' })[0]
        [int]$a.Hosts    | Should Be 2
        [int]$a.Findings | Should Be 2
    }

    It 'flags the KEV-carrying bulletin and orders it first (KEV, then most hosts)' {
        [int]$result.summary.kevIavas | Should Be 1
        @($result.rows)[0].IAVA | Should Be '2024-A-0001'
        @($result.rows)[0].KEV  | Should Be 'KEV'
        [int](@($result.rows)[0].Hosts) | Should Be 2
    }

    It 'reports the worst severity per bulletin and samples the CVEs' {
        $a = @($result.rows | Where-Object { $_.IAVA -eq '2024-A-0001' })[0]
        $a.Severity | Should Be 'Critical'   # hB Critical beats hA High
        $a.CVEs | Should Match 'CVE-2024-1111'
        $a.CVEs | Should Match 'CVE-2024-2222'
    }
}

# =============================================================================
#  audit 2026-07-24: the IAVA cell is MULTI-VALUE - Get-ReportsIavmTags joins every
#  bulletin a finding's CVEs map to with ', '. iavm-board grouped on that RAW string,
#  so a two-bulletin finding minted a phantom compound bucket ("2021-A-0573,
#  2022-A-0221") and was counted under NEITHER real bulletin. These tests FAIL on
#  the old behaviour.
# =============================================================================
Describe 'iavm-board: a multi-bulletin finding counts under EVERY bulletin (audit 2026-07-24)' {

    $multi = & $script:Mod {
        $script:AcasFindings = @(
            # one finding, two mapped bulletins (as the IAVM tagger emits them)
            [pscustomobject]@{ Hostname='mh1'; PluginID='11'; VulnName='Two-bulletin vuln'; Severity='High';     CVE='CVE-2021-4444, CVE-2022-5555'; Category='KB Patch'; Status='Open'; Solution='Patch.'; InKEV=$true;  KevCves='CVE-2021-4444'; IAVA='2021-A-0573, 2022-A-0221' }
            # a second, single-bulletin finding on the SAME first bulletin, different host
            [pscustomobject]@{ Hostname='mh2'; PluginID='12'; VulnName='Single-bulletin vuln'; Severity='Critical'; CVE='CVE-2021-4444';               Category='KB Patch'; Status='Open'; Solution='Patch.'; InKEV=$false; KevCves='';              IAVA='2021-A-0573' }
        )
        Invoke-JanetToolAction -ActionId 'iavm-board' -Params @{} -Emit { param($e) }
    }

    It 'never emits a compound bucket named after the joined cell' {
        @($multi.rows | Where-Object { $_.IAVA -match ',' }).Count | Should Be 0
    }

    It 'splits into the two REAL bulletins (was 2 buckets: one compound + one real)' {
        [int]$multi.summary.total | Should Be 2
        @($multi.rows | Where-Object { $_.IAVA -eq '2021-A-0573' }).Count | Should Be 1
        @($multi.rows | Where-Object { $_.IAVA -eq '2022-A-0221' }).Count | Should Be 1
    }

    It 'credits the shared bulletin with BOTH findings and BOTH hosts' {
        $b = @($multi.rows | Where-Object { $_.IAVA -eq '2021-A-0573' })[0]
        [int]$b.Findings | Should Be 2   # was 1 - the multi-bulletin finding fell into the phantom bucket
        [int]$b.Hosts    | Should Be 2   # was 1
    }

    It 'credits the second bulletin with the same finding (it is in both)' {
        $b = @($multi.rows | Where-Object { $_.IAVA -eq '2022-A-0221' })[0]
        [int]$b.Findings | Should Be 1
        [int]$b.Hosts    | Should Be 1
        $b.KEV | Should Be 'KEV'         # the KEV flag rides along to both bulletins
    }

    It 'still counts FINDINGS (not bulletin memberships) in the with/no-IAVA pair' {
        [int]$multi.summary.findingsWithIava | Should Be 2   # 2 findings, 3 memberships
        [int]$multi.summary.findingsNoIava   | Should Be 0
        [int]$multi.summary.hosts            | Should Be 2
    }
}
