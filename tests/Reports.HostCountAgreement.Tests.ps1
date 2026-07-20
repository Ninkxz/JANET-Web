# =============================================================================
#  Reports.HostCountAgreement.Tests.ps1 - Pester 3.4 for the loop-13 host-count
#  normalization (reports v2.14.21). The loop-13 correctness deep-dive found that
#  CORA dedups hosts by the normalized audit key (Get-ReportsAuditHostKey: IPv4
#  whole, else short-name upper - so WEB01 and web01.dom fold to ONE host), but
#  several sibling host tallies keyed on the RAW hostname, so the SAME host set
#  reported DIFFERENT host totals across the tool - and the posture digest was
#  internally self-contradictory (deduped UniqueHosts vs raw HostsWithKev in the
#  same file). Fixed the headline count sites (posture-digest KEV host map,
#  sla-aging per-host, command-brief KEV hosts, remediation-plan Hosts/KevHosts,
#  kb-needed). This test proves those counts now agree for a two-name-form host.
#
#  Read-only over a seeded $script:AcasFindings; no host contact.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.HostCountAgreement.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

# ONE logical host, two name forms (short + FQDN); both open, both KEV, both with
# the same KB in the solution. A correct tool counts this as ONE host everywhere.
# Defined as a MODULE-SCOPE function (the & $script:Mod blocks run in module scope,
# so a test-scope function would be invisible there).
& $script:Mod {
    function script:Seed-TwoNameFormHost {
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='WEB01';          PluginID='1'; VulnName='Security Update KB5031354'; Severity='Critical'; CVE='CVE-2024-1111'; Category='KB Patch'; Status='Open'; Solution='Install KB5031354.'; InKEV=$true; KevCves='CVE-2024-1111'; IAVA='' }
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='1'; VulnName='Security Update KB5031354'; Severity='High';     CVE='CVE-2024-1111'; Category='KB Patch'; Status='Open'; Solution='Install KB5031354.'; InKEV=$true; KevCves='CVE-2024-1111'; IAVA='' }
        )
    }
}

Describe 'reports 2.14.21 - manifest loads at the bumped version' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    It 'manifest id is reports and version is 2.14.21' {
        [string]$mani.id      | Should Be 'reports'
        [string]$mani.version | Should Be '2.14.21'
    }
}

Describe 'reports host-count normalization - a two-name-form host counts as ONE everywhere (loop13)' {

    It 'sla-aging counts 1 host (was 2 - short + FQDN keyed raw)' {
        $h = & $script:Mod { Seed-TwoNameFormHost; (Invoke-JanetToolAction -ActionId 'sla-aging' -Params @{} -Emit { param($e) }).summary.hosts }
        [int]$h | Should Be 1
    }

    It 'kb-needed counts 1 host for the shared KB (was 2)' {
        $h = & $script:Mod { Seed-TwoNameFormHost; (Invoke-JanetToolAction -ActionId 'kb-needed' -Params @{} -Emit { param($e) }).summary.hosts }
        [int]$h | Should Be 1
    }

    It 'the two headline tallies AGREE (sla-aging == kb-needed == 1)' {
        $r = & $script:Mod {
            Seed-TwoNameFormHost
            $sla = (Invoke-JanetToolAction -ActionId 'sla-aging' -Params @{} -Emit { param($e) }).summary.hosts
            $kb  = (Invoke-JanetToolAction -ActionId 'kb-needed' -Params @{} -Emit { param($e) }).summary.hosts
            [pscustomobject]@{ Sla=[int]$sla; Kb=[int]$kb }
        }
        $r.Sla | Should Be 1
        $r.Kb  | Should Be 1
        $r.Sla | Should Be $r.Kb
    }

    It 'posture-digest KEV host count (HostsWithKev) is 1, agreeing with UniqueHosts (fixes the self-contradiction)' {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetWeb_HostCountAgree_" + [guid]::NewGuid().ToString('N'))
        $res = & $script:Mod {
            param($OutDir)
            Seed-TwoNameFormHost
            Invoke-JanetToolAction -ActionId 'posture-digest' -Params @{ outDir = $OutDir; title = 'Agreement Test' } -Emit { param($e) }
        } $tempDir
        try {
            [int]$res.summary.hosts | Should Be 1   # = CORA UniqueHosts (already deduped)
            $csv = Get-Content -LiteralPath $res.summary.csvPath -Raw
            # the digest CSV writes a 'KEV,HostsWithKev,<count>,' row; before loop13 it read 2.
            $mkev = [regex]::Match($csv, '(?im)^KEV,HostsWithKev,(\d+),')
            $mkev.Success | Should Be $true
            [int]$mkev.Groups[1].Value | Should Be 1
        } finally {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
