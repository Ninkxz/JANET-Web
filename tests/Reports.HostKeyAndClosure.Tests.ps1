# =============================================================================
#  Reports.HostKeyAndClosure.Tests.ps1 - Pester 3.4 tests for two remediation
#  correctness fixes in JanetWeb.reports.psm1:
#   (a) FIX P2-8: the same physical host collapses to ONE key regardless of
#       FQDN / NetBIOS / case (Get-ReportsAuditHostKey normalization), so SLA
#       clocks and campaign keys are not reset/double-counted by name format.
#   (b) FIX P2-9: campaign-verify requires PHYSICAL ABSENCE from the fresh scan
#       to close a campaign; a manual 'Patched' flag alone must NOT flip a
#       campaign to verified-closed.
#  Unit-scope: synthetic in-session findings + the real campaign store with a
#  uniquely-named campaign that is deleted at the end. No host/share contact.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru
$script:Uniq = 'SELFTEST-HK-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

Describe 'Host-key normalization + closure evidence (FIX P2-8 / P2-9)' {

    # ---- (a) HOST1 and host1.dom collapse to one normalized key ---------------
    $keys = & $script:Mod {
        [pscustomobject]@{
            Short = Get-ReportsAuditHostKey 'HOST1'
            Fqdn  = Get-ReportsAuditHostKey 'host1.dom.mil'
            Lower = Get-ReportsAuditHostKey 'host1'
            Ip    = Get-ReportsAuditHostKey '10.1.2.3'
        }
    }

    It 'folds HOST1, host1.dom.mil and host1 to a single key' {
        $keys.Short | Should Be 'HOST1'
        $keys.Fqdn  | Should Be $keys.Short
        $keys.Lower | Should Be $keys.Short
    }
    It 'keeps a bare IPv4 whole (does not collapse to its first octet)' {
        $keys.Ip | Should Be '10.1.2.3'
    }

    # ---- (a) integration: campaign-create dedups HOST1 + host1.dom to 1 key ---
    $create = & $script:Mod {
        param($uniqName)
        $noop = { param($e) }
        # Same physical host, same plugin, two DIFFERENT name formats -> ONE key.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='HOST1';        PluginID='100'; VulnName='Chrome flaw'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='Update Chrome'; InKEV=$false; KevCves=''; IAVA=''; PatchedBy=''; PatchedDate='' }
            [pscustomobject]@{ Hostname='host1.dom.mil'; PluginID='100'; VulnName='Chrome flaw'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='Update Chrome'; InKEV=$false; KevCves=''; IAVA=''; PatchedBy=''; PatchedDate='' }
        )
        $cr = Invoke-JanetToolAction -ActionId 'campaign-create' -Params @{ name=($uniqName + '-KEY') } -Emit $noop
        $file = Join-Path (Get-ReportsCampaignDir) ("$($cr.summary.id).json")
        $json = if (Test-Path $file) { Get-Content $file -Raw | ConvertFrom-Json } else { $null }
        [pscustomobject]@{ Summary=$cr.summary; Json=$json; File=$file }
    } $script:Uniq

    It 'campaign-create collapses two name-formats of one host+plugin to a single findingKey' {
        @($create.Json.findingKeys).Count | Should Be 1
    }

    # ---- (b) manual 'Patched' flag alone must NOT close a campaign ------------
    $manual = & $script:Mod {
        param($uniqName)
        $noop = { param($e) }
        # Campaign of 2 genuinely-open findings.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='HOST1'; PluginID='100'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; InKEV=$false; KevCves=''; IAVA=''; PatchedBy=''; PatchedDate='' }
            [pscustomobject]@{ Hostname='host2'; PluginID='200'; VulnName='Apache'; Severity='High';     CVE='';      Category='Apache'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA=''; PatchedBy=''; PatchedDate='' }
        )
        $cr = Invoke-JanetToolAction -ActionId 'campaign-create' -Params @{ name=($uniqName + '-MAN') } -Emit $noop
        $id = $cr.summary.id
        # Operator hand-flags BOTH findings 'Patched' with ZERO re-scan; the SAME
        # (now-flagged) findings are still loaded - they are physically PRESENT.
        Invoke-JanetToolAction -ActionId 'acas-mark-status' -Params @{ newStatus='Patched'; keys=("HOST1|100`nhost2|200") } -Emit $noop | Out-Null
        $ver = Invoke-JanetToolAction -ActionId 'campaign-verify' -Params @{ campaignId=$id } -Emit $noop
        $json = Get-ReportsCampaignById -Id $id
        $file = Join-Path (Get-ReportsCampaignDir) ("$id.json")
        [pscustomobject]@{ Verify=$ver.summary; Json=$json; File=$file }
    } $script:Uniq

    It 'a campaign whose keys are only MANUALLY flagged Patched does NOT verify-closed' {
        $manual.Verify.status | Should Not Be 'verified-closed'
    }
    It 'manual flags are counted as attested, not scan-confirmed remediation' {
        [int]$manual.Verify.attested      | Should Be 2
        [int]$manual.Verify.scanConfirmed | Should Be 0
        [int]$manual.Verify.stillOpen     | Should Be 0
    }
    It 'persists the non-closed verdict (in-progress) to the campaign file' {
        $manual.Json.status | Should Be 'in-progress'
        [int]$manual.Json.verify.attested | Should Be 2
    }

    # ---- cleanup: delete the two test campaign files --------------------------
    It 'cleans up the test campaign files' {
        if ($create.File -and (Test-Path $create.File)) { [System.IO.File]::Delete($create.File) }
        if ($manual.File -and (Test-Path $manual.File)) { [System.IO.File]::Delete($manual.File) }
        (Test-Path $create.File) | Should Be $false
    }
}
