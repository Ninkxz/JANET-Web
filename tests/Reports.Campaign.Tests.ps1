# =============================================================================
#  Reports.Campaign.Tests.ps1 - Pester 3.4 tests for the remediation campaign
#  store (campaign-create / campaign-list). Uses the real JanetLocal\campaigns
#  store with a uniquely-named campaign, then deletes just that campaign's file.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetTwo.reports.psm1') -Force -PassThru
$script:Uniq = 'SELFTEST-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

Describe 'Remediation campaign store (campaign-create / campaign-list)' {

    $result = & $script:Mod {
        param($uniqName)
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hostA'; PluginID='1'; VulnName='Google Chrome flaw'; Severity='Critical'; CVE='CVE-2024-1'; Category='Chrome'; Status='Open'; Solution='Update Chrome'; InKEV=$true;  KevCves='CVE-2024-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hostA'; PluginID='2'; VulnName='Apache Struts';        Severity='High';     CVE='';          Category='Apache'; Status='Open'; Solution='';            InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='hostB'; PluginID='3'; VulnName='Old thing';            Severity='Low';      CVE='';          Category='Chrome'; Status='Patched'; Solution='';         InKEV=$false; KevCves=''; IAVA='' }
        )
        $noop = { param($e) }
        $cr = Invoke-JanetToolAction -ActionId 'campaign-create' -Params @{ name=$uniqName } -Emit $noop
        $lr = Invoke-JanetToolAction -ActionId 'campaign-list' -Params @{} -Emit $noop
        $file = Join-Path (Get-ReportsCampaignDir) ("$($cr.summary.id).json")
        $json = if (Test-Path $file) { Get-Content $file -Raw | ConvertFrom-Json } else { $null }
        [pscustomobject]@{ Create=$cr.summary; List=@($lr.rows); Json=$json; File=$file }
    } $script:Uniq

    It 'creates a campaign snapshotting only OPEN findings (2 of 3)' {
        [int]$result.Create.openFindings | Should Be 2
    }

    It 'counts KEV findings in the snapshot' {
        [int]$result.Create.kev | Should Be 1
    }

    It 'persists a campaign JSON with findingKeys + mapped routes' {
        $result.Json | Should Not BeNullOrEmpty
        $result.Json.status | Should Be 'open'
        @($result.Json.findingKeys).Count | Should Be 2
        ($result.Json.routes -join ' ') | Should Match 'Chrome'
    }

    It 'lists the just-created campaign (by unique name)' {
        $mine = @($result.List | Where-Object { $_['Name'] -eq $script:Uniq })
        $mine.Count | Should Be 1
        $mine[0]['OpenFindings'] | Should Be '2'
        $mine[0]['KEV'] | Should Be '1'
    }

    # ---- close-the-loop verify ------------------------------------------------
    $verify = & $script:Mod {
        param($uniqName)
        $noop = { param($e) }
        # Campaign of 2 open findings.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='1'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; InKEV=$true;  KevCves='CVE-1'; IAVA='' }
            [pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Apache'; Severity='High';     CVE='';      Category='Apache'; Status='Open'; Solution='';  InKEV=$false; KevCves=''; IAVA='' }
        )
        $cr = Invoke-JanetToolAction -ActionId 'campaign-create' -Params @{ name=($uniqName + '-VER') } -Emit $noop
        $id = $cr.summary.id
        # Fresh scan: hA|1 remediated (gone), hB|2 still open.
        $script:AcasFindings = @([pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Apache'; Severity='High'; CVE=''; Category='Apache'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' })
        $v1 = Invoke-JanetToolAction -ActionId 'campaign-verify' -Params @{ campaignId=$id } -Emit $noop
        # Fresh scan: both gone -> fully closed.
        $script:AcasFindings = @([pscustomobject]@{ Hostname='hZ'; PluginID='9'; VulnName='Other'; Severity='Low'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' })
        $v2 = Invoke-JanetToolAction -ActionId 'campaign-verify' -Params @{ campaignId=$id } -Emit $noop
        $json = Get-ReportsCampaignById -Id $id
        $file = Join-Path (Get-ReportsCampaignDir) ("$id.json")
        [pscustomobject]@{ V1=$v1.summary; V2=$v2.summary; Json=$json; File=$file }
    } $script:Uniq

    It 'partial verify: 1 remediated / 1 still-open = 50% closed, in-progress' {
        [int]$verify.V1.remediated | Should Be 1
        [int]$verify.V1.stillOpen  | Should Be 1
        $verify.V1.status          | Should Be 'in-progress'
    }
    It 'full verify: all remediated = 100% closed, verified-closed, persisted' {
        [int]$verify.V2.remediated | Should Be 2
        [int]$verify.V2.stillOpen  | Should Be 0
        $verify.V2.status          | Should Be 'verified-closed'
        $verify.Json.status        | Should Be 'verified-closed'
        [int]$verify.Json.verify.remediated | Should Be 2
    }
    It 'campaign-verify returns notFound for an unknown id' {
        $nf = & $script:Mod { $script:AcasFindings=@([pscustomobject]@{Hostname='x';PluginID='1';Status='Open';Severity='Low';VulnName='';CVE='';Category='Other';Solution='';InKEV=$false;KevCves='';IAVA=''}); (Invoke-JanetToolAction -ActionId 'campaign-verify' -Params @{ campaignId='no-such-id' } -Emit { param($e) }).summary }
        $nf.notFound | Should Be $true
    }

    # cleanup: delete both test campaign files
    It 'cleans up the test campaign files' {
        if ($result.File -and (Test-Path $result.File)) { [System.IO.File]::Delete($result.File) }
        if ($verify.File -and (Test-Path $verify.File)) { [System.IO.File]::Delete($verify.File) }
        (Test-Path $result.File) | Should Be $false
    }
}
