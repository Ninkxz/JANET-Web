# =============================================================================
#  Reports.HostKeyCollision.Tests.ps1 - Pester 3.4 for the cross-domain
#  short-name COLLISION guard (loop24, ledger row 36). Get-ReportsAuditHostKey
#  folds any non-IP name to its pre-dot short name (web01 <-> web01.dom -> WEB01),
#  which is INTENDED for short-vs-FQDN of ONE host. But two DISTINCT FQDNs sharing
#  a short name (web01.us.af.mil + web01.eu.af.mil) are DIFFERENT boxes; folding
#  them hides an open vuln behind the wrong host. Get-ReportsHostKeyCollisions
#  detects that, and campaign-verify marks such keys AMBIGUOUS (never remediated,
#  never a false closure).
#
#  Internal helpers + the real campaign-verify are driven in the module session
#  state (the Reports.Campaign idiom); the test campaign file is deleted after.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.HostKeyCollision.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru
$script:Uniq = 'SELFTEST-COLL-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

Describe 'Get-ReportsHostKeyCollisions - cross-domain short-name detection (loop24)' {
    It 'flags two DISTINCT FQDNs that fold to the same short key' {
        $c = & $script:Mod { param($hn) Get-ReportsHostKeyCollisions -Hostnames $hn } @('web01.us.af.mil','web01.eu.af.mil')
        $c.Contains('WEB01') | Should Be $true
    }
    It 'does NOT flag a short name + its own FQDN (the intended fold)' {
        $c = & $script:Mod { param($hn) Get-ReportsHostKeyCollisions -Hostnames $hn } @('web01','web01.us.af.mil')
        $c.Contains('WEB01') | Should Be $false
    }
    It 'does NOT flag a single FQDN, a repeated FQDN, or distinct short names' {
        $c = & $script:Mod { param($hn) Get-ReportsHostKeyCollisions -Hostnames $hn } @('web01.us.af.mil','web01.us.af.mil','web02.eu.af.mil')
        @($c).Count | Should Be 0
    }
    It 'does NOT flag IP literals (kept whole, never folded)' {
        $c = & $script:Mod { param($hn) Get-ReportsHostKeyCollisions -Hostnames $hn } @('10.0.0.1','10.0.0.2')
        @($c).Count | Should Be 0
    }
}

Describe 'campaign-verify - a collided short key is AMBIGUOUS, never a false closure (loop24)' {
    $out = & $script:Mod {
        param($uniqName)
        $noop = { param($e) }
        # Campaign snapshots one open finding on WEB01 (plugin 1).
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='1'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; InKEV=$false; KevCves=''; IAVA='' }
        )
        $cr = Invoke-JanetToolAction -ActionId 'campaign-create' -Params @{ name=$uniqName } -Emit $noop
        $id = $cr.summary.id
        # Fresh scan: web01.us present (plugin 1 GONE) AND web01.eu present (a DIFFERENT box that
        # folds to the same WEB01 short key). WEB01|1 looks remediated, but the closure is
        # ambiguous - it must NOT auto-close.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='99'; VulnName='Other'; Severity='Low'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
            [pscustomobject]@{ Hostname='web01.eu.af.mil'; PluginID='98'; VulnName='Other'; Severity='Low'; CVE=''; Category='Other'; Status='Open'; Solution=''; InKEV=$false; KevCves=''; IAVA='' }
        )
        $v = Invoke-JanetToolAction -ActionId 'campaign-verify' -Params @{ campaignId=$id } -Emit $noop
        $file = Join-Path (Get-ReportsCampaignDir) ("$id.json")
        [pscustomobject]@{ V=$v.summary; File=$file }
    } $script:Uniq

    It 'scores the collided key AMBIGUOUS, not remediated' {
        [int]$out.V.ambiguous  | Should Be 1
        [int]$out.V.remediated | Should Be 0
    }
    It 'does NOT auto-close the campaign (never verified-closed on an ambiguous key)' {
        $out.V.status | Should Not Be 'verified-closed'   # the fix: a collision can never false-close
    }
    It 'cleans up the test campaign file' {
        if ($out.File -and (Test-Path $out.File)) { [System.IO.File]::Delete($out.File) }
        (Test-Path $out.File) | Should Be $false
    }
}
