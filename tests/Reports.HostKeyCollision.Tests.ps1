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

Describe 'Get-ReportsHostKeyCollisions - IP-qualified signal for BARE short names (loop40 P1)' {
    It 'flags two BARE short names on DIFFERENT IPs (the short-name-only AFNET norm)' {
        $c = & $script:Mod { param($hn,$ip) Get-ReportsHostKeyCollisions -Hostnames $hn -IPs $ip } @('WEB01','WEB01') @('10.0.0.1','10.0.0.2')
        $c.Contains('WEB01') | Should Be $true
    }
    It 'does NOT flag a short name + its own FQDN sharing the SAME IP (one box, two forms - fixes F2 over-fire)' {
        $c = & $script:Mod { param($hn,$ip) Get-ReportsHostKeyCollisions -Hostnames $hn -IPs $ip } @('WEB01','web01.us.af.mil') @('10.0.0.1','10.0.0.1')
        $c.Contains('WEB01') | Should Be $false
    }
    It 'does NOT flag two BARE short names when NO IP is present (IP-less residual - undisambiguable, unchanged from loop39)' {
        $c = & $script:Mod { param($hn) Get-ReportsHostKeyCollisions -Hostnames $hn } @('WEB01','WEB01')
        @($c).Count | Should Be 0
    }
    It 'does NOT flag two BARE short names sharing ONE IP (same box re-listed)' {
        $c = & $script:Mod { param($hn,$ip) Get-ReportsHostKeyCollisions -Hostnames $hn -IPs $ip } @('WEB01','WEB01') @('10.0.0.9','10.0.0.9')
        @($c).Count | Should Be 0
    }
    It 'ignores blank / non-IPv4 IP cells (no false collision from junk in the IP column)' {
        $c = & $script:Mod { param($hn,$ip) Get-ReportsHostKeyCollisions -Hostnames $hn -IPs $ip } @('WEB01','WEB01') @('','n/a')
        @($c).Count | Should Be 0
    }
}

Describe 'New-AcasFinding / Parse-AcasFile - carries the scan IP discriminator (loop40 P1)' {
    It 'New-AcasFinding stamps the IP field from -IP' {
        $f = & $script:Mod { New-AcasFinding -Hostname 'WEB01' -PluginID '5' -VulnName 'x' -Severity 'High' -CVE '' -Category 'Other' -Solution '' -KevSet $null -IavmMap $null -IP '10.0.0.5' }
        $f.IP | Should Be '10.0.0.5'
    }
    It 'defaults IP to empty when -IP is omitted' {
        $f = & $script:Mod { New-AcasFinding -Hostname 'WEB01' -PluginID '5' -VulnName 'x' -Severity 'High' -CVE '' -Category 'Other' -Solution '' -KevSet $null -IavmMap $null }
        [string]$f.IP | Should Be ''
    }
    It 'Parse-AcasFile carries the IP from a CSV row that has an IP Address column' {
        $csv = Join-Path ([System.IO.Path]::GetTempPath()) ('SELFTEST-ACASIP-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.csv')
        Set-Content -LiteralPath $csv -Value "DNS Name,IP Address,Plugin,Name,Severity`r`nWEB01,10.0.0.7,900001,Chrome flaw,Critical" -Encoding ASCII
        try {
            $ip = & $script:Mod { param($p) $fs = @(Parse-AcasFile -FilePath $p); if ($fs.Count -gt 0) { [string]$fs[0].IP } else { '<none>' } } $csv
            $ip | Should Be '10.0.0.7'
        } finally {
            if (Test-Path -LiteralPath $csv) { [System.IO.File]::Delete($csv) }
        }
    }
}

Describe 'Compare-AcasScans / acas-run-compare - two BARE WEB01 on DIFFERENT IPs -> AMBIGUOUS, never false-closed (loop40 P1 core)' {
    # The regression loop39 missed: a BARE short-name-only export (no FQDN, no dot) of two
    # DISTINCT boxes sharing WEB01. Baseline WEB01 (10.0.0.1) has plugin 5 open; the comparison
    # only re-scanned the OTHER WEB01 (10.0.0.2). Under the raw fold WEB01|5 is baseline-only and
    # would be REMEDIATED (false close). The IP signal now demotes it to AMBIGUOUS.
    $cmp = & $script:Mod {
        $noop = { param($e) }
        $script:BaselineFindings = @(
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.1'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Solution='x' }
        )
        $script:ComparisonFindings = @(
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.2'; PluginID='7'; VulnName='Other'; Severity='Low'; CVE=''; Category='Other'; Solution='' }
        )
        Invoke-JanetToolAction -ActionId 'acas-run-compare' -Params @{} -Emit $noop
    }

    It 'scores the bare-name collision AMBIGUOUS via distinct IPs' {
        [int]$cmp.summary.ambiguous | Should Be 1
    }
    It 'does NOT false-close it as REMEDIATED' {
        [int]$cmp.summary.remediated | Should Be 0
        @($cmp.rows | Where-Object { $_.Delta -eq 'REMEDIATED' }).Count | Should Be 0
    }
    It 'surfaces the collided key as an AMBIGUOUS row' {
        @($cmp.rows | Where-Object { $_.Delta -eq 'AMBIGUOUS' -and [string]$_.PluginID -eq '5' }).Count | Should Be 1
    }
}

Describe 'acas-apply-remediated - two BARE WEB01 on DIFFERENT IPs are NOT flipped Patched (loop40 P1 mutation guard)' {
    $ap = & $script:Mod {
        $noop = { param($e) }
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.1'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; PatchedBy=''; PatchedDate='' }
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.2'; PluginID='9'; VulnName='Other';  Severity='Low';      CVE='';      Category='Other';  Status='Open'; Solution='';  PatchedBy=''; PatchedDate='' }
        )
        $script:ComparisonResults = @(
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.1'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Delta='REMEDIATED'; Solution='x' }
        )
        $res = Invoke-JanetToolAction -ActionId 'acas-apply-remediated' -Params @{} -Emit $noop
        [pscustomobject]@{ Summary=$res.summary; Status=($script:AcasFindings | Where-Object { $_.PluginID -eq '5' } | Select-Object -First 1).Status }
    }

    It 'leaves the collided finding Open (never patches the wrong box)' {
        $ap.Status | Should Be 'Open'
    }
    It 'marks zero and reports the skip as ambiguous' {
        [int]$ap.Summary.marked           | Should Be 0
        [int]$ap.Summary.skippedAmbiguous | Should Be 1
    }
}

Describe 'acas-apply-remediated - anti-over-guard: WEB01 + its own FQDN on the SAME IP still flips (loop40 F2)' {
    # One physical box exported two ways (short + FQDN) sharing ONE IP - NOT a collision.
    $ap = & $script:Mod {
        $noop = { param($e) }
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='WEB01';           IP='10.0.0.1'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; PatchedBy=''; PatchedDate='' }
            [pscustomobject]@{ Hostname='web01.us.af.mil'; IP='10.0.0.1'; PluginID='6'; VulnName='Apache'; Severity='High';     CVE='';      Category='Apache'; Status='Open'; Solution='';  PatchedBy=''; PatchedDate='' }
        )
        $script:ComparisonResults = @(
            [pscustomobject]@{ Hostname='WEB01'; IP='10.0.0.1'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Delta='REMEDIATED'; Solution='x' }
        )
        $res = Invoke-JanetToolAction -ActionId 'acas-apply-remediated' -Params @{} -Emit $noop
        [pscustomobject]@{ Summary=$res.summary; Status=($script:AcasFindings | Where-Object { $_.PluginID -eq '5' } | Select-Object -First 1).Status }
    }

    It 'flips the single-box finding to Patched (no over-guard)' {
        $ap.Status | Should Be 'Patched'
    }
    It 'marks one and skips none' {
        [int]$ap.Summary.marked           | Should Be 1
        [int]$ap.Summary.skippedAmbiguous | Should Be 0
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

Describe 'Compare-AcasScans / acas-run-compare - collided short key is AMBIGUOUS, not REMEDIATED (loop39, row 36)' {
    # Baseline: web01.us.af.mil has plugin 5 open (BEFORE patching).
    # Comparison: web01.us was NOT re-scanned; only web01.eu.af.mil is present (a DIFFERENT
    # physical box that folds to the SAME WEB01 short key, carrying a different plugin 7).
    # Under the raw fold, WEB01|5 is baseline-only and would be scored REMEDIATED - a FALSE
    # close, because web01.us was never confirmed patched. The collision guard demotes it to
    # AMBIGUOUS (never remediated, never auto-close).
    $cmp = & $script:Mod {
        $noop = { param($e) }
        $script:BaselineFindings = @(
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Solution='x' }
        )
        $script:ComparisonFindings = @(
            [pscustomobject]@{ Hostname='web01.eu.af.mil'; PluginID='7'; VulnName='Other'; Severity='Low'; CVE=''; Category='Other'; Solution='' }
        )
        Invoke-JanetToolAction -ActionId 'acas-run-compare' -Params @{} -Emit $noop
    }

    It 'scores the collided baseline-only key AMBIGUOUS' {
        [int]$cmp.summary.ambiguous | Should Be 1
    }
    It 'does NOT score the collided key REMEDIATED (no false close)' {
        [int]$cmp.summary.remediated | Should Be 0
        @($cmp.rows | Where-Object { $_.Delta -eq 'REMEDIATED' }).Count | Should Be 0
    }
    It 'surfaces the collided key as an AMBIGUOUS row for the operator' {
        @($cmp.rows | Where-Object { $_.Delta -eq 'AMBIGUOUS' -and [string]$_.PluginID -eq '5' }).Count | Should Be 1
    }
}

Describe 'Compare-AcasScans - anti-over-guard: a NON-collided host still REMEDIATES (loop39)' {
    # NO cross-domain collision here: one distinct short name (APPSERVER) and one legitimate
    # short+own-FQDN alias (HOST1 <-> host1.dom.mil, a SINGLE physical box). Both baseline-only
    # keys must still flip REMEDIATED - proving the fold + legitimate closure are intact and the
    # guard only fires on a genuine >=2-distinct-FQDN collision.
    $cmp = & $script:Mod {
        $noop = { param($e) }
        $script:BaselineFindings = @(
            [pscustomobject]@{ Hostname='appserver.us.af.mil'; PluginID='5'; VulnName='A'; Severity='High'; CVE=''; Category='Other'; Solution='' }
            [pscustomobject]@{ Hostname='HOST1';               PluginID='5'; VulnName='B'; Severity='High'; CVE=''; Category='Other'; Solution='' }
        )
        # Both hosts were RE-SCANNED and each cleared plugin 5, evidenced by a different
        # plugin still present for each.
        #
        # loop 2026-08-03 P1: this fixture used to give appserver NO comparison row at all
        # and call that "appserver patched (absent)" - which is precisely the unsafe
        # inference the NOT SCANNED bucket now refuses. A host missing from the comparison
        # was never scanned (the parser keeps Info findings, so a scanned host always
        # carries rows), so absence is not evidence of a fix. Giving appserver a real
        # re-scan row keeps this Describe's actual subject intact - that the collision
        # guard does NOT over-fire and a legitimate closure still REMEDIATES - while
        # expressing "patched" as evidence instead of silence.
        $script:ComparisonFindings = @(
            [pscustomobject]@{ Hostname='host1.dom.mil';      PluginID='9'; VulnName='C'; Severity='Low'; CVE=''; Category='Other'; Solution='' }
            [pscustomobject]@{ Hostname='appserver.us.af.mil'; PluginID='9'; VulnName='D'; Severity='Low'; CVE=''; Category='Other'; Solution='' }
        )
        Invoke-JanetToolAction -ActionId 'acas-run-compare' -Params @{} -Emit $noop
    }

    It 'flips both non-collided baseline-only keys to REMEDIATED' {
        [int]$cmp.summary.remediated | Should Be 2
    }
    It 'raises NO ambiguous verdict on the legitimate short+own-FQDN alias' {
        [int]$cmp.summary.ambiguous | Should Be 0
    }
}

Describe 'acas-apply-remediated - collided-key finding is NOT flipped to Patched (loop39 mutation guard)' {
    # The ONLY site that writes Status=Patched. ComparisonResults claims web01.us|5 REMEDIATED,
    # but the loaded set has web01.us.af.mil AND web01.eu.af.mil (distinct boxes -> WEB01 collision),
    # so the apply MUST skip the flip (leave the vuln open, surfaced) rather than patch the wrong box.
    $ap = & $script:Mod {
        $noop = { param($e) }
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Status='Open'; Solution='x'; PatchedBy=''; PatchedDate='' }
            [pscustomobject]@{ Hostname='web01.eu.af.mil'; PluginID='9'; VulnName='Other';  Severity='Low';      CVE='';      Category='Other';  Status='Open'; Solution='';  PatchedBy=''; PatchedDate='' }
        )
        $script:ComparisonResults = @(
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE='CVE-1'; Category='Chrome'; Delta='REMEDIATED'; Solution='x' }
        )
        $res = Invoke-JanetToolAction -ActionId 'acas-apply-remediated' -Params @{} -Emit $noop
        [pscustomobject]@{ Summary=$res.summary; UsStatus=($script:AcasFindings | Where-Object { $_.Hostname -eq 'web01.us.af.mil' } | Select-Object -First 1).Status }
    }

    It 'does NOT mark the collided finding Patched (Status stays Open)' {
        $ap.UsStatus | Should Be 'Open'
    }
    It 'marks zero and reports the skip as ambiguous' {
        [int]$ap.Summary.marked           | Should Be 0
        [int]$ap.Summary.skippedAmbiguous | Should Be 1
    }
}

Describe 'acas-apply-remediated - anti-over-guard: a NON-collided remediation still flips to Patched (loop39)' {
    # No collision (single distinct FQDN). The REMEDIATED key must still flip normally.
    $ap = & $script:Mod {
        $noop = { param($e) }
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='appserver.us.af.mil'; PluginID='7'; VulnName='A'; Severity='High'; CVE=''; Category='Other'; Status='Open'; Solution=''; PatchedBy=''; PatchedDate='' }
        )
        $script:ComparisonResults = @(
            [pscustomobject]@{ Hostname='appserver.us.af.mil'; PluginID='7'; VulnName='A'; Severity='High'; CVE=''; Category='Other'; Delta='REMEDIATED'; Solution='' }
        )
        $res = Invoke-JanetToolAction -ActionId 'acas-apply-remediated' -Params @{} -Emit $noop
        [pscustomobject]@{ Summary=$res.summary; Status=($script:AcasFindings | Select-Object -First 1).Status }
    }

    It 'flips the non-collided finding to Patched' {
        $ap.Status | Should Be 'Patched'
    }
    It 'marks one and skips none' {
        [int]$ap.Summary.marked           | Should Be 1
        [int]$ap.Summary.skippedAmbiguous | Should Be 0
    }
}

Describe 'Build-CoraSummary - one host as WEB01 + web01.us.af.mil counts ONCE (loop39, row 37)' {
    $sum = & $script:Mod {
        # Same physical box exported two ways (short + FQDN), two different plugins - one UNIQUE host.
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='WEB01';           PluginID='5'; VulnName='Chrome'; Severity='Critical'; CVE=''; Category='Chrome'; Status='Open'; Solution='' }
            [pscustomobject]@{ Hostname='web01.us.af.mil'; PluginID='6'; VulnName='Apache'; Severity='High';     CVE=''; Category='Apache'; Status='Open'; Solution='' }
        )
        $script:NetworkDeviceCount = 0
        Build-CoraSummary
    }

    It 'counts the two name-formats of one box as a single unique host' {
        [int]$sum.UniqueHosts | Should Be 1
    }
    It 'counts that one host once in the per-severity host tallies' {
        ([int]$sum.SevHosts.Critical + [int]$sum.SevHosts.High) | Should Be 2
        # (Critical from WEB01, High from web01.us) - two severities, but each is the SAME single
        # host keyed once per severity bucket; the point is neither bucket double-counts the box.
        [int]$sum.SevHosts.Critical | Should Be 1
        [int]$sum.SevHosts.High     | Should Be 1
    }
}
