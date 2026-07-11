# =============================================================================
#  C2c.JavaAndPkiCompanions.Tests.ps1 - Pester 3.4 for the v1.14.0 field-script
#  ports: fix-java (Java-Cleanup-ScanFix v1.1), the PkiRoots companions
#  (PKI-Fix-ScanFix v1.9 expired-intermediate prune + RDP listener repair) and
#  the MDE onboarding heal constants (Defender-ScanFix v2.1). PURE checks only:
#  the verdict classifier, wiring/labels, the deletion allowlist regex, and the
#  guard-copy sync between the remote prune allowlist and C2cLegacyIntermediates
#  (divergence there would make fix-pki DELETE the four certs it just PUSHED).
#
#  Run:  Invoke-Pester -Path .\tests\C2c.JavaAndPkiCompanions.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

Describe 'C2C v1.14.0 - Java verdict classifier (Get-C2cJavaVerdict, 1.8.0_491 bar)' {

    It 'old 1.x families are OLD' {
        & $cm { Get-C2cJavaVerdict '1.7.0' }     | Should Be 'OLD'
        & $cm { Get-C2cJavaVerdict '1.2' }       | Should Be 'OLD'
        & $cm { Get-C2cJavaVerdict '1.0.1' }     | Should Be 'OLD'
        & $cm { Get-C2cJavaVerdict '1.8.0_281' } | Should Be 'OLD'
    }
    It '1.8.0 at/above the update bar is OK' {
        & $cm { Get-C2cJavaVerdict '1.8.0_491' } | Should Be 'OK'
        & $cm { Get-C2cJavaVerdict '1.8.0_501' } | Should Be 'OK'
    }
    It 'Oracle DisplayVersion 8.0.xxxx scheme honours the bar (update = minor/10)' {
        & $cm { Get-C2cJavaVerdict '8.0.2810.9' } | Should Be 'OLD'   # 8u281
        & $cm { Get-C2cJavaVerdict '8.0.4910.9' } | Should Be 'OK'    # 8u491
    }
    It 'modern JDKs are OK; the 2.x auto-updater is OLD' {
        & $cm { Get-C2cJavaVerdict '11.0.2' }    | Should Be 'OK'
        & $cm { Get-C2cJavaVerdict '17' }        | Should Be 'OK'
        & $cm { Get-C2cJavaVerdict '21' }        | Should Be 'OK'
        & $cm { Get-C2cJavaVerdict '2.8.281.9' } | Should Be 'OLD'
    }
    It 'unparseable / empty versions are UNKNOWN (never auto-removed)' {
        & $cm { Get-C2cJavaVerdict '' }        | Should Be 'UNKNOWN'
        & $cm { Get-C2cJavaVerdict 'banana' }  | Should Be 'UNKNOWN'
        & $cm { Get-C2cJavaVerdict '8u281' }   | Should Be 'UNKNOWN'
    }
    It 'a custom MinUpdate bar is honoured' {
        & $cm { Get-C2cJavaVerdict '1.8.0_281' 271 } | Should Be 'OK'
        & $cm { Get-C2cJavaVerdict '1.8.0_261' 271 } | Should Be 'OLD'
    }
}

Describe 'C2C v1.14.0 - fix-java wiring (opt-in utility, never in run-all)' {

    It 'fix-java maps to the Java pillar' {
        & $cm { $script:C2cPillarByAction['fix-java'] } | Should Be 'Java'
    }
    It 'Java is NOT an endpoint-fixable (run-all) pillar' {
        & $cm { $script:C2cFixablePillars -contains 'Java' } | Should Be $false
    }
    It 'the manifest exposes fix-java as destructive with a typed-FIX confirm input' {
        $a = @((& $cm { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'fix-java' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $true
        @($a.inputs | Where-Object { $_.name -eq 'confirm' }).Count | Should Be 1
        @($a.inputs | Where-Object { $_.name -eq 'targets' }).Count | Should Be 1
    }
    It 'fix-java refuses without the FIX confirm word (nothing dialed)' {
        $r = & $cm { Invoke-C2cFixAction -ActionId 'fix-java' -Params @{ confirm = 'nope'; targets = 'HOSTA' } -Credential $null -Emit $null }
        [bool]$r.summary.rejected | Should Be $true
        @($r.rows).Count | Should Be 0
    }
}

Describe 'C2C v1.14.0 - new pillar-flavoured labels (shared map + inline fallback stay in sync)' {

    It 'Java / PkiExpired / PkiRdp / MdeOnboard labels resolve from the shared map' {
        & $cm { Get-C2cPillarLabel 'Java' 'FIXED' }       | Should Be 'JAVA CLEANED'
        & $cm { Get-C2cPillarLabel 'Java' 'NOCHANGE' }    | Should Be 'NO OLD JAVA'
        & $cm { Get-C2cPillarLabel 'PkiExpired' 'FIXED' } | Should Be 'EXPIRED PRUNED'
        & $cm { Get-C2cPillarLabel 'PkiRdp' 'FIXED' }     | Should Be 'RDP CERT REBOUND'
        & $cm { Get-C2cPillarLabel 'MdeOnboard' 'FIXED' } | Should Be 'MDE ONBOARDED'
    }
    It 'SKIP / FAIL still pass through the default arm' {
        & $cm { Get-C2cPillarLabel 'PkiRdp' 'SKIP' } | Should Be 'SKIP'
        & $cm { Get-C2cPillarLabel 'Java' 'FAIL' }   | Should Be 'FAIL'
    }
}

Describe 'C2C v1.14.0 - PkiExpired prune allowlist (v1.9 safety model)' {

    # The EXACT regex the remote prune uses (asserted below to stay in the fix block).
    $allow = '^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD'

    It 'the fix block carries the allowlist regex verbatim' {
        (& $cm { $script:C2cFixBlock.ToString() }) | Should Match ([regex]::Escape('^CN=DOD (EMAIL|ID|SW|DERILITY) CA-\d+, OU=PKI, OU=DoD'))
    }
    It 'matches retired DoD intermediates only' {
        'CN=DOD EMAIL CA-59, OU=PKI, OU=DoD, O=U.S. Government, C=US' -match $allow | Should Be $true
        'CN=DOD ID CA-62, OU=PKI, OU=DoD, O=U.S. Government, C=US'    -match $allow | Should Be $true
        'CN=DOD SW CA-60, OU=PKI, OU=DoD, O=U.S. Government, C=US'    -match $allow | Should Be $true
        'CN=DOD DERILITY CA-3, OU=PKI, OU=DoD, O=U.S. Government, C=US' -match $allow | Should Be $true
    }
    It 'never matches roots, machine identity or non-DoD subjects' {
        'CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US' -match $allow | Should Be $false
        'CN=RSDQL-12345.area52.afnoapps.usaf.mil'                   -match $allow | Should Be $false
        'CN=DigiCert Global Root CA, OU=www.digicert.com'           -match $allow | Should Be $false
        'CN=DOD WCF SIGNING CA-1, OU=PKI, OU=DoD'                   -match $allow | Should Be $false
    }
    It 'the prune guard-copy carries EXACTLY the C2cLegacyIntermediates thumbprints (divergence would delete what fix-pki pushes)' {
        $sync = & $cm {
            $src = $script:C2cFixBlock.ToString()
            # the guard copy lives between the legacyKeep declaration and its closing paren
            $m = [regex]::Match($src, '\$legacyKeep\s*=\s*@\(([^)]*)\)', 'Singleline')
            $inBlock = @([regex]::Matches($m.Groups[1].Value, "'([0-9A-F]{40})'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
            $canon = @($script:C2cLegacyIntermediates.Keys | ForEach-Object { [string]$_ } | Sort-Object)
            @{ InBlock = ($inBlock -join ','); Canon = ($canon -join ',') }
        }
        $sync.InBlock | Should Be $sync.Canon
        $sync.Canon   | Should Not BeNullOrEmpty
    }
}

Describe 'C2C v1.15.0 - offline Defender definition package staging (v2.1 last rung)' {

    It 'the shipped staging folder exists (empty apart from the README) and resolves to NO package' {
        $dir = & $cm { Get-C2cDefenderPackageDir }
        Test-Path $dir | Should Be $true
        $r = & $cm { Resolve-C2cDefenderPackage }
        [string]$r.Path | Should Be ''
        [string]$r.Note | Should Be ''
    }
    It 'a missing path is rejected as not found' {
        & $cm { Test-C2cDefenderPackage 'X:\does\not\exist\mpam-fe.exe' } | Should Be 'not found'
    }
    It 'a too-small file is rejected (not a full definition package) and never resolves' {
        $tmp = Join-Path $env:TEMP 'c2c-test-mpam-fe.exe'
        Set-Content -Path $tmp -Value 'not a real installer' -Encoding Ascii
        try {
            (& $cm { param($p) Test-C2cDefenderPackage $p } $tmp) | Should Match '^too small'
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'C2C v1.14.0 - MDE onboarding heal constants (Defender v2.1 port)' {

    It 'the embedded OnboardingInfo blob parses and its orgId matches the TASKORD MDE Org ID' {
        $ok = & $cm {
            $outer = $script:C2cMdeOnboardingBlob | ConvertFrom-Json
            $body  = $outer.body | ConvertFrom-Json
            ("$($body.orgId)".Trim().ToUpper() -eq $script:C2cMdeOrgId.Trim().ToUpper())
        }
        $ok | Should Be $true
    }
    It 'the blob carries the USGov gateway the heal ladder diagnoses' {
        $gw = & $cm {
            $outer = $script:C2cMdeOnboardingBlob | ConvertFrom-Json
            $body  = $outer.body | ConvertFrom-Json
            ([uri]$body.geoLocationUrl).Host
        }
        $gw | Should Be 'winatp-gw-usgv.microsoft.com'
    }
}
