# =============================================================================
#  C2c.SigAge.Tests.ps1 - Pester 3.4 for the Defender signature-age computation
#  (Get-C2cSigAgeHours, loop46 / c2c deep-dive F3, item 53). The AntiMalware scan
#  (the quarantine go/no-go) and fix derive the signature age in hours from
#  MpComputerStatus. When the timestamp (AntivirusSignatureLastUpdated) is missing,
#  they fell back to `[int]$mp.AntivirusSignatureAge * 24` in an else - and
#  `[int]$null` coerces to 0 (no throw), so an UNREADABLE signature age manufactured
#  a 0-hour "fresh" age that PASSED the AntiMalware freshness gate (scan -> PASS ->
#  READY), defeating the downstream `$null -ne $ageHours` guard. Now a null age stays
#  $null, which the freshness gate treats as stale (fail-closed).
#
#  Get-C2cSigAgeHours is the pure canonical computation; the scan + fix workers mirror
#  the datetime/age logic inline. Run:  Invoke-Pester -Path .\tests\C2c.SigAge.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
$src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

function Get-Age {
    param($LastUpdated, $SignatureAge)
    (& $cm { param($l,$a) Get-C2cSigAgeHours -LastUpdated $l -SignatureAge $a } $LastUpdated $SignatureAge)
}

Describe 'Get-C2cSigAgeHours - an unreadable signature age is $null, never a false 0 (F3 fail-close)' {
    It 'no timestamp AND null AntivirusSignatureAge -> $null (was coerced to 0 = false "fresh")' {
        Get-Age -LastUpdated $null -SignatureAge $null | Should Be $null
    }
    It 'no timestamp, a real AntivirusSignatureAge (days) -> days * 24 hours' {
        Get-Age -LastUpdated $null -SignatureAge 5 | Should Be 120
    }
    It 'no timestamp, a genuine 0-day age -> 0 (a real fresh age is still allowed)' {
        Get-Age -LastUpdated $null -SignatureAge 0 | Should Be 0
    }
    It 'a real recent datetime -> a small positive hour count (timestamp wins over the age fallback)' {
        $v = Get-Age -LastUpdated ((Get-Date).AddHours(-3)) -SignatureAge $null
        ($v -ge 2.5 -and $v -le 3.5) | Should Be $true
    }
}

Describe 'c2c scan + fix workers - both mirror the null-age guard (no unguarded [int]$null coercion)' {
    It 'the unguarded `else { [int]$mp.AntivirusSignatureAge * 24 }` fallback is gone (both sites)' {
        ($src -match "else \{ try \{ \`$ageHours = \[int\]\`$mp\.AntivirusSignatureAge \* 24") | Should Be $false
    }
    It 'both sites now guard the fallback with a null check' {
        (@([regex]::Matches($src, "elseif \(\`$null -ne \`$mp\.AntivirusSignatureAge\)")).Count -ge 2) | Should Be $true
    }
}

Describe 'c2c - manifest exact version pin (newest bump = loop-46 sig-age null-coercion fail-close)' {
    It 'c2c is at v1.15.7' {
        $man = & $cm { Get-JanetToolManifest }
        [string]$man.version | Should Be '1.15.7'
    }
}
