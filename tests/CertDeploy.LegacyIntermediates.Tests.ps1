# =============================================================================
#  CertDeploy.LegacyIntermediates.Tests.ps1 - the NARROW expiry-guard exception.
#  Four EXPIRED DoD intermediate CAs (DOD EMAIL/ID CA-59, DOD SW CA-60/61) are
#  allowlisted so cert-push (certdeploy Deploy + c2c fix-pki) installs them despite
#  expiry - for legacy chain/signature validation - WITHOUT weakening the guard for
#  any other expired ("dead anchor") cert. This proves: allowlisted-expired -> pushed;
#  non-allowlisted-expired -> still refused; valid -> pushed.
#
#  Run:  Invoke-Pester -Path .\tests\CertDeploy.LegacyIntermediates.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cd = Import-Module (Join-Path $script:Root 'modules\JanetWeb.certdeploy.psm1') -Force -PassThru
$c2 = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1')        -Force -PassThru

$script:Four = @(
    '53FDE0F40638BD1A68A68D1E91089009B33BAE5E'  # DOD EMAIL CA-59
    '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7'  # DOD ID CA-59
    '5DFFDAB658915FA6B0DB4E0BCF70D5BB1B8425FC'  # DOD SW CA-60
    '5F555AB8A87DD146314171621245CF720BF53B8A'  # DOD SW CA-61
)
$script:Bundle = Join-Path $script:Root 'Packages\DoD-Certs\Intermediate'

# Build a temp bundle folder that holds ONLY the four legacy certs, so census counts are
# deterministic (LegacyAllowedCount=4, ExpiredCount=0 - nothing non-allowlisted present).
function New-LegacyOnlyBundle {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("legacy_{0}" -f ([guid]::NewGuid().ToString('N')))
    $inter = Join-Path $tmp 'Intermediate'
    New-Item -ItemType Directory -Path $inter -Force | Out-Null
    foreach ($n in 'DOD_EMAIL_CA-59','DOD_ID_CA-59','DOD_SW_CA-60','DOD_SW_CA-61') {
        Copy-Item -LiteralPath (Join-Path $script:Bundle "$n.cer") -Destination (Join-Path $inter "$n.cer") -Force
    }
    return $tmp
}

Describe 'Test-CertDeployLegacyAllowed - allowlist membership' {
    It 'accepts all four legacy thumbprints (any case)' {
        foreach ($tp in $script:Four) {
            (& $cd { param($t) Test-CertDeployLegacyAllowed $t } $tp)          | Should Be $true
            (& $cd { param($t) Test-CertDeployLegacyAllowed $t } $tp.ToLower()) | Should Be $true
        }
    }
    It 'accepts a thumbprint with spaces (normalizes)' {
        (& $cd { param($t) Test-CertDeployLegacyAllowed $t } '53 FD E0 F4 06 38 BD 1A 68 A6 8D 1E 91 08 90 09 B3 3B AE 5E') | Should Be $true
    }
    It 'rejects a non-allowlisted thumbprint' {
        (& $cd { param($t) Test-CertDeployLegacyAllowed $t } 'DEADBEEF00000000000000000000000000000000') | Should Be $false
        (& $cd { param($t) Test-CertDeployLegacyAllowed $t } '') | Should Be $false
    }
}

Describe 'Convert-CertDeployBundleToJson push filter - deterministic (synthetic bundle)' {
    # CA store: one allowlisted-expired, one NON-allowlisted expired, one valid.
    $fake = @{
        Root = @(); Disallowed = @()
        CA = @(
            @{ Thumbprint = $script:Four[0];                          B64='AA'; NotAfter=(Get-Date).AddYears(-1) }  # allowlisted expired -> KEEP
            @{ Thumbprint = 'DEADBEEF00000000000000000000000000000000'; B64='BB'; NotAfter=(Get-Date).AddYears(-1) }  # dead anchor        -> DROP
            @{ Thumbprint = 'CAFEBABE00000000000000000000000000000001'; B64='CC'; NotAfter=(Get-Date).AddYears( 1) }  # valid              -> KEEP
        )
    }
    It 'default guard: keeps the allowlisted-expired + the valid, DROPS the dead anchor' {
        $ca = @((& $cd { param($b) Convert-CertDeployBundleToJson $b $false } $fake | ConvertFrom-Json).CA | ForEach-Object { $_.t.ToUpper() })
        $ca -contains $script:Four[0]                          | Should Be $true
        $ca -contains 'CAFEBABE00000000000000000000000000000001' | Should Be $true
        $ca -contains 'DEADBEEF00000000000000000000000000000000' | Should Be $false
        $ca.Count | Should Be 2
    }
    It 'includeExpired=$true still includes even the dead anchor (unchanged opt-in)' {
        $ca = @((& $cd { param($b) Convert-CertDeployBundleToJson $b $true } $fake | ConvertFrom-Json).CA | ForEach-Object { $_.t.ToUpper() })
        $ca.Count | Should Be 3
    }
}

Describe 'certdeploy Get-CertDeployBundle census - four legacy allowlisted, not counted as dead anchors' {
    $tmp = New-LegacyOnlyBundle
    try {
        $b = & $cd { param($f) Get-CertDeployBundle -Folder $f } $tmp
        It 'reads all four into the CA group' { @($b.CA).Count | Should Be 4 }
        It 'counts them as LegacyAllowed, NOT Expired' {
            [int]$b.LegacyAllowedCount | Should Be 4
            [int]$b.ExpiredCount       | Should Be 0
        }
        It 'push JSON (default guard) contains all four expired-but-allowlisted certs' {
            $ca = @((& $cd { param($bb) Convert-CertDeployBundleToJson $bb $false } $b | ConvertFrom-Json).CA | ForEach-Object { $_.t.ToUpper() })
            (@($script:Four | Where-Object { $ca -contains $_ }).Count) | Should Be 4
        }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'c2c Get-C2cCertBundle census - fix-pki pushes the four despite expiry' {
    $tmp = New-LegacyOnlyBundle
    try {
        $b = & $c2 { param($f) Get-C2cCertBundle -Folder $f } $tmp
        It 'is Ok with four usable certs (allowlisted-expired are usable, not skipped)' {
            [bool]$b.Ok | Should Be $true
            @($b.CA).Count | Should Be 4
        }
        It 'counts them LegacyAllowed, not Expired' {
            [int]$b.LegacyAllowedCount | Should Be 4
            [int]$b.ExpiredCount       | Should Be 0
        }
        It 'fix-pki push JSON contains all four' {
            $ca = @((& $c2 { param($bb) Convert-C2cBundleToJson $bb } $b | ConvertFrom-Json).CA | ForEach-Object { $_.t.ToUpper() })
            (@($script:Four | Where-Object { $ca -contains $_ }).Count) | Should Be 4
        }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Shipped bundle - the four legacy certs are present + allowlisted end to end' {
    It 'each of the four .cer files exists in Packages\DoD-Certs\Intermediate' {
        foreach ($n in 'DOD_EMAIL_CA-59','DOD_ID_CA-59','DOD_SW_CA-60','DOD_SW_CA-61') {
            (Test-Path -LiteralPath (Join-Path $script:Bundle "$n.cer")) | Should Be $true
        }
    }
    It 'certdeploy reports LegacyAllowedCount >= 4 on the real shipped bundle' {
        $b = & $cd { Get-CertDeployBundle -Folder (Get-CertDeployDefaultBundlePath) }
        [int]$b.LegacyAllowedCount | Should BeGreaterThan 3
    }
}
