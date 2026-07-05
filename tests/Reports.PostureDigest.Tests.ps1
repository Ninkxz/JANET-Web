# =============================================================================
#  Reports.PostureDigest.Tests.ps1 - Pester 3.4 tests for the 'posture-digest'
#  action: a self-contained HTML + CSV nightly snapshot built by REUSING the
#  existing rollups (Build-CoraSummary, sla-aging, kb-needed, thirdparty-catalog,
#  iavm-board) rather than re-deriving them. Read-only over $script:AcasFindings;
#  the only side effect is writing the two digest files to a caller-given outDir.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Force -PassThru

Describe 'posture-digest: nightly HTML + CSV snapshot' {

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("JanetWeb_PostureDigest_Tests_" + [guid]::NewGuid().ToString('N'))

    $result = & $script:Mod {
        param($OutDir)
        $script:AcasFindings = @(
            [pscustomobject]@{ Hostname='hA'; PluginID='1'; VulnName='Google Chrome vuln';        Severity='Critical'; CVE='CVE-2024-1111'; Category='Other';    Status='Open'; Solution='Upgrade Google Chrome to 120.'; InKEV=$true;  KevCves='CVE-2024-1111'; IAVA='2024-A-0001' }
            [pscustomobject]@{ Hostname='hB'; PluginID='2'; VulnName='Google Chrome vuln';        Severity='High';     CVE='CVE-2024-2222'; Category='Other';    Status='Open'; Solution='Upgrade Google Chrome to 120.'; InKEV=$false; KevCves='';            IAVA='2024-A-0001' }
            [pscustomobject]@{ Hostname='hC'; PluginID='3'; VulnName='Security Update KB5031354'; Severity='High';     CVE='CVE-2024-3333'; Category='KB Patch'; Status='Open'; Solution='Install KB5031354.';           InKEV=$true;  KevCves='CVE-2024-3333'; IAVA='' }
            [pscustomobject]@{ Hostname='hD'; PluginID='4'; VulnName='Mozilla Firefox vuln';      Severity='Medium';   CVE='CVE-2024-4444'; Category='Other';    Status='Open'; Solution='Upgrade Firefox to 121.';       InKEV=$false; KevCves='';            IAVA='' }
            [pscustomobject]@{ Hostname='hE'; PluginID='5'; VulnName='Minor advisory';            Severity='Low';      CVE='';              Category='Other';    Status='Open'; Solution='n/a.';                          InKEV=$false; KevCves='';            IAVA='' }
            [pscustomobject]@{ Hostname='hF'; PluginID='6'; VulnName='Already fixed';             Severity='Critical'; CVE='CVE-2024-9999'; Category='KB Patch'; Status='Patched'; Solution='Install KB1111111.';         InKEV=$true;  KevCves='CVE-2024-9999'; IAVA='' }
        )
        Invoke-JanetToolAction -ActionId 'posture-digest' -Params @{ outDir = $OutDir; title = 'Test Posture Digest' } -Emit { param($e) }
    } $tempDir

    It 'reports ok=true and returns the totals a digest needs' {
        $result.summary.ok            | Should Be $true
        [int]$result.summary.kev      | Should BeGreaterThan 0
        [int]$result.summary.hosts    | Should BeGreaterThan 0
        [int]$result.summary.totalFindings | Should BeGreaterThan 0
    }

    It 'writes a non-empty HTML file that contains the total/KEV numbers' {
        $result.summary.htmlPath | Should Not BeNullOrEmpty
        Test-Path -LiteralPath $result.summary.htmlPath | Should Be $true
        $htmlText = Get-Content -LiteralPath $result.summary.htmlPath -Raw
        $htmlText.Length | Should BeGreaterThan 0
        $htmlText | Should Match ([regex]::Escape([string]$result.summary.totalFindings))
        $htmlText | Should Match ([regex]::Escape([string]$result.summary.kev))
        $htmlText | Should Match 'Test Posture Digest'
    }

    It 'writes a non-empty CSV file next to the HTML' {
        $result.summary.csvPath | Should Not BeNullOrEmpty
        Test-Path -LiteralPath $result.summary.csvPath | Should Be $true
        $csvText = Get-Content -LiteralPath $result.summary.csvPath -Raw
        $csvText.Length | Should BeGreaterThan 0
        $csvText | Should Match '^Section,Metric,Value,Detail'
        $csvText | Should Match 'OpenFindings'
    }

    It 'returns one row per written file (Name / Path / Kind / Bytes)' {
        @($result.rows).Count | Should Be 2
        $kinds = @($result.rows | ForEach-Object { $_.Kind })
        ($kinds -contains 'HTML') | Should Be $true
        ($kinds -contains 'CSV')  | Should Be $true
        foreach ($r in $result.rows) { [int]$r.Bytes | Should BeGreaterThan 0 }
    }

    It 'creates outDir when it does not already exist' {
        Test-Path -LiteralPath $tempDir | Should Be $true
    }

    # Clean up the temp digest files/folder.
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'posture-digest: empty-findings guard' {

    $result = & $script:Mod {
        $script:AcasFindings = New-Object System.Collections.ArrayList
        Invoke-JanetToolAction -ActionId 'posture-digest' -Params @{ outDir = (Join-Path ([System.IO.Path]::GetTempPath()) 'JanetWeb_PostureDigest_ShouldNotBeCreated') } -Emit { param($e) }
    }

    It 'returns ok=false and writes nothing when no findings are loaded' {
        $result.summary.ok | Should Be $false
        @($result.rows).Count | Should Be 0
    }
}
