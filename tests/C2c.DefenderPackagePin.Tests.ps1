# =============================================================================
#  C2c.DefenderPackagePin.Tests.ps1 - loop-1 design: pin the offline Defender
#  package (mpam-fe.exe) SHA256 across validate->push. These tests lock the
#  ADMIN-SIDE capture + the reject paths of the gate so a future feature commit
#  can't silently regress them. The on-target re-hash needs a live host + a real
#  staged package -> pilot-pending (documented, not unit-tested).
#
#  Run:  Invoke-Pester -Path .\tests\C2c.DefenderPackagePin.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

Describe 'C2C offline Defender package - SHA256 capture (Resolve-C2cDefenderPackage)' {
    It 'returns a result carrying a Sha256 field (empty when the shipped folder holds no package)' {
        $res = & $script:Mod { Resolve-C2cDefenderPackage }
        $res | Should Not BeNullOrEmpty
        # empty DefenderDefinitions (README-only) -> no package resolved -> empty pin, consistent shape
        ([string]$res.Sha256) | Should Be ''
        ([string]$res.Path)   | Should Be ''
    }
}

Describe 'C2C offline Defender package - validation gate reject paths (Test-C2cDefenderPackage)' {
    It 'rejects a missing path' {
        (& $script:Mod { param($p) Test-C2cDefenderPackage $p } 'X:\definitely\not\here\mpam-fe.exe') | Should Match '(?i)not found'
    }
    It 'rejects a too-small file BEFORE any signature/identity check (the 50MB floor)' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mpamtest_" + [guid]::NewGuid().ToString('N') + ".exe")
        Set-Content -LiteralPath $tmp -Value 'not a real package' -Encoding Ascii
        try { (& $script:Mod { param($p) Test-C2cDefenderPackage $p } $tmp) | Should Match '(?i)too small' }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'never returns OK for a non-Microsoft-signed file (fail-closed)' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mpamtest_" + [guid]::NewGuid().ToString('N') + ".exe")
        # 51 MB of zeros: passes the size floor, has no valid Authenticode signature -> must NOT be OK
        $fs = [System.IO.File]::Create($tmp); try { $fs.SetLength(51MB) } finally { $fs.Close() }
        try { (& $script:Mod { param($p) Test-C2cDefenderPackage $p } $tmp) | Should Not Be 'OK' }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
