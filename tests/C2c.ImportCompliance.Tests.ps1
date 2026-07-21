# =============================================================================
#  C2c.ImportCompliance.Tests.ps1 - Pester 3.4 for the c2c import compliance
#  count (loop29, c2c deep-dive F4). c2c is a COMPLIANCE-readiness tool, so the
#  "Imported N host(s): X Compliant, Y Non-Compliant" number is the one most
#  likely to be quoted up-chain. The old import counted Compliant as
#  `total - nonCompliant`, so ANY row whose Compliance cell wasn't an explicit
#  "Non-Compliant" - including "Not Assessed" / "Error" / "Unknown" - was folded
#  into the Compliant count. A compliance tool must fail CLOSED: unknown is NOT
#  compliant. Now Compliant is counted only on an explicit ^Compliant match, and
#  unknown states land in a separate "other" bucket.
#
#  Exercises the PUBLIC contract (Invoke-JanetToolAction 'import') - local parse
#  only, no WinRM. Run:  Invoke-Pester -Path .\tests\C2c.ImportCompliance.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$null = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force

function Invoke-C2cImport([string]$Content) {
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_imp_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $p -Value $Content -Encoding UTF8
    try {
        $res = Invoke-JanetToolAction -ActionId 'import' -Params @{ csvPath = $p } -Credential $null -Emit ({ param($e) })
        return $res
    } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
}

Describe 'C2C import - an unknown compliance state is NOT counted Compliant (F4)' {
    # One explicit Compliant, one Non-Compliant, one "Not Assessed" (unknown).
    $csv = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
Compliant,,,HOST1.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Host Firewall",,,HOST2.area52.afnoapps.usaf.mil,1
Not Assessed,,,HOST3.area52.afnoapps.usaf.mil,1
"@
    $summary = (Invoke-C2cImport $csv).summary

    It 'imports all three hosts' {
        $summary.total | Should Be 3
    }
    It 'counts only the explicit Compliant host (NOT the unknown one)' {
        $summary.compliant | Should Be 1
    }
    It 'counts the explicit Non-Compliant host' {
        $summary.nonCompliant | Should Be 1
    }
    It 'puts the unknown "Not Assessed" host in the other bucket, not Compliant' {
        [int]$summary.other | Should Be 1
    }
    It 'compliant + nonCompliant + other == total (no host double-counted or lost)' {
        ([int]$summary.compliant + [int]$summary.nonCompliant + [int]$summary.other) | Should Be ([int]$summary.total)
    }
}

Describe 'C2C import - all-explicit rows are unchanged (no regression, other = 0)' {
    $csv = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
Compliant,,,HOSTX.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Host Firewall",,,HOSTY.area52.afnoapps.usaf.mil,1
"@
    $summary = (Invoke-C2cImport $csv).summary
    It 'compliant 1, non-compliant 1, other 0' {
        $summary.compliant    | Should Be 1
        $summary.nonCompliant | Should Be 1
        [int]$summary.other   | Should Be 0
    }
}

Describe 'c2c - manifest version floor (loop-29 import compliance count landed at 1.15.3)' {
    It 'c2c version is >= 1.15.3 (floor; exact pin lives in the newest bump test)' {
        $man = & (Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru) { Get-JanetToolManifest }
        ([version][string]$man.version -ge [version]'1.15.3') | Should Be $true
    }
}
