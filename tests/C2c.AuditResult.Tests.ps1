# =============================================================================
#  C2c.AuditResult.Tests.ps1 - Pester 3.4 for the host-level audit result mapping
#  (Get-C2cHostAuditResult, loop47 / c2c deep-dive F7, item 55). After a Mass Fix /
#  run-all, each host's run Status is booked to the JANET audit ledger as a
#  VulnPatched result. A PARTIAL host ALWAYS contains >= 1 pillar FAIL (the rollup
#  only reaches PARTIAL when failed >= 1), yet the audit switch mapped PARTIAL ->
#  'Success' with itemCount 1 - a false-compliance ledger record: an inspector
#  reading the audit trail saw a Success for a host that still has a failing pillar.
#  Now PARTIAL audits 'Failure' and only a fully-FIXED host is a Success / counts as
#  a patched item (the row Detail + per-pillar tally keep the granular info).
#
#  Get-C2cHostAuditResult is a pure switch (runs controller-side, module loaded).
#  Run:  Invoke-Pester -Path .\tests\C2c.AuditResult.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
$src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

function Get-Audit {
    param([string]$Status)
    (& $cm { param($s) Get-C2cHostAuditResult -Status $s } $Status)
}

Describe 'Get-C2cHostAuditResult - a PARTIAL host is NOT a compliance Success (F7 fix)' {
    It 'PARTIAL (has >= 1 pillar FAIL) -> Failure, not Success' {
        Get-Audit 'PARTIAL' | Should Be 'Failure'
    }
    It 'FAILED -> Failure' {
        Get-Audit 'FAILED' | Should Be 'Failure'
    }
    It 'NOT VERIFIED (loop44/45 verdicts) -> Failure, never Success' {
        Get-Audit 'NOT VERIFIED' | Should Be 'Failure'
    }
}

Describe 'Get-C2cHostAuditResult - the honest outcomes are unchanged' {
    It 'FIXED -> Success' {
        Get-Audit 'FIXED' | Should Be 'Success'
    }
    It 'NO CHANGE -> Skipped' {
        Get-Audit 'NO CHANGE' | Should Be 'Skipped'
    }
    It 'SKIPPED -> Skipped' {
        Get-Audit 'SKIPPED' | Should Be 'Skipped'
    }
    It 'OFFLINE -> Skipped' {
        Get-Audit 'OFFLINE' | Should Be 'Skipped'
    }
}

Describe 'c2c audit emit - only a fully-FIXED host counts as a patched item (itemCount)' {
    It 'itemCount is 1 only for FIXED (PARTIAL no longer counts as a patched host)' {
        ($src -match "\`$itemCount\s*=\s*if \(\`$row\.Status -eq 'FIXED'\) \{ 1 \} else \{ 0 \}") | Should Be $true
    }
    It 'the old PARTIAL->Success / PARTIAL-counts-as-item forms are gone' {
        ($src -match "'PARTIAL' \{'Success'\}") | Should Be $false
        ($src -match "\`$row\.Status -eq 'FIXED' -or \`$row\.Status -eq 'PARTIAL'") | Should Be $false
    }
}

Describe 'c2c - manifest exact version pin (newest bump = loop-47 PARTIAL audit honesty)' {
    It 'c2c is at v1.15.8' {
        $man = & $cm { Get-JanetToolManifest }
        [string]$man.version | Should Be '1.15.8'
    }
}
