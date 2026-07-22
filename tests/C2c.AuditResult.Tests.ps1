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

Describe 'c2c - manifest version floor (exact pin migrated to the newest bump: loop77 hint Describe, v1.15.9)' {
    It 'c2c is at least v1.15.8' {
        $man = & $cm { Get-JanetToolManifest }
        ([version][string]$man.version -ge [version]'1.15.8') | Should Be $true
    }
}

# loop77 (informative-failures theme): the c2c Mass-Fix / run-all harvest ($emitResult) now, on a host
# whose audit result is Failure, runs the raw error in $res.Detail through Get-JanetTroubleshootHint and
# attaches the hint to a Hint row field + an err log (FIX:), raw detail preserved. Static analysis (the
# harvest runs inside the fan-out over a real RunspacePool).
Describe 'c2c 1.15.9 - fix harvest attaches a troubleshooting hint to a failed host' {
    $man = & $cm { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

    It 'manifest version is at or past 1.15.9 (Mass-Fix hint; exact pin migrated to newest bump)' {
        ([version][string]$man.version -ge [version]'1.15.9') | Should Be $true
    }
    It 'c2c imports the shared troubleshoot engine' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1') | Should Be $true
    }
    It 'the fix harvest computes a hint only for a Failure host and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\$auditResult\s*-eq\s*''Failure''\s*-and\s*\$res\.Detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($src -match 'Detail=\[string\]\$res\.Detail;\s*Hint=\[string\]\$hint') | Should Be $true
    }
    It 'the Mass-Fix err log carries the FIX hint when one exists' {
        ($src -match "if \(\`$hint\) \{ &\s*\`$send @\{ type='log'; level='err'") | Should Be $true
        ($src -match 'FIX: \$hint')                                             | Should Be $true
    }
}

# loop82 (informative-failures follow-up): the two READ-ONLY c2c harvests - the readiness SCAN and the
# VERSION-CHECK - now attach a hint to a failure host. Scan: on Status CHECK ERRORS (ERROR/DNS MISMATCH
# collapse to it) the raw Detail runs through the engine. Version-check: scoped to $lvl -eq 'error' (OFFLINE +
# unknown) so a version string in a healthy Detail cannot false-match a numeric signature. Both mutate
# $row['Hint'] + a row-based FIX: err log. Static analysis (both harvests run inside a fan-out over a real pool).
Describe 'c2c 1.15.10 - read-only scan + version-check harvests attach a hint to a failure host' {
    $man = & $cm { Get-JanetToolManifest }
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

    It 'manifest version is exactly 1.15.10 (newest bump holds the exact pin)' {
        [string]$man.version | Should Be '1.15.10'
    }
    It 'the scan harvest computes a hint only for a CHECK ERRORS host' {
        ($src -match '\$hint\s*=\s*if\s*\(\$row\.Status\s*-eq\s*''CHECK ERRORS''\s*-and\s*\$row\.Detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
    }
    It 'the version-check harvest scopes the hint to error-level statuses (not a version-number false match)' {
        ($src -match '\$hint\s*=\s*if\s*\(\$lvl\s*-eq\s*''error''\s*-and\s*\$row\.Detail\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
    }
    It 'both read-only harvests mutate the row Hint and emit a row-based gated FIX err log' {
        # the $row['Hint'] mutation form is unique to the read-only harvests (Mass-Fix uses a row literal) -> 2
        ([regex]::Matches($src, "if \(\`$hint\) \{ \`$row\['Hint'\] = \[string\]\`$hint \}").Count) | Should Be 2
        # the row-based err log ($row.Host, not Mass-Fix's $res.Host) -> exactly the two read-only paths
        ([regex]::Matches($src, "level='err'; text=`"\`$\(\[string\]\`$row\.Host\).*FIX: \`$hint").Count) | Should Be 2
    }
}
