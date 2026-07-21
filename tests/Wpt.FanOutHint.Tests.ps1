# =============================================================================
#  Wpt.FanOutHint.Tests.ps1 - loop72 (informative-failures theme). Invoke-WptFanOut
#  is the generic fan-out behind wpt's remote actions; on a per-host FAILURE it now
#  runs the raw error through Get-JanetTroubleshootHint and attaches it to a Hint row
#  field + an err log (FIX:), raw error preserved. Static analysis (the fan-out runs
#  a real RunspacePool; wpt's fan-out tests are static, matching Wpt.ChromeProfiles).
#  Run:  Invoke-Pester -Path .\tests\Wpt.FanOutHint.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

Describe 'wpt 6.8.15 - fan-out attaches a troubleshooting hint to a failed host' {
    It 'manifest version is exactly 6.8.15 (newest bump holds the exact pin)' {
        [string](& $script:Mod { Get-JanetToolManifest }).version | Should Be '6.8.15'
    }
    It 'wpt imports the shared troubleshoot engine' {
        ($script:Src -match "Import-Module.*JanetWeb\.troubleshoot\.psm1") | Should Be $true
    }
    It 'the fan-out computes a hint only for a failure and attaches it to the Hint row field' {
        ($script:Src -match '\$hint\s*=\s*if\s*\(-not\s*\$ok\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($script:Src -match "\`$row\['Hint'\]\s*=\s*\`$hint")                                    | Should Be $true
    }
    It 'the fan-out emits an err log with the FIX hint only when a hint exists' {
        # the err-log emission is gated on $hint, and the log text carries the FIX + hint
        ($script:Src -match "if\s*\(\`$hint\)\s*\{\s*&\s*\`$Send\s*@\{\s*type='log';\s*level='err'") | Should Be $true
        ($script:Src -match 'FIX: \$hint')                                                            | Should Be $true
    }
    It 'the raw error is preserved (the hint never replaces it in the audit detail)' {
        # audit still emits the (untouched) audit-detail string, computed once and reused
        ($script:Src -match '\$auditDetailStr\s*=\s*\[string\]\(&\s*\$AuditDetail\s*\$res\)') | Should Be $true
    }
}
