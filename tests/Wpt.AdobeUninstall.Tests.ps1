# =============================================================================
#  Wpt.AdobeUninstall.Tests.ps1 - Pester 3.4 for the Adobe Acrobat uninstall branch
#  (loop52 / wpt deep-dive item46). Adobe Acrobat installs multiple MSI product-code
#  GUIDs across both Uninstall hives, so the uninstall branch msiexec /x each one.
#  It set $removed=$true if ANY one GUID uninstalled, with per-GUID failures NOT
#  tracked, and read 'Removed' - so a PARTIAL uninstall (one GUID gone, others
#  failed / locked) reported a clean Removed (which the software-uninstall counter
#  at :5265 books ok) while Adobe was still installed via the failed GUIDs. Now the
#  branch counts per-GUID success/failure: all GUIDs removed -> 'Removed'; some
#  failed while others succeeded -> 'Attention' (a not-clean bucket, not counted ok);
#  all failed -> the default 'Failed'.
#
#  The Adobe branch is an inline scriptblock in the module-less uninstall worker, so
#  this is static analysis. Run:  Invoke-Pester -Path .\tests\Wpt.AdobeUninstall.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

# Isolate the Adobe Acrobat branch (from its `if ($name -match 'Adobe Acrobat')` to the results.Add + continue).
$script:Blk = ([regex]::Match($script:Src, "(?s)if \(\`$name -match 'Adobe Acrobat'\) \{.*?App=\`$name; Type=\`$type; Result=\`$result.*?continue")).Value

Describe 'wpt Adobe Acrobat uninstall - a PARTIAL GUID removal is Attention, not a clean Removed (item46 fail-close)' {
    It 'the Adobe branch was isolated' {
        ($script:Blk.Length -gt 0) | Should Be $true
    }
    It 'per-GUID failures are counted (not discarded)' {
        ($script:Blk -match '\$adobeFail\+\+') | Should Be $true
    }
    It "a partial removal (some GUIDs failed while others succeeded) -> 'Attention', not 'Removed'" {
        ($script:Blk -match "if \(\`$adobeFail -gt 0 -and \`$adobeOk -gt 0\) \{ \`$result='Attention'") | Should Be $true
    }
    It "the old unconditional 'any-GUID-ok -> Removed' shape is gone (Removed no longer sits before the partial check)" {
        # the Attention (partial) check must precede the Removed assignment in the result decision
        $attIdx = $script:Blk.IndexOf("\$result='Attention'")
        $remIdx = $script:Blk.IndexOf("\$result='Removed'")
        # IndexOf on the literal (regex-escaped chars differ); fall back to plain tokens
        $attIdx = $script:Blk.IndexOf("'Attention'")
        $remIdx = $script:Blk.IndexOf("Adobe removed via MSI")
        ($attIdx -ge 0 -and $attIdx -lt $remIdx) | Should Be $true
    }
}

Describe 'wpt software-uninstall - only an exact Removed counts ok (Attention drops out)' {
    It 'the uninstall ok predicate is Result -eq Removed (Attention/Failed are not ok)' {
        ($script:Src -match "\`$isOk = \(\`$rst -eq 'Removed'\)") | Should Be $true
    }
}

Describe 'wpt - manifest version floor (exact pin migrated to the newest bump: loop72 fan-out hint, v6.8.15)' {
    It 'wpt is at least v6.8.14' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.14') | Should Be $true
    }
}
