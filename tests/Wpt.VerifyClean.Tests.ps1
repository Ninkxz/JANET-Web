# =============================================================================
#  Wpt.VerifyClean.Tests.ps1 - Pester 3.4 for the software-uninstall verify-and-clean
#  pass (loop51 / wpt deep-dive item45). After an uninstall reports success, the tool
#  confirms the install folder is gone and removes the orphaned uninstall registry
#  key from the three Uninstall hives. The key removal was UNCONDITIONAL - it ran
#  even when the install folder still existed (FilesRemain), so a still-installed
#  product (files present, row correctly 'Attention') lost its registry entry, and
#  every later REGISTRY-DRIVEN scan (Software Scan / unsupported-product / ACAS) then
#  read the host as clean - a fleet-level self-blinding false-clean. Now the key is
#  removed ONLY when the product's files are actually gone; if files remain, the key
#  is KEPT (the product is still installed, its key is not orphaned).
#
#  The verify-clean pass is an inline scriptblock in the module-less uninstall worker,
#  so this is static analysis. Run:  Invoke-Pester -Path .\tests\Wpt.VerifyClean.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

# Isolate the verify-clean scriptblock ($verifyClean = { ... }).
$script:Blk = ([regex]::Match($script:Src, "(?s)\`$verifyClean = \{.*?FilesRemain = \`$filesRemain")).Value

Describe 'wpt verify-and-clean - the uninstall key is removed only when files are gone (item45 fail-close)' {
    It 'the verify-clean scriptblock was isolated' {
        ($script:Blk.Length -gt 0) | Should Be $true
    }
    It 'the key-removal (Remove-Item of the uninstall key) is GATED, not unconditional' {
        # the remove now lives inside the files-gone (else) branch of `if ($filesRemain) { ...KEPT... } else {`
        ($script:Blk -match "if \(\`$filesRemain\) \{[\s\S]*?else \{[\s\S]*?Remove-Item -LiteralPath \`$kp") | Should Be $true
    }
    It 'when files remain the key is KEPT (not deleted - would hide the still-installed product)' {
        ($script:Blk -match "uninstall key KEPT \(product files still present") | Should Be $true
    }
    It 'the old UNCONDITIONAL key-removal form (removal outside a filesRemain gate) is gone' {
        # the previous shape had `if (-not [string]::IsNullOrWhiteSpace($key)) { $stale=@(); foreach ... Remove-Item`
        # with NO $filesRemain check between; assert the KEPT branch now sits before any Remove-Item.
        $keptIdx = $script:Blk.IndexOf('uninstall key KEPT')
        $rmIdx   = $script:Blk.IndexOf('Remove-Item -LiteralPath $kp')
        ($keptIdx -ge 0 -and $keptIdx -lt $rmIdx) | Should Be $true
    }
}

Describe 'wpt - manifest exact version pin (newest bump = loop-51 verify-clean self-blinding fail-close)' {
    It 'wpt is at v6.8.13' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '6.8.13'
    }
}
