# =============================================================================
#  Pkginstall.MsiList.Tests.ps1 - ConvertTo-JanetMsiList must keep in-bundle
#  relative paths but reject rooted / '..'-traversal entries (a pasted MSI list
#  is the only place a traversal could enter the copy). Defense-in-depth.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Force -PassThru

Describe 'ConvertTo-JanetMsiList: keep in-bundle paths, reject traversal' {

    It 'keeps a plain filename and a subdir entry' {
        $r = & $script:Mod { ConvertTo-JanetMsiList "foo.msi`r`nx64\bar.msi" }
        ($r -contains 'foo.msi')     | Should Be $true
        ($r -contains 'x64\bar.msi') | Should Be $true
        @($r).Count | Should Be 2
    }

    It 'drops a parent-traversal entry (..\)' {
        $r = @(& $script:Mod { ConvertTo-JanetMsiList "ok.msi`n..\..\Windows\System32\evil.msi" })
        ($r -contains 'ok.msi') | Should Be $true
        ($r -join '|') | Should Not Match '\.\.'
        @($r).Count | Should Be 1
    }

    It 'drops a mid-path .. segment (sub\..\..\evil.msi)' {
        $r = @(& $script:Mod { ConvertTo-JanetMsiList 'sub\..\..\evil.msi' })
        @($r).Count | Should Be 0
    }

    It 'drops a drive-rooted path (C:\...)' {
        $r = @(& $script:Mod { ConvertTo-JanetMsiList "keep.msi`nC:\Windows\evil.msi" })
        ($r -contains 'keep.msi') | Should Be $true
        @($r).Count | Should Be 1
    }

    It 'drops a UNC / backslash-rooted path' {
        $r = @(& $script:Mod { ConvertTo-JanetMsiList "a.msi`n\\server\share\evil.msi`n\rooted.msi" })
        @($r).Count | Should Be 1
        ($r -contains 'a.msi') | Should Be $true
    }

    It 'returns empty for blank input (caller then discovers *.msi in the bundle)' {
        @(& $script:Mod { ConvertTo-JanetMsiList '   ' }).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
# loop60 (item67): msiexec exit 1638 = "another version already installed" - msiexec REFUSED to
# install and NOTHING changed, and the installed version is NOT verified >= the package (may still
# be the OLD vulnerable one). It was mapped to 'AlreadyCompliant' -> host Status 'Success' ->
# VulnPatched/Success/itemCount=1, a false "patched" audit for an untouched, possibly-vulnerable
# host. Now the all-1638 host resolves to 'AlreadyInstalled' -> Skipped/itemCount 0. Static analysis
# (the per-MSI mapping + aggregate live inside the module-less runspace worker $RpiDeployHostScript).
Describe 'pkginstall 2.5.9 - all-1638 MSI host is Skipped, not a false VulnPatched Success' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Raw

    It 'manifest version is at least 2.5.9 (floor; newest exact pin = loop61 PSADT Describe, v2.5.10)' {
        ([version][string]$mani.version -ge [version]'2.5.9') | Should Be $true
    }
    It 'the all-1638 aggregate sets host Status AlreadyInstalled (not Success)' {
        ($src -match '\$installedCount\s*-eq\s*\$totalCount') | Should Be $true
        ($src -match "\`$res\.Status\s*=\s*'AlreadyInstalled'") | Should Be $true
    }
    It 'the harvest routes AlreadyInstalled to the skipped bucket, not ok/fail' {
        ($src -match "'AlreadyInstalled'\s*\{\s*\`$skipCount\+\+") | Should Be $true
    }
    It 'the audit maps AlreadyInstalled to Skipped (itemCount 0, no false VulnPatched)' {
        ($src -match "'AlreadyInstalled'\s*\{\s*'Skipped'") | Should Be $true
    }
    It 'the old false "treated as already compliant" wording is gone' {
        ($src -match 'treated as already compliant') | Should Be $false
    }
}

# -----------------------------------------------------------------------------
# loop61 (item68): the PSADT deploy branch pre-seeded $LASTEXITCODE=0, so a Deploy-Application.ps1
# that returns WITHOUT calling exit/Exit-Script (sets no exit code) left the pre-seeded 0 and was
# booked Status 'Success' + VulnPatched though nothing installed. Now pre-seed $null and catch a
# null exit as Failed BEFORE the success-exit check. Static analysis (the branch lives inside the
# module-less runspace worker $RpiDeployHostScript).
Describe 'pkginstall 2.5.10 - a PSADT deploy that sets no exit code is Failed, not a false Success' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Raw

    It 'manifest version is at least 2.5.10 (floor; newest exact pin = loop62 SelfGuard gate Describe, v2.5.11)' {
        ([version][string]$mani.version -ge [version]'2.5.10') | Should Be $true
    }
    It 'pre-seeds $LASTEXITCODE to $null, not 0' {
        ($src -match '\$global:LASTEXITCODE\s*=\s*\$null') | Should Be $true
        ($src -match '\$global:LASTEXITCODE\s*=\s*0\b')    | Should Be $false
    }
    It 'catches a null exit code as Failed BEFORE the success-exit check (so null cannot match exit 0)' {
        $idxNull = $src.IndexOf('$null -eq $exitCode')
        $idxSucc = $src.IndexOf('$successExits -contains $exitCode')
        ($idxNull -gt 0) | Should Be $true
        ($idxSucc -gt 0) | Should Be $true
        ($idxNull -lt $idxSucc) | Should Be $true
        ($src -match 'returned no exit code') | Should Be $true
    }
}
