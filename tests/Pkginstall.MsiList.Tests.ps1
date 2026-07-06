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
