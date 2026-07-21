# =============================================================================
#  Wpt.BulkPatchRv.Tests.ps1 - Pester 3.4 for the bulk-patch trigger-acceptance
#  predicate (loop42, roadmap item42). bulk-patch triggers pending CCM software
#  updates + app installs; it counts a host "triggered" from the client-SDK method's
#  ReturnValue. The update path (:2001) rejected only a non-null NONZERO rv, and the
#  app path (:2027) counted `$null -eq $rv -or 0` - so a NULL ReturnValue (the method
#  returned nothing, did NOT confirm acceptance) fell through to counted-as-triggered
#  and then booked a VulnPatched Success audit. kb-install already fail-closes on a
#  null rv (loop22, :2819: "a method that returned nothing did NOT confirm acceptance").
#  Now bulk-patch matches: accepted ONLY on a non-null 0.
#
#  Get-WptRvAccepted is the pure predicate; the two remote scriptblocks mirror it
#  inline. Run:  Invoke-Pester -Path .\tests\Wpt.BulkPatchRv.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

function Get-Accepted {
    param($Rv)
    (& $script:Mod { param($v) Get-WptRvAccepted -ReturnValue $v } $Rv)
}

Describe 'Get-WptRvAccepted - only a non-null 0 is acceptance (fail-closed on null)' {
    It 'ReturnValue 0 -> accepted' {
        Get-Accepted 0 | Should Be $true
    }
    It 'ReturnValue $null -> NOT accepted (the false-clean fix: null did not confirm acceptance)' {
        Get-Accepted $null | Should Be $false
    }
    It 'ReturnValue 1 (client rejected) -> NOT accepted' {
        Get-Accepted 1 | Should Be $false
    }
    It 'ReturnValue -1 (method threw, sentinel) -> NOT accepted' {
        Get-Accepted (-1) | Should Be $false
    }
}

Describe 'wpt bulk-patch remote scriptblocks - both mirror the fail-closed acceptance test' {
    It 'the update-trigger path accepts only a non-null 0 (old null-fallthrough gone)' {
        # new fail-closed form present at least twice (update + app path)
        (@([regex]::Matches($script:Src, '\$null -ne \$rv -and \[int\]\$rv -eq 0')).Count -ge 2) | Should Be $true
    }
    It 'the old null-accepting app form ($null -eq $rv -or [int]$rv -eq 0) is gone' {
        ($script:Src -match '\$null -eq \$rv -or \[int\]\$rv -eq 0') | Should Be $false
    }
    It 'the old null-fallthrough update form ($null -ne $rv -and [int]$rv -ne 0) is gone' {
        ($script:Src -match '\$null -ne \$rv -and \[int\]\$rv -ne 0') | Should Be $false
    }
}

Describe 'wpt - manifest version floor (null-RV fail-close shipped in 6.8.10; exact pin migrated to newest bump)' {
    It 'wpt is at or past v6.8.10' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.10') | Should Be $true
    }
}
