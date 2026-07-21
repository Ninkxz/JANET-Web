# =============================================================================
#  Acas.BumpVerdict.Tests.ps1 - Pester 3.4 for Get-AcasBumpVerdict (loop39, item36).
#  The acas update worker confirms a remediation ("bumped" -> OK -> lights the PATCHED
#  tile + books a VulnPatched Success audit) by comparing the pre/post verify version.
#  It formerly declared a bump on ANY preV != postV string inequality, so a post-probe
#  that degraded to a sentinel it emits when it could NOT read a current version
#  ('error' on a caught probe, 'n/a' on a vanished key, 'not installed'), or a numeric
#  DOWNGRADE, counted as a confirmed patch. Now a degraded post or a downgrade reads
#  'unconfirmed' (the worker returns UNCONFIRMED, never OK). Log4j's 'none' (clean) and
#  a non-version state transition (spec-exec -> COMPLIANT) are NOT degraded -> stay confirmed.
#
#  Get-AcasBumpVerdict is the PURE canonical twin; the module-less update worker mirrors
#  it inline. Run:  Invoke-Pester -Path .\tests\Acas.BumpVerdict.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw

function Get-Verdict {
    param([string]$Pre, [string]$Post)
    (& $script:Mod { param($a,$b) Get-AcasBumpVerdict -PreV $a -PostV $b } $Pre $Post)
}

Describe 'Get-AcasBumpVerdict - a degraded post-probe is NOT a confirmed bump (item36 fail-close)' {
    It 'post degraded to error -> unconfirmed (was booked as a patch)' {
        Get-Verdict '1.401.2410.0' 'error' | Should Be 'unconfirmed'
    }
    It 'post degraded to n/a -> unconfirmed' {
        Get-Verdict '16.0.17328.20124' 'n/a' | Should Be 'unconfirmed'
    }
    It 'post degraded to not installed -> unconfirmed' {
        Get-Verdict '120.0.6099.130' 'not installed' | Should Be 'unconfirmed'
    }
    It 'a numeric DOWNGRADE (post < pre) -> unconfirmed' {
        Get-Verdict '121.0.6100.0' '120.0.6099.130' | Should Be 'unconfirmed'
    }
    It 'equal versions -> unconfirmed (defensive; the caller already rules out pre==post)' {
        Get-Verdict '120.0.1' '120.0.1' | Should Be 'unconfirmed'
    }
}

Describe 'Get-AcasBumpVerdict - a genuine forward change stays confirmed (no regression)' {
    It 'a real forward version bump -> confirmed' {
        Get-Verdict '120.0.6099.130' '121.0.6100.0' | Should Be 'confirmed'
    }
    It 'installing a missing product (pre not installed -> a version) -> confirmed' {
        Get-Verdict 'not installed' '2.0.0.0' | Should Be 'confirmed'
    }
    It 'Log4j clean (pre a vulnerable version -> none) -> confirmed (none is clean, not degraded)' {
        Get-Verdict '2.14.1' 'none' | Should Be 'confirmed'
    }
    It 'spec-exec state transition VULNERABLE -> COMPLIANT -> confirmed (non-version, not degraded)' {
        Get-Verdict 'VULNERABLE' 'COMPLIANT' | Should Be 'confirmed'
    }
}

Describe 'acas update worker - the inline bump mirror carries the degraded/downgrade guard' {
    It 'the worker mirror lists the degraded post sentinels and a version downgrade check' {
        ($script:Src -match "bumpDegraded\s*=\s*@\('error','n/a','not installed'\)") | Should Be $true
        ($script:Src -match "bumpPostVer -le \`$bumpPreVer") | Should Be $true
    }
}

Describe 'acas - manifest version floor (bump-verdict shipped in 1.11.11; exact pin migrated to newest bump)' {
    It 'acas is at or past v1.11.11' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.11') | Should Be $true
    }
}
