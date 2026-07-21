# =============================================================================
#  Wpt.KbMatch.Tests.ps1 - Pester 3.4 for the wpt kb-install KB-match rule
#  (Test-WptKbNameMatch, loop22). kb-install matches each requested KB against
#  MECM's not-compliant CCM_SoftwareUpdate set to decide which update to trigger
#  and whether to fall back to an MSU. The old match used `-like "*$kb*"` on the
#  update Name, which let a SHORTER requested KB substring-match a LONGER article
#  (request KB5034 -> update ...KB5034123...): the WRONG update got triggered, the
#  real KB was marked handled, and the MSU fallback was skipped - a false-clean +
#  wrong-action on the most-used tool. The rule now matches ArticleID EXACTLY or
#  the Name's KB token bounded by a non-digit, so KB5034 can NOT match KB5034123.
#
#  Test-WptKbNameMatch is the canonical rule; the kb-install remote scriptblock
#  mirrors it inline (it runs over WinRM and can't call a module function).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Wpt.KbMatch.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

function Test-Match([string]$Name, [string]$Article, [string]$Kb) {
    (& $script:Mod { param($n, $a, $k) Test-WptKbNameMatch -UpdateName $n -ArticleId $a -RequestedKb $k } $Name $Article $Kb)
}

Describe 'Test-WptKbNameMatch - the shorter-KB substring bug is closed' {
    It 'KB5034 does NOT match an update named ...(KB5034123) with article 5034123' {
        Test-Match '2024-05 Cumulative Update (KB5034123)' '5034123' 'KB5034' | Should Be $false
    }
    It 'KB5034 does NOT match by article 5034123 either' {
        Test-Match 'some update' '5034123' 'KB5034' | Should Be $false
    }
    It 'KB5034123 DOES match the update whose article is 5034123 (exact)' {
        Test-Match 'some update' '5034123' 'KB5034123' | Should Be $true
    }
    It 'KB5034123 DOES match by its KB token in the Name when the article is blank' {
        Test-Match '2024-05 Cumulative Update (KB5034123)' '' 'KB5034123' | Should Be $true
    }
    It 'a requested KB does NOT cross-match a different KB in the Name' {
        Test-Match '2024-06 Cumulative Update (KB5040000)' '5040000' 'KB5034123' | Should Be $false
    }
}

Describe 'Test-WptKbNameMatch - boundaries and normalization' {
    It 'the KB token bounded by a non-digit (closing paren) matches' {
        Test-Match 'Update (KB5034)' '' 'KB5034' | Should Be $true
    }
    It 'an exact short article still matches exactly (KB5034 -> article 5034)' {
        Test-Match 'whatever' '5034' 'KB5034' | Should Be $true
    }
    It 'a bare numeric request (no KB prefix) matches the article' {
        Test-Match 'whatever' '5034123' '5034123' | Should Be $true
    }
    It 'lowercase kb prefix normalizes' {
        Test-Match 'Update (KB5034123)' '' 'kb5034123' | Should Be $true
    }
    It 'an empty requested KB never matches' {
        Test-Match 'Update (KB5034123)' '5034123' '' | Should Be $false
    }
}

Describe 'wpt - manifest version floor (loop-22 KB-match fix landed at 6.8.6)' {
    It 'wpt version is >= 6.8.6 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.6') | Should Be $true
    }
}
