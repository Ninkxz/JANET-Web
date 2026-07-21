# =============================================================================
#  Acas.KbMatch.Tests.ps1 - Pester 3.4 for the acas kb-install KB-match rule
#  (Test-AcasKbNameMatch, loop27 / roadmap item 21). The acas kb-install worker
#  carried the SAME loose match wpt fixed in loop 22: `-like "*$kb*"` on the MECM
#  update Name, which let a SHORTER requested KB substring-match a LONGER article
#  (request KB5034 -> update ...KB5034123...): the WRONG update was triggered, the
#  real KB marked handled, and the MSU fallback skipped. The rule now matches
#  ArticleID EXACTLY or the Name's KB token bounded by a non-digit, so KB5034 can
#  NOT match KB5034123 - a port of wpt's Test-WptKbNameMatch into the acas module.
#
#  Test-AcasKbNameMatch is the canonical rule; the acas MECM remote scriptblock
#  mirrors it inline (it runs over WinRM, can't call a module function).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.KbMatch.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Test-Match([string]$Name, [string]$Article, [string]$Kb) {
    (& $script:Mod { param($n, $a, $k) Test-AcasKbNameMatch -UpdateName $n -ArticleId $a -RequestedKb $k } $Name $Article $Kb)
}

Describe 'Test-AcasKbNameMatch - the shorter-KB substring bug is closed (wpt loop-22 parity)' {
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

Describe 'Test-AcasKbNameMatch - boundaries and normalization' {
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

Describe 'acas - manifest exact version pin (newest bump = loop-27 kb-install KB-match parity)' {
    It 'acas is at v1.11.8' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '1.11.8'
    }
}
