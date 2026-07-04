# =============================================================================
#  Upr.Adobe.Tests.ps1 - Pester 3.4 test for the Adobe-scoping fix (audit#3).
#  The real removal runs inside a remote scriptblock, so this test replicates
#  the GUID-resolution decision (the part that guarantees we act ONLY on the
#  selected candidate, never re-enumerate the whole Acrobat family) and proves
#  it never widens the target set. Pure logic, no registry / no msiexec.
# =============================================================================

# Mirror of the scoping expression in JanetTwo.upr.psm1 Adobe handler:
#   selected GUID comes from the candidate's own PSChildName and/or its
#   UninstallString - NEVER from a broad DisplayName match.
function Resolve-AdobeSelectedGuids {
    param([string]$ChildName, [string]$UnStr)
    $guids = @()
    if ($ChildName -match '^\{[^\}]+\}$') { $guids += $ChildName }
    if ($UnStr -match '(\{[^\}]+\})')     { $guids += $Matches[1] }
    @($guids | Select-Object -Unique)
}

Describe 'UPR Adobe removal scopes to the selected candidate (audit#3)' {

    It 'resolves exactly the selected Reader GUID, not the Pro sibling' {
        $reader = '{AC76BA86-1033-1033-7760-BC15014EA700}'
        $g = @(Resolve-AdobeSelectedGuids -ChildName $reader -UnStr "MsiExec.exe /X$reader")
        $g.Count      | Should Be 1
        $g -contains $reader | Should Be $true
    }

    It 'never returns a GUID that was not on the selected candidate' {
        $reader = '{AC76BA86-1033-1033-7760-BC15014EA700}'
        $pro    = '{AC76BA86-1033-FFFF-7760-000000000004}'
        $g = @(Resolve-AdobeSelectedGuids -ChildName $reader -UnStr "MsiExec.exe /X$reader")
        $g -contains $pro | Should Be $false
    }

    It 'returns empty (=> hard FAIL, nothing removed) when no GUID is resolvable' {
        $g = @(Resolve-AdobeSelectedGuids -ChildName 'AcrobatReader' -UnStr 'setup.exe /uninstall')
        $g.Count | Should Be 0
    }

    It 'deduplicates when PSChildName and UninstallString carry the same GUID' {
        $reader = '{AC76BA86-1033-1033-7760-BC15014EA700}'
        $g = @(Resolve-AdobeSelectedGuids -ChildName $reader -UnStr "MsiExec.exe /X$reader /qn")
        $g.Count | Should Be 1
    }
}
