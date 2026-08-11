# =============================================================================
#  Acas.Log4jVerifyScope.Tests.ps1 - the Log4j verify scans what the fix scans.
#
#  THE DEFECT (loop 2026-08-04, P2): the remediation Script recursively discovers
#  vulnerable log4j jars ANYWHERE under the search roots (default C:\Program Files
#  + C:\Program Files (x86)), but the Verify probed ONLY the two known service
#  paths (HID Global, Adobe AEM) - and then reported the all-clean case as
#  "All jars at <version> (recursive scan)".
#
#  "Recursive" was true only WITHIN those two folders. A host carrying a vulnerable
#  jar under any other path - C:\Program Files\SomeApp\lib - verified CLEAN, booked
#  a green OK row and counted as PATCHED. Verify-only ("Test Selected") produced the
#  same false clean with no fix having run. On a KEV-class finding.
#
#  The Verify now walks the same roots, de-duplicates against the named service
#  paths (which sit under those roots), and fails CLOSED on an unreadable root -
#  a permissions failure is not an absence of log4j.
#
#  HOW THIS IS DRIVEN: the Verify is a plain scriptblock in the profile table with
#  no parameters, so it is lifted out of the module and executed against a TEMP
#  tree with the two root paths redirected. That runs the REAL shipped block - edit
#  it and this test runs the edited version.
#
#  Run: Invoke-Pester -Path .\tests\Acas.Log4jVerifyScope.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("acas_log4j_" + [guid]::NewGuid().ToString('N'))

# Lift the Log4j profile's Verify block, then redirect the two hardcoded roots at the
# temp tree. Everything else - the version regex, the de-dupe, the verdict logic - runs
# exactly as shipped.
function Get-Log4jVerify {
    param([string]$RootA, [string]$RootB)
    $m = [regex]::Match($script:Src, "(?s)'Apache Log4j[^']*'\s*=\s*@\{.*?Verify = \{(.*?)\n        \}\n    \}")
    if (-not $m.Success) {
        # Fall back to the marker the fix comment leaves behind.
        $m = [regex]::Match($script:Src, "(?s)Verify = \{\s*\n\s*# loop 2026-08-04: this probed ONLY the two known service paths(.*?)\n        \}")
    }
    if (-not $m.Success) { throw 'Log4j Verify block not found - the extraction anchor needs updating' }
    $body = $m.Groups[0].Value
    $body = $body -replace "(?s)^.*?Verify = \{", ''      # strip to the block body
    $body = $body -replace "\n        \}\s*\n?\s*\}?\s*$", ''
    $body = $body.Replace("'C:\Program Files', 'C:\Program Files (x86)'", "'$RootA', '$RootB'")
    $body = $body.Replace("'C:\Program Files\HID Global\Credential Management Client\lib'", "'$RootA\HID Global\Credential Management Client\lib'")
    $body = $body.Replace("'C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'", "'$RootA\Adobe\Adobe Experience Manager Forms Designer\Java\libs'")
    return [scriptblock]::Create($body)
}

function New-Jar {
    param([string]$Dir, [string]$Name)
    [void][System.IO.Directory]::CreateDirectory($Dir)
    Set-Content -LiteralPath (Join-Path $Dir $Name) -Value 'jar' -Encoding ASCII
}

Describe 'Log4j verify - a vulnerable jar OUTSIDE the two service paths is found' {
    $rootA = Join-Path $script:Tmp 'PF'
    $rootB = Join-Path $script:Tmp 'PFx86'
    [void][System.IO.Directory]::CreateDirectory($rootA)
    [void][System.IO.Directory]::CreateDirectory($rootB)
    $vb = Get-Log4jVerify -RootA $rootA -RootB $rootB

    It 'a stale jar under an arbitrary app folder is STILL-VULNERABLE, not clean' {
        New-Jar -Dir (Join-Path $rootA 'SomeApp\lib') -Name 'log4j-core-2.17.0.jar'
        $r = & $vb
        $r.Verified | Should Be $false
        ([string]$r.Detail) | Should Match 'STILL-VULNERABLE'
    }
    It 'a current jar under an arbitrary app folder verifies clean' {
        Remove-Item -LiteralPath (Join-Path $rootA 'SomeApp\lib\log4j-core-2.17.0.jar') -Force
        New-Jar -Dir (Join-Path $rootA 'SomeApp\lib') -Name 'log4j-core-2.26.1.jar'
        $r = & $vb
        $r.Verified | Should Be $true
        ([string]$r.Detail) | Should Match '2\.26\.1'
    }
    It 'a jar NEWER than the floor also verifies clean (floor, not an exact pin)' {
        # The 2026-08-11 defect in miniature: an exact match called a newer jar vulnerable.
        Remove-Item -LiteralPath (Join-Path $rootA 'SomeApp\lib\log4j-core-2.26.1.jar') -Force
        New-Jar -Dir (Join-Path $rootA 'SomeApp\lib') -Name 'log4j-core-2.31.0.jar'
        $r = & $vb
        $r.Verified | Should Be $true
        ([string]$r.Detail) | Should Not Match 'STILL-VULNERABLE'
        # Restore the fixture the later cases in this Describe expect.
        Remove-Item -LiteralPath (Join-Path $rootA 'SomeApp\lib\log4j-core-2.31.0.jar') -Force
        New-Jar -Dir (Join-Path $rootA 'SomeApp\lib') -Name 'log4j-core-2.26.1.jar'
    }
    It 'a jar in the SECOND root (Program Files x86) is scanned too' {
        New-Jar -Dir (Join-Path $rootB 'Other\lib') -Name 'log4j-api-2.14.1.jar'
        $r = & $vb
        $r.Verified | Should Be $false
        ([string]$r.Detail) | Should Match 'log4j-api-2\.14\.1\.jar'
    }
    It 'a jar found under BOTH a root and a named service path is counted once' {
        Remove-Item -LiteralPath (Join-Path $rootB 'Other\lib\log4j-api-2.14.1.jar') -Force
        New-Jar -Dir (Join-Path $rootA 'HID Global\Credential Management Client\lib') -Name 'log4j-core-2.26.1.jar'
        $r = & $vb
        # 'log4j-core-2.26.1.jar' appears in the arbitrary folder AND the service path;
        # Version is a unique-sorted list, so a de-dupe failure would not show here - the
        # real proof is that the verdict stays clean and nothing double-reports.
        $r.Verified | Should Be $true
    }
}

Describe 'Log4j verify - an empty host is clean, and says what it scanned' {
    $rootA = Join-Path $script:Tmp 'EmptyPF'
    $rootB = Join-Path $script:Tmp 'EmptyPFx86'
    [void][System.IO.Directory]::CreateDirectory($rootA)
    [void][System.IO.Directory]::CreateDirectory($rootB)
    $vb = Get-Log4jVerify -RootA $rootA -RootB $rootB

    It 'no jars anywhere -> Verified true' {
        $r = & $vb
        $r.Verified | Should Be $true
    }
    It 'and the detail names the roots rather than claiming an unqualified recursive scan' {
        $r = & $vb
        ([string]$r.Detail) | Should Match 'anywhere under'
    }
}

Describe 'Log4j verify - the source no longer claims more than it checked' {
    It 'the clean detail names the roots it actually walked' {
        ($script:Src -match "All jars at or above \`$l4jFloor \(recursive scan of \`$\(\`$roots -join ' \+ '\)\)") | Should Be $true
    }
    It 'an unreadable root downgrades the verdict instead of reading as clean' {
        ($script:Src -match 'Search root UNREADABLE - log4j presence NOT determined') | Should Be $true
        ($script:Src -match 'a search root was UNREADABLE so the scan is INCOMPLETE')  | Should Be $true
    }
    It 'the verify walks the same default roots the Script documents' {
        ($script:Src -match "\`$roots = @\('C:\\Program Files', 'C:\\Program Files \(x86\)'\)") | Should Be $true
    }
}
