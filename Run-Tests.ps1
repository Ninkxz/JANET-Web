<#
.SYNOPSIS
    JANET Web test runner (Pester 3.4).

.DESCRIPTION
    Before this existed there was no runner and no way to run a subset: the only
    automation was the packaging gate in Sync-TakeToWork.ps1, and `-Tag` is used
    zero times across the suite, so `Invoke-Pester -Tag` filters nothing.

    This filters by FILE NAME instead, which needs no changes to 150+ files.

    -Contract runs only the Platform.*.Tests.ps1 contract files. Those are
    the ones that assert suite-wide invariants (manifests, guard parity, the view
    contract), so they are the fast pre-flight worth running before a commit.

.PARAMETER Contract
    Run only the platform contract tests (fast).

.PARAMETER Area
    Substring matched against test file names, e.g. -Area c2c, -Area Secureboot.

.PARAMETER Detailed
    List every failed test name and message, not just the totals.

.EXAMPLE
    .\Run-Tests.ps1                 # everything
    .\Run-Tests.ps1 -Contract       # platform invariants only
    .\Run-Tests.ps1 -Area wpt       # every test file with 'wpt' in the name
#>
[CmdletBinding()]
param(
    [switch]$Contract,
    [string]$Area,
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'
$root     = $PSScriptRoot
$testsDir = Join-Path $root 'tests'

if (-not (Test-Path $testsDir)) { Write-Error "tests folder not found: $testsDir"; exit 2 }

$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    # HARD failure, deliberately. Sync-TakeToWork.ps1 historically returned
    # Ran=$false when Pester was absent, i.e. a missing test framework degraded
    # into a silent pass. "I could not check" must never read as "it is fine".
    Write-Error 'Pester is not installed. Refusing to report a pass without running the suite.'
    exit 3
}

# IMPORTANT: filter to *.Tests.ps1. tests\ also holds _Janet.TestKit.ps1, which is
# a shared fixture, not a test file, and must never be executed as one.
$files = @(Get-ChildItem -Path $testsDir -Filter '*.Tests.ps1' -File | Sort-Object Name)

if ($Contract) { $files = @($files | Where-Object { $_.Name -like 'Platform.*' }) }
elseif ($Area) { $files = @($files | Where-Object { $_.Name -like ('*' + $Area + '*') }) }

if (-not $files.Count) { Write-Error "no test files matched (Contract=$Contract Area='$Area')"; exit 2 }

Write-Host ("Pester {0}  |  {1} file(s)" -f $pester.Version, $files.Count) -ForegroundColor Cyan

$total = 0; $passed = 0; $failed = 0; $failures = @()
foreach ($f in $files) {
    $r = Invoke-Pester -Path $f.FullName -PassThru -Quiet
    $total  += $r.TotalCount
    $passed += $r.PassedCount
    $failed += $r.FailedCount
    if ($r.FailedCount -gt 0) {
        Write-Host ("  FAIL {0,-52} {1}/{2}" -f $f.Name, $r.FailedCount, $r.TotalCount) -ForegroundColor Red
        $failures += @($r.TestResult | Where-Object { -not $_.Passed } | ForEach-Object {
            [pscustomobject]@{ File = $f.Name; Name = $_.Name; Message = $_.FailureMessage }
        })
    }
}

Write-Host ''
$colour = if ($failed -eq 0) { 'Green' } else { 'Red' }
Write-Host ("FILES: {0}  TESTS: {1}  PASSED: {2}  FAILED: {3}" -f $files.Count, $total, $passed, $failed) -ForegroundColor $colour

if ($Detailed -and $failures.Count) {
    Write-Host ''
    foreach ($x in $failures) {
        Write-Host ("[{0}] {1}" -f $x.File, $x.Name) -ForegroundColor Red
        Write-Host ("    " + (($x.Message -split "`n") | Select-Object -First 3 | ForEach-Object { $_.Trim() }) -join ' | ')
    }
}

exit ([int]($failed -gt 0))
