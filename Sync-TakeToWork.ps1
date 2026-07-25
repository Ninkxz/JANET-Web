# Sync JANET Web -> a timestamped "take to work" zip in X:\Archive.
#
# Stages a clean copy of the suite in %TEMP%, gates it, then zips it as
# X:\Archive\JANETWEB_TakeToWork_<stamp>.zip.
#
# SHIPPED:
#   Launch JANET Web.cmd, DO NOT RUN - JanetWeb.Internal.ps1, README.md
#   modules\  server\  web\
#   Packages\           - folder skeleton + payloads (READMEs, PKI-Fix scripts,
#                         staged mpam-fe.exe) but NO CERTIFICATES (see below)
#   JanetLocal\<files>  - top-level reference files only (c2c-baseline.json,
#                         KevCatalog.txt, IavmMap.csv, catalogs, ...).
#                         Runtime state (campaigns\, sla-ledger.json) stays local.
#
# NOT SHIPPED (policy 2026-07-17, per operator):
#   - CERTIFICATES: no certificate or key container ships in the zip, anywhere
#     (.cer/.crt/.der/.pem/.p7b/.sst/... - see $certExtPublic below).
#     DoD-Certs / PKI-Fix\Certs ship as empty folder skeletons; the operator
#     drops the cert bundles into the Packages folder ON THE WORK MACHINE.
#     The cert tools fail closed on an empty bundle by design.
#   - tests\  (Pester dev gate - dev-side only)
#   - docs\   (design history - dev-side only)
#
# GATES (all must pass or NO zip is produced):
#   1. certificates - no cert/key container may be staged, and no PRIVATE-KEY
#      container (.pfx/.p12/...) may exist anywhere in the source tree - swept
#      whole-repo, not just the folders we package from (audit 2026-07-25).
#   2. parse sweep  - every staged .ps1/.psm1 must parse.
#   3. Pester suite - tests\ must be green (Pester 3.x syntax).
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File '.\Sync-TakeToWork.ps1'
#   powershell.exe -ExecutionPolicy Bypass -File '.\Sync-TakeToWork.ps1' -GateOnly
#     ^ dry run: stage + run all three gates, report, then throw the stage away
#       WITHOUT writing a zip. Use this to prove the gates before a real cut.

[CmdletBinding()]
param(
    [string]$ZipDir = 'X:\Archive',
    # Dry run - exercise the gates, skip the zip (audit 2026-07-24).
    [switch]$GateOnly
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot

# Certificate / key-container extensions, in two tiers (audit 2026-07-24).
# The old gate was a 4-extension allowlist (.cer/.crt/.p7b/.sst), so .pfx, .p12,
# .pem and .der sailed straight through it and shipped SILENTLY.
#   $certExtPublic  - public cert / chain containers. Withheld from the stage and
#                     gated: bad to ship, but they carry no secret.
#   $certExtPrivate - containers that can hold a PRIVATE KEY. Withheld too, but
#                     finding one anywhere in the source is a HARD FAILURE, not a
#                     warning: a key in the tree is an incident, and it must not
#                     be quietly counted as "n certificate file(s) withheld".
$certExtPublic  = @('.cer', '.crt', '.cert', '.der', '.pem', '.p7b', '.p7c', '.p7s', '.sst', '.crl')
$certExtPrivate = @('.pfx', '.p12', '.pvk', '.key', '.jks', '.keystore')
$certExt        = $certExtPublic + $certExtPrivate

# --- Gate helpers ----------------------------------------------------------
# Before this the sync gated on cert extensions ONLY, so a file with a syntax
# error or a red test could be packaged and carried to a closed network - where
# there is no way to fix it. Both helpers report EVERYTHING they find (they never
# throw) so one run tells the operator the whole story. (audit 2026-07-24)

function Invoke-JwParseGate {
    # Parses every staged .ps1/.psm1 with the PowerShell parser itself, so the
    # gate agrees exactly with what the work machine will refuse to load.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)

    $failures = @()
    # -LiteralPath + Where-Object rather than -Include: the repo root has a SPACE
    # in it and -Include/-Path wildcard combinations have bitten us here before.
    $files = @(Get-ChildItem -LiteralPath $Root -Recurse -File |
               Where-Object { @('.ps1', '.psm1') -contains $_.Extension.ToLower() })
    foreach ($f in $files) {
        $tokens = $null
        $errors = $null
        try {
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
        } catch {
            # Unreadable/locked file - count it as a failure instead of aborting
            # the sweep, so the operator still sees the rest of the results.
            $failures += [pscustomobject]@{ Path = $f.FullName; Line = 0; Message = $_.Exception.Message }
            continue
        }
        foreach ($e in @($errors)) {
            $failures += [pscustomobject]@{
                Path    = $f.FullName
                Line    = $e.Extent.StartLineNumber
                Message = $e.Message
            }
        }
    }
    [pscustomobject]@{
        FileCount = $files.Count
        Failures  = @($failures)
        Ok        = (@($failures).Count -eq 0)
    }
}

function Invoke-JwTestGate {
    # Pester here is 3.4.0, NOT Pester 5: v3 syntax is -Script/-Path + -PassThru
    # + -Quiet, then read .FailedCount. v5 renamed all of it, so pin the family
    # we actually speak rather than letting a future v5 install break the cut.
    # Tests are dev-side only (they never ship), so this runs the SOURCE tree.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TestPath)

    $miss = { param($m) [pscustomobject]@{ Ran = $false; Ok = $false; Failed = 0; Total = 0; Message = $m } }

    if (-not (Test-Path -LiteralPath $TestPath)) { return (& $miss "test folder not found: $TestPath") }

    $mod = @(Get-Module -ListAvailable -Name Pester |
             Where-Object { $_.Version.Major -eq 3 } |
             Sort-Object Version -Descending)
    if (-not $mod.Count) { return (& $miss 'Pester 3.x not installed (this gate speaks v3 syntax)') }
    try { Import-Module $mod[0].Path -Force -ErrorAction Stop }
    catch { return (& $miss "Pester import failed: $($_.Exception.Message)") }

    # A failing test writes to the error stream; without this the script-wide
    # ErrorActionPreference='Stop' turns a red test into an unhandled throw and
    # the operator never sees the FailedCount that explains it.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $r = Invoke-Pester -Script $TestPath -PassThru -Quiet
    } catch {
        return (& $miss "Pester run threw: $($_.Exception.Message)")
    } finally {
        $ErrorActionPreference = $prev
    }

    if (-not $r) { return (& $miss 'Pester returned no result object') }
    [pscustomobject]@{
        Ran     = $true
        Failed  = [int]$r.FailedCount
        Total   = [int]$r.TotalCount
        Ok      = ([int]$r.FailedCount -eq 0)
        Message = ''
    }
}

Write-Host '=== JANET Web Sync-TakeToWork ===' -ForegroundColor Cyan
Write-Host "Source: $src"

$stage = Join-Path $env:TEMP ("JanetWebTTW_" + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $stage -Force)
try {
    # 1. Root files
    foreach ($f in @('Launch JANET Web.cmd', 'DO NOT RUN - JanetWeb.Internal.ps1', 'README.md')) {
        $from = Join-Path $src $f
        if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination $stage -Force; Write-Host "  + $f" }
        else { Write-Host "  WARN: missing '$f' - skipped" -ForegroundColor Yellow }
    }

    # 2. Suite folders (whole trees). tests\ and docs\ are dev-side only.
    foreach ($d in @('modules', 'server', 'web')) {
        $from = Join-Path $src $d
        if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination $stage -Recurse -Force; Write-Host "  + $d\" }
        else { Write-Host "  WARN: missing folder '$d' - skipped" -ForegroundColor Yellow }
    }

    # 3. Packages: full folder structure + non-certificate files only.
    #    Certs never ship - the operator populates the folders at work.
    $pkgSrc = Join-Path $src 'Packages'
    $pkgDst = Join-Path $stage 'Packages'
    $certSkipped = 0
    $keyHits     = @()   # private-key containers seen in the source (audit 2026-07-24)
    foreach ($d in @(Get-ChildItem -LiteralPath $pkgSrc -Directory -Recurse) + (Get-Item -LiteralPath $pkgSrc)) {
        $rel = $d.FullName.Substring($pkgSrc.Length).TrimStart('\')
        [void](New-Item -ItemType Directory -Path (Join-Path $pkgDst $rel) -Force)
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $pkgSrc -File -Recurse)) {
        $ext = $f.Extension.ToLower()
        if ($certExtPrivate -contains $ext) { $keyHits += $f.FullName; $certSkipped++; continue }
        if ($certExtPublic  -contains $ext) { $certSkipped++; continue }
        $rel = $f.FullName.Substring($pkgSrc.Length).TrimStart('\')
        Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pkgDst $rel) -Force
    }
    Write-Host "  + Packages\ (skeleton + payloads; $certSkipped certificate file(s) withheld per policy)"

    # 4. JanetLocal reference files (top-level files only; runtime + certs stay local)
    $jlSrc = Join-Path $src 'JanetLocal'
    $jlDst = Join-Path $stage 'JanetLocal'
    [void](New-Item -ItemType Directory -Path $jlDst -Force)
    foreach ($f in @(Get-ChildItem -LiteralPath $jlSrc -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'sla-ledger.json') { continue }                       # runtime ledger - work keeps its own
        $ext = $f.Extension.ToLower()
        # certs/keys never ship (e.g. DoDRoots.sst); a key container is also a
        # hard failure below, not a silent skip (audit 2026-07-24)
        if ($certExtPrivate -contains $ext) { $keyHits += $f.FullName; $certSkipped++; continue }
        if ($certExtPublic  -contains $ext) { $certSkipped++; continue }
        Copy-Item -LiteralPath $f.FullName -Destination $jlDst -Force
        Write-Host "  + JanetLocal\$($f.Name)"
    }

    # 5. SHIP GATES. All three must pass or NO zip is produced. Each one names
    #    itself in the output so a red run says exactly WHICH check failed
    #    (audit 2026-07-24 - there used to be only the cert check).
    Write-Host ''
    Write-Host 'Ship gates:' -ForegroundColor Cyan
    $failedGates = @()

    # 5a. Certificates: none staged, and no private-key container in the source.
    $leaked  = @(Get-ChildItem -LiteralPath $stage -Recurse -File | Where-Object { $certExt -contains $_.Extension.ToLower() })
    # audit 2026-07-25 (fable re-audit follow-up): the gate CLAIMS "no private-key
    # container in the source tree at all", but $keyHits was collected only from the two
    # folders we copy from (Packages\, JanetLocal\) plus the stage - so a .pfx parked in
    # tests\ or docs\ was invisible to it. Nothing shippable leaked (those folders never
    # stage), but the claim outran the check. WIDENED to match the claim: sweep the WHOLE
    # source tree, because a key in the tree is an incident wherever it sits, not only
    # where the packager happens to look. .git is skipped BEFORE recursing (its object
    # store is thousands of extensionless blobs - descending into it doubled the sweep
    # for nothing) and the stage lives in %TEMP%, outside $src.
    $treeHits = @()
    try {
        $treeHits = @(@(Get-ChildItem -LiteralPath $src -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.git' }) |
                      ForEach-Object { if ($_.PSIsContainer) { Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue } else { $_ } } |
                      Where-Object { $certExtPrivate -contains $_.Extension.ToLower() } |
                      ForEach-Object { $_.FullName })
    } catch {}
    $keyHits = @($keyHits + $treeHits + @($leaked | Where-Object { $certExtPrivate -contains $_.Extension.ToLower() } | ForEach-Object { $_.FullName }) | Sort-Object -Unique)
    $certOk  = (-not $leaked.Count) -and (-not $keyHits.Count)
    Write-Host ("  [{0}] certificates: {1} staged (must be 0), {2} withheld per policy, {3} private-key container(s) found (must be 0)" -f `
        $(if ($certOk) { 'OK' } else { 'FAIL' }), $leaked.Count, $certSkipped, $keyHits.Count) `
        -ForegroundColor $(if ($certOk) { 'Green' } else { 'Red' })
    $leaked | ForEach-Object { Write-Host "         staged: $($_.FullName.Substring($stage.Length))" -ForegroundColor Red }
    # A .pfx/.p12/.pvk/... can carry a PRIVATE KEY. Withholding it from the zip
    # is not enough - it should not be sitting in the tree at all, so it stops
    # the cut outright and gets named.
    $keyHits | ForEach-Object { Write-Host "         PRIVATE KEY CONTAINER: $_" -ForegroundColor Red }
    if (-not $certOk) { $failedGates += 'certificates' }

    $mpam = Join-Path $stage 'Packages\DefenderDefinitions\mpam-fe.exe'
    if (Test-Path -LiteralPath $mpam) {
        Write-Host ("  [OK] DefenderDefinitions: mpam-fe.exe staged ({0:N0} MB)" -f ((Get-Item -LiteralPath $mpam).Length / 1MB)) -ForegroundColor Green
    } else {
        Write-Host '  [--] DefenderDefinitions: empty (drop mpam-fe.exe there at work; offline rung stays off until then)' -ForegroundColor Gray
    }

    # 5b. Parse sweep over the STAGED copy - this is literally what work loads.
    $parse = Invoke-JwParseGate -Root $stage
    Write-Host ("  [{0}] parse sweep: {1} of {2} staged .ps1/.psm1 file(s) failed to parse" -f `
        $(if ($parse.Ok) { 'OK' } else { 'FAIL' }), @($parse.Failures).Count, $parse.FileCount) `
        -ForegroundColor $(if ($parse.Ok) { 'Green' } else { 'Red' })
    $parse.Failures | ForEach-Object {
        Write-Host ("         {0}:{1} {2}" -f $_.Path.Replace($stage, ''), $_.Line, $_.Message) -ForegroundColor Red
    }
    if (-not $parse.Ok) { $failedGates += 'parse sweep' }

    # 5c. Pester suite (source-side; tests\ never ships). Slowest gate, so last.
    Write-Host '  ...  Pester suite: running (this takes a minute)' -ForegroundColor Gray
    $tests = Invoke-JwTestGate -TestPath (Join-Path $src 'tests')
    if ($tests.Ran) {
        Write-Host ("  [{0}] Pester suite: {1} failed of {2} test(s)" -f `
            $(if ($tests.Ok) { 'OK' } else { 'FAIL' }), $tests.Failed, $tests.Total) `
            -ForegroundColor $(if ($tests.Ok) { 'Green' } else { 'Red' })
    } else {
        Write-Host ("  [FAIL] Pester suite: did not run - {0}" -f $tests.Message) -ForegroundColor Red
    }
    if (-not $tests.Ok) { $failedGates += 'Pester suite' }

    if ($failedGates.Count) {
        Write-Host ''
        Write-Host ("=== SYNC FAILED - gate(s): {0} - NO zip produced ===" -f ($failedGates -join ', ')) -ForegroundColor Red
        if ($failedGates -contains 'certificates') {
            Write-Host '    Certificates must never ship; key material must never be in the tree.' -ForegroundColor Red
        }
        exit 1
    }

    # 6. Zip (naming: JANETWEB_TakeToWork_yyyy-MM-dd_HHmmss.zip)
    if ($GateOnly) {
        Write-Host ''
        Write-Host ("=== GATES OK (-GateOnly) === {0} files staged; no zip written ===" -f (Get-ChildItem -LiteralPath $stage -Recurse -File).Count) -ForegroundColor Green
        exit 0
    }
    if (-not (Test-Path -LiteralPath $ZipDir)) { [void](New-Item -ItemType Directory -Path $ZipDir -Force) }
    $stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $zipPath = Join-Path $ZipDir ("JANETWEB_TakeToWork_$stamp.zip")
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $files = (Get-ChildItem -LiteralPath $stage -Recurse -File).Count
    Write-Host ''
    Write-Host ("=== SYNC OK === {0} files -> {1} ({2:N1} MB)" -f $files, $zipPath, ((Get-Item -LiteralPath $zipPath).Length / 1MB)) -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
