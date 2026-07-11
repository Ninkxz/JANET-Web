# Sync JANET Web -> a timestamped "take to work" zip in .\Take to Work\.
#
# Stages a clean copy of the suite in %TEMP%, verifies the payloads the tools are
# dead without, then zips it as Take to Work\JANETWEB_TakeToWork_<stamp>.zip
# (matching the existing zip naming in that folder).
#
# SHIPPED:
#   Launch JANET Web.cmd, DO NOT RUN - JanetWeb.Internal.ps1, README.md
#   modules\  server\  web\  tests\  docs\
#   Packages\           - IN FULL: DoD-Certs (the PKI bundle fix-pki/certdeploy need),
#                         DefenderDefinitions (incl. a staged mpam-fe.exe - that is the
#                         point of staging it), Log4j, anything else added later
#   JanetLocal\<files>  - top-level reference files only (c2c-baseline.json,
#                         KevCatalog.txt, DoDRoots.sst, IavmMap.csv, catalogs, ...).
#                         Runtime SUBFOLDERS (campaigns\, schedule\) and ledgers stay
#                         local - the work instance keeps its own state.
#
# GATE: the sync FAILS (no zip) if Packages\DoD-Certs stages with zero .cer files or
# fewer than the source has - a cert-less bundle must never reach the work machine.
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File '.\Sync-TakeToWork.ps1'

[CmdletBinding()]
param(
    [string]$ZipDir   # default: <repo>\Take to Work
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
if (-not $ZipDir) { $ZipDir = Join-Path $src 'Take to Work' }

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

    # 2. Suite folders (whole trees). Packages IN FULL - that carries the PKI bundle
    #    and the offline Defender package staging folder.
    foreach ($d in @('modules', 'server', 'web', 'tests', 'docs', 'Packages')) {
        $from = Join-Path $src $d
        if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination $stage -Recurse -Force; Write-Host "  + $d\" }
        else { Write-Host "  WARN: missing folder '$d' - skipped" -ForegroundColor Yellow }
    }

    # 3. JanetLocal reference files (top-level files only; runtime subfolders stay local)
    $jlSrc = Join-Path $src 'JanetLocal'
    $jlDst = Join-Path $stage 'JanetLocal'
    [void](New-Item -ItemType Directory -Path $jlDst -Force)
    foreach ($f in @(Get-ChildItem -LiteralPath $jlSrc -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'sla-ledger.json') { continue }   # runtime ledger - work keeps its own
        Copy-Item -LiteralPath $f.FullName -Destination $jlDst -Force
        Write-Host "  + JanetLocal\$($f.Name)"
    }

    # 4. PKI payload gate - the DoD cert bundle must ALWAYS ship, complete.
    Write-Host ''
    Write-Host 'PKI / payload check:' -ForegroundColor Cyan
    $srcCer   = @(Get-ChildItem (Join-Path $src   'Packages\DoD-Certs') -Filter '*.cer' -Recurse -File -ErrorAction SilentlyContinue).Count
    $stageCer = @(Get-ChildItem (Join-Path $stage 'Packages\DoD-Certs') -Filter '*.cer' -Recurse -File -ErrorAction SilentlyContinue).Count
    $cerOk = ($stageCer -ge 1 -and $stageCer -eq $srcCer)
    $cerColor = if ($cerOk) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] Packages\DoD-Certs .cer files: staged {1} / source {2}" -f $(if ($cerOk) { 'OK' } else { 'FAIL' }), $stageCer, $srcCer) -ForegroundColor $cerColor
    $mpam = Join-Path $stage 'Packages\DefenderDefinitions\mpam-fe.exe'
    if (Test-Path $mpam) {
        Write-Host ("  [OK] DefenderDefinitions: mpam-fe.exe staged ({0:N0} MB)" -f ((Get-Item $mpam).Length / 1MB)) -ForegroundColor Green
    } else {
        Write-Host '  [--] DefenderDefinitions: empty (drop mpam-fe.exe there at work; offline rung stays off until then)' -ForegroundColor Gray
    }
    if (-not $cerOk) {
        Write-Host ''
        Write-Host '=== SYNC FAILED - DoD-Certs bundle missing/incomplete; NO zip produced ===' -ForegroundColor Red
        exit 1
    }

    # 5. Zip (existing folder naming: JANETWEB_TakeToWork_yyyy-MM-dd_HHmmss.zip)
    if (-not (Test-Path $ZipDir)) { [void](New-Item -ItemType Directory -Path $ZipDir -Force) }
    $stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $zipPath = Join-Path $ZipDir ("JANETWEB_TakeToWork_$stamp.zip")
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $files = (Get-ChildItem $stage -Recurse -File).Count
    Write-Host ''
    Write-Host ("=== SYNC OK === {0} files -> {1} ({2:N1} MB)" -f $files, $zipPath, ((Get-Item $zipPath).Length / 1MB)) -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
