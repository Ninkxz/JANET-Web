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
#   - CERTIFICATES: no .cer/.crt/.p7b/.sst ships in the zip, anywhere.
#     DoD-Certs / PKI-Fix\Certs ship as empty folder skeletons; the operator
#     drops the cert bundles into the Packages folder ON THE WORK MACHINE.
#     The cert tools fail closed on an empty bundle by design.
#   - tests\  (Pester dev gate - dev-side only)
#   - docs\   (design history - dev-side only)
#
# GATE: the sync FAILS (no zip) if any certificate file ends up staged.
#
# Usage:
#   powershell.exe -ExecutionPolicy Bypass -File '.\Sync-TakeToWork.ps1'

[CmdletBinding()]
param(
    [string]$ZipDir = 'X:\Archive'
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$certExt = @('.cer', '.crt', '.p7b', '.sst')

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
    foreach ($d in @(Get-ChildItem -LiteralPath $pkgSrc -Directory -Recurse) + (Get-Item $pkgSrc)) {
        $rel = $d.FullName.Substring($pkgSrc.Length).TrimStart('\')
        [void](New-Item -ItemType Directory -Path (Join-Path $pkgDst $rel) -Force)
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $pkgSrc -File -Recurse)) {
        if ($certExt -contains $f.Extension.ToLower()) { $certSkipped++; continue }
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
        if ($certExt -contains $f.Extension.ToLower()) { continue }           # certs never ship (DoDRoots.sst)
        Copy-Item -LiteralPath $f.FullName -Destination $jlDst -Force
        Write-Host "  + JanetLocal\$($f.Name)"
    }

    # 5. GATE: no certificate file may be staged, anywhere.
    Write-Host ''
    Write-Host 'Cert-free / payload check:' -ForegroundColor Cyan
    $leaked = @(Get-ChildItem $stage -Recurse -File | Where-Object { $certExt -contains $_.Extension.ToLower() })
    $color = if ($leaked.Count) { 'Red' } else { 'Green' }
    Write-Host ("  [{0}] certificate files staged: {1} (must be 0)" -f $(if ($leaked.Count) { 'FAIL' } else { 'OK' }), $leaked.Count) -ForegroundColor $color
    $mpam = Join-Path $stage 'Packages\DefenderDefinitions\mpam-fe.exe'
    if (Test-Path $mpam) {
        Write-Host ("  [OK] DefenderDefinitions: mpam-fe.exe staged ({0:N0} MB)" -f ((Get-Item $mpam).Length / 1MB)) -ForegroundColor Green
    } else {
        Write-Host '  [--] DefenderDefinitions: empty (drop mpam-fe.exe there at work; offline rung stays off until then)' -ForegroundColor Gray
    }
    if ($leaked.Count) {
        $leaked | ForEach-Object { Write-Host "       $($_.FullName.Substring($stage.Length))" -ForegroundColor Red }
        Write-Host ''
        Write-Host '=== SYNC FAILED - certificates must never ship; NO zip produced ===' -ForegroundColor Red
        exit 1
    }

    # 6. Zip (naming: JANETWEB_TakeToWork_yyyy-MM-dd_HHmmss.zip)
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
