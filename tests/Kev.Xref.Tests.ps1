# =============================================================================
#  Kev.Xref.Tests.ps1 - Pester 3.4 tests for the KEV cross-reference engine
#  (audit 2026-07-24). The governing rule under test: if the tool does not KNOW,
#  it must not render an all-clear.
#    - finding 1: an empty / unreadable catalog emits NO verdict row at all
#                 (the old order streamed 'Not listed' for every CVE first).
#    - finding 2: the catalog's age is surfaced and a stale snapshot downgrades
#                 the "nothing on KEV" log off its green 'ok' level.
#    - finding 5: a multi-CVE cell no longer inherits the row's Year column.
#    - findings 6/7: add-kev reports the merged count and leaves no $script:kevFinal.
#
#  The engine reads JanetLocal\KevCatalog.txt via Get-KevCatalogPath. Each helper
#  shadows that function (and the IAVM map path) inside the module's session state
#  so the tests run against a temp catalog and never touch the shipped one.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.kev.psm1') -Force -PassThru
$script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("kevxref_" + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($script:Tmp)

function New-KevTempCatalog {
    param([string[]]$Cves, [int]$AgeDays = 0, [switch]$NoFile)
    $p = Join-Path $script:Tmp ("cat_" + [guid]::NewGuid().ToString('N') + ".txt")
    if (-not $NoFile) {
        $body = ''
        if ($Cves) { $body = ($Cves -join "`r`n") + "`r`n" }
        [System.IO.File]::WriteAllText($p, $body, (New-Object System.Text.UTF8Encoding($false)))
        if ($AgeDays -gt 0) { (Get-Item -LiteralPath $p).LastWriteTime = (Get-Date).AddDays(-$AgeDays) }
    }
    return $p
}

# Run an action against a temp catalog and hand back BOTH the return value and every
# emitted event (the streamed rows are the whole point of finding 1).
function Invoke-KevAction {
    param([string]$Action, [hashtable]$P, [string]$CatalogPath)
    & $script:Mod {
        param($act, $prm, $cp)
        function Get-KevCatalogPath  { $cp }
        function Get-KevIavmMapPath  { Join-Path (Split-Path -Parent $cp) 'IavmMap.csv' }   # absent -> empty map
        $ev = New-Object System.Collections.ArrayList
        $res = Invoke-JanetToolAction -ActionId $act -Params $prm -Emit { param($e) [void]$ev.Add($e) }
        @{ Result = $res; Events = @($ev) }
    } $Action $P $CatalogPath
}

function Get-KevRowEvents { param($R) return @($R.Events | Where-Object { $_.type -eq 'row' }) }
function Get-KevLogText   { param($R) return (@($R.Events | Where-Object { $_.type -eq 'log' } | ForEach-Object { [string]$_.text }) -join ' || ') }

Describe 'xref refuses to render an all-clear without a catalog (audit 2026-07-24 finding 1)' {

    It 'emits NO "Not listed" row when the catalog file is MISSING' {
        $cat = New-KevTempCatalog -NoFile
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = "CVE-2019-11634`nCVE-2021-44228" } -CatalogPath $cat
        $rowEvents = Get-KevRowEvents $r
        @($rowEvents).Count | Should Be 0
        @($r.Result.rows).Count | Should Be 0
        @($rowEvents | Where-Object { $_.InKEV -eq 'Not listed' }).Count | Should Be 0
    }

    It 'reports an explicit UNKNOWN state (not a clean result) when the catalog is MISSING' {
        $cat = New-KevTempCatalog -NoFile
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = "CVE-2019-11634`nCVE-2021-44228" } -CatalogPath $cat
        $r.Result.summary.empty   | Should Be $true
        $r.Result.summary.unknown | Should Be $true
        $r.Result.summary.overlap | Should Be 0
        $r.Result.summary.total   | Should Be 2      # the input WAS parsed - we just refuse to judge it
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' }).Count | Should Be 1
        (Get-KevLogText $r) -match 'NOT an all-clear' | Should Be $true
    }

    It 'emits NO verdict row when the catalog file exists but is EMPTY' {
        $cat = New-KevTempCatalog -Cves @()
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2019-11634' } -CatalogPath $cat
        @(Get-KevRowEvents $r).Count | Should Be 0
        @($r.Result.rows).Count      | Should Be 0
        $r.Result.summary.unknown    | Should Be $true
    }

    It 'emits NO verdict row and flags UNREADABLE when the catalog cannot be read' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        $fs = [System.IO.File]::Open($cat, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        try {
            $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2019-11634' } -CatalogPath $cat
        } finally { $fs.Close(); $fs.Dispose() }
        @(Get-KevRowEvents $r).Count      | Should Be 0
        $r.Result.summary.unknown         | Should Be $true
        $r.Result.summary.unreadable      | Should Be $true
        (Get-KevLogText $r) -match 'UNREADABLE' | Should Be $true
    }

    It 'still cross-references normally when the catalog HAS entries' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634','CVE-2021-44228')
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = "CVE-2019-11634`nCVE-2030-9999" } -CatalogPath $cat
        $rowEvents = Get-KevRowEvents $r
        @($rowEvents).Count | Should Be 2
        @($rowEvents | Where-Object { $_.CVE -eq 'CVE-2019-11634' })[0].InKEV | Should Be 'Listed (KEV)'
        @($rowEvents | Where-Object { $_.CVE -eq 'CVE-2030-9999' })[0].InKEV  | Should Be 'Not listed'
        $r.Result.summary.overlap | Should Be 1
    }
}

Describe 'catalog age / staleness is surfaced (audit 2026-07-24 finding 2)' {

    It 'reports the catalog age and last-updated stamp on a cross-reference' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634') -AgeDays 5
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2030-9999' } -CatalogPath $cat
        $r.Result.summary.ageDays | Should Be 5
        [string]::IsNullOrEmpty([string]$r.Result.summary.updated) | Should Be $false
        $r.Result.summary.stale | Should Be $false
    }

    It 'reports the catalog age on list-kev' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634') -AgeDays 3
        $r = Invoke-KevAction -Action 'list-kev' -P @{} -CatalogPath $cat
        $r.Result.summary.ageDays | Should Be 3
        $r.Result.summary.stale   | Should Be $false
    }

    It 'flags a months-old snapshot as STALE and warns' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634') -AgeDays 90
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2030-9999' } -CatalogPath $cat
        $r.Result.summary.stale | Should Be $true
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and ([string]$_.text) -match 'STALE' }).Count -gt 0 | Should Be $true
    }

    It 'does NOT log a green all-clear when the snapshot is stale' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634') -AgeDays 90
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2030-9999' } -CatalogPath $cat
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'ok' }).Count | Should Be 0
    }

    It 'DOES log a green all-clear when the snapshot is fresh' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2030-9999' } -CatalogPath $cat
        @($r.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'ok' }).Count | Should Be 1
    }
}

Describe 'Get-AradCves per-CVE Year (audit 2026-07-24 finding 5)' {

    It 'gives every CVE in a multi-CVE cell its OWN year, not the row Year column' {
        $csv = "Check ID,CVE Year,Severity`r`nCVE-2019-11634 CVE-2021-44228,2019,Critical"
        $out = & $script:Mod { param($t) Get-AradCves $t } $csv
        @($out).Count | Should Be 2
        (@($out) | Where-Object { $_.Cve -eq 'CVE-2019-11634' })[0].Year | Should Be '2019'
        (@($out) | Where-Object { $_.Cve -eq 'CVE-2021-44228' })[0].Year | Should Be '2021'
    }

    It 'keeps every CVE severity/score from its own row in a multi-CVE cell' {
        $csv = "Check ID,CVE Year,Severity`r`nCVE-2019-11634 CVE-2021-44228,2019,Critical"
        $out = & $script:Mod { param($t) Get-AradCves $t } $csv
        (@($out) | Where-Object { $_.Cve -eq 'CVE-2021-44228' })[0].Severity | Should Be 'Critical'
    }

    It 'still honours the row Year column for a single-CVE row' {
        $csv = "Check ID,CVE Year,Severity`r`nCVE-2019-11634,2018,High"
        $out = & $script:Mod { param($t) Get-AradCves $t } $csv
        @($out).Count | Should Be 1
        @($out)[0].Year | Should Be '2018'
    }

    It 'falls back to the id year when the row has no Year column' {
        $csv = "Check ID,Severity`r`nCVE-2021-44228,Critical"
        $out = & $script:Mod { param($t) Get-AradCves $t } $csv
        @($out)[0].Year | Should Be '2021'
    }

    It 'detects the CVE column by content when the header is not CVE-ish' {
        $csv = "Plugin,Detail`r`n12345,contains CVE-2021-44228 in the text"
        $out = & $script:Mod { param($t) Get-AradCves $t } $csv
        @($out).Count | Should Be 1
        @($out)[0].Cve | Should Be 'CVE-2021-44228'
    }
}

Describe 'add-kev merged count and lock-body handoff (audit 2026-07-24 findings 6/7)' {

    It 'reports the authoritative merged catalog size as summary.total' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        $r = Invoke-KevAction -Action 'add-kev' -P @{ cves = "CVE-2021-44228`nnot-a-cve`nCVE-2019-11634" } -CatalogPath $cat
        $r.Result.summary.added     | Should Be 1
        $r.Result.summary.duplicate | Should Be 1
        $r.Result.summary.invalid   | Should Be 1
        $r.Result.summary.total     | Should Be 2      # merged on-disk count, not 1 + 1 arithmetic
        @(Get-Content -LiteralPath $cat | Where-Object { $_ }).Count | Should Be 2
    }

    It 'reports the real catalog size when nothing was added' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634','CVE-2021-44228')
        $r = Invoke-KevAction -Action 'add-kev' -P @{ cves = 'CVE-2019-11634' } -CatalogPath $cat
        $r.Result.summary.added | Should Be 0
        $r.Result.summary.total | Should Be 2
    }

    It 'leaves no $script:kevFinal behind in module scope' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        [void](Invoke-KevAction -Action 'add-kev' -P @{ cves = 'CVE-2021-44228' } -CatalogPath $cat)
        $leaked = & $script:Mod { $null -ne (Get-Variable -Name 'kevFinal' -Scope Script -ErrorAction SilentlyContinue) }
        $leaked | Should Be $false
    }

    It 'releases the catalog lock after the merge' {
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        [void](Invoke-KevAction -Action 'add-kev' -P @{ cves = 'CVE-2021-44228' } -CatalogPath $cat)
        (Test-Path -LiteralPath "$cat.lock") | Should Be $false
    }
}

Describe 'kev manifest columns match what the engine emits (audit 2026-07-24 finding 3)' {

    It 'emits every column the xref action declares' {
        $man = & $script:Mod { Get-JanetToolManifest }
        $cols = @(($man.actions | Where-Object { $_.id -eq 'xref' }).columns)
        $cat = New-KevTempCatalog -Cves @('CVE-2019-11634')
        $r = Invoke-KevAction -Action 'xref' -P @{ arad = 'CVE-2019-11634' } -CatalogPath $cat
        $row = @(Get-KevRowEvents $r)[0]
        foreach ($c in $cols) { $row.ContainsKey($c) | Should Be $true }
    }
}

# cleanup (best effort; temp dir)
try { [System.IO.Directory]::Delete($script:Tmp, $true) } catch {}
