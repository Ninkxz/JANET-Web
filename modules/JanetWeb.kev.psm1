# =============================================================================
#  JanetWeb.kev.psm1  ->  KEV Cross-Check
#
#  Net-new JANET Web tool (no desktop twin). Cross-references a machine's
#  ACAS / ARAD CVE export against the CISA Known Exploited Vulnerabilities (KEV)
#  catalog that ships INSIDE JANET (JanetLocal\KevCatalog.txt) so it travels with
#  the take-to-work payload and works fully offline / air-gapped.
#
#  Three actions, all purely local (NO WinRM, NO hosts touched):
#    xref      - parse the pasted/imported ARAD CSV, flag every CVE that is also
#                on the KEV list (those are present AND known-exploited).
#    list-kev  - dump the current KEV catalog (count + CVEs).
#    add-kev   - append operator-supplied CVE(s) to the catalog and persist them
#                to the text file (de-duped, validated, sorted). This is the ONLY
#                writer of the catalog; write is temp-file + atomic rename.
#
#  Because no host is touched, this tool emits NO audit rows (the server's
#  TouchHost/VulnPatched ValidateSet does not apply). The server still keeps a
#  per-action session log automatically.
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. UTF-8 BOM, ASCII body.
#
#  v1.1.0 (audit 2026-07-24) - "if the tool does not KNOW, it must not render an
#  all-clear". xref now HARD-GATES on a usable catalog BEFORE it emits a single
#  verdict row (the old order streamed 'Not listed' for every CVE and only THEN
#  stopped, so the grid, the stat cards and the CSV export all read as a clean
#  all-clear built on a catalog we never had); every result carries the catalog's
#  last-updated / age and a snapshot older than $script:KevStaleDays downgrades the
#  all-clear to a warning; multi-CVE cells no longer inherit the row's Year column;
#  add-kev reports the authoritative merged count and returns the merged list out of
#  the lock body instead of smuggling it through module scope; the CVE-column
#  fallback short-circuits on its first hit.
#
#  v1.1.1 (audit 2026-07-25 (fable re-audit follow-up)) - add-kev carries the catalog
#  age too. list-kev and xref both report Updated / AgeDays / Stale; add-kev was the
#  one action that did not, so the same catalog described itself differently depending
#  on which button the operator pressed. The values it reports are the PRE-ADD ones:
#  writing the file necessarily stamps LastWriteTime with 'now', and a hand-added CVE
#  is not a CISA refresh, so the post-write age would read falsely fresh.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'kev'
        name     = 'KEV Cross-Check'
        version  = '1.1.1'
        category = 'Reporting'
        summary  = 'Cross-reference a machine ACAS/ARAD CVE export against the CISA Known Exploited Vulnerabilities (KEV) catalog stored inside JANET (JanetLocal\KevCatalog.txt). Flags the overlap (present AND known-exploited), opens each CVE in Google / NVD / CVE.org / CISA KEV / IAVM lookups, and lets the operator add new KEV CVEs that persist to the file.'
        actions  = @(
            @{
                id          = 'xref'
                label       = 'Cross-Reference'
                description = 'Parse the pasted/imported ARAD (or ACAS) CVE export and flag every CVE that is also on the KEV catalog, and badge each CVE with its IAVA / bulletin id when it is on the IAVM map (JanetLocal\IavmMap.csv). Read-only - no hosts are touched.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('CVE','Year','Severity','Score','IAVA','InKEV')
                inputs      = @(
                    @{ name='arad'; label='ARAD / ACAS CVE export (CSV or CVE list)'; type='text'; required=$true }
                )
            }
            @{
                id          = 'list-kev'
                label       = 'List KEV Catalog'
                description = 'Show every CVE currently in the KEV catalog (JanetLocal\KevCatalog.txt) and where it loaded from.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('CVE','Year')
                inputs      = @()
            }
            @{
                id          = 'add-kev'
                label       = 'Add to KEV'
                description = 'Add one or more CVE(s) to the KEV catalog and save them to JanetLocal\KevCatalog.txt (validated, de-duped, sorted). The catalog ships in take-to-work.'
                kind        = 'stream-table'
                destructive = $true   # PERSISTS to KevCatalog.txt - a state-changing write must ride the admin-session gate (audit loop7 P3)
                columns     = @('CVE','Status')
                inputs      = @(
                    @{ name='cves'; label='CVE(s) to add (one per line, or comma/space separated)'; type='text'; required=$true }
                )
            }
        )
    }
}

# --- Catalog location -------------------------------------------------------
# Lives in JanetLocal so it ships with the deployable payload (take-to-work) and
# is editable both in-app (add-kev) and by hand.
function Get-KevCatalogPath { Join-Path $PSScriptRoot '..\JanetLocal\KevCatalog.txt' }

# Staleness threshold for the catalog SNAPSHOT (audit 2026-07-24). CISA adds
# known-exploited CVEs to the KEV catalog most weeks, so a file that has not been
# refreshed in a month is very likely missing entries - and a "no overlap" answer
# off a stale snapshot is exactly the false all-clear this tool exists to prevent.
# 30 days: long enough not to nag on a normal take-to-work cycle, short enough to
# catch a catalog that was shipped once and then forgotten.
$script:KevStaleDays = 30

function Test-KevCveId {
    param([string]$Value)
    return ([string]$Value -match '^CVE-\d{4}-\d{4,}$')
}

# Read the catalog fresh each call. Format-agnostic: splits on any of
# newline/comma/semicolon/tab/space, so the file can be one-per-line OR the
# single comma-separated line CISA-style exports use. Returns a de-duped,
# numerically-sorted view plus a fast lookup HashSet. A missing/corrupt file
# yields an empty (but valid) catalog - it never throws, but it DOES report why via
# ReadError so callers can say "unreadable" instead of implying "clean".
# Also reports the snapshot's vintage (Updated / AgeDays / Stale) - audit 2026-07-24 -
# because a months-old catalog otherwise yields a silent green all-clear.
function Read-KevCatalog {
    $p   = Get-KevCatalogPath
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.ArrayList
    $source = ''
    $updated = $null
    $ageDays = $null
    $readError = $false
    if (Test-Path -LiteralPath $p) {
        try {
            $fi = Get-Item -LiteralPath $p -ErrorAction Stop
            $updated = $fi.LastWriteTime
            $ageDays = [int][Math]::Floor(((Get-Date) - $updated).TotalDays)
            if ($ageDays -lt 0) { $ageDays = 0 }   # clock skew on a share must not read as "fresher than now"
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if ($null -eq $raw) { $raw = '' }
            if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
            foreach ($tok in ($raw -split '[\r\n,;\t ]+')) {
                $c = ([string]$tok).Trim().ToUpper()
                if (Test-KevCveId $c) { if ($set.Add($c)) { [void]$list.Add($c) } }
            }
            $source = 'JanetLocal\KevCatalog.txt'
        } catch {
            $source = "read error: $($_.Exception.Message)"
            $readError = $true
        }
    } else {
        $source = '(missing - JanetLocal\KevCatalog.txt not found; use Add to KEV to create it)'
    }
    $sorted = Sort-KevCves @($list)
    $stale = ($null -ne $ageDays -and $ageDays -gt $script:KevStaleDays)
    return @{ Set = $set; List = $sorted; Count = $set.Count; Source = $source; Path = $p;
              Updated = $updated; AgeDays = $ageDays; Stale = $stale; ReadError = $readError }
}

# One-line freshness blurb for logs / status lines (audit 2026-07-24). An unknown
# vintage is stated as unknown - never silently omitted, because "no age shown" reads
# as "fine" to an operator.
function Get-KevAgeText {
    param($Cat)
    if ($null -eq $Cat -or $null -eq $Cat.Updated) { return 'last updated: UNKNOWN' }
    $when = ([datetime]$Cat.Updated).ToString('yyyy-MM-dd')
    $d = [int]$Cat.AgeDays
    if ($d -le 0) { return "last updated: $when (today)" }
    if ($d -eq 1) { return "last updated: $when (1 day ago)" }
    return "last updated: $when ($d days ago)"
}

# The ONLY writer. Writes the full list to a temp file then swaps it in: a true
# atomic replace ([IO.File]::Replace) when overwriting an existing catalog, or a
# plain move when creating it. The live KevCatalog.txt is never half-written, and
# a failed swap removes its own temp (no orphan .tmp on the share). No BOM (plain
# ASCII CVE list).
# ponytail: last-writer-wins on concurrent edits from two machines on the share -
# acceptable for a rarely-edited reference list; add a lock only if that bites.
function Write-KevCatalog {
    param([string[]]$List, [string]$Path)
    $content = ($List -join "`r`n") + "`r`n"
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = Join-Path $dir ("KevCatalog.$PID.$([DateTime]::UtcNow.Ticks).tmp")
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tmp, $content, $enc)
    try {
        if (Test-Path -LiteralPath $Path) {
            # PS 5.1 / .NET Framework has no File.Move overwrite overload; File.Replace
            # IS a true atomic swap. NullString (not $null) binds the no-backup overload.
            try { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) }
            catch { Move-Item -LiteralPath $tmp -Destination $Path -Force }   # DFS / odd-SMB fallback
        } else {
            Move-Item -LiteralPath $tmp -Destination $Path -Force
        }
    } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}

# Cross-machine advisory lock for the shared catalog on SMB (audit#8). A named
# mutex is per-machine and won't serialize two DIFFERENT boxes on the share, so we
# use an exclusive lock FILE (CreateNew + FileShare.None). A lock older than the
# timeout is assumed stale (holder died) and broken. Runs $Body while held, then
# releases. Constrained-Language-safe (only .NET File.Open + basic cmdlets).
function Invoke-WithKevLock {
    param([string]$CatalogPath, [scriptblock]$Body, [int]$TimeoutMs = 15000)
    $lock = "$CatalogPath.lock"
    $dir = Split-Path -Parent $CatalogPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $fs = $null
    while ($null -eq $fs) {
        try { $fs = [System.IO.File]::Open($lock, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
        catch {
            if ($sw.ElapsedMilliseconds -gt $TimeoutMs) {
                $broke = $false
                try {
                    $age = (Get-Date) - (Get-Item -LiteralPath $lock -ErrorAction Stop).LastWriteTime
                    if ($age.TotalMilliseconds -gt $TimeoutMs) { Remove-Item -LiteralPath $lock -Force -ErrorAction Stop; $broke = $true }
                } catch {}
                if (-not $broke) { throw "KEV catalog is locked by another operation (waited $([int]$sw.ElapsedMilliseconds)ms)." }
                $sw.Restart()
            }
            Start-Sleep -Milliseconds 200
        }
    }
    try { & $Body }
    finally {
        try { $fs.Close(); $fs.Dispose() } catch {}
        Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue
    }
}

# Sort a CVE id array numerically (year, then sequence).
function Sort-KevCves {
    param([string[]]$List)
    return @($List | Sort-Object `
        @{ Expression = { [long]($_ -replace '^CVE-(\d+)-(\d+)$','$1') } }, `
        @{ Expression = { [long]($_ -replace '^CVE-(\d+)-(\d+)$','$2') } })
}

# --- IAVM map (private reader; same flat file the Reports tool ships) --------
# Reads JanetLocal\IavmMap.csv (header CVE,IAVA,Title) into a CVE -> IAVA lookup so
# xref rows can be badged with their IAVA / bulletin id. Deliberately a small private
# copy (do NOT cross-import JanetWeb.reports.psm1 - each engine loads in its own
# runspace). A missing / empty / corrupt file yields an empty map; never throws.
function Get-KevIavmMapPath { Join-Path $PSScriptRoot '..\JanetLocal\IavmMap.csv' }

function Read-KevIavmMap {
    $p   = Get-KevIavmMapPath
    $map = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $source = ''
    if (Test-Path -LiteralPath $p) {
        try {
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if ($null -eq $raw) { $raw = '' }
            if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                foreach ($r in @($raw | ConvertFrom-Csv -ErrorAction Stop)) {
                    if ($null -eq $r) { continue }
                    $cve = ''; if ($r.PSObject.Properties['CVE']) { $cve = ([string]$r.CVE).Trim().ToUpper() }
                    if ($cve -notmatch '^CVE-\d{4}-\d{4,}$') { continue }
                    $iava = ''; if ($r.PSObject.Properties['IAVA']) { $iava = ([string]$r.IAVA).Trim() }
                    if (-not $map.ContainsKey($cve)) { $map[$cve] = $iava }
                }
            }
            $source = 'JanetLocal\IavmMap.csv'
        } catch {
            $source = "read error: $($_.Exception.Message)"
        }
    } else {
        $source = '(missing - JanetLocal\IavmMap.csv not found)'
    }
    return @{ Map = $map; Count = $map.Count; Source = $source; Path = $p }
}

# Parse an ARAD / ACAS CVE export. First tries CSV with fuzzy header detection
# (so 'Check ID', 'CVE', 'CVE ID' all work, picking up Year/Severity/Score when
# present); falls back to a raw CVE-token regex scan for any other layout. Returns
# an array of PSCustomObject { Cve; Year; Severity; Score }, de-duped by CVE.
function Get-AradCves {
    param([string]$Text)
    $out  = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }

    $rows = $null
    try { $rows = @($Text | ConvertFrom-Csv -ErrorAction Stop) } catch { $rows = $null }
    $usedCsv = $false

    if ($rows -and $rows.Count -gt 0 -and $rows[0].PSObject) {
        $props = @($rows[0].PSObject.Properties.Name)
        $cveProp = $null
        # A bare newline / Excel-column CVE list: ConvertFrom-Csv consumes the FIRST
        # CVE as the 'header'. If a column NAME is itself a CVE id, treat the input as
        # headerless and leave $cveProp null so the regex fallback below re-scans the
        # full text (recovering line 1). This guard also stops a 'CVE Year'-style label
        # from hijacking detection (the matcher no longer accepts a bare 'cve' prefix).
        $headerIsData = $false
        foreach ($p in $props) { if ($p -match '(?i)^\s*CVE-\d{4}-\d{4,}\s*$') { $headerIsData = $true; break } }
        if (-not $headerIsData) {
            foreach ($p in $props) { if ($p -match '(?i)check\s*id|cve\s*id|^\s*cve\s*$') { $cveProp = $p; break } }
            if (-not $cveProp) {
                # audit 2026-07-24: ONE row carrying a CVE id is proof enough that this is
                # the CVE column, so stop at the first hit. The old Where-Object form walked
                # every row of every column before deciding (full O(rows*cols) scan on a
                # multi-thousand-row ACAS export, for an answer known at row 1).
                foreach ($p in $props) {
                    foreach ($r in $rows) {
                        if (([string]$r.$p) -match '(?i)CVE-\d{4}-\d{4,}') { $cveProp = $p; break }
                    }
                    if ($cveProp) { break }
                }
            }
        }
        if ($cveProp) {
            $yearProp = $null; $sevProp = $null; $scoreProp = $null
            foreach ($p in $props) {
                if (-not $yearProp  -and $p -match '(?i)year')        { $yearProp  = $p }
                if (-not $sevProp   -and $p -match '(?i)sever')       { $sevProp   = $p }
                if (-not $scoreProp -and $p -match '(?i)score')       { $scoreProp = $p }
            }
            foreach ($r in $rows) {
                # A single cell can pack multiple comma/newline-separated CVE ids
                # (real ACAS/ARAD exports); emit EVERY id, not just the leading token.
                $rowSev = ''; if ($sevProp)  { $rowSev   = ([string]$r.$sevProp).Trim() }
                $rowSc  = ''; if ($scoreProp){ $rowSc    = ([string]$r.$scoreProp).Trim() }
                $rowYear = ''; if ($yearProp) { $rowYear = ([string]$r.$yearProp).Trim() }
                $hits = @([regex]::Matches([string]$r.$cveProp, '(?i)CVE-\d{4}-\d{4,}'))
                # audit 2026-07-24: the row's Year column describes ONE finding. When a single
                # cell packs several CVE ids they are routinely from different years, so
                # inheriting $rowYear mislabeled every id but the first. The id itself is
                # authoritative for a multi-id cell; the column is only trusted for a 1:1 row.
                $rowYearApplies = ($hits.Count -le 1)
                foreach ($mm in $hits) {
                    $cve = $mm.Value.ToUpper()
                    if (-not $seen.Add($cve)) { continue }
                    $year = ''
                    if ($rowYearApplies) { $year = $rowYear }
                    if (-not $year) { $ym = [regex]::Match($cve, 'CVE-(\d{4})-'); if ($ym.Success) { $year = $ym.Groups[1].Value } }
                    [void]$out.Add([pscustomobject]@{ Cve=$cve; Year=$year; Severity=$rowSev; Score=$rowSc })
                    $usedCsv = $true
                }
            }
        }
    }

    if (-not $usedCsv) {
        foreach ($mm in [regex]::Matches($Text, '(?i)CVE-\d{4}-\d{4,}')) {
            $cve = $mm.Value.ToUpper()
            if (-not $seen.Add($cve)) { continue }
            $year = ''; $ym = [regex]::Match($cve, 'CVE-(\d{4})-'); if ($ym.Success) { $year = $ym.Groups[1].Value }
            [void]$out.Add([pscustomobject]@{ Cve=$cve; Year=$year; Severity=''; Score='' })
        }
    }
    return ,@($out)
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cat = Read-KevCatalog

    # Catalog vintage, shaped for the wire (audit 2026-07-24). A DateTime serializes
    # unpredictably across the JSON boundary, so hand the UI a plain string plus an
    # integer day count; -1 means "we could not determine it".
    $ageText    = Get-KevAgeText $cat
    $catUpdated = ''
    if ($cat.Updated) { $catUpdated = ([datetime]$cat.Updated).ToString('yyyy-MM-dd HH:mm') }
    $catAge = -1
    if ($null -ne $cat.AgeDays) { $catAge = [int]$cat.AgeDays }

    # ---------------------------------------------------------------- list-kev
    if ($ActionId -eq 'list-kev') {
        & $send @{ type='status'; text="KEV catalog: $($cat.Count) CVE(s) - $ageText - source: $($cat.Source)" }
        if ($cat.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="KEV catalog is empty - source: $($cat.Source). Use Add to KEV to populate it." }
            return @{ rows=@(); summary=@{ total=0; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=$false; unreadable=[bool]$cat.ReadError } }
        }
        $rows = New-Object System.Collections.ArrayList
        foreach ($cve in $cat.List) {
            $year = ''; $ym = [regex]::Match($cve, 'CVE-(\d{4})-'); if ($ym.Success) { $year = $ym.Groups[1].Value }
            $row = @{ _rk=$cve; CVE=$cve; Year=$year }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        if ($cat.Stale) {
            & $send @{ type='log'; level='warn'; text="KEV catalog snapshot is STALE - $ageText (threshold $($script:KevStaleDays) days). CISA adds known-exploited CVEs most weeks; refresh JanetLocal\KevCatalog.txt or a cross-reference will under-report." }
        }
        & $send @{ type='log'; level='ok'; text="$($cat.Count) KEV CVE(s) loaded from $($cat.Source) - $ageText." }
        return @{ rows=@($rows); summary=@{ total=$cat.Count; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale; unreadable=[bool]$cat.ReadError } }
    }

    # ---------------------------------------------------------------- add-kev
    if ($ActionId -eq 'add-kev') {
        # audit 2026-07-25 (fable re-audit follow-up): add-kev reports the catalog's
        # vintage like every other action. The values are the PRE-ADD ones on purpose:
        # they describe the SNAPSHOT we merged into, and the write below necessarily
        # stamps the file's LastWriteTime with 'now' - a hand-added CVE resets the
        # staleness clock without being a CISA refresh, so quoting the post-write age
        # would turn a months-old catalog green for the wrong reason.
        $raw = [string]$Params['cves']
        $tokens = @($raw -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($tokens.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No CVE entered.' }
            return @{ rows=@(); summary=@{ added=0; duplicate=0; invalid=0; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale } }
        }
        if ($cat.Stale) {
            & $send @{ type='log'; level='warn'; text="KEV catalog snapshot is STALE - $ageText (threshold $($script:KevStaleDays) days). Adding a CVE by hand refreshes the FILE, not the CISA snapshot; refresh JanetLocal\KevCatalog.txt as well." }
        }
        $rows = New-Object System.Collections.ArrayList
        $newSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in $cat.Set) { [void]$newSet.Add($c) }
        $added = New-Object System.Collections.ArrayList
        $dup = 0; $invalid = 0; $idx = 0
        foreach ($t in $tokens) {
            $idx++
            $cve = $t.ToUpper()
            $status = ''
            if (-not (Test-KevCveId $cve)) { $status = 'Invalid format'; $invalid++ }
            elseif ($cat.Set.Contains($cve)) { $status = 'Already in KEV'; $dup++ }
            elseif (-not $newSet.Add($cve)) { $status = 'Duplicate in input'; $dup++ }
            else { [void]$added.Add($cve); $status = 'Added' }
            $row = @{ _rk="$idx|$cve"; CVE=$cve; Status=$status }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        # Authoritative post-write catalog size. Seeded with the pre-add count so the
        # "nothing added" path below reports the real number too (audit 2026-07-24).
        $finalCount = $cat.Count
        if ($added.Count -gt 0) {
            # Lock + RE-READ the on-disk catalog + merge our additions before writing
            # (audit#8): a concurrent operator on another machine may have added a
            # different CVE since we snapshotted, and a blind full-file overwrite would
            # silently drop it (a lost known-exploited CVE = a future false-negative).
            try {
                # audit 2026-07-24: the merged list comes back as the lock body's RETURN
                # VALUE. It used to be parked in $script:kevFinal, which outlives the call
                # in this module's runspace - a later add that failed before the write would
                # have read the previous call's list. The lock itself is untouched: the body
                # still runs inside Invoke-WithKevLock, which releases in its finally.
                $kevFinal = Invoke-WithKevLock -CatalogPath $cat.Path -Body {
                    $fresh = Read-KevCatalog
                    $merged = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($c in $fresh.Set) { [void]$merged.Add($c) }
                    foreach ($c in $added)     { [void]$merged.Add($c) }
                    $sorted = Sort-KevCves @($merged)
                    Write-KevCatalog -List $sorted -Path $cat.Path
                    ,$sorted   # single object out of the lock body - no module-scope smuggling
                }
                $finalCount = @($kevFinal).Count
                & $send @{ type='log'; level='ok'; text="Saved $($added.Count) new CVE(s) to JanetLocal\KevCatalog.txt (merged under lock). KEV catalog is now $finalCount CVE(s) - snapshot before this add: $ageText." }
                & $send @{ type='status'; text="Added $($added.Count); skipped $dup duplicate, $invalid invalid. Catalog now $finalCount ($ageText)." }
            } catch {
                & $send @{ type='error'; text="Save FAILED - catalog NOT changed: $($_.Exception.Message)" }
                return @{ rows=@($rows); summary=@{ added=0; duplicate=$dup; invalid=$invalid; saveError=$true; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale } }
            }
        } else {
            & $send @{ type='log'; level='warn'; text="Nothing new to add - $dup already present/duplicate, $invalid invalid. Catalog unchanged ($($cat.Count) CVE(s), $ageText)." }
            & $send @{ type='status'; text="Nothing added. $dup duplicate, $invalid invalid ($ageText)." }
        }
        # audit 2026-07-24: report the count the MERGE produced, not pre-count + adds.
        # The arithmetic form ignored whatever a concurrent operator wrote under the lock,
        # so the UI could claim a catalog size the file never had.
        return @{ rows=@($rows); summary=@{ added=$added.Count; duplicate=$dup; invalid=$invalid; total=$finalCount
                                            source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale } }
    }

    # ---------------------------------------------------------------- xref
    if ($ActionId -ne 'xref') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    $arad = Get-AradCves ([string]$Params['arad'])
    if ($arad.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No CVEs found in the ARAD export. Paste the CSV (or a CVE list) and try again.' }
        return @{ rows=@(); summary=@{ total=0; overlap=0; kev=$cat.Count } }
    }

    # ---- catalog gate, BEFORE a single verdict row leaves this function --------
    # audit 2026-07-24: this check used to sit AFTER the emit loop, so an empty or
    # unreadable catalog still streamed 'Not listed' for every machine CVE - the grid,
    # the stat cards and the CSV export all rendered a clean all-clear built on a
    # catalog we never actually had. An operator reads a clean KEV result as "nothing
    # here is being actively exploited in the wild". If we do not KNOW, we emit NO
    # verdict row at all and say so.
    if ($cat.Count -eq 0) {
        $why = 'EMPTY'
        if ($cat.ReadError) { $why = 'UNREADABLE' }
        & $send @{ type='log'; level='err'; text="KEV catalog is $why (source: $($cat.Source)) - this is NOT an all-clear. No cross-reference was performed and NO verdict rows were emitted for the $($arad.Count) machine CVE(s). Populate the KEV Catalog tab (Add to KEV) or restore JanetLocal\KevCatalog.txt, then re-run." }
        & $send @{ type='status'; text="KEV catalog $why - result is UNKNOWN, not clean. $($arad.Count) machine CVE(s) were NOT cross-referenced." }
        return @{ rows=@(); summary=@{ total=$arad.Count; overlap=0; kev=0; empty=$true; unknown=$true; unreadable=[bool]$cat.ReadError; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale } }
    }

    # Staleness is the softer form of the same failure (audit 2026-07-24): the catalog
    # is usable, but a snapshot this old may simply not contain the CVE we are asked
    # about. Warn UP FRONT so the caveat is on screen before the rows are.
    if ($cat.Stale) {
        & $send @{ type='log'; level='warn'; text="KEV catalog snapshot is STALE - $ageText (threshold $($script:KevStaleDays) days). CISA adds known-exploited CVEs most weeks, so a 'no overlap' answer below may just be missing recent entries. Refresh JanetLocal\KevCatalog.txt." }
    }

    # IAVM map (badge each CVE with its IAVA / bulletin id when mapped). Empty map is
    # not a failure: rows simply carry IAVA=''.
    $iavm = Read-KevIavmMap
    & $send @{ type='status'; text="Cross-referencing $($arad.Count) machine CVE(s) against $($cat.Count) KEV CVE(s) ($ageText)..." }
    $rows = New-Object System.Collections.ArrayList
    $overlap = New-Object System.Collections.ArrayList
    $iavmTags = New-Object System.Collections.ArrayList
    foreach ($a in $arad) {
        $listed = $cat.Set.Contains($a.Cve)
        $inkev = 'Not listed'
        if ($listed) { $inkev = 'Listed (KEV)'; [void]$overlap.Add($a.Cve) }
        $iavaId = ''
        if ($iavm.Map.ContainsKey($a.Cve)) { $iavaId = [string]$iavm.Map[$a.Cve]; if ($iavaId) { [void]$iavmTags.Add("$($a.Cve) ($iavaId)") } }
        $row = @{ _rk=$a.Cve; CVE=$a.Cve; Year=[string]$a.Year; Severity=[string]$a.Severity; Score=[string]$a.Score; IAVA=$iavaId; InKEV=$inkev }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
    }

    if ($overlap.Count -gt 0) {
        $sortedOverlap = Sort-KevCves @($overlap)
        & $send @{ type='log'; level='banner'; text="$($overlap.Count) of $($arad.Count) machine CVE(s) are on the CISA KEV list (KNOWN EXPLOITED - prioritize):" }
        & $send @{ type='log'; level='err'; text=($sortedOverlap -join ', ') }
    } elseif ($cat.Stale) {
        # audit 2026-07-24: a no-overlap answer off a stale snapshot is not an all-clear,
        # so it does not get the green 'ok' level - it is qualified by the catalog date.
        & $send @{ type='log'; level='warn'; text="None of the $($arad.Count) machine CVE(s) are on the KEV catalog ($($cat.Count) entries) - but that catalog is STALE ($ageText). Read this as 'nothing known as of $($catUpdated)', NOT as an all-clear." }
    } else {
        & $send @{ type='log'; level='ok'; text="None of the $($arad.Count) machine CVE(s) are on the KEV catalog ($($cat.Count) entries, $ageText)." }
    }
    if ($iavmTags.Count -gt 0) {
        & $send @{ type='log'; level='info'; text="$($iavmTags.Count) machine CVE(s) are IAVM-mapped: $(@($iavmTags) -join ', ')" }
    }
    & $send @{ type='status'; text="Done. $($overlap.Count) KEV overlap of $($arad.Count) machine CVE(s)." }
    return @{ rows=@($rows); summary=@{ total=$arad.Count; overlap=$overlap.Count; kev=$cat.Count; iavm=$iavmTags.Count; source=$cat.Source; updated=$catUpdated; ageDays=$catAge; stale=[bool]$cat.Stale } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
