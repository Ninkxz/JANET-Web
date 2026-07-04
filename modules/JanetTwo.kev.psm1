# =============================================================================
#  JanetTwo.kev.psm1  ->  KEV Cross-Check
#
#  Net-new JANET TWO tool (no desktop twin). Cross-references a machine's
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
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'kev'
        name     = 'KEV Cross-Check'
        version  = '1.0.2'
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
                destructive = $false
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

function Test-KevCveId {
    param([string]$Value)
    return ([string]$Value -match '^CVE-\d{4}-\d{4,}$')
}

# Read the catalog fresh each call. Format-agnostic: splits on any of
# newline/comma/semicolon/tab/space, so the file can be one-per-line OR the
# single comma-separated line CISA-style exports use. Returns a de-duped,
# numerically-sorted view plus a fast lookup HashSet. A missing/corrupt file
# yields an empty (but valid) catalog - it never throws.
function Read-KevCatalog {
    $p   = Get-KevCatalogPath
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object System.Collections.ArrayList
    $source = ''
    if (Test-Path -LiteralPath $p) {
        try {
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
        }
    } else {
        $source = '(missing - JanetLocal\KevCatalog.txt not found; use Add to KEV to create it)'
    }
    $sorted = Sort-KevCves @($list)
    return @{ Set = $set; List = $sorted; Count = $set.Count; Source = $source; Path = $p }
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
# copy (do NOT cross-import JanetTwo.reports.psm1 - each engine loads in its own
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
                foreach ($p in $props) {
                    $hit = @($rows | Where-Object { ([string]$_.$p) -match '(?i)CVE-\d{4}-\d{4,}' }).Count
                    if ($hit -gt 0) { $cveProp = $p; break }
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
                foreach ($mm in [regex]::Matches([string]$r.$cveProp, '(?i)CVE-\d{4}-\d{4,}')) {
                    $cve = $mm.Value.ToUpper()
                    if (-not $seen.Add($cve)) { continue }
                    $year = $rowYear
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

    # ---------------------------------------------------------------- list-kev
    if ($ActionId -eq 'list-kev') {
        & $send @{ type='status'; text="KEV catalog: $($cat.Count) CVE(s) - source: $($cat.Source)" }
        if ($cat.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="KEV catalog is empty - source: $($cat.Source). Use Add to KEV to populate it." }
            return @{ rows=@(); summary=@{ total=0; source=$cat.Source } }
        }
        $rows = New-Object System.Collections.ArrayList
        foreach ($cve in $cat.List) {
            $year = ''; $ym = [regex]::Match($cve, 'CVE-(\d{4})-'); if ($ym.Success) { $year = $ym.Groups[1].Value }
            $row = @{ _rk=$cve; CVE=$cve; Year=$year }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        & $send @{ type='log'; level='ok'; text="$($cat.Count) KEV CVE(s) loaded from $($cat.Source)." }
        return @{ rows=@($rows); summary=@{ total=$cat.Count; source=$cat.Source } }
    }

    # ---------------------------------------------------------------- add-kev
    if ($ActionId -eq 'add-kev') {
        $raw = [string]$Params['cves']
        $tokens = @($raw -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($tokens.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No CVE entered.' }
            return @{ rows=@(); summary=@{ added=0; duplicate=0; invalid=0 } }
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
        if ($added.Count -gt 0) {
            $final = Sort-KevCves @($newSet)
            try {
                Write-KevCatalog -List $final -Path $cat.Path
                & $send @{ type='log'; level='ok'; text="Saved $($added.Count) new CVE(s) to JanetLocal\KevCatalog.txt. KEV catalog is now $($final.Count) CVE(s)." }
                & $send @{ type='status'; text="Added $($added.Count); skipped $dup duplicate, $invalid invalid. Catalog now $($final.Count)." }
            } catch {
                & $send @{ type='error'; text="Save FAILED - catalog NOT changed: $($_.Exception.Message)" }
                return @{ rows=@($rows); summary=@{ added=0; duplicate=$dup; invalid=$invalid; saveError=$true } }
            }
        } else {
            & $send @{ type='log'; level='warn'; text="Nothing new to add - $dup already present/duplicate, $invalid invalid. Catalog unchanged ($($cat.Count))." }
            & $send @{ type='status'; text="Nothing added. $dup duplicate, $invalid invalid." }
        }
        return @{ rows=@($rows); summary=@{ added=$added.Count; duplicate=$dup; invalid=$invalid; total=($cat.Count + $added.Count) } }
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

    # IAVM map (badge each CVE with its IAVA / bulletin id when mapped). Empty map is
    # not a failure: rows simply carry IAVA=''.
    $iavm = Read-KevIavmMap
    & $send @{ type='status'; text="Cross-referencing $($arad.Count) machine CVE(s) against $($cat.Count) KEV CVE(s)..." }
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

    # Empty catalog must NEVER read as an all-clear: a clean result off zero KEV
    # entries is a false negative for a known-exploited-vuln tool. Hard-stop instead.
    if ($cat.Count -eq 0) {
        & $send @{ type='log'; level='err'; text="KEV catalog is EMPTY (source: $($cat.Source)) - this is NOT an all-clear. No cross-reference was performed. Populate the KEV Catalog tab (Add to KEV) or restore JanetLocal\KevCatalog.txt, then re-run." }
        & $send @{ type='status'; text="KEV catalog EMPTY - cannot cross-reference. Listed $($arad.Count) machine CVE(s); populate KEV and re-run." }
        return @{ rows=@($rows); summary=@{ total=$arad.Count; overlap=0; kev=0; empty=$true; source=$cat.Source } }
    }
    if ($overlap.Count -gt 0) {
        $sortedOverlap = Sort-KevCves @($overlap)
        & $send @{ type='log'; level='banner'; text="$($overlap.Count) of $($arad.Count) machine CVE(s) are on the CISA KEV list (KNOWN EXPLOITED - prioritize):" }
        & $send @{ type='log'; level='err'; text=($sortedOverlap -join ', ') }
    } else {
        & $send @{ type='log'; level='ok'; text="None of the $($arad.Count) machine CVE(s) are on the KEV catalog ($($cat.Count) entries)." }
    }
    if ($iavmTags.Count -gt 0) {
        & $send @{ type='log'; level='info'; text="$($iavmTags.Count) machine CVE(s) are IAVM-mapped: $(@($iavmTags) -join ', ')" }
    }
    & $send @{ type='status'; text="Done. $($overlap.Count) KEV overlap of $($arad.Count) machine CVE(s)." }
    return @{ rows=@($rows); summary=@{ total=$arad.Count; overlap=$overlap.Count; kev=$cat.Count; iavm=$iavmTags.Count; source=$cat.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
