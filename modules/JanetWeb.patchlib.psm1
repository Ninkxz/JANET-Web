# =============================================================================
#  JanetWeb.patchlib.psm1  ->  Patch Content (offline patch-content library)
#
#  Net-new JANET Web tool (no desktop twin). Read-only. Inventories the
#  remediation content already STAGED for offline / air-gapped use and cross-
#  references it against the KBs an operator still needs, so on an isolated net
#  they can see at a glance what can be pushed today vs. what is missing.
#
#  Two actions, both purely local file work (NO WinRM, NO hosts touched):
#    inventory - scan the content roots (the repo .\Packages folder, the work
#                share \\dm-tn-01\sh-usafe-automation$\JANET\Packages when the
#                host is reachable on 445, plus an operator-supplied extra path),
#                classify every item (PSADT package folder / MSI / MSU / CAB /
#                EXE / other) and extract name/size/date/KB-id (regex KB\d{6,7}).
#    crossref  - take a pasted list of needed KBs and/or product names AND/OR an
#                uploaded ACAS CSV (server temp path, acas convention), pull the
#                needed KB tokens leniently, and mark each ON HAND (staged
#                content matches) or MISSING. Stat cards: needed / on hand /
#                missing / coverage %.
#
#  Because no host is touched, this tool emits NO audit rows (the server's
#  TouchHost/VulnPatched ValidateSet does not apply). The server still keeps a
#  per-action session log automatically. Read-only: nothing is ever written.
#  Parsing is lenient and never throws on malformed input.
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'patchlib'
        name     = 'Patch Content'
        version  = '1.0.1'
        category = 'Remediation'
        summary  = 'Offline patch-content library. Inventories the remediation content already staged for air-gapped use (the repo .\Packages folder, the work share when reachable, plus an operator extra path) - classifying PSADT packages, MSI / MSU / CAB / EXE bundles and pulling KB ids from filenames - then cross-references it against the KBs you still need (pasted list or an uploaded ACAS CSV) so you know what can be pushed today and what is MISSING. Read-only; touches no hosts.'
        actions  = @(
            @{
                id          = 'inventory'
                label       = 'Inventory Content'
                description = 'Scan the content roots (repo .\Packages, the work share \\dm-tn-01\sh-usafe-automation$\JANET\Packages when reachable on 445, and an optional extra folder) and list every staged item - PSADT package folder / MSI / MSU / CAB / EXE / other - with its name, size, date and any KB id parsed from the filename. Read-only.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Name','ItemType','KB','Size','Modified','Location')
                inputs      = @(
                    @{ name='extraPath'; label='Extra content folder (optional UNC or local path)'; type='text'; required=$false }
                )
            }
            @{
                id          = 'crossref'
                label       = 'Cross-Reference'
                description = 'Match a list of needed KBs / product names (pasted and/or from an uploaded ACAS CSV) against the staged content and mark each ON HAND or MISSING. Read-only - no hosts touched.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Needed','Kind','Status','Matches')
                inputs      = @(
                    @{ name='needed';    label='Needed KBs / product names (one per line)'; type='text'; required=$false },
                    @{ name='csvPaths';  label='ACAS CSV (optional)'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$false },
                    @{ name='extraPath'; label='Extra content folder (optional UNC or local path)'; type='text'; required=$false }
                )
            }
        )
    }
}

# --- Content roots ----------------------------------------------------------
# The work share where the desktop suite stages package content. This is only
# the DEFAULT share leg: the server's full $packagesDir resolution also honors an
# explicit -PackagesRoot override (server\JanetWeb.Server.ps1). When the server is
# launched with -PackagesRoot it exports the resolved path as JANETWEB_PACKAGES_ROOT
# (env), which Get-PatchlibRoots picks up below so the tool scans exactly the
# folder the Remote Package Installer pushes from.
$script:PatchlibShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages'

function Get-PatchlibLocalPackages { Join-Path $PSScriptRoot '..\Packages' }

# AFNET-safe reachability: pure-TCP (never ICMP). One connect to 445 with a short
# timeout so a dead share never hangs the enumeration. Returns $true/$false.
function Test-PatchlibShareReachable {
    param([string]$ComputerName, [int]$Port = 445, [int]$TimeoutMs = 1500)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    $tc = $null
    try {
        $tc = New-Object System.Net.Sockets.TcpClient
        $iar = $tc.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) { return $true }
        return $false
    } catch { return $false }
    finally { if ($tc) { try { $tc.Close() } catch {} } }
}

# Resolve the list of roots to scan. Each entry is @{ Path; Label; Ok; Note }.
# The local .\Packages is always included (created by the server on boot). The
# work share is included ONLY when its host answers on 445 (ping-gated, so a
# dead share never stalls). An operator extra path is included when it exists.
function Get-PatchlibRoots {
    param([string]$ExtraPath)
    $roots = New-Object System.Collections.ArrayList

    $local = Get-PatchlibLocalPackages
    try { $local = (Resolve-Path -LiteralPath $local -ErrorAction Stop).Path } catch {}
    if (Test-Path -LiteralPath $local) { [void]$roots.Add(@{ Path=$local; Label='Local'; Ok=$true; Note='repo .\Packages' }) }
    else { [void]$roots.Add(@{ Path=$local; Label='Local'; Ok=$false; Note='repo .\Packages not present' }) }

    $shareHost = $null
    if ($script:PatchlibShare -match '^\\\\([^\\]+)') { $shareHost = $Matches[1] }
    $shareOk = $false
    if ($shareHost) { $shareOk = Test-PatchlibShareReachable $shareHost }
    if ($shareOk -and (Test-Path -LiteralPath $script:PatchlibShare)) {
        [void]$roots.Add(@{ Path=$script:PatchlibShare; Label='Share'; Ok=$true; Note='work share' })
    } elseif ($shareOk) {
        [void]$roots.Add(@{ Path=$script:PatchlibShare; Label='Share'; Ok=$false; Note='host up but path not accessible' })
    } else {
        [void]$roots.Add(@{ Path=$script:PatchlibShare; Label='Share'; Ok=$false; Note='host unreachable on 445' })
    }

    # Server-resolved packages root (honors the launcher's -PackagesRoot override).
    # Included as a distinct leg only when it differs from the local + share legs
    # already added, so a plain launch never double-scans the same folder.
    $srvRoot = [string]$env:JANETWEB_PACKAGES_ROOT
    # TWO-era name kept as a read-only fallback: operator environments may still set it.
    if ([string]::IsNullOrWhiteSpace($srvRoot)) { $srvRoot = [string]$env:JANET2_PACKAGES_ROOT }
    if (-not [string]::IsNullOrWhiteSpace($srvRoot)) {
        $sr = $srvRoot.Trim().Trim('"')
        $already = $false
        foreach ($rr in $roots) { if (([string]$rr.Path).TrimEnd('\') -eq $sr.TrimEnd('\')) { $already = $true; break } }
        if (-not $already) {
            $srOk = $true
            if ($sr -match '^\\\\([^\\]+)') { $srOk = Test-PatchlibShareReachable $Matches[1] }
            if ($srOk -and (Test-Path -LiteralPath $sr)) { [void]$roots.Add(@{ Path=$sr; Label='Server'; Ok=$true; Note='server -PackagesRoot' }) }
            elseif ($srOk) { [void]$roots.Add(@{ Path=$sr; Label='Server'; Ok=$false; Note='server -PackagesRoot not accessible' }) }
            else { [void]$roots.Add(@{ Path=$sr; Label='Server'; Ok=$false; Note='server -PackagesRoot host unreachable on 445' }) }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExtraPath)) {
        $ep = ([string]$ExtraPath).Trim().Trim('"')
        # 445-gate a UNC extra path the same way the work share is gated, so a dead
        # host does not stall Test-Path (and later Get-ChildItem) for the full SMB
        # connect/retry timeout with no cancel button in the UI.
        $epHostOk = $true
        if ($ep -match '^\\\\([^\\]+)') { $epHostOk = Test-PatchlibShareReachable $Matches[1] }
        if (-not $epHostOk) { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$false; Note='operator path host unreachable on 445' }) }
        elseif (Test-Path -LiteralPath $ep) { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$true; Note='operator path' }) }
        else { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$false; Note='operator path not found' }) }
    }
    return @($roots)
}

# Pull every KB id (regex KB\d{6,7}) from a string. Returns an upper-cased,
# de-duped [string[]] (possibly empty). Never throws.
function Get-PatchlibKbTokens {
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    foreach ($m in [regex]::Matches([string]$Text, '(?i)(?<![A-Za-z0-9])KB\d{6,7}(?!\d)')) {
        $kb = $m.Value.ToUpper()
        if ($seen.Add($kb)) { [void]$out.Add($kb) }
    }
    return ,@($out)
}

# Human-friendly byte size. Blank for a null/negative input.
function Format-PatchlibSize {
    param($Bytes)
    $b = 0L
    if (-not [long]::TryParse([string]$Bytes, [ref]$b)) { return '' }
    if ($b -lt 0) { return '' }
    if ($b -lt 1024)            { return "$b B" }
    if ($b -lt 1048576)         { return ('{0:N1} KB' -f ($b / 1024)) }
    if ($b -lt 1073741824)      { return ('{0:N1} MB' -f ($b / 1048576)) }
    return ('{0:N2} GB' -f ($b / 1073741824))
}

# Classify one item (file or directory) -> @{ Type; KbList }.
# Directory: PSADT when it holds a Deploy-Application.ps1 OR an
# Invoke-AppDeployToolkit.ps1 (PSADT v4's entry script - parity with the
# pkginstall v4 support; audit 2026-07-23) anywhere in the tree (recurse,
# bounded); else Folder. File: by extension. KB ids come from the item name AND,
# for a package folder, from any installer filename inside it. Never throws.
function Get-PatchlibItemInfo {
    param($Item)
    $info = @{ Type='Other'; KbList=@() }
    $kbSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in (Get-PatchlibKbTokens $Item.Name)) { [void]$kbSet.Add($k) }

    if ($Item.PSIsContainer) {
        # audit 2026-07-23: ONE bounded walk detects the PSADT marker AND harvests
        # installer-filename KB ids (was two full recursive share walks per folder).
        # NOTE: -Include is silently ignored when combined with -LiteralPath on
        # PS 5.1 (it only filters with -Path), so match names/extensions inline.
        # The 200-installer cap keeps bounding a huge package; the walk stops early
        # once the marker is found AND the cap is hit.
        $isPsadt = $false
        $harvested = 0
        try {
            foreach ($f in (Get-ChildItem -LiteralPath $Item.FullName -Recurse -Depth 4 -File -ErrorAction SilentlyContinue)) {
                if (-not $isPsadt -and ($f.Name -eq 'Deploy-Application.ps1' -or $f.Name -eq 'Invoke-AppDeployToolkit.ps1')) { $isPsadt = $true }
                if ($harvested -lt 200 -and $f.Extension -match '^(?i)\.(msi|msu|cab|exe)$') {
                    $harvested++
                    foreach ($k in (Get-PatchlibKbTokens $f.Name)) { [void]$kbSet.Add($k) }
                }
                if ($isPsadt -and $harvested -ge 200) { break }
            }
        } catch {}
        if ($isPsadt) { $info.Type = 'PSADT' } else { $info.Type = 'Folder' }
    } else {
        $ext = ''
        try { $ext = ([string]$Item.Extension).ToLower() } catch {}
        switch ($ext) {
            '.msi' { $info.Type = 'MSI' }
            '.msu' { $info.Type = 'MSU' }
            '.cab' { $info.Type = 'CAB' }
            '.exe' { $info.Type = 'EXE' }
            default { $info.Type = 'Other' }
        }
    }
    $info.KbList = @($kbSet)
    return $info
}

# Total size (bytes) of a directory's files, bounded + guarded (a huge or slow
# share folder must not hang the scan). -Depth caps the walk (matching the KB
# scan) so a deep tree on a slow share cannot stall inventory. Returns $null when
# it cannot be measured.
function Get-PatchlibFolderSize {
    param([string]$Path)
    try {
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $sum) { return 0L }
        return [long]$sum
    } catch { return $null }
}

# Build the staged-content inventory from the resolved roots. Returns an array of
# @{ Name; Type; KbList; Kb; SizeBytes; Size; Modified; Location; Path; Rk }.
# Read-only enumeration; each root/item is guarded so one bad path never aborts.
function Get-PatchlibInventory {
    # Param is '$Sink' (NOT '$Emit'): the caller passes its own '$send' wrapper,
    # which lexically references '$Emit'. PowerShell is dynamically scoped, so if
    # this parameter were named '$Emit' the caller's wrapper - executed inside this
    # function's call chain - would resolve '$Emit' to THIS parameter (itself) and
    # recurse until a call-depth overflow. A distinct name breaks that shadowing.
    # -SkipSizes: crossref never displays folder size, so it sets this to skip the
    # per-folder recursive size walk entirely (avoids a full SMB metadata walk of
    # the share tree just to match KBs).
    param([array]$Roots, [scriptblock]$Sink, [switch]$SkipSizes)
    $send = { param($e) if ($Sink) { & $Sink $e } }
    $items = New-Object System.Collections.ArrayList
    foreach ($root in $Roots) {
        if (-not $root.Ok) { continue }
        $rootPath = [string]$root.Path
        $label    = [string]$root.Label
        & $send @{ type='log'; level='info'; text="Scanning $label root: $rootPath" }
        $entries = @()
        try { $entries = @(Get-ChildItem -LiteralPath $rootPath -Force -ErrorAction SilentlyContinue | Sort-Object PSIsContainer, Name) } catch { $entries = @() }
        foreach ($e in $entries) {
            try {
                $info = Get-PatchlibItemInfo $e
                $sizeBytes = $null
                if ($e.PSIsContainer) { if (-not $SkipSizes) { $sizeBytes = Get-PatchlibFolderSize $e.FullName } }
                else { try { $sizeBytes = [long]$e.Length } catch { $sizeBytes = $null } }
                $modified = ''
                try { $modified = $e.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } catch {}
                $kbJoin = ''
                if ($info.KbList.Count -gt 0) { $kbJoin = (@($info.KbList) -join ', ') }
                $rec = @{
                    Name      = [string]$e.Name
                    Type      = [string]$info.Type
                    KbList    = @($info.KbList)
                    Kb        = $kbJoin
                    SizeBytes = $sizeBytes
                    Size      = (Format-PatchlibSize $sizeBytes)
                    Modified  = $modified
                    Location  = $label
                    Path      = [string]$e.FullName
                    Rk        = ($label + '|' + [string]$e.FullName)
                }
                [void]$items.Add($rec)
            } catch {
                & $send @{ type='log'; level='warn'; text="Skipped '$($e.Name)': $($_.Exception.Message)" }
            }
        }
    }
    return @($items)
}

# Read an uploaded ACAS CSV (server temp path; newline-separated like acas) and
# pull KB tokens leniently from the plugin / solution / cve columns, falling back
# to a raw regex scan of the whole file for any other layout. Never throws.
function Get-PatchlibCsvKbs {
    param([string]$Raw)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return ,@() }
    foreach ($p in ($Raw -split '[\r\n]+')) {
        $path = ([string]$p).Trim().Trim('"')
        if (-not $path) { continue }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $text = ''
        try { $text = Get-Content -LiteralPath $path -Raw -ErrorAction Stop } catch { $text = '' }
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $usedCols = $false
        $fileTokens = 0
        try {
            $rows = @($text | ConvertFrom-Csv -ErrorAction Stop)
            if ($rows.Count -gt 0 -and $rows[0].PSObject) {
                $cols = @($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)plugin|solution|cve|synopsis|description|name' })
                if ($cols.Count -gt 0) {
                    foreach ($r in $rows) {
                        foreach ($c in $cols) {
                            foreach ($k in (Get-PatchlibKbTokens ([string]$r.$c))) { $fileTokens++; [void]$set.Add($k) }
                        }
                    }
                    $usedCols = $true
                }
            }
        } catch { $usedCols = $false; $fileTokens = 0 }
        # Fall back to a whole-file regex scan when there were no matching columns
        # OR the matched columns yielded zero KBs (e.g. 'name' matched a DNS-Name
        # header but the KB ids live in an unmatched 'Fix Text' column).
        if (-not $usedCols -or $fileTokens -eq 0) {
            foreach ($k in (Get-PatchlibKbTokens $text)) { [void]$set.Add($k) }
        }
    }
    return ,@($set)
}

# Parse the operator's needed-list textarea into needed items. Each line yields
# either KB item(s) (any KB\d{6,7} token, or a bare 6-7 digit number treated as a
# KB) OR - when the line carries no KB - a Product item (the trimmed line).
# Returns an array of @{ Value; Kind } de-duped. Never throws.
function Get-PatchlibNeededFromText {
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    foreach ($line in ($Text -split '[\r\n]+')) {
        $l = ([string]$line).Trim()
        if (-not $l) { continue }
        if ($l.StartsWith('#')) { continue }
        $kbs = Get-PatchlibKbTokens $l
        if ($kbs.Count -eq 0) {
            # bare 6-7 digit KB number (no prefix)?
            $bare = New-Object System.Collections.ArrayList
            foreach ($m in [regex]::Matches($l, '(?<![A-Za-z0-9])\d{6,7}(?![0-9])')) { [void]$bare.Add(('KB' + $m.Value)) }
            $kbs = @($bare)
        }
        if ($kbs.Count -gt 0) {
            foreach ($kb in $kbs) {
                $key = 'KB|' + $kb.ToUpper()
                if ($seen.Add($key)) { [void]$out.Add(@{ Value=$kb.ToUpper(); Kind='KB' }) }
            }
        } else {
            $key = 'P|' + $l.ToLower()
            if ($seen.Add($key)) { [void]$out.Add(@{ Value=$l; Kind='Product' }) }
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
    if ($null -eq $Params) { $Params = @{} }
    $extraPath = [string]$Params['extraPath']

    # ---------------------------------------------------------------- inventory
    if ($ActionId -eq 'inventory') {
        $roots = Get-PatchlibRoots -ExtraPath $extraPath
        foreach ($r in $roots) {
            $state = if ($r.Ok) { 'included' } else { 'skipped' }
            $lvl = if ($r.Ok) { 'ok' } else { 'warn' }
            & $send @{ type='log'; level=$lvl; text="Root [$($r.Label)] $($r.Path) - $state ($($r.Note))." }
        }
        $okRoots = @($roots | Where-Object { $_.Ok })
        & $send @{ type='status'; text="Inventorying staged content across $($okRoots.Count) root(s)..." }
        if ($okRoots.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='No reachable content roots. Nothing to inventory.' }
            return @{ rows=@(); summary=@{ total=0; roots=0 } }
        }

        $inv = Get-PatchlibInventory -Roots $roots -Sink $send
        $rows = New-Object System.Collections.ArrayList
        foreach ($it in $inv) {
            # NOTE: the emitted key is 'ItemType', not 'Type' - a row hashtable
            # merged with '@{ type=''row'' }' cannot carry a case-insensitively
            # colliding 'Type' key (PowerShell hashtable keys are case-insensitive).
            $row = @{ _rk=$it.Rk; Name=$it.Name; ItemType=$it.Type; KB=$it.Kb; Size=$it.Size; Modified=$it.Modified; Location=$it.Location }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }

        # Tally by type + KB coverage.
        $byType = @{}
        foreach ($t in @('PSADT','MSI','MSU','CAB','EXE','Folder','Other')) { $byType[$t] = 0 }
        $withKb = 0; $kbAll = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($it in $inv) {
            if ($byType.ContainsKey($it.Type)) { $byType[$it.Type]++ } else { $byType[$it.Type] = 1 }
            if ($it.KbList.Count -gt 0) { $withKb++; foreach ($k in $it.KbList) { [void]$kbAll.Add($k) } }
        }
        & $send @{ type='log'; level='ok'; text="Inventory: $($inv.Count) item(s) - PSADT=$($byType['PSADT']) MSI=$($byType['MSI']) MSU=$($byType['MSU']) CAB=$($byType['CAB']) EXE=$($byType['EXE']) Folder=$($byType['Folder']) Other=$($byType['Other']). $($kbAll.Count) distinct KB id(s) across $withKb item(s)." }
        & $send @{ type='status'; text="Done. $($inv.Count) staged item(s) across $($okRoots.Count) root(s); $($kbAll.Count) KB id(s) on hand." }
        return @{ rows=@($rows); summary=@{
            total=$inv.Count; roots=$okRoots.Count; withKb=$withKb; distinctKbs=$kbAll.Count
            psadt=$byType['PSADT']; msi=$byType['MSI']; msu=$byType['MSU']; cab=$byType['CAB']; exe=$byType['EXE']; folder=$byType['Folder']; other=$byType['Other']
        } }
    }

    # ---------------------------------------------------------------- crossref
    if ($ActionId -ne 'crossref') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # Assemble the needed items: pasted text + KBs pulled from the uploaded CSV.
    $needed = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in (Get-PatchlibNeededFromText ([string]$Params['needed']))) {
        $key = $n.Kind + '|' + ([string]$n.Value).ToLower()
        if ($seen.Add($key)) { [void]$needed.Add($n) }
    }
    $csvKbCount = 0
    foreach ($kb in (Get-PatchlibCsvKbs ([string]$Params['csvPaths']))) {
        $csvKbCount++
        $key = 'KB|' + ([string]$kb).ToLower()
        if ($seen.Add($key)) { [void]$needed.Add(@{ Value=([string]$kb).ToUpper(); Kind='KB' }) }
    }
    if ($csvKbCount -gt 0) { & $send @{ type='log'; level='info'; text="Pulled $csvKbCount KB id(s) from the uploaded ACAS CSV." } }

    if ($needed.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No needed KBs or product names supplied. Paste a list and/or upload an ACAS CSV, then re-run.' }
        return @{ rows=@(); summary=@{ needed=0; onHand=0; missing=0; coverage=0 } }
    }

    # Build the on-hand inventory once and index it for matching.
    $roots = Get-PatchlibRoots -ExtraPath $extraPath
    foreach ($r in $roots) {
        $lvl = if ($r.Ok) { 'ok' } else { 'warn' }
        $state = if ($r.Ok) { 'included' } else { 'skipped' }
        & $send @{ type='log'; level=$lvl; text="Root [$($r.Label)] $($r.Path) - $state ($($r.Note))." }
    }
    & $send @{ type='status'; text="Cross-referencing $($needed.Count) needed item(s) against staged content..." }
    $inv = Get-PatchlibInventory -Roots $roots -Sink $send -SkipSizes

    # Index: KB id -> matching item names; keep a flat name list for product substring hits.
    $kbIndex = @{}
    $allItems = New-Object System.Collections.ArrayList
    foreach ($it in $inv) {
        [void]$allItems.Add($it)
        foreach ($k in $it.KbList) {
            $ku = ([string]$k).ToUpper()
            if (-not $kbIndex.ContainsKey($ku)) { $kbIndex[$ku] = New-Object System.Collections.ArrayList }
            [void]$kbIndex[$ku].Add($it.Name)
        }
    }

    $rows = New-Object System.Collections.ArrayList
    $onHand = 0; $idx = 0
    foreach ($n in $needed) {
        $idx++
        $val = [string]$n.Value
        $kind = [string]$n.Kind
        # NOTE: do NOT name this '$matches' - that is PowerShell's automatic
        # variable clobbered by every -match; keep it a plain ArrayList.
        $hits = New-Object System.Collections.ArrayList
        if ($kind -eq 'KB') {
            $ku = $val.ToUpper()
            if ($kbIndex.ContainsKey($ku)) { foreach ($m in $kbIndex[$ku]) { if (-not $hits.Contains($m)) { [void]$hits.Add($m) } } }
            # also match the KB even when it is not classified into KbList: the
            # prefixed form (substring) OR the BARE digits (digit-boundary regex, so
            # staged content named '5034441.msu' / a folder keyed by bare number is
            # still found - symmetry with the needed-side bare-number normalization).
            $bareRe = $null
            if ($ku.Length -gt 2) { $bareRe = '(?<!\d)' + [regex]::Escape($ku.Substring(2)) + '(?!\d)' }
            foreach ($it in $allItems) {
                if (-not $hits.Contains($it.Name)) {
                    $nm = [string]$it.Name
                    if (($nm.ToUpper().Contains($ku)) -or ($bareRe -and ($nm -match $bareRe))) { [void]$hits.Add($it.Name) }
                }
            }
        } else {
            # product-name substring match (case-insensitive) against item names.
            $needle = $val.ToLower()
            if ($needle) {
                foreach ($it in $allItems) {
                    if (([string]$it.Name).ToLower().Contains($needle) -and (-not $hits.Contains($it.Name))) { [void]$hits.Add($it.Name) }
                }
            }
        }
        $status = if ($hits.Count -gt 0) { 'ON HAND' } else { 'MISSING' }
        if ($hits.Count -gt 0) { $onHand++ }
        $matchTxt = ''
        if ($hits.Count -gt 0) { $matchTxt = ((@($hits) | Select-Object -First 6) -join '; '); if ($hits.Count -gt 6) { $matchTxt += " (+$($hits.Count - 6) more)" } }
        $row = @{ _rk=("$idx|$kind|$val"); Needed=$val; Kind=$kind; Status=$status; Matches=$matchTxt }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
    }

    $missing = $needed.Count - $onHand
    $coverage = if ($needed.Count -gt 0) { [math]::Round(($onHand / $needed.Count) * 100, 1) } else { 0 }
    if ($missing -gt 0) {
        & $send @{ type='log'; level='warn'; text="$missing of $($needed.Count) needed item(s) are MISSING from staged content - stage these before an air-gapped push." }
    } else {
        & $send @{ type='log'; level='ok'; text="All $($needed.Count) needed item(s) are ON HAND - ready to push offline." }
    }
    & $send @{ type='status'; text="Done. $onHand on hand, $missing missing of $($needed.Count) ($coverage% coverage)." }
    return @{ rows=@($rows); summary=@{ needed=$needed.Count; onHand=$onHand; missing=$missing; coverage=$coverage; inventory=$inv.Count } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
