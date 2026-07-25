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
#  v1.1.1 (audit 2026-07-25 (fable re-audit follow-up)) one correctness fix:
#    - the operator's extraPath root now de-dupes on the SAME canonical path key the
#      -PackagesRoot leg uses. Pasting the work share (or the repo Packages folder)
#      into "extra content folder" added it a SECOND time and double-counted the
#      whole inventory - every stat card doubled, every package listed twice.
#
#  v1.1.0 (audit 2026-07-24) four correctness/cost fixes:
#    - crossref gained a THIRD verdict, UNKNOWN. A content root that could not be
#      read is not evidence of absence; crossref used to render every unmatched
#      item MISSING even when ZERO roots were scanned (it never had the zero-root
#      guard the inventory path has), so "I did not look there" read exactly like
#      "it is not there" - the error that gets an operator to a closed network
#      without the patch. Skipped roots now flow into the verdict and the summary.
#    - product names match on NORMALISED TOKENS, not a raw substring, so a
#      multi-word name finally hits a real package folder ("Google Chrome" ->
#      'GoogleChrome_120.0.6099'). The old test could not match ANY multi-word
#      product, including the view's own "Google Chrome" placeholder.
#    - the -PackagesRoot leg de-dupes on a canonical path key, so an FQDN or a
#      relative alias of a folder already listed no longer double-counts the
#      entire inventory.
#    - folder size rides the SINGLE bounded classify/KB walk (Get-PatchlibFolderSize
#      is gone): every folder used to be walked TWICE per inventory.
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
        version  = '1.1.1'   # audit 2026-07-25 (fable re-audit follow-up): extraPath root de-dupes on the canonical path key
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
                description = 'Match a list of needed KBs / product names (pasted and/or from an uploaded ACAS CSV) against the staged content and mark each ON HAND, MISSING, or UNKNOWN. UNKNOWN means a content root could not be scanned, so this run cannot prove the item is absent - never read it as MISSING. Read-only - no hosts touched.'
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

# Canonical, comparable identity for a content root (audit 2026-07-24). The
# -PackagesRoot leg used to de-dupe on the RAW string, so '\\dm-tn-01\...' vs its
# FQDN, or '.\Packages' vs the resolved absolute path, read as two different roots
# and the ENTIRE inventory was counted twice (doubling every stat card and making
# the same package appear on two rows).
#
# [System.IO.Path]::GetFullPath is a PURE string normalisation - it collapses '.'
# and '..' and roots a relative alias against the process CWD WITHOUT touching the
# filesystem, so unlike Resolve-Path it can never stall on a dead UNC host (this
# runs BEFORE the 445 reachability gate). Never throws.
function Get-PatchlibPathKey {
    param([string]$Path)
    $p = ([string]$Path).Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    try { $p = [System.IO.Path]::GetFullPath($p) } catch {}
    $p = $p.TrimEnd('\', '/')
    # A UNC host is the same server whether it is spelled short or FQDN, so key on
    # the short name: '\\dm-tn-01.area52.afnoapps.usaf.mil\x' == '\\dm-tn-01\x'.
    if ($p -match '^\\\\([^\\]+)(\\.*)?$') {
        $p = '\\' + (($Matches[1] -split '\.')[0]) + ([string]$Matches[2])
    }
    return $p.ToLowerInvariant()
}

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
        # audit 2026-07-24: compare CANONICAL keys, not raw strings - an FQDN or a
        # relative alias of a root already listed used to slip through and double-scan
        # (and so double-count) the whole inventory.
        $already = $false
        $srKey = Get-PatchlibPathKey $sr
        foreach ($rr in $roots) { if ((Get-PatchlibPathKey ([string]$rr.Path)) -eq $srKey) { $already = $true; break } }
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
        # audit 2026-07-25 (fable re-audit follow-up): the operator's extra folder gets the
        # SAME canonical-key de-dupe the -PackagesRoot leg got - pasting the work share (or
        # the repo Packages folder) as "extra folder" used to add it as a SECOND root and
        # double-count the entire inventory: every item twice, every stat card doubled, and
        # two grid rows per package (the row key is Label|FullName, so the duplicate does
        # not even collapse). Only an EXACT canonical match is dropped, so a genuinely
        # distinct folder - including a subfolder or sibling of a listed root - is still
        # scanned. A de-duped duplicate is NOT added as a skipped root: it is already being
        # scanned, so recording it Ok=$false would fabricate an unreadable root and push
        # crossref's honest MISSING verdicts to UNKNOWN for no reason.
        $epKey = Get-PatchlibPathKey $ep
        $epDup = $false
        foreach ($rr in $roots) { if ((Get-PatchlibPathKey ([string]$rr.Path)) -eq $epKey) { $epDup = $true; break } }
        if (-not $epDup) {
            # 445-gate a UNC extra path the same way the work share is gated, so a dead
            # host does not stall Test-Path (and later Get-ChildItem) for the full SMB
            # connect/retry timeout with no cancel button in the UI.
            $epHostOk = $true
            if ($ep -match '^\\\\([^\\]+)') { $epHostOk = Test-PatchlibShareReachable $Matches[1] }
            if (-not $epHostOk) { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$false; Note='operator path host unreachable on 445' }) }
            elseif (Test-Path -LiteralPath $ep) { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$true; Note='operator path' }) }
            else { [void]$roots.Add(@{ Path=$ep; Label='Extra'; Ok=$false; Note='operator path not found' }) }
        }
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

# Normalise a name for product matching: keep ASCII letters/digits only, lower-
# case. 'Google_Chrome-124.0 (x64)' -> 'googlechrome1240x64'. The separators are
# EXACTLY what differs between an operator's "Google Chrome" and a real package
# folder name, so dropping them is the whole point (audit 2026-07-24). Never throws.
function Get-PatchlibNormalizedName {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return ([regex]::Replace([string]$Text, '[^A-Za-z0-9]+', '')).ToLowerInvariant()
}

# Split an operator-supplied product name into normalised match tokens
# ('Google Chrome 120' -> google, chrome, 120). The split pattern is OURS, not the
# operator's, so there is no -match/regex-injection surface here: the operator's
# text is only ever the SUBJECT of the split and is compared with literal
# .Contains() afterwards. Empty pieces dropped. Never throws.
function Get-PatchlibNameTokens {
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    foreach ($p in ([regex]::Split([string]$Text, '[^A-Za-z0-9]+'))) {
        $t = Get-PatchlibNormalizedName $p
        if ($t) { [void]$out.Add($t) }
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

# Classify one item (file or directory) -> @{ Type; KbList; SizeBytes }.
# Directory: PSADT when it holds a Deploy-Application.ps1 OR an
# Invoke-AppDeployToolkit.ps1 (PSADT v4's entry script - parity with the
# pkginstall v4 support; audit 2026-07-23) anywhere in the tree (recurse,
# bounded); else Folder. File: by extension. KB ids come from the item name AND,
# for a package folder, from any installer filename inside it. Never throws.
# -WithSize additionally sums the folder's files during that SAME walk; SizeBytes
# stays $null when it was not asked for or could not be measured.
function Get-PatchlibItemInfo {
    param($Item, [switch]$WithSize)
    $info = @{ Type='Other'; KbList=@(); SizeBytes=$null }
    $kbSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in (Get-PatchlibKbTokens $Item.Name)) { [void]$kbSet.Add($k) }

    if ($Item.PSIsContainer) {
        # audit 2026-07-23: ONE bounded walk detects the PSADT marker AND harvests
        # installer-filename KB ids (was two full recursive share walks per folder).
        # audit 2026-07-24: the FOLDER SIZE now rides that same walk too. A separate
        # Get-PatchlibFolderSize recursed the identical bounded tree a second time, so
        # every folder was enumerated TWICE per inventory - double the SMB metadata
        # round-trips on the work share for a number this walk already had in hand.
        # NOTE: -Include is silently ignored when combined with -LiteralPath on
        # PS 5.1 (it only filters with -Path), so match names/extensions inline.
        # The 200-installer cap keeps bounding a huge package; the walk stops early
        # once the marker is found AND the cap is hit - but ONLY when we are not
        # summing sizes, since breaking mid-tree would under-report the folder size.
        $isPsadt = $false
        $harvested = 0
        $bytes = 0L
        $walked = $false
        try {
            foreach ($f in (Get-ChildItem -LiteralPath $Item.FullName -Recurse -Depth 4 -File -ErrorAction SilentlyContinue)) {
                if (-not $isPsadt -and ($f.Name -eq 'Deploy-Application.ps1' -or $f.Name -eq 'Invoke-AppDeployToolkit.ps1')) { $isPsadt = $true }
                if ($harvested -lt 200 -and $f.Extension -match '^(?i)\.(msi|msu|cab|exe)$') {
                    $harvested++
                    foreach ($k in (Get-PatchlibKbTokens $f.Name)) { [void]$kbSet.Add($k) }
                }
                if ($WithSize) { try { $bytes += [long]$f.Length } catch {} }
                if (-not $WithSize -and $isPsadt -and $harvested -ge 200) { break }
            }
            $walked = $true
        } catch { $walked = $false }
        if ($isPsadt) { $info.Type = 'PSADT' } else { $info.Type = 'Folder' }
        # Unmeasurable stays $null (renders blank), matching the old helper.
        if ($WithSize -and $walked) { $info.SizeBytes = $bytes }
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

# (audit 2026-07-24: Get-PatchlibFolderSize is gone - its bounded recursive walk
#  was a verbatim duplicate of the classify/KB walk, so folder size is now summed
#  inline by Get-PatchlibItemInfo -WithSize. Same bound (-Depth 4), same guards,
#  half the enumerations.)

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
                # audit 2026-07-24: one walk per folder - classify, KB harvest and size
                # all come back from the SAME enumeration (see Get-PatchlibItemInfo).
                $wantSize = ($e.PSIsContainer -and -not $SkipSizes)
                $info = Get-PatchlibItemInfo -Item $e -WithSize:$wantSize
                $sizeBytes = $null
                if ($e.PSIsContainer) { if ($wantSize) { $sizeBytes = $info.SizeBytes } }
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
    # audit 2026-07-24: a root we could NOT read is not evidence of absence. crossref
    # had NO skipped-root signal and none of the zero-root guarding the inventory path
    # has, so an unreachable share (or a run with nothing reachable at all) rendered
    # every unmatched item as a flat MISSING - "I did not look there" printed exactly
    # like "it is not there". That is the error that gets someone to a closed network
    # without the patch. Skipped roots now carry through to a distinct UNKNOWN verdict.
    $okRoots      = @($roots | Where-Object { $_.Ok })
    $skippedRoots = @($roots | Where-Object { -not $_.Ok })
    $skipNote = ''
    if ($skippedRoots.Count -gt 0) { $skipNote = ((@($skippedRoots | ForEach-Object { "$($_.Label): $($_.Note)" })) -join '; ') }
    if ($okRoots.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text="NO reachable content roots ($skipNote) - NOTHING was scanned. Every needed item is reported UNKNOWN, not MISSING: this run proves nothing about what is staged. Fix the roots and re-run before trusting any coverage number." }
    } elseif ($skippedRoots.Count -gt 0) {
        & $send @{ type='log'; level='warn'; text="$($skippedRoots.Count) content root(s) were NOT scanned ($skipNote). Unmatched items are reported UNKNOWN rather than MISSING - they may well be staged on a root this run could not read." }
    }
    & $send @{ type='status'; text="Cross-referencing $($needed.Count) needed item(s) against staged content..." }
    $inv = Get-PatchlibInventory -Roots $roots -Sink $send -SkipSizes

    # Index: KB id -> matching item names; keep a flat name list for product hits.
    $kbIndex = @{}
    $allItems = New-Object System.Collections.ArrayList
    foreach ($it in $inv) {
        # Normalise each item name ONCE here, not once per (needed x item) pair below.
        $it.NameNorm = Get-PatchlibNormalizedName ([string]$it.Name)
        [void]$allItems.Add($it)
        foreach ($k in $it.KbList) {
            $ku = ([string]$k).ToUpper()
            if (-not $kbIndex.ContainsKey($ku)) { $kbIndex[$ku] = New-Object System.Collections.ArrayList }
            [void]$kbIndex[$ku].Add($it.Name)
        }
    }

    $rows = New-Object System.Collections.ArrayList
    $onHand = 0; $unknown = 0; $idx = 0
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
            # audit 2026-07-24: product names match on NORMALISED TOKENS, not a raw
            # substring. Real package folders are named 'GoogleChrome_120.0.6099' or
            # 'Google_Chrome-124', never 'google chrome', so the old
            # .Contains('google chrome') test could not match ANY multi-word product -
            # including the view's own "Google Chrome" placeholder, i.e. the advertised
            # example always reported MISSING with the package sitting right there.
            # Every token of the needle must appear in the item's alphanumeric-only
            # name. Comparison is literal .Contains(), NOT -match: an operator product
            # string is DATA and must never be evaluated as a regex.
            # NOTE: plain assignment, NOT '@(Get-PatchlibNameTokens ...)'. These
            # helpers return ',@(...)' so an EMPTY result survives the pipeline;
            # wrapping that in @() again yields a 1-element array holding the array,
            # which would compare a stringified array (and match '' -> everything).
            $tokens = Get-PatchlibNameTokens $val
            if ($tokens.Count -gt 0) {
                foreach ($it in $allItems) {
                    if ($hits.Contains($it.Name)) { continue }
                    $norm = [string]$it.NameNorm
                    if (-not $norm) { continue }
                    $allTok = $true
                    foreach ($t in $tokens) { if (-not $norm.Contains($t)) { $allTok = $false; break } }
                    if ($allTok) { [void]$hits.Add($it.Name) }
                }
            }
        }
        # MISSING is only honest when EVERY root was actually scanned. With a skipped
        # root a no-hit item is UNKNOWN - "not present in what we could read" - which
        # the view renders amber instead of the red certainty of a complete scan
        # (audit 2026-07-24). A HIT stays ON HAND regardless: finding it is proof.
        $status = 'MISSING'
        if ($hits.Count -gt 0) { $status = 'ON HAND'; $onHand++ }
        elseif ($skippedRoots.Count -gt 0) { $status = 'UNKNOWN'; $unknown++ }
        $matchTxt = ''
        if ($hits.Count -gt 0) { $matchTxt = ((@($hits) | Select-Object -First 6) -join '; '); if ($hits.Count -gt 6) { $matchTxt += " (+$($hits.Count - 6) more)" } }
        elseif ($status -eq 'UNKNOWN') { $matchTxt = "NOT SCANNED: $($okRoots.Count) root(s) searched, $($skippedRoots.Count) root(s) unreadable - absence is unproven" }
        $row = @{ _rk=("$idx|$kind|$val"); Needed=$val; Kind=$kind; Status=$status; Matches=$matchTxt }
        [void]$rows.Add($row); & $send (@{ type='row' } + $row)
    }

    # UNKNOWN is its own bucket: rolling it into MISSING would overstate what we
    # actually proved, and rolling it into coverage would understate the risk. It is
    # excluded from both (audit 2026-07-24).
    $missing = $needed.Count - $onHand - $unknown
    $coverage = if ($needed.Count -gt 0) { [math]::Round(($onHand / $needed.Count) * 100, 1) } else { 0 }
    if ($unknown -gt 0) {
        & $send @{ type='log'; level='warn'; text="$unknown of $($needed.Count) needed item(s) are UNKNOWN - $($skippedRoots.Count) content root(s) were never scanned ($skipNote), so this run CANNOT say whether they are staged. Do NOT read UNKNOWN as on hand, and do not read it as missing either: re-run with every root reachable before going to a closed network." }
    }
    if ($missing -gt 0) {
        & $send @{ type='log'; level='warn'; text="$missing of $($needed.Count) needed item(s) are MISSING from staged content - stage these before an air-gapped push." }
    } elseif ($unknown -eq 0) {
        & $send @{ type='log'; level='ok'; text="All $($needed.Count) needed item(s) are ON HAND - ready to push offline." }
    }
    $unkTxt = ''
    if ($unknown -gt 0) { $unkTxt = ", $unknown UNKNOWN ($($skippedRoots.Count) root(s) not scanned)" }
    & $send @{ type='status'; text="Done. $onHand on hand, $missing missing$unkTxt of $($needed.Count) ($coverage% coverage)." }
    return @{ rows=@($rows); summary=@{
        needed=$needed.Count; onHand=$onHand; missing=$missing; unknown=$unknown; coverage=$coverage; inventory=$inv.Count
        rootsScanned=$okRoots.Count; rootsSkipped=$skippedRoots.Count
    } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
