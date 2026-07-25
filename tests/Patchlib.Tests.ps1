# =============================================================================
#  Patchlib.Tests.ps1 - Pester 3.4 for JanetWeb.patchlib (the offline patch-content
#  library) and the 2026-07-24 audit fixes. The tool answers "can I push this on a
#  closed network today?", so BOTH of the covered findings are wrong-answer bugs:
#
#   F1 (P2): product-name matching was a raw substring test, so a MULTI-WORD name
#            could never hit a real package folder ('Google Chrome' vs
#            'GoogleChrome_120.0.6099.130_x64') - including the view's own
#            "Google Chrome" placeholder, i.e. the advertised example reported
#            MISSING with the package sitting right there. Now normalised tokens.
#   F2 (P2): crossref rendered MISSING for content it never scanned - no
#            skipped-root signal and none of the zero-root guarding the inventory
#            path has. "I did not look there" must never render as "it is not
#            there". Now a distinct UNKNOWN verdict + rootsScanned/rootsSkipped.
#   F3 (P3): the -PackagesRoot leg de-duped on the RAW string, so an FQDN or a
#            relative alias double-counted the whole inventory. Now a canonical key.
#   F4 (P4): every folder was walked TWICE per inventory (the size walk duplicated
#            the classify/KB walk). Size now rides the single walk.
#   F5 (P3, audit 2026-07-25 (fable re-audit follow-up)): the operator's extraPath
#            root was the ONE leg with no canonical-key de-dupe, so pasting the share
#            (or the repo Packages folder) as "extra folder" double-counted the whole
#            inventory. Now keyed like the -PackagesRoot leg - and a deduped duplicate
#            is NOT booked as a skipped root (that would fake an unreadable root).
#
#  Read-only tool: nothing here touches a host or a real share. Get-PatchlibRoots
#  is shadowed in MODULE scope so the roots are fake temp directories, and the
#  "unreachable" root is never enumerated (Ok=$false short-circuits the scan).
#
#  Run:  Invoke-Pester -Path .\tests\Patchlib.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.patchlib.psm1') -Force -PassThru

# ---- temp content roots ------------------------------------------------------
$script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("patchlibtest_" + [guid]::NewGuid().ToString('N'))
$script:R1  = Join-Path $script:Tmp 'root1'      # staged content
$script:R2  = Join-Path $script:Tmp 'root2'      # a second, empty root
[void][System.IO.Directory]::CreateDirectory($script:R1)
[void][System.IO.Directory]::CreateDirectory($script:R2)

# A REALISTICALLY named PSADT package folder - the separator style ('_', '.') is
# exactly what the old raw-substring test could not see past.
$script:Pkg = Join-Path $script:R1 'GoogleChrome_120.0.6099.130_x64'
[void][System.IO.Directory]::CreateDirectory((Join-Path $script:Pkg 'Files'))
# Exact byte counts so the folded size walk (F4) can be asserted exactly.
[System.IO.File]::WriteAllBytes((Join-Path $script:Pkg 'Deploy-Application.ps1'), (New-Object byte[] 100))
[System.IO.File]::WriteAllBytes((Join-Path $script:Pkg 'Files\googlechromestandaloneenterprise64.msi'), (New-Object byte[] 250))
[System.IO.File]::WriteAllBytes((Join-Path $script:R1 'windows10.0-kb5034441-x64.msu'), (New-Object byte[] 10))

$script:RootsAllOk = @(
    @{ Path = $script:R1; Label = 'Local'; Ok = $true;  Note = 'test root 1' },
    @{ Path = $script:R2; Label = 'Extra'; Ok = $true;  Note = 'test root 2' }
)
$script:RootsPartial = @(
    @{ Path = $script:R1;        Label = 'Local'; Ok = $true;  Note = 'test root 1' },
    @{ Path = '\\no-such-host\share'; Label = 'Share'; Ok = $false; Note = 'host unreachable on 445' }
)
$script:RootsNoneOk = @(
    @{ Path = $script:R1;        Label = 'Local'; Ok = $false; Note = 'repo .\Packages not present' },
    @{ Path = '\\no-such-host\share'; Label = 'Share'; Ok = $false; Note = 'host unreachable on 445' }
)

# Run crossref against a FAKE root set. Get-PatchlibRoots is shadowed in module
# scope (adto idiom) so no real share is probed and no 445 connect is attempted.
#
# The shim is SAVED AND RESTORED, not Remove-Item'd (audit 2026-07-25 (fable re-audit
# follow-up)): 'Remove-Item function:script:<name>' silently does nothing to a function
# defined at a MODULE's script scope, so the old form leaked the shim for the rest of
# the session - every later test in this file saw a Get-PatchlibRoots that returned
# $null, which is exactly what made the new extraPath de-dupe tests below report zero
# roots against a module that was working fine.
function Invoke-PatchlibCrossref {
    param($Roots, [string]$Needed)
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $script:Mod {
        param($rts, $nd, $em)
        $script:__origRoots = ${function:Get-PatchlibRoots}
        $script:__testRoots = @($rts)
        function script:Get-PatchlibRoots { param([string]$ExtraPath) $script:__testRoots }
        try { Invoke-JanetToolAction -ActionId 'crossref' -Params @{ needed = $nd } -Credential $null -Emit $em }
        finally {
            ${function:script:Get-PatchlibRoots} = $script:__origRoots
            Remove-Variable -Name __testRoots, __origRoots -Scope Script -ErrorAction SilentlyContinue
        }
    } $Roots $Needed $emit
    return @{ Result = $res; Events = @($evs) }
}

# First row for a given Needed value (rows are hashtables from the engine).
function Get-XrefRow {
    param($Run, [string]$Needed)
    foreach ($r in @($Run.Result.rows)) { if ([string]$r.Needed -eq $Needed) { return $r } }
    return $null
}

Describe 'Product-name matching uses normalised tokens (audit 2026-07-24 F1)' {

    It 'matches the multi-word "Google Chrome" against a real package folder name' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'Google Chrome'
        $row = Get-XrefRow $run 'Google Chrome'
        $row.Kind   | Should Be 'Product'
        $row.Status | Should Be 'ON HAND'
        $row.Matches | Should Match 'GoogleChrome_120'
    }

    It 'matches a single-token product name too (no regression)' {
        $row = Get-XrefRow (Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'Chrome') 'Chrome'
        $row.Status | Should Be 'ON HAND'
    }

    It 'matches regardless of the separators the operator typed' {
        $row = Get-XrefRow (Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'google-chrome') 'google-chrome'
        $row.Status | Should Be 'ON HAND'
    }

    It 'still reports MISSING for a product that really is not staged' {
        $row = Get-XrefRow (Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'Mozilla Firefox') 'Mozilla Firefox'
        $row.Status | Should Be 'MISSING'
    }

    It 'requires EVERY token - a partly-matching two-word name is not a hit' {
        $row = Get-XrefRow (Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'Mozilla Chrome') 'Mozilla Chrome'
        $row.Status | Should Be 'MISSING'
    }

    It 'treats a regex metacharacter product name as a LITERAL, not a pattern' {
        # '.*' as a regex would match every staged item. As a literal it has no
        # alphanumeric tokens at all, so it matches nothing.
        $row = Get-XrefRow (Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed '.*') '.*'
        $row.Status | Should Be 'MISSING'
    }

    It 'normalises a name down to lower-case alphanumerics only' {
        $n = & $script:Mod { param($t) Get-PatchlibNormalizedName $t } 'Google_Chrome-124.0 (x64)'
        $n | Should Be 'googlechrome1240x64'
    }

    It 'splits a product name into normalised tokens' {
        # Plain assignment: these helpers return ',@(...)' so an empty result survives
        # the pipeline - re-wrapping in @() would nest the array one level too deep.
        $t = & $script:Mod { param($x) Get-PatchlibNameTokens $x } 'Google Chrome 120'
        $t.Count | Should Be 3
        ($t -join ',') | Should Be 'google,chrome,120'
    }

    It 'yields ZERO tokens for a name with no alphanumerics (matches nothing)' {
        $t = & $script:Mod { param($x) Get-PatchlibNameTokens $x } '.*'
        $t.Count | Should Be 0
    }
}

Describe 'A skipped root yields UNKNOWN, never MISSING (audit 2026-07-24 F2)' {

    It 'reports UNKNOWN (not MISSING) when one content root could not be scanned' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsPartial -Needed 'KB9999999'
        $row = Get-XrefRow $run 'KB9999999'
        $row.Status | Should Be 'UNKNOWN'
        $row.Status | Should Not Be 'MISSING'
        $row.Matches | Should Match 'NOT SCANNED'
    }

    It 'reports UNKNOWN for EVERY item when no root at all was scanned' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsNoneOk -Needed "KB9999999`nGoogle Chrome"
        foreach ($r in @($run.Result.rows)) { $r.Status | Should Be 'UNKNOWN' }
        $run.Result.summary.rootsScanned | Should Be 0
        $run.Result.summary.missing      | Should Be 0
        $run.Result.summary.unknown      | Should Be 2
    }

    It 'warns loudly when nothing was scanned' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsNoneOk -Needed 'KB9999999'
        $warned = $false
        foreach ($e in $run.Events) { if ($e.type -eq 'log' -and "$($e.text)" -match 'NOTHING was scanned') { $warned = $true } }
        $warned | Should Be $true
    }

    It 'still reports MISSING when EVERY root was scanned (absence is proven)' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsAllOk -Needed 'KB9999999'
        $row = Get-XrefRow $run 'KB9999999'
        $row.Status | Should Be 'MISSING'
        $run.Result.summary.rootsSkipped | Should Be 0
        $run.Result.summary.unknown      | Should Be 0
    }

    It 'keeps ON HAND with a skipped root - finding it is proof either way' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsPartial -Needed 'Google Chrome'
        (Get-XrefRow $run 'Google Chrome').Status | Should Be 'ON HAND'
    }

    It 'excludes UNKNOWN from the MISSING tally and from coverage' {
        $run = Invoke-PatchlibCrossref -Roots $script:RootsPartial -Needed "Google Chrome`nKB9999999"
        $s = $run.Result.summary
        $s.needed   | Should Be 2
        $s.onHand   | Should Be 1
        $s.unknown  | Should Be 1
        $s.missing  | Should Be 0
        $s.coverage | Should Be 50
    }
}

Describe 'Content-root identity is canonical, not raw string (audit 2026-07-24 F3)' {

    It 'gives an FQDN and a short-name UNC of the same folder ONE key' {
        $a = & $script:Mod { param($p) Get-PatchlibPathKey $p } '\\dm-tn-01.area52.afnoapps.usaf.mil\sh$\JANET\Packages'
        $b = & $script:Mod { param($p) Get-PatchlibPathKey $p } '\\DM-TN-01\sh$\JANET\Packages\'
        $a | Should Be $b
    }

    It 'collapses a relative alias of the same folder to one key' {
        $a = & $script:Mod { param($p) Get-PatchlibPathKey $p } 'C:\Staged\Packages'
        $b = & $script:Mod { param($p) Get-PatchlibPathKey $p } 'C:\Staged\Other\..\Packages\'
        $a | Should Be $b
    }

    It 'keeps genuinely different folders distinct' {
        $a = & $script:Mod { param($p) Get-PatchlibPathKey $p } 'C:\Staged\Packages'
        $b = & $script:Mod { param($p) Get-PatchlibPathKey $p } 'C:\Staged\Packages2'
        $a | Should Not Be $b
    }

    It 'returns empty for a blank path (never throws)' {
        (& $script:Mod { Get-PatchlibPathKey '   ' }) | Should Be ''
    }
}

Describe 'Folder size rides the single classify/KB walk (audit 2026-07-24 F4)' {

    It 'returns the exact folder byte total from the one walk' {
        $info = & $script:Mod { param($p) Get-PatchlibItemInfo -Item (Get-Item -LiteralPath $p) -WithSize } $script:Pkg
        $info.Type      | Should Be 'PSADT'
        $info.SizeBytes | Should Be 350
    }

    It 'leaves SizeBytes null when the size was not asked for (crossref -SkipSizes)' {
        $info = & $script:Mod { param($p) Get-PatchlibItemInfo -Item (Get-Item -LiteralPath $p) } $script:Pkg
        $info.Type | Should Be 'PSADT'
        ($null -eq $info.SizeBytes) | Should Be $true
    }

    It 'still harvests KB ids from the folder walk' {
        $kb = & $script:Mod { param($p) (Get-PatchlibItemInfo -Item (Get-Item -LiteralPath $p)).KbList } (Join-Path $script:R1 'windows10.0-kb5034441-x64.msu')
        (@($kb) -join ',') | Should Be 'KB5034441'
    }
}

Describe 'The operator extraPath root de-dupes like every other leg (audit 2026-07-25 (fable re-audit follow-up))' {

    # Behavioural: run the REAL inventory action with the roots pinned to temp folders.
    # Get-PatchlibLocalPackages is shadowed in module scope so 'Local' is $script:R1, and
    # Test-PatchlibShareReachable is shadowed to $false so the work share (and any UNC
    # extra path) is skipped WITHOUT a single 445 connect. The -PackagesRoot env legs are
    # cleared for the duration so a developer box that sets one cannot add a third root.
    function Invoke-PatchlibInventory {
        param([string]$LocalRoot, [string]$ExtraPath)
        $savedA = $env:JANETWEB_PACKAGES_ROOT; $savedB = $env:JANET2_PACKAGES_ROOT
        $env:JANETWEB_PACKAGES_ROOT = ''; $env:JANET2_PACKAGES_ROOT = ''
        try {
            return & $script:Mod {
                param($lr, $ep)
                $script:__origLocal = ${function:Get-PatchlibLocalPackages}
                $script:__origReach = ${function:Test-PatchlibShareReachable}
                $script:__testLocal = $lr
                function script:Get-PatchlibLocalPackages { $script:__testLocal }
                function script:Test-PatchlibShareReachable { param($ComputerName, $Port, $TimeoutMs) $false }
                try { Invoke-JanetToolAction -ActionId 'inventory' -Params @{ extraPath = $ep } -Credential $null -Emit { param($e) } }
                finally {
                    # Save/restore, never Remove-Item - see Invoke-PatchlibCrossref above.
                    ${function:script:Get-PatchlibLocalPackages} = $script:__origLocal
                    ${function:script:Test-PatchlibShareReachable} = $script:__origReach
                    Remove-Variable -Name __testLocal, __origLocal, __origReach -Scope Script -ErrorAction SilentlyContinue
                }
            } $LocalRoot $ExtraPath
        } finally { $env:JANETWEB_PACKAGES_ROOT = $savedA; $env:JANET2_PACKAGES_ROOT = $savedB }
    }

    # A THIRD root with one file, to prove the de-dupe never suppresses a real folder.
    $script:R3 = Join-Path $script:Tmp 'root3'
    [void][System.IO.Directory]::CreateDirectory($script:R3)
    [System.IO.File]::WriteAllBytes((Join-Path $script:R3 'windows10.0-kb5099999-x64.msu'), (New-Object byte[] 5))

    $script:BaseInv = Invoke-PatchlibInventory -LocalRoot $script:R1

    It 'the baseline scans exactly one root' {
        [int]$script:BaseInv.summary.roots | Should Be 1
        [int]$script:BaseInv.summary.total | Should BeGreaterThan 0
    }

    It 'an extraPath EQUAL to an already-scanned root does not double the inventory' {
        $dup = Invoke-PatchlibInventory -LocalRoot $script:R1 -ExtraPath $script:R1
        [int]$dup.summary.roots | Should Be 1
        [int]$dup.summary.total | Should Be ([int]$script:BaseInv.summary.total)
        @($dup.rows).Count      | Should Be (@($script:BaseInv.rows).Count)
    }

    It 'an alias of an already-scanned root (trailing slash / dot segments) is deduped too' {
        $alias = (Join-Path $script:R1 '..') + '\.\root1\'
        $dup = Invoke-PatchlibInventory -LocalRoot $script:R1 -ExtraPath $alias
        [int]$dup.summary.roots | Should Be 1
        [int]$dup.summary.total | Should Be ([int]$script:BaseInv.summary.total)
    }

    It 'a genuinely DIFFERENT extra folder is still scanned (no over-suppression)' {
        $more = Invoke-PatchlibInventory -LocalRoot $script:R1 -ExtraPath $script:R3
        [int]$more.summary.roots | Should Be 2
        [int]$more.summary.total | Should Be ([int]$script:BaseInv.summary.total + 1)
    }

    It 'a deduped duplicate is NOT recorded as a skipped root (it was scanned)' {
        # A fabricated Ok=$false root would push crossref's honest MISSING to UNKNOWN.
        $roots = & $script:Mod {
            param($lr, $ep)
            $script:__origLocal = ${function:Get-PatchlibLocalPackages}
            $script:__origReach = ${function:Test-PatchlibShareReachable}
            $script:__testLocal = $lr
            function script:Get-PatchlibLocalPackages { $script:__testLocal }
            function script:Test-PatchlibShareReachable { param($ComputerName, $Port, $TimeoutMs) $false }
            try { Get-PatchlibRoots -ExtraPath $ep }
            finally {
                ${function:script:Get-PatchlibLocalPackages} = $script:__origLocal
                ${function:script:Test-PatchlibShareReachable} = $script:__origReach
                Remove-Variable -Name __testLocal, __origLocal, __origReach -Scope Script -ErrorAction SilentlyContinue
            }
        } $script:R1 $script:R1
        @($roots | Where-Object { $_.Label -eq 'Extra' }).Count | Should Be 0
    }
}

Describe 'Manifest still advertises the contract' {
    It 'reports the bumped version' {
        (Get-JanetToolManifest).version | Should Be '1.1.1'
    }
}

# ---- cleanup -----------------------------------------------------------------
Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
