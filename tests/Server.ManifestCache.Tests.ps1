# =============================================================================
#  Server.ManifestCache.Tests.ps1 - the startup manifest cache.
#
#  WHY IT EXISTS: Import-Module was the ENTIRE cost of startup. Measured on the dev
#  box: 21 modules, 3.2 MB of PowerShell parsed on every launch purely to read 21
#  small manifests, then the modules were unloaded again.
#
#      cold:  catalog 7794 ms   startup 10691 ms
#      warm:  catalog  311 ms   startup  3486 ms      (21 cached, 0 parsed)
#
#  ~7 seconds back, a 25x faster catalog pass. Touching one module re-parses ONLY
#  that module (verified: "20 cached, 1 parsed").
#
#  WHY A CACHE IS SAFE HERE: every manifest in this suite is a STATIC literal. All 21
#  were checked for environment-dependent calls (Get-ChildItem/Test-Path/Get-Date/
#  $env:/Resolve-Path/Get-Item) and the only hit was a Get-Item inside a COMMENT. So a
#  manifest can only change when its .psm1 changes, which the write-time+length key
#  detects.
#
#  WHY NOT A CONTENT HASH: measured 2778 ms to SHA256 the 3.2 MB over this SMB share -
#  a quarter of the saving spent on the check. Stat costs 44 ms.
#
#  RESIDUAL: a file replaced by a DIFFERENT build of identical length AND identical
#  write time (a timestamp-preserving restore) serves a stale entry. Deleting
#  JanetLocal\manifest-cache.json forces a full reload.
#
#  BLAST RADIUS, which is why that residual is tolerable: the catalog feeds the tool
#  list, the manifest endpoint and action-id validation ONLY. Every ACTION imports the
#  module fresh in its own runspace, so a stale entry could misreport a version or miss
#  a brand-new action id - it can never change what actually runs.
#
#  Run: Invoke-Pester -Path .\tests\Server.ManifestCache.Tests.ps1
# =============================================================================
$script:Root       = Split-Path $PSScriptRoot -Parent
$script:ModulesDir = Join-Path $script:Root 'modules'
$script:Src        = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw

Describe 'a manifest survives the cache round-trip byte-for-byte' {

    # THE risk this cache introduces: ConvertTo-Json truncates below its -Depth and would
    # silently flatten actions -> inputs -> options, so the UI would render a tool with no
    # input controls and nothing would look broken at startup. Asserted for EVERY module,
    # not a sample - the deep ones (wpt has 46 actions) are exactly the ones that would
    # truncate first. This needs no cache file: it tests the serialisation itself.
    It 'every module manifest is identical after ConvertTo-Json -Depth 12 / ConvertFrom-Json' {
        $bad = New-Object System.Collections.ArrayList
        foreach ($f in (Get-ChildItem -LiteralPath $script:ModulesDir -Filter 'JanetWeb.*.psm1')) {
            $m = $null
            try { $m = Import-Module $f.FullName -Force -PassThru -ErrorAction Stop } catch { continue }
            if (-not $m.ExportedFunctions.ContainsKey('Get-JanetToolManifest')) {
                Remove-Module $m -Force -ErrorAction SilentlyContinue; continue
            }
            $fresh = & $m { Get-JanetToolManifest }
            Remove-Module $m -Force -ErrorAction SilentlyContinue
            $json  = ConvertTo-Json $fresh -Depth 12 -Compress
            $round = $json | ConvertFrom-Json
            if ((ConvertTo-Json $round -Depth 12 -Compress) -ne $json) {
                [void]$bad.Add("$($f.Name) : manifest changed across the JSON round-trip (depth truncation?)")
            }
        }
        ($bad -join "`n") | Should BeNullOrEmpty
    }
}

Describe 'the cache key detects a changed module' {
    It 'the key is write-time ticks + length, not a name or a bare date' {
        ($script:Src -match '\$stamp = "\{0\}:\{1\}" -f \$fi\.LastWriteTimeUtc\.Ticks, \$fi\.Length') | Should Be $true
    }
    It 'a hit requires BOTH the stamp to match AND a manifest to be present' {
        ($script:Src -match '\$hit -and \(\[string\]\$hit\.stamp -eq \$stamp\) -and \$hit\.manifest') | Should Be $true
    }
    It 'serialisation uses a depth deep enough for actions -> inputs -> options' {
        ($script:Src -match 'ConvertTo-Json -Depth 12 -Compress') | Should Be $true
    }
}

Describe 'the cache fails safe in every direction' {

    It 'an unreadable or corrupt cache falls back to a full reload, never an error' {
        ($script:Src -match '\} catch \{ \$mfCache = @\{\} \}') | Should Be $true
    }
    It 'a module that FAILED to load is never cached' {
        ($script:Src -match '\[void\]\$mfCache\.Remove\(\[string\]\$t\.id\)') | Should Be $true
    }
    It 'a cache WRITE failure warns but does not break startup' {
        ($script:Src -match 'could not be written .* next start will be a cold one') | Should Be $true
    }
    It 'the cache lives in the gitignored runtime dir, beside target-groups.json' {
        ($script:Src -match "Join-Path \(Join-Path \`$Root 'JanetLocal'\) 'manifest-cache\.json'") | Should Be $true
        # JanetLocal/* is ignored with explicit negations for the tracked seed files;
        # manifest-cache.json is not one of them, so it must not become tracked.
        $ignore = Get-Content (Join-Path $script:Root '.gitignore') -Raw
        ($ignore -match 'JanetLocal/\*')                 | Should Be $true
        ($ignore -match '!JanetLocal/manifest-cache')    | Should Be $false
    }
}

Describe 'the console still shows what happened' {
    It 'a cached module is labelled differently from a parsed one' {
        ($script:Src -match '"  cached   \{0,-14\} v\{1,-10\} \{2,6\} ms \{3,6\} KB  \{4\}"') | Should Be $true
        ($script:Src -match '"  module   \{0,-14\} v\{1,-10\} \{2,6\} ms \{3,6\} KB  \{4\}"') | Should Be $true
    }
    It 'the catalog line states how many were cached vs parsed' {
        ($script:Src -match "\(\`$cacheHits cached, \`$parsedN parsed\)") | Should Be $true
        ($script:Src -match "all parsed - cold start")                   | Should Be $true
    }
}
