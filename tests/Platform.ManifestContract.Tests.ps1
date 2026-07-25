# =============================================================================
#  Platform.ManifestContract.Tests.ps1 - Pester 3.4  (audit 2026-07-25)
#
#  The platform contract, asserted over ALL tools at once instead of hand-picked
#  per tool. Before this file:
#    - server\tool-registry.json had ZERO test references, despite driving the
#      entire SPA tool list;
#    - no test asserted action-id uniqueness anywhere;
#    - no test asserted that every manifest input carries a type;
#    - the only loop over all actions was BiosFirmware.Tests.ps1:209, and that
#      is a "this one tool is read-only" check, not a contract check.
#
#  A new tool that ships a malformed manifest now turns THIS red, instead of
#  failing at runtime in the browser.
#
#  Run:  Invoke-Pester -Path .\tests\Platform.ManifestContract.Tests.ps1
# =============================================================================
. (Join-Path $PSScriptRoot '_Janet.TestKit.ps1')

$script:RegTools = Get-JanetRegistryTools
$script:ToolIds  = @($script:RegTools | ForEach-Object { [string]$_.id })

# Load every manifest ONCE at discovery; the It blocks assert against the cache.
$script:Manifests = @{}
$script:LoadErrors = @{}
foreach ($id in $script:ToolIds) {
    try { $script:Manifests[$id] = Get-JanetToolManifestFor $id }
    catch { $script:LoadErrors[$id] = $_.Exception.Message }
}

# The closed set of input types the generic server-side control factory renders.
# A type outside this set silently renders nothing in a generic view.
$script:AllowedInputTypes = @(
    'bool','file','hostlist','hostpick','int','msi-checklist',
    'password','savefile','select','string','text','textarea'
)

Describe 'Platform contract - the registry resolves' {

    It 'server\tool-registry.json parses and is non-empty' {
        @($script:RegTools).Count -gt 0 | Should Be $true
    }
    It 'every registry id is unique' {
        $dupe = @($script:ToolIds | Group-Object | Where-Object { $_.Count -gt 1 })
        ($dupe | ForEach-Object { $_.Name }) -join ',' | Should Be ''
    }
    It 'every registry id has a module file on disk' {
        $missing = @($script:ToolIds | Where-Object { -not (Test-Path (Get-JanetModulePath $_)) })
        ($missing -join ',') | Should Be ''
    }
    It 'every registry tool loads and exposes Get-JanetToolManifest' {
        ($script:LoadErrors.Keys -join ',') | Should Be ''
    }
    It 'every registry tool declares a category and a summary' {
        $bad = @($script:RegTools | Where-Object { -not $_.category -or -not $_.summary } | ForEach-Object { $_.id })
        ($bad -join ',') | Should Be ''
    }
}

Describe 'Platform contract - manifest identity and version' {

    It 'manifest id matches the registry id for every tool' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]
            if ($m -and [string]$m.id -ne $id) { $bad += ("$id->" + [string]$m.id) }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'every manifest declares a version' {
        $bad = @($script:ToolIds | Where-Object { $script:Manifests[$_] -and -not $script:Manifests[$_].version })
        ($bad -join ',') | Should Be ''
    }
    It 'every version is a parseable dotted version (a pre-release suffix is allowed)' {
        # Replaces 22 scattered EXACT version pins that broke on every bump and
        # proved nothing about behaviour. Exact pins now live in ONE test per tool.
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            $v = ([string]$m.version -split '-')[0]
            try { $null = [version]$v } catch { $bad += ($id + '=' + [string]$m.version) }
        }
        ($bad -join ',') | Should Be ''
    }
}

Describe 'Platform contract - actions' {

    It 'every tool declares at least one action' {
        $bad = @($script:ToolIds | Where-Object { $script:Manifests[$_] -and @($script:Manifests[$_].actions).Count -eq 0 })
        ($bad -join ',') | Should Be ''
    }
    It 'action ids are unique WITHIN each tool' {
        # Two actions sharing an id means one is unreachable - the dispatcher
        # takes the first match. Nothing asserted this before.
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            $ids = @($m.actions | ForEach-Object { [string]$_.id })
            $d = @($ids | Group-Object | Where-Object { $_.Count -gt 1 })
            if ($d) { $bad += ($id + ':' + (($d | ForEach-Object { $_.Name }) -join '/')) }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'every action declares an id and a label' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                if (-not $a.id)    { $bad += ($id + ':<no id>') }
                elseif (-not $a.label) { $bad += ($id + '/' + [string]$a.id + ':<no label>') }
            }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'every action declares a destructive key (present, not merely truthy)' {
        # An action with NO destructive key renders as read-only in the shell.
        # That is how a host-touching action can quietly lose its arming gate.
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                $has = $false
                if ($a -is [hashtable]) { $has = $a.ContainsKey('destructive') }
                else { $has = @($a.PSObject.Properties.Name) -contains 'destructive' }
                if (-not $has) { $bad += ($id + '/' + [string]$a.id) }
            }
        }
        ($bad -join ',') | Should Be ''
    }
}

Describe 'Platform contract - action inputs' {

    It 'every input declares a name' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                foreach ($i in @($a.inputs)) {
                    if ($null -eq $i) { continue }
                    if (-not $i.name) { $bad += ($id + '/' + [string]$a.id) }
                }
            }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'every input declares a type' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                foreach ($i in @($a.inputs)) {
                    if ($null -eq $i) { continue }
                    if (-not $i.type) { $bad += ($id + '/' + [string]$a.id + '/' + [string]$i.name) }
                }
            }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'every input type is in the closed set the control factory can render' {
        # A type outside the set renders NOTHING - a required input the operator
        # cannot fill, discovered only by clicking the action in a browser.
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                foreach ($i in @($a.inputs)) {
                    if ($null -eq $i -or -not $i.type) { continue }
                    if ($script:AllowedInputTypes -notcontains [string]$i.type) {
                        $bad += ($id + '/' + [string]$a.id + '/' + [string]$i.name + '=' + [string]$i.type)
                    }
                }
            }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'input names are unique within an action' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $m = $script:Manifests[$id]; if (-not $m) { continue }
            foreach ($a in @($m.actions)) {
                $names = @(@($a.inputs) | Where-Object { $_ -and $_.name } | ForEach-Object { [string]$_.name })
                $d = @($names | Group-Object | Where-Object { $_.Count -gt 1 })
                if ($d) { $bad += ($id + '/' + [string]$a.id + ':' + (($d | ForEach-Object { $_.Name }) -join '/')) }
            }
        }
        ($bad -join ',') | Should Be ''
    }
}

Describe 'Platform contract - the suite is bigger than any one tool test' {

    It 'the registry carries every module that defines a manifest (no orphan modules)' {
        # A module with a manifest but no registry entry is invisible in the SPA.
        # javafix / specfix / troubleshoot are SHARED ENGINE LIBRARIES and define
        # no Get-JanetToolManifest - they are correctly absent from the registry.
        $orphans = @()
        foreach ($f in Get-ChildItem (Join-Path (Get-JanetRepoRoot) 'modules') -Filter 'JanetWeb.*.psm1') {
            $id = $f.BaseName -replace '^JanetWeb\.', ''
            if ($script:ToolIds -contains $id) { continue }
            $src = Get-JanetStrippedSource $f.FullName
            if ($src -match 'function\s+Get-JanetToolManifest') { $orphans += $id }
        }
        ($orphans -join ',') | Should Be ''
    }
}
