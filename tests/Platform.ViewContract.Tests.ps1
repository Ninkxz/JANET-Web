# =============================================================================
#  Platform.ViewContract.Tests.ps1 - Pester 3.4  (audit 2026-07-25)
#
#  Generalises Wpt.FanOutInjection.Tests.ps1:251-258 (which checked ONE tool)
#  to all 21 views, and pins docs\VIEW-CONTRACT.md against the actual component
#  APIs so the prose contract cannot rot unnoticed again. It had: five documented
#  members - ctx.util.clickable, ResultsGrid.setSort, RunBar.secondary/.setLabel/
#  .attach - existed nowhere in web\js, plus a handle.jobId that lives on the
#  run-state instead and an audit(ev) handler that is dispatched nowhere.
#
#  EVERY assertion here runs against COMMENT-STRIPPED source. The capability
#  audit found tests passing on strings that appear only inside comments
#  (Server.ReportPreviewSandbox.Tests.ps1:75-77 asserts "Never add
#  allow-same-origin", which is a comment). A contract test that a comment can
#  satisfy is documentation, not a test.
#
#  Run:  Invoke-Pester -Path .\tests\Platform.ViewContract.Tests.ps1
# =============================================================================
. (Join-Path $PSScriptRoot '_Janet.TestKit.ps1')

$script:ToolIds = Get-JanetToolIds
$script:Root    = Get-JanetRepoRoot

# view source, comments stripped, cached once
$script:ViewSrc = @{}
foreach ($id in $script:ToolIds) {
    $p = Get-JanetViewPath $id
    if (Test-Path $p) { $script:ViewSrc[$id] = Get-JanetJsWithoutComments $p }
}

# manifest action ids + the module's stripped source (for undeclared internal actions)
$script:ActionIds = @{}
$script:ModuleSrc = @{}
foreach ($id in $script:ToolIds) {
    try {
        $man = Get-JanetToolManifestFor $id
        $script:ActionIds[$id] = @($man.actions | ForEach-Object { [string]$_.id })
    } catch { $script:ActionIds[$id] = @() }
    $mp = Get-JanetModulePath $id
    if (Test-Path $mp) { $script:ModuleSrc[$id] = Get-JanetStrippedSource $mp }
}

Describe 'View contract - every registry tool has a view that registers itself' {

    It 'every registry id has a view file' {
        $missing = @($script:ToolIds | Where-Object { -not (Test-Path (Get-JanetViewPath $_)) })
        ($missing -join ',') | Should Be ''
    }
    It 'every view registers under its own registry id' {
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $src = $script:ViewSrc[$id]; if (-not $src) { continue }
            if ($src -notmatch ("JanetViews\.register\(\s*'" + [regex]::Escape($id) + "'")) { $bad += $id }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'no view registers under an id that is not in the registry' {
        $bad = @()
        foreach ($f in Get-ChildItem (Join-Path $script:Root 'web\js\views') -Filter '*.view.js') {
            $src = Get-JanetJsWithoutComments $f.FullName
            foreach ($m in [regex]::Matches($src, "JanetViews\.register\(\s*'([a-z0-9\-]+)'")) {
                $rid = $m.Groups[1].Value
                if ($script:ToolIds -notcontains $rid) { $bad += ($f.Name + '->' + $rid) }
            }
        }
        ($bad -join ',') | Should Be ''
    }
}

Describe 'View contract - views go through ctx, never straight to the network' {

    It 'no view calls fetch() or XMLHttpRequest directly' {
        # Contract rule: all I/O goes through ctx.run / ctx.api / ctx.uploadFile,
        # which carry the auth token, the destructive flag and cancel-on-egress.
        # Asserted on comment-stripped source so a comment saying "never fetch()"
        # cannot fail it, and a real call cannot hide behind one.
        $bad = @()
        foreach ($id in $script:ToolIds) {
            $src = $script:ViewSrc[$id]; if (-not $src) { continue }
            if ($src -match '\bfetch\s*\(' -or $src -match '\bXMLHttpRequest\b') { $bad += $id }
        }
        ($bad -join ',') | Should Be ''
    }
}

Describe 'View contract - every ctx.run call site names an action the module handles' {

    # This catches a dead call site: a button that posts an action id the engine
    # will never recognise. NOTE the contract is "the MODULE handles it", not
    # "the manifest declares it" - acas deliberately serves four UI-driven
    # sub-actions (findings-for-host, patch-selected, group-findings,
    # list-profiles) from Invoke-JanetToolAction without exposing them as
    # buttons. A manifest-only rule would report four false failures.

    $script:DynamicSites = @()
    $script:DeadSites    = @()
    $script:LiteralCount = 0
    foreach ($id in $script:ToolIds) {
        $src = $script:ViewSrc[$id]; if (-not $src) { continue }
        # literal single-quoted id followed by , or )
        foreach ($m in [regex]::Matches($src, "ctx\.run\(\s*'([a-z0-9\-]+)'\s*[,)]")) {
            $called = $m.Groups[1].Value
            $script:LiteralCount++
            $declared = @($script:ActionIds[$id]) -contains $called
            $served   = $script:ModuleSrc[$id] -and ($script:ModuleSrc[$id] -match ("'" + [regex]::Escape($called) + "'"))
            if (-not $declared -and -not $served) { $script:DeadSites += ($id + "->" + $called) }
        }
        # a concatenated / variable id cannot be resolved statically - COUNT it,
        # never silently skip it (the audit's own "no silent caps" rule)
        foreach ($m in [regex]::Matches($src, "ctx\.run\(\s*'([a-z0-9\-]+)'\s*\+")) {
            $script:DynamicSites += ($id + "->'" + $m.Groups[1].Value + "'+<var>")
        }
    }

    It 'checked a meaningful number of literal ctx.run call sites' {
        $script:LiteralCount -gt 50 | Should Be $true
    }
    It 'no ctx.run call site names an action the module cannot serve' {
        ($script:DeadSites -join ',') | Should Be ''
    }
    It 'reports the dynamically-built action ids it could not statically verify' {
        # Not a failure - a record. Silent truncation reads as "covered everything"
        # when it did not. Today: dhcp builds bulk-add/bulk-remove as 'bulk-'+mode.
        @($script:DynamicSites).Count -le 4 | Should Be $true
    }
}

Describe 'View contract - docs\VIEW-CONTRACT.md matches the real component APIs' {

    # Strip the doc's own HTML comments before asserting. Written without this,
    # the "does not promise clickable()" test FAILED - satisfied by the audit note
    # that says clickable() does not exist. Exactly the pathology this file exists
    # to stop, reproduced inside the file itself. Assert on prose, not annotations.
    $script:Doc = [regex]::Replace((Get-Content (Join-Path $script:Root 'docs\VIEW-CONTRACT.md') -Raw), '<!--.*?-->', ' ', 'Singleline')
    $script:RunBarSrc = Get-JanetJsWithoutComments (Join-Path $script:Root 'web\js\components\runbar.js')
    $script:GridSrc   = Get-JanetJsWithoutComments (Join-Path $script:Root 'web\js\components\resultsgrid.js')
    $script:ShellSrc  = Get-JanetJsWithoutComments (Join-Path $script:Root 'web\js\shell.js')

    It 'the doc does not promise ctx.util.clickable (it does not exist)' {
        ($script:Doc -match '`clickable\(') | Should Be $false
    }
    It 'the doc does not promise ResultsGrid.setSort (it does not exist)' {
        ($script:GridSrc -match 'setSort') | Should Be $false
        ($script:Doc -match 'setSort\(key,dir\) \}') | Should Be $false
    }
    It 'the doc does not promise RunBar.setLabel / .attach (runbar returns neither)' {
        ($script:RunBarSrc -match 'setLabel') | Should Be $false
        ($script:Doc -match '`\{ el, cta, secondary,') | Should Be $false
    }
    It 'the doc does not promise an audit(ev) subscribe handler (nothing dispatches one)' {
        ($script:ShellSrc -match "dispatch\(key, 'audit'") | Should Be $false
        ($script:Doc -match '`audit\(ev\)`, `error') | Should Be $false
    }
    It 'the handlers the doc DOES promise are all really dispatched or replayed' {
        $bad = @()
        foreach ($h in @('status','progress','row','log','error','final')) {
            if ($script:ShellSrc -notmatch ("dispatch\(key, '" + $h + "'")) { $bad += $h }
        }
        foreach ($h in @('reset','active')) {
            if ($script:ShellSrc -notmatch ("h\." + $h)) { $bad += $h }
        }
        ($bad -join ',') | Should Be ''
    }
    It 'RunBar really returns the four members the doc now claims' {
        foreach ($mem in @('el:','cta:','setActive','setStatus')) {
            ($script:RunBarSrc -match [regex]::Escape($mem)) | Should Be $true
        }
    }
}
