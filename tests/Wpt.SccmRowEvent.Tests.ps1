# =============================================================================
#  Wpt.SccmRowEvent.Tests.ps1 - Pester 3.4 for the wpt SCCM deployment row-emit
#  crash (loop89 P1). sccm-available and sccm-install-available build a row that
#  carries an app 'Type' key (App/Update) and emitted it with `@{ type='row' } +
#  $row`. On PS 5.1 a @{} literal is a case-INSENSITIVE Hashtable, so adding the
#  event key 'type' to a row already holding 'Type' is a duplicate-key
#  ArgumentException - every Available/Install-Available query crashed at the
#  first result row, and on the install path the crash landed AFTER the
#  destructive CCM InstallUpdates/Install trigger already ran, so the per-item
#  VulnPatched audits were lost. Same class as the upr P0 (loop85). Fixed with
#  New-WptRowEvent (a case-SENSITIVE Hashtable that holds both keys; ConvertTo-Json
#  renders them as the distinct JSON keys the case-sensitive JS view expects).
#  Run:  Invoke-Pester -Path .\tests\Wpt.SccmRowEvent.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

Describe 'New-WptRowEvent - a Type-bearing row emits without the type/Type collision (loop89 P1)' {
    It 'the OLD merge really throws on 5.1 (guards the root cause)' {
        $sccmRow = @{ Host='WS01'; Type='App'; Name='7-Zip'; Result='Triggered'; Detail='Install (v22)' }
        $threw = $false
        try { $null = @{ type='row' } + $sccmRow } catch { $threw = $true }
        $threw | Should Be $true
    }
    It 'New-WptRowEvent does NOT throw and keeps BOTH the event type + the app Type (case-sensitive)' {
        $sccmRow = @{ Host='WS01'; Type='App'; Name='7-Zip'; Result='Triggered'; Detail='Install (v22)' }
        $threw = $false; $msg = $null
        try { $msg = & $script:Mod { param($r) New-WptRowEvent $r } $sccmRow } catch { $threw = $true }
        $threw               | Should Be $false
        [string]$msg['type'] | Should Be 'row'
        [string]$msg['Type'] | Should Be 'App'
        [string]$msg['Name'] | Should Be '7-Zip'
    }
    It 'the JSON serialization (the server emit path) carries both keys distinctly' {
        $msg = & $script:Mod { param($r) New-WptRowEvent $r } @{ Type='Update'; Host='WS01' }
        $j = $msg | ConvertTo-Json -Compress
        ($j -match '"type":"row"') | Should Be $true
        ($j -match '"Type":"Update"') | Should Be $true
    }
    It 'a null / empty row is handled (returns just the event type)' {
        $m1 = & $script:Mod { New-WptRowEvent $null }
        [string]$m1['type'] | Should Be 'row'
    }
    It 'New-WptRowEvent uses a case-SENSITIVE Hashtable (a plain @{} would re-introduce the collision)' {
        ($script:Src -match 'function New-WptRowEvent[\s\S]*?New-Object System\.Collections\.Hashtable') | Should Be $true
    }
}

Describe 'wpt SCCM dispatchers emit via New-WptRowEvent, not the colliding merge (loop89)' {
    It 'sccm-available + sccm-install-available emit their Type-bearing rows via New-WptRowEvent' {
        # both emit sites (the two rows that carry a Type key) now use the helper
        ([regex]::Matches($script:Src, "\`$rows\.Add\(\`$row\); & \`$send \(New-WptRowEvent \`$row\)").Count -ge 2) | Should Be $true
    }
    It "neither sccm row still uses the colliding '@{ type='row' } + `$row' on a Type-bearing row" {
        # the sccm rows are the only emitted wpt rows carrying a Type key; assert they were converted
        $availBlock = [regex]::Match($script:Src, "(?s)Type=\(& \`$g 'Type'\); Name=\(& \`$g 'Name'\); State.*?& \`$send \([^\r\n]*").Value
        ($availBlock -match 'New-WptRowEvent') | Should Be $true
    }
    It 'wpt manifest is at or past 6.8.18 (sccm emit fix; exact pin migrated to the newest bump)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'6.8.18') | Should Be $true
    }
}
