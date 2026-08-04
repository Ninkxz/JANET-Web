# =============================================================================
#  Server.LoadTiming.Tests.ps1 - the startup module-load detail and timing.
#
#  WHY: JANET Web loaded its module catalog SILENTLY - the only output was a
#  Write-Warning when a module failed - so "why does startup feel slow?" had no
#  answer short of instrumenting it by hand. E.P.I.C (X:\CSTs) prints one line per
#  engine as it loads but no cost. This does both: per-module id / version / ms /
#  KB / name, then a catalog total naming the three slowest, then a whole-startup
#  figure split into catalog vs server setup.
#
#  Measured on the dev box at the time it was added: 21 modules, ~10.2 s catalog,
#  ~13.1 s total. wpt was the most expensive at ~1.9 s / 510 KB while reports cost
#  ~0.6 s at 495 KB - so the cost tracks the big profile HASHTABLES in wpt/c2c/acas,
#  not file size. That is the kind of thing this output exists to make visible.
#
#  CONSOLE ONLY, deliberately: Write-Host on the launch window, exactly like
#  E.P.I.C. No /api route, nothing stored in $state, nothing a browser can reach -
#  module inventory and file sizes are not something the web surface needs to
#  publish.
#
#  Run: Invoke-Pester -Path .\tests\Server.LoadTiming.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Src  = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw

Describe 'startup prints per-module load detail' {

    It 'each module reports id, version, elapsed ms, size and name' {
        ($script:Src -match '"  module   \{0,-14\} v\{1,-10\} \{2,6\} ms \{3,6\} KB  \{4\}"') | Should Be $true
    }
    It 'a module that fails to load reports its own elapsed time and the reason' {
        ($script:Src -match 'MODULE FAILED')  | Should Be $true
        ($script:Src -match 'MODULE MISSING') | Should Be $true
    }
    It 'the failure path still raises the original warning (nothing was swallowed for prettiness)' {
        ($script:Src -match "Write-Warning ""JANET Web: module '\`$\(\`$t\.id\)' failed to load") | Should Be $true
    }
    # Positional index moved from {2} to {3} when the manifest cache added a
    # "(N cached, M parsed)" segment ahead of it. Asserted on the label rather than the
    # index now, so a future insertion does not fail a test that is not about ordering.
    It 'the catalog line names the slowest modules, not just a total' {
        ($script:Src -match 'slowest: \{\d\}')            | Should Be $true
        ($script:Src -match 'Sort-Object Ms -Descending') | Should Be $true
    }
    It 'failures are summarised separately so they cannot hide in the total' {
        ($script:Src -match "module\(s\) FAILED to load") | Should Be $true
    }
}

Describe 'startup reports the whole-launch cost, split' {

    It 'the clock starts AFTER the token guard (a bad launch reports no number)' {
        $iThrow = $script:Src.IndexOf('Start-JanetWebServer: -Token must be a non-empty')
        $iStart = $script:Src.IndexOf('$startupSw = [System.Diagnostics.Stopwatch]::StartNew()')
        ($iThrow -gt 0)      | Should Be $true
        ($iStart -gt $iThrow) | Should Be $true
    }
    It 'the total is split into module catalog vs server setup' {
        ($script:Src -match 'ms total  \(\{1\} ms module catalog \+ \{2\} ms server setup\)') | Should Be $true
    }
    It 'the setup slice cannot render negative if the clocks disagree' {
        ($script:Src -match '\[Math\]::Max\(0, \[int\]\$startupSw\.ElapsedMilliseconds - \[int\]\$catalogSw\.ElapsedMilliseconds\)') | Should Be $true
    }
    It 'it is printed before "Listening", so it is visible even if the server then blocks' {
        $iTime = $script:Src.IndexOf('ms total  ({1} ms module catalog')
        $iList = $script:Src.IndexOf('Listening. Ctrl+C to stop.')
        ($iTime -gt 0)     | Should Be $true
        ($iTime -lt $iList) | Should Be $true
    }
}

Describe 'the timing detail stays on the console' {
    # Module inventory, versions and file sizes are launch-console diagnostics. If a
    # future change wants them in the UI that is a deliberate decision with a token gate
    # and a CSP to think about - not something that should drift in unnoticed.
    # -cmatch, case-SENSITIVE. The first draft used -match and failed against its own
    # subject: PowerShell's -match is case-insensitive, so 'LoadRows' matched the local
    # $loadRows the feature legitimately uses. The thing being forbidden is a PascalCase
    # KEY in the $state hashtable, which is how every other served value is spelled.
    It 'no load-timing value is stashed in $state for a route to serve' {
        ($script:Src -cmatch "LoadRows\s*=")     | Should Be $false
        ($script:Src -cmatch "LoadTimings\s*=")  | Should Be $false
        ($script:Src -cmatch "StartupMs\s*=")    | Should Be $false
        ($script:Src -cmatch "CatalogMs\s*=")    | Should Be $false
    }
    It 'the rows are a local, and are only ever written with Write-Host' {
        ($script:Src -match "\`$loadRows = New-Object System\.Collections\.ArrayList") | Should Be $true
        ($script:Src -match "& \`$writeJson \`$resp @\{[^}]*loadRows")                 | Should Be $false
    }
}
