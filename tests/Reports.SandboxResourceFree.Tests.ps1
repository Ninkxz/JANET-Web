# =============================================================================
#  Reports.SandboxResourceFree.Tests.ps1 - Pester 3.4 static guard for the
#  loop-3 report-preview CSP `sandbox allow-scripts` backstop (roadmap item 7).
#
#  GET /api/report-preview serves the generated report under an OPAQUE origin
#  (server\JanetWeb.Server.ps1: `sandbox allow-scripts` leads the response CSP).
#  Under an opaque origin, `self` and any absolute path resolve to nothing, so
#  ANY external sub-resource the report references would silently fail to load:
#    - <script src> / <link> / @import  -> blocked (external code/style)
#    - <img src="/..."> / url(http...)  -> blocked (external asset)
#    - window.print() / <a download>    -> need allow-modals/allow-downloads,
#                                          which the sandbox deliberately omits
#  The report's ONLY script is a pure-DOM pill-filter/search block, which runs
#  fine under allow-scripts. This test fails the moment a report render function
#  adds a resource that the sandbox would break, so the constraint is
#  discoverable at edit time instead of as a silently-broken preview in the
#  field. (Opus loop-4 F8.)
#
#  ponytail: static source grep of JanetWeb.reports.psm1, not a render of each
#  report. A resource assembled by string concatenation (e.g. '<img '+'src=')
#  could slip past; the common case (a pasted <img>/<link>, a print button) is
#  caught. Upgrade path if that ceiling is ever hit: render each Render-*Html
#  function and assert on the emitted HTML.
#
#  Run:  Invoke-Pester -Path .\tests\Reports.SandboxResourceFree.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.reports.psm1') -Raw
$script:Srv  = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw

Describe 'the report-preview response is still sandboxed (the backstop this guard protects)' {
    It 'the /api/report-preview CSP still leads with sandbox allow-scripts' {
        $m = [regex]::Match($script:Srv, '\$reportCsp\s*=\s*"([^"]+)"')
        $m.Success | Should Be $true
        ($m.Groups[1].Value -match '^sandbox allow-scripts;') | Should Be $true
    }
}

Describe 'report HTML stays fully self-contained (no sandbox-breaking sub-resources)' {

    # NOTE: patterns are HTML-context-anchored (a tag name, or an attribute name
    # preceded by whitespace) so a PowerShell variable like `$src = ...` at
    # reports.psm1:3383 is NOT a false positive - only an actual `<tag attr=`
    # trips these.
    It 'has NO external script (no <script ...src...>)' {
        # The one legit report script is an attribute-free inline <script> (no
        # whitespace before >). A <script src=...> or any attributed script tag
        # introduces whitespace after "script" and trips this.
        ($script:Src -match '<script\s') | Should Be $false
    }
    It 'still contains the one inline pill-filter <script> block (anchor: the report is not empty)' {
        ($script:Src -match '<script>') | Should Be $true
    }
    It 'has NO src= HTML attribute (rules out <img src>, <iframe src>, <script src>)' {
        # whitespace before "src" => an attribute, not a $var ending in "src"
        ($script:Src -match '\ssrc\s*=') | Should Be $false
    }
    It 'has NO <img> element (external/inline image)' {
        ($script:Src -match '<img\b') | Should Be $false
    }
    It 'has NO <iframe> element' {
        ($script:Src -match '<iframe\b') | Should Be $false
    }
    It 'has NO <link> element (external stylesheet)' {
        ($script:Src -match '<link\b') | Should Be $false
    }
    It 'has NO @import (external CSS import)' {
        ($script:Src -match '@import') | Should Be $false
    }
    It 'has NO url( in CSS (external/background asset)' {
        ($script:Src -match 'url\(') | Should Be $false
    }
    It 'has NO href= HTML attribute (external anchor/resource; reports are self-contained)' {
        ($script:Src -match '\shref\s*=') | Should Be $false
    }
    It 'has NO programmatic print (needs allow-modals, omitted from the sandbox)' {
        ($script:Src -match '\.print\s*\(') | Should Be $false
    }
    It 'has NO download= HTML attribute (needs allow-downloads, omitted from the sandbox)' {
        ($script:Src -match '\sdownload\s*=') | Should Be $false
    }
}
