# =============================================================================
#  Server.ReportPreviewSandbox.Tests.ps1 - Pester 3.4 tests for the loop-3
#  report-preview XSS backstop (roadmap item 2).
#
#  Context (loop-1 P3-2): the report preview opens in a plain same-origin
#  window.open and /api/report-preview is served with a relaxed
#  script-src 'unsafe-inline' CSP so the generated report's inline pill-filter
#  script runs. Same-origin + unsafe-inline meant the ONLY barrier between an
#  unescaped report field and token-theft XSS (the popup inherits the SPA's
#  sessionStorage) was ConvertTo-HtmlEscaped.
#
#  Backstop: the preview response CSP now leads with "sandbox allow-scripts" -
#  the served DOCUMENT gets an opaque origin, so an injected script cannot read
#  sessionStorage (throws for opaque origins) and cannot reach /api same-origin,
#  while the report's own pure-DOM inline script keeps working. allow-same-origin
#  must NEVER appear (it would nullify the backstop); the SPA's own strict CSP
#  must NOT gain a sandbox directive (it would break the app shell).
#
#  Anchored source assertions (the request loop hosts a live HttpListener and
#  cannot be dot-sourced).
#
#  Run:  Invoke-Pester -Path .\tests\Server.ReportPreviewSandbox.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$srv  = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw
$view = Get-Content (Join-Path $script:Root 'web\js\views\reports.view.js') -Raw

Describe 'report-preview CSP carries the sandbox backstop' {
    # The $reportCsp assignment inside the GET /api/report-preview handler.
    $m = [regex]::Match($srv, '\$reportCsp\s*=\s*"([^"]+)"')
    It 'the $reportCsp assignment exists' {
        $m.Success | Should Be $true
    }
    $csp = $m.Groups[1].Value
    It 'leads with sandbox allow-scripts' {
        ($csp -match '^sandbox allow-scripts;') | Should Be $true
    }
    It 'does NOT grant allow-same-origin (that would nullify the backstop)' {
        ($csp -match 'allow-same-origin') | Should Be $false
    }
    It 'still allows the report''s inline script (unsafe-inline script-src preserved)' {
        ($csp -match "script-src 'unsafe-inline' 'self'") | Should Be $true
    }
}

Describe 'the SPA''s own CSP is NOT sandboxed (app shell must keep its origin)' {
    # The main static-serve $csp assignment (strict, sha256-pinned script-src).
    $m = [regex]::Match($srv, '\$csp\s*=\s*"([^"]+)"')
    It 'the main $csp assignment exists and is the sha256-pinned one' {
        $m.Success | Should Be $true
        ($m.Groups[1].Value -match 'sha256-') | Should Be $true
    }
    It 'contains no sandbox directive' {
        ($m.Groups[1].Value -match 'sandbox') | Should Be $false
    }
}

Describe 'one-shot capability semantics unchanged around the CSP change' {
    $start = $srv.IndexOf("'/api/report-preview'")
    $block = $srv.Substring($start, 2000)
    It 'the stashed preview is still deleted on read (one-shot)' {
        ($block -match [regex]::Escape('$state.ReportPreviews.Remove($rid)')) | Should Be $true
    }
    It 'the handler still sits BEFORE the token gate (top-level navigation cannot send the header)' {
        # Anchor on the gate's CODE line, not the string 'X-Janet-Token' (which
        # also appears in comments above the handler).
        $gate = $srv.IndexOf("`$tok = `$req.Headers['X-Janet-Token']")
        ($start -ge 0) | Should Be $true
        ($gate -gt $start) | Should Be $true
    }
}

Describe 'reports.view.js security note reflects the backstop' {
    It 'names the sandbox backstop and the never-add rule' {
        ($view -match 'sandbox allow-scripts') | Should Be $true
        ($view -match 'Never add allow-same-origin') | Should Be $true
    }
    It 'still names field escaping as the first line of defense' {
        ($view -match 'ConvertTo-HtmlEscaped') | Should Be $true
    }
}
