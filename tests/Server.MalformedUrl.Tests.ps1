# =============================================================================
#  Server.MalformedUrl.Tests.ps1 - Pester 3.4 for the audit 2026-07-24 (P3) fix
#  in Get-JanetWebAssetPath: a request URL carrying a Windows-illegal path char
#  (< > | ") must resolve to the 404 shape ($null), NOT throw.
#
#  Before the fix the leaf was extracted with [System.IO.Path]::GetFileName, which
#  on .NET Framework throws ArgumentException("Illegal characters in path") for
#  those chars. The throw unwound past the static-asset branch into the accept
#  loop's catch, so the client got a 500 and the console got a stack trace where a
#  plain 404 was correct. These tests assert the no-throw + $null contract, and
#  that a legal path's behavior is byte-for-byte unchanged.
#
#  Dot-sourcing JanetWeb.Server.ps1 only DEFINES its functions (no top-level
#  executable code; the accept loop lives inside Start-JanetWebServer), so no
#  listener is started.
#
#  Run:  Invoke-Pester -Path .\tests\Server.MalformedUrl.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

Describe 'Get-JanetWebAssetPath - malformed URL is a 404, never a throw (audit 2026-07-24)' {
    $web = Join-Path $TestDrive 'web'
    New-Item -ItemType Directory -Path (Join-Path $web 'js') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $web 'index.html') -Value '<html>' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $web 'js\app.js')  -Value 'x'      -Encoding UTF8
    $webResolved = (Resolve-Path -LiteralPath $web).Path

    # The four chars .NET Framework's GetFileName rejects but a URL can legally carry.
    # Each is exercised both as a bare leaf and nested under a real directory, because
    # the old code called GetFileName on the WHOLE relative path.
    $bad = @('/<', '/>', '/|', '/"', '/a<b.js', '/js/a>b.js', '/js/x"y.css', '/js/p|q.js', '/<script>alert(1)</script>')

    foreach ($u in $bad) {
        It "does not throw for the illegal-char URL '$u'" {
            # $u is captured per-iteration by Pester 3.4's closure over the It block.
            { Get-JanetWebAssetPath -WebDir $webResolved -UrlPath $u } | Should Not Throw
        }
        It "404s (null) the illegal-char URL '$u'" {
            Get-JanetWebAssetPath -WebDir $webResolved -UrlPath $u | Should BeNullOrEmpty
        }
    }

    It '404s an illegal char combined with a traversal attempt' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/../sec<ret.txt' | Should BeNullOrEmpty
    }

    It 'still 404s a dev/underscore asset whose name also carries an illegal char' {
        # The underscore rule reads the LEAF, so the regex leaf-strip must still find it.
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/js/_de<v.js' | Should BeNullOrEmpty
    }

    # Regression guard: the leaf-extraction swap must not change any legal-path result.
    It 'still serves index.html for /' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/' | Should Be (Join-Path $webResolved 'index.html')
    }
    It 'still serves a real nested asset' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/js/app.js' | Should Be (Join-Path $webResolved 'js\app.js')
    }
}
