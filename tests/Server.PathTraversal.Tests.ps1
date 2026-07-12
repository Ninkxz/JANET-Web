# =============================================================================
#  Server.PathTraversal.Tests.ps1 - Pester 3.4 for Get-JanetWebAssetPath, the
#  static-file serving path-traversal defense extracted from the accept loop
#  (loop13). This locks in the loop-12 audit's #1 property: a crafted asset URL
#  can NEVER escape the web root and read an arbitrary disk file (arbitrary file
#  read = full compromise: token file, other repos on the SMB drive).
#
#  We pass RAW '..' payloads straight to the function - i.e. we do NOT rely on
#  System.Uri collapsing '..' upstream (it does, in the live flow). This tests the
#  function's OWN defense (Resolve-Path canonicalize + StartsWith containment) as
#  defense-in-depth, so a future refactor that loses the Uri layer still can't leak.
#
#  Dot-sourcing JanetWeb.Server.ps1 only DEFINES its functions (the file has no
#  top-level executable code and the accept loop lives inside Start-JanetWebServer),
#  so no listener is started.
#
#  Run:  Invoke-Pester -Path .\tests\Server.PathTraversal.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')

Describe 'Get-JanetWebAssetPath - static-file path-traversal defense (loop13)' {
    # A real web root + a secret OUTSIDE it + a sibling 'web2', all under TestDrive.
    $web = Join-Path $TestDrive 'web'
    New-Item -ItemType Directory -Path (Join-Path $web 'js') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $web 'index.html')   -Value '<html>' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $web 'js\app.js')    -Value 'x'      -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $web '_devtest.html') -Value 'dev'   -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $TestDrive 'secret.txt') -Value 'TOP-SECRET' -Encoding UTF8
    New-Item -ItemType Directory -Path (Join-Path $TestDrive 'web2') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $TestDrive 'web2\x.js') -Value 'y' -Encoding UTF8
    $webResolved = (Resolve-Path -LiteralPath $web).Path

    It "serves index.html for '/'" {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/' | Should Be (Join-Path $webResolved 'index.html')
    }
    It 'serves a real in-root nested asset' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/js/app.js' | Should Be (Join-Path $webResolved 'js\app.js')
    }
    It '404s (null) a dev/underscore-prefixed asset' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/_devtest.html' | Should BeNullOrEmpty
    }
    It '404s a ../ traversal to a file outside the root' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/../secret.txt'        | Should BeNullOrEmpty
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/js/../../secret.txt'  | Should BeNullOrEmpty
    }
    It '404s a backslash ..\ traversal' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/..\secret.txt' | Should BeNullOrEmpty
    }
    It '404s an absolute drive path' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/C:/Windows/win.ini' | Should BeNullOrEmpty
    }
    It '404s a sibling web2 via prefix (trailing-separator containment)' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/../web2/x.js' | Should BeNullOrEmpty
    }
    It '404s a non-existent in-root file' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/nope.js' | Should BeNullOrEmpty
    }
    It 'does not serve a directory (leaf-only)' {
        Get-JanetWebAssetPath -WebDir $webResolved -UrlPath '/js' | Should BeNullOrEmpty
    }
}
