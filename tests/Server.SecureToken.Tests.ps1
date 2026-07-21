# =============================================================================
#  Server.SecureToken.Tests.ps1 - Pester 3.4 for the access-credential RNG
#  (New-JanetWebSecureToken, loop34). A loop-34 server/auth security deep-dive
#  found the boundary GREEN (constant-time-compared token, central /api
#  enforcement, canonicalize-and-root-checked static serve, Host guard +
#  custom-header token defeating DNS-rebinding/CSRF, loopback-only bind). The one
#  hardening item: the session token and the report-preview retrieval key - both
#  access credentials that guard the execution surface - were [guid]::NewGuid(),
#  which on Windows is CSPRNG-backed but relies on that implementation detail.
#  They are now minted from an EXPLICIT RandomNumberGenerator (256-bit hex), a
#  documented crypto guarantee. Defense-in-depth, not a vuln fix.
#
#  New-JanetWebSecureToken is the canonical mint (in the server module); the
#  no-modules launcher inlines a mirror. Run:  Invoke-Pester -Path .\tests\Server.SecureToken.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:Root 'server\JanetWeb.Server.ps1')   # defines the helpers; does not start a server

Describe 'New-JanetWebSecureToken - explicit CSPRNG access-credential mint' {
    It 'produces 64 lowercase hex chars (256 bits)' {
        (New-JanetWebSecureToken) | Should Match '^[0-9a-f]{64}$'
    }
    It 'produces a different value on each call (entropy sanity)' {
        (New-JanetWebSecureToken) | Should Not Be (New-JanetWebSecureToken)
    }
    It 'is never empty' {
        [string]::IsNullOrWhiteSpace((New-JanetWebSecureToken)) | Should Be $false
    }
}

Describe 'access credentials are minted from the CSPRNG, not GUIDv4' {
    $srv      = Get-Content (Join-Path $script:Root 'server\JanetWeb.Server.ps1') -Raw
    $launcher = Get-Content (Join-Path $script:Root 'DO NOT RUN - JanetWeb.Internal.ps1') -Raw

    It 'the report-preview retrieval key uses New-JanetWebSecureToken (not NewGuid)' {
        ($srv -match [regex]::Escape('$rid = New-JanetWebSecureToken')) | Should Be $true
    }
    It 'the launcher session token is minted from RandomNumberGenerator' {
        ($launcher -match 'RandomNumberGenerator') | Should Be $true
    }
    It 'the launcher session token no longer uses [guid]::NewGuid()' {
        ($launcher -match [regex]::Escape('$token = [guid]::NewGuid()')) | Should Be $false
    }
}
