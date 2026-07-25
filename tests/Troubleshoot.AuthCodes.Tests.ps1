# =============================================================================
#  Troubleshoot.AuthCodes.Tests.ps1 - Pester 3.4 for the audit 2026-07-24 fix to
#  the shared error-to-hint mapper (modules\JanetWeb.troubleshoot.psm1), imported
#  by c2c / certdeploy / dhcp / pkginstall / remoteadmin / restart / secureboot /
#  upr / acas.
#
#  The mapper listed 0x8009030E in the "logon failure = wrong password" branch.
#  0x8009030E is SEC_E_NO_CREDENTIALS ("no credentials are available") - the
#  credential is MISSING, not wrong - so an operator chasing a no-credential
#  problem was told to go reset a perfectly good password. The real wrong-password
#  code is 0x8009030C (SEC_E_LOGON_DENIED), which the mapper did not carry at all.
#
#  PURE / offline - the mapper makes no host contact.
#  Run:  Invoke-Pester -Path .\tests\Troubleshoot.AuthCodes.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$tm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.troubleshoot.psm1') -Force -PassThru

function Get-Hint { param([string]$Msg, [string]$Server = '') & $tm { param($m, $s) Get-JanetTroubleshootHint -Message $m -Server $s } $Msg $Server }

Describe 'troubleshoot audit 2026-07-24 - 0x8009030C is the wrong-password code' {

    It '0x8009030C (SEC_E_LOGON_DENIED) maps to the wrong-credential hint' {
        $h = Get-Hint 'Connecting to remote server WS-1 failed with error 0x8009030C'
        $h | Should Match 'the credential is wrong'
        $h | Should Match 'expired/changed password'
    }
    It 'the SEC_E_LOGON_DENIED symbol maps there too' {
        (Get-Hint 'SEC_E_LOGON_DENIED returned by the security package') | Should Match 'the credential is wrong'
    }
    It 'the pre-existing wrong-password signatures still map there (no regression)' {
        (Get-Hint 'Logon failure: unknown user name or bad password')     | Should Match 'the credential is wrong'
        (Get-Hint 'STATUS_LOGON_FAILURE 0xC000006D')                      | Should Match 'the credential is wrong'
        (Get-Hint 'The user name or password is incorrect')               | Should Match 'the credential is wrong'
    }
}

Describe 'troubleshoot audit 2026-07-24 - 0x8009030E is SEC_E_NO_CREDENTIALS, not a bad password' {

    It '0x8009030E gets its own no-credential hint, NOT the wrong-password one' {
        $h = Get-Hint 'The WinRM client cannot process the request: 0x8009030E' -Server 'WS-1'
        $h | Should Match '0x8009030E'
        $h | Should Match 'SEC_E_NO_CREDENTIALS'
        # The wrong-password hint's own advice must NOT be what the operator sees.
        $h | Should Not Match 'expired/changed password'
        $h | Should Not Match 'locked-out account'
    }
    It 'the hint names the target and points at the real fix (supply/re-authenticate)' {
        $h = Get-Hint 'error 0x8009030E' -Server 'WS-7'
        $h | Should Match 'WS-7'
        $h | Should Match 'Set Credentials'
    }
    It 'the SEC_E_NO_CREDENTIALS symbol and its plain-language phrasing map there too' {
        (Get-Hint 'SEC_E_NO_CREDENTIALS')                                       | Should Match 'SEC_E_NO_CREDENTIALS'
        (Get-Hint 'No credentials are available in the security package')       | Should Match 'SEC_E_NO_CREDENTIALS'
    }
}

Describe 'troubleshoot audit 2026-07-24 - the surrounding branches are untouched' {

    It 'the more specific 0x80090351 authority branch still wins over both' {
        (Get-Hint 'SEC_E_NO_AUTHENTICATING_AUTHORITY 0x80090351') | Should Match '0x80090351'
    }
    It 'TrustedHosts / access-denied / RPC / timeout branches still map' {
        (Get-Hint 'the TrustedHosts list must be configured') | Should Match 'TrustedHosts'
        (Get-Hint 'Access is denied.')                        | Should Match 'Access denied'
        (Get-Hint 'The RPC server is unavailable')            | Should Match 'RPC server unavailable'
        (Get-Hint 'The operation has timed out')              | Should Match 'timed out'
    }
    It 'the no-credential-supplied branch still maps (it sits below the new one)' {
        (Get-Hint 'no credential is set for this run') | Should Match 'No credential is set'
    }
    It 'an unmatched message still returns empty (callers append, never replace)' {
        (Get-Hint 'something entirely unremarkable happened') | Should Be ''
        (Get-Hint '')                                         | Should Be ''
    }
}
