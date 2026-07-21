# =============================================================================
#  Troubleshoot.Hint.Tests.ps1 - Get-JanetTroubleshootHint maps a raw remote
#  error string to a single, most-specific, actionable troubleshooting hint.
#  Pure (no host contact).  Run: Invoke-Pester -Path .\tests\Troubleshoot.Hint.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.troubleshoot.psm1') -Force -PassThru

function Hint([string]$msg, [string]$srv = '') { & $m { param($x,$s) Get-JanetTroubleshootHint -Message $x -Server $s } $msg $srv }

Describe 'Get-JanetTroubleshootHint - maps remote error signatures to actionable guidance' {
    It 'blank / unknown input -> empty (never guesses)' {
        (Hint '')                             | Should Be ''
        (Hint '   ')                          | Should Be ''
        (Hint 'some totally novel error 42')  | Should Be ''
    }
    It 'Kerberos no-authority (0x80090351) -> realm/TrustedHosts guidance' {
        (Hint 'Connecting failed: 0x80090351') | Should Match 'TrustedHosts|realm|CAC'
    }
    It 'access-denied vs logon-failure are distinguished (privilege vs bad credential)' {
        (Hint 'Access is denied. (0x80070005)')        | Should Match 'not a local administrator|not authorized'
        (Hint 'The user name or password is incorrect') | Should Match 'wrong|bad username'
    }
    It 'name resolution / unreachable -> DNS / offline guidance' {
        (Hint 'The WinRM client cannot process the request because the server name cannot be resolved') | Should Match 'resolve|DNS|reached'
    }
    It 'RPC unavailable -> port 135 guidance' {
        (Hint 'The RPC server is unavailable. (0x800706BA)') | Should Match '135|RPC'
    }
    It 'SMB bad-netpath -> C$ / port 445 guidance' {
        (Hint 'The network path was not found (0x80070035)') | Should Match '445|C\$|admin share'
    }
    It 'timeout -> retry / raise-timeout guidance' {
        (Hint 'The operation has timed out') | Should Match 'timed out|timeout|Retry'
    }
    It 'names the server when supplied' {
        (Hint 'Access is denied' 'WS-042') | Should Match 'WS-042'
    }
    It 'is most-specific-first: 0x80090351 wins over the generic auth text around it' {
        # a message carrying BOTH a Kerberos HRESULT and the word "authentication"
        $h = Hint 'authentication error 0x80090351 occurred'
        $h | Should Match '0x80090351'
    }
}

# loop79: folded restart's Get-RrsShutdownErrorHint knowledge into the shared engine so restart can
# delegate. These signatures are the ones the engine previously LACKED (privilege-not-held, RPC 1727,
# ERROR_BAD_NETPATH) plus restart's extra auth/DNS phrasings (unknown-security-error, could-not-be-found).
Describe 'Get-JanetTroubleshootHint - restart-folded signatures (loop79)' {
    It 'privilege-not-held is DISTINCT from access-denied (authenticated but lacks a user right)' {
        (Hint 'A required privilege is not held by the client') | Should Match 'Privilege not held|user right|SeRemoteShutdownPrivilege'
        (Hint 'ERROR_PRIVILEGE_NOT_HELD')                       | Should Match 'Privilege not held|user right'
        # must NOT be swallowed by the access-denied branch
        (Hint 'SeRemoteShutdownPrivilege') | Should Match 'user right|secpol|SeRemoteShutdownPrivilege'
    }
    It 'RPC 1727 (no-more-endpoints) maps to the RPC-unavailable guidance' {
        (Hint 'RPC_S_NO_MORE_ENDPOINTS') | Should Match '135|RPC|endpoint'
    }
    It 'ERROR_BAD_NETPATH text maps to the SMB / C$ guidance' {
        (Hint 'The operation failed with ERROR_BAD_NETPATH') | Should Match '445|C\$|admin share|SMB'
    }
    It 'unknown-security-error maps to the Kerberos/auth guidance' {
        (Hint 'An unknown security error occurred') | Should Match 'TrustedHosts|realm|CAC'
    }
    It 'could-not-be-found maps to name-resolution / unreachable guidance' {
        (Hint 'The computer could not be found') | Should Match 'resolve|DNS|reached'
    }
}
