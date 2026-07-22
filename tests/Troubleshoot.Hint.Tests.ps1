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
    It 'RPC 1727 (RPC_S_CALL_FAILED_DNE) + the real 1753 endpoint-mapper text map to RPC guidance' {
        # loop80 corrected the label: 1727 is RPC_S_CALL_FAILED_DNE, not "no-more-endpoints" (that phrase
        # is error 1753); both route to the RPC hint, but via REAL tokens, not a fabricated one.
        (Hint 'RPC_S_CALL_FAILED_DNE')                                            | Should Match '135|RPC|endpoint'
        (Hint 'There are no more endpoints available from the endpoint mapper')   | Should Match '135|RPC|endpoint'
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

# loop80 self-review (adversarial Fable review of loop79): the folded numeric tokens must not false-match a
# coincidental substring, and 'could not be found' must be host-qualified so it does not swallow unrelated
# "module/user name could not be found" errors. Regression guards for those confirmed false positives.
Describe 'Get-JanetTroubleshootHint - loop80 false-positive guards (bare-numeric boundaries + narrowed could-not-be-found)' {
    It '1314 as a coincidental substring (a KB number) does NOT trigger the privilege hint' {
        (Hint 'Download failed for KB5031314: connection closed') | Should Be ''
    }
    It '1727 inside a larger number (a byte count / duration) does NOT trigger the RPC hint' {
        (Hint 'copy failed after 172799 ms elapsed') | Should Be ''
    }
    It 'a non-host "could not be found" (module / user name) does NOT trigger the DNS hint' {
        (Hint 'The specified module could not be found.') | Should Be ''
        (Hint 'The user name could not be found.')        | Should Be ''
    }
    It 'the genuine host-qualified "computer ... could not be found" still routes to name-resolution' {
        (Hint "The computer 'WS01' could not be found.") | Should Match 'resolve|DNS|reached'
    }
    It 'a quoted long AFNET FQDN in "computer ... could not be found" still routes (loop81 window widened 40->80)' {
        (Hint "The computer 'AREA52-1234ABC5.area52.afnoapps.usaf.mil' could not be found") | Should Match 'resolve|DNS|reached'
    }
    It 'an AD-object error routes to a dedicated AD hint, NOT the DNS hint (loop82/83 self-review)' {
        # a deleted/missing AD computer account is NOT a name-resolution failure - the host may be reachable.
        # loop82 made these return '' via a single-alternative lookahead; loop83 gives them a proper AD hint
        # via a dedicated signature ABOVE name-resolution, which also closes the sibling-alternative leaks.
        foreach ($msg in @(
            "The computer account for 'WS01`$' in domain 'AREA' could not be found in Active Directory.",
            'The computer object associated with the cluster network name resource could not be found in Active Directory.',
            'The computer account for this workstation could not be found.',
            "The computer 'WS01' could not be found in Active Directory.",
            "Cannot find the computer account 'WS01`$' in Active Directory",                                 # loop82-review leak #1
            'The computer account for WS01 could not be found in Active Directory; the SID could not be resolved', # leak #2
            'The specified computer accounts could not be found in Active Directory'                          # plural
        )) {
            (Hint $msg) | Should Match 'Active Directory computer|AD identity|Reset the target'
            (Hint $msg) | Should Not Match 'check DNS resolves'
        }
    }
    It 'MSI / uninstaller exit-code failures route to their own hints (loop83 signature growth)' {
        (Hint 'msiexec exit 1618')        | Should Match 'already running|serializes|in-flight'
        (Hint 'uninstall exit 1605')      | Should Match 'not installed|already removed|orphaned'
        (Hint 'FAIL (setup exit 1603)')   | Should Match '1603|fatal|verbose log'
        (Hint 'rejected: executable not found: C:\App\uninst.exe') | Should Match 'uninstaller could not be launched|orphaned'
        (Hint 'rejected: unparseable uninstall string (no .exe)')  | Should Match 'could not be safely parsed|vendor'
    }
    It 'a dotted VERSION string containing an MSI/RPC/priv code does NOT false-match (loop83 boundary hardening)' {
        (Hint 'installed 16.0.1603 vs target 16.0.1700') | Should Be ''
        (Hint 'build 16.0.1722.0 detected')              | Should Be ''
        (Hint 'version 6.0.1314 is current')             | Should Be ''
    }
    It 'the real privilege HRESULT 0x80070522 (=win32 1314) routes to privilege-not-held' {
        (Hint 'Exception from HRESULT: 0x80070522') | Should Match 'Privilege not held|user right'
    }
    It 'the standalone word-boundaried codes still route (1314 / 1727 / 1722 alone)' {
        (Hint 'shutdown returned 1314')     | Should Match 'Privilege not held|user right'
        (Hint 'the call failed with 1727')  | Should Match '135|RPC|endpoint'
        (Hint 'RPC error 1722 occurred')    | Should Match '135|RPC'
    }
}
