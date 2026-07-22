# =============================================================================
#  JanetWeb.troubleshoot.psm1 - shared error-to-actionable-hint mapper.
#
#  Every JANET tool acts on remote hosts over WinRM/SMB, so a failure almost
#  always surfaces as a cryptic WinRM/RPC/auth/DNS error string. Two tools
#  (restart's Get-RrsShutdownErrorHint, dhcp's Get-JanetWsmanAuthHint) already
#  translate those into plain-language "here is why, here is how to fix it"
#  guidance; this generalises that into ONE helper every tool can import (the
#  same way tools import JanetWeb.javafix.psm1) and call where it surfaces a
#  failure to the operator.
#
#  Get-JanetTroubleshootHint -Message <raw error text> [-Server <host>] -> a
#  single most-specific hint string, or '' when nothing matches (callers append
#  it after the raw message, never in place of it - the raw detail is preserved).
#
#  PS 5.1, UTF-8 BOM. Pure (no host contact) - unit-tested.
# =============================================================================

function Get-JanetTroubleshootHint {
    param([string]$Message, [string]$Server = '')

    if ([string]::IsNullOrWhiteSpace($Message)) { return '' }
    $m   = [string]$Message
    $on  = $(if ($Server) { " on $Server" } else { '' })

    # --- Ordered most-specific-first. The first match wins, so put narrow,
    #     high-signal signatures (specific HRESULTs) above broad ones. ---

    # Kerberos / no authenticating authority (cross-realm, workgroup, missing SPN)
    if ($m -match '0x80090351|SEC_E_NO_AUTHENTICATING_AUTHORITY|no\s+authenticating\s+authority|unknown\s+security\s+error') {
        return "WinRM auth 0x80090351 (SEC_E_NO_AUTHENTICATING_AUTHORITY): no authority could validate the credential against the target$on. Common causes: the target is outside your Kerberos realm/trust, it is a workgroup/cross-domain host that needs a WinRM TrustedHosts entry, or its SPN is not registered. Clear the credential to fall back to the current CAC/session identity and re-run, or add the target to TrustedHosts."
    }
    # TrustedHosts (workgroup / cross-forest)
    if ($m -match 'TrustedHosts') {
        return "The target$on is not in the WinRM client TrustedHosts. As admin on the dispatcher: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<hostname-or-FQDN-or-*>' -Concatenate -Force. Workgroup and cross-forest targets always need this."
    }
    # Logon failure = genuinely wrong credential (distinct from access-denied)
    if ($m -match 'logon\s+failure|0x8009030E|0xC000006D|wrong\s+user\s*name\s+or\s+password|the\s+user\s+name\s+or\s+password\s+is\s+incorrect') {
        return "Logon failure - the credential is wrong (bad username/password), not merely under-privileged. Check for a missing domain prefix (DOMAIN\user or user@domain.com), an expired/changed password, or a locked-out account. Clear the credential to fall back to the current CAC/session identity, or supply a different one."
    }
    # Access denied = authenticated but not privileged / UAC token filtering
    if ($m -match 'access\s+is\s+denied|access\s+denied|0x80070005|ERROR_ACCESS_DENIED|E_ACCESSDENIED') {
        return "Access denied$on - the credential authenticated but is not authorized: it is not a local administrator on the target (BUILTIN\Administrators), or UAC is filtering the token, or (for a service like DHCP/Trellix) the account lacks that service's admin role. Verify the account's membership on the target."
    }
    # Privilege not held = authenticated (even local-admin) but missing a specific user right
    # (e.g. SeRemoteShutdownPrivilege). Distinct from access-denied - the account IS trusted,
    # it just lacks the one right this action needs. (folded from restart's numeric mapper, loop 79)
    if ($m -match '\b1314\b|0x80070522|ERROR_PRIVILEGE_NOT_HELD|SeRemoteShutdownPrivilege|SeShutdownPrivilege|required\s+privilege\s+is\s+not\s+held|privilege\s+not\s+held') {
        return "Privilege not held$on (ERROR_PRIVILEGE_NOT_HELD / 1314): the account authenticated and may even be a local admin, but lacks the specific user right this action needs (a remote restart needs SeRemoteShutdownPrivilege). Grant the right in the target's local security policy (secpol.msc -> User Rights Assignment) or by GPO, or use an account that already holds it."
    }
    # Name resolution / host offline / unreachable (a specific "...cannot be resolved"
    # inside a generic WinRM wrapper is a DNS failure -> match it BEFORE the generic
    # WinRM-client-config signature below).
    if ($m -match 'could\s+not\s+be\s+resolved|cannot\s+be\s+resolved|cannot\s+find\s+the\s+computer|computer\b(?!\s+(?:account|object)\b).{0,80}?could\s+not\s+be\s+found(?!\s+in\s+Active\s+Directory)|No\s+such\s+host\s+is\s+known|destination\s+unreachable|actively\s+refused|A\s+connection\s+attempt\s+failed') {
        return "The target$on could not be resolved or reached. Check DNS resolves the name, that the host is powered on and on the network, and that nothing between you and it is blocking the connection (firewall / VLAN / offline)."
    }
    # WinRM not enabled / 5985 blocked / cannot connect
    if ($m -match 'WinRM\s+cannot\s+complete\s+the\s+operation|cannot\s+connect\s+to\s+the\s+destination|check\s+that\s+the\s+WinRM\s+service|winrm\s+quickconfig|Enable-PSRemoting|WS-Management\s+service\s+running') {
        return "Could not reach WinRM on the target$on. WinRM may be disabled (run Enable-PSRemoting on the target), TCP 5985/5986 may be firewall-blocked, or the WinRM service may be stopped. Verify: Test-NetConnection $Server -Port 5985."
    }
    # WinRM client config rejected the request (generic - after the specific DNS case above)
    if ($m -match 'The\s+WinRM\s+client\s+cannot\s+process\s+the\s+request') {
        return "The dispatcher's WinRM client config rejected the request. Inspect: winrm get winrm/config/client. A workgroup/cross-domain target usually needs a TrustedHosts entry, or the auth mode (Negotiate/Kerberos) is misconfigured."
    }
    # RPC unavailable (135 / dynamic ports) - CIM/DCOM/scheduled-task paths. Numerics are word-
    # boundaried so a coincidental substring (a PID/byte-count/KB) does not false-match (loop80). 1727
    # is RPC_S_CALL_FAILED_DNE (folded from restart, loop79 - corrected from the wrong "no-more-endpoints"
    # label, which is actually 1753 EPT_S_NOT_REGISTERED, matched here by its real "no more endpoints" text).
    if ($m -match 'RPC\s+server\s+is\s+unavailable|\b1722\b|0x800706BA|\b1727\b|RPC_S_CALL_FAILED_DNE|no\s+more\s+endpoints') {
        return "RPC server unavailable$on (0x800706BA/1722, or a related RPC failure such as 1727 or the endpoint mapper reporting no free endpoints). The RPC endpoint mapper (TCP 135) or the dynamic RPC port range is firewall-blocked, the mapper is not serving requests, or the target's RPC service is down. This blocks CIM/DCOM/scheduled-task calls; a WinRM-only path may still work."
    }
    # SMB / admin-share path (copy-to-C$ failures)
    if ($m -match 'bad\s+net\s*path|ERROR_BAD_NETPATH|0x80070035|network\s+path\s+was\s+not\s+found|The\s+network\s+name\s+cannot\s+be\s+found') {
        return "Network path not found$on (SMB). The admin share (C$) is unreachable: TCP 445 is blocked, the Server/LanmanServer service is stopped on the target, or admin shares are disabled. Needed for staging package/payload files."
    }
    # Operation timed out
    if ($m -match 'timed?\s*out|timeout|operation\s+has\s+timed') {
        return "The operation timed out$on. The target may be slow/overloaded, or a firewall may be silently dropping the connection (a blocked port often manifests as a hang, not a refusal) rather than actively refusing it. Retry, or raise the per-host timeout if the action is genuinely long-running."
    }
    # No credential supplied where one is needed
    if ($m -match 'no\s+credential|credential\s+is\s+required|Set\s+Credentials|current\s+session\s+identity') {
        return "No credential is set. Use Set Credentials (top-right) to supply an account with admin rights on the target, or ensure the current CAC/session identity has them."
    }
    # Disk full (staging / logs)
    if ($m -match 'not\s+enough\s+space|disk\s+is\s+full|0x70\b|ERROR_DISK_FULL') {
        return "Not enough disk space$on (or on the dispatcher for staging). Free space on the target's system/temp volume and retry."
    }
    # File in use / locked (uninstall, delete, replace)
    if ($m -match 'being\s+used\s+by\s+another\s+process|because\s+it\s+is\s+being\s+used|file\s+is\s+locked|cannot\s+access\s+the\s+file') {
        return "A file is locked by a running process$on. The app is likely still running (close it / stop its service), or another install is in progress. Retry after the process releases the file."
    }

    return ''
}

Export-ModuleMember -Function Get-JanetTroubleshootHint
