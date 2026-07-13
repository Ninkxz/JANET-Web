# =============================================================================
#  WinRmBridge.RevertScope.Tests.ps1 - Pester 3.4 for the WinRM Bridge tool's
#  safety net (loop17). winrmbridge is DESTRUCTIVE (it stands up / tears down a
#  temporary 5986 HTTPS listener + cert + firewall rule on a remote host via a
#  SYSTEM scheduled task) yet had NO dedicated test. The crown-jewel property
#  (loop-12 audit P2): the REVERT must only remove artifacts THIS tool created -
#  it can never nuke a pre-existing production 5986 listener. These lock that in
#  plus the enable revert-first ordering, the self-guard, and the host-token gate.
#
#  All asserted functions are already exported; substring/index checks are literal
#  (.Contains / IndexOf) to avoid regex-escaping fragility on the generated scripts.
#
#  Run:  Invoke-Pester -Path .\tests\WinRmBridge.RevertScope.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $script:Root 'modules\JanetWeb.winrmbridge.psm1') -Force | Out-Null

Describe 'winrmbridge REVERT script - scoped to OUR artifacts only (never a prod listener)' {
    $rev = New-WinRmBridgeRevertScript

    It 'gates the entire teardown behind the presence of OUR temp cert' {
        # if our FriendlyName cert is absent, the box has a pre-existing/foreign listener
        # (enable creates nothing in that case), so nothing is torn down.
        $rev.Contains("FriendlyName -eq 'JANET-WinRMBridge-Temp'") | Should Be $true
        $rev.Contains('if ($myCert.Count -gt 0)')                  | Should Be $true
    }
    It 'removes the HTTPS listener ONLY inside the our-cert-present guard' {
        $gi = $rev.IndexOf('if ($myCert.Count -gt 0)')
        $ri = $rev.IndexOf('Remove-Item -Recurse -Force')
        ($gi -ge 0 -and $ri -gt $gi) | Should Be $true
    }
    It 'removes the firewall rule only by OUR group tag (not a blanket 5986 teardown)' {
        $rev.Contains("Remove-NetFirewallRule -Group 'JANET-WinRMBridge'") | Should Be $true
    }
    It 'never issues a blanket WinRM / PSRemoting teardown' {
        $rev.Contains('Disable-PSRemoting') | Should Be $false
        $rev.Contains('Stop-Service')       | Should Be $false
        $rev.Contains('winrm delete')       | Should Be $false
    }
    It 'deletes only its own scheduled tasks' {
        $rev.Contains("/tn 'JANET-WinRMBridge-Enable'") | Should Be $true
        $rev.Contains("/tn 'JANET-WinRMBridge-Revert'") | Should Be $true
    }
}

Describe 'winrmbridge ENABLE script - revert-first, never destroys a pre-existing listener' {
    $en = New-WinRmBridgeEnableScript -RevertMinutes 90 -RevertEncoded 'QUJD'

    It 'arms the self-revert task BEFORE standing up the listener (revert-first)' {
        $regi = $en.IndexOf("Register-ScheduledTask -TaskName 'JANET-WinRMBridge-Revert'")
        $crti = $en.IndexOf('New-SelfSignedCertificate')
        ($regi -ge 0 -and $crti -gt $regi) | Should Be $true
    }
    It 'leaves a pre-existing HTTPS listener untouched (creates nothing)' {
        $en.Contains('if ($existingHttps.Count -gt 0)') | Should Be $true
    }
    It 'tags its own cert + firewall rule so revert can scope to them' {
        $en.Contains("FriendlyName 'JANET-WinRMBridge-Temp'") | Should Be $true
        $en.Contains("-Group 'JANET-WinRMBridge'")            | Should Be $true
    }
    It 'floors a RevertMinutes below the 5-minute minimum' {
        (New-WinRmBridgeEnableScript -RevertMinutes 1 -RevertEncoded 'QUJD').Contains('AddMinutes(5)') | Should Be $true
    }
    It 'honors a normal RevertMinutes' {
        $en.Contains('AddMinutes(90)') | Should Be $true
    }
}

Describe 'winrmbridge self-guard + host-token gate' {
    It 'flags loopback / self as self (dispatcher never bridged)' {
        Test-WinRmBridgeSelfTarget 'localhost'        | Should Be $true
        Test-WinRmBridgeSelfTarget '127.0.0.1'        | Should Be $true
        Test-WinRmBridgeSelfTarget $env:COMPUTERNAME  | Should Be $true
        Test-WinRmBridgeSelfTarget ''                 | Should Be $true   # empty -> fail-safe drop
    }
    It 'does NOT flag a real remote host (no over-drop)' {
        Test-WinRmBridgeSelfTarget 'FAR-HOST-9' | Should Be $false
    }
    It 'accepts valid host tokens and rejects junk' {
        Test-WinRmBridgeHostToken 'WS-001'   | Should Be $true
        Test-WinRmBridgeHostToken '10.0.0.5' | Should Be $true
        Test-WinRmBridgeHostToken 'a b'      | Should Be $false
        Test-WinRmBridgeHostToken '|calc'    | Should Be $false
        Test-WinRmBridgeHostToken ''         | Should Be $false
    }
}
