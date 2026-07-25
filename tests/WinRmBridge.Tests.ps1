# =============================================================================
#  WinRmBridge.Tests.ps1 - Pester 3.4 for the WinRM Bridge tool's audit-2026-07-24
#  fixes. Companion to WinRmBridge.RevertScope.Tests.ps1 (which locks the original
#  revert-first / self-guard properties); this file locks the four P2 corrections:
#
#    1. the temporary 5986 firewall rule is SCOPED (dispatcher address + Domain
#       profile) instead of Any-profile / Any-remote-address / every NIC;
#    2. revert removes ONLY the listener bound to OUR temp cert's thumbprint, so a
#       legitimate 5986 listener stood up during the bridge window survives;
#    3. every audit row is emitted as 'TouchHost' - the server's ValidateSet
#       (TouchHost/VulnPatched) silently discarded the old 'WinRmBridge-<action>' id,
#       so the whole trail went nowhere;
#    4. check PROBES 5986 before claiming ACTIVE, and emits the LEFTOVER verdict the
#       manifest/registry/view have always advertised.
#
#  Plus cheap regression pins for the cancel contract, the CIM finally, the serial
#  loop (no 'threads' input) and the revert-window floor. The remote-exec paths are
#  not unit-testable without a domain, so behaviour is asserted on the PURE helpers
#  and on the generated target-facing scripts; the engine wiring is pinned by literal
#  source assertions (same approach as Acas.RebootAudit.Tests.ps1).
#
#  Run:  Invoke-Pester -Path .\tests\WinRmBridge.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:ModPath = Join-Path $script:Root 'modules\JanetWeb.winrmbridge.psm1'
Import-Module $script:ModPath -Force | Out-Null
$script:Src = Get-Content -LiteralPath $script:ModPath -Raw

Describe 'FINDING 1 (P2) - the temporary 5986 firewall rule is scoped, not Any/Any/Any' {
    $scoped   = New-WinRmBridgeEnableScript -RevertMinutes 90 -RevertEncoded 'QUJD' -RemoteAddress @('10.1.2.3')
    $unscoped = New-WinRmBridgeEnableScript -RevertMinutes 90 -RevertEncoded 'QUJD'

    It 'clamps the rule to the Domain profile even when no address resolves' {
        $unscoped.Contains('-Profile Domain') | Should Be $true
        $scoped.Contains('-Profile Domain')   | Should Be $true
    }
    It 'scopes the rule to the dispatcher address when one is supplied' {
        $scoped.Contains("-RemoteAddress @('10.1.2.3')") | Should Be $true
    }
    It 'never emits an Any-profile / Any-address rule' {
        $scoped.Contains('-Profile Any')        | Should Be $false
        $unscoped.Contains('-Profile Any')      | Should Be $false
        $scoped.Contains('-RemoteAddress Any')  | Should Be $false
        # with nothing resolvable the parameter is omitted entirely (Domain clamp only) -
        # it is never emitted with an empty/garbage value that would widen or void the rule
        $unscoped.Contains('-RemoteAddress')    | Should Be $false
    }
    It 'keeps the rule tagged with our group so revert can still find it' {
        $scoped.Contains("-Group 'JANET-WinRMBridge'") | Should Be $true
    }

    Context 'Select-WinRmBridgeScopeAddress - only real, routable IPv4 sources survive' {
        It 'keeps routable IPv4 and IPv4/CIDR' {
            $r = @(Select-WinRmBridgeScopeAddress -Address @('10.1.2.3','192.168.0.0/24'))
            $r.Count | Should Be 2
        }
        It 'drops loopback, APIPA and 0.0.0.0' {
            @(Select-WinRmBridgeScopeAddress -Address @('127.0.0.1','169.254.9.9','0.0.0.0')).Count | Should Be 0
        }
        It 'drops hostnames, IPv6 and anything that could be spliced into the remote script' {
            @(Select-WinRmBridgeScopeAddress -Address @('WS-001','::1','10.1.2.3; calc.exe',"10.1.2.3'")).Count | Should Be 0
        }
        It 'de-duplicates' {
            @(Select-WinRmBridgeScopeAddress -Address @('10.1.2.3','10.1.2.3')).Count | Should Be 1
        }
        It 'returns a FLAT string list (an extra wrap would splice System.Object[] into the rule)' {
            $r = @(Select-WinRmBridgeScopeAddress -Address @('10.1.2.3'))
            ($r[0] -is [string]) | Should Be $true
        }
    }

    Context 'Get-WinRmBridgeDispatcherAddress - enumerates the identity HashSet correctly' {
        It 'returns only routable IPv4 literals (no hostnames, no loopback)' {
            $bad = @(Get-WinRmBridgeDispatcherAddress | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$' -or $_ -like '127.*' })
            $bad.Count | Should Be 0
        }
    }
}

Describe 'FINDING 2 (P2) - revert only removes the listener bound to OUR cert thumbprint' {
    $rev = New-WinRmBridgeRevertScript

    It 'collects OUR temp cert thumbprint(s) before touching any listener' {
        $rev.Contains("FriendlyName -eq 'JANET-WinRMBridge-Temp'") | Should Be $true
        $rev.Contains('$mine = @($myCert | ForEach-Object')        | Should Be $true
    }
    It 'reads each HTTPS listener CertificateThumbprint and removes only a matching one' {
        $rev.Contains("$_.Name -eq 'CertificateThumbprint'")        | Should Be $true
        $rev.Contains('if ($tpRead -and ($mine -contains $tp))')    | Should Be $true
    }
    It 'no longer pipes EVERY Transport=HTTPS listener straight into Remove-Item (the old blanket teardown)' {
        $rev.Contains("Where-Object { `$_.Keys -contains 'Transport=HTTPS' } | Remove-Item") | Should Be $false
    }
    It 'keeps the thumbprint scoping while NOT gating the rest of the teardown on the cert' {
        # superseded by the 2026-07-25 fail-open fix: the cert scopes the LISTENER only.
        $mi = $rev.IndexOf('$mine = @($myCert | ForEach-Object')
        $ri = $rev.IndexOf('Remove-Item -Recurse -Force')
        ($mi -ge 0 -and $ri -gt $mi) | Should Be $true
        # the cert guard survives ONLY around the cert removal; rule + tasks are top level
        $rev.Contains('if ($myCert.Count -gt 0) { $myCert | Remove-Item -Force }') | Should Be $true
        $rev.Contains("`nRemove-NetFirewallRule -Group 'JANET-WinRMBridge'")       | Should Be $true
    }
    It 'still removes the firewall rule only by OUR group tag' {
        $rev.Contains("Remove-NetFirewallRule -Group 'JANET-WinRMBridge'") | Should Be $true
    }
    It 'never weakens WinRM to get a connection (no TrustedHosts *, no Basic, no unencrypted)' {
        foreach ($s in @($rev, (New-WinRmBridgeEnableScript -RevertMinutes 90 -RevertEncoded 'QUJD'))) {
            $s.Contains('TrustedHosts')        | Should Be $false
            $s.Contains('AllowUnencrypted')    | Should Be $false
            $s.Contains('Basic')               | Should Be $false
        }
    }
}

Describe 'FINDING 3 (P2) - every audit row uses an action the engine ValidateSet accepts' {
    # server\JanetWeb.Logging.ps1 pins [ValidateSet('TouchHost','VulnPatched')]; anything
    # else is dropped by the server with a warning, which is what used to happen to 100%
    # of this tool's audit rows.
    $auditLines = @(($script:Src -split "`r?`n") | Where-Object { $_ -match "type='audit'" })

    It 'emits at least one audit row' {
        ($auditLines.Count -ge 1) | Should Be $true
    }
    It 'uses TouchHost on every audit emit' {
        foreach ($l in $auditLines) { ($l -match "action='TouchHost'") | Should Be $true }
    }
    It 'no longer emits the rejected WinRmBridge-<action> id' {
        $script:Src.Contains("action=('WinRmBridge-") | Should Be $false
    }
    It 'keeps the bridge action searchable in the audit detail instead' {
        $script:Src.Contains('"winrmbridge/$ActionId - "') | Should Be $true
    }
    It 'uses only ValidateSet-legal results (Success/Failure/Skipped)' {
        $bad = @([regex]::Matches($script:Src, "result='([A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value } |
                 Where-Object { $_ -notin @('Success','Failure','Skipped') })
        $bad.Count | Should Be 0
    }
    It 'does not audit the read-only check action (no host is touched)' {
        $script:Src.Contains("if (`$ActionId -ne 'check') { & `$auditOf") | Should Be $true
    }
}

Describe 'FINDING 4 (P2) - check probes 5986 before claiming ACTIVE (and flags LEFTOVER)' {
    $now = [datetime]'2026-07-24 12:00:00'

    It 'ACTIVE only when the task is armed AND 5986 answers AND the revert is still ahead' {
        (Get-WinRmBridgeCheckState -Https5986 $true -TaskPresent $true -NextRunTime ([datetime]'2026-07-24 13:00') -TargetNow $now).State | Should Be 'ACTIVE'
    }
    It 'NEVER claims ACTIVE from the task alone when 5986 is closed' {
        $v = Get-WinRmBridgeCheckState -Https5986 $false -TaskPresent $true -NextRunTime ([datetime]'2026-07-24 13:00') -TargetNow $now
        $v.State | Should Be 'ARMED'
        ($v.Detail -like '*NOT listening*') | Should Be $true
    }
    It 'flags LEFTOVER when 5986 is still up past the timed revert' {
        (Get-WinRmBridgeCheckState -Https5986 $true -TaskPresent $true -NextRunTime ([datetime]'2026-07-24 11:00') -TargetNow $now).State | Should Be 'LEFTOVER'
    }
    It 'flags LEFTOVER when the timed trigger is gone entirely but the listener is up' {
        (Get-WinRmBridgeCheckState -Https5986 $true -TaskPresent $true -NextRunTime $null -TargetNow $now).State | Should Be 'LEFTOVER'
    }
    It 'reports REVIEW - never a clean none - for an unattributable 5986 listener' {
        # audit 2026-07-25 (fable re-audit follow-up): 'none / not ours; left alone' rendered
        # st-ok and MASKED the leftover the old fail-open revert produced (tasks self-deleted,
        # listener + rule left). Nothing is touched either way, but it must not read as clean.
        $v = Get-WinRmBridgeCheckState -Https5986 $true -TaskPresent $false -NextRunTime $null -TargetNow $now
        $v.State | Should Be 'REVIEW'
        ($v.Detail -like '*no JANET bridge task*') | Should Be $true
        ($v.Detail -like '*leftover*')             | Should Be $true
    }
    It 'reports none for a clean host' {
        (Get-WinRmBridgeCheckState -Https5986 $false -TaskPresent $false -NextRunTime $null -TargetNow $now).State | Should Be 'none'
    }
    It 'the engine feeds it the real 5986 probe and the TARGET clock' {
        $script:Src.Contains("Get-WinRmBridgeCheckState -Https5986 ([bool]`$ports['5986'])") | Should Be $true
        $script:Src.Contains('-TargetNow (Get-WrbTargetTime -CimSession $cim)')              | Should Be $true
    }
    It 'probes each port independently (no first-open short-circuit hiding 5986)' {
        (Get-WrbPortLabel ([ordered]@{ '5985'=$false; '5986'=$true; '135'=$true })) | Should Be 'TCP 5986'
        (Get-WrbPortLabel ([ordered]@{ '5985'=$false; '5986'=$false }))             | Should Be ''
    }
}

Describe 'audit 2026-07-24 regression pins (findings 5-11)' {
    It 'F5: the CIM session is disposed in a finally on every path' {
        $script:Src.Contains('} finally {') | Should Be $true
        $script:Src.Contains('if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }') | Should Be $true
    }
    It 'F6: operator cancel reads $Params[''__job''] like every peer engine' {
        $script:Src.Contains("`$Params.ContainsKey('__job')") | Should Be $true
        $script:Src.Contains('if (& $cancelCheck) {')         | Should Be $true
    }
    It 'F7: the dead threads input is gone from all three actions' {
        $m = Get-JanetToolManifest
        $bad = @($m.actions | Where-Object { @($_.inputs | ForEach-Object { $_.name }) -contains 'threads' })
        $bad.Count | Should Be 0
    }
    It 'F8: DCOM requires TCP 135 and the CIM connect is time-boxed' {
        $script:Src.Contains("if (-not `$ports['135'])") | Should Be $true
        $script:Src.Contains('OperationTimeoutSec=$TimeoutSec') | Should Be $true
    }
    It 'F9: LEFTOVER is really emitted by the module now (not just styled by the view)' {
        $script:Src.Contains("State='LEFTOVER'") | Should Be $true
    }
    It 'F10: a failed Start-ScheduledTask reports PENDING, not BRIDGING' {
        $script:Src.Contains("catch { `$started = `$false; `$startErr = `$_.Exception.Message }") | Should Be $true
        $script:Src.Contains("Status='PENDING'") | Should Be $true
    }
    It 'F10: the immediate trigger is stamped on the TARGET clock' {
        $script:Src.Contains('$startAt = (Get-WrbTargetTime -CimSession $cim).AddSeconds(30)') | Should Be $true
        $script:Src.Contains('New-ScheduledTaskTrigger -Once -At (Get-Date)') | Should Be $false
    }
    It 'F11: no double TCP prefix in the DCOM-failure detail' {
        $script:Src.Contains('"TCP $ping') | Should Be $false
    }
    It 'F11: the engine floors revertMinutes at 5 like the payload does' {
        $script:Src.Contains('if ($revertMinutes -lt 5) { $revertMinutes = 5 }') | Should Be $true
        (New-WinRmBridgeEnableScript -RevertMinutes 1 -RevertEncoded 'QUJD').Contains('AddMinutes(5)') | Should Be $true
    }
    It 'the manifest version was bumped for this pass' {
        (Get-JanetToolManifest).version | Should Be '0.2.1'
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - BEHAVIOURAL tests for the revert.
#
#  The revert script runs on the TARGET as SYSTEM, so it was only ever asserted as a
#  string. That is exactly how a fail-OPEN survived two passes: the whole teardown sat
#  inside 'if ($myCert.Count -gt 0)' while the schtasks deletes ran unconditionally, so a
#  temp cert removed out-of-band (cert-hygiene sweep of the 1-day self-signed cert, manual
#  delete, half-finished earlier revert) left the listener AND the group-tagged firewall
#  rule behind with every revert path deleted - 5986 open, forever, unreverted.
#
#  These EXECUTE the generated script against stubbed Cert:/WSMan:/firewall/schtasks
#  surfaces (functions outrank applications in PowerShell command resolution, so a
#  'schtasks.exe' function shadows the real binary) and assert the OUTCOME. Nothing here
#  touches the local machine: every cmdlet the script calls is shadowed.
# =============================================================================
function New-WrbFakeCert { param([string]$Thumb, [string]$Friendly = 'JANET-WinRMBridge-Temp')
    [pscustomobject]@{ FriendlyName = $Friendly; Thumbprint = $Thumb }
}
function New-WrbFakeListener { param([string]$Name, [string]$Tp = '', [bool]$ThrowOnRead = $false)
    [pscustomobject]@{ Name = $Name; PSPath = "WSMan:\localhost\Listener\$Name"; Keys = @("Transport=HTTPS","Address=*"); Tp = $Tp; ThrowOnRead = $ThrowOnRead }
}
function Invoke-WrbRevertHarness {
    param([object[]]$Certs = @(), [object[]]$Listeners = @())
    $seen = @{
        ListenersRemoved = New-Object System.Collections.ArrayList
        CertsRemoved     = New-Object System.Collections.ArrayList
        FwGroups         = New-Object System.Collections.ArrayList
        Tasks            = New-Object System.Collections.ArrayList
        Said             = New-Object System.Collections.ArrayList
    }
    $lst = @($Listeners)
    $crt = @($Certs)

    function Get-ChildItem {
        param([Parameter(Position = 0)][string]$Path)
        if ($Path -like 'Cert:*')  { return $crt }
        if ($Path -like 'WSMan:\localhost\Listener') { return $lst }
        $one = @($lst | Where-Object { $_.PSPath -eq $Path })[0]
        if ($one -and $one.ThrowOnRead) { throw 'access denied reading listener properties' }
        if ($one -and $one.Tp) { return @([pscustomobject]@{ Name = 'CertificateThumbprint'; Value = $one.Tp }) }
        return @()   # property missing entirely -> $tp stays blank (the other unreadable shape)
    }
    function Get-Item { param([Parameter(Position = 0)][string]$Path) @($lst | Where-Object { $_.PSPath -eq $Path }) }
    function Remove-Item {
        param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Position = 0)]$Path, [switch]$Recurse, [switch]$Force)
        process {
            if ($InputObject -and $InputObject.PSObject.Properties['PSPath']) { [void]$seen.ListenersRemoved.Add([string]$InputObject.Name) }
            elseif ($InputObject) { [void]$seen.CertsRemoved.Add([string]$InputObject.Thumbprint) }
        }
    }
    function Remove-NetFirewallRule { param([string]$Group) [void]$seen.FwGroups.Add([string]$Group) }
    function schtasks.exe { [void]$seen.Tasks.Add(($args -join ' ')) }
    function Out-Host { param([Parameter(ValueFromPipeline = $true)]$InputObject) process { [void]$seen.Said.Add([string]$InputObject) } }
    function New-EventLog { param($LogName, $Source) }
    function Write-EventLog { param($LogName, $Source, $EntryType, $EventId, $Message) [void]$seen.Said.Add('EVENTLOG:' + [string]$Message) }

    & ([scriptblock]::Create((New-WinRmBridgeRevertScript)))
    $seen
}
function Test-WrbTaskDeleted { param($Seen, [string]$Name) @($Seen.Tasks | Where-Object { $_ -like "*/tn $Name /f" }).Count -gt 0 }

Describe 'audit 2026-07-25 F1 (P3) - the revert cannot fail OPEN when the temp cert is gone' {
    It 'happy path: our cert + our listener -> everything comes down, both tasks deleted' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @(New-WrbFakeListener 'L1' 'aabbcc')
        @($s.ListenersRemoved) -contains 'L1'    | Should Be $true
        @($s.CertsRemoved) -contains 'AABBCC'    | Should Be $true
        @($s.FwGroups) -contains 'JANET-WinRMBridge' | Should Be $true
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Enable') | Should Be $true
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert') | Should Be $true
    }
    It 'cert GONE, nothing left listening -> the firewall rule and BOTH tasks still come down' {
        # the old code removed nothing but the tasks: rule left behind forever.
        $s = Invoke-WrbRevertHarness -Certs @() -Listeners @()
        @($s.FwGroups) -contains 'JANET-WinRMBridge'       | Should Be $true
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Enable') | Should Be $true
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert') | Should Be $true
        @($s.ListenersRemoved).Count | Should Be 0
    }
    It 'cert GONE but a 5986 listener remains -> rule removed, listener LEFT, revert task KEPT armed' {
        $s = Invoke-WrbRevertHarness -Certs @() -Listeners @(New-WrbFakeListener 'L1' 'aabbcc')
        @($s.FwGroups) -contains 'JANET-WinRMBridge'       | Should Be $true   # exposure shrinks either way
        @($s.ListenersRemoved).Count                        | Should Be 0       # unattributable -> never removed blind
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Enable')  | Should Be $true
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert')  | Should Be $false # the revert path SURVIVES
    }
    It 'and it says so loudly (host + event log), naming the listener it could not attribute' {
        $s = Invoke-WrbRevertHarness -Certs @() -Listeners @(New-WrbFakeListener 'L1' 'aabbcc')
        @($s.Said | Where-Object { $_ -like '*could not attribute*' -and $_ -like '*L1*' }).Count | Should BeGreaterThan 0
        @($s.Said | Where-Object { $_ -like 'EVENTLOG:*' }).Count | Should BeGreaterThan 0
    }
    It 'a foreign listener stood up during the window still survives our revert (P2 unchanged)' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @((New-WrbFakeListener 'MINE' 'aabbcc'), (New-WrbFakeListener 'PROD' 'DEADBEEF'))
        @($s.ListenersRemoved) -contains 'MINE' | Should Be $true
        @($s.ListenersRemoved) -contains 'PROD' | Should Be $false
        # PROD is attributable (readable thumbprint + our cert present) -> not a leftover,
        # so the tasks may still self-delete.
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert') | Should Be $true
    }
}

Describe 'audit 2026-07-25 F2 (P3) - an unreadable listener thumbprint fails CLOSED' {
    It 'a thumbprint read that THROWS leaves the listener reported, not silently skipped' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @(New-WrbFakeListener 'L1' '' $true)
        @($s.ListenersRemoved).Count | Should Be 0
        @($s.Said | Where-Object { $_ -like '*unreadable*' -and $_ -like '*L1*' }).Count | Should BeGreaterThan 0
    }
    It 'and the revert stays ARMED (the old code deleted the tasks, cert and rule around it)' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @(New-WrbFakeListener 'L1' '' $true)
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert')        | Should Be $false
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert-Force')  | Should Be $true   # the one-shot may go
        @($s.FwGroups) -contains 'JANET-WinRMBridge'               | Should Be $true
    }
    It 'a BLANK/absent CertificateThumbprint property is treated the same way' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @(New-WrbFakeListener 'L1' '')
        @($s.ListenersRemoved).Count                        | Should Be 0
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert') | Should Be $false
    }
    It 'ours still comes down even when a sibling listener is unreadable' {
        $s = Invoke-WrbRevertHarness -Certs @(New-WrbFakeCert 'AABBCC') -Listeners @((New-WrbFakeListener 'MINE' 'AABBCC'), (New-WrbFakeListener 'MYSTERY' '' $true))
        @($s.ListenersRemoved) -contains 'MINE'             | Should Be $true
        @($s.ListenersRemoved) -contains 'MYSTERY'          | Should Be $false
        (Test-WrbTaskDeleted $s 'JANET-WinRMBridge-Revert') | Should Be $false
    }
}

Describe 'audit 2026-07-25 F3 (P4) - a non-numeric revertMinutes is a clean refusal, not a cast throw' {
    function Invoke-WrbEnable { param($Minutes)
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        # nothing is touched: this refusal happens before the first CIM session (no network).
        $r = Invoke-JanetToolAction -ActionId 'enable' -Params @{ targets='FAR-HOST-9'; confirm='ENABLE'; revertMinutes=$Minutes } -Credential $null -Emit $emit
        @{ Result = $r; Events = @($evs) }
    }
    It 'refuses with an operator-readable message instead of throwing' {
        $o = Invoke-WrbEnable 'ninety'
        [bool]$o.Result.summary.rejected | Should Be $true
        @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'whole number of minutes' }).Count | Should BeGreaterThan 0
    }
    It 'refuses before any target is touched (no rows)' {
        @((Invoke-WrbEnable '90 min').Result.rows).Count | Should Be 0
    }
}
