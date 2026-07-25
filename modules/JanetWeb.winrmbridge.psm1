# =============================================================================
#  JanetWeb.winrmbridge.psm1  -  WinRM Bridge (tool id: 'winrmbridge')
#
#  Stands up a TEMPORARY, self-reverting WinRM-over-HTTPS (5986) channel on a
#  target so the rest of the JANET suite can push patches/fixes to a box whose
#  WinRM (5985) is blocked by GPO - WITHOUT waiting on a GPO refresh and WITHOUT
#  leaving an unmanaged listener behind.
#
#  DESIGNED FOR SERVER + SERVICE-ACCOUNT operation (not an interactive ADW): the
#  session credential is expected to be a service account with LOCAL ADMIN on the
#  targets. Bootstrap transport is DCOM/WMI (135) - NOT WinRM - because the whole
#  point is reaching a box where WinRM is down. The tool pushes ONE SYSTEM
#  scheduled task over a DCOM CIM session; that task, running locally:
#     1. ARMS THE SELF-REVERT FIRST (triggers: at-startup AND now+N minutes on the
#        target's own clock) so there is never a listener without an armed revert;
#     2. THEN creates a short-lived self-signed cert + the HTTPS listener + a tagged
#        firewall rule.
#  The revert task removes the listener, firewall rule, temp cert, and BOTH tasks.
#  GPO stays authoritative long-term; this is a documented stopgap.
#
#  SAFETY: revert-first; self-guard (never the dispatcher); admin session + typed
#  confirm; everything tagged 'JANET-WinRMBridge' so Check/Revert can find leftovers.
#  The remote-exec paths need a CONTROLLED PILOT before production (not unit-testable
#  without a domain); the target-facing SCRIPTS are pure + unit-tested below.
#
#  Contract: Get-JanetToolManifest / Invoke-JanetToolAction -ActionId -Params -Credential -Emit
#
#  v0.2.1 (audit 2026-07-25, fable re-audit follow-up) - the revert can no longer fail OPEN:
#    * the temp cert no longer gates the WHOLE teardown. It only scopes the LISTENER (by
#      thumbprint); the group-tagged firewall rule and the scheduled tasks are torn down
#      regardless, so a cert removed out-of-band can no longer leave 5986 open with every
#      revert path self-deleted (P3 :62/:75/:78);
#    * an HTTPS listener we cannot positively attribute (unreadable thumbprint, or no temp
#      cert left to compare against) is LEFT IN PLACE, reported loudly (host + event log) and
#      keeps the standing revert task ARMED - it is never silently skipped (P3 :71);
#    * check reports such a listener as REVIEW instead of the old 'none / not ours; left
#      alone', which actively masked exactly this leftover (P3 :252);
#    * a non-numeric revertMinutes is a clean refusal, not a cast exception (P4 :401).
#
#  v0.2.0 (audit 2026-07-24) - eleven audit findings, the security-relevant ones first:
#    * the temp 5986 firewall rule is no longer Any/Any/Any: it is scoped to the JANET
#      dispatcher's own IPv4 address(es) and to the Domain profile (P2 :85);
#    * revert now removes ONLY the listener bound to OUR temp cert's thumbprint, so a
#      legitimate 5986 listener provisioned during the bridge window survives (P2 :46);
#    * every audit row is emitted as 'TouchHost' - the engine's ValidateSet silently
#      discarded the old 'WinRmBridge-<action>' ids, so the whole trail went nowhere (P2 :294);
#    * check actually PROBES 5986 before claiming ACTIVE, and flags LEFTOVER when the
#      listener outlives its timed revert (P2 :268 / P3 :166);
#    * CIM sessions are disposed in a finally on every path (P2 :292);
#    * operator Cancel is honoured via $Params['__job'] like all 16 peers (P2 :221);
#    * 'threads' REMOVED from the manifest + view - the DCOM loop is serial by design (P3 :246);
#    * DCOM requires TCP 135 (RPC EPM) and the CIM connect is time-boxed (P3 :253);
#    * a failed Start-ScheduledTask now reports PENDING (not BRIDGING) and the immediate
#      trigger is stamped in the TARGET's local time, not the dispatcher's (P3 :282);
#    * port label / revert-window floor honesty in the streamed rows (P4 :271/:283).
# =============================================================================

$script:WrbGroup       = 'JANET-WinRMBridge'
$script:WrbEnableTask  = 'JANET-WinRMBridge-Enable'
$script:WrbRevertTask  = 'JANET-WinRMBridge-Revert'
$script:WrbCertFriendly = 'JANET-WinRMBridge-Temp'
$script:WrbFwRule      = 'JANET-WinRMBridge-5986'

# --- Pure: the script that REVERTS the bridge (runs on the target as SYSTEM) ----
# Idempotent + fail-quiet: remove OUR HTTPS listener, the tagged firewall rule, the temp
# cert, then delete the scheduled tasks (itself last). audit 2026-07-25 (fable re-audit
# follow-up): only the LISTENER teardown may depend on the temp cert - see below.
function New-WinRmBridgeRevertScript {
    @"
`$ErrorActionPreference='SilentlyContinue'
# Our temp cert is what SCOPES the listener teardown: enable creates nothing when a foreign
# HTTPS listener already exists, so a listener bound to OUR thumbprint is provably ours and
# anything else on 5986 is somebody else's - we NEVER remove a production listener (audit P2).
`$myCert = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.FriendlyName -eq '$($script:WrbCertFriendly)' })
`$mine = @(`$myCert | ForEach-Object { ([string]`$_.Thumbprint -replace '[^0-9A-Fa-f]','').ToUpperInvariant() } | Where-Object { `$_ })

# audit 2026-07-25 (fable re-audit follow-up) - FAIL-OPEN, fixed: the ENTIRE teardown used to
# sit inside 'if (`$myCert.Count -gt 0)' while the schtasks deletes ran UNCONDITIONALLY. The
# temp cert is the weakest artifact on the box (1-day self-signed - a cert-hygiene sweep, a
# manual delete or a half-finished earlier revert removes it), and the moment it was gone the
# tasks deleted THEMSELVES while the listener and the group-tagged firewall rule stayed
# FOREVER - i.e. 5986 open with every revert path deleted, the worst outcome this tool has.
# The group tag and the task names are OURS - they prove ownership on their own - so the
# firewall-rule and task teardown must NOT depend on the cert. Only the listener stays
# thumbprint-scoped, and a listener we cannot positively attribute is reported, never ignored.
`$unattributed = New-Object System.Collections.ArrayList
foreach (`$l in @(Get-ChildItem WSMan:\localhost\Listener | Where-Object { `$_.Keys -contains 'Transport=HTTPS' })) {
    `$tp = ''
    `$tpRead = `$true
    try { `$tp = [string](@(Get-ChildItem -Path `$l.PSPath | Where-Object { `$_.Name -eq 'CertificateThumbprint' })[0].Value) } catch { `$tpRead = `$false }
    `$tp = (`$tp -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
    if (-not `$tp) { `$tpRead = `$false }
    if (`$tpRead -and (`$mine -contains `$tp)) {
        Get-Item -Path `$l.PSPath | Remove-Item -Recurse -Force
    } elseif (-not `$tpRead) {
        # audit 2026-07-25: an unreadable thumbprint used to be swallowed by 'catch {}' and the
        # listener SILENTLY skipped - while the cert, the rule and the tasks all went away,
        # leaving a listener with a dead cert and no revert path. Fail CLOSED: ours-or-unknown.
        [void]`$unattributed.Add(('{0} (CertificateThumbprint unreadable)' -f `$l.Name))
    } elseif (`$mine.Count -eq 0) {
        # No temp cert left to compare against: ownership can be neither proved nor disproved.
        # Do NOT remove it (it may be a production listener) and do NOT pretend it is gone.
        [void]`$unattributed.Add(('{0} (thumbprint {1}; our temp cert is gone - cannot attribute)' -f `$l.Name, `$tp))
    }
}

# Unconditional: no other tool writes our group tag, so the tag alone proves the rule is ours.
# Removing it also SHRINKS exposure when a listener had to be left behind above.
Remove-NetFirewallRule -Group '$($script:WrbGroup)'
if (`$myCert.Count -gt 0) { `$myCert | Remove-Item -Force }

schtasks.exe /delete /tn '$($script:WrbEnableTask)' /f
if (`$unattributed.Count -eq 0) {
    schtasks.exe /delete /tn '$($script:WrbRevertTask)' /f
    schtasks.exe /delete /tn '$($script:WrbRevertTask)-Force' /f
} else {
    # LOUD, and armed: keep the standing revert task (at-startup + timed) so this host still has
    # a revert path AND still reports as a JANET bridge in Check - the alternative (self-delete)
    # is exactly the silent orphan this fix exists to kill. Only the one-shot -Force task goes.
    `$msg = 'JANET-WinRMBridge revert could not attribute ' + `$unattributed.Count + ' HTTPS listener(s): ' + (`$unattributed -join '; ') + '. LEFT IN PLACE (they may be production); temp firewall rule + cert removed; the revert task is deliberately LEFT ARMED so this host keeps a revert path and still reports as a bridge leftover.'
    `$msg | Out-Host
    try {
        # SourceExists itself throws for a caller that cannot enumerate every log (it walks the
        # Security log too) - that must not cost us the entry, so it gets its own catch.
        `$srcOk = `$false
        try { `$srcOk = [System.Diagnostics.EventLog]::SourceExists('$($script:WrbGroup)') } catch { `$srcOk = `$false }
        if (-not `$srcOk) { New-EventLog -LogName Application -Source '$($script:WrbGroup)' }
        Write-EventLog -LogName Application -Source '$($script:WrbGroup)' -EntryType Error -EventId 5986 -Message `$msg
    } catch {}
    schtasks.exe /delete /tn '$($script:WrbRevertTask)-Force' /f
}
"@
}

# --- Pure: the script that ENABLES the bridge (runs on the target as SYSTEM) -----
# REVERT-FIRST: registers the self-revert task (at-startup + now+N min, target clock)
# BEFORE standing up any listener. Then a short-lived self-signed cert + HTTPS
# listener + tagged firewall rule. Finally deletes its own (enable) task.
function New-WinRmBridgeEnableScript {
    param(
        [int]$RevertMinutes = 90,
        [Parameter(Mandatory)][string]$RevertEncoded,
        # audit 2026-07-24 (P2): the source address(es) the temp rule is scoped to - the JANET
        # dispatcher's own IPv4s. Empty (nothing resolvable) still gets the Domain-profile
        # clamp; the engine logs a warning so the operator knows the rule is wider.
        [string[]]$RemoteAddress = @(),
        [ValidateSet('Domain','Domain,Private','Any')][string]$FirewallProfile = 'Domain'
    )
    if ($RevertMinutes -lt 5) { $RevertMinutes = 5 }
    # Scope literal is BUILT here (not passed through as data) so it lands in the generated
    # script as a fixed argument list. Only IPv4/CIDR characters survive Select-...ScopeAddress,
    # so nothing operator-supplied can ever be spliced into the remote command line.
    $addrOk  = @(Select-WinRmBridgeScopeAddress -Address $RemoteAddress)
    $fwScope = "-Profile $FirewallProfile"
    if ($addrOk.Count -gt 0) { $fwScope += " -RemoteAddress @('" + ($addrOk -join "','") + "')" }
    @"
`$ErrorActionPreference='Stop'
`$dns = ([System.Net.Dns]::GetHostByName(`$env:COMPUTERNAME)).HostName

# 1) ARM THE REVERT FIRST (target's own clock): at-startup AND now+$RevertMinutes min.
`$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $RevertEncoded'
`$t1 = New-ScheduledTaskTrigger -AtStartup
`$t2 = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($RevertMinutes))
`$pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName '$($script:WrbRevertTask)' -Action `$act -Trigger `$t1,`$t2 -Principal `$pr -Force | Out-Null

# 2+3) NEVER destroy a pre-existing HTTPS listener. If one already exists the box already has
#      WinRM-over-HTTPS - leave it and create NOTHING (no bridge needed). Otherwise stand up OUR
#      short-lived self-signed cert (its presence is how revert knows the bridge is ours) + the
#      listener + a tagged firewall rule (audit P2).
`$existingHttps = @(Get-ChildItem WSMan:\localhost\Listener | Where-Object { `$_.Keys -contains 'Transport=HTTPS' })
if (`$existingHttps.Count -gt 0) {
    'JANET-WinRMBridge: a pre-existing HTTPS listener is present - left untouched; no bridge created.' | Out-Host
} else {
    `$cert = New-SelfSignedCertificate -DnsName `$dns -CertStoreLocation Cert:\LocalMachine\My -FriendlyName '$($script:WrbCertFriendly)' -NotAfter (Get-Date).AddDays(1)
    # -Address * stays: the target's NIC layout is unknown from here, and a wrong -Address
    # literal would bind nothing at all. The FIREWALL rule below is the scoping control.
    New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS -CertificateThumbPrint `$cert.Thumbprint -HostName `$dns -Force | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName '$($script:WrbFwRule)' -ErrorAction SilentlyContinue)) {
        # audit 2026-07-24 (P2): this rule used to be Any profile / Any remote address / Any
        # interface - i.e. the bridge briefly published 5986 to every network the box can see,
        # including a hotel/tether Public network. Only the JANET dispatcher ever needs to
        # reach this port, and only on the Domain profile, so scope it to both. Narrower scope
        # is also why the window can stay open the full N minutes without widening exposure.
        New-NetFirewallRule -DisplayName '$($script:WrbFwRule)' -Group '$($script:WrbGroup)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow $fwScope | Out-Null
    }
}

# 4) remove our own (enable) task - the revert task remains armed
schtasks.exe /delete /tn '$($script:WrbEnableTask)' /f | Out-Null
"@
}

# --- Pure: UTF-16LE base64 for powershell.exe -EncodedCommand -------------------
function ConvertTo-WinRmBridgeEncoded {
    param([Parameter(Mandatory)][string]$Script)
    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Script))
}

# --- Pure: dispatcher self-identity (short/FQDN/DNS + bound-NIC IPv4 + loopback) --
# Bound-NIC enumeration (parity with restart/winupgrade/acas) so a pasted OOB/mgmt-NIC
# IP literal that DNS does not know still counts as self (audit P3).
function Get-WinRmBridgeLocalIdentity {
    if ($script:WrbLocalIdentity) { return ,$script:WrbLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) } } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            try {
                if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
                foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                    if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
                }
            } catch {}
        }
    } catch {}
    $script:WrbLocalIdentity = $set; return ,$set
}

# --- Pure: self-guard - never bridge the dispatcher/local host -----------------
function Test-WinRmBridgeSelfTarget {
    param([string]$Computer)
    $c = ([string]$Computer).Trim()
    if (-not $c) { return $true }
    if ($c -in @('localhost','127.0.0.1','::1','.')) { return $true }
    if ($c -match '^127\.') { return $true }
    $self = Get-WinRmBridgeLocalIdentity
    if ($self.Contains($c)) { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($c, [ref]$ip)) { if ($self.Contains(($c -split '\.')[0])) { return $true } }
    return $false
}

# --- Pure: valid hostname / IPv4 token (same charset gate as the rest of the suite) --
# Rejects UNC fragments, switches, pipes, spaces before a token reaches New-CimSession (audit P3).
function Test-WinRmBridgeHostToken {
    param([string]$Token)
    return ([string]$Token) -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$'
}

# --- Pure: firewall-scope address filter (audit 2026-07-24 P2) ------------------
# Keeps only addresses that can actually be the SOURCE of a bridge connection and that are
# safe to splice into the generated remote script: real IPv4 literals (optionally /nn), never
# loopback (can never arrive from the wire) and never APIPA (169.254/16 - a link-local address
# would silently widen/void the rule). Anything else is dropped rather than sanitized.
function Select-WinRmBridgeScopeAddress {
    param([string[]]$Address = @())
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @($Address)) {
        $t = ([string]$a).Trim()
        if (-not $t) { continue }
        if ($t -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { continue }   # IPv4 or IPv4/CIDR only
        $bare = ($t -split '/')[0]
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($bare, [ref]$ip)) { continue }
        if ($bare -like '127.*' -or $bare -like '169.254.*' -or $bare -eq '0.0.0.0') { continue }
        if ($out -notcontains $t) { [void]$out.Add($t) }
    }
    # NO unary comma here (unlike the identity HashSet): callers want a flat string[] they
    # can join into the generated rule - an extra wrap would splice 'System.Object[]'.
    return @($out.ToArray())
}

# --- Pure-ish: the dispatcher's own routable IPv4 set (the only legitimate source) ---
# Reuses the self-identity cache (same NIC enumeration the self-guard uses), then filters it
# down to addresses a target could actually see us from (audit 2026-07-24 P2).
function Get-WinRmBridgeDispatcherAddress {
    # Get-WinRmBridgeLocalIdentity hands back the HashSet ITSELF (unary-comma contract, so the
    # OrdinalIgnoreCase comparer survives) - enumerate it, never @()-wrap it, or the whole set
    # arrives as one object and every address is silently dropped.
    $ids = New-Object System.Collections.ArrayList
    try { foreach ($a in (Get-WinRmBridgeLocalIdentity)) { [void]$ids.Add([string]$a) } } catch {}
    return @(Select-WinRmBridgeScopeAddress -Address @($ids.ToArray()))
}

# --- Pure: the CHECK verdict (audit 2026-07-24 P2 :268 / P3 :166) ---------------
# The old check called a bridge ACTIVE purely because a revert TASK existed - a task can sit
# there long after its listener is gone (or before enable finishes), so the column lied in both
# directions. The verdict now needs the 5986 probe as well, and it finally emits the LEFTOVER
# state the manifest/registry/view have always advertised:
#   ACTIVE   - our task is armed AND 5986 answers AND the timed revert is still in the future
#   LEFTOVER - 5986 answers but the timed revert has already come and gone (bridge outlived
#              its window - the thing the operator is actually hunting for)
#   ARMED    - our task is present but nothing is listening (reverted already / mid-enable)
#   REVIEW   - 5986 answers but no JANET task: EITHER a legitimate production listener OR a
#              bridge leftover whose tasks are already gone (audit 2026-07-25 - see below)
#   none     - no JANET bridge task and nothing on 5986
# $TargetNow is the TARGET's clock (never the dispatcher's) so skew cannot fake a LEFTOVER.
function Get-WinRmBridgeCheckState {
    param(
        [bool]$Https5986,
        [bool]$TaskPresent,
        $NextRunTime,
        [datetime]$TargetNow = (Get-Date)
    )
    $nrt = $null
    if ($NextRunTime -and ($NextRunTime -isnot [string] -or [string]$NextRunTime)) {
        try { $nrt = [datetime]$NextRunTime } catch { $nrt = $null }
    }
    $reverts = if ($nrt) { $nrt.ToString('yyyy-MM-dd HH:mm') } else { 'at next startup' }
    if (-not $TaskPresent) {
        # audit 2026-07-25 (fable re-audit follow-up): 'not ours; left alone' MASKED the exact
        # wreckage the old fail-open revert produced - tasks self-deleted, listener + firewall
        # rule left behind - and reported it as an OK (st-ok 'none') row. We cannot attribute a
        # listener without our task, so we must not claim it is somebody else's either: surface
        # it as REVIEW (warn) and let the operator decide. Nothing is touched either way.
        if ($Https5986) {
            return @{ State='REVIEW'; Reverts='-'; Detail='5986 is listening but NO JANET bridge task is present - either a legitimate production listener or a bridge leftover whose tasks are already gone; nothing was touched - verify this host manually' }
        }
        return @{ State='none'; Reverts='-'; Detail='no JANET bridge task present; 5986 closed' }
    }
    if (-not $Https5986) {
        return @{ State='ARMED'; Reverts=$reverts; Detail="revert task armed but 5986 is NOT listening (already reverted, or enable still running); reverts $reverts" }
    }
    if (-not $nrt -or $nrt -lt $TargetNow) {
        # No future timed run left (only the at-startup trigger) or it is already overdue,
        # yet the listener is still up: the window has lapsed - flag it for a forced Revert.
        return @{ State='LEFTOVER'; Reverts=$reverts; Detail="LEFTOVER: 5986 still listening past the timed revert ($reverts) - run Revert (force)" }
    }
    return @{ State='ACTIVE'; Reverts=$reverts; Detail="bridge up (5986 listening); reverts $reverts (target clock)" }
}

# --- Pure: build the enable payload once (revert encoded INTO the enable script) -
function Get-WinRmBridgePayload {
    param([int]$RevertMinutes = 90, [string[]]$RemoteAddress = @())
    $revertEnc = ConvertTo-WinRmBridgeEncoded (New-WinRmBridgeRevertScript)
    $enableSrc = New-WinRmBridgeEnableScript -RevertMinutes $RevertMinutes -RevertEncoded $revertEnc -RemoteAddress $RemoteAddress
    @{ RevertScript = (New-WinRmBridgeRevertScript); EnableScript = $enableSrc; EnableEncoded = (ConvertTo-WinRmBridgeEncoded $enableSrc); RevertEncoded = $revertEnc }
}

# =============================================================================
#  Tool contract + remote-exec engine (below the pure core).
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'winrmbridge'
        name     = 'WinRM Bridge'
        version  = '0.2.1'
        category = 'Operations'
        summary  = 'Stand up a TEMPORARY, self-reverting WinRM-over-HTTPS (5986) channel on hosts whose WinRM is GPO-blocked, so the rest of JANET can push patches without waiting on a GPO refresh. Bootstraps over DCOM (no WinRM needed) as a SYSTEM scheduled task that arms its own revert FIRST (at-startup + N minutes) then opens the listener. Designed to run server-side under a SERVICE ACCOUNT with local admin on the targets. Check (read-only) surfaces any leftover bridges; Revert forces cleanup. GPO stays authoritative; this is a documented stopgap.'
        actions  = @(
            @{
                id='check'; label='Check Bridge State'; kind='stream-table'; destructive=$false
                description='Read-only: probe WinRM HTTP 5985 / HTTPS 5986 and (over DCOM) report any JANET WinRM Bridge task present + when it reverts. Flags LEFTOVER bridges (5986 still listening past their revert window) and REVIEW hosts (5986 listening with no JANET task - unattributable, possibly a leftover whose tasks are gone).'
                columns=@('Host','Ping','Bridge','Reverts','Detail')
                # audit 2026-07-24 (P3): 'threads' was declared here and posted by the view but
                # never read - the DCOM loop is and stays SERIAL (see Invoke-JanetToolAction),
                # so advertising a knob that does nothing was a lie. Removed from manifest+view.
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true }
                )
            },
            @{
                id='enable'; label='Enable WinRM Bridge'; kind='stream-table'; destructive=$true
                description='DESTRUCTIVE: push a SYSTEM task over DCOM that arms a self-revert then opens a temporary 5986 HTTPS listener + a firewall rule scoped to the JANET dispatcher on the Domain profile. Service account needs local admin on the targets.'
                columns=@('Host','Ping','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='revertMinutes'; label='Auto-revert after (minutes)'; type='int'; required=$false; default=90 },
                    @{ name='confirm'; label='Type ENABLE to arm'; type='text'; required=$true }
                )
            },
            @{
                id='revert'; label='Revert WinRM Bridge (force)'; kind='stream-table'; destructive=$true
                description='DESTRUCTIVE: force-remove the bridge NOW (listener + firewall rule + temp cert + tasks) over DCOM, without waiting for the auto-revert. Use to clean up leftovers.'
                columns=@('Host','Ping','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='confirm'; label='Type REVERT to arm'; type='text'; required=$true }
                )
            }
        )
    }
}

# Single TCP port probe (pure-TCP, never ICMP - ICMP is dropped on AFNET).
function Test-WrbPort {
    param([string]$Computer, [int]$Port, [int]$TimeoutMs = 1500)
    $tc = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tc.BeginConnect($Computer, $Port, $null, $null)
        return ([bool]($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected))
    } catch { return $false } finally { try { $tc.Close() } catch {} }
}

# Per-port reachability map. audit 2026-07-24 (P2 :268 / P3 :253): the old single-label
# probe short-circuited on the FIRST open port, so the engine could not tell "5986 is up"
# from "only 445 answered" - which is exactly what check needed to stop guessing, and what
# enable/revert needed to stop attempting DCOM on a box with no RPC endpoint mapper.
function Get-WrbPortMap {
    param([string]$Computer, [int[]]$Ports = @(5985,5986,135,445), [int]$TimeoutMs = 1500)
    $map = [ordered]@{}
    foreach ($p in $Ports) { $map["$p"] = (Test-WrbPort -Computer $Computer -Port $p -TimeoutMs $TimeoutMs) }
    return $map
}

# First open port label ('TCP 5985') or '' - the Ping column's value, derived from the map.
function Get-WrbPortLabel {
    param($PortMap)
    if (-not $PortMap) { return '' }
    foreach ($k in $PortMap.Keys) { if ($PortMap[$k]) { return "TCP $k" } }
    return ''
}

# DCOM CIM session to a host (works when WinRM is down). Caller disposes.
# audit 2026-07-24 (P3): time-box the connect/operation. An untimed DCOM connect to a
# filtered/wedged host blocks the whole SERIAL loop on the RPC default (can be minutes).
function New-WrbDcomSession {
    param([string]$Computer, $Credential, [int]$TimeoutSec = 30)
    $opt = New-CimSessionOption -Protocol Dcom
    $sp = @{ ComputerName=$Computer; SessionOption=$opt; OperationTimeoutSec=$TimeoutSec; ErrorAction='Stop' }
    if ($Credential -is [System.Management.Automation.PSCredential]) { $sp['Credential'] = $Credential }
    New-CimSession @sp
}

# The TARGET's own local time (audit 2026-07-24 P3): scheduled-task triggers are stamped in
# the TARGET's local time, so a trigger built from the DISPATCHER's clock fires early/late by
# the full skew (or timezone) between the two boxes. Falls back to our clock if the query fails.
function Get-WrbTargetTime {
    param($CimSession)
    try {
        $os = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os -and $os.LocalDateTime) { return [datetime]$os.LocalDateTime }
    } catch {}
    return (Get-Date)
}

function Invoke-JanetToolAction {
    param([string]$ActionId, [hashtable]$Params, $Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel contract (audit 2026-07-24 P2): the server injects a synchronized
    # hashtable as $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) is how
    # every other engine (16/16) stops a fan-out. This module never read it, so the Cancel
    # button was a no-op on a run that pushes SYSTEM tasks to a whole target list. The loop
    # below is SERIAL, so a between-host check is a clean cut point: each host is one atomic
    # register+start, so we never leave a half-pushed bridge behind.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    $rawTargets = @(([string]$Params['targets'] -split '[\r\n,; ]+') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $targets = @($rawTargets | Where-Object { Test-WinRmBridgeHostToken $_ })
    $badTargets = @($rawTargets | Where-Object { -not (Test-WinRmBridgeHostToken $_) })
    if ($badTargets.Count -gt 0) { & $send @{ type='log'; level='warn'; text="Dropped $($badTargets.Count) invalid target token(s) (not a valid hostname/IP) before any DCOM call: $($badTargets -join ', ')" } }
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    if ($ActionId -in @('enable','revert')) {
        $want = if ($ActionId -eq 'enable') { 'ENABLE' } else { 'REVERT' }
        if ([string]$Params['confirm'] -cne $want) {
            & $send @{ type='log'; level='err'; text="Refused: type $want (exactly) in Confirm to arm this action." }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
    }

    # audit 2026-07-25 (fable re-audit follow-up): this was [int]("0" + [string]$Params['...']),
    # which THROWS on any non-numeric value ('90 min', 'ninety') - a raw cast exception out of the
    # engine instead of an operator-readable refusal. It failed closed (nothing was touched yet),
    # so this is cosmetic-but-clean: parse explicitly and refuse with a sentence. A blank/absent
    # value keeps the documented default; it is never silently defaulted from garbage.
    $revertMinutes = 90
    $rawRevert = [string]$Params['revertMinutes']
    if (-not [string]::IsNullOrWhiteSpace($rawRevert)) {
        $parsedRevert = 0
        if (-not [int]::TryParse($rawRevert.Trim(), [ref]$parsedRevert)) {
            & $send @{ type='log'; level='err'; text="Refused: 'Auto-revert after (minutes)' must be a whole number of minutes - got '$rawRevert'." }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        $revertMinutes = $parsedRevert
    }
    if ($revertMinutes -le 0) { $revertMinutes = 90 }
    # audit 2026-07-24 (P4): the PAYLOAD floors the window at 5 minutes, but the streamed row
    # printed the operator's raw number - a run asked for 2 minutes was armed for 5 and told
    # the operator 2. Floor here too so the row states the window that is actually armed.
    if ($revertMinutes -lt 5) { $revertMinutes = 5 }

    # audit 2026-07-24 (P2): resolve the source address(es) the temp 5986 rule will be scoped
    # to BEFORE building the payload, and say so in the log - an operator must be able to see
    # how wide the hole is. No routable dispatcher IPv4 -> Domain-profile clamp only, loudly.
    $scopeAddr = @()
    if ($ActionId -eq 'enable') {
        $scopeAddr = @(Get-WinRmBridgeDispatcherAddress)
        if ($scopeAddr.Count -gt 0) {
            & $send @{ type='log'; level='info'; text="Temp 5986 firewall rule will be scoped to the Domain profile and RemoteAddress $($scopeAddr -join ', ') (this dispatcher only)." }
        } else {
            & $send @{ type='log'; level='warn'; text='No routable dispatcher IPv4 could be resolved - the temp 5986 rule will be clamped to the Domain profile but NOT to a single source address.' }
        }
    }
    $payload = if ($ActionId -eq 'enable') { Get-WinRmBridgePayload -RevertMinutes $revertMinutes -RemoteAddress $scopeAddr } else { $null }
    # audit 2026-07-23: the encoded revert script is only pushed by the 'revert'
    # task registration below - don't build/encode it for the read-only 'check'
    # (enable carries its own copy inside $payload and never reads $revertEnc).
    $revertEnc = if ($ActionId -eq 'revert') { ConvertTo-WinRmBridgeEncoded (New-WinRmBridgeRevertScript) } else { $null }

    # Audit action ids are pinned by the engine's ValidateSet (TouchHost / VulnPatched) - see
    # server\JanetWeb.Logging.ps1:426. audit 2026-07-24 (P2): this module emitted
    # 'WinRmBridge-<action>', which the server rejects, so EVERY enable/revert audit row was
    # dropped - a tool that opens a network listener was writing nothing to the ledger. Opening
    # or tearing down a bridge is a host TOUCH (no vulnerability is patched), so: TouchHost,
    # with the bridge action carried in the detail text where it is still searchable.
    $auditOf = {
        param($TargetHost, $Result, $ItemCount, $Detail)
        & $send @{ type='audit'; action='TouchHost'; target=$TargetHost; result=$Result; itemCount=[int]$ItemCount; detail=("winrmbridge/$ActionId - " + [string]$Detail) }
    }

    $rows = New-Object System.Collections.ArrayList
    $n = 0
    $cancelled = $false
    foreach ($h in $targets) {
        # Cooperative cancel between hosts (see the __job contract above).
        if (& $cancelCheck) {
            $cancelled = $true
            & $send @{ type='log'; level='warn'; text="Cancelled by operator after $n of $($targets.Count) host(s) - remaining target(s) were NOT touched." }
            break
        }
        $n++
        & $send @{ type='progress'; done=$n; total=$targets.Count }
        if (Test-WinRmBridgeSelfTarget $h) {
            $row = @{ Host=$h; Ping=''; Status='SKIPPED'; Bridge='-'; Reverts='-'; Detail='self/dispatcher host - never bridged' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
        }
        $ports = Get-WrbPortMap -Computer $h
        $ping  = Get-WrbPortLabel $ports
        if (-not $ping) {
            $row = @{ Host=$h; Ping='unreachable'; Status='OFFLINE'; Bridge='?'; Reverts='-'; Detail='no TCP on 5985/5986/135/445' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
        }
        $probe = "5985=$(if($ports['5985']){'open'}else{'closed'}) 5986=$(if($ports['5986']){'open'}else{'closed'}) 135=$(if($ports['135']){'open'}else{'closed'})"

        # audit 2026-07-24 (P3): DCOM/WMI rides the RPC endpoint mapper on TCP 135. The old
        # gate accepted ANY of the four ports, so a host answering only on 445 (or on 5985)
        # still got a DCOM attempt that could only fail - slowly, and with a misleading error.
        if (-not $ports['135']) {
            $st = if ($ActionId -eq 'check') { $null } else { 'NO-DCOM' }
            $row = @{ Host=$h; Ping=$ping; Bridge='UNKNOWN'; Reverts='-'; Detail="RPC endpoint mapper (TCP 135) closed - DCOM bootstrap not possible; $probe" }
            if ($st) { $row['Status'] = $st }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            continue   # nothing was touched -> no audit row
        }

        # ONE session per host, always disposed. audit 2026-07-24 (P2): every failure path used
        # to skip Remove-CimSession (it sat after the throwing calls), leaking a DCOM session
        # per failed host for the life of the job.
        $cim = $null
        try {
            if ($ActionId -eq 'check') {
                $cim = New-WrbDcomSession -Computer $h -Credential $Credential
                $rt   = Get-ScheduledTask -CimSession $cim -TaskName $script:WrbRevertTask -ErrorAction SilentlyContinue
                $info = if ($rt) { Get-ScheduledTaskInfo -CimSession $cim -TaskName $script:WrbRevertTask -ErrorAction SilentlyContinue } else { $null }
                # audit 2026-07-24 (P2): the verdict now needs the 5986 probe, not just the
                # task's existence, and it is judged against the TARGET's clock.
                $v = Get-WinRmBridgeCheckState -Https5986 ([bool]$ports['5986']) -TaskPresent ([bool]$rt) `
                        -NextRunTime $(if ($info) { $info.NextRunTime } else { $null }) -TargetNow (Get-WrbTargetTime -CimSession $cim)
                $row = @{ Host=$h; Ping=$ping; Bridge=$v.State; Reverts=$v.Reverts; Detail="$($v.Detail); $probe" }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
            }

            $cim = New-WrbDcomSession -Computer $h -Credential $Credential
            # audit 2026-07-24 (P3): stamp the immediate trigger in the TARGET's local time -
            # a trigger built from OUR clock is off by the full skew/timezone delta.
            $startAt = (Get-WrbTargetTime -CimSession $cim).AddSeconds(30)
            $taskName = if ($ActionId -eq 'enable') { $script:WrbEnableTask } else { $script:WrbRevertTask + '-Force' }
            $enc      = if ($ActionId -eq 'enable') { $payload.EnableEncoded } else { $revertEnc }
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + $enc)
            $trg = New-ScheduledTaskTrigger -Once -At $startAt
            $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -CimSession $cim -TaskName $taskName -Action $act -Trigger $trg -Principal $pr -Force | Out-Null
            # audit 2026-07-24 (P3): a swallowed Start failure used to still report BRIDGING /
            # REVERTING. The task IS registered and its own trigger will fire, so this is not a
            # failure - but it is not confirmed running either: report PENDING and audit Skipped.
            $started = $true; $startErr = ''
            try { Start-ScheduledTask -CimSession $cim -TaskName $taskName -ErrorAction Stop }
            catch { $started = $false; $startErr = $_.Exception.Message }

            if ($ActionId -eq 'enable') {
                $scopeTxt = if ($scopeAddr.Count -gt 0) { "5986 scoped to $($scopeAddr -join ',') / Domain profile" } else { '5986 scoped to the Domain profile' }
                $row = if ($started) { @{ Host=$h; Ping=$ping; Status='BRIDGING'; Detail="enable task pushed ($scopeTxt; reverts in $revertMinutes min + at startup); verify 5986 shortly" } }
                       else          { @{ Host=$h; Ping=$ping; Status='PENDING';  Detail="enable task REGISTERED but immediate start failed ($startErr) - it fires on its own trigger at $($startAt.ToString('HH:mm:ss')) target time; $scopeTxt" } }
            } else {
                $row = if ($started) { @{ Host=$h; Ping=$ping; Status='REVERTING'; Detail='revert task pushed (removes OUR listener + firewall rule + temp cert + tasks; a listener it cannot attribute is LEFT and reported, with the revert task kept armed)' } }
                       else          { @{ Host=$h; Ping=$ping; Status='PENDING';   Detail="revert task REGISTERED but immediate start failed ($startErr) - it fires on its own trigger at $($startAt.ToString('HH:mm:ss')) target time" } }
            }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            if (-not $started) { & $send @{ type='log'; level='warn'; text="[$h] $ActionId task registered but Start-ScheduledTask failed: $startErr" } }
            & $auditOf $h $(if ($started) { 'Success' } else { 'Skipped' }) $(if ($started) { 1 } else { 0 }) $row.Detail
        } catch {
            $st = if ($ActionId -eq 'check') { 'UNKNOWN' } else { 'FAILED' }
            $detail = if ($ActionId -eq 'check') { "$ping reachable but DCOM query failed: $($_.Exception.Message)" } else { "DCOM/task error: $($_.Exception.Message)" }
            $row = @{ Host=$h; Ping=$ping; Status=$st; Bridge=$st; Reverts='-'; Detail=$detail }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            # check is read-only: a failed READ is not a host touch, so it stays out of the ledger.
            if ($ActionId -ne 'check') { & $auditOf $h 'Failure' 0 $row.Detail }
        } finally {
            if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
        }
    }

    & $send @{ type='status'; text="Done. $($rows.Count) host(s)$(if ($cancelled) { ' (cancelled - ' + ($targets.Count - $rows.Count) + ' not attempted)' })." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; action=$ActionId; cancelled=$cancelled } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, New-WinRmBridgeRevertScript, New-WinRmBridgeEnableScript, ConvertTo-WinRmBridgeEncoded, Test-WinRmBridgeSelfTarget, Test-WinRmBridgeHostToken, Get-WinRmBridgeLocalIdentity, Get-WinRmBridgePayload, Select-WinRmBridgeScopeAddress, Get-WinRmBridgeDispatcherAddress, Get-WinRmBridgeCheckState, Get-WrbPortLabel
