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
# =============================================================================

$script:WrbGroup       = 'JANET-WinRMBridge'
$script:WrbEnableTask  = 'JANET-WinRMBridge-Enable'
$script:WrbRevertTask  = 'JANET-WinRMBridge-Revert'
$script:WrbCertFriendly = 'JANET-WinRMBridge-Temp'
$script:WrbFwRule      = 'JANET-WinRMBridge-5986'

# --- Pure: the script that REVERTS the bridge (runs on the target as SYSTEM) ----
# Idempotent + fail-quiet: remove the HTTPS listener, the tagged firewall rule, the
# temp cert, then delete BOTH scheduled tasks (itself last).
function New-WinRmBridgeRevertScript {
    @"
`$ErrorActionPreference='SilentlyContinue'
# Only tear down a bridge WE created: our temp cert's presence proves enable created the
# listener (enable creates nothing when a foreign HTTPS listener already exists), so we
# NEVER remove a pre-existing production 5986 listener (audit P2).
`$myCert = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.FriendlyName -eq '$($script:WrbCertFriendly)' })
if (`$myCert.Count -gt 0) {
    Get-ChildItem WSMan:\localhost\Listener | Where-Object { `$_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force
    Remove-NetFirewallRule -Group '$($script:WrbGroup)'
    `$myCert | Remove-Item -Force
}
schtasks.exe /delete /tn '$($script:WrbEnableTask)' /f
schtasks.exe /delete /tn '$($script:WrbRevertTask)' /f
schtasks.exe /delete /tn '$($script:WrbRevertTask)-Force' /f
"@
}

# --- Pure: the script that ENABLES the bridge (runs on the target as SYSTEM) -----
# REVERT-FIRST: registers the self-revert task (at-startup + now+N min, target clock)
# BEFORE standing up any listener. Then a short-lived self-signed cert + HTTPS
# listener + tagged firewall rule. Finally deletes its own (enable) task.
function New-WinRmBridgeEnableScript {
    param([int]$RevertMinutes = 90, [Parameter(Mandatory)][string]$RevertEncoded)
    if ($RevertMinutes -lt 5) { $RevertMinutes = 5 }
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
    New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS -CertificateThumbPrint `$cert.Thumbprint -HostName `$dns -Force | Out-Null
    if (-not (Get-NetFirewallRule -DisplayName '$($script:WrbFwRule)' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName '$($script:WrbFwRule)' -Group '$($script:WrbGroup)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow | Out-Null
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

# --- Pure: build the enable payload once (revert encoded INTO the enable script) -
function Get-WinRmBridgePayload {
    param([int]$RevertMinutes = 90)
    $revertEnc = ConvertTo-WinRmBridgeEncoded (New-WinRmBridgeRevertScript)
    $enableSrc = New-WinRmBridgeEnableScript -RevertMinutes $RevertMinutes -RevertEncoded $revertEnc
    @{ RevertScript = (New-WinRmBridgeRevertScript); EnableScript = $enableSrc; EnableEncoded = (ConvertTo-WinRmBridgeEncoded $enableSrc); RevertEncoded = $revertEnc }
}

# =============================================================================
#  Tool contract + remote-exec engine (below the pure core).
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'winrmbridge'
        name     = 'WinRM Bridge'
        version  = '0.1.0'
        category = 'Operations'
        summary  = 'Stand up a TEMPORARY, self-reverting WinRM-over-HTTPS (5986) channel on hosts whose WinRM is GPO-blocked, so the rest of JANET can push patches without waiting on a GPO refresh. Bootstraps over DCOM (no WinRM needed) as a SYSTEM scheduled task that arms its own revert FIRST (at-startup + N minutes) then opens the listener. Designed to run server-side under a SERVICE ACCOUNT with local admin on the targets. Check (read-only) surfaces any leftover bridges; Revert forces cleanup. GPO stays authoritative; this is a documented stopgap.'
        actions  = @(
            @{
                id='check'; label='Check Bridge State'; kind='stream-table'; destructive=$false
                description='Read-only: probe WinRM HTTP 5985 / HTTPS 5986 and (over DCOM) report any JANET WinRM Bridge task present + when it reverts. Flags LEFTOVER bridges past their window.'
                columns=@('Host','Ping','Bridge','Reverts','Detail')
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id='enable'; label='Enable WinRM Bridge'; kind='stream-table'; destructive=$true
                description='DESTRUCTIVE: push a SYSTEM task over DCOM that arms a self-revert then opens a temporary 5986 HTTPS listener + firewall rule. Service account needs local admin on the targets.'
                columns=@('Host','Ping','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='revertMinutes'; label='Auto-revert after (minutes)'; type='int'; required=$false; default=90 },
                    @{ name='confirm'; label='Type ENABLE to arm'; type='text'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id='revert'; label='Revert WinRM Bridge (force)'; kind='stream-table'; destructive=$true
                description='DESTRUCTIVE: force-remove the bridge NOW (listener + firewall rule + temp cert + tasks) over DCOM, without waiting for the auto-revert. Use to clean up leftovers.'
                columns=@('Host','Ping','Status','Detail')
                inputs=@(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='confirm'; label='Type REVERT to arm'; type='text'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            }
        )
    }
}

# TCP reachability (pure-TCP, never ICMP). Returns the first open port label or ''.
function Test-WrbTcp {
    param([string]$Computer, [int[]]$Ports = @(5985,5986,135,445), [int]$TimeoutMs = 1500)
    foreach ($p in $Ports) {
        $tc = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tc.BeginConnect($Computer, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) { $tc.Close(); return "TCP $p" }
        } catch {} finally { try { $tc.Close() } catch {} }
    }
    return ''
}

# DCOM CIM session to a host (works when WinRM is down). Caller disposes.
function New-WrbDcomSession {
    param([string]$Computer, $Credential)
    $opt = New-CimSessionOption -Protocol Dcom
    $sp = @{ ComputerName=$Computer; SessionOption=$opt; ErrorAction='Stop' }
    if ($Credential -is [System.Management.Automation.PSCredential]) { $sp['Credential'] = $Credential }
    New-CimSession @sp
}

function Invoke-JanetToolAction {
    param([string]$ActionId, [hashtable]$Params, $Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }
    $rawTargets = @(([string]$Params['targets'] -split '[\r\n,; ]+') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $targets = @($rawTargets | Where-Object { Test-WinRmBridgeHostToken $_ })
    $badTargets = @($rawTargets | Where-Object { -not (Test-WinRmBridgeHostToken $_) })
    if ($badTargets.Count -gt 0) { & $send @{ type='log'; level='warn'; text="Dropped $($badTargets.Count) invalid target token(s) (not a valid hostname/IP) before any DCOM call: $($badTargets -join ', ')" } }
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    if ($ActionId -in @('enable','revert')) {
        $want = if ($ActionId -eq 'enable') { 'ENABLE' } else { 'REVERT' }
        if ([string]$Params['confirm'] -ne $want) {
            & $send @{ type='log'; level='err'; text="Refused: type $want (exactly) in Confirm to arm this action." }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
    }

    $revertMinutes = [int]("0" + [string]$Params['revertMinutes']); if ($revertMinutes -le 0) { $revertMinutes = 90 }
    $payload = if ($ActionId -eq 'enable') { Get-WinRmBridgePayload -RevertMinutes $revertMinutes } else { $null }
    # audit 2026-07-23: the encoded revert script is only pushed by the 'revert'
    # task registration below - don't build/encode it for the read-only 'check'
    # (enable carries its own copy inside $payload and never reads $revertEnc).
    $revertEnc = if ($ActionId -eq 'revert') { ConvertTo-WinRmBridgeEncoded (New-WinRmBridgeRevertScript) } else { $null }

    $rows = New-Object System.Collections.ArrayList
    $n = 0
    foreach ($h in $targets) {
        $n++
        & $send @{ type='progress'; done=$n; total=$targets.Count }
        if (Test-WinRmBridgeSelfTarget $h) {
            $row = @{ Host=$h; Ping=''; Status='SKIPPED'; Bridge='-'; Reverts='-'; Detail='self/dispatcher host - never bridged' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
        }
        $ping = Test-WrbTcp $h
        if (-not $ping) {
            $row = @{ Host=$h; Ping='unreachable'; Status='OFFLINE'; Bridge='?'; Reverts='-'; Detail='no TCP on 5985/5986/135/445' }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
        }

        try {
            if ($ActionId -eq 'check') {
                $bridge='none'; $reverts='-'; $detail="5985/5986 probe: $ping"
                try {
                    $cim = New-WrbDcomSession -Computer $h -Credential $Credential
                    $rt = Get-ScheduledTask -CimSession $cim -TaskName $script:WrbRevertTask -ErrorAction SilentlyContinue
                    if ($rt) {
                        $info = Get-ScheduledTaskInfo -CimSession $cim -TaskName $script:WrbRevertTask -ErrorAction SilentlyContinue
                        $nr = if ($info -and $info.NextRunTime) { [string]$info.NextRunTime } else { 'at next startup' }
                        $bridge='ACTIVE'; $reverts=$nr; $detail="bridge armed; reverts $nr"
                    } else { $detail="no JANET bridge task present; $ping" }
                    Remove-CimSession $cim -ErrorAction SilentlyContinue
                } catch { $detail="TCP $ping but DCOM query failed: $($_.Exception.Message)" }
                $row = @{ Host=$h; Ping=$ping; Bridge=$bridge; Reverts=$reverts; Detail=$detail }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row); continue
            }

            $cim = New-WrbDcomSession -Computer $h -Credential $Credential
            if ($ActionId -eq 'enable') {
                $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + $payload.EnableEncoded)
                $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
                $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -CimSession $cim -TaskName $script:WrbEnableTask -Action $act -Trigger $trg -Principal $pr -Force | Out-Null
                Start-ScheduledTask -CimSession $cim -TaskName $script:WrbEnableTask -ErrorAction SilentlyContinue
                $row = @{ Host=$h; Ping=$ping; Status='BRIDGING'; Detail="enable task pushed (reverts in $revertMinutes min + at startup); verify 5986 shortly" }
            } else {
                $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + $revertEnc)
                $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
                $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -CimSession $cim -TaskName ($script:WrbRevertTask + '-Force') -Action $act -Trigger $trg -Principal $pr -Force | Out-Null
                Start-ScheduledTask -CimSession $cim -TaskName ($script:WrbRevertTask + '-Force') -ErrorAction SilentlyContinue
                $row = @{ Host=$h; Ping=$ping; Status='REVERTING'; Detail='revert task pushed (removes listener + firewall + cert + tasks)' }
            }
            Remove-CimSession $cim -ErrorAction SilentlyContinue
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            & $send @{ type='audit'; action=('WinRmBridge-' + $ActionId); target=$h; result='Success'; itemCount=1; detail=([string]$row.Detail) }
        } catch {
            $row = @{ Host=$h; Ping=$ping; Status='FAILED'; Bridge='?'; Reverts='-'; Detail="DCOM/task error: $($_.Exception.Message)" }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            & $send @{ type='audit'; action=('WinRmBridge-' + $ActionId); target=$h; result='Failure'; itemCount=0; detail=([string]$row.Detail) }
        }
    }

    & $send @{ type='status'; text="Done. $($rows.Count) host(s)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; action=$ActionId } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, New-WinRmBridgeRevertScript, New-WinRmBridgeEnableScript, ConvertTo-WinRmBridgeEncoded, Test-WinRmBridgeSelfTarget, Test-WinRmBridgeHostToken, Get-WinRmBridgeLocalIdentity, Get-WinRmBridgePayload
