# =============================================================================
#  JanetWeb.dhcp.psm1  -  DHCP Scope Option tool engine for JANET Web
#  (Re-forked for JANET Web: the JANET ONE engine is the proven faithful fork of the
#   desktop DHCPScopeOptionTool_1.1.5.ps1; action contract cross-checked vs the spec.)
#
#  Ported from Tools\DHCPScopeOptionTool_1.1.5.ps1 (engine reused, WinForms layer
#  dropped). Edits IP-array DHCP scope options (006 DNS, 003 Router, 042 NTP,
#  044 WINS, 045 NBDD) on a remote Windows DHCP server over WinRM/Invoke-Command.
#  Lists IPv4 scopes, loads current option values, atomically replaces an option
#  on a single scope, and bulk-appends / prepends / removes IPs across many
#  scopes in one remote round-trip.
#
#  Contract (identical to JanetWeb.message.psm1):
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
#
#  The DHCP server is treated as the "Host" for every streamed row and audit so
#  the grid upserts cleanly. Single-scope and load/connect actions are single
#  remote round-trips; bulk actions process every scope serially inside ONE
#  remote session (the original tool's discipline -- avoids WSMan queue
#  saturation) and stream a row per scope as results come back.
#
#  v1.1.8 Connect's WSMan reachability preflight also probes HTTPS 5986 (after
#  HTTP 5985, before SMB 445 liveness), auto-switching that session to -UseSSL.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'dhcp'
        name     = 'DHCP Scope Options'
        version  = '1.1.10'
        category = 'Network'
        summary  = 'Edit IP-array DHCP scope options (006 DNS, 003 Router, 042 NTP, 044 WINS) on a remote Windows DHCP server: list scopes, load values, apply to one scope, or bulk append/prepend/remove across many scopes.'
        actions  = @(
            @{
                id          = 'connect'
                label       = 'Connect / List Scopes'
                description  = 'Validate WSMan reachability and the DhcpServer module on the server, then enumerate all IPv4 scopes (ScopeId, SubnetMask, Name, State, Description).'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','ScopeId','SubnetMask','Name','State','Description','Module')
                inputs       = @(
                    @{ name='targets'; label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true }
                )
            },
            @{
                id          = 'load'
                label       = 'Load Option Values'
                description  = 'Read the current ordered IPv4 list stored in a DHCP option (006/003/042/044/045 or any IP-array option ID) on one scope.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','ScopeId','OptionId','Values','ValueCount','NotSet')
                inputs       = @(
                    @{ name='targets';  label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true },
                    @{ name='scopeId';  label='Scope ID (dotted quad, e.g. 192.168.1.0)'; type='text'; required=$true },
                    @{ name='optionId'; label='Option ID'; type='int'; required=$false; default=6 }
                )
            },
            @{
                id          = 'apply'
                label       = 'Apply Values to Single Scope'
                description  = 'Atomically replace an option value on one scope with the supplied ordered IP list (Set-DhcpServerv4OptionValue). Removing the option requires the explicit Remove-option checkbox. Shows the add/remove/reorder diff; Dry run previews the diff without writing.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','ScopeId','OptionId','Status','OldValues','NewValues','Added','Removed','Reordered','Error')
                inputs       = @(
                    @{ name='targets';      label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true },
                    @{ name='scopeId';      label='Scope ID (dotted quad)'; type='text'; required=$true },
                    @{ name='optionId';     label='Option ID'; type='int'; required=$false; default=6 },
                    @{ name='newValues';    label='New values (ordered, one IPv4 per line; leave blank ONLY with Remove option checked)'; type='textarea'; required=$false },
                    @{ name='removeOption'; label='Remove option (delete the option from the scope; requires blank New values)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun';       label='Dry run (preview the diff, change nothing)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';      label='Type APPLY to arm'; type='text'; required=$true }
                )
            },
            @{
                id          = 'bulk-append'
                label       = 'Bulk Append IPs'
                description  = 'Append IPs to the bottom of an option on every listed scope. IPs already present are skipped. One row streamed per scope.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','ScopeId','Status','BeforeCount','AfterCount','BeforeValues','AfterValues','Error')
                inputs       = @(
                    @{ name='targets';     label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true },
                    @{ name='scopeIds';    label='Scope IDs (one dotted quad per line)'; type='textarea'; required=$true },
                    @{ name='optionId';    label='Option ID'; type='int'; required=$false; default=6 },
                    @{ name='ipAddresses'; label='IPs to append (one per line)'; type='textarea'; required=$true },
                    @{ name='dryRun';      label='Dry run (preview per-scope before/after, change nothing)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';     label='Type APPLY to arm'; type='text'; required=$true }
                )
            },
            @{
                id          = 'bulk-prepend'
                label       = 'Bulk Prepend IPs'
                description  = 'Prepend IPs to the top of an option on every listed scope. IPs already present are skipped. One row streamed per scope.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','ScopeId','Status','BeforeCount','AfterCount','BeforeValues','AfterValues','Error')
                inputs       = @(
                    @{ name='targets';     label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true },
                    @{ name='scopeIds';    label='Scope IDs (one dotted quad per line)'; type='textarea'; required=$true },
                    @{ name='optionId';    label='Option ID'; type='int'; required=$false; default=6 },
                    @{ name='ipAddresses'; label='IPs to prepend (one per line)'; type='textarea'; required=$true },
                    @{ name='dryRun';      label='Dry run (preview per-scope before/after, change nothing)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';     label='Type APPLY to arm'; type='text'; required=$true }
                )
            },
            @{
                id          = 'bulk-remove'
                label       = 'Bulk Remove IPs'
                description  = 'Remove IPs from an option on every listed scope (if present). If the list becomes empty the option is removed entirely. One row streamed per scope.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','ScopeId','Status','BeforeCount','AfterCount','BeforeValues','AfterValues','Error')
                inputs       = @(
                    @{ name='targets';     label='DHCP Server (hostname or FQDN)'; type='hostlist'; required=$true },
                    @{ name='scopeIds';    label='Scope IDs (one dotted quad per line)'; type='textarea'; required=$true },
                    @{ name='optionId';    label='Option ID'; type='int'; required=$false; default=6 },
                    @{ name='ipAddresses'; label='IPs to remove (one per line)'; type='textarea'; required=$true },
                    @{ name='dryRun';      label='Dry run (preview per-scope before/after, change nothing)'; type='bool'; required=$false; default=$false },
                    @{ name='confirm';     label='Type APPLY to arm'; type='text'; required=$true }
                )
            }
        )
    }
}

# -----------------------------------------------------------------------------
#  Helpers (lifted from the original tool)
# -----------------------------------------------------------------------------

function ConvertTo-JanetTokenList {
    # Split a pasted blob into clean, unique tokens (hostnames, scope IDs, IPs).
    # De-dupes case-insensitively, preserves first-seen order. Used for the
    # server list, scope-id list, and IP list.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $t = $tok.Trim()
        if ($t -and $seen.Add($t)) { [void]$out.Add($t) }
    }
    return $out.ToArray()
}

function Test-JanetIpv4 {
    # IPv4-only AND canonical dotted-quad only. .NET TryParse accepts classful
    # shorthand ('192.168.1' parses as 192.168.0.1) and bare integers, which must
    # NOT be stored as DHCP option values OR reach the remote [ipaddress] scope-id
    # cast on a destructive path, so require the parse round-trip ([ipaddress] then
    # ToString) to equal the trimmed input. Used for IP-typed option values (apply
    # newValues, bulk IPs) AND canonical scope-id validation.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $t = $Text.Trim()
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($t, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne 'InterNetwork') { return $false }
    return ($ip.ToString() -eq $t)
}

function Get-JanetValidIpList {
    # Parse + validate an IP blob. Returns @{ Valid=@(); Invalid=@() }, valid
    # IPs canonicalized and de-duped. Mirrors Get-BulkIps (line 2121).
    param([string]$Raw)
    $valid   = New-Object System.Collections.ArrayList
    $invalid = New-Object System.Collections.ArrayList
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($tok in ($Raw -split '[,;\s\r\n]+')) {
        $t = $tok.Trim()
        if (-not $t) { continue }
        if (Test-JanetIpv4 $t) {
            $clean = ([System.Net.IPAddress]::Parse($t)).ToString()
            if ($seen.Add($clean)) { [void]$valid.Add($clean) }
        } else {
            [void]$invalid.Add($t)
        }
    }
    return @{ Valid = @($valid.ToArray()); Invalid = @($invalid.ToArray()) }
}

function Test-JanetWsmanReachable {
    # TCP pre-flight against WSMan HTTP 5985, then WSMan HTTPS 5986, then SMB 445
    # (liveness only) (line 1681) -- surfaces a specific "unreachable" error
    # instead of the generic Invoke-Command timeout. Breaks on first connect (5985
    # preferred when both WinRM ports are open). Returns UseSsl=$true ONLY when the
    # server answered on 5986 (not 5985, not 445), so the caller can dial the
    # session over HTTPS.
    param([string]$Server, [int]$TimeoutMs = 3000)
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985, 5986, 445) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $tcp.BeginConnect($Server, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                $tcp.EndConnect($iar)
                $reachable = $true
                if ($port -eq 5986) { $useSsl = $true }
            }
        } catch {
        } finally {
            try { $tcp.Close() } catch {}
        }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        throw "WSMan port 5985/5986 (or SMB 445) on $Server did not respond within $([Math]::Round($TimeoutMs/1000,0))s."
    }
    return @{ Reachable = $true; UseSsl = $useSsl }
}

# Shared WinRM session options for every dhcp remote call. dhcp was the only
# engine carrying no -SessionOption, so a server that accepts TCP 5985 but whose
# WinRM / DhcpServer enumeration is wedged would otherwise hang at the WSMan
# default with no operator escape. OperationTimeout is generous (300s) because a
# bulk run loops over all scopes serially inside ONE session. WinRM-only
# (AFNET-safe), PS 5.1-safe.
$script:DhcpSessionOption = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 300000 -CancelTimeout 5000 -IdleTimeout 60000

function Invoke-JanetOnDhcp {
    # Mirrors Invoke-OnDhcp (line 1643). When $Credential is set, pass it with
    # -Authentication Default; when $null, omit -Credential so WSMan uses the
    # current process's Kerberos/NTLM identity (the tool's 'Use current session'
    # path). NOTE: the param is named $Arguments (not $Args) -- the original
    # 1.1.3 fix; $Args collides with the automatic variable and binds the remote
    # param() to empty positional slots. $UseSsl (set by Test-JanetWsmanReachable
    # when the server answered ONLY on 5986) dials over HTTPS with a fresh
    # SkipCACheck/SkipCNCheck session option instead of the shared HTTP one.
    param(
        [string]$Server,
        [scriptblock]$Script,
        [object[]]$Arguments = @(),
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$UseSsl = $false
    )
    if ([string]::IsNullOrWhiteSpace($Server)) { throw "No DHCP server specified." }
    $sessOpt = $script:DhcpSessionOption
    if ($UseSsl) {
        $sessOpt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 300000 -CancelTimeout 5000 -IdleTimeout 60000 -SkipCACheck -SkipCNCheck
    }
    $icParams = @{
        ComputerName  = $Server
        SessionOption = $sessOpt
        ScriptBlock   = $Script
        ArgumentList  = $Arguments
        ErrorAction   = 'Stop'
    }
    if ($UseSsl) { $icParams['UseSSL'] = $true }
    if ($Credential) {
        $icParams['Credential']     = $Credential
        $icParams['Authentication'] = 'Default'
    }
    Invoke-Command @icParams
}

function Invoke-JanetOnDhcpCancelable {
    # Cancel-aware wrapper around Invoke-JanetOnDhcp. This engine's destructive
    # work is a SINGLE remote round-trip per action (the bulk loop runs serially
    # inside the remote scriptblock to avoid WSMan queue saturation -- the
    # original tool's discipline), so there are no per-host PS handles to poll.
    # To honor the operator-cancel contract we run that one Invoke-Command on a
    # [powershell] handle and poll the injected job's Cancel flag in a short
    # harvest loop; on cancel we BeginStop the in-flight WinRM child (non-blocking
    # -- EndStop here would block cancel on the remote teardown) so a stood-down
    # bulk/apply stops mutating the remaining scopes mid-flight. On the non-cancel
    # path the behavior is identical to a plain blocking Invoke-JanetOnDhcp: same
    # single session, same full result set returned on completion.
    param(
        [string]$Server,
        [scriptblock]$Script,
        [object[]]$Arguments = @(),
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$CancelCheck,
        [bool]$UseSsl = $false
    )
    # $inner runs in a fresh [powershell] runspace that does NOT inherit the
    # module script scope, so the session option is passed in as an argument
    # (NOT referenced via $script:) and applied to both Invoke-Command branches.
    # $useSslInner (set by Test-JanetWsmanReachable when the server answered ONLY on
    # 5986) dials HTTPS - MUST match the destructive Apply/Bulk write to the same
    # transport the reachability probe green-lit, or a 5986-only server hangs on HTTP.
    $inner = {
        param($srv, $scr, $argList, $cred, $sessOpt, $useSslInner)
        $ic = @{ ComputerName=$srv; SessionOption=$sessOpt; ScriptBlock=$scr; ArgumentList=$argList; ErrorAction='Stop' }
        if ($useSslInner) { $ic['UseSSL'] = $true }
        if ($cred) { $ic['Credential']=$cred; $ic['Authentication']='Default' }
        Invoke-Command @ic
    }
    $sessOpt = $script:DhcpSessionOption
    if ($UseSsl) {
        $sessOpt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 300000 -CancelTimeout 5000 -IdleTimeout 60000 -SkipCACheck -SkipCNCheck
    }
    $ps = [powershell]::Create()
    [void]$ps.AddScript($inner)
    [void]$ps.AddArgument($Server)
    [void]$ps.AddArgument($Script)
    [void]$ps.AddArgument([object[]]$Arguments)
    [void]$ps.AddArgument($Credential)
    [void]$ps.AddArgument($sessOpt)
    [void]$ps.AddArgument($UseSsl)
    $async = $ps.BeginInvoke()
    $cancelled = $false
    try {
        while (-not $async.IsCompleted) {
            if ($CancelCheck -and (& $CancelCheck)) {
                $cancelled = $true
                # Canonical cancel teardown: BeginStop then NULL the handle.
                # Dispose immediately after BeginStop empirically blocks ~11s on
                # the WinRM teardown, and the caller emits its cancelled rows /
                # audits only after we return -- so the stopping pipeline is
                # abandoned to the finalizer instead of disposed here.
                try { [void]$ps.BeginStop($null, $null) } catch {}
                $ps = $null
                break
            }
            Start-Sleep -Milliseconds 120
        }
        if ($cancelled) {
            return @{ Cancelled = $true; Result = $null; Error = $null }
        }
        $out = $null; $err = $null
        try {
            $out = $ps.EndInvoke($async)
        } catch {
            $err = $_.Exception.Message
        }
        if ($err) { throw $err }
        return @{ Cancelled = $false; Result = $out; Error = $null }
    } finally {
        # Completed (non-cancel) path: reclaim the local runspace as before.
        # On cancel $ps was nulled right after BeginStop, so this settles
        # immediately and the operator-visible abandon rows/audits emitted by
        # the caller are not delayed by the blocking pipeline teardown.
        if ($ps) { try { $ps.Dispose() } catch {} }
    }
}

function Get-JanetWsmanAuthHint {
    # Reproduce the WSMan auth-rejection hint from the original (lines 2074,
    # 2285) -- generic 'access denied' rarely means a bad password.
    param([string]$Message, [string]$Server)
    if ($Message -match 'username or password|access is denied|authentication') {
        return ("WSMan auth rejection. Common causes: account not in 'DHCP Administrators' on $Server; " +
                "stale launcher credential; auth mode toggled mid-session; username missing domain prefix " +
                "(DOMAIN\user or user@domain.com); or account locked out.")
    }
    return ''
}

# -----------------------------------------------------------------------------
#  Remote scriptblocks (lifted verbatim from the original engine)
# -----------------------------------------------------------------------------

# Probe: confirm DhcpServer module is present and enumerate scopes, projecting
# ScopeId / SubnetMask to dotted-quad strings on the REMOTE side so the
# [ipaddress] objects survive PSRemoting deserialization (line 1690 / 1.1.2 fix).
$script:DhcpConnectScript = {
    $mod = Get-Module -ListAvailable -Name DhcpServer | Select-Object -First 1
    if (-not $mod) { throw "DhcpServer PowerShell module is not installed on $env:COMPUTERNAME." }
    Import-Module DhcpServer -ErrorAction Stop
    $scopes = Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ScopeId     = $_.ScopeId.IPAddressToString
            SubnetMask  = $_.SubnetMask.IPAddressToString
            Name        = [string]$_.Name
            State       = [string]$_.State
            Description = [string]$_.Description
        }
    }
    [pscustomobject]@{
        Host   = $env:COMPUTERNAME
        Module = $mod.Version.ToString()
        Scopes = @($scopes)
    }
}

# Load one option's current value list (line 1793). Missing option => empty
# list with NotSet=$true, never a failure.
$script:DhcpLoadScript = {
    param($scopeId, $optId)
    Import-Module DhcpServer -ErrorAction Stop
    $sid = [ipaddress]$scopeId
    try {
        $ov = Get-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
    } catch {
        # FAIL-CLOSED: distinguish a genuine "option not configured" (safe: really
        # not set) from a READ ERROR (RPC blip / connectivity / permission). A read
        # error must NOT be reported as an empty/not-set value, or an Append would
        # wipe the live list and a Remove short-circuit would pass. Only the "does
        # not exist" family means NotSet; anything else is Ok=$false with the error.
        $rmsg = [string]$_.Exception.Message
        $rfid = [string]$_.FullyQualifiedErrorId
        $notPresent = ($rmsg -match '(?i)does not exist' -or $rmsg -match '(?i)not\s+configured' -or $rmsg -match '(?i)no\s+option\s+value' -or $rfid -match '(?i)NotFound|DoesNotExist|20000')
        if ($notPresent) {
            return [pscustomobject]@{ Ok = $true; Values = @(); NotSet = $true; Err = $null }
        }
        return [pscustomobject]@{ Ok = $false; Values = @(); NotSet = $false; Err = ("read failed: $rmsg") }
    }
    $vals = @()
    if ($ov -and $ov.Value) {
        foreach ($v in @($ov.Value)) { $vals += [string]$v }
    }
    return [pscustomobject]@{ Ok = $true; Values = $vals; NotSet = $false; Err = $null }
}

# Single-scope apply (lines 2036-2054). Empty list => Remove; else Set with the
# full ordered array (atomic whole-option replace). [ipaddress] cast + empty
# guard reproduce the 1.1.2/1.1.3 fixes.
$script:DhcpApplyScript = {
    param($scopeId, $optId, $values)
    Import-Module DhcpServer -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($scopeId)) { throw "ScopeId arrived empty over WSMan." }
    $sid = [ipaddress]$scopeId
    $vals = @($values)
    if ($vals.Count -eq 0) {
        Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
        return [pscustomobject]@{ Removed = $true }
    } else {
        Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -Value $vals -Force -ErrorAction Stop
        return [pscustomobject]@{ Removed = $false }
    }
}

# Bulk apply across many scopes in ONE remote round-trip (lines 2197-2245).
# Serial per-scope loop returns one record per scope with Before/After/Status.
# $dryRun (web addition) computes the same Before/After diff but reports
# WouldChange/WouldRemove without calling Set/Remove.
$script:DhcpBulkScript = {
    param($scopeIds, $optId, $ips, $mode, $dryRun)
    Import-Module DhcpServer -ErrorAction Stop
    $out = New-Object System.Collections.ArrayList
    foreach ($sidStr in $scopeIds) {
        $rec = [pscustomobject]@{
            ScopeId = $sidStr; Status = ''; Before = @(); After = @(); Error = $null
        }
        try {
            $sid = [ipaddress]$sidStr
            $existing = @()
            # FAIL-CLOSED read: a read error must NOT collapse to "empty" (that would
            # make Append write ONLY the new IPs -- deleting the live list -- and let a
            # Remove short-circuit wipe config). Only a genuine "option not configured"
            # is treated as empty; any other read failure flags this scope ReadError and
            # SKIPS the write entirely.
            $readOk = $true; $readErrMsg = $null
            try {
                $ov = Get-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
                if ($ov -and $ov.Value) { $existing = @($ov.Value | ForEach-Object { [string]$_ }) }
            } catch {
                $rmsg = [string]$_.Exception.Message
                $rfid = [string]$_.FullyQualifiedErrorId
                if ($rmsg -match '(?i)does not exist' -or $rmsg -match '(?i)not\s+configured' -or $rmsg -match '(?i)no\s+option\s+value' -or $rfid -match '(?i)NotFound|DoesNotExist|20000') {
                    $existing = @()
                } else {
                    $readOk = $false; $readErrMsg = $rmsg
                }
            }
            if (-not $readOk) {
                $rec.Status = 'ReadError'
                $rec.Error  = ("refused (fail-closed): could not read current option value, no write attempted: $readErrMsg")
                [void]$out.Add($rec)
                continue
            }
            $rec.Before = $existing

            switch ($mode) {
                'Append'  { $newList = @($existing) + @($ips | Where-Object { $existing -notcontains $_ }) }
                'Prepend' { $newList = @($ips | Where-Object { $existing -notcontains $_ }) + @($existing) }
                'Remove'  { $newList = @($existing | Where-Object { $ips -notcontains $_ }) }
            }
            $newList = @($newList)
            $rec.After = $newList

            $same = ($existing -join '|') -eq ($newList -join '|')

            if ($same) {
                $rec.Status = 'NoChange'
            } elseif ($dryRun) {
                $rec.Status = $(if ($newList.Count -eq 0) { 'WouldRemove' } else { 'WouldChange' })
            } else {
                # Optimistic-concurrency guard (mirrors the single-scope apply's
                # CheckStale). The write below is a whole-option REPLACE of a list
                # computed from the $existing snapshot read at the top of this scope.
                # Re-read the option's CURRENT value immediately before writing; if a
                # concurrent writer / failover partner changed it in the gap, SKIP this
                # scope and flag 'Stale' rather than clobber their change with our
                # stale-computed replace. The re-read is a local DhcpServer query
                # inside this same remote session -- no extra WSMan round-trip.
                $current = @()
                # FAIL-CLOSED re-read: if the pre-write re-read errors, we cannot prove
                # the server state is unchanged, so REFUSE the write (never remove/replace
                # off an errored read that looks like "empty").
                $reReadOk = $true; $reErrMsg = $null
                try {
                    $cv = Get-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
                    if ($cv -and $cv.Value) { $current = @($cv.Value | ForEach-Object { [string]$_ }) }
                } catch {
                    $cmsg = [string]$_.Exception.Message
                    $cfid = [string]$_.FullyQualifiedErrorId
                    if ($cmsg -match '(?i)does not exist' -or $cmsg -match '(?i)not\s+configured' -or $cmsg -match '(?i)no\s+option\s+value' -or $cfid -match '(?i)NotFound|DoesNotExist|20000') {
                        $current = @()
                    } else {
                        $reReadOk = $false; $reErrMsg = $cmsg
                    }
                }
                if (-not $reReadOk) {
                    $rec.Status = 'ReadError'
                    $rec.After  = $existing
                    $rec.Error  = ("refused (fail-closed): could not re-read current option value before write, no write attempted: $reErrMsg")
                } elseif (($current -join '|') -ne ($existing -join '|')) {
                    $rec.Status = 'Stale'
                    $rec.After  = $current
                    $rec.Error  = ('refused: option changed on the server since read (was [' + ($existing -join ', ') + '], now [' + ($current -join ', ') + ']) -- reload and retry')
                } elseif ($newList.Count -eq 0) {
                    Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -ErrorAction Stop
                    $rec.Status = 'Removed'
                } else {
                    Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId $optId -Value $newList -Force -ErrorAction Stop
                    $rec.Status = 'Changed'
                }
            }
        } catch {
            $rec.Status = 'Error'; $rec.Error = $_.Exception.Message
        }
        [void]$out.Add($rec)
    }
    return ,$out.ToArray()
}

# -----------------------------------------------------------------------------
#  Action handlers
# -----------------------------------------------------------------------------

function Invoke-JanetDhcpConnect {
    param([string]$Server, $Credential, [scriptblock]$Send)
    $rows = New-Object System.Collections.ArrayList
    & $Send @{ type='status'; text="Connecting to $Server ..." }
    & $Send @{ type='progress'; done=0; total=1 }
    try {
        $wsmanCheck = Test-JanetWsmanReachable -Server $Server
        $probe  = Invoke-JanetOnDhcp -Server $Server -Script $script:DhcpConnectScript -Credential $Credential -UseSsl $wsmanCheck.UseSsl
        $scopes = @($probe.Scopes)
        $module = [string]$probe.Module
        if ($scopes.Count -eq 0) {
            $row = @{ Host=$Server; ScopeId=''; SubnetMask=''; Name='(no scopes)'; State=''; Description=''; Module=$module }
            [void]$rows.Add($row)
            & $Send (@{ type='row' } + $row)
        } else {
            foreach ($sc in $scopes) {
                $row = @{
                    Host        = $Server
                    ScopeId     = [string]$sc.ScopeId
                    SubnetMask  = [string]$sc.SubnetMask
                    Name        = [string]$sc.Name
                    State       = [string]$sc.State
                    Description = [string]$sc.Description
                    Module      = $module
                }
                [void]$rows.Add($row)
                & $Send (@{ type='row' } + $row)
            }
        }
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Success'; itemCount=$scopes.Count; detail=("listed $($scopes.Count) scope(s); DhcpServer v$module") }
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Connected to $($probe.Host). $($scopes.Count) scope(s), DhcpServer v$module." }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; scopes=$scopes.Count } }
    } catch {
        $emsg = $_.Exception.Message
        $hint = Get-JanetWsmanAuthHint -Message $emsg -Server $Server
        & $Send @{ type='log'; level='err'; text=("Connect to $Server failed: $emsg" + $(if($hint){" -- $hint"}else{''})) }
        $row = @{ Host=$Server; ScopeId=''; SubnetMask=''; Name=''; State='Error'; Description=$emsg; Module='' }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Failure'; itemCount=0; detail=$emsg }
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Connect failed." }
        return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; scopes=0 } }
    }
}

function Invoke-JanetDhcpLoad {
    param([string]$Server, [string]$ScopeId, [int]$OptionId, $Credential, [scriptblock]$Send)
    $rows = New-Object System.Collections.ArrayList
    & $Send @{ type='status'; text="Loading option $OptionId from scope $ScopeId on $Server ..." }
    & $Send @{ type='progress'; done=0; total=1 }
    try {
        if ([string]::IsNullOrWhiteSpace($ScopeId)) { throw "Scope ID is required." }
        # Non-throwing reachability probe: dial HTTPS when the server answered ONLY on 5986,
        # else let the Invoke-Command below surface the real error (preserves prior semantics).
        $useSsl = $false; try { $useSsl = [bool](Test-JanetWsmanReachable -Server $Server).UseSsl } catch {}
        $result = Invoke-JanetOnDhcp -Server $Server -Script $script:DhcpLoadScript `
                    -Arguments @($ScopeId, $OptionId) -Credential $Credential -UseSsl $useSsl
        # FAIL-CLOSED: a read error (Ok=$false) is NOT "option not set" -- surface it
        # as a failure row rather than a misleading empty/NotSet result.
        if ($result -and ($result.PSObject.Properties['Ok']) -and (-not $result.Ok)) {
            throw ($(if ($result.Err) { [string]$result.Err } else { 'could not read current option value' }))
        }
        $vals = @($result.Values | ForEach-Object { [string]$_ })
        $row = @{
            Host       = $Server
            ScopeId    = $ScopeId
            OptionId   = $OptionId
            Values     = ($vals -join ', ')
            ValueCount = $vals.Count
            NotSet     = [bool]$result.NotSet
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Success'; itemCount=$vals.Count; detail=("load scope=$ScopeId opt=$OptionId count=$($vals.Count)") }
        & $Send @{ type='progress'; done=1; total=1 }
        $statusText = $(if ($result.NotSet) { "Option $OptionId not set on scope $ScopeId." } else { "Loaded $($vals.Count) value(s)." })
        & $Send @{ type='status'; text=$statusText }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; valueCount=$vals.Count } }
    } catch {
        $emsg = $_.Exception.Message
        $hint = Get-JanetWsmanAuthHint -Message $emsg -Server $Server
        & $Send @{ type='log'; level='err'; text=("Load failed: $emsg" + $(if($hint){" -- $hint"}else{''})) }
        $row = @{ Host=$Server; ScopeId=$ScopeId; OptionId=$OptionId; Values=''; ValueCount=0; NotSet=$false }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Failure'; itemCount=0; detail=$emsg }
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Load failed." }
        return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; valueCount=0 } }
    }
}

function Invoke-JanetDhcpApply {
    param([string]$Server, [string]$ScopeId, [int]$OptionId, [string[]]$NewValues, $Credential, [scriptblock]$Send, [scriptblock]$CancelCheck, [bool]$DryRun = $false, [bool]$CheckStale = $false, [string[]]$ExpectedOld = @())
    $rows = New-Object System.Collections.ArrayList
    if ($DryRun) {
        & $Send @{ type='status'; text="DRY RUN preview of option $OptionId on scope $ScopeId on $Server ..." }
    } else {
        & $Send @{ type='status'; text="Applying option $OptionId to scope $ScopeId on $Server ..." }
    }
    & $Send @{ type='progress'; done=0; total=1 }

    $new = @($NewValues | ForEach-Object { [string]$_ })

    # Reachability/transport probe ONCE for this action: dial HTTPS on both the pre-read AND
    # the destructive write when the server answered only on 5986 (non-throwing - a probe
    # failure falls through to HTTP and the Invoke-Command surfaces the real error).
    $useSsl = $false; try { $useSsl = [bool](Test-JanetWsmanReachable -Server $Server).UseSsl } catch {}

    # Read current values first so we can compute and report the diff (the
    # original computed this in-memory from the loaded list; we re-read so the
    # web action is self-contained).
    $orig = @()
    $readErr = $null
    try {
        $loadRes = Invoke-JanetOnDhcp -Server $Server -Script $script:DhcpLoadScript `
                     -Arguments @($ScopeId, $OptionId) -Credential $Credential -UseSsl $useSsl
        # FAIL-CLOSED: the load script now reports Ok=$false on a genuine READ ERROR
        # (vs. Ok=$true/NotSet=$true for a legitimately unset option). Treat Ok=$false
        # as a read failure so we ABORT below instead of computing a fabricated diff
        # off a fake-empty before-state (which would wipe live config on a write).
        if ($loadRes -and ($loadRes.PSObject.Properties['Ok']) -and (-not $loadRes.Ok)) {
            $readErr = $(if ($loadRes.Err) { [string]$loadRes.Err } else { 'could not read current option value' })
        } else {
            $orig = @($loadRes.Values | ForEach-Object { [string]$_ })
        }
    } catch {
        $readErr = $_.Exception.Message
    }

    # If the pre-read failed we have no trustworthy before-state. Presenting a
    # fabricated diff (OldValues='' => every IP reads 'Added') on a destructive
    # whole-option replace is misleading, so ABORT this apply: emit an Error row
    # + a Failure audit and do NOT write. The operator can retry once the read
    # succeeds.
    if ($readErr) {
        $hint = Get-JanetWsmanAuthHint -Message $readErr -Server $Server
        # A dry run never attempts a write, so its abort is a read failure
        # (TouchHost), not a config-change failure (VulnPatched).
        $abortAudit = $(if ($DryRun) { 'TouchHost' } else { 'VulnPatched' })
        & $Send @{ type='log'; level='err'; text=("APPLY aborted -- could not read current values: $readErr" + $(if($hint){" -- $hint"}else{''})) }
        & $Send @{ type='audit'; action=$abortAudit; target=$Server; result='Failure'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId aborted: read of current values failed: $readErr") }
        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = 'Error'
            OldValues = 'unknown (read failed)'
            NewValues = ($new -join ', ')
            Added     = ''
            Removed   = ''
            Reordered = $false
            Error     = ("aborted: could not read current values: $readErr")
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Apply aborted (could not read current values)." }
        return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; status='Error' } }
    }

    $added     = @($new  | Where-Object { $orig -notcontains $_ })
    $removed   = @($orig | Where-Object { $new  -notcontains $_ })
    # Reordered = same set, different order. Sorted-set equality vs ordered equality.
    $sameSet   = (@($orig | Sort-Object) -join '|') -eq (@($new | Sort-Object) -join '|')
    $sameOrder = (($orig -join '|') -eq ($new -join '|'))
    $reordered = ($sameSet -and -not $sameOrder)

    # Dry run: report the diff the apply WOULD make, write nothing, and audit
    # it as a read (TouchHost) like the load action.
    if ($DryRun) {
        $wouldStatus = $(if ($new.Count -eq 0) { 'WouldRemove' } elseif ($sameOrder) { 'NoChange' } else { 'WouldChange' })
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Success'; itemCount=$new.Count; detail=("DRY RUN apply scope=$ScopeId opt=$OptionId would=$wouldStatus values=" + ($new -join ';')) }
        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = $wouldStatus
            OldValues = ($orig -join ', ')
            NewValues = ($new  -join ', ')
            Added     = ($added   -join ', ')
            Removed   = ($removed -join ', ')
            Reordered = [bool]$reordered
            Error     = ''
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Dry run complete ($wouldStatus); nothing was written." }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; status=$wouldStatus } }
    }

    # Optimistic-concurrency guard: the operator's before-state (captured when they
    # Loaded the option) must still match what the server has NOW. If another writer
    # (or a failover partner) changed it in the gap, REFUSE the whole-option replace
    # rather than silently clobber their change. The fresh read ($orig) is the same
    # one used for the diff above, so this is one comparison, no extra round-trip.
    if ($CheckStale) {
        $expOld = @($ExpectedOld | ForEach-Object { [string]$_ })
        if ((@($expOld) -join '|') -ne (@($orig) -join '|')) {
            & $Send @{ type='log'; level='err'; text=("APPLY refused -- option $OptionId changed on $Server since you loaded it (you had [" + ($expOld -join ', ') + "], it is now [" + ($orig -join ', ') + "]). Reload the option and re-apply.") }
            & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId refused: stale before-state (concurrent change)") }
            $row = @{
                Host=$Server; ScopeId=$ScopeId; OptionId=$OptionId; Status='Stale'
                OldValues=($orig -join ', '); NewValues=($new -join ', ')
                Added=''; Removed=''; Reordered=$false
                Error='refused: the option changed on the server since you loaded it -- reload and retry'
            }
            [void]$rows.Add($row)
            & $Send (@{ type='row' } + $row)
            & $Send @{ type='progress'; done=1; total=1 }
            & $Send @{ type='status'; text="Apply refused -- option changed since load. Reload and retry." }
            return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; status='Stale' } }
        }
    }

    # Pre-dispatch cancel guard: if the operator cancelled before this single
    # destructive round-trip starts, do not mutate the scope at all.
    if ($CancelCheck -and (& $CancelCheck)) {
        & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId cancelled by operator") }
        $row = @{
            Host=$Server; ScopeId=$ScopeId; OptionId=$OptionId; Status='Cancelled'
            OldValues=($orig -join ', '); NewValues=($new -join ', ')
            Added=($added -join ', '); Removed=($removed -join ', '); Reordered=[bool]$reordered
            Error='cancelled by operator'
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Apply cancelled." }
        return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; status='Cancelled' } }
    }

    # Idempotent removal: the operator asked to delete the option (empty new
    # list) but the fresh read shows it is already not set. Calling
    # Remove-DhcpServerv4OptionValue -ErrorAction Stop here would throw 'option
    # not found' and surface as Error/Failure, so short-circuit to a no-op: there
    # is nothing to write and the desired end-state already holds. Audited as a
    # read that changed nothing (TouchHost/Skipped, itemCount 0), mirroring the
    # bulk NoChange path.
    if ($new.Count -eq 0 -and $orig.Count -eq 0) {
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Skipped'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId remove no-op: option already not set") }
        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = 'NoChange'
            OldValues = ''
            NewValues = ''
            Added     = ''
            Removed   = ''
            Reordered = $false
            Error     = ''
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Option $OptionId already not set on scope $ScopeId; nothing to remove." }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; status='NoChange' } }
    }

    # No-op re-apply: the desired values already match what the server has (same
    # values in the same order). The BULK path already short-circuits this to
    # NoChange (~line 442); do the same for single-scope so a re-apply of an
    # unchanged option is NOT written and mis-reported as 'Changed' / a
    # VulnPatched-Success. Reaching here means the pre-read SUCCEEDED (a read error
    # aborts above), so this only fires on a genuine equal read, never off a
    # fail-closed empty. The remove-both-empty no-op is handled just above; this
    # covers a populated option whose value is unchanged. Audited as a read that
    # changed nothing (TouchHost/Skipped, itemCount 0), mirroring the removal no-op.
    if ($sameOrder -and $new.Count -gt 0) {
        & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Skipped'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId apply no-op: option already set to the requested value(s)") }
        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = 'NoChange'
            OldValues = ($orig -join ', ')
            NewValues = ($new  -join ', ')
            Added     = ''
            Removed   = ''
            Reordered = $false
            Error     = ''
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Option $OptionId already set to the requested value(s) on scope $ScopeId; nothing to change." }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; status='NoChange' } }
    }

    try {
        if ([string]::IsNullOrWhiteSpace($ScopeId)) {
            throw "Internal: ScopeId is empty -- supply a scope and try again."
        }
        $applyCall = Invoke-JanetOnDhcpCancelable -Server $Server -Script $script:DhcpApplyScript `
                      -Arguments @($ScopeId, $OptionId, $new) -Credential $Credential -CancelCheck $CancelCheck -UseSsl $useSsl
        if ($applyCall.Cancelled) {
            # Cancelled mid-flight: the WinRM child was BeginStop'd. We cannot know
            # whether the remote Set/Remove completed, so audit the scope as
            # abandoned and surface it as a cancelled row.
            & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId cancelled by operator") }
            $row = @{
                Host=$Server; ScopeId=$ScopeId; OptionId=$OptionId; Status='Cancelled'
                OldValues=($orig -join ', '); NewValues=($new -join ', ')
                Added=($added -join ', '); Removed=($removed -join ', '); Reordered=[bool]$reordered
                Error='cancelled by operator'
            }
            [void]$rows.Add($row)
            & $Send (@{ type='row' } + $row)
            & $Send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
            & $Send @{ type='progress'; done=1; total=1 }
            & $Send @{ type='status'; text="Apply cancelled." }
            return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; status='Cancelled' } }
        }
        $applyRes = @($applyCall.Result | Select-Object -First 1)[0]
        $status = $(if ([bool]$applyRes.Removed) { 'Removed' } else { 'Changed' })

        # JANET central log: a successful Apply changes the server's config
        # state -> VulnPatched (line 2062).
        & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Success'; itemCount=1; detail=("scope=$ScopeId opt=$OptionId values=" + ($new -join ';')) }

        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = $status
            OldValues = ($orig -join ', ')
            NewValues = ($new  -join ', ')
            Added     = ($added   -join ', ')
            Removed   = ($removed -join ', ')
            Reordered = [bool]$reordered
            Error     = ''
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Apply succeeded ($status)." }
        return @{ rows=@($rows); summary=@{ total=1; ok=1; failed=0; status=$status } }
    } catch {
        $emsg = $_.Exception.Message
        $hint = Get-JanetWsmanAuthHint -Message $emsg -Server $Server
        & $Send @{ type='log'; level='err'; text=("APPLY failed: $emsg" + $(if($hint){" -- $hint"}else{''})) }
        # Failed apply -> VulnPatched/Failure (line 2085).
        & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("scope=$ScopeId opt=$OptionId err=$emsg") }
        $row = @{
            Host      = $Server
            ScopeId   = $ScopeId
            OptionId  = $OptionId
            Status    = 'Error'
            OldValues = ($orig -join ', ')
            NewValues = ($new  -join ', ')
            Added     = ($added   -join ', ')
            Removed   = ($removed -join ', ')
            Reordered = [bool]$reordered
            Error     = $emsg
        }
        [void]$rows.Add($row)
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='progress'; done=1; total=1 }
        & $Send @{ type='status'; text="Apply failed." }
        return @{ rows=@($rows); summary=@{ total=1; ok=0; failed=1; status='Error' } }
    }
}

function Invoke-JanetDhcpBulk {
    param(
        [string]$Server,
        [string[]]$ScopeIds,
        [int]$OptionId,
        [string[]]$Ips,
        [ValidateSet('Append','Prepend','Remove')][string]$Mode,
        $Credential,
        [scriptblock]$Send,
        [scriptblock]$CancelCheck,
        [bool]$DryRun = $false
    )
    $rows = New-Object System.Collections.ArrayList
    $scopeIdList = @($ScopeIds)
    $ipList      = @($Ips)
    $total = $scopeIdList.Count

    # Transport probe once: dial the bulk write over HTTPS when the server answered only on
    # 5986 (non-throwing - a probe failure falls through to HTTP and the write surfaces it).
    $useSsl = $false; try { $useSsl = [bool](Test-JanetWsmanReachable -Server $Server).UseSsl } catch {}

    $bulkLabel = $(if ($DryRun) { "DRY RUN bulk $Mode" } else { "Bulk $Mode" })
    & $Send @{ type='status'; text="$bulkLabel on $total scope(s), option $OptionId, $($ipList.Count) IP(s) on $Server ..." }
    & $Send @{ type='progress'; done=0; total=([Math]::Max(1,$total)) }

    $changed = 0; $nochange = 0; $errs = 0
    # A dry run never attempts a write, so its failure/abandon audits are reads
    # (TouchHost), not config-change failures (VulnPatched).
    $failAudit = $(if ($DryRun) { 'TouchHost' } else { 'VulnPatched' })

    # Per-scope abandon helper: stream a Cancelled row + Failure audit for every
    # scope we did not get a confirmed result for, then warn + bump counters. The
    # remote loop runs serially inside ONE session, so a mid-flight cancel
    # (BeginStop) may leave some scopes already mutated and the rest untouched; we
    # cannot tell which, so every still-unreported scope is audited as abandoned.
    $emitBulkCancelled = {
        param($scopes)
        foreach ($sidStr in $scopes) {
            & $Send @{ type='audit'; action=$failAudit; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode scope=$sidStr opt=$OptionId cancelled by operator") }
            $crow = @{
                Host=$Server; ScopeId=[string]$sidStr; Status='Cancelled';
                BeforeCount=0; AfterCount=0; BeforeValues=''; AfterValues=''; Error='cancelled by operator'
            }
            [void]$rows.Add($crow)
            & $Send (@{ type='row' } + $crow)
            $errs++
        }
        & $Send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
    }

    # Pre-dispatch cancel guard: if cancelled before the destructive round-trip
    # starts, do not mutate any scope.
    if ($CancelCheck -and (& $CancelCheck)) {
        & $emitBulkCancelled $scopeIdList
        & $Send @{ type='progress'; done=([Math]::Max(1,$total)); total=([Math]::Max(1,$total)) }
        & $Send @{ type='status'; text="Bulk $Mode cancelled." }
        return @{ rows=@($rows); summary=@{ total=$total; ok=0; failed=$total; noChange=0 } }
    }

    try {
        # All scopes processed serially inside ONE remote session (the original
        # tool's discipline -- avoids WSMan queue saturation). We get the full
        # result set back, then stream a row per scope.
        $bulkCall = Invoke-JanetOnDhcpCancelable -Server $Server -Script $script:DhcpBulkScript `
                     -Arguments @($scopeIdList, $OptionId, $ipList, $Mode, $DryRun) -Credential $Credential -CancelCheck $CancelCheck -UseSsl $useSsl
        if ($bulkCall.Cancelled) {
            # Cancelled mid-flight: the WinRM child was BeginStop'd before results
            # came back, so we have no per-scope record -- abandon every scope.
            & $emitBulkCancelled $scopeIdList
            & $Send @{ type='progress'; done=([Math]::Max(1,$total)); total=([Math]::Max(1,$total)) }
            & $Send @{ type='status'; text="Bulk $Mode cancelled." }
            return @{ rows=@($rows); summary=@{ total=$total; ok=0; failed=$total; noChange=0 } }
        }
        $results = @($bulkCall.Result)

        $done = 0
        foreach ($r in $results) {
            $status   = [string]$r.Status
            $before   = @($r.Before | ForEach-Object { [string]$_ })
            $after    = @($r.After  | ForEach-Object { [string]$_ })
            $rowError = $(if ($r.Error) { [string]$r.Error } else { '' })

            # loop65 (item74): the final branch is a fail-CLOSED catch-all. Previously only Error/Stale
            # counted as errors, so the remote's own 'ReadError' refusal (it declined to write because it
            # could not read the current value) matched NO bucket - uncounted, and the summary read
            # "0 error(s)". Anything that is not a change or a genuine no-change is an error.
            if     ($status -in @('Changed','Removed','WouldChange','WouldRemove')) { $changed++ }
            elseif ($status -eq 'NoChange') { $nochange++ }
            else { $errs++ }

            # JANET central log per scope (lines 2263-2268): Changed/Removed are
            # state changes (VulnPatched/Success), NoChange is a TouchHost/Skipped,
            # Error is a VulnPatched/Failure. Dry runs write nothing, so every
            # per-scope audit is a read (TouchHost) like the load action.
            if ($DryRun) {
                switch ($status) {
                    'WouldChange' { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Success'; itemCount=$after.Count; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId would-change") } }
                    'WouldRemove' { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Success'; itemCount=0; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId would-remove") } }
                    'NoChange'    { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Skipped'; itemCount=0; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId no-change") } }
                    'ReadError'   { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId REFUSED: could not read current value (nothing previewed)") } }
                    'Error'       { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId err=$rowError") } }
                    default       { & $Send @{ type='audit'; action='TouchHost'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode DRY RUN scope=$($r.ScopeId) opt=$OptionId unexpected status '$status' - treated as failure") } }
                }
            } else {
                switch ($status) {
                    'Changed'  { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Success'; itemCount=1; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId") } }
                    'Removed'  { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Success'; itemCount=1; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId removed") } }
                    'NoChange' { & $Send @{ type='audit'; action='TouchHost';   target=$Server; result='Skipped'; itemCount=0; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId no-change") } }
                    'Stale'    { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId refused: stale (concurrent change)") } }
                    'ReadError' { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId REFUSED: could not read current value - nothing written") } }
                    'Error'    { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId err=$rowError") } }
                    default    { & $Send @{ type='audit'; action='VulnPatched'; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode scope=$($r.ScopeId) opt=$OptionId unexpected status '$status' - treated as failure") } }
                }
            }

            $row = @{
                Host         = $Server
                ScopeId      = [string]$r.ScopeId
                Status       = $status
                BeforeCount  = $before.Count
                AfterCount   = $after.Count
                BeforeValues = ($before -join ', ')
                AfterValues  = ($after  -join ', ')
                Error        = $rowError
            }
            [void]$rows.Add($row)
            & $Send (@{ type='row' } + $row)
            $done++
            & $Send @{ type='progress'; done=$done; total=([Math]::Max(1,$total)) }
        }

        $summaryText = $(if ($DryRun) {
            "Bulk $Mode DRY RUN complete: $changed would change, $nochange unchanged, $errs error(s); nothing was written."
        } else {
            "Bulk $Mode complete: $changed changed, $nochange unchanged, $errs error(s)."
        })
        & $Send @{ type='status'; text=$summaryText }
        if ($errs -gt 0) { & $Send @{ type='log'; level='warn'; text=$summaryText } }
        return @{ rows=@($rows); summary=@{ total=$total; ok=$changed; failed=$errs; noChange=$nochange } }
    } catch {
        # Session-level failure (auth, transport) -- the remote loop never ran
        # (line 2282). Emit one Failure audit + an error row per scope.
        $emsg = $_.Exception.Message
        $hint = Get-JanetWsmanAuthHint -Message $emsg -Server $Server
        & $Send @{ type='log'; level='err'; text=("Bulk $Mode failed at the session level: $emsg" + $(if($hint){" -- $hint"}else{''})) }
        & $Send @{ type='audit'; action=$failAudit; target=$Server; result='Failure'; itemCount=0; detail=("bulk-$Mode session-level err=$emsg") }
        $done = 0
        foreach ($sidStr in $scopeIdList) {
            $row = @{
                Host=$Server; ScopeId=[string]$sidStr; Status='Error';
                BeforeCount=0; AfterCount=0; BeforeValues=''; AfterValues=''; Error=$emsg
            }
            [void]$rows.Add($row)
            & $Send (@{ type='row' } + $row)
            $done++
            & $Send @{ type='progress'; done=$done; total=([Math]::Max(1,$total)) }
        }
        & $Send @{ type='status'; text="Bulk $Mode failed." }
        return @{ rows=@($rows); summary=@{ total=$total; ok=0; failed=$total; noChange=0 } }
    }
}

# -----------------------------------------------------------------------------
#  loop66 (item75): self-guard for the destructive DHCP-option writes. dhcp is the
#  DHCP admin tool - it must NEVER rewrite DHCP scope options on the box running
#  JANET itself. Mirrors the pkginstall/upr self-guard identity set (COMPUTERNAME
#  + FQDN + short + loopback + every bound NIC IPv4).
# -----------------------------------------------------------------------------
function Get-DhcpLocalIdentity {
    if ($script:DhcpLocalIdentity) { return ,$script:DhcpLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) } } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:DhcpLocalIdentity = $set
    return ,$set
}
function Test-DhcpHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-DhcpLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

# -----------------------------------------------------------------------------
#  Entry point
# -----------------------------------------------------------------------------

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel contract: the server injects a synchronized hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running destructive remote call break and BeginStop its in-flight WinRM
    # child. When no job context is supplied (e.g. direct calls), $cancelCheck
    # just returns $false. Passed down to the apply/bulk dispatchers.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Tolerant bool coercion for checkbox inputs (real bools or 'true'/'1'/'on').
    $asBool = { param($v) if ($v -is [bool]) { return [bool]$v }; return ([string]$v -match '^(?i:1|true|yes|on)$') }

    # The DHCP server is the single target for every action -- this tool
    # operates on ONE server per run. More than one parsed token is an operator
    # mistake (silently truncating to the first hid the rest), so fail loudly
    # and name the extras. @() is load-bearing: a 1-element function return
    # unrolls to a bare [string], and [0] on that yields the first CHARACTER.
    $servers = @(ConvertTo-JanetTokenList ([string]$Params['targets']))
    # Accept only a bare host/IPv4 server token (the splitter is generic - shared
    # with scope-id/IP lists - so validate the server target here, not in it) so a
    # pasted UNC/URL/junk never reaches the DHCP WSMan session.
    $servers = @($servers | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' })
    if ($servers.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No DHCP server specified.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    if ($servers.Count -gt 1) {
        $extras = @($servers | Select-Object -Skip 1)
        & $send @{ type='log'; level='err'; text=("This tool targets ONE DHCP server per run; got $($servers.Count). Remove the extra target(s): " + ($extras -join ', ')) }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    $server = [string]$servers[0]

    # loop66 (item75): destructive-action guards. The write actions (apply + bulk-*) modify DHCP scope
    # options on a live server, yet dhcp had NO typed confirm-word and NO self-guard (unlike every other
    # destructive engine). Fail closed, server-side, BEFORE any DHCP session: (1) require the operator to
    # type APPLY (case-insensitive, like adto's -ne 'FIX'); (2) refuse when the target resolves to the box
    # running JANET. connect/load are read-only and ungated.
    if ($ActionId -in @('apply','bulk-append','bulk-prepend','bulk-remove')) {
        if ([string]$Params['confirm'] -ne 'APPLY') {
            & $send @{ type='log'; level='err'; text='Refused: type APPLY (exactly) in Confirm to arm a DHCP option change.' }
            return @{ rows=@(); summary=@{ total=0; rejected=$true } }
        }
        if (Test-DhcpHostIsSelf $server) {
            & $send @{ type='log'; level='err'; text="Self-guard: refusing to modify DHCP options on '$server' - it is (or resolves to) the machine running JANET." }
            return @{ rows=@(); summary=@{ total=0; rejected=$true; selfSkipped=1 } }
        }
    }

    # OptionId (shared by load/apply/bulk). Default 6 (006 DNS Servers).
    # Non-numeric input falls back to the documented default (a bare TryParse
    # would zero it); the desktop NumericUpDown enforced the 1-254 range.
    $optionId = 6
    $rawOptId = [string]$Params['optionId']
    if (-not [string]::IsNullOrWhiteSpace($rawOptId)) {
        $parsedOptId = 0
        if ([int]::TryParse($rawOptId.Trim(), [ref]$parsedOptId)) {
            $optionId = $parsedOptId
        } else {
            & $send @{ type='log'; level='warn'; text=("Option ID '$rawOptId' is not numeric; using default 6 (006 DNS Servers).") }
        }
    }
    if ($optionId -lt 1 -or $optionId -gt 254) {
        & $send @{ type='log'; level='err'; text="Option ID $optionId is out of range (1-254)." }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    switch ($ActionId) {
        'connect' {
            return Invoke-JanetDhcpConnect -Server $server -Credential $Credential -Send $send
        }
        'load' {
            $scopeId = ([string]$Params['scopeId']).Trim()
            if ([string]::IsNullOrWhiteSpace($scopeId)) {
                & $send @{ type='log'; level='warn'; text='Scope ID is required for Load.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if (-not (Test-JanetIpv4 $scopeId)) {
                & $send @{ type='log'; level='err'; text="Scope ID '$scopeId' is not a canonical dotted quad (e.g. 192.168.1.0)." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            return Invoke-JanetDhcpLoad -Server $server -ScopeId $scopeId -OptionId $optionId -Credential $Credential -Send $send
        }
        'apply' {
            $scopeId = ([string]$Params['scopeId']).Trim()
            if ([string]::IsNullOrWhiteSpace($scopeId)) {
                & $send @{ type='log'; level='warn'; text='Scope ID is required for Apply.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            if (-not (Test-JanetIpv4 $scopeId)) {
                & $send @{ type='log'; level='err'; text="Scope ID '$scopeId' is not a canonical dotted quad (e.g. 192.168.1.0)." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            # newValues is an ordered list -- preserve order (the token helper
            # would reorder). Split, validate each token as IPv4, drop blanks,
            # and de-dupe repeats keeping the FIRST occurrence (the desktop
            # working list enforced uniqueness).
            $rawNew = [string]$Params['newValues']
            $newValues = New-Object System.Collections.ArrayList
            $badTokens = New-Object System.Collections.ArrayList
            $seenVals  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($tok in ($rawNew -split '[\r\n,;\t ]+')) {
                $t = $tok.Trim()
                if (-not $t) { continue }
                if (Test-JanetIpv4 $t) {
                    $clean = ([System.Net.IPAddress]::Parse($t)).ToString()
                    if ($seenVals.Add($clean)) { [void]$newValues.Add($clean) }
                } else {
                    [void]$badTokens.Add($t)
                }
            }
            # Empty-collapse guard: a bad paste (e.g. hostnames) must NEVER
            # silently become the empty-list -> Remove-DhcpServerv4OptionValue
            # path. Abort BEFORE any remote work on rejected tokens or on a
            # non-blank input that parsed to nothing; removing the option needs
            # the explicit removeOption checkbox.
            if ($badTokens.Count -gt 0) {
                & $send @{ type='log'; level='err'; text=("Apply aborted: non-IPv4 token(s) in New values: " + ($badTokens.ToArray() -join ', ')) }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $removeOption = $false
            if ($Params.ContainsKey('removeOption')) { $removeOption = & $asBool $Params['removeOption'] }
            if ($newValues.Count -eq 0) {
                if (-not [string]::IsNullOrWhiteSpace($rawNew)) {
                    & $send @{ type='log'; level='err'; text='Apply aborted: New values parsed to an empty list from non-blank input; nothing was changed.' }
                    return @{ rows=@(); summary=@{ total=0 } }
                }
                if (-not $removeOption) {
                    & $send @{ type='log'; level='err'; text="New values is blank. To delete option $optionId from the scope entirely, check 'Remove option'; otherwise supply at least one IPv4 address." }
                    return @{ rows=@(); summary=@{ total=0 } }
                }
            } elseif ($removeOption) {
                & $send @{ type='log'; level='err'; text="'Remove option' is checked but New values were supplied. Clear one or the other." }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $dryRun = $false
            if ($Params.ContainsKey('dryRun')) { $dryRun = & $asBool $Params['dryRun'] }
            # Optimistic-concurrency: the view sends the before-state it loaded so the
            # engine can refuse the replace if the option changed underneath. Absent =>
            # no check (back-compat). Present-but-empty => "must still be unset".
            $checkStale = $false; $expectedOld = @()
            if ($Params.ContainsKey('expectedOld')) {
                $checkStale = $true
                $eo = New-Object System.Collections.ArrayList
                foreach ($tok in (([string]$Params['expectedOld']) -split '[\r\n,;\t ]+')) { $t = $tok.Trim(); if ($t) { [void]$eo.Add($t) } }
                $expectedOld = @($eo.ToArray())
            }
            return Invoke-JanetDhcpApply -Server $server -ScopeId $scopeId -OptionId $optionId `
                     -NewValues @($newValues.ToArray()) -Credential $Credential -Send $send -CancelCheck $cancelCheck -DryRun $dryRun -CheckStale $checkStale -ExpectedOld $expectedOld
        }
        { $_ -in 'bulk-append','bulk-prepend','bulk-remove' } {
            $mode = switch ($ActionId) {
                'bulk-append'  { 'Append' }
                'bulk-prepend' { 'Prepend' }
                'bulk-remove'  { 'Remove' }
            }
            $scopeIds = ConvertTo-JanetTokenList ([string]$Params['scopeIds'])
            if ($scopeIds.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='At least one scope ID is required.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $badScopes = @($scopeIds | Where-Object { -not (Test-JanetIpv4 $_) })
            if ($badScopes.Count -gt 0) {
                & $send @{ type='log'; level='err'; text=("Bulk $mode aborted: scope ID(s) are not canonical dotted quads: " + ($badScopes -join ', ')) }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $parsed = Get-JanetValidIpList ([string]$Params['ipAddresses'])
            if ($parsed.Invalid.Count -gt 0) {
                & $send @{ type='log'; level='warn'; text=("Ignoring non-IPv4 token(s): " + ($parsed.Invalid -join ', ')) }
            }
            if ($parsed.Valid.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='At least one valid IPv4 address is required.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $dryRun = $false
            if ($Params.ContainsKey('dryRun')) { $dryRun = & $asBool $Params['dryRun'] }
            return Invoke-JanetDhcpBulk -Server $server -ScopeIds $scopeIds -OptionId $optionId `
                     -Ips $parsed.Valid -Mode $mode -Credential $Credential -Send $send -CancelCheck $cancelCheck -DryRun $dryRun
        }
        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
