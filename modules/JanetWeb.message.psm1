# =============================================================================
#  JanetWeb.message.psm1  -  Remote Message tool engine for JANET Web
#
#  RE-FORKED from the desktop  Tools\RemoteMessageTool_1.3.3.ps1  (the
#  $script:SendScriptBlock per-host worker + the runspace-pool send loop), with
#  the WinForms layer dropped. Cross-checked against JanetOne.message.psm1 to
#  keep its proven fixes: cooperative operator-cancel via the injected $__job,
#  a per-job wall-clock watchdog, and null-credential fallback to the current
#  Kerberos identity. Fans out msg.exe popups to every interactive session on
#  each target over WinRM, with an advisory reachability ping and per-host
#  streaming.
#
#  Contract (unchanged across the suite):
#    Get-JanetToolManifest                                         -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit     -> { rows; summary }
#  -Emit event shapes: status / progress / row / log / audit.  The bespoke view
#  (web/js/views/message.view.js) owns ALL presentation: it derives the colour-
#  coded per-host activity lines + banners from these row/progress events.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'message'
        name     = 'Remote Message'
        version  = '1.3.3'
        category = 'Operations'
        summary  = 'Broadcast a popup to logged-on users across many workstations in parallel (msg.exe over WinRM).'
        actions  = @(
            @{
                id          = 'send'
                label       = 'Send Message'
                description = 'Deliver a titled popup to every interactive session on each target.'
                kind        = 'stream-table'
                # pops a dialog on every interactive session of potentially many machines:
                # the view confirms the target count first (mass-send parity with the desktop).
                destructive = $true
                columns     = @('Host','Pingable','Sessions','Status','Detail')
                inputs      = @(
                    @{ name='targets';   label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='title';     label='Title';   type='text';     required=$true;  default='Message from the 48 Communications Squadron' },
                    @{ name='body';      label='Message'; type='textarea'; required=$true },
                    @{ name='requireOK'; label='Require user to click OK (popup stays until dismissed)'; type='bool'; required=$false; default=$false },
                    @{ name='timeout';   label='Auto-dismiss after (seconds)'; type='int';  required=$false; default=60 },
                    @{ name='parallel';  label='Send in parallel (faster for large target lists)'; type='bool'; required=$false; default=$true },
                    @{ name='requirePing'; label='Skip hosts that fail the TCP 5985/5986/445 probe'; type='bool'; required=$false; default=$false },
                    @{ name='threads';   label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'ping'
                label       = 'Ping All'
                description = 'Quick reachability pre-flight across the target list.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Pingable')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            }
        )
    }
}

function ConvertTo-MessageHostList {
    # Split a pasted blob into clean, unique hostnames (case-insensitive dedup),
    # mirroring the desktop Get-Targets parse on [,CRLF; TAB space]+.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim()
        # Accept only a bare host/IPv4 token; drop UNC/URL/junk before any remote call.
        if ($h -and ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h) }
    }
    return $out.ToArray()
}

# Per-host worker: ping, then deliver the popup to every interactive session.
# Returns the desktop result shape { Host; Success; Sessions; Pingable; Error;
# Detail; Diagnostic }; the harvest loop turns it into a streamed row.
$script:MessageWorker = {
    param($hostname, $title, $body, $timeoutSec, $requireOK, $requirePing, $cred, $openMs, $opMs, $cancelJob)
    $r = [ordered]@{ Host = $hostname; Pingable = $false; Sessions = 0; Success = $false; MsgStatus = ''; Detail = ''; Diagnostic = '' }

    # Cooperative cancel: poll the synchronized job's Cancel flag at safe points so
    # the worker returns normally and its Remove-PSSession finally still fires.
    $isCancelled = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Reachability is TCP-only (AFNET convention): reachable = a short TCP probe to
    # WinRM HTTP(5985), WinRM HTTPS(5986), or SMB(445) connects. NEVER ICMP/Test-Connection
    # - it is dropped on AFNET, so it only adds a per-host timeout for a result that gets
    # OR'd away. Mirrors the wpt ping-sweep TcpClient style. $useSsl is set when the host
    # answered ONLY on 5986 so the session below auto-switches to -UseSSL (HTTP 5985 is
    # preferred when both are open).
    $tcpUp = $false; $useSsl = $false
    foreach ($port in 5985, 5986, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($hostname, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $tcpUp = $true; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($tcpUp) { break }
    }
    $r.Pingable = $tcpUp
    # requirePing (opt-in): when the operator chose to skip hosts that fail the TCP
    # 5985/5986/445 probe, bail before WinRM instead of attempting delivery. Rebased onto
    # the TCP probe (an ICMP gate is meaningless on a no-ICMP network).
    if ($requirePing -and -not $tcpUp) { $r.Detail = 'Host not reachable (skipped: failed TCP 5985/5986/445 probe)'; return $r }
    # Ping is advisory by default: attempt WinRM even when ICMP is blocked (hardened
    # hosts often allow WinRM while dropping ICMP); mark Unreachable only if WinRM fails.
    if (& $isCancelled) { $r.Detail = 'cancelled by operator'; return $r }

    try {
        # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is
        # common on AFNET, so skip CA/CN validation - the transport stays encrypted;
        # port 5986 is implicit).
        $soP = @{ OpenTimeout=$openMs; OperationTimeout=$opMs; CancelTimeout=5000 }
        if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
        $opt = New-PSSessionOption @soP
        $splat = @{ ComputerName=$hostname; SessionOption=$opt; ErrorAction='Stop' }
        if ($useSsl) { $splat['UseSSL']=$true }
        if ($cred) { $splat['Credential']=$cred }
        $session = New-PSSession @splat
        # Reconcile reachability with delivery: a host we can open a WinRM session to
        # is definitively reachable, so the advisory Pingable must reflect that even if
        # the short pre-probe (ICMP/TCP) missed it (fixes Pingable=No on delivered rows).
        $r.Pingable = $true
        try {
            # Last safe point before the long remote call: bail cooperatively so the
            # finally below tears the session down instead of leaking a remote shell.
            if (& $isCancelled) { $r.Detail = 'cancelled by operator'; return $r }
            $sr = Invoke-Command -Session $session -ScriptBlock {
                param($t, $b, $to, $req)
                $fullMsg = "$t`r`n`r`n$b"
                $diag = New-Object System.Collections.ArrayList
                $count = 0
                # Interactive sessions: explorer.exe owners (SessionId 1-999), qwinsta fallback.
                $sids = New-Object System.Collections.ArrayList
                try {
                    $explorerProcs = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)
                    foreach ($p in $explorerProcs) {
                        $sid = [string]$p.SessionId
                        if ($sid -and [int]$sid -gt 0 -and [int]$sid -lt 1000 -and $sids -notcontains $sid) { [void]$sids.Add($sid) }
                    }
                    [void]$diag.Add("explorer.count=$($explorerProcs.Count)")
                    [void]$diag.Add("explorer.ids=[$($sids -join ',')]")
                } catch { [void]$diag.Add("explorer.exception=$($_.Exception.Message)") }
                if ($sids.Count -eq 0) {
                    try {
                        $qw = qwinsta 2>&1
                        $qwExit = $LASTEXITCODE
                        [void]$diag.Add("qw.exit=$qwExit")
                        if ($qwExit -eq 0 -and $qw) {
                            for ($i = 1; $i -lt @($qw).Count; $i++) {
                                if ($qw[$i] -match '\s(\d+)\s+(Active|Disc)') {
                                    $sid = $matches[1]
                                    if ($matches[2] -eq 'Active' -and [int]$sid -gt 0 -and [int]$sid -lt 1000 -and $sids -notcontains $sid) { [void]$sids.Add($sid) }
                                }
                            }
                            [void]$diag.Add("qw.ids=[$($sids -join ',')]")
                        }
                    } catch { [void]$diag.Add("qw.exception=$($_.Exception.Message)") }
                }
                if ($sids.Count -eq 0) { return @{ Count = 0; Status = 'Failed'; Error = 'No interactive user sessions detected on target'; Diagnostic = ($diag -join ' | ') } }

                # Broadcast first; fall back to per-session if that delivers nothing.
                # require-OK pins /TIME at 99999 (~27 hrs, effectively forever); larger
                # values are rejected by msg.exe on some builds with "Error 5".
                $cap = if ($req) { 99999 } else { [Math]::Min([int]$to, 99999) }
                # Real success signal only: msg.exe is SILENT on success and prints an
                # 'Error ...' string on any failure, so require exit 0 AND empty output.
                # Exit 0 WITH unrecognized (non-error) output cannot be confirmed -> mark
                # $ambiguous and report Unknown instead of over-reporting Delivered (the
                # safe middle-ground, ported from the SECRET fork). A recognized error /
                # non-zero exit is a real failure.
                $errPat = 'Error|denied|not found|No session|Invalid|incorrect|cannot|could not|fail'
                $ambiguous = $false
                try {
                    $out = $fullMsg | & msg.exe * "/TIME:$cap" 2>&1
                    $bcastExit = $LASTEXITCODE
                    $bcastStr = ($out | Out-String).Trim()
                    [void]$diag.Add("msg*.exit=$bcastExit")
                    if ($bcastStr) {
                        $shortOut = if ($bcastStr.Length -gt 150) { $bcastStr.Substring(0,150) + '...' } else { $bcastStr }
                        [void]$diag.Add("msg*.out=$shortOut")
                    }
                    if ($bcastExit -eq 0 -and [string]::IsNullOrWhiteSpace($bcastStr)) { $count = $sids.Count }
                    elseif ($bcastExit -eq 0 -and -not ($bcastStr -match $errPat)) { $ambiguous = $true }
                } catch { [void]$diag.Add("msg*.exception=$($_.Exception.Message)") }
                if ($count -eq 0) {
                    [void]$diag.Add("fallback=per-session")
                    foreach ($sid in $sids) {
                        try {
                            $out = $fullMsg | & msg.exe $sid "/TIME:$cap" 2>&1
                            $perExit = $LASTEXITCODE
                            $perStr = ($out | Out-String).Trim()
                            [void]$diag.Add("msg.$sid.exit=$perExit")
                            if ($perStr) {
                                $shortOut = if ($perStr.Length -gt 100) { $perStr.Substring(0,100) + '...' } else { $perStr }
                                [void]$diag.Add("msg.$sid.out=$shortOut")
                            }
                            # Same real-success rule as the broadcast path: exit 0 AND
                            # silent output (msg.exe prints nothing on a clean delivery).
                            if ($perExit -eq 0 -and [string]::IsNullOrWhiteSpace($perStr)) { $count++ }
                            elseif ($perExit -eq 0 -and -not ($perStr -match $errPat)) { $ambiguous = $true }
                        } catch { [void]$diag.Add("msg.$sid.exception=$($_.Exception.Message)") }
                    }
                }
                if ($count -gt 0) { return @{ Count = $count; Status = 'Delivered'; Error = $null; Diagnostic = ($diag -join ' | ') } }
                if ($ambiguous) { return @{ Count = 0; Status = 'Unknown'; Error = 'msg.exe gave no clear success or error signal - delivery unconfirmed'; Diagnostic = ($diag -join ' | ') } }
                return @{ Count = 0; Status = 'Failed'; Error = 'msg.exe delivery failed on all strategies'; Diagnostic = ($diag -join ' | ') }
            } -ArgumentList $title, $body, $timeoutSec, $requireOK -ErrorAction Stop

            $r.Sessions   = [int]$sr.Count
            $r.MsgStatus  = [string]$sr.Status
            $r.Success    = ($r.MsgStatus -eq 'Delivered' -and $r.Sessions -gt 0)
            $r.Diagnostic = [string]$sr.Diagnostic
            if ($r.Success) { $r.Detail = "Delivered to $($r.Sessions) session(s)" }
            elseif ($r.MsgStatus -eq 'Unknown') { $r.Detail = if ($sr.Error) { [string]$sr.Error } else { 'Delivery unconfirmed (no msg.exe success signal)' } }
            elseif ($sr.Error) { $r.Detail = [string]$sr.Error }
            else { $r.Detail = 'No sessions received message' }
        } finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    } catch {
        $r.Detail = "WinRM error: $($_.Exception.Message)"
    }
    return $r
}

# Lightweight reachability worker for the Ping All action.
# Reachability is TCP-only (AFNET convention): a host is reachable if a short TCP
# probe to WinRM HTTP(5985), WinRM HTTPS(5986), or SMB(445) connects (mirrors the
# wpt ping-sweep TcpClient style). NEVER ICMP/Test-Connection - it is dropped on
# AFNET and only adds a per-host timeout; WinRM/SMB-reachable hosts are what
# actually matter here. This worker only reports Pingable (no session is opened),
# so there is no $useSsl to thread anywhere.
$script:PingWorker = {
    param($hostname)
    $up = $false
    foreach ($port in 5985, 5986, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($hostname, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1200, $false) -and $tc.Connected) { $up = $true }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($up) { break }
    }
    [ordered]@{ Host = $hostname; Pingable = $up }
}

function Get-MessageBool {
    # Coerce a manifest/JSON bool-ish param to [bool] (true|1|yes|on), like the
    # JANET ONE engine, so a checkbox arriving as $true or "true" both work.
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return ("$Value" -match '^(?i:true|1|yes|on)$')
}

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
    # running fan-out break. The flag is passed into the worker so in-flight hosts
    # return COOPERATIVELY (firing their Remove-PSSession finally); BeginStop is a
    # last resort after a grace window. With no job context $cancelCheck is $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    $targets = ConvertTo-MessageHostList ([string]$Params['targets'])
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    # Parallel hosts: honor the explicit numeric 'threads' input (restored); else fall
    # back to a per-action default (send 16, ping 32, like the desktop). The 'parallel'
    # checkbox is a master switch - unchecked forces sequential (pool width 1). Cancel
    # works in both paths.
    $parallel = Get-MessageBool $Params['parallel'] $true
    $threads = if ($ActionId -eq 'ping') { 32 } else { 16 }
    if ($Params['threads']) { $tv = 0; if ([int]::TryParse([string]$Params['threads'], [ref]$tv) -and $tv -gt 0) { $threads = $tv } }
    if (-not $parallel) { $threads = 1 }
    $threads = [Math]::Max(1, [Math]::Min(64, $threads))

    # Build the per-host job set for the chosen action.
    if ($ActionId -eq 'ping') {
        $work = $script:PingWorker
        $argFactory = { param($h) ,@($h) }
        $auditDetail = { param($r) if ($r.Pingable) { 'reachable' } else { 'no ping reply' } }
        $rowOf = { param($r) @{ Host=$r.Host; Pingable=[bool]$r.Pingable } }
        $okOf  = { param($r) [bool]$r.Pingable }
        $resultOf = { param($r) if ($r.Pingable) { 'Success' } else { 'Failure' } }
    }
    elseif ($ActionId -eq 'send') {
        $title = [string]$Params['title']; $body = [string]$Params['body']
        # the view auto-fills the default title; an empty title here is still backstopped.
        if ([string]::IsNullOrWhiteSpace($title)) { $title = 'Message from the 48 Communications Squadron' }
        if ([string]::IsNullOrWhiteSpace($body)) {
            & $send @{ type='log'; level='warn'; text='Message body is required.' }
            return @{ rows=@(); summary=@{ total=$targets.Count } }
        }
        $timeout = 60
        if ($Params['timeout']) {
            $tv = 0
            if ([int]::TryParse([string]$Params['timeout'], [ref]$tv)) { $timeout = $tv }
        }
        $timeout = [Math]::Max(5, [Math]::Min(3600, $timeout))
        $openMs = 20000; $opMs = 45000
        $requireOK   = Get-MessageBool $Params['requireOK'] $false     # popup stays until dismissed
        $requirePing = Get-MessageBool $Params['requirePing'] $false   # skip hosts that fail the TCP 5985/5986/445 probe instead of trying WinRM
        $work = $script:MessageWorker
        $argFactory = { param($h) ,@($h, $title, $body, $timeout, $requireOK, $requirePing, $Credential, $openMs, $opMs, $cancelJob) }
        $auditDetail = { param($r) $r.Detail }
        # Diagnostic is not a column, so it surfaces in the row popup / export without widening the table.
        $rowOf = { param($r) @{ Host=$r.Host; Pingable=[bool]$r.Pingable; Sessions=[int]$r.Sessions; Status=$(if($r.Success){'Delivered'}elseif($r.MsgStatus -eq 'Unknown'){'Unknown'}elseif($r.Pingable){'Undelivered'}else{'Unreachable'}); Detail=$r.Detail; Diagnostic=[string]$r.Diagnostic } }
        $okOf  = { param($r) [bool]$r.Success }
        # Audit honesty (ported from SECRET): a confirmed delivery is Success; a host we
        # reached but whose delivery msg.exe could not confirm is Skipped (nothing-
        # confirmed-done, not a claimed success); everything else is a real Failure.
        $resultOf = { param($r) if ($r.Success) { 'Success' } elseif ($r.MsgStatus -eq 'Unknown') { 'Skipped' } else { 'Failure' } }
    }
    else { & $send @{ type='error'; text="Unknown action '$ActionId'." }; return @{ rows=@(); summary=@{} } }

    & $send @{ type='status'; text="Dispatching $($targets.Count) host(s) ($threads thread(s))..." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($work)
        foreach ($a in (& $argFactory $h)) { [void]$ps.AddArgument($a) }
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartTime=(Get-Date) })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0; $skipCount = 0
    $stopHandles = New-Object System.Collections.ArrayList   # captured BeginStop handles (last-resort cancel)
    $cancelling  = $false                                    # cooperative-drain mode after operator cancel
    $coopDeadline = [datetime]::MaxValue                     # grace window for workers to return on their own
    $maxJobSeconds = 90                                      # per-job wall-clock watchdog (desktop parity)
    try {
        while ($done -lt $jobs.Count) {
            foreach ($j in $jobs) {
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; Pingable=$false; Success=$false; Sessions=0; Detail="worker error: $($_.Exception.Message)"; Diagnostic='' } }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null
                    $result = [string](& $resultOf $res)
                    $ok = ($result -eq 'Success')
                    if ($ok) { $okCount++ } elseif ($result -eq 'Skipped') { $skipCount++ } else { $failCount++ }
                    $row = & $rowOf $res
                    [void]$rows.Add($row)
                    & $send (@{ type='row' } + $row)
                    # Audit parity with the desktop twin: only the message SEND is a
                    # state-changing host touch (Add-SendResult -> Write-JanetAction
                    # 'TouchHost'). Ping All is read-only there and is NOT logged, so
                    # gate the emit to the send action and skip it for ping. An
                    # unconfirmed delivery audits as Skipped (allowed result), not Failure.
                    if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$res.Host; result=$result; itemCount=$(if($ok){1}else{0}); detail=([string](& $auditDetail $res)) } }
                    $done++
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Watchdog: a wedged host (stuck WinRM, hung msg.exe) must not stall the
            # whole run. BeginStop only - never Dispose here (blocks ~11s); the
            # handle settles via EndStop in the finally below.
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.Async.IsCompleted -and ((Get-Date) - $j.StartTime).TotalSeconds -gt $maxJobSeconds) {
                    try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                    $j.PS = $null
                    $failCount++; $done++
                    $trow = & $rowOf @{ Host=$j.Host; Pingable=$false; Sessions=0; Success=$false; Detail='Job timeout over 90s'; Diagnostic='Aborted by per-job timeout' }
                    [void]$rows.Add($trow)
                    & $send (@{ type='row' } + $trow)
                    if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail='Job timeout over 90s' } }
                    & $send @{ type='log'; level='warn'; text="[$($j.Host)] TIMEOUT after ${maxJobSeconds}s - aborting" }
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                if (-not $cancelling -and (& $cancelCheck)) {
                    # Prefer COOPERATIVE cancel: signal the worker's Cancel flag and let
                    # in-flight workers poll it and return normally so their finally {
                    # Remove-PSSession } fires. BeginStop is reserved as a last resort.
                    $cancelling = $true
                    if ($cancelJob) { try { $cancelJob['Cancel'] = $true } catch { & $send @{ type='log'; level='warn'; text="Could not signal cooperative cancel; relying on grace-window force-stop: $($_.Exception.Message)" } } }
                    $coopDeadline = (Get-Date).AddMilliseconds(8000)
                    & $send @{ type='log'; level='warn'; text='Cancel requested - stopping in-flight job(s) cooperatively...' }
                }
                if ($cancelling -and (Get-Date) -ge $coopDeadline) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                            $j.PS = $null
                            $failCount++; $done++
                            $crow = & $rowOf @{ Host=$j.Host; Pingable=$false; Sessions=0; Success=$false; Detail='cancelled by operator'; Diagnostic='' }
                            [void]$rows.Add($crow)
                            & $send (@{ type='row' } + $crow)
                            if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail='cancelled by operator' } }
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Cancel grace elapsed; remaining host(s) force-stopped (in-flight calls aborted).' }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
    } finally {
        # Let any last-resort BeginStop calls settle before tearing down the pool.
        foreach ($sh in $stopHandles) {
            try { $sh.PS.EndStop($sh.Handle) } catch { & $send @{ type='log'; level='warn'; text="Runspace stop did not settle cleanly: $($_.Exception.Message)" } }
            try { $sh.PS.Dispose() } catch {}
        }
        try { $pool.Close(); $pool.Dispose() }
        catch { & $send @{ type='log'; level='warn'; text="Runspace pool close error: $($_.Exception.Message)" } }
    }

    & $send @{ type='status'; text="Done. $okCount ok, $skipCount unconfirmed, $failCount failed of $($jobs.Count)." }
    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; skipped=$skipCount; failed=$failCount; sent=$okCount } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
