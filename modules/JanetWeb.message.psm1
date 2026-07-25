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
#
#  Changelog
#    1.3.6  audit 2026-07-25 (fable re-audit follow-up): (1) an OVERALL run ceiling
#           reaps whatever the per-job watchdog structurally cannot - a host that
#           never got a runspace has no start stamp and so no clock, which left the
#           drain unbounded by design; (2) the EndInvoke-failure fallback row reports
#           'Worker error' instead of the unmeasured 'Unreachable' claim; (3) a
#           cancelled/abandoned PING row renders a BLANK reachability cell instead of
#           booking 'No' for a probe that never ran (send already did this).
#    1.3.5  audit 2026-07-24 fix pass: (1) wrong-box HARD ABORT inside the remote
#           send block - the box that answered proves its own name before msg.exe
#           runs; (2) the per-job watchdog clock now starts when the worker really
#           STARTS, not at enqueue (a saturated pool was false-timing-out its own
#           backlog); (3) "nobody logged on" + operator TCP-probe skips book as
#           Skipped, not Failure; (4) watchdog-/cancel-abandoned hosts report
#           'Timed out'/'Abandoned' instead of the unmeasured 'Unreachable' claim;
#           (5) dead $okOf / ping $auditDetail bindings dropped.
#    1.3.4  dispatcher self-guard (never message the JANET console host itself).
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'message'
        name     = 'Remote Message'
        version  = '1.3.6'   # audit 2026-07-25 (fable re-audit follow-up): overall run ceiling, honest worker-error + unmeasured-ping rows
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

# -----------------------------------------------------------------------------
#  Dispatcher self-guard (self-contained - COPIED from JanetWeb.restart.psm1's
#  Get-JanetLocalIdentity/Test-JanetHostIsSelf; NO cross-import). The SEND action is
#  destructive=$true: it opens a WinRM session to each target and pops msg.exe on every
#  interactive session there. A target that resolves to THIS box (WinRM loopback) would
#  pop a message ON the JANET console host itself, so we drop it from the fan-out BEFORE
#  any session is opened (parity with restart/acas/wpt/beta). Ping All is read-only and
#  stays self-inclusive (never calls this).
# -----------------------------------------------------------------------------
function Get-JanetMessageLocalIdentity {
    # Every identity that names THIS dispatcher host: shortname, FQDN, all NIC IPs,
    # loopback. Case-insensitive HashSet, computed once and cached.
    # Unary comma keeps the HashSet intact through the pipeline so the
    # OrdinalIgnoreCase comparer survives (parity-ledger row-9; audit 2026-07-23).
    if ($script:MessageLocalIdentity) { return ,$script:MessageLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    # Also add every locally-BOUND unicast IPv4 (mgmt/OOB NICs, lagging DNS): a bound IP
    # not registered under this box's own name would otherwise be missed by the DNS lookup
    # above, letting a pasted IP-literal target slip past the self-guard.
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:MessageLocalIdentity = $set
    return ,$set
}

# True when a target token names THIS dispatcher host (short / FQDN / NIC IP / loopback).
# An IPv4 literal is only self if it is one of our own NIC IPs (exact set match) or a
# 127.x loopback - never via the shortname-alias branch (IPv4-literal-safe).
function Test-JanetMessageHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetMessageLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }                      # any loopback literal
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }  # shortname alias, hostnames only
    }
    return $false
}

# -----------------------------------------------------------------------------
#  Verdict helpers (audit 2026-07-24). These were inline scriptblocks inside the
#  dispatcher; they are plain functions now ONLY so the honesty rules below are
#  unit-testable without opening a WinRM session. The worker's $r.MsgStatus is the
#  single source of truth for both.
# -----------------------------------------------------------------------------

# Audit verdict for one send result. A confirmed delivery is Success. Three
# outcomes are SKIPS, not failures, because the tool changed nothing and claims
# nothing (audit 2026-07-24 - "nobody logged on" and an operator-requested probe
# skip were both booked as Failure, which inflated the failure count and made the
# audit trail read as if the tool had tried and lost):
#   Unknown    - reached the host, msg.exe gave no clear success/error signal;
#   NoSessions - nobody is logged on, so there is no session to pop a message on;
#   Skipped    - the operator asked us to skip hosts failing the TCP probe.
# Everything else (WinRM error, wrong box, msg.exe failure, timeout, cancel) is a
# real Failure.
function Get-JanetMessageSendVerdict {
    param([bool]$Success, [string]$MsgStatus)
    if ($Success) { return 'Success' }
    if (@('Unknown','NoSessions','Skipped') -contains $MsgStatus) { return 'Skipped' }
    return 'Failure'
}

# Display Status for one row. 'Unreachable' is an AFFIRMATIVE network claim and is
# only ever emitted when the probe actually ran and the host stayed silent - a host
# we abandoned (watchdog timeout / operator cancel) was never measured, so it
# reports its real disposition instead (audit 2026-07-24).
function Get-JanetMessageRowStatus {
    param([bool]$Success, [string]$MsgStatus, [bool]$Pingable)
    if ($Success) { return 'Delivered' }
    switch ($MsgStatus) {
        'Unknown'    { return 'Unknown' }
        'NoSessions' { return 'No sessions' }
        'Skipped'    { return 'Skipped' }
        'TimedOut'   { return 'Timed out' }
        'Cancelled'  { return 'Abandoned' }
        'WrongBox'   { return 'Wrong host' }
        # audit 2026-07-25 (fable re-audit follow-up): a runspace that blew up inside
        # EndInvoke told us NOTHING about the target's network - it is OUR failure, not
        # the host's. It used to fall through to the affirmative 'Unreachable' claim.
        'WorkerError' { return 'Worker error' }
    }
    if ($Pingable) { return 'Undelivered' }
    return 'Unreachable'
}

# Per-job watchdog decision (audit 2026-07-24). $StartedAt is the stamp the worker
# writes into the shared start-map the instant it BEGINS executing - a host still
# queued behind a busy runspace pool has no stamp and can therefore never expire,
# no matter how long it has waited for a free runspace. The old code clocked from
# BeginInvoke (enqueue), so a pool narrower than the target list declared its own
# backlog timed-out before those hosts ever ran.
function Test-JanetMessageJobExpired {
    param($StartedAt, [datetime]$Now, [int]$LimitSeconds)
    if (-not $StartedAt) { return $false }
    return ((($Now - [datetime]$StartedAt).TotalSeconds) -gt $LimitSeconds)
}

# Overall run ceiling (audit 2026-07-25 (fable re-audit follow-up)). The per-job
# watchdog above is deliberately blind to a host that never STARTED, so it cannot
# reap one: if a watchdog-stopped runspace never releases its slot, the hosts still
# queued behind it have no clock at all and the drain loop would spin forever. That
# was previously bounded only INDIRECTLY (New-PSSessionOption -CancelTimeout 5000
# caps a BeginStop, and operator cancel is still an exit) - i.e. by luck, not by
# design. This gives the WHOLE run a hard wall-clock ceiling so the pool always
# drains: one full per-job window for every WAVE the pool must run (ceil(total /
# threads)), plus one wave of slack, so a legitimately slow-but-progressing run is
# never cut short. Pure + total: never throws, never returns less than one window.
function Get-JanetMessageRunCeilingSeconds {
    param([int]$Total, [int]$Threads, [int]$PerJobSeconds)
    if ($Total -lt 1) { $Total = 1 }
    if ($Threads -lt 1) { $Threads = 1 }
    if ($PerJobSeconds -lt 1) { $PerJobSeconds = 1 }
    $waves = [Math]::Ceiling($Total / [double]$Threads)
    return [int](($waves + 1) * $PerJobSeconds)
}

# Per-host worker: ping, then deliver the popup to every interactive session.
# Returns the desktop result shape { Host; Success; Sessions; Pingable; Error;
# Detail; Diagnostic }; the harvest loop turns it into a streamed row.
$script:MessageWorker = {
    param($hostname, $title, $body, $timeoutSec, $requireOK, $requirePing, $cred, $openMs, $opMs, $cancelJob, $startMap)
    # Watchdog start stamp (audit 2026-07-24): FIRST statement, so the per-job clock
    # measures actual runtime and not the time this host spent queued for a runspace.
    # Same cross-runspace idiom as the synchronized $cancelJob hashtable.
    if ($startMap) { try { $startMap[$hostname] = Get-Date } catch {} }
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
    # audit 2026-07-24: this is an OPERATOR-REQUESTED skip, not a failure - flag it so
    # the verdict helper books it Skipped (we never attempted a delivery to lose).
    if ($requirePing -and -not $tcpUp) { $r.MsgStatus = 'Skipped'; $r.Detail = 'Host not reachable (skipped: failed TCP 5985/5986/445 probe)'; return $r }
    # Ping is advisory by default: attempt WinRM even when ICMP is blocked (hardened
    # hosts often allow WinRM while dropping ICMP); mark Unreachable only if WinRM fails.
    # audit 2026-07-24: a cancelled host was abandoned, never measured - MsgStatus keeps
    # the row off the affirmative 'Unreachable' claim.
    if (& $isCancelled) { $r.MsgStatus = 'Cancelled'; $r.Detail = 'cancelled by operator'; return $r }

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
            if (& $isCancelled) { $r.MsgStatus = 'Cancelled'; $r.Detail = 'cancelled by operator'; return $r }
            # Wrong-box guard (audit 2026-07-24): the dialed name is resolved by DNS, so a
            # stale record / reused IP can land this destructive send on a DIFFERENT machine
            # than the operator typed. An IPv4 literal has no DNS indirection (the box at that
            # IP IS the box) and its first dot-token could never equal a COMPUTERNAME, so ''
            # skips the compare for IPs - same expected-name shape as restart/pkginstall.
            $expectedName = if ($hostname -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($hostname -split '\.')[0] }
            $sr = Invoke-Command -Session $session -ScriptBlock {
                param($t, $b, $to, $req, $expected)
                # HARD ABORT before msg.exe: the box that answered runs THIS block, so
                # $env:COMPUTERNAME is the real machine. If it isn't the one we dialed, pop
                # nothing (identical idiom to JanetWeb.restart.psm1's shutdown guard).
                if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                    return @{ Count = 0; Status = 'WrongBox'
                              Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no message sent"
                              Diagnostic = "wrongbox.expected=$expected | wrongbox.actual=$($env:COMPUTERNAME)" }
                }
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
                # audit 2026-07-24: nobody logged on is a SKIP, not a failure - there is no
                # session to pop a message on, so nothing was attempted and nothing lost.
                if ($sids.Count -eq 0) { return @{ Count = 0; Status = 'NoSessions'; Error = 'No interactive user sessions detected on target (nothing to message)'; Diagnostic = ($diag -join ' | ') } }

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
            } -ArgumentList $title, $body, $timeoutSec, $requireOK, $expectedName -ErrorAction Stop

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
    param($hostname, $startMap)
    # Watchdog start stamp - see the send worker (audit 2026-07-24).
    if ($startMap) { try { $startMap[$hostname] = Get-Date } catch {} }
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

    # Shared start-map for the per-job watchdog (audit 2026-07-24): each worker stamps
    # its own start time here the instant it begins running, so the watchdog measures
    # RUNTIME instead of enqueue-age. Declared before the arg factories below because
    # they close over it. Keys are hostnames (already de-duplicated case-insensitively
    # by ConvertTo-MessageHostList, and a PS hashtable is case-insensitive too).
    $startMap = [hashtable]::Synchronized(@{})

    $targets = ConvertTo-MessageHostList ([string]$Params['targets'])
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    # Self-guard (parity with restart/acas/wpt/beta): the SEND action is destructive
    # (destructive=$true) - it WinRM-connects to each target and pops msg.exe on every
    # interactive session. A target that resolves to THIS dispatcher would pop a message
    # on the operator's own console (self-WinRM-loopback), so drop it from the fan-out
    # BEFORE any session is opened, and short-circuit cleanly if nothing is left. Ping All
    # is read-only and stays self-inclusive (never dropped).
    if ($ActionId -eq 'send') {
        $selfHits = @($targets | Where-Object { Test-JanetMessageHostIsSelf $_ })
        if ($selfHits.Count -gt 0) {
            & $send @{ type='log'; level='warn'; text="Self-guard: dropped dispatcher host from the send wave (never message the JANET console host itself): $($selfHits -join ', ')" }
            $targets = @($targets | Where-Object { -not (Test-JanetMessageHostIsSelf $_) })
        }
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='Nothing left after the self-guard - only the dispatcher host was targeted.' }
            return @{ rows=@(); summary=@{ total=0 } }
        }
    }

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
        $argFactory = { param($h) ,@($h, $startMap) }
        # audit 2026-07-24: no $auditDetail / $okOf here - Ping All is read-only, emits no
        # audit event at all (the emit is gated to 'send'), and the harvest loop derives
        # $ok from $resultOf. Both bindings were dead.
        # audit 2026-07-25 (fable re-audit follow-up): Pingable stays EMPTY (not 'No')
        # when the probe never ran. Cancelling a sweep - and the watchdog/worker-error
        # rows below - hand this projection Pingable=$null, and the old [bool] cast turned
        # every one of them into an affirmative "this host is NOT reachable" claim we had
        # not measured. Same honesty rule the send projection already carries.
        $rowOf = { param($r) @{ Host=$r.Host; Pingable=$(if ($null -eq $r.Pingable) { '' } else { [bool]$r.Pingable }) } }
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
        $argFactory = { param($h) ,@($h, $title, $body, $timeout, $requireOK, $requirePing, $Credential, $openMs, $opMs, $cancelJob, $startMap) }
        $auditDetail = { param($r) $r.Detail }
        # Diagnostic is not a column, so it surfaces in the row popup / export without widening the table.
        # audit 2026-07-24: Status/verdict moved into the shared helpers above (they are the
        # honesty rules, and they are unit-tested); $okOf dropped - the harvest loop already
        # derives $ok from $resultOf, so it was dead in both branches.
        # Pingable stays EMPTY (not 'No') when the probe never ran - same audit 2026-07-24
        # honesty rule as the Status above; the view renders a blank REACHABLE cell.
        $rowOf = { param($r) @{ Host=$r.Host; Pingable=$(if ($null -eq $r.Pingable) { '' } else { [bool]$r.Pingable }); Sessions=[int]$r.Sessions; Status=(Get-JanetMessageRowStatus ([bool]$r.Success) ([string]$r.MsgStatus) ([bool]$r.Pingable)); Detail=$r.Detail; Diagnostic=[string]$r.Diagnostic } }
        # Audit honesty (ported from SECRET, extended by audit 2026-07-24): a confirmed
        # delivery is Success; unconfirmed / nobody-logged-on / operator-skipped are Skipped
        # (nothing-confirmed-done, and nothing lost); everything else is a real Failure.
        $resultOf = { param($r) Get-JanetMessageSendVerdict ([bool]$r.Success) ([string]$r.MsgStatus) }
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
        # audit 2026-07-24: NO enqueue timestamp here - BeginInvoke only QUEUES the work
        # when the pool is saturated. The watchdog reads $startMap, which the worker
        # itself stamps once it is actually running.
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke() })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0; $skipCount = 0
    $stopHandles = New-Object System.Collections.ArrayList   # captured BeginStop handles (last-resort cancel)
    $cancelling  = $false                                    # cooperative-drain mode after operator cancel
    $coopDeadline = [datetime]::MaxValue                     # grace window for workers to return on their own
    $maxJobSeconds = 90                                      # per-job wall-clock watchdog (desktop parity)
    # audit 2026-07-25 (fable re-audit follow-up): overall wall-clock ceiling for the
    # WHOLE run. The per-job watchdog only clocks hosts that actually started, so a host
    # that never gets a runspace (a stopped runspace whose stop never settles) is
    # structurally un-reapable by it - the drain was therefore unbounded BY DESIGN.
    # This ceiling is the never-started reaper: when it fires, every host still holding a
    # live PS is booked TimedOut (an honest 'Timed out', never an unmeasured network
    # claim) and the loop exits, so the pool ALWAYS drains.
    $runCeilingSeconds = Get-JanetMessageRunCeilingSeconds -Total $jobs.Count -Threads $threads -PerJobSeconds $maxJobSeconds
    $runDeadline = (Get-Date).AddSeconds($runCeilingSeconds)
    try {
        while ($done -lt $jobs.Count) {
            foreach ($j in $jobs) {
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    # audit 2026-07-25 (fable re-audit follow-up): a worker that blew up is
                    # OUR fault and tells us nothing about the target - MsgStatus='WorkerError'
                    # (Status 'Worker error') and Pingable=$null (blank cell), instead of the
                    # old Pingable=$false + no MsgStatus, which fell through to the affirmative
                    # 'Unreachable' claim for a host whose network we never measured.
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ Host=$j.Host; Pingable=$null; Success=$false; Sessions=0; MsgStatus='WorkerError'; Detail="worker error: $($_.Exception.Message)"; Diagnostic='' } }
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
                    # unconfirmed delivery - and, since audit 2026-07-24, a nobody-logged-on
                    # host and an operator probe-skip - audits Skipped (allowed result).
                    if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$res.Host; result=$result; itemCount=$(if($ok){1}else{0}); detail=([string](& $auditDetail $res)) } }
                    $done++
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Watchdog: a wedged host (stuck WinRM, hung msg.exe) must not stall the
            # whole run. BeginStop only - never Dispose here (blocks ~11s); the
            # handle settles via EndStop in the finally below. audit 2026-07-24: the
            # clock runs from the worker's OWN start stamp, so a host still waiting for
            # a free runspace is never declared timed-out before it ever ran; and the row
            # says 'Timed out' rather than asserting an unmeasured 'Unreachable'.
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.Async.IsCompleted -and (Test-JanetMessageJobExpired $startMap[$j.Host] (Get-Date) $maxJobSeconds)) {
                    try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                    $j.PS = $null
                    $failCount++; $done++
                    $tdetail = "Abandoned: no result after ${maxJobSeconds}s of run time (delivery state unknown)"
                    $trow = & $rowOf @{ Host=$j.Host; Pingable=$null; Sessions=0; Success=$false; MsgStatus='TimedOut'; Detail=$tdetail; Diagnostic='Aborted by per-job timeout' }
                    [void]$rows.Add($trow)
                    & $send (@{ type='row' } + $trow)
                    if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$tdetail } }
                    & $send @{ type='log'; level='warn'; text="[$($j.Host)] TIMEOUT after ${maxJobSeconds}s of run time - abandoning" }
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Overall run ceiling (audit 2026-07-25 (fable re-audit follow-up)): the last
            # backstop, above the per-job watchdog. Anything still outstanding here -
            # including a host that never started and therefore never had a per-job clock -
            # is booked 'Timed out' and the run ends. Never claims reachability it did not
            # measure (Pingable=$null -> blank cell).
            if ($done -lt $jobs.Count -and (Get-Date) -ge $runDeadline) {
                foreach ($j in $jobs) {
                    if ($j.PS) {
                        try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                        $j.PS = $null
                        $failCount++; $done++
                        $cdetail = "Abandoned: overall run ceiling of ${runCeilingSeconds}s reached before this host produced a result (delivery state unknown)"
                        $ceilRow = & $rowOf @{ Host=$j.Host; Pingable=$null; Sessions=0; Success=$false; MsgStatus='TimedOut'; Detail=$cdetail; Diagnostic='Aborted by overall run ceiling' }
                        [void]$rows.Add($ceilRow)
                        & $send (@{ type='row' } + $ceilRow)
                        if ($ActionId -eq 'send') { & $send @{ type='audit'; action='TouchHost'; target=$j.Host; result='Failure'; itemCount=0; detail=$cdetail } }
                    }
                }
                & $send @{ type='log'; level='warn'; text="Overall run ceiling of ${runCeilingSeconds}s reached - remaining host(s) abandoned so the run always drains." }
                & $send @{ type='progress'; done=$done; total=$jobs.Count }
                break
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
                            # audit 2026-07-24: 'Abandoned', not 'Unreachable' - we stopped
                            # this host on operator request and never measured its network.
                            $crow = & $rowOf @{ Host=$j.Host; Pingable=$null; Sessions=0; Success=$false; MsgStatus='Cancelled'; Detail='cancelled by operator'; Diagnostic='' }
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

    # audit 2026-07-24: 'skipped' now covers unconfirmed + nobody-logged-on + probe skips.
    & $send @{ type='status'; text="Done. $okCount ok, $skipCount skipped, $failCount failed of $($jobs.Count)." }
    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; skipped=$skipCount; failed=$failCount; sent=$okCount } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Test-JanetMessageHostIsSelf
