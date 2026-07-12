# =============================================================================
#  JanetWeb.remoteadmin.psm1  ->  Remote Admin (Open C$ + Run Script)
#
#  Net-new JANET Web tool. Two operator-requested capabilities:
#
#    open-cshare (READ-ONLY / non-destructive) - open \\<computer>\C$ in Explorer.
#      JANET Web runs as a loopback HttpListener INSIDE the operator's interactive
#      session, and tool actions run in runspaces in that SAME process/session, so
#      Start-Process explorer.exe surfaces the window on the operator's OWN desktop
#      (never a hidden/service session). Strict name validation; audited (accessing
#      an admin share is security-relevant). Needs no admin session.
#
#    run-script (DESTRUCTIVE) - fan an operator-authored PowerShell block to one or
#      many hosts over WinRM. Arbitrary remote code, so it is declared destructive
#      and the server 403s it unless a live admin session (ack + credential) exists.
#      Mirrors the WPT Custom Command SHA256 forensic audit (hash + preview logged
#      up front, stamped into every per-host audit record) and the dispatcher
#      self-guard (never runs against the JANET dispatcher host - an arbitrary block
#      hitting our own box could kill the HttpListener mid-dispatch).
#
#  Pure, unit-testable logic lives in named helpers (Test-RemoteAdminComputerName,
#  Get-RemoteAdminSharePath, Get-RemoteAdminShortHash, Get-RemoteAdminTargets,
#  Get-RemoteAdminTruncatedOutput, the self-guard trio) so the Pester suite drives
#  them with NO WinRM and NO Explorer. The boundary commands (Test-RemoteAdminReachable
#  / New-PSSession / Invoke-Command / Start-RemoteAdminShare) are named functions so
#  tests shim them (mirrors tests\Wpt.Guards.Tests.ps1 / Sysadmin.Sweeps.Tests.ps1).
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

# Own module path, captured at load, so a pool runspace can Import-Module it to get
# the helper functions (the run-script worker calls Test-RemoteAdminReachable etc.).
$script:RemoteAdminModulePath = $PSCommandPath

function Get-JanetToolManifest {
    @{
        id       = 'remoteadmin'
        name     = 'Remote Admin'
        version  = '1.0.0'
        category = 'Operations'
        summary  = 'Two operator hands-on-keyboard capabilities. Open C$: launch \\<computer>\C$ in Explorer on your own session by computer name (strict name validation, audited; needs no admin session). Run Script: fan an operator-authored PowerShell block to one or many hosts over WinRM - arbitrary remote code, so it is destructive and rides the admin-session gate, mirrors the WPT Custom Command SHA256 forensic audit, and self-guards the JANET dispatcher host out of every run.'
        actions  = @(
            @{
                id          = 'open-cshare'
                label       = 'Open C$'
                description = 'Open the C$ administrative share (\\<computer>\C$) of a single machine in Windows Explorer on the operator''s own session. Read-only / non-destructive: it only launches Explorer against the UNC path (no files are read, written, or changed by JANET). The computer name is strictly validated (bare hostname or IPv4 only). The share access is written to the audit trail.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Computer','Path','Status','Detail')
                inputs      = @(
                    @{ name='computer'; label='Computer name'; type='text'; required=$true }
                )
            }
            @{
                id          = 'run-script'
                label       = 'Run Script'
                description = 'Run an operator-authored PowerShell script block remotely on one or more hosts over WinRM and stream each host''s output. DESTRUCTIVE (arbitrary remote code): requires a live admin session (ADW credential + responsibility ack). The dispatcher self-guards the JANET host out of the run, and the script body is recorded to the audit trail by SHA256 hash + preview before it fans out.'
                kind        = 'stream-table'
                destructive = $true
                columns     = @('Host','Online','Status','Output','Error')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='script'; label='PowerShell script block'; type='textarea'; required=$true },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=8 },
                    @{ name='timeoutSeconds'; label='Per-host timeout (seconds, 15-900)'; type='int'; required=$false; default=120 }
                )
            }
        )
    }
}

# --- Pure, unit-testable helpers -------------------------------------------

# Accept ONLY a bare hostname or IPv4 literal: first char alphanumeric, then up to
# 254 of [alnum . _ -]. Rejects blanks, spaces, quotes, backslashes, UNC (\\srv\c$),
# forward slashes, and any injection punctuation - so nothing but a machine name can
# reach Start-Process / a UNC path.
function Test-RemoteAdminComputerName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($Name -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')
}

# Build the C$ admin-share UNC path for an ALREADY-VALIDATED computer name.
function Get-RemoteAdminSharePath {
    param([string]$Computer)
    return ('\\{0}\C$' -f $Computer)
}

# Short SHA256 (first 6 bytes -> 12 hex) of a text body - a deterministic forensic
# fingerprint for the run-script audit trail. Mirrors the WPT Custom Command hash.
function Get-RemoteAdminShortHash {
    param([string]$Text)
    if ($null -eq $Text) { $Text = '' }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hb  = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        $sha.Dispose()
        return (-join ($hb[0..5] | ForEach-Object { $_.ToString('x2') }))
    } catch { return 'nohash' }
}

# Strict target parse: split on whitespace/comma/semicolon, keep only bare
# host / IPv4 tokens, drop UNC/URL/junk, de-dup. Same guard the sysadmin tool uses.
function Get-RemoteAdminTargets {
    param([string]$Raw)
    return @(([string]$Raw) -split '[\r\n,;\t ]+' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and (Test-RemoteAdminComputerName -Name $_) } |
        Select-Object -Unique)
}

# Cap remote output to $Max chars (server-side) so one chatty host can't flood the
# grid / audit log; appends a visible truncation note when it trims.
function Get-RemoteAdminTruncatedOutput {
    param([string]$Text, [int]$Max = 4000)
    if ($null -eq $Text) { return '' }
    if ($Max -lt 1) { $Max = 1 }
    if ($Text.Length -le $Max) { return $Text }
    return ($Text.Substring(0, $Max) + "`n...[output truncated at $Max chars]")
}

# --- Dispatcher self-guard (Wpt-local mirror, re-implemented not cross-imported) --
# Set of identities that resolve to THIS dispatcher host: shortname, FQDN, the
# hostname's DNS-registered addresses, EVERY locally-bound NIC IPv4, and loopback.
# Used to drop the JANET box from a run-script wave - an arbitrary operator block
# hitting our own host could kill the HttpListener mid-dispatch and abandon every
# other host. The bound-NIC enumeration (mirrors the c2c Mass Fix self-guard) is
# the belt to DNS's suspenders: on a multi-homed dispatcher a live interface IP may
# not be registered under the box's hostname in DNS, so a DNS-only set would let
# that IP slip the guard. Computed once and cached; try/catch so an odd network
# stack still loads.
function Get-RemoteAdminLocalIdentity {
    # NOTE the unary comma on both returns: without it PowerShell UNROLLS the
    # HashSet into the output stream and the caller gets an Object[] - whose
    # .Contains is case-SENSITIVE, silently defeating the OrdinalIgnoreCase
    # comparer for hostname matching. ',$set' returns the HashSet intact.
    if ($script:RemoteAdminLocalIdentity) { return ,$script:RemoteAdminLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    # DNS forward-lookup of the hostname (can miss an unregistered interface IP)...
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    # ...and every ACTUALLY-BOUND local IPv4, which DNS can't miss (mirrors c2c).
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:RemoteAdminLocalIdentity = $set
    return ,$set
}

# True if a target token names this dispatcher host (short/FQDN/IP/loopback).
function Test-RemoteAdminHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-RemoteAdminLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }                      # any loopback literal
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }  # shortname alias, hostnames only
    }
    return $false
}

# Drop the JANET dispatcher host from a run-script wave. Warns via -Send when it
# drops one. Returns @{ Targets=<string[] kept>; SkippedCount=<int> }.
function Remove-RemoteAdminSelfTargets {
    param([string[]]$Targets, [scriptblock]$Send)
    $selfSkipped = New-Object System.Collections.ArrayList
    $kept = New-Object System.Collections.ArrayList
    foreach ($t in $Targets) {
        if (Test-RemoteAdminHostIsSelf $t) { [void]$selfSkipped.Add($t) } else { [void]$kept.Add($t) }
    }
    if ($selfSkipped.Count -gt 0 -and $Send) {
        & $Send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host from this run ($($selfSkipped -join ', ')) - an arbitrary remote block must never run against the box hosting this session." }
    }
    return @{ Targets = $kept.ToArray(); SkippedCount = $selfSkipped.Count }
}

# --- Reachability (AFNET-safe: TCP only, NEVER ICMP) ------------------------
# Named so the Pester suite can shim it and drive the post-reachability path.
# Default ladder is the WinRM pair (5985 HTTP, 5986 HTTPS) + SMB 445 liveness;
# break on first connect, so 5985 wins when both WinRM ports are open. Callers
# that only want the SMB-445 share-reachability signal (open-cshare) pass
# -Ports @(445) and never see $UseSsl. $UseSsl is an optional [ref] out-param -
# set $true ONLY when the port that answered is 5986 - so a caller that opens a
# WinRM session afterwards (the run-script worker) knows to dial -UseSSL.
function Test-RemoteAdminReachable {
    param([string]$ComputerName, [int[]]$Ports = @(5985, 5986, 445), [int]$TimeoutMs = 1500, [ref]$UseSsl)
    if ($UseSsl) { $UseSsl.Value = $false }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    foreach ($port in $Ports) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($ComputerName, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) {
                if ($UseSsl -and $port -eq 5986) { $UseSsl.Value = $true }
                return $true
            }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}

# --- Explorer launch (named boundary so tests shim it; never spawns in a test) --
function Start-RemoteAdminShare {
    param([string]$Computer)
    # See the file header: this runs in the operator's interactive session, so the
    # Explorer window opens on the operator's OWN desktop. Named + mockable so the
    # Pester suite replaces it and never actually spawns Explorer.
    Start-Process -FilePath 'explorer.exe' -ArgumentList (Get-RemoteAdminSharePath -Computer $Computer)
}

# --- Per-host worker for run-script (runs in a pool runspace; also runnable in
#     module scope for the tests). Returns @{ Host; Online; Status; Output; Error }.
#     Reachability / session / remote invoke go through named commands so tests can
#     shim them and assert the row shape with NO real WinRM.
$script:RemoteAdminScriptBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string]$ScriptText, [int]$TimeoutSeconds, [int]$MaxOutput, [string]$ModulePath)

    if (-not (Get-Command Test-RemoteAdminReachable -ErrorAction SilentlyContinue)) {
        if ($ModulePath) { try { Import-Module $ModulePath -Force -ErrorAction Stop } catch {} }
    }

    $r = @{ Host = $Computer; Online = $false; Status = 'Failed'; Output = ''; Error = '' }

    # $useSsl comes back via the [ref] out-param: $true ONLY when the host answered
    # ONLY on WinRM HTTPS 5986 (5985 is tried first and wins on a break when both are
    # open), so the session below auto-switches to -UseSSL for a 5986-only host.
    $useSsl = $false
    $reachable = Test-RemoteAdminReachable -ComputerName $Computer -UseSsl ([ref]$useSsl)
    if (-not $reachable) {
        $r.Status = 'Offline'; $r.Error = 'Offline (no TCP on 5985/5986/445)'
        return $r
    }
    $r.Online = $true

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is
    # common on AFNET, so skip CA/CN validation - the transport stays encrypted).
    $opTimeout = [Math]::Max(15000, $TimeoutSeconds * 1000)
    $soP = @{ OperationTimeout = $opTimeout; OpenTimeout = 15000; CancelTimeout = 5000; IdleTimeout = 60000 }
    if ($useSsl) { $soP['SkipCACheck'] = $true; $soP['SkipCNCheck'] = $true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName = $Computer; SessionOption = $wsOpt; ErrorAction = 'Stop' }
    if ($useSsl) { $splat['UseSSL'] = $true }
    if ($Cred) { $splat['Credential'] = $Cred; $splat['Authentication'] = $Auth }

    $sess = $null
    try { $sess = New-PSSession @splat }
    catch { $r.Status = 'Session error'; $r.Error = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box guard (HARD ABORT, before any operator code runs): compare the
    # answering box's name to the dialed short name. If DNS resolved the target to a
    # different (or the dispatcher's own) host, the operator's ARBITRARY scriptblock
    # would otherwise run on the WRONG box. IP-literal targets have no DNS indirection.
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                $r.Status = 'Skipped'
                $r.Error = "DNS MISMATCH: dialed '$Computer' but '$(([string]$answering).Trim())' answered - ABORTED, operator block NOT run"
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = 'Failed'
        $r.Error = "wrong-box guard probe failed: $($_.Exception.Message)"
        return $r
    }

    try {
        # Recreate the operator block INSIDE the worker (scriptblocks don't cross
        # runspace boundaries cleanly; the text does). Already parse-validated up
        # front in the dispatcher. 2>&1 merges the error stream into the captured
        # output so a non-terminating remote error still shows; a TERMINATING error
        # throws to the catch below and marks the host Failed.
        $sb = [scriptblock]::Create($ScriptText)
        $raw = Invoke-Command -Session $sess -ScriptBlock $sb -ErrorAction Stop 2>&1 | Out-String
        $r.Output = Get-RemoteAdminTruncatedOutput -Text $raw -Max $MaxOutput
        $r.Status = 'Success'
    } catch {
        $r.Status = 'Failed'; $r.Error = $_.Exception.Message
    } finally { if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} } }

    return $r
}

# --- open-cshare: single-machine Explorer launch ----------------------------
function Invoke-RemoteAdminOpenCShare {
    param([hashtable]$Params, [scriptblock]$Send)
    $computer = ([string]$Params['computer']).Trim()

    if (-not (Test-RemoteAdminComputerName -Name $computer)) {
        & $Send @{ type='log'; level='warn'; text="Rejected computer name '$computer' - only a bare hostname or IPv4 is allowed (no spaces, quotes, backslashes, or UNC)." }
        $row = @{ _rk='r1'; Computer=$computer; Path=''; Status='Rejected'; Detail='invalid computer name' }
        & $Send (@{ type='row' } + $row)
        & $Send @{ type='status'; text='Rejected: invalid computer name.' }
        return @{ rows=@($row); summary=@{ total=1; rejected=1 } }
    }

    $path = Get-RemoteAdminSharePath -Computer $computer
    $reachable = $false
    try { $reachable = Test-RemoteAdminReachable -ComputerName $computer -Ports @(445) } catch {}

    $status = ''; $detail = ''
    try {
        Start-RemoteAdminShare -Computer $computer | Out-Null
        $status = if ($reachable) { 'Opened' } else { 'Opened (host was unreachable on 445)' }
        $detail = "Launched Explorer on $path"
        # Accessing an admin share is security-relevant - record it.
        & $Send @{ type='audit'; action='TouchHost'; target=$computer; result='Success'; itemCount=1; detail="Opened admin share $path" }
    } catch {
        $status = 'Failed'; $detail = $_.Exception.Message
    }

    $row = @{ _rk='r1'; Computer=$computer; Path=$path; Status=$status; Detail=$detail }
    & $Send (@{ type='row' } + $row)
    $lvl = if ($status -eq 'Failed') { 'err' } elseif ($status -like 'Opened*') { 'ok' } else { 'warn' }
    & $Send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $computer : $status - $detail" }
    & $Send @{ type='status'; text="$computer : $status" }
    return @{ rows=@($row); summary=@{ total=1; opened=$(if ($status -like 'Opened*') { 1 } else { 0 }) } }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    if ($ActionId -eq 'open-cshare') {
        return Invoke-RemoteAdminOpenCShare -Params $Params -Send $send
    }

    if ($ActionId -ne 'run-script') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # ---- run-script ----
    # Parse the operator block up front so a syntax error fails fast with a clean
    # message and never fans out (mirrors WPT Custom Command).
    $scriptText = [string]$Params['script']
    if ([string]::IsNullOrWhiteSpace($scriptText)) {
        & $send @{ type='log'; level='warn'; text='Run Script requires a non-empty PowerShell script block.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    try { [void][scriptblock]::Create($scriptText) }
    catch {
        & $send @{ type='log'; level='err'; text="Script failed to parse: $($_.Exception.Message)" }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    # Strict target parse, then self-guard (drop the JANET box before any WinRM).
    $targets = @(Get-RemoteAdminTargets -Raw ([string]$Params['targets']))
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }
    $guard = Remove-RemoteAdminSelfTargets -Targets $targets -Send $send
    $targets = @($guard.Targets)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='Every target was the JANET dispatcher host (self-guard). Nothing to run.' }
        return @{ rows=@(); summary=@{ total=0; selfSkipped=$guard.SkippedCount } }
    }

    $threads = 8
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $timeoutSeconds = 120
    if ($Params['timeoutSeconds']) { [int]::TryParse([string]$Params['timeoutSeconds'], [ref]$timeoutSeconds) | Out-Null }
    $timeoutSeconds = [Math]::Max(15, [Math]::Min(900, $timeoutSeconds))
    $maxOutput = 4000

    # Operator-cancel bridge (server injects $Params['__job']).
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    # ---- FORENSIC AUDIT (mirror WPT Custom Command) ----
    # Arbitrary operator text is about to fan out to a remote scriptblock. Record the
    # body (hash + truncated preview) once up front, and stamp the short hash into
    # every per-host audit Detail so post-hoc review can reconstruct what ran.
    $scriptHash = Get-RemoteAdminShortHash -Text $scriptText
    $scriptFlat = ($scriptText -replace '\s+', ' ').Trim()
    $scriptLogText = if ($scriptFlat.Length -gt 500) { $scriptFlat.Substring(0, 500) + '... (truncated)' } else { $scriptFlat }
    $scriptAuditTag = " | script sha256:$scriptHash"
    & $send @{ type='log'; level='warn'; text="Run Script (sha256:$scriptHash) fanning out to $($targets.Count) host(s) ($authLabel): $scriptLogText" }
    & $send @{ type='audit'; action='TouchHost'; target='(run-script)'; result='Skipped'; itemCount=0; detail="Run Script queued for $($targets.Count) host(s) (pre-run forensic record; per-host audits carry the real result); sha256:$scriptHash; body: $scriptLogText" }

    & $send @{ type='status'; text="Run Script on $($targets.Count) host(s) with $threads thread(s)..." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:RemoteAdminScriptBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth)
        [void]$ps.AddArgument($scriptText); [void]$ps.AddArgument($timeoutSeconds); [void]$ps.AddArgument($maxOutput)
        [void]$ps.AddArgument($script:RemoteAdminModulePath)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList
    # Reference-type counter so the $emitResult scriptblock (invoked with &, a child
    # scope) mutates the SHARED object in place - a plain $rk++ would write a child-
    # scope local and never advance, giving every row the same _rk. ok/fail are
    # tallied from $rows AFTER the loop for the same reason.
    $rowState = @{ rk = 0 }

    $emitResult = {
        param($res)
        $rowState.rk++
        $row = @{
            _rk    = ('r{0}' -f $rowState.rk)
            Host   = [string]$res.Host
            Online = [bool]$res.Online
            Status = [string]$res.Status
            Output = [string]$res.Output
            Error  = [string]$res.Error
        }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $ok = ([string]$res.Status -eq 'Success')
        $auditResult = if ($ok) { 'Success' } else { 'Failure' }
        $detail = "Status=$($res.Status)"
        if ($res.Error) { $detail += "; $($res.Error)" }
        $detail += $scriptAuditTag
        & $send @{ type='audit'; action='TouchHost'; target=[string]$res.Host; result=$auditResult; itemCount=$(if ($ok) { 1 } else { 0 }); detail=$detail }
        $lvl = if ($ok) { 'ok' } elseif ([string]$res.Status -eq 'Offline' -or [string]$res.Status -eq 'Timeout') { 'warn' } else { 'err' }
        & $send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $($res.Host) : $($res.Status)$(if ($res.Error) { ' - ' + $res.Error } else { '' })" }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Stamp the per-host clock only up to the pool's real concurrency, in queue order: a PS
            # queued in a saturated RunspacePool reports State='Running' at once, so the old check
            # stamped StartedAt at ENQUEUE and the watchdog false-timed-out the backlog (~threads*timeout in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Online=$false; Status='Failed'; Output=''; Error="worker error: $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Online=$false; Status='Failed'; Output=''; Error='worker returned no result' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own timeout.
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $timeoutSeconds) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Online=$true; Status='Timeout'; Output=''; Error="per-host timeout (${timeoutSeconds}s) - the remote block was still running and has been abandoned" }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Online=$false; Status='Failed'; Output=''; Error='cancelled by operator' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight remote blocks stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    # Tally from the emitted rows (child-scope & invocation can't advance a counter).
    $okCount = @($rows | Where-Object { [string]$_.Status -eq 'Success' }).Count
    $failCount = @($rows).Count - $okCount
    $summary = @{ total=$targets.Count; succeeded=$okCount; failed=$failCount; selfSkipped=$guard.SkippedCount; scriptSha256=$scriptHash }
    & $send @{ type='log'; level='ok'; text="Done. $okCount succeeded, $failCount failed of $($targets.Count) host(s)." }
    & $send @{ type='status'; text="Done. $okCount ok, $failCount failed of $($targets.Count)." }
    return @{ rows=@($rows); summary=$summary }
}

Export-ModuleMember -Function `
    Get-JanetToolManifest, Invoke-JanetToolAction, Invoke-RemoteAdminOpenCShare, `
    Test-RemoteAdminComputerName, Get-RemoteAdminSharePath, Get-RemoteAdminShortHash, `
    Get-RemoteAdminTargets, Get-RemoteAdminTruncatedOutput, `
    Get-RemoteAdminLocalIdentity, Test-RemoteAdminHostIsSelf, Remove-RemoteAdminSelfTargets, `
    Test-RemoteAdminReachable, Start-RemoteAdminShare
