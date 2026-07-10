# =============================================================================
#  JanetWeb.beta.psm1  ->  Beta Lab (tool id: 'beta')
#
#  Staging ground for experimental / in-development JANET Web features. Each beta
#  feature is its own action with its own tab in web/js/views/beta.view.js; once a
#  feature is proven it graduates into its own real tool and is retired from here.
#
#  ACTIVE FEATURE: C2C Quarantine Killer
#    The C2C "C2C Quarantine" scheduled task keeps getting recreated on endpoints
#    (the quarantine cycle re-registers it). A one-shot fleet delete does not stick.
#    This feature installs a PERSISTENT SYSTEM watchdog scheduled task on each host
#    ("JANET C2C Quarantine Killer") that runs every 90 minutes (tunable) and, at
#    boot when a run was missed, deletes the "C2C Quarantine" task whenever it comes
#    back. Install also fires the watchdog once so the task is gone immediately.
#      status   (read-only) - per host: is "C2C Quarantine" present? and is our killer
#                             actually RUNNING (not just installed)? Reports watchdog
#                             run-health from Get-ScheduledTaskInfo (last run / result /
#                             next run). Safe verification, changes nothing.
#      install  (DESTRUCTIVE -> admin session + confirm word INSTALL) - register the
#                             SYSTEM watchdog (every N min) and run it once now.
#      remove   (DESTRUCTIVE -> admin session + confirm word REMOVE) - unregister the
#                             watchdog (undo). Leaves "C2C Quarantine" alone.
#    The watchdog deletes by NAME across all task folders (Get-ScheduledTask |
#    Unregister-ScheduledTask). The target task name is validated (no quotes/;) so it
#    is safe to embed in the SYSTEM -Command payload. The JANET dispatcher host is
#    self-guarded out of every state-changing run.
#
#  To add another beta section: add an action to Get-JanetToolManifest, a switch arm
#  in Invoke-JanetToolAction, and a tab in web/js/views/beta.view.js.
#
#  Contract: Get-JanetToolManifest / Invoke-JanetToolAction -> { rows; summary }.
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

# --- constants -----------------------------------------------------------------
# The watchdog we install. Deliberately DISTINCT from the target so the watchdog can
# never delete itself (see Get-BetaKillerCommand + the unit test).
function Get-BetaKillerTaskName    { 'JANET C2C Quarantine Killer' }
# The task we hunt and delete. Operator-overridable input defaults to this.
function Get-BetaDefaultTargetTask { 'C2C Quarantine' }

function Get-JanetToolManifest {
    $defTarget = Get-BetaDefaultTargetTask
    @{
        id       = 'beta'
        name     = 'Beta Lab'
        version  = '0.7.0'
        category = 'Beta'
        summary  = 'Experimental fleet features that bake here before graduating. ACTIVE: C2C Quarantine Killer - install a persistent SYSTEM watchdog scheduled task on each host that deletes the recreated "C2C Quarantine" task every 90 minutes (tunable), so a one-shot delete that would just come back is replaced by a self-healing kill. Status is read-only and CONFIRMS the watchdog is actually running (a Watchdog column: HEALTHY / RUNNING / NEVER RAN / DISABLED / LAST FAILED / NOT INSTALLED, from the task''s real last-run/next-run history), not merely installed. Install/Remove are admin-gated + confirm-worded and self-guard the JANET host out.'
        actions  = @(
            @{
                id          = 'status'
                label       = 'Check Status (read-only)'
                description = "READ-ONLY (no admin session, no confirm). Per host, one WinRM round-trip: is the ""$defTarget"" scheduled task present (the thing we want gone), and - crucially - is the JANET C2C Quarantine Killer watchdog actually RUNNING, not just installed. The Watchdog column reports run-health from the task's real history (Get-ScheduledTaskInfo): HEALTHY (last run OK) / RUNNING / NEVER RAN / DISABLED / LAST FAILED / NOT INSTALLED, and the Detail shows last run time, result and next scheduled run. Status QUARANTINE PRESENT (target task still there) / CLEAN (target absent). Reachability is TCP-only (5985/5986/445); never writes anything."
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Status','Watchdog','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='targetTask'; label='Target task name to hunt'; type='text'; required=$false; default=$defTarget },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'install'
                label       = 'Install Quarantine Killer'
                description = "DESTRUCTIVE (registers a SYSTEM scheduled task) - requires a live admin session and the exact confirm word INSTALL. Per host over WinRM: register the ""JANET C2C Quarantine Killer"" watchdog running as SYSTEM every N minutes (default 90, StartWhenAvailable so a boot-missed run fires after startup), whose action deletes the ""$defTarget"" task by name across all folders, then run it ONCE now so the task is gone immediately. Idempotent (-Force): a host that already has the watchdog is UPDATED. Wrong-box HARD abort + dispatcher self-guard + per-host watchdog + operator cancel."
                kind        = 'stream-table'
                destructive = $true
                confirm     = "Install the SYSTEM watchdog on the target host(s)? It registers a scheduled task that deletes ""$defTarget"" every 90 minutes and runs once now. Proceed?"
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='targetTask'; label='Target task name to delete'; type='text'; required=$false; default=$defTarget },
                    @{ name='intervalMinutes'; label='Run every N minutes (5-1440)'; type='int'; required=$false; default=90 },
                    @{ name='confirm'; label='Type INSTALL to confirm'; type='text'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 }
                )
            }
            @{
                id          = 'remove'
                label       = 'Remove Quarantine Killer'
                description = 'DESTRUCTIVE (unregisters the SYSTEM watchdog) - requires a live admin session and the exact confirm word REMOVE. Per host over WinRM: unregister the "JANET C2C Quarantine Killer" watchdog (undo of Install). Leaves the target task alone. A host that never had the watchdog is NOT PRESENT. Wrong-box HARD abort + dispatcher self-guard + operator cancel.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Remove the SYSTEM watchdog from the target host(s)? After this the "C2C Quarantine" task will no longer be auto-deleted. Proceed?'
                columns     = @('Host','Ping','Status','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='confirm'; label='Type REMOVE to confirm'; type='text'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-16)'; type='int'; required=$false; default=8 }
                )
            }
        )
    }
}

# =============================================================================
#  PURE helpers (unit-tested; the pool worker MIRRORS Get-BetaKillerCommand inline
#  because it runs in a bare runspace and cannot call back into this module).
# =============================================================================

# Task names allowed into a remote SYSTEM command string: letters, digits, space,
# dot, underscore, hyphen. Forbids quotes / ';' / '&' / '|' so the name cannot break
# out of the single-quoted -TaskName in the payload (SYSTEM code-injection guard).
function Test-BetaTaskName {
    param([string]$Name)
    $n = ([string]$Name).Trim()
    if ([string]::IsNullOrWhiteSpace($n)) { return $false }
    if ($n.Length -gt 240) { return $false }
    return ($n -match '^[A-Za-z0-9 ._\-]+$')
}

# The SYSTEM -Command payload the watchdog runs every N minutes: delete the target
# task by NAME wherever it lives. $false is escaped so it is literal in the stored
# command. TargetTask MUST have passed Test-BetaTaskName first (no quote breakout).
function Get-BetaKillerCommand {
    param([string]$TargetTask)
    $t = ([string]$TargetTask).Trim()
    return "Get-ScheduledTask -TaskName '$t' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:`$false -ErrorAction SilentlyContinue"
}

# Classify whether the installed watchdog is actually RUNNING, from Get-ScheduledTaskInfo
# fields (LastRunTime / LastTaskResult / NextRunTime). "Installed" is not "running": a
# Disabled task, a task that has never fired, or one whose last run failed are all
# INSTALLED but not confirmed running. PURE + unit-tested; computed ADMIN-SIDE (the worker
# returns the raw fields) so there is no bare-runspace mirror to keep in sync.
#   NOT INSTALLED - no watchdog task
#   DISABLED      - present but the task State is Disabled (will not run)
#   NEVER RAN     - present + enabled but LastRunTime is empty / result = task-has-not-run
#   LAST FAILED   - last run returned a non-zero, non-running result code
#   RUNNING       - executing right now
#   HEALTHY       - last run completed with result 0 (confirmed running on schedule)
function Get-BetaWatchdogHealth {
    param([bool]$Present, [string]$State, [string]$LastRun, $LastResult, [string]$NextRun, [int]$MissedRuns = 0, [string]$Interval = '')
    if (-not $Present) { return @{ Word = 'NOT INSTALLED'; Detail = 'watchdog NOT installed on this host' } }
    $st  = [string]$State
    $res = $null
    if ($null -ne $LastResult -and "$LastResult" -ne '') { try { $res = [int64]$LastResult } catch { $res = $null } }
    $nextTxt = if ($NextRun) { "next run $NextRun" } else { 'NO next run scheduled' }
    $repTxt  = if ($Interval) { " (repeats $Interval)" } else { '' }
    if ($st -match '(?i)disabled') { return @{ Word = 'DISABLED'; Detail = 'watchdog is INSTALLED but DISABLED - it will NOT run' } }
    if (-not $LastRun -or $res -eq 267011) {   # 0x00041303 SCHED_S_TASK_HAS_NOT_RUN
        return @{ Word = 'NEVER RAN'; Detail = "watchdog INSTALLED (State $st) but has NOT run yet; $nextTxt$repTxt" }
    }
    if ($st -match '(?i)running' -or $res -eq 267009) {   # 0x00041301 SCHED_S_TASK_RUNNING
        return @{ Word = 'RUNNING'; Detail = "watchdog is RUNNING now; last completed $LastRun; $nextTxt$repTxt" }
    }
    if ($null -ne $res -and $res -ne 0) {
        return @{ Word = 'LAST FAILED'; Detail = "watchdog INSTALLED but its LAST RUN FAILED (result $res) at $LastRun; $nextTxt$repTxt" }
    }
    $missTxt = if ($MissedRuns -gt 0) { "; $MissedRuns missed run(s)" } else { '' }
    return @{ Word = 'HEALTHY'; Detail = "watchdog HEALTHY - last ran $LastRun (result OK); $nextTxt$repTxt$missTxt" }
}

# --- self-guard (COPIED from JanetWeb.certdeploy.psm1) -------------------------
# Identities that resolve to THIS dispatcher host - dropped from every state-changing
# run so JANET never registers/removes a task on the box it is running on.
function Get-JanetBetaLocalIdentity {
    if ($script:BetaLocalIdentity) { return $script:BetaLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:BetaLocalIdentity = $set
    return $set
}

function Test-JanetBetaHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetBetaLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    if ($Target -match '^::1$')  { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

# --- bool coercion (view sends real bools; CLI/tests may send strings) ---------
function Get-BetaBool {
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return (@('true','1','yes','on') -contains ([string]$Value).Trim().ToLowerInvariant())
}

# =============================================================================
#  ONE per-host pool worker for all three modes. Runs in a bare RunspacePool
#  runspace (cannot call module functions). Does TCP reachability -> WinRM session
#  -> wrong-box guard, then a mode-specific remote Invoke-Command. Returns
#  @{ Host; Ping; Status; Detail; Ok; Audit }.
# =============================================================================
$script:BetaWorker = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string]$Mode, [string]$TargetTask, [string]$KillerTask, [int]$IntervalMinutes)

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Ok=$false; Audit='Failure' }
    $errStatus = if ($Mode -eq 'status') { 'CHECK ERROR' } else { 'FAILED' }

    # Reachability: pure-TCP probe (AFNET-safe; never ICMP). WinRM HTTP 5985, then WinRM
    # HTTPS 5986, then SMB 445 (liveness only), 1.5s, break on first connect (5985 tried
    # first so HTTP wins when both are open). $useSsl tracks whether ONLY 5986 answered,
    # so the session below auto-switches to -UseSSL.
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.Status = 'OFFLINE'; $r.Audit = 'Skipped'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'; return $r }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is common
    # on AFNET, so skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    $soP = @{ OperationTimeout=120000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = $errStatus; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # Wrong-box guard: compare the answering box's name to the dialed short name. For a
    # state-changing run this is a HARD ABORT before anything is registered/removed;
    # read-only status soft-skips. IP-literal targets have no DNS indirection.
    try {
        $expectedShort = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }
        if ($expectedShort) {
            $answering = Invoke-Command -Session $sess -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            if (([string]$answering).Trim().ToUpper() -ne $expectedShort.Trim().ToUpper()) {
                Remove-PSSession $sess -ErrorAction SilentlyContinue
                if ($Mode -eq 'status') { $r.Status = 'CHECK ERROR'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - soft-skipped, nothing read" }
                else { $r.Status = 'SKIPPED'; $r.Audit = 'Skipped'; $r.Detail = "DNS MISMATCH: dialed '$expectedShort' but remote is '$answering' - ABORTED, nothing changed" }
                return $r
            }
        }
    } catch {
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        $r.Status = $errStatus; $r.Detail = "wrong-box guard probe failed: $($_.Exception.Message)"; return $r
    }

    try {
        switch ($Mode) {
            'status' {
                # RUN-PROOF: don't just report the watchdog is present - pull its actual run
                # history (Get-ScheduledTaskInfo: LastRunTime / LastTaskResult / NextRunTime)
                # and the real repeat interval off the trigger, so the operator can confirm it
                # is genuinely firing, not merely registered. A never-run task's LastRunTime is
                # a pre-2000 sentinel -> normalize to empty.
                $raw = Invoke-Command -Session $sess -ArgumentList $TargetTask, $KillerTask -ErrorAction Stop -ScriptBlock {
                    param($TargetTask, $KillerTask)
                    $q = [bool](Get-ScheduledTask -TaskName $TargetTask -ErrorAction SilentlyContinue)
                    $k = Get-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue
                    $state=''; $lastRun=''; $lastRes=$null; $nextRun=''; $missed=0; $interval=''
                    if ($k) {
                        $k0 = @($k)[0]; $state = [string]$k0.State
                        try { $interval = [string]$k0.Triggers[0].Repetition.Interval } catch {}
                        try {
                            $info = Get-ScheduledTaskInfo -TaskName $KillerTask -ErrorAction SilentlyContinue
                            if ($info) {
                                if ($info.LastRunTime -and $info.LastRunTime.Year -ge 2000) { $lastRun = $info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') }
                                if ($null -ne $info.LastTaskResult) { $lastRes = [int64]$info.LastTaskResult }
                                if ($info.NextRunTime -and $info.NextRunTime.Year -ge 2000) { $nextRun = $info.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') }
                                try { $missed = [int]$info.NumberOfMissedRuns } catch {}
                            }
                        } catch {}
                    }
                    [pscustomobject]@{ QuarantinePresent=$q; KillerPresent=[bool]$k; KillerState=$state; LastRun=$lastRun; LastResult=$lastRes; NextRun=$nextRun; Missed=$missed; Interval=$interval }
                }
                if ($null -eq $raw) { $r.Status = 'CHECK ERROR'; $r.Detail = 'probe returned no result'; return $r }
                $r.Ok = $true; $r.Audit = 'Skipped'
                # Stash the raw watchdog fields; the fan-out driver (module scope) classifies
                # health via Get-BetaWatchdogHealth and fills the Watchdog column + Detail.
                $r.Wd = @{ Present=[bool]$raw.KillerPresent; State=[string]$raw.KillerState; LastRun=[string]$raw.LastRun; LastResult=$raw.LastResult; NextRun=[string]$raw.NextRun; Missed=[int]$raw.Missed; Interval=[string]$raw.Interval }
                if ([bool]$raw.QuarantinePresent) { $r.Status = 'QUARANTINE PRESENT'; $r.Detail = "'$TargetTask' task is present" }
                else { $r.Status = 'CLEAN'; $r.Detail = "'$TargetTask' task absent" }
                return $r
            }
            'install' {
                $killerCmd = "Get-ScheduledTask -TaskName '$TargetTask' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:`$false -ErrorAction SilentlyContinue"
                $raw = Invoke-Command -Session $sess -ArgumentList $TargetTask, $KillerTask, $IntervalMinutes, $killerCmd -ErrorAction Stop -ScriptBlock {
                    param($TargetTask, $KillerTask, $IntervalMinutes, $KillerCmd)
                    $existedBefore = [bool](Get-ScheduledTask -TaskName $TargetTask -ErrorAction SilentlyContinue)
                    $killerBefore  = [bool](Get-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue)
                    $arg     = "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$KillerCmd`""
                    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
                    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                                   -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
                                   -RepetitionDuration (New-TimeSpan -Days 3650)
                    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
                    $stSet   = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                                   -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
                    Register-ScheduledTask -TaskName $KillerTask -Action $action -Trigger $trigger -Principal $princ -Settings $stSet -Force -ErrorAction Stop | Out-Null
                    # Fire once now so the target task is gone immediately, not in up to N minutes.
                    Start-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                    $existsAfter = [bool](Get-ScheduledTask -TaskName $TargetTask -ErrorAction SilentlyContinue)
                    # Confirm the watchdog is now registered + scheduled (proof the install took).
                    $kState=''; $kNext=''
                    try { $kt = Get-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue; if ($kt) { $kState = [string]@($kt)[0].State } } catch {}
                    try { $ki = Get-ScheduledTaskInfo -TaskName $KillerTask -ErrorAction SilentlyContinue; if ($ki -and $ki.NextRunTime -and $ki.NextRunTime.Year -ge 2000) { $kNext = $ki.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } } catch {}
                    [pscustomobject]@{ ExistedBefore=$existedBefore; KillerBefore=$killerBefore; ExistsAfter=$existsAfter; KillerState=$kState; KillerNext=$kNext }
                }
                if ($null -eq $raw) { $r.Status = 'FAILED'; $r.Detail = 'installer returned no result'; return $r }
                $r.Ok = $true; $r.Audit = 'Success'
                $r.Status = if ([bool]$raw.KillerBefore) { 'UPDATED' } else { 'INSTALLED' }
                $bits = New-Object System.Collections.ArrayList
                # Confirm the schedule took: report the registered State + the actual next run.
                $schedTxt = "watchdog runs every ${IntervalMinutes}m as SYSTEM"
                if ([string]$raw.KillerState) { $schedTxt += " (State $([string]$raw.KillerState)" + $(if ([string]$raw.KillerNext) { "; next run $([string]$raw.KillerNext))" } else { ')' }) }
                [void]$bits.Add($schedTxt)
                if ([bool]$raw.ExistedBefore) {
                    if ([bool]$raw.ExistsAfter) { [void]$bits.Add("'$TargetTask' was present but STILL present after first run (recreated or in a folder the delete missed)") }
                    else { [void]$bits.Add("'$TargetTask' was present and deleted now") }
                } else {
                    [void]$bits.Add("'$TargetTask' not present (nothing to delete yet)")
                }
                $r.Detail = ($bits -join '; ') + '.'
                return $r
            }
            'remove' {
                $raw = Invoke-Command -Session $sess -ArgumentList $KillerTask -ErrorAction Stop -ScriptBlock {
                    param($KillerTask)
                    $before = [bool](Get-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue)
                    if ($before) { Unregister-ScheduledTask -TaskName $KillerTask -Confirm:$false -ErrorAction Stop }
                    $after = [bool](Get-ScheduledTask -TaskName $KillerTask -ErrorAction SilentlyContinue)
                    [pscustomobject]@{ Before=$before; After=$after }
                }
                if ($null -eq $raw) { $r.Status = 'FAILED'; $r.Detail = 'remove returned no result'; return $r }
                $r.Ok = $true; $r.Audit = 'Success'
                if (-not [bool]$raw.Before) { $r.Status = 'NOT PRESENT'; $r.Audit = 'Skipped'; $r.Detail = 'watchdog was not installed here - nothing to remove.' }
                elseif ([bool]$raw.After) { $r.Status = 'FAILED'; $r.Detail = 'watchdog still present after Unregister - remove did not take.' }
                else { $r.Status = 'REMOVED'; $r.Detail = "watchdog unregistered; '$TargetTask' is no longer auto-deleted." }
                return $r
            }
        }
    } catch {
        $r.Status = $errStatus; $r.Detail = "$Mode failed: $($_.Exception.Message)"; return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    return $r
}

# =============================================================================
#  ONE fan-out driver for all three modes (validate -> self-guard -> runspace pool
#  -> poll with per-host timeout + operator cancel -> summarize). Mirrors the
#  certdeploy fan-out loop.
# =============================================================================
function Invoke-BetaAction {
    param(
        [ValidateSet('status','install','remove')] [string]$Mode,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    $killerTask = Get-BetaKillerTaskName

    # Confirm-word gate FIRST for state-changing modes (before anything is dialed).
    if ($Mode -eq 'install' -and (([string]$Params['confirm']).Trim() -cne 'INSTALL')) {
        & $send @{ type='log'; level='err'; text='Confirm word mismatch: type INSTALL (exactly) to install the watchdog. Nothing was changed.' }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }
    if ($Mode -eq 'remove' -and (([string]$Params['confirm']).Trim() -cne 'REMOVE')) {
        & $send @{ type='log'; level='err'; text='Confirm word mismatch: type REMOVE (exactly) to remove the watchdog. Nothing was changed.' }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    # Target task name (status + install). Validated so it is safe to embed in the
    # SYSTEM -Command payload. Remove does not need it (it only touches our own task).
    $targetTask = ([string]$Params['targetTask']).Trim()
    if (-not $targetTask) { $targetTask = Get-BetaDefaultTargetTask }
    if ($Mode -ne 'remove' -and -not (Test-BetaTaskName $targetTask)) {
        & $send @{ type='log'; level='err'; text="Rejected target task name '$targetTask' - only letters, digits, space, dot, underscore and hyphen are allowed (no quotes/semicolons). Nothing was changed." }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    $intervalMinutes = 90
    if ($Params['intervalMinutes']) { [int]::TryParse([string]$Params['intervalMinutes'], [ref]$intervalMinutes) | Out-Null }
    $intervalMinutes = [Math]::Max(5, [Math]::Min(1440, $intervalMinutes))

    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $rows = New-Object System.Collections.ArrayList

    # Self-guard state-changing runs: drop the dispatcher host (SKIPPED row each).
    $dial = New-Object System.Collections.ArrayList
    if ($Mode -eq 'status') {
        foreach ($t in $targets) { [void]$dial.Add($t) }
    } else {
        $selfSkipped = New-Object System.Collections.ArrayList
        foreach ($t in $targets) {
            if (Test-JanetBetaHostIsSelf $t) {
                [void]$selfSkipped.Add($t)
                $row = @{ Host=$t; Ping=''; Status='SKIPPED'; Detail='self-guard: dispatcher/local host - refused (never register/remove a task on the JANET server mid-run)' }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            } else { [void]$dial.Add($t) }
        }
        if ($selfSkipped.Count -gt 0) { & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host ($($selfSkipped -join ', '))." } }
        if ($dial.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='Nothing left after the self-guard - only the dispatcher host was targeted.' }
            return @{ rows=@($rows); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
        }
    }

    $threadsMax = if ($Mode -eq 'status') { 32 } else { 16 }
    $threads = if ($Mode -eq 'status') { 16 } else { 8 }
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min($threadsMax, $threads))
    $perHostTimeout = 150
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    $verb = switch ($Mode) { 'status' { 'Status check' } 'install' { 'Install watchdog' } 'remove' { 'Remove watchdog' } }
    & $send @{ type='status'; text="$verb on $($dial.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START $verb on $($dial.Count) host(s) ($authLabel), $threads thread(s). Target task '$targetTask', watchdog '$killerTask'$(if ($Mode -eq 'install') { ", every ${intervalMinutes}m" } else { '' })." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    foreach ($h in $dial) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $dial) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:BetaWorker)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth)
        [void]$ps.AddArgument((Get-BetaBool $Params['attemptOffline'] $false)); [void]$ps.AddArgument($Mode); [void]$ps.AddArgument($targetTask); [void]$ps.AddArgument($killerTask); [void]$ps.AddArgument($intervalMinutes)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $emitResult = {
        param($res)
        $row = @{ Host=[string]$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail; Watchdog='' }
        # Watchdog run-health (status mode carries the raw $res.Wd fields). Classified here,
        # in module scope, so Get-BetaWatchdogHealth is reused (not mirrored into the worker).
        if ($res.Wd) {
            $h = Get-BetaWatchdogHealth -Present ([bool]$res.Wd.Present) -State ([string]$res.Wd.State) -LastRun ([string]$res.Wd.LastRun) -LastResult $res.Wd.LastResult -NextRun ([string]$res.Wd.NextRun) -MissedRuns ([int]$res.Wd.Missed) -Interval ([string]$res.Wd.Interval)
            $row.Watchdog = [string]$h.Word
            $row.Detail   = (([string]$row.Detail).TrimEnd('.',' ') + '; ' + [string]$h.Detail)
        }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $st = [string]$row.Status
        $lvl = 'info'
        if     (@('INSTALLED','UPDATED','REMOVED','CLEAN','NOT PRESENT') -contains $st) { $lvl = 'ok' }
        elseif (@('QUARANTINE PRESENT','OFFLINE','SKIPPED') -contains $st)              { $lvl = 'warn' }
        elseif (@('FAILED','CHECK ERROR','Cancelled') -contains $st)                    { $lvl = 'error' }
        & $send @{ type='log'; level=$lvl; text="[$(Get-Date -Format 'HH:mm:ss')] $([string]$row.Host) : $st - $([string]$row.Detail)" }
        # State-changing runs are audited (read-only status is not a state change).
        if ($Mode -ne 'status') {
            & $send @{ type='audit'; action='TouchHost'; target=$row.Host; result=[string]$res.Audit; itemCount=1; detail="$Mode C2C Quarantine Killer - $st - $([string]$row.Detail)" }
        }
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            # Cap the per-host clock to the pool's real concurrency, stamping in queue order:
            # a PS queued in a saturated RunspacePool reports State='Running' immediately, so the
            # old InvocationStateInfo check stamped StartedAt at ENQUEUE for every job and the
            # watchdog then falsely timed out the whole backlog at once (~threads*timeout hosts in).
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="worker error: $($_.Exception.Message)"; Audit='Failure' } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail='worker returned no result'; Audit='Failure' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="per-host timeout (${perHostTimeout}s) - possible remote hang"; Audit='Failure' }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Audit='Skipped' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight work stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    $ok       = @($rows | Where-Object { @('INSTALLED','UPDATED','REMOVED','CLEAN','NOT PRESENT') -contains [string]$_.Status }).Count
    $attn     = @($rows | Where-Object { @('QUARANTINE PRESENT','FAILED') -contains [string]$_.Status }).Count
    $offline  = @($rows | Where-Object { [string]$_.Status -eq 'OFFLINE' }).Count
    $errors   = @($rows | Where-Object { @('CHECK ERROR','SKIPPED','Cancelled') -contains [string]$_.Status }).Count
    & $send @{ type='log'; level='ok'; text="$verb done - OK: $ok, ATTENTION: $attn, OFFLINE: $offline, SKIPPED/ERROR: $errors (of $($rows.Count) row(s))." }
    # Status mode also rolls up watchdog RUN-health so a fleet check confirms it is firing.
    $wdSummary = @{}
    if ($Mode -eq 'status') {
        $wdRunning = @($rows | Where-Object { @('HEALTHY','RUNNING') -contains [string]$_.Watchdog }).Count
        $wdNotRun  = @($rows | Where-Object { @('DISABLED','NEVER RAN','LAST FAILED') -contains [string]$_.Watchdog }).Count
        $wdMissing = @($rows | Where-Object { [string]$_.Watchdog -eq 'NOT INSTALLED' }).Count
        $wdSummary = @{ running=$wdRunning; notRunning=$wdNotRun; notInstalled=$wdMissing }
        $lvl = if (($wdNotRun + $wdMissing) -gt 0) { 'warn' } else { 'ok' }
        & $send @{ type='log'; level=$lvl; text="Watchdog run-health: $wdRunning CONFIRMED RUNNING, $wdNotRun installed-but-not-running (disabled/never-ran/last-failed), $wdMissing NOT installed." }
    }
    & $send @{ type='status'; text="Done. $ok ok, $attn attention, $offline offline of $($rows.Count)." }
    return @{ rows=@($rows); summary=@{ total=$rows.Count; ok=$ok; attention=$attn; offline=$offline; errors=$errors; mode=$Mode; intervalMinutes=$intervalMinutes; targetTask=$targetTask; watchdog=$wdSummary } }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    switch ($ActionId) {
        'status'  { return (Invoke-BetaAction -Mode 'status'  -Params $Params -Credential $Credential -Emit $Emit) }
        'install' { return (Invoke-BetaAction -Mode 'install' -Params $Params -Credential $Credential -Emit $Emit) }
        'remove'  { return (Invoke-BetaAction -Mode 'remove'  -Params $Params -Credential $Credential -Emit $Emit) }
        default {
            & $send @{ type='error'; text="Beta Lab: unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Invoke-BetaAction, Test-BetaTaskName, Get-BetaKillerCommand, Get-BetaWatchdogHealth, Get-BetaKillerTaskName, Get-BetaDefaultTargetTask, Test-JanetBetaHostIsSelf, Get-BetaBool
