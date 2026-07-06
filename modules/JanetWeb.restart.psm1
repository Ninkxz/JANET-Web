# =============================================================================
#  JanetWeb.restart.psm1  -  Remote Restart Scheduler engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\RemoteRestartScheduler_1.5.0-beta4.ps1 (the "Convergence
#  build" engine reused, WinForms layer dropped). Fans out shutdown.exe /r
#  commands over WinRM/PSSession to many hosts in parallel via a RunspacePool,
#  with an optional pre-flight ping gate, a server-name skip gate, a never-
#  restart Exceptions list, an interactive user-consent prompt, three dispatch
#  models (burst CONVERGE on a shared time; TIME-GATED, where each worker HOLDS
#  until RestartAt - lead and then fires /t = lead*60; or ROLLING / go-fast
#  where each host reboots ~grace seconds after it approves), a single-host
#  test path, an abort (shutdown /a) fan-out, and a reboot-verification
#  monitor. In every mode except rolling the per-host /t is computed INSIDE the
#  worker at dispatch time, so pool-queue and consent delays converge on the
#  shared RestartAt instead of drifting. The remote shutdown command runs
#  through ProcessStartInfo to dodge
#  PS 5.1's native-command-stderr-as-ErrorRecord behavior (which corrupts the
#  exit code). Exit code 1190 (ERROR_SHUTDOWN_IS_SCHEDULED) is treated as
#  success ('Already-Scheduled').
#
#  Intentional web-model omissions vs the 1.5.0-beta4 desktop build:
#    - The in-app delayed-start arming ("begin dispatch at a scheduled time")
#      and the Schedule-as-Task one-shot auto-run are NOT ported. In the web
#      model the action request itself starts the run; the time gate lives
#      inside the per-host workers (TIME-GATED mode above).
#    - When consent is ON, each prompt PINS its pool slot for the whole prompt
#      window (the desktop's two-phase ConsentLaunch/ConsentPoll releases the
#      slot between polls). Waves larger than the thread count serialize in
#      ~ceil(hosts/threads) prompt-window batches; a warn log states the
#      estimate at dispatch.
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'restart'
        name     = 'Restart Scheduler'
        version  = '1.5.0-beta8'
        category = 'Lifecycle'
        summary  = 'Mass scheduled restart for Windows fleets - parallel shutdown.exe /r over WinRM with optional user consent, ping gate, abort, and reboot verification.'
        actions  = @(
            @{
                id          = 'dispatch-restart'
                label       = 'Dispatch Scheduled Restart'
                description  = 'Fan-out shutdown.exe /r to every target in parallel (1.5.0-beta4 engine). CONVERGE (default): every approved host reboots together at the scheduled time via per-host /t = (RestartAt - now) computed at dispatch time. TIME-GATED (burst and rolling both off): each host holds until RestartAt - lead minutes, then fires with /t = lead*60 - the reboot still lands at RestartAt. ROLLING / go-fast: prompts go out immediately and each host reboots ~grace seconds after IT approves - no shared reboot time. Optional user-consent prompt (default ON), a never-restart Exceptions list, a pre-flight ping gate, and a server-name skip gate all run before WinRM.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Status','DispatchAt','RestartAt','Result','ConsentState')
                inputs       = @(
                    @{ name='targets';              label='Targets (one host per line)';          type='hostlist'; required=$true },
                    @{ name='exceptions';           label='Exceptions - never restart (one host per line)'; type='textarea'; required=$false },
                    @{ name='restartTime';          label='Restart time (ISO 8601 or HH:mm) - shared reboot time in burst and time-gated modes; ignored in rolling mode'; type='text'; required=$true },
                    @{ name='leadMinutes';          label='Lead minutes (time-gated /t)';         type='int';      required=$false; default=15 },
                    @{ name='message';              label='Countdown message ({LEAD} token)';     type='textarea'; required=$false; default='System is restarting for maintenance. Save your work.' },
                    @{ name='burstMode';            label='Burst mode (/t = time-to-restart)';    type='bool';     required=$false; default=$true },
                    @{ name='rollingMode';          label='Rolling / go-fast (reboot each host ~grace after IT approves; no shared time)'; type='bool'; required=$false; default=$false },
                    @{ name='rollingGraceSeconds';  label='Rolling: reboot grace after approve (sec)';     type='int'; required=$false; default=60 },
                    @{ name='dryRun';               label='Dry run (do not actually restart)';    type='bool';     required=$false; default=$false },
                    @{ name='requireConsent';       label='Require user consent prompt';          type='bool';     required=$false; default=$true },
                    @{ name='consentPromptMinutes'; label='Consent prompt window (min)';          type='int';      required=$false; default=5 },
                    @{ name='consentGraceSeconds';  label='Accept grace / save-work (sec)';       type='int';      required=$false; default=60 },
                    @{ name='consentFailMode';      label='If consent prompt fails to run';       type='select';   required=$false; options=@('proceed','skip'); default='proceed' },
                    @{ name='skipServersRegex';     label='Skip servers regex (blank = off)';     type='text';     required=$false; default='^MSEK-[A-Za-z]{2,4}-' },
                    @{ name='skipUnreachablePing';  label='Skip unreachable (pre-flight ping)';   type='bool';     required=$false; default=$true },
                    @{ name='onlyIfPending';        label='Only restart hosts with a pending reboot'; type='bool'; required=$false; default=$false },
                    @{ name='threads';              label='Parallel hosts';                       type='int';      required=$false; default=96 }
                )
            },
            @{
                id          = 'abort-scheduled'
                label       = 'Abort Scheduled Restarts'
                description  = 'Issue shutdown /a to every target in parallel to cancel a pending restart timer. Use after a dispatch to stand the fleet down.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Status','Result')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            },
            @{
                id          = 'test-single-host'
                label       = 'Test Restart On Single Host'
                description  = 'Synchronous single-host restart test over WinRM. Returns exit code, shutdown.exe output, and a plain-English hint for common error codes (0x80090351, TrustedHosts, access denied, DNS, timeout).'
                kind         = 'single'
                destructive  = $true
                columns      = @('Host','ExitCode','Success','Stdout','ErrorHint')
                inputs       = @(
                    @{ name='hostname';    label='Hostname';              type='text';     required=$true },
                    @{ name='leadSeconds'; label='Countdown (seconds, min 30)';   type='int';      required=$false; default=60 },
                    @{ name='message';     label='Popup message';         type='textarea'; required=$false; default='TEST: this machine will restart shortly.' },
                    @{ name='dryRun';      label='Dry run (preview only - do not restart)'; type='bool'; required=$false; default=$false }
                )
            },
            @{
                id          = 'verify-reboots'
                label       = 'Verify Reboots (Reboot Monitor)'
                description  = 'Ping every target on a repeating interval and confirm a reboot via a DOWN-then-UP transition. Reports Rebooted, Online (no reboot seen), Offline, or No contact, with went-down / came-back timestamps.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','State','Went-Down','Came-Back','Result')
                inputs       = @(
                    @{ name='targets';             label='Targets (one host per line)';   type='hostlist'; required=$true },
                    @{ name='pingIntervalSeconds'; label='Ping interval (sec)';            type='int'; required=$false; default=15 },
                    @{ name='timeoutSeconds';      label='Monitor timeout (sec)';          type='int'; required=$false; default=1800 },
                    @{ name='threads';             label='Parallel pings';                 type='int'; required=$false; default=32 }
                )
            },
            @{
                id          = 'verify-boottime'
                label       = 'Verify (WinRM Boot Time)'
                description  = 'Query Win32_OperatingSystem.LastBootUpTime over WinRM for each target and, against an optional reference (the scheduled restart time), return an AUTHORITATIVE verdict that trumps ping inference: RESTARTED - confirmed by boot time; Did NOT restart - confirmed; Online (no reference to compare); or boot-time check failed.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','State','Boot-Time','Result')
                inputs       = @(
                    @{ name='targets';       label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='referenceTime'; label='Restart time to compare (ISO 8601 or HH:mm; blank = report boot time only)'; type='text'; required=$false },
                    @{ name='threads';       label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            },
            @{
                id          = 'ping'
                label       = 'Ping All (Reachability)'
                description  = 'Read-only TCP reachability sweep (WinRM 5985 then SMB 445, never ICMP - AFNET drops ICMP) across the target list. Backs the Targets-tab "Ping All" button; reports each host online/offline without touching it.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Pingable')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true }
                )
            },
            @{
                id          = 'cancel-pending'
                label       = 'Cancel Pending (Info)'
                description  = 'Guidance on stopping a wave. The run-bar Cancel button stops an in-progress dispatch mid-run: remaining hosts are abandoned and in-flight WinRM calls are stopped. Hosts that already received a restart command keep their countdown - run Abort Scheduled Restarts to stand them down.'
                kind         = 'single'
                destructive  = $false
                columns      = @('Status','Detail')
                inputs       = @()
            }
        )
    }
}

# -----------------------------------------------------------------------------
# Hostname parsing (mirrors the original ConvertTo-HostList: case-insensitive
# dedup, leading \\ stripped, comma/space/tab/newline/semicolon separators).
# -----------------------------------------------------------------------------
function ConvertTo-JanetHostList {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim().Trim('\','/').TrimStart('\\')
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        # Accept only a bare host/IPv4 token; drop UNC/URL/junk before New-PSSession.
        if (($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h) }
    }
    return ,$out.ToArray()
}

# Set of identities that resolve to THIS dispatcher host: shortname, FQDN, all
# NIC IPs, and loopback. Used to drop the JANET host from a destructive wave so a
# self-reboot can't kill the HttpListener mid-dispatch (audit#10). Computed once
# and cached. Returns a case-insensitive HashSet.
function Get-JanetLocalIdentity {
    if ($script:JanetLocalIdentity) { return $script:JanetLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    $script:JanetLocalIdentity = $set
    return $set
}

# True if a target token names this dispatcher host (short/FQDN/IP/loopback).
function Test-JanetHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }                      # any loopback literal
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }  # shortname alias, hostnames only
    }
    return $false
}

# -----------------------------------------------------------------------------
# The interactive consent agent. Staged on the target as agent_<token>.ps1 and
# launched in the user's session via a one-shot interactive scheduled task. It
# only RECORDS the choice to a local result JSON; the dispatcher reads it back
# over WinRM and performs the restart with its own admin rights (STIG-safe).
# Single-quoted here-string: every $ is the agent's own code; __TOKEN__ is the
# only per-host substitution. Lifted verbatim from RemoteRestartScheduler 1.4.2.
# -----------------------------------------------------------------------------
$script:ConsentAgentTemplate = @'
# === JANET Consent Agent === runs in the interactive user's session ===
$ErrorActionPreference = 'Stop'
$token      = '__TOKEN__'
$dir        = Join-Path $env:ProgramData 'JANET\Consent'
$cfgPath    = Join-Path $dir ("cfg_$token.json")
$resultPath = Join-Path $dir ("result_$token.json")

function Write-ConsentResult([string]$decision) {
    $o = [ordered]@{
        Token     = $token
        Decision  = $decision
        User      = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        DecidedAt = (Get-Date).ToString('o')
    }
    try { ($o | ConvertTo-Json -Compress) | Out-File -FilePath $resultPath -Encoding UTF8 -Force } catch {}
}

try { $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json }
catch { Write-ConsentResult 'AgentError'; return }

$promptSecs = [int]$cfg.PromptSeconds
$message    = [string]$cfg.Message

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text            = 'System Restart Required'
$form.Size            = New-Object System.Drawing.Size(580, 360)
$form.StartPosition   = 'CenterScreen'
$form.TopMost         = $true
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox     = $false
$form.MinimizeBox     = $false
$form.ShowInTaskbar   = $true
$form.BackColor       = [System.Drawing.Color]::FromArgb(28, 24, 38)
$form.ForeColor       = [System.Drawing.Color]::White

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = 'Scheduled System Restart'
$lblTitle.Font      = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::Gold
$lblTitle.Location  = New-Object System.Drawing.Point(24, 18)
$lblTitle.Size      = New-Object System.Drawing.Size(520, 32)
$form.Controls.Add($lblTitle)

$lblMsg = New-Object System.Windows.Forms.Label
$lblMsg.Text      = $message
$lblMsg.Font      = New-Object System.Drawing.Font('Segoe UI', 11)
$lblMsg.Location  = New-Object System.Drawing.Point(24, 60)
$lblMsg.Size      = New-Object System.Drawing.Size(525, 120)
$form.Controls.Add($lblMsg)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Font      = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Italic)
$lblCount.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
$lblCount.Location  = New-Object System.Drawing.Point(24, 188)
$lblCount.Size      = New-Object System.Drawing.Size(525, 44)
$form.Controls.Add($lblCount)

$btnAccept = New-Object System.Windows.Forms.Button
$btnAccept.Text      = 'Restart now'
$btnAccept.Size      = New-Object System.Drawing.Size(220, 44)
$btnAccept.Location  = New-Object System.Drawing.Point(24, 250)
$btnAccept.FlatStyle = 'Flat'
$btnAccept.BackColor = [System.Drawing.Color]::FromArgb(46, 122, 60)
$btnAccept.ForeColor = [System.Drawing.Color]::White
$btnAccept.Font      = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnAccept)

$btnDecline = New-Object System.Windows.Forms.Button
$btnDecline.Text      = 'Not now'
$btnDecline.Size      = New-Object System.Drawing.Size(220, 44)
$btnDecline.Location  = New-Object System.Drawing.Point(305, 250)
$btnDecline.FlatStyle = 'Flat'
$btnDecline.BackColor = [System.Drawing.Color]::FromArgb(90, 70, 40)
$btnDecline.ForeColor = [System.Drawing.Color]::White
$btnDecline.Font      = New-Object System.Drawing.Font('Segoe UI', 11)
$form.Controls.Add($btnDecline)

$script:decision = $null
$btnAccept.Add_Click({ $script:decision = 'Accepted'; $form.Close() })
$btnDecline.Add_Click({ $script:decision = 'Declined'; $form.Close() })

$deadline = (Get-Date).AddSeconds($promptSecs)
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $rem = [int][Math]::Ceiling((($deadline) - (Get-Date)).TotalSeconds)
    if ($rem -le 0) { $script:decision = 'Timeout'; $timer.Stop(); $form.Close(); return }
    $mm = [int]($rem / 60); $ss = $rem % 60
    $lblCount.Text = ("If you do not choose, this computer will restart automatically in {0}:{1:00}." -f $mm, $ss)
})
$timer.Start()
$form.Add_FormClosing({ $timer.Stop() })
[void]$form.ShowDialog()
if (-not $script:decision) { $script:decision = 'Timeout' }
Write-ConsentResult $script:decision

# Best-effort self-clean. The dispatcher also cleans up over WinRM, so a
# failure here (e.g. a limited user can't delete an admin-created task) is fine.
try { schtasks.exe /Delete /TN ('JANET\Consent_' + $token) /F 2>$null | Out-Null } catch {}
try { Remove-Item -LiteralPath $cfgPath -Force -ErrorAction SilentlyContinue } catch {}
try {
    $self = $MyInvocation.MyCommand.Path
    if ($self) { Start-Sleep -Milliseconds 300; Remove-Item -LiteralPath $self -Force -ErrorAction SilentlyContinue }
} catch {}
'@

# -----------------------------------------------------------------------------
# Per-host DISPATCH worker. Reproduces $script:DispatchScriptBlock from the
# original: ProcessStartInfo-based shutdown.exe (bypasses PS 5.1 native-stderr
# corruption), Negotiate WinRM, 1190 == success. When $consentRequired, it
# first stages the consent agent + a one-shot interactive scheduled task, polls
# the result file, and only restarts on Accept / Timeout / No-User / agent fail
# (Decline -> Skipped this run). The per-host /t is computed HERE at dispatch
# time (post-hold, post-consent) from the shared restart time, so every mode
# except rolling converges on RestartAt no matter how long the host queued.
# NOTE: unlike the desktop's two-phase ConsentLaunch/ConsentPoll, the whole
# per-host lifecycle (hold + prompt window + restart) runs inside ONE runspace
# and PINS its pool slot for the duration - waves larger than the thread count
# serialize in ~ceil(hosts/threads) prompt-window batches when consent is on.
# -----------------------------------------------------------------------------
$script:DispatchWorker = {
    param($hostname, $restartTicks, $mode, $leadMinutes, $rollingGraceSeconds, $message, $dryRun, $cred, $consentRequired, $agentTemplate, $promptSeconds, $consentGraceSeconds, $pollInterval, $consentFailMode, $cancelJob, $onlyIfPending)

    $r = [ordered]@{
        Host         = $hostname
        Status       = 'Pending'
        Success      = $false
        ExitCode     = $null
        Result       = ''
        ConsentState = ''
        Detail       = ''
    }

    # Shared restart time (DateTime round-tripped as ticks) + the relayed
    # operator-cancel flag (the server's synchronized job hashtable; reading a
    # key cross-runspace is safe, and a missing key reads as $false).
    $restartTime = New-Object System.DateTime ([long]$restartTicks)
    $isCancelled = { try { ($null -ne $cancelJob) -and [bool]$cancelJob['Cancel'] } catch { $false } }

    # ----- shutdown dispatch helper (shared by direct + post-consent paths) -----
    $doShutdown = {
        param($targetHost, $sec, $msg, $isDry, $credential, $session)
        $o = @{ Success = $false; ExitCode = $null; Detail = '' }
        try {
            if ($isDry) {
                $authNote = if ($null -ne $credential) { "as $($credential.UserName)" } else { 'current Windows session (CAC)' }
                $o.Success  = $true
                $o.ExitCode = 0
                $o.Detail   = "DRYRUN ($authNote): Invoke-Command $targetHost { shutdown /r /t $sec /c <msg> /f }"
                return $o
            }
            # IP-literal targets have no DNS indirection (the box answering at that IP
            # IS the box), and their first dot-token ('192') can never equal a
            # COMPUTERNAME - so pass '' to skip the name-compare guard for IPs (audit#9).
            $expectedName = if ($targetHost -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($targetHost -split '\.')[0] }
            $icArgs = @{
                ArgumentList   = @($sec, $msg, $expectedName)
                ErrorAction    = 'Stop'
                # ponytail: this remote shutdown block is duplicated in Invoke-RrsShutdownDirect on
                # purpose - this worker runs in a CreateDefault runspace (no module scope), so a
                # shared $script: scriptblock would be $null here and break the reboot. Keep in sync.
                ScriptBlock    = {
                    param($s, $m, $expected)
                    $res = @{ ExitCode = $null; Output = ''; Error = '' }
                    # DNS-mismatch guard (HARD ABORT): the box that answered runs this
                    # block, so $env:COMPUTERNAME IS the real machine. If it isn't the
                    # one we dialed (stale DNS / reused IP), abort before shutdown.exe.
                    if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                        $res.Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no shutdown sent"
                        return $res
                    }
                    try {
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName               = 'shutdown.exe'
                        $psi.UseShellExecute        = $false
                        $psi.RedirectStandardOutput = $true
                        $psi.RedirectStandardError  = $true
                        $psi.CreateNoWindow         = $true
                        # Strip CR/LF first (a newline in the message can break the /c token),
                        # then quote-escape. Single-line messages are unaffected.
                        $msgArg = '"' + ($m -replace '[\r\n]+',' ' -replace '"','\"') + '"'
                        $psi.Arguments = "/r /t $s /c $msgArg /f"
                        $p = [System.Diagnostics.Process]::Start($psi)
                        $stdout = $p.StandardOutput.ReadToEnd()
                        $stderr = $p.StandardError.ReadToEnd()
                        if (-not $p.WaitForExit(30000)) {
                            try { $p.Kill() } catch {}
                            $res.ExitCode = -1
                            $res.Output   = 'shutdown.exe timed out after 30s'
                        } else {
                            $res.ExitCode = $p.ExitCode
                            $res.Output   = (($stdout + $stderr) | Out-String).Trim()
                        }
                    } catch {
                        $res.Error = $_.Exception.Message
                    }
                    return $res
                }
            }
            if ($null -ne $session) {
                # Consent path: reuse the single open WinRM session (launch + every
                # poll + this shutdown share one connection).
                $icArgs['Session'] = $session
            } else {
                # Direct path (consent off): open a per-call WinRM connection, as before.
                $icArgs['ComputerName']   = $targetHost
                $icArgs['Authentication'] = 'Negotiate'
                $icArgs['SessionOption']  = (New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000)
                if ($null -ne $credential) { $icArgs['Credential'] = $credential }
            }
            $remote = Invoke-Command @icArgs
            if ($remote.Error) {
                $o.ExitCode = -3
                $o.Detail   = "remote: $($remote.Error)"
            } else {
                $o.ExitCode = [int]$remote.ExitCode
                $o.Detail   = if ($remote.Output) { $remote.Output.Substring(0, [Math]::Min(500, $remote.Output.Length)) } else { '' }
                $o.Success  = (($o.ExitCode -eq 0) -or ($o.ExitCode -eq 1190))
            }
        } catch {
            $o.ExitCode = -4
            $o.Detail   = "Invoke-Command failed: $($_.Exception.Message)"
        }
        return $o
    }

    # Reused consent WinRM session: ONE connection per host shared by the consent
    # launch, every poll, and the final shutdown (instead of ~17 reconnects per
    # consenting host). Opened in the consent phase below, always disposed in the
    # worker's finally. Stays $null when consent is off / dry run, so the direct
    # path opens per-call connections exactly as before.
    $consentSession = $null

    try {
        # ----- pending-reboot gate (opt-in; mirrors the PIRS pending check, redone
        # the AFNET-safe way over WinRM instead of PIRS's DCOM/WMI). When
        # onlyIfPending is on, probe the target's pending-reboot state and skip
        # any host that has none, so this wave only reboots hosts that actually
        # need it. Runs FIRST (before the hold/consent) so a non-pending host is
        # skipped without prompting the user or holding a consent thread - the
        # pre-flight reachability gate already filtered dead hosts in the handler.
        # Skipped on dry runs. Probe failure fails CLOSED: a host whose pending
        # state cannot be confirmed is NOT rebooted (operator asked pending-only).
        if ($onlyIfPending -and -not $dryRun) {
            $pendingState = $null
            try {
                $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
                $icArgs = @{
                    ComputerName   = $hostname
                    Authentication = 'Negotiate'
                    SessionOption  = $wsOpt
                    ErrorAction    = 'Stop'
                    ScriptBlock    = {
                        $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                        $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                        $pfro = $false
                        try { if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA Stop).PendingFileRenameOperations) { $pfro = $true } } catch {}
                        return [bool]($cbs -or $wu -or $pfro)
                    }
                }
                if ($null -ne $cred) { $icArgs['Credential'] = $cred }
                $pendingState = [bool](Invoke-Command @icArgs | Select-Object -First 1)
            } catch {
                # Could not determine pending state - fail closed (do NOT reboot).
                $r.Status   = 'Failed'
                $r.Success  = $false
                $r.ExitCode = -4
                $r.Result   = "pending-reboot probe failed: $($_.Exception.Message)"
                return $r
            }
            if (-not $pendingState) {
                # No pending reboot - skip this host. Mirrors the Declined/Dry-Run
                # skip shape so the fan-out's $SkipOf audits it Skipped (itemCount=0,
                # NOT a real reboot) and renders a distinct row.
                $r.Status  = 'No-Pending'
                $r.Success = $false
                $r.Result  = 'No pending reboot - skipped'
                return $r
            }
        }

        # ----- time-gated HOLD (desktop Tick-Dispatch gate ~4811-4813) -----
        # Burst and rolling never hold. Time-gated workers wait for
        # DispatchAt = RestartAt - leadMinutes; with consent on, the prompt
        # opens ConsentPromptSeconds early so the prompt window resolves
        # before the lead countdown begins (desktop ~4833-4835). The wait
        # polls the relayed cancel flag every few seconds (same pattern as
        # the consent poll) so a run-bar Cancel releases the host. Dry runs
        # skip the hold, like this port's other dry-run gates - the plan is
        # previewed immediately.
        if ($mode -eq 'timegated' -and -not $dryRun) {
            $dispatchAt = $restartTime.AddMinutes(-1 * [int]$leadMinutes)
            if ($consentRequired) { $dispatchAt = $dispatchAt.AddSeconds(-1 * [int]$promptSeconds) }
            while ((Get-Date) -lt $dispatchAt) {
                if (& $isCancelled) {
                    $r.Status  = 'Cancelled'
                    $r.Success = $false
                    $r.Result  = 'cancelled by operator while holding for the dispatch window'
                    return $r
                }
                $remHold = ($dispatchAt - (Get-Date)).TotalSeconds
                if ($remHold -gt 5) { Start-Sleep -Seconds 5 } else { Start-Sleep -Milliseconds 500 }
            }
        }

        # ----- consent phase (optional, skipped on dry runs) -----
        if ($consentRequired -and -not $dryRun) {
            $token = ([guid]::NewGuid().ToString('N').Substring(0, 12))
            $agentScript = $agentTemplate -replace '__TOKEN__', $token
            $cfgJson = (@{ PromptSeconds = [int]$promptSeconds; Message = [string]$message } | ConvertTo-Json -Compress)

            # Open ONE WinRM session for this host and reuse it for the consent
            # launch, every poll, and the final shutdown - a single connection
            # instead of ~17 per consenting host. Disposed in the worker's finally.
            # If it cannot open, $consentSession stays $null and the launch below
            # fails to Launch-Failed, so the existing consentFailMode (proceed/skip)
            # path decides exactly as before.
            try {
                $nsOpt = New-PSSessionOption -OperationTimeout 60000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
                $nsArgs = @{ ComputerName = $hostname; Authentication = 'Negotiate'; SessionOption = $nsOpt; ErrorAction = 'Stop' }
                if ($null -ne $cred) { $nsArgs['Credential'] = $cred }
                $consentSession = New-PSSession @nsArgs
            } catch { $consentSession = $null }

            # ConsentLaunch: stage agent + register/run an interactive one-shot task
            # over the shared session.
            $launch = $null
            try {
                $icArgs = @{
                    Session        = $consentSession
                    ErrorAction    = 'Stop'
                    ArgumentList   = @($token, $agentScript, $cfgJson)
                    ScriptBlock    = {
                        param($tok, $agent, $cfg)
                        $res = @{ Status = 'Launch-Failed'; User = $null; Detail = '' }
                        try {
                            $dir = Join-Path $env:ProgramData 'JANET\Consent'
                            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                            try { & icacls.exe $dir /grant '*S-1-5-11:(OI)(CI)M' /T /C /Q *>$null } catch {}
                            $user = $null
                            try { $user = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
                            if (-not $user) {
                                try {
                                    $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
                                    if ($ex) {
                                        $own = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction Stop
                                        if ($own.User) { $user = ("{0}\{1}" -f $own.Domain, $own.User) }
                                    }
                                } catch {}
                            }
                            if (-not $user) { $res.Status = 'No-User'; return $res }
                            $res.User = $user
                            $agentPath  = Join-Path $dir ("agent_$tok.ps1")
                            $cfgPath    = Join-Path $dir ("cfg_$tok.json")
                            $resultPath = Join-Path $dir ("result_$tok.json")
                            $enc = New-Object System.Text.UTF8Encoding($false)
                            [System.IO.File]::WriteAllText($agentPath, $agent, $enc)
                            [System.IO.File]::WriteAllText($cfgPath,   $cfg,   $enc)
                            if (Test-Path $resultPath) { Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue }
                            $taskName = 'JANET\Consent_' + $tok
                            $tr = 'powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $agentPath + '"'
                            & schtasks.exe /Delete /TN $taskName /F *>$null
                            $st = (Get-Date).AddHours(1).ToString('HH:mm')
                            & schtasks.exe /Create /TN $taskName /TR $tr /SC ONCE /ST $st /RU $user /IT /RL LIMITED /F *>$null
                            $rcCreate = $LASTEXITCODE
                            if ($rcCreate -ne 0) { $res.Detail = "schtasks /Create rc=$rcCreate (user=$user)"; return $res }
                            & schtasks.exe /Run /TN $taskName *>$null
                            $rcRun = $LASTEXITCODE
                            if ($rcRun -ne 0) { $res.Detail = "schtasks /Run rc=$rcRun"; return $res }
                            $res.Status = 'Prompt-Launched'
                        } catch {
                            $res.Detail = $_.Exception.Message
                        }
                        return $res
                    }
                }
                $launch = Invoke-Command @icArgs
            } catch {
                $launch = @{ Status = 'Launch-Failed'; User = $null; Detail = "Invoke-Command failed: $($_.Exception.Message)" }
            }

            $launchStatus = if ($null -ne $launch) { [string]$launch.Status } else { 'Launch-Failed' }
            $proceed = $false
            if ($launchStatus -eq 'Prompt-Launched') {
                # Poll the result file until a terminal decision or the backstop.
                $deadline = (Get-Date).AddSeconds([int]$promptSeconds + 20)
                $decision = $null
                $resUser  = $null
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Seconds ([Math]::Max(2, [int]$pollInterval))
                    $poll = $null
                    try {
                        # Reuse the shared session opened for the launch.
                        $icArgs = @{
                            Session        = $consentSession
                            ErrorAction    = 'Stop'
                            ArgumentList   = @($token)
                            ScriptBlock    = {
                                param($tok)
                                $o2 = @{ Found = $false; Decision = $null; User = $null }
                                try {
                                    $dir        = Join-Path $env:ProgramData 'JANET\Consent'
                                    $resultPath = Join-Path $dir ("result_$tok.json")
                                    if (Test-Path $resultPath) {
                                        $j = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json
                                        $o2.Found    = $true
                                        $o2.Decision = [string]$j.Decision
                                        $o2.User     = [string]$j.User
                                        try { & schtasks.exe /Delete /TN ('JANET\Consent_' + $tok) /F *>$null } catch {}
                                        foreach ($f in @("agent_$tok.ps1", "cfg_$tok.json", "result_$tok.json")) {
                                            try { Remove-Item -LiteralPath (Join-Path $dir $f) -Force -ErrorAction SilentlyContinue } catch {}
                                        }
                                    }
                                } catch {}
                                return $o2
                            }
                        }
                        $poll = Invoke-Command @icArgs
                    } catch { $poll = $null }

                    if ($null -ne $poll -and [bool]$poll.Found) {
                        $decision = [string]$poll.Decision
                        $resUser  = [string]$poll.User
                        break
                    }
                }

                if ($decision -eq 'Declined') {
                    $r.Status       = 'Declined'
                    $r.ConsentState = 'Declined'
                    $r.Result       = "Declined by $resUser - skipped this run"
                    return $r
                }
                elseif ($decision -eq 'Accepted') {
                    $r.ConsentState = 'Accepted'; $proceed = $true
                }
                elseif ($decision -eq 'Timeout') {
                    $r.ConsentState = 'Timeout'; $proceed = $true
                }
                elseif ($null -ne $decision -and $decision -ne '') {
                    # Unexpected decision (e.g. AgentError) - the prompt agent could
                    # not record a clean choice. Default ('proceed'): backstop reboot.
                    # Opt-in 'skip': treat as unverified and do NOT reboot.
                    $r.ConsentState = 'Agent-Failed'
                    if ($consentFailMode -eq 'skip') { $r.Success = $false; $proceed = $false } else { $proceed = $true }
                }
                else {
                    # No result within window. Default ('proceed'): backstop reboot.
                    # Opt-in 'skip': treat as unverified and do NOT reboot.
                    $r.ConsentState = 'No-Response'
                    if ($consentFailMode -eq 'skip') { $r.Success = $false; $proceed = $false } else { $proceed = $true }
                }
            }
            elseif ($launchStatus -eq 'No-User') {
                $r.ConsentState = 'No-User'; $proceed = $true
            }
            else {
                # The consent agent could not even launch (Launch-Failed). Default
                # ('proceed'): backstop reboot. Opt-in 'skip': do NOT reboot.
                $d = if ($null -ne $launch) { [string]$launch.Detail } else { 'no result' }
                $r.ConsentState = 'Prompt-Failed'
                $r.Detail = $d
                if ($consentFailMode -eq 'skip') { $r.Success = $false; $proceed = $false } else { $proceed = $true }
            }

            if (-not $proceed) {
                # Reached only when consentFailMode='skip' and the prompt could not
                # be verified (Prompt-Failed / No-Response / Agent-Failed). A clean
                # Decline already returned above. Do NOT reboot an unverified host.
                $r.Status  = 'Consent-Unverified'
                $r.Success = $false
                $extra = if ($r.Detail) { " - $($r.Detail)" } else { '' }
                $r.Result = "Consent not verified ($($r.ConsentState)) - skipped this run$extra"
                return $r
            }
        }

        # ----- compute the per-host /t NOW, at dispatch time -----
        # Desktop direct path ~4799-4814 and Consent-Approved ~4853-4874:
        # everything except rolling converges on the shared RestartAt, so
        # pool-queue and consent delays shrink the countdown instead of
        # pushing the reboot later.
        $consentRan = ($consentRequired -and -not $dryRun)
        $leadSeconds = 0
        if ($mode -eq 'rolling') {
            # Rolling: reboot ~grace seconds from now - no shared clock.
            $leadSeconds = [int]$rollingGraceSeconds
        } elseif ($consentRan) {
            # Consent resolved: /t = seconds remaining until RestartAt,
            # floored at the accept grace so an approver always gets at
            # least that much warning.
            $remSec = [int][Math]::Round(($restartTime - (Get-Date)).TotalSeconds)
            $leadSeconds = [Math]::Max([int]$consentGraceSeconds, $remSec)
        } elseif ($mode -eq 'burst') {
            # Burst converge: /t = (RestartAt - now), floored at 60s so a
            # late start gives a 1-minute warning, not an instant reboot.
            $remSec = ($restartTime - (Get-Date)).TotalSeconds
            if ($remSec -lt 60) { $leadSeconds = 60 } else { $leadSeconds = [int][Math]::Round($remSec) }
        } else {
            # Time-gated: the hold above already waited for DispatchAt.
            $leadSeconds = [int]$leadMinutes * 60
        }
        if ($leadSeconds -lt 0) { $leadSeconds = 60 }

        # ----- dispatch the restart -----
        # Pass the reused consent session (or $null when consent is off / dry run -
        # the direct path then opens its own per-call connection, unchanged).
        $sd = & $doShutdown $hostname $leadSeconds $message $dryRun $cred $consentSession
        $r.ExitCode = $sd.ExitCode
        $r.Success  = [bool]$sd.Success
        $r.Detail   = [string]$sd.Detail
        if ($r.Success -and $dryRun) {
            # Dry-run honesty: nothing was actually dispatched. Mark it Dry-Run so
            # the fan-out audits it Skipped (not Success) and never claims itemCount=1.
            $r.Status = 'Dry-Run'
            $r.Result = 'DRY-RUN - no reboot dispatched (preview only)'
        } elseif ($r.Success) {
            $isAlready = ($sd.ExitCode -eq 1190)
            $r.Status = if ($isAlready) { 'Already-Scheduled' } else { 'Dispatched' }
            $r.Result = if ($isAlready) { 'Already scheduled (rc=1190)' } else { "OK (rc=$($sd.ExitCode))" }
        } else {
            $r.Status = 'Failed'
            $extra = if ($sd.Detail) { " - $($sd.Detail)" } else { '' }
            $r.Result = "rc=$($sd.ExitCode)$extra"
        }
    } catch {
        $r.Status = 'Failed'
        $r.Success = $false
        $r.ExitCode = -4
        $r.Result = "worker error: $($_.Exception.Message)"
    } finally {
        # Dispose the reused consent session on EVERY exit path (approve, decline,
        # no-user, launch-fail, hold-cancel, broken session, worker error).
        if ($consentSession) { try { Remove-PSSession -Session $consentSession -ErrorAction SilentlyContinue } catch {} }
    }
    return $r
}

# -----------------------------------------------------------------------------
# Per-host ABORT worker - shutdown /a via the same ProcessStartInfo + Negotiate
# WinRM pattern (mirrors $script:DispatchScriptBlock action='Abort' branch).
# -----------------------------------------------------------------------------
$script:AbortWorker = {
    param($hostname, $cred)
    $r = [ordered]@{ Host = $hostname; Status = 'Pending'; Success = $false; ExitCode = $null; Result = '' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ScriptBlock    = {
                $o = @{ ExitCode = $null; Output = ''; Error = '' }
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName               = 'shutdown.exe'
                    $psi.UseShellExecute        = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError  = $true
                    $psi.CreateNoWindow         = $true
                    $psi.Arguments              = '/a'
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $stdout = $p.StandardOutput.ReadToEnd()
                    $stderr = $p.StandardError.ReadToEnd()
                    if (-not $p.WaitForExit(30000)) {
                        try { $p.Kill() } catch {}
                        $o.ExitCode = -1
                        $o.Output   = 'shutdown.exe timed out after 30s'
                    } else {
                        $o.ExitCode = $p.ExitCode
                        $o.Output   = (($stdout + $stderr) | Out-String).Trim()
                    }
                } catch {
                    $o.Error = $_.Exception.Message
                }
                return $o
            }
        }
        if ($null -ne $cred) { $icArgs['Credential'] = $cred }
        $remote = Invoke-Command @icArgs
        if ($remote.Error) {
            $r.ExitCode = -3
            $r.Status   = 'Abort Failed'
            $r.Result   = "remote: $($remote.Error)"
        } else {
            $r.ExitCode = [int]$remote.ExitCode
            # rc 0 = aborted; rc 1116 = nothing was scheduled (treated as no-op success).
            $r.Success  = (($r.ExitCode -eq 0) -or ($r.ExitCode -eq 1116))
            if ($r.Success) {
                $r.Status = 'Aborted'
                $r.Result = if ($r.ExitCode -eq 1116) { 'No pending restart (rc=1116)' } else { "Aborted (rc=$($r.ExitCode))" }
            } else {
                $r.Status = 'Abort Failed'
                $det = if ($remote.Output) { " - $($remote.Output)" } else { '' }
                $r.Result = "rc=$($r.ExitCode)$det"
            }
        }
    } catch {
        $r.ExitCode = -4
        $r.Status   = 'Abort Failed'
        $r.Result   = "Invoke-Command failed: $($_.Exception.Message)"
    }
    return $r
}

# -----------------------------------------------------------------------------
# Reachability worker - AFNET-safe TCP connect probe to WinRM (5985) then SMB
# (445), NOT ICMP echo: workstation GPOs routinely block inbound ICMP echo while
# leaving WinRM open, so an ICMP gate would falsely drop reachable hosts from a
# destructive reboot wave and never see a rebooted host return. Mirrors the
# proven wpt Ping Sweep / bulk-scan probe (JanetWeb.wpt.psm1). $timeoutMs is the
# per-port connect timeout (kept short, 1000-1500ms, so the parallel gate stays
# fast). Used by both the pre-flight gate and the reboot monitor; the returned
# shape ({Host;Up;At}) is unchanged so the gate and reboot state machine are not.
# -----------------------------------------------------------------------------
$script:PingWorker = {
    param($hostname, $timeoutMs)
    $up = $false
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($hostname, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne([int]$timeoutMs, $false) -and $tc.Connected) { $up = $true }
        } catch { } finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($up) { break }
    }
    [PSCustomObject]@{ Host = $hostname; Up = $up; At = (Get-Date) }
}

# Single WinRM boot-time probe: Win32_OperatingSystem.LastBootUpTime, compared
# against an optional reference (the scheduled restart) to confirm a reboot
# AUTHORITATIVELY - this trumps the ping-only DOWN/UP inference (OG Verify-RrsBootTime).
$script:BootTimeWorker = {
    param($hostname, $refTicks, $cred)
    $o = [ordered]@{ Host = $hostname; Online = $false; BootTicks = [long]0; Verdict = 'failed'; Detail = '' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ScriptBlock    = { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
        }
        if ($cred) { $icArgs.Credential = $cred }
        $bt = Invoke-Command @icArgs | Select-Object -First 1
        if ($bt) {
            $boot = [datetime]$bt
            $o.Online = $true
            $o.BootTicks = $boot.Ticks
            if ([long]$refTicks -gt 0) {
                if ($boot.Ticks -ge [long]$refTicks) { $o.Verdict = 'restarted' } else { $o.Verdict = 'did-not-restart' }
            } else { $o.Verdict = 'online-no-ref' }
        }
    } catch {
        $o.Online = $false; $o.Verdict = 'failed'; $o.Detail = $_.Exception.Message
    }
    return [pscustomobject]$o
}

# -----------------------------------------------------------------------------
# Single-host synchronous test (Invoke-ShutdownDirect) + the error-hint mapper
# (Get-ShutdownErrorHint). Both lifted from the original engine.
# -----------------------------------------------------------------------------
function Invoke-RrsShutdownDirect {
    param(
        [Parameter(Mandatory)] [string]$Hostname,
        [int]$LeadSeconds = 60,
        [string]$Message  = 'TEST: this machine will restart shortly.',
        $Credential       = $null
    )
    $r = @{ Host = $Hostname; Success = $false; ExitCode = $null; Stdout = ''; Detail = '' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $Hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            # Skip the name-compare guard for IP-literal targets (audit#9); an IP has no
            # DNS indirection and its first dot-token can never match a COMPUTERNAME.
            ArgumentList   = @($LeadSeconds, $Message, $(if ($Hostname -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Hostname -split '\.')[0] }))
            ErrorAction    = 'Stop'
            ScriptBlock    = {
                param($sec, $msg, $expected)
                $o = @{ ExitCode = $null; Output = ''; Error = '' }
                # DNS-mismatch guard (HARD ABORT): keep in sync with $doShutdown.
                if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                    $o.Error = "DNS mismatch: dialed '$expected' but this machine is '$($env:COMPUTERNAME)' - ABORTED, no shutdown sent"
                    return $o
                }
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName               = 'shutdown.exe'
                    $psi.UseShellExecute        = $false
                    $psi.RedirectStandardOutput = $true
                    $psi.RedirectStandardError  = $true
                    $psi.CreateNoWindow         = $true
                    # Strip CR/LF first (a newline in the message can break the /c token),
                    # then quote-escape. Single-line messages are unaffected.
                    $msgArg = '"' + ($msg -replace '[\r\n]+',' ' -replace '"','\"') + '"'
                    $psi.Arguments = "/r /t $sec /c $msgArg /f"
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $stdout = $p.StandardOutput.ReadToEnd()
                    $stderr = $p.StandardError.ReadToEnd()
                    if (-not $p.WaitForExit(30000)) {
                        try { $p.Kill() } catch {}
                        $o.ExitCode = -1
                        $o.Output   = 'shutdown.exe timed out after 30s'
                    } else {
                        $o.ExitCode = $p.ExitCode
                        $o.Output   = (($stdout + $stderr) | Out-String).Trim()
                    }
                } catch {
                    $o.Error = $_.Exception.Message
                }
                return $o
            }
        }
        if ($null -ne $Credential) { $icArgs['Credential'] = $Credential }
        $remote = Invoke-Command @icArgs
        if ($remote.Error) {
            $r.ExitCode = -3
            $r.Stdout   = "remote: $($remote.Error)"
        } else {
            $r.ExitCode = [int]$remote.ExitCode
            $r.Stdout   = [string]$remote.Output
            $r.Success  = (($r.ExitCode -eq 0) -or ($r.ExitCode -eq 1190))
        }
        $credNote = if ($null -ne $Credential) { "-Credential $($Credential.UserName) " } else { '' }
        $r.Detail = "Invoke-Command -ComputerName $Hostname $credNote-Authentication Negotiate { shutdown /r /t $LeadSeconds /c <msg> /f }"
    } catch {
        $r.ExitCode = -4
        $r.Stdout   = "Invoke-Command failed: $($_.Exception.Message)"
    }
    return $r
}

function Get-RrsShutdownErrorHint {
    param([int]$Code, [string]$Detail = '')
    if ($Detail) {
        if ($Detail -match '0x80090351|SEC_E_NO_AUTHENTICATING_AUTHORITY|no\s+authenticating\s+authority|unknown\s+security\s+error') {
            return 'WinRM auth: 0x80090351 SEC_E_NO_AUTHENTICATING_AUTHORITY. Could not contact an authentication authority that can validate the credential against the target. Common causes: target outside the Kerberos realm/trust, target needs a WinRM TrustedHosts entry (cross-domain/workgroup), or the SPN is not registered. Clear the credential to fall back to the current CAC session and re-run.'
        }
        if ($Detail -match 'TrustedHosts') {
            return 'Target not in the WinRM TrustedHosts. Run as admin: Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<hostname-or-FQDN-or-*>" -Concatenate -Force. Workgroup/cross-forest targets always need this.'
        }
        if ($Detail -match 'The WinRM client cannot process the request') {
            return 'WinRM client config rejected the request. Inspect: winrm get winrm/config/client. May need Enable-PSRemoting or a TrustedHosts entry.'
        }
        if ($Detail -match 'destination\s+unreachable|cannot\s+find\s+the\s+computer|could\s+not\s+be\s+resolved|not\s+be\s+found') {
            return 'Target name not resolvable / not pingable. Check DNS, that the target is online, and that you have line-of-sight to it.'
        }
        if ($Detail -match 'access\s+(is\s+)?denied|0x80070005|ERROR_ACCESS_DENIED') {
            return 'Access denied. The credential is not local-admin on the target, or UAC is filtering the token. Verify the account is in BUILTIN\Administrators on the target.'
        }
        if ($Detail -match 'logon\s+failure|0x8009030E|wrong\s+user\s+name\s+or\s+password|0xC000006D') {
            return 'Logon failure - bad credential. Clear the credential to fall back to the current CAC session, or supply a different identity.'
        }
    }
    switch ($Code) {
        0     { return 'OK - target accepted the restart command.' }
        5     { return 'ERROR_ACCESS_DENIED - your account is not local admin on this target.' }
        53    { return 'ERROR_BAD_NETPATH - host offline, DNS lookup failed, or SMB blocked.' }
        1314  { return 'ERROR_PRIVILEGE_NOT_HELD - your account lacks SeRemoteShutdownPrivilege on the target.' }
        1722  { return 'RPC_S_SERVER_UNAVAILABLE - RPC blocked (firewall TCP 135 / dynamic ports) or the target RPC service is down.' }
        1727  { return 'RPC_S_NO_MORE_ENDPOINTS - Remote Registry / RPC endpoint mapper not serving requests.' }
        1115  { return 'ERROR_SHUTDOWN_IN_PROGRESS - target already has a pending shutdown. Use Abort first.' }
        1116  { return 'ERROR_NO_SHUTDOWN_IN_PROGRESS - no scheduled shutdown to abort on this target.' }
        1190  { return 'ALREADY SCHEDULED - target already has a pending restart from a prior dispatch (or another tool). Treated as success: the target IS going to restart. Use Abort to cancel and reschedule.' }
        -1    { return 'Tool-side timeout - shutdown.exe took > 30 seconds and was killed.' }
        -3    { return 'Remote scriptblock threw - target reached but shutdown.exe failed (see Detail).' }
        -4    { return 'Invoke-Command failed to complete. Common causes: WinRM not enabled on target (Enable-PSRemoting), TCP 5985 blocked, target in a Kerberos realm you cannot reach, target not in TrustedHosts (cross-domain/workgroup), or hostname not resolvable.' }
        default { return "Unknown shutdown.exe return code $Code - look it up: net helpmsg $Code" }
    }
}

# -----------------------------------------------------------------------------
# Reboot state machine - advance one host from a single ping (Update-RebootHostState).
# -----------------------------------------------------------------------------
function Update-RrsRebootState {
    param($Mon, [bool]$Up, [datetime]$At)
    $Mon.LastPing = $At
    if ($Up) {
        $Mon.EverUp = $true
        switch ($Mon.State) {
            'Down'        { $Mon.State = 'Rebooted'; if (-not $Mon.UpAt) { $Mon.UpAt = $At } }
            'Pending'     { if ($Mon.EverDown) { $Mon.State = 'Rebooted'; if (-not $Mon.UpAt) { $Mon.UpAt = $At } } else { $Mon.State = 'Up' } }
            'Unreachable' { if ($Mon.EverDown) { $Mon.State = 'Rebooted'; if (-not $Mon.UpAt) { $Mon.UpAt = $At } } else { $Mon.State = 'Up' } }
            default       { }
        }
    } else {
        switch ($Mon.State) {
            'Up'       { $Mon.State = 'Down'; $Mon.DownAt = $At; $Mon.EverDown = $true }
            'Pending'  { $Mon.State = 'Unreachable'; $Mon.EverDown = $true; if (-not $Mon.DownAt) { $Mon.DownAt = $At } }
            'Rebooted' { $Mon.State = 'Down'; $Mon.DownAt = $At; $Mon.EverDown = $true }
            default    { }
        }
    }
}

function Get-RrsRebootDisplay {
    param([string]$State)
    switch ($State) {
        'Rebooted'    { return 'Rebooted - online' }
        'Up'          { return 'Online (no reboot seen)' }
        'Down'        { return 'Offline (down, waiting)' }
        'Unreachable' { return 'No contact' }
        default       { return 'Checking...' }
    }
}

# -----------------------------------------------------------------------------
# Open / use a bounded RunspacePool for a parallel fan-out of one worker, then
# harvest results, streaming row + audit + progress per host. Shared by the
# dispatch and abort actions. Returns @{ rows; ok; failed; skipped }.
# -----------------------------------------------------------------------------
function Invoke-RrsFanOut {
    param(
        [string[]]$Targets,
        [scriptblock]$Worker,
        [scriptblock]$ArgFactory,   # param($h) -> object[] of worker args
        [scriptblock]$RowOf,        # param($res) -> ordered row hashtable (with Host)
        [scriptblock]$OkOf,         # param($res) -> [bool] success
        [scriptblock]$SkipOf,       # param($res) -> [bool] skipped (audit Skipped)
        [scriptblock]$AuditDetail,  # param($res) -> string
        [string]$AuditAction,       # audit vocabulary, e.g. 'TouchHost'
        [int]$Threads,
        [scriptblock]$Send,
        [System.Collections.ArrayList]$PreRows,  # rows already finalized (gates) to include in output
        [int]$DeadlineSeconds = 3600,            # wall-clock backstop so a wedged WinRM host can't hang the wave forever (mirrors Invoke-WptFanOut)
        [int]$PerHostTimeoutSeconds = 0          # per-host limit; >0 abandons ONLY a host overrunning its OWN run clock (0 = off)
    )
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $iss, $Host)
    $jobs = New-Object System.Collections.ArrayList
    $rows = New-Object System.Collections.ArrayList
    if ($PreRows) { foreach ($pr in $PreRows) { [void]$rows.Add($pr) } }
    $done = 0; $okCount = 0; $failCount = 0; $skipCount = 0
    $cancelled = $false
    try {
        # Pool Open + the BeginInvoke submit loop live inside the try so a throw
        # mid-submit still reaches the finally that closes/disposes the pool.
        $pool.Open()
        foreach ($h in $Targets) {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($Worker)
            foreach ($a in (& $ArgFactory $h)) { [void]$ps.AddArgument($a) }
            [void]$jobs.Add([pscustomobject]@{ Host = $h; PS = $ps; Async = $ps.BeginInvoke(); StartedAt = $null })
        }
        $total = $jobs.Count
        $deadline = (Get-Date).AddSeconds([Math]::Max(60, $DeadlineSeconds))
        $timedOut = $false
        while ($done -lt $total) {
            foreach ($j in $jobs) {
                # Stamp real execution start (NotStarted->Running) so the per-host
                # clock doesn't penalize hosts still queued behind the thread cap.
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = [ordered]@{ Host = $j.Host; Status = 'Failed'; Success = $false; Result = "worker error: $($_.Exception.Message)"; ExitCode = -4 } }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null

                    $skipped = $false
                    if ($SkipOf) { $skipped = [bool](& $SkipOf $res) }
                    $ok = [bool](& $OkOf $res)
                    if ($skipped) { $skipCount++ }
                    elseif ($ok)  { $okCount++ }
                    else          { $failCount++ }

                    $row = & $RowOf $res
                    [void]$rows.Add($row)
                    & $Send (@{ type = 'row' } + $row)

                    $auditResult = if ($skipped) { 'Skipped' } elseif ($ok) { 'Success' } else { 'Failure' }
                    & $Send @{ type='audit'; action=$AuditAction; target=$res.Host; result=$auditResult; itemCount=$(if($ok -and -not $skipped){1}else{0}); detail=([string](& $AuditDetail $res)) }

                    $done++
                    & $Send @{ type='progress'; done=$done; total=$total }
                }
            }
            # Per-host watchdog: abandon ONLY a host that overran its own run clock
            # so one wedged WinRM call can't pin a thread for the whole wave.
            # Opt-in via -PerHostTimeoutSeconds; mirrors Invoke-WptFanOut.
            if ($PerHostTimeoutSeconds -gt 0 -and $done -lt $total) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $PerHostTimeoutSeconds) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}
                        $j.PS = $null
                        $detPh = "per-host timeout (${PerHostTimeoutSeconds}s) - possible WinRM hang"
                        $rowT = & $RowOf @{ Host = $j.Host; Status = 'Timeout'; Success = $false; Result = $detPh; ExitCode = $null; ConsentState = '' }
                        [void]$rows.Add($rowT)
                        & $Send (@{ type = 'row' } + $rowT)
                        & $Send @{ type='audit'; action=$AuditAction; target=$j.Host; result='Failure'; itemCount=0; detail="per-host timeout (${PerHostTimeoutSeconds}s)" }
                        & $Send @{ type='log'; level='warn'; text="$($j.Host) : abandoned after ${PerHostTimeoutSeconds}s per-host timeout (in-flight WinRM call being stopped); the rest of the wave continues." }
                        $failCount++; $done++
                        & $Send @{ type='progress'; done=$done; total=$total }
                    }
                }
            }
            if ($done -lt $total) {
                # Honor the server cancel contract: POST /job/<id>/cancel sets the
                # injected job's Cancel flag; stop in-flight WinRM children so a
                # stood-down reboot/abort fan-out stops dispatching to remaining hosts.
                # The wall-clock deadline is the backstop for when nobody presses
                # Cancel but a host is wedged past every per-host safeguard.
                if     ($script:RrsCancelCheck -and (& $script:RrsCancelCheck)) { $cancelled = $true }
                elseif ((Get-Date) -gt $deadline)                              { $timedOut  = $true }
                if ($cancelled -or $timedOut) {
                    $reason   = if ($cancelled) { 'cancelled by operator' } else { "timed out after $([int]$DeadlineSeconds)s" }
                    $abStatus = if ($cancelled) { 'Cancelled' } else { 'Timeout' }
                    $abandoned = 0
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            $ps = $j.PS
                            # BeginStop then NULL the handle - disposing here blocks
                            # ~11s per pipeline; the pool Close/Dispose in the
                            # finally reclaims the runspaces after the abandon
                            # rows/audits are emitted.
                            try { [void]$ps.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $rowR = & $RowOf @{ Host = $j.Host; Status = $abStatus; Success = $false; Result = $reason; ExitCode = $null; ConsentState = '' }
                            [void]$rows.Add($rowR)
                            & $Send (@{ type = 'row' } + $rowR)
                            & $Send @{ type='audit'; action=$AuditAction; target=$j.Host; result='Failure'; itemCount=0; detail=$reason }
                            $failCount++; $done++; $abandoned++
                            & $Send @{ type='progress'; done=$done; total=$total }
                        }
                    }
                    $abMsg = if ($cancelled) { "Cancelled by operator; $abandoned host(s) abandoned (in-flight calls stopped)." } else { "Wave $reason; $abandoned host(s) abandoned (in-flight WinRM calls stopped)." }
                    & $Send @{ type='log'; level='warn'; text=$abMsg }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }

    return @{ rows = $rows; ok = $okCount; failed = $failCount; skipped = $skipCount; cancelled = $cancelled; timedOut = $timedOut }
}

# -----------------------------------------------------------------------------
# Resolve an int param with a default and bounds.
# -----------------------------------------------------------------------------
function Get-RrsInt {
    param($Value, [int]$Default, [int]$Min = [int]::MinValue, [int]$Max = [int]::MaxValue)
    # [int]::TryParse writes 0 into the out-param on failure, so parse into a temp
    # and only adopt it on success - a malformed value keeps $Default, never 0.
    $n = $Default
    if ($null -ne $Value -and "$Value" -ne '') {
        $tmp = 0
        if ([int]::TryParse([string]$Value, [ref]$tmp)) { $n = $tmp }
    }
    return [Math]::Max($Min, [Math]::Min($Max, $n))
}

function Get-RrsBool {
    param($Value, [bool]$Default)
    if ($null -eq $Value -or "$Value" -eq '') { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = [string]$Value
    return ($s -match '^(?i:true|1|yes|on)$')
}

# =============================================================================
#  ENTRY POINT
# =============================================================================
function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge: the server injects the synchronized job as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running fan-out / monitor break and BeginStop in-flight WinRM children so a
    # stood-down reboot/abort/verify run stops mutating the remaining hosts.
    # Stored in a script-scoped var so the separate Invoke-RrsFanOut function and
    # the verify-reboots monitor loop both pick it up. When there is no job
    # (direct calls), $cancelCheck just returns $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }
    $script:RrsCancelCheck = $cancelCheck.GetNewClosure()

    switch ($ActionId) {

        # ---------------------------------------------------------------------
        # Reachability sweep behind the Targets-tab "Ping All" button (read-only).
        # The view's doPing only needs one row per host with { Host, Pingable };
        # fan $script:PingWorker out (parallel, cap 64) - same TCP 5985/445 probe
        # the pre-flight gate uses - and stream a row + progress per host.
        'ping' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets to ping.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            & $send @{ type='status'; text="Pinging $($targets.Count) host(s)..." }
            $pmax = [Math]::Min(64, [Math]::Max(4, $targets.Count))
            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $ppool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
            $pjobs = @{}
            $rows  = New-Object System.Collections.ArrayList
            $online = 0; $offline = 0; $done = 0
            try {
                $ppool.Open()
                foreach ($h in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $ppool
                    [void]$ps.AddScript($script:PingWorker); [void]$ps.AddArgument($h); [void]$ps.AddArgument(1500)
                    $pjobs[$h] = @{ PS = $ps; Async = $ps.BeginInvoke() }
                }
                while ($pjobs.Count -gt 0) {
                    $finished = @()
                    foreach ($k in @($pjobs.Keys)) { if ($pjobs[$k].Async.IsCompleted) { $finished += $k } }
                    foreach ($k in $finished) {
                        $jp = $pjobs[$k]; $rp = $null
                        try { $rp = $jp.PS.EndInvoke($jp.Async) | Select-Object -First 1 } catch { $rp = $null }
                        try { $jp.PS.Dispose() } catch {}
                        $pjobs.Remove($k)
                        $up = ($rp -and [bool]$rp.Up)
                        if ($up) { $online++ } else { $offline++ }
                        $row = [ordered]@{ Host = $k; Pingable = $up }
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                        $done++
                        & $send @{ type='progress'; done=$done; total=$targets.Count }
                    }
                    if ($pjobs.Count -gt 0) {
                        if (& $cancelCheck) {
                            foreach ($k in @($pjobs.Keys)) { try { [void]$pjobs[$k].PS.BeginStop($null, $null) } catch {}; $pjobs[$k].PS = $null }
                            $pjobs.Clear()
                            & $send @{ type='log'; level='warn'; text='Ping cancelled by operator; remaining host(s) abandoned.' }
                            break
                        }
                        Start-Sleep -Milliseconds 60
                    }
                }
            } finally {
                try { $ppool.Close(); $ppool.Dispose() } catch {}
            }
            & $send @{ type='status'; text="Ping complete: $online online, $offline offline of $($targets.Count)." }
            return @{ rows=@($rows); summary=@{ total=$targets.Count; online=$online; offline=$offline } }
        }

        # ---------------------------------------------------------------------
        'dispatch-restart' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }

            # Self-guard (audit#10): drop the JANET dispatcher host from the wave.
            # Rebooting ourselves kills the HttpListener mid-dispatch and abandons
            # every other host in the fan-out. The in-worker DNS-mismatch guard does
            # NOT catch this (our own name resolves to us, so the compare passes).
            $selfSkipped = New-Object System.Collections.ArrayList
            $nonSelf = New-Object System.Collections.ArrayList
            foreach ($t in $targets) {
                if (Test-JanetHostIsSelf $t) { [void]$selfSkipped.Add($t) } else { [void]$nonSelf.Add($t) }
            }
            if ($selfSkipped.Count -gt 0) {
                $targets = $nonSelf.ToArray()
                & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host from this wave ($($selfSkipped -join ', ')) - a self-reboot would abort the whole dispatch." }
                if ($targets.Count -eq 0) {
                    & $send @{ type='log'; level='warn'; text='Only target was this dispatcher host - nothing to dispatch.' }
                    return @{ rows=@(); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
                }
            }

            # Never-restart Exceptions list (1.5.0-beta4). Hosts on it are dropped
            # from this wave up front (case-insensitive), like the desktop tool.
            $excludedCount = 0
            $exHosts = ConvertTo-JanetHostList ([string]$Params['exceptions'])
            if ($exHosts.Count -gt 0) {
                # Add both the exception token AND its shortname so a shortname
                # exception (DC01) protects the FQDN target (DC01.area.af.mil) and an
                # FQDN exception protects the shortname form. Match on either at test
                # time. Case-insensitive throughout. This is the DC/flight-line/medical
                # never-restart safety control - err toward over-protecting.
                $exSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($e in $exHosts) {
                    [void]$exSet.Add($e)
                    # Only alias a real hostname to its shortname. An IP-form
                    # exception ('10.20.30.40') must NOT seed its first octet ('10')
                    # into the set - that would exclude every 10.x target.
                    $eIp = $null
                    if (-not [System.Net.IPAddress]::TryParse($e, [ref]$eIp)) {
                        $eShort = ($e -split '\.')[0]
                        if ($eShort) { [void]$exSet.Add($eShort) }
                    }
                }
                $kept = New-Object System.Collections.ArrayList
                $excludedNames = New-Object System.Collections.ArrayList
                foreach ($t in $targets) {
                    # Shortname-alias match only for hostname targets; an IP target
                    # ('10.99.1.5') must not alias to its first octet ('10').
                    $tIp = $null
                    if ([System.Net.IPAddress]::TryParse($t, [ref]$tIp)) { $tShort = $null } else { $tShort = ($t -split '\.')[0] }
                    if ($exSet.Contains($t) -or ($tShort -and $exSet.Contains($tShort))) { $excludedCount++; [void]$excludedNames.Add($t) } else { [void]$kept.Add($t) }
                }
                $targets = $kept.ToArray()
                if ($excludedCount -gt 0) { & $send @{ type='log'; level=''; text="Exceptions: $excludedCount never-restart host(s) filtered out of this wave: $($excludedNames -join ', ')." } }
                if ($targets.Count -eq 0) {
                    & $send @{ type='log'; level='warn'; text='Every target is on the exceptions list - nothing to dispatch.' }
                    return @{ rows=@(); summary=@{ total=0; excluded=$excludedCount } }
                }
            }

            # Parse the restart time. Accept ISO 8601, a parseable datetime, or
            # a bare HH:mm (interpreted as the next occurrence today/tomorrow).
            $restartRaw = [string]$Params['restartTime']
            $restartTime = $null
            if (-not [string]::IsNullOrWhiteSpace($restartRaw)) {
                $parsed = [datetime]::MinValue
                if ([datetime]::TryParse($restartRaw, [ref]$parsed)) {
                    $restartTime = $parsed
                    # If only a time-of-day was given and it already passed, roll to tomorrow.
                    if ($restartRaw -match '^\s*\d{1,2}:\d{2}' -and $restartTime -lt (Get-Date)) {
                        $restartTime = $restartTime.AddDays(1)
                    }
                }
            }
            if ($null -eq $restartTime) {
                & $send @{ type='log'; level='warn'; text="Could not parse restartTime '$restartRaw'." }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }

            $leadMinutes = Get-RrsInt $Params['leadMinutes'] 15 0 1440
            $message     = [string]$Params['message']
            if ([string]::IsNullOrWhiteSpace($message)) { $message = 'System is restarting for maintenance. Save your work.' }
            $message     = $message -replace '\{LEAD\}', [string]$leadMinutes
            $burst       = Get-RrsBool $Params['burstMode'] $true
            $rolling     = Get-RrsBool $Params['rollingMode'] $false
            $rollingGrace= Get-RrsInt $Params['rollingGraceSeconds'] 60 10 3600
            $dryRun      = Get-RrsBool $Params['dryRun'] $false
            $consent     = Get-RrsBool $Params['requireConsent'] $true
            $promptMin   = Get-RrsInt $Params['consentPromptMinutes'] 5 1 120
            $graceSec    = Get-RrsInt $Params['consentGraceSeconds'] 60 0 3600
            $consentFail = [string]$Params['consentFailMode']
            if ($consentFail -ne 'skip') { $consentFail = 'proceed' }  # default unchanged: backstop-proceed
            $skipRegex   = [string]$Params['skipServersRegex']
            $skipPing    = Get-RrsBool $Params['skipUnreachablePing'] $true
            $onlyIfPending = Get-RrsBool $Params['onlyIfPending'] $false
            $threads     = Get-RrsInt $Params['threads'] 96 1 256
            $promptSec   = $promptMin * 60
            $pollInt     = 20

            $modeText = if ($rolling) { "ROLLING (~${rollingGrace}s after approve; no shared time)" } elseif ($burst) { "burst converge @ $($restartTime.ToString('yyyy-MM-dd HH:mm'))" } else { "time-gated (hold until $($restartTime.AddMinutes(-1 * $leadMinutes).ToString('yyyy-MM-dd HH:mm')), then /t = $leadMinutes min; reboot @ $($restartTime.ToString('yyyy-MM-dd HH:mm')))" }
            & $send @{ type='status'; text="Planning restart of $($targets.Count) host(s) - mode: $modeText; dryRun=$dryRun; consent=$consent$(if ($onlyIfPending) { '; only-if-pending ON' })$(if ($excludedCount) { "; $excludedCount excepted" })." }

            # Rows that finished at a gate (Skipped-Server / Unreachable) and never
            # reach WinRM. They are emitted now and included in the final rows[].
            $gateRows = New-Object System.Collections.ArrayList
            $skippedServer = 0
            $unreachable   = 0

            # --- Server-name skip gate (instant, no network). A BLANK regex means
            #     skip-servers off. A NON-BLANK regex that does not compile fails
            #     SAFE: abort the whole dispatch rather than silently disabling the
            #     exclusion gate (which could reboot servers it was meant to spare). ---
            $pending = New-Object System.Collections.ArrayList
            $regexOk = $true
            if (-not [string]::IsNullOrWhiteSpace($skipRegex)) {
                try { $null = [regex]::new($skipRegex) }
                catch {
                    & $send @{ type='log'; level='err'; text="Invalid skipServersRegex '$skipRegex' - aborting dispatch (fail-safe: the server-exclusion gate could not compile, so no host is restarted)." }
                    & $send @{ type='status'; text='Dispatch aborted: skipServersRegex is invalid. Fix or clear the regex and re-run; nothing was restarted.' }
                    return @{ rows = @(); summary = @{ total=$targets.Count; sent=0; failed=0; declined=0; skipped=0; unreachable=0; excluded=$excludedCount; error='invalid skipServersRegex' } }
                }
            } else { $regexOk = $false }

            foreach ($h in $targets) {
                if ($regexOk -and ($h -match $skipRegex)) {
                    $skippedServer++
                    $row = [ordered]@{ Host=$h; Status='Skipped-Server'; DispatchAt=''; RestartAt=$restartTime.ToString('yyyy-MM-dd HH:mm:ss'); Result='Server-named host - excluded from this wave'; ConsentState='' }
                    [void]$gateRows.Add($row)
                    & $send (@{ type='row' } + $row)
                    & $send @{ type='audit'; action='TouchHost'; target=$h; result='Skipped'; itemCount=0; detail='skipped-server' }
                } else {
                    [void]$pending.Add($h)
                }
            }
            if ($skippedServer -gt 0) {
                & $send @{ type='log'; level=''; text="Server skip gate: $skippedServer server-named host(s) excluded." }
            }

            # --- Pre-flight ping gate (parallel, cap 64). Skipped on dry runs. ---
            if ($skipPing -and -not $dryRun -and $pending.Count -gt 0) {
                & $send @{ type='status'; text="Pre-flight ping of $($pending.Count) host(s)..." }
                $pmax = [Math]::Min(64, [Math]::Max(4, $pending.Count))
                $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                $ppool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
                $pjobs = @{}
                $reachable = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                $preflightCancelled = $false
                try {
                    # Pool Open inside the try so a throw still hits the finally that disposes it.
                    $ppool.Open()
                    foreach ($h in $pending) {
                        $ps = [powershell]::Create(); $ps.RunspacePool = $ppool
                        [void]$ps.AddScript($script:PingWorker); [void]$ps.AddArgument($h); [void]$ps.AddArgument(1000)
                        $pjobs[$h] = @{ PS = $ps; Async = $ps.BeginInvoke() }
                    }
                    while ($pjobs.Count -gt 0) {
                        $finished = @()
                        foreach ($k in @($pjobs.Keys)) { if ($pjobs[$k].Async.IsCompleted) { $finished += $k } }
                        foreach ($k in $finished) {
                            $jp = $pjobs[$k]; $rp = $null
                            try { $rp = $jp.PS.EndInvoke($jp.Async) | Select-Object -First 1 } catch { $rp = $null }
                            try { $jp.PS.Dispose() } catch {}
                            $pjobs.Remove($k)
                            if ($rp -and [bool]$rp.Up) { [void]$reachable.Add([string]$rp.Host) }
                        }
                        if ($pjobs.Count -gt 0) {
                            # Honor the server cancel contract during the pre-flight gate too:
                            # stop the in-flight pings and skip the WinRM dispatch entirely.
                            if ($script:RrsCancelCheck -and (& $script:RrsCancelCheck)) {
                                $preflightCancelled = $true
                                foreach ($k in @($pjobs.Keys)) {
                                    $pp = $pjobs[$k].PS
                                    # BeginStop only; the pool finally disposes.
                                    try { [void]$pp.BeginStop($null, $null) } catch {}
                                    $pjobs[$k].PS = $null
                                }
                                $pjobs.Clear()
                                break
                            }
                            Start-Sleep -Milliseconds 60
                        }
                    }
                } finally {
                    try { $ppool.Close(); $ppool.Dispose() } catch {}
                }
                if ($preflightCancelled) {
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
                    & $send @{ type='status'; text='Dispatch cancelled by operator during pre-flight ping; no WinRM restart attempted.' }
                    return @{ rows = @($gateRows); summary = @{ total=$targets.Count; sent=0; failed=$unreachable; skipped=$skippedServer; declined=0; cancelled=$true } }
                }
                $stillPending = New-Object System.Collections.ArrayList
                foreach ($h in $pending) {
                    if ($reachable.Contains($h)) { [void]$stillPending.Add($h) }
                    else {
                        $unreachable++
                        $row = [ordered]@{ Host=$h; Status='Unreachable'; DispatchAt=''; RestartAt=$restartTime.ToString('yyyy-MM-dd HH:mm:ss'); Result='Unreachable (no ping reply) - no WinRM attempted'; ConsentState='' }
                        [void]$gateRows.Add($row)
                        & $send (@{ type='row' } + $row)
                        & $send @{ type='audit'; action='TouchHost'; target=$h; result='Failure'; itemCount=0; detail='unreachable (preflight ping)' }
                    }
                }
                $pending = $stillPending
                & $send @{ type='log'; level=''; text="Pre-flight ping: $($pending.Count) reachable, $unreachable unreachable gated out." }
            }

            if ($pending.Count -eq 0) {
                & $send @{ type='status'; text="No hosts to dispatch after gates ($skippedServer skipped-server, $unreachable unreachable)." }
                return @{ rows = @($gateRows); summary = @{ total=$targets.Count; sent=0; failed=$unreachable; skipped=$skippedServer; declined=0 } }
            }

            & $send @{ type='status'; text="Dispatching to $($pending.Count) host(s) with $threads thread(s)$(if($consent){' (consent gate ON)'})..." }

            # Consent pins its pool slot for the whole prompt window (no two-phase
            # launch/poll like the desktop), so oversized waves serialize.
            if ($consent -and -not $dryRun -and $pending.Count -gt ($threads * 2)) {
                $cBatches = [int][Math]::Ceiling($pending.Count / [double]$threads)
                & $send @{ type='log'; level='warn'; text="Consent is ON for $($pending.Count) host(s) with $threads thread(s): each consent prompt pins its pool slot for the whole prompt window, so expect up to ~$cBatches batch(es) x $promptMin min = ~$($cBatches * $promptMin) min of serialized prompting. Raise threads or split the wave." }
            }
            if ($dryRun -and -not $burst -and -not $rolling) {
                & $send @{ type='log'; level=''; text="Dry run: time-gated hold skipped; a live run would hold each host until $($restartTime.AddMinutes(-1 * $leadMinutes).ToString('yyyy-MM-dd HH:mm')) before firing /t = $($leadMinutes * 60)s." }
            }

            $restartStr = if ($rolling) { "rolling +${rollingGrace}s" } else { $restartTime.ToString('yyyy-MM-dd HH:mm:ss') }
            # DispatchAt: when each host actually fires shutdown.exe. Burst/rolling never
            # hold (dispatch is immediate) so they show '-'; time-gated holds until
            # RestartAt - lead (- the consent prompt window when consent is on).
            $dispatchStr = if ($rolling -or $burst) { '-' } else {
                $da = $restartTime.AddMinutes(-1 * [int]$leadMinutes)
                if ($consent) { $da = $da.AddSeconds(-1 * [int]$promptSec) }
                $da.ToString('yyyy-MM-dd HH:mm:ss')
            }
            $agentTemplate = $script:ConsentAgentTemplate
            $mode = if ($rolling) { 'rolling' } elseif ($burst) { 'burst' } else { 'timegated' }
            $restartTicks = $restartTime.Ticks
            $argFactory = {
                param($h)
                # The per-host /t is computed INSIDE the worker at dispatch time
                # (post-hold, post-consent) from the shared restart time, so
                # every mode except rolling converges on RestartAt.
                ,@($h, $restartTicks, $mode, $leadMinutes, $rollingGrace, $message, $dryRun, $Credential, $consent, $agentTemplate, $promptSec, $graceSec, $pollInt, $consentFail, $cancelJob, $onlyIfPending)
            }
            $rowOf = {
                param($res)
                [ordered]@{
                    Host         = $res.Host
                    Status       = [string]$res.Status
                    DispatchAt   = $dispatchStr
                    RestartAt    = $restartStr
                    Result       = [string]$res.Result
                    ConsentState = [string]$res.ConsentState
                }
            }
            $okOf = { param($res) [bool]$res.Success }
            $skipOf = { param($res) (([string]$res.Status -eq 'Declined') -or ([string]$res.Status -eq 'Dry-Run') -or ([string]$res.Status -eq 'No-Pending')) }
            $auditDetail = {
                param($res)
                if ([string]$res.Status -eq 'Declined') { "consent declined" }
                elseif ([string]$res.Status -eq 'Dry-Run') { "dry-run preview - no reboot dispatched" }
                elseif ([string]$res.Status -eq 'No-Pending') { "no pending reboot - skipped" }
                elseif ([string]$res.Status -eq 'Cancelled') { "cancelled by operator" }
                else { "shutdown /r rc=$($res.ExitCode) $($res.ConsentState)".Trim() }
            }

            # Wall-clock backstop for the harvest loop. It must sit ABOVE the longest
            # legitimate worker runtime, never clip a healthy wave: a time-gated
            # worker SLEEPS in-runspace until RestartAt (hours away), and consent
            # prompts pin their pool slot for the full prompt window - serialized
            # into batches when the wave exceeds the thread cap. Size from those
            # knobs + slack; floored 1h, capped 7d; operator-overridable.
            $holdSec = 0
            if (-not $rolling -and -not $burst) { $holdSec = [Math]::Max(0, [int][Math]::Ceiling(($restartTime - (Get-Date)).TotalSeconds)) }
            $consentBatches = if ($consent) { [int][Math]::Ceiling($pending.Count / [double]$threads) } else { 1 }
            $fanoutDeadline = Get-RrsInt $Params['fanoutDeadlineSeconds'] ([int]($holdSec + (($promptSec + $graceSec + 60) * $consentBatches) + ($leadMinutes * 60) + $rollingGrace + 1800)) 60 604800

            $out = Invoke-RrsFanOut -Targets $pending.ToArray() -Worker $script:DispatchWorker `
                -ArgFactory $argFactory -RowOf $rowOf -OkOf $okOf -SkipOf $skipOf `
                -AuditDetail $auditDetail -AuditAction 'TouchHost' -Threads $threads -Send $send -PreRows $gateRows `
                -DeadlineSeconds $fanoutDeadline

            $declined = 0
            foreach ($row in $out.rows) { if ($row.Status -eq 'Declined') { $declined++ } }
            # onlyIfPending: hosts with no pending reboot were skipped by the worker
            # (counted in $out.skipped). Tally them separately so they don't vanish
            # from the summary line on a live run.
            $noPending = 0
            foreach ($row in $out.rows) { if ($row.Status -eq 'No-Pending') { $noPending++ } }

            $sent = $out.ok
            $failed = $out.failed + $unreachable
            $cancelled = [bool]$out.cancelled
            # Dry-run honesty: dry-run hosts are counted Skipped by the fan-out (along
            # with declines), so back them out into their own count. A 0-dispatched dry
            # run then reads as "N previewed" instead of looking like a total failure.
            $dryCount = if ($dryRun) { [Math]::Max(0, $out.skipped - $declined) } else { 0 }
            $dryText = if ($dryCount -gt 0) { " $dryCount previewed (dry-run)," } else { '' }
            $pendText = if ($noPending -gt 0) { " $noPending no-pending," } else { '' }
            $doneText = if ($cancelled) { "Cancelled by operator. $sent dispatched,$dryText $failed failed/abandoned, $declined declined,$pendText $skippedServer skipped-server of $($targets.Count)." } else { "Done. $sent dispatched,$dryText $failed failed, $declined declined,$pendText $skippedServer skipped-server of $($targets.Count)." }
            & $send @{ type='status'; text=$doneText }
            return @{
                rows    = @($out.rows)
                summary = @{ total=$targets.Count; sent=$sent; failed=$failed; declined=$declined; skipped=$skippedServer; unreachable=$unreachable; excluded=$excludedCount; rolling=$rolling; cancelled=$cancelled; dryRun=$dryCount; noPending=$noPending }
            }
        }

        # ---------------------------------------------------------------------
        'abort-scheduled' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $threads = Get-RrsInt $Params['threads'] 32 1 128
            & $send @{ type='status'; text="Aborting scheduled restart on $($targets.Count) host(s) with $threads thread(s)..." }

            $argFactory  = { param($h) ,@($h, $Credential) }
            $rowOf       = { param($res) [ordered]@{ Host=$res.Host; Status=[string]$res.Status; Result=[string]$res.Result } }
            $okOf        = { param($res) [bool]$res.Success }
            $auditDetail = { param($res) "shutdown /a rc=$($res.ExitCode)" }

            $out = Invoke-RrsFanOut -Targets $targets -Worker $script:AbortWorker `
                -ArgFactory $argFactory -RowOf $rowOf -OkOf $okOf -SkipOf $null `
                -AuditDetail $auditDetail -AuditAction 'TouchHost' -Threads $threads -Send $send -PreRows $null

            $abortDoneText = if ([bool]$out.cancelled) { "Cancelled by operator. $($out.ok) aborted, $($out.failed) failed/abandoned of $($targets.Count)." } else { "Done. $($out.ok) aborted, $($out.failed) failed of $($targets.Count)." }
            & $send @{ type='status'; text=$abortDoneText }
            return @{ rows = @($out.rows); summary = @{ total=$targets.Count; aborted=$out.ok; failed=$out.failed; cancelled=[bool]$out.cancelled } }
        }

        # ---------------------------------------------------------------------
        'test-single-host' {
            $hostname = ([string]$Params['hostname']).Trim().Trim('\','/').TrimStart('\\')
            if ([string]::IsNullOrWhiteSpace($hostname)) {
                & $send @{ type='log'; level='warn'; text='Hostname is required.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            # Self-guard (audit#10, parity with dispatch-restart's self-exclusion ~line 1282):
            # REFUSE to test-reboot the JANET dispatcher itself. The in-worker DNS-mismatch
            # guard (Invoke-RrsShutdownDirect) does NOT catch this - our own name resolves to
            # us, so the name compare passes - and a reboot here would kill the HttpListener
            # mid-session. Test-JanetHostIsSelf covers short/FQDN/IP/loopback.
            if (Test-JanetHostIsSelf $hostname) {
                & $send @{ type='log'; level='warn'; text="Self-guard: '$hostname' is this JANET dispatcher host - refused. A test restart here would reboot the server mid-session." }
                $row = [ordered]@{ Host=$hostname; ExitCode=$null; Success=$false; Stdout=''; ErrorHint='Refused: this is the JANET dispatcher host (self-reboot guard).' }
                & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='TouchHost'; target=$hostname; result='Skipped'; itemCount=0; detail='self-guard: dispatcher host - no reboot' }
                & $send @{ type='status'; text='Refused: self-reboot guard (dispatcher host).' }
                return @{ rows=@($row); summary=@{ total=1; ok=0; failed=0; refused=1 } }
            }
            $dryRun = Get-RrsBool $Params['dryRun'] $false
            # Floor 30s = the desktop test dialog's minimum - no accidental instant reboot.
            $leadSeconds = Get-RrsInt $Params['leadSeconds'] 60 30 99999
            $message     = [string]$Params['message']
            if ([string]::IsNullOrWhiteSpace($message)) { $message = 'TEST: this machine will restart shortly.' }

            if ($dryRun) {
                # Dry run: report what WOULD happen; contact nothing, reboot nothing
                # (mirrors dispatch-restart's dry-run honesty - audited Skipped, not Success).
                & $send @{ type='status'; text="DRY RUN: would test-restart $hostname (shutdown /r /t $leadSeconds) - no reboot dispatched." }
                $row = [ordered]@{ Host=$hostname; ExitCode=$null; Success=$true; Stdout="DRY-RUN - would issue shutdown /r /t $leadSeconds /f (no reboot dispatched)"; ErrorHint='DRY RUN - no machine contacted' }
                & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='TouchHost'; target=$hostname; result='Skipped'; itemCount=0; detail="dry-run test shutdown /r /t $leadSeconds" }
                & $send @{ type='status'; text='Done (dry run). No reboot dispatched.' }
                return @{ rows=@($row); summary=@{ total=1; ok=0; failed=0; dryRun=1 } }
            }

            & $send @{ type='status'; text="Testing restart on $hostname (/t=$leadSeconds)..." }
            $res  = Invoke-RrsShutdownDirect -Hostname $hostname -LeadSeconds $leadSeconds -Message $message -Credential $Credential
            $hint = Get-RrsShutdownErrorHint -Code ([int]$res.ExitCode) -Detail ([string]$res.Stdout)

            $row = [ordered]@{
                Host      = $hostname
                ExitCode  = $res.ExitCode
                Success   = [bool]$res.Success
                Stdout    = [string]$res.Stdout
                ErrorHint = $hint
            }
            & $send (@{ type='row' } + $row)
            $auditResult = if ($res.Success) { 'Success' } else { 'Failure' }
            & $send @{ type='audit'; action='TouchHost'; target=$hostname; result=$auditResult; itemCount=$(if($res.Success){1}else{0}); detail="test shutdown /r rc=$($res.ExitCode)" }
            & $send @{ type='status'; text="Done. rc=$($res.ExitCode) - $(if($res.Success){'success'}else{'failed'})." }
            return @{ rows = @($row); summary = @{ total=1; ok=$(if($res.Success){1}else{0}); failed=$(if($res.Success){0}else{1}); exitCode=$res.ExitCode } }
        }

        # ---------------------------------------------------------------------
        'verify-reboots' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $intervalSec = Get-RrsInt $Params['pingIntervalSeconds'] 15 3 600
            $timeoutSec  = Get-RrsInt $Params['timeoutSeconds'] 1800 10 86400
            $threads     = Get-RrsInt $Params['threads'] 32 1 64
            $timeoutMs   = 1500

            & $send @{ type='status'; text="Reboot monitor: $($targets.Count) host(s), $intervalSec s interval, $timeoutSec s timeout." }

            # Per-host monitor records.
            $mons = New-Object System.Collections.ArrayList
            $monByHost = @{}
            foreach ($h in $targets) {
                $rec = [pscustomobject]@{
                    Host = $h; State = 'Pending'
                    EverUp = $false; EverDown = $false
                    DownAt = $null; UpAt = $null; LastPing = $null
                    Rendered = ''
                }
                [void]$mons.Add($rec)
                $monByHost[$h] = $rec
            }

            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pmax = [Math]::Min($threads, [Math]::Max(4, $mons.Count))
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)

            $startTime = Get-Date
            $lastWaveAt = $null
            $jobs = @{}
            $monDone = $false
            $monCancelled = $false
            try {
                # Pool Open inside the try so a throw still hits the finally that disposes it.
                $pool.Open()
                while (-not $monDone) {
                    # Reap completed pings, advance state.
                    if ($jobs.Count -gt 0) {
                        $finished = @()
                        foreach ($k in @($jobs.Keys)) { if ($jobs[$k].Async.IsCompleted) { $finished += $k } }
                        foreach ($k in $finished) {
                            $jp = $jobs[$k]; $rp = $null
                            try { $rp = $jp.PS.EndInvoke($jp.Async) | Select-Object -First 1 } catch { $rp = $null }
                            try { $jp.PS.Dispose() } catch {}
                            $jobs.Remove($k)
                            if ($rp) {
                                $m = $monByHost[[string]$rp.Host]
                                if ($m) {
                                    $prevState = $m.State
                                    Update-RrsRebootState -Mon $m -Up ([bool]$rp.Up) -At $rp.At
                                    if ($m.State -ne $prevState -or $m.Rendered -eq '') {
                                        $m.Rendered = $m.State
                                        $row = [ordered]@{
                                            Host        = $m.Host
                                            State       = (Get-RrsRebootDisplay $m.State)
                                            'Went-Down' = $(if ($m.DownAt) { $m.DownAt.ToString('HH:mm:ss') } else { '' })
                                            'Came-Back' = $(if ($m.UpAt)   { $m.UpAt.ToString('HH:mm:ss') }   else { '' })
                                            Result      = (Get-RrsRebootDisplay $m.State)
                                        }
                                        & $send (@{ type='row' } + $row)
                                    }
                                }
                            }
                        }
                    }

                    # Honor the server cancel contract: a cancel breaks the monitor
                    # wait loop (which can run up to timeoutSeconds, max 86400s).
                    # Stop any in-flight pings and abandon the still-pending hosts.
                    if ($script:RrsCancelCheck -and (& $script:RrsCancelCheck)) {
                        $monCancelled = $true
                        foreach ($k in @($jobs.Keys)) {
                            $mp = $jobs[$k].PS
                            # BeginStop only; the pool finally disposes.
                            try { [void]$mp.BeginStop($null, $null) } catch {}
                            $jobs[$k].PS = $null
                        }
                        $jobs.Clear()
                        $abandoned = 0
                        foreach ($m in $mons) {
                            if ($m.State -eq 'Rebooted') { continue }
                            $row = [ordered]@{
                                Host        = $m.Host
                                State       = 'Cancelled by operator'
                                'Went-Down' = $(if ($m.DownAt) { $m.DownAt.ToString('HH:mm:ss') } else { '' })
                                'Came-Back' = $(if ($m.UpAt)   { $m.UpAt.ToString('HH:mm:ss') }   else { '' })
                                Result      = 'Cancelled by operator'
                            }
                            & $send (@{ type='row' } + $row)
                            & $send @{ type='audit'; action='TouchHost'; target=$m.Host; result='Failure'; itemCount=0; detail='cancelled by operator' }
                            $abandoned++
                        }
                        & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
                        & $send @{ type='status'; text="Reboot monitor cancelled by operator: $abandoned host(s) abandoned." }
                        $monDone = $true
                        break
                    }

                    $now = Get-Date
                    $elapsed = $now - $startTime

                    # New wave once the previous drained AND the interval elapsed.
                    if ($jobs.Count -eq 0) {
                        $due = ($null -eq $lastWaveAt) -or (($now - $lastWaveAt).TotalSeconds -ge $intervalSec)
                        if ($due) {
                            $lastWaveAt = $now
                            foreach ($m in $mons) {
                                if ($m.State -eq 'Rebooted') { continue }
                                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                                [void]$ps.AddScript($script:PingWorker); [void]$ps.AddArgument($m.Host); [void]$ps.AddArgument($timeoutMs)
                                $jobs[$m.Host] = @{ PS = $ps; Async = $ps.BeginInvoke() }
                            }
                        }
                    }

                    # Tally + progress.
                    $cReb = 0; $cUp = 0; $cDown = 0; $cNo = 0; $cChk = 0
                    foreach ($m in $mons) {
                        switch ($m.State) {
                            'Rebooted'    { $cReb++ }
                            'Up'          { $cUp++ }
                            'Down'        { $cDown++ }
                            'Unreachable' { $cNo++ }
                            default       { $cChk++ }
                        }
                    }
                    & $send @{ type='progress'; done=$cReb; total=$mons.Count }

                    $remaining = @($mons | Where-Object { $_.State -ne 'Rebooted' })
                    $allBack   = ($remaining.Count -eq 0)
                    $timedOut  = ($elapsed.TotalSeconds -ge $timeoutSec)
                    if ($allBack -or $timedOut) {
                        $monDone = $true
                        & $send @{ type='status'; text="Reboot monitor finished: $cReb rebooted, $cUp online-no-reboot, $cDown offline/down, $cNo no-contact of $($mons.Count)." }
                    } else {
                        & $send @{ type='status'; text="Monitoring... elapsed $([int]$elapsed.TotalSeconds)s, in-flight $($jobs.Count), rebooted $cReb/$($mons.Count)." }
                        Start-Sleep -Milliseconds 500
                    }
                }
            } finally {
                try { $pool.Close(); $pool.Dispose() } catch {}
            }

            # Final rows + per-host audit.
            $rows = New-Object System.Collections.ArrayList
            $okCount = 0; $failCount = 0
            foreach ($m in $mons) {
                $disp = Get-RrsRebootDisplay $m.State
                $row = [ordered]@{
                    Host        = $m.Host
                    State       = $disp
                    'Went-Down' = $(if ($m.DownAt) { $m.DownAt.ToString('HH:mm:ss') } else { '' })
                    'Came-Back' = $(if ($m.UpAt)   { $m.UpAt.ToString('HH:mm:ss') }   else { '' })
                    Result      = $disp
                }
                [void]$rows.Add($row)
                $rebooted = ($m.State -eq 'Rebooted')
                if ($rebooted) { $okCount++ } else { $failCount++ }
                # On cancel, non-rebooted hosts were already audited 'cancelled by
                # operator' in the monitor loop; don't double-audit them here.
                if ($monCancelled -and -not $rebooted) { continue }
                & $send @{ type='audit'; action='TouchHost'; target=$m.Host; result=$(if($rebooted){'Success'}else{'Failure'}); itemCount=$(if($rebooted){1}else{0}); detail=$disp }
            }
            return @{ rows = @($rows); summary = @{ total=$mons.Count; rebooted=$okCount; notConfirmed=$failCount; cancelled=$monCancelled } }
        }

        # ---------------------------------------------------------------------
        'verify-boottime' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $threads = Get-RrsInt $Params['threads'] 32 1 64
            $refTicks = [long]0; $refShown = ''
            $refStr = ([string]$Params['referenceTime']).Trim()
            if (-not [string]::IsNullOrWhiteSpace($refStr)) {
                $refDt = [datetime]::MinValue
                if ([datetime]::TryParse($refStr, [ref]$refDt)) { $refTicks = $refDt.Ticks; $refShown = $refDt.ToString('yyyy-MM-dd HH:mm:ss') }
                else { & $send @{ type='log'; level='warn'; text="Could not parse reference time '$refStr' - reporting boot time only (no restarted/not verdict)." } }
            }
            & $send @{ type='status'; text="WinRM boot-time verify: $($targets.Count) host(s)$(if ($refShown) { " vs restart @ $refShown" }) with $threads thread(s)..." }

            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pmax = [Math]::Min($threads, [Math]::Max(4, $targets.Count))
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
            $rows = New-Object System.Collections.ArrayList
            $confirmed = 0; $notRestarted = 0; $online = 0; $failed = 0; $done = 0; $cancelled = $false
            $jobs = @{}
            try {
                $pool.Open()
                foreach ($h in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                    [void]$ps.AddScript($script:BootTimeWorker); [void]$ps.AddArgument($h); [void]$ps.AddArgument($refTicks); [void]$ps.AddArgument($Credential)
                    $jobs[$h] = @{ PS = $ps; Async = $ps.BeginInvoke() }
                }
                while ($jobs.Count -gt 0) {
                    $finished = @()
                    foreach ($k in @($jobs.Keys)) { if ($jobs[$k].Async.IsCompleted) { $finished += $k } }
                    foreach ($k in $finished) {
                        $jp = $jobs[$k]; $res = $null
                        try { $res = $jp.PS.EndInvoke($jp.Async) | Select-Object -First 1 } catch { $res = $null }
                        try { $jp.PS.Dispose() } catch {}
                        $jobs.Remove($k)
                        $vk = if ($res) { [string]$res.Verdict } else { 'failed' }
                        $bootStr = ''
                        if ($res -and [long]$res.BootTicks -gt 0) { $bootStr = ([datetime]::new([long]$res.BootTicks)).ToString('yyyy-MM-dd HH:mm:ss') }
                        switch ($vk) {
                            'restarted'       { $verdict = "RESTARTED - confirmed by boot time ($bootStr)"; $confirmed++;   $auditRes='Success' }
                            'did-not-restart' { $verdict = "Did NOT restart - confirmed (last boot $bootStr)"; $notRestarted++; $auditRes='Failure' }
                            'online-no-ref'   { $verdict = "Online (last boot $bootStr - no restart time to compare)"; $online++; $auditRes='Skipped' }
                            default           { $verdict = "Boot-time check failed$(if ($res -and $res.Detail) { ' - ' + $res.Detail })"; $failed++; $auditRes='Failure' }
                        }
                        $row = [ordered]@{ Host = $k; State = $verdict; 'Boot-Time' = $bootStr; Result = $verdict }
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                        & $send @{ type='audit'; action='TouchHost'; target=$k; result=$auditRes; itemCount=0; detail=$verdict }
                        $done++
                        & $send @{ type='progress'; done=$done; total=$targets.Count }
                    }
                    if ($jobs.Count -gt 0) {
                        if ($script:RrsCancelCheck -and (& $script:RrsCancelCheck)) {
                            $cancelled = $true
                            foreach ($k in @($jobs.Keys)) { try { [void]$jobs[$k].PS.BeginStop($null, $null) } catch {}; $jobs[$k].PS = $null }
                            $jobs.Clear()
                            & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining boot-time checks abandoned.' }
                            break
                        }
                        Start-Sleep -Milliseconds 80
                    }
                }
            } finally {
                try { $pool.Close(); $pool.Dispose() } catch {}
            }
            & $send @{ type='status'; text="Boot-time verify done: $confirmed restarted, $notRestarted did-not-restart, $online online-no-ref, $failed failed of $($targets.Count)$(if ($cancelled) { ' (cancelled)' })." }
            return @{ rows=@($rows); summary=@{ total=$targets.Count; restarted=$confirmed; notRestarted=$notRestarted; online=$online; failed=$failed; cancelled=$cancelled } }
        }

        # ---------------------------------------------------------------------
        'cancel-pending' {
            & $send @{ type='status'; text='Cancel-pending acknowledged.' }
            $row = [ordered]@{
                Status = 'Acknowledged'
                Detail = 'To stop an in-progress dispatch mid-run, use the run-bar Cancel button on the running action: remaining hosts are abandoned and in-flight WinRM calls are stopped. Hosts that already received a restart command keep their countdown - run the Abort Scheduled Restarts action against them to stand them down.'
            }
            & $send (@{ type='row' } + $row)
            return @{ rows = @($row); summary = @{ cancelled = 0 } }
        }

        # ---------------------------------------------------------------------
        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
